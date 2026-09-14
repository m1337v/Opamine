/*
 * hidden_dylib_hider.c — Hide JB dylibs from image enumeration in hidden-injection mode.
 *
 * Strategy:
 *   - Hook dyld enumeration functions via litehook (in-place DSC replacement)
 *   - Maintain a stable, process-lifetime image catalog with filtered views
 *   - Caller capability via exact validated image ranges:
 *     systemhook/authorized selected tweaks → complete view, everyone else → filtered view
 *   - Also hooks task_info(TASK_DYLD_INFO) to present filtered dyld_all_image_infos
 *
 * Advantage over Shadow/Choicy: we're in systemhook, hooking at the DSC level
 * before any app code runs. No extra dylib to hide, no GOT modifications,
 * no dependency on MSHookFunction/ellekit.
 */

#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach/mig.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <libgen.h>
#include <os/lock.h>
#include <limits.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <stdio.h>
#include <strings.h>
#include <pthread.h>

#include "common.h"
#include "envbuf.h"
#include "hider_internal.h"
#include "hider_identity.h"
#include "hider_caller_policy.h"
#include "hider_hook_session.h"

// From roothider_main.c — non-static after our edit
extern bool hidden_tweak_filter_should_block_path(const char *path);
extern bool dyld_patch_fallback_enabled;
extern atomic_bool dlopen_fallback_hook_installed;
extern void *dlopen_fallback_hook(const char *path, int mode);
extern bool roothide_hidden_tweak_hooks_ready(void);

// dyld private — always available, NOT hooked by us
extern const char *dyld_image_path_containing_address(const void *addr);

// ObjC runtime functions we hook via GOT rebinding
extern const char *class_getImageName(Class cls);
extern Class *objc_copyClassList(unsigned int *outCount);
extern const char * _Nonnull * objc_copyImageNames(unsigned int *outCount);
extern const char * _Nonnull * objc_copyClassNamesForImage(const char *image, unsigned int *outCount);

// Saved original function pointers — published before any import-slot write.
// The new backend changes callers' slots, not the DSC function bodies.
static int (*orig_dladdr)(const void *, Dl_info *) = NULL;
static void *(*orig_dlsym)(void *, const char *) = NULL;
static char *(*orig_dlerror)(void) = NULL;
static uint32_t (*orig_dyld_image_count)(void) = NULL;
static const char *(*orig_dyld_get_image_name)(uint32_t) = NULL;
static const struct mach_header *(*orig_dyld_get_image_header)(uint32_t) = NULL;
static intptr_t (*orig_dyld_get_image_vmaddr_slide)(uint32_t) = NULL;
static void (*orig_dyld_register_func_for_add_image)(void (*)(const struct mach_header *, intptr_t)) = NULL;
static void (*orig_dyld_register_func_for_remove_image)(void (*)(const struct mach_header *, intptr_t)) = NULL;
static kern_return_t (*orig_task_info)(task_name_t, task_flavor_t, task_info_t, mach_msg_type_number_t *) = NULL;
static const char *(*orig_class_getImageName)(Class) = NULL;
static Class *(*orig_objc_copyClassList)(unsigned int *) = NULL;
static const char * _Nonnull *(*orig_objc_copyImageNames)(unsigned int *) = NULL;
static const char * _Nonnull *(*orig_objc_copyClassNamesForImage)(const char *, unsigned int *) = NULL;
static void (*orig_objc_addLoadImageFunc)(objc_func_loadImage) = NULL;
static void *(*orig_dlopen)(const char *, int) = NULL;
static int (*orig_dlclose)(void *) = NULL;
static pid_t (*orig_fork)(void) = NULL;
static int (*orig_getfsstat)(struct statfs *, int, int) = NULL;
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t) = NULL;
static char *(*orig_getenv)(const char *) = NULL;
static int (*orig_access)(const char *, int) = NULL;
static int (*orig_stat)(const char *, struct stat *) = NULL;
static int (*orig_lstat)(const char *, struct stat *) = NULL;
static int (*orig_statfs)(const char *, struct statfs *) = NULL;
static int (*orig_statvfs)(const char *, struct statvfs *) = NULL;
static FILE *(*orig_fopen)(const char *, const char *) = NULL;
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static DIR *(*orig_opendir)(const char *) = NULL;
static struct dirent *(*orig_readdir)(DIR *) = NULL;
static int (*orig_closedir)(DIR *) = NULL;
static kern_return_t (*orig_mach_port_get_refs)(ipc_space_t, mach_port_name_t, mach_port_right_t, mach_port_urefs_t *) = NULL;
static IMP orig_UIApplication_canOpenURL = NULL;
static IMP orig_UIApplication_openURL = NULL;
static IMP orig_UIApplication_openURL_options_completion = NULL;

/* Internal callback pins must use dlopen/dlclose, but callers are entitled to
 * the error that was pending before our bookkeeping began.  Virtualize that
 * one pending result in fixed TLS before an internal loader call consumes it;
 * on an internal failure, consume only the bookkeeping error and leave the
 * virtual caller result for h_dlerror.  This is allocation-free and does not
 * cache a libdyld-owned error pointer. */
#define RHI_LOADER_ERROR_CAPACITY 512U
static _Thread_local char g_loader_error_message[RHI_LOADER_ERROR_CAPACITY];
static _Thread_local bool g_loader_error_pending = false;

static void hider_loader_error_clear_pending(void) {
	g_loader_error_pending = false;
}

static void hider_loader_error_preserve_for_internal_call(void) {
	if (g_loader_error_pending || !orig_dlerror) {
		return;
	}
	char *pending = orig_dlerror();
	if (pending) {
		strlcpy(g_loader_error_message, pending, sizeof(g_loader_error_message));
		g_loader_error_pending = true;
	}
}

static void hider_loader_error_consume_internal_failure(void) {
	/* The pre-call application error, if any, already lives in TLS.  Discard the
	 * error produced by our RTLD_NOLOAD/dlclose bookkeeping so it cannot leak
	 * out through the caller's later dlerror(). */
	if (orig_dlerror) {
		(void)orig_dlerror();
	}
}

// Forward declarations of hook functions (needed by translate_hook_to_orig)
static uint32_t h_image_count(void);
static const char *h_get_image_name(uint32_t idx);
static const struct mach_header *h_get_image_header(uint32_t idx);
static intptr_t h_get_image_vmaddr_slide(uint32_t idx);
static void h_register_func_for_add_image(void (*func)(const struct mach_header *, intptr_t));
static void h_register_func_for_remove_image(void (*func)(const struct mach_header *, intptr_t));
static void on_objc_image_loaded(const struct mach_header *mh);
static kern_return_t h_task_info(task_name_t target, task_flavor_t flavor,
                                  task_info_t info_out, mach_msg_type_number_t *cnt);
static int h_dladdr(const void *addr, Dl_info *info);
static void *h_dlsym(void *handle, const char *symbol);
static char *h_dlerror(void);
static const char *h_class_getImageName(Class cls);
static Class *h_objc_copyClassList(unsigned int *outCount);
static const char * _Nonnull *h_objc_copyImageNames(unsigned int *outCount);
static const char * _Nonnull *h_objc_copyClassNamesForImage(const char *image, unsigned int *outCount);
static void h_objc_addLoadImageFunc(objc_func_loadImage func);
static void *h_dlopen(const char *path, int mode);
static pid_t h_fork(void);
static int h_getfsstat(struct statfs *buf, int bufsize, int mode);
static int h_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static char *h_getenv(const char *name);
static int h_access(const char *path, int mode);
static int h_stat(const char *path, struct stat *buf);
static int h_lstat(const char *path, struct stat *buf);
static int h_statfs(const char *path, struct statfs *buf);
static int h_statvfs(const char *path, struct statvfs *buf);
static FILE *h_fopen(const char *path, const char *mode);
static int h_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static DIR *h_opendir(const char *path);
static struct dirent *h_readdir(DIR *dirp);
static int h_closedir(DIR *dirp);
static kern_return_t h_mach_port_get_refs(ipc_space_t task, mach_port_name_t name, mach_port_right_t right, mach_port_urefs_t *refs);
static BOOL h_UIApplication_canOpenURL(id self, SEL _cmd, id url);
static BOOL h_UIApplication_openURL(id self, SEL _cmd, id url);
static void h_UIApplication_openURL_options_completion(id self, SEL _cmd, id url, id options, void *completion);
static bool fs_path_should_hide(const char *path);

//------------------------------------------------------------------------------
#pragma mark - Stable Image Catalog

/*
 * dyld owns the source image strings and unmaps a header at dlclose.  Keeping
 * pointers into either structure in a callback replay queue therefore creates
 * a timing-dependent stale-header bug.  The catalog deliberately never frees
 * a record: each load gets a new identity, its path/UUID are ours, and a
 * remove merely makes that identity inactive.  In particular an address being
 * reused for a later load cannot revive a prior record.
 */
typedef struct hider_image_record hider_image_record_t;

typedef enum {
	HIDER_IMAGE_EVENT_ADD = 0,
	HIDER_IMAGE_EVENT_REMOVE,
} hider_image_event_kind_t;

typedef struct hider_image_event {
	struct hider_image_event *next;
	hider_image_record_t     *record;
	uint64_t                  sequence;
	hider_image_event_kind_t  kind;
} hider_image_event_t;

typedef struct hider_objc_event {
	struct hider_objc_event *next;
	hider_image_record_t   *record;
	uint64_t                sequence;
} hider_objc_event_t;

struct hider_image_record {
	hider_image_record_t    *next;
	char                     *path;
	const struct mach_header *header;
	intptr_t                  slide;
	uint8_t                   uuid[16];
	uint64_t                  added_event;
	uint64_t                  removed_event;
	uint64_t                  added_generation;
	uint64_t                  identity;
	bool                      uuid_valid;
	bool                      hidden;
	bool                      active;
	bool                      objc_event_emitted;
	hider_image_event_t       add_event;
	hider_image_event_t       remove_event;
	hider_objc_event_t        objc_event;
};

typedef enum {
	HIDER_TRACKING_FILTERED = 0,
	HIDER_TRACKING_DEGRADING,
	HIDER_TRACKING_NATIVE,
} hider_tracking_state_t;

static hider_image_record_t *g_catalog_head = NULL;
static hider_image_record_t *g_catalog_tail = NULL;
static hider_image_event_t  *g_image_event_head = NULL;
static hider_image_event_t  *g_image_event_tail = NULL;
static uint64_t              g_image_event_sequence = 0;
static uint64_t              g_image_identity_sequence = 0;
static os_unfair_lock        g_lock = OS_UNFAIR_LOCK_INIT;

typedef enum {
	DIR_FILTER_NONE = 0,
	DIR_FILTER_PREBOOT_ROOT,
	DIR_FILTER_PREBOOT_HASH_ROOT,
} dir_filter_kind_t;

static bool path_is_preboot_root(const char *path) {
	return path && (!strcmp(path, "/private/preboot") || !strcmp(path, "/private/preboot/"));
}

static bool path_is_preboot_hash_root(const char *path) {
	if (!path || !string_has_prefix(path, "/private/preboot/")) {
		return false;
	}

	const char *relative = path + sizeof("/private/preboot/") - 1;
	if (!relative[0]) {
		return false;
	}
	if (strchr(relative, '/')) {
		return false;
	}
	if (!strcmp(relative, "active")) {
		return false;
	}
	return true;
}

static dir_filter_kind_t dir_filter_kind_for_path(const char *path) {
	if (path_is_preboot_root(path)) {
		return DIR_FILTER_PREBOOT_ROOT;
	}
	if (path_is_preboot_hash_root(path)) {
		return DIR_FILTER_PREBOOT_HASH_ROOT;
	}
	return DIR_FILTER_NONE;
}

/* A DIR* is not a stable path identity: libc may recycle the pointer and a
 * directory may be renamed after opendir.  Resolve the descriptor on every
 * external readdir decision instead of retaining process-global DIR state.
 * F_GETPATH is intentionally best-effort; sandboxed or unusual descriptors
 * simply keep stock readdir behavior. */
static bool dir_filter_kind_for_dir(DIR *dirp, dir_filter_kind_t *kind_out) {
	if (!dirp || !kind_out) {
		return false;
	}

	const int saved_errno = errno;
	const int fd = dirfd(dirp);
	char path[PATH_MAX];
	if (fd < 0 || fcntl(fd, F_GETPATH, path) != 0) {
		errno = saved_errno;
		return false;
	}

	*kind_out = dir_filter_kind_for_path(path);
	errno = saved_errno;
	return true;
}

static bool preboot_root_entry_should_hide(const char *name) {
	if (!name || !name[0]) {
		return false;
	}

	return !strcmp(name, ".installed_palera1n")
	    || !strcmp(name, "jb")
	    || !strcmp(name, "procursus");
}

static bool preboot_hash_root_entry_should_hide(const char *name) {
	if (!name || !name[0]) {
		return false;
	}

	return string_has_prefix(name, "dopamine-")
	    || string_has_prefix(name, "jb-");
}

static bool dir_entry_should_hide(dir_filter_kind_t kind, const char *name) {
	switch (kind) {
		case DIR_FILTER_PREBOOT_ROOT:
			return preboot_root_entry_should_hide(name);
		case DIR_FILTER_PREBOOT_HASH_ROOT:
			return preboot_hash_root_entry_should_hide(name);
		default:
			return false;
	}
}

/*
 * Registrations are process-lifetime objects too.  An image event never needs
 * to malloc a callback snapshot, and a registering callback stays invisible
 * to live dispatch until its historical replay completes.  This is the same
 * important property HookKit has for hook transactions: publication is an
 * explicit state transition, not an append to an exposed array.
 */
typedef enum {
	HIDER_CALLBACK_REPLAYING = 0,
	HIDER_CALLBACK_ACTIVE,
	HIDER_CALLBACK_NATIVE,
} hider_callback_state_t;

typedef enum {
	HIDER_DYLD_CALLBACK_ADD = 0,
	HIDER_DYLD_CALLBACK_REMOVE,
} hider_dyld_callback_kind_t;

typedef struct hider_dyld_callback_registration {
	_Atomic(struct hider_dyld_callback_registration *) next;
	void (*func)(const struct mach_header *, intptr_t);
	hider_image_event_t *event_marker; /* Last event covered by replay. */
	uint64_t replay_boundary;
	hider_dyld_callback_kind_t kind;
	bool from_hidden;
	atomic_uint state;
	atomic_bool delivering;
	atomic_bool callback_invoking;
	atomic_bool recursive_event;
	atomic_bool queued_event;
} hider_dyld_callback_registration_t;

typedef struct hider_objc_callback_registration {
	_Atomic(struct hider_objc_callback_registration *) next;
	objc_func_loadImage func;
	hider_objc_event_t *event_marker;
	bool from_hidden;
	atomic_uint state;
	atomic_bool delivering;
	atomic_bool callback_invoking;
	atomic_bool recursive_event;
	atomic_bool queued_event;
} hider_objc_callback_registration_t;

/* Heads are acquire/release-published for emergency source delivery. Nodes
 * never move or free, so a relay which cannot take the catalog lock can still
 * walk a complete prefix without racing a registration's initialization. */
static _Atomic(hider_dyld_callback_registration_t *) g_dyld_callbacks = NULL;
static hider_dyld_callback_registration_t *g_dyld_callbacks_tail = NULL;
static _Atomic(hider_objc_callback_registration_t *) g_objc_callbacks = NULL;
static hider_objc_callback_registration_t *g_objc_callbacks_tail = NULL;
static hider_objc_event_t *g_objc_event_head = NULL;
static hider_objc_event_t *g_objc_event_tail = NULL;
static uint64_t g_objc_event_sequence = 0;

/*
 * task_info callers retain the returned dyld_all_image_infos pointer after
 * h_task_info returns.  A single mutable snapshot (and reallocating its
 * backing arrays) therefore creates use-after-realloc races.  Publish only
 * complete, process-lifetime generations.  If a new generation cannot be
 * copied coherently, every linked view degrades to dyld's original APIs.
 */
typedef struct task_snapshot_generation {
	struct dyld_all_image_infos snapshot;
	struct dyld_image_info *images;
	struct dyld_uuid_info *uuids;
	uint64_t image_generation;
	struct task_snapshot_generation *previous;
} task_snapshot_generation_t;

#define RHI_TASK_SNAPSHOT_COPY_ATTEMPTS 3U

static task_snapshot_generation_t *g_ti_current = NULL;
static uint64_t                     g_image_generation = 0;
static struct dyld_all_image_infos *g_real_aii = NULL;  // cached from first task_info call
static hider_tracking_state_t       g_image_tracking_state = HIDER_TRACKING_FILTERED;
typedef enum {
	HIDER_DELIVERY_FILTERED = 0,
	HIDER_DELIVERY_PASSTHROUGH,
} hider_delivery_route_t;
/* The bootstrap dyld/ObjC relays are permanent multiplexers. Filtering and
 * callback delivery are separate: once an invariant fails, public image views
 * become native while already-linked registrations receive raw live events
 * from those same relays. They are never post-hoc registered with dyld/ObjC. */
static atomic_uint                   g_callback_delivery_route = HIDER_DELIVERY_FILTERED;
static atomic_bool                   g_callback_delivery_failed;
static _Thread_local bool            g_hider_atfork_catalog_held;

typedef enum {
	HIDER_STATE_UNINITIALIZED = 0,
	HIDER_STATE_INITIALIZING,
	HIDER_STATE_READY,
	HIDER_STATE_FAILED,
} hider_state_t;

static atomic_uint g_init_state;
static atomic_uint g_strict_state;

static bool g_hook_objc_runtime_enabled = true;
static bool g_hook_objc_copy_class_list_enabled = true;
static bool g_hook_url_schemes_enabled = true;
static bool g_hook_environment_enabled = true;
static bool g_hook_filesystem_enabled = true;
static bool g_hook_directory_enabled = true;
static bool g_url_scheme_hooks_active = false;

/* Core is one all-or-nothing concealment view; strict hooks stay independent. */
static rhi_hider_hook_session_t g_core_hook_session = { .name = "hider-core", .required = true };
static rhi_hider_hook_session_t g_strict_class_image_session = { .name = "strict-class-image" };
static rhi_hider_hook_session_t g_strict_copy_images_session = { .name = "strict-copy-images" };
static rhi_hider_hook_session_t g_strict_copy_names_session = { .name = "strict-copy-names" };
static rhi_hider_hook_session_t g_strict_copy_class_list_session = { .name = "strict-copy-class-list" };
static rhi_hider_hook_session_t g_strict_add_load_session = { .name = "strict-add-load" };
static rhi_hider_hook_session_t g_strict_getenv_session = { .name = "strict-getenv" };
static rhi_hider_hook_session_t g_strict_access_session = { .name = "strict-access" };
static rhi_hider_hook_session_t g_strict_stat_session = { .name = "strict-stat" };
static rhi_hider_hook_session_t g_strict_lstat_session = { .name = "strict-lstat" };
static rhi_hider_hook_session_t g_strict_fopen_session = { .name = "strict-fopen" };
static rhi_hider_hook_session_t g_strict_opendir_session = { .name = "strict-opendir" };
static rhi_hider_hook_session_t g_strict_readdir_session = { .name = "strict-readdir" };
static rhi_hider_hook_session_t g_strict_closedir_session = { .name = "strict-closedir" };

static bool hider_is_ready(void) {
	return atomic_load_explicit(&g_init_state, memory_order_acquire) == HIDER_STATE_READY &&
	       rhi_hider_hook_session_is_ready(&g_core_hook_session);
}

static bool hider_strict_hooks_ready(void) {
	return hider_is_ready() &&
	       atomic_load_explicit(&g_strict_state, memory_order_acquire) == HIDER_STATE_READY;
}

/* Optional hooks are physically left in place after a late-image failure: a
 * guessed rollback is unsafe once arbitrary constructors can execute.  Each
 * replacement therefore consults its own live transaction state and forwards
 * stock behavior as soon as that component (or the linked core view) is no
 * longer verified. */
static bool hider_strict_hook_is_ready(const rhi_hider_hook_session_t *session,
	                                  const char *symbol)
{
	return hider_strict_hooks_ready() &&
	       rhi_hider_hook_session_hook_is_active(session, symbol);
}

/*
 * xpcproxy consumes the launchd policy before it bridges the real app. Keep a
 * canonical, allocation-free representation so the child inherits the same
 * effective hook profile.
 */
static char g_hider_bridge_profile[8] = "full";
static char g_hider_bridge_disabled[96] = {0};

// Cache the executable path for dladdr / class_getImageName substitution
static const char *g_executable_path = NULL;
static const struct mach_header *g_executable_header = NULL;

static bool hider_component_list_contains(const char *list, const char *needle) {
	if (!list || !needle || !needle[0]) return false;

	size_t needle_len = strlen(needle);
	const char *cursor = list;
	while (*cursor) {
		while (*cursor == ':' || *cursor == ',' || *cursor == ';' ||
		       *cursor == ' ' || *cursor == '\t' || *cursor == '\n')
			cursor++;

		const char *start = cursor;
		while (*cursor && *cursor != ':' && *cursor != ',' && *cursor != ';' &&
		       *cursor != ' ' && *cursor != '\t' && *cursor != '\n')
			cursor++;

		if ((size_t)(cursor - start) == needle_len && strncmp(start, needle, needle_len) == 0)
			return true;
	}

	return false;
}

static void disable_all_strict_profile_hooks(void) {
	g_hook_objc_runtime_enabled = false;
	g_hook_objc_copy_class_list_enabled = false;
	g_hook_url_schemes_enabled = false;
	g_hook_environment_enabled = false;
	g_hook_filesystem_enabled = false;
	g_hook_directory_enabled = false;
}

static void hider_bridge_append_disabled(const char *token) {
	if (!token || !token[0]) return;
	if (g_hider_bridge_disabled[0]) {
		strlcat(g_hider_bridge_disabled, ":", sizeof(g_hider_bridge_disabled));
	}
	strlcat(g_hider_bridge_disabled, token, sizeof(g_hider_bridge_disabled));
}

static void retain_effective_hider_profile_for_child(void) {
	g_hider_bridge_disabled[0] = '\0';
	strlcpy(g_hider_bridge_profile, "full", sizeof(g_hider_bridge_profile));

	if (!g_hook_objc_runtime_enabled && !g_hook_objc_copy_class_list_enabled &&
	    !g_hook_url_schemes_enabled && !g_hook_environment_enabled &&
	    !g_hook_filesystem_enabled && !g_hook_directory_enabled) {
		strlcpy(g_hider_bridge_profile, "core", sizeof(g_hider_bridge_profile));
		return;
	}
	if (!g_hook_objc_runtime_enabled) {
		hider_bridge_append_disabled("objc-runtime");
	}
	else if (!g_hook_objc_copy_class_list_enabled) {
		hider_bridge_append_disabled("objc-copy-class-list");
	}
	if (!g_hook_url_schemes_enabled) hider_bridge_append_disabled("url-schemes");
	if (!g_hook_environment_enabled) hider_bridge_append_disabled("environment");
	if (!g_hook_filesystem_enabled) hider_bridge_append_disabled("filesystem");
	else if (!g_hook_directory_enabled) hider_bridge_append_disabled("directory");
}

static void load_hider_profile_from_environment(void) {
	const char *profile = getenv("ROOTHIDE_HIDER_PROFILE");
	const char *disabled = getenv("ROOTHIDE_HIDER_DISABLED_HOOKS");

	if (profile && (!strcmp(profile, "core") || !strcmp(profile, "minimal"))) {
		disable_all_strict_profile_hooks();
	}
	else if (profile && !strcmp(profile, "lite")) {
		g_hook_objc_copy_class_list_enabled = false;
		g_hook_url_schemes_enabled = false;
	}

	if (hider_component_list_contains(disabled, "all-strict")) {
		disable_all_strict_profile_hooks();
	}
	if (hider_component_list_contains(disabled, "objc-runtime")) {
		g_hook_objc_runtime_enabled = false;
		g_hook_objc_copy_class_list_enabled = false;
	}
	if (hider_component_list_contains(disabled, "objc-copy-class-list") ||
	    hider_component_list_contains(disabled, "copy-class-list")) {
		g_hook_objc_copy_class_list_enabled = false;
	}
	if (hider_component_list_contains(disabled, "url-schemes") ||
	    hider_component_list_contains(disabled, "can-open-url")) {
		g_hook_url_schemes_enabled = false;
	}
	if (hider_component_list_contains(disabled, "environment") ||
	    hider_component_list_contains(disabled, "getenv")) {
		g_hook_environment_enabled = false;
	}
	if (hider_component_list_contains(disabled, "filesystem") ||
	    hider_component_list_contains(disabled, "fs")) {
		g_hook_filesystem_enabled = false;
		g_hook_directory_enabled = false;
	}
	if (hider_component_list_contains(disabled, "directory") ||
	    hider_component_list_contains(disabled, "dir")) {
		g_hook_directory_enabled = false;
	}

	retain_effective_hider_profile_for_child();

	unsetenv("ROOTHIDE_HIDER_PROFILE");
	unsetenv("ROOTHIDE_HIDER_DISABLED_HOOKS");
}

bool hidden_dylib_hider_envbuf_apply(char ***envc) {
	if (!envc || !*envc) return false;
	return envbuf_setenv(envc, "ROOTHIDE_HIDER_PROFILE", g_hider_bridge_profile)
		&& (g_hider_bridge_disabled[0]
			? envbuf_setenv(envc, "ROOTHIDE_HIDER_DISABLED_HOOKS", g_hider_bridge_disabled)
			: envbuf_unsetenv(envc, "ROOTHIDE_HIDER_DISABLED_HOOKS"));
}

//------------------------------------------------------------------------------
#pragma mark - Path Filter

// Determine if an image path should be hidden from the app.
// Visible to tweaks regardless.
static bool image_path_should_hide(const char *path) {
	if (!path || path[0] == '\0') return false;

	const char *base = strrchr(path, '/');
	if (base) base++; else base = path;

	// Always hide systemhook (e.g. /usr/lib/systemhook-9D1722053A2B61DD.dylib)
	if (strncmp(base, "systemhook-", 11) == 0 ||
	    strcmp(base, "systemhook.dylib") == 0)
		return true;

	// Hide anything under .jbroot — ALL of it.
	// The whitelist only controls which tweaks get LOADED (dlopen filtering),
	// not which are VISIBLE in image enumeration.  Even whitelisted tweaks
	// must be hidden from the app's _dyld_image_count / dladdr / etc.
	if (strstr(path, "/.jbroot-") || strstr(path, "/.jbroot/")) {
		return true;
	}

	// Known JB loader basenames that might appear outside .jbroot
	static const char *hidden_bases[] = {
		"TweakLoader.dylib",    "ellekit.dylib",
		"libellekit.dylib",     "MobileSubstrate.dylib",
		"CydiaSubstrate.dylib", "libsubstrate.dylib",
		"libsubstitute.dylib",  "SubstrateLoader.dylib",
		"substitute-loader.dylib",
		"roothideinit.dylib",   "roothidepatch.dylib",
		"libroothide.dylib",    "libroot.dylib",
		NULL
	};
	for (int i = 0; hidden_bases[i]; i++) {
		if (strcmp(base, hidden_bases[i]) == 0)
			return true;
	}

	return false;
}

//------------------------------------------------------------------------------
#pragma mark - Caller Check

/*
 * Image concealment intentionally remains path based, but hidden-view access
 * is capability based.  Only systemhook itself, explicitly authorized selected
 * tweaks, and a narrowly scoped internal RootHide operation receive truth.
 * Unknown callers are external by default.
 */
static bool caller_is_hidden(const void *ra) {
	return rhi_hider_caller_can_read_hidden(ra);
}

//------------------------------------------------------------------------------
#pragma mark - dyld Notification Callbacks (registered before hooking)

static bool hider_tracking_is_filtered_locked(void) {
	return g_image_tracking_state == HIDER_TRACKING_FILTERED;
}

/* Catalog delivery is only valid while both the public view and permanent
 * relay route are filtered.  After pass-through starts, source callbacks use
 * their live raw data directly and catalog records are no longer dereferenced
 * for user delivery. */
static bool hider_tracking_can_dispatch_locked(void) {
	return g_image_tracking_state == HIDER_TRACKING_FILTERED &&
	       atomic_load_explicit(&g_callback_delivery_route, memory_order_acquire) ==
		       HIDER_DELIVERY_FILTERED;
}

static char *catalog_copy_path(const char *path) {
	if (!path) {
		return NULL;
	}
	size_t length = strnlen(path, PATH_MAX);
	if (length == PATH_MAX || length == SIZE_MAX) {
		return NULL;
	}
	char *copy = malloc(length + 1);
	if (!copy) {
		return NULL;
	}
	memcpy(copy, path, length);
	copy[length] = '\0';
	return copy;
}

static bool catalog_copy_uuid(const struct mach_header *header, intptr_t slide, uint8_t uuid_out[16]) {
	if (!header || !uuid_out) {
		return false;
	}
	uintptr_t text_start = 0;
	uintptr_t text_end = 0;
	if (!rhi_hider_identity_image_text_range(header, slide, &text_start, &text_end)) {
		return false;
	}
	const struct mach_header_64 *header64 = (const struct mach_header_64 *)header;
	if (header64->magic != MH_MAGIC_64) {
		return false;
	}
	const uint8_t *cursor = (const uint8_t *)(header64 + 1);
	const uint8_t *end = cursor + header64->sizeofcmds;
	for (uint32_t index = 0; index < header64->ncmds; index++) {
		if ((size_t)(end - cursor) < sizeof(struct load_command)) {
			return false;
		}
		const struct load_command *command = (const struct load_command *)cursor;
		if (command->cmdsize < sizeof(*command) || (size_t)(end - cursor) < command->cmdsize) {
			return false;
		}
		if (command->cmd == LC_UUID && command->cmdsize >= sizeof(struct uuid_command)) {
			memcpy(uuid_out, ((const struct uuid_command *)command)->uuid, 16);
			return true;
		}
		cursor += command->cmdsize;
	}
	return false;
}

static hider_image_record_t *catalog_create_record(const char *path,
	                                                  const struct mach_header *mh,
	                                                  intptr_t slide) {
	hider_image_record_t *record = calloc(1, sizeof(*record));
	if (!record) {
		return NULL;
	}
	if (path) {
		record->path = catalog_copy_path(path);
		if (!record->path) {
			free(record);
			return NULL;
		}
	}
	record->header = mh;
	record->slide = slide;
	record->hidden = image_path_should_hide(path);
	record->uuid_valid = catalog_copy_uuid(mh, slide, record->uuid);
	return record;
}

static hider_image_record_t *catalog_find_active_locked(const struct mach_header *mh,
	                                                        intptr_t slide) {
	for (hider_image_record_t *record = g_catalog_head; record; record = record->next) {
		if (record->active && record->header == mh && record->slide == slide) {
			return record;
		}
	}
	return NULL;
}

static bool catalog_append_event_locked(hider_image_event_t *event,
	                                       hider_image_record_t *record,
	                                       hider_image_event_kind_t kind) {
	if (!event || !record || g_image_event_sequence == UINT64_MAX) {
		return false;
	}
	event->record = record;
	event->kind = kind;
	event->sequence = ++g_image_event_sequence;
	if (kind == HIDER_IMAGE_EVENT_ADD) {
		record->added_event = event->sequence;
	} else {
		record->removed_event = event->sequence;
	}
	if (g_image_event_tail) {
		g_image_event_tail->next = event;
	} else {
		g_image_event_head = event;
	}
	g_image_event_tail = event;
	return true;
}

static bool catalog_record_visible_to(const hider_image_record_t *record, bool from_hidden) {
	return record && (from_hidden || !record->hidden);
}

static uint32_t catalog_active_count_locked(bool include_hidden) {
	uint32_t count = 0;
	for (hider_image_record_t *record = g_catalog_head; record; record = record->next) {
		if (record->active && catalog_record_visible_to(record, include_hidden)) {
			if (count == UINT32_MAX) {
				return UINT32_MAX;
			}
			count++;
		}
	}
	return count;
}

static hider_image_record_t *catalog_active_at_index_locked(uint32_t index, bool include_hidden) {
	for (hider_image_record_t *record = g_catalog_head; record; record = record->next) {
		if (!record->active || !catalog_record_visible_to(record, include_hidden)) {
			continue;
		}
		if (index == 0) {
			return record;
		}
		index--;
	}
	return NULL;
}

static void hider_degrade_to_native(void);

bool hidden_dylib_hider_catalog_snapshot(rhi_hider_catalog_snapshot_t *snapshot_out) {
	if (!snapshot_out) {
		return false;
	}
	memset(snapshot_out, 0, sizeof(*snapshot_out));

	uint32_t count = 0;
	size_t path_bytes = 0;
	uint64_t generation = 0;
	os_unfair_lock_lock(&g_lock);
	if (!hider_tracking_is_filtered_locked()) {
		os_unfair_lock_unlock(&g_lock);
		return false;
	}
	for (hider_image_record_t *record = g_catalog_head; record; record = record->next) {
		if (!record->active || count == UINT32_MAX) {
			if (count == UINT32_MAX) {
				os_unfair_lock_unlock(&g_lock);
				hider_degrade_to_native();
				return false;
			}
			continue;
		}
		size_t length = record->path ? strnlen(record->path, PATH_MAX) : 0;
		if (length == PATH_MAX || length > SIZE_MAX - path_bytes - 1) {
			os_unfair_lock_unlock(&g_lock);
			hider_degrade_to_native();
			return false;
		}
		path_bytes += length + 1;
		count++;
	}
	generation = g_image_generation;
	os_unfair_lock_unlock(&g_lock);

	if (count && ((size_t)count > (SIZE_MAX - path_bytes) / sizeof(rhi_hider_catalog_image_t))) {
		hider_degrade_to_native();
		return false;
	}
	size_t allocation_size = (size_t)count * sizeof(rhi_hider_catalog_image_t) + path_bytes;
	rhi_hider_catalog_image_t *images = allocation_size ? calloc(1, allocation_size) : NULL;
	if (allocation_size && !images) {
		hider_degrade_to_native();
		return false;
	}
	char *path_cursor = images ? (char *)(images + count) : NULL;

	os_unfair_lock_lock(&g_lock);
	if (!hider_tracking_is_filtered_locked() || g_image_generation != generation) {
		os_unfair_lock_unlock(&g_lock);
		free(images);
		return false;
	}
	uint32_t index = 0;
	for (hider_image_record_t *record = g_catalog_head; record; record = record->next) {
		if (!record->active) {
			continue;
		}
		rhi_hider_catalog_image_t *image = &images[index++];
		image->header = record->header;
		image->slide = record->slide;
		image->identity = record->identity;
		image->uuid_valid = record->uuid_valid;
		image->main_executable = record->header == g_executable_header;
		memcpy(image->uuid, record->uuid, sizeof(image->uuid));
		if (record->path) {
			size_t length = strlen(record->path);
			memcpy(path_cursor, record->path, length + 1);
			image->path = path_cursor;
			path_cursor += length + 1;
		}
	}
	os_unfair_lock_unlock(&g_lock);
	snapshot_out->images = images;
	snapshot_out->count = count;
	snapshot_out->generation = generation;
	return true;
}

void hidden_dylib_hider_catalog_snapshot_dispose(rhi_hider_catalog_snapshot_t *snapshot) {
	if (!snapshot) {
		return;
	}
	free(snapshot->images);
	memset(snapshot, 0, sizeof(*snapshot));
}

bool hidden_dylib_hider_catalog_generation_is_current(uint64_t generation) {
	os_unfair_lock_lock(&g_lock);
	bool current = hider_tracking_is_filtered_locked() && g_image_generation == generation;
	os_unfair_lock_unlock(&g_lock);
	return current;
}

static bool catalog_was_active_at(const hider_image_record_t *record, uint64_t boundary) {
	return record && record->added_event && record->added_event <= boundary &&
	       (!record->removed_event || record->removed_event > boundary);
}

static bool hider_dispatch_passthrough_dyld_event(hider_dyld_callback_kind_t kind,
	                                                const struct mach_header *mh,
	                                                intptr_t slide);
static bool hider_dispatch_passthrough_objc_event(const struct mach_header *mh);

/* Fork never clones an active worker: bootstrap relays are the only delivery
 * mechanism. Fence catalog/registration publication in prepare; a child then
 * chooses raw passthrough for the process lifetime, avoiding inherited locks
 * or an incomplete filtered catalog. */
static void hider_catalog_atfork_prepare(void) {
	os_unfair_lock_lock(&g_lock);
	g_hider_atfork_catalog_held = true;
}

static void hider_catalog_atfork_parent(void) {
	if (g_hider_atfork_catalog_held) {
		g_hider_atfork_catalog_held = false;
		os_unfair_lock_unlock(&g_lock);
	}
}

static void hider_catalog_atfork_child(void) {
	g_image_tracking_state = HIDER_TRACKING_NATIVE;
	atomic_store_explicit(&g_callback_delivery_route, HIDER_DELIVERY_PASSTHROUGH,
	                      memory_order_release);
	g_hider_atfork_catalog_held = false;
	os_unfair_lock_unlock(&g_lock);
}

/* Permanent bootstrap relays multiplex existing registrations. Once filtering
 * cannot be kept coherent, public image APIs switch to their originals and the
 * relays switch to raw live passthrough. No retained callback is registered
 * with an original API after the fact. */
static void hider_degrade_to_native(void) {
	os_unfair_lock_lock(&g_lock);
	if (g_image_tracking_state == HIDER_TRACKING_FILTERED) {
		g_image_tracking_state = HIDER_TRACKING_DEGRADING;
		g_image_generation++;
	}
	atomic_store_explicit(&g_callback_delivery_route, HIDER_DELIVERY_PASSTHROUGH,
	                      memory_order_release);
	/* There is no deferred callback migration: the permanent relay is already
	 * installed.  Complete the state transition while publication is fenced so
	 * all public image APIs immediately delegate to native dyld. */
	g_image_tracking_state = HIDER_TRACKING_NATIVE;
	os_unfair_lock_unlock(&g_lock);
}

/* A raw source callback can only be delivered exactly once while its header is
 * live. If a registration is replaying or already executing, attempting a
 * later catch-up would either reverse ordering or dereference an unloaded
 * header. Stop advertising hider readiness rather than hide that loss behind
 * a best-effort route switch. This is deliberately callable from either
 * source lane: it never waits, invokes an original registration, or runs user
 * code while holding g_lock. */
static void hider_callback_fail_stop(void) {
	atomic_store_explicit(&g_callback_delivery_failed, true, memory_order_release);
	hider_degrade_to_native();
	atomic_store_explicit(&g_init_state, HIDER_STATE_FAILED, memory_order_release);
}

typedef struct {
	void *handle;
} hider_callback_pin_t;

static void hider_callback_pin_release(hider_callback_pin_t *pin) {
	if (!pin || !pin->handle) {
		return;
	}
	if (orig_dlclose) {
		hider_loader_error_preserve_for_internal_call();
		if (orig_dlclose(pin->handle) != 0) {
			hider_loader_error_consume_internal_failure();
		}
	}
	pin->handle = NULL;
}

static bool hider_callback_pin_acquire(const hider_image_record_t *record,
	                                      hider_callback_pin_t *pin) {
	if (!record || !pin || !orig_dlopen || !orig_dlclose) {
		return false;
	}
	memset(pin, 0, sizeof(*pin));
	uint64_t identity = 0;
	uint64_t generation = 0;
	bool main_executable = false;
	const char *path = NULL;
	os_unfair_lock_lock(&g_lock);
	bool valid = hider_tracking_can_dispatch_locked() && record->active;
	if (valid) {
		identity = record->identity;
		generation = g_image_generation;
		main_executable = record->header == g_executable_header;
		path = record->path;
		valid = main_executable || path != NULL;
	}
	os_unfair_lock_unlock(&g_lock);
	if (!valid) {
		return false;
	}

	/* A pin is deliberately per delivery. RTLD_NOLOAD cannot introduce a new
	 * image; NULL is the only valid handle acquisition for the main executable.
	 * Preserve a prior caller error in TLS before this loader operation, then
	 * consume a failed bookkeeping error so neither case leaks through h_dlerror.
	 * A failed pin still fail-stops/degrades without exposing this record. */
	hider_loader_error_preserve_for_internal_call();
	pin->handle = orig_dlopen(main_executable ? NULL : path,
	                         RTLD_LAZY | (main_executable ? 0 : RTLD_NOLOAD));
	if (!pin->handle) {
		hider_loader_error_consume_internal_failure();
		return false;
	}

	os_unfair_lock_lock(&g_lock);
	valid = hider_tracking_can_dispatch_locked() && record->active &&
	        record->identity == identity && g_image_generation == generation;
	os_unfair_lock_unlock(&g_lock);
	if (!valid) {
		hider_callback_pin_release(pin);
		return false;
	}
	return true;
}

static bool hider_call_dyld_callback(hider_dyld_callback_registration_t *registration,
	                                    const hider_image_event_t *event,
	                                    bool native_notification_lane) {
	if (!registration || !event || !event->record || !registration->func) {
		return false;
	}
	if (!catalog_record_visible_to(event->record, registration->from_hidden)) {
		return true;
	}
	hider_callback_pin_t pin = {0};
	if (!native_notification_lane && !hider_callback_pin_acquire(event->record, &pin)) {
		return false;
	}
	atomic_store_explicit(&registration->callback_invoking, true, memory_order_release);
	registration->func(event->record->header, event->record->slide);
	atomic_store_explicit(&registration->callback_invoking, false, memory_order_release);
	if (!native_notification_lane) {
		hider_callback_pin_release(&pin);
	}
	return true;
}

/* Raw pass-through never queues a native event: remove has no historical
 * replay, and a header is only guaranteed mapped until this source relay
 * returns. Registrations are append-only and acquire/release-published, so
 * this walk has no catalog lock, allocation, pin, or loader re-entry. ACTIVE
 * callbacks receive the exact live event in order. A REPLAYING/delivering node
 * is an unavoidable ordering ambiguity; record fail-stop rather than invoke a
 * stale remove after its historical replay. */
static bool hider_dispatch_passthrough_dyld_event(hider_dyld_callback_kind_t kind,
	                                                const struct mach_header *mh,
	                                                intptr_t slide) {
	if (atomic_load_explicit(&g_callback_delivery_failed, memory_order_acquire)) {
		return false;
	}
	bool ordered = true;
	const char *path = mh ? dyld_image_path_containing_address(mh) : NULL;
	bool hidden = image_path_should_hide(path);
	hider_dyld_callback_registration_t *registration =
		atomic_load_explicit(&g_dyld_callbacks, memory_order_acquire);
	for (; registration;
	     registration = atomic_load_explicit(&registration->next, memory_order_acquire)) {
		if (registration->kind != kind) {
			continue;
		}
		unsigned state = atomic_load_explicit(&registration->state, memory_order_acquire);
		if (state != HIDER_CALLBACK_ACTIVE) {
			ordered = false;
			continue;
		}
		bool expected = false;
		if (!atomic_compare_exchange_strong_explicit(&registration->delivering, &expected, true,
		                                             memory_order_acq_rel, memory_order_acquire)) {
			ordered = false;
			continue;
		}
		if (registration->from_hidden || !hidden) {
			atomic_store_explicit(&registration->callback_invoking, true, memory_order_release);
			registration->func(mh, slide);
			atomic_store_explicit(&registration->callback_invoking, false, memory_order_release);
		}
		if (atomic_exchange_explicit(&registration->recursive_event, false, memory_order_acq_rel)) {
			ordered = false;
		}
		atomic_store_explicit(&registration->delivering, false, memory_order_release);
	}
	if (!ordered) hider_callback_fail_stop();
	return ordered;
}

static bool hider_dispatch_dyld_event_to_registration(hider_dyld_callback_registration_t *registration,
	                                                      hider_image_event_t *event) {
	if (!registration || !event) {
		return true;
	}
	unsigned state = atomic_load_explicit(&registration->state, memory_order_acquire);
	if (state != HIDER_CALLBACK_ACTIVE && state != HIDER_CALLBACK_REPLAYING) {
		return true;
	}
	bool expected = false;
	if (!atomic_compare_exchange_strong_explicit(&registration->delivering, &expected, true,
	                                             memory_order_acq_rel, memory_order_acquire)) {
		atomic_store_explicit(&registration->queued_event, true, memory_order_release);
		if (atomic_load_explicit(&registration->callback_invoking, memory_order_acquire)) {
			atomic_store_explicit(&registration->recursive_event, true, memory_order_release);
		}
		/* A queued remove cannot outlive this source callback. The caller stops
		 * readiness instead of later replaying an unmapped header. */
		return event->kind != HIDER_IMAGE_EVENT_REMOVE;
	}

	bool usable = false;
	os_unfair_lock_lock(&g_lock);
	usable = hider_tracking_can_dispatch_locked() &&
	         (event->kind == HIDER_IMAGE_EVENT_REMOVE || event->record->active);
	os_unfair_lock_unlock(&g_lock);
	if (!usable) {
		atomic_store_explicit(&registration->delivering, false, memory_order_release);
		return false;
	}

	if (!hider_call_dyld_callback(registration, event, true)) {
		atomic_store_explicit(&registration->delivering, false, memory_order_release);
		return false;
	}
	bool recursive = atomic_exchange_explicit(&registration->recursive_event, false, memory_order_acq_rel);
	atomic_store_explicit(&registration->delivering, false, memory_order_release);
	if (recursive) {
		/* A nested callback would otherwise be delivered after its caller
		 * returned. That reverses dyld ordering; the caller fail-stops. */
		return false;
	}
	return true;
}

static bool hider_dispatch_dyld_event(hider_image_event_t *event) {
	hider_dyld_callback_registration_t *registration = NULL;
	for (;;) {
		os_unfair_lock_lock(&g_lock);
		registration = registration
			? atomic_load_explicit(&registration->next, memory_order_acquire)
			: atomic_load_explicit(&g_dyld_callbacks, memory_order_acquire);
		os_unfair_lock_unlock(&g_lock);
		if (!registration) {
			break;
		}
		if (!hider_dispatch_dyld_event_to_registration(registration, event)) {
			return false;
		}
	}
	return true;
}

static bool hider_complete_dyld_add_replay(hider_dyld_callback_registration_t *registration) {
	if (!registration) {
		return false;
	}
	atomic_store_explicit(&registration->delivering, true, memory_order_release);

	/* Historical replay is selected by the catalog boundary captured while the
	 * registration was still REPLAYING.  A record removed after that boundary
	 * is never dereferenced: that is the only safe response to immediate
	 * load/unload recursion before the replay reaches it. */
	hider_image_record_t *record = NULL;
	for (;;) {
		bool historical = false;
		bool active = false;
		bool dispatchable = false;
		os_unfair_lock_lock(&g_lock);
		record = record ? record->next : g_catalog_head;
		if (!record) {
			os_unfair_lock_unlock(&g_lock);
			break;
		}
		historical = catalog_was_active_at(record, registration->replay_boundary);
		active = record->active;
		dispatchable = hider_tracking_can_dispatch_locked();
		os_unfair_lock_unlock(&g_lock);
		if (!dispatchable) {
			atomic_store_explicit(&registration->delivering, false, memory_order_release);
			hider_degrade_to_native();
			return false;
		}
		if (!historical) {
			continue;
		}
		if (!active) {
			atomic_store_explicit(&registration->delivering, false, memory_order_release);
			hider_degrade_to_native();
			return false;
		}
		hider_image_event_t replay_event = {
			.record = record,
			.kind = HIDER_IMAGE_EVENT_ADD,
		};
		if (!hider_call_dyld_callback(registration, &replay_event, false)) {
			atomic_store_explicit(&registration->delivering, false, memory_order_release);
			hider_degrade_to_native();
			return false;
		}
		if (atomic_exchange_explicit(&registration->recursive_event, false, memory_order_acq_rel)) {
			atomic_store_explicit(&registration->delivering, false, memory_order_release);
			hider_degrade_to_native();
			return false;
		}
	}

	/* Publish only after every historical image was delivered.  Events appended
	 * during replay are then drained in catalog order; a deferred removal is a
	 * stale-header risk and intentionally forces native fallback. */
	os_unfair_lock_lock(&g_lock);
	bool dispatchable = hider_tracking_can_dispatch_locked();
	hider_image_event_t *tail = g_image_event_tail;
	if (dispatchable) {
		/* The lock makes REPLAYING -> ACTIVE and the queue boundary one
		 * publication. Events before it are drained below; events after it see
		 * ACTIVE and either queue behind this delivery or dispatch afterwards. */
		atomic_store_explicit(&registration->state, HIDER_CALLBACK_ACTIVE, memory_order_release);
	}
	os_unfair_lock_unlock(&g_lock);
	if (!dispatchable) {
		atomic_store_explicit(&registration->delivering, false, memory_order_release);
		hider_degrade_to_native();
		return false;
	}
	hider_image_event_t *event = registration->event_marker;
	for (;;) {
		os_unfair_lock_lock(&g_lock);
		event = event ? event->next : g_image_event_head;
		if (!event) {
			if (g_image_event_tail == tail &&
			    !atomic_load_explicit(&registration->queued_event, memory_order_acquire)) {
				atomic_store_explicit(&registration->delivering, false, memory_order_release);
				os_unfair_lock_unlock(&g_lock);
				return true;
			}
			tail = g_image_event_tail;
			atomic_store_explicit(&registration->queued_event, false, memory_order_release);
			os_unfair_lock_unlock(&g_lock);
			continue;
		}
		bool active = event->record->active;
		os_unfair_lock_unlock(&g_lock);
		if (event->kind == HIDER_IMAGE_EVENT_REMOVE || !active) {
			atomic_store_explicit(&registration->delivering, false, memory_order_release);
			hider_degrade_to_native();
			return false;
		}
		if (!hider_call_dyld_callback(registration, event, false)) {
			atomic_store_explicit(&registration->delivering, false, memory_order_release);
			hider_degrade_to_native();
			return false;
		}
		if (atomic_exchange_explicit(&registration->recursive_event, false, memory_order_acq_rel)) {
			atomic_store_explicit(&registration->delivering, false, memory_order_release);
			hider_degrade_to_native();
			return false;
		}
		if (event == tail) {
			os_unfair_lock_lock(&g_lock);
			if (g_image_event_tail == tail &&
			    !atomic_load_explicit(&registration->queued_event, memory_order_acquire)) {
				atomic_store_explicit(&registration->delivering, false, memory_order_release);
				os_unfair_lock_unlock(&g_lock);
				return true;
			}
			tail = g_image_event_tail;
			atomic_store_explicit(&registration->queued_event, false, memory_order_release);
			os_unfair_lock_unlock(&g_lock);
		}
	}
}

static bool hider_call_objc_callback(hider_objc_callback_registration_t *registration,
	                                  const hider_objc_event_t *event,
	                                  bool native_notification_lane) {
	if (!registration || !event || !event->record || !registration->func) {
		return false;
	}
	if (!catalog_record_visible_to(event->record, registration->from_hidden)) {
		return true;
	}
	hider_callback_pin_t pin = {0};
	if (!native_notification_lane && !hider_callback_pin_acquire(event->record, &pin)) {
		return false;
	}
	atomic_store_explicit(&registration->callback_invoking, true, memory_order_release);
	registration->func(event->record->header);
	atomic_store_explicit(&registration->callback_invoking, false, memory_order_release);
	if (!native_notification_lane) {
		hider_callback_pin_release(&pin);
	}
	return true;
}

/* ObjC delivery has the same live-header rule as dyld, but its timing lane is
 * separate: this is called only from the real objc_addLoadImageFunc relay. */
static bool hider_dispatch_passthrough_objc_event(const struct mach_header *mh) {
	if (atomic_load_explicit(&g_callback_delivery_failed, memory_order_acquire)) {
		return false;
	}
	bool ordered = true;
	const char *path = mh ? dyld_image_path_containing_address(mh) : NULL;
	bool hidden = image_path_should_hide(path);
	hider_objc_callback_registration_t *registration =
		atomic_load_explicit(&g_objc_callbacks, memory_order_acquire);
	for (; registration;
	     registration = atomic_load_explicit(&registration->next, memory_order_acquire)) {
		unsigned state = atomic_load_explicit(&registration->state, memory_order_acquire);
		if (state != HIDER_CALLBACK_ACTIVE) {
			ordered = false;
			continue;
		}
		bool expected = false;
		if (!atomic_compare_exchange_strong_explicit(&registration->delivering, &expected, true,
		                                             memory_order_acq_rel, memory_order_acquire)) {
			ordered = false;
			continue;
		}
		if (registration->from_hidden || !hidden) {
			atomic_store_explicit(&registration->callback_invoking, true, memory_order_release);
			registration->func(mh);
			atomic_store_explicit(&registration->callback_invoking, false, memory_order_release);
		}
		if (atomic_exchange_explicit(&registration->recursive_event, false, memory_order_acq_rel)) {
			ordered = false;
		}
		atomic_store_explicit(&registration->delivering, false, memory_order_release);
	}
	if (!ordered) hider_callback_fail_stop();
	return ordered;
}

static bool hider_dispatch_objc_event_to_registration(hider_objc_callback_registration_t *registration,
	                                                     hider_objc_event_t *event) {
	if (!registration || !event || !event->record) {
		return true;
	}
	unsigned state = atomic_load_explicit(&registration->state, memory_order_acquire);
	if (state != HIDER_CALLBACK_ACTIVE && state != HIDER_CALLBACK_REPLAYING) {
		return true;
	}
	bool expected = false;
	if (!atomic_compare_exchange_strong_explicit(&registration->delivering, &expected, true,
	                                             memory_order_acq_rel, memory_order_acquire)) {
		atomic_store_explicit(&registration->queued_event, true, memory_order_release);
		if (atomic_load_explicit(&registration->callback_invoking, memory_order_acquire)) {
			atomic_store_explicit(&registration->recursive_event, true, memory_order_release);
		}
		return false;
	}
	os_unfair_lock_lock(&g_lock);
	bool usable = hider_tracking_can_dispatch_locked() && event->record->active;
	os_unfair_lock_unlock(&g_lock);
	if (!usable) {
		atomic_store_explicit(&registration->delivering, false, memory_order_release);
		return false;
	}
	if (!hider_call_objc_callback(registration, event, true)) {
		atomic_store_explicit(&registration->delivering, false, memory_order_release);
		return false;
	}
	bool recursive = atomic_exchange_explicit(&registration->recursive_event, false, memory_order_acq_rel);
	atomic_store_explicit(&registration->delivering, false, memory_order_release);
	if (recursive) {
		return false;
	}
	return true;
}

static bool hider_dispatch_objc_event(hider_objc_event_t *event) {
	hider_objc_callback_registration_t *registration = NULL;
	for (;;) {
		os_unfair_lock_lock(&g_lock);
		registration = registration
			? atomic_load_explicit(&registration->next, memory_order_acquire)
			: atomic_load_explicit(&g_objc_callbacks, memory_order_acquire);
		os_unfair_lock_unlock(&g_lock);
		if (!registration) {
			break;
		}
		if (!hider_dispatch_objc_event_to_registration(registration, event)) {
			return false;
		}
	}
	return true;
}

static bool hider_complete_objc_replay(hider_objc_callback_registration_t *registration) {
	if (!registration) {
		return false;
	}
	atomic_store_explicit(&registration->delivering, true, memory_order_release);
	/* This lane is populated only by the real objc runtime relay below.  Do not
	 * synthesize objc callbacks from dyld add-image notifications. */
	hider_objc_event_t *event = NULL;
	for (;;) {
		os_unfair_lock_lock(&g_lock);
		event = event ? event->next : g_objc_event_head;
		if (!event) {
			os_unfair_lock_unlock(&g_lock);
			break;
		}
		bool active = event->record->active;
		os_unfair_lock_unlock(&g_lock);
		if (registration->event_marker && event->sequence > registration->event_marker->sequence) {
			break;
		}
		if (!active) {
			continue;
		}
		if (!hider_call_objc_callback(registration, event, false)) {
			atomic_store_explicit(&registration->delivering, false, memory_order_release);
			hider_degrade_to_native();
			return false;
		}
		if (atomic_exchange_explicit(&registration->recursive_event, false, memory_order_acq_rel)) {
			atomic_store_explicit(&registration->delivering, false, memory_order_release);
			hider_degrade_to_native();
			return false;
		}
	}
	os_unfair_lock_lock(&g_lock);
	bool dispatchable = hider_tracking_can_dispatch_locked();
	hider_objc_event_t *tail = g_objc_event_tail;
	if (dispatchable) {
		atomic_store_explicit(&registration->state, HIDER_CALLBACK_ACTIVE, memory_order_release);
	}
	os_unfair_lock_unlock(&g_lock);
	if (!dispatchable) {
		atomic_store_explicit(&registration->delivering, false, memory_order_release);
		hider_degrade_to_native();
		return false;
	}
	event = registration->event_marker;
	for (;;) {
		os_unfair_lock_lock(&g_lock);
		event = event ? event->next : g_objc_event_head;
		if (!event) {
			if (g_objc_event_tail == tail &&
			    !atomic_load_explicit(&registration->queued_event, memory_order_acquire)) {
				atomic_store_explicit(&registration->delivering, false, memory_order_release);
				os_unfair_lock_unlock(&g_lock);
				return true;
			}
			tail = g_objc_event_tail;
			atomic_store_explicit(&registration->queued_event, false, memory_order_release);
			os_unfair_lock_unlock(&g_lock);
			continue;
		}
		bool active = event->record->active;
		os_unfair_lock_unlock(&g_lock);
		if (!active) {
			atomic_store_explicit(&registration->delivering, false, memory_order_release);
			hider_degrade_to_native();
			return false;
		}
		if (!hider_call_objc_callback(registration, event, false)) {
			atomic_store_explicit(&registration->delivering, false, memory_order_release);
			hider_degrade_to_native();
			return false;
		}
		if (atomic_exchange_explicit(&registration->recursive_event, false, memory_order_acq_rel)) {
			atomic_store_explicit(&registration->delivering, false, memory_order_release);
			hider_degrade_to_native();
			return false;
		}
		if (event == tail) {
			os_unfair_lock_lock(&g_lock);
			if (g_objc_event_tail == tail &&
			    !atomic_load_explicit(&registration->queued_event, memory_order_acquire)) {
				atomic_store_explicit(&registration->delivering, false, memory_order_release);
				os_unfair_lock_unlock(&g_lock);
				return true;
			}
			tail = g_objc_event_tail;
			atomic_store_explicit(&registration->queued_event, false, memory_order_release);
			os_unfair_lock_unlock(&g_lock);
		}
	}
}

static void on_image_added(const struct mach_header *mh, intptr_t slide) {
	/* Caller capability ranges outlive filtered catalog tracking. Invalidate
	 * them for every native event, including permanent pass-through. */
	rhi_hider_caller_image_added(mh, slide);
	/* The bootstrap relay is permanent.  Once public image views have fallen
	 * back to dyld, deliver this exact live event through the same relay rather
	 * than attempting an unsafe second registration with dyld. */
	if (atomic_load_explicit(&g_callback_delivery_route, memory_order_acquire) ==
	    HIDER_DELIVERY_PASSTHROUGH) {
		(void)hider_dispatch_passthrough_dyld_event(HIDER_DYLD_CALLBACK_ADD, mh, slide);
		return;
	}
	const char *path = dyld_image_path_containing_address(mh);
	hider_image_record_t *record = catalog_create_record(path, mh, slide);
	if (!record) {
		/* No catalog identity can be manufactured after OOM.  Switch public
		 * views to native, then forward the transition-causing live event before
		 * this dyld callback returns. */
		hider_degrade_to_native();
		(void)hider_dispatch_passthrough_dyld_event(HIDER_DYLD_CALLBACK_ADD, mh, slide);
		return;
	}

	os_unfair_lock_lock(&g_lock);
	bool dispatchable = hider_tracking_can_dispatch_locked() && g_image_identity_sequence != UINT64_MAX;
	if (dispatchable) {
		record->identity = ++g_image_identity_sequence;
		record->active = true;
		if (g_catalog_tail) {
			g_catalog_tail->next = record;
		} else {
			g_catalog_head = record;
		}
		g_catalog_tail = record;
		dispatchable = catalog_append_event_locked(&record->add_event, record, HIDER_IMAGE_EVENT_ADD);
		if (dispatchable) g_image_generation++;
		record->added_generation = g_image_generation;
	}
	os_unfair_lock_unlock(&g_lock);
	if (!dispatchable) {
		/* The record is intentionally retained if it was already linked; catalog
		 * identity remains inspectable even while views fall back to native. */
		if (!record->active) {
			free(record->path);
			free(record);
		}
		hider_degrade_to_native();
		(void)hider_dispatch_passthrough_dyld_event(HIDER_DYLD_CALLBACK_ADD, mh, slide);
		return;
	}
	if (!hider_dispatch_dyld_event(&record->add_event)) {
		/* Some registrations may already have seen the filtered event. A raw
		 * re-drive would duplicate them, so terminally fail closed instead. */
		hider_callback_fail_stop();
	}
}

static void on_image_removed(const struct mach_header *mh, intptr_t slide) {
	/* Keep the exact-range cache coherent after filtering has fallen back to
	 * native dyld; a stale authorized range is not acceptable in pass-through. */
	rhi_hider_caller_image_removed(mh, slide);
	if (atomic_load_explicit(&g_callback_delivery_route, memory_order_acquire) ==
	    HIDER_DELIVERY_PASSTHROUGH) {
		(void)hider_dispatch_passthrough_dyld_event(HIDER_DYLD_CALLBACK_REMOVE, mh, slide);
		return;
	}
	os_unfair_lock_lock(&g_lock);
	hider_image_record_t *record = hider_tracking_can_dispatch_locked()
		? catalog_find_active_locked(mh, slide) : NULL;
	bool dispatchable = record != NULL;
	if (dispatchable) {
		record->active = false;
		dispatchable = catalog_append_event_locked(&record->remove_event, record, HIDER_IMAGE_EVENT_REMOVE);
		if (dispatchable) g_image_generation++;
	}
	os_unfair_lock_unlock(&g_lock);
	if (!dispatchable) {
		/* A remove header stays valid only in this source callback.  The raw
		 * permanent relay is therefore invoked synchronously, never queued. */
		hider_degrade_to_native();
		(void)hider_dispatch_passthrough_dyld_event(HIDER_DYLD_CALLBACK_REMOVE, mh, slide);
		return;
	}
	if (!hider_dispatch_dyld_event(&record->remove_event)) {
		hider_callback_fail_stop();
	}
}

static void on_objc_image_loaded(const struct mach_header *mh) {
	if (atomic_load_explicit(&g_callback_delivery_route, memory_order_acquire) ==
	    HIDER_DELIVERY_PASSTHROUGH) {
		(void)hider_dispatch_passthrough_objc_event(mh);
		return;
	}
	/* objc_addLoadImageFunc is a distinct runtime timing lane.  The relay was
	 * registered with the original API, so every event below has runtime (not
	 * dyld) ordering. */
	const char *runtime_path = dyld_image_path_containing_address(mh);
	os_unfair_lock_lock(&g_lock);
	hider_image_record_t *record = NULL;
	uint32_t header_identities = 0;
	for (hider_image_record_t *candidate = g_catalog_head; candidate; candidate = candidate->next) {
		if (candidate->header == mh) header_identities++;
		if (candidate->active && candidate->header == mh) {
			record = candidate;
		}
	}
	uint8_t runtime_uuid[16] = {0};
	bool runtime_uuid_valid = record && catalog_copy_uuid(mh, record->slide, runtime_uuid);
	bool dispatchable = hider_tracking_can_dispatch_locked() && record &&
	                    record->identity != 0 && record->added_generation != 0 &&
	                    header_identities == 1 && !record->objc_event_emitted &&
	                    runtime_path && record->path && !strcmp(runtime_path, record->path) &&
	                    record->uuid_valid && runtime_uuid_valid &&
	                    !memcmp(record->uuid, runtime_uuid, sizeof(runtime_uuid)) &&
	                    g_objc_event_sequence != UINT64_MAX;
	if (dispatchable) {
		hider_objc_event_t *event = &record->objc_event;
		record->objc_event_emitted = true;
		event->record = record;
		event->sequence = ++g_objc_event_sequence;
		if (g_objc_event_tail) {
			g_objc_event_tail->next = event;
		} else {
			g_objc_event_head = event;
		}
		g_objc_event_tail = event;
	}
	os_unfair_lock_unlock(&g_lock);
	if (!dispatchable) {
		/* This stays on the ObjC runtime's timing lane.  No registration,
		 * allocation, loader call, or catalog lock is held for raw delivery. */
		hider_degrade_to_native();
		(void)hider_dispatch_passthrough_objc_event(mh);
		return;
	}
	if (!hider_dispatch_objc_event(&record->objc_event)) {
		hider_callback_fail_stop();
	}
}

//------------------------------------------------------------------------------
#pragma mark - Hooked dyld Functions

__attribute__((noinline))
static uint32_t h_image_count(void) {
	if (!hider_is_ready() && orig_dyld_image_count)
		return orig_dyld_image_count();
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	bool hidden = caller_is_hidden(ra);
	os_unfair_lock_lock(&g_lock);
	bool filtered = hider_tracking_is_filtered_locked();
	uint32_t c = filtered ? catalog_active_count_locked(hidden) : 0;
	os_unfair_lock_unlock(&g_lock);
	if (!filtered && orig_dyld_image_count)
		return orig_dyld_image_count();
	return c;
}

__attribute__((noinline))
static const char *h_get_image_name(uint32_t idx) {
	if (!hider_is_ready() && orig_dyld_get_image_name)
		return orig_dyld_get_image_name(idx);
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	bool hidden = caller_is_hidden(ra);
	os_unfair_lock_lock(&g_lock);
	bool filtered = hider_tracking_is_filtered_locked();
	hider_image_record_t *record = filtered ? catalog_active_at_index_locked(idx, hidden) : NULL;
	const char *n = record ? record->path : NULL;
	os_unfair_lock_unlock(&g_lock);
	if (!filtered && orig_dyld_get_image_name)
		return orig_dyld_get_image_name(idx);
	return n;
}

__attribute__((noinline))
static const struct mach_header *h_get_image_header(uint32_t idx) {
	if (!hider_is_ready() && orig_dyld_get_image_header)
		return orig_dyld_get_image_header(idx);
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	bool hidden = caller_is_hidden(ra);
	os_unfair_lock_lock(&g_lock);
	bool filtered = hider_tracking_is_filtered_locked();
	hider_image_record_t *record = filtered ? catalog_active_at_index_locked(idx, hidden) : NULL;
	const struct mach_header *h = record ? record->header : NULL;
	os_unfair_lock_unlock(&g_lock);
	if (!filtered && orig_dyld_get_image_header)
		return orig_dyld_get_image_header(idx);
	return h;
}

__attribute__((noinline))
static intptr_t h_get_image_vmaddr_slide(uint32_t idx) {
	if (!hider_is_ready() && orig_dyld_get_image_vmaddr_slide)
		return orig_dyld_get_image_vmaddr_slide(idx);
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	bool hidden = caller_is_hidden(ra);
	os_unfair_lock_lock(&g_lock);
	bool filtered = hider_tracking_is_filtered_locked();
	hider_image_record_t *record = filtered ? catalog_active_at_index_locked(idx, hidden) : NULL;
	intptr_t s = record ? record->slide : 0;
	os_unfair_lock_unlock(&g_lock);
	if (!filtered && orig_dyld_get_image_vmaddr_slide)
		return orig_dyld_get_image_vmaddr_slide(idx);
	return s;
}

__attribute__((noinline))
static void h_register_func_for_add_image(void (*func)(const struct mach_header *, intptr_t)) {
	if (!func) return;
	if (!hider_is_ready() && orig_dyld_register_func_for_add_image) {
		orig_dyld_register_func_for_add_image(func);
		return;
	}

	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	bool hidden = caller_is_hidden(ra);

	hider_dyld_callback_registration_t *registration = calloc(1, sizeof(*registration));
	if (!registration) {
		hider_degrade_to_native();
		if (orig_dyld_register_func_for_add_image) orig_dyld_register_func_for_add_image(func);
		return;
	}
	registration->func = func;
	registration->from_hidden = hidden;
	registration->kind = HIDER_DYLD_CALLBACK_ADD;
	atomic_init(&registration->state, HIDER_CALLBACK_REPLAYING);
	/* Set before publication. The permanent source relay sees a fully initialized
	 * REPLAYING node, never a partially initialized callback. */
	atomic_init(&registration->delivering, true);
	atomic_init(&registration->callback_invoking, false);
	atomic_init(&registration->recursive_event, false);
	atomic_init(&registration->queued_event, false);
	atomic_init(&registration->next, NULL);

	os_unfair_lock_lock(&g_lock);
	bool filtered = hider_tracking_is_filtered_locked();
	if (filtered) {
		registration->replay_boundary = g_image_event_sequence;
		registration->event_marker = g_image_event_tail;
		if (g_dyld_callbacks_tail) {
			atomic_store_explicit(&g_dyld_callbacks_tail->next, registration, memory_order_release);
		} else {
			atomic_store_explicit(&g_dyld_callbacks, registration, memory_order_release);
		}
		g_dyld_callbacks_tail = registration;
	}
	os_unfair_lock_unlock(&g_lock);
	if (!filtered) {
		free(registration);
		if (orig_dyld_register_func_for_add_image) orig_dyld_register_func_for_add_image(func);
		return;
	}
	(void)hider_complete_dyld_add_replay(registration);
}

__attribute__((noinline))
static void h_register_func_for_remove_image(void (*func)(const struct mach_header *, intptr_t)) {
	if (!func) return;
	if (!hider_is_ready() && orig_dyld_register_func_for_remove_image) {
		orig_dyld_register_func_for_remove_image(func);
		return;
	}

	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	bool hidden = caller_is_hidden(ra);

	hider_dyld_callback_registration_t *registration = calloc(1, sizeof(*registration));
	if (!registration) {
		hider_degrade_to_native();
		if (orig_dyld_register_func_for_remove_image) orig_dyld_register_func_for_remove_image(func);
		return;
	}
	registration->func = func;
	registration->from_hidden = hidden;
	registration->kind = HIDER_DYLD_CALLBACK_REMOVE;
	atomic_init(&registration->state, HIDER_CALLBACK_ACTIVE);
	atomic_init(&registration->delivering, false);
	atomic_init(&registration->callback_invoking, false);
	atomic_init(&registration->recursive_event, false);
	atomic_init(&registration->queued_event, false);
	atomic_init(&registration->next, NULL);
	os_unfair_lock_lock(&g_lock);
	bool filtered = hider_tracking_is_filtered_locked();
	if (filtered) {
		registration->event_marker = g_image_event_tail;
		if (g_dyld_callbacks_tail) {
			atomic_store_explicit(&g_dyld_callbacks_tail->next, registration, memory_order_release);
		} else {
			atomic_store_explicit(&g_dyld_callbacks, registration, memory_order_release);
		}
		g_dyld_callbacks_tail = registration;
	}
	os_unfair_lock_unlock(&g_lock);
	if (!filtered) {
		free(registration);
		if (orig_dyld_register_func_for_remove_image) orig_dyld_register_func_for_remove_image(func);
	}
}

//------------------------------------------------------------------------------
#pragma mark - task_info(TASK_DYLD_INFO) hook

// MIG message structures for task_info (routine 3418 in mach/task.defs)
#pragma pack(4)
typedef struct {
	mach_msg_header_t    Head;
	NDR_record_t         NDR;
	task_flavor_t        flavor;
	mach_msg_type_number_t task_info_outCnt;
} _ti_request_t;

typedef struct {
	mach_msg_header_t    Head;
	NDR_record_t         NDR;
	kern_return_t        RetCode;
	mach_msg_type_number_t task_info_outCnt;
	integer_t            task_info_out[87]; // TASK_INFO_MAX
} _ti_reply_t;
#pragma pack()

// Raw MIG call — bypasses any userspace hooks, goes directly to the kernel
// via mach_msg.  Detection-proof since it's just a Mach IPC message.
static kern_return_t raw_task_info(task_name_t target, task_flavor_t flavor,
                                   task_info_t info_out, mach_msg_type_number_t *cnt) {
	if (!info_out || !cnt) {
		return KERN_INVALID_ARGUMENT;
	}
	const mach_msg_type_number_t requested_count = *cnt;
	if (requested_count > (mach_msg_type_number_t)(sizeof(((_ti_reply_t *)0)->task_info_out) / sizeof(integer_t))) {
		return KERN_INVALID_ARGUMENT;
	}

	union {
		_ti_request_t req;
		_ti_reply_t   rep;
	} msg;

	_ti_request_t *req = &msg.req;
	memset(req, 0, sizeof(*req));
	req->Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,
	                                      MACH_MSG_TYPE_MAKE_SEND_ONCE);
	req->Head.msgh_size = sizeof(*req);
	req->Head.msgh_remote_port = target;
	req->Head.msgh_local_port = mig_get_reply_port();
	req->Head.msgh_id = 3418;
	req->NDR = NDR_record;
	req->flavor = flavor;
	req->task_info_outCnt = requested_count;

	kern_return_t kr = mach_msg(
		&req->Head,
		MACH_SEND_MSG | MACH_RCV_MSG | MACH_MSG_OPTION_NONE,
		(mach_msg_size_t)sizeof(*req),
		(mach_msg_size_t)sizeof(msg.rep),
		req->Head.msgh_local_port,
		MACH_MSG_TIMEOUT_NONE,
		MACH_PORT_NULL);

	if (kr != MACH_MSG_SUCCESS) {
		// Dealloc on failure per MIG convention
		if (kr == MACH_SEND_INVALID_REPLY)
			mig_dealloc_reply_port(msg.req.Head.msgh_local_port);
		return kr;
	}

	_ti_reply_t *rep = &msg.rep;
	if (rep->RetCode != KERN_SUCCESS)
		return rep->RetCode;

	mach_msg_type_number_t out_n = rep->task_info_outCnt;
	if (out_n > requested_count) out_n = requested_count;
	if (out_n > (mach_msg_type_number_t)(sizeof(rep->task_info_out) / sizeof(integer_t)))
		out_n = (mach_msg_type_number_t)(sizeof(rep->task_info_out) / sizeof(integer_t));
	memcpy(info_out, rep->task_info_out, out_n * sizeof(integer_t));
	*cnt = out_n;

	return KERN_SUCCESS;
}

typedef enum {
	TASK_SNAPSHOT_READY = 0,
	TASK_SNAPSHOT_TRANSIENT_UNAVAILABLE,
	TASK_SNAPSHOT_FATAL,
} task_snapshot_result_t;

typedef struct {
	struct dyld_all_image_infos snapshot;
	const struct dyld_image_info *images;
	uint32_t image_count;
	const struct dyld_uuid_info *uuids;
	uintptr_t uuid_count;
	uint64_t timestamp;
} task_snapshot_source_t;

static void discard_task_snapshot_generation(task_snapshot_generation_t *generation) {
	if (!generation) {
		return;
	}
	free(generation->images);
	free(generation->uuids);
	free(generation);
}

static bool capture_task_snapshot_source(task_snapshot_source_t *source) {
	if (!source || !g_real_aii || !g_real_aii->infoArray) {
		return false;
	}

	memset(source, 0, sizeof(*source));
	source->snapshot = *g_real_aii;
	source->images = source->snapshot.infoArray;
	source->image_count = source->snapshot.infoArrayCount;
	if (source->snapshot.version >= 8) {
		source->uuids = source->snapshot.uuidArray;
		source->uuid_count = source->snapshot.uuidArrayCount;
	}
	if (source->snapshot.version >= 15) {
		source->timestamp = source->snapshot.infoArrayChangeTimestamp;
	}
	return source->images != NULL;
}

static bool task_snapshot_source_is_current(const task_snapshot_source_t *source) {
	if (!source || !g_real_aii || !g_real_aii->infoArray ||
	    g_real_aii->infoArray != source->images ||
	    g_real_aii->infoArrayCount != source->image_count) {
		return false;
	}
	if (source->snapshot.version >= 8 &&
	    (g_real_aii->uuidArray != source->uuids ||
	     g_real_aii->uuidArrayCount != source->uuid_count)) {
		return false;
	}
	if (source->snapshot.version >= 15 &&
	    g_real_aii->infoArrayChangeTimestamp != source->timestamp) {
		return false;
	}
	return true;
}

static task_snapshot_generation_t *build_task_snapshot(task_snapshot_result_t *result_out) {
	// Must be called with g_lock held.
	if (result_out) {
		*result_out = TASK_SNAPSHOT_TRANSIENT_UNAVAILABLE;
	}
	if (!hider_tracking_is_filtered_locked() || !g_real_aii || !g_real_aii->infoArray) {
		return NULL;
	}
	if (g_ti_current && g_ti_current->image_generation == g_image_generation) {
		if (result_out) {
			*result_out = TASK_SNAPSHOT_READY;
		}
		return g_ti_current;
	}

	for (uint32_t attempt = 0; attempt < RHI_TASK_SNAPSHOT_COPY_ATTEMPTS; attempt++) {
		task_snapshot_source_t source = {0};
		if (!capture_task_snapshot_source(&source)) {
			return NULL;
		}
		uint32_t visible_image_count = catalog_active_count_locked(false);
		if (visible_image_count == UINT32_MAX ||
		    (size_t)visible_image_count > SIZE_MAX / sizeof(struct dyld_image_info) ||
		    (size_t)visible_image_count > SIZE_MAX / sizeof(struct dyld_uuid_info)) {
			break;
		}

		task_snapshot_generation_t *generation = calloc(1, sizeof(*generation));
		if (!generation) {
			break;
		}
		if (visible_image_count) {
			generation->images = calloc(visible_image_count, sizeof(*generation->images));
			generation->uuids = calloc(visible_image_count, sizeof(*generation->uuids));
			if (!generation->images || !generation->uuids) {
				discard_task_snapshot_generation(generation);
				break;
			}
		}

		/* The filtered task view is derived exclusively from catalog identities.
		 * Paths are catalog-owned and process-lifetime, unlike dyld's pointers. */
		uint32_t output_image_count = 0;
		uint32_t output_uuid_count = 0;
		for (hider_image_record_t *record = g_catalog_head; record; record = record->next) {
			if (!record->active || record->hidden) {
				continue;
			}
			generation->images[output_image_count] = (struct dyld_image_info){
				.imageLoadAddress = record->header,
				.imageFilePath = record->path,
				.imageFileModDate = 0,
			};
			if (record->uuid_valid) {
				generation->uuids[output_uuid_count].imageLoadAddress = record->header;
				memcpy(generation->uuids[output_uuid_count].imageUUID, record->uuid, 16);
				output_uuid_count++;
			}
			output_image_count++;
		}
		if (output_image_count != visible_image_count || !task_snapshot_source_is_current(&source)) {
			discard_task_snapshot_generation(generation);
			continue;
		}

		generation->snapshot = source.snapshot;
		generation->snapshot.infoArray = generation->images;
		generation->snapshot.infoArrayCount = output_image_count;
		if (generation->snapshot.version >= 8) {
			generation->snapshot.uuidArray = output_uuid_count ? generation->uuids : NULL;
			generation->snapshot.uuidArrayCount = output_uuid_count;
		}
		if (generation->snapshot.version >= 9) {
			generation->snapshot.dyldAllImageInfosAddress = &generation->snapshot;
		}
		if (!task_snapshot_source_is_current(&source)) {
			discard_task_snapshot_generation(generation);
			continue;
		}

		generation->image_generation = g_image_generation;
		generation->previous = g_ti_current;
		g_ti_current = generation;
		if (result_out) {
			*result_out = TASK_SNAPSHOT_READY;
		}
		return generation;
	}

	/*
	 * A stable but unpublishable dyld generation (OOM, overflow, malformed
	 * count, or a load storm that never stabilizes) cannot coexist with filtered
	 * enumeration.  Degrade every linked view to dyld's originals atomically.
	 */
	g_image_tracking_state = HIDER_TRACKING_DEGRADING;
	if (result_out) {
		*result_out = TASK_SNAPSHOT_FATAL;
	}
	return NULL;
}

__attribute__((noinline))
static kern_return_t h_task_info(task_name_t target, task_flavor_t flavor,
                                  task_info_t info_out, mach_msg_type_number_t *cnt) {
	if (!orig_task_info) {
		return KERN_FAILURE;
	}
	if (!hider_is_ready())
		return orig_task_info(target, flavor, info_out, cnt);
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra))
		return orig_task_info(target, flavor, info_out, cnt);

	// Use the saved original for the actual call — raw MIG is fragile
	// and unnecessary since we hold the real function pointer.
	kern_return_t kr = orig_task_info(target, flavor, info_out, cnt);
	if (kr != KERN_SUCCESS) return kr;

	// Only filter TASK_DYLD_INFO on mach_task_self()
	if (flavor != TASK_DYLD_INFO || target != mach_task_self())
		return kr;
	// The original call owns validation of the request.  Only reinterpret the
	// returned buffer when it contains a complete task_dyld_info structure.
	if (!info_out || !cnt || *cnt < TASK_DYLD_INFO_COUNT)
		return kr;

	struct task_dyld_info *tdi = (struct task_dyld_info *)info_out;

	os_unfair_lock_lock(&g_lock);
	// Cache the real dyld_all_image_infos pointer on first encounter.
	if (!g_real_aii && tdi->all_image_info_addr)
		g_real_aii = (struct dyld_all_image_infos *)(uintptr_t)tdi->all_image_info_addr;
	task_snapshot_result_t snapshot_result = TASK_SNAPSHOT_TRANSIENT_UNAVAILABLE;
	task_snapshot_generation_t *generation = build_task_snapshot(&snapshot_result);
	os_unfair_lock_unlock(&g_lock);
	if (!generation) {
		if (snapshot_result == TASK_SNAPSHOT_FATAL) {
			/* build_task_snapshot marked the handoff state while holding g_lock;
		 * migration itself must run out of lock because native registration can
		 * synchronously invoke arbitrary callbacks. */
			hider_degrade_to_native();
		}
		return kr;
	}

	tdi->all_image_info_addr = (mach_vm_address_t)(uintptr_t)&generation->snapshot;
	tdi->all_image_info_size = sizeof(generation->snapshot);

	return KERN_SUCCESS;
}

//------------------------------------------------------------------------------
#pragma mark - Hook→Original address translation for dladdr
//
// After GOT rebinding, app code referencing e.g. &dladdr or &dlsym via
// the GOT gets our hook address (h_dladdr / h_dlsym).  If the app then
// calls dladdr(addr, …) on that pointer it would resolve to systemhook
// (hidden) and fail.  Translate hook addresses back to their stock DSC
// originals so dladdr returns the correct stock image path.

static const void *translate_hook_to_orig(const void *addr) {
	// hook: the hook function address (compile-time constant)
	// orig: pointer to the variable holding the original DSC address (read at runtime)
	static const struct { const void *hook; void *const *orig; } map[] = {
		{ (const void *)h_dladdr,                        (void *const *)&orig_dladdr },
		{ (const void *)h_dlsym,                         (void *const *)&orig_dlsym },
		{ (const void *)h_dlerror,                       (void *const *)&orig_dlerror },
		{ (const void *)h_image_count,                   (void *const *)&orig_dyld_image_count },
		{ (const void *)h_get_image_name,                (void *const *)&orig_dyld_get_image_name },
		{ (const void *)h_get_image_header,              (void *const *)&orig_dyld_get_image_header },
		{ (const void *)h_get_image_vmaddr_slide,        (void *const *)&orig_dyld_get_image_vmaddr_slide },
		{ (const void *)h_register_func_for_add_image,   (void *const *)&orig_dyld_register_func_for_add_image },
		{ (const void *)h_register_func_for_remove_image,(void *const *)&orig_dyld_register_func_for_remove_image },
		{ (const void *)h_task_info,                     (void *const *)&orig_task_info },
		{ (const void *)h_class_getImageName,            (void *const *)&orig_class_getImageName },
		{ (const void *)h_objc_copyClassList,            (void *const *)&orig_objc_copyClassList },
		{ (const void *)h_objc_copyImageNames,           (void *const *)&orig_objc_copyImageNames },
		{ (const void *)h_objc_copyClassNamesForImage,   (void *const *)&orig_objc_copyClassNamesForImage },
		{ (const void *)h_objc_addLoadImageFunc,         (void *const *)&orig_objc_addLoadImageFunc },
		{ (const void *)h_dlopen,                        (void *const *)&orig_dlopen },
		{ (const void *)dlopen_fallback_hook,            (void *const *)&orig_dlopen },
		{ (const void *)h_fork,                          (void *const *)&orig_fork },
		{ (const void *)h_getfsstat,                     (void *const *)&orig_getfsstat },
		{ (const void *)h_sysctl,                        (void *const *)&orig_sysctl },
		{ (const void *)h_getenv,                        (void *const *)&orig_getenv },
		{ (const void *)h_access,                        (void *const *)&orig_access },
		{ (const void *)h_stat,                          (void *const *)&orig_stat },
		{ (const void *)h_lstat,                         (void *const *)&orig_lstat },
		{ (const void *)h_statfs,                        (void *const *)&orig_statfs },
		{ (const void *)h_statvfs,                       (void *const *)&orig_statvfs },
		{ (const void *)h_fopen,                         (void *const *)&orig_fopen },
		{ (const void *)h_sysctlbyname,                  (void *const *)&orig_sysctlbyname },
		{ (const void *)h_opendir,                       (void *const *)&orig_opendir },
		{ (const void *)h_readdir,                       (void *const *)&orig_readdir },
		{ (const void *)h_closedir,                      (void *const *)&orig_closedir },
		{ (const void *)h_mach_port_get_refs,            (void *const *)&orig_mach_port_get_refs },
		{ (const void *)h_UIApplication_canOpenURL,       (void *const *)&orig_UIApplication_canOpenURL },
		{ (const void *)h_UIApplication_openURL,          (void *const *)&orig_UIApplication_openURL },
		{ (const void *)h_UIApplication_openURL_options_completion,
		                                                   (void *const *)&orig_UIApplication_openURL_options_completion },
	};
	for (unsigned i = 0; i < sizeof(map) / sizeof(*map); i++) {
		if (addr == map[i].hook && map[i].orig && *map[i].orig)
			return *map[i].orig;
	}
	return addr;
}

//------------------------------------------------------------------------------
#pragma mark - dladdr hook

__attribute__((noinline))
static int h_dladdr(const void *addr, Dl_info *info) {
	if (!hider_is_ready())
		return orig_dladdr ? orig_dladdr(addr, info) : 0;
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra))
		return orig_dladdr(addr, info);  // tweak caller → full unfiltered result

	// Translate hook addresses back to originals so dladdr(&dladdr, …)
	// etc. resolve to the stock DSC image, not systemhook.
	addr = translate_hook_to_orig(addr);

	int result = orig_dladdr(addr, info);
	if (result == 0)
		return 0;

	// App caller: if the address is in a hidden image, rewrite dli_fname to
	// the app executable path instead of returning 0.  Returning 0 causes
	// detection SDKs (ICGN, SF) to flag the IMP as anomalous
	// because dladdr never fails for valid addresses on stock iOS.
	// This matches h_class_getImageName's strategy of returning g_executable_path.
	if (info && info->dli_fname && g_executable_path && g_executable_header &&
	    image_path_should_hide(info->dli_fname)) {
		// Rewrite the owning image to match the app executable. Preserve the
		// symbol name so callers that stringify dli_sname don't crash on NULL.
		// dli_saddr stays cleared because it would otherwise still point into the
		// hidden image even after we swap dli_fbase to the app binary.
		info->dli_fname = g_executable_path;
		info->dli_fbase = (void *)g_executable_header;
		info->dli_saddr = NULL;
		return 1;
	}

	return result;
}

//------------------------------------------------------------------------------
#pragma mark - dlsym hook

void *hidden_dylib_hider_dlsym_remap(const char *name);  // forward decl

/* h_dlsym can manufacture a failure after libdyld successfully resolved an
 * address in a hidden image. Keep that error local to the probing thread and
 * consume it exactly once from h_dlerror, matching dlerror's ownership model.
 * A fixed TLS buffer avoids allocation/re-entry on the loader/error path. */
#define RHI_DLSYM_ERROR_CAPACITY 512U
static _Thread_local char g_dlsym_error_message[RHI_DLSYM_ERROR_CAPACITY];
static _Thread_local bool g_dlsym_error_pending = false;

static void hider_dlsym_clear_pending_error(void) {
	g_dlsym_error_pending = false;
}

static void hider_dlsym_set_hidden_result_error(const char *symbol) {
	if (!symbol) {
		return;
	}
	snprintf(g_dlsym_error_message, sizeof(g_dlsym_error_message),
	         "symbol not found: %s", symbol);
	g_dlsym_error_pending = true;
}

__attribute__((noinline))
static void *h_dlsym(void *handle, const char *symbol) {
	if (!hider_is_ready())
		return orig_dlsym ? orig_dlsym(handle, symbol) : NULL;
	if (!orig_dlsym) {
		return NULL;
	}

	/* A later application loader operation supersedes an unconsumed synthetic
	 * denial or virtualized bookkeeping result on this same thread. */
	hider_loader_error_clear_pending();
	hider_dlsym_clear_pending_error();

	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra))
		return orig_dlsym(handle, symbol);  // tweak caller → full access

	/* Do not manufacture an error or dereference a NULL symbol. libdyld owns
	 * the exact invalid-input semantics for this uncommon caller misuse. */
	if (!symbol) {
		return orig_dlsym(handle, symbol);
	}

	void *result = orig_dlsym(handle, symbol);

	// App caller: remap our GOT-hooked functions so dlsym returns
	// our hook pointer, not the raw DSC address (which would bypass
	// our GOT hooks if the app caches the pointer).
	void *remapped = hidden_dylib_hider_dlsym_remap(symbol);
	if (remapped) {
		/* The original lookup may have failed for a particular handle even
		 * though the active policy remap succeeds. A successful dlsym must not
		 * leave that stale libdyld error visible through dlerror. */
		if (orig_dlerror) {
			(void)orig_dlerror();
		}
		return remapped;
	}

	// App caller: if the resolved address lives in a hidden image,
	// return NULL.  This catches MSHookFunction, ellekit symbols, etc.
	// without needing a symbol-name blocklist.
	if (result) {
		const char *path = dyld_image_path_containing_address(result);
		if (path && image_path_should_hide(path)) {
			/* Replace, rather than stack on, libdyld's prior per-thread error.
			 * After our one-shot denial is consumed, a second dlerror must be NULL. */
			if (orig_dlerror) (void)orig_dlerror();
			hider_dlsym_set_hidden_result_error(symbol);
			return NULL;
		}
	}

	/* RTLD_NEXT/RTLD_SELF are delegated to libdyld from this wrapper frame.
	 * That preserves the platform's normal lookup/error handling as far as
	 * possible, but is not a caller-relative emulation; do not advertise a
	 * stronger guarantee until a safe per-image resolver is implemented. */
	return result;
}

__attribute__((noinline))
static char *h_dlerror(void) {
	if (!hider_is_ready()) {
		return orig_dlerror ? orig_dlerror() : NULL;
	}
	if (g_loader_error_pending) {
		g_loader_error_pending = false;
		return g_loader_error_message;
	}

	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra)) {
		return orig_dlerror ? orig_dlerror() : NULL;
	}

	if (g_dlsym_error_pending) {
		g_dlsym_error_pending = false;
		return g_dlsym_error_message;
	}
	return orig_dlerror ? orig_dlerror() : NULL;
}

//------------------------------------------------------------------------------
#pragma mark - ObjC runtime hooks

__attribute__((noinline))
static const char *h_class_getImageName(Class cls) {
	const char *result = orig_class_getImageName(cls);
	if (!hider_strict_hook_is_ready(&g_strict_class_image_session, "class_getImageName"))
		return result;

	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra))
		return result;

	// App caller: if class lives in a hidden image, return the app executable path
	if (result && image_path_should_hide(result))
		return g_executable_path;

	return result;
}

static bool class_name_should_hide_from_app(const char *name) {
	if (!name || !name[0]) return false;

	static const char *hidden_names[] = {
		// Marriott/Appdome residue scan false-positive classes.
		"NSSubstituteWebResource",
		"GEODisplayHeaderSubstitute",
		"GEOPDDisplayHeaderSubstitute",
		"_UIContextBinderSubstrate",
		"_UINullSubstrate",
		"_UIFBSSceneSubstrate",
		// Common jailbreak/bypass runtime class names.
		"ShadowRuleset",
		"Shadow",
		"ABypass",
		"FlyJB",
		"FLEXManager",
		"FridaGadget",
		"FridaAgent",
		"EKHook",
		"EKHookClass",
		"TweakInjectLoader",
		NULL
	};

	for (int i = 0; hidden_names[i]; i++) {
		if (!strcmp(name, hidden_names[i]))
			return true;
	}

	return false;
}

static bool class_should_hide_from_app(Class cls) {
	if (!cls) return false;

	const char *name = class_getName(cls);
	if (class_name_should_hide_from_app(name))
		return true;

	const char *image = orig_class_getImageName ? orig_class_getImageName(cls) : NULL;
	return image && image_path_should_hide(image);
}

__attribute__((noinline))
static Class *h_objc_copyClassList(unsigned int *outCount) {
	Class *result = orig_objc_copyClassList(outCount);
	if (!hider_strict_hook_is_ready(&g_strict_copy_class_list_session, "objc_copyClassList"))
		return result;

	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra) || !result || !outCount)
		return result;

	unsigned int total = *outCount;
	Class *filtered = total ? malloc(total * sizeof(Class)) : NULL;
	if (total && !filtered)
		return result;

	unsigned int kept = 0;
	for (unsigned int i = 0; i < total; i++) {
		Class cls = result[i];
		if (!class_should_hide_from_app(cls))
			filtered[kept++] = cls;
	}

	free(result);
	*outCount = kept;
	return filtered;
}

__attribute__((noinline))
static const char * _Nonnull *h_objc_copyImageNames(unsigned int *outCount) {
	const char * _Nonnull *result = orig_objc_copyImageNames(outCount);
	if (!hider_strict_hook_is_ready(&g_strict_copy_images_session, "objc_copyImageNames"))
		return result;

	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra) || !result || !outCount)
		return result;

	// Filter: only keep non-hidden image names.
	// The result is malloc'd by the runtime; we can't modify in place safely,
	// so we build a filtered copy.
	unsigned int total = *outCount;
	const char **filtered = malloc(total * sizeof(const char *));
	if (!filtered) return result;

	unsigned int kept = 0;
	for (unsigned int i = 0; i < total; i++) {
		if (!image_path_should_hide(result[i]))
			filtered[kept++] = result[i];
	}

	// Free the original and return ours (caller will free())
	free(result);
	*outCount = kept;
	return (const char * _Nonnull *)filtered;
}

// NOTE: objc_getClass / NSClassFromString are intentionally NOT hooked.
// They're called thousands of times during startup by UIKit/Foundation —
// the caller_is_hidden() overhead would destroy launch performance.
// Detection is blocked by:
//   - objc_copyImageNames hides hidden images from enumeration
//   - class_getImageName returns executable path for hidden-image classes
//   - objc_copyClassNamesForImage returns NULL for hidden images
//   - dlsym returns NULL for JB symbols

__attribute__((noinline))
static const char * _Nonnull *h_objc_copyClassNamesForImage(const char *image, unsigned int *outCount) {
	if (!hider_strict_hook_is_ready(&g_strict_copy_names_session, "objc_copyClassNamesForImage"))
		return orig_objc_copyClassNamesForImage(image, outCount);
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra))
		return orig_objc_copyClassNamesForImage(image, outCount);

	// App caller asking about a hidden image → return nothing
	if (image && image_path_should_hide(image)) {
		if (outCount) *outCount = 0;
		return NULL;
	}

	return orig_objc_copyClassNamesForImage(image, outCount);
}

__attribute__((noinline))
static void h_objc_addLoadImageFunc(objc_func_loadImage func) {
	if (!hider_strict_hook_is_ready(&g_strict_add_load_session, "objc_addLoadImageFunc")) {
		if (orig_objc_addLoadImageFunc) orig_objc_addLoadImageFunc(func);
		return;
	}
	if (!func) return;

	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	bool hidden = caller_is_hidden(ra);
	hider_objc_callback_registration_t *registration = calloc(1, sizeof(*registration));
	if (!registration) {
		hider_degrade_to_native();
		if (orig_objc_addLoadImageFunc) orig_objc_addLoadImageFunc(func);
		return;
	}
	registration->func = func;
	registration->from_hidden = hidden;
	atomic_init(&registration->state, HIDER_CALLBACK_REPLAYING);
	/* See dyld add registration: REPLAYING is already delivering when linked. */
	atomic_init(&registration->delivering, true);
	atomic_init(&registration->callback_invoking, false);
	atomic_init(&registration->recursive_event, false);
	atomic_init(&registration->queued_event, false);
	atomic_init(&registration->next, NULL);

	os_unfair_lock_lock(&g_lock);
	bool filtered = hider_tracking_is_filtered_locked();
	if (filtered) {
		registration->event_marker = g_objc_event_tail;
		if (g_objc_callbacks_tail) {
			atomic_store_explicit(&g_objc_callbacks_tail->next, registration, memory_order_release);
		} else {
			atomic_store_explicit(&g_objc_callbacks, registration, memory_order_release);
		}
		g_objc_callbacks_tail = registration;
	}
	os_unfair_lock_unlock(&g_lock);
	if (!filtered) {
		free(registration);
		if (orig_objc_addLoadImageFunc) orig_objc_addLoadImageFunc(func);
		return;
	}
	(void)hider_complete_objc_replay(registration);
}

//------------------------------------------------------------------------------
#pragma mark - UIApplication URL scheme hook

static bool jailbreak_url_scheme_should_hide(const char *scheme) {
	if (!scheme || !scheme[0])
		return false;

	static const char *blocked_schemes[] = {
		"cydia",
		"sileo",
		"zbra",
		"zebra",
		"filza",
		"frida",
		"apt",
		"apt-repo",
		"pkg",
		"substrate",
		"activator",
		"taurine",
		"checkra1n",
		"unc0ver",
		"undecimus",
		"dopamine",
		"palera1n",
		"roothide",
		"iclean",
		NULL
	};

	for (int i = 0; blocked_schemes[i]; i++) {
		if (!strcasecmp(scheme, blocked_schemes[i]))
			return true;
	}

	return false;
}

static const char *url_scheme_utf8(id url) {
	if (!url)
		return NULL;

	SEL schemeSel = sel_registerName("scheme");
	if (!schemeSel || !((BOOL (*)(id, SEL, SEL))objc_msgSend)(url, sel_registerName("respondsToSelector:"), schemeSel))
		return NULL;

	id scheme = ((id (*)(id, SEL))objc_msgSend)(url, schemeSel);
	if (!scheme)
		return NULL;

	SEL utf8Sel = sel_registerName("UTF8String");
	if (!utf8Sel || !((BOOL (*)(id, SEL, SEL))objc_msgSend)(scheme, sel_registerName("respondsToSelector:"), utf8Sel))
		return NULL;

	return ((const char *(*)(id, SEL))objc_msgSend)(scheme, utf8Sel);
}

__attribute__((noinline))
static BOOL h_UIApplication_canOpenURL(id self, SEL _cmd, id url) {
	if (!hider_strict_hooks_ready()) {
		return orig_UIApplication_canOpenURL ?
			((BOOL (*)(id, SEL, id))orig_UIApplication_canOpenURL)(self, _cmd, url) : NO;
	}
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra)) {
		return ((BOOL (*)(id, SEL, id))orig_UIApplication_canOpenURL)(self, _cmd, url);
	}

	if (jailbreak_url_scheme_should_hide(url_scheme_utf8(url)))
		return NO;

	return ((BOOL (*)(id, SEL, id))orig_UIApplication_canOpenURL)(self, _cmd, url);
}

__attribute__((noinline))
static BOOL h_UIApplication_openURL(id self, SEL _cmd, id url) {
	if (!hider_strict_hooks_ready()) {
		return orig_UIApplication_openURL ?
			((BOOL (*)(id, SEL, id))orig_UIApplication_openURL)(self, _cmd, url) : NO;
	}
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra)) {
		return ((BOOL (*)(id, SEL, id))orig_UIApplication_openURL)(self, _cmd, url);
	}

	if (jailbreak_url_scheme_should_hide(url_scheme_utf8(url)))
		return NO;

	return ((BOOL (*)(id, SEL, id))orig_UIApplication_openURL)(self, _cmd, url);
}

typedef struct {
	void *isa;
	int flags;
	int reserved;
	void (*invoke)(void *, ...);
	void *descriptor;
} block_literal_t;

static void invoke_bool_completion(void *completion, BOOL success) {
	if (!completion)
		return;

	block_literal_t *block = (block_literal_t *)completion;
	if (!block->invoke)
		return;

	((void (*)(void *, BOOL))block->invoke)(completion, success);
}

__attribute__((noinline))
static void h_UIApplication_openURL_options_completion(id self, SEL _cmd, id url, id options, void *completion) {
	if (!hider_strict_hooks_ready()) {
		if (orig_UIApplication_openURL_options_completion)
			((void (*)(id, SEL, id, id, void *))orig_UIApplication_openURL_options_completion)(self, _cmd, url, options, completion);
		return;
	}
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra)) {
		((void (*)(id, SEL, id, id, void *))orig_UIApplication_openURL_options_completion)(self, _cmd, url, options, completion);
		return;
	}

	if (jailbreak_url_scheme_should_hide(url_scheme_utf8(url))) {
		invoke_bool_completion(completion, NO);
		return;
	}

	((void (*)(id, SEL, id, id, void *))orig_UIApplication_openURL_options_completion)(self, _cmd, url, options, completion);
}

static void install_url_scheme_hooks(void) {
	Class applicationClass = objc_getClass("UIApplication");
	if (!applicationClass)
		return;

	SEL canOpenURLSel = sel_registerName("canOpenURL:");
	Method canOpenURLMethod = class_getInstanceMethod(applicationClass, canOpenURLSel);
	if (!canOpenURLMethod)
		return;

	orig_UIApplication_canOpenURL = method_setImplementation(canOpenURLMethod, (IMP)h_UIApplication_canOpenURL);
	g_url_scheme_hooks_active = orig_UIApplication_canOpenURL != NULL;

	SEL openURLSel = sel_registerName("openURL:");
	Method openURLMethod = class_getInstanceMethod(applicationClass, openURLSel);
	if (openURLMethod) {
		orig_UIApplication_openURL = method_setImplementation(openURLMethod, (IMP)h_UIApplication_openURL);
	}

	SEL openURLOptionsCompletionSel = sel_registerName("openURL:options:completionHandler:");
	Method openURLOptionsCompletionMethod = class_getInstanceMethod(applicationClass, openURLOptionsCompletionSel);
	if (openURLOptionsCompletionMethod) {
		orig_UIApplication_openURL_options_completion = method_setImplementation(openURLOptionsCompletionMethod, (IMP)h_UIApplication_openURL_options_completion);
	}
}

//------------------------------------------------------------------------------
#pragma mark - fork hook
//
// ICGN (Hinge) uses fork() as a sandbox-escape probe at 0x10223a220.
// On stock iOS, fork() fails with EPERM inside the app sandbox.
// On jailbroken, fork() succeeds — instant detection.
// Block it for app callers by returning -1/ENOSYS.

__attribute__((noinline))
static pid_t h_fork(void) {
	if (!hider_is_ready())
		return orig_fork ? orig_fork() : -1;
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra))
		return orig_fork();

	// App caller: deny fork the same way a stock sandboxed app usually sees it.
	errno = EPERM;
	return -1;
}

//------------------------------------------------------------------------------
#pragma mark - getfsstat hook
//
// Both ICGN (Hinge, 0x10223afc0) and SF (TM, 0x0008c268)
// scan mount points via getfsstat() looking for .jbroot / procursus / jailbreak
// in f_mntfromname and f_mntonname.

static bool mount_entry_should_hide(const struct statfs *fs) {
	if (!fs) return false;
	const char *from = fs->f_mntfromname;
	const char *on   = fs->f_mntonname;
	// Hide any mount referencing .jbroot or procursus
	if ((from && (strstr(from, ".jbroot") || strstr(from, "procursus"))) ||
	    (on   && (strstr(on,   ".jbroot") || strstr(on,   "procursus"))))
		return true;
	return false;
}

static void sanitize_mount_entry(struct statfs *fs) {
	if (!fs) return;

	strlcpy(fs->f_fstypename, "apfs", sizeof(fs->f_fstypename));
	strlcpy(fs->f_mntonname, "/", sizeof(fs->f_mntonname));
	strlcpy(fs->f_mntfromname, "/dev/disk1s1s1", sizeof(fs->f_mntfromname));
}

__attribute__((noinline))
static int h_getfsstat(struct statfs *buf, int bufsize, int mode) {
	if (!hider_is_ready())
		return orig_getfsstat ? orig_getfsstat(buf, bufsize, mode) : -1;
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra))
		return orig_getfsstat(buf, bufsize, mode);

	// If buf is NULL, caller is querying count — we must still return
	// the filtered count so the caller allocates the right buffer size.
	if (!buf || bufsize <= 0) {
		// Query real count, then do a temporary full fetch to count visible entries
		int real_count = orig_getfsstat(NULL, 0, mode);
		if (real_count <= 0) return real_count;
		size_t tmpsize = (size_t)real_count * sizeof(struct statfs);
		struct statfs *tmp = malloc(tmpsize);
		if (!tmp) return real_count;
		int fetched = orig_getfsstat(tmp, (int)tmpsize, mode);
		int kept = 0;
		for (int i = 0; i < fetched; i++) {
			if (!mount_entry_should_hide(&tmp[i])) kept++;
		}
		free(tmp);
		return kept;
	}

	int real_count = orig_getfsstat(buf, bufsize, mode);
	if (real_count <= 0)
		return real_count;

	// Filter in-place: compact visible entries forward
	int kept = 0;
	for (int i = 0; i < real_count; i++) {
		if (!mount_entry_should_hide(&buf[i])) {
			if (kept != i)
				buf[kept] = buf[i];
			kept++;
		}
	}

	return kept;
}

__attribute__((noinline))
static int h_statfs(const char *path, struct statfs *buf) {
	if (!hider_is_ready())
		return orig_statfs ? orig_statfs(path, buf) : -1;
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra))
		return orig_statfs(path, buf);

	if (path && fs_path_should_hide(path)) {
		errno = ENOENT;
		return -1;
	}

	int result = orig_statfs(path, buf);
	if (result != 0 || !buf)
		return result;

	if (mount_entry_should_hide(buf))
		sanitize_mount_entry(buf);

	return result;
}

__attribute__((noinline))
static int h_statvfs(const char *path, struct statvfs *buf) {
	if (!hider_is_ready())
		return orig_statvfs ? orig_statvfs(path, buf) : -1;
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra))
		return orig_statvfs(path, buf);

	// Darwin's statvfs result does not expose mount path strings, so the useful
	// app-visible probe here is the input path itself. Keep it stock otherwise.
	if (path && fs_path_should_hide(path)) {
		errno = ENOENT;
		return -1;
	}

	return orig_statvfs(path, buf);
}

//------------------------------------------------------------------------------
#pragma mark - sysctl hook (P_TRACED)
//
// Both ICGN and SF use sysctl(KERN_PROC, KERN_PROC_PID, getpid())
// to read kp_proc.p_flag and check for P_TRACED (debugger attached).
// Clear the flag for app callers.

#ifndef P_TRACED
#define P_TRACED 0x00000800
#endif

__attribute__((noinline))
static int h_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
                    void *newp, size_t newlen) {
	if (!hider_is_ready())
		return orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : -1;
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra))
		return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);

	int result = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
	if (result != 0 || !oldp || !oldlenp || !name)
		return result;

	// Only filter KERN_PROC queries (name[0]==CTL_KERN, name[1]==KERN_PROC)
	if (namelen >= 2 && name[0] == CTL_KERN && name[1] == KERN_PROC) {
		struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
		size_t count = *oldlenp / sizeof(struct kinfo_proc);
		for (size_t i = 0; i < count; i++) {
			kp[i].kp_proc.p_flag &= ~P_TRACED;
		}
	}

	return result;
}

//------------------------------------------------------------------------------
#pragma mark - getenv hook
//
// Hide DYLD_INSERT_LIBRARIES and other JB-related environment variables.
// Detection SDKs (ICGN, SF) probe for DYLD_* vars to detect injection.

static bool env_name_should_hide(const char *name) {
	if (!name) return false;
	// Block all DYLD_* variables — they reveal injection
	if (strncmp(name, "DYLD_", 5) == 0) return true;
	if (strncmp(name, "ROOTHIDE_", 9) == 0) return true;
	// JB safe-mode / injection markers
	if (strcmp(name, "_MSSafeMode") == 0) return true;
	if (strcmp(name, "_SafeMode") == 0) return true;
	if (strcmp(name, "_SubstituteSafeMode") == 0) return true;
	return false;
}

__attribute__((noinline))
static char *h_getenv(const char *name) {
	if (!hider_strict_hook_is_ready(&g_strict_getenv_session, "getenv"))
		return orig_getenv ? orig_getenv(name) : NULL;
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra))
		return orig_getenv(name);

	// App caller: hide JB-related env vars
	if (env_name_should_hide(name))
		return NULL;

	return orig_getenv(name);
}

//------------------------------------------------------------------------------
#pragma mark - dlopen hook

__attribute__((noinline))
static void *h_dlopen(const char *path, int mode) {
	/* Do not let a callback-local bookkeeping pin leave a virtual error across
	 * the caller's next explicit loader operation. */
	hider_loader_error_clear_pending();
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra))
		return orig_dlopen(path, mode);

	// App caller: block probe-loading of hidden paths.
	// Also block RTLD_NOLOAD probes (checking if already loaded).
	if (path && image_path_should_hide(path))
		return NULL;

	return orig_dlopen(path, mode);
}

//------------------------------------------------------------------------------
#pragma mark - Filesystem probe hooks
//
// SF (TM) and other detection SDKs probe for jailbreak artifacts
// using stat/access/lstat/fopen. RootHide kernel-level hiding covers most paths,
// but these hooks provide defense-in-depth for any gaps.

// Check if a filesystem path targets a known jailbreak artifact.
// Only blocks paths that are unambiguously JB-related — we don't want to
// interfere with legitimate app file operations.
static bool fs_path_should_hide(const char *path) {
	if (!path) return false;

	// Paths containing .jbroot (roothide prefix)
	if (strstr(path, "/.jbroot-") || strstr(path, "/.jbroot/")) return true;

	// Rootless preboot probes recovered from TrueMoney and common jailbreak
	// layouts. Keep the bare preboot root and /private/preboot/active stock-like:
	// third-party apps can observe those on non-jailbroken systems too. Only hide
	// the actual jailbreak-owned descendants and direct artifact markers.
	static const char *preboot_exact_paths[] = {
		"/private/preboot/.installed_palera1n",
		"/private/preboot/jb",
		"/private/preboot/jb/",
		"/private/preboot/procursus",
		"/private/preboot/procursus/",
		NULL
	};
	for (int i = 0; preboot_exact_paths[i]; i++) {
		if (strcmp(path, preboot_exact_paths[i]) == 0) return true;
	}
	if (string_has_prefix(path, "/private/preboot/")) {
		const char *prebootRelative = path + sizeof("/private/preboot/") - 1;
		if (strstr(prebootRelative, "/dopamine-") != NULL) return true;
		if (strstr(prebootRelative, "/jb-") != NULL) return true;
		if (strstr(prebootRelative, "/procursus") != NULL) return true;
		if (strstr(prebootRelative, "/.installed_dopamine") != NULL) return true;
		if (strstr(prebootRelative, "/.installed_palera1n") != NULL) return true;
	}

	// Common jailbreak artifacts from SF's needle table
	static const char *jb_paths[] = {
		"/Applications/Cydia.app",
		"/Library/MobileSubstrate",
		"/usr/sbin/frida-server",
		"/usr/lib/libjailbreak.dylib",
		"/usr/lib/libhooker.dylib",
		"/usr/lib/libsubstitute.dylib",
		"/usr/lib/substrate",
		"/usr/lib/TweakInject",
		"/var/lib/dpkg",
		"/var/lib/cydia",
		"/var/log/syslog",
		"/var/tmp/cydia.log",
		"/private/var/lib/cydia",
		"/private/var/tmp/cydia.log",
		"/private/jailbreak.txt",
		"/jb/jailbreakd.plist",
		"/jb/libjailbreak.dylib",
		"/jb/amfid_payload.dylib",
		"/.cydia_no_stash",
		"/usr/share/jailbreak",
		"/etc/apt/sources.list.d/cydia.list",
		NULL
	};
	for (int i = 0; jb_paths[i]; i++) {
		if (strcmp(path, jb_paths[i]) == 0) return true;
	}

	// JB apps that might exist in /Applications
	if (strncmp(path, "/Applications/", 14) == 0) {
		static const char *jb_apps[] = {
			"Cydia.app", "Sileo.app", "Zebra.app", "Filza.app",
			"Substitute.app", "checkra1n.app", "crackerxi.app",
			NULL
		};
		const char *appname = path + 14;
		for (int i = 0; jb_apps[i]; i++) {
			if (strcmp(appname, jb_apps[i]) == 0) return true;
		}
	}

	// Basename checks for JB dylibs in arbitrary directories
	const char *base = strrchr(path, '/');
	if (base) base++; else base = path;
	if (strstr(base, "systemhook") ||
	    strstr(base, "roothideinit") ||
	    strstr(base, "SubstrateLoader") ||
	    strstr(base, "TweakInject") ||
	    strstr(base, "MobileSubstrate") ||
	    strstr(base, "CydiaSubstrate") ||
	    strstr(base, "libsubstitute") ||
	    strstr(base, "SSLKillSwitch") ||
	    strstr(base, "FridaGadget") ||
	    strstr(base, "cynject"))
		return true;

	return false;
}

__attribute__((noinline))
static int h_access(const char *path, int amode) {
	if (!hider_strict_hook_is_ready(&g_strict_access_session, "access"))
		return orig_access ? orig_access(path, amode) : -1;
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra))
		return orig_access(path, amode);

	if (fs_path_should_hide(path)) {
		errno = ENOENT;
		return -1;
	}
	return orig_access(path, amode);
}

__attribute__((noinline))
static int h_stat(const char *path, struct stat *buf) {
	if (!hider_strict_hook_is_ready(&g_strict_stat_session, "stat"))
		return orig_stat ? orig_stat(path, buf) : -1;
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra))
		return orig_stat(path, buf);

	if (fs_path_should_hide(path)) {
		errno = ENOENT;
		return -1;
	}
	return orig_stat(path, buf);
}

__attribute__((noinline))
static int h_lstat(const char *path, struct stat *buf) {
	if (!hider_strict_hook_is_ready(&g_strict_lstat_session, "lstat"))
		return orig_lstat ? orig_lstat(path, buf) : -1;
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra))
		return orig_lstat(path, buf);

	if (fs_path_should_hide(path)) {
		errno = ENOENT;
		return -1;
	}
	return orig_lstat(path, buf);
}

__attribute__((noinline))
static FILE *h_fopen(const char *path, const char *mode) {
	if (!hider_strict_hook_is_ready(&g_strict_fopen_session, "fopen"))
		return orig_fopen ? orig_fopen(path, mode) : NULL;
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra))
		return orig_fopen(path, mode);

	if (fs_path_should_hide(path)) {
		errno = ENOENT;
		return NULL;
	}
	return orig_fopen(path, mode);
}

__attribute__((noinline))
static DIR *h_opendir(const char *path) {
	if (!hider_strict_hook_is_ready(&g_strict_opendir_session, "opendir"))
		return orig_opendir ? orig_opendir(path) : NULL;
	/* h_readdir resolves the live directory descriptor for every filtered
	 * entry. opendir intentionally remains ownership-neutral. */
	return orig_opendir ? orig_opendir(path) : NULL;
}

__attribute__((noinline))
static struct dirent *h_readdir(DIR *dirp) {
	if (!hider_strict_hook_is_ready(&g_strict_readdir_session, "readdir"))
		return orig_readdir ? orig_readdir(dirp) : NULL;
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra)) {
		return orig_readdir(dirp);
	}

	dir_filter_kind_t kind = DIR_FILTER_NONE;
	if (!dir_filter_kind_for_dir(dirp, &kind) || kind == DIR_FILTER_NONE) {
		/* F_GETPATH is unavailable for some descriptor types/sandboxes. Do not
		 * turn that inability to classify into a detector-visible failure. */
		return orig_readdir(dirp);
	}

	struct dirent *entry = NULL;
	while ((entry = orig_readdir(dirp)) != NULL) {
		if (!dir_entry_should_hide(kind, entry->d_name)) {
			return entry;
		}
	}
	return NULL;
}

__attribute__((noinline))
static int h_closedir(DIR *dirp) {
	if (!hider_strict_hook_is_ready(&g_strict_closedir_session, "closedir"))
		return orig_closedir ? orig_closedir(dirp) : -1;
	/* No DIR allocation or global state is retained; simply preserve stock
	 * close ownership and errno behavior for every caller class. */
	return orig_closedir ? orig_closedir(dirp) : -1;
}

//------------------------------------------------------------------------------
#pragma mark - sysctlbyname hook
//
// SF uses sysctlbyname for device/kernel info queries.
// We filter results that might leak jailbreak state.

__attribute__((noinline))
static int h_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                          void *newp, size_t newlen) {
	if (!hider_is_ready())
		return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : -1;
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra))
		return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);

	/* Preserve the normal two-pass contract without first exposing the real
	 * boot-argument length. Writes and malformed calls still go to the kernel. */
	if (name && oldlenp && !newp && strcmp(name, "kern.bootargs") == 0) {
		const size_t required = 1;
		if (!oldp) {
			*oldlenp = required;
			return 0;
		}
		if (*oldlenp < required) {
			*oldlenp = required;
			errno = ENOMEM;
			return -1;
		}
		((char *)oldp)[0] = '\0';
		*oldlenp = required;
		return 0;
	}

	return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

//------------------------------------------------------------------------------
#pragma mark - mach_port_get_refs hook
//
// Hidden injection can leave extra self-task send rights around. Some app-side
// detectors treat that as proof that the task port was obtained. Normalize only
// that narrow self-query back to a stock-like count for app callers.

__attribute__((noinline))
static kern_return_t h_mach_port_get_refs(ipc_space_t task, mach_port_name_t name,
                                          mach_port_right_t right, mach_port_urefs_t *refs) {
	if (!hider_is_ready())
		return orig_mach_port_get_refs ? orig_mach_port_get_refs(task, name, right, refs) : KERN_FAILURE;
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra))
		return orig_mach_port_get_refs(task, name, right, refs);

	kern_return_t kr = orig_mach_port_get_refs(task, name, right, refs);
	if (kr != KERN_SUCCESS || !refs)
		return kr;

	if (task == mach_task_self_ && name == mach_task_self_ && right == MACH_PORT_RIGHT_SEND) {
		if (*refs > 2)
			*refs = 2;
	}

	return kr;
}

//------------------------------------------------------------------------------
#pragma mark - Public Init

extern void rhi_diag_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

// Called from main.c when gHiddenInjection is true, after env vars are
// consumed and before roothide_init_with_executable / TweakLoader.
void hidden_dylib_hider_init(void)
{
	unsigned expected = HIDER_STATE_UNINITIALIZED;
	if (!atomic_compare_exchange_strong_explicit(&g_init_state, &expected,
	                                             HIDER_STATE_INITIALIZING,
	                                             memory_order_acq_rel,
	                                             memory_order_acquire)) {
		// Another call is either completing initialization or has already made
		// the core hooks visible.  Do not recurse through dyld registration.
		return;
	}

	rhi_hider_identity_init();
	rhi_hider_caller_policy_init();
	if (!rhi_hider_caller_register_own_function(hidden_dylib_hider_init)) {
		/* Fail closed: systemhook retains no implicit privileged caller fallback. */
		rhi_diag_log("HIDER caller capability unavailable; unclassified callers remain filtered");
	}

	/* Save every native callback/loader entry point before registering our first
	 * permanent relay. Initial dyld/ObjC replays are callback contexts too, so
	 * the raw-pass-through fallback must already have its saved originals. */
	orig_dladdr = dladdr;
	orig_dlsym = dlsym;
	orig_dlerror = dlerror;
	orig_dyld_image_count = _dyld_image_count;
	orig_dyld_get_image_name = _dyld_get_image_name;
	orig_dyld_get_image_header = _dyld_get_image_header;
	orig_dyld_get_image_vmaddr_slide = _dyld_get_image_vmaddr_slide;
	orig_dyld_register_func_for_add_image = _dyld_register_func_for_add_image;
	orig_dyld_register_func_for_remove_image = _dyld_register_func_for_remove_image;
	orig_task_info = task_info;
	orig_class_getImageName = class_getImageName;
	orig_objc_copyClassList = objc_copyClassList;
	orig_objc_copyImageNames = objc_copyImageNames;
	orig_objc_copyClassNamesForImage = objc_copyClassNamesForImage;
	orig_objc_addLoadImageFunc = objc_addLoadImageFunc;
	orig_dlopen = dlopen;
	orig_dlclose = dlclose;
	orig_fork = fork;
	orig_getfsstat = getfsstat;
	orig_sysctl = sysctl;
	orig_getenv = getenv;
	orig_access = access;
	orig_stat = stat;
	orig_lstat = lstat;
	orig_statfs = statfs;
	orig_statvfs = statvfs;
	orig_fopen = fopen;
	orig_sysctlbyname = sysctlbyname;
	orig_opendir = opendir;
	orig_readdir = readdir;
	orig_closedir = closedir;
	orig_mach_port_get_refs = mach_port_get_refs;
	if (pthread_atfork(hider_catalog_atfork_prepare,
	                   hider_catalog_atfork_parent,
	                   hider_catalog_atfork_child) != 0) {
		rhi_diag_log("HIDER atfork barrier unavailable; refusing filtered hooks");
		os_unfair_lock_lock(&g_lock);
		g_image_tracking_state = HIDER_TRACKING_NATIVE;
		os_unfair_lock_unlock(&g_lock);
		atomic_store_explicit(&g_callback_delivery_route, HIDER_DELIVERY_PASSTHROUGH,
		                      memory_order_release);
		atomic_store_explicit(&g_init_state, HIDER_STATE_FAILED, memory_order_release);
		return;
	}

	// Cache true executable identity before the ObjC relay validates main-image pins.
	g_executable_path = rhi_hider_identity_executable_path();
	g_executable_header = rhi_hider_identity_executable_header();

	rhi_diag_log("HIDER init start, _dyld_image_count=%u", _dyld_image_count());

	// 1. Register callbacks with the REAL dyld functions (before hooking).
	//    dyld will immediately replay all currently-loaded images to our stable
	//    catalog before any replacement import slot becomes visible.
	if (!orig_dyld_register_func_for_add_image || !orig_dyld_register_func_for_remove_image) {
		rhi_diag_log("HIDER native dyld callback API unavailable; refusing filtered hooks");
		os_unfair_lock_lock(&g_lock);
		g_image_tracking_state = HIDER_TRACKING_NATIVE;
		os_unfair_lock_unlock(&g_lock);
		atomic_store_explicit(&g_init_state, HIDER_STATE_FAILED, memory_order_release);
		return;
	}
	orig_dyld_register_func_for_add_image(on_image_added);
	orig_dyld_register_func_for_remove_image(on_image_removed);

	os_unfair_lock_lock(&g_lock);
	uint32_t catalog_all = catalog_active_count_locked(true);
	uint32_t catalog_visible = catalog_active_count_locked(false);
	os_unfair_lock_unlock(&g_lock);
	rhi_diag_log("HIDER after catalog replay, all=%u visible=%u", catalog_all, catalog_visible);

	// 2. Cache dyld_all_image_infos for task_info filtering.
	{
		task_dyld_info_data_t tdi;
		mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
		if (task_info(mach_task_self_, TASK_DYLD_INFO, (task_info_t)&tdi, &cnt) == KERN_SUCCESS) {
			g_real_aii = (struct dyld_all_image_infos *)(uintptr_t)tdi.all_image_info_addr;
		}
	}

	rhi_diag_log("HIDER g_real_aii=%p", (void *)g_real_aii);

	/* Register exactly one relay with the original ObjC runtime before its API
	 * is rebound.  It records runtime-timed load events; filtered callbacks are
	 * never synthesized from dyld add-image delivery. */
	os_unfair_lock_lock(&g_lock);
	bool register_objc_relay = hider_tracking_is_filtered_locked();
	os_unfair_lock_unlock(&g_lock);
	if (register_objc_relay && orig_objc_addLoadImageFunc) {
		orig_objc_addLoadImageFunc(on_objc_image_loaded);
	}

	load_hider_profile_from_environment();

	/*
	 * 4. Prepare every required core import mutation before the first write.
	 * The originals above were published before this call. A transaction that
	 * is incomplete, partial, or uncertain is never presented as a hider: all
	 * linked views keep forwarding through the untouched real API instead.
	 */
	const rhi_rebind_spec_t core_specs[] = {
		{ "_dyld_image_count", (void *)_dyld_image_count, (void *)h_image_count },
		{ "_dyld_get_image_name", (void *)_dyld_get_image_name, (void *)h_get_image_name },
		{ "_dyld_get_image_header", (void *)_dyld_get_image_header, (void *)h_get_image_header },
		{ "_dyld_get_image_vmaddr_slide", (void *)_dyld_get_image_vmaddr_slide, (void *)h_get_image_vmaddr_slide },
		{ "_dyld_register_func_for_add_image", (void *)_dyld_register_func_for_add_image, (void *)h_register_func_for_add_image },
		{ "_dyld_register_func_for_remove_image", (void *)_dyld_register_func_for_remove_image, (void *)h_register_func_for_remove_image },
		{ "dlsym", (void *)dlsym, (void *)h_dlsym },
		{ "dlerror", (void *)dlerror, (void *)h_dlerror },
		{ "dladdr", (void *)dladdr, (void *)h_dladdr },
		{ "task_info", (void *)task_info, (void *)h_task_info },
		{ "fork", (void *)fork, (void *)h_fork },
		{ "sysctl", (void *)sysctl, (void *)h_sysctl },
		{ "getfsstat", (void *)getfsstat, (void *)h_getfsstat },
		{ "statfs", (void *)statfs, (void *)h_statfs },
		{ "statvfs", (void *)statvfs, (void *)h_statvfs },
		{ "sysctlbyname", (void *)sysctlbyname, (void *)h_sysctlbyname },
		{ "mach_port_get_refs", (void *)mach_port_get_refs, (void *)h_mach_port_get_refs },
	};
	rhi_hider_hook_session_reset(&g_core_hook_session, "hider-core", true);
	if (!rhi_hider_hook_session_start(&g_core_hook_session, core_specs,
	                                  sizeof(core_specs) / sizeof(*core_specs))) {
		rhi_diag_log("HIDER core transaction %s; concealment disabled",
		             rhi_hook_state_name(rhi_hider_hook_session_state(&g_core_hook_session)));
		atomic_store_explicit(&g_init_state, HIDER_STATE_FAILED, memory_order_release);
		return;
	}

	if (atomic_load_explicit(&g_callback_delivery_failed, memory_order_acquire) ||
	    atomic_load_explicit(&g_init_state, memory_order_acquire) == HIDER_STATE_FAILED) {
		rhi_diag_log("HIDER callback delivery ambiguity; concealment readiness disabled");
		atomic_store_explicit(&g_init_state, HIDER_STATE_FAILED, memory_order_release);
		return;
	}
	atomic_store_explicit(&g_init_state, HIDER_STATE_READY, memory_order_release);
	rhi_diag_log("HIDER init complete — verified core hooks enabled");
}

void hidden_dylib_hider_enable_strict_hooks(void)
{
	if (!hider_is_ready()) {
		return;
	}
	unsigned expected = HIDER_STATE_UNINITIALIZED;
	if (!atomic_compare_exchange_strong_explicit(&g_strict_state, &expected,
	                                             HIDER_STATE_INITIALIZING,
	                                             memory_order_acq_rel,
	                                             memory_order_acquire)) {
		return;
	}

	/*
	 * Strict components are independent optional transactions. A failed
	 * component stays unavailable, but cannot make us advertise its hook via
	 * dlsym. The helper's one-slot session gives each mutation its own
	 * prepare/commit/readback result rather than collapsing failures into a
	 * global success bit.
	 */
#define START_STRICT_SESSION(SESSION, SYMBOL, ORIGINAL, REPLACEMENT) do { \
	const rhi_rebind_spec_t strict_spec = { (SYMBOL), (void *)(ORIGINAL), (void *)(REPLACEMENT) }; \
	rhi_hider_hook_session_reset(&(SESSION), (SYMBOL), false); \
	if (!rhi_hider_hook_session_start(&(SESSION), &strict_spec, 1)) \
		rhi_diag_log("HIDER strict %s unavailable: %s", (SYMBOL), \
		             rhi_hook_state_name(rhi_hider_hook_session_state(&(SESSION)))); \
} while (0)

	// ObjC runtime — hide injected images from class/image enumeration.
	if (g_hook_objc_runtime_enabled) {
		START_STRICT_SESSION(g_strict_class_image_session, "class_getImageName", class_getImageName, h_class_getImageName);
		START_STRICT_SESSION(g_strict_copy_images_session, "objc_copyImageNames", objc_copyImageNames, h_objc_copyImageNames);
		START_STRICT_SESSION(g_strict_copy_names_session, "objc_copyClassNamesForImage", objc_copyClassNamesForImage, h_objc_copyClassNamesForImage);
		START_STRICT_SESSION(g_strict_add_load_session, "objc_addLoadImageFunc", objc_addLoadImageFunc, h_objc_addLoadImageFunc);
	}
	if (g_hook_objc_copy_class_list_enabled) {
		START_STRICT_SESSION(g_strict_copy_class_list_session, "objc_copyClassList", objc_copyClassList, h_objc_copyClassList);
	}
	if (g_hook_url_schemes_enabled) {
		install_url_scheme_hooks();
		if (!g_url_scheme_hooks_active)
			rhi_diag_log("HIDER strict URL-scheme hook unavailable");
	}

	// Environment — hide DYLD_INSERT_LIBRARIES and JB markers
	if (g_hook_environment_enabled) {
		START_STRICT_SESSION(g_strict_getenv_session, "getenv", getenv, h_getenv);
	}

	// Filesystem probes — hide jailbreak artifacts from stat/access/fopen and
	// filter preboot descendant enumeration without lying about the preboot root.
	if (g_hook_filesystem_enabled) {
		START_STRICT_SESSION(g_strict_access_session, "access", access, h_access);
		START_STRICT_SESSION(g_strict_stat_session, "stat", stat, h_stat);
		START_STRICT_SESSION(g_strict_lstat_session, "lstat", lstat, h_lstat);
		START_STRICT_SESSION(g_strict_fopen_session, "fopen", fopen, h_fopen);
	}
	if (g_hook_directory_enabled) {
		START_STRICT_SESSION(g_strict_opendir_session, "opendir", opendir, h_opendir);
		START_STRICT_SESSION(g_strict_readdir_session, "readdir", readdir, h_readdir);
		START_STRICT_SESSION(g_strict_closedir_session, "closedir", closedir, h_closedir);
	}

#undef START_STRICT_SESSION

	// Do not expose strict-hook pointers through dlsym until every requested
	// strict installation has run.  A concurrent/reentrant caller observes the
	// original APIs during this short window instead of a half-installed set.
	atomic_store_explicit(&g_strict_state, HIDER_STATE_READY, memory_order_release);
	rhi_diag_log("HIDER strict hooks enabled");
}

//------------------------------------------------------------------------------
#pragma mark - dlsym remap

// Called from dyld_dlsym_hook in main.c when gHiddenInjection is active.
// If the app looks up a symbol name that we've hooked, return our hooked
// function pointer so the app can't get the real (unhooked) address.
// Returns NULL if the symbol isn't one we remap (caller should proceed
// with the original dlsym).
void *hidden_dylib_hider_dlsym_remap(const char *name)
{
	if (!hider_is_ready() || !name)
		return NULL;

	// Only remap dlopen when the actual GOT-level fallback hook was installed.
	// dyld_patch_fallback_enabled is broader than that: it only means we need
	// the fallback-capable dyld patch path, not that dlopen itself was rebound.
	if (!strcmp(name, "dlopen") &&
	    atomic_load_explicit(&dlopen_fallback_hook_installed, memory_order_acquire) &&
	    roothide_hidden_tweak_hooks_ready())
		return (void *)dlopen_fallback_hook;

	// Table of symbol names → our hooked function pointers.
	// Only advertise symbols that are actually live in the current phase.
	static const struct {
		const char *sym;
		void *func;
		const rhi_hider_hook_session_t *session;
		const bool *enabled;
	} remap[] = {
		{ "_dyld_image_count",                    (void *)h_image_count,                   &g_core_hook_session, NULL },
		{ "_dyld_get_image_name",                  (void *)h_get_image_name,               &g_core_hook_session, NULL },
		{ "_dyld_get_image_header",                (void *)h_get_image_header,             &g_core_hook_session, NULL },
		{ "_dyld_get_image_vmaddr_slide",          (void *)h_get_image_vmaddr_slide,       &g_core_hook_session, NULL },
		{ "_dyld_register_func_for_add_image",     (void *)h_register_func_for_add_image,  &g_core_hook_session, NULL },
		{ "_dyld_register_func_for_remove_image",  (void *)h_register_func_for_remove_image,&g_core_hook_session, NULL },
		{ "task_info",                             (void *)h_task_info,                    &g_core_hook_session, NULL },
		{ "dladdr",                                (void *)h_dladdr,                       &g_core_hook_session, NULL },
		{ "dlsym",                                 (void *)h_dlsym,                        &g_core_hook_session, NULL },
		{ "dlerror",                               (void *)h_dlerror,                      &g_core_hook_session, NULL },
		{ "class_getImageName",                    (void *)h_class_getImageName,           &g_strict_class_image_session, &g_hook_objc_runtime_enabled },
		{ "objc_copyClassList",                    (void *)h_objc_copyClassList,           &g_strict_copy_class_list_session, &g_hook_objc_copy_class_list_enabled },
		{ "objc_copyImageNames",                   (void *)h_objc_copyImageNames,          &g_strict_copy_images_session, &g_hook_objc_runtime_enabled },
		{ "objc_copyClassNamesForImage",           (void *)h_objc_copyClassNamesForImage,  &g_strict_copy_names_session, &g_hook_objc_runtime_enabled },
		{ "objc_addLoadImageFunc",                 (void *)h_objc_addLoadImageFunc,        &g_strict_add_load_session, &g_hook_objc_runtime_enabled },
		// NOTE: keep dlopen off the remap table. The dlopen hook path remains
		// disabled due to the iOS 15 init_dyldhooks fallback conflict.
		// { "dlopen",                               (void *)h_dlopen,                       false, NULL },
		{ "fork",                                  (void *)h_fork,                         &g_core_hook_session, NULL },
		{ "getfsstat",                             (void *)h_getfsstat,                    &g_core_hook_session, NULL },
		{ "statfs",                                (void *)h_statfs,                       &g_core_hook_session, NULL },
		{ "statvfs",                               (void *)h_statvfs,                      &g_core_hook_session, NULL },
		{ "sysctl",                                (void *)h_sysctl,                       &g_core_hook_session, NULL },
		{ "getenv",                                (void *)h_getenv,                       &g_strict_getenv_session, &g_hook_environment_enabled },
		{ "access",                                (void *)h_access,                       &g_strict_access_session, &g_hook_filesystem_enabled },
		{ "stat",                                  (void *)h_stat,                         &g_strict_stat_session, &g_hook_filesystem_enabled },
		{ "lstat",                                 (void *)h_lstat,                        &g_strict_lstat_session, &g_hook_filesystem_enabled },
		{ "fopen",                                 (void *)h_fopen,                        &g_strict_fopen_session, &g_hook_filesystem_enabled },
		{ "opendir",                               (void *)h_opendir,                      &g_strict_opendir_session, &g_hook_directory_enabled },
		{ "readdir",                               (void *)h_readdir,                      &g_strict_readdir_session, &g_hook_directory_enabled },
		{ "closedir",                              (void *)h_closedir,                     &g_strict_closedir_session, &g_hook_directory_enabled },
		{ "sysctlbyname",                          (void *)h_sysctlbyname,                 &g_core_hook_session, NULL },
		{ "mach_port_get_refs",                    (void *)h_mach_port_get_refs,           &g_core_hook_session, NULL },
	};

	for (unsigned i = 0; i < sizeof(remap) / sizeof(*remap); i++) {
		if (strcmp(name, remap[i].sym) == 0) {
			if (!rhi_hider_hook_session_hook_is_active(remap[i].session, remap[i].sym))
				return NULL;
			if (remap[i].enabled && !*remap[i].enabled)
				return NULL;
			return remap[i].func;
		}
	}

	return NULL;
}
