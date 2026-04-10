/*
 * hidden_dylib_hider.c — Hide JB dylibs from image enumeration in hidden-injection mode.
 *
 * Strategy:
 *   - Hook dyld enumeration functions via litehook (in-place DSC replacement)
 *   - Maintain two image arrays: g_all (complete) and g_visible (filtered)
 *   - Caller detection via __builtin_return_address + dyld_image_path_containing_address:
 *     tweak callers → g_all, app callers → g_visible
 *   - Also hooks task_info(TASK_DYLD_INFO) to present filtered dyld_all_image_infos
 *
 * The caller check uses dyld_image_path_containing_address() which queries dyld's
 * internal image list (NOT affected by our hooks) — safe and accurate.
 *
 * Advantage over Shadow/Choicy: we're in systemhook, hooking at the DSC level
 * before any app code runs. No extra dylib to hide, no GOT modifications,
 * no dependency on MSHookFunction/ellekit.
 */

#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach/mig.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
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
#include <errno.h>
#include <dirent.h>

#include "common.h"

// From roothider_main.c — non-static after our edit
extern bool hidden_tweak_filter_should_block_path(const char *path);
extern bool dyld_patch_fallback_enabled;
extern bool dlopen_fallback_hook_installed;
extern void *dlopen_fallback_hook(const char *path, int mode);

// dyld private — always available, NOT hooked by us
extern const char *dyld_image_path_containing_address(const void *addr);

// From litehook
extern kern_return_t litehook_hook_function(void *source, void *target);
typedef struct mach_header mach_header_u;
#define LITEHOOK_REBIND_GLOBAL NULL
extern void litehook_rebind_symbol(const mach_header_u *targetHeader, void *replacee, void *replacement, bool (*exceptionFilter)(const mach_header_u *header));

// ObjC runtime functions we hook via GOT rebinding
extern const char *class_getImageName(Class cls);
extern const char * _Nonnull * objc_copyImageNames(unsigned int *outCount);
extern const char * _Nonnull * objc_copyClassNamesForImage(const char *image, unsigned int *outCount);

// Saved original function pointers — set before rebinding, stay valid because
// litehook_rebind_symbol only patches GOT entries, the DSC functions are intact.
static int (*orig_dladdr)(const void *, Dl_info *) = NULL;
static void *(*orig_dlsym)(void *, const char *) = NULL;
static uint32_t (*orig_dyld_image_count)(void) = NULL;
static const char *(*orig_dyld_get_image_name)(uint32_t) = NULL;
static const struct mach_header *(*orig_dyld_get_image_header)(uint32_t) = NULL;
static intptr_t (*orig_dyld_get_image_vmaddr_slide)(uint32_t) = NULL;
static void (*orig_dyld_register_func_for_add_image)(void (*)(const struct mach_header *, intptr_t)) = NULL;
static void (*orig_dyld_register_func_for_remove_image)(void (*)(const struct mach_header *, intptr_t)) = NULL;
static kern_return_t (*orig_task_info)(task_name_t, task_flavor_t, task_info_t, mach_msg_type_number_t *) = NULL;
static const char *(*orig_class_getImageName)(Class) = NULL;
static const char * _Nonnull *(*orig_objc_copyImageNames)(unsigned int *) = NULL;
static const char * _Nonnull *(*orig_objc_copyClassNamesForImage)(const char *, unsigned int *) = NULL;
static void (*orig_objc_addLoadImageFunc)(objc_func_loadImage) = NULL;
static void *(*orig_dlopen)(const char *, int) = NULL;
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

// Forward declarations of hook functions (needed by translate_hook_to_orig)
static uint32_t h_image_count(void);
static const char *h_get_image_name(uint32_t idx);
static const struct mach_header *h_get_image_header(uint32_t idx);
static intptr_t h_get_image_vmaddr_slide(uint32_t idx);
static void h_register_func_for_add_image(void (*func)(const struct mach_header *, intptr_t));
static void h_register_func_for_remove_image(void (*func)(const struct mach_header *, intptr_t));
static kern_return_t h_task_info(task_name_t target, task_flavor_t flavor,
                                  task_info_t info_out, mach_msg_type_number_t *cnt);
static int h_dladdr(const void *addr, Dl_info *info);
static void *h_dlsym(void *handle, const char *symbol);
static const char *h_class_getImageName(Class cls);
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
static bool fs_path_should_hide(const char *path);

//------------------------------------------------------------------------------
#pragma mark - Image Entry + Dynamic Array

typedef struct {
	const char               *name;     // dyld-owned pointer, valid while image loaded
	const struct mach_header *header;
	intptr_t                  slide;
} image_entry_t;

typedef struct {
	image_entry_t *items;
	uint32_t       count;
	uint32_t       cap;
} image_array_t;

static void arr_ensure(image_array_t *a, uint32_t need) {
	if (need <= a->cap) return;
	uint32_t nc = a->cap ? a->cap * 2 : 64;
	if (nc < need) nc = need;
	a->items = realloc(a->items, nc * sizeof(image_entry_t));
	a->cap = nc;
}

static void arr_add(image_array_t *a, const char *name,
                    const struct mach_header *mh, intptr_t slide) {
	arr_ensure(a, a->count + 1);
	a->items[a->count].name   = name;  // store dyld's canonical pointer directly
	a->items[a->count].header = mh;
	a->items[a->count].slide  = slide;
	a->count++;
}

static void arr_remove_by_header(image_array_t *a, const struct mach_header *mh) {
	for (uint32_t i = 0; i < a->count; i++) {
		if (a->items[i].header == mh) {
			// name is dyld-owned, don't free
			if (i + 1 < a->count)
				memmove(&a->items[i], &a->items[i + 1],
				        (a->count - i - 1) * sizeof(image_entry_t));
			a->count--;
			return;
		}
	}
}

static bool arr_contains_header(const image_array_t *a, const struct mach_header *mh) {
	for (uint32_t i = 0; i < a->count; i++) {
		if (a->items[i].header == mh) return true;
	}
	return false;
}

//------------------------------------------------------------------------------
#pragma mark - State

static image_array_t g_all     = {0};  // Every image (tweaks see this)
static image_array_t g_visible = {0};  // Filtered (app sees this)
static os_unfair_lock g_lock   = OS_UNFAIR_LOCK_INIT;

typedef enum {
	DIR_FILTER_NONE = 0,
	DIR_FILTER_PREBOOT_ROOT,
	DIR_FILTER_PREBOOT_HASH_ROOT,
} dir_filter_kind_t;

typedef struct dir_filter_entry {
	DIR *dirp;
	dir_filter_kind_t kind;
	struct dir_filter_entry *next;
} dir_filter_entry_t;

static dir_filter_entry_t *g_dir_filters = NULL;
static os_unfair_lock g_dir_filter_lock = OS_UNFAIR_LOCK_INIT;

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

static void register_dir_filter(DIR *dirp, dir_filter_kind_t kind) {
	if (!dirp || kind == DIR_FILTER_NONE) {
		return;
	}

	dir_filter_entry_t *entry = calloc(1, sizeof(*entry));
	if (!entry) {
		return;
	}

	entry->dirp = dirp;
	entry->kind = kind;

	os_unfair_lock_lock(&g_dir_filter_lock);
	entry->next = g_dir_filters;
	g_dir_filters = entry;
	os_unfair_lock_unlock(&g_dir_filter_lock);
}

static dir_filter_kind_t lookup_dir_filter(DIR *dirp) {
	dir_filter_kind_t kind = DIR_FILTER_NONE;

	os_unfair_lock_lock(&g_dir_filter_lock);
	for (dir_filter_entry_t *entry = g_dir_filters; entry; entry = entry->next) {
		if (entry->dirp == dirp) {
			kind = entry->kind;
			break;
		}
	}
	os_unfair_lock_unlock(&g_dir_filter_lock);

	return kind;
}

static void unregister_dir_filter(DIR *dirp) {
	os_unfair_lock_lock(&g_dir_filter_lock);
	dir_filter_entry_t **cursor = &g_dir_filters;
	while (*cursor) {
		if ((*cursor)->dirp == dirp) {
			dir_filter_entry_t *entry = *cursor;
			*cursor = entry->next;
			free(entry);
			break;
		}
		cursor = &(*cursor)->next;
	}
	os_unfair_lock_unlock(&g_dir_filter_lock);
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

// Callback tracking — stores app AND tweak registrations separately
typedef struct {
	void (*func)(const struct mach_header *, intptr_t);
	bool  from_hidden;  // true = registered by code in a hidden image (tweak)
} cb_entry_t;

static cb_entry_t *g_add_cbs    = NULL;
static uint32_t    g_add_cb_n   = 0;
static uint32_t    g_add_cb_cap = 0;
static cb_entry_t *g_rem_cbs    = NULL;
static uint32_t    g_rem_cb_n   = 0;
static uint32_t    g_rem_cb_cap = 0;
typedef struct {
	objc_func_loadImage func;
	bool                from_hidden;
} objc_load_cb_entry_t;
static objc_load_cb_entry_t *g_objc_addload_cbs = NULL;
static uint32_t              g_objc_addload_cb_n = 0;
static uint32_t              g_objc_addload_cb_cap = 0;

// task_info(TASK_DYLD_INFO) snapshot
static struct dyld_all_image_infos  g_ti_snap     = {0};
static struct dyld_image_info      *g_ti_images   = NULL;
static uint32_t                     g_ti_cap      = 0;
static struct dyld_uuid_info       *g_ti_uuids    = NULL;
static uint32_t                     g_ti_uuid_cap = 0;
static struct dyld_all_image_infos *g_real_aii    = NULL;  // cached from first task_info call

static bool g_inited = false;
static bool g_strict_hooks_enabled = false;

// Cache the executable path for dladdr / class_getImageName substitution
static const char *g_executable_path = NULL;

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

// Bypass cache: 64-slot ring buffer mapping return addresses → hidden decision.
// Avoids calling dyld_image_path_containing_address + string matching on every
// hooked function invocation. Same design as Choicy's stealth caller cache.
typedef struct {
	const void *ra;
	bool        hidden;
} caller_cache_entry_t;

static caller_cache_entry_t g_caller_cache[64] = {0};
static uint32_t             g_caller_cache_next = 0;
static os_unfair_lock        g_caller_cache_lock = OS_UNFAIR_LOCK_INIT;

static bool caller_is_hidden(const void *ra) {
	if (!ra) return false;

	// Check cache first
	os_unfair_lock_lock(&g_caller_cache_lock);
	for (uint32_t i = 0; i < 64; i++) {
		if (g_caller_cache[i].ra == ra) {
			bool h = g_caller_cache[i].hidden;
			os_unfair_lock_unlock(&g_caller_cache_lock);
			return h;
		}
	}
	os_unfair_lock_unlock(&g_caller_cache_lock);

	// Cache miss — resolve via dyld private API (unaffected by our hooks)
	const char *p = dyld_image_path_containing_address(ra);
	bool hidden = p ? image_path_should_hide(p) : false;

	// Store in cache
	os_unfair_lock_lock(&g_caller_cache_lock);
	uint32_t slot = g_caller_cache_next++ % 64;
	g_caller_cache[slot] = (caller_cache_entry_t){ .ra = ra, .hidden = hidden };
	os_unfair_lock_unlock(&g_caller_cache_lock);

	return hidden;
}

//------------------------------------------------------------------------------
#pragma mark - dyld Notification Callbacks (registered before hooking)

static void on_image_added(const struct mach_header *mh, intptr_t slide) {
	const char *path = dyld_image_path_containing_address(mh);
	if (!path) return;

	bool hide = image_path_should_hide(path);

	os_unfair_lock_lock(&g_lock);

	arr_add(&g_all, path, mh, slide);
	if (!hide)
		arr_add(&g_visible, path, mh, slide);

	// Copy callbacks that need notification (under lock)
	uint32_t n = g_add_cb_n;
	cb_entry_t *snapshot = n ? malloc(n * sizeof(cb_entry_t)) : NULL;
	if (snapshot) memcpy(snapshot, g_add_cbs, n * sizeof(cb_entry_t));
	uint32_t objc_n = g_objc_addload_cb_n;
	objc_load_cb_entry_t *objc_snapshot = objc_n ? malloc(objc_n * sizeof(objc_load_cb_entry_t)) : NULL;
	if (objc_snapshot) memcpy(objc_snapshot, g_objc_addload_cbs, objc_n * sizeof(objc_load_cb_entry_t));

	os_unfair_lock_unlock(&g_lock);

	// Deliver outside lock to avoid deadlock if callback does dyld calls
	for (uint32_t i = 0; i < n; i++) {
		// Tweak callback → always gets notified
		// App callback → only for visible images
		if (snapshot[i].from_hidden || !hide)
			snapshot[i].func(mh, slide);
	}
	free(snapshot);

	// ObjC load-image callbacks use the objc_addLoadImageFunc signature
	// (header only, no slide). Keep the same visibility policy as the dyld
	// add-image callbacks without returning NULL from dlsym for a real API.
	for (uint32_t i = 0; i < objc_n; i++) {
		if (objc_snapshot[i].from_hidden || !hide)
			objc_snapshot[i].func(mh);
	}
	free(objc_snapshot);
}

static void on_image_removed(const struct mach_header *mh, intptr_t slide) {
	os_unfair_lock_lock(&g_lock);

	bool was_in_all = arr_contains_header(&g_all, mh);
	bool was_visible = arr_contains_header(&g_visible, mh);
	arr_remove_by_header(&g_all, mh);
	if (was_visible)
		arr_remove_by_header(&g_visible, mh);

	uint32_t n = g_rem_cb_n;
	cb_entry_t *snapshot = n ? malloc(n * sizeof(cb_entry_t)) : NULL;
	if (snapshot) memcpy(snapshot, g_rem_cbs, n * sizeof(cb_entry_t));

	os_unfair_lock_unlock(&g_lock);

	if (was_in_all) {
		for (uint32_t i = 0; i < n; i++) {
			if (snapshot[i].from_hidden || was_visible)
				snapshot[i].func(mh, slide);
		}
	}
	free(snapshot);
}

//------------------------------------------------------------------------------
#pragma mark - Hooked dyld Functions

__attribute__((noinline))
static uint32_t h_image_count(void) {
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	bool hidden = caller_is_hidden(ra);
	os_unfair_lock_lock(&g_lock);
	uint32_t c = hidden ? g_all.count : g_visible.count;
	os_unfair_lock_unlock(&g_lock);
	return c;
}

__attribute__((noinline))
static const char *h_get_image_name(uint32_t idx) {
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	bool hidden = caller_is_hidden(ra);
	os_unfair_lock_lock(&g_lock);
	const image_array_t *a = hidden ? &g_all : &g_visible;
	const char *n = (idx < a->count) ? a->items[idx].name : NULL;
	os_unfair_lock_unlock(&g_lock);
	return n;
}

__attribute__((noinline))
static const struct mach_header *h_get_image_header(uint32_t idx) {
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	bool hidden = caller_is_hidden(ra);
	os_unfair_lock_lock(&g_lock);
	const image_array_t *a = hidden ? &g_all : &g_visible;
	const struct mach_header *h = (idx < a->count) ? a->items[idx].header : NULL;
	os_unfair_lock_unlock(&g_lock);
	return h;
}

__attribute__((noinline))
static intptr_t h_get_image_vmaddr_slide(uint32_t idx) {
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	bool hidden = caller_is_hidden(ra);
	os_unfair_lock_lock(&g_lock);
	const image_array_t *a = hidden ? &g_all : &g_visible;
	intptr_t s = (idx < a->count) ? a->items[idx].slide : 0;
	os_unfair_lock_unlock(&g_lock);
	return s;
}

__attribute__((noinline))
static void h_register_func_for_add_image(void (*func)(const struct mach_header *, intptr_t)) {
	if (!func) return;

	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	bool hidden = caller_is_hidden(ra);

	os_unfair_lock_lock(&g_lock);

	// Store callback with origin flag
	if (g_add_cb_n >= g_add_cb_cap) {
		g_add_cb_cap = g_add_cb_cap ? g_add_cb_cap * 2 : 8;
		g_add_cbs = realloc(g_add_cbs, g_add_cb_cap * sizeof(cb_entry_t));
	}
	g_add_cbs[g_add_cb_n++] = (cb_entry_t){.func = func, .from_hidden = hidden};

	// Replay: tweak gets all, app gets visible only
	const image_array_t *a = hidden ? &g_all : &g_visible;
	uint32_t n = a->count;
	const struct mach_header **hdrs = NULL;
	intptr_t *slides = NULL;
	if (n) {
		hdrs = malloc(n * sizeof(void *));
		slides = malloc(n * sizeof(intptr_t));
		for (uint32_t i = 0; i < n; i++) {
			hdrs[i]   = a->items[i].header;
			slides[i] = a->items[i].slide;
		}
	}

	os_unfair_lock_unlock(&g_lock);

	// Call outside lock
	for (uint32_t i = 0; i < n; i++)
		func(hdrs[i], slides[i]);
	free(hdrs);
	free(slides);
}

__attribute__((noinline))
static void h_register_func_for_remove_image(void (*func)(const struct mach_header *, intptr_t)) {
	if (!func) return;

	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	bool hidden = caller_is_hidden(ra);

	os_unfair_lock_lock(&g_lock);
	if (g_rem_cb_n >= g_rem_cb_cap) {
		g_rem_cb_cap = g_rem_cb_cap ? g_rem_cb_cap * 2 : 8;
		g_rem_cbs = realloc(g_rem_cbs, g_rem_cb_cap * sizeof(cb_entry_t));
	}
	g_rem_cbs[g_rem_cb_n++] = (cb_entry_t){.func = func, .from_hidden = hidden};
	os_unfair_lock_unlock(&g_lock);
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
	req->task_info_outCnt = *cnt;

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
	if (out_n > *cnt) out_n = *cnt;
	memcpy(info_out, rep->task_info_out, out_n * sizeof(integer_t));
	*cnt = out_n;

	return KERN_SUCCESS;
}

static bool header_is_visible(const struct mach_header *mh) {
	for (uint32_t i = 0; i < g_visible.count; i++) {
		if (g_visible.items[i].header == mh)
			return true;
	}
	return false;
}

static void build_task_snapshot(void) {
	// Must be called with g_lock held.
	// Filter g_real_aii->infoArray directly: copy visible entries verbatim.
	// This preserves every field (imageFilePath pointer, imageFileModDate,
	// imageLoadAddress) exactly as dyld reported — no reconstruction needed.
	// Pointer identity between task_info, _dyld_get_image_name, and dladdr
	// is maintained because all use dyld's canonical pointers.
	if (!g_real_aii || !g_real_aii->infoArray) {
		// Shouldn't happen, but handle gracefully
		memset(&g_ti_snap, 0, sizeof(g_ti_snap));
		return;
	}

	uint32_t src_n = g_real_aii->infoArrayCount;
	if (src_n > g_ti_cap) {
		g_ti_images = realloc(g_ti_images, src_n * sizeof(struct dyld_image_info));
		g_ti_cap = src_n;
	}

	uint32_t vis_n = 0;
	for (uint32_t i = 0; i < src_n; i++) {
		const struct dyld_image_info *entry = &g_real_aii->infoArray[i];
		if (!image_path_should_hide(entry->imageFilePath))
			g_ti_images[vis_n++] = *entry;  // verbatim copy
	}

	g_ti_snap = *g_real_aii;
	g_ti_snap.infoArray      = g_ti_images;
	g_ti_snap.infoArrayCount = vis_n;

	// Filter UUID array — must match visible images only
	if (g_real_aii && g_real_aii->version >= 8 &&
	    g_real_aii->uuidArray && g_real_aii->uuidArrayCount > 0) {
		uint32_t src_n = (uint32_t)g_real_aii->uuidArrayCount;
		if (src_n > g_ti_uuid_cap) {
			g_ti_uuids = realloc(g_ti_uuids, src_n * sizeof(struct dyld_uuid_info));
			g_ti_uuid_cap = src_n;
		}
		uint32_t vis_uuid_n = 0;
		for (uint32_t i = 0; i < src_n; i++) {
			if (header_is_visible(g_real_aii->uuidArray[i].imageLoadAddress))
				g_ti_uuids[vis_uuid_n++] = g_real_aii->uuidArray[i];
		}
		g_ti_snap.uuidArray      = vis_uuid_n ? g_ti_uuids : NULL;
		g_ti_snap.uuidArrayCount = vis_uuid_n;
	} else if (g_ti_snap.version >= 8) {
		g_ti_snap.uuidArray      = NULL;
		g_ti_snap.uuidArrayCount = 0;
	}
	if (g_ti_snap.version >= 9) {
		g_ti_snap.dyldAllImageInfosAddress = &g_ti_snap;
	}
}

__attribute__((noinline))
static kern_return_t h_task_info(task_name_t target, task_flavor_t flavor,
                                 task_info_t info_out, mach_msg_type_number_t *cnt) {
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

	struct task_dyld_info *tdi = (struct task_dyld_info *)info_out;

	// Cache the real dyld_all_image_infos pointer on first encounter
	if (!g_real_aii && tdi->all_image_info_addr)
		g_real_aii = (struct dyld_all_image_infos *)(uintptr_t)tdi->all_image_info_addr;

	os_unfair_lock_lock(&g_lock);
	build_task_snapshot();
	os_unfair_lock_unlock(&g_lock);

	tdi->all_image_info_addr = (mach_vm_address_t)(uintptr_t)&g_ti_snap;
	tdi->all_image_info_size = sizeof(g_ti_snap);

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
		{ (const void *)h_image_count,                   (void *const *)&orig_dyld_image_count },
		{ (const void *)h_get_image_name,                (void *const *)&orig_dyld_get_image_name },
		{ (const void *)h_get_image_header,              (void *const *)&orig_dyld_get_image_header },
		{ (const void *)h_get_image_vmaddr_slide,        (void *const *)&orig_dyld_get_image_vmaddr_slide },
		{ (const void *)h_register_func_for_add_image,   (void *const *)&orig_dyld_register_func_for_add_image },
		{ (const void *)h_register_func_for_remove_image,(void *const *)&orig_dyld_register_func_for_remove_image },
		{ (const void *)h_task_info,                     (void *const *)&orig_task_info },
		{ (const void *)h_class_getImageName,            (void *const *)&orig_class_getImageName },
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
	};
	for (unsigned i = 0; i < sizeof(map) / sizeof(*map); i++) {
		if (addr == map[i].hook)
			return *map[i].orig;
	}
	return addr;
}

//------------------------------------------------------------------------------
#pragma mark - dladdr hook

__attribute__((noinline))
static int h_dladdr(const void *addr, Dl_info *info) {
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
	if (info && info->dli_fname && image_path_should_hide(info->dli_fname)) {
		// Rewrite the owning image to match the app executable. Preserve the
		// symbol name so callers that stringify dli_sname don't crash on NULL.
		// dli_saddr stays cleared because it would otherwise still point into the
		// hidden image even after we swap dli_fbase to the app binary.
		info->dli_fname = g_executable_path;
		info->dli_fbase = (void *)orig_dyld_get_image_header(0);
		info->dli_saddr = NULL;
		return 1;
	}

	return result;
}

//------------------------------------------------------------------------------
#pragma mark - dlsym hook

void *hidden_dylib_hider_dlsym_remap(const char *name);  // forward decl

__attribute__((noinline))
static void *h_dlsym(void *handle, const char *symbol) {
	void *result = orig_dlsym(handle, symbol);

	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra))
		return result;  // tweak caller → full access

	// App caller: remap our GOT-hooked functions so dlsym returns
	// our hook pointer, not the raw DSC address (which would bypass
	// our GOT hooks if the app caches the pointer).
	if (symbol) {
		void *remapped = hidden_dylib_hider_dlsym_remap(symbol);
		if (remapped) return remapped;

		// Filtered wrapper for ObjC image-load callbacks. Returning NULL here is
		// risky for Swift callers because objc_addLoadImageFunc is a real API.
		if (strcmp(symbol, "objc_addLoadImageFunc") == 0)
			return (void *)h_objc_addLoadImageFunc;
	}

	// App caller: if the resolved address lives in a hidden image,
	// return NULL.  This catches MSHookFunction, ellekit symbols, etc.
	// without needing a symbol-name blocklist.
	if (result) {
		const char *path = dyld_image_path_containing_address(result);
		if (path && image_path_should_hide(path))
			return NULL;
	}

	return result;
}

//------------------------------------------------------------------------------
#pragma mark - ObjC runtime hooks

__attribute__((noinline))
static const char *h_class_getImageName(Class cls) {
	const char *result = orig_class_getImageName(cls);

	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra))
		return result;

	// App caller: if class lives in a hidden image, return the app executable path
	if (result && image_path_should_hide(result))
		return g_executable_path;

	return result;
}

__attribute__((noinline))
static const char * _Nonnull *h_objc_copyImageNames(unsigned int *outCount) {
	const char * _Nonnull *result = orig_objc_copyImageNames(outCount);

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
	if (!func) return;

	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	bool hidden = caller_is_hidden(ra);

	os_unfair_lock_lock(&g_lock);

	if (g_objc_addload_cb_n >= g_objc_addload_cb_cap) {
		g_objc_addload_cb_cap = g_objc_addload_cb_cap ? g_objc_addload_cb_cap * 2 : 8;
		g_objc_addload_cbs = realloc(g_objc_addload_cbs, g_objc_addload_cb_cap * sizeof(objc_load_cb_entry_t));
	}
	g_objc_addload_cbs[g_objc_addload_cb_n++] = (objc_load_cb_entry_t){ .func = func, .from_hidden = hidden };

	const image_array_t *a = hidden ? &g_all : &g_visible;
	uint32_t n = a->count;
	const struct mach_header **hdrs = NULL;
	if (n) {
		hdrs = malloc(n * sizeof(void *));
		for (uint32_t i = 0; i < n; i++) {
			hdrs[i] = a->items[i].header;
		}
	}

	os_unfair_lock_unlock(&g_lock);

	for (uint32_t i = 0; i < n; i++)
		func(hdrs[i]);
	free(hdrs);
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
	// JB safe-mode / injection markers
	if (strcmp(name, "_MSSafeMode") == 0) return true;
	if (strcmp(name, "_SafeMode") == 0) return true;
	if (strcmp(name, "_SubstituteSafeMode") == 0) return true;
	return false;
}

__attribute__((noinline))
static char *h_getenv(const char *name) {
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
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra)) {
		return orig_opendir(path);
	}

	DIR *dirp = orig_opendir(path);
	register_dir_filter(dirp, dir_filter_kind_for_path(path));
	return dirp;
}

__attribute__((noinline))
static struct dirent *h_readdir(DIR *dirp) {
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra)) {
		return orig_readdir(dirp);
	}

	dir_filter_kind_t kind = lookup_dir_filter(dirp);
	if (kind == DIR_FILTER_NONE) {
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
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra)) {
		return orig_closedir(dirp);
	}

	unregister_dir_filter(dirp);
	return orig_closedir(dirp);
}

//------------------------------------------------------------------------------
#pragma mark - sysctlbyname hook
//
// SF uses sysctlbyname for device/kernel info queries.
// We filter results that might leak jailbreak state.

__attribute__((noinline))
static int h_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                          void *newp, size_t newlen) {
	const void *ra = __builtin_extract_return_addr(__builtin_return_address(0));
	if (caller_is_hidden(ra))
		return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);

	int result = orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
	if (result != 0 || !oldp || !oldlenp || !name)
		return result;

	// kern.bootargs can leak jailbreak boot arguments
	if (strcmp(name, "kern.bootargs") == 0 && oldp && oldlenp && *oldlenp > 0) {
		((char *)oldp)[0] = '\0';
		*oldlenp = 1;
	}

	return result;
}

//------------------------------------------------------------------------------
#pragma mark - Public Init

extern void rhi_diag_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

// Called from main.c when gHiddenInjection is true, after env vars are
// consumed and before roothide_init_with_executable / TweakLoader.
void hidden_dylib_hider_init(void)
{
	if (g_inited) return;
	g_inited = true;

	rhi_diag_log("HIDER init start, _dyld_image_count=%u", _dyld_image_count());

	// 1. Register callbacks with the REAL dyld functions (before hooking).
	//    dyld will immediately replay all currently-loaded images to our
	//    callback, populating g_all and g_visible.
	_dyld_register_func_for_add_image(on_image_added);
	_dyld_register_func_for_remove_image(on_image_removed);

	rhi_diag_log("HIDER after register callbacks, g_all=%u g_visible=%u", g_all.count, g_visible.count);

	// 2. Cache dyld_all_image_infos for task_info filtering.
	{
		task_dyld_info_data_t tdi;
		mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
		if (task_info(mach_task_self_, TASK_DYLD_INFO, (task_info_t)&tdi, &cnt) == KERN_SUCCESS) {
			g_real_aii = (struct dyld_all_image_infos *)(uintptr_t)tdi.all_image_info_addr;
		}
	}

	rhi_diag_log("HIDER g_real_aii=%p", (void *)g_real_aii);

	// 3. Save original function pointers BEFORE rebinding.
	//    These point directly into the DSC code which remains intact.
	orig_dladdr = dladdr;
	orig_dlsym = dlsym;
	orig_dyld_image_count = _dyld_image_count;
	orig_dyld_get_image_name = _dyld_get_image_name;
	orig_dyld_get_image_header = _dyld_get_image_header;
	orig_dyld_get_image_vmaddr_slide = _dyld_get_image_vmaddr_slide;
	orig_dyld_register_func_for_add_image = _dyld_register_func_for_add_image;
	orig_dyld_register_func_for_remove_image = _dyld_register_func_for_remove_image;
	orig_task_info = task_info;
	orig_class_getImageName = class_getImageName;
	orig_objc_copyImageNames = objc_copyImageNames;
	orig_objc_copyClassNamesForImage = objc_copyClassNamesForImage;
	orig_objc_addLoadImageFunc = objc_addLoadImageFunc;
	orig_dlopen = dlopen;
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

	// Cache executable path for class_getImageName / dladdr substitution
	g_executable_path = _dyld_get_image_name(0);

	// 4. GOT rebinding for all hooks.
	//    Uses GOT rebinding (not in-place DSC patching) so the DSC functions
	//    remain intact — MSHookFunction/ellekit can still create trampolines.

	// dyld image enumeration — filtered view for app callers
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, _dyld_image_count, h_image_count, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)_dyld_get_image_name, h_get_image_name, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, _dyld_get_image_header, h_get_image_header, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, _dyld_get_image_vmaddr_slide, h_get_image_vmaddr_slide, NULL);

	// dyld callback registration — filter hidden images from app callbacks
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, _dyld_register_func_for_add_image, h_register_func_for_add_image, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, _dyld_register_func_for_remove_image, h_register_func_for_remove_image, NULL);

	// dlopen / dlsym / dladdr — block probing, remap hooked symbols, rewrite hidden paths
	// NOTE: dlopen hook commented out — conflicts with init_dyldhooks iOS 15 GOT fallback.
	// The dlopen GOT rebind here replaces the replacee that init_dyldhooks needs to find,
	// preventing its trust/filter hook from ever being installed on iOS 15.
	// litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, dlopen, h_dlopen, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, dlsym, h_dlsym, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, dladdr, h_dladdr, NULL);

	// task_info(TASK_DYLD_INFO) — present filtered dyld_all_image_infos
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, task_info, h_task_info, NULL);

	// Early strict-app probes that matter during startup and are safe enough
	// to bring up before the hidden loader chain. Keep the more invasive ObjC,
	// environment, and filesystem hooks for the later strict phase.
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, fork, h_fork, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, sysctl, h_sysctl, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, getfsstat, h_getfsstat, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, statfs, h_statfs, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, statvfs, h_statvfs, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, sysctlbyname, h_sysctlbyname, NULL);

	rhi_diag_log("HIDER init complete — core hooks enabled");
}

void hidden_dylib_hider_enable_strict_hooks(void)
{
	if (!g_inited || g_strict_hooks_enabled) {
		return;
	}

	g_strict_hooks_enabled = true;

	// ObjC runtime — hide injected images from class/image enumeration
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, class_getImageName, h_class_getImageName, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, objc_copyImageNames, h_objc_copyImageNames, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, objc_copyClassNamesForImage, h_objc_copyClassNamesForImage, NULL);

	// Environment — hide DYLD_INSERT_LIBRARIES and JB markers
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, getenv, h_getenv, NULL);

	// Filesystem probes — hide jailbreak artifacts from stat/access/fopen and
	// filter preboot descendant enumeration without lying about the preboot root.
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, access, h_access, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, stat, h_stat, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, lstat, h_lstat, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, fopen, h_fopen, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, opendir, h_opendir, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, readdir, h_readdir, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, closedir, h_closedir, NULL);

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
	if (!g_inited || !name)
		return NULL;

	// Only remap dlopen when the actual GOT-level fallback hook was installed.
	// dyld_patch_fallback_enabled is broader than that: it only means we need
	// the fallback-capable dyld patch path, not that dlopen itself was rebound.
	if (!strcmp(name, "dlopen") && dlopen_fallback_hook_installed)
		return (void *)dlopen_fallback_hook;

	// Table of symbol names → our hooked function pointers.
	// Only advertise symbols that are actually live in the current phase.
	static const struct {
		const char *sym;
		void *func;
		bool requiresStrictHooks;
	} remap[] = {
		{ "_dyld_image_count",                    (void *)h_image_count },
		{ "_dyld_get_image_name",                  (void *)h_get_image_name,               false },
		{ "_dyld_get_image_header",                (void *)h_get_image_header,             false },
		{ "_dyld_get_image_vmaddr_slide",          (void *)h_get_image_vmaddr_slide,       false },
		{ "_dyld_register_func_for_add_image",     (void *)h_register_func_for_add_image,  false },
		{ "_dyld_register_func_for_remove_image",  (void *)h_register_func_for_remove_image,false },
		{ "task_info",                             (void *)h_task_info,                    false },
		{ "dladdr",                                (void *)h_dladdr,                       false },
		{ "dlsym",                                 (void *)h_dlsym,                        false },
		{ "class_getImageName",                    (void *)h_class_getImageName,           true  },
		{ "objc_copyImageNames",                   (void *)h_objc_copyImageNames,          true  },
		{ "objc_copyClassNamesForImage",           (void *)h_objc_copyClassNamesForImage,  true  },
		{ "objc_addLoadImageFunc",                 (void *)h_objc_addLoadImageFunc,        false },
		// NOTE: keep dlopen off the remap table. The dlopen hook path remains
		// disabled due to the iOS 15 init_dyldhooks fallback conflict.
		// { "dlopen",                               (void *)h_dlopen,                       false },
		{ "fork",                                  (void *)h_fork,                         false },
		{ "getfsstat",                             (void *)h_getfsstat,                    false },
		{ "statfs",                                (void *)h_statfs,                       false },
		{ "statvfs",                               (void *)h_statvfs,                      false },
		{ "sysctl",                                (void *)h_sysctl,                       false },
		{ "getenv",                                (void *)h_getenv,                       true  },
		{ "access",                                (void *)h_access,                       true  },
		{ "stat",                                  (void *)h_stat,                         true  },
		{ "lstat",                                 (void *)h_lstat,                        true  },
		{ "fopen",                                 (void *)h_fopen,                        true  },
		{ "sysctlbyname",                          (void *)h_sysctlbyname,                 false },
	};

	for (unsigned i = 0; i < sizeof(remap) / sizeof(*remap); i++) {
		if (strcmp(name, remap[i].sym) == 0) {
			if (remap[i].requiresStrictHooks && !g_strict_hooks_enabled)
				return NULL;
			return remap[i].func;
		}
	}

	return NULL;
}
