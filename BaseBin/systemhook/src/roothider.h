#include <spawn.h>
#include "private.h"

#include <libjailbreak/jbroot.h>
#include <libjailbreak/jbclient_xpc.h>
#include <libjailbreak/roothider/jailbreakd.h>

#define OS_REASON_DYLD          6
#define DYLD_EXIT_REASON_OTHER  9
void abort_with_reason(uint32_t reason_namespace, uint64_t reason_code, const char *reason_string, uint64_t reason_flags);

#define ABORT(...) do { \
	const char* info = NULL; \
	asprintf(&info, __VA_ARGS__); \
	fprintf(stderr, "%s:%d: abort `%s'\n", __FILE_NAME__, __LINE__, info); \
	abort_with_reason(OS_REASON_DYLD, DYLD_EXIT_REASON_OTHER, info, 0); \
} while(0)

#define	ASSERT(e)	(__builtin_expect(!(e), 0) ?\
 ((void)fprintf(stderr, "%s:%d: failed ASSERTion `%s'\n", __FILE_NAME__, __LINE__, #e),\
 abort_with_reason(OS_REASON_DYLD,DYLD_EXIT_REASON_OTHER, #e, 0)), abort() : (void)0)

#include <stdlib.h>
#include <os/log.h>
#include <sys/syslog.h>
#define SYSLOG(...) do {openlog("systemhook",LOG_PID,LOG_AUTH);syslog(LOG_DEBUG, __VA_ARGS__);closelog();} while(0)
#define PROCLOG(progname, ...) do { const char* name=getprogname(); if(name && strcmp(name, progname)==0) {SYSLOG(__VA_ARGS__);} } while(0)
#define PROCASSERT(progname, e) do { const char* name=getprogname(); if(name && strcmp(name, progname)==0) {ASSERT(e);} } while(0)

pid_t __getppid();

bool hasTrollstoreMarker(const char* path);
bool isRemovableBundlePath(const char* path);
bool allowInjectWithSafeMode(const char* path);

void roothide_init();
void roothide_init_with_checkin(const char* rootdir);
void roothide_init_with_executable(const char* executable);

typedef enum {
	HIDDEN_TWEAK_LOAD_NOT_ATTEMPTED,
	HIDDEN_TWEAK_LOAD_PREPARED,
	HIDDEN_TWEAK_LOAD_ACTIVE,
	HIDDEN_TWEAK_LOAD_FAILED,
	HIDDEN_TWEAK_LOAD_PARTIAL,
	HIDDEN_TWEAK_LOAD_UNKNOWN,
} HiddenTweakLoadState;

/*
 * Hidden-tweak loading is an explicit one-way transaction.  PREPARED has not
 * loaded selected tweak code yet; PARTIAL/UNKNOWN are terminal for the life
 * of this process and callers must not automatically retry them.
 */
bool roothide_hidden_tweak_envbuf_apply(char ***envc);
/* Capture the selected-tweak bridge values before a hidden child scrubs its
 * observable environment.  Repeated calls retain the first canonical view. */
void roothide_hidden_tweak_consume_environment(void);
bool roothide_hidden_tweak_env_is_configured(void);
bool roothide_hidden_tweak_prepare_for_loader(void);
bool roothide_hidden_tweak_prepare_minimal_runtime(void);
bool roothide_hidden_tweak_load_selected(void);
bool roothide_hidden_tweak_hooks_ready(void);
HiddenTweakLoadState roothide_hidden_tweak_load_state(void);
void roothide_hidden_tweak_note_loader_result(bool succeeded);

int __sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen);
int __sysctl_hook(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen);
int __sysctlbyname(const char *name, size_t namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
int __sysctlbyname_hook(const char *name, size_t namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);

int roothide_systemhook___execve_prehook(const char *path, char *const argv[], char *const envp[], void *orig, int (*trust_binary)(const char *path));
int roothide_systemhook___execve_posthook(const char *path, char *const argv[], char *const envp[]);

int roothide_systemhook___posix_spawn_prehook(pid_t *restrict pid, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict], void *orig, int (*trust_binary)(const char *path), int (*set_process_debugged)(uint64_t pid, bool fullyDebugged), double jetsamMultiplier);
int roothide_systemhook___posix_spawn_posthook(pid_t *restrict pidp, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict]);
