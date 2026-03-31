#include "common.h"
#include "roothider.h"
#include <xpc/xpc.h>
#include "launchd.h"
#include <mach-o/dyld.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sandbox.h>
#include <paths.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <math.h>
#include <fcntl.h>
#include <dlfcn.h>
#include "envbuf.h"
#include "private.h"
#include <libjailbreak/jbclient_xpc.h>
#include <libjailbreak/jbserver_domains.h>
#include <libjailbreak/jbroot.h>

typedef enum
{
	kRootHideInjectionModeStock = 0,
	kRootHideInjectionModeBlacklist,
	kRootHideInjectionModeWhitelist,
} RootHideInjectionMode;

#define ROOT_HIDE_MODE_PLIST_RELATIVE "/var/mobile/Library/RootHide/cn.zqbb.inject.mode.plist"
#define ROOT_HIDE_MODE_PLIST_LEGACY "/var/mobile/Library/RootHide/cn.zqbb.inject.mode.plist"
#define ROOT_HIDE_INJECT_PLIST_RELATIVE "/var/mobile/Library/RootHide/cn.zqbb.inject.plist"
#define ROOT_HIDE_INJECT_PLIST_LEGACY "/var/mobile/Library/RootHide/cn.zqbb.inject.plist"
#define ROOT_HIDE_INJECT_SYSTEM_PLIST_RELATIVE "/var/mobile/Library/RootHide/cn.zqbb.inject.system.plist"
#define ROOT_HIDE_INJECT_SYSTEM_PLIST_LEGACY "/var/mobile/Library/RootHide/cn.zqbb.inject.system.plist"
#define ROOT_HIDE_JETSAM_ADDEND_PLIST_RELATIVE "/var/mobile/Library/RootHide/cn.zqbb.jetsam.addend.plist"
#define ROOT_HIDE_JETSAM_ADDEND_PLIST_LEGACY "/var/mobile/Library/RootHide/cn.zqbb.jetsam.addend.plist"
#define ROOT_HIDE_UNINJECT_PLIST_RELATIVE "/var/mobile/Library/RootHide/cn.zqbb.uninject.plist"
#define ROOT_HIDE_UNINJECT_PLIST_LEGACY "/var/mobile/Library/RootHide/cn.zqbb.uninject.plist"
#define ROOT_HIDE_UNINJECT_PLIST_LEGACY_OLD "/var/mobile/zp.unject.plist"

bool string_has_prefix(const char *str, const char* prefix)
{
	if (!str || !prefix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t prefix_len = strlen(prefix);

	if (str_len < prefix_len) {
		return false;
	}

	return !strncmp(str, prefix, prefix_len);
}

bool string_has_suffix(const char* str, const char* suffix)
{
	if (!str || !suffix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t suffix_len = strlen(suffix);

	if (str_len < suffix_len) {
		return false;
	}

	return !strcmp(str + str_len - suffix_len, suffix);
}

void string_enumerate_components(const char *string, const char *separator, void (^enumBlock)(const char *pathString, bool *stop))
{
	char *stringCopy = strdup(string);
	char *curString = strtok(stringCopy, separator);
	while (curString != NULL) {
		bool stop = false;
		enumBlock(curString, &stop);
		if (stop) break;
		curString = strtok(NULL, separator);
	}
	free(stringCopy);
}

extern xpc_object_t xpc_create_from_plist(const void* buf, size_t len);

static xpc_object_t root_hide_copy_plist(const char *path)
{
	if (!path || access(path, F_OK) != 0) {
		return NULL;
	}

	struct stat s = {};
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		return NULL;
	}

	if (fstat(fd, &s) != 0) {
		close(fd);
		return NULL;
	}

	void *addr = mmap(NULL, s.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
	close(fd);
	if (addr == MAP_FAILED) {
		return NULL;
	}

	xpc_object_t xplist = xpc_create_from_plist(addr, s.st_size);
	munmap(addr, s.st_size);
	return xplist;
}

static xpc_object_t root_hide_copy_plist_for_relative_path(const char *relativePath, const char *legacyPath)
{
	const char *jbrootPath = JBROOT_PATH(relativePath);
	xpc_object_t xplist = root_hide_copy_plist(jbrootPath);
	if (xplist) {
		return xplist;
	}
	if (legacyPath && (!jbrootPath || strcmp(jbrootPath, legacyPath) != 0)) {
		return root_hide_copy_plist(legacyPath);
	}
	return NULL;
}

static bool root_hide_plist_exists(const char *relativePath, const char *legacyPath)
{
	const char *jbrootPath = JBROOT_PATH(relativePath);
	if (jbrootPath && access(jbrootPath, F_OK) == 0) {
		return true;
	}
	if (legacyPath && (!jbrootPath || strcmp(jbrootPath, legacyPath) != 0) && access(legacyPath, F_OK) == 0) {
		return true;
	}
	return false;
}

static bool root_hide_dictionary_get_bool(const char *relativePath, const char *legacyPath, const char *key)
{
	if (!key) {
		return false;
	}

	xpc_object_t xplist = root_hide_copy_plist_for_relative_path(relativePath, legacyPath);
	if (!xplist || xpc_get_type(xplist) != XPC_TYPE_DICTIONARY) {
		if (xplist) xpc_release(xplist);
		return false;
	}

	bool result = xpc_dictionary_get_bool(xplist, key);
	xpc_release(xplist);
	return result;
}

static bool root_hide_dictionary_contains_enabled_path(const char *relativePath, const char *legacyPath, const char *path)
{
	if (!path) {
		return false;
	}

	xpc_object_t xplist = root_hide_copy_plist_for_relative_path(relativePath, legacyPath);
	if (!xplist || xpc_get_type(xplist) != XPC_TYPE_DICTIONARY) {
		if (xplist) xpc_release(xplist);
		return false;
	}

	__block bool found = false;
	xpc_dictionary_apply(xplist, ^bool(const char *key, xpc_object_t value) {
		if (xpc_get_type(value) == XPC_TYPE_BOOL && xpc_bool_get_value(value) && strstr(path, key)) {
			found = true;
			return false;
		}
		return true;
	});

	xpc_release(xplist);
	return found;
}

static RootHideInjectionMode root_hide_injection_mode(void)
{
	xpc_object_t modePlist = root_hide_copy_plist_for_relative_path(ROOT_HIDE_MODE_PLIST_RELATIVE, ROOT_HIDE_MODE_PLIST_LEGACY);
	if (modePlist && xpc_get_type(modePlist) == XPC_TYPE_DICTIONARY) {
		const char *mode = xpc_dictionary_get_string(modePlist, "mode");
		if (mode) {
			if (!strcmp(mode, "blacklist")) {
				xpc_release(modePlist);
				return kRootHideInjectionModeBlacklist;
			}
			if (!strcmp(mode, "whitelist")) {
				xpc_release(modePlist);
				return kRootHideInjectionModeWhitelist;
			}
			if (!strcmp(mode, "stock")) {
				xpc_release(modePlist);
				return kRootHideInjectionModeStock;
			}
		}
	}
	if (modePlist) {
		xpc_release(modePlist);
	}

	if (root_hide_plist_exists(ROOT_HIDE_INJECT_PLIST_RELATIVE, ROOT_HIDE_INJECT_PLIST_LEGACY)) {
		return kRootHideInjectionModeWhitelist;
	}
	if (root_hide_plist_exists(ROOT_HIDE_UNINJECT_PLIST_RELATIVE, ROOT_HIDE_UNINJECT_PLIST_LEGACY) || access(ROOT_HIDE_UNINJECT_PLIST_LEGACY_OLD, F_OK) == 0) {
		return kRootHideInjectionModeBlacklist;
	}
	return kRootHideInjectionModeStock;
}

static bool root_hide_allowlisted_executable(const char *execName)
{
	return root_hide_dictionary_get_bool(ROOT_HIDE_INJECT_PLIST_RELATIVE, ROOT_HIDE_INJECT_PLIST_LEGACY, execName);
}

static bool root_hide_system_allowlisted_path(const char *path)
{
	return root_hide_dictionary_contains_enabled_path(ROOT_HIDE_INJECT_SYSTEM_PLIST_RELATIVE, ROOT_HIDE_INJECT_SYSTEM_PLIST_LEGACY, path);
}

static int root_hide_jetsam_addend_for_path(const char *path)
{
	if (!path) {
		return 10;
	}

	xpc_object_t xplist = root_hide_copy_plist_for_relative_path(ROOT_HIDE_JETSAM_ADDEND_PLIST_RELATIVE, ROOT_HIDE_JETSAM_ADDEND_PLIST_LEGACY);
	if (!xplist || xpc_get_type(xplist) != XPC_TYPE_DICTIONARY) {
		if (xplist) xpc_release(xplist);
		return 10;
	}

	__block int result = 10;
	xpc_dictionary_apply(xplist, ^bool(const char *key, xpc_object_t value) {
		if (xpc_get_type(value) == XPC_TYPE_INT64) {
			int64_t addend = xpc_int64_get_value(value);
			if (addend > 0 && strstr(path, key) != NULL) {
				result = (int)addend;
				return false;
			}
		}
		return true;
	});

	xpc_release(xplist);
	return result;
}

static bool root_hide_uninject_executable(const char *execName)
{
	if (root_hide_dictionary_get_bool(ROOT_HIDE_UNINJECT_PLIST_RELATIVE, ROOT_HIDE_UNINJECT_PLIST_LEGACY, execName)) {
		return true;
	}
	return root_hide_dictionary_get_bool(ROOT_HIDE_UNINJECT_PLIST_LEGACY_OLD, ROOT_HIDE_UNINJECT_PLIST_LEGACY_OLD, execName);
}

kSpawnConfig spawn_config_for_executable(const char* path, char *const argv[restrict])
{
	// Blacklist to ensure general system stability
	// I don't like this but for some processes it seems neccessary
	const char *processBlacklist[] = {
		"/System/Library/Frameworks/GSS.framework/Helpers/GSSCred",
		"/System/Library/PrivateFrameworks/DataAccess.framework/Support/dataaccessd",
		"/System/Library/PrivateFrameworks/IDSBlastDoorSupport.framework/XPCServices/IDSBlastDoorService.xpc/IDSBlastDoorService",
		"/System/Library/PrivateFrameworks/MessagesBlastDoorSupport.framework/XPCServices/MessagesBlastDoorService.xpc/MessagesBlastDoorService",
	};
	size_t blacklistCount = sizeof(processBlacklist) / sizeof(processBlacklist[0]);
	for (size_t i = 0; i < blacklistCount; i++)
	{
		if (!strcmp(processBlacklist[i], path)) return 0;
	}

	RootHideInjectionMode injectionMode = root_hide_injection_mode();
	if (injectionMode == kRootHideInjectionModeWhitelist) {
		const char *exec = strrchr(path, '/');
		if (exec && root_hide_allowlisted_executable(exec + 1)) {
			return (kSpawnConfigInject | kSpawnConfigTrust);
		}
		if (root_hide_system_allowlisted_path(path)) {
			return (kSpawnConfigInject | kSpawnConfigTrust);
		}
		return 0;
	}

	if (injectionMode == kRootHideInjectionModeBlacklist) {
		if (strstr(path, "/.jbroot-")) {
			return (kSpawnConfigInject | kSpawnConfigTrust);
		}

		if (access("/var/mobile/.appex", F_OK) < 0) {
			const char *patterns[] = {
				"wxkb_plugin",
				"BaiduInputMethod",
				"com.sogou.sogouinput.BaseKeyboard",
				".appex/"
			};
			size_t patternsCount = sizeof(patterns) / sizeof(patterns[0]);
			for (size_t i = 0; i < patternsCount; ++i) {
				if (strstr(path, patterns[i]) != NULL) {
					return (i == patternsCount - 1) ? 0 : (kSpawnConfigInject | kSpawnConfigTrust);
				}
			}
		}

		const char *exec = strrchr(path, '/');
		if (exec && root_hide_uninject_executable(exec + 1)) {
			return 0;
		}
	}

	return (kSpawnConfigInject | kSpawnConfigTrust);
}

int __posix_spawn_orig(pid_t *restrict pid, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char * const envp[restrict])
{
	return syscall(SYS_posix_spawn, pid, path, desc, argv, envp);
}

int __execve_orig(const char *path, char *const argv[], char *const envp[])
{
	return syscall(SYS_execve, path, argv, envp);
}

// 1. Ensure the binary about to be spawned and all of it's dependencies are trust cached
// 2. Insert "DYLD_INSERT_LIBRARIES=/usr/lib/systemhook.dylib" into all binaries spawned
// 3. Increase Jetsam limit to more sane value (Multipler defined as JETSAM_MULTIPLIER)

static int spawn_exec_hook_common(const char *path,
								  char *const argv[restrict],
								  char *const envp[restrict],
			   struct _posix_spawn_args_desc *desc,
										int (*trust_binary)(const char *path),
									   double jetsamMultiplier,
									    int (^orig)(char *const envp[restrict]))
{
	if (!path) {
		return orig(envp);
	}

	posix_spawnattr_t attr = NULL;
	if (desc) attr = desc->attrp;

	kSpawnConfig spawnConfig = spawn_config_for_executable(path, argv);

	if (spawnConfig & kSpawnConfigTrust) {
		// Upload binary to trustcache if needed
		trust_binary(path);
	}

	const char *existingLibraryInserts = envbuf_getenv((const char **)envp, "DYLD_INSERT_LIBRARIES");
	__block bool systemHookAlreadyInserted = false;
	if (existingLibraryInserts) {
		string_enumerate_components(existingLibraryInserts, ":", ^(const char *existingLibraryInsert, bool *stop) {
			if (!strcmp(existingLibraryInsert, HOOK_DYLIB_PATH)) {
				systemHookAlreadyInserted = true;
			}
		});
	}

	int JBEnvAlreadyInsertedCount = (int)systemHookAlreadyInserted;

	// Check if we can find at least one reason to not insert jailbreak related environment variables
	// In this case we also need to remove pre existing environment variables if they are already set
	bool shouldInsertJBEnv = true;
	bool hasSafeModeVariable = false;
	do {
		if (!(spawnConfig & kSpawnConfigInject)) {
			shouldInsertJBEnv = false;
			break;
		}

		// Check if we can find a _SafeMode or _MSSafeMode variable
		// In this case we do not want to inject anything
		const char *safeModeValue = envbuf_getenv((const char **)envp, "_SafeMode");
		const char *msSafeModeValue = envbuf_getenv((const char **)envp, "_MSSafeMode");
		if (safeModeValue) {
			if (!strcmp(safeModeValue, "1")) {
				if(!allowInjectWithSafeMode(path)) shouldInsertJBEnv = false;
				hasSafeModeVariable = true;
				break;
			}
		}
		if (msSafeModeValue) {
			if (!strcmp(msSafeModeValue, "1")) {
				if(!allowInjectWithSafeMode(path)) shouldInsertJBEnv = false;
				hasSafeModeVariable = true;
				break;
			}
		}

		int proctype = 0;
		if (posix_spawnattr_getprocesstype_np(&attr, &proctype) == 0) {
			if (proctype == POSIX_SPAWN_PROC_TYPE_DRIVER) {
				// Do not inject hook into DriverKit drivers
				shouldInsertJBEnv = false;
				break;
			}
		}

		if (access(HOOK_DYLIB_PATH, F_OK) != 0) {
			// If the hook dylib doesn't exist, don't try to inject it (would crash the process)
			shouldInsertJBEnv = false;
			break;
		}
	} while (0);

	// If systemhook is being injected and jetsam limits are set, add the per-executable RootHide jetsam addend.
	if (shouldInsertJBEnv) {
		uint8_t *attrStruct = (uint8_t *)attr;
		if (attrStruct) {
			if (jetsamMultiplier == 0 || isnan(jetsamMultiplier)) jetsamMultiplier = 3; // default value (3x)
			int jetsamAddend = root_hide_jetsam_addend_for_path(path) + (int)round(jetsamMultiplier * 5);
			if (jetsamAddend > 0) {
				int memlimit_active = *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE);
				if (memlimit_active != -1) {
					*(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE) = memlimit_active + jetsamAddend;
				}
				int memlimit_inactive = *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE);
				if (memlimit_inactive != -1) {
					*(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE) = memlimit_inactive + jetsamAddend;
				}
			}
		}
	}

	int r = -1;

	if ((shouldInsertJBEnv && JBEnvAlreadyInsertedCount == 1) || (!shouldInsertJBEnv && JBEnvAlreadyInsertedCount == 0 && !hasSafeModeVariable)) {
		// we're already good, just call orig
		r = orig(envp);
	}
	else {
		// the state we want to be in is not the state we are in right now

		char **envc = envbuf_mutcopy((const char **)envp);

		if (shouldInsertJBEnv) {
			if (!systemHookAlreadyInserted) {
				char newLibraryInsert[strlen(HOOK_DYLIB_PATH) + (existingLibraryInserts ? (strlen(existingLibraryInserts) + 1) : 0) + 1];
				strcpy(newLibraryInsert, HOOK_DYLIB_PATH);
				if (existingLibraryInserts) {
					strcat(newLibraryInsert, ":");
					strcat(newLibraryInsert, existingLibraryInserts);
				}
				envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", newLibraryInsert);
			}
		}
		else {
			if (systemHookAlreadyInserted && existingLibraryInserts) {
				if (!strcmp(existingLibraryInserts, HOOK_DYLIB_PATH)) {
					envbuf_unsetenv(&envc, "DYLD_INSERT_LIBRARIES");
				}
				else {
					char *newLibraryInsert = malloc(strlen(existingLibraryInserts)+1);
					newLibraryInsert[0] = '\0';

					__block bool first = true;
					string_enumerate_components(existingLibraryInserts, ":", ^(const char *existingLibraryInsert, bool *stop) {
						if (strcmp(existingLibraryInsert, HOOK_DYLIB_PATH) != 0) {
							if (first) {
								strcpy(newLibraryInsert, existingLibraryInsert);
								first = false;
							}
							else {
								strcat(newLibraryInsert, ":");
								strcat(newLibraryInsert, existingLibraryInsert);
							}
						}
					});
					envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", newLibraryInsert);

					free(newLibraryInsert);
				}
			}
			envbuf_unsetenv(&envc, "_SafeMode");
			envbuf_unsetenv(&envc, "_MSSafeMode");
		}

		r = orig(envc);

		envbuf_free(envc);
	}

	return r;
}

int posix_spawn_hook_shared(pid_t *restrict pid, 
					   const char *restrict path,
			 struct _posix_spawn_args_desc *desc,
						  	    char *const argv[restrict],
					   			char *const envp[restrict],
					   				  void *orig,
					   				  int (*trust_binary)(const char *path),
					   				  int (*set_process_debugged)(uint64_t pid, bool fullyDebugged),
					   				 double jetsamMultiplier)
{
	int (*posix_spawn_orig)(pid_t *restrict, const char *restrict, struct _posix_spawn_args_desc *, char *const[restrict], char *const[restrict]) = orig;

	int r = spawn_exec_hook_common(path, argv, envp, desc, trust_binary, jetsamMultiplier, ^int(char *const envp_patched[restrict]) {
		return posix_spawn_orig(pid, path, desc, argv, envp_patched);
	});

	if (r == 0 && pid && desc) {
		posix_spawnattr_t attr = desc->attrp;
		short flags = 0;
		if (posix_spawnattr_getflags(&attr, &flags) == 0) {
			if (flags & POSIX_SPAWN_START_SUSPENDED) {
				// If something spawns a process as suspended, ensure mapping invalid pages in it is possible
				// Normally it would only be possible after systemhook.dylib enables it
				// Fixes Frida issues
				int r = set_process_debugged(*pid, false);
			}
		}
	}

	return r;
}

int execve_hook_shared(const char *path,
					   char *const argv[],
					   char *const envp[],
			 				 void *orig,
			 				 int (*trust_binary)(const char *path))
{
	int (*execve_orig)(const char *, char *const[], char *const[]) = orig;

	int r = spawn_exec_hook_common(path, argv, envp, NULL, trust_binary, 0, ^int(char *const envp_patched[restrict]){
		return execve_orig(path, argv, envp_patched);
	});

	return r;
}
