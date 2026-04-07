#import <Foundation/Foundation.h>

#include <spawn.h>
#include <substrate.h>
#include <sys/sysctl.h>
#include <fcntl.h>
#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/roothider.h>

#include "../systemhook/src/common.h"
#include "../systemhook/src/envbuf.h"

const char* HOOK_DYLIB_PATH = NULL;
static NSString * const kRootHideHiddenWhitelistTweaksRelativePath = @"/var/mobile/Library/RootHide/pro.m1337.hiddenwhitelist.tweaks.plist";
static NSString * const kRootHideInjectRelativePath = @"/var/mobile/Library/RootHide/pro.m1337.inject.plist";
static NSInteger const kRootHideHiddenTweakAllowMode = 1;
static NSInteger const kRootHideHiddenTweakDenyMode = 2;

extern bool gInEarlyBoot;

static void RootHideInjectionLaunchdLog(NSString *format, ...)
{
    // Only log after jailbreak is fully up (post userspace reboot, jailbreakd running).
    // During firstLoad or earlyBoot, jailbreakd XPC is not available and logging
    // can destabilize the bootstrap sequence.
    if (launchdhookFirstLoad || gInEarlyBoot) {
        return;
    }

    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    jbdSystemwideLog("[RHI-LD] %s", message.UTF8String);
}

static bool RootHideShouldTraceSpawnPath(const char *path)
{
	if (!path) {
		return false;
	}

	return strstr(path, ".app/") != NULL
		|| strstr(path, ".appex/") != NULL
		|| strstr(path, "/PlugIns/") != NULL
		|| strstr(path, "/Extensions/") != NULL
		|| strcmp(path, "/usr/libexec/xpcproxy") == 0;
}

static NSArray<NSString *> *RootHideNormalizedTweakNames(id value)
{
	if (![value isKindOfClass:[NSArray class]]) {
		return @[];
	}

	NSMutableOrderedSet<NSString *> *orderedValues = [NSMutableOrderedSet orderedSet];
	for (id candidate in (NSArray *)value) {
		if (![candidate isKindOfClass:[NSString class]]) {
			continue;
		}

		NSString *trimmedCandidate = [candidate stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
		if (trimmedCandidate.length > 0) {
			[orderedValues addObject:trimmedCandidate];
		}
	}
	return orderedValues.array;
}

static NSString *RootHideBundleIdentifierForExecutablePath(const char *path)
{
	if (!path) {
		return nil;
	}

	NSString *bundlePath = [@(path) stringByDeletingLastPathComponent];
	if (bundlePath.length == 0) {
		return nil;
	}

	NSDictionary *infoDictionary = [NSDictionary dictionaryWithContentsOfFile:[bundlePath stringByAppendingPathComponent:@"Info.plist"]];
	NSString *bundleIdentifier = [infoDictionary[@"CFBundleIdentifier"] isKindOfClass:[NSString class]] ? infoDictionary[@"CFBundleIdentifier"] : nil;
	return bundleIdentifier.length > 0 ? bundleIdentifier : nil;
}

static NSString *RootHideBundleIdentifierFromLaunchName(const char *launchName)
{
	if (!launchName || launchName[0] == '\0') {
		return nil;
	}

	NSString *rawName = @(launchName);
	if ([rawName hasPrefix:@"UIKitApplication:"]) {
		rawName = [rawName substringFromIndex:sizeof("UIKitApplication:") - 1];
		NSRange bracketRange = [rawName rangeOfString:@"["];
		if (bracketRange.location != NSNotFound) {
			rawName = [rawName substringToIndex:bracketRange.location];
		}
	}

	rawName = [rawName stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
	if (rawName.length == 0 || [rawName containsString:@"/"]) {
		return nil;
	}

	return rawName;
}

static void RootHideEnumerateCStringList(char *const values[restrict], void (^block)(NSString *value, bool *stop))
{
	if (!values || !block) {
		return;
	}

	for (NSUInteger index = 0; values[index] != NULL; index++) {
		NSString *value = @(values[index]);
		bool stop = false;
		block(value, &stop);
		if (stop) {
			break;
		}
	}
}

static NSString *RootHideNormalizedBundleIdentifierCandidate(NSString *candidate)
{
	if (![candidate isKindOfClass:[NSString class]]) {
		return nil;
	}

	NSString *trimmedCandidate = [candidate stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
	if (trimmedCandidate.length == 0 || [trimmedCandidate containsString:@"/"]) {
		return nil;
	}

	NSRange bracketRange = [trimmedCandidate rangeOfString:@"["];
	if (bracketRange.location != NSNotFound) {
		trimmedCandidate = [trimmedCandidate substringToIndex:bracketRange.location];
	}

	trimmedCandidate = [trimmedCandidate stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
	if (trimmedCandidate.length == 0 || ![trimmedCandidate containsString:@"."]) {
		return nil;
	}

	return trimmedCandidate;
}

static void RootHideAddBundleIdentifierCandidatesFromValue(NSMutableOrderedSet<NSString *> *bundleIdentifiers, NSString *value)
{
	if (!bundleIdentifiers || ![value isKindOfClass:[NSString class]]) {
		return;
	}

	NSString *directBundleIdentifier = RootHideBundleIdentifierFromLaunchName(value.UTF8String);
	if (directBundleIdentifier.length > 0) {
		[bundleIdentifiers addObject:directBundleIdentifier];
	}

	NSRange equalsRange = [value rangeOfString:@"="];
	if (equalsRange.location != NSNotFound && equalsRange.location + 1 < value.length) {
		NSString *valueAfterEquals = [value substringFromIndex:equalsRange.location + 1];
		NSString *bundleIdentifierAfterEquals = RootHideBundleIdentifierFromLaunchName(valueAfterEquals.UTF8String);
		if (bundleIdentifierAfterEquals.length > 0) {
			[bundleIdentifiers addObject:bundleIdentifierAfterEquals];
		}

		NSString *normalizedAfterEquals = RootHideNormalizedBundleIdentifierCandidate(valueAfterEquals);
		if (normalizedAfterEquals.length > 0) {
			[bundleIdentifiers addObject:normalizedAfterEquals];
		}
	}

	NSString *normalizedCandidate = RootHideNormalizedBundleIdentifierCandidate(value);
	if (normalizedCandidate.length > 0) {
		[bundleIdentifiers addObject:normalizedCandidate];
	}

	NSArray<NSString *> *components = [value componentsSeparatedByCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"=:[]"]];
	for (NSString *component in components) {
		NSString *normalizedComponent = RootHideNormalizedBundleIdentifierCandidate(component);
		if (normalizedComponent.length > 0) {
			[bundleIdentifiers addObject:normalizedComponent];
		}
	}
}

static NSArray<NSString *> *RootHideBundleIdentifiersForSpawn(const char *path, char *const argv[restrict], char *const envp[restrict])
{
	NSMutableOrderedSet<NSString *> *bundleIdentifiers = [NSMutableOrderedSet orderedSet];

	if (path && !strcmp(path, "/usr/libexec/xpcproxy")) {
		// argv[1] is the most reliable source for xpcproxy — it's the service/app
		// label passed by launchd (e.g. "UIKitApplication:com.example.App[0xABC]"
		// or "com.example.service"). Prioritize it by processing it first.
		if (argv && argv[0] && argv[1]) {
			NSString *primaryLabel = @(argv[1]);
			// Direct UIKitApplication: extraction has highest priority
			NSString *directBundleId = RootHideBundleIdentifierFromLaunchName(argv[1]);
			if (directBundleId.length > 0) {
				[bundleIdentifiers addObject:directBundleId];
			}
			RootHideAddBundleIdentifierCandidatesFromValue(bundleIdentifiers, primaryLabel);
		}

		// Then scan remaining argv entries
		RootHideEnumerateCStringList(argv, ^(NSString *value, bool *stop) {
			(void)stop;
			RootHideAddBundleIdentifierCandidatesFromValue(bundleIdentifiers, value);
		});

		// Then scan envp for any additional candidates
		RootHideEnumerateCStringList(envp, ^(NSString *value, bool *stop) {
			(void)stop;
			RootHideAddBundleIdentifierCandidatesFromValue(bundleIdentifiers, value);
		});

		// Log what we found when hidden-whitelist mode is active.
		// The guard in RootHideInjectionLaunchdLog already ensures this only runs
		// after the jailbreak is fully up.
		if (root_hide_injection_mode_is_hidden_whitelist()) {
			NSMutableString *argvDump = [NSMutableString string];
			if (argv) {
				for (int i = 0; argv[i]; i++) {
					if (i > 0) [argvDump appendString:@" "];
					[argvDump appendFormat:@"[%d]=%s", i, argv[i]];
				}
			}
			RootHideInjectionLaunchdLog(@"xpcproxy argv: %@ candidates: %@", argvDump, [bundleIdentifiers.array componentsJoinedByString:@","]);
		}
	}

	NSString *bundleIdentifierForExecutablePath = RootHideBundleIdentifierForExecutablePath(path);
	if (bundleIdentifierForExecutablePath.length > 0) {
		[bundleIdentifiers addObject:bundleIdentifierForExecutablePath];
	}

	return bundleIdentifiers.array;
}

static NSString *RootHideBundleIdentifierForSpawn(const char *path, char *const argv[restrict], char *const envp[restrict])
{
	return RootHideBundleIdentifiersForSpawn(path, argv, envp).firstObject;
}

static NSString *RootHideExecutableNameForPath(const char *path)
{
	if (!path) {
		return nil;
	}

	NSString *executableName = [@(path) lastPathComponent];
	return executableName.length > 0 ? executableName : nil;
}

static NSDictionary *RootHideHiddenWhitelistSettings(void)
{
	NSString *settingsPath = JBROOT_PATH(kRootHideHiddenWhitelistTweaksRelativePath);
	NSDictionary *settings = [NSDictionary dictionaryWithContentsOfFile:settingsPath];
	return [settings isKindOfClass:[NSDictionary class]] ? settings : @{};
}

static NSDictionary *RootHideHiddenWhitelistEntryForSpawn(const char *path, char *const argv[restrict], char *const envp[restrict])
{
	NSDictionary *allSettings = RootHideHiddenWhitelistSettings();

	for (NSString *bundleIdentifier in RootHideBundleIdentifiersForSpawn(path, argv, envp)) {
		NSDictionary *entry = [allSettings[bundleIdentifier] isKindOfClass:[NSDictionary class]] ? allSettings[bundleIdentifier] : nil;
		if (entry) {
			return entry;
		}
	}

	NSString *executableName = RootHideExecutableNameForPath(path);
	if (executableName.length > 0) {
		NSDictionary *entry = [allSettings[executableName] isKindOfClass:[NSDictionary class]] ? allSettings[executableName] : nil;
		if (entry) {
			return entry;
		}
	}

	return nil;
}

static BOOL RootHideHiddenWhitelistEntryHasSelection(NSDictionary *entry)
{
	if (![entry isKindOfClass:[NSDictionary class]]) {
		return NO;
	}

	NSInteger allowDenyMode = [entry[@"allowDenyMode"] respondsToSelector:@selector(integerValue)] ? [entry[@"allowDenyMode"] integerValue] : kRootHideHiddenTweakAllowMode;
	NSArray<NSString *> *selectedTweaks = RootHideNormalizedTweakNames(entry[allowDenyMode == kRootHideHiddenTweakDenyMode ? @"deniedTweaks" : @"allowedTweaks"]);
	return selectedTweaks.count > 0;
}

static BOOL RootHideApplyHiddenWhitelistTweakEnvironment(char ***envc, const char *path, char *const argv[restrict], char *const envp[restrict])
{
	NSDictionary *entry = RootHideHiddenWhitelistEntryForSpawn(path, argv, envp);
	if (!entry) {
		// No per-app tweak config exists.  Fall through to stock blacklist.
		RootHideInjectionLaunchdLog(@"hidden config missing, falling back to blacklist path=%s bundle=%@", path ?: "(null)", RootHideBundleIdentifierForSpawn(path, argv, envp) ?: @"(null)");
		return NO;
	}

	NSInteger allowDenyMode = [entry[@"allowDenyMode"] respondsToSelector:@selector(integerValue)] ? [entry[@"allowDenyMode"] integerValue] : kRootHideHiddenTweakAllowMode;
	NSString *modeString = allowDenyMode == kRootHideHiddenTweakDenyMode ? @"deny" : @"allow";
	NSArray<NSString *> *selectedTweaks = RootHideNormalizedTweakNames(entry[allowDenyMode == kRootHideHiddenTweakDenyMode ? @"deniedTweaks" : @"allowedTweaks"]);
	if (selectedTweaks.count == 0) {
		// Entry exists but no tweaks selected.  Fall through to stock blacklist.
		RootHideInjectionLaunchdLog(@"hidden tweak list empty, falling back to blacklist path=%s bundle=%@ mode=%@", path ?: "(null)", RootHideBundleIdentifierForSpawn(path, argv, envp) ?: @"(null)", modeString);
		return NO;
	}

	envbuf_setenv(envc, "ROOTHIDE_HIDDEN_INJECTION", "1");
	envbuf_setenv(envc, "ROOTHIDE_ENABLE_HIDDEN_TWEAKS", "1");
	envbuf_setenv(envc, "ROOTHIDE_HIDDEN_TWEAK_MODE", modeString.UTF8String);
	envbuf_setenv(envc, "ROOTHIDE_HIDDEN_TWEAK_LIST", [selectedTweaks componentsJoinedByString:@":"].UTF8String);
	envbuf_unsetenv(envc, "DISABLE_TWEAKS");
	envbuf_unsetenv(envc, "CHOICY_SKIP_TWEAKLOADER");
	RootHideInjectionLaunchdLog(@"apply hidden env path=%s bundle=%@ mode=%@ tweaks=%@", path ?: "(null)", RootHideBundleIdentifierForSpawn(path, argv, envp) ?: @"(null)", modeString, [selectedTweaks componentsJoinedByString:@":"]);
	return YES;
}

// Check whether the app is explicitly whitelisted in the inject plist.
// This is the same plist the rhinject UI uses to enable/disable whitelist
// per app.  A stale entry in the tweaks plist should not activate hidden
// injection if the user has disabled the whitelist for that app.
static BOOL RootHideIsAppWhitelisted(const char *path, char *const argv[restrict], char *const envp[restrict])
{
	NSString *injectPath = JBROOT_PATH(kRootHideInjectRelativePath);
	NSDictionary *injectRules = [NSDictionary dictionaryWithContentsOfFile:injectPath];
	if (![injectRules isKindOfClass:[NSDictionary class]]) {
		return NO;
	}

	for (NSString *bundleIdentifier in RootHideBundleIdentifiersForSpawn(path, argv, envp)) {
		id value = injectRules[bundleIdentifier];
		if ([value respondsToSelector:@selector(boolValue)] && [value boolValue]) {
			return YES;
		}
	}

	NSString *executableName = RootHideExecutableNameForPath(path);
	if (executableName.length > 0) {
		id value = injectRules[executableName];
		if ([value respondsToSelector:@selector(boolValue)] && [value boolValue]) {
			return YES;
		}
	}

	return NO;
}

static BOOL RootHideShouldEnableHiddenWhitelistBootstrap(const char *path, char *const argv[restrict], char *const envp[restrict])
{
	// Only activate hidden-whitelist bootstrap when:
	// 1. The app is explicitly whitelisted in inject.plist (UI toggle ON)
	// 2. There are actual tweaks selected in the hidden whitelist tweaks plist
	// Blacklist-only (no whitelist) should fall through to stock blacklist.
	if (!RootHideIsAppWhitelisted(path, argv, envp)) {
		return NO;
	}
	NSDictionary *entry = RootHideHiddenWhitelistEntryForSpawn(path, argv, envp);
	return entry != nil && RootHideHiddenWhitelistEntryHasSelection(entry);
}

#define POSIX_SPAWN_PROC_TYPE_DRIVER 0x700
extern int posix_spawnattr_getprocesstype_np(const posix_spawnattr_t *__restrict, int *__restrict) __API_AVAILABLE(macos(10.8), ios(6.0));
extern int posix_spawnattr_setexceptionports_np(posix_spawnattr_t *__restrict, exception_mask_t, mach_port_t, exception_behavior_t, thread_state_flavor_t) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);

//from launchdhook/spawn_hook.c
extern int systemwide_trust_file_by_path(const char *path);
extern int platform_set_process_debugged(uint64_t pid, bool fullyDebugged);
extern int __posix_spawn_hook(pid_t *restrict pid, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict]);
extern int __posix_spawn_orig_wrapper(pid_t *restrict pid, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict]);

//from systemhook/roothide_common.c
int __sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen);
int __sysctl_hook(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen);
int __sysctlbyname(const char *name, size_t namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
int __sysctlbyname_hook(const char *name, size_t namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);

/*
int (*sysctlbyname_orig)(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
int sysctlbyname_hook(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{
	if (strcmp(name, "vm.shared_region_pivot") == 0) {
		return 0;
	}
	return sysctlbyname_orig(name, oldp, oldlenp, newp, newlen);
}
*/

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
int (*orig_bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int new_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in addr_in = *(struct sockaddr_in*)addr;
        in_port_t port = ntohs(addr_in.sin_port);
        if (port == 0) {
			int ret = -1;
			for(port=IPPORT_HIFIRSTAUTO; port<=IPPORT_HILASTAUTO; port++)
			{
				addr_in.sin_port = htons(port);
				ret = orig_bind(sockfd, (struct sockaddr*)&addr_in, addrlen);
				if(ret==0 || errno!=EADDRINUSE) {
					break;
				}
			}
			return ret;
        }
    } else if (addr->sa_family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 addr_in6 = *(struct sockaddr_in6*)addr;
        in_port_t port = ntohs(addr_in6.sin6_port);
        if (port == 0) {
			int ret = -1;
			for(port=IPPORT_HIFIRSTAUTO; port<=IPPORT_HILASTAUTO; port++)
			{
				addr_in6.sin6_port = htons(port);
				ret = orig_bind(sockfd, (struct sockaddr*)&addr_in6, addrlen);
				if(ret==0 || errno!=EADDRINUSE) {
					break;
				}
			}
			return ret;
        }
    }
    return orig_bind(sockfd, addr, addrlen);
}

extern xpc_object_t (*orig_xpc_dictionary_create_reply)(xpc_object_t original);
extern xpc_object_t new_xpc_dictionary_create_reply(xpc_object_t original);
extern int (*orig_xpc_pipe_routine_reply)(xpc_object_t reply);
extern int new_xpc_pipe_routine_reply(xpc_object_t reply);

void roothide_launchd_preinit()
{
	JBLogDebug("roothide_launchd_preinit");

#ifdef ENABLE_LOGS
	enableJBDLog(JBLogDebugFunction, JBLogErrorFunction);
#endif

	exec_set_patch(false);
}

void roothide_launchd_postinit(bool firstLoad)
{
	JBLogDebug("roothide_launchd_postinit: firstLoad=%d", firstLoad);

	launchdhookFirstLoad = firstLoad;

	exec_set_patch(true);

	if(firstLoad)
	{
		HOOK_DYLIB_PATH = "";
		
		if (__builtin_available(iOS 16.0, *))
		{
			hideDeveloperMode();
		}
		
#ifdef __arm64e__
		if (!__builtin_available(iOS 16.0, *))
		{
			if(roothide_config_set_spinlock_fix(dyld_patch_enabled()) != 0) {
				launchd_panic("roothide_config_set_spinlock_fix failed");
				return;
			}
		}
#endif
	}
	else
	{		
		NSString* systemhookFilePath = [NSString stringWithFormat:@"%@/systemhook-%016llX.dylib", JBROOT_PATH(@"/basebin"), jbinfo(jbrand)];

		if([NSFileManager.defaultManager fileExistsAtPath:JBROOT_PATH(@"/basebin/systemhook.dylib")])
		{
			[NSFileManager.defaultManager removeItemAtPath:systemhookFilePath error:nil];
			assert([NSFileManager.defaultManager moveItemAtPath:JBROOT_PATH(@"/basebin/systemhook.dylib") toPath:systemhookFilePath error:nil]);
		}
		
		assert(unsandbox("/usr/lib", systemhookFilePath.fileSystemRepresentation) == 0);

		//new "real path"
		asprintf(&HOOK_DYLIB_PATH, "/usr/lib/systemhook-%016llX.dylib", jbinfo(jbrand));
	}

	if (__builtin_available(iOS 16.0, *))
	{
		void* __sysctl_orig = NULL;
		void* __sysctlbyname_orig = NULL;
		MSHookFunction(&__sysctl, (void *) __sysctl_hook, &__sysctl_orig);
		MSHookFunction(&__sysctlbyname, (void *) __sysctlbyname_hook, &__sysctlbyname_orig);
		MSHookFunction(&bind, (void*)new_bind, &orig_bind); //fix network issues on iOS16+
	}
#ifdef __arm64e__
	else 
	{
		// iOS15 arm64e only
		// MSHookFunction(sysctlbyname, (void *)sysctlbyname_hook, (void **)&sysctlbyname_orig);
	}
#endif

	if(!firstLoad)
	{
		int ret = ensure_dyld_trustcache(JBROOT_PATH("/basebin/.fakelib/dyld"));
		if (ret != 0) {
			launchd_panic("ensure dyld trustcache failed: %d", ret);
			return;
		}
	}

	loadAppStoredIdentifiers();

	MSHookFunction(&xpc_dictionary_create_reply, (void*)new_xpc_dictionary_create_reply, &orig_xpc_dictionary_create_reply);
	MSHookFunction(&xpc_pipe_routine_reply, (void*)new_xpc_pipe_routine_reply, &orig_xpc_pipe_routine_reply);

	// load jailbreakd after applying hooks
	assert(initJailbreakd(firstLoad) == 0);
}

int roothide_trust_executable_recurse(const char *executablePath, const char *processWorkingDir, xpc_object_t preferredArchsArray);
int roothide_launchd_trust_executable(const char* path)
{
	return dyld_patch_enabled() ? systemwide_trust_file_by_path(path) : roothide_trust_executable_recurse(path, "/", NULL);
}

int roothide_launchd___posix_spawn_posthook(pid_t *restrict pidp, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict])
{
	//spawn_prehook ensure this is always available
	posix_spawnattr_t attrp = &desc->attrp;

	short flags = 0;
	posix_spawnattr_getflags(attrp, &flags);

	int proctype = 0;
	posix_spawnattr_getprocesstype_np(attrp, &proctype);

	bool should_suspend = (proctype != POSIX_SPAWN_PROC_TYPE_DRIVER);
	bool should_resume = should_suspend && (flags & POSIX_SPAWN_START_SUSPENDED)==0;

	if (should_suspend) {
		posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);
	}

	// on some devices dyldhook may fail due to vm_protect(VM_PROT_READ|VM_PROT_WRITE), 2, (os/kern) protection failure in dsc::__DATA_CONST:__const, 
	// so we need to disable dyld-in-cache here. (or we can use VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY)
	char **envc = envbuf_mutcopy((const char **)envp);
	if(envbuf_getenv(envc, "DYLD_INSERT_LIBRARIES")) {
		envbuf_setenv(&envc, "DYLD_IN_CACHE", "0");
	}

#ifdef __arm64e__
	if (!__builtin_available(iOS 16.0, *))
	{
		if(!dyld_patch_enabled() && process_force_dyld_patch(path, argv)) {
			envbuf_setenv(&envc, "SPINLOCK_FIX_DISABLED", "1");
		}
	}
#endif

	int pid = 0;
	// Diagnostic: log ROOTHIDE_* env vars right before the actual syscall
	if (strstr(path, ".app/")) {
		const char *hi_val = envbuf_getenv((const char **)envc, "ROOTHIDE_HIDDEN_INJECTION");
		const char *ht_val = envbuf_getenv((const char **)envc, "ROOTHIDE_ENABLE_HIDDEN_TWEAKS");
		const char *dil_val = envbuf_getenv((const char **)envc, "DYLD_INSERT_LIBRARIES");
		RootHideInjectionLaunchdLog(@"posthook PRE-SYSCALL path=%s HI=%s HT=%s DYLD=%s", path, hi_val ?: "(null)", ht_val ?: "(null)", dil_val ?: "(null)");
	}
	int ret = __posix_spawn_orig_wrapper(&pid, path, desc, argv, envc);
	if(pidp) *pidp = pid;

	envbuf_free(envc);
	
	posix_spawnattr_setflags(attrp, flags); // maybe caller will use it again?

	if (ret == 0 && pid > 0) {
		if(should_suspend) {
			int patchResult = jbdSpawnPatchChild(pid, should_resume);
			if (strstr(path, ".app/")) {
				RootHideInjectionLaunchdLog(@"posthook PATCH pid=%d path=%s patchResult=%d should_resume=%d proctype=0x%x", pid, path, patchResult, should_resume, proctype);
			}
			if(patchResult != 0) {
				JBLogError("Failed to patch spawned process (%d) %s", pid, path);
				//just kill it instead of letting it hang forever so that launchd can respawn it later
				kill(pid, SIGQUIT); //core dump
				kill(pid, SIGKILL);
				ret = 202;
			}
		} else {
			if (strstr(path, ".app/")) {
				RootHideInjectionLaunchdLog(@"posthook SKIP-PATCH pid=%d path=%s should_suspend=%d proctype=0x%x", pid, path, should_suspend, proctype);
			}
		}
	} else {
		JBLogError("spawn failed: %d %s, pid=%d", ret, strerror(ret), pid);
		if (strstr(path, ".app/")) {
			RootHideInjectionLaunchdLog(@"posthook SPAWN-FAILED ret=%d path=%s pid=%d", ret, path, pid);
		}
	}

	return ret;
}

int roothide_launchd___posix_spawn__spinlock_fix_only(pid_t *restrict pidp, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict])
{
	//spawn_prehook ensure this is always available
	posix_spawnattr_t attrp = &desc->attrp;

	short flags = 0;
	posix_spawnattr_getflags(attrp, &flags);

	bool should_resume = (flags & POSIX_SPAWN_START_SUSPENDED)==0;

	posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);

	int pid = 0;
	int ret = __posix_spawn_orig_wrapper(&pid, path, desc, argv, envp);
	if(pidp) *pidp = pid;
	
	posix_spawnattr_setflags(attrp, flags); // maybe caller will use it again?

	if (ret == 0 && pid > 0) {
		if(jbdSpinlockFixOnly(pid, should_resume)  != 0) {
			JBLogError("Failed to patch(spinlock fix) spawned process (%d) %s", pid, path);
			//just kill it instead of letting it hang forever so that launchd can respawn it later
			kill(pid, SIGQUIT); //core dump
			kill(pid, SIGKILL);
			ret = 202;
		}
	} else {
		JBLogError("spawn failed: %d %s, pid=%d", ret, strerror(ret), pid);
	}

	return ret;
}

int roothide_launchd___posix_spawn_prehook(pid_t *restrict pidp, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict])
{
	if(!desc || !desc->attrp) {
		posix_spawnattr_t attr=NULL;
		posix_spawnattr_init(&attr);
		int ret = posix_spawn(pidp, path, (desc && desc->file_actions) ? &desc->file_actions : NULL, &attr, argv, envp);
		posix_spawnattr_destroy(&attr);
		return ret;
	}
	posix_spawnattr_t attrp = &desc->attrp;

	if(!path) {
		return __posix_spawn_hook(pidp, path, desc, argv, envp);
	}

	if(strcmp(path, "/sbin/launchd") == 0) {
		short flags = 0;
		posix_spawnattr_getflags(attrp, &flags);
		posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);
		return __posix_spawn_hook(pidp, path, desc, argv, envp);
	}

	if(path && string_has_suffix(path, "/Dopamine.app/Dopamine"))
	{
		/* if the jailbreak activation is interrupted for some reason, 
			we prevent the app from relaunching to prevent the system from being in an unknown state */
		if(launchdhookFirstLoad) {
#ifdef ENABLE_LOGS
			launchd_panic("reboot device due to jailbreak failure!");
#endif
			return EPERM;
		}

		char roothidefile[PATH_MAX];
		snprintf(roothidefile, sizeof(roothidefile), "%s.roothide", path);
		if(access(roothidefile, F_OK) != 0) {
			return EPERM;
		}
	}
	
	if(string_has_suffix(path, "/basebin/jailbreakd")) {
		return __posix_spawn_orig_wrapper(pidp, path, desc, argv, envp);
	}


	// mitigate spinlock panic for ios15(A12+) devices

	bool iOS15Arm64e = false;
	bool choicyBlocked = false;
#ifdef __arm64e__
	if (!__builtin_available(iOS 16.0, *))
	{
		iOS15Arm64e = true;
		if(envbuf_getenv(envp, "_SafeMode") || envbuf_getenv(envp, "_MSSafeMode")) {
			if(path && isRemovableBundlePath(path) && !hasTrollstoreMarker(path)) {
				choicyBlocked = true;
			}
		}
	}
#endif

	NSString *hiddenWhitelistBundleIdentifier = RootHideBundleIdentifierForSpawn(path, argv, envp);
	bool roothideBlacklisted = isBlacklistedPath(path)
		|| (hiddenWhitelistBundleIdentifier.length > 0 && isBlacklistedApp(hiddenWhitelistBundleIdentifier.UTF8String));
	bool hiddenWhitelistMode = root_hide_injection_mode_is_hidden_whitelist();
	bool hiddenWhitelistBootstrapEnabled = hiddenWhitelistMode && RootHideShouldEnableHiddenWhitelistBootstrap(path, argv, envp);
	if (hiddenWhitelistMode) {
		RootHideInjectionLaunchdLog(@"spawn path=%s bundle=%@ blacklisted=%d hiddenMode=%d hiddenBootstrap=%d", path ?: "(null)", hiddenWhitelistBundleIdentifier ?: @"(null)", roothideBlacklisted, hiddenWhitelistMode, hiddenWhitelistBootstrapEnabled);
	}
	if (roothideBlacklisted && hiddenWhitelistMode && hiddenWhitelistBootstrapEnabled)
	{
		int ret;

		RootHideInjectionLaunchdLog(@"taking hidden-whitelist branch path=%s", path ?: "(null)");

		char **envc = envbuf_mutcopy((const char **)envp);

		envbuf_unsetenv(&envc, "_SafeMode");
		envbuf_unsetenv(&envc, "_MSSafeMode");
		if (!RootHideApplyHiddenWhitelistTweakEnvironment(&envc, path, argv, envp)) {
			envbuf_free(envc);
			hiddenWhitelistBootstrapEnabled = false;
			RootHideInjectionLaunchdLog(@"hidden-whitelist branch fell back to blacklist path=%s", path ?: "(null)");
		}
		else {

			// CRITICAL: Do NOT register this process as blacklisted.
			// Blacklisted PIDs are blocked by roothide_domain_allowed() in
			// jbdomain_roothide.c, which causes jailbreakd to REFUSE the
			// process checkin.  Without checkin, systemhook's constructor
			// bails out and no tweaks load.
			//
			// Hidden-whitelist processes need the full JB infrastructure
			// (checkin, sandbox extensions, patched dyld) to function.
			// The ROOTHIDE_HIDDEN_INJECTION env var tells systemhook to
			// activate hidden mode (no forkfix, no rootlesshooks, no
			// exec/spawn hooks) while still loading selected tweaks.
			pid_t spawnedPid = 0;
			ret = __posix_spawn_hook(&spawnedPid, path, desc, argv, envc);

			if(pidp) *pidp = spawnedPid;

			RootHideInjectionLaunchdLog(@"hidden-whitelist spawn result ret=%d pid=%d path=%s", ret, spawnedPid, path ?: "(null)");

			envbuf_free(envc);

			if(ret==0 && spawnedPid>0) {
				short flags = 0;
				posix_spawnattr_getflags(attrp, &flags);
				if((flags & POSIX_SPAWN_START_SUSPENDED) != 0) {
					platform_set_process_debugged(spawnedPid, false);
				}
			}

			return ret;
		}
	}
	if (choicyBlocked || roothideBlacklisted)
	{
		int ret;

		RootHideInjectionLaunchdLog(@"taking blacklist branch path=%s choicyBlocked=%d roothideBlacklisted=%d", path ?: "(null)", choicyBlocked, roothideBlacklisted);

		if(dyld_patch_enabled() && iOS15Arm64e && roothideBlacklisted && (strstr(path, "/PlugIns/") || strstr(path, "/Extensions/") || strstr(path, ".appex/"))) {
			JBLogDebug("prevent blacklisted app's extension from running: ", path);
			ret = EPERM;
		}
		else if(dyld_patch_enabled() && iOS15Arm64e && roothideBlacklisted && (envbuf_getenv(envp, "ActivePrewarm") || envbuf_getenv(envp, "DYLD_USE_CLOSURES"))) {
			JBLogDebug("prevent blacklisted app from prewarming: ", path);
			ret = EPERM;
		}
		else
		{
			char **envc = envbuf_mutcopy((const char **)envp);

			//choicy may set these 
			envbuf_unsetenv(&envc, "_SafeMode");
			envbuf_unsetenv(&envc, "_MSSafeMode");
	
			/* According to xnu, the new thread in new process will not run in userland until after copyout pid
			https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_exec.c#L4321
			https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_exec.c#L4882
			https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_exec.c#L4933
			*/
	
			/* and posix_spawn->kernel->amfid->launchd may cause xpc dead loop so we can't use lock-spawn-unlock here */
	
			volatile pid_t* blacklistedPidp = allocBlacklistProcessId();
	
			if(roothideBlacklisted || !dyld_patch_enabled() || !iOS15Arm64e) {
				ret = __posix_spawn_orig_wrapper(blacklistedPidp, path, desc, argv, envc);
			} else {
				ret = roothide_launchd___posix_spawn__spinlock_fix_only(blacklistedPidp, path, desc, argv, envc);
			}
	
			pid_t pid = *blacklistedPidp;
			if(pidp) *pidp = *blacklistedPidp;

			commitBlacklistProcessId(blacklistedPidp); // will release blacklistedPidp
			blacklistedPidp = NULL;

			envbuf_free(envc);
				
			if(ret==0 && pid>0) {
				short flags = 0;
				posix_spawnattr_getflags(attrp, &flags);
				if((flags & POSIX_SPAWN_START_SUSPENDED) != 0) {
					platform_set_process_debugged(pid, false);
				}
			}
		}
	
		return ret;
	}

	if(launchdhookFirstLoad) 
	{
		//we should not enable system-wide injection until the jailbreak is finalized (userspace reboot).
		if (RootHideShouldTraceSpawnPath(path)) {
			RootHideInjectionLaunchdLog(@"taking first-load passthrough path=%s bundle=%@", path ?: "(null)", hiddenWhitelistBundleIdentifier ?: @"(null)");
		}
		return __posix_spawn_orig_wrapper(pidp, path, desc, argv, envp);
	}

	if (RootHideShouldTraceSpawnPath(path)) {
		RootHideInjectionLaunchdLog(@"taking normal inject branch path=%s bundle=%@", path ?: "(null)", hiddenWhitelistBundleIdentifier ?: @"(null)");
	}
	return __posix_spawn_hook(pidp, path, desc, argv, envp);
}
