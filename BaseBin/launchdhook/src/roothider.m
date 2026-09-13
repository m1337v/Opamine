#import <Foundation/Foundation.h>

#include <spawn.h>
#include <substrate.h>
#include <sys/sysctl.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <IOKit/IOKitLib.h>
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
    (void)format;
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

static NSString *RootHideNormalizedString(id value)
{
	if (![value isKindOfClass:[NSString class]]) {
		return nil;
	}

	NSString *trimmedValue = [(NSString *)value stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
	return trimmedValue.length > 0 ? trimmedValue : nil;
}

typedef NS_ENUM(NSUInteger, RootHideBundleIdentifierSource) {
	RootHideBundleIdentifierSourceNone,
	RootHideBundleIdentifierSourceAuthoritative,
	RootHideBundleIdentifierSourceUniqueHeuristic,
	RootHideBundleIdentifierSourceAmbiguousHeuristic,
};

static const NSUInteger kRootHideMaxSpawnArgumentEntries = 128;
static const NSUInteger kRootHideMaxHeuristicBundleIdentifiers = 16;

static NSString *RootHideNormalizedBundleIdentifierCandidate(NSString *candidate)
{
	if (![candidate isKindOfClass:[NSString class]]) {
		return nil;
	}

	NSString *trimmedCandidate = [candidate stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
	// Structured key=value data is never a direct identity. Callers must split
	// recognized identity labels first, otherwise a harmless dotted setting can
	// silently turn into an app/service selection.
	if (trimmedCandidate.length == 0 || [trimmedCandidate containsString:@"/"] || [trimmedCandidate containsString:@"="]) {
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
	return RootHideNormalizedBundleIdentifierCandidate(infoDictionary[@"CFBundleIdentifier"]);
}

static NSString *RootHideBundleIdentifierFromUIKitApplicationLaunchName(const char *launchName)
{
	if (!launchName || launchName[0] == '\0') {
		return nil;
	}

	NSString *rawName = @(launchName);
	if (![rawName hasPrefix:@"UIKitApplication:"]) {
		return nil;
	}

	rawName = [rawName substringFromIndex:sizeof("UIKitApplication:") - 1];
	NSRange bracketRange = [rawName rangeOfString:@"["];
	if (bracketRange.location != NSNotFound) {
		rawName = [rawName substringToIndex:bracketRange.location];
	}

	return RootHideNormalizedBundleIdentifierCandidate(rawName);
}

static BOOL RootHideIsIdentityEnvironmentKey(NSString *key)
{
	return [key isEqualToString:@"XPC_SERVICE_NAME"]
		|| [key isEqualToString:@"CFBundleIdentifier"]
		|| [key isEqualToString:@"BUNDLE_IDENTIFIER"];
}

static NSString *RootHideBundleIdentifierFromStructuredIdentityValue(NSString *value)
{
	if (![value isKindOfClass:[NSString class]]) {
		return nil;
	}

	NSRange equalsRange = [value rangeOfString:@"="];
	if (equalsRange.location == NSNotFound || equalsRange.location + 1 >= value.length) {
		return nil;
	}
	NSString *key = [value substringToIndex:equalsRange.location];
	if (!RootHideIsIdentityEnvironmentKey(key)) {
		return nil;
	}
	NSString *candidate = [value substringFromIndex:equalsRange.location + 1];
	return RootHideBundleIdentifierFromUIKitApplicationLaunchName(candidate.UTF8String)
		?: RootHideNormalizedBundleIdentifierCandidate(candidate);
}

static void RootHideEnumerateCStringList(char *const values[restrict], void (^block)(NSString *value, bool *stop))
{
	if (!values || !block) {
		return;
	}

	for (NSUInteger index = 0; index < kRootHideMaxSpawnArgumentEntries && values[index] != NULL; index++) {
		NSString *value = @(values[index]);
		bool stop = false;
		block(value, &stop);
		if (stop) {
			break;
		}
	}
}

static void RootHideAddBundleIdentifierCandidatesFromValue(NSMutableOrderedSet<NSString *> *bundleIdentifiers, NSString *value)
{
	if (!bundleIdentifiers || ![value isKindOfClass:[NSString class]]) {
		return;
	}

	if (bundleIdentifiers.count >= kRootHideMaxHeuristicBundleIdentifiers) {
		return;
	}

	NSString *directBundleIdentifier = RootHideBundleIdentifierFromUIKitApplicationLaunchName(value.UTF8String);
	if (directBundleIdentifier.length > 0) {
		[bundleIdentifiers addObject:directBundleIdentifier];
		return;
	}

	NSRange equalsRange = [value rangeOfString:@"="];
	if (equalsRange.location != NSNotFound) {
		NSString *bundleIdentifierAfterEquals = RootHideBundleIdentifierFromStructuredIdentityValue(value);
		if (bundleIdentifierAfterEquals.length > 0) {
			[bundleIdentifiers addObject:bundleIdentifierAfterEquals];
		}
		return;
	}

	NSString *normalizedCandidate = RootHideNormalizedBundleIdentifierCandidate(value);
	if (normalizedCandidate.length > 0) {
		[bundleIdentifiers addObject:normalizedCandidate];
	}

}

static NSString *RootHideAuthoritativeBundleIdentifierForSpawn(const char *path, char *const argv[restrict])
{
	if (path && strcmp(path, "/usr/libexec/xpcproxy") != 0) {
		return RootHideBundleIdentifierForExecutablePath(path);
	}

	if (!path || strcmp(path, "/usr/libexec/xpcproxy") != 0 || !argv || !argv[1]) {
		return nil;
	}

	// launchd's primary xpcproxy label is the only argv value that carries
	// ownership.  A UIKitApplication label identifies the app; an exact dotted
	// service label identifies the service.  Other argv/env values are merely
	// discovery hints and must not win over this source.
	NSString *uikitBundleIdentifier = RootHideBundleIdentifierFromUIKitApplicationLaunchName(argv[1]);
	if (uikitBundleIdentifier.length > 0) {
		return uikitBundleIdentifier;
	}
	NSString *structuredPrimaryLabel = RootHideBundleIdentifierFromStructuredIdentityValue(@(argv[1]));
	if (structuredPrimaryLabel.length > 0) {
		return structuredPrimaryLabel;
	}

	return RootHideNormalizedBundleIdentifierCandidate(@(argv[1]));
}

static NSArray<NSString *> *RootHideHeuristicBundleIdentifiersForSpawn(char *const argv[restrict], char *const envp[restrict])
{
	NSMutableOrderedSet<NSString *> *bundleIdentifiers = [NSMutableOrderedSet orderedSet];
	RootHideEnumerateCStringList(argv, ^(NSString *value, bool *stop) {
		RootHideAddBundleIdentifierCandidatesFromValue(bundleIdentifiers, value);
		*stop = bundleIdentifiers.count >= kRootHideMaxHeuristicBundleIdentifiers;
	});
	RootHideEnumerateCStringList(envp, ^(NSString *value, bool *stop) {
		RootHideAddBundleIdentifierCandidatesFromValue(bundleIdentifiers, value);
		*stop = bundleIdentifiers.count >= kRootHideMaxHeuristicBundleIdentifiers;
	});
	return bundleIdentifiers.array;
}

static NSString *RootHideBundleIdentifierForSpawn(const char *path, char *const argv[restrict], char *const envp[restrict], RootHideBundleIdentifierSource *sourceOut)
{
	RootHideBundleIdentifierSource source = RootHideBundleIdentifierSourceNone;
	NSString *bundleIdentifier = RootHideAuthoritativeBundleIdentifierForSpawn(path, argv);
	if (bundleIdentifier.length > 0) {
		source = RootHideBundleIdentifierSourceAuthoritative;
	}
	else {
		NSArray<NSString *> *candidates = RootHideHeuristicBundleIdentifiersForSpawn(argv, envp);
		if (candidates.count == 1) {
			bundleIdentifier = candidates.firstObject;
			source = RootHideBundleIdentifierSourceUniqueHeuristic;
		}
		else if (candidates.count > 1) {
			source = RootHideBundleIdentifierSourceAmbiguousHeuristic;
			RootHideInjectionLaunchdLog(@"reject hidden bootstrap due to ambiguous bundle candidates path=%s candidates=%@", path ?: "(null)", [candidates componentsJoinedByString:@","]);
		}
	}

	if (sourceOut) {
		*sourceOut = source;
	}
	return bundleIdentifier;
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
	RootHideBundleIdentifierSource source = RootHideBundleIdentifierSourceNone;
	NSString *bundleIdentifier = RootHideBundleIdentifierForSpawn(path, argv, envp, &source);
	if (bundleIdentifier.length > 0) {
		NSDictionary *entry = [allSettings[bundleIdentifier] isKindOfClass:[NSDictionary class]] ? allSettings[bundleIdentifier] : nil;
		if (entry) {
			return entry;
		}
	}
	else if (source == RootHideBundleIdentifierSourceAmbiguousHeuristic) {
		return nil;
	}

	// Preserve the historical executable-name fallback for non-bundle services,
	// but never let it override an ambiguous argv/env-derived identity.
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
	if (!envc || !*envc) {
		RootHideInjectionLaunchdLog(@"hidden env allocation failed path=%s", path ?: "(null)");
		return NO;
	}

	NSDictionary *entry = RootHideHiddenWhitelistEntryForSpawn(path, argv, envp);
	if (!entry) {
		// No per-app tweak config exists.  Fall through to stock blacklist.
		RootHideInjectionLaunchdLog(@"hidden config missing, falling back to blacklist path=%s bundle=%@", path ?: "(null)", RootHideBundleIdentifierForSpawn(path, argv, envp, NULL) ?: @"(null)");
		return NO;
	}

	NSInteger allowDenyMode = [entry[@"allowDenyMode"] respondsToSelector:@selector(integerValue)] ? [entry[@"allowDenyMode"] integerValue] : kRootHideHiddenTweakAllowMode;
	NSString *modeString = allowDenyMode == kRootHideHiddenTweakDenyMode ? @"deny" : @"allow";
	NSArray<NSString *> *selectedTweaks = RootHideNormalizedTweakNames(entry[allowDenyMode == kRootHideHiddenTweakDenyMode ? @"deniedTweaks" : @"allowedTweaks"]);
	if (selectedTweaks.count == 0) {
		// Entry exists but no tweaks selected.  Fall through to stock blacklist.
		RootHideInjectionLaunchdLog(@"hidden tweak list empty, falling back to blacklist path=%s bundle=%@ mode=%@", path ?: "(null)", RootHideBundleIdentifierForSpawn(path, argv, envp, NULL) ?: @"(null)", modeString);
		return NO;
	}

	// Build the complete hidden handoff on a second owned buffer.  A partial
	// marker set is worse than a clean blacklist fallback: it can start the
	// child with systemhook but without the matching selected-tweak policy.
	char **candidateEnvc = envbuf_mutcopy((const char **)*envc);
	NSString *hiderProfile = RootHideNormalizedString(entry[@"hiderProfile"]) ?: @"full";
	NSArray<NSString *> *disabledHiderHooks = RootHideNormalizedTweakNames(entry[@"disabledHiderHooks"]);
	NSString *selectedTweakList = [selectedTweaks componentsJoinedByString:@":"];
	NSString *disabledHookList = [disabledHiderHooks componentsJoinedByString:@":"];
	BOOL mutationsSucceeded = candidateEnvc != NULL
		&& envbuf_setenv(&candidateEnvc, "ROOTHIDE_HIDDEN_INJECTION", "1")
		&& envbuf_setenv(&candidateEnvc, "ROOTHIDE_ENABLE_HIDDEN_TWEAKS", "1")
		&& envbuf_setenv(&candidateEnvc, "ROOTHIDE_HIDDEN_TWEAK_MODE", modeString.UTF8String)
		&& envbuf_setenv(&candidateEnvc, "ROOTHIDE_HIDDEN_TWEAK_LIST", selectedTweakList.UTF8String)
		&& envbuf_setenv(&candidateEnvc, "ROOTHIDE_HIDER_PROFILE", hiderProfile.UTF8String)
		&& (disabledHiderHooks.count > 0
			? envbuf_setenv(&candidateEnvc, "ROOTHIDE_HIDER_DISABLED_HOOKS", disabledHookList.UTF8String)
			: envbuf_unsetenv(&candidateEnvc, "ROOTHIDE_HIDER_DISABLED_HOOKS"))
		&& envbuf_unsetenv(&candidateEnvc, "_SafeMode")
		&& envbuf_unsetenv(&candidateEnvc, "_MSSafeMode")
		&& envbuf_unsetenv(&candidateEnvc, "DISABLE_TWEAKS")
		&& envbuf_unsetenv(&candidateEnvc, "CHOICY_SKIP_TWEAKLOADER");
	if (!mutationsSucceeded) {
		envbuf_free(candidateEnvc);
		RootHideInjectionLaunchdLog(@"hidden env transaction failed path=%s", path ?: "(null)");
		return NO;
	}

	envbuf_free(*envc);
	*envc = candidateEnvc;
	RootHideInjectionLaunchdLog(@"apply hidden env path=%s bundle=%@ mode=%@ tweaks=%@", path ?: "(null)", RootHideBundleIdentifierForSpawn(path, argv, envp, NULL) ?: @"(null)", modeString, [selectedTweaks componentsJoinedByString:@":"]);
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

	RootHideBundleIdentifierSource source = RootHideBundleIdentifierSourceNone;
	NSString *bundleIdentifier = RootHideBundleIdentifierForSpawn(path, argv, envp, &source);
	if (bundleIdentifier.length > 0) {
		id value = injectRules[bundleIdentifier];
		if ([value respondsToSelector:@selector(boolValue)] && [value boolValue]) {
			return YES;
		}
	}
	else if (source == RootHideBundleIdentifierSourceAmbiguousHeuristic) {
		return NO;
	}

	// See the matching settings fallback above: service-name compatibility is
	// retained only where bundle identification found no conflicting candidates.
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

		// New real path. Keep the existing first-load literal untouched: it may
		// not be heap allocated, so only publish a fully allocated replacement.
		char *hookDylibPath = NULL;
		if (asprintf(&hookDylibPath, "/usr/lib/systemhook-%016llX.dylib", jbinfo(jbrand)) < 0 || !hookDylibPath) {
			launchd_panic("failed to allocate systemhook path");
			return;
		}
		HOOK_DYLIB_PATH = hookDylibPath;
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

static void RootHideRefreshLaunchdIOSurfaceConnectForAppSpawn(void)
{
	MSImageRef iosurfaceImage = MSGetImageByName("/System/Library/Frameworks/IOSurface.framework/IOSurface");
	if (!iosurfaceImage) {
		return;
	}

	io_service_t *iosService = MSFindSymbol(iosurfaceImage, "__iosService");
	io_connect_t *iosConnect = MSFindSymbol(iosurfaceImage, "__iosConnect");
	if (!iosService || !iosConnect || *iosService == IO_OBJECT_NULL || *iosConnect == IO_OBJECT_NULL) {
		return;
	}

	kern_return_t (*ioServiceOpen)(io_service_t service, task_port_t owningTask, uint32_t type, io_connect_t *connect) = NULL;
	kern_return_t (*ioServiceClose)(io_connect_t connect) = NULL;
	*(void **)&ioServiceOpen = dlsym(RTLD_DEFAULT, "IOServiceOpen");
	*(void **)&ioServiceClose = dlsym(RTLD_DEFAULT, "IOServiceClose");
	if (!ioServiceOpen || !ioServiceClose) {
		return;
	}

	io_connect_t oldConnect = *iosConnect;
	io_connect_t newConnect = IO_OBJECT_NULL;
	kern_return_t kr = ioServiceOpen(*iosService, mach_task_self(), 0, &newConnect);
	if (kr != KERN_SUCCESS || newConnect == IO_OBJECT_NULL) {
		return;
	}

	*iosConnect = newConnect;
	ioServiceClose(oldConnect);
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
	const bool needsDyldInCacheMutation = envbuf_getenv((const char **)envp, "DYLD_INSERT_LIBRARIES") != NULL;
	bool needsSpinlockFixMutation = false;
#ifdef __arm64e__
	if (!__builtin_available(iOS 16.0, *)) {
		needsSpinlockFixMutation = !dyld_patch_enabled() && process_force_dyld_patch(path, (const char **)argv);
	}
#endif
	char **envc = envbuf_mutcopy((const char **)envp);
	bool ownsEnvc = envc != NULL;
	if (!envc) {
		if (needsDyldInCacheMutation || needsSpinlockFixMutation) {
			posix_spawnattr_setflags(attrp, flags);
			return ENOMEM;
		}
		envc = (char **)envp;
	}
	if (needsDyldInCacheMutation && !envbuf_setenv(&envc, "DYLD_IN_CACHE", "0")) {
		if (ownsEnvc) envbuf_free(envc);
		posix_spawnattr_setflags(attrp, flags);
		return ENOMEM;
	}

#ifdef __arm64e__
	if (needsSpinlockFixMutation) {
		if (!envbuf_setenv(&envc, "SPINLOCK_FIX_DISABLED", "1")) {
			if (ownsEnvc) envbuf_free(envc);
			posix_spawnattr_setflags(attrp, flags);
			return ENOMEM;
		}
	}
#endif

	pid_t pidval = 0;
	if (!pidp) pidp = &pidval;
	// Diagnostic: log ROOTHIDE_* env vars right before the actual syscall
	if (strstr(path, ".app/")) {
		const char *hi_val = envbuf_getenv((const char **)envc, "ROOTHIDE_HIDDEN_INJECTION");
		const char *ht_val = envbuf_getenv((const char **)envc, "ROOTHIDE_ENABLE_HIDDEN_TWEAKS");
		const char *dil_val = envbuf_getenv((const char **)envc, "DYLD_INSERT_LIBRARIES");
		RootHideInjectionLaunchdLog(@"posthook PRE-SYSCALL path=%s HI=%s HT=%s DYLD=%s", path, hi_val ?: "(null)", ht_val ?: "(null)", dil_val ?: "(null)");
	}
	int ret = __posix_spawn_orig_wrapper(pidp, path, desc, argv, envc);
	pid_t pid = *pidp;

	if (ownsEnvc) envbuf_free(envc);
	
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

	pid_t pidval = 0;
	if (!pidp) pidp = &pidval;
	int ret = __posix_spawn_orig_wrapper(pidp, path, desc, argv, envp);
	pid_t pid = *pidp;
	
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

	if(isRemovableBundlePath(path)) {
		static dispatch_once_t onceToken = 0;
		dispatch_once(&onceToken, ^{
			RootHideRefreshLaunchdIOSurfaceConnectForAppSpawn();
		});
	}

	if(strcmp(path, "/sbin/launchd") == 0) {
		short flags = 0;
		posix_spawnattr_getflags(attrp, &flags);
		posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);
		return __posix_spawn_hook(pidp, path, desc, argv, envp);
	}

	if(path && isRemovableBundlePath(path) && string_has_suffix(path, "/Dopamine"))
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
		if(envbuf_getenv((const char * const *)envp, "_SafeMode") || envbuf_getenv((const char * const *)envp, "_MSSafeMode")) {
			if(path && isRemovableBundlePath(path) && !hasTrollstoreMarker(path)) {
				choicyBlocked = true;
			}
		}
	}
#endif

	RootHideBundleIdentifierSource hiddenWhitelistBundleIdentifierSource = RootHideBundleIdentifierSourceNone;
	NSString *hiddenWhitelistBundleIdentifier = RootHideBundleIdentifierForSpawn(path, argv, envp, &hiddenWhitelistBundleIdentifierSource);
	bool roothideBlacklisted = isBlacklistedPath(path)
		|| (hiddenWhitelistBundleIdentifier.length > 0 && isBlacklistedApp(hiddenWhitelistBundleIdentifier.UTF8String));
	bool hiddenWhitelistMode = root_hide_injection_mode_is_hidden_whitelist();
	bool blacklistAllowlistMode = root_hide_injection_mode_is_blacklist_allowlist();
	bool hiddenAllowlistMode = hiddenWhitelistMode || blacklistAllowlistMode;
	bool hiddenWhitelistBootstrapEnabled = hiddenAllowlistMode && RootHideShouldEnableHiddenWhitelistBootstrap(path, argv, envp);
	if (hiddenAllowlistMode) {
		RootHideInjectionLaunchdLog(@"spawn path=%s bundle=%@ bundleSource=%lu blacklisted=%d hiddenMode=%d blacklistAllowlistMode=%d hiddenBootstrap=%d", path ?: "(null)", hiddenWhitelistBundleIdentifier ?: @"(null)", (unsigned long)hiddenWhitelistBundleIdentifierSource, roothideBlacklisted, hiddenWhitelistMode, blacklistAllowlistMode, hiddenWhitelistBootstrapEnabled);
	}
	if (roothideBlacklisted && hiddenAllowlistMode && hiddenWhitelistBootstrapEnabled)
	{
		int ret;

		RootHideInjectionLaunchdLog(@"taking hidden allowlist branch path=%s mode=%s", path ?: "(null)", blacklistAllowlistMode ? "blacklistallowlist" : "hiddenwhitelist");

		char **envc = envbuf_mutcopy((const char **)envp);
		if (!envc || !RootHideApplyHiddenWhitelistTweakEnvironment(&envc, path, argv, envp)) {
			envbuf_free(envc);
			hiddenWhitelistBootstrapEnabled = false;
			RootHideInjectionLaunchdLog(@"hidden-whitelist branch fell back to blacklist path=%s", path ?: "(null)");
		}
		else {

			pid_t spawnedPid = 0;
			if (blacklistAllowlistMode) {
				// Blacklist + Allowlist keeps the process in a restricted
				// blacklisted class for Roothide's hiding paths, but allows
				// roothide/systemwide domain access so systemhook can still
				// check in and load the selected hidden tweak subset.
				pid_t *restrictedPidp = allocRestrictedBlacklistedProcessId();
				if (!restrictedPidp) {
					ret = ENOMEM;
				}
				else {
					ret = __posix_spawn_hook(restrictedPidp, path, desc, argv, envc);
					spawnedPid = *restrictedPidp;
					commitBlacklistProcessId(restrictedPidp);
				}
			}
			else {
				// Hidden Whitelist keeps the process fully out of the
				// blacklisted PID state and relies on the hidden env markers.
				ret = __posix_spawn_hook(&spawnedPid, path, desc, argv, envc);
			}

			if(pidp) *pidp = spawnedPid;

			RootHideInjectionLaunchdLog(@"hidden allowlist spawn result ret=%d pid=%d path=%s mode=%s", ret, spawnedPid, path ?: "(null)", blacklistAllowlistMode ? "blacklistallowlist" : "hiddenwhitelist");

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
		else if(dyld_patch_enabled() && iOS15Arm64e && roothideBlacklisted && (envbuf_getenv((const char * const *)envp, "ActivePrewarm") || envbuf_getenv((const char * const *)envp, "DYLD_USE_CLOSURES"))) {
			JBLogDebug("prevent blacklisted app from prewarming: ", path);
			ret = EPERM;
		}
		else
		{
			char **envc = envbuf_mutcopy((const char **)envp);
			if (!envc) {
				return ENOMEM;
			}

			//choicy may set these 
			if (!envbuf_unsetenv(&envc, "_SafeMode") || !envbuf_unsetenv(&envc, "_MSSafeMode")) {
				envbuf_free(envc);
				return ENOMEM;
			}
	
			/* According to xnu, the new thread in new process will not run in userland until after copyout pid
			https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_exec.c#L4321
			https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_exec.c#L4882
			https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_exec.c#L4933
			*/
	
			/* and posix_spawn->kernel->amfid->launchd may cause xpc dead loop so we can't use lock-spawn-unlock here */
	
			pid_t* blacklistedPidp = allocBlacklistProcessId();
			if (!blacklistedPidp) {
				envbuf_free(envc);
				return ENOMEM;
			}
	
			if(roothideBlacklisted || !dyld_patch_enabled() || !iOS15Arm64e) {
				ret = __posix_spawn_orig_wrapper(blacklistedPidp, path, desc, argv, envc);
			} else {
				ret = roothide_launchd___posix_spawn__spinlock_fix_only(blacklistedPidp, path, desc, argv, envc);
			}
	
			pid_t pid = *blacklistedPidp;
			if(pidp) *pidp = *blacklistedPidp;

			commitBlacklistProcessId(blacklistedPidp); // releases blacklistedPidp

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
