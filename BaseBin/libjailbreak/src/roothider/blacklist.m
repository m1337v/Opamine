#import <Foundation/Foundation.h>
#import <os/log.h>
#include <stdarg.h>
#include "../libjailbreak.h"
#include "common.h"

static NSString * const kRootHideInjectionModeStock = @"stock";
static NSString * const kRootHideInjectionModeBlacklist = @"blacklist";
static NSString * const kRootHideInjectionModeWhitelist = @"whitelist";
static NSString * const kRootHideInjectionModeHiddenWhitelist = @"hiddenwhitelist";
static NSString * const kRootHideModeRelativePath = @"/var/mobile/Library/RootHide/pro.m1337.inject.mode.plist";
static NSString * const kRootHideInjectRelativePath = @"/var/mobile/Library/RootHide/pro.m1337.inject.plist";
static NSString * const kRootHideInjectSystemRelativePath = @"/var/mobile/Library/RootHide/pro.m1337.inject.system.plist";
static NSString * const kRootHideInjectWantsBlacklistRelativePath = @"/var/mobile/Library/RootHide/pro.m1337.inject.wantsblacklist.plist";
static NSString * const kRootHideUninjectRelativePath = @"/var/mobile/Library/RootHide/pro.m1337.uninject.plist";
#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"
#define NULL_UUID "00000000-0000-0000-0000-000000000000"

static NSString *normalizedRootHideInjectionMode(NSString *mode)
{
    if ([mode isEqualToString:kRootHideInjectionModeBlacklist] || [mode isEqualToString:kRootHideInjectionModeWhitelist] || [mode isEqualToString:kRootHideInjectionModeHiddenWhitelist]) {
        return mode;
    }
    if ([mode isEqualToString:kRootHideInjectionModeStock]) {
        return mode;
    }
    return nil;
}

static void RootHideTraceLog(NSString *format, ...)
{
    (void)format;
}

static BOOL RootHideShouldTracePath(const char *path)
{
    if (!path) {
        return NO;
    }

    return strstr(path, ".app/") != NULL
        || strstr(path, ".appex/") != NULL
        || strstr(path, "/PlugIns/") != NULL
        || strstr(path, "/Extensions/") != NULL
        || strcmp(path, "/usr/libexec/xpcproxy") == 0;
}

static NSArray<NSString *> *rootHideCandidatePaths(NSString *relativePath)
{
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    NSString *jbrootPath = JBROOT_PATH(relativePath);
    if (jbrootPath.length > 0) {
        [paths addObject:jbrootPath];
    }
    return paths;
}

static NSDictionary *rootHideDictionaryAtCandidatePaths(NSString *relativePath)
{
    for (NSString *path in rootHideCandidatePaths(relativePath)) {
        NSDictionary *dictionary = [NSDictionary dictionaryWithContentsOfFile:path];
        if ([dictionary isKindOfClass:[NSDictionary class]]) {
            return dictionary;
        }
    }
    return nil;
}

static BOOL rootHidePathExistsAtCandidatePaths(NSString *relativePath)
{
    NSFileManager *fileManager = [NSFileManager defaultManager];
    for (NSString *path in rootHideCandidatePaths(relativePath)) {
        if ([fileManager fileExistsAtPath:path]) {
            return YES;
        }
    }
    return NO;
}

static NSString *rootHideInjectionMode(void)
{
    NSDictionary *modeConfiguration = rootHideDictionaryAtCandidatePaths(kRootHideModeRelativePath);
    NSString *configuredMode = normalizedRootHideInjectionMode(modeConfiguration[@"mode"]);
    if (configuredMode) {
        RootHideTraceLog(@"mode resolved=%@ source=plist", configuredMode);
        return configuredMode;
    }

    if (rootHidePathExistsAtCandidatePaths(kRootHideUninjectRelativePath)) {
        RootHideTraceLog(@"mode resolved=blacklist source=uninject-exists");
        return kRootHideInjectionModeBlacklist;
    }

    if (rootHidePathExistsAtCandidatePaths(kRootHideInjectRelativePath)) {
        RootHideTraceLog(@"mode resolved=whitelist source=inject-exists");
        return kRootHideInjectionModeWhitelist;
    }

    RootHideTraceLog(@"mode resolved=stock source=default");
    return kRootHideInjectionModeStock;
}

static BOOL rootHideDictionaryHasEnabledKey(NSString *relativePath, NSString *key)
{
    if (key.length == 0) {
        return NO;
    }

    NSDictionary *dictionary = rootHideDictionaryAtCandidatePaths(relativePath);
    if (!dictionary) {
        return NO;
    }
    return [dictionary[key] boolValue];
}

static BOOL rootHideDictionaryContainsEnabledSubstring(NSString *relativePath, const char *path)
{
    if (!path) {
        return NO;
    }

    NSDictionary *dictionary = rootHideDictionaryAtCandidatePaths(relativePath);
    if (!dictionary) {
        return NO;
    }

    for (NSString *key in dictionary) {
        if ([dictionary[key] boolValue] && strstr(path, key.UTF8String)) {
            return YES;
        }
    }
    return NO;
}

NSString *getAppBundlePathFromSpawnPath(const char *path) {
    if (!path) return nil;

    char abspath[PATH_MAX];
    if (!realpath(path, abspath)) return nil;

    if (strncmp(abspath, APP_PATH_PREFIX, sizeof(APP_PATH_PREFIX) - 1) != 0)
        return nil;

    char *p1 = abspath + sizeof(APP_PATH_PREFIX) - 1;
    char *p2 = strchr(p1, '/');
    if (!p2) return nil;

    if ((p2 - p1) != (sizeof(NULL_UUID) - 1))
        return nil;

    char *p = strstr(p2, ".app/");
    if (!p) return nil;

    p[sizeof(".app/") - 1] = '\0';

    return [NSString stringWithUTF8String:abspath];
}

NSString *getAppIdentifierFromPath(const char *path) {
    if (!path) return nil;

    NSString *bundlePath = getAppBundlePathFromSpawnPath(path);
    if (!bundlePath) return nil;

    NSDictionary *appInfo = [NSDictionary dictionaryWithContentsOfFile:[NSString stringWithFormat:@"%@/Info.plist", bundlePath]];
    if (!appInfo) return nil;

    NSString *identifier = appInfo[@"CFBundleIdentifier"];
    if (!identifier) return nil;

    return identifier;
}

NSArray* builtinApps = @[
    @"com.opa334.Dopamine-roothide",
];

bool isBlacklistedApp(const char* identifier)
{
    if(!identifier) return false;

    if([builtinApps containsObject:@(identifier)]) {
        RootHideTraceLog(@"blacklist app identifier=%s result=0 reason=builtin", identifier);
        return false;
    }

    NSString* configFilePath = JBROOT_PATH(@"/var/mobile/Library/RootHide/RootHideConfig.plist");
    NSDictionary* roothideConfig = [NSDictionary dictionaryWithContentsOfFile:configFilePath];
    if(!roothideConfig) {
        RootHideTraceLog(@"blacklist app identifier=%s result=0 reason=no-config path=%@", identifier, configFilePath);
        return false;
    }

    NSDictionary* appconfig = roothideConfig[@"appconfig"];
    if(!appconfig) {
        RootHideTraceLog(@"blacklist app identifier=%s result=0 reason=no-appconfig", identifier);
        return false;
    }

    NSNumber* blacklisted = appconfig[@(identifier)];
    if(!blacklisted) {
        RootHideTraceLog(@"blacklist app identifier=%s result=0 reason=no-entry", identifier);
        return false;
    }

    RootHideTraceLog(@"blacklist app identifier=%s result=%d", identifier, blacklisted.boolValue);
    return blacklisted.boolValue;
}

static bool isBlacklistedPathOrig(const char* path)
{
    if(!path) return false;
    NSString* identifier = getAppIdentifierFromPath(path);
    if(!identifier) return false;
    return isBlacklistedApp(identifier.UTF8String);
}

static BOOL isWantsBlacklist(NSString *execName)
{
    return rootHideDictionaryHasEnabledKey(kRootHideInjectWantsBlacklistRelativePath, execName);
}

static bool isBlacklistedExec(const char *path)
{
    const char *exec = strrchr(path, '/');
    if (!exec) return true;
    exec++;

    if (isWantsBlacklist([NSString stringWithUTF8String:exec]) && isBlacklistedPathOrig(path)) {
        if (RootHideShouldTracePath(path)) {
            RootHideTraceLog(@"blacklist exec path=%s exec=%s result=1 reason=wantsblacklist", path, exec);
        }
        return true;
    }

    if (rootHideDictionaryHasEnabledKey(kRootHideInjectRelativePath, @(exec))) {
        if (RootHideShouldTracePath(path)) {
            RootHideTraceLog(@"blacklist exec path=%s exec=%s result=0 reason=allowlisted", path, exec);
        }
        return false;
    }

    if (RootHideShouldTracePath(path)) {
        RootHideTraceLog(@"blacklist exec path=%s exec=%s result=1 reason=default", path, exec);
    }
    return true;
}

bool isBlacklistedPath(const char* path)
{
	if(!path) return false;

    NSString *mode = rootHideInjectionMode();
    if ([mode isEqualToString:kRootHideInjectionModeHiddenWhitelist]) {
        // Hidden whitelist keeps the classic RootHide hidden-app semantics.
        // Injection is separately gated by the executable allowlist at spawn time.
        bool result = isBlacklistedPathOrig(path);
        if (RootHideShouldTracePath(path)) {
            RootHideTraceLog(@"blacklist path=%s mode=%@ result=%d reason=hiddenwhitelist-orig", path, mode, result);
        }
        return result;
    }

    if ([mode isEqualToString:kRootHideInjectionModeWhitelist]) {
        if (!strcmp(path, "/sbin/launchd")) {
            RootHideTraceLog(@"blacklist path=%s mode=%@ result=0 reason=launchd", path, mode);
            return false;
        }
        if (rootHideDictionaryContainsEnabledSubstring(kRootHideInjectSystemRelativePath, path)) {
            if (RootHideShouldTracePath(path)) {
                RootHideTraceLog(@"blacklist path=%s mode=%@ result=0 reason=system-allowlist", path, mode);
            }
            return false;
        }
        bool result = isBlacklistedExec(path);
        if (RootHideShouldTracePath(path)) {
            RootHideTraceLog(@"blacklist path=%s mode=%@ result=%d reason=whitelist-exec", path, mode, result);
        }
        return result;
    }

    bool result = isBlacklistedPathOrig(path);
    if (RootHideShouldTracePath(path)) {
        RootHideTraceLog(@"blacklist path=%s mode=%@ result=%d reason=orig", path, mode, result);
    }
    return result;
}
