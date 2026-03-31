#import <Foundation/Foundation.h>

#include "../libjailbreak.h"
#include "common.h"

static NSString * const kRootHideInjectionModeStock = @"stock";
static NSString * const kRootHideInjectionModeBlacklist = @"blacklist";
static NSString * const kRootHideInjectionModeWhitelist = @"whitelist";
static NSString * const kRootHideModeRelativePath = @"/var/mobile/Library/RootHide/cn.zqbb.inject.mode.plist";
static NSString * const kRootHideInjectRelativePath = @"/var/mobile/Library/RootHide/cn.zqbb.inject.plist";
static NSString * const kRootHideInjectSystemRelativePath = @"/var/mobile/Library/RootHide/cn.zqbb.inject.system.plist";
static NSString * const kRootHideInjectWantsBlacklistRelativePath = @"/var/mobile/Library/RootHide/cn.zqbb.inject.wantsblacklist.plist";
static NSString * const kRootHideUninjectRelativePath = @"/var/mobile/Library/RootHide/cn.zqbb.uninject.plist";
static NSString * const kRootHideLegacyUninjectPath = @"/var/mobile/zp.unject.plist";

#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"
#define NULL_UUID "00000000-0000-0000-0000-000000000000"

static NSString *normalizedRootHideInjectionMode(NSString *mode)
{
    if ([mode isEqualToString:kRootHideInjectionModeBlacklist] || [mode isEqualToString:kRootHideInjectionModeWhitelist]) {
        return mode;
    }
    if ([mode isEqualToString:kRootHideInjectionModeStock]) {
        return mode;
    }
    return nil;
}

static NSArray<NSString *> *rootHideCandidatePaths(NSString *relativePath)
{
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    NSString *jbrootPath = JBROOT_PATH(relativePath);
    if (jbrootPath.length > 0) {
        [paths addObject:jbrootPath];
    }
    if (![paths containsObject:relativePath]) {
        [paths addObject:relativePath];
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
        return configuredMode;
    }

    if (rootHidePathExistsAtCandidatePaths(kRootHideInjectRelativePath)) {
        return kRootHideInjectionModeWhitelist;
    }

    if (rootHidePathExistsAtCandidatePaths(kRootHideUninjectRelativePath) || [[NSFileManager defaultManager] fileExistsAtPath:kRootHideLegacyUninjectPath]) {
        return kRootHideInjectionModeBlacklist;
    }

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

    if([builtinApps containsObject:@(identifier)]) return false;

    NSString* configFilePath = JBROOT_PATH(@"/var/mobile/Library/RootHide/RootHideConfig.plist");
    NSDictionary* roothideConfig = [NSDictionary dictionaryWithContentsOfFile:configFilePath];
    if(!roothideConfig) return false;

    NSDictionary* appconfig = roothideConfig[@"appconfig"];
    if(!appconfig) return false;

    NSNumber* blacklisted = appconfig[@(identifier)];
    if(!blacklisted) return false;

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
        return true;
    }

    if (rootHideDictionaryHasEnabledKey(kRootHideInjectRelativePath, @(exec))) {
        return false;
    }

    return true;
}

bool isBlacklistedPath(const char* path)
{
    if(!path) return false;

    if ([rootHideInjectionMode() isEqualToString:kRootHideInjectionModeWhitelist]) {
        if (!strcmp(path, "/sbin/launchd")) return false;
        if (rootHideDictionaryContainsEnabledSubstring(kRootHideInjectSystemRelativePath, path)) return false;
        return isBlacklistedExec(path);
    }

    return isBlacklistedPathOrig(path);
}
