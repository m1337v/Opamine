//
//  EnvironmentManager.h
//  Dopamine
//
//  Created by Lars Fröder on 10.01.24.
//

#import <Foundation/Foundation.h>
#import "DOBootstrapper.h"

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSString * const DORootHideInjectionModeStock;
FOUNDATION_EXPORT NSString * const DORootHideInjectionModeBlacklist;
FOUNDATION_EXPORT NSString * const DORootHideInjectionModeWhitelist;
FOUNDATION_EXPORT NSString * const DORootHideInjectionModeHiddenWhitelist;
FOUNDATION_EXPORT NSString * const DORootHideInjectionModeBlacklistAllowlist;

@interface DOEnvironmentManager : NSObject
{
    DOBootstrapper *_bootstrapper;
    BOOL _bootstrapNeedsMigration;
}

+ (instancetype)sharedManager;

@property (nonatomic, readonly) NSData *bootManifestHash;

- (NSString *)appVersion;
- (NSString *)appVersionDisplayString;
- (NSString *)nightlyHash;

- (BOOL)isInstalledThroughTrollStore;
- (BOOL)isJailbroken;
- (BOOL)isBootstrapped;
- (NSString *)jailbrokenVersion;
- (NSString *)jailbrokenBasebinMD5;
- (NSString *)launchedBasebinMD5;
- (NSString *)jailbrokenBuildID;
- (NSString *)launchedBuildID;

- (BOOL)isSupported;
- (BOOL)isArm64e;
- (NSString *)versionSupportString;
- (NSString *)accessibleKernelPath;
- (void)locateJailbreakRoot;
- (NSError *)ensureJailbreakRootExists;


- (void)runUnsandboxed:(void (^)(void))unsandboxBlock;
- (void)runAsRoot:(void (^)(void))rootBlock;

- (void)respring;
- (void)rebootUserspace;
- (void)refreshJailbreakApps;
- (void)reboot;
- (void)changeMobilePassword:(NSString *)newPassword;
- (NSError*)updateEnvironment;
- (void)updateJailbreakFromTIPA:(NSString *)tipaPath;

- (BOOL)isTweakInjectionEnabled;
- (void)setTweakInjectionEnabled:(BOOL)enabled;
- (NSString *)configuredTweakInjectionMode;
- (void)syncRootHideInjectionSettingsNeedsUnsandbox:(BOOL)needsUnsandbox;
- (BOOL)isIDownloadEnabled;
- (void)setIDownloadEnabled:(BOOL)enabled needsUnsandbox:(BOOL)needsUnsandbox;
- (void)setIDownloadLoaded:(BOOL)loaded needsUnsandbox:(BOOL)needsUnsandbox;
/*
- (BOOL)isFakelibMounted;
- (int)setFakelibMounted:(BOOL)mounted;
- (int)setPrivatePrebootProtected:(BOOL)protected;
- (BOOL)isJailbreakHidden;
- (void)setJailbreakHidden:(BOOL)hidden;
*/

- (BOOL)isPACBypassRequired;
- (BOOL)isPPLBypassRequired;

- (NSError *)prepareBootstrap;
- (NSError *)finalizeBootstrap;
- (NSError *)deleteBootstrap;
- (NSError *)reinstallPackageManagers;
- (NSError *)updateBootLogo;
@end

NS_ASSUME_NONNULL_END
