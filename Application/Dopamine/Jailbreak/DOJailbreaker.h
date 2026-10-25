//
//  Jailbreaker.h
//  Dopamine
//
//  Created by Lars Fröder on 10.01.24.
//

#import <Foundation/Foundation.h>

#import <xpc/xpc.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, DOJailbreakActivationPhase) {
    DOJailbreakActivationPhasePreInjection = 0,
    // Set immediately before the first opainject attempt. From this point a
    // partial launchd load is indistinguishable from a completed one to the
    // app, so retrying in the same boot is unsafe.
    DOJailbreakActivationPhaseLaunchdFirstLoad,
    DOJailbreakActivationPhaseFinalized,
    DOJailbreakActivationPhaseUserspaceRebooting,
};

FOUNDATION_EXPORT NSString * const DOJailbreakerErrorRequiresFullRebootKey;
FOUNDATION_EXPORT NSString * const DOJailbreakerErrorActivationPhaseKey;

@interface DOJailbreaker : NSObject
{
    xpc_object_t _systemInfoXdict;
}

@property (nonatomic, readonly) DOJailbreakActivationPhase activationPhase;

- (void)runWithError:(NSError **)errOut didRemoveJailbreak:(BOOL*)didRemove showLogs:(BOOL *)showLogs;
- (void)finalize;

- (BOOL)contiguousMappingWorkaroundNeeded;
- (void)applyContiguousMappingWorkaround;

@end

NS_ASSUME_NONNULL_END
