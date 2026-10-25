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
    DOJailbreakActivationPhaseLaunchdFirstLoad,
    DOJailbreakActivationPhaseFinalized,
    DOJailbreakActivationPhaseUserspaceRebooting,
};

// Errors raised after launchd has entered first-load mode cannot be retried in
// this boot. The launchd hook deliberately rejects a new Dopamine process
// until a full device reboot has restored a known-good state.
FOUNDATION_EXPORT NSString * const DOJailbreakerErrorRequiresFullRebootKey;
FOUNDATION_EXPORT NSString * const DOJailbreakerErrorActivationPhaseKey;

@interface DOJailbreaker : NSObject
{
    xpc_object_t _systemInfoXdict;
}

@property (nonatomic, readonly) DOJailbreakActivationPhase activationPhase;

- (void)runWithError:(NSError **)errOut didRemoveJailbreak:(BOOL*)didRemove showLogs:(BOOL *)showLogs;
- (void)finalize;

// Some exploits require a PurpleGfxMem mapping before they can start. The
// caller must apply the workaround before beginning exploitation when this is
// true; a non-nil error means no surface port was preserved.
- (BOOL)contiguousMappingWorkaroundNeeded;
- (NSError * _Nullable)applyContiguousMappingWorkaround;

@end

NS_ASSUME_NONNULL_END
