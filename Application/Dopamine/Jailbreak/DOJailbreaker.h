//
//  Jailbreaker.h
//  Dopamine
//
//  Created by Lars Fröder on 10.01.24.
//

#import <Foundation/Foundation.h>

#import <xpc/xpc.h>

NS_ASSUME_NONNULL_BEGIN

@interface DOJailbreaker : NSObject
{
    xpc_object_t _systemInfoXdict;
}

- (void)runWithError:(NSError **)errOut didRemoveJailbreak:(BOOL*)didRemove showLogs:(BOOL *)showLogs;
- (void)finalize;

// Some exploits require a PurpleGfxMem mapping before they can start. The
// caller must apply the workaround before beginning exploitation when this is
// true; a non-nil error means no surface port was preserved.
- (BOOL)contiguousMappingWorkaroundNeeded;
- (NSError * _Nullable)applyContiguousMappingWorkaround;

@end

NS_ASSUME_NONNULL_END
