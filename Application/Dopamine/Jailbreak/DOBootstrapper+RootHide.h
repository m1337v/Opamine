//
//  DOBootstrapper+RootHide.h
//  Dopamine
//
//  RootHide owns the live bootstrap transaction in DOBootstrapper.m's
//  `roothide` category. Keeping this API separate prevents the primary class
//  from advertising selectors that exist only in disabled legacy code.
//

#import "DOBootstrapper.h"

@interface DOBootstrapper (roothide)

- (void)prepareBootstrapWithCompletion:(void (^)(NSError *))completion;
- (NSError *)finalizeBootstrap;
- (NSError *)deleteBootstrap;

@end
