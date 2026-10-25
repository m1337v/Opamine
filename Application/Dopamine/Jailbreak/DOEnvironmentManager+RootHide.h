//
//  DOEnvironmentManager+RootHide.h
//  Dopamine
//
//  RootHide's paired-root discovery and preparation are implemented by
//  DOBootstrapper.m. Keep their declarations in the matching category so a
//  primary-class compile cannot silently accept commented-out implementations.
//

#import "DOEnvironmentManager.h"

@interface DOEnvironmentManager (roothide)

- (void)locateJailbreakRoot;
- (NSError *)ensureJailbreakRootExists;

@end
