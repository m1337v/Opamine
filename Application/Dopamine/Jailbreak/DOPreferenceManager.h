//
//  PreferenceManager.h
//  Dopamine
//
//  Created by Lars Fröder on 13.01.24.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DOPreferenceManager : NSObject
{
    NSString *_preferencesPath;
    NSMutableDictionary *_preferences;
}

+ (instancetype)sharedManager;

- (id)preferenceValueForKey:(NSString *)key;
- (BOOL)boolPreferenceValueForKey:(NSString *)key fallback:(BOOL)fallback;

- (BOOL)setPreferenceValue:(NSObject * _Nullable)obj forKey:(NSString *)key;
- (BOOL)removePreferenceValueForKey:(NSString *)key;

@end

NS_ASSUME_NONNULL_END
