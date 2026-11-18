//
//  PreferenceManager.m
//  Dopamine
//
//  Created by Lars Fröder on 13.01.24.
//

#import "DOPreferenceManager.h"

@implementation DOPreferenceManager

+ (instancetype)sharedManager
{
    static DOPreferenceManager *preferenceManager;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        preferenceManager = [[DOPreferenceManager alloc] init];
    });
    return preferenceManager;
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        _preferencesPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Preferences/com.opa334.Dopamine-roothide.plist"];
        [self loadPreferences];
    }
    return self;
}

- (void)loadPreferences
{
    _preferences = [NSDictionary dictionaryWithContentsOfFile:_preferencesPath].mutableCopy ?: [NSMutableDictionary new];
}

- (void)savePreferences
{
    [_preferences writeToFile:_preferencesPath atomically:YES];
}

- (id)preferenceValueForKey:(NSString *)key
{
    return [_preferences objectForKey:key];
}

- (BOOL)boolPreferenceValueForKey:(NSString *)key fallback:(BOOL)fallback
{
    NSNumber *num = [self preferenceValueForKey:key];
    if (num) {
        return num.boolValue;
    }
    return fallback;
}

- (BOOL)setPreferenceValue:(NSObject *)obj forKey:(NSString *)key
{
    NSMutableDictionary *updated = [_preferences mutableCopy];
    updated[key] = obj;
    if (![updated writeToFile:_preferencesPath atomically:YES]) return NO;
    _preferences = updated;
    return YES;
}

- (BOOL)removePreferenceValueForKey:(NSString *)key
{
    return [self setPreferenceValue:nil forKey:key];
}

@end
