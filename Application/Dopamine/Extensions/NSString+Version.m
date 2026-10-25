//
//  NSString+Version.h
//  Dopamine
//
//  Created by Lars Fröder on 12.06.24.
//

#import <Foundation/Foundation.h>
#include <stdint.h>

static BOOL ParseVersionNumber(NSString *string, NSUInteger *index, NSUInteger end, uint32_t maximum, uint32_t *result)
{
    NSUInteger start = *index;
    uint32_t value = 0;
    while (*index < end) {
        unichar character = [string characterAtIndex:*index];
        if (character < '0' || character > '9')
            break;

        uint32_t digit = (uint32_t)(character - '0');
        if (value > (maximum - digit) / 10)
            return NO;
        value = value * 10 + digit;
        (*index)++;
    }

    if (*index == start)
        return NO;

    *result = value;
    return YES;
}

static BOOL IsValidForkSuffix(NSString *string, NSUInteger start)
{
    if (start >= string.length)
        return NO;

    for (NSUInteger index = start; index < string.length; index++) {
        unichar character = [string characterAtIndex:index];
        BOOL isDigit = character >= '0' && character <= '9';
        BOOL isLowercase = character >= 'a' && character <= 'z';
        BOOL isUppercase = character >= 'A' && character <= 'Z';
        if (!isDigit && !isLowercase && !isUppercase && character != '.' && character != '-' && character != '_')
            return NO;
    }
    return YES;
}

@implementation NSString (Version)

- (NSInteger)numericalVersionRepresentation
{
    NSUInteger end = self.length;
    NSRange suffixMarker = [self rangeOfString:@"+"];
    if (suffixMarker.location != NSNotFound) {
        if (!IsValidForkSuffix(self, suffixMarker.location + 1))
            return 0;
        end = suffixMarker.location;
    }

    uint32_t components[4] = { 0, 0, 0, 0 };
    NSUInteger componentCount = 0;
    NSUInteger index = 0;
    BOOL hasHyphenRevision = NO;
    while (index < end) {
        if (componentCount >= 4)
            return 0;

        uint32_t maximum = componentCount == 0 ? 32767 : 65535;
        if (!ParseVersionNumber(self, &index, end, maximum, &components[componentCount]))
            return 0;
        componentCount++;

        if (index == end)
            break;

        unichar delimiter = [self characterAtIndex:index++];
        if (delimiter == '.') {
            if (hasHyphenRevision || componentCount >= 4)
                return 0;
        } else if (delimiter == '-') {
            if (hasHyphenRevision || componentCount != 3)
                return 0;
            hasHyphenRevision = YES;
        } else {
            return 0;
        }

        if (index == end)
            return 0;
    }

    if (componentCount != 3 && componentCount != 4)
        return 0;

    // Four unsigned 16-bit fields occupy a positive 63-bit NSInteger. The
    // major component is limited to 15 bits so the sign bit always stays clear.
    uint64_t representation = ((uint64_t)components[0] << 48)
                            | ((uint64_t)components[1] << 32)
                            | ((uint64_t)components[2] << 16)
                            | (uint64_t)components[3];
    return (NSInteger)representation;
}

@end
