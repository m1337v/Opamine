#!/usr/bin/env python3
"""Compile the production NSString version category and check its ordering."""

from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
EXTENSIONS = ROOT / "Extensions"
IMPLEMENTATION = EXTENSIONS / "NSString+Version.m"
HEADER = EXTENSIONS / "NSString+Version.h"


HARNESS = r'''#import <Foundation/Foundation.h>
#import "NSString+Version.h"

static void Require(BOOL condition, NSString *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message.UTF8String);
        exit(1);
    }
}

static void RequireGreater(NSString *left, NSString *right)
{
    Require([left numericalVersionRepresentation] > [right numericalVersionRepresentation],
            [NSString stringWithFormat:@"%@ should be newer than %@", left, right]);
}

static void RequireEqual(NSString *left, NSString *right)
{
    Require([left numericalVersionRepresentation] == [right numericalVersionRepresentation],
            [NSString stringWithFormat:@"%@ should equal %@", left, right]);
}

static void RequireZero(NSString *version)
{
    Require([version numericalVersionRepresentation] == 0,
            [NSString stringWithFormat:@"%@ should be rejected as zero", version]);
}

int main(void)
{
    RequireGreater(@"3.0.12-29", @"3.0.12-28+opamine1");
    RequireGreater(@"3.0.13-1", @"3.0.12-99");
    RequireEqual(@"3.0.12-28+opamine2", @"3.0.12-28+opamine1");
    RequireEqual(@"3.0.12", @"3.0.12-0");
    RequireEqual(@"3.0.12.28", @"3.0.12-28");

    RequireGreater(@"2.4.9.28", @"2.4.9.27");
    RequireGreater(@"2.4.10.1", @"2.4.9.99");
    RequireGreater(@"2.5.0.0", @"2.4.99.99");

    Require([@"32767.65535.65535.65535" numericalVersionRepresentation] == NSIntegerMax,
            @"the maximum supported tuple should remain positive NSIntegerMax");
    RequireZero(@"32768.0.0");
    RequireZero(@"3.0.12-65536");
    RequireZero(@"3.0.12.65536");
    RequireZero(@"3.0.12-999999999999999999999999999999999");
    RequireZero(@"3.0.12-abc");
    RequireZero(@"3..12");
    RequireZero(@"3.0.12.1.2");
    RequireZero(@"3.0.12+");
    RequireZero(@"3.0.12+opamine1+extra");
    RequireZero(nil);

    puts("NSString version ordering passed");
    return 0;
}
'''


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="version-ordering-") as directory:
        temp = Path(directory)
        harness = temp / "main.m"
        binary = temp / "version-ordering"
        harness.write_text(HARNESS, encoding="utf-8")

        compile_command = [
            "xcrun",
            "clang",
            "-fobjc-arc",
            "-framework",
            "Foundation",
            "-I",
            str(EXTENSIONS),
            str(IMPLEMENTATION),
            str(harness),
            "-o",
            str(binary),
        ]
        subprocess.run(compile_command, check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
