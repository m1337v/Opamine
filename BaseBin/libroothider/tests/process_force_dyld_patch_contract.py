#!/usr/bin/env python3
"""Host contract test for process_force_dyld_patch in common.m.

The test compiles the function body extracted from production source. Only
availability checks are substituted so the iOS major version can be selected
on the host; the path and argv decision logic remains production code.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path


def extract_function(source: str) -> str:
    signature = re.search(
        r"\bbool\s+process_force_dyld_patch\s*\([^)]*\)\s*\{", source
    )
    if signature is None:
        raise AssertionError("process_force_dyld_patch definition not found")

    opening_brace = source.find("{", signature.start(), signature.end())
    depth = 0
    state = "code"
    escaped = False
    index = opening_brace

    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""

        if state == "line_comment":
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if char == "*" and next_char == "/":
                state = "code"
                index += 1
        elif state in ("string", "character"):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (state == "string" and char == '"') or (
                state == "character" and char == "'"
            ):
                state = "code"
        elif char == "/" and next_char == "/":
            state = "line_comment"
            index += 1
        elif char == "/" and next_char == "*":
            state = "block_comment"
            index += 1
        elif char == '"':
            state = "string"
        elif char == "'":
            state = "character"
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[signature.start() : index + 1]

        index += 1

    raise AssertionError("unterminated process_force_dyld_patch definition")


def replace_availability_checks(function: str) -> str:
    for major in (16, 17):
        pattern = re.compile(
            rf"__builtin_available\s*\(\s*iOS\s+{major}\.0\s*,\s*\*\s*\)"
        )
        function, count = pattern.subn(
            f"test_ios_version_at_least({major})", function
        )
        if count != 1:
            raise AssertionError(
                f"expected one iOS {major}.0 availability check, found {count}"
            )
    if "__builtin_available" in function:
        raise AssertionError("unsubstituted availability check remains in function")
    return function


HARNESS = r'''#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static int test_ios_major;

static bool test_ios_version_at_least(int major)
{
    return test_ios_major >= major;
}

static bool string_has_prefix(const char *value, const char *prefix)
{
    return value != NULL && strncmp(value, prefix, strlen(prefix)) == 0;
}

static bool string_has_suffix(const char *value, const char *suffix)
{
    if (value == NULL) return false;
    size_t value_length = strlen(value);
    size_t suffix_length = strlen(suffix);
    return value_length >= suffix_length &&
           strcmp(value + value_length - suffix_length, suffix) == 0;
}

__PRODUCTION_FUNCTION__

static int check(const char *label, bool actual, bool expected)
{
    if (actual == expected) return 0;
    fprintf(stderr, "FAIL: %s: expected %s, got %s\n", label,
            expected ? "true" : "false", actual ? "true" : "false");
    return 1;
}

#define CHECK(label, expression, expected) \
    do { if (check(label, (expression), (expected))) return 1; } while (0)

int main(void)
{
    static const char *messages_airlock_path =
        "/System/Library/PrivateFrameworks/MessagesBlastDoorSupport.framework/"
        "XPCServices/MessagesAirlockService.xpc/MessagesAirlockService";
    static const char *webkit_content_path =
        "/System/Library/Frameworks/WebKit.framework/XPCServices/"
        "com.apple.WebKit.WebContent";
    static const char *webkit_captive_path =
        "/System/Library/Frameworks/WebKit.framework/XPCServices/"
        "com.apple.WebKit.WebContent.CaptivePortal";

    test_ios_major = 17;
    CHECK("MessagesAirlock direct on iOS 17",
          process_force_dyld_patch(messages_airlock_path, NULL), true);
    test_ios_major = 16;
    CHECK("MessagesAirlock direct on iOS 16",
          process_force_dyld_patch(messages_airlock_path, NULL), false);

    const char *messages_argv[] = {
        "xpcproxy", "com.apple.MessagesAirlockService.extension", NULL
    };
    test_ios_major = 17;
    CHECK("MessagesAirlock xpcproxy argv prefix on iOS 17",
          process_force_dyld_patch("/usr/libexec/xpcproxy", messages_argv), true);
    test_ios_major = 16;
    CHECK("MessagesAirlock xpcproxy argv prefix on iOS 16",
          process_force_dyld_patch("/usr/libexec/xpcproxy", messages_argv), false);

    test_ios_major = 16;
    CHECK("WebKit direct WebContent on iOS 16",
          process_force_dyld_patch(webkit_content_path, NULL), true);
    CHECK("WebKit direct CaptivePortal on iOS 16",
          process_force_dyld_patch(webkit_captive_path, NULL), true);
    test_ios_major = 15;
    CHECK("WebKit direct WebContent on iOS 15",
          process_force_dyld_patch(webkit_content_path, NULL), false);
    CHECK("WebKit direct CaptivePortal on iOS 15",
          process_force_dyld_patch(webkit_captive_path, NULL), false);

    const char *webkit_content_argv[] = {
        "xpcproxy", "com.apple.WebKit.WebContent", NULL
    };
    const char *webkit_captive_argv[] = {
        "xpcproxy", "com.apple.WebKit.WebContent.CaptivePortal", NULL
    };
    test_ios_major = 16;
    CHECK("WebKit xpcproxy WebContent on iOS 16",
          process_force_dyld_patch("/usr/libexec/xpcproxy", webkit_content_argv), true);
    CHECK("WebKit xpcproxy CaptivePortal on iOS 16",
          process_force_dyld_patch("/usr/libexec/xpcproxy", webkit_captive_argv), true);
    test_ios_major = 15;
    CHECK("WebKit xpcproxy WebContent on iOS 15",
          process_force_dyld_patch("/usr/libexec/xpcproxy", webkit_content_argv), false);
    CHECK("WebKit xpcproxy CaptivePortal on iOS 15",
          process_force_dyld_patch("/usr/libexec/xpcproxy", webkit_captive_argv), false);

    const char *unrelated_argv[] = {"xpcproxy", "com.example.Unrelated", NULL};
    test_ios_major = 17;
    CHECK("unrelated executable path",
          process_force_dyld_patch("/usr/bin/unrelated", unrelated_argv), false);
    CHECK("unrelated xpcproxy process",
          process_force_dyld_patch("/usr/libexec/xpcproxy", unrelated_argv), false);

    CHECK("xpcproxy with NULL argv",
          process_force_dyld_patch("/usr/libexec/xpcproxy", NULL), false);
    const char *argv_with_null_first[] = {NULL};
    CHECK("xpcproxy with short argv and NULL argv[0]",
          process_force_dyld_patch("/usr/libexec/xpcproxy", argv_with_null_first), false);
    const char *argv_with_null_second[] = {"xpcproxy", NULL};
    CHECK("xpcproxy with short argv and NULL argv[1]",
          process_force_dyld_patch("/usr/libexec/xpcproxy", argv_with_null_second), false);

    CHECK("both path and argv NULL",
          process_force_dyld_patch(NULL, NULL), false);

    puts("PASS: process_force_dyld_patch production contract (18 checks)");
    return 0;
}
'''


def main() -> int:
    repo_root = Path(__file__).resolve().parents[3]
    source_path = repo_root / "BaseBin/libroothider/src/common.m"
    source = source_path.read_text(encoding="utf-8")
    function = replace_availability_checks(extract_function(source))
    harness = HARNESS.replace("__PRODUCTION_FUNCTION__", function)

    clang = shutil.which("clang")
    if clang is None:
        raise SystemExit("clang not found on PATH")

    with tempfile.TemporaryDirectory(prefix="process-force-dyld-patch-") as tmp:
        tmp_path = Path(tmp)
        c_path = tmp_path / "contract.c"
        executable = tmp_path / "contract"
        c_path.write_text(harness, encoding="utf-8")

        subprocess.run(
            [
                clang,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(c_path),
                "-o",
                str(executable),
            ],
            check=True,
        )
        subprocess.run([str(executable)], check=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
