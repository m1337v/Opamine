#!/usr/bin/env python3
"""Compile the production posix_spawn wrapper against small host stubs."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "BaseBin/systemhook/src/common/common.c"


def extract_function(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    state = "code"
    escaped = False
    index = opening

    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""

        if state == "line_comment":
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if char == "*" and following == "/":
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
        else:
            if char == "/" and following == "/":
                state = "line_comment"
                index += 1
            elif char == "/" and following == "*":
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
                    return source[start : index + 1]

        index += 1

    raise ValueError(f"unterminated function beginning with {marker!r}")


HARNESS_PREFIX = r"""
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#define POSIX_SPAWN_START_SUSPENDED 0x0080
#define POSIX_SPAWN_SETEXEC 0x0040
#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 0x0001
#define POSIX_SPAWN_PERSONA_UID 0x00010000
#define POSIX_SPAWN_PERSONA_GID 0x00020000
#define POSIX_SPAWNATTR_OFF_PERSONA 0xD8
#define SIGKILL 9
#define SIGCONT 18

typedef struct fake_spawnattr *posix_spawnattr_t;
struct fake_spawnattr {
	uint8_t bytes[0x100];
	short flags;
};

struct _posix_spawn_persona_info {
	uid_t pspi_id;
	uint32_t pspi_flags;
	uid_t pspi_uid;
	gid_t pspi_gid;
	uint32_t pspi_ngroups;
	gid_t pspi_groups[16];
	uid_t pspi_gmuid;
};

struct _posix_spawn_args_desc {
	posix_spawnattr_t attrp;
};

static struct fake_spawnattr g_attr;
static struct _posix_spawn_args_desc g_desc;
static struct _posix_spawn_persona_info g_persona;
static bool g_has_persona;
static int g_common_calls;
static int g_orig_calls;
static int g_fix_calls;
static int g_kill_calls;
static int g_debug_calls;
static bool g_common_early_return;
static int g_spawn_result;
static int g_fix_result;
static pid_t g_configured_child_pid;
static pid_t g_fix_pid;
static uid_t g_fix_uid;
static gid_t g_fix_gid;
static bool g_orig_received_pid;
static uid_t g_spawn_seen_uid;
static gid_t g_spawn_seen_gid;
static short g_spawn_seen_flags;
static int g_last_kill_signal;
static int g_events[8];
static int g_event_count;

enum { EVENT_FIX = 1, EVENT_CONTINUE, EVENT_KILL };

static void record_event(int event)
{
	if (g_event_count < (int)(sizeof(g_events) / sizeof(g_events[0]))) {
		g_events[g_event_count++] = event;
	}
}

static int event_index(int event)
{
	for (int i = 0; i < g_event_count; i++) {
		if (g_events[i] == event) return i;
	}
	return -1;
}

int getuid(void)
{
	return 501;
}

int posix_spawnattr_getflags(const posix_spawnattr_t *restrict attr, short *restrict flags)
{
	if (!attr || !*attr || !flags) return EINVAL;
	*flags = (*attr)->flags;
	return 0;
}

int posix_spawnattr_setflags(posix_spawnattr_t *restrict attr, short flags)
{
	if (!attr || !*attr) return EINVAL;
	(*attr)->flags = flags;
	return 0;
}

int jbclient_persona_fix(int childPid, uid_t overwriteUid, gid_t overwriteGid)
{
	g_fix_calls++;
	g_fix_pid = childPid;
	g_fix_uid = overwriteUid;
	g_fix_gid = overwriteGid;
	record_event(EVENT_FIX);
	return g_fix_result;
}

int kill(pid_t pid, int signal)
{
	(void)pid;
	g_kill_calls++;
	g_last_kill_signal = signal;
	record_event(signal == SIGCONT ? EVENT_CONTINUE : EVENT_KILL);
	return 0;
}

static int set_process_debugged_stub(uint64_t pid, bool fullyDebugged)
{
	(void)pid;
	(void)fullyDebugged;
	g_debug_calls++;
	return 0;
}

static int trust_binary_stub(const char *path)
{
	(void)path;
	return 0;
}

static int posix_spawn_orig_stub(pid_t *restrict pid,
								 const char *restrict path,
								 struct _posix_spawn_args_desc *desc,
								 char *const argv[restrict],
								 char *const envp[restrict])
{
	(void)path;
	(void)argv;
	(void)envp;
	(void)desc;
	g_orig_calls++;
	g_orig_received_pid = pid != NULL;
	g_spawn_seen_flags = g_attr.flags;
	if (g_has_persona) {
		g_spawn_seen_uid = g_persona.pspi_uid;
		g_spawn_seen_gid = g_persona.pspi_gid;
	}
	if (g_spawn_result == 0 && pid) *pid = g_configured_child_pid;
	return g_spawn_result;
}

static int spawn_exec_hook_common(const char *path,
								  char *const argv[restrict],
								  char *const envp[restrict],
								  struct _posix_spawn_args_desc *desc,
								  int (*trust_binary)(const char *path),
								  double jetsamMultiplier,
								  int mutationErrorReturn,
								  int (^orig)(char *const envp_patched[restrict]))
{
	(void)path;
	(void)argv;
	(void)desc;
	(void)trust_binary;
	(void)jetsamMultiplier;
	g_common_calls++;
	if (mutationErrorReturn != ENOMEM) return EINVAL;
	if (g_has_persona) {
		g_spawn_seen_uid = g_persona.pspi_uid;
		g_spawn_seen_gid = g_persona.pspi_gid;
	}
	g_spawn_seen_flags = g_attr.flags;
	if (g_common_early_return) return mutationErrorReturn;
	return orig(envp);
}

int posix_spawn_hook_shared(pid_t *restrict pid,
						   const char *restrict path,
						   struct _posix_spawn_args_desc *desc,
						   char *const argv[restrict],
						   char *const envp[restrict],
						   void *orig,
						   int (*trust_binary)(const char *path),
						   int (*set_process_debugged)(uint64_t pid, bool fullyDebugged),
						   double jetsamMultiplier);

static void reset_case(short flags, bool persona, bool earlyReturn)
{
	memset(&g_attr, 0, sizeof(g_attr));
	memset(&g_persona, 0, sizeof(g_persona));
	g_attr.flags = flags;
	g_desc.attrp = &g_attr;
	g_has_persona = persona;
	if (persona) {
		g_persona.pspi_id = 99;
		g_persona.pspi_flags = POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE |
			POSIX_SPAWN_PERSONA_UID | POSIX_SPAWN_PERSONA_GID;
		g_persona.pspi_uid = 0;
		g_persona.pspi_gid = 0;
		struct _posix_spawn_persona_info *personaPointer = &g_persona;
		memcpy(g_attr.bytes + POSIX_SPAWNATTR_OFF_PERSONA,
		       &personaPointer, sizeof(personaPointer));
	}
	g_common_calls = 0;
	g_orig_calls = 0;
	g_fix_calls = 0;
	g_kill_calls = 0;
	g_debug_calls = 0;
	g_common_early_return = earlyReturn;
	g_spawn_result = 0;
	g_fix_result = 0;
	g_configured_child_pid = 4321;
	g_fix_pid = -1;
	g_fix_uid = (uid_t)-1;
	g_fix_gid = (gid_t)-1;
	g_orig_received_pid = false;
	g_spawn_seen_uid = (uid_t)-1;
	g_spawn_seen_gid = (gid_t)-1;
	g_spawn_seen_flags = 0;
	g_last_kill_signal = 0;
	g_event_count = 0;
	memset(g_events, 0, sizeof(g_events));
}

static int run_spawn(pid_t *pid)
{
	char *argv[] = { (char *)"child", NULL };
	char *envp[] = { NULL };
	return posix_spawn_hook_shared(pid, "/bin/child", &g_desc, argv, envp,
								   (void *)posix_spawn_orig_stub,
								   trust_binary_stub,
								   set_process_debugged_stub, 3.0);
}

static int require(bool condition, const char *message)
{
	if (!condition) fprintf(stderr, "FAIL: %s\n", message);
	return condition ? 0 : 1;
}

static int require_restored(short flags, bool persona)
{
	if (require(g_attr.flags == flags, "original spawn flags were not restored")) return 1;
	if (persona &&
	    (require(g_persona.pspi_uid == 0, "original persona UID was not restored") ||
	     require(g_persona.pspi_gid == 0, "original persona GID was not restored"))) return 1;
	return 0;
}
"""


HARNESS_SUFFIX = r"""
static int test_failed_spawn_does_not_fix_or_resume(void)
{
	reset_case(0, true, false);
	g_spawn_result = ENOENT;
	pid_t callerPid = 77;
	int result = run_spawn(&callerPid);
	if (require(result == ENOENT, "failed spawn result was changed") ||
	    require(g_common_calls == 1, "custom spawn function was bypassed") ||
	    require(g_orig_calls == 1, "original spawn was not called") ||
	    require(g_orig_received_pid, "wrapper did not provide storage for the child PID") ||
	    require(g_spawn_seen_uid == 501 && g_spawn_seen_gid == 501,
	            "root persona was not temporarily reduced during spawn") ||
	    require((g_spawn_seen_flags & POSIX_SPAWN_START_SUSPENDED) != 0,
	            "root persona spawn was not suspended") ||
	    require(g_fix_calls == 0, "failed spawn attempted persona repair") ||
	    require(g_kill_calls == 0, "failed spawn signaled an invalid child PID") ||
	    require(g_event_count == 0, "failed spawn emitted fix or resume events") ||
	    require(callerPid == 77, "failed spawn overwrote caller PID")) return 1;
	return require_restored(0, true);
}

static int test_null_caller_pid_uses_spawned_child(void)
{
	reset_case(0, true, false);
	int result = run_spawn(NULL);
	if (require(result == 0, "NULL-pid spawn failed") ||
	    require(g_common_calls == 1, "custom spawn function was bypassed") ||
	    require(g_orig_calls == 1, "original spawn was not called") ||
	    require(g_orig_received_pid, "NULL-pid call did not use local PID storage") ||
	    require(g_fix_calls == 1 && g_fix_pid == 4321,
	            "persona repair did not receive the spawned PID") ||
	    require(g_fix_uid == 0 && g_fix_gid == 0,
	            "persona repair did not receive the requested root IDs") ||
	    require(g_kill_calls == 1 && g_last_kill_signal == SIGCONT,
	            "successful forced-suspended spawn was not resumed") ||
	    require(event_index(EVENT_FIX) >= 0 &&
	            event_index(EVENT_FIX) < event_index(EVENT_CONTINUE),
	            "child resumed before persona repair succeeded")) return 1;
	return require_restored(0, true);
}

static int test_persona_fix_failure_kills_child(void)
{
	reset_case(0, true, false);
	g_fix_result = EPERM;
	pid_t callerPid = 77;
	int result = run_spawn(&callerPid);
	if (require(result == EPERM, "persona fix failure was not returned") ||
	    require(g_common_calls == 1, "custom spawn function was bypassed") ||
	    require(g_fix_calls == 1 && g_fix_pid == 4321,
	            "persona repair did not receive the spawned PID") ||
	    require(g_kill_calls == 1 && g_last_kill_signal == SIGKILL,
	            "child was not killed after persona repair failed") ||
	    require(event_index(EVENT_CONTINUE) < 0,
	            "child resumed after persona repair failed") ||
	    require(callerPid == 77, "failed wrapper result overwrote caller PID")) return 1;
	return require_restored(0, true);
}

static int test_caller_suspended_child_stays_suspended(void)
{
	reset_case(POSIX_SPAWN_START_SUSPENDED, true, false);
	pid_t callerPid = -1;
	int result = run_spawn(&callerPid);
	if (require(result == 0, "caller-suspended spawn failed") ||
	    require(g_common_calls == 1, "custom spawn function was bypassed") ||
	    require(g_fix_calls == 1 && g_fix_pid == 4321,
	            "suspended child was not repaired") ||
	    require(g_spawn_seen_uid == 501 && g_spawn_seen_gid == 501,
	            "persona was not temporarily reduced during suspended spawn") ||
	    require((g_spawn_seen_flags & POSIX_SPAWN_START_SUSPENDED) != 0,
	            "caller's suspended flag was not preserved") ||
	    require(event_index(EVENT_CONTINUE) < 0,
	            "wrapper resumed a child the caller requested suspended") ||
	    require(g_debug_calls == 1, "suspended-child debug setup was skipped") ||
	    require(callerPid == 4321, "successful spawn PID was not returned")) return 1;
	return require_restored(POSIX_SPAWN_START_SUSPENDED, true);
}

static int test_enomem_restores_attributes_before_return(void)
{
	reset_case(0, true, true);
	pid_t callerPid = 77;
	int result = run_spawn(&callerPid);
	if (require(result == ENOMEM, "custom ENOMEM result was changed") ||
	    require(g_common_calls == 1, "custom spawn function was bypassed") ||
	    require(g_orig_calls == 0, "original spawn ran after custom ENOMEM") ||
	    require(g_spawn_seen_uid == 501 && g_spawn_seen_gid == 501,
	            "environment error did not occur after persona substitution") ||
	    require((g_spawn_seen_flags & POSIX_SPAWN_START_SUSPENDED) != 0,
	            "environment error did not occur after forced suspension") ||
	    require(g_fix_calls == 0 && g_kill_calls == 0,
	            "environment allocation error attempted child operations") ||
	    require(callerPid == 77, "environment error overwrote caller PID")) return 1;
	return require_restored(0, true);
}

static int test_success_returns_caller_pid(void)
{
	reset_case(0, false, false);
	pid_t callerPid = -1;
	int result = run_spawn(&callerPid);
	if (require(result == 0, "ordinary spawn failed") ||
	    require(g_common_calls == 1, "custom spawn function was bypassed") ||
	    require(g_orig_calls == 1 && g_orig_received_pid,
	            "original spawn did not receive local PID storage") ||
	    require(callerPid == 4321, "spawned PID was not copied to caller") ||
	    require(g_fix_calls == 0 && g_kill_calls == 0,
	            "ordinary spawn received persona operations")) return 1;
	return require_restored(0, false);
}

int main(void)
{
	if (test_failed_spawn_does_not_fix_or_resume() ||
	    test_null_caller_pid_uses_spawned_child() ||
	    test_persona_fix_failure_kills_child() ||
	    test_caller_suspended_child_stays_suspended() ||
	    test_enomem_restores_attributes_before_return() ||
	    test_success_returns_caller_pid()) return 1;
	puts("persona_spawn_contract: PASS (production wrapper compiled and exercised)");
	return 0;
}
"""


def main() -> int:
    compiler = shutil.which("clang")
    if compiler is None:
        raise RuntimeError("clang is required to compile the production wrapper harness")

    source = SOURCE.read_text(encoding="utf-8")
    wrapper = extract_function(source, "int posix_spawn_hook_shared(")
    availability = "__builtin_available(iOS 17.6, *)"
    if wrapper.count(availability) != 1:
        raise AssertionError("expected one iOS availability check in production wrapper")
    # The host harness fixes platform availability to true while retaining the
    # exact extracted wrapper and its control flow.
    wrapper = wrapper.replace(availability, "true")

    with tempfile.TemporaryDirectory(prefix="persona-spawn-contract-") as directory:
        harness_path = Path(directory) / "persona_spawn_contract.c"
        executable_path = Path(directory) / "persona_spawn_contract"
        harness_path.write_text(HARNESS_PREFIX + wrapper + HARNESS_SUFFIX, encoding="utf-8")
        subprocess.run(
            [
                compiler,
                "-std=c11",
                "-fblocks",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wno-unused-parameter",
                str(harness_path),
                "-o",
                str(executable_path),
            ],
            check=True,
        )
        subprocess.run([str(executable_path)], check=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
