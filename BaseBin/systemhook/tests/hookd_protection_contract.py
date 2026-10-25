#!/usr/bin/env python3
"""Compile production hookd protection code against host Mach VM stubs."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "BaseBin/hookd/src/main.c"


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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef int32_t kern_return_t;
typedef uint32_t mach_port_t;
typedef uint32_t natural_t;
typedef uint32_t mach_msg_type_number_t;
typedef uint64_t mach_vm_address_t;
typedef uint64_t mach_vm_size_t;
typedef uint64_t vm_address_t;
typedef uint64_t vm_size_t;
typedef uint64_t vm_offset_t;
typedef int32_t vm_prot_t;

typedef struct {
	bool is_submap;
	vm_prot_t protection;
} vm_region_submap_info_data_64_t;
typedef vm_region_submap_info_data_64_t *vm_region_recurse_info_t;

int apply_hook(mach_port_t clientTaskPort, mach_port_t taskPortInClient,
			   vm_address_t vmaddr, const void *data, vm_size_t size);

#define KERN_SUCCESS 0
#define KERN_INVALID_ADDRESS 1
#define KERN_INVALID_ARGUMENT 2
#define KERN_FAILURE 5
#define MACH_PORT_NULL 0
#define MACH_PORT_RIGHT_SEND 0
#define VM_PROT_NONE 0
#define VM_PROT_READ 1
#define VM_PROT_WRITE 2
#define VM_PROT_EXECUTE 4
#define VM_PROT_COPY 16
#define VM_REGION_SUBMAP_INFO_COUNT_64 8
#define MACH_PORT_VALID(port) ((port) != MACH_PORT_NULL && (port) != (mach_port_t)-1)

enum { EVENT_LOOKUP = 1, EVENT_TEMP_PROTECT, EVENT_WRITE, EVENT_RESTORE_PROTECT };

static kern_return_t g_lookup_result;
static kern_return_t g_temp_protect_result;
static kern_return_t g_restore_result;
static kern_return_t g_write_result;
static vm_address_t g_region_base;
static vm_size_t g_region_size;
static vm_prot_t g_region_protection;
static int g_lookup_calls;
static int g_protect_calls;
static int g_write_calls;
static int g_mod_refs_calls;
static vm_address_t g_protect_addresses[2];
static vm_size_t g_protect_sizes[2];
static vm_prot_t g_protections[2];
static bool g_set_maximum[2];
static int g_events[8];
static int g_event_count;

static void record_event(int event)
{
	if (g_event_count < (int)(sizeof(g_events) / sizeof(g_events[0]))) {
		g_events[g_event_count++] = event;
	}
}

mach_port_t mach_task_self(void)
{
	return 1;
}

mach_port_t extract_task_port(mach_port_t client_task_port, mach_port_t caller_port)
{
	(void)client_task_port;
	(void)caller_port;
	return 42;
}

kern_return_t mach_vm_region_recurse(mach_port_t task,
									 mach_vm_address_t *address,
									 mach_vm_size_t *size,
									 natural_t *depth,
									 vm_region_recurse_info_t info,
									 mach_msg_type_number_t *count)
{
	(void)task;
	(void)depth;
	(void)count;
	g_lookup_calls++;
	record_event(EVENT_LOOKUP);
	if (g_lookup_result != KERN_SUCCESS) return g_lookup_result;
	*address = g_region_base;
	*size = g_region_size;
	info->is_submap = false;
	info->protection = g_region_protection;
	return KERN_SUCCESS;
}

kern_return_t vm_protect(mach_port_t task, vm_address_t address, vm_size_t size,
						 bool set_maximum, vm_prot_t protection)
{
	(void)task;
	int index = g_protect_calls++;
	if (index < 2) {
		g_protect_addresses[index] = address;
		g_protect_sizes[index] = size;
		g_protections[index] = protection;
		g_set_maximum[index] = set_maximum;
	}
	if (index == 0) {
		record_event(EVENT_TEMP_PROTECT);
		return g_temp_protect_result;
	}
	record_event(EVENT_RESTORE_PROTECT);
	return g_restore_result;
}

kern_return_t vm_write(mach_port_t task, vm_address_t address,
					   vm_offset_t data, uint32_t size)
{
	(void)task;
	(void)address;
	(void)data;
	(void)size;
	g_write_calls++;
	record_event(EVENT_WRITE);
	return g_write_result;
}

kern_return_t mach_port_mod_refs(mach_port_t task, mach_port_t name, int right, int delta)
{
	(void)task;
	(void)name;
	(void)right;
	(void)delta;
	g_mod_refs_calls++;
	return KERN_SUCCESS;
}

static void reset_case(vm_prot_t protection)
{
	g_lookup_result = KERN_SUCCESS;
	g_temp_protect_result = KERN_SUCCESS;
	g_restore_result = KERN_SUCCESS;
	g_write_result = KERN_SUCCESS;
	g_region_base = 0x1000;
	g_region_size = 0x1000;
	g_region_protection = protection;
	g_lookup_calls = 0;
	g_protect_calls = 0;
	g_write_calls = 0;
	g_mod_refs_calls = 0;
	g_event_count = 0;
	for (int index = 0; index < 2; index++) {
		g_protect_addresses[index] = 0;
		g_protect_sizes[index] = 0;
		g_protections[index] = VM_PROT_NONE;
		g_set_maximum[index] = true;
	}
}

static int expect(bool condition, const char *message)
{
	if (condition) return 0;
	fprintf(stderr, "FAIL %s\n", message);
	return 1;
}

static const uint8_t g_patch_data[8] = {1, 2, 3, 4, 5, 6, 7, 8};

static int test_readonly_data_page(void)
{
	reset_case(VM_PROT_READ);
	int result = apply_hook(2, 3, 0x1100, g_patch_data, sizeof(g_patch_data));
	return expect(result == KERN_SUCCESS, "read-only data hook should succeed") ||
		expect(g_protect_calls == 2 && g_write_calls == 1, "data write must be bracketed by protection changes") ||
		expect(g_protections[0] == (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY), "data page writable mode must retain R and add W/COPY without X") ||
		expect((g_protections[0] & VM_PROT_EXECUTE) == 0, "data page temporary protection must not add X") ||
		expect(g_protections[1] == VM_PROT_READ, "data page must restore exact read-only protection") ||
		expect(g_events[0] == EVENT_LOOKUP && g_events[1] == EVENT_TEMP_PROTECT &&
		       g_events[2] == EVENT_WRITE && g_events[3] == EVENT_RESTORE_PROTECT,
		       "data page sequence must query, protect, write, then restore") ||
		expect(g_protect_addresses[0] == 0x1100 && g_protect_addresses[1] == 0x1100 &&
		       g_protect_sizes[0] == sizeof(g_patch_data) && g_protect_sizes[1] == sizeof(g_patch_data),
		       "data protection changes must cover only the requested range") ||
		expect(!g_set_maximum[0] && !g_set_maximum[1], "protection changes must not alter maximum permissions") ||
		expect(g_mod_refs_calls == 1, "task send right must be released once");
}

static int test_executable_page(void)
{
	reset_case(VM_PROT_READ | VM_PROT_EXECUTE);
	int result = apply_hook(2, 3, 0x1100, g_patch_data, sizeof(g_patch_data));
	return expect(result == KERN_SUCCESS, "executable page hook should succeed") ||
		expect(g_protect_calls == 2 && g_write_calls == 1, "executable write must be bracketed by protection changes") ||
		expect(g_protections[0] == (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY),
		       "executable page must be temporarily RW-copy without X") ||
		expect((g_protections[0] & VM_PROT_EXECUTE) == 0,
		       "temporary write window must never retain execute permission") ||
		expect(g_protections[1] == (VM_PROT_READ | VM_PROT_EXECUTE), "code page must restore exact RX protection");
}

static int test_write_failure_still_restores(void)
{
	reset_case(VM_PROT_READ);
	g_write_result = KERN_FAILURE;
	int result = apply_hook(2, 3, 0x1100, g_patch_data, sizeof(g_patch_data));
	return expect(result == KERN_FAILURE, "write failure must be reported after cleanup") ||
		expect(g_write_calls == 1 && g_protect_calls == 2, "write failure must still attempt restoration") ||
		expect(g_protections[1] == VM_PROT_READ, "write failure must restore original data-page permissions") ||
		expect(g_event_count == 4 && g_events[2] == EVENT_WRITE && g_events[3] == EVENT_RESTORE_PROTECT,
		       "restore must run immediately after a failed write");
}

static int test_lookup_failure_has_no_mutation(void)
{
	reset_case(VM_PROT_READ);
	g_lookup_result = KERN_FAILURE;
	int result = apply_hook(2, 3, 0x1100, g_patch_data, sizeof(g_patch_data));
	return expect(result == KERN_FAILURE, "range lookup failure must be returned") ||
		expect(g_lookup_calls == 1 && g_protect_calls == 0 && g_write_calls == 0,
		       "lookup failure must occur before any protection change or write") ||
		expect(g_mod_refs_calls == 1, "lookup failure must release the task send right");
}

static int test_cross_leaf_range_has_no_mutation(void)
{
	reset_case(VM_PROT_READ);
	int result = apply_hook(2, 3, 0x1100, g_patch_data, 0xF01);
	return expect(result == KERN_INVALID_ADDRESS, "a request crossing the reported leaf must be rejected") ||
		expect(g_lookup_calls == 1 && g_protect_calls == 0 && g_write_calls == 0,
		       "cross-leaf request must not mutate either mapping");
}

static int test_temporary_protection_failure_has_no_write(void)
{
	reset_case(VM_PROT_READ);
	g_temp_protect_result = KERN_FAILURE;
	int result = apply_hook(2, 3, 0x1100, g_patch_data, sizeof(g_patch_data));
	return expect(result == KERN_FAILURE, "temporary protection failure must be reported") ||
		expect(g_protect_calls == 1 && g_write_calls == 0,
		       "failed writable transition must not write or attempt a false restoration");
}

static int test_restore_failure_is_reported(void)
{
	reset_case(VM_PROT_READ | VM_PROT_EXECUTE);
	g_restore_result = KERN_FAILURE;
	int result = apply_hook(2, 3, 0x1100, g_patch_data, sizeof(g_patch_data));
	return expect(result == KERN_FAILURE, "protection restoration failure must fail the hook") ||
		expect(g_write_calls == 1 && g_protect_calls == 2, "restore failure occurs after the write and restore attempt") ||
		expect(g_protections[1] == (VM_PROT_READ | VM_PROT_EXECUTE),
		       "restore attempt must request the exact original RX permissions");
}

int main(void)
{
	if (test_readonly_data_page() || test_executable_page() ||
	    test_write_failure_still_restores() || test_lookup_failure_has_no_mutation() ||
	    test_cross_leaf_range_has_no_mutation() || test_temporary_protection_failure_has_no_write() ||
	    test_restore_failure_is_reported()) return 1;
	puts("hookd_protection_contract: PASS");
	return 0;
}
"""


def main() -> int:
    source = SOURCE.read_text(encoding="utf-8")
    range_helper = extract_function(source, "static kern_return_t hookd_range_protection(")
    apply_hook = extract_function(source, "int apply_hook(")

    if "vm_write(" not in apply_hook:
        raise AssertionError("production apply_hook must write through the Mach VM provider")
    if "__atomic_store_n(" in apply_hook or "memcpy(" in apply_hook:
        raise AssertionError("production apply_hook must not use a local-store fallback")
    if "vm_protect(taskPort, vmaddr, size, false, originalProtection)" not in apply_hook:
        raise AssertionError("production apply_hook must restore the captured protection")

    clang = shutil.which("clang")
    if clang is None:
        raise RuntimeError("clang is required for the hookd protection host contract")

    with tempfile.TemporaryDirectory(prefix="hookd-protection-contract-") as directory:
        source_path = Path(directory) / "hookd_protection_contract.c"
        binary_path = Path(directory) / "hookd_protection_contract"
        source_path.write_text(
            HARNESS_PREFIX + "\n" + range_helper + "\n" + apply_hook + "\n",
            encoding="utf-8",
        )
        compiled = subprocess.run(
            [clang, "-std=c11", "-Wall", "-Wextra", "-Werror", str(source_path), "-o", str(binary_path)],
            check=False,
            capture_output=True,
            text=True,
        )
        if compiled.returncode != 0:
            raise RuntimeError(f"hookd host fixture did not compile:\n{compiled.stderr}")
        subprocess.run([str(binary_path)], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
