/* Portable, table-driven checks for the standalone environment policy. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "hider_environment_policy.h"

#define ARRAY_COUNT(items) (sizeof(items) / sizeof((items)[0]))

typedef struct {
	uint8_t bytes[512];
	size_t length;
	size_t terminal_offset;
} procargs_fixture_t;

static bool append_bytes(procargs_fixture_t *fixture, const void *source, size_t count)
{
	if (!fixture || !source || count > sizeof(fixture->bytes) - fixture->length) return false;
	memcpy(fixture->bytes + fixture->length, source, count);
	fixture->length += count;
	return true;
}

static bool append_cstr(procargs_fixture_t *fixture, const char *value)
{
	return append_bytes(fixture, value, strlen(value) + 1U);
}

static bool append_zeroes(procargs_fixture_t *fixture, size_t count)
{
	static const uint8_t zeroes[16] = {0};
	while (count) {
		size_t piece = count < sizeof(zeroes) ? count : sizeof(zeroes);
		if (!append_bytes(fixture, zeroes, piece)) return false;
		count -= piece;
	}
	return true;
}

static bool append_argc(procargs_fixture_t *fixture, int32_t argc)
{
	return append_bytes(fixture, &argc, sizeof(argc));
}

static bool make_valid_fixture(procargs_fixture_t *fixture, bool include_hidden,
	                               bool include_tail_padding)
{
	if (!fixture) return false;
	memset(fixture, 0, sizeof(*fixture));
	if (!append_argc(fixture, 2) ||
	    !append_cstr(fixture, "/usr/bin/App") ||
	    !append_zeroes(fixture, 2) ||
	    !append_cstr(fixture, "App") ||
	    !append_cstr(fixture, "--inspect") ||
	    !append_cstr(fixture, "PATH=/usr/bin:/bin") ||
	    !append_cstr(fixture, "VISIBLE=one") ||
	    !append_cstr(fixture, "EMPTY=") ||
	    !append_cstr(fixture, "VALUE_LOOKS_DYLD=DYLD_INSERT_LIBRARIES=/x")) {
		return false;
	}
	if (include_hidden &&
	    (!append_cstr(fixture, "DYLD_INSERT_LIBRARIES=/usr/lib/systemhook.dylib") ||
	     !append_cstr(fixture, "ROOTHIDE_HIDER_PROFILE=strict") ||
	     !append_cstr(fixture, "_SafeMode=1") ||
	     !append_cstr(fixture, "ROOTHIDE_DUP=first") ||
	     !append_cstr(fixture, "ROOTHIDE_DUP=second") ||
	     !append_cstr(fixture, "_MSSafeMode=") ||
	     !append_cstr(fixture, "_SubstituteSafeMode=1") ||
	     !append_cstr(fixture, "DYLD_EMPTY="))) {
		return false;
	}
	if (!append_cstr(fixture, "LAST=visible")) return false;
	fixture->terminal_offset = fixture->length;
	if (!append_zeroes(fixture, 1)) return false; /* envp NULL terminator */
	if (include_tail_padding && !append_zeroes(fixture, 3)) return false;
	return true;
}

static int require_true(bool condition, const char *message)
{
	if (condition) return 0;
	fprintf(stderr, "environment policy fixture failed: %s\n", message);
	return 1;
}

static bool contains_entry(const uint8_t *bytes, size_t length, const char *entry)
{
	const size_t entry_length = strlen(entry);
	if (!bytes || entry_length == 0 || entry_length >= length) return false;
	for (size_t offset = 0; offset + entry_length < length; offset++) {
		if ((offset == 0 || bytes[offset - 1U] == '\0') &&
		    bytes[offset + entry_length] == '\0' &&
		    memcmp(bytes + offset, entry, entry_length) == 0) {
			return true;
		}
	}
	return false;
}

static int test_name_entry_equivalence(void)
{
	struct predicate_case {
		const char *name;
		const char *entry;
		bool hidden;
	};
	static const struct predicate_case cases[] = {
		{ "DYLD_INSERT_LIBRARIES", "DYLD_INSERT_LIBRARIES=/x", true },
		{ "DYLD_", "DYLD_=", true },
		{ "ROOTHIDE_HIDER_PROFILE", "ROOTHIDE_HIDER_PROFILE=strict", true },
		{ "ROOTHIDE_", "ROOTHIDE_=", true },
		{ "_SafeMode", "_SafeMode=1", true },
		{ "_MSSafeMode", "_MSSafeMode=", true },
		{ "_SubstituteSafeMode", "_SubstituteSafeMode=1", true },
		{ "PATH", "PATH=DYLD_INSERT_LIBRARIES=/x", false },
		{ "HOME", "HOME=/var/mobile", false },
		{ "DYLD", "DYLD=value", false },
		{ "NOT_ROOTHIDE_X", "NOT_ROOTHIDE_X=1", false },
	};
	for (size_t index = 0; index < ARRAY_COUNT(cases); index++) {
		if (require_true(rhi_hider_env_name_hidden(cases[index].name) == cases[index].hidden,
		                 "name predicate table") ||
		    require_true(rhi_hider_env_entry_hidden(cases[index].entry) == cases[index].hidden,
		                 "NAME=value predicate table") ||
		    require_true(rhi_hider_env_name_hidden(cases[index].name) ==
		                 rhi_hider_env_entry_hidden(cases[index].entry),
		                 "getenv and entry predicates must agree")) {
			return 1;
		}
	}
	return require_true(!rhi_hider_env_entry_hidden("PATH") &&
	                    !rhi_hider_env_entry_hidden("=value") &&
	                    !rhi_hider_env_entry_hidden(NULL),
	                    "malformed entries are not names");
}

static int test_vector_scrub(void)
{
	char entry0[] = "PATH=/usr/bin";
	char entry1[] = "DYLD_INSERT_LIBRARIES=/x";
	char entry2[] = "EMPTY=";
	char entry3[] = "ROOTHIDE_DUP=first";
	char entry4[] = "ROOTHIDE_DUP=second";
	char entry5[] = "NORMAL=DYLD_INSERT_LIBRARIES=/x";
	char *entries[] = { entry0, entry1, entry2, entry3, entry4, entry5, NULL };
	size_t visible_count = 99;
	if (require_true(rhi_hider_env_scrub_vector(entries, ARRAY_COUNT(entries), &visible_count),
	                 "bounded vector scrub succeeds") ||
	    require_true(visible_count == 3, "vector retains only visible entries") ||
	    require_true(entries[0] == entry0 && entries[1] == entry2 && entries[2] == entry5 &&
	                 entries[3] == NULL && entries[6] == NULL,
	                 "vector ordering and termination")) {
		return 1;
	}

	char unterminated0[] = "DYLD_X=1";
	char unterminated1[] = "PATH=/bin";
	char *unterminated[] = { unterminated0, unterminated1 };
	char *before[] = { unterminated0, unterminated1 };
	visible_count = 88;
	return require_true(!rhi_hider_env_scrub_vector(unterminated,
	                                                ARRAY_COUNT(unterminated), &visible_count) &&
	                    memcmp(unterminated, before, sizeof(before)) == 0 && visible_count == 88,
	                    "unterminated vector is unchanged");
}

static int test_valid_payload_filter(void)
{
	procargs_fixture_t actual = {0};
	procargs_fixture_t expected = {0};
	if (!make_valid_fixture(&actual, true, true) || !make_valid_fixture(&expected, false, true)) {
		return require_true(false, "fixture construction");
	}
	size_t output_length = 0;
	if (require_true(rhi_hider_procargs2_filter_inplace(actual.bytes, actual.length,
	                                                   sizeof(actual.bytes), &output_length),
	                 "valid PROCARGS2 filters") ||
	    require_true(output_length == expected.length, "compacted length") ||
	    require_true(memcmp(actual.bytes, expected.bytes, expected.length) == 0,
	                 "argv/env ordering, values, and terminator") ||
	    require_true(memcmp(actual.bytes + sizeof(int32_t), "/usr/bin/App", sizeof("/usr/bin/App")) == 0,
	                 "executable preserved") ||
	    require_true(contains_entry(actual.bytes, output_length, "--inspect"),
	                 "argv preserved") ||
	    require_true(contains_entry(actual.bytes, output_length, "PATH=/usr/bin:/bin") &&
	                 contains_entry(actual.bytes, output_length, "EMPTY=") &&
	                 contains_entry(actual.bytes, output_length, "VALUE_LOOKS_DYLD=DYLD_INSERT_LIBRARIES=/x"),
	                 "unrelated and empty values preserved") ||
	    require_true(!contains_entry(actual.bytes, output_length,
	                                 "DYLD_INSERT_LIBRARIES=/usr/lib/systemhook.dylib") &&
	                 !contains_entry(actual.bytes, output_length, "ROOTHIDE_HIDER_PROFILE=strict") &&
	                 !contains_entry(actual.bytes, output_length, "ROOTHIDE_DUP=first") &&
	                 !contains_entry(actual.bytes, output_length, "ROOTHIDE_DUP=second") &&
	                 !contains_entry(actual.bytes, output_length, "DYLD_EMPTY="),
	                 "every hidden duplicate and marker removed")) {
		return 1;
	}

	/* A valid input with no hidden entry is a successful byte-identical no-op. */
	procargs_fixture_t no_hidden = {0};
	if (!make_valid_fixture(&no_hidden, false, true)) return require_true(false, "no-hidden fixture");
	uint8_t before[sizeof(no_hidden.bytes)];
	memcpy(before, no_hidden.bytes, sizeof(before));
	output_length = 0;
	return require_true(rhi_hider_procargs2_filter_inplace(no_hidden.bytes, no_hidden.length,
	                                                       no_hidden.length, &output_length) &&
	                    output_length == no_hidden.length &&
	                    memcmp(no_hidden.bytes, before, sizeof(before)) == 0,
	                    "valid no-hidden payload remains byte-identical");
}

static int test_malformed_payloads_unchanged(void)
{
	procargs_fixture_t valid = {0};
	if (!make_valid_fixture(&valid, true, false)) return require_true(false, "base malformed fixture");

	struct malformed_case {
		const char *name;
		size_t length;
		size_t capacity;
	};
	const struct malformed_case cases[] = {
		{ "short-header", sizeof(int32_t) - 1U, valid.length },
		{ "truncated-executable", sizeof(int32_t) + 3U, valid.length },
		{ "truncated-argv", sizeof(int32_t) + sizeof("/usr/bin/App") + 2U + 2U, valid.length },
		{ "truncated-environment", valid.terminal_offset, valid.length },
		{ "capacity-short", valid.length, valid.length - 1U },
	};
	for (size_t index = 0; index < ARRAY_COUNT(cases); index++) {
		uint8_t bytes[sizeof(valid.bytes)];
		memcpy(bytes, valid.bytes, sizeof(bytes));
		uint8_t before[sizeof(bytes)];
		memcpy(before, bytes, sizeof(before));
		size_t output_length = 12345;
		if (require_true(!rhi_hider_procargs2_filter_inplace(bytes, cases[index].length,
		                                                   cases[index].capacity, &output_length) &&
		                 memcmp(bytes, before, sizeof(bytes)) == 0 && output_length == 12345,
		                 cases[index].name)) {
			return 1;
		}
	}

	/* A non NAME=value environment element is rejected before mutation. */
	procargs_fixture_t invalid = {0};
	if (!append_argc(&invalid, 1) || !append_cstr(&invalid, "/x") ||
	    !append_zeroes(&invalid, 1) || !append_cstr(&invalid, "x") ||
	    !append_cstr(&invalid, "BROKEN") || !append_zeroes(&invalid, 1)) {
		return require_true(false, "invalid-entry fixture");
	}
	uint8_t before[sizeof(invalid.bytes)];
	memcpy(before, invalid.bytes, sizeof(before));
	size_t output_length = 67890;
	return require_true(!rhi_hider_procargs2_filter_inplace(invalid.bytes, invalid.length,
	                                                       sizeof(invalid.bytes), &output_length) &&
	                    memcmp(invalid.bytes, before, sizeof(before)) == 0 && output_length == 67890,
	                    "invalid environment entry leaves bytes unchanged");
}

int main(void)
{
	if (test_name_entry_equivalence() || test_vector_scrub() ||
	    test_valid_payload_filter() || test_malformed_payloads_unchanged()) {
		return 1;
	}
	puts("hider_environment_policy_host: PASS");
	return 0;
}
