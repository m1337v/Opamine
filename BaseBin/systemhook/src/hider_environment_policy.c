#include "hider_environment_policy.h"

#include <stdint.h>
#include <string.h>

static bool rhi_hider_env_name_hidden_span(const char *name, size_t name_length)
{
	return (name_length >= sizeof("DYLD_") - 1U &&
	        memcmp(name, "DYLD_", sizeof("DYLD_") - 1U) == 0) ||
	       (name_length >= sizeof("ROOTHIDE_") - 1U &&
	        memcmp(name, "ROOTHIDE_", sizeof("ROOTHIDE_") - 1U) == 0) ||
	       (name_length == sizeof("_SafeMode") - 1U &&
	        memcmp(name, "_SafeMode", sizeof("_SafeMode") - 1U) == 0) ||
	       (name_length == sizeof("_MSSafeMode") - 1U &&
	        memcmp(name, "_MSSafeMode", sizeof("_MSSafeMode") - 1U) == 0) ||
	       (name_length == sizeof("_SubstituteSafeMode") - 1U &&
	        memcmp(name, "_SubstituteSafeMode", sizeof("_SubstituteSafeMode") - 1U) == 0);
}

bool rhi_hider_env_name_hidden(const char *name)
{
	return name && rhi_hider_env_name_hidden_span(name, strlen(name));
}

bool rhi_hider_env_entry_hidden(const char *entry)
{
	if (!entry) return false;
	const char *equals = strchr(entry, '=');
	if (!equals || equals == entry) return false;

	return rhi_hider_env_name_hidden_span(entry, (size_t)(equals - entry));
}

bool rhi_hider_env_scrub_vector(char *entries[], size_t entry_capacity,
	                              size_t *visible_entry_count_out)
{
	if (!entries || entry_capacity == 0) return false;

	/* Find the terminator before changing any caller-owned pointer slot. */
	size_t original_count = 0;
	while (original_count < entry_capacity && entries[original_count] != NULL) {
		original_count++;
	}
	if (original_count == entry_capacity) return false;

	size_t visible_count = 0;
	for (size_t read = 0; read < original_count; read++) {
		if (!rhi_hider_env_entry_hidden(entries[read])) {
			entries[visible_count++] = entries[read];
		}
	}
	/* Clear every pointer we compacted over, including the old terminator. */
	for (size_t clear = visible_count; clear <= original_count; clear++) {
		entries[clear] = NULL;
	}

	if (visible_entry_count_out) *visible_entry_count_out = visible_count;
	return true;
}

typedef struct {
	size_t environment_offset;
	size_t output_length;
	bool has_hidden_entries;
} rhi_hider_procargs2_layout_t;

static bool rhi_hider_procargs2_find_nul(const uint8_t *bytes, size_t length,
	                                        size_t start, size_t *nul_offset_out)
{
	if (!bytes || !nul_offset_out || start >= length) return false;
	const void *nul = memchr(bytes + start, '\0', length - start);
	if (!nul) return false;
	*nul_offset_out = (size_t)((const uint8_t *)nul - bytes);
	return true;
}

static bool rhi_hider_procargs2_entry_valid(const uint8_t *bytes,
	                                           size_t start, size_t end)
{
	if (!bytes || start >= end) return false;
	const void *equals = memchr(bytes + start, '=', end - start);
	return equals != NULL && equals != bytes + start;
}

static bool rhi_hider_procargs2_parse(const uint8_t *bytes, size_t length,
	                                     rhi_hider_procargs2_layout_t *layout_out)
{
	if (!bytes || !layout_out || length < sizeof(int32_t)) return false;

	int32_t argc = 0;
	memcpy(&argc, bytes, sizeof(argc));
	/* A KERN_PROCARGS2 argv has an executable argument.  Rejecting an empty
	 * argv avoids treating arbitrary zero padding as a valid environment list. */
	if (argc <= 0) return false;

	size_t cursor = sizeof(argc);
	size_t nul_offset = 0;
	if (!rhi_hider_procargs2_find_nul(bytes, length, cursor, &nul_offset) ||
	    nul_offset == cursor) {
		return false;
	}
	cursor = nul_offset + 1U;

	/* Darwin pads the executable string before argv.  The exact padding width
	 * is ABI-private, so accept only zero bytes and require a real argv after it. */
	while (cursor < length && bytes[cursor] == '\0') cursor++;
	if (cursor == length || (size_t)argc > length - cursor) return false;

	for (int32_t argument = 0; argument < argc; argument++) {
		if (!rhi_hider_procargs2_find_nul(bytes, length, cursor, &nul_offset) ||
		    nul_offset == cursor) {
			return false;
		}
		cursor = nul_offset + 1U;
	}

	const size_t environment_offset = cursor;
	size_t removed_bytes = 0;
	bool has_hidden_entries = false;
	for (;;) {
		if (cursor >= length) return false;
		if (bytes[cursor] == '\0') {
			/* The kernel may expose zero-filled tail padding, never data after
			 * the envp terminator.  Rejecting nonzero tail bytes prevents an
			 * ambiguous, partially parsed payload from being rewritten. */
			for (size_t tail = cursor + 1U; tail < length; tail++) {
				if (bytes[tail] != '\0') return false;
			}
			break;
		}
		if (!rhi_hider_procargs2_find_nul(bytes, length, cursor, &nul_offset) ||
		    !rhi_hider_procargs2_entry_valid(bytes, cursor, nul_offset)) {
			return false;
		}

		const size_t entry_bytes = nul_offset - cursor + 1U;
		if (rhi_hider_env_entry_hidden((const char *)(const void *)(bytes + cursor))) {
			if (removed_bytes > length - entry_bytes) return false;
			removed_bytes += entry_bytes;
			has_hidden_entries = true;
		}
		cursor = nul_offset + 1U;
	}

	layout_out->environment_offset = environment_offset;
	layout_out->output_length = length - removed_bytes;
	layout_out->has_hidden_entries = has_hidden_entries;
	return true;
}

bool rhi_hider_procargs2_filter_inplace(void *buffer, size_t input_length,
	                                       size_t buffer_capacity,
	                                       size_t *filtered_length_out)
{
	if (!buffer || !filtered_length_out || buffer_capacity < input_length) return false;

	rhi_hider_procargs2_layout_t layout = {0};
	uint8_t *bytes = buffer;
	/* Parse before the first write, so all failure paths preserve byte identity. */
	if (!rhi_hider_procargs2_parse(bytes, input_length, &layout)) return false;
	if (!layout.has_hidden_entries) {
		*filtered_length_out = input_length;
		return true;
	}

	size_t read = layout.environment_offset;
	size_t write = layout.environment_offset;
	for (;;) {
		if (bytes[read] == '\0') break;
		size_t nul_offset = 0;
		/* The first validation pass proved this lookup and entry are bounded. */
		(void)rhi_hider_procargs2_find_nul(bytes, input_length, read, &nul_offset);
		const size_t entry_bytes = nul_offset - read + 1U;
		if (!rhi_hider_env_entry_hidden((const char *)(const void *)(bytes + read))) {
			if (write != read) memmove(bytes + write, bytes + read, entry_bytes);
			write += entry_bytes;
		}
		read = nul_offset + 1U;
	}

	/* Preserve the valid envp terminator and any validated zero tail. */
	memmove(bytes + write, bytes + read, input_length - read);
	*filtered_length_out = layout.output_length;
	return true;
}
