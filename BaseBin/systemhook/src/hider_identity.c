#include "hider_identity.h"

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/vm_prot.h>
#include <os/lock.h>
#include <limits.h>
#include <ptrauth.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	char *path;
	const struct mach_header *header;
	intptr_t slide;
	bool initialized;
} rhi_hider_identity_state_t;

static rhi_hider_identity_state_t g_identity = {0};
static os_unfair_lock g_identity_lock = OS_UNFAIR_LOCK_INIT;

/* Mach headers are data pointers; strip an arm64e signature before arithmetic. */
static uintptr_t rhi_hider_identity_data_address(const void *pointer)
{
#if defined(__arm64e__)
	return (uintptr_t)ptrauth_strip(pointer, ptrauth_key_process_independent_data);
#else
	return (uintptr_t)pointer;
#endif
}

static const struct mach_header *rhi_hider_identity_strip_header(const struct mach_header *header)
{
#if defined(__arm64e__)
	return ptrauth_strip(header, ptrauth_key_process_independent_data);
#else
	return header;
#endif
}

static bool rhi_add_slide(uint64_t vmaddr, intptr_t slide, uintptr_t *out)
{
	if (!out || vmaddr > UINTPTR_MAX) {
		return false;
	}

	uintptr_t value = (uintptr_t)vmaddr;
	if (slide >= 0) {
		uintptr_t positive_slide = (uintptr_t)slide;
		if (value > UINTPTR_MAX - positive_slide) {
			return false;
		}
		*out = value + positive_slide;
		return true;
	}

	/* Avoid negating INTPTR_MIN. */
	uintptr_t negative_slide = (uintptr_t)(-(slide + 1)) + 1U;
	if (value < negative_slide) {
		return false;
	}
	*out = value - negative_slide;
	return true;
}

static char *rhi_hider_identity_copy_path(const char *path)
{
	if (!path) {
		return NULL;
	}
	size_t length = strnlen(path, PATH_MAX);
	if (length == PATH_MAX || length == SIZE_MAX) {
		return NULL;
	}
	char *copy = malloc(length + 1);
	if (!copy) {
		return NULL;
	}
	memcpy(copy, path, length);
	copy[length] = '\0';
	return copy;
}

static bool rhi_validate_header_and_commands(const struct mach_header_64 *header,
	                                          const uint8_t **commands_out,
	                                          const uint8_t **commands_end_out)
{
	if (!header || header->magic != MH_MAGIC_64) {
		return false;
	}

	const uint8_t *commands = (const uint8_t *)(header + 1);
	uintptr_t commands_end_address = 0;
	if (__builtin_add_overflow(rhi_hider_identity_data_address(commands), (uintptr_t)header->sizeofcmds,
	                           &commands_end_address)) {
		return false;
	}
	const uint8_t *commands_end = (const uint8_t *)commands_end_address;
	uintptr_t cursor_address = rhi_hider_identity_data_address(commands);

	for (uint32_t index = 0; index < header->ncmds; index++) {
		if (cursor_address > commands_end_address ||
		    commands_end_address - cursor_address < sizeof(struct load_command)) {
			return false;
		}
		const struct load_command *command = (const struct load_command *)cursor_address;
		if (command->cmdsize < sizeof(*command) ||
		    commands_end_address - cursor_address < command->cmdsize) {
			return false;
		}
		cursor_address += command->cmdsize;
	}

	if (commands_out) {
		*commands_out = commands;
	}
	if (commands_end_out) {
		*commands_end_out = commands_end;
	}
	return true;
}

bool rhi_hider_identity_image_text_range(const struct mach_header *header,
	                                      intptr_t slide,
	                                      uintptr_t *start_out,
	                                      uintptr_t *end_out)
{
	if (!header || !start_out || !end_out) {
		return false;
	}

	const struct mach_header *stripped_header = rhi_hider_identity_strip_header(header);
	const struct mach_header_64 *header64 = (const struct mach_header_64 *)stripped_header;
	const uint8_t *cursor = NULL;
	const uint8_t *commands_end = NULL;
	if (!rhi_validate_header_and_commands(header64, &cursor, &commands_end)) {
		return false;
	}

	uintptr_t cursor_address = rhi_hider_identity_data_address(cursor);
	uintptr_t commands_end_address = rhi_hider_identity_data_address(commands_end);
	for (uint32_t index = 0; index < header64->ncmds; index++) {
		const struct load_command *command = (const struct load_command *)cursor_address;
		if (command->cmd == LC_SEGMENT_64 &&
		    command->cmdsize >= sizeof(struct segment_command_64)) {
			const struct segment_command_64 *segment =
				(const struct segment_command_64 *)command;
			if (strncmp(segment->segname, SEG_TEXT, sizeof(segment->segname)) == 0) {
				uintptr_t text_start = 0;
				if (!segment->vmsize ||
				    !rhi_add_slide(segment->vmaddr, slide, &text_start) ||
				    segment->vmsize > UINTPTR_MAX - text_start) {
					return false;
				}

				uintptr_t text_end = text_start + (uintptr_t)segment->vmsize;
				/* The Mach header must reside in the mapped __TEXT segment. */
				uintptr_t header_address = rhi_hider_identity_data_address(stripped_header);
				if (header_address < text_start || header_address >= text_end) {
					return false;
				}
				*start_out = text_start;
				*end_out = text_end;
				return true;
			}
		}
		if (cursor_address > commands_end_address ||
		    commands_end_address - cursor_address < command->cmdsize) {
			return false;
		}
		cursor_address += command->cmdsize;
	}

	return false;
}

bool rhi_hider_identity_executable_ranges(const struct mach_header *header,
	                                      intptr_t slide,
	                                      rhi_hider_executable_ranges_t *ranges_out,
	                                      rhi_hider_identity_ranges_result_t *result_out)
{
	if (result_out) {
		*result_out = RHI_HIDER_IDENTITY_RANGES_INVALID;
	}
	if (!header || !ranges_out) {
		return false;
	}
	memset(ranges_out, 0, sizeof(*ranges_out));

	/* Require a valid __TEXT/header relationship before trusting any segment. */
	uintptr_t text_start = 0;
	uintptr_t text_end = 0;
	if (!rhi_hider_identity_image_text_range(header, slide, &text_start, &text_end)) {
		return false;
	}

	const struct mach_header *stripped_header = rhi_hider_identity_strip_header(header);
	const struct mach_header_64 *header64 = (const struct mach_header_64 *)stripped_header;
	const uint8_t *cursor = NULL;
	const uint8_t *commands_end = NULL;
	if (!rhi_validate_header_and_commands(header64, &cursor, &commands_end)) {
		return false;
	}

	uintptr_t cursor_address = rhi_hider_identity_data_address(cursor);
	uintptr_t commands_end_address = rhi_hider_identity_data_address(commands_end);
	for (uint32_t index = 0; index < header64->ncmds; index++) {
		const struct load_command *command = (const struct load_command *)cursor_address;
		if (command->cmd == LC_SEGMENT_64 &&
		    command->cmdsize >= sizeof(struct segment_command_64)) {
			const struct segment_command_64 *segment =
				(const struct segment_command_64 *)command;
			if ((segment->initprot & VM_PROT_EXECUTE) != 0 && segment->vmsize != 0) {
				if (ranges_out->count == RHI_HIDER_EXECUTABLE_RANGE_LIMIT) {
					memset(ranges_out, 0, sizeof(*ranges_out));
					if (result_out) {
						*result_out = RHI_HIDER_IDENTITY_RANGES_CAPACITY;
					}
					return false;
				}
				uintptr_t start = 0;
				if (!rhi_add_slide(segment->vmaddr, slide, &start) ||
				    segment->vmsize > UINTPTR_MAX - start) {
					memset(ranges_out, 0, sizeof(*ranges_out));
					return false;
				}
				ranges_out->ranges[ranges_out->count++] = (rhi_hider_executable_range_t){
					.start = start,
					.end = start + (uintptr_t)segment->vmsize,
				};
			}
		}
		if (cursor_address > commands_end_address ||
		    commands_end_address - cursor_address < command->cmdsize) {
			memset(ranges_out, 0, sizeof(*ranges_out));
			return false;
		}
		cursor_address += command->cmdsize;
	}

	if (ranges_out->count == 0) {
		return false;
	}
	if (result_out) {
		*result_out = RHI_HIDER_IDENTITY_RANGES_VALID;
	}
	return true;
}

static bool rhi_hider_identity_candidate(uint32_t index,
	                                      const struct mach_header **header_out,
	                                      const char **path_out,
	                                      intptr_t *slide_out)
{
	const struct mach_header *header = rhi_hider_identity_strip_header(_dyld_get_image_header(index));
	intptr_t slide = _dyld_get_image_vmaddr_slide(index);
	uintptr_t start = 0;
	uintptr_t end = 0;
	if (!header || !rhi_hider_identity_image_text_range(header, slide, &start, &end)) {
		return false;
	}

	if (header_out) {
		*header_out = header;
	}
	if (path_out) {
		*path_out = _dyld_get_image_name(index);
	}
	if (slide_out) {
		*slide_out = slide;
	}
	return true;
}

void rhi_hider_identity_init(void)
{
	os_unfair_lock_lock(&g_identity_lock);
	if (g_identity.initialized) {
		os_unfair_lock_unlock(&g_identity_lock);
		return;
	}

	const uint32_t image_count = _dyld_image_count();
	for (uint32_t index = 0; index < image_count; index++) {
		const struct mach_header *header = NULL;
		const char *path = NULL;
		intptr_t slide = 0;
		if (!rhi_hider_identity_candidate(index, &header, &path, &slide)) {
			continue;
		}
		if (((const struct mach_header_64 *)header)->filetype == MH_EXECUTE) {
			char *path_copy = rhi_hider_identity_copy_path(path);
			if (!path_copy) {
				break;
			}
			g_identity.header = header;
			g_identity.path = path_copy;
			g_identity.slide = slide;
			g_identity.initialized = true;
			os_unfair_lock_unlock(&g_identity_lock);
			return;
		}
	}

	/* Do not substitute an arbitrary injected dylib for the main executable. */
	g_identity.header = NULL;
	g_identity.path = NULL;
	g_identity.slide = 0;
	g_identity.initialized = true;
	os_unfair_lock_unlock(&g_identity_lock);
}

const char *rhi_hider_identity_executable_path(void)
{
	rhi_hider_identity_init();
	os_unfair_lock_lock(&g_identity_lock);
	const char *path = g_identity.path;
	os_unfair_lock_unlock(&g_identity_lock);
	return path;
}

const struct mach_header *rhi_hider_identity_executable_header(void)
{
	rhi_hider_identity_init();
	os_unfair_lock_lock(&g_identity_lock);
	const struct mach_header *header = g_identity.header;
	os_unfair_lock_unlock(&g_identity_lock);
	return header;
}

intptr_t rhi_hider_identity_executable_slide(void)
{
	rhi_hider_identity_init();
	os_unfair_lock_lock(&g_identity_lock);
	intptr_t slide = g_identity.slide;
	os_unfair_lock_unlock(&g_identity_lock);
	return slide;
}
