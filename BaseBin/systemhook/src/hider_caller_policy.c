#include "hider_caller_policy.h"

#include "hider_identity.h"

#include <mach-o/dyld.h>
#include <os/lock.h>
#include <ptrauth.h>
#include <stdatomic.h>
#include <string.h>
#include <limits.h>

/* Selected-tweak limits should not turn into implicit trust for every dylib. */
#define RHI_CALLER_TRUSTED_RANGE_LIMIT 128U
#define RHI_CALLER_CACHE_LIMIT 128U

typedef enum {
	RHI_CALLER_RANGE_OWN = 1,
	RHI_CALLER_RANGE_SELECTED_TWEAK = 2,
} rhi_caller_range_kind_t;

typedef struct {
	uintptr_t header_address;
	uintptr_t start;
	uintptr_t end;
	rhi_caller_range_kind_t kind;
} rhi_caller_range_t;

typedef struct {
	uintptr_t return_address;
	uint64_t generation;
	bool can_read_hidden;
} rhi_caller_cache_entry_t;

static rhi_caller_range_t g_ranges[RHI_CALLER_TRUSTED_RANGE_LIMIT] = {0};
static uint32_t g_range_count = 0;
static os_unfair_lock g_range_lock = OS_UNFAIR_LOCK_INIT;

static rhi_caller_cache_entry_t g_cache[RHI_CALLER_CACHE_LIMIT] = {0};
static uint32_t g_cache_next = 0;
static os_unfair_lock g_cache_lock = OS_UNFAIR_LOCK_INIT;

static atomic_uint_fast64_t g_generation = 1;
static atomic_bool g_initialized = false;
static __thread uint32_t g_internal_read_depth = 0;

static uintptr_t rhi_hider_caller_data_address(const void *pointer)
{
#if defined(__arm64e__)
	return (uintptr_t)ptrauth_strip(pointer, ptrauth_key_process_independent_data);
#else
	return (uintptr_t)pointer;
#endif
}

static uintptr_t rhi_hider_caller_return_address_value(const void *return_address)
{
#if defined(__arm64e__)
	return (uintptr_t)ptrauth_strip(return_address, ptrauth_key_return_address);
#else
	return (uintptr_t)return_address;
#endif
}

static uintptr_t rhi_hider_caller_function_address_value(void (*function)(void))
{
#if defined(__arm64e__)
	return (uintptr_t)ptrauth_strip(function, ptrauth_key_function_pointer);
#else
	return (uintptr_t)function;
#endif
}

/*
 * Call while g_range_lock is held.  Taking the cache lock before advancing the
 * generation makes the range change and cache invalidation one visibility
 * boundary: a reader either returns before the change commits or observes the
 * new generation, never a removed range paired with an old cache entry.
 */
static void rhi_hider_caller_advance_generation_locked(void)
{
	os_unfair_lock_lock(&g_cache_lock);
	(void)atomic_fetch_add_explicit(&g_generation, 1, memory_order_acq_rel);
	memset(g_cache, 0, sizeof(g_cache));
	g_cache_next = 0;
	os_unfair_lock_unlock(&g_cache_lock);
}

void rhi_hider_caller_policy_init(void)
{
	bool expected = false;
	if (atomic_compare_exchange_strong_explicit(&g_initialized, &expected, true,
	                                            memory_order_acq_rel,
	                                            memory_order_acquire)) {
		rhi_hider_identity_init();
	}
}

static rhi_hider_caller_authorization_result_t rhi_hider_caller_upsert_ranges(
	const struct mach_header *header, intptr_t slide, rhi_caller_range_kind_t kind)
{
	rhi_hider_executable_ranges_t executable_ranges = {0};
	rhi_hider_identity_ranges_result_t identity_result = RHI_HIDER_IDENTITY_RANGES_INVALID;
	if (!rhi_hider_identity_executable_ranges(header, slide, &executable_ranges, &identity_result)) {
		return identity_result == RHI_HIDER_IDENTITY_RANGES_CAPACITY
			? RHI_HIDER_CALLER_AUTH_RANGE_CAPACITY
			: RHI_HIDER_CALLER_AUTH_INVALID_RANGE;
	}
	uintptr_t header_address = rhi_hider_caller_data_address(header);
	if (!header_address) {
		return RHI_HIDER_CALLER_AUTH_INVALID_RANGE;
	}

	os_unfair_lock_lock(&g_range_lock);
	rhi_caller_range_t replacement[RHI_CALLER_TRUSTED_RANGE_LIMIT] = {0};
	uint32_t replacement_count = 0;
	for (uint32_t index = 0; index < g_range_count; index++) {
		if (g_ranges[index].header_address != header_address) {
			replacement[replacement_count++] = g_ranges[index];
		}
	}
	if (executable_ranges.count > RHI_CALLER_TRUSTED_RANGE_LIMIT - replacement_count) {
		os_unfair_lock_unlock(&g_range_lock);
		/* Refuse the entire capability; never install a partial image range set. */
		return RHI_HIDER_CALLER_AUTH_RANGE_CAPACITY;
	}
	for (uint32_t index = 0; index < executable_ranges.count; index++) {
		replacement[replacement_count++] = (rhi_caller_range_t){
			.header_address = header_address,
			.start = executable_ranges.ranges[index].start,
			.end = executable_ranges.ranges[index].end,
			.kind = kind,
		};
	}
	memset(g_ranges, 0, sizeof(g_ranges));
	memcpy(g_ranges, replacement, (size_t)replacement_count * sizeof(replacement[0]));
	g_range_count = replacement_count;
	rhi_hider_caller_advance_generation_locked();
	os_unfair_lock_unlock(&g_range_lock);
	return RHI_HIDER_CALLER_AUTHORIZED;
}

static bool rhi_hider_caller_remove_range_locked(const struct mach_header *header)
{
	bool removed = false;
	uintptr_t header_address = rhi_hider_caller_data_address(header);
	if (!header_address) {
		return false;
	}
	uint32_t write_index = 0;
	for (uint32_t index = 0; index < g_range_count; index++) {
		if (g_ranges[index].header_address == header_address) {
			removed = true;
			continue;
		}
		g_ranges[write_index++] = g_ranges[index];
	}
	if (removed) {
		memset(&g_ranges[write_index], 0,
		       (g_range_count - write_index) * sizeof(g_ranges[0]));
		g_range_count = write_index;
	}
	return removed;
}

bool rhi_hider_caller_register_own_function(void (*function)(void))
{
	if (!function) {
		return false;
	}
	rhi_hider_caller_policy_init();

	uint32_t count = _dyld_image_count();
	uintptr_t target = rhi_hider_caller_function_address_value(function);
	for (uint32_t index = 0; index < count; index++) {
		const struct mach_header *header = _dyld_get_image_header(index);
		intptr_t slide = _dyld_get_image_vmaddr_slide(index);
		rhi_hider_executable_ranges_t executable_ranges = {0};
		if (!rhi_hider_identity_executable_ranges(header, slide, &executable_ranges, NULL)) {
			continue;
		}
		for (uint32_t range_index = 0; range_index < executable_ranges.count; range_index++) {
			if (target >= executable_ranges.ranges[range_index].start &&
			    target < executable_ranges.ranges[range_index].end) {
				return rhi_hider_caller_upsert_ranges(header, slide, RHI_CALLER_RANGE_OWN) ==
					RHI_HIDER_CALLER_AUTHORIZED;
			}
		}
	}

	return false;
}

bool rhi_hider_caller_authorize_loaded_image_path(
	const char *path, rhi_hider_caller_authorization_result_t *result_out)
{
	if (result_out) {
		*result_out = RHI_HIDER_CALLER_AUTH_INVALID_PATH;
	}
	if (!path || !path[0]) {
		return false;
	}
	rhi_hider_caller_policy_init();

	uint32_t count = _dyld_image_count();
	for (uint32_t index = 0; index < count; index++) {
		const char *loaded_path = _dyld_get_image_name(index);
		if (!loaded_path || strcmp(path, loaded_path) != 0) {
			continue;
		}
		rhi_hider_caller_authorization_result_t result = rhi_hider_caller_upsert_ranges(
			_dyld_get_image_header(index), _dyld_get_image_vmaddr_slide(index),
			RHI_CALLER_RANGE_SELECTED_TWEAK);
		if (result_out) {
			*result_out = result;
		}
		return result == RHI_HIDER_CALLER_AUTHORIZED;
	}

	/* A successful dlopen without a matching, validated dyld image gets no trust. */
	if (result_out) {
		*result_out = RHI_HIDER_CALLER_AUTH_IMAGE_NOT_FOUND;
	}
	return false;
}

const char *rhi_hider_caller_authorization_result_name(
	rhi_hider_caller_authorization_result_t result)
{
	switch (result) {
		case RHI_HIDER_CALLER_AUTHORIZED: return "authorized";
		case RHI_HIDER_CALLER_AUTH_INVALID_PATH: return "invalid-path";
		case RHI_HIDER_CALLER_AUTH_IMAGE_NOT_FOUND: return "image-not-found";
		case RHI_HIDER_CALLER_AUTH_INVALID_RANGE: return "invalid-range";
		case RHI_HIDER_CALLER_AUTH_RANGE_CAPACITY: return "range-capacity";
	}
	return "invalid-result";
}

void rhi_hider_caller_image_added(const struct mach_header *header, intptr_t slide)
{
	(void)header;
	(void)slide;
	rhi_hider_caller_policy_init();
	/* A newly loaded image can reuse an address cached from a prior image. */
	os_unfair_lock_lock(&g_range_lock);
	rhi_hider_caller_advance_generation_locked();
	os_unfair_lock_unlock(&g_range_lock);
}

void rhi_hider_caller_image_removed(const struct mach_header *header, intptr_t slide)
{
	(void)slide;
	rhi_hider_caller_policy_init();
	os_unfair_lock_lock(&g_range_lock);
	(void)rhi_hider_caller_remove_range_locked(header);
	/* Always invalidate, including untrusted unloads and address reuse. */
	rhi_hider_caller_advance_generation_locked();
	os_unfair_lock_unlock(&g_range_lock);
}

bool rhi_hider_caller_can_read_hidden(const void *return_address)
{
	if (g_internal_read_depth != 0) {
		return true;
	}
	if (!return_address) {
		return false;
	}
	rhi_hider_caller_policy_init();
	uintptr_t address = rhi_hider_caller_return_address_value(return_address);
	if (!address) {
		return false;
	}

	for (uint32_t attempt = 0; attempt < 2; attempt++) {
		uint64_t generation = atomic_load_explicit(&g_generation, memory_order_acquire);
		os_unfair_lock_lock(&g_cache_lock);
		for (uint32_t index = 0; index < RHI_CALLER_CACHE_LIMIT; index++) {
			if (g_cache[index].return_address == address &&
			    g_cache[index].generation == generation) {
				bool result = g_cache[index].can_read_hidden;
				os_unfair_lock_unlock(&g_cache_lock);
				return result;
			}
		}
		os_unfair_lock_unlock(&g_cache_lock);

		bool can_read_hidden = false;
		os_unfair_lock_lock(&g_range_lock);
		for (uint32_t index = 0; index < g_range_count; index++) {
			const rhi_caller_range_t *range = &g_ranges[index];
			if (address >= range->start && address < range->end) {
				can_read_hidden = true;
				break;
			}
		}
		os_unfair_lock_unlock(&g_range_lock);

		/* A concurrent add/remove invalidates this classification; retry once. */
		if (atomic_load_explicit(&g_generation, memory_order_acquire) != generation) {
			continue;
		}

		os_unfair_lock_lock(&g_cache_lock);
		if (atomic_load_explicit(&g_generation, memory_order_acquire) != generation) {
			os_unfair_lock_unlock(&g_cache_lock);
			continue;
		}
		uint32_t slot = g_cache_next++ % RHI_CALLER_CACHE_LIMIT;
		g_cache[slot] = (rhi_caller_cache_entry_t){
			.return_address = address,
			.generation = generation,
			.can_read_hidden = can_read_hidden,
		};
		os_unfair_lock_unlock(&g_cache_lock);
		return can_read_hidden;
	}

	/* A sustained image-churn race is external until a later stable lookup. */
	return false;
}

bool rhi_hider_caller_internal_read_enter(void)
{
	if (g_internal_read_depth == UINT32_MAX) {
		return false;
	}
	g_internal_read_depth++;
	return true;
}

void rhi_hider_caller_internal_read_leave(void)
{
	if (g_internal_read_depth != 0) {
		g_internal_read_depth--;
	}
}

uint64_t rhi_hider_caller_generation(void)
{
	return atomic_load_explicit(&g_generation, memory_order_acquire);
}
