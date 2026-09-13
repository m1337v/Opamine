#ifndef RHI_HIDER_CALLER_POLICY_H
#define RHI_HIDER_CALLER_POLICY_H

#include <stdbool.h>
#include <stdint.h>
#include <mach-o/loader.h>

#include "hider_internal.h"

/*
 * Capabilities are deliberately narrower than image concealment.  A library
 * may be hidden from app-facing dyld APIs without being trusted to receive an
 * unfiltered view of those APIs.
 */
RHI_HIDER_INTERNAL void rhi_hider_caller_policy_init(void);
RHI_HIDER_INTERNAL bool rhi_hider_caller_can_read_hidden(const void *return_address);

/* Register the systemhook image containing address as an exact trusted range. */
RHI_HIDER_INTERNAL bool rhi_hider_caller_register_own_function(void (*function)(void));

/*
 * Authorize one successfully loaded selected tweak by its exact dyld path.
 * No basename, .jbroot-prefix, or failed dlopen can grant this capability.
 */
typedef enum {
	RHI_HIDER_CALLER_AUTHORIZED = 0,
	RHI_HIDER_CALLER_AUTH_INVALID_PATH,
	RHI_HIDER_CALLER_AUTH_IMAGE_NOT_FOUND,
	RHI_HIDER_CALLER_AUTH_INVALID_RANGE,
	RHI_HIDER_CALLER_AUTH_RANGE_CAPACITY,
} rhi_hider_caller_authorization_result_t;

RHI_HIDER_INTERNAL bool rhi_hider_caller_authorize_loaded_image_path(
	const char *path, rhi_hider_caller_authorization_result_t *result_out);
RHI_HIDER_INTERNAL const char *rhi_hider_caller_authorization_result_name(
	rhi_hider_caller_authorization_result_t result);

/* dyld callback integration; each notification invalidates return-address cache. */
RHI_HIDER_INTERNAL void rhi_hider_caller_image_added(const struct mach_header *header, intptr_t slide);
RHI_HIDER_INTERNAL void rhi_hider_caller_image_removed(const struct mach_header *header, intptr_t slide);

/*
 * Same-thread, nesting-safe scope for systemhook/RootHide operations that
 * must traverse forwarding framework code before the trusted caller returns.
 */
RHI_HIDER_INTERNAL bool rhi_hider_caller_internal_read_enter(void);
RHI_HIDER_INTERNAL void rhi_hider_caller_internal_read_leave(void);

RHI_HIDER_INTERNAL uint64_t rhi_hider_caller_generation(void);

#endif
