#ifndef RHI_HIDER_IDENTITY_H
#define RHI_HIDER_IDENTITY_H

#include <stdbool.h>
#include <stdint.h>
#include <mach-o/loader.h>

#include "hider_internal.h"

/*
 * Stable process identity for the hider.  Launch injection means dyld image
 * zero is not guaranteed to be the main executable, so callers must use this
 * layer rather than indexing the image list directly.
 */
RHI_HIDER_INTERNAL void rhi_hider_identity_init(void);

RHI_HIDER_INTERNAL const char *rhi_hider_identity_executable_path(void);
RHI_HIDER_INTERNAL const struct mach_header *rhi_hider_identity_executable_header(void);
RHI_HIDER_INTERNAL intptr_t rhi_hider_identity_executable_slide(void);

/* A bounded all-or-nothing collection of a Mach-O image's executable segments. */
#define RHI_HIDER_EXECUTABLE_RANGE_LIMIT 16U
typedef struct {
	uintptr_t start;
	uintptr_t end;
} rhi_hider_executable_range_t;

typedef struct {
	uint32_t count;
	rhi_hider_executable_range_t ranges[RHI_HIDER_EXECUTABLE_RANGE_LIMIT];
} rhi_hider_executable_ranges_t;

typedef enum {
	RHI_HIDER_IDENTITY_RANGES_VALID = 0,
	RHI_HIDER_IDENTITY_RANGES_INVALID,
	RHI_HIDER_IDENTITY_RANGES_CAPACITY,
} rhi_hider_identity_ranges_result_t;

/*
 * Validate a dyld-supplied Mach-O header and calculate its mapped __TEXT
 * range.  The function never follows load commands beyond sizeofcmds and
 * rejects arithmetic overflow.  It is intentionally limited to headers and
 * slides supplied by the public dyld callback/image APIs.
 */
RHI_HIDER_INTERNAL bool rhi_hider_identity_image_text_range(const struct mach_header *header,
                                                             intptr_t slide,
                                                             uintptr_t *start_out,
                                                             uintptr_t *end_out);

RHI_HIDER_INTERNAL bool rhi_hider_identity_executable_ranges(const struct mach_header *header,
                                                              intptr_t slide,
                                                              rhi_hider_executable_ranges_t *ranges_out,
                                                              rhi_hider_identity_ranges_result_t *result_out);

#endif
