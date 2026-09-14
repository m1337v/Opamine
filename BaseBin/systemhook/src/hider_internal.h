#ifndef RHI_HIDER_INTERNAL_H
#define RHI_HIDER_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>
#include <mach-o/loader.h>

/*
 * These symbols are implementation seams inside systemhook, never a runtime
 * API for injected code.  Keeping them private prevents a hostile in-process
 * dylib from obtaining a capability-granting entry point through dlsym.
 */
#if defined(__GNUC__)
#define RHI_HIDER_INTERNAL __attribute__((visibility("hidden")))
#else
#define RHI_HIDER_INTERNAL
#endif

RHI_HIDER_INTERNAL void hidden_dylib_hider_init(void);
RHI_HIDER_INTERNAL void hidden_dylib_hider_enable_strict_hooks(void);
RHI_HIDER_INTERNAL void *hidden_dylib_hider_dlsym_remap(const char *name);
RHI_HIDER_INTERNAL bool hidden_dylib_hider_envbuf_apply(char ***envc);

/* Stable catalog seam for caller-relative lookup. The snapshot owns each path
 * and is safe to inspect without the hider lock, but header/slide are opaque
 * identities only and must never be dereferenced by a snapshot consumer. Any
 * future caller-relative resolver stays in hidden_dylib_hider.c, where it can
 * take an internal short-lived pin and recheck generation/identity around a
 * loader operation. This remains internal to systemhook, never a dlsym
 * capability. */
typedef struct {
	const char               *path;
	const struct mach_header *header;
	intptr_t                  slide;
	uint8_t                   uuid[16];
	uint64_t                  identity;
	bool                      uuid_valid;
	bool                      main_executable;
	/* This snapshot deliberately includes both views.  A caller-relative
	 * resolver must walk the real load order, then decide whether a matching
	 * provider may be exposed to its caller. */
	bool                      hidden;
} rhi_hider_catalog_image_t;

typedef struct {
	rhi_hider_catalog_image_t *images;
	uint32_t                   count;
	uint64_t                   generation;
} rhi_hider_catalog_snapshot_t;

RHI_HIDER_INTERNAL bool hidden_dylib_hider_catalog_snapshot(rhi_hider_catalog_snapshot_t *snapshot_out);
RHI_HIDER_INTERNAL void hidden_dylib_hider_catalog_snapshot_dispose(rhi_hider_catalog_snapshot_t *snapshot);
RHI_HIDER_INTERNAL bool hidden_dylib_hider_catalog_generation_is_current(uint64_t generation);

#endif
