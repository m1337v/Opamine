#ifndef RHI_HIDER_INTERNAL_H
#define RHI_HIDER_INTERNAL_H

#include <stdbool.h>

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

#endif
