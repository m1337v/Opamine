#ifndef RHI_HIDER_PATH_POLICY_H
#define RHI_HIDER_PATH_POLICY_H

#include <stdbool.h>

/*
 * Pure, lexical visibility policy for app-facing paths.  These functions do
 * not resolve symlinks, inspect the filesystem, allocate, or mutate state.
 * Keep selected-tweak authorization in hider_caller_policy: a path matching
 * this policy never grants an injected image any visibility capability.
 */
#if defined(__GNUC__)
#define RHI_HIDER_PATH_POLICY_INTERNAL __attribute__((visibility("hidden")))
#else
#define RHI_HIDER_PATH_POLICY_INTERNAL
#endif

/* True when a dyld image path is an artifact the app-facing image view hides. */
RHI_HIDER_PATH_POLICY_INTERNAL bool rhi_hider_image_path_hidden(const char *path);

/* True when an app-facing filesystem operation should treat path as absent. */
RHI_HIDER_PATH_POLICY_INTERNAL bool rhi_hider_filesystem_path_hidden(const char *path);

/*
 * Equivalent to rhi_hider_filesystem_path_hidden(parent_path + "/" + name)
 * for a single, ordinary directory entry.  Invalid names (empty, dot, dotdot,
 * or names containing '/') are deliberately not classified.
 */
RHI_HIDER_PATH_POLICY_INTERNAL bool rhi_hider_directory_entry_hidden(const char *parent_path,
                                                                      const char *name);

#endif
