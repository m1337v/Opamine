/*
 * Central environment-marker policy for the hidden-dylib hider.
 *
 * This is deliberately independent of sysctl and hook code.  Callers must
 * consume any ROOTHIDE bridge values they require before asking this module to
 * scrub the process view.  The policy has no allow-list exceptions: a marker
 * visible through getenv, direct environ enumeration, or KERN_PROCARGS2 must
 * receive the same decision.
 */
#ifndef RHI_HIDER_ENVIRONMENT_POLICY_H
#define RHI_HIDER_ENVIRONMENT_POLICY_H

#include <stdbool.h>
#include <stddef.h>

#if defined(__GNUC__)
#define RHI_HIDER_ENV_POLICY_INTERNAL __attribute__((visibility("hidden")))
#else
#define RHI_HIDER_ENV_POLICY_INTERNAL
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Return true only for intentional loader/runtime marker names. */
RHI_HIDER_ENV_POLICY_INTERNAL bool rhi_hider_env_name_hidden(const char *name);

/*
 * Evaluate a conventional NAME=value environment entry with the exact same
 * predicate used for getenv names.  An entry with no '=', or an empty name,
 * is not a marker; PROCARGS2 validation treats such an entry as malformed
 * before this predicate is reached.
 */
RHI_HIDER_ENV_POLICY_INTERNAL bool rhi_hider_env_entry_hidden(const char *entry);

/*
 * Compact a terminated process-environment pointer vector in place without
 * allocating, freeing, or changing the pointed-to strings.  entry_capacity is
 * the number of pointer slots supplied by the caller and must include a NULL
 * terminator.  If no terminator occurs in that bounded range, the vector is
 * left untouched and false is returned.  On success visible_entry_count_out
 * receives the number of retained entries when it is non-NULL.
 *
 * This is a last-step scrub primitive.  Its caller owns bridge-value
 * consumption and must not invoke it until that work is complete.
 */
RHI_HIDER_ENV_POLICY_INTERNAL bool rhi_hider_env_scrub_vector(
	char *entries[], size_t entry_capacity, size_t *visible_entry_count_out);

/*
 * Filter a self KERN_PROCARGS2 payload in place.  The payload starts with its
 * 32-bit argc, followed by a non-empty executable path, zero padding, argc
 * non-empty argv strings, and a NUL-terminated NAME=value environment list.
 * Any bytes after that terminator must be zero padding.  input_length is the
 * exact returned byte length; buffer_capacity is the writable allocation.
 *
 * The function validates the entire layout before its first write.  A false
 * return therefore leaves buffer and *filtered_length_out untouched.  On
 * success, argv order and all visible environment-entry order are preserved;
 * *filtered_length_out is the compacted byte length that the sysctl caller
 * must report.  The function makes no PID or sysctl-query decision itself.
 */
RHI_HIDER_ENV_POLICY_INTERNAL bool rhi_hider_procargs2_filter_inplace(
	void *buffer, size_t input_length, size_t buffer_capacity,
	size_t *filtered_length_out);

#ifdef __cplusplus
}
#endif

#endif /* RHI_HIDER_ENVIRONMENT_POLICY_H */
