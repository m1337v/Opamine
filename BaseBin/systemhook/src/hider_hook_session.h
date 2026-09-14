/* Hider-specific ownership and policy wrapper for rhi_rebind transactions. */
#ifndef RHI_HIDER_HOOK_SESSION_H
#define RHI_HIDER_HOOK_SESSION_H

#include <stdbool.h>
#include <stddef.h>

#include "rhi_rebind.h"

typedef struct {
	const char *name;
	rhi_rebind_transaction_t *transaction;
	rhi_hook_state_t state;
	bool required;
} rhi_hider_hook_session_t;

RHI_REBIND_INTERNAL void rhi_hider_hook_session_reset(rhi_hider_hook_session_t *session,
	                                                     const char *name, bool required);

/* Analyze, publish known originals, commit, read back, then arm add-image work. */
RHI_REBIND_INTERNAL bool rhi_hider_hook_session_start(
	rhi_hider_hook_session_t *session,
	const rhi_rebind_spec_t *specs, size_t spec_count);

RHI_REBIND_INTERNAL bool rhi_hider_hook_session_is_ready(
	const rhi_hider_hook_session_t *session);
RHI_REBIND_INTERNAL bool rhi_hider_hook_session_hook_is_active(
	const rhi_hider_hook_session_t *session, const char *name);
RHI_REBIND_INTERNAL rhi_hook_state_t rhi_hider_hook_session_state(
	const rhi_hider_hook_session_t *session);

#endif /* RHI_HIDER_HOOK_SESSION_H */
