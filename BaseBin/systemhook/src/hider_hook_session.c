#include "hider_hook_session.h"

/*
 * This wrapper deliberately has no fallback implementation.  A hider session
 * becomes ready only after the transaction's slot readback is complete and it
 * has been armed for later images.  The caller owns original function storage;
 * rhi_rebind records it during prepare, before commit can make a replacement
 * reachable.
 */
void rhi_hider_hook_session_reset(rhi_hider_hook_session_t *session,
	                              const char *name, bool required)
{
	if (!session) return;
	if (session->transaction) rhi_rebind_transaction_destroy(session->transaction);
	*session = (rhi_hider_hook_session_t){
		.name = name,
		.required = required,
		.state = RHI_HOOK_NOT_ATTEMPTED,
	};
}

bool rhi_hider_hook_session_start(rhi_hider_hook_session_t *session,
	                             const rhi_rebind_spec_t *specs, size_t spec_count)
{
	if (!session || !specs || spec_count == 0 || session->transaction) return false;
	session->transaction = rhi_rebind_transaction_create();
	if (!session->transaction) {
		session->state = RHI_HOOK_FAILED;
		return false;
	}
	if (!rhi_rebind_transaction_prepare_global(session->transaction, specs, spec_count)) {
		session->state = rhi_rebind_transaction_state(session->transaction);
		return false;
	}
	/* The captured originals exist before any commit write. */
	for (size_t i = 0; i < spec_count; i++) {
		if (!rhi_rebind_transaction_original(session->transaction, i)) {
			session->state = RHI_HOOK_FAILED;
			return false;
		}
	}
	/* Required sessions must prove every requested hook before any write. */
	if (session->required &&
	    !rhi_rebind_transaction_all_hooks_prepared(session->transaction)) {
		session->state = RHI_HOOK_FAILED;
		return false;
	}
	rhi_rebind_result_t result = rhi_rebind_transaction_commit(session->transaction);
	if (result != RHI_REBIND_COMPLETE ||
	    (session->required &&
	     !rhi_rebind_transaction_all_hooks_active(session->transaction)) ||
	    !rhi_rebind_transaction_activate_global(session->transaction)) {
		session->state = rhi_rebind_transaction_state(session->transaction);
		return false;
	}
	session->state = RHI_HOOK_ACTIVE;
	return true;
}

bool rhi_hider_hook_session_is_ready(const rhi_hider_hook_session_t *session)
{
	return session && session->state == RHI_HOOK_ACTIVE && session->transaction &&
	       rhi_rebind_transaction_state(session->transaction) == RHI_HOOK_ACTIVE &&
	       (!session->required || rhi_rebind_transaction_all_hooks_active(session->transaction));
}

bool rhi_hider_hook_session_hook_is_active(const rhi_hider_hook_session_t *session,
	                                       const char *name)
{
	return rhi_hider_hook_session_is_ready(session) &&
	       rhi_rebind_transaction_hook_is_active(session->transaction, name);
}

rhi_hook_state_t rhi_hider_hook_session_state(const rhi_hider_hook_session_t *session)
{
	if (!session) return RHI_HOOK_FAILED;
	if (session->transaction) return rhi_rebind_transaction_state(session->transaction);
	return session->state;
}
