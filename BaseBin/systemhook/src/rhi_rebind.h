/*
 * rhi_rebind.h -- result-aware, parent-owned import-slot rebinding.
 *
 * This intentionally does not expose LiteHook's historic void rebind API.
 * A caller can observe whether a transaction changed no slots, all slots, a
 * subset of slots, or cannot prove the final state.  In particular, a
 * PARTIAL or UNKNOWN transaction is terminal and is never retried.
 */
#ifndef RHI_REBIND_H
#define RHI_REBIND_H

#include <stdbool.h>
#include <stddef.h>

#include <mach-o/loader.h>

#if defined(__GNUC__)
#define RHI_REBIND_INTERNAL __attribute__((visibility("hidden")))
#else
#define RHI_REBIND_INTERNAL
#endif

typedef enum {
	RHI_HOOK_NOT_ATTEMPTED = 0,
	RHI_HOOK_PREPARED,
	RHI_HOOK_ACTIVE,
	RHI_HOOK_FAILED,
	RHI_HOOK_PARTIAL,
	RHI_HOOK_UNKNOWN,
} rhi_hook_state_t;

typedef enum {
	/* Proves that no write was made. */
	RHI_REBIND_NONE = 0,
	/* Every prepared slot was changed and read back with protections restored. */
	RHI_REBIND_COMPLETE,
	/* At least one slot was written but a later operation failed. */
	RHI_REBIND_PARTIAL,
	/* A write or protection transition cannot be proven after an error. */
	RHI_REBIND_UNKNOWN,
} rhi_rebind_result_t;

typedef struct {
	const char *name;       /* diagnostics only; must stay valid for session life */
	void *replacee;         /* canonical original target */
	void *replacement;      /* replacement function */
} rhi_rebind_spec_t;

typedef struct rhi_rebind_transaction rhi_rebind_transaction_t;

/*
 * Allocate a transaction which owns only its mutable plan/artifact ledger.
 * The supplied specs are copied during prepare, so their storage may be
 * temporary.  Prepare is read-only and returns false on any ambiguous image,
 * malformed import table, or allocation failure.
 */
RHI_REBIND_INTERNAL rhi_rebind_transaction_t *rhi_rebind_transaction_create(void);
RHI_REBIND_INTERNAL void rhi_rebind_transaction_destroy(rhi_rebind_transaction_t *transaction);
RHI_REBIND_INTERNAL bool rhi_rebind_transaction_prepare_global(
	rhi_rebind_transaction_t *transaction,
	const rhi_rebind_spec_t *specs,
	size_t spec_count);

/*
 * Publish the previously captured originals through the caller's own storage
 * before invoking commit.  The rebind layer itself does not call arbitrary
 * callbacks while its lock is held.
 */
RHI_REBIND_INTERNAL void *rhi_rebind_transaction_original(
	const rhi_rebind_transaction_t *transaction, size_t hook_index);

/* Commit exactly once. PARTIAL and UNKNOWN make the transaction terminal. */
RHI_REBIND_INTERNAL rhi_rebind_result_t rhi_rebind_transaction_commit(
	rhi_rebind_transaction_t *transaction);

/*
 * Once an initial COMPLETE commit is verified, register for future image
 * additions. Each new image is analyzed in full before its first write. A
 * post-activation PARTIAL/UNKNOWN invalidates the entire transaction; there
 * is deliberately no automatic repair or retry path.
 */
RHI_REBIND_INTERNAL bool rhi_rebind_transaction_activate_global(
	rhi_rebind_transaction_t *transaction);

RHI_REBIND_INTERNAL rhi_hook_state_t rhi_rebind_transaction_state(
	const rhi_rebind_transaction_t *transaction);
RHI_REBIND_INTERNAL rhi_hook_state_t rhi_rebind_transaction_hook_state(
	const rhi_rebind_transaction_t *transaction, size_t hook_index);
RHI_REBIND_INTERNAL bool rhi_rebind_transaction_all_hooks_prepared(
	const rhi_rebind_transaction_t *transaction);
RHI_REBIND_INTERNAL bool rhi_rebind_transaction_all_hooks_active(
	const rhi_rebind_transaction_t *transaction);
RHI_REBIND_INTERNAL bool rhi_rebind_transaction_hook_is_active(
	const rhi_rebind_transaction_t *transaction, const char *name);
RHI_REBIND_INTERNAL size_t rhi_rebind_transaction_hook_count(
	const rhi_rebind_transaction_t *transaction);
RHI_REBIND_INTERNAL const char *rhi_hook_state_name(rhi_hook_state_t state);
RHI_REBIND_INTERNAL const char *rhi_rebind_result_name(rhi_rebind_result_t result);

#endif /* RHI_REBIND_H */
