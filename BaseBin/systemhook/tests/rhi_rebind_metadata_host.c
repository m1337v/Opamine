/* Executes the production chained-fixup metadata decoder in this translation
 * unit. It deliberately stops before Mach VM writes; the fixture proves that
 * imports, addends, weak state and exact arm64e PAC schema come from original
 * file words, and malformed metadata is refused before planning a slot. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/rhi_rebind.c"

static void put32(uint8_t *p, uint32_t value)
{
	memcpy(p, &value, sizeof(value));
}

static void put16(uint8_t *p, uint16_t value)
{
	memcpy(p, &value, sizeof(value));
}

static void put64(uint8_t *p, uint64_t value)
{
	memcpy(p, &value, sizeof(value));
}

static void fixture_original(void) {}
static void fixture_replacement(void) {}

/* This exercises the production bounded ledger comparison directly.  It
 * purposefully never invokes the public attestation entry point because that
 * also validates the host process's live dyld image identity.  The production
 * entry point wraps this helper with those lifecycle fences on device. */
static int run_slot_attestation_fixture(void)
{
	uintptr_t raw_word = UINT64_C(0xfa00000012345678); /* PAC-shaped opaque raw value */
	const uintptr_t original_raw = UINT64_C(0xaa00000012345678);
	const uintptr_t replacement_raw = UINT64_C(0xfa00000012345678);
	const uintptr_t foreign_raw = UINT64_C(0xbb00000012345678);
	rhi_rebind_slot_t slots[2] = {{
		.address = (void **)(void *)&raw_word,
		.image = { .header = (const struct mach_header *)(uintptr_t)0x1000U },
		.original_raw = original_raw,
		.replacement_raw = replacement_raw,
		.wrote = true,
	}};
	rhi_rebind_transaction_t transaction = {
		.slots = slots,
		.slot_count = 1,
		.global_armed = true,
	};
	RHI_STATE_STORE(&transaction.state, RHI_HOOK_ACTIVE);
	RHI_STATE_STORE(&transaction.result, RHI_REBIND_COMPLETE);

	/* Intact checks exact raw data, does not strip a PAC-shaped replacement,
	 * and must not modify the slot ledger or its live word. */
	const rhi_rebind_slot_t before = slots[0];
	const uintptr_t word_before = raw_word;
	if (rhi_attest_slots_readonly(&transaction) != RHI_ATTEST_INTACT ||
	    raw_word != word_before || memcmp(&slots[0], &before, sizeof(before)) != 0) {
		fputs("rhi intact/no-write attestation fixture failed\n", stderr);
		return 1;
	}

	/* An exact original raw word is a proven loss, not a repair opportunity. */
	raw_word = original_raw;
	if (rhi_attest_slots_readonly(&transaction) != RHI_ATTEST_FAILED ||
	    rhi_apply_attestation_locked(&transaction, RHI_ATTEST_FAILED) != RHI_ATTEST_FAILED ||
	    rhi_rebind_transaction_state(&transaction) != RHI_HOOK_FAILED ||
	    !transaction.terminal || transaction.global_armed ||
	    rhi_rebind_transaction_result(&transaction) != RHI_REBIND_COMPLETE ||
	    rhi_rebind_transaction_attestation(&transaction) != RHI_ATTEST_FAILED ||
	    rhi_apply_attestation_locked(&transaction, RHI_ATTEST_UNKNOWN) != RHI_ATTEST_FAILED) {
		fputs("rhi original/terminal attestation fixture failed\n", stderr);
		return 1;
	}

	/* A foreign raw word is unprovable and therefore terminal UNKNOWN. */
	raw_word = foreign_raw;
	transaction = (rhi_rebind_transaction_t){
		.slots = slots, .slot_count = 1, .global_armed = true,
	};
	RHI_STATE_STORE(&transaction.state, RHI_HOOK_ACTIVE);
	RHI_STATE_STORE(&transaction.result, RHI_REBIND_COMPLETE);
	if (rhi_attest_slots_readonly(&transaction) != RHI_ATTEST_UNKNOWN ||
	    rhi_apply_attestation_locked(&transaction, RHI_ATTEST_UNKNOWN) != RHI_ATTEST_UNKNOWN ||
	    rhi_rebind_transaction_state(&transaction) != RHI_HOOK_UNKNOWN ||
	    !transaction.terminal || transaction.global_armed ||
	    rhi_rebind_transaction_result(&transaction) != RHI_REBIND_COMPLETE) {
		fputs("rhi foreign/terminal attestation fixture failed\n", stderr);
		return 1;
	}

	/* A mixed ledger with an original slot is FAILED; a mixed ledger containing
	 * any foreign slot is UNKNOWN because the full state is no longer proven. */
	raw_word = replacement_raw;
	uintptr_t second_word = original_raw;
	slots[1] = (rhi_rebind_slot_t){
		.address = (void **)(void *)&second_word,
		.image = { .header = (const struct mach_header *)(uintptr_t)0x2000U },
		.original_raw = original_raw,
		.replacement_raw = replacement_raw,
		.wrote = true,
	};
	transaction = (rhi_rebind_transaction_t){ .slots = slots, .slot_count = 2 };
	if (rhi_attest_slots_readonly(&transaction) != RHI_ATTEST_FAILED) {
		fputs("rhi mixed-original attestation fixture failed\n", stderr);
		return 1;
	}
	second_word = foreign_raw;
	if (rhi_attest_slots_readonly(&transaction) != RHI_ATTEST_UNKNOWN) {
		fputs("rhi mixed-foreign attestation fixture failed\n", stderr);
		return 1;
	}

	/* Retired artifacts must never be dereferenced, and zero-site monitored
	 * transactions remain healthy attestation candidates. */
	slots[0].image.header = NULL;
	slots[0].address = (void **)(uintptr_t)1U;
	transaction = (rhi_rebind_transaction_t){ .slots = slots, .slot_count = 1 };
	if (rhi_attest_slots_readonly(&transaction) != RHI_ATTEST_INTACT) {
		fputs("rhi retired-slot attestation fixture failed\n", stderr);
		return 1;
	}
	transaction = (rhi_rebind_transaction_t){};
	if (rhi_attest_slots_readonly(&transaction) != RHI_ATTEST_INTACT) {
		fputs("rhi zero-site attestation fixture failed\n", stderr);
		return 1;
	}

	/* A live but malformed slot record is structural uncertainty, without a
	 * read or write through its unaligned address. */
	uint8_t unaligned[sizeof(uintptr_t) + 1U] = {0};
	transaction = (rhi_rebind_transaction_t){
		.slots = slots,
		.slot_count = 1,
	};
	slots[0] = (rhi_rebind_slot_t){
		.address = (void **)(void *)(unaligned + 1U),
		.image = { .header = (const struct mach_header *)(uintptr_t)0x3000U },
		.original_raw = original_raw,
		.replacement_raw = replacement_raw,
		.wrote = true,
	};
	if (rhi_attest_slots_readonly(&transaction) != RHI_ATTEST_UNKNOWN ||
	    strcmp(rhi_rebind_attestation_name(RHI_ATTEST_INTACT), "intact") != 0) {
		fputs("rhi structural attestation fixture failed\n", stderr);
		return 1;
	}
	return 0;
}

/* Exercise the public entry point against a real, stable host dyld snapshot.
 * The transaction is not linked into g_global_transactions (the test has no
 * lifecycle callbacks); in_global_registry models the already-activated
 * production ownership required by the public API. */
static int run_public_attestation_fixture(void)
{
	rhi_rebind_transaction_t transaction = { .lock = OS_UNFAIR_LOCK_INIT };
	const uint32_t image_count = _dyld_image_count();
	if (!image_count || image_count > RHI_REBIND_MAX_IMAGES) return 1;
	transaction.known_images = calloc(image_count, sizeof(*transaction.known_images));
	if (!transaction.known_images) return 1;
	transaction.known_image_count = image_count;
	transaction.known_image_capacity = image_count;
	for (uint32_t i = 0; i < image_count; i++) {
		if (!rhi_live_identity(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i),
		                       &transaction.known_images[i])) {
			free(transaction.known_images);
			return 1;
		}
	}
	uintptr_t raw_word = UINT64_C(0xfa00000089abcdef);
	transaction.slots = calloc(1, sizeof(*transaction.slots));
	if (!transaction.slots) {
		free(transaction.known_images);
		return 1;
	}
	transaction.slot_count = 1;
	transaction.slot_capacity = 1;
	transaction.slots[0] = (rhi_rebind_slot_t){
		.address = (void **)(void *)&raw_word,
		.image = transaction.known_images[0],
		.original_raw = UINT64_C(0xaa00000089abcdef),
		.replacement_raw = raw_word,
		.wrote = true,
	};
	RHI_STATE_STORE(&transaction.lifecycle_generation,
	                __atomic_load_n(&g_lifecycle_generation, __ATOMIC_ACQUIRE));
	RHI_STATE_STORE(&transaction.state, RHI_HOOK_ACTIVE);
	RHI_STATE_STORE(&transaction.result, RHI_REBIND_COMPLETE);
	RHI_STATE_STORE(&transaction.attestation, RHI_ATTEST_NOT_ATTEMPTED);
	transaction.global_armed = true;
	transaction.in_global_registry = true;
	const uintptr_t before = raw_word;
	const rhi_rebind_attestation_t intact = rhi_rebind_transaction_attest(&transaction);
	const bool intact_ok = intact == RHI_ATTEST_INTACT && raw_word == before &&
		rhi_rebind_transaction_result(&transaction) == RHI_REBIND_COMPLETE;
	/* The public path must make a proven original word terminal without
	 * rewriting it or reclassifying the historic successful commit. */
	raw_word = transaction.slots[0].original_raw;
	const rhi_rebind_attestation_t failed = rhi_rebind_transaction_attest(&transaction);
	const bool failed_ok = failed == RHI_ATTEST_FAILED &&
		raw_word == transaction.slots[0].original_raw && transaction.terminal &&
		!transaction.global_armed && rhi_rebind_transaction_state(&transaction) == RHI_HOOK_FAILED &&
		rhi_rebind_transaction_result(&transaction) == RHI_REBIND_COMPLETE;
	free(transaction.slots);
	free(transaction.known_images);
	if (!intact_ok || !failed_ok) {
		fputs("rhi public attestation fixture failed\n", stderr);
		return 1;
	}
	return 0;
}

static int run_file_word_walk_fixture(void)
{
	uint8_t payload[128] = {0};
	uint8_t file_words[4096] = {0};
	uint8_t image[4096] = {0};
	put32(payload + 4, 64);  /* starts */
	put32(payload + 8, 28);  /* imports */
	put32(payload + 12, 32); /* symbols */
	put32(payload + 16, 1);
	put32(payload + 20, RHI_CHAINED_IMPORT);
	put32(payload + 28, 1);  /* lib ordinal 1, name offset zero */
	memcpy(payload + 32, "fixture", sizeof("fixture"));
	put32(payload + 64, 1);  /* one segment */
	put32(payload + 68, 8);  /* starts-in-segment is relative to starts */
	put32(payload + 72, 24); /* header + one page-start */
	put16(payload + 76, 4096);
	put16(payload + 78, RHI_CHAINED_PTR_ARM64E_USERLAND);
	put64(payload + 80, 0);  /* segment image offset */
	put16(payload + 92, 1);
	put16(payload + 94, 0x100);
	put64(file_words + 0x100, UINT64_C(1) << 62); /* bind ordinal zero */

	void **slot = (void **)(void *)(image + 0x100);
	*slot = (void *)fixture_original;
	rhi_rebind_hook_t hook = {
		.name = "fixture",
		.replacee = (void *)fixture_original,
		.replacement = (void *)fixture_replacement,
	};
	rhi_rebind_transaction_t transaction = {
		.hooks = &hook,
		.hook_count = 1,
	};
	rhi_image_identity_t identity = { .header = (const struct mach_header *)(const void *)image };
	rhi_image_layout_t layout = {
		.count = 1,
		.preferred_vmaddr = 0,
		.entries = {{ .vmaddr = 0, .vmsize = sizeof(image), .fileoff = 0, .filesize = sizeof(file_words) }},
	};
	rhi_chained_fixups_t fixups;
	if (!rhi_parse_chained_fixups(payload, sizeof(payload), &fixups) ||
	    !rhi_chained_imports_validate(&fixups) ||
	    !rhi_walk_chained_image(&transaction, &fixups, &identity, &layout,
	                            file_words, sizeof(file_words)) ||
	    transaction.slot_count != 1 || transaction.slots[0].address != slot ||
	    transaction.slots[0].original_raw != (uintptr_t)fixture_original ||
	    transaction.slots[0].replacement_raw != (uintptr_t)fixture_replacement ||
	    *slot != (void *)fixture_original) {
		free(transaction.slots);
		return 1;
	}
	/* A malformed chain is rejected in prepare and leaves the live slot
	 * untouched; this fixture never calls the commit/write path. */
	rhi_rebind_transaction_t malformed = { .hooks = &hook, .hook_count = 1 };
	put64(file_words + 0x100, (UINT64_C(1) << 62) | (UINT64_C(0x7ff) << 51));
	const bool rejected = !rhi_walk_chained_image(&malformed, &fixups, &identity, &layout,
	                                              file_words, sizeof(file_words));
	free(transaction.slots);
	free(malformed.slots);
	return rejected && *slot == (void *)fixture_original ? 0 : 1;
}

int main(void)
{
	uint8_t blob[96] = {0};
	/* header: starts=64, imports=28, strings=36, one ADDEND import */
	put32(blob + 4, 64);
	put32(blob + 8, 28);
	put32(blob + 12, 36);
	put32(blob + 16, 1);
	put32(blob + 20, RHI_CHAINED_IMPORT_ADDEND);
	put32(blob + 28, 1U | (1U << 8)); /* lib ordinal + weak import */
	put32(blob + 32, 0xfffffff8U);     /* -8 import addend */
	memcpy(blob + 36, "_fixture_symbol", sizeof("_fixture_symbol"));
	put32(blob + 64, 0);                /* starts_in_image has no segments */

	rhi_chained_fixups_t fixups;
	rhi_chained_import_t import;
	if (!rhi_parse_chained_fixups(blob, sizeof(blob), &fixups) ||
	    !rhi_chained_imports_validate(&fixups) ||
	    !rhi_chained_import_at(&fixups, 0, &import) || import.library_ordinal != 1 || !import.weak ||
	    import.addend != -8 || strcmp(import.name, "_fixture_symbol") != 0) {
		fputs("rhi metadata import fixture failed\n", stderr);
		return 1;
	}

	/* authenticated arm64e userland bind: ordinal=7, diversity=0x55aa,
	 * address diversity, key=IB, next=3. */
	const uint64_t raw = (UINT64_C(1) << 63) | (UINT64_C(1) << 62) |
		(UINT64_C(3) << 51) | (UINT64_C(1) << 49) | (UINT64_C(1) << 48) |
		(UINT64_C(0x55aa) << 32) | 7U;
	rhi_chained_pointer_t pointer;
	rhi_decode_chain_pointer(raw, RHI_CHAINED_PTR_ARM64E_USERLAND, &pointer);
	if (!pointer.bind || !pointer.authenticated || pointer.ordinal != 7 ||
	    pointer.key != RHI_PAC_KEY_IB || pointer.diversity != 0x55aa ||
	    !pointer.address_diversity || pointer.next != 3) {
		fputs("rhi metadata PAC fixture failed\n", stderr);
		return 1;
	}

	/* A non-terminated symbol pool is malformed. No transaction or VM write
	 * path is reached by this parser failure. */
	memset(blob + 36, 'X', sizeof(blob) - 36); /* no terminator in symbol pool */
	if (rhi_chained_imports_validate(&fixups)) {
		fputs("rhi malformed metadata fixture failed\n", stderr);
		return 1;
	}
	if (run_file_word_walk_fixture() != 0) {
		fputs("rhi file-word chain walk fixture failed\n", stderr);
		return 1;
	}
	if (run_slot_attestation_fixture() != 0) return 1;
	if (run_public_attestation_fixture() != 0) return 1;
	puts("rhi_rebind_metadata_host: PASS");
	return 0;
}
