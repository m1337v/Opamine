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
	puts("rhi_rebind_metadata_host: PASS");
	return 0;
}
