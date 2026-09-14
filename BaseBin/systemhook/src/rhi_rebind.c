/*
 * rhi_rebind.c -- a deliberately small import-slot transaction engine.
 *
 * LiteHook remains the source for symbol lookup and inline patches.  This
 * file owns only GOT/import-slot writes because the old LiteHook global API
 * could not report whether it had changed every intended slot.  The rules
 * here are intentionally stricter than that API:
 *
 *   - all current images are analysed before the first write;
 *   - every write is preceded by a stale-value check and followed by readback;
 *   - the containing page's protection is restored to its exact prior value;
 *   - no rollback is attempted after a write (constructors/concurrent calls
 *     make a guessed rollback worse than a truthful PARTIAL/UNKNOWN result);
 *   - unsupported chained-fixup metadata is rejected before mutation.
 */

#include "rhi_rebind.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/vm_region.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <os/lock.h>
#include <ptrauth.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* iPhoneOS SDK headers omit these exported 64-bit MIG declarations. */
extern kern_return_t mach_vm_region_recurse(mach_port_t target_task,
	                                        mach_vm_address_t *address,
	                                        mach_vm_size_t *size,
	                                        natural_t *nesting_depth,
	                                        vm_region_recurse_info_t info,
	                                        mach_msg_type_number_t *info_count);
extern kern_return_t mach_vm_protect(mach_port_t target_task,
	                                  mach_vm_address_t address,
	                                  mach_vm_size_t size,
	                                  boolean_t set_maximum,
	                                  vm_prot_t new_protection);
extern const void *_dyld_get_shared_cache_range(size_t *length) __attribute__((weak_import));

#define RHI_REBIND_MAX_HOOKS             48U
#define RHI_REBIND_MAX_SLOTS              16384U
#define RHI_REBIND_MAX_IMAGES             2048U
#define RHI_REBIND_MAX_SLOTS_PER_SECTION  4096U
#define RHI_REBIND_MAX_SEGMENTS            128U
#define RHI_REBIND_MAX_CHAIN_PAGES       65535U

/* dyld_chained_fixups import formats.  We deliberately decode the on-disk
 * layout with shifts/masks instead of SDK bitfield declarations: the latter
 * have compiler-layout assumptions and cannot prove what the file contained. */
#define RHI_CHAINED_HEADER_SIZE                 28U
#define RHI_CHAINED_IMPORT                      1U
#define RHI_CHAINED_IMPORT_ADDEND               2U
#define RHI_CHAINED_IMPORT_ADDEND64             3U
#define RHI_CHAINED_SYMBOLS_UNCOMPRESSED        0U
#define RHI_CHAINED_PTR_ARM64E                  1U
#define RHI_CHAINED_PTR_64                      2U
#define RHI_CHAINED_PTR_64_OFFSET               6U
#define RHI_CHAINED_PTR_ARM64E_USERLAND         9U
#define RHI_CHAINED_PTR_ARM64E_USERLAND24      12U
#define RHI_CHAINED_PAGE_START_NONE        0xffffU
#define RHI_CHAINED_PAGE_START_MULTI       0x8000U
#define RHI_CHAINED_PAGE_START_LAST        0x8000U

typedef enum {
	RHI_PAC_KEY_IA = 0,
	RHI_PAC_KEY_IB = 1,
	RHI_PAC_KEY_DA = 2,
	RHI_PAC_KEY_DB = 3,
} rhi_pac_key_t;

typedef struct {
	bool authenticated;
	rhi_pac_key_t key;
	uint16_t diversity;
	bool address_diversity;
} rhi_pac_schema_t;

typedef struct {
	const struct mach_header *header;
	intptr_t slide;
	uint8_t uuid[16];
} rhi_image_identity_t;

#ifndef INDIRECT_SYMBOL_LOCAL
#define INDIRECT_SYMBOL_LOCAL 0x80000000U
#endif
#ifndef INDIRECT_SYMBOL_ABS
#define INDIRECT_SYMBOL_ABS 0x40000000U
#endif

typedef struct {
	void **address;
	rhi_image_identity_t image;
	uintptr_t original_raw;
	uintptr_t replacement_raw;
	size_t hook_index;
	rhi_pac_schema_t schema;
	int64_t addend;
	bool wrote;
	bool protection_captured;
	vm_prot_t original_protection;
} rhi_rebind_slot_t;

typedef struct {
	char *name;
	void *replacee;
	void *replacement;
	const struct mach_header *replacement_header;
	rhi_hook_state_t state;
	size_t slot_count;
	bool predecessor_set;
	uintptr_t predecessor;
} rhi_rebind_hook_t;

/* The legacy LC_DYSYMTAB path reads loaded linkedit tables. Modern chained
 * fixups are decoded separately from UUID/architecture-matched file words so
 * their ordinal and PAC schema are never guessed from a live pointer value. */
typedef struct {
	const struct nlist_64 *symbols;
	uint32_t symbol_count;
	const char *strings;
	uint32_t string_size;
	const uint32_t *indirect_symbols;
	uint32_t indirect_count;
} rhi_legacy_import_metadata_t;

struct rhi_rebind_transaction {
	os_unfair_lock lock;
	rhi_rebind_hook_t *hooks;
	size_t hook_count;
	rhi_rebind_slot_t *slots;
	size_t slot_count;
	size_t slot_capacity;
	rhi_image_identity_t *known_images;
	size_t known_image_count;
	size_t known_image_capacity;
	rhi_hook_state_t state;
	rhi_rebind_result_t result;
	uint64_t lifecycle_generation;
	bool prepared;
	bool terminal;
	bool global_armed;
	bool in_global_registry;
	struct rhi_rebind_transaction *next_global;
};

static os_unfair_lock g_global_lock = OS_UNFAIR_LOCK_INIT;
/* VM protection is page-granular. Serialize complete writes across sessions
 * so adjacent GOT slots cannot race protection restoration. */
static os_unfair_lock g_writer_lock = OS_UNFAIR_LOCK_INIT;
static rhi_rebind_transaction_t *g_global_transactions = NULL;
static bool g_lifecycle_callbacks_registered = false;
static bool g_lifecycle_callbacks_registering = false;
static uint64_t g_lifecycle_generation = 1;
static void (*g_native_register_add_image)(void (*)(const struct mach_header *, intptr_t)) = NULL;
static void (*g_native_register_remove_image)(void (*)(const struct mach_header *, intptr_t)) = NULL;

#define RHI_STATE_LOAD(PTR) __atomic_load_n((PTR), __ATOMIC_ACQUIRE)
#define RHI_STATE_STORE(PTR, VALUE) __atomic_store_n((PTR), (VALUE), __ATOMIC_RELEASE)

static uintptr_t rhi_data_address(const void *pointer)
{
#if defined(__arm64e__)
	return (uintptr_t)ptrauth_strip(pointer, ptrauth_key_process_independent_data);
#else
	return (uintptr_t)pointer;
#endif
}

static const struct mach_header *rhi_strip_header(const struct mach_header *header)
{
#if defined(__arm64e__)
	return ptrauth_strip(header, ptrauth_key_process_independent_data);
#else
	return header;
#endif
}

static uintptr_t rhi_strip_function(const void *pointer)
{
#if defined(__arm64e__)
	/* Import slots may be unauthenticated. Authentication before we have a
	 * file-recorded schema can trap on exactly those valid raw words; stripping
	 * is safe, while authenticated slots are verified separately below. */
	return (uintptr_t)ptrauth_strip(pointer, ptrauth_key_asia);
#else
	return (uintptr_t)pointer;
#endif
}

static uintptr_t rhi_pac_discriminator(const rhi_pac_schema_t *schema, void **slot)
{
	if (!schema) return 0;
#if defined(__arm64e__)
	return schema->address_diversity
		? (uintptr_t)ptrauth_blend_discriminator(slot, schema->diversity)
		: schema->diversity;
#else
	(void)slot;
	return schema->diversity;
#endif
}

static uintptr_t rhi_pac_strip_key(uintptr_t raw, rhi_pac_key_t key)
{
#if defined(__arm64e__)
	switch (key) {
		case RHI_PAC_KEY_IB: return (uintptr_t)ptrauth_strip((void *)raw, ptrauth_key_asib);
		case RHI_PAC_KEY_DA: return (uintptr_t)ptrauth_strip((void *)raw, ptrauth_key_asda);
		case RHI_PAC_KEY_DB: return (uintptr_t)ptrauth_strip((void *)raw, ptrauth_key_asdb);
		case RHI_PAC_KEY_IA:
		default: return (uintptr_t)ptrauth_strip((void *)raw, ptrauth_key_asia);
	}
#else
	(void)key;
	return raw;
#endif
}

static uintptr_t rhi_pac_sign_key(uintptr_t value, rhi_pac_key_t key, uintptr_t discriminator)
{
#if defined(__arm64e__)
	switch (key) {
		case RHI_PAC_KEY_IB:
			return (uintptr_t)ptrauth_sign_unauthenticated((void *)value, ptrauth_key_asib, discriminator);
		case RHI_PAC_KEY_DA:
			return (uintptr_t)ptrauth_sign_unauthenticated((void *)value, ptrauth_key_asda, discriminator);
		case RHI_PAC_KEY_DB:
			return (uintptr_t)ptrauth_sign_unauthenticated((void *)value, ptrauth_key_asdb, discriminator);
		case RHI_PAC_KEY_IA:
		default:
			return (uintptr_t)ptrauth_sign_unauthenticated((void *)value, ptrauth_key_asia, discriminator);
	}
#else
	(void)key;
	(void)discriminator;
	return value;
#endif
}

/* A chained authenticated pointer is valid only if re-signing its stripped
 * payload with the exact file-recorded schema reproduces the raw live word. */
static bool rhi_slot_schema_matches(uintptr_t raw, const rhi_pac_schema_t *schema, void **slot)
{
	if (!schema || !schema->authenticated) return true;
	return rhi_pac_sign_key(rhi_pac_strip_key(raw, schema->key), schema->key,
	                        rhi_pac_discriminator(schema, slot)) == raw;
}

static uintptr_t rhi_slot_target(void **slot, const rhi_pac_schema_t *schema)
{
	const uintptr_t raw = __atomic_load_n((uintptr_t *)slot, __ATOMIC_ACQUIRE);
	if (!schema || !schema->authenticated) return rhi_strip_function((void *)raw);
	if (!rhi_slot_schema_matches(raw, schema, slot)) return 0;
	return rhi_pac_strip_key(raw, schema->key);
}

static bool rhi_checked_adjust(uintptr_t value, int64_t addend, bool increase, uintptr_t *out)
{
	if (!out) return false;
	const uint64_t magnitude = addend < 0
		? (uint64_t)(-(addend + 1)) + 1U : (uint64_t)addend;
	const bool add = (addend >= 0) == increase;
	if (add) {
		if (magnitude > UINTPTR_MAX - value) return false;
		*out = value + (uintptr_t)magnitude;
	} else {
		if (magnitude > value) return false;
		*out = value - (uintptr_t)magnitude;
	}
	return true;
}

static bool rhi_slot_replacement(void **slot, const rhi_pac_schema_t *schema,
	                              void *replacement, int64_t addend, uintptr_t *raw_out)
{
	if (!slot || !replacement || !raw_out) return false;
	uintptr_t adjusted = 0;
	if (!rhi_checked_adjust(rhi_strip_function(replacement), addend, true, &adjusted)) return false;
	if (!schema || !schema->authenticated) {
		*raw_out = adjusted;
		return true;
	}
	*raw_out = rhi_pac_sign_key(adjusted, schema->key,
	                           rhi_pac_discriminator(schema, slot));
	return true;
}

static bool rhi_safe_add_uintptr(uintptr_t lhs, uint64_t rhs, uintptr_t *out)
{
	if (!out || rhs > UINTPTR_MAX || lhs > UINTPTR_MAX - (uintptr_t)rhs) return false;
	*out = lhs + (uintptr_t)rhs;
	return true;
}

static bool rhi_file_range_contains(uint64_t container_offset, uint64_t container_size,
	                                uint64_t value_offset, uint64_t value_size)
{
	return value_offset >= container_offset &&
	       value_offset - container_offset <= container_size &&
	       value_size <= container_size - (value_offset - container_offset);
}

static bool rhi_legacy_import_metadata_init(
	const struct mach_header *header, uint64_t text_vmaddr,
	const struct segment_command_64 *linkedit,
	const struct symtab_command *symtab,
	const struct dysymtab_command *dysymtab,
	rhi_legacy_import_metadata_t *metadata)
{
	if (!header || !linkedit || !symtab || !dysymtab || !metadata ||
	    linkedit->vmaddr < text_vmaddr || linkedit->filesize > linkedit->vmsize)
		return false;
	uint64_t symbols_size = 0;
	uint64_t indirect_size = 0;
	if (__builtin_mul_overflow((uint64_t)symtab->nsyms, sizeof(struct nlist_64), &symbols_size) ||
	    __builtin_mul_overflow((uint64_t)dysymtab->nindirectsyms, sizeof(uint32_t), &indirect_size) ||
	    !rhi_file_range_contains(linkedit->fileoff, linkedit->filesize, symtab->symoff, symbols_size) ||
	    !rhi_file_range_contains(linkedit->fileoff, linkedit->filesize, symtab->stroff, symtab->strsize) ||
	    !rhi_file_range_contains(linkedit->fileoff, linkedit->filesize,
	                             dysymtab->indirectsymoff, indirect_size))
		return false;
	uintptr_t linkedit_runtime = 0;
	if (!rhi_safe_add_uintptr(rhi_data_address(header), linkedit->vmaddr - text_vmaddr,
	                          &linkedit_runtime))
		return false;
	uintptr_t symbols = 0, strings = 0, indirect = 0;
	if (!rhi_safe_add_uintptr(linkedit_runtime, symtab->symoff - linkedit->fileoff, &symbols) ||
	    !rhi_safe_add_uintptr(linkedit_runtime, symtab->stroff - linkedit->fileoff, &strings) ||
	    !rhi_safe_add_uintptr(linkedit_runtime,
	                          dysymtab->indirectsymoff - linkedit->fileoff, &indirect))
		return false;
	*metadata = (rhi_legacy_import_metadata_t){
		.symbols = (const struct nlist_64 *)symbols,
		.symbol_count = symtab->nsyms,
		.strings = (const char *)strings,
		.string_size = symtab->strsize,
		.indirect_symbols = (const uint32_t *)indirect,
		.indirect_count = dysymtab->nindirectsyms,
	};
	return true;
}

static bool rhi_import_name_matches_spec(const char *symbol, size_t symbol_length,
	                                      const char *spec_name)
{
	if (!symbol || !spec_name) return false;
	const size_t spec_length = strlen(spec_name);
	if (symbol_length == spec_length && memcmp(symbol, spec_name, spec_length) == 0) return true;
	/* Mach-O external names normally gain one leading underscore over the C
	 * spelling.  Some dyld private APIs already begin with one. */
	return symbol_length == spec_length + 1U && symbol[0] == '_' &&
	       memcmp(symbol + 1U, spec_name, spec_length) == 0;
}

typedef enum {
	RHI_IMPORT_NO_MATCH = 0,
	RHI_IMPORT_MATCH,
	RHI_IMPORT_MALFORMED,
} rhi_import_match_t;

static rhi_import_match_t rhi_legacy_slot_hook_index(const rhi_legacy_import_metadata_t *metadata,
                                                  const struct section_64 *section,
                                                  size_t slot_index,
                                                  const rhi_rebind_transaction_t *transaction,
                                                  size_t *hook_index_out, bool *weak_out)
{
	if (!metadata || !section || !transaction || !hook_index_out || !weak_out ||
	    slot_index > UINT32_MAX || section->reserved1 > UINT32_MAX - (uint32_t)slot_index)
		return RHI_IMPORT_MALFORMED;
	const uint32_t indirect_index = section->reserved1 + (uint32_t)slot_index;
	if (indirect_index >= metadata->indirect_count) return RHI_IMPORT_MALFORMED;
	const uint32_t symbol_index = metadata->indirect_symbols[indirect_index];
	if ((symbol_index & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) != 0 ||
	    symbol_index >= metadata->symbol_count) {
		return (symbol_index & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS))
			? RHI_IMPORT_NO_MATCH : RHI_IMPORT_MALFORMED;
	}
	const struct nlist_64 *symbol = &metadata->symbols[symbol_index];
	if (symbol->n_un.n_strx >= metadata->string_size) return RHI_IMPORT_MALFORMED;
	const char *name = metadata->strings + symbol->n_un.n_strx;
	const size_t remaining = metadata->string_size - symbol->n_un.n_strx;
	const char *terminator = memchr(name, '\0', remaining);
	if (!terminator) return RHI_IMPORT_MALFORMED;
	const size_t name_length = (size_t)(terminator - name);
	for (size_t hook = 0; hook < transaction->hook_count; hook++) {
		if (rhi_import_name_matches_spec(name, name_length, transaction->hooks[hook].name)) {
			*hook_index_out = hook;
			*weak_out = (symbol->n_desc & N_WEAK_REF) != 0;
			return RHI_IMPORT_MATCH;
		}
	}
	return RHI_IMPORT_NO_MATCH;
}

static bool rhi_validate_header(const struct mach_header_64 *header,
	                            const uint8_t **commands_out,
	                            const uint8_t **commands_end_out)
{
	if (!header || header->magic != MH_MAGIC_64 || header->ncmds > 8192U) return false;
	const uint8_t *commands = (const uint8_t *)(header + 1);
	uintptr_t end_address = 0;
	if (__builtin_add_overflow(rhi_data_address(commands), (uintptr_t)header->sizeofcmds,
	                           &end_address)) return false;
	const uint8_t *end = (const uint8_t *)end_address;
	uintptr_t cursor = rhi_data_address(commands);
	for (uint32_t i = 0; i < header->ncmds; i++) {
		if (cursor > end_address || end_address - cursor < sizeof(struct load_command)) return false;
		const struct load_command *command = (const struct load_command *)cursor;
		if (command->cmdsize < sizeof(*command) || command->cmdsize > end_address - cursor) return false;
		cursor += command->cmdsize;
	}
	if (commands_out) *commands_out = commands;
	if (commands_end_out) *commands_end_out = end;
	return true;
}

static bool rhi_section_name_equals(const char value[16], const char *name)
{
	return strncmp(value, name, 16) == 0;
}

static bool rhi_slot_section_supported(const struct section_64 *section)
{
	if (!section) return false;
	uint32_t type = section->flags & SECTION_TYPE;
	if (type != S_LAZY_SYMBOL_POINTERS && type != S_NON_LAZY_SYMBOL_POINTERS) return false;
	return rhi_section_name_equals(section->sectname, "__got") ||
	       rhi_section_name_equals(section->sectname, "__auth_got") ||
	       rhi_section_name_equals(section->sectname, "__la_symbol_ptr") ||
	       rhi_section_name_equals(section->sectname, "__nl_symbol_ptr");
}

static bool rhi_slot_is_authenticated(const struct section_64 *section)
{
	return rhi_section_name_equals(section->sectname, "__auth_got");
}

static bool rhi_transaction_ensure_slots(rhi_rebind_transaction_t *transaction, size_t needed)
{
	if (needed <= transaction->slot_capacity) return true;
	if (needed > RHI_REBIND_MAX_SLOTS || needed > SIZE_MAX / sizeof(*transaction->slots)) return false;
	size_t capacity = transaction->slot_capacity ? transaction->slot_capacity : 128U;
	while (capacity < needed) {
		if (capacity > RHI_REBIND_MAX_SLOTS / 2U) {
			capacity = RHI_REBIND_MAX_SLOTS;
			break;
		}
		capacity *= 2U;
	}
	rhi_rebind_slot_t *slots = realloc(transaction->slots, capacity * sizeof(*slots));
	if (!slots) return false;
	transaction->slots = slots;
	transaction->slot_capacity = capacity;
	return true;
}

static bool rhi_transaction_ensure_images(rhi_rebind_transaction_t *transaction, size_t needed)
{
	if (needed <= transaction->known_image_capacity) return true;
	if (needed > RHI_REBIND_MAX_IMAGES || needed > SIZE_MAX / sizeof(*transaction->known_images)) return false;
	size_t capacity = transaction->known_image_capacity ? transaction->known_image_capacity : 32U;
	while (capacity < needed) {
		if (capacity > RHI_REBIND_MAX_IMAGES / 2U) {
			capacity = RHI_REBIND_MAX_IMAGES;
			break;
		}
		capacity *= 2U;
	}
	rhi_image_identity_t *images = realloc(transaction->known_images, capacity * sizeof(*images));
	if (!images) return false;
	transaction->known_images = images;
	transaction->known_image_capacity = capacity;
	return true;
}

static bool rhi_image_identity_equal(const rhi_image_identity_t *lhs,
	                                  const rhi_image_identity_t *rhs)
{
	return lhs && rhs && lhs->header == rhs->header && lhs->slide == rhs->slide &&
	       memcmp(lhs->uuid, rhs->uuid, sizeof(lhs->uuid)) == 0;
}

static bool rhi_transaction_has_image(const rhi_rebind_transaction_t *transaction,
	                                  const rhi_image_identity_t *identity)
{
	for (size_t i = 0; i < transaction->known_image_count; i++) {
		if (rhi_image_identity_equal(&transaction->known_images[i], identity)) return true;
	}
	return false;
}

static bool rhi_transaction_add_image(rhi_rebind_transaction_t *transaction,
	                                  const rhi_image_identity_t *identity)
{
	if (!identity || !identity->header) return false;
	if (rhi_transaction_has_image(transaction, identity)) return true;
	if (!rhi_transaction_ensure_images(transaction, transaction->known_image_count + 1U)) return false;
	transaction->known_images[transaction->known_image_count++] = *identity;
	return true;
}

static bool rhi_transaction_add_slot(rhi_rebind_transaction_t *transaction,
	                                 size_t hook_index, void **address,
	                                 const rhi_pac_schema_t *schema,
	                                 int64_t addend,
	                                 const rhi_image_identity_t *image)
{
	if (!address || ((uintptr_t)address % _Alignof(uintptr_t)) != 0 ||
	    !schema || !image || !image->header || hook_index >= transaction->hook_count) return false;
	for (size_t i = 0; i < transaction->slot_count; i++) {
		if (transaction->slots[i].address == address) {
			/* Keep stale ledger artifacts after dlclose, but do not mistake a
			 * later mapping reusing the virtual address for the unloaded slot. */
			if (!transaction->slots[i].image.header) continue;
			/* One slot cannot honestly stand for two distinct hook targets. */
			return rhi_image_identity_equal(&transaction->slots[i].image, image) &&
			       transaction->slots[i].hook_index == hook_index &&
			       transaction->slots[i].schema.authenticated == schema->authenticated &&
			       transaction->slots[i].schema.key == schema->key &&
			       transaction->slots[i].schema.diversity == schema->diversity &&
			       transaction->slots[i].schema.address_diversity == schema->address_diversity &&
			       transaction->slots[i].addend == addend;
		}
	}
	if (!rhi_transaction_ensure_slots(transaction, transaction->slot_count + 1U)) return false;
	rhi_rebind_hook_t *hook = &transaction->hooks[hook_index];
	uintptr_t replacement_raw = 0;
	if (!rhi_slot_replacement(address, schema, hook->replacement, addend, &replacement_raw)) return false;
	const uintptr_t raw = __atomic_load_n((uintptr_t *)address, __ATOMIC_ACQUIRE);
	uintptr_t predecessor = rhi_slot_target(address, schema);
	if (predecessor == 0 || !rhi_checked_adjust(predecessor, addend, false, &predecessor)) return false;
	if (predecessor != rhi_strip_function(hook->replacee)) return false;
	if (hook->predecessor_set && hook->predecessor != predecessor) return false;
	hook->predecessor = predecessor;
	hook->predecessor_set = true;
	transaction->slots[transaction->slot_count++] = (rhi_rebind_slot_t){
		.address = address,
		.image = *image,
		.original_raw = raw,
		.replacement_raw = replacement_raw,
		.hook_index = hook_index,
		.schema = *schema,
		.addend = addend,
	};
	hook->slot_count++;
	return true;
}

typedef struct {
	uint64_t vmaddr;
	uint64_t vmsize;
	uint64_t fileoff;
	uint64_t filesize;
	char name[17];
} rhi_segment_t;

typedef struct {
	rhi_segment_t entries[RHI_REBIND_MAX_SEGMENTS];
	size_t count;
	uint64_t preferred_vmaddr;
} rhi_image_layout_t;

typedef struct {
	const uint8_t *base;
	size_t size;
	bool mapped;
} rhi_file_view_t;

typedef struct {
	const uint8_t *blob;
	size_t size;
	uint32_t starts_offset;
	uint32_t imports_offset;
	uint32_t symbols_offset;
	uint32_t imports_count;
	uint32_t imports_format;
	uint32_t import_size;
} rhi_chained_fixups_t;

typedef struct {
	const char *name;
	int32_t library_ordinal;
	bool weak;
	int64_t addend;
} rhi_chained_import_t;

typedef struct {
	bool bind;
	bool authenticated;
	uint32_t ordinal;
	uint32_t next;
	uint8_t key;
	uint16_t diversity;
	bool address_diversity;
	int64_t addend;
} rhi_chained_pointer_t;

static uint16_t rhi_read_u16(const uint8_t *p) { uint16_t v; memcpy(&v, p, sizeof(v)); return v; }
static uint32_t rhi_read_u32(const uint8_t *p) { uint32_t v; memcpy(&v, p, sizeof(v)); return v; }
static uint64_t rhi_read_u64(const uint8_t *p) { uint64_t v; memcpy(&v, p, sizeof(v)); return v; }
static uint32_t rhi_read_be32(const uint8_t *p) {
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static uint64_t rhi_read_be64(const uint8_t *p) {
	return ((uint64_t)rhi_read_be32(p) << 32) | rhi_read_be32(p + 4);
}

static bool rhi_validate_file_header(const uint8_t *base, size_t size,
	                                  const struct mach_header_64 **header_out)
{
	if (!base || size < sizeof(struct mach_header_64)) return false;
	const struct mach_header_64 *header = (const struct mach_header_64 *)(const void *)base;
	if (header->magic != MH_MAGIC_64 || header->sizeofcmds > size - sizeof(*header) ||
	    !rhi_validate_header(header, NULL, NULL)) return false;
	if (header_out) *header_out = header;
	return true;
}

static bool rhi_copy_uuid(const struct mach_header_64 *header, uint8_t uuid[16])
{
	const uint8_t *commands = NULL;
	const uint8_t *end = NULL;
	if (!header || !uuid || !rhi_validate_header(header, &commands, &end)) return false;
	const uint8_t *cursor = commands;
	bool found = false;
	for (uint32_t i = 0; i < header->ncmds; i++) {
		const struct load_command *command = (const struct load_command *)(const void *)cursor;
		if (command->cmd == LC_UUID) {
			if (found || command->cmdsize < sizeof(struct uuid_command)) return false;
			memcpy(uuid, ((const struct uuid_command *)(const void *)command)->uuid, 16);
			found = true;
		}
		cursor += command->cmdsize;
		if (cursor > end) return false;
	}
	return found;
}

static bool rhi_live_identity(const struct mach_header *unstripped, intptr_t slide,
	                          rhi_image_identity_t *identity)
{
	const struct mach_header *header = rhi_strip_header(unstripped);
	if (!header || !identity) return false;
	const struct mach_header_64 *header64 = (const struct mach_header_64 *)(const void *)header;
	if (!rhi_validate_header(header64, NULL, NULL) || !rhi_copy_uuid(header64, identity->uuid)) return false;
	identity->header = header;
	identity->slide = slide;
	return true;
}

static bool rhi_collect_layout(const struct mach_header_64 *header, rhi_image_layout_t *layout)
{
	const uint8_t *commands = NULL;
	const uint8_t *end = NULL;
	if (!header || !layout || !rhi_validate_header(header, &commands, &end)) return false;
	memset(layout, 0, sizeof(*layout));
	layout->preferred_vmaddr = UINT64_MAX;
	const uint8_t *cursor = commands;
	for (uint32_t i = 0; i < header->ncmds; i++) {
		const struct load_command *command = (const struct load_command *)(const void *)cursor;
		if (command->cmd == LC_SEGMENT_64) {
			if (command->cmdsize < sizeof(struct segment_command_64) ||
			    layout->count == RHI_REBIND_MAX_SEGMENTS) return false;
			const struct segment_command_64 *segment = (const struct segment_command_64 *)(const void *)command;
			if (segment->nsects > (command->cmdsize - sizeof(*segment)) / sizeof(struct section_64) ||
			    segment->filesize > segment->vmsize) return false;
			rhi_segment_t *out = &layout->entries[layout->count++];
			out->vmaddr = segment->vmaddr;
			out->vmsize = segment->vmsize;
			out->fileoff = segment->fileoff;
			out->filesize = segment->filesize;
			memcpy(out->name, segment->segname, 16);
			out->name[16] = '\0';
			if (strncmp(segment->segname, SEG_PAGEZERO, 16) != 0 && segment->vmsize &&
			    segment->vmaddr < layout->preferred_vmaddr)
				layout->preferred_vmaddr = segment->vmaddr;
		}
		cursor += command->cmdsize;
		if (cursor > end) return false;
	}
	return layout->count && layout->preferred_vmaddr != UINT64_MAX;
}

static bool rhi_layouts_agree(const rhi_image_layout_t *live, const rhi_image_layout_t *file)
{
	if (!live || !file || live->count != file->count ||
	    live->preferred_vmaddr != file->preferred_vmaddr) return false;
	for (size_t i = 0; i < live->count; i++) {
		if (live->entries[i].vmaddr != file->entries[i].vmaddr ||
		    live->entries[i].vmsize != file->entries[i].vmsize ||
		    live->entries[i].fileoff != file->entries[i].fileoff ||
		    live->entries[i].filesize != file->entries[i].filesize ||
		    memcmp(live->entries[i].name, file->entries[i].name, 16) != 0) return false;
	}
	return true;
}

static bool rhi_open_file_view(const char *path, rhi_file_view_t *view)
{
	if (!view || !path || !*path) return false;
	memset(view, 0, sizeof(*view));
	const int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return false;
	struct stat st = {0};
	if (fstat(fd, &st) != 0 || st.st_size <= 0 || (uint64_t)st.st_size > SIZE_MAX) {
		close(fd);
		return false;
	}
	void *mapped = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (mapped == MAP_FAILED) return false;
	view->base = mapped;
	view->size = (size_t)st.st_size;
	view->mapped = true;
	return true;
}

static void rhi_close_file_view(rhi_file_view_t *view)
{
	if (view && view->mapped) munmap((void *)view->base, view->size);
	if (view) memset(view, 0, sizeof(*view));
}

static bool rhi_select_file_slice(const rhi_file_view_t *view, cpu_type_t cputype,
	                              cpu_subtype_t cpusubtype, const uint8_t **slice_out,
	                              size_t *slice_size_out)
{
	if (!view || !view->base || !slice_out || !slice_size_out || view->size < 4) return false;
	const struct mach_header_64 *thin = NULL;
	if (rhi_validate_file_header(view->base, view->size, &thin)) {
		if (thin->cputype != cputype || thin->cpusubtype != cpusubtype) return false;
		*slice_out = view->base;
		*slice_size_out = view->size;
		return true;
	}
	if (view->size < 8) return false;
	const uint32_t magic = rhi_read_be32(view->base);
	const bool fat64 = magic == FAT_MAGIC_64;
	if (magic != FAT_MAGIC && !fat64) return false;
	const uint32_t count = rhi_read_be32(view->base + 4);
	const size_t stride = fat64 ? 32U : 20U;
	if ((uint64_t)count * stride > view->size - 8U) return false;
	for (uint32_t i = 0; i < count; i++) {
		const uint8_t *arch = view->base + 8U + (size_t)i * stride;
		if (rhi_read_be32(arch) != (uint32_t)cputype ||
		    rhi_read_be32(arch + 4) != (uint32_t)cpusubtype) continue;
		const uint64_t offset = fat64 ? rhi_read_be64(arch + 8) : rhi_read_be32(arch + 8);
		const uint64_t size = fat64 ? rhi_read_be64(arch + 16) : rhi_read_be32(arch + 12);
		if (offset > view->size || size > view->size - offset || size > SIZE_MAX) return false;
		const struct mach_header_64 *selected = NULL;
		if (!rhi_validate_file_header(view->base + (size_t)offset, (size_t)size, &selected) ||
		    selected->cputype != cputype || selected->cpusubtype != cpusubtype) return false;
		*slice_out = view->base + (size_t)offset;
		*slice_size_out = (size_t)size;
		return true;
	}
	return false;
}

static bool rhi_range_is_mapped(uintptr_t address, size_t size)
{
	if (!address || !size || address > UINTPTR_MAX - size) return false;
	mach_vm_address_t cursor = address;
	const mach_vm_address_t end = address + size;
	for (unsigned tries = 0; tries < 32 && cursor < end; tries++) {
		mach_vm_address_t region = cursor;
		mach_vm_size_t region_size = 0;
		natural_t depth = 0;
		vm_region_submap_info_data_64_t info = {0};
		mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
		if (mach_vm_region_recurse(mach_task_self(), &region, &region_size, &depth,
		                           (vm_region_recurse_info_t)&info, &info_count) != KERN_SUCCESS ||
		    info.is_submap || region > cursor || !region_size || region > UINTPTR_MAX - region_size)
			return false;
		const mach_vm_address_t region_end = region + region_size;
		if (region_end <= cursor) return false;
		cursor = region_end < end ? region_end : end;
	}
	return cursor == end;
}

static int64_t rhi_sign_extend(uint64_t value, unsigned bits)
{
	const uint64_t sign = UINT64_C(1) << (bits - 1U);
	return (int64_t)((value ^ sign) - sign);
}

static uint32_t rhi_chain_stride(uint16_t format)
{
	switch (format) {
		case RHI_CHAINED_PTR_ARM64E:
		case RHI_CHAINED_PTR_ARM64E_USERLAND:
		case RHI_CHAINED_PTR_ARM64E_USERLAND24: return 8U;
		case RHI_CHAINED_PTR_64:
		case RHI_CHAINED_PTR_64_OFFSET: return 4U;
		default: return 0;
	}
}

static bool rhi_chain_is_arm64e(uint16_t format)
{
	return format == RHI_CHAINED_PTR_ARM64E || format == RHI_CHAINED_PTR_ARM64E_USERLAND ||
	       format == RHI_CHAINED_PTR_ARM64E_USERLAND24;
}

static void rhi_decode_chain_pointer(uint64_t raw, uint16_t format, rhi_chained_pointer_t *out)
{
	memset(out, 0, sizeof(*out));
	if (rhi_chain_is_arm64e(format)) {
		out->authenticated = ((raw >> 63) & 1U) != 0;
		out->bind = ((raw >> 62) & 1U) != 0;
		out->next = (uint32_t)((raw >> 51) & 0x7ffU);
		out->ordinal = format == RHI_CHAINED_PTR_ARM64E_USERLAND24
			? (uint32_t)(raw & 0xffffffU) : (uint32_t)(raw & 0xffffU);
		if (out->bind && out->authenticated) {
			out->diversity = (uint16_t)((raw >> 32) & 0xffffU);
			out->address_diversity = ((raw >> 48) & 1U) != 0;
			out->key = (uint8_t)((raw >> 49) & 3U);
		} else if (out->bind) {
			out->addend = rhi_sign_extend((raw >> 32) & 0x7ffffU, 19U);
		}
	} else {
		out->bind = ((raw >> 63) & 1U) != 0;
		out->next = (uint32_t)((raw >> 51) & 0xfffU);
		out->ordinal = (uint32_t)(raw & 0xffffffU);
		if (out->bind) out->addend = (int64_t)((raw >> 24) & 0xffU);
	}
}

static bool rhi_parse_chained_fixups(const uint8_t *blob, size_t size, rhi_chained_fixups_t *out)
{
	if (!blob || !out || size < RHI_CHAINED_HEADER_SIZE) return false;
	memset(out, 0, sizeof(*out));
	const uint32_t version = rhi_read_u32(blob);
	out->starts_offset = rhi_read_u32(blob + 4);
	out->imports_offset = rhi_read_u32(blob + 8);
	out->symbols_offset = rhi_read_u32(blob + 12);
	out->imports_count = rhi_read_u32(blob + 16);
	out->imports_format = rhi_read_u32(blob + 20);
	if (version != 0 || rhi_read_u32(blob + 24) != RHI_CHAINED_SYMBOLS_UNCOMPRESSED) return false;
	switch (out->imports_format) {
		case RHI_CHAINED_IMPORT: out->import_size = 4; break;
		case RHI_CHAINED_IMPORT_ADDEND: out->import_size = 8; break;
		case RHI_CHAINED_IMPORT_ADDEND64: out->import_size = 16; break;
		default: return false;
	}
	if (out->starts_offset > size || out->imports_offset > size || out->symbols_offset > size ||
	    (uint64_t)out->imports_count * out->import_size > size - out->imports_offset) return false;
	out->blob = blob;
	out->size = size;
	return true;
}

static bool rhi_chained_import_at(const rhi_chained_fixups_t *fixups, uint32_t index,
	                              rhi_chained_import_t *out)
{
	if (!fixups || !out || index >= fixups->imports_count) return false;
	const uint8_t *entry = fixups->blob + fixups->imports_offset + (size_t)index * fixups->import_size;
	uint64_t name_offset = 0;
	memset(out, 0, sizeof(*out));
	if (fixups->imports_format == RHI_CHAINED_IMPORT ||
	    fixups->imports_format == RHI_CHAINED_IMPORT_ADDEND) {
		const uint32_t word = rhi_read_u32(entry);
		out->library_ordinal = (int32_t)(int8_t)(uint8_t)word;
		out->weak = ((word >> 8) & 1U) != 0;
		name_offset = (word >> 9) & 0x7fffffU;
		if (fixups->imports_format == RHI_CHAINED_IMPORT_ADDEND) {
			int32_t addend = 0;
			memcpy(&addend, entry + 4, sizeof(addend));
			out->addend = addend;
		}
	} else {
		const uint64_t word = rhi_read_u64(entry);
		out->library_ordinal = (int32_t)(int16_t)(uint16_t)word;
		out->weak = ((word >> 16) & 1U) != 0;
		name_offset = word >> 32;
		out->addend = (int64_t)rhi_read_u64(entry + 8);
	}
	const size_t symbols_size = fixups->size - fixups->symbols_offset;
	if (name_offset >= symbols_size) return false;
	const char *name = (const char *)fixups->blob + fixups->symbols_offset + (size_t)name_offset;
	if (!memchr(name, '\0', symbols_size - (size_t)name_offset)) return false;
	out->name = name;
	return true;
}

static bool rhi_chained_imports_validate(const rhi_chained_fixups_t *fixups)
{
	for (uint32_t i = 0; i < fixups->imports_count; i++) {
		rhi_chained_import_t ignored;
		if (!rhi_chained_import_at(fixups, i, &ignored)) return false;
	}
	return true;
}

static bool rhi_find_image_path(const rhi_image_identity_t *identity, const char **path_out)
{
	if (!identity || !path_out) return false;
	for (uint32_t i = 0; i < _dyld_image_count(); i++) {
		if (rhi_strip_header(_dyld_get_image_header(i)) == identity->header &&
		    _dyld_get_image_vmaddr_slide(i) == identity->slide) {
			const char *path = _dyld_get_image_name(i);
			if (path && *path) { *path_out = path; return true; }
		}
	}
	return false;
}

static bool rhi_image_in_shared_cache(const rhi_image_identity_t *identity)
{
	if (!identity || !_dyld_get_shared_cache_range) return false;
	size_t length = 0;
	const uintptr_t base = (uintptr_t)_dyld_get_shared_cache_range(&length);
	const uintptr_t header = (uintptr_t)identity->header;
	return base && length && header >= base && header - base < length;
}

typedef struct {
	rhi_rebind_transaction_t *transaction;
	const rhi_chained_fixups_t *fixups;
	const rhi_image_identity_t *identity;
	const rhi_image_layout_t *layout;
	bool failed;
} rhi_chain_visit_t;

static bool rhi_chain_add_bind(rhi_chain_visit_t *visit, uint64_t slot_offset,
	                           uint32_t ordinal, const rhi_pac_schema_t *schema,
	                           int64_t pointer_addend)
{
	rhi_chained_import_t import;
	if (!rhi_chained_import_at(visit->fixups, ordinal, &import)) return false;
	if ((pointer_addend > 0 && import.addend > INT64_MAX - pointer_addend) ||
	    (pointer_addend < 0 && import.addend < INT64_MIN - pointer_addend)) return false;
	const int64_t combined_addend = import.addend + pointer_addend;
	for (size_t i = 0; i < visit->transaction->hook_count; i++) {
		if (!rhi_import_name_matches_spec(import.name, strlen(import.name), visit->transaction->hooks[i].name)) continue;
		if (slot_offset > UINTPTR_MAX || slot_offset > SIZE_MAX ||
		    (uintptr_t)visit->identity->header > UINTPTR_MAX - (uintptr_t)slot_offset) return false;
		void **slot = (void **)((uintptr_t)visit->identity->header + (uintptr_t)slot_offset);
		if (((uintptr_t)slot % _Alignof(uintptr_t)) != 0 ||
		    !rhi_range_is_mapped((uintptr_t)slot, sizeof(uintptr_t))) return false;
		const uintptr_t raw = __atomic_load_n((uintptr_t *)slot, __ATOMIC_ACQUIRE);
		/* An unresolved weak import has no callable predecessor. It is cleanly
		 * monitored for later images instead of fabricating an interposition. */
		if (raw == 0 && import.weak && combined_addend == 0) continue;
		if (!rhi_transaction_add_slot(visit->transaction, i, slot, schema,
		                              combined_addend, visit->identity)) return false;
	}
	return true;
}

static bool rhi_walk_chained_image(rhi_rebind_transaction_t *transaction,
                               const rhi_chained_fixups_t *fixups,
                               const rhi_image_identity_t *identity,
                               const rhi_image_layout_t *layout,
                               const uint8_t *file_base, size_t file_size)
{
	if (!transaction || !fixups || !identity || !layout || !file_base ||
	    fixups->starts_offset > fixups->size || fixups->size - fixups->starts_offset < 4) return false;
	const uint8_t *starts = fixups->blob + fixups->starts_offset;
	const uint32_t segment_count = rhi_read_u32(starts);
	if ((uint64_t)segment_count * 4U > fixups->size - fixups->starts_offset - 4U ||
	    segment_count > layout->count) return false;
	rhi_chain_visit_t visit = { .transaction = transaction, .fixups = fixups,
		.identity = identity, .layout = layout };
	for (uint32_t segment_index = 0; segment_index < segment_count; segment_index++) {
		const uint32_t relative = rhi_read_u32(starts + 4U + (size_t)segment_index * 4U);
		if (!relative) continue;
		if (relative > fixups->size - fixups->starts_offset ||
		    fixups->size - fixups->starts_offset - relative < 22U) return false;
		const uint8_t *info = starts + relative;
		const uint32_t declared = rhi_read_u32(info);
		const uint16_t page_size = rhi_read_u16(info + 4);
		const uint16_t format = rhi_read_u16(info + 6);
		const uint64_t segment_offset = rhi_read_u64(info + 8);
		const uint16_t page_count = rhi_read_u16(info + 20);
		const uint32_t stride = rhi_chain_stride(format);
		const rhi_segment_t *segment = &layout->entries[segment_index];
		if (!page_size || !stride || page_count > RHI_REBIND_MAX_CHAIN_PAGES ||
		    declared < 22U || (uint64_t)declared - 22U < (uint64_t)page_count * 2U ||
		    declared > fixups->size - (size_t)(info - fixups->blob) ||
		    segment->vmaddr < layout->preferred_vmaddr ||
		    segment_offset != segment->vmaddr - layout->preferred_vmaddr ||
		    (uint64_t)page_count * page_size > segment->vmsize ||
		    segment->fileoff > file_size || segment->filesize > file_size - segment->fileoff) return false;
		const uint8_t *page_starts = info + 22;
		const size_t starts_count = ((size_t)declared - 22U) / 2U;
		for (uint16_t page = 0; page < page_count; page++) {
			uint16_t start = rhi_read_u16(page_starts + (size_t)page * 2U);
			if (start == RHI_CHAINED_PAGE_START_NONE) continue;
			uint32_t multi_index = 0;
			uint32_t multi_limit = 1;
			if (start & RHI_CHAINED_PAGE_START_MULTI) {
				multi_index = start & ~RHI_CHAINED_PAGE_START_MULTI;
				multi_limit = (uint32_t)starts_count;
			} else {
				multi_index = UINT32_MAX;
			}
			for (;;) {
				uint16_t offset = 0;
				bool final = true;
				if (multi_index == UINT32_MAX) offset = start;
				else {
					if (multi_index >= multi_limit) return false;
					const uint16_t value = rhi_read_u16(page_starts + (size_t)multi_index * 2U);
					offset = value & ~RHI_CHAINED_PAGE_START_LAST;
					final = (value & RHI_CHAINED_PAGE_START_LAST) != 0;
				}
				if (offset > page_size || 8U > page_size - offset) return false;
				uint64_t slot_offset = segment_offset + (uint64_t)page * page_size + offset;
				uint64_t steps = 0;
				for (;;) {
					if (slot_offset < segment_offset || slot_offset - segment_offset > segment->filesize ||
					    8U > segment->filesize - (slot_offset - segment_offset) ||
					    slot_offset - segment_offset > segment->vmsize ||
					    8U > segment->vmsize - (slot_offset - segment_offset)) return false;
					const uint64_t file_offset = segment->fileoff + (slot_offset - segment_offset);
					if (file_offset > file_size || 8U > file_size - file_offset) return false;
					const uint64_t raw = rhi_read_u64(file_base + (size_t)file_offset);
					rhi_chained_pointer_t pointer;
					rhi_decode_chain_pointer(raw, format, &pointer);
					if (pointer.bind) {
						if (pointer.ordinal >= fixups->imports_count || (pointer.authenticated && pointer.key > RHI_PAC_KEY_DB)) return false;
						const rhi_pac_schema_t schema = {
							.authenticated = pointer.authenticated,
							.key = (rhi_pac_key_t)pointer.key,
							.diversity = pointer.diversity,
							.address_diversity = pointer.address_diversity,
						};
						if (!rhi_chain_add_bind(&visit, slot_offset, pointer.ordinal, &schema,
						                        pointer.addend)) return false;
					}
					if (!pointer.next) break;
					const uint64_t advance = (uint64_t)pointer.next * stride;
					if (!advance || advance > UINT64_MAX - slot_offset || ++steps > segment->vmsize / stride + 1U) return false;
					slot_offset += advance;
				}
				if (multi_index == UINT32_MAX || final) break;
				multi_index++;
			}
		}
	}
	return !visit.failed;
}

typedef struct {
	size_t slot_count;
	size_t hook_slots[RHI_REBIND_MAX_HOOKS];
	bool predecessor_set[RHI_REBIND_MAX_HOOKS];
	uintptr_t predecessor[RHI_REBIND_MAX_HOOKS];
} rhi_scan_checkpoint_t;

static void rhi_scan_checkpoint(const rhi_rebind_transaction_t *transaction,
	                            rhi_scan_checkpoint_t *checkpoint)
{
	memset(checkpoint, 0, sizeof(*checkpoint));
	checkpoint->slot_count = transaction->slot_count;
	for (size_t i = 0; i < transaction->hook_count; i++) {
		checkpoint->hook_slots[i] = transaction->hooks[i].slot_count;
		checkpoint->predecessor_set[i] = transaction->hooks[i].predecessor_set;
		checkpoint->predecessor[i] = transaction->hooks[i].predecessor;
	}
}

static void rhi_scan_rewind(rhi_rebind_transaction_t *transaction,
	                        const rhi_scan_checkpoint_t *checkpoint)
{
	transaction->slot_count = checkpoint->slot_count;
	for (size_t i = 0; i < transaction->hook_count; i++) {
		transaction->hooks[i].slot_count = checkpoint->hook_slots[i];
		transaction->hooks[i].predecessor_set = checkpoint->predecessor_set[i];
		transaction->hooks[i].predecessor = checkpoint->predecessor[i];
	}
}

static bool rhi_scan_chained_image(rhi_rebind_transaction_t *transaction,
	                               const rhi_image_identity_t *identity,
	                               const rhi_image_layout_t *live_layout)
{
	const char *path = NULL;
	rhi_file_view_t file = {0};
	const uint8_t *slice = NULL;
	size_t slice_size = 0;
	const struct mach_header_64 *file_header = NULL;
	rhi_image_layout_t file_layout;
	uint8_t file_uuid[16];
	const struct linkedit_data_command *chained_command = NULL;
	if (!rhi_find_image_path(identity, &path) || !rhi_open_file_view(path, &file) ||
	    !rhi_select_file_slice(&file, ((const struct mach_header_64 *)identity->header)->cputype,
	                           ((const struct mach_header_64 *)identity->header)->cpusubtype,
	                           &slice, &slice_size) ||
	    !rhi_validate_file_header(slice, slice_size, &file_header) ||
	    !rhi_copy_uuid(file_header, file_uuid) || memcmp(file_uuid, identity->uuid, sizeof(file_uuid)) != 0 ||
	    !rhi_collect_layout(file_header, &file_layout) || !rhi_layouts_agree(live_layout, &file_layout)) {
		rhi_close_file_view(&file);
		return false;
	}
	const uint8_t *commands = NULL;
	const uint8_t *end = NULL;
	if (!rhi_validate_header(file_header, &commands, &end)) {
		rhi_close_file_view(&file);
		return false;
	}
	for (const uint8_t *cursor = commands; cursor < end; ) {
		const struct load_command *command = (const struct load_command *)(const void *)cursor;
		if (command->cmd == LC_DYLD_CHAINED_FIXUPS) {
			if (chained_command || command->cmdsize < sizeof(struct linkedit_data_command)) {
				rhi_close_file_view(&file);
				return false;
			}
			chained_command = (const struct linkedit_data_command *)(const void *)command;
		}
		cursor += command->cmdsize;
	}
	if (!chained_command || chained_command->dataoff > slice_size ||
	    chained_command->datasize > slice_size - chained_command->dataoff) {
		rhi_close_file_view(&file);
		return false;
	}
	rhi_chained_fixups_t fixups;
	if (!rhi_parse_chained_fixups(slice + chained_command->dataoff, chained_command->datasize, &fixups) ||
	    !rhi_chained_imports_validate(&fixups)) {
		rhi_close_file_view(&file);
		return false;
	}
	rhi_scan_checkpoint_t mutable_checkpoint;
	rhi_scan_checkpoint(transaction, &mutable_checkpoint);
	const bool ok = rhi_walk_chained_image(transaction, &fixups, identity, &file_layout, slice, slice_size) &&
	                rhi_transaction_add_image(transaction, identity);
	if (!ok) rhi_scan_rewind(transaction, &mutable_checkpoint);
	rhi_close_file_view(&file);
	return ok;
}

static bool rhi_scan_legacy_image(rhi_rebind_transaction_t *transaction,
	                              const rhi_image_identity_t *identity,
	                              const rhi_image_layout_t *layout)
{
	const struct mach_header_64 *header = (const struct mach_header_64 *)(const void *)identity->header;
	const uint8_t *commands = NULL;
	const uint8_t *end = NULL;
	const struct symtab_command *symtab = NULL;
	const struct dysymtab_command *dysymtab = NULL;
	const struct segment_command_64 *linkedit = NULL;
	if (!rhi_validate_header(header, &commands, &end)) return false;
	for (const uint8_t *cursor = commands; cursor < end; ) {
		const struct load_command *command = (const struct load_command *)(const void *)cursor;
		if (command->cmd == LC_SYMTAB) {
			if (symtab || command->cmdsize < sizeof(*symtab)) return false;
			symtab = (const struct symtab_command *)(const void *)command;
		} else if (command->cmd == LC_DYSYMTAB) {
			if (dysymtab || command->cmdsize < sizeof(*dysymtab)) return false;
			dysymtab = (const struct dysymtab_command *)(const void *)command;
		} else if (command->cmd == LC_SEGMENT_64) {
			const struct segment_command_64 *segment = (const struct segment_command_64 *)(const void *)command;
			if (rhi_section_name_equals(segment->segname, SEG_LINKEDIT)) {
				if (linkedit) return false;
				linkedit = segment;
			}
		}
		cursor += command->cmdsize;
	}
	/* Static/no-import images are cleanly monitored: there are no current
	 * candidate slots, but future load callbacks still use this transaction. */
	if (!symtab && !dysymtab) return rhi_transaction_add_image(transaction, identity);
	if (!symtab || !dysymtab || !linkedit) return false;
	rhi_legacy_import_metadata_t metadata = {0};
	if (!rhi_legacy_import_metadata_init(identity->header, layout->preferred_vmaddr, linkedit,
	                                     symtab, dysymtab, &metadata) ||
	    (metadata.symbol_count && !rhi_range_is_mapped((uintptr_t)metadata.symbols,
	                          (size_t)metadata.symbol_count * sizeof(*metadata.symbols))) ||
	    (metadata.string_size && !rhi_range_is_mapped((uintptr_t)metadata.strings, metadata.string_size)) ||
	    (metadata.indirect_count && !rhi_range_is_mapped((uintptr_t)metadata.indirect_symbols,
	                          (size_t)metadata.indirect_count * sizeof(*metadata.indirect_symbols)))) return false;
	rhi_scan_checkpoint_t checkpoint;
	rhi_scan_checkpoint(transaction, &checkpoint);
	for (const uint8_t *cursor = commands; cursor < end; ) {
		const struct load_command *command = (const struct load_command *)(const void *)cursor;
		if (command->cmd == LC_SEGMENT_64) {
			const struct segment_command_64 *segment = (const struct segment_command_64 *)(const void *)command;
			const struct section_64 *sections = (const struct section_64 *)(const void *)(segment + 1);
			for (uint32_t section_index = 0; section_index < segment->nsects; section_index++) {
				const struct section_64 *section = &sections[section_index];
				if (!rhi_slot_section_supported(section)) continue;
				if (!section->size || section->size % sizeof(void *) ||
				    section->size / sizeof(void *) > RHI_REBIND_MAX_SLOTS_PER_SECTION ||
				    section->addr < segment->vmaddr ||
				    section->addr - segment->vmaddr > segment->vmsize ||
				    section->size > segment->vmsize - (section->addr - segment->vmaddr) ||
				    section->addr < layout->preferred_vmaddr ||
				    section->addr - layout->preferred_vmaddr > UINTPTR_MAX ||
				    (uintptr_t)identity->header > UINTPTR_MAX - (uintptr_t)(section->addr - layout->preferred_vmaddr)) {
					rhi_scan_rewind(transaction, &checkpoint);
					return false;
				}
				void **slots = (void **)((uintptr_t)identity->header +
				                         (uintptr_t)(section->addr - layout->preferred_vmaddr));
				if (((uintptr_t)slots % _Alignof(uintptr_t)) != 0 ||
				    !rhi_range_is_mapped((uintptr_t)slots, (size_t)section->size)) {
					rhi_scan_rewind(transaction, &checkpoint);
					return false;
				}
				const rhi_pac_schema_t schema = {
					.authenticated = rhi_slot_is_authenticated(section),
					.key = RHI_PAC_KEY_IA,
					.address_diversity = rhi_slot_is_authenticated(section),
				};
				for (size_t index = 0; index < section->size / sizeof(void *); index++) {
					size_t hook_index = 0;
					bool weak = false;
					const rhi_import_match_t match = rhi_legacy_slot_hook_index(&metadata, section, index,
					                                                      transaction, &hook_index, &weak);
					if (match == RHI_IMPORT_NO_MATCH) continue;
					if (match == RHI_IMPORT_MATCH && weak &&
					    __atomic_load_n((uintptr_t *)&slots[index], __ATOMIC_ACQUIRE) == 0) continue;
					if (match != RHI_IMPORT_MATCH || !rhi_transaction_add_slot(transaction, hook_index,
					                                                      &slots[index], &schema, 0, identity)) {
						rhi_scan_rewind(transaction, &checkpoint);
						return false;
					}
				}
			}
		}
		cursor += command->cmdsize;
	}
	if (!rhi_transaction_add_image(transaction, identity)) {
		rhi_scan_rewind(transaction, &checkpoint);
		return false;
	}
	return true;
}

static bool rhi_scan_image(rhi_rebind_transaction_t *transaction,
	                       const struct mach_header *header, intptr_t slide)
{
	rhi_image_identity_t identity;
	if (!rhi_live_identity(header, slide, &identity)) return false;
	if (rhi_transaction_has_image(transaction, &identity)) return true;
	for (size_t i = 0; i < transaction->hook_count; i++) {
		if (transaction->hooks[i].replacement_header == identity.header)
			return rhi_transaction_add_image(transaction, &identity);
	}
	rhi_image_layout_t layout;
	if (!rhi_collect_layout((const struct mach_header_64 *)(const void *)identity.header, &layout)) return false;
	const uint8_t *commands = NULL;
	const uint8_t *end = NULL;
	bool has_chained = false;
	if (!rhi_validate_header((const struct mach_header_64 *)(const void *)identity.header, &commands, &end)) return false;
	for (const uint8_t *cursor = commands; cursor < end; ) {
		const struct load_command *command = (const struct load_command *)(const void *)cursor;
		if (command->cmd == LC_DYLD_CHAINED_FIXUPS) {
			if (has_chained || command->cmdsize < sizeof(struct linkedit_data_command)) return false;
			has_chained = true;
		}
		cursor += command->cmdsize;
	}
	/* Cached images have no standalone input bind-chain file to validate. Their
	 * shared-cache patch table is intentionally not guessed from live words;
	 * record a zero-site monitored image and let writable app/bundle images use
	 * the exact file-backed parser below. */
	if (has_chained && rhi_image_in_shared_cache(&identity))
		return rhi_transaction_add_image(transaction, &identity);
	return has_chained ? rhi_scan_chained_image(transaction, &identity, &layout)
	                   : rhi_scan_legacy_image(transaction, &identity, &layout);
}

static bool rhi_transaction_image_snapshot_stable(const rhi_rebind_transaction_t *transaction)
{
	if (!transaction || __atomic_load_n(&g_lifecycle_generation, __ATOMIC_ACQUIRE) !=
	                    __atomic_load_n(&transaction->lifecycle_generation, __ATOMIC_ACQUIRE)) return false;
	const uint32_t image_count = _dyld_image_count();
	if (image_count != transaction->known_image_count || image_count > RHI_REBIND_MAX_IMAGES) return false;
	for (uint32_t i = 0; i < image_count; i++) {
		rhi_image_identity_t identity;
		if (!rhi_live_identity(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i), &identity) ||
		    !rhi_transaction_has_image(transaction, &identity)) return false;
	}
	return __atomic_load_n(&g_lifecycle_generation, __ATOMIC_ACQUIRE) ==
	       __atomic_load_n(&transaction->lifecycle_generation, __ATOMIC_ACQUIRE);
}

static bool rhi_page_protection(void *address, mach_vm_address_t *page_out,
	                            mach_vm_size_t *page_size_out,
	                            vm_prot_t *protection_out)
{
	if (!address || !page_out || !page_size_out || !protection_out) return false;
	vm_size_t page_size = vm_page_size ? vm_page_size : (vm_size_t)getpagesize();
	if (!page_size || ((uintptr_t)address % _Alignof(uintptr_t)) != 0) return false;
	mach_vm_address_t page = (mach_vm_address_t)(uintptr_t)address;
	page -= page % page_size;
	mach_vm_address_t region = page;
	mach_vm_size_t region_size = 0;
	natural_t depth = 0;
	vm_region_submap_info_data_64_t info = {0};
	mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kern_return_t kr = KERN_FAILURE;
	/* Descend through submaps. A parent mapping's protections are not a safe
	 * restoration value for a leaf import page. */
	for (unsigned levels = 0; ; levels++) {
		if (levels == 32U) return false;
		region = page;
		region_size = 0;
		count = VM_REGION_SUBMAP_INFO_COUNT_64;
		kr = mach_vm_region_recurse(mach_task_self(), &region, &region_size,
		                            &depth, (vm_region_recurse_info_t)&info, &count);
		if (kr != KERN_SUCCESS) return false;
		if (!info.is_submap) break;
		depth++;
	}
	/* A slot that straddles a page or leaf mapping is never written. */
	if (region > page || region_size < page - region ||
	    region_size - (page - region) < page_size ||
	    (uintptr_t)address > UINTPTR_MAX - sizeof(uintptr_t) ||
	    (uintptr_t)address + sizeof(uintptr_t) > (uintptr_t)page + page_size) return false;
	*page_out = page;
	*page_size_out = page_size;
	*protection_out = info.protection;
	return true;
}

static rhi_rebind_result_t rhi_write_slot(const rhi_rebind_slot_t *slot)
{
	if (!slot || !slot->address) return RHI_REBIND_NONE;
	if (__atomic_load_n((uintptr_t *)slot->address, __ATOMIC_ACQUIRE) != slot->original_raw) {
		return RHI_REBIND_NONE;
	}
	mach_vm_address_t page = 0;
	mach_vm_size_t page_size = 0;
	vm_prot_t original_protection = 0;
	if (!rhi_page_protection(slot->address, &page, &page_size, &original_protection)) return RHI_REBIND_NONE;
	/* Artifacts stay in the ledger even after a partial/unknown result. */
	((rhi_rebind_slot_t *)slot)->original_protection = original_protection;
	((rhi_rebind_slot_t *)slot)->protection_captured = true;
	kern_return_t kr = mach_vm_protect(mach_task_self(), page, page_size, false,
	                                  original_protection | VM_PROT_WRITE | VM_PROT_COPY);
	if (kr != KERN_SUCCESS) return RHI_REBIND_NONE;
	__atomic_store_n((uintptr_t *)slot->address, slot->replacement_raw, __ATOMIC_RELEASE);
	((rhi_rebind_slot_t *)slot)->wrote = true;
	const uintptr_t readback = __atomic_load_n((uintptr_t *)slot->address, __ATOMIC_ACQUIRE);
	const kern_return_t restore = mach_vm_protect(mach_task_self(), page, page_size,
	                                             false, original_protection);
	if (restore != KERN_SUCCESS || readback != slot->replacement_raw) {
		return RHI_REBIND_UNKNOWN;
	}
	return RHI_REBIND_COMPLETE;
}

static rhi_rebind_result_t rhi_commit_slots(rhi_rebind_transaction_t *transaction,
	                                        size_t start, size_t end)
{
	if (end < start || end > transaction->slot_count) return RHI_REBIND_NONE;
	/* A validated zero-site plan is a clean monitored state, not a failed
	 * mutation: it remains armed for a future image importing this symbol. */
	if (start == end) return RHI_REBIND_COMPLETE;
	os_unfair_lock_lock(&g_writer_lock);
	/* Lifecycle callbacks increment this generation under g_writer_lock, so a
	 * dlclose/address reuse cannot cross this check and a subsequent store. */
	if (!rhi_transaction_image_snapshot_stable(transaction)) {
		os_unfair_lock_unlock(&g_writer_lock);
		return RHI_REBIND_NONE;
	}
	/* Revalidate the whole plan before its first write. */
	for (size_t i = start; i < end; i++) {
		if (__atomic_load_n((uintptr_t *)transaction->slots[i].address, __ATOMIC_ACQUIRE) !=
		    transaction->slots[i].original_raw) {
			os_unfair_lock_unlock(&g_writer_lock);
			return RHI_REBIND_NONE;
		}
	}
	size_t writes = 0;
	for (size_t i = start; i < end; i++) {
		rhi_rebind_result_t result = rhi_write_slot(&transaction->slots[i]);
		if (result == RHI_REBIND_COMPLETE) {
			writes++;
			continue;
		}
		if (result == RHI_REBIND_UNKNOWN) {
			os_unfair_lock_unlock(&g_writer_lock);
			return RHI_REBIND_UNKNOWN;
		}
		os_unfair_lock_unlock(&g_writer_lock);
		return writes ? RHI_REBIND_PARTIAL : RHI_REBIND_NONE;
	}
	os_unfair_lock_unlock(&g_writer_lock);
	return RHI_REBIND_COMPLETE;
}

static void rhi_set_hook_states(rhi_rebind_transaction_t *transaction,
	                            rhi_hook_state_t state)
{
	for (size_t i = 0; i < transaction->hook_count; i++) {
		RHI_STATE_STORE(&transaction->hooks[i].state, state);
	}
}

const char *rhi_hook_state_name(rhi_hook_state_t state)
{
	switch (state) {
		case RHI_HOOK_NOT_ATTEMPTED: return "not-attempted";
		case RHI_HOOK_PREPARED: return "prepared";
		case RHI_HOOK_ACTIVE: return "active";
		case RHI_HOOK_FAILED: return "failed";
		case RHI_HOOK_PARTIAL: return "partial";
		case RHI_HOOK_UNKNOWN: return "unknown";
	}
	return "invalid";
}

const char *rhi_rebind_result_name(rhi_rebind_result_t result)
{
	switch (result) {
		case RHI_REBIND_NONE: return "none";
		case RHI_REBIND_COMPLETE: return "complete";
		case RHI_REBIND_PARTIAL: return "partial";
		case RHI_REBIND_UNKNOWN: return "unknown";
	}
	return "invalid";
}

static void rhi_global_image_added(const struct mach_header *header, intptr_t slide);
static void rhi_global_image_removed(const struct mach_header *header, intptr_t slide);

/* Register lifecycle tracking before the first snapshot, rather than after a
 * commit. add-image replays synchronously, so this establishes an epoch that
 * sees a remove/reload even when it reuses exactly the same virtual address. */
static bool rhi_ensure_lifecycle_callbacks(void)
{
	void (*add)(void (*)(const struct mach_header *, intptr_t)) = NULL;
	void (*remove)(void (*)(const struct mach_header *, intptr_t)) = NULL;
	bool register_now = false;
	os_unfair_lock_lock(&g_global_lock);
	if (!g_native_register_add_image) g_native_register_add_image = _dyld_register_func_for_add_image;
	if (!g_native_register_remove_image) g_native_register_remove_image = _dyld_register_func_for_remove_image;
	if (g_lifecycle_callbacks_registered) {
		os_unfair_lock_unlock(&g_global_lock);
		return true;
	}
	if (!g_lifecycle_callbacks_registering &&
	    g_native_register_add_image && g_native_register_remove_image) {
		g_lifecycle_callbacks_registering = true;
		register_now = true;
		add = g_native_register_add_image;
		remove = g_native_register_remove_image;
	}
	os_unfair_lock_unlock(&g_global_lock);
	/* Another initializer is between registration and add-image's synchronous
	 * replay. Refuse this attempt rather than plan against an incomplete epoch;
	 * a later transaction can retry after the initializer publishes readiness. */
	if (!register_now) return false;
	remove(rhi_global_image_removed);
	add(rhi_global_image_added);
	os_unfair_lock_lock(&g_global_lock);
	g_lifecycle_callbacks_registered = true;
	g_lifecycle_callbacks_registering = false;
	os_unfair_lock_unlock(&g_global_lock);
	return true;
}

rhi_rebind_transaction_t *rhi_rebind_transaction_create(void)
{
	rhi_rebind_transaction_t *transaction = calloc(1, sizeof(*transaction));
	if (!transaction) return NULL;
	transaction->lock = OS_UNFAIR_LOCK_INIT;
	RHI_STATE_STORE(&transaction->state, RHI_HOOK_NOT_ATTEMPTED);
	transaction->result = RHI_REBIND_NONE;
	if (!rhi_ensure_lifecycle_callbacks()) {
		free(transaction);
		return NULL;
	}
	return transaction;
}

static void rhi_transaction_clear(rhi_rebind_transaction_t *transaction)
{
	if (!transaction) return;
	for (size_t i = 0; i < transaction->hook_count; i++) free(transaction->hooks[i].name);
	free(transaction->hooks);
	free(transaction->slots);
	free(transaction->known_images);
	transaction->hooks = NULL;
	transaction->slots = NULL;
	transaction->known_images = NULL;
	transaction->hook_count = 0;
	transaction->slot_count = 0;
	transaction->slot_capacity = 0;
	transaction->known_image_count = 0;
	transaction->known_image_capacity = 0;
}

void rhi_rebind_transaction_destroy(rhi_rebind_transaction_t *transaction)
{
	if (!transaction) return;
	os_unfair_lock_lock(&transaction->lock);
	/* A dyld callback has no unregister API; retain activated ledgers safely. */
	if (transaction->in_global_registry) {
		transaction->global_armed = false;
		transaction->terminal = true;
		RHI_STATE_STORE(&transaction->state, RHI_HOOK_UNKNOWN);
		os_unfair_lock_unlock(&transaction->lock);
		return;
	}
	rhi_transaction_clear(transaction);
	os_unfair_lock_unlock(&transaction->lock);
	free(transaction);
}

bool rhi_rebind_transaction_prepare_global(rhi_rebind_transaction_t *transaction,
	                                       const rhi_rebind_spec_t *specs,
	                                       size_t spec_count)
{
	if (!transaction || !specs || spec_count == 0 || spec_count > RHI_REBIND_MAX_HOOKS) return false;
	/* Keep the single global->transaction lock order used by lifecycle callbacks.
	 * Registration is normally complete at create time; this is a fail-closed
	 * recheck without holding the transaction lock. */
	if (!rhi_ensure_lifecycle_callbacks()) return false;
	os_unfair_lock_lock(&transaction->lock);
	if (transaction->prepared || transaction->terminal || transaction->in_global_registry) {
		os_unfair_lock_unlock(&transaction->lock);
		return false;
	}
	transaction->hooks = calloc(spec_count, sizeof(*transaction->hooks));
	if (!transaction->hooks) goto fail;
	transaction->hook_count = spec_count;
	for (size_t i = 0; i < spec_count; i++) {
		if (!specs[i].name || !specs[i].replacee || !specs[i].replacement) goto fail;
		size_t name_length = strnlen(specs[i].name, 128U);
		if (name_length == 128U) goto fail;
		transaction->hooks[i].name = strndup(specs[i].name, name_length);
		if (!transaction->hooks[i].name) goto fail;
		transaction->hooks[i].replacee = specs[i].replacee;
		transaction->hooks[i].replacement = specs[i].replacement;
		Dl_info info = {0};
		if (!dladdr(specs[i].replacement, &info) || !info.dli_fname) goto fail;
		for (uint32_t image = 0; image < _dyld_image_count(); image++) {
			const char *path = _dyld_get_image_name(image);
			if (path && strcmp(path, info.dli_fname) == 0) {
				transaction->hooks[i].replacement_header = rhi_strip_header(_dyld_get_image_header(image));
				break;
			}
		}
		if (!transaction->hooks[i].replacement_header) goto fail;
	}

	const uint32_t image_count = _dyld_image_count();
	if (image_count > RHI_REBIND_MAX_IMAGES) goto fail;
	RHI_STATE_STORE(&transaction->lifecycle_generation,
	                __atomic_load_n(&g_lifecycle_generation, __ATOMIC_ACQUIRE));
	for (uint32_t image = 0; image < image_count; image++) {
		if (!rhi_scan_image(transaction, _dyld_get_image_header(image),
		                    _dyld_get_image_vmaddr_slide(image))) goto fail;
	}
	if (!rhi_transaction_image_snapshot_stable(transaction)) goto fail;
	transaction->prepared = true;
	RHI_STATE_STORE(&transaction->state, RHI_HOOK_PREPARED);
	rhi_set_hook_states(transaction, RHI_HOOK_PREPARED);
	os_unfair_lock_unlock(&transaction->lock);
	return true;

fail:
	rhi_transaction_clear(transaction);
	RHI_STATE_STORE(&transaction->state, RHI_HOOK_FAILED);
	transaction->result = RHI_REBIND_NONE;
	os_unfair_lock_unlock(&transaction->lock);
	return false;
}

void *rhi_rebind_transaction_original(const rhi_rebind_transaction_t *transaction,
	                                size_t hook_index)
{
	if (!transaction || hook_index >= transaction->hook_count ||
	    RHI_STATE_LOAD(&transaction->state) != RHI_HOOK_PREPARED) return NULL;
	return transaction->hooks[hook_index].replacee;
}

rhi_rebind_result_t rhi_rebind_transaction_commit(rhi_rebind_transaction_t *transaction)
{
	if (!transaction) return RHI_REBIND_NONE;
	os_unfair_lock_lock(&transaction->lock);
	if (!transaction->prepared || RHI_STATE_LOAD(&transaction->state) != RHI_HOOK_PREPARED || transaction->terminal) {
		os_unfair_lock_unlock(&transaction->lock);
		return RHI_REBIND_NONE;
	}
	if (!rhi_transaction_image_snapshot_stable(transaction)) {
		RHI_STATE_STORE(&transaction->state, RHI_HOOK_FAILED);
		transaction->result = RHI_REBIND_NONE;
		rhi_set_hook_states(transaction, RHI_HOOK_FAILED);
		os_unfair_lock_unlock(&transaction->lock);
		return RHI_REBIND_NONE;
	}
	rhi_rebind_result_t result = rhi_commit_slots(transaction, 0, transaction->slot_count);
	transaction->result = result;
	if (result == RHI_REBIND_COMPLETE) {
		RHI_STATE_STORE(&transaction->state, RHI_HOOK_ACTIVE);
		for (size_t i = 0; i < transaction->hook_count; i++) {
			RHI_STATE_STORE(&transaction->hooks[i].state, RHI_HOOK_ACTIVE);
		}
	} else if (result == RHI_REBIND_PARTIAL) {
		RHI_STATE_STORE(&transaction->state, RHI_HOOK_PARTIAL);
		transaction->terminal = true;
		rhi_set_hook_states(transaction, RHI_HOOK_PARTIAL);
	} else if (result == RHI_REBIND_UNKNOWN) {
		RHI_STATE_STORE(&transaction->state, RHI_HOOK_UNKNOWN);
		transaction->terminal = true;
		rhi_set_hook_states(transaction, RHI_HOOK_UNKNOWN);
	} else {
		RHI_STATE_STORE(&transaction->state, RHI_HOOK_FAILED);
		rhi_set_hook_states(transaction, RHI_HOOK_FAILED);
	}
	os_unfair_lock_unlock(&transaction->lock);
	return result;
}

static void rhi_global_image_added(const struct mach_header *header, intptr_t slide)
{
	/* This lock forms the lifecycle/write fence: commit revalidates the epoch
	 * while holding it, and a dyld remove cannot unmap a slot mid-store. */
	os_unfair_lock_lock(&g_writer_lock);
	__atomic_fetch_add(&g_lifecycle_generation, 1U, __ATOMIC_RELEASE);
	os_unfair_lock_unlock(&g_writer_lock);
	rhi_image_identity_t identity;
	if (!rhi_live_identity(header, slide, &identity)) return;
	os_unfair_lock_lock(&g_global_lock);
	for (rhi_rebind_transaction_t *transaction = g_global_transactions;
	     transaction; transaction = transaction->next_global) {
		os_unfair_lock_lock(&transaction->lock);
		if (!transaction->global_armed || transaction->terminal ||
		    RHI_STATE_LOAD(&transaction->state) != RHI_HOOK_ACTIVE ||
		    rhi_transaction_has_image(transaction, &identity)) {
			os_unfair_lock_unlock(&transaction->lock);
			continue;
		}
		const size_t old_slot_count = transaction->slot_count;
		if (!rhi_scan_image(transaction, header, slide)) {
			/* Nothing was written for this image; fail closed for this session. */
			transaction->slot_count = old_slot_count;
			RHI_STATE_STORE(&transaction->state, RHI_HOOK_FAILED);
			rhi_set_hook_states(transaction, RHI_HOOK_FAILED);
			os_unfair_lock_unlock(&transaction->lock);
			continue;
		}
		RHI_STATE_STORE(&transaction->lifecycle_generation,
		                __atomic_load_n(&g_lifecycle_generation, __ATOMIC_ACQUIRE));
		if (!rhi_transaction_image_snapshot_stable(transaction)) {
			RHI_STATE_STORE(&transaction->state, RHI_HOOK_FAILED);
			rhi_set_hook_states(transaction, RHI_HOOK_FAILED);
			os_unfair_lock_unlock(&transaction->lock);
			continue;
		}
		rhi_rebind_result_t result = rhi_commit_slots(transaction, old_slot_count,
	                                            transaction->slot_count);
		if (result == RHI_REBIND_COMPLETE) {
			for (size_t i = 0; i < transaction->hook_count; i++)
				RHI_STATE_STORE(&transaction->hooks[i].state, RHI_HOOK_ACTIVE);
		} else if (result == RHI_REBIND_NONE) {
			/* A candidate slot changed after prepare; do not leave it unhooked. */
			RHI_STATE_STORE(&transaction->state, RHI_HOOK_FAILED);
			rhi_set_hook_states(transaction, RHI_HOOK_FAILED);
		} else if (result == RHI_REBIND_PARTIAL) {
			transaction->result = result;
			RHI_STATE_STORE(&transaction->state, RHI_HOOK_PARTIAL);
			transaction->terminal = true;
			rhi_set_hook_states(transaction, RHI_HOOK_PARTIAL);
		} else {
			transaction->result = result;
			RHI_STATE_STORE(&transaction->state, RHI_HOOK_UNKNOWN);
			transaction->terminal = true;
			rhi_set_hook_states(transaction, RHI_HOOK_UNKNOWN);
		}
		os_unfair_lock_unlock(&transaction->lock);
	}
	os_unfair_lock_unlock(&g_global_lock);
}

/* dyld has no callback unregistration.  Retain the exact write artifacts for
 * diagnostics/repair, but discard unloaded headers and make their slots inert
 * so an address reused by a later dlopen is planned as a new image rather than
 * compared to unmapped memory.  No rollback is safe after constructors may
 * have run. */
static void rhi_global_image_removed(const struct mach_header *header, intptr_t slide)
{
	os_unfair_lock_lock(&g_writer_lock);
	__atomic_fetch_add(&g_lifecycle_generation, 1U, __ATOMIC_RELEASE);
	os_unfair_lock_unlock(&g_writer_lock);
	rhi_image_identity_t removed;
	if (!rhi_live_identity(header, slide, &removed)) {
		/* A remove event whose identity cannot be proven makes every retained
		 * slot ledger suspect. Keep prior writes truthful, but stop advertising
		 * verified interception rather than risk address-reuse confusion. */
		os_unfair_lock_lock(&g_global_lock);
		for (rhi_rebind_transaction_t *transaction = g_global_transactions;
		     transaction; transaction = transaction->next_global) {
			os_unfair_lock_lock(&transaction->lock);
			RHI_STATE_STORE(&transaction->state, RHI_HOOK_FAILED);
			rhi_set_hook_states(transaction, RHI_HOOK_FAILED);
			os_unfair_lock_unlock(&transaction->lock);
		}
		os_unfair_lock_unlock(&g_global_lock);
		return;
	}
	os_unfair_lock_lock(&g_global_lock);
	for (rhi_rebind_transaction_t *transaction = g_global_transactions;
	     transaction; transaction = transaction->next_global) {
		os_unfair_lock_lock(&transaction->lock);
		for (size_t image = 0; image < transaction->known_image_count; image++) {
			if (!rhi_image_identity_equal(&transaction->known_images[image], &removed)) continue;
			memmove(&transaction->known_images[image],
			        &transaction->known_images[image + 1U],
			        (transaction->known_image_count - image - 1U) *
			        sizeof(*transaction->known_images));
			transaction->known_image_count--;
			break;
		}
		for (size_t slot = 0; slot < transaction->slot_count; slot++) {
			if (rhi_image_identity_equal(&transaction->slots[slot].image, &removed)) {
				transaction->slots[slot].image.header = NULL;
			}
		}
		RHI_STATE_STORE(&transaction->lifecycle_generation,
		                __atomic_load_n(&g_lifecycle_generation, __ATOMIC_ACQUIRE));
		os_unfair_lock_unlock(&transaction->lock);
	}
	os_unfair_lock_unlock(&g_global_lock);
}

static bool rhi_rebind_transaction_reconcile_loaded_images(rhi_rebind_transaction_t *transaction)
{
	if (!transaction) return false;
	/* Keep the dyld snapshot and its address-bearing ledger coordinated with
	 * remove-image cleanup. The callback lock order is global -> transaction. */
	os_unfair_lock_lock(&g_global_lock);
	os_unfair_lock_lock(&transaction->lock);
	if (!transaction->global_armed || transaction->terminal ||
	    RHI_STATE_LOAD(&transaction->state) != RHI_HOOK_ACTIVE) {
		os_unfair_lock_unlock(&transaction->lock);
		os_unfair_lock_unlock(&g_global_lock);
		return false;
	}
	const uint32_t count = _dyld_image_count();
	for (uint32_t i = 0; i < count; i++) {
		const struct mach_header *header = _dyld_get_image_header(i);
		rhi_image_identity_t identity;
		if (!rhi_live_identity(header, _dyld_get_image_vmaddr_slide(i), &identity)) {
			RHI_STATE_STORE(&transaction->state, RHI_HOOK_FAILED);
			rhi_set_hook_states(transaction, RHI_HOOK_FAILED);
			break;
		}
		if (rhi_transaction_has_image(transaction, &identity)) continue;
		const size_t old_slot_count = transaction->slot_count;
		if (!rhi_scan_image(transaction, header, _dyld_get_image_vmaddr_slide(i))) {
			transaction->slot_count = old_slot_count;
			RHI_STATE_STORE(&transaction->state, RHI_HOOK_FAILED);
			rhi_set_hook_states(transaction, RHI_HOOK_FAILED);
			break;
		}
		RHI_STATE_STORE(&transaction->lifecycle_generation,
		                __atomic_load_n(&g_lifecycle_generation, __ATOMIC_ACQUIRE));
		if (!rhi_transaction_image_snapshot_stable(transaction)) {
			RHI_STATE_STORE(&transaction->state, RHI_HOOK_FAILED);
			rhi_set_hook_states(transaction, RHI_HOOK_FAILED);
			break;
		}
		rhi_rebind_result_t result = rhi_commit_slots(transaction, old_slot_count,
	                                            transaction->slot_count);
		if (result == RHI_REBIND_COMPLETE) {
			continue;
		}
		if (result == RHI_REBIND_PARTIAL) {
			transaction->result = result;
			RHI_STATE_STORE(&transaction->state, RHI_HOOK_PARTIAL);
			transaction->terminal = true;
			rhi_set_hook_states(transaction, RHI_HOOK_PARTIAL);
		} else if (result == RHI_REBIND_UNKNOWN) {
			transaction->result = result;
			RHI_STATE_STORE(&transaction->state, RHI_HOOK_UNKNOWN);
			transaction->terminal = true;
			rhi_set_hook_states(transaction, RHI_HOOK_UNKNOWN);
		} else {
			RHI_STATE_STORE(&transaction->state, RHI_HOOK_FAILED);
			rhi_set_hook_states(transaction, RHI_HOOK_FAILED);
		}
		break;
	}
	if (RHI_STATE_LOAD(&transaction->state) == RHI_HOOK_ACTIVE && !transaction->terminal) {
		RHI_STATE_STORE(&transaction->lifecycle_generation,
		                __atomic_load_n(&g_lifecycle_generation, __ATOMIC_ACQUIRE));
		if (!rhi_transaction_image_snapshot_stable(transaction)) {
			RHI_STATE_STORE(&transaction->state, RHI_HOOK_FAILED);
			rhi_set_hook_states(transaction, RHI_HOOK_FAILED);
		}
	}
	const bool ready = RHI_STATE_LOAD(&transaction->state) == RHI_HOOK_ACTIVE && !transaction->terminal;
	os_unfair_lock_unlock(&transaction->lock);
	os_unfair_lock_unlock(&g_global_lock);
	return ready;
}

bool rhi_rebind_transaction_activate_global(rhi_rebind_transaction_t *transaction)
{
	if (!transaction) return false;
	if (!rhi_ensure_lifecycle_callbacks()) return false;
	os_unfair_lock_lock(&transaction->lock);
	if (RHI_STATE_LOAD(&transaction->state) != RHI_HOOK_ACTIVE || transaction->terminal || transaction->global_armed) {
		os_unfair_lock_unlock(&transaction->lock);
		return false;
	}
	transaction->global_armed = true;
	os_unfair_lock_unlock(&transaction->lock);

	os_unfair_lock_lock(&g_global_lock);
	transaction->next_global = g_global_transactions;
	g_global_transactions = transaction;
	transaction->in_global_registry = true;
	os_unfair_lock_unlock(&g_global_lock);
	/* Cover the interval between initial commit and registry insertion. */
	return rhi_rebind_transaction_reconcile_loaded_images(transaction);
}

rhi_hook_state_t rhi_rebind_transaction_state(const rhi_rebind_transaction_t *transaction)
{
	if (!transaction) return RHI_HOOK_FAILED;
	return RHI_STATE_LOAD(&transaction->state);
}

rhi_hook_state_t rhi_rebind_transaction_hook_state(const rhi_rebind_transaction_t *transaction,
	                                               size_t hook_index)
{
	if (!transaction || hook_index >= transaction->hook_count) return RHI_HOOK_FAILED;
	return RHI_STATE_LOAD(&transaction->hooks[hook_index].state);
}

bool rhi_rebind_transaction_all_hooks_prepared(const rhi_rebind_transaction_t *transaction)
{
	if (!transaction || RHI_STATE_LOAD(&transaction->state) != RHI_HOOK_PREPARED ||
	    !transaction->prepared || transaction->hook_count == 0) return false;
	for (size_t i = 0; i < transaction->hook_count; i++) {
		if (RHI_STATE_LOAD(&transaction->hooks[i].state) != RHI_HOOK_PREPARED) return false;
	}
	return true;
}

bool rhi_rebind_transaction_all_hooks_active(const rhi_rebind_transaction_t *transaction)
{
	if (!transaction || RHI_STATE_LOAD(&transaction->state) != RHI_HOOK_ACTIVE ||
	    transaction->hook_count == 0) return false;
	for (size_t i = 0; i < transaction->hook_count; i++) {
		if (RHI_STATE_LOAD(&transaction->hooks[i].state) != RHI_HOOK_ACTIVE) return false;
	}
	return true;
}

bool rhi_rebind_transaction_hook_is_active(const rhi_rebind_transaction_t *transaction,
	                                       const char *name)
{
	if (!transaction || !name || RHI_STATE_LOAD(&transaction->state) != RHI_HOOK_ACTIVE) return false;
	for (size_t i = 0; i < transaction->hook_count; i++) {
		if (strcmp(name, transaction->hooks[i].name) == 0) {
			return RHI_STATE_LOAD(&transaction->hooks[i].state) == RHI_HOOK_ACTIVE;
		}
	}
	return false;
}

size_t rhi_rebind_transaction_hook_count(const rhi_rebind_transaction_t *transaction)
{
	return transaction ? transaction->hook_count : 0;
}
