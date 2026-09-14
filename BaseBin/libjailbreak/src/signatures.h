#ifndef SIGNATURES_H
#define SIGNATURES_H

#include <choma/CodeDirectory.h>
#include <choma/Fat.h>

typedef enum {
    /* Keep the deployed RootHide wire values stable.  siginfo is passed over
     * the launchdhook Mach boundary, so ALLOCATION is deliberately appended
     * rather than copied at the front from upstream. */
	SIGNATURE_SOURCE_FILE,
	SIGNATURE_SOURCE_PROC,
	SIGNATURE_SOURCE_ALLOCATION,
} signature_source_t;

struct siginfo {
	signature_source_t source;
	fsignatures_t signature;
};

typedef uint8_t cdhash_t[CS_CDHASH_LEN];

/*
 * The path-aware collector has two benign completion modes.  A caller may
 * ignore this status and retain the historical void API, but transactional
 * callers must propagate negative errors instead of treating a failed jbrand
 * rewrite as an empty (policy-skipped) collection.
 */
typedef enum {
	FILE_CDHASH_COLLECTION_COMPLETED = 0,
	FILE_CDHASH_COLLECTION_SKIPPED = 1,
} file_cdhash_collection_status_t;

bool code_signature_calculate_adhoc_cdhash(CS_SuperBlob *superblob, cdhash_t cdhashOut);
bool macho_is_mappable(MachO *macho);
void fat_collect_untrusted_cdhashes(Fat *fat, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut);
void file_collect_untrusted_cdhashes(int fd, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut);
/* Returns COMPLETED, SKIPPED for path-policy/non-Mach input, or a negative
 * errno-style error.  Outputs are always cleared on SKIPPED or error. */
int file_collect_untrusted_cdhashes_by_path_status(const char *path, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut);
void file_collect_untrusted_cdhashes_by_path(const char *path, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut);
void fat_collect_signatures(Fat *fat, struct siginfo **sigInfosOut, uint32_t *sigInfoCountOut);
void file_collect_signatures(int fd, struct siginfo **sigInfosOut, uint32_t *sigInfoCountOut);
CS_SuperBlob *siginfo_resolve_superblob(const struct siginfo *siginfo, int pid, int fd);
int trust_signatures(int pid, int fd, struct siginfo *sigInfos, uint32_t sigInfoCount);
#endif
