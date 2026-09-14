#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <choma/MachO.h>
#include <choma/Fat.h>
#include <choma/MemoryStream.h>
#include <choma/FileStream.h>
#include <choma/CSBlob.h>
#include <choma/CodeDirectory.h>
#include <choma/Util.h>
#include <choma/Host.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <libkern/OSByteOrder.h>

#include "trustcache.h"
#include "util.h"
#include "kernel.h"
#include "primitives.h"
#include "codesign.h"
#include "roothider.h"

static void signature_outputs_clear(cdhash_t **cdhashesOut, uint32_t *cdhashCountOut)
{
	if (cdhashesOut) *cdhashesOut = NULL;
	if (cdhashCountOut) *cdhashCountOut = 0;
}

static void siginfo_outputs_clear(struct siginfo **sigInfosOut, uint32_t *sigInfoCountOut)
{
	if (sigInfosOut) *sigInfosOut = NULL;
	if (sigInfoCountOut) *sigInfoCountOut = 0;
}

static int append_unique_cdhash(cdhash_t **hashes, uint32_t *count, const cdhash_t hash)
{
	if (!hashes || !count) return -EINVAL;
	for (uint32_t i = 0; i < *count; i++) {
		if (memcmp((*hashes)[i], hash, sizeof(cdhash_t)) == 0) return 0;
	}
	if (*count == UINT32_MAX || (size_t)(*count + 1) > SIZE_MAX / sizeof(cdhash_t)) return -EOVERFLOW;
	cdhash_t *grown = realloc(*hashes, (size_t)(*count + 1) * sizeof(cdhash_t));
	if (!grown) return -ENOMEM;
	memcpy(grown[*count], hash, sizeof(cdhash_t));
	*hashes = grown;
	(*count)++;
	return 0;
}

static int append_siginfo(struct siginfo **sigInfos, uint32_t *count, const struct siginfo *siginfo)
{
	if (!sigInfos || !count || !siginfo) return -EINVAL;
	if (*count == UINT32_MAX || (size_t)(*count + 1) > SIZE_MAX / sizeof(struct siginfo)) return -EOVERFLOW;
	struct siginfo *grown = realloc(*sigInfos, (size_t)(*count + 1) * sizeof(struct siginfo));
	if (!grown) return -ENOMEM;
	grown[*count] = *siginfo;
	*sigInfos = grown;
	(*count)++;
	return 0;
}

static bool root_hide_allows_trust_path(const char *path)
{
	if (!path || path[0] == '\0') return false;
	if (string_has_prefix(path, "/private/preboot/Cryptexes/")) {
		JBLogDebug("Skipping Cryptexes file: %s", path);
		return false;
	}
	if (isRemovableBundlePath(path) && !hasTrollstoreLiteMarker(path)) {
		/* Keep RootHide's allowlist boundary: a removable app is not implicitly
		 * trusted unless it was installed through TrollStore Lite. */
		JBLogDebug("Ignoring adhoc-signed removable app: %s", path);
		return false;
	}
	return true;
}

bool macho_is_mappable(MachO *macho)
{
	if (!macho) return false;
	struct mach_header *header = macho_get_mach_header(macho);
	if (!header || header->cputype != CPU_TYPE_ARM64) return false;

	cpu_subtype_t cpusubtype = header->cpusubtype;
	bool isLibrary = (header->filetype == MH_DYLIB);
	if (host_is_arm64e()) {
		if (cpusubtype == (CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_ABI_V2)) return true;
		/* The old ABI can only be mapped as a dylib; executables fall back to
		 * arm64 instead.  This preserves the RootHide/official architecture rule. */
		if (cpusubtype == CPU_SUBTYPE_ARM64E && isLibrary) return true;
	}

	return cpusubtype == CPU_SUBTYPE_ARM64_V8 || cpusubtype == CPU_SUBTYPE_ARM64_ALL;
}

bool csd_superblob_is_adhoc_signed(CS_DecodedSuperBlob *superblob)
{
	if (!superblob) return false;
	CS_DecodedBlob *wrapperBlob = csd_superblob_find_blob(superblob, CSSLOT_SIGNATURESLOT, NULL);
	return !wrapperBlob || csd_blob_get_size(wrapperBlob) <= 8;
}

bool code_signature_calculate_adhoc_cdhash(CS_SuperBlob *superblob, cdhash_t cdhashOut)
{
	if (!superblob || !cdhashOut) return false;
	CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
	if (!decodedSuperblob) return false;
	bool result = csd_superblob_is_adhoc_signed(decodedSuperblob) &&
	              csd_superblob_calculate_best_cdhash(decodedSuperblob, cdhashOut, NULL) == 0;
	csd_superblob_free(decodedSuperblob);
	return result;
}

bool macho_parse_code_signature(MachO *macho, cdhash_t cdhashOut)
{
	if (!macho || !cdhashOut) return false;
	CS_SuperBlob *superblob = macho_read_code_signature(macho);
	if (!superblob) return false;
	bool result = code_signature_calculate_adhoc_cdhash(superblob, cdhashOut);
	free(superblob);
	return result;
}

void fat_collect_untrusted_cdhashes(Fat *fat, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut)
{
	signature_outputs_clear(cdhashesOut, cdhashCountOut);
	if (!fat || !cdhashesOut || !cdhashCountOut) return;

	__block cdhash_t *cdhashes = NULL;
	__block uint32_t cdhashCount = 0;
	__block int collectionError = 0;
	fat_enumerate_slices(fat, ^(MachO *macho, bool *stop) {
		if (!macho_is_mappable(macho)) return;
		cdhash_t cdhash;
		if (!macho_parse_code_signature(macho, cdhash) || is_cdhash_trustcached(cdhash)) return;
		collectionError = append_unique_cdhash(&cdhashes, &cdhashCount, cdhash);
		if (collectionError != 0) *stop = true;
	});

	if (collectionError != 0) {
		free(cdhashes);
		return;
	}
	*cdhashesOut = cdhashes;
	*cdhashCountOut = cdhashCount;
}

static int file_cdhash_input_kind(int fd)
{
	struct stat st = {};
	if (fstat(fd, &st) != 0) return -errno;
	if (st.st_size < (off_t)sizeof(uint32_t)) return FILE_CDHASH_COLLECTION_SKIPPED;

	uint32_t magic = 0;
	ssize_t readCount = -1;
	do {
		readCount = pread(fd, &magic, sizeof(magic), 0);
	} while (readCount < 0 && errno == EINTR);
	if (readCount < 0) return -errno;
	if (readCount != (ssize_t)sizeof(magic)) return -EIO;

	/* ChOma accepts little-endian thin Mach-O and FAT input.  Recognize both
	 * byte orders here solely to distinguish a benign non-Mach file from a
	 * malformed Mach-O/FAT that the parser must reject below. */
	switch (magic) {
		case MH_MAGIC:
		case MH_MAGIC_64:
		case FAT_MAGIC:
		case FAT_MAGIC_64:
		case FAT_CIGAM:
		case FAT_CIGAM_64:
			return FILE_CDHASH_COLLECTION_COMPLETED;
		default:
			return FILE_CDHASH_COLLECTION_SKIPPED;
	}
}

static int file_collect_untrusted_cdhashes_status(int fd, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut)
{
	signature_outputs_clear(cdhashesOut, cdhashCountOut);
	if (fd < 0 || !cdhashesOut || !cdhashCountOut) return -EINVAL;

	char filepath[PATH_MAX] = {0};
	if (fcntl(fd, F_GETPATH, filepath) != 0) {
		JBLogError("Failed to get file path for fd %d", fd);
		return -errno;
	}
	if (!root_hide_allows_trust_path(filepath)) return FILE_CDHASH_COLLECTION_SKIPPED;

	int inputKind = file_cdhash_input_kind(fd);
	if (inputKind != FILE_CDHASH_COLLECTION_COMPLETED) return inputKind;
	const char *pathForBlock = filepath;

	MemoryStream *stream = file_stream_init_from_file_descriptor(fd, 0, FILE_STREAM_SIZE_AUTO, 0);
	if (!stream) return -EIO;
	Fat *fat = fat_init_from_memory_stream(stream);
	if (!fat) {
		memory_stream_free(stream);
		return -EINVAL;
	}

	/* RootHide needs the final, jbrand-randomized cdhash.  Do this before the
	 * trust-cache lookup: looking up the pre-randomization hash can otherwise
	 * skip the only hash that will actually execute. */
	__block cdhash_t *cdhashes = NULL;
	__block uint32_t cdhashCount = 0;
	__block int collectionError = 0;
	fat_enumerate_slices(fat, ^(MachO *macho, bool *stop) {
		if (!macho_is_mappable(macho)) return;
		cdhash_t cdhash;
		if (!macho_parse_code_signature(macho, cdhash)) return;
		int jbrandError = ensure_randomized_cdhash_for_slice(pathForBlock, macho->archDescriptor.offset, cdhash);
		if (jbrandError != 0) {
			JBLogError("Failed to ensure randomized cdhash for %s: %d", pathForBlock, jbrandError);
			collectionError = jbrandError < 0 ? jbrandError : -EIO;
			*stop = true;
			return;
		}
		if (is_cdhash_trustcached(cdhash)) return;
		collectionError = append_unique_cdhash(&cdhashes, &cdhashCount, cdhash);
		if (collectionError != 0) *stop = true;
	});
	fat_free(fat);

	if (collectionError != 0) {
		free(cdhashes);
		return collectionError;
	}
	*cdhashesOut = cdhashes;
	*cdhashCountOut = cdhashCount;
	return FILE_CDHASH_COLLECTION_COMPLETED;
}

void file_collect_untrusted_cdhashes(int fd, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut)
{
	(void)file_collect_untrusted_cdhashes_status(fd, cdhashesOut, cdhashCountOut);
}

int file_collect_untrusted_cdhashes_by_path_status(const char *path, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut)
{
	signature_outputs_clear(cdhashesOut, cdhashCountOut);
	if (!path || !cdhashesOut || !cdhashCountOut) return -EINVAL;
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return -errno;
	int result = file_collect_untrusted_cdhashes_status(fd, cdhashesOut, cdhashCountOut);
	close(fd);
	return result;
}

void file_collect_untrusted_cdhashes_by_path(const char *path, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut)
{
	(void)file_collect_untrusted_cdhashes_by_path_status(path, cdhashesOut, cdhashCountOut);
}

void fat_collect_signatures(Fat *fat, struct siginfo **sigInfosOut, uint32_t *sigInfoCountOut)
{
	siginfo_outputs_clear(sigInfosOut, sigInfoCountOut);
	if (!fat || !sigInfosOut || !sigInfoCountOut) return;

	__block struct siginfo *sigInfos = NULL;
	__block uint32_t sigInfoCount = 0;
	__block int collectionError = 0;
	fat_enumerate_slices(fat, ^(MachO *macho, bool *stop) {
		if (!macho_is_mappable(macho)) return;
		CS_SuperBlob *superblob = macho_read_code_signature(macho);
		if (!superblob) return;
		uint32_t superblobSize = OSSwapBigToHostInt32(superblob->length);
		if (superblobSize < sizeof(CS_SuperBlob)) {
			free(superblob);
			return;
		}
		struct siginfo siginfo = {
			.source = SIGNATURE_SOURCE_ALLOCATION,
			.signature = {
				.fs_file_start = macho->archDescriptor.offset,
				.fs_blob_start = superblob,
				.fs_blob_size = superblobSize,
			},
		};
		collectionError = append_siginfo(&sigInfos, &sigInfoCount, &siginfo);
		if (collectionError != 0) {
			free(superblob);
			*stop = true;
		}
	});

	if (collectionError != 0) {
		for (uint32_t i = 0; i < sigInfoCount; i++) free(sigInfos[i].signature.fs_blob_start);
		free(sigInfos);
		return;
	}
	*sigInfosOut = sigInfos;
	*sigInfoCountOut = sigInfoCount;
}

void file_collect_signatures(int fd, struct siginfo **sigInfosOut, uint32_t *sigInfoCountOut)
{
	siginfo_outputs_clear(sigInfosOut, sigInfoCountOut);
	if (fd < 0 || !sigInfosOut || !sigInfoCountOut) return;
	MemoryStream *stream = file_stream_init_from_file_descriptor(fd, 0, FILE_STREAM_SIZE_AUTO, 0);
	if (!stream) return;
	Fat *fat = fat_init_from_memory_stream(stream);
	if (!fat) {
		memory_stream_free(stream);
		return;
	}
	fat_collect_signatures(fat, sigInfosOut, sigInfoCountOut);
	fat_free(fat);
}

static int read_all(int fd, void *buffer, size_t size)
{
	uint8_t *cursor = buffer;
	while (size > 0) {
		ssize_t readCount = read(fd, cursor, size);
		if (readCount < 0 && errno == EINTR) continue;
		if (readCount <= 0) return -EIO;
		cursor += readCount;
		size -= (size_t)readCount;
	}
	return 0;
}

CS_SuperBlob *siginfo_resolve_superblob(const struct siginfo *siginfo, int pid, int fd)
{
	if (!siginfo || siginfo->signature.fs_blob_size < sizeof(CS_SuperBlob)) return NULL;
	size_t superblobSize = siginfo->signature.fs_blob_size;
	CS_SuperBlob *superblob = malloc(superblobSize);
	if (!superblob) return NULL;

	bool success = false;
	switch (siginfo->source) {
		case SIGNATURE_SOURCE_ALLOCATION:
			if (siginfo->signature.fs_blob_start) {
				memcpy(superblob, siginfo->signature.fs_blob_start, superblobSize);
				success = true;
			}
			break;
		case SIGNATURE_SOURCE_FILE: {
			if (fd < 0) break;
			uintptr_t blobOffset = (uintptr_t)siginfo->signature.fs_blob_start;
			if (siginfo->signature.fs_file_start > UINTPTR_MAX - blobOffset) break;
			uintptr_t superblobStart = siginfo->signature.fs_file_start + blobOffset;
			if (superblobStart > UINTPTR_MAX - superblobSize) break;
			uintptr_t superblobEnd = superblobStart + superblobSize;
			struct stat st = {};
			if (fstat(fd, &st) != 0 || st.st_size < 0 || superblobEnd > (uintmax_t)st.st_size) break;
			off_t originalPosition = lseek(fd, 0, SEEK_CUR);
			if (lseek(fd, (off_t)superblobStart, SEEK_SET) != (off_t)superblobStart) break;
			success = read_all(fd, superblob, superblobSize) == 0;
			if (originalPosition != (off_t)-1) lseek(fd, originalPosition, SEEK_SET);
			break;
		}
		case SIGNATURE_SOURCE_PROC: {
			uint64_t proc = proc_find(pid);
			if (proc && proc_vreadbuf(proc, siginfo->signature.fs_blob_start, superblob, superblobSize) == 0) {
				success = true;
			}
			break;
		}
		default:
			break;
	}

	if (!success) {
		free(superblob);
		return NULL;
	}
	return superblob;
}

int trust_signatures(int pid, int fd, struct siginfo *sigInfos, uint32_t sigInfoCount)
{
	if (sigInfoCount == 0) return 0;
	if (!sigInfos || fd < 0 || (size_t)sigInfoCount > SIZE_MAX / sizeof(cdhash_t) ||
	    (size_t)sigInfoCount > SIZE_MAX / sizeof(struct siginfo *)) return -EINVAL;

	/* A legacy one-image XPF startup must never be allowed to take a partial
	 * TXM signature path. */
	bool txmSignaturesRequired = jbinfo_has_sptm_metadata();
	if (txmSignaturesRequired && !jbinfo_sptm_runtime_ready()) return -ENOTSUP;

	cdhash_t *cdhashes = calloc(sigInfoCount, sizeof(cdhash_t));
	struct siginfo **sigInfosToAttach = calloc(sigInfoCount, sizeof(struct siginfo *));
	if (!cdhashes || !sigInfosToAttach) {
		free(cdhashes);
		free(sigInfosToAttach);
		return -ENOMEM;
	}

	uint32_t cdhashCount = 0;
	uint32_t sigInfosToAttachCount = 0;
	int result = 0;
	for (uint32_t i = 0; i < sigInfoCount; i++) {
		struct siginfo *curSigInfo = &sigInfos[i];
		CS_SuperBlob *superblob = siginfo_resolve_superblob(curSigInfo, pid, fd);
		if (!superblob) {
			result = -EIO;
			goto out;
		}
		CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
		free(superblob);
		if (!decodedSuperblob) {
			result = -EINVAL;
			goto out;
		}

		if (!csd_superblob_is_adhoc_signed(decodedSuperblob)) {
			csd_superblob_free(decodedSuperblob);
			continue;
		}
		CS_DecodedBlob *bestCDBlob = csd_superblob_find_best_code_directory(decodedSuperblob);
		if (!bestCDBlob) {
			csd_superblob_free(decodedSuperblob);
			result = -EINVAL;
			goto out;
		}

		if (txmSignaturesRequired) {
			uint32_t flags = csd_code_directory_get_flags(bestCDBlob);
			char *teamId = csd_code_directory_copy_team_id(bestCDBlob, NULL);
			bool hasTeamId = teamId != NULL;
			free(teamId);
			if (!!(flags & CS_ADHOC) == hasTeamId) {
				if (curSigInfo->source != SIGNATURE_SOURCE_ALLOCATION) {
					csd_superblob_free(decodedSuperblob);
					result = -EPERM;
					goto out;
				}
				csd_code_directory_set_flags(bestCDBlob, hasTeamId ? (flags & ~CS_ADHOC) : (flags | CS_ADHOC));
				CS_SuperBlob *encoded = csd_superblob_encode(decodedSuperblob);
				if (!encoded) {
					csd_superblob_free(decodedSuperblob);
					result = -ENOMEM;
					goto out;
				}
				free(curSigInfo->signature.fs_blob_start);
				curSigInfo->signature.fs_blob_start = encoded;
				curSigInfo->signature.fs_blob_size = OSSwapBigToHostInt32(encoded->length);
				sigInfosToAttach[sigInfosToAttachCount++] = curSigInfo;
			}
		}

		cdhash_t cdhash;
		csd_code_directory_calculate_hash(bestCDBlob, &cdhash);
		csd_superblob_free(decodedSuperblob);
		if (is_cdhash_trustcached(cdhash)) continue;
		for (uint32_t j = 0; j < cdhashCount; j++) {
			if (memcmp(cdhashes[j], cdhash, sizeof(cdhash_t)) == 0) goto next_signature;
		}
		memcpy(cdhashes[cdhashCount++], cdhash, sizeof(cdhash_t));
	next_signature:
		;
	}

	/* Attach every rewritten local signature before publishing its cdhash.  A
	 * failed F_ADDSIGS therefore cannot leave an otherwise-unused hash in the
	 * global RootHide trust cache.  Attachments are fd-local and disappear when
	 * the caller closes the descriptor. */
	for (uint32_t i = 0; i < sigInfosToAttachCount; i++) {
		result = fd_attach_signature(fd, &sigInfosToAttach[i]->signature);
		if (result != 0) goto out;
	}
	if (cdhashCount > 0) result = jb_trustcache_add_cdhashes(cdhashes, cdhashCount);

out:
	free(sigInfosToAttach);
	free(cdhashes);
	return result;
}
