#include "trustcache.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include "kernel.h"
#include "info.h"
#include "primitives.h"

#define TRUSTCACHE_MAX_LIST_NODES 4096U

static int trustcache_compute_size(uint32_t entryCount, uint64_t *sizeOut)
{
	if (!sizeOut || ksizeof(trustcache) == 0) return -EINVAL;
	uint64_t fileSize = sizeof(trustcache_file_v1);
	if (entryCount > (UINT64_MAX - fileSize) / sizeof(trustcache_entry_v1)) return -EOVERFLOW;
	fileSize += (uint64_t)entryCount * sizeof(trustcache_entry_v1);
	if (fileSize > UINT64_MAX - ksizeof(trustcache)) return -EOVERFLOW;
	uint64_t size = ksizeof(trustcache) + fileSize;
	if (size > JB_TRUSTCACHE_SIZE) return -E2BIG;
	*sizeOut = size;
	return 0;
}

static bool trustcache_file_is_sorted(const trustcache_file_v1 *file)
{
	if (!file || file->version != 1) return false;
	for (uint32_t i = 1; i < file->length; i++) {
		if (memcmp(file->entries[i - 1].hash, file->entries[i].hash, sizeof(cdhash_t)) > 0) return false;
	}
	return true;
}

void _trustcache_file_init(trustcache_file_v1 *file)
{
	memset(file, 0, sizeof(*file));
	file->version = 1;
	uuid_generate(file->uuid);
}

// iOS 16:
// ppl_trust_cache_rt has trustcache runtime
// **(ppl_trust_cache_rt+0x20) seems to have the loaded trustcache linked list
// trustcache struct changed, "next" is still at +0x0, but "this" is at +0x20

/* Return the kernel word which owns the list root.  Keeping the owner lets
 * removal snapshot and verify the precise root write rather than treating a
 * failed _trustcache_list_set_start as if it were side-effect free. */
static uint64_t trustcache_list_start_slot(void)
{
	if (ksymbol(pmap_image4_trust_caches)) { // iOS <=15
		return ksymbol(pmap_image4_trust_caches);
	}
	else if (ksymbol(ppl_trust_cache_rt)) {  // iOS >=16
		return kread64(ksymbol(ppl_trust_cache_rt) + 0x20);
	}
	else if (jbinfo_sptm_runtime_ready() && ksymbol_txm(txm_trustcache_root)) { // iOS >=17, SPTM/TXM
		return kread64(ksymbol_txm(txm_trustcache_root) + 0x20);
	}
	return 0;
}

uint64_t _trustcache_list_get_start(void)
{
	uint64_t slot = trustcache_list_start_slot();
	return slot ? kread64(slot) : 0;
}

/* A primitive can report failure after a write has reached the kernel.  Every
 * link mutation is therefore read back; callers restore snapshots even when
 * this helper reports an error. */
static int trustcache_write64_verified(uint64_t address, uint64_t value)
{
	if (!address) return -EINVAL;
	(void)kwrite64(address, value);
	/* Some primitive backends can report a late transport failure after the
	 * kernel write committed.  The readback, not that transport status alone,
	 * decides whether this link transition completed. */
	return kread64(address) == value ? 0 : -EIO;
}

static int trustcache_restore64(uint64_t address, uint64_t originalValue)
{
	if (!address) return -EINVAL;
	if (kread64(address) == originalValue) return 0;
	return trustcache_write64_verified(address, originalValue);
}

int _trustcache_list_set_start(uint64_t newStart)
{
	uint64_t slot = trustcache_list_start_slot();
	return slot ? trustcache_write64_verified(slot, newStart) : -ENOTSUP;
}

void _trustcache_list_enumerate(void (^enumerateBlock)(uint64_t tcKaddr, bool *stop))
{
	if (!enumerateBlock) return;
	uint64_t curTC = _trustcache_list_get_start();
	for (uint32_t seen = 0; curTC != 0 && seen < TRUSTCACHE_MAX_LIST_NODES; seen++) {
		bool stop = false;
		enumerateBlock(curTC, &stop);
		if (stop) break;
		curTC = kread64(curTC + koffsetof(trustcache, nextptr));
	}
}

static bool trustcache_list_contains(uint64_t target);

/* linkedOut reports whether the new node is reachable.  safeToFreeOut is
 * stricter: it is true only when no live list field can still point at the
 * candidate.  Allocation failure paths must use the latter, not reachability
 * alone, because a failed reverse-link restore can otherwise leave a dangling
 * prevptr to a freed cache. */
static int trustcache_list_insert_transactional(uint64_t tcToInsert, bool *linkedOut, bool *safeToFreeOut)
{
	if (linkedOut) *linkedOut = false;
	if (safeToFreeOut) *safeToFreeOut = false;
	if (!tcToInsert || !linkedOut || !safeToFreeOut) return -EINVAL;

	/* TXM makes the allocation read-only after it is registered.  Append to the
	 * last existing (writable) cache instead of letting TXM update our prevptr. */
	if (jbinfo_sptm_runtime_ready()) {
		__block uint64_t lastTC = 0;
		_trustcache_list_enumerate(^(uint64_t tcKaddr, bool *stop) {
			lastTC = tcKaddr;
		});
		if (!lastTC) {
			*safeToFreeOut = true;
			return -ENOENT;
		}
		if (koffsetof(trustcache, prevptr) &&
		    trustcache_write64_verified(tcToInsert + koffsetof(trustcache, prevptr), lastTC) != 0) {
			/* Only candidate-local memory was touched. */
			*safeToFreeOut = true;
			return -EIO;
		}
		if (trustcache_write64_verified(tcToInsert + koffsetof(trustcache, nextptr), 0) != 0) {
			*safeToFreeOut = true;
			return -EIO;
		}
		uint64_t lastNextAddr = lastTC + koffsetof(trustcache, nextptr);
		uint64_t previousLastNext = kread64(lastNextAddr);
		if (previousLastNext != 0) {
			*safeToFreeOut = true;
			return -EIO;
		}
		if (trustcache_write64_verified(lastNextAddr, tcToInsert) == 0) {
			*linkedOut = true;
			return 0;
		}
		/* Do not make a caller free a node which may have been published by a
		 * primitive that reported failure late. */
		if (trustcache_restore64(lastNextAddr, previousLastNext) == 0) {
			*safeToFreeOut = true;
		}
		else {
			*linkedOut = trustcache_list_contains(tcToInsert);
		}
		return -EIO;
	}

	uint64_t previousStartTC = _trustcache_list_get_start();
	uint64_t previousPrevAddr = previousStartTC && koffsetof(trustcache, prevptr)
		? previousStartTC + koffsetof(trustcache, prevptr) : 0;
	uint64_t previousPrev = previousPrevAddr ? kread64(previousPrevAddr) : 0;
	if (previousStartTC && koffsetof(trustcache, prevptr) &&
	    trustcache_write64_verified(previousStartTC + koffsetof(trustcache, prevptr), tcToInsert) != 0) {
		if (!previousPrevAddr || trustcache_restore64(previousPrevAddr, previousPrev) == 0) {
			*safeToFreeOut = true;
		}
		return -EIO;
	}
	if (trustcache_write64_verified(tcToInsert + koffsetof(trustcache, nextptr), previousStartTC) != 0) {
		if (!previousPrevAddr || trustcache_restore64(previousPrevAddr, previousPrev) == 0) {
			*safeToFreeOut = true;
		}
		return -EIO;
	}
	if (_trustcache_list_set_start(tcToInsert) != 0) {
		/* The root was the final publish step.  Restore the detached node's
		 * reverse link before reporting failure; the caller will not free it
		 * when the root cannot be proven to still reference the old start. */
		if (!previousPrevAddr || trustcache_restore64(previousPrevAddr, previousPrev) == 0) {
			*safeToFreeOut = true;
		}
		return -EIO;
	}
	*linkedOut = true;
	return 0;
}

int trustcache_list_insert(uint64_t tcToInsert)
{
	bool linked = false;
	bool safeToFree = false;
	return trustcache_list_insert_transactional(tcToInsert, &linked, &safeToFree);
}

static bool trustcache_list_contains(uint64_t target)
{
	__block bool found = false;
	_trustcache_list_enumerate(^(uint64_t tcKaddr, bool *stop) {
		if (tcKaddr == target) {
			found = true;
			*stop = true;
		}
	});
	return found;
}

/* removedOut is true only after the target is no longer reachable through the
 * forward list.  Callers may free a node only in that state. */
static int trustcache_list_remove_transactional(uint64_t tcKaddr, bool *removedOut)
{
	if (removedOut) *removedOut = false;
	if (!tcKaddr || !removedOut) return -EINVAL;

	uint64_t rootSlot = trustcache_list_start_slot();
	if (!rootSlot) return -ENOTSUP;
	uint64_t rootBefore = kread64(rootSlot);
	if (!rootBefore) return -ENOENT;

	uint64_t prevTc = 0;
	uint64_t curTc = rootBefore;
	uint32_t seen = 0;
	while (curTc != tcKaddr && curTc != 0 && seen++ < TRUSTCACHE_MAX_LIST_NODES) {
		prevTc = curTc;
		curTc = kread64(curTc + koffsetof(trustcache, nextptr));
	}
	if (curTc != tcKaddr) return -ENOENT;

	uint64_t nextTc = kread64(tcKaddr + koffsetof(trustcache, nextptr));
	uint64_t forwardAddr = prevTc ? prevTc + koffsetof(trustcache, nextptr) : rootSlot;
	uint64_t forwardBefore = kread64(forwardAddr);
	if (forwardBefore != tcKaddr) return -EIO;

	uint64_t reverseAddr = 0;
	uint64_t reverseBefore = 0;
	uint64_t reverseAfter = prevTc;
	if (nextTc && koffsetof(trustcache, prevptr)) {
		reverseAddr = nextTc + koffsetof(trustcache, prevptr);
		reverseBefore = kread64(reverseAddr);
		/* A mismatched reverse pointer means the list changed or is corrupt.  Do
		 * not guess at a repair while a BaseBin/DYLD cache is live. */
		if (reverseBefore != tcKaddr) return -EIO;
	}

	/* Commit the non-forward link first.  Thus a failure before the final root/
	 * next write cannot make the target unreachable. */
	if (reverseAddr && trustcache_write64_verified(reverseAddr, reverseAfter) != 0) {
		(void)trustcache_restore64(reverseAddr, reverseBefore);
		return -EIO;
	}
	if (trustcache_write64_verified(forwardAddr, nextTc) == 0) {
		*removedOut = true;
		return 0;
	}

	/* The final forward publish may have failed after reaching the kernel.  Put
	 * the forward chain back first, then its reverse metadata.  If the forward
	 * restore itself cannot be proven, report whether the old node is still
	 * reachable so replacement cleanup never frees a live node. */
	int forwardRollback = trustcache_restore64(forwardAddr, forwardBefore);
	int reverseRollback = reverseAddr ? trustcache_restore64(reverseAddr, reverseBefore) : 0;
	*removedOut = !trustcache_list_contains(tcKaddr);
	if (*removedOut) {
		/* A complete forward unlink is safer than claiming the old cache remains
		 * active; the published replacement remains live.  Keep the detached old
		 * allocation for the caller's error path rather than freeing on doubt. */
		return -EIO;
	}
	/* Both values are deliberately retained for debugger inspection.  A failed
	 * restore is still reported as EIO, but removedOut above prevents a caller
	 * from treating the old cache as safely reclaimable. */
	(void)forwardRollback;
	(void)reverseRollback;
	return -EIO;
}

int trustcache_list_remove(uint64_t tcKaddr)
{
	bool removed = false;
	int result = trustcache_list_remove_transactional(tcKaddr, &removed);
	return result;
}

int _trustcache_file_sort_entry_comparator_v1(const void * vp1, const void * vp2)
{
	trustcache_entry_v1* tc1 = (trustcache_entry_v1*)vp1;
	trustcache_entry_v1* tc2 = (trustcache_entry_v1*)vp2;
	return memcmp(tc1->hash, tc2->hash, sizeof(cdhash_t));
}

void _trustcache_file_sort(trustcache_file_v1 *file)
{
	qsort(file->entries, file->length, sizeof(trustcache_entry_v1), _trustcache_file_sort_entry_comparator_v1);
}

bool _is_jb_trustcache(uint64_t tcKaddr)
{
	uint64_t jbTcFile = tcKaddr + offsetof(jb_trustcache, file);
	uint64_t file = kread64(tcKaddr + koffsetof(trustcache, fileptr));
	if (file == jbTcFile) {
		// If there is exactly one 8-byte value between the kpage start and the trustcache file,
		// Check if that matches against the JB_MAGIC
		// This is a 100% accurate way of determining whether this entry is a jb_trustcache or not
		return (kread64(tcKaddr + offsetof(jb_trustcache, magic)) == JB_MAGIC);
	}
	return false;
}

void _jb_trustcache_enumerate(void (^enumerateBlock)(uint64_t jbTcKaddr, bool *stop))
{
	_trustcache_list_enumerate(^(uint64_t tcKaddr, bool *stop) {
		if (_is_jb_trustcache(tcKaddr)) {
			enumerateBlock(tcKaddr, stop);
		}
	});
}

void jb_trustcache_clear(void)
{
	_jb_trustcache_enumerate(^(uint64_t jbTcKaddr, bool *stop) {
		kwrite64(jbTcKaddr + offsetof(jb_trustcache, file.length), 0);
	});
}

#define JB_TRUSTCACHE_MAX_TRANSACTION_ENTRIES 8192U

uint64_t _jb_trustcache_grow(void)
{
	uint64_t jbTcKern = 0;
	if (kalloc(&jbTcKern, JB_TRUSTCACHE_SIZE) != 0 || !jbTcKern) return 0;

	jb_trustcache *jbTc = calloc(1, JB_TRUSTCACHE_SIZE);
	if (!jbTc) {
		(void)kfree(jbTcKern, JB_TRUSTCACHE_SIZE);
		return 0;
	}
	_trustcache_file_init(&jbTc->file);
	jbTc->magic = JB_MAGIC;
	*(uint64_t *)(jbTc->trustcache + koffsetof(trustcache, fileptr)) = jbTcKern + offsetof(jb_trustcache, file);
	if (koffsetof(trustcache, size)) {
		*(uint64_t *)(jbTc->trustcache + koffsetof(trustcache, size)) = JB_TRUSTCACHE_SIZE;
	}
	if (koffsetof(trustcache, type)) {
		*(uint64_t *)(jbTc->trustcache + koffsetof(trustcache, type)) = 0x5;
	}
	int writeResult = kwritebuf(jbTcKern, jbTc, JB_TRUSTCACHE_SIZE);
	free(jbTc);
	/* This allocation is not published until the list transaction begins, so a
	 * partial initial write is safe to reclaim. */
	if (writeResult != 0) {
		(void)kfree(jbTcKern, JB_TRUSTCACHE_SIZE);
		return 0;
	}
	bool linked = false;
	bool safeToFree = false;
	if (trustcache_list_insert_transactional(jbTcKern, &linked, &safeToFree) != 0) {
		/* A reverse-link restore can fail while the candidate is not yet forward
		 * reachable.  Retain it in that case; freeing would leave a dangling
		 * pointer in an otherwise-live jailbreaking trustcache list. */
		if (safeToFree && !linked) (void)kfree(jbTcKern, JB_TRUSTCACHE_SIZE);
		return 0;
	}
	return jbTcKern;
}

struct jb_trustcache_mutation {
	uint64_t address;
	uint8_t *before;
};

static void jb_trustcache_rollback(struct jb_trustcache_mutation *mutations, uint32_t mutationCount)
{
	while (mutationCount > 0) {
		mutationCount--;
		if (mutations[mutationCount].before) {
			(void)kwritebuf(mutations[mutationCount].address, mutations[mutationCount].before, JB_TRUSTCACHE_SIZE);
			free(mutations[mutationCount].before);
		}
	}
}

int jb_trustcache_add_entries(struct trustcache_entry_v1 *entries, uint32_t entryCount)
{
	if (entryCount == 0) return 0;
	if (!entries) return -EINVAL;
	if (entryCount > JB_TRUSTCACHE_MAX_TRANSACTION_ENTRIES ||
	    (size_t)entryCount > SIZE_MAX / sizeof(*entries)) return -E2BIG;

	/* Canonicalize the request before touching kernel state.  This prevents
	 * retries and overlapping sources from consuming a new cache page twice. */
	trustcache_entry_v1 *pending = malloc((size_t)entryCount * sizeof(*pending));
	if (!pending) return -ENOMEM;
	memcpy(pending, entries, (size_t)entryCount * sizeof(*pending));
	qsort(pending, entryCount, sizeof(*pending), _trustcache_file_sort_entry_comparator_v1);

	uint32_t pendingCount = 0;
	for (uint32_t i = 0; i < entryCount; i++) {
		if (i > 0 && memcmp(pending[i - 1].hash, pending[i].hash, sizeof(cdhash_t)) == 0) continue;
		if (is_cdhash_trustcached(pending[i].hash)) continue;
		pending[pendingCount++] = pending[i];
	}
	if (pendingCount == 0) {
		free(pending);
		return 0;
	}

	struct jb_trustcache_mutation *mutations = calloc(pendingCount, sizeof(*mutations));
	if (!mutations) {
		free(pending);
		return -ENOMEM;
	}

	uint32_t pendingIndex = 0;
	uint32_t mutationCount = 0;
	int result = 0;
	while (pendingIndex < pendingCount) {
		__block uint64_t target = 0;
		__block uint32_t targetLength = 0;
		_jb_trustcache_enumerate(^(uint64_t jbTcKaddr, bool *stop) {
			uint32_t length = kread32(jbTcKaddr + offsetof(jb_trustcache, file.length));
			if (length < JB_TRUSTCACHE_ENTRY_COUNT) {
				target = jbTcKaddr;
				targetLength = length;
				*stop = true;
			}
		});
		if (!target) {
			target = _jb_trustcache_grow();
			targetLength = 0;
		}
		if (!target || targetLength >= JB_TRUSTCACHE_ENTRY_COUNT) {
			result = -ENOMEM;
			goto rollback;
		}

		uint32_t toInsert = JB_TRUSTCACHE_ENTRY_COUNT - targetLength;
		if (toInsert > pendingCount - pendingIndex) toInsert = pendingCount - pendingIndex;
		uint8_t *before = malloc(JB_TRUSTCACHE_SIZE);
		uint8_t *after = malloc(JB_TRUSTCACHE_SIZE);
		uint8_t *verify = malloc(JB_TRUSTCACHE_SIZE);
		if (!before || !after || !verify) {
			free(before);
			free(after);
			free(verify);
			result = -ENOMEM;
			goto rollback;
		}
		if (kreadbuf(target, before, JB_TRUSTCACHE_SIZE) != 0) {
			free(before);
			free(after);
			free(verify);
			result = -EIO;
			goto rollback;
		}
		memcpy(after, before, JB_TRUSTCACHE_SIZE);
		jb_trustcache *next = (jb_trustcache *)after;
		if (next->magic != JB_MAGIC || next->file.version != 1 || next->file.length != targetLength) {
			free(before);
			free(after);
			free(verify);
			result = -EIO;
			goto rollback;
		}
		for (uint32_t i = 0; i < toInsert; i++) next->file.entries[targetLength + i] = pending[pendingIndex + i];
		next->file.length += toInsert;
		_trustcache_file_sort(&next->file);

		mutations[mutationCount].address = target;
		mutations[mutationCount].before = before;
		mutationCount++;
		if (kwritebuf(target, after, JB_TRUSTCACHE_SIZE) != 0 ||
		    kreadbuf(target, verify, JB_TRUSTCACHE_SIZE) != 0 ||
		    memcmp(after, verify, JB_TRUSTCACHE_SIZE) != 0) {
			free(after);
			free(verify);
			result = -EIO;
			goto rollback;
		}
		free(after);
		free(verify);
		pendingIndex += toInsert;
	}

	for (uint32_t i = 0; i < mutationCount; i++) free(mutations[i].before);
	free(mutations);
	free(pending);
	return 0;

rollback:
	jb_trustcache_rollback(mutations, mutationCount);
	free(mutations);
	free(pending);
	return result;
}

int jb_trustcache_add_cdhashes(cdhash_t *hashes, uint32_t hashCount)
{
	if (hashCount == 0) return 0;
	if (!hashes || hashCount > JB_TRUSTCACHE_MAX_TRANSACTION_ENTRIES ||
	    (size_t)hashCount > SIZE_MAX / sizeof(trustcache_entry_v1)) return -EINVAL;
	trustcache_entry_v1 *entries = calloc(hashCount, sizeof(*entries));
	if (!entries) return -ENOMEM;
	for (uint32_t i = 0; i < hashCount; i++) {
		memcpy(entries[i].hash, hashes[i], sizeof(cdhash_t));
		entries[i].hash_type = 1;
	}
	int result = jb_trustcache_add_entries(entries, hashCount);
	free(entries);
	return result;
}

int jb_trustcache_add_entry(struct trustcache_entry_v1 entry)
{
	return jb_trustcache_add_entries(&entry, 1);
}


/*int jb_trustcache_add_file(const char *filePath)
{
	
}

int jb_trustcache_add_directory(const char *directoryPath)
{

}*/

xpc_object_t jb_trustcache_info(void)
{
	xpc_object_t arr = xpc_array_create_empty();
	_jb_trustcache_enumerate(^(uint64_t jbTcKaddr, bool *stop) {
		uuid_t uuid;
		kreadbuf(jbTcKaddr + offsetof(jb_trustcache, file.uuid), (void *)uuid, sizeof(uuid));
		uint32_t length = kread32(jbTcKaddr + offsetof(jb_trustcache, file.length));

		xpc_object_t tcDict = xpc_dictionary_create_empty();
		xpc_dictionary_set_data(tcDict, "uuid", &uuid, sizeof(uuid));

		xpc_object_t hashesArr = xpc_array_create_empty();
		for (int i = 0; i < length; i++) {
			trustcache_entry_v1 entry;
			kreadbuf(jbTcKaddr + offsetof(jb_trustcache, file.entries[i]), &entry, sizeof(entry));
			xpc_array_set_data(hashesArr, XPC_ARRAY_APPEND, &entry.hash, sizeof(entry.hash));
		}
		xpc_dictionary_set_value(tcDict, "cdhashes", hashesArr);
		xpc_release(hashesArr);

		xpc_array_append_value(arr, tcDict);
		xpc_release(tcDict);
	});
	return arr;
}

void jb_trustcache_debug_print(FILE *f)
{
	__block int i = 0;
	_jb_trustcache_enumerate(^(uint64_t jbTcKaddr, bool *stop) {
		uuid_t uuid;
		kreadbuf(jbTcKaddr + offsetof(jb_trustcache, file.uuid), (void *)uuid, sizeof(uuid));
		uint32_t length = kread32(jbTcKaddr + offsetof(jb_trustcache, file.length));

		uint32_t *uuidData = (uint32_t *)uuid;
		fprintf(f, "Jailbreak TrustCache %d <%08x%08x%08x%08x> (length: %u) (kaddr: 0x%llx):\n", i++, htonl(uuidData[0]), htonl(uuidData[1]), htonl(uuidData[2]), htonl(uuidData[3]), length, jbTcKaddr);
		
		for (uint32_t j = 0; j < length; j++) {
			trustcache_entry_v1 entry;
			kreadbuf(jbTcKaddr + offsetof(jb_trustcache, file.entries[j]), &entry, sizeof(entry));
			fprintf(f, "| ");
			for (uint32_t k = 0; k < sizeof(cdhash_t); k++) {
				fprintf(f, "%02x", entry.hash[k]);
			}
			fprintf(f, "\n");
		}
	});


	/////////////////////////////////////////////////////////////////
	_trustcache_list_enumerate(^(uint64_t tcKaddr, bool *stop) {
		if (_is_jb_trustcache(tcKaddr)) return;

		uint64_t tcFileKaddr = kread64(tcKaddr + koffsetof(trustcache, fileptr));
		uint32_t length = kread32(tcFileKaddr + offsetof(trustcache_file_v1, length));
		if (length == 0) return;
	
		uuid_t uuid;
		kreadbuf(tcFileKaddr + offsetof(trustcache_file_v1, uuid), (void *)uuid, sizeof(uuid));

		uint32_t *uuidData = (uint32_t *)uuid;
		fprintf(f, "TrustCache File <%08x%08x%08x%08x> (length: %u) (kaddr: 0x%llx):\n", htonl(uuidData[0]), htonl(uuidData[1]), htonl(uuidData[2]), htonl(uuidData[3]), length, tcFileKaddr);
		
		for (uint32_t j = 0; j < length; j++) {
			trustcache_entry_v1 entry;
			kreadbuf(tcFileKaddr + offsetof(trustcache_file_v1, entries[j]), &entry, sizeof(entry));
			fprintf(f, "| ");
			for (uint32_t k = 0; k < sizeof(cdhash_t); k++) {
				fprintf(f, "%02x", entry.hash[k]);
			}
			fprintf(f, "\n");
		}
	});
	
}

static int trustcache_payload_size(uint32_t entryCount, size_t *payloadSizeOut)
{
	if (!payloadSizeOut) return -EINVAL;
	/* entryCount is uint32_t and this product is bounded far below SIZE_MAX on
	 * every supported arm64 userspace; allocation-size policy is enforced by
	 * trustcache_compute_size before any kernel write. */
	*payloadSizeOut = sizeof(trustcache_file_v1) + (size_t)entryCount * sizeof(trustcache_entry_v1);
	return 0;
}

static bool trustcache_kernel_file_equals(uint64_t fileKaddr, const trustcache_file_v1 *file, size_t payloadSize)
{
	uint8_t *kernelCopy = malloc(payloadSize);
	if (!kernelCopy) return false;
	bool equal = kreadbuf(fileKaddr, kernelCopy, payloadSize) == 0 && memcmp(kernelCopy, file, payloadSize) == 0;
	free(kernelCopy);
	return equal;
}

static int trustcache_allocate_and_insert(const trustcache_file_v1 *tc, uint64_t tcSize, uint64_t *tcKaddrOut)
{
	uint64_t tcKaddr = 0;
	/* These must be initialized before any goto fail path: early payload/header
	 * failures have not touched list links and are therefore not safe to treat
	 * as a failed insert transaction. */
	bool linked = false;
	bool safeToFree = false;
	bool listTransactionStarted = false;
	if (!tcKaddrOut || kalloc(&tcKaddr, tcSize) != 0 || !tcKaddr) return -ENOMEM;
	uint8_t *head = calloc(1, ksizeof(trustcache));
	if (!head) {
		(void)kfree(tcKaddr, tcSize);
		return -ENOMEM;
	}
	int result = kwritebuf(tcKaddr, head, ksizeof(trustcache));
	free(head);
	if (result != 0) goto fail;

	uint64_t tcFileKaddr = tcKaddr + ksizeof(trustcache);
	/* Payload-only write is intentional.  Do not reintroduce the pre-45bfd49
	 * heap overrun by writing the kernel head into this allocation. */
	if (kwritebuf(tcFileKaddr, tc, tcSize - ksizeof(trustcache)) != 0 ||
	    !trustcache_kernel_file_equals(tcFileKaddr, tc, tcSize - ksizeof(trustcache))) {
		result = -EIO;
		goto fail;
	}
	if (kwrite64(tcKaddr + koffsetof(trustcache, fileptr), tcFileKaddr) != 0) {
		result = -EIO;
		goto fail;
	}
	if (koffsetof(trustcache, size) && kwrite64(tcKaddr + koffsetof(trustcache, size), tcSize) != 0) {
		result = -EIO;
		goto fail;
	}
	if (koffsetof(trustcache, type) && kwrite64(tcKaddr + koffsetof(trustcache, type), 0x5) != 0) {
		result = -EIO;
		goto fail;
	}
	listTransactionStarted = true;
	result = trustcache_list_insert_transactional(tcKaddr, &linked, &safeToFree);
	if (result != 0) goto fail;
	*tcKaddrOut = tcKaddr;
	return 0;

fail:
	/* A failed list publish can be reported after its final write committed, or
	 * leave a reverse link which still names the candidate.  Free only when the
	 * insert transaction proved both forward non-membership and reverse cleanup. */
	if (!listTransactionStarted || (safeToFree && !linked)) (void)kfree(tcKaddr, tcSize);
	return result;
}

int trustcache_file_upload(trustcache_file_v1 *tc)
{
	if (!trustcache_file_is_sorted(tc)) return -EINVAL;
	uint64_t tcSize = 0;
	int result = trustcache_compute_size(tc->length, &tcSize);
	if (result != 0) return result;
	size_t payloadSize = (size_t)(tcSize - ksizeof(trustcache));

	/* Check first for an already-identical UUID.  Update retries then become
	 * idempotent instead of allocating another cache or perturbing list order. */
	__block uint64_t existingTcKaddr = 0;
	__block uint64_t existingTcFile = 0;
	_trustcache_list_enumerate(^(uint64_t tcKaddr, bool *stop) {
		uint64_t tcFileKaddr = kread64(tcKaddr + koffsetof(trustcache, fileptr));
		if (!tcFileKaddr) return;
		uuid_t tcFileUUID;
		if (kreadbuf(tcFileKaddr + offsetof(trustcache_file_v1, uuid), tcFileUUID, sizeof(tcFileUUID)) != 0) return;
		if (memcmp(tcFileUUID, tc->uuid, sizeof(tcFileUUID)) == 0) {
			existingTcKaddr = tcKaddr;
			existingTcFile = tcFileKaddr;
			*stop = true;
		}
	});

	if (!existingTcKaddr) {
		uint64_t inserted = 0;
		return trustcache_allocate_and_insert(tc, tcSize, &inserted);
	}
	if (_is_jb_trustcache(existingTcKaddr)) return -EPERM;

	uint32_t previousLength = kread32(existingTcFile + offsetof(trustcache_file_v1, length));
	uint64_t previousTcSize = 0;
	result = trustcache_compute_size(previousLength, &previousTcSize);
	if (result != 0) return result;
	if (previousTcSize == tcSize) {
		/* Same-size replacement is the only in-place path.  Snapshot the complete
		 * payload first: unlike the grow/shrink path there is no second live cache
		 * to fall back to if a kernel write faults half way through. */
		trustcache_file_v1 *previousPayload = malloc(payloadSize);
		if (!previousPayload) return -ENOMEM;
		if (kreadbuf(existingTcFile, previousPayload, payloadSize) != 0) {
			free(previousPayload);
			return -EIO;
		}
		if (memcmp(previousPayload, tc, payloadSize) == 0) {
			free(previousPayload);
			return 0;
		}
		(void)kwritebuf(existingTcFile, tc, payloadSize);
		if (trustcache_kernel_file_equals(existingTcFile, tc, payloadSize)) {
			free(previousPayload);
			return 0;
		}
		/* Never claim an in-place update succeeded unless its replacement payload
		 * readbacks exactly.  Restore and verify the original before returning an
		 * error; if that verification also fails the caller still gets EIO rather
		 * than a false successful UUID update. */
		(void)kwritebuf(existingTcFile, previousPayload, payloadSize);
		bool restored = trustcache_kernel_file_equals(existingTcFile, previousPayload, payloadSize);
		free(previousPayload);
		(void)restored;
		return -EIO;
	}

	/* Publish a complete replacement before retiring the old UUID.  If allocation
	 * or insertion fails, the active BaseBin/DYLD trust cache is untouched. */
	uint64_t replacementTcKaddr = 0;
	result = trustcache_allocate_and_insert(tc, tcSize, &replacementTcKaddr);
	if (result != 0) return result;
	bool oldRemoved = false;
	result = trustcache_list_remove_transactional(existingTcKaddr, &oldRemoved);
	if (result != 0) {
		if (oldRemoved) {
			/* The forward list now reaches the verified replacement, but a rollback
			 * write could not be proven.  Do not free the detached old allocation
			 * while reporting the integrity failure. */
			return result;
		}

		/* The old cache is still linked.  Remove only a replacement which the
		 * transactional helper proves unreachable; retry once because a one-shot
		 * primitive fault must not strand two UUID-identical live entries. */
		bool replacementRemoved = false;
		int rollbackResult = -EIO;
		for (unsigned attempt = 0; attempt < 2 && !replacementRemoved; attempt++) {
			rollbackResult = trustcache_list_remove_transactional(replacementTcKaddr, &replacementRemoved);
		}
		if (replacementRemoved) {
			if (kfree(replacementTcKaddr, tcSize) != 0) return -EIO;
		}
		else {
			/* Persistent primitive failure: preserve both verified allocations rather
			 * than freeing a still-linked cache.  A retry is idempotent and the UUID
			 * lookup continues to select the old entry first. */
			return rollbackResult != 0 ? rollbackResult : -EIO;
		}
		return result;
	}

	/* List readers can have a borrowed pointer.  This matches upstream's grace
	 * interval, but only after a verified replacement is visible. */
	usleep(10000);
	if (kfree(existingTcKaddr, previousTcSize) != 0) return -EIO;
	return 0;
}

int trustcache_file_upload_with_uuid(trustcache_file_v1 *tc, uuid_t uuid)
{
	if (!tc || !uuid) return -EINVAL;
	size_t payloadSize = 0;
	if (trustcache_payload_size(tc->length, &payloadSize) != 0) return -EOVERFLOW;
	trustcache_file_v1 *copy = malloc(payloadSize);
	if (!copy) return -ENOMEM;
	memcpy(copy, tc, payloadSize);
	memcpy(copy->uuid, uuid, sizeof(uuid_t));
	int result = trustcache_file_upload(copy);
	free(copy);
	return result;
}

int trustcache_file_build_from_cdhashes(cdhash_t *CDHashes, uint32_t CDHashCount, trustcache_file_v1 **tcOut)
{
	if (tcOut) *tcOut = NULL;
	if (!CDHashes || CDHashCount == 0 || !tcOut) return -EINVAL;
	uint64_t tcSize = 0;
	int result = trustcache_compute_size(CDHashCount, &tcSize);
	if (result != 0) return result;
	size_t payloadSize = (size_t)(tcSize - ksizeof(trustcache));
	trustcache_file_v1 *file = malloc(payloadSize);
	if (!file) return -ENOMEM;
	_trustcache_file_init(file);

	file->length = CDHashCount;
	for (uint32_t i = 0; i < CDHashCount; i++) {
		memcpy(file->entries[i].hash, CDHashes[i], sizeof(cdhash_t));
		file->entries[i].hash_type = 2;
	}
	_trustcache_file_sort(file);
	*tcOut = file;
	return 0;
}

static int trustcache_read_all(int fd, void *buffer, size_t size)
{
	uint8_t *cursor = buffer;
	while (size > 0) {
		ssize_t count = read(fd, cursor, size);
		if (count < 0 && errno == EINTR) continue;
		if (count <= 0) return -EIO;
		cursor += count;
		size -= (size_t)count;
	}
	return 0;
}

int trustcache_file_build_from_path(const char *filePath, trustcache_file_v1 **tcOut)
{
	if (tcOut) *tcOut = NULL;
	if (!filePath || !tcOut) return -EINVAL;
	int fd = open(filePath, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return -errno;
	struct stat s = {0};
	if (fstat(fd, &s) != 0 || !S_ISREG(s.st_mode) || s.st_size < (off_t)sizeof(trustcache_file_v1)) {
		close(fd);
		return -EINVAL;
	}
	if ((uintmax_t)s.st_size > SIZE_MAX) {
		close(fd);
		return -E2BIG;
	}
	size_t payloadSize = (size_t)s.st_size;
	trustcache_file_v1 *file = malloc(payloadSize);
	if (!file) {
		close(fd);
		return -ENOMEM;
	}
	int result = trustcache_read_all(fd, file, payloadSize);
	close(fd);
	if (result != 0 || !trustcache_file_is_sorted(file)) {
		free(file);
		return result != 0 ? result : -EINVAL;
	}
	size_t expectedSize = 0;
	if (trustcache_payload_size(file->length, &expectedSize) != 0 || expectedSize != payloadSize) {
		free(file);
		return -EINVAL;
	}
	uint64_t allocationSize = 0;
	if (trustcache_compute_size(file->length, &allocationSize) != 0) {
		free(file);
		return -E2BIG;
	}
	*tcOut = file;
	return 0;
}

bool trustcache_contains_cdhash(uint64_t tcKaddr, cdhash_t CDHash)
{
	if (!tcKaddr || !CDHash) return false;
	uint64_t tcFileKaddr = kread64(tcKaddr + koffsetof(trustcache, fileptr));
	if (!tcFileKaddr) return false;
	uint32_t length = kread32(tcFileKaddr + offsetof(trustcache_file_v1, length));
	if (length == 0) return false;

	uint32_t left = 0;
	uint32_t right = length;
	while (left < right) {
		uint32_t mid = left + (right - left) / 2;
		cdhash_t itCDHash;
		if (kreadbuf(tcFileKaddr + offsetof(trustcache_file_v1, entries[mid].hash), itCDHash, CS_CDHASH_LEN) != 0) return false;
		int32_t cmp = memcmp(CDHash, itCDHash, CS_CDHASH_LEN);
		if (cmp == 0) {
			return true;
		}
		if (cmp < 0) {
			right = mid;
		} else {
			left = mid + 1;
		}
	}
	return false;
}

bool is_cdhash_in_trustcache(uint64_t tcKaddr, cdhash_t CDHash)
{
	return trustcache_contains_cdhash(tcKaddr, CDHash);
}

bool is_cdhash_trustcached(cdhash_t CDHash)
{
	__block bool inTrustCache = false;
	_trustcache_list_enumerate(^(uint64_t tcKaddr, bool *stop) {
		bool inThisTrustCache = trustcache_contains_cdhash(tcKaddr, CDHash);
		if (inThisTrustCache) {
			inTrustCache = true;
			*stop = true;
		}
	});
	return inTrustCache;
}
