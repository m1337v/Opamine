#include "txm.h"

#include <errno.h>

#include "util.h"

int TXMCodeRegion_comparator(uint64_t regionSearchPtr, uint64_t regionCurPtr)
{
	uint64_t searchStartAddr = kread64(regionSearchPtr + koffsetof(TXMCodeRegion, startAddr));
	uint64_t curStartAddr = kread64(regionCurPtr + koffsetof(TXMCodeRegion, startAddr));
	if (searchStartAddr < curStartAddr) return -1;
	if (searchStartAddr > curStartAddr) return 1;
	return 0;
}

RB_GENERATE(TXMCodeRegionRBTree, uint64_t, koffsetof(TXMCodeRegion, RBLink), TXMCodeRegion_comparator)

int txm_code_region_allocator_status(void)
{
	if (!jbinfo_sptm_runtime_ready() || !koffsetof(pmap, txm_address_space) ||
	    !koffsetof(TXMAddressSpace, codeRegions) || !koffsetof(TXMCodeRegion, active) ||
	    !koffsetof(TXMCodeRegion, startAddr) || !koffsetof(TXMCodeRegion, RBLink)) return -ENOTSUP;
	/* iOS 26 requires hookd_vm_protect.  This RootHide port deliberately does
	 * not call vm_protect directly there until hookd, its launchd provider, and
	 * the caller-side policy are landed as one transaction. */
	if (__builtin_available(iOS 26.0, *)) return -ENOTSUP;
	return 0;
}

uint64_t allocateCodeRegionObject(void)
{
	if (txm_code_region_allocator_status() != 0) return 0;

	vm_address_t victimPage = 0;
	if (vm_allocate(mach_task_self_, &victimPage, 0x4000, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) return 0;
	if (vm_protect(mach_task_self_, victimPage, 0x4000, false,
	               VM_PROT_READ | VM_PROT_EXECUTE | VM_PROT_COPY) != KERN_SUCCESS) {
		(void)vm_deallocate(mach_task_self_, victimPage, 0x4000);
		return 0;
	}

	uint64_t faultValue = 0;
	vm_size_t readSize = sizeof(faultValue);
	if (vm_read_overwrite(mach_task_self_, victimPage, readSize, (vm_address_t)&faultValue, &readSize) != KERN_SUCCESS ||
	    readSize != sizeof(faultValue)) {
		(void)vm_deallocate(mach_task_self_, victimPage, 0x4000);
		return 0;
	}

	uint64_t pmap = pmap_self();
	uint64_t txmAddressSpace = pmap ? kread_ptr(pmap + koffsetof(pmap, txm_address_space)) : 0;
	uint64_t head = txmAddressSpace ? txmAddressSpace + koffsetof(TXMAddressSpace, codeRegions) : 0;
	uint64_t keyBacking = phystokv(vtophys(ttep_self(), (uint64_t)&victimPage));
	if (!head || !keyBacking || keyBacking < koffsetof(TXMCodeRegion, startAddr)) {
		(void)vm_deallocate(mach_task_self_, victimPage, 0x4000);
		return 0;
	}
	/* startAddr stores the backing kernel VA of the faulted user page.  Build
	 * the RB lookup key only after validating the translation, so a failed
	 * primitive cannot wrap into an arbitrary tree lookup. */
	uint64_t key = keyBacking - koffsetof(TXMCodeRegion, startAddr);
	uint64_t victimDebugRegion = RB_FIND(TXMCodeRegionRBTree, head, key);
	if (!victimDebugRegion || RB_REMOVE(TXMCodeRegionRBTree, head, victimDebugRegion) != victimDebugRegion) {
		(void)vm_deallocate(mach_task_self_, victimPage, 0x4000);
		return 0;
	}
	(void)vm_deallocate(mach_task_self_, victimPage, 0x4000);

	uint8_t cleared[0x50] = {0};
	if (kwritebuf(victimDebugRegion, cleared, sizeof(cleared)) != 0 ||
	    kwrite8(victimDebugRegion + koffsetof(TXMCodeRegion, active), true) != 0) return 0;
	return victimDebugRegion;
}
