#include "txm.h"

#include <errno.h>

#include "util.h"
#include "hookd.h"

int TXMCodeRegion_comparator(uint64_t regionSearchPtr, uint64_t regionCurPtr)
{
	uint64_t searchStartAddr  = kread64(regionSearchPtr + koffsetof(TXMCodeRegion, startAddr));
	uint64_t curStartAddr     = kread64(regionCurPtr    + koffsetof(TXMCodeRegion, startAddr));

	if (searchStartAddr < curStartAddr) {
		return -1;
	}
	else if (searchStartAddr > curStartAddr) {
		return 1;
	}
	else {
		return 0;
	}
}

RB_GENERATE(TXMCodeRegionRBTree, uint64_t, koffsetof(TXMCodeRegion, RBLink), TXMCodeRegion_comparator)

/* D3 supplies hookd_vm_protect on iOS 26+, but all SPTM/TXM symbols and
 * offsets still need to be complete before we create or unlink an RB entry. */
static int txm_code_region_allocator_status(void)
{
	if (!jbinfo_sptm_runtime_ready() || !koffsetof(pmap, txm_address_space) ||
	    !koffsetof(TXMAddressSpace, codeRegions) || !koffsetof(TXMCodeRegion, active) ||
	    !koffsetof(TXMCodeRegion, startAddr) || !koffsetof(TXMCodeRegion, RBLink)) return -ENOTSUP;
	return 0;
}

uint64_t allocateCodeRegionObject(void)
{
	if (txm_code_region_allocator_status() != 0) return 0;
	// Here we simulate "allocating" a code region object by creating one in our process it and then removing it from the RB tree again to leak it
	// This works fine because nothing checks / panics if we remove it, just faulting in new code from the region would not work
	// Only works if the process calling this has allowsInvalidCode set to true

	// Allocate
	vm_address_t victimPage = 0;
	if (vm_allocate(mach_task_self_, &victimPage, 0x4000, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) return 0;

	// Make executable
	kern_return_t kr;
	if (__builtin_available(iOS 26, *)) {
		kr = hookd_vm_protect(mach_task_self_, victimPage, 0x4000, false, VM_PROT_READ | VM_PROT_EXECUTE | VM_PROT_COPY);
	}
	else {
		kr = vm_protect(mach_task_self_, victimPage, 0x4000, false, VM_PROT_READ | VM_PROT_EXECUTE | VM_PROT_COPY);
	}
	if (kr != KERN_SUCCESS) {
		vm_deallocate(mach_task_self_, victimPage, 0x4000);
		return 0;
	}

	// Fault in
	uint64_t faultValue = 0;
	vm_size_t readSize = sizeof(faultValue);
	if (vm_read_overwrite(mach_task_self_, victimPage, readSize, (vm_address_t)&faultValue, &readSize) != KERN_SUCCESS ||
	    readSize != sizeof(faultValue)) {
		vm_deallocate(mach_task_self_, victimPage, 0x4000);
		return 0;
	}

	// At this point there will be an associated code region in the rb tree, find and remove it
	uint64_t pmap = pmap_self();
	uint64_t txmAddressSpace = pmap ? kread_ptr(pmap + koffsetof(pmap, txm_address_space)) : 0;
	uint64_t head = txmAddressSpace ? txmAddressSpace + koffsetof(TXMAddressSpace, codeRegions) : 0;
	uint64_t keyBacking = phystokv(vtophys(ttep_self(), (uint64_t)&victimPage));
	if (!head || !keyBacking || keyBacking < koffsetof(TXMCodeRegion, startAddr)) {
		vm_deallocate(mach_task_self_, victimPage, 0x4000);
		return 0;
	}
	uint64_t key = keyBacking - koffsetof(TXMCodeRegion, startAddr);
	uint64_t victimDebugRegion = RB_FIND(TXMCodeRegionRBTree, head, key);
	if (!victimDebugRegion || RB_REMOVE(TXMCodeRegionRBTree, head, victimDebugRegion) != victimDebugRegion) {
		vm_deallocate(mach_task_self_, victimPage, 0x4000);
		return 0;
	}

	// Now deallocate the victimPage again
	vm_deallocate(mach_task_self_, victimPage, 0x4000);

	// Clear any leftover data
	uint8_t cleared[0x50] = {0};
	if (kwritebuf(victimDebugRegion, cleared, sizeof(cleared)) != 0 ||
	    kwrite8(victimDebugRegion + koffsetof(TXMCodeRegion, active), true) != 0) return 0;

	// This needs to be true when we return it in order for the object to be usable
	return victimDebugRegion;
}
