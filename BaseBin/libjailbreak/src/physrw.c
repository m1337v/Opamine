#include "physrw.h"
#include "primitives.h"
#include "kernel.h"
#include "translation.h"
#include "info.h"
#include "util.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool physrw_range_is_valid(uint64_t pa, uint64_t size)
{
	uint64_t physBase = kconstant(physBase);
	uint64_t physSize = kconstant(physSize);
	if (physSize == 0 || pa < physBase) return false;
	return size <= physSize && pa - physBase <= physSize - size;
}

void *physrw_phystouaddr(uint64_t pa)
{
	errno = 0;

	uint64_t physBase = kconstant(physBase), physSize = kconstant(physSize);
	if (physBase == 0 || physSize == 0 || !physrw_range_is_valid(pa, 1)) {
		errno = ENXIO;
		return 0;
	}

	if (arm_tt_level[1].indexMask == 0) {
		errno = ENOTSUP;
		return NULL;
	}
	uint64_t paUaStartOffset = physBase & ~(arm_tt_level[1].indexMask | (arm_tt_level[1].indexMask - 1));
	return (void *)((pa - paUaStartOffset) + PPLRW_USER_MAPPING_OFFSET);
}

void *physrw_kvtouaddr(uint64_t va)
{
	uint64_t pa = kvtophys(va);
	if (!pa) return 0;
	return physrw_phystouaddr(pa);
}

int physrw_physreadbuf(uint64_t pa, void* output, size_t size)
{
	if (size != 0 && !output) return EINVAL;
	if (!physrw_range_is_valid(pa, size)) {
		if (output) memset(output, 0, size);
		return ENXIO;
	}
	void *uaddr = physrw_phystouaddr(pa);
	if (!uaddr && errno != 0) {
		memset(output, 0x0, size);
		return errno;
	}

	asm volatile("dmb sy");
	memcpy(output, uaddr, size);
	return 0;
}

int physrw_physwritebuf(uint64_t pa, const void* input, size_t size)
{
	if (size != 0 && !input) return EINVAL;
	if (!physrw_range_is_valid(pa, size)) return ENXIO;
	void *uaddr = physrw_phystouaddr(pa);
	if (!uaddr && errno != 0) {
		return errno;
	}

	memcpy(uaddr, input, size);
	asm volatile("dmb sy");
	return 0;
}

int physrw_physaccess_mapped(uint64_t pa, uint64_t size, kernel_map_accessor accessorBlock)
{
	if (!accessorBlock || size == 0 || size > UINT64_MAX - pa) return -1;
	if (!physrw_range_is_valid(pa, size)) return -1;
	void *ptr = physrw_phystouaddr(pa);
	if (!ptr) return -1;
	accessorBlock(ptr);
	return 0;
}

int physrw_handoff(pid_t pid)
{
	if (!pid) return -1;

	uint64_t proc = proc_find(pid);
	if (!proc) return -2;

	int ret = 0;
	do {
		uint64_t task = proc_task(proc);
		if (!task) { ret = -3; break; };

		uint64_t vmMap = kread_ptr(task + koffsetof(task, map));
		if (!vmMap) { ret = -4; break; };

		uint64_t pmap = kread_ptr(vmMap + koffsetof(vm_map, pmap));
		if (!pmap) { ret = -5; break; };

		if (kconstant(physBase) == 0 || kconstant(physSize) == 0 || arm_tt_level[1].indexMask == 0) {
			ret = -6;
			break;
		}
		// On iOS 26+ SPTM systems physBase can exceed the user L1 addressable range.
		uint64_t paUaStartOffset = kconstant(physBase) & ~(arm_tt_level[1].indexMask | (arm_tt_level[1].indexMask - 1));
		// Map the kernel physical address space into the handoff process.
		int mapInRet = pmap_map_in(pmap, kconstant(physBase) - paUaStartOffset + PPLRW_USER_MAPPING_OFFSET, kconstant(physBase), kconstant(physSize));
		if (mapInRet != 0) ret = -10 + mapInRet;
	} while (0);

	proc_rele(proc);
	return ret;
}

int libjailbreak_physrw_init(bool receivedHandoff)
{
	int r = 0;
	if (!receivedHandoff) {
		r = physrw_handoff(getpid());
		if (r != 0) return r;
	}
	gPrimitives.physreadbuf = physrw_physreadbuf;
	gPrimitives.physwritebuf = physrw_physwritebuf;
	gPrimitives.physaccess_mapped = physrw_physaccess_mapped;
	gPrimitives.kreadbuf = NULL;
	gPrimitives.kwritebuf = NULL;

	return r;
}
