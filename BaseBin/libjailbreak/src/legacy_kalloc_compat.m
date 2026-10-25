#include "legacy_kalloc_compat.h"

#include "primitives.h"
#include "translation.h"
#include "util.h"

#import <Foundation/Foundation.h>

static NSMutableArray<NSNumber *> *gLegacyPageTablePool;

static int legacy_kalloc_global_pt(uint64_t *kaddrOut, uint64_t size)
{
	@autoreleasepool {
		if (!kaddrOut || size == 0 || size > vm_real_kernel_page_size) return -1;
		if (gLegacyPageTablePool.count) {
			NSNumber *poolAllocation = gLegacyPageTablePool[0];
			[gLegacyPageTablePool removeObjectAtIndex:0];
			*kaddrOut = poolAllocation.unsignedLongLongValue;
			return 0;
		}

		uint64_t allocPA = alloc_page_table_unassigned();
		uint64_t allocVA = allocPA ? phystokv(allocPA) : 0;
		if (!allocVA) return -1;
		*kaddrOut = allocVA;
		return 0;
	}
}

static int legacy_kfree_global_pt(uint64_t kaddr, uint64_t size)
{
	(void)size;
	@autoreleasepool {
		if (!kaddr || !gLegacyPageTablePool) return -1;
		[gLegacyPageTablePool addObject:@(kaddr)];
		return 0;
	}
}

void libjailbreak_kalloc_pt_init(void)
{
	if (!gLegacyPageTablePool) gLegacyPageTablePool = [NSMutableArray new];
	gPrimitives.kalloc_global = legacy_kalloc_global_pt;
	gPrimitives.kfree_global = legacy_kfree_global_pt;
}
