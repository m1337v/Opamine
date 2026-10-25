#ifndef LJB_LEGACY_KALLOC_COMPAT_H
#define LJB_LEGACY_KALLOC_COMPAT_H

/*
 * Compatibility only: RootHide's external boomerang/launchdhook consumers
 * still expect the iOS 16 page-table allocator to be installed after the
 * primitive handoff.  The previous kalloc_pt implementation was retired
 * from the active source tree; this shim keeps its ABI without reviving a
 * duplicate legacy module.
 */
void libjailbreak_kalloc_pt_init(void);

#endif
