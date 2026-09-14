#ifndef LJB_TXM_H
#define LJB_TXM_H

#include "tree_krw.h"
#include "translation.h"

enum {
	kTXMCodeRegionTypeExecutable = 0,
	kTXMCodeRegionTypeSharedRegion = 1,
	kTXMCodeRegionTypeJIT = 2,
	kTXMCodeRegionTypeDebug = 3,
};

RB_PROTOTYPE(TXMCodeRegionRBTree, uint64_t, koffsetof(TXMCodeRegion, RBLink), TXMCodeRegion_comparator)

/* 0 on a supported 17–25 TXM runtime; -ENOTSUP for legacy/incomplete startup
 * and intentionally on iOS 26+ until the hookd/provider transaction lands. */
int txm_code_region_allocator_status(void);
uint64_t allocateCodeRegionObject(void);

#endif
