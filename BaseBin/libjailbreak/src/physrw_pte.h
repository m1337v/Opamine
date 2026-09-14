#ifndef PHYSRW_PTE_H
#define PHYSRW_PTE_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include "info.h"

/* Keep two L1 slots above this window for the ASID page and future handoff
 * mappings.  Do not place it at the final slot used by newer XNU layouts. */
#define MAGIC_PT_ADDRESS (L1_BLOCK_SIZE * (L1_BLOCK_COUNT - 3))
#define gMagicPT ((uint64_t *)MAGIC_PT_ADDRESS)

int physrw_pte_handoff(pid_t pid, uint64_t *asidPtr);
int libjailbreak_physrw_pte_init(bool receivedHandoff, uint64_t asidPtr);
bool device_supports_physrw_pte(void);

#endif
