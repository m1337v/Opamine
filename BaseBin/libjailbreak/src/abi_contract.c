#include "info.h"
#include "primitives_external.h"
#include <stddef.h>

/*
 * Compile-time contract for the Dopamine 3 information extension.  system_info
 * is exchanged as named XPC fields, but these checks keep in-process users and
 * the primitive vtable from silently drifting when future RootHide work adds
 * fields.  This translation unit deliberately has no runtime behaviour.
 */
_Static_assert(sizeof(uint64_t) == 8, "libjailbreak requires 64-bit kernel addresses");
_Static_assert(offsetof(struct system_info, kernelConstant.staticSptmBase) ==
               offsetof(struct system_info, kernelConstant.staticBase) + sizeof(uint64_t),
               "SPTM static image base must follow kernel static image base");
_Static_assert(offsetof(struct system_info, kernelConstant.staticTxmBase) ==
               offsetof(struct system_info, kernelConstant.staticSptmBase) + sizeof(uint64_t),
               "TXM static image base must follow SPTM static image base");
_Static_assert(offsetof(struct system_info, kernelConstant.sptmBase) <
               offsetof(struct system_info, kernelConstant.txmBase),
               "SPTM/TXM live bases must retain their ordered ABI");
_Static_assert(offsetof(struct system_info, jailbreakInfo.appIdentifier) <
               offsetof(struct system_info, jailbreakInfo.jbrand),
               "RootHide jbrand must remain serialized after Dopamine app identity");
_Static_assert(offsetof(struct system_info, jailbreakInfo.jbrand) <
               offsetof(struct system_info, jailbreakInfo.palera1n),
               "RootHide jailbreak identity ordering changed");
_Static_assert(offsetof(struct system_info, kernelStruct.pmap.txm_address_space) >
               offsetof(struct system_info, kernelStruct.pmap.asid),
               "TXM pmap capability fields are incomplete");
_Static_assert(offsetof(struct kernel_primitives, physaccess_mapped) ==
               offsetof(struct kernel_primitives, kmap) + sizeof(((struct kernel_primitives *)0)->kmap),
               "mapped physical accessor must be appended after kmap");
_Static_assert(offsetof(struct kernel_primitives, vtophys) ==
               offsetof(struct kernel_primitives, physaccess_mapped) +
               sizeof(((struct kernel_primitives *)0)->physaccess_mapped),
               "primitive vtable ordering changed");
