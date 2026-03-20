#include "util.h"
#include "primitives.h"
#include "info.h"
#include "kernel.h"
#include "translation.h"
#include <spawn.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/sysctl.h>
#include <archive.h>
#include <archive_entry.h>
#include <math.h>
#include <mach-o/dyld.h>
#include <dirent.h>
#include <IOKit/IOKitLib.h>
#include <mach-o/dyld_images.h>
#include <mach-o/getsect.h>
#include <dyld_cache_format.h>
extern char **environ;

#define FAKE_PHYSPAGE_TO_MAP 0x13370000

#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
extern int posix_spawnattr_set_persona_np(const posix_spawnattr_t* __restrict, uid_t, uint32_t);
extern int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t* __restrict, uid_t);
extern int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t* __restrict, uid_t);
int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t * __restrict attr, mach_port_t portarray[], uint32_t count);

const struct mach_header *get_mach_header(const char *name)
{
	const struct mach_header *mh = NULL;
	for (int i = 0; i < _dyld_image_count(); i++) {
		if (!strcmp(_dyld_get_image_name(i), name)) {
			mh = _dyld_get_image_header(i);
			break;
		}
	}
	return mh;
}

void proc_iterate(void (^itBlock)(uint64_t, bool*))
{
	uint64_t proc = ksymbol(allproc);
	while((proc = kread_ptr(proc + koffsetof(proc, list_next))))
	{
		bool stop = false;
		itBlock(proc, &stop);
		if(stop) return;
	}
}

uint64_t proc_self(void)
{
	static uint64_t gSelfProc = 0;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		gSelfProc = proc_find(getpid());
		// decrement ref count again, we assume proc_self will exist for the whole lifetime of this process
		proc_rele(gSelfProc);
	});
	return gSelfProc;
}

uint64_t task_self(void)
{
	static uint64_t gSelfTask = 0;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		gSelfTask = proc_task(proc_self());
	});
	return gSelfTask;
}

uint64_t vm_map_self(void)
{
	static uint64_t gSelfMap = 0;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		gSelfMap = kread_ptr(task_self() + koffsetof(task, map));
	});
	return gSelfMap;
}

uint64_t pmap_self(void)
{
	static uint64_t gSelfPmap = 0;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		gSelfPmap = kread_ptr(vm_map_self() + koffsetof(vm_map, pmap));
	});
	return gSelfPmap;
}

uint64_t ttep_self(void)
{
	static uint64_t gSelfTTEP = 0;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		gSelfTTEP = kread_ptr(pmap_self() + koffsetof(pmap, ttep));
	});
	return gSelfTTEP;
}

uint64_t tte_self(void)
{
	static uint64_t gSelfTTE = 0;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		gSelfTTE = kread_ptr(pmap_self() + koffsetof(pmap, tte));
	});
	return gSelfTTE;
}

uint64_t task_get_ipc_port_table_entry(uint64_t task, mach_port_t port)
{
	uint64_t itk_space = kread_ptr(task + koffsetof(task, itk_space));
	return ipc_entry_lookup(itk_space, port);
}

uint64_t task_get_ipc_port_object(uint64_t task, mach_port_t port)
{
	return kread_ptr(task_get_ipc_port_table_entry(task, port) + koffsetof(ipc_entry, object));
}

uint64_t task_get_ipc_port_kobject(uint64_t task, mach_port_t port)
{
	return kread_ptr(task_get_ipc_port_object(task, port) + koffsetof(ipc_port, kobject));
}

uint64_t alloc_page_table_unassigned(void)
{
    // On SPTM devices, we cannot directly manipulate page table entries
    // or reference counts. SPTM manages all frame types and PTEs atomically.
    // Return 0 to signal that caller should use kcall-based approach instead.
    if (jbinfo(usesSPTM)) {
        return 0;
    }
    uint64_t pmap = pmap_self();
    uint64_t ttep = kread64(pmap + koffsetof(pmap, ttep));
    uint64_t tte_lvl2 = 0;
    uint64_t allocatedPT = 0;
    uint64_t pinfo_pa = 0;

    while (true) {
        // Allocate 2x so we can align manually, avoiding posix_memalign's
        // large-alignment malloc zone issues on iOS 17
        void *map_base = mmap(NULL, L2_BLOCK_SIZE * 2, PROT_READ|PROT_WRITE,
                              MAP_PRIVATE|MAP_ANON, -1, 0);
        if (map_base == MAP_FAILED) {
            printf("WARNING: Failed to mmap L2 page table address range\n");
            return 0;
        }

        // Manually align up to L2_BLOCK_SIZE boundary
        void *free_lvl2 = (void *)(((uintptr_t)map_base + L2_BLOCK_SIZE - 1) & ~((uintptr_t)(L2_BLOCK_SIZE - 1)));

        // Fault in one page to make the kernel allocate the page table for it
        *(volatile uint64_t *)free_lvl2;

        // Find the newly allocated page table
        uint64_t lvl = PMAP_TT_L2_LEVEL;
        allocatedPT = vtophys_lvl(ttep, (uint64_t)free_lvl2, &lvl, &tte_lvl2);
        uint64_t pvh = pai_to_pvh(pa_index(allocatedPT));
        uint64_t ptdp = pvh_ptd(pvh);
        uint64_t pinfo = kread64(ptdp + koffsetof(pt_desc, ptd_info));
        pinfo_pa = kvtophys(pinfo);
        uint16_t refCount = physread16(pinfo_pa);
        if (refCount != 1) {
            munmap(map_base, L2_BLOCK_SIZE * 2);
            continue;
        }

        // Bump reference count so the page table survives deallocation
        physwrite16(pinfo_pa, 0x1337);

        // Release the address range — page table stays due to bumped refcount
        munmap(map_base, L2_BLOCK_SIZE * 2);
        break;
    }

    // Remove our allocated page table from its original location (leak it)
    physwrite64(tte_lvl2, 0);

    // Refcount must be 0 — our PTEs are outside the pmap layer
    physwrite16(pinfo_pa, 0);

    return allocatedPT;
}

uint64_t pmap_alloc_page_table(uint64_t pmap, uint64_t va)
{
	if (!pmap) {
		pmap = pmap_self();
	}

	uint64_t tt_p = alloc_page_table_unassigned();
	if (!tt_p) return 0;

	uint64_t pvh = pai_to_pvh(pa_index(tt_p));
	uint64_t ptdp = pvh_ptd(pvh);

	uint64_t ptdp_pa = kvtophys(ptdp);

	// At this point the allocated page table is associated
	// to the pmap of this process alongside the address it was allocated on
	// We now need to replace the association with the context in which it will be used
	physwrite64(ptdp_pa + koffsetof(pt_desc, pmap), pmap);

	// On A14+ PT_INDEX_MAX is 4, for whatever reason
	// However in practice, only the first slot is used...
	for (uint64_t po = 0; po < vm_page_size; po += vm_real_kernel_page_size) {
		physwrite64(ptdp_pa + koffsetof(pt_desc, va) + (po / vm_page_size), va + po);
	}

	return tt_p;
}

int pmap_expand_range(uint64_t pmap, uint64_t vaStart, uint64_t size)
{
	// On SPTM devices, page table expansion must go through SPTM APIs
	// We cannot directly write to PTEs or modify pmap type fields
	// Use kcall to pmap_enter_options_addr if available, otherwise fail gracefully
	if (jbinfo(usesSPTM)) {
		if (is_kcall_available()) {
			// Use kcall to expand via pmap_enter (SPTM-approved path)
			uint64_t l2Start = (vaStart & ~L2_BLOCK_MASK);
			uint64_t l2End = (((vaStart + size) + (L2_BLOCK_SIZE-1)) & ~L2_BLOCK_MASK);
			for (uint64_t va = l2Start; va < l2End; va += L2_BLOCK_SIZE) {
				uint64_t kr = 0;
				kcall(&kr, ksymbol(pmap_enter_options_addr), 8,
					(uint64_t[]){ pmap, va, FAKE_PHYSPAGE_TO_MAP, VM_PROT_READ | VM_PROT_WRITE, 0, 0, 1, 1 });
				if (kr != KERN_SUCCESS && kr != KERN_RESOURCE_SHORTAGE) {
					return -7;
				}
				kcall(&kr, ksymbol(pmap_remove_options), 4,
					(uint64_t[]){ pmap, va, va + vm_real_kernel_page_size, 0x100 });
			}
			return 0;
		}
		// Without kcall, we cannot expand page tables on SPTM
		return -1;
	}
	uint64_t ttep = kread_ptr(pmap + koffsetof(pmap, ttep));

	if (is_kcall_available()) {
		uint64_t unmappedStart = 0, unmappedSize = 0;

		uint64_t l2Start = vaStart & ~L2_BLOCK_MASK;
		uint64_t l2End = (vaStart + (size - 1)) & ~L2_BLOCK_MASK;
		uint64_t l2Count = ((l2End - l2Start) / L2_BLOCK_SIZE) + 1;

		for (uint64_t i = 0; i <= l2Count; i++) {
			uint64_t curL2 = l2Start + (i * L2_BLOCK_SIZE);

			uint64_t leafLevel = PMAP_TT_L3_LEVEL;
			uint64_t pt3 = 0;
			vtophys_lvl(ttep, curL2, &leafLevel, &pt3);
			if (leafLevel == PMAP_TT_L3_LEVEL || i == l2Count) {
				// i == l2Count: one extra cycle that this for loop takes
				// We hit this block either if there was a mapping or at the end
				// Alloc page tables for the current area (unmappedStart, unmappedSize) by running pmap_enter_options on every page
				// And then running pmap_remove on the entire area while nested is true

				for (uint64_t l2Off = 0; l2Off < unmappedSize; l2Off += L2_BLOCK_SIZE) {
					kern_return_t kr = pmap_enter_options_addr(pmap, FAKE_PHYSPAGE_TO_MAP, unmappedStart + l2Off);
					if (kr != KERN_SUCCESS) {
						return -7;
					}
				}

				// Set type to nested
				physwrite8(kvtophys(pmap + koffsetof(pmap, type)), 3);

				// Remove mapping (table will stay cause nested is set)
				pmap_remove(pmap, unmappedStart, unmappedStart + unmappedSize);

				// Change type back
				physwrite8(kvtophys(pmap + koffsetof(pmap, type)), 0);
				
				unmappedStart = 0;
				unmappedSize = 0;
				continue;
			}
			else {
				if (unmappedStart == 0) {
					unmappedStart = curL2;
				}
				unmappedSize += L2_BLOCK_SIZE;
			}
		}
	}
	else {
		uint64_t l2Start = (vaStart & ~L2_BLOCK_MASK);
		uint64_t l2End   = (((vaStart + size) + (L2_BLOCK_SIZE-1)) & ~L2_BLOCK_MASK);
		for (uint64_t va = l2Start; va < l2End; va += L2_BLOCK_SIZE) {
			uint64_t leafLevel;
			do {
				leafLevel = PMAP_TT_L3_LEVEL;
				uint64_t pte = 0;
				vtophys_lvl(ttep, va, &leafLevel, &pte);
				if (leafLevel != PMAP_TT_L3_LEVEL) {
					uint64_t pt_va = 0;
					switch (leafLevel) {
						case PMAP_TT_L1_LEVEL: {
							pt_va = va & ~L1_BLOCK_MASK;
							break;
						}
						case PMAP_TT_L2_LEVEL: {
							pt_va = va & ~L2_BLOCK_MASK;
							break;
						}
					}
					leafLevel++;
					uint64_t newTable = pmap_alloc_page_table(pmap, pt_va);
					if (newTable) {
						physwrite64(pte, newTable | ARM_TTE_VALID | ARM_TTE_TYPE_TABLE);
					}
					else {
						return -2;
					}
				}
			} while (leafLevel < PMAP_TT_L3_LEVEL);
		}
	}
	return 0;
}

int pmap_map_in(uint64_t pmap, uint64_t uaStart, uint64_t paStart, uint64_t size)
{
	// On SPTM devices, we cannot directly write to page table entries
	// Use kcall to pmap_enter_options_addr for each page (SPTM-approved)
	if (jbinfo(usesSPTM)) {
		if (!is_kcall_available()) return -1;
		uint64_t curPA = paStart;
		for (uint64_t ua = uaStart; ua < uaStart + size; ua += vm_real_kernel_page_size, curPA += vm_real_kernel_page_size) {
			uint64_t kr = 0;
			kcall(&kr, ksymbol(pmap_enter_options_addr), 8,
				(uint64_t[]){ pmap, ua, curPA, VM_PROT_READ | VM_PROT_WRITE, 0, 0, 1, 1 });
			if (kr != KERN_SUCCESS) return -1;
		}
		return 0;
	}
	uint64_t ttep = kread64(pmap + koffsetof(pmap, ttep));

	uint64_t paEnd = paStart + size;
	uint64_t uaEnd = uaStart + size;

	uint64_t uaL2Start = uaStart & ~L2_BLOCK_MASK;
	uint64_t uaL2End   = ((uaStart + size - 1) + L2_BLOCK_SIZE) & ~L2_BLOCK_MASK;

	uint64_t paL2Start = paStart & ~L2_BLOCK_MASK;
	uint64_t l2Count = (((uaL2End - uaL2Start) - 1) / L2_BLOCK_SIZE) + 1;

	// Sanity check: Ensure the entire area to be mapped in is not mapped to anything yet
	for(uint64_t ua = uaStart; ua < uaEnd; ua += vm_real_kernel_page_size) {
		uint64_t leafLevel = PMAP_TT_L3_LEVEL;
		if (vtophys_lvl(ttep, ua, &leafLevel, NULL) != 0) {
			return -1;
		}
		else {
			// Performance improvement
			// If there is no L1 / L2 mapping we can skip a whole bunch of addresses
			if (leafLevel == PMAP_TT_L1_LEVEL) {
				ua = (((ua + L1_BLOCK_SIZE) & ~L1_BLOCK_MASK) - vm_real_kernel_page_size);
			}
			else if (leafLevel == PMAP_TT_L2_LEVEL) {
				ua = (((ua + L2_BLOCK_SIZE) & ~L2_BLOCK_MASK) - vm_real_kernel_page_size);
			}
		}

		if (vtophys(ttep, ua)) return -1;
		// TODO: If all mappings match 1:1, maybe return 0 instead of -1?
	}

	// Allocate all page tables that need to be allocated
	if (pmap_expand_range(pmap, uaStart, size) != 0) return -1;

	// Insert entries into L3 pages
	uint64_t curPA = paStart;
	for (uint64_t i = 0; i < l2Count; i++) {
		uint64_t uaL2Cur = uaL2Start + (i * L2_BLOCK_SIZE);

		// Current L2 range
		uint64_t uaL2CurStart = uaL2Cur;
		uint64_t uaL2CurEnd = uaL2Cur + L2_BLOCK_SIZE;

		// Round to passed boundary if neccessary
		if (uaStart > uaL2CurStart) uaL2CurStart = uaStart;
		if (uaEnd < uaL2CurEnd) uaL2CurEnd = uaEnd;

		// Create full table for this mapping
		uint64_t tableToWrite[L2_BLOCK_COUNT];
		memset(tableToWrite, 0, sizeof(tableToWrite));
		for (uint64_t curUA = uaL2CurStart; curUA < uaL2CurEnd; curUA += vm_real_kernel_page_size, curPA += vm_real_kernel_page_size) {
			int idx = (curUA - uaL2Cur) / vm_real_kernel_page_size;
			tableToWrite[idx] = curPA | PERM_TO_PTE(PERM_KRW_URW) | PTE_NON_GLOBAL | PTE_OUTER_SHAREABLE | PTE_LEVEL3_ENTRY;
		}

		// Replace table with the entries we generated
		uint64_t leafLevel = PMAP_TT_L2_LEVEL;
		uint64_t level2Table = vtophys_lvl(ttep, uaL2Cur, &leafLevel, NULL);
		if (!level2Table) return -2;
		physwritebuf(level2Table, tableToWrite, vm_real_kernel_page_size);
	}

	return 0;
}

#ifdef __arm64e__

uint64_t pmap_find_main_binary_code_dir(uint64_t pmap)
{
	// On SPTM/TXM devices, pmap_cs structures don't exist in the same form
	// TXM manages code directories separately and they're not accessible
	// via the pmap structure. Return 0 to indicate unavailable.
	if (jbinfo(usesSPTM)) {
		return 0;
	}
	uint64_t mainCodeDir = 0;
	uint64_t pmap_cs_region = kread_ptr(pmap + koffsetof(pmap, pmap_cs_main));
	while (pmap_cs_region && !mainCodeDir) {
		uint64_t pmap_cs_code_dir = kread_ptr(pmap_cs_region + koffsetof(pmap_cs_region, cd_entry));
		while (pmap_cs_code_dir) {
			_Bool mainBinary = kread64(pmap_cs_code_dir + koffsetof(pmap_cs_code_directory, main_binary));
			if (mainBinary) {
				mainCodeDir = pmap_cs_code_dir;
				break;
			}
			pmap_cs_code_dir = kread_ptr(pmap_cs_code_dir + koffsetof(pmap_cs_code_directory, pmap_cs_code_directory_next));
		}
		pmap_cs_region = kread_ptr(pmap_cs_region + koffsetof(pmap_cs_region, pmap_cs_region_next));
	}
	return mainCodeDir;
}

uint64_t proc_find_main_binary_code_dir(uint64_t proc)
{
	uint64_t task = proc_task(proc);
	uint64_t map = kread_ptr(task + koffsetof(task, map));
	uint64_t pmap = kread_ptr(map + koffsetof(vm_map, pmap));
	return pmap_find_main_binary_code_dir(pmap);
}

uint32_t pmap_cs_trust_string_to_int(const char *trustString)
{
	int trustInt = 0;
	if (__builtin_available(iOS 16.0, *)) {
		if      (!strcmp(trustString, "PMAP_CS_UNTRUSTED"))             trustInt = 0;
		else if (!strcmp(trustString, "PMAP_CS_RETIRED"))               trustInt = 1;
		else if (!strcmp(trustString, "PMAP_CS_PROFILE_PREFLIGHT"))     trustInt = 2;
		else if (!strcmp(trustString, "PMAP_CS_COMPILATION_SERVICE"))   trustInt = 3;
		else if (!strcmp(trustString, "PMAP_CS_OOP_JIT"))               trustInt = 4;
		else if (!strcmp(trustString, "PMAP_CS_LOCAL_SIGNING"))         trustInt = 5;
		else if (!strcmp(trustString, "PMAP_CS_PROFILE_VALIDATED"))     trustInt = 6;
		else if (!strcmp(trustString, "PMAP_CS_APP_STORE"))             trustInt = 7;
		else if (!strcmp(trustString, "PMAP_CS_IN_LOADED_TRUST_CACHE")) trustInt = 8;
		else if (!strcmp(trustString, "PMAP_CS_IN_STATIC_TRUST_CACHE")) trustInt = 9;
	}
	else {
		if      (!strcmp(trustString, "PMAP_CS_UNTRUSTED"))             trustInt = 0;
		else if (!strcmp(trustString, "PMAP_CS_RETIRED"))               trustInt = 1;
		else if (!strcmp(trustString, "PMAP_CS_PROFILE_PREFLIGHT"))     trustInt = 2;
		else if (!strcmp(trustString, "PMAP_CS_COMPILATION_SERVICE"))   trustInt = 3;
		else if (!strcmp(trustString, "PMAP_CS_LOCAL_SIGNING"))         trustInt = 4;
		else if (!strcmp(trustString, "PMAP_CS_PROFILE_VALIDATED"))     trustInt = 5;
		else if (!strcmp(trustString, "PMAP_CS_APP_STORE"))             trustInt = 6;
		else if (!strcmp(trustString, "PMAP_CS_IN_LOADED_TRUST_CACHE")) trustInt = 7;
		else if (!strcmp(trustString, "PMAP_CS_IN_STATIC_TRUST_CACHE")) trustInt = 8;
	}
	return trustInt;
}

#endif

int sign_kernel_thread(uint64_t proc, mach_port_t threadPort)
{
	uint64_t threadKobj = task_get_ipc_port_kobject(proc_task(proc), threadPort);
	uint64_t threadContext = kread_ptr(threadKobj + koffsetof(thread, machine_contextData));

	uint64_t pc   = kread64(threadContext + offsetof(kRegisterState, pc));
	uint64_t cpsr = kread64(threadContext + offsetof(kRegisterState, cpsr));
	uint64_t lr   = kread64(threadContext + offsetof(kRegisterState, lr));
	uint64_t x16  = kread64(threadContext + offsetof(kRegisterState, x[16]));
	uint64_t x17  = kread64(threadContext + offsetof(kRegisterState, x[17]));

	return kcall(NULL, ksymbol(ml_sign_thread_state), 6, (uint64_t[]){ threadContext, pc, cpsr, lr, x16, x17 });
}

uint64_t kpacda(uint64_t pointer, uint64_t modifier)
{
	if (gPrimitives.kexec && kgadget(pacda)) {
		// |------- GADGET -------|
		// | cmp x1, #0		      |
		// | pacda x1, x9         |
		// | str x9, [x8]         |
		// | csel x9, xzr, x1, eq |
		// | ret                  |
		// |----------------------|
		uint64_t output = 0;
		uint64_t output_kernelVA = phystokv(vtophys(kread_ptr(pmap_self() + koffsetof(pmap, ttep)), (uint64_t)&output));
		kRegisterState threadState = { 0 };
		threadState.pc = kgadget(pacda);
		threadState.x[1] = pointer;
		threadState.x[9] = modifier;
		threadState.x[8] = output_kernelVA;
		kexec(&threadState);
		return output;
	}
	return 0;
}

uint64_t kptr_sign(uint64_t kaddr, uint64_t pointer, uint16_t salt)
{
	uint64_t modifier = (kaddr & 0xffffffffffff) | ((uint64_t)salt << 48);
	return kpacda(UNSIGN_PTR(pointer), modifier);
}

int kwrite1_bits(uint64_t startPtr, uint32_t bitCount)
{
	uint32_t byteSize = ceil((float)bitCount / 8);
	uint8_t buf[byteSize];

	for (uint32_t i = 0; i < bitCount; i += 8) {
		uint32_t rem = (bitCount - i);
		if (rem < 8) {
			for (int y = 0; y < rem; y++) {
				buf[i/8] |= (1 << y);
			}
		}
		else {
			buf[i/8] = 0xff;
		}
	}

	return kwritebuf(startPtr, buf, byteSize);
}

void proc_allow_all_syscalls(uint64_t proc)
{
	if (!gSystemInfo.kernelStruct.proc_ro.exists) return;
	uint64_t proc_ro = kread_ptr(proc + koffsetof(proc, proc_ro));

	uint64_t bsdFilter = kread_ptr(proc_ro + koffsetof(proc_ro, syscall_filter_mask));
	uint64_t machFilter = kread_ptr(proc_ro + koffsetof(proc_ro, mach_trap_filter_mask));
	uint64_t machKobjFilter = kread_ptr(proc_ro + koffsetof(proc_ro, mach_kobj_filter_mask));

	if (bsdFilter) {
		kwrite1_bits(bsdFilter, kconstant(nsysent));
	}
	if (machFilter) {
		kwrite1_bits(machFilter, kconstant(mach_trap_count));
	}
	if (machKobjFilter) {
		kwrite1_bits(machKobjFilter, kread64(ksymbol(mach_kobj_count)));
	}
}

void proc_remove_msg_filter(uint64_t proc)
{
	if (__builtin_available(iOS 16.0, *)) {
		#define TFRO_FILTER_MSG                 0x00004000

		if (koffsetof(proc_ro, t_flags_ro)) {
			// iOS 16.1+
			uint64_t proc_ro = kread_ptr(proc + koffsetof(proc, proc_ro));
			uint32_t t_flags = kread32(proc_ro + koffsetof(proc_ro, t_flags_ro));
			kwrite32(proc_ro + koffsetof(proc_ro, t_flags_ro), t_flags & ~TFRO_FILTER_MSG);
		}
		else if (koffsetof(task, flags)) {
			// iOS 16.0.x
			uint64_t task = proc_task(proc);
			uint32_t t_flags = kread32(task + koffsetof(task, flags));
			kwrite32(task + koffsetof(task, flags), t_flags & ~TFRO_FILTER_MSG);
		}
	}
}

int cmd_wait_for_exit(pid_t pid)
{
	int status = 0;
	do {
		if (waitpid(pid, &status, 0) == -1) {
			return -1;
		}
	} while (!WIFEXITED(status) && !WIFSIGNALED(status));
	return status;
}

int __exec_cmd_internal_va(bool suspended, bool root, bool waitForExit, pid_t *pidOut, const char *binary, int argc, va_list va_args, char **envp)
{
	const char *argv[argc+1];
	argv[0] = binary;
	for (int i = 1; i < argc; i++) {
		argv[i] = va_arg(va_args, const char *);
	}
	argv[argc] = NULL;

	posix_spawnattr_t attr = NULL;
	posix_spawnattr_init(&attr);
	if (suspended) {
		posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
	}
	if (root) {
		posix_spawnattr_set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
		posix_spawnattr_set_persona_uid_np(&attr, 0);
		posix_spawnattr_set_persona_gid_np(&attr, 0);
	}

	char **envToUse = envp;
	if (!envToUse && getpid() != 1) {
		// We NEVER want to pass launchd's environment to any process whatsoever
		// This is because, amongst other things, it has DYLD_INSERT_LIBRARIES set to launchdhook which is NO good
		envToUse = environ;
	}

	pid_t spawnedPid = 0;
	int spawnError = posix_spawn(&spawnedPid, binary, NULL, &attr, (char *const *)argv, envToUse);
	if (attr) posix_spawnattr_destroy(&attr);
	if (spawnError != 0) return spawnError;

	if (waitForExit && !suspended) {
		return cmd_wait_for_exit(spawnedPid);
	}
	else if (pidOut) {
		*pidOut = spawnedPid;
	}
	return 0;
}

int exec_cmd(const char *binary, ...)
{
	int argc = 1;
	va_list args;
	va_start(args, binary);
	while (va_arg(args, const char *)) argc++;
	va_end(args);

	va_start(args, binary);
	int r = __exec_cmd_internal_va(false, false, true, NULL, binary, argc, args, NULL);
	va_end(args);
	return r;
}

int exec_cmd_nowait(pid_t *pidOut, const char *binary, ...)
{
	int argc = 1;
	va_list args;
	va_start(args, binary);
	while (va_arg(args, const char *)) argc++;
	va_end(args);

	va_start(args, binary);
	int r = __exec_cmd_internal_va(false, false, false, pidOut, binary, argc, args, NULL);
	va_end(args);
	return r;
}

int exec_cmd_suspended(pid_t *pidOut, const char *binary, ...)
{
	int argc = 1;
	va_list args;
	va_start(args, binary);
	while (va_arg(args, const char *)) argc++;
	va_end(args);

	va_start(args, binary);
	int r = __exec_cmd_internal_va(true, false, false, pidOut, binary, argc, args, NULL);
	va_end(args);
	return r;
}

int exec_cmd_root(const char *binary, ...)
{
	int argc = 1;
	va_list args;
	va_start(args, binary);
	while (va_arg(args, const char *)) argc++;
	va_end(args);

	va_start(args, binary);
	int r = __exec_cmd_internal_va(false, true, true, NULL, binary, argc, args, NULL);
	va_end(args);
	return r;
}

int exec_cmd_env(char **envp, const char *binary, ...)
{
	int argc = 1;
	va_list args;
	va_start(args, binary);
	while (va_arg(args, const char *)) argc++;
	va_end(args);

	va_start(args, binary);
	int r = __exec_cmd_internal_va(false, false, true, NULL, binary, argc, args, envp);
	va_end(args);
	return r;
}

int jbctl_earlyboot(mach_port_t earlyBootServer, ...)
{
	int argc = 2;
	va_list args;
	va_start(args, earlyBootServer);
	while (va_arg(args, const char *)) argc++;
	va_end(args);

	const char *jbctlPath = JBROOT_PATH("/basebin/jbctl");
	const char *argsArr[argc+1];
	argsArr[0] = jbctlPath;
	va_start(args, earlyBootServer);
	for (int i = 1; i < argc-1; i++) {
		argsArr[i] = va_arg(args, const char *);
	}
	argsArr[argc-1] = "earlyboot";
	argsArr[argc] = NULL;

	posix_spawnattr_t attr;
	posix_spawnattr_init(&attr);
	posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){earlyBootServer, MACH_PORT_NULL, MACH_PORT_NULL}, 3);
	pid_t spawnedPid = 0;
	int r = posix_spawn(&spawnedPid, jbctlPath, NULL, &attr, (char *const *)argsArr, NULL);
	posix_spawnattr_destroy(&attr);
	if (r != 0) return r;
	return cmd_wait_for_exit(spawnedPid);
}

void killall(const char *executablePath, int signal)
{
	static int maxArgumentSize = 0;
	if (maxArgumentSize == 0) {
		size_t size = sizeof(maxArgumentSize);
		if (sysctl((int[]){ CTL_KERN, KERN_ARGMAX }, 2, &maxArgumentSize, &size, NULL, 0) == -1) {
			perror("sysctl argument size");
			maxArgumentSize = 4096; // Default
		}
	}
	int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL};
	struct kinfo_proc *info;
	size_t length;
	int count;
	
	if (sysctl(mib, 3, NULL, &length, NULL, 0) < 0)
		return;
	if (!(info = malloc(length)))
		return;
	if (sysctl(mib, 3, info, &length, NULL, 0) < 0) {
		free(info);
		return;
	}
	count = length / sizeof(struct kinfo_proc);
	for (int i = 0; i < count; i++) {
		pid_t pid = info[i].kp_proc.p_pid;
		if (pid == 0) {
			continue;
		}
		size_t size = maxArgumentSize;
		char* buffer = (char *)malloc(length);
		if (sysctl((int[]){ CTL_KERN, KERN_PROCARGS2, pid }, 3, buffer, &size, NULL, 0) == 0) {
			char *cExecutablePath = buffer + sizeof(int);
			if (strcmp(cExecutablePath, executablePath) == 0) {
				kill(pid, signal);
			}
		}
		free(buffer);
	}
	free(info);
}

static int
copy_data(struct archive *ar, struct archive *aw)
{
	int r;
	const void *buff;
	size_t size;
	la_int64_t offset;

	for (;;) {
		r = archive_read_data_block(ar, &buff, &size, &offset);
		if (r == ARCHIVE_EOF)
			return (ARCHIVE_OK);
		if (r < ARCHIVE_OK)
			return (r);
		r = archive_write_data_block(aw, buff, size, offset);
		if (r < ARCHIVE_OK) {
			fprintf(stderr, "%s\n", archive_error_string(aw));
			return (r);
		}
	}
}

int libarchive_unarchive(const char *fileToExtract, const char *extractionPath)
{
	struct archive *a;
	struct archive *ext;
	struct archive_entry *entry;
	int flags;
	int r;

	/* Select which attributes we want to restore. */
	flags = ARCHIVE_EXTRACT_TIME;
	flags |= ARCHIVE_EXTRACT_PERM;
	flags |= ARCHIVE_EXTRACT_ACL;
	flags |= ARCHIVE_EXTRACT_FFLAGS;
	flags |= ARCHIVE_EXTRACT_OWNER;

	a = archive_read_new();
	archive_read_support_format_all(a);
	archive_read_support_filter_all(a);
	ext = archive_write_disk_new();
	archive_write_disk_set_options(ext, flags);
	archive_write_disk_set_standard_lookup(ext);
	if ((r = archive_read_open_filename(a, fileToExtract, 10240)))
			return 1;
	for (;;) {
			r = archive_read_next_header(a, &entry);
			if (r == ARCHIVE_EOF)
					break;
			if (r < ARCHIVE_OK)
					fprintf(stderr, "%s\n", archive_error_string(a));
			if (r < ARCHIVE_WARN)
					return 1;

			const char *currentFile = archive_entry_pathname(entry);
			char outputPath[PATH_MAX];
			strlcpy(outputPath, extractionPath, PATH_MAX);
			strlcat(outputPath, "/", PATH_MAX);
			strlcat(outputPath, currentFile, PATH_MAX);

			archive_entry_set_pathname(entry, outputPath);
			
			r = archive_write_header(ext, entry);
			if (r < ARCHIVE_OK)
					fprintf(stderr, "%s\n", archive_error_string(ext));
			else if (archive_entry_size(entry) > 0) {
					r = copy_data(a, ext);
					if (r < ARCHIVE_OK)
							fprintf(stderr, "%s\n", archive_error_string(ext));
					if (r < ARCHIVE_WARN)
							return 1;
			}
			r = archive_write_finish_entry(ext);
			if (r < ARCHIVE_OK)
					fprintf(stderr, "%s\n", archive_error_string(ext));
			if (r < ARCHIVE_WARN)
					return 1;
	}
	archive_read_close(a);
	archive_read_free(a);
	archive_write_close(ext);
	archive_write_free(ext);
	
	return 0;
}


// code from ktrw by Brandon Azad : https://github.com/googleprojectzero/ktrw
// A worker thread for activity_thread that just spins.
static void* worker_thread(void *arg)
{
	uint64_t end = *(uint64_t *)arg;
	for (;;) {
		close(-1);
		uint64_t now = mach_absolute_time();
		if (now >= end) {
			break;
		}
	}
	return NULL;
}

// A thread to alternately spin and sleep.
#define ACTIVITY_WORKER_COUNT 10
static void* activity_thread(void *arg)
{
	volatile uint64_t *runCount = arg;
	struct mach_timebase_info tb;
	mach_timebase_info(&tb);
	const unsigned milliseconds = 40;
	while (*runCount != 0) {
		// Spin for one period on multiple threads.
		uint64_t start = mach_absolute_time();
		uint64_t end = start + milliseconds * 1000 * 1000 * tb.denom / tb.numer;
		pthread_t worker[ACTIVITY_WORKER_COUNT];
		for (unsigned i = 0; i < ACTIVITY_WORKER_COUNT; i++) {
			pthread_create(&worker[i], NULL, worker_thread, &end);
		}
		worker_thread(&end);
		for (unsigned i = 0; i < ACTIVITY_WORKER_COUNT; i++) {
			pthread_join(worker[i], NULL);
		}
		// Sleep for one period.
		usleep(milliseconds * 1000);
	}
	return NULL;
}

static uint64_t gCaffeinateThreadRunCount = 0;
static pthread_t gCaffeinateThread = NULL;

void thread_caffeinate_start(void)
{
	if (gCaffeinateThreadRunCount == UINT64_MAX) return;
	gCaffeinateThreadRunCount++;
	if (gCaffeinateThreadRunCount == 1) {
		pthread_create(&gCaffeinateThread, NULL, activity_thread, &gCaffeinateThreadRunCount);
	}
}

void thread_caffeinate_stop(void)
{
	if (gCaffeinateThreadRunCount == 0) return;
	gCaffeinateThreadRunCount--;
	if (gCaffeinateThreadRunCount == 0) {
		pthread_join(gCaffeinateThread, NULL);
	}
}

void convert_data_to_hex_string(const void *data, size_t size, char *outBuf)
{
	unsigned char *pin = (unsigned char *)data;
	const char *hex = "0123456789ABCDEF";
	char *pout = outBuf;
	for(; pin < ((unsigned char *)data)+size; pout+=2, pin++){
		pout[0] = hex[(*pin>>4) & 0xF];
		pout[1] = hex[ *pin     & 0xF];
	}
	pout[0] = 0;
}

int convert_hex_string_to_data(const char *string, void *outBuf)
{
	size_t length = strlen(string);
	const char *pin = string;
	char *pout = outBuf;
	for (; pin < string+length; pin++) {
		char byte = *pin;
		if (byte >= '0' && byte <= '9') byte = byte - '0';
		else if (byte >= 'a' && byte <='f') byte = byte - 'a' + 10;
		else if (byte >= 'A' && byte <='F') byte = byte - 'A' + 10;
		else return -1;

		int shift = ((pin - (string+length)) % 2) ? 0 : 4;
		*pout = (*pout & ~(0xf << shift)) | (byte << shift);
		if (shift == 0) pout++;
	}
	return 0;
}

char *boot_manifest_hash(void)
{
	static char *gBuf = NULL;
	
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		io_registry_entry_t registryEntry = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/chosen");
		if (registryEntry) {
			CFDataRef bootManifestHashData = IORegistryEntryCreateCFProperty(registryEntry, CFSTR("boot-manifest-hash"), NULL, 0);
			CFIndex bootManifestHashLength = CFDataGetLength(bootManifestHashData);

			gBuf = malloc((bootManifestHashLength * 2 * sizeof(char)) + sizeof(char));
			unsigned char *buf = (unsigned char *)CFDataGetBytePtr(bootManifestHashData);
			convert_data_to_hex_string(buf, bootManifestHashLength, gBuf);

			CFRelease(bootManifestHashData);
		}
	});

	return gBuf;
}
