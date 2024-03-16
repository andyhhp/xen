#ifndef _ASM_X86_SLAUNCH_H_
#define _ASM_X86_SLAUNCH_H_

#include <xen/types.h>
#include <xen/slr_table.h>

#define DRTM_LOC                   2
#define DRTM_CODE_PCR              17
#define DRTM_DATA_PCR              18

/*
 * Secure Launch event log entry types. The TXT specification defines the
 * base event value as 0x400 for DRTM values.
 *
 * Using the same values for AMD SKINIT.
 */
#define TXT_EVTYPE_BASE            0x400
#define DLE_EVTYPE_SLAUNCH         (TXT_EVTYPE_BASE + 0x102)
#define DLE_EVTYPE_SLAUNCH_START   (TXT_EVTYPE_BASE + 0x103)
#define DLE_EVTYPE_SLAUNCH_END     (TXT_EVTYPE_BASE + 0x104)

#ifndef cpuid
/*
 * Generic CPUID function
 * clear %ecx since some cpus (Cyrix MII) do not set or clear %ecx
 * resulting in stale register contents being returned.
 *
 * Copied from processor.h because that header can't be included by early code.
 */
#define cpuid(_op,_eax,_ebx,_ecx,_edx)          \
    asm volatile ( "cpuid"                      \
          : "=a" (*(int *)(_eax)),              \
            "=b" (*(int *)(_ebx)),              \
            "=c" (*(int *)(_ecx)),              \
            "=d" (*(int *)(_edx))               \
          : "0" (_op), "2" (0) )
#endif

extern bool slaunch_active;
extern uint32_t slaunch_slrt; /* physical address */

/* evt_log is a physical address and the caller must map it to virtual, if
 * needed. */
static inline void find_evt_log(struct slr_table *slrt, void **evt_log,
                                uint32_t *evt_log_size)
{
    struct slr_entry_log_info *log_info =
        (void *)slr_next_entry_by_tag(slrt, NULL, SLR_ENTRY_LOG_INFO);

    if ( log_info != NULL ) {
        *evt_log = _p(log_info->addr);
        *evt_log_size = log_info->size;
    } else {
        *evt_log = NULL;
        *evt_log_size = 0;
    }
}

void map_slaunch_mem_regions(void);

void protect_slaunch_mem_regions(void);

/*
 * This helper function is used to map memory using L2 page tables by aligning
 * mapped regions to 2MB. This way page allocator (which at this point isn't
 * yet initialized) isn't needed for creating new L1 mappings. The function
 * also checks and skips memory already mapped by the prebuilt tables.
 *
 * There is no unmap_l2() because the function is meant to be used for code that
 * accesses TXT registers and TXT heap soon after which Xen rebuilds memory
 * maps, effectively dropping all existing mappings.
 */
extern int map_l2(unsigned long paddr, unsigned long size);

#endif /* _ASM_X86_SLAUNCH_H_ */
