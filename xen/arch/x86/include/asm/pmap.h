#ifndef __ASM_PMAP_H__
#define __ASM_PMAP_H__

#include <asm/fixmap.h>

static inline void arch_pmap_map(unsigned int slot, mfn_t mfn)
{
    unsigned long linear = (unsigned long)fix_to_virt(slot);
    l1_pgentry_t *pl1e = &l1_fixmap[l1_table_offset(linear)];

    BUILD_BUG_ON(FIX_APIC_BASE - 1 > L1_PAGETABLE_ENTRIES - 1);
    ASSERT(!(l1e_get_flags(*pl1e) & _PAGE_PRESENT));

    l1e_write(pl1e, l1e_from_mfn(mfn, PAGE_HYPERVISOR));
}

static inline void arch_pmap_unmap(unsigned int slot)
{
    unsigned long linear = (unsigned long)fix_to_virt(slot);
    l1_pgentry_t *pl1e = &l1_fixmap[l1_table_offset(linear)];

    l1e_write(pl1e, l1e_empty());
    flush_tlb_one_local(linear);
}

#endif /* __ASM_PMAP_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
