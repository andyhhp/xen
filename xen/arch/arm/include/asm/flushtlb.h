#ifndef __ASM_ARM_FLUSHTLB_H__
#define __ASM_ARM_FLUSHTLB_H__

#include <xen/cpumask.h>

#if defined(CONFIG_ARM_32)
# include <asm/arm32/flushtlb.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/flushtlb.h>
#else
# error "unknown ARM variant"
#endif

/* Flush specified CPUs' TLBs */
void arch_flush_tlb_mask(const cpumask_t *mask);

/*
 * Flush a range of VA's hypervisor mappings from the TLB of the local
 * processor.
 */
static inline void flush_xen_tlb_range_va_local(vaddr_t va,
                                                unsigned long size)
{
    vaddr_t end = va + size;

    /* See asm/arm{32,64}/flushtlb.h for the explanation of the sequence. */
    dsb(nshst); /* Ensure prior page-tables updates have completed */
    while ( va < end )
    {
        __flush_xen_tlb_one_local(va);
        va += PAGE_SIZE;
    }
    dsb(nsh); /* Ensure the TLB invalidation has completed */
    isb();
}

/*
 * Flush a range of VA's hypervisor mappings from the TLB of all
 * processors in the inner-shareable domain.
 */
static inline void flush_xen_tlb_range_va(vaddr_t va,
                                          unsigned long size)
{
    vaddr_t end = va + size;

    /* See asm/arm{32,64}/flushtlb.h for the explanation of the sequence. */
    dsb(ishst); /* Ensure prior page-tables updates have completed */
    while ( va < end )
    {
        __flush_xen_tlb_one(va);
        va += PAGE_SIZE;
    }
    dsb(ish); /* Ensure the TLB invalidation has completed */
    isb();
}

#endif /* __ASM_ARM_FLUSHTLB_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
