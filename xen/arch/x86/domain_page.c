/******************************************************************************
 * domain_page.h
 *
 * Allow temporary mapping of domain pages.
 *
 * Copyright (c) 2003-2006, Keir Fraser <keir@xensource.com>
 */

#include <xen/domain_page.h>
#include <xen/efi.h>
#include <xen/mm.h>
#include <xen/perfc.h>
#include <xen/pfn.h>
#include <xen/sched.h>
#include <xen/vmap.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <asm/hardirq.h>
#include <asm/setup.h>

/*
 * Global mapcache entries are implemented using the vmap() infrastructure.
 *
 * Local mapcache entries are implemented with a percpu linear range, starting
 * at PERCPU_MAPCACHE_START.  The maximum number of concurrent mappings we
 * expect to use (NR_MAPCACHE_SLOTS) is for a nested pagewalk.  Being a small
 * number, allocations are tracked with a simple bitmap (inuse).
 *
 * There is plenty of linear address space to use, so addresses are handed out
 * by index into the inuse bitmap, with unmapped guard pages inbetween, to
 * help catch bounds errors in the code using the mappings.
 *
 * It is *not* safe to pass local mapcache mappings to other CPUs to use.
 */

struct mapcache_info {
#define NR_MAPCACHE_SLOTS (CONFIG_PAGING_LEVELS * CONFIG_PAGING_LEVELS)
    unsigned long inuse;
};
static DEFINE_PER_CPU(struct mapcache_info, mapcache_info);

static unsigned long mapcache_idx_to_linear(unsigned int idx)
{
    return PERCPU_MAPCACHE_START + pfn_to_paddr(idx * 2 + 1);
}

static unsigned int mapcache_linear_to_idx(unsigned long linear)
{
    return paddr_to_pfn(linear - PERCPU_MAPCACHE_START) / 2;
}

static l1_pgentry_t *mapcache_l1e(unsigned long linear)
{
    l1_pgentry_t *l1t = (l1_pgentry_t *)PERCPU_MAPCACHE_L1ES;

    return &l1t[l1_table_offset(linear)];
}

/*
 * Look up a mapcache entry, based on a linear address, ASSERT()ing that it is
 * bounded senibly and in use.
 */
static l1_pgentry_t *lookup_inuse_mapcache_entry(
    unsigned long linear, unsigned int *p_idx)
{
    unsigned int idx;
    l1_pgentry_t *pl1e;

    ASSERT(linear >= PERCPU_MAPCACHE_START && linear < PERCPU_MAPCACHE_END);

    idx = mapcache_linear_to_idx(linear);
    ASSERT(idx < NR_MAPCACHE_SLOTS);
    ASSERT(test_bit(idx, &this_cpu(mapcache_info).inuse));

    if ( p_idx )
        *p_idx = idx;

    pl1e = mapcache_l1e(linear);
    ASSERT(l1e_get_flags(*pl1e) & _PAGE_PRESENT);

    return pl1e;
}

void *map_domain_page(mfn_t mfn)
{
    unsigned long flags, linear;
    unsigned int idx;
    struct mapcache_info *mci = &this_cpu(mapcache_info);
    l1_pgentry_t *pl1e;

#ifdef NDEBUG
    if ( mfn_x(mfn) <= PFN_DOWN(__pa(HYPERVISOR_VIRT_END - 1)) )
        return mfn_to_virt(mfn_x(mfn));
#endif

    if ( this_cpu(curr_extended_directmap) )
        return mfn_to_virt(mfn_x(mfn));

    /*
     * map_domain_page() is used from many contexts, including fault handlers.
     * Disable interrupts to keep the inuse bitmap consistent with the l1t.
     *
     * Be aware! Any #PF inside this region will most likely recurse with the
     * spurious pagefault handler until the BUG_ON() is hit.
     */
    local_irq_save(flags);

    idx = find_first_zero_bit(&mci->inuse, NR_MAPCACHE_SLOTS);
    BUG_ON(idx == NR_MAPCACHE_SLOTS);

    __set_bit(idx, &mci->inuse);

    linear = mapcache_idx_to_linear(idx);
    pl1e = mapcache_l1e(linear);

    ASSERT(!(l1e_get_flags(*pl1e) & _PAGE_PRESENT));
    *pl1e = l1e_from_mfn(mfn, __PAGE_HYPERVISOR_RW);
    barrier(); /* Ensure the pagetable is updated before enabling interrupts. */

    local_irq_restore(flags);

    return (void *)linear;
}

void unmap_domain_page(const void *ptr)
{
    struct mapcache_info *mci = &this_cpu(mapcache_info);
    unsigned long flags, linear = (unsigned long)ptr;
    unsigned int idx;
    l1_pgentry_t *pl1e;

    if ( linear >= DIRECTMAP_VIRT_START )
        return;

    pl1e = lookup_inuse_mapcache_entry(linear, &idx);

    local_irq_save(flags);

    *pl1e = l1e_empty();
    asm volatile ( "invlpg %0" :: "m" (*(char *)ptr) : "memory" );
    __clear_bit(idx, &mci->inuse);

    local_irq_restore(flags);
}

void *map_domain_page_global(mfn_t mfn)
{
    ASSERT(!in_irq() &&
           ((system_state >= SYS_STATE_boot &&
             system_state < SYS_STATE_active) ||
            local_irq_is_enabled()));

#ifdef NDEBUG
    if ( mfn_x(mfn) <= PFN_DOWN(__pa(HYPERVISOR_VIRT_END - 1)) )
        return mfn_to_virt(mfn_x(mfn));
#endif

    return vmap(&mfn, 1);
}

void unmap_domain_page_global(const void *ptr)
{
    unsigned long va = (unsigned long)ptr;

    if ( va >= DIRECTMAP_VIRT_START )
        return;

    ASSERT(va >= VMAP_VIRT_START && va < VMAP_VIRT_END);

    vunmap(ptr);
}

/* Translate a map-domain-page'd address to the underlying MFN */
mfn_t domain_page_map_to_mfn(const void *ptr)
{
    unsigned long va = (unsigned long)ptr;
    const l1_pgentry_t *pl1e;

    if ( va >= DIRECTMAP_VIRT_START )
        return _mfn(virt_to_mfn(ptr));

    if ( va >= VMAP_VIRT_START && va < VMAP_VIRT_END )
    {
        pl1e = virt_to_xen_l1e(va);
        BUG_ON(!pl1e);
    }
    else
        pl1e = lookup_inuse_mapcache_entry(va, NULL);

    return l1e_get_mfn(*pl1e);
}

static __init __maybe_unused void build_assertions(void)
{
    struct mapcache_info info;

    /* NR_MAPCACHE_SLOTS within the bounds of the inuse bitmap? */
    BUILD_BUG_ON(NR_MAPCACHE_SLOTS > (sizeof(info.inuse) * 8));

    /* Enough linear address space, including guard pages? */
    BUILD_BUG_ON((NR_MAPCACHE_SLOTS * 2) >
                 (PERCPU_MAPCACHE_END - PERCPU_MAPCACHE_START));
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
