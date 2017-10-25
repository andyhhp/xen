/*
 * arch/x86/pv/pt-shadow.c
 *
 * PV Pagetable shadowing logic to allow Xen to run with per-pcpu pagetables.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2017 Citrix Systems Ltd.
 */
#include <xen/domain_page.h>
#include <xen/mm.h>
#include <xen/numa.h>

#include <asm/pv/pt-shadow.h>

/* Override macros from asm/mm.h to make them work with mfn_t */
#undef page_to_mfn
#define page_to_mfn(pg) _mfn(__page_to_mfn(pg))

/*
 * To use percpu linear ranges, we require that no two pcpus have %cr3
 * pointing at the same L4 pagetable at the same time.
 *
 * Guests however might choose to use the same L4 pagetable on multiple vcpus
 * at once, e.g. concurrently scheduling two threads from the same process.
 * In practice, all HVM guests, and 32bit PV guests run on Xen-provided
 * per-vcpu monitor tables, so it is only 64bit PV guests which are an issue.
 *
 * To resolve the issue, we shadow L4 pagetables from 64bit PV guests when
 * they are in context.
 *
 * The algorithm is fairly simple.
 *
 *   - A small cache of shadowed L4s from the same guest is maintained.
 *   - When a pcpu is switching to a new vcpu cr3 and shadowing is necessary,
 *     the cache is searched.
 *     - If the new cr3 is already cached, use our existing shadow.
 *     - If not, drop an entry and shadow the new frame with a full 4K copy.
 *   - When a write to a guests L4 pagetable occurs, the update must be
 *     propagated to all existing shadows.  An IPI is sent to the domains
 *     dirty mask indicating which frame/slot was updated, and each pcpu
 *     checks to see whether it needs to sync the update into its shadow.
 *   - When a guest L4 pagetable is freed, it must be dropped from any caches,
 *     as Xen will allow it to become writeable to the guest again, and its
 *     contents will go stale.  It uses the same IPI mechanism as for writes.
 */

#define L4_SHADOW_ORDER 2
#define NR_L4_SHADOWS   (1ul << L4_SHADOW_ORDER)

/*
 * An individual cache entry.  Contains a %cr3 which has been cached, and the
 * index of this entry into the shadow frames.
 *
 * The layout relies on %cr3 being page aligned, with the index stored in the
 * lower bits.  idx could be a smaller bitfield, but there is no other
 * information to store, and having it as an 8bit field results in better
 * compiled code.
 */
typedef union pt_cache_entry {
    unsigned long raw;
    struct {
        uint8_t idx;
        unsigned long :4, cr3_mfn:52;
    };
} pt_cache_entry_t;

struct pt_shadow {
    /*
     * A cache of frames used to shadow a vcpus intended pagetables.  When
     * shadowing, one of these frames is the one actually referenced by %cr3.
     */
    paddr_t shadow_l4;
    l4_pgentry_t *shadow_l4_va;

    /*
     * Domain to which the shadowed state belongs, or NULL if no state is
     * being cached.  IPIs for updates to cached information are based on the
     * domain dirty mask, which can race with the target of the IPI switching
     * to a different context.
     */
    const struct domain *domain;

    /*
     * A collection of %cr3's, belonging to @p domain, which are shadowed
     * locally.
     *
     * A cache entry is used if cr3_mfn != 0, free otherwise.  The cache is
     * maintained in most-recently-used order.  As a result, cache[0].cr3_mfn
     * should always match v->arch.cr3.
     *
     * The cache[].idx fields will always be unique, and between 0 and
     * NR_L4_SHADOWS.  Their order however will vary as most-recently-used
     * order is maintained.
     */
    pt_cache_entry_t cache[NR_L4_SHADOWS];
};

static DEFINE_PER_CPU(struct pt_shadow, ptsh);

static l4_pgentry_t *shadow_l4_va(struct pt_shadow *ptsh, unsigned int idx)
{
    return _p(ptsh->shadow_l4_va) + idx * PAGE_SIZE;
}

static paddr_t shadow_l4(struct pt_shadow *ptsh, unsigned int idx)
{
    return ptsh->shadow_l4 + idx * PAGE_SIZE;
}

int pt_shadow_alloc(unsigned int cpu)
{
    struct pt_shadow *ptsh = &per_cpu(ptsh, cpu);
    unsigned int memflags = 0, i;
    nodeid_t node = cpu_to_node(cpu);
    struct page_info *pg;
    mfn_t mfns[NR_L4_SHADOWS];

    if ( node != NUMA_NO_NODE )
        memflags = MEMF_node(node);

    pg = alloc_domheap_pages(NULL, L4_SHADOW_ORDER, memflags);
    if ( !pg )
        return -ENOMEM;

    ptsh->shadow_l4 = page_to_maddr(pg);

    for ( i = 0; i < ARRAY_SIZE(mfns); ++i )
    {
        /* Initialise the cache (ascending idx fields). */
        ptsh->cache[i] = (pt_cache_entry_t){ i };

        /* Collect MFNs to vmap(). */
        mfns[i] = mfn_add(maddr_to_mfn(ptsh->shadow_l4), i);
    }

    ptsh->shadow_l4_va = vmap(mfns, ARRAY_SIZE(mfns));
    if ( !ptsh->shadow_l4_va )
        return -ENOMEM;

    return 0;
}

void pt_shadow_free(unsigned int cpu)
{
    struct pt_shadow *ptsh = &per_cpu(ptsh, cpu);

    if ( ptsh->shadow_l4_va )
    {
        vunmap(ptsh->shadow_l4_va);
        ptsh->shadow_l4_va = NULL;
    }

    if ( ptsh->shadow_l4 )
    {
        free_domheap_pages(maddr_to_page(ptsh->shadow_l4), L4_SHADOW_ORDER);
        ptsh->shadow_l4 = 0;
    }
}

static pt_cache_entry_t *pt_cache_lookup(
    struct pt_shadow *ptsh, unsigned long maddr)
{
    unsigned int i;

    ASSERT(!local_irq_is_enabled());

    for ( i = 0; i < ARRAY_SIZE(ptsh->cache); ++i )
    {
        pt_cache_entry_t *ent = &ptsh->cache[i];

        if ( ent->cr3_mfn == (maddr >> PAGE_SHIFT) )
            return ent;
    }

    return NULL;
}

/*
 * We only need to shadow 4-level PV guests.  All other guests have per-vcpu
 * monitor tables which are never scheduled on concurrent pcpus.  Care needs
 * to be taken not to shadow d0v0 during construction, as it writes its L4
 * directly.
 */
static bool pt_need_shadow(const struct domain *d)
{
    return (system_state >= SYS_STATE_active && is_pv_domain(d) &&
            !is_idle_domain(d) && !is_pv_32bit_domain(d) && d->max_vcpus > 1);
}

unsigned long pt_maybe_shadow(struct vcpu *v)
{
    unsigned int cpu = smp_processor_id();
    struct pt_shadow *ptsh = &per_cpu(ptsh, cpu);
    unsigned long flags, new_cr3 = v->arch.cr3;
    pt_cache_entry_t *ent;

    /*
     * IPIs for updates are based on the domain dirty mask.  If we ever switch
     * out of the currently shadowed context (even to idle), the cache will
     * become stale.
     */
    if ( ptsh->domain &&
         ptsh->domain != v->domain )
    {
        unsigned int i;

        ptsh->domain = NULL;

        for ( i = 0; i < ARRAY_SIZE(ptsh->cache); ++i )
            ptsh->cache[i].cr3_mfn = 0;
    }

    /* No shadowing necessary? Run on the intended pagetable. */
    if ( !pt_need_shadow(v->domain) )
        return new_cr3;

    ptsh->domain = v->domain;

    /*
     * We may be called with interrupts disabled (e.g. context switch), or
     * interrupts enabled (e.g. new_guest_cr3()).
     *
     * Reads and modifications of ptsh-> are only on the local cpu, but must
     * be excluded against reads and modifications in _pt_shadow_ipi().
     */
    local_irq_save(flags);

    ent = pt_cache_lookup(ptsh, new_cr3);
    if ( ent )
    {
        /*
         * Cache hit.  Promote this entry to being most recently used (if it
         * isn't already).
         */
        unsigned int cache_idx = ent - ptsh->cache;

        if ( cache_idx )
        {
            pt_cache_entry_t tmp = *ent;

            switch ( cache_idx )
            {
            case 3: ptsh->cache[3] = ptsh->cache[2];
            case 2: ptsh->cache[2] = ptsh->cache[1];
            case 1: ptsh->cache[1] = ptsh->cache[0];
                    ptsh->cache[0] = tmp;
            }
        }
        local_irq_restore(flags);
    }
    else
    {
        /*
         * Cache miss.  Recycle whatever was in the last slot, promote it to
         * being most recently used, and copy the entire pagetable.
         */
        unsigned int slot = l4_table_offset(PERCPU_LINEAR_START);
        unsigned int idx = ptsh->cache[3].idx;
        l4_pgentry_t *l4t, *vcpu_l4t;

        ptsh->cache[3] = ptsh->cache[2];
        ptsh->cache[2] = ptsh->cache[1];
        ptsh->cache[1] = ptsh->cache[0];
        ptsh->cache[0] = (pt_cache_entry_t){ new_cr3 | idx };
        local_irq_restore(flags);

        l4t = shadow_l4_va(ptsh, idx);
        vcpu_l4t = map_domain_page(maddr_to_mfn(new_cr3));

        /*
         * Careful!  When context switching between two vcpus, both of which
         * require shadowing, l4t[] may be the live pagetables.
         *
         * We mustn't clobber the PERCPU slot (with a zero, as vcpu_l4t[] will
         * never have had a percpu mapping inserted into it).  The context
         * switch logic will unconditionally insert the correct value anyway.
         */
        memcpy(l4t, vcpu_l4t,
               sizeof(*l4t) * slot);
        memcpy(&l4t[slot + 1], &vcpu_l4t[slot + 1],
               sizeof(*l4t) * (L4_PAGETABLE_ENTRIES - (slot + 1)));

        unmap_domain_page(vcpu_l4t);
    }

    ASSERT(ptsh->cache[0].cr3_mfn == (new_cr3 >> PAGE_SHIFT));

    return shadow_l4(ptsh, ptsh->cache[0].idx);
}

struct ptsh_ipi_info
{
    const struct domain *d;
    const struct page_info *pg;
    enum {
        PTSH_IPI_WRITE,
        PTSH_IPI_INVLPG,
    } op;
    unsigned int slot;
};

static void _pt_shadow_ipi(void *arg)
{
    unsigned int cpu = smp_processor_id();
    struct pt_shadow *ptsh = &per_cpu(ptsh, cpu);
    const struct ptsh_ipi_info *info = arg;
    pt_cache_entry_t *ent;

    /* No longer shadowing state from this domain?  Nothing to do. */
    if ( info->d != ptsh->domain )
        return;

    ent = pt_cache_lookup(ptsh, page_to_maddr(info->pg));

    /* Not shadowing this frame?  Nothing to do. */
    if ( ent == NULL )
        return;

    switch ( info->op )
    {
        l4_pgentry_t *l4t, *vcpu_l4t;
        unsigned int cache_idx, shadow_idx;

    case PTSH_IPI_WRITE:
        l4t = shadow_l4_va(ptsh, ent->idx);
        vcpu_l4t = map_domain_page(page_to_mfn(info->pg));

        l4t[info->slot] = vcpu_l4t[info->slot];

        unmap_domain_page(vcpu_l4t);
        break;

    case PTSH_IPI_INVLPG:
        cache_idx = ent - ptsh->cache;
        shadow_idx = ent->idx;

        /*
         * Demote the dropped entry to least-recently-used, so it is the next
         * entry to be reused.
         */
        switch ( cache_idx )
        {
        case 0: BUG(); /* ??? Freeing the L4 which current is running on! */
        case 1: ptsh->cache[1] = ptsh->cache[2];
        case 2: ptsh->cache[2] = ptsh->cache[3];
        case 3: ptsh->cache[3] = (pt_cache_entry_t){ shadow_idx };
        }
        break;

    default:
        ASSERT_UNREACHABLE();
    }
}

void pt_shadow_l4_write(const struct domain *d, const struct page_info *pg,
                        unsigned int slot)
{
    struct ptsh_ipi_info info;

    if ( !pt_need_shadow(d) )
        return;

    info = (struct ptsh_ipi_info){
        .d = d,
        .pg = pg,
        .op = PTSH_IPI_WRITE,
        .slot = slot,
    };

    on_selected_cpus(d->domain_dirty_cpumask, _pt_shadow_ipi, &info, 1);
}

void pt_shadow_l4_invlpg(const struct domain *d, const struct page_info *pg)
{
    struct ptsh_ipi_info info;

    if ( !pt_need_shadow(d) )
        return;

    info = (struct ptsh_ipi_info){
        .d = d,
        .pg = pg,
        .op = PTSH_IPI_INVLPG,
    };

    on_selected_cpus(d->domain_dirty_cpumask, _pt_shadow_ipi, &info, 1);
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
