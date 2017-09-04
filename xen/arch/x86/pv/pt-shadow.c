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

#include <asm/fixmap.h>
#include <asm/pv/pt-shadow.h>

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
 *   - When a pcpu is switching to a new vcpu cr3 and shadowing is necessary,
 *     perform a full 4K copy of the guests frame into a percpu frame, and run
 *     on that.
 *   - When a write to a guests L4 pagetable occurs, the update must be
 *     propagated to all existing shadows.  An IPI is sent to the domains
 *     dirty mask indicating which frame/slot was updated, and each pcpu
 *     checks to see whether it needs to sync the update into its shadow.
 */

struct pt_shadow {
    /*
     * A frame used to shadow a vcpus intended pagetable.  When shadowing,
     * this frame is the one actually referenced by %cr3.
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

    /* If nonzero, a guests pagetable which we are shadowing. */
    paddr_t shadowing;
};

static DEFINE_PER_CPU(struct pt_shadow, ptsh);

int pt_shadow_alloc(unsigned int cpu)
{
    struct pt_shadow *ptsh = &per_cpu(ptsh, cpu);
    unsigned int memflags = 0;
    nodeid_t node = cpu_to_node(cpu);
    struct page_info *pg;

    if ( node != NUMA_NO_NODE )
        memflags = MEMF_node(node);

    pg = alloc_domheap_page(NULL, memflags);
    if ( !pg )
        return -ENOMEM;

    ptsh->shadow_l4 = page_to_maddr(pg);

    ptsh->shadow_l4_va = __map_domain_page_global(pg);
    if ( !ptsh->shadow_l4_va )
        return -ENOMEM;

    return 0;
}

void pt_shadow_free(unsigned int cpu)
{
    struct pt_shadow *ptsh = &per_cpu(ptsh, cpu);

    if ( ptsh->shadow_l4_va )
    {
        unmap_domain_page_global(ptsh->shadow_l4_va);
        ptsh->shadow_l4_va = NULL;
    }

    if ( ptsh->shadow_l4 )
    {
        free_domheap_page(maddr_to_page(ptsh->shadow_l4));
        ptsh->shadow_l4 = 0;
    }
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

    /*
     * IPIs for updates are based on the domain dirty mask.  If we ever switch
     * out of the currently shadowed context (even to idle), the cache will
     * become stale.
     */
    if ( ptsh->domain &&
         ptsh->domain != v->domain )
    {
        ptsh->domain = NULL;
        ptsh->shadowing = 0;
    }

    /* No shadowing necessary? Run on the intended pagetable. */
    if ( !pt_need_shadow(v->domain) )
        return new_cr3;

    ptsh->domain = v->domain;

    /* Fastpath, if we are already shadowing the intended pagetable. */
    if ( ptsh->shadowing == new_cr3 )
        return ptsh->shadow_l4;

    /*
     * We may be called with interrupts disabled (e.g. context switch), or
     * interrupts enabled (e.g. new_guest_cr3()).
     *
     * Reads and modifications of ptsh-> are only on the local cpu, but must
     * be excluded against reads and modifications in _pt_shadow_ipi().
     */
    local_irq_save(flags);

    {
        l4_pgentry_t *l4t, *vcpu_l4t;

        set_percpu_fixmap(cpu, PERCPU_FIXSLOT_SHADOW,
                          l1e_from_paddr(new_cr3, __PAGE_HYPERVISOR_RO));
        ptsh->shadowing = new_cr3;
        local_irq_restore(flags);

        l4t = ptsh->shadow_l4_va;
        vcpu_l4t = percpu_fix_to_virt(cpu, PERCPU_FIXSLOT_SHADOW);

        copy_page(l4t, vcpu_l4t);
    }

    return ptsh->shadow_l4;
}

struct ptsh_ipi_info
{
    const struct domain *d;
    const struct page_info *pg;
    enum {
        PTSH_IPI_WRITE,
    } op;
    unsigned int slot;
};

static void _pt_shadow_ipi(void *arg)
{
    unsigned int cpu = smp_processor_id();
    struct pt_shadow *ptsh = &per_cpu(ptsh, cpu);
    const struct ptsh_ipi_info *info = arg;
    unsigned long maddr = page_to_maddr(info->pg);

    /* No longer shadowing state from this domain?  Nothing to do. */
    if ( info->d != ptsh->domain )
        return;

    /* Not shadowing this frame?  Nothing to do. */
    if ( ptsh->shadowing != maddr )
        return;

    switch ( info->op )
    {
        l4_pgentry_t *l4t, *vcpu_l4t;

    case PTSH_IPI_WRITE:
        l4t = ptsh->shadow_l4_va;

        /* Reuse the mapping established in pt_maybe_shadow(). */
        ASSERT(l1e_get_paddr(*percpu_fixmap_l1e(cpu, PERCPU_FIXSLOT_SHADOW)) ==
               maddr);
        vcpu_l4t = percpu_fix_to_virt(cpu, PERCPU_FIXSLOT_SHADOW);

        l4t[info->slot] = vcpu_l4t[info->slot];
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

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
