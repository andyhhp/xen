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

struct pt_shadow {
    /*
     * A frame used to shadow a vcpus intended pagetable.  When shadowing,
     * this frame is the one actually referenced by %cr3.
     */
    paddr_t shadow_l4;
    l4_pgentry_t *shadow_l4_va;
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
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
