/*
 * include/asm-x86/pv/pt-shadow.h
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
#ifndef __X86_PV_PT_SHADOW_H__
#define __X86_PV_PT_SHADOW_H__

#include <xen/sched.h>

#ifdef CONFIG_PV

/*
 * Allocate an free per-pcpu resources for pagetable shadowing.  If alloc()
 * returns nonzero, it is the callers responsibility to call free().
 */
int pt_shadow_alloc(unsigned int cpu);
void pt_shadow_free(unsigned int cpu);

/*
 * Called for context switches, and when a vcpu explicitly changes cr3.  The
 * PT shadow logic returns the cr3 hardware should run on, which is either
 * v->arch.cr3 (no shadowing necessary), or a local frame (which is a suitable
 * shadow of v->arch.cr3).
 */
unsigned long pt_maybe_shadow(struct vcpu *v);

/*
 * Called when a write occurs to an L4 pagetable.  The PT shadow logic brings
 * any shadows of this page up-to-date.
 */
void pt_shadow_l4_write(
    const struct domain *d, const struct page_info *pg, unsigned int slot);

/*
 * Called when an L4 pagetable is freed.  The PT shadow logic ensures that it
 * is purged from any caches.
 */
void pt_shadow_l4_invlpg(
    const struct domain *d, const struct page_info *pg);

#else /* !CONFIG_PV */

static inline int pt_shadow_alloc(unsigned int cpu) { return 0; }
static inline void pt_shadow_free(unsigned int cpu) { }

static inline unsigned long pt_maybe_shadow(struct vcpu *v)
{
    return v->arch.cr3;
}
static inline void pt_shadow_l4_write(
    const struct domain *d, const struct page_info *pg, unsigned int slot) { }
static inline void pt_shadow_l4_invlpg(
    const struct domain *d, const struct page_info *pg) { }

#endif /* CONFIG_PV */

#endif /* __X86_PV_PT_SHADOW_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
