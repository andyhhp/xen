/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef XEN_TLB_CLOCK_H
#define XEN_TLB_CLOCK_H

#include <xen/types.h>

#ifdef CONFIG_HAS_TLB_CLOCK

#include <xen/mm.h>

#include <asm/flushtlb.h>

static inline void accumulate_tlbflush(
    bool *need_tlbflush, const struct page_info *page,
    uint32_t *tlbflush_timestamp)
{
    if ( page->u.free.need_tlbflush &&
         page->tlbflush_timestamp <= tlbflush_current_time() &&
         (!*need_tlbflush ||
          page->tlbflush_timestamp > *tlbflush_timestamp) )
    {
        *need_tlbflush = true;
        *tlbflush_timestamp = page->tlbflush_timestamp;
    }
}

static inline void filtered_flush_tlb_mask(uint32_t tlbflush_timestamp)
{
    cpumask_t mask;

    cpumask_copy(&mask, &cpu_online_map);
    tlbflush_filter(&mask, tlbflush_timestamp);
    if ( !cpumask_empty(&mask) )
    {
        perfc_incr(need_flush_tlb_flush);
        arch_flush_tlb_mask(&mask);
    }
}

#else /* !CONFIG_HAS_TLB_CLOCK */

struct page_info;
static inline void accumulate_tlbflush(
    bool *need_tlbflush, const struct page_info *page,
    uint32_t *tlbflush_timestamp) {}
static inline void filtered_flush_tlb_mask(uint32_t tlbflush_timestamp) {}
static inline void page_set_tlbflush_timestamp(struct page_info *page) {}

#endif /* !CONFIG_HAS_TLB_CLOCK*/
#endif /* XEN_TLB_CLOCK_H */
