/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/mm/shadow/multi.c
 *
 * Simple, mostly-synchronous shadow page tables.
 * Parts of this code are Copyright (c) 2006 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
 */

#include <xen/types.h>
#include <xen/mm.h>
#include <xen/trace.h>
#include <xen/sched.h>
#include <xen/perfc.h>
#include <xen/domain_page.h>
#include <xen/iocap.h>
#include <xsm/xsm.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/shadow.h>
#include <asm/flushtlb.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/cacheattr.h>
#include <asm/mtrr.h>
#include <asm/guest_pt.h>
#include <public/sched.h>
#include "private.h"
#include "types.h"

/* THINGS TO DO LATER:
 *
 * TEARDOWN HEURISTICS
 * Also: have a heuristic for when to destroy a previous paging-mode's
 * shadows.  When a guest is done with its start-of-day 32-bit tables
 * and reuses the memory we want to drop those shadows.  Start with
 * shadows in a page in two modes as a hint, but beware of clever tricks
 * like reusing a pagetable for both PAE and 64-bit during boot...
 *
 * PAE LINEAR MAPS
 * Rework shadow_get_l*e() to have the option of using map_domain_page()
 * instead of linear maps.  Add appropriate unmap_l*e calls in the users.
 * Then we can test the speed difference made by linear maps.  If the
 * map_domain_page() version is OK on PAE, we could maybe allow a lightweight
 * l3-and-l2h-only shadow mode for PAE PV guests that would allow them
 * to share l2h pages again.
 *
 * PSE disabled / PSE36
 * We don't support any modes other than PSE enabled, PSE36 disabled.
 * Neither of those would be hard to change, but we'd need to be able to
 * deal with shadows made in one mode and used in another.
 */

#define FETCH_TYPE_PREFETCH 1
#define FETCH_TYPE_DEMAND   2
#define FETCH_TYPE_WRITE    4
typedef enum {
    ft_prefetch     = FETCH_TYPE_PREFETCH,
    ft_demand_read  = FETCH_TYPE_DEMAND,
    ft_demand_write = FETCH_TYPE_DEMAND | FETCH_TYPE_WRITE,
} fetch_type_t;

extern const char *const fetch_type_names[];

#if SHADOW_DEBUG_PROPAGATE && CONFIG_PAGING_LEVELS == GUEST_PAGING_LEVELS
const char *const fetch_type_names[] = {
    [ft_prefetch]     = "prefetch",
    [ft_demand_read]  = "demand read",
    [ft_demand_write] = "demand write",
};
#endif

#if SHADOW_PAGING_LEVELS == 3
# define for_each_shadow_table(v, i) \
    for ( (i) = 0; \
          (i) < ARRAY_SIZE((v)->arch.paging.shadow.shadow_table); \
          ++(i) )
#else
# define for_each_shadow_table(v, i) for ( (i) = 0; (i) < 1; ++(i) )
#endif

/* Helper to perform a local TLB flush. */
static void sh_flush_local(const struct domain *d)
{
    flush_local(guest_flush_tlb_flags(d));
}

#if GUEST_PAGING_LEVELS >= 4 && defined(CONFIG_PV32)
#define ASSERT_VALID_L2(t) \
    ASSERT((t) == SH_type_l2_shadow || (t) == SH_type_l2h_shadow)
#else
#define ASSERT_VALID_L2(t) ASSERT((t) == SH_type_l2_shadow)
#endif

/**************************************************************************/
/* Hash table mapping from guest pagetables to shadows
 *
 * normal case: see private.h.
 * FL1's:       maps the *gfn* of the start of a superpage to the mfn of a
 *              shadow L1 which maps its "splinters".
 */

static inline mfn_t
get_fl1_shadow_status(struct domain *d, gfn_t gfn)
/* Look for FL1 shadows in the hash table */
{
    mfn_t smfn = shadow_hash_lookup(d, gfn_x(gfn), SH_type_fl1_shadow);
    ASSERT(mfn_eq(smfn, INVALID_MFN) || mfn_to_page(smfn)->u.sh.head);
    return smfn;
}

static inline void
set_fl1_shadow_status(struct domain *d, gfn_t gfn, mfn_t smfn)
/* Put an FL1 shadow into the hash table */
{
    SHADOW_PRINTK("gfn=%"SH_PRI_gfn", type=%08x, smfn=%"PRI_mfn"\n",
                   gfn_x(gfn), SH_type_fl1_shadow, mfn_x(smfn));

    ASSERT(mfn_to_page(smfn)->u.sh.head);
    shadow_hash_insert(d, gfn_x(gfn), SH_type_fl1_shadow, smfn);
}

static inline void
delete_fl1_shadow_status(struct domain *d, gfn_t gfn, mfn_t smfn)
/* Remove a shadow from the hash table */
{
    SHADOW_PRINTK("gfn=%"SH_PRI_gfn", type=%08x, smfn=%"PRI_mfn"\n",
                   gfn_x(gfn), SH_type_fl1_shadow, mfn_x(smfn));
    ASSERT(mfn_to_page(smfn)->u.sh.head);
    if ( !shadow_hash_delete(d, gfn_x(gfn), SH_type_fl1_shadow, smfn) )
    {
        printk(XENLOG_G_ERR
               "%pd: %"PRI_gfn":FL1 hash entry not found for %"PRI_mfn"\n",
               d, gfn_x(gfn), mfn_x(smfn));
        domain_crash(d);
    }
}


/**************************************************************************/
/* Functions for walking the guest page tables */

static inline bool
sh_walk_guest_tables(struct vcpu *v, unsigned long va, walk_t *gw,
                     uint32_t pfec)
{
    gfn_t root_gfn = _gfn(paging_mode_external(v->domain)
                          ? cr3_pa(v->arch.hvm.guest_cr[3]) >> PAGE_SHIFT
                          : pagetable_get_pfn(v->arch.guest_table));

#if GUEST_PAGING_LEVELS != 3 /* 32 or 64 */
    const struct domain *d = v->domain;
    mfn_t root_mfn = (v->arch.flags & TF_kernel_mode
                      ? pagetable_get_mfn(v->arch.guest_table)
                      : pagetable_get_mfn(v->arch.guest_table_user));
    void *root_map = map_domain_page(root_mfn);
    bool ok = guest_walk_tables(v, p2m_get_hostp2m(d), va, gw, pfec,
                                root_gfn, root_mfn, root_map);

    unmap_domain_page(root_map);

    return ok;
#elif !defined(CONFIG_HVM)
    ASSERT_UNREACHABLE();
    (void)root_gfn;
    memset(gw, 0, sizeof(*gw));
    return false;
#else /* PAE */
    return guest_walk_tables(v, p2m_get_hostp2m(v->domain), va, gw, pfec,
                             root_gfn, INVALID_MFN, v->arch.paging.shadow.gl3e);
#endif
}

/* This validation is called with lock held, and after write permission
 * removal. Then check is atomic and no more inconsistent content can
 * be observed before lock is released
 *
 * Return 1 to indicate success and 0 for inconsistency
 */
static inline uint32_t
shadow_check_gwalk(struct vcpu *v, unsigned long va, walk_t *gw, int version)
{
    struct domain *d = v->domain;
    guest_l1e_t *l1p;
    guest_l2e_t *l2p;
#if GUEST_PAGING_LEVELS >= 4
    guest_l3e_t *l3p;
    guest_l4e_t *l4p;
#endif
    int mismatch = 0;

    ASSERT(paging_locked_by_me(d));

    /* No need for smp_rmb() here; taking the paging lock was enough. */
    if ( version == atomic_read(&d->arch.paging.shadow.gtable_dirty_version) )
         return 1;

    /* We may consider caching guest page mapping from last
     * guest table walk. However considering this check happens
     * relatively less-frequent, and a bit burden here to
     * remap guest page is better than caching mapping in each
     * guest table walk.
     *
     * Also when inconsistency occurs, simply return to trigger
     * another fault instead of re-validate new path to make
     * logic simple.
     */
    perfc_incr(shadow_check_gwalk);
#if GUEST_PAGING_LEVELS >= 3 /* PAE or 64... */
#if GUEST_PAGING_LEVELS >= 4 /* 64-bit only... */
    l4p = map_domain_page(gw->l4mfn);
    mismatch |= (gw->l4e.l4 != l4p[guest_l4_table_offset(va)].l4);
    unmap_domain_page(l4p);
    l3p = map_domain_page(gw->l3mfn);
    mismatch |= (gw->l3e.l3 != l3p[guest_l3_table_offset(va)].l3);
    unmap_domain_page(l3p);
#elif defined(CONFIG_HVM)
    mismatch |= (gw->l3e.l3 !=
                 v->arch.paging.shadow.gl3e[guest_l3_table_offset(va)].l3);
#endif
#endif
    l2p = map_domain_page(gw->l2mfn);
    mismatch |= (gw->l2e.l2 != l2p[guest_l2_table_offset(va)].l2);
    unmap_domain_page(l2p);

    if ( !(guest_can_use_l2_superpages(v) &&
           (guest_l2e_get_flags(gw->l2e) & _PAGE_PSE)) )
    {
        l1p = map_domain_page(gw->l1mfn);
        mismatch |= (gw->l1e.l1 != l1p[guest_l1_table_offset(va)].l1);
        unmap_domain_page(l1p);
    }

    return !mismatch;
}

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
static int
shadow_check_gl1e(struct vcpu *v, walk_t *gw)
{
    guest_l1e_t *l1p, nl1e;

    if ( !mfn_valid(gw->l1mfn) )
        return 0;

    /* Can't just pull-through because mfn may have changed */
    l1p = map_domain_page(gw->l1mfn);
    nl1e.l1 = l1p[guest_l1_table_offset(gw->va)].l1;
    unmap_domain_page(l1p);

    return gw->l1e.l1 != nl1e.l1;
}
#endif

/* Remove write access permissions from a gwalk_t in a batch, and
 * return OR-ed result for TLB flush hint and need to rewalk the guest
 * pages.
 *
 * Syncing pages will remove write access to that page; but it may
 * also give write access to other pages in the path. If we resync any
 * pages, re-walk from the beginning.
 */
#define GW_RMWR_FLUSHTLB 1
#define GW_RMWR_REWALK   2

static inline uint32_t
gw_remove_write_accesses(struct vcpu *v, unsigned long va, walk_t *gw)
{
    struct domain *d = v->domain;
    uint32_t rc = 0;

#if GUEST_PAGING_LEVELS >= 3 /* PAE or 64... */
#if GUEST_PAGING_LEVELS >= 4 /* 64-bit only... */
#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    if ( mfn_is_out_of_sync(gw->l3mfn) )
    {
        sh_resync(d, gw->l3mfn);
        rc = GW_RMWR_REWALK;
    }
    else
#endif /* OOS */
     if ( sh_remove_write_access(d, gw->l3mfn, 3, va) )
         rc = GW_RMWR_FLUSHTLB;
#endif /* GUEST_PAGING_LEVELS >= 4 */

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    if ( mfn_is_out_of_sync(gw->l2mfn) )
    {
        sh_resync(d, gw->l2mfn);
        rc |= GW_RMWR_REWALK;
    }
    else
#endif /* OOS */
    if ( sh_remove_write_access(d, gw->l2mfn, 2, va) )
        rc |= GW_RMWR_FLUSHTLB;
#endif /* GUEST_PAGING_LEVELS >= 3 */

    if ( !(guest_can_use_l2_superpages(v) &&
           (guest_l2e_get_flags(gw->l2e) & _PAGE_PSE))
#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
         && !mfn_is_out_of_sync(gw->l1mfn)
#endif /* OOS */
         && sh_remove_write_access(d, gw->l1mfn, 1, va) )
        rc |= GW_RMWR_FLUSHTLB;

    return rc;
}

/* Lightweight audit: pass all the shadows associated with this guest walk
 * through the audit mechanisms */
static void sh_audit_gw(struct vcpu *v, const walk_t *gw)
{
#if SHADOW_AUDIT & SHADOW_AUDIT_ENTRIES
    struct domain *d = v->domain;
    mfn_t smfn;

    if ( !(SHADOW_AUDIT_ENABLE) )
        return;

#if GUEST_PAGING_LEVELS >= 4 /* 64-bit only... */
    if ( mfn_valid(gw->l4mfn)
         && mfn_valid((smfn = get_shadow_status(d, gw->l4mfn,
                                                SH_type_l4_shadow))) )
        sh_audit_l4_table(d, smfn, INVALID_MFN);
    if ( mfn_valid(gw->l3mfn)
         && mfn_valid((smfn = get_shadow_status(d, gw->l3mfn,
                                                SH_type_l3_shadow))) )
        sh_audit_l3_table(d, smfn, INVALID_MFN);
#endif /* PAE or 64... */
    if ( mfn_valid(gw->l2mfn) )
    {
        if ( mfn_valid((smfn = get_shadow_status(d, gw->l2mfn,
                                                 SH_type_l2_shadow))) )
            sh_audit_l2_table(d, smfn, INVALID_MFN);
#if GUEST_PAGING_LEVELS >= 4 && defined(CONFIG_PV32)
        if ( mfn_valid((smfn = get_shadow_status(d, gw->l2mfn,
                                                 SH_type_l2h_shadow))) )
            sh_audit_l2_table(d, smfn, INVALID_MFN);
#endif
    }
    if ( mfn_valid(gw->l1mfn)
         && mfn_valid((smfn = get_shadow_status(d, gw->l1mfn,
                                                SH_type_l1_shadow))) )
        sh_audit_l1_table(d, smfn, INVALID_MFN);
    else if ( (guest_l2e_get_flags(gw->l2e) & _PAGE_PRESENT)
              && (guest_l2e_get_flags(gw->l2e) & _PAGE_PSE)
              && mfn_valid(
              (smfn = get_fl1_shadow_status(d, guest_l2e_get_gfn(gw->l2e)))) )
        sh_audit_fl1_table(d, smfn, INVALID_MFN);
#endif /* SHADOW_AUDIT & SHADOW_AUDIT_ENTRIES */
}

/**************************************************************************/
/* Functions to compute the correct index into a shadow page, given an
 * index into the guest page (as returned by guest_get_index()).
 * This is trivial when the shadow and guest use the same sized PTEs, but
 * gets more interesting when those sizes are mismatched (e.g. 32-bit guest,
 * PAE- or 64-bit shadows).
 *
 * These functions also increment the shadow mfn, when necessary.  When PTE
 * sizes are mismatched, it takes 2 shadow L1 pages for a single guest L1
 * page.  In this case, we allocate 2 contiguous pages for the shadow L1, and
 * use simple pointer arithmetic on a pointer to the guest L1e to figure out
 * which shadow page we really want.  Similarly, when PTE sizes are
 * mismatched, we shadow a guest L2 page with 4 shadow L2 pages.  (The easiest
 * way to see this is: a 32-bit guest L2 page maps 4GB of virtual address
 * space, while a PAE- or 64-bit shadow L2 page maps 1GB of virtual address
 * space.)
 */

#if GUEST_PAGING_LEVELS == 2
/* From one page of a multi-page shadow, find the next one */
static inline mfn_t cf_check sh_next_page(mfn_t smfn)
{
    struct page_info *pg = mfn_to_page(smfn), *next;
    struct page_list_head h = PAGE_LIST_HEAD_INIT(h);

    ASSERT(pg->u.sh.type == SH_type_l1_32_shadow
           || pg->u.sh.type == SH_type_fl1_32_shadow
           || pg->u.sh.type == SH_type_l2_32_shadow);
    ASSERT(pg->u.sh.type == SH_type_l2_32_shadow || pg->u.sh.head);

    next = page_list_next(pg, &h);

    ASSERT(next);
    ASSERT(next->u.sh.type == pg->u.sh.type);
    ASSERT(!next->u.sh.head);
    return page_to_mfn(next);
}
#else
# define sh_next_page NULL
#endif

#define shadow_set_l2e(d, sl2e, new_sl2e, sl2mfn) \
    shadow_set_l2e(d, sl2e, new_sl2e, sl2mfn, SH_type_fl1_shadow, sh_next_page)

static inline u32
guest_index(void *ptr)
{
    return (u32)((unsigned long)ptr & ~PAGE_MASK) / sizeof(guest_l1e_t);
}

static u32 cf_check shadow_l1_index(mfn_t *smfn, u32 guest_index)
{
#if (GUEST_PAGING_LEVELS == 2)
    ASSERT(mfn_to_page(*smfn)->u.sh.head);
    if ( guest_index >= SHADOW_L1_PAGETABLE_ENTRIES )
        *smfn = sh_next_page(*smfn);
    return (guest_index % SHADOW_L1_PAGETABLE_ENTRIES);
#else
    return guest_index;
#endif
}

static u32 cf_check shadow_l2_index(mfn_t *smfn, u32 guest_index)
{
#if (GUEST_PAGING_LEVELS == 2)
    int i;
    ASSERT(mfn_to_page(*smfn)->u.sh.head);
    // Because we use 2 shadow l2 entries for each guest entry, the number of
    // guest entries per shadow page is SHADOW_L2_PAGETABLE_ENTRIES/2
    for ( i = 0; i < guest_index / (SHADOW_L2_PAGETABLE_ENTRIES / 2); i++ )
        *smfn = sh_next_page(*smfn);
    // We multiply by two to get the index of the first of the two entries
    // used to shadow the specified guest entry.
    return (guest_index % (SHADOW_L2_PAGETABLE_ENTRIES / 2)) * 2;
#else
    return guest_index;
#endif
}

#if GUEST_PAGING_LEVELS >= 4

static u32 cf_check shadow_l3_index(mfn_t *smfn, u32 guest_index)
{
    return guest_index;
}

static u32 cf_check shadow_l4_index(mfn_t *smfn, u32 guest_index)
{
    return guest_index;
}

#endif // GUEST_PAGING_LEVELS >= 4


/**************************************************************************/
/* Function which computes shadow entries from their corresponding guest
 * entries.  This is the "heart" of the shadow code. It operates using
 * level-1 shadow types, but handles all levels of entry.
 * Don't call it directly, but use the four wrappers below.
 */

static always_inline void
_sh_propagate(struct vcpu *v,
              guest_intpte_t guest_intpte,
              mfn_t target_mfn,
              void *shadow_entry_ptr,
              int level,
              fetch_type_t ft,
              p2m_type_t p2mt)
{
    guest_l1e_t guest_entry = { guest_intpte };
    shadow_l1e_t *sp = shadow_entry_ptr;
    struct domain *d = v->domain;
    gfn_t target_gfn = guest_l1e_get_gfn(guest_entry);
    u32 pass_thru_flags;
    u32 gflags, sflags;
    bool mmio_mfn;

    /* We don't shadow PAE l3s */
    ASSERT(GUEST_PAGING_LEVELS > 3 || level != 3);

    if ( !gfn_valid(d, target_gfn) )
    {
        *sp = shadow_l1e_empty();
        goto done;
    }

    gflags = guest_l1e_get_flags(guest_entry);

    if ( unlikely(!(gflags & _PAGE_PRESENT)) )
    {
#if !(SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
        /* If a guest l1 entry is not present, shadow with the magic
         * guest-not-present entry. */
        if ( level == 1 )
            *sp = sh_l1e_gnp();
        else
#endif /* !OOS */
            *sp = shadow_l1e_empty();
        goto done;
    }

    if ( level == 1 && p2mt == p2m_mmio_dm )
    {
        /* Guest l1e maps emulated MMIO space */
        *sp = sh_l1e_mmio(target_gfn, gflags);
        if ( sh_l1e_is_magic(*sp) )
            d->arch.paging.shadow.has_fast_mmio_entries = true;
        goto done;
    }

    /* Check there's something for the shadows to map to */
    if ( !p2m_is_any_ram(p2mt) && p2mt != p2m_mmio_direct )
    {
        *sp = shadow_l1e_empty();
        goto done;
    }

    // Must have a valid target_mfn unless this is a prefetch or an l1
    // pointing at MMIO space.  In the case of a prefetch, an invalid
    // mfn means that we can not usefully shadow anything, and so we
    // return early.
    //
    mmio_mfn = !mfn_valid(target_mfn)
               || (level == 1
                   && page_get_owner(mfn_to_page(target_mfn)) == dom_io);
    if ( mmio_mfn
         && !(level == 1 && (!shadow_mode_refcounts(d)
                             || p2mt == p2m_mmio_direct)) )
    {
        ASSERT((ft == ft_prefetch));
        *sp = shadow_l1e_empty();
        goto done;
    }

    // Propagate bits from the guest to the shadow.
    // Some of these may be overwritten, below.
    // Since we know the guest's PRESENT bit is set, we also set the shadow's
    // SHADOW_PRESENT bit.
    //
    pass_thru_flags = (_PAGE_ACCESSED | _PAGE_USER |
                       _PAGE_RW | _PAGE_PRESENT);
    if ( guest_nx_enabled(v) )
        pass_thru_flags |= _PAGE_NX_BIT;
    if ( level == 1 && !shadow_mode_refcounts(d) && mmio_mfn )
        pass_thru_flags |= PAGE_CACHE_ATTRS;
    sflags = gflags & pass_thru_flags;

    /*
     * For HVM domains with direct access to MMIO areas, set the correct
     * caching attributes in the shadows to match what was asked for.
     */
    if ( (level == 1) && is_hvm_domain(d) &&
         (mmio_mfn || !is_special_page(mfn_to_page(target_mfn))) )
    {
        int type;

        ASSERT(!(sflags & PAGE_CACHE_ATTRS));

        /*
         * Compute the PAT index for shadow page entry when IOMMU is enabled.
         * 1) direct MMIO: compute the PAT index with gMTRR=UC and gPAT.
         * 2) if enables snoop control, compute the PAT index as WB.
         * 3) if disables snoop control, compute the PAT index with
         *    gMTRR and gPAT.
         */
        if ( !mmio_mfn &&
             (type = hvm_get_mem_pinned_cacheattr(d, target_gfn, 0)) >= 0 )
            sflags |= pat_type_2_pte_flags(type);
        else if ( d->arch.hvm.is_in_uc_mode )
            sflags |= pat_type_2_pte_flags(X86_MT_UC);
        else
            if ( iomem_access_permitted(d, mfn_x(target_mfn), mfn_x(target_mfn)) )
            {
                if ( p2mt == p2m_mmio_direct )
                    sflags |= get_pat_flags(v,
                            gflags,
                            gfn_to_gaddr(target_gfn),
                            mfn_to_maddr(target_mfn),
                            X86_MT_UC);
                else if ( is_iommu_enabled(d) && iommu_snoop )
                    sflags |= pat_type_2_pte_flags(X86_MT_WB);
                else
                    sflags |= get_pat_flags(v,
                            gflags,
                            gfn_to_gaddr(target_gfn),
                            mfn_to_maddr(target_mfn),
                            NO_HARDCODE_MEM_TYPE);
            }
    }

    // Set the A&D bits for higher level shadows.
    // Higher level entries do not, strictly speaking, have dirty bits, but
    // since we use shadow linear tables, each of these entries may, at some
    // point in time, also serve as a shadow L1 entry.
    // By setting both the A&D bits in each of these, we eliminate the burden
    // on the hardware to update these bits on initial accesses.
    //
    if ( (level > 1) && !((SHADOW_PAGING_LEVELS == 3) && (level == 3)) )
        sflags |= _PAGE_ACCESSED | _PAGE_DIRTY;

    // If the A or D bit has not yet been set in the guest, then we must
    // prevent the corresponding kind of access.
    //
    if ( unlikely(!(gflags & _PAGE_ACCESSED)) )
        sflags &= ~_PAGE_PRESENT;

    /* D bits exist in L1es and PSE L2es */
    if ( unlikely(((level == 1) ||
                   ((level == 2) &&
                    (gflags & _PAGE_PSE) &&
                    guest_can_use_l2_superpages(v)))
                  && !(gflags & _PAGE_DIRTY)) )
        sflags &= ~_PAGE_RW;

#ifdef CONFIG_HVM
    if ( unlikely(level == 1) && is_hvm_domain(d) )
    {
        struct sh_dirty_vram *dirty_vram = d->arch.hvm.dirty_vram;

        if ( dirty_vram && dirty_vram->last_dirty == -1 &&
             gfn_x(target_gfn) >= dirty_vram->begin_pfn &&
             gfn_x(target_gfn) < dirty_vram->end_pfn )
        {
            if ( ft & FETCH_TYPE_WRITE )
                dirty_vram->last_dirty = NOW();
            else
                sflags &= ~_PAGE_RW;
        }
    }
#endif

    /* Read-only memory */
    if ( p2m_is_readonly(p2mt) )
        sflags &= ~_PAGE_RW;
    else if ( p2mt == p2m_mmio_direct &&
              rangeset_contains_singleton(mmio_ro_ranges, mfn_x(target_mfn)) )
    {
        sflags &= ~(_PAGE_RW | PAGE_CACHE_ATTRS);
        sflags |= _PAGE_UC;
    }

    // protect guest page tables
    //
    if ( unlikely((level == 1)
                  && sh_mfn_is_a_page_table(target_mfn)
#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC )
                  /* Unless the page is out of sync and the guest is
                     writing to it. */
                  && !(mfn_oos_may_write(target_mfn)
                       && (ft == ft_demand_write))
#endif /* OOS */
                  ) )
        sflags &= ~_PAGE_RW;

    /*
     * shadow_mode_log_dirty support
     *
     * Only allow the guest write access to a page a) on a demand fault,
     * or b) if the page is already marked as dirty.
     *
     * (We handle log-dirty entirely inside the shadow code, without using the
     * p2m_ram_logdirty p2m type: only HAP uses that.)
     */
    if ( level == 1 && unlikely(shadow_mode_log_dirty(d)) && !mmio_mfn )
    {
        if ( ft & FETCH_TYPE_WRITE )
            paging_mark_dirty(d, target_mfn);
        else if ( (sflags & _PAGE_RW) &&
                  !paging_mfn_is_dirty(d, target_mfn) )
            sflags &= ~_PAGE_RW;
    }

    // PV guests in 64-bit mode use two different page tables for user vs
    // supervisor permissions, making the guest's _PAGE_USER bit irrelevant.
    // It is always shadowed as present...
    if ( (GUEST_PAGING_LEVELS == 4) && !is_hvm_domain(d) &&
         !is_pv_32bit_domain(d) )
    {
        sflags |= _PAGE_USER;
    }

    *sp = shadow_l1e_from_mfn(target_mfn, sflags);

 done:
    SHADOW_DEBUG(PROPAGATE,
                 "%s level %u guest %" SH_PRI_gpte " shadow %" SH_PRI_pte "\n",
                 fetch_type_names[ft], level, guest_entry.l1, sp->l1);
}


/* These four wrappers give us a little bit of type-safety back around
 * the use of void-* pointers and intpte types in _sh_propagate(), and
 * allow the compiler to optimize out some level checks. */

#if GUEST_PAGING_LEVELS >= 4
static void
l4e_propagate_from_guest(struct vcpu *v,
                         guest_l4e_t gl4e,
                         mfn_t sl3mfn,
                         shadow_l4e_t *sl4e,
                         fetch_type_t ft)
{
    if ( !mfn_eq(sl3mfn, INVALID_MFN) &&
         (guest_l4e_get_flags(gl4e) & _PAGE_PRESENT) )
        ASSERT(!guest_l4e_rsvd_bits(v, gl4e));

    _sh_propagate(v, gl4e.l4, sl3mfn, sl4e, 4, ft, p2m_ram_rw);
}

static void
l3e_propagate_from_guest(struct vcpu *v,
                         guest_l3e_t gl3e,
                         mfn_t sl2mfn,
                         shadow_l3e_t *sl3e,
                         fetch_type_t ft)
{
    if ( !mfn_eq(sl2mfn, INVALID_MFN) &&
         (guest_l3e_get_flags(gl3e) & _PAGE_PRESENT) )
        ASSERT(!guest_l3e_rsvd_bits(v, gl3e));

    _sh_propagate(v, gl3e.l3, sl2mfn, sl3e, 3, ft, p2m_ram_rw);
}
#endif // GUEST_PAGING_LEVELS >= 4

static void
l2e_propagate_from_guest(struct vcpu *v,
                         guest_l2e_t gl2e,
                         mfn_t sl1mfn,
                         shadow_l2e_t *sl2e,
                         fetch_type_t ft)
{
    if ( !mfn_eq(sl1mfn, INVALID_MFN) &&
         (guest_l2e_get_flags(gl2e) & _PAGE_PRESENT) )
        ASSERT(!guest_l2e_rsvd_bits(v, gl2e));

    _sh_propagate(v, gl2e.l2, sl1mfn, sl2e, 2, ft, p2m_ram_rw);
}

static void
l1e_propagate_from_guest(struct vcpu *v,
                         guest_l1e_t gl1e,
                         mfn_t gmfn,
                         shadow_l1e_t *sl1e,
                         fetch_type_t ft,
                         p2m_type_t p2mt)
{
    if ( !mfn_eq(gmfn, INVALID_MFN) &&
         (guest_l1e_get_flags(gl1e) & _PAGE_PRESENT) )
        ASSERT(!guest_l1e_rsvd_bits(v, gl1e));

    _sh_propagate(v, gl1e.l1, gmfn, sl1e, 1, ft, p2mt);
}


/**************************************************************************/
/* Macros to walk pagetables.  These take the shadow of a pagetable and
 * walk every "interesting" entry.  That is, they don't touch Xen mappings,
 * and for 32-bit l2s shadowed onto PAE or 64-bit, they only touch every
 * second entry (since pairs of entries are managed together). For multi-page
 * shadows they walk all pages.
 *
 * Arguments are an MFN, the variable to point to each entry, a variable
 * to indicate that we are done (we will shortcut to the end of the scan
 * when _done != 0), a variable to indicate that we should avoid Xen mappings,
 * and the code.
 *
 * WARNING: These macros have side-effects.  They change the values of both
 * the pointer and the MFN. */

static inline void increment_ptr_to_guest_entry(void *ptr)
{
    if ( ptr )
    {
        guest_l1e_t **entry = ptr;
        (*entry)++;
    }
}

/* All kinds of l1: touch all entries */
#define _FOREACH_PRESENT_L1E(_sl1mfn, _sl1e, _gl1p, _done, _code)       \
do {                                                                    \
    int _i;                                                             \
    shadow_l1e_t *_sp = map_domain_page((_sl1mfn));                     \
    ASSERT(mfn_to_page(_sl1mfn)->u.sh.type == SH_type_l1_shadow  \
           || mfn_to_page(_sl1mfn)->u.sh.type == SH_type_fl1_shadow);\
    for ( _i = 0; _i < SHADOW_L1_PAGETABLE_ENTRIES; _i++ )              \
    {                                                                   \
        (_sl1e) = _sp + _i;                                             \
        if ( shadow_l1e_get_flags(*(_sl1e)) & _PAGE_PRESENT )           \
            {_code}                                                     \
        if ( _done ) break;                                             \
        increment_ptr_to_guest_entry(_gl1p);                            \
    }                                                                   \
    unmap_domain_page(_sp);                                             \
} while (0)

/* 32-bit l1, on PAE or 64-bit shadows: need to walk both pages of shadow */
#if GUEST_PAGING_LEVELS == 2 && SHADOW_PAGING_LEVELS > 2
#define FOREACH_PRESENT_L1E(_sl1mfn, _sl1e, _gl1p, _done,  _code)       \
do {                                                                    \
    int __done = 0;                                                     \
    _FOREACH_PRESENT_L1E(_sl1mfn, _sl1e, _gl1p,                         \
                         ({ (__done = _done); }), _code);               \
    _sl1mfn = sh_next_page(_sl1mfn);                                    \
    if ( !__done )                                                      \
        _FOREACH_PRESENT_L1E(_sl1mfn, _sl1e, _gl1p, _done, _code);      \
} while (0)
#else /* Everything else; l1 shadows are only one page */
#define FOREACH_PRESENT_L1E(_sl1mfn, _sl1e, _gl1p, _done, _code)        \
       _FOREACH_PRESENT_L1E(_sl1mfn, _sl1e, _gl1p, _done, _code)
#endif


#if GUEST_PAGING_LEVELS == 2

/* 32-bit l2 on PAE/64: four pages, touch every second entry */
#define FOREACH_PRESENT_L2E(_sl2mfn, _sl2e, _gl2p, _done, _dom, _code)    \
do {                                                                      \
    int _i, _j;                                                           \
    ASSERT(shadow_mode_external(_dom));                                   \
    ASSERT(mfn_to_page(_sl2mfn)->u.sh.type == SH_type_l2_32_shadow);      \
    for ( _j = 0; _j < 4; _j++ )                                          \
    {                                                                     \
        shadow_l2e_t *_sp = map_domain_page(_sl2mfn);                     \
        for ( _i = 0; _i < SHADOW_L2_PAGETABLE_ENTRIES; _i += 2 )         \
        {                                                                 \
            (_sl2e) = _sp + _i;                                           \
            if ( shadow_l2e_get_flags(*(_sl2e)) & _PAGE_PRESENT )         \
                {_code}                                                   \
            if ( _done ) break;                                           \
            increment_ptr_to_guest_entry(_gl2p);                          \
        }                                                                 \
        unmap_domain_page(_sp);                                           \
        if ( _j < 3 ) _sl2mfn = sh_next_page(_sl2mfn);                    \
        if ( _i < SHADOW_L2_PAGETABLE_ENTRIES ) break;                    \
    }                                                                     \
} while (0)

#elif GUEST_PAGING_LEVELS == 3

/* PAE: touch all entries */
#define FOREACH_PRESENT_L2E(_sl2mfn, _sl2e, _gl2p, _done, _dom, _code)     \
do {                                                                       \
    int _i;                                                                \
    shadow_l2e_t *_sp = map_domain_page((_sl2mfn));                        \
    ASSERT(shadow_mode_external(_dom));                                    \
    ASSERT(mfn_to_page(_sl2mfn)->u.sh.type == SH_type_l2_pae_shadow);      \
    for ( _i = 0; _i < SHADOW_L2_PAGETABLE_ENTRIES; _i++ )                 \
    {                                                                      \
        (_sl2e) = _sp + _i;                                                \
        if ( shadow_l2e_get_flags(*(_sl2e)) & _PAGE_PRESENT )              \
            {_code}                                                        \
        if ( _done ) break;                                                \
        increment_ptr_to_guest_entry(_gl2p);                               \
    }                                                                      \
    unmap_domain_page(_sp);                                                \
} while (0)

#else

/* 64-bit l2: touch all entries except for PAE compat guests. */
#define FOREACH_PRESENT_L2E(_sl2mfn, _sl2e, _gl2p, _done, _dom, _code)      \
do {                                                                        \
    unsigned int _i, _end = SHADOW_L2_PAGETABLE_ENTRIES;                    \
    shadow_l2e_t *_sp = map_domain_page((_sl2mfn));                         \
    ASSERT_VALID_L2(mfn_to_page(_sl2mfn)->u.sh.type);                       \
    if ( is_pv_32bit_domain(_dom) /* implies !shadow_mode_external */ &&    \
         mfn_to_page(_sl2mfn)->u.sh.type != SH_type_l2_64_shadow )          \
        _end = COMPAT_L2_PAGETABLE_FIRST_XEN_SLOT(_dom);                    \
    for ( _i = 0; _i < _end; ++_i )                                         \
    {                                                                       \
        (_sl2e) = _sp + _i;                                                 \
        if ( shadow_l2e_get_flags(*(_sl2e)) & _PAGE_PRESENT )               \
        {                                                                   \
            _code;                                                          \
        }                                                                   \
        if ( _done )                                                        \
            break;                                                          \
        increment_ptr_to_guest_entry(_gl2p);                                \
    }                                                                       \
    unmap_domain_page(_sp);                                                 \
} while (0)

#endif /* different kinds of l2 */

#if GUEST_PAGING_LEVELS == 4

/* 64-bit l3: touch all entries */
#define FOREACH_PRESENT_L3E(_sl3mfn, _sl3e, _gl3p, _done, _code)        \
do {                                                                    \
    int _i;                                                             \
    shadow_l3e_t *_sp = map_domain_page((_sl3mfn));                     \
    ASSERT(mfn_to_page(_sl3mfn)->u.sh.type == SH_type_l3_64_shadow);\
    for ( _i = 0; _i < SHADOW_L3_PAGETABLE_ENTRIES; _i++ )              \
    {                                                                   \
        (_sl3e) = _sp + _i;                                             \
        if ( shadow_l3e_get_flags(*(_sl3e)) & _PAGE_PRESENT )           \
            {_code}                                                     \
        if ( _done ) break;                                             \
        increment_ptr_to_guest_entry(_gl3p);                            \
    }                                                                   \
    unmap_domain_page(_sp);                                             \
} while (0)

/* 64-bit l4: avoid Xen mappings */
#define FOREACH_PRESENT_L4E(_sl4mfn, _sl4e, _gl4p, _done, _dom, _code)  \
do {                                                                    \
    shadow_l4e_t *_sp = map_domain_page((_sl4mfn));                     \
    int _xen = !shadow_mode_external(_dom);                             \
    int _i;                                                             \
    ASSERT(mfn_to_page(_sl4mfn)->u.sh.type == SH_type_l4_64_shadow);\
    for ( _i = 0; _i < SHADOW_L4_PAGETABLE_ENTRIES; _i++ )              \
    {                                                                   \
        if ( (!(_xen)) || is_guest_l4_slot(_dom, _i) )                  \
        {                                                               \
            (_sl4e) = _sp + _i;                                         \
            if ( shadow_l4e_get_flags(*(_sl4e)) & _PAGE_PRESENT )       \
                {_code}                                                 \
            if ( _done ) break;                                         \
        }                                                               \
        increment_ptr_to_guest_entry(_gl4p);                            \
    }                                                                   \
    unmap_domain_page(_sp);                                             \
} while (0)

#endif


/**************************************************************************/
/* Create a shadow of a given guest page.
 */
static mfn_t cf_check
sh_make_shadow(struct vcpu *v, mfn_t gmfn, u32 shadow_type)
{
    struct domain *d = v->domain;
    mfn_t smfn = shadow_alloc(d, shadow_type, mfn_x(gmfn));
    SHADOW_DEBUG(MAKE_SHADOW, "(%"PRI_mfn", %u)=>%"PRI_mfn"\n",
                  mfn_x(gmfn), shadow_type, mfn_x(smfn));

    if ( sh_type_has_up_pointer(d, shadow_type) )
        /* Lower-level shadow, not yet linked form a higher level */
        mfn_to_page(smfn)->up = 0;

#if GUEST_PAGING_LEVELS >= 4

#if (SHADOW_OPTIMIZATIONS & SHOPT_LINUX_L3_TOPLEVEL)
    if ( shadow_type == SH_type_l4_64_shadow &&
         unlikely(d->arch.paging.shadow.opt_flags & SHOPT_LINUX_L3_TOPLEVEL) )
    {
        /* We're shadowing a new l4, but we've been assuming the guest uses
         * only one l4 per vcpu and context switches using an l4 entry.
         * Count the number of active l4 shadows.  If there are enough
         * of them, decide that this isn't an old linux guest, and stop
         * pinning l3es.  This is not very quick but it doesn't happen
         * very often. */
        struct page_info *sp, *t;
        unsigned int l4count = 0;

        page_list_for_each(sp, &d->arch.paging.shadow.pinned_shadows)
        {
            if ( sp->u.sh.type == SH_type_l4_64_shadow )
                l4count++;
        }
        if ( l4count > 2 * d->max_vcpus )
        {
            /* Unpin all the pinned l3 tables, and don't pin any more. */
            page_list_for_each_safe(sp, t, &d->arch.paging.shadow.pinned_shadows)
            {
                if ( sp->u.sh.type == SH_type_l3_64_shadow )
                    sh_unpin(d, page_to_mfn(sp));
            }
            d->arch.paging.shadow.opt_flags &= ~SHOPT_LINUX_L3_TOPLEVEL;
        }
    }
#endif

    // Create the Xen mappings...
    if ( !shadow_mode_external(d) )
    {
        switch (shadow_type)
        {
        case SH_type_l4_shadow:
        {
            shadow_l4e_t *l4t = map_domain_page(smfn);

            BUILD_BUG_ON(sizeof(l4_pgentry_t) != sizeof(shadow_l4e_t));

            init_xen_l4_slots(l4t, gmfn, d, smfn, (!is_pv_32bit_domain(d) &&
                                                   VM_ASSIST(d, m2p_strict)));
            unmap_domain_page(l4t);
        }
        break;

#ifdef CONFIG_PV32
        case SH_type_l2h_shadow:
            BUILD_BUG_ON(sizeof(l2_pgentry_t) != sizeof(shadow_l2e_t));
            if ( is_pv_32bit_domain(d) )
            {
                shadow_l2e_t *l2t = map_domain_page(smfn);

                init_xen_pae_l2_slots(l2t, d);
                unmap_domain_page(l2t);
            }
            break;
#endif

        default: /* Do nothing */ break;
        }
    }

#endif /* GUEST_PAGING_LEVELS >= 4 */

    shadow_promote(d, gmfn, shadow_type);
    set_shadow_status(d, gmfn, shadow_type, smfn);

    return smfn;
}

/* Make a splintered superpage shadow */
static mfn_t
make_fl1_shadow(struct domain *d, gfn_t gfn)
{
    mfn_t smfn = shadow_alloc(d, SH_type_fl1_shadow, gfn_x(gfn));

    SHADOW_DEBUG(MAKE_SHADOW, "(%" SH_PRI_gfn ")=>%" PRI_mfn "\n",
                  gfn_x(gfn), mfn_x(smfn));

    set_fl1_shadow_status(d, gfn, smfn);
    return smfn;
}


/**************************************************************************/
/* These functions also take a virtual address and return the level-N
 * shadow table mfn and entry, but they create the shadow pagetables if
 * they are needed.  The "demand" argument is non-zero when handling
 * a demand fault (so we know what to do about accessed bits &c).
 * If the necessary tables are not present in the guest, they return NULL. */

/* N.B. The use of GUEST_PAGING_LEVELS here is correct.  If the shadow has
 * more levels than the guest, the upper levels are always fixed and do not
 * reflect any information from the guest, so we do not use these functions
 * to access them. */

#if GUEST_PAGING_LEVELS >= 4
static shadow_l4e_t * shadow_get_and_create_l4e(struct vcpu *v,
                                                walk_t *gw,
                                                mfn_t *sl4mfn)
{
    /* There is always a shadow of the top level table.  Get it. */
    *sl4mfn = pagetable_get_mfn(v->arch.paging.shadow.shadow_table[0]);
    /* Reading the top level table is always valid. */
    return sh_linear_l4_table(v) + shadow_l4_linear_offset(gw->va);
}

static shadow_l3e_t * shadow_get_and_create_l3e(struct vcpu *v,
                                                walk_t *gw,
                                                mfn_t *sl3mfn,
                                                fetch_type_t ft,
                                                int *resync)
{
    struct domain *d = v->domain;
    mfn_t sl4mfn;
    shadow_l4e_t *sl4e;
    if ( !mfn_valid(gw->l3mfn) ) return NULL; /* No guest page. */
    /* Get the l4e */
    sl4e = shadow_get_and_create_l4e(v, gw, &sl4mfn);
    ASSERT(sl4e != NULL);
    if ( shadow_l4e_get_flags(*sl4e) & _PAGE_PRESENT )
    {
        *sl3mfn = shadow_l4e_get_mfn(*sl4e);
        ASSERT(mfn_valid(*sl3mfn));
    }
    else
    {
        int r;
        shadow_l4e_t new_sl4e;
        /* No l3 shadow installed: find and install it. */
        *sl3mfn = get_shadow_status(d, gw->l3mfn, SH_type_l3_shadow);
        if ( !mfn_valid(*sl3mfn) )
        {
            /* No l3 shadow of this page exists at all: make one. */
            *sl3mfn = sh_make_shadow(v, gw->l3mfn, SH_type_l3_shadow);
        }
        /* Install the new sl3 table in the sl4e */
        l4e_propagate_from_guest(v, gw->l4e, *sl3mfn, &new_sl4e, ft);
        r = shadow_set_l4e(d, sl4e, new_sl4e, sl4mfn);
        ASSERT((r & SHADOW_SET_FLUSH) == 0);
        if ( r & SHADOW_SET_ERROR )
            return NULL;

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC )
        *resync |= 1;
#endif

    }
    /* Now follow it down a level.  Guaranteed to succeed. */
    return sh_linear_l3_table(v) + shadow_l3_linear_offset(gw->va);
}
#endif /* GUEST_PAGING_LEVELS >= 4 */


static shadow_l2e_t * shadow_get_and_create_l2e(struct vcpu *v,
                                                walk_t *gw,
                                                mfn_t *sl2mfn,
                                                fetch_type_t ft,
                                                int *resync)
{
#if GUEST_PAGING_LEVELS >= 4 /* 64bit... */
    struct domain *d = v->domain;
    mfn_t sl3mfn = INVALID_MFN;
    shadow_l3e_t *sl3e;
    if ( !mfn_valid(gw->l2mfn) ) return NULL; /* No guest page. */
    /* Get the l3e */
    sl3e = shadow_get_and_create_l3e(v, gw, &sl3mfn, ft, resync);
    if ( sl3e == NULL ) return NULL;
    if ( shadow_l3e_get_flags(*sl3e) & _PAGE_PRESENT )
    {
        *sl2mfn = shadow_l3e_get_mfn(*sl3e);
        ASSERT(mfn_valid(*sl2mfn));
    }
    else
    {
        int r;
        shadow_l3e_t new_sl3e;
        unsigned int t = SH_type_l2_shadow;

#ifdef CONFIG_PV32
        /* Tag compat L2 containing hypervisor (m2p) mappings */
        if ( is_pv_32bit_domain(d) &&
             guest_l4_table_offset(gw->va) == 0 &&
             guest_l3_table_offset(gw->va) == 3 )
            t = SH_type_l2h_shadow;
#endif

        /* No l2 shadow installed: find and install it. */
        *sl2mfn = get_shadow_status(d, gw->l2mfn, t);
        if ( !mfn_valid(*sl2mfn) )
        {
            /* No l2 shadow of this page exists at all: make one. */
            *sl2mfn = sh_make_shadow(v, gw->l2mfn, t);
        }
        /* Install the new sl2 table in the sl3e */
        l3e_propagate_from_guest(v, gw->l3e, *sl2mfn, &new_sl3e, ft);
        r = shadow_set_l3e(d, sl3e, new_sl3e, sl3mfn);
        ASSERT((r & SHADOW_SET_FLUSH) == 0);
        if ( r & SHADOW_SET_ERROR )
            return NULL;

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC )
        *resync |= 1;
#endif

    }
    /* Now follow it down a level.  Guaranteed to succeed. */
    return sh_linear_l2_table(v) + shadow_l2_linear_offset(gw->va);
#elif !defined(CONFIG_HVM)
    return NULL;
#elif GUEST_PAGING_LEVELS == 3 /* PAE... */
    /* We never demand-shadow PAE l3es: they are only created in
     * sh_update_cr3().  Check if the relevant sl3e is present. */
    shadow_l3e_t *sl3e = ((shadow_l3e_t *)&v->arch.paging.shadow.l3table)
        + shadow_l3_linear_offset(gw->va);
    if ( !(shadow_l3e_get_flags(*sl3e) & _PAGE_PRESENT) )
        return NULL;
    *sl2mfn = shadow_l3e_get_mfn(*sl3e);
    ASSERT(mfn_valid(*sl2mfn));
    return sh_linear_l2_table(v) + shadow_l2_linear_offset(gw->va);
#else /* 32bit... */
    /* There is always a shadow of the top level table.  Get it. */
    *sl2mfn = pagetable_get_mfn(v->arch.paging.shadow.shadow_table[0]);
    /* This next line is important: the guest l2 has a 16k
     * shadow, we need to return the right mfn of the four. This
     * call will set it for us as a side-effect. */
    (void) shadow_l2_index(sl2mfn, guest_l2_table_offset(gw->va));
    /* Reading the top level table is always valid. */
    return sh_linear_l2_table(v) + shadow_l2_linear_offset(gw->va);
#endif
}


static shadow_l1e_t * shadow_get_and_create_l1e(struct vcpu *v,
                                                walk_t *gw,
                                                mfn_t *sl1mfn,
                                                fetch_type_t ft)
{
    struct domain *d = v->domain;
    mfn_t sl2mfn;
    int resync = 0;
    shadow_l2e_t *sl2e;

    /* Get the l2e */
    sl2e = shadow_get_and_create_l2e(v, gw, &sl2mfn, ft, &resync);
    if ( sl2e == NULL ) return NULL;

    /* Install the sl1 in the l2e if it wasn't there or if we need to
     * re-do it to fix a PSE dirty bit. */
    if ( shadow_l2e_get_flags(*sl2e) & _PAGE_PRESENT
         && likely(ft != ft_demand_write
                   || (shadow_l2e_get_flags(*sl2e) & _PAGE_RW)
                   || !(guest_l2e_get_flags(gw->l2e) & _PAGE_PSE)) )
    {
        *sl1mfn = shadow_l2e_get_mfn(*sl2e);
        ASSERT(mfn_valid(*sl1mfn));
    }
    else
    {
        shadow_l2e_t new_sl2e;
        int r, flags = guest_l2e_get_flags(gw->l2e);
        /* No l1 shadow installed: find and install it. */
        if ( !(flags & _PAGE_PRESENT) )
            return NULL; /* No guest page. */
        if ( guest_can_use_l2_superpages(v) && (flags & _PAGE_PSE) )
        {
            /* Splintering a superpage */
            gfn_t l2gfn = guest_l2e_get_gfn(gw->l2e);
            *sl1mfn = get_fl1_shadow_status(d, l2gfn);
            if ( !mfn_valid(*sl1mfn) )
            {
                /* No fl1 shadow of this superpage exists at all: make one. */
                *sl1mfn = make_fl1_shadow(d, l2gfn);
            }
        }
        else
        {
            /* Shadowing an actual guest l1 table */
            if ( !mfn_valid(gw->l1mfn) ) return NULL; /* No guest page. */
            *sl1mfn = get_shadow_status(d, gw->l1mfn, SH_type_l1_shadow);
            if ( !mfn_valid(*sl1mfn) )
            {
                /* No l1 shadow of this page exists at all: make one. */
                *sl1mfn = sh_make_shadow(v, gw->l1mfn, SH_type_l1_shadow);
            }
        }
        /* Install the new sl1 table in the sl2e */
        l2e_propagate_from_guest(v, gw->l2e, *sl1mfn, &new_sl2e, ft);
        r = shadow_set_l2e(d, sl2e, new_sl2e, sl2mfn);
        ASSERT((r & SHADOW_SET_FLUSH) == 0);
        if ( r & SHADOW_SET_ERROR )
            return NULL;

        /* This next line is important: in 32-on-PAE and 32-on-64 modes,
         * the guest l1 table has an 8k shadow, and we need to return
         * the right mfn of the pair. This call will set it for us as a
         * side-effect.  (In all other cases, it's a no-op and will be
         * compiled out.) */
        (void) shadow_l1_index(sl1mfn, guest_l1_table_offset(gw->va));
    }

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC )
    /* All pages walked are now pagetables. Safe to resync pages
       in case level 4 or 3 shadows were set. */
    if ( resync )
        shadow_resync_all(v);
#endif

    /* Now follow it down a level.  Guaranteed to succeed. */
    return sh_linear_l1_table(v) + shadow_l1_linear_offset(gw->va);
}



/**************************************************************************/
/* Destructors for shadow tables:
 * Unregister the shadow, decrement refcounts of any entries present in it,
 * and release the memory.
 *
 * N.B. These destructors do not clear the contents of the shadows.
 *      This allows us to delay TLB shootdowns until the page is being reused.
 *      See shadow_alloc() and shadow_free() for how this is handled.
 */

#if GUEST_PAGING_LEVELS >= 4
void sh_destroy_l4_shadow(struct domain *d, mfn_t smfn)
{
    shadow_l4e_t *sl4e;
    struct page_info *sp = mfn_to_page(smfn);
    u32 t = sp->u.sh.type;
    mfn_t gmfn, sl4mfn;

    SHADOW_DEBUG(DESTROY_SHADOW, "%"PRI_mfn"\n", mfn_x(smfn));
    ASSERT(t == SH_type_l4_shadow);
    ASSERT(sp->u.sh.head);

    /* Record that the guest page isn't shadowed any more (in this type) */
    gmfn = backpointer(sp);
    delete_shadow_status(d, gmfn, t, smfn);
    shadow_demote(d, gmfn, t);
    /* Decrement refcounts of all the old entries */
    sl4mfn = smfn;
    FOREACH_PRESENT_L4E(sl4mfn, sl4e, NULL, 0, d, {
        sh_put_ref(d, shadow_l4e_get_mfn(*sl4e),
                   mfn_to_maddr(sl4mfn) | ((unsigned long)sl4e & ~PAGE_MASK));
    });

    /* Put the memory back in the pool */
    shadow_free(d, smfn);
}

void sh_destroy_l3_shadow(struct domain *d, mfn_t smfn)
{
    shadow_l3e_t *sl3e;
    struct page_info *sp = mfn_to_page(smfn);
    u32 t = sp->u.sh.type;
    mfn_t gmfn, sl3mfn;

    SHADOW_DEBUG(DESTROY_SHADOW, "%"PRI_mfn"\n", mfn_x(smfn));
    ASSERT(t == SH_type_l3_shadow);
    ASSERT(sp->u.sh.head);

    /* Record that the guest page isn't shadowed any more (in this type) */
    gmfn = backpointer(sp);
    delete_shadow_status(d, gmfn, t, smfn);
    shadow_demote(d, gmfn, t);

    /* Decrement refcounts of all the old entries */
    sl3mfn = smfn;
    FOREACH_PRESENT_L3E(sl3mfn, sl3e, NULL, 0, {
        sh_put_ref(d, shadow_l3e_get_mfn(*sl3e),
                   mfn_to_maddr(sl3mfn) | ((unsigned long)sl3e & ~PAGE_MASK));
    });

    /* Put the memory back in the pool */
    shadow_free(d, smfn);
}
#endif /* GUEST_PAGING_LEVELS >= 4 */


void sh_destroy_l2_shadow(struct domain *d, mfn_t smfn)
{
    shadow_l2e_t *sl2e;
    struct page_info *sp = mfn_to_page(smfn);
    u32 t = sp->u.sh.type;
    mfn_t gmfn, sl2mfn;

    SHADOW_DEBUG(DESTROY_SHADOW, "%"PRI_mfn"\n", mfn_x(smfn));

    ASSERT_VALID_L2(t);
    ASSERT(sp->u.sh.head);

    /* Record that the guest page isn't shadowed any more (in this type) */
    gmfn = backpointer(sp);
    delete_shadow_status(d, gmfn, t, smfn);
    shadow_demote(d, gmfn, t);

    /* Decrement refcounts of all the old entries */
    sl2mfn = smfn;
    FOREACH_PRESENT_L2E(sl2mfn, sl2e, NULL, 0, d, {
        sh_put_ref(d, shadow_l2e_get_mfn(*sl2e),
                   mfn_to_maddr(sl2mfn) | ((unsigned long)sl2e & ~PAGE_MASK));
    });

    /* Put the memory back in the pool */
    shadow_free(d, smfn);
}

void sh_destroy_l1_shadow(struct domain *d, mfn_t smfn)
{
    shadow_l1e_t *sl1e;
    struct page_info *sp = mfn_to_page(smfn);
    u32 t = sp->u.sh.type;

    SHADOW_DEBUG(DESTROY_SHADOW, "%"PRI_mfn"\n", mfn_x(smfn));
    ASSERT(t == SH_type_l1_shadow || t == SH_type_fl1_shadow);
    ASSERT(sp->u.sh.head);

    /* Record that the guest page isn't shadowed any more (in this type) */
    if ( t == SH_type_fl1_shadow )
    {
        gfn_t gfn = _gfn(sp->v.sh.back);
        delete_fl1_shadow_status(d, gfn, smfn);
    }
    else
    {
        mfn_t gmfn = backpointer(sp);
        delete_shadow_status(d, gmfn, t, smfn);
        shadow_demote(d, gmfn, t);
    }

    if ( shadow_mode_refcounts(d) )
    {
        /* Decrement refcounts of all the old entries */
        mfn_t sl1mfn = smfn;
        FOREACH_PRESENT_L1E(sl1mfn, sl1e, NULL, 0, {
            if ( !sh_l1e_is_magic(*sl1e) )
            {
                shadow_vram_put_mfn(shadow_l1e_get_mfn(*sl1e),
                                    shadow_l1e_get_flags(*sl1e),
                                    sl1mfn, sl1e, d);
                shadow_put_page_from_l1e(*sl1e, d);
            }
        });
    }

    /* Put the memory back in the pool */
    shadow_free(d, smfn);
}

/**************************************************************************/
/* Functions to destroy non-Xen mappings in a pagetable hierarchy.
 * These are called from common code when we are running out of shadow
 * memory, and unpinning all the top-level shadows hasn't worked.
 *
 * With user_only == 1, we leave guest kernel-mode mappings in place too,
 * unhooking only the user-mode mappings
 *
 * This implementation is pretty crude and slow, but we hope that it won't
 * be called very often. */

#if GUEST_PAGING_LEVELS < 4

void sh_unhook_l2_mappings(struct domain *d, mfn_t sl2mfn, bool user_only)
{
    shadow_l2e_t *sl2e;
    FOREACH_PRESENT_L2E(sl2mfn, sl2e, NULL, 0, d, {
        if ( !user_only || (sl2e->l2 & _PAGE_USER) )
            shadow_set_l2e(d, sl2e, shadow_l2e_empty(), sl2mfn);
    });
}

#elif GUEST_PAGING_LEVELS == 4

void sh_unhook_l4_mappings(struct domain *d, mfn_t sl4mfn, bool user_only)
{
    shadow_l4e_t *sl4e;
    FOREACH_PRESENT_L4E(sl4mfn, sl4e, NULL, 0, d, {
        if ( !user_only || (sl4e->l4 & _PAGE_USER) )
            shadow_set_l4e(d, sl4e, shadow_l4e_empty(), sl4mfn);
    });
}

#endif

/**************************************************************************/
/* Internal translation functions.
 * These functions require a pointer to the shadow entry that will be updated.
 */

/* These functions take a new guest entry, translate it to shadow and write
 * the shadow entry.
 *
 * They return the same bitmaps as the shadow_set_lXe() functions.
 */

#if GUEST_PAGING_LEVELS >= 4
static int cf_check validate_gl4e(
    struct vcpu *v, void *new_ge, mfn_t sl4mfn, void *se)
{
    shadow_l4e_t new_sl4e;
    guest_l4e_t new_gl4e = *(guest_l4e_t *)new_ge;
    shadow_l4e_t *sl4p = se;
    mfn_t sl3mfn = INVALID_MFN;
    struct domain *d = v->domain;
    p2m_type_t p2mt;
    int result = 0;

    perfc_incr(shadow_validate_gl4e_calls);

    if ( (guest_l4e_get_flags(new_gl4e) & _PAGE_PRESENT) &&
         !guest_l4e_rsvd_bits(v, new_gl4e) )
    {
        gfn_t gl3gfn = guest_l4e_get_gfn(new_gl4e);
        mfn_t gl3mfn = get_gfn_query_unlocked(d, gfn_x(gl3gfn), &p2mt);
        if ( p2m_is_ram(p2mt) )
            sl3mfn = get_shadow_status(d, gl3mfn, SH_type_l3_shadow);
        else if ( !p2m_is_pod(p2mt) )
            result |= SHADOW_SET_ERROR;

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC )
        if ( mfn_valid(sl3mfn) )
            shadow_resync_all(v);
#endif
    }
    l4e_propagate_from_guest(v, new_gl4e, sl3mfn, &new_sl4e, ft_prefetch);

    // check for updates to xen reserved slots
    if ( !shadow_mode_external(d) )
    {
        int shadow_index = (((unsigned long)sl4p & ~PAGE_MASK) /
                            sizeof(shadow_l4e_t));
        int reserved_xen_slot = !is_guest_l4_slot(d, shadow_index);

        if ( unlikely(reserved_xen_slot) )
        {
            // attempt by the guest to write to a xen reserved slot
            //
            SHADOW_PRINTK("out-of-range update "
                          "sl4mfn=%"PRI_mfn" index=%#x val=%" SH_PRI_pte "\n",
                          mfn_x(sl4mfn), shadow_index, new_sl4e.l4);
            if ( shadow_l4e_get_flags(new_sl4e) & _PAGE_PRESENT )
            {
                printk(XENLOG_G_ERR "out-of-range l4e update\n");
                result |= SHADOW_SET_ERROR;
            }

            // do not call shadow_set_l4e...
            return result;
        }
    }

    result |= shadow_set_l4e(d, sl4p, new_sl4e, sl4mfn);
    return result;
}


static int cf_check validate_gl3e(
    struct vcpu *v, void *new_ge, mfn_t sl3mfn, void *se)
{
    struct domain *d = v->domain;
    shadow_l3e_t new_sl3e;
    guest_l3e_t new_gl3e = *(guest_l3e_t *)new_ge;
    shadow_l3e_t *sl3p = se;
    mfn_t sl2mfn = INVALID_MFN;
    p2m_type_t p2mt;
    int result = 0;

    perfc_incr(shadow_validate_gl3e_calls);

    if ( (guest_l3e_get_flags(new_gl3e) & _PAGE_PRESENT) &&
         !guest_l3e_rsvd_bits(v, new_gl3e) )
    {
        gfn_t gl2gfn = guest_l3e_get_gfn(new_gl3e);
        mfn_t gl2mfn = get_gfn_query_unlocked(d, gfn_x(gl2gfn), &p2mt);
        if ( p2m_is_ram(p2mt) )
            sl2mfn = get_shadow_status(d, gl2mfn, SH_type_l2_shadow);
        else if ( !p2m_is_pod(p2mt) )
            result |= SHADOW_SET_ERROR;

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC )
        if ( mfn_valid(sl2mfn) )
            shadow_resync_all(v);
#endif
    }
    l3e_propagate_from_guest(v, new_gl3e, sl2mfn, &new_sl3e, ft_prefetch);
    result |= shadow_set_l3e(d, sl3p, new_sl3e, sl3mfn);

    return result;
}
#endif // GUEST_PAGING_LEVELS >= 4

static int cf_check validate_gl2e(
    struct vcpu *v, void *new_ge, mfn_t sl2mfn, void *se)
{
    struct domain *d = v->domain;
    shadow_l2e_t new_sl2e;
    guest_l2e_t new_gl2e = *(guest_l2e_t *)new_ge;
    shadow_l2e_t *sl2p = se;
    mfn_t sl1mfn = INVALID_MFN;
    p2m_type_t p2mt;
    int result = 0;

    perfc_incr(shadow_validate_gl2e_calls);

    if ( (guest_l2e_get_flags(new_gl2e) & _PAGE_PRESENT) &&
         !guest_l2e_rsvd_bits(v, new_gl2e) )
    {
        gfn_t gl1gfn = guest_l2e_get_gfn(new_gl2e);
        if ( guest_can_use_l2_superpages(v) &&
             (guest_l2e_get_flags(new_gl2e) & _PAGE_PSE) )
        {
            // superpage -- need to look up the shadow L1 which holds the
            // splitters...
            sl1mfn = get_fl1_shadow_status(d, gl1gfn);
#if 0
            // XXX - it's possible that we want to do some kind of prefetch
            // for superpage fl1's here, but this is *not* on the demand path,
            // so we'll hold off trying that for now...
            //
            if ( !mfn_valid(sl1mfn) )
                sl1mfn = make_fl1_shadow(d, gl1gfn);
#endif
        }
        else
        {
            mfn_t gl1mfn = get_gfn_query_unlocked(d, gfn_x(gl1gfn), &p2mt);
            if ( p2m_is_ram(p2mt) )
                sl1mfn = get_shadow_status(d, gl1mfn, SH_type_l1_shadow);
            else if ( !p2m_is_pod(p2mt) )
                result |= SHADOW_SET_ERROR;
        }
    }
    l2e_propagate_from_guest(v, new_gl2e, sl1mfn, &new_sl2e, ft_prefetch);

    result |= shadow_set_l2e(d, sl2p, new_sl2e, sl2mfn);

    return result;
}

static int cf_check validate_gl1e(
    struct vcpu *v, void *new_ge, mfn_t sl1mfn, void *se)
{
    struct domain *d = v->domain;
    shadow_l1e_t new_sl1e;
    guest_l1e_t new_gl1e = *(guest_l1e_t *)new_ge;
    shadow_l1e_t *sl1p = se;
    gfn_t gfn;
    mfn_t gmfn = INVALID_MFN;
    p2m_type_t p2mt = p2m_invalid;
    int result = 0;
#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    mfn_t gl1mfn;
#endif /* OOS */

    perfc_incr(shadow_validate_gl1e_calls);

    if ( (guest_l1e_get_flags(new_gl1e) & _PAGE_PRESENT) &&
         !guest_l1e_rsvd_bits(v, new_gl1e) )
    {
        gfn = guest_l1e_get_gfn(new_gl1e);
        gmfn = get_gfn_query_unlocked(d, gfn_x(gfn), &p2mt);
    }

    l1e_propagate_from_guest(v, new_gl1e, gmfn, &new_sl1e, ft_prefetch, p2mt);
    result |= shadow_set_l1e(d, sl1p, new_sl1e, p2mt, sl1mfn);

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    gl1mfn = backpointer(mfn_to_page(sl1mfn));
    if ( mfn_valid(gl1mfn)
         && mfn_is_out_of_sync(gl1mfn) )
    {
        /* Update the OOS snapshot. */
        mfn_t snpmfn = oos_snapshot_lookup(d, gl1mfn);
        guest_l1e_t *snp;

        ASSERT(mfn_valid(snpmfn));

        snp = map_domain_page(snpmfn);
        snp[guest_index(new_ge)] = new_gl1e;
        unmap_domain_page(snp);
    }
#endif /* OOS */

    return result;
}

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
/**************************************************************************/
/* Special validation function for re-syncing out-of-sync shadows.
 * Walks the *shadow* page, and for every entry that it finds,
 * revalidates the guest entry that corresponds to it.
 * N.B. This function is called with the vcpu that unsynced the page,
 *      *not* the one that is causing it to be resynced. */
void sh_resync_l1(struct vcpu *v, mfn_t gl1mfn, mfn_t snpmfn)
{
    struct domain *d = v->domain;
    mfn_t sl1mfn;
    shadow_l1e_t *sl1p;
    guest_l1e_t *gl1p, *gp, *snp;
    int rc = 0;

    ASSERT(mfn_valid(snpmfn));

    sl1mfn = get_shadow_status(d, gl1mfn, SH_type_l1_shadow);
    ASSERT(mfn_valid(sl1mfn)); /* Otherwise we would not have been called */

    snp = map_domain_page(snpmfn);
    gp = map_domain_page(gl1mfn);
    gl1p = gp;

   FOREACH_PRESENT_L1E(sl1mfn, sl1p, &gl1p, 0, {
        guest_l1e_t gl1e = *gl1p;

        if ( snp[guest_index(gl1p)].l1 != gl1e.l1 )
        {
            gfn_t gfn;
            mfn_t gmfn = INVALID_MFN;
            p2m_type_t p2mt = p2m_invalid;
            shadow_l1e_t nsl1e;

            if ( (guest_l1e_get_flags(gl1e) & _PAGE_PRESENT) &&
                 !guest_l1e_rsvd_bits(v, gl1e) )
            {
                gfn = guest_l1e_get_gfn(gl1e);
                gmfn = get_gfn_query_unlocked(d, gfn_x(gfn), &p2mt);
            }

            l1e_propagate_from_guest(v, gl1e, gmfn, &nsl1e, ft_prefetch, p2mt);
            rc |= shadow_set_l1e(d, sl1p, nsl1e, p2mt, sl1mfn);
            snp[guest_index(gl1p)] = gl1e;
        }
    });

    unmap_domain_page(gp);
    unmap_domain_page(snp);

    /* Setting shadow L1 entries should never need us to flush the TLB */
    ASSERT(!(rc & SHADOW_SET_FLUSH));
}

/* Figure out whether it's definitely safe not to sync this l1 table.
 * That is: if we can tell that it's only used once, and that the
 * toplevel shadow responsible is not one of ours.
 * N.B. This function is called with the vcpu that required the resync,
 *      *not* the one that originally unsynced the page, but it is
 *      called in the *mode* of the vcpu that unsynced it.  Clear?  Good. */
int sh_safe_not_to_sync(struct vcpu *v, mfn_t gl1mfn)
{
    struct domain *d = v->domain;
    struct page_info *sp;
    mfn_t smfn;
    unsigned int i;

    if ( !sh_type_has_up_pointer(d, SH_type_l1_shadow) )
        return 0;

    smfn = get_shadow_status(d, gl1mfn, SH_type_l1_shadow);
    ASSERT(mfn_valid(smfn)); /* Otherwise we would not have been called */

    /* Up to l2 */
    sp = mfn_to_page(smfn);
    if ( sp->u.sh.count != 1 || !sp->up )
        return 0;
    smfn = maddr_to_mfn(sp->up);
    ASSERT(mfn_valid(smfn));

#if (SHADOW_PAGING_LEVELS == 4)
    /* up to l3 */
    sp = mfn_to_page(smfn);
    ASSERT(sh_type_has_up_pointer(d, SH_type_l2_shadow));
    if ( sp->u.sh.count != 1 || !sp->up )
        return 0;
    smfn = maddr_to_mfn(sp->up);
    ASSERT(mfn_valid(smfn));

    /* up to l4 */
    sp = mfn_to_page(smfn);
    if ( sp->u.sh.count != 1
         || !sh_type_has_up_pointer(d, SH_type_l3_64_shadow) || !sp->up )
        return 0;
    smfn = maddr_to_mfn(sp->up);
    ASSERT(mfn_valid(smfn));
#endif

    for_each_shadow_table(v, i)
        if ( pagetable_get_pfn(v->arch.paging.shadow.shadow_table[i]) ==
             mfn_x(smfn) )
            return 0;

    /* Only in use in one toplevel shadow, and it's not the one we're
     * running on */
    return 1;
}
#endif /* (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC) */


/**************************************************************************/
/* Functions which translate and install the shadows of arbitrary guest
 * entries that we have just seen the guest write. */


static inline int
sh_map_and_validate(struct vcpu *v, mfn_t gmfn,
                     void *new_gp, u32 size, u32 sh_type,
                     u32 (*shadow_index)(mfn_t *smfn, u32 idx),
                     int (*validate_ge)(struct vcpu *v, void *ge,
                                        mfn_t smfn, void *se))
/* Generic function for mapping and validating. */
{
    struct domain *d = v->domain;
    mfn_t smfn, smfn2, map_mfn;
    shadow_l1e_t *sl1p;
    u32 shadow_idx, guest_idx;
    int result = 0;

    /* Align address and size to guest entry boundaries */
    size += (unsigned long)new_gp & (sizeof (guest_l1e_t) - 1);
    new_gp = (void *)((unsigned long)new_gp & ~(sizeof (guest_l1e_t) - 1));
    size = (size + sizeof (guest_l1e_t) - 1) & ~(sizeof (guest_l1e_t) - 1);
    ASSERT(size + (((unsigned long)new_gp) & ~PAGE_MASK) <= PAGE_SIZE);

    /* Map the shadow page */
    smfn = get_shadow_status(d, gmfn, sh_type);
    ASSERT(mfn_valid(smfn)); /* Otherwise we would not have been called */
    guest_idx = guest_index(new_gp);
    map_mfn = smfn;
    shadow_idx = shadow_index(&map_mfn, guest_idx);
    sl1p = map_domain_page(map_mfn);

    /* Validate one entry at a time */
    while ( size )
    {
        smfn2 = smfn;
        guest_idx = guest_index(new_gp);
        shadow_idx = shadow_index(&smfn2, guest_idx);
        if ( !mfn_eq(smfn2, map_mfn) )
        {
            /* We have moved to another page of the shadow */
            map_mfn = smfn2;
            unmap_domain_page(sl1p);
            sl1p = map_domain_page(map_mfn);
        }
        result |= validate_ge(v,
                              new_gp,
                              map_mfn,
                              &sl1p[shadow_idx]);
        size -= sizeof(guest_l1e_t);
        new_gp += sizeof(guest_l1e_t);
    }
    unmap_domain_page(sl1p);
    return result;
}


int
sh_map_and_validate_gl4e(struct vcpu *v, mfn_t gl4mfn,
                          void *new_gl4p, u32 size)
{
#if GUEST_PAGING_LEVELS >= 4
    return sh_map_and_validate(v, gl4mfn, new_gl4p, size,
                                SH_type_l4_shadow,
                                shadow_l4_index,
                                validate_gl4e);
#else // ! GUEST_PAGING_LEVELS >= 4
    BUG(); /* Called in wrong paging mode! */
#endif
}

int
sh_map_and_validate_gl3e(struct vcpu *v, mfn_t gl3mfn,
                          void *new_gl3p, u32 size)
{
#if GUEST_PAGING_LEVELS >= 4
    return sh_map_and_validate(v, gl3mfn, new_gl3p, size,
                                SH_type_l3_shadow,
                                shadow_l3_index,
                                validate_gl3e);
#else // ! GUEST_PAGING_LEVELS >= 4
    BUG(); /* Called in wrong paging mode! */
#endif
}

int
sh_map_and_validate_gl2e(struct vcpu *v, mfn_t gl2mfn,
                          void *new_gl2p, u32 size)
{
    return sh_map_and_validate(v, gl2mfn, new_gl2p, size,
                                SH_type_l2_shadow,
                                shadow_l2_index,
                                validate_gl2e);
}

int
sh_map_and_validate_gl2he(struct vcpu *v, mfn_t gl2mfn,
                           void *new_gl2p, u32 size)
{
#if GUEST_PAGING_LEVELS >= 4 && defined(CONFIG_PV32)
    return sh_map_and_validate(v, gl2mfn, new_gl2p, size,
                                SH_type_l2h_shadow,
                                shadow_l2_index,
                                validate_gl2e);
#else /* Non-PAE guests don't have different kinds of l2 table */
    BUG(); /* Called in wrong paging mode! */
#endif
}

int
sh_map_and_validate_gl1e(struct vcpu *v, mfn_t gl1mfn,
                          void *new_gl1p, u32 size)
{
    return sh_map_and_validate(v, gl1mfn, new_gl1p, size,
                                SH_type_l1_shadow,
                                shadow_l1_index,
                                validate_gl1e);
}


/**************************************************************************/
/* Optimization: Prefetch multiple L1 entries.  This is called after we have
 * demand-faulted a shadow l1e in the fault handler, to see if it's
 * worth fetching some more.
 */

#if SHADOW_OPTIMIZATIONS & SHOPT_PREFETCH

/* XXX magic number */
#define PREFETCH_DISTANCE 32

static void sh_prefetch(struct vcpu *v, walk_t *gw,
                        shadow_l1e_t *ptr_sl1e, mfn_t sl1mfn)
{
    struct domain *d = v->domain;
    int i, dist;
    gfn_t gfn;
    mfn_t gmfn;
    guest_l1e_t *gl1p = NULL, gl1e;
    shadow_l1e_t sl1e;
    u32 gflags;
    p2m_type_t p2mt;
#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    guest_l1e_t *snpl1p = NULL;
#endif /* OOS */


    /* Prefetch no further than the end of the _shadow_ l1 MFN */
    dist = (PAGE_SIZE - ((unsigned long)ptr_sl1e & ~PAGE_MASK)) / sizeof sl1e;
    /* And no more than a maximum fetches-per-fault */
    if ( dist > PREFETCH_DISTANCE )
        dist = PREFETCH_DISTANCE;

    if ( mfn_valid(gw->l1mfn) )
    {
        /* Normal guest page; grab the next guest entry */
        gl1p = map_domain_page(gw->l1mfn);
        gl1p += guest_l1_table_offset(gw->va);

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
        if ( mfn_is_out_of_sync(gw->l1mfn) )
        {
            mfn_t snpmfn = oos_snapshot_lookup(d, gw->l1mfn);

            ASSERT(mfn_valid(snpmfn));
            snpl1p = map_domain_page(snpmfn);
            snpl1p += guest_l1_table_offset(gw->va);
        }
#endif /* OOS */
    }

    for ( i = 1; i < dist ; i++ )
    {
        /* No point in prefetching if there's already a shadow */
        if ( ptr_sl1e[i].l1 != 0 )
            break;

        if ( mfn_valid(gw->l1mfn) )
        {
            /* Normal guest page; grab the next guest entry */
            gl1e = gl1p[i];
            /* Not worth continuing if we hit an entry that will need another
             * fault for A/D-bit propagation anyway */
            gflags = guest_l1e_get_flags(gl1e);
            if ( (gflags & _PAGE_PRESENT)
                 && (!(gflags & _PAGE_ACCESSED)
                     || ((gflags & _PAGE_RW) && !(gflags & _PAGE_DIRTY))) )
                break;
        }
        else
        {
            /* Fragmented superpage, unless we've been called wrongly */
            ASSERT(guest_l2e_get_flags(gw->l2e) & _PAGE_PSE);
            /* Increment the l1e's GFN by the right number of guest pages */
            gl1e = guest_l1e_from_gfn(
                _gfn(gfn_x(guest_l1e_get_gfn(gw->l1e)) + i),
                guest_l1e_get_flags(gw->l1e));
        }

        /* Look at the gfn that the l1e is pointing at */
        if ( (guest_l1e_get_flags(gl1e) & _PAGE_PRESENT) &&
             !guest_l1e_rsvd_bits(v, gl1e) )
        {
            gfn = guest_l1e_get_gfn(gl1e);
            gmfn = get_gfn_query_unlocked(d, gfn_x(gfn), &p2mt);
        }
        else
        {
            gmfn = INVALID_MFN;
            p2mt = p2m_invalid;
        }

        /* Propagate the entry.  */
        l1e_propagate_from_guest(v, gl1e, gmfn, &sl1e, ft_prefetch, p2mt);
        shadow_set_l1e(d, ptr_sl1e + i, sl1e, p2mt, sl1mfn);

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
        if ( snpl1p != NULL )
            snpl1p[i] = gl1e;
#endif /* OOS */
    }
    if ( gl1p != NULL )
        unmap_domain_page(gl1p);
#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    if ( snpl1p != NULL )
        unmap_domain_page(snpl1p);
#endif /* OOS */
}

#endif /* SHADOW_OPTIMIZATIONS & SHOPT_PREFETCH */

#if GUEST_PAGING_LEVELS == 4
typedef u64 guest_va_t;
typedef u64 guest_pa_t;
#elif GUEST_PAGING_LEVELS == 3
typedef u32 guest_va_t;
typedef u64 guest_pa_t;
#else
typedef u32 guest_va_t;
typedef u32 guest_pa_t;
#endif

/* Shadow trace event with GUEST_PAGING_LEVELS folded into the event field. */
static void sh_trace(uint32_t event, unsigned int extra, const void *extra_data)
{
    trace(event | ((GUEST_PAGING_LEVELS - 2) << 8), extra, extra_data);
}

/* Shadow trace event with the guest's linear address. */
static void sh_trace_va(uint32_t event, guest_va_t va)
{
    if ( tb_init_done )
        sh_trace(event, sizeof(va), &va);
}

/* Shadow trace event with a gl1e, linear address and flags. */
static void sh_trace_gl1e_va(uint32_t event, guest_l1e_t gl1e, guest_va_t va)
{
    if ( tb_init_done )
    {
        struct __packed {
            /*
             * For GUEST_PAGING_LEVELS=3 (PAE paging), guest_l1e is 64 while
             * guest_va is 32.  Put it first to avoid padding.
             */
            guest_l1e_t gl1e;
            guest_va_t va;
            uint32_t flags;
        } d = {
            .gl1e  = gl1e,
            .va    = va,
            .flags = this_cpu(trace_shadow_path_flags),
        };

        sh_trace(event, sizeof(d), &d);
    }
}

/* Shadow trace event with a gfn, linear address and flags. */
static void __maybe_unused sh_trace_gfn_va(uint32_t event, gfn_t gfn,
                                           guest_va_t va)
{
    if ( tb_init_done )
    {
        struct __packed {
            /*
             * For GUEST_PAGING_LEVELS=3 (PAE paging), gfn is 64 while
             * guest_va is 32.  Put it first to avoid padding.
             */
#if GUEST_PAGING_LEVELS == 2
            uint32_t gfn;
#else
            uint64_t gfn;
#endif
            guest_va_t va;
            uint32_t flags;
        } d = {
            .gfn   = gfn_x(gfn),
            .va    = va,
            .flags = this_cpu(trace_shadow_path_flags),
        };

        sh_trace(event, sizeof(d), &d);
    }
}

#ifdef CONFIG_HVM
#if GUEST_PAGING_LEVELS == 3
static DEFINE_PER_CPU(guest_va_t,trace_emulate_initial_va);
static DEFINE_PER_CPU(int,trace_extra_emulation_count);
#endif
static DEFINE_PER_CPU(guest_pa_t,trace_emulate_write_val);

static void cf_check trace_emulate_write_val(
    const void *ptr, unsigned long vaddr, const void *src, unsigned int bytes)
{
#if GUEST_PAGING_LEVELS == 3
    if ( vaddr == this_cpu(trace_emulate_initial_va) )
        memcpy(&this_cpu(trace_emulate_write_val), src, bytes);
    else if ( (vaddr & ~(GUEST_PTE_SIZE - 1)) ==
              this_cpu(trace_emulate_initial_va) )
    {
        TRACE_SHADOW_PATH_FLAG(TRCE_SFLAG_EMULATE_FULL_PT);
        memcpy(&this_cpu(trace_emulate_write_val),
               (typeof(ptr))((unsigned long)ptr & ~(GUEST_PTE_SIZE - 1)),
               GUEST_PTE_SIZE);
    }
#else
    memcpy(&this_cpu(trace_emulate_write_val), src, bytes);
#endif
}

static inline void sh_trace_emulate(guest_l1e_t gl1e, unsigned long va)
{
    if ( tb_init_done )
    {
        struct __packed {
            /*
             * For GUEST_PAGING_LEVELS=3 (PAE paging), guest_l1e is 64 while
             * guest_va is 32.  Put it first to avoid padding.
             */
            guest_l1e_t gl1e, write_val;
            guest_va_t va;
            uint32_t flags:29, emulation_count:3;
        } d = {
            .gl1e            = gl1e,
            .write_val.l1    = this_cpu(trace_emulate_write_val),
            .va              = va,
#if GUEST_PAGING_LEVELS == 3
            .emulation_count = this_cpu(trace_extra_emulation_count),
#endif
            .flags           = this_cpu(trace_shadow_path_flags),
        };

        sh_trace(TRC_SHADOW_EMULATE, sizeof(d), &d);
    }
}
#endif /* CONFIG_HVM */

/**************************************************************************/
/* Entry points into the shadow code */

/* Called from pagefault handler in Xen, and from the HVM trap handlers
 * for pagefaults.  Returns 1 if this fault was an artefact of the
 * shadow code (and the guest should retry) or 0 if it is not (and the
 * fault should be handled elsewhere or passed to the guest). */

static int cf_check sh_page_fault(
    struct vcpu *v, unsigned long va, struct cpu_user_regs *regs)
{
    struct domain *d = v->domain;
    walk_t gw;
    gfn_t gfn = _gfn(0);
    mfn_t gmfn, sl1mfn = _mfn(0);
    shadow_l1e_t sl1e, *ptr_sl1e;
#ifdef CONFIG_HVM
    paddr_t gpa;
    struct sh_emulate_ctxt emul_ctxt;
    const struct x86_emulate_ops *emul_ops;
    int r;
#endif
    p2m_type_t p2mt;
    uint32_t rc, error_code;
    bool walk_ok;
    int version;
    unsigned int cpl;
    const struct npfec access = {
         .read_access = 1,
         .write_access = !!(regs->error_code & PFEC_write_access),
         .gla_valid = 1,
         .kind = npfec_kind_with_gla
    };
    const fetch_type_t ft =
        access.write_access ? ft_demand_write : ft_demand_read;
#if SHADOW_OPTIMIZATIONS & SHOPT_FAST_EMULATION
    int fast_emul = 0;
#endif

    SHADOW_PRINTK("%pv va=%#lx err=%#x, rip=%lx\n",
                  v, va, regs->error_code, regs->rip);

    perfc_incr(shadow_fault);

#if SHADOW_OPTIMIZATIONS & SHOPT_FAST_EMULATION
    /* If faulting frame is successfully emulated in last shadow fault
     * it's highly likely to reach same emulation action for this frame.
     * Then try to emulate early to avoid lock aquisition.
     */
    if ( v->arch.paging.last_write_emul_ok
         && v->arch.paging.shadow.last_emulated_frame == (va >> PAGE_SHIFT) )
    {
        /* check whether error code is 3, or else fall back to normal path
         * in case of some validation is required
         */
        if ( regs->error_code == (PFEC_write_access | PFEC_page_present) )
        {
            fast_emul = 1;
            gmfn = _mfn(v->arch.paging.shadow.last_emulated_mfn);

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
            /* Fall back to the slow path if we're trying to emulate
               writes to an out of sync page. */
            if ( mfn_valid(gmfn) && mfn_is_out_of_sync(gmfn) )
            {
                fast_emul = 0;
                v->arch.paging.last_write_emul_ok = 0;
                goto page_fault_slow_path;
            }
#endif /* OOS */

            perfc_incr(shadow_fault_fast_emulate);
            goto early_emulation;
        }
        else
            v->arch.paging.last_write_emul_ok = 0;
    }
#endif

    //
    // XXX: Need to think about eventually mapping superpages directly in the
    //      shadow (when possible), as opposed to splintering them into a
    //      bunch of 4K maps.
    //

#if (SHADOW_OPTIMIZATIONS & SHOPT_FAST_FAULT_PATH)
    if ( (regs->error_code & PFEC_reserved_bit) )
    {
#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
        /* First, need to check that this isn't an out-of-sync
         * shadow l1e.  If it is, we fall back to the slow path, which
         * will sync it up again. */
        {
            shadow_l2e_t sl2e;
            mfn_t gl1mfn;
            if ( (get_unsafe(sl2e,
                             (sh_linear_l2_table(v) +
                              shadow_l2_linear_offset(va))) != 0)
                 || !(shadow_l2e_get_flags(sl2e) & _PAGE_PRESENT)
                 || !mfn_valid(gl1mfn = backpointer(mfn_to_page(
                                  shadow_l2e_get_mfn(sl2e))))
                 || unlikely(mfn_is_out_of_sync(gl1mfn)) )
            {
                /* Hit the slow path as if there had been no
                 * shadow entry at all, and let it tidy up */
                ASSERT(regs->error_code & PFEC_page_present);
                regs->error_code ^= (PFEC_reserved_bit|PFEC_page_present);
                goto page_fault_slow_path;
            }
        }
#endif /* SHOPT_OUT_OF_SYNC */
        /* The only reasons for reserved bits to be set in shadow entries
         * are the two "magic" shadow_l1e entries. */
        if ( likely((get_unsafe(sl1e,
                                (sh_linear_l1_table(v) +
                                 shadow_l1_linear_offset(va))) == 0)
                    && sh_l1e_is_magic(sl1e)) )
        {

            if ( sh_l1e_is_gnp(sl1e) )
            {
                /* Not-present in a guest PT: pass to the guest as
                 * a not-present fault (by flipping two bits). */
                ASSERT(regs->error_code & PFEC_page_present);
                regs->error_code ^= (PFEC_reserved_bit|PFEC_page_present);
                sh_reset_early_unshadow(v);
                perfc_incr(shadow_fault_fast_gnp);
                SHADOW_PRINTK("fast path not-present\n");
                sh_trace_va(TRC_SHADOW_FAST_PROPAGATE, va);
                return 0;
            }
#ifdef CONFIG_HVM
            /* Magic MMIO marker: extract gfn for MMIO address */
            ASSERT(sh_l1e_is_mmio(sl1e));
            ASSERT(is_hvm_vcpu(v));
            gpa = gfn_to_gaddr(sh_l1e_mmio_get_gfn(sl1e)) | (va & ~PAGE_MASK);
            perfc_incr(shadow_fault_fast_mmio);
            SHADOW_PRINTK("fast path mmio %#"PRIpaddr"\n", gpa);
            sh_reset_early_unshadow(v);
            sh_trace_va(TRC_SHADOW_FAST_MMIO, va);
            return handle_mmio_with_translation(va, gpa >> PAGE_SHIFT, access)
                   ? EXCRET_fault_fixed : 0;
#else
            /* When HVM is not enabled, there shouldn't be MMIO marker */
            BUG();
#endif
        }
        else
        {
            /* This should be exceptionally rare: another vcpu has fixed
             * the tables between the fault and our reading the l1e.
             * Retry and let the hardware give us the right fault next time. */
            perfc_incr(shadow_fault_fast_fail);
            SHADOW_PRINTK("fast path false alarm!\n");
            sh_trace_va(TRC_SHADOW_FALSE_FAST_PATH, va);
            return EXCRET_fault_fixed;
        }
    }

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
 page_fault_slow_path:
#endif
#endif /* SHOPT_FAST_FAULT_PATH */

    /* Detect if this page fault happened while we were already in Xen
     * doing a shadow operation.  If that happens, the only thing we can
     * do is let Xen's normal fault handlers try to fix it.  In any case,
     * a diagnostic trace of the fault will be more useful than
     * a BUG() when we try to take the lock again. */
    if ( unlikely(paging_locked_by_me(d)) )
    {
        printk(XENLOG_G_ERR "Recursive shadow fault: lock taken by %s\n",
               d->arch.paging.lock.locker_function);
        return 0;
    }

    cpl = is_hvm_domain(d) ? hvm_get_cpl(v) : (regs->ss & 3);

 rewalk:

    error_code = regs->error_code;

    /*
     * When CR4.SMAP is enabled, instructions which have a side effect of
     * accessing the system data structures (e.g. mov to %ds accessing the
     * LDT/GDT, or int $n accessing the IDT) are known as implicit supervisor
     * accesses.
     *
     * The distinction between implicit and explicit accesses form part of the
     * determination of access rights, controlling whether the access is
     * successful, or raises a #PF.
     *
     * Unfortunately, the processor throws away the implicit/explicit
     * distinction and does not provide it to the pagefault handler
     * (i.e. here.) in the #PF error code.  Therefore, we must try to
     * reconstruct the lost state so it can be fed back into our pagewalk
     * through the guest tables.
     *
     * User mode accesses are easy to reconstruct:
     *
     *   If we observe a cpl3 data fetch which was a supervisor walk, this
     *   must have been an implicit access to a system table.
     *
     * Supervisor mode accesses are not easy:
     *
     *   In principle, we could decode the instruction under %rip and have the
     *   instruction emulator tell us if there is an implicit access.
     *   However, this is racy with other vcpus updating the pagetable or
     *   rewriting the instruction stream under our feet.
     *
     *   Therefore, we do nothing.  (If anyone has a sensible suggestion for
     *   how to distinguish these cases, xen-devel@ is all ears...)
     *
     * As a result, one specific corner case will fail.  If a guest OS with
     * SMAP enabled ends up mapping a system table with user mappings, sets
     * EFLAGS.AC to allow explicit accesses to user mappings, and implicitly
     * accesses the user mapping, hardware and the shadow code will disagree
     * on whether a #PF should be raised.
     *
     * Hardware raises #PF because implicit supervisor accesses to user
     * mappings are strictly disallowed.  As we can't reconstruct the correct
     * input, the pagewalk is performed as if it were an explicit access,
     * which concludes that the access should have succeeded and the shadow
     * pagetables need modifying.  The shadow pagetables are modified (to the
     * same value), and we re-enter the guest to re-execute the instruction,
     * which causes another #PF, and the vcpu livelocks, unable to make
     * forward progress.
     *
     * In practice, this is tolerable.  No production OS will deliberately
     * construct this corner case (as doing so would mean that a system table
     * is directly accessable to userspace, and the OS is trivially rootable.)
     * If this corner case comes about accidentally, then a security-relevant
     * bug has been tickled.
     */
    if ( !(error_code & (PFEC_insn_fetch|PFEC_user_mode)) && cpl == 3 )
        error_code |= PFEC_implicit;

    /* The walk is done in a lock-free style, with some sanity check
     * postponed after grabbing paging lock later. Those delayed checks
     * will make sure no inconsistent mapping being translated into
     * shadow page table. */
    version = atomic_read(&d->arch.paging.shadow.gtable_dirty_version);
    smp_rmb();
    walk_ok = sh_walk_guest_tables(v, va, &gw, error_code);

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    regs->error_code &= ~PFEC_page_present;
    if ( gw.pfec & PFEC_page_present )
        regs->error_code |= PFEC_page_present;
#endif

    if ( !walk_ok )
    {
        perfc_incr(shadow_fault_bail_real_fault);
        SHADOW_PRINTK("not a shadow fault\n");
        sh_reset_early_unshadow(v);
        regs->error_code = gw.pfec & PFEC_arch_mask;
        goto propagate;
    }

    /* It's possible that the guest has put pagetables in memory that it has
     * already used for some special purpose (ioreq pages, or granted pages).
     * If that happens we'll have killed the guest already but it's still not
     * safe to propagate entries out of the guest PT so get out now. */
    if ( unlikely(d->is_shutting_down && d->shutdown_code == SHUTDOWN_crash) )
    {
        SHADOW_PRINTK("guest is shutting down\n");
        goto propagate;
    }

    /* What mfn is the guest trying to access? */
    gfn = guest_walk_to_gfn(&gw);
    gmfn = get_gfn(d, gfn, &p2mt);

    /*
     * p2m_mmio_dm in particular is handled further down, and hence can't be
     * short-circuited here. Furthermore, while not fitting with architectural
     * behavior, propagating #PF to the guest when a sensible shadow entry
     * can't be written is necessary. Without doing so (by installing a non-
     * present entry) we'd get back right here immediately afterwards, thus
     * preventing the guest from making further forward progress.
     */
    if ( shadow_mode_refcounts(d) &&
         !p2m_is_mmio(p2mt) &&
         (!p2m_is_any_ram(p2mt) || !mfn_valid(gmfn)) )
    {
        perfc_incr(shadow_fault_bail_bad_gfn);
        SHADOW_PRINTK("BAD gfn=%"SH_PRI_gfn" gmfn=%"PRI_mfn"\n",
                      gfn_x(gfn), mfn_x(gmfn));
        sh_reset_early_unshadow(v);
        put_gfn(d, gfn_x(gfn));
        goto propagate;
    }

#if (SHADOW_OPTIMIZATIONS & SHOPT_VIRTUAL_TLB)
    /* Remember this successful VA->GFN translation for later. */
    vtlb_insert(v, va >> PAGE_SHIFT, gfn_x(gfn),
                regs->error_code | PFEC_page_present);
#endif /* (SHADOW_OPTIMIZATIONS & SHOPT_VIRTUAL_TLB) */

    paging_lock(d);

    TRACE_CLEAR_PATH_FLAGS;

    /* Make sure there is enough free shadow memory to build a chain of
     * shadow tables. (We never allocate a top-level shadow on this path,
     * only a 32b l1, pae l1, or 64b l3+2+1. Note that while
     * SH_type_l1_shadow isn't correct in the latter case, all page
     * tables are the same size there.)
     *
     * Preallocate shadow pages *before* removing writable accesses
     * otherwhise an OOS L1 might be demoted and promoted again with
     * writable mappings. */
    if ( !shadow_prealloc(d, SH_type_l1_shadow,
                          GUEST_PAGING_LEVELS < 4
                          ? 1 : GUEST_PAGING_LEVELS - 1) )
    {
        paging_unlock(d);
        put_gfn(d, gfn_x(gfn));
        return 0;
    }

    rc = gw_remove_write_accesses(v, va, &gw);

    /* First bit set: Removed write access to a page. */
    if ( rc & GW_RMWR_FLUSHTLB )
    {
        /* Write permission removal is also a hint that other gwalks
         * overlapping with this one may be inconsistent
         */
        perfc_incr(shadow_rm_write_flush_tlb);
        smp_wmb();
        atomic_inc(&d->arch.paging.shadow.gtable_dirty_version);
        guest_flush_tlb_mask(d, d->dirty_cpumask);
    }

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    /* Second bit set: Resynced a page. Re-walk needed. */
    if ( rc & GW_RMWR_REWALK )
    {
        paging_unlock(d);
        put_gfn(d, gfn_x(gfn));
        goto rewalk;
    }
#endif /* OOS */

    if ( !shadow_check_gwalk(v, va, &gw, version) )
    {
        perfc_incr(shadow_inconsistent_gwalk);
        paging_unlock(d);
        put_gfn(d, gfn_x(gfn));
        goto rewalk;
    }

    shadow_audit_tables(v);
    sh_audit_gw(v, &gw);

    /* Acquire the shadow.  This must happen before we figure out the rights
     * for the shadow entry, since we might promote a page here. */
    ptr_sl1e = shadow_get_and_create_l1e(v, &gw, &sl1mfn, ft);
    if ( unlikely(ptr_sl1e == NULL) )
    {
        /* Couldn't get the sl1e!  Since we know the guest entries
         * are OK, this can only have been caused by a failed
         * shadow_set_l*e(), which will have crashed the guest.
         * Get out of the fault handler immediately. */
        /* Windows 7 apparently relies on the hardware to do something
         * it explicitly hasn't promised to do: load l3 values after
         * the cr3 is loaded.
         * In any case, in the PAE case, the ASSERT is not true; it can
         * happen because of actions the guest is taking. */
#if GUEST_PAGING_LEVELS == 3
        v->arch.paging.mode->update_cr3(v, false);
#else
        ASSERT(d->is_shutting_down);
#endif
        paging_unlock(d);
        put_gfn(d, gfn_x(gfn));
        sh_trace_va(TRC_SHADOW_DOMF_DYING, va);
        return 0;
    }

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    /* Always unsync when writing to L1 page tables. */
    if ( sh_mfn_is_a_page_table(gmfn)
         && ft == ft_demand_write )
        sh_unsync(v, gmfn);

    if ( unlikely(d->is_shutting_down && d->shutdown_code == SHUTDOWN_crash) )
    {
        /* We might end up with a crashed domain here if
         * sh_remove_shadows() in a previous sh_resync() call has
         * failed. We cannot safely continue since some page is still
         * OOS but not in the hash table anymore. */
        paging_unlock(d);
        put_gfn(d, gfn_x(gfn));
        return 0;
    }

    /* Final check: if someone has synced a page, it's possible that
     * our l1e is stale.  Compare the entries, and rewalk if necessary. */
    if ( shadow_check_gl1e(v, &gw)  )
    {
        perfc_incr(shadow_inconsistent_gwalk);
        paging_unlock(d);
        put_gfn(d, gfn_x(gfn));
        goto rewalk;
    }
#endif /* OOS */

    /* Calculate the shadow entry and write it */
    l1e_propagate_from_guest(v, gw.l1e, gmfn, &sl1e, ft, p2mt);
    shadow_set_l1e(d, ptr_sl1e, sl1e, p2mt, sl1mfn);

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    if ( mfn_valid(gw.l1mfn)
         && mfn_is_out_of_sync(gw.l1mfn) )
    {
        /* Update the OOS snapshot. */
        mfn_t snpmfn = oos_snapshot_lookup(d, gw.l1mfn);
        guest_l1e_t *snp;

        ASSERT(mfn_valid(snpmfn));

        snp = map_domain_page(snpmfn);
        snp[guest_l1_table_offset(va)] = gw.l1e;
        unmap_domain_page(snp);
    }
#endif /* OOS */

#if SHADOW_OPTIMIZATIONS & SHOPT_PREFETCH
    /* Prefetch some more shadow entries */
    sh_prefetch(v, &gw, ptr_sl1e, sl1mfn);
#endif

    /* Need to emulate accesses to page tables */
    if ( sh_mfn_is_a_page_table(gmfn)
#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
         /* Unless they've been allowed to go out of sync with their
            shadows and we don't need to unshadow it. */
         && !(mfn_is_out_of_sync(gmfn)
              && !(regs->error_code & PFEC_user_mode))
#endif
         && (ft == ft_demand_write) )
    {
        perfc_incr(shadow_fault_emulate_write);
        goto emulate;
    }

#ifdef CONFIG_HVM

    /* Need to hand off device-model MMIO to the device model */
    if ( p2mt == p2m_mmio_dm )
    {
        ASSERT(is_hvm_vcpu(v));

        sh_audit_gw(v, &gw);
        gpa = guest_walk_to_gpa(&gw);
        SHADOW_PRINTK("mmio %#"PRIpaddr"\n", gpa);
        shadow_audit_tables(v);
        sh_reset_early_unshadow(v);

        paging_unlock(d);
        put_gfn(d, gfn_x(gfn));

        perfc_incr(shadow_fault_mmio);
        sh_trace_va(TRC_SHADOW_MMIO, va);

        return handle_mmio_with_translation(va, gpa >> PAGE_SHIFT, access)
               ? EXCRET_fault_fixed : 0;
    }

    /* Ignore attempts to write to read-only memory. */
    if ( p2m_is_readonly(p2mt) && (ft == ft_demand_write) )
        goto emulate_readonly; /* skip over the instruction */

    /* In HVM guests, we force CR0.WP always to be set, so that the
     * pagetables are always write-protected.  If the guest thinks
     * CR0.WP is clear, we must emulate faulting supervisor writes to
     * allow the guest to write through read-only PTEs.  Emulate if the
     * fault was a non-user write to a present page.  */
    if ( is_hvm_domain(d)
         && unlikely(!hvm_wp_enabled(v))
         && regs->error_code == (PFEC_write_access|PFEC_page_present)
         && mfn_valid(gmfn) )
    {
        perfc_incr(shadow_fault_emulate_wp);
        goto emulate;
    }

#endif /* CONFIG_HVM */

    perfc_incr(shadow_fault_fixed);
    d->arch.paging.log_dirty.fault_count++;
    sh_reset_early_unshadow(v);

    sh_trace_gl1e_va(TRC_SHADOW_FIXUP, gw.l1e, va);
 done: __maybe_unused;
    sh_audit_gw(v, &gw);
    SHADOW_PRINTK("fixed\n");
    shadow_audit_tables(v);
    paging_unlock(d);
    put_gfn(d, gfn_x(gfn));
    return EXCRET_fault_fixed;

 emulate:
    if ( !shadow_mode_refcounts(d) )
        goto not_a_shadow_fault;

#ifdef CONFIG_HVM
    /*
     * We do not emulate user writes. Instead we use them as a hint that the
     * page is no longer a page table. This behaviour differs from native, but
     * it seems very unlikely that any OS grants user access to page tables.
     */
    if ( (regs->error_code & PFEC_user_mode) )
    {
        SHADOW_PRINTK("user-mode fault to PT, unshadowing mfn %#lx\n",
                      mfn_x(gmfn));
        perfc_incr(shadow_fault_emulate_failed);
        shadow_remove_all_shadows(d, gmfn);
        sh_trace_gfn_va(TRC_SHADOW_EMULATE_UNSHADOW_USER, gfn, va);
        goto done;
    }

    /*
     * Write from userspace to ro-mem needs to jump here to avoid getting
     * caught by user-mode page-table check above.
     */
 emulate_readonly:
    /*
     * Unshadow if we are writing to a toplevel pagetable that is
     * flagged as a dying process, and that is not currently used.
     */
    if ( sh_mfn_is_a_page_table(gmfn) && mfn_to_page(gmfn)->pagetable_dying )
    {
        int used = 0;
        struct vcpu *tmp;
        for_each_vcpu(d, tmp)
        {
#if GUEST_PAGING_LEVELS == 3
            unsigned int i;

            for_each_shadow_table(tmp, i)
            {
                mfn_t smfn = pagetable_get_mfn(
                                 tmp->arch.paging.shadow.shadow_table[i]);

                if ( mfn_x(smfn) )
                {
                    used |= (mfn_to_page(smfn)->v.sh.back == mfn_x(gmfn));

                    if ( used )
                        break;
                }
            }
#else /* 32 or 64 */
            used = mfn_eq(pagetable_get_mfn(tmp->arch.guest_table), gmfn);
#endif
            if ( used )
                break;
        }

        if ( !used )
            sh_remove_shadows(d, gmfn, 1 /* fast */, 0 /* can fail */);
    }

    /*
     * We don't need to hold the lock for the whole emulation; we will
     * take it again when we write to the pagetables.
     */
    sh_audit_gw(v, &gw);
    shadow_audit_tables(v);
    paging_unlock(d);
    put_gfn(d, gfn_x(gfn));

    this_cpu(trace_emulate_write_val) = 0;

#if SHADOW_OPTIMIZATIONS & SHOPT_FAST_EMULATION
 early_emulation:
#endif
    /*
     * If we are in the middle of injecting an exception or interrupt then
     * we should not emulate: the fault is a side effect of the processor
     * trying to deliver the exception (e.g. IDT/GDT accesses, pushing the
     * exception frame onto the stack).  Furthermore it is almost
     * certainly the case the handler stack is currently considered to be
     * a page table, so we should unshadow the faulting page before
     * exiting.
     */
    if ( unlikely(hvm_event_pending(v)) )
    {
#if SHADOW_OPTIMIZATIONS & SHOPT_FAST_EMULATION
        if ( fast_emul )
        {
            perfc_incr(shadow_fault_fast_emulate_fail);
            v->arch.paging.last_write_emul_ok = 0;
        }
#endif
        shadow_remove_all_shadows(d, gmfn);
        sh_trace_gfn_va(TRC_SHADOW_EMULATE_UNSHADOW_EVTINJ, gfn, va);
        return EXCRET_fault_fixed;
    }

    SHADOW_PRINTK("emulate: eip=%#lx esp=%#lx\n", regs->rip, regs->rsp);

    emul_ops = shadow_init_emulation(&emul_ctxt, regs, GUEST_PTE_SIZE);

    r = x86_emulate(&emul_ctxt.ctxt, emul_ops);
    if ( r == X86EMUL_EXCEPTION )
    {
        /*
         * This emulation covers writes to shadow pagetables.  We tolerate #PF
         * (from accesses spanning pages, concurrent paging updated from
         * vcpus, etc) and #GP[0]/#SS[0] (from segmentation errors).  Anything
         * else is an emulation bug, or a guest playing with the instruction
         * stream under Xen's feet.
         */
        if ( emul_ctxt.ctxt.event.type == X86_ET_HW_EXC &&
             ((emul_ctxt.ctxt.event.vector == X86_EXC_PF) ||
              (((emul_ctxt.ctxt.event.vector == X86_EXC_GP) ||
                (emul_ctxt.ctxt.event.vector == X86_EXC_SS)) &&
               emul_ctxt.ctxt.event.error_code == 0)) )
            hvm_inject_event(&emul_ctxt.ctxt.event);
        else
        {
            SHADOW_PRINTK(
                "Unexpected event (type %u, vector %#x) from emulation\n",
                emul_ctxt.ctxt.event.type, emul_ctxt.ctxt.event.vector);
            r = X86EMUL_UNHANDLEABLE;
        }
    }

    /*
     * NB. We do not unshadow on X86EMUL_EXCEPTION. It's not clear that it
     * would be a good unshadow hint. If we *do* decide to unshadow-on-fault
     * then it must be 'failable': we cannot require the unshadow to succeed.
     */
    if ( r == X86EMUL_UNHANDLEABLE || r == X86EMUL_UNIMPLEMENTED )
    {
        perfc_incr(shadow_fault_emulate_failed);
#if SHADOW_OPTIMIZATIONS & SHOPT_FAST_EMULATION
        if ( fast_emul )
        {
            perfc_incr(shadow_fault_fast_emulate_fail);
            v->arch.paging.last_write_emul_ok = 0;
        }
#endif
        SHADOW_PRINTK("emulator failure (rc=%d), unshadowing mfn %#lx\n",
                       r, mfn_x(gmfn));
        /* If this is actually a page table, then we have a bug, and need
         * to support more operations in the emulator.  More likely,
         * though, this is a hint that this page should not be shadowed. */
        shadow_remove_all_shadows(d, gmfn);

        sh_trace_gfn_va(TRC_SHADOW_EMULATE_UNSHADOW_UNHANDLED, gfn, va);
        goto emulate_done;
    }

#if SHADOW_OPTIMIZATIONS & SHOPT_FAST_EMULATION
    /* Record successfully emulated information as heuristics to next
     * fault on same frame for acceleration. But be careful to verify
     * its attribute still as page table, or else unshadow triggered
     * in write emulation normally requires a re-sync with guest page
     * table to recover r/w permission. Incorrect record for such case
     * will cause unexpected more shadow faults due to propagation is
     * skipped.
     */
    if ( (r == X86EMUL_OKAY) && sh_mfn_is_a_page_table(gmfn) )
    {
        if ( !fast_emul )
        {
            v->arch.paging.shadow.last_emulated_frame = va >> PAGE_SHIFT;
            v->arch.paging.shadow.last_emulated_mfn = mfn_x(gmfn);
            v->arch.paging.last_write_emul_ok = 1;
        }
    }
    else if ( fast_emul )
        v->arch.paging.last_write_emul_ok = 0;
#endif

    if ( emul_ctxt.ctxt.retire.singlestep )
        hvm_inject_hw_exception(X86_EXC_DB, X86_EVENT_NO_EC);

#if GUEST_PAGING_LEVELS == 3 /* PAE guest */
    /*
     * If there are no pending actions, emulate up to four extra instructions
     * in the hope of catching the "second half" of a 64-bit pagetable write.
     */
    if ( r == X86EMUL_OKAY && !emul_ctxt.ctxt.retire.raw )
    {
        int i, emulation_count=0;
        this_cpu(trace_emulate_initial_va) = va;

        for ( i = 0 ; i < 4 ; i++ )
        {
            shadow_continue_emulation(&emul_ctxt, regs);
            v->arch.paging.last_write_was_pt = 0;
            r = x86_emulate(&emul_ctxt.ctxt, emul_ops);

            /*
             * Only continue the search for the second half if there are no
             * exceptions or pending actions.  Otherwise, give up and re-enter
             * the guest.
             */
            if ( r == X86EMUL_OKAY && !emul_ctxt.ctxt.retire.raw )
            {
                emulation_count++;
                if ( v->arch.paging.last_write_was_pt )
                {
                    perfc_incr(shadow_em_ex_pt);
                    TRACE_SHADOW_PATH_FLAG(TRCE_SFLAG_EMULATION_2ND_PT_WRITTEN);
                    break; /* Don't emulate past the other half of the write */
                }
                else
                    perfc_incr(shadow_em_ex_non_pt);
            }
            else
            {
                perfc_incr(shadow_em_ex_fail);
                TRACE_SHADOW_PATH_FLAG(TRCE_SFLAG_EMULATION_LAST_FAILED);

                if ( emul_ctxt.ctxt.retire.singlestep )
                    hvm_inject_hw_exception(X86_EXC_DB, X86_EVENT_NO_EC);

                break; /* Don't emulate again if we failed! */
            }
        }
        this_cpu(trace_extra_emulation_count)=emulation_count;
    }
#endif /* PAE guest */

    sh_trace_emulate(gw.l1e, va);
 emulate_done:
    SHADOW_PRINTK("emulated\n");
    return EXCRET_fault_fixed;
#endif /* CONFIG_HVM */

 not_a_shadow_fault:
    sh_audit_gw(v, &gw);
    SHADOW_PRINTK("not a shadow fault\n");
    shadow_audit_tables(v);
    sh_reset_early_unshadow(v);
    paging_unlock(d);
    put_gfn(d, gfn_x(gfn));

propagate:
    sh_trace_gl1e_va(TRC_SHADOW_NOT_SHADOW, gw.l1e, va);

    return 0;
}


/*
 * Called when the guest requests an invlpg.  Returns true if the invlpg
 * instruction should be issued on the hardware, or false if it's safe not
 * to do so.
 */
static bool cf_check sh_invlpg(struct vcpu *v, unsigned long linear)
{
    mfn_t sl1mfn;
    shadow_l2e_t sl2e;

    perfc_incr(shadow_invlpg);

#if (SHADOW_OPTIMIZATIONS & SHOPT_VIRTUAL_TLB)
    /* No longer safe to use cached gva->gfn translations */
    vtlb_flush(v);
#endif

#if SHADOW_OPTIMIZATIONS & SHOPT_FAST_EMULATION
    v->arch.paging.last_write_emul_ok = 0;
#endif

    /* First check that we can safely read the shadow l2e.  SMP/PAE linux can
     * run as high as 6% of invlpg calls where we haven't shadowed the l2
     * yet. */
#if SHADOW_PAGING_LEVELS == 4
    {
        shadow_l3e_t sl3e;
        if ( !(shadow_l4e_get_flags(
                   sh_linear_l4_table(v)[shadow_l4_linear_offset(linear)])
               & _PAGE_PRESENT) )
            return false;
        /* This must still be a copy-from-unsafe because we don't have the
         * paging lock, and the higher-level shadows might disappear
         * under our feet. */
        if ( get_unsafe(sl3e,
                        (sh_linear_l3_table(v) +
                         shadow_l3_linear_offset(linear))) != 0 )
        {
            perfc_incr(shadow_invlpg_fault);
            return false;
        }
        if ( !(shadow_l3e_get_flags(sl3e) & _PAGE_PRESENT) )
            return false;
    }
#elif !defined(CONFIG_HVM)
    return false;
#else /* SHADOW_PAGING_LEVELS == 3 */
    if ( !(l3e_get_flags(v->arch.paging.shadow.l3table[shadow_l3_linear_offset(linear)])
           & _PAGE_PRESENT) )
        // no need to flush anything if there's no SL2...
        return false;
#endif

    /* This must still be a copy-from-unsafe because we don't have the shadow
     * lock, and the higher-level shadows might disappear under our feet. */
    if ( get_unsafe(sl2e,
                    (sh_linear_l2_table(v) +
                     shadow_l2_linear_offset(linear))) != 0 )
    {
        perfc_incr(shadow_invlpg_fault);
        return false;
    }

    // If there's nothing shadowed for this particular sl2e, then
    // there is no need to do an invlpg, either...
    //
    if ( !(shadow_l2e_get_flags(sl2e) & _PAGE_PRESENT) )
        return false;

    // Check to see if the SL2 is a splintered superpage...
    // If so, then we'll need to flush the entire TLB (because that's
    // easier than invalidating all of the individual 4K pages).
    //
    sl1mfn = shadow_l2e_get_mfn(sl2e);
    if ( mfn_to_page(sl1mfn)->u.sh.type
         == SH_type_fl1_shadow )
    {
        sh_flush_local(v->domain);
        return false;
    }

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    /* Check to see if the SL1 is out of sync. */
    {
        struct domain *d = v->domain;
        mfn_t gl1mfn = backpointer(mfn_to_page(sl1mfn));
        struct page_info *pg = mfn_to_page(gl1mfn);
        if ( mfn_valid(gl1mfn)
             && page_is_out_of_sync(pg) )
        {
            /* The test above may give false positives, since we don't
             * hold the paging lock yet.  Check again with the lock held. */
            paging_lock(d);

            /* This must still be a copy-from-unsafe because we didn't
             * have the paging lock last time we checked, and the
             * higher-level shadows might have disappeared under our
             * feet. */
            if ( get_unsafe(sl2e,
                            (sh_linear_l2_table(v) +
                             shadow_l2_linear_offset(linear))) != 0 )
            {
                perfc_incr(shadow_invlpg_fault);
                paging_unlock(d);
                return false;
            }

            if ( !(shadow_l2e_get_flags(sl2e) & _PAGE_PRESENT) )
            {
                paging_unlock(d);
                return false;
            }

            sl1mfn = shadow_l2e_get_mfn(sl2e);
            gl1mfn = backpointer(mfn_to_page(sl1mfn));
            pg = mfn_to_page(gl1mfn);

            if ( likely(sh_mfn_is_a_page_table(gl1mfn)
                        && page_is_out_of_sync(pg) ) )
            {
                shadow_l1e_t *sl1;
                sl1 = sh_linear_l1_table(v) + shadow_l1_linear_offset(linear);
                /* Remove the shadow entry that maps this VA */
                shadow_set_l1e(d, sl1, shadow_l1e_empty(), p2m_invalid, sl1mfn);
            }
            paging_unlock(d);
            /* Need the invlpg, to pick up the disappeareance of the sl1e */
            return true;
        }
    }
#endif

    return true;
}

#ifdef CONFIG_HVM

static unsigned long cf_check sh_gva_to_gfn(
    struct vcpu *v, struct p2m_domain *p2m, unsigned long va, uint32_t *pfec)
/* Called to translate a guest virtual address to what the *guest*
 * pagetables would map it to. */
{
    walk_t gw;
    gfn_t gfn;
    bool walk_ok;

#if (SHADOW_OPTIMIZATIONS & SHOPT_VIRTUAL_TLB)
    /* Check the vTLB cache first */
    unsigned long vtlb_gfn = vtlb_lookup(v, va, *pfec);
    if ( vtlb_gfn != gfn_x(INVALID_GFN) )
        return vtlb_gfn;
#endif /* (SHADOW_OPTIMIZATIONS & SHOPT_VIRTUAL_TLB) */

    if ( !(walk_ok = sh_walk_guest_tables(v, va, &gw, *pfec)) )
    {
        *pfec = gw.pfec;
        return gfn_x(INVALID_GFN);
    }
    gfn = guest_walk_to_gfn(&gw);

#if (SHADOW_OPTIMIZATIONS & SHOPT_VIRTUAL_TLB)
    /* Remember this successful VA->GFN translation for later. */
    vtlb_insert(v, va >> PAGE_SHIFT, gfn_x(gfn), *pfec);
#endif /* (SHADOW_OPTIMIZATIONS & SHOPT_VIRTUAL_TLB) */

    return gfn_x(gfn);
}

#endif /* CONFIG_HVM */

static inline void
sh_update_linear_entries(struct vcpu *v)
/* Sync up all the linear mappings for this vcpu's pagetables */
{
    struct domain *d = v->domain;

    /*
     * Linear pagetables in HVM guests
     * -------------------------------
     *
     * For HVM guests, the linear pagetables are installed in the monitor
     * tables (since we can't put them in the shadow).  Shadow linear
     * pagetables, which map the shadows, are at SH_LINEAR_PT_VIRT_START,
     * and we use the linear pagetable slot at LINEAR_PT_VIRT_START for
     * a linear pagetable of the monitor tables themselves.  We have
     * the same issue of having to re-copy PAE l3 entries whevever we use
     * PAE shadows.
     *
     * Because HVM guests run on the same monitor tables regardless of the
     * shadow tables in use, the linear mapping of the shadow tables has to
     * be updated every time v->arch.paging.shadow.shadow_table changes.
     */

    /* Don't try to update the monitor table if it doesn't exist */
    if ( !shadow_mode_external(d) ||
         pagetable_get_pfn(v->arch.hvm.monitor_table) == 0 )
        return;

#if !defined(CONFIG_HVM)
    return;
#elif SHADOW_PAGING_LEVELS == 4

    /* For HVM, just need to update the l4e that points to the shadow l4. */

    /* Use the linear map if we can; otherwise make a new mapping */
    if ( v == current )
    {
        __linear_l4_table[l4_linear_offset(SH_LINEAR_PT_VIRT_START)] =
            l4e_from_pfn(
                pagetable_get_pfn(v->arch.paging.shadow.shadow_table[0]),
                __PAGE_HYPERVISOR_RW);
    }
    else
    {
        l4_pgentry_t *ml4e;

        ml4e = map_domain_page(pagetable_get_mfn(v->arch.hvm.monitor_table));
        ml4e[l4_table_offset(SH_LINEAR_PT_VIRT_START)] =
            l4e_from_pfn(
                pagetable_get_pfn(v->arch.paging.shadow.shadow_table[0]),
                __PAGE_HYPERVISOR_RW);
        unmap_domain_page(ml4e);
    }

#elif SHADOW_PAGING_LEVELS == 3

    /*
     * HVM: To give ourselves a linear map of the  shadows, we need to
     * extend a PAE shadow to 4 levels.  We do this by  having a monitor
     * l3 in slot 0 of the monitor l4 table, and  copying the PAE l3
     * entries into it.  Then, by having the monitor l4e for shadow
     * pagetables also point to the monitor l4, we can use it to access
     * the shadows.
     */

    {
        /* Install copies of the shadow l3es into the monitor l2 table
         * that maps SH_LINEAR_PT_VIRT_START. */
        shadow_l3e_t *sl3e;
        l2_pgentry_t *ml2e;
        int i;

        /* Use linear mappings if we can; otherwise make new mappings */
        if ( v == current )
            ml2e = __linear_l2_table
                + l2_linear_offset(SH_LINEAR_PT_VIRT_START);
        else
        {
            mfn_t l3mfn, l2mfn;
            l4_pgentry_t *ml4e;
            l3_pgentry_t *ml3e;
            int linear_slot = shadow_l4_table_offset(SH_LINEAR_PT_VIRT_START);
            ml4e = map_domain_page(pagetable_get_mfn(v->arch.hvm.monitor_table));

            ASSERT(l4e_get_flags(ml4e[linear_slot]) & _PAGE_PRESENT);
            l3mfn = l4e_get_mfn(ml4e[linear_slot]);
            ml3e = map_domain_page(l3mfn);
            unmap_domain_page(ml4e);

            ASSERT(l3e_get_flags(ml3e[0]) & _PAGE_PRESENT);
            l2mfn = l3e_get_mfn(ml3e[0]);
            ml2e = map_domain_page(l2mfn);
            unmap_domain_page(ml3e);
        }

        /* Shadow l3 tables are made up by sh_update_cr3 */
        sl3e = v->arch.paging.shadow.l3table;

        for ( i = 0; i < SHADOW_L3_PAGETABLE_ENTRIES; i++ )
        {
            ml2e[i] =
                (shadow_l3e_get_flags(sl3e[i]) & _PAGE_PRESENT)
                ? l2e_from_mfn(shadow_l3e_get_mfn(sl3e[i]),
                               __PAGE_HYPERVISOR_RW)
                : l2e_empty();
        }

        if ( v != current )
            unmap_domain_page(ml2e);
    }

#else
#error this should not happen
#endif

    /*
     * Having modified the linear pagetable mapping, flush local host TLBs.
     * This was not needed when vmenter/vmexit always had the side effect of
     * flushing host TLBs but, with ASIDs, it is possible to finish this CR3
     * update, vmenter the guest, vmexit due to a page fault, without an
     * intervening host TLB flush. Then the page fault code could use the
     * linear pagetable to read a top-level shadow page table entry. But,
     * without this change, it would fetch the wrong value due to a stale TLB.
     */
    sh_flush_local(d);
}

static pagetable_t cf_check sh_update_cr3(struct vcpu *v, bool noflush)
/* Updates vcpu->arch.cr3 after the guest has changed CR3.
 * Paravirtual guests should set v->arch.guest_table (and guest_table_user,
 * if appropriate).
 * HVM guests should also make sure hvm_get_guest_cntl_reg(v, 3) works;
 * this function will call hvm_update_guest_cr(v, 3) to tell them where the
 * shadow tables are.
 */
{
    struct domain *d = v->domain;
    mfn_t gmfn;
    pagetable_t old_entry = pagetable_null();
#if GUEST_PAGING_LEVELS == 3
    const guest_l3e_t *gl3e;
    unsigned int i, guest_idx;
#endif

    /* Don't do anything on an uninitialised vcpu */
    if ( !is_hvm_domain(d) && !v->is_initialised )
    {
        ASSERT(v->arch.cr3 == 0);
        return old_entry;
    }

    /*
     * This is used externally (with the paging lock not taken) and internally
     * by the shadow code (with the lock already taken).
     */
    paging_lock_recursive(v->domain);

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    /* Need to resync all the shadow entries on a TLB flush.  Resync
     * current vcpus OOS pages before switching to the new shadow
     * tables so that the VA hint is still valid.  */
    shadow_resync_current_vcpu(v);
#endif

    ASSERT(paging_locked_by_me(v->domain));
    ASSERT(v->arch.paging.mode);

    ////
    //// vcpu->arch.guest_table is already set
    ////

#ifndef NDEBUG
    /* Double-check that the HVM code has sent us a sane guest_table */
    if ( is_hvm_domain(d) )
    {
        ASSERT(shadow_mode_external(d));
        if ( hvm_paging_enabled(v) )
            ASSERT(pagetable_get_pfn(v->arch.guest_table));
        else
            ASSERT(v->arch.guest_table.pfn
                   == d->arch.paging.shadow.unpaged_pagetable.pfn);
    }
#endif

    SHADOW_PRINTK("%pv guest_table=%"PRI_mfn"\n",
                  v, (unsigned long)pagetable_get_pfn(v->arch.guest_table));

#if GUEST_PAGING_LEVELS == 4
    if ( !(v->arch.flags & TF_kernel_mode) )
        gmfn = pagetable_get_mfn(v->arch.guest_table_user);
    else
#endif
        gmfn = pagetable_get_mfn(v->arch.guest_table);

#if GUEST_PAGING_LEVELS == 3
    /*
     * On PAE guests we don't use a mapping of the guest's own top-level
     * table.  We cache the current state of that table and shadow that,
     * until the next CR3 write makes us refresh our cache.
     */
    ASSERT(shadow_mode_external(d));

    /*
     * Find where in the page the l3 table is, but ignore the low 2 bits of
     * guest_idx -- they are really just cache control.
     */
    guest_idx = guest_index((void *)v->arch.hvm.guest_cr[3]) & ~3;

    gl3e = ((guest_l3e_t *)map_domain_page(gmfn)) + guest_idx;
    for ( i = 0; i < 4 ; i++ )
        v->arch.paging.shadow.gl3e[i] = gl3e[i];
    unmap_domain_page(gl3e);
#endif


    ////
    //// vcpu->arch.paging.shadow.shadow_table[]
    ////

    /* We revoke write access to the new guest toplevel page(s) before we
     * replace the old shadow pagetable(s), so that we can safely use the
     * (old) shadow linear maps in the writeable mapping heuristics. */
#if GUEST_PAGING_LEVELS == 4
    if ( sh_remove_write_access(d, gmfn, 4, 0) != 0 )
        guest_flush_tlb_mask(d, d->dirty_cpumask);
    old_entry = sh_set_toplevel_shadow(v, 0, gmfn, SH_type_l4_shadow,
                                       sh_make_shadow);
    if ( unlikely(pagetable_is_null(v->arch.paging.shadow.shadow_table[0])) )
    {
        ASSERT(d->is_dying || d->is_shutting_down);
        return old_entry;
    }
    if ( !shadow_mode_external(d) && !is_pv_32bit_domain(d) )
    {
        mfn_t smfn = pagetable_get_mfn(v->arch.paging.shadow.shadow_table[0]);

        if ( !(v->arch.flags & TF_kernel_mode) && VM_ASSIST(d, m2p_strict) )
            zap_ro_mpt(smfn);
        else if ( (v->arch.flags & TF_kernel_mode) &&
                  !VM_ASSIST(d, m2p_strict) )
            fill_ro_mpt(smfn);
    }
#elif GUEST_PAGING_LEVELS == 3
    /* PAE guests have four shadow_table entries, based on the
     * current values of the guest's four l3es. */
    {
        int flush = 0;
        gfn_t gl2gfn;
        mfn_t gl2mfn;
        p2m_type_t p2mt;

        gl3e = v->arch.paging.shadow.gl3e;

        /* First, make all four entries read-only. */
        for ( i = 0; i < 4; i++ )
        {
            if ( guest_l3e_get_flags(gl3e[i]) & _PAGE_PRESENT )
            {
                gl2gfn = guest_l3e_get_gfn(gl3e[i]);
                gl2mfn = get_gfn_query_unlocked(d, gfn_x(gl2gfn), &p2mt);
                if ( p2m_is_ram(p2mt) )
                    flush |= sh_remove_write_access(d, gl2mfn, 2, 0);
            }
        }
        if ( flush )
            guest_flush_tlb_mask(d, d->dirty_cpumask);
        /* Now install the new shadows. */
        for ( i = 0; i < 4; i++ )
        {
            if ( guest_l3e_get_flags(gl3e[i]) & _PAGE_PRESENT )
            {
                gl2gfn = guest_l3e_get_gfn(gl3e[i]);
                gl2mfn = get_gfn_query_unlocked(d, gfn_x(gl2gfn), &p2mt);
                if ( p2m_is_ram(p2mt) )
                    old_entry = sh_set_toplevel_shadow(v, i, gl2mfn,
                                                       SH_type_l2_shadow,
                                                       sh_make_shadow);
                else
                    old_entry = sh_set_toplevel_shadow(v, i, INVALID_MFN, 0,
                                                       sh_make_shadow);
            }
            else
                old_entry = sh_set_toplevel_shadow(v, i, INVALID_MFN, 0,
                                                   sh_make_shadow);

            ASSERT(pagetable_is_null(old_entry));
        }
    }
#elif GUEST_PAGING_LEVELS == 2
    if ( sh_remove_write_access(d, gmfn, 2, 0) != 0 )
        guest_flush_tlb_mask(d, d->dirty_cpumask);
    old_entry = sh_set_toplevel_shadow(v, 0, gmfn, SH_type_l2_shadow,
                                       sh_make_shadow);
    ASSERT(pagetable_is_null(old_entry));
    if ( unlikely(pagetable_is_null(v->arch.paging.shadow.shadow_table[0])) )
    {
        ASSERT(d->is_dying || d->is_shutting_down);
        return old_entry;
    }
#else
#error This should never happen
#endif

    ///
    /// v->arch.paging.shadow.l3table
    ///
#if SHADOW_PAGING_LEVELS == 3
        {
            mfn_t smfn = pagetable_get_mfn(v->arch.paging.shadow.shadow_table[0]);
            unsigned int i;

            for_each_shadow_table(v, i)
            {
#if GUEST_PAGING_LEVELS == 2
                /* 2-on-3: make a PAE l3 that points at the four-page l2 */
                if ( i != 0 )
                    smfn = sh_next_page(smfn);
#else
                /* 3-on-3: make a PAE l3 that points at the four l2 pages */
                smfn = pagetable_get_mfn(v->arch.paging.shadow.shadow_table[i]);
#endif
                v->arch.paging.shadow.l3table[i] =
                    (mfn_x(smfn) == 0)
                    ? shadow_l3e_empty()
                    : shadow_l3e_from_mfn(smfn, _PAGE_PRESENT);
            }
        }
#endif /* SHADOW_PAGING_LEVELS == 3 */

    ///
    /// v->arch.cr3
    ///
    if ( shadow_mode_external(d) )
    {
        make_cr3(v, pagetable_get_mfn(v->arch.hvm.monitor_table));
    }
#if SHADOW_PAGING_LEVELS == 4
    else // not shadow_mode_external...
    {
        /* We don't support PV except guest == shadow == config levels */
        BUILD_BUG_ON(GUEST_PAGING_LEVELS != SHADOW_PAGING_LEVELS);
        /* Just use the shadow top-level directly */
        make_cr3(v, pagetable_get_mfn(v->arch.paging.shadow.shadow_table[0]));
    }
#endif

    ///
    /// v->arch.hvm.hw_cr[3]
    ///
    if ( shadow_mode_external(d) )
    {
        ASSERT(is_hvm_domain(d));
#if SHADOW_PAGING_LEVELS == 3
        /* 2-on-3 or 3-on-3: Use the PAE shadow l3 table we just fabricated */
        v->arch.hvm.hw_cr[3] = virt_to_maddr(&v->arch.paging.shadow.l3table);
#else
        /* 4-on-4: Just use the shadow top-level directly */
        v->arch.hvm.hw_cr[3] =
            pagetable_get_paddr(v->arch.paging.shadow.shadow_table[0]);
#endif
        hvm_update_guest_cr3(v, noflush);
    }

    /* Fix up the linear pagetable mappings */
    sh_update_linear_entries(v);

#if (SHADOW_OPTIMIZATIONS & SHOPT_VIRTUAL_TLB)
    /* No longer safe to use cached gva->gfn translations */
    vtlb_flush(v);
#endif

#if SHADOW_OPTIMIZATIONS & SHOPT_FAST_EMULATION
    v->arch.paging.last_write_emul_ok = 0;
#endif

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    /* Need to resync all the shadow entries on a TLB flush. We only
     * update the shadows, leaving the pages out of sync. Also, we try
     * to skip synchronization of shadows not mapped in the new
     * tables. */
    shadow_sync_other_vcpus(v);
#endif

    paging_unlock(v->domain);

    return old_entry;
}


/**************************************************************************/
/* Functions to revoke guest rights */

#if SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC
int sh_rm_write_access_from_sl1p(struct domain *d, mfn_t gmfn,
                                 mfn_t smfn, unsigned long off)
{
#ifdef CONFIG_HVM
    struct vcpu *curr = current;
#endif
    int r;
    shadow_l1e_t *sl1p, sl1e;
    struct page_info *sp;

    ASSERT(mfn_valid(gmfn));
    ASSERT(mfn_valid(smfn));

#ifdef CONFIG_HVM
    /* Remember if we've been told that this process is being torn down */
    if ( curr->domain == d && is_hvm_domain(d) )
        curr->arch.paging.shadow.pagetable_dying
            = mfn_to_page(gmfn)->pagetable_dying;
#endif

    sp = mfn_to_page(smfn);

    if ( ((sp->count_info & PGC_count_mask) != 0)
         || (sp->u.sh.type != SH_type_l1_shadow
             && sp->u.sh.type != SH_type_fl1_shadow) )
        goto fail;

    sl1p = map_domain_page(smfn);
    sl1p += off;
    sl1e = *sl1p;
    if ( ((shadow_l1e_get_flags(sl1e) & (_PAGE_PRESENT|_PAGE_RW))
          != (_PAGE_PRESENT|_PAGE_RW))
         || !mfn_eq(shadow_l1e_get_mfn(sl1e), gmfn) )
    {
        unmap_domain_page(sl1p);
        goto fail;
    }

    /* Found it!  Need to remove its write permissions. */
    sl1e = shadow_l1e_remove_flags(sl1e, _PAGE_RW);
    r = shadow_set_l1e(d, sl1p, sl1e, p2m_ram_rw, smfn);
    ASSERT( !(r & SHADOW_SET_ERROR) );

    unmap_domain_page(sl1p);
    perfc_incr(shadow_writeable_h_7);
    return 1;

 fail:
    perfc_incr(shadow_writeable_h_8);
    return 0;
}
#endif /* OOS */

#if defined(CONFIG_HVM) && (SHADOW_OPTIMIZATIONS & SHOPT_WRITABLE_HEURISTIC)
static int cf_check sh_guess_wrmap(
    struct vcpu *v, unsigned long vaddr, mfn_t gmfn)
/* Look up this vaddr in the current shadow and see if it's a writeable
 * mapping of this gmfn.  If so, remove it.  Returns 1 if it worked. */
{
    struct domain *d = v->domain;
    shadow_l1e_t sl1e, *sl1p;
    shadow_l2e_t *sl2p;
    shadow_l3e_t *sl3p;
#if SHADOW_PAGING_LEVELS >= 4
    shadow_l4e_t *sl4p;
#endif
    mfn_t sl1mfn;
    int r;

    /* Carefully look in the shadow linear map for the l1e we expect */
#if SHADOW_PAGING_LEVELS >= 4
    /*
     * Non-external guests (i.e. PV) have a SHADOW_LINEAR mapping from the
     * moment their shadows are created.  External guests (i.e. HVM) may not,
     * but always have a regular linear mapping, which we can use to observe
     * whether a SHADOW_LINEAR mapping is present.
     */
    if ( paging_mode_external(d) )
    {
        sl4p =  __linear_l4_table + l4_linear_offset(SH_LINEAR_PT_VIRT_START);
        if ( !(shadow_l4e_get_flags(*sl4p) & _PAGE_PRESENT) )
            return 0;
    }
    sl4p = sh_linear_l4_table(v) + shadow_l4_linear_offset(vaddr);
    if ( !(shadow_l4e_get_flags(*sl4p) & _PAGE_PRESENT) )
        return 0;
    sl3p = sh_linear_l3_table(v) + shadow_l3_linear_offset(vaddr);
    if ( !(shadow_l3e_get_flags(*sl3p) & _PAGE_PRESENT) )
        return 0;
#else /* SHADOW_PAGING_LEVELS == 3 */
    sl3p = ((shadow_l3e_t *) v->arch.paging.shadow.l3table)
        + shadow_l3_linear_offset(vaddr);
    if ( !(shadow_l3e_get_flags(*sl3p) & _PAGE_PRESENT) )
        return 0;
#endif
    sl2p = sh_linear_l2_table(v) + shadow_l2_linear_offset(vaddr);
    if ( !(shadow_l2e_get_flags(*sl2p) & _PAGE_PRESENT) )
        return 0;
    sl1p = sh_linear_l1_table(v) + shadow_l1_linear_offset(vaddr);
    sl1e = *sl1p;
    if ( ((shadow_l1e_get_flags(sl1e) & (_PAGE_PRESENT|_PAGE_RW))
          != (_PAGE_PRESENT|_PAGE_RW))
         || !mfn_eq(shadow_l1e_get_mfn(sl1e), gmfn) )
        return 0;

    /* Found it!  Need to remove its write permissions. */
    sl1mfn = shadow_l2e_get_mfn(*sl2p);
    sl1e = shadow_l1e_remove_flags(sl1e, _PAGE_RW);
    r = shadow_set_l1e(d, sl1p, sl1e, p2m_ram_rw, sl1mfn);
    if ( r & SHADOW_SET_ERROR ) {
        /* Can only currently happen if we found a grant-mapped
         * page.  Just make the guess fail. */
        return 0;
    }
    TRACE_SHADOW_PATH_FLAG(TRCE_SFLAG_WRMAP_GUESS_FOUND);
    return 1;
}
#endif

int cf_check sh_rm_write_access_from_l1(
    struct domain *d, mfn_t sl1mfn, mfn_t readonly_mfn)
/* Excises all writeable mappings to readonly_mfn from this l1 shadow table */
{
    shadow_l1e_t *sl1e;
    int done = 0;
#if SHADOW_OPTIMIZATIONS & SHOPT_WRITABLE_HEURISTIC
    struct vcpu *curr = current;
    mfn_t base_sl1mfn = sl1mfn; /* Because sl1mfn changes in the foreach */
#endif

    FOREACH_PRESENT_L1E(sl1mfn, sl1e, NULL, done,
    {
        if ( (shadow_l1e_get_flags(*sl1e) & _PAGE_RW) &&
             mfn_eq(shadow_l1e_get_mfn(*sl1e), readonly_mfn) )
        {
            shadow_l1e_t ro_sl1e = shadow_l1e_remove_flags(*sl1e, _PAGE_RW);

            shadow_set_l1e(d, sl1e, ro_sl1e, p2m_ram_rw, sl1mfn);
#if SHADOW_OPTIMIZATIONS & SHOPT_WRITABLE_HEURISTIC
            /* Remember the last shadow that we shot a writeable mapping in */
            if ( curr->domain == d )
                curr->arch.paging.shadow.last_writeable_pte_smfn = mfn_x(base_sl1mfn);
#endif
            if ( (mfn_to_page(readonly_mfn)->u.inuse.type_info
                  & PGT_count_mask) == 0 )
                /* This breaks us cleanly out of the FOREACH macro */
                done = 1;
        }
    });
    return done;
}


int cf_check sh_rm_mappings_from_l1(
    struct domain *d, mfn_t sl1mfn, mfn_t target_mfn)
/* Excises all mappings to guest frame from this shadow l1 table */
{
    shadow_l1e_t *sl1e;
    int done = 0;

    FOREACH_PRESENT_L1E(sl1mfn, sl1e, NULL, done,
    {
        if ( mfn_eq(shadow_l1e_get_mfn(*sl1e), target_mfn) )
        {
            shadow_set_l1e(d, sl1e, shadow_l1e_empty(), p2m_invalid, sl1mfn);
            if ( sh_check_page_has_no_refs(mfn_to_page(target_mfn)) )
                /* This breaks us cleanly out of the FOREACH macro */
                done = 1;
        }
    });
    return done;
}

/**************************************************************************/
/* Functions to excise all pointers to shadows from higher-level shadows. */

void sh_clear_shadow_entry(struct domain *d, void *ep, mfn_t smfn)
/* Blank out a single shadow entry */
{
    switch ( mfn_to_page(smfn)->u.sh.type )
    {
    case SH_type_l1_shadow:
        shadow_set_l1e(d, ep, shadow_l1e_empty(), p2m_invalid, smfn);
        break;
    case SH_type_l2_shadow:
#if GUEST_PAGING_LEVELS >= 4 && defined(CONFIG_PV32)
    case SH_type_l2h_shadow:
#endif
        shadow_set_l2e(d, ep, shadow_l2e_empty(), smfn);
        break;
#if GUEST_PAGING_LEVELS >= 4
    case SH_type_l3_shadow:
        shadow_set_l3e(d, ep, shadow_l3e_empty(), smfn);
        break;
    case SH_type_l4_shadow:
        shadow_set_l4e(d, ep, shadow_l4e_empty(), smfn);
        break;
#endif
    default: BUG(); /* Called with the wrong kind of shadow. */
    }
}

int cf_check sh_remove_l1_shadow(struct domain *d, mfn_t sl2mfn, mfn_t sl1mfn)
/* Remove all mappings of this l1 shadow from this l2 shadow */
{
    shadow_l2e_t *sl2e;
    int done = 0;

    FOREACH_PRESENT_L2E(sl2mfn, sl2e, NULL, done, d,
    {
        if ( mfn_eq(shadow_l2e_get_mfn(*sl2e), sl1mfn) )
        {
            shadow_set_l2e(d, sl2e, shadow_l2e_empty(), sl2mfn);
            if ( mfn_to_page(sl1mfn)->u.sh.type == 0 )
                /* This breaks us cleanly out of the FOREACH macro */
                done = 1;
        }
    });
    return done;
}

#if GUEST_PAGING_LEVELS >= 4
int cf_check sh_remove_l2_shadow(struct domain *d, mfn_t sl3mfn, mfn_t sl2mfn)
/* Remove all mappings of this l2 shadow from this l3 shadow */
{
    shadow_l3e_t *sl3e;
    int done = 0;

    FOREACH_PRESENT_L3E(sl3mfn, sl3e, NULL, done,
    {
        if ( mfn_eq(shadow_l3e_get_mfn(*sl3e), sl2mfn) )
        {
            shadow_set_l3e(d, sl3e, shadow_l3e_empty(), sl3mfn);
            if ( mfn_to_page(sl2mfn)->u.sh.type == 0 )
                /* This breaks us cleanly out of the FOREACH macro */
                done = 1;
        }
    });
    return done;
}

int cf_check sh_remove_l3_shadow(struct domain *d, mfn_t sl4mfn, mfn_t sl3mfn)
/* Remove all mappings of this l3 shadow from this l4 shadow */
{
    shadow_l4e_t *sl4e;
    int done = 0;

    FOREACH_PRESENT_L4E(sl4mfn, sl4e, NULL, done, d,
    {
        if ( mfn_eq(shadow_l4e_get_mfn(*sl4e), sl3mfn) )
        {
            shadow_set_l4e(d, sl4e, shadow_l4e_empty(), sl4mfn);
            if ( mfn_to_page(sl3mfn)->u.sh.type == 0 )
                /* This breaks us cleanly out of the FOREACH macro */
                done = 1;
        }
    });
    return done;
}
#endif /* 64bit guest */

#ifdef CONFIG_HVM
/**************************************************************************/
/* Function for the guest to inform us that a process is being torn
 * down.  We remember that as a hint to unshadow its pagetables soon,
 * and in the meantime we unhook its top-level user-mode entries. */

#if GUEST_PAGING_LEVELS == 3
static void cf_check sh_pagetable_dying(paddr_t gpa)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    unsigned int i;
    int flush = 0;
    int fast_path = 0;
    paddr_t gcr3 = 0;
    p2m_type_t p2mt;
    char *gl3pa = NULL;
    guest_l3e_t *gl3e = NULL;
    unsigned long l3gfn;
    mfn_t l3mfn;

    ASSERT(is_hvm_domain(d));

    gcr3 = v->arch.hvm.guest_cr[3];
    /* fast path: the pagetable belongs to the current context */
    if ( gcr3 == gpa )
        fast_path = 1;

    l3gfn = gpa >> PAGE_SHIFT;
    l3mfn = get_gfn_query(d, _gfn(l3gfn), &p2mt);
    if ( !mfn_valid(l3mfn) || !p2m_is_ram(p2mt) )
    {
        printk(XENLOG_DEBUG "sh_pagetable_dying: gpa not valid %"PRIpaddr"\n",
               gpa);
        goto out_put_gfn;
    }

    paging_lock(d);

    if ( !fast_path )
    {
        gl3pa = map_domain_page(l3mfn);
        gl3e = (guest_l3e_t *)(gl3pa + ((unsigned long)gpa & ~PAGE_MASK));
    }
    for_each_shadow_table(v, i)
    {
        mfn_t smfn, gmfn;

        if ( fast_path )
        {
            if ( pagetable_is_null(v->arch.paging.shadow.shadow_table[i]) )
                smfn = INVALID_MFN;
            else
                smfn = pagetable_get_mfn(v->arch.paging.shadow.shadow_table[i]);
        }
        else
        {
            /* retrieving the l2s */
            gmfn = get_gfn_query_unlocked(d, gfn_x(guest_l3e_get_gfn(gl3e[i])),
                                          &p2mt);
            smfn = unlikely(mfn_eq(gmfn, INVALID_MFN))
                   ? INVALID_MFN
                   : shadow_hash_lookup(d, mfn_x(gmfn), SH_type_l2_pae_shadow);
        }

        if ( !mfn_eq(smfn, INVALID_MFN) )
        {
            gmfn = _mfn(mfn_to_page(smfn)->v.sh.back);
            mfn_to_page(gmfn)->pagetable_dying = true;
            shadow_unhook_mappings(d, smfn, 1/* user pages only */);
            flush = 1;
        }
    }
    if ( flush )
        guest_flush_tlb_mask(d, d->dirty_cpumask);

    /* Remember that we've seen the guest use this interface, so we
     * can rely on it using it in future, instead of guessing at
     * when processes are being torn down. */
    d->arch.paging.shadow.pagetable_dying_op = 1;

    v->arch.paging.shadow.pagetable_dying = 1;

    if ( !fast_path )
        unmap_domain_page(gl3pa);
    paging_unlock(d);
out_put_gfn:
    put_gfn(d, l3gfn);
}
#else
static void cf_check sh_pagetable_dying(paddr_t gpa)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    mfn_t smfn, gmfn;
    p2m_type_t p2mt;

    ASSERT(is_hvm_domain(d));

    gmfn = get_gfn_query(d, _gfn(gpa >> PAGE_SHIFT), &p2mt);
    paging_lock(d);

#if GUEST_PAGING_LEVELS == 2
    smfn = shadow_hash_lookup(d, mfn_x(gmfn), SH_type_l2_32_shadow);
#else
    smfn = shadow_hash_lookup(d, mfn_x(gmfn), SH_type_l4_64_shadow);
#endif

    if ( !mfn_eq(smfn, INVALID_MFN) )
    {
        mfn_to_page(gmfn)->pagetable_dying = true;
        shadow_unhook_mappings(d, smfn, 1/* user pages only */);
        /* Now flush the TLB: we removed toplevel mappings. */
        guest_flush_tlb_mask(d, d->dirty_cpumask);
    }

    /* Remember that we've seen the guest use this interface, so we
     * can rely on it using it in future, instead of guessing at
     * when processes are being torn down. */
    d->arch.paging.shadow.pagetable_dying_op = 1;

    v->arch.paging.shadow.pagetable_dying = 1;

    paging_unlock(d);
    put_gfn(d, gpa >> PAGE_SHIFT);
}
#endif
#endif /* CONFIG_HVM */

/**************************************************************************/
/* Audit tools */

#if SHADOW_AUDIT & SHADOW_AUDIT_ENTRIES

#define AUDIT_FAIL(_level, _fmt, _a...) do {                            \
    printk("Shadow %u-on-%u audit failed at level %i, index %i\n"       \
           "gl" #_level "mfn = %" PRI_mfn                               \
           " sl" #_level "mfn = %" PRI_mfn                              \
           " &gl" #_level "e = %p &sl" #_level "e = %p"                 \
           " gl" #_level "e = %" SH_PRI_gpte                            \
           " sl" #_level "e = %" SH_PRI_pte "\nError: " _fmt "\n",      \
           GUEST_PAGING_LEVELS, SHADOW_PAGING_LEVELS,                   \
               _level, guest_index(gl ## _level ## e),                  \
               mfn_x(gl ## _level ## mfn), mfn_x(sl ## _level ## mfn),  \
               gl ## _level ## e, sl ## _level ## e,                    \
               gl ## _level ## e->l ## _level, sl ## _level ## e->l ## _level, \
               ##_a);                                                   \
        BUG();                                                          \
        done = 1;                                                       \
} while (0)

#define AUDIT_FAIL_MIN(_level, _fmt, _a...) do {                        \
    printk("Shadow %u-on-%u audit failed at level %i\n"                 \
           "gl" #_level "mfn = %" PRI_mfn                               \
           " sl" #_level "mfn = %" PRI_mfn                              \
           " Error: " _fmt "\n",                                        \
           GUEST_PAGING_LEVELS, SHADOW_PAGING_LEVELS,                   \
           _level,                                                      \
           mfn_x(gl ## _level ## mfn), mfn_x(sl ## _level ## mfn),      \
           ##_a);                                                       \
    BUG();                                                              \
    done = 1;                                                           \
} while (0)

static const char *sh_audit_flags(const struct domain *d, int level,
                                  int gflags, int sflags)
/* Common code for auditing flag bits */
{
    if ( (sflags & _PAGE_PRESENT) && !(gflags & _PAGE_PRESENT) )
        return "shadow is present but guest is not present";
    if ( (sflags & _PAGE_GLOBAL) && !is_hvm_domain(d) )
        return "global bit set in PV shadow";
    if ( level == 2 && (sflags & _PAGE_PSE) )
        return "PS bit set in shadow";
#if SHADOW_PAGING_LEVELS == 3
    if ( level == 3 ) return NULL; /* All the other bits are blank in PAEl3 */
#endif
    if ( (sflags & _PAGE_PRESENT) && !(gflags & _PAGE_ACCESSED) )
        return "accessed bit not propagated";
    if ( (level == 1 || (level == 2 && (gflags & _PAGE_PSE)))
         && ((sflags & _PAGE_RW) && !(gflags & _PAGE_DIRTY)) )
        return "dirty bit not propagated";
    if ( (sflags & _PAGE_USER) != (gflags & _PAGE_USER) )
        return "user/supervisor bit does not match";
    if ( (sflags & _PAGE_NX_BIT) != (gflags & _PAGE_NX_BIT) )
        return "NX bit does not match";
    if ( (sflags & _PAGE_RW) && !(gflags & _PAGE_RW) )
        return "shadow grants write access but guest does not";
    return NULL;
}

int cf_check sh_audit_l1_table(struct domain *d, mfn_t sl1mfn, mfn_t x)
{
    guest_l1e_t *gl1e, *gp;
    shadow_l1e_t *sl1e;
    mfn_t mfn, gmfn, gl1mfn;
    gfn_t gfn;
    p2m_type_t p2mt;
    const char *s;
    int done = 0;

    /* Follow the backpointer */
    ASSERT(mfn_to_page(sl1mfn)->u.sh.head);
    gl1mfn = backpointer(mfn_to_page(sl1mfn));

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    /* Out-of-sync l1 shadows can contain anything: just check the OOS hash */
    if ( page_is_out_of_sync(mfn_to_page(gl1mfn)) )
    {
        oos_audit_hash_is_present(d, gl1mfn);
        return 0;
    }
#endif

    gl1e = gp = map_domain_page(gl1mfn);
    FOREACH_PRESENT_L1E(sl1mfn, sl1e, &gl1e, done, {

        if ( sh_l1e_is_magic(*sl1e) )
        {
#if (SHADOW_OPTIMIZATIONS & SHOPT_FAST_FAULT_PATH)
            if ( sh_l1e_is_gnp(*sl1e) )
            {
                if ( guest_l1e_get_flags(*gl1e) & _PAGE_PRESENT )
                    AUDIT_FAIL(1, "shadow is GNP magic but guest is present");
            }
            else
            {
                ASSERT(sh_l1e_is_mmio(*sl1e));
                gfn = sh_l1e_mmio_get_gfn(*sl1e);
                if ( gfn_x(gfn) != gfn_x(guest_l1e_get_gfn(*gl1e)) )
                    AUDIT_FAIL(1, "shadow MMIO gfn is %" SH_PRI_gfn
                               " but guest gfn is %" SH_PRI_gfn,
                               gfn_x(gfn),
                               gfn_x(guest_l1e_get_gfn(*gl1e)));
            }
#endif
        }
        else
        {
            s = sh_audit_flags(d, 1, guest_l1e_get_flags(*gl1e),
                               shadow_l1e_get_flags(*sl1e));
            if ( s ) AUDIT_FAIL(1, "%s", s);

            if ( SHADOW_AUDIT & SHADOW_AUDIT_ENTRIES_MFNS )
            {
                gfn = guest_l1e_get_gfn(*gl1e);
                mfn = shadow_l1e_get_mfn(*sl1e);
                gmfn = get_gfn_query_unlocked(d, gfn_x(gfn), &p2mt);
                if ( !p2m_is_grant(p2mt) && !mfn_eq(gmfn, mfn) )
                    AUDIT_FAIL(1, "bad translation: gfn %" SH_PRI_gfn
                               " --> %" PRI_mfn " != mfn %" PRI_mfn,
                               gfn_x(gfn), mfn_x(gmfn), mfn_x(mfn));
            }
        }
    });
    unmap_domain_page(gp);
    return done;
}

int cf_check sh_audit_fl1_table(struct domain *d, mfn_t sl1mfn, mfn_t x)
{
    guest_l1e_t *gl1e, e;
    shadow_l1e_t *sl1e;
    mfn_t gl1mfn = INVALID_MFN;
    int f;
    int done = 0;

    /* fl1 has no useful backpointer: all we can check are flags */
    e = guest_l1e_from_gfn(_gfn(0), 0); gl1e = &e; /* Needed for macro */
    FOREACH_PRESENT_L1E(sl1mfn, sl1e, NULL, done, {
        f = shadow_l1e_get_flags(*sl1e);
        f &= ~(_PAGE_AVAIL0|_PAGE_AVAIL1|_PAGE_AVAIL2);
        if ( !(f == 0
               || f == (_PAGE_PRESENT|_PAGE_USER|_PAGE_RW|
                        _PAGE_ACCESSED)
               || f == (_PAGE_PRESENT|_PAGE_USER|_PAGE_ACCESSED)
               || f == (_PAGE_PRESENT|_PAGE_USER|_PAGE_RW|
                        _PAGE_ACCESSED|_PAGE_DIRTY)
               || f == (_PAGE_PRESENT|_PAGE_USER|_PAGE_ACCESSED|_PAGE_DIRTY)
               || sh_l1e_is_magic(*sl1e)) )
            AUDIT_FAIL(1, "fl1e has bad flags");
    });
    return 0;
}

int cf_check sh_audit_l2_table(struct domain *d, mfn_t sl2mfn, mfn_t x)
{
    guest_l2e_t *gl2e, *gp;
    shadow_l2e_t *sl2e;
    mfn_t mfn, gmfn, gl2mfn;
    gfn_t gfn;
    p2m_type_t p2mt;
    const char *s;
    int done = 0;

    /* Follow the backpointer */
    ASSERT(mfn_to_page(sl2mfn)->u.sh.head);
    gl2mfn = backpointer(mfn_to_page(sl2mfn));

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    /* Only L1's may be out of sync. */
    if ( page_is_out_of_sync(mfn_to_page(gl2mfn)) )
        AUDIT_FAIL_MIN(2, "gmfn %lx is out of sync", mfn_x(gl2mfn));
#endif

    gl2e = gp = map_domain_page(gl2mfn);
    FOREACH_PRESENT_L2E(sl2mfn, sl2e, &gl2e, done, d, {

        s = sh_audit_flags(d, 2, guest_l2e_get_flags(*gl2e),
                           shadow_l2e_get_flags(*sl2e));
        if ( s ) AUDIT_FAIL(2, "%s", s);

        if ( SHADOW_AUDIT & SHADOW_AUDIT_ENTRIES_MFNS )
        {
            gfn = guest_l2e_get_gfn(*gl2e);
            mfn = shadow_l2e_get_mfn(*sl2e);
            gmfn = (guest_l2e_get_flags(*gl2e) & _PAGE_PSE)
                ? get_fl1_shadow_status(d, gfn)
                : get_shadow_status(d,
                    get_gfn_query_unlocked(d, gfn_x(gfn),
                                        &p2mt), SH_type_l1_shadow);
            if ( !mfn_eq(gmfn, mfn) )
                AUDIT_FAIL(2, "bad translation: gfn %" SH_PRI_gfn
                           " (--> %" PRI_mfn ")"
                           " --> %" PRI_mfn " != mfn %" PRI_mfn,
                           gfn_x(gfn),
                           (guest_l2e_get_flags(*gl2e) & _PAGE_PSE) ? 0
                           : mfn_x(get_gfn_query_unlocked(d,
                                   gfn_x(gfn), &p2mt)), mfn_x(gmfn), mfn_x(mfn));
        }
    });
    unmap_domain_page(gp);
    return 0;
}

#if GUEST_PAGING_LEVELS >= 4
int cf_check sh_audit_l3_table(struct domain *d, mfn_t sl3mfn, mfn_t x)
{
    guest_l3e_t *gl3e, *gp;
    shadow_l3e_t *sl3e;
    mfn_t mfn, gmfn, gl3mfn;
    gfn_t gfn;
    p2m_type_t p2mt;
    const char *s;
    int done = 0;

    /* Follow the backpointer */
    ASSERT(mfn_to_page(sl3mfn)->u.sh.head);
    gl3mfn = backpointer(mfn_to_page(sl3mfn));

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    /* Only L1's may be out of sync. */
    if ( page_is_out_of_sync(mfn_to_page(gl3mfn)) )
        AUDIT_FAIL_MIN(3, "gmfn %lx is out of sync", mfn_x(gl3mfn));
#endif

    gl3e = gp = map_domain_page(gl3mfn);
    FOREACH_PRESENT_L3E(sl3mfn, sl3e, &gl3e, done, {

        s = sh_audit_flags(d, 3, guest_l3e_get_flags(*gl3e),
                           shadow_l3e_get_flags(*sl3e));
        if ( s ) AUDIT_FAIL(3, "%s", s);

        if ( SHADOW_AUDIT & SHADOW_AUDIT_ENTRIES_MFNS )
        {
            unsigned int t = SH_type_l2_shadow;

            gfn = guest_l3e_get_gfn(*gl3e);
            mfn = shadow_l3e_get_mfn(*sl3e);
#ifdef CONFIG_PV32
            if ( guest_index(gl3e) == 3 && is_pv_32bit_domain(d) )
                t = SH_type_l2h_shadow;
#endif
            gmfn = get_shadow_status(
                       d, get_gfn_query_unlocked(d, gfn_x(gfn), &p2mt), t);
            if ( !mfn_eq(gmfn, mfn) )
                AUDIT_FAIL(3, "bad translation: gfn %" SH_PRI_gfn
                           " --> %" PRI_mfn " != mfn %" PRI_mfn,
                           gfn_x(gfn), mfn_x(gmfn), mfn_x(mfn));
        }
    });
    unmap_domain_page(gp);
    return 0;
}

int cf_check sh_audit_l4_table(struct domain *d, mfn_t sl4mfn, mfn_t x)
{
    guest_l4e_t *gl4e, *gp;
    shadow_l4e_t *sl4e;
    mfn_t mfn, gmfn, gl4mfn;
    gfn_t gfn;
    p2m_type_t p2mt;
    const char *s;
    int done = 0;

    /* Follow the backpointer */
    ASSERT(mfn_to_page(sl4mfn)->u.sh.head);
    gl4mfn = backpointer(mfn_to_page(sl4mfn));

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
    /* Only L1's may be out of sync. */
    if ( page_is_out_of_sync(mfn_to_page(gl4mfn)) )
        AUDIT_FAIL_MIN(4, "gmfn %lx is out of sync", mfn_x(gl4mfn));
#endif

    gl4e = gp = map_domain_page(gl4mfn);
    FOREACH_PRESENT_L4E(sl4mfn, sl4e, &gl4e, done, d,
    {
        s = sh_audit_flags(d, 4, guest_l4e_get_flags(*gl4e),
                           shadow_l4e_get_flags(*sl4e));
        if ( s ) AUDIT_FAIL(4, "%s", s);

        if ( SHADOW_AUDIT & SHADOW_AUDIT_ENTRIES_MFNS )
        {
            gfn = guest_l4e_get_gfn(*gl4e);
            mfn = shadow_l4e_get_mfn(*sl4e);
            gmfn = get_shadow_status(d, get_gfn_query_unlocked(
                                     d, gfn_x(gfn), &p2mt),
                                     SH_type_l3_shadow);
            if ( !mfn_eq(gmfn, mfn) )
                AUDIT_FAIL(4, "bad translation: gfn %" SH_PRI_gfn
                           " --> %" PRI_mfn " != mfn %" PRI_mfn,
                           gfn_x(gfn), mfn_x(gmfn), mfn_x(mfn));
        }
    });
    unmap_domain_page(gp);
    return 0;
}
#endif /* GUEST_PAGING_LEVELS >= 4 */


#undef AUDIT_FAIL

#endif /* Audit code */

/**************************************************************************/
/* Entry points into this mode of the shadow code.
 * This will all be mangled by the preprocessor to uniquify everything. */
const struct paging_mode sh_paging_mode = {
    .page_fault                    = sh_page_fault,
    .invlpg                        = sh_invlpg,
#ifdef CONFIG_HVM
    .gva_to_gfn                    = sh_gva_to_gfn,
#endif
    .update_cr3                    = sh_update_cr3,
    .guest_levels                  = GUEST_PAGING_LEVELS,
#ifdef CONFIG_HVM
#if SHADOW_OPTIMIZATIONS & SHOPT_WRITABLE_HEURISTIC
    .shadow.guess_wrmap            = sh_guess_wrmap,
#endif
    .shadow.pagetable_dying        = sh_pagetable_dying,
    .shadow.trace_emul_write_val   = trace_emulate_write_val,
#endif /* CONFIG_HVM */
    .shadow.shadow_levels          = SHADOW_PAGING_LEVELS,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
