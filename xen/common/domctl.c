/******************************************************************************
 * domctl.c
 *
 * Domain management operations. For use by node control stack.
 *
 * Copyright (c) 2002-2006, K A Fraser
 */

#include <xen/types.h>
#include <xen/lib.h>
#include <xen/llc-coloring.h>
#include <xen/err.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/event.h>
#include <xen/grant_table.h>
#include <xen/domain_page.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/iocap.h>
#include <xen/rcupdate.h>
#include <xen/guest_access.h>
#include <xen/bitmap.h>
#include <xen/paging.h>
#include <xen/hypercall.h>
#include <xen/vm_event.h>
#include <xen/monitor.h>
#include <xen/xvmalloc.h>

#include <asm/current.h>
#include <asm/irq.h>
#include <asm/page.h>
#include <asm/p2m.h>
#include <public/domctl.h>
#include <xsm/xsm.h>

static DEFINE_SPINLOCK(domctl_lock);

static int nodemask_to_xenctl_bitmap(struct xenctl_bitmap *xenctl_nodemap,
                                     const nodemask_t *nodemask)
{
    return bitmap_to_xenctl_bitmap(xenctl_nodemap, nodemask_bits(nodemask),
                                   MAX_NUMNODES);
}

static int xenctl_bitmap_to_nodemask(nodemask_t *nodemask,
                                     const struct xenctl_bitmap *xenctl_nodemap)
{
    return xenctl_bitmap_to_bitmap(nodemask_bits(nodemask), xenctl_nodemap,
                                   MAX_NUMNODES);
}

static inline int is_free_domid(domid_t dom)
{
    struct domain *d;

    if ( dom >= DOMID_FIRST_RESERVED )
        return 0;

    if ( (d = rcu_lock_domain_by_id(dom)) == NULL )
        return 1;

    rcu_unlock_domain(d);
    return 0;
}

void getdomaininfo(struct domain *d, struct xen_domctl_getdomaininfo *info)
{
    struct vcpu *v;
    u64 cpu_time = 0;
    int flags = XEN_DOMINF_blocked;
    struct vcpu_runstate_info runstate;

    memset(info, 0, sizeof(*info));

    info->domain = d->domain_id;
    info->max_vcpu_id = XEN_INVALID_MAX_VCPU_ID;

    /*
     * - domain is marked as blocked only if all its vcpus are blocked
     * - domain is marked as running if any of its vcpus is running
     */
    for_each_vcpu ( d, v )
    {
        vcpu_runstate_get(v, &runstate);
        cpu_time += runstate.time[RUNSTATE_running];
        info->max_vcpu_id = v->vcpu_id;
        if ( !(v->pause_flags & VPF_down) )
        {
            if ( !(v->pause_flags & VPF_blocked) )
                flags &= ~XEN_DOMINF_blocked;
            if ( v->is_running )
                flags |= XEN_DOMINF_running;
            info->nr_online_vcpus++;
        }
    }

    info->cpu_time = cpu_time;

    info->flags = (info->nr_online_vcpus ? flags : 0) |
        ((d->is_dying == DOMDYING_dead) ? XEN_DOMINF_dying     : 0) |
        (d->is_shut_down                ? XEN_DOMINF_shutdown  : 0) |
        (d->controller_pause_count > 0  ? XEN_DOMINF_paused    : 0) |
        (d->debugger_attached           ? XEN_DOMINF_debugged  : 0) |
        (is_xenstore_domain(d)          ? XEN_DOMINF_xs_domain : 0) |
        (is_hvm_domain(d)               ? XEN_DOMINF_hvm_guest : 0) |
        d->shutdown_code << XEN_DOMINF_shutdownshift;

    xsm_security_domaininfo(d, info);

    info->tot_pages         = domain_tot_pages(d);
    info->max_pages         = d->max_pages;
    info->outstanding_pages = d->outstanding_pages;
#ifdef CONFIG_MEM_SHARING
    info->shr_pages         = atomic_read(&d->shr_pages);
#endif
#ifdef CONFIG_MEM_PAGING
    info->paged_pages       = atomic_read(&d->paged_pages);
#endif
    info->shared_info_frame =
        gfn_x(mfn_to_gfn(d, _mfn(virt_to_mfn(d->shared_info))));
    BUG_ON(SHARED_M2P(info->shared_info_frame));

    info->cpupool = cpupool_get_id(d);

    memcpy(info->handle, d->handle, sizeof(xen_domain_handle_t));

    arch_get_domain_info(d, info);
}

bool domctl_lock_acquire(void)
{
    /*
     * Caller may try to pause its own VCPUs. We must prevent deadlock
     * against other non-domctl routines which try to do the same.
     */
    if ( !spin_trylock(&current->domain->hypercall_deadlock_mutex) )
        return 0;

    /*
     * Trylock here is paranoia if we have multiple privileged domains. Then
     * we could have one domain trying to pause another which is spinning
     * on domctl_lock -- results in deadlock.
     */
    if ( spin_trylock(&domctl_lock) )
        return 1;

    spin_unlock(&current->domain->hypercall_deadlock_mutex);
    return 0;
}

void domctl_lock_release(void)
{
    spin_unlock(&domctl_lock);
    spin_unlock(&current->domain->hypercall_deadlock_mutex);
}

void vnuma_destroy(struct vnuma_info *vnuma)
{
    if ( vnuma )
    {
        xfree(vnuma->vmemrange);
        xfree(vnuma->vcpu_to_vnode);
        xvfree(vnuma->vdistance);
        xfree(vnuma->vnode_to_pnode);
        xfree(vnuma);
    }
}

/*
 * Allocates memory for vNUMA, **vnuma should be NULL.
 * Caller has to make sure that domain has max_pages
 * and number of vcpus set for domain.
 * Verifies that single allocation does not exceed
 * PAGE_SIZE.
 */
static struct vnuma_info *vnuma_alloc(unsigned int nr_vnodes,
                                      unsigned int nr_ranges,
                                      unsigned int nr_vcpus)
{

    struct vnuma_info *vnuma;

    /*
     * Check if any of the allocations are bigger than PAGE_SIZE.
     * See XSA-77.
     */
    if ( nr_vnodes == 0 ||
         nr_vnodes > (PAGE_SIZE / sizeof(*vnuma->vdistance) / nr_vnodes) ||
         nr_ranges > (PAGE_SIZE / sizeof(*vnuma->vmemrange)) )
        return ERR_PTR(-EINVAL);

    /*
     * If allocations become larger then PAGE_SIZE, these allocations
     * should be split into PAGE_SIZE allocations due to XSA-77.
     */
    vnuma = xmalloc(struct vnuma_info);
    if ( !vnuma )
        return ERR_PTR(-ENOMEM);

    vnuma->vdistance = xvmalloc_array(unsigned int, nr_vnodes, nr_vnodes);
    vnuma->vcpu_to_vnode = xmalloc_array(unsigned int, nr_vcpus);
    vnuma->vnode_to_pnode = xmalloc_array(nodeid_t, nr_vnodes);
    vnuma->vmemrange = xmalloc_array(xen_vmemrange_t, nr_ranges);

    if ( vnuma->vdistance == NULL || vnuma->vmemrange == NULL ||
         vnuma->vcpu_to_vnode == NULL || vnuma->vnode_to_pnode == NULL )
    {
        vnuma_destroy(vnuma);
        return ERR_PTR(-ENOMEM);
    }

    return vnuma;
}

/*
 * Construct vNUMA topology form uinfo.
 */
static struct vnuma_info *vnuma_init(const struct xen_domctl_vnuma *uinfo,
                                     const struct domain *d)
{
    unsigned int i, nr_vnodes;
    int ret = -EINVAL;
    struct vnuma_info *info;

    nr_vnodes = uinfo->nr_vnodes;

    if ( uinfo->nr_vcpus != d->max_vcpus || uinfo->pad != 0 )
        return ERR_PTR(ret);

    info = vnuma_alloc(nr_vnodes, uinfo->nr_vmemranges, d->max_vcpus);
    if ( IS_ERR(info) )
        return info;

    ret = -EFAULT;

    if ( copy_from_guest(info->vdistance, uinfo->vdistance,
                         nr_vnodes * nr_vnodes) )
        goto vnuma_fail;

    if ( copy_from_guest(info->vmemrange, uinfo->vmemrange,
                         uinfo->nr_vmemranges) )
        goto vnuma_fail;

    if ( copy_from_guest(info->vcpu_to_vnode, uinfo->vcpu_to_vnode,
                         d->max_vcpus) )
        goto vnuma_fail;

    ret = -E2BIG;
    for ( i = 0; i < d->max_vcpus; ++i )
        if ( info->vcpu_to_vnode[i] >= nr_vnodes )
            goto vnuma_fail;

    for ( i = 0; i < nr_vnodes; ++i )
    {
        unsigned int pnode;

        ret = -EFAULT;
        if ( copy_from_guest_offset(&pnode, uinfo->vnode_to_pnode, i, 1) )
            goto vnuma_fail;
        ret = -E2BIG;
        if ( pnode >= MAX_NUMNODES )
            goto vnuma_fail;
        info->vnode_to_pnode[i] = pnode;
    }

    info->nr_vnodes = nr_vnodes;
    info->nr_vmemranges = uinfo->nr_vmemranges;

    /* Check that vmemranges flags are zero. */
    ret = -EINVAL;
    for ( i = 0; i < info->nr_vmemranges; i++ )
        if ( info->vmemrange[i].flags != 0 )
            goto vnuma_fail;

    return info;

 vnuma_fail:
    vnuma_destroy(info);
    return ERR_PTR(ret);
}

static bool is_stable_domctl(uint32_t cmd)
{
    return cmd == XEN_DOMCTL_get_domain_state;
}

long do_domctl(XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    long ret = 0;
    bool copyback = false;
    struct xen_domctl curop, *op = &curop;
    struct domain *d;

    if ( copy_from_guest(op, u_domctl, 1) )
        return -EFAULT;

    if ( op->interface_version !=
         (is_stable_domctl(op->cmd) ? 0 : XEN_DOMCTL_INTERFACE_VERSION) )
        return -EACCES;

    switch ( op->cmd )
    {
    case XEN_DOMCTL_createdomain:
        d = NULL;
        break;

    case XEN_DOMCTL_assign_device:
    case XEN_DOMCTL_deassign_device:
        if ( op->domain == DOMID_IO )
        {
            d = dom_io;
            break;
        }
        else if ( op->domain == DOMID_INVALID )
            return -ESRCH;
        fallthrough;
    case XEN_DOMCTL_test_assign_device:
    case XEN_DOMCTL_vm_event_op:
    case XEN_DOMCTL_get_domain_state:
        if ( op->domain == DOMID_INVALID )
        {
            d = NULL;
            break;
        }
        fallthrough;
    default:
        d = rcu_lock_domain_by_id(op->domain);
        if ( !d )
            return -ESRCH;
        break;
    }

    ret = xsm_domctl(XSM_OTHER, d, op->cmd,
                     /* SSIDRef only applicable for cmd == createdomain */
                     op->u.createdomain.ssidref);
    if ( ret )
        goto domctl_out_unlock_domonly;

    if ( !domctl_lock_acquire() )
    {
        if ( d && d != dom_io )
            rcu_unlock_domain(d);
        return hypercall_create_continuation(
            __HYPERVISOR_domctl, "h", u_domctl);
    }

    switch ( op->cmd )
    {

    case XEN_DOMCTL_setvcpucontext:
    {
        vcpu_guest_context_u c = { .nat = NULL };
        unsigned int vcpu = op->u.vcpucontext.vcpu;
        struct vcpu *v;

        ret = -EINVAL;
        if ( (d == current->domain) || /* no domain_pause() */
             (vcpu >= d->max_vcpus) || ((v = d->vcpu[vcpu]) == NULL) )
            break;

        if ( guest_handle_is_null(op->u.vcpucontext.ctxt) )
        {
            ret = vcpu_reset(v);
            if ( ret == -ERESTART )
                ret = hypercall_create_continuation(
                          __HYPERVISOR_domctl, "h", u_domctl);
            break;
        }

#ifdef CONFIG_COMPAT
        BUILD_BUG_ON(sizeof(struct vcpu_guest_context)
                     < sizeof(struct compat_vcpu_guest_context));
#endif
        ret = -ENOMEM;
        if ( (c.nat = alloc_vcpu_guest_context()) == NULL )
            break;

#ifdef CONFIG_COMPAT
        if ( !is_pv_32bit_domain(d) )
            ret = copy_from_guest(c.nat, op->u.vcpucontext.ctxt, 1);
        else
            ret = copy_from_guest(c.cmp,
                                  guest_handle_cast(op->u.vcpucontext.ctxt,
                                                    void), 1);
#else
        ret = copy_from_guest(c.nat, op->u.vcpucontext.ctxt, 1);
#endif
        ret = ret ? -EFAULT : 0;

        if ( ret == 0 )
        {
            domain_pause(d);
            ret = arch_set_info_guest(v, c);
            domain_unpause(d);

            if ( ret == -ERESTART )
                ret = hypercall_create_continuation(
                          __HYPERVISOR_domctl, "h", u_domctl);
        }

        free_vcpu_guest_context(c.nat);
        break;
    }

    case XEN_DOMCTL_pausedomain:
        ret = -EINVAL;
        if ( d != current->domain )
            ret = domain_pause_by_systemcontroller(d);
        break;

    case XEN_DOMCTL_unpausedomain:
        ret = domain_unpause_by_systemcontroller(d);
        break;

    case XEN_DOMCTL_resumedomain:
        if ( d == current->domain ) /* no domain_pause() */
            ret = -EINVAL;
        else
            domain_resume(d);
        break;

    case XEN_DOMCTL_createdomain:
    {
        domid_t        dom;
        static domid_t rover = 0;

        dom = op->domain;
        if ( (dom > 0) && (dom < DOMID_FIRST_RESERVED) )
        {
            ret = -EEXIST;
            if ( !is_free_domid(dom) )
                break;
        }
        else
        {
            for ( dom = rover + 1; dom != rover; dom++ )
            {
                if ( dom == DOMID_FIRST_RESERVED )
                    dom = 1;
                if ( is_free_domid(dom) )
                    break;
            }

            ret = -ENOMEM;
            if ( dom == rover )
                break;

            rover = dom;
        }

        d = domain_create(dom, &op->u.createdomain, false);
        if ( IS_ERR(d) )
        {
            ret = PTR_ERR(d);
            d = NULL;
            break;
        }

        ret = 0;
        op->domain = d->domain_id;
        copyback = 1;
        d = NULL;
        break;
    }

    case XEN_DOMCTL_max_vcpus:
    {
        unsigned int i, max = op->u.max_vcpus.max;

        ret = -EINVAL;
        if ( (d == current->domain) || /* no domain_pause() */
             (max != d->max_vcpus) )   /* max_vcpus set up in createdomain */
            break;

        /* Needed, for example, to ensure writable p.t. state is synced. */
        domain_pause(d);

        ret = -ENOMEM;

        for ( i = 0; i < max; i++ )
        {
            if ( d->vcpu[i] != NULL )
                continue;

            if ( vcpu_create(d, i) == NULL )
                goto maxvcpu_out;
        }

        domain_update_node_affinity(d);
        ret = 0;

    maxvcpu_out:
        domain_unpause(d);
        break;
    }

    case XEN_DOMCTL_soft_reset:
    case XEN_DOMCTL_soft_reset_cont:
        if ( d == current->domain ) /* no domain_pause() */
        {
            ret = -EINVAL;
            break;
        }
        ret = domain_soft_reset(d, op->cmd == XEN_DOMCTL_soft_reset_cont);
        if ( ret == -ERESTART )
        {
            op->cmd = XEN_DOMCTL_soft_reset_cont;
            if ( !__copy_field_to_guest(u_domctl, op, cmd) )
                ret = hypercall_create_continuation(__HYPERVISOR_domctl,
                                                    "h", u_domctl);
            else
                ret = -EFAULT;
        }
        break;

    case XEN_DOMCTL_destroydomain:
        ret = domain_kill(d);
        if ( ret == -ERESTART )
            ret = hypercall_create_continuation(
                __HYPERVISOR_domctl, "h", u_domctl);
        break;

    case XEN_DOMCTL_setnodeaffinity:
    {
        nodemask_t new_affinity;

        ret = xenctl_bitmap_to_nodemask(&new_affinity,
                                        &op->u.nodeaffinity.nodemap);
        if ( !ret )
            ret = domain_set_node_affinity(d, &new_affinity);
        break;
    }

    case XEN_DOMCTL_getnodeaffinity:
        ret = nodemask_to_xenctl_bitmap(&op->u.nodeaffinity.nodemap,
                                        &d->node_affinity);
        break;

    case XEN_DOMCTL_setvcpuaffinity:
    case XEN_DOMCTL_getvcpuaffinity:
        ret = vcpu_affinity_domctl(d, op->cmd, &op->u.vcpuaffinity);
        break;

    case XEN_DOMCTL_scheduler_op:
        ret = sched_adjust(d, &op->u.scheduler_op);
        copyback = 1;
        break;

    case XEN_DOMCTL_getdomaininfo:
        ret = xsm_getdomaininfo(XSM_XS_PRIV, d);
        if ( ret )
            break;

        getdomaininfo(d, &op->u.getdomaininfo);

        op->domain = op->u.getdomaininfo.domain;
        copyback = 1;
        break;

    case XEN_DOMCTL_getvcpucontext:
    {
        vcpu_guest_context_u c = { .nat = NULL };
        struct vcpu         *v;

        ret = -EINVAL;
        if ( op->u.vcpucontext.vcpu >= d->max_vcpus ||
             (v = d->vcpu[op->u.vcpucontext.vcpu]) == NULL ||
             v == current ) /* no vcpu_pause() */
            goto getvcpucontext_out;

        ret = -ENODATA;
        if ( !v->is_initialised )
            goto getvcpucontext_out;

#ifdef CONFIG_COMPAT
        BUILD_BUG_ON(sizeof(struct vcpu_guest_context)
                     < sizeof(struct compat_vcpu_guest_context));
#endif
        ret = -ENOMEM;
        if ( (c.nat = xzalloc(struct vcpu_guest_context)) == NULL )
            goto getvcpucontext_out;

        vcpu_pause(v);

        arch_get_info_guest(v, c);
        ret = 0;

        vcpu_unpause(v);

#ifdef CONFIG_COMPAT
        if ( !is_pv_32bit_domain(d) )
            ret = copy_to_guest(op->u.vcpucontext.ctxt, c.nat, 1);
        else
            ret = copy_to_guest(guest_handle_cast(op->u.vcpucontext.ctxt,
                                                  void), c.cmp, 1);
#else
        ret = copy_to_guest(op->u.vcpucontext.ctxt, c.nat, 1);
#endif

        if ( ret )
            ret = -EFAULT;
        copyback = 1;

    getvcpucontext_out:
        xfree(c.nat);
        break;
    }

    case XEN_DOMCTL_getvcpuinfo:
    {
        struct vcpu   *v;
        struct vcpu_runstate_info runstate;

        ret = -EINVAL;
        if ( op->u.getvcpuinfo.vcpu >= d->max_vcpus )
            break;

        ret = -ESRCH;
        if ( (v = d->vcpu[op->u.getvcpuinfo.vcpu]) == NULL )
            break;

        vcpu_runstate_get(v, &runstate);

        op->u.getvcpuinfo.online   = !(v->pause_flags & VPF_down);
        op->u.getvcpuinfo.blocked  = !!(v->pause_flags & VPF_blocked);
        op->u.getvcpuinfo.running  = v->is_running;
        op->u.getvcpuinfo.cpu_time = runstate.time[RUNSTATE_running];
        op->u.getvcpuinfo.cpu      = v->processor;
        ret = 0;
        copyback = 1;
        break;
    }

    case XEN_DOMCTL_max_mem:
    {
        uint64_t new_max = op->u.max_mem.max_memkb >> (PAGE_SHIFT - 10);

        nrspin_lock(&d->page_alloc_lock);
        /*
         * NB. We removed a check that new_max >= current tot_pages; this means
         * that the domain will now be allowed to "ratchet" down to new_max. In
         * the meantime, while tot > max, all new allocations are disallowed.
         */
        d->max_pages = min(new_max, (uint64_t)(typeof(d->max_pages))-1);
        nrspin_unlock(&d->page_alloc_lock);
        break;
    }

    case XEN_DOMCTL_setdomainhandle:
        memcpy(d->handle, op->u.setdomainhandle.handle,
               sizeof(xen_domain_handle_t));
        break;

    case XEN_DOMCTL_setdebugging:
        if ( unlikely(d == current->domain) ) /* no domain_pause() */
            ret = -EINVAL;
        else
        {
            domain_pause(d);
            d->debugger_attached = !!op->u.setdebugging.enable;
            domain_unpause(d); /* causes guest to latch new status */
        }
        break;

#ifdef CONFIG_HAS_PIRQ
    case XEN_DOMCTL_irq_permission:
    {
        unsigned int pirq = op->u.irq_permission.pirq, irq;
        int allow = op->u.irq_permission.allow_access;

        if ( pirq >= current->domain->nr_pirqs )
        {
            ret = -EINVAL;
            break;
        }
        irq = pirq_access_permitted(current->domain, pirq);
        if ( !irq || xsm_irq_permission(XSM_HOOK, d, irq, allow) )
            ret = -EPERM;
        else if ( allow )
            ret = irq_permit_access(d, irq);
        else
            ret = irq_deny_access(d, irq);
        break;
    }
#endif

    case XEN_DOMCTL_iomem_permission:
    {
        unsigned long mfn = op->u.iomem_permission.first_mfn;
        unsigned long nr_mfns = op->u.iomem_permission.nr_mfns;
        int allow = op->u.iomem_permission.allow_access;

        ret = -EINVAL;
        if ( (mfn + nr_mfns - 1) < mfn ) /* wrap? */
            break;

        if ( !iomem_access_permitted(current->domain,
                                     mfn, mfn + nr_mfns - 1) ||
             xsm_iomem_permission(XSM_HOOK, d, mfn, mfn + nr_mfns - 1, allow) )
            ret = -EPERM;
        else if ( allow )
            ret = iomem_permit_access(d, mfn, mfn + nr_mfns - 1);
        else
            ret = iomem_deny_access(d, mfn, mfn + nr_mfns - 1);
        break;
    }

    case XEN_DOMCTL_memory_mapping:
    {
        unsigned long gfn = op->u.memory_mapping.first_gfn;
        unsigned long mfn = op->u.memory_mapping.first_mfn;
        unsigned long nr_mfns = op->u.memory_mapping.nr_mfns;
        unsigned long mfn_end = mfn + nr_mfns - 1;
        int add = op->u.memory_mapping.add_mapping;

        ret = -EINVAL;
        if ( mfn_end < mfn || /* wrap? */
             ((mfn | mfn_end) >> (paddr_bits - PAGE_SHIFT)) ||
             (gfn + nr_mfns - 1) < gfn ) /* wrap? */
            break;

#ifndef CONFIG_X86 /* XXX ARM!? */
        ret = -E2BIG;
        /* Must break hypercall up as this could take a while. */
        if ( nr_mfns > 64 )
            break;
#endif

        ret = -EPERM;
        if ( !iomem_access_permitted(current->domain, mfn, mfn_end) ||
             !iomem_access_permitted(d, mfn, mfn_end) )
            break;

        ret = xsm_iomem_mapping(XSM_HOOK, d, mfn, mfn_end, add);
        if ( ret )
            break;

        if ( !paging_mode_translate(d) )
            break;

        if ( add )
        {
            printk(XENLOG_G_DEBUG
                   "memory_map:add: dom%d gfn=%lx mfn=%lx nr=%lx\n",
                   d->domain_id, gfn, mfn, nr_mfns);

            ret = map_mmio_regions(d, _gfn(gfn), nr_mfns, _mfn(mfn));
            if ( ret < 0 )
                printk(XENLOG_G_WARNING
                       "memory_map:fail: dom%d gfn=%lx mfn=%lx nr=%lx ret:%ld\n",
                       d->domain_id, gfn, mfn, nr_mfns, ret);
        }
        else
        {
            printk(XENLOG_G_DEBUG
                   "memory_map:remove: dom%d gfn=%lx mfn=%lx nr=%lx\n",
                   d->domain_id, gfn, mfn, nr_mfns);

            ret = unmap_mmio_regions(d, _gfn(gfn), nr_mfns, _mfn(mfn));
            if ( ret < 0 && is_hardware_domain(current->domain) )
                printk(XENLOG_ERR
                       "memory_map: error %ld removing dom%d access to [%lx,%lx]\n",
                       ret, d->domain_id, mfn, mfn_end);
        }
        break;
    }

    case XEN_DOMCTL_settimeoffset:
        domain_set_time_offset(d, op->u.settimeoffset.time_offset_seconds);
        break;

    case XEN_DOMCTL_set_target:
    {
        struct domain *e;

        ret = -ESRCH;
        e = get_domain_by_id(op->u.set_target.target);
        if ( e == NULL )
            break;

        ret = -EINVAL;
        if ( (d == e) || (d->target != NULL) )
        {
            put_domain(e);
            break;
        }

        ret = -EOPNOTSUPP;
        if ( is_hvm_domain(e) )
            ret = xsm_set_target(XSM_HOOK, d, e);
        if ( ret )
        {
            put_domain(e);
            break;
        }

        /* Hold reference on @e until we destroy @d. */
        d->target = e;
        break;
    }

    case XEN_DOMCTL_subscribe:
        d->suspend_evtchn = op->u.subscribe.port;
        break;

    case XEN_DOMCTL_vm_event_op:
        ret = vm_event_domctl(d, &op->u.vm_event_op);
        if ( ret == 0 )
            copyback = true;
        break;

#ifdef CONFIG_VM_EVENT
    case XEN_DOMCTL_set_access_required:
        if ( unlikely(current->domain == d) ) /* no domain_pause() */
            ret = -EPERM;
        else
        {
            domain_pause(d);
            arch_p2m_set_access_required(d,
                op->u.access_required.access_required);
            domain_unpause(d);
        }
        break;
#endif

    case XEN_DOMCTL_set_virq_handler:
        ret = set_global_virq_handler(d, op->u.set_virq_handler.virq);
        break;

    case XEN_DOMCTL_setvnumainfo:
    {
        struct vnuma_info *vnuma;

        vnuma = vnuma_init(&op->u.vnuma, d);
        if ( IS_ERR(vnuma) )
        {
            ret = PTR_ERR(vnuma);
            break;
        }

        /* overwrite vnuma topology for domain. */
        write_lock(&d->vnuma_rwlock);
        vnuma_destroy(d->vnuma);
        d->vnuma = vnuma;
        write_unlock(&d->vnuma_rwlock);

        break;
    }

    case XEN_DOMCTL_monitor_op:
        ret = monitor_domctl(d, &op->u.monitor_op);
        if ( !ret )
            copyback = 1;
        break;

    case XEN_DOMCTL_assign_device:
    case XEN_DOMCTL_test_assign_device:
    case XEN_DOMCTL_deassign_device:
    case XEN_DOMCTL_get_device_group:
        ret = iommu_do_domctl(op, d, u_domctl);
        break;

    case XEN_DOMCTL_get_paging_mempool_size:
        ret = arch_get_paging_mempool_size(d, &op->u.paging_mempool.size);
        if ( !ret )
            copyback = 1;
        break;

    case XEN_DOMCTL_set_paging_mempool_size:
        ret = arch_set_paging_mempool_size(d, op->u.paging_mempool.size);

        if ( ret == -ERESTART )
            ret = hypercall_create_continuation(
                __HYPERVISOR_domctl, "h", u_domctl);
        break;

    case XEN_DOMCTL_set_llc_colors:
        if ( op->u.set_llc_colors.pad )
            ret = -EINVAL;
        else if ( llc_coloring_enabled )
            ret = domain_set_llc_colors(d, &op->u.set_llc_colors);
        else
            ret = -EOPNOTSUPP;
        break;

    case XEN_DOMCTL_get_domain_state:
        ret = xsm_get_domain_state(XSM_XS_PRIV, d);
        if ( ret )
            break;

        copyback = 1;
        ret = get_domain_state(&op->u.get_domain_state, d, &op->domain);
        break;

    default:
        ret = arch_do_domctl(op, d, u_domctl);
        break;
    }

    domctl_lock_release();

 domctl_out_unlock_domonly:
    if ( d && d != dom_io )
        rcu_unlock_domain(d);

    if ( copyback && __copy_to_guest(u_domctl, op, 1) )
        ret = -EFAULT;

    return ret;
}

static void __init __maybe_unused build_assertions(void)
{
    struct xen_domctl d;

    BUILD_BUG_ON(sizeof(d) != 16 /* header */ + 128 /* union */);
    BUILD_BUG_ON(offsetof(typeof(d), u) != 16);
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
