/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * vmce.c - provide software emulated vMCE support to guest
 *
 * Copyright (C) 2010, 2011 Jiang, Yunhong <yunhong.jiang@intel.com>
 * Copyright (C) 2012, 2013 Liu, Jinsong <jinsong.liu@intel.com>
 */

#include <xen/init.h>
#include <xen/types.h>
#include <xen/irq.h>
#include <xen/event.h>
#include <xen/kernel.h>
#include <xen/delay.h>
#include <xen/smp.h>
#include <xen/mm.h>
#include <asm/hvm/save.h>
#include <asm/processor.h>
#include <public/hvm/params.h>
#include <public/sysctl.h>
#include <asm/system.h>
#include <asm/msr.h>
#include <asm/p2m.h>
#include <asm/pv/traps.h>

#include "mce.h"
#include "x86_mca.h"
#include "vmce.h"

/*
 * MCG_SER_P:  software error recovery supported
 * MCG_TES_P:  to avoid MCi_status bit56:53 model specific
 * MCG_CMCI_P: expose CMCI capability but never really inject it to guest,
 *             for sake of performance since guest not polling periodically
 */
#define INTEL_GUEST_MCG_CAP (MCG_SER_P |	\
                             MCG_TES_P |	\
                             MCG_CMCI_P |	\
                             GUEST_MC_BANK_NUM)

#define AMD_GUEST_MCG_CAP GUEST_MC_BANK_NUM

void vmce_init_vcpu(struct vcpu *v)
{
    int i;

    /* global MCA MSRs init */
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL )
        v->arch.vmce.mcg_cap = INTEL_GUEST_MCG_CAP;
    else
        v->arch.vmce.mcg_cap = AMD_GUEST_MCG_CAP;

    v->arch.vmce.mcg_status = 0;

    /* per-bank MCA MSRs init */
    for ( i = 0; i < GUEST_MC_BANK_NUM; i++ )
        memset(&v->arch.vmce.bank[i], 0, sizeof(struct vmce_bank));

    spin_lock_init(&v->arch.vmce.lock);
}

int vmce_restore_vcpu(struct vcpu *v, const struct hvm_vmce_vcpu *ctxt)
{
    unsigned long guest_mcg_cap;

    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL )
        guest_mcg_cap = INTEL_GUEST_MCG_CAP | MCG_LMCE_P;
    else
        guest_mcg_cap = AMD_GUEST_MCG_CAP;

    if ( ctxt->caps & ~guest_mcg_cap & ~MCG_CAP_COUNT & ~MCG_CTL_P )
    {
        printk(XENLOG_G_ERR
               "%s restore: unsupported MCA capabilities %#"PRIx64" for %pv (supported: %#Lx)\n",
                is_hvm_vcpu(v) ? "HVM" : "PV", ctxt->caps,
                v, guest_mcg_cap & ~MCG_CAP_COUNT);
        return -EINVAL;
    }

    v->arch.vmce.mcg_cap = ctxt->caps;
    v->arch.vmce.bank[0].mci_ctl2 = ctxt->mci_ctl2_bank0;
    v->arch.vmce.bank[1].mci_ctl2 = ctxt->mci_ctl2_bank1;
    v->arch.vmce.mcg_ext_ctl = ctxt->mcg_ext_ctl;

    return 0;
}

/*
 * For historic version reason, bank number may greater than GUEST_MC_BANK_NUM,
 * when migrating from old vMCE version to new vMCE.
 */
static int bank_mce_rdmsr(const struct vcpu *v, uint32_t msr, uint64_t *val)
{
    int ret = 1;
    unsigned int bank = (msr - MSR_IA32_MC0_CTL) / 4;

    *val = 0;

    switch ( msr & (-MSR_IA32_MC0_CTL | 3) )
    {
    case MSR_IA32_MC0_CTL:
        /* stick all 1's to MCi_CTL */
        *val = ~0UL;
        mce_printk(MCE_VERBOSE, "MCE: %pv: rd MC%u_CTL %#"PRIx64"\n",
                   v, bank, *val);
        break;

    case MSR_IA32_MC0_STATUS:
        if ( bank < GUEST_MC_BANK_NUM )
        {
            *val = v->arch.vmce.bank[bank].mci_status;
            if ( *val )
                mce_printk(MCE_VERBOSE, "MCE: %pv: rd MC%u_STATUS %#"PRIx64"\n",
                           v, bank, *val);
        }
        break;

    case MSR_IA32_MC0_ADDR:
        if ( bank < GUEST_MC_BANK_NUM )
        {
            *val = v->arch.vmce.bank[bank].mci_addr;
            if ( *val )
                mce_printk(MCE_VERBOSE, "MCE: %pv: rd MC%u_ADDR %#"PRIx64"\n",
                           v, bank, *val);
        }
        break;

    case MSR_IA32_MC0_MISC:
        if ( bank < GUEST_MC_BANK_NUM )
        {
            *val = v->arch.vmce.bank[bank].mci_misc;
            if ( *val )
                mce_printk(MCE_VERBOSE, "MCE: %pv: rd MC%u_MISC %#"PRIx64"\n",
                           v, bank, *val);
        }
        break;

    default:
        switch ( boot_cpu_data.x86_vendor )
        {
#ifdef CONFIG_INTEL
        case X86_VENDOR_CENTAUR:
        case X86_VENDOR_SHANGHAI:
        case X86_VENDOR_INTEL:
            ret = vmce_intel_rdmsr(v, msr, val);
            break;
#endif

#ifdef CONFIG_AMD
        case X86_VENDOR_AMD:
        case X86_VENDOR_HYGON:
            ret = vmce_amd_rdmsr(v, msr, val);
            break;
#endif

        default:
            ret = 0;
            break;
        }
        break;
    }

    return ret;
}

/*
 * < 0: Unsupported and will #GP fault to guest
 * = 0: Not handled, should be handled by other components
 * > 0: Success
 */
int vmce_rdmsr(uint32_t msr, uint64_t *val)
{
    struct vcpu *cur = current;
    int ret = 1;

    *val = 0;

    spin_lock(&cur->arch.vmce.lock);

    switch ( msr )
    {
    case MSR_IA32_MCG_STATUS:
        *val = cur->arch.vmce.mcg_status;
        if ( *val )
            mce_printk(MCE_VERBOSE,
                       "MCE: %pv: rd MCG_STATUS %#"PRIx64"\n", cur, *val);
        break;

    case MSR_IA32_MCG_CAP:
        *val = cur->arch.vmce.mcg_cap;
        mce_printk(MCE_VERBOSE, "MCE: %pv: rd MCG_CAP %#"PRIx64"\n", cur, *val);
        break;

    case MSR_IA32_MCG_CTL:
        if ( cur->arch.vmce.mcg_cap & MCG_CTL_P )
            *val = ~0ULL;
        mce_printk(MCE_VERBOSE, "MCE: %pv: rd MCG_CTL %#"PRIx64"\n", cur, *val);
        break;

    case MSR_IA32_MCG_EXT_CTL:
        /*
         * If MCG_LMCE_P is present in guest MSR_IA32_MCG_CAP, the LMCE and LOCK
         * bits are always set in guest MSR_IA32_FEATURE_CONTROL by Xen, so it
         * does not need to check them here.
         */
        if ( vmce_has_lmce(cur) )
        {
            *val = cur->arch.vmce.mcg_ext_ctl;
            mce_printk(MCE_VERBOSE, "MCE: %pv: rd MCG_EXT_CTL %#"PRIx64"\n",
                       cur, *val);
        }
        else
        {
            ret = -1;
            mce_printk(MCE_VERBOSE, "MCE: %pv: rd MCG_EXT_CTL, not supported\n",
                       cur);
        }
        break;

    default:
        ret = mce_bank_msr(cur, msr) ? bank_mce_rdmsr(cur, msr, val) : 0;
        break;
    }

    spin_unlock(&cur->arch.vmce.lock);

    return ret;
}

/*
 * For historic version reason, bank number may greater than GUEST_MC_BANK_NUM,
 * when migratie from old vMCE version to new vMCE.
 */
static int bank_mce_wrmsr(struct vcpu *v, uint32_t msr, uint64_t val)
{
    int ret = 1;
    unsigned int bank = (msr - MSR_IA32_MC0_CTL) / 4;

    switch ( msr & (-MSR_IA32_MC0_CTL | 3) )
    {
    case MSR_IA32_MC0_CTL:
        /*
         * if guest crazy clear any bit of MCi_CTL,
         * treat it as not implement and ignore write change it.
         */
        break;

    case MSR_IA32_MC0_STATUS:
        mce_printk(MCE_VERBOSE, "MCE: %pv: wr MC%u_STATUS %#"PRIx64"\n",
                   v, bank, val);
        if ( val )
            ret = -1;
        else if ( bank < GUEST_MC_BANK_NUM )
            v->arch.vmce.bank[bank].mci_status = val;
        break;

    case MSR_IA32_MC0_ADDR:
        mce_printk(MCE_VERBOSE, "MCE: %pv: wr MC%u_ADDR %#"PRIx64"\n",
                   v, bank, val);
        if ( val )
            ret = -1;
        else if ( bank < GUEST_MC_BANK_NUM )
            v->arch.vmce.bank[bank].mci_addr = val;
        break;

    case MSR_IA32_MC0_MISC:
        mce_printk(MCE_VERBOSE, "MCE: %pv: wr MC%u_MISC %#"PRIx64"\n",
                   v, bank, val);
        if ( val )
            ret = -1;
        else if ( bank < GUEST_MC_BANK_NUM )
            v->arch.vmce.bank[bank].mci_misc = val;
        break;

    default:
        switch ( boot_cpu_data.x86_vendor )
        {
#ifdef CONFIG_INTEL
        case X86_VENDOR_INTEL:
            ret = vmce_intel_wrmsr(v, msr, val);
            break;
#endif

#ifdef CONFIG_AMD
        case X86_VENDOR_AMD:
        case X86_VENDOR_HYGON:
            ret = vmce_amd_wrmsr(v, msr, val);
            break;
#endif

        default:
            ret = 0;
            break;
        }
        break;
    }

    return ret;
}

/*
 * < 0: Unsupported and will #GP fault to guest
 * = 0: Not handled, should be handled by other components
 * > 0: Success
 */
int vmce_wrmsr(uint32_t msr, uint64_t val)
{
    struct vcpu *cur = current;
    int ret = 1;

    spin_lock(&cur->arch.vmce.lock);

    switch ( msr )
    {
    case MSR_IA32_MCG_CTL:
        /* If MCG_CTL exists then stick to all 1's, else ignore. */
        break;

    case MSR_IA32_MCG_STATUS:
        cur->arch.vmce.mcg_status = val;
        mce_printk(MCE_VERBOSE, "MCE: %pv: wr MCG_STATUS %"PRIx64"\n",
                   cur, val);
        break;

    case MSR_IA32_MCG_CAP:
        /*
         * According to Intel SDM, IA32_MCG_CAP is a read-only register,
         * the effect of writing to the IA32_MCG_CAP is undefined. Here we
         * treat writing as 'write not change'. Guest would not surprise.
         */
        mce_printk(MCE_VERBOSE, "MCE: %pv: MCG_CAP is r/o\n", cur);
        break;

    case MSR_IA32_MCG_EXT_CTL:
        if ( vmce_has_lmce(cur) && !(val & ~MCG_EXT_CTL_LMCE_EN) )
            cur->arch.vmce.mcg_ext_ctl = val;
        else
            ret = -1;
        mce_printk(MCE_VERBOSE, "MCE: %pv: wr MCG_EXT_CTL %"PRIx64"%s\n",
                   cur, val, (ret == -1) ? ", not supported" : "");
        break;

    default:
        ret = mce_bank_msr(cur, msr) ? bank_mce_wrmsr(cur, msr, val) : 0;
        break;
    }

    spin_unlock(&cur->arch.vmce.lock);
    return ret;
}

#if CONFIG_HVM
static int cf_check vmce_save_vcpu_ctxt(struct vcpu *v, hvm_domain_context_t *h)
{
    struct hvm_vmce_vcpu ctxt = {
        .caps = v->arch.vmce.mcg_cap,
        .mci_ctl2_bank0 = v->arch.vmce.bank[0].mci_ctl2,
        .mci_ctl2_bank1 = v->arch.vmce.bank[1].mci_ctl2,
        .mcg_ext_ctl = v->arch.vmce.mcg_ext_ctl,
    };

    return hvm_save_entry(VMCE_VCPU, v->vcpu_id, h, &ctxt);
}

static int cf_check vmce_load_vcpu_ctxt(struct domain *d, hvm_domain_context_t *h)
{
    unsigned int vcpuid = hvm_load_instance(h);
    struct vcpu *v;
    struct hvm_vmce_vcpu ctxt;
    int err;

    if ( vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL )
    {
        dprintk(XENLOG_G_ERR, "HVM restore: dom%d has no vcpu%u\n",
                d->domain_id, vcpuid);
        err = -EINVAL;
    }
    else
        err = hvm_load_entry_zeroextend(VMCE_VCPU, h, &ctxt);

    return err ?: vmce_restore_vcpu(v, &ctxt);
}

HVM_REGISTER_SAVE_RESTORE(VMCE_VCPU, vmce_save_vcpu_ctxt, NULL,
                          vmce_load_vcpu_ctxt, 1, HVMSR_PER_VCPU);
#endif

/*
 * for Intel MCE, broadcast vMCE to all vcpus
 * for AMD MCE, only inject vMCE to vcpu0
 *
 * @ d, domain to which would inject vmce
 * @ vcpu,
 *   -1 (VMCE_INJECT_BROADCAST), broadcast vMCE to all vcpus
 *   >= 0, vcpu, the vMCE is injected to
 */
int inject_vmce(struct domain *d, int vcpu)
{
    struct vcpu *v;
    int ret = -ESRCH;

    for_each_vcpu ( d, v )
    {
        if ( vcpu != VMCE_INJECT_BROADCAST && vcpu != v->vcpu_id )
            continue;

        /* Don't inject to uninitialized VCPU. */
        if ( !v->is_initialised )
            continue;

        if ( (is_hvm_domain(d) ||
              pv_trap_callback_registered(v, X86_EXC_MC)) &&
             !test_and_set_bool(v->arch.mce_pending) )
        {
            mce_printk(MCE_VERBOSE, "MCE: inject vMCE to %pv\n", v);
            vcpu_kick(v);
            ret = 0;
        }
        else
        {
            mce_printk(MCE_QUIET, "Failed to inject vMCE to %pv\n", v);
            ret = -EBUSY;
            break;
        }

        if ( vcpu != VMCE_INJECT_BROADCAST )
            break;
    }

    return ret;
}

static int vcpu_fill_mc_msrs(struct vcpu *v, uint64_t mcg_status,
                             uint64_t mci_status, uint64_t mci_addr,
                             uint64_t mci_misc)
{
    if ( v->arch.vmce.mcg_status & MCG_STATUS_MCIP )
    {
        mce_printk(MCE_QUIET, "MCE: %pv: guest has not handled previous"
                   " vMCE yet!\n", v);
        return -EBUSY;
    }

    spin_lock(&v->arch.vmce.lock);

    v->arch.vmce.mcg_status = mcg_status;
    /*
     * 1. Skip bank 0 to avoid 'bank 0 quirk' of old processors
     * 2. Filter MCi_STATUS MSCOD model specific error code to guest
     */
    v->arch.vmce.bank[1].mci_status = mci_status & MCi_STATUS_MSCOD_MASK;
    v->arch.vmce.bank[1].mci_addr = mci_addr;
    v->arch.vmce.bank[1].mci_misc = mci_misc;

    spin_unlock(&v->arch.vmce.lock);

    return 0;
}

int fill_vmsr_data(struct mcinfo_bank *mc_bank, struct domain *d,
                   uint64_t gstatus, int vmce_vcpuid)
{
    struct vcpu *v = d->vcpu[0];
    bool broadcast = (vmce_vcpuid == VMCE_INJECT_BROADCAST);
    int ret, err;

    if ( mc_bank->mc_domid == DOMID_INVALID )
        return -EINVAL;

    if ( broadcast )
        gstatus &= ~MCG_STATUS_LMCE;
    else if ( gstatus & MCG_STATUS_LMCE )
    {
        ASSERT(vmce_vcpuid >= 0 && vmce_vcpuid < d->max_vcpus);
        v = d->vcpu[vmce_vcpuid];
    }

    /*
     * vMCE with the actual error information is injected to vCPU0,
     * and, if broadcast is required, we choose to inject less severe
     * vMCEs to other vCPUs. Thus guest can always get the severest
     * error (i.e. the actual one) on vCPU0. If guest can recover from
     * the severest error on vCPU0, the less severe errors on other
     * vCPUs will not prevent guest from recovering on those vCPUs.
     */
    ret = vcpu_fill_mc_msrs(v, gstatus, mc_bank->mc_status,
                            mc_bank->mc_addr, mc_bank->mc_misc);
    if ( broadcast )
        for_each_vcpu ( d, v )
        {
            if ( !v->vcpu_id )
                continue;
            err = vcpu_fill_mc_msrs(v, MCG_STATUS_MCIP | MCG_STATUS_RIPV,
                                    0, 0, 0);
            if ( err )
                ret = err;
        }

    return ret;
}

/* It's said some ram is setup as mmio_direct for UC cache attribute */
#define P2M_UNMAP_TYPES (p2m_to_mask(p2m_ram_rw) \
                                | p2m_to_mask(p2m_ram_logdirty) \
                                | p2m_to_mask(p2m_ram_ro)       \
                                | p2m_to_mask(p2m_mmio_direct))

/*
 * Currently all CPUs are redenzevous at the MCE softirq handler, no
 * need to consider paging p2m type
 * Currently only support HVM guest with EPT paging mode
 * XXX following situation missed:
 * PoD, Foreign mapped, Granted, Shared
 */
int unmmap_broken_page(struct domain *d, mfn_t mfn, unsigned long gfn)
{
    mfn_t r_mfn;
    p2m_type_t pt;
    int rc;

    /* Always trust dom0's MCE handler will prevent future access */
    if ( is_hardware_domain(d) )
        return 0;

    if ( !mfn_valid(mfn) )
        return -EINVAL;

    if ( !is_hvm_domain(d) || !paging_mode_hap(d) )
        return -EOPNOTSUPP;

    rc = -1;
    r_mfn = get_gfn_query(d, gfn, &pt);
    if ( p2m_to_mask(pt) & P2M_UNMAP_TYPES)
    {
        ASSERT(mfn_eq(r_mfn, mfn));
        rc = p2m_change_type_one(d, gfn, pt, p2m_ram_broken);
    }
    put_gfn(d, gfn);

    return rc;
}

int vmce_enable_mca_cap(struct domain *d, uint64_t cap)
{
    struct vcpu *v;

    if ( cap & ~XEN_HVM_MCA_CAP_MASK )
        return -EINVAL;

    if ( cap & XEN_HVM_MCA_CAP_LMCE )
    {
        if ( !lmce_support )
            return -EINVAL;
        for_each_vcpu(d, v)
            v->arch.vmce.mcg_cap |= MCG_LMCE_P;
    }

    return 0;
}
