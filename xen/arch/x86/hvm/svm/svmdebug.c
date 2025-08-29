/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * svmdebug.c: debug functions
 * Copyright (c) 2011, Advanced Micro Devices, Inc.
 *
 */

#include <xen/sched.h>
#include <asm/processor.h>
#include <asm/msr-index.h>
#include <asm/hvm/svm/svmdebug.h>

#include "vmcb.h"

static void svm_dump_sel(const char *name, const struct segment_register *s)
{
    printk("%s: %04x %04x %08x %016"PRIx64"\n",
           name, s->sel, s->attr, s->limit, s->base);
}

void svm_vmcb_dump(const char *from, const struct vmcb_struct *vmcb)
{
    struct vcpu *curr = current;

    /*
     * If we are dumping the VMCB currently in context, some guest state may
     * still be cached in hardware.  Retrieve it.
     */
    if ( vmcb == curr->arch.hvm.svm.vmcb )
        svm_sync_vmcb(curr, vmcb_in_sync);

    printk("Dumping guest's current state at %s...\n", from);
    printk("Size of VMCB = %zu, paddr = %"PRIpaddr", vaddr = %p\n",
           sizeof(struct vmcb_struct), virt_to_maddr(vmcb), vmcb);

    printk("cr_intercepts = %#x dr_intercepts = %#x "
           "exception_intercepts = %#x\n",
           vmcb_get_cr_intercepts(vmcb), vmcb_get_dr_intercepts(vmcb),
           vmcb_get_exception_intercepts(vmcb));
    printk("general1_intercepts = %#x general2_intercepts = %#x\n",
           vmcb_get_general1_intercepts(vmcb), vmcb_get_general2_intercepts(vmcb));
    printk("iopm_base_pa = %#"PRIx64" msrpm_base_pa = %#"PRIx64" tsc_offset = %#"PRIx64"\n",
           vmcb_get_iopm_base_pa(vmcb), vmcb_get_msrpm_base_pa(vmcb),
           vmcb_get_tsc_offset(vmcb));
    printk("tlb_control = %#x vintr = %#"PRIx64" int_stat = %#"PRIx64"\n",
           vmcb->tlb_control, vmcb_get_vintr(vmcb).bytes,
           vmcb->int_stat.raw);
    printk("event_inj %016"PRIx64", valid? %d, ec? %d, type %u, vector %#x\n",
           vmcb->event_inj.raw, vmcb->event_inj.v,
           vmcb->event_inj.ev, vmcb->event_inj.type,
           vmcb->event_inj.vector);
    printk("exitcode = %#"PRIx64" exit_int_info = %#"PRIx64"\n",
           vmcb->exitcode, vmcb->exit_int_info.raw);
    printk("exitinfo1 = %#"PRIx64" exitinfo2 = %#"PRIx64"\n",
           vmcb->exitinfo1, vmcb->exitinfo2);
    printk("asid = %#x np_ctrl = %#"PRIx64":%s%s%s\n",
           vmcb_get_asid(vmcb), vmcb_get_np_ctrl(vmcb),
           vmcb_get_np(vmcb)     ? " NP"     : "",
           vmcb_get_sev(vmcb)    ? " SEV"    : "",
           vmcb_get_sev_es(vmcb) ? " SEV_ES" : "");
    printk("virtual vmload/vmsave = %d, virt_ext = %#"PRIx64"\n",
           vmcb->virt_ext.fields.vloadsave_enable, vmcb->virt_ext.bytes);
    printk("cpl = %d efer = %#"PRIx64" star = %#"PRIx64" lstar = %#"PRIx64"\n",
           vmcb_get_cpl(vmcb), vmcb_get_efer(vmcb), vmcb->star, vmcb->lstar);
    printk("CR0 = 0x%016"PRIx64" CR2 = 0x%016"PRIx64"\n",
           vmcb_get_cr0(vmcb), vmcb_get_cr2(vmcb));
    printk("CR3 = 0x%016"PRIx64" CR4 = 0x%016"PRIx64"\n",
           vmcb_get_cr3(vmcb), vmcb_get_cr4(vmcb));
    printk("RSP = 0x%016"PRIx64"  RIP = 0x%016"PRIx64"\n",
           vmcb->rsp, vmcb->rip);
    printk("RAX = 0x%016"PRIx64"  RFLAGS=0x%016"PRIx64"\n",
           vmcb->rax, vmcb->rflags);
    printk("DR6 = 0x%016"PRIx64", DR7 = 0x%016"PRIx64"\n",
           vmcb_get_dr6(vmcb), vmcb_get_dr7(vmcb));
    printk("CSTAR = 0x%016"PRIx64" SFMask = 0x%016"PRIx64"\n",
           vmcb->cstar, vmcb->sfmask);
    printk("KernGSBase = 0x%016"PRIx64" PAT = 0x%016"PRIx64"\n",
           vmcb->kerngsbase, vmcb_get_g_pat(vmcb));
    printk("SSP = 0x%016"PRIx64" S_CET = 0x%016"PRIx64" ISST = 0x%016"PRIx64"\n",
           vmcb->_ssp, vmcb->_msr_s_cet, vmcb->_msr_isst);
    printk("H_CR3 = 0x%016"PRIx64" CleanBits = %#x\n",
           vmcb_get_h_cr3(vmcb), vmcb->cleanbits.raw);

    /* print out all the selectors */
    printk("       sel attr  limit   base\n");
    svm_dump_sel("  CS", &vmcb->cs);
    svm_dump_sel("  DS", &vmcb->ds);
    svm_dump_sel("  SS", &vmcb->ss);
    svm_dump_sel("  ES", &vmcb->es);
    svm_dump_sel("  FS", &vmcb->fs);
    svm_dump_sel("  GS", &vmcb->gs);
    svm_dump_sel("GDTR", &vmcb->gdtr);
    svm_dump_sel("LDTR", &vmcb->ldtr);
    svm_dump_sel("IDTR", &vmcb->idtr);
    svm_dump_sel("  TR", &vmcb->tr);
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
