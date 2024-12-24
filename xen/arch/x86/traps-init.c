/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Configuration of event handling for all CPUs.
 */
#include <xen/init.h>
#include <xen/param.h>
#include <xen/types.h>

#include <asm/idt.h>
#include <asm/msr.h>
#include <asm/page.h>
#include <asm/system.h>
#include <asm/traps.h>

DEFINE_PER_CPU_READ_MOSTLY(idt_entry_t *, idt);

static bool __initdata opt_ler;
boolean_param("ler", opt_ler);

int8_t __ro_after_init opt_fred = true;
boolean_param("fred", opt_fred);

void nocall entry_PF(void);
void nocall entry_FRED_CPL3(void);

static void __init init_ler(void)
{
    unsigned int msr = 0;

    if ( !opt_ler )
        return;

    /*
     * Intel Pentium 4 is the only known CPU to not use the architectural MSR
     * indicies.
     */
    switch ( boot_cpu_data.x86_vendor )
    {
    case X86_VENDOR_INTEL:
        if ( boot_cpu_data.x86 == 0xf )
        {
            msr = MSR_P4_LER_FROM_LIP;
            break;
        }
        fallthrough;
    case X86_VENDOR_AMD:
    case X86_VENDOR_HYGON:
        msr = MSR_IA32_LASTINTFROMIP;
        break;
    }

    if ( msr == 0 )
    {
        printk(XENLOG_WARNING "LER disabled: failed to identify MSRs\n");
        return;
    }

    ler_msr = msr;
    setup_force_cpu_cap(X86_FEATURE_XEN_LBR);
}

/*
 * Set up all FRED MSRs.
 */
void init_fred(void)
{
    wrmsrns(MSR_FRED_RSP_SL0, 0);
    wrmsrns(MSR_FRED_RSP_SL1, 0);
    wrmsrns(MSR_FRED_RSP_SL2, 0);
    wrmsrns(MSR_FRED_RSP_SL3, 0);
    wrmsrns(MSR_FRED_STK_LVLS, 3UL << (X86_EXC_DF * 2));

    if ( cpu_has_xen_shstk )
    {
        wrmsrns(MSR_FRED_SSP_SL0, 0);
        wrmsrns(MSR_FRED_SSP_SL1, 0);
        wrmsrns(MSR_FRED_SSP_SL2, 0);
        wrmsrns(MSR_FRED_SSP_SL3, 0);
    }

    wrmsrns(MSR_FRED_CONFIG, (unsigned long)entry_FRED_CPL3);
}

/*
 * Configure basic exception handling.  This is prior to parsing the command
 * line or configuring a console, and needs to be as simple as possible.
 *
 * boot_gdt is already loaded, and bsp_idt[] is constructed at build time
 * without IST settings, so we don't need a TSS configured yet.
 *
 * Load bsp_idt[], and invalidate the TSS and LDT.
 */
void __init early_traps_init(void)
{
    const struct desc_ptr idtr = {
        .base = (unsigned long)bsp_idt,
        .limit = sizeof(bsp_idt) - 1,
    };

    lidt(&idtr);

    _set_tssldt_desc(boot_gdt + TSS_ENTRY - FIRST_RESERVED_GDT_ENTRY,
                     0, 0, SYS_DESC_tss_avail);

    ltr(TSS_SELECTOR);
    lldt(0);
}

/*
 * Configure complete exception, interrupt and syscall handling.
 */
void __init traps_init(void)
{
    /* Replace early pagefault with real pagefault handler. */
    _update_gate_addr_lower(&bsp_idt[X86_EXC_PF], entry_PF);

    if ( !boot_cpu_has(X86_FEATURE_FRED) ||
         !boot_cpu_has(X86_FEATURE_LKGS) )
    {
        if ( opt_fred )
            printk(XENLOG_WARNING "FRED not available, ignoring\n");
        opt_fred = false;
    }

    if ( opt_fred == -1 && pv_shim )
        opt_fred = false;

    if ( opt_fred )
    {
        init_fred();
        set_in_cr4(X86_CR4_FRED);
    }

    this_cpu(idt) = bsp_idt;
    this_cpu(gdt) = boot_gdt;
    if ( IS_ENABLED(CONFIG_PV32) )
        this_cpu(compat_gdt) = boot_compat_gdt;

    load_system_tables();

    init_ler();

    /* Cache {,compat_}gdt_l1e now that physically relocation is done. */
    this_cpu(gdt_l1e) =
        l1e_from_pfn(virt_to_mfn(boot_gdt), __PAGE_HYPERVISOR_RW);
    if ( IS_ENABLED(CONFIG_PV32) )
        this_cpu(compat_gdt_l1e) =
            l1e_from_pfn(virt_to_mfn(boot_compat_gdt), __PAGE_HYPERVISOR_RW);

    percpu_traps_init();
}

/*
 * Set up per-CPU linkage registers for exception, interrupt and syscall
 * handling.
 */
void percpu_traps_init(void)
{
    subarch_percpu_traps_init();

    if ( cpu_has_xen_lbr )
        wrmsrl(MSR_IA32_DEBUGCTLMSR, IA32_DEBUGCTLMSR_LBR);

    init_fred();
}
