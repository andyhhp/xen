/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Configuration of event handling for all CPUs.
 */
#include <xen/init.h>

#include <asm/idt.h>
#include <asm/msr.h>
#include <asm/page.h>
#include <asm/system.h>
#include <asm/traps.h>

DEFINE_PER_CPU_READ_MOSTLY(idt_entry_t *, idt);

/*
 * Configure basic exception handling.  This is prior to parsing the command
 * line or configuring a console, and needs to be as simple as possible.
 */
void __init early_traps_init(void)
{
    init_idt_traps();
    load_system_tables();
}

/*
 * Configure complete exception, interrupt and syscall handling.
 */
void __init traps_init(void)
{
    trap_init();
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
}
