#include <xen/compiler.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <asm/e820.h>
#include <xen/string.h>
#include <asm/page.h>
#include <asm/intel_txt.h>
#include <asm/slaunch.h>
#include <asm/tpm.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/slr_table.h>

static uint64_t __initdata txt_heap_base, txt_heap_size;

void __init map_txt_mem_regions(void)
{
    void *evt_log_addr;
    uint32_t evt_log_size;

    map_l2(TXT_PRIV_CONFIG_REGS_BASE, NR_TXT_CONFIG_PAGES * PAGE_SIZE);
    map_l2(TPM_TIS_BASE, TPM_TIS_SIZE);

    txt_heap_base = read_txt_reg(TXTCR_HEAP_BASE);
    BUG_ON(txt_heap_base == 0);

    txt_heap_size = read_txt_reg(TXTCR_HEAP_SIZE);
    BUG_ON(txt_heap_size == 0);

    map_l2(txt_heap_base, txt_heap_size);

    find_evt_log(__va(txt_find_slrt()), &evt_log_addr, &evt_log_size);
    map_l2((unsigned long)evt_log_addr, evt_log_size);
}

void __init protect_txt_mem_regions(void)
{
    void *evt_log_addr;
    uint32_t evt_log_size;

    uint64_t sinit_base, sinit_size;

    /* TXT Heap */
    BUG_ON(txt_heap_base == 0);
    printk("SLAUNCH: reserving TXT heap (%#lx - %#lx)\n", txt_heap_base,
           txt_heap_base + txt_heap_size);
    e820_change_range_type(&e820_raw, txt_heap_base,
                           txt_heap_base + txt_heap_size,
                           E820_RAM, E820_RESERVED);

    /* TXT TPM Event Log */
    find_evt_log(__va(txt_find_slrt()), &evt_log_addr, &evt_log_size);
    if ( evt_log_addr != 0 ) {
        printk("SLAUNCH: reserving event log (%#lx - %#lx)\n",
               (uint64_t)evt_log_addr,
               (uint64_t)evt_log_addr + evt_log_size);
        e820_change_range_type(&e820_raw, (uint64_t)evt_log_addr,
                               (uint64_t)evt_log_addr + evt_log_size,
                               E820_RAM, E820_RESERVED);
    }

    sinit_base = read_txt_reg(TXTCR_SINIT_BASE);
    BUG_ON(sinit_base == 0);

    sinit_size = read_txt_reg(TXTCR_SINIT_SIZE);
    BUG_ON(sinit_size == 0);

    /* SINIT */
    printk("SLAUNCH: reserving SINIT memory (%#lx - %#lx)\n", sinit_base,
           sinit_base + sinit_size);
    e820_change_range_type(&e820_raw, sinit_base,
                           sinit_base + sinit_size,
                           E820_RAM, E820_RESERVED);

    /* TXT Private Space */
    e820_change_range_type(&e820_raw, TXT_PRIV_CONFIG_REGS_BASE,
                 TXT_PRIV_CONFIG_REGS_BASE + NR_TXT_CONFIG_PAGES * PAGE_SIZE,
                 E820_RAM, E820_UNUSABLE);
}

void __init txt_restore_mtrrs(bool e820_verbose)
{
    struct txt_os_mle_data *os_mle;
    struct slr_table *slrt;
    struct slr_entry_intel_info *intel_info;
    int os_mle_size;
    uint64_t mtrr_cap, mtrr_def, base, mask;
    unsigned int i;

    os_mle_size = txt_os_mle_data_size(__va(txt_heap_base));
    os_mle = txt_os_mle_data_start(__va(txt_heap_base));

    if ( os_mle_size < sizeof(*os_mle) )
        panic("OS-MLE too small\n");

    rdmsrl(MSR_MTRRcap, mtrr_cap);
    rdmsrl(MSR_MTRRdefType, mtrr_def);

    if ( e820_verbose ) {
        printk("MTRRs set previously for SINIT ACM:\n");
        printk(" MTRR cap: %"PRIx64" type: %"PRIx64"\n", mtrr_cap, mtrr_def);

        for ( i = 0; i < (uint8_t)mtrr_cap; i++ )
        {
            rdmsrl(MSR_IA32_MTRR_PHYSBASE(i), base);
            rdmsrl(MSR_IA32_MTRR_PHYSMASK(i), mask);

            printk(" MTRR[%d]: base %"PRIx64" mask %"PRIx64"\n",
                   i, base, mask);
        }
    }

    slrt = __va(os_mle->slrt);
    intel_info = (struct slr_entry_intel_info *)
        slr_next_entry_by_tag(slrt, NULL, SLR_ENTRY_INTEL_INFO);

    if ( (mtrr_cap & 0xFF) != intel_info->saved_bsp_mtrrs.mtrr_vcnt ) {
        printk("Bootloader saved %ld MTRR values, but there should be %ld\n",
               intel_info->saved_bsp_mtrrs.mtrr_vcnt, mtrr_cap & 0xFF);
        /* Choose the smaller one to be on the safe side. */
        mtrr_cap = (mtrr_cap & 0xFF) > intel_info->saved_bsp_mtrrs.mtrr_vcnt ?
                   intel_info->saved_bsp_mtrrs.mtrr_vcnt : mtrr_cap;
    }

    /* Restore MTRRs saved by bootloader. */
    wrmsrl(MSR_MTRRdefType, intel_info->saved_bsp_mtrrs.default_mem_type);

    for ( i = 0; i < (uint8_t)mtrr_cap; i++ )
    {
        base = intel_info->saved_bsp_mtrrs.mtrr_pair[i].mtrr_physbase;
        mask = intel_info->saved_bsp_mtrrs.mtrr_pair[i].mtrr_physmask;
        wrmsrl(MSR_IA32_MTRR_PHYSBASE(i), base);
        wrmsrl(MSR_IA32_MTRR_PHYSMASK(i), mask);
    }

    if ( e820_verbose )
        printk("Restored MTRRs:\n"); /* Printed by caller, mtrr_top_of_ram(). */
}
