#include <xen/compiler.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <asm/e820.h>
#include <xen/string.h>
#include <asm/page.h>
#include <asm/intel_txt.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/slr_table.h>

static uint64_t __initdata txt_heap_base, txt_heap_size;

bool __initdata slaunch_active;

static void __maybe_unused compile_time_checks(void)
{
    BUILD_BUG_ON(sizeof(slaunch_active) != 1);
}

int __init map_l2(unsigned long paddr, unsigned long size)
{
    unsigned long aligned_paddr = paddr & ~((1ULL << L2_PAGETABLE_SHIFT) - 1);
    unsigned long pages = ((paddr + size) - aligned_paddr);
    pages = ROUNDUP(pages, 1ULL << L2_PAGETABLE_SHIFT) >> PAGE_SHIFT;

    if ( (aligned_paddr + pages * PAGE_SIZE) <= PREBUILT_MAP_LIMIT )
        return 0;

    if ( aligned_paddr < PREBUILT_MAP_LIMIT ) {
        pages -= (PREBUILT_MAP_LIMIT - aligned_paddr) >> PAGE_SHIFT;
        aligned_paddr = PREBUILT_MAP_LIMIT;
    }

    return map_pages_to_xen((unsigned long)__va(aligned_paddr),
                            maddr_to_mfn(aligned_paddr),
                            pages, PAGE_HYPERVISOR);
}

void __init map_txt_mem_regions(void)
{
    void *evt_log_addr;
    uint32_t evt_log_size;

    map_l2(TXT_PRIV_CONFIG_REGS_BASE, NR_TXT_CONFIG_PAGES * PAGE_SIZE);

    txt_heap_base = read_txt_reg(TXTCR_HEAP_BASE);
    BUG_ON(txt_heap_base == 0);

    txt_heap_size = read_txt_reg(TXTCR_HEAP_SIZE);
    BUG_ON(txt_heap_size == 0);

    map_l2(txt_heap_base, txt_heap_size);

    find_evt_log(&evt_log_addr, &evt_log_size);
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
    find_evt_log(&evt_log_addr, &evt_log_size);
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
