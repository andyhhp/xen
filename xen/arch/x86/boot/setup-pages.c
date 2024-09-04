#include <xen/stdint.h>
#include <xen/compiler.h>
#include <xen/config.h>
#ifndef __i386__
#include <xen/mm.h>
#endif

#if defined(__i386__)

#pragma GCC visibility push(hidden)
extern char _start[], _end[];
extern uint64_t l2_xenmap[512], l3_bootmap[512], l2_directmap[512], l2_bootmap[512];
extern unsigned long xen_phys_start;
#pragma GCC visibility pop

#define _PAGE_PRESENT 0x001
#define _PAGE_RW 0x002
#define _PAGE_ACCESSED 0x020
#define _PAGE_DIRTY 0x040
#define _PAGE_PSE 0x080
#define _PAGE_GLOBAL 0x100

#define PAGE_HYPERVISOR       PAGE_HYPERVISOR_RW
#define PAGE_HYPERVISOR_RW    (__PAGE_HYPERVISOR_RW | _PAGE_GLOBAL)
#define __PAGE_HYPERVISOR_RW  (__PAGE_HYPERVISOR_RO | _PAGE_DIRTY | _PAGE_RW)
// TODO
#define _PAGE_NX 0
#define __PAGE_HYPERVISOR_RO  (_PAGE_PRESENT | _PAGE_ACCESSED | _PAGE_NX)
#define PAGE_HYPERVISOR_RWX   (__PAGE_HYPERVISOR | _PAGE_GLOBAL)
#define __PAGE_HYPERVISOR     (__PAGE_HYPERVISOR_RX | _PAGE_DIRTY | _PAGE_RW)
#define __PAGE_HYPERVISOR_RX  (_PAGE_PRESENT | _PAGE_ACCESSED)

#define L2_PAGETABLE_SHIFT 21
#define L2_PAGETABLE_ENTRIES 512
#define PAGE_SIZE 4096
#define l2_table_offset(a) (((a) >> L2_PAGETABLE_SHIFT) & (L2_PAGETABLE_ENTRIES - 1))
#define l2e_from_paddr(a,f) ((a) | put_pte_flags(f))
#define l3e_from_paddr(a,f) ((a) | put_pte_flags(f))
#define l2e_add_flags(x, flags)    (x |= put_pte_flags(flags))
typedef uint64_t l2_pgentry_t;
static inline int64_t put_pte_flags(unsigned int x)
{
    return (((int64_t)x & ~0xfff) << 40) | (x & 0xfff);
}

void setup_pages32(void)
#elif defined (__x86_64__)
void setup_pages64(void)
#else
#error Unknow architecture
#endif
{
    unsigned int i;

    /*
     * Map Xen into the higher mappings, using 2M superpages.
     *
     * NB: We are currently in physical mode, so a RIP-relative relocation
     * against _start/_end result in our arbitrary placement by the bootloader
     * in memory, rather than the intended high mappings position.  Subtract
     * xen_phys_start to get the appropriate slots in l2_xenmap[].
     */
    for ( i =  l2_table_offset((unsigned long)_start   - xen_phys_start);
          i <= l2_table_offset((unsigned long)_end - 1 - xen_phys_start); ++i )
        l2_xenmap[i] =
            l2e_from_paddr(xen_phys_start + (i << L2_PAGETABLE_SHIFT),
                           PAGE_HYPERVISOR_RWX | _PAGE_PSE);

    /* Check that there is at least 4G of mapping space in l2_*map[] */
#ifndef __i386__
    BUILD_BUG_ON((sizeof(l2_bootmap)   / L2_PAGETABLE_ENTRIES) < 4);
    BUILD_BUG_ON((sizeof(l2_directmap) / L2_PAGETABLE_ENTRIES) < 4);
#endif

    /* Initialize L3 boot-map page directory entries. */
    for ( i = 0; i < 4; ++i )
        l3_bootmap[i] = l3e_from_paddr((unsigned long)l2_bootmap + i * PAGE_SIZE,
                                       __PAGE_HYPERVISOR);
    /*
     * Map Xen into the directmap (needed for early-boot pagetable
     * handling/walking), and identity map Xen into bootmap (needed for the
     * transition from the EFI pagetables to Xen), using 2M superpages.
     *
     * NB: We are currently in physical mode, so a RIP-relative relocation
     * against _start/_end gets their real position in memory, which are the
     * appropriate l2 slots to map.
     */
#define l2_4G_offset(a)                                                 \
    (((a) >> L2_PAGETABLE_SHIFT) & (4 * L2_PAGETABLE_ENTRIES - 1))

    for ( i  = l2_4G_offset((unsigned long)_start);
          i <= l2_4G_offset((unsigned long)_end - 1); ++i )
    {
        l2_pgentry_t pte = l2e_from_paddr(i << L2_PAGETABLE_SHIFT,
                                          __PAGE_HYPERVISOR | _PAGE_PSE);

        l2_bootmap[i] = pte;

        /* Bootmap RWX/Non-global.  Directmap RW/Global. */
        l2e_add_flags(pte, PAGE_HYPERVISOR);

        l2_directmap[i] = pte;
    }
#undef l2_4G_offset
}
