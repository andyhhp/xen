/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2024 Christopher Clark <christopher.w.clark@gmail.com>
 * Copyright (c) 2024 Apertus Solutions, LLC
 * Author: Daniel P. Smith <dpsmith@apertussolutions.com>
 */

#ifndef X86_BOOTINFO_H
#define X86_BOOTINFO_H

#include <xen/types.h>
#include <asm/bootdomain.h>

/* Max number of boot modules a bootloader can provide in addition to Xen */
#define MAX_NR_BOOTMODS 63

/* Max number of boot domains that Xen can construct */
#define MAX_NR_BOOTDOMS 1

/* Boot module binary type / purpose */
enum bootmod_type {
    BOOTMOD_UNKNOWN,
    BOOTMOD_XEN,
    BOOTMOD_KERNEL,
    BOOTMOD_RAMDISK,
    BOOTMOD_MICROCODE,
    BOOTMOD_XSM_POLICY,
};

struct boot_module {
    /*
     * A boot module may contain a compressed kernel that will require
     * additional space, before the module data, into which the kernel will be
     * decompressed.
     *
     * Memory layout at boot:
     *     [ compressed kernel ]
     * After boot module relocation:
     *     [ estimated headroom + PAGE_SIZE rounding ][ compressed kernel ]
     * After kernel decompression:
     *     [ decompressed kernel ][ unused rounding ]
     */
    unsigned long headroom;
    enum bootmod_type type;

    /*
     * Module State Flags:
     *   relocated: indicates module has been relocated in memory.
     *   consumed:  indicates that the subystem that claimed the module has
     *              finished with it.
     */
    bool relocated:1;
    bool consumed:1;

    paddr_t cmdline;

    paddr_t start;
    size_t size;
};

/*
 * Xen internal representation of information provided by the
 * bootloader/environment, or derived from the information.
 */
struct boot_info {
    const char *loader;
    const char *cmdline;
    const char *kextra;

    paddr_t memmap_addr;
    size_t memmap_length;

    unsigned int nr_modules;
    struct boot_module mods[MAX_NR_BOOTMODS + 1];
    struct boot_domain domains[MAX_NR_BOOTDOMS];
};

static inline struct boot_module *__init next_boot_module_by_type(
    struct boot_info *bi, struct boot_module *bm, enum bootmod_type t)
{
    if ( bm == NULL )
        bm = &bi->mods[0];
    else
        bm++;

    for ( ; bm <= &bi->mods[bi->nr_modules]; bm++ )
    {
        if ( bm->type == t )
            return bm;
    }

    return NULL;
}

#define for_each_boot_module(bi, bm, t)                                     \
    for ( bm = &bi->mods[0]; bm != NULL && bm <= &bi->mods[bi->nr_modules]; \
          bm = next_boot_module_by_type(bi, bm, t) )

#define boot_module_index(bi, bm)                   \
    (unsigned int)(bm - &bi->mods[0])

/*
 * next_boot_module_index:
 *     Finds the next boot module of type t, starting at array index start.
 *
 * Returns:
 *      Success - index in boot_module array
 *      Failure - a value greater than MAX_NR_BOOTMODS
 */
static inline unsigned int __init next_boot_module_index(
    const struct boot_info *bi, enum bootmod_type t, unsigned int start)
{
    unsigned int i;

    if ( t == BOOTMOD_XEN )
        return bi->nr_modules;

    for ( i = start; i < bi->nr_modules; i++ )
    {
        if ( bi->mods[i].type == t )
            return i;
    }

    return MAX_NR_BOOTMODS + 1;
}

#define first_boot_module_index(bi, t)              \
    next_boot_module_index(bi, t, 0)

#endif /* X86_BOOTINFO_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
