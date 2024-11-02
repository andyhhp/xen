/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2024 Christopher Clark <christopher.w.clark@gmail.com>
 * Copyright (c) 2024 Apertus Solutions, LLC
 * Author: Daniel P. Smith <dpsmith@apertussolutions.com>
 */

#ifndef X86_BOOTINFO_H
#define X86_BOOTINFO_H

#include <xen/multiboot.h>
#include <xen/types.h>

/* Max number of boot modules a bootloader can provide in addition to Xen */
#define MAX_NR_BOOTMODS 63

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
    /* Transitionary only */
    module_t *mod;

    enum bootmod_type type;
};

/*
 * Xen internal representation of information provided by the
 * bootloader/environment, or derived from the information.
 */
struct boot_info {
    const char *loader;
    const char *cmdline;

    paddr_t memmap_addr;
    size_t memmap_length;

    unsigned int nr_modules;
    struct boot_module mods[MAX_NR_BOOTMODS + 1];
};

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

/*
 * first_boot_module_index:
 *     Finds the first boot module of type t.
 *
 * Returns:
 *      Success - index in boot_module array
 *      Failure - a value greater than MAX_NR_BOOTMODS
 */
#define first_boot_module_index(bi, t)          \
    next_boot_module_index(bi, t, 0)

#define for_each_boot_module_by_type(i, b, t)           \
    for ( (i) = first_boot_module_index(b, t);          \
          (i) <= (b)->nr_modules;                       \
          (i) = next_boot_module_index(b, t, i + 1) )

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
