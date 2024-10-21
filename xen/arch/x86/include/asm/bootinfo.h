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
};

struct boot_module {
    /* Transitionary only */
    module_t *mod;

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
    unsigned long *module_map; /* Temporary */
    struct boot_module mods[MAX_NR_BOOTMODS + 1];
};

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
