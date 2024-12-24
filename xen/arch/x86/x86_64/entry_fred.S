/* SPDX-License-Identifier: GPL-2.0-or-later */

        .file "x86_64/entry_fred.S"

#include <asm/asm_defns.h>

        .section .text.entry, "ax", @progbits

        /* CPL3 entry point is required to be 4k aligned. */

FUNC(entry_FRED_CPL3, 4096)
        ENDBR64

        SAVE_ALL

        mov     %rsp, %rdi
        call    entry_from_guest

        RESTORE_ALL

        eretu
END(entry_FRED_CPL3)

        /* CPL0 entrypoint is at CPL3 + 256. */
        .org entry_FRED_CPL3 + 256, 0xcc

FUNC_LOCAL(entry_FRED_CPL0, 0)
        ENDBR64

        SAVE_ALL

        mov     %rsp, %rdi
        call    entry_from_xen

        RESTORE_ALL

        erets
END(entry_FRED_CPL0)
