/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/efi.h>
#include <xen/init.h>
#include <xen/multiboot2.h>
#include <asm/asm_defns.h>
#include <asm/efi.h>
#include <asm/io.h>

static void __init
out_char(char c)
{
    enum {
        io_base = 0x3f8,
        data_port = io_base,
        status_port = io_base + 5,

        thr_empty = 0x20,
    };

    /* wait space available */
    while ((inb(status_port) & thr_empty) == 0)
        continue;
    outb(c, data_port);
}

static void __init
out_string(const char *s)
{
    for (; *s; ++s)
        out_char(*s);
}

static void __init
out_byte_hex(uint8_t byte)
{
    static const char hex[] = "0123456789abcdef";
    out_char(hex[(byte >> 4) & 0xf]);
    out_char(hex[(byte >> 0) & 0xf]);
    out_char(',');
}

static void __init
out_buf(const void *start, const void *end)
{
    out_string("Buffer: ");
    for (const uint8_t *p = start; (const void *)p < end; ++p)
        out_byte_hex(*p);
    out_string("\r\n");
}

const char * asmlinkage __init
efi_multiboot2_prelude(uint32_t magic, const multiboot2_fixed_t *mbi)
{
    const multiboot2_tag_t *tag;
    EFI_HANDLE ImageHandle = NULL;
    EFI_SYSTEM_TABLE *SystemTable = NULL;
    const char *cmdline = NULL;
    bool have_bs = false;
    const void *mbi_copy = mbi;

    if ( magic != MULTIBOOT2_BOOTLOADER_MAGIC )
        return "ERR: Not a Multiboot2 bootloader!";

    /* dump header pointer */
    out_buf(&mbi_copy, (&mbi_copy) + 1);

    /* dump just header */
    out_buf(mbi, mbi + 1);

    /* dump all buffer */
    out_buf(mbi, (const void *)mbi + mbi->total_size);

    /* Skip Multiboot2 information fixed part. */
    tag = _p(ROUNDUP((unsigned long)(mbi + 1), MULTIBOOT2_TAG_ALIGN));

    for ( ; (const void *)tag - (const void *)mbi < mbi->total_size &&
            tag->type != MULTIBOOT2_TAG_TYPE_END;
          tag = _p(ROUNDUP((unsigned long)tag + tag->size,
                   MULTIBOOT2_TAG_ALIGN)) )
    {
        switch ( tag->type )
        {
        case MULTIBOOT2_TAG_TYPE_EFI_BS:
            have_bs = true;
            break;

        case MULTIBOOT2_TAG_TYPE_EFI64:
            SystemTable = _p(((const multiboot2_tag_efi64_t *)tag)->pointer);
            break;

        case MULTIBOOT2_TAG_TYPE_EFI64_IH:
            ImageHandle = _p(((const multiboot2_tag_efi64_ih_t *)tag)->pointer);
            break;

        case MULTIBOOT2_TAG_TYPE_CMDLINE:
            cmdline = ((const multiboot2_tag_string_t *)tag)->string;
            break;

        default:
            /* Satisfy MISRA requirement. */
            break;
        }
    }

    if ( !have_bs )
        return "ERR: Bootloader shutdown EFI x64 boot services!";
    if ( !SystemTable )
        return "ERR: EFI SystemTable is not provided by bootloader!";
    if ( !ImageHandle )
        return "ERR: EFI ImageHandle is not provided by bootloader!";

    efi_multiboot2(ImageHandle, SystemTable, cmdline);

    return NULL;
}
