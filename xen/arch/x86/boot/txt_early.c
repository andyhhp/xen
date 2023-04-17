/*
 * Copyright (c) 2022-2023 3mdeb Sp. z o.o. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This entry point is entered from xen/arch/x86/boot/head.S with Xen base at
 * 0x4(%esp). A pointer to MBI is returned in %eax.
 */
asm (
    "    .text                         \n"
    "    .globl _start                 \n"
    "_start:                           \n"
    "    jmp  txt_early_tests          \n"
    );

#include "defs.h"
#include "../include/asm/intel_txt.h"

static void verify_pmr_ranges(struct txt_os_mle_data *os_mle,
                              struct txt_os_sinit_data *os_sinit,
                              uint32_t load_base_addr, uint32_t tgt_base_addr,
                              uint32_t xen_size)
{
    int check_high_pmr = 0;

    /* Verify the value of the low PMR base. It should always be 0. */
    if (os_sinit->vtd_pmr_lo_base != 0)
        txt_reset(SLAUNCH_ERROR_LO_PMR_BASE);

    /*
     * Low PMR size should not be 0 on current platforms. There is an ongoing
     * transition to TPR-based DMA protection instead of PMR-based; this is not
     * yet supported by the code.
     */
    if (os_sinit->vtd_pmr_lo_size == 0)
        txt_reset(SLAUNCH_ERROR_LO_PMR_BASE);

    /* Check if regions overlap. Treat regions with no hole between as error. */
    if (os_sinit->vtd_pmr_hi_size != 0 &&
        os_sinit->vtd_pmr_hi_base <= os_sinit->vtd_pmr_lo_size)
        txt_reset(SLAUNCH_ERROR_HI_PMR_BASE);

    /* All regions accessed by 32b code must be below 4G. */
    if (os_sinit->vtd_pmr_hi_base + os_sinit->vtd_pmr_hi_size <= 0x100000000ull)
        check_high_pmr = 1;

    /*
     * ACM checks that TXT heap and MLE memory is protected against DMA. We have
     * to check if MBI and whole Xen memory is protected. The latter is done in
     * case bootloader failed to set whole image as MLE and to make sure that
     * both pre- and post-relocation code is protected.
     */

    /* Check if all of Xen before relocation is covered by PMR. */
    if (!is_in_pmr(os_sinit, load_base_addr, xen_size, check_high_pmr))
        txt_reset(SLAUNCH_ERROR_LO_PMR_MLE);

    /* Check if all of Xen after relocation is covered by PMR. */
    if (load_base_addr != tgt_base_addr &&
        !is_in_pmr(os_sinit, tgt_base_addr, xen_size, check_high_pmr))
        txt_reset(SLAUNCH_ERROR_LO_PMR_MLE);

    /* Check if MBI is covered by PMR. MBI starts with 'uint32_t total_size'. */
    if (!is_in_pmr(os_sinit, os_mle->boot_params_addr,
                   *(uint32_t *)os_mle->boot_params_addr, check_high_pmr))
        txt_reset(SLAUNCH_ERROR_BUFFER_BEYOND_PMR);

    /* Check if TPM event log (if present) is covered by PMR. */
    /*
     * FIXME: currently commented out as GRUB allocates it in a hole between
     * PMR and reserved RAM, due to 2MB resolution of PMR. There are no other
     * easy-to-use DMA protection mechanisms that would allow to protect that
     * part of memory. TPR (TXT DMA Protection Range) gives 1MB resolution, but
     * it still wouldn't be enough.
     *
     * One possible solution would be for GRUB to allocate log at lower address,
     * but this would further increase memory space fragmentation. Another
     * option is to align PMR up instead of down, making PMR cover part of
     * reserved region, but it is unclear what the consequences may be.
     *
     * In tboot this issue was resolved by reserving leftover chunks of memory
     * in e820 and/or UEFI memory map. This is also a valid solution, but would
     * require more changes to GRUB than the ones listed above, as event log is
     * allocated much earlier than PMRs.
     */
    /*
    if (os_mle->evtlog_addr != 0 && os_mle->evtlog_size != 0 &&
        !is_in_pmr(os_sinit, os_mle->evtlog_addr, os_mle->evtlog_size,
                   check_high_pmr))
        txt_reset(SLAUNCH_ERROR_BUFFER_BEYOND_PMR);
    */
}

uint32_t __stdcall txt_early_tests(uint32_t load_base_addr,
                                   uint32_t tgt_base_addr,
                                   uint32_t tgt_end_addr)
{
    void *txt_heap;
    struct txt_os_mle_data *os_mle;
    struct txt_os_sinit_data *os_sinit;
    uint32_t size = tgt_end_addr - tgt_base_addr;

    /* Clear the TXT error registers for a clean start of day */
    write_txt_reg(TXTCR_ERRORCODE, 0);

    txt_heap = _p(read_txt_reg(TXTCR_HEAP_BASE));

    if (txt_os_mle_data_size(txt_heap) < sizeof(*os_mle) ||
        txt_os_sinit_data_size(txt_heap) < sizeof(*os_sinit))
        txt_reset(SLAUNCH_ERROR_GENERIC);

    os_mle = txt_os_mle_data_start(txt_heap);
    os_sinit = txt_os_sinit_data_start(txt_heap);

    verify_pmr_ranges(os_mle, os_sinit, load_base_addr, tgt_base_addr, size);

    return os_mle->boot_params_addr;
}
