/*
 * Copyright (C) 2007 Advanced Micro Devices, Inc.
 * Author: Leo Duran <leo.duran@amd.com>
 * Author: Wei Wang <wei.wang2@amd.com> - adapted to xen
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
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/acpi.h>
#include <xen/pci.h>

#include "iommu.h"

static int __init get_iommu_msi_capabilities(
    pci_sbdf_t sbdf, struct amd_iommu *iommu)
{
    int pos;

    pos = pci_find_cap_offset(sbdf, PCI_CAP_ID_MSI);

    if ( !pos )
        return -ENODEV;

    AMD_IOMMU_DEBUG("Found MSI capability block at %#x\n", pos);

    iommu->msi.msi_attrib.type = PCI_CAP_ID_MSI;
    iommu->msi.msi_attrib.pos = pos;
    iommu->msi.msi_attrib.is_64 = 1;
    return 0;
}

static int __init get_iommu_capabilities(
    pci_sbdf_t sbdf, u16 cap_ptr, struct amd_iommu *iommu)
{
    u8 type;

    iommu->cap.header = pci_conf_read32(sbdf, cap_ptr);
    type = get_field_from_reg_u32(iommu->cap.header, PCI_CAP_TYPE_MASK,
                                  PCI_CAP_TYPE_SHIFT);

    if ( type != PCI_CAP_TYPE_IOMMU )
        return -ENODEV;

    return 0;
}

void __init get_iommu_features(struct amd_iommu *iommu)
{
    const struct amd_iommu *first;
    ASSERT( iommu->mmio_base );

    if ( !(amd_iommu_acpi_info & ACPI_IVRS_EFR_SUP) )
    {
        if ( !iommu_has_cap(iommu, PCI_CAP_EFRSUP_SHIFT) )
            return;

        iommu->features.raw =
            readq(iommu->mmio_base + IOMMU_EXT_FEATURE_MMIO_OFFSET);

        if ( 4 + iommu->features.flds.hats < amd_iommu_max_paging_mode )
            amd_iommu_max_paging_mode = 4 + iommu->features.flds.hats;
    }

    /* Don't log the same set of features over and over. */
    first = list_first_entry(&amd_iommu_head, struct amd_iommu, list);
    if ( iommu != first && iommu->features.raw == first->features.raw )
        return;

    printk("AMD-Vi: IOMMU Extended Features:\n");

#define FEAT(fld, str) do {                                    \
    if ( --((union amd_iommu_ext_features){}).flds.fld > 1 )   \
        printk( "- " str ": %#x\n", iommu->features.flds.fld); \
    else if ( iommu->features.flds.fld )                       \
        printk( "- " str "\n");                                \
} while ( false )

    FEAT(pref_sup,           "Prefetch Pages Command");
    FEAT(ppr_sup,            "Peripheral Page Service Request");
    FEAT(xt_sup,             "x2APIC");
    FEAT(nx_sup,             "NX bit");
    FEAT(gappi_sup,          "Guest APIC Physical Processor Interrupt");
    FEAT(ia_sup,             "Invalidate All Command");
    FEAT(ga_sup,             "Guest APIC");
    FEAT(he_sup,             "Hardware Error Registers");
    FEAT(pc_sup,             "Performance Counters");
    FEAT(hats,               "Host Address Translation Size");

    if ( iommu->features.flds.gt_sup )
    {
        FEAT(gats,           "Guest Address Translation Size");
        FEAT(glx_sup,        "Guest CR3 Root Table Level");
        FEAT(pas_max,        "Maximum PASID");
    }

    FEAT(smif_sup,           "SMI Filter Register");
    FEAT(smif_rc,            "SMI Filter Register Count");
    FEAT(gam_sup,            "Guest Virtual APIC Modes");
    FEAT(dual_ppr_log_sup,   "Dual PPR Log");
    FEAT(dual_event_log_sup, "Dual Event Log");
    FEAT(sats_sup,           "Secure ATS");
    FEAT(us_sup,             "User / Supervisor Page Protection");
    FEAT(dev_tbl_seg_sup,    "Device Table Segmentation");
    FEAT(ppr_early_of_sup,   "PPR Log Overflow Early Warning");
    FEAT(ppr_auto_rsp_sup,   "PPR Automatic Response");
    FEAT(marc_sup,           "Memory Access Routing and Control");
    FEAT(blk_stop_mrk_sup,   "Block StopMark Message");
    FEAT(perf_opt_sup ,      "Performance Optimization");
    FEAT(msi_cap_mmio_sup,   "MSI Capability MMIO Access");
    FEAT(gio_sup,            "Guest I/O Protection");
    FEAT(ha_sup,             "Host Access");
    FEAT(eph_sup,            "Enhanced PPR Handling");
    FEAT(attr_fw_sup,        "Attribute Forward");
    FEAT(hd_sup,             "Host Dirty");
    FEAT(inv_iotlb_type_sup, "Invalidate IOTLB Type");
    FEAT(viommu_sup,         "Virtualized IOMMU");
    FEAT(vm_guard_io_sup,    "VMGuard I/O Support");
    FEAT(vm_table_size,      "VM Table Size");
    FEAT(ga_update_dis_sup,  "Guest Access Bit Update Disable");

#undef FEAT
}

int __init amd_iommu_detect_one_acpi(
    const struct acpi_ivrs_hardware *ivhd_block)
{
    struct amd_iommu *iommu;
    u8 bus, dev, func;
    int rt = 0;

    if ( ivhd_block->header.length < sizeof(*ivhd_block) )
    {
        AMD_IOMMU_ERROR("invalid IVHD block length\n");
        return -ENODEV;
    }

    if ( !ivhd_block->header.device_id ||
        !ivhd_block->capability_offset || !ivhd_block->base_address)
    {
        AMD_IOMMU_ERROR("invalid IVHD block\n");
        return -ENODEV;
    }

    iommu = xzalloc(struct amd_iommu);
    if ( !iommu )
    {
        AMD_IOMMU_ERROR("cannot allocate amd_iommu\n");
        return -ENOMEM;
    }

    spin_lock_init(&iommu->lock);
    INIT_LIST_HEAD(&iommu->ats_devices);

    iommu->sbdf = PCI_SBDF(ivhd_block->pci_segment_group,
                           ivhd_block->header.device_id);
    iommu->cap_offset = ivhd_block->capability_offset;
    iommu->mmio_base_phys = ivhd_block->base_address;

    if ( ivhd_type != ACPI_IVRS_TYPE_HARDWARE )
        iommu->features.raw = ivhd_block->efr_image;
    else if ( amd_iommu_acpi_info & ACPI_IVRS_EFR_SUP )
    {
        union {
            uint32_t raw;
            struct {
                unsigned int xt_sup:1;
                unsigned int nx_sup:1;
                unsigned int gt_sup:1;
                unsigned int glx_sup:2;
                unsigned int ia_sup:1;
                unsigned int ga_sup:1;
                unsigned int he_sup:1;
                unsigned int pas_max:5;
                unsigned int pn_counters:4;
                unsigned int pn_banks:6;
                unsigned int msi_num_ppr:5;
                unsigned int gats:2;
                unsigned int hats:2;
            };
        } attr = { .raw = ivhd_block->iommu_attr };

        iommu->features.flds.xt_sup = attr.xt_sup;
        iommu->features.flds.nx_sup = attr.nx_sup;
        iommu->features.flds.gt_sup = attr.gt_sup;
        iommu->features.flds.glx_sup = attr.glx_sup;
        iommu->features.flds.ia_sup = attr.ia_sup;
        iommu->features.flds.ga_sup = attr.ga_sup;
        iommu->features.flds.pas_max = attr.pas_max;
        iommu->features.flds.gats = attr.gats;
        iommu->features.flds.hats = attr.hats;
    }
    else if ( list_empty(&amd_iommu_head) )
        AMD_IOMMU_DEBUG("EFRSup not set in ACPI table; will fall back to hardware\n");

    if ( (amd_iommu_acpi_info & ACPI_IVRS_EFR_SUP) &&
         4 + iommu->features.flds.hats < amd_iommu_max_paging_mode )
        amd_iommu_max_paging_mode = 4 + iommu->features.flds.hats;

    /* override IOMMU HT flags */
    iommu->ht_flags = ivhd_block->header.flags;

    bus = PCI_BUS(iommu->sbdf.bdf);
    dev = PCI_SLOT(iommu->sbdf.bdf);
    func = PCI_FUNC(iommu->sbdf.bdf);

    rt = get_iommu_capabilities(iommu->sbdf, iommu->cap_offset, iommu);
    if ( rt )
        goto out;

    rt = get_iommu_msi_capabilities(iommu->sbdf, iommu);
    if ( rt )
        goto out;

    iommu->domid_map = iommu_init_domid(DOMID_INVALID);
    rt = -ENOMEM;
    if ( !iommu->domid_map )
        goto out;

    rt = pci_ro_device(iommu->sbdf.seg, bus, PCI_DEVFN(dev, func));
    if ( rt )
        printk(XENLOG_ERR "Could not mark config space of %pp read-only (%d)\n",
               &iommu->sbdf, rt);

    list_add_tail(&iommu->list, &amd_iommu_head);
    rt = 0;

 out:
    if ( rt )
    {
        xfree(iommu->domid_map);
        xfree(iommu);
    }

    return rt;
}
