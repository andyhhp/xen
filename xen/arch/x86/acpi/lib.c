/*
 *  lib.c - Architecture-Specific Low-Level ACPI Support
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <xen/errno.h>
#include <xen/init.h>
#include <xen/acpi.h>
#include <asm/apic.h>
#include <asm/fixmap.h>

u32 __read_mostly acpi_smi_cmd;
u8 __read_mostly acpi_enable_value;
u8 __read_mostly acpi_disable_value;

u32 __read_mostly x86_acpiid_to_apicid[MAX_MADT_ENTRIES] =
    {[0 ... MAX_MADT_ENTRIES - 1] = BAD_APICID };

/*
 * Important Safety Note:  The fixed ACPI page numbers are *subtracted*
 * from the fixed base.  That's why we start at FIX_ACPI_END and
 * count idx down while incrementing the phys address.
 */
char *__acpi_map_table(paddr_t phys, unsigned long size)
{
	unsigned long base, offset, mapped_size;
	int idx;

	/* XEN: RAM holes above 1MB are not permanently mapped. */
	if ((phys + size) <= (1 * 1024 * 1024))
		return __va(phys);

	offset = phys & (PAGE_SIZE - 1);
	mapped_size = PAGE_SIZE - offset;
	set_fixmap(FIX_ACPI_END, phys);
	base = __fix_to_virt(FIX_ACPI_END);

	/*
	 * Most cases can be covered by the below.
	 */
	idx = FIX_ACPI_END;
	while (mapped_size < size) {
		if (--idx < FIX_ACPI_BEGIN)
			return NULL;	/* cannot handle this */
		phys += PAGE_SIZE;
		set_fixmap(idx, phys);
		mapped_size += PAGE_SIZE;
	}

	return ((char *) base + offset);
}

unsigned int acpi_get_processor_id(unsigned int cpu)
{
	unsigned int acpiid, apicid;

	if ((apicid = x86_cpu_to_apicid[cpu]) == BAD_APICID)
		return INVALID_ACPIID;

	for (acpiid = 0; acpiid < ARRAY_SIZE(x86_acpiid_to_apicid); acpiid++)
		if (x86_acpiid_to_apicid[acpiid] == apicid)
			return acpiid;

	return INVALID_ACPIID;
}

int arch_acpi_set_pdc_bits(u32 acpi_id, u32 *pdc, u32 mask)
{
	unsigned int cpu = get_cpu_id(acpi_id);
	struct cpuinfo_x86 *c;

	if (!(acpi_id + 1))
		c = &boot_cpu_data;
	else if (cpu >= nr_cpu_ids || !cpu_online(cpu))
		return -EINVAL;
	else
		c = cpu_data + cpu;

	pdc[2] |= ACPI_PDC_C_CAPABILITY_SMP & mask;

	if (cpu_has(c, X86_FEATURE_EIST))
		pdc[2] |= ACPI_PDC_EST_CAPABILITY_SWSMP & mask;

	if (cpu_has(c, X86_FEATURE_ACPI))
		pdc[2] |= ACPI_PDC_T_FFH & mask;

	/*
	 * If mwait/monitor or its break-on-interrupt extension are
	 * unsupported, Cx_FFH will be disabled.
	 */
	if ( !cpu_has_xen_monitor )
		pdc[2] &= ~(ACPI_PDC_C_C1_FFH | ACPI_PDC_C_C2C3_FFH);

	return 0;
}
