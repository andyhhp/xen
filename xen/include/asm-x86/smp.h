#ifndef __ASM_SMP_H
#define __ASM_SMP_H

/*
 * We need the APIC definitions automatically as part of 'smp.h'
 */
#ifndef __ASSEMBLY__
#include <xen/kernel.h>
#include <xen/cpumask.h>
#include <asm/current.h>
#endif

#ifndef __ASSEMBLY__
#include <xen/bitops.h>
#include <asm/mpspec.h>
#endif

#define BAD_APICID   (-1U)
#define INVALID_CUID (~0U)   /* AMD Compute Unit ID */
#ifndef __ASSEMBLY__

DECLARE_PER_CPU(paddr_t, percpu_idle_pt);

/*
 * Private routines/data
 */
DECLARE_PER_CPU(cpumask_var_t, cpu_sibling_mask);
DECLARE_PER_CPU(cpumask_var_t, cpu_core_mask);
DECLARE_PER_CPU(cpumask_var_t, scratch_cpumask);

void smp_send_nmi_allbutself(void);

void send_IPI_mask(const cpumask_t *, int vector);
void send_IPI_self(int vector);

extern void (*mtrr_hook) (void);

extern void zap_low_mappings(void);

extern u32 x86_cpu_to_apicid[];

#define cpu_physical_id(cpu)	x86_cpu_to_apicid[cpu]

#define cpu_is_offline(cpu) unlikely(!cpu_online(cpu))
extern void cpu_exit_clear(unsigned int cpu);
extern void cpu_uninit(unsigned int cpu);
int cpu_add(uint32_t apic_id, uint32_t acpi_id, uint32_t pxm);

/*
 * This function is needed by all SMP systems. It must _always_ be valid
 * from the initial startup. We map APIC_BASE very early in page_setup(),
 * so this is correct in the x86 case.
 */
#define raw_smp_processor_id() (get_processor_id())

void __stop_this_cpu(void);

void cpu_smpboot_bsp(void);
long cpu_up_helper(void *data);
long cpu_down_helper(void *data);

long core_parking_helper(void *data);
uint32_t get_cur_idle_nums(void);

/*
 * The value may be greater than the actual socket number in the system and
 * is required not to change from the initial startup.
 */
extern unsigned int nr_sockets;

void set_nr_sockets(void);

/* Representing HT and core siblings in each socket. */
extern cpumask_t **socket_cpumask;

static inline bool arch_ipi_param_ok(const void *_param)
{
    unsigned long param = (unsigned long)_param;

    /*
     * It is not safe to pass pointers in the PERCPU linear range to other
     * cpus in an IPI.
     *
     * Not all parameters passed are actually pointers, so only reject
     * parameters which are a canonical address in the PERCPU range.
     */
    return (!is_canonical_address(param) ||
            l4_table_offset(param) != l4_table_offset(PERCPU_LINEAR_START));
}

#endif /* !__ASSEMBLY__ */

#endif
