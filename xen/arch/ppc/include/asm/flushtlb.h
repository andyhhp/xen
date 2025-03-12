/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_PPC_FLUSHTLB_H__
#define __ASM_PPC_FLUSHTLB_H__

#include <xen/cpumask.h>

/* Flush specified CPUs' TLBs */
void arch_flush_tlb_mask(const cpumask_t *mask);

#endif /* __ASM_PPC_FLUSHTLB_H__ */
