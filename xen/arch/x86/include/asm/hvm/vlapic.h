/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * hvm_vlapic.h: virtualize LAPIC definitions.
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2006 Keir Fraser, XenSource Inc.
 */

#ifndef __ASM_X86_HVM_VLAPIC_H__
#define __ASM_X86_HVM_VLAPIC_H__

#include <xen/tasklet.h>
#include <asm/hvm/vpt.h>

#define vcpu_vlapic(x)   (&(x)->arch.hvm.vlapic)
#define vlapic_vcpu(x)   (container_of((x), struct vcpu, arch.hvm.vlapic))
#define const_vlapic_vcpu(x) (container_of((x), const struct vcpu, \
                              arch.hvm.vlapic))
#define vlapic_domain(x) (vlapic_vcpu(x)->domain)

#define _VLAPIC_ID(vlapic, id) (vlapic_x2apic_mode(vlapic) \
                                ? (id) : GET_xAPIC_ID(id))
#define VLAPIC_ID(vlapic) _VLAPIC_ID(vlapic, vlapic_get_reg(vlapic, APIC_ID))

/*
 * APIC can be disabled in two ways:
 *  1. 'Hardware disable': via IA32_APIC_BASE_MSR[11]
 *     CPU should behave as if it does not have an APIC.
 *  2. 'Software disable': via APIC_SPIV[8].
 *     APIC is visible but does not respond to interrupt messages.
 */
#define VLAPIC_HW_DISABLED              0x1
#define VLAPIC_SW_DISABLED              0x2
#define vlapic_sw_disabled(vlapic) ((vlapic)->hw.disabled & VLAPIC_SW_DISABLED)
#define vlapic_hw_disabled(vlapic) ((vlapic)->hw.disabled & VLAPIC_HW_DISABLED)
#define vlapic_disabled(vlapic)    ((vlapic)->hw.disabled)
#define vlapic_enabled(vlapic)     (!vlapic_disabled(vlapic))

#define vlapic_base_address(vlapic)                             \
    ((vlapic)->hw.apic_base_msr & APIC_BASE_ADDR_MASK)
/* Only check EXTD bit as EXTD can't be set if it is disabled by hardware */
#define vlapic_x2apic_mode(vlapic)                              \
    ((vlapic)->hw.apic_base_msr & APIC_BASE_EXTD)
#define vlapic_xapic_mode(vlapic)                               \
    (!vlapic_hw_disabled(vlapic) && \
     !((vlapic)->hw.apic_base_msr & APIC_BASE_EXTD))

/*
 * Generic APIC bitmap vector update & search routines.
 */

#define VEC_POS(v) ((v) % 32)
#define REG_POS(v) (((v) / 32) * 0x10)
#define vlapic_test_vector(vec, bitmap)                                 \
    test_bit(VEC_POS(vec), (const uint32_t *)((bitmap) + REG_POS(vec)))
#define vlapic_test_and_set_vector(vec, bitmap)                         \
    test_and_set_bit(VEC_POS(vec), (uint32_t *)((bitmap) + REG_POS(vec)))
#define vlapic_test_and_clear_vector(vec, bitmap)                       \
    test_and_clear_bit(VEC_POS(vec), (uint32_t *)((bitmap) + REG_POS(vec)))
#define vlapic_set_vector(vec, bitmap)                                  \
    set_bit(VEC_POS(vec), (uint32_t *)((bitmap) + REG_POS(vec)))
#define vlapic_clear_vector(vec, bitmap)                                \
    clear_bit(VEC_POS(vec), (uint32_t *)((bitmap) + REG_POS(vec)))

struct vlapic {
    struct hvm_hw_lapic      hw;
    struct hvm_hw_lapic_regs *regs;
    struct {
        bool                 hw, regs;
        uint32_t             id, ldr;
    }                        loaded;
    struct periodic_time     pt;
    s_time_t                 timer_last_update;
    struct page_info         *regs_page;
    /* INIT-SIPI-SIPI work gets deferred to a tasklet. */
    struct {
        uint32_t             icr, dest;
        struct tasklet       tasklet;
    } init_sipi;
};

/* vlapic's frequence is 100 MHz */
#define APIC_BUS_CYCLE_NS               10

static inline uint32_t vlapic_get_reg(const struct vlapic *vlapic,
                                      uint32_t reg)
{
    return *((uint32_t *)(&vlapic->regs->data[reg]));
}

static inline void vlapic_set_reg(
    struct vlapic *vlapic, uint32_t reg, uint32_t val)
{
    *((uint32_t *)(&vlapic->regs->data[reg])) = val;
}

void vlapic_reg_write(struct vcpu *v, unsigned int reg, uint32_t val);

bool is_vlapic_lvtpc_enabled(struct vlapic *vlapic);

bool vlapic_test_irq(const struct vlapic *vlapic, uint8_t vec);
void vlapic_set_irq(struct vlapic *vlapic, uint8_t vec, uint8_t trig);

int vlapic_has_pending_irq(struct vcpu *v);
int vlapic_ack_pending_irq(struct vcpu *v, int vector, bool force_ack);

int  vlapic_init(struct vcpu *v);
void vlapic_destroy(struct vcpu *v);

void vlapic_reset(struct vlapic *vlapic);

int guest_wrmsr_apic_base(struct vcpu *v, uint64_t val);
int guest_rdmsr_x2apic(const struct vcpu *v, uint32_t msr, uint64_t *val);
int guest_wrmsr_x2apic(struct vcpu *v, uint32_t msr, uint64_t val);

void vlapic_tdt_msr_set(struct vlapic *vlapic, uint64_t value);
uint64_t vlapic_tdt_msr_get(struct vlapic *vlapic);

int vlapic_accept_pic_intr(struct vcpu *v);
uint32_t vlapic_set_ppr(struct vlapic *vlapic);

void vlapic_adjust_i8259_target(struct domain *d);

void vlapic_EOI_set(struct vlapic *vlapic);
void vlapic_handle_EOI(struct vlapic *vlapic, u8 vector);

void vlapic_ipi(struct vlapic *vlapic, uint32_t icr_low, uint32_t icr_high);

int vlapic_apicv_write(struct vcpu *v, unsigned int offset);

struct vlapic *vlapic_lowest_prio(
    struct domain *d, const struct vlapic *source,
    int short_hand, uint32_t dest, bool dest_mode);

bool vlapic_match_dest(
    const struct vlapic *target, const struct vlapic *source,
    int short_hand, uint32_t dest, bool dest_mode);

#endif /* __ASM_X86_HVM_VLAPIC_H__ */
