/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * vmx.h: VMX Architecture related definitions
 * Copyright (c) 2004, Intel Corporation.
 *
 */
#ifndef __ASM_X86_HVM_VMX_VMX_H__
#define __ASM_X86_HVM_VMX_VMX_H__

#include <xen/sched.h>
#include <xen/types.h>

#include <asm/regs.h>
#include <asm/asm_defns.h>
#include <asm/processor.h>
#include <asm/p2m.h>
#include <asm/i387.h>
#include <asm/hvm/vmx/vmcs.h>

extern int8_t opt_ept_exec_sp;

typedef union {
    struct {
        u64 r       :   1,  /* bit 0 - Read permission */
        w           :   1,  /* bit 1 - Write permission */
        x           :   1,  /* bit 2 - Execute permission */
        emt         :   3,  /* bits 5:3 - EPT Memory type */
        ipat        :   1,  /* bit 6 - Ignore PAT memory type */
        sp          :   1,  /* bit 7 - Is this a superpage? */
        a           :   1,  /* bit 8 - Access bit */
        d           :   1,  /* bit 9 - Dirty bit */
        recalc      :   1,  /* bit 10 - Software available 1 */
        snp         :   1,  /* bit 11 - VT-d snoop control in shared
                               EPT/VT-d usage */
        mfn         :   40, /* bits 51:12 - Machine physical frame number */
        sa_p2mt     :   6,  /* bits 57:52 - Software available 2 */
        pw          :   1,  /* bit 58 - Paging-write access */
        access      :   4,  /* bits 62:59 - p2m_access_t */
        suppress_ve :   1;  /* bit 63 - suppress #VE */
    };
    u64 epte;
} ept_entry_t;

typedef struct {
    /*use lxe[0] to save result */
    ept_entry_t lxe[5];
} ept_walk_t;

typedef enum {
    ept_access_n     = 0, /* No access permissions allowed */
    ept_access_r     = 1, /* Read only */
    ept_access_w     = 2, /* Write only */
    ept_access_rw    = 3, /* Read & Write */
    ept_access_x     = 4, /* Exec Only */
    ept_access_rx    = 5, /* Read & Exec */
    ept_access_wx    = 6, /* Write & Exec*/
    ept_access_all   = 7, /* Full permissions */
} ept_access_t;

#define EPT_TABLE_ORDER         9
#define EPTE_SUPER_PAGE_MASK    0x80
#define EPTE_MFN_MASK           0xffffffffff000ULL
#define EPTE_AVAIL1_MASK        0xF00
#define EPTE_EMT_MASK           0x38
#define EPTE_IGMT_MASK          0x40
#define EPTE_AVAIL1_SHIFT       8
#define EPTE_EMT_SHIFT          3
#define EPTE_IGMT_SHIFT         6
#define EPTE_RWX_MASK           0x7
#define EPTE_FLAG_MASK          0x7f

#define PI_xAPIC_NDST_MASK      0xFF00

void vmx_intr_assist(void);
void noreturn cf_check vmx_do_resume(void);
void cf_check vmx_vlapic_msr_changed(struct vcpu *v);
struct hvm_emulate_ctxt;
void vmx_realmode_emulate_one(struct hvm_emulate_ctxt *hvmemul_ctxt);
void vmx_realmode(struct cpu_user_regs *regs);
void vmx_update_exception_bitmap(struct vcpu *v);
void vmx_update_cpu_exec_control(struct vcpu *v);
void vmx_update_secondary_exec_control(struct vcpu *v);
void vmx_update_tertiary_exec_control(const struct vcpu *v);

#define POSTED_INTR_ON  0
#define POSTED_INTR_SN  1
static inline int pi_test_and_set_pir(uint8_t vector, struct pi_desc *pi_desc)
{
    return test_and_set_bit(vector, pi_desc->pir);
}

static inline int pi_test_pir(uint8_t vector, const struct pi_desc *pi_desc)
{
    return test_bit(vector, pi_desc->pir);
}

static inline int pi_test_and_set_on(struct pi_desc *pi_desc)
{
    return test_and_set_bit(POSTED_INTR_ON, &pi_desc->control);
}

static inline void pi_set_on(struct pi_desc *pi_desc)
{
    set_bit(POSTED_INTR_ON, &pi_desc->control);
}

static inline int pi_test_and_clear_on(struct pi_desc *pi_desc)
{
    return test_and_clear_bit(POSTED_INTR_ON, &pi_desc->control);
}

static inline int pi_test_on(struct pi_desc *pi_desc)
{
    return pi_desc->on;
}

static inline unsigned long pi_get_pir(struct pi_desc *pi_desc, int group)
{
    return xchg(&pi_desc->pir[group], 0);
}

static inline int pi_test_sn(struct pi_desc *pi_desc)
{
    return pi_desc->sn;
}

static inline void pi_set_sn(struct pi_desc *pi_desc)
{
    set_bit(POSTED_INTR_SN, &pi_desc->control);
}

static inline void pi_clear_sn(struct pi_desc *pi_desc)
{
    clear_bit(POSTED_INTR_SN, &pi_desc->control);
}

/*
 * Exit Reasons
 */
#define VMX_EXIT_REASONS_FAILED_VMENTRY (1u << 31)
#define VMX_EXIT_REASONS_BUS_LOCK       (1u << 26)

#define EXIT_REASON_EXCEPTION_NMI       0
#define EXIT_REASON_EXTERNAL_INTERRUPT  1
#define EXIT_REASON_TRIPLE_FAULT        2
#define EXIT_REASON_INIT                3
#define EXIT_REASON_SIPI                4
#define EXIT_REASON_IO_SMI              5
#define EXIT_REASON_OTHER_SMI           6
#define EXIT_REASON_PENDING_VIRT_INTR   7
#define EXIT_REASON_PENDING_VIRT_NMI    8
#define EXIT_REASON_TASK_SWITCH         9
#define EXIT_REASON_CPUID               10
#define EXIT_REASON_GETSEC              11
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_INVD                13
#define EXIT_REASON_INVLPG              14
#define EXIT_REASON_RDPMC               15
#define EXIT_REASON_RDTSC               16
#define EXIT_REASON_RSM                 17
#define EXIT_REASON_VMCALL              18
#define EXIT_REASON_VMCLEAR             19
#define EXIT_REASON_VMLAUNCH            20
#define EXIT_REASON_VMPTRLD             21
#define EXIT_REASON_VMPTRST             22
#define EXIT_REASON_VMREAD              23
#define EXIT_REASON_VMRESUME            24
#define EXIT_REASON_VMWRITE             25
#define EXIT_REASON_VMXOFF              26
#define EXIT_REASON_VMXON               27
#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_DR_ACCESS           29
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32
#define EXIT_REASON_INVALID_GUEST_STATE 33
#define EXIT_REASON_MSR_LOADING         34
#define EXIT_REASON_MWAIT_INSTRUCTION   36
#define EXIT_REASON_MONITOR_TRAP_FLAG   37
#define EXIT_REASON_MONITOR_INSTRUCTION 39
#define EXIT_REASON_PAUSE_INSTRUCTION   40
#define EXIT_REASON_MCE_DURING_VMENTRY  41
#define EXIT_REASON_TPR_BELOW_THRESHOLD 43
#define EXIT_REASON_APIC_ACCESS         44
#define EXIT_REASON_EOI_INDUCED         45
#define EXIT_REASON_ACCESS_GDTR_OR_IDTR 46
#define EXIT_REASON_ACCESS_LDTR_OR_TR   47
#define EXIT_REASON_EPT_VIOLATION       48
#define EXIT_REASON_EPT_MISCONFIG       49
#define EXIT_REASON_INVEPT              50
#define EXIT_REASON_RDTSCP              51
#define EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED 52
#define EXIT_REASON_INVVPID             53
#define EXIT_REASON_WBINVD              54
#define EXIT_REASON_XSETBV              55
#define EXIT_REASON_APIC_WRITE          56
#define EXIT_REASON_INVPCID             58
#define EXIT_REASON_VMFUNC              59
#define EXIT_REASON_PML_FULL            62
#define EXIT_REASON_XSAVES              63
#define EXIT_REASON_XRSTORS             64
#define EXIT_REASON_BUS_LOCK            74
#define EXIT_REASON_NOTIFY              75
/* Remember to also update VMX_PERF_EXIT_REASON_SIZE! */

/*
 * Interruption-information format
 *
 * Note INTR_INFO_NMI_UNBLOCKED_BY_IRET is also used with Exit Qualification
 * field for EPT violations, PML full and SPP-related event vmexits.
 */
#define INTR_INFO_VECTOR_MASK           0x000000ffU     /* 7:0 */
#define INTR_INFO_INTR_TYPE_MASK        0x00000700U     /* 10:8 */
#define INTR_INFO_DELIVER_CODE_MASK     0x00000800U     /* 11 */
#define INTR_INFO_NMI_UNBLOCKED_BY_IRET 0x00001000U     /* 12 */
#define INTR_INFO_VALID_MASK            0x80000000U     /* 31 */
#define INTR_INFO_RESVD_BITS_MASK       0x7ffff000U

/*
 * Exit Qualifications for NOTIFY VM EXIT
 */
#define NOTIFY_VM_CONTEXT_INVALID       1u

/*
 * Exit Qualifications for MOV for Control Register Access
 */
enum {
    VMX_CR_ACCESS_TYPE_MOV_TO_CR,
    VMX_CR_ACCESS_TYPE_MOV_FROM_CR,
    VMX_CR_ACCESS_TYPE_CLTS,
    VMX_CR_ACCESS_TYPE_LMSW,
};
typedef union cr_access_qual {
    unsigned long raw;
    struct {
        uint16_t cr:4,
                 access_type:2,  /* VMX_CR_ACCESS_TYPE_* */
                 lmsw_op_type:1, /* 0 => reg, 1 => mem   */
                 :1,
                 gpr:4,
                 :4;
        uint16_t lmsw_data;
        uint32_t :32;
    };
} __transparent__ cr_access_qual_t;

/*
 * Access Rights
 */
#define X86_SEG_AR_SEG_TYPE     0xf        /* 3:0, segment type */
#define X86_SEG_AR_DESC_TYPE    (1u << 4)  /* 4, descriptor type */
#define X86_SEG_AR_DPL          0x60       /* 6:5, descriptor privilege level */
#define X86_SEG_AR_SEG_PRESENT  (1u << 7)  /* 7, segment present */
#define X86_SEG_AR_AVL          (1u << 12) /* 12, available for system software */
#define X86_SEG_AR_CS_LM_ACTIVE (1u << 13) /* 13, long mode active (CS only) */
#define X86_SEG_AR_DEF_OP_SIZE  (1u << 14) /* 14, default operation size */
#define X86_SEG_AR_GRANULARITY  (1u << 15) /* 15, granularity */
#define X86_SEG_AR_SEG_UNUSABLE (1u << 16) /* 16, segment unusable */

extern uint8_t posted_intr_vector;

#define cpu_has_vmx_ept_exec_only_supported        \
    (vmx_caps.ept & VMX_EPT_EXEC_ONLY_SUPPORTED)

#define cpu_has_vmx_ept_wl4_supported           \
    (vmx_caps.ept & VMX_EPT_WALK_LENGTH_4_SUPPORTED)
#define cpu_has_vmx_ept_mt_uc (vmx_caps.ept & VMX_EPT_MEMORY_TYPE_UC)
#define cpu_has_vmx_ept_mt_wb (vmx_caps.ept & VMX_EPT_MEMORY_TYPE_WB)
#define cpu_has_vmx_ept_2mb   (vmx_caps.ept & VMX_EPT_SUPERPAGE_2MB)
#define cpu_has_vmx_ept_1gb   (vmx_caps.ept & VMX_EPT_SUPERPAGE_1GB)
#define cpu_has_vmx_ept_ad    (vmx_caps.ept & VMX_EPT_AD_BIT)
#define cpu_has_vmx_ept_invept_single_context   \
    (vmx_caps.ept & VMX_EPT_INVEPT_SINGLE_CONTEXT)

#define EPT_2MB_SHIFT     16
#define EPT_1GB_SHIFT     17
#define ept_has_2mb(c)    ((c >> EPT_2MB_SHIFT) & 1)
#define ept_has_1gb(c)    ((c >> EPT_1GB_SHIFT) & 1)

#define INVEPT_SINGLE_CONTEXT   1
#define INVEPT_ALL_CONTEXT      2

#define cpu_has_vmx_vpid_invvpid_individual_addr                    \
    (vmx_caps.vpid & VMX_VPID_INVVPID_INDIVIDUAL_ADDR)
#define cpu_has_vmx_vpid_invvpid_single_context                     \
    (vmx_caps.vpid & VMX_VPID_INVVPID_SINGLE_CONTEXT)
#define cpu_has_vmx_vpid_invvpid_single_context_retaining_global    \
    (vmx_caps.vpid & VMX_VPID_INVVPID_SINGLE_CONTEXT_RETAINING_GLOBAL)

#define INVVPID_INDIVIDUAL_ADDR                 0
#define INVVPID_SINGLE_CONTEXT                  1
#define INVVPID_ALL_CONTEXT                     2
#define INVVPID_SINGLE_CONTEXT_RETAINING_GLOBAL 3

static always_inline void __vmptrld(u64 addr)
{
    asm goto ( "vmptrld %[addr]\n\t"
               "jbe %l[vmfail]"
               :
               : [addr] "m" (addr)
               : "memory"
               : vmfail );
    return;

 vmfail:
    BUG();
}

static always_inline void __vmpclear(u64 addr)
{
    asm goto ( "vmclear %[addr]\n\t"
               "jbe %l[vmfail]"
               :
               : [addr] "m" (addr)
               : "memory"
               : vmfail );
    return;

 vmfail:
    BUG();
}

static always_inline unsigned long vmread(unsigned long field)
{
    unsigned long value;

    asm volatile ( "vmread %[field], %[value]\n\t"
                   /* CF==1 or ZF==1 --> BUG() */
                   UNLIKELY_START(be, vmread)
                   _ASM_BUGFRAME_TEXT(0)
                   UNLIKELY_END_SECTION
                   : [value] "=rm" (value)
                   : [field] "r" (field),
                     _ASM_BUGFRAME_INFO(BUGFRAME_bug, __LINE__, __FILE__, 0) );

    return value;
}

static always_inline void __vmread(unsigned long field, unsigned long *value)
{
    *value = vmread(field);
}

static always_inline void __vmwrite(unsigned long field, unsigned long value)
{
    asm goto ( "vmwrite %[value], %[field]\n\t"
               "jbe %l[vmfail]"
               :
               : [field] "r" (field), [value] "rm" (value)
               :
               : vmfail );
    return;

 vmfail:
    BUG();
}

static inline enum vmx_insn_errno vmread_safe(unsigned long field,
                                              unsigned long *value)
{
    unsigned long ret = VMX_INSN_SUCCEED;
    bool fail_invalid, fail_valid;

    asm volatile ( "vmread %[field], %[value]\n\t"
                   ASM_FLAG_OUT(, "setc %[invalid]\n\t")
                   ASM_FLAG_OUT(, "setz %[valid]\n\t")
                   : ASM_FLAG_OUT("=@ccc", [invalid] "=rm") (fail_invalid),
                     ASM_FLAG_OUT("=@ccz", [valid] "=rm") (fail_valid),
                     [value] "=rm" (*value)
                   : [field] "r" (field) );

    if ( unlikely(fail_invalid) )
        ret = VMX_INSN_FAIL_INVALID;
    else if ( unlikely(fail_valid) )
        ret = vmread(VM_INSTRUCTION_ERROR);

    return ret;
}

static inline enum vmx_insn_errno vmwrite_safe(unsigned long field,
                                               unsigned long value)
{
    asm goto ( "vmwrite %[value], %[field]\n\t"
               "jc %l[vmfail_invalid]\n\t"
               "jz %l[vmfail_valid]"
               :
               : [field] "r" (field), [value] "rm" (value)
               :
               : vmfail_invalid, vmfail_valid );
    return VMX_INSN_SUCCEED;

 vmfail_invalid:
    return VMX_INSN_FAIL_INVALID;

 vmfail_valid:
    return vmread(VM_INSTRUCTION_ERROR);
}

static always_inline void __invept(unsigned long type, uint64_t eptp)
{
    struct {
        uint64_t eptp, rsvd;
    } operand = { eptp };

    /*
     * If single context invalidation is not supported, we escalate to
     * use all context invalidation.
     */
    if ( (type == INVEPT_SINGLE_CONTEXT) &&
         !cpu_has_vmx_ept_invept_single_context )
        type = INVEPT_ALL_CONTEXT;

    asm goto ( "invept %[operand], %[type]\n\t"
               "jbe %l[vmfail]"
               :
               : [operand] "m" (operand), [type] "r" (type)
               : "memory"
               : vmfail );
    return;

 vmfail:
    BUG();
}

static always_inline void __invvpid(unsigned long type, u16 vpid, u64 gva)
{
    struct __packed {
        u64 vpid:16;
        u64 rsvd:48;
        u64 gva;
    }  operand = {vpid, 0, gva};

    /* Fix up #UD exceptions which occur when TLBs are flushed before VMXON. */
    asm_inline goto (
        "1: invvpid %[operand], %[type]\n\t"
        "   jbe %l[vmfail]\n\t"
        "2:" _ASM_EXTABLE(1b, 2b)
        :
        : [operand] "m" (operand), [type] "r" (type)
        : "memory"
        : vmfail );
    return;

 vmfail:
    BUG();
}

static inline void ept_sync_all(void)
{
    __invept(INVEPT_ALL_CONTEXT, 0);
}

void ept_sync_domain(struct p2m_domain *p2m);

static inline void vpid_sync_vcpu_gva(struct vcpu *v, unsigned long gva)
{
    int type = INVVPID_INDIVIDUAL_ADDR;

    /*
     * If individual address invalidation is not supported, we escalate to
     * use single context invalidation.
     */
    if ( likely(cpu_has_vmx_vpid_invvpid_individual_addr) )
        goto execute_invvpid;

    type = INVVPID_SINGLE_CONTEXT;

    /*
     * If single context invalidation is not supported, we escalate to
     * use all context invalidation.
     */
    if ( !cpu_has_vmx_vpid_invvpid_single_context )
        type = INVVPID_ALL_CONTEXT;

execute_invvpid:
    __invvpid(type, v->arch.hvm.n1asid.asid, (u64)gva);
}

static inline void vpid_sync_all(void)
{
    __invvpid(INVVPID_ALL_CONTEXT, 0, 0);
}

int cf_check vmx_guest_x86_mode(struct vcpu *v);
unsigned int vmx_get_cpl(void);

void vmx_inject_extint(int trap, uint8_t source);
void vmx_inject_nmi(void);

void ept_walk_table(struct domain *d, unsigned long gfn);
bool ept_handle_misconfig(uint64_t gpa);
int epte_get_entry_emt(struct domain *d, gfn_t gfn, mfn_t mfn,
                       unsigned int order, bool *ipat, p2m_type_t type);
void ept_vcpu_flush_pml_buffer(struct vcpu *v);
void setup_ept_dump(void);
/* Locate an alternate p2m by its EPTP */
unsigned int p2m_find_altp2m_by_eptp(struct domain *d, uint64_t eptp);

void update_guest_eip(void);

void vmx_pi_per_cpu_init(unsigned int cpu);
void vmx_pi_desc_fixup(unsigned int cpu);

void vmx_sync_exit_bitmap(struct vcpu *v);

#ifdef CONFIG_INTEL_VMX
void vmx_pi_hooks_assign(struct domain *d);
void vmx_pi_hooks_deassign(struct domain *d);
#else
static inline void vmx_pi_hooks_assign(struct domain *d) {}
static inline void vmx_pi_hooks_deassign(struct domain *d) {}
#endif

#define APIC_INVALID_DEST           0xffffffffU

/* EPT violation qualifications definitions */
typedef union ept_qual {
    unsigned long raw;
    struct {
        bool read:1, write:1, fetch:1,
            eff_read:1, eff_write:1, eff_exec:1, /* eff_user_exec */:1,
            gla_valid:1,
            gla_fault:1; /* Valid iff gla_valid. */
        unsigned long /* pad */:55;
    };
} __transparent__ ept_qual_t;

#define EPT_L4_PAGETABLE_SHIFT      39
#define EPT_PAGETABLE_ENTRIES       512

/* #VE information page */
typedef struct {
    u32 exit_reason;
    u32 semaphore;
    u64 exit_qualification;
    u64 gla;
    u64 gpa;
    u16 eptp_index;
} ve_info_t;

/* VM-Exit instruction info for LIDT, LGDT, SIDT, SGDT */
typedef union idt_or_gdt_instr_info {
    unsigned long raw;
    struct {
        unsigned long scaling   :2,  /* bits 0:1 - Scaling */
                                :5,  /* bits 6:2 - Undefined */
        addr_size               :3,  /* bits 9:7 - Address size */
                                :1,  /* bit 10 - Cleared to 0 */
        operand_size            :1,  /* bit 11 - Operand size */
                                :3,  /* bits 14:12 - Undefined */
        segment_reg             :3,  /* bits 17:15 - Segment register */
        index_reg               :4,  /* bits 21:18 - Index register */
        index_reg_invalid       :1,  /* bit 22 - Index register invalid */
        base_reg                :4,  /* bits 26:23 - Base register */
        base_reg_invalid        :1,  /* bit 27 - Base register invalid */
        instr_identity          :1,  /* bit 28 - 0:GDT, 1:IDT */
        instr_write             :1,  /* bit 29 - 0:store, 1:load */
                                :34; /* bits 30:63 - Undefined */
    };
} idt_or_gdt_instr_info_t;

/* VM-Exit instruction info for LLDT, LTR, SLDT, STR */
typedef union ldt_or_tr_instr_info {
    unsigned long raw;
    struct {
        unsigned long scaling   :2,  /* bits 0:1 - Scaling */
                                :1,  /* bit 2 - Undefined */
        reg1                    :4,  /* bits 6:3 - Reg1 */
        addr_size               :3,  /* bits 9:7 - Address size */
        mem_reg                 :1,  /* bit 10 - Mem/Reg */
                                :4,  /* bits 14:11 - Undefined */
        segment_reg             :3,  /* bits 17:15 - Segment register */
        index_reg               :4,  /* bits 21:18 - Index register */
        index_reg_invalid       :1,  /* bit 22 - Index register invalid */
        base_reg                :4,  /* bits 26:23 - Base register */
        base_reg_invalid        :1,  /* bit 27 - Base register invalid */
        instr_identity          :1,  /* bit 28 - 0:LDT, 1:TR */
        instr_write             :1,  /* bit 29 - 0:store, 1:load */
                                :34; /* bits 31:63 - Undefined */
    };
} ldt_or_tr_instr_info_t;

#endif /* __ASM_X86_HVM_VMX_VMX_H__ */
