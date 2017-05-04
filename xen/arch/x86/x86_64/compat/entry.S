/*
 * Compatibility hypercall routines.
 */

        .file "x86_64/compat/entry.S"

#include <xen/errno.h>
#include <xen/softirq.h>
#include <asm/asm_defns.h>
#include <asm/apicdef.h>
#include <asm/page.h>
#include <asm/desc.h>
#include <public/xen.h>
#include <irq_vectors.h>

ENTRY(entry_int82)
        ASM_CLAC
        pushq $0
        SAVE_VOLATILE type=HYPERCALL_VECTOR compat=1
        CR4_PV32_RESTORE

        GET_CURRENT(bx)

        mov   %rsp, %rdi
        call  do_entry_int82

/* %rbx: struct vcpu */
ENTRY(compat_test_all_events)
        ASSERT_NOT_IN_ATOMIC
        cli                             # tests must not race interrupts
/*compat_test_softirqs:*/
        movl  VCPU_processor(%rbx),%eax
        shll  $IRQSTAT_shift,%eax
        leaq  irq_stat+IRQSTAT_softirq_pending(%rip),%rcx
        cmpl  $0,(%rcx,%rax,1)
        jne   compat_process_softirqs
        testb $1,VCPU_mce_pending(%rbx)
        jnz   compat_process_mce
.Lcompat_test_guest_nmi:
        testb $1,VCPU_nmi_pending(%rbx)
        jnz   compat_process_nmi
compat_test_guest_events:
        movq  VCPU_vcpu_info(%rbx),%rax
        movzwl COMPAT_VCPUINFO_upcall_pending(%rax),%eax
        decl  %eax
        cmpl  $0xfe,%eax
        ja    compat_restore_all_guest
/*compat_process_guest_events:*/
        sti
        leaq  VCPU_trap_bounce(%rbx),%rdx
        movl  VCPU_event_addr(%rbx),%eax
        movl  %eax,TRAPBOUNCE_eip(%rdx)
        movl  VCPU_event_sel(%rbx),%eax
        movw  %ax,TRAPBOUNCE_cs(%rdx)
        movb  $TBF_INTERRUPT,TRAPBOUNCE_flags(%rdx)
        call  pv_create_exception_frame
        jmp   compat_test_all_events

        ALIGN
/* %rbx: struct vcpu */
compat_process_softirqs:
        sti
        andl  $~TRAP_regs_partial,UREGS_entry_vector(%rsp)
        call  do_softirq
        jmp   compat_test_all_events

	ALIGN
/* %rbx: struct vcpu */
compat_process_mce:
        testb $1 << VCPU_TRAP_MCE,VCPU_async_exception_mask(%rbx)
        jnz   .Lcompat_test_guest_nmi
        sti
        movb $0,VCPU_mce_pending(%rbx)
        call set_guest_machinecheck_trapbounce
        testl %eax,%eax
        jz    compat_test_all_events
        movzbl VCPU_async_exception_mask(%rbx),%edx # save mask for the
        movb %dl,VCPU_mce_old_mask(%rbx)            # iret hypercall
        orl  $1 << VCPU_TRAP_MCE,%edx
        movb %dl,VCPU_async_exception_mask(%rbx)
        jmp   compat_process_trap

	ALIGN
/* %rbx: struct vcpu */
compat_process_nmi:
        testb $1 << VCPU_TRAP_NMI,VCPU_async_exception_mask(%rbx)
        jnz  compat_test_guest_events
        sti
        movb  $0,VCPU_nmi_pending(%rbx)
        call  set_guest_nmi_trapbounce
        testl %eax,%eax
        jz    compat_test_all_events
        movzbl VCPU_async_exception_mask(%rbx),%edx # save mask for the
        movb %dl,VCPU_nmi_old_mask(%rbx)            # iret hypercall
        orl  $1 << VCPU_TRAP_NMI,%edx
        movb %dl,VCPU_async_exception_mask(%rbx)
        /* FALLTHROUGH */
compat_process_trap:
        leaq  VCPU_trap_bounce(%rbx),%rdx
        call  pv_create_exception_frame
        jmp   compat_test_all_events

/* %rbx: struct vcpu, interrupts disabled */
ENTRY(compat_restore_all_guest)
        ASSERT_INTERRUPTS_DISABLED
        mov   $~(X86_EFLAGS_IOPL|X86_EFLAGS_NT|X86_EFLAGS_VM),%r11d
        and   UREGS_eflags(%rsp),%r11d
.Lcr4_orig:
        .skip .Lcr4_alt_end - .Lcr4_alt, 0x90
.Lcr4_orig_end:
        .pushsection .altinstr_replacement, "ax"
.Lcr4_alt:
        testb $3,UREGS_cs(%rsp)
        jpe   .Lcr4_alt_end
        mov   CPUINFO_cr4-CPUINFO_guest_cpu_user_regs(%rsp), %rax
        and   $~XEN_CR4_PV32_BITS, %rax
1:
        mov   %rax, CPUINFO_cr4-CPUINFO_guest_cpu_user_regs(%rsp)
        mov   %rax, %cr4
        /*
         * An NMI or MCE may have occurred between the previous two
         * instructions, leaving register and cache in a state where
         * the next exit from the guest would trigger the BUG in
         * cr4_pv32_restore. If this happened, the cached value is no
         * longer what we just set it to, which we can utilize to
         * correct that state. Note that we do not have to fear this
         * loop to cause a live lock: If NMIs/MCEs occurred at that
         * high a rate, we'd be live locked anyway.
         */
        cmp   %rax, CPUINFO_cr4-CPUINFO_guest_cpu_user_regs(%rsp)
        jne   1b
.Lcr4_alt_end:
        .section .altinstructions, "a"
        altinstruction_entry .Lcr4_orig, .Lcr4_orig, X86_FEATURE_ALWAYS, \
                             (.Lcr4_orig_end - .Lcr4_orig), 0
        altinstruction_entry .Lcr4_orig, .Lcr4_alt, X86_FEATURE_XEN_SMEP, \
                             (.Lcr4_orig_end - .Lcr4_orig), \
                             (.Lcr4_alt_end - .Lcr4_alt)
        altinstruction_entry .Lcr4_orig, .Lcr4_alt, X86_FEATURE_XEN_SMAP, \
                             (.Lcr4_orig_end - .Lcr4_orig), \
                             (.Lcr4_alt_end - .Lcr4_alt)
        .popsection
        or    $X86_EFLAGS_IF,%r11
        mov   %r11d,UREGS_eflags(%rsp)
        RESTORE_ALL adj=8 compat=1
.Lft0:  iretq
        _ASM_PRE_EXTABLE(.Lft0, handle_exception)

/* This mustn't modify registers other than %rax. */
ENTRY(cr4_pv32_restore)
        push  %rdx
        GET_CPUINFO_FIELD(cr4, dx)
        mov   (%rdx), %rax
        test  $XEN_CR4_PV32_BITS, %eax
        jnz   0f
        or    cr4_pv32_mask(%rip), %rax
        mov   %rax, %cr4
        mov   %rax, (%rdx)
        pop   %rdx
        ret
0:
#ifndef NDEBUG
        /* Check that _all_ of the bits intended to be set actually are. */
        mov   %cr4, %rax
        and   cr4_pv32_mask(%rip), %rax
        cmp   cr4_pv32_mask(%rip), %rax
        je    1f
        /* Cause cr4_pv32_mask to be visible in the BUG register dump. */
        mov   cr4_pv32_mask(%rip), %rdx
        /* Avoid coming back here while handling the #UD we cause below. */
        mov   %cr4, %rcx
        or    %rdx, %rcx
        mov   %rcx, %cr4
        BUG
1:
#endif
        pop   %rdx
        xor   %eax, %eax
        ret

/* %rdx: trap_bounce, %rbx: struct vcpu */
ENTRY(compat_post_handle_exception)
        testb $TBF_EXCEPTION,TRAPBOUNCE_flags(%rdx)
        jz    compat_test_all_events
.Lcompat_bounce_exception:
        call  pv_create_exception_frame
        jmp   compat_test_all_events

/* See lstar_enter for entry register state. */
ENTRY(cstar_enter)
        sti
        CR4_PV32_RESTORE
        movq  8(%rsp),%rax /* Restore %rax. */
        movq  $FLAT_KERNEL_SS,8(%rsp)
        pushq %r11
        pushq $FLAT_USER_CS32
        pushq %rcx
        pushq $0
        SAVE_VOLATILE TRAP_syscall
        GET_CURRENT(bx)
        movq  VCPU_domain(%rbx),%rcx
        cmpb  $0,DOMAIN_is_32bit_pv(%rcx)
        je    switch_to_kernel
        cmpb  $0,VCPU_syscall32_disables_events(%rbx)
        movzwl VCPU_syscall32_sel(%rbx),%esi
        movq  VCPU_syscall32_addr(%rbx),%rax
        setne %cl
        leaq  VCPU_trap_bounce(%rbx),%rdx
        testl $~3,%esi
        leal  (,%rcx,TBF_INTERRUPT),%ecx
UNLIKELY_START(z, compat_syscall_gpf)
        movq  VCPU_trap_ctxt(%rbx),%rdi
        movl  $TRAP_gp_fault,UREGS_entry_vector(%rsp)
        subl  $2,UREGS_rip(%rsp)
        movl  $0,TRAPBOUNCE_error_code(%rdx)
        movl  TRAP_gp_fault * TRAPINFO_sizeof + TRAPINFO_eip(%rdi),%eax
        movzwl TRAP_gp_fault * TRAPINFO_sizeof + TRAPINFO_cs(%rdi),%esi
        testb $4,TRAP_gp_fault * TRAPINFO_sizeof + TRAPINFO_flags(%rdi)
        setnz %cl
        leal  TBF_EXCEPTION|TBF_EXCEPTION_ERRCODE(,%rcx,TBF_INTERRUPT),%ecx
UNLIKELY_END(compat_syscall_gpf)
        movq  %rax,TRAPBOUNCE_eip(%rdx)
        movw  %si,TRAPBOUNCE_cs(%rdx)
        movb  %cl,TRAPBOUNCE_flags(%rdx)
        jmp   .Lcompat_bounce_exception

ENTRY(compat_sysenter)
        CR4_PV32_RESTORE
        movq  VCPU_trap_ctxt(%rbx),%rcx
        cmpb  $TRAP_gp_fault,UREGS_entry_vector(%rsp)
        movzwl VCPU_sysenter_sel(%rbx),%eax
        movzwl TRAP_gp_fault * TRAPINFO_sizeof + TRAPINFO_cs(%rcx),%ecx
        cmovel %ecx,%eax
        testl $~3,%eax
        movl  $FLAT_COMPAT_USER_SS,UREGS_ss(%rsp)
        cmovzl %ecx,%eax
        movw  %ax,TRAPBOUNCE_cs(%rdx)
        call  pv_create_exception_frame
        jmp   compat_test_all_events

ENTRY(compat_int80_direct_trap)
        CR4_PV32_RESTORE
        call  pv_create_exception_frame
        jmp   compat_test_all_events
