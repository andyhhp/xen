/*
 * Hypercall and fault low-level handling routines.
 *
 * Copyright (c) 2005, K A Fraser
 */

        .file "x86_64/entry.S"

#include <xen/errno.h>
#include <xen/softirq.h>
#include <asm/asm_defns.h>
#include <asm/apicdef.h>
#include <asm/page.h>
#include <public/xen.h>
#include <irq_vectors.h>

/* %rbx: struct vcpu */
ENTRY(switch_to_kernel)
        leaq  VCPU_trap_bounce(%rbx),%rdx
        /* TB_eip = (32-bit syscall && syscall32_addr) ?
         *          syscall32_addr : syscall_addr */
        xor   %eax,%eax
        cmpw  $FLAT_USER_CS32,UREGS_cs(%rsp)
        cmoveq VCPU_syscall32_addr(%rbx),%rax
        testq %rax,%rax
        cmovzq VCPU_syscall_addr(%rbx),%rax
        movq  %rax,TRAPBOUNCE_eip(%rdx)
        /* TB_flags = VGCF_syscall_disables_events ? TBF_INTERRUPT : 0 */
        btl   $_VGCF_syscall_disables_events,VCPU_guest_context_flags(%rbx)
        setc  %cl
        leal  (,%rcx,TBF_INTERRUPT),%ecx
        movb  %cl,TRAPBOUNCE_flags(%rdx)
        call  pv_create_exception_frame
        andl  $~X86_EFLAGS_DF,UREGS_eflags(%rsp)
        jmp   test_all_events

/* %rbx: struct vcpu, interrupts disabled */
restore_all_guest:
        ASSERT_INTERRUPTS_DISABLED
        RESTORE_ALL
        testw $TRAP_syscall,4(%rsp)
        jz    iret_exit_to_guest

        movq  24(%rsp),%r11           # RFLAGS
        andq  $~(X86_EFLAGS_IOPL|X86_EFLAGS_NT|X86_EFLAGS_VM),%r11
        orq   $X86_EFLAGS_IF,%r11

        /* Don't use SYSRET path if the return address is not canonical. */
        movq  8(%rsp),%rcx
        sarq  $47,%rcx
        incl  %ecx
        cmpl  $1,%ecx
        movq  8(%rsp),%rcx            # RIP
        ja    iret_exit_to_guest

        cmpw  $FLAT_USER_CS32,16(%rsp)# CS
        movq  32(%rsp),%rsp           # RSP
        je    1f
        sysretq
1:      sysretl

        ALIGN
/* No special register assumptions. */
iret_exit_to_guest:
        andl  $~(X86_EFLAGS_IOPL|X86_EFLAGS_NT|X86_EFLAGS_VM),24(%rsp)
        orl   $X86_EFLAGS_IF,24(%rsp)
        addq  $8,%rsp
.Lft0:  iretq
        _ASM_PRE_EXTABLE(.Lft0, handle_exception)

        ALIGN
/* No special register assumptions. */
restore_all_xen:
        RESTORE_ALL adj=8
        iretq

/*
 * When entering SYSCALL from kernel mode:
 *  %rax                            = hypercall vector
 *  %rdi, %rsi, %rdx, %r10, %r8, %9 = hypercall arguments
 *  %rcx                            = SYSCALL-saved %rip
 *  NB. We must move %r10 to %rcx for C function-calling ABI.
 *
 * When entering SYSCALL from user mode:
 *  Vector directly to the registered arch.syscall_addr.
 *
 * Initial work is done by per-CPU trampolines. At this point %rsp has been
 * initialised to point at the correct Xen stack, %rsp has been saved, and
 * %rax needs to be restored from the %ss save slot. All other registers are
 * still to be saved onto the stack, starting with RFLAGS, and an appropriate
 * %ss must be saved into the space left by the trampoline.
 */
ENTRY(lstar_enter)
        sti
        movq  8(%rsp),%rax /* Restore %rax. */
        movq  $FLAT_KERNEL_SS,8(%rsp)
        pushq %r11
        pushq $FLAT_KERNEL_CS64
        pushq %rcx
        pushq $0
        SAVE_VOLATILE TRAP_syscall
        GET_CURRENT(bx)
        testb $TF_kernel_mode,VCPU_thread_flags(%rbx)
        jz    switch_to_kernel

        mov   %rsp, %rdi
        call  pv_hypercall

/* %rbx: struct vcpu */
test_all_events:
        ASSERT_NOT_IN_ATOMIC
        cli                             # tests must not race interrupts
/*test_softirqs:*/  
        movl  VCPU_processor(%rbx),%eax
        shll  $IRQSTAT_shift,%eax
        leaq  irq_stat+IRQSTAT_softirq_pending(%rip),%rcx
        cmpl  $0,(%rcx,%rax,1)
        jne   process_softirqs
        testb $1,VCPU_mce_pending(%rbx)
        jnz   process_mce
.Ltest_guest_nmi:
        testb $1,VCPU_nmi_pending(%rbx)
        jnz   process_nmi
test_guest_events:
        movq  VCPU_vcpu_info(%rbx),%rax
        movzwl VCPUINFO_upcall_pending(%rax),%eax
        decl  %eax
        cmpl  $0xfe,%eax
        ja    restore_all_guest
/*process_guest_events:*/
        sti
        leaq  VCPU_trap_bounce(%rbx),%rdx
        movq  VCPU_event_addr(%rbx),%rax
        movq  %rax,TRAPBOUNCE_eip(%rdx)
        movb  $TBF_INTERRUPT,TRAPBOUNCE_flags(%rdx)
        call  pv_create_exception_frame
        jmp   test_all_events

        ALIGN
/* %rbx: struct vcpu */
process_softirqs:
        sti       
        SAVE_PRESERVED
        call do_softirq
        jmp  test_all_events

        ALIGN
/* %rbx: struct vcpu */
process_mce:
        testb $1 << VCPU_TRAP_MCE,VCPU_async_exception_mask(%rbx)
        jnz  .Ltest_guest_nmi
        sti
        movb $0,VCPU_mce_pending(%rbx)
        call set_guest_machinecheck_trapbounce
        test %eax,%eax
        jz   test_all_events
        movzbl VCPU_async_exception_mask(%rbx),%edx # save mask for the
        movb %dl,VCPU_mce_old_mask(%rbx)            # iret hypercall
        orl  $1 << VCPU_TRAP_MCE,%edx
        movb %dl,VCPU_async_exception_mask(%rbx)
        jmp  process_trap

        ALIGN
/* %rbx: struct vcpu */
process_nmi:
        testb $1 << VCPU_TRAP_NMI,VCPU_async_exception_mask(%rbx)
        jnz  test_guest_events
        sti
        movb $0,VCPU_nmi_pending(%rbx)
        call set_guest_nmi_trapbounce
        test %eax,%eax
        jz   test_all_events
        movzbl VCPU_async_exception_mask(%rbx),%edx # save mask for the
        movb %dl,VCPU_nmi_old_mask(%rbx)            # iret hypercall
        orl  $1 << VCPU_TRAP_NMI,%edx
        movb %dl,VCPU_async_exception_mask(%rbx)
        /* FALLTHROUGH */
process_trap:
        leaq VCPU_trap_bounce(%rbx),%rdx
        call pv_create_exception_frame
        jmp  test_all_events

ENTRY(sysenter_entry)
        sti
        pushq $FLAT_USER_SS
        pushq $0
        pushfq
GLOBAL(sysenter_eflags_saved)
        ASM_CLAC
        pushq $3 /* ring 3 null cs */
        pushq $0 /* null rip */
        pushq $0
        SAVE_VOLATILE TRAP_syscall
        GET_CURRENT(bx)
        cmpb  $0,VCPU_sysenter_disables_events(%rbx)
        movq  VCPU_sysenter_addr(%rbx),%rax
        setne %cl
        testl $X86_EFLAGS_NT,UREGS_eflags(%rsp)
        leaq  VCPU_trap_bounce(%rbx),%rdx
UNLIKELY_START(nz, sysenter_nt_set)
        pushfq
        andl  $~X86_EFLAGS_NT,(%rsp)
        popfq
        xorl  %eax,%eax
UNLIKELY_END(sysenter_nt_set)
        testq %rax,%rax
        leal  (,%rcx,TBF_INTERRUPT),%ecx
UNLIKELY_START(z, sysenter_gpf)
        movq  VCPU_trap_ctxt(%rbx),%rsi
        SAVE_PRESERVED
        movl  $TRAP_gp_fault,UREGS_entry_vector(%rsp)
        movl  %eax,TRAPBOUNCE_error_code(%rdx)
        movq  TRAP_gp_fault * TRAPINFO_sizeof + TRAPINFO_eip(%rsi),%rax
        testb $4,TRAP_gp_fault * TRAPINFO_sizeof + TRAPINFO_flags(%rsi)
        setnz %cl
        leal  TBF_EXCEPTION|TBF_EXCEPTION_ERRCODE(,%rcx,TBF_INTERRUPT),%ecx
UNLIKELY_END(sysenter_gpf)
        movq  VCPU_domain(%rbx),%rdi
        movq  %rax,TRAPBOUNCE_eip(%rdx)
        movb  %cl,TRAPBOUNCE_flags(%rdx)
        testb $1,DOMAIN_is_32bit_pv(%rdi)
        jnz   compat_sysenter
        jmp   .Lbounce_exception

ENTRY(int80_direct_trap)
        ASM_CLAC
        pushq $0
        SAVE_VOLATILE 0x80

        cmpb  $0,untrusted_msi(%rip)
UNLIKELY_START(ne, msi_check)
        movl  $0x80,%edi
        call  check_for_unexpected_msi
UNLIKELY_END(msi_check)

        GET_CURRENT(bx)

        mov   VCPU_trap_ctxt(%rbx), %rsi
        mov   VCPU_domain(%rbx), %rax

        /*
         * if ( null_trap_bounce(v, &v->arch.pv_vcpu.trap_ctxt[0x80]) )
         *    goto int80_slow_path;
         */
        mov    0x80 * TRAPINFO_sizeof + TRAPINFO_eip(%rsi), %rdi
        movzwl 0x80 * TRAPINFO_sizeof + TRAPINFO_cs (%rsi), %ecx

        mov   %ecx, %edx
        and   $~3, %edx

        testb $1, DOMAIN_is_32bit_pv(%rax)
        cmove %rdi, %rdx

        test  %rdx, %rdx
        jz    int80_slow_path

        /* Construct trap_bounce from trap_ctxt[0x80]. */
        lea   VCPU_trap_bounce(%rbx), %rdx
        movw  %cx, TRAPBOUNCE_cs(%rdx)
        movq  %rdi, TRAPBOUNCE_eip(%rdx)

        /* TB_flags = TBF_EXCEPTION | (TI_GET_IF(ti) ? TBF_INTERRUPT : 0); */
        testb $4, 0x80 * TRAPINFO_sizeof + TRAPINFO_flags(%rsi)
        setnz %cl
        lea   TBF_EXCEPTION(, %rcx, TBF_INTERRUPT), %ecx
        movb  %cl, TRAPBOUNCE_flags(%rdx)

        testb $1,DOMAIN_is_32bit_pv(%rax)
        jnz   compat_int80_direct_trap

        call  pv_create_exception_frame
        jmp   test_all_events

int80_slow_path:
        /* 
         * Setup entry vector and error code as if this was a GPF caused by an
         * IDT entry with DPL==0.
         */
        movl  $((0x80 << 3) | X86_XEC_IDT),UREGS_error_code(%rsp)
        SAVE_PRESERVED
        movl  $TRAP_gp_fault,UREGS_entry_vector(%rsp)
        /* A GPF wouldn't have incremented the instruction pointer. */
        subq  $2,UREGS_rip(%rsp)
        jmp   handle_exception_saved

ENTRY(common_interrupt)
        SAVE_ALL CLAC
        CR4_PV32_RESTORE
        movq %rsp,%rdi
        callq do_IRQ
        jmp ret_from_intr

/* No special register assumptions. */
ENTRY(ret_from_intr)
        GET_CURRENT(bx)
        testb $3,UREGS_cs(%rsp)
        jz    restore_all_xen
        movq  VCPU_domain(%rbx),%rax
        testb $1,DOMAIN_is_32bit_pv(%rax)
        jz    test_all_events
        jmp   compat_test_all_events

ENTRY(page_fault)
        movl  $TRAP_page_fault,4(%rsp)
/* No special register assumptions. */
GLOBAL(handle_exception)
        SAVE_ALL CLAC
handle_exception_saved:
        GET_CURRENT(bx)
        testb $X86_EFLAGS_IF>>8,UREGS_eflags+1(%rsp)
        jz    exception_with_ints_disabled

.Lcr4_pv32_orig:
        jmp   .Lcr4_pv32_done
        .skip (.Lcr4_pv32_alt_end - .Lcr4_pv32_alt) - (. - .Lcr4_pv32_orig), 0xcc
        .pushsection .altinstr_replacement, "ax"
.Lcr4_pv32_alt:
        mov   VCPU_domain(%rbx),%rax
.Lcr4_pv32_alt_end:
        .section .altinstructions, "a"
        altinstruction_entry .Lcr4_pv32_orig, .Lcr4_pv32_alt, \
                             X86_FEATURE_XEN_SMEP, \
                             (.Lcr4_pv32_alt_end - .Lcr4_pv32_alt), \
                             (.Lcr4_pv32_alt_end - .Lcr4_pv32_alt)
        altinstruction_entry .Lcr4_pv32_orig, .Lcr4_pv32_alt, \
                             X86_FEATURE_XEN_SMAP, \
                             (.Lcr4_pv32_alt_end - .Lcr4_pv32_alt), \
                             (.Lcr4_pv32_alt_end - .Lcr4_pv32_alt)
        .popsection

        testb $3,UREGS_cs(%rsp)
        jz    .Lcr4_pv32_done
        cmpb  $0,DOMAIN_is_32bit_pv(%rax)
        je    .Lcr4_pv32_done
        call  cr4_pv32_restore
        /*
         * An NMI or #MC may occur between clearing CR4.SMEP / CR4.SMAP in
         * compat_restore_all_guest and it actually returning to guest
         * context, in which case the guest would run with the two features
         * enabled. The only bad that can happen from this is a kernel mode
         * #PF which the guest doesn't expect. Rather than trying to make the
         * NMI/#MC exit path honor the intended CR4 setting, simply check
         * whether the wrong CR4 was in use when the #PF occurred, and exit
         * back to the guest (which will in turn clear the two CR4 bits) to
         * re-execute the instruction. If we get back here, the CR4 bits
         * should then be found clear (unless another NMI/#MC occurred at
         * exactly the right time), and we'll continue processing the
         * exception as normal.
         */
        test  %rax,%rax
        jnz   .Lcr4_pv32_done
        /*
         * The below effectively is
         * if ( regs->entry_vector == TRAP_page_fault &&
         *      (regs->error_code & PFEC_page_present) &&
         *      !(regs->error_code & ~(PFEC_write_access|PFEC_insn_fetch)) )
         *     goto compat_test_all_events;
         */
        mov   $PFEC_page_present,%al
        cmpb  $TRAP_page_fault,UREGS_entry_vector(%rsp)
        jne   .Lcr4_pv32_done
        xor   UREGS_error_code(%rsp),%eax
        test  $~(PFEC_write_access|PFEC_insn_fetch),%eax
        jz    compat_test_all_events
.Lcr4_pv32_done:
        sti
1:      movq  %rsp,%rdi
        movzbl UREGS_entry_vector(%rsp),%eax
        leaq  exception_table(%rip),%rdx
        PERFC_INCR(exceptions, %rax, %rbx)
        callq *(%rdx,%rax,8)
        testb $3,UREGS_cs(%rsp)
        jz    restore_all_xen
        leaq  VCPU_trap_bounce(%rbx),%rdx
        movq  VCPU_domain(%rbx),%rax
        testb $1,DOMAIN_is_32bit_pv(%rax)
        jnz   compat_post_handle_exception
        testb $TBF_EXCEPTION,TRAPBOUNCE_flags(%rdx)
        jz    test_all_events
.Lbounce_exception:
        call  pv_create_exception_frame
        jmp   test_all_events

/* No special register assumptions. */
exception_with_ints_disabled:
        testb $3,UREGS_cs(%rsp)         # interrupts disabled outside Xen?
        jnz   FATAL_exception_with_ints_disabled
        movq  %rsp,%rdi
        call  search_pre_exception_table
        testq %rax,%rax                 # no fixup code for faulting EIP?
        jz    1b
        movq  %rax,UREGS_rip(%rsp)
        subq  $8,UREGS_rsp(%rsp)        # add ec/ev to previous stack frame
        testb $15,UREGS_rsp(%rsp)       # return %rsp is now aligned?
        jz    1f                        # then there is a pad quadword already
        movq  %rsp,%rsi
        subq  $8,%rsp
        movq  %rsp,%rdi
        movq  $UREGS_kernel_sizeof/8,%rcx
        rep;  movsq                     # make room for ec/ev
1:      movq  UREGS_error_code(%rsp),%rax # ec/ev
        movq  %rax,UREGS_kernel_sizeof(%rsp)
        jmp   restore_all_xen           # return to fixup code

/* No special register assumptions. */
FATAL_exception_with_ints_disabled:
        xorl  %esi,%esi
        movq  %rsp,%rdi
        call  fatal_trap
        BUG   /* fatal_trap() shouldn't return. */

ENTRY(divide_error)
        pushq $0
        movl  $TRAP_divide_error,4(%rsp)
        jmp   handle_exception

ENTRY(coprocessor_error)
        pushq $0
        movl  $TRAP_copro_error,4(%rsp)
        jmp   handle_exception

ENTRY(simd_coprocessor_error)
        pushq $0
        movl  $TRAP_simd_error,4(%rsp)
        jmp   handle_exception

ENTRY(device_not_available)
        pushq $0
        movl  $TRAP_no_device,4(%rsp)
        jmp   handle_exception

ENTRY(debug)
        pushq $0
        movl  $TRAP_debug,4(%rsp)
        jmp   handle_exception

ENTRY(int3)
        pushq $0
        movl  $TRAP_int3,4(%rsp)
        jmp   handle_exception

ENTRY(overflow)
        pushq $0
        movl  $TRAP_overflow,4(%rsp)
        jmp   handle_exception

ENTRY(bounds)
        pushq $0
        movl  $TRAP_bounds,4(%rsp)
        jmp   handle_exception

ENTRY(invalid_op)
        pushq $0
        movl  $TRAP_invalid_op,4(%rsp)
        jmp   handle_exception

ENTRY(invalid_TSS)
        movl  $TRAP_invalid_tss,4(%rsp)
        jmp   handle_exception

ENTRY(segment_not_present)
        movl  $TRAP_no_segment,4(%rsp)
        jmp   handle_exception

ENTRY(stack_segment)
        movl  $TRAP_stack_error,4(%rsp)
        jmp   handle_exception

ENTRY(general_protection)
        movl  $TRAP_gp_fault,4(%rsp)
        jmp   handle_exception

ENTRY(alignment_check)
        movl  $TRAP_alignment_check,4(%rsp)
        jmp   handle_exception

ENTRY(double_fault)
        movl  $TRAP_double_fault,4(%rsp)
        /* Set AC to reduce chance of further SMAP faults */
        SAVE_ALL STAC
        movq  %rsp,%rdi
        call  do_double_fault
        BUG   /* do_double_fault() shouldn't return. */

        .pushsection .init.text, "ax", @progbits
ENTRY(early_page_fault)
        movl  $TRAP_page_fault,4(%rsp)
        SAVE_ALL
        movq  %rsp,%rdi
        call  do_early_page_fault
        jmp   restore_all_xen
        .popsection

ENTRY(nmi)
        pushq $0
        movl  $TRAP_nmi,4(%rsp)
handle_ist_exception:
        SAVE_ALL CLAC
        CR4_PV32_RESTORE
        testb $3,UREGS_cs(%rsp)
        jz    1f
        /* Interrupted guest context. Copy the context to stack bottom. */
        GET_CPUINFO_FIELD(guest_cpu_user_regs,di)
        movq  %rsp,%rsi
        movl  $UREGS_kernel_sizeof/8,%ecx
        movq  %rdi,%rsp
        rep   movsq
1:      movq  %rsp,%rdi
        movzbl UREGS_entry_vector(%rsp),%eax
        leaq  exception_table(%rip),%rdx
        callq *(%rdx,%rax,8)
        cmpb  $TRAP_nmi,UREGS_entry_vector(%rsp)
        jne   ret_from_intr

        /* We want to get straight to the IRET on the NMI exit path. */
        testb $3,UREGS_cs(%rsp)
        jz    restore_all_xen
        GET_CURRENT(bx)
        /* Send an IPI to ourselves to cover for the lack of event checking. */
        movl  VCPU_processor(%rbx),%eax
        shll  $IRQSTAT_shift,%eax
        leaq  irq_stat+IRQSTAT_softirq_pending(%rip),%rcx
        cmpl  $0,(%rcx,%rax,1)
        je    1f
        movl  $EVENT_CHECK_VECTOR,%edi
        call  send_IPI_self
1:      movq  VCPU_domain(%rbx),%rax
        cmpb  $0,DOMAIN_is_32bit_pv(%rax)
        je    restore_all_guest
        jmp   compat_restore_all_guest

ENTRY(machine_check)
        pushq $0
        movl  $TRAP_machine_check,4(%rsp)
        jmp   handle_ist_exception

/* Enable NMIs.  No special register assumptions. Only %rax is not preserved. */
ENTRY(enable_nmis)
        movq  %rsp, %rax /* Grab RSP before pushing */

        /* Set up stack frame */
        pushq $0               /* SS */
        pushq %rax             /* RSP */
        pushfq                 /* RFLAGS */
        pushq $__HYPERVISOR_CS /* CS */
        leaq  1f(%rip),%rax
        pushq %rax             /* RIP */

        iretq /* Disable the hardware NMI latch */
1:
        retq

/* No op trap handler.  Required for kexec crash path. */
GLOBAL(trap_nop)
        iretq



.section .rodata, "a", @progbits

ENTRY(exception_table)
        .quad do_trap
        .quad do_debug
        .quad do_nmi
        .quad do_int3
        .quad do_trap
        .quad do_trap
        .quad do_invalid_op
        .quad do_device_not_available
        .quad do_reserved_trap /* double_fault - has its own entry. */
        .quad do_reserved_trap /* coproc_seg_overrun - Intel 387 only. */
        .quad do_trap
        .quad do_trap
        .quad do_trap
        .quad do_general_protection
        .quad do_page_fault
        .quad do_reserved_trap /* Default PIC spurious irq - architecturally reserved. */
        .quad do_trap
        .quad do_trap
        .quad do_machine_check
        .quad do_trap
        .rept TRAP_nr - ((. - exception_table) / 8)
        .quad do_reserved_trap /* Architecturally reserved exceptions. */
        .endr
        .size exception_table, . - exception_table

/* Table of automatically generated entry points.  One per vector. */
        .section .init.rodata, "a", @progbits
GLOBAL(autogen_entrypoints)
        /* pop into the .init.rodata section and record an entry point. */
        .macro entrypoint ent
        .pushsection .init.rodata
        .quad \ent
        .popsection
        .endm

        .text
autogen_stubs: /* Automatically generated stubs. */

        vec = 0
        .rept NR_VECTORS

        /* Common interrupts, heading towards do_IRQ(). */
#ifdef CONFIG_PV
        .if vec >= FIRST_DYNAMIC_VECTOR && vec != HYPERCALL_VECTOR && vec != LEGACY_SYSCALL_VECTOR
#else
        .if vec >= FIRST_DYNAMIC_VECTOR
#endif

        ALIGN
1:      pushq $0
        movb  $vec,4(%rsp)
        jmp   common_interrupt

        entrypoint 1b

        /* Reserved exceptions, heading towards do_reserved_trap(). */
        .elseif vec == TRAP_copro_seg || vec == TRAP_spurious_int || (vec > TRAP_simd_error && vec < TRAP_nr)

1:      test  $8,%spl        /* 64bit exception frames are 16 byte aligned, but the word */
        jz    2f             /* size is 8 bytes.  Check whether the processor gave us an */
        pushq $0             /* error code, and insert an empty one if not.              */
2:      movb  $vec,4(%rsp)
        jmp   handle_exception

        entrypoint 1b

        /* Hand crafted entry points above. */
        .else
        entrypoint 0
        .endif

        vec = vec + 1
        .endr

        .section .init.rodata
        .size autogen_entrypoints, . - autogen_entrypoints
