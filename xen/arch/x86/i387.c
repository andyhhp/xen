/*
 *  linux/arch/i386/kernel/i387.c
 *
 *  Copyright (C) 1994 Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *  General FPU state handling cleanups
 *  Gareth Hughes <gareth@valinux.com>, May 2000
 */

#include <xen/sched.h>
#include <asm/current.h>
#include <asm/processor.h>
#include <asm/hvm/support.h>
#include <asm/i387.h>
#include <asm/xstate.h>
#include <asm/asm_defns.h>

/*******************************/
/*     FPU Restore Functions   */
/*******************************/
/* Restore x87 extended state */
static inline void fpu_xrstor(struct vcpu *v)
{
    bool ok;

    ASSERT(v->arch.xsave_area);
    /*
     * XCR0 normally represents what guest OS set. In case of Xen itself,
     * we set the accumulated feature mask before doing save/restore.
     *
     * Combine the outgoing and incoming XCR0 before calling xrstor to make
     * sure any state component used by outgoing vcpu is cleared. Rewrite XCR0
     * to be the ones used by incoming vcpu afterwards.
     */
    ok = set_xcr0(v->arch.xcr0_accum | get_xcr0() | XSTATE_FP_SSE);
    ASSERT(ok);
    xrstor(v, XSTATE_ALL);
    ok = set_xcr0(v->arch.xcr0 ?: XSTATE_FP_SSE);
    ASSERT(ok);
}

/* Restore x87 FPU, MMX, SSE and SSE2 state */
static inline void fpu_fxrstor(struct vcpu *v)
{
    const typeof(v->arch.xsave_area->fpu_sse) *fpu_ctxt = v->arch.fpu_ctxt;

    /*
     * AMD CPUs don't save/restore FDP/FIP/FOP unless an exception
     * is pending. Clear the x87 state here by setting it to fixed
     * values. The hypervisor data segment can be sometimes 0 and
     * sometimes new user value. Both should be ok. Use the FPU saved
     * data block as a safe address because it should be in L1.
     */
    if ( !(fpu_ctxt->fsw & ~fpu_ctxt->fcw & 0x003f) &&
         boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
    {
        asm volatile ( "fnclex\n\t"
                       "ffree %%st(7)\n\t" /* clear stack tag */
                       "fildl %0"          /* load to clear state */
                       : : "m" (*fpu_ctxt) );
    }

    /*
     * FXRSTOR can fault if passed a corrupted data block. We handle this
     * possibility, which may occur if the block was passed to us by control
     * tools or through VCPUOP_initialise, by silently clearing the block.
     */
    switch ( __builtin_expect(fpu_ctxt->x[FPU_WORD_SIZE_OFFSET], 8) )
    {
    default:
        asm volatile (
            /* See below for why the operands/constraints are this way. */
            "1: " REX64_PREFIX "fxrstor (%2)\n"
            ".section .fixup,\"ax\"   \n"
            "2: push %%"__OP"ax       \n"
            "   push %%"__OP"cx       \n"
            "   push %%"__OP"di       \n"
            "   mov  %2,%%"__OP"di    \n"
            "   mov  %1,%%ecx         \n"
            "   xor  %%eax,%%eax      \n"
            "   rep ; stosl           \n"
            "   pop  %%"__OP"di       \n"
            "   pop  %%"__OP"cx       \n"
            "   pop  %%"__OP"ax       \n"
            "   jmp  1b               \n"
            ".previous                \n"
            _ASM_EXTABLE(1b, 2b)
            :
            : "m" (*fpu_ctxt), "i" (sizeof(*fpu_ctxt) / 4), "R" (fpu_ctxt) );
        break;
    case 4: case 2:
        asm volatile (
            "1: fxrstor %0         \n"
            ".section .fixup,\"ax\"\n"
            "2: push %%"__OP"ax    \n"
            "   push %%"__OP"cx    \n"
            "   push %%"__OP"di    \n"
            "   lea  %0,%%"__OP"di \n"
            "   mov  %1,%%ecx      \n"
            "   xor  %%eax,%%eax   \n"
            "   rep ; stosl        \n"
            "   pop  %%"__OP"di    \n"
            "   pop  %%"__OP"cx    \n"
            "   pop  %%"__OP"ax    \n"
            "   jmp  1b            \n"
            ".previous             \n"
            _ASM_EXTABLE(1b, 2b)
            :
            : "m" (*fpu_ctxt), "i" (sizeof(*fpu_ctxt) / 4) );
        break;
    }
}

/*******************************/
/*      FPU Save Functions     */
/*******************************/

/* Save x87 extended state */
static inline void fpu_xsave(struct vcpu *v)
{
    bool ok;

    ASSERT(v->arch.xsave_area);
    /*
     * XCR0 normally represents what guest OS set. In case of Xen itself,
     * we set the accumulated feature mask before doing save/restore.
     */
    ok = set_xcr0(v->arch.xcr0_accum | XSTATE_FP_SSE);
    ASSERT(ok);
    xsave(v, XSTATE_ALL);
    ok = set_xcr0(v->arch.xcr0 ?: XSTATE_FP_SSE);
    ASSERT(ok);
}

/* Save x87 FPU, MMX, SSE and SSE2 state */
static inline void fpu_fxsave(struct vcpu *v)
{
    typeof(v->arch.xsave_area->fpu_sse) *fpu_ctxt = v->arch.fpu_ctxt;
    unsigned int fip_width = v->domain->arch.x87_fip_width;

    if ( fip_width != 4 )
    {
        /*
         * The only way to force fxsaveq on a wide range of gas versions.
         * On older versions the rex64 prefix works only if we force an
         * addressing mode that doesn't require extended registers.
         */
        asm volatile ( REX64_PREFIX "fxsave (%1)"
                       : "=m" (*fpu_ctxt) : "R" (fpu_ctxt) );

        /*
         * AMD CPUs don't save/restore FDP/FIP/FOP unless an exception
         * is pending.
         */
        if ( !(fpu_ctxt->fsw & 0x0080) &&
             boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
            return;

        /*
         * If the FIP/FDP[63:32] are both zero, it is safe to use the
         * 32-bit restore to also restore the selectors.
         */
        if ( !fip_width &&
             !((fpu_ctxt->fip.addr | fpu_ctxt->fdp.addr) >> 32) )
        {
            struct ix87_env fpu_env;

            asm volatile ( "fnstenv %0" : "=m" (fpu_env) );
            fpu_ctxt->fip.sel = fpu_env.fcs;
            fpu_ctxt->fdp.sel = fpu_env.fds;
            fip_width = 4;
        }
        else
            fip_width = 8;
    }
    else
    {
        asm volatile ( "fxsave %0" : "=m" (*fpu_ctxt) );
        fip_width = 4;
    }

    fpu_ctxt->x[FPU_WORD_SIZE_OFFSET] = fip_width;
}

/*******************************/
/*       VCPU FPU Functions    */
/*******************************/

/* Initialize FPU's context save area */
int vcpu_init_fpu(struct vcpu *v)
{
    int rc;

    if ( (rc = xstate_alloc_save_area(v)) != 0 )
        return rc;

    if ( v->arch.xsave_area )
        v->arch.fpu_ctxt = &v->arch.xsave_area->fpu_sse;
    else
    {
        BUILD_BUG_ON(__alignof(v->arch.xsave_area->fpu_sse) < 16);
        v->arch.fpu_ctxt = _xzalloc(sizeof(v->arch.xsave_area->fpu_sse),
                                    __alignof(v->arch.xsave_area->fpu_sse));
        if ( v->arch.fpu_ctxt )
        {
            typeof(v->arch.xsave_area->fpu_sse) *fpu_sse = v->arch.fpu_ctxt;

            fpu_sse->fcw = FCW_DEFAULT;
            fpu_sse->mxcsr = MXCSR_DEFAULT;
        }
        else
            rc = -ENOMEM;
    }

    return rc;
}

/* Free FPU's context save area */
void vcpu_destroy_fpu(struct vcpu *v)
{
    if ( v->arch.xsave_area )
        xstate_free_save_area(v);
    else
        xfree(v->arch.fpu_ctxt);
}

void vcpu_save_fpu(struct vcpu *v)
{
    ASSERT(!is_idle_vcpu(v));

    /* This can happen, if a paravirtualised guest OS has set its CR0.TS. */
    clts();

    if ( cpu_has_xsave )
        fpu_xsave(v);
    else
        fpu_fxsave(v);
}

void vcpu_restore_fpu(struct vcpu *v)
{
    ASSERT(!is_idle_vcpu(v));
    ASSERT(!(read_cr0() & X86_CR0_TS));

    if ( cpu_has_xsave )
        fpu_xrstor(v);
    else
        fpu_fxrstor(v);

    if ( is_pv_vcpu(v) && (v->arch.pv_vcpu.ctrlreg[0] & X86_CR0_TS) )
        stts();
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
