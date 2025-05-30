/*
 *  arch/x86/xstate.c
 *
 *  x86 extended state operations
 *
 */

#include <xen/param.h>
#include <xen/percpu.h>
#include <xen/sched.h>
#include <xen/xvmalloc.h>

#include <asm/cpu-policy.h>
#include <asm/current.h>
#include <asm/processor.h>
#include <asm/i387.h>
#include <asm/xstate.h>
#include <asm/asm_defns.h>

/*
 * Maximum size (in byte) of the XSAVE/XRSTOR save area required by all
 * the supported and enabled features on the processor, including the
 * XSAVE.HEADER. We only enable XCNTXT_MASK that we have known.
 */
static u32 __read_mostly xsave_cntxt_size;

/* A 64-bit bitmask of the XSAVE/XRSTOR features supported by processor. */
u64 __read_mostly xfeature_mask;

unsigned int *__read_mostly xstate_offsets;
unsigned int *__read_mostly xstate_sizes;
u64 __read_mostly xstate_align;
static unsigned int __read_mostly xstate_features;

uint32_t __read_mostly mxcsr_mask = 0x0000ffbf;

/* Cached xcr0 for fast read */
static DEFINE_PER_CPU(uint64_t, xcr0);

/* Because XCR0 is cached for each CPU, xsetbv() is not exposed. Users should 
 * use set_xcr0() instead.
 */
static inline bool xsetbv(uint32_t xcr, uint64_t val)
{
    uint32_t hi = val >> 32, lo = val;

    asm_inline goto (
        "1: xsetbv\n\t"
        _ASM_EXTABLE(1b, %l[fault])
        :
        : "a" (lo), "c" (xcr), "d" (hi)
        :
        : fault );

    return true;

 fault:
    return false;
}

bool set_xcr0(u64 xfeatures)
{
    uint64_t *this_xcr0 = &this_cpu(xcr0);

    if ( *this_xcr0 != xfeatures )
    {
        if ( !xsetbv(XCR_XFEATURE_ENABLED_MASK, xfeatures) )
            return false;

        *this_xcr0 = xfeatures;
    }

    return true;
}

uint64_t get_xcr0(void)
{
    return this_cpu(xcr0);
}

/* Cached xss for fast read */
static DEFINE_PER_CPU(uint64_t, xss);

void set_msr_xss(u64 xss)
{
    u64 *this_xss = &this_cpu(xss);

    if ( *this_xss != xss )
    {
        wrmsrl(MSR_IA32_XSS, xss);
        *this_xss = xss;
    }
}

uint64_t get_msr_xss(void)
{
    return this_cpu(xss);
}

static int setup_xstate_features(bool bsp)
{
    unsigned int leaf, eax, ebx, ecx, edx;

    if ( bsp )
    {
        xstate_features = flsl(xfeature_mask);
        xstate_offsets = xzalloc_array(unsigned int, xstate_features);
        if ( !xstate_offsets )
            return -ENOMEM;

        xstate_sizes = xzalloc_array(unsigned int, xstate_features);
        if ( !xstate_sizes )
            return -ENOMEM;
    }

    for ( leaf = 2; leaf < xstate_features; leaf++ )
    {
        if ( bsp )
        {
            cpuid_count(XSTATE_CPUID, leaf, &xstate_sizes[leaf],
                        &xstate_offsets[leaf], &ecx, &edx);
            if ( ecx & XSTATE_ALIGN64 )
                __set_bit(leaf, &xstate_align);
        }
        else
        {
            cpuid_count(XSTATE_CPUID, leaf, &eax,
                        &ebx, &ecx, &edx);
            BUG_ON(eax != xstate_sizes[leaf]);
            BUG_ON(ebx != xstate_offsets[leaf]);
            BUG_ON(!(ecx & XSTATE_ALIGN64) != !test_bit(leaf, &xstate_align));
        }
    }

    return 0;
}

static void setup_xstate_comp(uint16_t *comp_offsets,
                              const uint64_t xcomp_bv)
{
    unsigned int i;
    unsigned int offset;

    /*
     * The FP xstates and SSE xstates are legacy states. They are always
     * in the fixed offsets in the xsave area in either compacted form
     * or standard form.
     */
    comp_offsets[0] = 0;
    comp_offsets[1] = XSAVE_SSE_OFFSET;

    comp_offsets[2] = FXSAVE_SIZE + XSAVE_HDR_SIZE;

    offset = comp_offsets[2];
    for ( i = 2; i < xstate_features; i++ )
    {
        if ( (1UL << i) & xcomp_bv )
        {
            if ( test_bit(i, &xstate_align) )
                offset = ROUNDUP(offset, 64);
            comp_offsets[i] = offset;
            offset += xstate_sizes[i];
        }
    }
    ASSERT(offset <= xsave_cntxt_size);
}

/*
 * Serialise a vcpus xsave state into a representation suitable for the
 * toolstack.
 *
 * Internally a vcpus xsave state may be compressed or uncompressed, depending
 * on the features in use, but the ABI with the toolstack is strictly
 * uncompressed.
 *
 * It is the callers responsibility to ensure that there is xsave state to
 * serialise, and that the provided buffer is exactly the right size.
 */
void expand_xsave_states(const struct vcpu *v, void *dest, unsigned int size)
{
    const struct xsave_struct *xstate = VCPU_MAP_XSAVE_AREA(v);
    const void *src;
    uint16_t comp_offsets[sizeof(xfeature_mask)*8];
    u64 xstate_bv = xstate->xsave_hdr.xstate_bv;
    u64 valid;

    /* Check there is state to serialise (i.e. at least an XSAVE_HDR) */
    BUG_ON(!v->arch.xcr0_accum);
    /* Check there is the correct room to decompress into. */
    BUG_ON(size != xstate_uncompressed_size(v->arch.xcr0_accum));

    if ( !(xstate->xsave_hdr.xcomp_bv & XSTATE_COMPACTION_ENABLED) )
    {
        memcpy(dest, xstate, size);
        goto out;
    }

    ASSERT(xsave_area_compressed(xstate));
    setup_xstate_comp(comp_offsets, xstate->xsave_hdr.xcomp_bv);

    /*
     * Copy legacy XSAVE area and XSAVE hdr area.
     */
    memcpy(dest, xstate, XSTATE_AREA_MIN_SIZE);
    memset(dest + XSTATE_AREA_MIN_SIZE, 0, size - XSTATE_AREA_MIN_SIZE);

    ((struct xsave_struct *)dest)->xsave_hdr.xcomp_bv =  0;

    /*
     * Copy each region from the possibly compacted offset to the
     * non-compacted offset.
     */
    src = xstate;
    valid = xstate_bv & ~XSTATE_FP_SSE;
    while ( valid )
    {
        u64 feature = valid & -valid;
        unsigned int index = fls(feature) - 1;

        /*
         * We previously verified xstate_bv.  If there isn't valid
         * comp_offsets[] information, something is very broken.
         */
        BUG_ON(!comp_offsets[index]);
        BUG_ON((xstate_offsets[index] + xstate_sizes[index]) > size);

        memcpy(dest + xstate_offsets[index], src + comp_offsets[index],
               xstate_sizes[index]);

        valid &= ~feature;
    }

 out:
    VCPU_UNMAP_XSAVE_AREA(v, xstate);
}

/*
 * Deserialise a toolstack's xsave state representation suitably for a vcpu.
 *
 * Internally a vcpus xsave state may be compressed or uncompressed, depending
 * on the features in use, but the ABI with the toolstack is strictly
 * uncompressed.
 *
 * It is the callers responsibility to ensure that the source buffer contains
 * xsave state, is uncompressed, and is exactly the right size.
 */
void compress_xsave_states(struct vcpu *v, const void *src, unsigned int size)
{
    struct xsave_struct *xstate = VCPU_MAP_XSAVE_AREA(v);
    void *dest;
    uint16_t comp_offsets[sizeof(xfeature_mask)*8];
    u64 xstate_bv, valid;

    BUG_ON(!v->arch.xcr0_accum);
    BUG_ON(size != xstate_uncompressed_size(v->arch.xcr0_accum));
    ASSERT(!xsave_area_compressed(src));

    xstate_bv = ((const struct xsave_struct *)src)->xsave_hdr.xstate_bv;

    if ( !(v->arch.xcr0_accum & XSTATE_XSAVES_ONLY) )
    {
        memcpy(xstate, src, size);
        goto out;
    }

    /*
     * Copy legacy XSAVE area, to avoid complications with CPUID
     * leaves 0 and 1 in the loop below.
     */
    memcpy(xstate, src, FXSAVE_SIZE);

    /* Set XSTATE_BV and XCOMP_BV.  */
    xstate->xsave_hdr.xstate_bv = xstate_bv;
    xstate->xsave_hdr.xcomp_bv = v->arch.xcr0_accum | XSTATE_COMPACTION_ENABLED;

    setup_xstate_comp(comp_offsets, xstate->xsave_hdr.xcomp_bv);

    /*
     * Copy each region from the non-compacted offset to the
     * possibly compacted offset.
     */
    dest = xstate;
    valid = xstate_bv & ~XSTATE_FP_SSE;
    while ( valid )
    {
        u64 feature = valid & -valid;
        unsigned int index = fls(feature) - 1;

        /*
         * We previously verified xstate_bv.  If we don't have valid
         * comp_offset[] information, something is very broken.
         */
        BUG_ON(!comp_offsets[index]);
        BUG_ON((xstate_offsets[index] + xstate_sizes[index]) > size);

        memcpy(dest + comp_offsets[index], src + xstate_offsets[index],
               xstate_sizes[index]);

        valid &= ~feature;
    }

 out:
    VCPU_UNMAP_XSAVE_AREA(v, xstate);
}

void xsave(struct vcpu *v, uint64_t mask)
{
    struct xsave_struct *ptr = v->arch.xsave_area;
    uint32_t hmask = mask >> 32;
    uint32_t lmask = mask;
    unsigned int fip_width = v->domain->arch.x87_fip_width;
#define XSAVE(pfx) \
        if ( v->arch.xcr0_accum & XSTATE_XSAVES_ONLY ) \
            asm volatile ( ".byte " pfx "0x0f,0xc7,0x2f\n" /* xsaves */ \
                           : "=m" (*ptr) \
                           : "a" (lmask), "d" (hmask), "D" (ptr) ); \
        else \
            alternative_io(".byte " pfx "0x0f,0xae,0x27\n", /* xsave */ \
                           ".byte " pfx "0x0f,0xae,0x37\n", /* xsaveopt */ \
                           X86_FEATURE_XSAVEOPT, \
                           "=m" (*ptr), \
                           "a" (lmask), "d" (hmask), "D" (ptr))

    if ( fip_width == 8 || !(mask & X86_XCR0_X87) )
    {
        XSAVE("0x48,");
    }
    else if ( fip_width == 4 )
    {
        XSAVE("");
    }
    else
    {
        /*
         * FIP/FDP may not be written in some cases (e.g., if XSAVEOPT/XSAVES
         * is used, or on AMD CPUs if an exception isn't pending).
         *
         * To tell if the hardware writes these fields, poison the FIP field.
         * The poison is
         * a) non-canonical
         * b) non-zero for the reserved part of a 32-bit FCS:FIP
         * c) random with a vanishingly small probability to match a value the
         *    hardware may write (1e-19) even if it did not canonicalize the
         *    64-bit FIP or zero-extend the 16-bit FCS.
         */
        uint64_t orig_fip = ptr->fpu_sse.fip.addr;
        const uint64_t bad_fip = 0x6a3f5c4b13a533f6;

        ptr->fpu_sse.fip.addr = bad_fip;

        XSAVE("0x48,");

        /* FIP/FDP not updated? Restore the old FIP value. */
        if ( ptr->fpu_sse.fip.addr == bad_fip )
        {
            ptr->fpu_sse.fip.addr = orig_fip;
            return;
        }

        /*
         * If the FIP/FDP[63:32] are both zero, it is safe to use the
         * 32-bit restore to also restore the selectors.
         */
        if ( !((ptr->fpu_sse.fip.addr | ptr->fpu_sse.fdp.addr) >> 32) )
        {
            struct ix87_env fpu_env;

            asm volatile ( "fnstenv %0" : "=m" (fpu_env) );
            ptr->fpu_sse.fip.sel = fpu_env.fcs;
            ptr->fpu_sse.fdp.sel = fpu_env.fds;
            fip_width = 4;
        }
        else
            fip_width = 8;
    }
#undef XSAVE
    if ( mask & X86_XCR0_X87 )
        ptr->fpu_sse.x[FPU_WORD_SIZE_OFFSET] = fip_width;
}

void xrstor(struct vcpu *v, uint64_t mask)
{
    uint32_t hmask = mask >> 32;
    uint32_t lmask = mask;
    struct xsave_struct *ptr = v->arch.xsave_area;
    unsigned int faults, prev_faults;

    /*
     * Some CPUs don't save/restore FDP/FIP/FOP unless an exception
     * is pending. Clear the x87 state here by setting it to fixed
     * values. The hypervisor data segment can be sometimes 0 and
     * sometimes new user value. Both should be ok. Use the FPU saved
     * data block as a safe address because it should be in L1.
     */
    if ( cpu_bug_fpu_ptrs &&
         !(ptr->fpu_sse.fsw & ~ptr->fpu_sse.fcw & 0x003f) )
        asm volatile ( "fnclex\n\t"        /* clear exceptions */
                       "ffree %%st(7)\n\t" /* clear stack tag */
                       "fildl %0"          /* load to clear state */
                       : : "m" (ptr->fpu_sse) );

    /*
     * XRSTOR can fault if passed a corrupted data block. We handle this
     * possibility, which may occur if the block was passed to us by control
     * tools or through VCPUOP_initialise, by silently adjusting state.
     */
    for ( prev_faults = faults = 0; ; prev_faults = faults )
    {
        switch ( __builtin_expect(ptr->fpu_sse.x[FPU_WORD_SIZE_OFFSET], 8) )
        {
            BUILD_BUG_ON(sizeof(faults) != 4); /* Clang doesn't support %z in asm. */
#define _xrstor(insn) \
        asm volatile ( "1: .byte " insn "\n" \
                       "3:\n" \
                       "   .section .fixup,\"ax\"\n" \
                       "2: incl %[faults]\n" \
                       "   jmp 3b\n" \
                       "   .previous\n" \
                       _ASM_EXTABLE(1b, 2b) \
                       : [mem] "+m" (*ptr), [faults] "+g" (faults) \
                       : [lmask] "a" (lmask), [hmask] "d" (hmask), \
                         [ptr] "D" (ptr) )

#define XRSTOR(pfx) \
        if ( v->arch.xcr0_accum & XSTATE_XSAVES_ONLY ) \
        { \
            if ( unlikely(!(ptr->xsave_hdr.xcomp_bv & \
                            XSTATE_COMPACTION_ENABLED)) ) \
            { \
                ASSERT(!ptr->xsave_hdr.xcomp_bv); \
                ptr->xsave_hdr.xcomp_bv = ptr->xsave_hdr.xstate_bv | \
                                          XSTATE_COMPACTION_ENABLED; \
            } \
            _xrstor(pfx "0x0f,0xc7,0x1f"); /* xrstors */ \
        } \
        else \
            _xrstor(pfx "0x0f,0xae,0x2f") /* xrstor */

        default:
            XRSTOR("0x48,");
            break;
        case 4: case 2:
            XRSTOR("");
            break;
#undef XRSTOR
#undef _xrstor
        }
        if ( likely(faults == prev_faults) )
            break;
#ifndef NDEBUG
        gprintk(XENLOG_WARNING, "fault#%u: mxcsr=%08x\n",
                faults, ptr->fpu_sse.mxcsr);
        gprintk(XENLOG_WARNING, "xs=%016lx xc=%016lx\n",
                ptr->xsave_hdr.xstate_bv, ptr->xsave_hdr.xcomp_bv);
        gprintk(XENLOG_WARNING, "r0=%016lx r1=%016lx\n",
                ptr->xsave_hdr.reserved[0], ptr->xsave_hdr.reserved[1]);
        gprintk(XENLOG_WARNING, "r2=%016lx r3=%016lx\n",
                ptr->xsave_hdr.reserved[2], ptr->xsave_hdr.reserved[3]);
        gprintk(XENLOG_WARNING, "r4=%016lx r5=%016lx\n",
                ptr->xsave_hdr.reserved[4], ptr->xsave_hdr.reserved[5]);
#endif
        switch ( faults )
        {
        case 1: /* Stage 1: Reset state to be loaded. */
            ptr->xsave_hdr.xstate_bv &= ~mask;
            /*
             * Also try to eliminate fault reasons, even if this shouldn't be
             * needed here (other code should ensure the sanity of the data).
             */
            if ( ((mask & X86_XCR0_SSE) ||
                  ((mask & X86_XCR0_YMM) &&
                   !(ptr->xsave_hdr.xcomp_bv & XSTATE_COMPACTION_ENABLED))) )
                ptr->fpu_sse.mxcsr &= mxcsr_mask;
            if ( v->arch.xcr0_accum & XSTATE_XSAVES_ONLY )
            {
                ptr->xsave_hdr.xcomp_bv &= this_cpu(xcr0) | this_cpu(xss);
                ptr->xsave_hdr.xstate_bv &= ptr->xsave_hdr.xcomp_bv;
                ptr->xsave_hdr.xcomp_bv |= XSTATE_COMPACTION_ENABLED;
            }
            else
            {
                ptr->xsave_hdr.xstate_bv &= this_cpu(xcr0);
                ptr->xsave_hdr.xcomp_bv = 0;
            }
            memset(ptr->xsave_hdr.reserved, 0, sizeof(ptr->xsave_hdr.reserved));
            continue;

        case 2: /* Stage 2: Reset all state. */
            ptr->fpu_sse.mxcsr = MXCSR_DEFAULT;
            ptr->xsave_hdr.xstate_bv = 0;
            ptr->xsave_hdr.xcomp_bv = v->arch.xcr0_accum & XSTATE_XSAVES_ONLY
                                      ? XSTATE_COMPACTION_ENABLED : 0;
            continue;
        }

        domain_crash(current->domain);
        return;
    }
}

bool xsave_enabled(const struct vcpu *v)
{
    if ( !cpu_has_xsave )
        return false;

    ASSERT(xsave_cntxt_size >= XSTATE_AREA_MIN_SIZE);
    ASSERT(v->arch.xsave_area);

    return !!v->arch.xcr0_accum;
}

int xstate_alloc_save_area(struct vcpu *v)
{
    struct xsave_struct *save_area;
    unsigned int size;

    if ( !cpu_has_xsave )
    {
        /*
         * On non-XSAVE systems, we allocate an XSTATE buffer for simplicity.
         * XSTATE is backwards compatible to FXSAVE, and only one cacheline
         * larger.
         */
        size = XSTATE_AREA_MIN_SIZE;
    }
    else if ( !is_idle_vcpu(v) || !cpu_has_xsavec )
    {
        size = xsave_cntxt_size;
        BUG_ON(size < XSTATE_AREA_MIN_SIZE);
    }
    else
    {
        /*
         * For idle vcpus on XSAVEC-capable CPUs allocate an area large
         * enough to save any individual extended state.
         */
        unsigned int i;

        for ( size = 0, i = 2; i < xstate_features; ++i )
            if ( size < xstate_sizes[i] )
                size = xstate_sizes[i];
        size += XSTATE_AREA_MIN_SIZE;
    }

    /* XSAVE/XRSTOR requires the save area be 64-byte-boundary aligned. */
    BUILD_BUG_ON(__alignof(*save_area) < 64);
    save_area = _xvzalloc(size, __alignof(*save_area));
    if ( save_area == NULL )
        return -ENOMEM;

    /*
     * Set the memory image to default values, but don't force the context
     * to be loaded from memory (i.e. keep save_area->xsave_hdr.xstate_bv
     * clear).
     */
    save_area->fpu_sse.fcw = FCW_DEFAULT;
    save_area->fpu_sse.mxcsr = MXCSR_DEFAULT;

    v->arch.xsave_area = save_area;
    v->arch.xcr0 = 0;
    v->arch.xcr0_accum = 0;

    return 0;
}

void xstate_free_save_area(struct vcpu *v)
{
    XVFREE(v->arch.xsave_area);
}

static bool valid_xcr0(uint64_t xcr0)
{
    /* FP must be unconditionally set. */
    if ( !(xcr0 & X86_XCR0_X87) )
        return false;

    /* YMM depends on SSE. */
    if ( (xcr0 & X86_XCR0_YMM) && !(xcr0 & X86_XCR0_SSE) )
        return false;

    if ( xcr0 & (X86_XCR0_OPMASK | X86_XCR0_ZMM | X86_XCR0_HI_ZMM) )
    {
        /* OPMASK, ZMM, and HI_ZMM require YMM. */
        if ( !(xcr0 & X86_XCR0_YMM) )
            return false;

        /* OPMASK, ZMM, and HI_ZMM must be the same. */
        if ( ~xcr0 & (X86_XCR0_OPMASK | X86_XCR0_ZMM | X86_XCR0_HI_ZMM) )
            return false;
    }

    /* BNDREGS and BNDCSR must be the same. */
    if ( !(xcr0 & X86_XCR0_BNDREGS) != !(xcr0 & X86_XCR0_BNDCSR) )
        return false;

    /* TILECFG and TILEDATA must be the same. */
    if ( !(xcr0 & X86_XCR0_TILE_CFG) != !(xcr0 & X86_XCR0_TILE_DATA) )
        return false;

    return true;
}

unsigned int xstate_uncompressed_size(uint64_t xcr0)
{
    unsigned int size = XSTATE_AREA_MIN_SIZE;

    /* Non-XCR0 states don't exist in an uncompressed image. */
    ASSERT((xcr0 & ~X86_XCR0_STATES) == 0);

    if ( xcr0 == 0 )
        return 0;

    if ( xcr0 <= (X86_XCR0_SSE | X86_XCR0_X87) )
        return size;

    /*
     * For the non-legacy states, search all activate states and find the
     * maximum offset+size.  Some states (e.g. LWP, APX_F) are out-of-order
     * with respect their index.
     */
    xcr0 &= ~(X86_XCR0_SSE | X86_XCR0_X87);
    for_each_set_bit ( i, xcr0 )
    {
        const struct xstate_component *c = &raw_cpu_policy.xstate.comp[i];
        unsigned int s = c->offset + c->size;

        ASSERT(c->offset && c->size);

        size = max(size, s);
    }

    return size;
}

unsigned int xstate_compressed_size(uint64_t xstates)
{
    unsigned int size = XSTATE_AREA_MIN_SIZE;

    ASSERT((xstates & ~(X86_XCR0_STATES | X86_XSS_STATES)) == 0);

    if ( xstates == 0 )
        return 0;

    if ( xstates <= (X86_XCR0_SSE | X86_XCR0_X87) )
        return size;

    /*
     * For the compressed size, every non-legacy component matters.  Some
     * componenets require aligning to 64 first.
     */
    xstates &= ~(X86_XCR0_SSE | X86_XCR0_X87);
    for_each_set_bit ( i, xstates )
    {
        const struct xstate_component *c = &raw_cpu_policy.xstate.comp[i];

        ASSERT(c->size);

        if ( c->align )
            size = ROUNDUP(size, 64);

        size += c->size;
    }

    return size;
}

struct xcheck_state {
    uint64_t states;
    uint32_t uncomp_size;
    uint32_t comp_size;
};

static void __init check_new_xstate(struct xcheck_state *s, uint64_t new)
{
    uint32_t hw_size, xen_size;

    BUILD_BUG_ON(X86_XCR0_STATES & X86_XSS_STATES);

    BUG_ON(new <= s->states); /* States strictly increase by index. */
    BUG_ON(s->states & new);  /* States only accumulate. */
    BUG_ON(!valid_xcr0(s->states | new)); /* Xen thinks it's a good value. */
    BUG_ON(new & ~(X86_XCR0_STATES | X86_XSS_STATES)); /* Known state. */
    BUG_ON((new & X86_XCR0_STATES) &&
           (new & X86_XSS_STATES)); /* User or supervisor, not both. */

    s->states |= new;
    if ( new & X86_XCR0_STATES )
    {
        if ( !set_xcr0(s->states & X86_XCR0_STATES) )
            BUG();
    }
    else
        set_msr_xss(s->states & X86_XSS_STATES);

    /*
     * Check the uncompressed size.  First ask hardware.
     */
    hw_size = cpuid_count_ebx(0xd, 0);

    if ( new & X86_XSS_STATES )
    {
        /*
         * Supervisor states don't exist in an uncompressed image, so check
         * that the uncompressed size doesn't change.  Otherwise...
         */
        if ( hw_size != s->uncomp_size )
            panic("XSTATE 0x%016"PRIx64", new sup bits {%63pbl}, uncompressed hw size %#x != prev size %#x\n",
                  s->states, &new, hw_size, s->uncomp_size);
    }
    else
    {
        /*
         * ... some user XSTATEs are out-of-order and fill in prior holes.
         * The best check we make is that the size never decreases.
         */
        if ( hw_size < s->uncomp_size )
            panic("XSTATE 0x%016"PRIx64", new bits {%63pbl}, uncompressed hw size %#x < prev size %#x\n",
                  s->states, &new, hw_size, s->uncomp_size);
    }

    s->uncomp_size = hw_size;

    /*
     * Second, check that Xen's calculation always matches hardware's.
     */
    xen_size = xstate_uncompressed_size(s->states & X86_XCR0_STATES);

    if ( xen_size != hw_size )
        panic("XSTATE 0x%016"PRIx64", uncompressed hw size %#x != xen size %#x\n",
              s->states, hw_size, xen_size);

    /*
     * Check the compressed size, if available.
     */
    hw_size = cpuid_count_ebx(0xd, 1);

    if ( cpu_has_xsavec )
    {
        /*
         * All components strictly appear in index order, irrespective of
         * whether they're user or supervisor.  As each component also has
         * non-zero size, the accumulated size should strictly increase.
         */
        if ( hw_size <= s->comp_size )
            panic("XSTATE 0x%016"PRIx64", new bits {%63pbl}, compressed hw size %#x <= prev size %#x\n",
                  s->states, &new, hw_size, s->comp_size);

        s->comp_size = hw_size;

        /*
         * Again, check that Xen's calculation always matches hardware's.
         */
        xen_size = xstate_compressed_size(s->states);

        if ( xen_size != hw_size )
            panic("XSTATE 0x%016"PRIx64", compressed hw size %#x != xen size %#x\n",
                  s->states, hw_size, xen_size);
    }
    else if ( hw_size ) /* Compressed size reported, but no XSAVEC ? */
    {
        static bool once;

        if ( !once )
        {
            WARN();
            once = true;
        }
    }
}

/*
 * The {un,}compressed XSTATE sizes are reported by dynamic CPUID value, based
 * on the current %XCR0 and MSR_XSS values.  The exact layout is also feature
 * and vendor specific.  Cross-check Xen's understanding against real hardware
 * on boot.
 *
 * Testing every combination is prohibitive, so we use a partial approach.
 * Starting with nothing active, we add new XSTATEs and check that the CPUID
 * dynamic values never decreases.
 */
static void __init noinline xstate_check_sizes(void)
{
    uint64_t old_xcr0 = get_xcr0();
    uint64_t old_xss = get_msr_xss();
    struct xcheck_state s = {};

    /*
     * User and supervisor XSTATEs, increasing by index.
     *
     * Chronologically, Intel and AMD had identical layouts for AVX (YMM).
     * AMD introduced LWP in Fam15h, following immediately on from YMM.  Intel
     * left an LWP-shaped hole when adding MPX (BND{CSR,REGS}) in Skylake.
     * AMD removed LWP in Fam17h, putting PKRU in the same space, breaking
     * layout compatibility with Intel and having a knock-on effect on all
     * subsequent states.
     */
    check_new_xstate(&s, X86_XCR0_SSE | X86_XCR0_X87);

    if ( cpu_has_avx )
        check_new_xstate(&s, X86_XCR0_YMM);

    if ( cpu_has_mpx )
        check_new_xstate(&s, X86_XCR0_BNDCSR | X86_XCR0_BNDREGS);

    if ( cpu_has_avx512f )
        check_new_xstate(&s, X86_XCR0_HI_ZMM | X86_XCR0_ZMM | X86_XCR0_OPMASK);

    /*
     * Intel Broadwell has Processor Trace but no XSAVES.  There doesn't
     * appear to have been a new enumeration when X86_XSS_PROC_TRACE was
     * introduced in Skylake.
     */
    if ( cpu_has_xsaves && cpu_has_proc_trace )
        check_new_xstate(&s, X86_XSS_PROC_TRACE);

    if ( cpu_has_pku )
        check_new_xstate(&s, X86_XCR0_PKRU);

    if ( cpu_has_xsaves && boot_cpu_has(X86_FEATURE_ENQCMD) )
        check_new_xstate(&s, X86_XSS_PASID);

    if ( cpu_has_xsaves && (boot_cpu_has(X86_FEATURE_CET_SS) ||
                            boot_cpu_has(X86_FEATURE_CET_IBT)) )
    {
        check_new_xstate(&s, X86_XSS_CET_U);
        check_new_xstate(&s, X86_XSS_CET_S);
    }

    if ( cpu_has_xsaves && boot_cpu_has(X86_FEATURE_UINTR) )
        check_new_xstate(&s, X86_XSS_UINTR);

    if ( cpu_has_xsaves && boot_cpu_has(X86_FEATURE_ARCH_LBR) )
        check_new_xstate(&s, X86_XSS_LBR);

    if ( boot_cpu_has(X86_FEATURE_AMX_TILE) )
        check_new_xstate(&s, X86_XCR0_TILE_DATA | X86_XCR0_TILE_CFG);

    if ( boot_cpu_has(X86_FEATURE_LWP) )
        check_new_xstate(&s, X86_XCR0_LWP);

    /* Restore old state now the test is done. */
    if ( !set_xcr0(old_xcr0) )
        BUG();
    if ( cpu_has_xsaves )
        set_msr_xss(old_xss);
}

/* Collect the information of processor's extended state */
void xstate_init(struct cpuinfo_x86 *c)
{
    /*
     * NB: use_xsave cannot live in initdata because llvm might optimize
     * reading it, see: https://bugs.llvm.org/show_bug.cgi?id=39707
     */
    static bool __read_mostly use_xsave = true;
    boolean_param("xsave", use_xsave);

    bool bsp = c == &boot_cpu_data;
    u32 eax, ebx, ecx, edx;
    u64 feature_mask;

    if ( bsp )
    {
        static fpusse_t __initdata ctxt;

        asm ( "fxsave %0" : "=m" (ctxt) );
        if ( ctxt.mxcsr_mask )
            mxcsr_mask = ctxt.mxcsr_mask;
    }

    if ( !cpu_has_xsave )
        return;

    if ( (bsp && !use_xsave) ||
         boot_cpu_data.cpuid_level < XSTATE_CPUID )
    {
        BUG_ON(!bsp);
        setup_clear_cpu_cap(X86_FEATURE_XSAVE);
        return;
    }

    cpuid_count(XSTATE_CPUID, 0, &eax, &ebx, &ecx, &edx);
    feature_mask = (((u64)edx << 32) | eax) & XCNTXT_MASK;
    BUG_ON(!valid_xcr0(feature_mask));
    BUG_ON(!(feature_mask & X86_XCR0_SSE));

    /*
     * Set CR4_OSXSAVE and run "cpuid" to get xsave_cntxt_size.
     */
    set_in_cr4(X86_CR4_OSXSAVE);

    /*
     * Zap the cached values to make set_xcr0() and set_msr_xss() really write
     * the hardware register.
     */
    this_cpu(xcr0) = 0;
    if ( !set_xcr0(feature_mask) )
        BUG();
    if ( cpu_has_xsaves )
    {
        this_cpu(xss) = ~0;
        set_msr_xss(0);
    }

    if ( bsp )
    {
        xfeature_mask = feature_mask;
        /*
         * xsave_cntxt_size is the max size required by enabled features.
         * We know FP/SSE and YMM about eax, and nothing about edx at present.
         */
        xsave_cntxt_size = cpuid_count_ebx(0xd, 0);
        printk("xstate: size: %#x and states: %#"PRIx64"\n",
               xsave_cntxt_size, xfeature_mask);
    }
    else
    {
        BUG_ON(xfeature_mask != feature_mask);
        BUG_ON(xsave_cntxt_size != cpuid_count_ebx(0xd, 0));
    }

    if ( setup_xstate_features(bsp) && bsp )
        BUG();

    if ( IS_ENABLED(CONFIG_SELF_TESTS) && bsp )
        xstate_check_sizes();
}

int validate_xstate(const struct domain *d, uint64_t xcr0, uint64_t xcr0_accum,
                    const struct xsave_hdr *hdr)
{
    uint64_t xcr0_max = cpu_policy_xcr0_max(d->arch.cpuid);
    unsigned int i;

    if ( (hdr->xstate_bv & ~xcr0_accum) ||
         (xcr0 & ~xcr0_accum) ||
         (xcr0_accum & ~xcr0_max) ||
         !valid_xcr0(xcr0) ||
         !valid_xcr0(xcr0_accum) )
        return -EINVAL;

    if ( (xcr0_accum & ~xfeature_mask) ||
         hdr->xcomp_bv )
        return -EOPNOTSUPP;

    for ( i = 0; i < ARRAY_SIZE(hdr->reserved); ++i )
        if ( hdr->reserved[i] )
            return -EIO;

    return 0;
}

int handle_xsetbv(u32 index, u64 new_bv)
{
    struct vcpu *curr = current;
    uint64_t xcr0_max = cpu_policy_xcr0_max(curr->domain->arch.cpuid);
    u64 mask;

    if ( index != XCR_XFEATURE_ENABLED_MASK )
        return -EOPNOTSUPP;

    /*
     * The CPUID logic shouldn't be able to hand out an XCR0 exceeding Xen's
     * maximum features, but keep the check for robustness.
     */
    if ( unlikely(xcr0_max & ~xfeature_mask) )
    {
        gprintk(XENLOG_ERR,
                "xcr0_max %016" PRIx64 " exceeds hardware max %016" PRIx64 "\n",
                xcr0_max, xfeature_mask);
        domain_crash(curr->domain);

        return -EINVAL;
    }

    if ( (new_bv & ~xcr0_max) || !valid_xcr0(new_bv) )
        return -EINVAL;

    /* By this point, new_bv really should be accepted by hardware. */
    if ( unlikely(!set_xcr0(new_bv)) )
    {
        gprintk(XENLOG_ERR, "new_bv %016" PRIx64 " rejected by hardware\n",
                new_bv);
        domain_crash(curr->domain);

        return -EFAULT;
    }

    mask = new_bv & ~curr->arch.xcr0_accum;
    curr->arch.xcr0 = new_bv;
    curr->arch.xcr0_accum |= new_bv;

    if ( new_bv & XSTATE_NONLAZY )
        curr->arch.nonlazy_xstate_used = 1;

    mask &= curr->fpu_dirtied ? ~XSTATE_FP_SSE : XSTATE_NONLAZY;
    if ( mask )
    {
        unsigned long cr0 = read_cr0();

        clts();
        if ( curr->fpu_dirtied )
        {
            /* Has a fastpath for `current`, so there's no actual map */
            struct xsave_struct *xsave_area = VCPU_MAP_XSAVE_AREA(curr);

            asm ( "stmxcsr %0" : "=m" (xsave_area->fpu_sse.mxcsr) );
            VCPU_UNMAP_XSAVE_AREA(curr, xsave_area);
        }
        else if ( xstate_all(curr) )
        {
            /* See the comment in i387.c:vcpu_restore_fpu_eager(). */
            mask |= XSTATE_LAZY;
            curr->fpu_initialised = 1;
            curr->fpu_dirtied = 1;
            cr0 &= ~X86_CR0_TS;
        }
        xrstor(curr, mask);
        if ( cr0 & X86_CR0_TS )
            write_cr0(cr0);
    }

    return 0;
}

uint64_t read_bndcfgu(void)
{
    unsigned long cr0 = read_cr0();
    struct xsave_struct *xstate
        = idle_vcpu[smp_processor_id()]->arch.xsave_area;
    const struct xstate_bndcsr *bndcsr;

    ASSERT(cpu_has_mpx);
    clts();

    if ( cpu_has_xsavec )
    {
        asm ( ".byte 0x0f,0xc7,0x27\n" /* xsavec */
              : "=m" (*xstate)
              : "a" (X86_XCR0_BNDCSR), "d" (0), "D" (xstate) );

        bndcsr = (void *)(xstate + 1);
    }
    else
    {
        asm ( ".byte 0x0f,0xae,0x27\n" /* xsave */
              : "=m" (*xstate)
              : "a" (X86_XCR0_BNDCSR), "d" (0), "D" (xstate) );

        bndcsr = (void *)xstate + xstate_offsets[ilog2(X86_XCR0_BNDCSR)];
    }

    if ( cr0 & X86_CR0_TS )
        write_cr0(cr0);

    return xstate->xsave_hdr.xstate_bv & X86_XCR0_BNDCSR ? bndcsr->bndcfgu : 0;
}

void xstate_set_init(uint64_t mask)
{
    unsigned long cr0 = read_cr0();
    unsigned long xcr0 = this_cpu(xcr0);
    struct vcpu *v = idle_vcpu[smp_processor_id()];
    struct xsave_struct *xstate;

    if ( ~xfeature_mask & mask )
    {
        ASSERT_UNREACHABLE();
        return;
    }

    if ( (~xcr0 & mask) && !set_xcr0(xcr0 | mask) )
        return;

    clts();

    xstate = VCPU_MAP_XSAVE_AREA(v);
    memset(&xstate->xsave_hdr, 0, sizeof(xstate->xsave_hdr));
    xrstor(v, mask);
    VCPU_UNMAP_XSAVE_AREA(v, xstate);

    if ( cr0 & X86_CR0_TS )
        write_cr0(cr0);

    if ( (~xcr0 & mask) && !set_xcr0(xcr0) )
        BUG();
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
