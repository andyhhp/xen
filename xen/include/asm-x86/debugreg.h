#ifndef _X86_DEBUGREG_H
#define _X86_DEBUGREG_H

/*
 * DR6 status bits.
 *   N.B. For backwards compatibility, X86_DR6_RTM has inverted polarity.
 */
#define X86_DR6_B0              (1u <<  0)  /* Breakpoint 0 triggered  */
#define X86_DR6_B1              (1u <<  1)  /* Breakpoint 1 triggered  */
#define X86_DR6_B2              (1u <<  2)  /* Breakpoint 2 triggered  */
#define X86_DR6_B3              (1u <<  3)  /* Breakpoint 3 triggered  */
#define X86_DR6_BD              (1u << 13)  /* Debug register accessed */
#define X86_DR6_BS              (1u << 14)  /* Single step             */
#define X86_DR6_BT              (1u << 15)  /* Task switch             */
#define X86_DR6_RTM             (1u << 16)  /* #DB/#BP in RTM region   */

#define X86_DR6_BP_MASK                                 \
    (X86_DR6_B0 | X86_DR6_B1 | X86_DR6_B2 | X86_DR6_B3)

#define X86_DR6_KNOWN_MASK                                              \
    (X86_DR6_BP_MASK | X86_DR6_BD | X86_DR6_BS | X86_DR6_BT | X86_DR6_RTM)

#define X86_DR6_DEFAULT 0xffff0ff0ul    /* Default %dr6 value. */

/* Now define a bunch of things for manipulating the control register.
   The top two bytes of the control register consist of 4 fields of 4
   bits - each field corresponds to one of the four debug registers,
   and indicates what types of access we trap on, and how large the data
   field is that we are looking at */

#define DR_CONTROL_SHIFT 16 /* Skip this many bits in ctl register */
#define DR_CONTROL_SIZE   4 /* 4 control bits per register */

#define DR_RW_EXECUTE (0x0) /* Settings for the access types to trap on */
#define DR_RW_WRITE   (0x1)
#define DR_IO         (0x2)
#define DR_RW_READ    (0x3)

#define DR_LEN_1      (0x0) /* Settings for data length to trap on */
#define DR_LEN_2      (0x4)
#define DR_LEN_4      (0xC)
#define DR_LEN_8      (0x8)

/* The low byte to the control register determine which registers are
   enabled.  There are 4 fields of two bits.  One bit is "local", meaning
   that the processor will reset the bit after a task switch and the other
   is global meaning that we have to explicitly reset the bit. */

#define DR_LOCAL_ENABLE_SHIFT  0   /* Extra shift to the local enable bit */
#define DR_GLOBAL_ENABLE_SHIFT 1   /* Extra shift to the global enable bit */
#define DR_ENABLE_SIZE         2   /* 2 enable bits per register */

#define DR_LOCAL_ENABLE_MASK (0x55)  /* Set  local bits for all 4 regs */
#define DR_GLOBAL_ENABLE_MASK (0xAA) /* Set global bits for all 4 regs */

#define DR7_ACTIVE_MASK (DR_LOCAL_ENABLE_MASK|DR_GLOBAL_ENABLE_MASK)

/* The second byte to the control register has a few special things.
   We can slow the instruction pipeline for instructions coming via the
   gdt or the ldt if we want to.  I am not sure why this is an advantage */

#define DR_LOCAL_EXACT_ENABLE    (0x00000100ul) /* Local exact enable */
#define DR_GLOBAL_EXACT_ENABLE   (0x00000200ul) /* Global exact enable */
#define DR_RTM_ENABLE            (0x00000800ul) /* RTM debugging enable */
#define DR_GENERAL_DETECT        (0x00002000ul) /* General detect enable */

#define X86_DR7_DEFAULT 0x00000400ul    /* Default %dr7 value. */

#define write_debugreg(reg, val) do {                       \
    unsigned long __val = val;                              \
    asm volatile ( "mov %0,%%db" #reg : : "r" (__val) );    \
} while (0)
#define read_debugreg(reg) ({                               \
    unsigned long __val;                                    \
    asm volatile ( "mov %%db" #reg ",%0" : "=r" (__val) );  \
    __val;                                                  \
})
long set_debugreg(struct vcpu *, unsigned int reg, unsigned long value);
void activate_debugregs(const struct vcpu *);

static inline unsigned long adjust_dr6_rsvd(unsigned long dr6, bool rtm)
{
    /*
     * DR6: Bits 4-11,17-31 reserved (set to 1).
     *      Bit  16 reserved (set to 1) if RTM unavailable.
     *      Bit  12 reserved (set to 0).
     */
    dr6 |= 0xfffe0ff0 | (rtm ? 0 : X86_DR6_RTM);
    dr6 &= 0xffffefff;

    return dr6;
}

static inline unsigned long merge_dr6(unsigned long dr6, unsigned long new,
                                      bool rtm)
{
    /* Flip dr6 to have positive polarity. */
    dr6 ^= X86_DR6_DEFAULT;

    /* Sanity check that only known values are passed in. */
    ASSERT(!(dr6 & ~X86_DR6_KNOWN_MASK));
    ASSERT(!(new & ~X86_DR6_KNOWN_MASK));

    /* Breakpoints 0-3 overridden.  BD, BS, BT and RTM accumulate. */
    dr6 = (dr6 & ~X86_DR6_BP_MASK) | new;

    /* Flip dr6 back to having default polarity. */
    dr6 ^= X86_DR6_DEFAULT;

    return adjust_dr6_rsvd(dr6, rtm);
}

static inline unsigned long adjust_dr7_rsvd(unsigned long dr7, bool rtm)
{
    /*
     * DR7: Bit  10 reserved (set to 1).
     *      Bit  11 reserved (set to 0) if RTM unavailable.
     *      Bits 12,14-15 reserved (set to 0).
     */
    dr7 |= 0x00000400;
    dr7 &= 0xffff23ff & (rtm ? 0 : ~DR_RTM_ENABLE);

    return dr7;
}

#endif /* _X86_DEBUGREG_H */
