/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Adapted from Linux's arch/powerpc/include/asm/bitops.h.
 *
 * Merged version by David Gibson <david@gibson.dropbear.id.au>.
 * Based on ppc64 versions by: Dave Engebretsen, Todd Inglett, Don
 * Reed, Pat McCarthy, Peter Bergner, Anton Blanchard.  They
 * originally took it from the ppc32 code.
 */
#ifndef _ASM_PPC_BITOPS_H
#define _ASM_PPC_BITOPS_H

#include <asm/memory.h>

#define __set_bit(n, p)         set_bit(n, p)
#define __clear_bit(n, p)       clear_bit(n, p)

#define BITOP_BITS_PER_WORD     32
#define BITOP_MASK(nr)          (1U << ((nr) % BITOP_BITS_PER_WORD))
#define BITOP_WORD(nr)          ((nr) / BITOP_BITS_PER_WORD)
#define BITS_PER_BYTE           8

/* PPC bit number conversion */
#define PPC_BITLSHIFT(be)    (BITS_PER_LONG - 1 - (be))
#define PPC_BIT(bit)         (1UL << PPC_BITLSHIFT(bit))
#define PPC_BITMASK(bs, be)  ((PPC_BIT(bs) - PPC_BIT(be)) | PPC_BIT(bs))

/* Macro for generating the ***_bits() functions */
#define DEFINE_BITOP(fn, op)                                                   \
static inline void fn(unsigned int mask,                                       \
                      volatile unsigned int *p_)                               \
{                                                                              \
    unsigned int old;                                                          \
    unsigned int *p = (unsigned int *)p_;                                      \
    asm volatile ( "1: lwarx %0,0,%3,0\n"                                      \
                   #op "%I2 %0,%0,%2\n"                                        \
                   "stwcx. %0,0,%3\n"                                          \
                   "bne- 1b\n"                                                 \
                   : "=&r" (old), "+m" (*p)                                    \
                   : "rK" (mask), "r" (p)                                      \
                   : "cc", "memory" );                                         \
}

DEFINE_BITOP(set_bits, or)
DEFINE_BITOP(change_bits, xor)

#define DEFINE_CLROP(fn)                                                       \
static inline void fn(unsigned int mask, volatile unsigned int *p_)            \
{                                                                              \
    unsigned int old;                                                          \
    unsigned int *p = (unsigned int *)p_;                                      \
    asm volatile ( "1: lwarx %0,0,%3,0\n"                                      \
                   "andc %0,%0,%2\n"                                           \
                   "stwcx. %0,0,%3\n"                                          \
                   "bne- 1b\n"                                                 \
                   : "=&r" (old), "+m" (*p)                                    \
                   : "r" (mask), "r" (p)                                       \
                   : "cc", "memory" );                                         \
}

DEFINE_CLROP(clear_bits)

static inline void set_bit(int nr, volatile void *addr)
{
    set_bits(BITOP_MASK(nr), (volatile unsigned int *)addr + BITOP_WORD(nr));
}
static inline void clear_bit(int nr, volatile void *addr)
{
    clear_bits(BITOP_MASK(nr), (volatile unsigned int *)addr + BITOP_WORD(nr));
}

/**
 * test_bit - Determine whether a bit is set
 * @nr: bit number to test
 * @addr: Address to start counting from
 */
static inline int test_bit(int nr, const volatile void *addr)
{
    const volatile unsigned int *p = addr;
    return 1 & (p[BITOP_WORD(nr)] >> (nr & (BITOP_BITS_PER_WORD - 1)));
}

static inline unsigned int test_and_clear_bits(
    unsigned int mask,
    volatile unsigned int *p)
{
    unsigned int old, t;

    asm volatile ( PPC_ATOMIC_ENTRY_BARRIER
                   "1: lwarx %0,0,%3,0\n"
                   "andc %1,%0,%2\n"
                   "stwcx. %1,0,%3\n"
                   "bne- 1b\n"
                   PPC_ATOMIC_EXIT_BARRIER
                   : "=&r" (old), "=&r" (t)
                   : "r" (mask), "r" (p)
                   : "cc", "memory" );

    return (old & mask);
}

static inline int test_and_clear_bit(unsigned int nr,
                                     volatile void *addr)
{
    return test_and_clear_bits(
        BITOP_MASK(nr),
        (volatile unsigned int *)addr + BITOP_WORD(nr)) != 0;
}

static inline unsigned int test_and_set_bits(
    unsigned int mask,
    volatile unsigned int *p)
{
    unsigned int old, t;

    asm volatile ( PPC_ATOMIC_ENTRY_BARRIER
                   "1: lwarx %0,0,%3,0\n"
                   "or%I2 %1,%0,%2\n"
                   "stwcx. %1,0,%3\n"
                   "bne- 1b\n"
                   PPC_ATOMIC_EXIT_BARRIER
                   : "=&r" (old), "=&r" (t)
                   : "rK" (mask), "r" (p)
                   : "cc", "memory" );

    return (old & mask);
}

static inline int test_and_set_bit(unsigned int nr, volatile void *addr)
{
    return test_and_set_bits(
        BITOP_MASK(nr),
        (volatile unsigned int *)addr + BITOP_WORD(nr)) != 0;
}

/**
 * __test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is non-atomic and can be reordered.
 * If two examples of this operation race, one can appear to succeed
 * but actually fail.  You must protect multiple accesses with a lock.
 */
static inline int __test_and_set_bit(int nr, volatile void *addr)
{
    unsigned int mask = BITOP_MASK(nr);
    volatile unsigned int *p = (volatile unsigned int *)addr + BITOP_WORD(nr);
    unsigned int old = *p;

    *p = old | mask;
    return (old & mask) != 0;
}

/**
 * __test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to clear
 * @addr: Address to count from
 *
 * This operation is non-atomic and can be reordered.
 * If two examples of this operation race, one can appear to succeed
 * but actually fail.  You must protect multiple accesses with a lock.
 */
static inline int __test_and_clear_bit(int nr, volatile void *addr)
{
    unsigned int mask = BITOP_MASK(nr);
    volatile unsigned int *p = (volatile unsigned int *)addr + BITOP_WORD(nr);
    unsigned int old = *p;

    *p = old & ~mask;
    return (old & mask) != 0;
}

#define arch_ffs(x)  ((x) ? 1 + __builtin_ctz(x) : 0)
#define arch_ffsl(x) ((x) ? 1 + __builtin_ctzl(x) : 0)
#define arch_fls(x)  ((x) ? 32 - __builtin_clz(x) : 0)
#define arch_flsl(x) ((x) ? BITS_PER_LONG - __builtin_clzl(x) : 0)

/**
 * hweightN - returns the hamming weight of a N-bit word
 * @x: the word to weigh
 *
 * The Hamming Weight of a number is the total number of bits set in it.
 */
#define hweight64(x) __builtin_popcountll(x)
#define hweight32(x) __builtin_popcount(x)
#define hweight16(x) __builtin_popcount((uint16_t)(x))
#define hweight8(x)  __builtin_popcount((uint8_t)(x))

#endif /* _ASM_PPC_BITOPS_H */
