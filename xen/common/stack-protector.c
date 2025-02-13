/* SPDX-License-Identifier: GPL-2.0-only */
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/random.h>
#include <xen/time.h>

/*
 * Initial value is chosen by a fair dice roll.
 * It will be updated during boot process.
 */
#if BITS_PER_LONG == 32
unsigned long __ro_after_init __stack_chk_guard = 0xdd2cc927UL;
#else
unsigned long __ro_after_init __stack_chk_guard = 0x2d853605a4d9a09cUL;
#endif

/*
 * This function should be called from early asm or from a C function
 * that escapes stack canary tracking (by calling
 * reset_stack_and_jump() for example).
 */
void __init asmlinkage boot_stack_chk_guard_setup(void)
{
    /*
     * Linear congruent generator (X_n+1 = X_n * a + c).
     *
     * Constant is taken from "Tables Of Linear Congruential
     * Generators Of Different Sizes And Good Lattice Structure" by
     * Pierre L’Ecuyer.
     */
#if BITS_PER_LONG == 32
    const unsigned long a = 2891336453UL;
#else
    const unsigned long a = 2862933555777941757UL;
#endif
    const unsigned long c = 1;

    unsigned long cycles = get_cycles();

    /* Use the initial value if we can't generate random one */
    if ( !cycles )
        return;

    __stack_chk_guard = cycles * a + c;
}

void asmlinkage __stack_chk_fail(void)
{
    dump_execution_state();
    panic("Stack Protector integrity violation identified\n");
}
