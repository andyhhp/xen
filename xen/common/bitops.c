#include <xen/bitops.h>
#include <xen/bug.h>
#include <xen/init.h>

/* Hide a value from the optimiser. */
#define HIDE(x) ({ typeof(x) _x = (x); asm volatile ( "" : "+r" (_x) ); _x; })

/*
 * Check that fn(val) can be calcuated by the compiler, and that it gives the
 * expected answer.
 *
 * Clang < 8 can't fold constants through static inlines, causing this to
 * fail.  Simply skip it for incredibly old compilers.
 */
#if !CONFIG_CC_IS_CLANG || CONFIG_CLANG_VERSION >= 80000
#define COMPILE_CHECK(fn, val, res)                                     \
    do {                                                                \
        typeof(fn(val)) real = fn(val);                                 \
                                                                        \
        if ( !__builtin_constant_p(real) )                              \
            asm ( ".error \"'" STR(fn(val)) "' not compile-time constant\"" ); \
        else if ( real != res )                                         \
            asm ( ".error \"Compile time check '" STR(fn(val) == res) "' failed\"" ); \
    } while ( 0 )
#else
#define COMPILE_CHECK(fn, val, res)
#endif

/*
 * Check that Xen's runtime logic for fn(val) gives the expected answer.  This
 * requires using HIDE() to prevent the optimiser from emitting the full
 * calculation.
 */
#define RUNTIME_CHECK(fn, val, res)             \
    do {                                        \
        BUG_ON(fn(HIDE(val)) != res);           \
    } while ( 0 )

/*
 * Perform compiletime and runtime checks for fn(val) == res.
 */
#define CHECK(fn, val, res)                     \
    do {                                        \
        COMPILE_CHECK(fn, val, res);            \
        RUNTIME_CHECK(fn, val, res);            \
    } while ( 0 )

static int __init cf_check test_bitops(void)
{
    return 0;
}
__initcall(test_bitops);
