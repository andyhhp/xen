#include <xen/bitops.h>
#include <xen/boot-check.h>
#include <xen/init.h>

static void __init test_ffs(void)
{
    /* unsigned int ffs(unsigned int) */
    CHECK(ffs, 0, 0);
    CHECK(ffs, 1, 1);
    CHECK(ffs, 3, 1);
    CHECK(ffs, 7, 1);
    CHECK(ffs, 6, 2);
    CHECK(ffs, 0x80000000U, 32);
}

static void __init __constructor test_bitops(void)
{
    test_ffs();
}
