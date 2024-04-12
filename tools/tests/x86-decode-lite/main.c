/*
 * Userspace test harness for x86_decode_lite().
 */
#include <stdio.h>

#include "x86-emulate.h"

static unsigned int nr_failures;
#define fail(t, fmt, ...)                                       \
({                                                              \
    const unsigned char *insn = (t)->ip;                        \
                                                                \
    nr_failures++;                                              \
                                                                \
    (void)printf("  Fail '%s' [%02x", (t)->name, *insn);        \
    for ( unsigned int i = 1; i < (t)->len; i++ )               \
        printf(" %02x", insn[i]);                               \
    printf("]\n");                                              \
                                                                \
    (void)printf(fmt, ##__VA_ARGS__);                           \
})

struct test {
    const char *name;
    void *ip;
    unsigned long len;
};

extern const struct test
/* Defined in insns.S, ends with sentinel */
    tests_rel0[], /* No relocatable entry */
    tests_rel1[], /* disp8 */
    tests_rel4[], /* disp32 or RIP-relative */
    tests_unsup[]; /* Unsupported instructions */

static inline void run_tests(const struct test *tests, unsigned int rel_sz)
{
    printf("Test rel%u\n", rel_sz);

    for ( unsigned int i = 0; tests[i].name; ++i )
    {
        const struct test *t = &tests[i];
        x86_decode_lite_t r;

        /*
         * Don't end strictly at t->len.  This provides better diagnostics if
         * too many bytes end up getting consumed.
         */
        r = x86_decode_lite(t->ip, t->ip + /* t->len */ 20);

        if ( r.len == 0 )
        {
            fail(t, "    Failed to decode instruction\n");

            if ( r.rel_sz != 0 || r.rel )
                fail(t, "    Rel/sz despite no decode\n");

            continue;
        }

        if ( r.len != t->len )
        {
            fail(t, "    Expected length %lu, got %u\n",
                 t->len, r.len);
            continue;
        }

        if ( r.rel_sz != rel_sz )
        {
            fail(t, "    Expected relocation size %u, got %u\n",
                 rel_sz, r.rel_sz);
            continue;
        }

        if ( r.rel_sz &&
             (r.rel < t->ip ||
              r.rel > t->ip + t->len ||
              r.rel + r.rel_sz > t->ip + t->len) )
        {
            fail(t, "    Rel [%p,+%u) outside insn [%p,+%lu)\n",
                 r.rel, r.rel_sz, t->ip, t->len);
            continue;
        }
    }
}

static void run_tests_unsup(const struct test *tests)
{
    printf("Test unsup\n");

    for ( unsigned int i = 0; tests[i].name; ++i )
    {
        const struct test *t = &tests[i];
        x86_decode_lite_t r = x86_decode_lite(t->ip, t->ip + t->len);

        if ( r.len )
            fail(t, "    Got len %u\n", r.len);
    }
}

int main(int argc, char **argv)
{
    printf("Tests for x86_decode_lite()\n");

    run_tests(tests_rel0, 0);
    run_tests(tests_rel1, 1);
    run_tests(tests_rel4, 4);
    run_tests_unsup(tests_unsup);

    return !!nr_failures;
}
