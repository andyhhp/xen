#include <stdio.h>
#include <err.h>
#include <string.h>
#include <errno.h>

#include <xenctrl.h>
#include <xen-tools/libs.h>

static xc_interface *xch;

static void test_domain_create(void)
{
    static struct test {
        const char *name;
        struct xen_domctl_createdomain create;
    } tests[] = {
#if defined(__i386__) || defined(__x86_64__)
        {
            .name = "x86 PV",
            .create = {
                .max_vcpus = 1,
            },
        },
        {
            .name = "x86 PVH Shadow",
            .create = {
                .flags = XEN_DOMCTL_CDF_hvm,
                .max_vcpus = 1,
                .arch = {
                    .emulation_flags = XEN_X86_EMU_LAPIC,
                },
            },
        },
        {
            .name = "x86 PVH HAP",
            .create = {
                .flags = XEN_DOMCTL_CDF_hvm | XEN_DOMCTL_CDF_hap,
                .max_vcpus = 1,
                .arch = {
                    .emulation_flags = XEN_X86_EMU_LAPIC,
                },
            },
        },
        {
            .name = "x86 HVM",
            .create = {
                .flags = XEN_DOMCTL_CDF_hvm | XEN_DOMCTL_CDF_hap,
                .max_vcpus = 1,
                .arch = {
                    .emulation_flags = XEN_X86_EMU_ALL,
                },
            },
        },
#endif /* x86 */
    };

    printf("Testing domain create:\n");

    for ( size_t i = 0; i < ARRAY_SIZE(tests); ++i )
    {
        struct test *t = &tests[i];
        uint32_t domid = 0;
        int rc;

        do {
            t->create.fault_ttl++;
            rc = xc_domain_create(xch, &domid, &t->create);
        } while ( rc && errno == ENOMEM );

        if ( rc == 0 )
        {
            printf("  %s d%u created with fault_ttl of %u\n",
                   t->name, domid, t->create.fault_ttl);
            xc_domain_destroy(xch, domid);
        }
        else
            printf("  %s creation failed: %d: %s\n",
                   t->name, -errno, strerror(errno));
    }
}

int main(int argc, char **argv)
{
    xch = xc_interface_open(NULL, NULL, 0);
    if ( !xch )
        err(1, "xc_interface_open");

    test_domain_create();

    xc_interface_close(xch);

    return 0;
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
