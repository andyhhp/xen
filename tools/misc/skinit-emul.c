#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define XC_WANT_COMPAT_MAP_FOREIGN_API 1
#include <xenctrl.h>
#include <xenctrl_compat.h>

#include <xen-tools/libs.h>

#define X86_CR0_PE 0x01
#define X86_CR0_ET 0x10

#define X86_DR6_DEFAULT 0xffff0ff0u
#define X86_DR7_DEFAULT 0x00000400u

int main(int argc, char **argv)
{
    xc_interface *xch = xc_interface_open(NULL, NULL, 0);

    if ( argc < 2 )
        errx(1, "Usage skinit-emul $file [$load_addr]");

    if ( !xch )
        err(1, "xc_interface_open");

    struct xen_domctl_createdomain create = {
        .flags = (XEN_DOMCTL_CDF_hvm |
                  XEN_DOMCTL_CDF_hap),
        .max_vcpus = 1,
        .max_evtchn_port = -1,
        .max_grant_frames = 64,
        .max_maptrack_frames = 1024,
        .arch = {
            .emulation_flags = XEN_X86_EMU_LAPIC,
        },
    };
    uint32_t domid = 1;

    int rc = xc_domain_create(xch, &domid, &create);
    if ( rc )
    {
        /* Try cleaning up. */
        rc = xc_domain_destroy(xch, domid);
        if ( rc )
            err(1, "xc_domain_destroy");

        rc = xc_domain_create(xch, &domid, &create);
        if ( rc )
            err(1, "xc_domain_create");
    }
    rc = xc_domain_max_vcpus(xch, domid, 1);
    if ( rc )
        err(1, "xc_domain_max_vcpus");

    printf("Created d%u\n", domid);

    /*
     * Set up RAM for 64k
     */
    xen_pfn_t ram[16];

    unsigned long lz_base = 1u << 31;

    if ( argc > 2 )
    {
        errno = 0;
        unsigned long val = strtoul(argv[2], NULL, 0);
        if ( errno || val != (unsigned int)val || val & 0xffff )
            printf("Ignoring bad load_addr '%s'\n", argv[2]);
        else
            lz_base = val;
    }

    printf("Secure Loader base address 0x%08lx\n", lz_base);

    for ( int i = 0; i < ARRAY_SIZE(ram); ++i )
        ram[i] = (lz_base >> 12) + i;

    rc = xc_domain_setmaxmem(xch, domid, -1);
    if ( rc )
        err(1, "xc_domain_setmaxmem");

    rc = xc_domain_populate_physmap_exact(xch, domid, ARRAY_SIZE(ram),
                                          0, 0, ram);
    if ( rc )
        err(1, "populate physmap exact");

    void *ptr = xc_map_foreign_pages(xch, domid, PROT_READ | PROT_WRITE,
                                     ram, ARRAY_SIZE(ram));
    if ( ptr == NULL )
        err(1, "xc_map_foreign_pages");

    /*
     * Copy LZ_HEADER into place.
     */
    int fd = open(argv[1], O_RDONLY);
    if ( fd < 0 )
        err(1, "open");

    struct stat st;
    if ( fstat(fd, &st) < 0 )
        err(1, "fstat");

    if ( st.st_size >= 0x10000 )
        err(1, "Bad size");

    void *hdr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if ( hdr == MAP_FAILED )
        err(1, "mmap");

    memcpy(ptr, hdr, st.st_size);

    /*
     * Set up initial register state.
     */
    rc = xc_domain_hvm_getcontext(xch, domid, NULL, 0);
    if ( rc <= 0 )
        err(1, "xc_domain_hvm_getcontext(,, NULL)");

    struct {
        struct hvm_save_descriptor header_d;
        HVM_SAVE_TYPE(HEADER) header;
        struct hvm_save_descriptor cpu_d;
        HVM_SAVE_TYPE(CPU) cpu;
        struct hvm_save_descriptor end_d;
        HVM_SAVE_TYPE(END) end;
    } bsp_ctx = {};
    void *full_ctx = calloc(1, rc);
    if ( full_ctx == NULL )
        err(1, "calloc");

    rc = xc_domain_hvm_getcontext(xch, domid, full_ctx, rc);
    if ( rc <= 0 )
        err(1, "xc_domain_hvm_getcontext(,, full_ctx)");

    memcpy(&bsp_ctx, full_ctx,
           sizeof(struct hvm_save_descriptor) + HVM_SAVE_LENGTH(HEADER));

    /* Set the CPU descriptor. */
    bsp_ctx.cpu_d.typecode = HVM_SAVE_CODE(CPU);
    bsp_ctx.cpu_d.instance = 0;
    bsp_ctx.cpu_d.length = HVM_SAVE_LENGTH(CPU);

    /* Set the cached part of the relevant segment registers. */
    bsp_ctx.cpu.cs_base = 0;
    bsp_ctx.cpu.ds_base = 0;
    bsp_ctx.cpu.ss_base = 0;
    bsp_ctx.cpu.tr_base = 0;
    bsp_ctx.cpu.cs_limit = ~0u;
    bsp_ctx.cpu.ds_limit = 0xffffu;
    bsp_ctx.cpu.ss_limit = ~0u;
    bsp_ctx.cpu.tr_limit = 0x67;
    bsp_ctx.cpu.cs_arbytes = 0xc9b;
    bsp_ctx.cpu.ds_arbytes = 0xf3;
    bsp_ctx.cpu.ss_arbytes = 0xc93;
    bsp_ctx.cpu.tr_arbytes = 0x8b;

    /* Set the control registers. */
    bsp_ctx.cpu.cr0 = X86_CR0_PE | X86_CR0_ET;

    /* Set the GPRs. */
    bsp_ctx.cpu.rax = lz_base;
    bsp_ctx.cpu.rip = lz_base + *(uint16_t *)hdr;

    bsp_ctx.cpu.dr6 = X86_DR6_DEFAULT;
    bsp_ctx.cpu.dr7 = X86_DR7_DEFAULT;

    /* Set the end descriptor. */
    bsp_ctx.end_d.typecode = HVM_SAVE_CODE(END);
    bsp_ctx.end_d.instance = 0;
    bsp_ctx.end_d.length = HVM_SAVE_LENGTH(END);

    rc = xc_domain_hvm_setcontext(xch, domid,
                                  (uint8_t *)&bsp_ctx, sizeof(bsp_ctx));
    if ( rc != 0 )
        err(1, "xc_domain_hvm_setcontext");

    printf("Ready\n");

    xc_domain_unpause(xch, domid);

    munmap(hdr, st.st_size);
    close(fd);
    munmap(ptr, ARRAY_SIZE(ram) * 4096);
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
