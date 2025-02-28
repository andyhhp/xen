/*
 *  AMD CPU Microcode Update Driver for Linux
 *  Copyright (C) 2008 Advanced Micro Devices Inc.
 *
 *  Author: Peter Oruba <peter.oruba@amd.com>
 *
 *  Based on work by:
 *  Tigran Aivazian <tigran@aivazian.fsnet.co.uk>
 *
 *  This driver allows to upgrade microcode on AMD
 *  family 0x10 and later.
 *
 *  Licensed unter the terms of the GNU General Public
 *  License version 2. See file COPYING for details.
 */

#include <xen/bsearch.h>
#include <xen/console.h>
#include <xen/err.h>
#include <xen/init.h>
#include <xen/mm.h> /* TODO: Fix asm/tlbflush.h breakage */
#include <xen/sha2.h>

#include <asm/apic.h>
#include <asm/msr.h>
#include <asm/trampoline.h>

#include "private.h"

#define pr_debug(x...) ((void)0)

struct equiv_cpu_entry {
    uint32_t installed_cpu;
    uint32_t fixed_errata_mask;
    uint32_t fixed_errata_compare;
    uint16_t equiv_cpu;
    uint16_t reserved;
};

struct microcode_patch {
    uint16_t year;
    uint8_t  day;
    uint8_t  month;
    uint32_t patch_id;
    uint8_t  mc_patch_data_id[2];
    uint8_t  mc_patch_data_len;
    uint8_t  init_flag;
    union {
        uint32_t checksum; /* Fam12h and earlier */
        uint32_t min_rev;  /* Zen3-5, post Entrysign */
    };
    uint32_t nb_dev_id;
    uint32_t sb_dev_id;
    uint16_t processor_rev_id;
    uint8_t  nb_rev_id;
    uint8_t  sb_rev_id;
    uint8_t  bios_api_rev;
    uint8_t  reserved1[3];
};

#define UCODE_MAGIC                0x00414d44
#define UCODE_EQUIV_TYPE           0x00000000
#define UCODE_UCODE_TYPE           0x00000001

struct container_equiv_table {
    uint32_t type; /* UCODE_EQUIV_TYPE */
    uint32_t len;
    struct equiv_cpu_entry eq[];
};
struct container_microcode {
    uint32_t type; /* UCODE_UCODE_TYPE */
    uint32_t len;
    struct microcode_patch patch[];
};

/*
 * Microcode updates for different CPUs are distinguished by their
 * processor_rev_id in the header.  This denotes the format of the internals
 * of the microcode engine, and is fixed for an individual CPU.
 *
 * There is a mapping from the CPU signature (CPUID.1.EAX -
 * family/model/stepping) to the "equivalent CPU identifier" which is
 * similarly fixed.  In some cases, multiple different CPU signatures map to
 * the same equiv_id for processor lines which share identical microcode
 * facilities.
 *
 * This mapping can't be calculated in the general case, but is provided in
 * the microcode container, so the correct piece of microcode for the CPU can
 * be identified.  We cache it the first time we encounter the correct mapping
 * for this system.
 *
 * Note: for now, we assume a fully homogeneous setup, meaning that there is
 * exactly one equiv_id we need to worry about for microcode blob
 * identification.  This may need revisiting in due course.
 */
static struct {
    uint32_t sig;
    uint16_t id;
} equiv __read_mostly;

static const struct patch_digest {
    uint32_t patch_id;
    uint8_t digest[SHA2_256_DIGEST_SIZE];
} patch_digests[] = {
#include "amd-patch-digests.c"
};
static bool __ro_after_init entrysign_mitigiated_in_firmware;

static int cf_check cmp_patch_id(const void *key, const void *elem)
{
    const struct patch_digest *pd = elem;
    uint32_t patch_id = *(uint32_t *)key;

    if ( patch_id == pd->patch_id )
        return 0;
    else if ( patch_id < pd->patch_id )
        return -1;
    return 1;
}

static bool check_digest(const struct container_microcode *mc)
{
    const struct microcode_patch *patch = mc->patch;
    const struct patch_digest *pd;
    uint8_t digest[SHA2_256_DIGEST_SIZE];

    /*
     * Zen1 thru Zen5 CPUs are known to use a weak signature algorithm on
     * microcode updates.  If this has not been mitigated in firmware, check
     * the digest of the patch against a list of known provenance.
     */
    if ( boot_cpu_data.family < 0x17 || boot_cpu_data.family > 0x1a ||
         entrysign_mitigiated_in_firmware || !opt_digest_check )
        return true;

    pd = bsearch(&patch->patch_id, patch_digests, ARRAY_SIZE(patch_digests),
                 sizeof(struct patch_digest), cmp_patch_id);
    if ( !pd )
    {
        printk(XENLOG_WARNING "No digest found for patch_id %08x\n",
               patch->patch_id);
        return false;
    }

    sha2_256(digest, patch, mc->len);

    if ( memcmp(digest, pd->digest, sizeof(digest)) )
    {
        printk(XENLOG_WARNING "Patch %08x SHA256 mismatch:\n"
               "  expected %" STR(SHA2_256_DIGEST_SIZE) "phN\n"
               "       got %" STR(SHA2_256_DIGEST_SIZE) "phN\n",
               patch->patch_id, pd->digest, digest);
        return false;
    }

    return true;
}

static void cf_check collect_cpu_info(void)
{
    struct cpu_signature *csig = &this_cpu(cpu_sig);

    memset(csig, 0, sizeof(*csig));

    csig->sig = cpuid_eax(1);
    rdmsrl(MSR_AMD_PATCHLEVEL, csig->rev);

    pr_debug("microcode: CPU%d collect_cpu_info: patch_id=%#x\n",
             smp_processor_id(), csig->rev);
}

static bool verify_patch_size(uint32_t patch_size)
{
    uint32_t max_size;

#define F1XH_MPB_MAX_SIZE 2048
#define F14H_MPB_MAX_SIZE 1824
#define F15H_MPB_MAX_SIZE 4096
#define F16H_MPB_MAX_SIZE 3458
#define F17H_MPB_MAX_SIZE 3200
#define F19H_MPB_MAX_SIZE 5568
#define F1AH_MPB_MAX_SIZE 15296

    switch ( boot_cpu_data.family )
    {
    case 0x14:
        max_size = F14H_MPB_MAX_SIZE;
        break;
    case 0x15:
        max_size = F15H_MPB_MAX_SIZE;
        break;
    case 0x16:
        max_size = F16H_MPB_MAX_SIZE;
        break;
    case 0x17:
        max_size = F17H_MPB_MAX_SIZE;
        break;
    case 0x19:
        max_size = F19H_MPB_MAX_SIZE;
        break;
    case 0x1a:
        max_size = F1AH_MPB_MAX_SIZE;
        break;
    default:
        max_size = F1XH_MPB_MAX_SIZE;
        break;
    }

    return patch_size <= max_size;
}

static bool check_final_patch_levels(const struct cpu_signature *sig)
{
    /*
     * The 'final_levels' of patch ids have been obtained empirically.
     * Refer bug https://bugzilla.suse.com/show_bug.cgi?id=913996
     * for details of the issue. The short version is that people
     * using certain Fam10h systems noticed system hang issues when
     * trying to update microcode levels beyond the patch IDs below.
     * From internal discussions, we gathered that OS/hypervisor
     * cannot reliably perform microcode updates beyond these levels
     * due to hardware issues. Therefore, we need to abort microcode
     * update process if we hit any of these levels.
     */
    static const unsigned int final_levels[] = {
        0x01000098,
        0x0100009f,
        0x010000af,
    };
    unsigned int i;

    if ( boot_cpu_data.family != 0x10 )
        return false;

    for ( i = 0; i < ARRAY_SIZE(final_levels); i++ )
        if ( sig->rev == final_levels[i] )
            return true;

    return false;
}

static int compare_revisions(uint32_t old_rev, uint32_t new_rev)
{
    if ( new_rev > old_rev )
        return NEW_UCODE;

    if ( new_rev == old_rev )
        return SAME_UCODE;

    return OLD_UCODE;
}

/*
 * Check whether this microcode patch is applicable for the current CPU.
 *
 * AMD microcode blobs only have the "equivalent CPU identifier" which is a 16
 * bit contraction of the 32 bit Family/Model/Stepping.
 *
 * We expect to only be run after scan_equiv_cpu_table() has found a valid
 * mapping for the current CPU.  If this is violated, the 0 in equiv.id will
 * cause the patch to be rejected too.
 */
static bool microcode_fits_cpu(const struct microcode_patch *patch)
{
    ASSERT(equiv.sig);

    return equiv.id == patch->processor_rev_id;
}

static int cf_check amd_compare(
    const struct microcode_patch *old, const struct microcode_patch *new)
{
    /* Both patches to compare are supposed to be applicable to local CPU. */
    ASSERT(microcode_fits_cpu(new));
    ASSERT(microcode_fits_cpu(old));

    return compare_revisions(old->patch_id, new->patch_id);
}

/*
 * Check whether this patch has a minimum revision given, and whether the
 * condition is satisfied.
 *
 * In linux-firmware for CPUs suffering from the Entrysign vulnerability,
 * ucodes signed with the updated signature algorithm have reused the checksum
 * field as a min-revision field.  From public archives, the checksum field
 * appears to have been unused since Fam12h.
 *
 * Returns false if there is a min revision given, and it suggests that that
 * the patch cannot be loaded on the current system.  True otherwise.
 */
static bool check_min_rev(const struct microcode_patch *patch)
{
    ASSERT(microcode_fits_cpu(patch));

    if ( patch->processor_rev_id < 0xa000 || /* pre Zen3? */
         patch->min_rev == 0 )               /* No min rev specified */
        return true;

    /*
     * Sanity check, as this is a reused field.  If this is a true
     * min_revision field, it will differ only in the bottom byte from the
     * patch_id.  Otherwise, it's probably a checksum.
     */
    if ( (patch->patch_id ^ patch->min_rev) & ~0xff )
    {
        printk(XENLOG_WARNING
               "microcode: patch %#x has unexpected min_rev %#x\n",
               patch->patch_id, patch->min_rev);
        return true;
    }

    return this_cpu(cpu_sig).rev >= patch->min_rev;
}

static int cf_check apply_microcode(const struct microcode_patch *patch,
                                    unsigned int flags)
{
    int hw_err, result;
    unsigned int cpu = smp_processor_id();
    struct cpu_signature *sig = &per_cpu(cpu_sig, cpu);
    uint32_t rev, old_rev = sig->rev;
    bool ucode_force = flags & XENPF_UCODE_FORCE;

    if ( !microcode_fits_cpu(patch) )
        return -EINVAL;

    result = compare_revisions(old_rev, patch->patch_id);

    /*
     * Allow application of the same revision to pick up SMT-specific changes
     * even if the revision of the other SMT thread is already up-to-date.
     */
    if ( !ucode_force && (result == SAME_UCODE || result == OLD_UCODE) )
        return -EEXIST;

    if ( check_final_patch_levels(sig) )
    {
        printk(XENLOG_ERR
               "microcode: CPU%u current rev %#x unsafe to update\n",
               cpu, sig->rev);
        return -ENXIO;
    }

    if ( !ucode_force && !check_min_rev(patch) )
    {
        printk(XENLOG_ERR
               "microcode: CPU%u current rev %#x below patch min_rev %#x\n",
               cpu, sig->rev, patch->min_rev);
        return -ENXIO;
    }

    hw_err = wrmsr_safe(MSR_AMD_PATCHLOADER, (unsigned long)patch);

    /* get patch id after patching */
    rdmsrl(MSR_AMD_PATCHLEVEL, rev);
    sig->rev = rev;

    /*
     * Fam17h processors leave the mapping of the ucode as UC after the
     * update.  Flush the mapping to regain normal cacheability.
     *
     * We do not know the granularity of mapping, and at 3200 bytes in size
     * there is a good chance of crossing a 4k page boundary.  Shoot-down the
     * start and end just to be safe.
     */
    if ( boot_cpu_data.family == 0x17 )
    {
        invlpg(patch);
        invlpg((const void *)patch + F17H_MPB_MAX_SIZE - 1);
    }

    /* check current patch id and patch's id for match */
    if ( hw_err || (rev != patch->patch_id) )
    {
        printk(XENLOG_ERR
               "microcode: CPU%u update rev %#x to %#x failed, result %#x\n",
               cpu, old_rev, patch->patch_id, rev);
        return -EIO;
    }

    printk(XENLOG_WARNING
           "microcode: CPU%u updated from revision %#x to %#x, date = %04x-%02x-%02x\n",
           cpu, old_rev, rev, patch->year, patch->month, patch->day);

    return 0;
}

static int scan_equiv_cpu_table(const struct container_equiv_table *et)
{
    const struct cpu_signature *sig = &this_cpu(cpu_sig);
    unsigned int i, nr = et->len / sizeof(et->eq[0]);

    /* Search the equiv_cpu_table for the current CPU. */
    for ( i = 0; i < nr && et->eq[i].installed_cpu; ++i )
    {
        if ( et->eq[i].installed_cpu != sig->sig )
            continue;

        if ( !equiv.sig ) /* Cache details on first find. */
        {
            equiv.sig = sig->sig;
            equiv.id  = et->eq[i].equiv_cpu;
            return 0;
        }

        if ( equiv.sig != sig->sig || equiv.id != et->eq[i].equiv_cpu )
        {
            /*
             * This can only occur if two equiv tables have been seen with
             * different mappings for the same CPU.  The mapping is fixed, so
             * one of the tables is wrong.  As we can't calculate the mapping,
             * we trusted the first table we saw.
             */
            printk(XENLOG_ERR
                   "microcode: Equiv mismatch: cpu %08x, got %04x, cached %04x\n",
                   sig->sig, et->eq[i].equiv_cpu, equiv.id);
            return -EINVAL;
        }

        return 0;
    }

    /* equiv_cpu_table was fine, but nothing found for the current CPU. */
    return -ESRCH;
}

static struct microcode_patch *cf_check cpu_request_microcode(
    const void *buf, size_t size, bool make_copy)
{
    const struct microcode_patch *saved = NULL;
    struct microcode_patch *patch = NULL;
    size_t saved_size = 0;
    int error = 0;

    while ( size )
    {
        const struct container_equiv_table *et;
        bool skip_ucode;

        if ( size < 4 || *(const uint32_t *)buf != UCODE_MAGIC )
        {
            printk(XENLOG_ERR "microcode: Wrong microcode patch file magic\n");
            error = -EINVAL;
            break;
        }

        /* Move over UCODE_MAGIC. */
        buf  += 4;
        size -= 4;

        if ( size < sizeof(*et) ||                   /* No space for header? */
             (et = buf)->type != UCODE_EQUIV_TYPE || /* Not an Equivalence Table? */
             size - sizeof(*et) < et->len ||         /* No space for table? */
             et->len % sizeof(et->eq[0]) )           /* Not multiple of equiv_cpu_entry? */
        {
            printk(XENLOG_ERR "microcode: Bad equivalent cpu table\n");
            error = -EINVAL;
            break;
        }

        /* Move over the Equiv table. */
        buf  += sizeof(*et) + et->len;
        size -= sizeof(*et) + et->len;

        error = scan_equiv_cpu_table(et);

        /*
         * -ESRCH means no applicable microcode in this container.  But, there
         * might be subsequent containers in the blob.  Skipping to the end of
         * this container still requires us to follow the UCODE_UCODE_TYPE/len
         * metadata because there's no overall container length given.
         */
        if ( error && error != -ESRCH )
            break;
        skip_ucode = error;
        error = 0;

        while ( size )
        {
            const struct container_microcode *mc;

            if ( size < sizeof(*mc) ||                      /* No space for container header? */
                 (mc = buf)->type != UCODE_UCODE_TYPE ||    /* Not a ucode blob? */
                 size - sizeof(*mc) < mc->len ||            /* No space for blob? */
                 mc->len < sizeof(struct microcode_patch) ) /* No space for patch header? */
            {
                printk(XENLOG_ERR "microcode: Bad microcode data\n");
                error = -EINVAL;
                break;
            }

            if ( skip_ucode )
                goto skip;

            if ( !verify_patch_size(mc->len) )
            {
                printk(XENLOG_WARNING
                       "microcode: Bad microcode length 0x%08x for cpu 0x%04x\n",
                       mc->len, mc->patch->processor_rev_id);
                /*
                 * If the blob size sanity check fails, trust the container
                 * length which has already been checked to be at least
                 * plausible at this point.
                 */
                goto skip;
            }

            /*
             * If the new ucode covers current CPU, compare ucodes and store the
             * one with higher revision.
             */
            if ( microcode_fits_cpu(mc->patch) &&
                 (!saved ||
                  compare_revisions(saved->patch_id,
                                    mc->patch->patch_id) == NEW_UCODE) &&
                 check_digest(mc) )
            {
                saved = mc->patch;
                saved_size = mc->len;
            }

            /* Move over the microcode blob. */
        skip:
            buf  += sizeof(*mc) + mc->len;
            size -= sizeof(*mc) + mc->len;

            /*
             * Peek ahead.  If we see the start of another container, we've
             * exhaused all microcode blobs in this container.  Exit cleanly.
             */
            if ( size >= 4 && *(const uint32_t *)buf == UCODE_MAGIC )
                break;
        }

        /*
         * Any error means we didn't get cleanly to the end of the microcode
         * container.  There isn't an overall length field, so we've got no
         * way of skipping to the next container in the stream.
         */
        if ( error )
            break;
    }

    if ( saved )
    {
        if ( make_copy )
        {
            patch = xmemdup_bytes(saved, saved_size);
            if ( !patch )
                error = -ENOMEM;
        }
        else
            patch = (struct microcode_patch *)saved;
    }

    if ( error && !patch )
        patch = ERR_PTR(error);

    return patch;
}

static const char __initconst amd_cpio_path[] =
    "kernel/x86/microcode/AuthenticAMD.bin";

static const struct microcode_ops __initconst_cf_clobber amd_ucode_ops = {
    .cpu_request_microcode            = cpu_request_microcode,
    .collect_cpu_info                 = collect_cpu_info,
    .apply_microcode                  = apply_microcode,
    .compare                          = amd_compare,
    .cpio_path                        = amd_cpio_path,
};

void __init ucode_probe_amd(struct microcode_ops *ops)
{
    /*
     * The Entrysign vulnerability (SB-7033, CVE-2024-36347) affects Zen1-5
     * CPUs.  Taint Xen if digest checking is turned off.
     */
    if ( boot_cpu_data.family >= 0x17 && boot_cpu_data.family <= 0x1a &&
         !opt_digest_check )
    {
        printk(XENLOG_WARNING
               "Microcode patch additional digest checks disabled\n");
        add_taint(TAINT_CPU_OUT_OF_SPEC);
    }

    if ( boot_cpu_data.family < 0x10 )
        return;

    *ops = amd_ucode_ops;
}

#if 0 /* Manual CONFIG_SELF_TESTS */
static void __init __constructor test_digests_sorted(void)
{
    for ( unsigned int i = 1; i < ARRAY_SIZE(patch_digests); ++i )
    {
        if ( patch_digests[i - 1].patch_id < patch_digests[i].patch_id )
            continue;

        panic("patch_digests[] not sorted: %08x >= %08x\n",
              patch_digests[i - 1].patch_id,
              patch_digests[i].patch_id);
    }
}
#endif /* CONFIG_SELF_TESTS */

/*
 * Probe for the mode of the LAPIC.  If the LAPIC is disabled, or the MMIO
 * window is in a non-standard place, fix it up.  Set up the fixmap entry.
 * Returns true for x2apic mode, false for xapic.
 */
static bool __init probe_lapic(void)
{
    uint64_t val;

    rdmsrl(MSR_APIC_BASE, val);

    if ( val & APIC_BASE_EXTD )
        return true;

    if ( !(val & APIC_BASE_ENABLE) ||
         (val & APIC_BASE_ADDR_MASK) != APIC_DEFAULT_PHYS_BASE )
    {
        printk(XENLOG_WARNING
               "  Unexpected LAPIC configuration 0x%08lx, fixing\n", val);
        wrmsrl(MSR_APIC_BASE,
               APIC_DEFAULT_PHYS_BASE | APIC_BASE_ENABLE | APIC_BASE_BSP);
    }

    set_fixmap_nocache(FIX_APIC_BASE, APIC_DEFAULT_PHYS_BASE);

    return false;
}

/*
 * Local simplification apic_icr_write().  Because we always use destination
 * shorthands, we do not need to write to APIC_ICR2 in xAPIC mode.
 */
static void __init icr_write(bool x2apic, uint32_t val)
{
    if ( x2apic )
        return apic_wrmsr(APIC_ICR, val);

    while ( apic_mem_read(APIC_ICR) & APIC_ICR_BUSY )
        cpu_relax();
    apic_mem_write(APIC_ICR, val);
}

/*
 * Send an ALL_BUT_SELF INIT or INIT-SIPI sequence.  As we're dealing with
 * modern platforms, we don't need INIT assert/deassrt cycles, or the second
 * SIPI.
 */
static void __init send_init(bool x2apic, bool sipi)
{
    unsigned long sipi_vec;

    icr_write(x2apic, APIC_DEST_ALLBUT | APIC_DM_INIT);

    if ( !sipi )
        return;

    sipi_vec = bootsym_phys(entry_SIPI16) >> 12;

    icr_write(x2apic, APIC_DEST_ALLBUT | APIC_DM_STARTUP | sipi_vec);
}

/*
 * We're far too early to calibrate time.  Assume a 5GHz processor (the upper
 * end of the Fam19h range), which causes us to be wrong in the safe direction
 * on slower systems.
 */
static void __init wait(unsigned int usecs)
{
    unsigned long ticks = usecs * (5UL*1000*1000 /* cpu_khz */ / 1000);
    unsigned long s, e;

    s = rdtsc_ordered();
    do
    {
        cpu_relax();
        e = rdtsc_ordered();
    } while ( (e - s) < ticks );
}

/*
 * Control variables between the BSP running logic in this file, and the APs
 * running amd_parallel_ucode_loader().
 *
 * APs do a LOCK INC on callin_*, then spin on ptr/wait.  The BSP waits for
 * the callin_* count to match the number of APs, then sets ptr/wait.  The BSP
 * is also responsible for resetting this state at relevant positions of the
 * cycle.
 */
volatile unsigned int trampoline_ucode_callin_ready;
volatile unsigned int trampoline_ucode_callin_done;
volatile unsigned long trampoline_ucode_ptr;
volatile bool trampoline_ucode_wait;

/*
 * Wait for the APs to be ready.  Returns the number of APs.  Will return 0 on
 * timeout, including if the platform is down-cored to just the BSP.
 */
static unsigned int __init wait_for_aps(void)
{
    volatile uint8_t *started = &bootsym(trampoline_cpu_started);
    unsigned int i, old_nr, nr;

    /*
     * Wait up to 100us to see the AP sign-of-life.  This is issued
     * immediately after the AP starts executing code, while still in 16bit
     * mode.
     *
     * If the platform is down-cored to just the BSP, we'll time out here.
     */
    for ( i = 0; *started == 0; ++i )
    {
        if ( i == 100 )
        {
            printk(XENLOG_WARNING
                   "  Timeout waiting for APs to start, or in single core configuration\n");
            return 0;
        }
        wait(1 /* us */);
    }
    pr_debug(XENLOG_DEBUG "  AP(s) started after %uus\n", i);

    /*
     * We don't know how many APs there are supposed to be, but we've seen
     * signs of life and they're all running in parallel.  Wait for the count
     * in trampoline_ucode_callin_ready to stabilise (i.e. not changed in
     * 10us).
     */
    old_nr = 0;
    do {
        for ( i = 0; (nr = trampoline_ucode_callin_ready) == old_nr; ++i )
        {
            if ( i == 10 )
                goto done;
            wait(1 /* us */);
        }
        old_nr = nr;
    } while ( true );

 done:
    pr_debug(XENLOG_DEBUG "  AP count stabilised at %u\n", nr);

    /* Reset AP signs-of-life */
    *started = 0;

    return nr;
}

static bool __init orchestrate_load(unsigned int nr_aps, const struct microcode_patch *blob)
{
    unsigned long addr = (unsigned long)blob;
    unsigned int rev;
    bool err;

    err = wrmsr_safe(MSR_AMD_PATCHLOADER, addr);
    if ( err )
    {
        printk(XENLOG_ERR "  Failed to load %#x, aborting\n", blob->patch_id);
        return false;
    }

    rdmsrl(MSR_AMD_PATCHLEVEL, rev);
    this_cpu(cpu_sig).rev = rev;

    if ( rev != blob->patch_id )
    {
        printk(XENLOG_ERR "  Patch %#x not accepted; CPU rev %#x, aborting\n",
               blob->patch_id, rev);
        return false;
    }

    if ( nr_aps == 0 ) /* If there are no APs, we're done. */
        return true;

    /* Wait for callin_ready.  APs will then spin on ptr == 0. */
    while ( trampoline_ucode_callin_ready < nr_aps )
        cpu_relax();
    printk(XENLOG_INFO "  Loading patch %#x\n", blob->patch_id);

    /* Reset state */
    trampoline_ucode_callin_ready = 0;
    trampoline_ucode_wait = true;

    /* Kick APs to start loading. */
    trampoline_ucode_ptr = addr;

    /* Wait for callin_done.  APs will then spin on wait == true. */
    while ( trampoline_ucode_callin_done < nr_aps )
        cpu_relax();

    /* Reset state */
    trampoline_ucode_callin_done = 0;
    trampoline_ucode_ptr = 0;

    /* Kick APs to restart the waiting loop. */
    trampoline_ucode_wait = false;

    return true;
}

extern unsigned long trampoline_ap_fn;
void nocall amd_parallel_ucode_loader(void);
void nocall __high_start(void);

static void __init parallel_load(const struct microcode_patch *p1,
                                 const struct microcode_patch *p2)
{
    unsigned long *tramp_fn;
    unsigned int nr_aps;
    bool x2apic;

    printk(XENLOG_INFO "microcode: Attempting parallel load of Entrysign fixes\n");

    tramp_fn = &bootsym(trampoline_ap_fn);
    if ( *tramp_fn != (unsigned long)__high_start )
    {
        printk(XENLOG_ERR "  Unexpected trampoline function %ps, aborting\n",
               _p(*tramp_fn));
        return;
    }

    console_start_sync();

    x2apic = probe_lapic();

    *tramp_fn = (unsigned long)amd_parallel_ucode_loader;

    send_init(x2apic, true);

    nr_aps = wait_for_aps();
    printk(XENLOG_INFO "  Found %u APs\n", nr_aps);

    if ( p1 && p1->patch_id > this_cpu(cpu_sig).rev &&
         !orchestrate_load(nr_aps, p1) )
        goto out;

    if ( p2 && p2->patch_id > this_cpu(cpu_sig).rev &&
         !orchestrate_load(nr_aps, p2) )
        goto out;

    /*
     * Bending the truth at little, but the signature fix is in place, so Xen
     * can drop the digest check and accept newer blobs.
     */
    entrysign_mitigiated_in_firmware = true;

    printk(XENLOG_INFO "  Parallel load complete\n");

 out:
    send_init(x2apic, false);

    console_end_sync();

    *tramp_fn = (unsigned long)__high_start;
}

extern const struct microcode_patch
    patch_0a0011d8[], patch_0a0011d9[], /* GN-B1, Milan */
    patch_0a001241[], patch_0a001242[], /* GN-B2, MilanX */
    patch_0a101152[], patch_0a101153[], /* RS-B1, Genoa */
    patch_0a10124d[], patch_0a10124e[], /* RS-B2, GenoaX */
    patch_0aa00217[], patch_0aa00218[], /* RSDN-A2, Bergamo */
    patch_0b002140[], /* BRH-C1,  Turin */
    patch_0b101040[]; /* BRHD-B0, Turin Dense */

/*
 * The Entrysign vulnerability affects all Zen1 thru Zen5 CPUs.  Firmware
 * fixes were produced from Nov 2024.  Zen3 thru Zen5 can continue to take
 * OS-loadable microcode updates using a new signature scheme, as long as
 * firmware has been updated first.
 */
void __init amd_check_entrysign(void)
{
    const struct microcode_patch *p1 = NULL, *p2 = NULL;
    unsigned int curr_rev;
    uint8_t fixed_rev;

    if ( boot_cpu_data.vendor != X86_VENDOR_AMD ||
         boot_cpu_data.family < 0x17 ||
         boot_cpu_data.family > 0x1a )
        return;

    /*
     * Table taken from Linux, which is the only known source of information
     * about client revisions.  Note, Linux expresses "last-vulnerable-rev"
     * while Xen wants "first-fixed-rev".
     */
    curr_rev = this_cpu(cpu_sig).rev;
    switch ( curr_rev >> 8 )
    {
    case 0x080012: fixed_rev = 0x78; break;
    case 0x080082: fixed_rev = 0x10; break;
    case 0x083010: fixed_rev = 0x7d; break;
    case 0x086001: fixed_rev = 0x0f; break;
    case 0x086081: fixed_rev = 0x09; break;
    case 0x087010: fixed_rev = 0x35; break;
    case 0x08a000: fixed_rev = 0x0b; break;
    case 0x0a0010: fixed_rev = 0x7b; break;
    case 0x0a0011: fixed_rev = 0xdb; break;
    case 0x0a0012: fixed_rev = 0x44; break;
    case 0x0a0082: fixed_rev = 0x0f; break;
    case 0x0a1011: fixed_rev = 0x54; break;
    case 0x0a1012: fixed_rev = 0x4f; break;
    case 0x0a1081: fixed_rev = 0x0a; break;
    case 0x0a2010: fixed_rev = 0x30; break;
    case 0x0a2012: fixed_rev = 0x13; break;
    case 0x0a4041: fixed_rev = 0x0a; break;
    case 0x0a5000: fixed_rev = 0x14; break;
    case 0x0a6012: fixed_rev = 0x0b; break;
    case 0x0a7041: fixed_rev = 0x0a; break;
    case 0x0a7052: fixed_rev = 0x09; break;
    case 0x0a7080: fixed_rev = 0x0a; break;
    case 0x0a70c0: fixed_rev = 0x0a; break;
    case 0x0aa001: fixed_rev = 0x17; break;
    case 0x0aa002: fixed_rev = 0x19; break;
    case 0x0b0021: fixed_rev = 0x47; break;
    case 0x0b0081: fixed_rev = 0x12; break;
    case 0x0b1010: fixed_rev = 0x47; break;
    case 0x0b2040: fixed_rev = 0x32; break;
    case 0x0b4040: fixed_rev = 0x32; break;
    case 0x0b4041: fixed_rev = 0x02; break;
    case 0x0b6000: fixed_rev = 0x32; break;
    case 0x0b6080: fixed_rev = 0x32; break;
    case 0x0b7000: fixed_rev = 0x32; break;
    default:
        printk(XENLOG_WARNING
               "Unrecognised CPU %02x-%02x-%02x ucode 0x%08x, assuming vulnerable to Entrysign\n",
               boot_cpu_data.family, boot_cpu_data.model,
               boot_cpu_data.stepping, curr_rev);
        return;
    }

    /*
     * This check is best-effort.  If the platform looks to be out of date, it
     * probably is.  If the platform looks to be fixed, it either genuinely
     * is, or malware has gotten in before Xen booted and all bets are off.
     */
    if ( (uint8_t)curr_rev >= fixed_rev )
    {
        entrysign_mitigiated_in_firmware = true;
        return;
    }

    printk(XENLOG_WARNING
           "WARNING: Platform vulnerable to Entrysign (SB-7033, CVE-2024-36347) - firmware update required\n");
    add_taint(TAINT_CPU_OUT_OF_SPEC);

    if ( !opt_es_boot_load )
        return;

    /*
     * If we have the OS-loadable Entrysign mitigation, try applying it.
     */
    switch ( curr_rev >> 8 )
    {
    case 0x0a0011: p1 = patch_0a0011d8; p2 = patch_0a0011d9; break;
    case 0x0a0012: p1 = patch_0a001241; p2 = patch_0a001242; break;
    case 0x0a1011: p1 = patch_0a101152; p2 = patch_0a101153; break;
    case 0x0a1012: p1 = patch_0a10124d; p2 = patch_0a10124e; break;
    case 0x0aa002: p1 = patch_0aa00217; p2 = patch_0aa00218; break;
    case 0x0b0021: p1 = patch_0b002140; break;
    case 0x0b1010: p1 = patch_0b101040; break;
    default:
        return;
    }

    parallel_load(p1, p2);
}
