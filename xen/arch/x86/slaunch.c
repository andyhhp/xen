#include <xen/types.h>
#include <asm/intel_txt.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/slaunch.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/multiboot.h>

bool __initdata slaunch_active;

static void __maybe_unused compile_time_checks(void)
{
    BUILD_BUG_ON(sizeof(slaunch_active) != 1);
}

int __init map_l2(unsigned long paddr, unsigned long size)
{
    unsigned long aligned_paddr = paddr & ~((1ULL << L2_PAGETABLE_SHIFT) - 1);
    unsigned long pages = ((paddr + size) - aligned_paddr);
    pages = ROUNDUP(pages, 1ULL << L2_PAGETABLE_SHIFT) >> PAGE_SHIFT;

    if ( (aligned_paddr + pages * PAGE_SIZE) <= PREBUILT_MAP_LIMIT )
        return 0;

    if ( aligned_paddr < PREBUILT_MAP_LIMIT )
    {
        pages -= (PREBUILT_MAP_LIMIT - aligned_paddr) >> PAGE_SHIFT;
        aligned_paddr = PREBUILT_MAP_LIMIT;
    }

    return map_pages_to_xen((unsigned long)__va(aligned_paddr),
                            maddr_to_mfn(aligned_paddr),
                            pages, PAGE_HYPERVISOR);
}

static struct slr_table *slr_get_table(void)
{
    uint32_t slrt_pa = txt_find_slrt();
    struct slr_table *slrt = __va(slrt_pa);

    map_l2(slrt_pa, PAGE_SIZE);

    if ( slrt->magic != SLR_TABLE_MAGIC )
        panic("SLRT has invalid magic value: %#08x!\n", slrt->magic);
    /* XXX: are newer revisions allowed? */
    if ( slrt->revision != SLR_TABLE_REVISION )
        panic("SLRT is of unsupported revision: %#04x!\n", slrt->revision);
    if ( slrt->architecture != SLR_INTEL_TXT )
        panic("SLRT is for unexpected architecture: %#04x!\n",
              slrt->architecture);
    if ( slrt->size > slrt->max_size )
        panic("SLRT is larger than its max size: %#08x > %#08x!\n",
              slrt->size, slrt->max_size);

    if ( slrt->size > PAGE_SIZE )
        map_l2(slrt_pa, slrt->size);

    return slrt;
}

void tpm_measure_slrt(void)
{
    struct slr_table *slrt = slr_get_table();

    if ( slrt->revision == 1 )
    {
        /* In revision one of the SLRT, only Intel info table is measured. */
        struct slr_entry_intel_info *intel_info =
            (void *)slr_next_entry_by_tag(slrt, NULL, SLR_ENTRY_INTEL_INFO);
        if ( intel_info == NULL )
            panic("SLRT is missing Intel-specific information!\n");

        tpm_hash_extend(DRTM_LOC, DRTM_DATA_PCR, (uint8_t *)intel_info,
                        sizeof(*intel_info), DLE_EVTYPE_SLAUNCH, NULL, 0);
    }
    else
    {
        /*
         * slr_get_table() checks that the revision is valid, so we must not
         * get here unless the code is wrong.
         */
        panic("Unhandled SLRT revision: %d!\n", slrt->revision);
    }
}

static struct slr_entry_policy *slr_get_policy(struct slr_table *slrt)
{
    struct slr_entry_policy *policy;

    policy = (struct slr_entry_policy *)
        slr_next_entry_by_tag(slrt, NULL, SLR_ENTRY_DRTM_POLICY);
    if (policy == NULL)
        panic("SLRT is missing DRTM policy!\n");

    /* XXX: are newer revisions allowed? */
    if ( policy->revision != SLR_POLICY_REVISION )
        panic("DRTM policy in SLRT is of unsupported revision: %#04x!\n",
              slrt->revision);

    return policy;
}

static void check_drtm_policy(struct slr_table *slrt,
                              struct slr_entry_policy *policy,
                              struct slr_policy_entry *policy_entry,
                              const multiboot_info_t *mbi)
{
    uint32_t i;
    module_t *mods;
    uint32_t num_mod_entries;

    if ( policy->nr_entries < 2 )
        panic("DRTM policy in SLRT contains less than 2 entries (%d)!\n",
              policy->nr_entries);

    /* MBI policy entry must be the first one, so that measuring order matches
     * policy order. */
    if ( policy_entry[0].entity_type != SLR_ET_MULTIBOOT2_INFO )
        panic("First entry of DRTM policy in SLRT is not MBI: %#04x!\n",
              policy_entry[0].entity_type);
    if ( policy_entry[0].pcr != DRTM_DATA_PCR )
        panic("MBI was measured to %d instead of %d PCR!\n", DRTM_DATA_PCR,
              policy_entry[0].pcr);

    /* SLRT policy entry must be the second one. */
    if ( policy_entry[1].entity_type != SLR_ET_SLRT )
        panic("Second entry of DRTM policy in SLRT is not SLRT: %#04x!\n",
              policy_entry[1].entity_type);
    if ( policy_entry[1].pcr != DRTM_DATA_PCR )
        panic("SLRT was measured to %d instead of %d PCR!\n", DRTM_DATA_PCR,
              policy_entry[1].pcr);
    if ( policy_entry[1].entity != (uint64_t)__pa(slrt) )
        panic("SLRT address (%#08lx) differes from its DRTM entry (%#08lx)\n",
              __pa(slrt), policy_entry[1].entity);

    mods = __va(mbi->mods_addr);
    for ( i = 0; i < mbi->mods_count; i++ )
    {
        uint16_t j;
        uint64_t start = mods[i].mod_start;
        uint64_t size = mods[i].mod_end - mods[i].mod_start;

        for ( j = 0; j < policy->nr_entries; j++ )
        {
            if ( policy_entry[j].entity_type != SLR_ET_MULTIBOOT2_MODULE )
                continue;

            if ( policy_entry[j].entity == start &&
                 policy_entry[j].size == size )
                break;
        }

        if ( j >= policy->nr_entries )
        {
            panic("Couldn't find Multiboot module \"%s\" (at %d) in DRTM of Secure Launch\n",
                  (const char *)__va(mods[i].string), i);
        }
    }

    num_mod_entries = 0;
    for ( i = 0; i < policy->nr_entries; i++ )
    {
        if ( policy_entry[i].entity_type == SLR_ET_MULTIBOOT2_MODULE )
            num_mod_entries++;
    }

    if ( mbi->mods_count != num_mod_entries )
    {
        panic("Unexpected number of Multiboot modules: %d instead of %d\n",
              (int)mbi->mods_count, (int)num_mod_entries);
    }
}

void tpm_process_drtm_policy(const multiboot_info_t *mbi)
{
    struct slr_table *slrt;
    struct slr_entry_policy *policy;
    struct slr_policy_entry *policy_entry;
    uint16_t i;

    slrt = slr_get_table();

    policy = slr_get_policy(slrt);
    policy_entry = (struct slr_policy_entry *)
        ((uint8_t *)policy + sizeof(*policy));

    check_drtm_policy(slrt, policy, policy_entry, mbi);
    /* MBI was measured in tpm_extend_mbi(). */
    policy_entry[0].flags |= SLR_POLICY_FLAG_MEASURED;
    /* SLRT was measured in tpm_measure_slrt(). */
    policy_entry[1].flags |= SLR_POLICY_FLAG_MEASURED;

    for ( i = 2; i < policy->nr_entries; i++ )
    {
        uint64_t start = policy_entry[i].entity;
        uint64_t size = policy_entry[i].size;

        /* No already measured entries are expected here. */
        if ( policy_entry[i].flags & SLR_POLICY_FLAG_MEASURED )
            panic("DRTM entry at %d was measured out of order!\n", i);

        switch ( policy_entry[i].entity_type )
        {
        case SLR_ET_MULTIBOOT2_INFO:
            panic("Duplicated MBI entry in DRTM of Secure Launch at %d\n", i);
        case SLR_ET_SLRT:
            panic("Duplicated SLRT entry in DRTM of Secure Launch at %d\n", i);

        case SLR_ET_UNSPECIFIED:
        case SLR_ET_BOOT_PARAMS:
        case SLR_ET_SETUP_DATA:
        case SLR_ET_CMDLINE:
        case SLR_ET_UEFI_MEMMAP:
        case SLR_ET_RAMDISK:
        case SLR_ET_MULTIBOOT2_MODULE:
        case SLR_ET_TXT_OS2MLE:
            /* Measure this entry below. */
            break;

        case SLR_ET_UNUSED:
            /* Skip this entry. */
            continue;
        }

        if ( policy_entry[i].flags & SLR_POLICY_IMPLICIT_SIZE )
            panic("Unexpected implicitly-sized DRTM entry of Secure Launch at %d\n",
                  i);

        map_l2(start, size);
        tpm_hash_extend(DRTM_LOC, policy_entry[i].pcr, __va(start), size,
                        DLE_EVTYPE_SLAUNCH, (uint8_t *)policy_entry[i].evt_info,
                        strnlen(policy_entry[i].evt_info,
                                TPM_EVENT_INFO_LENGTH));

        policy_entry[i].flags |= SLR_POLICY_FLAG_MEASURED;
    }
}
