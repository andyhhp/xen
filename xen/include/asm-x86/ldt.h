
#ifndef __ARCH_LDT_H
#define __ARCH_LDT_H

#ifndef __ASSEMBLY__

DECLARE_PER_CPU(unsigned int, ldt_ents);

static inline void load_LDT(struct vcpu *v)
{
    unsigned int ents = is_pv_vcpu(v) && v->arch.pv_vcpu.ldt_ents;
    unsigned int *this_ldt_ents = &this_cpu(ldt_ents);

    if ( likely(ents == *this_ldt_ents) )
        return;

    if ( ents == 0 )
        lldt(0);
    else
    {
        _set_tssldt_desc(&pv_gdt[LDT_ENTRY], PERCPU_LDT_MAPPING,
                         ents * 8 - 1, SYS_DESC_ldt);
        lldt(LDT_ENTRY << 3);
    }

    *this_ldt_ents = ents;
}

#endif /* !__ASSEMBLY__ */

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
