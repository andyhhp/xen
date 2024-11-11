#ifndef __ASM_ARM_DOMAIN_PAGE_H__
#define __ASM_ARM_DOMAIN_PAGE_H__

#ifdef CONFIG_ARCH_MAP_DOMAIN_PAGE
bool init_domheap_mappings(unsigned int cpu);
#else
static inline bool init_domheap_mappings(unsigned int cpu)
{
    return true;
}
#endif

#endif /* __ASM_ARM_DOMAIN_PAGE_H__ */
