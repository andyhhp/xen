
#include <xen/stdint.h>

#pragma GCC visibility push(hidden)
extern const int32_t __trampoline_rel_start[], __trampoline_rel_stop[];
extern const int32_t __trampoline_seg_start[], __trampoline_seg_stop[];
#pragma GCC visibility pop

#if defined(__i386__)
void reloc_trampoline32(unsigned long phys)
#elif defined (__x86_64__)
void reloc_trampoline64(unsigned long phys)
#else
#error Unknow architecture
#endif
{
    const int32_t *trampoline_ptr;

    /* Apply relocations to trampoline. */
    for ( trampoline_ptr = __trampoline_rel_start;
          trampoline_ptr < __trampoline_rel_stop;
          ++trampoline_ptr )
        *(uint32_t *)(*trampoline_ptr + (long)trampoline_ptr) += phys;
    for ( trampoline_ptr = __trampoline_seg_start;
          trampoline_ptr < __trampoline_seg_stop;
          ++trampoline_ptr )
        *(uint16_t *)(*trampoline_ptr + (long)trampoline_ptr) = phys >> 4;
}
