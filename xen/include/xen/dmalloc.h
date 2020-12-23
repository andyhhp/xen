#ifndef XEN_DMALLOC_H
#define XEN_DMALLOC_H

#include <xen/types.h>

struct domain;

#define dzalloc_array(d, _type, _num)                                   \
    ((_type *)_dzalloc_array(d, sizeof(_type), __alignof__(_type), _num))


void dfree(struct domain *d, void *ptr);

#define DFREE(d, p)                             \
    do {                                        \
        dfree(d, p);                            \
        (p) = NULL;                             \
    } while ( 0 )


void *_dzalloc(struct domain *d, size_t size, size_t align);

static inline void *_dzalloc_array(struct domain *d, size_t size,
                                   size_t align, size_t num)
{
    return _dzalloc(d, size * num, align);
}

#endif /* XEN_DMALLOC_H */
