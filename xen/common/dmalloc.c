#include <xen/dmalloc.h>
#include <xen/sched.h>
#include <xen/xmalloc.h>

void dfree(struct domain *d, void *ptr)
{
    if ( !ptr || ptr == ZERO_BLOCK_PTR )
        return;

    atomic_dec(&d->dalloc_heap);
    xfree(ptr);
}

void *_dzalloc(struct domain *d, size_t size, size_t align)
{
    void *ptr;

    if ( should_simulate_failure(d) )
        return NULL;

    ptr = _xmalloc(size, align);

    if ( !ptr || ptr == ZERO_BLOCK_PTR )
        return ptr;

    atomic_inc(&d->dalloc_heap);

    return ptr;
}
