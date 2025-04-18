
#ifndef __XMALLOC_H__
#define __XMALLOC_H__

#include <xen/types.h>
#include <xen/cache.h>

/*
 * Xen malloc/free-style interface.
 *
 * NOTE: Unless physically contiguous memory space is required, the interfaces
 *       in xvmalloc.h are to be used in preference to the ones here.
 */

/* Allocate space for typed object. */
#define xmalloc(_type) ((_type *)_xmalloc(sizeof(_type), __alignof__(_type)))
#define xzalloc(_type) ((_type *)_xzalloc(sizeof(_type), __alignof__(_type)))

/*
 * Allocate space for a typed object and copy an existing instance.
 *
 * Note: Due to const propagating in the typeof(), ptr needs to be mutable.
 * This can be fixed by changing n_ to being void *, but then we lose type
 * safety on the return value.
 */
#define xmemdup(ptr)                                         \
({                                                           \
    typeof(*(ptr)) *p_ = (ptr), *n_ = xmalloc(typeof(*p_));  \
                                                             \
    if ( n_ )                                                \
        memcpy(n_, p_, sizeof(*n_));                         \
    n_;                                                      \
})

/* Allocate space for array of typed objects. */
#define xmalloc_array(_type, _num) \
    ((_type *)_xmalloc_array(sizeof(_type), __alignof__(_type), _num))
#define xzalloc_array(_type, _num) \
    ((_type *)_xzalloc_array(sizeof(_type), __alignof__(_type), _num))
#define xrealloc_array(_ptr, _num)                                  \
    ((typeof(_ptr))_xrealloc_array(_ptr, sizeof(typeof(*(_ptr))),   \
                                   __alignof__(typeof(*(_ptr))), _num))

/* Allocate space for a structure with a flexible array of typed objects. */
#define xzalloc_flex_struct(type, field, nr) \
    ((type *)_xzalloc(offsetof(type, field[nr]), __alignof__(type)))

#define xmalloc_flex_struct(type, field, nr) \
    ((type *)_xmalloc(offsetof(type, field[nr]), __alignof__(type)))

/* Re-allocate space for a structure with a flexible array of typed objects. */
#define xrealloc_flex_struct(ptr, field, nr)                           \
    ((typeof(ptr))_xrealloc(ptr, offsetof(typeof(*(ptr)), field[nr]),  \
                            __alignof__(typeof(*(ptr)))))

/* Allocate untyped storage. */
#define xmalloc_bytes(_bytes) _xmalloc(_bytes, SMP_CACHE_BYTES)
#define xzalloc_bytes(_bytes) _xzalloc(_bytes, SMP_CACHE_BYTES)

/* Allocate untyped storage and copying an existing instance. */
#define xmemdup_bytes(_src, _nr)                \
    ({                                          \
        unsigned long nr_ = (_nr);              \
        void *dst_ = xmalloc_bytes(nr_);        \
                                                \
        if ( dst_ )                             \
            memcpy(dst_, _src, nr_);            \
        dst_;                                   \
    })

/* Free any of the above. */
extern void xfree(void *p);

/* Free an allocation, and zero the pointer to it. */
#define XFREE(p) do {                       \
    void *_ptr_ = (p);                      \
    (p) = NULL;                             \
    xfree(_ptr_);                           \
} while ( false )

/* Underlying functions */
extern void *_xmalloc(unsigned long size, unsigned long align);
extern void *_xzalloc(unsigned long size, unsigned long align);
extern void *_xrealloc(void *ptr, unsigned long size, unsigned long align);

static inline void *_xmalloc_array(
    unsigned long size, unsigned long align, unsigned long num)
{
    /* Check for overflow. */
    if ( size && num > UINT_MAX / size )
        return NULL;
    return _xmalloc(size * num, align);
}

static inline void *_xzalloc_array(
    unsigned long size, unsigned long align, unsigned long num)
{
    /* Check for overflow. */
    if ( size && num > UINT_MAX / size )
        return NULL;
    return _xzalloc(size * num, align);
}

static inline void *_xrealloc_array(
    void *ptr, unsigned long size, unsigned long align, unsigned long num)
{
    /* Check for overflow. */
    if ( size && num > UINT_MAX / size )
        return NULL;
    return _xrealloc(ptr, size * num, align);
}

/*
 * Pooled allocator interface.
 */

struct xmem_pool;

typedef void *(xmem_pool_get_memory)(unsigned long bytes);
typedef void (xmem_pool_put_memory)(void *ptr);

/**
 * xmem_pool_create - create dynamic memory pool
 * @name: name of the pool
 * @get_mem: callback function used to expand pool
 * @put_mem: callback function used to shrink pool
 * @max_size: maximum pool size (in bytes) - set this as 0 for no limit
 * @grow_size: amount of memory (in bytes) added to pool whenever required
 *
 * All size values are rounded up to next page boundary.
 */
struct xmem_pool *xmem_pool_create(
    const char *name,
    xmem_pool_get_memory get_mem,
    xmem_pool_put_memory put_mem,
    unsigned long max_size,
    unsigned long grow_size);

/**
 * xmem_pool_destroy - cleanup given pool
 * @mem_pool: Pool to be destroyed
 *
 * Data structures associated with pool are freed.
 * All memory allocated from pool must be freed before
 * destorying it.
 */
void xmem_pool_destroy(struct xmem_pool *pool);

/**
 * xmem_pool_alloc - allocate memory from given pool
 * @size: no. of bytes
 * @mem_pool: pool to allocate from
 */
void *xmem_pool_alloc(unsigned long size, struct xmem_pool *pool);

/**
 * xmem_pool_maxalloc - xmem_pool_alloc's greater than this size will fail
 * @mem_pool: pool
 */
int xmem_pool_maxalloc(struct xmem_pool *pool);

/**
 * xmem_pool_maxsize - 
 * @ptr: address of memory to be freed
 * @mem_pool: pool to free from
 */
void xmem_pool_free(void *ptr, struct xmem_pool *pool);

/**
 * xmem_pool_get_used_size - get memory currently used by given pool
 *
 * Used memory includes stored data + metadata + internal fragmentation
 */
unsigned long xmem_pool_get_used_size(struct xmem_pool *pool);

/**
 * xmem_pool_get_total_size - get total memory currently allocated for pool
 *
 * This is the total memory currently allocated for this pool which includes
 * used size + free size.
 *
 * (Total - Used) is good indicator of memory efficiency of allocator.
 */
unsigned long xmem_pool_get_total_size(struct xmem_pool *pool);

#endif /* __XMALLOC_H__ */
