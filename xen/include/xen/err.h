#if !defined(__XEN_ERR_H__) && !defined(__ASSEMBLY__)
#define __XEN_ERR_H__

#include <xen/compiler.h>
#include <xen/stdbool.h>
#include <xen/errno.h>

/*
 * Kernel pointers have redundant information, so we can use a
 * scheme where we can return either an error code or a dentry
 * pointer with the same return value.
 *
 * This could be a per-architecture thing, to allow different
 * error and pointer decisions.
 */
#define MAX_ERRNO	4095

/*
 * Individual architectures may wish to slide the error region away from its
 * default position at the very top of virtual address space.  (e.g. if Xen
 * doesn't own the range).
 */
#ifndef ARCH_ERR_PTR_SLIDE
#define ARCH_ERR_PTR_SLIDE 0
#endif

static inline bool IS_ERR_VALUE(unsigned long x)
{
	return (x + ARCH_ERR_PTR_SLIDE) >= (unsigned long)-MAX_ERRNO;
}

static inline void *__must_check ERR_PTR(long error)
{
	return (void *)((unsigned long)error - ARCH_ERR_PTR_SLIDE);
}

static inline long __must_check PTR_ERR(const void *ptr)
{
	return (long)((unsigned long)ptr + ARCH_ERR_PTR_SLIDE);
}

static inline bool __must_check IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline bool __must_check IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

/**
 * ERR_CAST - Explicitly cast an error-valued pointer to another pointer type
 * @ptr: The pointer to cast.
 *
 * Explicitly cast an error-valued pointer to another pointer type in such a
 * way as to make it clear that's what's going on.
 */
static inline void * __must_check ERR_CAST(const void *ptr)
{
	/* cast away the const */
	return (void *)ptr;
}

static inline int __must_check PTR_RET(const void *ptr)
{
	return IS_ERR(ptr) ? PTR_ERR(ptr) : 0;
}

#endif /* __XEN_ERR_H__ */
