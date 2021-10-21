#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include INCLUDE_ENDIAN_H
#include <stdint.h>

#include "xg_private.h"
#include "xg_dom_decompress_unsafe.h"

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint64_t u64;

#define likely(a) a
#define noinline
#define unlikely(a) a

static inline u16 be16_to_cpu(const u16 v)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	return __builtin_bswap16(v);
#else
	return v;
#endif
}

static inline u32 be32_to_cpup(const u32 v)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	return __builtin_bswap32(v);
#else
	return v;
#endif
}

#include "../../xen/common/lzo.c"
#include "../../xen/common/unlzo.c"

int xc_try_lzo1x_decode(
    struct xc_dom_image *dom, void **blob, size_t *size)
{
    return xc_dom_decompress_unsafe(unlzo, dom, blob, size);
}
