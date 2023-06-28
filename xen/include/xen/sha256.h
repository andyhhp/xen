#ifndef __XEN_SHA256_H
#define __XEN_SHA256_H

#include <xen/inttypes.h>

#define SHA256_DIGEST_SIZE  32

void sha256_hash(const uint8_t message[], size_t len,
                 uint8_t hash[static SHA256_DIGEST_SIZE]);

#endif /* !__XEN_SHA256_H */
