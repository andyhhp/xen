#ifndef __XEN_SHA1_H
#define __XEN_SHA1_H

#include <xen/inttypes.h>

#define SHA1_DIGEST_SIZE  20

void sha1_hash(const uint8_t message[], size_t len,
               uint8_t hash[static SHA1_DIGEST_SIZE]);

#endif /* !__XEN_SHA1_H */
