/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SHA-256: https://csrc.nist.gov/pubs/fips/180-2/upd1/final
 */
#ifndef XEN_SHA256_H
#define XEN_SHA256_H

#include <xen/types.h>

#define SHA256_DIGEST_SIZE 32

void sha256_digest(uint8_t digest[SHA256_DIGEST_SIZE],
                   const void *msg, size_t len);

#endif /* XEN_SHA256_H */
