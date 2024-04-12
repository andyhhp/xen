#ifndef X86_EMULATE_H
#define X86_EMULATE_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <xen/asm/x86-defns.h>
#include <xen/asm/x86-vendors.h>

#include <xen-tools/common-macros.h>

#define ASSERT assert

#define printk(...)

#define likely
#define unlikely
#define cf_check
#define init_or_livepatch
#define init_or_livepatch_const

#include "x86_emulate/x86_emulate.h"

#endif /* X86_EMULATE_H */
