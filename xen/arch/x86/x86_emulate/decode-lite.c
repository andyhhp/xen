/* SPDX-License-Identifier: GPL-2.0-only */

#include "private.h"

#define Imm8   (1 << 0)
#define Imm    (1 << 1)
#define Moffs  (1 << 2)
#define Branch (1 << 5) /* ... that we care about */
/*      ModRM  (1 << 6) */
#define Known  (1 << 7)

#define ALU_OPS                                 \
    (Known|ModRM),                              \
    (Known|ModRM),                              \
    (Known|ModRM),                              \
    (Known|ModRM),                              \
    (Known|Imm8),                               \
    (Known|Imm)

static const uint8_t init_or_livepatch_const onebyte[256] = {
    [0x00] = ALU_OPS, /* ADD */ [0x08] = ALU_OPS, /* OR  */
    [0x10] = ALU_OPS, /* ADC */ [0x18] = ALU_OPS, /* SBB */
    [0x20] = ALU_OPS, /* AND */ [0x28] = ALU_OPS, /* SUB */
    [0x30] = ALU_OPS, /* XOR */ [0x38] = ALU_OPS, /* CMP */
/*  [0x40 ... 0x4f] = REX prefixes */
    [0x50 ... 0x5f] = (Known),             /* PUSH/POP %reg */

    [0x63]          = (Known|ModRM),       /* MOVSxd */

    [0x68]          = (Known|Imm),         /* PUSH $imm */
    [0x69]          = (Known|ModRM|Imm),   /* IMUL $imm/r/rm */
    [0x6a]          = (Known|Imm8),        /* PUSH $imm8 */
    [0x6b]          = (Known|ModRM|Imm8),  /* PUSH $imm8/r/rm */
    [0x6c ... 0x6f] = (Known),             /* INS/OUTS */

    [0x70 ... 0x7f] = (Known|Branch|Imm8), /* Jcc disp8 */
    [0x80]          = (Known|ModRM|Imm8),  /* Grp1 */
    [0x81]          = (Known|ModRM|Imm),   /* Grp1 */

    [0x83]          = (Known|ModRM|Imm8),  /* Grp1 */
    [0x84 ... 0x8e] = (Known|ModRM),       /* TEST/XCHG/MOV/MOV-SREG/LEA r/rm */

    [0x90 ... 0x99] = (Known),             /* NOP/XCHG rAX/CLTQ/CQTO */

    [0x9b ... 0x9f] = (Known),             /* FWAIT/PUSHF/POPF/SAHF/LAHF */

    [0xa0 ... 0xa3] = (Known|Moffs),       /* MOVABS */
    [0xa4 ... 0xa7] = (Known),             /* MOVS/CMPS */
    [0xa8]          = (Known|Imm8),        /* TEST %al */
    [0xa9]          = (Known|Imm),         /* TEST %al */
    [0xaa ... 0xaf] = (Known),             /* STOS/LODS/SCAS */
    [0xb0 ... 0xb7] = (Known|Imm8),        /* MOV $imm8, %reg */
    [0xb8 ... 0xbf] = (Known|Imm),         /* MOV $imm{16,32,64}, %reg */
    [0xc0 ... 0xc1] = (Known|ModRM|Imm8),  /* Grp2 (ROL..SAR $imm8, %reg) */

    [0xc3]          = (Known),             /* RET */
    [0xc6]          = (Known|ModRM|Imm8),  /* Grp11, Further ModRM decode */
    [0xc7]          = (Known|ModRM|Imm),   /* Grp11, Further ModRM decode */

    [0xcb ... 0xcc] = (Known),             /* LRET/INT3 */
    [0xcd]          = (Known|Imm8),        /* INT $imm8 */

    [0xd0 ... 0xd3] = (Known|ModRM),       /* Grp2 (ROL..SAR {$1,%cl}, %reg) */

    [0xe4 ... 0xe7] = (Known|Imm8),        /* IN/OUT $imm8 */
    [0xe8 ... 0xe9] = (Known|Branch|Imm),  /* CALL/JMP disp32 */
    [0xeb]          = (Known|Branch|Imm8), /* JMP disp8 */
    [0xec ... 0xef] = (Known),             /* IN/OUT %dx */

    [0xf1]          = (Known),             /* ICEBP */
    [0xf4]          = (Known),             /* HLT */
    [0xf5]          = (Known),             /* CMC */
    [0xf6 ... 0xf7] = (Known|ModRM),       /* Grp3, Further ModRM decode */
    [0xf8 ... 0xfd] = (Known),             /* CLC ... STD */
    [0xfe ... 0xff] = (Known|ModRM),       /* Grp4 */
};
static const uint8_t init_or_livepatch_const twobyte[256] = {
    [0x00 ... 0x03] = (Known|ModRM),       /* Grp6/Grp7/LAR/LSL */
    [0x06]          = (Known),             /* CLTS */
    [0x09]          = (Known),             /* WBINVD */
    [0x0b]          = (Known),             /* UD2 */

    [0x18 ... 0x1f] = (Known|ModRM),       /* Grp16 (Hint Nop) */
    [0x20 ... 0x23] = (Known|ModRM),       /* MOV %cr/%dr */

    [0x30 ... 0x33] = (Known),             /* WRMSR/RDTSC/RDMSR/RDPMC */

    [0x40 ... 0x4f] = (Known|ModRM),       /* CMOVcc */

    [0x80 ... 0x8f] = (Known|Branch|Imm),  /* Jcc disp32 */
    [0x90 ... 0x9f] = (Known|ModRM),       /* SETcc */

    [0xa0 ... 0xa2] = (Known),             /* PUSH/POP %fs/CPUID */
    [0xa3]          = (Known|ModRM),       /* BT r/rm */
    [0xa4]          = (Known|ModRM|Imm8),  /* SHLD $imm8 */
    [0xa5]          = (Known|ModRM),       /* SHLD %cl */

    [0xa8 ... 0xa9] = (Known),             /* PUSH/POP %gs */

    [0xab]          = (Known|ModRM),       /* BTS */
    [0xac]          = (Known|ModRM|Imm8),  /* SHRD $imm8 */
    [0xad ... 0xaf] = (Known|ModRM),       /* SHRD %cl/Grp15/IMUL */

    [0xb0 ... 0xb9] = (Known|ModRM),       /* CMPXCHG/LSS/BTR/LFS/LGS/MOVZxx/POPCNT/Grp10 */
    [0xba]          = (Known|ModRM|Imm8),  /* Grp8 */
    [0xbb ... 0xbf] = (Known|ModRM),       /* BSR/BSF/BSR/MOVSX */
    [0xc0 ... 0xc1] = (Known|ModRM),       /* XADD */
    [0xc7]          = (Known|ModRM),       /* Grp9 */
    [0xc8 ... 0xcf] = (Known),             /* BSWAP */
};

/*
 * Bare minimum x86 instruction decoder to parse the alternative replacement
 * instructions and locate the IP-relative references that may need updating.
 *
 * These are:
 *  - disp8/32 from near branches
 *  - RIP-relative memory references
 *
 * The following simplifications are used:
 *  - All code is 64bit, and the instruction stream is safe to read.
 *  - The 67 prefix is not implemented, so the address size is only 64bit.
 *
 * Inputs:
 *  @ip  The position to start decoding from.
 *  @end End of the replacement block.  Exceeding this is considered an error.
 *
 * Returns: x86_decode_lite_t
 *  - On failure, length of 0.
 *  - On success, length > 0.  For rel_sz > 0, rel points at the relative
 *    field in the instruction stream.
 */
x86_decode_lite_t init_or_livepatch x86_decode_lite(void *ip, void *end)
{
    void *start = ip, *rel = NULL;
    unsigned int opc, rel_sz = 0;
    uint8_t b, d, rex = 0, osize = 4;

#define OPC_TWOBYTE (1 << 8)

    /* Mutates IP, uses END. */
#define FETCH(ty)                                       \
    ({                                                  \
        ty _val;                                        \
                                                        \
        if ( (ip + sizeof(ty)) > end )                  \
            goto overrun;                               \
        _val = *(ty *)ip;                               \
        ip += sizeof(ty);                               \
        _val;                                           \
    })

    for ( ;; ) /* Prefixes */
    {
        switch ( b = FETCH(uint8_t) )
        {
        case 0x26: /* ES override */
        case 0x2e: /* CS override */
        case 0x36: /* DS override */
        case 0x3e: /* SS override */
        case 0x64: /* FS override */
        case 0x65: /* GS override */
        case 0xf0: /* LOCK */
        case 0xf2: /* REPNE */
        case 0xf3: /* REP */
            break;

        case 0x66: /* Operand size override */
            osize = 2;
            break;

        /* case 0x67: Address size override, not implemented */

        case 0x40 ... 0x4f: /* REX */
            rex = b;
            continue;

        default:
            goto prefixes_done;
        }
        rex = 0; /* REX cancelled by subsequent legacy prefix. */
    }
 prefixes_done:

    if ( rex & 0x08 ) /* REX.W */
        osize = 8;

    /* Fetch the main opcode byte(s) */
    if ( b == 0x0f )
    {
        b = FETCH(uint8_t);
        opc = OPC_TWOBYTE | b;

        d = twobyte[b];
    }
    else
    {
        opc = b;
        d = onebyte[b];
    }

    if ( unlikely(!(d & Known)) )
        goto unknown;

    if ( d & ModRM )
    {
        uint8_t modrm = FETCH(uint8_t);
        uint8_t mod = modrm >> 6;
        uint8_t reg = (modrm >> 3) & 7;
        uint8_t rm = modrm & 7;

        /* ModRM/SIB decode */
        if ( mod == 0 && rm == 5 ) /* RIP relative */
        {
            rel = ip;
            rel_sz = 4;
            FETCH(uint32_t);
        }
        else if ( mod != 3 && rm == 4 ) /* SIB */
        {
            uint8_t sib = FETCH(uint8_t);
            uint8_t base = sib & 7;

            if ( mod == 0 && base == 5 )
                goto disp32;
        }

        if ( mod == 1 ) /* disp8 */
            FETCH(uint8_t);
        else if ( mod == 2 ) /* disp32 */
        {
        disp32:
            FETCH(uint32_t);
        }

        /* ModRM based decode adjustements */
        switch ( opc )
        {
        case 0xc7: /* Grp11 XBEGIN is a branch. */
            if ( modrm == 0xf8 )
                d |= Branch;
            break;
        case 0xf6: /* Grp3 TEST(s) have extra Imm8 */
            if ( reg == 0 || reg == 1 )
                d |= Imm8;
            break;
        case 0xf7: /* Grp3 TEST(s) have extra Imm */
            if ( reg == 0 || reg == 1 )
                d |= Imm;
            break;
        }
    }

    if ( d & Branch )
    {
        /*
         * We don't tolerate 66-prefixed call/jmp in alternatives.  Some are
         * genuinely decoded differently between Intel and AMD CPUs.
         *
         * We also don't support APX instructions, so don't have to cope with
         * JMPABS which is the first branch to have an 8-byte immediate.
         */
        if ( osize < 4 )
            goto bad_osize;

        rel = ip;
        rel_sz = (d & Imm8) ? 1 : 4;
    }

    if ( d & (Imm | Imm8 | Moffs) )
    {
        if ( d & Imm8 )
            osize = 1;
        else if ( d & Moffs )
            osize = 8;
        else if ( osize == 8 && !(opc >= 0xb8 && opc <= 0xbf) )
            osize = 4;

        switch ( osize )
        {
        case 1: FETCH(uint8_t);  break;
        case 2: FETCH(uint16_t); break;
        case 4: FETCH(uint32_t); break;
        case 8: FETCH(uint64_t); break;
        default: goto bad_osize;
        }
    }

    return (x86_decode_lite_t){ ip - start, rel_sz, rel };

 bad_osize:
    printk(XENLOG_ERR "%s() Bad osize %u in %*ph\n",
           __func__, osize,
           (int)(unsigned long)(end - start), start);
    return (x86_decode_lite_t){ 0, 0, NULL };

 unknown:
    printk(XENLOG_ERR "%s() Unknown opcode in %*ph <%02x> %*ph\n",
           __func__,
           (int)(unsigned long)(ip - 1 - start), start, b,
           (int)(unsigned long)(end - ip), ip);
    return (x86_decode_lite_t){ 0, 0, NULL };

 overrun:
    printk(XENLOG_ERR "%s() Decode overrun, got %*ph\n",
           __func__,
           (int)(unsigned long)(end - start), start);
    return (x86_decode_lite_t){ 0, 0, NULL };

#undef FETCH
}
