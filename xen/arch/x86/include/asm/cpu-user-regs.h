#ifndef X86_CPU_USER_REGS_H
#define X86_CPU_USER_REGS_H

#define DECL_REG_LOHI(which) union { \
    uint64_t r ## which ## x; \
    uint32_t e ## which ## x; \
    uint16_t which ## x; \
    struct { \
        uint8_t which ## l; \
        uint8_t which ## h; \
    }; \
}
#define DECL_REG_LO8(name) union { \
    uint64_t r ## name; \
    uint32_t e ## name; \
    uint16_t name; \
    uint8_t name ## l; \
}
#define DECL_REG_LO16(name) union { \
    uint64_t r ## name; \
    uint32_t e ## name; \
    uint16_t name; \
}
#define DECL_REG_HI(num) union { \
    uint64_t r ## num; \
    uint32_t r ## num ## d; \
    uint16_t r ## num ## w; \
    uint8_t r ## num ## b; \
}

struct cpu_user_regs
{
    DECL_REG_HI(15);
    DECL_REG_HI(14);
    DECL_REG_HI(13);
    DECL_REG_HI(12);
    DECL_REG_LO8(bp);
    DECL_REG_LOHI(b);
    DECL_REG_HI(11);
    DECL_REG_HI(10);
    DECL_REG_HI(9);
    DECL_REG_HI(8);
    DECL_REG_LOHI(a);
    DECL_REG_LOHI(c);
    DECL_REG_LOHI(d);
    DECL_REG_LO8(si);
    DECL_REG_LO8(di);

    /*
     *
     */

    uint32_t error_code;
    uint32_t entry_vector;

    DECL_REG_LO16(ip);
    uint16_t cs, _pad0[1];
    uint8_t  saved_upcall_mask;
    uint8_t  _pad1[3];
    DECL_REG_LO16(flags); /* rflags.IF == !saved_upcall_mask */
    DECL_REG_LO8(sp);
    uint16_t ss, _pad2[3];

    uint64_t edata, _rsvd;
};

#undef DECL_REG_HI
#undef DECL_REG_LO16
#undef DECL_REG_LO8
#undef DECL_REG_LOHI

#endif /* X86_CPU_USER_REGS_H */
