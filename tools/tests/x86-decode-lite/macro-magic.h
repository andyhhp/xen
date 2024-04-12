#ifndef X86_DECODE_LITE_LINKAGE_H
#define X86_DECODE_LITE_LINKAGE_H

/* Start a 'struct test' array */
.macro start_arr aname
    .pushsection .data.rel.ro.\aname, "aw", @progbits
    .globl \aname
    .type \aname, STT_OBJECT
\aname:
    .popsection

    /* Declare a macro wrapping \aname */
    .macro pushsection_arr
    .pushsection .data.rel.ro.\aname, "aw", @progbits
    .endm
.endm

/* Macro 'n' to wrap the metadata of an instruction.  Name can be different. */
.macro n name:req insn:vararg
    /* Emit the instruction, with start & end markers. */
.Ls\@: \insn
.Le\@:

    /* Emit \name as a string. */
    .pushsection .rosdata.str1, "aMS", @progbits, 1
.Ln\@: .asciz "\name"
    .popsection

    /* Emit an entry into the array. */
    pushsection_arr
    .quad .Ln\@, .Ls\@, .Le\@ - .Ls\@
    .popsection
.endm

/* Macro '_' where the name is the instruction itself. */
.macro _ insn:vararg
    n "\insn" \insn
.endm

/* Finish a 'struct test' array */
.macro finish_arr aname
    pushsection_arr
    .quad 0, 0, 0
    .size \aname, . - \aname
    .popsection
    .purgem pushsection_arr
.endm

#define DECL(aname) start_arr aname
#define END(aname) finish_arr aname

#endif /* X86_DECODE_LITE_LINKAGE_H */
