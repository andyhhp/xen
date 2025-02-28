#include <xen/linkage.h>

#include <asm/msr-index.h>

        .section .init.text, "ax", @progbits

        /*
         * This "function" is run by all APs in parallel, and has no stack.
         * It is terminated by the BSP sending INIT.
         *
         * See orchestrate_load() for the matching BSP logic.
         */
FUNC(amd_parallel_ucode_loader)

        mov     $MSR_AMD_PATCHLOADER, %ecx

.L_restart:
        lock incl trampoline_ucode_callin_ready(%rip)

.L_wait_to_load:
        mov     trampoline_ucode_ptr(%rip), %rdx
        test    %rdx, %rdx
        jnz     .L_load
        pause
        jmp     .L_wait_to_load

.L_load:
        mov     %rdx, %rax
        shr     $32, %rdx
        wrmsr

        lock incl trampoline_ucode_callin_done(%rip)

.L_wait_to_restart:
        testb   $1, trampoline_ucode_wait(%rip)
        jz      .L_restart
        pause
        jmp     .L_wait_to_restart
END(amd_parallel_ucode_loader)


        .section .init.rodata, "aw", @progbits

.macro ucode_blob p
DATA(patch_\p, 64)
        .incbin "\p"
END(patch_\p)
.endm

        ucode_blob 0a0011d8
        ucode_blob 0a0011d9
        ucode_blob 0a001241
        ucode_blob 0a001242
        ucode_blob 0a101152
        ucode_blob 0a101153
        ucode_blob 0a10124d
        ucode_blob 0a10124e
        ucode_blob 0aa00217
        ucode_blob 0aa00218
        ucode_blob 0b002140
        ucode_blob 0b101040
