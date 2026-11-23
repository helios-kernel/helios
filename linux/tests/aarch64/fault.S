// The aarch64 twin of `../fault.S`: a load from the kernel's TTBR1 half
// must fault at EL0 and end the process with SIGSEGV.
.global _start
.section .text
_start:
    movz x0, #0xffff, lsl #48
    ldr x0, [x0]
    udf #0
.section .note.GNU-stack,"",@progbits
