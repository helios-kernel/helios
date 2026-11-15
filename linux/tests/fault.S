.global _start
.section .text
_start:
    // Supervisor half: access must fault in user mode, never fault the kernel.
    movabs $0xffff800000000000, %rax
    movq $1, (%rax)
    ud2
.section .note.GNU-stack,"",@progbits
