.global _start
.section .text
_start:
    // Limine x86-64 kernel mapping base: reading a present supervisor page
    // must fault in user mode, even though no write permission is requested.
    movabs $0xffffffff80000000, %rax
    movq (%rax), %rax
    ud2
.section .note.GNU-stack,"",@progbits
