.global _start
.section .text
_start:
    test $15, %rsp
    jnz failed
    cmpq $1, (%rsp)
    jne failed
    // Unknown calls must return -ENOSYS, never invented success.
    mov $9999, %eax
    syscall
    cmp $-38, %rax
    jne failed
    mov $1, %eax
    mov $9, %edi
    lea message(%rip), %rsi
    mov $message_end-message, %edx
    syscall
    cmp $-9, %rax
    jne failed
    mov $1, %eax
    mov $1, %edi
    xor %esi, %esi
    mov $1, %edx
    syscall
    cmp $-14, %rax
    jne failed
    // Callee-saved registers and vector state survive a syscall round trip.
    mov $0x12345678, %r12
    pcmpeqd %xmm0, %xmm0
    mov $1, %eax
    mov $1, %edi
    lea message(%rip), %rsi
    mov $message_end-message, %edx
    syscall
    cmp $message_end-message, %rax
    jne failed
    cmp $0x12345678, %r12
    jne failed
    pmovmskb %xmm0, %eax
    cmp $65535, %eax
    jne failed
    mov $231, %eax
    xor %edi, %edi
    syscall
    ud2
failed:
    mov $60, %eax
    mov $1, %edi
    syscall
    ud2
.section .rodata
message:
    .ascii "native Linux syscall: ok\n"
message_end:
.section .note.GNU-stack,"",@progbits
