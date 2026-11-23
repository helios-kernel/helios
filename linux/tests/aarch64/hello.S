// The aarch64 twin of `../hello.S`: asm-generic syscall numbers in x8,
// arguments in x0-x5, the result in x0.
.global _start
.section .text
_start:
    mov x9, sp
    tst x9, #15
    b.ne failed
    ldr x9, [sp]
    cmp x9, #1
    b.ne failed
    // Unknown calls must return -ENOSYS, never invented success.
    mov x8, #9999
    svc #0
    cmn x0, #38
    b.ne failed
    // write(9, ...) on a closed descriptor is -EBADF.
    mov x8, #64
    mov x0, #9
    adr x1, message
    mov x2, #(message_end - message)
    svc #0
    cmn x0, #9
    b.ne failed
    // write(1, NULL, 1) is -EFAULT.
    mov x8, #64
    mov x0, #1
    mov x1, #0
    mov x2, #1
    svc #0
    cmn x0, #14
    b.ne failed
    // Callee-saved and vector registers survive a syscall round trip.
    movz x19, #0x5678
    movk x19, #0x1234, lsl #16
    movi v8.16b, #0xff
    mov x8, #64
    mov x0, #1
    adr x1, message
    mov x2, #(message_end - message)
    svc #0
    cmp x0, #(message_end - message)
    b.ne failed
    movz x9, #0x5678
    movk x9, #0x1234, lsl #16
    cmp x19, x9
    b.ne failed
    umov x9, v8.d[1]
    cmn x9, #1
    b.ne failed
    mov x8, #94
    mov x0, #0
    svc #0
    udf #0
failed:
    mov x8, #93
    mov x0, #1
    svc #0
    udf #0
.section .rodata
message:
    .ascii "native Linux syscall: ok\n"
message_end:
.section .note.GNU-stack,"",@progbits
