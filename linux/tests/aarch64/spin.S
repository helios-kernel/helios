// The aarch64 twin of `../spin.S`: a loop that never calls out, which only
// preemption and a kill end.
.global _start
.section .text
_start:
    b _start
.section .note.GNU-stack,"",@progbits
