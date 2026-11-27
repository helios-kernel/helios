// Bootstrap and Limine MP secondary entry points for the RISC-V 64-bit
// higher-half kernel.
//
// Limine enters `_start` on the bootstrap hart and `_limine_secondary_entry`
// on each secondary hart in supervisor mode with Sv48 paging active, higher-half
// mappings installed, interrupts disabled, and `sstatus.FS` cleared (`Off`).
// Both entries set `gp`, enable floating point (`sstatus.FS = Initial`,
// `fscsr = 0`) so `lp64d` Rust code can run safely, and enter Rust.

.section .text._start, "ax"
.global _start
.type _start, %function
_start:
    csrci sstatus, 0x2
    csrw sie, zero

    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    // Enable floating point (`sstatus.FS = Initial`, `fcsr = 0`).
    .option push
    .option arch, +f
    li t0, 0x4000
    csrc sstatus, t0
    li t0, 0x2000
    csrs sstatus, t0
    fscsr x0
    .option pop

    la sp, __riscv_boot_stack_top
    call riscv_kernel_main
1:
    wfi
    j 1b
.size _start, . - _start

.section .text.limine_secondary, "ax"
.global _limine_secondary_entry
.type _limine_secondary_entry, %function
_limine_secondary_entry:
    csrci sstatus, 0x2
    csrw sie, zero

    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    // Enable floating point (`sstatus.FS = Initial`, `fcsr = 0`).
    .option push
    .option arch, +f
    li t0, 0x4000
    csrc sstatus, t0
    li t0, 0x2000
    csrs sstatus, t0
    fscsr x0
    .option pop

    // Limine passes `&MpInfo` in `a0` and already provides a dedicated stack
    // sized by `STACK_SIZE_REQUEST`.
    call riscv_secondary_main
1:
    wfi
    j 1b
.size _limine_secondary_entry, . - _limine_secondary_entry

.section .bss.stack, "aw", @nobits
.align 12
.global __riscv_boot_stack
__riscv_boot_stack:
    .skip {boot_stack_bytes}
.global __riscv_boot_stack_top
__riscv_boot_stack_top:
