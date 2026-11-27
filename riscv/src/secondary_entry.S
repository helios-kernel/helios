// Re-entry of a hart that `Cpu::stop_current` took out of service via SBI HSM
// `hart_stop`.
//
// `sbi_rt::hart_start` enters `_hart_restart` at its physical address with
// paging disabled (`satp = 0`), `a0` holding the hart id and `a1` holding the
// physical address of `RestartArgs`. Everything in `_hart_restart` is
// position-independent and touches only `RestartArgs` until Sv48 paging is
// enabled through the temporary restart root table (which maps both the
// physical address of `_hart_restart` and the kernel's higher half). Once in
// `_hart_restart_virtual`, the hart switches to the live kernel `satp`,
// restores `gp`, `sp`, and `tp`, enables floating point (`sstatus.FS = Initial`,
// `fcsr = 0`), and tail-calls `helios_hart_resume`.
//
// The byte offsets below are asserted at compile time in `lifecycle.rs`.
.equ HELIOS_RESTART_SATP,          0x00
.equ HELIOS_RESTART_KERNEL_SATP,   0x08
.equ HELIOS_RESTART_VIRTUAL_ENTRY, 0x10
.equ HELIOS_RESTART_CONTEXT_VIRT,  0x18

.equ HELIOS_CONTEXT_SP, 0x08
.equ HELIOS_CONTEXT_TP, 0x10

.section .text.hart_restart, "ax"
.global _hart_restart
.balign 4
_hart_restart:
    csrci sstatus, 0x2
    csrw sie, zero

    ld t0, HELIOS_RESTART_SATP(a1)
    ld t2, HELIOS_RESTART_KERNEL_SATP(a1)
    ld t1, HELIOS_RESTART_VIRTUAL_ENTRY(a1)
    ld a1, HELIOS_RESTART_CONTEXT_VIRT(a1)

    csrw satp, t0
    sfence.vma zero, zero
    jr t1

.global _hart_restart_virtual
.balign 4
_hart_restart_virtual:
    csrw satp, t2
    sfence.vma zero, zero

    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    ld sp, HELIOS_CONTEXT_SP(a1)
    ld tp, HELIOS_CONTEXT_TP(a1)

    // Enable floating point (`sstatus.FS = Initial`, `fcsr = 0`):
    // `sbi_hart_start` leaves `sstatus.FS` unspecified.
    .option push
    .option arch, +f
    li t0, 0x4000
    csrc sstatus, t0
    li t0, 0x2000
    csrs sstatus, t0
    fscsr x0
    .option pop

    tail helios_hart_resume
