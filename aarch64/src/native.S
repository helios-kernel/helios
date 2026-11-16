// Native user execution at EL0 (`crate::native`).
//
// A slice runs with SP_EL1 pointing at its `Switch` record, so an exception
// taken from EL0 (which always lands on SP_EL1) saves the user registers
// straight into it. The kernel's SP_EL1, SP_EL0 (the per-processor
// exception stack), TTBR0, TCR, TPIDR_EL0 and FPCR and its callee-saved
// registers are saved by the entry and restored by the exit, which then
// returns to the caller of `helios_aarch64_native_enter` with IRQs masked.

.section .text.helios_aarch64_native, "ax"
.global helios_aarch64_native_enter
.type helios_aarch64_native_enter, %function
helios_aarch64_native_enter:
    stp x29, x30, [sp, #-0xa0]!
    stp x19, x20, [sp, #0x10]
    stp x21, x22, [sp, #0x20]
    stp x23, x24, [sp, #0x30]
    stp x25, x26, [sp, #0x40]
    stp x27, x28, [sp, #0x50]
    stp d8, d9, [sp, #0x60]
    stp d10, d11, [sp, #0x70]
    stp d12, d13, [sp, #0x80]
    stp d14, d15, [sp, #0x90]
    mov x1, sp
    str x1, [x0, #{kernel_sp}]
    mrs x1, sp_el0
    str x1, [x0, #{kernel_sp_el0}]
    mrs x1, ttbr0_el1
    str x1, [x0, #{kernel_ttbr0}]
    mrs x1, tcr_el1
    str x1, [x0, #{kernel_tcr}]
    mrs x1, tpidr_el0
    str x1, [x0, #{kernel_tpidr}]
    mrs x1, fpcr
    str x1, [x0, #{kernel_fpcr}]
    // The user translation, and no stale one of ASID 0 left behind by
    // whatever TTBR0 held before.
    ldr x1, [x0, #{user_tcr}]
    msr tcr_el1, x1
    ldr x1, [x0, #{user_ttbr0}]
    msr ttbr0_el1, x1
    isb
    tlbi aside1, xzr
    dsb nsh
    isb
    ldr x1, [x0, #{sp}]
    msr sp_el0, x1
    ldr x1, [x0, #{pc}]
    msr elr_el1, x1
    ldr x1, [x0, #{pstate}]
    msr spsr_el1, x1
    ldr x1, [x0, #{tpidr}]
    msr tpidr_el0, x1
    ldp x1, x2, [x0, #{fpsr}]
    msr fpsr, x1
    msr fpcr, x2
    add x1, x0, #{q}
    ldp q0, q1, [x1, #0x000]
    ldp q2, q3, [x1, #0x020]
    ldp q4, q5, [x1, #0x040]
    ldp q6, q7, [x1, #0x060]
    ldp q8, q9, [x1, #0x080]
    ldp q10, q11, [x1, #0x0a0]
    ldp q12, q13, [x1, #0x0c0]
    ldp q14, q15, [x1, #0x0e0]
    ldp q16, q17, [x1, #0x100]
    ldp q18, q19, [x1, #0x120]
    ldp q20, q21, [x1, #0x140]
    ldp q22, q23, [x1, #0x160]
    ldp q24, q25, [x1, #0x180]
    ldp q26, q27, [x1, #0x1a0]
    ldp q28, q29, [x1, #0x1c0]
    ldp q30, q31, [x1, #0x1e0]
    mov sp, x0
    ldp x2, x3, [x0, #0x10]
    ldp x4, x5, [x0, #0x20]
    ldp x6, x7, [x0, #0x30]
    ldp x8, x9, [x0, #0x40]
    ldp x10, x11, [x0, #0x50]
    ldp x12, x13, [x0, #0x60]
    ldp x14, x15, [x0, #0x70]
    ldp x16, x17, [x0, #0x80]
    ldp x18, x19, [x0, #0x90]
    ldp x20, x21, [x0, #0xa0]
    ldp x22, x23, [x0, #0xb0]
    ldp x24, x25, [x0, #0xc0]
    ldp x26, x27, [x0, #0xd0]
    ldp x28, x29, [x0, #0xe0]
    ldr x30, [x0, #0xf0]
    ldp x0, x1, [x0, #0x00]
    eret
.size helios_aarch64_native_enter, . - helios_aarch64_native_enter

// Lower-EL AArch64 synchronous exception: SP is the slice's `Switch`.
.global helios_aarch64_native_lower_sync
.type helios_aarch64_native_lower_sync, %function
helios_aarch64_native_lower_sync:
    stp x0, x1, [sp, #0x00]
    mrs x0, esr_el1
    mrs x1, far_el1
    stp x0, x1, [sp, #{esr}]
    mov x0, #{exit_sync}
    b helios_aarch64_native_exit
.size helios_aarch64_native_lower_sync, . - helios_aarch64_native_lower_sync

// Lower-EL AArch64 IRQ: the interrupt stays pending in the GIC, and the
// caller acknowledges it once the kernel's state is back.
.global helios_aarch64_native_lower_irq
.type helios_aarch64_native_lower_irq, %function
helios_aarch64_native_lower_irq:
    stp x0, x1, [sp, #0x00]
    mov x0, #{exit_irq}
    b helios_aarch64_native_exit
.size helios_aarch64_native_lower_irq, . - helios_aarch64_native_lower_irq

// Lower-EL AArch64 FIQ: the kernel takes no FIQ and a slice runs with
// PSTATE.F set as the kernel does (`SPSR_FIQ_MASKED`), so a FIQ reaches
// this vector only if that mask is ever lifted. It then ends the slice and
// stays pending, as an IRQ does.
.global helios_aarch64_native_lower_fiq
.type helios_aarch64_native_lower_fiq, %function
helios_aarch64_native_lower_fiq:
    stp x0, x1, [sp, #0x00]
    mov x0, #{exit_fiq}
    b helios_aarch64_native_exit
.size helios_aarch64_native_lower_fiq, . - helios_aarch64_native_lower_fiq

// Lower-EL AArch64 SError: an asynchronous error taken while the slice ran,
// recorded with its syndrome for the program's fault.
.global helios_aarch64_native_lower_serror
.type helios_aarch64_native_lower_serror, %function
helios_aarch64_native_lower_serror:
    stp x0, x1, [sp, #0x00]
    mrs x0, esr_el1
    stp x0, xzr, [sp, #{esr}]
    mov x0, #{exit_serror}
    b helios_aarch64_native_exit
.size helios_aarch64_native_lower_serror, . - helios_aarch64_native_lower_serror

helios_aarch64_native_exit:
    str x0, [sp, #{exit}]
    stp x2, x3, [sp, #0x10]
    stp x4, x5, [sp, #0x20]
    stp x6, x7, [sp, #0x30]
    stp x8, x9, [sp, #0x40]
    stp x10, x11, [sp, #0x50]
    stp x12, x13, [sp, #0x60]
    stp x14, x15, [sp, #0x70]
    stp x16, x17, [sp, #0x80]
    stp x18, x19, [sp, #0x90]
    stp x20, x21, [sp, #0xa0]
    stp x22, x23, [sp, #0xb0]
    stp x24, x25, [sp, #0xc0]
    stp x26, x27, [sp, #0xd0]
    stp x28, x29, [sp, #0xe0]
    str x30, [sp, #0xf0]
    mrs x0, sp_el0
    str x0, [sp, #{sp}]
    mrs x0, elr_el1
    str x0, [sp, #{pc}]
    mrs x0, spsr_el1
    str x0, [sp, #{pstate}]
    mrs x0, tpidr_el0
    str x0, [sp, #{tpidr}]
    mrs x0, fpsr
    mrs x1, fpcr
    stp x0, x1, [sp, #{fpsr}]
    add x1, sp, #{q}
    stp q0, q1, [x1, #0x000]
    stp q2, q3, [x1, #0x020]
    stp q4, q5, [x1, #0x040]
    stp q6, q7, [x1, #0x060]
    stp q8, q9, [x1, #0x080]
    stp q10, q11, [x1, #0x0a0]
    stp q12, q13, [x1, #0x0c0]
    stp q14, q15, [x1, #0x0e0]
    stp q16, q17, [x1, #0x100]
    stp q18, q19, [x1, #0x120]
    stp q20, q21, [x1, #0x140]
    stp q22, q23, [x1, #0x160]
    stp q24, q25, [x1, #0x180]
    stp q26, q27, [x1, #0x1a0]
    stp q28, q29, [x1, #0x1c0]
    stp q30, q31, [x1, #0x1e0]
    // The kernel's translation, with every user translation of ASID 0
    // gone from this processor.
    ldr x0, [sp, #{kernel_tcr}]
    msr tcr_el1, x0
    ldr x0, [sp, #{kernel_ttbr0}]
    msr ttbr0_el1, x0
    isb
    tlbi aside1, xzr
    dsb nsh
    isb
    ldr x0, [sp, #{kernel_sp_el0}]
    msr sp_el0, x0
    ldr x0, [sp, #{kernel_tpidr}]
    msr tpidr_el0, x0
    ldr x0, [sp, #{kernel_fpcr}]
    msr fpcr, x0
    ldr x0, [sp, #{kernel_sp}]
    mov sp, x0
    ldp d14, d15, [sp, #0x90]
    ldp d12, d13, [sp, #0x80]
    ldp d10, d11, [sp, #0x70]
    ldp d8, d9, [sp, #0x60]
    ldp x27, x28, [sp, #0x50]
    ldp x25, x26, [sp, #0x40]
    ldp x23, x24, [sp, #0x30]
    ldp x21, x22, [sp, #0x20]
    ldp x19, x20, [sp, #0x10]
    ldp x29, x30, [sp], #0xa0
    ret
