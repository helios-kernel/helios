// BSP double-return snapshot point for AArch64.
//
// Field offsets match `helios_hal::cpu::Aarch64SnapshotContext`, pinned by
// compile-time assertions in `aarch64/src/lib.rs`:
//   0x00..0x60: x19..x30
//   0x60:       sp
//   0x68..0xa8: d8..d15
//   0xa8:       fpcr
.section .text.helios_aarch64_snapshot, "ax"

// extern "C" fn __helios_aarch64_capture_bsp_state(ctx: *mut Aarch64SnapshotContext) -> u64
//
// Leaf routine (no stack spill of LR): saves callee-saved GPRs, SP, d8-d15,
// and FPCR into `ctx`, returning 0 (`SnapshotPoint::Captured`). A restore stub
// jumping to `__helios_aarch64_resume_bsp_state` restores the context and
// returns 1 (`SnapshotPoint::Resumed`) to the caller.
.global __helios_aarch64_capture_bsp_state
.type __helios_aarch64_capture_bsp_state, %function
__helios_aarch64_capture_bsp_state:
    hint #34
    stp x19, x20, [x0, #0x00]
    stp x21, x22, [x0, #0x10]
    stp x23, x24, [x0, #0x20]
    stp x25, x26, [x0, #0x30]
    stp x27, x28, [x0, #0x40]
    stp x29, x30, [x0, #0x50]
    mov x1, sp
    str x1, [x0, #0x60]
    stp d8, d9, [x0, #0x68]
    stp d10, d11, [x0, #0x78]
    stp d12, d13, [x0, #0x88]
    stp d14, d15, [x0, #0x98]
    mrs x1, fpcr
    str x1, [x0, #0xa8]
    mov x0, #0
    ret
.size __helios_aarch64_capture_bsp_state, . - __helios_aarch64_capture_bsp_state

// extern "C" fn __helios_aarch64_resume_bsp_state(ctx: *const Aarch64SnapshotContext) -> !
//
// Restores the callee-saved state captured by
// `__helios_aarch64_capture_bsp_state` (after system registers and translation
// tables are in place) and returns 1 (`SnapshotPoint::Resumed`) to its caller.
.global __helios_aarch64_resume_bsp_state
.type __helios_aarch64_resume_bsp_state, %function
__helios_aarch64_resume_bsp_state:
    hint #34
    ldr x1, [x0, #0xa8]
    msr fpcr, x1
    isb
    ldp d8, d9, [x0, #0x68]
    ldp d10, d11, [x0, #0x78]
    ldp d12, d13, [x0, #0x88]
    ldp d14, d15, [x0, #0x98]
    ldr x1, [x0, #0x60]
    mov sp, x1
    ldp x19, x20, [x0, #0x00]
    ldp x21, x22, [x0, #0x10]
    ldp x23, x24, [x0, #0x20]
    ldp x25, x26, [x0, #0x30]
    ldp x27, x28, [x0, #0x40]
    ldp x29, x30, [x0, #0x50]
    mov x0, #1
    ret
.size __helios_aarch64_resume_bsp_state, . - __helios_aarch64_resume_bsp_state
