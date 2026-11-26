// BSP double-return snapshot point for RISC-V 64-bit.
//
// Field offsets match `helios_hal::cpu::Riscv64SnapshotContext`, pinned by
// compile-time assertions in `riscv/src/lib.rs`:
//   0x00: ra        0x08: sp        0x10: gp        0x18: tp
//   0x20..0x80: s0..s11
//   0x80..0xe0: fs0..fs11
//   0xe0: fcsr
.option push
.option arch, +f, +d

.section .text.helios_riscv_snapshot, "ax"
.global __helios_riscv_capture_bsp_state
.balign 4
// extern "C" fn __helios_riscv_capture_bsp_state(ctx: *mut Riscv64SnapshotContext) -> u64
//
// Saves ra, sp, gp, tp, s0-s11, fs0-fs11, and fcsr into `ctx` and returns 0
// (`SnapshotPoint::Captured`). `__helios_riscv_resume_bsp_state` restores the
// context and returns 1 (`SnapshotPoint::Resumed`) to the caller.
__helios_riscv_capture_bsp_state:
    sd ra,  0x00(a0)
    sd sp,  0x08(a0)
    sd gp,  0x10(a0)
    sd tp,  0x18(a0)
    sd s0,  0x20(a0)
    sd s1,  0x28(a0)
    sd s2,  0x30(a0)
    sd s3,  0x38(a0)
    sd s4,  0x40(a0)
    sd s5,  0x48(a0)
    sd s6,  0x50(a0)
    sd s7,  0x58(a0)
    sd s8,  0x60(a0)
    sd s9,  0x68(a0)
    sd s10, 0x70(a0)
    sd s11, 0x78(a0)
    fsd fs0,  0x80(a0)
    fsd fs1,  0x88(a0)
    fsd fs2,  0x90(a0)
    fsd fs3,  0x98(a0)
    fsd fs4,  0xa0(a0)
    fsd fs5,  0xa8(a0)
    fsd fs6,  0xb0(a0)
    fsd fs7,  0xb8(a0)
    fsd fs8,  0xc0(a0)
    fsd fs9,  0xc8(a0)
    fsd fs10, 0xd0(a0)
    fsd fs11, 0xd8(a0)
    frcsr t0
    sd t0, 0xe0(a0)
    li a0, 0
    li a1, 0
    ret

.global __helios_riscv_resume_bsp_state
.balign 4
// extern "C" fn __helios_riscv_resume_bsp_state(ctx: *const Riscv64SnapshotContext) -> !
__helios_riscv_resume_bsp_state:
    ld t0, 0xe0(a0)
    fscsr t0
    fld fs0,  0x80(a0)
    fld fs1,  0x88(a0)
    fld fs2,  0x90(a0)
    fld fs3,  0x98(a0)
    fld fs4,  0xa0(a0)
    fld fs5,  0xa8(a0)
    fld fs6,  0xb0(a0)
    fld fs7,  0xb8(a0)
    fld fs8,  0xc0(a0)
    fld fs9,  0xc8(a0)
    fld fs10, 0xd0(a0)
    fld fs11, 0xd8(a0)
    ld s0,  0x20(a0)
    ld s1,  0x28(a0)
    ld s2,  0x30(a0)
    ld s3,  0x38(a0)
    ld s4,  0x40(a0)
    ld s5,  0x48(a0)
    ld s6,  0x50(a0)
    ld s7,  0x58(a0)
    ld s8,  0x60(a0)
    ld s9,  0x68(a0)
    ld s10, 0x70(a0)
    ld s11, 0x78(a0)
    ld gp,  0x10(a0)
    ld tp,  0x18(a0)
    ld sp,  0x08(a0)
    ld ra,  0x00(a0)
    li a0, 1
    ret

.option pop
