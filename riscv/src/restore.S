// Hibernate restore trampoline for RISC-V 64-bit (Sv48 higher-half kernel).
//
// Entered from the boot kernel with supervisor interrupts disabled and `a0`
// pointing to a `RiscvRestoreParams` block placed on the dedicated
// non-colliding trampoline page (mapped in Boot 2's HHDM).
//
// Field offsets in `RiscvRestoreParams` (pinned by compile-time assertions
// in `riscv/src/hibernate.rs`):
//   0x00: trampoline_satp
//   0x08: copy_table_virt
//   0x10: copy_count
//   0x18: direct_map_offset
//   0x20: stack_top_virt
//   0x28: handoff_phys
//   0x30: ctx_virt
//
// Field offsets in `Riscv64SnapshotContext` (pinned in `riscv/src/hibernate.rs`):
//   0x00: ra        0x08: sp        0x10: gp        0x18: tp
//   0x20..0x80: s0..s11
//   0x80..0xe0: fs0..fs11
//   0xe0: fcsr
//   0xe8: sscratch
//   0xf0: sie
//   0xf8: satp
//   0x100: stvec
//   0x108: sstatus
.option push
.option arch, +f, +d

.section .text.helios_riscv_restore, "ax"
.balign 4096
.global __helios_riscv_restore_trampoline
__helios_riscv_restore_trampoline:
    // Ensure supervisor interrupts are masked and `sie` is cleared while
    // physical memory is rewritten.
    csrci sstatus, 0x2
    csrw sie, zero

    mv t6, a0
    // Switch to the private stack on the safe trampoline page.
    ld sp, 0x20(t6)

    // Switch `satp` to the self-contained Sv48 trampoline table on safe
    // frames mapping HHDM, `V_enter -> enter_copy_phys`, and
    // `V_finish -> image_finish_phys`.
    ld t0, 0x00(t6)
    csrw satp, t0
    sfence.vma zero, zero

    // Linear copy loop over `DisplacedFrameCopy` entries (16 bytes each).
    // Every `src_phys` is disjoint from every `dst_phys` and from the
    // trampoline/table pages, so a forward pass is cycle-free.
    ld t1, 0x08(t6)         // copy_table_virt
    ld t2, 0x10(t6)         // copy_count
    ld a3, 0x18(t6)         // direct_map_offset
.Lhelios_riscv_copy_loop:
    beqz t2, .Lhelios_riscv_copy_done
    ld t3, 0(t1)            // src_phys
    ld t4, 8(t1)            // dst_phys
    add t3, t3, a3          // src_virt
    add t4, t4, a3          // dst_virt
    addi t1, t1, 16
    li t5, 512              // 512 * 8 = 4096 bytes
.Lhelios_riscv_page_loop:
    ld a2, 0(t3)
    sd a2, 0(t4)
    addi t3, t3, 8
    addi t4, t4, 8
    addi t5, t5, -1
    bnez t5, .Lhelios_riscv_page_loop
    addi t2, t2, -1
    j .Lhelios_riscv_copy_loop
.Lhelios_riscv_copy_done:
    // Order all memory writes and flush the instruction stream.
    fence rw, rw
    fence.i
    j __helios_riscv_restore_finish
.global __helios_riscv_restore_trampoline_enter_end
__helios_riscv_restore_trampoline_enter_end:

.balign 4096
.global __helios_riscv_restore_finish
__helios_riscv_restore_finish:
    // Read saved context and handoff physical address while the trampoline
    // HHDM mapping is still active, so Boot 1 and Boot 2 may use distinct
    // HHDM offsets.
    ld t0, 0x30(t6)         // ctx_virt
    ld a1, 0x28(t6)         // handoff_phys

    // Restore supervisor trap/interrupt CSRs while keeping `sstatus.SIE` clear
    // (the caller entered `capture_bsp_state` under `LocalInterruptsMasked`).
    ld t1, 0x100(t0)        // stvec
    csrw stvec, t1
    ld t1, 0xe8(t0)         // sscratch
    csrw sscratch, t1
    ld t1, 0xf0(t0)         // sie
    csrw sie, t1

    // Ensure floating-point state is enabled (`sstatus.FS = Initial`) before
    // restoring `fcsr` and `fs0..fs11`.
    li t1, 0x2000
    csrs sstatus, t1
    ld t1, 0xe0(t0)
    fscsr t1
    fld fs0,  0x80(t0)
    fld fs1,  0x88(t0)
    fld fs2,  0x90(t0)
    fld fs3,  0x98(t0)
    fld fs4,  0xa0(t0)
    fld fs5,  0xa8(t0)
    fld fs6,  0xb0(t0)
    fld fs7,  0xb8(t0)
    fld fs8,  0xc0(t0)
    fld fs9,  0xc8(t0)
    fld fs10, 0xd0(t0)
    fld fs11, 0xd8(t0)

    // Restore callee-saved GPRs, global/thread pointers, stack pointer, and RA.
    ld s0,  0x20(t0)
    ld s1,  0x28(t0)
    ld s2,  0x30(t0)
    ld s3,  0x38(t0)
    ld s4,  0x40(t0)
    ld s5,  0x48(t0)
    ld s6,  0x50(t0)
    ld s7,  0x58(t0)
    ld s8,  0x60(t0)
    ld s9,  0x68(t0)
    ld s10, 0x70(t0)
    ld s11, 0x78(t0)
    ld gp,  0x10(t0)
    ld tp,  0x18(t0)
    ld sp,  0x08(t0)
    ld ra,  0x00(t0)

    // Switch to the image kernel's `satp` and flush the TLB. Both tables map
    // `__helios_riscv_restore_finish` at the same virtual page pointing to
    // `image_finish_phys`.
    ld t1, 0xf8(t0)         // satp
    csrw satp, t1
    sfence.vma zero, zero

    // Return (a0 = 1 (`SnapshotPoint::Resumed`), a1 = handoff_phys) directly
    // into `RiscvCpu::capture_bsp_state`.
    li a0, 1
    ret
.global __helios_riscv_restore_finish_end
__helios_riscv_restore_finish_end:

.option pop
