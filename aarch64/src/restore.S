// Hibernate restore trampoline for AArch64.
//
// Entered from the boot kernel with interrupts masked and `x0` pointing to an
// `Aarch64RestoreParams` block placed on the dedicated non-colliding
// trampoline page (`trampoline_phys + direct_map_offset`).
//
// Field offsets in `Aarch64RestoreParams` (pinned by compile-time assertions
// in `aarch64/src/hibernate.rs`):
//   0x00: trampoline_ttbr1
//   0x08: copy_table_virt
//   0x10: copy_count
//   0x18: direct_map_offset
//   0x20: stack_top_virt
//   0x28: handoff_phys
//   0x30: ctx_virt
//
// Field offsets in `Aarch64SnapshotContext` (pinned in `aarch64/src/hibernate.rs`):
//   0x00..0x60: x19..x30
//   0x60:       sp
//   0x68..0xa8: d8..d15
//   0xa8:       fpcr
//   0xb0:       tpidr_el1
//   0xb8:       sp_el0
//   0xc0:       ttbr0_el1
//   0xc8:       ttbr1_el1
//   0xd0:       mair_el1
//   0xd8:       tcr_el1
//   0xe0:       sctlr_el1
//   0xe8:       vbar_el1
//   0xf0:       cpacr_el1
//   0xf8:       daif
//   0x100:      apia_lo
//   0x108:      apia_hi
//   0x110:      mte_enabled
//   0x118:      gcr_el1
//   0x120:      rgsr_el1
.section .text.helios_aarch64_restore, "ax"
.arch armv8.5-a+memtag
.balign 4096

.global __helios_aarch64_restore_trampoline
.type __helios_aarch64_restore_trampoline, %function
__helios_aarch64_restore_trampoline:
    // BTI c landing pad for indirect/direct call into guarded kernel text.
    hint #34
    msr daifset, #0xf

    mov x19, x0
    // Switch to private stack on the safe trampoline page.
    ldr x1, [x19, #0x20]
    mov sp, x1

    // Switch TTBR1_EL1 to the self-contained safe trampoline page tables.
    // `V_enter` maps to `trampoline_enter_copy_phys` (exact copy of this page),
    // so the copy loop can overwrite Boot 2's `.text` without faulting.
    ldr x1, [x19, #0x00]
    msr ttbr1_el1, x1
    dsb ish
    tlbi vmalle1
    dsb ish
    isb

    // Compute D-cache (x14) and I-cache (x15) minimum line sizes from CTR_EL0.
    mrs x9, ctr_el0
    ubfx x10, x9, #16, #4
    mov x14, #4
    lsl x14, x14, x10
    and x10, x9, #0xf
    mov x15, #4
    lsl x15, x15, x10

    // Linear copy loop over `DisplacedFrameCopy` entries (16 bytes each).
    ldr x8,  [x19, #0x08]       // copy_table_virt
    ldr x9,  [x19, #0x10]       // copy_count
    ldr x10, [x19, #0x18]       // direct_map_offset
.Lhelios_aarch64_copy_loop:
    cbz x9, .Lhelios_aarch64_copy_done
    ldp x11, x12, [x8], #16     // x11 = src_phys, x12 = dst_phys
    add x11, x11, x10           // src_virt
    add x12, x12, x10           // dst_virt
    mov x13, x12                // save dst_virt start for cache maintenance
    mov x16, #256               // 256 * 16 = 4096 bytes
.Lhelios_aarch64_page_loop:
    ldp x2, x3, [x11], #16
    stp x2, x3, [x12], #16
    subs x16, x16, #1
    b.ne .Lhelios_aarch64_page_loop

    // Clean D-cache to Point of Unification across the copied 4 KiB page.
    mov x2, x13
    add x3, x13, #4096
.Lhelios_aarch64_dc_loop:
    dc cvau, x2
    add x2, x2, x14
    cmp x2, x3
    b.lo .Lhelios_aarch64_dc_loop
    dsb ish

    // Invalidate I-cache to Point of Unification across the copied 4 KiB page.
    mov x2, x13
.Lhelios_aarch64_ic_loop:
    ic ivau, x2
    add x2, x2, x15
    cmp x2, x3
    b.lo .Lhelios_aarch64_ic_loop
    dsb ish

    sub x9, x9, #1
    b .Lhelios_aarch64_copy_loop
.Lhelios_aarch64_copy_done:
    // Invalidate the entire instruction cache across all restored & relocated
    // `.text` pages before branching to `V_finish`.
    dsb ish
    ic iallu
    dsb ish
    isb
    b __helios_aarch64_restore_finish
.size __helios_aarch64_restore_trampoline, . - __helios_aarch64_restore_trampoline
.global __helios_aarch64_restore_trampoline_enter_end
__helios_aarch64_restore_trampoline_enter_end:

.balign 4096
.global __helios_aarch64_restore_finish
.type __helios_aarch64_restore_finish, %function
__helios_aarch64_restore_finish:
    // BTI jc landing pad for guarded kernel text.
    hint #38

    // Point x20 at saved Aarch64SnapshotContext on the safe trampoline page.
    ldr x20, [x19, #0x30]

    // Restore PAC instruction key A before restoring SCTLR_EL1 (which may have EnIA set).
    ldr x1, [x20, #0x100]
    msr apiakeylo_el1, x1
    ldr x1, [x20, #0x108]
    msr apiakeyhi_el1, x1

    // Restore MTE tag-generation registers when MTE was enabled in the image.
    ldr x1, [x20, #0x110]
    cbz x1, .Lhelios_aarch64_skip_mte
    ldr x1, [x20, #0x118]
    msr gcr_el1, x1
    ldr x1, [x20, #0x120]
    msr rgsr_el1, x1
    msr tco, #0
.Lhelios_aarch64_skip_mte:
    isb

    // Switch back to the image kernel's translation regime. `V_finish` maps to
    // Boot 1's `image_finish_phys` in both `trampoline_ttbr1` and `ctx.ttbr1_el1`.
    ldr x1, [x20, #0xd0]        // mair_el1
    msr mair_el1, x1
    ldr x1, [x20, #0xd8]        // tcr_el1
    msr tcr_el1, x1
    ldr x1, [x20, #0xc0]        // ttbr0_el1
    msr ttbr0_el1, x1
    ldr x1, [x20, #0xc8]        // ttbr1_el1
    msr ttbr1_el1, x1
    isb
    tlbi vmalle1
    dsb ish
    isb
    ldr x1, [x20, #0xe0]        // sctlr_el1
    msr sctlr_el1, x1
    isb

    // Restore remaining EL1 system registers.
    ldr x1, [x20, #0xf0]        // cpacr_el1
    msr cpacr_el1, x1
    isb
    ldr x1, [x20, #0xe8]        // vbar_el1
    msr vbar_el1, x1
    ldr x1, [x20, #0xb0]        // tpidr_el1
    msr tpidr_el1, x1
    ldr x1, [x20, #0xb8]        // sp_el0
    msr sp_el0, x1
    ldr x1, [x20, #0xa8]        // fpcr
    msr fpcr, x1
    isb

    // Load handoff_phys into x1 before restoring x19..x30.
    ldr x1, [x19, #0x28]

    // Restore FP/SIMD callee-saved registers, stack pointer, and GPRs x19..x30.
    ldp d8, d9, [x20, #0x68]
    ldp d10, d11, [x20, #0x78]
    ldp d12, d13, [x20, #0x88]
    ldp d14, d15, [x20, #0x98]
    ldr x2, [x20, #0x60]
    mov sp, x2
    // Keep x20 in x0 temporarily so we can restore x19 and x20 cleanly last.
    mov x0, x20
    ldp x21, x22, [x0, #0x10]
    ldp x23, x24, [x0, #0x20]
    ldp x25, x26, [x0, #0x30]
    ldp x27, x28, [x0, #0x40]
    ldp x29, x30, [x0, #0x50]
    ldp x19, x20, [x0, #0x00]

    // Return (x0 = 1 (`SnapshotPoint::Resumed`), x1 = handoff_phys) into
    // `Aarch64Cpu::capture_bsp_state`.
    mov x0, #1
    ret
.size __helios_aarch64_restore_finish, . - __helios_aarch64_restore_finish
.global __helios_aarch64_restore_finish_end
__helios_aarch64_restore_finish_end:
