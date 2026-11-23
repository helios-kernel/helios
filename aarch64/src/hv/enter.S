// SP_EL2 retains the host frame throughout guest execution. Lower-EL
// vectors never use SP_EL0, which belongs to the guest until restored here.
.section .text.hv, "ax"
.arch armv8.5-a
.balign 2048
__helios_aarch64_guest_vectors:
    .rept 8
        b __helios_aarch64_guest_host_fault
        .balign 128
    .endr
    b __helios_aarch64_guest_sync
    .balign 128
    b __helios_aarch64_guest_irq
    .balign 128
    b __helios_aarch64_guest_fiq
    .balign 128
    b __helios_aarch64_guest_serror
    .balign 128
    .rept 4
        b __helios_aarch64_guest_host_fault
        .balign 128
    .endr

.macro save_vectors base
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
        str q\n, [\base, #({vectors} + 16 * \n)]
    .endr
    mrs x10, fpcr
    str x10, [\base, #{fpcr}]
    mrs x10, fpsr
    str x10, [\base, #{fpsr}]
.endm

.macro load_vectors base
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
        ldr q\n, [\base, #({vectors} + 16 * \n)]
    .endr
    ldr x10, [\base, #{fpcr}]
    msr fpcr, x10
    ldr x10, [\base, #{fpsr}]
    msr fpsr, x10
.endm

.global helios_aarch64_enter_guest
.type helios_aarch64_enter_guest, %function
helios_aarch64_enter_guest:
    sub sp, sp, #{frame_bytes}
    str x0, [sp, #{context_bytes}]
    stp x19, x20, [sp, #152]
    stp x21, x22, [sp, #168]
    stp x23, x24, [sp, #184]
    stp x25, x26, [sp, #200]
    stp x27, x28, [sp, #216]
    stp x29, x30, [sp, #232]
    mrs x10, hcr_el2
    str x10, [sp, #{hcr}]
    save_system sp
    save_vectors sp
    mrs x10, vbar_el2
    str x10, [sp, #{host_vbar}]
    adr x10, __helios_aarch64_guest_vectors
    msr vbar_el2, x10
    isb

    load_system x0
    load_vectors x0
    ldr x10, [x0, #{pc}]
    msr elr_el2, x10
    ldr x10, [x0, #{pstate}]
    msr spsr_el2, x10
    ldr x10, [x0, #{sp}]
    msr sp_el1, x10
    ldr x10, [x0, #{hcr}]
    msr hcr_el2, x10
    isb
    mov x30, x0
    ldp x2, x3, [x30, #16]
    ldp x4, x5, [x30, #32]
    ldp x6, x7, [x30, #48]
    ldp x8, x9, [x30, #64]
    ldp x10, x11, [x30, #80]
    ldp x12, x13, [x30, #96]
    ldp x14, x15, [x30, #112]
    ldp x16, x17, [x30, #128]
    ldp x18, x19, [x30, #144]
    ldp x20, x21, [x30, #160]
    ldp x22, x23, [x30, #176]
    ldp x24, x25, [x30, #192]
    ldp x26, x27, [x30, #208]
    ldp x28, x29, [x30, #224]

    // Start the execution slice only after the expensive state switch.
    // X0/X1 remain scratch until the final two loads; X30 owns the context.
    mrs x0, cntpct_el0
    ldr x1, [x30, #{slice_ticks}]
    adds x0, x0, x1
    csinv x0, x0, xzr, cc // Saturate now + ticks on unsigned overflow.
    ldr x1, [x30, #{timer_deadline}]
    cbz x1, .Lguest_timer_selected
    cmp x0, x1
    csel x0, x0, x1, ls
.Lguest_timer_selected:
    msr cnthp_cval_el2, x0
    mov x0, #1
    msr cnthp_ctl_el2, x0
    isb
    ldp x0, x1, [x30, #0]
    ldr x30, [x30, #240]
    eret
.size helios_aarch64_enter_guest, . - helios_aarch64_enter_guest

.macro guest_exit name, kind
    .global \name
    .type \name, %function
\name:
    stp x0, x1, [sp, #-16]!
    mov x0, #\kind
    b __helios_aarch64_guest_exit
    .size \name, . - \name
.endm
guest_exit __helios_aarch64_guest_sync, 0
guest_exit __helios_aarch64_guest_irq, 1
guest_exit __helios_aarch64_guest_fiq, 2
guest_exit __helios_aarch64_guest_serror, 3
guest_exit __helios_aarch64_guest_host_fault, 4

__helios_aarch64_guest_exit:
    ldr x1, [sp, #({context_bytes} + 16)]
    str x0, [x1, #{exit_kind}]
    ldr x0, [sp, #0]
    str x0, [x1, #0]
    ldr x0, [sp, #8]
    str x0, [x1, #8]
    add sp, sp, #16
    stp x2, x3, [x1, #16]
    stp x4, x5, [x1, #32]
    stp x6, x7, [x1, #48]
    stp x8, x9, [x1, #64]
    stp x10, x11, [x1, #80]
    stp x12, x13, [x1, #96]
    stp x14, x15, [x1, #112]
    stp x16, x17, [x1, #128]
    stp x18, x19, [x1, #144]
    stp x20, x21, [x1, #160]
    stp x22, x23, [x1, #176]
    stp x24, x25, [x1, #192]
    stp x26, x27, [x1, #208]
    stp x28, x29, [x1, #224]
    str x30, [x1, #240]
    mrs x10, elr_el2
    str x10, [x1, #{pc}]
    mrs x10, spsr_el2
    str x10, [x1, #{pstate}]
    mrs x10, sp_el1
    str x10, [x1, #{sp}]
    mrs x10, esr_el2
    str x10, [x1, #{esr}]
    mrs x10, far_el2
    str x10, [x1, #{far}]
    mrs x10, hpfar_el2
    str x10, [x1, #{hpfar}]
    save_system x1
    save_vectors x1

    // Arm ARM R_FKLWR: a final-access Stage-2 permission fault does
    // not define HPFAR. Translate FAR while the guest EL1 bank and
    // HCR.TGE=0 are still installed. PAR was saved above.
    ldr x10, [x1, #{esr}]
    ubfx x11, x10, #26, #6
    cmp x11, #0x20
    b.eq 80f
    cmp x11, #0x24
    b.ne 83f
80:
    and x11, x10, #0x3c
    cmp x11, #0x0c
    b.ne 83f
    tbnz x10, #7, 83f
    ldr x11, [x1, #{far}]
    at s1e1r, x11
    isb
    mrs x11, par_el1
    tbnz x11, #0, 82f
    ubfx x11, x11, #12, #36
    lsl x11, x11, #4
    str x11, [x1, #{hpfar}]
    b 83f
82:
    // A concurrent Stage-1 update invalidated the translation. Return
    // detached and retry the original guest instruction on its next slice.
    mov x11, #5
    str x11, [x1, #{exit_kind}]
83:

    ldr x10, [sp, #{hcr}]
    msr hcr_el2, x10
    isb
    load_system sp
    load_vectors sp
    ldr x10, [sp, #{host_vbar}]
    msr vbar_el2, x10
    isb
    ldp x19, x20, [sp, #152]
    ldp x21, x22, [sp, #168]
    ldp x23, x24, [sp, #184]
    ldp x25, x26, [sp, #200]
    ldp x27, x28, [sp, #216]
    ldp x29, x30, [sp, #232]
    add sp, sp, #{frame_bytes}
    ret
