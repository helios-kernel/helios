# BSP double-return snapshot point for x86-64.
#
# Field offsets match `helios_hal::cpu::X86_64SnapshotContext`, pinned by
# compile-time assertions in `x86/src/lib.rs`:
#   0x00: rbx     0x08: rbp     0x10: r12     0x18: r13
#   0x20: r14     0x28: r15     0x30: rsp     0x38: rip
#   0x40: rflags  0x48: cr3     0x50: cr0     0x58: cr4
#   0x60: efer    0x68: fs_base 0x70: gs_base
#   0x78: mxcsr (u32)           0x7c: fcw (u16)
.section .text.helios_x86_snapshot, "ax"

# extern "C" fn helios_x86_capture_bsp_state(ctx: *mut X86_64SnapshotContext) -> u64
#
# Saves callee-saved GPRs, caller RSP/RIP, RFLAGS, CR3/CR0/CR4, MXCSR, and FCW.
# Returns 0 on initial capture; `helios_x86_resume_bsp_state` jumps back to
# the saved RIP with rax = 1.
.global helios_x86_capture_bsp_state
helios_x86_capture_bsp_state:
    mov qword ptr [rdi + 0x00], rbx
    mov qword ptr [rdi + 0x08], rbp
    mov qword ptr [rdi + 0x10], r12
    mov qword ptr [rdi + 0x18], r13
    mov qword ptr [rdi + 0x20], r14
    mov qword ptr [rdi + 0x28], r15
    # Caller's RSP after our `ret` pops the return address.
    lea rax, [rsp + 8]
    mov qword ptr [rdi + 0x30], rax
    # Caller's return address (RIP).
    mov rax, qword ptr [rsp]
    mov qword ptr [rdi + 0x38], rax
    pushfq
    pop rax
    mov qword ptr [rdi + 0x40], rax
    mov rax, cr3
    mov qword ptr [rdi + 0x48], rax
    mov rax, cr0
    mov qword ptr [rdi + 0x50], rax
    mov rax, cr4
    mov qword ptr [rdi + 0x58], rax
    stmxcsr dword ptr [rdi + 0x78]
    fnstcw word ptr [rdi + 0x7c]
    xor eax, eax
    xor edx, edx
    ret

# extern "C" fn helios_x86_resume_bsp_state(ctx: *const X86_64SnapshotContext) -> !
#
# Restores architectural state saved by `helios_x86_capture_bsp_state` and
# returns 1 (`SnapshotPoint::Resumed`) to its caller.
.global helios_x86_resume_bsp_state
helios_x86_resume_bsp_state:
    mov rax, qword ptr [rdi + 0x48]
    mov cr3, rax
    ldmxcsr dword ptr [rdi + 0x78]
    fldcw word ptr [rdi + 0x7c]
    mov rbx, qword ptr [rdi + 0x00]
    mov rbp, qword ptr [rdi + 0x08]
    mov r12, qword ptr [rdi + 0x10]
    mov r13, qword ptr [rdi + 0x18]
    mov r14, qword ptr [rdi + 0x20]
    mov r15, qword ptr [rdi + 0x28]
    mov rsp, qword ptr [rdi + 0x30]
    push qword ptr [rdi + 0x40]
    popfq
    mov eax, 1
    jmp qword ptr [rdi + 0x38]
