# Hibernate restore trampoline for x86-64.
#
# Entered from the boot kernel with interrupts masked and `rdi` pointing to a
# `X86RestoreParams` block placed on the dedicated non-colliding trampoline
# page (`trampoline_phys + direct_map_offset`).
#
# Field offsets in `X86RestoreParams` (pinned by compile-time assertions in
# `x86/src/hibernate.rs`):
#   0x00: trampoline_cr3     (physical address of safe 4-level page table)
#   0x08: copy_table_virt    (HHDM virtual address of `DisplacedFrameCopy` array)
#   0x10: copy_count         (number of 4 KiB displaced frame copies)
#   0x18: direct_map_offset  (HHDM base offset)
#   0x20: stack_top_virt     (private stack top on the safe trampoline page)
#   0x28: handoff_phys       (physical address of `ResumeHandoffWire` on trampoline page)
#   0x30: ctx_virt           (HHDM virtual address of `X86_64SnapshotContext`)
#
# Field offsets in `X86_64SnapshotContext` (pinned in `x86/src/lib.rs`):
#   0x00: rbx     0x08: rbp     0x10: r12     0x18: r13
#   0x20: r14     0x28: r15     0x30: rsp     0x38: rip
#   0x40: rflags  0x48: cr3     0x50: cr0     0x58: cr4
#   0x60: efer    0x68: fs_base 0x70: gs_base
#   0x78: mxcsr (u32)           0x7c: fcw (u16)
.section .text.helios_x86_restore, "ax"
.balign 4096

.global helios_x86_restore_trampoline
helios_x86_restore_trampoline:
    cli
    mov rbx, rdi
    # Switch to private stack on the safe trampoline page.
    mov rsp, qword ptr [rbx + 0x20]
    # Activate the safe trampoline page table. `V_enter` maps to
    # `trampoline_enter_copy_phys` (an exact byte-for-byte copy of this page),
    # so the copy loop can overwrite Boot 2's `.text` without faulting.
    mov rax, qword ptr [rbx + 0x00]
    mov cr3, rax

    # Linear copy of all displaced 4 KiB pages (every src_phys is disjoint from
    # every dst_phys, the trampoline pages, the copy table, and trampoline_cr3).
    mov r8,  qword ptr [rbx + 0x08]
    mov r9,  qword ptr [rbx + 0x10]
    mov r10, qword ptr [rbx + 0x18]
    cld
.Lhelios_x86_restore_copy_loop:
    test r9, r9
    jz .Lhelios_x86_restore_copy_done
    mov rsi, qword ptr [r8 + 0x00]
    add rsi, r10
    mov rdi, qword ptr [r8 + 0x08]
    add rdi, r10
    mov rcx, 512
    rep movsq
    add r8, 16
    dec r9
    jmp .Lhelios_x86_restore_copy_loop
.Lhelios_x86_restore_copy_done:
    # Transition to `V_finish`, which is mapped to Boot 1's `image_finish_phys`
    # in BOTH `trampoline_cr3` and Boot 1's saved `ctx.cr3`.
    jmp helios_x86_restore_finish
.global helios_x86_restore_trampoline_enter_end
helios_x86_restore_trampoline_enter_end:

.balign 4096
.global helios_x86_restore_finish
helios_x86_restore_finish:
    # Load pointer to saved X86_64SnapshotContext on the safe trampoline page.
    mov r11, qword ptr [rbx + 0x30]

    # Restore IA32_FS_BASE (0xc000_0100) and IA32_GS_BASE (0xc000_0101).
    mov ecx, 0xc0000100
    mov eax, dword ptr [r11 + 0x68]
    mov edx, dword ptr [r11 + 0x6c]
    wrmsr
    mov ecx, 0xc0000101
    mov eax, dword ptr [r11 + 0x70]
    mov edx, dword ptr [r11 + 0x74]
    wrmsr

    # Restore saved CR0, CR4, and switch to the image kernel's CR3.
    # `V_finish` maps to Boot 1's `image_finish_phys` in both `trampoline_cr3`
    # and `ctx.cr3`.
    mov rax, qword ptr [r11 + 0x50]
    mov cr0, rax
    mov rax, qword ptr [r11 + 0x58]
    mov cr4, rax
    mov rax, qword ptr [r11 + 0x48]
    mov cr3, rax

    # Restore MXCSR and x87 control word.
    ldmxcsr dword ptr [r11 + 0x78]
    fldcw word ptr [r11 + 0x7c]

    # Return value pair: rax = 1 (`SnapshotPoint::Resumed`), rdx = handoff_phys.
    mov rdx, qword ptr [rbx + 0x28]

    # Restore saved RSP and non-IF RFLAGS (keep IF=0 until
    # `restore_bsp_post_resume_state` re-programs APIC, IDT, and wake-only CR8).
    mov rsp, qword ptr [r11 + 0x30]
    mov rax, qword ptr [r11 + 0x40]
    and rax, -513
    push rax
    popfq

    # Restore callee-saved GPRs and jump back to the snapshot call site.
    mov rbx, qword ptr [r11 + 0x00]
    mov rbp, qword ptr [r11 + 0x08]
    mov r12, qword ptr [r11 + 0x10]
    mov r13, qword ptr [r11 + 0x18]
    mov r14, qword ptr [r11 + 0x20]
    mov r15, qword ptr [r11 + 0x28]
    mov eax, 1
    jmp qword ptr [r11 + 0x38]
.global helios_x86_restore_finish_end
helios_x86_restore_finish_end:
