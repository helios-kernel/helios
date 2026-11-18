.section .text.helios_x86_native, "ax"
.global helios_x86_native_enter
helios_x86_native_enter:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [rdi + {kernel_rsp}], rsp
    mov rsi, [rdi + {kernel_xstate}]
    mov eax, -1
    mov edx, -1
    xsave64 [rsi]
    mov rsi, [rdi + {user_xstate}]
    xrstor64 [rsi]
    mov rax, [rdi + {user_cr3}]
    mov cr3, rax
    // User TLS is separate from the kernel's per-processor FS anchor.
    mov ecx, 0xc0000100
    mov rax, [rdi + {user_fs}]
    mov rdx, rax
    shr rdx, 32
    wrmsr
    mov rsp, rdi
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    add rsp, 16
    iretq

.global helios_x86_native_syscall
helios_x86_native_syscall:
    swapgs
    mov gs:[{scratch_rsp}], rsp
    mov rsp, gs:[{entry_stack}]
    push {user_data}
    push qword ptr gs:[{scratch_rsp}]
    push r11
    push {user_code}
    push rcx
    push 0
    push {syscall_vector}
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    jmp helios_x86_native_exit

.global helios_x86_native_trap_exit
helios_x86_native_trap_exit:
    swapgs
    // An exception keeps the user's RFLAGS.AC, which would lift SMAP for
    // the kernel; SYSCALL clears it through FMASK.
    clac
helios_x86_native_exit:
    // Registers already have the same layout as the ordinary exception frame.
    cld
    mov r12, rsp
    mov rsi, rsp
    mov rdi, gs:[{self_pointer}]
    mov ecx, {frame_words}
    rep movsq
    mov rsi, gs:[{user_xstate}]
    mov eax, -1
    mov edx, -1
    xsave64 [rsi]
    mov rax, gs:[{kernel_cr3}]
    mov cr3, rax
    mov rax, gs:[{kernel_fs}]
    mov rdx, rax
    shr rdx, 32
    mov ecx, 0xc0000100
    wrmsr
    // Clear user-controlled flags, including AC and DF, before entering Rust.
    push 2
    popfq
    fninit
    sub rsp, 16
    mov dword ptr [rsp], 0x1f80
    ldmxcsr [rsp]
    // Acknowledge external interrupts on their original per-CPU IST stack.
    mov rax, [r12 + 120]
    cmp rax, 32
    jb 1f
    cmp rax, 255
    ja 1f
    mov rdi, r12
    call helios_x86_native_interrupt
1:
    mov rsi, gs:[{kernel_xstate}]
    mov eax, -1
    mov edx, -1
    xrstor64 [rsi]
    mov rsp, gs:[{kernel_rsp}]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

// The ring-0 load and store of `native::verify_user_isolation`, on the
// user page in RDI. Each faults at its first instruction while SMAP
// holds, and the page-fault dispatcher resumes at the return address the
// caller's `call` pushed.
.global helios_x86_isolation_load
helios_x86_isolation_load:
    mov rax, [rdi]
    ret

.global helios_x86_isolation_store
helios_x86_isolation_store:
    mov [rdi + 8], rdi
    ret
