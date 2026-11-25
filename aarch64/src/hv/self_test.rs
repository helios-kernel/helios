//! Hardware checks compiled only into the explicitly requested test image.

use super::{Registers, Space, Vcpu};
use core::alloc::Layout;
use core::arch::asm;
use core::ptr::NonNull;
use core::time::Duration;
use helios_hal::cpu::{Cpu, ProcessorId, current_processor};
use helios_hal::hv::{
    GuestAddress, GuestRange, GuestVcpu, HvError, Hypervisor, IoAccess, IoWidth, IrqLevel,
    Stage2Space, VirtualIrq, VmExit,
};
use helios_hal::pmm::PhysFrame;
use helios_hal::vmm::PageFlags;
use helios_kernel::{
    ProcessorControl, ProcessorLifecycle, allocate_user_run_zeroed_on, deallocate_user_run_on,
};
use triomphe::Arc;

struct TestPage {
    address: usize,
    owner: ProcessorId,
    layout: Layout,
}
impl Drop for TestPage {
    fn drop(&mut self) {
        deallocate_user_run_on(
            self.owner,
            NonNull::new(core::ptr::with_exposed_provenance_mut(self.address)).unwrap(),
            self.layout,
        );
    }
}

pub(crate) struct Remote {
    request: helios_kernel::Mutex<Option<Vcpu>>,
    reply: helios_kernel::Mutex<Option<(Vcpu, VmExit)>>,
    requested: helios_kernel::Notify,
    replied: helios_kernel::Notify,
}
impl Remote {
    pub(crate) fn new() -> Self {
        Self {
            request: helios_kernel::Mutex::new(None),
            reply: helios_kernel::Mutex::new(None),
            requested: helios_kernel::Notify::new(),
            replied: helios_kernel::Notify::new(),
        }
    }
    async fn enter(&self, vcpu: Vcpu) -> (Vcpu, VmExit) {
        let reply = self.replied.notified();
        assert!(self.request.lock().await.replace(vcpu).is_none());
        self.requested.notify_one();
        reply.await;
        self.reply.lock().await.take().unwrap()
    }
    pub(crate) async fn serve(&self) {
        loop {
            self.requested.notified().await;
            let mut vcpu = self.request.lock().await.take().unwrap();
            let exit = loop {
                vcpu.prepare_run(current_processor(), None, Duration::from_millis(1))
                    .unwrap();
                match vcpu.run().unwrap() {
                    VmExit::Preempted => helios_kernel::yield_now().await,
                    exit => break exit,
                }
            };
            assert!(self.reply.lock().await.replace((vcpu, exit)).is_none());
            self.replied.notify_all();
        }
    }
}

pub(crate) async fn run(cpu: crate::Aarch64Cpu, control: ProcessorControl<crate::Aarch64Cpu>) {
    let owner = current_processor();
    let layout = Layout::from_size_align(PhysFrame::SIZE, PhysFrame::SIZE).unwrap();
    let page = TestPage {
        address: allocate_user_run_zeroed_on(owner, layout)
            .unwrap()
            .as_ptr()
            .expose_provenance(),
        owner,
        layout,
    };
    let address = page.address;
    // A64: infinite branch, WFI, STR X0,[X1], HVC #0,
    // MRS X0,ICC_IAR1_EL1, MSR ICC_EOIR1_EL1,X0, HVC #0.
    let instructions = [
        0x1400_0000u32,
        0xd503_207f,
        0xf900_0020,
        0xd400_0002,
        0xd538_cc00,
        0xd518_cc20,
        0xd400_0002,
    ];
    let code_ptr = core::ptr::with_exposed_provenance_mut::<u32>(address);
    // SAFETY: `address` came from `allocate_user_run_zeroed_on` with a full
    // 4 KiB frame (`instructions.len() * 4 <= PhysFrame::SIZE`) and 4 KiB
    // alignment, and `page` uniquely owns it here.
    let code = unsafe { core::slice::from_raw_parts_mut(code_ptr, instructions.len()) };
    code.copy_from_slice(&instructions);
    let hv = cpu.hv().expect("HV self-test requires EL2 VHE");
    // SAFETY: `address` points to the exclusively owned test frame above,
    // which is mapped in the kernel direct map.
    unsafe {
        hv.synchronize_memory(&[PhysFrame::from_phys_addr(address)]);
    }
    let space = Arc::new(hv.create_space().unwrap());
    let range = GuestRange::new(GuestAddress(0x4000_0000), PhysFrame::SIZE).unwrap();
    // SAFETY: the empty slice fails range validation before mapping any frame.
    let empty_map = unsafe { space.map_pages(range, &[], PageFlags::READ) };
    assert_eq!(empty_map, Err(HvError::InvalidRange));
    assert!(!space.tables.contains(range.start()));
    // SAFETY: `page` uniquely owns the frame at `address` and outlives
    // `space` (dropped before `page` at the end of `run`).
    unsafe {
        space
            .map_pages(
                range,
                &[PhysFrame::from_phys_addr(address)],
                PageFlags::READ | PageFlags::EXECUTE,
            )
            .unwrap();
    }
    let mut vcpu = Space::create_vcpu(&space, 0).unwrap();
    for level in [IrqLevel::Assert, IrqLevel::Deassert] {
        assert!(vcpu.inject_irq(VirtualIrq { number: 32, level }).unwrap());
    }
    helios_hal::critical_section::with_local_interrupts_masked(|| {
        vcpu.vgic.install();
        let maintenance: u64;
        // SAFETY: reading `ich_misr_el2` at EL2 with interrupts masked has no
        // side effects and touches no memory.
        unsafe {
            asm!("mrs {maintenance}, ich_misr_el2", maintenance = out(reg) maintenance,
                options(nomem, nostack));
        }
        vcpu.vgic.detach();
        assert_eq!(
            maintenance & 1,
            0,
            "deasserted IRQ retained EOI maintenance"
        );
    });
    tracing::info!("HV self-test: deasserted IRQ retired without maintenance");
    let mut registers = Registers {
        pc: range.start().0,
        ..Registers::default()
    };
    vcpu.set_regs(&registers).unwrap();
    let slice = Duration::from_millis(1);
    vcpu.prepare_run(current_processor(), None, slice).unwrap();
    assert_eq!(vcpu.run().unwrap(), VmExit::Preempted);
    tracing::info!("HV self-test: infinite guest preempted");
    registers.pc += 4;
    vcpu.set_regs(&registers).unwrap();
    loop {
        vcpu.prepare_run(current_processor(), None, slice).unwrap();
        match vcpu.run().unwrap() {
            VmExit::Preempted => helios_kernel::yield_now().await,
            VmExit::Halt => break,
            exit => panic!("HV self-test expected Halt, got {exit:?}"),
        }
    }
    tracing::info!("HV self-test: WFI halted");
    registers.pc += 4;
    registers.x[0] = 0x1234;
    registers.x[1] = 0x9000_0000;
    vcpu.set_regs(&registers).unwrap();
    loop {
        vcpu.prepare_run(current_processor(), None, slice).unwrap();
        match vcpu.run().unwrap() {
            VmExit::Preempted => helios_kernel::yield_now().await,
            exit => {
                assert_eq!(
                    exit,
                    VmExit::Mmio {
                        address: GuestAddress(0x9000_0000),
                        access: IoAccess::Write {
                            width: IoWidth::Qword,
                            value: 0x1234
                        }
                    }
                );
                break;
            }
        }
    }
    vcpu.complete_exit(0).unwrap();
    assert_eq!(vcpu.get_regs().unwrap().pc, range.start().0 + 12);
    tracing::info!("HV self-test: MMIO completed once");
    registers.pc = range.start().0 + 16;
    vcpu.set_regs(&registers).unwrap();
    assert!(
        vcpu.inject_irq(VirtualIrq {
            number: 32,
            level: IrqLevel::Pulse
        })
        .unwrap()
    );
    loop {
        vcpu.prepare_run(current_processor(), None, slice).unwrap();
        match vcpu.run().unwrap() {
            VmExit::Preempted => helios_kernel::yield_now().await,
            exit => {
                assert_eq!(exit, VmExit::Hypercall { number: 32 });
                break;
            }
        }
    }
    tracing::info!("HV self-test: virtual IRQ acknowledged by guest");
    // Program the detached guest virtual timer, then execute WFI. Its
    // hardware bank is disabled while the host awaits the saved deadline.
    let counter: u64;
    // SAFETY: reading the architected physical counter `cntpct_el0` touches
    // no memory and has no side effects.
    unsafe {
        asm!("mrs {counter}, cntpct_el0", counter = out(reg) counter, options(nomem, nostack));
    }
    vcpu.context.system.cntv_cval =
        counter + cpu.timebase().duration_to_ticks(Duration::from_millis(100));
    vcpu.context.system.cntv_ctl = 1;
    registers.pc = range.start().0 + 4;
    vcpu.set_regs(&registers).unwrap();
    loop {
        vcpu.prepare_run(current_processor(), None, slice).unwrap();
        match vcpu.run().unwrap() {
            VmExit::Preempted => helios_kernel::yield_now().await,
            exit => {
                assert_eq!(exit, VmExit::Halt);
                break;
            }
        }
    }
    tracing::info!("HV self-test: waiting for detached guest timer");
    vcpu.wait_for_interrupt().await.unwrap();
    tracing::info!("HV self-test: detached guest timer deadline reached");
    registers.pc = range.start().0 + 16;
    vcpu.set_regs(&registers).unwrap();
    loop {
        vcpu.prepare_run(current_processor(), None, slice).unwrap();
        match vcpu.run().unwrap() {
            VmExit::Preempted => helios_kernel::yield_now().await,
            exit => {
                assert_eq!(exit, VmExit::Hypercall { number: 27 });
                break;
            }
        }
    }
    vcpu.context.system.cntv_ctl = 0;
    tracing::info!("HV self-test: detached virtual timer woke and injected IRQ");
    assert!(
        cpu.processor_count() >= 2,
        "HV SMP self-test requires two processors"
    );
    registers.pc = range.start().0 + 12;
    registers.x[0] = 42;
    vcpu.set_regs(&registers).unwrap();
    let (returned, exit) = cpu.state.hv_test.enter(vcpu).await;
    vcpu = returned;
    assert_eq!(exit, VmExit::Hypercall { number: 42 });
    space.protect_pages(range, PageFlags::READ).await.unwrap();
    registers.pc = range.start().0;
    vcpu.set_regs(&registers).unwrap();
    let (returned, exit) = cpu.state.hv_test.enter(vcpu).await;
    vcpu = returned;
    assert_eq!(
        exit,
        VmExit::Stage2Fault {
            address: range.start(),
            access: PageFlags::EXECUTE
        }
    );
    tracing::info!("HV self-test: remote permission revocation acknowledged");
    space
        .protect_pages(range, PageFlags::READ | PageFlags::EXECUTE)
        .await
        .unwrap();
    registers.pc = range.start().0 + 12;
    vcpu.set_regs(&registers).unwrap();
    let (returned, exit) = cpu.state.hv_test.enter(vcpu).await;
    vcpu = returned;
    assert_eq!(exit, VmExit::Hypercall { number: 42 });
    space.unmap_pages(range).await.unwrap();
    registers.pc = range.start().0;
    vcpu.set_regs(&registers).unwrap();
    let (returned, exit) = cpu.state.hv_test.enter(vcpu).await;
    vcpu = returned;
    assert_eq!(
        exit,
        VmExit::Stage2Fault {
            address: range.start(),
            access: PageFlags::EXECUTE
        }
    );
    tracing::info!("HV self-test: revoked mapping faults");
    drop(vcpu);
    drop(space);
    drop(page);
    let resumed = ProcessorId::new(2);
    assert!(
        control.is_online(resumed),
        "HV lifecycle test requires three online processors"
    );
    control.offline(resumed).await.unwrap();
    assert!(!control.is_online(resumed));
    control.online(resumed).await.unwrap();
    assert!(control.is_online(resumed));
    tracing::info!("HV self-test: EL2 processor offline/online completed");
    tracing::info!("HV self-test: complete");
}
