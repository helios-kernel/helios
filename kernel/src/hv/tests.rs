use super::*;
use crate::exec::Notify;
use crate::test_support::single_node_pool;
use alloc::collections::VecDeque;
use alloc::vec;
use core::future::Future;
use core::num::NonZeroU8;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use futures_lite::future::block_on;
use helios_hal::cpu::ProcessorId;
use helios_hal::hv::{HvCapabilities, IrqLevel, VcpuKick, VirtualIrq, VmExit};
use helios_hal::pmm::PhysFrame;

fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
fn range(pages: usize) -> GuestRange {
    GuestRange::new(helios_hal::hv::GuestAddress(0), pages * PhysFrame::SIZE).unwrap()
}
fn irq() -> VirtualIrq {
    VirtualIrq {
        number: 32,
        level: IrqLevel::Assert,
    }
}

#[derive(Default)]
pub(crate) struct TestKick {
    kicks: AtomicUsize,
}
impl VcpuKick for TestKick {
    fn kick(&self) {
        self.kicks.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) struct TestSpace {
    exits: IrqSafeMutex<VecDeque<VmExit>>,
    entries: IrqSafeMutex<Vec<(ProcessorId, Option<ProcessorId>, Duration)>>,
    interrupts: IrqSafeMutex<Vec<VirtualIrq>>,
    accept_irq: AtomicBool,
    map_fails: AtomicBool,
    entered: AtomicBool,
    tracker: Stage2Tracker,
    revoked: AtomicBool,
    revocation_started: Notify,
    dropped: Arc<AtomicBool>,
    irq_on_exit: IrqSafeMutex<Option<VcpuControl<TestKick>>>,
    architectural_wake: Notify,
    architectural_waiters: AtomicUsize,
}
impl TestSpace {
    pub(crate) fn new(exits: impl IntoIterator<Item = VmExit>) -> Self {
        Self {
            exits: IrqSafeMutex::new(exits.into_iter().collect()),
            entries: IrqSafeMutex::new(Vec::new()),
            interrupts: IrqSafeMutex::new(Vec::new()),
            accept_irq: AtomicBool::new(true),
            map_fails: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            tracker: Stage2Tracker::new(NonZeroUsize::new(2).unwrap()),
            revoked: AtomicBool::new(false),
            revocation_started: Notify::new(),
            dropped: Arc::new(AtomicBool::new(false)),
            irq_on_exit: IrqSafeMutex::new(None),
            architectural_wake: Notify::new(),
            architectural_waiters: AtomicUsize::new(0),
        }
    }
}
impl Drop for TestSpace {
    fn drop(&mut self) {
        assert!(!self.entered.load(Ordering::Acquire));
        self.dropped.store(true, Ordering::Release);
    }
}

// SAFETY: test backend never executes hardware or accesses mapped frames;
// the real tracker controls revocation completion in the cancellation tests.
unsafe impl Stage2Space for TestSpace {
    type Vcpu = TestVcpu;
    fn capabilities(&self) -> HvCapabilities {
        HvCapabilities {
            guest_address_bits: NonZeroU8::new(48).unwrap(),
            max_vcpus: NonZeroUsize::new(2).unwrap(),
        }
    }
    fn vmid(&self) -> Option<u32> {
        Some(42)
    }
    fn create_vcpu(space: &Arc<Self>, _: u32) -> Result<TestVcpu, HvError> {
        Ok(TestVcpu {
            space: space.clone(),
            kick: Arc::new(TestKick::default()),
            registers: 0,
            prepared: false,
        })
    }
    unsafe fn map_pages(
        &self,
        range: GuestRange,
        frames: &[PhysFrame],
        _: PageFlags,
    ) -> Result<(), HvError> {
        assert_eq!(range.page_count(), frames.len());
        if self.map_fails.load(Ordering::Acquire) {
            return Err(HvError::OutOfMemory);
        }
        Ok(())
    }
    async fn unmap_pages(&self, _: GuestRange) -> Result<(), HvError> {
        self.revoked.store(true, Ordering::Release);
        let shootdown = self.tracker.invalidate();
        self.revocation_started.notify_all();
        shootdown.wait().await;
        Ok(())
    }
    async fn protect_pages(&self, range: GuestRange, _: PageFlags) -> Result<(), HvError> {
        self.unmap_pages(range).await
    }
}
pub(crate) struct TestVcpu {
    space: Arc<TestSpace>,
    kick: Arc<TestKick>,
    registers: u64,
    prepared: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TestRegisters(u64);

impl helios_hal::hv::GuestRegisters for TestRegisters {
    fn read(&self, register: helios_hal::hv::RegisterId) -> Result<u64, HvError> {
        match register {
            helios_hal::hv::RegisterId::Aarch64X(0) => Ok(self.0),
            _ => Err(HvError::InvalidRegister),
        }
    }
    fn write(&mut self, register: helios_hal::hv::RegisterId, value: u64) -> Result<(), HvError> {
        match register {
            helios_hal::hv::RegisterId::Aarch64X(0) => {
                self.0 = value;
                Ok(())
            }
            _ => Err(HvError::InvalidRegister),
        }
    }
}
// SAFETY: records bounded entry and restores detached state before every return.
unsafe impl GuestVcpu for TestVcpu {
    type Registers = TestRegisters;
    type Kick = TestKick;
    async fn wait_for_interrupt(&mut self) -> Result<(), HvError> {
        struct Registration<'a>(&'a AtomicUsize);
        impl Drop for Registration<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::Relaxed);
            }
        }
        self.space
            .architectural_waiters
            .fetch_add(1, Ordering::Relaxed);
        let _registration = Registration(&self.space.architectural_waiters);
        self.space.architectural_wake.notified().await;
        Ok(())
    }
    fn kick_handle(&self) -> Arc<TestKick> {
        self.kick.clone()
    }
    fn prepare_run(
        &mut self,
        current: ProcessorId,
        previous: Option<ProcessorId>,
        slice: Duration,
    ) -> Result<(), HvError> {
        assert!(!slice.is_zero());
        assert!(!self.prepared);
        self.space
            .entries
            .with(|entries| entries.push((current, previous, slice)));
        self.prepared = true;
        Ok(())
    }
    fn run(&mut self) -> Result<VmExit, HvError> {
        assert!(self.prepared);
        self.prepared = false;
        self.space.entered.store(true, Ordering::Release);
        let exit = self
            .space
            .exits
            .with(|exits| exits.pop_front().expect("unexpected extra guest entry"));
        if let Some(control) = self.space.irq_on_exit.with(Option::take) {
            control.inject_irq(irq()).unwrap();
        }
        self.space.entered.store(false, Ordering::Release);
        Ok(exit)
    }
    fn inject_irq(&mut self, irq: VirtualIrq) -> Result<bool, HvError> {
        if irq.number == u32::MAX {
            return Err(HvError::InvalidInterrupt);
        }
        let accepted = self.space.accept_irq.load(Ordering::Acquire);
        if accepted {
            self.space.interrupts.with(|irqs| irqs.push(irq));
        }
        Ok(accepted)
    }
    fn set_irq_window(&mut self, _: bool) {}
    fn reset(&mut self) -> Result<(), HvError> {
        self.registers = 0;
        self.prepared = false;
        Ok(())
    }
    fn get_regs(&mut self) -> Result<TestRegisters, HvError> {
        Ok(TestRegisters(self.registers))
    }
    fn set_regs(&mut self, registers: &TestRegisters) -> Result<(), HvError> {
        self.registers = registers.0;
        Ok(())
    }
    fn complete_exit(&mut self, value: u64) -> Result<(), HvError> {
        self.registers = value;
        Ok(())
    }
}
pub(crate) fn vm(
    exits: impl IntoIterator<Item = VmExit>,
    pages: usize,
) -> VirtualMachine<TestSpace> {
    VirtualMachine::new(
        TestSpace::new(exits),
        single_node_pool(2),
        pages * PhysFrame::SIZE,
    )
}
struct TestHypervisor {
    published: IrqSafeMutex<Vec<PhysFrame>>,
}

impl Hypervisor for TestHypervisor {
    type Space = TestSpace;
    fn capabilities(&self) -> HvCapabilities {
        TestSpace::new([]).capabilities()
    }
    fn create_space(&self) -> Result<TestSpace, HvError> {
        Ok(TestSpace::new([]))
    }
    unsafe fn synchronize_memory(&self, frames: &[PhysFrame]) {
        self.published
            .with(|published| published.extend_from_slice(frames));
    }
}

#[test]
fn memory_publication_validates_bounds_before_synchronizing_covered_pages() {
    let mut vm = vm([], 2);
    let region = vm
        .allocate_memory(range(2), PageFlags::READ | PageFlags::WRITE)
        .unwrap();
    let hardware = TestHypervisor {
        published: IrqSafeMutex::new(Vec::new()),
    };
    region.publish(&hardware, PhysFrame::SIZE + 1, 1).unwrap();
    hardware
        .published
        .with(|frames| assert_eq!(frames, &region.pages.frames()[1..2]));
    assert_eq!(
        region.publish(&hardware, usize::MAX, 1),
        Err(GuestMemoryError::Bounds)
    );
    region.publish(&hardware, 0, 0).unwrap();
    hardware
        .published
        .with(|frames| assert_eq!(frames.len(), 1));
}

fn vcpu(vm: &mut VirtualMachine<TestSpace>) -> Vcpu<TestSpace> {
    vm.create_vcpu(0, NonZeroUsize::new(2).unwrap()).unwrap()
}

#[test]
fn ioevent_completes_a_matching_write_before_notifying_and_resuming() {
    use helios_hal::hv::IoAccess;

    let address = GuestAddress(0x1000);
    let write = VmExit::Mmio {
        address,
        access: IoAccess::Write {
            width: IoWidth::Dword,
            value: 4,
        },
    };
    let mut vm = vm([write, VmExit::Shutdown], 0);
    let event = vm
        .register_ioevent(address, IoWidth::Dword, Some(4))
        .unwrap();
    let mut cpu = vcpu(&mut vm);
    cpu.set_regs(&TestRegisters(99)).unwrap();
    {
        let mut run = core::pin::pin!(cpu.run_vcpu());
        assert!(poll(run.as_mut()).is_pending());
        assert_eq!(vm.shared.space.entries.with(|entries| entries.len()), 1);
        assert_eq!(block_on(event.wait()), Ok(()));
    }
    assert_eq!(cpu.get_regs().unwrap(), TestRegisters(0));
    assert_eq!(block_on(cpu.run_vcpu()), Ok(VmExit::Shutdown));
}

#[test]
fn unregistered_ioevent_leaves_mmio_to_the_vmm() {
    use helios_hal::hv::IoAccess;

    let address = GuestAddress(0x1000);
    let write = VmExit::Mmio {
        address,
        access: IoAccess::Write {
            width: IoWidth::Dword,
            value: 4,
        },
    };
    let mut vm = vm([write], 0);
    let event = vm.register_ioevent(address, IoWidth::Dword, None).unwrap();
    let mut cpu = vcpu(&mut vm);
    drop(event);
    assert_eq!(block_on(cpu.run_vcpu()), Ok(write));
}

#[test]
fn vm_control_stops_a_vcpu_while_the_vm_owner_is_leased() {
    let mut vm = vm([VmExit::Halt], 0);
    let mut cpu = vcpu(&mut vm);
    let control = vm.control();
    let slot = ResourceSlot::new(vm);
    let lease = slot.take().unwrap();
    let mut run = core::pin::pin!(cpu.run_vcpu());
    assert!(poll(run.as_mut()).is_pending());
    control.stop();
    assert_eq!(poll(run.as_mut()), Poll::Ready(Ok(VmExit::Shutdown)));
    drop(lease);
}

#[test]
fn preemption_yields_before_reentry_and_tracks_migration() {
    let mut vm = vm([VmExit::Preempted, VmExit::Shutdown], 0);
    let mut cpu = vcpu(&mut vm);
    crate::test_processor_identity::set(ProcessorId::new(0));
    let mut run = core::pin::pin!(cpu.run_vcpu());
    assert!(poll(run.as_mut()).is_pending());
    assert_eq!(vm.shared.space.entries.with(|entries| entries.len()), 1);
    assert!(!vm.shared.space.entered.load(Ordering::Acquire));
    crate::test_processor_identity::set(ProcessorId::new(1));
    assert_eq!(poll(run.as_mut()), Poll::Ready(Ok(VmExit::Shutdown)));
    vm.shared.space.entries.with(|entries| {
        assert_eq!(
            entries[0],
            (ProcessorId::new(0), None, crate::GUEST_TIME_SLICE)
        );
        assert_eq!(
            entries[1],
            (
                ProcessorId::new(1),
                Some(ProcessorId::new(0)),
                crate::GUEST_TIME_SLICE
            )
        );
    });
    crate::test_processor_identity::set(ProcessorId::new(0));
}

#[test]
fn halted_cpu_wakes_for_remote_irq_without_repolling_guest() {
    let mut vm = vm([VmExit::Halt, VmExit::Shutdown], 0);
    let mut cpu = vcpu(&mut vm);
    let control = cpu.control();
    let mut run = core::pin::pin!(cpu.run_vcpu());
    assert!(poll(run.as_mut()).is_pending());
    assert!(poll(run.as_mut()).is_pending());
    assert_eq!(vm.shared.space.entries.with(|entries| entries.len()), 1);
    std::thread::spawn(move || control.inject_irq(irq()).unwrap())
        .join()
        .unwrap();
    assert_eq!(poll(run.as_mut()), Poll::Ready(Ok(VmExit::Shutdown)));
    assert_eq!(
        vm.shared.space.interrupts.with(|irqs| irqs.clone()),
        vec![irq()]
    );
}

#[test]
fn kick_wakes_halt_and_yields_without_an_extra_entry() {
    let mut vm = vm([VmExit::Halt], 0);
    let mut cpu = vcpu(&mut vm);
    let control = cpu.control();
    let mut run = core::pin::pin!(cpu.run_vcpu());
    assert!(poll(run.as_mut()).is_pending());
    control.kick();
    assert!(poll(run.as_mut()).is_pending());
    assert_eq!(poll(run.as_mut()), Poll::Ready(Ok(VmExit::Preempted)));
    assert_eq!(vm.shared.space.entries.with(|entries| entries.len()), 1);
}

#[test]
fn cancellation_detaches_and_vm_drop_stops_a_halted_vcpu() {
    let mut vm = vm([VmExit::Halt], 1);
    let account = vm.memory_account().clone();
    drop(
        vm.allocate_memory(range(1), PageFlags::READ | PageFlags::WRITE)
            .unwrap(),
    );
    let dropped = vm.shared.space.dropped.clone();
    let mut cpu = vcpu(&mut vm);
    {
        let mut run = core::pin::pin!(cpu.run_vcpu());
        assert!(poll(run.as_mut()).is_pending());
    }
    assert!(!vm.shared.space.entered.load(Ordering::Acquire));
    drop(vm);
    assert!(!dropped.load(Ordering::Acquire));
    assert_eq!(account.allocated_bytes(), PhysFrame::SIZE);
    assert_eq!(block_on(cpu.run_vcpu()), Ok(VmExit::Shutdown));
    drop(cpu);
    assert!(dropped.load(Ordering::Acquire));
    assert_eq!(account.allocated_bytes(), 0);
}

#[test]
fn irq_backpressure_preserves_pending_interrupt_across_yield() {
    let mut vm = vm([VmExit::IrqWindow, VmExit::Shutdown], 0);
    let mut cpu = vcpu(&mut vm);
    cpu.control().inject_irq(irq()).unwrap();
    vm.shared.space.accept_irq.store(false, Ordering::Release);
    let mut run = core::pin::pin!(cpu.run_vcpu());
    assert!(poll(run.as_mut()).is_pending());
    vm.shared.space.accept_irq.store(true, Ordering::Release);
    assert_eq!(poll(run.as_mut()), Poll::Ready(Ok(VmExit::Shutdown)));
    assert_eq!(
        vm.shared.space.interrupts.with(|irqs| irqs.clone()),
        vec![irq()]
    );
}

#[test]
fn memory_access_spans_frames_and_validates_scatter_before_writing() {
    let mut vm = vm([], 2);
    let region = vm
        .allocate_memory(range(2), PageFlags::READ | PageFlags::WRITE)
        .unwrap();
    let start = PhysFrame::SIZE - 2;
    region.write(start, b"abcd").unwrap();
    let mut bytes = [0; 4];
    region.read(start, &mut bytes).unwrap();
    assert_eq!(&bytes, b"abcd");
    let slices = [
        GuestSlice {
            offset: start,
            len: 2,
        },
        GuestSlice { offset: 0, len: 2 },
    ];
    region.write_scattered(&slices, b"1234").unwrap();
    region.read_scattered(&slices, &mut bytes).unwrap();
    assert_eq!(&bytes, b"1234");
    let invalid = [
        slices[0],
        GuestSlice {
            offset: usize::MAX,
            len: 2,
        },
    ];
    assert_eq!(
        region.write_scattered(&invalid, b"5678"),
        Err(GuestMemoryError::Bounds)
    );
    region.read_scattered(&slices, &mut bytes).unwrap();
    assert_eq!(&bytes, b"1234");
    assert_eq!(
        region.read(usize::MAX, &mut bytes),
        Err(GuestMemoryError::Bounds)
    );
}

#[test]
fn guest_budget_map_failure_and_handle_lifetime_return_user_frames() {
    let mut vm = vm([], 1);
    let before = vm.pool.stats().allocated_bytes;
    let account = vm.memory_account().clone();
    vm.shared.space.map_fails.store(true, Ordering::Release);
    assert!(matches!(
        vm.allocate_memory(range(1), PageFlags::READ),
        Err(VmError::Hardware(HvError::OutOfMemory))
    ));
    assert_eq!(account.allocated_bytes(), 0);
    assert_eq!(vm.pool.stats().allocated_bytes, before);
    vm.shared.space.map_fails.store(false, Ordering::Release);
    assert!(matches!(
        vm.allocate_memory(range(2), PageFlags::READ),
        Err(VmError::Memory(GuestMemoryError::Budget { .. }))
    ));
    let region = vm.allocate_memory(range(1), PageFlags::READ).unwrap();
    let mut zeroes = [1; 4];
    region.read(0, &mut zeroes).unwrap();
    assert_eq!(zeroes, [0; 4]);
    assert_eq!(account.allocated_bytes(), PhysFrame::SIZE);
    block_on(vm.unmap_memory(range(1))).unwrap();
    assert_eq!(account.allocated_bytes(), PhysFrame::SIZE);
    drop(region);
    assert_eq!(account.allocated_bytes(), 0);
    assert_eq!(vm.pool.stats().allocated_bytes, before);
}

#[test]
fn cancelled_unmap_holds_frames_until_every_cpu_acknowledges_retry() {
    let mut vm = vm([], 1);
    drop(vm.allocate_memory(range(1), PageFlags::READ).unwrap());
    let account = vm.memory_account().clone();
    let shared = vm.shared.clone();
    let first = ProcessorId::new(0);
    let second = ProcessorId::new(1);
    shared.space.tracker.enter(first);
    shared.space.tracker.enter(second);
    let old;
    {
        let mut removal = core::pin::pin!(vm.unmap_memory(range(1)));
        assert!(poll(removal.as_mut()).is_pending());
        old = shared.space.tracker.generation();
        shared.space.tracker.acknowledge(first, old);
        assert!(poll(removal.as_mut()).is_pending());
    }
    assert_eq!(account.allocated_bytes(), PhysFrame::SIZE);
    let mut retry = core::pin::pin!(vm.unmap_memory(range(1)));
    assert!(poll(retry.as_mut()).is_pending());
    shared.space.tracker.acknowledge(second, old);
    assert!(poll(retry.as_mut()).is_pending());
    let latest = shared.space.tracker.generation();
    shared.space.tracker.acknowledge(first, latest);
    assert!(poll(retry.as_mut()).is_pending());
    assert_eq!(account.allocated_bytes(), PhysFrame::SIZE);
    shared.space.tracker.acknowledge(second, latest);
    assert!(matches!(poll(retry.as_mut()), Poll::Ready(Ok(()))));
    assert_eq!(account.allocated_bytes(), 0);
    shared.space.tracker.detach(first);
    shared.space.tracker.detach(second);
}

#[test]
fn stage2_entry_after_revocation_observes_new_generation() {
    let tracker = Stage2Tracker::new(NonZeroUsize::new(2).unwrap());
    let first = ProcessorId::new(0);
    let second = ProcessorId::new(1);
    tracker.enter(first);
    let revoke = tracker.invalidate();
    assert_eq!(revoke.targets(), &[first]);
    assert_eq!(tracker.enter(second), revoke.generation());
    let mut wait = core::pin::pin!(revoke.wait());
    assert!(poll(wait.as_mut()).is_pending());
    tracker.detach(first);
    assert!(poll(wait.as_mut()).is_ready());
    tracker.detach(second);
}

#[test]
fn duplicate_vcpu_ids_and_full_irq_queue_are_typed_errors() {
    let mut vm = vm([], 0);
    let cpu = vcpu(&mut vm);
    assert!(matches!(
        vm.create_vcpu(0, NonZeroUsize::new(1).unwrap()),
        Err(HvError::InvalidVcpu)
    ));
    let control = cpu.control();
    control.inject_irq(irq()).unwrap();
    control.inject_irq(irq()).unwrap();
    assert_eq!(control.inject_irq(irq()), Err(HvError::InterruptQueueFull));
    drop(cpu);
    assert_eq!(control.inject_irq(irq()), Err(HvError::Stopped));
    assert!(vm.create_vcpu(0, NonZeroUsize::new(1).unwrap()).is_ok());
}

#[test]
fn irq_arriving_during_halt_exit_is_not_lost_before_wait_registration() {
    let mut vm = vm([VmExit::Halt, VmExit::Shutdown], 0);
    let mut cpu = vcpu(&mut vm);
    vm.shared
        .space
        .irq_on_exit
        .with(|control| *control = Some(cpu.control()));
    let mut run = core::pin::pin!(cpu.run_vcpu());
    assert!(poll(run.as_mut()).is_pending());
    assert_eq!(poll(run.as_mut()), Poll::Ready(Ok(VmExit::Shutdown)));
    assert_eq!(
        vm.shared.space.interrupts.with(|irqs| irqs.clone()),
        vec![irq()]
    );
}

#[test]
fn a_late_allocation_failure_releases_earlier_frames_and_the_entire_charge() {
    // A dedicated small pool makes exhaustion real without consuming the
    // shared test machine. The size covers its per-processor metadata.
    let pool = crate::test_support::TestMachine::round_robin(1, 1).pool(4 * 1024 * 1024);
    let before = pool.stats();
    let bytes = (before.available_bytes() / PhysFrame::SIZE + 1) * PhysFrame::SIZE;
    let mut vm = VirtualMachine::new(TestSpace::new([]), pool, bytes);
    let region = GuestRange::new(helios_hal::hv::GuestAddress(0), bytes).unwrap();
    assert!(matches!(
        vm.allocate_memory(region, PageFlags::READ),
        Err(VmError::Memory(GuestMemoryError::Frames(_)))
    ));
    assert_eq!(vm.memory_account().allocated_bytes(), 0);
    assert_eq!(pool.stats().allocated_bytes, before.allocated_bytes);
}

#[test]
fn unsupported_cpu_refuses_vm_creation() {
    let cpu = crate::test_support::TestCpu::without_entropy();
    assert!(matches!(
        create_vm(&cpu, single_node_pool(1), PhysFrame::SIZE),
        Err(VmError::Hardware(HvError::Unavailable))
    ));
}

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl std::task::Wake for WakeCount {
    fn wake(self: std::sync::Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn parked_vcpu_notifies_the_executor_waker() {
    let mut vm = vm([VmExit::Halt, VmExit::Shutdown], 0);
    let mut cpu = vcpu(&mut vm);
    let control = cpu.control();
    let count = std::sync::Arc::new(WakeCount::default());
    let waker = Waker::from(count.clone());
    let mut context = Context::from_waker(&waker);
    let mut run = core::pin::pin!(cpu.run_vcpu());
    assert!(run.as_mut().poll(&mut context).is_pending());
    assert_eq!(count.0.load(Ordering::Acquire), 0);
    control.inject_irq(irq()).unwrap();
    assert!(count.0.load(Ordering::Acquire) > 0);
    assert_eq!(
        run.as_mut().poll(&mut context),
        Poll::Ready(Ok(VmExit::Shutdown))
    );
}

#[test]
fn rejected_irq_does_not_poison_later_guest_runs() {
    let mut vm = vm([VmExit::Shutdown], 0);
    let mut cpu = vcpu(&mut vm);
    cpu.control()
        .inject_irq(VirtualIrq {
            number: u32::MAX,
            level: IrqLevel::Pulse,
        })
        .unwrap();
    assert_eq!(block_on(cpu.run_vcpu()), Err(HvError::InvalidInterrupt));
    cpu.control().inject_irq(irq()).unwrap();
    assert_eq!(block_on(cpu.run_vcpu()), Ok(VmExit::Shutdown));
    assert_eq!(
        vm.shared.space.interrupts.with(|irqs| irqs.clone()),
        vec![irq()]
    );
}

#[test]
fn masked_pending_irq_does_not_busy_reenter_a_halted_guest() {
    let mut vm = vm([VmExit::Halt, VmExit::Shutdown], 0);
    let mut cpu = vcpu(&mut vm);
    let control = cpu.control();
    control.inject_irq(irq()).unwrap();
    control.inject_irq(irq()).unwrap();
    vm.shared.space.accept_irq.store(false, Ordering::Release);
    {
        let mut run = core::pin::pin!(cpu.run_vcpu());
        assert!(poll(run.as_mut()).is_pending());
        assert!(poll(run.as_mut()).is_pending());
        assert_eq!(vm.shared.space.entries.with(|entries| entries.len()), 1);
        control.kick();
        assert!(poll(run.as_mut()).is_pending());
        assert_eq!(poll(run.as_mut()), Poll::Ready(Ok(VmExit::Preempted)));
    }
    vm.shared.space.accept_irq.store(true, Ordering::Release);
    assert_eq!(block_on(cpu.run_vcpu()), Ok(VmExit::Shutdown));
    assert_eq!(
        vm.shared.space.interrupts.with(|irqs| irqs.clone()),
        vec![irq(), irq()]
    );
}

#[test]
fn architectural_timer_wakes_halted_vcpu() {
    let mut vm = vm([VmExit::Halt, VmExit::Shutdown], 0);
    let mut cpu = vcpu(&mut vm);
    let mut run = core::pin::pin!(cpu.run_vcpu());
    assert!(poll(run.as_mut()).is_pending());
    assert!(poll(run.as_mut()).is_pending());
    assert_eq!(vm.shared.space.entries.with(|entries| entries.len()), 1);
    assert_eq!(
        vm.shared
            .space
            .architectural_waiters
            .load(Ordering::Relaxed),
        1
    );
    vm.shared.space.architectural_wake.notify_all();
    assert_eq!(poll(run.as_mut()), Poll::Ready(Ok(VmExit::Shutdown)));
    assert_eq!(
        vm.shared
            .space
            .architectural_waiters
            .load(Ordering::Relaxed),
        0
    );
}

#[test]
fn cancelling_halt_releases_architectural_timer_wait() {
    let mut vm = vm([VmExit::Halt, VmExit::Halt], 0);
    let mut cpu = vcpu(&mut vm);
    {
        let mut run = core::pin::pin!(cpu.run_vcpu());
        assert!(poll(run.as_mut()).is_pending());
        assert_eq!(
            vm.shared
                .space
                .architectural_waiters
                .load(Ordering::Relaxed),
            1
        );
    }
    assert_eq!(
        vm.shared
            .space
            .architectural_waiters
            .load(Ordering::Relaxed),
        0
    );
    let control = cpu.control();
    let mut run = core::pin::pin!(cpu.run_vcpu());
    assert!(poll(run.as_mut()).is_pending());
    control.stop();
    assert_eq!(poll(run.as_mut()), Poll::Ready(Ok(VmExit::Shutdown)));
    assert_eq!(
        vm.shared
            .space
            .architectural_waiters
            .load(Ordering::Relaxed),
        0
    );
}

#[test]
fn reset_discards_registers_pending_irqs_and_kicks_but_preserves_stop() {
    let mut vm = vm([VmExit::Shutdown], 0);
    let mut cpu = vcpu(&mut vm);
    cpu.set_regs(&TestRegisters(99)).unwrap();
    cpu.control().inject_irq(irq()).unwrap();
    cpu.control().kick();
    cpu.reset().unwrap();
    assert_eq!(cpu.get_regs().unwrap(), TestRegisters(0));
    assert_eq!(block_on(cpu.run_vcpu()), Ok(VmExit::Shutdown));
    assert!(vm.shared.space.interrupts.with(|irqs| irqs.is_empty()));
    vm.control().stop();
    assert_eq!(cpu.reset(), Err(HvError::Stopped));
}

#[test]
fn partial_guest_writes_preserve_neighbors_across_words_and_pages() {
    let mut vm = vm([], 2);
    let region = vm
        .allocate_memory(range(2), PageFlags::READ | PageFlags::WRITE)
        .unwrap();
    for start in [0, PhysFrame::SIZE - 8] {
        region.write(start, &[0xa5; 24]).unwrap();
        region.write(start + 3, &[0x5a; 14]).unwrap();
        let mut bytes = [0; 24];
        region.read(start, &mut bytes).unwrap();
        assert_eq!(&bytes[..3], &[0xa5; 3]);
        assert_eq!(&bytes[3..17], &[0x5a; 14]);
        assert_eq!(&bytes[17..], &[0xa5; 7]);
    }
}

#[test]
fn concurrent_guest_writes_preserve_other_lanes_and_never_tear_indices() {
    let mut vm = vm([], 1);
    let region = vm
        .allocate_memory(range(1), PageFlags::READ | PageFlags::WRITE)
        .unwrap();
    std::thread::scope(|scope| {
        let region = &region;
        let writer = scope.spawn(move || {
            for _ in 0..4096 {
                for value in [0x55aau16, 0xaa55] {
                    loop {
                        match region.write(0, &value.to_ne_bytes()) {
                            Ok(()) => break,
                            Err(GuestMemoryError::Contended) => std::thread::yield_now(),
                            error => panic!("unexpected write result: {error:?}"),
                        }
                    }
                }
            }
        });
        for _ in 0..4096 {
            loop {
                match region.write(2, &[0x37; 2]) {
                    Ok(()) => break,
                    Err(GuestMemoryError::Contended) => std::thread::yield_now(),
                    error => panic!("unexpected write result: {error:?}"),
                }
            }
            let mut index = [0; 2];
            region.read(0, &mut index).unwrap();
            assert!([0, 0x55aa, 0xaa55].contains(&u16::from_ne_bytes(index)));
        }
        writer.join().unwrap();
    });
    let mut bytes = [0; 4];
    region.read(0, &mut bytes).unwrap();
    assert_eq!(&bytes[2..], &[0x37; 2]);
}
