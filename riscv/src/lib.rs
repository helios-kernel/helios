#![no_std]
#![no_main]

extern crate alloc;
mod balloon;
mod block;
mod device;
mod entropy;
mod gpu;
mod hibernate;
mod host_fs;
mod input;
mod iommu;
mod net;
mod pci;
mod rtc;
mod snd;
mod tpm;
mod vsock;
mod watchdog;

mod debug_state {
    /// The network service this machine's virtio-net device backs.
    pub(crate) type NetworkService =
        helios_kernel::NetworkService<crate::RiscvCpu, crate::net::VirtioNetworkDevice>;
    pub(crate) type RuntimeState =
        helios_kernel::HostRuntimeState<crate::RiscvCpu, NetworkService, Storage>;
    pub(crate) type ProgramService =
        helios_kernel::UserProgramService<crate::RiscvCpu, NetworkService, Storage>;

    /// This machine's storage: the virtio-9p host share and the
    /// virtio-blk disks.
    #[derive(Clone, Copy)]
    pub(crate) struct Storage;

    impl helios_kernel::Storage for Storage {
        type HostShare = crate::host_fs::HostFileSystemService;
        type Disk = crate::block::RiscvVirtioBlockDevice;
    }
}

use ns16550a::{Break, DLAB, ParityBit, ParitySelect, StickParity, StopBits, Uart, WordLength};

/// 16550 interrupt-enable register; this port arms only the
/// received-data condition.
const UART_IER: usize = 1;
const UART_IER_RDI: u8 = 1 << 0;

/// Debugger byte transport backed by the machine's boot UART. Kernel tracing
/// stays in memory so the line remains reserved for RPC traffic after boot.
#[derive(Clone, Copy)]
pub(crate) struct DebugTransport {
    uart_base: usize,
    /// The PLIC line the same device-tree node routes the port's
    /// interrupt to.
    plic_line: net::PlicInterrupt,
}

impl DebugTransport {
    pub(crate) fn discover(fdt: &Fdt<'_>) -> Option<Self> {
        let chosen = fdt.find_node("/chosen")?;
        let stdout_path = chosen
            .properties()
            .find(|property| property.name == "stdin-path")
            .or_else(|| {
                chosen
                    .properties()
                    .find(|property| property.name == "stdout-path")
            })?;
        let path = core::str::from_utf8(stdout_path.value)
            .ok()?
            .trim_end_matches('\0')
            .split(':')
            .next()?;
        let node = fdt
            .find_node(path)
            .or_else(|| fdt.aliases().and_then(|aliases| aliases.resolve_node(path)))?;
        let region = node.reg()?.next()?;
        // The PLIC's specifier is a bare source number, the same
        // one-cell binding the grant walk decodes.
        let plic_line = helios_virtio::node_interrupt(fdt, &node)
            .and_then(net::PlicInterrupt::from_specifier)
            .unwrap_or_else(|| {
                panic!(
                    "the {} debug UART node declares no PLIC source in its interrupts cell; \
                     the serial line could only be polled",
                    node.name
                )
            });
        Some(Self {
            uart_base: region.starting_address as usize,
            plic_line,
        })
    }

    pub(crate) fn try_read_byte(&self) -> Option<u8> {
        Uart::new(self.uart_base).get()
    }

    pub(crate) fn write_bytes(&self, bytes: &[u8]) {
        let uart = Uart::new(self.uart_base);
        for &byte in bytes {
            while uart.put(byte).is_none() {
                core::hint::spin_loop();
            }
        }
    }
}

impl ByteSerial for DebugTransport {
    fn try_read_byte(&self) -> Option<u8> {
        DebugTransport::try_read_byte(self)
    }

    fn write_bytes(&self, bytes: &[u8]) {
        DebugTransport::write_bytes(self, bytes);
    }

    /// Received data is the only condition this port arms, so a plain
    /// write of exactly that bit rather than a read-modify-write.
    /// Idempotent, and callable from interrupt context: a register
    /// write, no lock, no allocation.
    fn enable_receive_interrupt(&self) {
        let ier = (self.uart_base + UART_IER) as *mut u8;
        // SAFETY: `uart_base` came from the FDT node's `reg` window and is
        // identity-mapped 16550 MMIO; `UART_IER` is the 1-byte interrupt-enable
        // register and the divisor latch was cleared during `publish_debug_transport`.
        unsafe { ier.write_volatile(UART_IER_RDI) };
    }

    fn disable_receive_interrupt(&self) {
        let ier = (self.uart_base + UART_IER) as *mut u8;
        // SAFETY: `uart_base` came from the FDT node's `reg` window and is
        // identity-mapped 16550 MMIO; `UART_IER` is the 1-byte interrupt-enable
        // register.
        unsafe { ier.write_volatile(0) };
    }
}

use helios_virtio::DeviceType;

/// RISC-V MMIO is identity-mapped, so candidates are probed at their
/// physical base directly.
pub(crate) fn matches_virtio_mmio_device(base: usize, expected: DeviceType) -> bool {
    // SAFETY: `base` came from `helios_virtio::mmio_candidates(fdt)`, and
    // RISC-V identity-maps physical MMIO addresses.
    unsafe { helios_virtio::mmio_device_matches(base, expected) }
}

pub(crate) fn count_virtio_mmio_devices(fdt: &Fdt<'_>, expected: DeviceType) -> usize {
    helios_virtio::mmio_candidates(fdt)
        .filter(|candidate| matches_virtio_mmio_device(candidate.base, expected))
        .count()
}

use core::arch::{asm, global_asm};
use core::num::NonZeroUsize;
use core::ops::Range;
use core::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering, compiler_fence};

use arrayvec::ArrayVec;
use fdt::Fdt;
use helios_firmware::{DeviceTreeNuma, ProcessorIdentities};
use helios_hal::boot::{
    BootMemoryKind, BootMemoryMetadata, BootMemoryRegion, BootPayloadMetadata, BootPhysicalRange,
    BootReservedRanges, KernelImageSections, KernelSectionRange, usable_node_regions,
};
use helios_hal::cpu::{
    BspSnapshotContext, Cpu, GUEST_STACK_LIMIT_OFFSET, Instant, ProcessorId, ResumeHandoff,
    ResumeHandoffWire, Riscv64SnapshotContext, SnapshotPoint, SnapshotUnsupported, Timebase,
    TimerInterrupt, current_processor,
};
use helios_hal::critical_section::ProcessorIdentity;
use helios_hal::memory::MemoryRegion;
use helios_hal::numa::NumaTopology;
use helios_hal::serial::ByteSerial;
use helios_hal::{DeviceInventory, DmaModel, ProcessorStartupPolicy, ProcessorTopology};
use helios_kernel::{
    DebugSerialAccess, KernelException, KernelExceptionCause, KernelNativeTrapHandler, Timer,
    WasmtimeTlsSlots,
};
use riscv::interrupt::Trap;
use riscv::interrupt::supervisor::{Exception, Interrupt};
use riscv_rt::entry;
use spin::Once;

mod lifecycle;
mod trap;

pub use trap::{GeneralRegs, TrapFrame};

global_asm!(include_str!("mp_hook.S"));
global_asm!(include_str!("secondary_entry.S"));
global_asm!(include_str!("snapshot.S"));

const UNINITIALIZED_BOOT_HART: usize = usize::MAX;
/// One bit of [`ONLINE_HARTS`] per hart id.
const MAX_TRACKED_HARTS: usize = usize::BITS as usize;
const SSTATUS_SPP_BIT: usize = 1 << 8;

static BOOT_HART_ID: AtomicUsize = AtomicUsize::new(UNINITIALIZED_BOOT_HART);
/// Harts that have entered [`run_hart`] and can therefore be parked in `wfi`.
///
/// SBI only accepts `sbi_send_ipi` for harts the firmware currently reports as
/// started, suspended, or resume-pending: OpenSBI's `sbi_ipi_send_many`
/// intersects the requested mask with the interruptible harts and rejects the
/// whole call with `SBI_ERR_INVALID_PARAM` when any requested hart drops out.
/// The kernel scheduler legitimately nudges secondaries while the bootstrap
/// hart is still bringing up devices, long before it hands them to
/// `sbi_hart_start`, so the backend tracks which harts are actually running
/// kernel code. A hart that has not entered the kernel is not parked and needs
/// no nudge: it drains the run queues as soon as it reaches the scheduler.
static ONLINE_HARTS: AtomicUsize = AtomicUsize::new(0);
static CRITICAL_SECTION_STATE: helios_hal::critical_section::CriticalSectionState =
    helios_hal::critical_section::CriticalSectionState::new();
static DEBUG_STATE: Once<debug_state::RuntimeState> = Once::new();
static WATCHDOG_STATE: Once<watchdog::RiscvWatchdog> = Once::new();
/// Shared monotonic tick offset added to the RISC-V `time` CSR so [`Cpu::now`]
/// continues strictly forward across hibernate/resume and [`Cpu::set_deadline`]
/// translates deadlines back into raw `time` CSR ticks for `sbi_rt::set_timer`.
static TIMEBASE_OFFSET: AtomicU64 = AtomicU64::new(0);

use core::ptr::NonNull;

const SSTATUS_SIE_BIT: usize = 1 << 1;
const SSTATUS_SPIE_BIT: usize = 1 << 5;

pub type ComputeTaskEntry = extern "C" fn(usize) -> !;

/// Register state that must be inherited by every supervisor-mode compute task.
///
/// `gp` and `tp` are not task-local in this kernel:
/// - `gp` must keep pointing at the kernel's global pointer window
/// - `tp` carries the current hart runtime pointer
///
/// The scheduler captures this template once per hart and stamps it into every
/// newly created compute task context.
#[derive(Clone, Copy)]
pub struct ComputeContextTemplate {
    gp: usize,
    tp: usize,
    sstatus: usize,
}

impl ComputeContextTemplate {
    pub fn capture_current() -> Self {
        let gp: usize;
        let tp: usize;
        // SAFETY: reading `gp` has no side effects and modifies no memory or flags.
        unsafe {
            asm!("mv {}, gp", out(reg) gp, options(nomem, nostack, preserves_flags));
        }
        // SAFETY: reading `tp` has no side effects and modifies no memory or flags.
        unsafe {
            asm!("mv {}, tp", out(reg) tp, options(nomem, nostack, preserves_flags));
        }

        Self {
            gp,
            tp,
            sstatus: riscv::register::sstatus::read().bits(),
        }
    }

    fn task_sstatus(self) -> usize {
        // Compute threads always resume in supervisor mode with interrupts
        // enabled after `sret`, but not while the trap handler is still
        // mutating the frame.
        (self.sstatus | SSTATUS_SPP_BIT | SSTATUS_SPIE_BIT) & !SSTATUS_SIE_BIT
    }
}

/// Saved execution context for one preemptible compute task.
///
/// The timer interrupt handler will save the interrupted trap frame here, and
/// the scheduler will later restore it into the live trap frame of a compute
/// hart before returning from the interrupt.
#[derive(Clone, Copy)]
pub struct ComputeTaskContext {
    trap_frame: TrapFrame,
}

impl ComputeTaskContext {
    /// Builds the initial supervisor context for a fresh compute task.
    ///
    /// The returned frame is ready to be copied into the live trap frame of a
    /// compute hart. After `sret`, execution will begin at `entry(arg)` on the
    /// provided stack.
    pub fn start(
        stack: NonNull<[u8]>,
        entry: ComputeTaskEntry,
        arg: usize,
        template: ComputeContextTemplate,
    ) -> Self {
        let mut trap_frame = TrapFrame::default();
        trap_frame.general.sp = aligned_stack_top(stack);
        trap_frame.general.gp = template.gp;
        trap_frame.general.tp = template.tp;
        trap_frame.general.a0 = arg;
        trap_frame.general.ra = compute_task_returned as *const () as usize;
        trap_frame.sstatus = template.task_sstatus();
        trap_frame.sepc = entry as usize;
        Self { trap_frame }
    }

    pub fn save_from_trap(&mut self, trap_frame: &TrapFrame) {
        self.trap_frame = *trap_frame;
    }

    pub fn restore_into_trap(self, trap_frame: &mut TrapFrame) {
        *trap_frame = self.trap_frame;
    }

    pub fn trap_frame(&self) -> &TrapFrame {
        &self.trap_frame
    }
}

fn aligned_stack_top(stack: NonNull<[u8]>) -> usize {
    let top = stack.cast::<u8>().as_ptr() as usize + stack.len();
    top & !0xF
}

extern "C" fn compute_task_returned() -> ! {
    panic!("compute task returned unexpectedly");
}

struct SupervisorInterruptOps;

impl helios_hal::critical_section::InterruptOps for SupervisorInterruptOps {
    fn interrupts_enabled() -> bool {
        riscv::register::sstatus::read().sie()
    }

    fn disable_interrupts() {
        riscv::interrupt::supervisor::disable();
    }

    unsafe fn enable_interrupts() {
        // SAFETY: the caller upholds `InterruptOps::enable_interrupts` that
        // supervisor interrupts may be enabled here.
        unsafe { riscv::interrupt::supervisor::enable() };
    }

    fn current_identity() -> ProcessorIdentity {
        read_hart_identity()
    }
}

struct SupervisorCriticalSection;

critical_section::set_impl!(SupervisorCriticalSection);

// The processor-local half, for locks that carry their own spin word
// and need only to keep this processor's interrupt handler out.
helios_hal::critical_section::set_local_interrupt_mask_impl!(SupervisorInterruptOps);

// SAFETY: `CRITICAL_SECTION_STATE` synchronises supervisor-mode critical
// sections across harts using each hart's `ProcessorIdentity` from `tp`.
unsafe impl critical_section::Impl for SupervisorCriticalSection {
    unsafe fn acquire() -> usize {
        // SAFETY: the caller pairs each `acquire` with a matching `release`.
        unsafe { CRITICAL_SECTION_STATE.acquire::<SupervisorInterruptOps>() }
    }

    unsafe fn release(restore_state: usize) {
        // SAFETY: `restore_state` was returned by the matching `acquire`.
        unsafe { CRITICAL_SECTION_STATE.release::<SupervisorInterruptOps>(restore_state) }
    }
}

/// The hart's local block, addressed by `tp` once [`HartRuntime::install`]
/// has run.
///
/// The layout is `#[repr(C)]` because compiled guest code reads
/// `guest_stack_limit` as `GUEST_STACK_LIMIT_OFFSET(tp)`; the offset is
/// asserted below.
#[repr(C)]
struct HartRuntime {
    /// The stack every trap on this hart is built on once
    /// [`HartRuntime::install`] has published it through `sscratch`.
    trap_stack: Range<usize>,
    /// The stack limit of the guest running on this hart, under
    /// [`GUEST_STACK_LIMIT_OFFSET`]'s contract: Wasmtime publishes it through
    /// `wasmtime_processor_stack_limit`, and any hart may store the interrupt
    /// sentinel into it.
    guest_stack_limit: AtomicUsize,
    hart_id: ProcessorId,
    timer: Timer<RiscvCpu>,
    wasmtime_tls: WasmtimeTlsSlots,
    /// The PLIC domains this hart takes interrupts for, if any; the
    /// `SupervisorExternal` trap arm claims from them.
    external_interrupts: Option<net::HartInterrupts>,
    program_service: Once<debug_state::ProgramService>,
    /// The stack a kernel exception the kernel did not resolve is handed
    /// to the runtime from (`trap::hand_over_trap`). It is not the trap
    /// stack because the hand-over gives that back before the runtime's
    /// handler runs, so the next trap can carve its region at the top.
    hand_over_stack: Range<usize>,
    /// The record of this hart's trap hand-over self-check.
    hand_over_probe: trap::HandOverProbe,
}

const _: () = assert!(
    core::mem::offset_of!(HartRuntime, guest_stack_limit) == GUEST_STACK_LIMIT_OFFSET as usize,
    "compiled guest code would compare its stack pointer against the wrong word"
);

impl HartRuntime {
    /// Publishes this runtime as the hart's identity.
    ///
    /// Hart-local runtime state lives in `tp`, which the trap entry saves
    /// and restores with the rest of the integer file.
    /// This keeps trap entry correct while still giving the kernel a cheap
    /// per-hart lookup path. The hart already carried a bootstrapping identity
    /// in `tp`; this replaces it, and both forms are distinguishable, so the
    /// critical section never confuses two harts for one.
    ///
    /// The runtime must outlive the hart: `run_hart` never returns, so the
    /// stack frame holding it lives as long as the hart does.
    fn install(&self) {
        write_hart_identity(ProcessorIdentity::installed(self));
        // SAFETY: `trap_stack` came from `allocate_trap_stack` for this
        // hart, and this is the only writer of `sscratch` outside the
        // trap entry and exit.
        unsafe {
            trap::seed_trap_stack(&self.trap_stack);
        }
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    fatal_panic(info)
}

/// The kernel console: every record is retained for the debugger and,
/// when the debug UART is carrying the kernel log, mirrored to it
/// through the port's own console.
///
/// The mirror is the port's [`helios_kernel::DebugSerialWriter`] and
/// nothing else. It used to be a byte loop over `sbi_rt::console_write_byte`,
/// which reaches the very same 16550 the debugger's `[KDBG …]` markers
/// go to — but beside the console that owns it rather than through it,
/// so a marker emitted while a tracing record was mid-write came out
/// spliced into it (#164).
fn kernel_console(
    debug_state: debug_state::RuntimeState,
    mirror_to_uart: bool,
) -> helios_kernel::RecordingConsole<debug_state::RuntimeState, impl FnMut() -> u64> {
    helios_kernel::RecordingConsole::new(
        debug_state,
        riscv::register::time::read64,
        mirror_to_uart.then_some(DEBUG_SERIAL_WRITER),
    )
}

#[derive(Clone)]
pub struct RiscvCpu {
    bootstrap_hart: ProcessorId,
    hart_count: usize,
    timebase: Timebase,
    fdt_addr: usize,
}

impl RiscvCpu {
    pub(crate) fn new(
        bootstrap_hart: ProcessorId,
        hart_count: usize,
        timebase: Timebase,
        fdt_addr: usize,
    ) -> Self {
        Self {
            bootstrap_hart,
            hart_count,
            timebase,
            fdt_addr,
        }
    }
}

/// The processor identity `hal` publishes as a linkage contract.
///
/// `tp` carries the hart identity `run_hart` seeds before anything else
/// runs, and its bootstrapping form until `HartRuntime::install`
/// replaces it, so this answers from the first instruction of the
/// kernel onwards.
#[unsafe(no_mangle)]
extern "Rust" fn helios_current_processor() -> ProcessorId {
    match installed_hart_runtime() {
        Some(runtime) => runtime.hart_id,
        None => {
            let hardware_id = read_hart_identity()
                .hardware_id()
                .expect("an identity without a runtime address carries a hardware id");
            ProcessorId::new(
                u16::try_from(hardware_id).expect("riscv hart id does not fit a processor id"),
            )
        }
    }
}

/// The supervisor timer and external interrupt enables cleared on the
/// hart that took them, and put back as they were when dropped. Only the
/// software interrupt, the wake, stays enabled meanwhile; the rest stays
/// pending in `sip`. `sie` is the hart's own register, so the value is
/// not `Send`; it leaves `sstatus.SIE` alone.
pub struct RiscvWakeOnlyMask {
    timer: bool,
    external: bool,
    _processor_local: core::marker::PhantomData<*mut ()>,
}

impl Drop for RiscvWakeOnlyMask {
    fn drop(&mut self) {
        compiler_fence(Ordering::SeqCst);
        if self.timer {
            // SAFETY: restores the `sie.STIE` bit saved when the mask was raised.
            unsafe { riscv::register::sie::set_stimer() };
        }
        if self.external {
            // SAFETY: restores the `sie.SEIE` bit saved when the mask was raised.
            unsafe { riscv::register::sie::set_sext() };
        }
    }
}

impl Cpu for RiscvCpu {
    type Hypervisor = core::convert::Infallible;
    type Native = core::convert::Infallible;
    // SBI `set_timer` programs this hart's one-shot comparator.
    const TIMER_INTERRUPT: TimerInterrupt = TimerInterrupt::Deadline;

    fn processor_count(&self) -> usize {
        self.hart_count
    }

    fn bootstrap_processor(&self) -> ProcessorId {
        self.bootstrap_hart
    }

    fn park_current(&self) {
        riscv::asm::wfi();
    }

    type WakeOnlyMask = RiscvWakeOnlyMask;

    fn mask_to_wake_only(&self) -> RiscvWakeOnlyMask {
        // The wake is the supervisor software interrupt; the timer and the
        // external interrupt (every device) are taken out of `sie`, so
        // they stay pending in `sip` and a `wfi` neither ends on them nor
        // delivers them. The shootdown is an SBI call that needs no
        // supervisor interrupt on this hart.
        let sie = riscv::register::sie::read();
        let (timer, external) = (sie.stimer(), sie.sext());
        // SAFETY: `RiscvWakeOnlyMask` restores `stimer` when dropped.
        unsafe { riscv::register::sie::clear_stimer() };
        // SAFETY: `RiscvWakeOnlyMask` restores `sext` when dropped.
        unsafe { riscv::register::sie::clear_sext() };
        compiler_fence(Ordering::SeqCst);
        RiscvWakeOnlyMask {
            timer,
            external,
            _processor_local: core::marker::PhantomData,
        }
    }

    fn park_wake_only(&self, word: &AtomicU8, held: u8) {
        assert!(
            !riscv::register::sstatus::read().sie(),
            "RISC-V park_wake_only was entered with supervisor interrupts enabled, before the \
             enable set was narrowed"
        );
        // A `wfi` ends on any pending interrupt that `sie` enables,
        // whatever `sstatus.SIE` says, so a wake raised between the test
        // below and the `wfi` completes it at once.
        let mask = self.mask_to_wake_only();
        while word.load(Ordering::Acquire) == held {
            riscv::asm::wfi();
            // The wait leaves the software interrupt pending: taking it
            // runs the trap handler that clears it. Nothing else is
            // enabled in `sie`, so nothing else is taken in the window.
            // SAFETY: the window is closed again on the next line.
            unsafe { riscv::interrupt::supervisor::enable() };
            riscv::interrupt::supervisor::disable();
        }
        drop(mask);
    }

    fn start_processor(&self, hart: ProcessorId) {
        match hart_status(hart) {
            sbi_spec::hsm::hart_state::STARTED => {
                self.wake_processor(hart);
            }
            sbi_spec::hsm::hart_state::STOPPED => {
                lifecycle::assert_never_stopped(hart);
                let ret = sbi_rt::hart_start(
                    hart.id() as usize,
                    core::ptr::addr_of!(_secondary_start).addr(),
                    self.fdt_addr,
                );
                if ret.is_ok() {
                    return;
                }

                panic!(
                    "failed to start hart {} via SBI HSM: error={} value={}",
                    hart.id(),
                    ret.error,
                    ret.value
                );
            }
            state => panic!(
                "hart {} reported unexpected SBI HSM state {}",
                hart.id(),
                state
            ),
        }
    }

    fn stop_current(&self) {
        lifecycle::stop_current();
    }

    fn restart_processor(&self, hart: ProcessorId) {
        lifecycle::restart_processor(hart);
    }

    fn wait_processor_stopped(&self, hart: ProcessorId) {
        lifecycle::wait_hart_stopped(hart);
    }

    fn restore_bsp_post_resume_state(&self) {
        // SAFETY: `sscratch` was restored by the restore trampoline before
        // returning here.
        unsafe { trap::install_trap_vector() };
        if let Some(runtime) = installed_hart_runtime()
            && let Some(interrupts) = runtime.external_interrupts
        {
            interrupts.open();
        }
        sbi_rt::set_timer(u64::MAX);
        // SAFETY: clears any stale pending supervisor software interrupt bit
        // while supervisor interrupts are masked.
        unsafe {
            riscv::register::sip::clear_ssoft();
        }
    }

    fn wake_processor(&self, hart: ProcessorId) {
        if current_processor() == hart {
            return;
        }

        if !hart_is_online(hart) {
            // The hart has not entered the kernel yet, so it cannot be parked
            // in `wfi`. Sending it an IPI would be rejected by SBI with
            // `SBI_ERR_INVALID_PARAM`, and there is nothing to wake: the hart
            // observes every queued task once it reaches the scheduler.
            return;
        }

        let ret = sbi_rt::send_ipi(sbi_rt::HartMask::from_mask_base(1, hart.id() as usize));
        if ret.is_ok() {
            return;
        }

        panic!(
            "failed to wake hart {} via SBI IPI: error={} value={}",
            hart.id(),
            ret.error,
            ret.value
        );
    }

    fn now(&self) -> Instant {
        let offset = TIMEBASE_OFFSET.load(Ordering::Acquire);
        Instant::new(riscv::register::time::read64().saturating_add(offset))
    }

    fn continue_timebase(&self, floor: Instant) {
        let raw = riscv::register::time::read64();
        let new_offset = floor.ticks().saturating_add(1).saturating_sub(raw);
        TIMEBASE_OFFSET.store(new_offset, Ordering::Release);
    }

    fn timebase(&self) -> Timebase {
        self.timebase
    }

    fn set_deadline(&self, deadline: Instant) {
        let offset = TIMEBASE_OFFSET.load(Ordering::Acquire);
        sbi_rt::set_timer(deadline.ticks().saturating_sub(offset));
    }

    fn publish_executable(&self, ptr: *const u8, len: usize) {
        helios_kernel::runtime_memory::publish_code_memory(ptr, len);
        // Every hart is fenced before the range is handed out. A range is
        // executable only between this call and `unpublish_executable`, so
        // a reused range is fenced here again before anything runs it.
        fence_instruction_streams();
    }

    fn unpublish_executable(&self, ptr: *const u8, len: usize) {
        helios_kernel::runtime_memory::unpublish_code_memory(ptr, len);
    }

    fn native_feature_probe(&self) -> Option<fn(&str) -> Option<bool>> {
        None
    }

    fn has_lazy_commit_virtual_memory(&self) -> bool {
        // `RiscvUserAddressSpace` reserves Sv48 virtual ranges without
        // touching a frame and commits them page by page on request, so the
        // runtime can pre-reserve a 4 GiB slot per linear memory out of the
        // 32 TiB user window and pay physical memory only for what a guest
        // actually touches.
        true
    }

    fn capture_bsp_state(
        &self,
        context: &mut BspSnapshotContext,
    ) -> Result<SnapshotPoint, SnapshotUnsupported> {
        let sscratch: u64;
        let sie: u64;
        let satp: u64;
        let stvec: u64;
        // SAFETY: reading `sscratch` has no side effects.
        unsafe {
            asm!("csrr {}, sscratch", out(reg) sscratch, options(nomem, nostack));
        }
        // SAFETY: reading `sie` has no side effects.
        unsafe {
            asm!("csrr {}, sie", out(reg) sie, options(nomem, nostack));
        }
        // SAFETY: reading `satp` has no side effects.
        unsafe {
            asm!("csrr {}, satp", out(reg) satp, options(nomem, nostack));
        }
        // SAFETY: reading `stvec` has no side effects.
        unsafe {
            asm!("csrr {}, stvec", out(reg) stvec, options(nomem, nostack));
        }
        let mut raw = Riscv64SnapshotContext {
            sscratch,
            sie,
            satp,
            stvec,
            sstatus: riscv::register::sstatus::read().bits() as u64,
            ..Riscv64SnapshotContext::default()
        };

        // SAFETY: `&raw mut raw` is a valid, aligned `Riscv64SnapshotContext`
        // matching the offsets pinned for `__helios_riscv_capture_bsp_state`.
        let result = unsafe { __helios_riscv_capture_bsp_state(&raw mut raw) };
        if result.status == 0 {
            *context = BspSnapshotContext::from_riscv64(&raw);
            Ok(SnapshotPoint::Captured)
        } else {
            let handoff_ptr = core::ptr::with_exposed_provenance_mut::<ResumeHandoffWire>(
                result.handoff_phys as usize,
            );
            // SAFETY: RISC-V identity-maps physical RAM, and the restore
            // trampoline wrote a valid `ResumeHandoffWire` at
            // `result.handoff_phys` on the safe trampoline page.
            let wire = unsafe { core::ptr::read(handoff_ptr) };
            // Wipe the handoff copy (which contains fresh boot entropy) once consumed.
            // SAFETY: `handoff_ptr` is exclusively owned by this resuming BSP.
            unsafe {
                core::ptr::write_volatile(handoff_ptr, ResumeHandoffWire::default());
            }
            Ok(SnapshotPoint::Resumed(ResumeHandoff::from_wire(wire)))
        }
    }

    fn shutdown(&self) -> ! {
        sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::NoReason);
        halt_forever()
    }

    fn reboot(&self) -> ! {
        sbi_rt::system_reset(sbi_rt::ColdReboot, sbi_rt::NoReason);
        halt_forever()
    }
}

#[entry]
fn main(hart_id: usize, fdt_addr: usize, opaque: usize) -> ! {
    let _ = opaque;
    run_hart(hart_id, fdt_addr)
}

mod vmm;
pub use vmm::RiscvUserAddressSpace;

#[unsafe(no_mangle)]
extern "C" fn secondary_start_rust(hart_id: usize, fdt_addr: usize) -> ! {
    run_hart(hart_id, fdt_addr)
}

/// The Rust half of the supervisor trap entry in `trap.S`.
#[unsafe(no_mangle)]
extern "C" fn __helios_riscv_trap_dispatch(tf: &mut TrapFrame) {
    trap_dispatch(tf);
}

#[inline(never)]
fn trap_dispatch(tf: &mut TrapFrame) {
    if let Some(runtime) = installed_hart_runtime() {
        trap::assert_frame_on_trap_stack(tf, &runtime.trap_stack);
    }
    match riscv::register::scause::read().cause().try_into() {
        Ok(Trap::Interrupt(Interrupt::SupervisorTimer)) => {
            // Every hart's timer interrupt ends the slice of every guest
            // on the machine that has run one.
            if let Some(program_service) = current_hart_runtime().program_service.get() {
                program_service.preempt_overdue_guests();
            }
            current_hart_runtime().timer.handle_interrupt();
        }
        Ok(Trap::Interrupt(Interrupt::SupervisorSoft)) => {
            if let Some(runtime) = installed_hart_runtime() {
                runtime.hand_over_probe.record_interrupt(tf);
            }
            // SAFETY: clears the pending supervisor software interrupt after
            // recording it in `hand_over_probe`.
            unsafe {
                riscv::register::sip::clear_ssoft();
            }
        }
        Ok(Trap::Interrupt(Interrupt::SupervisorExternal)) => {
            let runtime = current_hart_runtime();
            let interrupts = runtime.external_interrupts.as_ref().unwrap_or_else(|| {
                panic!(
                    "unhandled hardware interrupt without registered dispatch: interrupt={:?}, tf={tf:#x?}",
                    Interrupt::SupervisorExternal
                )
            });
            interrupts.handle();
        }
        // The trap hand-over self-check's second trap is resolved in place.
        Ok(Trap::Exception(Exception::Breakpoint))
            if installed_hart_runtime()
                .is_some_and(|runtime| runtime.hand_over_probe.resolve_returning_trap(tf)) => {}
        Ok(Trap::Exception(exception)) => {
            handle_exception(exception, tf);
        }
        Err(err) => {
            panic!("invalid supervisor trap cause: {err:?}, tf={tf:#x?}");
        }
    }
}

fn run_hart(hart_id: usize, fdt_addr: usize) -> ! {
    // Every hart takes critical sections long before it builds its runtime,
    // and several harts run this prologue concurrently. Seeding `tp` with the
    // hart's own bootstrapping identity here is what keeps those acquires
    // distinguishable; sharing one sentinel makes a second hart's acquire look
    // like the first hart's nested re-acquire and voids mutual exclusion.
    write_hart_identity(ProcessorIdentity::bootstrapping(hart_id));
    // SAFETY: OpenSBI (or `sbi_rt::hart_start` for secondaries) passes a
    // valid device-tree blob physical address in `fdt_addr`, and physical
    // memory is directly addressable before paging is enabled.
    let fdt = unsafe { Fdt::from_ptr(fdt_addr as *const u8) }
        .expect("OpenSBI did not provide a valid FDT");
    let mut cpus = fdt.cpus().filter(|cpu| cpu_is_usable(*cpu));
    let first_cpu = cpus.next().expect("FDT does not describe any usable CPU");
    let hart_count = 1 + cpus.count();
    // Processor ids are the hart ids and the possible set is dense, so the
    // usable harts must be exactly `0..hart_count`: a gap would name a
    // processor the machine cannot start, and an id past the count one
    // the kernel never sizes for.
    for cpu in fdt.cpus().filter(|cpu| cpu_is_usable(*cpu)) {
        let id = cpu.ids().first();
        assert!(
            id < hart_count,
            "FDT describes usable hart {id} but only {hart_count} harts are usable; \
             processor ids are hart ids and must be dense"
        );
    }
    assert!(
        hart_count <= MAX_TRACKED_HARTS,
        "FDT describes {hart_count} harts but this backend tracks at most {MAX_TRACKED_HARTS}"
    );
    let timebase = Timebase::new(first_cpu.timebase_frequency() as u64);
    // QEMU delivers the user payload through `-initrd` and publishes its
    // physical range in `/chosen`; the bytes stay borrowed for the
    // kernel's lifetime, so the range is carved out of the memory the
    // allocator is primed with below.
    let initrd = initrd_range(&fdt);
    let allocator_window = allocator_window();
    // A tree without `numa-node-id` describes one node holding every hart
    // and all of memory.
    let numa = DeviceTreeNuma::new(&fdt, HartIds { harts: hart_count })
        .unwrap_or_else(|error| panic!("FDT NUMA description refused: {error}"));
    let memory_regions = collect_memory_regions(&fdt, allocator_window.clone(), &initrd, &numa);
    let current_hart = ProcessorId::new(hart_id as u16);
    let bootstrap_processor = remember_bootstrap_hart(hart_id);
    mark_hart_online(current_hart);
    // Bring up Sv48 paging on every hart before any allocator or
    // driver work. The bootstrap hart populates the root table once
    // (identity-mapping the kernel's 512 GiB physical window with a
    // single root-level leaf), then every hart writes its own `satp` to
    // switch into paged execution. Identity mapping makes the transition
    // transparent for kernel addresses; the 32 TiB user-VA window above
    // the identity map is owned by `RiscvUserAddressSpace`, which is
    // where the runtime's linear-memory reservations live.
    for region in &memory_regions {
        let (start, end) = (region.start(), region.end());
        assert!(
            end <= vmm::KERNEL_IDENTITY_LIMIT,
            "firmware reports physical memory at {start:#x}..{end:#x}, past the {:#x} the Sv48 \
             kernel identity map reaches",
            vmm::KERNEL_IDENTITY_LIMIT
        );
    }
    if current_hart == bootstrap_processor {
        // SAFETY: only the bootstrap hart executes this branch, once, before
        // any hart activates paging or releases early-boot secondaries.
        unsafe {
            vmm::install_kernel_paging();
        }
        vmm::install_runtime_memory_hooks();
    }
    // SAFETY: `install_kernel_paging` completed on the bootstrap hart before
    // this hart reached here, and every address in flight is identity-mapped.
    unsafe {
        vmm::activate_paging();
    }
    let user_pool = (current_hart == bootstrap_processor).then(|| {
        helios_kernel::prime_bootstrap_allocator(
            memory_regions.iter().copied(),
            &numa,
            bootstrap_processor,
        )
    });

    let debug_state = shared_debug_state(timebase, hart_count, initrd.clone());
    let has_debug_transport = publish_debug_transport(DebugTransport::discover(&fdt));
    let watchdog = shared_watchdog(&fdt);
    let pci = pci::PciHostController::discover(&fdt);
    let pci_virtio = pci.as_ref().map(pci::PciHostController::virtio_functions);
    let iommu_topology = pci.as_ref().and_then(pci::PciHostController::iommu);
    let has_vsock = vsock::has_vsock_device(&fdt, pci_virtio.as_ref());
    // The boot UART carries kernel tracing when a vsock device is present for
    // inspector RPC framing, keeping the UART clear for binary serial RPC on
    // machines without vsock. A machine whose device tree describes no console
    // has no line to carry it at all.
    let console = kernel_console(debug_state.clone(), has_debug_transport && has_vsock);
    let cpu = RiscvCpu::new(bootstrap_processor, hart_count, timebase, fdt_addr);
    let mut devices = DeviceInventory::new();
    if has_debug_transport {
        devices = devices.with_debug_serial();
    }
    if net::has_network_device(&fdt, pci_virtio.as_ref()) {
        devices = devices.with_network();
    }
    let block_device_count = block::count_block_devices(&fdt, pci_virtio.as_ref());
    if block_device_count != 0 {
        devices = devices.with_block_devices(block_device_count);
    }
    if host_fs::has_9p_device(&fdt, pci_virtio.as_ref()) {
        devices = devices.with_host_share();
    }
    if entropy::has_entropy_device(&fdt, pci_virtio.as_ref()) {
        devices = devices.with_entropy_device();
    }
    if balloon::has_balloon_device(&fdt, pci_virtio.as_ref()) {
        devices = devices.with_memory_balloon();
    }
    if has_vsock {
        devices = devices.with_vsock();
    }
    let has_display = gpu::has_display_device(&fdt, pci_virtio.as_ref());
    let input_count = input::count_input_devices(&fdt, pci_virtio.as_ref());
    let has_sound = snd::has_sound_device(&fdt, pci_virtio.as_ref());
    let (measured_boot, measured_boot_discovery) = if current_hart == bootstrap_processor {
        tpm::discover(&fdt, cpu.clone())
    } else {
        (None, helios_tpm::Discovery::NotDescribed)
    };
    let boot_memory =
        collect_boot_memory_metadata(&fdt, fdt_addr, &initrd, &debug_state.payload_digest());
    let kernel = helios_kernel::init_with_watchdog(
        helios_kernel::Platform::with_watchdog(console, cpu.clone(), watchdog.clone())
            .with_topology(
                ProcessorTopology::start_all_secondaries(bootstrap_processor, hart_count)
                    .with_startup_policy(ProcessorStartupPolicy::BootstrapOnly),
            )
            .with_timer_frequency_hz(timebase.frequency())
            .with_dma_model(if iommu_topology.is_some() {
                DmaModel::Iommu
            } else {
                DmaModel::Identity
            })
            .with_devices(devices)
            .with_measured_boot(measured_boot)
            .with_boot_memory(boot_memory),
    );
    if current_hart == bootstrap_processor {
        if measured_boot_discovery.is_refusal() {
            tracing::warn!("{measured_boot_discovery}");
        } else {
            tracing::info!("{measured_boot_discovery}");
        }
    }
    // Only the bootstrap hart brings devices up.
    if let Some(pool) = user_pool {
        if !has_display {
            tracing::info!("no virtio-gpu device discovered; this machine has no display");
        }
        if input_count == 0 {
            tracing::info!("no virtio-input device discovered; this machine has no input device");
        }
        if !has_sound {
            tracing::info!("no virtio-snd device discovered; this machine has no sound device");
        }
        if let Some(pci) = pci.as_ref() {
            pci.reserve_assigned_memory_bars();
        }
        // Confine every virtio-PCI function in its own domain before any
        // driver (including PCI virtio-rng) touches its queues.
        let mut confinement = match (pci.as_ref(), pci_virtio.as_ref(), iommu_topology) {
            (Some(pci), Some(pci_virtio), Some(topology)) => {
                let confined = pci_virtio.addresses();
                let confinement = iommu::confine_devices(pci, topology, &confined);
                let report = confinement.report();
                debug_state.install_iommu_report(report.clone());
                kernel.spawn_detached(iommu::watch_faults(
                    confinement.device(),
                    report,
                    kernel.timer(),
                ));
                Some(confinement)
            }
            _ => {
                tracing::info!(
                    "no virtio-iommu in the device tree topology; device DMA reaches physical \
                     memory directly"
                );
                None
            }
        };
        let mut dma_arenas = iommu::RiscvDmaArenas::new(helios_kernel::UserPoolChunks::new(pool));
        // The entropy device comes up after IOMMU confinement (so a PCI
        // virtio-rng is never touched unconfined) and before the root DRBG
        // is seeded (so a platform whose firmware leaves no
        // `/chosen/rng-seed` still seeds from hardware entropy).
        let entropy_device = entropy::bring_up(
            &fdt,
            pci.as_ref(),
            pci_virtio.as_ref(),
            &mut dma_arenas,
            confinement.as_mut(),
            hart_count,
        );
        // No VM generation ID window is discovered on this platform yet,
        // so the machine generation moves only through `advance`.
        let generation = helios_kernel::MachineGeneration::new(None);
        debug_state.install_machine_generation(generation.clone());
        let root_entropy = helios_kernel::seed_root_entropy(
            &cpu,
            helios_hal::entropy::device_tree_seed(&fdt),
            entropy_device.as_ref().map(|entropy| &entropy.device),
            generation,
        );
        debug_state.install_root_entropy(root_entropy.clone());
        // Settle the TPM-sealed machine seed early so `HibernateAuthKey` is
        // available for the early-boot resume probe below without settling twice.
        helios_kernel::settle_boot_signing_keys(&kernel, &debug_state);
        // The calendar is read once, on the bootstrap hart, before any
        // component can ask what time it is. The hart timer carries wall
        // time forward from that reading; only a machine restore re-reads
        // it, which the reactions task does with the same clock.
        let rtc = rtc::discover(&fdt);
        match &rtc {
            Some(rtc) => {
                debug_state.seed_wall_clock(cpu.now().ticks(), rtc);
            }
            None => {
                tracing::warn!(
                    "no goldfish RTC in the device tree; the wall clock reads as uptime"
                );
            }
        }
        let mut hibernate_devices = hibernate::RiscvHibernateDevices::new(
            cpu.clone(),
            debug_state.machine_generation_handle(),
        );
        hibernate_devices.iommu = confinement.as_ref().map(iommu::Confinement::device);

        // A machine may carry several PLICs — QEMU's `virt` gives every
        // socket its own and wires devices to different ones — so each
        // PLIC is its own domain, taken by one hart with a context in
        // it, and each device attaches to the domain its node's
        // interrupt parent names.
        let mut domains = net::InterruptDomains::discover(&fdt, bootstrap_processor);
        // The device path's platform surface comes up before any grant
        // is published, which the registry enforces.
        device::install_hooks();
        if let Some(transport) = DEBUG_TRANSPORT.get().copied() {
            assert!(
                domains.takes(transport.plic_line.controller),
                "the device tree wires the debug UART to the interrupt controller at {:#x}, in \
                 which no hart has a PLIC supervisor-external context; the serial line could \
                 only be polled",
                transport.plic_line.controller.base()
            );
            domains.attach_debug_serial(
                transport.plic_line,
                DebugTransport::console().interrupt_handler::<DebugTransport>(),
            );
        }
        if let Some(network) = net::install_network_service(
            &cpu,
            &kernel,
            &fdt,
            pci.as_ref(),
            pci_virtio.as_ref(),
            &mut dma_arenas,
            confinement.as_mut(),
            &debug_state,
        ) {
            hibernate_devices.network = Some(network.device.device().clone());
            domains.attach_network(network);
        }
        if let Some(host_fs) = host_fs::install(
            &cpu,
            &fdt,
            pci.as_ref(),
            pci_virtio.as_ref(),
            &mut dma_arenas,
            confinement.as_mut(),
            &debug_state,
        ) {
            hibernate_devices.host_fs = Some(host_fs.transport.clone());
            domains.attach_host_fs(host_fs);
        }
        if let Some(entropy) = entropy_device {
            hibernate_devices.entropy = Some(entropy.device.device().clone());
            entropy::install(&kernel, &entropy, root_entropy.clone());
            domains.attach_entropy(entropy);
        }
        if let Some(balloon) = balloon::install(
            &cpu,
            &kernel,
            &fdt,
            pci.as_ref(),
            pci_virtio.as_ref(),
            &mut dma_arenas,
            confinement.as_mut(),
            debug_state.machine_generation_handle(),
        ) {
            hibernate_devices.balloon = Some(balloon.handler.device().clone());
            debug_state.install_memory_balloon(balloon.handle.clone());
            domains.attach_balloon(balloon);
        }
        if let Some(vsock) = vsock::install(
            &kernel,
            &cpu,
            &fdt,
            pci.as_ref(),
            pci_virtio.as_ref(),
            &mut dma_arenas,
            confinement.as_mut(),
            &debug_state,
        ) {
            hibernate_devices.vsock = Some(vsock.device.device().clone());
            domains.attach_vsock(vsock);
        }
        if let Some(display) = gpu::install(
            &cpu,
            &kernel,
            &fdt,
            pci.as_ref(),
            pci_virtio.as_ref(),
            &mut dma_arenas,
            confinement.as_mut(),
            &debug_state,
        ) {
            hibernate_devices.display = Some(display.device.device().clone());
            domains.attach_display(display);
        }
        for device in input::install(
            &cpu,
            &kernel,
            &fdt,
            pci.as_ref(),
            pci_virtio.as_ref(),
            &mut dma_arenas,
            confinement.as_mut(),
            &debug_state,
        ) {
            hibernate_devices
                .inputs
                .push(device.device.device().clone());
            domains.attach_input(device);
        }
        if let Some(sound) = snd::install(
            &cpu,
            &kernel,
            &fdt,
            pci.as_ref(),
            pci_virtio.as_ref(),
            &mut dma_arenas,
            confinement.as_mut(),
            &debug_state,
        ) {
            hibernate_devices.sound = Some(sound.device.device().clone());
            domains.attach_sound(sound);
        }
        for block in block::install(
            &cpu,
            &kernel,
            &fdt,
            pci.as_ref(),
            pci_virtio.as_ref(),
            &mut dma_arenas,
            confinement.as_mut(),
            &debug_state,
            root_entropy.clone(),
        ) {
            hibernate_devices.blocks.push(block.device.device().clone());
            domains.attach_block(block);
        }
        kernel.spawn_detached(helios_kernel::maintain_dma_arenas(
            dma_arenas,
            kernel.timer(),
        ));
        // Early-boot hibernate resume probe: runs on the bootstrap hart with
        // interrupts disabled, BEFORE starting secondary harts, enabling
        // swap/init, or unmasking interrupts. If a valid authenticated
        // hibernate image is present on `"helios-hibernate"`, enters the
        // restore trampoline and never returns.
        hibernate::probe_and_resume_if_present(
            &cpu,
            &kernel,
            &watchdog,
            &debug_state,
            pool,
            &root_entropy,
            rtc.as_ref(),
            &mut hibernate_devices,
            &[],
        );
        helios_kernel::install_generation_reactions(&kernel, debug_state.clone(), rtc);
        let grants = device::publish_grants(&fdt, debug_state.device_grants(), &domains);
        for (line, route) in grants {
            domains.attach_device(line, route);
        }
        net::publish_interrupt_domains(domains);
        helios_kernel::disable_swap(helios_kernel::SwapDisabled::NoSwapHooks);
        release_early_boot_harts();
    }
    let hart_runtime = HartRuntime {
        trap_stack: trap::allocate_trap_stack(),
        guest_stack_limit: AtomicUsize::new(usize::MAX),
        hart_id: current_hart,
        timer: kernel.timer(),
        wasmtime_tls: WasmtimeTlsSlots::new(),
        external_interrupts: net::HartInterrupts::of(current_hart),
        program_service: Once::new(),
        hand_over_stack: trap::allocate_trap_stack(),
        hand_over_probe: trap::HandOverProbe::new(),
    };
    hart_runtime.install();
    // Only now, on the hart itself: the firmware reset this hart's PLIC
    // contexts when it started it, after the bootstrap hart's bring-up.
    if let Some(interrupts) = hart_runtime.external_interrupts {
        interrupts.open();
    }
    // Every hart's timer preempts the guest running on it, so every hart
    // holds the service: the bootstrap hart installs it, and the others,
    // which it starts only afterwards, take the installed one.
    let program_service = helios_kernel::install_component_host_program_service(
        &kernel,
        &cpu,
        &debug_state,
        read_debug_serial,
        DEBUG_SERIAL_WRITER,
    )
    .unwrap_or_else(|| {
        debug_state.program_service().unwrap_or_else(|| {
            panic!("RISC-V hart {hart_id} started before program service installation")
        })
    });
    hart_runtime.program_service.call_once(|| program_service);
    // SAFETY: `hart_runtime` is installed with its trap stack, hand-over
    // stack, external interrupts, and `program_service` initialised.
    unsafe {
        configure_interrupts();
    }
    if current_hart == bootstrap_processor {
        for processor in
            helios_kernel::component_host_processors_to_start(hart_count, bootstrap_processor)
        {
            cpu.start_processor(processor);
        }
    }
    helios_kernel::run_component_host_processor_forever(
        cpu,
        kernel,
        debug_state,
        read_debug_serial,
        DEBUG_SERIAL_WRITER,
    );
}

fn shared_debug_state(
    timebase: Timebase,
    hart_count: usize,
    initrd: Range<usize>,
) -> debug_state::RuntimeState {
    DEBUG_STATE
        .call_once(|| {
            // The Sv48 identity map is already active, so the initrd's
            // physical range reads directly.
            // SAFETY: `initrd` is a non-empty valid physical range from `/chosen`
            // reserved out of allocator memory, readable through the identity map,
            // and immutable for the kernel's lifetime.
            let bytes =
                unsafe { core::slice::from_raw_parts(initrd.start as *const u8, initrd.len()) };
            let payload = helios_kernel::BootPayload::parse(bytes).unwrap_or_else(|error| {
                panic!("initrd is not a valid helios-bootfs payload: {error}")
            });
            debug_state::RuntimeState::new(
                timebase,
                hart_count,
                riscv::register::time::read64(),
                payload,
                // The RISC-V `Cpu` answers no feature probe (`native_feature_probe`).
                helios_kernel::GuestIsa::for_build_target(None),
            )
        })
        .clone()
}

/// Whether a `/cpus/cpu*` node describes a hart the machine can run.
///
/// The device tree specification defaults `status` to `okay` when absent;
/// `disabled` is a hart that is present but not started (it may be brought
/// up later), and `reserved` and `fail` are not usable at all. None of the
/// three is a processor this kernel's possible set holds.
fn cpu_is_usable(cpu: fdt::standard_nodes::Cpu<'_, '_>) -> bool {
    cpu.property("status").is_none_or(|status| {
        status
            .as_str()
            .unwrap_or_else(|| panic!("a cpu node's status is not a string"))
            == "okay"
    })
}

fn shared_watchdog(fdt: &Fdt<'_>) -> watchdog::RiscvWatchdog {
    WATCHDOG_STATE.call_once(|| watchdog::discover(fdt)).clone()
}

#[repr(C)]
struct RiscvCaptureResult {
    status: u64,
    handoff_phys: u64,
}

unsafe extern "C" {
    static __stext: u8;
    static __etext: u8;
    static __srodata: u8;
    static __erodata: u8;
    static __sdata: u8;
    static __edata: u8;
    static __sbss: u8;
    static __ebss: u8;
    static __suninit: u8;
    static __euninit: u8;
    static __estack: u8;
    static __sstack: u8;
    static _stack_start: u8;
    static _secondary_start: u8;
    static _hart_restart: u8;
    fn _release_mp_harts();
    fn __helios_riscv_capture_bsp_state(ctx: *mut Riscv64SnapshotContext) -> RiscvCaptureResult;
}

const _: () = {
    assert!(core::mem::offset_of!(Riscv64SnapshotContext, ra) == 0x00);
    assert!(core::mem::offset_of!(Riscv64SnapshotContext, sp) == 0x08);
    assert!(core::mem::offset_of!(Riscv64SnapshotContext, gp) == 0x10);
    assert!(core::mem::offset_of!(Riscv64SnapshotContext, tp) == 0x18);
    assert!(core::mem::offset_of!(Riscv64SnapshotContext, s) == 0x20);
    assert!(core::mem::offset_of!(Riscv64SnapshotContext, fs) == 0x80);
    assert!(core::mem::offset_of!(Riscv64SnapshotContext, fcsr) == 0xe0);
};

fn riscv_section_range(start_sym: *const u8, end_sym: *const u8) -> KernelSectionRange {
    let start = start_sym.addr() as u64;
    let end = end_sym.addr() as u64;
    let len = end
        .checked_sub(start)
        .unwrap_or_else(|| panic!("RISC-V kernel section end {end:#x} precedes start {start:#x}"));
    KernelSectionRange::new(start, start, len)
}

fn collect_boot_memory_metadata(
    fdt: &Fdt<'_>,
    fdt_addr: usize,
    initrd: &Range<usize>,
    payload_sha256: &[u8; 32],
) -> BootMemoryMetadata {
    let uninit = riscv_section_range(&raw const __suninit, &raw const __euninit);
    let stack = riscv_section_range(&raw const __estack, &raw const __sstack);
    let mut metadata = BootMemoryMetadata {
        kernel_sections: KernelImageSections {
            text: riscv_section_range(&raw const __stext, &raw const __etext),
            rodata: riscv_section_range(&raw const __srodata, &raw const __erodata),
            data: riscv_section_range(&raw const __sdata, &raw const __edata),
            bss: riscv_section_range(&raw const __sbss, &raw const __ebss),
            uninit: (!uninit.is_empty()).then_some(uninit),
            stack: (!stack.is_empty()).then_some(stack),
        },
        device_tree_blob: Some(BootPhysicalRange::from_start_len(
            fdt_addr as u64,
            fdt.total_size() as u64,
        )),
        boot_payload: Some(BootPayloadMetadata {
            physical_address: initrd.start as u64,
            len: initrd.len() as u64,
            sha256: *payload_sha256,
        }),
        physical_memory_offset: 0,
        ..BootMemoryMetadata::default()
    };

    for region in fdt
        .all_nodes()
        .filter(|node| {
            node.property("device_type")
                .is_some_and(|property| property.value == b"memory\0")
        })
        .flat_map(|node| {
            node.reg().unwrap_or_else(|| {
                panic!("FDT memory node {} has no usable reg property", node.name)
            })
        })
    {
        let start = region.starting_address as u64;
        let end = start
            .checked_add(region.size.unwrap_or(0) as u64)
            .expect("FDT memory region overflows u64");
        let _ = metadata.firmware_memory_map.try_push(BootMemoryRegion {
            start,
            end,
            kind: BootMemoryKind::Usable,
        });
    }

    metadata
}

fn allocator_window() -> Range<usize> {
    let start = align_up(
        core::ptr::addr_of!(_stack_start).addr(),
        core::mem::align_of::<usize>(),
    );
    assert!(
        core::ptr::addr_of!(__ebss).addr() < start,
        "riscv stack must be linked after kernel bss"
    );
    start..usize::MAX
}

/// The physical range QEMU placed the `-initrd` payload in, published
/// in `/chosen` as `linux,initrd-start`/`linux,initrd-end`.
///
/// riscv64 does not boot through Limine — its Limine protocol entry is
/// a higher-half handoff with paging already enabled, a different
/// backend contract — so the payload arrives as an initrd instead.
/// Absent or malformed properties panic: a kernel without the payload
/// has no init to run.
fn initrd_range(fdt: &Fdt<'_>) -> Range<usize> {
    let chosen = fdt
        .find_node("/chosen")
        .unwrap_or_else(|| panic!("FDT has no /chosen node to name the initrd"));
    let property = |name: &str| {
        chosen
            .property(name)
            .and_then(|property| property.as_usize())
            .unwrap_or_else(|| {
                panic!("FDT /chosen/{name} is missing or malformed; the payload needs -initrd")
            })
    };
    let start = property("linux,initrd-start");
    let end = property("linux,initrd-end");
    assert!(
        start < end,
        "FDT /chosen initrd range {start:#x}..{end:#x} is empty or reversed"
    );
    start..end
}

/// The firmware identity of each processor. A hart's [`ProcessorId`] is its
/// hart id (`run_hart`), and a devicetree cpu node's `reg` is the hart id
/// too, so the mapping is the identity.
struct HartIds {
    harts: usize,
}

impl ProcessorIdentities for HartIds {
    fn processor_count(&self) -> usize {
        self.harts
    }

    fn hardware_id(&self, processor: ProcessorId) -> u64 {
        u64::from(processor.id())
    }
}

/// Capacity for the allocator regions: a devicetree carries one `memory`
/// node per range, and the initrd carve-out splits one of them in two. A
/// tree that describes more is refused by name below.
const MAX_MEMORY_REGIONS: usize = 16;

/// Every `reg` range of every node whose `device_type` is `memory`, clipped
/// to the allocator window with the initrd taken out.
fn collect_memory_regions<Numa: NumaTopology>(
    fdt: &Fdt<'_>,
    allocator_window: Range<usize>,
    initrd: &Range<usize>,
    numa: &Numa,
) -> ArrayVec<MemoryRegion, MAX_MEMORY_REGIONS> {
    let mut regions = ArrayVec::new();
    let mut reserved = BootReservedRanges::new();
    reserved.reserve(initrd.clone());

    for region in fdt
        .all_nodes()
        .filter(|node| {
            node.property("device_type")
                .is_some_and(|property| property.value == b"memory\0")
        })
        .flat_map(|node| {
            node.reg().unwrap_or_else(|| {
                panic!("FDT memory node {} has no usable reg property", node.name)
            })
        })
        .map(|region| {
            let start = region.starting_address as usize;
            let end = start
                .checked_add(region.size.unwrap())
                .expect("FDT memory region overflows usize");

            start..end
        })
        .filter_map(|region| intersect(region, allocator_window.clone()))
        .map(|region| BootMemoryRegion {
            start: region.start as u64,
            end: region.end as u64,
            kind: BootMemoryKind::Usable,
        })
        // SAFETY: the memory nodes are RAM nothing else owns, reachable at
        // its physical address through the kernel identity map, and the
        // initrd is reserved out.
        .flat_map(|region| unsafe { usable_node_regions(region, &reserved, 0, numa) })
    {
        regions.try_push(region).unwrap_or_else(|_| {
            panic!("FDT described more memory regions than the kernel supports")
        });
    }

    regions
}

fn intersect(left: Range<usize>, right: Range<usize>) -> Option<Range<usize>> {
    let start = left.start.max(right.start);
    let end = left.end.min(right.end);

    (start < end).then_some(start..end)
}

use helios_hal::align_up;

fn remember_bootstrap_hart(current_hart: usize) -> ProcessorId {
    match BOOT_HART_ID.compare_exchange(
        UNINITIALIZED_BOOT_HART,
        current_hart,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => ProcessorId::new(current_hart as u16),
        Err(bootstrap_hart) => ProcessorId::new(bootstrap_hart as u16),
    }
}

fn hart_bit(hart: ProcessorId) -> usize {
    let index = usize::from(hart.id());
    assert!(
        index < MAX_TRACKED_HARTS,
        "hart {index} is outside the {MAX_TRACKED_HARTS} harts this backend tracks"
    );

    1 << index
}

/// Publishes the current hart as a valid IPI target.
///
/// Called before the hart can reach any parking point, so a waker that misses
/// the publication still cannot lose a wakeup: the hart drains the run queues
/// after this point.
fn mark_hart_online(hart: ProcessorId) {
    ONLINE_HARTS.fetch_or(hart_bit(hart), Ordering::Release);
}

fn hart_is_online(hart: ProcessorId) -> bool {
    ONLINE_HARTS.load(Ordering::Acquire) & hart_bit(hart) != 0
}

/// Orders every hart's instruction fetch after the stores made to code memory
/// so far.
///
/// `fence.i` is the only ordering RISC-V defines between a store to an
/// instruction's memory and a fetch of it, and it affects only the hart that
/// executes it. The current hart fences itself, then `sbi_remote_fence_i`
/// (SBI specification, chapter 8 "RFENCE Extension", function 0) has every
/// hart the firmware runs execute `fence.i`.
fn fence_instruction_streams() {
    // SAFETY: `fence.i` synchronises this hart's instruction fetches with
    // stores to executable memory and touches no memory or stack operands.
    unsafe {
        core::arch::asm!("fence.i", options(nostack, preserves_flags));
    }
    // A hart mask base of `usize::MAX` addresses all available harts.
    let ret = sbi_rt::remote_fence_i(sbi_rt::HartMask::from_mask_base(0, usize::MAX));
    assert!(
        ret.is_ok(),
        "SBI remote_fence_i failed: error={} value={}",
        ret.error,
        ret.value
    );
}

fn release_early_boot_harts() {
    // `_mp_hook` keeps every non-winning hart in a tiny early-boot spin loop
    // until the winner has completed the runtime's RAM initialization. Once
    // Rust code is safe to execute, publish the release gate so the other harts
    // can proceed into `helios_kernel::init`, which will park them again until
    // full kernel bootstrap is complete.
    // SAFETY: bootstrap initialisation of shared early-boot state is complete
    // and secondary harts are spinning in `_mp_hook` waiting on this release.
    unsafe {
        _release_mp_harts();
    }
}

fn hart_status(hart: ProcessorId) -> usize {
    let ret = sbi_rt::hart_get_status(hart.id() as usize);
    if ret.is_ok() {
        return ret.value;
    }

    panic!(
        "failed to query hart {} via SBI HSM: error={} value={}",
        hart.id(),
        ret.error,
        ret.value
    );
}

fn current_hart_runtime() -> &'static HartRuntime {
    installed_hart_runtime().expect("hart runtime is not installed")
}

pub(crate) fn current_hart_id() -> ProcessorId {
    current_hart_runtime().hart_id
}

/// The machine's debug UART, published by the first hart to discover it.
///
/// The port is a machine-wide device: every hart resolves the same
/// `/chosen` node to the same register block, so it is described once
/// here rather than copied into each hart's runtime.
static DEBUG_TRANSPORT: Once<DebugTransport> = Once::new();

/// The console that owns the right to write to that port.
///
/// Every byte the kernel or a guest puts on the boot UART is ordered by
/// this one transmit role: the kernel log, the debugger's stage markers
/// and the inspector's RPC frames alike.
static DEBUG_CONSOLE: helios_kernel::DebugConsole = helios_kernel::DebugConsole::new();

/// Publishes the discovered UART, and reports whether this machine has
/// one at all.
///
/// Every hart calls this with the description it read from the same
/// device tree, so the value is installed once and read afterwards.
fn publish_debug_transport(discovered: Option<DebugTransport>) -> bool {
    if let Some(transport) = discovered {
        DEBUG_TRANSPORT.call_once(|| {
            // The interrupt-enable register shares its offset with the
            // high divisor latch, so the line-control register is set
            // here — eight data bits, one stop bit, no parity, latch
            // closed — rather than inherited from whatever the firmware
            // left: an IER write behind an open latch would corrupt the
            // divisor and never arm the line. Firmware already picked
            // the divisor; it is not touched.
            Uart::new(transport.uart_base).set_lcr(
                WordLength::EIGHT,
                StopBits::ONE,
                ParityBit::DISABLE,
                ParitySelect::EVEN,
                StickParity::DISABLE,
                Break::DISABLE,
                DLAB::CLEAR,
            );
            transport
        });
    }
    DEBUG_TRANSPORT.get().is_some()
}

impl DebugSerialAccess for DebugTransport {
    type Port = Self;

    fn port() -> Self {
        *DEBUG_TRANSPORT
            .get()
            .expect("the debug UART was reached before the device tree described it")
    }

    fn console() -> &'static helios_kernel::DebugConsole {
        &DEBUG_CONSOLE
    }
}

fn read_debug_serial(buffer: &mut alloc::vec::Vec<u8>, max_bytes: u32) {
    helios_kernel::read_debug_serial::<DebugTransport>(buffer, max_bytes);
}

/// The kernel's writer for this machine's debug UART.
///
/// Every byte the kernel or a guest puts on the port goes through the
/// console this names; the backend supplies only the accessor.
const DEBUG_SERIAL_WRITER: helios_kernel::DebugSerialWriter =
    helios_kernel::DebugSerialWriter::of::<DebugTransport>();

#[unsafe(no_mangle)]
extern "C" fn wasmtime_tls_get(slot: usize) -> *mut u8 {
    installed_hart_runtime().map_or(core::ptr::null_mut(), |runtime| {
        runtime.wasmtime_tls.get(slot)
    })
}

#[unsafe(no_mangle)]
extern "C" fn wasmtime_tls_set(slot: usize, ptr: *mut u8) {
    current_hart_runtime().wasmtime_tls.set(slot, ptr);
}

#[unsafe(no_mangle)]
extern "C" fn wasmtime_init_traps(handler: KernelNativeTrapHandler) -> i32 {
    helios_kernel::install_native_trap_handler(handler);
    0
}

/// # Safety
/// Must be called once per hart after [`HartRuntime::install`] has seeded its
/// trap stack and hand-over stack and populated `program_service`.
unsafe fn configure_interrupts() {
    // SAFETY: the caller guarantees `HartRuntime::install` already seeded
    // `sscratch` with this hart's trap stack.
    unsafe { trap::install_trap_vector() };
    // SAFETY: the trap vector is installed, so supervisor software interrupts
    // can be handled safely.
    unsafe { riscv::register::sie::set_ssoft() };
    // SAFETY: the trap vector and timer are ready to handle supervisor timer
    // interrupts.
    unsafe { riscv::register::sie::set_stimer() };
    // SAFETY: the trap vector and PLIC dispatch are ready to handle
    // supervisor external interrupts.
    unsafe { riscv::register::sie::set_sext() };
    // SAFETY: `stvec` and `sie` are configured, so enabling supervisor
    // interrupts is safe.
    unsafe { riscv::register::sstatus::set_sie() };
    // The entry is live from here, so this is the first moment the hart can
    // prove it round-trips the floating-point file. §3.4: every hart proves
    // it for itself, because `FS` and the trap vector are per-hart state.
    trap::verify_trap_preserves_fp_state();
    // `sscratch` and the hand-over stack are per-hart state too.
    trap::verify_trap_hand_over();
}

/// Handles one synchronous exception.
///
/// Returns only when the fault was resolved in place and the trap
/// epilogue should restore the interrupted context and run the faulting
/// instruction again. Every other path diverges: into the hand-over to
/// the runtime's trap handler (`trap::hand_over_trap`), which leaves the
/// trap stack for good, or into a panic.
fn handle_exception(exception: Exception, tf: &TrapFrame) {
    let stval = riscv::register::stval::read();
    // Fiber stacks commit ahead of the guest through the stack-reserve
    // callback; a fault on an uncommitted page inside one fails fast here,
    // and the guard page below one stays a stack-overflow fault.
    let stack_fault = match kernel_exception_faulting_address(exception, stval) {
        Some(addr) => helios_kernel::classify_stack_fault(helios_hal::vmm::VirtAddr::new(addr)),
        None => helios_kernel::StackFault::Elsewhere,
    };
    match trap_origin(tf) {
        TrapOrigin::Kernel => {
            let Some(cause) = kernel_exception_cause(exception) else {
                panic!(
                    "kernel exception: {exception:?}, sepc={:#x}, stval={:#x}{stack_fault}, \
                     tf={tf:#x?}",
                    tf.sepc, stval,
                );
            };
            let refusal = trap::hand_over_trap(
                trap::TrapHandOver {
                    exception: KernelException {
                        cause,
                        instruction_pointer: tf.sepc,
                        frame_pointer: tf.general.s0,
                        faulting_address: kernel_exception_faulting_address(exception, stval),
                    },
                    cause: exception,
                    stval,
                    stack_fault,
                    frame_address: core::ptr::from_ref(tf) as usize,
                    frame: *tf,
                },
                tf,
            );
            panic!(
                "kernel exception: {exception:?}, sepc={:#x}, stval={:#x}{stack_fault}, \
                 tf={tf:#x?}; not handed to the runtime because {refusal}",
                tf.sepc, stval,
            )
        }
        TrapOrigin::User => handle_user_exception(exception, stval, tf),
    }
}

fn kernel_exception_cause(exception: Exception) -> Option<KernelExceptionCause> {
    match exception {
        Exception::InstructionMisaligned
        | Exception::InstructionFault
        | Exception::InstructionPageFault => Some(KernelExceptionCause::InstructionFault),
        Exception::IllegalInstruction => Some(KernelExceptionCause::IllegalInstruction),
        Exception::Breakpoint => Some(KernelExceptionCause::Breakpoint),
        Exception::LoadMisaligned
        | Exception::LoadFault
        | Exception::StoreMisaligned
        | Exception::StoreFault
        | Exception::LoadPageFault
        | Exception::StorePageFault => Some(KernelExceptionCause::DataFault),
        Exception::UserEnvCall | Exception::SupervisorEnvCall => None,
    }
}

fn kernel_exception_faulting_address(exception: Exception, stval: usize) -> Option<usize> {
    match exception {
        Exception::InstructionMisaligned
        | Exception::InstructionFault
        | Exception::InstructionPageFault
        | Exception::LoadMisaligned
        | Exception::LoadFault
        | Exception::StoreMisaligned
        | Exception::StoreFault
        | Exception::LoadPageFault
        | Exception::StorePageFault => Some(stval),
        Exception::IllegalInstruction
        | Exception::Breakpoint
        | Exception::UserEnvCall
        | Exception::SupervisorEnvCall => None,
    }
}

fn handle_user_exception(exception: Exception, stval: usize, tf: &TrapFrame) -> ! {
    panic!(
        "unhandled user trap: exception={exception:?}, sepc={:#x}, stval={:#x}, tf={tf:#x?}",
        tf.sepc, stval,
    )
}

/// The port a panicking hart writes its report to.
///
/// SBI, not the debugger's transport: firmware answers whatever state
/// the kernel left the machine in, and a byte it refuses is a byte
/// nothing can be done about here.
struct PanicConsolePort;

impl helios_kernel::PanicSerial for PanicConsolePort {
    fn write_bytes(bytes: &[u8]) {
        for &byte in bytes {
            if sbi_rt::console_write_byte(byte).is_err() {
                return;
            }
        }
    }
}

fn fatal_panic(info: &core::panic::PanicInfo<'_>) -> ! {
    mask_interrupts();

    // Nothing follows the report: the hart shuts down next.
    helios_kernel::emit_panic_report::<PanicConsolePort>(info);

    // SBI shutdown is a request, not a guarantee: a firmware that refuses it
    // returns here, and the hart must not run on past a fatal panic.
    sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::NoReason);
    halt_forever()
}

fn mask_interrupts() {
    riscv::interrupt::supervisor::disable();
    // SAFETY: masking all supervisor interrupts on a panicking hart before
    // emitting the panic report and halting.
    unsafe { riscv::register::sie::clear_ssoft() };
    // SAFETY: masking all supervisor interrupts on a panicking hart before
    // emitting the panic report and halting.
    unsafe { riscv::register::sie::clear_stimer() };
    // SAFETY: masking all supervisor interrupts on a panicking hart before
    // emitting the panic report and halting.
    unsafe { riscv::register::sie::clear_sext() };
    compiler_fence(Ordering::SeqCst);
}

fn halt_forever() -> ! {
    loop {
        riscv::asm::wfi();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TrapOrigin {
    Kernel,
    User,
}

fn trap_origin(tf: &TrapFrame) -> TrapOrigin {
    if tf.sstatus & SSTATUS_SPP_BIT != 0 {
        TrapOrigin::Kernel
    } else {
        TrapOrigin::User
    }
}

fn current_hart_runtime_ptr() -> usize {
    let runtime_ptr: usize;
    // SAFETY: reading `tp` has no side effects and modifies no memory or flags.
    unsafe {
        asm!("mv {}, tp", out(reg) runtime_ptr, options(nomem, nostack, preserves_flags));
    }
    runtime_ptr
}

/// The identity this hart carries in `tp`: its bootstrapping form until
/// [`HartRuntime::install`] replaces it with the runtime address.
fn read_hart_identity() -> ProcessorIdentity {
    let word = NonZeroUsize::new(current_hart_runtime_ptr())
        .expect("tp lost the hart identity `run_hart` seeded");
    ProcessorIdentity::from_raw(word)
}

fn write_hart_identity(identity: ProcessorIdentity) {
    // SAFETY: `tp` is reserved by this kernel for the current hart's
    // `ProcessorIdentity` word; `options(nostack, preserves_flags)` holds.
    unsafe {
        asm!("mv tp, {}", in(reg) identity.raw(), options(nostack, preserves_flags));
    }
}

/// The installed runtime, or `None` while the hart still carries only its
/// bootstrapping identity.
fn installed_hart_runtime() -> Option<&'static HartRuntime> {
    let address = read_hart_identity().runtime_address()?;
    // SAFETY: only `HartRuntime::install` publishes a runtime address, and it
    // does so from a `&'static HartRuntime`.
    Some(unsafe { &*(address.get() as *const HartRuntime) })
}

/// The executing hart's guest stack-limit word, the location the kernel's
/// engines publish stack limits to
/// (`helios_hal::cpu::GUEST_STACK_LIMIT_OFFSET`).
#[unsafe(no_mangle)]
extern "C" fn wasmtime_processor_stack_limit() -> *mut usize {
    current_hart_runtime().guest_stack_limit.as_ptr()
}

#[unsafe(no_mangle)]
extern "C" fn wasmtime_parking_wait(timeout_nanos: u64) -> bool {
    helios_kernel::park_wasmtime_waiter(&current_hart_runtime().timer, timeout_nanos)
}

#[unsafe(no_mangle)]
extern "C" fn wasmtime_parking_unpark() {
    helios_kernel::unpark_wasmtime_waiters();
}

#[unsafe(no_mangle)]
extern "C" fn wasmtime_monotonic_nanos() -> u64 {
    helios_kernel::wasmtime_monotonic_nanos(&current_hart_runtime().timer)
}
