//! The Linux process host: a static Linux executable launched through the
//! program service, as a wasm program is, run natively through the
//! platform's [`helios_hal::native`] capability.
//!
//! Each thread of a Linux process runs on its own executor task with its own
//! [`UserContext`] and [`Process`] handle, sharing one [`UserSpace`] and one
//! underlying process state (descriptor table, futex queues, program break
//! and process attributes). Tasks spawned by `clone` / `clone3` enter the
//! instance's global home-node queue (`InstanceSpawner::try_spawn_detached`),
//! so online processors steal and execute threads of one process concurrently
//! across SMP. Its exit status, or the signal that ended it, reaches the
//! parent through the child's exit channel once every thread of the group has
//! exited and dropped its handles.
//!
//! # Concurrency
//!
//! - User slices and address-space mutations synchronize inside [`UserSpace`],
//!   which shoots down stale translations across active processors before
//!   reclaiming physical frames; multi-step VM compositions serialize on the
//!   process's shared address-space lock in `helios-linux`.
//! - Process-wide state in [`LinuxShared`] uses lock-free atomics for summed
//!   processor ticks, fatal-error latch and live spawned-task count, plus a
//!   bounded non-awaiting `spin::Mutex` for wall-clock offset updates.
//! - Each thread task checks instance condemnation, thread-group exit and
//!   process signals before every user slice and again after arming its
//!   `NotifyWaiter`s around every suspended system call, so `exit_group`, a
//!   fatal fault, OOM, a signal or a kill wakes every parked sibling at once
//!   and stops running slices at the next timer preemption.

use super::*;
use crate::{
    ComponentFsNodeKind, Ipv4Cidr as KernelIpv4Cidr, Ipv4Route as KernelIpv4Route, LinkSourceCap,
    MulticastCap, NetworkAdminCap, NetworkControlError, NetworkPortId, PrivilegedBindCap,
    SetWallClockCap, SymlinkCreateCap, SymlinkReadCap, TcpCap, TerminalAuthorityRights,
    TerminalInputCap, TerminalOutputCap, TtyControlCap, UdpCap,
};
use core::num::NonZeroU32;
use core::ops::ControlFlow;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use helios_hal::fs::{FsError, Landed, NodeKind, RenameMode, WritePosition};
use helios_hal::native::{
    FaultKind, NativeError, NativeExecution, NativeUnavailable, Stop, UserContext, UserFault,
    UserSpace,
};
use helios_hal::pmm::PhysFrame;
use helios_hal::vmm::{PageFlags, VirtAddr, VirtRange};
use helios_linux::abi::{self, Abi};
use helios_linux::elf::{self, Image};
use helios_linux::syscall::{
    self, AccessCheck, Call, Denied, DirListEntry, EpollData, Exit, FileAccess, FileStat,
    Filesystem, LinkOptions, MapError, MemoryFault, MemoryTotals, OpenRequest, Process,
    ProcessSignals, READY_ERR, READY_HUP, READY_IN, READY_OUT, Region, Resource, Resources,
    SignalDelivery, SpawnError, SpawnedThread, Start, StdinTryRead, Stdio, Stream, SyscallOutcome,
    SyscallRestart, System, Termios, TermiosAction, Thread, TimeUpdate, Tty, TtyError, TtyStream,
    UserMemory, VirtualMemory, Winsize, WriteError,
};
use helios_sync::{TryRead, TryWrite};

/// The ELF identification bytes every ELF file starts with (System V gABI,
/// `e_ident[EI_MAG0..EI_MAG3]`).
const ELF_MAGIC: &[u8] = b"\x7fELF";

/// Whether `bytes` are an ELF file, which only the Linux host runs.
pub(super) fn is_linux_elf(bytes: &[u8]) -> bool {
    bytes.starts_with(ELF_MAGIC)
}

/// A validated static Linux executable, ready to map into a new process.
pub(super) struct LinuxExecutable {
    image: Bytes,
    abi: Abi,
}

impl LinuxExecutable {
    /// Validates `image` for this platform. Refused when the platform has
    /// no native execution or its processor lacks a protection the
    /// isolation contract requires, when no Linux ABI is decoded for its
    /// instruction set, or when the image is not one the loader maps.
    pub(super) fn load<CpuImpl: Cpu>(
        cpu: &CpuImpl,
        image: Bytes,
    ) -> Result<Self, ProgramExecError> {
        let native = cpu.native().map_err(native_unavailable)?;
        let abi = Abi::for_instruction_set(native.instruction_set()).ok_or(ProgramExecError {
            kind: ProgramExecErrorKind::Unavailable,
            detail: ProgramExecErrorDetail::LinuxAbiUnsupported,
        })?;
        Image::parse(&image, abi, user_end(native)).map_err(image_error)?;
        Ok(Self { image, abi })
    }
}

fn native_unavailable(reason: NativeUnavailable) -> ProgramExecError {
    ProgramExecError {
        kind: ProgramExecErrorKind::Unavailable,
        detail: ProgramExecErrorDetail::NativeExecutionUnavailable(reason),
    }
}

fn user_end<Native: NativeExecution>(native: &Native) -> u64 {
    native.user_range().end().raw() as u64
}

/// What a Linux process's [`ProcessAuthority`] lets its system calls
/// reach, derived once from the authority its parent granted. Each
/// resource a later system call reaches (files, sockets, clocks,
/// processes, devices) derives its capability here the way the matching
/// WASIX import does, and a missing one is refused with Linux's errno.
/// User and group IDs are values a process reports and take no part here.
struct LinuxGrants {
    terminal_input: Option<TerminalInputCap>,
    terminal_output: Option<TerminalOutputCap>,
    tty_control: Option<TtyControlCap>,
    /// What WASIX's `clock_time_set` derives, for `clock_settime`.
    set_wall_clock: Option<SetWallClockCap>,
    link_source: Option<LinkSourceCap>,
    symlink_create: Option<SymlinkCreateCap>,
    symlink_read: Option<SymlinkReadCap>,
    tcp: Option<TcpCap>,
    udp: Option<UdpCap>,
    privileged_bind: Option<PrivilegedBindCap>,
    multicast: Option<MulticastCap>,
    network_admin: Option<NetworkAdminCap>,
}

impl LinuxGrants {
    fn derive(authority: &ProcessAuthority) -> Self {
        Self {
            terminal_input: authority.derive_terminal_input_cap().ok(),
            terminal_output: authority.derive_terminal_output_cap().ok(),
            tty_control: authority.derive_tty_control_cap().ok(),
            set_wall_clock: authority.derive_set_wall_clock_cap().ok(),
            link_source: authority.derive_link_source_cap().ok(),
            symlink_create: authority.derive_symlink_create_cap().ok(),
            symlink_read: authority.derive_symlink_read_cap().ok(),
            tcp: authority.derive_tcp_cap().ok(),
            udp: authority.derive_udp_cap().ok(),
            privileged_bind: authority.derive_privileged_bind_cap().ok(),
            multicast: authority.derive_multicast_cap().ok(),
            network_admin: authority.derive_network_admin_cap().ok(),
        }
    }
}

/// Process-wide terminal state aligned with [`WasixTtyState`]: whether each
/// standard stream is attached to a terminal, plus the active `termios` and
/// window size.
struct LinuxTtyState {
    stdin_tty: bool,
    stdout_tty: bool,
    stderr_tty: bool,
    termios: Termios,
    winsize: Winsize,
}

impl LinuxTtyState {
    fn new(
        authority: &ProcessAuthority,
        output_mode: &OutputMode,
        instance_id: crate::InstanceId,
    ) -> Self {
        let rights = authority.terminal_rights();
        let stdin_tty = matches!(
            output_mode.stdin_route(),
            crate::ComponentInputRoute::Serial
        ) && rights.contains(TerminalAuthorityRights::INPUT);
        let stdout_tty = matches!(
            output_mode.sink(crate::ComponentOutputStreamKind::Stdout, instance_id),
            crate::ComponentOutputSink::Local(crate::LocalOutputSink::Serial)
        ) && rights.contains(TerminalAuthorityRights::OUTPUT);
        let stderr_tty = matches!(
            output_mode.sink(crate::ComponentOutputStreamKind::Stderr, instance_id),
            crate::ComponentOutputSink::Local(crate::LocalOutputSink::Serial)
        ) && rights.contains(TerminalAuthorityRights::OUTPUT);
        Self {
            stdin_tty,
            stdout_tty,
            stderr_tty,
            termios: Termios::from_flags(stdin_tty, stdin_tty, true),
            winsize: Winsize::DEFAULT,
        }
    }

    fn is_tty(&self, stream: TtyStream) -> bool {
        match stream {
            TtyStream::Stdin => self.stdin_tty,
            TtyStream::Stdout => self.stdout_tty,
            TtyStream::Stderr => self.stderr_tty,
        }
    }
}

fn image_error(error: elf::Error) -> ProgramExecError {
    let refusal = match error {
        elf::Error::Parse(_) => crate::LinuxImageRefusal::Malformed,
        elf::Error::UnsupportedImage => crate::LinuxImageRefusal::Unsupported,
        elf::Error::UnsupportedSegment => crate::LinuxImageRefusal::Dynamic,
        elf::Error::InvalidSegment | elf::Error::Overlap => crate::LinuxImageRefusal::Segment,
        elf::Error::InvalidEntry => crate::LinuxImageRefusal::Entry,
    };
    ProgramExecError {
        kind: ProgramExecErrorKind::InvalidBinary,
        detail: ProgramExecErrorDetail::LinuxImageInvalid(refusal),
    }
}

fn native_error(error: NativeError) -> ProgramExecError {
    match error {
        NativeError::OutOfMemory => ProgramExecError {
            kind: ProgramExecErrorKind::OutOfMemory,
            detail: ProgramExecErrorDetail::NativeMemoryExhausted,
        },
        // The image was validated and the stack built inside the user
        // range, so any other refusal is a kernel defect.
        error => panic!("mapping a validated Linux image was refused: {error}"),
    }
}

/// The objects a Linux process's descriptors share with WASIX programs.
pub(super) struct LinuxResources<Net>(core::marker::PhantomData<fn() -> Net>);

impl<Net: ComponentHostNetwork> Resources for LinuxResources<Net> {
    type File = FsDescriptor;
    type Network = crate::UnixNetwork<Net>;
    type Data = EpollUserData;
}

/// A Linux interest's 64-bit `epoll_data` rides in the WASIX record's
/// 64-bit field; the rest of the record is a WASIX program's own.
impl EpollData for EpollUserData {
    fn from_linux(data: u64) -> Self {
        Self {
            ptr: 0,
            fd: 0,
            data1: 0,
            data2: data,
        }
    }
    fn to_linux(&self) -> u64 {
        self.data2
    }
}

/// A process's address space as the system-call decoder sees it.
struct LinuxMemory<'a, Space> {
    space: &'a Space,
    /// The platform's user range, whose start is the lowest mappable
    /// address.
    user: VirtRange,
    /// Initial-stack growth region (`VM_GROWSDOWN`, bounded by `RLIMIT_STACK`
    /// and the highest ELF segment), so kernel writes such as signal frames
    /// (`setup_signal_frame`) or syscall outputs into a fresh stack page
    /// expand the initial stack on demand just as Linux `copy_to_user` does.
    stack_growth: Option<VirtRange>,
}

impl<Space: UserSpace> LinuxMemory<'_, Space> {
    fn expand_stack_for(&self, address: u64, length: usize) -> bool {
        let Some(growth) = self.stack_growth else {
            return false;
        };
        if length == 0 {
            return false;
        }
        let Ok(start_raw) = usize::try_from(address) else {
            return false;
        };
        let Some(end_raw) = start_raw.checked_add(length) else {
            return false;
        };
        let mut page = VirtAddr::new(start_raw).page_floor().raw();
        let end_page = end_raw.next_multiple_of(PhysFrame::SIZE);
        let mut expanded = false;
        while page < end_page {
            let page_addr = VirtAddr::new(page);
            if growth.contains(page_addr) {
                let range = VirtRange::new(page_addr, PhysFrame::SIZE);
                match self
                    .space
                    .map(range, &[], PageFlags::READ | PageFlags::WRITE)
                {
                    Ok(()) => expanded = true,
                    Err(NativeError::Overlap) => {}
                    Err(_) => return false,
                }
            }
            page += PhysFrame::SIZE;
        }
        expanded
    }
}

impl<Space: UserSpace> UserMemory for LinuxMemory<'_, Space> {
    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault> {
        self.space
            .read(VirtAddr::new(address as usize), output)
            .map_err(|_| MemoryFault)
    }

    fn check_writable(&self, address: u64, length: usize) -> Result<(), MemoryFault> {
        match self
            .space
            .check_writable(VirtAddr::new(address as usize), length)
        {
            Ok(()) => Ok(()),
            Err(NativeError::NotMapped) if self.expand_stack_for(address, length) => self
                .space
                .check_writable(VirtAddr::new(address as usize), length)
                .map_err(|_| MemoryFault),
            Err(_) => Err(MemoryFault),
        }
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryFault> {
        match self.space.write(VirtAddr::new(address as usize), bytes) {
            Ok(()) => Ok(()),
            Err(NativeError::NotMapped) if self.expand_stack_for(address, bytes.len()) => self
                .space
                .write(VirtAddr::new(address as usize), bytes)
                .map_err(|_| MemoryFault),
            Err(_) => Err(MemoryFault),
        }
    }

    fn atomic_load_u32(&self, address: u64) -> Result<u32, MemoryFault> {
        self.space
            .atomic_load_u32(VirtAddr::new(address as usize))
            .map_err(|_| MemoryFault)
    }

    fn atomic_store_u32(&mut self, address: u64, value: u32) -> Result<(), MemoryFault> {
        self.space
            .atomic_store_u32(VirtAddr::new(address as usize), value)
            .map_err(|_| MemoryFault)
    }

    fn atomic_compare_exchange_u32(
        &mut self,
        address: u64,
        expected: u32,
        desired: u32,
    ) -> Result<Result<u32, u32>, MemoryFault> {
        self.space
            .atomic_compare_exchange_u32(VirtAddr::new(address as usize), expected, desired)
            .map_err(|_| MemoryFault)
    }
}

fn page_range(address: u64, length: u64) -> VirtRange {
    VirtRange::new(VirtAddr::new(address as usize), length as usize)
}

/// A refusal of a memory-map call the decoder already validated. Only the
/// address space's own limits reach the process; anything else means the
/// decoder and the space disagree on a range, a kernel defect.
fn map_error(error: NativeError) -> MapError {
    match error {
        NativeError::OutOfMemory => MapError::OutOfMemory,
        NativeError::Address => MapError::Address,
        NativeError::Overlap => MapError::Occupied,
        error @ (NativeError::NotMapped | NativeError::Register) => {
            panic!("a validated Linux memory-map call was refused: {error}")
        }
    }
}

impl<Space: UserSpace> VirtualMemory for LinuxMemory<'_, Space> {
    fn lowest_address(&self) -> u64 {
        self.user.start.raw() as u64
    }

    fn map_anywhere(&mut self, hint: u64, length: u64, access: PageFlags) -> Result<u64, MapError> {
        self.space
            .map_anywhere(VirtAddr::new(hint as usize), length as usize, access)
            .map(|range| range.start.raw() as u64)
            .map_err(map_error)
    }

    fn map_at(&mut self, address: u64, length: u64, access: PageFlags) -> Result<(), MapError> {
        self.space
            .map(page_range(address, length), &[], access)
            .map_err(map_error)
    }

    fn unmap(&mut self, address: u64, length: u64) {
        self.space
            .unmap(page_range(address, length))
            .unwrap_or_else(|error| panic!("unmapping a validated Linux range: {error}"));
    }

    fn protect(&mut self, address: u64, length: u64, access: PageFlags) -> Result<(), MapError> {
        self.space
            .protect(page_range(address, length), access)
            .map_err(map_error)
    }

    fn discard(&mut self, address: u64, length: u64) {
        self.space
            .discard(page_range(address, length))
            .unwrap_or_else(|error| panic!("discarding a validated Linux range: {error}"));
    }

    fn remap(&mut self, from: u64, length: u64, to: u64, new_length: u64) -> Result<(), MapError> {
        self.space
            .remap(page_range(from, length), page_range(to, new_length))
            .map_err(map_error)
    }

    fn region(&self, start: u64, end: u64) -> Option<Region> {
        if start >= end {
            return None;
        }
        self.space
            .mapping(page_range(start, end - start))
            .map(|mapping| Region {
                start: mapping.range.start.raw() as u64,
                end: mapping.range.end().raw() as u64,
                access: mapping.flags,
            })
    }

    fn free_range(&self, hint: u64, length: u64) -> Option<u64> {
        self.space
            .free_range(VirtAddr::new(hint as usize), length as usize)
            .map(|start| start.raw() as u64)
    }
}

/// Process-wide host state shared across every thread task of one Linux
/// process.
struct LinuxShared<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    cpu: CpuImpl,
    timer: crate::Timer<CpuImpl>,
    spawner: crate::InstanceSpawner<CpuImpl>,
    runtime_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
    read_serial: crate::SerialReader,
    write_serial: crate::DebugSerialWriter,
    output_mode: OutputMode,
    launched_instance: crate::RegisteredInstance,
    signal_state: WasixSignalState,
    container: Arc<crate::LinuxContainer<StorageImpl>>,
    /// Keeps this process's container-local PID reserved until every thread
    /// task has exited and dropped `LinuxShared`.
    _process_guard: crate::ContainerProcessGuard,
    grants: LinuxGrants,
    /// Process-wide terminal state (`termios`, window size, stream TTY flags).
    /// Never held across `.await`.
    tty: spin::Mutex<LinuxTtyState>,
    /// Bytes drained from the debug serial ring during non-blocking reads or
    /// readiness checks so `poll`/`epoll`/`read(O_NONBLOCK)` never drop input.
    /// Never held across `.await`.
    serial_peek: spin::Mutex<Vec<u8>>,
    /// The process's view of wall time, which `clock_settime` moves as
    /// WASIX's `clock_time_set` moves a program's. Never held across `.await`.
    clock: spin::Mutex<crate::KernelClock<CpuImpl, HostRuntimeState<CpuImpl, Net, StorageImpl>>>,
    abi: Abi,
    registers: abi::SystemCallRegisters,
    user: VirtRange,
    stack_top: u64,
    stack_base: usize,
    image_end: usize,
    /// User-executable `rt_sigreturn` trampoline page on ABIs that supply one
    /// (AArch64), or `0` on ABIs that require `SA_RESTORER` (x86-64).
    sigreturn_trampoline: u64,
    space: Arc<Space>,
    /// Summed user-slice ticks across every thread of the process
    /// (`CLOCK_PROCESS_CPUTIME_ID`).
    process_cpu_ticks: AtomicU64,
    /// First host-level failure (user memory exhaustion or instance kill)
    /// observed on any thread of the process.
    fatal_error: spin::Mutex<Option<ProgramExecError>>,
    /// Detached thread tasks still executing or dropping their process/space
    /// handles.
    running_tasks: AtomicUsize,
    tasks_drained: helios_sync::Notify,
}

impl<CpuImpl, Net, StorageImpl, Space> LinuxShared<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    /// Where the initial stack may grow down into: from its initial pages
    /// down as far as the process's current `RLIMIT_STACK` allows, stopping
    /// above the highest ELF segment.
    fn stack_growth(&self, limit: u64) -> VirtRange {
        let lowest = (self.stack_top.saturating_sub(limit) as usize).max(self.image_end);
        VirtRange::new(
            VirtAddr::new(lowest),
            self.stack_base.saturating_sub(lowest),
        )
    }

    fn record_fatal(&self, error: ProgramExecError) {
        let mut slot = self.fatal_error.lock();
        if slot.is_none() {
            *slot = Some(error);
        }
    }

    fn take_fatal(&self) -> Option<ProgramExecError> {
        self.fatal_error.lock().take()
    }

    fn pull_serial_into_peek(&self, max_bytes: usize) -> bool {
        let mut peek = self.serial_peek.lock();
        if !peek.is_empty() {
            return true;
        }
        let mut scratch = Vec::new();
        (self.read_serial)(
            &mut scratch,
            u32::try_from(max_bytes.max(1)).unwrap_or(u32::MAX),
        );
        if scratch.is_empty() {
            return false;
        }
        peek.extend_from_slice(&scratch);
        true
    }

    fn take_serial_peek(&self, limit: usize) -> Option<Bytes> {
        let mut peek = self.serial_peek.lock();
        if peek.is_empty() {
            let mut scratch = Vec::new();
            (self.read_serial)(&mut scratch, u32::try_from(limit).unwrap_or(u32::MAX));
            if scratch.is_empty() {
                return None;
            }
            peek.extend_from_slice(&scratch);
        }
        let take = peek.len().min(limit);
        let bytes = Bytes::copy_from_slice(&peek[..take]);
        peek.drain(..take);
        Some(bytes)
    }

    async fn wait_tasks_drained(&self) {
        loop {
            let mut waiter = self.tasks_drained.waiter();
            if self.running_tasks.load(Ordering::SeqCst) == 0 {
                return;
            }
            core::future::poll_fn(|cx| self.tasks_drained.poll_notified(cx, &mut waiter)).await;
        }
    }
}

/// Decrements [`LinuxShared::running_tasks`] after a spawned thread task has
/// finished [`drive_linux_thread`] and dropped its `Process`, `UserContext`
/// and `LinuxThreadPlatform`.
struct TaskDrainGuard<CpuImpl, Net, StorageImpl, Space>(
    Arc<LinuxShared<CpuImpl, Net, StorageImpl, Space>>,
)
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage;

impl<CpuImpl, Net, StorageImpl, Space> Drop for TaskDrainGuard<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn drop(&mut self) {
        if self.0.running_tasks.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.tasks_drained.notify_all();
        }
    }
}

/// Per-thread host state: per-thread DRBG stream and per-thread slice tick
/// counter (`CLOCK_THREAD_CPUTIME_ID`).
struct LinuxThreadPlatform<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    shared: Arc<LinuxShared<CpuImpl, Net, StorageImpl, Space>>,
    entropy: crate::EntropyPool,
    thread_cpu_ticks: u64,
}

impl<CpuImpl, Net, StorageImpl, Space> LinuxThreadPlatform<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn new(shared: Arc<LinuxShared<CpuImpl, Net, StorageImpl, Space>>, tid: NonZeroU32) -> Self {
        let personalization = shared.launched_instance.id().raw() ^ (u64::from(tid.get()) << 32);
        let entropy =
            crate::EntropyPool::derive(shared.runtime_state.root_entropy(), personalization);
        Self {
            shared,
            entropy,
            thread_cpu_ticks: 0,
        }
    }
}

impl<CpuImpl, Net, StorageImpl, Space: UserSpace> Stdio
    for LinuxThreadPlatform<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    async fn write(&mut self, stream: Stream, bytes: &[u8]) -> Result<usize, WriteError> {
        let kind = match stream {
            Stream::Stdout => crate::ComponentOutputStreamKind::Stdout,
            Stream::Stderr => crate::ComponentOutputStreamKind::Stderr,
        };
        let writer = match self
            .shared
            .output_mode
            .sink(kind, self.shared.launched_instance.id())
        {
            // The terminal is the one destination the stream reaches on
            // the process's own authority; a channel or a log belongs to
            // whoever routed the stream there.
            crate::ComponentOutputSink::Local(crate::LocalOutputSink::Serial)
                if self.shared.grants.terminal_output.is_none() =>
            {
                return Err(WriteError::Denied);
            }
            crate::ComponentOutputSink::Local(local) => loop {
                // Zero means another processor owns the debug UART now:
                // offer the same bytes again after a yield.
                let taken = local.write(
                    &self.shared.cpu,
                    &self.shared.runtime_state,
                    self.shared.write_serial,
                    bytes,
                );
                if taken != 0 || bytes.is_empty() {
                    return Ok(taken);
                }
                crate::yield_now().await;
            },
            crate::ComponentOutputSink::Child(writer) => writer.clone(),
        };
        match writer.write(Bytes::copy_from_slice(bytes)).await {
            Ok(()) => Ok(bytes.len()),
            Err(crate::ClosedPeer) => Err(WriteError::Io),
        }
    }

    fn try_write(&mut self, stream: Stream, bytes: &[u8]) -> Result<usize, WriteError> {
        let kind = match stream {
            Stream::Stdout => crate::ComponentOutputStreamKind::Stdout,
            Stream::Stderr => crate::ComponentOutputStreamKind::Stderr,
        };
        match self
            .shared
            .output_mode
            .sink(kind, self.shared.launched_instance.id())
        {
            crate::ComponentOutputSink::Local(crate::LocalOutputSink::Serial)
                if self.shared.grants.terminal_output.is_none() =>
            {
                Err(WriteError::Denied)
            }
            crate::ComponentOutputSink::Local(local) => {
                let taken = local.write(
                    &self.shared.cpu,
                    &self.shared.runtime_state,
                    self.shared.write_serial,
                    bytes,
                );
                if taken == 0 && !bytes.is_empty() {
                    Err(WriteError::WouldBlock)
                } else {
                    Ok(taken)
                }
            }
            crate::ComponentOutputSink::Child(writer) => {
                match writer.try_write(Bytes::copy_from_slice(bytes)) {
                    TryWrite::Written => Ok(bytes.len()),
                    TryWrite::Closed => Err(WriteError::Io),
                    TryWrite::Full(_) => Err(WriteError::WouldBlock),
                }
            }
        }
    }

    async fn read_input(&mut self, limit: usize) -> Result<Bytes, Denied> {
        Ok(match self.shared.output_mode.stdin_route() {
            crate::ComponentInputRoute::Serial if self.shared.grants.terminal_input.is_none() => {
                return Err(Denied);
            }
            crate::ComponentInputRoute::Serial => loop {
                let wait = self.shared.write_serial.wait_for_debug_serial_input();
                if let Some(bytes) = self.shared.take_serial_peek(limit) {
                    break bytes;
                }
                wait.await;
            },
            crate::ComponentInputRoute::Closed => Bytes::new(),
            crate::ComponentInputRoute::Child(stdin_rx) => {
                stdin_rx.read_limit(limit).await.unwrap_or_default()
            }
        })
    }

    fn try_read_input(&mut self, limit: usize) -> StdinTryRead {
        match self.shared.output_mode.stdin_route() {
            crate::ComponentInputRoute::Serial if self.shared.grants.terminal_input.is_none() => {
                StdinTryRead::Denied
            }
            crate::ComponentInputRoute::Serial => match self.shared.take_serial_peek(limit) {
                Some(bytes) => StdinTryRead::Ready(bytes),
                None => StdinTryRead::WouldBlock,
            },
            crate::ComponentInputRoute::Closed => StdinTryRead::Eof,
            crate::ComponentInputRoute::Child(stdin_rx) => match stdin_rx.try_read_limit(limit) {
                TryRead::Ready(bytes) => StdinTryRead::Ready(bytes),
                TryRead::Eof => StdinTryRead::Eof,
                TryRead::Pending => StdinTryRead::WouldBlock,
            },
        }
    }

    fn stdin_ready_mask(&self) -> u32 {
        match self.shared.output_mode.stdin_route() {
            crate::ComponentInputRoute::Serial if self.shared.grants.terminal_input.is_none() => {
                READY_ERR
            }
            crate::ComponentInputRoute::Serial => {
                if self.shared.pull_serial_into_peek(4096) {
                    READY_IN
                } else {
                    0
                }
            }
            crate::ComponentInputRoute::Closed => READY_IN | READY_HUP,
            crate::ComponentInputRoute::Child(stdin_rx) => {
                (if stdin_rx.has_buffered_data() {
                    READY_IN
                } else {
                    0
                }) | (if stdin_rx.is_writer_closed() {
                    READY_HUP
                } else {
                    0
                })
            }
        }
    }

    async fn wait_stdin_ready(&self) {
        match self.shared.output_mode.stdin_route() {
            crate::ComponentInputRoute::Serial if self.shared.grants.terminal_input.is_none() => {}
            crate::ComponentInputRoute::Serial => loop {
                let wait = self.shared.write_serial.wait_for_debug_serial_input();
                if self.shared.pull_serial_into_peek(4096) {
                    return;
                }
                wait.await;
            },
            crate::ComponentInputRoute::Closed => {}
            crate::ComponentInputRoute::Child(stdin_rx) => {
                let mut wait = stdin_rx.wait_state();
                core::future::poll_fn(|cx| stdin_rx.poll_readable(cx, &mut wait)).await;
            }
        }
    }

    fn stdout_ready_mask(&self, stream: Stream) -> u32 {
        let kind = match stream {
            Stream::Stdout => crate::ComponentOutputStreamKind::Stdout,
            Stream::Stderr => crate::ComponentOutputStreamKind::Stderr,
        };
        match self
            .shared
            .output_mode
            .sink(kind, self.shared.launched_instance.id())
        {
            crate::ComponentOutputSink::Local(crate::LocalOutputSink::Serial)
                if self.shared.grants.terminal_output.is_none() =>
            {
                READY_ERR
            }
            crate::ComponentOutputSink::Local(_) => READY_OUT,
            crate::ComponentOutputSink::Child(writer) => {
                if writer.is_reader_closed() {
                    READY_ERR
                } else if writer.is_writable() {
                    READY_OUT
                } else {
                    0
                }
            }
        }
    }
}

fn node_kind_to_component(kind: NodeKind) -> ComponentFsNodeKind {
    match kind {
        NodeKind::Directory => ComponentFsNodeKind::Directory,
        NodeKind::File => ComponentFsNodeKind::File,
        NodeKind::Symlink => ComponentFsNodeKind::Symlink,
        NodeKind::CharacterDevice => ComponentFsNodeKind::CharacterDevice,
        NodeKind::BlockDevice => ComponentFsNodeKind::BlockDevice,
        NodeKind::Fifo => ComponentFsNodeKind::Fifo,
        NodeKind::Socket => ComponentFsNodeKind::Socket,
    }
}

fn join_synthetic_etc_path(base_dir: &str, path: &str) -> Option<String> {
    // Reject `..` components so `/nonexistent/../etc/hosts` cannot lexically
    // collapse onto a synthetic `/etc` entry.
    if path.split('/').any(|seg| seg == "..") {
        return None;
    }
    let combined = if path.starts_with('/') {
        String::from(path)
    } else if base_dir.ends_with('/') {
        alloc::format!("{base_dir}{path}")
    } else {
        alloc::format!("{base_dir}/{path}")
    };
    Some(combined)
}

fn synthetic_etc_stat(path: &str, size: u64) -> FileStat {
    let ino = if path.ends_with("/resolv.conf") { 1 } else { 2 };
    FileStat {
        dev: u64::MAX,
        ino,
        kind: NodeKind::File,
        permissions: 0o444,
        nlink: 1,
        uid: 0,
        gid: 0,
        rdev: 0,
        size,
        access_nanos: 0,
        modified_nanos: 0,
        status_nanos: 0,
    }
}

fn container_info_to_stat(info: &crate::ContainerNodeInfo) -> FileStat {
    FileStat {
        dev: info.metadata.id.device.raw(),
        ino: info.metadata.id.inode,
        kind: info.metadata.kind,
        permissions: info.unix.permissions,
        nlink: info.metadata.link_count,
        uid: info.unix.uid,
        gid: info.unix.gid,
        rdev: 0,
        size: info.metadata.size,
        access_nanos: info.metadata.access_nanos,
        modified_nanos: info.metadata.modified_nanos,
        status_nanos: info.metadata.status_nanos,
    }
}

fn resolve_time_update(update: TimeUpdate, now: u64) -> Option<u64> {
    match update {
        TimeUpdate::Omit => None,
        TimeUpdate::Now => Some(now),
        TimeUpdate::Set(nanos) => Some(nanos),
    }
}

impl<CpuImpl, Net, StorageImpl, Space: UserSpace> Tty
    for LinuxThreadPlatform<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn is_tty(&self, stream: TtyStream) -> bool {
        self.shared.tty.lock().is_tty(stream)
    }

    fn get_termios(&self, stream: TtyStream) -> Result<Termios, TtyError> {
        let state = self.shared.tty.lock();
        if !state.is_tty(stream) {
            return Err(TtyError::NotTty);
        }
        Ok(state.termios)
    }

    fn set_termios(
        &mut self,
        stream: TtyStream,
        termios: Termios,
        action: TermiosAction,
    ) -> Result<(), TtyError> {
        let mut state = self.shared.tty.lock();
        if !state.is_tty(stream) {
            return Err(TtyError::NotTty);
        }
        if self.shared.grants.tty_control.is_none() {
            return Err(TtyError::Denied);
        }
        state.termios = termios;
        drop(state);
        if action == TermiosAction::Flush {
            self.shared.serial_peek.lock().clear();
        }
        Ok(())
    }

    fn get_winsize(&self, stream: TtyStream) -> Result<Winsize, TtyError> {
        let state = self.shared.tty.lock();
        if !state.is_tty(stream) {
            return Err(TtyError::NotTty);
        }
        Ok(state.winsize)
    }

    fn set_winsize(&mut self, stream: TtyStream, winsize: Winsize) -> Result<(), TtyError> {
        let mut state = self.shared.tty.lock();
        if !state.is_tty(stream) {
            return Err(TtyError::NotTty);
        }
        if self.shared.grants.tty_control.is_none() {
            return Err(TtyError::Denied);
        }
        state.winsize = winsize;
        Ok(())
    }
}

impl<CpuImpl, Net, StorageImpl, Space: UserSpace> Filesystem<LinuxResources<Net>>
    for LinuxThreadPlatform<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn file_access(&self, file: &FsDescriptor) -> FileAccess {
        let read = file.flags.contains(FsDescriptorFlags::READ);
        let write = file.flags.contains(FsDescriptorFlags::WRITE);
        match (read, write) {
            (true, true) => FileAccess::ReadWrite,
            (true, false) => FileAccess::ReadOnly,
            (false, true) => FileAccess::WriteOnly,
            (false, false) => FileAccess::PathOnly,
        }
    }

    fn file_is_directory(&self, file: &FsDescriptor) -> bool {
        file.kind == ComponentFsNodeKind::Directory
    }

    fn file_path<'a>(&self, file: &'a FsDescriptor) -> Option<&'a str> {
        Some(&file.path)
    }

    fn can_exec_file(&self, file: &FsDescriptor) -> bool {
        self.shared.container.filesystem().can_exec(&file.path)
    }

    fn same_file(&self, a: &FsDescriptor, b: &FsDescriptor) -> bool {
        match (a.identity, b.identity) {
            (Some(ia), Some(ib)) => ia == ib,
            _ => a.path == b.path,
        }
    }

    async fn open(
        &mut self,
        base: Option<&FsDescriptor>,
        cwd: &str,
        path: &str,
        request: OpenRequest,
    ) -> Result<FsDescriptor, FsError> {
        let base_dir = base.map_or(cwd, |f| f.path.as_str());
        let now = self.shared.clock.lock().system_time_nanos();
        let opened = self
            .shared
            .container
            .filesystem()
            .open_at(base_dir, path, request, now)
            .await;
        let (info, container_path, mount_hold) = match opened {
            Ok(ok) => ok,
            Err(FsError::NoEntry) => {
                let Some(combined) = join_synthetic_etc_path(base_dir, path) else {
                    return Err(FsError::NoEntry);
                };
                let servers = self
                    .shared
                    .runtime_state
                    .network_service()
                    .map(|service| service.dns_servers())
                    .unwrap_or_default();
                if self
                    .shared
                    .container
                    .synthetic_etc_file(&combined, &servers)
                    .is_some()
                {
                    if request.directory {
                        return Err(FsError::NotDirectory);
                    }
                    if request.write || request.truncate || request.create || request.exclusive {
                        return Err(FsError::ReadOnly);
                    }
                    let mut flags = FsDescriptorFlags::empty();
                    if request.read {
                        flags |= FsDescriptorFlags::READ;
                    }
                    return Ok(FsDescriptor {
                        path: combined,
                        kind: ComponentFsNodeKind::File,
                        flags,
                        identity: None,
                        mount: None,
                        open: None,
                    });
                }
                return Err(FsError::NoEntry);
            }
            Err(error) => return Err(error),
        };
        let mut flags = FsDescriptorFlags::empty();
        if request.read {
            flags |= FsDescriptorFlags::READ;
        }
        if request.write {
            flags |= FsDescriptorFlags::WRITE;
        }
        if request.sync {
            flags |= FsDescriptorFlags::FILE_INTEGRITY_SYNC;
        }
        if request.dsync {
            flags |= FsDescriptorFlags::DATA_INTEGRITY_SYNC;
        }
        if info.metadata.kind == NodeKind::Directory {
            flags |= FsDescriptorFlags::MUTATE_DIRECTORY;
        }
        Ok(FsDescriptor {
            path: container_path,
            kind: node_kind_to_component(info.metadata.kind),
            flags,
            identity: Some(crate::vfs::object_identity(&info.metadata)),
            mount: mount_hold,
            open: None,
        })
    }

    async fn stat_path(
        &self,
        base: Option<&FsDescriptor>,
        cwd: &str,
        path: &str,
        follow: bool,
    ) -> Result<(FileStat, String), FsError> {
        let base_dir = base.map_or(cwd, |f| f.path.as_str());
        match self
            .shared
            .container
            .filesystem()
            .stat_at(base_dir, path, follow)
            .await
        {
            Ok((info, resolved_path)) => Ok((container_info_to_stat(&info), resolved_path)),
            Err(FsError::NoEntry) => {
                let Some(combined) = join_synthetic_etc_path(base_dir, path) else {
                    return Err(FsError::NoEntry);
                };
                let servers = self
                    .shared
                    .runtime_state
                    .network_service()
                    .map(|service| service.dns_servers())
                    .unwrap_or_default();
                if let Some(bytes) = self
                    .shared
                    .container
                    .synthetic_etc_file(&combined, &servers)
                {
                    return Ok((synthetic_etc_stat(&combined, bytes.len() as u64), combined));
                }
                Err(FsError::NoEntry)
            }
            Err(error) => Err(error),
        }
    }

    async fn stat_file(&self, file: &FsDescriptor) -> Result<FileStat, FsError> {
        match self
            .shared
            .container
            .filesystem()
            .stat_resolved(&file.path)
            .await
        {
            Ok(info) => Ok(container_info_to_stat(&info)),
            Err(FsError::NoEntry) => {
                let servers = self
                    .shared
                    .runtime_state
                    .network_service()
                    .map(|service| service.dns_servers())
                    .unwrap_or_default();
                if let Some(bytes) = self
                    .shared
                    .container
                    .synthetic_etc_file(&file.path, &servers)
                {
                    return Ok(synthetic_etc_stat(&file.path, bytes.len() as u64));
                }
                Err(FsError::NoEntry)
            }
            Err(error) => Err(error),
        }
    }

    async fn access_path(
        &self,
        base: Option<&FsDescriptor>,
        cwd: &str,
        path: &str,
        check: AccessCheck,
    ) -> Result<(), FsError> {
        let base_dir = base.map_or(cwd, |f| f.path.as_str());
        match self
            .shared
            .container
            .filesystem()
            .access_at(base_dir, path, check)
            .await
        {
            Ok(()) => Ok(()),
            Err(FsError::NoEntry) => {
                let Some(combined) = join_synthetic_etc_path(base_dir, path) else {
                    return Err(FsError::NoEntry);
                };
                let servers = self
                    .shared
                    .runtime_state
                    .network_service()
                    .map(|service| service.dns_servers())
                    .unwrap_or_default();
                if self
                    .shared
                    .container
                    .synthetic_etc_file(&combined, &servers)
                    .is_some()
                {
                    if check.write {
                        return Err(FsError::ReadOnly);
                    }
                    if check.exec {
                        return Err(FsError::NotPermitted);
                    }
                    return Ok(());
                }
                Err(FsError::NoEntry)
            }
            Err(error) => Err(error),
        }
    }

    async fn read_at(
        &self,
        file: &FsDescriptor,
        offset: u64,
        max_bytes: usize,
    ) -> Result<Bytes, FsError> {
        match self
            .shared
            .container
            .filesystem()
            .read_at(&file.path, offset, max_bytes)
            .await
        {
            Ok(bytes) => Ok(bytes),
            Err(FsError::NoEntry) => {
                let servers = self
                    .shared
                    .runtime_state
                    .network_service()
                    .map(|service| service.dns_servers())
                    .unwrap_or_default();
                if let Some(bytes) = self
                    .shared
                    .container
                    .synthetic_etc_file(&file.path, &servers)
                {
                    let start = usize::try_from(offset)
                        .unwrap_or(bytes.len())
                        .min(bytes.len());
                    let end = start.saturating_add(max_bytes).min(bytes.len());
                    return Ok(Bytes::copy_from_slice(&bytes[start..end]));
                }
                Err(FsError::NoEntry)
            }
            Err(error) => Err(error),
        }
    }

    async fn write_at(
        &mut self,
        file: &FsDescriptor,
        position: WritePosition,
        bytes: &[u8],
    ) -> Result<Landed, FsError> {
        let now = self.shared.clock.lock().system_time_nanos();
        self.shared
            .container
            .filesystem()
            .write_at(&file.path, position, bytes, now)
            .await
    }

    async fn list_dir(
        &self,
        file: &FsDescriptor,
    ) -> Result<(u64, u64, Vec<DirListEntry>), FsError> {
        let (self_ino, parent_ino, entries) = self
            .shared
            .container
            .filesystem()
            .list_with_inodes(&file.path)
            .await?;
        let out = entries
            .into_iter()
            .map(|entry| DirListEntry {
                name: entry.name,
                kind: entry.kind,
                inode: entry.inode,
            })
            .collect();
        Ok((self_ino, parent_ino, out))
    }

    async fn set_size_file(&mut self, file: &FsDescriptor, size: u64) -> Result<(), FsError> {
        let now = self.shared.clock.lock().system_time_nanos();
        self.shared
            .container
            .filesystem()
            .set_size(&file.path, size, now)
            .await
    }

    async fn set_size_path(&mut self, cwd: &str, path: &str, size: u64) -> Result<(), FsError> {
        let now = self.shared.clock.lock().system_time_nanos();
        self.shared
            .container
            .filesystem()
            .set_size_at(cwd, path, size, now)
            .await
    }

    async fn sync(&self, file: &FsDescriptor, data_only: bool) -> Result<(), FsError> {
        self.shared
            .container
            .filesystem()
            .sync(&file.path, data_only)
            .await
    }

    async fn read_link(
        &self,
        base: Option<&FsDescriptor>,
        cwd: &str,
        path: &str,
    ) -> Result<String, FsError> {
        if self.shared.grants.symlink_read.is_none() {
            return Err(FsError::NotPermitted);
        }
        if path.is_empty() {
            let Some(file) = base else {
                return Err(FsError::NoEntry);
            };
            return self
                .shared
                .container
                .filesystem()
                .read_link_resolved(&file.path)
                .await;
        }
        let base_dir = base.map_or(cwd, |f| f.path.as_str());
        self.shared
            .container
            .filesystem()
            .read_link_at(base_dir, path)
            .await
    }

    async fn mkdir(
        &mut self,
        base: Option<&FsDescriptor>,
        cwd: &str,
        path: &str,
        mode: u32,
    ) -> Result<(), FsError> {
        let base_dir = base.map_or(cwd, |f| f.path.as_str());
        let now = self.shared.clock.lock().system_time_nanos();
        self.shared
            .container
            .filesystem()
            .mkdir_at(base_dir, path, mode, now)
            .await
    }

    async fn unlink(
        &mut self,
        base: Option<&FsDescriptor>,
        cwd: &str,
        path: &str,
        remove_dir: bool,
    ) -> Result<(), FsError> {
        let base_dir = base.map_or(cwd, |f| f.path.as_str());
        let now = self.shared.clock.lock().system_time_nanos();
        self.shared
            .container
            .filesystem()
            .unlink_at(base_dir, path, remove_dir, now)
            .await
    }

    async fn rename(
        &mut self,
        old_base: Option<&FsDescriptor>,
        old_path: &str,
        new_base: Option<&FsDescriptor>,
        new_path: &str,
        cwd: &str,
        mode: RenameMode,
    ) -> Result<(), FsError> {
        let old_dir = old_base.map_or(cwd, |f| f.path.as_str());
        let new_dir = new_base.map_or(cwd, |f| f.path.as_str());
        let now = self.shared.clock.lock().system_time_nanos();
        self.shared
            .container
            .filesystem()
            .rename_at(old_dir, old_path, new_dir, new_path, mode, now)
            .await
    }

    async fn link(
        &mut self,
        old_base: Option<&FsDescriptor>,
        old_path: &str,
        new_base: Option<&FsDescriptor>,
        new_path: &str,
        cwd: &str,
        options: LinkOptions,
    ) -> Result<(), FsError> {
        if self.shared.grants.link_source.is_none() {
            return Err(FsError::NotPermitted);
        }
        let old_dir = old_base.map_or(cwd, |f| f.path.as_str());
        let new_dir = new_base.map_or(cwd, |f| f.path.as_str());
        let now = self.shared.clock.lock().system_time_nanos();
        self.shared
            .container
            .filesystem()
            .link_at(
                old_dir,
                old_path,
                new_dir,
                new_path,
                options.follow,
                options.empty_path,
                now,
            )
            .await
    }

    async fn symlink(
        &mut self,
        target: &str,
        base: Option<&FsDescriptor>,
        cwd: &str,
        link_path: &str,
    ) -> Result<(), FsError> {
        if self.shared.grants.symlink_create.is_none() {
            return Err(FsError::NotPermitted);
        }
        let base_dir = base.map_or(cwd, |f| f.path.as_str());
        let now = self.shared.clock.lock().system_time_nanos();
        self.shared
            .container
            .filesystem()
            .symlink_at(target, base_dir, link_path, now)
            .await
    }

    async fn set_times_path(
        &mut self,
        base: Option<&FsDescriptor>,
        cwd: &str,
        path: &str,
        follow: bool,
        access: TimeUpdate,
        modified: TimeUpdate,
    ) -> Result<(), FsError> {
        let base_dir = base.map_or(cwd, |f| f.path.as_str());
        let now = self.shared.clock.lock().system_time_nanos();
        self.shared
            .container
            .filesystem()
            .set_times_at(
                base_dir,
                path,
                follow,
                resolve_time_update(access, now),
                resolve_time_update(modified, now),
                now,
            )
            .await
    }

    async fn set_times_file(
        &mut self,
        file: &FsDescriptor,
        access: TimeUpdate,
        modified: TimeUpdate,
    ) -> Result<(), FsError> {
        let now = self.shared.clock.lock().system_time_nanos();
        self.shared
            .container
            .filesystem()
            .set_times_resolved(
                &file.path,
                resolve_time_update(access, now),
                resolve_time_update(modified, now),
                now,
            )
            .await
    }
}

impl<CpuImpl, Net, StorageImpl, Space: UserSpace> syscall::Clock
    for LinuxThreadPlatform<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    /// The uptime clock, the one WASIX's `clock_time_get` reads.
    fn now_nanos(&self) -> u64 {
        self.shared
            .runtime_state
            .uptime_nanos(self.shared.cpu.now().ticks())
    }

    async fn sleep_until(&self, deadline: u64) {
        let remaining = deadline.saturating_sub(self.now_nanos());
        self.shared
            .timer
            .sleep_for(Duration::from_nanos(remaining))
            .await;
    }
}

impl<CpuImpl, Net, StorageImpl, Space: UserSpace> System
    for LinuxThreadPlatform<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn realtime_nanos(&self) -> u64 {
        self.shared.clock.lock().system_time_nanos()
    }

    fn set_realtime_nanos(&mut self, nanos: u64) -> Result<(), Denied> {
        // The right WASIX's `clock_time_set` derives.
        let cap = self.shared.grants.set_wall_clock.as_ref().ok_or(Denied)?;
        self.shared.clock.lock().set_system_time_nanos(cap, nanos);
        Ok(())
    }

    fn cpu_nanos(&self) -> u64 {
        self.shared
            .cpu
            .timebase()
            .ticks_to_nanos(self.thread_cpu_ticks)
    }

    fn process_cpu_nanos(&self) -> u64 {
        self.shared
            .cpu
            .timebase()
            .ticks_to_nanos(self.shared.process_cpu_ticks.load(Ordering::Relaxed))
    }

    fn processor_count(&self) -> u32 {
        u32::try_from(self.shared.cpu.processor_count().max(1)).unwrap_or(u32::MAX)
    }

    fn fill_random(&mut self, output: &mut [u8]) {
        self.entropy
            .fill_secure(self.shared.runtime_state.root_entropy(), output);
    }

    fn memory(&self) -> MemoryTotals {
        let machine = crate::machine_memory();
        MemoryTotals {
            total_bytes: machine.usable_bytes as u64,
            free_bytes: machine.free_bytes as u64,
        }
    }

    fn process_count(&self) -> u32 {
        self.shared.container.process_count()
    }

    fn kernel_version(&self) -> &str {
        concat!("#1 Helios ", env!("CARGO_PKG_VERSION"))
    }

    fn hostname(&self) -> syscall::UtsField {
        self.shared.container.hostname()
    }

    fn domainname(&self) -> syscall::UtsField {
        self.shared.container.domainname()
    }

    fn set_hostname(&mut self, name: syscall::UtsField) -> Result<(), Denied> {
        self.shared.container.set_hostname(name);
        Ok(())
    }

    fn set_domainname(&mut self, name: syscall::UtsField) -> Result<(), Denied> {
        self.shared.container.set_domainname(name);
        Ok(())
    }
}

fn linux_to_network_ip(ip: syscall::IpAddr) -> crate::NetworkIpAddress {
    match ip {
        syscall::IpAddr::V4(octets) => {
            crate::NetworkIpAddress::Ipv4(crate::Ipv4Address::new(octets))
        }
        syscall::IpAddr::V6(octets) => {
            crate::NetworkIpAddress::Ipv6(helios_netstack::Ipv6Address::new(octets))
        }
    }
}

fn network_to_linux_ip(address: crate::NetworkIpAddress) -> syscall::IpAddr {
    match address {
        crate::NetworkIpAddress::Ipv4(addr) => syscall::IpAddr::V4(addr.octets()),
        crate::NetworkIpAddress::Ipv6(addr) => syscall::IpAddr::V6(addr.octets()),
    }
}

fn linux_errno_from_tcp_error(error: crate::TcpError) -> u64 {
    const EACCES: u64 = 13;
    const EIO: u64 = 5;
    match error.detail {
        crate::NetworkErrorDetail::AddressNotAvailable => return syscall::EADDRNOTAVAIL,
        crate::NetworkErrorDetail::TcpRemotePortUnreachable => return syscall::ECONNREFUSED,
        crate::NetworkErrorDetail::TcpRemoteNetworkUnreachable => return syscall::ENETUNREACH,
        crate::NetworkErrorDetail::TcpRemoteHostUnreachable => return syscall::EHOSTUNREACH,
        crate::NetworkErrorDetail::TcpRemoteCommunicationProhibited => return EACCES,
        crate::NetworkErrorDetail::TcpClosedDuringConnect => return syscall::ECONNREFUSED,
        crate::NetworkErrorDetail::TcpListenStartFailed => return syscall::EADDRINUSE,
        crate::NetworkErrorDetail::TcpNoLongerWritable => return syscall::EPIPE,
        _ => {}
    }
    match error.kind {
        crate::TcpErrorKind::UnresolvedHost => syscall::EHOSTUNREACH,
        crate::TcpErrorKind::Timeout => syscall::ETIMEDOUT,
        crate::TcpErrorKind::ConnectionReset => syscall::ECONNRESET,
        crate::TcpErrorKind::ConnectionAborted => syscall::ECONNABORTED,
        crate::TcpErrorKind::PermissionDenied => EACCES,
        crate::TcpErrorKind::Unavailable => syscall::ENETDOWN,
        crate::TcpErrorKind::Internal => EIO,
    }
}

fn linux_errno_from_udp_error(error: crate::UdpError) -> u64 {
    const EACCES: u64 = 13;
    const EIO: u64 = 5;
    const EINVAL: u64 = 22;
    const EOPNOTSUPP: u64 = 95;
    match error.detail {
        crate::NetworkErrorDetail::AddressNotAvailable
        | crate::NetworkErrorDetail::UdpMulticastInterfaceUnavailable => {
            return syscall::EADDRNOTAVAIL;
        }
        crate::NetworkErrorDetail::UdpPortInUse => return syscall::EADDRINUSE,
        crate::NetworkErrorDetail::UdpDatagramTooLarge => return syscall::EMSGSIZE,
        crate::NetworkErrorDetail::UdpRemotePortUnreachable => return syscall::ECONNREFUSED,
        crate::NetworkErrorDetail::UdpRemoteNetworkUnreachable => return syscall::ENETUNREACH,
        crate::NetworkErrorDetail::UdpRemoteHostUnreachable => return syscall::EHOSTUNREACH,
        crate::NetworkErrorDetail::UdpRemoteCommunicationProhibited => return EACCES,
        crate::NetworkErrorDetail::UnsupportedAddressFamily => return syscall::EAFNOSUPPORT,
        crate::NetworkErrorDetail::UdpMulticastJoinFailed
        | crate::NetworkErrorDetail::UdpMulticastLeaveFailed => return EINVAL,
        _ => {}
    }
    match error.kind {
        crate::UdpErrorKind::UnresolvedHost => syscall::EHOSTUNREACH,
        crate::UdpErrorKind::Unsupported => EOPNOTSUPP,
        crate::UdpErrorKind::Timeout => syscall::ETIMEDOUT,
        crate::UdpErrorKind::PermissionDenied => EACCES,
        crate::UdpErrorKind::Unavailable => syscall::ENETDOWN,
        crate::UdpErrorKind::Internal => EIO,
    }
}

impl<CpuImpl, Net, StorageImpl, Space: UserSpace> syscall::Network<crate::UnixNetwork<Net>>
    for LinuxThreadPlatform<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn to_ip(&self, address: crate::NetworkIpAddress) -> syscall::IpAddr {
        network_to_linux_ip(address)
    }

    fn encode_ip(&self, ip: syscall::IpAddr) -> crate::NetworkIpAddress {
        linux_to_network_ip(ip)
    }

    fn check_tcp_open(&self) -> Result<(), u64> {
        const EACCES: u64 = 13;
        if self.shared.grants.tcp.is_none() {
            return Err(EACCES);
        }
        if self.shared.runtime_state.network_service().is_none() {
            return Err(syscall::ENETDOWN);
        }
        Ok(())
    }

    fn check_udp_open(&self) -> Result<(), u64> {
        const EACCES: u64 = 13;
        if self.shared.grants.udp.is_none() {
            return Err(EACCES);
        }
        if self.shared.runtime_state.network_service().is_none() {
            return Err(syscall::ENETDOWN);
        }
        Ok(())
    }

    fn check_tcp_bind(&self, local_port: u16) -> Result<(), u64> {
        const EACCES: u64 = 13;
        self.check_tcp_open()?;
        if local_port != 0 && local_port < 1024 && self.shared.grants.privileged_bind.is_none() {
            return Err(EACCES);
        }
        Ok(())
    }

    fn check_udp_bind(&self, local_port: u16) -> Result<(), u64> {
        const EACCES: u64 = 13;
        self.check_udp_open()?;
        if local_port != 0 && local_port < 1024 && self.shared.grants.privileged_bind.is_none() {
            return Err(EACCES);
        }
        Ok(())
    }

    async fn tcp_listen(
        &self,
        local: syscall::SocketAddr,
        backlog: u16,
        hop_limit: u8,
    ) -> Result<(Arc<OwnedTcpListener<crate::UnixNetwork<Net>>>, u16), u64> {
        self.check_tcp_bind(local.port)?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let bound = service
            .tcp_listen(
                linux_to_network_ip(local.ip),
                local.port,
                backlog,
                hop_limit,
            )
            .await
            .map_err(linux_errno_from_tcp_error)?;
        let owned = OwnedTcpListener::new(crate::UnixNetwork::new(service), bound.listener);
        Ok((owned, bound.local_port))
    }

    async fn tcp_accept(
        &self,
        listener: Net::TcpListener,
        timeout_nanos: u64,
    ) -> Result<
        (
            Arc<OwnedTcpStream<crate::UnixNetwork<Net>>>,
            syscall::SocketAddr,
        ),
        u64,
    > {
        self.check_tcp_open()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let accepted = service
            .tcp_accept(listener, timeout_nanos)
            .await
            .map_err(linux_errno_from_tcp_error)?;
        let owned = OwnedTcpStream::new(crate::UnixNetwork::new(service), accepted.stream);
        Ok((
            owned,
            syscall::SocketAddr {
                ip: network_to_linux_ip(accepted.address),
                port: accepted.port,
            },
        ))
    }

    async fn tcp_connect(
        &self,
        remote: syscall::SocketAddr,
        local_port: u16,
        hop_limit: u8,
        timeout_nanos: u64,
    ) -> Result<Arc<OwnedTcpStream<crate::UnixNetwork<Net>>>, u64> {
        self.check_tcp_open()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let stream = service
            .tcp_connect_address(
                linux_to_network_ip(remote.ip),
                remote.port,
                local_port,
                hop_limit,
                timeout_nanos,
            )
            .await
            .map_err(linux_errno_from_tcp_error)?;
        Ok(OwnedTcpStream::new(
            crate::UnixNetwork::new(service),
            stream,
        ))
    }

    async fn tcp_connect_start(
        &self,
        remote: syscall::SocketAddr,
        local_port: u16,
        hop_limit: u8,
    ) -> Result<
        (
            Arc<OwnedTcpStream<crate::UnixNetwork<Net>>>,
            syscall::ConnectProgress,
        ),
        u64,
    > {
        self.check_tcp_open()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let (stream, progress) = service
            .tcp_connect_start(
                linux_to_network_ip(remote.ip),
                remote.port,
                local_port,
                hop_limit,
            )
            .await
            .map_err(linux_errno_from_tcp_error)?;
        let owned = OwnedTcpStream::new(crate::UnixNetwork::new(service), stream);
        let progress = match progress {
            crate::TcpConnectPoll::Pending => syscall::ConnectProgress::Pending,
            crate::TcpConnectPoll::Connected => syscall::ConnectProgress::Connected,
        };
        Ok((owned, progress))
    }

    async fn tcp_connect_poll(
        &self,
        stream: Net::TcpStream,
    ) -> Result<syscall::ConnectProgress, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        match service
            .tcp_connect_poll(stream)
            .await
            .map_err(linux_errno_from_tcp_error)?
        {
            crate::TcpConnectPoll::Pending => Ok(syscall::ConnectProgress::Pending),
            crate::TcpConnectPoll::Connected => Ok(syscall::ConnectProgress::Connected),
        }
    }

    fn tcp_local_endpoint(
        &self,
        stream: Net::TcpStream,
    ) -> Result<Option<syscall::SocketAddr>, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        Ok(service
            .tcp_local_endpoint(stream)
            .map_err(linux_errno_from_tcp_error)?
            .map(|(ip, port)| syscall::SocketAddr {
                ip: network_to_linux_ip(ip),
                port,
            }))
    }

    fn tcp_set_hop_limit(&self, stream: Net::TcpStream, hop_limit: u8) -> Result<(), u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .tcp_set_hop_limit(stream, hop_limit)
            .map_err(linux_errno_from_tcp_error)
    }

    fn tcp_listener_set_hop_limit(
        &self,
        listener: Net::TcpListener,
        hop_limit: u8,
    ) -> Result<(), u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .tcp_listener_set_hop_limit(listener, hop_limit)
            .map_err(linux_errno_from_tcp_error)
    }

    async fn tcp_read(
        &self,
        stream: Net::TcpStream,
        max_bytes: u32,
        timeout_nanos: u64,
        peek: bool,
    ) -> Result<Option<Bytes>, u64> {
        self.check_tcp_open()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        if !peek {
            return service
                .tcp_read(stream, max_bytes, timeout_nanos)
                .await
                .map_err(linux_errno_from_tcp_error);
        }
        let cap = (max_bytes as usize).min(65_536);
        let mut storage = alloc::vec![0u8; cap];
        let ranges = [(0usize, storage.len())];
        // SAFETY: `storage` is a live, exclusively owned heap buffer that stays
        // in place for the duration of `tcp_peek_into`, and no page of it can
        // be swapped out (`residency = None`).
        let mut buffer = unsafe {
            crate::RegisteredTcpReadBuffer::new(storage.as_mut_ptr() as usize, &ranges, None)
        };
        match service
            .tcp_peek_into(stream, &mut buffer, timeout_nanos)
            .await
            .map_err(linux_errno_from_tcp_error)?
        {
            crate::TcpReadInto::Data(n) => {
                storage.truncate(n);
                Ok(Some(Bytes::from(storage)))
            }
            crate::TcpReadInto::Eof => Ok(None),
            crate::TcpReadInto::PageLost(_) => Err(5),
        }
    }

    async fn tcp_write(
        &self,
        stream: Net::TcpStream,
        bytes: Bytes,
        timeout_nanos: u64,
    ) -> Result<usize, u64> {
        self.check_tcp_open()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .tcp_write_some_bytes(stream, bytes, timeout_nanos)
            .await
            .map_err(linux_errno_from_tcp_error)
    }

    async fn tcp_shutdown_send(&self, stream: Net::TcpStream) -> Result<(), u64> {
        self.check_tcp_open()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .tcp_shutdown_send(stream)
            .await
            .map_err(linux_errno_from_tcp_error)
    }

    async fn tcp_readiness(&self, stream: Net::TcpStream) -> Result<syscall::SocketReady, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let r = service
            .tcp_readiness(stream)
            .await
            .map_err(linux_errno_from_tcp_error)?;
        Ok(syscall::SocketReady {
            readable: r.readable,
            writable: r.writable,
            hangup: r.hangup,
        })
    }

    async fn tcp_listener_readiness(
        &self,
        listener: Net::TcpListener,
    ) -> Result<syscall::SocketReady, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let r = service
            .tcp_listener_readiness(listener)
            .await
            .map_err(linux_errno_from_tcp_error)?;
        Ok(syscall::SocketReady {
            readable: r.readable,
            writable: r.writable,
            hangup: r.hangup,
        })
    }

    async fn udp_bind(
        &self,
        local: syscall::SocketAddr,
        hop_limit: u8,
    ) -> Result<(Arc<OwnedUdpSocket<crate::UnixNetwork<Net>>>, u16), u64> {
        self.check_udp_bind(local.port)?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let bound = service
            .udp_bind(linux_to_network_ip(local.ip), local.port)
            .await
            .map_err(linux_errno_from_udp_error)?;
        let owned = OwnedUdpSocket::new(crate::UnixNetwork::new(service.clone()), bound.socket);
        service
            .udp_set_hop_limit(bound.socket, hop_limit)
            .map_err(linux_errno_from_udp_error)?;
        Ok((owned, bound.local_port))
    }

    fn udp_connect(&self, socket: Net::UdpSocket, remote: syscall::SocketAddr) -> Result<(), u64> {
        self.check_udp_open()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .udp_connect(socket, linux_to_network_ip(remote.ip), remote.port)
            .map_err(linux_errno_from_udp_error)
    }

    fn udp_disconnect(&self, socket: Net::UdpSocket) -> Result<(), u64> {
        self.check_udp_open()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .udp_disconnect(socket)
            .map_err(linux_errno_from_udp_error)
    }

    fn udp_set_hop_limit(&self, socket: Net::UdpSocket, hop_limit: u8) -> Result<(), u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .udp_set_hop_limit(socket, hop_limit)
            .map_err(linux_errno_from_udp_error)
    }

    async fn udp_send<'a>(
        &'a self,
        socket: Net::UdpSocket,
        remote: syscall::SocketAddr,
        bytes: &'a [u8],
        timeout_nanos: u64,
    ) -> Result<usize, u64> {
        self.check_udp_open()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let sent = service
            .udp_send_address(
                socket,
                linux_to_network_ip(remote.ip),
                remote.port,
                bytes,
                timeout_nanos,
            )
            .await
            .map_err(linux_errno_from_udp_error)?;
        Ok(sent as usize)
    }

    async fn udp_receive(
        &self,
        socket: Net::UdpSocket,
        max_bytes: u32,
        timeout_nanos: u64,
        peek: bool,
    ) -> Result<Option<(Bytes, syscall::SocketAddr, usize)>, u64> {
        self.check_udp_open()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let datagram = if peek {
            service
                .udp_peek(socket, max_bytes, timeout_nanos)
                .await
                .map_err(linux_errno_from_udp_error)?
        } else {
            service
                .udp_receive(socket, max_bytes, timeout_nanos)
                .await
                .map_err(linux_errno_from_udp_error)?
        };
        Ok(datagram.map(|d| {
            (
                d.bytes,
                syscall::SocketAddr {
                    ip: network_to_linux_ip(d.address),
                    port: d.port,
                },
                d.original_len,
            )
        }))
    }

    async fn udp_readiness(&self, socket: Net::UdpSocket) -> Result<syscall::SocketReady, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let r = service
            .udp_readiness(socket)
            .await
            .map_err(linux_errno_from_udp_error)?;
        Ok(syscall::SocketReady {
            readable: r.readable,
            writable: r.writable,
            hangup: r.hangup,
        })
    }

    async fn udp_join_multicast_v4(&self, group: [u8; 4], interface: [u8; 4]) -> Result<(), u64> {
        const EACCES: u64 = 13;
        if self.shared.grants.multicast.is_none() {
            return Err(EACCES);
        }
        self.check_udp_open()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .udp_join_multicast_v4(
                crate::Ipv4Address::new(group),
                crate::Ipv4Address::new(interface),
            )
            .await
            .map_err(linux_errno_from_udp_error)
    }

    async fn udp_leave_multicast_v4(&self, group: [u8; 4], interface: [u8; 4]) -> Result<(), u64> {
        const EACCES: u64 = 13;
        if self.shared.grants.multicast.is_none() {
            return Err(EACCES);
        }
        self.check_udp_open()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .udp_leave_multicast_v4(
                crate::Ipv4Address::new(group),
                crate::Ipv4Address::new(interface),
            )
            .await
            .map_err(linux_errno_from_udp_error)
    }

    fn check_multicast_v6(&self) -> Result<(), u64> {
        const EACCES: u64 = 13;
        if self.shared.grants.multicast.is_none() {
            return Err(EACCES);
        }
        self.check_udp_open()
    }

    async fn interface_mac(&self) -> Result<[u8; 6], u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .mac_address(NetworkPortId::new(0))
            .await
            .map(crate::MacAddress::octets)
            .map_err(linux_errno_from_control_error)
    }

    async fn list_ipv4_addresses(&self) -> Result<Vec<syscall::Ipv4InterfaceAddress>, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let addrs = service
            .list_addresses(NetworkPortId::new(0))
            .await
            .map_err(linux_errno_from_control_error)?;
        Ok(addrs
            .into_iter()
            .map(|cidr| syscall::Ipv4InterfaceAddress {
                address: cidr.address().octets(),
                prefix: cidr.prefix_len(),
            })
            .collect())
    }

    async fn add_ipv4_address(&self, address: syscall::Ipv4InterfaceAddress) -> Result<(), u64> {
        self.check_net_admin()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let cidr = KernelIpv4Cidr::new(crate::Ipv4Address::new(address.address), address.prefix);
        service
            .add_address(NetworkPortId::new(0), cidr)
            .await
            .map_err(linux_errno_from_control_error)
    }

    async fn remove_ipv4_address(&self, address: syscall::Ipv4InterfaceAddress) -> Result<(), u64> {
        self.check_net_admin()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let cidr = KernelIpv4Cidr::new(crate::Ipv4Address::new(address.address), address.prefix);
        service
            .remove_address(NetworkPortId::new(0), cidr)
            .await
            .map_err(linux_errno_from_control_error)
    }

    async fn list_ipv4_routes(&self) -> Result<Vec<syscall::Ipv4RouteEntry>, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let routes = service
            .list_routes(NetworkPortId::new(0))
            .await
            .map_err(linux_errno_from_control_error)?;
        Ok(routes
            .into_iter()
            .map(|route| {
                let gw = route.gateway().octets();
                syscall::Ipv4RouteEntry {
                    destination: route.destination().address().octets(),
                    prefix: route.destination().prefix_len(),
                    gateway: if gw == [0, 0, 0, 0] { None } else { Some(gw) },
                }
            })
            .collect())
    }

    async fn add_ipv4_route(&self, route: syscall::Ipv4RouteEntry) -> Result<(), u64> {
        self.check_net_admin()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let cidr = KernelIpv4Cidr::new(crate::Ipv4Address::new(route.destination), route.prefix);
        let gw = crate::Ipv4Address::new(route.gateway.unwrap_or([0, 0, 0, 0]));
        service
            .add_route(NetworkPortId::new(0), KernelIpv4Route::new(cidr, gw))
            .await
            .map_err(linux_errno_from_control_error)
    }

    async fn remove_ipv4_route(&self, route: syscall::Ipv4RouteEntry) -> Result<(), u64> {
        self.check_net_admin()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let cidr = KernelIpv4Cidr::new(crate::Ipv4Address::new(route.destination), route.prefix);
        let gw = crate::Ipv4Address::new(route.gateway.unwrap_or([0, 0, 0, 0]));
        service
            .remove_route(NetworkPortId::new(0), KernelIpv4Route::new(cidr, gw))
            .await
            .map_err(linux_errno_from_control_error)
    }

    fn check_net_admin(&self) -> Result<(), u64> {
        const EPERM: u64 = 1;
        if self.shared.grants.network_admin.is_none() {
            return Err(EPERM);
        }
        Ok(())
    }

    fn packet_open(
        &self,
        protocol: u16,
    ) -> Result<Arc<helios_unix::OwnedPacketSocket<crate::UnixNetwork<Net>>>, u64> {
        self.check_net_admin()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let id = service
            .packet_open(protocol)
            .map_err(linux_errno_from_udp_error)?;
        Ok(helios_unix::OwnedPacketSocket::new(
            crate::UnixNetwork::new(service),
            id,
        ))
    }

    fn packet_bind(&self, socket: u64, protocol: u16, ifindex: u32) -> Result<(), u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .packet_bind(socket, protocol, ifindex)
            .map_err(linux_errno_from_udp_error)
    }

    async fn packet_send<'a>(
        &'a self,
        socket: u64,
        ifindex: u32,
        frame: &'a [u8],
    ) -> Result<usize, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .packet_send(socket, ifindex, frame)
            .await
            .map_err(linux_errno_from_udp_error)
    }

    async fn packet_receive(
        &self,
        socket: u64,
        max_bytes: u32,
        timeout_nanos: u64,
        peek: bool,
    ) -> Result<Option<syscall::PacketFrameData>, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let frame = service
            .packet_receive(socket, max_bytes, timeout_nanos, peek)
            .await
            .map_err(linux_errno_from_udp_error)?;
        Ok(frame.map(|f| syscall::PacketFrameData {
            ifindex: f.ifindex,
            protocol: f.protocol,
            bytes: f.bytes,
            original_len: f.original_len,
        }))
    }

    async fn packet_readiness(&self, socket: u64) -> Result<syscall::SocketReady, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let ready = service
            .packet_readiness(socket)
            .await
            .map_err(linux_errno_from_udp_error)?;
        Ok(syscall::SocketReady {
            readable: ready.readable,
            writable: ready.writable,
            hangup: ready.hangup,
        })
    }
}

fn linux_errno_from_control_error(error: NetworkControlError) -> u64 {
    const EINVAL: u64 = 22;
    const EIO: u64 = 5;
    const EOPNOTSUPP: u64 = 95;
    match error {
        NetworkControlError::PortUnavailable => syscall::ENODEV,
        NetworkControlError::BridgeUnavailable => EOPNOTSUPP,
        NetworkControlError::InvalidBridgeRequest
        | NetworkControlError::InvalidAddress
        | NetworkControlError::InvalidRoute
        | NetworkControlError::RouteTimestampOutOfRange => EINVAL,
        NetworkControlError::BackendFault => EIO,
    }
}

/// Calling thread's context view for `arch_prctl` and `clone` / `clone3`.
struct ContextThread<'a, CpuImpl, Net, StorageImpl, Context: UserContext>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    context: &'a mut Context,
    shared: &'a Arc<LinuxShared<CpuImpl, Net, StorageImpl, Context::Space>>,
}

impl<CpuImpl, Net, StorageImpl, Context: UserContext> Thread<LinuxResources<Net>>
    for ContextThread<'_, CpuImpl, Net, StorageImpl, Context>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn thread_pointer(&self) -> u64 {
        self.context.thread_pointer().raw() as u64
    }

    fn set_thread_pointer(&mut self, address: u64) -> Result<(), Denied> {
        self.context
            .set_thread_pointer(VirtAddr::new(address as usize))
            .map_err(|_| Denied)
    }

    fn stack_pointer(&self) -> u64 {
        self.context
            .register(self.shared.abi.stack_pointer_register())
            .expect("the ABI names registers of this instruction set")
    }

    fn spawn_thread(
        &mut self,
        child: Process<LinuxResources<Net>>,
        state: SpawnedThread,
    ) -> Result<(), SpawnError> {
        let mut child_context = self
            .context
            .try_clone()
            .map_err(|_| SpawnError::OutOfMemory)?;
        if let Some(tls) = state.tls {
            child_context
                .set_thread_pointer(VirtAddr::new(tls as usize))
                .map_err(|_| SpawnError::InvalidTls)?;
        }
        if let Some(stack) = state.stack {
            child_context
                .set_register(self.shared.abi.stack_pointer_register(), stack)
                .expect("the ABI names registers of this instruction set");
        }
        child_context
            .set_register(self.shared.registers.result, 0)
            .expect("the ABI names registers of this instruction set");
        let child_platform = LinuxThreadPlatform::new(self.shared.clone(), child.tid());
        self.shared.running_tasks.fetch_add(1, Ordering::SeqCst);
        let guard = TaskDrainGuard(self.shared.clone());
        self.shared
            .spawner
            .try_spawn_detached(async move {
                drive_linux_thread(child_context, child, child_platform).await;
                drop(guard);
            })
            .map_err(|error| {
                tracing::warn!(
                    target: "helios_kernel::linux",
                    instance = ?self.shared.launched_instance.id(),
                    %error,
                    "refused a Linux thread: the executor's instance share is full"
                );
                SpawnError::Busy
            })
    }
}

/// What ended a system call a thread was suspended in.
enum CallEnd {
    Done(ControlFlow<Exit, SyscallOutcome>),
    /// Thread-group exit or instance kill arrived; the loop's next check acts
    /// on it.
    Stopped,
}

fn forward_external_signals(process_signals: &ProcessSignals, external_signals: &WasixSignalState) {
    while let Some(signal) = external_signals.take_pending() {
        process_signals.raise_external(signal);
    }
}

fn check_thread_stop<CpuImpl, Net, StorageImpl, Space>(
    process: &mut Process<LinuxResources<Net>>,
    shared: &LinuxShared<CpuImpl, Net, StorageImpl, Space>,
) -> bool
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    if let Some(reason) = shared.launched_instance.pending_kill() {
        match reason {
            crate::KillReason::Operator | crate::KillReason::RequesterGone => {
                process.terminate_group(helios_unix::ChildTermination::Killed);
            }
            crate::KillReason::OutOfMemory
            | crate::KillReason::SupervisorRestart
            | crate::KillReason::StoreFailed => {
                shared.record_fatal(map_program_runtime_error(wasmtime::Error::from(
                    crate::InstanceKilled { reason },
                )));
                process.terminate_group(helios_unix::ChildTermination::Killed);
            }
        }
        return true;
    }
    if process.group_ended() {
        return true;
    }
    forward_external_signals(&process.process_signals(), &shared.signal_state);
    false
}

/// Parks the thread while its process is stopped (`SIGSTOP`/`SIGTSTP`/etc.)
/// until `SIGCONT`, `SIGKILL`, group termination, or an instance kill arrives.
async fn wait_while_stopped<CpuImpl, Net, StorageImpl, Space>(
    process: &mut Process<LinuxResources<Net>>,
    shared: &LinuxShared<CpuImpl, Net, StorageImpl, Space>,
    observer: &syscall::ProcessObserver,
) -> bool
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let proc_signals = process.process_signals();
    loop {
        if check_thread_stop(process, shared) {
            return true;
        }
        let mut stop_wait = proc_signals.stop_waiter();
        let mut group_wait = observer.waiter();
        let mut signal_wait = shared.signal_state.wait_state();
        let mut kill_wait = shared.launched_instance.arm_kill_wait();
        forward_external_signals(&proc_signals, &shared.signal_state);
        if !proc_signals.is_stopped() {
            return false;
        }
        if check_thread_stop(process, shared) {
            return true;
        }
        core::future::poll_fn(|cx| {
            let resumed = proc_signals
                .poll_stop_changed(cx, &mut stop_wait)
                .is_ready();
            let group_stopped = observer.poll_changed(cx, &mut group_wait).is_ready();
            let signalled = shared
                .signal_state
                .poll_changed(cx, &mut signal_wait)
                .is_ready();
            let killed = shared
                .launched_instance
                .poll_kill_wait(cx, &mut kill_wait)
                .is_ready();
            if resumed || group_stopped || signalled || killed {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }
}

/// Applies signal delivery on return to user mode. Returns `true` when the
/// thread group was terminated and the driving loop should exit.
fn deliver_and_apply<CpuImpl, Net, StorageImpl, Context>(
    process: &mut Process<LinuxResources<Net>>,
    context: &mut Context,
    shared: &LinuxShared<CpuImpl, Net, StorageImpl, Context::Space>,
    restart: Option<SyscallRestart>,
) -> bool
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
    Context: UserContext,
{
    let mut memory = LinuxMemory {
        space: &*shared.space,
        user: shared.user,
        stack_growth: Some(shared.stack_growth(process.limit(Resource::Stack).current)),
    };
    match process.deliver_pending_signals(
        context,
        &mut memory,
        restart,
        shared.sigreturn_trampoline,
    ) {
        SignalDelivery::None | SignalDelivery::Delivered | SignalDelivery::Stopped => false,
        SignalDelivery::Terminated { signal, .. } => {
            // No core dump file is produced (`RLIMIT_CORE` default is 0), so
            // `WCOREDUMP` stays false as on Linux.
            process.terminate_group(helios_unix::ChildTermination::Signaled(
                helios_unix::SignalTermination {
                    signal: signal.raw(),
                    core_dumped: false,
                },
            ));
            true
        }
    }
}

/// Delivers an unresolvable hardware fault as a Linux signal (`force_sig_fault`
/// semantics). Returns `true` when the thread group terminated.
fn handle_unresolvable_fault<CpuImpl, Net, StorageImpl, Context>(
    process: &mut Process<LinuxResources<Net>>,
    context: &mut Context,
    shared: &LinuxShared<CpuImpl, Net, StorageImpl, Context::Space>,
    instance_id: crate::InstanceId,
    mut fault: UserFault,
) -> bool
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
    Context: UserContext,
{
    // Linux decides `SEGV_MAPERR` vs `SEGV_ACCERR` from VMA presence rather
    // than hardware PTE residency: a first write to a lazy-committed `PROT_READ`
    // or `PROT_NONE` mapping faults with `present == false` in hardware yet
    // delivers `SEGV_ACCERR` because the mapping exists.
    if let FaultKind::Page {
        address,
        present: ref mut present @ false,
        ..
    } = fault.kind
        && shared.user.contains(address)
        && shared
            .space
            .mapping(VirtRange::new(address.page_floor(), PhysFrame::SIZE))
            .is_some()
    {
        *present = true;
    }
    let mut memory = LinuxMemory {
        space: &*shared.space,
        user: shared.user,
        stack_growth: Some(shared.stack_growth(process.limit(Resource::Stack).current)),
    };
    match process.deliver_fault_signal(fault, context, &mut memory, shared.sigreturn_trampoline) {
        SignalDelivery::Delivered => false,
        SignalDelivery::Terminated { signal, .. } => {
            tracing::debug!(
                target: "helios_kernel::linux",
                instance = ?instance_id,
                tid = process.tid().get(),
                ?fault,
                signal = signal.raw(),
                "Linux thread faulted"
            );
            process.terminate_group(helios_unix::ChildTermination::Signaled(
                helios_unix::SignalTermination {
                    signal: signal.raw(),
                    core_dumped: false,
                },
            ));
            true
        }
        SignalDelivery::None | SignalDelivery::Stopped => false,
    }
}

/// Drives one Linux thread (`main` or a `clone`-spawned worker) until that
/// thread exits (`exit`), condemns the group (`exit_group`, unhandled fault,
/// OOM), or observes condemnation from a sibling, signal or kill.
async fn drive_linux_thread<CpuImpl, Net, StorageImpl, Context>(
    mut context: Context,
    mut process: Process<LinuxResources<Net>>,
    mut platform: LinuxThreadPlatform<CpuImpl, Net, StorageImpl, Context::Space>,
) where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
    Context: UserContext,
{
    let shared = platform.shared.clone();
    let observer = process.observer();
    let proc_signals = process.process_signals();
    let instance_id = shared.launched_instance.id();
    let registers = shared.registers;
    loop {
        if check_thread_stop(&mut process, &shared) {
            break;
        }
        if process.is_stopped() && wait_while_stopped(&mut process, &shared, &observer).await {
            break;
        }
        if deliver_and_apply(&mut process, &mut context, &shared, None) {
            break;
        }
        if process.is_stopped() {
            continue;
        }
        let slice_began = shared.cpu.now().ticks();
        let stop = context.resume(&shared.space);
        let elapsed = shared.cpu.now().ticks().saturating_sub(slice_began);
        platform.thread_cpu_ticks += elapsed;
        shared
            .process_cpu_ticks
            .fetch_add(elapsed, Ordering::Relaxed);
        let user_ns = shared.cpu.timebase().ticks_to_nanos(elapsed);
        process.account_cpu_timers(user_ns, user_ns);
        match stop {
            Stop::SystemCall => {
                let (call, orig_reg) = {
                    let read = |register| {
                        context
                            .register(register)
                            .expect("the ABI names registers of this instruction set")
                    };
                    (
                        Call {
                            number: read(registers.number),
                            arguments: registers.arguments.map(read),
                        },
                        read(registers.result),
                    )
                };
                // Arm every stop source before testing them so an `exit_group`,
                // signal or kill raised during the user slice cannot be missed
                // before `dispatch` suspends.
                let mut group_wait = observer.waiter();
                let mut signal_wait = shared.signal_state.wait_state();
                let mut kill_wait = shared.launched_instance.arm_kill_wait();
                if check_thread_stop(&mut process, &shared) {
                    break;
                }
                let syscall_began = shared.cpu.now().ticks();
                let ended = {
                    let mut memory = LinuxMemory {
                        space: &*shared.space,
                        user: shared.user,
                        stack_growth: Some(
                            shared.stack_growth(process.limit(Resource::Stack).current),
                        ),
                    };
                    let mut thread = ContextThread {
                        context: &mut context,
                        shared: &shared,
                    };
                    let mut call = core::pin::pin!(syscall::dispatch(
                        &mut process,
                        call,
                        &mut memory,
                        &mut thread,
                        &mut platform,
                    ));
                    core::future::poll_fn(|cx| {
                        // Forward any externally raised signals into Linux's
                        // signal mailbox so blocking syscalls observe them via
                        // their own `ThreadSignalSlot` and handle masks/EINTR.
                        if shared
                            .signal_state
                            .poll_changed(cx, &mut signal_wait)
                            .is_ready()
                        {
                            forward_external_signals(&proc_signals, &shared.signal_state);
                            signal_wait = shared.signal_state.wait_state();
                            let _ = shared.signal_state.poll_changed(cx, &mut signal_wait);
                        }
                        if let Poll::Ready(flow) = call.as_mut().poll(cx) {
                            return Poll::Ready(CallEnd::Done(flow));
                        }
                        let group_stopped = observer.poll_changed(cx, &mut group_wait).is_ready();
                        let killed = shared
                            .launched_instance
                            .poll_kill_wait(cx, &mut kill_wait)
                            .is_ready();
                        if group_stopped || killed {
                            Poll::Ready(CallEnd::Stopped)
                        } else {
                            Poll::Pending
                        }
                    })
                    .await
                };
                let sys_elapsed = shared.cpu.now().ticks().saturating_sub(syscall_began);
                let sys_ns = shared.cpu.timebase().ticks_to_nanos(sys_elapsed);
                process.account_cpu_timers(0, sys_ns);
                match ended {
                    CallEnd::Done(ControlFlow::Continue(SyscallOutcome::Return(result))) => {
                        context
                            .set_register(registers.result, result)
                            .expect("the ABI names registers of this instruction set");
                    }
                    CallEnd::Done(ControlFlow::Continue(SyscallOutcome::RestartSys)) => {
                        if deliver_and_apply(
                            &mut process,
                            &mut context,
                            &shared,
                            Some(SyscallRestart::RestartSys { orig_reg }),
                        ) {
                            break;
                        }
                    }
                    CallEnd::Done(ControlFlow::Continue(SyscallOutcome::RestartNoHand)) => {
                        if deliver_and_apply(
                            &mut process,
                            &mut context,
                            &shared,
                            Some(SyscallRestart::RestartNoHand { orig_reg }),
                        ) {
                            break;
                        }
                    }
                    CallEnd::Done(ControlFlow::Continue(SyscallOutcome::SigReturn)) => {
                        let memory = LinuxMemory {
                            space: &*shared.space,
                            user: shared.user,
                            stack_growth: None,
                        };
                        if process.restore_signal_frame(&mut context, &memory).is_err() {
                            process.terminate_group(helios_unix::ChildTermination::Signaled(
                                helios_unix::SignalTermination {
                                    signal: helios_unix::Signal::SIGSEGV.raw(),
                                    core_dumped: false,
                                },
                            ));
                            break;
                        }
                    }
                    CallEnd::Done(ControlFlow::Break(_)) => break,
                    CallEnd::Stopped => {}
                }
            }
            Stop::Preempted | Stop::Interrupted => crate::yield_now().await,
            Stop::Fault(fault) => match fault.kind {
                // An uncommitted page's first touch, a translation older than
                // the page's current access, or growth of the initial stack:
                // resolved atomically against concurrent sibling VM ops.
                FaultKind::Page {
                    address,
                    access,
                    present,
                } if shared.user.contains(address) => {
                    match shared.space.resolve_fault(address, access) {
                        Ok(()) => {}
                        Err(NativeError::OutOfMemory) => {
                            shared.record_fatal(native_error(NativeError::OutOfMemory));
                            process.terminate_group(helios_unix::ChildTermination::Killed);
                            break;
                        }
                        Err(NativeError::NotMapped)
                            if !present
                                && !access.contains(PageFlags::EXECUTE)
                                && shared
                                    .stack_growth(process.limit(Resource::Stack).current)
                                    .contains(address) =>
                        {
                            let page = VirtRange::new(address.page_floor(), PhysFrame::SIZE);
                            match shared
                                .space
                                .map(page, &[], PageFlags::READ | PageFlags::WRITE)
                            {
                                // Commit the new stack page in the same fault
                                // rather than taking a second fault on resume;
                                // `Overlap` means a sibling thread already
                                // mapped or grew this page concurrently.
                                Ok(()) | Err(NativeError::Overlap) => {
                                    match shared.space.resolve_fault(address, access) {
                                        Ok(()) => {}
                                        Err(NativeError::OutOfMemory) => {
                                            shared.record_fatal(native_error(
                                                NativeError::OutOfMemory,
                                            ));
                                            process.terminate_group(
                                                helios_unix::ChildTermination::Killed,
                                            );
                                            break;
                                        }
                                        Err(NativeError::NotMapped) => {
                                            if handle_unresolvable_fault(
                                                &mut process,
                                                &mut context,
                                                &shared,
                                                instance_id,
                                                fault,
                                            ) {
                                                break;
                                            }
                                        }
                                        Err(error) => panic!(
                                            "resolving a stack-growth fault on {page:?}: {error}"
                                        ),
                                    }
                                }
                                Err(NativeError::OutOfMemory) => {
                                    shared.record_fatal(native_error(NativeError::OutOfMemory));
                                    process.terminate_group(helios_unix::ChildTermination::Killed);
                                    break;
                                }
                                Err(error) => {
                                    panic!("growing a Linux stack into {page:?}: {error}")
                                }
                            }
                        }
                        Err(NativeError::NotMapped) => {
                            if handle_unresolvable_fault(
                                &mut process,
                                &mut context,
                                &shared,
                                instance_id,
                                fault,
                            ) {
                                break;
                            }
                        }
                        Err(error) => panic!("resolving a page fault at {address:?}: {error}"),
                    }
                }
                _ => {
                    if handle_unresolvable_fault(
                        &mut process,
                        &mut context,
                        &shared,
                        instance_id,
                        fault,
                    ) {
                        break;
                    }
                }
            },
        }
    }
    let memory = LinuxMemory {
        space: &*shared.space,
        user: shared.user,
        stack_growth: None,
    };
    process.flush_shared_mappings(&memory, &mut platform).await;
}

/// Drives a process's `ITIMER_REAL` (`alarm` / `setitimer`) asynchronously
/// until every thread of the process has exited, without holding any spin lock
/// across `.await`.
async fn drive_real_timer<CpuImpl, Net, StorageImpl>(
    cpu: CpuImpl,
    timer: crate::Timer<CpuImpl>,
    runtime_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
    proc_signals: Arc<ProcessSignals>,
    observer: syscall::ProcessObserver,
) where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    loop {
        let mut group_wait = observer.waiter();
        let mut timer_wait = proc_signals.real_timer_waiter();
        if observer.all_threads_exited() || observer.group_ended() {
            return;
        }
        let now = runtime_state.uptime_nanos(cpu.now().ticks());
        if proc_signals.fire_real_timer_if_due(now) {
            continue;
        }
        let deadline = proc_signals.next_real_timer_deadline();
        match deadline {
            None => {
                core::future::poll_fn(|cx| {
                    if observer.poll_changed(cx, &mut group_wait).is_ready()
                        || proc_signals
                            .poll_real_timer_changed(cx, &mut timer_wait)
                            .is_ready()
                    {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
            }
            Some((target_ns, _generation)) => {
                let remaining = target_ns.saturating_sub(now);
                let sleep = timer.sleep_for(Duration::from_nanos(remaining));
                let mut sleep = core::pin::pin!(sleep);
                core::future::poll_fn(|cx| {
                    if observer.poll_changed(cx, &mut group_wait).is_ready()
                        || proc_signals
                            .poll_real_timer_changed(cx, &mut timer_wait)
                            .is_ready()
                        || sleep.as_mut().poll(cx).is_ready()
                    {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
            }
        }
    }
}

/// Computes the initial stack top and, when `abi` supplies a sigreturn
/// trampoline (AArch64), maps it at the top of `user` above an unmapped guard
/// page so it never collides with `brk` growth at `image_end`.
fn map_sigreturn_trampoline<Space: UserSpace>(
    space: &Space,
    user: VirtRange,
    abi: Abi,
) -> Result<(u64, u64), NativeError> {
    if let Some(code) = abi.sigreturn_trampoline_code() {
        let trampoline = VirtAddr::new(user.end().raw() - PhysFrame::SIZE);
        space.map(
            VirtRange::new(trampoline, PhysFrame::SIZE),
            code,
            PageFlags::READ | PageFlags::EXECUTE,
        )?;
        Ok((
            (user.end().raw() - 2 * PhysFrame::SIZE) as u64,
            trampoline.raw() as u64,
        ))
    } else {
        Ok(((user.end().raw() - PhysFrame::SIZE) as u64, 0))
    }
}

/// Runs a Linux process inside `container` to its end: maps `executable`,
/// builds its initial stack from `argv` and `env`, allocates its container-local
/// PID (starting at 1), drives `main` and every thread spawned via
/// `clone` / `clone3`, and returns once every thread task has exited and
/// released the process's resources.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_linux_process<CpuImpl, Net, StorageImpl>(
    exec_context: ProgramExecContext<CpuImpl, Net, StorageImpl>,
    argv: ProgramArgv,
    env: Vec<(String, String)>,
    container: Arc<crate::LinuxContainer<StorageImpl>>,
    credentials: Option<syscall::Credentials>,
    descriptors: Option<Preview1DescriptorTable<Net>>,
    signal_state: WasixSignalState,
    spawner: crate::InstanceSpawner<CpuImpl>,
    launched_instance: crate::RegisteredInstance,
    output_mode: OutputMode,
    executable: LinuxExecutable,
    timeline: &phases::Timeline,
) -> Result<ChildExit, ProgramExecError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let instance_id = launched_instance.id();
    timeline.set_instance(instance_id);
    timeline.record(&exec_context.cpu, LaunchPhase::TaskBegin);
    let cpu = exec_context.cpu.clone();
    let native = cpu.native().map_err(native_unavailable)?;
    let image =
        Image::parse(&executable.image, executable.abi, user_end(native)).map_err(image_error)?;
    let space = Arc::new(native.create_space().map_err(native_error)?);
    // The end of the highest segment: the stack never grows down past it,
    // whatever its limit, so a wild pointer into the unmapped space below
    // the stack stays a fault.
    let mut image_end = 0;
    for segment in image.segments() {
        let mut flags = PageFlags::READ;
        flags.set(PageFlags::WRITE, segment.writable);
        flags.set(PageFlags::EXECUTE, segment.executable);
        let range = VirtRange::new(
            VirtAddr::new(segment.address as usize),
            segment.memory_size as usize,
        );
        image_end = image_end.max(range.end().raw().next_multiple_of(PhysFrame::SIZE));
        space
            .map(range, segment.bytes, flags)
            .map_err(native_error)?;
    }

    let argv = argv.into_vec();
    let environment: Vec<String> = env
        .into_iter()
        .map(|(name, value)| {
            let mut variable = String::with_capacity(name.len() + 1 + value.len());
            variable.push_str(&name);
            variable.push('=');
            variable.push_str(&value);
            variable
        })
        .collect();
    let arguments: Vec<&[u8]> = argv.iter().map(String::as_bytes).collect();
    let variables: Vec<&[u8]> = environment.iter().map(String::as_bytes).collect();
    let mut random = [0; 16];
    exec_context.runtime_state.root_entropy().fill(&mut random);
    let user = native.user_range();
    let (top, sigreturn_trampoline) =
        map_sigreturn_trampoline(&*space, user, executable.abi).map_err(native_error)?;
    let stack = helios_linux::stack::build(
        &helios_linux::stack::Startup {
            entry: image.entry(),
            page_size: PhysFrame::SIZE as u64,
            headers: image.program_headers().map_err(image_error)?,
            random,
            arguments: &arguments,
            environment: &variables,
            // The name the program was invoked under; the resolved path
            // does not travel with a launch.
            executable: arguments[0],
        },
        top,
    )
    .map_err(|_| ProgramExecError {
        kind: ProgramExecErrorKind::InvalidPath,
        detail: ProgramExecErrorDetail::InvalidProgramPath,
    })?;
    space
        .map(
            VirtRange::new(VirtAddr::new(stack.base as usize), stack.bytes.len()),
            &stack.bytes,
            PageFlags::READ | PageFlags::WRITE,
        )
        .map_err(native_error)?;
    let context = native
        .create_context(
            VirtAddr::new(image.entry() as usize),
            VirtAddr::new(stack.pointer as usize),
        )
        .map_err(native_error)?;

    let process_guard = container.allocate_process().map_err(|_| ProgramExecError {
        kind: ProgramExecErrorKind::OutOfMemory,
        detail: ProgramExecErrorDetail::ContainerRefused(crate::RuntimeMessage::of(
            "container PID namespace exhausted",
        )),
    })?;
    let pid = process_guard.pid();
    let table = match descriptors {
        Some(table) => table.into_slots(),
        None => syscall::standard_streams::<LinuxResources<Net>>(),
    };
    let credentials = credentials.unwrap_or_else(|| container.default_credentials().clone());
    let initial_cwd = container
        .authority()
        .cwd()
        .map(|preopen| String::from(preopen.guest_name()));
    let process = Process::<LinuxResources<Net>>::with_descriptors(
        executable.abi,
        pid,
        image.program_break(PhysFrame::SIZE as u64),
        table,
        Start {
            credentials,
            memory_bytes: crate::machine_memory().usable_bytes as u64,
            futex: container.futex_table().clone(),
            pids: Some(container.pid_namespace().clone()),
            memory_id: Some(instance_id.raw()),
            cwd: initial_cwd,
            ..Start::default()
        },
    );
    let observer = process.observer();
    let proc_signals = process.process_signals();
    let grants = LinuxGrants::derive(container.authority());
    let tty = LinuxTtyState::new(container.authority(), &output_mode, instance_id);
    let shared = Arc::new(LinuxShared {
        cpu: cpu.clone(),
        timer: exec_context.timer.clone(),
        spawner,
        runtime_state: exec_context.runtime_state.clone(),
        read_serial: exec_context.read_serial,
        write_serial: exec_context.write_serial,
        output_mode,
        launched_instance,
        signal_state,
        container,
        _process_guard: process_guard,
        grants,
        tty: spin::Mutex::new(tty),
        serial_peek: spin::Mutex::new(Vec::new()),
        clock: spin::Mutex::new(crate::KernelClock::new(
            cpu.clone(),
            exec_context.runtime_state.clone(),
        )),
        abi: executable.abi,
        registers: executable.abi.system_call_registers(),
        user,
        stack_top: top,
        stack_base: stack.base as usize,
        image_end,
        sigreturn_trampoline,
        space,
        process_cpu_ticks: AtomicU64::new(0),
        fatal_error: spin::Mutex::new(None),
        running_tasks: AtomicUsize::new(0),
        tasks_drained: helios_sync::Notify::new(),
    });
    let main_platform = LinuxThreadPlatform::new(shared.clone(), pid);

    timeline.record(&cpu, LaunchPhase::GuestBegin);
    let real_timer_driver = drive_real_timer(
        cpu.clone(),
        shared.timer.clone(),
        shared.runtime_state.clone(),
        proc_signals.clone(),
        observer.clone(),
    );
    let main_and_siblings = async {
        // `drive_linux_thread` consumes `main`'s `Process` and `Context`, so if
        // `main` calls `SYS_exit` (`pthread_exit`) while worker threads
        // continue, `main`'s thread handle withdraws immediately without
        // holding the group open.
        drive_linux_thread(context, process, main_platform).await;

        // Wait for every live sibling thread to exit, still honouring external
        // signals and instance kills while `main` is already gone.
        loop {
            let mut group_wait = observer.waiter();
            let mut signal_wait = shared.signal_state.wait_state();
            let mut kill_wait = shared.launched_instance.arm_kill_wait();
            if let Some(reason) = shared.launched_instance.pending_kill() {
                match reason {
                    crate::KillReason::Operator | crate::KillReason::RequesterGone => {
                        observer.terminate_group(helios_unix::ChildTermination::Killed);
                    }
                    crate::KillReason::OutOfMemory
                    | crate::KillReason::SupervisorRestart
                    | crate::KillReason::StoreFailed => {
                        shared.record_fatal(map_program_runtime_error(wasmtime::Error::from(
                            crate::InstanceKilled { reason },
                        )));
                        observer.terminate_group(helios_unix::ChildTermination::Killed);
                    }
                }
            } else if !observer.group_ended() {
                forward_external_signals(&proc_signals, &shared.signal_state);
            }
            if observer.all_threads_exited() {
                break;
            }
            core::future::poll_fn(|cx| {
                let group_changed = observer.poll_changed(cx, &mut group_wait).is_ready();
                let signalled = shared
                    .signal_state
                    .poll_changed(cx, &mut signal_wait)
                    .is_ready();
                let killed = shared
                    .launched_instance
                    .poll_kill_wait(cx, &mut kill_wait)
                    .is_ready();
                if group_changed || signalled || killed {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
    };
    futures::future::join(main_and_siblings, real_timer_driver).await;

    // Wait for every detached thread task to drop its `Process` (descriptor
    // table) and `Arc<Space>` before reporting `ChildExit` to the parent.
    shared.wait_tasks_drained().await;
    timeline.record(&cpu, LaunchPhase::GuestEnd);

    let fatal = shared.take_fatal();
    let termination = observer.termination();
    drop(observer);
    drop(shared);

    match fatal {
        Some(error) => Err(error),
        None => Ok(ChildExit {
            instance_id,
            termination,
            filesystem: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{
        NativeSpace, UserMemoryPool, UserTranslation, install_user_memory_pool,
        installed_user_memory_pool,
    };
    use core::alloc::Layout;
    use core::ptr::NonNull;

    fn ensure_pool() {
        const POOL_BYTES: usize = 4 * 1024 * 1024;
        if installed_user_memory_pool().is_some() {
            return;
        }
        let layout = Layout::from_size_align(POOL_BYTES, PhysFrame::SIZE).expect("pool layout");
        // SAFETY: nonzero size, leaked for the lifetime of the test process.
        let base = unsafe { alloc::alloc::alloc_zeroed(layout) } as usize;
        assert!(base != 0, "pool backing");
        install_user_memory_pool(UserMemoryPool::single_node(1, &[(base, base + POOL_BYTES)]));
    }

    struct DummyTables;

    // SAFETY: host unit test uses `NativeSpace`'s direct-map operations only
    // and never enters hardware user mode.
    unsafe impl UserTranslation for DummyTables {
        fn install(&mut self, _: u64, _: u64, _: PageFlags) -> Result<(), NativeError> {
            Ok(())
        }
        fn uninstall(&mut self, _: u64) {}
        fn protect(&mut self, _: u64, _: PageFlags) {}
        fn invalidate(&self, _: u64, _: u64) {}
        fn physical(&self, frame: NonNull<u8>) -> u64 {
            frame.as_ptr() as u64
        }
    }

    #[test]
    fn linux_memory_atomic_u32_ops_commit_discarded_pages_and_enforce_permissions() {
        ensure_pool();
        let start = PhysFrame::SIZE;
        let end = 1 << 32;
        let space = NativeSpace::new(DummyTables, start as u64, end as u64);
        let user = VirtRange::new(VirtAddr::new(start), end - start);
        let mut memory = LinuxMemory {
            space: &space,
            user,
            stack_growth: None,
        };

        let rw_addr = 0x10_000u64;
        memory
            .map_at(
                rw_addr,
                PhysFrame::SIZE as u64,
                PageFlags::READ | PageFlags::WRITE,
            )
            .unwrap();
        assert_eq!(memory.atomic_load_u32(rw_addr + 2), Err(MemoryFault));
        assert_eq!(memory.atomic_load_u32(0x20_000), Err(MemoryFault));
        assert_eq!(memory.atomic_load_u32(rw_addr), Ok(0));

        // Discard leaves a zero-fill-on-demand page; atomic store commits a
        // fresh frame and writes the word.
        memory.discard(rw_addr, PhysFrame::SIZE as u64);
        assert_eq!(memory.atomic_load_u32(rw_addr), Ok(0));
        memory.atomic_store_u32(rw_addr, 0x1234_5678).unwrap();
        assert_eq!(memory.atomic_load_u32(rw_addr), Ok(0x1234_5678));
        assert_eq!(
            memory.atomic_compare_exchange_u32(rw_addr, 9, 10),
            Ok(Err(0x1234_5678))
        );
        assert_eq!(
            memory.atomic_compare_exchange_u32(rw_addr, 0x1234_5678, 0xdead_beef),
            Ok(Ok(0x1234_5678))
        );
        assert_eq!(memory.atomic_load_u32(rw_addr), Ok(0xdead_beef));

        // Narrowing to read-only keeps atomic loads working and refuses atomic
        // stores and CAS.
        memory
            .protect(rw_addr, PhysFrame::SIZE as u64, PageFlags::READ)
            .unwrap();
        assert_eq!(memory.atomic_load_u32(rw_addr), Ok(0xdead_beef));
        assert_eq!(memory.atomic_store_u32(rw_addr, 1), Err(MemoryFault));
        assert_eq!(
            memory.atomic_compare_exchange_u32(rw_addr, 0xdead_beef, 1),
            Err(MemoryFault)
        );
    }

    struct DummyThread;

    impl Thread for DummyThread {
        fn thread_pointer(&self) -> u64 {
            0
        }
        fn set_thread_pointer(&mut self, _: u64) -> Result<(), Denied> {
            Err(Denied)
        }
        fn spawn_thread(
            &mut self,
            _: Process<helios_linux::syscall::NoBacking>,
            _: SpawnedThread,
        ) -> Result<(), SpawnError> {
            unreachable!("no thread spawned")
        }
    }

    struct DummyOutput;

    impl syscall::Network<helios_unix::NoNetwork> for DummyOutput {
        fn to_ip(&self, address: core::convert::Infallible) -> syscall::IpAddr {
            match address {}
        }
        fn encode_ip(&self, _: syscall::IpAddr) -> core::convert::Infallible {
            unreachable!()
        }
    }

    impl Stdio for DummyOutput {
        async fn write(&mut self, _: Stream, _: &[u8]) -> Result<usize, WriteError> {
            Err(WriteError::Io)
        }
        async fn read_input(&mut self, _: usize) -> Result<Bytes, Denied> {
            Err(Denied)
        }
    }

    impl syscall::Clock for DummyOutput {
        fn now_nanos(&self) -> u64 {
            0
        }
        async fn sleep_until(&self, _: u64) {}
    }

    impl System for DummyOutput {
        fn realtime_nanos(&self) -> u64 {
            0
        }
        fn set_realtime_nanos(&mut self, _: u64) -> Result<(), Denied> {
            Err(Denied)
        }
        fn cpu_nanos(&self) -> u64 {
            0
        }
        fn fill_random(&mut self, _: &mut [u8]) {}
        fn memory(&self) -> MemoryTotals {
            MemoryTotals {
                total_bytes: 0,
                free_bytes: 0,
            }
        }
        fn process_count(&self) -> u32 {
            1
        }
        fn kernel_version(&self) -> &str {
            "test"
        }
    }

    impl Filesystem<syscall::NoBacking> for DummyOutput {}
    impl Tty for DummyOutput {}

    #[test]
    fn linux_mmap_brk_and_mremap_commit_only_touched_pages() {
        use core::future::Future;
        use core::task::{Context, Poll, Waker};
        use helios_linux::syscall::dispatch;

        const MMAP: u64 = 9;
        const MUNMAP: u64 = 11;
        const BRK: u64 = 12;
        const MREMAP: u64 = 25;
        const PROT_RW: u64 = 0x3;
        const MAP_PRIVATE_ANON: u64 = 0x22;
        const MREMAP_MAYMOVE: u64 = 1;

        ensure_pool();
        let page = PhysFrame::SIZE as u64;
        let start = PhysFrame::SIZE;
        let end = 1usize << 32;
        let space = NativeSpace::new(DummyTables, start as u64, end as u64);
        let user = VirtRange::new(VirtAddr::new(start), end - start);
        let mut memory = LinuxMemory {
            space: &space,
            user,
            stack_growth: None,
        };
        let mut process = Process::new(Abi::X86_64, NonZeroU32::new(1).unwrap(), 0x50_0000);
        let mut call = |number: u64, arguments: [u64; 6]| -> u64 {
            let (mut thread, mut output) = (DummyThread, DummyOutput);
            let mut fut = core::pin::pin!(dispatch(
                &mut process,
                Call { number, arguments },
                &mut memory,
                &mut thread,
                &mut output,
            ));
            match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(ControlFlow::Continue(SyscallOutcome::Return(result))) => result,
                other => panic!("unexpected syscall state: {other:?}"),
            }
        };

        let baseline = crate::memory::user_heap_stats().allocated_bytes;

        // An anonymous mapping larger than the entire 4 MiB test pool succeeds
        // and takes zero frames until touched.
        let large_len = 16 * 1024 * 1024;
        let mapped = call(
            MMAP,
            [
                0x1000_0000,
                large_len,
                PROT_RW,
                MAP_PRIVATE_ANON,
                u64::MAX,
                0,
            ],
        );
        assert_eq!(mapped, 0x1000_0000);
        assert_eq!(crate::memory::user_heap_stats().allocated_bytes, baseline);

        // Touching the first and last pages commits exactly two frames.
        space
            .resolve_fault(VirtAddr::new(mapped as usize), PageFlags::WRITE)
            .unwrap();
        space
            .resolve_fault(
                VirtAddr::new((mapped + large_len - page) as usize),
                PageFlags::READ,
            )
            .unwrap();
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 2 * PhysFrame::SIZE
        );

        // `brk` growth takes zero frames until touched, then commits per touched page.
        let brk_start = call(BRK, [0; 6]);
        let brk_end = brk_start + 8 * page;
        assert_eq!(call(BRK, [brk_end, 0, 0, 0, 0, 0]), brk_end);
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 2 * PhysFrame::SIZE
        );
        space
            .resolve_fault(
                VirtAddr::new((brk_start + 5 * page) as usize),
                PageFlags::WRITE,
            )
            .unwrap();
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 3 * PhysFrame::SIZE
        );

        // `mremap` growth (beyond the entire 4 MiB pool!) keeps existing frames
        // and commits no frames for the new tail until touched.
        let small = call(MMAP, [0, 2 * page, PROT_RW, MAP_PRIVATE_ANON, u64::MAX, 0]);
        space.write(VirtAddr::new(small as usize), b"kept").unwrap();
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 4 * PhysFrame::SIZE
        );
        let grown_len = 8 * 1024 * 1024;
        let moved = call(MREMAP, [small, 2 * page, grown_len, MREMAP_MAYMOVE, 0, 0]);
        assert!(moved >= start as u64);
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 4 * PhysFrame::SIZE
        );
        let mut head = [0u8; 4];
        space
            .read(VirtAddr::new(moved as usize), &mut head)
            .unwrap();
        assert_eq!(&head, b"kept");
        space
            .resolve_fault(
                VirtAddr::new((moved + grown_len - page) as usize),
                PageFlags::WRITE,
            )
            .unwrap();
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 5 * PhysFrame::SIZE
        );

        // Unmapping and shrinking the break release every committed frame.
        assert_eq!(call(MUNMAP, [mapped, large_len, 0, 0, 0, 0]), 0);
        assert_eq!(call(MUNMAP, [moved, grown_len, 0, 0, 0, 0]), 0);
        assert_eq!(call(BRK, [brk_start, 0, 0, 0, 0, 0]), brk_start);
        assert_eq!(crate::memory::user_heap_stats().allocated_bytes, baseline);
    }

    #[test]
    fn aarch64_sigreturn_trampoline_sits_above_stack_guard_and_leaves_brk_free() {
        use core::future::Future;
        use core::task::{Context, Poll, Waker};
        use helios_linux::syscall::dispatch;

        ensure_pool();
        let page = PhysFrame::SIZE;
        let start = page;
        let end = 1usize << 32;
        let user = VirtRange::new(VirtAddr::new(start), end - start);

        // x86-64 needs no kernel trampoline and keeps one guard page above the stack.
        let x86_space = NativeSpace::new(DummyTables, start as u64, end as u64);
        let (x86_top, x86_tramp) = map_sigreturn_trampoline(&x86_space, user, Abi::X86_64).unwrap();
        assert_eq!(x86_tramp, 0);
        assert_eq!(x86_top, (end - page) as u64);
        assert_eq!(
            x86_space.mapping(VirtRange::new(VirtAddr::new(end - page), page)),
            None
        );

        // AArch64 maps the RX trampoline at the very top page, keeps an unmapped
        // guard page between the stack and the trampoline, and leaves `brk`
        // growth right at `image_end` unblocked.
        let arm_space = NativeSpace::new(DummyTables, start as u64, end as u64);
        let image_end = 0x41_0000usize;
        arm_space
            .map(
                VirtRange::new(VirtAddr::new(0x40_0000), image_end - 0x40_0000),
                &[],
                PageFlags::READ | PageFlags::EXECUTE,
            )
            .unwrap();
        let (arm_top, arm_tramp) =
            map_sigreturn_trampoline(&arm_space, user, Abi::Aarch64).unwrap();
        assert_eq!(arm_tramp, (end - page) as u64);
        assert_eq!(arm_top, (end - 2 * page) as u64);
        assert_eq!(
            arm_space
                .mapping(VirtRange::new(VirtAddr::new(end - page), page))
                .map(|m| m.flags),
            Some(PageFlags::READ | PageFlags::EXECUTE)
        );
        assert_eq!(
            arm_space.mapping(VirtRange::new(VirtAddr::new(end - 2 * page), page)),
            None
        );

        let expected_code = Abi::Aarch64.sigreturn_trampoline_code().unwrap();
        let mut actual_code = vec![0u8; expected_code.len()];
        arm_space
            .read(VirtAddr::new(arm_tramp as usize), &mut actual_code)
            .unwrap();
        assert_eq!(actual_code.as_slice(), expected_code);

        // Growing `brk` directly above `image_end` must succeed without colliding.
        const AARCH64_BRK: u64 = 214;
        let mut memory = LinuxMemory {
            space: &arm_space,
            user,
            stack_growth: None,
        };
        let mut process = Process::new(Abi::Aarch64, NonZeroU32::new(1).unwrap(), image_end as u64);
        let (mut thread, mut output) = (DummyThread, DummyOutput);
        let grown = image_end as u64 + 4 * page as u64;
        let mut fut = core::pin::pin!(dispatch(
            &mut process,
            Call {
                number: AARCH64_BRK,
                arguments: [grown, 0, 0, 0, 0, 0],
            },
            &mut memory,
            &mut thread,
            &mut output,
        ));
        match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(ControlFlow::Continue(SyscallOutcome::Return(result))) => {
                assert_eq!(result, grown);
            }
            other => panic!("unexpected aarch64 brk outcome: {other:?}"),
        }
    }
}
