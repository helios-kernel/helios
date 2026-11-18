//! The Linux process host: a static Linux executable launched through the
//! program service, as a wasm program is, run natively through the
//! platform's [`helios_hal::native`] capability.
//!
//! A Linux process is one executor task, its one thread. The task resumes
//! the thread's user context for one slice at a time and answers each
//! system call through `helios-linux`'s decoder, whose descriptors are the
//! same `helios-unix` objects a WASIX program's are: the table a WASIX
//! parent hands down (a pipe dash made, its standard streams) is the
//! table the Linux process reads and writes. Its exit status, or the
//! signal that ended it, reaches the parent through the child's exit
//! channel exactly as a wasm child's does.
//!
//! # Concurrency
//!
//! The process's space, context and descriptor table are owned by its
//! task, which drives one slice or one system call at a time. A signal is
//! raised on the shared [`WasixSignalState`] and a kill on the instance's
//! condemnation flag from any processor; the task reads both at every
//! stop, a slice ends within one timer period by the native contract, and
//! a system call that suspends is dropped when either arrives.

use super::*;
use crate::{SetWallClockCap, TerminalInputCap, TerminalOutputCap};
use core::num::NonZeroU32;
use core::ops::ControlFlow;
use helios_hal::native::{
    FaultKind, NativeError, NativeExecution, NativeUnavailable, Stop, UserContext, UserSpace,
};
use helios_hal::pmm::PhysFrame;
use helios_hal::vmm::{PageFlags, VirtAddr, VirtRange};
use helios_linux::abi::{self, Abi};
use helios_linux::elf::{self, Image};
use helios_linux::syscall::{
    self, Call, Denied, EpollData, MapError, MemoryFault, MemoryTotals, Process, Region, Resource,
    Resources, Start, Stdio, Stream, System, Thread, UserMemory, VirtualMemory, WriteError,
};

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

/// A thread's thread pointer, which lives in its user context.
struct ContextThread<'a, Context>(&'a mut Context);

impl<Context: UserContext> Thread for ContextThread<'_, Context> {
    fn thread_pointer(&self) -> u64 {
        self.0.thread_pointer().raw() as u64
    }
    fn set_thread_pointer(&mut self, address: u64) -> Result<(), Denied> {
        self.0
            .set_thread_pointer(VirtAddr::new(address as usize))
            .map_err(|_| Denied)
    }
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
    /// What WASIX's `clock_time_set` derives, for `clock_settime`.
    set_wall_clock: Option<SetWallClockCap>,
}

impl LinuxGrants {
    fn derive(authority: &ProcessAuthority) -> Self {
        Self {
            terminal_input: authority.derive_terminal_input_cap().ok(),
            terminal_output: authority.derive_terminal_output_cap().ok(),
            set_wall_clock: authority.derive_set_wall_clock_cap().ok(),
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
}

impl<Space: UserSpace> UserMemory for LinuxMemory<'_, Space> {
    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault> {
        self.space
            .read(VirtAddr::new(address as usize), output)
            .map_err(|_| MemoryFault)
    }
    fn check_writable(&self, address: u64, length: usize) -> Result<(), MemoryFault> {
        self.space
            .check_writable(VirtAddr::new(address as usize), length)
            .map_err(|_| MemoryFault)
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryFault> {
        self.space
            .write(VirtAddr::new(address as usize), bytes)
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

/// What a Linux process's system calls reach beyond its own state: the
/// standard streams, routed as the launching program's output mode routes
/// a wasm child's, and the kernel's clocks, entropy and machine totals,
/// read from the services a WASIX program's imports read.
struct LinuxPlatform<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    cpu: CpuImpl,
    timer: crate::Timer<CpuImpl>,
    runtime_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
    read_serial: crate::SerialReader,
    write_serial: crate::DebugSerialWriter,
    serial_input: Vec<u8>,
    output_mode: OutputMode,
    instance: crate::InstanceId,
    grants: LinuxGrants,
    /// The process's view of wall time, which `clock_settime` moves as
    /// WASIX's `clock_time_set` moves a program's.
    clock: crate::KernelClock<CpuImpl, HostRuntimeState<CpuImpl, Net, StorageImpl>>,
    entropy: crate::EntropyPool,
    instances: crate::InstanceRegistry,
    /// Timer ticks the thread's user context has run, summed over its
    /// slices.
    cpu_ticks: u64,
}

impl<CpuImpl, Net, StorageImpl> Stdio for LinuxPlatform<CpuImpl, Net, StorageImpl>
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
        let writer = match self.output_mode.sink(kind, self.instance) {
            // The terminal is the one destination the stream reaches on
            // the process's own authority; a channel or a log belongs to
            // whoever routed the stream there.
            crate::ComponentOutputSink::Local(crate::LocalOutputSink::Serial)
                if self.grants.terminal_output.is_none() =>
            {
                return Err(WriteError::Denied);
            }
            crate::ComponentOutputSink::Local(local) => loop {
                // Zero means another processor owns the debug UART now:
                // offer the same bytes again after a yield.
                let taken = local.write(&self.cpu, &self.runtime_state, self.write_serial, bytes);
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

    async fn read_input(&mut self, limit: usize) -> Result<Bytes, Denied> {
        Ok(match self.output_mode.stdin_route() {
            crate::ComponentInputRoute::Serial if self.grants.terminal_input.is_none() => {
                return Err(Denied);
            }
            crate::ComponentInputRoute::Serial => loop {
                let wait = self.write_serial.wait_for_debug_serial_input();
                (self.read_serial)(
                    &mut self.serial_input,
                    u32::try_from(limit).unwrap_or(u32::MAX),
                );
                if !self.serial_input.is_empty() {
                    break Bytes::copy_from_slice(&self.serial_input);
                }
                wait.await;
            },
            crate::ComponentInputRoute::Closed => Bytes::new(),
            crate::ComponentInputRoute::Child(stdin_rx) => {
                stdin_rx.read_limit(limit).await.unwrap_or_default()
            }
        })
    }
}

impl<CpuImpl, Net, StorageImpl> syscall::Clock for LinuxPlatform<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    /// The uptime clock, the one WASIX's `clock_time_get` reads.
    fn now_nanos(&self) -> u64 {
        self.clock.monotonic_nanos()
    }
    async fn sleep_until(&self, deadline: u64) {
        let remaining = deadline.saturating_sub(self.now_nanos());
        self.timer.sleep_for(Duration::from_nanos(remaining)).await;
    }
}

impl<CpuImpl, Net, StorageImpl> System for LinuxPlatform<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn realtime_nanos(&self) -> u64 {
        self.clock.system_time_nanos()
    }

    fn set_realtime_nanos(&mut self, nanos: u64) -> Result<(), Denied> {
        // The right WASIX's `clock_time_set` derives.
        let cap = self.grants.set_wall_clock.as_ref().ok_or(Denied)?;
        self.clock.set_system_time_nanos(cap, nanos);
        Ok(())
    }

    fn cpu_nanos(&self) -> u64 {
        self.cpu.timebase().ticks_to_nanos(self.cpu_ticks)
    }

    fn fill_random(&mut self, output: &mut [u8]) {
        self.entropy
            .fill_secure(self.runtime_state.root_entropy(), output);
    }

    fn memory(&self) -> MemoryTotals {
        let machine = crate::machine_memory();
        MemoryTotals {
            total_bytes: machine.usable_bytes as u64,
            free_bytes: machine.free_bytes as u64,
        }
    }

    fn process_count(&self) -> u32 {
        u32::try_from(self.instances.count()).unwrap_or(u32::MAX)
    }

    fn kernel_version(&self) -> &str {
        concat!("#1 Helios ", env!("CARGO_PKG_VERSION"))
    }
}

/// What ended a system call the process was suspended in.
enum CallEnd {
    Done(ControlFlow<u8, u64>),
    /// A signal or a kill arrived; the loop's next check acts on it.
    Stopped,
}

/// Runs a Linux process to its end: maps `executable`, builds its initial
/// stack from `argv` and `env`, and drives its one thread.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_linux_process<CpuImpl, Net, StorageImpl>(
    exec_context: ProgramExecContext<CpuImpl, Net, StorageImpl>,
    argv: ProgramArgv,
    env: Vec<(String, String)>,
    authority: ProcessAuthority,
    descriptors: Option<Preview1DescriptorTable<Net>>,
    signal_state: WasixSignalState,
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
    let space = native.create_space().map_err(native_error)?;
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
    // One unmapped guard page above the stack.
    let top = (user.end().raw() - PhysFrame::SIZE) as u64;
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
    // Where the stack may grow into: from its initial pages down as far as
    // the process's current `RLIMIT_STACK` allows. An argument vector
    // larger than the limit leaves it no room.
    let growth = |limit: u64| {
        let lowest = (top.saturating_sub(limit) as usize).max(image_end);
        VirtRange::new(
            VirtAddr::new(lowest),
            (stack.base as usize).saturating_sub(lowest),
        )
    };
    let mut context = native
        .create_context(
            VirtAddr::new(image.entry() as usize),
            VirtAddr::new(stack.pointer as usize),
        )
        .map_err(native_error)?;

    let pid = u32::try_from(instance_id.raw())
        .ok()
        .and_then(NonZeroU32::new)
        .expect("an instance id is a nonzero process id below 2^32");
    let table = match descriptors {
        Some(table) => table.into_slots(),
        None => syscall::standard_streams::<LinuxResources<Net>>(),
    };
    // The launch hands a process no user or group IDs, so it reports zero
    // ones; the machine's memory sizes the limits Linux derives from it.
    let mut process = Process::<LinuxResources<Net>>::with_descriptors(
        executable.abi,
        pid,
        image.program_break(PhysFrame::SIZE as u64),
        table,
        Start {
            memory_bytes: crate::machine_memory().usable_bytes as u64,
            ..Start::default()
        },
    );
    let mut stdio = LinuxPlatform {
        cpu: cpu.clone(),
        timer: exec_context.timer.clone(),
        runtime_state: exec_context.runtime_state.clone(),
        read_serial: exec_context.read_serial,
        write_serial: exec_context.write_serial,
        serial_input: Vec::new(),
        output_mode,
        instance: instance_id,
        grants: LinuxGrants::derive(&authority),
        clock: crate::KernelClock::new(cpu.clone(), exec_context.runtime_state.clone()),
        entropy: crate::EntropyPool::derive(
            exec_context.runtime_state.root_entropy(),
            instance_id.raw(),
        ),
        instances: exec_context.instance_registry.clone(),
        cpu_ticks: 0,
    };
    let registers = executable.abi.system_call_registers();
    let exit = |termination: helios_unix::ChildTermination| ChildExit {
        instance_id,
        termination,
        filesystem: None,
    };
    timeline.record(&cpu, LaunchPhase::GuestBegin);
    let end = loop {
        if let Some(reason) = launched_instance.pending_kill() {
            break match reason {
                crate::KillReason::Operator | crate::KillReason::RequesterGone => {
                    Ok(exit(helios_unix::ChildTermination::Killed))
                }
                _ => Err(map_program_runtime_error(wasmtime::Error::from(
                    crate::InstanceKilled { reason },
                ))),
            };
        }
        if let Some(signal) = signal_state.take_pending() {
            break Ok(exit(helios_unix::ChildTermination::Signaled(
                helios_unix::SignalTermination {
                    signal: u8::try_from(signal).unwrap_or(u8::MAX),
                    core_dumped: false,
                },
            )));
        }
        let slice_began = cpu.now().ticks();
        let stop = context.resume(&space);
        stdio.cpu_ticks += cpu.now().ticks().saturating_sub(slice_began);
        match stop {
            Stop::SystemCall => {
                let read = |register| {
                    context
                        .register(register)
                        .expect("the ABI names registers of this instruction set")
                };
                let call = Call {
                    number: read(registers.number),
                    arguments: registers.arguments.map(read),
                };
                // Armed before the check at the top of the next turn
                // reads them, so a raise or kill during the call is seen.
                let mut signal_wait = signal_state.wait_state();
                let mut kill_wait = launched_instance.arm_kill_wait();
                // The call borrows the context for its thread pointer; the
                // block ends that borrow before its result is written back.
                let ended = {
                    let mut memory = LinuxMemory {
                        space: &space,
                        user,
                    };
                    let mut thread = ContextThread(&mut context);
                    let mut call = core::pin::pin!(syscall::dispatch(
                        &mut process,
                        call,
                        &mut memory,
                        &mut thread,
                        &mut stdio
                    ));
                    core::future::poll_fn(|cx| {
                        if let Poll::Ready(flow) = call.as_mut().poll(cx) {
                            return Poll::Ready(CallEnd::Done(flow));
                        }
                        let signalled = signal_state.poll_changed(cx, &mut signal_wait).is_ready();
                        let killed = launched_instance
                            .poll_kill_wait(cx, &mut kill_wait)
                            .is_ready();
                        if signalled || killed {
                            Poll::Ready(CallEnd::Stopped)
                        } else {
                            Poll::Pending
                        }
                    })
                    .await
                };
                match ended {
                    CallEnd::Done(ControlFlow::Continue(result)) => context
                        .set_register(registers.result, result)
                        .expect("the ABI names registers of this instruction set"),
                    CallEnd::Done(ControlFlow::Break(status)) => {
                        break Ok(exit(helios_unix::ChildTermination::Exited(u32::from(
                            status,
                        ))));
                    }
                    CallEnd::Stopped => {}
                }
            }
            Stop::Preempted | Stop::Interrupted => crate::yield_now().await,
            Stop::Fault(fault) => match fault.kind {
                // A discarded page's first touch, or a translation older
                // than the page's current access: the space answers both,
                // and the context retries the access.
                FaultKind::Page {
                    address, access, ..
                } if user.contains(address)
                    && space
                        .mapping(VirtRange::new(address.page_floor(), PhysFrame::SIZE))
                        .is_some_and(|page| page.flags.contains(access)) =>
                {
                    match space.resolve_fault(address, access) {
                        Ok(()) => {}
                        Err(NativeError::OutOfMemory) => {
                            break Err(native_error(NativeError::OutOfMemory));
                        }
                        Err(error) => panic!("resolving a fault on a mapped page: {error}"),
                    }
                }
                FaultKind::Page {
                    address,
                    present: false,
                    ..
                } if growth(process.limit(Resource::Stack).current).contains(address) => {
                    let page = VirtRange::new(address.page_floor(), PhysFrame::SIZE);
                    match space.map(page, &[], PageFlags::READ | PageFlags::WRITE) {
                        Ok(()) => {}
                        Err(NativeError::OutOfMemory) => {
                            break Err(native_error(NativeError::OutOfMemory));
                        }
                        Err(error) => panic!("growing a Linux stack into {page:?}: {error}"),
                    }
                }
                kind => {
                    tracing::debug!(
                        target: "helios_kernel::linux",
                        instance = ?instance_id,
                        ?fault,
                        "Linux process faulted"
                    );
                    break Ok(exit(helios_unix::ChildTermination::Signaled(
                        helios_unix::SignalTermination {
                            signal: abi::fault_signal(kind),
                            core_dumped: false,
                        },
                    )));
                }
            },
        }
    };
    timeline.record(&cpu, LaunchPhase::GuestEnd);
    // The descriptor table goes before the parent hears of the exit, so a
    // reader of a pipe this process held sees its end first.
    drop(process);
    end
}
