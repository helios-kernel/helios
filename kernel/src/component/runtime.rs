extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use bytes::Bytes;
use spin::Mutex;

use crate::io::{ByteReader, ByteWriter, TryRead};
use crate::{
    EntropyPool, InstanceActivity, InstanceId, InstanceRegistry, KernelClock, KillReason,
    ProcessAuthority, RegisteredInstance, SetWallClockCap, Sleep, Timer,
};
use helios_hal::cpu::{Cpu, Instant};

use crate::memory::user_mapping_kernel_heap_bytes;
use thiserror::Error;

/// The stack a component instance runs on: both the guest wasm call
/// stack and the host Rust async frames driving it.
///
/// CPython's class construction recurses deeply and does not fit
/// Wasmtime's 512 KiB default. This is kernel policy rather than a
/// runtime knob — the kernel is what pays for the stack, in user pages
/// for the stack itself and in kernel heap for the page tables that
/// address it — so the runtime adapter's engine configuration reads it
/// from here.
pub const COMPONENT_ASYNC_STACK_SIZE: usize = 8 * 1024 * 1024;

/// The bytes the kernel keeps committed below every guest stack pointer
/// the runtime has checked (`R`).
///
/// Host code runs below the guest frame that called it and meets no check
/// of its own: a call into a host function, a libcall such as
/// `memory.grow`, a trap handler. At each guest stack-limit check that
/// falls below the stack's reserve limit, and at each entry into wasm, the
/// runtime asks the kernel to commit this many bytes below the stack
/// pointer it checked. A guest frame of at most
/// `helios_artifact::CWASM_STACK_LIMIT_LARGE_FRAME` (`S`) may sit between
/// that pointer and the host code, so host code may use `R - S` less the
/// entry path's own frames. 64 KiB covers the 28,672 bytes measured for the
/// deepest host path of the smoke and bench boots (helios#535) with a page
/// of measurement resolution, the commit path itself, and the paths that
/// run below a guest stack pointer and were not measured (x86 trap
/// capture, the swap trampoline).
pub const FIBER_STACK_HOST_RESERVE: usize = 64 * 1024;

/// The bytes a fresh fiber stack commits when the kernel hands it out (`H`).
///
/// Host code runs from the top of the stack down to the first guest entry
/// (fiber start, instantiation, the pooling allocator) before any guest
/// check commits the reserve, and that span measured at most 8,192 bytes
/// (helios#535). 16 KiB is that plus a page of measurement resolution,
/// rounded up to a multiple of [`FIBER_STACK_COMMIT_STEP`].
pub const FIBER_STACK_ENTRY_RESERVE: usize = 16 * 1024;

/// The bytes committed beyond [`FIBER_STACK_HOST_RESERVE`] each time the
/// runtime asks the kernel to commit below a stack pointer (`G`).
///
/// It trades trips through the runtime's slow path against committed
/// memory: a descent commits `G` ahead of its reserve, so it takes one trip
/// per `G` of depth. 16 KiB is one trip per four pages, the same size as
/// [`FIBER_STACK_ENTRY_RESERVE`] (helios#535).
pub const FIBER_STACK_COMMIT_STEP: usize = 16 * 1024;

/// How many component instances the kernel serves at once.
///
/// This is kernel policy and belongs here for the same reason
/// [`COMPONENT_ASYNC_STACK_SIZE`] does: the kernel is what pays for a
/// live instance, and the runtime adapter reads the number rather than
/// choosing it. Until #284 the number was Wasmtime's own default — one
/// value, 1000, that its `InstanceLimits` assigns to every total it has,
/// including the *core* instance count, which is not the same thing as a
/// program: `instance-startup-500` never once completed on any bench run
/// because 500 programs draw more than 1000 core instances between them.
///
/// The cap the runtime is told is not the real limit. What actually
/// bounds concurrency is user memory, and the instance that cannot get
/// its pages dies as any other user OOM does (AGENTS §3.1); this number
/// exists so that the refusal comes from the memory the kernel accounts
/// for rather than from a pool sized by a default nobody chose.
pub const MAX_CONCURRENT_INSTANCES: u32 = 1024;

/// The most core instances one component may instantiate.
///
/// Measured across every component this tree builds: `hello` and the
/// curl program instantiate three core modules each — the component
/// tooling's shim, the main module and the preview1 adapter — and
/// `python3` four. Eight leaves room for a component that carries more
/// without letting one draw the pool down.
pub const MAX_CORE_INSTANCES_PER_COMPONENT: u32 = 8;

/// The most linear memories one component may hold.
///
/// Every component in the tree defines exactly one, including the
/// threaded ones: a guest's threads share its single memory rather than
/// adding a second. Two is the multi-memory headroom, and it is what
/// each unit of [`MAX_CONCURRENT_INSTANCES`] reserves address space for,
/// so it is deliberately tight.
pub const MAX_MEMORIES_PER_COMPONENT: u32 = 2;

/// The tables the pool sets aside for each of [`MAX_CONCURRENT_INSTANCES`].
///
/// Measured at exactly two for every single component this tree builds:
/// the main module's function table and the shim's. There is no headroom
/// here on purpose — the table pool is the one pool the runtime commits
/// up front rather than reserving, so this number is paid in user pages
/// per live slot whether or not any component uses it. See
/// [`MAX_POOLED_USER_MEMORY`].
pub const TABLES_PER_INSTANCE: u32 = 2;

/// The most tables one component may hold.
///
/// A component the build composed from others holds the sum of theirs: a
/// program with the WebGPU provider plugged in carries its own two and
/// the provider's two. The pool is sized by [`TABLES_PER_INSTANCE`], not
/// by this, so a composed program draws more of the shared pool rather
/// than growing what every slot commits.
pub const MAX_TABLES_PER_COMPONENT: u32 = 4;

/// The virtual address space the kernel will let the runtime's instance
/// pools reserve.
///
/// A pooled linear-memory slot reserves
/// `CWASM_MEMORY_RESERVATION + CWASM_MEMORY_GUARD_SIZE` of address space
/// whether or not anything ever runs in it, so the instance budget is
/// spent in address space long before it is spent in pages. Every
/// bare-metal backend hands the runtime a 32 TiB window
/// (`USER_VA_BASE..USER_VA_END` in `x86/src/vmm.rs`,
/// `aarch64/src/vmm.rs` and `riscv/src/vmm.rs`), and the kernel keeps
/// its pools inside half of it so that everything else mapped out of the
/// same window — compiled code, the fiber stacks, a guest's own growth —
/// still has somewhere to go. The pools the budget below implies reserve
/// about 8.1 TiB of that.
///
/// This is the number to check before widening
/// [`MAX_CONCURRENT_INSTANCES`] or [`MAX_MEMORIES_PER_COMPONENT`]; the
/// runtime adapter asserts the derived pools fit.
pub const MAX_POOLED_ADDRESS_SPACE: u64 = 16 << 40;

/// The user memory the kernel's component engine may commit up front
/// for its instance pools.
///
/// Reserved address space is not the only thing a pool costs, and the
/// exception is what made the first draft of the instance budget a
/// regression rather than a fix. The linear-memory, stack and GC-heap
/// pools all take their space as they use it — the memory pool maps its
/// whole slab inaccessible, the bare-metal stack pool is a counter — but
/// the **table pool commits its entire mapping when the engine is
/// built**, one page-rounded `table_elements`-sized slot per
/// `total_tables`. On the bench lane that is user memory gone before a
/// program runs: run 34224973216 refused `cpython-json` its 40 MiB with
/// `available=34942976 of 1510993920`, because a fourfold table budget
/// had committed 1.3 GiB of the 1.44 GiB the guest had.
///
/// The kernel builds **one** component engine — owned by the program
/// service and shared by the root supervisor and every launched program
/// — rather than two, so this constant is the whole guest's upfront
/// table-pool budget and keeps total boot-committed user memory
/// unchanged at 256 MiB (`2048` table slots × `128 KiB`).
pub const MAX_POOLED_USER_MEMORY: u64 = 256 << 20;

/// The kernel heap one wasm store costs the kernel.
///
/// Two terms, and both are per *store* rather than per instance, which
/// is what makes an instance's kernel-heap footprint track the stores
/// it holds — a guest thread gets its own store over the same instance
/// — instead of only the linear memory it grew:
///
/// - `store_bytes`, the store value itself. Every service the guest can
///   reach hangs off it: the resource and descriptor tables, preopened
///   directories, signal state, stdio plumbing, the entropy pool. The
///   kernel owns the whole thing on its own heap.
/// - The page tables and reservation records for the fiber stack the
///   store runs on. The stack's pages come from the user pool and
///   arrive one page-fault at a time, but the kernel heap pays to
///   address the whole span the moment the stack is created: the
///   arena's `prepare_demand_commit` builds every page-table level over
///   [`COMPONENT_ASYNC_STACK_SIZE`] up front, because a fault-time
///   commit cannot build one. So this term is the store's true
///   kernel-heap cost rather than a stand-in for resident user pages,
///   which are now only the pages the store actually touched.
pub fn store_kernel_heap_bytes(store_bytes: usize) -> u64 {
    let bytes =
        store_bytes.saturating_add(user_mapping_kernel_heap_bytes(COMPONENT_ASYNC_STACK_SIZE));
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

/// Error a guest call ends with when a kill was requested for its
/// instance — by the OOM killer, a kernel-plugin supervisor or an
/// operator. The runtime adapter raises it as a trap from the store's
/// interrupt callback, [`super::OnProcessor`] reports it for a call that completes
/// while condemned, and the component executor surfaces it as a typed
/// `ProgramExecError`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("instance terminated: {reason:?}")]
pub struct InstanceKilled {
    pub reason: KillReason,
}

/// Where stdin/stdout/stderr traffic flows for a component.
///
/// Three concrete routings are supported:
///
/// - `Serial`: debugger component path — stdout/stderr are written to the
///   serial debug port; stdin reads drain it.
/// - `Trace`: diagnostic path — stdout/stderr bytes are recorded as
///   observer console text; stdin is always empty.
/// - `Child { … }`: spawned-child path — stdin, stdout, and stderr are
///   connected to byte channels the parent controls.
#[derive(Clone)]
pub enum ComponentOutputRoute {
    Serial,
    Trace,
    Child(ByteWriter),
    Discard,
}

/// Maximum bytes buffered for a single unterminated serial line before
/// forcing a chunk flush to the trace log.
const SERIAL_TRACE_LINE_MAX_BYTES: usize = 4096;

/// Capacity retained on a serial trace line buffer after flushing, matching
/// [`crate::RecordingConsole`] so one long line never pins an oversized buffer.
const SERIAL_TRACE_BUFFER_RETAINED_CAPACITY: usize = 4096;

/// Bounded per-stream UTF-8 line accumulator for mirroring serial stdout/stderr
/// writes into [`crate::TraceLog`] without altering raw serial wire framing.
#[derive(Debug, Default)]
pub(crate) struct SerialLineBuffer {
    pending: Vec<u8>,
}

impl SerialLineBuffer {
    pub(crate) const fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }

    /// Feeds `bytes` into the line buffer, invoking `emit` for every completed
    /// line (with any trailing `\r` stripped) and for any chunk forced out when
    /// an unterminated line reaches [`SERIAL_TRACE_LINE_MAX_BYTES`].
    pub(crate) fn push_bytes(&mut self, mut bytes: &[u8], mut emit: impl FnMut(&str)) {
        while !bytes.is_empty() {
            if let Some(newline_pos) = bytes.iter().position(|&byte| byte == b'\n') {
                let segment = &bytes[..newline_pos];
                self.push_unterminated(segment, &mut emit);
                self.emit_pending(&mut emit);
                bytes = &bytes[newline_pos + 1..];
            } else {
                self.push_unterminated(bytes, &mut emit);
                break;
            }
        }
    }

    /// Flushes any remaining unterminated partial line on stream/store finish.
    pub(crate) fn flush(&mut self, mut emit: impl FnMut(&str)) {
        self.emit_pending(&mut emit);
    }

    fn push_unterminated(&mut self, mut bytes: &[u8], emit: &mut impl FnMut(&str)) {
        while !bytes.is_empty() {
            let available = SERIAL_TRACE_LINE_MAX_BYTES.saturating_sub(self.pending.len());
            if available == 0 {
                self.flush_overlong_chunk(emit);
                continue;
            }
            let take = bytes.len().min(available);
            self.pending.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.pending.len() >= SERIAL_TRACE_LINE_MAX_BYTES {
                self.flush_overlong_chunk(emit);
            }
        }
    }

    fn flush_overlong_chunk(&mut self, emit: &mut impl FnMut(&str)) {
        if self.pending.is_empty() {
            return;
        }
        // Preserve an incomplete multi-byte UTF-8 sequence at the cut boundary
        // when valid text precedes it so split CJK/UTF-8 characters reassemble.
        let split_at = match core::str::from_utf8(&self.pending) {
            Ok(_) => self.pending.len(),
            Err(error) if error.error_len().is_none() && error.valid_up_to() > 0 => {
                error.valid_up_to()
            }
            Err(_) => self.pending.len(),
        };
        let chunk = strip_trailing_cr(&self.pending[..split_at]);
        emit_utf8_or_lossy(chunk, emit);
        self.pending.drain(..split_at);
        self.shrink_if_oversized();
    }

    fn emit_pending(&mut self, emit: &mut impl FnMut(&str)) {
        if self.pending.is_empty() {
            return;
        }
        let line = strip_trailing_cr(&self.pending);
        emit_utf8_or_lossy(line, emit);
        self.pending.clear();
        self.shrink_if_oversized();
    }

    fn shrink_if_oversized(&mut self) {
        if self.pending.capacity() > SERIAL_TRACE_BUFFER_RETAINED_CAPACITY {
            self.pending
                .shrink_to(SERIAL_TRACE_BUFFER_RETAINED_CAPACITY);
        }
    }
}

fn strip_trailing_cr(mut bytes: &[u8]) -> &[u8] {
    while let Some(rest) = bytes.strip_suffix(b"\r") {
        bytes = rest;
    }
    bytes
}

fn emit_utf8_or_lossy(bytes: &[u8], emit: &mut impl FnMut(&str)) {
    if bytes.is_empty() {
        return;
    }
    match core::str::from_utf8(bytes) {
        Ok(line) => emit(line),
        Err(_) => {
            let lossy = String::from_utf8_lossy(bytes);
            if !lossy.is_empty() {
                emit(&lossy);
            }
        }
    }
}

/// Shareable per-stream line buffer handle owned by [`ComponentStoreData`] and
/// passed into [`LocalOutputSink::write_mirrored`] so component output stream
/// consumers can buffer lines across polls without holding any lock across
/// `.await` or while invoking `record_console_text`.
#[derive(Clone, Debug)]
pub(crate) struct SerialLineMirror {
    buffer: Arc<Mutex<SerialLineBuffer>>,
}

impl SerialLineMirror {
    pub(crate) fn new() -> Self {
        Self {
            buffer: Arc::new(Mutex::new(SerialLineBuffer::new())),
        }
    }

    /// Buffers `bytes` and emits every completed line after releasing the
    /// buffer lock so `emit` (which acquires `TraceLog`'s `IrqSafeMutex`) never
    /// nests inside this spinlock.
    pub(crate) fn push_bytes(&self, bytes: &[u8], mut emit: impl FnMut(&str)) {
        let mut completed = Vec::new();
        {
            let mut guard = self.buffer.lock();
            guard.push_bytes(bytes, |line| completed.push(String::from(line)));
        }
        for line in &completed {
            emit(line);
        }
    }

    /// Flushes any trailing partial line after releasing the buffer lock.
    pub(crate) fn flush(&self, mut emit: impl FnMut(&str)) {
        let mut flushed = None;
        {
            let mut guard = self.buffer.lock();
            guard.flush(|line| flushed = Some(String::from(line)));
        }
        if let Some(line) = flushed {
            emit(&line);
        }
    }
}

/// Per-store serial-to-trace line mirrors that flush any partial trailing
/// stdout/stderr line when the store drops.
struct SerialStreamTrace<CpuImpl, RuntimeStateImpl>
where
    CpuImpl: Cpu + Clone,
    RuntimeStateImpl: ComponentRuntimeState,
{
    cpu: CpuImpl,
    runtime_state: RuntimeStateImpl,
    instance: InstanceId,
    stdout: Option<SerialLineMirror>,
    stderr: Option<SerialLineMirror>,
}

impl<CpuImpl, RuntimeStateImpl> SerialStreamTrace<CpuImpl, RuntimeStateImpl>
where
    CpuImpl: Cpu + Clone,
    RuntimeStateImpl: ComponentRuntimeState,
{
    fn new(
        cpu: CpuImpl,
        runtime_state: RuntimeStateImpl,
        instance: InstanceId,
        output_mode: &ComponentOutputMode,
    ) -> Self {
        let stdout = matches!(
            output_mode.sink(ComponentOutputStreamKind::Stdout, instance),
            ComponentOutputSink::Local(LocalOutputSink::Serial(_))
        )
        .then(SerialLineMirror::new);
        let stderr = matches!(
            output_mode.sink(ComponentOutputStreamKind::Stderr, instance),
            ComponentOutputSink::Local(LocalOutputSink::Serial(_))
        )
        .then(SerialLineMirror::new);
        Self {
            cpu,
            runtime_state,
            instance,
            stdout,
            stderr,
        }
    }

    fn mirror(&self, stream: ComponentOutputStreamKind) -> Option<SerialLineMirror> {
        match stream {
            ComponentOutputStreamKind::Stdout => self.stdout.clone(),
            ComponentOutputStreamKind::Stderr => self.stderr.clone(),
        }
    }
}

impl<CpuImpl, RuntimeStateImpl> Drop for SerialStreamTrace<CpuImpl, RuntimeStateImpl>
where
    CpuImpl: Cpu + Clone,
    RuntimeStateImpl: ComponentRuntimeState,
{
    fn drop(&mut self) {
        if self.stdout.is_none() && self.stderr.is_none() {
            return;
        }
        let ticks = self.cpu.now().ticks();
        let runtime_state = &self.runtime_state;
        let instance = self.instance;
        if let Some(stdout) = &self.stdout {
            stdout.flush(|line| {
                runtime_state.record_console_text(ticks, Some(instance), line);
            });
        }
        if let Some(stderr) = &self.stderr {
            stderr.flush(|line| {
                runtime_state.record_console_text(ticks, Some(instance), line);
            });
        }
    }
}

impl ComponentOutputRoute {
    /// Borrow this route as a sink so every writer path matches on one
    /// exhaustive set of destinations. `instance` is the writer; both
    /// [`LocalOutputSink::Serial`] and [`LocalOutputSink::Trace`] attribute
    /// what they record in the trace log to it.
    pub fn sink(&self, instance: InstanceId) -> ComponentOutputSink<'_> {
        match self {
            Self::Serial => ComponentOutputSink::Local(LocalOutputSink::Serial(instance)),
            Self::Trace => ComponentOutputSink::Local(LocalOutputSink::Trace(instance)),
            Self::Child(writer) => ComponentOutputSink::Child(writer),
            Self::Discard => ComponentOutputSink::Local(LocalOutputSink::Discard),
        }
    }
}

/// Borrowed resolution of where one stdio stream's bytes go.
///
/// The split is exactly the flow-control boundary: a [`LocalOutputSink`]
/// never parks the caller, while `Child` is a bounded byte channel that
/// applies backpressure — callers must either await
/// [`ByteWriter::write`] or drive [`ByteWriter::poll_write`] from a poll
/// context.
///
/// Neither half takes bytes unconditionally. A local serial sink is the
/// machine's one debug UART, whose owner may be another processor
/// mid-segment (#103), so it reports how much of the chunk it took and
/// the caller yields for the rest.
pub enum ComponentOutputSink<'a> {
    Local(LocalOutputSink),
    Child(&'a ByteWriter),
}

/// Output destinations the kernel serves itself, without a channel
/// between the guest and the bytes' destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalOutputSink {
    /// Debug UART byte stream, mirrored line-by-line into the observer trace
    /// log attributed to the instance that wrote it.
    Serial(InstanceId),
    /// Observer console text, attributed to the instance that wrote it.
    Trace(InstanceId),
    Discard,
}

impl LocalOutputSink {
    /// Takes what it can of `bytes` and reports how many it took.
    ///
    /// Zero means the debug UART is owned by another processor right
    /// now: the caller yields and offers the same bytes again. A short
    /// count means the console cut the stream at a line boundary, which
    /// is the granularity at which a kernel console record may reach
    /// the wire between the guest's own lines.
    #[must_use]
    pub(crate) fn write<CpuImpl, RuntimeStateImpl>(
        self,
        cpu: &CpuImpl,
        runtime_state: &RuntimeStateImpl,
        serial_writer: crate::DebugSerialWriter,
        bytes: &[u8],
    ) -> usize
    where
        CpuImpl: Cpu + Clone,
        RuntimeStateImpl: ComponentRuntimeState,
    {
        self.write_mirrored(cpu, runtime_state, serial_writer, None, bytes)
    }

    /// Like [`Self::write`], using a persistent per-stream [`SerialLineMirror`]
    /// when provided so split writes across chunks reassemble into whole lines
    /// in the observer trace log while keeping `serial_writer.write_stream`
    /// byte-for-byte unchanged.
    #[must_use]
    pub(crate) fn write_mirrored<CpuImpl, RuntimeStateImpl>(
        self,
        cpu: &CpuImpl,
        runtime_state: &RuntimeStateImpl,
        serial_writer: crate::DebugSerialWriter,
        line_mirror: Option<&SerialLineMirror>,
        bytes: &[u8],
    ) -> usize
    where
        CpuImpl: Cpu + Clone,
        RuntimeStateImpl: ComponentRuntimeState,
    {
        match self {
            Self::Serial(instance) => {
                let written = serial_writer.write_stream(bytes);
                if written != 0 {
                    let accepted = &bytes[..written];
                    let ticks = cpu.now().ticks();
                    if let Some(mirror) = line_mirror {
                        mirror.push_bytes(accepted, |line| {
                            runtime_state.record_console_text(ticks, Some(instance), line);
                        });
                    } else {
                        let mut scratch = SerialLineBuffer::new();
                        scratch.push_bytes(accepted, |line| {
                            runtime_state.record_console_text(ticks, Some(instance), line);
                        });
                        scratch.flush(|line| {
                            runtime_state.record_console_text(ticks, Some(instance), line);
                        });
                    }
                }
                written
            }
            Self::Trace(instance) => {
                let text = core::str::from_utf8(bytes).unwrap_or_else(|error| {
                    panic!("guest attempted to write non-utf8 stdout/stderr bytes: {error}")
                });
                runtime_state.record_console_text(cpu.now().ticks(), Some(instance), text);
                bytes.len()
            }
            Self::Discard => bytes.len(),
        }
    }
}

/// Where a component's standard input bytes arrive from.
#[derive(Clone)]
pub enum ComponentInputRoute {
    Serial,
    Closed,
    Child(ByteReader),
}

#[derive(Clone)]
pub enum ComponentOutputMode {
    Serial,
    Trace,
    Child {
        stdin_rx: ByteReader,
        stdout_tx: ByteWriter,
        stderr_tx: ByteWriter,
    },
    RoutedChild {
        stdin: ComponentInputRoute,
        stdout: ComponentOutputRoute,
        stderr: ComponentOutputRoute,
    },
}

impl ComponentOutputMode {
    /// Where standard input arrives from, as a route a child launched from
    /// this mode can inherit.
    pub fn stdin_route(&self) -> ComponentInputRoute {
        match self {
            ComponentOutputMode::Serial => ComponentInputRoute::Serial,
            ComponentOutputMode::Trace => ComponentInputRoute::Closed,
            ComponentOutputMode::Child { stdin_rx, .. } => {
                ComponentInputRoute::Child(stdin_rx.clone())
            }
            ComponentOutputMode::RoutedChild { stdin, .. } => stdin.clone(),
        }
    }

    /// Obtain a cloneable writer for the requested child stream, when
    /// this mode has one. Returns `None` for `Serial`/`Trace`; callers
    /// that need every route should use [`Self::sink`] instead.
    pub fn child_writer(&self, kind: ComponentOutputStreamKind) -> Option<ByteWriter> {
        match (self, kind) {
            (ComponentOutputMode::Child { stdout_tx, .. }, ComponentOutputStreamKind::Stdout) => {
                Some(stdout_tx.clone())
            }
            (ComponentOutputMode::Child { stderr_tx, .. }, ComponentOutputStreamKind::Stderr) => {
                Some(stderr_tx.clone())
            }
            (
                ComponentOutputMode::RoutedChild {
                    stdout: ComponentOutputRoute::Child(writer),
                    ..
                },
                ComponentOutputStreamKind::Stdout,
            )
            | (
                ComponentOutputMode::RoutedChild {
                    stderr: ComponentOutputRoute::Child(writer),
                    ..
                },
                ComponentOutputStreamKind::Stderr,
            ) => Some(writer.clone()),
            _ => None,
        }
    }

    /// Where `kind` goes, as a route a child launched from this mode can
    /// inherit: the same destination, with a cloned writer handle when
    /// it is a channel.
    pub fn route(&self, kind: ComponentOutputStreamKind) -> ComponentOutputRoute {
        match (self, kind) {
            (ComponentOutputMode::Serial, _) => ComponentOutputRoute::Serial,
            (ComponentOutputMode::Trace, _) => ComponentOutputRoute::Trace,
            (ComponentOutputMode::Child { stdout_tx, .. }, ComponentOutputStreamKind::Stdout) => {
                ComponentOutputRoute::Child(stdout_tx.clone())
            }
            (ComponentOutputMode::Child { stderr_tx, .. }, ComponentOutputStreamKind::Stderr) => {
                ComponentOutputRoute::Child(stderr_tx.clone())
            }
            (
                ComponentOutputMode::RoutedChild { stdout, .. },
                ComponentOutputStreamKind::Stdout,
            ) => stdout.clone(),
            (
                ComponentOutputMode::RoutedChild { stderr, .. },
                ComponentOutputStreamKind::Stderr,
            ) => stderr.clone(),
        }
    }

    /// Resolve where `kind` goes without cloning a writer handle.
    /// `instance` is the writer; both [`LocalOutputSink::Serial`] and
    /// [`LocalOutputSink::Trace`] attribute what they record to it.
    pub fn sink(
        &self,
        kind: ComponentOutputStreamKind,
        instance: InstanceId,
    ) -> ComponentOutputSink<'_> {
        match (self, kind) {
            (ComponentOutputMode::Serial, _) => {
                ComponentOutputSink::Local(LocalOutputSink::Serial(instance))
            }
            (ComponentOutputMode::Trace, _) => {
                ComponentOutputSink::Local(LocalOutputSink::Trace(instance))
            }
            (ComponentOutputMode::Child { stdout_tx, .. }, ComponentOutputStreamKind::Stdout) => {
                ComponentOutputSink::Child(stdout_tx)
            }
            (ComponentOutputMode::Child { stderr_tx, .. }, ComponentOutputStreamKind::Stderr) => {
                ComponentOutputSink::Child(stderr_tx)
            }
            (
                ComponentOutputMode::RoutedChild { stdout, .. },
                ComponentOutputStreamKind::Stdout,
            ) => stdout.sink(instance),
            (
                ComponentOutputMode::RoutedChild { stderr, .. },
                ComponentOutputStreamKind::Stderr,
            ) => stderr.sink(instance),
        }
    }

    /// Obtain a reference to the child-stdin reader, when this mode has one.
    pub fn child_stdin(&self) -> Option<&ByteReader> {
        match self {
            ComponentOutputMode::Child { stdin_rx, .. }
            | ComponentOutputMode::RoutedChild {
                stdin: ComponentInputRoute::Child(stdin_rx),
                ..
            } => Some(stdin_rx),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
pub enum ComponentOutputStreamKind {
    Stdout,
    Stderr,
}

pub trait ComponentRuntimeState: Clone + Send + 'static {
    fn uptime_nanos(&self, current_ticks: u64) -> u64;

    /// Nanoseconds between the monotonic clock and wall time, as the
    /// platform's real-time clock set them at boot.
    ///
    /// Zero on a machine whose kernel found no real-time clock, where
    /// wall time cannot be told apart from uptime.
    fn wall_clock_offset_nanos(&self) -> i128;

    /// Records `text` as console events attributed to `origin`: the
    /// instance that wrote it, or `None` for the kernel's own console.
    fn record_console_text(&self, current_ticks: u64, origin: Option<InstanceId>, text: &str);

    /// The kernel's root DRBG, from which this instance's pool is
    /// derived.
    fn root_entropy(&self) -> &crate::RootEntropy;

    /// The memory balloon the host resizes this guest through, if the
    /// platform has one. The out-of-memory path asks it to give its
    /// memory back before it condemns an instance.
    fn memory_balloon(&self) -> Option<crate::memory::BalloonHandle>;

    /// The devices discovery is willing to hand to a user-mode driver.
    ///
    /// Empty on a machine whose backend found nothing outside the
    /// hardware it drives itself, which is every machine until a
    /// backend publishes a grant.
    fn device_grants(&self) -> &crate::device::DeviceGrantRegistry;

    /// The machine's display, once a backend has brought one up.
    ///
    /// Empty on a machine with no display device, where a claim is
    /// refused with `unavailable` rather than trapping.
    fn display_service(&self) -> Option<crate::display::DisplayService>;

    /// The machine's input devices, or `None` on a machine the backend
    /// brought none up on.
    fn input_service(&self) -> Option<crate::input::InputService>;

    /// The display engine's rendering half, once a backend brought the
    /// device up.
    ///
    /// Empty on a machine with no display device at all, where a claim
    /// is refused `unavailable` rather than trapping; a device that
    /// renders nothing answers `no-renderer`.
    fn gpu3d_service(&self) -> Option<crate::gpu::Gpu3dService>;

    /// The machine's client windows, which every instance may ask for
    /// one of.
    fn surface_service(&self) -> crate::surface::SurfaceService;
    /// The machine's sound device, once a backend has brought one up.
    ///
    /// Empty on a machine with no sound device, where a claim is
    /// refused with `unavailable` rather than trapping.
    fn audio_service(&self) -> Option<crate::audio::AudioService>;

    fn profiling_enabled(&self) -> bool;

    fn record_profile_stack_nanos(
        &self,
        scope: crate::ProfileScope,
        stack: String,
        weight_nanos: u64,
    );

    /// Records `weight_nanos` of time `instance`, running the program
    /// named `program`, spent in user code.
    fn record_user_profile(&self, instance: InstanceId, program: &str, weight_nanos: u64);

    fn record_perf_metric_parts(
        &self,
        scope: crate::ProfileScope,
        prefix: &str,
        suffix: &str,
        sample: crate::PerfSample,
    );

    /// Retires the network handles that a dying socket resource could
    /// not retire itself, and wakes the packet pump if any did.
    ///
    /// The runtime state is the one value that holds the machine's
    /// network service, so it is where a queue of bare handle ids turns
    /// back into closes. See [`super::SocketRetirementQueue`] for why
    /// a socket resource cannot do it itself.
    fn retire_network_handles(&self, retired: &super::SocketRetirementQueue);

    /// Reopens the host-share snapshot gate when a dying store still held an
    /// active `snapshot-hold` resource identified by `token`.
    fn release_snapshot_hold(&self, token: u64);
}

/// Associates a store's filesystem type with its per-instance default Linux
/// image representation without adding type parameters to [`ComponentStoreData`].
pub trait StoreFilesystem {
    type DefaultImage: Clone + Send + Sync + 'static;
}

impl<S: crate::Storage> StoreFilesystem for crate::Namespace<S> {
    type DefaultImage = crate::DefaultLinuxImage<S>;
}

impl StoreFilesystem for () {
    type DefaultImage = ();
}

pub(crate) struct ComponentExecutionContext<FileSystem: StoreFilesystem> {
    activity: InstanceActivity,
    filesystem: FileSystem,
    arguments: Vec<String>,
    environment: Vec<(String, String)>,
    process_authority: ProcessAuthority,
    ipc_grants: crate::IpcEndpointGrants,
    default_linux_image: spin::Mutex<Option<FileSystem::DefaultImage>>,
    output_mode: ComponentOutputMode,
}

/// One instance's store data.
///
/// It holds no linear memory: a span a guest names is in the memory of
/// the call that names it, which the runtime adapter takes from that
/// call.
pub struct ComponentStoreData<CpuImpl, RuntimeStateImpl, FileSystem, ResourceTableImpl>
where
    CpuImpl: Cpu + Clone,
    RuntimeStateImpl: ComponentRuntimeState,
    FileSystem: StoreFilesystem,
{
    pub table: ResourceTableImpl,
    /// Pre-bound listening sockets handed to this instance at spawn.
    ///
    /// Declared before `retirement` so any unclaimed TCP listeners still held
    /// when the store drops push onto `retirement` before it drains.
    pub inherited_sockets: crate::InheritedSockets,
    /// The handles of socket resources that have died, and the runtime
    /// state that closes them.
    ///
    /// Declared after `table` and `inherited_sockets` on purpose: both are torn
    /// down first, so every socket still open has already pushed what it owned
    /// by the time this field's `Drop` drains the queue.
    pub retirement: super::StoreSocketRetirement<RuntimeStateImpl>,
    pub cpu: CpuImpl,
    timer: Timer<CpuImpl>,
    spawner: crate::InstanceSpawner<CpuImpl>,
    pub runtime_state: RuntimeStateImpl,
    pub instance_registry: InstanceRegistry,
    entropy: EntropyPool,
    clock: KernelClock<CpuImpl, RuntimeStateImpl>,
    execution_context: ComponentExecutionContext<FileSystem>,
    serial_reader: crate::SerialReader,
    serial_writer: crate::DebugSerialWriter,
    /// Per-stream line buffers mirroring `Serial` stdout/stderr into the trace
    /// log, flushing any partial trailing line when the store drops.
    serial_trace: SerialStreamTrace<CpuImpl, RuntimeStateImpl>,
    /// Every buffer and device region shown in this instance's linear
    /// memory.
    ///
    /// Declared before `device` on purpose: fields drop in order, so a
    /// dying store withdraws every view before any claim it holds is
    /// let go, and the claims' owner tasks — which may run on another
    /// processor the moment a claim drops — never act on a device whose
    /// memory this instance can still reach. The runtime drops store
    /// data before it deallocates the instance and resets the memory
    /// slot, so no view outlives the memory it was shown in.
    pub views: crate::buffer::ViewTable,
    /// The devices, display, desktop windows, 3D engine and playback
    /// stream this instance holds, if any. Empty on every instance that
    /// never asks for one.
    pub device: crate::device::DeviceOwnership,
    /// The input devices this instance holds, if any. Empty on every
    /// instance that never claims one, which is every instance that is
    /// not a compositor.
    pub input: crate::input::InputOwnership,
    /// Set by the runtime exit interface before the guest
    /// traps; the executor reads it to distinguish a clean requested
    /// exit (turn into an exit code) from an actual runtime error.
    requested_exit: Option<u8>,
    /// Number of open debug serial port resources held in `table`.
    serial_ports_held: u32,
}

impl<FileSystem: StoreFilesystem> ComponentExecutionContext<FileSystem> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        instance: RegisteredInstance,
        store_kernel_heap_bytes: u64,
        filesystem: FileSystem,
        arguments: Vec<String>,
        environment: Vec<(String, String)>,
        process_authority: ProcessAuthority,
        output_mode: ComponentOutputMode,
    ) -> Self {
        Self {
            activity: InstanceActivity::new(instance, store_kernel_heap_bytes),
            filesystem,
            arguments,
            environment,
            process_authority,
            ipc_grants: crate::IpcEndpointGrants::new(),
            default_linux_image: spin::Mutex::new(None),
            output_mode,
        }
    }
}

impl<CpuImpl, RuntimeStateImpl, FileSystem, ResourceTableImpl>
    ComponentStoreData<CpuImpl, RuntimeStateImpl, FileSystem, ResourceTableImpl>
where
    CpuImpl: Cpu + Clone,
    RuntimeStateImpl: ComponentRuntimeState,
    FileSystem: StoreFilesystem + Send,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        table: ResourceTableImpl,
        cpu: CpuImpl,
        timer: Timer<CpuImpl>,
        spawner: crate::InstanceSpawner<CpuImpl>,
        runtime_state: RuntimeStateImpl,
        instance_registry: InstanceRegistry,
        instance: RegisteredInstance,
        filesystem: FileSystem,
        arguments: Vec<String>,
        environment: Vec<(String, String)>,
        process_authority: ProcessAuthority,
        output_mode: ComponentOutputMode,
        serial_reader: crate::SerialReader,
        serial_writer: crate::DebugSerialWriter,
    ) -> Self {
        let entropy = EntropyPool::derive(runtime_state.root_entropy(), instance.id().raw());
        let clock = KernelClock::new(cpu.clone(), runtime_state.clone());
        let serial_trace = SerialStreamTrace::new(
            cpu.clone(),
            runtime_state.clone(),
            instance.id(),
            &output_mode,
        );
        Self {
            table,
            inherited_sockets: crate::InheritedSockets::new(),
            retirement: super::StoreSocketRetirement::new(runtime_state.clone()),
            cpu,
            timer,
            spawner,
            runtime_state,
            instance_registry,
            entropy,
            clock,
            execution_context: ComponentExecutionContext::new(
                instance,
                store_kernel_heap_bytes(size_of::<Self>()),
                filesystem,
                arguments,
                environment,
                process_authority,
                output_mode,
            ),
            serial_reader,
            serial_writer,
            serial_trace,
            views: crate::buffer::ViewTable::new(),
            device: crate::device::DeviceOwnership::new(),
            input: crate::input::InputOwnership::new(),
            requested_exit: None,
            serial_ports_held: 0,
        }
    }

    /// Attaches explicit IPC endpoint capabilities granted to this instance at spawn.
    pub fn with_ipc_grants(mut self, ipc_grants: crate::IpcEndpointGrants) -> Self {
        self.execution_context.ipc_grants = ipc_grants;
        self
    }

    /// Attaches an inherited default Linux image to this instance at spawn.
    pub fn with_default_linux_image(self, image: Option<FileSystem::DefaultImage>) -> Self {
        *self.execution_context.default_linux_image.lock() = image;
        self
    }

    /// Attaches pre-bound listening sockets granted to this instance at spawn,
    /// rebinding their TCP retirement senders to this store's retirement queue.
    pub fn with_inherited_sockets(mut self, sockets: crate::InheritedSockets) -> Self {
        sockets.rebind_retirement(self.retirement.sender());
        self.inherited_sockets = sockets;
        self
    }

    pub(crate) fn default_linux_image(&self) -> Option<FileSystem::DefaultImage> {
        self.execution_context.default_linux_image.lock().clone()
    }

    pub(crate) fn set_default_linux_image(&self, image: Option<FileSystem::DefaultImage>) {
        *self.execution_context.default_linux_image.lock() = image;
    }

    pub(crate) fn increment_serial_ports_held(&mut self) {
        self.serial_ports_held = self.serial_ports_held.saturating_add(1);
    }

    pub(crate) fn decrement_serial_ports_held(&mut self) {
        self.serial_ports_held = self.serial_ports_held.saturating_sub(1);
    }

    pub(crate) const fn holds_serial_port(&self) -> bool {
        self.serial_ports_held > 0
    }

    pub(crate) fn inherited_sockets(&self) -> &crate::InheritedSockets {
        &self.inherited_sockets
    }

    /// Retires every network handle a dying socket resource queued
    /// since the last drain.
    ///
    /// Called right after a socket resource is deleted, so that the
    /// common case — a guest closing its own connection — retires on
    /// that very call. Everything else a store's dying sockets queue is
    /// retired when the store's processor turn ends: see
    /// [`Self::guest_turns`].
    pub fn retire_sockets(&self) {
        self.retirement.drain();
    }

    /// The handle the code driving this store accounts its processor
    /// turns through. Taken before the store is borrowed for the call;
    /// see [`super::GuestTurns::drive`].
    pub fn guest_turns(
        &self,
    ) -> super::GuestTurns<CpuImpl, RuntimeStateImpl, super::SocketRetirementQueue> {
        self.guest_turns_with_epilogue(self.retirement.turn_queue())
    }

    pub(crate) fn guest_turns_with_epilogue<Epilogue>(
        &self,
        epilogue: Epilogue,
    ) -> super::GuestTurns<CpuImpl, RuntimeStateImpl, Epilogue>
    where
        Epilogue: super::StopWake,
    {
        super::GuestTurns::new(
            self.execution_context.activity.turns(),
            self.cpu.clone(),
            self.runtime_state.clone(),
            epilogue,
        )
    }

    /// Record the exit code requested by the runtime exit interface so the
    /// executor can report it cleanly after the guest trap.
    pub fn request_exit(&mut self, code: u8) {
        self.requested_exit = Some(code);
    }

    /// Consume any exit code recorded before the guest trapped.
    pub fn take_requested_exit(&mut self) -> Option<u8> {
        self.requested_exit.take()
    }

    pub(crate) fn instance(&self) -> &RegisteredInstance {
        self.execution_context.activity.instance()
    }

    pub(crate) fn ipc_grants(&self) -> &crate::IpcEndpointGrants {
        &self.execution_context.ipc_grants
    }

    pub(crate) fn filesystem(&self) -> &FileSystem {
        &self.execution_context.filesystem
    }

    pub(crate) fn arguments(&self) -> &[String] {
        &self.execution_context.arguments
    }

    pub(crate) fn environment(&self) -> &[(String, String)] {
        &self.execution_context.environment
    }

    pub(crate) fn process_authority(&self) -> &ProcessAuthority {
        &self.execution_context.process_authority
    }

    pub fn output_mode(&self) -> &ComponentOutputMode {
        &self.execution_context.output_mode
    }

    pub(crate) fn serial_reader_fn(&self) -> crate::SerialReader {
        self.serial_reader
    }

    /// The kernel's writer for the machine's debug UART.
    pub(crate) fn serial_writer(&self) -> crate::DebugSerialWriter {
        self.serial_writer
    }

    pub(crate) fn serial_trace_mirror(
        &self,
        stream: ComponentOutputStreamKind,
    ) -> Option<SerialLineMirror> {
        self.serial_trace.mirror(stream)
    }

    pub fn now_nanos(&self) -> u64 {
        self.clock.monotonic_nanos()
    }

    pub fn system_time_nanos(&self) -> u64 {
        self.clock.system_time_nanos()
    }

    pub fn set_system_time_nanos(&mut self, cap: &SetWallClockCap, nanos: u64) {
        self.clock.set_system_time_nanos(cap, nanos);
    }

    pub fn timer(&self) -> Timer<CpuImpl> {
        self.timer.clone()
    }

    pub fn sleep_for(&self, duration: core::time::Duration) -> Sleep<CpuImpl> {
        self.timer.sleep_for(duration)
    }

    pub fn spawner(&self) -> &crate::InstanceSpawner<CpuImpl> {
        &self.spawner
    }

    pub(crate) fn fill_secure_random(&mut self, buffer: &mut [u8]) {
        self.entropy
            .fill_secure(self.runtime_state.root_entropy(), buffer);
    }

    pub(crate) fn secure_random_u64(&mut self) -> u64 {
        self.entropy.secure_u64(self.runtime_state.root_entropy())
    }

    pub(crate) fn fill_insecure_random(&mut self, buffer: &mut [u8]) {
        self.entropy
            .fill_insecure(self.runtime_state.root_entropy(), buffer);
    }

    pub(crate) fn insecure_random_u64(&mut self) -> u64 {
        self.entropy.insecure_u64(self.runtime_state.root_entropy())
    }

    pub(crate) fn insecure_seed(&mut self) -> (u64, u64) {
        self.entropy
            .insecure_seed(self.runtime_state.root_entropy())
    }

    /// Deliver an owned stdout/stderr chunk from a synchronous poll
    /// context, honouring child-channel backpressure.
    ///
    /// A serial sink parks on the debug console's transmit signal:
    /// `serial_wait` keeps the registration armed across polls, so the
    /// UART releasing the port wakes this task into another write
    /// attempt. A child pipe that is at capacity parks the caller:
    /// `pending` keeps the chunk and `wait` keeps the registration, so
    /// the next poll retries the very same bytes once the parent has
    /// drained. Nothing is dropped and a full pipe is never reported
    /// as an error — a vanished reader is swallowed like a POSIX write
    /// to a closed pipe with SIGPIPE suppressed.
    pub fn poll_write_output_bytes(
        &self,
        stream: ComponentOutputStreamKind,
        cx: &mut core::task::Context<'_>,
        wait: &mut Option<crate::ByteWriteWait>,
        serial_wait: &mut Option<crate::NotifyWaiter>,
        pending: &mut Option<Bytes>,
    ) -> core::task::Poll<()> {
        let Some(bytes) = pending.as_ref() else {
            return core::task::Poll::Ready(());
        };
        if bytes.is_empty() {
            *pending = None;
            return core::task::Poll::Ready(());
        }
        match self
            .execution_context
            .output_mode
            .sink(stream, self.instance().id())
        {
            ComponentOutputSink::Local(local) => {
                // The waiter is armed before the port is tried, so a
                // transmit release that lands between the write and the
                // poll is not lost.
                let serial_wait = serial_wait
                    .get_or_insert_with(|| self.serial_writer.debug_serial_output_waiter());
                let line_mirror = self.serial_trace_mirror(stream);
                loop {
                    let chunk = pending.take().expect("the chunk was present a line ago");
                    let taken = local.write_mirrored(
                        &self.cpu,
                        &self.runtime_state,
                        self.serial_writer,
                        line_mirror.as_ref(),
                        &chunk,
                    );
                    if taken == chunk.len() {
                        return core::task::Poll::Ready(());
                    }
                    // The debug UART's owner is another processor. Keep
                    // what is left and come back for it when the
                    // console's transmit signal fires.
                    *pending = Some(chunk.slice(taken..));
                    match self
                        .serial_writer
                        .poll_debug_serial_output_ready(cx, serial_wait)
                    {
                        core::task::Poll::Ready(()) => continue,
                        core::task::Poll::Pending => return core::task::Poll::Pending,
                    }
                }
            }
            ComponentOutputSink::Child(writer) => {
                let wait = wait.get_or_insert_with(|| writer.wait_state());
                writer.poll_write(cx, wait, pending).map(|_closed_or_ok| ())
            }
        }
    }

    /// Non-blocking drain of whatever stdin bytes are currently buffered,
    /// up to `max_bytes`.  Returns an empty `Vec` when the port is idle;
    /// callers that need bytes arm the console's receive wait before this
    /// call and park on it.  For `Child` mode, the reader half of the
    /// parent-provided channel is polled once.
    pub fn try_read_stdin(&self, max_bytes: u32) -> Vec<u8> {
        match self.execution_context.output_mode.stdin_route() {
            ComponentInputRoute::Serial => {
                let mut bytes = Vec::new();
                (self.serial_reader)(&mut bytes, max_bytes);
                bytes
            }
            ComponentInputRoute::Closed => Vec::new(),
            ComponentInputRoute::Child(stdin_rx) => {
                match stdin_rx.try_read_limit(max_bytes as usize) {
                    TryRead::Ready(bytes) => bytes.to_vec(),
                    TryRead::Pending | TryRead::Eof => Vec::new(),
                }
            }
        }
    }

    /// Await the next stdin chunk, parking on the debug console's
    /// receive signal between polls. Returns `None` on EOF (Child mode
    /// after parent closes stdin, or for Trace/Closed mode which never
    /// produces bytes).
    pub async fn await_stdin_chunk(&self) -> Option<Vec<u8>> {
        match self.execution_context.output_mode.stdin_route() {
            ComponentInputRoute::Serial => {
                // Arm the wait before testing the FIFO so a byte that
                // lands between the two still completes it.
                loop {
                    let wait = self.serial_writer.wait_for_debug_serial_input();
                    let mut bytes = Vec::new();
                    (self.serial_reader)(&mut bytes, u32::MAX);
                    if !bytes.is_empty() {
                        return Some(bytes);
                    }
                    wait.await;
                }
            }
            ComponentInputRoute::Closed => None,
            ComponentInputRoute::Child(stdin_rx) => {
                stdin_rx.read().await.map(|bytes| bytes.to_vec())
            }
        }
    }

    /// Raw read of the serial debug port, regardless of this component's
    /// configured stdio routing. Used by `helios:system/serial.read` and
    /// the debugger shell to drain user input directly from hardware.
    pub fn try_read_serial_port(&self, max_bytes: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        (self.serial_reader)(&mut bytes, max_bytes);
        bytes
    }

    /// The condemnation recorded for this instance, if any. The
    /// interrupt callback reads it: a guest that is running traps with it
    /// at its next interrupt check, which the kill's interruption of the
    /// instance's stores makes immediate.
    pub fn pending_kill(&self) -> Option<KillReason> {
        self.execution_context.activity.pending_kill()
    }
}

pub async fn wait_until_runtime_deadline<CpuImpl, RuntimeStateImpl>(
    timer: Timer<CpuImpl>,
    cpu: CpuImpl,
    runtime_state: RuntimeStateImpl,
    deadline_nanos: u64,
) where
    CpuImpl: Cpu + Clone,
    RuntimeStateImpl: ComponentRuntimeState,
{
    loop {
        let now_ticks = cpu.now().ticks();
        let now_nanos = runtime_state.uptime_nanos(now_ticks);
        if now_nanos >= deadline_nanos {
            return;
        }

        let remaining_nanos = deadline_nanos.saturating_sub(now_nanos);
        let remaining_ticks = cpu
            .timebase()
            .nanos_to_ticks_ceil_saturating(remaining_nanos)
            .max(1);
        timer
            .sleep_until(Instant::new(now_ticks.saturating_add(remaining_ticks)))
            .await;
    }
}

// Runtime-adapter trait impls live in the concrete adapter module.

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::string::String;
    use alloc::vec::Vec;
    use spin::Mutex;

    use helios_hal::serial::ByteSerial;

    use super::{
        ComponentOutputMode, ComponentOutputRoute, ComponentOutputStreamKind,
        ComponentRuntimeState, LocalOutputSink, SERIAL_TRACE_LINE_MAX_BYTES, SerialLineBuffer,
        SerialLineMirror, SerialStreamTrace,
    };
    use crate::test_support::TestCpu;
    use crate::{
        DebugConsole, DebugSerialAccess, DebugSerialWriter, InstanceId, MachineObservation,
        PrefixSet, ProfileScope, TraceFilter, TraceLog, TraceValue,
    };

    static SERIAL_WIRE: Mutex<Vec<u8>> = Mutex::new(Vec::new());
    static SERIAL_CONSOLE: DebugConsole = DebugConsole::new();

    struct RecordingSerialPort;

    impl ByteSerial for RecordingSerialPort {
        fn try_read_byte(&self) -> Option<u8> {
            None
        }

        fn write_bytes(&self, bytes: &[u8]) {
            SERIAL_WIRE.lock().extend_from_slice(bytes);
        }

        fn enable_receive_interrupt(&self) {}

        fn disable_receive_interrupt(&self) {}
    }

    impl DebugSerialAccess for RecordingSerialPort {
        type Port = Self;

        fn port() -> Self {
            Self
        }

        fn console() -> &'static DebugConsole {
            &SERIAL_CONSOLE
        }
    }

    const SERIAL_WRITER: DebugSerialWriter = DebugSerialWriter::of::<RecordingSerialPort>();

    #[derive(Clone)]
    struct TraceRecordingState {
        trace_log: alloc::sync::Arc<TraceLog>,
    }

    impl TraceRecordingState {
        fn new() -> Self {
            Self {
                trace_log: alloc::sync::Arc::new(TraceLog::new(64)),
            }
        }

        fn events(&self) -> Vec<(Option<InstanceId>, String)> {
            let filter = TraceFilter {
                min_level: None,
                target_prefixes: PrefixSet::default(),
            };
            self.trace_log
                .recent(&MachineObservation, &filter, 64)
                .into_iter()
                .map(|event| {
                    let message = event
                        .fields
                        .iter()
                        .find_map(|field| match &field.value {
                            TraceValue::Text(text) if field.key == "message" => Some(text.clone()),
                            _ => None,
                        })
                        .unwrap_or_default();
                    (event.origin, message)
                })
                .collect()
        }
    }

    impl ComponentRuntimeState for TraceRecordingState {
        fn uptime_nanos(&self, current_ticks: u64) -> u64 {
            current_ticks
        }

        fn wall_clock_offset_nanos(&self) -> i128 {
            0
        }

        fn record_console_text(&self, current_ticks: u64, origin: Option<InstanceId>, text: &str) {
            self.trace_log
                .record_console_text(current_ticks, origin, text);
        }

        fn root_entropy(&self) -> &crate::RootEntropy {
            panic!("serial trace test state has no root entropy")
        }

        fn memory_balloon(&self) -> Option<crate::memory::BalloonHandle> {
            None
        }

        fn device_grants(&self) -> &crate::device::DeviceGrantRegistry {
            panic!("serial trace test state has no device grants")
        }

        fn display_service(&self) -> Option<crate::display::DisplayService> {
            None
        }

        fn input_service(&self) -> Option<crate::input::InputService> {
            None
        }

        fn gpu3d_service(&self) -> Option<crate::gpu::Gpu3dService> {
            None
        }

        fn surface_service(&self) -> crate::surface::SurfaceService {
            panic!("serial trace test state has no surface service")
        }

        fn audio_service(&self) -> Option<crate::audio::AudioService> {
            None
        }

        fn profiling_enabled(&self) -> bool {
            false
        }

        fn record_profile_stack_nanos(&self, _: ProfileScope, _: String, _: u64) {}

        fn record_user_profile(&self, _: InstanceId, _: &str, _: u64) {}

        fn record_perf_metric_parts(
            &self,
            _: ProfileScope,
            _: &str,
            _: &str,
            _: crate::PerfSample,
        ) {
        }

        fn retire_network_handles(&self, _: &crate::component::SocketRetirementQueue) {}

        fn release_snapshot_hold(&self, _: u64) {}
    }

    #[test]
    fn serial_line_buffer_handles_crlf_split_cjk_overlong_lines_and_invalid_utf8() {
        let mut buf = SerialLineBuffer::new();
        let mut emitted = Vec::new();

        // Split multi-byte UTF-8 across CJK (Chinese, Japanese, Korean) and CRLF.
        let cjk_line = "中文・日本語・한국어\r\n";
        let cjk_bytes = cjk_line.as_bytes();
        buf.push_bytes(&cjk_bytes[..2], |line| emitted.push(String::from(line)));
        assert!(emitted.is_empty());
        buf.push_bytes(&cjk_bytes[2..cjk_bytes.len() - 1], |line| {
            emitted.push(String::from(line))
        });
        assert!(emitted.is_empty());
        buf.push_bytes(&cjk_bytes[cjk_bytes.len() - 1..], |line| {
            emitted.push(String::from(line))
        });
        assert_eq!(emitted, alloc::vec![String::from("中文・日本語・한국어")]);
        emitted.clear();

        // Overlong single line without newline flushes bounded chunks and preserves
        // a 3-byte UTF-8 character straddling the 4096-byte boundary.
        let mut overlong = alloc::vec![b'a'; SERIAL_TRACE_LINE_MAX_BYTES - 1];
        overlong.extend_from_slice("中".as_bytes());
        overlong.push(b'\n');
        buf.push_bytes(&overlong, |line| emitted.push(String::from(line)));
        assert_eq!(emitted.len(), 2);
        assert_eq!(emitted[0].len(), SERIAL_TRACE_LINE_MAX_BYTES - 1);
        assert_eq!(emitted[1], "中");
        assert!(buf.pending.is_empty());
        emitted.clear();

        // Invalid UTF-8 bytes never panic and decode lossily.
        buf.push_bytes(b"bad-\xff-byte\n", |line| emitted.push(String::from(line)));
        assert_eq!(emitted, alloc::vec![String::from("bad-\u{FFFD}-byte")]);
        emitted.clear();

        // Partial trailing line flushes on explicit flush.
        buf.push_bytes(b"trailing-no-newline\r", |line| {
            emitted.push(String::from(line))
        });
        assert!(emitted.is_empty());
        buf.flush(|line| emitted.push(String::from(line)));
        assert_eq!(emitted, alloc::vec![String::from("trailing-no-newline")]);
    }

    #[test]
    fn serial_sink_mirrors_complete_lines_to_trace_log_and_preserves_raw_serial_bytes() {
        SERIAL_WIRE.lock().clear();
        let cpu = TestCpu::with_entropy(0x41);
        let state = TraceRecordingState::new();
        let instance = InstanceId::from_raw(42);
        let mirror = SerialLineMirror::new();
        let sink = LocalOutputSink::Serial(instance);

        let chunks: [&[u8]; 4] = [
            b"helios init: ",
            b"booting services\r\n",
            b"[KDBG run:begin]\n",
            b"partial-tail",
        ];
        let mut expected_wire = Vec::new();
        for chunk in chunks {
            expected_wire.extend_from_slice(chunk);
            let mut offset = 0;
            while offset < chunk.len() {
                let written = sink.write_mirrored(
                    &cpu,
                    &state,
                    SERIAL_WRITER,
                    Some(&mirror),
                    &chunk[offset..],
                );
                assert!(written > 0);
                offset += written;
            }
        }

        // Raw wire output is 100% byte-for-byte unchanged.
        assert_eq!(*SERIAL_WIRE.lock(), expected_wire);

        // Only completed lines are in TraceLog before flush/drop.
        assert_eq!(
            state.events(),
            alloc::vec![
                (
                    Some(instance),
                    String::from("helios init: booting services")
                ),
                (Some(instance), String::from("[KDBG run:begin]")),
            ]
        );

        // Dropping SerialStreamTrace flushes any partial stdout/stderr line.
        {
            let trace = SerialStreamTrace::new(
                cpu,
                state.clone(),
                instance,
                &ComponentOutputMode::RoutedChild {
                    stdin: super::ComponentInputRoute::Closed,
                    stdout: ComponentOutputRoute::Serial,
                    stderr: ComponentOutputRoute::Serial,
                },
            );
            let stdout_mirror = trace
                .mirror(ComponentOutputStreamKind::Stdout)
                .expect("serial stdout gets mirror");
            let stderr_mirror = trace
                .mirror(ComponentOutputStreamKind::Stderr)
                .expect("serial stderr gets mirror");
            let _ = sink.write_mirrored(
                &cpu,
                &state,
                SERIAL_WRITER,
                Some(&stdout_mirror),
                b"stdout-unterminated",
            );
            let _ = sink.write_mirrored(
                &cpu,
                &state,
                SERIAL_WRITER,
                Some(&stderr_mirror),
                b"stderr-unterminated",
            );
            assert_eq!(state.events().len(), 2);
        }

        assert_eq!(
            state.events(),
            alloc::vec![
                (
                    Some(instance),
                    String::from("helios init: booting services")
                ),
                (Some(instance), String::from("[KDBG run:begin]")),
                (Some(instance), String::from("stdout-unterminated")),
                (Some(instance), String::from("stderr-unterminated")),
            ]
        );
    }
}
