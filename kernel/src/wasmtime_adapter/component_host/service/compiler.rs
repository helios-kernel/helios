use super::*;
use crate::wasmtime_adapter::preemption::kill_or_yield;
use helios_compiler_abi::{CompilerStatus, OutputKind, UnknownDiscriminant};
use helios_hal::fs::{FilledWrite, PreparedWrite, WritePosition, WriteProgress};

/// Rejects raw wasm input larger than `limit` (`compiler.max-input-bytes`).
pub(super) fn check_compiler_input_limit(bytes: u64, limit: u64) -> Result<(), ProgramExecError> {
    if bytes > limit {
        return Err(ProgramExecError {
            kind: ProgramExecErrorKind::InvalidBinary,
            detail: ProgramExecErrorDetail::CompilerInputTooLarge { bytes, limit },
        });
    }
    Ok(())
}

/// Converts a host length to the signed 32-bit size the compiler plugin's
/// `alloc`/`free` exports take, failing fast instead of truncating.
pub(super) fn compiler_abi_i32(len: usize) -> Result<i32, ProgramExecError> {
    i32::try_from(len).map_err(|_| ProgramExecError {
        kind: ProgramExecErrorKind::InvalidBinary,
        detail: ProgramExecErrorDetail::CompilerAbiLengthOverflow,
    })
}

/// Converts a host length to the unsigned 32-bit field in
/// [`CompilerRequestHeader`], failing fast instead of truncating.
pub(super) fn compiler_abi_u32(len: usize) -> Result<u32, ProgramExecError> {
    u32::try_from(len).map_err(|_| ProgramExecError {
        kind: ProgramExecErrorKind::InvalidBinary,
        detail: ProgramExecErrorDetail::CompilerAbiLengthOverflow,
    })
}

/// Destination for a signed AOT artifact streamed directly from plugin memory.
pub(crate) struct AotDestination<StorageImpl: crate::Storage> {
    pub(crate) namespace: crate::Namespace<StorageImpl>,
    pub(crate) absolute: String,
    pub(crate) now: u64,
    pub(crate) payer: crate::StoragePayer,
    pub(crate) requester: crate::InstanceId,
}

/// Where the compiled output of one compile session lands.
pub(super) enum CompileOutputSink<StorageImpl: crate::Storage> {
    /// Return the raw Wasmtime payload to the caller (`exec`/`spawn` of raw wasm).
    ReturnPayload,
    /// Sign the payload directly in plugin memory and stream `[payload || trailer]`
    /// straight to `destination` without a whole-artifact kernel-heap copy.
    WriteSignedFile(AotDestination<StorageImpl>),
}

/// What one compile call produced according to its [`CompileOutputSink`].
pub(super) enum CompileOutput {
    Payload(Vec<u8>),
    WrittenBytes(usize),
}

/// Cached runtime of the compiler kernel plugin (`SharedMemory` + `InstancePre`
/// + main-thread TLS block).
pub(super) struct CompilerPluginRuntime<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    pub(super) instance_pre: Arc<InstancePre<CompilerCoreStore<CpuImpl, Net, StorageImpl>>>,
    pub(super) shared: Arc<SharedMemoryCoreShared<CompilerCoreStore<CpuImpl, Net, StorageImpl>>>,
    /// The linker-reserved main-thread TLS block, initialised once by the
    /// instance that wins the memory-init flag; every per-compile instance
    /// adopts it because later instances skip that init and see `__tls_base == 0`.
    pub(super) main_thread_tls_base: u32,
    /// Names the plugin's code to the instruction sampler while the
    /// plugin is resident.
    pub(super) _code: crate::wasmtime_adapter::code_map::CodeRegistration,
}

/// The compiler plugin's exports one call uses.
pub(super) struct CompilerExports {
    pub(super) alloc: wasmtime::TypedFunc<(i32, i32), i32>,
    pub(super) free: wasmtime::TypedFunc<(i32, i32, i32), ()>,
    pub(super) compile: wasmtime::TypedFunc<(i32, i32), i32>,
    pub(super) outstanding: wasmtime::TypedFunc<(), i32>,
}

/// The bytes the plugin counts as owned across the interface right now.
pub(super) async fn compiler_outstanding_bytes<CpuImpl, Net, StorageImpl>(
    drive: &CompilerStoreDrive<CpuImpl>,
    store: &mut wasmtime::Store<CompilerCoreStore<CpuImpl, Net, StorageImpl>>,
    outstanding: &wasmtime::TypedFunc<(), i32>,
) -> Result<u32, ProgramExecError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    drive
        .call(store, outstanding, ())
        .await
        .map(|bytes| bytes as u32)
        .map_err(map_program_runtime_error)
}

/// Holds the interface to its accounting once a compile's buffers have been
/// released: the plugin's count is back at the level it had before the
/// request was allocated, or the call is an ABI failure. The error is
/// `Internal`, so the supervisor discards a runtime whose memory no longer
/// matches the contract instead of compiling on with it.
pub(super) fn ensure_compiler_buffers_returned(
    before: u32,
    after: u32,
) -> Result<(), ProgramExecError> {
    if after == before {
        return Ok(());
    }
    tracing::error!(
        before,
        after,
        "compiler plugin buffers were not all returned after a compile"
    );
    Err(ProgramExecError {
        kind: ProgramExecErrorKind::Internal,
        detail: ProgramExecErrorDetail::CompilerBuffersOutstanding,
    })
}

/// How a compile call ended, as far as the plugin's memory is concerned.
///
/// The outer `Err` is a failed call into the plugin (a trap, a kill, an
/// allocation the plugin refused): its allocator and memory are in an unknown
/// state, the runtime is discarded or about to be, and nothing is freed
/// because the memory dies with it. Every other end, the success and the
/// kernel's own failures (a bad response, a rejected input), is the inner
/// `Result`, and means every call into the plugin returned, so the call's
/// [`CompilerAllocations`] are released. The two are told apart by which side
/// of the interface produced the error, never by a flag, and the nesting
/// (rather than a wrapper enum) keeps the error within the size budget of a
/// program `Err`.
pub(super) type CompilerCallOutcome =
    Result<Result<CompileOutput, ProgramExecError>, ProgramExecError>;

/// What one compile asks of the plugin: the module, the ISA the artifact
/// is for, how hard to optimise it, and where its output lands.
pub(super) struct CompileRequest<StorageImpl: crate::Storage> {
    pub(super) wasm: Bytes,
    pub(super) guest_isa: GuestIsa,
    pub(super) hint: AotCompileHint,
    /// Whether the plugin reports its pass timings.
    pub(super) profile: bool,
    pub(super) sink: CompileOutputSink<StorageImpl>,
}

/// A buffer in the plugin's memory, with the layout it was allocated with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PluginBuffer {
    ptr: u32,
    len: i32,
    align: i32,
}

/// The plugin allocations of one compile call: the four request buffers the
/// kernel allocates and the three response buffers the plugin hands over (the
/// ownership table is in `helios_compiler_abi`).
///
/// They are freed together by [`Self::release`], which is reached only when
/// every call into the plugin returned. It cannot be a `Drop`, because
/// freeing is an async call into the plugin; a call that trapped simply never
/// reaches `release`, and its allocations die with the runtime.
#[must_use = "the plugin's allocations leak unless released"]
pub(super) struct CompilerAllocations {
    /// Four request buffers and three response buffers.
    buffers: SmallVec<[PluginBuffer; 7]>,
}

impl CompilerAllocations {
    pub(super) fn new() -> Self {
        Self {
            buffers: SmallVec::new(),
        }
    }

    /// Allocates a request buffer through the plugin and records it. A
    /// zero-length buffer is pointer 0 and is not allocated.
    pub(super) async fn alloc<CpuImpl, Net, StorageImpl>(
        &mut self,
        drive: &CompilerStoreDrive<CpuImpl>,
        store: &mut wasmtime::Store<CompilerCoreStore<CpuImpl, Net, StorageImpl>>,
        alloc: &wasmtime::TypedFunc<(i32, i32), i32>,
        len: usize,
        align: usize,
    ) -> Result<u32, ProgramExecError>
    where
        CpuImpl: Cpu + Clone,
        Net: ComponentHostNetwork,
        StorageImpl: crate::Storage,
    {
        if len == 0 {
            return Ok(0);
        }
        let abi_len = compiler_abi_i32(len)?;
        let abi_align = compiler_abi_i32(align)?;
        let ptr = compiler_alloc(drive, store, alloc, abi_len, abi_align).await?;
        self.buffers.push(PluginBuffer {
            ptr,
            len: abi_len,
            align: abi_align,
        });
        Ok(ptr)
    }

    /// Takes ownership of a buffer the plugin handed over in its response. A
    /// zero-length buffer is pointer 0 and was never allocated.
    pub(super) fn adopt(
        &mut self,
        ptr: u32,
        len: usize,
        align: usize,
    ) -> Result<(), ProgramExecError> {
        if len == 0 {
            return Ok(());
        }
        self.buffers.push(PluginBuffer {
            ptr,
            len: compiler_abi_i32(len)?,
            align: compiler_abi_i32(align)?,
        });
        Ok(())
    }

    /// Returns every recorded buffer to the plugin.
    pub(super) async fn release<CpuImpl, Net, StorageImpl>(
        self,
        drive: &CompilerStoreDrive<CpuImpl>,
        store: &mut wasmtime::Store<CompilerCoreStore<CpuImpl, Net, StorageImpl>>,
        free: &wasmtime::TypedFunc<(i32, i32, i32), ()>,
    ) -> Result<(), ProgramExecError>
    where
        CpuImpl: Cpu + Clone,
        Net: ComponentHostNetwork,
        StorageImpl: crate::Storage,
    {
        for buffer in self.buffers {
            drive
                .call(store, free, (buffer.ptr as i32, buffer.len, buffer.align))
                .await
                .map_err(map_program_runtime_error)?;
        }
        Ok(())
    }
}

/// What every store of one compile shares: the platform handles, the
/// compile's instance and the plugin runtime's shared state. A worker store
/// is built from a clone of its parent's context.
#[derive(Clone)]
pub(super) struct CompilerCompileContext<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    pub(super) cpu: CpuImpl,
    pub(super) spawner: crate::Spawner<CpuImpl>,
    pub(super) runtime_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
    pub(super) instance: crate::RegisteredInstance,
    /// The registry `instance` lives in, which a condemnation goes through.
    pub(super) registry: crate::InstanceRegistry,
    pub(super) shared: Arc<SharedMemoryCoreShared<CompilerCoreStore<CpuImpl, Net, StorageImpl>>>,
    /// Core-affinity plan for every thread of this compile session.
    pub(super) affinity_plan: CoreAffinityPlan,
    pub(super) write_serial: crate::DebugSerialWriter,
    pub(super) _marker: core::marker::PhantomData<fn() -> StorageImpl>,
}

impl<CpuImpl, Net, StorageImpl> CompilerCompileContext<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    /// Condemns the compile's instance for `reason` and interrupts every
    /// store of it.
    fn condemn(&self, reason: crate::KillReason) -> crate::KillOutcome {
        condemn_session(
            &self.registry,
            &self.shared.interrupts,
            self.instance.id(),
            reason,
            self.runtime_state.uptime_nanos(self.cpu.now().ticks()),
        )
    }

    /// A worker store's call ended in `error`; returns the error the compile
    /// reports when this is the compile's first trap.
    ///
    /// A trap on one store tells the compile's other stores nothing: main
    /// parks for ever on the job the dead worker held, or the workers park
    /// for ever once main is gone. So a trap, an end that is not the compile's
    /// own kill, condemns the instance, and every other store unwinds through
    /// the kill path. The first condemnation's reason stands, so only the
    /// trap that condemns first reports its error: a store that ends by a
    /// kill, or by a trap after another store condemned, reports none.
    pub(super) fn condemn_for_store_end(&self, error: wasmtime::Error) -> Option<ProgramExecError> {
        if error.downcast_ref::<crate::InstanceKilled>().is_some() {
            return None;
        }
        match self.condemn(crate::KillReason::StoreFailed) {
            crate::KillOutcome::Requested => Some(map_program_runtime_error(error)),
            crate::KillOutcome::AlreadyStopping | crate::KillOutcome::NoSuchInstance => None,
        }
    }

    /// The compile's main thread ended its part with `result`, before the
    /// workers are joined: a failure condemns the instance, as a worker's
    /// trap does ([`Self::condemn_for_store_end`]), so workers parked in the
    /// pool's idle wait end instead of being joined for ever.
    ///
    /// A failure after a worker's own trap is the condemnation reaching main;
    /// [`first_trap_wins`] swaps it for the worker's error once the workers
    /// are joined.
    pub(super) fn end_main_part<T>(
        &self,
        result: Result<T, ProgramExecError>,
    ) -> Result<T, ProgramExecError> {
        if result.is_err() {
            self.condemn(crate::KillReason::StoreFailed);
        }
        result
    }
}

/// The result a compile reports once every worker is joined: the first
/// trap's error, taken from the worker that condemned the compile, over
/// whatever main ended with (the condemnation, when main was ended by it).
///
/// Only the store that condemned the instance carries an error, so at most one
/// report does. A compile in which a store trapped fails even when main
/// returned a response, because the plugin's memory is in an unknown state.
pub(super) fn first_trap_wins<T>(
    result: Result<T, ProgramExecError>,
    reports: &mut [SharedMemoryThreadReport],
) -> Result<T, ProgramExecError> {
    match reports.iter_mut().find_map(|report| report.trap.take()) {
        Some(trap) => Err(trap),
        None => result,
    }
}

/// One compiler store's data: the compile's context, and what belongs to
/// this store alone and is therefore not `Clone`, its accounting and its
/// descriptors.
///
/// The accounting names no owner for the user memory its turns commit: the
/// plugin's memory belongs to the cached runtime, not to the compile's
/// instance or to the requester, and the kernel reads it without a
/// pre-fault, so it is never the swap policy's to evict.
pub(super) struct CompilerCoreStore<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    pub(super) context: CompilerCompileContext<CpuImpl, Net, StorageImpl>,
    pub(super) preview1_descriptors: CompilerPreview1Descriptors,
    activity: crate::InstanceActivity,
}

pub(super) struct CompilerPreview1Descriptors {
    pub(super) stdout_open: bool,
    pub(super) stderr_open: bool,
}

impl CompilerPreview1Descriptors {
    pub(super) const fn new() -> Self {
        Self {
            stdout_open: true,
            stderr_open: true,
        }
    }

    pub(super) fn can_write(&self, fd: i32) -> bool {
        match fd {
            1 => self.stdout_open,
            2 => self.stderr_open,
            _ => false,
        }
    }

    pub(super) fn close(&mut self, fd: i32) -> i32 {
        match fd {
            1 if self.stdout_open => {
                self.stdout_open = false;
                p1::errno::SUCCESS
            }
            2 if self.stderr_open => {
                self.stderr_open = false;
                p1::errno::SUCCESS
            }
            _ => p1::errno::BADF,
        }
    }
}

impl<CpuImpl, Net, StorageImpl> CompilerCoreStore<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    /// A store of `context`'s compile, with its own accounting over the
    /// compile's instance.
    pub(super) fn new(context: CompilerCompileContext<CpuImpl, Net, StorageImpl>) -> Self {
        let activity = crate::InstanceActivity::without_memory_owner(
            context.instance.clone(),
            crate::store_kernel_heap_bytes(size_of::<Self>()),
        );
        Self {
            context,
            preview1_descriptors: CompilerPreview1Descriptors::new(),
            activity,
        }
    }

    pub(super) fn memory(&self) -> &SharedMemory {
        &self.context.shared.memory
    }

    /// The handle the code driving this store accounts its processor
    /// turns through. Taken before the store is borrowed for the call;
    /// see [`crate::component::GuestTurns::drive`].
    pub(super) fn guest_turns(
        &self,
    ) -> crate::component::GuestTurns<CpuImpl, HostRuntimeState<CpuImpl, Net, StorageImpl>, ()>
    {
        crate::component::GuestTurns::new(
            self.activity.turns(),
            self.context.cpu.clone(),
            self.context.runtime_state.clone(),
            (),
        )
    }

    /// The interrupt callback: a pending kill of the compile's instance
    /// traps, and any other interruption is the end of a time slice, on
    /// which the store yields. It is the decision every store makes
    /// ([`kill_or_yield`]).
    fn on_interrupt(&self) -> wasmtime::Result<wasmtime::InterruptAction> {
        kill_or_yield(self.activity.pending_kill())
    }
}

pub(super) fn compiler_shared_memory(
    engine: &wasmtime::Engine,
    module: &Module,
) -> Result<SharedMemory, ProgramExecError> {
    imported_shared_memory_with_declared_maximum(engine, module)?.ok_or(ProgramExecError {
        kind: ProgramExecErrorKind::InvalidBinary,
        detail: ProgramExecErrorDetail::CompilerMemoryContractInvalid,
    })
}

pub(super) fn define_compiler_shared_memory<T>(
    linker: &mut CoreLinker<T>,
    store: &wasmtime::Store<T>,
    module: &Module,
    memory: SharedMemory,
) -> Result<(), ProgramExecError> {
    define_imported_shared_memory(linker, store, module, memory)
}

pub(super) fn add_compiler_core_imports<CpuImpl, Net, StorageImpl>(
    linker: &mut CoreLinker<CompilerCoreStore<CpuImpl, Net, StorageImpl>>,
    memory: SharedMemory,
) -> Result<(), ProgramExecError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    add_wasi_p1_imports(linker)?;
    add_wasi_thread_spawn(linker)?;
    let _ = memory;
    Ok(())
}

pub(super) fn compiler_rayon_env_len(thread_count: u32) -> u32 {
    RAYON_NUM_THREADS_ENV.len() as u32 + decimal_len(thread_count) + 1
}

pub(super) fn compiler_environ_get<CpuImpl, Net, StorageImpl>(
    caller: Caller<'_, CompilerCoreStore<CpuImpl, Net, StorageImpl>>,
    environ: u32,
    buf: u32,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let thread_count = caller.data().context.shared.worker_threads();
    let memory = caller.data().memory();
    let environ = GuestAddress::wasm32(environ);
    let pointer_status = write_u32(memory, environ, buf);
    let bytes_status = write_rayon_threads_env(memory, GuestAddress::wasm32(buf), thread_count);
    pointer_status.max(bytes_status)
}

pub(super) fn write_rayon_threads_env(
    memory: &SharedMemory,
    ptr: GuestAddress,
    thread_count: u32,
) -> i32 {
    let prefix_status = write_shared_memory(memory, ptr, RAYON_NUM_THREADS_ENV).map_or(28, |_| 0);
    if prefix_status != 0 {
        return prefix_status;
    }
    let digits_start = ptr.offset(RAYON_NUM_THREADS_ENV.len() as u64);
    let digits_len = write_decimal(memory, digits_start, thread_count);
    if digits_len < 0 {
        return 28;
    }
    let nul_ptr = digits_start.offset(digits_len as u64);
    write_shared_memory(memory, nul_ptr, &[0]).map_or(28, |_| 0)
}

pub(super) fn decimal_len(mut value: u32) -> u32 {
    let mut len = 1;
    while value >= 10 {
        value /= 10;
        len += 1;
    }
    len
}

pub(super) fn write_decimal(memory: &SharedMemory, ptr: GuestAddress, mut value: u32) -> i32 {
    let mut digits = [0_u8; 10];
    let len = decimal_len(value) as usize;
    for index in (0..len).rev() {
        digits[index] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    write_shared_memory(memory, ptr, &digits[..len]).map_or(-1, |_| len as i32)
}

/// The route every call into one compiler store goes through: the store
/// registered for kills and for the end of a time slice, whose calls are
/// published as their processor's running store and accounted one
/// processor turn per poll, exactly as a program's are.
///
/// Every call into a compiler store, the compile's main thread and each
/// worker alike, is made through [`Self::call`] or [`Self::instantiate`], so
/// the end of a processor's guest time slice, or a freeze's request
/// (`GuestInterrupts::interrupt_running`), makes the guest yield to the
/// executor and a kill of the compile's instance ends the call, including
/// one parked in `memory.atomic.wait`.
///
/// # Concurrency
///
/// Owned by the task that drives the store; see
/// [`crate::wasmtime_adapter::preemption`] for the contract of the running
/// slots and the kill table, and [`crate::component::GuestTurns`] for the
/// turns. Nothing here takes a lock of its own.
pub(super) struct CompilerStoreDrive<CpuImpl: Cpu> {
    interrupts: crate::wasmtime_adapter::preemption::StoreInterrupts<CpuImpl>,
}

impl<CpuImpl: Cpu + Clone> CompilerStoreDrive<CpuImpl> {
    /// Calls `func` on `store` under the drive.
    pub(super) async fn call<Net, StorageImpl, Params, Results>(
        &self,
        store: &mut wasmtime::Store<CompilerCoreStore<CpuImpl, Net, StorageImpl>>,
        func: &wasmtime::TypedFunc<Params, Results>,
        params: Params,
    ) -> wasmtime::Result<Results>
    where
        Net: ComponentHostNetwork,
        StorageImpl: crate::Storage,
        Params: wasmtime::WasmParams + Sync,
        Results: wasmtime::WasmResults + Sync,
    {
        let turns = store.data().guest_turns();
        self.interrupts
            .drive(turns.drive(func.call_async(&mut *store, params)))
            .await
    }

    /// Instantiates `instance_pre` on `store` under the drive.
    pub(super) async fn instantiate<Net, StorageImpl>(
        &self,
        store: &mut wasmtime::Store<CompilerCoreStore<CpuImpl, Net, StorageImpl>>,
        instance_pre: &InstancePre<CompilerCoreStore<CpuImpl, Net, StorageImpl>>,
    ) -> wasmtime::Result<wasmtime::Instance>
    where
        Net: ComponentHostNetwork,
        StorageImpl: crate::Storage,
    {
        let turns = store.data().guest_turns();
        self.interrupts
            .drive(turns.drive(instance_pre.instantiate_async(&mut *store)))
            .await
    }
}

/// Installs the compiler store's interrupt callback and registers the
/// store for kills, for as long as the returned drive lives.
pub(super) fn configure_compiler_core_store<CpuImpl, Net, StorageImpl>(
    store: &mut wasmtime::Store<CompilerCoreStore<CpuImpl, Net, StorageImpl>>,
) -> CompilerStoreDrive<CpuImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    store.interrupt_callback(|caller| caller.data().on_interrupt());
    // The compiler's store has no OOM-kill route: a stack reserve the
    // pool cannot back ends the compile with its typed out-of-memory
    // failure, and the plugin's owner discards or restarts it.
    crate::wasmtime_adapter::store::install_stack_reserve(store, |_, _| {});
    let interrupts = store.data().context.shared.interrupts.clone();
    let instance = store.data().context.instance.id();
    CompilerStoreDrive {
        interrupts: interrupts.register(instance, store, store.data().context.cpu.clone()),
    }
}

pub(super) fn compiler_tls_base<CpuImpl, Net, StorageImpl>(
    store: &mut wasmtime::Store<CompilerCoreStore<CpuImpl, Net, StorageImpl>>,
    instance: &wasmtime::Instance,
) -> Result<u32, ProgramExecError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let global = instance
        .get_global(&mut *store, "__tls_base")
        .ok_or(ProgramExecError {
            kind: ProgramExecErrorKind::InvalidBinary,
            detail: ProgramExecErrorDetail::CompilerPluginInvalid,
        })?;
    match global.get(&mut *store) {
        Val::I32(value) => Ok(value as u32),
        value => Err(ProgramExecError {
            kind: ProgramExecErrorKind::InvalidBinary,
            detail: {
                tracing::error!(?value, "compiler __tls_base has invalid value type");
                ProgramExecErrorDetail::CompilerPluginInvalid
            },
        }),
    }
}

pub(super) fn set_compiler_tls_base<CpuImpl, Net, StorageImpl>(
    store: &mut wasmtime::Store<CompilerCoreStore<CpuImpl, Net, StorageImpl>>,
    instance: &wasmtime::Instance,
    tls_base: u32,
) -> Result<(), ProgramExecError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let global = instance
        .get_global(&mut *store, "__tls_base")
        .ok_or(ProgramExecError {
            kind: ProgramExecErrorKind::InvalidBinary,
            detail: ProgramExecErrorDetail::CompilerPluginInvalid,
        })?;
    global
        .set(&mut *store, Val::I32(tls_base as i32))
        .map_err(map_program_runtime_error)
}

pub(super) async fn compiler_alloc<CpuImpl, Net, StorageImpl>(
    drive: &CompilerStoreDrive<CpuImpl>,
    store: &mut wasmtime::Store<CompilerCoreStore<CpuImpl, Net, StorageImpl>>,
    alloc: &wasmtime::TypedFunc<(i32, i32), i32>,
    len: i32,
    align: i32,
) -> Result<u32, ProgramExecError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let ptr = drive
        .call(store, alloc, (len, align))
        .await
        .map_err(map_program_runtime_error)?;
    if ptr == 0 {
        let memory = store.data().memory();
        tracing::error!(
            len,
            pages = memory.size(),
            bytes = memory.data_size(),
            "compiler allocation returned null"
        );
        return Err(ProgramExecError {
            kind: ProgramExecErrorKind::OutOfMemory,
            detail: ProgramExecErrorDetail::CompilerAllocationFailed,
        });
    }
    Ok(ptr as u32)
}

/// The typed error for a wire value the plugin sent that names no variant.
pub(super) fn compiler_abi_value_error(error: UnknownDiscriminant) -> ProgramExecError {
    tracing::error!(
        field = error.field,
        value = error.value,
        "compiler plugin sent an unknown ABI value"
    );
    ProgramExecError {
        kind: ProgramExecErrorKind::InvalidBinary,
        detail: ProgramExecErrorDetail::CompilerAbiValueInvalid(error),
    }
}

/// Decodes the enumerated fields of a response header; an unknown value is
/// the typed ABI error rather than an invalid enum.
pub(super) fn decode_compiler_response(
    header: &CompilerResponseHeader,
) -> Result<(CompilerStatus, OutputKind), ProgramExecError> {
    let status = CompilerStatus::try_from(header.status).map_err(compiler_abi_value_error)?;
    let output_kind = OutputKind::try_from(header.output_kind).map_err(compiler_abi_value_error)?;
    Ok((status, output_kind))
}

/// Everything the kernel does with a response once `compile` returned, which
/// is host-side work only: no call into the plugin is made here, so every
/// failure leaves the instance intact and the call's allocations are freed by
/// the caller. The response buffers are adopted into `allocations` as soon as
/// the header's layout is known to be this ABI's, before anything else can
/// fail, so a rejected or malformed response is freed too.
///
/// The plugin's memory is read during the store's turns
/// ([`in_guest_turn`]): `compile` has returned, so the instance is off every
/// processor between them. The header is all `u32` fields, so every byte
/// pattern in plugin memory decodes to a header; what its enumerated fields
/// mean is checked by [`decode_compiler_response`].
/// Copies the region `[offset .. offset + dst.len()]` of the logical
/// `[payload || trailer]` stream into `dst`, where `payload_chunk` covers
/// `[payload_start .. payload_start + payload_chunk.len()]` of `payload`.
pub(super) fn copy_payload_and_trailer(
    offset: usize,
    dst: &mut [u8],
    payload_start: usize,
    payload_chunk: &[u8],
    payload_len: usize,
    trailer: &[u8],
) {
    let payload_part = payload_len.saturating_sub(offset).min(dst.len());
    if payload_part > 0 {
        let rel = offset - payload_start;
        dst[..payload_part].copy_from_slice(&payload_chunk[rel..rel + payload_part]);
    }
    if payload_part < dst.len() {
        let trailer_start = (offset + payload_part) - payload_len;
        let trailer_len = dst.len() - payload_part;
        dst[payload_part..].copy_from_slice(&trailer[trailer_start..trailer_start + trailer_len]);
    }
}

/// Maps a WASI filesystem error while streaming an AOT artifact to a
/// [`ProgramExecError`].
pub(in crate::wasmtime_adapter::component_host) fn map_aot_fs_error(
    error: fs_types::ErrorCode,
) -> ProgramExecError {
    tracing::error!(
        ?error,
        "filesystem operation failed during AOT output write"
    );
    let kind = match error {
        fs_types::ErrorCode::NoEntry
        | fs_types::ErrorCode::NotDirectory
        | fs_types::ErrorCode::BadDescriptor
        | fs_types::ErrorCode::ReadOnly
        | fs_types::ErrorCode::NotPermitted
        | fs_types::ErrorCode::Exist
        | fs_types::ErrorCode::IsDirectory
        | fs_types::ErrorCode::IllegalByteSequence
        | fs_types::ErrorCode::Invalid
        | fs_types::ErrorCode::Overflow => ProgramExecErrorKind::InvalidPath,
        fs_types::ErrorCode::InsufficientMemory => ProgramExecErrorKind::OutOfMemory,
        _ => ProgramExecErrorKind::Internal,
    };
    ProgramExecError {
        kind,
        detail: ProgramExecErrorDetail::FilesystemOperationFailed,
    }
}

/// A byte range inside the compiler plugin's linear memory.
#[derive(Clone, Copy)]
struct PluginSlice {
    ptr: u32,
    len: usize,
}

/// Signs the compiled artifact directly inside plugin linear memory and
/// streams `[payload || trailer]` straight into `destination` via
/// [`PreparedWrite`], avoiding any whole-artifact copy on the kernel heap.
async fn write_signed_artifact_from_plugin_memory<CpuImpl, Net, StorageImpl>(
    store: &CompilerCoreStore<CpuImpl, Net, StorageImpl>,
    memory: &Preview1AsyncMemory,
    precompiled: PluginSlice,
    destination: AotDestination<StorageImpl>,
    signing_key: &crate::CwasmSigningKey,
    profile: bool,
    phases: &mut CompilerPhaseTimestamps,
) -> Result<usize, ProgramExecError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let precompiled_ptr = precompiled.ptr;
    let precompiled_len = precompiled.len;
    let trailer = in_guest_turn(
        store.guest_turns(),
        memory.read(
            GuestAddress::wasm32(precompiled_ptr),
            precompiled_len,
            |payload| cwasm::sign_artifact_trailer(payload, signing_key),
        ),
    )
    .await?
    .map_err(map_artifact_trust_error)?;
    phases.signed_ns = if profile {
        monotonic_nanos(&store.context.cpu)
    } else {
        0
    };
    let total_len = precompiled_len
        .checked_add(trailer.len())
        .ok_or(ProgramExecError {
            kind: ProgramExecErrorKind::InvalidBinary,
            detail: ProgramExecErrorDetail::CompilerAbiLengthOverflow,
        })?;
    let write_started_ns = if profile {
        monotonic_nanos(&store.context.cpu)
    } else {
        0
    };
    let map_write_error = |error: fs_types::ErrorCode| {
        if matches!(error, fs_types::ErrorCode::InsufficientMemory) {
            crate::wasmtime_adapter::store::request_oom_kill(
                &store.context.runtime_state,
                &store.context.registry,
                &store.context.cpu,
                destination.requester,
                crate::MemoryPool::User,
                total_len.max(helios_hal::pmm::PhysFrame::SIZE),
            );
        }
        map_aot_fs_error(error)
    };
    let resolved = crate::wasmtime_adapter::wasi::open_program_file_for_write(
        &destination.namespace,
        &destination.absolute,
        destination.now,
        &destination.payer,
    )
    .await
    .map_err(&map_write_error)?;
    let mut next = crate::wasmtime_adapter::wasi::prepare_resolved_write(
        &resolved,
        WritePosition::At(0),
        total_len,
        destination.now,
        &destination.payer,
    )
    .await
    .map_err(&map_write_error)?;
    let mut written = 0usize;
    loop {
        let round_len = next.staged_len();
        let payload_start = written.min(precompiled_len);
        let payload_end = (written + round_len).min(precompiled_len);
        let payload_len = payload_end - payload_start;
        let filled = if payload_len > 0 {
            let mut next_slot = Some(next);
            in_guest_turn(
                store.guest_turns(),
                memory.read(
                    GuestAddress::wasm32(precompiled_ptr).offset(payload_start as u64),
                    payload_len,
                    |payload_chunk| {
                        next_slot
                            .take()
                            .expect("prepared write round filled once")
                            .fill(|offset, dst| {
                                copy_payload_and_trailer(
                                    offset,
                                    dst,
                                    payload_start,
                                    payload_chunk,
                                    precompiled_len,
                                    &trailer,
                                );
                            })
                    },
                ),
            )
            .await?
        } else {
            next.fill(|offset, dst| {
                let start = offset - precompiled_len;
                dst.copy_from_slice(&trailer[start..start + dst.len()]);
            })
        };
        match filled
            .submit()
            .await
            .map_err(|error| map_write_error(crate::wasmtime_adapter::wasi::fs_error_code(error)))?
        {
            WriteProgress::Done(landed) => {
                if landed.len != total_len {
                    return Err(map_aot_fs_error(fs_types::ErrorCode::InsufficientSpace));
                }
                break;
            }
            WriteProgress::More(more) => {
                written += round_len;
                next = more;
            }
        }
    }
    if profile {
        store.context.write_serial.emit_fmt(format_args!(
            "aot-write us={} bytes={}\n",
            monotonic_nanos(&store.context.cpu).saturating_sub(write_started_ns) / 1_000,
            total_len,
        ));
    }
    Ok(total_len)
}

pub(super) async fn accept_compiler_response<CpuImpl, Net, StorageImpl>(
    store: &CompilerCoreStore<CpuImpl, Net, StorageImpl>,
    allocations: &mut CompilerAllocations,
    response_ptr: u32,
    profile: bool,
    sink: CompileOutputSink<StorageImpl>,
    signing_key: &crate::CwasmSigningKey,
    phases: &mut CompilerPhaseTimestamps,
) -> Result<CompileOutput, ProgramExecError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let memory = Preview1AsyncMemory::of_shared(store.memory());
    let header = in_guest_turn(
        store.guest_turns(),
        memory.read_array::<{ CompilerResponseHeader::SIZE }>(GuestAddress::wasm32(response_ptr)),
    )
    .await?;
    let header = CompilerResponseHeader::from_bytes(&header);
    if header.abi_version != HELIOS_COMPILER_ABI_VERSION {
        return Err(ProgramExecError {
            kind: ProgramExecErrorKind::InvalidBinary,
            detail: ProgramExecErrorDetail::CompilerAbiMismatch,
        });
    }
    allocations.adopt(
        response_ptr,
        CompilerResponseHeader::SIZE,
        CompilerResponseHeader::ALIGN,
    )?;
    allocations.adopt(header.diagnostic_ptr, header.diagnostic_len as usize, 1)?;
    allocations.adopt(header.precompiled_ptr, header.precompiled_len as usize, 1)?;
    let (status, _output_kind) = decode_compiler_response(&header)?;
    let diagnostic = in_guest_turn(
        store.guest_turns(),
        memory.read_bytes(
            GuestAddress::wasm32(header.diagnostic_ptr),
            header.diagnostic_len as usize,
        ),
    )
    .await?;
    if status != CompilerStatus::Ok {
        if !diagnostic.is_empty() {
            tracing::error!(
                diagnostic = %core::str::from_utf8(&diagnostic).unwrap_or("<non-utf8 compiler diagnostic>"),
                "compiler plugin rejected input"
            );
        }
        return Err(ProgramExecError {
            kind: ProgramExecErrorKind::InvalidBinary,
            detail: ProgramExecErrorDetail::CompilerRejectedInput,
        });
    }
    if !diagnostic.is_empty() {
        store.context.write_serial.emit(&diagnostic);
    }
    phases.diagnostic_done_ns = if profile {
        monotonic_nanos(&store.context.cpu)
    } else {
        0
    };
    let output = match sink {
        CompileOutputSink::ReturnPayload => {
            let payload = in_guest_turn(
                store.guest_turns(),
                memory.read_bytes(
                    GuestAddress::wasm32(header.precompiled_ptr),
                    header.precompiled_len as usize,
                ),
            )
            .await?;
            CompileOutput::Payload(payload)
        }
        CompileOutputSink::WriteSignedFile(destination) => {
            let bytes = write_signed_artifact_from_plugin_memory(
                store,
                &memory,
                PluginSlice {
                    ptr: header.precompiled_ptr,
                    len: header.precompiled_len as usize,
                },
                destination,
                signing_key,
                profile,
                phases,
            )
            .await?;
            CompileOutput::WrittenBytes(bytes)
        }
    };
    phases.response_done_ns = if profile {
        monotonic_nanos(&store.context.cpu)
    } else {
        0
    };
    Ok(output)
}

pub(super) fn compiler_fd_fdstat_get<CpuImpl, Net, StorageImpl>(
    caller: Caller<'_, CompilerCoreStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    stat: u32,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let descriptor = match fd {
        1 if caller.data().preview1_descriptors.stdout_open => Preview1Descriptor::<Net>::Stdout,
        2 if caller.data().preview1_descriptors.stderr_open => Preview1Descriptor::<Net>::Stderr,
        _ => return p1::errno::BADF,
    };
    let bytes = p1_fdstat_bytes(2, 0, p1_descriptor_rights(&descriptor));
    write_shared_memory(caller.data().memory(), GuestAddress::wasm32(stat), &bytes)
        .map_or(p1::errno::FAULT, |_| p1::errno::SUCCESS)
}

pub(super) fn fd_write<CpuImpl, Net, StorageImpl>(
    caller: Caller<'_, CompilerCoreStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    iovs: u32,
    iovs_len: u32,
    nwritten: u32,
) -> i32
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    if !caller.data().preview1_descriptors.can_write(fd) {
        return p1::errno::BADF;
    }
    let memory = caller.data().memory();
    let iovs = GuestAddress::wasm32(iovs);
    let mut written = 0u32;
    for index in 0..iovs_len {
        let iov = iovs.offset(u64::from(index) * 8);
        let Ok(ptr) = try_read_u32(memory, iov) else {
            return p1::errno::FAULT;
        };
        let Ok(len) = try_read_u32(memory, iov.offset(4)) else {
            return p1::errno::FAULT;
        };
        let Ok(bytes) = read_shared_memory(memory, GuestAddress::wasm32(ptr), len) else {
            return p1::errno::FAULT;
        };
        // The compiler plugin is bootfs-provisioned and trusted (§3.3),
        // and this host function is synchronous, so its diagnostics go
        // to the console the way a kernel record does: handed to the
        // port's owner rather than waiting for the port.
        caller.data().context.write_serial.emit(&bytes);
        written = written.saturating_add(len);
    }
    write_u32(memory, GuestAddress::wasm32(nwritten), written)
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc as SharedArc;
    use alloc::task::Wake;
    use core::pin::pin;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{Context, Waker};

    use futures_lite::future::block_on;

    use super::*;

    /// A waker that counts the wakes it receives.
    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl WakeCount {
        fn count(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl Wake for WakeCount {
        fn wake(self: SharedArc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn response_with(status: u32, output_kind: u32) -> CompilerResponseHeader {
        CompilerResponseHeader {
            abi_version: HELIOS_COMPILER_ABI_VERSION,
            status,
            output_kind,
            precompiled_ptr: 0,
            precompiled_len: 0,
            diagnostic_ptr: 0,
            diagnostic_len: 0,
        }
    }

    #[test]
    fn a_known_status_and_output_kind_decode() {
        assert_eq!(
            decode_compiler_response(&response_with(
                CompilerStatus::CompileFailed.into(),
                OutputKind::Component.into()
            )),
            Ok((CompilerStatus::CompileFailed, OutputKind::Component))
        );
    }

    #[test]
    fn an_unknown_status_is_the_typed_abi_error() {
        assert_eq!(
            decode_compiler_response(&response_with(7, 0)),
            Err(ProgramExecError {
                kind: ProgramExecErrorKind::InvalidBinary,
                detail: ProgramExecErrorDetail::CompilerAbiValueInvalid(UnknownDiscriminant {
                    field: "status",
                    value: 7
                }),
            })
        );
    }

    #[test]
    fn an_unknown_output_kind_is_the_typed_abi_error() {
        assert_eq!(
            decode_compiler_response(&response_with(0, u32::MAX)),
            Err(ProgramExecError {
                kind: ProgramExecErrorKind::InvalidBinary,
                detail: ProgramExecErrorDetail::CompilerAbiValueInvalid(UnknownDiscriminant {
                    field: "output_kind",
                    value: u32::MAX
                }),
            })
        );
    }

    #[test]
    fn a_count_off_its_starting_level_is_the_typed_abi_error() {
        assert_eq!(ensure_compiler_buffers_returned(4096, 4096), Ok(()));
        assert_eq!(
            ensure_compiler_buffers_returned(0, 28),
            Err(ProgramExecError {
                kind: ProgramExecErrorKind::Internal,
                detail: ProgramExecErrorDetail::CompilerBuffersOutstanding,
            })
        );
    }

    /// A zero-length buffer is pointer 0 and was never allocated, so it is
    /// never owned and never freed.
    #[test]
    fn a_zero_length_response_buffer_is_not_adopted() {
        let mut allocations = CompilerAllocations::new();
        allocations.adopt(0, 0, 1).unwrap();
        allocations.adopt(64, 10, 1).unwrap();
        assert_eq!(
            allocations.buffers.as_slice(),
            &[PluginBuffer {
                ptr: 64,
                len: 10,
                align: 1
            }]
        );
    }

    #[test]
    fn compiler_abi_lengths_reject_overflow_without_truncating() {
        assert_eq!(compiler_abi_i32(i32::MAX as usize), Ok(i32::MAX));
        assert_eq!(
            compiler_abi_i32(i32::MAX as usize + 1),
            Err(ProgramExecError {
                kind: ProgramExecErrorKind::InvalidBinary,
                detail: ProgramExecErrorDetail::CompilerAbiLengthOverflow,
            })
        );
        assert_eq!(
            compiler_abi_u32(u32::MAX as usize + 1),
            Err(ProgramExecError {
                kind: ProgramExecErrorKind::InvalidBinary,
                detail: ProgramExecErrorDetail::CompilerAbiLengthOverflow,
            })
        );
        assert_eq!(
            check_compiler_input_limit(1025, 1024),
            Err(ProgramExecError {
                kind: ProgramExecErrorKind::InvalidBinary,
                detail: ProgramExecErrorDetail::CompilerInputTooLarge {
                    bytes: 1025,
                    limit: 1024,
                },
            })
        );
        assert_eq!(check_compiler_input_limit(1024, 1024), Ok(()));
    }

    #[test]
    fn copy_payload_and_trailer_streams_across_arbitrary_round_boundaries() {
        let payload: Vec<u8> = (0..137u8).collect();
        let trailer: Vec<u8> = (200..243u8).collect();
        let total = payload.len() + trailer.len();
        let mut expected = payload.clone();
        expected.extend_from_slice(&trailer);

        // Test multiple chunk sizes including ones that straddle the payload/trailer seam.
        for chunk_size in [1usize, 7, 16, 64, 137, 200] {
            let mut out = vec![0u8; total];
            let mut written = 0;
            while written < total {
                let round_len = chunk_size.min(total - written);
                let payload_start = written.min(payload.len());
                let payload_end = (written + round_len).min(payload.len());
                let payload_chunk = &payload[payload_start..payload_end];
                copy_payload_and_trailer(
                    written,
                    &mut out[written..written + round_len],
                    payload_start,
                    payload_chunk,
                    payload.len(),
                    &trailer,
                );
                written += round_len;
            }
            assert_eq!(out, expected, "chunk_size={chunk_size}");
        }
    }

    /// A compile that arrives while another holds the slot parks, and the
    /// release wakes exactly one waiter, the first, without either being
    /// polled in between.
    #[test]
    fn a_waiting_compile_is_woken_by_the_release() {
        let slot = SharedMemorySessionSlot::new();
        let first = block_on(slot.acquire());

        let second_wakes = SharedArc::new(WakeCount::default());
        let third_wakes = SharedArc::new(WakeCount::default());
        let second_waker = Waker::from(second_wakes.clone());
        let third_waker = Waker::from(third_wakes.clone());
        let mut second_context = Context::from_waker(&second_waker);
        let mut third_context = Context::from_waker(&third_waker);
        let mut second = pin!(slot.acquire());
        let mut third = pin!(slot.acquire());

        assert!(second.as_mut().poll(&mut second_context).is_pending());
        assert!(third.as_mut().poll(&mut third_context).is_pending());
        assert_eq!(second_wakes.count() + third_wakes.count(), 0);

        drop(first);

        assert_eq!(second_wakes.count(), 1, "the first waiter is woken");
        assert_eq!(third_wakes.count(), 0, "only one waiter is woken");
        assert!(second.as_mut().poll(&mut second_context).is_ready());
    }

    type FixtureStore = CompilerCoreStore<
        crate::test_support::TestCpu,
        crate::test_support::TestNetworkService,
        crate::test_support::UnsupportedStorage,
    >;

    /// A compile's context on the fixtures a kernel unit test carries, the
    /// engine its stores run on and the interrupt routes of that engine.
    struct CompileFixture {
        engine: wasmtime::Engine,
        interrupts: SharedArc<crate::wasmtime_adapter::preemption::GuestInterrupts>,
        registry: crate::InstanceRegistry,
        instance: crate::RegisteredInstance,
        context: CompilerCompileContext<
            crate::test_support::TestCpu,
            crate::test_support::TestNetworkService,
            crate::test_support::UnsupportedStorage,
        >,
    }

    impl CompileFixture {
        fn new() -> Self {
            use crate::test_support::TestCpu;
            use crate::wasmtime_adapter::component_host::service::test_store::DiscardPort;
            use crate::wasmtime_adapter::engine::build_component_engine_for_platform;
            use crate::wasmtime_adapter::preemption::GuestInterrupts;

            let cpu = TestCpu::with_entropy(0x5a);
            let engine = build_component_engine_for_platform(&cpu)
                .expect("the component engine builds on the test platform");
            let interrupts = SharedArc::new(GuestInterrupts::new(1, cpu.timebase()));
            let runtime_state: HostRuntimeState<
                TestCpu,
                crate::test_support::TestNetworkService,
                crate::test_support::UnsupportedStorage,
            > = crate::RuntimeState::new(
                cpu.timebase(),
                1,
                0,
                crate::BootPayload::for_tests(),
                GuestIsa::for_build_target(cpu.native_feature_probe()),
            );
            runtime_state.install_root_entropy(triomphe::Arc::new(
                crate::RootEntropy::from_platform(
                    &cpu,
                    None,
                    None,
                    crate::MachineGeneration::new(None),
                )
                .expect("the fixture CPU has an entropy source"),
            ));
            let executor = crate::Executor::new(
                helios_hal::watchdog::ProgressCounter::new(),
                crate::test_support::single_node_pool(1),
                helios_hal::cpu::ProcessorId::new(0),
            );
            let registry = crate::InstanceRegistry::new();
            let instance = registry.register("compiler-plugin", 0);
            let memory = SharedMemory::new(
                &engine,
                wasmtime::MemoryType::shared(1, 1).expect("1..=1 is a valid shared memory type"),
            )
            .expect("the engine enables shared memories");
            let shared = Arc::new(SharedMemoryCoreShared::new(
                memory,
                crate::EntropyPool::derive(runtime_state.root_entropy(), 0),
                interrupts.clone(),
                1,
            ));
            let context = CompilerCompileContext {
                cpu,
                spawner: executor.spawner(cpu),
                runtime_state,
                instance: instance.clone(),
                registry: registry.clone(),
                shared,
                affinity_plan: CoreAffinityPlan::single(helios_hal::cpu::ProcessorId::new(0)),
                write_serial: crate::DebugSerialWriter::of::<DiscardPort>(),
                _marker: core::marker::PhantomData,
            };
            Self {
                engine,
                interrupts,
                registry,
                instance,
                context,
            }
        }

        /// A store of the compile, registered and driven the way the
        /// compile's main store and each worker store are.
        fn open_store(
            &self,
        ) -> (
            wasmtime::Store<FixtureStore>,
            CompilerStoreDrive<crate::test_support::TestCpu>,
        ) {
            let mut store =
                wasmtime::Store::new(&self.engine, CompilerCoreStore::new(self.context.clone()));
            let drive = configure_compiler_core_store(&mut store);
            (store, drive)
        }
    }

    /// Every call into a compiler store is its processor's running store
    /// while it is polled, which is what lets a processor's timer tick
    /// interrupt it at the end of its slice; the store leaves the slot when
    /// the poll returns.
    #[test]
    fn a_compiler_call_is_its_processors_running_store() {
        let fixture = CompileFixture::new();
        let (mut store, drive) = fixture.open_store();
        let processor = helios_hal::cpu::current_processor();
        let running_during_call = SharedArc::new(core::sync::atomic::AtomicBool::new(false));
        let observed = running_during_call.clone();
        let interrupts = fixture.interrupts.clone();
        let probe = wasmtime::Func::wrap(&mut store, move || {
            observed.store(interrupts.is_running_a_store(processor), Ordering::SeqCst);
        })
        .typed::<(), ()>(&store)
        .expect("the probe is a () -> () function");

        assert!(!fixture.interrupts.is_running_a_store(processor));
        block_on(drive.call(&mut store, &probe, ())).expect("the probe returns");

        assert!(
            running_during_call.load(Ordering::SeqCst),
            "the store is the processor's running store during its call"
        );
        assert!(
            !fixture.interrupts.is_running_a_store(processor),
            "and no longer once the call returns"
        );
    }

    /// The end of a time slice makes a compiler store's guest yield, and a
    /// kill traps it with the reason it was condemned for: the decision the
    /// component store and the preview1 store make.
    #[test]
    fn a_compiler_interruption_without_a_kill_yields() {
        let fixture = CompileFixture::new();
        let (store, _drive) = fixture.open_store();
        assert!(matches!(
            store.data().on_interrupt(),
            Ok(wasmtime::InterruptAction::Yield)
        ));

        for reason in [
            crate::KillReason::OutOfMemory,
            crate::KillReason::SupervisorRestart,
            crate::KillReason::Operator,
            crate::KillReason::RequesterGone,
            crate::KillReason::StoreFailed,
        ] {
            let fixture = CompileFixture::new();
            let (store, _drive) = fixture.open_store();
            fixture.registry.request_kill(
                fixture.instance.id(),
                reason,
                0,
                &crate::UserResidency::default(),
            );
            let Err(error) = store.data().on_interrupt() else {
                panic!("a condemned instance's guest traps at its next check");
            };
            assert_eq!(
                error.downcast_ref::<crate::InstanceKilled>(),
                Some(&crate::InstanceKilled { reason })
            );
        }
    }

    /// Records that the value holding it was dropped.
    struct DropFlag(SharedArc<core::sync::atomic::AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// A worker parked where the plugin's wait parks it, in an async host
    /// future that nothing resolves, is ended by a kill of the compile's
    /// instance: its turn wakes, drops the call, and the call reports the
    /// kill. Without the drive the call stays pending for ever.
    #[test]
    fn a_kill_ends_a_parked_compiler_worker() {
        let fixture = CompileFixture::new();
        // A worker is a store of its own over the compile's instance.
        let (mut worker, drive) = fixture.open_store();
        let dropped = SharedArc::new(core::sync::atomic::AtomicBool::new(false));
        let flag = dropped.clone();
        let parked = wasmtime::Func::wrap_async(
            &mut worker,
            move |_: wasmtime::Caller<'_, FixtureStore>, (): ()| {
                let guard = DropFlag(flag.clone());
                Box::new(async move {
                    let _guard = guard;
                    core::future::pending::<()>().await;
                })
            },
        )
        .typed::<(), ()>(&worker)
        .expect("the parked wait is a () -> () function");
        let wakes = SharedArc::new(WakeCount::default());
        let waker = Waker::from(wakes.clone());
        let mut context = Context::from_waker(&waker);
        let mut call = pin!(drive.call(&mut worker, &parked, ()));

        assert!(call.as_mut().poll(&mut context).is_pending());
        assert!(!dropped.load(Ordering::SeqCst));

        assert_eq!(
            fixture.registry.request_kill(
                fixture.instance.id(),
                crate::KillReason::Operator,
                0,
                &crate::UserResidency::default()
            ),
            crate::KillOutcome::Requested
        );
        assert_eq!(wakes.count(), 1, "the condemnation wakes the parked turn");
        match call.as_mut().poll(&mut context) {
            Poll::Ready(Err(error)) => assert_eq!(
                error.downcast_ref::<crate::InstanceKilled>(),
                Some(&crate::InstanceKilled {
                    reason: crate::KillReason::Operator
                })
            ),
            other => panic!("the kill ends the parked worker's call, got {other:?}"),
        }
        assert!(
            dropped.load(Ordering::SeqCst),
            "the worker unwound past its parked host future"
        );
    }

    /// A function of `store` that traps: a host function that returns an
    /// error, as the plugin's abort does.
    fn trapping(
        store: &mut wasmtime::Store<FixtureStore>,
        message: &'static str,
    ) -> wasmtime::TypedFunc<(), ()> {
        wasmtime::Func::wrap(&mut *store, move || -> wasmtime::Result<()> {
            Err(wasmtime::Error::msg(message))
        })
        .typed::<(), ()>(&*store)
        .expect("the trap is a () -> () function")
    }

    /// A function of `store` that parks where the plugin's wait parks it, in
    /// an async host future that nothing resolves.
    fn parked(store: &mut wasmtime::Store<FixtureStore>) -> wasmtime::TypedFunc<(), ()> {
        wasmtime::Func::wrap_async(
            &mut *store,
            move |_: wasmtime::Caller<'_, FixtureStore>, (): ()| {
                Box::new(core::future::pending::<()>())
            },
        )
        .typed::<(), ()>(&*store)
        .expect("the parked wait is a () -> () function")
    }

    fn report(trap: Option<ProgramExecError>) -> SharedMemoryThreadReport {
        SharedMemoryThreadReport {
            trap,
            thread_id: 1,
            processor: 0,
            spawned_ns: 0,
            started_ns: 0,
            instantiated_ns: 0,
            finished_ns: 0,
        }
    }

    /// The runtime's message an error carries.
    fn message_of(error: &ProgramExecError) -> &str {
        match &error.detail {
            ProgramExecErrorDetail::RuntimeFailure(message) => message.as_str(),
            other => panic!("expected the runtime's own failure, got {other:?}"),
        }
    }

    /// A trap on the compile's main thread while a worker is parked
    /// condemns the compile: the worker's call ends with the kill instead of
    /// being joined for ever, and the compile's error is the trap's.
    #[test]
    fn a_trap_on_main_ends_a_parked_worker_and_is_the_compiles_error() {
        let fixture = CompileFixture::new();
        let (mut main, main_drive) = fixture.open_store();
        let (mut worker, worker_drive) = fixture.open_store();
        let trap = trapping(&mut main, "main trapped");
        let wait = parked(&mut worker);
        let mut cx = Context::from_waker(Waker::noop());
        let mut worker_call = pin!(worker_drive.call(&mut worker, &wait, ()));
        assert!(worker_call.as_mut().poll(&mut cx).is_pending());

        let main_error =
            block_on(main_drive.call(&mut main, &trap, ())).expect_err("the main thread traps");
        let result = fixture
            .context
            .end_main_part::<()>(Err(map_program_runtime_error(main_error)));

        assert_eq!(
            fixture.instance.pending_kill(),
            Some(crate::KillReason::StoreFailed),
            "main's failure condemns the compile before its workers are joined"
        );
        match worker_call.as_mut().poll(&mut cx) {
            Poll::Ready(Err(error)) => {
                assert_eq!(
                    error.downcast_ref::<crate::InstanceKilled>(),
                    Some(&crate::InstanceKilled {
                        reason: crate::KillReason::StoreFailed
                    })
                );
                assert!(
                    fixture.context.condemn_for_store_end(error).is_none(),
                    "a worker ended by the condemnation reports no trap"
                );
            }
            other => panic!("the condemnation ends the parked worker, got {other:?}"),
        }
        let mut reports = [report(None)];
        let Err(error) = first_trap_wins(result, &mut reports) else {
            panic!("a compile whose main thread trapped fails");
        };
        assert!(
            message_of(&error).contains("main trapped"),
            "the requester gets main's trap, got {error}"
        );
    }

    /// A trap on a worker while main waits on it condemns the compile: main's
    /// call ends with the kill, and the error handed to the requester is the
    /// worker's trap, not the condemnation main ended with.
    #[test]
    fn a_trap_on_a_worker_ends_main_and_is_the_compiles_error() {
        let fixture = CompileFixture::new();
        let (mut main, main_drive) = fixture.open_store();
        let (mut worker, worker_drive) = fixture.open_store();
        let wait = parked(&mut main);
        let trap = trapping(&mut worker, "worker trapped");
        let mut cx = Context::from_waker(Waker::noop());
        let mut main_call = pin!(main_drive.call(&mut main, &wait, ()));
        assert!(main_call.as_mut().poll(&mut cx).is_pending());

        let worker_error =
            block_on(worker_drive.call(&mut worker, &trap, ())).expect_err("the worker traps");
        let worker_trap = fixture.context.condemn_for_store_end(worker_error);
        assert!(
            worker_trap.is_some(),
            "the trap that condemns the compile carries its error"
        );
        assert_eq!(
            fixture.instance.pending_kill(),
            Some(crate::KillReason::StoreFailed)
        );

        let Poll::Ready(Err(kill)) = main_call.as_mut().poll(&mut cx) else {
            panic!("the condemnation ends main's parked call");
        };
        let kill = map_program_runtime_error(kill);
        assert!(
            message_of(&kill).contains("terminated"),
            "main ended by the kill, got {kill}"
        );
        let result = fixture.context.end_main_part::<()>(Err(kill));
        let mut reports = [report(None), report(worker_trap)];
        let Err(error) = first_trap_wins(result, &mut reports) else {
            panic!("a compile whose worker trapped fails");
        };
        assert!(
            message_of(&error).contains("worker trapped"),
            "the requester gets the worker's trap, not the kill, got {error}"
        );
        assert!(!message_of(&error).contains("terminated"));
    }

    /// A store that ends by a kill does not condemn the compile again: the
    /// first condemnation's reason stands, and the end is no trap.
    #[test]
    fn a_store_that_ends_by_a_kill_does_not_condemn_with_the_trap_reason() {
        // A kill the registry has not recorded: only the error's type says it
        // is one, so the decision is the end's, not the registry's.
        let fixture = CompileFixture::new();
        let (mut worker, drive) = fixture.open_store();
        let killed = wasmtime::Func::wrap(&mut worker, || -> wasmtime::Result<()> {
            Err(wasmtime::Error::new(crate::InstanceKilled {
                reason: crate::KillReason::Operator,
            }))
        })
        .typed::<(), ()>(&worker)
        .expect("the kill is a () -> () function");
        let error = block_on(drive.call(&mut worker, &killed, ())).expect_err("the call ends");
        assert!(fixture.context.condemn_for_store_end(error).is_none());
        assert_eq!(
            fixture.instance.pending_kill(),
            None,
            "a store ended by a kill is not a trap and condemns nothing"
        );

        // A real kill, then a worker parked in the wait it ends.
        let fixture = CompileFixture::new();
        let (mut worker, drive) = fixture.open_store();
        let wait = parked(&mut worker);
        let mut cx = Context::from_waker(Waker::noop());
        let mut call = pin!(drive.call(&mut worker, &wait, ()));
        assert!(call.as_mut().poll(&mut cx).is_pending());
        fixture.registry.request_kill(
            fixture.instance.id(),
            crate::KillReason::Operator,
            0,
            &crate::UserResidency::default(),
        );
        let Poll::Ready(Err(error)) = call.as_mut().poll(&mut cx) else {
            panic!("the kill ends the parked worker");
        };
        assert!(fixture.context.condemn_for_store_end(error).is_none());
        assert_eq!(
            fixture.instance.pending_kill(),
            Some(crate::KillReason::Operator),
            "the first reason stands"
        );
    }

    /// A trap after another store condemned the compile is not the first
    /// trap: it reports no error, and the first condemnation's reason stands.
    #[test]
    fn only_the_first_trap_reports_its_error() {
        let fixture = CompileFixture::new();
        let (mut first, first_drive) = fixture.open_store();
        let (mut second, second_drive) = fixture.open_store();
        let first_trap = trapping(&mut first, "first trapped");
        let second_trap = trapping(&mut second, "second trapped");
        let first_error =
            block_on(first_drive.call(&mut first, &first_trap, ())).expect_err("traps");
        let second_error =
            block_on(second_drive.call(&mut second, &second_trap, ())).expect_err("traps");

        let first = fixture.context.condemn_for_store_end(first_error);
        let second = fixture.context.condemn_for_store_end(second_error);
        assert!(first.is_some());
        assert!(second.is_none());
        assert_eq!(
            fixture.instance.pending_kill(),
            Some(crate::KillReason::StoreFailed)
        );
    }
}
