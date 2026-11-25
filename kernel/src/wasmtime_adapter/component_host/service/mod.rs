use crate::ComponentHostNetwork;
mod argv;
pub(crate) use argv::ProgramArgv;
mod environment;
use environment::LaunchEnvironment;
mod shared_memory;
use shared_memory::*;
mod memory;
use memory::*;
mod descriptor;
use descriptor::*;
pub(crate) use descriptor::{Preview1SignalExit, WasixSignalState};
mod display;
pub(super) use display::add_display_to_linker;
pub use display::{DisplayHandle, SurfaceHandle};
mod gpu;
pub(super) use gpu::add_gpu_to_linker;
#[cfg(test)]
pub(crate) use gpu::test_store;
pub use gpu::{BlobHandle, CommandBufferHandle, ContextHandle, GpuHandle};
mod input;
pub use input::InputDeviceHandle;
pub(super) use input::add_input_to_linker;
mod surface;
pub(super) use surface::add_surface_to_linker;
pub use surface::{ClientImageSurfaceHandle, ClientSurfaceHandle};
mod audio;
pub use audio::PlaybackHandle;
pub(super) use audio::add_audio_to_linker;
mod hv;
pub(super) use hv::add_hv_to_linker;
mod processors;
pub(super) use processors::add_processors_to_linker;
mod btrfs;
pub(super) use btrfs::add_btrfs_to_linker;
mod shared_memory_plugin;
use shared_memory_plugin::*;
mod compiler;
pub(crate) use compiler::AotDestination;
#[cfg(test)]
pub(super) use compiler::map_aot_fs_error;
use compiler::*;
mod exec;
use exec::*;
mod component_plugin;
use component_plugin::*;
mod network_step;
use network_step::NetworkStep;
mod root_supervisor;
pub use root_supervisor::ProviderHandle;
use root_supervisor::{
    CompilerProviderRegistration, HttpProviderRegistration, SurfaceProviderRegistration,
};
pub(super) use root_supervisor::{add_root_supervisor_to_linker, root_supervisor_authority};
mod preview1;
use preview1::*;
#[cfg(test)]
mod path_lookup_tests;
mod wasix_proc;
use wasix_proc::*;
mod wasix_thread;
use wasix_thread::*;
mod wasix_net;
#[cfg(test)]
mod wasix_shared_state_tests;
#[cfg(test)]
mod wasix_signal_tests;
use wasix_net::*;
mod wasix_epoll;
use wasix_epoll::*;
#[cfg(feature = "linux")]
mod linux;
#[cfg(test)]
mod stdin_inheritance_tests;
#[cfg(feature = "linux")]
use linux::*;
#[cfg(test)]
mod boot_init_tests;
#[cfg(test)]
mod child_exit_tests;

use super::*;
use crate::DescriptorLimitSetting;
use crate::Settings;
use crate::isa::GuestIsa;
use crate::wasmtime_adapter::artifact_profile::{self, ArtifactProfileError};
use crate::wasmtime_adapter::code_map::{CodeMap, CodeRegistration};
use crate::wasmtime_adapter::config::AotCompileHint;
use crate::wasmtime_adapter::cwasm::{self, ArtifactTrustError, UntrustedCwasm};
use crate::wasmtime_adapter::preemption::{GuestInterrupts, StoreInterrupts};
use crate::wasmtime_adapter::{WasmtimeCompiledComponent, WasmtimeCompiledCoreModule};
use crate::wasmtime_adapter::{
    WasmtimePrecompiledKind,
    wasi::{
        self as wasi_fs, FsDescriptor, FsNodeKind, GUEST_IO_CHUNK_BYTES, WasiImportSet,
        bindings::filesystem::types as fs_types, preview1 as p1,
    },
};
use crate::{
    BootfsBytes, ComponentStdioRefusal, ProgramExecErrorDetail, RuntimeMessage, UnbindableStdio,
    machine_memory,
};
use crate::{FileContents, FsDescriptorFlags, MemoryFs, Namespace};
use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use bytes::Bytes;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::Ordering as AtomicOrdering;
use core::task::{Context, Poll};
use core::time::Duration;
use hashbrown::HashMap;
use helios_compiler_abi::{
    CompileHint as CompilerAbiHint, CompilerRequestHeader, CompilerResponseHeader,
    HELIOS_COMPILER_ABI_VERSION, HELIOS_COMPILER_ALLOC, HELIOS_COMPILER_COMPILE,
    HELIOS_COMPILER_FREE, HELIOS_COMPILER_INITIALIZE, HELIOS_COMPILER_OUTSTANDING_BYTES,
    HELIOS_COMPILER_PTHREAD_SELF_OFFSET,
};
use helios_hal::fs::WritePosition;
use helios_hal::measured_boot::MeasuredBoot;
use helios_hal::watchdog::Watchdog;
use helios_unix::OpenFile;
use helios_unix::{DescriptorLimit, GuestAddress};
use smallvec::SmallVec;
use thiserror::Error;
use wasmtime::component::{Component, InstancePre as ComponentInstancePre};
use wasmtime::{
    Caller, ExternType, InstancePre, Linker as CoreLinker, MemoryType, Module, SharedMemory, Val,
};

const RAYON_NUM_THREADS_ENV: &[u8] = b"RAYON_NUM_THREADS=";
const WASM_PAGE_SIZE: usize = 64 * 1024;
const PROGRAM_SHARED_MEMORY_MAX_PAGES: u32 = 8192;
const SHARED_MEMORY_POOL_FRACTION: usize = 16;
const WASIX_ASYNCIFY_DATA_SIZE: u32 = 8;
const WASIX_STACK_SNAPSHOT_SIZE: usize = 24;
const WASIX_THREAD_START_SIZE: usize = 64;
const WASIX_MODULE: &str = "wasix_32v1";
const WASIX_NULL_DEVICE_PATH: &str = "/dev/null";
const WASIX_IPPROTO_TCP_I32: i32 = 6;
const WASIX_IPPROTO_UDP_I32: i32 = 17;
const WASIX_STREAM_SECURITY_UNENCRYPTED: u8 = 1 << 0;
const WASIX_STREAM_SECURITY_ANY_ENCRYPTION: u8 = 1 << 1;
const WASIX_STREAM_SECURITY_CLASSIC_ENCRYPTION: u8 = 1 << 2;
const WASIX_STREAM_SECURITY_DOUBLE_ENCRYPTION: u8 = 1 << 3;
const DEFAULT_WASIX_EXEC_SEARCH_PATHS: &[&str] = &["/usr/local/bin", "/bin", "/usr/bin"];
type Preview1Iovs = SmallVec<[(u32, u32); 8]>;
type CompilerThreadTasks = SmallVec<[crate::JoinHandle<SharedMemoryThreadReport>; 8]>;
type CompilerThreadReports = SmallVec<[SharedMemoryThreadReport; 8]>;
type CompilerPluginHandle<CpuImpl, Net, StorageImpl> =
    Arc<CompilerPluginRuntime<CpuImpl, Net, StorageImpl>>;

/// What one compile session takes from its requester: the registered compiler
/// provider's metadata and artifact, the input, how to compile it, and where
/// its output lands.
struct CompileJob<StorageImpl: crate::Storage> {
    compiler_generation: u64,
    compiler_name: String,
    compiler_path: String,
    compiler_payload: Bytes,
    compiler_oom_policy: crate::OomPolicy,
    compiler_parent_instance_id: Option<crate::InstanceId>,
    wasm: Bytes,
    hint: AotCompileHint,
    profile: bool,
    sink: CompileOutputSink<StorageImpl>,
}

/// How a compile's body ended, with the phase timestamps and live worker count.
struct CompileEnd {
    result: Result<(CompileOutput, CompilerThreadReports), ProgramExecError>,
    worker_threads: u32,
    phases: CompilerPhaseTimestamps,
}

/// What [`UserProgramService::aot_to_file`] produced.
pub(crate) struct AotWritten {
    /// Total signed artifact bytes written to the destination file.
    pub(crate) bytes: usize,
    /// The live worker count the compiler plugin was told to compile with,
    /// reported so a caller comparing this compile with another can hold the
    /// count fixed.
    pub(crate) worker_threads: u32,
}

#[derive(Clone, Copy, Default)]
struct CompilerPhaseTimestamps {
    processor: u16,
    entered_ns: u64,
    slot_acquired_ns: u64,
    plugin_ready_ns: u64,
    instantiated_ns: u64,
    input_done_ns: u64,
    compile_started_ns: u64,
    compile_returned_ns: u64,
    diagnostic_done_ns: u64,
    response_done_ns: u64,
    tasks_joined_ns: u64,
    signed_ns: u64,
    plugin_cached: bool,
}

const WASIX_PROC_SPAWN_FD_OP_SIZE: u32 = 56;
const WASIX_PROC_SPAWN_FD_OP_CMD_OFFSET: u32 = 0;
const WASIX_PROC_SPAWN_FD_OP_FD_OFFSET: u32 = 4;
const WASIX_PROC_SPAWN_FD_OP_SRC_FD_OFFSET: u32 = 8;
const WASIX_PROC_SPAWN_FD_OP_PATH_OFFSET: u32 = 12;
const WASIX_PROC_SPAWN_FD_OP_PATH_LEN_OFFSET: u32 = 16;
const WASIX_PROC_SPAWN_FD_OP_DIRFLAGS_OFFSET: u32 = 20;
const WASIX_PROC_SPAWN_FD_OP_OFLAGS_OFFSET: u32 = 24;
const WASIX_PROC_SPAWN_FD_OP_RIGHTS_BASE_OFFSET: u32 = 32;
const WASIX_PROC_SPAWN_FD_OP_FDFLAGS_OFFSET: u32 = 48;
const WASIX_PROC_SPAWN_FD_OP_FDFLAGSEXT_OFFSET: u32 = 50;
const WASIX_PROC_SPAWN_FD_OP_CLOSE: u8 = 0;
const WASIX_PROC_SPAWN_FD_OP_DUP2: u8 = 1;
const WASIX_PROC_SPAWN_FD_OP_OPEN: u8 = 2;
const WASIX_PROC_SPAWN_FD_OP_CHDIR: u8 = 3;
const WASIX_PROC_SPAWN_FD_OP_FCHDIR: u8 = 4;
const WASIX_SIGNAL_DISPOSITION_SIZE: u32 = 2;
const WASIX_SIGNAL_DISPOSITION_SIGNAL_OFFSET: u32 = 0;
const WASIX_SIGNAL_DISPOSITION_ACTION_OFFSET: u32 = 1;
const WASIX_SIGNAL_DISPOSITION_DEFAULT: u8 = 0;
const WASIX_SIGNAL_DISPOSITION_IGNORE: u8 = 1;

fn system_component_profile_stack(component_name: &str) -> String {
    let mut stack = String::with_capacity(
        "kernel;system-component;".len() + component_name.len() + ";poll".len(),
    );
    stack.push_str("kernel;system-component;");
    stack.push_str(component_name);
    stack.push_str(";poll");
    stack
}

fn kernel_processor_profile_stack(processor: u16) -> String {
    let mut stack = String::from("kernel;executor;processor-");
    write!(stack, "{processor}").expect("profile stack formatting should not fail");
    stack
}

#[derive(Clone)]
pub struct UserProgramService<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    inner: Arc<UserProgramServiceInner<CpuImpl, Net, StorageImpl>>,
}

/// The program a launch runs and the credentials it runs under.
///
/// Distinct from [`ProgramExecContext`], which is the host the program
/// runs *in*, and from [`ChildStdio`], which is how the caller talks to
/// it once it is running.
#[cfg(feature = "linux")]
pub(super) struct LinuxContainerLaunch<StorageImpl: crate::Storage> {
    pub(super) container: Arc<crate::LinuxContainer<StorageImpl>>,
    pub(super) credentials: Option<helios_linux::syscall::Credentials>,
}

pub(super) struct ProgramLaunch<Net: ComponentHostNetwork, StorageImpl: crate::Storage> {
    argv: ProgramArgv,
    env: LaunchEnvironment,
    authority: ProcessAuthority,
    /// Pre-registered child instance when the host launch path needed the
    /// child's [`crate::InstanceId`] upfront to resolve `subtree(none)` grants.
    launched_instance: Option<crate::RegisteredInstance>,
    /// IPC capability endpoints moved into the child at launch.
    ipc_grants: crate::IpcEndpointGrants,
    /// Default Linux root image inherited by the child instance.
    default_linux_image: Option<crate::DefaultLinuxImage<StorageImpl>>,
    /// Pre-bound listening sockets handed off to the child (`fd = 3+` for
    /// Linux/WASIX processes, or `take-inherited-sockets` for components).
    inherited_sockets: crate::InheritedSockets,
    /// Explicit initial working directory override for the child process.
    cwd: Option<String>,
    /// The namespace the program runs in: the launcher's own tree when it
    /// shares it, or a tree descending from the launcher's. `None` for a
    /// program the kernel launches, which runs in a tree descending from
    /// the root namespace.
    filesystem: Option<Namespace<StorageImpl>>,
    /// Where the process's preview1 descriptors come from. Only core
    /// modules have a descriptor table; a component ignores one.
    descriptors: DescriptorOrigin<Net>,
    signal_dispositions: Vec<WasixSignalDisposition>,
    /// Explicit Linux container for launches started through a container
    /// handle. Direct Linux ELF launches wrap themselves in an ephemeral
    /// container bounded by `authority`.
    #[cfg(feature = "linux")]
    container: Option<LinuxContainerLaunch<StorageImpl>>,
    /// OOM protection tier assigned to the launched instance.
    oom_policy: crate::OomPolicy,
    /// The launch's phase timeline: [`phases::Timeline::disabled`]
    /// when the launch-phase target is off or the launcher is not a
    /// launch call (plugin loads record nothing).
    timeline: phases::Timeline,
}

impl<Net: ComponentHostNetwork, StorageImpl: crate::Storage> ProgramLaunch<Net, StorageImpl> {
    /// A launch that inherits nothing: no descriptors, no signal
    /// dispositions. `env` is the caller's environment; the kernel owns
    /// `HELIOS_PROCESS_ID` and replaces any entry for it (see
    /// [`LaunchEnvironment`]).
    pub(super) fn new(
        argv: ProgramArgv,
        env: Vec<(String, String)>,
        authority: ProcessAuthority,
        filesystem: Option<Namespace<StorageImpl>>,
    ) -> Self {
        Self {
            argv,
            env: LaunchEnvironment::from_guest(env),
            authority,
            launched_instance: None,
            ipc_grants: crate::IpcEndpointGrants::new(),
            default_linux_image: None,
            inherited_sockets: crate::InheritedSockets::new(),
            cwd: None,
            filesystem,
            descriptors: DescriptorOrigin::Fresh,
            signal_dispositions: Vec::new(),
            #[cfg(feature = "linux")]
            container: None,
            oom_policy: crate::OomPolicy::UserProgram,
            timeline: phases::Timeline::disabled(),
        }
    }

    #[cfg(feature = "linux")]
    pub(super) fn in_container(
        argv: ProgramArgv,
        env: Vec<(String, String)>,
        container: Arc<crate::LinuxContainer<StorageImpl>>,
        credentials: Option<helios_linux::syscall::Credentials>,
    ) -> Self {
        let authority = container.authority().clone();
        Self {
            argv,
            env: LaunchEnvironment::from_guest(env),
            authority,
            launched_instance: None,
            ipc_grants: crate::IpcEndpointGrants::new(),
            default_linux_image: None,
            inherited_sockets: crate::InheritedSockets::new(),
            cwd: None,
            filesystem: None,
            descriptors: DescriptorOrigin::Fresh,
            signal_dispositions: Vec::new(),
            container: Some(LinuxContainerLaunch {
                container,
                credentials,
            }),
            oom_policy: crate::OomPolicy::UserProgram,
            timeline: phases::Timeline::disabled(),
        }
    }

    pub(super) fn with_oom_policy(mut self, oom_policy: crate::OomPolicy) -> Self {
        self.oom_policy = oom_policy;
        self
    }

    pub(super) fn with_launched_instance(
        mut self,
        launched_instance: crate::RegisteredInstance,
    ) -> Self {
        self.launched_instance = Some(launched_instance);
        self
    }

    pub(super) fn with_ipc_grants(mut self, ipc_grants: crate::IpcEndpointGrants) -> Self {
        self.ipc_grants = ipc_grants;
        self
    }

    pub(super) fn with_default_linux_image(
        mut self,
        image: Option<crate::DefaultLinuxImage<StorageImpl>>,
    ) -> Self {
        self.default_linux_image = image;
        self
    }

    pub(super) fn with_inherited_sockets(mut self, sockets: crate::InheritedSockets) -> Self {
        self.inherited_sockets = sockets;
        self
    }

    pub(super) fn with_cwd(mut self, cwd: Option<String>) -> Self {
        self.cwd = cwd;
        self
    }

    /// The timeline this launch's phases record into. The handle's
    /// `task_emits` flag decides whether the run task emits the line —
    /// set by [`phases::Timeline::for_task`] for launches whose line is
    /// the run task's to write.
    pub(super) fn with_timeline(mut self, timeline: phases::Timeline) -> Self {
        self.timeline = timeline;
        self
    }
}

/// The ends of a child's standard streams that stay with the parent.
pub(super) struct ChildStdio {
    pub(super) stdin: Option<crate::ByteWriter>,
    pub(super) stdout: Option<crate::ByteReader>,
    pub(super) stderr: Option<crate::ByteReader>,
}

#[derive(Clone)]
pub(crate) struct ProgramExecContext<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    cpu: CpuImpl,
    timer: crate::Timer<CpuImpl>,
    spawner: crate::Spawner<CpuImpl>,
    runtime_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
    instance_registry: crate::InstanceRegistry,
    parent_instance_id: Option<crate::InstanceId>,
    read_serial: crate::SerialReader,
    write_serial: crate::DebugSerialWriter,
}

impl<CpuImpl, Net, StorageImpl> ProgramExecContext<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    pub(crate) fn spawner(&self) -> crate::Spawner<CpuImpl> {
        self.spawner.clone()
    }

    pub(crate) fn parent_instance_id(&self) -> Option<crate::InstanceId> {
        self.parent_instance_id
    }

    pub(crate) fn instance_registry(&self) -> &crate::InstanceRegistry {
        &self.instance_registry
    }

    pub(crate) fn now_uptime_nanos(&self) -> u64 {
        self.runtime_state.uptime_nanos(self.cpu.now().ticks())
    }
}

struct UserProgramServiceInner<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    runtime: crate::wasmtime_adapter::WasmtimeComponentRuntime<CpuImpl>,
    engine: crate::wasmtime_adapter::WasmtimeEngine,
    preview1_core_linker: CoreLinker<Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    shared_memory_pool: Arc<Mutex<SharedMemoryPool>>,
    component_cache: Mutex<ComponentCache<ProgramComponent>>,
    component_instance_pre_cache:
        Mutex<ComponentCache<ComponentInstancePre<StoreData<CpuImpl, Net, StorageImpl>>>>,
    core_module_cache: Mutex<ComponentCache<WasmtimeCompiledCoreModule>>,
    // Release AArch64/HVF quickjs-loop evidence: caching the Preview1 core
    // InstancePre moved the median from 53 ms to 50-51 ms. Cache only modules
    // whose imports are independent of per-process shared-memory binding.
    core_module_instance_pre_cache: CoreModuleInstancePreCache<CpuImpl, Net, StorageImpl>,
    /// Monotonic generation counter for root-supervisor provider registrations.
    next_provider_generation: core::sync::atomic::AtomicU64,
    /// Active singleton `surface` (compositor) provider installed by the root supervisor.
    surface_provider: Mutex<Option<SurfaceProviderRegistration>>,
    /// Active per-processor `wasi:http/client` provider installed by the root supervisor.
    http_provider: Mutex<Option<Arc<HttpProviderRegistration<CpuImpl, Net, StorageImpl>>>>,
    /// Active AOT `compiler` provider installed by the root supervisor.
    compiler_registration: Mutex<Option<CompilerProviderRegistration>>,
    /// The key the compiler plugin's output is signed with, and the only
    /// key a written `cwasm` verifies against. Settled at bring-up,
    /// before this service exists, and never replaced.
    cwasm_signing_key: crate::CwasmSigningKey,
    /// The level the in-kernel compiler emits, selected once at install.
    guest_isa: GuestIsa,
    /// Lazily-built compiler kernel-plugin runtime. The plugin's
    /// `wasmtime::Module`, `InstancePre`, and 512 MiB `SharedMemory` are
    /// allocated on first compile and reused for subsequent calls of the
    /// same provider generation.
    compiler_plugin: Mutex<Option<Arc<CompilerPluginRuntime<CpuImpl, Net, StorageImpl>>>>,
    /// Serialises compile calls. The cached `SharedMemory` is the
    /// plugin's only scratch surface; concurrent calls would race on
    /// the bump allocator and corrupt each other's request/response
    /// buffers. The slot is held only on the kernel side; the rayon
    /// worker pool inside the plugin still parallelises a single
    /// compile across all cores.
    compile_slot: SharedMemorySessionSlot,
    /// Every wasm image this service loaded, by address, for the
    /// instruction sampler to name.
    code_map: CodeMap,
    clock_cpu: CpuImpl,
    plugin_read_serial: crate::SerialReader,
    plugin_write_serial: crate::DebugSerialWriter,
    #[cfg(feature = "linux")]
    next_container_id: core::sync::atomic::AtomicU64,
    #[cfg(feature = "linux")]
    containers: Mutex<
        alloc::collections::BTreeMap<crate::ContainerId, Arc<crate::LinuxContainer<StorageImpl>>>,
    >,
    #[cfg(feature = "linux")]
    retired_containers: Arc<Mutex<Vec<NonZeroU64>>>,
    _marker: core::marker::PhantomData<fn() -> StorageImpl>,
}

/// A program component as the cache holds it: the compiled artifact and
/// the entry that names its code to the instruction sampler while it lives.
struct ProgramComponent {
    compiled: WasmtimeCompiledComponent,
    _code: CodeRegistration,
}

struct ProgramSpawnRequest<Net: ComponentHostNetwork, StorageImpl: crate::Storage> {
    argv: ProgramArgv,
    env: Vec<(String, String)>,
    authority: ProcessAuthority,
    ipc_grants: crate::IpcEndpointGrants,
    default_linux_image: Option<crate::DefaultLinuxImage<StorageImpl>>,
    inherited_sockets: crate::InheritedSockets,
    cwd: Option<String>,
    filesystem: Option<Namespace<StorageImpl>>,
    descriptors: DescriptorOrigin<Net>,
    signal_state: WasixSignalState,
    signal_dispositions: Vec<WasixSignalDisposition>,
    #[cfg(feature = "linux")]
    container: Option<LinuxContainerLaunch<StorageImpl>>,
}

/// Maximum `#!` interpreter indirections (`fs/binfmt_script.c` recursion cap).
#[cfg(feature = "linux")]
pub(super) const MAX_SHEBANG_DEPTH: usize = 4;

/// Parses a `#!` script header (`fs/binfmt_script.c`): returns
/// `(interpreter, optional_argument)` from the first line (up to 256 bytes).
#[cfg(feature = "linux")]
pub(super) fn parse_shebang(bytes: &[u8]) -> Option<(String, Option<String>)> {
    if !bytes.starts_with(b"#!") {
        return None;
    }
    let line = bytes[2..].split(|&b| b == b'\n').next().unwrap_or(&[]);
    let line = &line[..line.len().min(256)];
    let trimmed = core::str::from_utf8(line)
        .ok()?
        .trim_matches([' ', '\t', '\r']);
    if trimmed.is_empty() {
        return None;
    }
    let mut split = trimmed.splitn(2, [' ', '\t']);
    let interp = split.next()?.to_owned();
    let arg = split
        .next()
        .map(|s| s.trim_matches([' ', '\t']))
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);
    Some((interp, arg))
}

/// Merges inherited default-image base environment variables underneath explicit
/// request environment variables (explicit entries override matching keys).
#[cfg(feature = "linux")]
pub(super) fn merge_default_image_env(
    base: &[(String, String)],
    explicit: Vec<(String, String)>,
) -> Vec<(String, String)> {
    let mut merged = Vec::with_capacity(base.len() + explicit.len());
    for (key, value) in base {
        if !explicit.iter().any(|(override_key, _)| override_key == key) {
            merged.push((key.clone(), value.clone()));
        }
    }
    merged.extend(explicit);
    merged
}

/// Converts transferred [`crate::InheritedSockets`] into shared UNIX socket
/// objects installed at `fd = 3, 4, ...` for Linux and WASIX processes.
pub(super) fn inherited_sockets_to_unix_sockets<CpuImpl, Net, StorageImpl>(
    runtime_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
    sockets: crate::InheritedSockets,
) -> Result<Vec<UnixSocket<Net>>, ProgramExecError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let items = sockets.take_all();
    if items.is_empty() {
        return Ok(Vec::new());
    }
    let mut result = Vec::with_capacity(items.len());
    for mut item in items {
        if let Some((raw, local_address, local_port, hop_limit)) = item.take_tcp() {
            let service = runtime_state.network_service().ok_or(ProgramExecError {
                kind: ProgramExecErrorKind::Unavailable,
                detail: ProgramExecErrorDetail::HostOperationFailed,
            })?;
            let family = match local_address {
                crate::NetworkIpAddress::Ipv4(_) => SocketFamily::Ipv4,
                crate::NetworkIpAddress::Ipv6(_) => SocketFamily::Ipv6,
            };
            let options = unix_socket_options::<Net>();
            let listener = OwnedTcpListener::new(
                crate::UnixNetwork::with_vsock(Some(service), runtime_state.vsock_service()),
                <Net::TcpListener as crate::NetworkHandle>::from_raw(raw),
            );
            let sock = UnixSocket::<Net>::from_tcp(UnixTcpSocket::<Net>::Listening {
                family,
                listener,
                local_address,
                local_port,
                options,
            });
            let _ = sock.set_size(SocketSize::Ttl, u64::from(hop_limit));
            result.push(sock);
        } else if let Some((vsock_service, listener_id)) = item.take_vsock() {
            let local_cid = vsock_service.guest_cid() as u32;
            let local_port =
                vsock_service
                    .listener_port(listener_id)
                    .map_err(|_| ProgramExecError {
                        kind: ProgramExecErrorKind::Unavailable,
                        detail: ProgramExecErrorDetail::HostOperationFailed,
                    })?;
            let owned = OwnedVsockListener::new(
                crate::UnixNetwork::with_vsock(
                    runtime_state.network_service(),
                    Some(vsock_service),
                ),
                listener_id.as_u64(),
            );
            let sock = UnixSocket::<Net>::from_vsock(VsockSocket::Listening {
                listener: owned,
                local_cid,
                local_port,
                options: unix_socket_options::<Net>(),
            });
            result.push(sock);
        } else {
            return Err(ProgramExecError {
                kind: ProgramExecErrorKind::Unavailable,
                detail: ProgramExecErrorDetail::HostOperationFailed,
            });
        }
    }
    Ok(result)
}

/// A program's bytes, classified by how far the kernel trusts them.
///
/// The trust follows where the bytes came from, never which path or
/// branch read them: only [`BootfsBytes`] can become a
/// [`ProgramSource::BootfsArtifact`], which loads without a signature
/// check. A cwasm from anywhere else, guest-written files and the host
/// share alike, is a [`ProgramSource::SignedArtifact`] and loads only
/// if its signature verifies against the kernel's trusted roots.
pub(crate) enum ProgramSource {
    RawWasm(Bytes),
    SignedArtifact(Bytes),
    BootfsArtifact(BootfsBytes),
    /// A Linux executable. It runs natively in an address space of its
    /// own, so no provenance is asked of its bytes.
    #[cfg(feature = "linux")]
    LinuxElf(Bytes),
}

impl ProgramSource {
    /// Classifies a program file by the provenance the filesystem layer
    /// that produced its bytes gave them.
    pub(crate) fn from_file(contents: FileContents) -> Self {
        // A Wasmtime artifact is an ELF file too, so it is recognised first.
        match contents {
            FileContents::Boot(bytes)
                if WasmtimePrecompiledKind::detect(bytes.as_slice()).is_some() =>
            {
                Self::BootfsArtifact(bytes)
            }
            #[cfg(feature = "linux")]
            FileContents::Boot(bytes) if is_linux_elf(bytes.as_slice()) => {
                Self::LinuxElf(bytes.to_bytes())
            }
            FileContents::Boot(bytes) => Self::RawWasm(bytes.to_bytes()),
            FileContents::Written(bytes) => Self::from_untrusted(bytes),
        }
    }

    /// Classifies bytes no boot payload vouches for: a file a guest
    /// wrote, on whichever mount, or one a host shared.
    fn from_untrusted(bytes: Bytes) -> Self {
        if cwasm::is_cwasm(&bytes) {
            return Self::SignedArtifact(bytes);
        }
        // A Wasmtime artifact is an ELF file too, so one without a
        // signature is raw bytes for the wasm validator to refuse, never
        // a Linux program.
        #[cfg(feature = "linux")]
        if WasmtimePrecompiledKind::detect(&bytes).is_none() && is_linux_elf(&bytes) {
            return Self::LinuxElf(bytes);
        }
        Self::RawWasm(bytes)
    }

    /// Byte length of the payload the source carries, whichever
    /// variant it is.
    pub(crate) fn payload_len(&self) -> usize {
        match self {
            Self::RawWasm(bytes) | Self::SignedArtifact(bytes) => bytes.len(),
            #[cfg(feature = "linux")]
            Self::LinuxElf(bytes) => bytes.len(),
            Self::BootfsArtifact(bytes) => bytes.as_slice().len(),
        }
    }

    /// Returns `true` when this source is a Wasm artifact (precompiled bootfs,
    /// signed `cwasm`, or raw WebAssembly binary with `\0asm` magic).
    pub(crate) fn is_wasm(&self) -> bool {
        match self {
            Self::BootfsArtifact(_) | Self::SignedArtifact(_) => true,
            Self::RawWasm(bytes) => bytes.starts_with(b"\0asm"),
            #[cfg(feature = "linux")]
            Self::LinuxElf(_) => false,
        }
    }
}

#[cfg(feature = "linux")]
fn map_container_error(error: crate::ContainerError) -> ProgramExecError {
    let kind = match &error {
        crate::ContainerError::InvalidRootTarget(_)
        | crate::ContainerError::InvalidMountTarget(_)
        | crate::ContainerError::DuplicateMountTarget(_)
        | crate::ContainerError::NotADirectory { .. }
        | crate::ContainerError::TooManyMounts => ProgramExecErrorKind::InvalidPath,
        crate::ContainerError::Authority { .. }
        | crate::ContainerError::MountSharingMismatch { .. }
        | crate::ContainerError::PrivateMountBusy { .. }
        | crate::ContainerError::ReadOnlyMount { .. } => ProgramExecErrorKind::PermissionDenied,
        crate::ContainerError::Filesystem { error: fs, .. } => {
            return ProgramExecError::from_source_read_error(*fs);
        }
    };
    ProgramExecError {
        kind,
        detail: ProgramExecErrorDetail::ContainerRefused(crate::RuntimeMessage::of(error)),
    }
}

#[cfg(feature = "linux")]
async fn load_container_executable<CpuImpl, StorageImpl>(
    cpu: &CpuImpl,
    container: &crate::LinuxContainer<StorageImpl>,
    path: &str,
    argv: &mut ProgramArgv,
    creds: &helios_linux::syscall::Credentials,
    timeline: &phases::Timeline,
) -> Result<LinuxExecutable, ProgramExecError>
where
    CpuImpl: Cpu,
    StorageImpl: crate::Storage,
{
    let mut current_path = path.to_owned();
    let bytes = {
        let mut resolved = None;
        for depth in 0..=MAX_SHEBANG_DEPTH {
            let contents = container
                .filesystem()
                .read_executable(&current_path)
                .await
                .map_err(ProgramExecError::from_source_read_error)?;
            let bytes = match contents {
                FileContents::Boot(boot) => Bytes::copy_from_slice(boot.as_slice()),
                FileContents::Written(written) => written,
            };
            if let Some((interp, opt_arg)) = parse_shebang(&bytes) {
                if depth == MAX_SHEBANG_DEPTH {
                    return Err(ProgramExecError {
                        kind: ProgramExecErrorKind::InvalidPath,
                        detail: ProgramExecErrorDetail::InvalidProgramPath,
                    });
                }
                argv.rewrite_shebang(interp.clone(), opt_arg, current_path);
                current_path = interp;
                continue;
            }
            resolved = Some(bytes);
            break;
        }
        resolved.ok_or(ProgramExecError {
            kind: ProgramExecErrorKind::InvalidPath,
            detail: ProgramExecErrorDetail::InvalidProgramPath,
        })?
    };
    timeline.record(cpu, LaunchPhase::SourceRead);
    if !is_linux_elf(&bytes) {
        return Err(ProgramExecError {
            kind: ProgramExecErrorKind::InvalidBinary,
            detail: ProgramExecErrorDetail::LinuxImageInvalid(crate::LinuxImageRefusal::Malformed),
        });
    }
    timeline.record(cpu, LaunchPhase::LoadBegin);
    let loaded = LinuxExecutable::load_in_container(
        cpu,
        container,
        "/",
        bytes,
        Some(path.to_owned()),
        creds,
    )
    .await?;
    timeline.record(cpu, LaunchPhase::LoadComplete);
    Ok(loaded)
}

#[cfg(feature = "linux")]
async fn validate_container_cwd<StorageImpl: crate::Storage>(
    container: &crate::LinuxContainer<StorageImpl>,
    cwd: Option<&str>,
) -> Result<Option<String>, ProgramExecError> {
    let Some(raw_cwd) = cwd else {
        return Ok(None);
    };
    let normalized = crate::resolve_guest_path("/", raw_cwd).map_err(|_| ProgramExecError {
        kind: ProgramExecErrorKind::InvalidPath,
        detail: ProgramExecErrorDetail::InvalidProgramPath,
    })?;
    let stat = container
        .filesystem()
        .stat(&normalized)
        .await
        .map_err(ProgramExecError::from_source_read_error)?;
    if stat.metadata.kind != helios_hal::fs::NodeKind::Directory {
        return Err(ProgramExecError {
            kind: ProgramExecErrorKind::InvalidPath,
            detail: ProgramExecErrorDetail::InvalidProgramPath,
        });
    }
    Ok(Some(normalized))
}

/// Handle to a kernel Linux container stored in a component's resource table.
///
/// Kept non-generic so `wasmtime::component::bindgen!` maps
/// `helios:system/programs.container` directly to it; the underlying
/// [`crate::LinuxContainer`] lives in [`UserProgramService`] keyed by `id`.
/// Dropping the handle (either explicitly or on store teardown) retires `id`
/// so the service drops the container and releases any private mount claims.
pub struct ContainerHandle {
    id: NonZeroU64,
    retired: Arc<Mutex<Vec<NonZeroU64>>>,
    active: bool,
}

impl ContainerHandle {
    #[cfg(feature = "linux")]
    fn new(id: crate::ContainerId, retired: Arc<Mutex<Vec<NonZeroU64>>>) -> Self {
        Self {
            id: NonZeroU64::new(id.raw()).expect("container id is nonzero"),
            retired,
            active: true,
        }
    }

    #[cfg(feature = "linux")]
    pub(super) fn id(&self) -> crate::ContainerId {
        crate::ContainerId::new(self.id)
    }

    #[cfg(feature = "linux")]
    fn disarm(&mut self) -> crate::ContainerId {
        self.active = false;
        crate::ContainerId::new(self.id)
    }
}

impl Drop for ContainerHandle {
    fn drop(&mut self) {
        if self.active {
            self.active = false;
            self.retired.lock().push(self.id);
        }
    }
}

/// Handle to a spawned child component as seen by the kernel and its
/// direct Rust callers. WIT `child` resources wrap one of these.
pub struct ChildHandle {
    pub instance_id: crate::InstanceId,
    signal_state: WasixSignalState,
    stdin: Option<crate::ByteWriter>,
    stdout: Option<crate::ByteReader>,
    stderr: Option<crate::ByteReader>,
    exit: Option<futures::channel::oneshot::Receiver<Result<ChildExit, ProgramExecError>>>,
}

impl ChildHandle {
    fn signal_state(&self) -> WasixSignalState {
        self.signal_state.clone()
    }

    /// Deliver a POSIX signal to the running child process.
    pub fn signal(&self, signal: helios_unix::Signal) {
        self.signal_state.raise(signal);
    }

    /// Take the writer end of the child's stdin. Dropping it delivers
    /// EOF to the child.
    pub fn take_stdin(&mut self) -> Option<crate::ByteWriter> {
        self.stdin.take()
    }

    /// Take the reader end of the child's stdout stream.
    pub fn take_stdout(&mut self) -> Option<crate::ByteReader> {
        self.stdout.take()
    }

    /// Take the reader end of the child's stderr stream.
    pub fn take_stderr(&mut self) -> Option<crate::ByteReader> {
        self.stderr.take()
    }

    /// Take the exit-status receiver so an external driver (e.g. the WIT
    /// host `wait` impl that runs while the child resource is borrowed)
    /// can await it without consuming the handle.
    pub fn take_wait(
        &mut self,
    ) -> Option<futures::channel::oneshot::Receiver<Result<ChildExit, ProgramExecError>>> {
        self.exit.take()
    }

    /// Await child exit. Consumes the handle.
    pub async fn wait(mut self) -> Result<ChildExit, ProgramExecError> {
        match self.exit.take() {
            Some(rx) => match rx.await {
                Ok(result) => result,
                Err(_) => Err(ProgramExecError {
                    kind: ProgramExecErrorKind::Internal,
                    detail: ProgramExecErrorDetail::ChildExitChannelDropped,
                }),
            },
            None => Err(ProgramExecError {
                kind: ProgramExecErrorKind::Internal,
                detail: ProgramExecErrorDetail::ChildExitAlreadyConsumed,
            }),
        }
    }
}

/// Drain `child`'s stdout and stderr into kernel buffers bounded by
/// `max_output_bytes` (combined across both streams). If the child writes past
/// the bound, it is condemned and interrupted immediately, the pipe readers are
/// dropped so the child observes closed streams, the child is reaped, and the
/// caller receives [`ProgramExecErrorDetail::OutputLimitExceeded`].
async fn drain_child_output_bounded<CpuImpl, Net, StorageImpl>(
    mut child: ChildHandle,
    max_output_bytes: usize,
    runtime_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
    instance_registry: &crate::InstanceRegistry,
    cpu: &CpuImpl,
) -> Result<(ExecResult, Option<MemoryFs>), ProgramExecError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let child_id = child.instance_id;
    let stdout_reader = child.take_stdout();
    let stderr_reader = child.take_stderr();
    let remaining_budget = core::sync::atomic::AtomicUsize::new(max_output_bytes);
    let overflowed = core::sync::atomic::AtomicBool::new(false);

    let reserve_or_kill = |chunk_len: usize| -> bool {
        if overflowed.load(AtomicOrdering::Acquire) {
            return false;
        }
        let admitted = remaining_budget
            .try_update(
                AtomicOrdering::AcqRel,
                AtomicOrdering::Acquire,
                |remaining| remaining.checked_sub(chunk_len),
            )
            .is_ok();
        if !admitted {
            if !overflowed.swap(true, AtomicOrdering::AcqRel) {
                let residency = super::super::store::user_residency();
                let now = monotonic_nanos(cpu);
                instance_registry.request_kill(
                    child_id,
                    crate::KillReason::OutOfMemory,
                    now,
                    &residency,
                );
                super::deliver_kill(runtime_state, child_id);
            }
            return false;
        }
        true
    };

    let drain = |reader: Option<crate::ByteReader>| async {
        let mut bytes = Vec::new();
        if let Some(reader) = reader {
            while let Some(chunk) = reader.read().await {
                if !reserve_or_kill(chunk.len()) {
                    drop(reader);
                    break;
                }
                bytes.extend_from_slice(&chunk);
            }
        }
        bytes
    };

    let stdout_task = drain(stdout_reader);
    let stderr_task = drain(stderr_reader);
    let wait_task = child.wait();
    let (stdout, (stderr, exit)) =
        futures::future::join(stdout_task, futures::future::join(stderr_task, wait_task)).await;

    if overflowed.load(AtomicOrdering::Acquire) {
        return Err(ProgramExecError {
            kind: ProgramExecErrorKind::OutOfMemory,
            detail: ProgramExecErrorDetail::OutputLimitExceeded,
        });
    }

    let exit = exit?;
    let exit_code = match exit.termination {
        helios_unix::ChildTermination::Exited(code) => code,
        helios_unix::ChildTermination::Signaled(sig) => {
            128u32.saturating_add(u32::from(sig.signal))
        }
        helios_unix::ChildTermination::Trapped => {
            return Err(ProgramExecError {
                kind: ProgramExecErrorKind::Internal,
                detail: ProgramExecErrorDetail::ChildTrapped,
            });
        }
        helios_unix::ChildTermination::Killed => {
            return Err(ProgramExecError {
                kind: ProgramExecErrorKind::Internal,
                detail: ProgramExecErrorDetail::ChildKilled,
            });
        }
    };

    Ok((
        ExecResult {
            instance_id: exit.instance_id,
            exit_code,
            output: crate::ExecOutput { stdout, stderr },
        },
        exit.filesystem,
    ))
}

#[derive(Clone, Debug)]
pub struct ChildExit {
    pub instance_id: crate::InstanceId,
    pub termination: helios_unix::ChildTermination,
    filesystem: Option<MemoryFs>,
}

pub fn install_program_service<CpuImpl, Net, StorageImpl, WatchdogImpl, MeasuredBootImpl>(
    kernel: &crate::Kernel<CpuImpl, WatchdogImpl, MeasuredBootImpl>,
    cpu: &CpuImpl,
    debug_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
    read_serial: crate::SerialReader,
    write_serial: crate::DebugSerialWriter,
) -> UserProgramService<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
    WatchdogImpl: Watchdog + Clone,
    MeasuredBootImpl: MeasuredBoot,
{
    install_program_service_inner(kernel, cpu, debug_state, read_serial, write_serial)
}

pub fn install_component_host_program_service<
    CpuImpl,
    Net,
    StorageImpl,
    WatchdogImpl,
    MeasuredBootImpl,
>(
    kernel: &crate::Kernel<CpuImpl, WatchdogImpl, MeasuredBootImpl>,
    cpu: &CpuImpl,
    debug_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
    read_serial: crate::SerialReader,
    write_serial: crate::DebugSerialWriter,
) -> Option<UserProgramService<CpuImpl, Net, StorageImpl>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
    WatchdogImpl: Watchdog + Clone,
    MeasuredBootImpl: MeasuredBoot,
{
    let topology = kernel.topology();
    if helios_hal::cpu::current_processor() != topology.bootstrap_processor {
        return None;
    }

    Some(install_program_service_inner(
        kernel,
        cpu,
        debug_state,
        read_serial,
        write_serial,
    ))
}

fn install_program_service_inner<CpuImpl, Net, StorageImpl, WatchdogImpl, MeasuredBootImpl>(
    kernel: &crate::Kernel<CpuImpl, WatchdogImpl, MeasuredBootImpl>,
    cpu: &CpuImpl,
    debug_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
    read_serial: crate::SerialReader,
    write_serial: crate::DebugSerialWriter,
) -> UserProgramService<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
    WatchdogImpl: Watchdog + Clone,
    MeasuredBootImpl: MeasuredBoot,
{
    if let Some(service) = debug_state.program_service() {
        // The service and its key exist already; a device still held
        // here would never be measured into or read.
        assert!(
            kernel.take_measured_boot().is_none(),
            "the program service was installed before the measured-boot device it was handed \
             settled the compiler-signing key"
        );
        return service;
    }

    // The signing key is settled before any program can be admitted,
    // with the measured-boot device the platform handed the kernel.
    let mut measured_boot = kernel.take_measured_boot();
    let settled = crate::signing_key::settle_signing_key_at_bring_up(
        measured_boot.as_mut(),
        debug_state.payload_body(),
        debug_state.root_entropy(),
    );
    let cwasm_signing_key = settled.key;
    debug_state.install_machine_identity_key(settled.machine_identity);
    debug_state.install_hibernate_auth(settled.hibernate_auth, settled.source);
    // Selected by the backend when it built the runtime state, before any
    // secondary processor ran guest code, and logged once here: this is the
    // single place every backend's program service passes through, after the
    // logger is up.
    let guest_isa = debug_state.guest_isa();
    guest_isa.log();
    let cache_budget = machine_memory().free_bytes / COMPONENT_CACHE_FRACTION;
    let shared_memory_pool_budget =
        user_heap_stats().available_bytes() / SHARED_MEMORY_POOL_FRACTION;
    let runtime = crate::wasmtime_adapter::WasmtimeComponentRuntime::new(cpu.clone());
    let engine = <crate::wasmtime_adapter::WasmtimeComponentRuntime<CpuImpl> as crate::ComponentRuntimeFactory<CpuImpl, HostRuntimeState<CpuImpl, Net, StorageImpl>, StorageImpl>>::create_engine(&runtime)
        .unwrap_or_else(|error| panic!("failed to create launched-program engine: {error:#}"));
    let preview1_core_linker = preview1_program_linker(engine.raw())
        .unwrap_or_else(|error| panic!("failed to create preview1 program linker: {error:#}"));
    let service = UserProgramService {
        inner: Arc::new(UserProgramServiceInner {
            runtime,
            engine,
            preview1_core_linker,
            shared_memory_pool: Arc::new(Mutex::new(SharedMemoryPool::new(
                shared_memory_pool_budget,
            ))),
            component_cache: Mutex::new(ComponentCache::new(cache_budget)),
            component_instance_pre_cache: Mutex::new(ComponentCache::new(cache_budget)),
            core_module_cache: Mutex::new(ComponentCache::new(cache_budget)),
            core_module_instance_pre_cache: Arc::new(Mutex::new(ComponentCache::new(cache_budget))),
            next_provider_generation: core::sync::atomic::AtomicU64::new(1),
            surface_provider: Mutex::new(None),
            http_provider: Mutex::new(None),
            compiler_registration: Mutex::new(None),
            cwasm_signing_key,
            guest_isa,
            compiler_plugin: Mutex::new(None),
            compile_slot: SharedMemorySessionSlot::new(),
            code_map: CodeMap::new(),
            clock_cpu: cpu.clone(),
            plugin_read_serial: read_serial,
            plugin_write_serial: write_serial,
            #[cfg(feature = "linux")]
            next_container_id: core::sync::atomic::AtomicU64::new(1),
            #[cfg(feature = "linux")]
            containers: Mutex::new(alloc::collections::BTreeMap::new()),
            #[cfg(feature = "linux")]
            retired_containers: Arc::new(Mutex::new(Vec::new())),
            _marker: core::marker::PhantomData,
        }),
    };
    debug_state.install_program_service(service.clone());
    spawn_instruction_sample_drain(kernel, &service, debug_state);
    service
}

/// Attributes the instruction sampler's addresses while sampling runs.
///
/// A sample can only be named while the code it landed in is loaded, so
/// the rings are drained every [`crate::SAMPLE_DRAIN_INTERVAL_MILLIS`]
/// rather than once when the profile is read. Between profiles the task
/// parks on the sampler's start signal and costs nothing.
fn spawn_instruction_sample_drain<CpuImpl, Net, StorageImpl, WatchdogImpl, MeasuredBootImpl>(
    kernel: &crate::Kernel<CpuImpl, WatchdogImpl, MeasuredBootImpl>,
    service: &UserProgramService<CpuImpl, Net, StorageImpl>,
    debug_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
) where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
    WatchdogImpl: Watchdog + Clone,
    MeasuredBootImpl: MeasuredBoot,
{
    let sampler = debug_state.instruction_sampler();
    let code_map = service.code_map().clone();
    let timer = kernel.timer();
    let interval = Duration::from_millis(crate::SAMPLE_DRAIN_INTERVAL_MILLIS);
    kernel.spawn_detached(async move {
        loop {
            sampler.sampling_started().await;
            while sampler.sampling() {
                timer.sleep_for(interval).await;
                sampler.drain(&code_map);
            }
        }
    });
}

/// Runs the signed root supervisor component (`init` / `component-manager`)
/// once on the calling processor and returns its outcome after flushing any
/// writable mounts.
///
/// Bare-metal and hosted boots invoke [`run_root_component_forever`]; hosted
/// integration tests call this entry directly to observe the root component's
/// full bring-up and exit without shutting down the test process.
pub fn run_root_component_once<CpuImpl, Net, StorageImpl, WatchdogImpl, MeasuredBootImpl>(
    init: crate::EmbeddedInit,
    cpu: CpuImpl,
    kernel: &crate::Kernel<CpuImpl, WatchdogImpl, MeasuredBootImpl>,
    debug_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
    read_serial: crate::SerialReader,
    write_serial: crate::DebugSerialWriter,
) -> Result<(), RootComponentError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
    WatchdogImpl: Watchdog + Clone,
    MeasuredBootImpl: MeasuredBoot,
{
    let component_name = init.component().name();
    let has_debug_serial = kernel.devices().has_debug_serial;
    let stack = system_component_profile_stack(component_name);
    let namespace = debug_state.root_namespace().clone();
    let result = kernel.run_local_future(ProfiledSystemComponentFuture::new(
        run_root_component(
            init,
            super::SystemComponentHost {
                cpu: cpu.clone(),
                timer: kernel.timer(),
                spawner: kernel.spawner(),
                debug_state: debug_state.clone(),
                read_serial,
                write_serial,
            },
            has_debug_serial,
        ),
        cpu,
        debug_state,
        stack,
    ));
    // As Linux syncs and unmounts before it powers off: what the writable
    // mounts hold reaches their devices before the machine goes down.
    kernel.run_local_future(async move { namespace.sync_writable_mounts().await });
    result
}

pub fn run_root_component_forever<CpuImpl, Net, StorageImpl, WatchdogImpl, MeasuredBootImpl>(
    init: crate::EmbeddedInit,
    cpu: CpuImpl,
    kernel: &crate::Kernel<CpuImpl, WatchdogImpl, MeasuredBootImpl>,
    debug_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
    read_serial: crate::SerialReader,
    write_serial: crate::DebugSerialWriter,
) -> !
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
    WatchdogImpl: Watchdog + Clone,
    MeasuredBootImpl: MeasuredBoot,
{
    let component_name = init.component().name();
    write_serial.emit_stage_marker("boot");
    write_serial.emit_stage_marker("component-host:trace-begin");
    tracing::info!(
        component = component_name,
        argv0 = init.argv0(),
        "launching root supervisor component"
    );
    write_serial.emit_stage_marker("component-host:run-local-begin");
    run_root_component_once(
        init,
        cpu.clone(),
        kernel,
        debug_state,
        read_serial,
        write_serial,
    )
    .unwrap_or_else(|error| {
        write_serial.emit_error_marker("error failed-root-component", format_args!("{error:#}"));
        panic!("failed to exec root supervisor component:\n{error:#}");
    });
    write_serial.emit_stage_marker("done");
    tracing::info!(
        component = component_name,
        "root supervisor component exited cleanly"
    );
    report_fiber_stack_commits(&cpu);
    cpu.shutdown()
}

struct ProfiledSystemComponentFuture<CpuImpl, Net, StorageImpl, Fut>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    inner: Fut,
    cpu: CpuImpl,
    debug_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
    stack: String,
}

impl<CpuImpl, Net, StorageImpl, Fut> ProfiledSystemComponentFuture<CpuImpl, Net, StorageImpl, Fut>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn new(
        inner: Fut,
        cpu: CpuImpl,
        debug_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
        stack: String,
    ) -> Self {
        Self {
            inner,
            cpu,
            debug_state,
            stack,
        }
    }
}

impl<CpuImpl, Net, StorageImpl, Fut> Future
    for ProfiledSystemComponentFuture<CpuImpl, Net, StorageImpl, Fut>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
    Fut: Future,
{
    type Output = Fut::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: `inner` is pinned in place with `Self`; this projection never moves it.
        let this = unsafe { self.get_unchecked_mut() };
        let started = this.cpu.now().ticks();
        // SAFETY: `inner` has not been moved after `Self` was pinned.
        let result = unsafe { Pin::new_unchecked(&mut this.inner) }.poll(cx);
        if this.debug_state.profiling_enabled() {
            this.debug_state.record_profile_stack_str(
                ProfileScope::Kernel,
                &this.stack,
                this.cpu.now().ticks().saturating_sub(started),
            );
        }
        result
    }
}

pub fn run_program_workers_forever<CpuImpl, Net, StorageImpl, WatchdogImpl, MeasuredBootImpl>(
    cpu: CpuImpl,
    kernel: crate::Kernel<CpuImpl, WatchdogImpl, MeasuredBootImpl>,
    debug_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
) -> !
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
    WatchdogImpl: Watchdog + Clone,
    MeasuredBootImpl: MeasuredBoot,
{
    // The packet pump and per-processor WASI 0.3 plugin shards live on this
    // processor as local tasks: the plugins come up after `NetworkStep` and
    // go down before it on processor offline.
    let network = NetworkStep::start(&kernel, &debug_state);
    let http_client = PerProcessorHttpStep::start(&cpu, &kernel, &debug_state);
    let steps = (network, http_client);
    kernel.run_with_steps(&steps)
}

pub fn run_component_host_processor_forever<
    CpuImpl,
    Net,
    StorageImpl,
    WatchdogImpl,
    MeasuredBootImpl,
>(
    cpu: CpuImpl,
    kernel: crate::Kernel<CpuImpl, WatchdogImpl, MeasuredBootImpl>,
    debug_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
    read_serial: crate::SerialReader,
    write_serial: crate::DebugSerialWriter,
) -> !
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
    WatchdogImpl: Watchdog + Clone,
    MeasuredBootImpl: MeasuredBoot,
{
    // Started before the role dispatch decides what else the processor
    // does: every processor's pump and lazy per-processor HTTP provider shard
    // run locally here. A processor running the root supervisor keeps the
    // steps alive without lending them to a lifecycle, since it never goes
    // offline.
    let network = NetworkStep::start(&kernel, &debug_state);
    let http_client = PerProcessorHttpStep::start(&cpu, &kernel, &debug_state);
    let steps = (network, http_client);
    let topology = kernel.topology();
    // Every backend's bootstrap processor reaches here only after starting
    // its secondaries, and a backend enables its mechanisms on a processor
    // before `start_processor` returns for it, so the line follows every
    // processor's enable.
    if helios_hal::cpu::current_processor() == topology.bootstrap_processor {
        crate::control_flow::ReturnAddressCoverage::of(&cpu, env!("HELIOS_BUILD_TARGET"))
            .log(topology.configured_processors);
        crate::memory_tagging::log(&cpu);
    }
    match component_host_processor_role(
        helios_hal::cpu::current_processor(),
        topology.configured_processors,
        topology.bootstrap_processor,
    ) {
        ComponentHostProcessorRole::Kernel => {
            run_kernel_processor_forever(cpu, kernel, debug_state, &steps);
        }
        ComponentHostProcessorRole::SharedRuntime | ComponentHostProcessorRole::SystemComponent => {
            run_root_component_forever(
                debug_state.embedded_init(),
                cpu,
                &kernel,
                debug_state,
                read_serial,
                write_serial,
            )
        }
    }
}

/// Prints what the fiber-stack arena did over this boot, per processor.
///
/// The arena's whole claim is that a live instance costs the stack it
/// touched rather than the stack it might, and a reserve commit is the
/// event that makes that true. Counting them per processor is also what
/// shows the reserve path running on every processor rather than only on
/// the one that created the stack.
fn report_fiber_stack_commits<CpuImpl: Cpu>(cpu: &CpuImpl) {
    let Some(stats) = crate::fiber_stack_arena_stats() else {
        return;
    };
    for processor in 0..cpu.processor_count() {
        let processor =
            helios_hal::cpu::ProcessorId::new(u16::try_from(processor).unwrap_or_else(|_| {
                panic!("processor {processor} is beyond the identifiers this platform can name")
            }));
        tracing::info!(
            target: "helios_kernel::fiber_stack",
            processor = processor.id(),
            reserve_commits = crate::fiber_stack_reserve_commits_on(processor),
            "fiber stack reserve commits resolved on this processor"
        );
    }
    tracing::info!(
        target: "helios_kernel::fiber_stack",
        slots = stats.slots,
        live_slots = stats.live_slots,
        warm_slots = stats.warm_slots,
        retained_bytes = stats.retained_bytes,
        committed_bytes = stats.committed_bytes,
        eager_bytes = stats.eager_bytes,
        released_stacks = stats.released_stacks,
        released_committed_bytes = stats.released_committed_bytes,
        released_eager_bytes = stats.released_eager_bytes,
        reserve_commits = stats.reserve_commits,
        reserve_committed_pages = stats.reserve_committed_pages,
        "fiber stack arena totals for this boot"
    );
}

fn run_kernel_processor_forever<CpuImpl, Net, StorageImpl, WatchdogImpl, MeasuredBootImpl, Steps>(
    cpu: CpuImpl,
    kernel: crate::Kernel<CpuImpl, WatchdogImpl, MeasuredBootImpl>,
    debug_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
    steps: &Steps,
) -> !
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
    WatchdogImpl: Watchdog + Clone,
    MeasuredBootImpl: MeasuredBoot,
    Steps: crate::exec::ProcessorStep,
{
    let processor = helios_hal::cpu::current_processor().id();
    let stack = kernel_processor_profile_stack(processor);
    loop {
        let progress = if debug_state.profiling_enabled() {
            let started = cpu.now().ticks();
            let counters = cpu.hardware_perf_counters();
            let stats = kernel.run_until_stalled_with_steps(steps);
            let progress = stats.progress_count();
            if progress != 0 {
                record_executor_metrics(&cpu, &debug_state, &stack, started, counters, stats);
            }
            progress
        } else {
            kernel.run_until_stalled_with_steps(steps).progress_count()
        };

        if progress != 0 {
            continue;
        }

        let outcome = kernel.park_until_work();
        if debug_state.profiling_enabled() {
            record_executor_idle_metrics(&debug_state, outcome);
        }
    }
}

fn record_executor_metrics<CpuImpl, Net, StorageImpl>(
    cpu: &CpuImpl,
    debug_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
    stack: &str,
    started: u64,
    counters: helios_hal::cpu::HardwarePerfCounters,
    stats: crate::KernelRunStats,
) where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let progress = stats.progress_count();
    let ended = cpu.now().ticks();
    let elapsed = ended.saturating_sub(started);
    debug_state.record_profile_stack_str(ProfileScope::Kernel, stack, elapsed);
    let elapsed_nanos = debug_state
        .uptime_nanos(ended)
        .saturating_sub(debug_state.uptime_nanos(started));
    let counter_delta = cpu.hardware_perf_counters().delta_since(counters);
    debug_state.record_perf_metric_parts(
        ProfileScope::Kernel,
        "kernel;executor;",
        "run",
        crate::PerfSample {
            events: usize_to_u64(progress, "executor progress count"),
            elapsed_nanos,
            counters: counter_delta,
            bytes: 0,
        },
    );
    record_executor_event_metric(
        debug_state,
        "local-runnable",
        stats.executor_local_runnable_count,
    );
    record_executor_event_metric(
        debug_state,
        "global-runnable",
        stats.executor_global_runnable_count,
    );
    record_executor_event_metric(
        debug_state,
        "local-empty-pop",
        stats.executor_local_empty_pop_count,
    );
    record_executor_event_metric(
        debug_state,
        "global-empty-pop",
        stats.executor_global_empty_pop_count,
    );
    record_executor_event_metric(debug_state, "timer-fired", stats.timer_fired_count);
    debug_state.record_kernel_heap_metrics(crate::heap_stats());
}

/// What one idle park cost: the poll phase under
/// `kernel;executor;idle-poll`, the parked span under
/// `kernel;executor;idle-parked`, and a hit/miss event so a profile
/// can weigh IPI-and-halt-exit wakes against polled ones.
fn record_executor_idle_metrics<CpuImpl, Net, StorageImpl>(
    debug_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
    outcome: crate::IdleOutcome,
) where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let (polled_ticks, parked_ticks) = match outcome {
        crate::IdleOutcome::Polled { polled_ticks } => {
            record_executor_event_metric(debug_state, "idle-poll-hit", 1);
            (polled_ticks, None)
        }
        crate::IdleOutcome::Parked {
            polled_ticks,
            parked_ticks,
        } => {
            record_executor_event_metric(debug_state, "idle-poll-miss", 1);
            (polled_ticks, Some(parked_ticks))
        }
    };
    debug_state.record_profile_stack_str(
        ProfileScope::Kernel,
        "kernel;executor;idle-poll",
        polled_ticks,
    );
    if let Some(parked_ticks) = parked_ticks {
        debug_state.record_profile_stack_str(
            ProfileScope::Kernel,
            "kernel;executor;idle-parked",
            parked_ticks,
        );
    }
}

fn record_executor_event_metric<CpuImpl, Net, StorageImpl>(
    runtime_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
    name: &'static str,
    events: usize,
) where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    if events == 0 {
        return;
    }
    runtime_state.record_perf_metric_parts(
        ProfileScope::Kernel,
        "kernel;executor;",
        name,
        crate::PerfSample {
            events: usize_to_u64(events, "executor event count"),
            elapsed_nanos: 0,
            counters: helios_hal::cpu::HardwarePerfCounterDelta::default(),
            bytes: 0,
        },
    );
}

fn usize_to_u64(value: usize, label: &'static str) -> u64 {
    u64::try_from(value).unwrap_or_else(|_| panic!("{label} does not fit into u64"))
}

fn record_program_kernel_profile<CpuImpl, Net, StorageImpl>(
    runtime_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
    cpu: &CpuImpl,
    phase: &'static str,
    started_ticks: u64,
) where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    if runtime_state.profiling_enabled() {
        runtime_state.record_profile_stack_parts(
            ProfileScope::Kernel,
            "kernel;program;",
            phase,
            cpu.now().ticks().saturating_sub(started_ticks),
        );
    }
}

fn record_named_program_kernel_profile<CpuImpl, Net, StorageImpl>(
    runtime_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
    cpu: &CpuImpl,
    phase: &'static str,
    name: &str,
    started_ticks: u64,
) where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    if runtime_state.profiling_enabled() {
        let mut stack = String::with_capacity("kernel;program;;".len() + phase.len() + name.len());
        stack.push_str("kernel;program;");
        stack.push_str(phase);
        stack.push(';');
        stack.push_str(name);
        runtime_state.record_profile_stack_str(
            ProfileScope::Kernel,
            &stack,
            cpu.now().ticks().saturating_sub(started_ticks),
        );
    }
}

struct ProgramKernelProfile<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    runtime_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
    cpu: CpuImpl,
    started_ticks: u64,
    counters: helios_hal::cpu::HardwarePerfCounters,
    started_heap: crate::HeapStats,
}

fn start_program_kernel_profile<CpuImpl, Net, StorageImpl>(
    runtime_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
    cpu: &CpuImpl,
) -> Option<ProgramKernelProfile<CpuImpl, Net, StorageImpl>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    runtime_state
        .profiling_enabled()
        .then(|| ProgramKernelProfile {
            runtime_state: runtime_state.clone(),
            cpu: cpu.clone(),
            started_ticks: cpu.now().ticks(),
            counters: cpu.hardware_perf_counters(),
            started_heap: crate::heap_stats(),
        })
}

fn record_program_kernel_profile_sample<CpuImpl, Net, StorageImpl>(
    profile: Option<ProgramKernelProfile<CpuImpl, Net, StorageImpl>>,
    phase: &'static str,
) where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    if let Some(profile) = profile {
        let ended_ticks = profile.cpu.now().ticks();
        let elapsed_ticks = ended_ticks.saturating_sub(profile.started_ticks);
        profile.runtime_state.record_profile_stack_parts(
            ProfileScope::Kernel,
            "kernel;program;",
            phase,
            elapsed_ticks,
        );
        let elapsed_nanos = profile
            .runtime_state
            .uptime_nanos(ended_ticks)
            .saturating_sub(profile.runtime_state.uptime_nanos(profile.started_ticks));
        let counter_delta = profile
            .cpu
            .hardware_perf_counters()
            .delta_since(profile.counters);
        profile.runtime_state.record_perf_metric_parts(
            ProfileScope::Kernel,
            "kernel;program;",
            phase,
            crate::PerfSample {
                events: 1,
                elapsed_nanos,
                counters: counter_delta,
                bytes: 0,
            },
        );

        let heap = crate::heap_stats();
        record_program_heap_delta(
            &profile.runtime_state,
            phase,
            "heap-alloc",
            heap.allocation_count
                .saturating_sub(profile.started_heap.allocation_count),
            heap.total_allocation_bytes
                .saturating_sub(profile.started_heap.total_allocation_bytes),
        );
        record_program_heap_delta(
            &profile.runtime_state,
            phase,
            "heap-realloc",
            heap.reallocation_count
                .saturating_sub(profile.started_heap.reallocation_count),
            heap.total_reallocation_bytes
                .saturating_sub(profile.started_heap.total_reallocation_bytes),
        );
        record_program_heap_delta(
            &profile.runtime_state,
            phase,
            "heap-dealloc",
            heap.deallocation_count
                .saturating_sub(profile.started_heap.deallocation_count),
            heap.total_deallocation_bytes
                .saturating_sub(profile.started_heap.total_deallocation_bytes),
        );
    }
}

fn record_program_heap_delta<CpuImpl, Net, StorageImpl>(
    runtime_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
    phase: &'static str,
    kind: &'static str,
    events: u64,
    bytes: u64,
) where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    if events == 0 && bytes == 0 {
        return;
    }
    let phase_prefix = match kind {
        "heap-alloc" => "kernel;program-heap;alloc;",
        "heap-realloc" => "kernel;program-heap;realloc;",
        "heap-dealloc" => "kernel;program-heap;dealloc;",
        _ => panic!("unknown program heap metric kind {kind}"),
    };
    runtime_state.record_perf_metric_parts(
        ProfileScope::Kernel,
        phase_prefix,
        phase,
        crate::PerfSample {
            events,
            elapsed_nanos: 0,
            counters: helios_hal::cpu::HardwarePerfCounterDelta::default(),
            bytes,
        },
    );
}

impl<CpuImpl, Net, StorageImpl> UserProgramService<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    /// Preempts every guest, on any processor, that has held its
    /// processor for at least one [`crate::GUEST_TIME_SLICE`].
    ///
    /// Each backend calls this from every processor's timer interrupt,
    /// whatever the interrupt's period: it takes no lock, allocates
    /// nothing and sends no IPI.
    pub fn preempt_overdue_guests(&self) {
        self.inner
            .engine
            .interrupts()
            .preempt_overdue(self.inner.clock_cpu.now());
    }

    /// Interrupts every guest that is running on any processor now,
    /// however long it has run: what a freeze passes as its
    /// `interrupt_guests`, so a processor inside wasm reaches a
    /// scheduler boundary at its next check.
    ///
    /// Like [`Self::preempt_overdue_guests`] it takes no lock, allocates
    /// nothing and sends no IPI.
    pub fn interrupt_running_guests(&self) {
        self.inner.engine.interrupts().interrupt_running();
    }

    /// Interrupts every store of `instance`, so a kill whose flag is set
    /// reaches the guest wherever it is.
    pub fn interrupt_instance(&self, instance: crate::InstanceId) {
        self.inner.engine.interrupts().interrupt_instance(instance);
    }

    /// The wasm images this service has loaded, which name the
    /// instruction sampler's addresses.
    pub(crate) fn code_map(&self) -> &CodeMap {
        &self.inner.code_map
    }

    #[cfg(feature = "linux")]
    fn drain_retired_containers(&self) {
        let retired: Vec<NonZeroU64> = {
            let mut queue = self.inner.retired_containers.lock();
            core::mem::take(&mut *queue)
        };
        if retired.is_empty() {
            return;
        }
        let mut table = self.inner.containers.lock();
        for id in retired {
            table.remove(&crate::ContainerId::new(id));
        }
    }

    #[cfg(feature = "linux")]
    pub(super) fn allocate_container_id(&self) -> crate::ContainerId {
        let raw = self
            .inner
            .next_container_id
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        crate::ContainerId::new(NonZeroU64::new(raw).expect("container id counter starts at 1"))
    }

    /// Creates a new isolated Linux container owned by this service and returns
    /// its resource handle.
    #[cfg(feature = "linux")]
    pub(super) async fn create_container(
        &self,
        caller_authority: &ProcessAuthority,
        caller_namespace: &Namespace<StorageImpl>,
        non_fs_authority: ProcessAuthority,
        config: crate::ContainerConfig,
    ) -> Result<ContainerHandle, ProgramExecError> {
        self.drain_retired_containers();
        let id = self.allocate_container_id();
        let container = crate::LinuxContainer::create(
            id,
            caller_authority,
            caller_namespace,
            non_fs_authority,
            config,
        )
        .await
        .map_err(map_container_error)?;
        let container = Arc::new(container);
        self.inner.containers.lock().insert(id, container);
        Ok(ContainerHandle::new(
            id,
            self.inner.retired_containers.clone(),
        ))
    }

    /// Looks up a live container by handle.
    #[cfg(feature = "linux")]
    pub(super) fn get_container(
        &self,
        handle: &ContainerHandle,
    ) -> Result<Arc<crate::LinuxContainer<StorageImpl>>, ProgramExecError> {
        self.drain_retired_containers();
        self.inner
            .containers
            .lock()
            .get(&handle.id())
            .cloned()
            .ok_or_else(|| ProgramExecError {
                kind: ProgramExecErrorKind::Unavailable,
                detail: ProgramExecErrorDetail::ContainerRefused(crate::RuntimeMessage::of(
                    "container handle is no longer active",
                )),
            })
    }

    /// Immediately removes a dropped container handle from the service so any
    /// private mount claims it held are released right away.
    pub(super) fn remove_container(&self, handle: &mut ContainerHandle) {
        #[cfg(feature = "linux")]
        {
            let id = handle.disarm();
            self.inner.containers.lock().remove(&id);
            self.drain_retired_containers();
        }
        #[cfg(not(feature = "linux"))]
        {
            let _ = handle;
        }
    }

    /// Creates an ephemeral overlay Linux container backed by `default_image.lower`
    /// as `"/"` (with a fresh `UserMemoryPool`-backed upper layer) and bind-mounts
    /// the child's granted non-`"/"` host directories on top.
    #[cfg(feature = "linux")]
    pub(super) fn create_ephemeral_overlay_container(
        &self,
        authority: ProcessAuthority,
        namespace: &Namespace<StorageImpl>,
        default_image: &crate::DefaultLinuxImage<StorageImpl>,
    ) -> Result<Arc<crate::LinuxContainer<StorageImpl>>, ProgramExecError> {
        let credentials = match default_image.credentials.as_ref() {
            Some(creds) => Some(
                helios_linux::syscall::Credentials::try_for_ids(
                    creds.uid,
                    creds.gid,
                    creds.supplementary_groups.clone(),
                )
                .map_err(|error| ProgramExecError {
                    kind: ProgramExecErrorKind::InvalidPath,
                    detail: ProgramExecErrorDetail::ContainerRefused(crate::RuntimeMessage::of(
                        error,
                    )),
                })?,
            ),
            None => None,
        };
        let container = Arc::new(
            crate::LinuxContainer::ephemeral_with_overlay(
                self.allocate_container_id(),
                authority,
                namespace,
                default_image.lower.clone(),
                credentials,
            )
            .map_err(map_container_error)?,
        );
        Ok(container)
    }

    /// Loads a Linux executable strictly from `container`'s own filesystem and
    /// spawns it inside `container`.
    #[cfg(feature = "linux")]
    pub(super) async fn spawn_in_container(
        &self,
        exec_context: ProgramExecContext<CpuImpl, Net, StorageImpl>,
        path: &str,
        mut launch: ProgramLaunch<Net, StorageImpl>,
    ) -> Result<ChildHandle, ProgramExecError> {
        let container_launch = launch
            .container
            .as_ref()
            .expect("container spawn carries a container");
        let container = container_launch.container.clone();
        let mut creds = container_launch
            .credentials
            .clone()
            .unwrap_or_else(|| container.default_credentials().clone());
        container.clamp_credentials(&mut creds);
        launch.cwd = validate_container_cwd(&container, launch.cwd.as_deref()).await?;
        let executable = load_container_executable(
            &exec_context.cpu,
            &container,
            path,
            &mut launch.argv,
            &creds,
            &launch.timeline,
        )
        .await?;
        self.spawn_loaded(exec_context, ProgramExecutable::Linux(executable), launch)
    }

    /// Loads a Linux executable strictly from `container`'s own filesystem,
    /// runs it to completion inside `container`, and returns buffered output.
    #[cfg(feature = "linux")]
    pub(super) async fn exec_in_container(
        &self,
        exec_context: ProgramExecContext<CpuImpl, Net, StorageImpl>,
        path: &str,
        stdin: Vec<u8>,
        mut launch: ProgramLaunch<Net, StorageImpl>,
    ) -> Result<ExecResult, ProgramExecError> {
        let container_launch = launch
            .container
            .as_ref()
            .expect("container exec carries a container");
        let container = container_launch.container.clone();
        let mut creds = container_launch
            .credentials
            .clone()
            .unwrap_or_else(|| container.default_credentials().clone());
        container.clamp_credentials(&mut creds);
        launch.cwd = validate_container_cwd(&container, launch.cwd.as_deref()).await?;
        let executable = load_container_executable(
            &exec_context.cpu,
            &container,
            path,
            &mut launch.argv,
            &creds,
            &launch.timeline,
        )
        .await?;
        self.exec_loaded_buffered(
            exec_context,
            ProgramExecutable::Linux(executable),
            stdin,
            launch,
        )
        .await
        .map(|(result, _)| result)
    }

    #[cfg(feature = "linux")]
    async fn load_overlay_executable(
        cpu: &CpuImpl,
        container: &crate::LinuxContainer<StorageImpl>,
        path: &str,
        fallback_bytes: Option<Bytes>,
        argv: &mut ProgramArgv,
        creds: &helios_linux::syscall::Credentials,
        timeline: &phases::Timeline,
    ) -> Result<LinuxExecutable, ProgramExecError> {
        match load_container_executable(cpu, container, path, argv, creds, timeline).await {
            Ok(executable) => Ok(executable),
            Err(error)
                if error.kind == ProgramExecErrorKind::NotFound && fallback_bytes.is_some() =>
            {
                let bytes = fallback_bytes.expect("checked is_some above");
                if let Some((interp, opt_arg)) = parse_shebang(&bytes) {
                    argv.rewrite_shebang(interp.clone(), opt_arg, path.to_owned());
                    load_container_executable(cpu, container, &interp, argv, creds, timeline).await
                } else if is_linux_elf(&bytes) {
                    timeline.record(cpu, LaunchPhase::SourceRead);
                    timeline.record(cpu, LaunchPhase::LoadBegin);
                    let loaded = LinuxExecutable::load_in_container(
                        cpu,
                        container,
                        "/",
                        bytes,
                        Some(path.to_owned()),
                        creds,
                    )
                    .await?;
                    timeline.record(cpu, LaunchPhase::LoadComplete);
                    Ok(loaded)
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Spawns a Linux executable or `#!` script inside a freshly built
    /// ephemeral overlay container (used when the caller has a default Linux
    /// image configured).
    #[cfg(feature = "linux")]
    pub(super) async fn spawn_in_overlay_container(
        &self,
        exec_context: ProgramExecContext<CpuImpl, Net, StorageImpl>,
        path: &str,
        fallback_bytes: Option<Bytes>,
        mut launch: ProgramLaunch<Net, StorageImpl>,
    ) -> Result<ChildHandle, ProgramExecError> {
        let container_launch = launch
            .container
            .as_ref()
            .expect("overlay spawn carries a container");
        let container = container_launch.container.clone();
        let mut creds = container_launch
            .credentials
            .clone()
            .unwrap_or_else(|| container.default_credentials().clone());
        container.clamp_credentials(&mut creds);
        launch.cwd = validate_container_cwd(&container, launch.cwd.as_deref()).await?;
        let executable = Self::load_overlay_executable(
            &exec_context.cpu,
            &container,
            path,
            fallback_bytes,
            &mut launch.argv,
            &creds,
            &launch.timeline,
        )
        .await?;
        self.spawn_loaded(exec_context, ProgramExecutable::Linux(executable), launch)
    }

    /// Runs a Linux executable or `#!` script to completion inside a freshly
    /// built ephemeral overlay container and returns buffered output.
    #[cfg(feature = "linux")]
    pub(super) async fn exec_in_overlay_container(
        &self,
        exec_context: ProgramExecContext<CpuImpl, Net, StorageImpl>,
        path: &str,
        fallback_bytes: Option<Bytes>,
        stdin: Vec<u8>,
        mut launch: ProgramLaunch<Net, StorageImpl>,
    ) -> Result<ExecResult, ProgramExecError> {
        let container_launch = launch
            .container
            .as_ref()
            .expect("overlay exec carries a container");
        let container = container_launch.container.clone();
        let mut creds = container_launch
            .credentials
            .clone()
            .unwrap_or_else(|| container.default_credentials().clone());
        container.clamp_credentials(&mut creds);
        launch.cwd = validate_container_cwd(&container, launch.cwd.as_deref()).await?;
        let executable = Self::load_overlay_executable(
            &exec_context.cpu,
            &container,
            path,
            fallback_bytes,
            &mut launch.argv,
            &creds,
            &launch.timeline,
        )
        .await?;
        self.exec_loaded_buffered(
            exec_context,
            ProgramExecutable::Linux(executable),
            stdin,
            launch,
        )
        .await
        .map(|(result, _)| result)
    }

    /// Spawn a new child program. The returned handle gives the caller
    /// direct access to the child's stdin/stdout/stderr channels and a
    /// future resolving with its exit status.
    pub(super) async fn spawn(
        &self,
        compile: &CompileAuthority,
        exec_context: ProgramExecContext<CpuImpl, Net, StorageImpl>,
        source: ProgramSource,
        hint: Option<AotCompileHint>,
        launch: ProgramLaunch<Net, StorageImpl>,
    ) -> Result<ChildHandle, ProgramExecError> {
        super::emit_program_stage_marker(exec_context.write_serial, "program:spawn-begin");
        let executable = self
            .load_executable(
                compile,
                &exec_context,
                launch.argv.program_name(),
                &source,
                hint,
                &launch.timeline,
            )
            .await?;
        self.spawn_loaded(exec_context, executable, launch)
    }

    /// Spawn a child whose stdio the caller has already wired up.
    ///
    /// A preview1 descriptor table only means anything to a core
    /// module, so one supplied alongside a component is dropped here
    /// rather than at every call site.
    async fn spawn_with_output_mode(
        &self,
        compile: &CompileAuthority,
        exec_context: ProgramExecContext<CpuImpl, Net, StorageImpl>,
        source: ProgramSource,
        mut launch: ProgramLaunch<Net, StorageImpl>,
        output_mode: OutputMode,
        stdio: ChildStdio,
    ) -> Result<ChildHandle, ProgramExecError> {
        super::emit_program_stage_marker(exec_context.write_serial, "program:spawn-begin");
        let executable = self
            .load_executable(
                compile,
                &exec_context,
                launch.argv.program_name(),
                &source,
                None,
                &launch.timeline,
            )
            .await?;
        if matches!(executable, ProgramExecutable::Component(_)) {
            launch.descriptors = DescriptorOrigin::Fresh;
        }
        self.spawn_loaded_with_output_mode(exec_context, executable, launch, output_mode, stdio)
    }

    fn spawn_loaded(
        &self,
        exec_context: ProgramExecContext<CpuImpl, Net, StorageImpl>,
        executable: ProgramExecutable<CpuImpl, Net, StorageImpl>,
        launch: ProgramLaunch<Net, StorageImpl>,
    ) -> Result<ChildHandle, ProgramExecError> {
        let (stdin_writer, stdin_reader) = crate::byte_channel();
        let (stdout_writer, stdout_reader) = crate::byte_channel();
        let (stderr_writer, stderr_reader) = crate::byte_channel();
        self.spawn_loaded_with_output_mode(
            exec_context,
            executable,
            launch,
            OutputMode::Child {
                stdin_rx: stdin_reader,
                stdout_tx: stdout_writer,
                stderr_tx: stderr_writer,
            },
            ChildStdio {
                stdin: Some(stdin_writer),
                stdout: Some(stdout_reader),
                stderr: Some(stderr_reader),
            },
        )
    }

    fn spawn_loaded_with_output_mode(
        &self,
        exec_context: ProgramExecContext<CpuImpl, Net, StorageImpl>,
        executable: ProgramExecutable<CpuImpl, Net, StorageImpl>,
        launch: ProgramLaunch<Net, StorageImpl>,
        output_mode: OutputMode,
        stdio: ChildStdio,
    ) -> Result<ChildHandle, ProgramExecError> {
        let ProgramLaunch {
            argv,
            env,
            authority,
            launched_instance,
            ipc_grants,
            default_linux_image,
            inherited_sockets,
            cwd,
            filesystem,
            descriptors,
            signal_dispositions,
            #[cfg(feature = "linux")]
            container,
            oom_policy,
            timeline,
        } = launch;
        #[cfg(feature = "linux")]
        let container = match (&executable, container) {
            (ProgramExecutable::Linux(_), Some(explicit)) => Some(explicit),
            (ProgramExecutable::Linux(_), None) => {
                // Every Linux process runs inside a container; direct ELF
                // launches (e.g. from WASIX `/bin/dash` or `programs.exec`)
                // receive a dedicated container bounded by their launch
                // authority and namespace.
                let namespace = filesystem
                    .as_ref()
                    .unwrap_or_else(|| exec_context.runtime_state.root_namespace());
                let ephemeral = Arc::new(crate::LinuxContainer::ephemeral(
                    self.allocate_container_id(),
                    authority.clone(),
                    namespace,
                ));
                exec_context.runtime_state.register_container(&ephemeral);
                Some(LinuxContainerLaunch {
                    container: ephemeral,
                    credentials: None,
                })
            }
            (_, other) => other,
        };
        let started_at = exec_context
            .runtime_state
            .uptime_nanos(exec_context.cpu.now().ticks());
        let launched_instance = launched_instance.unwrap_or_else(|| {
            exec_context.instance_registry.register_child_with_policy(
                exec_context.parent_instance_id,
                argv.program_name().to_owned(),
                started_at,
                oom_policy,
            )
        });
        let instance_id = launched_instance.id();
        let ipc_grant_count = ipc_grants.len();
        if !authority.is_empty() || ipc_grant_count > 0 {
            crate::audit::privileged_spawn(
                exec_context.parent_instance_id,
                instance_id,
                argv.program_name(),
                ipc_grant_count,
            );
        }
        let env = env.into_process_env(instance_id);
        let signal_state = WasixSignalState::new();
        let request = ProgramSpawnRequest {
            argv,
            env,
            authority,
            ipc_grants,
            default_linux_image,
            inherited_sockets,
            cwd,
            filesystem,
            descriptors,
            signal_state: signal_state.clone(),
            signal_dispositions,
            #[cfg(feature = "linux")]
            container,
        };

        let (exit_tx, exit_rx) = futures::channel::oneshot::channel();
        let runtime = self.inner.runtime.clone();
        let engine = self.inner.engine.clone();
        let preview1_core_linker = self.inner.preview1_core_linker.clone();
        let shared_memory_pool = self.inner.shared_memory_pool.clone();
        let core_module_instance_pre_cache = self.inner.core_module_instance_pre_cache.clone();
        // Task funding follows the instance's OOM policy (`OomPolicy::task_funding`):
        // user programs draw from the arena's instance share so a spawn storm
        // stops there, while kernel plugins and system components draw from the
        // kernel reserve.
        let spawner = exec_context.spawner.instance_spawner(
            launched_instance.oom_policy().task_funding(),
            &launched_instance,
        );
        let run_spawner = spawner.clone();
        let progress = spawner.progress_counter();

        let launched = spawner.try_spawn_local_detached(async move {
            let result = run_program_executable(
                exec_context,
                request.argv,
                request.env,
                request.authority,
                request.ipc_grants,
                request.default_linux_image,
                request.inherited_sockets,
                request.cwd,
                request.filesystem,
                request.descriptors,
                request.signal_state,
                request.signal_dispositions,
                #[cfg(feature = "linux")]
                request.container,
                run_spawner,
                progress,
                executable,
                &engine,
                &runtime,
                preview1_core_linker,
                shared_memory_pool,
                core_module_instance_pre_cache,
                launched_instance,
                output_mode,
                timeline,
            )
            .await;
            let _ = exit_tx.send(result);
        });
        if let Err(error) = launched {
            tracing::warn!(
                target: "helios_kernel::program",
                instance = ?instance_id,
                %error,
                "refused a program launch: the executor's instance task share is full"
            );
            return Err(ProgramExecError {
                kind: ProgramExecErrorKind::OutOfMemory,
                detail: ProgramExecErrorDetail::ExecutorTaskCapacityExhausted,
            });
        }

        let ChildStdio {
            stdin,
            stdout,
            stderr,
        } = stdio;
        let child = ChildHandle {
            instance_id,
            signal_state,
            stdin,
            stdout,
            stderr,
            exit: Some(exit_rx),
        };
        Ok(child)
    }

    /// Convenience wrapper: spawn a program, feed it `stdin`, drain its
    /// stdout and stderr into buffers, and return the collected output
    /// along with the exit code.
    pub(super) async fn exec_buffered(
        &self,
        compile: &CompileAuthority,
        exec_context: ProgramExecContext<CpuImpl, Net, StorageImpl>,
        source: ProgramSource,
        hint: Option<AotCompileHint>,
        stdin: Vec<u8>,
        launch: ProgramLaunch<Net, StorageImpl>,
    ) -> Result<ExecResult, ProgramExecError> {
        self.exec_buffered_with_snapshot(compile, exec_context, source, hint, stdin, launch)
            .await
            .map(|(result, _)| result)
    }

    async fn exec_buffered_with_snapshot(
        &self,
        compile: &CompileAuthority,
        exec_context: ProgramExecContext<CpuImpl, Net, StorageImpl>,
        source: ProgramSource,
        hint: Option<AotCompileHint>,
        stdin: Vec<u8>,
        launch: ProgramLaunch<Net, StorageImpl>,
    ) -> Result<(ExecResult, Option<MemoryFs>), ProgramExecError> {
        let executable = self
            .load_executable(
                compile,
                &exec_context,
                launch.argv.program_name(),
                &source,
                hint,
                &launch.timeline,
            )
            .await?;
        self.exec_loaded_buffered(exec_context, executable, stdin, launch)
            .await
    }

    async fn exec_loaded_buffered(
        &self,
        exec_context: ProgramExecContext<CpuImpl, Net, StorageImpl>,
        executable: ProgramExecutable<CpuImpl, Net, StorageImpl>,
        stdin: Vec<u8>,
        launch: ProgramLaunch<Net, StorageImpl>,
    ) -> Result<(ExecResult, Option<MemoryFs>), ProgramExecError> {
        let runtime_state = exec_context.runtime_state.clone();
        let instance_registry = exec_context.instance_registry.clone();
        let cpu = exec_context.cpu.clone();
        let max_output_bytes = runtime_state
            .settings()
            .get::<crate::process::BufferedExecOutputLimitSetting>();
        let mut child = self.spawn_loaded(exec_context, executable, launch)?;

        // Feed stdin in one shot, then close the writer to signal EOF.
        if let Some(writer) = child.take_stdin() {
            if !stdin.is_empty() {
                // The child may not have started draining yet, so this
                // waits for room rather than overrunning the channel.
                let _: Result<(), crate::ClosedPeer> = writer.write(stdin).await;
            }
            drop(writer);
        }

        drain_child_output_bounded(
            child,
            max_output_bytes,
            &runtime_state,
            &instance_registry,
            &cpu,
        )
        .await
    }

    pub(crate) async fn aot_to_file(
        &self,
        compile: &CompileAuthority,
        exec_context: &ProgramExecContext<CpuImpl, Net, StorageImpl>,
        wasm: &Bytes,
        hint: AotCompileHint,
        profile: bool,
        destination: AotDestination<StorageImpl>,
    ) -> Result<AotWritten, ProgramExecError> {
        let (output, worker_threads) = self
            .compile_raw_component(
                compile,
                exec_context,
                wasm,
                hint,
                profile,
                CompileOutputSink::WriteSignedFile(destination),
            )
            .await?;
        match output {
            CompileOutput::WrittenBytes(bytes) => Ok(AotWritten {
                bytes,
                worker_threads,
            }),
            CompileOutput::Payload(_) => unreachable!("WriteSignedFile returns WrittenBytes"),
        }
    }

    async fn load_executable(
        &self,
        compile: &CompileAuthority,
        exec_context: &ProgramExecContext<CpuImpl, Net, StorageImpl>,
        program: &str,
        source: &ProgramSource,
        hint: Option<AotCompileHint>,
        timeline: &phases::Timeline,
    ) -> Result<ProgramExecutable<CpuImpl, Net, StorageImpl>, ProgramExecError> {
        let write_serial = exec_context.write_serial;
        let started_at = monotonic_nanos(&self.inner.clock_cpu);
        timeline.record(&self.inner.clock_cpu, LaunchPhase::LoadBegin);
        let payload = match source {
            #[cfg(feature = "linux")]
            ProgramSource::LinuxElf(image) => {
                if hint.is_some() {
                    return Err(ProgramExecError {
                        kind: ProgramExecErrorKind::InvalidHint,
                        detail: ProgramExecErrorDetail::HintNotAllowedForPrecompiledArtifact,
                    });
                }
                let loaded = LinuxExecutable::load(&exec_context.cpu, image.clone())
                    .map(ProgramExecutable::Linux);
                timeline.record(&self.inner.clock_cpu, LaunchPhase::LoadComplete);
                return loaded;
            }
            ProgramSource::SignedArtifact(bytes) => {
                if hint.is_some() {
                    return Err(ProgramExecError {
                        kind: ProgramExecErrorKind::InvalidHint,
                        detail: ProgramExecErrorDetail::HintNotAllowedForPrecompiledArtifact,
                    });
                }
                trusted_signed_payload(bytes, &self.inner.cwasm_signing_key)?
            }
            ProgramSource::BootfsArtifact(bytes) => {
                if hint.is_some() {
                    return Err(ProgramExecError {
                        kind: ProgramExecErrorKind::InvalidHint,
                        detail: ProgramExecErrorDetail::HintNotAllowedForPrecompiledArtifact,
                    });
                }
                trusted_bootfs_payload(bytes)
            }
            ProgramSource::RawWasm(wasm) => {
                let _profile = artifact_profile::classify_raw_wasm(wasm)
                    .map_err(map_artifact_profile_error)?;
                let hint = hint.unwrap_or(AotCompileHint::Performance);
                let (output, _) = self
                    .compile_raw_component(
                        compile,
                        exec_context,
                        wasm,
                        hint,
                        false,
                        CompileOutputSink::ReturnPayload,
                    )
                    .await?;
                match output {
                    CompileOutput::Payload(payload) => Bytes::from(payload),
                    CompileOutput::WrittenBytes(_) => {
                        unreachable!("ReturnPayload returns Payload")
                    }
                }
            }
        };
        timeline.record(&self.inner.clock_cpu, LaunchPhase::ArtifactTrust);
        let loaded =
            self.load_precompiled_executable(program, payload, write_serial, started_at, timeline);
        timeline.record(&self.inner.clock_cpu, LaunchPhase::LoadComplete);
        loaded
    }

    fn load_precompiled_executable(
        &self,
        program: &str,
        payload: Bytes,
        write_serial: crate::DebugSerialWriter,
        started_at: u64,
        timeline: &phases::Timeline,
    ) -> Result<ProgramExecutable<CpuImpl, Net, StorageImpl>, ProgramExecError> {
        match WasmtimePrecompiledKind::detect(&payload) {
            Some(WasmtimePrecompiledKind::Component) => self
                .load_precompiled_component(program, payload, write_serial, started_at, timeline)
                .map(ProgramExecutable::Component),
            Some(WasmtimePrecompiledKind::CoreModule) => self
                .load_precompiled_core_module(program, payload, write_serial, started_at, timeline)
                .map(ProgramExecutable::CoreModule),
            None => Err(ProgramExecError {
                kind: ProgramExecErrorKind::InvalidBinary,
                detail: ProgramExecErrorDetail::InvalidRuntimeArtifact,
            }),
        }
    }

    fn load_precompiled_component(
        &self,
        program: &str,
        payload: Bytes,
        write_serial: crate::DebugSerialWriter,
        started_at: u64,
        timeline: &phases::Timeline,
    ) -> Result<PreparedComponent<CpuImpl, Net, StorageImpl>, ProgramExecError> {
        let cached = self.inner.component_cache.lock().get(&payload);
        timeline.record_hit(
            &self.inner.clock_cpu,
            LaunchPhase::CacheLookup,
            cached.is_some(),
        );
        let component = if let Some(component) = cached {
            super::emit_program_stage_marker(write_serial, "program:deserialize-cache-hit");
            let now = monotonic_nanos(&self.inner.clock_cpu);
            tracing::debug!(
                target: "helios_component_host::program_host",
                phase = "deserialize-component",
                cache = "hit",
                cwasm_bytes = payload.len(),
                elapsed_ms = elapsed_millis(started_at, now),
                "program component deserialization cache hit"
            );
            component
        } else {
            super::emit_program_stage_marker(write_serial, "program:deserialize-begin");
            tracing::debug!(
                target: "helios_component_host::program_host",
                phase = "deserialize-component",
                cache = "miss",
                cwasm_bytes = payload.len(),
                "program component deserialization started"
            );
            match WasmtimePrecompiledKind::detect(&payload) {
                Some(WasmtimePrecompiledKind::Component) => {}
                Some(WasmtimePrecompiledKind::CoreModule) => {
                    return Err(ProgramExecError {
                        kind: ProgramExecErrorKind::InvalidBinary,
                        detail: ProgramExecErrorDetail::InvalidRuntimeArtifact,
                    });
                }
                None => {
                    return Err(ProgramExecError {
                        kind: ProgramExecErrorKind::InvalidBinary,
                        detail: ProgramExecErrorDetail::InvalidRuntimeArtifact,
                    });
                }
            }
            let compiled = self.deserialize_component(&payload)?;
            timeline.record(&self.inner.clock_cpu, LaunchPhase::Deserialize);
            super::emit_program_stage_marker(write_serial, "program:deserialize-end");
            let code = self
                .inner
                .code_map
                .register_component(program, &compiled.component);
            let component = Arc::new(ProgramComponent {
                compiled,
                _code: code,
            });
            let now = monotonic_nanos(&self.inner.clock_cpu);
            tracing::debug!(
                target: "helios_component_host::program_host",
                phase = "deserialize-component",
                cache = "miss",
                cwasm_bytes = payload.len(),
                elapsed_ms = elapsed_millis(started_at, now),
                "program component deserialized"
            );
            self.inner
                .component_cache
                .lock()
                .insert_if_missing(payload.clone(), component)
        };

        let cached_pre = self.inner.component_instance_pre_cache.lock().get(&payload);
        let hit = cached_pre.is_some();
        let instance_pre = if let Some(instance_pre) = cached_pre {
            super::emit_program_stage_marker(write_serial, "program:instantiate-pre-cache-hit");
            instance_pre
        } else {
            super::emit_program_stage_marker(write_serial, "program:instantiate-pre-begin");
            let linker = super::component_linker(
                self.inner.engine.raw(),
                ComponentBindingSet::Program,
                &component.compiled.component,
            )
            .map_err(map_program_runtime_error)?;
            let instance_pre = Arc::new(
                linker
                    .instantiate_pre(&component.compiled.component)
                    .map_err(map_program_runtime_error)?,
            );
            super::emit_program_stage_marker(write_serial, "program:instantiate-pre-end");
            self.inner
                .component_instance_pre_cache
                .lock()
                .insert_if_missing(payload, instance_pre)
        };
        timeline.record_hit(&self.inner.clock_cpu, LaunchPhase::InstantiatePre, hit);
        Ok(instance_pre)
    }

    fn load_precompiled_core_module(
        &self,
        program: &str,
        payload: Bytes,
        write_serial: crate::DebugSerialWriter,
        started_at: u64,
        timeline: &phases::Timeline,
    ) -> Result<Arc<WasmtimeCompiledCoreModule>, ProgramExecError> {
        let cached = self.inner.core_module_cache.lock().get(&payload);
        timeline.record_hit(
            &self.inner.clock_cpu,
            LaunchPhase::CacheLookup,
            cached.is_some(),
        );
        if let Some(module) = cached {
            super::emit_program_stage_marker(write_serial, "program:deserialize-core-cache-hit");
            let now = monotonic_nanos(&self.inner.clock_cpu);
            tracing::debug!(
                target: "helios_component_host::program_host",
                phase = "deserialize-core-module",
                cache = "hit",
                cwasm_bytes = payload.len(),
                elapsed_ms = elapsed_millis(started_at, now),
                "program core module deserialization cache hit"
            );
            return Ok(module);
        }

        super::emit_program_stage_marker(write_serial, "program:deserialize-core-begin");
        // SAFETY: `payload` comes from bootfs, a signature-verified `cwasm`, or the in-kernel
        // compiler plugin targeting this engine's configuration.
        let module = unsafe { Module::deserialize(self.inner.engine.raw(), payload.as_ref()) }
            .map_err(map_program_runtime_error)?;
        validate_preview1_program_module_imports(&module)?;
        super::emit_program_stage_marker(write_serial, "program:deserialize-core-end");
        timeline.record(&self.inner.clock_cpu, LaunchPhase::Deserialize);
        let code = self.inner.code_map.register_module(program, &module);
        let compiled = Arc::new(WasmtimeCompiledCoreModule {
            cache_key: payload.clone(),
            module,
            _code: code,
        });
        let now = monotonic_nanos(&self.inner.clock_cpu);
        tracing::debug!(
            target: "helios_component_host::program_host",
            phase = "deserialize-core-module",
            cache = "miss",
            cwasm_bytes = payload.len(),
            elapsed_ms = elapsed_millis(started_at, now),
            "program core module deserialized"
        );
        Ok(self
            .inner
            .core_module_cache
            .lock()
            .insert_if_missing(payload, compiled))
    }

    fn deserialize_component(
        &self,
        payload: &[u8],
    ) -> Result<WasmtimeCompiledComponent, ProgramExecError> {
        // SAFETY: `payload` comes from bootfs, a signature-verified `cwasm`, or the in-kernel
        // compiler plugin targeting this engine's configuration.
        let component = unsafe { Component::deserialize(self.inner.engine.raw(), payload) }
            .map_err(|error| {
                tracing::error!(?error, "program component deserialization failed");
                ProgramExecError {
                    kind: ProgramExecErrorKind::InvalidBinary,
                    detail: ProgramExecErrorDetail::RuntimeFailure(RuntimeMessage::of(&error)),
                }
            })?;
        let imports = WasiImportSet::from_component(self.inner.engine.raw(), &component);
        for import in imports.names() {
            artifact_profile::validate_component_import_name(import)
                .map_err(map_artifact_profile_error)?;
        }
        Ok(WasmtimeCompiledComponent { component })
    }

    async fn compile_raw_component(
        &self,
        compile: &CompileAuthority,
        exec_context: &ProgramExecContext<CpuImpl, Net, StorageImpl>,
        wasm: &Bytes,
        hint: AotCompileHint,
        profile: bool,
        sink: CompileOutputSink<StorageImpl>,
    ) -> Result<(CompileOutput, u32), ProgramExecError> {
        let _ = compile;
        let limit = exec_context
            .runtime_state
            .settings()
            .get::<crate::CompilerMaxInputBytesSetting>();
        check_compiler_input_limit(wasm.len() as u64, limit)?;
        let phases = CompilerPhaseTimestamps {
            processor: if profile {
                helios_hal::cpu::current_processor().id()
            } else {
                0
            },
            entered_ns: if profile {
                monotonic_nanos(&exec_context.cpu)
            } else {
                0
            },
            ..CompilerPhaseTimestamps::default()
        };
        let registration = self
            .compiler_provider_registration()
            .ok_or(ProgramExecError {
                kind: ProgramExecErrorKind::Unavailable,
                detail: ProgramExecErrorDetail::CompilerUnavailable,
            })?;
        let job = CompileJob {
            compiler_generation: registration.generation,
            compiler_name: registration.name,
            compiler_path: registration.path,
            compiler_payload: registration.payload,
            compiler_oom_policy: registration.oom_policy,
            compiler_parent_instance_id: registration.parent_instance_id,
            wasm: wasm.clone(),
            hint,
            profile,
            sink,
        };
        // The compile runs in a task of its own, whichever route asked for
        // it, and this call holds only the receiving half of its reply: the
        // compile outlives a requester that stops waiting, and stops itself
        // when that happens (`run_shared_memory_session`).
        let (reply, artifact) = futures::channel::oneshot::channel();
        exec_context.spawner.spawn_detached({
            let service = self.clone();
            let exec_context = exec_context.clone();
            async move {
                service
                    .compile_session(&exec_context, job, phases, reply)
                    .await;
            }
        });
        match artifact.await {
            Ok(result) => result,
            Err(_) => Err(ProgramExecError {
                kind: ProgramExecErrorKind::Internal,
                detail: ProgramExecErrorDetail::CompileSessionEnded,
            }),
        }
    }

    /// The compile session task: waits for the session slot, runs the compile
    /// with core affinity until every worker is joined, condemns the compile
    /// if its requester leaves, and replies with the output.
    async fn compile_session(
        &self,
        exec_context: &ProgramExecContext<CpuImpl, Net, StorageImpl>,
        job: CompileJob<StorageImpl>,
        phases: CompilerPhaseTimestamps,
        reply: futures::channel::oneshot::Sender<Result<(CompileOutput, u32), ProgramExecError>>,
    ) {
        let profile = job.profile;
        run_shared_memory_session(
            &self.inner.compile_slot,
            reply,
            || {
                let started_at = exec_context
                    .runtime_state
                    .uptime_nanos(exec_context.cpu.now().ticks());
                let instance = exec_context.instance_registry.register_child_with_policy(
                    job.compiler_parent_instance_id,
                    job.compiler_name.clone(),
                    started_at,
                    job.compiler_oom_policy,
                );
                let condemn = {
                    let registry = exec_context.instance_registry.clone();
                    let interrupts = self.inner.engine.interrupts().clone();
                    let cpu = exec_context.cpu.clone();
                    let runtime_state = exec_context.runtime_state.clone();
                    let id = instance.id();
                    move || {
                        condemn_session(
                            &registry,
                            &interrupts,
                            id,
                            crate::KillReason::RequesterGone,
                            runtime_state.uptime_nanos(cpu.now().ticks()),
                        );
                    }
                };
                (
                    condemn,
                    self.run_compile(exec_context, job, instance, phases),
                )
            },
            |end| self.finish_compiled(exec_context, profile, end),
        )
        .await;
    }

    /// Reports compile phases and hands back the compiled output.
    fn finish_compiled(
        &self,
        exec_context: &ProgramExecContext<CpuImpl, Net, StorageImpl>,
        profile: bool,
        end: CompileEnd,
    ) -> Result<(CompileOutput, u32), ProgramExecError> {
        let CompileEnd {
            result,
            worker_threads,
            phases,
        } = end;
        let (output, thread_reports) = result?;
        if profile {
            let output_bytes = match &output {
                CompileOutput::Payload(payload) => payload.len(),
                CompileOutput::WrittenBytes(bytes) => *bytes,
            };
            emit_compiler_phase_report(
                exec_context.write_serial,
                phases,
                &thread_reports,
                output_bytes,
            );
        }
        Ok((output, worker_threads))
    }

    /// The compile proper, run with the compile slot held: the plugin's call,
    /// then the join of every core-pinned worker task the plugin spawned, so the
    /// slot is never released while one still runs on the plugin's memory.
    async fn run_compile(
        &self,
        exec_context: &ProgramExecContext<CpuImpl, Net, StorageImpl>,
        job: CompileJob<StorageImpl>,
        instance: crate::RegisteredInstance,
        mut phases: CompilerPhaseTimestamps,
    ) -> CompileEnd {
        let CompileJob {
            compiler_generation,
            compiler_name: _,
            compiler_path,
            compiler_payload,
            compiler_oom_policy: _,
            compiler_parent_instance_id: _,
            wasm,
            hint,
            profile,
            sink,
        } = job;
        phases.slot_acquired_ns = if profile {
            monotonic_nanos(&exec_context.cpu)
        } else {
            0
        };
        let affinity_plan = CoreAffinityPlan::capture(
            &exec_context.cpu,
            exec_context.spawner.processor_control().online_set(),
            helios_hal::cpu::current_processor(),
        );
        let worker_threads = affinity_plan.worker_count();
        let result = self
            .invoke_compiler_inner(
                exec_context,
                compiler_generation,
                &compiler_path,
                &compiler_payload,
                instance,
                CompileRequest {
                    wasm,
                    guest_isa: self.inner.guest_isa,
                    hint,
                    profile,
                    sink,
                },
                affinity_plan,
                &mut phases,
            )
            .await;
        // A failure of the main thread has condemned the compile
        // (`end_main_part`), so the workers parked in the pool end and are
        // joined; the first trap's error is the one reported.
        let mut thread_reports = self.await_compiler_thread_tasks().await;
        let result = first_trap_wins(result, &mut thread_reports);
        phases.tasks_joined_ns = if profile {
            monotonic_nanos(&exec_context.cpu)
        } else {
            0
        };
        // On a kill or fatal-state error, drop the cached runtime for this
        // generation so the next compile rebuilds from the currently installed
        // compiler provider artifact.
        if let Err(error) = &result
            && plugin_runtime_should_be_recycled(error)
        {
            tracing::warn!(
                target: "helios_kernel::supervisor",
                detail = %error.detail,
                generation = compiler_generation,
                "compiler plugin runtime invalidated; next compile rebuilds from scratch"
            );
            let mut slot = self.inner.compiler_plugin.lock();
            if slot
                .as_ref()
                .is_some_and(|cached| cached.generation == compiler_generation)
            {
                *slot = None;
            }
        }
        CompileEnd {
            result: result.map(|payload| (payload, thread_reports)),
            worker_threads,
            phases,
        }
    }

    async fn await_compiler_thread_tasks(&self) -> CompilerThreadReports {
        let mut reports = CompilerThreadReports::new();
        loop {
            let tasks = self
                .inner
                .compiler_plugin
                .lock()
                .as_ref()
                .map(|plugin| {
                    plugin
                        .shared
                        .thread_tasks
                        .lock()
                        .drain(..)
                        .collect::<CompilerThreadTasks>()
                })
                .unwrap_or_default();
            if tasks.is_empty() {
                break;
            }
            for task in tasks {
                reports.push(task.await);
            }
        }
        reports
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "internal compile-session handoff carries provider metadata and timing state"
    )]
    async fn invoke_compiler_inner(
        &self,
        exec_context: &ProgramExecContext<CpuImpl, Net, StorageImpl>,
        compiler_generation: u64,
        compiler_path: &str,
        compiler_payload: &Bytes,
        compiler_instance: crate::RegisteredInstance,
        request: CompileRequest<StorageImpl>,
        affinity_plan: CoreAffinityPlan,
        phases: &mut CompilerPhaseTimestamps,
    ) -> Result<CompileOutput, ProgramExecError> {
        let profile = request.profile;
        let (plugin, plugin_cached) = self
            .ensure_compiler_plugin(
                exec_context,
                compiler_generation,
                compiler_path,
                compiler_payload,
                affinity_plan.worker_count(),
            )
            .await?;
        plugin.shared.begin_session(&affinity_plan);
        phases.plugin_cached = plugin_cached;
        phases.plugin_ready_ns = if profile {
            monotonic_nanos(&exec_context.cpu)
        } else {
            0
        };
        let context = CompilerCompileContext {
            cpu: exec_context.cpu.clone(),
            spawner: exec_context.spawner.clone(),
            runtime_state: exec_context.runtime_state.clone(),
            instance: compiler_instance,
            registry: exec_context.instance_registry.clone(),
            shared: plugin.shared.clone(),
            affinity_plan: affinity_plan.clone(),
            write_serial: exec_context.write_serial,
            _marker: core::marker::PhantomData,
        };
        // Pin the compile's main store to `affinity_plan.main()` so main and all
        // workers execute deterministically across the live `Kernel` cores.
        let main_core = affinity_plan.main();
        let (result, updated_phases) = affinity_plan
            .spawn_pinned(&exec_context.spawner, main_core, {
                let service = self.clone();
                let exec_context = exec_context.clone();
                let context = context.clone();
                let mut local_phases = *phases;
                async move {
                    let result = service
                        .run_main_thread(
                            &exec_context,
                            &plugin,
                            context,
                            request,
                            &mut local_phases,
                        )
                        .await;
                    (result, local_phases)
                }
            })
            .await;
        *phases = updated_phases;
        context.end_main_part(result)
    }

    /// The compile's main thread: its store, the plugin's initialisation and
    /// the `compile` call, whose rayon workers run on stores of their own.
    async fn run_main_thread(
        &self,
        exec_context: &ProgramExecContext<CpuImpl, Net, StorageImpl>,
        plugin: &CompilerPluginHandle<CpuImpl, Net, StorageImpl>,
        context: CompilerCompileContext<CpuImpl, Net, StorageImpl>,
        request: CompileRequest<StorageImpl>,
        phases: &mut CompilerPhaseTimestamps,
    ) -> Result<CompileOutput, ProgramExecError> {
        let profile = request.profile;
        let engine = self.inner.engine.raw();
        let store_data = CompilerCoreStore::new(context);
        let mut store = wasmtime::Store::new(engine, store_data);
        let drive = configure_compiler_core_store(&mut store);
        let instance = drive
            .instantiate(&mut store, &plugin.instance_pre)
            .await
            .map_err(map_program_runtime_error)?;
        let tls_base = plugin.main_thread_tls_base;
        set_compiler_tls_base(&mut store, &instance, tls_base)?;
        let pthread_self_offset = {
            let pthread_self_offset = instance
                .get_typed_func::<(), i32>(&mut store, HELIOS_COMPILER_PTHREAD_SELF_OFFSET)
                .map_err(map_program_runtime_error)?;
            drive
                .call(&mut store, &pthread_self_offset, ())
                .await
                .map_err(map_program_runtime_error)? as u32
        };
        let thread_pointer = tls_base
            .checked_add(pthread_self_offset)
            .ok_or(ProgramExecError {
                kind: ProgramExecErrorKind::Internal,
                detail: ProgramExecErrorDetail::CompilerThreadPointerOverflow,
            })?;
        let initialize = instance
            .get_typed_func::<i32, ()>(&mut store, HELIOS_COMPILER_INITIALIZE)
            .map_err(map_program_runtime_error)?;
        drive
            .call(&mut store, &initialize, thread_pointer as i32)
            .await
            .map_err(map_program_runtime_error)?;
        let exports = CompilerExports {
            alloc: instance
                .get_typed_func::<(i32, i32), i32>(&mut store, HELIOS_COMPILER_ALLOC)
                .map_err(map_program_runtime_error)?,
            free: instance
                .get_typed_func::<(i32, i32, i32), ()>(&mut store, HELIOS_COMPILER_FREE)
                .map_err(map_program_runtime_error)?,
            compile: instance
                .get_typed_func::<(i32, i32), i32>(&mut store, HELIOS_COMPILER_COMPILE)
                .map_err(map_program_runtime_error)?,
            outstanding: instance
                .get_typed_func::<(), i32>(&mut store, HELIOS_COMPILER_OUTSTANDING_BYTES)
                .map_err(map_program_runtime_error)?,
        };
        phases.instantiated_ns = if profile {
            monotonic_nanos(&exec_context.cpu)
        } else {
            0
        };
        let outstanding_before =
            compiler_outstanding_bytes(&drive, &mut store, &exports.outstanding).await?;
        let mut allocations = CompilerAllocations::new();
        let outcome = self
            .call_compiler(
                &drive,
                &mut store,
                &exports,
                &mut allocations,
                request,
                phases,
            )
            .await;
        // A call into the plugin that failed leaves its allocator in an
        // unknown state, so nothing is freed and the memory dies with the
        // runtime; every other end returns the call's allocations. A release
        // that fails, or leaves the plugin's count off its starting level,
        // comes before the compile's own result: it says the plugin's memory
        // can no longer be trusted, which is what discards the runtime.
        let result = outcome?;
        allocations
            .release(&drive, &mut store, &exports.free)
            .await?;
        let outstanding_after =
            compiler_outstanding_bytes(&drive, &mut store, &exports.outstanding).await?;
        ensure_compiler_buffers_returned(outstanding_before, outstanding_after)?;
        result
    }

    /// Runs one compile against the plugin instance: allocates the request,
    /// calls `compile`, and copies the response out. The caller owns
    /// `allocations` and releases them according to the returned
    /// [`CompilerCallOutcome`].
    async fn call_compiler(
        &self,
        drive: &CompilerStoreDrive<CpuImpl>,
        store: &mut wasmtime::Store<CompilerCoreStore<CpuImpl, Net, StorageImpl>>,
        exports: &CompilerExports,
        allocations: &mut CompilerAllocations,
        request: CompileRequest<StorageImpl>,
        phases: &mut CompilerPhaseTimestamps,
    ) -> CompilerCallOutcome {
        let CompileRequest {
            wasm,
            guest_isa,
            hint,
            profile,
            sink,
        } = request;
        let target = guest_isa.compile_target();
        let isa_level = target.level().name().as_bytes();
        let target = target.triple().as_bytes();
        let wasm_len = match compiler_abi_u32(wasm.len()) {
            Ok(len) => len,
            Err(error) => return Ok(Err(error)),
        };
        let target_len = match compiler_abi_u32(target.len()) {
            Ok(len) => len,
            Err(error) => return Ok(Err(error)),
        };
        let isa_level_len = match compiler_abi_u32(isa_level.len()) {
            Ok(len) => len,
            Err(error) => return Ok(Err(error)),
        };
        let wasm_ptr = allocations
            .alloc(drive, &mut *store, &exports.alloc, wasm.len(), 1)
            .await?;
        let target_ptr = allocations
            .alloc(drive, &mut *store, &exports.alloc, target.len(), 1)
            .await?;
        let isa_level_ptr = allocations
            .alloc(drive, &mut *store, &exports.alloc, isa_level.len(), 1)
            .await?;
        let request_ptr = allocations
            .alloc(
                drive,
                &mut *store,
                &exports.alloc,
                CompilerRequestHeader::SIZE,
                CompilerRequestHeader::ALIGN,
            )
            .await?;
        // From here to the response, only host-side work can fail apart from
        // the `compile` call itself, so a failure is the inner `Err`.
        let header = CompilerRequestHeader {
            abi_version: HELIOS_COMPILER_ABI_VERSION,
            hint: u32::from(match hint {
                AotCompileHint::Balanced => CompilerAbiHint::Balanced,
                AotCompileHint::Performance => CompilerAbiHint::Performance,
            }),
            wasm_ptr,
            wasm_len,
            target_ptr,
            target_len,
            isa_level_ptr,
            isa_level_len,
            flags: if profile {
                helios_compiler_abi::HELIOS_COMPILER_REQUEST_PROFILE
            } else {
                0
            },
        };
        // The instance is off every processor between its calls, so the
        // request is written during one of its turns (`in_guest_turn`).
        let memory = Preview1AsyncMemory::of_shared(store.data().memory());
        let written = in_guest_turn(store.data().guest_turns(), async {
            memory
                .write_bytes(GuestAddress::wasm32(wasm_ptr), &wasm)
                .await?;
            memory
                .write_bytes(GuestAddress::wasm32(target_ptr), target)
                .await?;
            memory
                .write_bytes(GuestAddress::wasm32(isa_level_ptr), isa_level)
                .await?;
            memory
                .write_bytes(GuestAddress::wasm32(request_ptr), &header.to_bytes())
                .await
        })
        .await;
        if let Err(error) = written {
            return Ok(Err(error));
        }
        phases.input_done_ns = if profile {
            monotonic_nanos(&store.data().context.cpu)
        } else {
            0
        };
        phases.compile_started_ns = if profile {
            monotonic_nanos(&store.data().context.cpu)
        } else {
            0
        };
        let response_ptr = drive
            .call(
                &mut *store,
                &exports.compile,
                (request_ptr as i32, CompilerRequestHeader::SIZE as i32),
            )
            .await;
        phases.compile_returned_ns = if profile {
            monotonic_nanos(&store.data().context.cpu)
        } else {
            0
        };
        let response_ptr = response_ptr.map_err(map_program_runtime_error)? as u32;
        Ok(compiler::accept_compiler_response(
            store.data(),
            allocations,
            response_ptr,
            profile,
            sink,
            &self.inner.cwasm_signing_key,
            phases,
        )
        .await)
    }

    /// Build the compiler kernel-plugin runtime on first compile for a
    /// provider generation, reuse it for subsequent compiles of the same
    /// generation. The cached `wasmtime::Module`, `InstancePre` and
    /// `SharedMemory` are stable across calls; per-call work drops to a fresh
    /// `wasmtime::Store` and `instance_pre.instantiate`.
    ///
    /// Called only with the compile slot held, which is what makes the
    /// build exclusive: nothing else builds or discards the cached runtime
    /// between the check below and the store at the end, so the cache's
    /// lock is never held across the build's awaits.
    async fn ensure_compiler_plugin(
        &self,
        exec_context: &ProgramExecContext<CpuImpl, Net, StorageImpl>,
        compiler_generation: u64,
        compiler_path: &str,
        compiler_payload: &Bytes,
        worker_threads: u32,
    ) -> Result<(CompilerPluginHandle<CpuImpl, Net, StorageImpl>, bool), ProgramExecError> {
        let cached = self.inner.compiler_plugin.lock().clone();
        if let Some(plugin) = cached
            && plugin.generation == compiler_generation
        {
            return Ok((plugin, true));
        }

        // The compiler plugin is a precompiled core module; a component
        // or anything else is not the artifact this builds a runtime for.
        if !matches!(
            WasmtimePrecompiledKind::detect(compiler_payload),
            Some(WasmtimePrecompiledKind::CoreModule)
        ) {
            return Err(ProgramExecError {
                kind: ProgramExecErrorKind::InvalidBinary,
                detail: ProgramExecErrorDetail::CompilerPluginInvalid,
            });
        }

        tracing::info!(
            worker_threads,
            generation = compiler_generation,
            path = compiler_path,
            "building cached compiler plugin runtime"
        );

        let engine = self.inner.engine.raw();
        // SAFETY: `compiler_payload` is the precompiled compiler plugin read from bootfs.
        let module = unsafe { Module::deserialize(engine, compiler_payload.as_ref()) }
            .map_err(map_program_runtime_error)?;
        let code = self.inner.code_map.register_module(compiler_path, &module);
        let shared_memory = compiler_shared_memory(engine, &module)?;
        let shared = Arc::new(SharedMemoryCoreShared::new(
            shared_memory.clone(),
            crate::EntropyPool::derive(exec_context.runtime_state.root_entropy(), 0),
            self.inner.engine.interrupts().clone(),
            worker_threads,
        ));
        let mut linker: CoreLinker<CompilerCoreStore<CpuImpl, Net, StorageImpl>> =
            CoreLinker::new(engine);
        add_compiler_core_imports(&mut linker, shared_memory.clone())?;

        // `linker.define` requires an `AsContext<Data = T>`; build a
        // throwaway store solely to satisfy that bound. The store has no
        // role beyond `define_compiler_shared_memory`; its transient
        // `RegisteredInstance` (named "compiler-plugin-init") deregisters
        // on drop at the end of this method.
        let scratch_started_at = exec_context
            .runtime_state
            .uptime_nanos(exec_context.cpu.now().ticks());
        let scratch_instance = exec_context.instance_registry.register_with_policy(
            "compiler-plugin-init",
            scratch_started_at,
            crate::OomPolicy::KernelPlugin,
        );
        let scratch_store_data = CompilerCoreStore::new(CompilerCompileContext {
            cpu: exec_context.cpu.clone(),
            spawner: exec_context.spawner.clone(),
            runtime_state: exec_context.runtime_state.clone(),
            instance: scratch_instance,
            registry: exec_context.instance_registry.clone(),
            shared: shared.clone(),
            affinity_plan: CoreAffinityPlan::single(exec_context.cpu.bootstrap_processor()),
            write_serial: exec_context.write_serial,
            _marker: core::marker::PhantomData,
        });
        let mut scratch_store = wasmtime::Store::new(engine, scratch_store_data);
        define_compiler_shared_memory(&mut linker, &scratch_store, &module, shared_memory)?;

        let instance_pre = Arc::new(
            linker
                .instantiate_pre(&module)
                .map_err(map_program_runtime_error)?,
        );
        let scratch_drive = configure_compiler_core_store(&mut scratch_store);
        let scratch_instance = scratch_drive
            .instantiate(&mut scratch_store, &instance_pre)
            .await
            .map_err(map_program_runtime_error)?;
        let main_thread_tls_base = compiler_tls_base(&mut scratch_store, &scratch_instance)?;
        if main_thread_tls_base == 0 {
            tracing::error!("compiler plugin start did not publish a static TLS block");
            return Err(ProgramExecError {
                kind: ProgramExecErrorKind::InvalidBinary,
                detail: ProgramExecErrorDetail::CompilerPluginInvalid,
            });
        }
        drop(scratch_drive);
        drop(scratch_store);
        shared.instance_pre.call_once(|| instance_pre.clone());

        let _ = module; // InstancePre holds the Module via Arc internally.
        let plugin = Arc::new(CompilerPluginRuntime {
            generation: compiler_generation,
            instance_pre,
            shared,
            main_thread_tls_base,
            _code: code,
        });
        *self.inner.compiler_plugin.lock() = Some(plugin.clone());
        Ok((plugin, false))
    }
}

fn emit_compiler_phase_report(
    write_serial: crate::DebugSerialWriter,
    phases: CompilerPhaseTimestamps,
    thread_reports: &CompilerThreadReports,
    output_bytes: usize,
) {
    write_serial.emit_fmt(format_args!(
        "aot-phases processor={} plugin_cached={} slot_us={} plugin_us={} instantiate_us={} input_us={} compile_us={} diagnostic_us={} output_copy_us={} join_us={} sign_us={} output_bytes={}\n",
        phases.processor,
        phases.plugin_cached,
        phase_us(phases.entered_ns, phases.slot_acquired_ns),
        phase_us(phases.slot_acquired_ns, phases.plugin_ready_ns),
        phase_us(phases.plugin_ready_ns, phases.instantiated_ns),
        phase_us(phases.instantiated_ns, phases.input_done_ns),
        phase_us(phases.compile_started_ns, phases.compile_returned_ns),
        phase_us(phases.compile_returned_ns, phases.diagnostic_done_ns),
        phase_us(phases.diagnostic_done_ns, phases.response_done_ns),
        phase_us(phases.response_done_ns, phases.tasks_joined_ns),
        phase_us(phases.tasks_joined_ns, phases.signed_ns),
        output_bytes,
    ));
    for report in thread_reports {
        write_serial.emit_fmt(format_args!(
            "aot-thread id={} processor={} queued_us={} instantiate_us={} run_us={} start_after_compile_begin_us={} finish_after_compile_end_us={}\n",
            report.thread_id,
            report.processor,
            phase_us(report.spawned_ns, report.started_ns),
            phase_us(report.started_ns, report.instantiated_ns),
            phase_us(report.instantiated_ns, report.finished_ns),
            signed_phase_us(phases.compile_started_ns, report.started_ns),
            signed_phase_us(phases.compile_returned_ns, report.finished_ns),
        ));
    }
}

fn phase_us(started_ns: u64, finished_ns: u64) -> u64 {
    finished_ns.saturating_sub(started_ns) / 1_000
}

fn signed_phase_us(started_ns: u64, finished_ns: u64) -> i64 {
    if finished_ns >= started_ns {
        phase_us(started_ns, finished_ns).min(i64::MAX as u64) as i64
    } else {
        -(phase_us(finished_ns, started_ns).min(i64::MAX as u64) as i64)
    }
}

impl<CpuImpl, Net, StorageImpl> ProgramExecContext<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    pub(crate) fn from_store(store: &StoreData<CpuImpl, Net, StorageImpl>) -> Self {
        Self {
            cpu: store.cpu.clone(),
            timer: store.timer(),
            // The launch path funds a child instance from a fresh
            // instance share; what it needs from the parent is the
            // processor its tasks will live on.
            spawner: store.spawner().launch_spawner().clone(),
            runtime_state: store.runtime_state.clone(),
            instance_registry: store.instance_registry.clone(),
            parent_instance_id: Some(store.instance().id()),
            read_serial: store.serial_reader_fn(),
            write_serial: store.serial_writer(),
        }
    }
}

const P1_RIGHT_FD_DATASYNC: u64 = 1 << 0;
const P1_RIGHT_FD_READ: u64 = 1 << 1;
const P1_RIGHT_FD_SEEK: u64 = 1 << 2;
const P1_RIGHT_FD_FDSTAT_SET_FLAGS: u64 = 1 << 3;
const P1_RIGHT_FD_SYNC: u64 = 1 << 4;
const P1_RIGHT_FD_TELL: u64 = 1 << 5;
const P1_RIGHT_FD_WRITE: u64 = 1 << 6;
const P1_RIGHT_FD_ADVISE: u64 = 1 << 7;
const P1_RIGHT_FD_ALLOCATE: u64 = 1 << 8;
const P1_RIGHT_PATH_CREATE_DIRECTORY: u64 = 1 << 9;
const P1_RIGHT_PATH_CREATE_FILE: u64 = 1 << 10;
const P1_RIGHT_PATH_LINK_SOURCE: u64 = 1 << 11;
const P1_RIGHT_PATH_LINK_TARGET: u64 = 1 << 12;
const P1_RIGHT_PATH_OPEN: u64 = 1 << 13;
const P1_RIGHT_FD_READDIR: u64 = 1 << 14;
const P1_RIGHT_PATH_READLINK: u64 = 1 << 15;
const P1_RIGHT_PATH_RENAME_SOURCE: u64 = 1 << 16;
const P1_RIGHT_PATH_RENAME_TARGET: u64 = 1 << 17;
const P1_RIGHT_PATH_FILESTAT_GET: u64 = 1 << 18;
const P1_RIGHT_PATH_FILESTAT_SET_SIZE: u64 = 1 << 19;
const P1_RIGHT_PATH_FILESTAT_SET_TIMES: u64 = 1 << 20;
const P1_RIGHT_FD_FILESTAT_GET: u64 = 1 << 21;
const P1_RIGHT_FD_FILESTAT_SET_SIZE: u64 = 1 << 22;
const P1_RIGHT_FD_FILESTAT_SET_TIMES: u64 = 1 << 23;
const P1_RIGHT_PATH_SYMLINK: u64 = 1 << 24;
const P1_RIGHT_PATH_REMOVE_DIRECTORY: u64 = 1 << 25;
const P1_RIGHT_PATH_UNLINK_FILE: u64 = 1 << 26;
const P1_RIGHT_POLL_FD_READWRITE: u64 = 1 << 27;
const P1_FDFLAG_APPEND: u16 = 1 << 0;
const P1_FDFLAG_DSYNC: u16 = 1 << 1;
const P1_FDFLAG_NONBLOCK: u16 = 1 << 2;
const P1_FDFLAG_RSYNC: u16 = 1 << 3;
const P1_FDFLAG_SYNC: u16 = 1 << 4;
const P1_FILE_FDFLAGS: u16 =
    P1_FDFLAG_APPEND | P1_FDFLAG_DSYNC | P1_FDFLAG_NONBLOCK | P1_FDFLAG_RSYNC | P1_FDFLAG_SYNC;
const P1_SOCKET_FDFLAGS: u16 = P1_FDFLAG_NONBLOCK;
const WASIX_FDFLAGSEXT_CLOEXEC: u16 = 1 << 0;
const WASIX_EVENTFDFLAG_SEMAPHORE: u32 = 1 << 0;
const WASIX_OPTION_NONE: u8 = 0;
const WASIX_OPTION_SOME: u8 = 1;
const WASIX_OPTION_UNION_U32_OFFSET: u32 = 4;
const WASIX_OPTION_UNION_U64_OFFSET: u32 = 8;
const WASIX_STDIO_MODE_PIPED: i32 = 0;
const WASIX_STDIO_MODE_INHERIT: i32 = 1;
const WASIX_STDIO_MODE_NULL: i32 = 2;
const WASIX_STDIO_MODE_LOG: i32 = 3;
const WASIX_PROCESS_HANDLES_STDIN_OFFSET: u32 = 4;
const WASIX_PROCESS_HANDLES_STDOUT_OFFSET: u32 = 12;
const WASIX_PROCESS_HANDLES_STDERR_OFFSET: u32 = 20;
const WASIX_JOIN_FLAG_NON_BLOCKING: u32 = 1 << 0;
const WASIX_JOIN_FLAGS_SUPPORTED: u32 = WASIX_JOIN_FLAG_NON_BLOCKING | (1 << 1);
const WASIX_JOIN_STATUS_NOTHING: u8 = 0;
const WASIX_JOIN_STATUS_EXIT_NORMAL: u8 = 1;
const WASIX_JOIN_STATUS_EXIT_SIGNAL: u8 = 2;
const WASIX_JOIN_STATUS_UNION_OFFSET: u32 = 2;
const WASIX_ERRNO_SIGNAL_SIGNAL_OFFSET: u32 = 4;
const WASIX_SIGABRT: u8 = 6;
const WASIX_SIGKILL: u8 = 9;
const WASIX_SOCK_TYPE_STREAM: i32 = 1;
const WASIX_SOCK_TYPE_DGRAM: i32 = 2;
const WASIX_SOCK_TYPE_RAW: i32 = 3;
const WASIX_SOCK_STATUS_OPENED: u8 = 1;
const WASIX_SOCK_OPTION_REUSE_PORT: i32 = 1;
const WASIX_SOCK_OPTION_REUSE_ADDR: i32 = 2;
const WASIX_SOCK_OPTION_NO_DELAY: i32 = 3;
const WASIX_SOCK_OPTION_DONT_ROUTE: i32 = 4;
const WASIX_SOCK_OPTION_ONLY_V6: i32 = 5;
const WASIX_SOCK_OPTION_BROADCAST: i32 = 6;
const WASIX_SOCK_OPTION_MULTICAST_LOOP_V4: i32 = 7;
const WASIX_SOCK_OPTION_MULTICAST_LOOP_V6: i32 = 8;
const WASIX_SOCK_OPTION_PROMISCUOUS: i32 = 9;
const WASIX_SOCK_OPTION_LISTENING: i32 = 10;
const WASIX_SOCK_OPTION_KEEP_ALIVE: i32 = 12;
const WASIX_SOCK_OPTION_LINGER: i32 = 13;
const WASIX_SOCK_OPTION_OOB_INLINE: i32 = 14;
const WASIX_SOCK_OPTION_RECV_BUF_SIZE: i32 = 15;
const WASIX_SOCK_OPTION_SEND_BUF_SIZE: i32 = 16;
const WASIX_SOCK_OPTION_RECV_LOWAT: i32 = 17;
const WASIX_SOCK_OPTION_SEND_LOWAT: i32 = 18;
const WASIX_SOCK_OPTION_RECV_TIMEOUT: i32 = 19;
const WASIX_SOCK_OPTION_SEND_TIMEOUT: i32 = 20;
const WASIX_SOCK_OPTION_CONNECT_TIMEOUT: i32 = 21;
const WASIX_SOCK_OPTION_ACCEPT_TIMEOUT: i32 = 22;
const WASIX_SOCK_OPTION_TTL: i32 = 23;
const WASIX_SOCK_OPTION_MULTICAST_TTL_V4: i32 = 24;
const WASIX_SOCK_OPTION_TYPE: i32 = 25;
const WASIX_SOCK_OPTION_PROTO: i32 = 26;
const WASIX_RIFLAGS_RECV_PEEK: u16 = 1 << 0;
const WASIX_RIFLAGS_RECV_DONT_WAIT: u16 = 1 << 3;
const WASIX_RIFLAGS_SUPPORTED: u16 = WASIX_RIFLAGS_RECV_PEEK | WASIX_RIFLAGS_RECV_DONT_WAIT;
const WASIX_ROFLAGS_DATA_TRUNCATED: u16 = 1 << 0;
const WASIX_ADDRESS_FAMILY_UNSPEC: u8 = 0;
const WASIX_ADDRESS_FAMILY_IP_INET4: u8 = 1;
const WASIX_ADDRESS_FAMILY_IP_INET6: u8 = 2;
const WASIX_ADDRESS_FAMILY_UNIX: u8 = 3;
const WASIX_ADDRESS_FAMILY_UNSPEC_I32: i32 = 0;
const WASIX_ADDRESS_FAMILY_IP_INET4_I32: i32 = 1;
const WASIX_ADDRESS_FAMILY_IP_INET6_I32: i32 = 2;
const WASIX_ADDRESS_FAMILY_UNIX_I32: i32 = 3;
const WASIX_ADDR_IP_UNION_OFFSET: u32 = 2;
const WASIX_ADDR_IP_SIZE: u32 = 18;
const WASIX_ADDR_CIDR_SIZE: u32 = 28;
const WASIX_ADDR_CIDR_UNION_OFFSET: u32 = 2;
const WASIX_ADDR_CIDR_IP4_ADDRESS_OFFSET: u32 = WASIX_ADDR_CIDR_UNION_OFFSET;
const WASIX_ADDR_CIDR_IP4_PREFIX_OFFSET: u32 = WASIX_ADDR_CIDR_IP4_ADDRESS_OFFSET + 4;
const WASIX_ADDR_PORT_UNION_OFFSET: u32 = 2;
const WASIX_ADDR_PORT_IP4_ADDRESS_OFFSET: u32 = 4;
/// `__wasi_addr_ip6_port_t` overlays `__wasi_addr_ip4_port_t` in the
/// `__wasi_addr_port_t` union: both are `{ u16 port; address }`, so the
/// address starts at the same offset and only its width differs.
const WASIX_ADDR_PORT_IP6_ADDRESS_OFFSET: u32 = WASIX_ADDR_PORT_IP4_ADDRESS_OFFSET;
const WASIX_ROUTE_SIZE: u32 = 176;
const WASIX_ROUTE_CIDR_OFFSET: u32 = 0;
const WASIX_ROUTE_ROUTER_OFFSET: u32 = 28;
const WASIX_ROUTE_PREFERRED_UNTIL_OFFSET: u32 = 144;
const WASIX_ROUTE_EXPIRES_AT_OFFSET: u32 = 160;
const WASIX_EPOLL_TYPE_EPOLLIN: u32 = 1 << 0;
const WASIX_EPOLL_TYPE_EPOLLOUT: u32 = 1 << 1;
const WASIX_EPOLL_TYPE_EPOLLERR: u32 = 1 << 4;
const WASIX_EPOLL_TYPE_EPOLLHUP: u32 = 1 << 5;
const WASIX_EPOLL_TYPE_EPOLLONESHOT: u32 = 1 << 7;
const WASIX_EPOLL_CTL_ADD: i32 = 0;
const WASIX_EPOLL_CTL_MOD: i32 = 1;
const WASIX_EPOLL_CTL_DEL: i32 = 2;
const WASIX_EPOLL_EVENT_SIZE: u32 = 32;
const WASIX_EPOLL_EVENT_PADDING_OFFSET: u32 = 4;
const WASIX_EPOLL_EVENT_DATA_OFFSET: u32 = 8;
const WASIX_EPOLL_EVENT_DATA_FD_OFFSET: u32 = 12;
const WASIX_EPOLL_EVENT_DATA1_OFFSET: u32 = 16;
const WASIX_EPOLL_EVENT_DATA_PADDING_OFFSET: u32 = 20;
const WASIX_EPOLL_EVENT_DATA2_OFFSET: u32 = 24;
const P1_FSTFLAG_ATIM: u16 = 1 << 0;
const P1_FSTFLAG_ATIM_NOW: u16 = 1 << 1;
const P1_FSTFLAG_MTIM: u16 = 1 << 2;
const P1_FSTFLAG_MTIM_NOW: u16 = 1 << 3;
const P1_EVENTTYPE_CLOCK: u8 = 0;
const P1_EVENTTYPE_FD_READ: u8 = 1;
const P1_EVENTTYPE_FD_WRITE: u8 = 2;
const P1_SDFLAGS_RD: u8 = 1 << 0;
const P1_SDFLAGS_WR: u8 = 1 << 1;
const P1_SDFLAGS_SUPPORTED: u8 = P1_SDFLAGS_RD | P1_SDFLAGS_WR;
const P1_SUBSCRIPTION_CLOCK_ABSTIME: u16 = 1;
const P1_SUBSCRIPTION_SIZE: u32 = 48;
const P1_EVENT_SIZE: u32 = 32;
const PREVIEW1_PROGRAM_LINKED_IMPORTS: &[&str] = &[
    "args_get",
    "args_sizes_get",
    "environ_get",
    "environ_sizes_get",
    "clock_res_get",
    "clock_time_get",
    "fd_advise",
    "fd_allocate",
    "fd_close",
    "fd_datasync",
    "fd_fdstat_get",
    "fd_fdstat_set_flags",
    "fd_fdstat_set_rights",
    "fd_filestat_get",
    "fd_filestat_set_size",
    "fd_filestat_set_times",
    "fd_pread",
    "fd_prestat_get",
    "fd_prestat_dir_name",
    "fd_pwrite",
    "fd_read",
    "fd_readdir",
    "fd_renumber",
    "fd_seek",
    "fd_sync",
    "fd_tell",
    "fd_write",
    "path_create_directory",
    "path_filestat_get",
    "path_filestat_set_times",
    "path_link",
    "path_open",
    "path_readlink",
    "path_remove_directory",
    "path_rename",
    "path_symlink",
    "path_unlink_file",
    "poll_oneoff",
    "proc_exit",
    "proc_raise",
    "sched_yield",
    "random_get",
    "sock_accept",
    "sock_recv",
    "sock_send",
    "sock_shutdown",
];
const P1_RIGHT_PATH_READ_MASK: u64 =
    P1_RIGHT_PATH_OPEN | P1_RIGHT_FD_READDIR | P1_RIGHT_PATH_READLINK | P1_RIGHT_PATH_FILESTAT_GET;
const P1_RIGHT_PATH_FILE_WRITE_MASK: u64 =
    P1_RIGHT_PATH_CREATE_FILE | P1_RIGHT_PATH_FILESTAT_SET_SIZE | P1_RIGHT_PATH_FILESTAT_SET_TIMES;
const P1_RIGHT_PATH_MUTATE_MASK: u64 = P1_RIGHT_PATH_CREATE_DIRECTORY
    | P1_RIGHT_PATH_CREATE_FILE
    | P1_RIGHT_PATH_LINK_SOURCE
    | P1_RIGHT_PATH_LINK_TARGET
    | P1_RIGHT_PATH_RENAME_SOURCE
    | P1_RIGHT_PATH_RENAME_TARGET
    | P1_RIGHT_PATH_SYMLINK
    | P1_RIGHT_PATH_REMOVE_DIRECTORY
    | P1_RIGHT_PATH_UNLINK_FILE;

#[cfg(test)]
mod tests {
    use super::*;

    /// The descriptor flavour the table tests use. None of them opens a
    /// socket, so the service type only has to exist; the recording one
    /// is what the rest of the kernel's tests already carry.
    type TestNet = crate::test_support::TestNetworkService;
    type TestDescriptor = Preview1Descriptor<TestNet>;
    type TestDescriptorTable = Preview1DescriptorTable<TestNet>;
    type TestSpawnFdSnapshot = WasixSpawnFdSnapshot<TestNet>;
    type TestSocketDescriptor = UnixSocket<TestNet>;

    #[test]
    fn preview1_program_linked_imports_match_manifest() {
        assert_eq!(PREVIEW1_PROGRAM_LINKED_IMPORTS, p1::PREVIEW1_FUNCTIONS);
    }

    #[test]
    fn preview1_fdstat_layout_is_little_endian_and_zero_padded() {
        let bytes = p1_fdstat_bytes(2, 0x1234, 0x0102_0304_0506_0708);
        assert_eq!(bytes[0], 2);
        assert_eq!(bytes[1], 0);
        assert_eq!(&bytes[2..4], &0x1234u16.to_le_bytes());
        assert_eq!(&bytes[4..8], &[0; 4]);
        assert_eq!(&bytes[8..16], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&bytes[16..24], &0x0102_0304_0506_0708u64.to_le_bytes());
    }

    #[test]
    fn wasix_program_linked_imports_have_authority_mapping() {
        for import in crate::wasmtime_adapter::wasix::LINKED_IMPORTS {
            assert!(
                crate::wasmtime_adapter::wasix::authority_for(import).is_some(),
                "WASIX linked import {import} has no capability mapping"
            );
        }
    }

    #[test]
    fn wasix_manifest_is_linked_by_core_adapter() {
        assert_eq!(
            crate::wasmtime_adapter::wasix::LINKED_IMPORTS,
            crate::wasmtime_adapter::wasix::manifest().collect::<Vec<_>>()
        );
    }

    #[test]
    fn wasix_linked_imports_are_accepted_by_core_validator() {
        for import in crate::wasmtime_adapter::wasix::LINKED_IMPORTS {
            validate_preview1_program_import(WASIX_MODULE, import)
                .expect("linked WASIX imports should validate");
        }
    }

    #[test]
    fn wasi_unstable_imports_are_accepted_as_preview1() {
        for import in PREVIEW1_PROGRAM_LINKED_IMPORTS {
            validate_preview1_program_import("wasi_unstable", import)
                .expect("wasi_unstable imports should validate as preview1");
        }
    }

    /// A stack-reserve commit the user pool refuses ends the guest's call
    /// with the pool's refusal, and the program service classifies that as
    /// running out of memory, whatever context the runtime wraps it in. The
    /// adapter asks the OOM killer to cover the bytes the pool could not
    /// give.
    #[test]
    fn a_refused_stack_reserve_ends_the_call_as_out_of_memory() {
        use crate::wasmtime_adapter::store::answer_stack_reserve;
        use core::sync::atomic::{AtomicUsize, Ordering};

        let engine = crate::wasmtime_adapter::engine::build_component_engine_for_platform(
            &crate::test_support::TestCpu::without_entropy(),
        )
        .expect("the component engine builds on the test platform");
        let mut store = wasmtime::Store::new(&engine, ());
        let condemned_for = Arc::new(AtomicUsize::new(0));
        let seen = condemned_for.clone();
        store.stack_reserve_callback(move |_context, _sp| {
            let shortfall = crate::ProgramOutOfMemory {
                requested_bytes: 4096,
                available_bytes: 0,
                pool_bytes: 1 << 20,
                reserved_bytes: 0,
            };
            answer_stack_reserve(
                Err(crate::StackReserveError::OutOfMemory(shortfall)),
                |requested_bytes| seen.store(requested_bytes, Ordering::Relaxed),
            )
        });
        let host = wasmtime::Func::wrap(&mut store, || {});

        let error = futures_lite::future::block_on(host.call_async(&mut store, &[], &mut []))
            .expect_err("the entry into wasm asks for the reserve, and the pool refuses it");

        assert_eq!(
            condemned_for.load(Ordering::Relaxed),
            4096,
            "the OOM killer was asked to cover the refused bytes"
        );
        let error = map_program_runtime_error(error);
        assert_eq!(
            error.kind,
            ProgramExecErrorKind::OutOfMemory,
            "a refused reserve is the same out-of-memory a refused grow is: {error:?}"
        );
    }

    #[test]
    fn wasix_getcwd_reports_path_length_without_trailing_nul() {
        assert_eq!(wasix_getcwd_required_len("/"), Ok(1));
        assert_eq!(wasix_getcwd_required_len("/tmp/work"), Ok(9));
    }

    #[test]
    fn wasix_exec_search_path_builds_confined_candidates() {
        assert_eq!(
            wasix_search_path_candidate(Some("/work"), "/bin", "dash"),
            Some(String::from("/bin/dash"))
        );
        assert_eq!(
            wasix_search_path_candidate(Some("/work"), "tools", "qjs"),
            Some(String::from("/work/tools/qjs"))
        );
        assert_eq!(
            wasix_search_path_candidate(Some("/work"), "", "local"),
            Some(String::from("/work/local"))
        );
        assert_eq!(
            wasix_search_path_candidate(Some("/work"), "../escape", "bad"),
            None
        );
        assert_eq!(
            wasix_search_path_candidate(Some("/work"), "/bin", "../bad"),
            None
        );
        assert_eq!(wasix_search_path_candidate(None, "bin", "dash"), None);
    }

    #[test]
    fn a_name_too_long_is_name_too_long_in_every_wasi_layer() {
        let code =
            crate::wasmtime_adapter::wasi::fs_error_code(helios_hal::fs::FsError::NameTooLong);

        // Preview 3 returns the code itself; preview 1 and WASIX
        // answer its errno.
        assert!(matches!(code, fs_types::ErrorCode::NameTooLong));
        assert_eq!(
            p1_errno_from_fs(fs_types::ErrorCode::NameTooLong),
            p1::errno::NAMETOOLONG
        );
    }

    #[test]
    fn null_device_open_is_confined_to_authorized_path_resolution() {
        let root = FsDescriptor {
            path: "/".into(),
            kind: FsNodeKind::Directory,
            flags: FsDescriptorFlags::READ,
            identity: None,
            mount: None,
            open: None,
        };
        let work = FsDescriptor {
            path: "/work".into(),
            kind: FsNodeKind::Directory,
            flags: FsDescriptorFlags::READ,
            identity: None,
            mount: None,
            open: None,
        };

        assert_eq!(
            p1_open_null_device(&root, "dev/null", fs_types::OpenFlags::empty()),
            Ok(true)
        );
        assert_eq!(
            p1_open_null_device(&work, "dev/null", fs_types::OpenFlags::empty()),
            Ok(false)
        );
        assert_eq!(
            p1_open_null_device(&root, "dev/null", fs_types::OpenFlags::DIRECTORY),
            Err(p1::errno::NOTDIR)
        );
        assert_eq!(
            p1_open_null_device(
                &root,
                "dev/null",
                fs_types::OpenFlags::CREATE | fs_types::OpenFlags::EXCLUSIVE
            ),
            Err(p1::errno::EXIST)
        );
    }

    #[test]
    fn null_device_rights_and_stat_match_character_device_semantics() {
        let rights = p1_descriptor_rights(&TestDescriptor::NullDevice);
        assert_ne!(rights & P1_RIGHT_FD_READ, 0);
        assert_ne!(rights & P1_RIGHT_FD_WRITE, 0);
        assert_ne!(rights & P1_RIGHT_POLL_FD_READWRITE, 0);
        assert!(matches!(
            p1_null_device_stat().type_,
            fs_types::DescriptorType::CharacterDevice
        ));
        assert!(matches!(
            p1_probe_descriptor(Some(&TestDescriptor::NullDevice), P1_EVENTTYPE_FD_WRITE),
            Ok(P1Probe::Local(P1Readiness::Ready { bytes })) if bytes == usize::MAX as u64
        ));
    }

    #[test]
    fn fd_renumber_replaces_stdio_descriptor() {
        let file: TestDescriptor = Preview1Descriptor::File(OpenFile::new(FsDescriptor {
            path: "/redirected".into(),
            kind: FsNodeKind::File,
            flags: FsDescriptorFlags::WRITE,
            identity: None,
            mount: None,
            open: None,
        }));
        let mut table: TestDescriptorTable = Preview1DescriptorTable::from_entries(vec![
            Some(Preview1DescriptorEntry::new(
                Preview1Descriptor::Stdin {
                    carry: Bytes::new(),
                },
                false,
            )),
            Some(Preview1DescriptorEntry::new(
                Preview1Descriptor::Stdout,
                false,
            )),
            Some(Preview1DescriptorEntry::new(
                Preview1Descriptor::Stderr,
                false,
            )),
            Some(Preview1DescriptorEntry::new(file, true)),
        ]);

        assert_eq!(table.renumber(3, 1), p1::errno::SUCCESS);
        match table.get(1) {
            Some(Preview1Descriptor::File(file)) => {
                assert_eq!(file.node().path, "/redirected");
            }
            _ => panic!("fd 1 should be redirected to the file descriptor"),
        }
        assert_eq!(table.close_on_exec(1), Ok(false));
        assert!(table.get(3).is_none());
    }

    fn stdio_table() -> TestDescriptorTable {
        Preview1DescriptorTable::from_entries(vec![
            Some(Preview1DescriptorEntry::new(
                Preview1Descriptor::Stdin {
                    carry: Bytes::new(),
                },
                false,
            )),
            Some(Preview1DescriptorEntry::new(
                Preview1Descriptor::Stdout,
                false,
            )),
            Some(Preview1DescriptorEntry::new(
                Preview1Descriptor::Stderr,
                false,
            )),
        ])
    }

    /// dash applies `2>&1` around a command in the shell itself and
    /// restores afterwards: save fd 2 (`fcntl(F_DUPFD)`, which is
    /// `fd_dup`), `dup2(1, 2)`, run the command, `dup2(saved, 2)`,
    /// `close(saved)`. The WASIX libc's `dup2` is `fd_renumber`, so the
    /// shell's own stdout survives the pair only if `fd_renumber` copies.
    #[test]
    fn wasix_dup2_and_restore_of_stderr_leaves_stdout_open() {
        let mut table = stdio_table();

        let saved = i32::try_from(table.dup(2).expect("fd 2 is open")).expect("small fd");
        assert_eq!(table.dup2(1, 2), p1::errno::SUCCESS);
        assert!(matches!(table.get(1), Some(Preview1Descriptor::Stdout)));
        assert!(matches!(table.get(2), Some(Preview1Descriptor::Stdout)));

        assert_eq!(table.dup2(saved, 2), p1::errno::SUCCESS);
        assert_eq!(table.close(saved), p1::errno::SUCCESS);
        assert!(matches!(table.get(1), Some(Preview1Descriptor::Stdout)));
        assert!(matches!(table.get(2), Some(Preview1Descriptor::Stderr)));
        assert!(table.get(saved).is_none());
    }

    #[test]
    fn wasix_dup2_onto_itself_changes_nothing_and_needs_an_open_source() {
        let mut table = stdio_table();
        assert_eq!(table.set_close_on_exec(1, true), p1::errno::SUCCESS);

        assert_eq!(table.dup2(1, 1), p1::errno::SUCCESS);
        assert_eq!(table.close_on_exec(1), Ok(true));
        assert_eq!(table.dup2(7, 7), p1::errno::BADF);
        assert_eq!(table.dup2(7, 1), p1::errno::BADF);
        assert!(matches!(table.get(1), Some(Preview1Descriptor::Stdout)));
    }

    /// The writer a component's stream `kind` resolves to under `mode`.
    fn component_channel(
        mode: &OutputMode,
        kind: crate::ComponentOutputStreamKind,
    ) -> crate::ByteWriter {
        match mode.route(kind) {
            OutputRoute::Child(writer) => writer,
            _ => panic!("the component's stream is not a channel"),
        }
    }

    /// The process's own stdio as the debugger hands it to a shell: three
    /// channels whose far ends the test holds.
    fn session_stdio() -> (OutputMode, crate::ByteReader, crate::ByteReader) {
        let (_, stdin_rx) = crate::byte_channel();
        let (stdout_tx, stdout_rx) = crate::byte_channel();
        let (stderr_tx, stderr_rx) = crate::byte_channel();
        (
            OutputMode::Child {
                stdin_rx,
                stdout_tx,
                stderr_tx,
            },
            stdout_rx,
            stderr_rx,
        )
    }

    /// `$(component)`: the shell's child puts a pipe's write end at fd 1
    /// and execs the component, whose stdout must reach the pipe rather
    /// than the session.
    #[test]
    fn component_launched_with_a_pipe_at_stdout_writes_to_the_pipe() {
        let (session, session_stdout, session_stderr) = session_stdio();
        let (pipe_tx, pipe_rx) = crate::byte_channel();
        let mut table = stdio_table();
        let pipe = table
            .insert(Preview1Descriptor::PipeWrite {
                writer: pipe_tx,
                inode: helios_unix::PipeInode::default(),
            })
            .expect("a free slot");
        let pipe = i32::try_from(pipe).expect("small fd");
        assert_eq!(table.dup2(pipe, 1), p1::errno::SUCCESS);
        assert_eq!(table.close(pipe), p1::errno::SUCCESS);

        let mode = table
            .clone_for_exec()
            .component_output_mode(&session)
            .expect("a pipe is a component stdout");
        drop(table);

        let stdout = component_channel(&mode, crate::ComponentOutputStreamKind::Stdout);
        assert!(matches!(
            stdout.try_write(Bytes::from_static(b"possible 4\n")),
            crate::TryWrite::Written
        ));
        assert!(matches!(
            pipe_rx.try_read(),
            crate::io::TryRead::Ready(bytes) if bytes.as_ref() == b"possible 4\n"
        ));
        assert!(matches!(
            session_stdout.try_read(),
            crate::io::TryRead::Pending
        ));

        let stderr = component_channel(&mode, crate::ComponentOutputStreamKind::Stderr);
        assert!(matches!(
            stderr.try_write(Bytes::from_static(b"usage\n")),
            crate::TryWrite::Written
        ));
        assert!(matches!(
            session_stderr.try_read(),
            crate::io::TryRead::Ready(bytes) if bytes.as_ref() == b"usage\n"
        ));

        // The component's stream is the pipe's last write end, so the
        // shell reading the substitution sees end of file once it ends.
        drop((stdout, mode));
        assert!(matches!(pipe_rx.try_read(), crate::io::TryRead::Eof));
    }

    /// `component 2>&1`: fd 2 is a copy of fd 1, so the component's stderr
    /// goes where the shell's stdout goes.
    #[test]
    fn component_launched_with_stderr_on_stdout_writes_stderr_to_stdout() {
        let (session, session_stdout, session_stderr) = session_stdio();
        let mut table = stdio_table();
        assert_eq!(table.dup2(1, 2), p1::errno::SUCCESS);

        let mode = table
            .component_output_mode(&session)
            .expect("stdout is a component stderr");
        let stderr = component_channel(&mode, crate::ComponentOutputStreamKind::Stderr);
        assert!(matches!(
            stderr.try_write(Bytes::from_static(b"usage\n")),
            crate::TryWrite::Written
        ));
        assert!(matches!(
            session_stdout.try_read(),
            crate::io::TryRead::Ready(bytes) if bytes.as_ref() == b"usage\n"
        ));
        assert!(matches!(
            session_stderr.try_read(),
            crate::io::TryRead::Pending
        ));
    }

    #[test]
    fn component_launched_over_the_process_stdio_keeps_the_process_mode() {
        let mode = stdio_table()
            .component_output_mode(&OutputMode::Serial)
            .expect("the process's own stdio");
        assert!(matches!(mode, OutputMode::Serial));
    }

    #[test]
    fn component_stdio_closed_slots_are_closed_streams_and_files_are_refused() {
        let (session, _, _) = session_stdio();
        let mut table = stdio_table();
        assert_eq!(table.close(0), p1::errno::SUCCESS);
        assert_eq!(table.close(1), p1::errno::SUCCESS);
        let mode = table
            .component_output_mode(&session)
            .expect("closed slots are closed streams");
        let OutputMode::RoutedChild { stdin, .. } = &mode else {
            panic!("a redirected table routes each stream");
        };
        assert!(matches!(stdin, crate::ComponentInputRoute::Closed));
        let stdout = component_channel(&mode, crate::ComponentOutputStreamKind::Stdout);
        assert!(matches!(
            stdout.try_write(Bytes::from_static(b"lost\n")),
            crate::TryWrite::Closed
        ));

        let file: TestDescriptor = Preview1Descriptor::File(OpenFile::new(FsDescriptor {
            path: "/redirected".into(),
            kind: FsNodeKind::File,
            flags: FsDescriptorFlags::WRITE,
            identity: None,
            mount: None,
            open: None,
        }));
        assert_eq!(
            table.insert_entry_at(1, Preview1DescriptorEntry::new(file, false)),
            Ok(1)
        );
        assert_eq!(
            table.component_output_mode(&session).err(),
            Some(ComponentStdioRefusal {
                fd: 1,
                held: UnbindableStdio::File,
            })
        );
    }

    #[test]
    fn fd_renumber_past_the_descriptor_limit_is_badf_and_allocates_nothing() {
        let mut table = stdio_table();

        // `fd_renumber` takes an `i32`, so `i32::MAX - 1` is the highest
        // number a guest can name; it used to resize the table to match.
        assert_eq!(table.renumber(1, i32::MAX - 1), p1::errno::BADF);
        assert_eq!(table.renumber(1, -2), p1::errno::BADF);
        assert_eq!(table.renumber(1, 1024), p1::errno::BADF);
        assert_eq!(table.entries.len(), 3);
        assert!(table.get(1).is_some());

        assert_eq!(table.renumber(1, 1023), p1::errno::SUCCESS);
        assert!(table.get(1023).is_some());
    }

    #[test]
    fn fd_dup2_past_the_descriptor_limit_is_badf_and_allocates_nothing() {
        let mut table = stdio_table();
        table.limit = DescriptorLimit::new(8);

        assert_eq!(table.dup_to(0, i32::MAX - 1, false), Err(p1::errno::BADF));
        assert_eq!(table.dup_to(0, 8, false), Err(p1::errno::BADF));
        assert_eq!(table.entries.len(), 3);
        assert_eq!(table.dup_to(0, 7, false), Ok(7));
    }

    #[test]
    fn spawn_dup2_action_inherits_the_descriptor_limit() {
        let mut table = stdio_table();
        table.limit = DescriptorLimit::new(8);
        let mut snapshot = table.clone_for_exec();

        // The spawn-time dup2 action applies `dup_to` to this table.
        assert_eq!(snapshot.limit, DescriptorLimit::new(8));
        assert_eq!(
            snapshot.dup_to(0, i32::MAX - 1, false),
            Err(p1::errno::BADF)
        );
        assert_eq!(
            snapshot.insert_entry_at(
                i32::MAX - 1,
                Preview1DescriptorEntry::new(Preview1Descriptor::NullDevice, false)
            ),
            Err(p1::errno::BADF)
        );
        assert_eq!(snapshot.target_index(i32::MAX - 1), Err(p1::errno::BADF));
        assert_eq!(snapshot.entries.len(), 3);
    }

    #[test]
    fn lowest_free_allocation_at_the_descriptor_limit_is_mfile() {
        let mut table = stdio_table();
        table.limit = DescriptorLimit::new(4);

        assert_eq!(table.insert(Preview1Descriptor::NullDevice), Ok(3));
        assert_eq!(
            table.insert(Preview1Descriptor::NullDevice),
            Err(p1::errno::MFILE)
        );
        assert_eq!(table.dup(0), Err(p1::errno::MFILE));
        assert_eq!(table.entries.len(), 4);

        assert_eq!(table.close(1), p1::errno::SUCCESS);
        assert_eq!(table.dup(0), Ok(1));
    }

    /// A process created after the operator changes the descriptor-limit
    /// setting takes the new value; a running process keeps the limit it
    /// was created with, and so does a process that only changes its image.
    #[test]
    fn a_process_created_after_a_change_takes_the_new_limit_and_a_running_one_keeps_its_own() {
        let machine = test_store::store_data_authorized(ProcessAuthority::empty(), |_| {});
        let settings = machine.runtime_state.settings();
        let mut operator = ProcessAuthority::empty();
        operator.grant_settings_rights(crate::SettingsAuthorityRights::WRITE);
        let proof = operator
            .derive_write_settings_cap()
            .expect("an authority granted the right derives its proof");
        let authority = ProcessAuthority::empty();

        // 1. A process created before the change has the default.
        let mut running: TestDescriptorTable =
            process_descriptors(DescriptorOrigin::Fresh, &authority, settings, Vec::new());
        assert_eq!(running.limit, DescriptorLimit::DEFAULT);

        // 2. The operator lowers the setting and is told what it was.
        assert_eq!(
            settings.set::<DescriptorLimitSetting>(&proof, DescriptorLimit::new(64)),
            DescriptorLimit::DEFAULT
        );

        // 3. A process created after it takes the new value.
        let mut created: TestDescriptorTable =
            process_descriptors(DescriptorOrigin::Fresh, &authority, settings, Vec::new());
        assert_eq!(created.limit, DescriptorLimit::new(64));

        // 4. The running process still hands out numbers up to its own.
        assert_eq!(
            running.insert_entry_at(
                100,
                Preview1DescriptorEntry::new(Preview1Descriptor::NullDevice, false),
            ),
            Ok(100)
        );

        // 5. The new process refuses a number at its limit.
        assert_eq!(
            created.insert_entry_at(
                64,
                Preview1DescriptorEntry::new(Preview1Descriptor::NullDevice, false),
            ),
            Err(p1::errno::BADF)
        );

        // 6. Its lowest-free allocation runs out at the limit.
        for expected in 3..64 {
            assert_eq!(created.insert(Preview1Descriptor::NullDevice), Ok(expected));
        }
        assert_eq!(
            created.insert(Preview1Descriptor::NullDevice),
            Err(p1::errno::MFILE)
        );

        // 7. An exec is the same process: it keeps the limit it has.
        let exec = process_descriptors(
            DescriptorOrigin::SameProcess(running.clone_for_exec()),
            &authority,
            settings,
            Vec::new(),
        );
        assert_eq!(exec.limit, DescriptorLimit::DEFAULT);

        // 8. A fork or spawn child is a new process: it takes the setting,
        // and the descriptors it inherits at or past the limit stay open.
        let mut child = process_descriptors(
            DescriptorOrigin::NewProcess(running.clone()),
            &authority,
            settings,
            Vec::new(),
        );
        assert_eq!(child.limit, DescriptorLimit::new(64));
        assert!(child.get(100).is_some());
        assert_eq!(
            child.insert_entry_at(
                65,
                Preview1DescriptorEntry::new(Preview1Descriptor::NullDevice, false),
            ),
            Err(p1::errno::BADF)
        );
    }

    #[test]
    fn fd_close_can_close_stdio_slots() {
        let mut table: TestDescriptorTable = Preview1DescriptorTable::from_entries(vec![
            Some(Preview1DescriptorEntry::new(
                Preview1Descriptor::Stdin {
                    carry: Bytes::new(),
                },
                false,
            )),
            Some(Preview1DescriptorEntry::new(
                Preview1Descriptor::Stdout,
                false,
            )),
            Some(Preview1DescriptorEntry::new(
                Preview1Descriptor::Stderr,
                false,
            )),
        ]);

        assert_eq!(table.close(1), p1::errno::SUCCESS);
        assert!(table.get(1).is_none());
        assert_eq!(table.close(1), p1::errno::BADF);
    }

    #[test]
    fn descriptor_insert_reuses_lowest_closed_slot() {
        let mut table: TestDescriptorTable = Preview1DescriptorTable::from_entries(vec![
            Some(Preview1DescriptorEntry::new(
                Preview1Descriptor::Stdin {
                    carry: Bytes::new(),
                },
                false,
            )),
            Some(Preview1DescriptorEntry::new(
                Preview1Descriptor::Stdout,
                false,
            )),
            Some(Preview1DescriptorEntry::new(
                Preview1Descriptor::Stderr,
                false,
            )),
        ]);

        assert_eq!(table.close(2), p1::errno::SUCCESS);
        assert_eq!(table.close(0), p1::errno::SUCCESS);
        assert_eq!(table.insert(Preview1Descriptor::NullDevice), Ok(0));
    }

    #[test]
    fn fd_dup2_replaces_exact_target_descriptor() {
        let file: TestDescriptor = Preview1Descriptor::File(OpenFile::new(FsDescriptor {
            path: "/redirected".into(),
            kind: FsNodeKind::File,
            flags: FsDescriptorFlags::WRITE,
            identity: None,
            mount: None,
            open: None,
        }));
        let mut table: TestDescriptorTable = Preview1DescriptorTable::from_entries(vec![
            Some(Preview1DescriptorEntry::new(
                Preview1Descriptor::Stdin {
                    carry: Bytes::new(),
                },
                false,
            )),
            Some(Preview1DescriptorEntry::new(
                Preview1Descriptor::Stdout,
                false,
            )),
            Some(Preview1DescriptorEntry::new(
                Preview1Descriptor::Stderr,
                false,
            )),
            Some(Preview1DescriptorEntry::new(file, false)),
        ]);

        assert_eq!(table.dup_to(3, 1, true), Ok(1));
        match table.get(1) {
            Some(Preview1Descriptor::File(file)) => {
                assert_eq!(file.node().path, "/redirected");
            }
            _ => panic!("fd 1 should be duplicated to the file descriptor"),
        }
        assert_eq!(table.close_on_exec(1), Ok(true));
    }

    #[test]
    fn descriptor_table_preserves_fdflags_across_dup_and_exec_snapshot() {
        let file: TestDescriptor = Preview1Descriptor::File(OpenFile::new(FsDescriptor {
            path: "/nonblock".into(),
            kind: FsNodeKind::File,
            flags: FsDescriptorFlags::READ,
            identity: None,
            mount: None,
            open: None,
        }));
        let entry = Preview1DescriptorEntry::new(file, false);
        entry.set_fdflags(P1_FDFLAG_NONBLOCK);
        let mut table: TestDescriptorTable =
            Preview1DescriptorTable::from_entries(vec![Some(entry)]);

        assert_eq!(table.fdflags(0), Ok(P1_FDFLAG_NONBLOCK));
        assert_eq!(table.dup(0), Ok(1));
        assert_eq!(table.fdflags(1), Ok(P1_FDFLAG_NONBLOCK));
        assert_eq!(table.close_on_exec(1), Ok(false));
        assert_eq!(
            table.set_fdflags(1, P1_FDFLAG_NONBLOCK | P1_FDFLAG_APPEND),
            p1::errno::SUCCESS
        );

        let exec_table = table.clone_for_exec();

        assert_eq!(
            exec_table.fdflags(1),
            Ok(P1_FDFLAG_NONBLOCK | P1_FDFLAG_APPEND)
        );
    }

    #[test]
    fn socket_descriptor_accepts_only_nonblock_fdflag() {
        let socket = Preview1Descriptor::Socket(UnixSocket::<TestNet>::pair(SocketKind::Stream).0);
        let mut table: TestDescriptorTable = Preview1DescriptorTable::from_entries(vec![Some(
            Preview1DescriptorEntry::new(socket, false),
        )]);

        assert_eq!(table.set_fdflags(0, P1_FDFLAG_NONBLOCK), p1::errno::SUCCESS);
        assert_eq!(table.fdflags(0), Ok(P1_FDFLAG_NONBLOCK));
        assert!(p1_socket_fdflags_supported(P1_FDFLAG_NONBLOCK));
        assert!(!p1_socket_fdflags_supported(P1_FDFLAG_APPEND));
    }

    #[test]
    fn wasix_socket_timeout_respects_nonblocking_fdflag() {
        assert_eq!(wasix_effective_socket_timeout(Some(99), 0), 99);
        assert_eq!(wasix_effective_socket_timeout(None, 0), u64::MAX);
        assert_eq!(
            wasix_effective_socket_timeout(Some(99), P1_FDFLAG_NONBLOCK),
            0
        );
        assert_eq!(
            p1_errno_from_tcp_error_for_fdflags(
                crate::TcpError {
                    kind: crate::TcpErrorKind::Timeout,
                    detail: crate::NetworkErrorDetail::TcpConnectTimeout,
                },
                P1_FDFLAG_NONBLOCK,
            ),
            p1::errno::AGAIN
        );
        assert_eq!(
            p1_errno_from_udp_error_for_fdflags(
                crate::UdpError {
                    kind: crate::UdpErrorKind::Timeout,
                    detail: crate::NetworkErrorDetail::UdpReceiveTimeout,
                },
                P1_FDFLAG_NONBLOCK,
            ),
            p1::errno::AGAIN
        );
    }

    #[test]
    fn wasix_split_helpers_preallocate_nonempty_entries() {
        let lines = wasix_split_lines("alpha\n\nbeta\ngamma\n");
        assert_eq!(lines, ["alpha", "beta", "gamma"]);
        assert_eq!(lines.capacity(), 3);

        let environment = wasix_split_environment("A=1\nEMPTY\n\nB=two\n");
        assert_eq!(
            environment,
            [
                ("A".into(), "1".into()),
                ("EMPTY".into(), String::new()),
                ("B".into(), "two".into())
            ]
        );
        assert_eq!(environment.capacity(), 3);
    }

    #[test]
    fn proc_spawn_preopen_guest_name_resolves_relative_to_cwd() {
        let cwd = Preview1Cwd {
            guest_name: "/workspace".into(),
            descriptor: FsDescriptor {
                path: "/mnt/workspace".into(),
                kind: FsNodeKind::Directory,
                flags: FsDescriptorFlags::READ,
                identity: None,
                mount: None,
                open: None,
            },
        };

        assert_eq!(
            wasix_proc_spawn_preopen_guest_name(Some(&cwd), "tools").unwrap(),
            "/workspace/tools"
        );
        assert_eq!(
            wasix_proc_spawn_preopen_guest_name(Some(&cwd), "/bin").unwrap(),
            "/bin"
        );
        assert_eq!(
            wasix_proc_spawn_preopen_guest_name(Some(&cwd), "../escape"),
            Err(p1::errno::PERM)
        );
        assert_eq!(
            wasix_proc_spawn_preopen_guest_name(None, "relative"),
            Err(p1::errno::NOTCAPABLE)
        );
    }

    #[test]
    fn proc_spawn_preopen_authority_inherits_only_non_directory_rights() {
        let mut parent = ProcessAuthority::empty();
        parent.insert_directory_preopen(
            crate::DirectoryPreopen::new(
                "/workspace",
                "/workspace",
                crate::DirectoryAuthorityRights::READ,
            )
            .expect("test preopen should be valid"),
        );
        parent.grant_network_rights(crate::NetworkAuthorityRights::TCP);
        parent.grant_clock_rights(crate::ClockAuthorityRights::SET_WALL_CLOCK);
        parent.grant_terminal_rights(crate::TerminalAuthorityRights::OUTPUT);
        parent.grant_process_rights(crate::ProcessAuthorityRights::SPAWN);
        parent.grant_link_rights(crate::LinkAuthorityRights::SYMLINK_READ);
        parent.grant_device_classes(
            crate::DeviceClassRights::DISPLAY | crate::DeviceClassRights::AUDIO,
        );
        let registry = crate::InstanceRegistry::new();
        let parent_inst = registry.register("parent", 0);
        let child_inst = registry.register_child(Some(parent_inst.id()), "child", 1);
        let root_id = parent_inst.id();
        parent.grant_inspect_read(crate::AuthorityScope::Subtree(root_id));
        parent.grant_trace_read(crate::AuthorityScope::Own);
        parent.grant_profile_read(crate::AuthorityScope::Machine);
        parent.grant_diagnostic_rights(crate::DiagnosticAuthorityRights::CONTROL);
        parent.grant_instance_control(crate::AuthorityScope::Subtree(root_id));
        parent.grant_settings_rights(crate::SettingsAuthorityRights::WRITE);
        parent.grant_machine_rights(
            crate::MachineAuthorityRights::CONTROL
                | crate::MachineAuthorityRights::IDENTITY
                | crate::MachineAuthorityRights::VIRTUALIZE,
        );

        let child = wasix_proc_spawn_inherited_non_directory_authority(&parent);

        assert!(child.directory_preopens().is_empty());
        assert_eq!(child.network_rights(), crate::NetworkAuthorityRights::TCP);
        assert_eq!(
            child.clock_rights(),
            crate::ClockAuthorityRights::SET_WALL_CLOCK
        );
        assert_eq!(
            child.terminal_rights(),
            crate::TerminalAuthorityRights::OUTPUT
        );
        assert_eq!(child.process_rights(), crate::ProcessAuthorityRights::SPAWN);
        assert_eq!(
            child.link_rights(),
            crate::LinkAuthorityRights::SYMLINK_READ
        );
        assert_eq!(
            child.device_class_rights(),
            crate::DeviceClassRights::DISPLAY | crate::DeviceClassRights::AUDIO
        );
        assert_eq!(
            child.inspect_read_scope(),
            Some(crate::AuthorityScope::Subtree(root_id))
        );
        assert_eq!(child.trace_read_scope(), None);
        assert_eq!(
            child.profile_read_scope(),
            Some(crate::AuthorityScope::Machine)
        );
        assert_eq!(
            child.diagnostic_rights(),
            crate::DiagnosticAuthorityRights::CONTROL
        );
        assert_eq!(
            child.instance_control_scope(),
            Some(crate::AuthorityScope::Subtree(root_id))
        );
        assert_eq!(
            child.settings_rights(),
            crate::SettingsAuthorityRights::WRITE
        );
        assert_eq!(
            child.machine_rights(),
            crate::MachineAuthorityRights::CONTROL
                | crate::MachineAuthorityRights::IDENTITY
                | crate::MachineAuthorityRights::VIRTUALIZE
        );
        assert!(parent.contains_child_authority(
            parent_inst.id(),
            child_inst.id(),
            &child,
            &registry,
        ));
    }

    #[test]
    fn proc_spawn_inherits_device_classes_but_not_named_devices() {
        let mut parent = ProcessAuthority::empty();
        parent.grant_device_classes(crate::DeviceClassRights::all());
        parent
            .grant_device(
                crate::DeviceName::new("pci:0000:00:04.0").expect("the test name is short"),
            )
            .expect("one named device fits");

        let child = wasix_proc_spawn_inherited_non_directory_authority(&parent);

        assert_eq!(child.device_class_rights(), crate::DeviceClassRights::all());
        assert!(child.granted_devices().is_empty());
        assert!(parent.contains_authority(&child));
    }

    #[test]
    fn chroot_authority_resolution_maps_guest_root_to_derived_source() {
        let mut authority = ProcessAuthority::empty();
        authority.insert_directory_preopen(
            crate::DirectoryPreopen::new(
                "/mnt/workspace/app",
                "/",
                crate::DirectoryAuthorityRights::READ | crate::DirectoryAuthorityRights::WRITE,
            )
            .expect("test preopen should be valid"),
        );
        let cwd = authority
            .derive_directory_cap(
                "/mnt/workspace/app",
                "/",
                crate::DirectoryAuthorityRights::READ,
            )
            .expect("cwd cap should derive from chroot root");
        authority.chdir(cwd);

        let (source, flags) = wasix_authority_resolve_absolute_guest_path(&authority, "/bin/tool")
            .expect("guest path should resolve inside chroot root");

        assert_eq!(source, "/mnt/workspace/app/bin/tool");
        assert!(flags.contains(FsDescriptorFlags::READ));
        assert!(flags.contains(FsDescriptorFlags::WRITE));
    }

    #[test]
    fn exec_descriptor_snapshot_drops_close_on_exec_entries() {
        let closed = Preview1Descriptor::File(OpenFile::new(FsDescriptor {
            path: "/closed-on-exec".into(),
            kind: FsNodeKind::File,
            flags: FsDescriptorFlags::READ,
            identity: None,
            mount: None,
            open: None,
        }));
        let retained = Preview1Descriptor::File(OpenFile::new(FsDescriptor {
            path: "/retained".into(),
            kind: FsNodeKind::File,
            flags: FsDescriptorFlags::READ,
            identity: None,
            mount: None,
            open: None,
        }));
        let table: TestDescriptorTable = Preview1DescriptorTable::from_entries(vec![
            Some(Preview1DescriptorEntry::new(
                Preview1Descriptor::Stdin {
                    carry: Bytes::new(),
                },
                false,
            )),
            Some(Preview1DescriptorEntry::new(closed, true)),
            Some(Preview1DescriptorEntry::new(retained, false)),
        ]);

        let exec_table = table.clone_for_exec();

        assert!(exec_table.get(1).is_none());
        match exec_table.get(2) {
            Some(Preview1Descriptor::File(file)) => {
                assert_eq!(file.node().path, "/retained");
            }
            _ => panic!("fd 2 should be retained across exec"),
        }
    }

    #[test]
    fn spawn_fd_snapshot_maps_directory_source_to_guest_path() {
        let snapshot: TestSpawnFdSnapshot = WasixSpawnFdSnapshot {
            descriptors: Preview1DescriptorTable::from_entries(vec![Some(
                Preview1DescriptorEntry::new(
                    Preview1Descriptor::Preopen {
                        guest_name: "/workspace".into(),
                        descriptor: FsDescriptor {
                            path: "/mnt/workspace".into(),
                            kind: FsNodeKind::Directory,
                            flags: FsDescriptorFlags::READ,
                            identity: None,
                            mount: None,
                            open: None,
                        },
                    },
                    false,
                ),
            )]),
            authority: ProcessAuthority::root(),
            cwd: None,
        };

        assert_eq!(
            wasix_spawn_guest_name_for_source(&snapshot, "/mnt/workspace/tools").unwrap(),
            "/workspace/tools"
        );
        assert_eq!(
            wasix_spawn_guest_name_for_source(&snapshot, "/outside"),
            Err(p1::errno::NOTCAPABLE)
        );
    }

    #[test]
    fn spawn_fd_fchdir_updates_child_authority_cwd() {
        let preopen: TestDescriptor = Preview1Descriptor::Preopen {
            guest_name: "/workspace".into(),
            descriptor: FsDescriptor {
                path: "/mnt/workspace".into(),
                kind: FsNodeKind::Directory,
                flags: FsDescriptorFlags::READ,
                identity: None,
                mount: None,
                open: None,
            },
        };
        let mut authority = ProcessAuthority::empty();
        authority.insert_directory_preopen(
            crate::DirectoryPreopen::new(
                "/mnt/workspace",
                "/workspace",
                DirectoryAuthorityRights::READ,
            )
            .expect("test preopen must be valid"),
        );
        let mut snapshot: TestSpawnFdSnapshot = WasixSpawnFdSnapshot {
            descriptors: Preview1DescriptorTable::from_entries(vec![Some(
                Preview1DescriptorEntry::new(preopen, false),
            )]),
            authority,
            cwd: None,
        };

        wasix_apply_spawn_fchdir(&mut snapshot, 0).expect("preopen fchdir must succeed");
        assert_eq!(
            snapshot
                .authority
                .cwd()
                .expect("fchdir should set child cwd")
                .guest_name(),
            "/workspace"
        );
    }

    #[test]
    fn spawn_fd_open_base_uses_child_cwd_for_relative_paths() {
        let snapshot: TestSpawnFdSnapshot = WasixSpawnFdSnapshot {
            descriptors: Preview1DescriptorTable::from_entries(vec![Some(
                Preview1DescriptorEntry::new(
                    Preview1Descriptor::Preopen {
                        guest_name: "/root".into(),
                        descriptor: FsDescriptor {
                            path: "/source/root".into(),
                            kind: FsNodeKind::Directory,
                            flags: FsDescriptorFlags::READ,
                            identity: None,
                            mount: None,
                            open: None,
                        },
                    },
                    false,
                ),
            )]),
            authority: ProcessAuthority::root(),
            cwd: Some(Preview1Cwd {
                guest_name: "/workspace".into(),
                descriptor: FsDescriptor {
                    path: "/source/workspace".into(),
                    kind: FsNodeKind::Directory,
                    flags: FsDescriptorFlags::READ,
                    identity: None,
                    mount: None,
                    open: None,
                },
            }),
        };

        let (base, path) =
            wasix_spawn_resolve_open_base(&snapshot, 0, "out.log").expect("cwd should resolve");

        assert_eq!(base.path, "/source/workspace");
        assert_eq!(path, "out.log");
    }

    #[test]
    fn spawn_fd_open_base_resolves_absolute_guest_path_through_preopen() {
        let snapshot: TestSpawnFdSnapshot = WasixSpawnFdSnapshot {
            descriptors: Preview1DescriptorTable::from_entries(vec![Some(
                Preview1DescriptorEntry::new(
                    Preview1Descriptor::Preopen {
                        guest_name: "/workspace".into(),
                        descriptor: FsDescriptor {
                            path: "/source/workspace".into(),
                            kind: FsNodeKind::Directory,
                            flags: FsDescriptorFlags::READ,
                            identity: None,
                            mount: None,
                            open: None,
                        },
                    },
                    false,
                ),
            )]),
            authority: ProcessAuthority::root(),
            cwd: None,
        };

        let (base, path) = wasix_spawn_resolve_open_base(&snapshot, 0, "/workspace/logs/out")
            .expect("absolute preopen path should resolve");

        assert_eq!(base.path, "/source/workspace");
        assert_eq!(path, "logs/out");
    }

    #[test]
    fn wasix_signal_disposition_validation_accepts_default_and_ignore() {
        assert_eq!(
            wasix_signal_disposition_from_raw(2, WASIX_SIGNAL_DISPOSITION_DEFAULT),
            Ok(WasixSignalDisposition {
                signal: 2,
                action: WasixSignalDispositionAction::Default,
            })
        );
        assert_eq!(
            wasix_signal_disposition_from_raw(15, WASIX_SIGNAL_DISPOSITION_IGNORE),
            Ok(WasixSignalDisposition {
                signal: 15,
                action: WasixSignalDispositionAction::Ignore,
            })
        );
        assert_eq!(
            wasix_signal_disposition_from_raw(0, WASIX_SIGNAL_DISPOSITION_DEFAULT),
            Err(p1::errno::INVAL)
        );
        assert_eq!(
            wasix_signal_disposition_from_raw(1, 2),
            Err(p1::errno::INVAL)
        );
    }

    #[test]
    fn wasix_bridge_security_accepts_documented_values_only() {
        assert_eq!(
            wasix_bridge_security(i32::from(WASIX_STREAM_SECURITY_UNENCRYPTED))
                .map(crate::NetworkBridgeSecurity::raw),
            Ok(WASIX_STREAM_SECURITY_UNENCRYPTED)
        );
        assert_eq!(
            wasix_bridge_security(i32::from(WASIX_STREAM_SECURITY_ANY_ENCRYPTION))
                .map(crate::NetworkBridgeSecurity::raw),
            Ok(WASIX_STREAM_SECURITY_ANY_ENCRYPTION)
        );
        assert_eq!(wasix_bridge_security(0), Err(p1::errno::INVAL));
        assert_eq!(
            wasix_bridge_security(
                i32::from(WASIX_STREAM_SECURITY_CLASSIC_ENCRYPTION)
                    | i32::from(WASIX_STREAM_SECURITY_DOUBLE_ENCRYPTION)
            ),
            Err(p1::errno::INVAL)
        );
    }

    #[test]
    fn wasix_socket_operations_select_network_authority_by_socket_kind() {
        let tcp = Preview1Descriptor::Socket(UnixSocket::from_tcp(UnixTcpSocket::Connected {
            family: SocketFamily::Ipv4,
            stream: OwnedTcpStream::new(
                crate::UnixNetwork::new(crate::test_support::test_network_service()),
                1,
            ),
            peer_address: crate::NetworkIpAddress::Ipv4(crate::Ipv4Address::new([127, 0, 0, 1])),
            peer_port: 80,
            options: unix_socket_options::<TestNet>(),
        }));
        let udp_bound = Preview1Descriptor::Socket(UnixSocket::from_udp(UnixUdpSocket::Bound {
            family: SocketFamily::Ipv4,
            socket: OwnedUdpSocket::new(
                crate::UnixNetwork::new(crate::test_support::test_network_service()),
                2,
            ),
            local_address: crate::unix::unspecified_address(SocketFamily::Ipv4),
            local_port: 5353,
            peer: None,
            options: unix_socket_options::<TestNet>(),
        }));
        let udp_unbound: TestDescriptor =
            Preview1Descriptor::Socket(UnixSocket::udp(SocketFamily::Ipv4));
        let pair: TestDescriptor =
            Preview1Descriptor::Socket(TestSocketDescriptor::pair(SocketKind::Stream).0);
        let nonsocket: TestDescriptor = Preview1Descriptor::Stdout;

        assert_eq!(
            wasix_sock_recv_authority(Some(&tcp)),
            Ok(WasixSocketAuthority::Tcp)
        );
        assert_eq!(
            wasix_sock_send_authority(Some(&tcp)),
            Ok(WasixSocketAuthority::Tcp)
        );
        assert_eq!(
            wasix_sock_recv_authority(Some(&udp_bound)),
            Ok(WasixSocketAuthority::Udp)
        );
        assert_eq!(
            wasix_sock_send_authority(Some(&udp_bound)),
            Ok(WasixSocketAuthority::Udp)
        );
        assert_eq!(
            wasix_sock_send_authority(Some(&udp_unbound)),
            Ok(WasixSocketAuthority::Udp)
        );
        assert_eq!(
            wasix_sock_bind_authority(Some(&udp_unbound)),
            Ok(WasixSocketAuthority::Udp)
        );
        assert_eq!(
            wasix_sock_recv_authority(Some(&pair)),
            Ok(WasixSocketAuthority::LocalOnly)
        );
        assert_eq!(
            wasix_sock_send_authority(Some(&pair)),
            Ok(WasixSocketAuthority::LocalOnly)
        );
        assert_eq!(
            wasix_sock_bind_authority(Some(&udp_bound)),
            Err(p1::errno::INVAL)
        );
        assert_eq!(
            wasix_sock_listen_authority(Some(&tcp)),
            Ok(WasixSocketAuthority::Tcp)
        );
        assert_eq!(
            wasix_sock_listen_authority(Some(&udp_bound)),
            Err(p1::errno::INVAL)
        );
        assert_eq!(
            wasix_sock_listen_authority(Some(&pair)),
            Err(p1::errno::INVAL)
        );
        assert_eq!(
            wasix_sock_recv_authority(Some(&udp_unbound)),
            Err(p1::errno::INVAL)
        );
        assert_eq!(
            wasix_sock_send_authority(Some(&nonsocket)),
            Err(p1::errno::NOTSOCK)
        );
        assert_eq!(
            wasix_sock_listen_authority(Some(&nonsocket)),
            Err(p1::errno::NOTSOCK)
        );
        assert_eq!(
            wasix_sock_recv_authority::<TestNet>(None),
            Err(p1::errno::BADF)
        );
        assert_eq!(
            wasix_sock_send_authority::<TestNet>(None),
            Err(p1::errno::BADF)
        );
        assert_eq!(
            wasix_sock_listen_authority::<TestNet>(None),
            Err(p1::errno::BADF)
        );
    }

    #[test]
    fn wasix_multicast_preflight_accepts_udp_sockets_only() {
        let udp: TestDescriptor = Preview1Descriptor::Socket(UnixSocket::udp(SocketFamily::Ipv4));
        let tcp: TestDescriptor = Preview1Descriptor::Socket(UnixSocket::tcp(SocketFamily::Ipv4));
        let file: TestDescriptor = Preview1Descriptor::Stdout;

        assert_eq!(
            wasix_udp_socket_descriptor_status(Some(&udp)),
            p1::errno::SUCCESS
        );
        assert_eq!(
            wasix_udp_socket_descriptor_status(Some(&tcp)),
            p1::errno::INVAL
        );
        assert_eq!(
            wasix_udp_socket_descriptor_status(Some(&file)),
            p1::errno::NOTSOCK
        );
        assert_eq!(
            wasix_udp_socket_descriptor_status::<TestNet>(None),
            p1::errno::BADF
        );
    }

    #[test]
    fn wasix_multicast_v6_accepts_only_ipv6_address_tags() {
        assert_eq!(
            wasix_addr_ip6_family_status(WASIX_ADDRESS_FAMILY_IP_INET6),
            Ok(())
        );
        assert_eq!(
            wasix_addr_ip6_family_status(WASIX_ADDRESS_FAMILY_IP_INET4),
            Err(p1::errno::INVAL)
        );
        assert_eq!(
            wasix_addr_ip6_family_status(WASIX_ADDRESS_FAMILY_UNSPEC),
            Err(p1::errno::INVAL)
        );
        assert_eq!(
            wasix_addr_ip6_family_status(WASIX_ADDRESS_FAMILY_UNIX),
            Err(p1::errno::NOTSUP)
        );
        assert_eq!(wasix_addr_ip6_family_status(0xff), Err(p1::errno::INVAL));
    }

    #[test]
    fn preview1_fixed_memory_reads_copy_into_caller_buffer() {
        let guest = [1_u8, 2, 3, 4, 5, 6];
        let memory = Preview1Memory {
            base: guest.as_ptr() as usize,
            len: guest.len(),
        };
        let mut bytes = [0_u8; 4];

        preview1_read_memory_into(memory, GuestAddress::wasm32(1), &mut bytes)
            .expect("fixed read should fit");

        assert_eq!(bytes, [2, 3, 4, 5]);
        let error = preview1_read_memory_into(memory, GuestAddress::wasm32(4), &mut bytes)
            .expect_err("read should overflow");
        assert_eq!(error.kind, crate::ProgramExecErrorKind::InvalidBinary);
        assert_eq!(
            error.detail,
            ProgramExecErrorDetail::GuestMemoryAccessOutOfBounds
        );
    }

    /// Every WASI/WASIX host-call family addresses the fields of a guest
    /// structure as `base.offset(field)`. A base near the top of the 32-bit
    /// space must fault at the access, never wrap into low guest memory.
    #[test]
    fn guest_field_offsets_near_the_top_of_guest_space_fault_for_every_family() {
        let mut guest = [0xAA_u8; 64];
        let memory = Preview1Memory {
            base: guest.as_mut_ptr() as usize,
            len: guest.len(),
        };
        let base = GuestAddress::wasm32(u32::MAX - 2);
        // preview1 fd_prestat_get (+4), poll_oneoff event (+8..), filestat (+8..56)
        // and iovec (+4), WASIX epoll event, proc spawn handles, tty state and
        // thread snapshot (+8/+16) fields all use these offsets.
        let family_offsets = [
            ("preview1 prestat", 4_u64),
            ("preview1 iovec", 4),
            ("preview1 poll event", 8),
            ("preview1 filestat", 56),
            ("wasix epoll event", 16),
            ("wasix proc handles", 12),
            ("wasix tty state", 21),
            ("wasix thread snapshot", 16),
        ];
        for (family, offset) in family_offsets {
            let field = base.offset(offset);
            assert_eq!(
                preview1_write_memory(memory, field, &[1, 2, 3, 4]),
                p1::errno::FAULT,
                "{family}: write at u32::MAX - 2 + {offset} must be EFAULT",
            );
            let mut bytes = [0_u8; 4];
            assert!(
                preview1_read_memory_into(memory, field, &mut bytes).is_err(),
                "{family}: read at u32::MAX - 2 + {offset} must fail",
            );
        }
        assert!(
            guest.iter().all(|byte| *byte == 0xAA),
            "a wrapped offset must not write into low guest memory",
        );
    }

    #[test]
    fn guest_iovec_array_beyond_guest_space_faults() {
        let guest = [0_u8; 16];
        let memory = Preview1AsyncMemory::new(Preview1Memory {
            base: guest.as_ptr() as usize,
            len: guest.len(),
        });
        let layout = Preview1IovLayout {
            iovs: SmallVec::from_slice(&[(u32::MAX - 2, 4)]),
            byte_len: 4,
        };
        assert_eq!(
            Preview1Gather::new(&memory, &layout).err(),
            Some(p1::errno::FAULT),
        );
    }

    #[test]
    fn wasix_socket_creation_validates_family_and_protocol() {
        assert_eq!(
            wasix_validate_network_socket_request(
                WASIX_ADDRESS_FAMILY_IP_INET4_I32,
                WASIX_SOCK_TYPE_STREAM,
                WASIX_IPPROTO_TCP_I32,
            ),
            Ok(())
        );
        assert_eq!(
            wasix_validate_network_socket_request(
                WASIX_ADDRESS_FAMILY_UNSPEC_I32,
                WASIX_SOCK_TYPE_DGRAM,
                0,
            ),
            Ok(())
        );
        assert_eq!(
            wasix_validate_network_socket_request(
                WASIX_ADDRESS_FAMILY_UNIX_I32,
                WASIX_SOCK_TYPE_STREAM,
                0,
            ),
            Err(p1::errno::NOTSUP)
        );
        // AF_INET6 is a supported family for both socket types; only
        // AF_UNIX remains unsupported for network sockets.
        assert_eq!(
            wasix_validate_network_socket_request(
                WASIX_ADDRESS_FAMILY_IP_INET6_I32,
                WASIX_SOCK_TYPE_STREAM,
                WASIX_IPPROTO_TCP_I32,
            ),
            Ok(())
        );
        assert_eq!(
            wasix_validate_network_socket_request(
                WASIX_ADDRESS_FAMILY_IP_INET6_I32,
                WASIX_SOCK_TYPE_DGRAM,
                WASIX_IPPROTO_UDP_I32,
            ),
            Ok(())
        );
        // A mismatched protocol is still rejected within AF_INET6.
        assert_eq!(
            wasix_validate_network_socket_request(
                WASIX_ADDRESS_FAMILY_IP_INET6_I32,
                WASIX_SOCK_TYPE_STREAM,
                WASIX_IPPROTO_UDP_I32,
            ),
            Err(p1::errno::INVAL)
        );
        // socket_pair stays AF_UNIX/AF_UNSPEC only.
        assert_eq!(
            wasix_validate_socket_pair_request(
                WASIX_ADDRESS_FAMILY_IP_INET6_I32,
                WASIX_SOCK_TYPE_STREAM,
                0,
            ),
            Err(p1::errno::NOTSUP)
        );
        assert_eq!(
            wasix_validate_network_socket_request(
                WASIX_ADDRESS_FAMILY_IP_INET4_I32,
                WASIX_SOCK_TYPE_STREAM,
                WASIX_IPPROTO_UDP_I32,
            ),
            Err(p1::errno::INVAL)
        );
        assert_eq!(
            wasix_validate_socket_pair_request(
                WASIX_ADDRESS_FAMILY_UNIX_I32,
                WASIX_SOCK_TYPE_STREAM,
                0,
            ),
            Ok(SocketKind::Stream)
        );
        assert_eq!(
            wasix_validate_socket_pair_request(
                WASIX_ADDRESS_FAMILY_IP_INET4_I32,
                WASIX_SOCK_TYPE_STREAM,
                0,
            ),
            Err(p1::errno::NOTSUP)
        );
        assert_eq!(
            wasix_validate_socket_pair_request(
                WASIX_ADDRESS_FAMILY_IP_INET6_I32,
                WASIX_SOCK_TYPE_STREAM,
                0,
            ),
            Err(p1::errno::NOTSUP)
        );
        assert_eq!(
            wasix_validate_socket_pair_request(
                WASIX_ADDRESS_FAMILY_UNIX_I32,
                WASIX_SOCK_TYPE_DGRAM,
                WASIX_IPPROTO_UDP_I32,
            ),
            Err(p1::errno::INVAL)
        );
    }

    /// Ready mask for a descriptor whose readiness needs no network service.
    fn local_epoll_mask(descriptor: Option<&TestDescriptor>, interest: u32) -> u32 {
        if descriptor.is_none() {
            return WASIX_EPOLL_TYPE_EPOLLERR | WASIX_EPOLL_TYPE_EPOLLHUP;
        }
        let event_type = if interest & WASIX_EPOLL_TYPE_EPOLLOUT != 0 {
            P1_EVENTTYPE_FD_WRITE
        } else {
            P1_EVENTTYPE_FD_READ
        };
        let readiness = match p1_probe_descriptor(descriptor, event_type) {
            Ok(P1Probe::Local(readiness)) => Ok(readiness),
            Ok(P1Probe::Network(_)) => panic!("descriptor needs the network service"),
            Err(errno) => Err(errno),
        };
        wasix_epoll_mask_bit(readiness, event_type)
    }

    #[test]
    fn wasix_epoll_ready_mask_reports_supported_descriptor_readiness() {
        let stdout = Preview1Descriptor::Stdout;
        assert_eq!(
            local_epoll_mask(Some(&stdout), WASIX_EPOLL_TYPE_EPOLLOUT),
            WASIX_EPOLL_TYPE_EPOLLOUT
        );

        let event = Preview1Descriptor::Event(EventFd::new(1, false));
        assert_eq!(
            local_epoll_mask(Some(&event), WASIX_EPOLL_TYPE_EPOLLIN),
            WASIX_EPOLL_TYPE_EPOLLIN
        );

        let empty_event = Preview1Descriptor::Event(EventFd::new(0, false));
        assert_eq!(
            local_epoll_mask(Some(&empty_event), WASIX_EPOLL_TYPE_EPOLLIN),
            0
        );

        let (pipe_writer, pipe_reader) = crate::byte_channel();
        let pipe = Preview1Descriptor::PipeRead {
            reader: pipe_reader,
            inode: helios_unix::PipeInode::default(),
        };
        assert_eq!(local_epoll_mask(Some(&pipe), WASIX_EPOLL_TYPE_EPOLLIN), 0);
        assert_eq!(
            pipe_writer.try_write(Bytes::from_static(b"pipe")),
            crate::TryWrite::Written,
            "pipe reader is still open"
        );
        assert_eq!(
            local_epoll_mask(Some(&pipe), WASIX_EPOLL_TYPE_EPOLLIN),
            WASIX_EPOLL_TYPE_EPOLLIN
        );

        let (pair_socket, pair_peer) = TestSocketDescriptor::pair(SocketKind::Stream);
        let pair_writer = pair_peer.pair_writer().expect("pair peer has writer");
        let pair: TestDescriptor = Preview1Descriptor::Socket(pair_socket);
        assert_eq!(local_epoll_mask(Some(&pair), WASIX_EPOLL_TYPE_EPOLLIN), 0);
        assert_eq!(
            pair_writer.try_write(Bytes::from_static(b"pair")),
            crate::TryWrite::Written,
            "socket-pair reader is still open"
        );
        assert_eq!(
            local_epoll_mask(Some(&pair), WASIX_EPOLL_TYPE_EPOLLIN),
            WASIX_EPOLL_TYPE_EPOLLIN
        );

        assert_eq!(
            local_epoll_mask(None, WASIX_EPOLL_TYPE_EPOLLIN),
            WASIX_EPOLL_TYPE_EPOLLERR | WASIX_EPOLL_TYPE_EPOLLHUP
        );
    }

    #[test]
    fn shared_memory_pool_reuses_matching_spec_bucket() {
        let mut config = wasmtime::Config::new();
        config.wasm_threads(true);
        config.shared_memory(true);
        let engine = wasmtime::Engine::new(&config).unwrap();
        let spec = SharedMemorySpec {
            initial_pages: 1,
            maximum_pages: 1,
        };
        let mut pool = SharedMemoryPool::new(spec.byte_size() * 2);
        let memory = SharedMemory::new(&engine, spec.memory_type().unwrap()).unwrap();
        let ptr = memory.data().as_ptr().cast::<u8>() as *mut u8;
        // SAFETY: `memory` was created with 1 page (65,536 bytes) and is unshared here, so byte
        // 0 is in bounds and exclusively accessed.
        unsafe {
            ptr.write(0xa5);
        }

        // The recycle path scrubs before re-pooling, so acquire never
        // zeroes on the spawn path and pooled entries come back clean.
        assert!(pool.reserve_for_recycle(spec, &memory));
        assert_eq!(pool.resident_bytes, spec.byte_size());
        futures_lite::future::block_on(scrub_shared_memory(&memory));
        pool.finish_recycle(spec, memory);

        let reused = pool.acquire(&engine, spec).unwrap();
        assert_eq!(pool.resident_bytes, 0);
        assert!(pool.buckets.contains_key(&spec));
        // SAFETY: `reused` has 1 page (65,536 bytes) and was just acquired exclusively from
        // `pool`, so byte 0 is valid to read with no concurrent writers.
        let zeroed = unsafe { reused.data()[0].get().read() };
        assert_eq!(zeroed, 0);
    }

    #[test]
    fn shared_memory_pool_evicts_other_specs_under_pressure() {
        let mut config = wasmtime::Config::new();
        config.wasm_threads(true);
        config.shared_memory(true);
        let engine = wasmtime::Engine::new(&config).unwrap();
        let spec = SharedMemorySpec {
            initial_pages: 1,
            maximum_pages: 1,
        };
        let mut pool = SharedMemoryPool::new(spec.byte_size() * 2);
        let memory = SharedMemory::new(&engine, spec.memory_type().unwrap()).unwrap();
        assert!(pool.reserve_for_recycle(spec, &memory));
        futures_lite::future::block_on(scrub_shared_memory(&memory));
        pool.finish_recycle(spec, memory);

        // A retained entry under another spec is dropped, releasing its
        // budget and user RAM, rather than starving a failing allocation.
        assert!(pool.evict_one());
        assert_eq!(pool.resident_bytes, 0);
        assert!(!pool.evict_one());
    }

    #[test]
    fn wasix_socket_size_options_are_descriptor_local_state() {
        let descriptor: TestSocketDescriptor = UnixSocket::tcp(SocketFamily::Ipv4);

        // The defaults a WASIX program reads back before setting anything.
        assert_eq!(
            descriptor.options().size(SocketSize::ReceiveBuffer),
            64 * 1024
        );
        assert_eq!(descriptor.options().size(SocketSize::SendBuffer), 64 * 1024);
        assert_eq!(
            wasix_socket_size(&descriptor, WASIX_SOCK_OPTION_RECV_LOWAT),
            Ok(1)
        );
        assert_eq!(
            wasix_socket_size(&descriptor, WASIX_SOCK_OPTION_TTL),
            Ok(u64::from(helios_netstack::DEFAULT_HOP_LIMIT))
        );

        assert_eq!(
            wasix_socket_set_size(&descriptor, WASIX_SOCK_OPTION_RECV_BUF_SIZE, 4096),
            p1::errno::SUCCESS
        );
        assert_eq!(
            wasix_socket_set_size(&descriptor, WASIX_SOCK_OPTION_SEND_BUF_SIZE, 8192),
            p1::errno::SUCCESS
        );
        assert_eq!(
            wasix_socket_set_size(&descriptor, WASIX_SOCK_OPTION_RECV_LOWAT, 2),
            p1::errno::SUCCESS
        );
        assert_eq!(
            wasix_socket_set_size(&descriptor, WASIX_SOCK_OPTION_TTL, 128),
            p1::errno::SUCCESS
        );

        assert_eq!(descriptor.options().size(SocketSize::ReceiveBuffer), 4096);
        assert_eq!(descriptor.options().size(SocketSize::SendBuffer), 8192);
        assert_eq!(
            wasix_socket_size(&descriptor, WASIX_SOCK_OPTION_RECV_LOWAT),
            Ok(2)
        );
        assert_eq!(
            wasix_socket_size(&descriptor, WASIX_SOCK_OPTION_TTL),
            Ok(128)
        );
        assert_eq!(
            wasix_socket_set_size(
                &descriptor,
                WASIX_SOCK_OPTION_TYPE,
                WASIX_SOCK_TYPE_STREAM as u64
            ),
            p1::errno::INVAL
        );
        assert_eq!(
            wasix_socket_size(&descriptor, WASIX_SOCK_OPTION_RECV_TIMEOUT),
            Err(p1::errno::INVAL)
        );
    }

    #[test]
    fn wasix_socket_flag_options_are_descriptor_local_state() {
        let descriptor: TestSocketDescriptor = UnixSocket::udp(SocketFamily::Ipv4);

        assert_eq!(
            wasix_socket_set_flag(&descriptor, WASIX_SOCK_OPTION_BROADCAST, true),
            p1::errno::SUCCESS
        );
        assert_eq!(
            wasix_socket_set_flag(&descriptor, WASIX_SOCK_OPTION_REUSE_ADDR, true),
            p1::errno::SUCCESS
        );
        assert_eq!(
            wasix_socket_flag(&descriptor, WASIX_SOCK_OPTION_BROADCAST),
            Ok(true)
        );
        assert_eq!(
            wasix_socket_flag(&descriptor, WASIX_SOCK_OPTION_REUSE_ADDR),
            Ok(true)
        );
        assert_eq!(
            wasix_socket_flag(&descriptor, WASIX_SOCK_OPTION_KEEP_ALIVE),
            Ok(false)
        );

        assert_eq!(
            wasix_socket_set_flag(&descriptor, WASIX_SOCK_OPTION_BROADCAST, false),
            p1::errno::SUCCESS
        );
        assert_eq!(
            wasix_socket_flag(&descriptor, WASIX_SOCK_OPTION_BROADCAST),
            Ok(false)
        );
        assert_eq!(
            wasix_socket_flag(&descriptor, WASIX_SOCK_OPTION_RECV_BUF_SIZE),
            Err(p1::errno::INVAL)
        );
    }

    /// Options the netstack cannot honour must fail loudly.
    ///
    /// The stack has no keepalive timer and transmits as soon as the window
    /// allows, so `SO_KEEPALIVE` on and `TCP_NODELAY` off are behaviours it
    /// will never produce. Recording them silently would tell a guest its
    /// connections are being probed or coalesced when they are not.
    #[test]
    fn wasix_socket_rejects_flags_the_netstack_cannot_honour() {
        let descriptor: TestSocketDescriptor = UnixSocket::tcp(SocketFamily::Ipv4);

        assert_eq!(
            wasix_socket_set_flag(&descriptor, WASIX_SOCK_OPTION_KEEP_ALIVE, true),
            p1::errno::NOTSUP
        );
        assert_eq!(
            wasix_socket_flag(&descriptor, WASIX_SOCK_OPTION_KEEP_ALIVE),
            Ok(false)
        );
        assert_eq!(
            wasix_socket_set_flag(&descriptor, WASIX_SOCK_OPTION_KEEP_ALIVE, false),
            p1::errno::SUCCESS
        );

        assert_eq!(
            wasix_socket_set_flag(&descriptor, WASIX_SOCK_OPTION_NO_DELAY, true),
            p1::errno::SUCCESS
        );
        assert_eq!(
            wasix_socket_flag(&descriptor, WASIX_SOCK_OPTION_NO_DELAY),
            Ok(true)
        );
        assert_eq!(
            wasix_socket_set_flag(&descriptor, WASIX_SOCK_OPTION_NO_DELAY, false),
            p1::errno::NOTSUP
        );
        assert_eq!(
            wasix_socket_flag(&descriptor, WASIX_SOCK_OPTION_NO_DELAY),
            Ok(true)
        );
    }

    /// Buffer hints clamp to the netstack's real per-socket reservations, and
    /// a TTL outside the IP header's range is rejected instead of truncated.
    #[test]
    fn wasix_socket_size_options_clamp_to_netstack_capacity() {
        let descriptor: TestSocketDescriptor = UnixSocket::tcp(SocketFamily::Ipv4);

        assert_eq!(
            wasix_socket_set_size(&descriptor, WASIX_SOCK_OPTION_RECV_BUF_SIZE, u64::MAX),
            p1::errno::SUCCESS
        );
        assert_eq!(
            descriptor.options().size(SocketSize::ReceiveBuffer),
            helios_netstack::TCP_RECEIVE_WINDOW_BYTES as u64
        );
        assert_eq!(
            wasix_socket_set_size(&descriptor, WASIX_SOCK_OPTION_SEND_BUF_SIZE, u64::MAX),
            p1::errno::SUCCESS
        );
        assert_eq!(
            descriptor.options().size(SocketSize::SendBuffer),
            helios_netstack::TCP_TRANSMIT_BUFFER_BYTES as u64
        );

        assert_eq!(
            wasix_socket_set_size(&descriptor, WASIX_SOCK_OPTION_TTL, 0),
            p1::errno::INVAL
        );
        assert_eq!(
            wasix_socket_set_size(&descriptor, WASIX_SOCK_OPTION_TTL, 256),
            p1::errno::INVAL
        );
        assert_eq!(
            descriptor.options().hop_limit(),
            helios_netstack::DEFAULT_HOP_LIMIT
        );
        assert_eq!(
            wasix_socket_set_size(&descriptor, WASIX_SOCK_OPTION_TTL, 9),
            p1::errno::SUCCESS
        );
        assert_eq!(descriptor.options().hop_limit(), 9);
    }

    /// `/dev/null` has no backing filesystem object, so it needs a device id
    /// of its own for `st_dev`/`st_ino` to stay distinct and stable.
    #[test]
    fn null_device_reports_a_stable_device_identity() {
        let identity = p1_null_device_identity();

        assert_eq!(identity, p1_null_device_identity());
        assert_eq!(identity.domain(), crate::AuthorityDomain::GUEST_DEVICES);
        assert_ne!(identity.domain(), crate::AuthorityDomain::GUEST_BOOTFS);
        assert_ne!(identity.domain(), crate::AuthorityDomain::HOST_SHARE_9P);
        assert_ne!(identity.domain().raw(), 0);
        assert_ne!(identity.local(), 0);
    }

    #[test]
    fn stdio_and_pipe_descriptors_report_character_device_filestat() {
        let (writer, reader) = crate::byte_channel();
        let descriptors: [TestDescriptor; 5] = [
            Preview1Descriptor::Stdin {
                carry: Bytes::new(),
            },
            Preview1Descriptor::Stdout,
            Preview1Descriptor::Stderr,
            Preview1Descriptor::PipeRead {
                reader,
                inode: helios_unix::PipeInode::default(),
            },
            Preview1Descriptor::PipeWrite {
                writer,
                inode: helios_unix::PipeInode::default(),
            },
        ];
        for descriptor in &descriptors {
            let (identity, stat) =
                p1_synthetic_descriptor_stat(descriptor).expect("stdio/pipe must have filestat");
            assert_eq!(identity.domain(), crate::AuthorityDomain::GUEST_DEVICES);
            assert_ne!(identity.local(), 0);
            assert_ne!(identity, p1_null_device_identity());
            assert!(matches!(
                stat.type_,
                fs_types::DescriptorType::CharacterDevice
            ));
        }
    }

    #[test]
    fn wasix_socket_time_options_are_descriptor_local_state() {
        let descriptor: TestSocketDescriptor = UnixSocket::tcp(SocketFamily::Ipv4);

        assert_eq!(
            wasix_socket_time(&descriptor, WASIX_SOCK_OPTION_RECV_TIMEOUT),
            Ok(None)
        );
        assert_eq!(
            wasix_socket_set_time(&descriptor, WASIX_SOCK_OPTION_RECV_TIMEOUT, Some(1_000)),
            p1::errno::SUCCESS
        );
        assert_eq!(
            wasix_socket_time(&descriptor, WASIX_SOCK_OPTION_RECV_TIMEOUT),
            Ok(Some(1_000))
        );
        assert_eq!(
            wasix_socket_set_time(&descriptor, WASIX_SOCK_OPTION_LINGER, Some(2_000)),
            p1::errno::SUCCESS
        );
        assert_eq!(
            wasix_socket_time(&descriptor, WASIX_SOCK_OPTION_LINGER),
            Ok(Some(2_000))
        );
        assert_eq!(
            wasix_socket_set_time(&descriptor, WASIX_SOCK_OPTION_SEND_BUF_SIZE, None),
            p1::errno::INVAL
        );
    }

    /// An exec of a path the authority admits but no file backs is the
    /// filesystem's no-entry, not an authority refusal (#502): the kind is
    /// `NotFound`, the detail carries the filesystem's error, and the
    /// guest reads `ENOENT`.
    #[test]
    fn wasix_exec_of_a_missing_program_file_is_not_found() {
        let namespace =
            Namespace::<crate::test_support::UnsupportedStorage>::new(crate::MountTable::new(
                crate::BootFs::new(crate::EmbeddedBootFs::new(&[], &[]), crate::BOOT_DEVICE),
                1,
            ));
        let authority = ProcessAuthority::root();

        let error = futures_lite::future::block_on(read_program_source_from(
            &namespace, &authority, "/forged",
        ))
        .err()
        .expect("a path no file backs cannot be read as a program");

        assert_eq!(error.kind, ProgramExecErrorKind::NotFound);
        assert_eq!(
            error.detail,
            ProgramExecErrorDetail::ProgramSourceUnreadable(helios_hal::fs::FsError::NoEntry),
            "the filesystem's own error travels in the detail"
        );
        assert_eq!(p1_errno_from_program_exec_error(&error), p1::errno::NOENT);
    }
}
