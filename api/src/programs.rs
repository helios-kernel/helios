//! User-program exec and spawn interfaces.
//!
//! `spawn` is the low-level entry point: it launches a program artifact and
//! returns a handle whose `stdin`/`stdout`/`stderr` are byte streams that
//! can be piped from/into another stream endpoint. `exec` is the
//! convenience "run to completion with buffered output" wrapper, and `aot`
//! produces a signed `cwasm` artifact at a caller-chosen destination path.

use crate::bindings::helios::system::programs as raw;
use crate::bindings::wit_stream;
use crate::wit_bindgen::{FutureReader, StreamReader};
use futures_lite::future::zip;

pub use crate::bindings::helios::system::programs::{
    AotHint, AotRequest, AotResult, AuthorityScope, CapabilityGrant, ChildTermination, ClockGrant,
    ClockRight, ContainerConfig, ContainerCredentials, ContainerExecRequest, ContainerIdentity,
    ContainerMount, ContainerMountSharing, ContainerSpawnRequest, DefaultLinuxImage, DeviceClass,
    DeviceGrant, DiagnosticsGrant, DirectoryGrant, ExecError, ExecErrorKind, ExecOutput,
    ExecRequest, ExecResult, ExitStatus, FilesystemRight, InheritedSocket, IpcGrant, LinkGrant,
    LinkRight, MachineGrant, MachineRight, MountGrant, MountRight, NetworkGrant, NetworkRight,
    ProcessGrant, ProcessRight, SettingsGrant, SettingsRight, SignalTermination, SpawnError,
    SpawnErrorKind, SpawnRequest, TerminalGrant, TerminalRight,
};

impl PartialEq for ChildTermination {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Exited(a), Self::Exited(b)) => a == b,
            (
                Self::Signaled(SignalTermination {
                    signal: a_sig,
                    core_dumped: a_core,
                }),
                Self::Signaled(SignalTermination {
                    signal: b_sig,
                    core_dumped: b_core,
                }),
            ) => a_sig == b_sig && a_core == b_core,
            (Self::Trapped, Self::Trapped) | (Self::Killed, Self::Killed) => true,
            _ => false,
        }
    }
}

impl Eq for ChildTermination {}

impl core::fmt::Display for ChildTermination {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Exited(code) => write!(f, "exited with code {code}"),
            Self::Signaled(SignalTermination {
                signal,
                core_dumped: false,
            }) => write!(f, "ended by signal {signal}"),
            Self::Signaled(SignalTermination {
                signal,
                core_dumped: true,
            }) => write!(f, "ended by signal {signal} (core dumped)"),
            Self::Trapped => f.write_str("trapped"),
            Self::Killed => f.write_str("was killed"),
        }
    }
}

/// Build a directory capability grant for `helios:system/programs`.
pub fn directory_grant(
    source_path: impl Into<String>,
    guest_name: impl Into<String>,
    rights: Vec<FilesystemRight>,
) -> CapabilityGrant {
    CapabilityGrant::Directory(DirectoryGrant {
        source_path: source_path.into(),
        guest_name: guest_name.into(),
        rights,
    })
}

/// Full root preopen grant for trusted system programs such as the shell.
pub fn root_directory_grant() -> CapabilityGrant {
    directory_grant(
        "/",
        "/",
        vec![
            FilesystemRight::Read,
            FilesystemRight::Write,
            FilesystemRight::MutateDirectory,
            FilesystemRight::Execute,
        ],
    )
}

pub fn network_grant(rights: Vec<NetworkRight>) -> CapabilityGrant {
    CapabilityGrant::Network(NetworkGrant { rights })
}

pub fn clock_grant(rights: Vec<ClockRight>) -> CapabilityGrant {
    CapabilityGrant::Clock(ClockGrant { rights })
}

pub fn terminal_grant(rights: Vec<TerminalRight>) -> CapabilityGrant {
    CapabilityGrant::Terminal(TerminalGrant { rights })
}

pub fn root_terminal_grant() -> CapabilityGrant {
    terminal_grant(vec![
        TerminalRight::Input,
        TerminalRight::Output,
        TerminalRight::Control,
    ])
}

pub fn process_grant(rights: Vec<ProcessRight>) -> CapabilityGrant {
    CapabilityGrant::Process(ProcessGrant { rights })
}

pub fn link_grant(rights: Vec<LinkRight>) -> CapabilityGrant {
    CapabilityGrant::Link(LinkGrant { rights })
}

/// Build a mount-table capability grant: the child may attach or detach
/// filesystems at directories its directory grants let it change.
pub fn mount_grant(rights: Vec<MountRight>) -> CapabilityGrant {
    CapabilityGrant::Mount(MountGrant { rights })
}

pub fn root_mount_grant() -> CapabilityGrant {
    mount_grant(vec![MountRight::Mount, MountRight::Unmount])
}

pub fn root_link_grant() -> CapabilityGrant {
    link_grant(vec![
        LinkRight::Source,
        LinkRight::TargetDirectory,
        LinkRight::SymlinkCreate,
        LinkRight::SymlinkRead,
    ])
}

/// Build a device-class grant. A program holds a class only when its
/// parent granted it, so the classes must be a subset of the caller's.
pub fn device_grant(classes: Vec<DeviceClass>) -> CapabilityGrant {
    CapabilityGrant::Device(DeviceGrant { classes })
}

/// Every device class, for a trusted launcher that runs programs on the
/// machine owner's behalf.
pub fn all_device_classes_grant() -> CapabilityGrant {
    device_grant(vec![
        DeviceClass::Display,
        DeviceClass::Input,
        DeviceClass::Gpu,
        DeviceClass::Audio,
    ])
}

/// Build a single orthogonal diagnostics capability grant.
pub fn diagnostics_grant(grant: DiagnosticsGrant) -> CapabilityGrant {
    CapabilityGrant::Diagnostics(grant)
}

/// Grant `helios:system/instances.snapshot` and `helios:system/inspect` read
/// visibility within `scope`.
pub fn inspect_read_grant(scope: AuthorityScope) -> CapabilityGrant {
    CapabilityGrant::Diagnostics(DiagnosticsGrant::InspectRead(scope))
}

/// Grant `helios:system/tracing` read visibility within `scope`.
pub fn trace_read_grant(scope: AuthorityScope) -> CapabilityGrant {
    CapabilityGrant::Diagnostics(DiagnosticsGrant::TraceRead(scope))
}

/// Grant `helios:system/profiling` read visibility within `scope`.
pub fn profile_read_grant(scope: AuthorityScope) -> CapabilityGrant {
    CapabilityGrant::Diagnostics(DiagnosticsGrant::ProfileRead(scope))
}

/// Grant mutation of global diagnostic gates and profilers.
pub fn diagnostics_control_grant() -> CapabilityGrant {
    CapabilityGrant::Diagnostics(DiagnosticsGrant::Control)
}

/// Grant `helios:system/instances.kill` within `scope`.
pub fn instance_control_grant(scope: AuthorityScope) -> CapabilityGrant {
    CapabilityGrant::InstanceControl(scope)
}

/// Build a settings grant. A program holds a right only when its parent
/// granted it, so the rights must be a subset of the caller's.
pub fn settings_grant(rights: Vec<SettingsRight>) -> CapabilityGrant {
    CapabilityGrant::Settings(SettingsGrant { rights })
}

/// Change the machine-wide settings, for a trusted launcher that runs
/// programs on the machine owner's behalf.
pub fn write_settings_grant() -> CapabilityGrant {
    settings_grant(vec![SettingsRight::Write])
}

/// Build a machine grant. A program holds a right only when its parent
/// granted it, so the rights must be a subset of the caller's.
pub fn machine_grant(rights: Vec<MachineRight>) -> CapabilityGrant {
    CapabilityGrant::Machine(MachineGrant { rights })
}

/// Grant `machine-right.control` (processor online/offline transitions and
/// VMM snapshot holds).
pub fn machine_control_grant() -> CapabilityGrant {
    machine_grant(vec![MachineRight::Control])
}

/// Grant `machine-right.identity` (Ed25519 machine-identity signing).
pub fn machine_identity_grant() -> CapabilityGrant {
    machine_grant(vec![MachineRight::Identity])
}

/// Transfer a duplex IPC channel endpoint into a spawned child under `name`.
pub fn ipc_grant(
    name: impl Into<String>,
    endpoint: crate::bindings::helios::system::ipc::Endpoint,
) -> CapabilityGrant {
    CapabilityGrant::Ipc(IpcGrant {
        name: name.into(),
        endpoint,
    })
}

/// Create hardware virtual machines (`helios:hv/virtualization`), for a
/// trusted launcher that runs VMMs on the machine owner's behalf.
pub fn virtualize_grant() -> CapabilityGrant {
    machine_grant(vec![MachineRight::Virtualize])
}

pub fn root_process_grant() -> CapabilityGrant {
    process_grant(vec![
        ProcessRight::Spawn,
        ProcessRight::Exec,
        ProcessRight::Fork,
        ProcessRight::Join,
        ProcessRight::Signal,
    ])
}

/// Owned handle to a spawned child program.
///
/// The handle is the userland wrapper around the `helios:system/programs.child`
/// WIT resource. It exposes ergonomic Rust APIs for reading the child's
/// stdout/stderr, feeding it stdin, and waiting for its exit status.
pub struct Child {
    inner: raw::Child,
}

/// The child closed its standard input before the bytes were delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StdinClosed;

impl core::fmt::Display for StdinClosed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the child closed its standard input")
    }
}

impl std::error::Error for StdinClosed {}

impl Child {
    #[cfg(feature = "root-supervisor")]
    pub(crate) fn from_raw(inner: raw::Child) -> Self {
        Self { inner }
    }

    /// Launch a program and return a live [`Child`] handle.
    pub async fn spawn(request: SpawnRequest) -> Result<Self, SpawnError> {
        let inner = raw::spawn(request).await?;
        Ok(Self { inner })
    }

    /// Pipe `bytes` into the child's stdin and close the writer. Returns
    /// when the delivery completes.
    pub async fn write_stdin(&self, bytes: Vec<u8>) -> Result<(), StdinClosed> {
        let (mut tx, rx) = wit_stream::new::<u8>();
        let future = self.inner.stdin(rx);
        let produce = async move {
            if !bytes.is_empty() {
                let _ = tx.write_all(bytes).await;
            }
            drop(tx);
        };
        let ((), result) = zip(produce, std::future::IntoFuture::into_future(future)).await;
        result.map_err(|()| StdinClosed)
    }

    /// Collect the child's entire stdout as a `Vec<u8>`.
    pub async fn read_stdout(&self) -> Vec<u8> {
        drain_stream(self.inner.stdout()).await
    }

    /// Collect the child's entire stderr as a `Vec<u8>`.
    pub async fn read_stderr(&self) -> Vec<u8> {
        drain_stream(self.inner.stderr()).await
    }

    /// Return the child's raw stdout byte stream reader plus the
    /// completion future. Useful for piping the child's stdout directly
    /// into another program's stdin without buffering.
    pub fn stdout(&self) -> (StreamReader<u8>, FutureReader<Result<(), ()>>) {
        self.inner.stdout()
    }

    /// Return the child's raw stderr byte stream reader plus the
    /// completion future.
    pub fn stderr(&self) -> (StreamReader<u8>, FutureReader<Result<(), ()>>) {
        self.inner.stderr()
    }

    /// Pipe a stream into the child's stdin. Returns the completion
    /// future.
    pub fn pipe_stdin(&self, data: StreamReader<u8>) -> FutureReader<Result<(), ()>> {
        self.inner.stdin(data)
    }

    /// Deliver a POSIX signal (`1..=64`) to the child process.
    pub fn signal(&self, signal: u8) -> Result<(), SpawnError> {
        self.inner.signal(signal)
    }

    /// Await child completion.
    pub async fn wait(self) -> Result<ExitStatus, SpawnError> {
        self.inner.wait().await
    }
}

async fn drain_stream(pair: (StreamReader<u8>, FutureReader<Result<(), ()>>)) -> Vec<u8> {
    let (mut stream, future) = pair;
    let mut collected = Vec::new();
    const CHUNK: usize = 16 * 1024;
    loop {
        let buf = Vec::with_capacity(CHUNK);
        let (result, chunk) = stream.read(buf).await;
        if !chunk.is_empty() {
            collected.extend_from_slice(&chunk);
        }
        if crate::stream_closed(result) {
            break;
        }
    }
    let _ = std::future::IntoFuture::into_future(future).await;
    collected
}

/// Owned handle to a kernel Linux container.
///
/// The handle wraps the `helios:system/programs.container` WIT resource.
/// Processes launched through it share its root, mounts, PID namespace
/// (starting at 1), hostname and domain name, and are bounded by the
/// container's granted authority.
pub struct Container {
    inner: raw::Container,
}

impl Container {
    /// Create a new Linux container bounded by the caller's authority.
    pub async fn create(config: ContainerConfig) -> Result<Self, SpawnError> {
        let inner = raw::create_container(config).await?;
        Ok(Self { inner })
    }

    /// Spawn a Linux program inside this container and return its live handle.
    pub async fn spawn(&self, request: ContainerSpawnRequest) -> Result<Child, SpawnError> {
        let inner = self.inner.spawn(request).await?;
        Ok(Child { inner })
    }

    /// Run a Linux program to completion inside this container, collecting its
    /// buffered stdout and stderr.
    pub async fn exec(&self, request: ContainerExecRequest) -> Result<ExecResult, ExecError> {
        self.inner.exec(request).await
    }
}

/// Create a new Linux container bounded by the caller's authority.
pub async fn create_container(config: ContainerConfig) -> Result<Container, SpawnError> {
    Container::create(config).await
}

/// Launch a program by path and wait for it to finish, collecting its
/// stdout/stderr buffers.
pub async fn exec(request: ExecRequest) -> Result<ExecResult, ExecError> {
    raw::exec(request).await
}

/// Spawn a program and return the live handle.
pub async fn spawn(request: SpawnRequest) -> Result<Child, SpawnError> {
    Child::spawn(request).await
}

/// Set or clear this instance's default Linux root image.
pub async fn set_default_image(image: Option<DefaultLinuxImage>) -> Result<(), SpawnError> {
    raw::set_default_image(image).await
}

/// Return this instance's current default Linux root image, if any.
pub fn get_default_image() -> Option<DefaultLinuxImage> {
    raw::get_default_image()
}

/// Claim pre-bound listening sockets handed to this instance at spawn.
pub fn take_inherited_sockets() -> Vec<InheritedSocket> {
    raw::take_inherited_sockets()
}

/// Ahead-of-time compile a raw program artifact into a signed `cwasm` file.
pub async fn aot(request: AotRequest) -> Result<AotResult, ExecError> {
    raw::aot(request).await
}

/// Non-filesystem capability grant that may be attached to a Linux [`crate::linux::Container`].
///
/// Intentionally omits [`DirectoryGrant`]: containers receive filesystem authority
/// exclusively through `ContainerConfig.root` and `ContainerConfig.mounts`, enforcing
/// separation at compile time.
pub enum NonFsGrant {
    Network(NetworkGrant),
    Clock(ClockGrant),
    Terminal(TerminalGrant),
    Process(ProcessGrant),
    Link(LinkGrant),
    Mount(MountGrant),
    Device(DeviceGrant),
    Diagnostics(DiagnosticsGrant),
    InstanceControl(AuthorityScope),
    Settings(SettingsGrant),
    Machine(MachineGrant),
    Ipc(IpcGrant),
}

impl From<NonFsGrant> for CapabilityGrant {
    fn from(grant: NonFsGrant) -> Self {
        match grant {
            NonFsGrant::Network(g) => Self::Network(g),
            NonFsGrant::Clock(g) => Self::Clock(g),
            NonFsGrant::Terminal(g) => Self::Terminal(g),
            NonFsGrant::Process(g) => Self::Process(g),
            NonFsGrant::Link(g) => Self::Link(g),
            NonFsGrant::Mount(g) => Self::Mount(g),
            NonFsGrant::Device(g) => Self::Device(g),
            NonFsGrant::Diagnostics(g) => Self::Diagnostics(g),
            NonFsGrant::InstanceControl(s) => Self::InstanceControl(s),
            NonFsGrant::Settings(g) => Self::Settings(g),
            NonFsGrant::Machine(g) => Self::Machine(g),
            NonFsGrant::Ipc(g) => Self::Ipc(g),
        }
    }
}

/// Fluent, typed builder for non-filesystem capability grants.
///
/// Accepted by [`crate::linux::ContainerBuilder::grants`]; rejects [`DirectoryGrant`]
/// and [`ProcessGrants`] at compile time.
///
/// ```compile_fail
/// use helios_api::linux::Container;
/// use helios_api::programs::ProcessGrants;
///
/// let process_grants = ProcessGrants::new().bind_dir_rw("/workspace");
/// let _ = Container::ephemeral("/oci/alpine").grants(process_grants);
/// ```
#[derive(Default)]
pub struct NonFsGrants {
    grants: Vec<NonFsGrant>,
}

impl NonFsGrants {
    #[must_use]
    pub const fn new() -> Self {
        Self { grants: Vec::new() }
    }

    #[must_use]
    pub fn grant(mut self, grant: NonFsGrant) -> Self {
        self.grants.push(grant);
        self
    }

    #[must_use]
    pub fn network(self, rights: Vec<NetworkRight>) -> Self {
        self.grant(NonFsGrant::Network(NetworkGrant { rights }))
    }

    #[must_use]
    pub fn full_network(self) -> Self {
        self.network(vec![
            NetworkRight::Tcp,
            NetworkRight::Udp,
            NetworkRight::Dns,
            NetworkRight::PrivilegedBind,
            NetworkRight::Multicast,
            NetworkRight::Admin,
        ])
    }

    #[must_use]
    pub fn clock(self, rights: Vec<ClockRight>) -> Self {
        self.grant(NonFsGrant::Clock(ClockGrant { rights }))
    }

    #[must_use]
    pub fn set_wall_clock(self) -> Self {
        self.clock(vec![ClockRight::SetWallClock])
    }

    #[must_use]
    pub fn terminal(self, rights: Vec<TerminalRight>) -> Self {
        self.grant(NonFsGrant::Terminal(TerminalGrant { rights }))
    }

    #[must_use]
    pub fn all_terminal(self) -> Self {
        self.terminal(vec![
            TerminalRight::Input,
            TerminalRight::Output,
            TerminalRight::Control,
        ])
    }

    #[must_use]
    pub fn process(self, rights: Vec<ProcessRight>) -> Self {
        self.grant(NonFsGrant::Process(ProcessGrant { rights }))
    }

    #[must_use]
    pub fn all_process(self) -> Self {
        self.process(vec![
            ProcessRight::Spawn,
            ProcessRight::Exec,
            ProcessRight::Fork,
            ProcessRight::Join,
            ProcessRight::Signal,
        ])
    }

    #[must_use]
    pub fn link(self, rights: Vec<LinkRight>) -> Self {
        self.grant(NonFsGrant::Link(LinkGrant { rights }))
    }

    #[must_use]
    pub fn all_link(self) -> Self {
        self.link(vec![
            LinkRight::Source,
            LinkRight::TargetDirectory,
            LinkRight::SymlinkCreate,
            LinkRight::SymlinkRead,
        ])
    }

    #[must_use]
    pub fn mount(self, rights: Vec<MountRight>) -> Self {
        self.grant(NonFsGrant::Mount(MountGrant { rights }))
    }

    #[must_use]
    pub fn all_mount(self) -> Self {
        self.mount(vec![MountRight::Mount, MountRight::Unmount])
    }

    #[must_use]
    pub fn device(self, classes: Vec<DeviceClass>) -> Self {
        self.grant(NonFsGrant::Device(DeviceGrant { classes }))
    }

    #[must_use]
    pub fn all_devices(self) -> Self {
        self.device(vec![
            DeviceClass::Display,
            DeviceClass::Input,
            DeviceClass::Gpu,
            DeviceClass::Audio,
        ])
    }

    #[must_use]
    pub fn diagnostics(self, grant: DiagnosticsGrant) -> Self {
        self.grant(NonFsGrant::Diagnostics(grant))
    }

    #[must_use]
    pub fn inspect_read(self, scope: AuthorityScope) -> Self {
        self.diagnostics(DiagnosticsGrant::InspectRead(scope))
    }

    #[must_use]
    pub fn trace_read(self, scope: AuthorityScope) -> Self {
        self.diagnostics(DiagnosticsGrant::TraceRead(scope))
    }

    #[must_use]
    pub fn profile_read(self, scope: AuthorityScope) -> Self {
        self.diagnostics(DiagnosticsGrant::ProfileRead(scope))
    }

    #[must_use]
    pub fn diagnostics_control(self) -> Self {
        self.diagnostics(DiagnosticsGrant::Control)
    }

    #[must_use]
    pub fn instance_control(self, scope: AuthorityScope) -> Self {
        self.grant(NonFsGrant::InstanceControl(scope))
    }

    #[must_use]
    pub fn settings(self, rights: Vec<SettingsRight>) -> Self {
        self.grant(NonFsGrant::Settings(SettingsGrant { rights }))
    }

    #[must_use]
    pub fn write_settings(self) -> Self {
        self.settings(vec![SettingsRight::Write])
    }

    #[must_use]
    pub fn machine(self, rights: Vec<MachineRight>) -> Self {
        self.grant(NonFsGrant::Machine(MachineGrant { rights }))
    }

    #[must_use]
    pub fn machine_control(self) -> Self {
        self.machine(vec![MachineRight::Control])
    }

    #[must_use]
    pub fn machine_identity(self) -> Self {
        self.machine(vec![MachineRight::Identity])
    }

    #[must_use]
    pub fn virtualize(self) -> Self {
        self.machine(vec![MachineRight::Virtualize])
    }

    #[must_use]
    pub fn ipc(
        self,
        name: impl Into<String>,
        endpoint: crate::bindings::helios::system::ipc::Endpoint,
    ) -> Self {
        self.grant(NonFsGrant::Ipc(IpcGrant {
            name: name.into(),
            endpoint,
        }))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Convert into WIT [`CapabilityGrant`] values (statically guaranteed to contain
    /// zero [`CapabilityGrant::Directory`] entries).
    #[must_use]
    pub fn into_capability_grants(self) -> Vec<CapabilityGrant> {
        self.grants.into_iter().map(Into::into).collect()
    }
}

/// Fluent, typed capability builder for direct process launches (`programs::Command`,
/// `programs::exec`, `programs::spawn`).
///
/// Combines explicit Helios [`DirectoryGrant`]s (which are bind-mounted directly for
/// persistent host I/O on Linux binaries) with [`NonFsGrants`].
#[derive(Default)]
pub struct ProcessGrants {
    directories: Vec<DirectoryGrant>,
    non_fs: NonFsGrants,
}

impl From<NonFsGrants> for ProcessGrants {
    fn from(non_fs: NonFsGrants) -> Self {
        Self {
            directories: Vec::new(),
            non_fs,
        }
    }
}

impl ProcessGrants {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            directories: Vec::new(),
            non_fs: NonFsGrants::new(),
        }
    }

    /// Add an explicit [`DirectoryGrant`].
    #[must_use]
    pub fn directory_grant(mut self, grant: DirectoryGrant) -> Self {
        self.directories.push(grant);
        self
    }

    /// Grant directory `source_path` as `guest_name` with explicit `rights`.
    #[must_use]
    pub fn directory(
        self,
        source_path: impl Into<String>,
        guest_name: impl Into<String>,
        rights: Vec<FilesystemRight>,
    ) -> Self {
        self.directory_grant(DirectoryGrant {
            source_path: source_path.into(),
            guest_name: guest_name.into(),
            rights,
        })
    }

    /// Grant directory read-only (`Read`).
    #[must_use]
    pub fn directory_ro(
        self,
        source_path: impl Into<String>,
        guest_name: impl Into<String>,
    ) -> Self {
        self.directory(source_path, guest_name, vec![FilesystemRight::Read])
    }

    /// Grant directory read+execute (`Read | Execute`).
    #[must_use]
    pub fn directory_rx(
        self,
        source_path: impl Into<String>,
        guest_name: impl Into<String>,
    ) -> Self {
        self.directory(
            source_path,
            guest_name,
            vec![FilesystemRight::Read, FilesystemRight::Execute],
        )
    }

    /// Grant directory read+write (`Read | Write | MutateDirectory`).
    #[must_use]
    pub fn directory_rw(
        self,
        source_path: impl Into<String>,
        guest_name: impl Into<String>,
    ) -> Self {
        self.directory(
            source_path,
            guest_name,
            vec![
                FilesystemRight::Read,
                FilesystemRight::Write,
                FilesystemRight::MutateDirectory,
            ],
        )
    }

    /// Grant directory read+write+execute (`Read | Write | MutateDirectory | Execute`).
    #[must_use]
    pub fn directory_rwx(
        self,
        source_path: impl Into<String>,
        guest_name: impl Into<String>,
    ) -> Self {
        self.directory(
            source_path,
            guest_name,
            vec![
                FilesystemRight::Read,
                FilesystemRight::Write,
                FilesystemRight::MutateDirectory,
                FilesystemRight::Execute,
            ],
        )
    }

    /// Bind-mount a Helios host directory at the same path read-only.
    #[must_use]
    pub fn bind_dir_ro(self, path: impl Into<String>) -> Self {
        let p = path.into();
        self.directory_ro(p.clone(), p)
    }

    /// Bind-mount a Helios host directory at the same path read+execute.
    #[must_use]
    pub fn bind_dir_rx(self, path: impl Into<String>) -> Self {
        let p = path.into();
        self.directory_rx(p.clone(), p)
    }

    /// Bind-mount a Helios host directory at the same path read+write.
    #[must_use]
    pub fn bind_dir_rw(self, path: impl Into<String>) -> Self {
        let p = path.into();
        self.directory_rw(p.clone(), p)
    }

    /// Bind-mount a Helios host directory at the same path read+write+execute.
    #[must_use]
    pub fn bind_dir_rwx(self, path: impl Into<String>) -> Self {
        let p = path.into();
        self.directory_rwx(p.clone(), p)
    }

    /// Grant full root preopen (`/`).
    #[must_use]
    pub fn root_directory(self) -> Self {
        self.directory_rwx("/", "/")
    }

    /// Merge a [`NonFsGrants`] bundle into this [`ProcessGrants`].
    #[must_use]
    pub fn with_non_fs(mut self, non_fs: NonFsGrants) -> Self {
        self.non_fs.grants.extend(non_fs.grants);
        self
    }

    #[must_use]
    pub fn network(mut self, rights: Vec<NetworkRight>) -> Self {
        self.non_fs = self.non_fs.network(rights);
        self
    }

    #[must_use]
    pub fn full_network(mut self) -> Self {
        self.non_fs = self.non_fs.full_network();
        self
    }

    #[must_use]
    pub fn clock(mut self, rights: Vec<ClockRight>) -> Self {
        self.non_fs = self.non_fs.clock(rights);
        self
    }

    #[must_use]
    pub fn terminal(mut self, rights: Vec<TerminalRight>) -> Self {
        self.non_fs = self.non_fs.terminal(rights);
        self
    }

    #[must_use]
    pub fn all_terminal(mut self) -> Self {
        self.non_fs = self.non_fs.all_terminal();
        self
    }

    #[must_use]
    pub fn process(mut self, rights: Vec<ProcessRight>) -> Self {
        self.non_fs = self.non_fs.process(rights);
        self
    }

    #[must_use]
    pub fn all_process(mut self) -> Self {
        self.non_fs = self.non_fs.all_process();
        self
    }

    #[must_use]
    pub fn link(mut self, rights: Vec<LinkRight>) -> Self {
        self.non_fs = self.non_fs.link(rights);
        self
    }

    #[must_use]
    pub fn all_link(mut self) -> Self {
        self.non_fs = self.non_fs.all_link();
        self
    }

    #[must_use]
    pub fn mount(mut self, rights: Vec<MountRight>) -> Self {
        self.non_fs = self.non_fs.mount(rights);
        self
    }

    #[must_use]
    pub fn all_mount(mut self) -> Self {
        self.non_fs = self.non_fs.all_mount();
        self
    }

    #[must_use]
    pub fn device(mut self, classes: Vec<DeviceClass>) -> Self {
        self.non_fs = self.non_fs.device(classes);
        self
    }

    #[must_use]
    pub fn all_devices(mut self) -> Self {
        self.non_fs = self.non_fs.all_devices();
        self
    }

    #[must_use]
    pub fn diagnostics(mut self, grant: DiagnosticsGrant) -> Self {
        self.non_fs = self.non_fs.diagnostics(grant);
        self
    }

    #[must_use]
    pub fn instance_control(mut self, scope: AuthorityScope) -> Self {
        self.non_fs = self.non_fs.instance_control(scope);
        self
    }

    #[must_use]
    pub fn settings(mut self, rights: Vec<SettingsRight>) -> Self {
        self.non_fs = self.non_fs.settings(rights);
        self
    }

    #[must_use]
    pub fn machine(mut self, rights: Vec<MachineRight>) -> Self {
        self.non_fs = self.non_fs.machine(rights);
        self
    }

    #[must_use]
    pub fn virtualize(mut self) -> Self {
        self.non_fs = self.non_fs.virtualize();
        self
    }

    #[must_use]
    pub fn ipc(
        mut self,
        name: impl Into<String>,
        endpoint: crate::bindings::helios::system::ipc::Endpoint,
    ) -> Self {
        self.non_fs = self.non_fs.ipc(name, endpoint);
        self
    }

    /// Convert into the flat WIT `list<capability-grant>` accepted by [`ExecRequest`] and
    /// [`SpawnRequest`].
    #[must_use]
    pub fn into_capability_grants(self) -> Vec<CapabilityGrant> {
        let mut out = Vec::with_capacity(self.directories.len() + self.non_fs.len());
        out.extend(self.directories.into_iter().map(CapabilityGrant::Directory));
        out.extend(self.non_fs.into_capability_grants());
        out
    }
}

/// Fluent command builder for directly executing or spawning Wasm components or Linux ELF
/// binaries through the unified `helios:system/programs` interface.
///
/// When `path` names a Linux ELF binary (or `#!` script), the kernel automatically creates
/// a dedicated per-binary container over the caller's process-tree-inherited
/// [`set_default_image`] ephemeral overlay (or bare Linux syscalls when unset) while
/// bind-mounting granted Helios host directories directly for persistent host I/O.
pub struct Command {
    path: String,
    name: Option<String>,
    args: Vec<String>,
    env: Vec<(String, String)>,
    cwd: Option<String>,
    stdin: Vec<u8>,
    hint: Option<AotHint>,
    sockets: Vec<InheritedSocket>,
    grants: ProcessGrants,
}

impl Command {
    /// Start building a command targeting executable `path`.
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            name: None,
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            stdin: Vec::new(),
            hint: None,
            sockets: Vec::new(),
            grants: ProcessGrants::new(),
        }
    }

    /// Override `argv[0]` / instance name (defaults to `path`).
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Append one command-line argument.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append multiple command-line arguments.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set an environment variable (merged on top of any inherited default Linux image `env`).
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Extend environment variables.
    #[must_use]
    pub fn envs<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (k, v) in vars {
            self.env.push((k.into(), v.into()));
        }
        self
    }

    /// Set the working directory for the launched process.
    #[must_use]
    pub fn cwd(mut self, dir: impl Into<String>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    /// Supply buffered standard input bytes (used by [`Self::exec`]).
    #[must_use]
    pub fn stdin(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.stdin = bytes.into();
        self
    }

    /// Set an optional AOT compilation hint for Wasm programs (used by [`Self::exec`]).
    #[must_use]
    pub const fn aot_hint(mut self, hint: AotHint) -> Self {
        self.hint = Some(hint);
        self
    }

    /// Hand off a pre-bound listening socket to the spawned child (`fd = 3+` on Linux).
    #[must_use]
    pub fn socket(mut self, socket: InheritedSocket) -> Self {
        self.sockets.push(socket);
        self
    }

    /// Replace the command's [`ProcessGrants`].
    #[must_use]
    pub fn grants(mut self, grants: ProcessGrants) -> Self {
        self.grants = grants;
        self
    }

    /// Mutate the command's [`ProcessGrants`] inline.
    #[must_use]
    pub fn with_grants(mut self, configure: impl FnOnce(ProcessGrants) -> ProcessGrants) -> Self {
        self.grants = configure(self.grants);
        self
    }

    /// Convenience helper: grant a Helios host directory read-only at the same path.
    #[must_use]
    pub fn dir_ro(mut self, path: impl Into<String>) -> Self {
        self.grants = self.grants.bind_dir_ro(path);
        self
    }

    /// Convenience helper: grant a Helios host directory read+write at the same path.
    #[must_use]
    pub fn dir_rw(mut self, path: impl Into<String>) -> Self {
        self.grants = self.grants.bind_dir_rw(path);
        self
    }

    /// Convenience helper: grant a Helios host directory read+write+execute at the same path.
    #[must_use]
    pub fn dir_rwx(mut self, path: impl Into<String>) -> Self {
        self.grants = self.grants.bind_dir_rwx(path);
        self
    }

    /// Build the WIT [`ExecRequest`] without executing it.
    #[must_use]
    pub fn into_exec_request(self) -> ExecRequest {
        ExecRequest {
            name: self.name.unwrap_or_else(|| self.path.clone()),
            args: self.args,
            env: self.env,
            path: self.path,
            cwd: self.cwd,
            stdin: self.stdin,
            hint: self.hint,
            capability_grants: self.grants.into_capability_grants(),
        }
    }

    /// Build the WIT [`SpawnRequest`] without spawning it.
    #[must_use]
    pub fn into_spawn_request(self) -> SpawnRequest {
        SpawnRequest {
            name: self.name.unwrap_or_else(|| self.path.clone()),
            args: self.args,
            env: self.env,
            path: self.path,
            cwd: self.cwd,
            sockets: self.sockets,
            capability_grants: self.grants.into_capability_grants(),
        }
    }

    /// Execute the command to completion and return buffered stdout/stderr + exit code.
    pub async fn exec(self) -> Result<ExecResult, ExecError> {
        exec(self.into_exec_request()).await
    }

    /// Spawn the command and return a streaming [`Child`] handle.
    pub async fn spawn(self) -> Result<Child, SpawnError> {
        spawn(self.into_spawn_request()).await
    }
}

/// Construct a new [`Command`] for `path`.
#[must_use]
pub fn command(path: impl Into<String>) -> Command {
    Command::new(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_grants_and_command_build_exec_and_spawn_requests() {
        let non_fs = NonFsGrants::new()
            .network(vec![NetworkRight::Tcp, NetworkRight::Dns])
            .all_terminal();
        let grants = ProcessGrants::from(non_fs)
            .bind_dir_rw("/workspace")
            .directory_ro("/etc/ssl", "/etc/ssl");

        let exec_req = Command::new("/usr/bin/python3")
            .name("python3")
            .args(["-c", "print('hello')"])
            .env("PYTHONUNBUFFERED", "1")
            .cwd("/workspace")
            .stdin(b"input".to_vec())
            .grants(grants)
            .into_exec_request();

        assert_eq!(exec_req.name, "python3");
        assert_eq!(exec_req.path, "/usr/bin/python3");
        assert_eq!(exec_req.cwd.as_deref(), Some("/workspace"));
        assert_eq!(exec_req.stdin, b"input");
        assert_eq!(exec_req.capability_grants.len(), 4);
        assert!(matches!(
            &exec_req.capability_grants[0],
            CapabilityGrant::Directory(d) if d.source_path == "/workspace" && d.guest_name == "/workspace"
        ));

        let spawn_req = command("/bin/busybox")
            .arg("sh")
            .cwd("/tmp")
            .dir_rwx("/data")
            .into_spawn_request();
        assert_eq!(spawn_req.name, "/bin/busybox");
        assert_eq!(spawn_req.cwd.as_deref(), Some("/tmp"));
        assert_eq!(spawn_req.capability_grants.len(), 1);
    }
}
