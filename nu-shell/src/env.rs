//! Async-first Helios environment contract for `helios-nu`.
//!
//! Every capability that touches external programs, VFS mounts, system
//! telemetry, inspection, snapshots, profiling, timers, or HTTP passes through
//! [`HeliosEnv`]. Nothing in `helios-nu` assumes ambient host OS access.

use core::future::Future;
use core::time::Duration;
use std::collections::BTreeMap;

use chrono::{DateTime, FixedOffset};
use nu_protocol::ShellError;

use crate::error::EnvError;

/// Bounded stream of raw byte chunks transferred asynchronously across
/// pipeline stages and external processes.
pub type AsyncByteReceiver = async_channel::Receiver<Result<Vec<u8>, ShellError>>;

/// Bounded sender paired with [`AsyncByteReceiver`].
pub type AsyncByteSender = async_channel::Sender<Result<Vec<u8>, ShellError>>;

/// Default bounded capacity (in chunks or values) for async pipeline channels.
pub const STREAM_CHANNEL_CAPACITY: usize = 64;

/// A single explicit capability grant attached to an external launch or
/// `with-grants` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSpec {
    /// Capability kind (e.g. `"dir"`, `"fs"`, `"net"`, `"http"`, `"virtualize"`, `"inspect"`).
    pub kind: String,
    /// Target path, moniker, host pattern, or resource identifier.
    pub target: String,
    /// Optional mode or rights (e.g. `"ro"`, `"rw"`).
    pub mode: Option<String>,
}

/// Request parameters for spawning an external program via `run-external`.
#[derive(Debug)]
pub struct ExternalSpawnRequest {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub env: BTreeMap<String, String>,
    pub grants: Vec<GrantSpec>,
    pub scope: Option<String>,
    pub stdin: Option<AsyncByteReceiver>,
    pub capture_stdout: bool,
    pub capture_stderr: bool,
}

/// Live handle to a spawned external process whose streams run concurrently
/// with downstream pipeline stages.
#[derive(Debug)]
pub struct ExternalProcess {
    pub stdout: Option<AsyncByteReceiver>,
    pub stderr: Option<AsyncByteReceiver>,
    pub exit_code: async_channel::Receiver<Result<i32, EnvError>>,
}

/// Resolved executable location reported by `which`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableMatch {
    pub command: String,
    pub path: String,
}

/// Per-CPU telemetry row for `sys cpu`.
#[derive(Debug, Clone, PartialEq)]
pub struct SysCpuInfo {
    pub name: String,
    pub brand: String,
    pub vendor_id: String,
    pub freq_mhz: u64,
    pub cpu_usage: Option<f64>,
    pub load_average: String,
}

/// Memory telemetry record for `sys mem`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysMemInfo {
    pub total: u64,
    pub free: u64,
    pub used: u64,
    pub available: u64,
    pub swap_total: u64,
    pub swap_free: u64,
    pub swap_used: u64,
}

/// Network interface telemetry row for `sys net`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysNetInfo {
    pub name: String,
    pub mac: String,
    pub ip: Vec<String>,
    pub sent: u64,
    pub recv: u64,
}

/// Disk / mount telemetry row for `sys disks`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysDiskInfo {
    pub device: String,
    pub kind: String,
    pub mount: String,
    pub total: u64,
    pub free: u64,
    pub removable: bool,
}

/// Host identity and uptime record for `sys host`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysHostInfo {
    pub name: String,
    pub os_version: String,
    pub long_os_version: String,
    pub kernel_version: String,
    pub hostname: String,
    pub uptime: Duration,
    pub boot_time: Option<DateTime<FixedOffset>>,
}

/// Component / process telemetry row for `ps`.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessInfo {
    pub pid: u64,
    pub ppid: u64,
    pub moniker: String,
    pub name: String,
    pub status: String,
    pub cpu: f64,
    pub mem: u64,
    pub virtual_mem: u64,
    pub command: String,
}

/// Structured value returned by `helios:system/inspect`.
#[derive(Debug, Clone, PartialEq)]
pub enum InspectValue {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    List(Vec<InspectValue>),
    Map(BTreeMap<String, InspectValue>),
}

/// Entry returned by [`HeliosEnv::inspect`].
#[derive(Debug, Clone, PartialEq)]
pub struct InspectEntry {
    pub path: String,
    pub moniker: String,
    pub value: InspectValue,
}

/// Snapshot metadata returned by [`HeliosEnv::take_snapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub id: String,
    pub name: String,
    pub moniker: Option<String>,
}

/// Instruction profile sample summary returned by [`HeliosEnv::end_instruction_profile`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionProfileSummary {
    pub target: String,
    pub instructions: u64,
    pub cycles: u64,
    pub samples: u64,
    pub elapsed: Duration,
}

/// Filesystem node kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    File,
    Dir,
    Symlink,
}

impl FileType {
    /// Nushell-conventional string representation (`"file"`, `"dir"`, `"symlink"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Dir => "dir",
            Self::Symlink => "symlink",
        }
    }
}

/// Metadata for a VFS entry returned by [`HeliosEnv::stat`] and [`HeliosEnv::list_dir`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetadata {
    pub path: String,
    pub name: String,
    pub file_type: FileType,
    pub size: u64,
    pub modified: Option<DateTime<FixedOffset>>,
    pub readonly: bool,
    pub target: Option<String>,
}

/// Event emitted by [`HeliosEnv::watch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchEvent {
    pub operation: String,
    pub path: String,
    pub new_path: Option<String>,
}

/// Redirect handling mode for `http` commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpRedirectMode {
    #[default]
    Follow,
    Manual,
    Error,
}

/// Outgoing HTTP request passed to [`HeliosEnv::http_send`].
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout: Option<Duration>,
    pub redirect_mode: HttpRedirectMode,
}

/// Incoming HTTP response returned by [`HeliosEnv::http_send`].
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Default OCI image reference automatically pulled on first Linux use when no
/// per-user preference has been configured.
pub const DEFAULT_LINUX_IMAGE_REF: &str = "alpine";

/// Current default Linux image configuration for the authenticated shell principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxImageInfo {
    pub principal: String,
    pub image_ref: Option<String>,
    pub default_ref: String,
    pub rootfs_path: Option<String>,
    pub active: bool,
    pub persisted: bool,
    pub env: Vec<(String, String)>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

/// Outcome of `linux image clear`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxImageClearResult {
    pub principal: String,
    pub cleared: bool,
    pub previous_ref: Option<String>,
}

/// Configured or live component status row (`component ls`, `component status`, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentInfo {
    pub moniker: String,
    pub program: String,
    pub state: String,
    pub instance_id: Option<u64>,
    pub restarts: u64,
}

/// Source for dynamically mounting a component subtree (`component add`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentSubtreeSource {
    GuestDir { subtree_name: String, path: String },
    Manifests(Vec<(String, String)>),
}

/// Request parameters for `component add`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentAddRequest {
    pub parent_moniker: String,
    pub source: ComponentSubtreeSource,
}

/// Summary row for a pulled OCI image (`oci pull`, `oci ls`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciImageSummary {
    pub reference: String,
    pub digest: String,
    pub arch: String,
    pub layers: usize,
    pub rootfs_path: String,
    pub btrfs_backed: bool,
}

/// Detailed metadata returned by `oci inspect`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciImageInspect {
    pub reference: String,
    pub digest: String,
    pub arch: String,
    pub os: String,
    pub layer_chain_ids: Vec<String>,
    pub rootfs_path: String,
    pub btrfs_backed: bool,
    pub user: Option<String>,
    pub working_dir: Option<String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub env: Vec<(String, String)>,
    pub labels: BTreeMap<String, String>,
}

/// Sharing mode for an additional container bind mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContainerMountSharingSpec {
    Private,
    #[default]
    Shared,
    EphemeralOverlay,
}

impl ContainerMountSharingSpec {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Shared => "shared",
            Self::EphemeralOverlay => "ephemeral-overlay",
        }
    }
}

/// One filesystem mount attached to a Linux container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerMountSpec {
    pub source_path: String,
    pub target_path: String,
    pub mode: String,
    pub sharing: ContainerMountSharingSpec,
}

/// Request parameters for `container create`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerCreateRequest {
    pub image: Option<String>,
    pub rootfs: Option<String>,
    pub mounts: Vec<ContainerMountSpec>,
    pub grants: Vec<GrantSpec>,
    pub hostname: Option<String>,
    pub domainname: Option<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<String>,
}

/// Metadata for a live Linux container handle (`container create`, `container ls`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInfo {
    pub handle: String,
    pub image: Option<String>,
    pub rootfs_path: String,
    pub hostname: String,
    pub cwd: Option<String>,
    pub uid: u32,
    pub gid: u32,
}

/// Buffered command execution request inside a live container (`container exec`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerExecRequest {
    pub program: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<String>,
    pub stdin: Vec<u8>,
}

/// Buffered command output returned by `container exec`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerExecOutput {
    pub instance_id: u64,
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Streaming process launch request inside a live container (`container spawn`, `with-container`).
#[derive(Debug)]
pub struct ContainerSpawnRequest {
    pub program: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<String>,
    pub stdin: Option<AsyncByteReceiver>,
    pub capture_stdout: bool,
    pub capture_stderr: bool,
}

/// Filesystem source for `mount` (`helios:system/mounts.mount-source`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountSourceSpec {
    Memory,
    BootImage,
    HostShare,
    Disk(String),
    Btrfs(String),
}

impl MountSourceSpec {
    #[must_use]
    pub fn display_label(&self) -> String {
        match self {
            Self::Memory => String::from("memory"),
            Self::BootImage => String::from("boot-image"),
            Self::HostShare => String::from("host-share"),
            Self::Disk(serial) => format!("disk:{serial}"),
            Self::Btrfs(serial) => format!("btrfs:{serial}"),
        }
    }

    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::BootImage => "boot-image",
            Self::HostShare => "host-share",
            Self::Disk(_) => "erofs",
            Self::Btrfs(_) => "btrfs",
        }
    }
}

/// Mount sharing policy (`helios:system/mounts.mount-sharing`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MountSharingSpec {
    Private,
    #[default]
    Shared,
}

impl MountSharingSpec {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Shared => "shared",
        }
    }
}

/// Request parameters for `mount`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountRequestSpec {
    pub source: MountSourceSpec,
    pub path: String,
    pub read_only: bool,
    pub sharing: MountSharingSpec,
    pub compress: Option<String>,
    pub commit: Option<u32>,
    pub max_inline: Option<u64>,
}

/// Active mount entry row returned by `mount` (no arguments).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntryInfo {
    pub path: String,
    pub source: String,
    pub kind: String,
    pub read_only: bool,
    pub sharing: String,
}

/// Subvolume metadata row returned by `btrfs subvolume *`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsSubvolumeInfo {
    pub id: u64,
    pub parent_id: Option<u64>,
    pub path: String,
    pub uuid: String,
    pub parent_uuid: Option<String>,
    pub received_uuid: Option<String>,
    pub generation: u64,
    pub ctransid: u64,
    pub otransid: u64,
    pub stransid: u64,
    pub rtransid: u64,
    pub read_only: bool,
}

/// Pass-through host directory share for a micro-VM (`vm run --share-dir`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmShareSpec {
    pub tag: String,
    pub host_path: String,
    pub read_only: bool,
}

/// Launch parameters for `vm run`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmRunRequest {
    pub name: Option<String>,
    pub oci_ref: Option<String>,
    pub kernel: Option<String>,
    pub initramfs: Option<String>,
    pub disk: Option<String>,
    pub rootfs_dir: Option<String>,
    pub shares: Vec<VmShareSpec>,
    pub cpus: u32,
    pub memory_mib: u64,
    pub cmdline: Option<String>,
    pub detach: bool,
}

/// Running or completed micro-VM record (`vm run`, `vm ls`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmInfo {
    pub id: String,
    pub name: String,
    pub state: String,
    pub cpus: u32,
    pub memory_mib: u64,
    pub oci_ref: Option<String>,
    pub kernel: Option<String>,
    pub exit_reason: Option<String>,
}

/// Async-first capability environment backing every Helios-native command in
/// `helios-nu`.
///
/// Trait methods spell out explicit `+ Send + '_` futures per `AGENTS.md §3.2`.
pub trait HeliosEnv: Send + Sync {
    /// Return the current working directory (normalized absolute VFS path).
    fn cwd(&self) -> impl Future<Output = Result<String, EnvError>> + Send;

    /// Change the current working directory, validating it exists and is a directory.
    fn set_cwd(&self, path: &str) -> impl Future<Output = Result<String, EnvError>> + Send;

    /// Spawn an external program with streaming stdio and explicit capability grants.
    fn spawn_external(
        &self,
        request: ExternalSpawnRequest,
    ) -> impl Future<Output = Result<ExternalProcess, EnvError>> + Send;

    /// Resolve an executable name (or path) in granted PATH directories.
    fn resolve_executable(
        &self,
        name: &str,
        path_env: &[String],
    ) -> impl Future<Output = Result<Option<ExecutableMatch>, EnvError>> + Send;

    /// List available executable names for completion.
    fn list_executables(&self) -> impl Future<Output = Result<Vec<String>, EnvError>> + Send {
        async { Ok(Vec::new()) }
    }

    /// CPU telemetry (`sys cpu`).
    fn sys_cpu(&self, long: bool)
    -> impl Future<Output = Result<Vec<SysCpuInfo>, EnvError>> + Send;

    /// Memory telemetry (`sys mem`).
    fn sys_mem(&self) -> impl Future<Output = Result<SysMemInfo, EnvError>> + Send;

    /// Network interface telemetry (`sys net`).
    fn sys_net(&self) -> impl Future<Output = Result<Vec<SysNetInfo>, EnvError>> + Send;

    /// Disk / mount telemetry (`sys disks`).
    fn sys_disks(&self) -> impl Future<Output = Result<Vec<SysDiskInfo>, EnvError>> + Send;

    /// Host telemetry (`sys host`).
    fn sys_host(&self) -> impl Future<Output = Result<SysHostInfo, EnvError>> + Send;

    /// Query `helios:system/inspect` at an optional key/moniker prefix.
    fn inspect(
        &self,
        path: Option<&str>,
    ) -> impl Future<Output = Result<Vec<InspectEntry>, EnvError>> + Send;

    /// List running components / processes (`ps`).
    fn list_processes(&self) -> impl Future<Output = Result<Vec<ProcessInfo>, EnvError>> + Send;

    /// Deliver a signal / termination request to a component or process (`kill`).
    fn kill_process(
        &self,
        pid: u64,
        signal: Option<&str>,
        force: bool,
    ) -> impl Future<Output = Result<(), EnvError>> + Send;

    /// Current principal / identity (`whoami`).
    fn whoami(&self) -> impl Future<Output = Result<String, EnvError>> + Send;

    /// Asynchronous monotonic sleep (`sleep`).
    fn sleep(&self, duration: Duration) -> impl Future<Output = Result<(), EnvError>> + Send;

    /// Clear the active terminal surface (`clear`).
    fn clear(&self) -> impl Future<Output = Result<(), EnvError>> + Send;

    /// Write raw bytes to the shell's standard output stream (`print`).
    fn write_stdout(&self, _bytes: &[u8]) -> impl Future<Output = Result<(), EnvError>> + Send {
        async { Ok(()) }
    }

    /// Write raw bytes to the shell's standard error stream (`print -e`).
    fn write_stderr(&self, _bytes: &[u8]) -> impl Future<Output = Result<(), EnvError>> + Send {
        async { Ok(()) }
    }

    /// Validate / enter a named capability subtree scope (`with-scope`).
    fn enter_scope(&self, scope: &str) -> impl Future<Output = Result<String, EnvError>> + Send;

    /// Exit a previously entered capability subtree scope.
    fn leave_scope(&self, scope: &str) -> impl Future<Output = Result<(), EnvError>> + Send;

    /// Create a snapshot before running a `with-snapshot` block.
    fn take_snapshot(
        &self,
        name: &str,
        moniker: Option<&str>,
    ) -> impl Future<Output = Result<SnapshotInfo, EnvError>> + Send;

    /// Release a previously acquired snapshot hold when `with-snapshot` completes.
    fn release_snapshot(&self, _id: &str) -> impl Future<Output = Result<(), EnvError>> + Send {
        async { Ok(()) }
    }

    /// Begin instruction profiling for `target` (`with-instruction-profile`).
    fn begin_instruction_profile(
        &self,
        target: Option<&str>,
    ) -> impl Future<Output = Result<String, EnvError>> + Send;

    /// Finish instruction profiling for the handle returned by [`Self::begin_instruction_profile`].
    fn end_instruction_profile(
        &self,
        handle: &str,
    ) -> impl Future<Output = Result<InstructionProfileSummary, EnvError>> + Send;

    /// List directory entries under a granted path (`ls`, `glob`, completion).
    fn list_dir(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<Vec<FileMetadata>, EnvError>> + Send;

    /// Fetch metadata for a single granted path.
    fn stat(&self, path: &str) -> impl Future<Output = Result<FileMetadata, EnvError>> + Send;

    /// Read a file's contents (`open`).
    fn read_file(&self, path: &str) -> impl Future<Output = Result<Vec<u8>, EnvError>> + Send;

    /// Write or append bytes to a file (`save`, file redirections).
    fn write_file(
        &self,
        path: &str,
        data: &[u8],
        append: bool,
        force: bool,
    ) -> impl Future<Output = Result<(), EnvError>> + Send;

    /// Create a directory and any missing parents (`mkdir`).
    fn mkdir(&self, path: &str) -> impl Future<Output = Result<(), EnvError>> + Send;

    /// Remove a file or directory (`rm`).
    fn remove(
        &self,
        path: &str,
        recursive: bool,
        force: bool,
    ) -> impl Future<Output = Result<(), EnvError>> + Send;

    /// Copy a file or directory (`cp`).
    fn copy(
        &self,
        from: &str,
        to: &str,
        recursive: bool,
        force: bool,
    ) -> impl Future<Output = Result<(), EnvError>> + Send;

    /// Rename / move a file or directory (`mv`).
    fn rename(
        &self,
        from: &str,
        to: &str,
        force: bool,
    ) -> impl Future<Output = Result<(), EnvError>> + Send;

    /// Create an empty file or update its modification time (`touch`).
    fn touch(
        &self,
        path: &str,
        no_create: bool,
    ) -> impl Future<Output = Result<(), EnvError>> + Send;

    /// Subscribe to filesystem change events under `path` (`watch`).
    fn watch(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<async_channel::Receiver<WatchEvent>, EnvError>> + Send;

    /// Execute an HTTP request. Defaults to [`crate::commands::http::zenwave_send`],
    /// which uses `zenwave::WasiBackend` on Component Model WASI targets and
    /// `zenwave`'s native backend on host builds.
    fn http_send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, EnvError>> + Send {
        crate::commands::http::zenwave_send(request)
    }

    /// Return the authenticated user's persisted / active default Linux image (`linux image get`).
    fn linux_image_get(&self) -> impl Future<Output = Result<LinuxImageInfo, EnvError>> + Send;

    /// Pull (if needed), persist for the current login identity, and activate a default Linux image (`linux image set`).
    fn linux_image_set(
        &self,
        image_ref: &str,
        arch: Option<&str>,
    ) -> impl Future<Output = Result<LinuxImageInfo, EnvError>> + Send;

    /// Clear the current login identity's persisted and active default Linux image (`linux image clear`).
    fn linux_image_clear(
        &self,
    ) -> impl Future<Output = Result<LinuxImageClearResult, EnvError>> + Send;

    /// List managed components under the caller's authorized scope (`component ls`).
    fn component_list(&self) -> impl Future<Output = Result<Vec<ComponentInfo>, EnvError>> + Send;

    /// Fetch the status of a single managed component (`component status`).
    fn component_status(
        &self,
        moniker: &str,
    ) -> impl Future<Output = Result<ComponentInfo, EnvError>> + Send;

    /// Start a managed component by moniker (`component start`).
    fn component_start(
        &self,
        moniker: &str,
    ) -> impl Future<Output = Result<ComponentInfo, EnvError>> + Send;

    /// Stop a running component by moniker (`component stop`).
    fn component_stop(&self, moniker: &str) -> impl Future<Output = Result<(), EnvError>> + Send;

    /// Restart a managed component by moniker (`component restart`).
    fn component_restart(
        &self,
        moniker: &str,
    ) -> impl Future<Output = Result<ComponentInfo, EnvError>> + Send;

    /// Dynamically mount a component subtree under a parent moniker (`component add`).
    fn component_add(
        &self,
        request: ComponentAddRequest,
    ) -> impl Future<Output = Result<String, EnvError>> + Send;

    /// Dynamically unmount a component subtree (`component rm`).
    fn component_remove(&self, moniker: &str) -> impl Future<Output = Result<(), EnvError>> + Send;

    /// Pull and materialize an OCI image into the image store (`oci pull`).
    fn oci_pull(
        &self,
        reference: &str,
        arch: Option<&str>,
    ) -> impl Future<Output = Result<OciImageSummary, EnvError>> + Send;

    /// List OCI images present in the image store (`oci ls`).
    fn oci_list(&self) -> impl Future<Output = Result<Vec<OciImageSummary>, EnvError>> + Send;

    /// Inspect a pulled OCI image (`oci inspect`).
    fn oci_inspect(
        &self,
        reference: &str,
    ) -> impl Future<Output = Result<OciImageInspect, EnvError>> + Send;

    /// Remove a pulled OCI image from the image store (`oci rm`).
    fn oci_remove(&self, reference: &str) -> impl Future<Output = Result<(), EnvError>> + Send;

    /// Create a live Linux container and return its session handle (`container create`).
    fn container_create(
        &self,
        request: ContainerCreateRequest,
    ) -> impl Future<Output = Result<ContainerInfo, EnvError>> + Send;

    /// List live Linux containers owned by this shell session (`container ls`).
    fn container_list(&self) -> impl Future<Output = Result<Vec<ContainerInfo>, EnvError>> + Send;

    /// Execute a command to completion inside a live Linux container (`container exec`).
    fn container_exec(
        &self,
        handle: &str,
        request: ContainerExecRequest,
    ) -> impl Future<Output = Result<ContainerExecOutput, EnvError>> + Send;

    /// Spawn a streaming command inside a live Linux container (`container spawn`, `with-container`).
    fn container_spawn(
        &self,
        handle: &str,
        request: ContainerSpawnRequest,
    ) -> impl Future<Output = Result<ExternalProcess, EnvError>> + Send;

    /// Destroy a live Linux container handle and release its overlay (`container rm`).
    fn container_remove(&self, handle: &str) -> impl Future<Output = Result<(), EnvError>> + Send;

    /// List active filesystem mounts (`mount`).
    fn list_mounts(&self) -> impl Future<Output = Result<Vec<MountEntryInfo>, EnvError>> + Send;

    /// Attach a filesystem mount (`mount <source> <path>`).
    fn mount(&self, request: MountRequestSpec)
    -> impl Future<Output = Result<(), EnvError>> + Send;

    /// Detach a mounted filesystem (`umount <path>`).
    fn umount(&self, path: &str) -> impl Future<Output = Result<(), EnvError>> + Send;

    /// Create a btrfs subvolume (`btrfs subvolume create`).
    fn btrfs_subvolume_create(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<BtrfsSubvolumeInfo, EnvError>> + Send;

    /// Delete a btrfs subvolume (`btrfs subvolume delete`).
    fn btrfs_subvolume_delete(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<(), EnvError>> + Send;

    /// Snapshot a btrfs subvolume (`btrfs subvolume snapshot`).
    fn btrfs_subvolume_snapshot(
        &self,
        source: &str,
        destination: &str,
        read_only: bool,
    ) -> impl Future<Output = Result<BtrfsSubvolumeInfo, EnvError>> + Send;

    /// List btrfs subvolumes on a mounted volume (`btrfs subvolume list`).
    fn btrfs_subvolume_list(
        &self,
        mount_point: &str,
    ) -> impl Future<Output = Result<Vec<BtrfsSubvolumeInfo>, EnvError>> + Send;

    /// Inspect a single btrfs subvolume (`btrfs subvolume show`).
    fn btrfs_subvolume_info(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<BtrfsSubvolumeInfo, EnvError>> + Send;

    /// Set or clear read-only state on a btrfs subvolume (`btrfs subvolume set-ro`).
    fn btrfs_subvolume_set_ro(
        &self,
        path: &str,
        read_only: bool,
    ) -> impl Future<Output = Result<(), EnvError>> + Send;

    /// Produce a btrfs v1 send stream for a read-only subvolume (`btrfs subvolume send`).
    fn btrfs_subvolume_send(
        &self,
        subvolume: &str,
        parent: Option<&str>,
        clone_sources: &[String],
    ) -> impl Future<Output = Result<Vec<u8>, EnvError>> + Send;

    /// Receive a btrfs v1 send stream into `destination` (`btrfs subvolume receive`).
    fn btrfs_subvolume_receive(
        &self,
        destination: &str,
        payload: Vec<u8>,
    ) -> impl Future<Output = Result<BtrfsSubvolumeInfo, EnvError>> + Send;

    /// Launch a hardware-virtualized micro-VM (`vm run`).
    fn vm_run(
        &self,
        request: VmRunRequest,
    ) -> impl Future<Output = Result<VmInfo, EnvError>> + Send;

    /// List running or tracked micro-VMs (`vm ls`).
    fn vm_list(&self) -> impl Future<Output = Result<Vec<VmInfo>, EnvError>> + Send;

    /// List known component monikers for AST completion.
    fn complete_monikers(&self) -> impl Future<Output = Result<Vec<String>, EnvError>> + Send {
        async {
            let mut out = Vec::new();
            if let Ok(components) = self.component_list().await {
                for comp in components {
                    out.push(comp.moniker);
                }
            }
            if let Ok(procs) = self.list_processes().await {
                for p in procs {
                    if !out.contains(&p.moniker) {
                        out.push(p.moniker);
                    }
                }
            }
            Ok(out)
        }
    }

    /// List known inspect keys for AST completion.
    fn complete_inspect_keys(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<String>, EnvError>> + Send {
        let prefix = prefix.to_owned();
        async move {
            let entries = self.inspect(None).await?;
            Ok(entries
                .into_iter()
                .map(|e| e.path)
                .filter(|p| p.starts_with(&prefix))
                .collect())
        }
    }

    /// List diagnostic / profiling targets for AST completion.
    fn complete_diagnostic_targets(
        &self,
    ) -> impl Future<Output = Result<Vec<String>, EnvError>> + Send {
        async { Ok(Vec::new()) }
    }

    /// List known OCI image references for AST completion.
    fn complete_oci_refs(&self) -> impl Future<Output = Result<Vec<String>, EnvError>> + Send {
        async {
            let images = self.oci_list().await?;
            Ok(images.into_iter().map(|img| img.reference).collect())
        }
    }

    /// List active container handles for AST completion.
    fn complete_containers(&self) -> impl Future<Output = Result<Vec<String>, EnvError>> + Send {
        async {
            let containers = self.container_list().await?;
            Ok(containers.into_iter().map(|c| c.handle).collect())
        }
    }

    /// Additional environment-specific commands registered alongside [`crate::AsyncBuiltin`].
    fn custom_command_specs(&self) -> Vec<crate::command::CustomCommandSpec> {
        Vec::new()
    }

    /// Dispatch an environment-specific custom command registered by [`Self::custom_command_specs`].
    fn run_custom_command<'a>(
        &'a self,
        _name: &'a str,
        _ctx: &'a mut crate::command::AsyncCommandContext<'_, Self>,
        _input: crate::pipeline::AsyncPipelineData,
    ) -> impl Future<Output = Result<crate::pipeline::AsyncPipelineData, ShellError>> + Send + 'a
    where
        Self: Sized,
    {
        async {
            Err(crate::error::generic_error(
                "unknown custom command",
                "environment does not implement this custom command",
                nu_protocol::Span::unknown(),
            ))
        }
    }
}

/// Normalize a VFS path relative to `cwd`, resolving `.` and `..` without
/// escaping root `/`.
#[must_use]
pub fn normalize_vfs_path(cwd: &str, raw: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    let combined = if raw.starts_with('/') {
        raw.to_owned()
    } else if cwd == "/" {
        format!("/{raw}")
    } else {
        format!("{cwd}/{raw}")
    };

    for segment in combined.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }

    if parts.is_empty() {
        String::from("/")
    } else {
        format!("/{}", parts.join("/"))
    }
}
