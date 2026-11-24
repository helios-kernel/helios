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

    /// List known component monikers for AST completion.
    fn complete_monikers(&self) -> impl Future<Output = Result<Vec<String>, EnvError>> + Send {
        async {
            let procs = self.list_processes().await?;
            Ok(procs.into_iter().map(|p| p.moniker).collect())
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
        async { Ok(Vec::new()) }
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
