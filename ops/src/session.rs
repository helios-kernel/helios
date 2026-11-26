//! Async-first [`Session`] handle for a single Helios node over `helios-wit-rpc`.

use std::future::Future;
use std::path::{Component, Path};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use helios_inspector_protocol::auth::ClientIdentity;
use helios_wit_rpc::inspector::helios::system::{
    component_control::ComponentStatus,
    inspect::{self as rpc_inspect, Query, SnapshotResult},
    instances::{self as rpc_instances, Instance},
    ipc::Endpoint as WireIpcEndpoint,
    processors::{self as rpc_processors, ProcessorSets},
    profiling::{
        self as rpc_profiling, Filter as ProfileFilter, FoldedSample, InstructionProfile,
        MetricFilter, MetricSample,
    },
    programs::{
        self as rpc_programs, AuthorityScope, CapabilityGrant, ChildTermination, ClockGrant,
        ClockRight, DefaultLinuxImage, DeviceClass, DeviceGrant, DiagnosticsGrant, DirectoryGrant,
        ExecOutput, ExecRequest, ExecResult, FilesystemRight, LinkGrant, LinkRight, MachineGrant,
        MachineRight, MountGrant, MountRight, NetworkGrant, NetworkRight, ProcessGrant,
        ProcessRight, SettingsGrant, SettingsRight, SpawnRequest as WireSpawnRequest,
        TerminalGrant, TerminalRight,
    },
    snapshot::{self as rpc_snapshot, SnapshotHold as RemoteSnapshotHold},
    tracing as rpc_tracing,
};
use helios_wit_rpc::inspector_fs::{self, EntryKind, MountBtrfsRequest};
use helios_wit_rpc::inspector_snapshot::KernelSnapshot;
use helios_wit_rpc::{RpcError, StreamReader, StreamWriter, stream as rpc_stream};

use crate::components::ComponentsClient;
use crate::error::OpsError;
use crate::oci::OciClient;
use crate::storage::{BtrfsClient, MountsClient};
use crate::symbolize::{
    SymbolizedInstructionProfile, render_folded_instruction_profile, symbolize_instruction_profile,
};
use crate::target::{
    Attenuation, GrantRight, IdentityProfile, Target, normalize_scope, scope_contains,
};
use crate::transport::{ProtocolClient, RpcConnection, SecurityMode};
use crate::vm::VmClient;

/// Default per-RPC timeout when none is configured on [`SessionOptions`].
pub const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(180);

/// Chunk size (64 KiB) used when reading the guest kernel's LLVM raw profile.
const RAW_PROFILE_CHUNK_BYTES: u32 = 64 * 1024;

/// Configuration applied when constructing or connecting a [`Session`].
#[derive(Debug, Clone)]
pub struct SessionOptions {
    pub timeout: Duration,
    pub attenuation: Attenuation,
    pub identity: Option<IdentityProfile>,
    pub security: SecurityMode,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_RPC_TIMEOUT,
            attenuation: Attenuation::default(),
            identity: None,
            security: SecurityMode::Plain,
        }
    }
}

impl SessionOptions {
    /// Resolve identity profile and [`SecurityMode`] from an explicit identity
    /// name/path, an optional `"default"` identity profile, or
    /// `HELIOS_INSPECTOR_CLIENT_KEY` when `allow_ambient_auth` is `true`.
    pub fn resolve_security(
        identity_arg: Option<&str>,
        allow_ambient_auth: bool,
    ) -> Result<(Option<IdentityProfile>, SecurityMode), OpsError> {
        let identity = match identity_arg {
            Some(name_or_path) => Some(IdentityProfile::load(name_or_path)?),
            None if allow_ambient_auth => IdentityProfile::load("default").ok(),
            None => None,
        };
        let security =
            if let Some(profile) = identity.as_ref().filter(|p| p.secret_key_hex.is_some()) {
                profile.to_security_mode()?
            } else if (identity_arg.is_some() || allow_ambient_auth)
                && let Ok(key_path) = std::env::var("HELIOS_INSPECTOR_CLIENT_KEY")
                && !key_path.trim().is_empty()
            {
                let client_identity = ClientIdentity::from_seed_file(Path::new(key_path.trim()))
                    .map_err(|err| {
                        OpsError::Auth(crate::error::AuthError::InvalidIdentity {
                            name: key_path,
                            detail: err.to_string(),
                        })
                    })?;
                SecurityMode::Authenticated {
                    identity: Box::new(client_identity),
                    expected_machine_public_key: None,
                }
            } else {
                SecurityMode::Plain
            };
        Ok((identity, security))
    }
}

/// Request parameters for [`Session::spawn`].
#[derive(Debug)]
pub struct SpawnRequest {
    pub path: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<String>,
    pub stdin: Vec<u8>,
    pub capability_grants: Vec<CapabilityGrant<WireIpcEndpoint>>,
}

impl SpawnRequest {
    #[must_use]
    pub fn new(path: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            path: path.into(),
            args,
            env: Vec::new(),
            cwd: None,
            stdin: Vec::new(),
            capability_grants: Vec::new(),
        }
    }
}

/// Parse a CLI `--grant` string (e.g. `dir:/tmp:rw`, `net:tcp,dns`, `inspect:own`,
/// `diagnostics:control`, `terminal:all`, `process:spawn,exec`) into a typed [`CapabilityGrant`].
pub fn parse_capability_grant(spec: &str) -> Result<CapabilityGrant<WireIpcEndpoint>, OpsError> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err(OpsError::InvalidGrant {
            spec: spec.to_owned(),
            reason: "grant specification must not be empty".to_owned(),
        });
    }
    let parts: Vec<&str> = trimmed.splitn(3, ':').collect();
    match parts.as_slice() {
        [kind] => parse_grant_spec(kind, "", None),
        [kind, target] => parse_grant_spec(kind, target, None),
        [kind, target, mode] => parse_grant_spec(kind, target, Some(mode)),
        _ => unreachable!("splitn(3) produces 1..=3 parts"),
    }
}

/// Translate structured `(kind, target, mode)` grant fields (used by both `--grant`
/// and Nushell `with-grants`) into a wire [`CapabilityGrant`], failing fast on
/// unknown kinds or modes.
pub fn parse_grant_spec(
    kind: &str,
    target: &str,
    mode: Option<&str>,
) -> Result<CapabilityGrant<WireIpcEndpoint>, OpsError> {
    let spec_display = match mode {
        Some(m) if !m.is_empty() => format!("{kind}:{target}:{m}"),
        _ if !target.is_empty() => format!("{kind}:{target}"),
        _ => kind.to_owned(),
    };
    let invalid = |reason: &str| OpsError::InvalidGrant {
        spec: spec_display.clone(),
        reason: reason.to_owned(),
    };

    match kind.trim().to_ascii_lowercase().as_str() {
        "dir" | "fs" | "directory" => {
            if target.is_empty() {
                return Err(invalid("directory grant requires a path"));
            }
            let norm = normalize_absolute_path(target)?;
            let rights = match mode.unwrap_or("ro").trim().to_ascii_lowercase().as_str() {
                "ro" | "r" => vec![FilesystemRight::Read],
                "rx" => vec![FilesystemRight::Read, FilesystemRight::Execute],
                "rw" => vec![
                    FilesystemRight::Read,
                    FilesystemRight::Write,
                    FilesystemRight::MutateDirectory,
                ],
                "rwx" => vec![
                    FilesystemRight::Read,
                    FilesystemRight::Write,
                    FilesystemRight::MutateDirectory,
                    FilesystemRight::Execute,
                ],
                other => {
                    return Err(OpsError::InvalidGrant {
                        spec: spec_display,
                        reason: format!("unknown directory mode `{other}`; expected ro|rx|rw|rwx"),
                    });
                }
            };
            Ok(CapabilityGrant::Directory(DirectoryGrant {
                source_path: norm.clone(),
                guest_name: norm,
                rights,
            }))
        }
        "net" | "network" => {
            let tokens = if target.is_empty() || target.eq_ignore_ascii_case("all") {
                vec!["tcp", "udp", "dns", "privileged-bind", "multicast", "admin"]
            } else {
                target.split(',').collect()
            };
            let mut rights = Vec::with_capacity(tokens.len());
            for tok in tokens {
                let r = match tok.trim().to_ascii_lowercase().as_str() {
                    "tcp" => NetworkRight::Tcp,
                    "udp" => NetworkRight::Udp,
                    "dns" => NetworkRight::Dns,
                    "privileged-bind" => NetworkRight::PrivilegedBind,
                    "multicast" => NetworkRight::Multicast,
                    "admin" => NetworkRight::Admin,
                    other => {
                        return Err(OpsError::InvalidGrant {
                            spec: spec_display,
                            reason: format!("unknown network right `{other}`"),
                        });
                    }
                };
                rights.push(r);
            }
            Ok(CapabilityGrant::Network(NetworkGrant { rights }))
        }
        "clock" => {
            if !target.is_empty()
                && !target.eq_ignore_ascii_case("set-wall-clock")
                && !target.eq_ignore_ascii_case("all")
            {
                return Err(invalid("expected `clock:set-wall-clock` or `clock:all`"));
            }
            Ok(CapabilityGrant::Clock(ClockGrant {
                rights: vec![ClockRight::SetWallClock],
            }))
        }
        "terminal" | "tty" => {
            let tokens = if target.is_empty() || target.eq_ignore_ascii_case("all") {
                vec!["input", "output", "control"]
            } else {
                target.split(',').collect()
            };
            let mut rights = Vec::with_capacity(tokens.len());
            for tok in tokens {
                let r = match tok.trim().to_ascii_lowercase().as_str() {
                    "input" => TerminalRight::Input,
                    "output" => TerminalRight::Output,
                    "control" => TerminalRight::Control,
                    other => {
                        return Err(OpsError::InvalidGrant {
                            spec: spec_display,
                            reason: format!("unknown terminal right `{other}`"),
                        });
                    }
                };
                rights.push(r);
            }
            Ok(CapabilityGrant::Terminal(TerminalGrant { rights }))
        }
        "process" | "proc" => {
            let tokens = if target.is_empty() || target.eq_ignore_ascii_case("all") {
                vec!["spawn", "exec", "fork", "join", "signal"]
            } else {
                target.split(',').collect()
            };
            let mut rights = Vec::with_capacity(tokens.len());
            for tok in tokens {
                let r = match tok.trim().to_ascii_lowercase().as_str() {
                    "spawn" => ProcessRight::Spawn,
                    "exec" => ProcessRight::Exec,
                    "fork" => ProcessRight::Fork,
                    "join" => ProcessRight::Join,
                    "signal" => ProcessRight::Signal,
                    other => {
                        return Err(OpsError::InvalidGrant {
                            spec: spec_display,
                            reason: format!("unknown process right `{other}`"),
                        });
                    }
                };
                rights.push(r);
            }
            Ok(CapabilityGrant::Process(ProcessGrant { rights }))
        }
        "link" => {
            let tokens = if target.is_empty() || target.eq_ignore_ascii_case("all") {
                vec![
                    "source",
                    "target-directory",
                    "symlink-create",
                    "symlink-read",
                ]
            } else {
                target.split(',').collect()
            };
            let mut rights = Vec::with_capacity(tokens.len());
            for tok in tokens {
                let r = match tok.trim().to_ascii_lowercase().as_str() {
                    "source" => LinkRight::Source,
                    "target-directory" => LinkRight::TargetDirectory,
                    "symlink-create" => LinkRight::SymlinkCreate,
                    "symlink-read" => LinkRight::SymlinkRead,
                    other => {
                        return Err(OpsError::InvalidGrant {
                            spec: spec_display,
                            reason: format!("unknown link right `{other}`"),
                        });
                    }
                };
                rights.push(r);
            }
            Ok(CapabilityGrant::Link(LinkGrant { rights }))
        }
        "mount" => {
            let tokens = if target.is_empty() || target.eq_ignore_ascii_case("all") {
                vec!["mount", "unmount"]
            } else {
                target.split(',').collect()
            };
            let mut rights = Vec::with_capacity(tokens.len());
            for tok in tokens {
                let r = match tok.trim().to_ascii_lowercase().as_str() {
                    "mount" => MountRight::Mount,
                    "unmount" => MountRight::Unmount,
                    other => {
                        return Err(OpsError::InvalidGrant {
                            spec: spec_display,
                            reason: format!("unknown mount right `{other}`"),
                        });
                    }
                };
                rights.push(r);
            }
            Ok(CapabilityGrant::Mount(MountGrant { rights }))
        }
        "device" | "dev" => {
            let tokens = if target.is_empty() || target.eq_ignore_ascii_case("all") {
                vec!["display", "input", "gpu", "audio"]
            } else {
                target.split(',').collect()
            };
            let mut classes = Vec::with_capacity(tokens.len());
            for tok in tokens {
                let c = match tok.trim().to_ascii_lowercase().as_str() {
                    "display" => DeviceClass::Display,
                    "input" => DeviceClass::Input,
                    "gpu" => DeviceClass::Gpu,
                    "audio" => DeviceClass::Audio,
                    other => {
                        return Err(OpsError::InvalidGrant {
                            spec: spec_display,
                            reason: format!("unknown device class `{other}`"),
                        });
                    }
                };
                classes.push(c);
            }
            Ok(CapabilityGrant::Device(DeviceGrant { classes }))
        }
        "inspect" => Ok(CapabilityGrant::Diagnostics(DiagnosticsGrant::InspectRead(
            parse_authority_scope(target, &spec_display)?,
        ))),
        "trace" | "tracing" => Ok(CapabilityGrant::Diagnostics(DiagnosticsGrant::TraceRead(
            parse_authority_scope(target, &spec_display)?,
        ))),
        "profile" | "profiling" => Ok(CapabilityGrant::Diagnostics(DiagnosticsGrant::ProfileRead(
            parse_authority_scope(target, &spec_display)?,
        ))),
        "diagnostics" => {
            if !target.is_empty() && !target.eq_ignore_ascii_case("control") {
                return Err(invalid("expected `diagnostics:control`"));
            }
            Ok(CapabilityGrant::Diagnostics(DiagnosticsGrant::Control))
        }
        "instance-control" | "instances" => Ok(CapabilityGrant::InstanceControl(
            parse_authority_scope(target, &spec_display)?,
        )),
        "settings" => {
            if !target.is_empty() && !target.eq_ignore_ascii_case("write") {
                return Err(invalid("expected `settings:write`"));
            }
            Ok(CapabilityGrant::Settings(SettingsGrant {
                rights: vec![SettingsRight::Write],
            }))
        }
        "virtualize" => {
            if !target.is_empty() && !target.eq_ignore_ascii_case("virtualize") {
                return Err(invalid("expected `virtualize`"));
            }
            if mode.is_some() {
                return Err(invalid("`virtualize` grant takes no mode"));
            }
            Ok(CapabilityGrant::Machine(MachineGrant {
                rights: vec![MachineRight::Virtualize],
            }))
        }
        "machine" => {
            let tokens = if target.is_empty() || target.eq_ignore_ascii_case("all") {
                vec!["control", "identity", "virtualize"]
            } else {
                target.split(',').collect()
            };
            let mut rights = Vec::with_capacity(tokens.len());
            for tok in tokens {
                let r = match tok.trim().to_ascii_lowercase().as_str() {
                    "control" => MachineRight::Control,
                    "identity" => MachineRight::Identity,
                    "virtualize" => MachineRight::Virtualize,
                    other => {
                        return Err(OpsError::InvalidGrant {
                            spec: spec_display,
                            reason: format!("unknown machine right `{other}`"),
                        });
                    }
                };
                rights.push(r);
            }
            Ok(CapabilityGrant::Machine(MachineGrant { rights }))
        }
        other => Err(OpsError::InvalidGrant {
            spec: spec_display,
            reason: format!("unknown capability grant kind `{other}`"),
        }),
    }
}

fn parse_authority_scope(raw: &str, spec: &str) -> Result<AuthorityScope, OpsError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "own" => Ok(AuthorityScope::Own),
        "subtree" => Ok(AuthorityScope::Subtree(None)),
        "machine" => Ok(AuthorityScope::Machine),
        other => {
            if let Ok(id) = other.parse::<u64>() {
                Ok(AuthorityScope::Subtree(Some(id)))
            } else {
                Err(OpsError::InvalidGrant {
                    spec: spec.to_owned(),
                    reason: format!(
                        "unknown authority scope `{other}`; expected own|subtree|machine|<instance-id>"
                    ),
                })
            }
        }
    }
}

/// Parse a POSIX signal name or number (`1..=64`) into its kernel signal number.
pub fn parse_posix_signal(raw: &str) -> Result<u8, OpsError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(OpsError::InvalidSignal {
            signal: raw.to_owned(),
        });
    }
    if let Ok(num) = trimmed.parse::<u8>() {
        if (1..=64).contains(&num) {
            return Ok(num);
        }
        return Err(OpsError::InvalidSignal {
            signal: raw.to_owned(),
        });
    }
    let upper = trimmed.to_ascii_uppercase();
    let short = upper.strip_prefix("SIG").unwrap_or(&upper);
    let num = match short {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "ILL" => 4,
        "TRAP" => 5,
        "ABRT" | "IOT" => 6,
        "BUS" => 7,
        "FPE" => 8,
        "KILL" => 9,
        "USR1" => 10,
        "SEGV" => 11,
        "USR2" => 12,
        "PIPE" => 13,
        "ALRM" => 14,
        "TERM" => 15,
        "STKFLT" => 16,
        "CHLD" | "CLD" => 17,
        "CONT" => 18,
        "STOP" => 19,
        "TSTP" => 20,
        "TTIN" => 21,
        "TTOU" => 22,
        "URG" => 23,
        "XCPU" => 24,
        "XFSZ" => 25,
        "VTALRM" => 26,
        "PROF" => 27,
        "WINCH" => 28,
        "IO" | "POLL" => 29,
        "PWR" => 30,
        "SYS" => 31,
        _ => {
            return Err(OpsError::InvalidSignal {
                signal: raw.to_owned(),
            });
        }
    };
    Ok(num)
}

/// Streaming handle to a remotely spawned program.
pub struct Child {
    session: Session,
    remote_child: rpc_programs::Child,
    instance_id: Arc<AtomicU64>,
    pub stdout: async_channel::Receiver<Result<Vec<u8>, OpsError>>,
    pub stderr: async_channel::Receiver<Result<Vec<u8>, OpsError>>,
    stdin_tx: Arc<tokio::sync::Mutex<Option<StreamWriter<u8>>>>,
    stdin_task: Option<tokio::task::JoinHandle<()>>,
    started_at: Instant,
}

impl Child {
    pub(crate) async fn from_remote(
        session: Session,
        remote_child: rpc_programs::Child,
        stdin_bytes: Vec<u8>,
    ) -> Result<Self, OpsError> {
        let started_at = Instant::now();
        let id = session
            .call(
                "system.programs.child.instance-id",
                remote_child.instance_id(),
            )
            .await?;
        let instance_id = Arc::new(AtomicU64::new(id));

        let (stdout_stream, stdout_done) = session
            .call("system.programs.child.stdout", remote_child.stdout())
            .await?;
        let (stderr_stream, stderr_done) = session
            .call("system.programs.child.stderr", remote_child.stderr())
            .await?;

        let (stdout_tx, stdout_rx) = async_channel::bounded(16);
        let (stderr_tx, stderr_rx) = async_channel::bounded(16);

        spawn_stream_pump(
            "system.programs.child.stdout",
            stdout_stream,
            stdout_done,
            stdout_tx,
        );
        spawn_stream_pump(
            "system.programs.child.stderr",
            stderr_stream,
            stderr_done,
            stderr_tx,
        );

        let (stdin_tx, stdin_task) = if stdin_bytes.is_empty() {
            let (tx, rx) = rpc_stream::<u8>();
            let stdin_done = session
                .call("system.programs.child.stdin", remote_child.stdin(rx))
                .await?;
            let task = tokio::spawn(async move {
                let _ = stdin_done.await;
            });
            (Arc::new(tokio::sync::Mutex::new(Some(tx))), Some(task))
        } else {
            let stdin_reader = StreamReader::from_vec(stdin_bytes);
            let stdin_done = session
                .call(
                    "system.programs.child.stdin",
                    remote_child.stdin(stdin_reader),
                )
                .await?;
            let task = tokio::spawn(async move {
                let _ = stdin_done.await;
            });
            (Arc::new(tokio::sync::Mutex::new(None)), Some(task))
        };

        Ok(Self {
            session,
            remote_child,
            instance_id,
            stdout: stdout_rx,
            stderr: stderr_rx,
            stdin_tx,
            stdin_task,
            started_at,
        })
    }

    /// Live instance ID if reported by the guest.
    #[must_use]
    pub fn instance_id(&self) -> Option<u64> {
        let id = self.instance_id.load(Ordering::Acquire);
        (id != 0).then_some(id)
    }

    /// Write a chunk of bytes into the running child's stdin stream.
    pub async fn write_stdin(&self, data: &[u8]) -> Result<(), OpsError> {
        let mut guard = self.stdin_tx.lock().await;
        let Some(tx) = guard.as_mut() else {
            return Err(OpsError::StdinClosed);
        };
        if data.is_empty() {
            return Ok(());
        }
        tx.send_batch(data.to_vec())
            .await
            .map_err(|source| OpsError::Rpc {
                operation: "system.programs.child.stdin",
                source,
            })
    }

    /// Close the child's stdin stream and deliver EOF.
    pub async fn close_stdin(&self) -> Result<(), OpsError> {
        let tx = self.stdin_tx.lock().await.take();
        if let Some(tx) = tx {
            let _ = tx.close().await;
        }
        Ok(())
    }

    /// Deliver a POSIX signal (`SIGINT`/`INT`/`2`, `SIGTERM`/`TERM`/`15`,
    /// `SIGKILL`/`KILL`/`9`, etc.) to this live child instance.
    pub async fn signal(&self, signal: &str) -> Result<(), OpsError> {
        let sig_num = parse_posix_signal(signal)?;
        match self
            .session
            .call(
                "system.programs.child.signal",
                self.remote_child.signal(sig_num),
            )
            .await?
        {
            Ok(()) => Ok(()),
            Err(err) => {
                if sig_num == 9
                    && let Some(id) = self.instance_id()
                    && self
                        .session
                        .options()
                        .attenuation
                        .allows(GrantRight::InstanceControl)
                    && self.session.kill(id).await.is_ok()
                {
                    return Ok(());
                }
                Err(OpsError::from(err))
            }
        }
    }

    /// Await completion of the remote execution and return its [`ExecResult`].
    pub async fn wait(mut self) -> Result<ExecResult, OpsError> {
        let _ = self.close_stdin().await;
        let status = self
            .session
            .call("system.programs.child.wait", self.remote_child.wait())
            .await?
            .map_err(OpsError::from)?;
        if let Some(task) = self.stdin_task.take() {
            let _ = task.await;
        }
        self.instance_id
            .store(status.instance_id, Ordering::Release);
        let exit_code = match status.termination {
            ChildTermination::Exited(code) => code,
            ChildTermination::Signaled(sig) => 128 + u32::from(sig.signal),
            ChildTermination::Trapped => 134,
            ChildTermination::Killed => 137,
        };
        Ok(ExecResult {
            instance_id: status.instance_id,
            exit_code,
            output: ExecOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
            launch_nanos: u64::try_from(self.started_at.elapsed().as_nanos()).unwrap_or(u64::MAX),
        })
    }
}

fn spawn_stream_pump(
    operation: &'static str,
    mut stream: StreamReader<u8>,
    done: helios_wit_rpc::FutureReader<Result<(), ()>>,
    tx: async_channel::Sender<Result<Vec<u8>, OpsError>>,
) {
    tokio::spawn(async move {
        loop {
            match stream.next_batch().await {
                Ok(Some(chunk)) => {
                    if !chunk.is_empty() && tx.send(Ok(chunk)).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(source) => {
                    let _ = tx.send(Err(OpsError::Rpc { operation, source })).await;
                    break;
                }
            }
        }
        let _ = done.await;
    });
}

/// Snapshot readiness flags reported by `helios:system/snapshot.snapshot-hold`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotReadiness {
    pub has_generation_id: bool,
}

/// RAII handle holding the guest's VMM snapshot preparation state over the
/// standard `helios:system/snapshot.snapshot-hold` WIT resource.
///
/// Dropping this handle automatically emits `Frame::ResourceDrop` to the
/// remote `inspector-worker`, releasing the kernel's snapshot hold.
pub struct SnapshotHold {
    handle: Option<RemoteSnapshotHold>,
    readiness: SnapshotReadiness,
}

impl SnapshotHold {
    /// Readiness flags reported by the guest when preparing for snapshot.
    #[must_use]
    pub const fn readiness(&self) -> SnapshotReadiness {
        self.readiness
    }

    /// End the snapshot hold on the guest so its host share re-attaches.
    pub async fn release(mut self) -> Result<(), OpsError> {
        drop(self.handle.take());
        Ok(())
    }
}

/// Standalone RAII lease holding a live `helios:system/profiling.sampling-session`
/// resource on the remote guest.
///
/// Dropping this handle non-blockingly emits `Frame::ResourceDrop` to the
/// remote `inspector-worker` (zero `block_on`), restoring normal processor
/// timer periods while keeping collected samples readable via
/// [`Session::profile_instruction_samples`].
pub struct SamplingSession {
    session: Session,
    handle: Option<rpc_profiling::SamplingSession>,
}

impl SamplingSession {
    /// Returns `true` while the remote sampling lease is still held.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.handle.is_some()
    }

    /// Read collected instruction samples while sampling remains active.
    pub async fn samples(&self) -> Result<InstructionProfile, OpsError> {
        self.session.profile_instruction_samples().await
    }

    /// Read collected instruction samples and release the sampling lease.
    pub async fn stop_and_collect(mut self) -> Result<InstructionProfile, OpsError> {
        let profile = self.session.profile_instruction_samples().await;
        drop(self.handle.take());
        profile
    }

    /// Stop instruction sampling cleanly without blocking.
    pub async fn stop(mut self) -> Result<(), OpsError> {
        drop(self.handle.take());
        Ok(())
    }
}

/// Remote VFS directory entry returned by [`Session::list_dir`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteEntry {
    pub path: String,
    pub name: String,
    pub kind: EntryKind,
}

/// Remote VFS metadata returned by [`Session::stat`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteStat {
    pub path: String,
    pub name: String,
    pub kind: EntryKind,
    pub size: u64,
}

/// Connected async operations session against one Helios target.
#[derive(Clone)]
pub struct Session {
    target: Target,
    connection: RpcConnection,
    options: SessionOptions,
    sampling_session: Arc<tokio::sync::Mutex<Option<rpc_profiling::SamplingSession>>>,
}

impl Session {
    /// Connect asynchronously to `target` with `options`.
    pub async fn connect(target: &Target, options: SessionOptions) -> Result<Self, OpsError> {
        let uri = target.parsed_uri()?;
        let connection = RpcConnection::connect(&uri, &options.security).await?;
        Ok(Self {
            target: target.clone(),
            connection,
            options,
            sampling_session: Arc::new(tokio::sync::Mutex::new(None)),
        })
    }

    /// Wrap an already-connected [`RpcConnection`] (e.g. from `helios vm` boot).
    #[must_use]
    pub fn from_connection(
        target: Target,
        connection: RpcConnection,
        options: SessionOptions,
    ) -> Self {
        Self {
            target,
            connection,
            options,
            sampling_session: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Target descriptor for this session.
    #[must_use]
    pub const fn target(&self) -> &Target {
        &self.target
    }

    /// Active options, including capability attenuation and identity.
    #[must_use]
    pub const fn options(&self) -> &SessionOptions {
        &self.options
    }

    /// Borrow the underlying `helios-wit-rpc` [`ProtocolClient`].
    #[must_use]
    pub fn protocol_client(&self) -> &ProtocolClient {
        self.connection.client()
    }

    /// Return a new [`Session`] handle sharing this connection with monotonically
    /// narrowed attenuation. Refuses any privilege or scope widening with
    /// [`OpsError::AttenuationDenied`].
    pub fn attenuated(&self, attenuation: Attenuation) -> Result<Self, OpsError> {
        let narrowed = self.options.attenuation.attenuate(&attenuation)?;
        let mut next = self.clone();
        next.options.attenuation = narrowed;
        Ok(next)
    }

    /// Active principal name for `whoami`.
    #[must_use]
    pub fn whoami(&self) -> String {
        if let Some(identity) = &self.options.identity {
            return identity.principal.clone();
        }
        format!("local@{}", self.target.name)
    }

    pub(crate) fn require_right(&self, right: GrantRight) -> Result<(), OpsError> {
        if self.options.attenuation.allows(right) {
            Ok(())
        } else {
            Err(OpsError::AttenuationDenied {
                capability: right.as_str().to_owned(),
                scope: self.options.attenuation.effective_scope().to_owned(),
            })
        }
    }

    pub(crate) async fn call<T>(
        &self,
        operation: &'static str,
        fut: impl Future<Output = Result<T, RpcError>>,
    ) -> Result<T, OpsError> {
        let res = tokio::time::timeout(self.options.timeout, fut)
            .await
            .map_err(|_| OpsError::TimedOut { operation })?;
        res.map_err(|source| OpsError::Rpc { operation, source })
    }

    /// Query `helios:system/inspect` across `/kernel/*` and component inspect trees.
    pub async fn inspect(&self, prefixes: &[&str], limit: u32) -> Result<SnapshotResult, OpsError> {
        self.require_right(GrantRight::Inspect)?;
        let active_scope = normalize_scope(self.options.attenuation.effective_scope());
        let effective_prefixes: Vec<String> = if active_scope == "/" {
            prefixes.iter().map(|p| (*p).to_owned()).collect()
        } else if prefixes.is_empty() {
            vec![active_scope.clone()]
        } else {
            prefixes
                .iter()
                .map(|p| {
                    let candidate = if p.starts_with('/') {
                        normalize_absolute_path(p)?
                    } else {
                        normalize_absolute_path(&format!("{active_scope}/{p}"))?
                    };
                    if !scope_contains(&active_scope, &candidate) {
                        return Err(OpsError::AttenuationDenied {
                            capability: GrantRight::Inspect.as_str().to_owned(),
                            scope: active_scope.clone(),
                        });
                    }
                    if p.ends_with('/') && candidate != "/" {
                        Ok(format!("{candidate}/"))
                    } else {
                        Ok(candidate)
                    }
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        let client = rpc_inspect::RpcClient::new(self.connection.client().clone());
        let answer = self
            .call(
                "system.inspect.snapshot",
                client.snapshot(
                    Query {
                        prefixes: effective_prefixes,
                    },
                    limit,
                ),
            )
            .await?;
        let mut snapshot = answer.map_err(|error| OpsError::FilterRefused {
            operation: "system.inspect.snapshot",
            error,
        })?;
        if active_scope != "/" {
            snapshot
                .entries
                .retain(|entry| scope_contains(&active_scope, &normalize_scope(&entry.path)));
        }
        Ok(snapshot)
    }

    /// Decode the `/kernel/*` inspect subtree into a typed [`KernelSnapshot`].
    pub async fn kernel_snapshot(&self) -> Result<KernelSnapshot, OpsError> {
        let raw = self.inspect(&["/kernel/"], 0).await?;
        Ok(KernelSnapshot::from_snapshot(&raw))
    }

    /// List live instances (`ps`).
    pub async fn instances(&self) -> Result<Vec<Instance>, OpsError> {
        self.require_right(GrantRight::InstanceRead)?;
        let client = rpc_instances::RpcClient::new(self.connection.client().clone());
        let mut live = self
            .call("system.instances.snapshot", client.snapshot())
            .await?;
        let active_scope = normalize_scope(self.options.attenuation.effective_scope());
        if active_scope != "/" {
            live.retain(|inst| scope_contains(&active_scope, &normalize_scope(&inst.name)));
        }
        Ok(live)
    }

    /// Alias for [`Self::instances`].
    pub async fn ps(&self) -> Result<Vec<Instance>, OpsError> {
        self.instances().await
    }

    /// Request termination of instance `id`.
    pub async fn kill(&self, id: u64) -> Result<(), OpsError> {
        self.require_right(GrantRight::InstanceControl)?;
        let client = rpc_instances::RpcClient::new(self.connection.client().clone());
        let answer = self.call("system.instances.kill", client.kill(id)).await?;
        answer.map_err(|error| OpsError::KillRefused { id, error })
    }

    /// Resolve a live instance by name and request its termination.
    pub async fn kill_by_name(&self, name: &str) -> Result<u64, OpsError> {
        let live = self.instances().await?;
        let id = live
            .iter()
            .find(|inst| inst.name == name)
            .map(|inst| inst.id)
            .ok_or_else(|| OpsError::NoInstanceNamed {
                name: name.to_owned(),
            })?;
        self.kill(id).await?;
        Ok(id)
    }

    /// Component-topology control client (`list`, `status`, `start`, `stop`, `restart`).
    #[must_use]
    pub fn components(&self) -> ComponentsClient {
        ComponentsClient::new(self.clone())
    }

    /// Remote OCI image store client (`pull`, `list`, `inspect`, `remove`).
    #[must_use]
    pub fn oci(&self) -> OciClient {
        OciClient::new(self.clone())
    }

    /// Remote OCI image store client targeting a custom guest `store_root`.
    pub fn oci_with_store_root(&self, store_root: impl AsRef<str>) -> Result<OciClient, OpsError> {
        OciClient::with_store_root(self.clone(), store_root)
    }

    /// Remote mount-table client (`list`, `mount`, `mount_btrfs`, `unmount`).
    #[must_use]
    pub fn mounts(&self) -> MountsClient {
        MountsClient::new(self.clone())
    }

    /// Remote `helios:system/btrfs` subvolume, extent, device, and quota client.
    #[must_use]
    pub fn btrfs(&self) -> BtrfsClient {
        BtrfsClient::new(self.clone())
    }

    /// Remote custom Linux `MicroVm` orchestration client (`list`, `spawn`, `builder`).
    #[must_use]
    pub fn vm(&self) -> VmClient {
        VmClient::new(self.clone())
    }

    /// List configured components via opt-in `helios:system/component-control`.
    pub async fn list_components(&self) -> Result<Vec<ComponentStatus>, OpsError> {
        self.components().list().await
    }

    /// Query the status of one component by moniker.
    pub async fn component_status(&self, moniker: &str) -> Result<ComponentStatus, OpsError> {
        self.components().status(moniker).await
    }

    /// Start a component by moniker via opt-in `helios:system/component-control`.
    pub async fn start_component(&self, moniker: &str) -> Result<ComponentStatus, OpsError> {
        self.components().start(moniker).await
    }

    /// Stop a component by moniker via opt-in `helios:system/component-control`.
    pub async fn stop_component(&self, moniker: &str) -> Result<(), OpsError> {
        self.components().stop(moniker).await
    }

    /// Restart a component by moniker via opt-in `helios:system/component-control`.
    pub async fn restart_component(&self, moniker: &str) -> Result<ComponentStatus, OpsError> {
        self.components().restart(moniker).await
    }

    /// Fetch recent guest tracing events matching `filter`.
    pub async fn trace_recent(
        &self,
        filter: &rpc_tracing::Filter,
        limit: u32,
    ) -> Result<Vec<rpc_tracing::Event>, OpsError> {
        self.require_right(GrantRight::Trace)?;
        let client = rpc_tracing::RpcClient::new(self.connection.client().clone());
        let answer = self
            .call(
                "system.tracing.recent",
                client.recent(filter.clone(), limit),
            )
            .await?;
        answer.map_err(|error| OpsError::FilterRefused {
            operation: "system.tracing.recent",
            error,
        })
    }

    /// Enable or disable a named kernel diagnostic tracing target.
    pub async fn set_trace_target_enabled(
        &self,
        target: &str,
        enabled: bool,
    ) -> Result<(), OpsError> {
        self.require_right(GrantRight::Trace)?;
        let client = rpc_tracing::RpcClient::new(self.connection.client().clone());
        let answer = self
            .call(
                "system.tracing.set-target-enabled",
                client.set_target_enabled(target.to_owned(), enabled),
            )
            .await?;
        answer.map_err(|error| OpsError::TraceTargetRefused {
            target: target.to_owned(),
            error,
        })
    }

    /// Toggle guest profiling collection.
    pub async fn profile_set_enabled(&self, enabled: bool) -> Result<(), OpsError> {
        self.require_right(GrantRight::Profile)?;
        let client = rpc_profiling::RpcClient::new(self.connection.client().clone());
        let answer = self
            .call("system.profiling.set-enabled", client.set_enabled(enabled))
            .await?;
        answer.map_err(|error| OpsError::ProfilingControlRefused {
            operation: "set-enabled",
            error,
        })
    }

    /// Clear collected guest profile samples.
    pub async fn profile_clear(&self) -> Result<(), OpsError> {
        self.require_right(GrantRight::Profile)?;
        let client = rpc_profiling::RpcClient::new(self.connection.client().clone());
        let answer = self.call("system.profiling.clear", client.clear()).await?;
        answer.map_err(|error| OpsError::ProfilingControlRefused {
            operation: "clear",
            error,
        })
    }

    /// Fetch folded stack samples matching `filter`.
    pub async fn profile_folded(
        &self,
        filter: &ProfileFilter,
        limit: u32,
    ) -> Result<Vec<FoldedSample>, OpsError> {
        self.require_right(GrantRight::Profile)?;
        let client = rpc_profiling::RpcClient::new(self.connection.client().clone());
        let answer = self
            .call(
                "system.profiling.folded",
                client.folded(filter.clone(), limit),
            )
            .await?;
        answer.map_err(|error| OpsError::FilterRefused {
            operation: "system.profiling.folded",
            error,
        })
    }

    /// Fetch metric samples matching `filter`.
    pub async fn profile_metrics(
        &self,
        filter: &MetricFilter,
        limit: u32,
    ) -> Result<Vec<MetricSample>, OpsError> {
        self.require_right(GrantRight::Profile)?;
        let client = rpc_profiling::RpcClient::new(self.connection.client().clone());
        let answer = self
            .call(
                "system.profiling.metrics",
                client.metrics(filter.clone(), limit),
            )
            .await?;
        answer.map_err(|error| OpsError::FilterRefused {
            operation: "system.profiling.metrics",
            error,
        })
    }

    /// Start periodic kernel instruction sampling and return a standalone RAII
    /// [`SamplingSession`] guard whose drop stops sampling non-blockingly.
    pub async fn start_instruction_sampling(&self) -> Result<SamplingSession, OpsError> {
        self.require_right(GrantRight::Profile)?;
        let client = rpc_profiling::RpcClient::new(self.connection.client().clone());
        let lease = self
            .call(
                "system.profiling.start-instruction-sampling",
                client.start_instruction_sampling(),
            )
            .await?
            .map_err(|error| OpsError::InstructionProfileRefused {
                operation: "start-instruction-sampling",
                error,
            })?;
        Ok(SamplingSession {
            session: self.clone(),
            handle: Some(lease),
        })
    }

    /// Start or stop kernel instruction sampling via the RAII `sampling-session` resource.
    pub async fn profile_set_instruction_sampling(&self, enabled: bool) -> Result<(), OpsError> {
        self.require_right(GrantRight::Profile)?;
        let mut slot = self.sampling_session.lock().await;
        if enabled {
            if slot.is_some() {
                return Ok(());
            }
            let client = rpc_profiling::RpcClient::new(self.connection.client().clone());
            let answer = self
                .call(
                    "system.profiling.start-instruction-sampling",
                    client.start_instruction_sampling(),
                )
                .await?;
            let lease = answer.map_err(|error| OpsError::InstructionProfileRefused {
                operation: "start-instruction-sampling",
                error,
            })?;
            *slot = Some(lease);
        } else {
            let _ = slot.take();
        }
        Ok(())
    }

    /// Retrieve collected kernel instruction samples.
    pub async fn profile_instruction_samples(&self) -> Result<InstructionProfile, OpsError> {
        self.require_right(GrantRight::Profile)?;
        let client = rpc_profiling::RpcClient::new(self.connection.client().clone());
        let answer = self
            .call(
                "system.profiling.instruction-samples",
                client.instruction_samples(),
            )
            .await?;
        answer.map_err(|error| OpsError::InstructionProfileRefused {
            operation: "instruction-samples",
            error,
        })
    }

    /// Retrieve collected kernel instruction samples and symbolize them against the
    /// local kernel ELF/DWARF image at `kernel_image`.
    pub async fn profile_instruction_samples_symbolized(
        &self,
        kernel_image: &Path,
    ) -> Result<SymbolizedInstructionProfile, OpsError> {
        let raw = self.profile_instruction_samples().await?;
        symbolize_instruction_profile(raw, kernel_image)
            .await
            .map_err(OpsError::from)
    }

    /// Retrieve collected kernel instruction samples, symbolize them against
    /// `kernel_image` (requiring DWARF), and render flamegraph folded stacks.
    pub async fn render_instruction_profile_folded(
        &self,
        kernel_image: &Path,
    ) -> Result<String, OpsError> {
        let raw = self.profile_instruction_samples().await?;
        render_folded_instruction_profile(raw, kernel_image)
            .await
            .map_err(OpsError::from)
    }

    /// Read the complete LLVM raw profile buffer from an instrumented kernel.
    pub async fn profile_raw_collect(&self) -> Result<Vec<u8>, OpsError> {
        self.require_right(GrantRight::Profile)?;
        let client = rpc_profiling::RpcClient::new(self.connection.client().clone());
        let total_size = self
            .call(
                "system.profiling.raw-profile-size",
                client.raw_profile_size(),
            )
            .await?
            .map_err(|error| OpsError::RawProfileRefused {
                operation: "raw-profile-size",
                error,
            })?;
        let mut out = Vec::with_capacity(usize::try_from(total_size).unwrap_or(0));
        let mut offset = 0_u64;
        while offset < total_size {
            let remaining = total_size - offset;
            let len = u32::try_from(remaining.min(u64::from(RAW_PROFILE_CHUNK_BYTES)))
                .unwrap_or(RAW_PROFILE_CHUNK_BYTES);
            let chunk = self
                .call(
                    "system.profiling.raw-profile-read",
                    client.raw_profile_read(offset, len),
                )
                .await?
                .map_err(|error| OpsError::RawProfileRefused {
                    operation: "raw-profile-read",
                    error,
                })?;
            if chunk.is_empty() {
                break;
            }
            offset = offset.saturating_add(chunk.len() as u64);
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    /// Query possible and online processor sets.
    pub async fn processors_sets(&self) -> Result<ProcessorSets, OpsError> {
        self.require_right(GrantRight::Processors)?;
        let client = rpc_processors::RpcClient::new(self.connection.client().clone());
        self.call("system.processors.sets", client.sets()).await
    }

    /// Take processor `id` offline.
    pub async fn processor_offline(&self, id: u32) -> Result<(), OpsError> {
        self.require_right(GrantRight::Processors)?;
        let client = rpc_processors::RpcClient::new(self.connection.client().clone());
        let answer = self
            .call("system.processors.offline", client.offline(id))
            .await?;
        answer.map_err(|error| OpsError::ProcessorOfflineRefused {
            processor: id,
            error,
        })
    }

    /// Bring processor `id` online.
    pub async fn processor_online(&self, id: u32) -> Result<(), OpsError> {
        self.require_right(GrantRight::Processors)?;
        let client = rpc_processors::RpcClient::new(self.connection.client().clone());
        let answer = self
            .call("system.processors.online", client.online(id))
            .await?;
        answer.map_err(|error| OpsError::ProcessorOnlineRefused {
            processor: id,
            error,
        })
    }

    /// Execute a program by path via `helios:system/programs.exec` with no
    /// hardcoded implicit root capability grants.
    pub async fn exec(&self, path: &str, args: &[String]) -> Result<ExecResult, OpsError> {
        self.require_right(GrantRight::Exec)?;
        let normalized = normalize_absolute_path(path)?;
        let req = ExecRequest {
            name: normalized.clone(),
            args: args.to_vec(),
            env: Vec::new(),
            path: normalized,
            cwd: None,
            stdin: Vec::new(),
            hint: None,
            capability_grants: Vec::new(),
        };
        self.exec_request(req).await
    }

    /// Execute a full [`ExecRequest`] via `helios:system/programs.exec`.
    pub async fn exec_request(
        &self,
        request: ExecRequest<WireIpcEndpoint>,
    ) -> Result<ExecResult, OpsError> {
        self.require_right(GrantRight::Exec)?;
        let client = rpc_programs::RpcClient::new(self.connection.client().clone());
        let answer = self
            .call("system.programs.exec", client.exec(request))
            .await?;
        answer.map_err(OpsError::from)
    }

    /// Construct a fluent [`crate::Command`] bound for execution on this session.
    #[must_use]
    pub fn command(&self, path: impl Into<String>) -> crate::grants::Command {
        crate::grants::Command::new(path)
    }

    /// Install or clear the session's inherited default Linux root image on the
    /// remote `inspector-worker` (`helios:system/programs.set-default-image`).
    ///
    /// Passing `None` restores bare-syscall Linux execution without a default overlay root.
    pub async fn set_default_image(
        &self,
        image: Option<DefaultLinuxImage>,
    ) -> Result<(), OpsError> {
        self.require_right(GrantRight::Exec)?;
        let normalized = match image {
            Some(mut img) => {
                img.root_path = normalize_absolute_path(&img.root_path)?;
                Some(img)
            }
            None => None,
        };
        let client = rpc_programs::RpcClient::new(self.connection.client().clone());
        self.call(
            "system.programs.set-default-image",
            client.set_default_image(normalized),
        )
        .await?
        .map_err(OpsError::from)
    }

    /// Query the session's current inherited default Linux root image on the
    /// remote `inspector-worker` (`helios:system/programs.get-default-image`).
    pub async fn get_default_image(&self) -> Result<Option<DefaultLinuxImage>, OpsError> {
        self.require_right(GrantRight::Exec)?;
        let client = rpc_programs::RpcClient::new(self.connection.client().clone());
        self.call(
            "system.programs.get-default-image",
            client.get_default_image(),
        )
        .await
    }

    /// Install a pulled OCI image as the session's remote default Linux root image.
    pub async fn set_default_image_from_oci(
        &self,
        image: &helios_oci::PulledImage,
    ) -> Result<(), OpsError> {
        let default_img = crate::linux::default_linux_image_from_oci(image)?;
        self.set_default_image(Some(default_img)).await
    }

    /// Install a guest root directory path as the session's remote default Linux root image.
    pub async fn set_default_image_path(&self, root_path: &str) -> Result<(), OpsError> {
        self.set_default_image(Some(DefaultLinuxImage {
            root_path: root_path.to_owned(),
            env: Vec::new(),
            credentials: None,
        }))
        .await
    }

    /// Persist this authenticated session principal's default Linux image preference
    /// inside `store_root` (`helios_oci::DefaultImageStore`).
    pub fn set_user_default_image(
        &self,
        store_root: &Path,
        image: &helios_oci::PulledImage,
    ) -> Result<helios_oci::UserDefaultImage, OpsError> {
        let mut store = helios_oci::DefaultImageStore::load(
            helios_oci::DefaultImageStore::path_in_store(store_root),
        )?;
        let pref = helios_oci::UserDefaultImage::from_pulled_image(image)?;
        store.set(&self.whoami(), pref.clone())?;
        Ok(pref)
    }

    /// Look up this authenticated session principal's persisted default Linux image preference.
    pub fn get_user_default_image(
        &self,
        store_root: &Path,
    ) -> Result<Option<helios_oci::UserDefaultImage>, OpsError> {
        let store = helios_oci::DefaultImageStore::load(
            helios_oci::DefaultImageStore::path_in_store(store_root),
        )?;
        Ok(store.get(&self.whoami())?.cloned())
    }

    /// Spawn a remote program via `helios:system/programs.spawn` and expose live
    /// async stdout, stderr, signal, and wait handles.
    pub async fn spawn(&self, request: SpawnRequest) -> Result<Child, OpsError> {
        self.require_right(GrantRight::Exec)?;
        let path = normalize_absolute_path(&request.path)?;
        let client = rpc_programs::RpcClient::new(self.connection.client().clone());
        let remote_child = self
            .call(
                "system.programs.spawn",
                client.spawn(WireSpawnRequest {
                    name: path.clone(),
                    args: request.args,
                    env: request.env,
                    path,
                    cwd: request.cwd,
                    sockets: Vec::new(),
                    capability_grants: request.capability_grants,
                }),
            )
            .await?
            .map_err(OpsError::from)?;
        Child::from_remote(self.clone(), remote_child, request.stdin).await
    }

    /// Prepare the guest for a VMM snapshot and return an RAII [`SnapshotHold`].
    pub async fn snapshot_hold(&self) -> Result<SnapshotHold, OpsError> {
        self.require_right(GrantRight::Snapshot)?;
        let client = rpc_snapshot::RpcClient::new(self.connection.client().clone());
        let handle = self
            .call("system.snapshot.prepare", client.prepare())
            .await?
            .map_err(|error| OpsError::SnapshotRefused { error })?;
        let has_generation_id = self
            .call(
                "system.snapshot.has-generation-id",
                handle.has_generation_id(),
            )
            .await?;
        Ok(SnapshotHold {
            handle: Some(handle),
            readiness: SnapshotReadiness { has_generation_id },
        })
    }

    /// List directory entries on the remote VFS via `wasi:filesystem/{preopens,types}`.
    pub async fn list_dir(&self, path: &str) -> Result<Vec<RemoteEntry>, OpsError> {
        self.require_right(GrantRight::FilesystemRead)?;
        let dir = normalize_absolute_path(path)?;
        let raw = tokio::time::timeout(
            self.options.timeout,
            inspector_fs::list_dir(self.connection.client(), &dir),
        )
        .await
        .map_err(|_| OpsError::TimedOut {
            operation: "wasi:filesystem.read-directory",
        })??;
        Ok(raw
            .into_iter()
            .map(|entry| {
                let full_path = if dir == "/" {
                    format!("/{}", entry.name)
                } else {
                    format!("{dir}/{}", entry.name)
                };
                RemoteEntry {
                    path: full_path,
                    name: entry.name,
                    kind: entry.kind,
                }
            })
            .collect())
    }

    /// Stat a single path on the remote VFS via `wasi:filesystem/{preopens,types}`.
    pub async fn stat(&self, path: &str) -> Result<RemoteStat, OpsError> {
        self.require_right(GrantRight::FilesystemRead)?;
        let normalized = normalize_absolute_path(path)?;
        let st = tokio::time::timeout(
            self.options.timeout,
            inspector_fs::stat(self.connection.client(), &normalized),
        )
        .await
        .map_err(|_| OpsError::TimedOut {
            operation: "wasi:filesystem.stat",
        })?
        .map_err(|err| match err {
            inspector_fs::FsRpcError::Fs {
                code: helios_wit_rpc::inspector::wasi::filesystem::types::ErrorCode::NoEntry,
                ..
            } => OpsError::NotFound {
                path: normalized.clone(),
            },
            other => OpsError::Fs(other),
        })?;
        let name = if normalized == "/" {
            "/".to_owned()
        } else {
            Path::new(&normalized)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&normalized)
                .to_owned()
        };
        Ok(RemoteStat {
            path: normalized,
            name,
            kind: st.kind,
            size: st.size,
        })
    }

    /// Read a file from the remote VFS via `wasi:filesystem/{preopens,types}`.
    pub async fn read_file(&self, path: &str) -> Result<Vec<u8>, OpsError> {
        self.require_right(GrantRight::FilesystemRead)?;
        let normalized = normalize_absolute_path(path)?;
        tokio::time::timeout(
            self.options.timeout,
            inspector_fs::read_file(self.connection.client(), &normalized),
        )
        .await
        .map_err(|_| OpsError::TimedOut {
            operation: "wasi:filesystem.read-via-stream",
        })?
        .map_err(OpsError::from)
    }

    /// Write or append bytes to a file on the remote VFS via `wasi:filesystem/{preopens,types}`.
    pub async fn write_file(&self, path: &str, data: &[u8], append: bool) -> Result<(), OpsError> {
        self.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(path)?;
        tokio::time::timeout(
            self.options.timeout,
            inspector_fs::write_file(self.connection.client(), &normalized, data, append),
        )
        .await
        .map_err(|_| OpsError::TimedOut {
            operation: "wasi:filesystem.write-via-stream",
        })?
        .map_err(OpsError::from)
    }

    /// Create a directory on the remote VFS via `wasi:filesystem/{preopens,types}`.
    pub async fn mkdir(&self, path: &str) -> Result<(), OpsError> {
        self.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(path)?;
        tokio::time::timeout(
            self.options.timeout,
            inspector_fs::mkdir(self.connection.client(), &normalized),
        )
        .await
        .map_err(|_| OpsError::TimedOut {
            operation: "wasi:filesystem.create-directory-at",
        })?
        .map_err(OpsError::from)
    }

    /// Remove a file or directory on the remote VFS via `wasi:filesystem/{preopens,types}`.
    pub async fn remove(&self, path: &str) -> Result<(), OpsError> {
        self.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(path)?;
        tokio::time::timeout(
            self.options.timeout,
            inspector_fs::remove(self.connection.client(), &normalized),
        )
        .await
        .map_err(|_| OpsError::TimedOut {
            operation: "wasi:filesystem.remove",
        })?
        .map_err(OpsError::from)
    }

    /// Copy a file on the remote VFS via `wasi:filesystem/{preopens,types}`.
    pub async fn copy(&self, source: &str, destination: &str) -> Result<(), OpsError> {
        self.require_right(GrantRight::FilesystemWrite)?;
        let src = normalize_absolute_path(source)?;
        let dst = normalize_absolute_path(destination)?;
        tokio::time::timeout(
            self.options.timeout,
            inspector_fs::copy(self.connection.client(), &src, &dst),
        )
        .await
        .map_err(|_| OpsError::TimedOut {
            operation: "wasi:filesystem.copy",
        })?
        .map_err(OpsError::from)
    }

    /// Rename / move a file or directory on the remote VFS via `wasi:filesystem/{preopens,types}`.
    pub async fn rename(&self, source: &str, destination: &str) -> Result<(), OpsError> {
        self.require_right(GrantRight::FilesystemWrite)?;
        let src = normalize_absolute_path(source)?;
        let dst = normalize_absolute_path(destination)?;
        tokio::time::timeout(
            self.options.timeout,
            inspector_fs::rename(self.connection.client(), &src, &dst),
        )
        .await
        .map_err(|_| OpsError::TimedOut {
            operation: "wasi:filesystem.rename-at",
        })?
        .map_err(OpsError::from)
    }

    /// Touch a file on the remote VFS via `wasi:filesystem/{preopens,types}`.
    pub async fn touch(&self, path: &str) -> Result<(), OpsError> {
        self.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(path)?;
        tokio::time::timeout(
            self.options.timeout,
            inspector_fs::touch(self.connection.client(), &normalized),
        )
        .await
        .map_err(|_| OpsError::TimedOut {
            operation: "wasi:filesystem.touch",
        })?
        .map_err(OpsError::from)
    }

    /// Mount a btrfs volume on the remote guest via `helios:system/mounts.mount`.
    pub async fn mount_btrfs(&self, request: &MountBtrfsRequest) -> Result<(), OpsError> {
        self.require_right(GrantRight::FilesystemWrite)?;
        tokio::time::timeout(
            self.options.timeout,
            inspector_fs::mount_btrfs(self.connection.client(), request),
        )
        .await
        .map_err(|_| OpsError::TimedOut {
            operation: "helios:system/mounts.mount",
        })?
        .map_err(OpsError::from)
    }
}

/// Normalize a remote VFS path to an absolute `/...` path without parent traversal.
pub fn normalize_absolute_path(input: &str) -> Result<String, OpsError> {
    let mut segments = Vec::new();
    for component in Path::new(input).components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(seg) => {
                let text = seg.to_str().ok_or_else(|| OpsError::InvalidPath {
                    path: input.to_owned(),
                    reason: "contains non-UTF-8 segment",
                })?;
                segments.push(text.to_owned());
            }
            Component::ParentDir => {
                segments.pop();
            }
            Component::Prefix(_) => {
                return Err(OpsError::InvalidPath {
                    path: input.to_owned(),
                    reason: "contains unsupported path prefix",
                });
            }
        }
    }
    if segments.is_empty() {
        Ok("/".to_owned())
    } else {
        Ok(format!("/{}", segments.join("/")))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::os::unix::net::UnixStream;

    use async_io::Async;

    use super::*;
    use crate::target::TargetUri;
    use crate::transport::{RpcConnection, SecurityMode};

    fn dummy_session(attenuation: Attenuation) -> Session {
        let (host, _guest) = UnixStream::pair().expect("socket pair");
        host.set_nonblocking(true).expect("nonblocking");
        let read = host.try_clone().expect("clone");
        let conn = RpcConnection::from_split(
            Box::new(Async::new(read).expect("async read")),
            Box::new(Async::new(host).expect("async write")),
        );
        let target = Target::new("node", "tcp://127.0.0.1:9443").expect("target");
        Session::from_connection(
            target,
            conn,
            SessionOptions {
                attenuation,
                ..SessionOptions::default()
            },
        )
    }

    #[tokio::test]
    async fn session_attenuation_is_strictly_monotonic() {
        let base = dummy_session(Attenuation {
            scope: Some("/core/http".to_owned()),
            only: BTreeSet::from([GrantRight::Inspect, GrantRight::InstanceRead]),
        });

        // Narrowing within scope + subset of rights succeeds.
        let narrowed = base
            .attenuated(Attenuation {
                scope: Some("/core/http/v1".to_owned()),
                only: BTreeSet::from([GrantRight::Inspect]),
            })
            .expect("monotonic narrowing must succeed");
        assert_eq!(
            narrowed.options().attenuation.effective_scope(),
            "/core/http/v1"
        );

        // Widening scope to sibling prefix `/core/http-admin` must fail.
        assert!(matches!(
            base.attenuated(Attenuation {
                scope: Some("/core/http-admin".to_owned()),
                only: BTreeSet::from([GrantRight::Inspect]),
            }),
            Err(OpsError::AttenuationDenied { .. })
        ));

        // Widening scope back to `/` must fail.
        assert!(matches!(
            base.attenuated(Attenuation {
                scope: Some("/".to_owned()),
                only: BTreeSet::from([GrantRight::Inspect]),
            }),
            Err(OpsError::AttenuationDenied { .. })
        ));

        // Widening rights (empty `only` or extra right) must fail.
        assert!(matches!(
            base.attenuated(Attenuation {
                scope: None,
                only: BTreeSet::new(),
            }),
            Err(OpsError::AttenuationDenied { .. })
        ));
        assert!(matches!(
            base.attenuated(Attenuation {
                scope: None,
                only: BTreeSet::from([GrantRight::Inspect, GrantRight::InstanceControl]),
            }),
            Err(OpsError::AttenuationDenied { .. })
        ));

        // Out-of-scope inspect prefixes (including `/kernel/*` and sibling `/core/http-admin`) must fail.
        assert!(matches!(
            base.inspect(&["/kernel/memory"], 0).await,
            Err(OpsError::AttenuationDenied { .. })
        ));
        assert!(matches!(
            base.inspect(&["/core/http-admin"], 0).await,
            Err(OpsError::AttenuationDenied { .. })
        ));
    }

    #[tokio::test]
    async fn helios_tls_uri_requires_authenticated_mode_and_never_downgrades() {
        for raw in ["helios://127.0.0.1:9443", "helios+tls://127.0.0.1:9443"] {
            let uri = TargetUri::parse(raw).expect("parse helios uri");
            let err = RpcConnection::connect(&uri, &SecurityMode::Plain)
                .await
                .err()
                .expect("helios:// must refuse Plain mode");
            assert!(matches!(
                err,
                crate::error::TransportError::AuthRequired { .. }
            ));
        }
    }

    #[tokio::test]
    async fn helios_tls_end_to_end_authenticates_and_invokes_wit_rpc() {
        use futures_util::AsyncReadExt as _;
        use helios_inspector_protocol::auth::{
            AuthPolicy, ClientIdentity, MACHINE_IDENTITY_HANDSHAKE_DOMAIN, SessionGrants,
            TransportKind, server_handshake, sign_machine_identity_seed,
        };
        use helios_inspector_protocol::tls::{TlsServerStream, build_ephemeral_server_config};
        use helios_wit_rpc::Endpoint;
        use helios_wit_rpc::inspector::helios::system::inspect::{
            self as rpc_inspect, Entry, Value,
        };

        struct FakeInspect;
        impl rpc_inspect::RpcHandler for FakeInspect {
            type Publication = ();
            async fn publish(
                &self,
                _name: String,
                _span: helios_wit_rpc::inspector::helios::system::memory::Span,
            ) -> Result<Self::Publication, rpc_inspect::PublishError> {
                Ok(())
            }
            async fn snapshot(
                &self,
                _query: Query,
                _limit: u32,
            ) -> Result<
                SnapshotResult,
                helios_wit_rpc::inspector::helios::system::filters::FilterError,
            > {
                Ok(SnapshotResult {
                    timestamp: 42,
                    truncated: false,
                    publications: Vec::new(),
                    entries: vec![Entry {
                        path: "/kernel/clock/uptime-nanos".to_owned(),
                        value: Value::Unsigned64(1234),
                    }],
                })
            }
        }

        let machine_seed = [0x11_u8; 32];
        let machine_pub = ClientIdentity::from_static_seed(machine_seed).public_key();
        let client_seed = [0x22_u8; 32];
        let client_identity = ClientIdentity::from_static_seed(client_seed);
        let policy = AuthPolicy::single_static_key("ops-test", client_identity.public_key());

        let listener = async_net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind tcp");
        let addr = listener.local_addr().expect("local addr");

        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let (cfg, spki_sha256) = build_ephemeral_server_config().expect("server tls config");
            let tls = TlsServerStream::accept(tcp.clone(), tcp, cfg, spki_sha256)
                .await
                .expect("tls accept");
            let tls_binding = tls.binding();
            let (mut r, mut w) = tls.split();
            let verified = server_handshake(
                &mut r,
                &mut w,
                TransportKind::TcpTls,
                &policy,
                &SessionGrants::full_worker_ceiling(),
                machine_pub,
                1_700_000_000,
                7,
                Some(tls_binding.channel_binding),
                Some(tls_binding.peer_cert_sha256),
                |challenge| {
                    Ok(sign_machine_identity_seed(
                        &machine_seed,
                        MACHINE_IDENTITY_HANDSHAKE_DOMAIN,
                        challenge,
                    ))
                },
            )
            .await
            .expect("server handshake");
            assert_eq!(verified.principal, "ops-test");
            let ep = Endpoint::new(r, w, rpc_inspect::RpcServer::new(FakeInspect));
            let _ = ep.drive().await;
        });

        let target = Target::new(
            "tls-node",
            format!("helios+tls://127.0.0.1:{}", addr.port()),
        )
        .expect("target");
        let session = Session::connect(
            &target,
            SessionOptions {
                security: SecurityMode::Authenticated {
                    identity: Box::new(client_identity),
                    expected_machine_public_key: Some(machine_pub),
                },
                ..SessionOptions::default()
            },
        )
        .await
        .expect("connect over helios+tls://");

        let snap = session.kernel_snapshot().await.expect("kernel_snapshot");
        assert_eq!(snap.uptime, 1234);
        drop(session);
        let _ = server_task.await;
    }

    #[test]
    fn parse_capability_grant_translates_valid_and_rejects_invalid_specs() {
        assert!(matches!(
            parse_capability_grant("dir:/tmp:rw").expect("dir rw"),
            CapabilityGrant::Directory(DirectoryGrant { ref source_path, ref rights, .. })
                if source_path == "/tmp" && rights.contains(&FilesystemRight::Write)
        ));
        assert!(matches!(
            parse_capability_grant("net:tcp,dns").expect("net tcp,dns"),
            CapabilityGrant::Network(NetworkGrant { ref rights })
                if rights.len() == 2
        ));
        assert!(matches!(
            parse_capability_grant("inspect:own").expect("inspect own"),
            CapabilityGrant::Diagnostics(DiagnosticsGrant::InspectRead(AuthorityScope::Own))
        ));
        assert!(matches!(
            parse_capability_grant("unknown:foo"),
            Err(OpsError::InvalidGrant { .. })
        ));
        assert!(matches!(
            parse_capability_grant("dir:/tmp:badmode"),
            Err(OpsError::InvalidGrant { .. })
        ));
        assert!(matches!(
            parse_capability_grant("virtualize").expect("virtualize"),
            CapabilityGrant::Machine(MachineGrant { ref rights })
                if rights.contains(&MachineRight::Virtualize)
        ));
        assert!(matches!(
            parse_capability_grant("machine:virtualize").expect("machine:virtualize"),
            CapabilityGrant::Machine(MachineGrant { ref rights })
                if rights.contains(&MachineRight::Virtualize)
        ));
    }

    #[test]
    fn parse_posix_signal_handles_names_and_numbers() {
        assert_eq!(parse_posix_signal("SIGINT").expect("SIGINT"), 2);
        assert_eq!(parse_posix_signal("int").expect("int"), 2);
        assert_eq!(parse_posix_signal("2").expect("2"), 2);
        assert_eq!(parse_posix_signal("SIGTERM").expect("SIGTERM"), 15);
        assert_eq!(parse_posix_signal("term").expect("term"), 15);
        assert_eq!(parse_posix_signal("SIGKILL").expect("SIGKILL"), 9);
        assert_eq!(parse_posix_signal("SIGHUP").expect("SIGHUP"), 1);
        assert_eq!(parse_posix_signal("SIGQUIT").expect("SIGQUIT"), 3);
        assert_eq!(parse_posix_signal("SIGUSR1").expect("SIGUSR1"), 10);
        assert_eq!(parse_posix_signal("SIGUSR2").expect("SIGUSR2"), 12);
        assert_eq!(parse_posix_signal("64").expect("64"), 64);
        assert!(matches!(
            parse_posix_signal("SIGBOGUS"),
            Err(OpsError::InvalidSignal { .. })
        ));
        assert!(matches!(
            parse_posix_signal("0"),
            Err(OpsError::InvalidSignal { .. })
        ));
        assert!(matches!(
            parse_posix_signal("65"),
            Err(OpsError::InvalidSignal { .. })
        ));
    }

    #[tokio::test]
    async fn plain_tcp_uri_rejects_authenticated_security_mode() {
        let client_identity =
            helios_inspector_protocol::auth::ClientIdentity::from_static_seed([0x55; 32]);
        let uri = TargetUri::parse("tcp://127.0.0.1:9443").expect("parse tcp");
        let err = RpcConnection::connect(
            &uri,
            &SecurityMode::Authenticated {
                identity: Box::new(client_identity),
                expected_machine_public_key: None,
            },
        )
        .await
        .err()
        .expect("tcp:// must refuse Authenticated mode");
        assert!(matches!(
            err,
            crate::error::TransportError::PlainTcpAuthUnsupported { .. }
        ));
    }

    #[tokio::test]
    async fn session_spawn_streams_stdio_populates_id_and_delivers_signal() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU8, Ordering};

        use helios_wit_rpc::inspector::helios::system::programs::{
            AotRequest, AotResult, ChildTermination, ContainerConfig, ContainerExecRequest,
            ContainerSpawnRequest, DefaultLinuxImage, ExecError, ExecOutput, ExecRequest,
            ExecResult, ExitStatus, InheritedSocket, SpawnError, SpawnRequest as WireSpawnRequest,
        };
        use helios_wit_rpc::{Endpoint, FutureReader, StreamReader};

        struct FakeChild {
            id: u64,
            stdin_len: Arc<AtomicU8>,
            last_signal: Arc<AtomicU8>,
        }

        struct FakePrograms {
            last_signal: Arc<AtomicU8>,
            stdin_len: Arc<AtomicU8>,
        }

        impl rpc_programs::RpcHandler for FakePrograms {
            type Child = FakeChild;
            type Container = ();
            type Endpoint = ();
            type TcpListener = ();
            type TcpStream = ();
            type SerialPort = ();
            type VsockListener = ();
            type VsockStream = ();

            async fn child_stdin(
                &self,
                self_: &Self::Child,
                data: StreamReader<u8>,
            ) -> FutureReader<Result<(), ()>> {
                let bytes = data.collect_all().await.unwrap_or_default();
                self_.stdin_len.store(bytes.len() as u8, Ordering::Release);
                FutureReader::ready(Ok(()))
            }

            async fn child_stdout(
                &self,
                _self_: &Self::Child,
            ) -> (StreamReader<u8>, FutureReader<Result<(), ()>>) {
                (
                    StreamReader::from_vec(b"live-stdout".to_vec()),
                    FutureReader::ready(Ok(())),
                )
            }

            async fn child_stderr(
                &self,
                _self_: &Self::Child,
            ) -> (StreamReader<u8>, FutureReader<Result<(), ()>>) {
                (
                    StreamReader::from_vec(b"live-stderr".to_vec()),
                    FutureReader::ready(Ok(())),
                )
            }

            async fn child_instance_id(&self, self_: &Self::Child) -> u64 {
                self_.id
            }

            async fn child_signal(
                &self,
                self_: &Self::Child,
                signal: u8,
            ) -> Result<(), SpawnError> {
                self_.last_signal.store(signal, Ordering::Release);
                Ok(())
            }

            async fn child_wait(&self, self_: &Self::Child) -> Result<ExitStatus, SpawnError> {
                Ok(ExitStatus {
                    instance_id: self_.id,
                    termination: ChildTermination::Exited(0),
                })
            }

            async fn container_spawn(
                &self,
                _self_: &Self::Container,
                _request: ContainerSpawnRequest<
                    Self::TcpListener,
                    Self::VsockListener,
                    Self::TcpStream,
                    Self::VsockStream,
                    Self::SerialPort,
                >,
            ) -> Result<Self::Child, SpawnError> {
                unreachable!()
            }

            async fn container_exec(
                &self,
                _self_: &Self::Container,
                _request: ContainerExecRequest,
            ) -> Result<ExecResult, ExecError> {
                unreachable!()
            }

            async fn set_default_image(
                &self,
                _image: Option<DefaultLinuxImage>,
            ) -> Result<(), SpawnError> {
                Ok(())
            }

            async fn get_default_image(&self) -> Option<DefaultLinuxImage> {
                None
            }

            async fn take_inherited_sockets(
                &self,
            ) -> Vec<
                InheritedSocket<
                    Self::TcpListener,
                    Self::VsockListener,
                    Self::TcpStream,
                    Self::VsockStream,
                    Self::SerialPort,
                >,
            > {
                Vec::new()
            }

            async fn create_container(
                &self,
                _config: ContainerConfig<Self::Endpoint>,
            ) -> Result<Self::Container, SpawnError> {
                Ok(())
            }

            async fn spawn(
                &self,
                _request: WireSpawnRequest<
                    Self::TcpListener,
                    Self::VsockListener,
                    Self::TcpStream,
                    Self::VsockStream,
                    Self::SerialPort,
                    Self::Endpoint,
                >,
            ) -> Result<Self::Child, SpawnError> {
                Ok(FakeChild {
                    id: 77,
                    stdin_len: Arc::clone(&self.stdin_len),
                    last_signal: Arc::clone(&self.last_signal),
                })
            }

            async fn exec(
                &self,
                _request: ExecRequest<Self::Endpoint>,
            ) -> Result<ExecResult, ExecError> {
                Ok(ExecResult {
                    instance_id: 1,
                    exit_code: 0,
                    output: ExecOutput {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                    },
                    launch_nanos: 0,
                })
            }

            async fn aot(&self, _request: AotRequest) -> Result<AotResult, ExecError> {
                unreachable!()
            }
        }

        let (host, guest) = UnixStream::pair().expect("socket pair");
        host.set_nonblocking(true).expect("host nonblocking");
        guest.set_nonblocking(true).expect("guest nonblocking");
        let host_read = host.try_clone().expect("clone");
        let guest_read = guest.try_clone().expect("clone");
        let conn = RpcConnection::from_split(
            Box::new(Async::new(host_read).expect("async")),
            Box::new(Async::new(host).expect("async")),
        );
        let target = Target::new("spawn-test", "serial:///tmp/spawn.sock").expect("target");
        let session = Session::from_connection(target, conn, SessionOptions::default());

        let last_signal = Arc::new(AtomicU8::new(0));
        let stdin_len = Arc::new(AtomicU8::new(0));
        let ep = Endpoint::new(
            Async::new(guest_read).expect("async"),
            Async::new(guest).expect("async"),
            rpc_programs::RpcServer::new(FakePrograms {
                last_signal: Arc::clone(&last_signal),
                stdin_len: Arc::clone(&stdin_len),
            }),
        );
        let server_task = tokio::spawn(async move {
            let _ = ep.drive().await;
        });

        let mut req = SpawnRequest::new("/bin/demo", vec!["--flag".to_owned()]);
        req.stdin = b"abcde".to_vec();
        let child = session.spawn(req).await.expect("spawn");
        assert_eq!(child.instance_id(), Some(77));

        let mut out = Vec::new();
        while let Ok(chunk) = child.stdout.recv().await {
            out.extend_from_slice(&chunk.expect("ok"));
        }
        assert_eq!(out, b"live-stdout");
        let mut err = Vec::new();
        while let Ok(chunk) = child.stderr.recv().await {
            err.extend_from_slice(&chunk.expect("ok"));
        }
        assert_eq!(err, b"live-stderr");

        child.signal("SIGTERM").await.expect("signal");
        assert_eq!(last_signal.load(Ordering::Acquire), 15);

        let res = child.wait().await.expect("wait");
        assert_eq!(res.instance_id, 77);
        assert_eq!(res.exit_code, 0);
        assert_eq!(stdin_len.load(Ordering::Acquire), 5);

        server_task.abort();
    }

    #[tokio::test]
    async fn session_default_image_and_live_child_stdin_round_trip() {
        use std::sync::{Arc, Mutex};

        use helios_wit_rpc::inspector::helios::system::programs::{
            AotRequest, AotResult, ChildTermination, ContainerConfig, ContainerExecRequest,
            ContainerSpawnRequest, DefaultLinuxImage, ExecError, ExecOutput, ExecRequest,
            ExecResult, ExitStatus, InheritedSocket, SpawnError, SpawnRequest as WireSpawnRequest,
        };
        use helios_wit_rpc::{Endpoint, FutureReader, StreamReader};

        struct LivePrograms {
            default_image: Arc<Mutex<Option<DefaultLinuxImage>>>,
            received_stdin: Arc<Mutex<Vec<u8>>>,
        }

        struct LiveChild {
            received_stdin: Arc<Mutex<Vec<u8>>>,
        }

        impl rpc_programs::RpcHandler for LivePrograms {
            type Child = LiveChild;
            type Container = ();
            type Endpoint = ();
            type TcpListener = ();
            type TcpStream = ();
            type SerialPort = ();
            type VsockListener = ();
            type VsockStream = ();

            async fn child_stdin(
                &self,
                self_: &Self::Child,
                data: StreamReader<u8>,
            ) -> FutureReader<Result<(), ()>> {
                let (tx, rx) = helios_wit_rpc::future::<Result<(), ()>>();
                let received = Arc::clone(&self_.received_stdin);
                tokio::spawn(async move {
                    let bytes = data.collect_all().await.unwrap_or_default();
                    received.lock().expect("lock").extend_from_slice(&bytes);
                    let _ = tx.resolve(Ok(())).await;
                });
                rx
            }

            async fn child_stdout(
                &self,
                _self_: &Self::Child,
            ) -> (StreamReader<u8>, FutureReader<Result<(), ()>>) {
                (
                    StreamReader::from_vec(Vec::new()),
                    FutureReader::ready(Ok(())),
                )
            }

            async fn child_stderr(
                &self,
                _self_: &Self::Child,
            ) -> (StreamReader<u8>, FutureReader<Result<(), ()>>) {
                (
                    StreamReader::from_vec(Vec::new()),
                    FutureReader::ready(Ok(())),
                )
            }

            async fn child_instance_id(&self, _self_: &Self::Child) -> u64 {
                88
            }

            async fn child_signal(
                &self,
                _self_: &Self::Child,
                _signal: u8,
            ) -> Result<(), SpawnError> {
                Ok(())
            }

            async fn child_wait(&self, _self_: &Self::Child) -> Result<ExitStatus, SpawnError> {
                Ok(ExitStatus {
                    instance_id: 88,
                    termination: ChildTermination::Exited(0),
                })
            }

            async fn container_spawn(
                &self,
                _self_: &Self::Container,
                _request: ContainerSpawnRequest<
                    Self::TcpListener,
                    Self::VsockListener,
                    Self::TcpStream,
                    Self::VsockStream,
                    Self::SerialPort,
                >,
            ) -> Result<Self::Child, SpawnError> {
                unreachable!()
            }

            async fn container_exec(
                &self,
                _self_: &Self::Container,
                _request: ContainerExecRequest,
            ) -> Result<ExecResult, ExecError> {
                unreachable!()
            }

            async fn set_default_image(
                &self,
                image: Option<DefaultLinuxImage>,
            ) -> Result<(), SpawnError> {
                *self.default_image.lock().expect("lock") = image;
                Ok(())
            }

            async fn get_default_image(&self) -> Option<DefaultLinuxImage> {
                self.default_image.lock().expect("lock").clone()
            }

            async fn take_inherited_sockets(
                &self,
            ) -> Vec<
                InheritedSocket<
                    Self::TcpListener,
                    Self::VsockListener,
                    Self::TcpStream,
                    Self::VsockStream,
                    Self::SerialPort,
                >,
            > {
                Vec::new()
            }

            async fn create_container(
                &self,
                _config: ContainerConfig<Self::Endpoint>,
            ) -> Result<Self::Container, SpawnError> {
                Ok(())
            }

            async fn spawn(
                &self,
                _request: WireSpawnRequest<
                    Self::TcpListener,
                    Self::VsockListener,
                    Self::TcpStream,
                    Self::VsockStream,
                    Self::SerialPort,
                    Self::Endpoint,
                >,
            ) -> Result<Self::Child, SpawnError> {
                Ok(LiveChild {
                    received_stdin: Arc::clone(&self.received_stdin),
                })
            }

            async fn exec(
                &self,
                _request: ExecRequest<Self::Endpoint>,
            ) -> Result<ExecResult, ExecError> {
                Ok(ExecResult {
                    instance_id: 1,
                    exit_code: 0,
                    output: ExecOutput {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                    },
                    launch_nanos: 0,
                })
            }

            async fn aot(&self, _request: AotRequest) -> Result<AotResult, ExecError> {
                unreachable!()
            }
        }

        let default_image = Arc::new(Mutex::new(None));
        let received_stdin = Arc::new(Mutex::new(Vec::new()));
        let (host, guest) = UnixStream::pair().expect("pair");
        host.set_nonblocking(true).expect("host nb");
        guest.set_nonblocking(true).expect("guest nb");
        let host_r = host.try_clone().expect("clone");
        let guest_r = guest.try_clone().expect("clone");
        let conn = RpcConnection::from_split(
            Box::new(Async::new(host_r).expect("async")),
            Box::new(Async::new(host).expect("async")),
        );
        let session = Session::from_connection(
            Target::new("live-test", "serial:///tmp/live.sock").expect("target"),
            conn,
            SessionOptions::default(),
        );
        let ep = Endpoint::new(
            Async::new(guest_r).expect("async"),
            Async::new(guest).expect("async"),
            rpc_programs::RpcServer::new(LivePrograms {
                default_image: Arc::clone(&default_image),
                received_stdin: Arc::clone(&received_stdin),
            }),
        );
        let server_task = tokio::spawn(async move {
            let _ = ep.drive().await;
        });

        assert!(
            session
                .get_default_image()
                .await
                .expect("get none")
                .is_none()
        );
        session
            .set_default_image_path("/var/lib/alpine")
            .await
            .expect("set path");
        let fetched = session
            .get_default_image()
            .await
            .expect("get some")
            .expect("some");
        assert_eq!(fetched.root_path, "/var/lib/alpine");
        session.set_default_image(None).await.expect("clear");
        assert!(
            session
                .get_default_image()
                .await
                .expect("cleared")
                .is_none()
        );

        // Interactive live write_stdin with CJK bytes.
        let child = session
            .spawn(SpawnRequest::new("/bin/cat", Vec::new()))
            .await
            .expect("spawn");
        let payload = "你好世界 こんにちは 세계\n".as_bytes();
        child.write_stdin(payload).await.expect("write_stdin");
        child.close_stdin().await.expect("close_stdin");
        assert!(matches!(
            child.write_stdin(b"after-close").await,
            Err(OpsError::StdinClosed)
        ));
        let res = child.wait().await.expect("wait");
        assert_eq!(res.exit_code, 0);
        assert_eq!(received_stdin.lock().expect("lock").as_slice(), payload);

        server_task.abort();
    }

    #[tokio::test]
    async fn sampling_session_raii_drop_stops_sampling_non_blockingly() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        use helios_wit_rpc::Endpoint;
        use helios_wit_rpc::inspector::helios::system::filters::FilterError;
        use helios_wit_rpc::inspector::helios::system::profiling::{
            ControlError, Filter, FoldedSample, InstructionProfile, InstructionProfileError,
            InstructionSample, MetricFilter, MetricSample, RawProfileError, SampledCode,
        };

        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        struct FakeProfiling {
            dropped: Arc<AtomicBool>,
        }

        impl rpc_profiling::RpcHandler for FakeProfiling {
            type SamplingSession = DropFlag;

            async fn set_enabled(&self, _enabled: bool) -> Result<(), ControlError> {
                Ok(())
            }
            async fn clear(&self) -> Result<(), ControlError> {
                Ok(())
            }
            async fn folded(
                &self,
                _filter: Filter,
                _limit: u32,
            ) -> Result<Vec<FoldedSample>, FilterError> {
                Ok(Vec::new())
            }
            async fn metrics(
                &self,
                _filter: MetricFilter,
                _limit: u32,
            ) -> Result<Vec<MetricSample>, FilterError> {
                Ok(Vec::new())
            }
            async fn start_instruction_sampling(
                &self,
            ) -> Result<Self::SamplingSession, InstructionProfileError> {
                Ok(DropFlag(Arc::clone(&self.dropped)))
            }
            async fn instruction_samples(
                &self,
            ) -> Result<InstructionProfile, InstructionProfileError> {
                Ok(InstructionProfile {
                    period_nanos: 500_000,
                    kernel_image_base: 0xffff_8000_0000_0000,
                    samples: vec![InstructionSample {
                        code: SampledCode::Native(0xffff_8000_0000_1000),
                        count: 7,
                    }],
                    dropped: 0,
                })
            }
            async fn raw_profile_size(&self) -> Result<u64, RawProfileError> {
                Ok(0)
            }
            async fn raw_profile_read(
                &self,
                _offset: u64,
                _len: u32,
            ) -> Result<Vec<u8>, RawProfileError> {
                Ok(Vec::new())
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let (host, guest) = UnixStream::pair().expect("pair");
        host.set_nonblocking(true).expect("host nb");
        guest.set_nonblocking(true).expect("guest nb");
        let host_r = host.try_clone().expect("clone");
        let guest_r = guest.try_clone().expect("clone");
        let conn = RpcConnection::from_split(
            Box::new(Async::new(host_r).expect("async")),
            Box::new(Async::new(host).expect("async")),
        );
        let session = Session::from_connection(
            Target::new("prof-test", "serial:///tmp/prof.sock").expect("target"),
            conn,
            SessionOptions::default(),
        );
        let ep = Endpoint::new(
            Async::new(guest_r).expect("async"),
            Async::new(guest).expect("async"),
            rpc_profiling::RpcServer::new(FakeProfiling {
                dropped: Arc::clone(&dropped),
            }),
        );
        let server_task = tokio::spawn(async move {
            let _ = ep.drive().await;
        });

        let sampling = session
            .start_instruction_sampling()
            .await
            .expect("start sampling");
        assert!(sampling.is_active());
        let profile = sampling.stop_and_collect().await.expect("stop_and_collect");
        assert_eq!(profile.period_nanos, 500_000);
        assert_eq!(profile.samples.len(), 1);

        // Give the background multiplexer a brief slice to deliver `ResourceDrop`.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            dropped.load(Ordering::Acquire),
            "dropping SamplingSession must release remote sampling-session resource"
        );

        server_task.abort();
    }
}
