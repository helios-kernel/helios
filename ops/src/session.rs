//! Async-first [`Session`] handle for a single Helios node.

use std::future::Future;
use std::path::{Component, Path};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use helios_inspector_protocol::RpcError;
use helios_inspector_protocol::debugger::filesystem::{
    self as dbg_fs, DirectoryEntry, EntryKind, MountBtrfsRequest,
};
use helios_inspector_protocol::debugger::programs as dbg_programs;
use helios_inspector_protocol::debugger::snapshot::{self as dbg_snapshot, SnapshotReadiness};
use helios_inspector_protocol::system::{
    inspect::{self, KernelSnapshot, SnapshotResult},
    instances::{self, Instance},
    processors::{self, ProcessorSets},
    profiling::{
        self, Filter as ProfileFilter, FoldedSample, InstructionProfile, MetricFilter, MetricSample,
    },
    programs::{
        self, AuthorityScope, CapabilityGrant, ClockGrant, ClockRight, DeviceClass, DeviceGrant,
        DiagnosticsGrant, DirectoryGrant, ExecRequest, ExecResult, FilesystemRight, LinkGrant,
        LinkRight, MachineGrant, MachineRight, MountGrant, MountRight, NetworkGrant, NetworkRight,
        ProcessGrant, ProcessRight, SettingsGrant, SettingsRight, TerminalGrant, TerminalRight,
    },
    tracing as sys_tracing,
};

use crate::error::OpsError;
use crate::target::{
    Attenuation, GrantRight, IdentityProfile, Target, normalize_scope, scope_contains,
};
use crate::transport::{ProtocolClient, RpcConnection, SecurityMode};

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

/// Request parameters for [`Session::spawn`].
#[derive(Debug, Clone)]
pub struct SpawnRequest {
    pub path: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<String>,
    pub stdin: Vec<u8>,
    pub capability_grants: Vec<CapabilityGrant>,
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
pub fn parse_capability_grant(spec: &str) -> Result<CapabilityGrant, OpsError> {
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
) -> Result<CapabilityGrant, OpsError> {
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
        "machine" => {
            let tokens = if target.is_empty() || target.eq_ignore_ascii_case("all") {
                vec!["control", "identity"]
            } else {
                target.split(',').collect()
            };
            let mut rights = Vec::with_capacity(tokens.len());
            for tok in tokens {
                let r = match tok.trim().to_ascii_lowercase().as_str() {
                    "control" => MachineRight::Control,
                    "identity" => MachineRight::Identity,
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

/// Streaming handle to a remotely spawned program.
pub struct Child {
    session: Session,
    instance_id: Arc<AtomicU64>,
    pub stdout: async_channel::Receiver<Result<Vec<u8>, OpsError>>,
    pub stderr: async_channel::Receiver<Result<Vec<u8>, OpsError>>,
    completion: async_channel::Receiver<Result<ExecResult, OpsError>>,
}

impl Child {
    /// Live instance ID if reported by the guest.
    #[must_use]
    pub fn instance_id(&self) -> Option<u64> {
        let id = self.instance_id.load(Ordering::Acquire);
        (id != 0).then_some(id)
    }

    /// Deliver a termination/signal request to this child instance.
    pub async fn signal(&self, _signal: &str) -> Result<(), OpsError> {
        if let Some(id) = self.instance_id() {
            self.session.kill(id).await?;
        }
        Ok(())
    }

    /// Await completion of the remote execution and return its full [`ExecResult`].
    pub async fn wait(self) -> Result<ExecResult, OpsError> {
        self.completion
            .recv()
            .await
            .map_err(|_| OpsError::TimedOut {
                operation: "child completion",
            })?
    }
}

/// RAII handle holding the guest's VMM snapshot preparation state.
///
/// Call [`Self::release`] explicitly to await `snapshot_finished`; dropping an
/// unreleased hold triggers a best-effort async release on the active runtime.
pub struct SnapshotHold {
    connection: RpcConnection,
    readiness: SnapshotReadiness,
    released: AtomicBool,
}

impl SnapshotHold {
    /// Readiness flags reported by the guest when preparing for snapshot.
    #[must_use]
    pub const fn readiness(&self) -> SnapshotReadiness {
        self.readiness
    }

    /// End the snapshot hold on the guest so its host share re-attaches.
    pub async fn release(self) -> Result<(), OpsError> {
        self.released.store(true, Ordering::Release);
        dbg_snapshot::snapshot_finished(self.connection.client())
            .await
            .map_err(|source| OpsError::Rpc {
                operation: "debugger.snapshot.snapshot-finished",
                source,
            })
    }
}

impl Drop for SnapshotHold {
    fn drop(&mut self) {
        if !self.released.swap(true, Ordering::AcqRel) {
            let conn = self.connection.clone();
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    if let Err(err) = dbg_snapshot::snapshot_finished(conn.client()).await {
                        tracing::warn!("failed to release SnapshotHold on drop: {err}");
                    }
                });
            }
        }
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

    /// Borrow the underlying protocol RPC client.
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

    fn require_right(&self, right: GrantRight) -> Result<(), OpsError> {
        if self.options.attenuation.allows(right) {
            Ok(())
        } else {
            Err(OpsError::AttenuationDenied {
                capability: right.as_str().to_owned(),
                scope: self.options.attenuation.effective_scope().to_owned(),
            })
        }
    }

    async fn call<T>(
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
        let scoped_owned: Vec<String>;
        let effective_prefixes: Vec<&str> = if active_scope == "/" {
            prefixes.to_vec()
        } else if prefixes.is_empty() {
            vec![active_scope.as_str()]
        } else {
            scoped_owned = prefixes
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
                .collect::<Result<Vec<_>, _>>()?;
            scoped_owned.iter().map(String::as_str).collect()
        };

        let answer = self
            .call(
                "system.inspect.snapshot",
                inspect::snapshot_prefixes(self.connection.client(), &effective_prefixes, limit),
            )
            .await?;
        let mut snapshot = answer.map_err(|source| OpsError::FilterRefused {
            operation: "system.inspect.snapshot",
            source,
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
        let mut live = self
            .call(
                "system.instances.snapshot",
                instances::snapshot(self.connection.client()),
            )
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
        let answer = self
            .call(
                "system.instances.kill",
                instances::kill(self.connection.client(), id),
            )
            .await?;
        answer.map_err(|source| OpsError::KillRefused { id, source })
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

    /// Fetch recent guest tracing events matching `filter`.
    pub async fn trace_recent(
        &self,
        filter: &sys_tracing::Filter,
        limit: u32,
    ) -> Result<Vec<sys_tracing::Event>, OpsError> {
        self.require_right(GrantRight::Trace)?;
        let answer = self
            .call(
                "system.tracing.recent",
                sys_tracing::recent(self.connection.client(), filter, limit),
            )
            .await?;
        answer.map_err(|source| OpsError::FilterRefused {
            operation: "system.tracing.recent",
            source,
        })
    }

    /// Enable or disable a named kernel diagnostic tracing target.
    pub async fn set_trace_target_enabled(
        &self,
        target: &str,
        enabled: bool,
    ) -> Result<(), OpsError> {
        self.require_right(GrantRight::Trace)?;
        let answer = self
            .call(
                "system.tracing.set-target-enabled",
                sys_tracing::set_target_enabled(self.connection.client(), target, enabled),
            )
            .await?;
        answer.map_err(|source| OpsError::TraceTargetRefused {
            target: target.to_owned(),
            source,
        })
    }

    /// Toggle guest profiling collection.
    pub async fn profile_set_enabled(&self, enabled: bool) -> Result<(), OpsError> {
        self.require_right(GrantRight::Profile)?;
        let answer = self
            .call(
                "system.profiling.set-enabled",
                profiling::set_enabled(self.connection.client(), enabled),
            )
            .await?;
        answer.map_err(|source| OpsError::ProfilingControlRefused {
            operation: "set-enabled",
            source,
        })
    }

    /// Clear collected guest profile samples.
    pub async fn profile_clear(&self) -> Result<(), OpsError> {
        self.require_right(GrantRight::Profile)?;
        let answer = self
            .call(
                "system.profiling.clear",
                profiling::clear(self.connection.client()),
            )
            .await?;
        answer.map_err(|source| OpsError::ProfilingControlRefused {
            operation: "clear",
            source,
        })
    }

    /// Fetch folded stack samples matching `filter`.
    pub async fn profile_folded(
        &self,
        filter: &ProfileFilter,
        limit: u32,
    ) -> Result<Vec<FoldedSample>, OpsError> {
        self.require_right(GrantRight::Profile)?;
        let answer = self
            .call(
                "system.profiling.folded",
                profiling::folded(self.connection.client(), filter, limit),
            )
            .await?;
        answer.map_err(|source| OpsError::FilterRefused {
            operation: "system.profiling.folded",
            source,
        })
    }

    /// Fetch metric samples matching `filter`.
    pub async fn profile_metrics(
        &self,
        filter: &MetricFilter,
        limit: u32,
    ) -> Result<Vec<MetricSample>, OpsError> {
        self.require_right(GrantRight::Profile)?;
        let answer = self
            .call(
                "system.profiling.metrics",
                profiling::metrics(self.connection.client(), filter, limit),
            )
            .await?;
        answer.map_err(|source| OpsError::FilterRefused {
            operation: "system.profiling.metrics",
            source,
        })
    }

    /// Start or stop kernel instruction sampling.
    pub async fn profile_set_instruction_sampling(&self, enabled: bool) -> Result<(), OpsError> {
        self.require_right(GrantRight::Profile)?;
        let answer = self
            .call(
                "system.profiling.set-instruction-sampling",
                profiling::set_instruction_sampling(self.connection.client(), enabled),
            )
            .await?;
        answer.map_err(|source| OpsError::InstructionProfileRefused {
            operation: "set-instruction-sampling",
            source,
        })
    }

    /// Retrieve collected kernel instruction samples.
    pub async fn profile_instruction_samples(&self) -> Result<InstructionProfile, OpsError> {
        self.require_right(GrantRight::Profile)?;
        let answer = self
            .call(
                "system.profiling.instruction-samples",
                profiling::instruction_samples(self.connection.client()),
            )
            .await?;
        answer.map_err(|source| OpsError::InstructionProfileRefused {
            operation: "instruction-samples",
            source,
        })
    }

    /// Read the complete LLVM raw profile buffer from an instrumented kernel.
    pub async fn profile_raw_collect(&self) -> Result<Vec<u8>, OpsError> {
        self.require_right(GrantRight::Profile)?;
        let total_size = self
            .call(
                "system.profiling.raw-profile-size",
                profiling::raw_profile_size(self.connection.client()),
            )
            .await?
            .map_err(|source| OpsError::RawProfileRefused {
                operation: "raw-profile-size",
                source,
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
                    profiling::raw_profile_read(self.connection.client(), offset, len),
                )
                .await?
                .map_err(|source| OpsError::RawProfileRefused {
                    operation: "raw-profile-read",
                    source,
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
        self.call(
            "system.processors.sets",
            processors::sets(self.connection.client()),
        )
        .await
    }

    /// Take processor `id` offline.
    pub async fn processor_offline(&self, id: u32) -> Result<(), OpsError> {
        self.require_right(GrantRight::Processors)?;
        let answer = self
            .call(
                "system.processors.offline",
                processors::offline(self.connection.client(), id),
            )
            .await?;
        answer.map_err(|source| OpsError::ProcessorOfflineRefused {
            processor: id,
            source,
        })
    }

    /// Bring processor `id` online.
    pub async fn processor_online(&self, id: u32) -> Result<(), OpsError> {
        self.require_right(GrantRight::Processors)?;
        let answer = self
            .call(
                "system.processors.online",
                processors::online(self.connection.client(), id),
            )
            .await?;
        answer.map_err(|source| OpsError::ProcessorOnlineRefused {
            processor: id,
            source,
        })
    }

    /// Execute a program by path via `debugger.programs.exec-path`.
    pub async fn exec(&self, path: &str, args: &[String]) -> Result<ExecResult, OpsError> {
        self.require_right(GrantRight::Exec)?;
        let normalized = normalize_absolute_path(path)?;
        let answer = self
            .call(
                "debugger.programs.exec-path",
                dbg_programs::exec_path(self.connection.client(), &normalized, args),
            )
            .await?;
        answer.map_err(OpsError::from)
    }

    /// Execute a full [`ExecRequest`] via `helios:system/programs.exec`.
    pub async fn exec_request(&self, request: &ExecRequest) -> Result<ExecResult, OpsError> {
        self.require_right(GrantRight::Exec)?;
        let answer = self
            .call(
                "system.programs.exec",
                programs::exec(self.connection.client(), request),
            )
            .await?;
        answer.map_err(OpsError::from)
    }

    /// Construct a fluent [`crate::Command`] bound for execution on this session.
    #[must_use]
    pub fn command(&self, path: impl Into<String>) -> crate::grants::Command {
        crate::grants::Command::new(path)
    }

    /// Execute a Linux binary inside a container via `debugger.programs.exec-in-container`.
    pub async fn exec_in_container(
        &self,
        request: &dbg_programs::ExecInContainerRequest,
    ) -> Result<ExecResult, OpsError> {
        self.require_right(GrantRight::Exec)?;
        let answer = self
            .call(
                "debugger.programs.exec-in-container",
                dbg_programs::exec_in_container(self.connection.client(), request),
            )
            .await?;
        answer.map_err(OpsError::from)
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

    /// Spawn a remote program and expose async stdout, stderr, signal, and wait handles.
    pub async fn spawn(&self, request: SpawnRequest) -> Result<Child, OpsError> {
        self.require_right(GrantRight::Exec)?;
        let path = normalize_absolute_path(&request.path)?;
        let (stdout_tx, stdout_rx) = async_channel::bounded(16);
        let (stderr_tx, stderr_rx) = async_channel::bounded(16);
        let (done_tx, done_rx) = async_channel::bounded(1);
        let instance_id = Arc::new(AtomicU64::new(0));

        let session = self.clone();
        let instance_slot = Arc::clone(&instance_id);
        tokio::spawn(async move {
            let outcome = if request.env.is_empty()
                && request.cwd.is_none()
                && request.stdin.is_empty()
                && request.capability_grants.is_empty()
            {
                session.exec(&path, &request.args).await
            } else {
                let req = ExecRequest {
                    name: path.clone(),
                    args: request.args,
                    env: request.env,
                    path: path.clone(),
                    cwd: request.cwd,
                    stdin: request.stdin,
                    hint: None,
                    capability_grants: request.capability_grants,
                };
                session.exec_request(&req).await
            };

            match outcome {
                Ok(res) => {
                    instance_slot.store(res.instance_id, Ordering::Release);
                    if !res.output.stdout.is_empty() {
                        let _ = stdout_tx.send(Ok(res.output.stdout.clone())).await;
                    }
                    if !res.output.stderr.is_empty() {
                        let _ = stderr_tx.send(Ok(res.output.stderr.clone())).await;
                    }
                    let _ = done_tx.send(Ok(res)).await;
                }
                Err(err) => {
                    let _ = done_tx.send(Err(err)).await;
                }
            }
        });

        Ok(Child {
            session: self.clone(),
            instance_id,
            stdout: stdout_rx,
            stderr: stderr_rx,
            completion: done_rx,
        })
    }

    /// Prepare the guest for a VMM snapshot and return an RAII [`SnapshotHold`].
    pub async fn snapshot_hold(&self) -> Result<SnapshotHold, OpsError> {
        self.require_right(GrantRight::Snapshot)?;
        let readiness = self
            .call(
                "debugger.snapshot.prepare-snapshot",
                dbg_snapshot::prepare_snapshot(self.connection.client()),
            )
            .await?;
        Ok(SnapshotHold {
            connection: self.connection.clone(),
            readiness,
            released: AtomicBool::new(false),
        })
    }

    /// List directory entries on the remote VFS.
    pub async fn list_dir(&self, path: &str) -> Result<Vec<RemoteEntry>, OpsError> {
        self.require_right(GrantRight::FilesystemRead)?;
        let dir = normalize_absolute_path(path)?;
        let raw: Vec<DirectoryEntry> = self
            .call(
                "debugger.filesystem.list",
                dbg_fs::list(self.connection.client(), &dir),
            )
            .await?;
        Ok(raw
            .into_iter()
            .filter(|entry| entry.name != "." && entry.name != "..")
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

    /// Stat a single path on the remote VFS.
    pub async fn stat(&self, path: &str) -> Result<RemoteStat, OpsError> {
        self.require_right(GrantRight::FilesystemRead)?;
        let normalized = normalize_absolute_path(path)?;
        if normalized == "/" {
            return Ok(RemoteStat {
                path: "/".to_owned(),
                name: "/".to_owned(),
                kind: EntryKind::Directory,
                size: 0,
            });
        }
        let parent = Path::new(&normalized)
            .parent()
            .and_then(Path::to_str)
            .unwrap_or("/");
        let name = Path::new(&normalized)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&normalized);
        let entries = self.list_dir(parent).await?;
        let Some(found) = entries.into_iter().find(|e| e.name == name) else {
            return Err(OpsError::NotFound { path: normalized });
        };
        let size = if found.kind == EntryKind::File {
            self.read_file(&normalized)
                .await
                .map_or(0, |b| b.len() as u64)
        } else {
            0
        };
        Ok(RemoteStat {
            path: normalized,
            name: found.name,
            kind: found.kind,
            size,
        })
    }

    /// Read a file from the remote VFS.
    pub async fn read_file(&self, path: &str) -> Result<Vec<u8>, OpsError> {
        self.require_right(GrantRight::FilesystemRead)?;
        let normalized = normalize_absolute_path(path)?;
        self.call(
            "debugger.filesystem.read",
            dbg_fs::read(self.connection.client(), &normalized),
        )
        .await
    }

    /// Write or append bytes to a file on the remote VFS.
    pub async fn write_file(&self, path: &str, data: &[u8], append: bool) -> Result<(), OpsError> {
        self.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(path)?;
        self.call(
            "debugger.filesystem.write",
            dbg_fs::write(self.connection.client(), &normalized, data, append),
        )
        .await
    }

    /// Create a directory on the remote VFS.
    pub async fn mkdir(&self, path: &str) -> Result<(), OpsError> {
        self.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(path)?;
        self.call(
            "debugger.filesystem.create-directory",
            dbg_fs::mkdir(self.connection.client(), &normalized),
        )
        .await
    }

    /// Remove a file or directory on the remote VFS.
    pub async fn remove(&self, path: &str) -> Result<(), OpsError> {
        self.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(path)?;
        self.call(
            "debugger.filesystem.remove",
            dbg_fs::remove(self.connection.client(), &normalized),
        )
        .await
    }

    /// Copy a file on the remote VFS.
    pub async fn copy(&self, source: &str, destination: &str) -> Result<(), OpsError> {
        self.require_right(GrantRight::FilesystemWrite)?;
        let src = normalize_absolute_path(source)?;
        let dst = normalize_absolute_path(destination)?;
        self.call(
            "debugger.filesystem.copy",
            dbg_fs::copy(self.connection.client(), &src, &dst),
        )
        .await
    }

    /// Rename / move a file or directory on the remote VFS.
    pub async fn rename(&self, source: &str, destination: &str) -> Result<(), OpsError> {
        self.require_right(GrantRight::FilesystemWrite)?;
        let src = normalize_absolute_path(source)?;
        let dst = normalize_absolute_path(destination)?;
        self.call(
            "debugger.filesystem.move",
            dbg_fs::move_path(self.connection.client(), &src, &dst),
        )
        .await
    }

    /// Touch a file on the remote VFS.
    pub async fn touch(&self, path: &str) -> Result<(), OpsError> {
        self.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(path)?;
        self.call(
            "debugger.filesystem.touch",
            dbg_fs::touch(self.connection.client(), &normalized),
        )
        .await
    }

    /// Mount a btrfs volume on the remote guest.
    pub async fn mount_btrfs(&self, request: &MountBtrfsRequest) -> Result<(), OpsError> {
        self.require_right(GrantRight::FilesystemWrite)?;
        self.call(
            "debugger.filesystem.mount-btrfs",
            dbg_fs::mount_btrfs(self.connection.client(), request),
        )
        .await
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
    async fn helios_tls_uri_fails_fast_instead_of_downgrading_to_cleartext() {
        let uri = TargetUri::parse("helios://127.0.0.1:9443").expect("parse helios uri");
        let err = RpcConnection::connect(&uri, &SecurityMode::Plain)
            .await
            .err()
            .expect("helios:// must fail fast until #1190 TLS lands");
        assert!(matches!(
            err,
            crate::error::TransportError::TlsNotYetImplemented { .. }
        ));
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
    }
}
