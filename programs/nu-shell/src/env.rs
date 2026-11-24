//! Guest [`HeliosEnv`] implementation backed directly by async-first `helios-api`.

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::collections::BTreeMap;
use std::sync::Mutex;

use chrono::{DateTime, FixedOffset, TimeZone};
use futures_lite::future::zip;
use helios_api::bindings::wasi::cli::terminal_stdout;
use helios_api::bindings::wasi::clocks::{monotonic_clock, system_clock};
use helios_api::bindings::wasi::filesystem::preopens;
use helios_api::bindings::wasi::filesystem::types::{
    Descriptor, DescriptorFlags, DescriptorStat, DescriptorType, ErrorCode, NewTimestamp,
    OpenFlags, PathFlags,
};
use helios_api::bindings::wit_stream;
use helios_api::inspect::{self, Query as InspectQuery, Value as RawInspectValue};
use helios_api::instances::{self, KillError};
use helios_api::io as helios_io;
use helios_api::processors;
use helios_api::profiling::{self, InstructionProfileError, SamplingSession};
use helios_api::programs::{
    AuthorityScope, CapabilityGrant, Child, ChildTermination, ClockRight, DeviceClass,
    DiagnosticsGrant, FilesystemRight, LinkRight, MachineRight, MountRight, NetworkRight,
    ProcessRight, SettingsRight, SpawnError, SpawnErrorKind, SpawnRequest, TerminalRight,
    all_device_classes_grant, clock_grant, device_grant, diagnostics_control_grant,
    diagnostics_grant, directory_grant, inspect_read_grant, instance_control_grant, link_grant,
    machine_control_grant, machine_grant, mount_grant, network_grant, process_grant,
    profile_read_grant, root_link_grant, root_mount_grant, root_process_grant, root_terminal_grant,
    settings_grant, terminal_grant, trace_read_grant, write_settings_grant,
};
use helios_api::snapshot::{self, SnapshotError, SnapshotHold};
use helios_api::task;
use helios_nu::{
    EnvError, ExecutableMatch, ExternalProcess, ExternalSpawnRequest, FileMetadata, FileType,
    GrantSpec, HeliosEnv, InspectEntry, InspectValue, InstructionProfileSummary, ProcessInfo,
    STREAM_CHANNEL_CAPACITY, SnapshotInfo, SysCpuInfo, SysDiskInfo, SysHostInfo, SysMemInfo,
    SysNetInfo, WatchEvent, normalize_vfs_path,
};

const STREAM_READ_CHUNK: usize = 16 * 1024;

struct ActiveProfile {
    target: String,
    started_nanos: u64,
    _session: SamplingSession,
}

/// Fixed detail string returned by the kernel's `map_process_authority_error`
/// (`ProgramExecErrorDetail::ProcessAuthorityDenied`) when any requested child
/// grant exceeds the caller's held authority.
const PROCESS_AUTHORITY_DENIED_DETAIL: &str = "process authority rejected the requested grant";

/// Monotonic tier of default child grants inherited when a spawn does not
/// specify explicit `with-grants`.
///
/// The kernel reports every rejected capability grant with the single fixed
/// message [`PROCESS_AUTHORITY_DENIED_DETAIL`], so narrowing steps down a
/// deterministic sequence of tiers until the child spawn succeeds or reaches
/// directory-only grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DefaultGrantTier {
    /// Full launcher bundle (machine inspect/trace/profile/diagnostics,
    /// instance/machine control, settings, devices, mount, network, terminal,
    /// link, process, and preopen directories with `Execute`).
    MachineFull,
    /// Machine read-only inspect, optional terminal, link, process, and
    /// preopen directories with `Execute`.
    InspectTerminalExec,
    /// Optional terminal, link, process, and preopen directories with `Execute`.
    TerminalExec,
    /// Link, process, and preopen directories with `Execute`.
    ProcessExec,
    /// Preopen directories with `Execute` only (no non-directory grants).
    DirectoryExec,
    /// Preopen directories with only the `Read`/`Write`/`MutateDirectory`
    /// flags reported by `Descriptor::get_flags()` (no `Execute`, no
    /// non-directory grants).
    DirectoryOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DefaultGrantPolicy {
    tier: DefaultGrantTier,
    has_terminal: bool,
}

impl DefaultGrantPolicy {
    fn initial(has_machine_inspect: bool, has_terminal: bool) -> Self {
        let tier = if has_machine_inspect {
            DefaultGrantTier::MachineFull
        } else if has_terminal {
            DefaultGrantTier::TerminalExec
        } else {
            DefaultGrantTier::ProcessExec
        };
        Self { tier, has_terminal }
    }

    fn include_dir_execute(self) -> bool {
        !matches!(self.tier, DefaultGrantTier::DirectoryOnly)
    }

    fn append_non_directory_grants(self, grants: &mut Vec<CapabilityGrant>) {
        match self.tier {
            DefaultGrantTier::MachineFull => {
                grants.push(root_link_grant());
                grants.push(root_process_grant());
                grants.push(network_grant(vec![
                    NetworkRight::Tcp,
                    NetworkRight::Udp,
                    NetworkRight::Dns,
                    NetworkRight::PrivilegedBind,
                    NetworkRight::Multicast,
                    NetworkRight::Admin,
                ]));
                grants.push(root_terminal_grant());
                grants.push(root_mount_grant());
                grants.push(all_device_classes_grant());
                grants.push(inspect_read_grant(AuthorityScope::Machine));
                grants.push(trace_read_grant(AuthorityScope::Machine));
                grants.push(profile_read_grant(AuthorityScope::Machine));
                grants.push(diagnostics_control_grant());
                grants.push(instance_control_grant(AuthorityScope::Machine));
                grants.push(write_settings_grant());
                grants.push(machine_control_grant());
            }
            DefaultGrantTier::InspectTerminalExec => {
                grants.push(root_link_grant());
                grants.push(root_process_grant());
                grants.push(inspect_read_grant(AuthorityScope::Machine));
                if self.has_terminal {
                    grants.push(root_terminal_grant());
                }
            }
            DefaultGrantTier::TerminalExec => {
                grants.push(root_link_grant());
                grants.push(root_process_grant());
                if self.has_terminal {
                    grants.push(root_terminal_grant());
                }
            }
            DefaultGrantTier::ProcessExec => {
                grants.push(root_link_grant());
                grants.push(root_process_grant());
            }
            DefaultGrantTier::DirectoryExec | DefaultGrantTier::DirectoryOnly => {}
        }
    }

    /// Step down one tier when the kernel reports
    /// [`PROCESS_AUTHORITY_DENIED_DETAIL`].
    ///
    /// Returns `true` if the policy narrowed to a lower tier so the caller can
    /// retry, or `false` if the refusal was unrelated (such as
    /// `ProgramSourceNotGranted`) or the policy is already at its minimum tier.
    fn narrow_for_refusal(&mut self, detail: &str) -> bool {
        if detail != PROCESS_AUTHORITY_DENIED_DETAIL {
            return false;
        }
        let next = match self.tier {
            DefaultGrantTier::MachineFull => DefaultGrantTier::InspectTerminalExec,
            DefaultGrantTier::InspectTerminalExec => {
                if self.has_terminal {
                    DefaultGrantTier::TerminalExec
                } else {
                    DefaultGrantTier::ProcessExec
                }
            }
            DefaultGrantTier::TerminalExec => DefaultGrantTier::ProcessExec,
            DefaultGrantTier::ProcessExec => DefaultGrantTier::DirectoryExec,
            DefaultGrantTier::DirectoryExec => DefaultGrantTier::DirectoryOnly,
            DefaultGrantTier::DirectoryOnly => return false,
        };
        self.tier = next;
        true
    }
}

/// Guest implementation of [`HeliosEnv`] over `helios-api` and WASI Preview 3.
pub struct GuestHeliosEnv {
    cwd: Mutex<String>,
    scopes: Mutex<Vec<String>>,
    snapshots: Mutex<BTreeMap<String, SnapshotHold>>,
    profiles: Mutex<BTreeMap<String, ActiveProfile>>,
    default_grants: Mutex<DefaultGrantPolicy>,
    next_id: AtomicU64,
}

impl GuestHeliosEnv {
    /// Construct a guest environment anchored at `initial_cwd`.
    pub fn new(initial_cwd: String) -> Self {
        let initial_cwd = normalize_vfs_path("/", &initial_cwd);
        // Probe once via read-only `inspect.snapshot` whether this shell holds
        // machine-level inspect authority; unheld grants in the default tier
        // step down deterministically on the first authority refusal.
        let has_machine_inspect = inspect::snapshot(
            &InspectQuery {
                prefixes: vec![String::from("/kernel/")],
            },
            1,
        )
        .is_ok_and(|snap| !snap.entries.is_empty());
        let has_terminal = terminal_stdout::get_terminal_stdout().is_some();

        Self {
            cwd: Mutex::new(initial_cwd),
            scopes: Mutex::new(Vec::new()),
            snapshots: Mutex::new(BTreeMap::new()),
            profiles: Mutex::new(BTreeMap::new()),
            default_grants: Mutex::new(DefaultGrantPolicy::initial(
                has_machine_inspect,
                has_terminal,
            )),
            next_id: AtomicU64::new(1),
        }
    }

    fn current_cwd(&self) -> String {
        self.cwd.lock().expect("guest cwd lock poisoned").clone()
    }

    async fn default_child_grants(&self) -> Vec<CapabilityGrant> {
        let policy = *self
            .default_grants
            .lock()
            .expect("guest default grants lock poisoned");
        let mut grants = preopen_directory_grants(policy.include_dir_execute()).await;
        policy.append_non_directory_grants(&mut grants);
        grants
    }

    fn translate_explicit_grants(
        &self,
        specs: &[GrantSpec],
    ) -> Result<Vec<CapabilityGrant>, EnvError> {
        let mut grants = Vec::new();

        for spec in specs {
            match spec.kind.as_str() {
                "dir" | "fs" => {
                    let target = if spec.target.is_empty() {
                        String::from("/")
                    } else {
                        normalize_vfs_path(&self.current_cwd(), &spec.target)
                    };
                    let rights = match spec.mode.as_deref() {
                        Some("ro" | "r") => vec![FilesystemRight::Read],
                        Some("rx") => vec![FilesystemRight::Read, FilesystemRight::Execute],
                        Some("rw" | "w") => vec![
                            FilesystemRight::Read,
                            FilesystemRight::Write,
                            FilesystemRight::MutateDirectory,
                        ],
                        Some("rwx") | None => vec![
                            FilesystemRight::Read,
                            FilesystemRight::Write,
                            FilesystemRight::MutateDirectory,
                            FilesystemRight::Execute,
                        ],
                        Some(other) => {
                            return Err(EnvError::InvalidArgument {
                                detail: format!("unknown directory grant mode `{other}`"),
                            });
                        }
                    };
                    grants.push(directory_grant(target.clone(), target, rights));
                }
                "net" | "network" => {
                    let rights = match spec
                        .mode
                        .as_deref()
                        .or((!spec.target.is_empty()).then_some(spec.target.as_str()))
                    {
                        Some("tcp") => vec![NetworkRight::Tcp],
                        Some("udp") => vec![NetworkRight::Udp],
                        Some("dns") => vec![NetworkRight::Dns],
                        _ => vec![
                            NetworkRight::Tcp,
                            NetworkRight::Udp,
                            NetworkRight::Dns,
                            NetworkRight::PrivilegedBind,
                            NetworkRight::Multicast,
                            NetworkRight::Admin,
                        ],
                    };
                    grants.push(network_grant(rights));
                }
                "clock" => grants.push(clock_grant(vec![ClockRight::SetWallClock])),
                "terminal" | "tty" => grants.push(terminal_grant(vec![
                    TerminalRight::Input,
                    TerminalRight::Output,
                    TerminalRight::Control,
                ])),
                "process" | "proc" => grants.push(process_grant(vec![
                    ProcessRight::Spawn,
                    ProcessRight::Exec,
                    ProcessRight::Fork,
                    ProcessRight::Join,
                    ProcessRight::Signal,
                ])),
                "link" => grants.push(link_grant(vec![
                    LinkRight::Source,
                    LinkRight::TargetDirectory,
                    LinkRight::SymlinkCreate,
                    LinkRight::SymlinkRead,
                ])),
                "mount" => grants.push(mount_grant(vec![MountRight::Mount, MountRight::Unmount])),
                "device" => {
                    let classes = match spec.target.as_str() {
                        "display" => vec![DeviceClass::Display],
                        "input" => vec![DeviceClass::Input],
                        "gpu" => vec![DeviceClass::Gpu],
                        "audio" => vec![DeviceClass::Audio],
                        "" | "all" => vec![
                            DeviceClass::Display,
                            DeviceClass::Input,
                            DeviceClass::Gpu,
                            DeviceClass::Audio,
                        ],
                        other => {
                            return Err(EnvError::InvalidArgument {
                                detail: format!("unknown device class `{other}`"),
                            });
                        }
                    };
                    grants.push(device_grant(classes));
                }
                "inspect" => {
                    grants.push(diagnostics_grant(DiagnosticsGrant::InspectRead(
                        parse_scope(&spec.target)?,
                    )));
                }
                "trace" => {
                    grants.push(diagnostics_grant(DiagnosticsGrant::TraceRead(parse_scope(
                        &spec.target,
                    )?)));
                }
                "profile" => {
                    grants.push(diagnostics_grant(DiagnosticsGrant::ProfileRead(
                        parse_scope(&spec.target)?,
                    )));
                }
                "diagnostics" => grants.push(diagnostics_control_grant()),
                "instance-control" => {
                    grants.push(instance_control_grant(parse_scope(&spec.target)?));
                }
                "settings" => grants.push(settings_grant(vec![SettingsRight::Write])),
                "machine" => {
                    let rights = match spec.target.as_str() {
                        "identity" => vec![MachineRight::Identity],
                        "all" => vec![MachineRight::Control, MachineRight::Identity],
                        "" | "control" => vec![MachineRight::Control],
                        other => {
                            return Err(EnvError::InvalidArgument {
                                detail: format!("unknown machine right `{other}`"),
                            });
                        }
                    };
                    grants.push(machine_grant(rights));
                }
                other => {
                    return Err(EnvError::InvalidArgument {
                        detail: format!("unsupported grant kind `{other}`"),
                    });
                }
            }
        }

        Ok(grants)
    }
}

impl HeliosEnv for GuestHeliosEnv {
    async fn cwd(&self) -> Result<String, EnvError> {
        Ok(self.current_cwd())
    }

    async fn set_cwd(&self, path: &str) -> Result<String, EnvError> {
        let normalized = normalize_vfs_path(&self.current_cwd(), path);
        let meta = self.stat(&normalized).await?;
        if meta.file_type != FileType::Dir {
            return Err(EnvError::NotADirectory { path: normalized });
        }
        *self.cwd.lock().expect("guest cwd lock poisoned") = normalized.clone();
        Ok(normalized)
    }

    async fn spawn_external(
        &self,
        request: ExternalSpawnRequest,
    ) -> Result<ExternalProcess, EnvError> {
        let path_env: Vec<String> = request
            .env
            .get("PATH")
            .map(|raw| {
                raw.split(':')
                    .filter(|s| !s.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .filter(|v: &Vec<String>| !v.is_empty())
            .unwrap_or_else(|| vec![String::from("/bin")]);

        let resolved_path = match self.resolve_executable(&request.program, &path_env).await? {
            Some(found) => found.path,
            None => {
                return Err(EnvError::NotFound {
                    path: request.program,
                });
            }
        };

        let mut env_pairs: Vec<(String, String)> = request.env.into_iter().collect();
        if !env_pairs.iter().any(|(k, _)| k == "PWD") {
            env_pairs.push((String::from("PWD"), request.cwd));
        }

        let child = if request.grants.is_empty() {
            loop {
                let capability_grants = self.default_child_grants().await;
                match Child::spawn(SpawnRequest {
                    name: request.program.clone(),
                    args: request.args.clone(),
                    env: env_pairs.clone(),
                    path: resolved_path.clone(),
                    capability_grants,
                })
                .await
                {
                    Ok(child) => break child,
                    Err(err)
                        if err.kind == SpawnErrorKind::PermissionDenied
                            && self
                                .default_grants
                                .lock()
                                .expect("guest default grants lock poisoned")
                                .narrow_for_refusal(&err.detail) => {}
                    Err(err) => return Err(map_spawn_error(err)),
                }
            }
        } else {
            let capability_grants = self.translate_explicit_grants(&request.grants)?;
            Child::spawn(SpawnRequest {
                name: request.program,
                args: request.args,
                env: env_pairs,
                path: resolved_path,
                capability_grants,
            })
            .await
            .map_err(map_spawn_error)?
        };

        if let Some(stdin_rx) = request.stdin {
            let (mut tx, rx) = wit_stream::new::<u8>();
            let stdin_done = child.pipe_stdin(rx);
            task::spawn(async move {
                while let Ok(chunk) = stdin_rx.recv().await {
                    match chunk {
                        Ok(bytes) if !bytes.is_empty() => {
                            if !tx.write_all(bytes).await.is_empty() {
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                drop(tx);
                let _ = core::future::IntoFuture::into_future(stdin_done).await;
            });
        }

        let (stdout_rx, out_inherited_done) = if request.capture_stdout {
            let (out_tx, out_rx) = async_channel::bounded(STREAM_CHANNEL_CAPACITY);
            let (mut stream, done) = child.stdout();
            task::spawn(async move {
                loop {
                    let (status, chunk) = stream.read(Vec::with_capacity(STREAM_READ_CHUNK)).await;
                    if !chunk.is_empty() && out_tx.send(Ok(chunk)).await.is_err() {
                        break;
                    }
                    if helios_api::stream_closed(status) {
                        break;
                    }
                }
                let _ = core::future::IntoFuture::into_future(done).await;
            });
            (Some(out_rx), None)
        } else {
            let (done_tx, done_rx) = async_channel::bounded(1);
            let (mut stream, done) = child.stdout();
            task::spawn(async move {
                let stdout = helios_io::stdout();
                loop {
                    let (status, chunk) = stream.read(Vec::with_capacity(STREAM_READ_CHUNK)).await;
                    if !chunk.is_empty() {
                        let _ = stdout.write_all(&chunk).await;
                    }
                    if helios_api::stream_closed(status) {
                        break;
                    }
                }
                let _ = core::future::IntoFuture::into_future(done).await;
                let _ = done_tx.send(()).await;
            });
            (None, Some(done_rx))
        };

        let (stderr_rx, err_inherited_done) = if request.capture_stderr {
            let (err_tx, err_rx) = async_channel::bounded(STREAM_CHANNEL_CAPACITY);
            let (mut stream, done) = child.stderr();
            task::spawn(async move {
                loop {
                    let (status, chunk) = stream.read(Vec::with_capacity(STREAM_READ_CHUNK)).await;
                    if !chunk.is_empty() && err_tx.send(Ok(chunk)).await.is_err() {
                        break;
                    }
                    if helios_api::stream_closed(status) {
                        break;
                    }
                }
                let _ = core::future::IntoFuture::into_future(done).await;
            });
            (Some(err_rx), None)
        } else {
            let (done_tx, done_rx) = async_channel::bounded(1);
            let (mut stream, done) = child.stderr();
            task::spawn(async move {
                let stderr = helios_io::stderr();
                loop {
                    let (status, chunk) = stream.read(Vec::with_capacity(STREAM_READ_CHUNK)).await;
                    if !chunk.is_empty() {
                        let _ = stderr.write_all(&chunk).await;
                    }
                    if helios_api::stream_closed(status) {
                        break;
                    }
                }
                let _ = core::future::IntoFuture::into_future(done).await;
                let _ = done_tx.send(()).await;
            });
            (None, Some(done_rx))
        };

        let (code_tx, code_rx) = async_channel::bounded(1);
        task::spawn(async move {
            let wait_res = child.wait().await;
            if let Some(rx) = out_inherited_done {
                let _ = rx.recv().await;
            }
            if let Some(rx) = err_inherited_done {
                let _ = rx.recv().await;
            }
            let outcome = match wait_res {
                Ok(status) => Ok(match status.termination {
                    ChildTermination::Exited(code) => i32::try_from(code).unwrap_or(1),
                    ChildTermination::Signaled(sig) => 128 + i32::from(sig.signal),
                    ChildTermination::Trapped => 134,
                    ChildTermination::Killed => 137,
                }),
                Err(err) => Err(map_spawn_error(err)),
            };
            let _ = code_tx.send(outcome).await;
        });

        Ok(ExternalProcess {
            stdout: stdout_rx,
            stderr: stderr_rx,
            exit_code: code_rx,
        })
    }

    async fn resolve_executable(
        &self,
        name: &str,
        path_env: &[String],
    ) -> Result<Option<ExecutableMatch>, EnvError> {
        if name.is_empty() {
            return Ok(None);
        }
        if name.contains('/') {
            let candidate = normalize_vfs_path(&self.current_cwd(), name);
            if self
                .stat(&candidate)
                .await
                .is_ok_and(|meta| meta.file_type == FileType::File)
            {
                return Ok(Some(ExecutableMatch {
                    command: name.to_owned(),
                    path: candidate,
                }));
            }
            return Ok(None);
        }

        let search_dirs: Vec<String> = if path_env.is_empty() {
            vec![String::from("/bin")]
        } else {
            path_env.to_vec()
        };

        for dir in search_dirs {
            let candidate = normalize_vfs_path(&dir, name);
            if self
                .stat(&candidate)
                .await
                .is_ok_and(|meta| meta.file_type == FileType::File)
            {
                return Ok(Some(ExecutableMatch {
                    command: name.to_owned(),
                    path: candidate,
                }));
            }
        }
        Ok(None)
    }

    async fn list_executables(&self) -> Result<Vec<String>, EnvError> {
        match self.list_dir("/bin").await {
            Ok(entries) => Ok(entries
                .into_iter()
                .filter(|entry| entry.file_type == FileType::File)
                .map(|entry| entry.name)
                .collect()),
            Err(_) => Ok(Vec::new()),
        }
    }

    async fn sys_cpu(&self, _long: bool) -> Result<Vec<SysCpuInfo>, EnvError> {
        let sets = processors::sets();
        let snap = inspect::snapshot(
            &InspectQuery {
                prefixes: vec![String::from("/kernel/processors/")],
            },
            0,
        )
        .ok();

        let mut cpus = Vec::with_capacity(sets.possible as usize);
        for id in 0..sets.possible {
            let online = sets.online.contains(&id);
            let busy_key = format!("/kernel/processors/{id}/busy-permille");
            let usage = snap.as_ref().and_then(|s| {
                s.entries.iter().find_map(|e| {
                    (e.path == busy_key).then_some(match e.value {
                        RawInspectValue::Unsigned64(v) => v as f64 / 10.0,
                        RawInspectValue::Signed64(v) => v as f64 / 10.0,
                        RawInspectValue::Float64(v) => v,
                        _ => 0.0,
                    })
                })
            });
            cpus.push(SysCpuInfo {
                name: format!("cpu{id}"),
                brand: if id == sets.bootstrap {
                    String::from("Helios bootstrap processor")
                } else if online {
                    String::from("Helios online processor")
                } else {
                    String::from("Helios offline processor")
                },
                vendor_id: String::from("Helios"),
                freq_mhz: 0,
                cpu_usage: usage,
                load_average: String::from("0.00, 0.00, 0.00"),
            });
        }
        Ok(cpus)
    }

    async fn sys_mem(&self) -> Result<SysMemInfo, EnvError> {
        let snap = inspect::snapshot(
            &InspectQuery {
                prefixes: vec![
                    String::from("/kernel/memory/"),
                    String::from("/kernel/swap/"),
                ],
            },
            0,
        )
        .map_err(|err| EnvError::Io {
            detail: format!("inspect memory failed: {err:?}"),
        })?;

        let u64_metric = |exact_path: &str| -> u64 {
            snap.entries
                .iter()
                .find_map(|entry| {
                    (entry.path == exact_path).then_some(match entry.value {
                        RawInspectValue::Unsigned64(v) => v,
                        RawInspectValue::Signed64(v) => u64::try_from(v).unwrap_or(0),
                        _ => 0,
                    })
                })
                .unwrap_or(0)
        };

        // Match the exact paths published by `kernel/src/inspect/kernel_tree.rs`.
        let total = u64_metric("/kernel/memory/total-bytes");
        let available = u64_metric("/kernel/memory/available-bytes");
        let free = available;
        let used = total.saturating_sub(available);
        let swap_total = u64_metric("/kernel/swap/capacity-bytes");
        let swap_used = u64_metric("/kernel/swap/used-bytes");
        let swap_free = swap_total.saturating_sub(swap_used);

        Ok(SysMemInfo {
            total,
            free,
            used,
            available,
            swap_total,
            swap_free,
            swap_used,
        })
    }

    async fn sys_net(&self) -> Result<Vec<SysNetInfo>, EnvError> {
        let snap = inspect::snapshot(
            &InspectQuery {
                prefixes: vec![String::from("/kernel/network/")],
            },
            0,
        )
        .map_err(|err| EnvError::Io {
            detail: format!("inspect network failed: {err:?}"),
        })?;

        if snap.entries.is_empty() {
            return Ok(Vec::new());
        }

        // Aggregate per-queue counters published by `kernel/src/inspect/kernel_tree.rs`:
        // `/kernel/network/queues/{id}/{tx-frames,rx-frames}`.
        let mut queues: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
        for entry in snap.entries {
            let Some(rest) = entry.path.strip_prefix("/kernel/network/queues/") else {
                continue;
            };
            let Some((id_str, field)) = rest.split_once('/') else {
                continue;
            };
            let Ok(id) = id_str.parse::<u64>() else {
                continue;
            };
            let value = match entry.value {
                RawInspectValue::Unsigned64(v) => v,
                RawInspectValue::Signed64(v) => u64::try_from(v).unwrap_or(0),
                _ => continue,
            };
            let counters = queues.entry(id).or_insert((0, 0));
            match field {
                "tx-frames" => counters.0 = value,
                "rx-frames" => counters.1 = value,
                _ => {}
            }
        }

        Ok(queues
            .into_iter()
            .map(|(id, (sent, recv))| SysNetInfo {
                name: format!("virtio-net0-q{id}"),
                mac: String::new(),
                ip: Vec::new(),
                sent,
                recv,
            })
            .collect())
    }

    async fn sys_disks(&self) -> Result<Vec<SysDiskInfo>, EnvError> {
        let preopens_list = preopens::get_directories();
        let mut disks = Vec::with_capacity(preopens_list.len());
        for (_desc, mount) in preopens_list {
            disks.push(SysDiskInfo {
                device: String::from("helios-vfs"),
                kind: String::from("vfs"),
                mount,
                total: 0,
                free: 0,
                removable: false,
            });
        }
        Ok(disks)
    }

    async fn sys_host(&self) -> Result<SysHostInfo, EnvError> {
        let uptime_nanos = monotonic_clock::now();
        let uptime = Duration::from_nanos(uptime_nanos);
        let wall = system_clock::now();
        let now_secs = wall.seconds;
        let boot_secs = now_secs.saturating_sub(i64::try_from(uptime.as_secs()).unwrap_or(0));
        let boot_time = FixedOffset::east_opt(0)
            .and_then(|offset| offset.timestamp_opt(boot_secs, wall.nanoseconds).single());

        Ok(SysHostInfo {
            name: String::from("Helios"),
            os_version: String::from("0.1.0"),
            long_os_version: String::from("Helios 0.1.0"),
            kernel_version: String::from("helios"),
            hostname: String::from("helios"),
            uptime,
            boot_time,
        })
    }

    async fn inspect(&self, path: Option<&str>) -> Result<Vec<InspectEntry>, EnvError> {
        let prefixes = match path {
            Some(p) if !p.is_empty() => {
                let normalized = if p.starts_with('/') {
                    p.to_owned()
                } else {
                    format!("/{p}")
                };
                vec![normalized]
            }
            _ => Vec::new(),
        };
        let snap =
            inspect::snapshot(&InspectQuery { prefixes }, 0).map_err(|err| EnvError::Io {
                detail: format!("inspect snapshot failed: {err:?}"),
            })?;

        let mut out = Vec::with_capacity(snap.entries.len());
        for entry in snap.entries {
            let moniker = moniker_from_inspect_path(&entry.path);
            out.push(InspectEntry {
                path: entry.path,
                moniker,
                value: convert_inspect_value(entry.value),
            });
        }
        Ok(out)
    }

    async fn list_processes(&self) -> Result<Vec<ProcessInfo>, EnvError> {
        let list = instances::snapshot();
        Ok(list
            .into_iter()
            .map(|inst| ProcessInfo {
                pid: inst.id,
                ppid: 0,
                moniker: format!("/instances/{}/{}", inst.id, inst.name),
                name: inst.name.clone(),
                status: String::from("Running"),
                cpu: f64::from(inst.cpu_busy) / 10.0,
                mem: inst.memory_bytes,
                virtual_mem: inst.memory_bytes,
                command: inst.name,
            })
            .collect())
    }

    async fn kill_process(
        &self,
        pid: u64,
        _signal: Option<&str>,
        _force: bool,
    ) -> Result<(), EnvError> {
        instances::kill(pid).map_err(|err| match err {
            KillError::NoSuchInstance => EnvError::NotFound {
                path: format!("instance:{pid}"),
            },
            KillError::AlreadyStopping => EnvError::Io {
                detail: format!("instance {pid} is already stopping"),
            },
            KillError::Denied => EnvError::PermissionDenied {
                detail: format!("instance-control denied for instance {pid}"),
            },
        })
    }

    async fn whoami(&self) -> Result<String, EnvError> {
        Ok(std::env::var("USER").unwrap_or_else(|_| String::from("helios")))
    }

    async fn sleep(&self, duration: Duration) -> Result<(), EnvError> {
        task::sleep(duration).await;
        Ok(())
    }

    async fn clear(&self) -> Result<(), EnvError> {
        helios_io::stdout()
            .write_str("\x1b[2J\x1b[H")
            .await
            .map_err(|err| EnvError::Io {
                detail: err.to_string(),
            })
    }

    async fn write_stdout(&self, bytes: &[u8]) -> Result<(), EnvError> {
        helios_io::stdout()
            .write_all(bytes)
            .await
            .map_err(|err| EnvError::Io {
                detail: err.to_string(),
            })
    }

    async fn write_stderr(&self, bytes: &[u8]) -> Result<(), EnvError> {
        helios_io::stderr()
            .write_all(bytes)
            .await
            .map_err(|err| EnvError::Io {
                detail: err.to_string(),
            })
    }

    async fn enter_scope(&self, scope: &str) -> Result<String, EnvError> {
        let normalized = normalize_vfs_path("/", scope);
        self.scopes
            .lock()
            .expect("guest scopes lock poisoned")
            .push(normalized.clone());
        Ok(normalized)
    }

    async fn leave_scope(&self, scope: &str) -> Result<(), EnvError> {
        let mut scopes = self.scopes.lock().expect("guest scopes lock poisoned");
        if let Some(pos) = scopes.iter().rposition(|entry| entry == scope) {
            scopes.remove(pos);
        }
        Ok(())
    }

    async fn take_snapshot(
        &self,
        name: &str,
        moniker: Option<&str>,
    ) -> Result<SnapshotInfo, EnvError> {
        let hold = snapshot::prepare().await.map_err(|err| match err {
            SnapshotError::Denied => EnvError::PermissionDenied {
                detail: String::from("machine.control required for snapshot"),
            },
            SnapshotError::Busy => EnvError::Io {
                detail: String::from("another snapshot hold is already active"),
            },
        })?;
        let seq = self.next_id.fetch_add(1, Ordering::Relaxed);
        let id = format!("snapshot-{seq}");
        self.snapshots
            .lock()
            .expect("guest snapshots lock poisoned")
            .insert(id.clone(), hold);
        Ok(SnapshotInfo {
            id,
            name: name.to_owned(),
            moniker: moniker.map(ToOwned::to_owned),
        })
    }

    async fn release_snapshot(&self, id: &str) -> Result<(), EnvError> {
        let _ = self
            .snapshots
            .lock()
            .expect("guest snapshots lock poisoned")
            .remove(id);
        Ok(())
    }

    async fn begin_instruction_profile(&self, target: Option<&str>) -> Result<String, EnvError> {
        let session = profiling::start_instruction_sampling().map_err(map_profile_error)?;
        let seq = self.next_id.fetch_add(1, Ordering::Relaxed);
        let handle = format!("prof-{seq}");
        let started_nanos = monotonic_clock::now();
        self.profiles
            .lock()
            .expect("guest profiles lock poisoned")
            .insert(
                handle.clone(),
                ActiveProfile {
                    target: target.unwrap_or("machine").to_owned(),
                    started_nanos,
                    _session: session,
                },
            );
        Ok(handle)
    }

    async fn end_instruction_profile(
        &self,
        handle: &str,
    ) -> Result<InstructionProfileSummary, EnvError> {
        let active = self
            .profiles
            .lock()
            .expect("guest profiles lock poisoned")
            .remove(handle)
            .ok_or_else(|| EnvError::NotFound {
                path: handle.to_owned(),
            })?;
        let elapsed_nanos = monotonic_clock::now().saturating_sub(active.started_nanos);
        let target = active.target.clone();
        // Drop the RAII SamplingSession to stop timer perturbation before reading samples.
        drop(active);

        let profile = profiling::instruction_samples().map_err(map_profile_error)?;
        let total_samples: u64 = profile.samples.iter().map(|s| s.count).sum();
        Ok(InstructionProfileSummary {
            target,
            instructions: total_samples,
            cycles: 0,
            samples: total_samples,
            elapsed: Duration::from_nanos(elapsed_nanos),
        })
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<FileMetadata>, EnvError> {
        let normalized = normalize_vfs_path(&self.current_cwd(), path);
        let dir = open_directory(&normalized, false).await?;
        let (mut stream, done) = dir.read_directory();
        let mut raw_entries = Vec::new();
        loop {
            let (status, batch) = stream.read(Vec::with_capacity(64)).await;
            raw_entries.extend(batch);
            if helios_api::stream_closed(status) {
                break;
            }
        }
        done.await.map_err(|code| map_fs_error(&normalized, code))?;

        let mut entries = Vec::with_capacity(raw_entries.len());
        for entry in raw_entries {
            let child_path = normalize_vfs_path(&normalized, &entry.name);
            let stat = dir
                .stat_at(PathFlags::empty(), entry.name.clone())
                .await
                .ok();
            let file_type = descriptor_type_to_file_type(&entry.type_);
            let target = if file_type == FileType::Symlink {
                dir.readlink_at(entry.name.clone()).await.ok()
            } else {
                None
            };
            entries.push(FileMetadata {
                path: child_path,
                name: entry.name,
                file_type,
                size: stat.as_ref().map_or(0, |s| s.size),
                modified: stat
                    .as_ref()
                    .and_then(|s| s.data_modification_timestamp)
                    .and_then(wasi_instant_to_datetime),
                readonly: false,
                target,
            });
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    async fn stat(&self, path: &str) -> Result<FileMetadata, EnvError> {
        let normalized = normalize_vfs_path(&self.current_cwd(), path);
        let (base, rel) = resolve_preopen(&normalized)?;
        let stat = if rel.is_empty() {
            base.stat()
                .await
                .map_err(|code| map_fs_error(&normalized, code))?
        } else {
            base.stat_at(PathFlags::SYMLINK_FOLLOW, rel.clone())
                .await
                .map_err(|code| map_fs_error(&normalized, code))?
        };
        let target = if matches!(stat.type_, DescriptorType::SymbolicLink) && !rel.is_empty() {
            base.readlink_at(rel).await.ok()
        } else {
            None
        };
        Ok(stat_to_metadata(&normalized, &stat, target))
    }

    async fn read_file(&self, path: &str) -> Result<Vec<u8>, EnvError> {
        let normalized = normalize_vfs_path(&self.current_cwd(), path);
        let (base, rel) = resolve_preopen(&normalized)?;
        if rel.is_empty() {
            return Err(EnvError::IsADirectory { path: normalized });
        }
        let descriptor = base
            .open_at(
                PathFlags::SYMLINK_FOLLOW,
                rel,
                OpenFlags::empty(),
                DescriptorFlags::READ,
            )
            .await
            .map_err(|code| map_fs_error(&normalized, code))?;

        let (mut stream, done) = descriptor.read_via_stream(0);
        let mut bytes = Vec::new();
        loop {
            let (status, chunk) = stream.read(Vec::with_capacity(STREAM_READ_CHUNK)).await;
            if !chunk.is_empty() {
                bytes.extend_from_slice(&chunk);
            }
            if helios_api::stream_closed(status) {
                break;
            }
        }
        done.await.map_err(|code| map_fs_error(&normalized, code))?;
        Ok(bytes)
    }

    async fn write_file(
        &self,
        path: &str,
        data: &[u8],
        append: bool,
        force: bool,
    ) -> Result<(), EnvError> {
        let normalized = normalize_vfs_path(&self.current_cwd(), path);
        let (parent, leaf) = open_parent_and_leaf(&normalized, true).await?;

        let open_flags = if append {
            OpenFlags::CREATE
        } else if force {
            OpenFlags::CREATE | OpenFlags::TRUNCATE
        } else {
            OpenFlags::CREATE | OpenFlags::EXCLUSIVE
        };

        let descriptor = parent
            .open_at(
                PathFlags::SYMLINK_FOLLOW,
                leaf,
                open_flags,
                DescriptorFlags::WRITE,
            )
            .await
            .map_err(|code| map_fs_error(&normalized, code))?;

        let (mut tx, rx) = wit_stream::new::<u8>();
        let payload = data.to_vec();
        let target_path = normalized.clone();
        let (write_res, feed_res) = zip(
            async move {
                let fut = if append {
                    descriptor.append_via_stream(rx)
                } else {
                    descriptor.write_via_stream(rx, 0)
                };
                fut.await.map_err(|code| map_fs_error(&target_path, code))
            },
            async move {
                let unwritten = tx.write_all(payload).await.len();
                drop(tx);
                if unwritten == 0 {
                    Ok(())
                } else {
                    Err(EnvError::Io {
                        detail: format!("short write to {normalized}: {unwritten} bytes unwritten"),
                    })
                }
            },
        )
        .await;
        write_res?;
        feed_res
    }

    async fn mkdir(&self, path: &str) -> Result<(), EnvError> {
        let normalized = normalize_vfs_path(&self.current_cwd(), path);
        let (mut current, rel) = resolve_preopen(&normalized)?;
        if rel.is_empty() {
            return Ok(());
        }
        for segment in rel.split('/').filter(|s| !s.is_empty()) {
            match current.create_directory_at(segment.to_owned()).await {
                Ok(()) | Err(ErrorCode::Exist) => {}
                Err(code) => return Err(map_fs_error(&normalized, code)),
            }
            current = current
                .open_at(
                    PathFlags::SYMLINK_FOLLOW,
                    segment.to_owned(),
                    OpenFlags::DIRECTORY,
                    DescriptorFlags::READ | DescriptorFlags::MUTATE_DIRECTORY,
                )
                .await
                .map_err(|code| map_fs_error(&normalized, code))?;
        }
        Ok(())
    }

    async fn remove(&self, path: &str, recursive: bool, force: bool) -> Result<(), EnvError> {
        let normalized = normalize_vfs_path(&self.current_cwd(), path);
        let meta = match self.stat(&normalized).await {
            Ok(meta) => meta,
            Err(EnvError::NotFound { .. }) if force => return Ok(()),
            Err(err) => return Err(err),
        };
        if meta.file_type == FileType::Dir {
            if !recursive {
                let (parent, leaf) = open_parent_and_leaf(&normalized, true).await?;
                parent
                    .remove_directory_at(leaf)
                    .await
                    .map_err(|code| map_fs_error(&normalized, code))?;
            } else {
                remove_dir_recursive(&normalized).await?;
            }
        } else {
            let (parent, leaf) = open_parent_and_leaf(&normalized, true).await?;
            parent
                .unlink_file_at(leaf)
                .await
                .map_err(|code| map_fs_error(&normalized, code))?;
        }
        Ok(())
    }

    async fn copy(
        &self,
        from: &str,
        to: &str,
        recursive: bool,
        force: bool,
    ) -> Result<(), EnvError> {
        let src = normalize_vfs_path(&self.current_cwd(), from);
        let dst = normalize_vfs_path(&self.current_cwd(), to);
        let meta = self.stat(&src).await?;
        if meta.file_type == FileType::Dir {
            if !recursive {
                return Err(EnvError::IsADirectory { path: src });
            }
            copy_dir_recursive(self, &src, &dst, force).await?;
        } else {
            let data = self.read_file(&src).await?;
            self.write_file(&dst, &data, false, force).await?;
        }
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str, force: bool) -> Result<(), EnvError> {
        let src = normalize_vfs_path(&self.current_cwd(), from);
        let dst = normalize_vfs_path(&self.current_cwd(), to);
        if !force && self.stat(&dst).await.is_ok() {
            return Err(EnvError::AlreadyExists { path: dst });
        }
        let (src_parent, src_leaf) = open_parent_and_leaf(&src, true).await?;
        let (dst_parent, dst_leaf) = open_parent_and_leaf(&dst, true).await?;
        src_parent
            .rename_at(src_leaf, &dst_parent, dst_leaf)
            .await
            .map_err(|code| map_fs_error(&src, code))
    }

    async fn touch(&self, path: &str, no_create: bool) -> Result<(), EnvError> {
        let normalized = normalize_vfs_path(&self.current_cwd(), path);
        let (parent, leaf) = open_parent_and_leaf(&normalized, true).await?;
        match parent
            .set_times_at(
                PathFlags::SYMLINK_FOLLOW,
                leaf,
                NewTimestamp::Now,
                NewTimestamp::Now,
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(ErrorCode::NoEntry) if !no_create => {
                self.write_file(&normalized, &[], false, true).await
            }
            Err(ErrorCode::NoEntry) => Ok(()),
            Err(code) => Err(map_fs_error(&normalized, code)),
        }
    }

    async fn watch(&self, _path: &str) -> Result<async_channel::Receiver<WatchEvent>, EnvError> {
        Err(EnvError::Unsupported {
            detail: String::from("filesystem watch is not exposed by WASI Preview 3 filesystem"),
        })
    }
}

async fn preopen_directory_grants(include_execute: bool) -> Vec<CapabilityGrant> {
    let mut grants = Vec::new();
    for (desc, path) in preopens::get_directories() {
        let normalized = normalize_vfs_path("/", &path);
        let flags = desc.get_flags().await.unwrap_or(DescriptorFlags::READ);
        let mut rights = Vec::new();
        if (flags & DescriptorFlags::READ) != DescriptorFlags::empty() {
            rights.push(FilesystemRight::Read);
            if include_execute {
                rights.push(FilesystemRight::Execute);
            }
        }
        if (flags & DescriptorFlags::WRITE) != DescriptorFlags::empty() {
            rights.push(FilesystemRight::Write);
        }
        if (flags & DescriptorFlags::MUTATE_DIRECTORY) != DescriptorFlags::empty() {
            rights.push(FilesystemRight::MutateDirectory);
        }
        if !rights.is_empty() {
            grants.push(directory_grant(normalized.clone(), normalized, rights));
        }
    }
    grants
}

fn parse_scope(raw: &str) -> Result<AuthorityScope, EnvError> {
    match raw {
        "" | "machine" => Ok(AuthorityScope::Machine),
        "own" | "self" => Ok(AuthorityScope::Own),
        "subtree" => Ok(AuthorityScope::Subtree(None)),
        other => {
            if let Some(id_str) = other.strip_prefix("subtree:") {
                let id = id_str
                    .parse::<u64>()
                    .map_err(|_| EnvError::InvalidArgument {
                        detail: format!("invalid subtree instance id `{id_str}`"),
                    })?;
                Ok(AuthorityScope::Subtree(Some(id)))
            } else {
                Err(EnvError::InvalidArgument {
                    detail: format!("unknown authority scope `{other}`"),
                })
            }
        }
    }
}

fn resolve_preopen(path: &str) -> Result<(Descriptor, String), EnvError> {
    let normalized = normalize_vfs_path("/", path);
    let mut best: Option<(usize, Descriptor, String)> = None;
    for (desc, mount) in preopens::get_directories() {
        let mount_norm = normalize_vfs_path("/", &mount);
        let rel = if mount_norm == "/" {
            normalized.trim_start_matches('/').to_owned()
        } else if normalized == mount_norm {
            String::new()
        } else if let Some(rest) = normalized.strip_prefix(&format!("{mount_norm}/")) {
            rest.to_owned()
        } else {
            continue;
        };
        let score = mount_norm.len();
        if best
            .as_ref()
            .is_none_or(|(best_score, _, _)| score > *best_score)
        {
            best = Some((score, desc, rel));
        }
    }
    best.map(|(_, desc, rel)| (desc, rel))
        .ok_or_else(|| EnvError::PermissionDenied {
            detail: format!("no preopened directory covers {path}"),
        })
}

async fn open_directory(path: &str, writable: bool) -> Result<Descriptor, EnvError> {
    let (base, rel) = resolve_preopen(path)?;
    if rel.is_empty() {
        return Ok(base);
    }
    let flags = if writable {
        DescriptorFlags::READ | DescriptorFlags::MUTATE_DIRECTORY
    } else {
        DescriptorFlags::READ
    };
    base.open_at(PathFlags::SYMLINK_FOLLOW, rel, OpenFlags::DIRECTORY, flags)
        .await
        .map_err(|code| map_fs_error(path, code))
}

async fn open_parent_and_leaf(
    path: &str,
    writable: bool,
) -> Result<(Descriptor, String), EnvError> {
    let normalized = normalize_vfs_path("/", path);
    if normalized == "/" {
        return Err(EnvError::InvalidArgument {
            detail: String::from("root directory `/` has no parent"),
        });
    }
    let (parent_path, leaf) = match normalized.rsplit_once('/') {
        Some(("", leaf)) => ("/", leaf.to_owned()),
        Some((parent, leaf)) => (parent, leaf.to_owned()),
        None => ("/", normalized.clone()),
    };
    let parent = open_directory(parent_path, writable).await?;
    Ok((parent, leaf))
}

fn remove_dir_recursive<'a>(
    path: &'a str,
) -> Pin<Box<dyn Future<Output = Result<(), EnvError>> + Send + 'a>> {
    Box::pin(async move {
        let dir = open_directory(path, true).await?;
        let (mut stream, done) = dir.read_directory();
        let mut entries = Vec::new();
        loop {
            let (status, batch) = stream.read(Vec::with_capacity(64)).await;
            entries.extend(batch);
            if helios_api::stream_closed(status) {
                break;
            }
        }
        done.await.map_err(|code| map_fs_error(path, code))?;

        for entry in entries {
            let child = normalize_vfs_path(path, &entry.name);
            if matches!(entry.type_, DescriptorType::Directory) {
                remove_dir_recursive(&child).await?;
            } else {
                dir.unlink_file_at(entry.name)
                    .await
                    .map_err(|code| map_fs_error(&child, code))?;
            }
        }

        let (parent, leaf) = open_parent_and_leaf(path, true).await?;
        parent
            .remove_directory_at(leaf)
            .await
            .map_err(|code| map_fs_error(path, code))
    })
}

fn copy_dir_recursive<'a>(
    env: &'a GuestHeliosEnv,
    src: &'a str,
    dst: &'a str,
    force: bool,
) -> Pin<Box<dyn Future<Output = Result<(), EnvError>> + Send + 'a>> {
    Box::pin(async move {
        env.mkdir(dst).await?;
        let entries = env.list_dir(src).await?;
        for entry in entries {
            let next_dst = normalize_vfs_path(dst, &entry.name);
            if entry.file_type == FileType::Dir {
                copy_dir_recursive(env, &entry.path, &next_dst, force).await?;
            } else {
                let data = env.read_file(&entry.path).await?;
                env.write_file(&next_dst, &data, false, force).await?;
            }
        }
        Ok(())
    })
}

fn descriptor_type_to_file_type(ty: &DescriptorType) -> FileType {
    match ty {
        DescriptorType::Directory => FileType::Dir,
        DescriptorType::SymbolicLink => FileType::Symlink,
        _ => FileType::File,
    }
}

fn stat_to_metadata(path: &str, stat: &DescriptorStat, target: Option<String>) -> FileMetadata {
    let name = if path == "/" {
        String::from("/")
    } else {
        path.rsplit('/').next().unwrap_or(path).to_owned()
    };
    FileMetadata {
        path: path.to_owned(),
        name,
        file_type: descriptor_type_to_file_type(&stat.type_),
        size: stat.size,
        modified: stat
            .data_modification_timestamp
            .and_then(wasi_instant_to_datetime),
        readonly: false,
        target,
    }
}

fn wasi_instant_to_datetime(
    instant: helios_api::bindings::wasi::clocks::system_clock::Instant,
) -> Option<DateTime<FixedOffset>> {
    FixedOffset::east_opt(0).and_then(|offset| {
        offset
            .timestamp_opt(instant.seconds, instant.nanoseconds)
            .single()
    })
}

fn moniker_from_inspect_path(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("/instances/") {
        let mut parts = rest.split('/');
        if let (Some(id), Some(name)) = (parts.next(), parts.next()) {
            return format!("/instances/{id}/{name}");
        }
    }
    String::from("/kernel")
}

fn convert_inspect_value(val: RawInspectValue) -> InspectValue {
    match val {
        RawInspectValue::Boolean(b) => InspectValue::Bool(b),
        RawInspectValue::Signed64(i) => InspectValue::Int(i),
        RawInspectValue::Unsigned64(u) => InspectValue::Uint(u),
        RawInspectValue::Float64(f) => InspectValue::Float(f),
        RawInspectValue::Text(s) => InspectValue::String(s),
        RawInspectValue::Blob(b) => InspectValue::Bytes(b),
    }
}

fn map_fs_error(path: &str, code: ErrorCode) -> EnvError {
    match code {
        ErrorCode::NoEntry => EnvError::NotFound {
            path: path.to_owned(),
        },
        ErrorCode::NotDirectory => EnvError::NotADirectory {
            path: path.to_owned(),
        },
        ErrorCode::IsDirectory => EnvError::IsADirectory {
            path: path.to_owned(),
        },
        ErrorCode::Exist => EnvError::AlreadyExists {
            path: path.to_owned(),
        },
        ErrorCode::Access | ErrorCode::NotPermitted | ErrorCode::ReadOnly => {
            EnvError::PermissionDenied {
                detail: format!("{path}: {code:?}"),
            }
        }
        other => EnvError::Io {
            detail: format!("{path}: {other:?}"),
        },
    }
}

fn map_spawn_error(err: SpawnError) -> EnvError {
    use helios_api::programs::SpawnErrorKind;
    match err.kind {
        SpawnErrorKind::NotFound => EnvError::NotFound { path: err.detail },
        SpawnErrorKind::PermissionDenied => EnvError::PermissionDenied { detail: err.detail },
        SpawnErrorKind::InvalidPath | SpawnErrorKind::InvalidHint => {
            EnvError::InvalidArgument { detail: err.detail }
        }
        _ => EnvError::Io {
            detail: format!("{:?}: {}", err.kind, err.detail),
        },
    }
}

fn map_profile_error(err: InstructionProfileError) -> EnvError {
    match err {
        InstructionProfileError::Denied => EnvError::PermissionDenied {
            detail: String::from("profiling permission denied"),
        },
        InstructionProfileError::Busy => EnvError::Io {
            detail: String::from("another profiling session is active"),
        },
        InstructionProfileError::NotCaptured => EnvError::Unsupported {
            detail: String::from("instruction sampling not captured on this target"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{DefaultGrantPolicy, DefaultGrantTier, PROCESS_AUTHORITY_DENIED_DETAIL};

    fn non_dir_count(policy: DefaultGrantPolicy) -> usize {
        let mut grants = Vec::new();
        policy.append_non_directory_grants(&mut grants);
        grants.len()
    }

    #[test]
    fn default_grant_policy_narrows_deterministically_on_kernel_authority_refusal() {
        let mut policy = DefaultGrantPolicy::initial(true, true);
        assert_eq!(policy.tier, DefaultGrantTier::MachineFull);
        assert!(policy.include_dir_execute());
        assert_eq!(non_dir_count(policy), 13);

        // Unrelated PermissionDenied detail (e.g. ProgramSourceNotGranted) must not downgrade.
        assert!(!policy.narrow_for_refusal("program source is not granted by process authority"));
        assert_eq!(policy.tier, DefaultGrantTier::MachineFull);

        // Fixed kernel ProcessAuthorityDenied string steps monotonically through every tier.
        let expected = [
            (DefaultGrantTier::InspectTerminalExec, true, 4),
            (DefaultGrantTier::TerminalExec, true, 3),
            (DefaultGrantTier::ProcessExec, true, 2),
            (DefaultGrantTier::DirectoryExec, true, 0),
            (DefaultGrantTier::DirectoryOnly, false, 0),
        ];
        for (tier, dir_exec, count) in expected {
            assert!(policy.narrow_for_refusal(PROCESS_AUTHORITY_DENIED_DETAIL));
            assert_eq!(policy.tier, tier);
            assert_eq!(policy.include_dir_execute(), dir_exec);
            assert_eq!(non_dir_count(policy), count);
        }

        // Minimum tier stops retrying so spawn surfaces PermissionDenied.
        assert!(!policy.narrow_for_refusal(PROCESS_AUTHORITY_DENIED_DETAIL));
        assert_eq!(policy.tier, DefaultGrantTier::DirectoryOnly);
    }

    #[test]
    fn default_grant_policy_skips_terminal_tier_without_terminal() {
        let mut policy = DefaultGrantPolicy::initial(true, false);
        assert_eq!(policy.tier, DefaultGrantTier::MachineFull);

        assert!(policy.narrow_for_refusal(PROCESS_AUTHORITY_DENIED_DETAIL));
        assert_eq!(policy.tier, DefaultGrantTier::InspectTerminalExec);
        assert_eq!(non_dir_count(policy), 3);

        assert!(policy.narrow_for_refusal(PROCESS_AUTHORITY_DENIED_DETAIL));
        assert_eq!(policy.tier, DefaultGrantTier::ProcessExec);
        assert_eq!(non_dir_count(policy), 2);

        assert!(policy.narrow_for_refusal(PROCESS_AUTHORITY_DENIED_DETAIL));
        assert_eq!(policy.tier, DefaultGrantTier::DirectoryExec);
        assert!(policy.include_dir_execute());

        assert!(policy.narrow_for_refusal(PROCESS_AUTHORITY_DENIED_DETAIL));
        assert_eq!(policy.tier, DefaultGrantTier::DirectoryOnly);
        assert!(!policy.include_dir_execute());

        assert!(!policy.narrow_for_refusal(PROCESS_AUTHORITY_DENIED_DETAIL));
    }

    #[test]
    fn default_grant_policy_initial_tiers_without_machine_inspect() {
        let with_tty = DefaultGrantPolicy::initial(false, true);
        assert_eq!(with_tty.tier, DefaultGrantTier::TerminalExec);
        assert_eq!(non_dir_count(with_tty), 3);

        let headless = DefaultGrantPolicy::initial(false, false);
        assert_eq!(headless.tier, DefaultGrantTier::ProcessExec);
        assert_eq!(non_dir_count(headless), 2);
    }
}
