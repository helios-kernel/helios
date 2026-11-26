//! Host [`HeliosEnv`] implementation over [`helios_ops::Session`], [`helios_ops::Fleet`],
//! and [`helios_ops::http`] (`zenwave`), plus host-only `fleet`, `bundle`, `trace`, and
//! `--local` file I/O commands.

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, FixedOffset, Utc};
use helios_nu::{
    AsyncCommand, AsyncCommandContext, AsyncPipelineData, CustomCommandSpec, EnvError,
    ExecutableMatch, ExternalProcess, ExternalSpawnRequest, FileMetadata, FileType, HeliosEnv,
    HttpRequest, HttpResponse, InspectEntry, InspectValue, InstructionProfileSummary, ProcessInfo,
    STREAM_CHANNEL_CAPACITY, SnapshotInfo, SysCpuInfo, SysDiskInfo, SysHostInfo, SysMemInfo,
    SysNetInfo, WatchEvent, normalize_vfs_path,
};
use helios_ops::{DiagnosticBundle, Fleet, OpsError, Session, SpawnRequest};
use helios_wit_rpc::inspector::helios::system::{
    inspect as proto_inspect, tracing as proto_tracing,
};
use helios_wit_rpc::inspector_fs::EntryKind;
use nu_engine::CallExt as _;
use nu_protocol::{
    Category, DataSource, NuGlob, PipelineMetadata, Record, ShellError, Signature, Span, Spanned,
    SyntaxShape, Type, Value, shell_error::generic::GenericError,
};
use tokio::sync::RwLock;

use crate::cache::RemoteCompletionCache;

/// Host-side async [`HeliosEnv`] backed by a live [`helios_ops::Session`],
/// optional [`helios_ops::Fleet`], and a 1.5s TTL / 150ms-bounded completion cache.
#[derive(Clone)]
pub struct HostEnv {
    session: Session,
    fleet: Option<Fleet>,
    cwd: Arc<RwLock<String>>,
    scope_stack: Arc<RwLock<Vec<String>>>,
    snapshots: Arc<tokio::sync::Mutex<BTreeMap<String, helios_ops::SnapshotHold>>>,
    active_profiles: Arc<tokio::sync::Mutex<BTreeSet<String>>>,
    next_id: Arc<AtomicU64>,
    completion_cache: RemoteCompletionCache,
    /// When `true`, `list_dir` and completion probes go through `completion_cache`
    /// with the 150ms latency ceiling.
    completion_mode: bool,
}

impl HostEnv {
    /// Create a [`HostEnv`] connected to `session` (and optional multi-node `fleet`).
    #[must_use]
    pub fn new(session: Session, fleet: Option<Fleet>) -> Self {
        Self::with_cache(session, fleet, RemoteCompletionCache::default())
    }

    /// Create a [`HostEnv`] with a custom [`RemoteCompletionCache`] (e.g. for tests).
    #[must_use]
    pub fn with_cache(
        session: Session,
        fleet: Option<Fleet>,
        completion_cache: RemoteCompletionCache,
    ) -> Self {
        Self {
            session,
            fleet,
            cwd: Arc::new(RwLock::new(String::from("/"))),
            scope_stack: Arc::new(RwLock::new(Vec::new())),
            snapshots: Arc::new(tokio::sync::Mutex::new(BTreeMap::new())),
            active_profiles: Arc::new(tokio::sync::Mutex::new(BTreeSet::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            completion_cache,
            completion_mode: false,
        }
    }

    /// Release any held snapshot leases or active instruction sampling sessions
    /// (e.g. after `Ctrl+C` cancellation of `with-snapshot` or `with-instruction-profile`).
    pub async fn cleanup_active(&self) {
        let holds: Vec<helios_ops::SnapshotHold> = {
            let mut guard = self.snapshots.lock().await;
            std::mem::take(&mut *guard).into_values().collect()
        };
        for hold in holds {
            let _ = hold.release().await;
        }
        let had_profiles = {
            let mut guard = self.active_profiles.lock().await;
            let non_empty = !guard.is_empty();
            guard.clear();
            non_empty
        };
        if had_profiles {
            let _ = self.session.profile_set_instruction_sampling(false).await;
        }
    }

    async fn active_scope(&self) -> String {
        if let Some(top) = self.scope_stack.read().await.last() {
            return top.clone();
        }
        helios_ops::target::normalize_scope(self.session.options().attenuation.effective_scope())
    }

    async fn scoped_session(&self) -> Result<Session, EnvError> {
        let top = self.scope_stack.read().await.last().cloned();
        let Some(scope) = top else {
            return Ok(self.session.clone());
        };
        let mut att = self.session.options().attenuation.clone();
        att.scope = Some(scope);
        self.session.attenuated(att).map_err(ops_to_env_err)
    }

    /// Return a lightweight clone configured for bounded-latency `<Tab>` completion.
    #[must_use]
    pub fn for_completion(&self) -> Self {
        let mut cloned = self.clone();
        cloned.completion_mode = true;
        cloned
    }

    /// Borrow the underlying [`Session`].
    #[must_use]
    pub const fn session(&self) -> &Session {
        &self.session
    }

    /// Borrow the configured [`Fleet`], if any.
    #[must_use]
    pub const fn fleet(&self) -> Option<&Fleet> {
        self.fleet.as_ref()
    }

    /// Borrow the shared [`RemoteCompletionCache`].
    #[must_use]
    pub const fn completion_cache(&self) -> &RemoteCompletionCache {
        &self.completion_cache
    }

    fn effective_fleet(&self) -> Fleet {
        self.fleet
            .clone()
            .unwrap_or_else(|| Fleet::from_sessions(vec![self.session.clone()], 1))
    }
}

impl HeliosEnv for HostEnv {
    async fn cwd(&self) -> Result<String, EnvError> {
        Ok(self.cwd.read().await.clone())
    }

    async fn set_cwd(&self, path: &str) -> Result<String, EnvError> {
        let current = self.cwd.read().await.clone();
        let normalized = normalize_vfs_path(&current, path);
        // Verify the directory exists and is listable on the remote guest.
        self.session
            .list_dir(&normalized)
            .await
            .map_err(ops_to_env_err)?;
        *self.cwd.write().await = normalized.clone();
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

        let program_path = match self.resolve_executable(&request.program, &path_env).await? {
            Some(found) => found.path,
            None if request.program.starts_with('/') => request.program.clone(),
            None => format!("/bin/{}", request.program),
        };

        let mut stdin_bytes = Vec::new();
        if let Some(rx) = request.stdin {
            while let Ok(chunk) = rx.recv().await {
                match chunk {
                    Ok(bytes) => stdin_bytes.extend_from_slice(&bytes),
                    Err(err) => {
                        return Err(EnvError::Process {
                            detail: err.to_string(),
                        });
                    }
                }
            }
        }

        let mut capability_grants = Vec::with_capacity(request.grants.len());
        for grant in &request.grants {
            let translated = helios_ops::session::parse_grant_spec(
                &grant.kind,
                &grant.target,
                grant.mode.as_deref(),
            )
            .map_err(ops_to_env_err)?;
            capability_grants.push(translated);
        }

        let cwd = (!request.cwd.is_empty()).then_some(request.cwd);
        let spawn_req = SpawnRequest {
            path: program_path,
            args: request.args,
            env: request.env.into_iter().collect(),
            cwd,
            stdin: stdin_bytes,
            capability_grants,
        };
        let child = self
            .session
            .spawn(spawn_req)
            .await
            .map_err(ops_to_env_err)?;

        let (exit_tx, exit_rx) = async_channel::bounded(1);

        let child_stdout = child.stdout.clone();
        let child_stderr = child.stderr.clone();

        let (stdout, stdout_inherited_done) = if request.capture_stdout {
            let (stdout_tx, stdout_rx) = async_channel::bounded(STREAM_CHANNEL_CAPACITY);
            tokio::spawn(async move {
                while let Ok(item) = child_stdout.recv().await {
                    let mapped = item.map_err(|err| {
                        ShellError::Generic(GenericError::new(
                            "remote stdout error",
                            err.to_string(),
                            Span::unknown(),
                        ))
                    });
                    if stdout_tx.send(mapped).await.is_err() {
                        break;
                    }
                }
            });
            (Some(stdout_rx), None)
        } else {
            let (done_tx, done_rx) = async_channel::bounded(1);
            tokio::spawn(async move {
                use std::io::Write as _;
                while let Ok(item) = child_stdout.recv().await {
                    if let Ok(bytes) = item {
                        let mut out = std::io::stdout().lock();
                        let _ = out.write_all(&bytes);
                        let _ = out.flush();
                    }
                }
                let _ = done_tx.send(()).await;
            });
            (None, Some(done_rx))
        };

        let (stderr, stderr_inherited_done) = if request.capture_stderr {
            let (stderr_tx, stderr_rx) = async_channel::bounded(STREAM_CHANNEL_CAPACITY);
            tokio::spawn(async move {
                while let Ok(item) = child_stderr.recv().await {
                    let mapped = item.map_err(|err| {
                        ShellError::Generic(GenericError::new(
                            "remote stderr error",
                            err.to_string(),
                            Span::unknown(),
                        ))
                    });
                    if stderr_tx.send(mapped).await.is_err() {
                        break;
                    }
                }
            });
            (Some(stderr_rx), None)
        } else {
            let (done_tx, done_rx) = async_channel::bounded(1);
            tokio::spawn(async move {
                use std::io::Write as _;
                while let Ok(item) = child_stderr.recv().await {
                    if let Ok(bytes) = item {
                        let mut err = std::io::stderr().lock();
                        let _ = err.write_all(&bytes);
                        let _ = err.flush();
                    }
                }
                let _ = done_tx.send(()).await;
            });
            (None, Some(done_rx))
        };

        tokio::spawn(async move {
            let wait_res = child.wait().await;
            if let Some(rx) = stdout_inherited_done {
                let _ = rx.recv().await;
            }
            if let Some(rx) = stderr_inherited_done {
                let _ = rx.recv().await;
            }
            let status = match wait_res {
                Ok(res) => Ok(i32::try_from(res.exit_code).unwrap_or(1)),
                Err(err) => Err(ops_to_env_err(err)),
            };
            let _ = exit_tx.send(status).await;
        });

        Ok(ExternalProcess {
            stdout,
            stderr,
            exit_code: exit_rx,
        })
    }

    async fn resolve_executable(
        &self,
        name: &str,
        path_env: &[String],
    ) -> Result<Option<ExecutableMatch>, EnvError> {
        if name.starts_with('/') {
            if self.session.stat(name).await.is_ok() {
                return Ok(Some(ExecutableMatch {
                    command: name.to_owned(),
                    path: name.to_owned(),
                }));
            }
            return Ok(None);
        }
        let search_dirs: Vec<String> = if path_env.is_empty() {
            vec!["/bin".to_owned()]
        } else {
            path_env.to_vec()
        };
        for dir in search_dirs {
            let entries = self.completion_cache.list_dir(&self.session, &dir).await;
            if let Some(found) = entries
                .into_iter()
                .find(|entry| entry.name == name && entry.file_type == FileType::File)
            {
                return Ok(Some(ExecutableMatch {
                    command: name.to_owned(),
                    path: found.path,
                }));
            }
        }
        Ok(None)
    }

    async fn list_executables(&self) -> Result<Vec<String>, EnvError> {
        Ok(self.completion_cache.executables(&self.session).await)
    }

    async fn sys_cpu(&self, _long: bool) -> Result<Vec<SysCpuInfo>, EnvError> {
        let snap = self
            .session
            .kernel_snapshot()
            .await
            .map_err(ops_to_env_err)?;
        let isa = if snap.processors.guest_isa_level.is_empty() {
            "helios-cpu".to_owned()
        } else {
            snap.processors.guest_isa_level.clone()
        };
        if snap.processors.utilization.is_empty() {
            let count = snap
                .processors
                .online
                .max(snap.processors.configured)
                .max(1);
            return Ok((0..count)
                .map(|id| SysCpuInfo {
                    name: format!("cpu{id}"),
                    brand: isa.clone(),
                    vendor_id: "Helios".to_owned(),
                    freq_mhz: 0,
                    cpu_usage: None,
                    load_average: "0.00, 0.00, 0.00".to_owned(),
                })
                .collect());
        }
        Ok(snap
            .processors
            .utilization
            .into_iter()
            .map(|cpu| SysCpuInfo {
                name: format!("cpu{}", cpu.id),
                brand: isa.clone(),
                vendor_id: "Helios".to_owned(),
                freq_mhz: 0,
                cpu_usage: Some(f64::from(cpu.busy) / 10.0),
                load_average: "0.00, 0.00, 0.00".to_owned(),
            })
            .collect())
    }

    async fn sys_mem(&self) -> Result<SysMemInfo, EnvError> {
        let snap = self
            .session
            .kernel_snapshot()
            .await
            .map_err(ops_to_env_err)?;
        let total = snap.memory.total_bytes;
        let available = snap.memory.available_bytes;
        let used = total.saturating_sub(available);
        let (swap_total, swap_used) = snap
            .swap
            .map_or((0, 0), |s| (s.capacity_bytes, s.used_bytes));
        Ok(SysMemInfo {
            total,
            free: available,
            used,
            available,
            swap_total,
            swap_free: swap_total.saturating_sub(swap_used),
            swap_used,
        })
    }

    async fn sys_net(&self) -> Result<Vec<SysNetInfo>, EnvError> {
        let snap = self
            .session
            .kernel_snapshot()
            .await
            .map_err(ops_to_env_err)?;
        let Some(net) = snap.network else {
            return Ok(Vec::new());
        };
        Ok(net
            .queues
            .into_iter()
            .map(|q| SysNetInfo {
                name: format!("virtio-net-q{}", q.id),
                mac: String::new(),
                ip: Vec::new(),
                sent: q.tx_frames,
                recv: q.rx_frames,
            })
            .collect())
    }

    async fn sys_disks(&self) -> Result<Vec<SysDiskInfo>, EnvError> {
        let snap = self
            .session
            .kernel_snapshot()
            .await
            .map_err(ops_to_env_err)?;
        let mut disks = Vec::new();
        if let Some(blk) = snap.block {
            disks.push(SysDiskInfo {
                device: "virtio-blk0".to_owned(),
                kind: "virtio-blk".to_owned(),
                mount: "/".to_owned(),
                total: blk.capacity_bytes,
                free: 0,
                removable: false,
            });
        }
        Ok(disks)
    }

    async fn sys_host(&self) -> Result<SysHostInfo, EnvError> {
        let snap = self
            .session
            .kernel_snapshot()
            .await
            .map_err(ops_to_env_err)?;
        let boot_time = if snap.wall_clock > snap.uptime {
            let boot_secs = i64::try_from((snap.wall_clock - snap.uptime) / 1_000_000_000).ok();
            boot_secs
                .and_then(|s| DateTime::from_timestamp(s, 0))
                .map(|dt| dt.fixed_offset())
        } else {
            None
        };
        Ok(SysHostInfo {
            name: "Helios".to_owned(),
            os_version: env!("CARGO_PKG_VERSION").to_owned(),
            long_os_version: format!("Helios ({})", snap.processors.guest_isa_level),
            kernel_version: env!("CARGO_PKG_VERSION").to_owned(),
            hostname: self.session.target().name.clone(),
            uptime: Duration::from_nanos(snap.uptime),
            boot_time,
        })
    }

    async fn inspect(&self, path: Option<&str>) -> Result<Vec<InspectEntry>, EnvError> {
        let session = self.scoped_session().await?;
        let prefixes: Vec<&str> = path.into_iter().collect();
        let snap = session
            .inspect(&prefixes, 0)
            .await
            .map_err(ops_to_env_err)?;
        Ok(snap
            .entries
            .into_iter()
            .map(|entry| {
                let moniker = entry
                    .path
                    .split('/')
                    .nth(1)
                    .map_or_else(|| "/".to_owned(), |seg| format!("/{seg}"));
                InspectEntry {
                    path: entry.path,
                    moniker,
                    value: convert_inspect_value(entry.value),
                }
            })
            .collect())
    }

    async fn list_processes(&self) -> Result<Vec<ProcessInfo>, EnvError> {
        let session = self.scoped_session().await?;
        let instances = session.instances().await.map_err(ops_to_env_err)?;
        Ok(instances
            .into_iter()
            .map(|inst| {
                let moniker = if inst.name.starts_with('/') {
                    inst.name.clone()
                } else {
                    format!("/{}", inst.name)
                };
                ProcessInfo {
                    pid: inst.id,
                    ppid: 0,
                    moniker,
                    name: inst.name.clone(),
                    status: "running".to_owned(),
                    cpu: f64::from(inst.cpu_busy) / 10.0,
                    mem: inst.memory_bytes,
                    virtual_mem: inst.memory_bytes,
                    command: inst.name,
                }
            })
            .collect())
    }

    async fn kill_process(
        &self,
        pid: u64,
        _signal: Option<&str>,
        _force: bool,
    ) -> Result<(), EnvError> {
        self.session.kill(pid).await.map_err(ops_to_env_err)?;
        self.completion_cache.invalidate_all().await;
        Ok(())
    }

    async fn whoami(&self) -> Result<String, EnvError> {
        Ok(self.session.whoami())
    }

    async fn sleep(&self, duration: Duration) -> Result<(), EnvError> {
        tokio::time::sleep(duration).await;
        Ok(())
    }

    async fn clear(&self) -> Result<(), EnvError> {
        use std::io::Write as _;
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(b"\x1b[2J\x1b[H");
        let _ = out.flush();
        Ok(())
    }

    async fn write_stdout(&self, bytes: &[u8]) -> Result<(), EnvError> {
        use std::io::Write as _;
        let mut out = std::io::stdout().lock();
        out.write_all(bytes)
            .and_then(|()| out.flush())
            .map_err(|err| EnvError::Io {
                detail: err.to_string(),
            })
    }

    async fn write_stderr(&self, bytes: &[u8]) -> Result<(), EnvError> {
        use std::io::Write as _;
        let mut err = std::io::stderr().lock();
        err.write_all(bytes)
            .and_then(|()| err.flush())
            .map_err(|e| EnvError::Io {
                detail: e.to_string(),
            })
    }

    async fn enter_scope(&self, scope: &str) -> Result<String, EnvError> {
        let current = self.active_scope().await;
        let normalized = helios_ops::target::normalize_scope(scope);
        if !helios_ops::target::scope_contains(&current, &normalized) {
            return Err(EnvError::PermissionDenied {
                detail: format!("cannot widen scope from `{current}` to `{normalized}`"),
            });
        }
        self.scope_stack.write().await.push(normalized.clone());
        Ok(normalized)
    }

    async fn leave_scope(&self, scope: &str) -> Result<(), EnvError> {
        let normalized = helios_ops::target::normalize_scope(scope);
        let mut stack = self.scope_stack.write().await;
        if let Some(pos) = stack.iter().rposition(|s| s == &normalized) {
            stack.remove(pos);
        } else {
            stack.pop();
        }
        Ok(())
    }

    async fn take_snapshot(
        &self,
        name: &str,
        moniker: Option<&str>,
    ) -> Result<SnapshotInfo, EnvError> {
        let hold = self.session.snapshot_hold().await.map_err(ops_to_env_err)?;
        let readiness = hold.readiness();
        let seq = self.next_id.fetch_add(1, Ordering::Relaxed);
        let id = format!(
            "snap-{name}-{seq}-gen{}",
            usize::from(readiness.has_generation_id)
        );
        self.snapshots.lock().await.insert(id.clone(), hold);
        Ok(SnapshotInfo {
            id,
            name: name.to_owned(),
            moniker: moniker.map(ToOwned::to_owned),
        })
    }

    async fn release_snapshot(&self, id: &str) -> Result<(), EnvError> {
        let hold = self.snapshots.lock().await.remove(id);
        if let Some(hold) = hold {
            hold.release().await.map_err(ops_to_env_err)?;
        }
        Ok(())
    }

    async fn begin_instruction_profile(&self, target: Option<&str>) -> Result<String, EnvError> {
        let target_name = target.unwrap_or("kernel");
        self.session
            .profile_set_instruction_sampling(true)
            .await
            .map_err(ops_to_env_err)?;
        let seq = self.next_id.fetch_add(1, Ordering::Relaxed);
        let handle = format!("{target_name}#{seq}");
        self.active_profiles.lock().await.insert(handle.clone());
        Ok(handle)
    }

    async fn end_instruction_profile(
        &self,
        handle: &str,
    ) -> Result<InstructionProfileSummary, EnvError> {
        self.active_profiles.lock().await.remove(handle);
        let profile_res = self.session.profile_instruction_samples().await;
        let stop_res = self.session.profile_set_instruction_sampling(false).await;
        let profile = profile_res.map_err(ops_to_env_err)?;
        stop_res.map_err(ops_to_env_err)?;
        let samples: u64 = profile.samples.iter().map(|s| s.count).sum();
        let target = handle
            .rsplit_once('#')
            .map_or(handle, |(name, _)| name)
            .to_owned();
        Ok(InstructionProfileSummary {
            target,
            instructions: samples,
            cycles: samples,
            samples,
            elapsed: Duration::from_nanos(profile.period_nanos.saturating_mul(samples)),
        })
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<FileMetadata>, EnvError> {
        if self.completion_mode {
            return Ok(self.completion_cache.list_dir(&self.session, path).await);
        }
        let entries = self.session.list_dir(path).await.map_err(ops_to_env_err)?;
        Ok(entries
            .into_iter()
            .map(|entry| FileMetadata {
                path: entry.path,
                name: entry.name,
                file_type: match entry.kind {
                    EntryKind::Directory => FileType::Dir,
                    EntryKind::File | EntryKind::Other => FileType::File,
                },
                size: 0,
                modified: None,
                readonly: false,
                target: None,
            })
            .collect())
    }

    async fn stat(&self, path: &str) -> Result<FileMetadata, EnvError> {
        let st = self.session.stat(path).await.map_err(ops_to_env_err)?;
        Ok(FileMetadata {
            path: st.path,
            name: st.name,
            file_type: match st.kind {
                EntryKind::Directory => FileType::Dir,
                EntryKind::File | EntryKind::Other => FileType::File,
            },
            size: st.size,
            modified: None,
            readonly: false,
            target: None,
        })
    }

    async fn read_file(&self, path: &str) -> Result<Vec<u8>, EnvError> {
        self.session.read_file(path).await.map_err(ops_to_env_err)
    }

    async fn write_file(
        &self,
        path: &str,
        data: &[u8],
        append: bool,
        _force: bool,
    ) -> Result<(), EnvError> {
        self.session
            .write_file(path, data, append)
            .await
            .map_err(ops_to_env_err)?;
        if let Some(parent) = Path::new(path).parent().and_then(Path::to_str) {
            self.completion_cache.invalidate_dir(parent).await;
        }
        Ok(())
    }

    async fn mkdir(&self, path: &str) -> Result<(), EnvError> {
        self.session.mkdir(path).await.map_err(ops_to_env_err)?;
        if let Some(parent) = Path::new(path).parent().and_then(Path::to_str) {
            self.completion_cache.invalidate_dir(parent).await;
        }
        Ok(())
    }

    async fn remove(&self, path: &str, _recursive: bool, force: bool) -> Result<(), EnvError> {
        match self.session.remove(path).await {
            Ok(()) => {
                if let Some(parent) = Path::new(path).parent().and_then(Path::to_str) {
                    self.completion_cache.invalidate_dir(parent).await;
                }
                Ok(())
            }
            Err(_) if force => Ok(()),
            Err(err) => Err(ops_to_env_err(err)),
        }
    }

    async fn copy(
        &self,
        from: &str,
        to: &str,
        _recursive: bool,
        _force: bool,
    ) -> Result<(), EnvError> {
        self.session.copy(from, to).await.map_err(ops_to_env_err)?;
        if let Some(parent) = Path::new(to).parent().and_then(Path::to_str) {
            self.completion_cache.invalidate_dir(parent).await;
        }
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str, _force: bool) -> Result<(), EnvError> {
        self.session
            .rename(from, to)
            .await
            .map_err(ops_to_env_err)?;
        self.completion_cache.invalidate_all().await;
        Ok(())
    }

    async fn touch(&self, path: &str, _no_create: bool) -> Result<(), EnvError> {
        self.session.touch(path).await.map_err(ops_to_env_err)?;
        if let Some(parent) = Path::new(path).parent().and_then(Path::to_str) {
            self.completion_cache.invalidate_dir(parent).await;
        }
        Ok(())
    }

    async fn watch(&self, _path: &str) -> Result<async_channel::Receiver<WatchEvent>, EnvError> {
        Err(EnvError::Unsupported {
            detail: "remote filesystem watch is not yet exposed by the guest debugger".to_owned(),
        })
    }

    async fn http_send(&self, request: HttpRequest) -> Result<HttpResponse, EnvError> {
        // Delegates directly through `helios_nu`'s zenwave-backed HTTP sender,
        // which shares `helios_ops::zenwave` on host builds.
        helios_nu::commands::http::zenwave_send(request).await
    }

    async fn complete_monikers(&self) -> Result<Vec<String>, EnvError> {
        let active_scope = self.active_scope().await;
        let all = self.completion_cache.monikers(&self.session).await;
        Ok(all
            .into_iter()
            .filter(|m| helios_ops::target::scope_contains(&active_scope, m))
            .collect())
    }

    async fn complete_inspect_keys(&self, prefix: &str) -> Result<Vec<String>, EnvError> {
        let active_scope = self.active_scope().await;
        let all = self
            .completion_cache
            .inspect_keys(&self.session, prefix)
            .await;
        Ok(all
            .into_iter()
            .filter(|k| helios_ops::target::scope_contains(&active_scope, k))
            .collect())
    }

    async fn complete_diagnostic_targets(&self) -> Result<Vec<String>, EnvError> {
        Ok(self
            .completion_cache
            .diagnostic_targets(&self.session)
            .await)
    }

    fn custom_command_specs(&self) -> Vec<CustomCommandSpec> {
        vec![
            spec_fleet(),
            spec_fleet_inspect(),
            spec_fleet_ps(),
            spec_fleet_exec(),
            spec_bundle(),
            spec_trace(),
            spec_host_ls(),
            spec_host_open(),
            spec_host_save(),
        ]
    }

    async fn run_custom_command<'a>(
        &'a self,
        name: &'a str,
        ctx: &'a mut AsyncCommandContext<'_, Self>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        run_custom_command_boxed(self, name, ctx, input).await
    }
}

/// Box each host-only custom command future independently so `HostEnv::run_custom_command`
/// stays 16 bytes on the caller's stack rather than combining every host command future.
fn run_custom_command_boxed<'a>(
    env: &'a HostEnv,
    name: &'a str,
    ctx: &'a mut AsyncCommandContext<'_, HostEnv>,
    input: AsyncPipelineData,
) -> Pin<Box<dyn Future<Output = Result<AsyncPipelineData, ShellError>> + Send + 'a>> {
    match name {
        "fleet" => Box::pin(run_fleet_overview(env, ctx)),
        "fleet inspect" => Box::pin(run_fleet_inspect(env, ctx)),
        "fleet ps" => Box::pin(run_fleet_ps(env, ctx)),
        "fleet exec" => Box::pin(run_fleet_exec(env, ctx)),
        "bundle" => Box::pin(run_bundle(env, ctx)),
        "trace" => Box::pin(run_trace(env, ctx)),
        "ls" => Box::pin(run_host_ls(ctx, input)),
        "open" => Box::pin(run_host_open(ctx, input)),
        "save" => Box::pin(run_host_save(ctx, input)),
        other => {
            let head = ctx.call.head;
            let msg = format!("unhandled host command `{other}`");
            Box::pin(async move { Err(shell_err("unknown host command", msg, head)) })
        }
    }
}

fn spec_fleet() -> CustomCommandSpec {
    CustomCommandSpec {
        name: "fleet".to_owned(),
        description: "Show targets in the active Helios fleet or run multi-node subcommands."
            .to_owned(),
        extra_description: "Subcommands: fleet inspect, fleet ps, fleet exec".to_owned(),
        search_terms: vec!["fleet".to_owned(), "nodes".to_owned(), "cluster".to_owned()],
        signature: Signature::build("fleet")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Table(
                    vec![
                        ("name".into(), Type::String),
                        ("uri".into(), Type::String),
                        ("labels".into(), Type::Record(vec![].into())),
                    ]
                    .into(),
                ),
            )])
            .category(Category::System),
    }
}

fn spec_fleet_inspect() -> CustomCommandSpec {
    CustomCommandSpec {
        name: "fleet inspect".to_owned(),
        description: "Query `helios:system/inspect` concurrently across every node in the fleet."
            .to_owned(),
        extra_description: String::new(),
        search_terms: vec!["fleet".to_owned(), "inspect".to_owned()],
        signature: Signature::build("fleet inspect")
            .optional(
                "prefix",
                SyntaxShape::String,
                "Optional inspect path prefix.",
            )
            .named(
                "limit",
                SyntaxShape::Int,
                "Maximum entries per node.",
                Some('n'),
            )
            .input_output_types(vec![(
                Type::Nothing,
                Type::Table(
                    vec![
                        ("target".into(), Type::String),
                        ("ok".into(), Type::Bool),
                        ("path".into(), Type::String),
                        ("value".into(), Type::Any),
                        ("error".into(), Type::String),
                    ]
                    .into(),
                ),
            )])
            .category(Category::System),
    }
}

fn spec_fleet_ps() -> CustomCommandSpec {
    CustomCommandSpec {
        name: "fleet ps".to_owned(),
        description: "List running instances concurrently across every node in the fleet."
            .to_owned(),
        extra_description: String::new(),
        search_terms: vec!["fleet".to_owned(), "ps".to_owned(), "instances".to_owned()],
        signature: Signature::build("fleet ps")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Table(
                    vec![
                        ("target".into(), Type::String),
                        ("ok".into(), Type::Bool),
                        ("pid".into(), Type::Int),
                        ("moniker".into(), Type::String),
                        ("name".into(), Type::String),
                        ("cpu".into(), Type::Float),
                        ("mem".into(), Type::Filesize),
                        ("error".into(), Type::String),
                    ]
                    .into(),
                ),
            )])
            .category(Category::System),
    }
}

fn spec_fleet_exec() -> CustomCommandSpec {
    CustomCommandSpec {
        name: "fleet exec".to_owned(),
        description: "Execute a program concurrently across every node in the fleet.".to_owned(),
        extra_description: String::new(),
        search_terms: vec!["fleet".to_owned(), "exec".to_owned(), "spawn".to_owned()],
        signature: Signature::build("fleet exec")
            .required("path", SyntaxShape::String, "Remote executable path.")
            .rest("args", SyntaxShape::String, "Arguments for the executable.")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Table(
                    vec![
                        ("target".into(), Type::String),
                        ("ok".into(), Type::Bool),
                        ("exit_code".into(), Type::Int),
                        ("stdout".into(), Type::String),
                        ("stderr".into(), Type::String),
                        ("error".into(), Type::String),
                    ]
                    .into(),
                ),
            )])
            .category(Category::System),
    }
}

fn spec_bundle() -> CustomCommandSpec {
    CustomCommandSpec {
        name: "bundle".to_owned(),
        description: "Collect a `.tar.zst` diagnostic bundle from the active Helios target."
            .to_owned(),
        extra_description: String::new(),
        search_terms: vec![
            "bundle".to_owned(),
            "diagnostics".to_owned(),
            "archive".to_owned(),
        ],
        signature: Signature::build("bundle")
            .required(
                "output",
                SyntaxShape::Filepath,
                "Local host destination path for the `.tar.zst` bundle.",
            )
            .input_output_types(vec![(
                Type::Nothing,
                Type::Record(
                    vec![
                        ("path".into(), Type::String),
                        ("target".into(), Type::String),
                        ("entries".into(), Type::Int),
                    ]
                    .into(),
                ),
            )])
            .category(Category::System),
    }
}

fn spec_trace() -> CustomCommandSpec {
    CustomCommandSpec {
        name: "trace".to_owned(),
        description: "Query recent guest tracing events as a structured table.".to_owned(),
        extra_description: String::new(),
        search_terms: vec!["trace".to_owned(), "tracing".to_owned(), "logs".to_owned()],
        signature: Signature::build("trace")
            .named(
                "min-level",
                SyntaxShape::String,
                "Minimum severity (trace, debug, info, warn, error).",
                Some('l'),
            )
            .named(
                "target-prefix",
                SyntaxShape::String,
                "Filter events whose target starts with this prefix.",
                Some('t'),
            )
            .named(
                "limit",
                SyntaxShape::Int,
                "Maximum number of events to fetch.",
                Some('n'),
            )
            .input_output_types(vec![(
                Type::Nothing,
                Type::Table(
                    vec![
                        ("timestamp".into(), Type::Int),
                        ("level".into(), Type::String),
                        ("target".into(), Type::String),
                        ("message".into(), Type::String),
                    ]
                    .into(),
                ),
            )])
            .category(Category::System),
    }
}

fn spec_host_ls() -> CustomCommandSpec {
    let mut sig = <helios_nu::commands::fs::Ls as AsyncCommand<HostEnv>>::signature(
        &helios_nu::commands::fs::Ls,
    );
    sig = sig.switch(
        "local",
        "List files on the local host filesystem instead of the remote Helios guest.",
        Some('L'),
    );
    CustomCommandSpec {
        name: "ls".to_owned(),
        description: "List files on the remote Helios VFS (or host filesystem with `--local`)."
            .to_owned(),
        extra_description: String::new(),
        search_terms: vec!["dir".to_owned(), "files".to_owned(), "local".to_owned()],
        signature: sig,
    }
}

fn spec_host_open() -> CustomCommandSpec {
    let mut sig = <helios_nu::commands::fs::Open as AsyncCommand<HostEnv>>::signature(
        &helios_nu::commands::fs::Open,
    );
    sig = sig.switch(
        "local",
        "Read file(s) from the local host filesystem instead of the remote Helios guest.",
        Some('L'),
    );
    CustomCommandSpec {
        name: "open".to_owned(),
        description: "Load a remote Helios VFS file (or host file with `--local`).".to_owned(),
        extra_description: String::new(),
        search_terms: vec!["load".to_owned(), "read".to_owned(), "local".to_owned()],
        signature: sig,
    }
}

fn spec_host_save() -> CustomCommandSpec {
    let mut sig = <helios_nu::commands::fs::Save as AsyncCommand<HostEnv>>::signature(
        &helios_nu::commands::fs::Save,
    );
    sig = sig.switch(
        "local",
        "Write output to the local host filesystem instead of the remote Helios guest.",
        Some('L'),
    );
    CustomCommandSpec {
        name: "save".to_owned(),
        description: "Save pipeline data to the remote Helios VFS (or host file with `--local`)."
            .to_owned(),
        extra_description: String::new(),
        search_terms: vec!["write".to_owned(), "local".to_owned()],
        signature: sig,
    }
}

async fn run_fleet_overview(
    env: &HostEnv,
    ctx: &mut AsyncCommandContext<'_, HostEnv>,
) -> Result<AsyncPipelineData, ShellError> {
    let head = ctx.call.head;
    let fleet = env.effective_fleet();
    let rows: Vec<Value> = fleet
        .targets()
        .iter()
        .map(|target| {
            let mut rec = Record::new();
            rec.push("name", Value::string(target.name.clone(), head));
            rec.push("uri", Value::string(target.uri.clone(), head));
            let mut labels = Record::new();
            for (k, v) in &target.labels {
                labels.push(k.clone(), Value::string(v.clone(), head));
            }
            rec.push("labels", Value::record(labels, head));
            Value::record(rec, head)
        })
        .collect();
    Ok(AsyncPipelineData::value(Value::list(rows, head), None))
}

async fn run_fleet_inspect(
    env: &HostEnv,
    ctx: &mut AsyncCommandContext<'_, HostEnv>,
) -> Result<AsyncPipelineData, ShellError> {
    let head = ctx.call.head;
    let prefix: Option<String> = ctx.call.opt(ctx.engine_state, ctx.stack, 0)?;
    let limit: Option<i64> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "limit")?;
    let limit = limit
        .and_then(|v| u32::try_from(v.max(0)).ok())
        .unwrap_or(0);
    let prefixes: Vec<String> = prefix.into_iter().collect();
    let outcomes = env.effective_fleet().inspect(prefixes, limit).await;

    let mut rows = Vec::new();
    for outcome in outcomes {
        match outcome.result {
            Ok(snapshot) => {
                for entry in snapshot.entries {
                    let mut rec = Record::new();
                    rec.push("target", Value::string(outcome.target.name.clone(), head));
                    rec.push("ok", Value::bool(true, head));
                    rec.push("path", Value::string(entry.path, head));
                    rec.push("value", proto_inspect_to_nu(entry.value, head));
                    rec.push("error", Value::nothing(head));
                    rows.push(Value::record(rec, head));
                }
            }
            Err(err) => {
                let mut rec = Record::new();
                rec.push("target", Value::string(outcome.target.name, head));
                rec.push("ok", Value::bool(false, head));
                rec.push("path", Value::nothing(head));
                rec.push("value", Value::nothing(head));
                rec.push("error", Value::string(err.to_string(), head));
                rows.push(Value::record(rec, head));
            }
        }
    }
    Ok(AsyncPipelineData::value(Value::list(rows, head), None))
}

async fn run_fleet_ps(
    env: &HostEnv,
    ctx: &mut AsyncCommandContext<'_, HostEnv>,
) -> Result<AsyncPipelineData, ShellError> {
    let head = ctx.call.head;
    let outcomes = env.effective_fleet().ps().await;
    let mut rows = Vec::new();
    for outcome in outcomes {
        match outcome.result {
            Ok(instances) => {
                for inst in instances {
                    let moniker = if inst.name.starts_with('/') {
                        inst.name.clone()
                    } else {
                        format!("/{}", inst.name)
                    };
                    let mut rec = Record::new();
                    rec.push("target", Value::string(outcome.target.name.clone(), head));
                    rec.push("ok", Value::bool(true, head));
                    rec.push(
                        "pid",
                        Value::int(i64::try_from(inst.id).unwrap_or(i64::MAX), head),
                    );
                    rec.push("moniker", Value::string(moniker, head));
                    rec.push("name", Value::string(inst.name, head));
                    rec.push("cpu", Value::float(f64::from(inst.cpu_busy) / 10.0, head));
                    rec.push(
                        "mem",
                        Value::filesize(i64::try_from(inst.memory_bytes).unwrap_or(i64::MAX), head),
                    );
                    rec.push("error", Value::nothing(head));
                    rows.push(Value::record(rec, head));
                }
            }
            Err(err) => {
                let mut rec = Record::new();
                rec.push("target", Value::string(outcome.target.name, head));
                rec.push("ok", Value::bool(false, head));
                rec.push("pid", Value::nothing(head));
                rec.push("moniker", Value::nothing(head));
                rec.push("name", Value::nothing(head));
                rec.push("cpu", Value::nothing(head));
                rec.push("mem", Value::nothing(head));
                rec.push("error", Value::string(err.to_string(), head));
                rows.push(Value::record(rec, head));
            }
        }
    }
    Ok(AsyncPipelineData::value(Value::list(rows, head), None))
}

async fn run_fleet_exec(
    env: &HostEnv,
    ctx: &mut AsyncCommandContext<'_, HostEnv>,
) -> Result<AsyncPipelineData, ShellError> {
    let head = ctx.call.head;
    let path: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
    let args: Vec<String> = ctx.call.rest(ctx.engine_state, ctx.stack, 1)?;
    let outcomes = env.effective_fleet().exec(path, args).await;
    let mut rows = Vec::new();
    for outcome in outcomes {
        let mut rec = Record::new();
        rec.push("target", Value::string(outcome.target.name, head));
        match outcome.result {
            Ok(exec) => {
                rec.push("ok", Value::bool(exec.exit_code == 0, head));
                rec.push("exit_code", Value::int(i64::from(exec.exit_code), head));
                rec.push(
                    "stdout",
                    Value::string(
                        String::from_utf8_lossy(&exec.output.stdout).into_owned(),
                        head,
                    ),
                );
                rec.push(
                    "stderr",
                    Value::string(
                        String::from_utf8_lossy(&exec.output.stderr).into_owned(),
                        head,
                    ),
                );
                rec.push("error", Value::nothing(head));
            }
            Err(err) => {
                rec.push("ok", Value::bool(false, head));
                rec.push("exit_code", Value::nothing(head));
                rec.push("stdout", Value::nothing(head));
                rec.push("stderr", Value::nothing(head));
                rec.push("error", Value::string(err.to_string(), head));
            }
        }
        rows.push(Value::record(rec, head));
    }
    Ok(AsyncPipelineData::value(Value::list(rows, head), None))
}

async fn run_bundle(
    env: &HostEnv,
    ctx: &mut AsyncCommandContext<'_, HostEnv>,
) -> Result<AsyncPipelineData, ShellError> {
    let head = ctx.call.head;
    let output: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
    let bundle = DiagnosticBundle::collect(&env.session)
        .await
        .map_err(|err| shell_err("bundle collection failed", err.to_string(), head))?;
    let written = bundle
        .write_tar_zst(&output)
        .await
        .map_err(|err| shell_err("bundle write failed", err.to_string(), head))?;
    let mut rec = Record::new();
    rec.push("path", Value::string(written.display().to_string(), head));
    rec.push(
        "target",
        Value::string(env.session.target().name.clone(), head),
    );
    rec.push(
        "entries",
        Value::int(i64::try_from(bundle.entries.len() + 1).unwrap_or(0), head),
    );
    Ok(AsyncPipelineData::value(Value::record(rec, head), None))
}

async fn run_trace(
    env: &HostEnv,
    ctx: &mut AsyncCommandContext<'_, HostEnv>,
) -> Result<AsyncPipelineData, ShellError> {
    let head = ctx.call.head;
    let min_level_str: Option<String> =
        ctx.call
            .get_flag(ctx.engine_state, ctx.stack, "min-level")?;
    let target_prefix: Option<String> =
        ctx.call
            .get_flag(ctx.engine_state, ctx.stack, "target-prefix")?;
    let limit: Option<i64> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "limit")?;
    let min_level = match min_level_str.as_deref() {
        None => Some(proto_tracing::Level::Info),
        Some("none") => None,
        Some("error") => Some(proto_tracing::Level::Error),
        Some("warn") => Some(proto_tracing::Level::Warn),
        Some("info") => Some(proto_tracing::Level::Info),
        Some("debug") => Some(proto_tracing::Level::Debug),
        Some("trace") => Some(proto_tracing::Level::Trace),
        Some(other) => {
            return Err(shell_err(
                "invalid min-level",
                format!("expected trace|debug|info|warn|error|none, got `{other}`"),
                head,
            ));
        }
    };
    let filter = proto_tracing::Filter {
        min_level,
        target_prefixes: target_prefix.into_iter().collect(),
    };
    let limit = limit
        .and_then(|v| u32::try_from(v.max(1)).ok())
        .unwrap_or(64);
    let events = env
        .session
        .trace_recent(&filter, limit)
        .await
        .map_err(|err| shell_err("trace failed", err.to_string(), head))?;
    let rows = events
        .into_iter()
        .map(|ev| {
            let mut message = String::new();
            let mut extras = Vec::new();
            for field in ev.fields {
                let rendered = match field.value {
                    proto_tracing::Value::Boolean(b) => b.to_string(),
                    proto_tracing::Value::Signed64(n) => n.to_string(),
                    proto_tracing::Value::Unsigned64(n) => n.to_string(),
                    proto_tracing::Value::Float64(f) => f.to_string(),
                    proto_tracing::Value::Text(s) => s,
                    proto_tracing::Value::Blob(b) => format!("{b:?}"),
                };
                if field.key == "message" {
                    message = rendered;
                } else {
                    extras.push(format!("{}={}", field.key, rendered));
                }
            }
            if !extras.is_empty() {
                if !message.is_empty() {
                    message.push(' ');
                }
                message.push_str(&extras.join(" "));
            }
            let mut rec = Record::new();
            rec.push(
                "timestamp",
                Value::int(i64::try_from(ev.timestamp).unwrap_or(i64::MAX), head),
            );
            rec.push("level", Value::string(format!("{:?}", ev.level), head));
            rec.push("target", Value::string(ev.target, head));
            rec.push("message", Value::string(message, head));
            Value::record(rec, head)
        })
        .collect();
    Ok(AsyncPipelineData::value(Value::list(rows, head), None))
}

async fn run_host_ls(
    ctx: &mut AsyncCommandContext<'_, HostEnv>,
    input: AsyncPipelineData,
) -> Result<AsyncPipelineData, ShellError> {
    let local = ctx.call.has_flag(ctx.engine_state, ctx.stack, "local")?;
    if !local {
        return helios_nu::commands::fs::Ls.run_async(ctx, input).await;
    }
    let head = ctx.call.head;
    let all = ctx.call.has_flag(ctx.engine_state, ctx.stack, "all")?;
    let pattern: Option<Spanned<NuGlob>> = ctx.call.opt(ctx.engine_state, ctx.stack, 0)?;
    let target_path =
        pattern.map_or_else(|| PathBuf::from("."), |p| PathBuf::from(p.item.as_ref()));

    let mut dir = tokio::fs::read_dir(&target_path).await.map_err(|err| {
        shell_err(
            "local ls failed",
            format!("failed to read `{}`: {err}", target_path.display()),
            head,
        )
    })?;
    let mut rows = Vec::new();
    while let Some(entry) = dir
        .next_entry()
        .await
        .map_err(|err| shell_err("local ls failed", err.to_string(), head))?
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !all && name.starts_with('.') {
            continue;
        }
        let meta = entry.metadata().await.ok();
        let file_type = meta.as_ref().map_or("file", |m| {
            if m.is_dir() {
                "dir"
            } else if m.file_type().is_symlink() {
                "symlink"
            } else {
                "file"
            }
        });
        let size = meta.as_ref().map_or(0, std::fs::Metadata::len);
        let modified = meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .map(|st| DateTime::<Utc>::from(st).with_timezone(&FixedOffset::east_opt(0).unwrap()));
        let mut rec = Record::new();
        rec.push("name", Value::string(name, head));
        rec.push("type", Value::string(file_type, head));
        rec.push(
            "size",
            Value::filesize(i64::try_from(size).unwrap_or(i64::MAX), head),
        );
        rec.push(
            "modified",
            modified.map_or_else(|| Value::nothing(head), |dt| Value::date(dt, head)),
        );
        rows.push(Value::record(rec, head));
    }
    Ok(AsyncPipelineData::value(Value::list(rows, head), None))
}

async fn run_host_open(
    ctx: &mut AsyncCommandContext<'_, HostEnv>,
    input: AsyncPipelineData,
) -> Result<AsyncPipelineData, ShellError> {
    let local = ctx.call.has_flag(ctx.engine_state, ctx.stack, "local")?;
    if !local {
        return helios_nu::commands::fs::Open.run_async(ctx, input).await;
    }
    let head = ctx.call.head;
    let raw_flag = ctx.call.has_flag(ctx.engine_state, ctx.stack, "raw")?;
    let paths: Vec<Spanned<NuGlob>> = ctx.call.rest(ctx.engine_state, ctx.stack, 0)?;
    if paths.is_empty() {
        return Err(ShellError::MissingParameter {
            param_name: "files".to_owned(),
            span: head,
        });
    }
    let mut outputs = Vec::with_capacity(paths.len());
    for p in paths {
        let path_str = p.item.as_ref().to_owned();
        let bytes = tokio::fs::read(&path_str).await.map_err(|err| {
            shell_err(
                "local open failed",
                format!("failed to read `{path_str}`: {err}"),
                p.span,
            )
        })?;
        let metadata = Some(PipelineMetadata {
            data_source: DataSource::FilePath(PathBuf::from(&path_str)),
            ..PipelineMetadata::default()
        });
        if !raw_flag
            && let Some(ext) = Path::new(&path_str).extension().and_then(|e| e.to_str())
            && let Some(converter) = local_converter(ext, "from")
            && ctx
                .engine_state
                .find_decl(converter.as_bytes(), &[])
                .is_some()
        {
            let input_val = match String::from_utf8(bytes.clone()) {
                Ok(s) => Value::string(s, p.span),
                Err(_) => Value::binary(bytes.clone(), p.span),
            };
            let mut rt = helios_nu::EvalRuntime {
                env: ctx.env,
                registry: ctx.registry,
                runtime_scope: ctx.runtime_scope,
            };
            if let Some(decoded) = helios_nu::eval_call_by_name_async(
                ctx.engine_state,
                ctx.stack,
                &converter,
                p.span,
                AsyncPipelineData::value(input_val, metadata.clone()),
                &mut rt,
            )
            .await?
            {
                outputs.push(decoded);
                continue;
            }
        }
        let val = match String::from_utf8(bytes) {
            Ok(s) => Value::string(s, p.span),
            Err(err) => Value::binary(err.into_bytes(), p.span),
        };
        outputs.push(AsyncPipelineData::value(val, metadata));
    }
    if outputs.len() == 1 {
        Ok(outputs.pop().unwrap_or(AsyncPipelineData::Empty))
    } else {
        let mut list = Vec::with_capacity(outputs.len());
        for item in outputs {
            list.push(item.into_value_async(head).await?);
        }
        Ok(AsyncPipelineData::value(Value::list(list, head), None))
    }
}

async fn run_host_save(
    ctx: &mut AsyncCommandContext<'_, HostEnv>,
    input: AsyncPipelineData,
) -> Result<AsyncPipelineData, ShellError> {
    let local = ctx.call.has_flag(ctx.engine_state, ctx.stack, "local")?;
    if !local {
        return helios_nu::commands::fs::Save.run_async(ctx, input).await;
    }
    let head = ctx.call.head;
    let raw_flag = ctx.call.has_flag(ctx.engine_state, ctx.stack, "raw")?;
    let append = ctx.call.has_flag(ctx.engine_state, ctx.stack, "append")?;
    let force = ctx.call.has_flag(ctx.engine_state, ctx.stack, "force")?;
    let filename: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;

    if !append && !force && tokio::fs::try_exists(&filename).await.unwrap_or(false) {
        return Err(shell_err(
            "local save refused",
            format!("file `{filename}` already exists (pass `--force` to overwrite)"),
            head,
        ));
    }

    let prepared = if !raw_flag
        && let Some(ext) = Path::new(&filename).extension().and_then(|e| e.to_str())
        && let Some(converter) = local_converter(ext, "to")
        && ctx
            .engine_state
            .find_decl(converter.as_bytes(), &[])
            .is_some()
        && !matches!(
            &input,
            AsyncPipelineData::Value(Value::String { .. } | Value::Binary { .. }, _)
                | AsyncPipelineData::ByteStream { .. }
        ) {
        let mut rt = helios_nu::EvalRuntime {
            env: ctx.env,
            registry: ctx.registry,
            runtime_scope: ctx.runtime_scope,
        };
        helios_nu::eval_call_by_name_async(
            ctx.engine_state,
            ctx.stack,
            &converter,
            head,
            input,
            &mut rt,
        )
        .await?
        .unwrap_or(AsyncPipelineData::Empty)
    } else {
        input
    };

    let bytes = prepared.into_bytes_async(head).await?;
    if append {
        use tokio::io::AsyncWriteExt as _;
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&filename)
            .await
            .map_err(|err| shell_err("local save failed", err.to_string(), head))?;
        file.write_all(&bytes)
            .await
            .map_err(|err| shell_err("local save failed", err.to_string(), head))?;
    } else {
        tokio::fs::write(&filename, &bytes)
            .await
            .map_err(|err| shell_err("local save failed", err.to_string(), head))?;
    }
    Ok(AsyncPipelineData::Empty)
}

fn local_converter(ext: &str, verb: &str) -> Option<String> {
    match ext.to_ascii_lowercase().as_str() {
        "json" => Some(format!("{verb} json")),
        "toml" => Some(format!("{verb} toml")),
        "yaml" | "yml" => Some(format!("{verb} yaml")),
        "csv" => Some(format!("{verb} csv")),
        "tsv" => Some(format!("{verb} tsv")),
        "nuon" => Some(format!("{verb} nuon")),
        _ => None,
    }
}

fn convert_inspect_value(value: proto_inspect::Value) -> InspectValue {
    match value {
        proto_inspect::Value::Boolean(v) => InspectValue::Bool(v),
        proto_inspect::Value::Signed64(v) => InspectValue::Int(v),
        proto_inspect::Value::Unsigned64(v) => InspectValue::Uint(v),
        proto_inspect::Value::Float64(v) => InspectValue::Float(v),
        proto_inspect::Value::Text(v) => InspectValue::String(v),
        proto_inspect::Value::Blob(v) => InspectValue::Bytes(v),
    }
}

fn proto_inspect_to_nu(value: proto_inspect::Value, span: Span) -> Value {
    match value {
        proto_inspect::Value::Boolean(v) => Value::bool(v, span),
        proto_inspect::Value::Signed64(v) => Value::int(v, span),
        proto_inspect::Value::Unsigned64(v) => {
            Value::int(i64::try_from(v).unwrap_or(i64::MAX), span)
        }
        proto_inspect::Value::Float64(v) => Value::float(v, span),
        proto_inspect::Value::Text(v) => Value::string(v, span),
        proto_inspect::Value::Blob(v) => Value::binary(v, span),
    }
}

fn ops_to_env_err(err: OpsError) -> EnvError {
    match err {
        OpsError::NotFound { path } => EnvError::NotFound { path },
        OpsError::AttenuationDenied { capability, scope } => EnvError::PermissionDenied {
            detail: format!("capability `{capability}` denied for scope `{scope}`"),
        },
        OpsError::InvalidPath { path, reason } => EnvError::InvalidArgument {
            detail: format!("invalid path `{path}`: {reason}"),
        },
        OpsError::InvalidGrant { spec, reason } => EnvError::InvalidArgument {
            detail: format!("invalid capability grant `{spec}`: {reason}"),
        },
        OpsError::ExecRefused { kind, detail } => EnvError::Process {
            detail: format!("{kind:?}: {detail}"),
        },
        OpsError::Http(http) => EnvError::Http {
            detail: http.to_string(),
        },
        other => EnvError::Io {
            detail: other.to_string(),
        },
    }
}

fn shell_err(title: impl Into<String>, msg: impl Into<String>, span: Span) -> ShellError {
    ShellError::Generic(GenericError::new(title.into(), msg.into(), span))
}

/// Convert a [`BTreeMap`] of labels into a formatted `k=v,...` string.
#[must_use]
pub fn format_labels(labels: &BTreeMap<String, String>) -> String {
    labels
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_io::Async;
    use helios_ops::{RpcConnection, Session, SessionOptions, Target};
    use helios_wit_rpc::inspector::helios::system::{
        filters::FilterError,
        ipc as rpc_ipc, net as rpc_net,
        profiling::{
            self as rpc_profiling, ControlError, Filter as ProfileFilter, FoldedSample,
            InstructionProfile, InstructionProfileError, InstructionSample, MetricFilter,
            MetricSample, RawProfileError, SampledCode,
        },
        programs::{
            self as rpc_programs, AotRequest, AotResult, ChildTermination, ContainerConfig,
            ContainerExecRequest, ContainerSpawnRequest, DefaultLinuxImage, ExecError, ExecOutput,
            ExecRequest, ExecResult, ExitStatus, InheritedSocket, SpawnError, SpawnRequest,
        },
        serial as rpc_serial,
        snapshot::{self as rpc_snapshot, SnapshotError},
        vsock as rpc_vsock,
    };
    use helios_wit_rpc::inspector::wasi::filesystem::{
        preopens as rpc_preopens,
        types::{
            self as rpc_fs, Advice, DescriptorFlags, DescriptorStat, DescriptorType,
            DirectoryEntry, ErrorCode, Filesize, MetadataHashValue, NewTimestamp, OpenFlags,
            PathFlags,
        },
    };
    use helios_wit_rpc::{
        Dispatcher, Endpoint, FutureReader, ResourceEntry, ResourceSlotAccess, ServerInvocation,
        StreamReader, WireError,
    };

    use super::*;
    use crate::{OutputFormat, eval_command};

    struct DropCounter(Arc<AtomicUsize>);
    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::AcqRel);
        }
    }

    enum TestResource {
        Snapshot(Arc<DropCounter>),
        Sampling(Arc<DropCounter>),
        Child(Arc<String>),
        Dir(Arc<()>),
        Unit(Arc<()>),
    }

    impl ResourceEntry for TestResource {
        fn kind_name(&self) -> &'static str {
            match self {
                Self::Snapshot(_) => "snapshot-hold",
                Self::Sampling(_) => "sampling-session",
                Self::Child(_) => "child",
                Self::Dir(_) => "descriptor",
                Self::Unit(_) => "unit",
            }
        }
    }

    macro_rules! impl_unit_slot {
        ($($marker:ty),* $(,)?) => {
            $(
                impl ResourceSlotAccess<$marker, ()> for TestResource {
                    fn into_entry(arc: Arc<()>) -> Self {
                        Self::Unit(arc)
                    }
                    fn borrow_entry(&self) -> Option<&Arc<()>> {
                        match self {
                            Self::Unit(u) => Some(u),
                            _ => None,
                        }
                    }
                    fn take_entry(self) -> Result<Arc<()>, Self> {
                        match self {
                            Self::Unit(u) => Ok(u),
                            other => Err(other),
                        }
                    }
                }
            )*
        };
    }

    impl_unit_slot!(
        rpc_ipc::Endpoint,
        rpc_programs::Container,
        rpc_net::TcpListener,
        rpc_net::TcpStream,
        rpc_serial::SerialPort,
        rpc_vsock::VsockListener,
        rpc_vsock::VsockStream,
    );

    impl ResourceSlotAccess<rpc_snapshot::SnapshotHold, DropCounter> for TestResource {
        fn into_entry(arc: Arc<DropCounter>) -> Self {
            Self::Snapshot(arc)
        }
        fn borrow_entry(&self) -> Option<&Arc<DropCounter>> {
            match self {
                Self::Snapshot(c) => Some(c),
                _ => None,
            }
        }
        fn take_entry(self) -> Result<Arc<DropCounter>, Self> {
            match self {
                Self::Snapshot(c) => Ok(c),
                other => Err(other),
            }
        }
    }

    impl ResourceSlotAccess<rpc_profiling::SamplingSession, DropCounter> for TestResource {
        fn into_entry(arc: Arc<DropCounter>) -> Self {
            Self::Sampling(arc)
        }
        fn borrow_entry(&self) -> Option<&Arc<DropCounter>> {
            match self {
                Self::Sampling(c) => Some(c),
                _ => None,
            }
        }
        fn take_entry(self) -> Result<Arc<DropCounter>, Self> {
            match self {
                Self::Sampling(c) => Ok(c),
                other => Err(other),
            }
        }
    }

    impl ResourceSlotAccess<rpc_programs::Child, String> for TestResource {
        fn into_entry(arc: Arc<String>) -> Self {
            Self::Child(arc)
        }
        fn borrow_entry(&self) -> Option<&Arc<String>> {
            match self {
                Self::Child(s) => Some(s),
                _ => None,
            }
        }
        fn take_entry(self) -> Result<Arc<String>, Self> {
            match self {
                Self::Child(s) => Ok(s),
                other => Err(other),
            }
        }
    }

    impl ResourceSlotAccess<rpc_fs::Descriptor, ()> for TestResource {
        fn into_entry(arc: Arc<()>) -> Self {
            Self::Dir(arc)
        }
        fn borrow_entry(&self) -> Option<&Arc<()>> {
            match self {
                Self::Dir(d) => Some(d),
                _ => None,
            }
        }
        fn take_entry(self) -> Result<Arc<()>, Self> {
            match self {
                Self::Dir(d) => Ok(d),
                other => Err(other),
            }
        }
    }

    struct TestSnapshot {
        live_holds: Arc<AtomicUsize>,
    }

    impl rpc_snapshot::RpcHandler for TestSnapshot {
        type SnapshotHold = DropCounter;

        async fn prepare(&self) -> Result<Self::SnapshotHold, SnapshotError> {
            self.live_holds.fetch_add(1, Ordering::AcqRel);
            Ok(DropCounter(Arc::clone(&self.live_holds)))
        }

        async fn snapshot_hold_has_generation_id(&self, _self_: &Self::SnapshotHold) -> bool {
            true
        }
    }

    struct TestProfiling {
        live_sampling: Arc<AtomicUsize>,
        fail_read: Arc<AtomicBool>,
    }

    impl rpc_profiling::RpcHandler for TestProfiling {
        type SamplingSession = DropCounter;

        async fn set_enabled(&self, _enabled: bool) -> Result<(), ControlError> {
            Ok(())
        }

        async fn clear(&self) -> Result<(), ControlError> {
            Ok(())
        }

        async fn folded(
            &self,
            _filter: ProfileFilter,
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
            self.live_sampling.fetch_add(1, Ordering::AcqRel);
            Ok(DropCounter(Arc::clone(&self.live_sampling)))
        }

        async fn instruction_samples(&self) -> Result<InstructionProfile, InstructionProfileError> {
            if self.fail_read.load(Ordering::Acquire) {
                return Err(InstructionProfileError::Denied);
            }
            Ok(InstructionProfile {
                period_nanos: 1_000,
                kernel_image_base: 0,
                samples: vec![
                    InstructionSample {
                        code: SampledCode::Native(0x1000),
                        count: 3,
                    },
                    InstructionSample {
                        code: SampledCode::Native(0x2000),
                        count: 7,
                    },
                ],
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

    struct TestPrograms {
        seen_cwd: Arc<tokio::sync::Mutex<Option<String>>>,
        seen_path: Arc<tokio::sync::Mutex<Option<String>>>,
    }

    impl rpc_programs::RpcHandler for TestPrograms {
        type Child = String;
        type Container = ();
        type Endpoint = ();
        type TcpListener = ();
        type TcpStream = ();
        type SerialPort = ();
        type VsockListener = ();
        type VsockStream = ();

        async fn child_stdin(
            &self,
            _self_: &Self::Child,
            data: StreamReader<u8>,
        ) -> FutureReader<Result<(), ()>> {
            let _ = data.collect_all().await;
            FutureReader::ready(Ok(()))
        }

        async fn child_stdout(
            &self,
            self_: &Self::Child,
        ) -> (StreamReader<u8>, FutureReader<Result<(), ()>>) {
            (
                StreamReader::from_vec(self_.as_bytes().to_vec()),
                FutureReader::ready(Ok(())),
            )
        }

        async fn child_stderr(
            &self,
            _self_: &Self::Child,
        ) -> (StreamReader<u8>, FutureReader<Result<(), ()>>) {
            (StreamReader::empty(), FutureReader::ready(Ok(())))
        }

        async fn child_instance_id(&self, _self_: &Self::Child) -> u64 {
            55
        }

        async fn child_signal(&self, _self_: &Self::Child, _sig: u8) -> Result<(), SpawnError> {
            Ok(())
        }

        async fn child_wait(&self, _self_: &Self::Child) -> Result<ExitStatus, SpawnError> {
            Ok(ExitStatus {
                instance_id: 55,
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
            request: SpawnRequest<
                Self::TcpListener,
                Self::VsockListener,
                Self::TcpStream,
                Self::VsockStream,
                Self::SerialPort,
                Self::Endpoint,
            >,
        ) -> Result<Self::Child, SpawnError> {
            *self.seen_cwd.lock().await = request.cwd.clone();
            *self.seen_path.lock().await = Some(request.path.clone());
            Ok(format!("ran:{}", request.path))
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

    struct TestPreopens;
    impl rpc_preopens::RpcHandler for TestPreopens {
        type Descriptor = ();
        async fn get_directories(&self) -> Vec<(Self::Descriptor, String)> {
            vec![((), "/".to_owned())]
        }
    }

    struct TestFs;
    impl rpc_fs::RpcHandler for TestFs {
        type Descriptor = ();
        async fn descriptor_read_via_stream(
            &self,
            _self_: &Self::Descriptor,
            _offset: Filesize,
        ) -> (StreamReader<u8>, FutureReader<Result<(), ErrorCode>>) {
            (StreamReader::empty(), FutureReader::ready(Ok(())))
        }
        async fn descriptor_write_via_stream(
            &self,
            _self_: &Self::Descriptor,
            _data: StreamReader<u8>,
            _offset: Filesize,
        ) -> FutureReader<Result<(), ErrorCode>> {
            FutureReader::ready(Ok(()))
        }
        async fn descriptor_append_via_stream(
            &self,
            _self_: &Self::Descriptor,
            _data: StreamReader<u8>,
        ) -> FutureReader<Result<(), ErrorCode>> {
            FutureReader::ready(Ok(()))
        }
        async fn descriptor_advise(
            &self,
            _self_: &Self::Descriptor,
            _offset: Filesize,
            _length: Filesize,
            _advice: Advice,
        ) -> Result<(), ErrorCode> {
            Ok(())
        }
        async fn descriptor_sync_data(&self, _self_: &Self::Descriptor) -> Result<(), ErrorCode> {
            Ok(())
        }
        async fn descriptor_get_flags(
            &self,
            _self_: &Self::Descriptor,
        ) -> Result<DescriptorFlags, ErrorCode> {
            Ok(DescriptorFlags::READ)
        }
        async fn descriptor_get_type(
            &self,
            _self_: &Self::Descriptor,
        ) -> Result<DescriptorType, ErrorCode> {
            Ok(DescriptorType::Directory)
        }
        async fn descriptor_set_size(
            &self,
            _self_: &Self::Descriptor,
            _size: Filesize,
        ) -> Result<(), ErrorCode> {
            Ok(())
        }
        async fn descriptor_set_times(
            &self,
            _self_: &Self::Descriptor,
            _a: NewTimestamp,
            _m: NewTimestamp,
        ) -> Result<(), ErrorCode> {
            Ok(())
        }
        async fn descriptor_read_directory(
            &self,
            _self_: &Self::Descriptor,
        ) -> (
            StreamReader<DirectoryEntry>,
            FutureReader<Result<(), ErrorCode>>,
        ) {
            (
                StreamReader::from_vec(vec![DirectoryEntry {
                    r#type: DescriptorType::RegularFile,
                    name: "demo".to_owned(),
                }]),
                FutureReader::ready(Ok(())),
            )
        }
        async fn descriptor_sync(&self, _self_: &Self::Descriptor) -> Result<(), ErrorCode> {
            Ok(())
        }
        async fn descriptor_create_directory_at(
            &self,
            _self_: &Self::Descriptor,
            _path: String,
        ) -> Result<(), ErrorCode> {
            Ok(())
        }
        async fn descriptor_stat(
            &self,
            _self_: &Self::Descriptor,
        ) -> Result<DescriptorStat, ErrorCode> {
            Ok(DescriptorStat {
                r#type: DescriptorType::RegularFile,
                link_count: 1,
                size: 4,
                data_access_timestamp: None,
                data_modification_timestamp: None,
                status_change_timestamp: None,
            })
        }
        async fn descriptor_stat_at(
            &self,
            _self_: &Self::Descriptor,
            _path_flags: PathFlags,
            path: String,
        ) -> Result<DescriptorStat, ErrorCode> {
            if path == "demo" || path == "usr/bin/demo" || path == "/usr/bin/demo" {
                Ok(DescriptorStat {
                    r#type: DescriptorType::RegularFile,
                    link_count: 1,
                    size: 4,
                    data_access_timestamp: None,
                    data_modification_timestamp: None,
                    status_change_timestamp: None,
                })
            } else {
                Err(ErrorCode::NoEntry)
            }
        }
        async fn descriptor_set_times_at(
            &self,
            _self_: &Self::Descriptor,
            _path_flags: PathFlags,
            _path: String,
            _a: NewTimestamp,
            _m: NewTimestamp,
        ) -> Result<(), ErrorCode> {
            Ok(())
        }
        async fn descriptor_link_at(
            &self,
            _self_: &Self::Descriptor,
            _old_path_flags: PathFlags,
            _old_path: String,
            _new_descriptor: &Self::Descriptor,
            _new_path: String,
        ) -> Result<(), ErrorCode> {
            Ok(())
        }
        async fn descriptor_open_at(
            &self,
            _self_: &Self::Descriptor,
            _path_flags: PathFlags,
            _path: String,
            _open_flags: OpenFlags,
            _flags: DescriptorFlags,
        ) -> Result<Self::Descriptor, ErrorCode> {
            Ok(())
        }
        async fn descriptor_readlink_at(
            &self,
            _self_: &Self::Descriptor,
            _path: String,
        ) -> Result<String, ErrorCode> {
            Err(ErrorCode::Invalid)
        }
        async fn descriptor_remove_directory_at(
            &self,
            _self_: &Self::Descriptor,
            _path: String,
        ) -> Result<(), ErrorCode> {
            Ok(())
        }
        async fn descriptor_rename_at(
            &self,
            _self_: &Self::Descriptor,
            _old_path: String,
            _new_descriptor: &Self::Descriptor,
            _new_path: String,
        ) -> Result<(), ErrorCode> {
            Ok(())
        }
        async fn descriptor_symlink_at(
            &self,
            _self_: &Self::Descriptor,
            _old_path: String,
            _new_path: String,
        ) -> Result<(), ErrorCode> {
            Ok(())
        }
        async fn descriptor_unlink_file_at(
            &self,
            _self_: &Self::Descriptor,
            _path: String,
        ) -> Result<(), ErrorCode> {
            Ok(())
        }
        async fn descriptor_is_same_object(
            &self,
            _self_: &Self::Descriptor,
            _other: &Self::Descriptor,
        ) -> bool {
            true
        }
        async fn descriptor_metadata_hash(
            &self,
            _self_: &Self::Descriptor,
        ) -> Result<MetadataHashValue, ErrorCode> {
            Ok(MetadataHashValue { lower: 0, upper: 0 })
        }
        async fn descriptor_metadata_hash_at(
            &self,
            _self_: &Self::Descriptor,
            _path_flags: PathFlags,
            _path: String,
        ) -> Result<MetadataHashValue, ErrorCode> {
            Ok(MetadataHashValue { lower: 0, upper: 0 })
        }
    }

    struct TestDispatcher {
        snapshot: rpc_snapshot::RpcServer<TestSnapshot>,
        profiling: rpc_profiling::RpcServer<TestProfiling>,
        programs: rpc_programs::RpcServer<TestPrograms>,
        preopens: rpc_preopens::RpcServer<TestPreopens>,
        fs: rpc_fs::RpcServer<TestFs>,
    }

    impl Dispatcher for TestDispatcher {
        type Resource = TestResource;

        fn supports(&self, instance: &str, func: &str) -> bool {
            self.snapshot.supports_call(instance, func)
                || self.profiling.supports_call(instance, func)
                || self.programs.supports_call(instance, func)
                || self.preopens.supports_call(instance, func)
                || self.fs.supports_call(instance, func)
        }

        async fn dispatch<'a>(
            &'a self,
            ctx: ServerInvocation<'a, Self::Resource>,
            instance: &'a str,
            func: &'a str,
        ) -> Result<(), WireError> {
            if self.snapshot.supports_call(instance, func) {
                self.snapshot.dispatch_with(ctx, instance, func).await
            } else if self.profiling.supports_call(instance, func) {
                self.profiling.dispatch_with(ctx, instance, func).await
            } else if self.programs.supports_call(instance, func) {
                self.programs.dispatch_with(ctx, instance, func).await
            } else if self.preopens.supports_call(instance, func) {
                self.preopens.dispatch_with(ctx, instance, func).await
            } else if self.fs.supports_call(instance, func) {
                self.fs.dispatch_with(ctx, instance, func).await
            } else {
                Err(WireError::MalformedPayload {
                    context: "TestDispatcher".to_owned(),
                    detail: format!("unsupported {instance}.{func}"),
                })
            }
        }
    }

    struct EnvFixture {
        env: HostEnv,
        live_holds: Arc<AtomicUsize>,
        live_sampling: Arc<AtomicUsize>,
        fail_read: Arc<AtomicBool>,
        seen_cwd: Arc<tokio::sync::Mutex<Option<String>>>,
        seen_path: Arc<tokio::sync::Mutex<Option<String>>>,
        server_task: tokio::task::JoinHandle<()>,
    }

    fn spawn_env_fixture() -> EnvFixture {
        let (host, guest) = UnixStream::pair().expect("pair");
        host.set_nonblocking(true).expect("nonblocking");
        guest.set_nonblocking(true).expect("nonblocking");
        let host_read = host.try_clone().expect("clone");
        let guest_read = guest.try_clone().expect("clone");
        let conn = RpcConnection::from_split(
            Box::new(Async::new(host_read).expect("async")),
            Box::new(Async::new(host).expect("async")),
        );
        let session = Session::from_connection(
            Target::new("env-test", "serial:///tmp/env.sock").expect("target"),
            conn,
            SessionOptions::default(),
        );
        let live_holds = Arc::new(AtomicUsize::new(0));
        let live_sampling = Arc::new(AtomicUsize::new(0));
        let fail_read = Arc::new(AtomicBool::new(false));
        let seen_cwd = Arc::new(tokio::sync::Mutex::new(None));
        let seen_path = Arc::new(tokio::sync::Mutex::new(None));

        let dispatcher = TestDispatcher {
            snapshot: rpc_snapshot::RpcServer::new(TestSnapshot {
                live_holds: Arc::clone(&live_holds),
            }),
            profiling: rpc_profiling::RpcServer::new(TestProfiling {
                live_sampling: Arc::clone(&live_sampling),
                fail_read: Arc::clone(&fail_read),
            }),
            programs: rpc_programs::RpcServer::new(TestPrograms {
                seen_cwd: Arc::clone(&seen_cwd),
                seen_path: Arc::clone(&seen_path),
            }),
            preopens: rpc_preopens::RpcServer::new(TestPreopens),
            fs: rpc_fs::RpcServer::new(TestFs),
        };
        let ep = Endpoint::new(
            Async::new(guest_read).expect("async"),
            Async::new(guest).expect("async"),
            dispatcher,
        );
        let server_task = tokio::spawn(async move {
            let _ = ep.drive().await;
        });
        EnvFixture {
            env: HostEnv::new(session, None),
            live_holds,
            live_sampling,
            fail_read,
            seen_cwd,
            seen_path,
            server_task,
        }
    }

    async fn assert_eventually_zero(counter: &AtomicUsize, label: &str) {
        for _ in 0..100 {
            if counter.load(Ordering::Acquire) == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(counter.load(Ordering::Acquire), 0, "{label}");
    }

    #[tokio::test]
    async fn host_env_holds_snapshots_cleans_up_on_errors_sums_samples_and_preserves_cwd() {
        let EnvFixture {
            env,
            live_holds,
            live_sampling,
            fail_read,
            seen_cwd,
            seen_path,
            server_task,
        } = spawn_env_fixture();

        // 1. Snapshot hold stays live across take_snapshot until release_snapshot.
        let snap = env.take_snapshot("s1", None).await.expect("take_snapshot");
        assert_eq!(live_holds.load(Ordering::Acquire), 1);
        env.release_snapshot(&snap.id)
            .await
            .expect("release_snapshot");
        assert_eventually_zero(
            &live_holds,
            "release_snapshot must drop remote SnapshotHold",
        )
        .await;

        // 2. with-snapshot and with-instruction-profile release/stop even when closure fails.
        let snap_err = eval_command(
            env.clone(),
            r#"with-snapshot failing { error make { msg: "boom" } }"#,
            OutputFormat::Json,
        )
        .await;
        assert!(snap_err.is_err());
        assert_eventually_zero(&live_holds, "with-snapshot must release hold on error").await;

        let prof_err = eval_command(
            env.clone(),
            r#"with-instruction-profile { error make { msg: "boom" } }"#,
            OutputFormat::Json,
        )
        .await;
        assert!(prof_err.is_err());
        assert_eventually_zero(
            &live_sampling,
            "with-instruction-profile must stop sampling on error",
        )
        .await;

        // 3. end_instruction_profile sums sample.count and stops sampling even on read failure.
        let handle = env
            .begin_instruction_profile(None)
            .await
            .expect("begin profile");
        assert_eq!(live_sampling.load(Ordering::Acquire), 1);
        let summary = env
            .end_instruction_profile(&handle)
            .await
            .expect("end profile");
        assert_eq!(summary.samples, 10);
        assert_eventually_zero(&live_sampling, "end_instruction_profile must stop sampling").await;

        fail_read.store(true, Ordering::Release);
        let handle2 = env
            .begin_instruction_profile(None)
            .await
            .expect("begin profile 2");
        assert!(env.end_instruction_profile(&handle2).await.is_err());
        assert_eventually_zero(
            &live_sampling,
            "end_instruction_profile must stop sampling on read error",
        )
        .await;

        // 4. cleanup_active clears dangling snapshots & active profiles (Ctrl+C safety).
        let _dangling = env.take_snapshot("ctrlc", None).await.expect("snap");
        let _dangling_prof = env.begin_instruction_profile(None).await.expect("prof");
        assert_eq!(live_holds.load(Ordering::Acquire), 1);
        assert_eq!(live_sampling.load(Ordering::Acquire), 1);
        env.cleanup_active().await;
        assert_eventually_zero(&live_holds, "cleanup_active must drop snapshots").await;
        assert_eventually_zero(&live_sampling, "cleanup_active must stop sampling").await;

        // 5. spawn_external preserves non-empty cwd with empty grants & resolves PATH binary.
        let proc = env
            .spawn_external(ExternalSpawnRequest {
                program: "demo".to_owned(),
                args: Vec::new(),
                env: BTreeMap::from([("PATH".to_owned(), "/usr/bin:/bin".to_owned())]),
                cwd: "/work".to_owned(),
                scope: None,
                stdin: None,
                capture_stdout: true,
                capture_stderr: true,
                grants: Vec::new(),
            })
            .await
            .expect("spawn_external");
        let _ = proc.exit_code.recv().await;
        assert_eq!(seen_cwd.lock().await.as_deref(), Some("/work"));
        assert_eq!(seen_path.lock().await.as_deref(), Some("/usr/bin/demo"));

        server_task.abort();
    }
}
