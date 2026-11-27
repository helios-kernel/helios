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
    AsyncCommand, AsyncCommandContext, AsyncPipelineData, BtrfsSubvolumeInfo, ComponentAddRequest,
    ComponentInfo, ComponentSubtreeSource, ContainerCreateRequest, ContainerExecOutput,
    ContainerExecRequest, ContainerInfo, ContainerMountSharingSpec, ContainerSpawnRequest,
    CustomCommandSpec, DEFAULT_LINUX_IMAGE_REF, EnvError, ExecutableMatch, ExternalProcess,
    ExternalSpawnRequest, FileMetadata, FileType, GrantSpec, HeliosEnv, HttpRequest, HttpResponse,
    InspectEntry, InspectValue, InstructionProfileSummary, LinuxImageClearResult, LinuxImageInfo,
    MountEntryInfo, MountRequestSpec, MountSharingSpec, MountSourceSpec, OciImageInspect,
    OciImageSummary, ProcessInfo, STREAM_CHANNEL_CAPACITY, SnapshotInfo, SysCpuInfo, SysDiskInfo,
    SysHostInfo, SysMemInfo, SysNetInfo, VmInfo, VmRunRequest, WatchEvent, normalize_vfs_path,
};
use helios_ops::helios_oci::{Arch, PulledImage, ResolvedUser, UserDefaultImage};
use helios_ops::linux::{
    Container as OpsContainer, ContainerBuilder as OpsContainerBuilder,
    ContainerMount as OpsContainerMount, ContainerMountSharing as OpsContainerMountSharing,
};
use helios_ops::{
    DiagnosticBundle, Fleet, MicroVmConfig, NonFsGrant, NonFsGrants, OpsError, PullOptions,
    Session, SpawnRequest, VmDisk, VmShare,
};
use helios_wit_rpc::inspector::helios::system::{
    btrfs as rpc_btrfs, inspect as proto_inspect, mounts as rpc_mounts, programs as rpc_programs,
    tracing as proto_tracing,
};
use helios_wit_rpc::inspector_fs::EntryKind;
use nu_engine::CallExt as _;
use nu_protocol::{
    Category, DataSource, NuGlob, PipelineMetadata, Record, ShellError, Signature, Span, Spanned,
    SyntaxShape, Type, Value, shell_error::generic::GenericError,
};
use tokio::sync::RwLock;

use crate::cache::RemoteCompletionCache;

const DEFAULT_LINUX_SEARCH_DIRS: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];

struct HostContainerEntry {
    info: ContainerInfo,
    container: OpsContainer,
}

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
    containers: Arc<tokio::sync::Mutex<BTreeMap<String, Arc<HostContainerEntry>>>>,
    vms: Arc<tokio::sync::Mutex<Vec<VmInfo>>>,
    default_image_cleared: Arc<RwLock<bool>>,
    default_image_ref: Arc<RwLock<Option<String>>>,
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
            containers: Arc::new(tokio::sync::Mutex::new(BTreeMap::new())),
            vms: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            default_image_cleared: Arc::new(RwLock::new(false)),
            default_image_ref: Arc::new(RwLock::new(None)),
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

    async fn ensure_remote_oci_image(
        &self,
        reference: &str,
        arch: Option<&str>,
    ) -> Result<PulledImage, EnvError> {
        let arch_override = parse_oci_arch(arch)?;
        let oci = self.session.oci();
        match oci.inspect(reference).await {
            Ok(img) if arch_override.is_none_or(|wanted| img.arch == wanted) => Ok(img),
            Ok(_) | Err(OpsError::NotFound { .. }) => oci
                .pull_with_options(
                    reference,
                    PullOptions {
                        arch: arch_override,
                        ..Default::default()
                    },
                )
                .await
                .map_err(ops_to_env_err),
            Err(err) => Err(ops_to_env_err(err)),
        }
    }

    /// Ensure the remote session has an active default Linux image:
    /// 1. Honors an already-active or inherited `session.get_default_image()`.
    /// 2. Respects an explicit `linux image clear` in the current shell session.
    /// 3. Loads any persisted per-principal preference from the remote OCI store.
    /// 4. When `allow_auto_pull` is `true`, lazily pulls `alpine` and installs it via
    ///    `session.set_default_image`.
    async fn ensure_default_linux_image(
        &self,
        allow_auto_pull: bool,
    ) -> Result<Option<rpc_programs::DefaultLinuxImage>, EnvError> {
        if let Ok(Some(active)) = self.session.get_default_image().await {
            return Ok(Some(active));
        }
        if *self.default_image_cleared.read().await {
            return Ok(None);
        }
        let principal = self.session.whoami();
        if let Ok(users) = load_remote_default_images(&self.session).await
            && let Some(saved) = users.get(&principal)
        {
            let img = default_linux_image_from_pref(saved);
            self.session
                .set_default_image(Some(img.clone()))
                .await
                .map_err(ops_to_env_err)?;
            *self.default_image_ref.write().await = Some(saved.image_ref.clone());
            return Ok(Some(img));
        }
        if !allow_auto_pull {
            return Ok(None);
        }
        let pulled = self
            .ensure_remote_oci_image(DEFAULT_LINUX_IMAGE_REF, None)
            .await?;
        let default_img = default_linux_image_from_remote_oci(&self.session, &pulled).await?;
        self.session
            .set_default_image(Some(default_img.clone()))
            .await
            .map_err(ops_to_env_err)?;
        *self.default_image_ref.write().await = Some(pulled.reference.canonical());
        Ok(Some(default_img))
    }

    async fn probe_in_default_image(
        &self,
        default_img: &rpc_programs::DefaultLinuxImage,
        name: &str,
        search_dirs: &[String],
    ) -> Option<ExecutableMatch> {
        if name.starts_with('/') {
            let in_image = join_under_root(&default_img.root_path, name);
            match self.session.stat(&in_image).await {
                Ok(st) if st.kind != EntryKind::Directory => {
                    return Some(ExecutableMatch {
                        command: name.to_owned(),
                        path: name.to_owned(),
                    });
                }
                Err(OpsError::AttenuationDenied { .. }) => {
                    return Some(ExecutableMatch {
                        command: name.to_owned(),
                        path: name.to_owned(),
                    });
                }
                _ => return None,
            }
        }
        let mut dirs: Vec<String> = search_dirs.to_vec();
        for fallback in DEFAULT_LINUX_SEARCH_DIRS {
            if !dirs.iter().any(|d| d == fallback) {
                dirs.push((*fallback).to_owned());
            }
        }
        for dir in dirs {
            let candidate = normalize_vfs_path(&dir, name);
            let in_image = join_under_root(&default_img.root_path, &candidate);
            if let Ok(st) = self.session.stat(&in_image).await
                && st.kind != EntryKind::Directory
            {
                return Some(ExecutableMatch {
                    command: name.to_owned(),
                    path: candidate,
                });
            }
        }
        None
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

        let mut resolved = self.resolve_executable(&request.program, &path_env).await?;
        if resolved.is_none()
            && let Ok(Some(default_img)) = self.ensure_default_linux_image(true).await
        {
            resolved = self
                .probe_in_default_image(&default_img, &request.program, &path_env)
                .await;
        }
        let program_path = match resolved {
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

        Ok(wire_ops_child_streams(
            child,
            request.capture_stdout,
            request.capture_stderr,
            "remote",
        ))
    }

    async fn resolve_executable(
        &self,
        name: &str,
        path_env: &[String],
    ) -> Result<Option<ExecutableMatch>, EnvError> {
        let search_dirs: Vec<String> = if path_env.is_empty() {
            vec!["/bin".to_owned()]
        } else {
            path_env.to_vec()
        };
        if name.starts_with('/') {
            if let Ok(st) = self.session.stat(name).await
                && st.kind != EntryKind::Directory
            {
                return Ok(Some(ExecutableMatch {
                    command: name.to_owned(),
                    path: name.to_owned(),
                }));
            }
        } else {
            for dir in &search_dirs {
                let entries = self.completion_cache.list_dir(&self.session, dir).await;
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
        }

        if let Ok(Some(default_img)) = self.ensure_default_linux_image(false).await
            && let Some(found) = self
                .probe_in_default_image(&default_img, name, &search_dirs)
                .await
        {
            return Ok(Some(found));
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

    async fn linux_image_get(&self) -> Result<LinuxImageInfo, EnvError> {
        let principal = self.session.whoami();
        let active = self
            .session
            .get_default_image()
            .await
            .map_err(ops_to_env_err)?;
        let saved = load_remote_default_images(&self.session)
            .await
            .ok()
            .and_then(|mut map| map.remove(&principal));

        if let Some(img) = active {
            let cached_ref = self.default_image_ref.read().await.clone();
            let (uid, gid) = img
                .credentials
                .as_ref()
                .map_or((None, None), |c| (Some(c.uid), Some(c.gid)));
            return Ok(LinuxImageInfo {
                principal,
                image_ref: saved
                    .as_ref()
                    .map(|p| p.image_ref.clone())
                    .or(cached_ref)
                    .or_else(|| Some(img.root_path.clone())),
                default_ref: DEFAULT_LINUX_IMAGE_REF.to_owned(),
                rootfs_path: Some(img.root_path),
                active: true,
                persisted: saved.is_some(),
                env: img.env,
                uid,
                gid,
            });
        }

        if let Some(pref) = saved {
            return Ok(LinuxImageInfo {
                principal,
                image_ref: Some(pref.image_ref),
                default_ref: DEFAULT_LINUX_IMAGE_REF.to_owned(),
                rootfs_path: Some(pref.rootfs_path),
                active: false,
                persisted: true,
                env: pref.env,
                uid: Some(pref.credentials.uid),
                gid: Some(pref.credentials.gid),
            });
        }

        Ok(LinuxImageInfo {
            principal,
            image_ref: None,
            default_ref: DEFAULT_LINUX_IMAGE_REF.to_owned(),
            rootfs_path: None,
            active: false,
            persisted: false,
            env: Vec::new(),
            uid: None,
            gid: None,
        })
    }

    async fn linux_image_set(
        &self,
        image_ref: &str,
        arch: Option<&str>,
    ) -> Result<LinuxImageInfo, EnvError> {
        let principal = self.session.whoami();
        let pulled = self.ensure_remote_oci_image(image_ref, arch).await?;
        let resolved_user = resolve_remote_oci_user(&self.session, &pulled).await?;
        let rootfs_path = pulled.rootfs_path().to_string_lossy().into_owned();
        let env_pairs = pulled.config.config.env_pairs();
        let default_img = rpc_programs::DefaultLinuxImage {
            root_path: rootfs_path.clone(),
            env: env_pairs.clone(),
            credentials: Some(rpc_programs::ContainerCredentials {
                uid: resolved_user.uid,
                gid: resolved_user.gid,
                supplementary_groups: resolved_user.supplementary_groups.clone(),
            }),
        };
        self.session
            .set_default_image(Some(default_img))
            .await
            .map_err(ops_to_env_err)?;

        let canonical = pulled.reference.canonical();
        let pref = UserDefaultImage {
            image_ref: canonical.clone(),
            rootfs_path: rootfs_path.clone(),
            env: env_pairs.clone(),
            credentials: resolved_user.clone(),
        };
        let mut users = load_remote_default_images(&self.session).await?;
        users.insert(principal.clone(), pref);
        save_remote_default_images(&self.session, &users).await?;

        *self.default_image_cleared.write().await = false;
        *self.default_image_ref.write().await = Some(canonical.clone());
        self.completion_cache.invalidate_all().await;

        Ok(LinuxImageInfo {
            principal,
            image_ref: Some(canonical),
            default_ref: DEFAULT_LINUX_IMAGE_REF.to_owned(),
            rootfs_path: Some(rootfs_path),
            active: true,
            persisted: true,
            env: env_pairs,
            uid: Some(resolved_user.uid),
            gid: Some(resolved_user.gid),
        })
    }

    async fn linux_image_clear(&self) -> Result<LinuxImageClearResult, EnvError> {
        let principal = self.session.whoami();
        let mut users = load_remote_default_images(&self.session).await?;
        let removed = users.remove(&principal);
        if removed.is_some() {
            save_remote_default_images(&self.session, &users).await?;
        }
        let previous_ref =
            removed
                .map(|p| p.image_ref)
                .or(self.default_image_ref.write().await.take());
        self.session
            .set_default_image(None)
            .await
            .map_err(ops_to_env_err)?;
        *self.default_image_cleared.write().await = true;
        self.completion_cache.invalidate_all().await;
        Ok(LinuxImageClearResult {
            principal,
            cleared: true,
            previous_ref,
        })
    }

    async fn component_list(&self) -> Result<Vec<ComponentInfo>, EnvError> {
        let session = self.scoped_session().await?;
        let list = session.components().list().await.map_err(ops_to_env_err)?;
        Ok(list
            .into_iter()
            .map(|c| ComponentInfo {
                moniker: c.moniker,
                program: c.program,
                state: c.state,
                instance_id: c.instance_id,
                restarts: c.restarts,
            })
            .collect())
    }

    async fn component_status(&self, moniker: &str) -> Result<ComponentInfo, EnvError> {
        let session = self.scoped_session().await?;
        let c = session
            .components()
            .status(moniker)
            .await
            .map_err(ops_to_env_err)?;
        Ok(ComponentInfo {
            moniker: c.moniker,
            program: c.program,
            state: c.state,
            instance_id: c.instance_id,
            restarts: c.restarts,
        })
    }

    async fn component_start(&self, moniker: &str) -> Result<ComponentInfo, EnvError> {
        let session = self.scoped_session().await?;
        let c = session
            .components()
            .start(moniker)
            .await
            .map_err(ops_to_env_err)?;
        self.completion_cache.invalidate_all().await;
        Ok(ComponentInfo {
            moniker: c.moniker,
            program: c.program,
            state: c.state,
            instance_id: c.instance_id,
            restarts: c.restarts,
        })
    }

    async fn component_stop(&self, moniker: &str) -> Result<(), EnvError> {
        let session = self.scoped_session().await?;
        session
            .components()
            .stop(moniker)
            .await
            .map_err(ops_to_env_err)?;
        self.completion_cache.invalidate_all().await;
        Ok(())
    }

    async fn component_restart(&self, moniker: &str) -> Result<ComponentInfo, EnvError> {
        let session = self.scoped_session().await?;
        let c = session
            .components()
            .restart(moniker)
            .await
            .map_err(ops_to_env_err)?;
        self.completion_cache.invalidate_all().await;
        Ok(ComponentInfo {
            moniker: c.moniker,
            program: c.program,
            state: c.state,
            instance_id: c.instance_id,
            restarts: c.restarts,
        })
    }

    async fn component_add(&self, request: ComponentAddRequest) -> Result<String, EnvError> {
        let session = self.scoped_session().await?;
        let mounted = match request.source {
            ComponentSubtreeSource::GuestDir { subtree_name, path } => {
                session
                    .components()
                    .mount_dynamic_dir(&request.parent_moniker, &subtree_name, &path)
                    .await
            }
            ComponentSubtreeSource::Manifests(manifests) => {
                session
                    .components()
                    .mount_dynamic_manifests(&request.parent_moniker, manifests)
                    .await
            }
        }
        .map_err(ops_to_env_err)?;
        self.completion_cache.invalidate_all().await;
        Ok(mounted)
    }

    async fn component_remove(&self, moniker: &str) -> Result<(), EnvError> {
        let session = self.scoped_session().await?;
        session
            .components()
            .unmount_dynamic(moniker)
            .await
            .map_err(ops_to_env_err)?;
        self.completion_cache.invalidate_all().await;
        Ok(())
    }

    async fn oci_pull(
        &self,
        reference: &str,
        arch: Option<&str>,
    ) -> Result<OciImageSummary, EnvError> {
        let arch_override = parse_oci_arch(arch)?;
        let pulled = self
            .session
            .oci()
            .pull_with_options(
                reference,
                PullOptions {
                    arch: arch_override,
                    ..Default::default()
                },
            )
            .await
            .map_err(ops_to_env_err)?;
        self.completion_cache.invalidate_all().await;
        Ok(pulled_to_summary(&pulled))
    }

    async fn oci_list(&self) -> Result<Vec<OciImageSummary>, EnvError> {
        let list = self.session.oci().list().await.map_err(ops_to_env_err)?;
        Ok(list.iter().map(pulled_to_summary).collect())
    }

    async fn oci_inspect(&self, reference: &str) -> Result<OciImageInspect, EnvError> {
        let img = self
            .session
            .oci()
            .inspect(reference)
            .await
            .map_err(ops_to_env_err)?;
        Ok(pulled_to_inspect(&img))
    }

    async fn oci_remove(&self, reference: &str) -> Result<(), EnvError> {
        self.session
            .oci()
            .remove(reference)
            .await
            .map_err(ops_to_env_err)?;
        self.completion_cache.invalidate_all().await;
        Ok(())
    }

    async fn container_create(
        &self,
        request: ContainerCreateRequest,
    ) -> Result<ContainerInfo, EnvError> {
        let (mut builder, rootfs, image_label) = match (&request.image, &request.rootfs) {
            (Some(image_ref), _) => {
                let pulled = self.ensure_remote_oci_image(image_ref, None).await?;
                let rootfs = pulled.rootfs_path().to_string_lossy().into_owned();
                let builder = match OpsContainerBuilder::from_image(&pulled) {
                    Ok(b) => b,
                    Err(_) => {
                        let resolved_user = resolve_remote_oci_user(&self.session, &pulled).await?;
                        let mut b = OpsContainerBuilder::ephemeral(rootfs.clone())
                            .user(resolved_user.uid, resolved_user.gid)
                            .shared_owner(resolved_user.uid, resolved_user.gid);
                        for (k, v) in pulled.config.config.env_pairs() {
                            b = b.env(k, v);
                        }
                        if let Some(wd) = pulled.config.config.effective_working_dir() {
                            b = b.working_dir(wd);
                        }
                        b
                    }
                };
                (builder, rootfs, Some(pulled.reference.canonical()))
            }
            (None, Some(path)) => (
                OpsContainerBuilder::ephemeral(path.clone()),
                path.clone(),
                None,
            ),
            (None, None) => {
                return Err(EnvError::InvalidArgument {
                    detail: String::from("container create requires `--image` or `--rootfs`"),
                });
            }
        };

        for mount in &request.mounts {
            let rights = parse_ops_fs_rights(&mount.mode)?;
            let sharing = match mount.sharing {
                ContainerMountSharingSpec::Private => OpsContainerMountSharing::Private,
                ContainerMountSharingSpec::Shared => OpsContainerMountSharing::Shared,
                ContainerMountSharingSpec::EphemeralOverlay => {
                    OpsContainerMountSharing::EphemeralOverlay
                }
            };
            builder = builder.mount(OpsContainerMount {
                source_path: mount.source_path.clone(),
                target_path: mount.target_path.clone(),
                rights,
                sharing,
            });
        }
        if !request.grants.is_empty() {
            let non_fs = parse_ops_non_fs_grants(&request.grants)?;
            builder = builder.grants(non_fs);
        }
        if let Some(hostname) = &request.hostname {
            builder = builder.hostname(hostname.clone());
        }
        if let Some(domainname) = &request.domainname {
            builder = builder.domainname(domainname.clone());
        }
        if request.uid.is_some() || request.gid.is_some() {
            let uid = request.uid.unwrap_or(0);
            let gid = request.gid.unwrap_or(0);
            builder = builder.user(uid, gid).shared_owner(uid, gid);
        }
        for (k, v) in &request.env {
            builder = builder.env(k.clone(), v.clone());
        }
        if let Some(cwd) = &request.cwd {
            builder = builder.working_dir(cwd.clone());
        }

        let container = builder
            .create(self.session.clone())
            .await
            .map_err(ops_to_env_err)?;
        let seq = self.next_id.fetch_add(1, Ordering::Relaxed);
        let handle = format!("ctr-{seq}");
        let info = ContainerInfo {
            handle: handle.clone(),
            image: image_label,
            rootfs_path: rootfs,
            hostname: container.config().hostname.clone(),
            cwd: container.config().default_cwd.clone(),
            uid: container.config().credentials.uid,
            gid: container.config().credentials.gid,
        };
        self.containers.lock().await.insert(
            handle,
            Arc::new(HostContainerEntry {
                info: info.clone(),
                container,
            }),
        );
        Ok(info)
    }

    async fn container_list(&self) -> Result<Vec<ContainerInfo>, EnvError> {
        let guard = self.containers.lock().await;
        Ok(guard.values().map(|e| e.info.clone()).collect())
    }

    async fn container_exec(
        &self,
        handle: &str,
        request: ContainerExecRequest,
    ) -> Result<ContainerExecOutput, EnvError> {
        let entry = self
            .containers
            .lock()
            .await
            .get(handle)
            .cloned()
            .ok_or_else(|| EnvError::NotFound {
                path: handle.to_owned(),
            })?;
        let env_pairs: Vec<(String, String)> = request.env.into_iter().collect();
        let res = entry
            .container
            .exec_with_options(
                &request.program,
                &request.args,
                &env_pairs,
                request.cwd.as_deref(),
                request.stdin,
            )
            .await
            .map_err(ops_to_env_err)?;
        Ok(ContainerExecOutput {
            instance_id: res.instance_id,
            exit_code: i32::try_from(res.exit_code).unwrap_or(1),
            stdout: res.output.stdout,
            stderr: res.output.stderr,
        })
    }

    async fn container_spawn(
        &self,
        handle: &str,
        request: ContainerSpawnRequest,
    ) -> Result<ExternalProcess, EnvError> {
        let entry = self
            .containers
            .lock()
            .await
            .get(handle)
            .cloned()
            .ok_or_else(|| EnvError::NotFound {
                path: handle.to_owned(),
            })?;
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
        let env_pairs: Vec<(String, String)> = request.env.into_iter().collect();
        let child = entry
            .container
            .spawn_with_options(
                &request.program,
                &request.args,
                &env_pairs,
                request.cwd.as_deref(),
                stdin_bytes,
            )
            .await
            .map_err(ops_to_env_err)?;

        Ok(wire_ops_child_streams(
            child,
            request.capture_stdout,
            request.capture_stderr,
            "remote container",
        ))
    }

    async fn container_remove(&self, handle: &str) -> Result<(), EnvError> {
        self.containers
            .lock()
            .await
            .remove(handle)
            .map(|_| ())
            .ok_or_else(|| EnvError::NotFound {
                path: handle.to_owned(),
            })
    }

    async fn list_mounts(&self) -> Result<Vec<MountEntryInfo>, EnvError> {
        let list = self.session.mounts().list().await.map_err(ops_to_env_err)?;
        Ok(list
            .into_iter()
            .map(|m| {
                let kind = m.source.split(':').next().unwrap_or(&m.source).to_owned();
                MountEntryInfo {
                    path: m.path,
                    source: m.source,
                    kind,
                    read_only: m.read_only,
                    sharing: m.sharing,
                }
            })
            .collect())
    }

    async fn mount(&self, request: MountRequestSpec) -> Result<(), EnvError> {
        let source = match request.source {
            MountSourceSpec::Memory => rpc_mounts::MountSource::Memory,
            MountSourceSpec::BootImage => rpc_mounts::MountSource::BootImage,
            MountSourceSpec::HostShare => rpc_mounts::MountSource::HostShare,
            MountSourceSpec::Disk(serial) => rpc_mounts::MountSource::Disk(serial),
            MountSourceSpec::Btrfs(serial) => rpc_mounts::MountSource::Btrfs(serial),
        };
        let sharing = match request.sharing {
            MountSharingSpec::Private => rpc_mounts::MountSharing::Private,
            MountSharingSpec::Shared => rpc_mounts::MountSharing::Shared,
        };
        self.session
            .mounts()
            .mount(rpc_mounts::MountRequest {
                source,
                path: request.path,
                read_only: request.read_only,
                sharing,
                compress: request.compress,
                commit: request.commit,
                max_inline: request.max_inline,
            })
            .await
            .map_err(ops_to_env_err)?;
        self.completion_cache.invalidate_all().await;
        Ok(())
    }

    async fn umount(&self, path: &str) -> Result<(), EnvError> {
        self.session
            .mounts()
            .unmount(path)
            .await
            .map_err(ops_to_env_err)?;
        self.completion_cache.invalidate_all().await;
        Ok(())
    }

    async fn btrfs_subvolume_create(&self, path: &str) -> Result<BtrfsSubvolumeInfo, EnvError> {
        let info = self
            .session
            .btrfs()
            .create_subvolume(path)
            .await
            .map_err(ops_to_env_err)?;
        Ok(convert_subvolume_info(info))
    }

    async fn btrfs_subvolume_delete(&self, path: &str) -> Result<(), EnvError> {
        self.session
            .btrfs()
            .delete_subvolume(path)
            .await
            .map_err(ops_to_env_err)
    }

    async fn btrfs_subvolume_snapshot(
        &self,
        source: &str,
        destination: &str,
        read_only: bool,
    ) -> Result<BtrfsSubvolumeInfo, EnvError> {
        let info = self
            .session
            .btrfs()
            .snapshot_subvolume(source, destination, read_only)
            .await
            .map_err(ops_to_env_err)?;
        Ok(convert_subvolume_info(info))
    }

    async fn btrfs_subvolume_list(
        &self,
        mount_point: &str,
    ) -> Result<Vec<BtrfsSubvolumeInfo>, EnvError> {
        let list = self
            .session
            .btrfs()
            .list_subvolumes(mount_point)
            .await
            .map_err(ops_to_env_err)?;
        Ok(list.into_iter().map(convert_subvolume_info).collect())
    }

    async fn btrfs_subvolume_info(&self, path: &str) -> Result<BtrfsSubvolumeInfo, EnvError> {
        let info = self
            .session
            .btrfs()
            .subvolume_info(path)
            .await
            .map_err(ops_to_env_err)?;
        Ok(convert_subvolume_info(info))
    }

    async fn btrfs_subvolume_set_ro(&self, path: &str, read_only: bool) -> Result<(), EnvError> {
        self.session
            .btrfs()
            .set_subvolume_read_only(path, read_only)
            .await
            .map_err(ops_to_env_err)
    }

    async fn btrfs_subvolume_send(
        &self,
        subvolume: &str,
        parent: Option<&str>,
        clone_sources: &[String],
    ) -> Result<Vec<u8>, EnvError> {
        self.session
            .btrfs()
            .send_subvolume(subvolume, parent, clone_sources)
            .await
            .map_err(ops_to_env_err)
    }

    async fn btrfs_subvolume_receive(
        &self,
        destination: &str,
        payload: Vec<u8>,
    ) -> Result<BtrfsSubvolumeInfo, EnvError> {
        let info = self
            .session
            .btrfs()
            .receive_subvolume(destination, payload)
            .await
            .map_err(ops_to_env_err)?;
        Ok(convert_subvolume_info(info))
    }

    async fn vm_run(&self, request: VmRunRequest) -> Result<VmInfo, EnvError> {
        let kernel = request
            .kernel
            .clone()
            .unwrap_or_else(|| String::from("/boot/vmlinux"));
        let mut builder = MicroVmConfig::builder(kernel.clone())
            .cpus(request.cpus)
            .memory_mib(request.memory_mib);
        if let Some(initramfs) = &request.initramfs {
            builder = builder.initramfs(initramfs.clone());
        }
        if let Some(cmdline) = &request.cmdline {
            builder = builder.cmdline(cmdline.clone());
        }
        if let Some(disk) = &request.disk {
            builder = builder.disk(VmDisk::new(disk.clone(), true));
        }
        for share in &request.shares {
            let s = VmShare::new(&share.tag, &share.host_path, !share.read_only)
                .map_err(ops_to_env_err)?;
            builder = builder.share(s);
        }
        if let Some(rootfs_dir) = &request.rootfs_dir {
            builder = builder.rootfs_dir(rootfs_dir.clone());
        }
        if let Some(oci_ref) = &request.oci_ref {
            builder = builder.oci_image(oci_ref.clone());
        }

        let vm = self
            .session
            .vm()
            .spawn(builder.build())
            .await
            .map_err(ops_to_env_err)?;
        let seq = self.next_id.fetch_add(1, Ordering::Relaxed);
        let vm_id = vm
            .instance_id()
            .map_or_else(|| format!("vm-{seq}"), |id| format!("vm-{id}"));
        let name = request.name.clone().unwrap_or_else(|| vm_id.clone());
        let running_info = VmInfo {
            id: vm_id.clone(),
            name,
            state: String::from("running"),
            cpus: request.cpus,
            memory_mib: request.memory_mib,
            oci_ref: request.oci_ref,
            kernel: Some(kernel),
            exit_reason: None,
        };
        self.vms.lock().await.push(running_info.clone());

        if request.detach {
            let vms_ref = Arc::clone(&self.vms);
            let id_copy = vm_id.clone();
            tokio::spawn(async move {
                let outcome = vm.wait().await;
                let (state, reason) = match outcome {
                    Ok(res) => (
                        String::from("stopped"),
                        format!("exit-code-{}", res.exit_code),
                    ),
                    Err(err) => (String::from("failed"), err.to_string()),
                };
                if let Some(slot) = vms_ref
                    .lock()
                    .await
                    .iter_mut()
                    .find(|entry| entry.id == id_copy)
                {
                    slot.state = state;
                    slot.exit_reason = Some(reason);
                }
            });
            return Ok(running_info);
        }

        let console_rx = vm.console().clone();
        let stderr_rx = vm.stderr().clone();
        let out_pump = tokio::spawn(async move {
            use std::io::Write as _;
            while let Ok(item) = console_rx.recv().await {
                if let Ok(bytes) = item {
                    let mut out = std::io::stdout().lock();
                    let _ = out.write_all(&bytes);
                    let _ = out.flush();
                }
            }
        });
        let err_pump = tokio::spawn(async move {
            use std::io::Write as _;
            while let Ok(item) = stderr_rx.recv().await {
                if let Ok(bytes) = item {
                    let mut err = std::io::stderr().lock();
                    let _ = err.write_all(&bytes);
                    let _ = err.flush();
                }
            }
        });
        let wait_res = vm.wait().await;
        let _ = out_pump.await;
        let _ = err_pump.await;
        let res = match wait_res {
            Ok(res) => res,
            Err(err) => {
                if let Some(slot) = self
                    .vms
                    .lock()
                    .await
                    .iter_mut()
                    .find(|entry| entry.id == vm_id)
                {
                    slot.state = String::from("failed");
                    slot.exit_reason = Some(err.to_string());
                }
                return Err(ops_to_env_err(err));
            }
        };
        let reason = format!("exit-code-{}", res.exit_code);
        let mut final_info = running_info;
        final_info.state = String::from("stopped");
        final_info.exit_reason = Some(reason.clone());
        if let Some(slot) = self
            .vms
            .lock()
            .await
            .iter_mut()
            .find(|entry| entry.id == vm_id)
        {
            slot.state = String::from("stopped");
            slot.exit_reason = Some(reason);
        }
        Ok(final_info)
    }

    async fn vm_list(&self) -> Result<Vec<VmInfo>, EnvError> {
        let mut out = self.vms.lock().await.clone();
        if let Ok(hv_vms) = self.session.vm().list().await {
            for hv in hv_vms {
                let id = format!("hv-{}", hv.id);
                let owner_id = hv.owner_instance_id.map(|oid| format!("vm-{oid}"));
                if out
                    .iter()
                    .any(|entry| entry.id == id || owner_id.as_deref() == Some(entry.id.as_str()))
                {
                    continue;
                }
                out.push(VmInfo {
                    id: id.clone(),
                    name: id,
                    state: String::from("running"),
                    cpus: u32::try_from(hv.vcpus).unwrap_or(u32::MAX),
                    memory_mib: hv.memory_limit_bytes / (1024 * 1024),
                    oci_ref: None,
                    kernel: None,
                    exit_reason: None,
                });
            }
        }
        Ok(out)
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

    async fn complete_oci_refs(&self) -> Result<Vec<String>, EnvError> {
        Ok(self.completion_cache.oci_refs(&self.session).await)
    }

    async fn complete_containers(&self) -> Result<Vec<String>, EnvError> {
        Ok(self.containers.lock().await.keys().cloned().collect())
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
            rec.push("level", Value::string(trace_level_label(ev.level), head));
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
            detail: format!("{}: {detail}", exec_error_kind_label(kind)),
        },
        OpsError::Http(http) => EnvError::Http {
            detail: http.to_string(),
        },
        other => EnvError::Io {
            detail: other.to_string(),
        },
    }
}

fn trace_level_label(level: proto_tracing::Level) -> &'static str {
    match level {
        proto_tracing::Level::Error => "error",
        proto_tracing::Level::Warn => "warn",
        proto_tracing::Level::Info => "info",
        proto_tracing::Level::Debug => "debug",
        proto_tracing::Level::Trace => "trace",
    }
}

fn exec_error_kind_label(kind: rpc_programs::ExecErrorKind) -> &'static str {
    match kind {
        rpc_programs::ExecErrorKind::InvalidBinary => "invalid binary",
        rpc_programs::ExecErrorKind::MissingEntry => "missing entry point",
        rpc_programs::ExecErrorKind::UnsupportedImport => "unsupported import",
        rpc_programs::ExecErrorKind::InvalidSignature => "invalid signature",
        rpc_programs::ExecErrorKind::InvalidPath => "invalid path",
        rpc_programs::ExecErrorKind::PermissionDenied => "permission denied",
        rpc_programs::ExecErrorKind::InvalidHint => "invalid hint",
        rpc_programs::ExecErrorKind::OutOfMemory => "out of memory",
        rpc_programs::ExecErrorKind::Unavailable => "unavailable",
        rpc_programs::ExecErrorKind::Internal => "internal error",
        rpc_programs::ExecErrorKind::NotFound => "not found",
        rpc_programs::ExecErrorKind::Io => "i/o error",
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

fn parse_ops_fs_rights(mode: &str) -> Result<Vec<rpc_programs::FilesystemRight>, EnvError> {
    use rpc_programs::FilesystemRight;
    match mode {
        "ro" | "r" => Ok(vec![FilesystemRight::Read]),
        "rx" => Ok(vec![FilesystemRight::Read, FilesystemRight::Execute]),
        "rw" | "w" => Ok(vec![
            FilesystemRight::Read,
            FilesystemRight::Write,
            FilesystemRight::MutateDirectory,
        ]),
        "rwx" => Ok(vec![
            FilesystemRight::Read,
            FilesystemRight::Write,
            FilesystemRight::MutateDirectory,
            FilesystemRight::Execute,
        ]),
        other => Err(EnvError::InvalidArgument {
            detail: format!("unknown container mount mode `{other}`"),
        }),
    }
}

fn parse_ops_non_fs_grants(specs: &[GrantSpec]) -> Result<NonFsGrants, EnvError> {
    let mut grants = NonFsGrants::new();
    for spec in specs {
        let cap =
            helios_ops::session::parse_grant_spec(&spec.kind, &spec.target, spec.mode.as_deref())
                .map_err(ops_to_env_err)?;
        let non_fs = match cap {
            rpc_programs::CapabilityGrant::Directory(_) => {
                return Err(EnvError::InvalidArgument {
                    detail: String::from(
                        "container grants do not accept directory grants; use `--mount` instead",
                    ),
                });
            }
            rpc_programs::CapabilityGrant::Network(g) => NonFsGrant::Network(g),
            rpc_programs::CapabilityGrant::Clock(g) => NonFsGrant::Clock(g),
            rpc_programs::CapabilityGrant::Terminal(g) => NonFsGrant::Terminal(g),
            rpc_programs::CapabilityGrant::Process(g) => NonFsGrant::Process(g),
            rpc_programs::CapabilityGrant::Link(g) => NonFsGrant::Link(g),
            rpc_programs::CapabilityGrant::Mount(g) => NonFsGrant::Mount(g),
            rpc_programs::CapabilityGrant::Device(g) => NonFsGrant::Device(g),
            rpc_programs::CapabilityGrant::Diagnostics(g) => NonFsGrant::Diagnostics(g),
            rpc_programs::CapabilityGrant::InstanceControl(s) => NonFsGrant::InstanceControl(s),
            rpc_programs::CapabilityGrant::Settings(g) => NonFsGrant::Settings(g),
            rpc_programs::CapabilityGrant::Machine(g) => NonFsGrant::Machine(g),
            rpc_programs::CapabilityGrant::Ipc(_) => {
                return Err(EnvError::InvalidArgument {
                    detail: String::from("IPC channel grants are not supported on containers"),
                });
            }
        };
        grants = grants.grant(non_fs);
    }
    Ok(grants)
}

fn parse_oci_arch(arch: Option<&str>) -> Result<Option<Arch>, EnvError> {
    match arch {
        Some(raw) => Arch::parse(raw)
            .map(Some)
            .ok_or_else(|| EnvError::InvalidArgument {
                detail: format!(
                    "unsupported OCI architecture `{raw}` (expected amd64/x86_64 or arm64/aarch64)"
                ),
            }),
        None => Ok(None),
    }
}

fn join_under_root(root: &str, relative_abs: &str) -> String {
    let r = root.trim_end_matches('/');
    let rel = relative_abs.trim_start_matches('/');
    if r.is_empty() {
        format!("/{rel}")
    } else if rel.is_empty() {
        r.to_owned()
    } else {
        format!("{r}/{rel}")
    }
}

fn default_linux_image_from_pref(pref: &UserDefaultImage) -> rpc_programs::DefaultLinuxImage {
    rpc_programs::DefaultLinuxImage {
        root_path: pref.rootfs_path.clone(),
        env: pref.env.clone(),
        credentials: Some(rpc_programs::ContainerCredentials {
            uid: pref.credentials.uid,
            gid: pref.credentials.gid,
            supplementary_groups: pref.credentials.supplementary_groups.clone(),
        }),
    }
}

async fn resolve_remote_oci_user(
    session: &Session,
    pulled: &PulledImage,
) -> Result<ResolvedUser, EnvError> {
    if let Ok(user) = pulled.config.config.resolve_user(None) {
        return Ok(user);
    }
    let rootfs = pulled.rootfs_path().to_string_lossy();
    let passwd_path = join_under_root(&rootfs, "/etc/passwd");
    let group_path = join_under_root(&rootfs, "/etc/group");
    let passwd_bytes = session.read_file(&passwd_path).await.ok();
    let group_bytes = session.read_file(&group_path).await.ok();
    let tmp = std::env::temp_dir().join(format!(
        "helios-oci-user-{}-{}",
        std::process::id(),
        pulled.manifest_digest.hex()
    ));
    let etc_dir = tmp.join("etc");
    std::fs::create_dir_all(&etc_dir).map_err(|err| EnvError::Io {
        detail: format!("create temp etc dir: {err}"),
    })?;
    if let Some(bytes) = passwd_bytes {
        let _ = std::fs::write(etc_dir.join("passwd"), bytes);
    }
    if let Some(bytes) = group_bytes {
        let _ = std::fs::write(etc_dir.join("group"), bytes);
    }
    let resolved = pulled.config.config.resolve_user(Some(&tmp));
    let _ = std::fs::remove_dir_all(&tmp);
    resolved.map_err(|err| EnvError::InvalidArgument {
        detail: err.to_string(),
    })
}

async fn default_linux_image_from_remote_oci(
    session: &Session,
    pulled: &PulledImage,
) -> Result<rpc_programs::DefaultLinuxImage, EnvError> {
    let user = resolve_remote_oci_user(session, pulled).await?;
    Ok(rpc_programs::DefaultLinuxImage {
        root_path: pulled.rootfs_path().to_string_lossy().into_owned(),
        env: pulled.config.config.env_pairs(),
        credentials: Some(rpc_programs::ContainerCredentials {
            uid: user.uid,
            gid: user.gid,
            supplementary_groups: user.supplementary_groups,
        }),
    })
}

async fn load_remote_default_images(
    session: &Session,
) -> Result<BTreeMap<String, UserDefaultImage>, EnvError> {
    let path = format!(
        "{}/user-default-images.json",
        session.oci().store_root().trim_end_matches('/')
    );
    match session.read_file(&path).await {
        Ok(raw) => {
            let doc: serde_json::Value =
                serde_json::from_slice(&raw).map_err(|err| EnvError::Io {
                    detail: format!("invalid user-default-images.json: {err}"),
                })?;
            match doc.get("users") {
                Some(users) => serde_json::from_value(users.clone()).map_err(|err| EnvError::Io {
                    detail: format!("invalid user-default-images.json users map: {err}"),
                }),
                None => Ok(BTreeMap::new()),
            }
        }
        Err(
            OpsError::NotFound { .. }
            | OpsError::Fs(helios_wit_rpc::inspector_fs::FsRpcError::Fs {
                code: helios_wit_rpc::inspector::wasi::filesystem::types::ErrorCode::NoEntry,
                ..
            }),
        ) => Ok(BTreeMap::new()),
        Err(err) => Err(ops_to_env_err(err)),
    }
}

async fn save_remote_default_images(
    session: &Session,
    users: &BTreeMap<String, UserDefaultImage>,
) -> Result<(), EnvError> {
    let oci = session.oci();
    let store_root = oci.store_root().trim_end_matches('/');
    let mut current = String::new();
    for seg in store_root.split('/').filter(|s| !s.is_empty()) {
        current.push('/');
        current.push_str(seg);
        let _ = session.mkdir(&current).await;
    }
    let path = format!("{store_root}/user-default-images.json");
    let body =
        serde_json::to_vec_pretty(&serde_json::json!({ "users": users })).map_err(|err| {
            EnvError::Io {
                detail: format!("serialize user-default-images.json: {err}"),
            }
        })?;
    session
        .write_file(&path, &body, false)
        .await
        .map_err(ops_to_env_err)
}

fn pulled_to_summary(img: &PulledImage) -> OciImageSummary {
    OciImageSummary {
        reference: img.reference.canonical(),
        digest: img.manifest_digest.as_str(),
        arch: img.arch.to_string(),
        layers: img.layer_chain_ids.len(),
        rootfs_path: img.rootfs_path().to_string_lossy().into_owned(),
        btrfs_backed: img.btrfs_backed,
    }
}

fn pulled_to_inspect(img: &PulledImage) -> OciImageInspect {
    OciImageInspect {
        reference: img.reference.canonical(),
        digest: img.manifest_digest.as_str(),
        arch: img.arch.to_string(),
        os: img.config.os.clone(),
        rootfs_path: img.rootfs_path().to_string_lossy().into_owned(),
        btrfs_backed: img.btrfs_backed,
        layer_chain_ids: img.layer_chain_ids.iter().map(|d| d.as_str()).collect(),
        user: img.config.config.user.clone(),
        working_dir: img.config.config.working_dir.clone(),
        entrypoint: img.config.config.entrypoint.clone(),
        cmd: img.config.config.cmd.clone(),
        env: img.config.config.env_pairs(),
        labels: img.config.config.labels.clone(),
    }
}

fn convert_subvolume_info(info: rpc_btrfs::SubvolumeInfo) -> BtrfsSubvolumeInfo {
    BtrfsSubvolumeInfo {
        id: info.id,
        parent_id: info.parent_id,
        path: info.path,
        uuid: format_uuid_bytes(&info.uuid),
        parent_uuid: info.parent_uuid.as_deref().map(format_uuid_bytes),
        received_uuid: info.received_uuid.as_deref().map(format_uuid_bytes),
        generation: info.generation,
        ctransid: info.ctransid,
        otransid: info.otransid,
        stransid: info.stransid,
        rtransid: info.rtransid,
        read_only: info.read_only,
    }
}

fn format_uuid_bytes(bytes: &[u8]) -> String {
    if bytes.len() == 16 {
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5],
            bytes[6],
            bytes[7],
            bytes[8],
            bytes[9],
            bytes[10],
            bytes[11],
            bytes[12],
            bytes[13],
            bytes[14],
            bytes[15],
        )
    } else {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("")
    }
}

fn wire_ops_child_streams(
    child: helios_ops::Child,
    capture_stdout: bool,
    capture_stderr: bool,
    label: &'static str,
) -> ExternalProcess {
    let (exit_tx, exit_rx) = async_channel::bounded(1);
    let child_stdout = child.stdout.clone();
    let child_stderr = child.stderr.clone();

    let (stdout, stdout_inherited_done) = if capture_stdout {
        let (stdout_tx, stdout_rx) = async_channel::bounded(STREAM_CHANNEL_CAPACITY);
        tokio::spawn(async move {
            while let Ok(item) = child_stdout.recv().await {
                let mapped = item.map_err(|err| {
                    ShellError::Generic(GenericError::new(
                        format!("{label} stdout error"),
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

    let (stderr, stderr_inherited_done) = if capture_stderr {
        let (stderr_tx, stderr_rx) = async_channel::bounded(STREAM_CHANNEL_CAPACITY);
        tokio::spawn(async move {
            while let Ok(item) = child_stderr.recv().await {
                let mapped = item.map_err(|err| {
                    ShellError::Generic(GenericError::new(
                        format!("{label} stderr error"),
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

    ExternalProcess {
        stdout,
        stderr,
        exit_code: exit_rx,
    }
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

        async fn hibernate(&self) -> Result<(), rpc_snapshot::HibernateError> {
            Err(rpc_snapshot::HibernateError::Unsupported)
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

    #[tokio::test]
    async fn host_env_wires_linux_image_component_oci_container_storage_and_vm_surfaces() {
        use helios_ops::helios_oci::{
            Digest, ImageConfig, ImageReference, ImageRuntimeConfig, RootFs,
        };
        use helios_wit_rpc::inspector::helios::system::{
            btrfs::{
                self as test_btrfs, BalanceFilter, BalanceReport, BtrfsError, BtrfsErrorKind,
                DedupeOutcome, QgroupId, QgroupInfo, QgroupLimit, QuotaStatus, ResizeTarget,
                ScrubReport, SubvolumeInfo, VolumeDeviceInfo,
            },
            component_control::{
                self as test_cc, ComponentStatus, ControlError, ControlErrorKind,
                DynamicSubtreeSource,
            },
            mounts::{self as test_mounts, MountError, MountErrorKind, MountRequest},
        };
        use std::sync::Mutex;

        struct MemFs {
            files: Mutex<BTreeMap<String, Vec<u8>>>,
            dirs: Mutex<BTreeSet<String>>,
        }

        impl MemFs {
            fn new() -> Self {
                let mut dirs = BTreeSet::new();
                dirs.insert("/".to_owned());
                Self {
                    files: Mutex::new(BTreeMap::new()),
                    dirs: Mutex::new(dirs),
                }
            }

            fn seed_file(&self, path: &str, bytes: Vec<u8>) {
                let mut parent = String::new();
                let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
                for seg in &parts[..parts.len().saturating_sub(1)] {
                    parent.push('/');
                    parent.push_str(seg);
                    self.dirs.lock().expect("dirs").insert(parent.clone());
                }
                self.files
                    .lock()
                    .expect("files")
                    .insert(path.to_owned(), bytes);
            }
        }

        #[derive(Clone)]
        struct PathDesc(String);

        enum FullResource {
            Dir(Arc<PathDesc>),
            Child(Arc<String>),
            Unit(Arc<()>),
        }

        impl ResourceEntry for FullResource {
            fn kind_name(&self) -> &'static str {
                match self {
                    Self::Dir(_) => "descriptor",
                    Self::Child(_) => "child",
                    Self::Unit(_) => "unit",
                }
            }
        }

        impl ResourceSlotAccess<rpc_fs::Descriptor, PathDesc> for FullResource {
            fn into_entry(arc: Arc<PathDesc>) -> Self {
                Self::Dir(arc)
            }
            fn borrow_entry(&self) -> Option<&Arc<PathDesc>> {
                match self {
                    Self::Dir(d) => Some(d),
                    _ => None,
                }
            }
            fn take_entry(self) -> Result<Arc<PathDesc>, Self> {
                match self {
                    Self::Dir(d) => Ok(d),
                    other => Err(other),
                }
            }
        }

        impl ResourceSlotAccess<rpc_programs::Child, String> for FullResource {
            fn into_entry(arc: Arc<String>) -> Self {
                Self::Child(arc)
            }
            fn borrow_entry(&self) -> Option<&Arc<String>> {
                match self {
                    Self::Child(c) => Some(c),
                    _ => None,
                }
            }
            fn take_entry(self) -> Result<Arc<String>, Self> {
                match self {
                    Self::Child(c) => Ok(c),
                    other => Err(other),
                }
            }
        }

        macro_rules! impl_full_unit_slot {
            ($($marker:ty),* $(,)?) => {
                $(
                    impl ResourceSlotAccess<$marker, ()> for FullResource {
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

        impl_full_unit_slot!(
            rpc_ipc::Endpoint,
            rpc_programs::Container,
            rpc_net::TcpListener,
            rpc_net::TcpStream,
            rpc_serial::SerialPort,
            rpc_vsock::VsockListener,
            rpc_vsock::VsockStream,
        );

        fn join_path(base: &str, rel: &str) -> String {
            let rel = rel.trim_matches('/');
            if rel.is_empty() {
                base.to_owned()
            } else if base == "/" {
                format!("/{rel}")
            } else {
                format!("{base}/{rel}")
            }
        }

        struct FullPreopens;
        impl rpc_preopens::RpcHandler for FullPreopens {
            type Descriptor = PathDesc;
            async fn get_directories(&self) -> Vec<(Self::Descriptor, String)> {
                vec![(PathDesc("/".to_owned()), "/".to_owned())]
            }
        }

        struct FullFs {
            fs: Arc<MemFs>,
        }

        impl rpc_fs::RpcHandler for FullFs {
            type Descriptor = PathDesc;
            async fn descriptor_read_via_stream(
                &self,
                self_: &Self::Descriptor,
                offset: Filesize,
            ) -> (StreamReader<u8>, FutureReader<Result<(), ErrorCode>>) {
                let data = self.fs.files.lock().expect("files").get(&self_.0).cloned();
                match data {
                    Some(bytes) => {
                        let start = usize::try_from(offset).unwrap_or(bytes.len());
                        let slice = bytes.get(start..).unwrap_or_default().to_vec();
                        (StreamReader::from_vec(slice), FutureReader::ready(Ok(())))
                    }
                    None => (
                        StreamReader::empty(),
                        FutureReader::ready(Err(ErrorCode::NoEntry)),
                    ),
                }
            }
            async fn descriptor_write_via_stream(
                &self,
                self_: &Self::Descriptor,
                data: StreamReader<u8>,
                _offset: Filesize,
            ) -> FutureReader<Result<(), ErrorCode>> {
                let (ftx, frx) = helios_wit_rpc::future::<Result<(), ErrorCode>>();
                let fs = Arc::clone(&self.fs);
                let path = self_.0.clone();
                tokio::spawn(async move {
                    let bytes = data.collect_all().await.unwrap_or_default();
                    fs.seed_file(&path, bytes);
                    let _ = ftx.resolve(Ok(())).await;
                });
                frx
            }
            async fn descriptor_append_via_stream(
                &self,
                self_: &Self::Descriptor,
                data: StreamReader<u8>,
            ) -> FutureReader<Result<(), ErrorCode>> {
                let (ftx, frx) = helios_wit_rpc::future::<Result<(), ErrorCode>>();
                let fs = Arc::clone(&self.fs);
                let path = self_.0.clone();
                tokio::spawn(async move {
                    let bytes = data.collect_all().await.unwrap_or_default();
                    {
                        let mut guard = fs.files.lock().expect("files");
                        guard.entry(path).or_default().extend_from_slice(&bytes);
                    }
                    let _ = ftx.resolve(Ok(())).await;
                });
                frx
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
            async fn descriptor_sync_data(
                &self,
                _self_: &Self::Descriptor,
            ) -> Result<(), ErrorCode> {
                Ok(())
            }
            async fn descriptor_get_flags(
                &self,
                _self_: &Self::Descriptor,
            ) -> Result<DescriptorFlags, ErrorCode> {
                Ok(DescriptorFlags::READ | DescriptorFlags::WRITE)
            }
            async fn descriptor_get_type(
                &self,
                self_: &Self::Descriptor,
            ) -> Result<DescriptorType, ErrorCode> {
                if self.fs.dirs.lock().expect("dirs").contains(&self_.0) {
                    Ok(DescriptorType::Directory)
                } else {
                    Ok(DescriptorType::RegularFile)
                }
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
                self_: &Self::Descriptor,
            ) -> (
                StreamReader<DirectoryEntry>,
                FutureReader<Result<(), ErrorCode>>,
            ) {
                let prefix = if self_.0 == "/" {
                    "/".to_owned()
                } else {
                    format!("{}/", self_.0.trim_end_matches('/'))
                };
                let mut seen = BTreeMap::<String, DescriptorType>::new();
                for d in self.fs.dirs.lock().expect("dirs").iter() {
                    if let Some(rest) = d.strip_prefix(&prefix)
                        && !rest.is_empty()
                        && !rest.contains('/')
                    {
                        seen.insert(rest.to_owned(), DescriptorType::Directory);
                    }
                }
                for f in self.fs.files.lock().expect("files").keys() {
                    if let Some(rest) = f.strip_prefix(&prefix)
                        && !rest.is_empty()
                        && !rest.contains('/')
                    {
                        seen.insert(rest.to_owned(), DescriptorType::RegularFile);
                    }
                }
                let entries: Vec<DirectoryEntry> = seen
                    .into_iter()
                    .map(|(name, r#type)| DirectoryEntry { r#type, name })
                    .collect();
                (StreamReader::from_vec(entries), FutureReader::ready(Ok(())))
            }
            async fn descriptor_sync(&self, _self_: &Self::Descriptor) -> Result<(), ErrorCode> {
                Ok(())
            }
            async fn descriptor_create_directory_at(
                &self,
                self_: &Self::Descriptor,
                path: String,
            ) -> Result<(), ErrorCode> {
                let full = join_path(&self_.0, &path);
                let mut dirs = self.fs.dirs.lock().expect("dirs");
                if !dirs.insert(full) {
                    return Err(ErrorCode::Exist);
                }
                Ok(())
            }
            async fn descriptor_stat(
                &self,
                self_: &Self::Descriptor,
            ) -> Result<DescriptorStat, ErrorCode> {
                if self.fs.dirs.lock().expect("dirs").contains(&self_.0) {
                    return Ok(DescriptorStat {
                        r#type: DescriptorType::Directory,
                        link_count: 1,
                        size: 0,
                        data_access_timestamp: None,
                        data_modification_timestamp: None,
                        status_change_timestamp: None,
                    });
                }
                if let Some(bytes) = self.fs.files.lock().expect("files").get(&self_.0) {
                    return Ok(DescriptorStat {
                        r#type: DescriptorType::RegularFile,
                        link_count: 1,
                        size: bytes.len() as u64,
                        data_access_timestamp: None,
                        data_modification_timestamp: None,
                        status_change_timestamp: None,
                    });
                }
                Err(ErrorCode::NoEntry)
            }
            async fn descriptor_stat_at(
                &self,
                self_: &Self::Descriptor,
                _path_flags: PathFlags,
                path: String,
            ) -> Result<DescriptorStat, ErrorCode> {
                let full = join_path(&self_.0, &path);
                self.descriptor_stat(&PathDesc(full)).await
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
                self_: &Self::Descriptor,
                _path_flags: PathFlags,
                path: String,
                open_flags: OpenFlags,
                _flags: DescriptorFlags,
            ) -> Result<Self::Descriptor, ErrorCode> {
                let full = join_path(&self_.0, &path);
                if open_flags.contains(OpenFlags::CREATE) {
                    if !self.fs.files.lock().expect("files").contains_key(&full) {
                        self.fs.seed_file(&full, Vec::new());
                    }
                    return Ok(PathDesc(full));
                }
                if self.fs.dirs.lock().expect("dirs").contains(&full)
                    || self.fs.files.lock().expect("files").contains_key(&full)
                {
                    Ok(PathDesc(full))
                } else {
                    Err(ErrorCode::NoEntry)
                }
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
                self_: &Self::Descriptor,
                path: String,
            ) -> Result<(), ErrorCode> {
                let full = join_path(&self_.0, &path);
                if self.fs.dirs.lock().expect("dirs").remove(&full) {
                    Ok(())
                } else {
                    Err(ErrorCode::NoEntry)
                }
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
                self_: &Self::Descriptor,
                path: String,
            ) -> Result<(), ErrorCode> {
                let full = join_path(&self_.0, &path);
                if self.fs.files.lock().expect("files").remove(&full).is_some() {
                    Ok(())
                } else {
                    Err(ErrorCode::NoEntry)
                }
            }
            async fn descriptor_is_same_object(
                &self,
                self_: &Self::Descriptor,
                other: &Self::Descriptor,
            ) -> bool {
                self_.0 == other.0
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

        struct FullPrograms {
            default_image: Mutex<Option<DefaultLinuxImage>>,
            spawned_paths: Mutex<Vec<String>>,
        }

        impl rpc_programs::RpcHandler for FullPrograms {
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
                let (ftx, frx) = helios_wit_rpc::future::<Result<(), ()>>();
                tokio::spawn(async move {
                    let _ = data.collect_all().await;
                    let _ = ftx.resolve(Ok(())).await;
                });
                frx
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
                77
            }
            async fn child_signal(&self, _self_: &Self::Child, _sig: u8) -> Result<(), SpawnError> {
                Ok(())
            }
            async fn child_wait(&self, _self_: &Self::Child) -> Result<ExitStatus, SpawnError> {
                Ok(ExitStatus {
                    instance_id: 77,
                    termination: ChildTermination::Exited(0),
                })
            }
            async fn container_spawn(
                &self,
                _self_: &Self::Container,
                request: ContainerSpawnRequest<
                    Self::TcpListener,
                    Self::VsockListener,
                    Self::TcpStream,
                    Self::VsockStream,
                    Self::SerialPort,
                >,
            ) -> Result<Self::Child, SpawnError> {
                Ok(format!("ctr-spawn:{}", request.path))
            }
            async fn container_exec(
                &self,
                _self_: &Self::Container,
                request: ContainerExecRequest,
            ) -> Result<ExecResult, ExecError> {
                Ok(ExecResult {
                    instance_id: 88,
                    exit_code: 0,
                    output: ExecOutput {
                        stdout: format!("ctr-exec:{} 你好 こんにちは 안녕하세요", request.path)
                            .into_bytes(),
                        stderr: Vec::new(),
                    },
                    launch_nanos: 1,
                })
            }
            async fn set_default_image(
                &self,
                image: Option<DefaultLinuxImage>,
            ) -> Result<(), SpawnError> {
                *self.default_image.lock().expect("default_image") = image;
                Ok(())
            }
            async fn get_default_image(&self) -> Option<DefaultLinuxImage> {
                self.default_image.lock().expect("default_image").clone()
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
                self.spawned_paths
                    .lock()
                    .expect("spawned_paths")
                    .push(request.path.clone());
                Ok(format!("ran:{}", request.path))
            }
            async fn exec(
                &self,
                _request: ExecRequest<Self::Endpoint>,
            ) -> Result<ExecResult, ExecError> {
                unreachable!()
            }
            async fn aot(&self, _request: AotRequest) -> Result<AotResult, ExecError> {
                unreachable!()
            }
        }

        struct FullComponents {
            items: Mutex<BTreeMap<String, ComponentStatus>>,
        }

        impl test_cc::RpcHandler for FullComponents {
            async fn list_components(&self) -> Result<Vec<ComponentStatus>, ControlError> {
                Ok(self
                    .items
                    .lock()
                    .expect("items")
                    .values()
                    .cloned()
                    .collect())
            }
            async fn start(&self, moniker: String) -> Result<ComponentStatus, ControlError> {
                let mut guard = self.items.lock().expect("items");
                let c = guard.get_mut(&moniker).ok_or(ControlError {
                    kind: ControlErrorKind::NotFound,
                    detail: moniker,
                })?;
                c.state = "running".to_owned();
                c.instance_id = Some(12);
                Ok(c.clone())
            }
            async fn stop(&self, moniker: String) -> Result<(), ControlError> {
                let mut guard = self.items.lock().expect("items");
                let c = guard.get_mut(&moniker).ok_or(ControlError {
                    kind: ControlErrorKind::NotFound,
                    detail: moniker,
                })?;
                c.state = "stopped".to_owned();
                c.instance_id = None;
                Ok(())
            }
            async fn restart(&self, moniker: String) -> Result<ComponentStatus, ControlError> {
                let mut guard = self.items.lock().expect("items");
                let c = guard.get_mut(&moniker).ok_or(ControlError {
                    kind: ControlErrorKind::NotFound,
                    detail: moniker,
                })?;
                c.state = "running".to_owned();
                c.restarts += 1;
                Ok(c.clone())
            }
            async fn mount_dynamic(
                &self,
                parent_moniker: String,
                source: DynamicSubtreeSource,
            ) -> Result<String, ControlError> {
                let name = match source {
                    DynamicSubtreeSource::GuestDir(d) => d.subtree_name,
                    DynamicSubtreeSource::Manifests(list) => list
                        .first()
                        .and_then(|(p, _)| p.split('/').next())
                        .unwrap_or("dyn")
                        .to_owned(),
                };
                let mounted = format!("{}/{}", parent_moniker.trim_end_matches('/'), name);
                self.items.lock().expect("items").insert(
                    mounted.clone(),
                    ComponentStatus {
                        moniker: mounted.clone(),
                        program: "/bin/dyn".to_owned(),
                        state: "running".to_owned(),
                        instance_id: Some(90),
                        restarts: 0,
                    },
                );
                Ok(mounted)
            }
            async fn unmount_dynamic(&self, moniker: String) -> Result<(), ControlError> {
                if self.items.lock().expect("items").remove(&moniker).is_none() {
                    return Err(ControlError {
                        kind: ControlErrorKind::NotFound,
                        detail: moniker,
                    });
                }
                Ok(())
            }
        }

        struct FullMounts {
            mounted: Mutex<Vec<String>>,
        }

        impl test_mounts::RpcHandler for FullMounts {
            async fn mount(&self, request: MountRequest) -> Result<(), MountError> {
                self.mounted.lock().expect("mounted").push(request.path);
                Ok(())
            }
            async fn unmount(&self, path: String) -> Result<(), MountError> {
                let mut guard = self.mounted.lock().expect("mounted");
                if let Some(pos) = guard.iter().position(|p| p == &path) {
                    guard.remove(pos);
                    Ok(())
                } else {
                    Err(MountError {
                        kind: MountErrorKind::NotMounted,
                        detail: path,
                    })
                }
            }
        }

        struct FullBtrfs {
            subvols: Mutex<BTreeMap<String, SubvolumeInfo>>,
        }

        impl FullBtrfs {
            fn make_info(id: u64, path: String, read_only: bool) -> SubvolumeInfo {
                SubvolumeInfo {
                    id,
                    parent_id: Some(5),
                    path,
                    uuid: vec![0xab; 16],
                    parent_uuid: None,
                    received_uuid: None,
                    generation: 1,
                    ctransid: 1,
                    otransid: 1,
                    stransid: 0,
                    rtransid: 0,
                    read_only,
                }
            }
        }

        impl test_btrfs::RpcHandler for FullBtrfs {
            async fn create_subvolume(&self, path: String) -> Result<SubvolumeInfo, BtrfsError> {
                let mut guard = self.subvols.lock().expect("subvols");
                let info = Self::make_info(256 + guard.len() as u64, path.clone(), false);
                guard.insert(path, info.clone());
                Ok(info)
            }
            async fn delete_subvolume(&self, path: String) -> Result<(), BtrfsError> {
                self.subvols
                    .lock()
                    .expect("subvols")
                    .remove(&path)
                    .map(|_| ())
                    .ok_or(BtrfsError {
                        kind: BtrfsErrorKind::NotFound,
                        detail: path,
                    })
            }
            async fn snapshot_subvolume(
                &self,
                _source: String,
                destination: String,
                read_only: bool,
            ) -> Result<SubvolumeInfo, BtrfsError> {
                let mut guard = self.subvols.lock().expect("subvols");
                let info =
                    Self::make_info(256 + guard.len() as u64, destination.clone(), read_only);
                guard.insert(destination, info.clone());
                Ok(info)
            }
            async fn set_subvolume_read_only(
                &self,
                path: String,
                read_only: bool,
            ) -> Result<(), BtrfsError> {
                let mut guard = self.subvols.lock().expect("subvols");
                let entry = guard.get_mut(&path).ok_or(BtrfsError {
                    kind: BtrfsErrorKind::NotFound,
                    detail: path,
                })?;
                entry.read_only = read_only;
                Ok(())
            }
            async fn get_subvolume_info(&self, path: String) -> Result<SubvolumeInfo, BtrfsError> {
                self.subvols
                    .lock()
                    .expect("subvols")
                    .get(&path)
                    .cloned()
                    .ok_or(BtrfsError {
                        kind: BtrfsErrorKind::NotFound,
                        detail: path,
                    })
            }
            async fn list_subvolumes(
                &self,
                _mount_point: String,
            ) -> Result<Vec<SubvolumeInfo>, BtrfsError> {
                Ok(self
                    .subvols
                    .lock()
                    .expect("subvols")
                    .values()
                    .cloned()
                    .collect())
            }
            async fn send_subvolume(
                &self,
                _subvolume: String,
                _parent: Option<String>,
                _clone_sources: Vec<String>,
            ) -> Result<Vec<u8>, BtrfsError> {
                Ok(b"btrfs-stream\0\x01".to_vec())
            }
            async fn receive_subvolume(
                &self,
                destination: String,
                _payload: Vec<u8>,
            ) -> Result<SubvolumeInfo, BtrfsError> {
                let path = format!("{}/received", destination.trim_end_matches('/'));
                let mut guard = self.subvols.lock().expect("subvols");
                let info = Self::make_info(256 + guard.len() as u64, path.clone(), true);
                guard.insert(path, info.clone());
                Ok(info)
            }
            async fn reflink(
                &self,
                _s: String,
                _so: u64,
                _d: String,
                _do: u64,
                _l: u64,
            ) -> Result<(), BtrfsError> {
                unreachable!()
            }
            async fn dedupe(
                &self,
                _s: String,
                _so: u64,
                _d: String,
                _do: u64,
                _l: u64,
            ) -> Result<DedupeOutcome, BtrfsError> {
                unreachable!()
            }
            async fn list_devices(&self, _m: String) -> Result<Vec<VolumeDeviceInfo>, BtrfsError> {
                unreachable!()
            }
            async fn add_device(
                &self,
                _m: String,
                _d: String,
            ) -> Result<VolumeDeviceInfo, BtrfsError> {
                unreachable!()
            }
            async fn remove_device(&self, _m: String, _id: u64) -> Result<(), BtrfsError> {
                unreachable!()
            }
            async fn replace_device(
                &self,
                _m: String,
                _id: u64,
                _t: String,
            ) -> Result<VolumeDeviceInfo, BtrfsError> {
                unreachable!()
            }
            async fn resize_device(
                &self,
                _m: String,
                _id: Option<u64>,
                _t: ResizeTarget,
            ) -> Result<VolumeDeviceInfo, BtrfsError> {
                unreachable!()
            }
            async fn balance(
                &self,
                _m: String,
                _f: BalanceFilter,
            ) -> Result<BalanceReport, BtrfsError> {
                unreachable!()
            }
            async fn scrub(
                &self,
                _m: String,
                _id: Option<u64>,
                _ro: bool,
            ) -> Result<ScrubReport, BtrfsError> {
                unreachable!()
            }
            async fn quota_enable(&self, _m: String) -> Result<(), BtrfsError> {
                unreachable!()
            }
            async fn quota_disable(&self, _m: String) -> Result<(), BtrfsError> {
                unreachable!()
            }
            async fn quota_rescan(&self, _m: String) -> Result<(), BtrfsError> {
                unreachable!()
            }
            async fn get_quota_status(&self, _m: String) -> Result<QuotaStatus, BtrfsError> {
                unreachable!()
            }
            async fn qgroup_list(&self, _m: String) -> Result<Vec<QgroupInfo>, BtrfsError> {
                unreachable!()
            }
            async fn qgroup_create(&self, _m: String, _g: QgroupId) -> Result<(), BtrfsError> {
                unreachable!()
            }
            async fn qgroup_destroy(&self, _m: String, _g: QgroupId) -> Result<(), BtrfsError> {
                unreachable!()
            }
            async fn qgroup_assign(
                &self,
                _m: String,
                _mem: QgroupId,
                _p: QgroupId,
            ) -> Result<(), BtrfsError> {
                unreachable!()
            }
            async fn qgroup_remove(
                &self,
                _m: String,
                _mem: QgroupId,
                _p: QgroupId,
            ) -> Result<(), BtrfsError> {
                unreachable!()
            }
            async fn set_qgroup_limit(
                &self,
                _m: String,
                _g: QgroupId,
                _l: QgroupLimit,
            ) -> Result<(), BtrfsError> {
                unreachable!()
            }
        }

        struct FullDispatcher {
            preopens: rpc_preopens::RpcServer<FullPreopens>,
            fs: rpc_fs::RpcServer<FullFs>,
            programs: rpc_programs::RpcServer<FullPrograms>,
            components: test_cc::RpcServer<FullComponents>,
            mounts: test_mounts::RpcServer<FullMounts>,
            btrfs: test_btrfs::RpcServer<FullBtrfs>,
        }

        impl Dispatcher for FullDispatcher {
            type Resource = FullResource;
            fn supports(&self, instance: &str, func: &str) -> bool {
                self.preopens.supports_call(instance, func)
                    || self.fs.supports_call(instance, func)
                    || self.programs.supports_call(instance, func)
                    || self.components.supports_call(instance, func)
                    || self.mounts.supports_call(instance, func)
                    || self.btrfs.supports_call(instance, func)
            }
            async fn dispatch<'a>(
                &'a self,
                ctx: ServerInvocation<'a, Self::Resource>,
                instance: &'a str,
                func: &'a str,
            ) -> Result<(), WireError> {
                if self.preopens.supports_call(instance, func) {
                    self.preopens.dispatch_with(ctx, instance, func).await
                } else if self.fs.supports_call(instance, func) {
                    self.fs.dispatch_with(ctx, instance, func).await
                } else if self.programs.supports_call(instance, func) {
                    self.programs.dispatch_with(ctx, instance, func).await
                } else if self.components.supports_call(instance, func) {
                    self.components.dispatch_with(ctx, instance, func).await
                } else if self.mounts.supports_call(instance, func) {
                    self.mounts.dispatch_with(ctx, instance, func).await
                } else if self.btrfs.supports_call(instance, func) {
                    self.btrfs.dispatch_with(ctx, instance, func).await
                } else {
                    Err(WireError::MalformedPayload {
                        context: "FullDispatcher".to_owned(),
                        detail: format!("unsupported {instance}.{func}"),
                    })
                }
            }
        }

        // Seed remote OCI store with `docker.io/library/alpine:3.21` and a `/bin/busybox` binary inside its rootfs.
        let mem_fs = Arc::new(MemFs::new());
        let alpine_ref = ImageReference::parse("alpine:3.21").expect("ref");
        let layer_id = Digest::sha256(b"alpine-layer");
        let rootfs_dir = format!("/var/lib/helios/oci/layers/{}", layer_id.hex());
        mem_fs.seed_file(&format!("{rootfs_dir}/bin/busybox"), b"ELF".to_vec());
        let pulled = PulledImage {
            reference: alpine_ref.clone(),
            manifest_digest: Digest::sha256(b"alpine-manifest"),
            arch: Arch::Aarch64,
            config: ImageConfig {
                architecture: "arm64".to_owned(),
                os: "linux".to_owned(),
                config: ImageRuntimeConfig {
                    user: None,
                    env: vec!["PATH=/usr/bin:/bin".to_owned()],
                    entrypoint: Vec::new(),
                    cmd: vec!["/bin/sh".to_owned()],
                    working_dir: Some("/".to_owned()),
                    labels: BTreeMap::new(),
                    stop_signal: None,
                },
                rootfs: RootFs {
                    kind: "layers".to_owned(),
                    diff_ids: vec![layer_id.clone()],
                },
            },
            layer_chain_ids: vec![layer_id],
            rootfs_path: PathBuf::from(&rootfs_dir),
            btrfs_backed: false,
        };
        let record_path = format!(
            "/var/lib/helios/oci/images/{}.json",
            alpine_ref.storage_key()
        );
        mem_fs.seed_file(
            &record_path,
            serde_json::to_vec_pretty(&pulled).expect("json"),
        );

        let mut initial_components = BTreeMap::new();
        initial_components.insert(
            "/core/http".to_owned(),
            ComponentStatus {
                moniker: "/core/http".to_owned(),
                program: "/bin/http".to_owned(),
                state: "stopped".to_owned(),
                instance_id: None,
                restarts: 0,
            },
        );

        let (host, guest) = UnixStream::pair().expect("pair");
        host.set_nonblocking(true).expect("nb");
        guest.set_nonblocking(true).expect("nb");
        let host_r = host.try_clone().expect("clone");
        let guest_r = guest.try_clone().expect("clone");
        let conn = RpcConnection::from_split(
            Box::new(Async::new(host_r).expect("async")),
            Box::new(Async::new(host).expect("async")),
        );
        let session = Session::from_connection(
            Target::new("phase2-test", "serial:///tmp/p2.sock").expect("target"),
            conn,
            SessionOptions::default(),
        );
        let ep = Endpoint::new(
            Async::new(guest_r).expect("async"),
            Async::new(guest).expect("async"),
            FullDispatcher {
                preopens: rpc_preopens::RpcServer::new(FullPreopens),
                fs: rpc_fs::RpcServer::new(FullFs {
                    fs: Arc::clone(&mem_fs),
                }),
                programs: rpc_programs::RpcServer::new(FullPrograms {
                    default_image: Mutex::new(None),
                    spawned_paths: Mutex::new(Vec::new()),
                }),
                components: test_cc::RpcServer::new(FullComponents {
                    items: Mutex::new(initial_components),
                }),
                mounts: test_mounts::RpcServer::new(FullMounts {
                    mounted: Mutex::new(Vec::new()),
                }),
                btrfs: test_btrfs::RpcServer::new(FullBtrfs {
                    subvols: Mutex::new(BTreeMap::new()),
                }),
            },
        );
        let server_task = tokio::spawn(async move {
            let _ = ep.drive().await;
        });

        let env = HostEnv::new(session, None);

        // 1. linux image get (implicit alpine) -> set -> resolve_executable inside rootfs -> clear.
        let img0 = env.linux_image_get().await.expect("linux_image_get");
        assert_eq!(img0.default_ref, DEFAULT_LINUX_IMAGE_REF);
        assert_eq!(img0.image_ref, None);
        assert!(!img0.active);

        let img1 = env
            .linux_image_set("alpine:3.21", Some("arm64"))
            .await
            .expect("linux_image_set");
        assert!(img1.active);
        assert!(img1.persisted);
        let expected_canonical = alpine_ref.canonical();
        assert_eq!(img1.image_ref.as_deref(), Some(expected_canonical.as_str()));
        assert_eq!(img1.rootfs_path.as_deref(), Some(rootfs_dir.as_str()));

        let resolved = env
            .resolve_executable("busybox", &["/usr/bin".to_owned(), "/bin".to_owned()])
            .await
            .expect("resolve_executable")
            .expect("busybox should resolve inside active default Linux image");
        assert_eq!(resolved.path, "/bin/busybox");

        let cleared = env.linux_image_clear().await.expect("linux_image_clear");
        assert!(cleared.cleared);
        assert_eq!(
            cleared.previous_ref.as_deref(),
            Some(expected_canonical.as_str())
        );

        // 2. component {ls, status, start, stop, restart, add, rm} via eval_command + HostEnv.
        let comps = env.component_list().await.expect("component_list");
        assert_eq!(comps.len(), 1);
        let started = env.component_start("/core/http").await.expect("start");
        assert_eq!(started.state, "running");
        let restarted = env.component_restart("/core/http").await.expect("restart");
        assert_eq!(restarted.restarts, 1);
        env.component_stop("/core/http").await.expect("stop");
        let status = env.component_status("/core/http").await.expect("status");
        assert_eq!(status.state, "stopped");

        let mounted = env
            .component_add(ComponentAddRequest {
                parent_moniker: "/core".to_owned(),
                source: ComponentSubtreeSource::GuestDir {
                    subtree_name: "edge".to_owned(),
                    path: "/data/edge".to_owned(),
                },
            })
            .await
            .expect("component_add");
        assert_eq!(mounted, "/core/edge");
        env.component_remove(&mounted)
            .await
            .expect("component_remove");

        // 3. oci {ls, inspect, rm}.
        let oci_list = env.oci_list().await.expect("oci_list");
        assert_eq!(oci_list.len(), 1);
        let oci_info = env.oci_inspect("alpine:3.21").await.expect("oci_inspect");
        assert_eq!(oci_info.reference, expected_canonical);

        // 4. container {create --image, ls, exec (CJK), spawn, rm} & with-container.
        let ctr = env
            .container_create(ContainerCreateRequest {
                image: Some("alpine:3.21".to_owned()),
                rootfs: None,
                mounts: Vec::new(),
                grants: Vec::new(),
                hostname: Some("alpine-ctr".to_owned()),
                domainname: None,
                uid: None,
                gid: None,
                env: BTreeMap::new(),
                cwd: None,
            })
            .await
            .expect("container_create");
        assert_eq!(env.container_list().await.expect("container_list").len(), 1);
        let exec_out = env
            .container_exec(
                &ctr.handle,
                helios_nu::ContainerExecRequest {
                    program: "/bin/busybox".to_owned(),
                    args: Vec::new(),
                    env: BTreeMap::new(),
                    cwd: None,
                    stdin: Vec::new(),
                },
            )
            .await
            .expect("container_exec");
        assert_eq!(exec_out.exit_code, 0);
        let stdout_text = String::from_utf8(exec_out.stdout).expect("utf8");
        assert!(stdout_text.contains("你好 こんにちは 안녕하세요"));
        let with_ctr_out = eval_command(
            env.clone(),
            &format!("with-container {} {{ ^/bin/busybox }}", ctr.handle),
            OutputFormat::Json,
        )
        .await
        .expect("with-container");
        assert!(with_ctr_out.contains("ctr-spawn:/bin/busybox"));
        env.container_remove(&ctr.handle)
            .await
            .expect("container_remove");

        env.oci_remove("alpine:3.21").await.expect("oci_remove");
        assert!(env.oci_list().await.expect("oci_list empty").is_empty());

        // 5. mount / umount & btrfs subvolume {create, snapshot, list, show, set-ro, send, receive, delete}.
        env.mount(MountRequestSpec {
            source: MountSourceSpec::Memory,
            path: "/mnt/scratch".to_owned(),
            read_only: false,
            sharing: MountSharingSpec::Private,
            compress: None,
            commit: None,
            max_inline: None,
        })
        .await
        .expect("mount");
        assert!(!env.list_mounts().await.expect("list_mounts").is_empty());
        env.umount("/mnt/scratch").await.expect("umount");

        let sub = env
            .btrfs_subvolume_create("/data/app")
            .await
            .expect("btrfs create");
        assert_eq!(sub.path, "/data/app");
        let snap = env
            .btrfs_subvolume_snapshot("/data/app", "/data/app-ro", true)
            .await
            .expect("btrfs snapshot");
        assert!(snap.read_only);
        assert_eq!(
            env.btrfs_subvolume_list("/data")
                .await
                .expect("btrfs list")
                .len(),
            2
        );
        env.btrfs_subvolume_set_ro("/data/app-ro", false)
            .await
            .expect("btrfs set-ro");
        assert!(
            !env.btrfs_subvolume_info("/data/app-ro")
                .await
                .expect("btrfs show")
                .read_only
        );
        let stream = env
            .btrfs_subvolume_send("/data/app-ro", None, &[])
            .await
            .expect("btrfs send");
        assert!(stream.starts_with(b"btrfs-stream"));
        let recv = env
            .btrfs_subvolume_receive("/data", stream)
            .await
            .expect("btrfs receive");
        assert_eq!(recv.path, "/data/received");
        env.btrfs_subvolume_delete("/data/app-ro")
            .await
            .expect("btrfs delete");

        // 6. vm run --detach & vm ls.
        let vm = env
            .vm_run(VmRunRequest {
                name: Some("alpine-vm".to_owned()),
                kernel: Some("/boot/Image".to_owned()),
                initramfs: None,
                cpus: 2,
                memory_mib: 256,
                cmdline: Some("console=hvc0".to_owned()),
                disk: None,
                shares: Vec::new(),
                rootfs_dir: None,
                oci_ref: None,
                detach: true,
            })
            .await
            .expect("vm_run");
        assert_eq!(vm.name, "alpine-vm");
        assert_eq!(vm.cpus, 2);
        let vms = env.vm_list().await.expect("vm_list");
        assert_eq!(vms.len(), 1);

        server_task.abort();
    }
}
