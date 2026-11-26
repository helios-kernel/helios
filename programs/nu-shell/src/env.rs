//! Guest [`HeliosEnv`] implementation backed directly by async-first `helios-api`.

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, FixedOffset, TimeZone};
use futures_lite::future::zip;
use helios_api::bindings::wasi::cli::{terminal_stdin, terminal_stdout};
use helios_api::bindings::wasi::clocks::{monotonic_clock, system_clock};
use helios_api::bindings::wasi::filesystem::preopens;
use helios_api::bindings::wasi::filesystem::types::{
    Descriptor, DescriptorFlags, DescriptorStat, DescriptorType, ErrorCode, NewTimestamp,
    OpenFlags, PathFlags,
};
use helios_api::bindings::wit_stream;
use helios_api::btrfs::{self, BtrfsError, BtrfsErrorKind, SubvolumeInfo as ApiSubvolumeInfo};
use helios_api::inspect::{self, Query as InspectQuery, Value as RawInspectValue};
use helios_api::instances::{self, KillError};
use helios_api::io as helios_io;
use helios_api::linux::{Container as ApiContainer, ContainerBuilder as ApiContainerBuilder};
use helios_api::mounts::{
    self, MountError, MountErrorKind, MountRequest as ApiMountRequest,
    MountSharing as ApiMountSharing, MountSource as ApiMountSource,
};
use helios_api::oci::{
    Arch, BtrfsSubvolumeBackend, DefaultImageStore, ImageReference, ImageStore, OciVmRootfs,
    PulledImage, RegistryClient, SubvolumeBackend as _, UserDefaultImage,
    default_linux_image_from_oci, open_image_store,
};
use helios_api::processors;
use helios_api::profiling::{self, InstructionProfileError, SamplingSession};
use helios_api::programs::{
    self, AuthorityScope, CapabilityGrant, Child, ChildTermination, ClockRight,
    ContainerCredentials, ContainerExecRequest as ApiContainerExecRequest,
    ContainerMount as ApiContainerMount, ContainerMountSharing as ApiContainerMountSharing,
    ContainerSpawnRequest as ApiContainerSpawnRequest, DefaultLinuxImage, DeviceClass,
    DiagnosticsGrant, ExecError, ExecErrorKind, FilesystemRight, LinkRight, MachineRight,
    MountRight, NetworkRight, NonFsGrant, NonFsGrants, ProcessRight, SettingsRight, SpawnError,
    SpawnRequest, TerminalRight, clock_grant, device_grant, diagnostics_control_grant,
    diagnostics_grant, directory_grant, inspect_read_grant, instance_control_grant, link_grant,
    machine_grant, mount_grant, network_grant, process_grant, root_link_grant, root_process_grant,
    settings_grant, terminal_grant, virtualize_grant,
};
use helios_api::snapshot::{self, SnapshotError, SnapshotHold};
use helios_api::task;
use helios_nu::{
    BtrfsSubvolumeInfo, ComponentAddRequest, ComponentInfo, ComponentSubtreeSource,
    ContainerCreateRequest, ContainerExecOutput, ContainerExecRequest, ContainerInfo,
    ContainerMountSharingSpec, ContainerSpawnRequest, DEFAULT_LINUX_IMAGE_REF, EnvError,
    ExecutableMatch, ExternalProcess, ExternalSpawnRequest, FileMetadata, FileType, GrantSpec,
    HeliosEnv, InspectEntry, InspectValue, InstructionProfileSummary, LinuxImageClearResult,
    LinuxImageInfo, MountEntryInfo, MountRequestSpec, MountSharingSpec, MountSourceSpec,
    OciImageInspect, OciImageSummary, ProcessInfo, STREAM_CHANNEL_CAPACITY, SnapshotInfo,
    SysCpuInfo, SysDiskInfo, SysHostInfo, SysMemInfo, SysNetInfo, VmInfo, VmRunRequest, WatchEvent,
    normalize_vfs_path,
};
use helios_vmm::{ExitReason, MicroVm};
use helios_wit_rpc::PeerHandle;
use helios_wit_rpc::inspector::helios::system::component_control::{
    self as rpc_cc, ControlError, ControlErrorKind,
};

use crate::control;

const STREAM_READ_CHUNK: usize = 16 * 1024;
const DEFAULT_OCI_STORE_PATH: &str = "/var/lib/oci";
const DEFAULT_LINUX_SEARCH_DIRS: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];

struct GuestContainerEntry {
    info: ContainerInfo,
    container: ApiContainer,
}

struct ActiveProfile {
    target: String,
    started_nanos: u64,
    _session: SamplingSession,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HeldCapabilities {
    has_machine_inspect: bool,
    has_terminal_stdin: bool,
    has_terminal_stdout: bool,
}

impl HeldCapabilities {
    fn append_non_directory_grants(self, grants: &mut Vec<CapabilityGrant>) {
        grants.push(root_link_grant());
        grants.push(root_process_grant());
        if self.has_machine_inspect {
            grants.push(inspect_read_grant(AuthorityScope::Machine));
        }
        let mut terminal_rights = Vec::new();
        if self.has_terminal_stdin {
            terminal_rights.push(TerminalRight::Input);
        }
        if self.has_terminal_stdout {
            terminal_rights.push(TerminalRight::Output);
            terminal_rights.push(TerminalRight::Control);
        }
        if !terminal_rights.is_empty() {
            grants.push(terminal_grant(terminal_rights));
        }
    }
}

/// Guest implementation of [`HeliosEnv`] over `helios-api` and WASI Preview 3.
pub struct GuestHeliosEnv {
    cwd: Mutex<String>,
    scopes: Mutex<Vec<String>>,
    snapshots: Mutex<BTreeMap<String, SnapshotHold>>,
    profiles: Mutex<BTreeMap<String, ActiveProfile>>,
    oci_store_root: PathBuf,
    default_image_cleared: Mutex<bool>,
    default_image_ref: Mutex<Option<String>>,
    component_control: Option<PeerHandle>,
    containers: Mutex<BTreeMap<String, Arc<GuestContainerEntry>>>,
    vms: Arc<Mutex<Vec<VmInfo>>>,
    held: HeldCapabilities,
    next_id: AtomicU64,
}

impl GuestHeliosEnv {
    /// Construct a guest environment anchored at `initial_cwd`.
    pub fn new(initial_cwd: String) -> Self {
        let initial_cwd = normalize_vfs_path("/", &initial_cwd);
        // Probe only non-privileged, side-effect-free queries for held rights.
        let has_machine_inspect = inspect::snapshot(
            &InspectQuery {
                prefixes: vec![String::from("/kernel/")],
            },
            1,
        )
        .is_ok_and(|snap| !snap.entries.is_empty());
        let has_terminal_stdin = terminal_stdin::get_terminal_stdin().is_some();
        let has_terminal_stdout = terminal_stdout::get_terminal_stdout().is_some();
        let oci_store_root = PathBuf::from(
            std::env::var("HELIOS_OCI_STORE")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| String::from(DEFAULT_OCI_STORE_PATH)),
        );
        let component_control = control::connect_component_control();

        Self {
            cwd: Mutex::new(initial_cwd),
            scopes: Mutex::new(Vec::new()),
            snapshots: Mutex::new(BTreeMap::new()),
            profiles: Mutex::new(BTreeMap::new()),
            oci_store_root,
            default_image_cleared: Mutex::new(false),
            default_image_ref: Mutex::new(None),
            component_control,
            containers: Mutex::new(BTreeMap::new()),
            vms: Arc::new(Mutex::new(Vec::new())),
            held: HeldCapabilities {
                has_machine_inspect,
                has_terminal_stdin,
                has_terminal_stdout,
            },
            next_id: AtomicU64::new(1),
        }
    }

    fn current_cwd(&self) -> String {
        self.cwd.lock().expect("guest cwd lock poisoned").clone()
    }

    fn principal(&self) -> String {
        std::env::var("USER")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| String::from("helios"))
    }

    fn open_oci_store(&self) -> Result<ImageStore<BtrfsSubvolumeBackend>, EnvError> {
        open_image_store(&self.oci_store_root).map_err(map_oci_error)
    }

    fn detect_guest_arch(&self) -> Arch {
        if let Ok(snap) = inspect::snapshot(
            &InspectQuery {
                prefixes: vec![String::from("/kernel/processors/guest-isa-level")],
            },
            4,
        ) {
            for entry in snap.entries {
                if let RawInspectValue::Text(isa) = entry.value {
                    let lower = isa.to_ascii_lowercase();
                    if lower.starts_with("aarch64") || lower.starts_with("arm") {
                        return Arch::Aarch64;
                    }
                    if lower.starts_with("x86") || lower.starts_with("amd64") {
                        return Arch::X86_64;
                    }
                }
            }
        }
        Arch::host_default()
    }

    fn parse_target_arch(&self, arch: Option<&str>) -> Result<Arch, EnvError> {
        match arch {
            Some(raw) => Arch::parse(raw).ok_or_else(|| EnvError::InvalidArgument {
                detail: format!(
                    "unsupported OCI architecture `{raw}` (expected amd64/x86_64 or arm64/aarch64)"
                ),
            }),
            None => Ok(self.detect_guest_arch()),
        }
    }

    async fn ensure_oci_image(
        &self,
        reference: &str,
        arch: Option<&str>,
    ) -> Result<PulledImage, EnvError> {
        let parsed = ImageReference::parse(reference).map_err(map_oci_error)?;
        let target_arch = self.parse_target_arch(arch)?;
        let store = self.open_oci_store()?;
        if let Some(cached) = store.get_image(&parsed).map_err(map_oci_error)?
            && cached.arch == target_arch
            && cached.rootfs_path().is_dir()
        {
            return Ok(cached);
        }
        let mut client = RegistryClient::new();
        store
            .pull(&mut client, &parsed, target_arch)
            .await
            .map_err(map_oci_error)
    }

    /// Ensure the current shell instance has a default Linux root image configured:
    /// 1. Honors an already-active/inherited `programs.get-default-image()`.
    /// 2. Respects an explicit `linux image clear` in the current session.
    /// 3. Loads any persisted per-user preference from [`DefaultImageStore`].
    /// 4. When `allow_auto_pull` is `true`, lazily pulls `alpine` via `helios-oci`
    ///    and installs it with `programs.set-default-image`.
    async fn ensure_default_linux_image(
        &self,
        allow_auto_pull: bool,
    ) -> Result<Option<DefaultLinuxImage>, EnvError> {
        if let Some(active) = programs::get_default_image() {
            return Ok(Some(active));
        }
        if *self
            .default_image_cleared
            .lock()
            .expect("default_image_cleared lock poisoned")
        {
            return Ok(None);
        }

        let principal = self.principal();
        let prefs_path = DefaultImageStore::path_in_store(&self.oci_store_root);
        if let Ok(pref_store) = DefaultImageStore::load(&prefs_path)
            && let Ok(Some(saved)) = pref_store.get(&principal)
        {
            let image = default_image_from_pref(saved);
            programs::set_default_image(Some(image.clone()))
                .await
                .map_err(map_spawn_error)?;
            *self
                .default_image_ref
                .lock()
                .expect("default_image_ref lock poisoned") = Some(saved.image_ref.clone());
            return Ok(Some(image));
        }

        if !allow_auto_pull {
            return Ok(None);
        }

        let pulled = self.ensure_oci_image(DEFAULT_LINUX_IMAGE_REF, None).await?;
        let default_img = default_linux_image_from_oci(&pulled).map_err(map_oci_error)?;
        programs::set_default_image(Some(default_img.clone()))
            .await
            .map_err(map_spawn_error)?;
        *self
            .default_image_ref
            .lock()
            .expect("default_image_ref lock poisoned") = Some(pulled.reference.canonical());
        Ok(Some(default_img))
    }

    fn component_control_client(&self) -> Result<rpc_cc::RpcClient, EnvError> {
        self.component_control
            .clone()
            .map(rpc_cc::RpcClient::new)
            .ok_or_else(|| EnvError::PermissionDenied {
                detail: String::from(
                    "component-control capability not granted to this shell instance",
                ),
            })
    }

    fn read_oci_images(&self) -> Result<Vec<PulledImage>, EnvError> {
        let images_dir = self.oci_store_root.join("images");
        let entries = match std::fs::read_dir(&images_dir) {
            Ok(iter) => iter,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => {
                return Err(EnvError::Io {
                    detail: format!("failed to read `{}`: {err}", images_dir.display()),
                });
            }
        };
        let mut images = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|err| EnvError::Io {
                detail: format!("failed reading OCI store entry: {err}"),
            })?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let raw = std::fs::read_to_string(&path).map_err(|err| EnvError::Io {
                detail: format!("failed reading `{}`: {err}", path.display()),
            })?;
            let img: PulledImage = serde_json::from_str(&raw).map_err(|err| EnvError::Io {
                detail: format!("malformed OCI image record `{}`: {err}", path.display()),
            })?;
            images.push(img);
        }
        images.sort_by_key(|a| a.reference.canonical());
        Ok(images)
    }

    async fn default_child_grants(&self) -> Vec<CapabilityGrant> {
        let mut grants = preopen_directory_grants(true).await;
        self.held.append_non_directory_grants(&mut grants);
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
                "virtualize" => {
                    if !spec.target.is_empty() && spec.target != "virtualize" {
                        return Err(EnvError::InvalidArgument {
                            detail: format!("unexpected `virtualize` target `{}`", spec.target),
                        });
                    }
                    if let Some(mode) = &spec.mode {
                        return Err(EnvError::InvalidArgument {
                            detail: format!("unexpected `virtualize` mode `{mode}`"),
                        });
                    }
                    grants.push(virtualize_grant());
                }
                "machine" => {
                    let rights = match spec.target.as_str() {
                        "identity" => vec![MachineRight::Identity],
                        "virtualize" => vec![MachineRight::Virtualize],
                        "all" => vec![
                            MachineRight::Control,
                            MachineRight::Identity,
                            MachineRight::Virtualize,
                        ],
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
            env_pairs.push((String::from("PWD"), request.cwd.clone()));
        }

        let capability_grants = if request.grants.is_empty() {
            self.default_child_grants().await
        } else {
            self.translate_explicit_grants(&request.grants)?
        };
        let cwd = (!request.cwd.is_empty()).then_some(request.cwd);
        let child = Child::spawn(SpawnRequest {
            name: request.program,
            args: request.args,
            env: env_pairs,
            path: resolved_path,
            cwd,
            sockets: Vec::new(),
            capability_grants,
        })
        .await
        .map_err(map_spawn_error)?;

        Ok(wire_child_streams(
            child,
            request.stdin,
            request.capture_stdout,
            request.capture_stderr,
        ))
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
            if let Some(default_img) = self.resolve_default_linux_image_for_exec().await {
                let in_image = join_under_root(&default_img.root_path, &candidate);
                match lstat_path(&in_image).await {
                    Ok(meta) if matches!(meta.file_type, FileType::File | FileType::Symlink) => {
                        return Ok(Some(ExecutableMatch {
                            command: name.to_owned(),
                            path: candidate,
                        }));
                    }
                    Err(EnvError::PermissionDenied { .. }) => {
                        // Inherited `set-default-image` roots are pinned by the kernel even
                        // when this shell holds no direct WASI preopen covering `root_path`.
                        return Ok(Some(ExecutableMatch {
                            command: name.to_owned(),
                            path: candidate,
                        }));
                    }
                    _ => {}
                }
            }
            return Ok(None);
        }

        let search_dirs: Vec<String> = if path_env.is_empty() {
            vec![String::from("/bin")]
        } else {
            path_env.to_vec()
        };

        for dir in &search_dirs {
            let candidate = normalize_vfs_path(dir, name);
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

        if let Some(default_img) = self.resolve_default_linux_image_for_exec().await {
            let image_dirs = collect_linux_search_dirs(&search_dirs, &default_img.env);
            let mut saw_permission_denied = false;
            for dir in &image_dirs {
                let candidate = normalize_vfs_path(dir, name);
                let in_image = join_under_root(&default_img.root_path, &candidate);
                match lstat_path(&in_image).await {
                    Ok(meta) if matches!(meta.file_type, FileType::File | FileType::Symlink) => {
                        return Ok(Some(ExecutableMatch {
                            command: name.to_owned(),
                            path: candidate,
                        }));
                    }
                    Err(EnvError::PermissionDenied { .. }) => {
                        saw_permission_denied = true;
                    }
                    _ => {}
                }
            }
            if saw_permission_denied {
                return Ok(Some(ExecutableMatch {
                    command: name.to_owned(),
                    path: format!("/bin/{name}"),
                }));
            }
        }

        Ok(None)
    }

    async fn list_executables(&self) -> Result<Vec<String>, EnvError> {
        let mut names = BTreeSet::new();
        if let Ok(entries) = self.list_dir("/bin").await {
            for entry in entries {
                if matches!(entry.file_type, FileType::File | FileType::Symlink) {
                    names.insert(entry.name);
                }
            }
        }
        if let Some(default_img) = programs::get_default_image() {
            for sub in ["/bin", "/usr/bin"] {
                let dir = join_under_root(&default_img.root_path, sub);
                if let Ok(entries) = self.list_dir(&dir).await {
                    for entry in entries {
                        if matches!(entry.file_type, FileType::File | FileType::Symlink) {
                            names.insert(entry.name);
                        }
                    }
                }
            }
        }
        Ok(names.into_iter().collect())
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

    async fn linux_image_get(&self) -> Result<LinuxImageInfo, EnvError> {
        let principal = self.principal();
        let active = programs::get_default_image();
        let prefs_path = DefaultImageStore::path_in_store(&self.oci_store_root);
        let saved = DefaultImageStore::load(&prefs_path)
            .ok()
            .and_then(|store| store.get(&principal).ok().flatten().cloned());
        let session_ref = self
            .default_image_ref
            .lock()
            .expect("default_image_ref lock poisoned")
            .clone();

        let (image_ref, rootfs_path, env, uid, gid, persisted) = match (&active, &saved) {
            (Some(act), Some(pref)) => (
                session_ref.or_else(|| Some(pref.image_ref.clone())),
                Some(act.root_path.clone()),
                act.env.clone(),
                act.credentials.as_ref().map(|c| c.uid),
                act.credentials.as_ref().map(|c| c.gid),
                true,
            ),
            (Some(act), None) => (
                session_ref,
                Some(act.root_path.clone()),
                act.env.clone(),
                act.credentials.as_ref().map(|c| c.uid),
                act.credentials.as_ref().map(|c| c.gid),
                false,
            ),
            (None, Some(pref)) => (
                Some(pref.image_ref.clone()),
                Some(pref.rootfs_path.clone()),
                pref.env.clone(),
                Some(pref.credentials.uid),
                Some(pref.credentials.gid),
                true,
            ),
            (None, None) => (None, None, Vec::new(), None, None, false),
        };

        Ok(LinuxImageInfo {
            principal,
            image_ref,
            default_ref: String::from(DEFAULT_LINUX_IMAGE_REF),
            rootfs_path,
            active: active.is_some(),
            persisted,
            env,
            uid,
            gid,
        })
    }

    async fn linux_image_set(
        &self,
        image_ref: &str,
        arch: Option<&str>,
    ) -> Result<LinuxImageInfo, EnvError> {
        let pulled = self.ensure_oci_image(image_ref, arch).await?;
        let default_img = default_linux_image_from_oci(&pulled).map_err(map_oci_error)?;
        programs::set_default_image(Some(default_img.clone()))
            .await
            .map_err(map_spawn_error)?;

        let principal = self.principal();
        let pref = UserDefaultImage::from_pulled_image(&pulled).map_err(map_oci_error)?;
        let prefs_path = DefaultImageStore::path_in_store(&self.oci_store_root);
        let mut pref_store = DefaultImageStore::load(&prefs_path).map_err(map_oci_error)?;
        pref_store
            .set(&principal, pref.clone())
            .map_err(map_oci_error)?;

        *self
            .default_image_cleared
            .lock()
            .expect("default_image_cleared lock poisoned") = false;
        *self
            .default_image_ref
            .lock()
            .expect("default_image_ref lock poisoned") = Some(pref.image_ref.clone());

        Ok(LinuxImageInfo {
            principal,
            image_ref: Some(pref.image_ref),
            default_ref: String::from(DEFAULT_LINUX_IMAGE_REF),
            rootfs_path: Some(default_img.root_path),
            active: true,
            persisted: true,
            env: default_img.env,
            uid: default_img.credentials.as_ref().map(|c| c.uid),
            gid: default_img.credentials.as_ref().map(|c| c.gid),
        })
    }

    async fn linux_image_clear(&self) -> Result<LinuxImageClearResult, EnvError> {
        programs::set_default_image(None)
            .await
            .map_err(map_spawn_error)?;
        *self
            .default_image_cleared
            .lock()
            .expect("default_image_cleared lock poisoned") = true;
        let prev_session = self
            .default_image_ref
            .lock()
            .expect("default_image_ref lock poisoned")
            .take();

        let principal = self.principal();
        let prefs_path = DefaultImageStore::path_in_store(&self.oci_store_root);
        let prev_persisted = match DefaultImageStore::load(&prefs_path) {
            Ok(mut store) => store
                .clear(&principal)
                .map_err(map_oci_error)?
                .map(|p| p.image_ref),
            Err(_) => None,
        };
        let previous_ref = prev_persisted.or(prev_session);
        Ok(LinuxImageClearResult {
            principal,
            cleared: true,
            previous_ref,
        })
    }

    async fn component_list(&self) -> Result<Vec<ComponentInfo>, EnvError> {
        let client = self.component_control_client()?;
        run_local(async move {
            let list = client
                .list_components()
                .await
                .map_err(map_rpc_transport_error)?
                .map_err(map_control_error)?;
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
        })
        .await
    }

    async fn component_status(&self, moniker: &str) -> Result<ComponentInfo, EnvError> {
        let list = self.component_list().await?;
        list.into_iter()
            .find(|c| c.moniker == moniker)
            .ok_or_else(|| EnvError::NotFound {
                path: moniker.to_owned(),
            })
    }

    async fn component_start(&self, moniker: &str) -> Result<ComponentInfo, EnvError> {
        let client = self.component_control_client()?;
        let moniker = moniker.to_owned();
        run_local(async move {
            let c = client
                .start(moniker)
                .await
                .map_err(map_rpc_transport_error)?
                .map_err(map_control_error)?;
            Ok(ComponentInfo {
                moniker: c.moniker,
                program: c.program,
                state: c.state,
                instance_id: c.instance_id,
                restarts: c.restarts,
            })
        })
        .await
    }

    async fn component_stop(&self, moniker: &str) -> Result<(), EnvError> {
        let client = self.component_control_client()?;
        let moniker = moniker.to_owned();
        run_local(async move {
            client
                .stop(moniker)
                .await
                .map_err(map_rpc_transport_error)?
                .map_err(map_control_error)
        })
        .await
    }

    async fn component_restart(&self, moniker: &str) -> Result<ComponentInfo, EnvError> {
        let client = self.component_control_client()?;
        let moniker = moniker.to_owned();
        run_local(async move {
            let c = client
                .restart(moniker)
                .await
                .map_err(map_rpc_transport_error)?
                .map_err(map_control_error)?;
            Ok(ComponentInfo {
                moniker: c.moniker,
                program: c.program,
                state: c.state,
                instance_id: c.instance_id,
                restarts: c.restarts,
            })
        })
        .await
    }

    async fn component_add(&self, request: ComponentAddRequest) -> Result<String, EnvError> {
        let client = self.component_control_client()?;
        let parent = request.parent_moniker;
        let source = match request.source {
            ComponentSubtreeSource::GuestDir { subtree_name, path } => {
                rpc_cc::DynamicSubtreeSource::GuestDir(rpc_cc::DynamicDirSource {
                    subtree_name,
                    path,
                })
            }
            ComponentSubtreeSource::Manifests(entries) => {
                rpc_cc::DynamicSubtreeSource::Manifests(entries)
            }
        };
        run_local(async move {
            client
                .mount_dynamic(parent, source)
                .await
                .map_err(map_rpc_transport_error)?
                .map_err(map_control_error)
        })
        .await
    }

    async fn component_remove(&self, moniker: &str) -> Result<(), EnvError> {
        let client = self.component_control_client()?;
        let moniker = moniker.to_owned();
        run_local(async move {
            client
                .unmount_dynamic(moniker)
                .await
                .map_err(map_rpc_transport_error)?
                .map_err(map_control_error)
        })
        .await
    }

    async fn oci_pull(
        &self,
        reference: &str,
        arch: Option<&str>,
    ) -> Result<OciImageSummary, EnvError> {
        let pulled = self.ensure_oci_image(reference, arch).await?;
        Ok(pulled_to_summary(&pulled))
    }

    async fn oci_list(&self) -> Result<Vec<OciImageSummary>, EnvError> {
        let images = self.read_oci_images()?;
        Ok(images.iter().map(pulled_to_summary).collect())
    }

    async fn oci_inspect(&self, reference: &str) -> Result<OciImageInspect, EnvError> {
        let parsed = ImageReference::parse(reference).map_err(map_oci_error)?;
        let store = self.open_oci_store()?;
        let pulled = store
            .get_image(&parsed)
            .map_err(map_oci_error)?
            .ok_or_else(|| EnvError::NotFound {
                path: reference.to_owned(),
            })?;
        Ok(OciImageInspect {
            reference: pulled.reference.canonical(),
            digest: pulled.manifest_digest.as_str(),
            arch: pulled.arch.to_string(),
            os: pulled.config.os.clone(),
            layer_chain_ids: pulled
                .layer_chain_ids
                .iter()
                .map(helios_api::oci::Digest::as_str)
                .collect(),
            rootfs_path: pulled.rootfs_path.to_string_lossy().into_owned(),
            btrfs_backed: pulled.btrfs_backed,
            user: pulled.config.config.user.clone(),
            working_dir: pulled.config.config.working_dir.clone(),
            entrypoint: pulled.config.config.entrypoint.clone(),
            cmd: pulled.config.config.cmd.clone(),
            env: pulled.config.config.env_pairs(),
            labels: pulled.config.config.labels.clone(),
        })
    }

    async fn oci_remove(&self, reference: &str) -> Result<(), EnvError> {
        let parsed = ImageReference::parse(reference).map_err(map_oci_error)?;
        let store = self.open_oci_store()?;
        let removed = store
            .get_image(&parsed)
            .map_err(map_oci_error)?
            .ok_or_else(|| EnvError::NotFound {
                path: reference.to_owned(),
            })?;
        let record_path = self
            .oci_store_root
            .join("images")
            .join(format!("{}.json", parsed.storage_key()));
        std::fs::remove_file(&record_path).map_err(|err| EnvError::Io {
            detail: format!("failed to remove `{}`: {err}", record_path.display()),
        })?;

        // Garbage-collect layers that are no longer referenced by any remaining image.
        let remaining = self.read_oci_images().unwrap_or_default();
        let mut live_layers = BTreeSet::new();
        for img in &remaining {
            for cid in &img.layer_chain_ids {
                live_layers.insert(cid.hex().to_owned());
            }
        }
        let backend = BtrfsSubvolumeBackend;
        for cid in removed.layer_chain_ids.iter().rev() {
            if live_layers.contains(cid.hex()) {
                continue;
            }
            let layer_dir = store.layer_path(cid);
            if removed.btrfs_backed {
                let _ = backend.set_subvolume_read_only(&layer_dir, false).await;
                let _ = backend.delete_subvolume(&layer_dir).await;
            }
            if layer_dir.exists() {
                let _ = std::fs::remove_dir_all(&layer_dir);
            }
            let meta_path = store.layer_meta_path(cid);
            if meta_path.exists() {
                let _ = std::fs::remove_file(&meta_path);
            }
        }
        Ok(())
    }

    async fn container_create(
        &self,
        request: ContainerCreateRequest,
    ) -> Result<ContainerInfo, EnvError> {
        let mut builder = if let Some(ref image_ref) = request.image {
            let pulled = self.ensure_oci_image(image_ref, None).await?;
            ApiContainerBuilder::from_image(&pulled).map_err(|err| EnvError::Io {
                detail: err.to_string(),
            })?
        } else if let Some(ref rootfs) = request.rootfs {
            ApiContainer::ephemeral(rootfs.clone())
        } else {
            return Err(EnvError::InvalidArgument {
                detail: String::from("container create requires an OCI image or `--rootfs`"),
            });
        };

        for mount in &request.mounts {
            let rights = parse_fs_rights(&mount.mode)?;
            let sharing = match mount.sharing {
                ContainerMountSharingSpec::Private => ApiContainerMountSharing::Private,
                ContainerMountSharingSpec::Shared => ApiContainerMountSharing::Shared,
                ContainerMountSharingSpec::EphemeralOverlay => {
                    ApiContainerMountSharing::EphemeralOverlay
                }
            };
            builder = builder.mount(ApiContainerMount {
                source_path: mount.source_path.clone(),
                target_path: mount.target_path.clone(),
                rights,
                sharing,
            });
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

        let non_fs = self.translate_non_fs_grants(&request.grants)?;
        builder = builder.grants(non_fs);

        let spec = builder.into_spec();
        let rootfs_path = spec.config.root.source_path.clone();
        let hostname = spec.config.hostname.clone();
        let cwd = spec.default_cwd.clone();
        let uid = spec.config.credentials.uid;
        let gid = spec.config.credentials.gid;

        let mut create_builder = ApiContainerBuilder::new(spec.config.root);
        for m in spec.config.mounts {
            create_builder = create_builder.mount(m);
        }
        create_builder = create_builder
            .shared_owner(spec.config.shared_owner.uid, spec.config.shared_owner.gid)
            .credentials(spec.config.credentials)
            .hostname(spec.config.hostname)
            .domainname(spec.config.domainname)
            .envs(spec.default_env)
            .entrypoint(spec.entrypoint)
            .default_cmd(spec.cmd);
        if let Some(dir) = spec.default_cwd {
            create_builder = create_builder.working_dir(dir);
        }
        let mut rebuilt_non_fs = NonFsGrants::new();
        for g in spec.config.capability_grants {
            if let Some(nfg) = capability_grant_to_non_fs(g) {
                rebuilt_non_fs = rebuilt_non_fs.grant(nfg);
            }
        }
        create_builder = create_builder.grants(rebuilt_non_fs);

        let container = create_builder.create().await.map_err(map_spawn_error)?;
        let seq = self.next_id.fetch_add(1, Ordering::Relaxed);
        let handle = format!("ctr-{seq}");
        let info = ContainerInfo {
            handle: handle.clone(),
            image: request.image,
            rootfs_path,
            hostname,
            cwd,
            uid,
            gid,
        };
        self.containers
            .lock()
            .expect("guest containers lock poisoned")
            .insert(
                handle,
                Arc::new(GuestContainerEntry {
                    info: info.clone(),
                    container,
                }),
            );
        Ok(info)
    }

    async fn container_list(&self) -> Result<Vec<ContainerInfo>, EnvError> {
        Ok(self
            .containers
            .lock()
            .expect("guest containers lock poisoned")
            .values()
            .map(|e| e.info.clone())
            .collect())
    }

    async fn container_exec(
        &self,
        handle: &str,
        request: ContainerExecRequest,
    ) -> Result<ContainerExecOutput, EnvError> {
        let entry = self
            .containers
            .lock()
            .expect("guest containers lock poisoned")
            .get(handle)
            .cloned()
            .ok_or_else(|| EnvError::NotFound {
                path: handle.to_owned(),
            })?;
        let env_pairs: Vec<(String, String)> = request.env.into_iter().collect();
        let res = entry
            .container
            .exec(ApiContainerExecRequest {
                name: request.program.clone(),
                args: request.args,
                env: env_pairs,
                path: request.program,
                cwd: request.cwd,
                stdin: request.stdin,
                credentials: None,
            })
            .await
            .map_err(map_exec_error)?;
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
            .expect("guest containers lock poisoned")
            .get(handle)
            .cloned()
            .ok_or_else(|| EnvError::NotFound {
                path: handle.to_owned(),
            })?;
        let env_pairs: Vec<(String, String)> = request.env.into_iter().collect();
        let child = entry
            .container
            .spawn(ApiContainerSpawnRequest {
                name: request.program.clone(),
                args: request.args,
                env: env_pairs,
                path: request.program,
                cwd: request.cwd,
                sockets: Vec::new(),
                credentials: None,
            })
            .await
            .map_err(map_spawn_error)?;
        Ok(wire_child_streams(
            child,
            request.stdin,
            request.capture_stdout,
            request.capture_stderr,
        ))
    }

    async fn container_remove(&self, handle: &str) -> Result<(), EnvError> {
        self.containers
            .lock()
            .expect("guest containers lock poisoned")
            .remove(handle)
            .map(|_| ())
            .ok_or_else(|| EnvError::NotFound {
                path: handle.to_owned(),
            })
    }

    async fn list_mounts(&self) -> Result<Vec<MountEntryInfo>, EnvError> {
        let mut entries = Vec::new();
        for (desc, mount) in preopens::get_directories() {
            let flags = desc.get_flags().await.unwrap_or(DescriptorFlags::READ);
            let read_only = (flags & DescriptorFlags::WRITE) == DescriptorFlags::empty();
            entries.push(MountEntryInfo {
                path: normalize_vfs_path("/", &mount),
                source: String::from("preopen"),
                kind: String::from("vfs"),
                read_only,
                sharing: String::from("shared"),
            });
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }

    async fn mount(&self, request: MountRequestSpec) -> Result<(), EnvError> {
        let source = match request.source {
            MountSourceSpec::Memory => ApiMountSource::Memory,
            MountSourceSpec::BootImage => ApiMountSource::BootImage,
            MountSourceSpec::HostShare => ApiMountSource::HostShare,
            MountSourceSpec::Disk(serial) => ApiMountSource::Disk(serial),
            MountSourceSpec::Btrfs(serial) => ApiMountSource::Btrfs(serial),
        };
        let sharing = match request.sharing {
            MountSharingSpec::Private => ApiMountSharing::Private,
            MountSharingSpec::Shared => ApiMountSharing::Shared,
        };
        mounts::mount(ApiMountRequest {
            source,
            path: request.path,
            read_only: request.read_only,
            sharing,
            compress: request.compress,
            commit: request.commit,
            max_inline: request.max_inline,
        })
        .await
        .map_err(map_mount_error)
    }

    async fn umount(&self, path: &str) -> Result<(), EnvError> {
        mounts::unmount(path).await.map_err(map_mount_error)
    }

    async fn btrfs_subvolume_create(&self, path: &str) -> Result<BtrfsSubvolumeInfo, EnvError> {
        btrfs::create_subvolume(path)
            .await
            .map(convert_subvol_info)
            .map_err(map_btrfs_error)
    }

    async fn btrfs_subvolume_delete(&self, path: &str) -> Result<(), EnvError> {
        btrfs::delete_subvolume(path).await.map_err(map_btrfs_error)
    }

    async fn btrfs_subvolume_snapshot(
        &self,
        source: &str,
        destination: &str,
        read_only: bool,
    ) -> Result<BtrfsSubvolumeInfo, EnvError> {
        btrfs::snapshot_subvolume(source, destination, read_only)
            .await
            .map(convert_subvol_info)
            .map_err(map_btrfs_error)
    }

    async fn btrfs_subvolume_list(
        &self,
        mount_point: &str,
    ) -> Result<Vec<BtrfsSubvolumeInfo>, EnvError> {
        btrfs::list_subvolumes(mount_point)
            .await
            .map(|list| list.into_iter().map(convert_subvol_info).collect())
            .map_err(map_btrfs_error)
    }

    async fn btrfs_subvolume_info(&self, path: &str) -> Result<BtrfsSubvolumeInfo, EnvError> {
        btrfs::subvolume_info(path)
            .await
            .map(convert_subvol_info)
            .map_err(map_btrfs_error)
    }

    async fn btrfs_subvolume_set_ro(&self, path: &str, read_only: bool) -> Result<(), EnvError> {
        btrfs::set_subvolume_read_only(path, read_only)
            .await
            .map_err(map_btrfs_error)
    }

    async fn btrfs_subvolume_send(
        &self,
        subvolume: &str,
        parent: Option<&str>,
        clone_sources: &[String],
    ) -> Result<Vec<u8>, EnvError> {
        btrfs::send_subvolume(
            subvolume,
            parent.map(ToOwned::to_owned),
            clone_sources.to_vec(),
        )
        .await
        .map_err(map_btrfs_error)
    }

    async fn btrfs_subvolume_receive(
        &self,
        destination: &str,
        payload: Vec<u8>,
    ) -> Result<BtrfsSubvolumeInfo, EnvError> {
        btrfs::receive_subvolume(destination, payload)
            .await
            .map(convert_subvol_info)
            .map_err(map_btrfs_error)
    }

    async fn vm_run(&self, request: VmRunRequest) -> Result<VmInfo, EnvError> {
        let kernel = request
            .kernel
            .clone()
            .ok_or_else(|| EnvError::InvalidArgument {
                detail: String::from("vm run requires `--kernel <path>`"),
            })?;
        let seq = self.next_id.fetch_add(1, Ordering::Relaxed);
        let vm_id = format!("vm-{seq}");
        let name = request.name.clone().unwrap_or_else(|| vm_id.clone());

        let mut builder = MicroVm::builder()
            .cpus(request.cpus)
            .memory_mib(request.memory_mib)
            .map_err(|err| EnvError::InvalidArgument {
                detail: err.to_string(),
            })?
            .kernel(kernel.clone());
        if let Some(initramfs) = &request.initramfs {
            builder = builder.initramfs(initramfs.clone());
        }
        if let Some(disk) = &request.disk {
            builder = builder.disk(disk.clone());
        }

        let oci_overlay = if let Some(ref oci_ref) = request.oci_ref {
            let pulled = self.ensure_oci_image(oci_ref, None).await?;
            let overlay_path = self.oci_store_root.join("vm-overlays").join(&vm_id);
            let mut rootfs = OciVmRootfs::prepare(&pulled, overlay_path, &BtrfsSubvolumeBackend)
                .await
                .map_err(map_oci_error)?;
            for share in &request.shares {
                rootfs = rootfs
                    .with_host_share(&share.tag, &share.host_path, share.read_only)
                    .map_err(map_oci_error)?;
            }
            if let Some(cmdline) = &request.cmdline {
                rootfs = rootfs.with_cmdline(cmdline.clone());
            }
            let rootfs_str = rootfs.rootfs_path_str().map_err(map_oci_error)?;
            builder = builder.rootfs_dir(rootfs_str).map_err(|e| EnvError::Io {
                detail: e.to_string(),
            })?;
            for share in rootfs.host_shares() {
                builder = builder
                    .share_dir(&share.tag, &share.host_path)
                    .map_err(|e| EnvError::Io {
                        detail: e.to_string(),
                    })?;
            }
            builder = builder.cmdline(rootfs.cmdline());
            Some(rootfs)
        } else {
            if let Some(rootfs_dir) = &request.rootfs_dir {
                builder = builder.rootfs_dir(rootfs_dir.clone()).map_err(|e| {
                    EnvError::InvalidArgument {
                        detail: e.to_string(),
                    }
                })?;
            }
            for share in &request.shares {
                builder = builder
                    .share_dir(&share.tag, &share.host_path)
                    .map_err(|e| EnvError::InvalidArgument {
                        detail: e.to_string(),
                    })?;
            }
            if let Some(cmdline) = &request.cmdline {
                builder = builder.cmdline(cmdline.clone());
            }
            None
        };

        let vm = builder.build_vm().map_err(|e| EnvError::Io {
            detail: e.to_string(),
        })?;

        let running_info = VmInfo {
            id: vm_id.clone(),
            name: name.clone(),
            state: String::from("running"),
            cpus: request.cpus,
            memory_mib: request.memory_mib,
            oci_ref: request.oci_ref.clone(),
            kernel: Some(kernel.clone()),
            exit_reason: None,
        };
        self.vms
            .lock()
            .expect("guest vms lock poisoned")
            .push(running_info.clone());

        if request.detach {
            let vms_ref = Arc::clone(&self.vms);
            let id_copy = vm_id.clone();
            task::spawn(async move {
                let outcome = vm.run().await;
                if let Some(overlay) = oci_overlay {
                    let _ = overlay.cleanup(&BtrfsSubvolumeBackend).await;
                }
                let (state, reason) = match outcome {
                    Ok(reason) => (String::from("stopped"), format_vm_exit_reason(&reason)),
                    Err(err) => (String::from("failed"), err.to_string()),
                };
                if let Some(slot) = vms_ref
                    .lock()
                    .expect("guest vms lock poisoned")
                    .iter_mut()
                    .find(|entry| entry.id == id_copy)
                {
                    slot.state = state;
                    slot.exit_reason = Some(reason);
                }
            });
            return Ok(running_info);
        }

        let run_res = run_local(async move {
            let outcome = vm.run().await;
            if let Some(overlay) = oci_overlay {
                let _ = overlay.cleanup(&BtrfsSubvolumeBackend).await;
            }
            outcome.map_err(|err| EnvError::Io {
                detail: err.to_string(),
            })
        })
        .await;
        let exit_reason = run_res.inspect_err(|err| {
            if let Some(slot) = self
                .vms
                .lock()
                .expect("guest vms lock poisoned")
                .iter_mut()
                .find(|entry| entry.id == vm_id)
            {
                slot.state = String::from("failed");
                slot.exit_reason = Some(err.to_string());
            }
        })?;
        let reason_str = format_vm_exit_reason(&exit_reason);
        let mut final_info = running_info;
        final_info.state = String::from("stopped");
        final_info.exit_reason = Some(reason_str.clone());
        if let Some(slot) = self
            .vms
            .lock()
            .expect("guest vms lock poisoned")
            .iter_mut()
            .find(|entry| entry.id == vm_id)
        {
            slot.state = String::from("stopped");
            slot.exit_reason = Some(reason_str);
        }
        Ok(final_info)
    }

    async fn vm_list(&self) -> Result<Vec<VmInfo>, EnvError> {
        let mut out = self.vms.lock().expect("guest vms lock poisoned").clone();
        for inst in instances::snapshot() {
            if inst.name == "vmm" || inst.name.ends_with("/vmm") {
                let id = format!("instance-{}", inst.id);
                if !out.iter().any(|vm| vm.id == id) {
                    out.push(VmInfo {
                        id,
                        name: inst.name,
                        state: String::from("running"),
                        cpus: 0,
                        memory_mib: inst.memory_bytes / (1024 * 1024),
                        oci_ref: None,
                        kernel: None,
                        exit_reason: None,
                    });
                }
            }
        }
        Ok(out)
    }
}

impl GuestHeliosEnv {
    async fn resolve_default_linux_image_for_exec(&self) -> Option<DefaultLinuxImage> {
        match self.ensure_default_linux_image(true).await {
            Ok(img) => img,
            Err(err) => {
                tracing::debug!(error = %err, "lazy default Linux image lookup skipped");
                None
            }
        }
    }

    fn translate_non_fs_grants(&self, specs: &[GrantSpec]) -> Result<NonFsGrants, EnvError> {
        let translated = self.translate_explicit_grants(specs)?;
        let mut non_fs = NonFsGrants::new();
        for grant in translated {
            match capability_grant_to_non_fs(grant) {
                Some(nfg) => non_fs = non_fs.grant(nfg),
                None => {
                    return Err(EnvError::InvalidArgument {
                        detail: String::from(
                            "directory grants are not permitted on containers; use `--mount`",
                        ),
                    });
                }
            }
        }
        Ok(non_fs)
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

fn wire_child_streams(
    child: Child,
    stdin: Option<helios_nu::AsyncByteReceiver>,
    capture_stdout: bool,
    capture_stderr: bool,
) -> ExternalProcess {
    if let Some(stdin_rx) = stdin {
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

    let (stdout_rx, out_inherited_done) = if capture_stdout {
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

    let (stderr_rx, err_inherited_done) = if capture_stderr {
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

    ExternalProcess {
        stdout: stdout_rx,
        stderr: stderr_rx,
        exit_code: code_rx,
    }
}

async fn lstat_path(path: &str) -> Result<FileMetadata, EnvError> {
    let normalized = normalize_vfs_path("/", path);
    let (base, rel) = resolve_preopen(&normalized)?;
    let stat = if rel.is_empty() {
        base.stat()
            .await
            .map_err(|code| map_fs_error(&normalized, code))?
    } else {
        base.stat_at(PathFlags::empty(), rel)
            .await
            .map_err(|code| map_fs_error(&normalized, code))?
    };
    Ok(stat_to_metadata(&normalized, &stat, None))
}

fn join_under_root(root: &str, rel_or_abs: &str) -> String {
    let root = normalize_vfs_path("/", root);
    let sub = normalize_vfs_path("/", rel_or_abs);
    let trimmed = sub.trim_start_matches('/');
    if trimmed.is_empty() {
        root
    } else if root == "/" {
        format!("/{trimmed}")
    } else {
        format!("{root}/{trimmed}")
    }
}

fn collect_linux_search_dirs(path_env: &[String], image_env: &[(String, String)]) -> Vec<String> {
    let mut dirs = Vec::new();
    let mut push_unique = |dir: &str| {
        let norm = normalize_vfs_path("/", dir);
        if !dirs.contains(&norm) {
            dirs.push(norm);
        }
    };
    for dir in path_env {
        if !dir.is_empty() {
            push_unique(dir);
        }
    }
    for (k, v) in image_env {
        if k == "PATH" {
            for segment in v.split(':').filter(|s| !s.is_empty()) {
                push_unique(segment);
            }
        }
    }
    for dir in DEFAULT_LINUX_SEARCH_DIRS {
        push_unique(dir);
    }
    dirs
}

fn default_image_from_pref(pref: &UserDefaultImage) -> DefaultLinuxImage {
    DefaultLinuxImage {
        root_path: pref.rootfs_path.clone(),
        env: pref.env.clone(),
        credentials: Some(ContainerCredentials {
            uid: pref.credentials.uid,
            gid: pref.credentials.gid,
            supplementary_groups: pref.credentials.supplementary_groups.clone(),
        }),
    }
}

fn pulled_to_summary(img: &PulledImage) -> OciImageSummary {
    OciImageSummary {
        reference: img.reference.canonical(),
        digest: img.manifest_digest.as_str(),
        arch: img.arch.to_string(),
        layers: img.layer_chain_ids.len(),
        rootfs_path: img.rootfs_path.to_string_lossy().into_owned(),
        btrfs_backed: img.btrfs_backed,
    }
}

fn parse_fs_rights(mode: &str) -> Result<Vec<FilesystemRight>, EnvError> {
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

fn capability_grant_to_non_fs(grant: CapabilityGrant) -> Option<NonFsGrant> {
    match grant {
        CapabilityGrant::Directory(_) => None,
        CapabilityGrant::Network(g) => Some(NonFsGrant::Network(g)),
        CapabilityGrant::Clock(g) => Some(NonFsGrant::Clock(g)),
        CapabilityGrant::Terminal(g) => Some(NonFsGrant::Terminal(g)),
        CapabilityGrant::Process(g) => Some(NonFsGrant::Process(g)),
        CapabilityGrant::Link(g) => Some(NonFsGrant::Link(g)),
        CapabilityGrant::Mount(g) => Some(NonFsGrant::Mount(g)),
        CapabilityGrant::Device(g) => Some(NonFsGrant::Device(g)),
        CapabilityGrant::Diagnostics(g) => Some(NonFsGrant::Diagnostics(g)),
        CapabilityGrant::InstanceControl(s) => Some(NonFsGrant::InstanceControl(s)),
        CapabilityGrant::Settings(g) => Some(NonFsGrant::Settings(g)),
        CapabilityGrant::Machine(g) => Some(NonFsGrant::Machine(g)),
        CapabilityGrant::Ipc(g) => Some(NonFsGrant::Ipc(g)),
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
            bytes[15]
        )
    } else {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

fn convert_subvol_info(info: ApiSubvolumeInfo) -> BtrfsSubvolumeInfo {
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

/// Spawn a `!Send` guest future on the single-threaded WASI Preview 3 executor
/// and return a `Send` future that awaits its result across a bounded channel.
fn run_local<T, F>(fut: F) -> impl Future<Output = Result<T, EnvError>> + Send
where
    T: Send + 'static,
    F: Future<Output = Result<T, EnvError>> + 'static,
{
    let (tx, rx) = async_channel::bounded(1);
    task::spawn(async move {
        let _ = tx.send(fut.await).await;
    });
    async move {
        rx.recv().await.map_err(|_| EnvError::Io {
            detail: String::from("guest local task exited before delivering a result"),
        })?
    }
}

fn format_vm_exit_reason(reason: &ExitReason) -> String {
    match reason {
        ExitReason::GuestShutdown => String::from("guest-shutdown"),
        ExitReason::VmShutdown => String::from("vm-shutdown"),
    }
}

fn map_oci_error(err: helios_api::oci::OciError) -> EnvError {
    EnvError::Io {
        detail: err.to_string(),
    }
}

fn map_rpc_transport_error(err: helios_wit_rpc::RpcError) -> EnvError {
    EnvError::Io {
        detail: format!("component-control RPC error: {err}"),
    }
}

fn map_control_error(err: ControlError) -> EnvError {
    match err.kind {
        ControlErrorKind::PermissionDenied => EnvError::PermissionDenied { detail: err.detail },
        ControlErrorKind::NotFound => EnvError::NotFound { path: err.detail },
        ControlErrorKind::AlreadyExists => EnvError::AlreadyExists { path: err.detail },
        ControlErrorKind::InvalidArgument => EnvError::InvalidArgument { detail: err.detail },
        ControlErrorKind::Unavailable => EnvError::Unsupported { detail: err.detail },
        ControlErrorKind::Internal => EnvError::Io { detail: err.detail },
    }
}

fn map_exec_error(err: ExecError) -> EnvError {
    match err.kind {
        ExecErrorKind::NotFound => EnvError::NotFound { path: err.detail },
        ExecErrorKind::PermissionDenied => EnvError::PermissionDenied { detail: err.detail },
        ExecErrorKind::InvalidPath | ExecErrorKind::InvalidHint => {
            EnvError::InvalidArgument { detail: err.detail }
        }
        _ => EnvError::Process {
            detail: format!("{:?}: {}", err.kind, err.detail),
        },
    }
}

fn map_mount_error(err: MountError) -> EnvError {
    match err.kind {
        MountErrorKind::PermissionDenied => EnvError::PermissionDenied { detail: err.detail },
        MountErrorKind::AlreadyMounted => EnvError::AlreadyExists { path: err.detail },
        MountErrorKind::NotMounted => EnvError::NotFound { path: err.detail },
        MountErrorKind::InvalidPoint
        | MountErrorKind::InvalidPath
        | MountErrorKind::InvalidFilesystem
        | MountErrorKind::InvalidOption => EnvError::InvalidArgument { detail: err.detail },
        MountErrorKind::Unavailable => EnvError::Unsupported { detail: err.detail },
        MountErrorKind::Busy | MountErrorKind::TableFull | MountErrorKind::Io => {
            EnvError::Io { detail: err.detail }
        }
    }
}

fn map_btrfs_error(err: BtrfsError) -> EnvError {
    match err.kind {
        BtrfsErrorKind::PermissionDenied => EnvError::PermissionDenied { detail: err.detail },
        BtrfsErrorKind::NotFound => EnvError::NotFound { path: err.detail },
        BtrfsErrorKind::AlreadyExists => EnvError::AlreadyExists { path: err.detail },
        BtrfsErrorKind::NotDirectory => EnvError::NotADirectory { path: err.detail },
        BtrfsErrorKind::IsDirectory => EnvError::IsADirectory { path: err.detail },
        BtrfsErrorKind::InvalidArgument | BtrfsErrorKind::InvalidStream => {
            EnvError::InvalidArgument { detail: err.detail }
        }
        BtrfsErrorKind::NotBtrfs | BtrfsErrorKind::NotSubvolume => {
            EnvError::Unsupported { detail: err.detail }
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
    use super::{GuestHeliosEnv, HeldCapabilities};
    use helios_api::programs::{CapabilityGrant, DiagnosticsGrant, MachineRight, TerminalRight};
    use helios_nu::{GrantSpec, HeliosEnv};

    #[test]
    fn held_capabilities_append_only_verified_non_directory_grants() {
        let held = HeldCapabilities {
            has_machine_inspect: true,
            has_terminal_stdin: true,
            has_terminal_stdout: false,
        };
        let mut grants = Vec::new();
        held.append_non_directory_grants(&mut grants);
        assert!(grants.iter().any(|g| matches!(
            g,
            CapabilityGrant::Diagnostics(DiagnosticsGrant::InspectRead(_))
        )));
        assert!(grants.iter().any(|g| matches!(
            g,
            CapabilityGrant::Terminal(t) if t.rights == vec![TerminalRight::Input]
        )));
        assert!(
            !grants
                .iter()
                .any(|g| matches!(g, CapabilityGrant::Machine(_)))
        );
    }

    #[test]
    fn translate_explicit_grants_supports_virtualize_and_machine_rights() {
        let env = GuestHeliosEnv {
            cwd: std::sync::Mutex::new(String::from("/")),
            scopes: std::sync::Mutex::new(Vec::new()),
            snapshots: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            profiles: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            oci_store_root: std::path::PathBuf::from("/var/lib/oci"),
            default_image_cleared: std::sync::Mutex::new(false),
            default_image_ref: std::sync::Mutex::new(None),
            component_control: None,
            containers: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            vms: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            held: HeldCapabilities {
                has_machine_inspect: false,
                has_terminal_stdin: false,
                has_terminal_stdout: false,
            },
            next_id: std::sync::atomic::AtomicU64::new(1),
        };
        let translated = env
            .translate_explicit_grants(&[
                GrantSpec {
                    kind: String::from("virtualize"),
                    target: String::new(),
                    mode: None,
                },
                GrantSpec {
                    kind: String::from("machine"),
                    target: String::from("virtualize"),
                    mode: None,
                },
                GrantSpec {
                    kind: String::from("machine"),
                    target: String::from("all"),
                    mode: None,
                },
            ])
            .expect("virtualize and machine grants must translate");
        assert!(matches!(
            &translated[0],
            CapabilityGrant::Machine(m) if m.rights == vec![MachineRight::Virtualize]
        ));
        assert!(matches!(
            &translated[1],
            CapabilityGrant::Machine(m) if m.rights == vec![MachineRight::Virtualize]
        ));
        assert!(matches!(
            &translated[2],
            CapabilityGrant::Machine(m)
                if m.rights
                    == vec![
                        MachineRight::Control,
                        MachineRight::Identity,
                        MachineRight::Virtualize,
                    ]
        ));
        assert!(matches!(env.cwd(), _));
    }

    #[test]
    fn linux_search_path_and_uuid_helpers_behave_consistently() {
        assert_eq!(
            super::join_under_root("/var/lib/oci/layers/abc", "/bin/sh"),
            "/var/lib/oci/layers/abc/bin/sh"
        );
        assert_eq!(super::join_under_root("/", "/usr/bin/env"), "/usr/bin/env");

        let dirs = super::collect_linux_search_dirs(
            &[String::from("/custom/bin"), String::from("/bin")],
            &[(String::from("PATH"), String::from("/opt/bin:/usr/bin:/bin"))],
        );
        assert_eq!(dirs[0], "/custom/bin");
        assert!(dirs.contains(&String::from("/opt/bin")));
        assert!(dirs.contains(&String::from("/usr/bin")));
        assert!(dirs.contains(&String::from("/sbin")));

        let uuid = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
            0x70, 0x80,
        ];
        assert_eq!(
            super::format_uuid_bytes(&uuid),
            "01234567-89ab-cdef-1020-304050607080"
        );
    }
}
