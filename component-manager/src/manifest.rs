//! Directory-tree `component.toml` manifest parser (`manifest` / `dynamic-components`
//! features only; never compiled into default `component-manager` binaries).

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

use crate::authority::{
    ValidationError, normalize_abs_path, validate_dynamic_subtree, validate_moniker,
    validate_topology,
};
use crate::model::{
    AuthorityScopeSpec, CapabilityCeiling, ClockRights, ComponentNode, ComponentTopology,
    ContainerMountSharingSpec, ContainerMountSpec, Criticality, DEFAULT_BURST_LIMIT,
    DEFAULT_BURST_WINDOW_MS, DEFAULT_RESTART_BACKOFF_MAX_MS, DEFAULT_RESTART_BACKOFF_MS,
    DEFAULT_SOCKET_BACKLOG, DEFAULT_STOP_TIMEOUT_MS, DeviceClasses, DirectoryGrantSpec, EnvVarSpec,
    EscalationAction, ExecRunnerSpec, ExposeSpec, FsRights, HardwarePredicates, IpAddrSpec,
    LifecycleKind, LinkRights, MachineRights, MountRights, MountSharingSpec, MountSourceSpec,
    MountSpec, NameCeiling, NetRights, OciRunnerSpec, OomTier, PortCeiling, ProcessRights,
    ProviderSlot, RestartPolicy, RouteSpec, RunnerSpec, SocketActivationSpec, StartupPolicy,
    TerminalRights, VmRunnerSpec, VmShareSpec, WasmRunnerSpec, WasmSharding,
};

/// File name required inside every component/realm directory.
pub const COMPONENT_MANIFEST_FILE: &str = "component.toml";

/// Why loading or parsing a `component.toml` directory tree failed.
#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("component tree root `{path}` is not a directory")]
    RootNotDirectory { path: String },
    #[error("missing `{COMPONENT_MANIFEST_FILE}` in `{path}`")]
    MissingManifest { path: String },
    #[error("failed to read `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse `{path}`: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("invalid field `{field}` in `{moniker}`: {detail}")]
    InvalidField {
        moniker: String,
        field: &'static str,
        detail: String,
    },
    #[error("non-UTF-8 directory name under `{path}`")]
    NonUtf8Path { path: String },
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawComponentManifest {
    #[serde(default)]
    #[expect(
        dead_code,
        reason = "manifest documentation field accepted by schema and validated by deny_unknown_fields"
    )]
    description: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    runner: Option<RawRunnerKind>,
    #[serde(default)]
    sharding: Option<RawWasmSharding>,
    #[serde(default)]
    provider: Option<RawProviderSlot>,
    #[serde(default)]
    program: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    optional: bool,
    #[serde(default)]
    oci: Option<RawOciConfig>,
    #[serde(default)]
    vm: Option<RawVmConfig>,
    #[serde(default)]
    startup: Option<RawStartupPolicy>,
    #[serde(default)]
    lifecycle: Option<RawLifecycleKind>,
    #[serde(default)]
    requires: Vec<RawHardwarePredicate>,
    #[serde(default)]
    after: Vec<String>,
    #[serde(default)]
    mounts: Vec<RawMount>,
    #[serde(default)]
    restart: Option<RawRestartPolicy>,
    #[serde(default)]
    restart_backoff: Option<String>,
    #[serde(default)]
    restart_backoff_max: Option<String>,
    #[serde(default)]
    burst_limit: Option<u32>,
    #[serde(default)]
    burst_window: Option<String>,
    #[serde(default)]
    stop_timeout: Option<String>,
    #[serde(default)]
    critical: Option<RawCriticality>,
    #[serde(default)]
    escalation: Option<RawEscalationAction>,
    #[serde(default)]
    oom_tier: Option<RawOomTier>,
    #[serde(default)]
    dynamic_mount: bool,
    #[serde(default)]
    capabilities: RawCapabilities,
    #[serde(default)]
    expose: Vec<RawExpose>,
    #[serde(default, rename = "use")]
    uses: Vec<RawUse>,
    #[serde(default)]
    sockets: Vec<RawSocket>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawRunnerKind {
    Realm,
    Wasm,
    Oci,
    Exec,
    Vm,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawWasmSharding {
    Singleton,
    PerProcessor,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawProviderSlot {
    Compiler,
    HttpClient,
    Surface,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawStartupPolicy {
    Lazy,
    Eager,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawLifecycleKind {
    Service,
    Oneshot,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawHardwarePredicate {
    Display,
    Input,
    Gpu,
    Audio,
    Hv,
    Native,
    Vsock,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawRestartPolicy {
    Never,
    OnFailure,
    Always,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawCriticality {
    None,
    Parent,
    System,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawEscalationAction {
    Halt,
    Reboot,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawOomTier {
    User,
    Plugin,
    Protected,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawMountSharing {
    Private,
    Shared,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawContainerMountSharing {
    Private,
    Shared,
    EphemeralOverlay,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMount {
    source: String,
    path: String,
    sharing: RawMountSharing,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    compress: Option<String>,
    #[serde(default)]
    commit: Option<u32>,
    #[serde(default)]
    max_inline: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOciConfig {
    #[serde(default)]
    image: Option<String>,
    #[serde(default)]
    rootfs: Option<String>,
    #[serde(default)]
    store: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    uid: u32,
    #[serde(default)]
    gid: u32,
    #[serde(default)]
    entrypoint: Vec<String>,
    #[serde(default)]
    cmd: Vec<String>,
    #[serde(default)]
    mounts: Vec<RawContainerMount>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawContainerMount {
    source: String,
    target: String,
    #[serde(default = "default_container_mount_sharing")]
    sharing: RawContainerMountSharing,
    rights: Vec<RawFsRight>,
}

fn default_container_mount_sharing() -> RawContainerMountSharing {
    RawContainerMountSharing::Shared
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVmConfig {
    kernel: String,
    #[serde(default)]
    initramfs: Option<String>,
    #[serde(default)]
    disk: Option<String>,
    #[serde(default = "default_vm_memory_mib")]
    memory_mib: u64,
    #[serde(default = "default_vm_cpus")]
    cpus: u32,
    #[serde(default)]
    cmdline: Option<String>,
    #[serde(default)]
    rootfs_dir: Option<String>,
    #[serde(default)]
    share_dirs: Vec<String>,
}

const fn default_vm_memory_mib() -> u64 {
    128
}

const fn default_vm_cpus() -> u32 {
    1
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCapabilities {
    #[serde(default)]
    directories: Vec<RawDirectoryGrant>,
    #[serde(default)]
    network: Vec<RawNetRight>,
    #[serde(default)]
    tcp_ports: Vec<u16>,
    #[serde(default)]
    allow_all_tcp_ports: bool,
    #[serde(default)]
    vsock_ports: Vec<u32>,
    #[serde(default)]
    allow_all_vsock_ports: bool,
    #[serde(default)]
    clock: Vec<RawClockRight>,
    #[serde(default)]
    terminal: Vec<RawTerminalRight>,
    #[serde(default)]
    process: Vec<RawProcessRight>,
    #[serde(default)]
    link: Vec<RawLinkRight>,
    #[serde(default)]
    mount: Vec<RawMountRight>,
    #[serde(default)]
    devices: Vec<RawDeviceClass>,
    #[serde(default)]
    named_devices: Vec<String>,
    #[serde(default)]
    allow_all_named_devices: bool,
    #[serde(default)]
    inspect_read: Option<RawScope>,
    #[serde(default)]
    trace_read: Option<RawScope>,
    #[serde(default)]
    profile_read: Option<RawScope>,
    #[serde(default)]
    diagnostics_control: bool,
    #[serde(default)]
    instance_control: Option<RawScope>,
    #[serde(default)]
    settings_write: bool,
    #[serde(default)]
    machine: Vec<RawMachineRight>,
    #[serde(default)]
    wit_interfaces: Vec<String>,
    #[serde(default)]
    allow_all_wit_interfaces: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDirectoryGrant {
    source: String,
    #[serde(default)]
    guest: Option<String>,
    rights: Vec<RawFsRight>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawFsRight {
    Read,
    Write,
    MutateDirectory,
    Execute,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawNetRight {
    Tcp,
    Udp,
    Dns,
    PrivilegedBind,
    Multicast,
    Admin,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawClockRight {
    SetWallClock,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawTerminalRight {
    Input,
    Output,
    Control,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawProcessRight {
    Spawn,
    Exec,
    Fork,
    Join,
    Signal,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawLinkRight {
    Source,
    TargetDirectory,
    SymlinkCreate,
    SymlinkRead,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawMountRight {
    Mount,
    Unmount,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawDeviceClass {
    Display,
    Input,
    Gpu,
    Audio,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawMachineRight {
    Control,
    Identity,
    Virtualize,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawScope {
    None,
    Own,
    Subtree,
    Machine,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExpose {
    interface: String,
    channel: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUse {
    interface: String,
    from: String,
    channel: String,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawSocketKind {
    Tcp,
    Vsock,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSocket {
    kind: RawSocketKind,
    #[serde(default)]
    address: Option<String>,
    port: u32,
    #[serde(default)]
    backlog: Option<u32>,
}

/// Parses a human-readable duration string (`"250ms"`, `"5s"`, `"1m"`, `"1h"`) into milliseconds.
pub fn parse_duration_ms(raw: &str) -> Result<u64, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("duration must not be empty".to_owned());
    }
    let (num_str, factor) = if let Some(n) = trimmed.strip_suffix("ms") {
        (n, 1_u64)
    } else if let Some(n) = trimmed.strip_suffix('s') {
        (n, 1_000_u64)
    } else if let Some(n) = trimmed.strip_suffix('m') {
        (n, 60_000_u64)
    } else if let Some(n) = trimmed.strip_suffix('h') {
        (n, 3_600_000_u64)
    } else {
        return Err(format!(
            "unsupported duration `{raw}` (expected `<n>ms`, `<n>s`, `<n>m`, or `<n>h`)"
        ));
    };
    let count: u64 = num_str
        .parse()
        .map_err(|_| format!("invalid numeric value in duration `{raw}`"))?;
    count
        .checked_mul(factor)
        .ok_or_else(|| format!("duration `{raw}` overflows u64 milliseconds"))
}

/// Loads, parses, and statically validates a complete component directory tree rooted at `root`.
///
/// The root directory maps to moniker `"/"`, and every child directory containing
/// `component.toml` maps to its normalized slash-separated path (e.g., `/plugins/http-client`).
pub fn load_tree_from_dir(root: &Path) -> Result<ComponentTopology, ManifestError> {
    if !root.is_dir() {
        return Err(ManifestError::RootNotDirectory {
            path: root.display().to_string(),
        });
    }
    let mut raw_entries = BTreeMap::new();
    collect_manifests(root, "/", &mut raw_entries)?;
    build_and_validate_topology(raw_entries, None)
}

/// Loads, parses, and validates a dynamic subtree rooted at `dir`, mounted under
/// `parent` (whose moniker prefixes all loaded monikers).
pub fn load_dynamic_subtree_from_dir(
    parent: &ComponentNode,
    subtree_name: &str,
    dir: &Path,
) -> Result<ComponentTopology, ManifestError> {
    if !dir.is_dir() {
        return Err(ManifestError::RootNotDirectory {
            path: dir.display().to_string(),
        });
    }
    let mount_prefix = if parent.moniker.as_ref() == "/" {
        format!("/{subtree_name}")
    } else {
        format!("{}/{subtree_name}", parent.moniker)
    };
    validate_moniker(&mount_prefix)?;
    let mut raw_entries = BTreeMap::new();
    collect_manifests(dir, &mount_prefix, &mut raw_entries)?;
    build_and_validate_topology(raw_entries, Some(parent))
}

/// Parses and validates an in-memory map of `moniker -> component.toml` text.
pub fn load_tree_from_map(
    entries: BTreeMap<String, String>,
) -> Result<ComponentTopology, ManifestError> {
    let mut parsed = BTreeMap::new();
    for (moniker, text) in entries {
        validate_moniker(&moniker)?;
        let raw: RawComponentManifest =
            toml::from_str(&text).map_err(|source| ManifestError::Parse {
                path: format!("{moniker}/{COMPONENT_MANIFEST_FILE}"),
                source,
            })?;
        parsed.insert(moniker, raw);
    }
    build_and_validate_topology(parsed, None)
}

/// Parses and validates a dynamic subtree from an in-memory map of `moniker -> component.toml` text.
pub fn load_dynamic_subtree_from_map(
    parent: &ComponentNode,
    entries: BTreeMap<String, String>,
) -> Result<ComponentTopology, ManifestError> {
    let mut parsed = BTreeMap::new();
    for (moniker, text) in entries {
        validate_moniker(&moniker)?;
        let raw: RawComponentManifest =
            toml::from_str(&text).map_err(|source| ManifestError::Parse {
                path: format!("{moniker}/{COMPONENT_MANIFEST_FILE}"),
                source,
            })?;
        parsed.insert(moniker, raw);
    }
    build_and_validate_topology(parsed, Some(parent))
}

fn collect_manifests(
    dir: &Path,
    moniker: &str,
    out: &mut BTreeMap<String, RawComponentManifest>,
) -> Result<(), ManifestError> {
    validate_moniker(moniker)?;
    let manifest_path = dir.join(COMPONENT_MANIFEST_FILE);
    if !manifest_path.is_file() {
        return Err(ManifestError::MissingManifest {
            path: dir.display().to_string(),
        });
    }
    let text = fs::read_to_string(&manifest_path).map_err(|source| ManifestError::Io {
        path: manifest_path.display().to_string(),
        source,
    })?;
    let raw: RawComponentManifest =
        toml::from_str(&text).map_err(|source| ManifestError::Parse {
            path: manifest_path.display().to_string(),
            source,
        })?;
    out.insert(moniker.to_owned(), raw);

    let mut subdirs = Vec::new();
    for entry in fs::read_dir(dir).map_err(|source| ManifestError::Io {
        path: dir.display().to_string(),
        source,
    })? {
        let entry = entry.map_err(|source| ManifestError::Io {
            path: dir.display().to_string(),
            source,
        })?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return Err(ManifestError::NonUtf8Path {
                path: path.display().to_string(),
            });
        };
        if name.starts_with('.') {
            continue;
        }
        subdirs.push((name.to_owned(), path));
    }
    subdirs.sort_by(|a, b| a.0.cmp(&b.0));

    for (name, path) in subdirs {
        let child_moniker = if moniker == "/" {
            format!("/{name}")
        } else {
            format!("{moniker}/{name}")
        };
        collect_manifests(&path, &child_moniker, out)?;
    }
    Ok(())
}

fn parent_moniker(moniker: &str) -> Option<&str> {
    if moniker == "/" {
        return None;
    }
    match moniker.rfind('/') {
        Some(0) => Some("/"),
        Some(pos) => Some(&moniker[..pos]),
        None => None,
    }
}

fn leaf_name(moniker: &str) -> &str {
    if moniker == "/" {
        "root"
    } else {
        moniker.rsplit('/').next().unwrap_or("component")
    }
}

fn build_and_validate_topology(
    raw_entries: BTreeMap<String, RawComponentManifest>,
    dynamic_parent: Option<&ComponentNode>,
) -> Result<ComponentTopology, ManifestError> {
    if raw_entries.is_empty() {
        return Err(ValidationError::EmptyTopology.into());
    }

    // Order monikers breadth-first (by path depth, then lexicographically) so
    // every parent appears strictly before all of its children and index 0 is the root.
    let mut ordered_monikers: Vec<String> = raw_entries.keys().cloned().collect();
    ordered_monikers.sort_by(|a, b| {
        let depth_a = if a == "/" {
            0
        } else {
            a.bytes().filter(|&c| c == b'/').count()
        };
        let depth_b = if b == "/" {
            0
        } else {
            b.bytes().filter(|&c| c == b'/').count()
        };
        depth_a.cmp(&depth_b).then_with(|| a.cmp(b))
    });

    let index_by_moniker: BTreeMap<String, usize> = ordered_monikers
        .iter()
        .enumerate()
        .map(|(idx, m)| (m.clone(), idx))
        .collect();

    // Pre-build parent -> children index lists.
    let mut children_map: Vec<Vec<usize>> = vec![Vec::new(); ordered_monikers.len()];
    let mut parent_indices: Vec<Option<usize>> = vec![None; ordered_monikers.len()];
    for (idx, moniker) in ordered_monikers.iter().enumerate() {
        if idx == 0 {
            if dynamic_parent.is_none() && moniker != "/" {
                return Err(ValidationError::InvalidRootMoniker {
                    found: moniker.clone(),
                }
                .into());
            }
            continue;
        }
        let parent_m = parent_moniker(moniker).ok_or_else(|| ValidationError::MissingParent {
            moniker: moniker.clone(),
            parent_index: usize::MAX,
        })?;
        let Some(&p_idx) = index_by_moniker.get(parent_m) else {
            return Err(ManifestError::MissingManifest {
                path: parent_m.to_owned(),
            });
        };
        parent_indices[idx] = Some(p_idx);
        children_map[p_idx].push(idx);
    }

    // Pre-index exposed interfaces for route resolution.
    let mut exposes_by_node: Vec<Vec<ExposeSpec>> = Vec::with_capacity(ordered_monikers.len());
    for moniker in &ordered_monikers {
        let raw = &raw_entries[moniker];
        let exposes = raw
            .expose
            .iter()
            .map(|e| ExposeSpec {
                interface: Cow::Owned(e.interface.clone()),
                channel: Cow::Owned(e.channel.clone()),
            })
            .collect();
        exposes_by_node.push(exposes);
    }

    let mut nodes = Vec::with_capacity(ordered_monikers.len());
    for (idx, moniker) in ordered_monikers.iter().enumerate() {
        let raw = &raw_entries[moniker];
        let instance_name = raw
            .name
            .clone()
            .unwrap_or_else(|| leaf_name(moniker).to_owned());
        let runner = convert_runner(moniker, raw)?;
        let startup = match raw.startup.unwrap_or(RawStartupPolicy::Lazy) {
            RawStartupPolicy::Lazy => StartupPolicy::Lazy,
            RawStartupPolicy::Eager => StartupPolicy::Eager,
        };
        let lifecycle = match raw.lifecycle.unwrap_or(RawLifecycleKind::Service) {
            RawLifecycleKind::Service => LifecycleKind::Service,
            RawLifecycleKind::Oneshot => LifecycleKind::Oneshot,
        };
        let requires = convert_hardware_predicates(&raw.requires);

        let mut after_indices = Vec::with_capacity(raw.after.len());
        for dep in &raw.after {
            let Some(&dep_idx) = index_by_moniker.get(dep) else {
                return Err(ManifestError::InvalidField {
                    moniker: moniker.clone(),
                    field: "after",
                    detail: format!("unknown dependency moniker `{dep}`"),
                });
            };
            after_indices.push(dep_idx);
        }

        let mounts = raw
            .mounts
            .iter()
            .map(|m| convert_mount(moniker, m))
            .collect::<Result<Vec<_>, _>>()?;

        let restart = match raw.restart.unwrap_or(RawRestartPolicy::Never) {
            RawRestartPolicy::Never => RestartPolicy::Never,
            RawRestartPolicy::OnFailure => RestartPolicy::OnFailure,
            RawRestartPolicy::Always => RestartPolicy::Always,
        };
        let restart_backoff_ms = match &raw.restart_backoff {
            Some(s) => parse_duration_ms(s).map_err(|detail| ManifestError::InvalidField {
                moniker: moniker.clone(),
                field: "restart_backoff",
                detail,
            })?,
            None => DEFAULT_RESTART_BACKOFF_MS,
        };
        let restart_backoff_max_ms = match &raw.restart_backoff_max {
            Some(s) => parse_duration_ms(s).map_err(|detail| ManifestError::InvalidField {
                moniker: moniker.clone(),
                field: "restart_backoff_max",
                detail,
            })?,
            None => DEFAULT_RESTART_BACKOFF_MAX_MS,
        };
        let burst_limit = raw.burst_limit.unwrap_or(DEFAULT_BURST_LIMIT);
        let burst_window_ms = match &raw.burst_window {
            Some(s) => parse_duration_ms(s).map_err(|detail| ManifestError::InvalidField {
                moniker: moniker.clone(),
                field: "burst_window",
                detail,
            })?,
            None => DEFAULT_BURST_WINDOW_MS,
        };
        let stop_timeout_ms = match &raw.stop_timeout {
            Some(s) => parse_duration_ms(s).map_err(|detail| ManifestError::InvalidField {
                moniker: moniker.clone(),
                field: "stop_timeout",
                detail,
            })?,
            None => DEFAULT_STOP_TIMEOUT_MS,
        };
        let critical = match raw.critical.unwrap_or(RawCriticality::None) {
            RawCriticality::None => Criticality::None,
            RawCriticality::Parent => Criticality::Parent,
            RawCriticality::System => Criticality::System,
        };
        let escalation = match raw.escalation.unwrap_or(RawEscalationAction::Halt) {
            RawEscalationAction::Halt => EscalationAction::Halt,
            RawEscalationAction::Reboot => EscalationAction::Reboot,
        };
        let oom_tier = match raw.oom_tier.unwrap_or(RawOomTier::User) {
            RawOomTier::User => OomTier::User,
            RawOomTier::Plugin => OomTier::Plugin,
            RawOomTier::Protected => OomTier::Protected,
        };

        let capabilities = convert_capabilities(moniker, &raw.capabilities)?;
        let sockets = raw
            .sockets
            .iter()
            .map(|s| convert_socket(moniker, s))
            .collect::<Result<Vec<_>, _>>()?;

        let mut routes = Vec::with_capacity(raw.uses.len());
        for u in &raw.uses {
            let Some(&provider_index) = index_by_moniker.get(&u.from) else {
                return Err(ValidationError::UnknownRouteTarget {
                    consumer: moniker.clone(),
                    interface: u.interface.clone(),
                    from: u.from.clone(),
                }
                .into());
            };
            let Some(exp) = exposes_by_node[provider_index]
                .iter()
                .find(|e| e.interface.as_ref() == u.interface.as_str())
            else {
                return Err(ValidationError::UnexposedInterface {
                    consumer: moniker.clone(),
                    interface: u.interface.clone(),
                    from: u.from.clone(),
                }
                .into());
            };
            routes.push(RouteSpec {
                interface: Cow::Owned(u.interface.clone()),
                provider_index,
                provider_moniker: Cow::Owned(u.from.clone()),
                provider_channel: exp.channel.clone(),
                consumer_channel: Cow::Owned(u.channel.clone()),
            });
        }

        nodes.push(ComponentNode {
            moniker: Cow::Owned(moniker.clone()),
            instance_name: Cow::Owned(instance_name),
            parent_index: parent_indices[idx],
            children_indices: Cow::Owned(children_map[idx].clone()),
            runner,
            startup,
            lifecycle,
            requires,
            after: Cow::Owned(after_indices),
            mounts: Cow::Owned(mounts),
            restart,
            restart_backoff_ms,
            restart_backoff_max_ms,
            burst_limit,
            burst_window_ms,
            stop_timeout_ms,
            critical,
            escalation,
            oom_tier,
            dynamic_mount: raw.dynamic_mount,
            capabilities,
            exposes: Cow::Owned(exposes_by_node[idx].clone()),
            routes: Cow::Owned(routes),
            sockets: Cow::Owned(sockets),
        });
    }

    let topology = ComponentTopology {
        nodes: Cow::Owned(nodes),
    };
    if let Some(parent) = dynamic_parent {
        validate_dynamic_subtree(parent, &topology)?;
    } else {
        validate_topology(&topology)?;
    }
    Ok(topology)
}

fn convert_runner(moniker: &str, raw: &RawComponentManifest) -> Result<RunnerSpec, ManifestError> {
    let kind = raw.runner.unwrap_or(RawRunnerKind::Realm);
    let env: Vec<EnvVarSpec> = raw
        .env
        .iter()
        .map(|(k, v)| EnvVarSpec {
            key: Cow::Owned(k.clone()),
            value: Cow::Owned(v.clone()),
        })
        .collect();
    let args: Vec<Cow<'static, str>> = raw.args.iter().cloned().map(Cow::Owned).collect();

    match kind {
        RawRunnerKind::Realm => {
            if raw.provider.is_some() || raw.oci.is_some() || raw.vm.is_some() {
                return Err(ManifestError::InvalidField {
                    moniker: moniker.to_owned(),
                    field: "runner",
                    detail: "realm cannot specify `provider`, `[oci]`, or `[vm]`".to_owned(),
                });
            }
            Ok(RunnerSpec::Realm)
        }
        RawRunnerKind::Wasm => {
            if raw.oci.is_some() || raw.vm.is_some() {
                return Err(ManifestError::InvalidField {
                    moniker: moniker.to_owned(),
                    field: "runner",
                    detail: "wasm runner cannot specify `[oci]` or `[vm]`".to_owned(),
                });
            }
            let program = raw
                .program
                .clone()
                .ok_or_else(|| ManifestError::InvalidField {
                    moniker: moniker.to_owned(),
                    field: "program",
                    detail: "wasm runner requires `program`".to_owned(),
                })?;
            let sharding = match raw.sharding.unwrap_or(RawWasmSharding::Singleton) {
                RawWasmSharding::Singleton => WasmSharding::Singleton,
                RawWasmSharding::PerProcessor => WasmSharding::PerProcessor,
            };
            let provider = raw.provider.map(|p| match p {
                RawProviderSlot::Compiler => ProviderSlot::Compiler,
                RawProviderSlot::HttpClient => ProviderSlot::HttpClient,
                RawProviderSlot::Surface => ProviderSlot::Surface,
            });
            Ok(RunnerSpec::Wasm(WasmRunnerSpec {
                program: Cow::Owned(program),
                sharding,
                provider,
                args: Cow::Owned(args),
                env: Cow::Owned(env),
                cwd: raw.cwd.clone().map(Cow::Owned),
                optional: raw.optional,
            }))
        }
        RawRunnerKind::Oci => {
            if raw.provider.is_some() || raw.vm.is_some() {
                return Err(ManifestError::InvalidField {
                    moniker: moniker.to_owned(),
                    field: "runner",
                    detail: "oci runner cannot specify `provider` or `[vm]`".to_owned(),
                });
            }
            let oci = raw
                .oci
                .as_ref()
                .ok_or_else(|| ManifestError::InvalidField {
                    moniker: moniker.to_owned(),
                    field: "oci",
                    detail: "oci runner requires `[oci]` section".to_owned(),
                })?;
            let mounts = oci
                .mounts
                .iter()
                .map(|m| {
                    let source = normalize_abs_path(&m.source).map_err(|reason| {
                        ManifestError::InvalidField {
                            moniker: moniker.to_owned(),
                            field: "oci.mounts.source",
                            detail: format!("`{}`: {reason}", m.source),
                        }
                    })?;
                    let target = normalize_abs_path(&m.target).map_err(|reason| {
                        ManifestError::InvalidField {
                            moniker: moniker.to_owned(),
                            field: "oci.mounts.target",
                            detail: format!("`{}`: {reason}", m.target),
                        }
                    })?;
                    Ok(ContainerMountSpec {
                        source: Cow::Owned(source),
                        target: Cow::Owned(target),
                        sharing: match m.sharing {
                            RawContainerMountSharing::Private => ContainerMountSharingSpec::Private,
                            RawContainerMountSharing::Shared => ContainerMountSharingSpec::Shared,
                            RawContainerMountSharing::EphemeralOverlay => {
                                ContainerMountSharingSpec::EphemeralOverlay
                            }
                        },
                        rights: convert_fs_rights(&m.rights),
                    })
                })
                .collect::<Result<Vec<_>, ManifestError>>()?;
            Ok(RunnerSpec::Oci(OciRunnerSpec {
                image: oci.image.clone().map(Cow::Owned),
                rootfs: oci.rootfs.clone().map(Cow::Owned),
                store: oci.store.clone().map(Cow::Owned),
                hostname: Cow::Owned(
                    oci.hostname
                        .clone()
                        .unwrap_or_else(|| leaf_name(moniker).to_owned()),
                ),
                uid: oci.uid,
                gid: oci.gid,
                entrypoint: Cow::Owned(oci.entrypoint.iter().cloned().map(Cow::Owned).collect()),
                cmd: Cow::Owned(oci.cmd.iter().cloned().map(Cow::Owned).collect()),
                env: Cow::Owned(env),
                cwd: raw.cwd.clone().map(Cow::Owned),
                mounts: Cow::Owned(mounts),
            }))
        }
        RawRunnerKind::Exec => {
            if raw.provider.is_some() || raw.oci.is_some() || raw.vm.is_some() {
                return Err(ManifestError::InvalidField {
                    moniker: moniker.to_owned(),
                    field: "runner",
                    detail: "exec runner cannot specify `provider`, `[oci]`, or `[vm]`".to_owned(),
                });
            }
            let program = raw
                .program
                .clone()
                .ok_or_else(|| ManifestError::InvalidField {
                    moniker: moniker.to_owned(),
                    field: "program",
                    detail: "exec runner requires `program`".to_owned(),
                })?;
            Ok(RunnerSpec::Exec(ExecRunnerSpec {
                program: Cow::Owned(program),
                args: Cow::Owned(args),
                env: Cow::Owned(env),
                cwd: raw.cwd.clone().map(Cow::Owned),
                optional: raw.optional,
            }))
        }
        RawRunnerKind::Vm => {
            if raw.provider.is_some() || raw.oci.is_some() {
                return Err(ManifestError::InvalidField {
                    moniker: moniker.to_owned(),
                    field: "runner",
                    detail: "vm runner cannot specify `provider` or `[oci]`".to_owned(),
                });
            }
            let vm = raw.vm.as_ref().ok_or_else(|| ManifestError::InvalidField {
                moniker: moniker.to_owned(),
                field: "vm",
                detail: "vm runner requires `[vm]` section".to_owned(),
            })?;
            let mut share_dirs = Vec::with_capacity(vm.share_dirs.len());
            for spec in &vm.share_dirs {
                let Some((tag, host_path)) = spec.split_once(':') else {
                    return Err(ManifestError::InvalidField {
                        moniker: moniker.to_owned(),
                        field: "vm.share_dirs",
                        detail: format!("invalid share_dir `{spec}` (expected `<tag>:<path>`)"),
                    });
                };
                if tag.is_empty() || host_path.is_empty() {
                    return Err(ManifestError::InvalidField {
                        moniker: moniker.to_owned(),
                        field: "vm.share_dirs",
                        detail: format!("invalid share_dir `{spec}` (empty tag or path)"),
                    });
                }
                share_dirs.push(VmShareSpec {
                    tag: Cow::Owned(tag.to_owned()),
                    host_path: Cow::Owned(host_path.to_owned()),
                });
            }
            Ok(RunnerSpec::Vm(VmRunnerSpec {
                kernel: Cow::Owned(vm.kernel.clone()),
                initramfs: vm.initramfs.clone().map(Cow::Owned),
                disk: vm.disk.clone().map(Cow::Owned),
                memory_mib: vm.memory_mib,
                cpus: vm.cpus,
                cmdline: vm.cmdline.clone().map(Cow::Owned),
                rootfs_dir: vm.rootfs_dir.clone().map(Cow::Owned),
                share_dirs: Cow::Owned(share_dirs),
            }))
        }
    }
}

fn convert_hardware_predicates(list: &[RawHardwarePredicate]) -> HardwarePredicates {
    let mut pred = HardwarePredicates::NONE;
    for item in list {
        match item {
            RawHardwarePredicate::Display => pred.display = true,
            RawHardwarePredicate::Input => pred.input = true,
            RawHardwarePredicate::Gpu => pred.gpu = true,
            RawHardwarePredicate::Audio => pred.audio = true,
            RawHardwarePredicate::Hv => pred.hv = true,
            RawHardwarePredicate::Native => pred.native = true,
            RawHardwarePredicate::Vsock => pred.vsock = true,
        }
    }
    pred
}

fn convert_mount(moniker: &str, raw: &RawMount) -> Result<MountSpec, ManifestError> {
    let source = match raw.source.as_str() {
        "memory" => MountSourceSpec::Memory,
        "boot-image" => MountSourceSpec::BootImage,
        "host-share" => MountSourceSpec::HostShare,
        other => {
            if let Some(serial) = other.strip_prefix("disk:")
                && !serial.is_empty()
            {
                MountSourceSpec::Disk(Cow::Owned(serial.to_owned()))
            } else if let Some(serial) = other.strip_prefix("btrfs:")
                && !serial.is_empty()
            {
                MountSourceSpec::Btrfs(Cow::Owned(serial.to_owned()))
            } else {
                return Err(ManifestError::InvalidField {
                    moniker: moniker.to_owned(),
                    field: "mounts.source",
                    detail: format!("unknown mount source `{other}`"),
                });
            }
        }
    };
    let path = normalize_abs_path(&raw.path).map_err(|reason| ManifestError::InvalidField {
        moniker: moniker.to_owned(),
        field: "mounts.path",
        detail: format!("`{}`: {reason}", raw.path),
    })?;
    let sharing = match raw.sharing {
        RawMountSharing::Private => MountSharingSpec::Private,
        RawMountSharing::Shared => MountSharingSpec::Shared,
    };
    Ok(MountSpec {
        source,
        path: Cow::Owned(path),
        sharing,
        read_only: raw.read_only,
        compress: raw.compress.clone().map(Cow::Owned),
        commit: raw.commit,
        max_inline: raw.max_inline,
    })
}

fn convert_socket(moniker: &str, raw: &RawSocket) -> Result<SocketActivationSpec, ManifestError> {
    match raw.kind {
        RawSocketKind::Tcp => {
            let port = u16::try_from(raw.port).map_err(|_| ManifestError::InvalidField {
                moniker: moniker.to_owned(),
                field: "sockets.port",
                detail: format!("TCP port {} exceeds u16::MAX", raw.port),
            })?;
            let backlog = match raw.backlog {
                Some(b) => u16::try_from(b).map_err(|_| ManifestError::InvalidField {
                    moniker: moniker.to_owned(),
                    field: "sockets.backlog",
                    detail: format!("TCP backlog {b} exceeds u16::MAX"),
                })?,
                None => DEFAULT_SOCKET_BACKLOG,
            };
            let addr_str = raw.address.as_deref().unwrap_or("0.0.0.0");
            let parsed: IpAddr = addr_str.parse().map_err(|_| ManifestError::InvalidField {
                moniker: moniker.to_owned(),
                field: "sockets.address",
                detail: format!("invalid IP address `{addr_str}`"),
            })?;
            let address = match parsed {
                IpAddr::V4(v4) => IpAddrSpec::V4(v4.octets()),
                IpAddr::V6(v6) => IpAddrSpec::V6(v6.segments()),
            };
            Ok(SocketActivationSpec::Tcp {
                address,
                port,
                backlog,
            })
        }
        RawSocketKind::Vsock => {
            if raw.address.is_some() {
                return Err(ManifestError::InvalidField {
                    moniker: moniker.to_owned(),
                    field: "sockets.address",
                    detail: "vsock socket does not accept `address`".to_owned(),
                });
            }
            Ok(SocketActivationSpec::Vsock {
                port: raw.port,
                backlog: raw.backlog.unwrap_or(u32::from(DEFAULT_SOCKET_BACKLOG)),
            })
        }
    }
}

fn convert_fs_rights(rights: &[RawFsRight]) -> FsRights {
    let mut mask = FsRights::EMPTY;
    for r in rights {
        mask = mask.union(match r {
            RawFsRight::Read => FsRights::READ,
            RawFsRight::Write => FsRights::WRITE,
            RawFsRight::MutateDirectory => FsRights::MUTATE_DIRECTORY,
            RawFsRight::Execute => FsRights::EXECUTE,
        });
    }
    mask
}

fn convert_scope(scope: Option<RawScope>) -> AuthorityScopeSpec {
    match scope.unwrap_or(RawScope::None) {
        RawScope::None => AuthorityScopeSpec::None,
        RawScope::Own => AuthorityScopeSpec::Own,
        RawScope::Subtree => AuthorityScopeSpec::Subtree,
        RawScope::Machine => AuthorityScopeSpec::Machine,
    }
}

fn convert_capabilities(
    moniker: &str,
    raw: &RawCapabilities,
) -> Result<CapabilityCeiling, ManifestError> {
    let mut directories = Vec::with_capacity(raw.directories.len());
    for d in &raw.directories {
        let source =
            normalize_abs_path(&d.source).map_err(|reason| ManifestError::InvalidField {
                moniker: moniker.to_owned(),
                field: "capabilities.directories.source",
                detail: format!("`{}`: {reason}", d.source),
            })?;
        let guest = match &d.guest {
            Some(g) => normalize_abs_path(g).map_err(|reason| ManifestError::InvalidField {
                moniker: moniker.to_owned(),
                field: "capabilities.directories.guest",
                detail: format!("`{g}`: {reason}"),
            })?,
            None => source.clone(),
        };
        directories.push(DirectoryGrantSpec {
            source: Cow::Owned(source),
            guest: Cow::Owned(guest),
            rights: convert_fs_rights(&d.rights),
        });
    }

    let mut network = NetRights::EMPTY;
    for r in &raw.network {
        network = network.union(match r {
            RawNetRight::Tcp => NetRights::TCP,
            RawNetRight::Udp => NetRights::UDP,
            RawNetRight::Dns => NetRights::DNS,
            RawNetRight::PrivilegedBind => NetRights::PRIVILEGED_BIND,
            RawNetRight::Multicast => NetRights::MULTICAST,
            RawNetRight::Admin => NetRights::ADMIN,
        });
    }
    let tcp_ports = if raw.allow_all_tcp_ports {
        PortCeiling::Any
    } else {
        PortCeiling::Set(Cow::Owned(raw.tcp_ports.clone()))
    };
    let vsock_ports = if raw.allow_all_vsock_ports {
        PortCeiling::Any
    } else {
        PortCeiling::Set(Cow::Owned(raw.vsock_ports.clone()))
    };

    let mut clock = ClockRights::EMPTY;
    for r in &raw.clock {
        clock = clock.union(match r {
            RawClockRight::SetWallClock => ClockRights::SET_WALL_CLOCK,
        });
    }
    let mut terminal = TerminalRights::EMPTY;
    for r in &raw.terminal {
        terminal = terminal.union(match r {
            RawTerminalRight::Input => TerminalRights::INPUT,
            RawTerminalRight::Output => TerminalRights::OUTPUT,
            RawTerminalRight::Control => TerminalRights::CONTROL,
        });
    }
    let mut process = ProcessRights::EMPTY;
    for r in &raw.process {
        process = process.union(match r {
            RawProcessRight::Spawn => ProcessRights::SPAWN,
            RawProcessRight::Exec => ProcessRights::EXEC,
            RawProcessRight::Fork => ProcessRights::FORK,
            RawProcessRight::Join => ProcessRights::JOIN,
            RawProcessRight::Signal => ProcessRights::SIGNAL,
        });
    }
    let mut link = LinkRights::EMPTY;
    for r in &raw.link {
        link = link.union(match r {
            RawLinkRight::Source => LinkRights::SOURCE,
            RawLinkRight::TargetDirectory => LinkRights::TARGET_DIRECTORY,
            RawLinkRight::SymlinkCreate => LinkRights::SYMLINK_CREATE,
            RawLinkRight::SymlinkRead => LinkRights::SYMLINK_READ,
        });
    }
    let mut mount = MountRights::EMPTY;
    for r in &raw.mount {
        mount = mount.union(match r {
            RawMountRight::Mount => MountRights::MOUNT,
            RawMountRight::Unmount => MountRights::UNMOUNT,
        });
    }
    let mut devices = DeviceClasses::EMPTY;
    for d in &raw.devices {
        devices = devices.union(match d {
            RawDeviceClass::Display => DeviceClasses::DISPLAY,
            RawDeviceClass::Input => DeviceClasses::INPUT,
            RawDeviceClass::Gpu => DeviceClasses::GPU,
            RawDeviceClass::Audio => DeviceClasses::AUDIO,
        });
    }
    let named_devices = if raw.allow_all_named_devices {
        NameCeiling::Any
    } else {
        NameCeiling::Set(Cow::Owned(
            raw.named_devices.iter().cloned().map(Cow::Owned).collect(),
        ))
    };
    let mut machine = MachineRights::EMPTY;
    for r in &raw.machine {
        machine = machine.union(match r {
            RawMachineRight::Control => MachineRights::CONTROL,
            RawMachineRight::Identity => MachineRights::IDENTITY,
            RawMachineRight::Virtualize => MachineRights::VIRTUALIZE,
        });
    }
    let wit_interfaces = if raw.allow_all_wit_interfaces {
        NameCeiling::Any
    } else {
        NameCeiling::Set(Cow::Owned(
            raw.wit_interfaces.iter().cloned().map(Cow::Owned).collect(),
        ))
    };

    Ok(CapabilityCeiling {
        directories: Cow::Owned(directories),
        network,
        tcp_ports,
        vsock_ports,
        clock,
        terminal,
        process,
        link,
        mount,
        devices,
        named_devices,
        inspect_read: convert_scope(raw.inspect_read),
        trace_read: convert_scope(raw.trace_read),
        profile_read: convert_scope(raw.profile_read),
        diagnostics_control: raw.diagnostics_control,
        instance_control: convert_scope(raw.instance_control),
        settings_write: raw.settings_write,
        machine,
        wit_interfaces,
    })
}
