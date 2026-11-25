//! Helios component manager core library.
//!
//! By default (`default = []`), this crate contains **zero** TOML parsing or
//! manifest deserialization code: static component topologies are validated and
//! compiled into native Rust tables on the host by `helios-cli`.
//!
//! Enabling the `manifest` feature exposes the `component.toml` directory-tree
//! parser for host tooling (`helios-cli`). Enabling `dynamic-components` also
//! compiles in bounded runtime dynamic subtree mounting under parent realms
//! that explicitly opt in (`dynamic_mount = true`).

pub mod authority;
#[cfg(feature = "dynamic-components")]
pub mod dynamic;
#[cfg(feature = "manifest")]
pub mod manifest;
pub mod model;
pub mod supervisor;

pub use authority::{
    ValidationError, directory_covered_by, normalize_abs_path, path_is_prefix,
    validate_dynamic_subtree, validate_moniker, validate_topology, verify_monotonic_ceiling,
};
#[cfg(feature = "dynamic-components")]
pub use dynamic::DynamicMountError;
#[cfg(feature = "manifest")]
pub use manifest::{
    COMPONENT_MANIFEST_FILE, ManifestError, load_dynamic_subtree_from_dir,
    load_dynamic_subtree_from_map, load_tree_from_dir, load_tree_from_map, parse_duration_ms,
};
pub use model::{
    AuthorityScopeSpec, CapabilityCeiling, ClockRights, ComponentNode, ComponentStateRecord,
    ComponentStatus, ComponentTopology, ContainerMountSharingSpec, ContainerMountSpec, Criticality,
    DEFAULT_BURST_LIMIT, DEFAULT_BURST_WINDOW_MS, DEFAULT_RESTART_BACKOFF_MAX_MS,
    DEFAULT_RESTART_BACKOFF_MS, DEFAULT_SOCKET_BACKLOG, DEFAULT_STOP_TIMEOUT_MS, DeviceClasses,
    DirectoryGrantSpec, EnvVarSpec, EscalationAction, ExecRunnerSpec, ExposeSpec, FsRights,
    HardwareInventorySnapshot, HardwarePredicates, IpAddrSpec, LifecycleKind, LinkRights,
    MachineRights, MountRights, MountSharingSpec, MountSourceSpec, MountSpec, NameCeiling,
    NetRights, OciRunnerSpec, OomTier, PortCeiling, ProcessRights, ProviderSlot, RestartPolicy,
    RouteSpec, RunnerSpec, SocketActivationSpec, StartupPolicy, TerminalRights, VmRunnerSpec,
    VmShareSpec, WasmRunnerSpec, WasmSharding,
};
pub use supervisor::{
    BoundSocket, ChildProcess, ExitOutcome, FatalEscalation, IpcChannelEnd, ProviderEndpoint,
    ProviderOutcome, RuntimeError, SIGKILL, SIGTERM, SpawnComponentArgs, Supervisor,
    SupervisorError, SupervisorRuntime, TcpSocketListener, VsockSocketListener,
    exponential_backoff_ms,
};
