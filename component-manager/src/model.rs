//! Static topology model, capability ceiling types, and runtime state records
//! shared between compile-time Rust codegen (`helios-cli`), the zero-TOML
//! runtime supervisor (`component-manager`), and opt-in dynamic subtrees.

use std::borrow::Cow;
use std::fmt;

/// Default initial restart backoff (`250ms`).
pub const DEFAULT_RESTART_BACKOFF_MS: u64 = 250;
/// Default maximum exponential restart backoff (`30s`).
pub const DEFAULT_RESTART_BACKOFF_MAX_MS: u64 = 30_000;
/// Default maximum restart attempts allowed inside [`DEFAULT_BURST_WINDOW_MS`].
pub const DEFAULT_BURST_LIMIT: u32 = 5;
/// Default sliding burst-window duration (`60s`).
pub const DEFAULT_BURST_WINDOW_MS: u64 = 60_000;
/// Default graceful shutdown timeout before forced termination (`5s`).
pub const DEFAULT_STOP_TIMEOUT_MS: u64 = 5_000;
/// Default TCP / vsock listen backlog when not overridden in `component.toml`.
pub const DEFAULT_SOCKET_BACKLOG: u16 = 128;

/// Filesystem rights bitmask matching `helios:system/programs.filesystem-right`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FsRights(u8);

impl FsRights {
    pub const EMPTY: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const MUTATE_DIRECTORY: Self = Self(1 << 2);
    pub const EXECUTE: Self = Self(1 << 3);
    pub const ALL: Self = Self(0b1111);

    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & Self::ALL.0)
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Network rights bitmask matching `helios:system/programs.network-right`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NetRights(u8);

impl NetRights {
    pub const EMPTY: Self = Self(0);
    pub const TCP: Self = Self(1 << 0);
    pub const UDP: Self = Self(1 << 1);
    pub const DNS: Self = Self(1 << 2);
    pub const PRIVILEGED_BIND: Self = Self(1 << 3);
    pub const MULTICAST: Self = Self(1 << 4);
    pub const ADMIN: Self = Self(1 << 5);
    pub const ALL: Self = Self(0b0011_1111);

    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & Self::ALL.0)
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Clock rights bitmask matching `helios:system/programs.clock-right`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ClockRights(u8);

impl ClockRights {
    pub const EMPTY: Self = Self(0);
    pub const SET_WALL_CLOCK: Self = Self(1 << 0);
    pub const ALL: Self = Self(1 << 0);

    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & Self::ALL.0)
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Terminal rights bitmask matching `helios:system/programs.terminal-right`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TerminalRights(u8);

impl TerminalRights {
    pub const EMPTY: Self = Self(0);
    pub const INPUT: Self = Self(1 << 0);
    pub const OUTPUT: Self = Self(1 << 1);
    pub const CONTROL: Self = Self(1 << 2);
    pub const ALL: Self = Self(0b0111);

    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & Self::ALL.0)
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Process rights bitmask matching `helios:system/programs.process-right`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ProcessRights(u8);

impl ProcessRights {
    pub const EMPTY: Self = Self(0);
    pub const SPAWN: Self = Self(1 << 0);
    pub const EXEC: Self = Self(1 << 1);
    pub const FORK: Self = Self(1 << 2);
    pub const JOIN: Self = Self(1 << 3);
    pub const SIGNAL: Self = Self(1 << 4);
    pub const ALL: Self = Self(0b0001_1111);

    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & Self::ALL.0)
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Link rights bitmask matching `helios:system/programs.link-right`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct LinkRights(u8);

impl LinkRights {
    pub const EMPTY: Self = Self(0);
    pub const SOURCE: Self = Self(1 << 0);
    pub const TARGET_DIRECTORY: Self = Self(1 << 1);
    pub const SYMLINK_CREATE: Self = Self(1 << 2);
    pub const SYMLINK_READ: Self = Self(1 << 3);
    pub const ALL: Self = Self(0b1111);

    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & Self::ALL.0)
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Mount rights bitmask matching `helios:system/programs.mount-right`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct MountRights(u8);

impl MountRights {
    pub const EMPTY: Self = Self(0);
    pub const MOUNT: Self = Self(1 << 0);
    pub const UNMOUNT: Self = Self(1 << 1);
    pub const ALL: Self = Self(0b11);

    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & Self::ALL.0)
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Machine-wide device classes matching `helios:system/programs.device-class`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct DeviceClasses(u8);

impl DeviceClasses {
    pub const EMPTY: Self = Self(0);
    pub const DISPLAY: Self = Self(1 << 0);
    pub const INPUT: Self = Self(1 << 1);
    pub const GPU: Self = Self(1 << 2);
    pub const AUDIO: Self = Self(1 << 3);
    pub const ALL: Self = Self(0b1111);

    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & Self::ALL.0)
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Machine-level rights matching `helios:system/programs.machine-right`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct MachineRights(u8);

impl MachineRights {
    pub const EMPTY: Self = Self(0);
    pub const CONTROL: Self = Self(1 << 0);
    pub const IDENTITY: Self = Self(1 << 1);
    pub const VIRTUALIZE: Self = Self(1 << 2);
    pub const ALL: Self = Self(0b0111);

    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & Self::ALL.0)
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Monotonically ordered visibility/control scope (`None < Own < Subtree < Machine`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum AuthorityScopeSpec {
    #[default]
    None = 0,
    Own = 1,
    Subtree = 2,
    Machine = 3,
}

impl AuthorityScopeSpec {
    #[must_use]
    pub const fn admits(self, child: Self) -> bool {
        (child as u8) <= (self as u8)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Own => "own",
            Self::Subtree => "subtree",
            Self::Machine => "machine",
        }
    }
}

/// Monotonically ordered OOM protection tier (`User < Plugin < Protected`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum OomTier {
    #[default]
    User = 0,
    Plugin = 1,
    Protected = 2,
}

impl OomTier {
    #[must_use]
    pub const fn admits(self, child: Self) -> bool {
        (child as u8) <= (self as u8)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Plugin => "plugin",
            Self::Protected => "protected",
        }
    }
}

/// Directory prefix and rights grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryGrantSpec {
    pub source: Cow<'static, str>,
    pub guest: Cow<'static, str>,
    pub rights: FsRights,
}

/// Port ceiling for TCP (`u16`) or vsock (`u32`) listening sockets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortCeiling<T: 'static + Clone> {
    /// Any port is permitted by this realm ceiling.
    Any,
    /// Only ports in this explicit set are permitted.
    Set(Cow<'static, [T]>),
}

impl<T: 'static + Copy + PartialEq> PortCeiling<T> {
    pub const EMPTY: Self = Self::Set(Cow::Borrowed(&[]));

    #[must_use]
    pub fn admits_port(&self, port: T) -> bool {
        match self {
            Self::Any => true,
            Self::Set(allowed) => allowed.contains(&port),
        }
    }

    #[must_use]
    pub fn admits_ceiling(&self, child: &Self) -> bool {
        match (self, child) {
            (Self::Any, _) => true,
            (Self::Set(_), Self::Any) => false,
            (Self::Set(parent), Self::Set(child_ports)) => {
                child_ports.iter().all(|p| parent.contains(p))
            }
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Set(ports) if ports.is_empty())
    }
}

/// String-name ceiling (used for raw named devices and routed WIT interfaces).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameCeiling {
    /// Any name is permitted by this realm ceiling.
    Any,
    /// Only names in this explicit set are permitted.
    Set(Cow<'static, [Cow<'static, str>]>),
}

impl NameCeiling {
    pub const EMPTY: Self = Self::Set(Cow::Borrowed(&[]));

    #[must_use]
    pub fn admits_name(&self, name: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Set(allowed) => allowed.iter().any(|entry| entry.as_ref() == name),
        }
    }

    #[must_use]
    pub fn admits_ceiling(&self, child: &Self) -> bool {
        match (self, child) {
            (Self::Any, _) => true,
            (Self::Set(_), Self::Any) => false,
            (Self::Set(parent), Self::Set(child_names)) => child_names
                .iter()
                .all(|name| parent.iter().any(|p| p.as_ref() == name.as_ref())),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Set(items) if items.is_empty())
    }
}

/// Complete capability ceiling for a realm or component.
///
/// Every dimension is checked monotonically against its parent realm
/// (`Cap(child) <= Cap(parent)`) both statically at CLI build time and at
/// runtime before spawning or mounting a dynamic subtree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityCeiling {
    pub directories: Cow<'static, [DirectoryGrantSpec]>,
    pub network: NetRights,
    pub tcp_ports: PortCeiling<u16>,
    pub vsock_ports: PortCeiling<u32>,
    pub clock: ClockRights,
    pub terminal: TerminalRights,
    pub process: ProcessRights,
    pub link: LinkRights,
    pub mount: MountRights,
    pub devices: DeviceClasses,
    pub named_devices: NameCeiling,
    pub inspect_read: AuthorityScopeSpec,
    pub trace_read: AuthorityScopeSpec,
    pub profile_read: AuthorityScopeSpec,
    pub diagnostics_control: bool,
    pub instance_control: AuthorityScopeSpec,
    pub settings_write: bool,
    pub machine: MachineRights,
    pub wit_interfaces: NameCeiling,
}

impl CapabilityCeiling {
    /// Empty ceiling granting zero capabilities.
    pub const EMPTY: Self = Self {
        directories: Cow::Borrowed(&[]),
        network: NetRights::EMPTY,
        tcp_ports: PortCeiling::EMPTY,
        vsock_ports: PortCeiling::EMPTY,
        clock: ClockRights::EMPTY,
        terminal: TerminalRights::EMPTY,
        process: ProcessRights::EMPTY,
        link: LinkRights::EMPTY,
        mount: MountRights::EMPTY,
        devices: DeviceClasses::EMPTY,
        named_devices: NameCeiling::EMPTY,
        inspect_read: AuthorityScopeSpec::None,
        trace_read: AuthorityScopeSpec::None,
        profile_read: AuthorityScopeSpec::None,
        diagnostics_control: false,
        instance_control: AuthorityScopeSpec::None,
        settings_write: false,
        machine: MachineRights::EMPTY,
        wit_interfaces: NameCeiling::EMPTY,
    };

    /// Returns true if this ceiling grants zero capabilities across every dimension.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.directories.is_empty()
            && self.network.is_empty()
            && self.tcp_ports.is_empty()
            && self.vsock_ports.is_empty()
            && self.clock.is_empty()
            && self.terminal.is_empty()
            && self.process.is_empty()
            && self.link.is_empty()
            && self.mount.is_empty()
            && self.devices.is_empty()
            && self.named_devices.is_empty()
            && self.inspect_read == AuthorityScopeSpec::None
            && self.trace_read == AuthorityScopeSpec::None
            && self.profile_read == AuthorityScopeSpec::None
            && !self.diagnostics_control
            && self.instance_control == AuthorityScopeSpec::None
            && !self.settings_write
            && self.machine.is_empty()
            && self.wit_interfaces.is_empty()
    }
}

/// Sharding mode for `runner = "wasm"` components.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WasmSharding {
    #[default]
    Singleton,
    PerProcessor,
}

impl WasmSharding {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Singleton => "singleton",
            Self::PerProcessor => "per-processor",
        }
    }
}

/// Kernel provider slot managed through `helios:system/root-supervisor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderSlot {
    Compiler,
    HttpClient,
    Surface,
}

impl ProviderSlot {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compiler => "compiler",
            Self::HttpClient => "http-client",
            Self::Surface => "surface",
        }
    }
}

/// Key-value environment variable entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvVarSpec {
    pub key: Cow<'static, str>,
    pub value: Cow<'static, str>,
}

/// Configuration for `runner = "wasm"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmRunnerSpec {
    pub program: Cow<'static, str>,
    pub sharding: WasmSharding,
    pub provider: Option<ProviderSlot>,
    pub args: Cow<'static, [Cow<'static, str>]>,
    pub env: Cow<'static, [EnvVarSpec]>,
    pub cwd: Option<Cow<'static, str>>,
    /// If true, skip launch when `program` is absent from a subset bootfs image.
    pub optional: bool,
}

/// Container mount sharing mode for `runner = "oci"`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ContainerMountSharingSpec {
    Private,
    #[default]
    Shared,
    EphemeralOverlay,
}

/// Pass-through or overlay mount attached to an OCI container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerMountSpec {
    pub source: Cow<'static, str>,
    pub target: Cow<'static, str>,
    pub sharing: ContainerMountSharingSpec,
    pub rights: FsRights,
}

/// Configuration for `runner = "oci"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OciRunnerSpec {
    pub image: Option<Cow<'static, str>>,
    pub rootfs: Option<Cow<'static, str>>,
    pub store: Option<Cow<'static, str>>,
    pub hostname: Cow<'static, str>,
    pub uid: u32,
    pub gid: u32,
    pub entrypoint: Cow<'static, [Cow<'static, str>]>,
    pub cmd: Cow<'static, [Cow<'static, str>]>,
    pub env: Cow<'static, [EnvVarSpec]>,
    pub cwd: Option<Cow<'static, str>>,
    pub mounts: Cow<'static, [ContainerMountSpec]>,
}

/// Configuration for `runner = "exec"` (direct Wasm or Linux ELF binary).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecRunnerSpec {
    pub program: Cow<'static, str>,
    pub args: Cow<'static, [Cow<'static, str>]>,
    pub env: Cow<'static, [EnvVarSpec]>,
    pub cwd: Option<Cow<'static, str>>,
    pub optional: bool,
}

/// Shared virtio-fs directory exposed to a `runner = "vm"` MicroVm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmShareSpec {
    pub tag: Cow<'static, str>,
    pub host_path: Cow<'static, str>,
}

/// Configuration for `runner = "vm"` (`MicroVm`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmRunnerSpec {
    pub kernel: Cow<'static, str>,
    pub initramfs: Option<Cow<'static, str>>,
    pub disk: Option<Cow<'static, str>>,
    pub memory_mib: u64,
    pub cpus: u32,
    pub cmdline: Option<Cow<'static, str>>,
    pub rootfs_dir: Option<Cow<'static, str>>,
    pub share_dirs: Cow<'static, [VmShareSpec]>,
}

/// Unified execution runner for a node in the component tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunnerSpec {
    /// Organizing realm defining a capability ceiling and optional mounts for children.
    Realm,
    /// Wasm component (`singleton` or `per-processor`, optional kernel provider slot).
    Wasm(WasmRunnerSpec),
    /// OCI-packaged Linux container with ephemeral overlay `/` and host bind mounts.
    Oci(OciRunnerSpec),
    /// Direct Wasm or Linux ELF binary execution.
    Exec(ExecRunnerSpec),
    /// Isolated hardware virtual machine (`MicroVm`, requires `MachineRights::VIRTUALIZE`).
    Vm(VmRunnerSpec),
}

impl RunnerSpec {
    #[must_use]
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::Realm => "realm",
            Self::Wasm(_) => "wasm",
            Self::Oci(_) => "oci",
            Self::Exec(_) => "exec",
            Self::Vm(_) => "vm",
        }
    }

    #[must_use]
    pub const fn is_realm(&self) -> bool {
        matches!(self, Self::Realm)
    }
}

/// Whether a component activates lazily on first request or eagerly with its parent realm.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StartupPolicy {
    #[default]
    Lazy,
    Eager,
}

impl StartupPolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lazy => "lazy",
            Self::Eager => "eager",
        }
    }
}

/// Long-lived service vs run-to-zero-exit setup unit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LifecycleKind {
    #[default]
    Service,
    Oneshot,
}

impl LifecycleKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Oneshot => "oneshot",
        }
    }
}

/// Restart policy after termination.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RestartPolicy {
    #[default]
    Never,
    OnFailure,
    Always,
}

impl RestartPolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::OnFailure => "on-failure",
            Self::Always => "always",
        }
    }
}

/// Failure blast-radius policy when a component fails unrecoverably.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Criticality {
    #[default]
    None,
    Parent,
    System,
}

impl Criticality {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Parent => "parent",
            Self::System => "system",
        }
    }
}

/// Terminal machine action for `critical = "system"` escalation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EscalationAction {
    #[default]
    Halt,
    Reboot,
}

impl EscalationAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Halt => "halt",
            Self::Reboot => "reboot",
        }
    }
}

/// Hardware-presence predicates guarding eager component activation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HardwarePredicates {
    pub display: bool,
    pub input: bool,
    pub gpu: bool,
    pub audio: bool,
    pub hv: bool,
    pub native: bool,
    pub vsock: bool,
}

impl HardwarePredicates {
    pub const NONE: Self = Self {
        display: false,
        input: false,
        gpu: false,
        audio: false,
        hv: false,
        native: false,
        vsock: false,
    };

    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.display
            && !self.input
            && !self.gpu
            && !self.audio
            && !self.hv
            && !self.native
            && !self.vsock
    }

    #[must_use]
    pub const fn satisfied_by(self, inv: &HardwareInventorySnapshot) -> bool {
        (!self.display || inv.display)
            && (!self.input || inv.input)
            && (!self.gpu || inv.gpu)
            && (!self.audio || inv.audio)
            && (!self.hv || inv.hv)
            && (!self.native || inv.native)
            && (!self.vsock || inv.vsock)
    }
}

/// Snapshot of platform hardware presence returned by `root-supervisor`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HardwareInventorySnapshot {
    pub display: bool,
    pub input: bool,
    pub gpu: bool,
    pub audio: bool,
    pub hv: bool,
    pub native: bool,
    pub vsock: bool,
}

/// Declarative mount source matching `helios:system/mounts.mount-source`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MountSourceSpec {
    Memory,
    BootImage,
    HostShare,
    Disk(Cow<'static, str>),
    Btrfs(Cow<'static, str>),
}

/// Declarative mount sharing mode matching `helios:system/mounts.mount-sharing`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MountSharingSpec {
    Private,
    #[default]
    Shared,
}

/// Declarative volume mount attached before a realm/component starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountSpec {
    pub source: MountSourceSpec,
    pub path: Cow<'static, str>,
    pub sharing: MountSharingSpec,
    pub read_only: bool,
    pub compress: Option<Cow<'static, str>>,
    pub commit: Option<u32>,
    pub max_inline: Option<u64>,
}

/// IPv4 or IPv6 bind address for a pre-bound TCP activation listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IpAddrSpec {
    V4([u8; 4]),
    V6([u16; 8]),
}

impl fmt::Display for IpAddrSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4([a, b, c, d]) => write!(f, "{a}.{b}.{c}.{d}"),
            Self::V6(segs) => write!(
                f,
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], segs[7]
            ),
        }
    }
}

/// Pre-bound listening socket for zero-first-packet-loss lazy activation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SocketActivationSpec {
    Tcp {
        address: IpAddrSpec,
        port: u16,
        backlog: u16,
    },
    Vsock {
        port: u32,
        backlog: u32,
    },
}

/// Exposed WIT/IPC interface on a component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExposeSpec {
    pub interface: Cow<'static, str>,
    pub channel: Cow<'static, str>,
}

/// Resolved static WIT/IPC route from a consumer component to a provider component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteSpec {
    pub interface: Cow<'static, str>,
    pub provider_index: usize,
    pub provider_moniker: Cow<'static, str>,
    pub provider_channel: Cow<'static, str>,
    pub consumer_channel: Cow<'static, str>,
}

/// One node in the component topology tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentNode {
    pub moniker: Cow<'static, str>,
    pub instance_name: Cow<'static, str>,
    pub parent_index: Option<usize>,
    pub children_indices: Cow<'static, [usize]>,
    pub runner: RunnerSpec,
    pub startup: StartupPolicy,
    pub lifecycle: LifecycleKind,
    pub requires: HardwarePredicates,
    pub after: Cow<'static, [usize]>,
    pub mounts: Cow<'static, [MountSpec]>,
    pub restart: RestartPolicy,
    pub restart_backoff_ms: u64,
    pub restart_backoff_max_ms: u64,
    pub burst_limit: u32,
    pub burst_window_ms: u64,
    pub stop_timeout_ms: u64,
    pub critical: Criticality,
    pub escalation: EscalationAction,
    pub oom_tier: OomTier,
    pub dynamic_mount: bool,
    pub capabilities: CapabilityCeiling,
    pub exposes: Cow<'static, [ExposeSpec]>,
    pub routes: Cow<'static, [RouteSpec]>,
    pub sockets: Cow<'static, [SocketActivationSpec]>,
}

impl ComponentNode {
    /// Relative path under `/components` used for `helios:system/inspect` publication.
    ///
    /// Root `"/"` maps to `"root"`, and `"/plugins/compiler"` maps to `"plugins/compiler"`.
    #[must_use]
    pub fn inspect_prefix(&self) -> &str {
        let stripped = self.moniker.trim_start_matches('/');
        if stripped.is_empty() {
            "root"
        } else {
            stripped
        }
    }
}

/// Validated static or owned component topology table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentTopology {
    pub nodes: Cow<'static, [ComponentNode]>,
}

impl ComponentTopology {
    /// Finds a component node index by its normalized moniker.
    #[must_use]
    pub fn find_by_moniker(&self, moniker: &str) -> Option<usize> {
        self.nodes
            .iter()
            .position(|node| node.moniker.as_ref() == moniker)
    }

    /// Returns the node at `index`.
    #[must_use]
    pub fn node(&self, index: usize) -> &ComponentNode {
        &self.nodes[index]
    }
}

/// Live lifecycle status published under `/components/<moniker>/state`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ComponentStatus {
    #[default]
    Unstarted,
    Starting,
    Running,
    Completed,
    Failed,
}

impl ComponentStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unstarted => "unstarted",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

/// Live component state record published to `helios:system/inspect`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentStateRecord {
    pub moniker: String,
    pub inspect_prefix: String,
    pub status: ComponentStatus,
    pub restarts: u64,
    pub instance_id: Option<u64>,
    pub runner: &'static str,
    pub oom_tier: &'static str,
}
