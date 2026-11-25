//! Unified Ed25519 + `postcard` authentication, short-lived `CapabilityCert`
//! issuance and offline monotonic attenuation, and `MachineIdentity` handshake
//! verification across `tcp+tls`, `vsock`, and `serial` inspector transports.
//!
//! Zero X.509 client-certificate parsing is performed anywhere in this protocol:
//! clients authenticate exclusively via raw 32-byte Ed25519 public keys (either
//! authorized static keys or Authority CA-signed short-lived [`CapabilityCert`]s
//! with optional offline [`AttenuationLink`] chains), bound to the node's live
//! `MachineIdentity` public key and, on `tcp+tls`, the RFC 8446 `tls-exporter`
//! channel binding.

use std::io;
use std::pin::Pin;

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use futures_io::{AsyncRead, AsyncWrite};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Default TCP port for `helios://` (`tcp+tls`) inspector endpoints.
pub const DEFAULT_INSPECTOR_TCP_PORT: u16 = 9443;

/// Bootfs/VFS path where `inspector-host` loads its serialized [`AuthPolicy`].
pub const INSPECTOR_POLICY_PATH: &str = "/etc/inspector/policy.postcard";

/// Host-only filename (mode `0600`) holding the dev/test Ed25519 client seed
/// paired with the public key written into [`INSPECTOR_POLICY_PATH`] by
/// `helios-cli kernel-prebuild` / `image-build`.
pub const INSPECTOR_CLIENT_KEY_FILE: &str = "inspector-client-secret.key";

/// Domain label passed to `helios:system/machine-identity.sign` when signing
/// the inspector handshake challenge.
pub const MACHINE_IDENTITY_HANDSHAKE_DOMAIN: &str = "inspector-handshake";

/// RFC 8446 `tls-exporter` label used to derive the 32-byte channel binding on
/// `tcp+tls` inspector connections.
pub const TLS_EXPORTER_LABEL: &[u8] = b"EXPORTER-helios-inspector-v1";

/// Console-safe 8-byte frame sync magic for pre-RPC auth handshake messages.
///
/// Distinct from [`crate::wire::FRAME_MAGIC`] (`HRPC`) so interleaved guest
/// boot console lines on `serial` are skipped cleanly without colliding with
/// post-handshake WIT-RPC framing.
pub const AUTH_FRAME_MAGIC: [u8; 8] = [0xff, 0x00, b'H', b'A', b'U', b'T', 0xaa, 0x55];

/// Maximum encoded size of a single handshake or control message (64 KiB).
pub const MAX_AUTH_FRAME_SIZE: usize = 64 * 1024;

/// Current inspector authentication protocol version.
pub const AUTH_PROTOCOL_VERSION: u16 = 1;

/// Maximum offline attenuation links allowed on one [`CapabilityCert`].
pub const MAX_ATTENUATION_CHAIN_DEPTH: usize = 16;

/// Exact domain-separation prefix enforced by `helios:system/machine-identity.sign`
/// (`wit/deps/helios-system/machine-identity.wit`).
const MACHINE_IDENTITY_PREFIX: &[u8] = b"helios.machine-identity.v1\0";
const CAPABILITY_CERT_DOMAIN: &[u8] = b"helios.inspector.capability-cert.v1\0";
const ATTENUATION_LINK_DOMAIN: &[u8] = b"helios.inspector.attenuation.v1\0";
const CLIENT_AUTH_PROOF_DOMAIN: &[u8] = b"helios.inspector.client-auth.v1\0";
const HANDSHAKE_CHALLENGE_DOMAIN: &[u8] = b"helios.inspector.handshake-challenge.v1\0";
const MAX_SERIAL_PREAMBLE_BYTES: usize = 256 * 1024;

/// Transport carrying an inspector session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportKind {
    TcpTls,
    Vsock,
    Serial,
}

impl TransportKind {
    #[must_use]
    pub const fn as_mask(self) -> TransportMask {
        match self {
            Self::TcpTls => TransportMask::TCP_TLS,
            Self::Vsock => TransportMask::VSOCK,
            Self::Serial => TransportMask::SERIAL,
        }
    }

    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::TcpTls => 1,
            Self::Vsock => 2,
            Self::Serial => 3,
        }
    }
}

macro_rules! define_mask {
    (
        $(#[$meta:meta])*
        pub struct $name:ident(u8, all = $all_val:expr) {
            $(pub const $bit_name:ident = $bit_val:expr;)*
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(u8);

        impl $name {
            pub const EMPTY: Self = Self(0);
            $(pub const $bit_name: Self = Self($bit_val);)*
            pub const ALL: Self = Self($all_val);

            #[must_use]
            pub const fn from_bits_truncate(bits: u8) -> Self {
                Self(bits & $all_val)
            }

            #[must_use]
            pub const fn bits(self) -> u8 {
                self.0
            }

            #[must_use]
            pub const fn is_empty(self) -> bool {
                self.0 == 0
            }

            #[must_use]
            pub const fn contains(self, other: Self) -> bool {
                (self.0 & other.0) == other.0
            }

            #[must_use]
            pub const fn is_subset_of(self, ceiling: Self) -> bool {
                (self.0 & !ceiling.0) == 0
            }

            #[must_use]
            pub const fn union(self, other: Self) -> Self {
                Self((self.0 | other.0) & $all_val)
            }

            #[must_use]
            pub const fn intersection(self, other: Self) -> Self {
                Self(self.0 & other.0)
            }
        }
    };
}

define_mask! {
    /// Allowed transports for a policy entry or capability certificate.
    pub struct TransportMask(u8, all = 0x07) {
        pub const TCP_TLS = 1 << 0;
        pub const VSOCK = 1 << 1;
        pub const SERIAL = 1 << 2;
    }
}

define_mask! {
    /// Fine-grained directory rights mirroring `helios:system/programs.filesystem-right`.
    pub struct DirectoryRightsMask(u8, all = 0x0f) {
        pub const READ = 1 << 0;
        pub const WRITE = 1 << 1;
        pub const MUTATE_DIRECTORY = 1 << 2;
        pub const EXECUTE = 1 << 3;
    }
}

define_mask! {
    /// Fine-grained network rights mirroring `helios:system/programs.network-right`.
    pub struct NetworkRightsMask(u8, all = 0x3f) {
        pub const TCP = 1 << 0;
        pub const UDP = 1 << 1;
        pub const DNS = 1 << 2;
        pub const PRIVILEGED_BIND = 1 << 3;
        pub const MULTICAST = 1 << 4;
        pub const ADMIN = 1 << 5;
    }
}

define_mask! {
    /// Clock rights mirroring `helios:system/programs.clock-right`.
    pub struct ClockRightsMask(u8, all = 0x01) {
        pub const SET_WALL_CLOCK = 1 << 0;
    }
}

define_mask! {
    /// Terminal rights mirroring `helios:system/programs.terminal-right`.
    pub struct TerminalRightsMask(u8, all = 0x07) {
        pub const INPUT = 1 << 0;
        pub const OUTPUT = 1 << 1;
        pub const CONTROL = 1 << 2;
    }
}

define_mask! {
    /// Process-control rights mirroring `helios:system/programs.process-right`.
    pub struct ProcessRightsMask(u8, all = 0x1f) {
        pub const SPAWN = 1 << 0;
        pub const EXEC = 1 << 1;
        pub const FORK = 1 << 2;
        pub const JOIN = 1 << 3;
        pub const SIGNAL = 1 << 4;
    }
}

define_mask! {
    /// Link rights mirroring `helios:system/programs.link-right`.
    pub struct LinkRightsMask(u8, all = 0x0f) {
        pub const SOURCE = 1 << 0;
        pub const TARGET_DIRECTORY = 1 << 1;
        pub const SYMLINK_CREATE = 1 << 2;
        pub const SYMLINK_READ = 1 << 3;
    }
}

define_mask! {
    /// Mount rights mirroring `helios:system/programs.mount-right`.
    pub struct MountRightsMask(u8, all = 0x03) {
        pub const MOUNT = 1 << 0;
        pub const UNMOUNT = 1 << 1;
    }
}

define_mask! {
    /// Device-class rights mirroring `helios:system/programs.device-class`.
    pub struct DeviceClassMask(u8, all = 0x0f) {
        pub const DISPLAY = 1 << 0;
        pub const INPUT = 1 << 1;
        pub const GPU = 1 << 2;
        pub const AUDIO = 1 << 3;
    }
}

/// Directory capability grant rule bounded monotonically by path prefix and rights.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryRule {
    pub source_path: String,
    pub guest_name: String,
    pub rights: DirectoryRightsMask,
}

impl DirectoryRule {
    #[must_use]
    pub fn new(
        source_path: impl Into<String>,
        guest_name: impl Into<String>,
        rights: DirectoryRightsMask,
    ) -> Self {
        Self {
            source_path: source_path.into(),
            guest_name: guest_name.into(),
            rights,
        }
    }

    /// Validates that both paths are normalized absolute paths with no `..` traversal.
    pub fn validate(&self) -> Result<(), AuthError> {
        let src = normalize_abs_path(&self.source_path).ok_or_else(|| AuthError::Malformed {
            detail: format!("invalid directory grant source path `{}`", self.source_path),
        })?;
        let guest = normalize_abs_path(&self.guest_name).ok_or_else(|| AuthError::Malformed {
            detail: format!("invalid directory grant guest name `{}`", self.guest_name),
        })?;
        if src != self.source_path || guest != self.guest_name {
            return Err(AuthError::Malformed {
                detail: format!(
                    "non-canonical directory grant `{}` -> `{}`",
                    self.source_path, self.guest_name
                ),
            });
        }
        Ok(())
    }
}

/// Observation or control scope for an instance-scoped capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeRule {
    /// Only the worker instance itself.
    Own,
    /// A component moniker subtree (e.g. `"/core/http"`), enforced on strict `/` boundaries.
    Subtree(String),
    /// The entire machine, including kernel records and all instances.
    Machine,
}

impl ScopeRule {
    /// Returns `true` iff `self` is within or equal to `ceiling`.
    #[must_use]
    pub fn is_subset_of(&self, ceiling: &Self) -> bool {
        match (self, ceiling) {
            (_, Self::Machine) => true,
            (Self::Own, Self::Own | Self::Subtree(_)) => true,
            (Self::Subtree(child), Self::Subtree(parent)) => {
                let Some(norm_child) = normalize_abs_path(child) else {
                    return false;
                };
                let Some(norm_parent) = normalize_abs_path(parent) else {
                    return false;
                };
                path_is_prefix(&norm_parent, &norm_child)
            }
            (Self::Machine, Self::Own | Self::Subtree(_)) => false,
            (Self::Subtree(_), Self::Own) => false,
        }
    }

    #[must_use]
    pub fn intersect(&self, ceiling: &Self) -> Option<Self> {
        match (self, ceiling) {
            (other, Self::Machine) => Some(other.clone()),
            (Self::Machine, other) => Some(other.clone()),
            (Self::Own, _) | (_, Self::Own) => Some(Self::Own),
            (Self::Subtree(a), Self::Subtree(b)) => {
                let na = normalize_abs_path(a)?;
                let nb = normalize_abs_path(b)?;
                if path_is_prefix(&nb, &na) {
                    Some(Self::Subtree(na))
                } else if path_is_prefix(&na, &nb) {
                    Some(Self::Subtree(nb))
                } else {
                    None
                }
            }
        }
    }
}

/// Fine-grained capability set negotiated for one `inspector-worker` session.
///
/// `machine-right.identity` is intentionally unrepresentable here so a session
/// worker can never be granted access to the node's `MachineIdentity` signing key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionGrants {
    pub directories: Vec<DirectoryRule>,
    pub network: NetworkRightsMask,
    pub clock: ClockRightsMask,
    pub terminal: TerminalRightsMask,
    pub process: ProcessRightsMask,
    pub link: LinkRightsMask,
    pub mount: MountRightsMask,
    pub devices: DeviceClassMask,
    pub inspect_read: Option<ScopeRule>,
    pub trace_read: Option<ScopeRule>,
    pub profile_read: Option<ScopeRule>,
    pub diagnostics_control: bool,
    pub instance_control: Option<ScopeRule>,
    pub settings_write: bool,
    pub machine_control: bool,
    pub virtualize: bool,
    pub component_control: Option<ScopeRule>,
}

impl SessionGrants {
    /// Empty authority (`ProcessAuthority::empty()`).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Maximum capability ceiling permitted for an `inspector-worker` session
    /// (matches `components/inspector/worker/component.toml`; omits
    /// `machine.identity`).
    #[must_use]
    pub fn full_worker_ceiling() -> Self {
        Self {
            directories: vec![DirectoryRule::new("/", "/", DirectoryRightsMask::ALL)],
            network: NetworkRightsMask::ALL,
            clock: ClockRightsMask::ALL,
            terminal: TerminalRightsMask::ALL,
            process: ProcessRightsMask::ALL,
            link: LinkRightsMask::ALL,
            mount: MountRightsMask::ALL,
            devices: DeviceClassMask::ALL,
            inspect_read: Some(ScopeRule::Machine),
            trace_read: Some(ScopeRule::Machine),
            profile_read: Some(ScopeRule::Machine),
            diagnostics_control: true,
            instance_control: Some(ScopeRule::Machine),
            settings_write: true,
            machine_control: true,
            virtualize: true,
            component_control: Some(ScopeRule::Machine),
        }
    }

    /// Validates all internal path invariants.
    pub fn validate(&self) -> Result<(), AuthError> {
        for dir in &self.directories {
            dir.validate()?;
        }
        for scope in [
            self.inspect_read.as_ref(),
            self.trace_read.as_ref(),
            self.profile_read.as_ref(),
            self.instance_control.as_ref(),
            self.component_control.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if let ScopeRule::Subtree(moniker) = scope {
                let norm = normalize_abs_path(moniker).ok_or_else(|| AuthError::Malformed {
                    detail: format!("invalid scope moniker `{moniker}`"),
                })?;
                if norm != *moniker {
                    return Err(AuthError::Malformed {
                        detail: format!("non-canonical scope moniker `{moniker}`"),
                    });
                }
            }
        }
        Ok(())
    }

    /// Returns `Ok(())` iff every capability in `self` is monotonically bounded
    /// by `ceiling`; otherwise returns [`AuthError::CapabilityEscalation`] naming
    /// the escalated dimension.
    pub fn check_subset_of(&self, ceiling: &Self) -> Result<(), AuthError> {
        self.validate()?;
        ceiling.validate()?;

        for req_dir in &self.directories {
            if req_dir.rights.is_empty() {
                continue;
            }
            let mut covered = DirectoryRightsMask::EMPTY;
            for ceil_dir in &ceiling.directories {
                if path_is_prefix(&ceil_dir.source_path, &req_dir.source_path) {
                    covered = covered.union(ceil_dir.rights);
                }
            }
            if !req_dir.rights.is_subset_of(covered) {
                return Err(AuthError::CapabilityEscalation {
                    dimension: "directories",
                    detail: format!(
                        "directory `{}` requests rights {:#x}, exceeding ceiling {:#x}",
                        req_dir.source_path,
                        req_dir.rights.bits(),
                        covered.bits()
                    ),
                });
            }
        }

        if !self.network.is_subset_of(ceiling.network) {
            return Err(AuthError::CapabilityEscalation {
                dimension: "network",
                detail: format!(
                    "network rights {:#x} exceed ceiling {:#x}",
                    self.network.bits(),
                    ceiling.network.bits()
                ),
            });
        }
        if !self.clock.is_subset_of(ceiling.clock) {
            return Err(AuthError::CapabilityEscalation {
                dimension: "clock",
                detail: "clock rights exceed ceiling".to_owned(),
            });
        }
        if !self.terminal.is_subset_of(ceiling.terminal) {
            return Err(AuthError::CapabilityEscalation {
                dimension: "terminal",
                detail: "terminal rights exceed ceiling".to_owned(),
            });
        }
        if !self.process.is_subset_of(ceiling.process) {
            return Err(AuthError::CapabilityEscalation {
                dimension: "process",
                detail: "process rights exceed ceiling".to_owned(),
            });
        }
        if !self.link.is_subset_of(ceiling.link) {
            return Err(AuthError::CapabilityEscalation {
                dimension: "link",
                detail: "link rights exceed ceiling".to_owned(),
            });
        }
        if !self.mount.is_subset_of(ceiling.mount) {
            return Err(AuthError::CapabilityEscalation {
                dimension: "mount",
                detail: "mount rights exceed ceiling".to_owned(),
            });
        }
        if !self.devices.is_subset_of(ceiling.devices) {
            return Err(AuthError::CapabilityEscalation {
                dimension: "devices",
                detail: "device classes exceed ceiling".to_owned(),
            });
        }

        check_scope_subset("inspect-read", &self.inspect_read, &ceiling.inspect_read)?;
        check_scope_subset("trace-read", &self.trace_read, &ceiling.trace_read)?;
        check_scope_subset("profile-read", &self.profile_read, &ceiling.profile_read)?;
        if self.diagnostics_control && !ceiling.diagnostics_control {
            return Err(AuthError::CapabilityEscalation {
                dimension: "diagnostics-control",
                detail: "diagnostics control exceeds ceiling".to_owned(),
            });
        }
        check_scope_subset(
            "instance-control",
            &self.instance_control,
            &ceiling.instance_control,
        )?;
        if self.settings_write && !ceiling.settings_write {
            return Err(AuthError::CapabilityEscalation {
                dimension: "settings-write",
                detail: "settings write exceeds ceiling".to_owned(),
            });
        }
        if self.machine_control && !ceiling.machine_control {
            return Err(AuthError::CapabilityEscalation {
                dimension: "machine-control",
                detail: "machine control exceeds ceiling".to_owned(),
            });
        }
        if self.virtualize && !ceiling.virtualize {
            return Err(AuthError::CapabilityEscalation {
                dimension: "virtualize",
                detail: "virtualize right exceeds ceiling".to_owned(),
            });
        }
        check_scope_subset(
            "component-control",
            &self.component_control,
            &ceiling.component_control,
        )?;

        Ok(())
    }

    /// Monotonically narrows `self` to `requested`, rejecting any widening.
    pub fn attenuate(&self, requested: &Self) -> Result<Self, AuthError> {
        requested.check_subset_of(self)?;
        Ok(requested.clone())
    }

    /// Computes the monotonic intersection of `self` and `ceiling`.
    #[must_use]
    pub fn intersect(&self, ceiling: &Self) -> Self {
        let mut directories = Vec::new();
        for dir in &self.directories {
            let mut covered = DirectoryRightsMask::EMPTY;
            for ceil in &ceiling.directories {
                if path_is_prefix(&ceil.source_path, &dir.source_path) {
                    covered = covered.union(ceil.rights);
                }
            }
            let rights = dir.rights.intersection(covered);
            if !rights.is_empty() {
                directories.push(DirectoryRule {
                    source_path: dir.source_path.clone(),
                    guest_name: dir.guest_name.clone(),
                    rights,
                });
            }
        }
        Self {
            directories,
            network: self.network.intersection(ceiling.network),
            clock: self.clock.intersection(ceiling.clock),
            terminal: self.terminal.intersection(ceiling.terminal),
            process: self.process.intersection(ceiling.process),
            link: self.link.intersection(ceiling.link),
            mount: self.mount.intersection(ceiling.mount),
            devices: self.devices.intersection(ceiling.devices),
            inspect_read: intersect_opt_scope(&self.inspect_read, &ceiling.inspect_read),
            trace_read: intersect_opt_scope(&self.trace_read, &ceiling.trace_read),
            profile_read: intersect_opt_scope(&self.profile_read, &ceiling.profile_read),
            diagnostics_control: self.diagnostics_control && ceiling.diagnostics_control,
            instance_control: intersect_opt_scope(
                &self.instance_control,
                &ceiling.instance_control,
            ),
            settings_write: self.settings_write && ceiling.settings_write,
            machine_control: self.machine_control && ceiling.machine_control,
            virtualize: self.virtualize && ceiling.virtualize,
            component_control: intersect_opt_scope(
                &self.component_control,
                &ceiling.component_control,
            ),
        }
    }
}

fn check_scope_subset(
    dimension: &'static str,
    child: &Option<ScopeRule>,
    parent: &Option<ScopeRule>,
) -> Result<(), AuthError> {
    match (child, parent) {
        (None, _) => Ok(()),
        (Some(_), None) => Err(AuthError::CapabilityEscalation {
            dimension,
            detail: format!("{dimension} requested without parent ceiling grant"),
        }),
        (Some(c), Some(p)) if c.is_subset_of(p) => Ok(()),
        (Some(c), Some(p)) => Err(AuthError::CapabilityEscalation {
            dimension,
            detail: format!("{dimension} scope {c:?} exceeds ceiling {p:?}"),
        }),
    }
}

fn intersect_opt_scope(a: &Option<ScopeRule>, b: &Option<ScopeRule>) -> Option<ScopeRule> {
    match (a, b) {
        (Some(sa), Some(sb)) => sa.intersect(sb),
        _ => None,
    }
}

/// Static Ed25519 key authorized directly in [`AuthPolicy`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedStaticKey {
    pub label: String,
    pub public_key: [u8; 32],
    pub grants: SessionGrants,
    pub allowed_transports: TransportMask,
}

/// Authority CA Ed25519 public key trusted to issue short-lived [`CapabilityCert`]s.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedAuthorityCa {
    pub label: String,
    pub public_key: [u8; 32],
    pub ceiling: SessionGrants,
    /// Maximum allowed lifetime (`expires_at_unix - not_before_unix`), in seconds.
    pub max_ttl_secs: u64,
    pub allowed_transports: TransportMask,
}

/// Policy file staged into bootfs/VFS at [`INSPECTOR_POLICY_PATH`] and loaded
/// exclusively by `inspector-host`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthPolicy {
    pub version: u16,
    pub static_keys: Vec<AuthorizedStaticKey>,
    pub trusted_cas: Vec<TrustedAuthorityCa>,
}

impl AuthPolicy {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            version: AUTH_PROTOCOL_VERSION,
            static_keys: Vec::new(),
            trusted_cas: Vec::new(),
        }
    }

    /// Creates a policy authorizing one static Ed25519 key across all transports
    /// up to [`SessionGrants::full_worker_ceiling`].
    #[must_use]
    pub fn single_static_key(label: impl Into<String>, public_key: [u8; 32]) -> Self {
        Self {
            version: AUTH_PROTOCOL_VERSION,
            static_keys: vec![AuthorizedStaticKey {
                label: label.into(),
                public_key,
                grants: SessionGrants::full_worker_ceiling(),
                allowed_transports: TransportMask::ALL,
            }],
            trusted_cas: Vec::new(),
        }
    }

    pub fn encode_postcard(&self) -> Result<Vec<u8>, AuthError> {
        postcard::to_allocvec(self).map_err(|source| AuthError::Encode {
            context: "AuthPolicy",
            source,
        })
    }

    pub fn decode_postcard(bytes: &[u8]) -> Result<Self, AuthError> {
        let policy: Self = postcard::from_bytes(bytes).map_err(|source| AuthError::Decode {
            context: "AuthPolicy",
            source,
        })?;
        if policy.version != AUTH_PROTOCOL_VERSION {
            return Err(AuthError::UnsupportedVersion {
                version: policy.version,
            });
        }
        for key in &policy.static_keys {
            key.grants.validate()?;
        }
        for ca in &policy.trusted_cas {
            ca.ceiling.validate()?;
        }
        Ok(policy)
    }
}

/// Signed body of a short-lived Authority CA [`CapabilityCert`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityCertPayload {
    pub version: u16,
    pub principal: String,
    pub subject_public_key: [u8; 32],
    /// Optional target node pin (`MachineIdentity` Ed25519 public key).
    pub node_public_key: Option<[u8; 32]>,
    pub not_before_unix: u64,
    pub expires_at_unix: u64,
    pub grants: SessionGrants,
    pub allowed_transports: TransportMask,
}

/// Short-lived Authority CA-signed Ed25519 capability certificate (`postcard`,
/// zero X.509 parsing).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityCert {
    pub payload: CapabilityCertPayload,
    pub ca_public_key: [u8; 32],
    #[serde(with = "serde_bytes_64")]
    pub ca_signature: [u8; 64],
}

impl CapabilityCert {
    /// Signs `payload` with the Authority CA's Ed25519 signing key.
    pub fn issue(
        ca_signing_key: &SigningKey,
        payload: CapabilityCertPayload,
    ) -> Result<Self, AuthError> {
        payload.grants.validate()?;
        let encoded = postcard::to_allocvec(&payload).map_err(|source| AuthError::Encode {
            context: "CapabilityCertPayload",
            source,
        })?;
        let mut msg = Vec::with_capacity(CAPABILITY_CERT_DOMAIN.len() + encoded.len());
        msg.extend_from_slice(CAPABILITY_CERT_DOMAIN);
        msg.extend_from_slice(&encoded);
        let sig = ca_signing_key.sign(&msg);
        Ok(Self {
            payload,
            ca_public_key: ca_signing_key.verifying_key().to_bytes(),
            ca_signature: sig.to_bytes(),
        })
    }

    /// Encodes this certificate to canonical postcard bytes.
    pub fn encode_postcard(&self) -> Result<Vec<u8>, AuthError> {
        postcard::to_allocvec(self).map_err(|source| AuthError::Encode {
            context: "CapabilityCert",
            source,
        })
    }

    /// Decodes a certificate from canonical postcard bytes.
    pub fn decode_postcard(bytes: &[u8]) -> Result<Self, AuthError> {
        postcard::from_bytes(bytes).map_err(|source| AuthError::Decode {
            context: "CapabilityCert",
            source,
        })
    }

    /// SHA-256 commitment over the certificate's canonical bytes, used to chain
    /// offline [`AttenuationLink`] signatures.
    pub fn commitment_hash(&self) -> Result<[u8; 32], AuthError> {
        let encoded = self.encode_postcard()?;
        let digest = Sha256::digest(&encoded);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok(out)
    }

    /// Produces an offline monotonically attenuated delegation link chained
    /// onto `self` and `prior_links`, signed by `parent_signing_key`.
    pub fn attenuate(
        &self,
        prior_links: &[AttenuationLink],
        parent_signing_key: &SigningKey,
        payload: AttenuationPayload,
    ) -> Result<AttenuationLink, AuthError> {
        payload.grants.validate()?;
        let prev_hash = match prior_links.last() {
            Some(last) => last.commitment_hash()?,
            None => self.commitment_hash()?,
        };
        AttenuationLink::sign(parent_signing_key, prev_hash, payload)
    }
}

/// Signed body of one offline monotonic attenuation link.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttenuationPayload {
    pub delegate_public_key: [u8; 32],
    /// Optional narrower target node pin; cannot replace or remove a parent pin.
    pub node_public_key: Option<[u8; 32]>,
    pub expires_at_unix: u64,
    pub grants: SessionGrants,
    pub allowed_transports: TransportMask,
}

/// Offline monotonic attenuation link chaining from a [`CapabilityCert`] or a
/// preceding [`AttenuationLink`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttenuationLink {
    pub payload: AttenuationPayload,
    #[serde(with = "serde_bytes_64")]
    pub signature: [u8; 64],
}

impl AttenuationLink {
    pub fn sign(
        parent_signing_key: &SigningKey,
        prev_hash: [u8; 32],
        payload: AttenuationPayload,
    ) -> Result<Self, AuthError> {
        payload.grants.validate()?;
        let encoded = postcard::to_allocvec(&payload).map_err(|source| AuthError::Encode {
            context: "AttenuationPayload",
            source,
        })?;
        let mut msg =
            Vec::with_capacity(ATTENUATION_LINK_DOMAIN.len() + prev_hash.len() + encoded.len());
        msg.extend_from_slice(ATTENUATION_LINK_DOMAIN);
        msg.extend_from_slice(&prev_hash);
        msg.extend_from_slice(&encoded);
        let sig = parent_signing_key.sign(&msg);
        Ok(Self {
            payload,
            signature: sig.to_bytes(),
        })
    }

    pub fn commitment_hash(&self) -> Result<[u8; 32], AuthError> {
        let encoded = postcard::to_allocvec(self).map_err(|source| AuthError::Encode {
            context: "AttenuationLink",
            source,
        })?;
        let digest = Sha256::digest(&encoded);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok(out)
    }
}

/// Client credential presented inside [`ClientAuth`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientCredential {
    StaticKey {
        public_key: [u8; 32],
        /// Optional narrower grants requested below the policy entry's ceiling.
        requested_grants: Option<SessionGrants>,
    },
    CapabilityCert {
        cert: CapabilityCert,
        attenuations: Vec<AttenuationLink>,
    },
}

/// Client-to-server handshake opener sent before [`ServerHello`] so serial and
/// socket listeners never emit binary framing before a client begins auth.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientHello {
    pub protocol_version: u16,
}

/// Server-to-client handshake message signed by `helios:system/machine-identity`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerHello {
    pub protocol_version: u16,
    pub transport: TransportKind,
    pub machine_public_key: [u8; 32],
    pub server_nonce: [u8; 32],
    pub server_unix_time: u64,
    pub tls_binding_required: bool,
    #[serde(with = "serde_bytes_64")]
    pub machine_signature: [u8; 64],
}

/// Client-to-server authentication message bound to the server's `MachineIdentity`,
/// nonce, transport, and (on `tcp+tls`) RFC 8446 `tls-exporter` channel binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientAuth {
    pub credential: ClientCredential,
    pub channel_binding: Option<[u8; 32]>,
    pub client_nonce: [u8; 32],
    #[serde(with = "serde_bytes_64")]
    pub proof_signature: [u8; 64],
}

/// Machine-readable reason code when `inspector-host` rejects authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthRejectCode {
    UnsupportedVersion,
    UnknownKey,
    UntrustedCa,
    InvalidSignature,
    Expired,
    NotYetValid,
    TtlExceeded,
    WrongNode,
    WrongTransport,
    WrongChannelBinding,
    CapabilityEscalation,
    ChainTooDeep,
    Malformed,
    Internal,
}

/// Final server decision after verifying [`ClientAuth`] and spawning `inspector-worker`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerAuthResult {
    Accepted {
        granted: SessionGrants,
        session_id: u64,
    },
    Rejected {
        code: AuthRejectCode,
        detail: String,
    },
}

/// Control-channel request from zero-authority `inspector-tls` to `inspector-host`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsControlRequest {
    /// Request `inspector-host` to sign the TLS 1.3 channel binding and peer
    /// ephemeral SPKI digest using `helios:system/machine-identity`.
    SignHandshake {
        channel_binding: [u8; 32],
        tls_spki_sha256: [u8; 32],
        server_nonce: [u8; 32],
    },
    /// Request `inspector-host` to verify [`ClientAuth`], spawn the attenuated
    /// `inspector-worker` bound to the session's data IPC channel, and return
    /// the decision.
    Authenticate {
        server_hello: ServerHello,
        channel_binding: [u8; 32],
        client_auth: Box<ClientAuth>,
    },
}

/// Control-channel response from `inspector-host` to `inspector-tls`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsControlResponse {
    HandshakeSigned(ServerHello),
    AuthDecision(ServerAuthResult),
    Error(String),
}

/// Verified session metadata returned by [`verify_client_auth`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSession {
    pub principal: String,
    pub leaf_public_key: [u8; 32],
    pub granted: SessionGrants,
}

/// Typed authentication and handshake verification errors.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("unsupported inspector auth protocol version {version}")]
    UnsupportedVersion { version: u16 },
    #[error("transport mismatch: expected {expected:?}, got {actual:?}")]
    TransportMismatch {
        expected: TransportKind,
        actual: TransportKind,
    },
    #[error("client key is not authorized by inspector policy")]
    UnknownKey,
    #[error("capability certificate issuer CA is not trusted")]
    UntrustedCa,
    #[error("Ed25519 signature verification failed ({context})")]
    InvalidSignature { context: &'static str },
    #[error("credential expired at unix timestamp {expires_at} (now {now})")]
    Expired { expires_at: u64, now: u64 },
    #[error("credential is not valid until unix timestamp {not_before} (now {now})")]
    NotYetValid { not_before: u64, now: u64 },
    #[error("certificate lifetime {ttl}s exceeds CA max TTL {max_ttl}s")]
    TtlExceeded { ttl: u64, max_ttl: u64 },
    #[error("credential is pinned to a different node MachineIdentity")]
    WrongNode,
    #[error("credential is not permitted on transport {transport:?}")]
    WrongTransport { transport: TransportKind },
    #[error("TLS channel binding missing or mismatched")]
    WrongChannelBinding,
    #[error("capability escalation in {dimension}: {detail}")]
    CapabilityEscalation {
        dimension: &'static str,
        detail: String,
    },
    #[error("attenuation chain length {depth} exceeds maximum {MAX_ATTENUATION_CHAIN_DEPTH}")]
    ChainTooDeep { depth: usize },
    #[error("malformed auth payload: {detail}")]
    Malformed { detail: String },
    #[error("remote rejected authentication ({code:?}): {detail}")]
    Rejected {
        code: AuthRejectCode,
        detail: String,
    },
    #[error("failed to encode {context}: {source}")]
    Encode {
        context: &'static str,
        #[source]
        source: postcard::Error,
    },
    #[error("failed to decode {context}: {source}")]
    Decode {
        context: &'static str,
        #[source]
        source: postcard::Error,
    },
    #[error("authentication transport I/O failed during {operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("peer closed transport before completing authentication")]
    UnexpectedEof,
}

impl AuthError {
    #[must_use]
    pub const fn reject_code(&self) -> AuthRejectCode {
        match self {
            Self::UnsupportedVersion { .. } => AuthRejectCode::UnsupportedVersion,
            Self::UnknownKey => AuthRejectCode::UnknownKey,
            Self::UntrustedCa => AuthRejectCode::UntrustedCa,
            Self::InvalidSignature { .. } => AuthRejectCode::InvalidSignature,
            Self::Expired { .. } => AuthRejectCode::Expired,
            Self::NotYetValid { .. } => AuthRejectCode::NotYetValid,
            Self::TtlExceeded { .. } => AuthRejectCode::TtlExceeded,
            Self::WrongNode => AuthRejectCode::WrongNode,
            Self::WrongTransport { .. } | Self::TransportMismatch { .. } => {
                AuthRejectCode::WrongTransport
            }
            Self::WrongChannelBinding => AuthRejectCode::WrongChannelBinding,
            Self::CapabilityEscalation { .. } => AuthRejectCode::CapabilityEscalation,
            Self::ChainTooDeep { .. } => AuthRejectCode::ChainTooDeep,
            Self::Malformed { .. } | Self::Decode { .. } => AuthRejectCode::Malformed,
            Self::Rejected { code, .. } => *code,
            Self::Encode { .. } | Self::Io { .. } | Self::UnexpectedEof => AuthRejectCode::Internal,
        }
    }
}

/// Client-side Ed25519 credential used to authenticate a session.
#[derive(Clone)]
pub enum ClientIdentity {
    StaticKey {
        signing_key: [u8; 32],
        requested_grants: Option<SessionGrants>,
    },
    CapabilityCert {
        signing_key: [u8; 32],
        cert: Box<CapabilityCert>,
        attenuations: Vec<AttenuationLink>,
    },
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StaticKey {
                requested_grants, ..
            } => f
                .debug_struct("ClientIdentity::StaticKey")
                .field("public_key", &self.public_key())
                .field("requested_grants", requested_grants)
                .finish(),
            Self::CapabilityCert {
                cert, attenuations, ..
            } => f
                .debug_struct("ClientIdentity::CapabilityCert")
                .field("principal", &cert.payload.principal)
                .field("attenuations", &attenuations.len())
                .finish(),
        }
    }
}

impl ClientIdentity {
    /// Creates a static-key client identity from a raw 32-byte Ed25519 seed.
    #[must_use]
    pub fn from_static_seed(seed: [u8; 32]) -> Self {
        Self::StaticKey {
            signing_key: seed,
            requested_grants: None,
        }
    }

    /// Creates a static-key client identity requesting an explicit narrowed grant set.
    #[must_use]
    pub fn from_static_seed_with_grants(seed: [u8; 32], grants: SessionGrants) -> Self {
        Self::StaticKey {
            signing_key: seed,
            requested_grants: Some(grants),
        }
    }

    /// Creates a capability-certificate client identity from the subject/delegate
    /// 32-byte Ed25519 seed, CA-signed [`CapabilityCert`], and optional offline
    /// attenuation chain.
    #[must_use]
    pub fn from_capability_cert(
        seed: [u8; 32],
        cert: CapabilityCert,
        attenuations: Vec<AttenuationLink>,
    ) -> Self {
        Self::CapabilityCert {
            signing_key: seed,
            cert: Box::new(cert),
            attenuations,
        }
    }

    /// Loads a raw 32-byte Ed25519 secret seed file (e.g. `inspector-client-secret.key`).
    pub fn from_seed_file(path: &std::path::Path) -> Result<Self, AuthError> {
        let bytes = std::fs::read(path).map_err(|source| AuthError::Io {
            operation: "read client identity seed file",
            source,
        })?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|raw: Vec<u8>| AuthError::Malformed {
                detail: format!(
                    "client identity seed file `{}` must be 32 bytes, found {}",
                    path.display(),
                    raw.len()
                ),
            })?;
        Ok(Self::from_static_seed(seed))
    }

    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        let seed = match self {
            Self::StaticKey { signing_key, .. } | Self::CapabilityCert { signing_key, .. } => {
                signing_key
            }
        };
        SigningKey::from_bytes(seed).verifying_key().to_bytes()
    }

    /// Returns a copy requesting strictly narrowed grants (offline attenuation
    /// for [`Self::CapabilityCert`], or explicit narrowed request for static keys).
    pub fn with_attenuated_grants(
        &self,
        grants: SessionGrants,
        node_public_key: Option<[u8; 32]>,
        expires_at_unix: Option<u64>,
        allowed_transports: Option<TransportMask>,
    ) -> Result<Self, AuthError> {
        grants.validate()?;
        match self {
            Self::StaticKey {
                signing_key,
                requested_grants,
            } => {
                if let Some(existing) = requested_grants {
                    grants.check_subset_of(existing)?;
                }
                Ok(Self::StaticKey {
                    signing_key: *signing_key,
                    requested_grants: Some(grants),
                })
            }
            Self::CapabilityCert {
                signing_key,
                cert,
                attenuations,
            } => {
                let parent_key = SigningKey::from_bytes(signing_key);
                let (parent_exp, parent_transports, parent_node) = match attenuations.last() {
                    Some(last) => (
                        last.payload.expires_at_unix,
                        last.payload.allowed_transports,
                        last.payload
                            .node_public_key
                            .or(cert.payload.node_public_key),
                    ),
                    None => (
                        cert.payload.expires_at_unix,
                        cert.payload.allowed_transports,
                        cert.payload.node_public_key,
                    ),
                };
                let link = cert.attenuate(
                    attenuations,
                    &parent_key,
                    AttenuationPayload {
                        delegate_public_key: parent_key.verifying_key().to_bytes(),
                        node_public_key: node_public_key.or(parent_node),
                        expires_at_unix: expires_at_unix.unwrap_or(parent_exp),
                        grants,
                        allowed_transports: allowed_transports.unwrap_or(parent_transports),
                    },
                )?;
                let mut next_links = attenuations.clone();
                next_links.push(link);
                Ok(Self::CapabilityCert {
                    signing_key: *signing_key,
                    cert: cert.clone(),
                    attenuations: next_links,
                })
            }
        }
    }

    /// Builds and signs a [`ClientAuth`] bound to `hello`, `channel_binding`,
    /// and `client_nonce`.
    pub fn build_client_auth(
        &self,
        hello: &ServerHello,
        channel_binding: Option<[u8; 32]>,
        client_nonce: [u8; 32],
    ) -> Result<ClientAuth, AuthError> {
        let (signing_key, credential) = match self {
            Self::StaticKey {
                signing_key,
                requested_grants,
            } => (
                SigningKey::from_bytes(signing_key),
                ClientCredential::StaticKey {
                    public_key: self.public_key(),
                    requested_grants: requested_grants.clone(),
                },
            ),
            Self::CapabilityCert {
                signing_key,
                cert,
                attenuations,
            } => (
                SigningKey::from_bytes(signing_key),
                ClientCredential::CapabilityCert {
                    cert: (**cert).clone(),
                    attenuations: attenuations.clone(),
                },
            ),
        };
        let proof_msg = client_auth_proof_message(
            hello.machine_public_key,
            hello.server_nonce,
            client_nonce,
            hello.transport,
            channel_binding,
            &credential,
        )?;
        let sig = signing_key.sign(&proof_msg);
        Ok(ClientAuth {
            credential,
            channel_binding,
            client_nonce,
            proof_signature: sig.to_bytes(),
        })
    }
}

/// Computes the 32-byte challenge passed to `helios:system/machine-identity.sign`
/// under [`MACHINE_IDENTITY_HANDSHAKE_DOMAIN`].
#[must_use]
pub fn compute_handshake_challenge(
    protocol_version: u16,
    transport: TransportKind,
    server_nonce: [u8; 32],
    server_unix_time: u64,
    channel_binding: Option<[u8; 32]>,
    tls_spki_sha256: Option<[u8; 32]>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HANDSHAKE_CHALLENGE_DOMAIN);
    hasher.update(protocol_version.to_le_bytes());
    hasher.update([transport.tag()]);
    hasher.update(server_nonce);
    hasher.update(server_unix_time.to_le_bytes());
    match channel_binding {
        Some(binding) => {
            hasher.update([1u8]);
            hasher.update(binding);
        }
        None => {
            hasher.update([0u8]);
            hasher.update([0u8; 32]);
        }
    }
    match tls_spki_sha256 {
        Some(spki) => {
            hasher.update([1u8]);
            hasher.update(spki);
        }
        None => {
            hasher.update([0u8]);
            hasher.update([0u8; 32]);
        }
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Formats the exact domain-separated signing transcript enforced by
/// `helios:system/machine-identity.sign` (`wit/deps/helios-system/machine-identity.wit`).
#[must_use]
pub fn machine_identity_signing_message(domain: &str, challenge: &[u8]) -> Vec<u8> {
    let domain_bytes = domain.as_bytes();
    let mut out = Vec::with_capacity(
        MACHINE_IDENTITY_PREFIX.len() + 4 + domain_bytes.len() + 4 + challenge.len(),
    );
    out.extend_from_slice(MACHINE_IDENTITY_PREFIX);
    out.extend_from_slice(&(domain_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(domain_bytes);
    out.extend_from_slice(&(challenge.len() as u32).to_le_bytes());
    out.extend_from_slice(challenge);
    out
}

/// Signs a handshake challenge locally using a test/simulated machine key in
/// the exact format `helios:system/machine-identity.sign` produces.
#[must_use]
pub fn sign_machine_identity_message(
    machine_key: &SigningKey,
    domain: &str,
    challenge: &[u8],
) -> [u8; 64] {
    let msg = machine_identity_signing_message(domain, challenge);
    machine_key.sign(&msg).to_bytes()
}

/// Signs a handshake challenge locally from a raw 32-byte machine key seed.
#[must_use]
pub fn sign_machine_identity_seed(seed: &[u8; 32], domain: &str, challenge: &[u8]) -> [u8; 64] {
    let key = SigningKey::from_bytes(seed);
    sign_machine_identity_message(&key, domain, challenge)
}

/// Verifies [`ServerHello`] on the client side before sending any credentials.
pub fn verify_server_hello(
    hello: &ServerHello,
    expected_transport: TransportKind,
    expected_node_key: Option<[u8; 32]>,
    channel_binding: Option<[u8; 32]>,
    tls_spki_sha256: Option<[u8; 32]>,
) -> Result<(), AuthError> {
    if hello.protocol_version != AUTH_PROTOCOL_VERSION {
        return Err(AuthError::UnsupportedVersion {
            version: hello.protocol_version,
        });
    }
    if hello.transport != expected_transport {
        return Err(AuthError::TransportMismatch {
            expected: expected_transport,
            actual: hello.transport,
        });
    }
    let expects_tls_binding = expected_transport == TransportKind::TcpTls;
    if hello.tls_binding_required != expects_tls_binding
        || (expects_tls_binding && (channel_binding.is_none() || tls_spki_sha256.is_none()))
    {
        return Err(AuthError::WrongChannelBinding);
    }
    if let Some(expected_key) = expected_node_key
        && hello.machine_public_key != expected_key
    {
        return Err(AuthError::WrongNode);
    }

    let challenge = compute_handshake_challenge(
        hello.protocol_version,
        hello.transport,
        hello.server_nonce,
        hello.server_unix_time,
        channel_binding,
        tls_spki_sha256,
    );
    let transcript =
        machine_identity_signing_message(MACHINE_IDENTITY_HANDSHAKE_DOMAIN, &challenge);
    verify_ed25519(
        hello.machine_public_key,
        &transcript,
        hello.machine_signature,
        "ServerHello.machine_signature",
    )
}

/// Verifies [`ClientAuth`] against `policy` and `host_ceiling` on `inspector-host`.
pub fn verify_client_auth(
    policy: &AuthPolicy,
    host_ceiling: &SessionGrants,
    hello: &ServerHello,
    expected_channel_binding: Option<[u8; 32]>,
    auth: &ClientAuth,
    now_unix: u64,
) -> Result<VerifiedSession, AuthError> {
    if hello.protocol_version != AUTH_PROTOCOL_VERSION {
        return Err(AuthError::UnsupportedVersion {
            version: hello.protocol_version,
        });
    }
    match (
        hello.transport,
        expected_channel_binding,
        auth.channel_binding,
    ) {
        (TransportKind::TcpTls, Some(expected), Some(actual)) if expected == actual => {}
        (TransportKind::TcpTls, _, _) => return Err(AuthError::WrongChannelBinding),
        (TransportKind::Vsock | TransportKind::Serial, None, None) => {}
        (TransportKind::Vsock | TransportKind::Serial, _, _) => {
            return Err(AuthError::WrongChannelBinding);
        }
    }

    let (principal, leaf_public_key, effective_grants) = match &auth.credential {
        ClientCredential::StaticKey {
            public_key,
            requested_grants,
        } => {
            let entry = policy
                .static_keys
                .iter()
                .find(|k| k.public_key == *public_key)
                .ok_or(AuthError::UnknownKey)?;
            if !entry.allowed_transports.contains(hello.transport.as_mask()) {
                return Err(AuthError::WrongTransport {
                    transport: hello.transport,
                });
            }
            let grants = match requested_grants {
                Some(req) => entry.grants.attenuate(req)?,
                None => entry.grants.clone(),
            };
            grants.check_subset_of(host_ceiling)?;
            (entry.label.clone(), *public_key, grants)
        }
        ClientCredential::CapabilityCert { cert, attenuations } => {
            if attenuations.len() > MAX_ATTENUATION_CHAIN_DEPTH {
                return Err(AuthError::ChainTooDeep {
                    depth: attenuations.len(),
                });
            }
            if cert.payload.version != AUTH_PROTOCOL_VERSION {
                return Err(AuthError::UnsupportedVersion {
                    version: cert.payload.version,
                });
            }
            let ca = policy
                .trusted_cas
                .iter()
                .find(|c| c.public_key == cert.ca_public_key)
                .ok_or(AuthError::UntrustedCa)?;

            // Verify CA signature over domain-separated postcard payload.
            let cert_payload_bytes =
                postcard::to_allocvec(&cert.payload).map_err(|source| AuthError::Encode {
                    context: "CapabilityCertPayload",
                    source,
                })?;
            let mut cert_msg =
                Vec::with_capacity(CAPABILITY_CERT_DOMAIN.len() + cert_payload_bytes.len());
            cert_msg.extend_from_slice(CAPABILITY_CERT_DOMAIN);
            cert_msg.extend_from_slice(&cert_payload_bytes);
            verify_ed25519(
                ca.public_key,
                &cert_msg,
                cert.ca_signature,
                "CapabilityCert.ca_signature",
            )?;

            // Check certificate validity window & CA TTL limit.
            if cert.payload.expires_at_unix < cert.payload.not_before_unix {
                return Err(AuthError::Malformed {
                    detail: "certificate expires_at precedes not_before".to_owned(),
                });
            }
            let ttl = cert.payload.expires_at_unix - cert.payload.not_before_unix;
            if ttl > ca.max_ttl_secs {
                return Err(AuthError::TtlExceeded {
                    ttl,
                    max_ttl: ca.max_ttl_secs,
                });
            }
            if now_unix < cert.payload.not_before_unix {
                return Err(AuthError::NotYetValid {
                    not_before: cert.payload.not_before_unix,
                    now: now_unix,
                });
            }
            if now_unix > cert.payload.expires_at_unix {
                return Err(AuthError::Expired {
                    expires_at: cert.payload.expires_at_unix,
                    now: now_unix,
                });
            }

            // Enforce CA transport and capability ceilings.
            if !cert
                .payload
                .allowed_transports
                .is_subset_of(ca.allowed_transports)
            {
                return Err(AuthError::CapabilityEscalation {
                    dimension: "transports",
                    detail: "certificate transports exceed CA policy".to_owned(),
                });
            }
            cert.payload.grants.check_subset_of(&ca.ceiling)?;

            // Walk offline monotonic attenuation chain.
            let mut current_key = cert.payload.subject_public_key;
            let mut current_node = cert.payload.node_public_key;
            let mut current_expiry = cert.payload.expires_at_unix;
            let mut current_grants = cert.payload.grants.clone();
            let mut current_transports = cert.payload.allowed_transports;
            let mut prev_hash = cert.commitment_hash()?;

            for link in attenuations {
                let link_payload_bytes =
                    postcard::to_allocvec(&link.payload).map_err(|source| AuthError::Encode {
                        context: "AttenuationPayload",
                        source,
                    })?;
                let mut link_msg = Vec::with_capacity(
                    ATTENUATION_LINK_DOMAIN.len() + prev_hash.len() + link_payload_bytes.len(),
                );
                link_msg.extend_from_slice(ATTENUATION_LINK_DOMAIN);
                link_msg.extend_from_slice(&prev_hash);
                link_msg.extend_from_slice(&link_payload_bytes);
                verify_ed25519(
                    current_key,
                    &link_msg,
                    link.signature,
                    "AttenuationLink.signature",
                )?;

                if link.payload.expires_at_unix > current_expiry {
                    return Err(AuthError::CapabilityEscalation {
                        dimension: "expiry",
                        detail: format!(
                            "attenuation link extends expiry {} beyond parent {}",
                            link.payload.expires_at_unix, current_expiry
                        ),
                    });
                }
                if now_unix > link.payload.expires_at_unix {
                    return Err(AuthError::Expired {
                        expires_at: link.payload.expires_at_unix,
                        now: now_unix,
                    });
                }

                match (current_node, link.payload.node_public_key) {
                    (Some(parent_node), Some(child_node)) if parent_node == child_node => {}
                    (Some(_), _) => {
                        return Err(AuthError::CapabilityEscalation {
                            dimension: "node-pin",
                            detail: "attenuation link cannot widen or alter parent node pin"
                                .to_owned(),
                        });
                    }
                    (None, narrowed) => current_node = narrowed,
                }

                if !link
                    .payload
                    .allowed_transports
                    .is_subset_of(current_transports)
                {
                    return Err(AuthError::CapabilityEscalation {
                        dimension: "transports",
                        detail: "attenuation link widens allowed transports".to_owned(),
                    });
                }
                link.payload.grants.check_subset_of(&current_grants)?;

                current_key = link.payload.delegate_public_key;
                current_expiry = link.payload.expires_at_unix;
                current_grants = link.payload.grants.clone();
                current_transports = link.payload.allowed_transports;
                prev_hash = link.commitment_hash()?;
            }

            if let Some(pinned_node) = current_node
                && pinned_node != hello.machine_public_key
            {
                return Err(AuthError::WrongNode);
            }
            if !current_transports.contains(hello.transport.as_mask()) {
                return Err(AuthError::WrongTransport {
                    transport: hello.transport,
                });
            }
            current_grants.check_subset_of(host_ceiling)?;
            (cert.payload.principal.clone(), current_key, current_grants)
        }
    };

    // Finally verify the client's live proof-of-possession signature over the
    // full session transcript (machine key, nonces, transport, channel binding,
    // and credential).
    let proof_msg = client_auth_proof_message(
        hello.machine_public_key,
        hello.server_nonce,
        auth.client_nonce,
        hello.transport,
        auth.channel_binding,
        &auth.credential,
    )?;
    verify_ed25519(
        leaf_public_key,
        &proof_msg,
        auth.proof_signature,
        "ClientAuth.proof_signature",
    )?;

    Ok(VerifiedSession {
        principal,
        leaf_public_key,
        granted: effective_grants,
    })
}

fn client_auth_proof_message(
    machine_public_key: [u8; 32],
    server_nonce: [u8; 32],
    client_nonce: [u8; 32],
    transport: TransportKind,
    channel_binding: Option<[u8; 32]>,
    credential: &ClientCredential,
) -> Result<Vec<u8>, AuthError> {
    let cred_bytes = postcard::to_allocvec(credential).map_err(|source| AuthError::Encode {
        context: "ClientCredential",
        source,
    })?;
    let mut hasher = Sha256::new();
    hasher.update(machine_public_key);
    hasher.update(server_nonce);
    hasher.update(client_nonce);
    hasher.update([transport.tag()]);
    match channel_binding {
        Some(binding) => {
            hasher.update([1u8]);
            hasher.update(binding);
        }
        None => {
            hasher.update([0u8]);
            hasher.update([0u8; 32]);
        }
    }
    hasher.update((cred_bytes.len() as u32).to_le_bytes());
    hasher.update(&cred_bytes);
    let digest = hasher.finalize();

    let mut out = Vec::with_capacity(CLIENT_AUTH_PROOF_DOMAIN.len() + 32);
    out.extend_from_slice(CLIENT_AUTH_PROOF_DOMAIN);
    out.extend_from_slice(&digest);
    Ok(out)
}

fn verify_ed25519(
    public_key: [u8; 32],
    message: &[u8],
    signature: [u8; 64],
    context: &'static str,
) -> Result<(), AuthError> {
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| AuthError::InvalidSignature { context })?;
    let sig = Signature::from_bytes(&signature);
    verifying_key
        .verify(message, &sig)
        .map_err(|_| AuthError::InvalidSignature { context })
}

/// Writes one `postcard`-encoded auth message framed with [`AUTH_FRAME_MAGIC`].
pub async fn write_auth_message<W, T>(writer: &mut W, message: &T) -> Result<(), AuthError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = postcard::to_allocvec(message).map_err(|source| AuthError::Encode {
        context: "auth frame",
        source,
    })?;
    if payload.len() > MAX_AUTH_FRAME_SIZE {
        return Err(AuthError::Malformed {
            detail: format!(
                "auth frame length {} exceeds max {}",
                payload.len(),
                MAX_AUTH_FRAME_SIZE
            ),
        });
    }
    let len = payload.len() as u32;
    let mut buf = Vec::with_capacity(AUTH_FRAME_MAGIC.len() + 4 + payload.len());
    buf.extend_from_slice(&AUTH_FRAME_MAGIC);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&payload);
    write_all(writer, &buf).await?;
    flush(writer).await
}

/// Reads one `postcard`-encoded auth message framed with [`AUTH_FRAME_MAGIC`],
/// skipping any interleaved serial console preamble bytes before the magic.
pub async fn read_auth_message<R, T>(reader: &mut R) -> Result<T, AuthError>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut matched = 0usize;
    let mut skipped = 0usize;
    loop {
        let mut byte = [0u8; 1];
        let n = std::future::poll_fn(|cx| Pin::new(&mut *reader).poll_read(cx, &mut byte))
            .await
            .map_err(|source| AuthError::Io {
                operation: "sync auth frame magic",
                source,
            })?;
        if n == 0 {
            return Err(AuthError::UnexpectedEof);
        }
        if byte[0] == AUTH_FRAME_MAGIC[matched] {
            matched += 1;
            if matched == AUTH_FRAME_MAGIC.len() {
                break;
            }
        } else {
            skipped += matched + 1;
            if skipped > MAX_SERIAL_PREAMBLE_BYTES {
                return Err(AuthError::Malformed {
                    detail: "exceeded maximum skipped preamble bytes waiting for auth frame"
                        .to_owned(),
                });
            }
            matched = usize::from(byte[0] == AUTH_FRAME_MAGIC[0]);
        }
    }

    let mut len_bytes = [0u8; 4];
    read_exact(reader, &mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > MAX_AUTH_FRAME_SIZE {
        return Err(AuthError::Malformed {
            detail: format!("auth frame length {len} exceeds max {MAX_AUTH_FRAME_SIZE}"),
        });
    }
    let mut payload = vec![0u8; len];
    read_exact(reader, &mut payload).await?;
    postcard::from_bytes(&payload).map_err(|source| AuthError::Decode {
        context: "auth frame",
        source,
    })
}

/// Runs the client side of the unified inspector authentication handshake over
/// any `AsyncRead + AsyncWrite` stream (`tcp+tls`, `vsock`, or `serial`).
pub async fn client_handshake<R, W>(
    read: &mut R,
    write: &mut W,
    transport: TransportKind,
    identity: &ClientIdentity,
    expected_node_key: Option<[u8; 32]>,
    channel_binding: Option<[u8; 32]>,
    tls_spki_sha256: Option<[u8; 32]>,
) -> Result<(ServerHello, SessionGrants, u64), AuthError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    write_auth_message(
        write,
        &ClientHello {
            protocol_version: AUTH_PROTOCOL_VERSION,
        },
    )
    .await?;

    let hello: ServerHello = read_auth_message(read).await?;
    verify_server_hello(
        &hello,
        transport,
        expected_node_key,
        channel_binding,
        tls_spki_sha256,
    )?;

    let client_nonce = random_32()?;
    let client_auth = identity.build_client_auth(&hello, channel_binding, client_nonce)?;
    write_auth_message(write, &client_auth).await?;

    let result: ServerAuthResult = read_auth_message(read).await?;
    match result {
        ServerAuthResult::Accepted {
            granted,
            session_id,
        } => Ok((hello, granted, session_id)),
        ServerAuthResult::Rejected { code, detail } => Err(AuthError::Rejected { code, detail }),
    }
}

/// Runs the server side of the unified inspector authentication handshake for
/// `vsock` and `serial` transports (and unit tests).
#[expect(
    clippy::too_many_arguments,
    reason = "handshake takes explicit transport, policy, ceiling, identity, clock, and binding inputs with zero global state"
)]
pub async fn server_handshake<R, W, F>(
    read: &mut R,
    write: &mut W,
    transport: TransportKind,
    policy: &AuthPolicy,
    host_ceiling: &SessionGrants,
    machine_public_key: [u8; 32],
    now_unix: u64,
    session_id: u64,
    channel_binding: Option<[u8; 32]>,
    tls_spki_sha256: Option<[u8; 32]>,
    sign_challenge: F,
) -> Result<VerifiedSession, AuthError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnOnce(&[u8; 32]) -> Result<[u8; 64], AuthError>,
{
    let client_hello: ClientHello = read_auth_message(read).await?;
    if client_hello.protocol_version != AUTH_PROTOCOL_VERSION {
        return Err(AuthError::UnsupportedVersion {
            version: client_hello.protocol_version,
        });
    }

    let server_nonce = random_32()?;
    let challenge = compute_handshake_challenge(
        AUTH_PROTOCOL_VERSION,
        transport,
        server_nonce,
        now_unix,
        channel_binding,
        tls_spki_sha256,
    );
    let machine_signature = sign_challenge(&challenge)?;
    let hello = ServerHello {
        protocol_version: AUTH_PROTOCOL_VERSION,
        transport,
        machine_public_key,
        server_nonce,
        server_unix_time: now_unix,
        tls_binding_required: transport == TransportKind::TcpTls,
        machine_signature,
    };
    write_auth_message(write, &hello).await?;

    let client_auth: ClientAuth = read_auth_message(read).await?;
    match verify_client_auth(
        policy,
        host_ceiling,
        &hello,
        channel_binding,
        &client_auth,
        now_unix,
    ) {
        Ok(verified) => {
            write_auth_message(
                write,
                &ServerAuthResult::Accepted {
                    granted: verified.granted.clone(),
                    session_id,
                },
            )
            .await?;
            Ok(verified)
        }
        Err(err) => {
            let _ = write_auth_message(
                write,
                &ServerAuthResult::Rejected {
                    code: err.reject_code(),
                    detail: err.to_string(),
                },
            )
            .await;
            Err(err)
        }
    }
}

/// Generates 32 cryptographically random bytes via `getrandom` (works on both
/// host OS and `wasm32-wasip3` `wasi:random`).
pub fn random_32() -> Result<[u8; 32], AuthError> {
    let mut out = [0u8; 32];
    getrandom::fill(&mut out).map_err(|err| AuthError::Io {
        operation: "getrandom",
        source: io::Error::other(err.to_string()),
    })?;
    Ok(out)
}

/// Normalizes an absolute slash-delimited path, rejecting relative paths and
/// `..` parent traversal.
#[must_use]
pub fn normalize_abs_path(raw: &str) -> Option<String> {
    if !raw.starts_with('/') {
        return None;
    }
    let mut segments = Vec::new();
    for part in raw.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return None;
        }
        segments.push(part);
    }
    if segments.is_empty() {
        Some("/".to_owned())
    } else {
        Some(format!("/{}", segments.join("/")))
    }
}

/// Returns `true` iff normalized `parent` covers normalized `child` on a strict
/// `/` path-segment boundary.
#[must_use]
pub fn path_is_prefix(parent: &str, child: &str) -> bool {
    if parent == "/" {
        return child.starts_with('/');
    }
    if child == parent {
        return true;
    }
    child
        .strip_prefix(parent)
        .is_some_and(|rest| rest.starts_with('/'))
}

async fn write_all<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut bytes: &[u8],
) -> Result<(), AuthError> {
    while !bytes.is_empty() {
        let written = std::future::poll_fn(|cx| Pin::new(&mut *writer).poll_write(cx, bytes))
            .await
            .map_err(|source| AuthError::Io {
                operation: "write auth frame",
                source,
            })?;
        if written == 0 {
            return Err(AuthError::Io {
                operation: "write auth frame",
                source: io::Error::new(io::ErrorKind::WriteZero, "zero-byte write"),
            });
        }
        bytes = &bytes[written..];
    }
    Ok(())
}

async fn flush<W: AsyncWrite + Unpin>(writer: &mut W) -> Result<(), AuthError> {
    std::future::poll_fn(|cx| Pin::new(&mut *writer).poll_flush(cx))
        .await
        .map_err(|source| AuthError::Io {
            operation: "flush auth frame",
            source,
        })
}

async fn read_exact<R: AsyncRead + Unpin>(
    reader: &mut R,
    mut buf: &mut [u8],
) -> Result<(), AuthError> {
    while !buf.is_empty() {
        let read = std::future::poll_fn(|cx| Pin::new(&mut *reader).poll_read(cx, buf))
            .await
            .map_err(|source| AuthError::Io {
                operation: "read auth frame",
                source,
            })?;
        if read == 0 {
            return Err(AuthError::UnexpectedEof);
        }
        let (_, rest) = buf.split_at_mut(read);
        buf = rest;
    }
    Ok(())
}

mod serde_bytes_64 {
    use serde::{Deserializer, Serializer, de};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = [u8; 64];

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a 64-byte Ed25519 signature")
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                v.try_into().map_err(|_| E::invalid_length(v.len(), &self))
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; 64];
                for (idx, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(idx, &self))?;
                }
                Ok(out)
            }
        }

        deserializer.deserialize_bytes(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(seed_byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed_byte; 32])
    }

    fn make_hello(
        machine_key: &SigningKey,
        transport: TransportKind,
        channel_binding: Option<[u8; 32]>,
        tls_spki_sha256: Option<[u8; 32]>,
        now_unix: u64,
    ) -> ServerHello {
        let server_nonce = [0x42; 32];
        let challenge = compute_handshake_challenge(
            AUTH_PROTOCOL_VERSION,
            transport,
            server_nonce,
            now_unix,
            channel_binding,
            tls_spki_sha256,
        );
        let machine_signature = sign_machine_identity_message(
            machine_key,
            MACHINE_IDENTITY_HANDSHAKE_DOMAIN,
            &challenge,
        );
        ServerHello {
            protocol_version: AUTH_PROTOCOL_VERSION,
            transport,
            machine_public_key: machine_key.verifying_key().to_bytes(),
            server_nonce,
            server_unix_time: now_unix,
            tls_binding_required: transport == TransportKind::TcpTls,
            machine_signature,
        }
    }

    #[test]
    fn static_key_policy_authenticates_and_enforces_attenuation_across_all_transports() {
        let machine = test_key(1);
        let client_seed = [2u8; 32];
        let client_pub = SigningKey::from_bytes(&client_seed)
            .verifying_key()
            .to_bytes();
        let ceiling = SessionGrants {
            directories: vec![DirectoryRule::new(
                "/tmp",
                "/tmp",
                DirectoryRightsMask::READ.union(DirectoryRightsMask::WRITE),
            )],
            inspect_read: Some(ScopeRule::Subtree("/core".to_owned())),
            process: ProcessRightsMask::EXEC,
            ..SessionGrants::empty()
        };
        let policy = AuthPolicy {
            version: AUTH_PROTOCOL_VERSION,
            static_keys: vec![AuthorizedStaticKey {
                label: "ops-dev".to_owned(),
                public_key: client_pub,
                grants: ceiling.clone(),
                allowed_transports: TransportMask::ALL,
            }],
            trusted_cas: Vec::new(),
        };

        for transport in [
            TransportKind::TcpTls,
            TransportKind::Vsock,
            TransportKind::Serial,
        ] {
            let binding = (transport == TransportKind::TcpTls).then_some([0xaa; 32]);
            let spki = (transport == TransportKind::TcpTls).then_some([0xbb; 32]);
            let hello = make_hello(&machine, transport, binding, spki, 1_700_000_000);
            verify_server_hello(
                &hello,
                transport,
                Some(machine.verifying_key().to_bytes()),
                binding,
                spki,
            )
            .expect("valid ServerHello must verify");

            // Narrowed request succeeds.
            let narrowed = SessionGrants {
                directories: vec![DirectoryRule::new(
                    "/tmp/work",
                    "/tmp/work",
                    DirectoryRightsMask::READ,
                )],
                inspect_read: Some(ScopeRule::Subtree("/core/http".to_owned())),
                ..SessionGrants::empty()
            };
            let identity =
                ClientIdentity::from_static_seed_with_grants(client_seed, narrowed.clone());
            let auth = identity
                .build_client_auth(&hello, binding, [0x99; 32])
                .expect("build auth");
            let verified = verify_client_auth(
                &policy,
                &SessionGrants::full_worker_ceiling(),
                &hello,
                binding,
                &auth,
                1_700_000_000,
            )
            .expect("narrowed static key must authenticate");
            assert_eq!(verified.principal, "ops-dev");
            assert_eq!(verified.granted, narrowed);

            // Escalating directory to sibling `/tmp-other` or right `EXECUTE` fails.
            let escalated = SessionGrants {
                directories: vec![DirectoryRule::new(
                    "/tmp-other",
                    "/tmp-other",
                    DirectoryRightsMask::READ,
                )],
                ..SessionGrants::empty()
            };
            let bad_id = ClientIdentity::from_static_seed_with_grants(client_seed, escalated);
            let bad_auth = bad_id
                .build_client_auth(&hello, binding, [0x98; 32])
                .expect("build escalated auth");
            let err = verify_client_auth(
                &policy,
                &SessionGrants::full_worker_ceiling(),
                &hello,
                binding,
                &bad_auth,
                1_700_000_000,
            )
            .expect_err("escalated directory must be rejected");
            assert!(matches!(err, AuthError::CapabilityEscalation { .. }));
        }
    }

    #[test]
    fn capability_cert_supports_offline_monotonic_attenuation_and_rejects_forged_expired_escalated_wrong_node_and_wrong_binding()
     {
        let machine = test_key(10);
        let other_machine = test_key(11);
        let ca = test_key(20);
        let user = test_key(30);
        let delegate = test_key(31);
        let attacker = test_key(40);
        let now = 1_700_000_500;

        let policy = AuthPolicy {
            version: AUTH_PROTOCOL_VERSION,
            static_keys: Vec::new(),
            trusted_cas: vec![TrustedAuthorityCa {
                label: "corp-ca".to_owned(),
                public_key: ca.verifying_key().to_bytes(),
                ceiling: SessionGrants::full_worker_ceiling(),
                max_ttl_secs: 3600,
                allowed_transports: TransportMask::ALL,
            }],
        };

        let cert = CapabilityCert::issue(
            &ca,
            CapabilityCertPayload {
                version: AUTH_PROTOCOL_VERSION,
                principal: "alice@helios.local".to_owned(),
                subject_public_key: user.verifying_key().to_bytes(),
                node_public_key: None,
                not_before_unix: now - 60,
                expires_at_unix: now + 600,
                grants: SessionGrants {
                    directories: vec![DirectoryRule::new(
                        "/var",
                        "/var",
                        DirectoryRightsMask::READ.union(DirectoryRightsMask::WRITE),
                    )],
                    inspect_read: Some(ScopeRule::Subtree("/core".to_owned())),
                    virtualize: true,
                    mount: MountRightsMask::MOUNT,
                    component_control: Some(ScopeRule::Subtree("/core".to_owned())),
                    ..SessionGrants::empty()
                },
                allowed_transports: TransportMask::TCP_TLS.union(TransportMask::VSOCK),
            },
        )
        .expect("issue cert");

        // Offline monotonic attenuation to a delegate key pinned to `machine` and `TcpTls`.
        let link = cert
            .attenuate(
                &[],
                &user,
                AttenuationPayload {
                    delegate_public_key: delegate.verifying_key().to_bytes(),
                    node_public_key: Some(machine.verifying_key().to_bytes()),
                    expires_at_unix: now + 300,
                    grants: SessionGrants {
                        directories: vec![DirectoryRule::new(
                            "/var/log",
                            "/var/log",
                            DirectoryRightsMask::READ,
                        )],
                        inspect_read: Some(ScopeRule::Subtree("/core/http".to_owned())),
                        ..SessionGrants::empty()
                    },
                    allowed_transports: TransportMask::TCP_TLS,
                },
            )
            .expect("attenuate cert");

        let binding = Some([0x77; 32]);
        let spki = Some([0x88; 32]);
        let hello = make_hello(&machine, TransportKind::TcpTls, binding, spki, now);

        let delegated_identity = ClientIdentity::from_capability_cert(
            delegate.to_bytes(),
            cert.clone(),
            vec![link.clone()],
        );
        let auth = delegated_identity
            .build_client_auth(&hello, binding, [0x11; 32])
            .expect("build delegated auth");
        let verified = verify_client_auth(
            &policy,
            &SessionGrants::full_worker_ceiling(),
            &hello,
            binding,
            &auth,
            now,
        )
        .expect("valid attenuated cert must authenticate");
        assert_eq!(verified.principal, "alice@helios.local");
        assert_eq!(
            verified.leaf_public_key,
            delegate.verifying_key().to_bytes()
        );
        assert!(!verified.granted.virtualize);
        assert_eq!(
            verified.granted.inspect_read,
            Some(ScopeRule::Subtree("/core/http".to_owned()))
        );

        // 1. Wrong RFC 8446 channel binding must be rejected.
        let wrong_binding_err = verify_client_auth(
            &policy,
            &SessionGrants::full_worker_ceiling(),
            &hello,
            Some([0x55; 32]),
            &auth,
            now,
        )
        .expect_err("wrong channel binding must fail");
        assert!(matches!(wrong_binding_err, AuthError::WrongChannelBinding));

        // 2. Expired credential must be rejected.
        let expired_err = verify_client_auth(
            &policy,
            &SessionGrants::full_worker_ceiling(),
            &hello,
            binding,
            &auth,
            now + 301,
        )
        .expect_err("expired link must fail");
        assert!(matches!(expired_err, AuthError::Expired { .. }));

        // 3. Wrong node (different MachineIdentity) must be rejected.
        let other_hello = make_hello(&other_machine, TransportKind::TcpTls, binding, spki, now);
        let other_auth = delegated_identity
            .build_client_auth(&other_hello, binding, [0x12; 32])
            .expect("build auth for wrong node");
        let wrong_node_err = verify_client_auth(
            &policy,
            &SessionGrants::full_worker_ceiling(),
            &other_hello,
            binding,
            &other_auth,
            now,
        )
        .expect_err("wrong node pin must fail");
        assert!(matches!(wrong_node_err, AuthError::WrongNode));

        // 4. Forged CA signature must be rejected.
        let mut forged_cert = cert.clone();
        forged_cert.ca_signature[0] ^= 0xff;
        let forged_id =
            ClientIdentity::from_capability_cert(user.to_bytes(), forged_cert, Vec::new());
        let forged_auth = forged_id
            .build_client_auth(&hello, binding, [0x13; 32])
            .expect("build forged auth");
        let forged_err = verify_client_auth(
            &policy,
            &SessionGrants::full_worker_ceiling(),
            &hello,
            binding,
            &forged_auth,
            now,
        )
        .expect_err("forged CA signature must fail");
        assert!(matches!(forged_err, AuthError::InvalidSignature { .. }));

        // 5. Escalation in attenuation link (trying to re-enable `machine_control` or widen scope) must be rejected.
        let escalated_link = cert
            .attenuate(
                &[],
                &user,
                AttenuationPayload {
                    delegate_public_key: delegate.verifying_key().to_bytes(),
                    node_public_key: None,
                    expires_at_unix: now + 300,
                    grants: SessionGrants {
                        inspect_read: Some(ScopeRule::Machine),
                        ..SessionGrants::empty()
                    },
                    allowed_transports: TransportMask::TCP_TLS,
                },
            )
            .expect("sign escalated link");
        let esc_id = ClientIdentity::from_capability_cert(
            delegate.to_bytes(),
            cert.clone(),
            vec![escalated_link],
        );
        let esc_auth = esc_id
            .build_client_auth(&hello, binding, [0x14; 32])
            .expect("build escalated link auth");
        let esc_err = verify_client_auth(
            &policy,
            &SessionGrants::full_worker_ceiling(),
            &hello,
            binding,
            &esc_auth,
            now,
        )
        .expect_err("escalated attenuation link must fail");
        assert!(matches!(esc_err, AuthError::CapabilityEscalation { .. }));

        // 6. Wrong leaf proof key (attacker signs ClientAuth without holding delegate key) must be rejected.
        let stolen_id = ClientIdentity::from_capability_cert(attacker.to_bytes(), cert, vec![link]);
        let stolen_auth = stolen_id
            .build_client_auth(&hello, binding, [0x15; 32])
            .expect("build attacker auth");
        let stolen_err = verify_client_auth(
            &policy,
            &SessionGrants::full_worker_ceiling(),
            &hello,
            binding,
            &stolen_auth,
            now,
        )
        .expect_err("wrong leaf signing key must fail");
        assert!(matches!(stolen_err, AuthError::InvalidSignature { .. }));
    }
}
