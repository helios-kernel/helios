//! Typed error hierarchy for `helios-ops` (`thiserror` only, zero `anyhow`).

use std::io;
use std::path::PathBuf;

use helios_inspector_protocol::auth::AuthError as ProtocolAuthError;
use helios_inspector_protocol::tls::TlsError;
use helios_wit_rpc::RpcError;
use helios_wit_rpc::inspector::helios::system::{
    btrfs::{BtrfsError, BtrfsErrorKind},
    component_control::{
        ControlError as ComponentControlError, ControlErrorKind as ComponentControlErrorKind,
    },
    filters::FilterError,
    instances::KillError,
    mounts::{MountError, MountErrorKind},
    processors::{OfflineError, OfflineRefusal, OnlineError},
    profiling::{ControlError, InstructionProfileError, ProfileSection, RawProfileError},
    programs::{ExecError, ExecErrorKind},
    snapshot::SnapshotError,
    tracing::TargetError as TraceTargetError,
};
use helios_wit_rpc::inspector_fs::FsRpcError;

use crate::symbolize::KernelSymbolsError;

/// Top-level error returned by [`crate::Session`], [`crate::Fleet`], and SDK helpers.
#[derive(Debug, thiserror::Error)]
pub enum OpsError {
    #[error("{0}")]
    Target(#[from] TargetError),
    #[error("{0}")]
    Transport(#[from] TransportError),
    #[error("{0}")]
    Auth(#[from] AuthError),
    #[error("{0}")]
    Account(#[from] AccountError),
    #[error("{0}")]
    Http(#[from] HttpError),
    #[error("{0}")]
    Bundle(#[from] BundleError),
    #[error("{0}")]
    Oci(#[from] helios_oci::OciError),
    #[error("{0}")]
    Fs(#[from] FsRpcError),
    #[error("timed out waiting for {operation}")]
    TimedOut { operation: &'static str },
    #[error("remote RPC `{operation}` failed: {source}")]
    Rpc {
        operation: &'static str,
        #[source]
        source: RpcError,
    },
    #[error(
        "remote filter for `{operation}` refused: {}",
        format_filter_error(error)
    )]
    FilterRefused {
        operation: &'static str,
        error: FilterError,
    },
    #[error("no live instance is named `{name}`")]
    NoInstanceNamed { name: String },
    #[error("guest refused to stop instance {id}: {}", format_kill_error(*error))]
    KillRefused { id: u64, error: KillError },
    #[error(
        "guest refused tracing target `{target}`: {}",
        format_trace_target_error(target, error)
    )]
    TraceTargetRefused {
        target: String,
        error: TraceTargetError,
    },
    #[error(
        "guest refused profiling control `{operation}`: {}",
        format_profiling_control_error(*error)
    )]
    ProfilingControlRefused {
        operation: &'static str,
        error: ControlError,
    },
    #[error(
        "guest refused instruction profiling `{operation}`: {}",
        format_instruction_profile_error(*error)
    )]
    InstructionProfileRefused {
        operation: &'static str,
        error: InstructionProfileError,
    },
    #[error(
        "guest refused raw profile `{operation}`: {}",
        format_raw_profile_error(error)
    )]
    RawProfileRefused {
        operation: &'static str,
        error: RawProfileError,
    },
    #[error(
        "guest refused processor offline for CPU {processor}: {}",
        format_offline_error(error)
    )]
    ProcessorOfflineRefused { processor: u32, error: OfflineError },
    #[error(
        "guest refused processor online for CPU {processor}: {}",
        format_online_error(error)
    )]
    ProcessorOnlineRefused { processor: u32, error: OnlineError },
    #[error("guest refused snapshot prepare: {}", format_snapshot_error(*error))]
    SnapshotRefused { error: SnapshotError },
    #[error(
        "component-control `{operation}` refused: {}",
        format_kind_detail(format_component_control_error_kind(*kind), detail)
    )]
    ComponentControlRefused {
        operation: &'static str,
        kind: ComponentControlErrorKind,
        detail: String,
    },
    #[error(
        "mount `{operation}` on `{path}` refused: {}",
        format_kind_detail(format_mount_error_kind(*kind), detail)
    )]
    MountRefused {
        operation: &'static str,
        path: String,
        kind: MountErrorKind,
        detail: String,
    },
    #[error(
        "btrfs `{operation}` on `{path}` refused: {}",
        format_kind_detail(format_btrfs_error_kind(*kind), detail)
    )]
    BtrfsRefused {
        operation: &'static str,
        path: String,
        kind: BtrfsErrorKind,
        detail: String,
    },
    #[error("{0}")]
    Symbolize(#[from] KernelSymbolsError),
    #[error(
        "program execution refused: {}",
        format_kind_detail(format_exec_error_kind(*kind), detail)
    )]
    ExecRefused { kind: ExecErrorKind, detail: String },
    #[error("child stdin stream is already closed")]
    StdinClosed,
    #[error("MicroVm configuration error: {detail}")]
    InvalidVmConfig { detail: String },
    #[error("path `{path}` is invalid: {reason}")]
    InvalidPath { path: String, reason: &'static str },
    #[error("remote path not found: {path}")]
    NotFound { path: String },
    #[error("capability attenuation denied `{capability}` for scope `{scope}`")]
    AttenuationDenied { capability: String, scope: String },
    #[error("invalid capability grant `{spec}`: {reason}")]
    InvalidGrant { spec: String, reason: String },
    #[error("invalid POSIX signal `{signal}`")]
    InvalidSignal { signal: String },
}

impl OpsError {
    /// Returns the guest kernel panic text if the failure originated from a dead guest.
    #[must_use]
    pub fn guest_panic(&self) -> Option<&str> {
        match self {
            Self::Rpc { source, .. } => source.guest_panic(),
            Self::Fs(err) => err.guest_panic(),
            _ => None,
        }
    }

    pub fn from_component_control(operation: &'static str, err: ComponentControlError) -> Self {
        Self::ComponentControlRefused {
            operation,
            kind: err.kind,
            detail: err.detail,
        }
    }

    pub fn from_mount(operation: &'static str, path: String, err: MountError) -> Self {
        Self::MountRefused {
            operation,
            path,
            kind: err.kind,
            detail: err.detail,
        }
    }

    pub fn from_btrfs(operation: &'static str, path: String, err: BtrfsError) -> Self {
        Self::BtrfsRefused {
            operation,
            path,
            kind: err.kind,
            detail: err.detail,
        }
    }
}

impl From<ExecError> for OpsError {
    fn from(error: ExecError) -> Self {
        Self::ExecRefused {
            kind: error.kind,
            detail: error.detail,
        }
    }
}

/// Errors parsing, storing, or resolving targets in `targets.toml`.
#[derive(Debug, thiserror::Error)]
pub enum TargetError {
    #[error("invalid target URI `{uri}`: {reason}")]
    InvalidUri { uri: String, reason: String },
    #[error("target `{name}` not found in {store_path}")]
    NotFound { name: String, store_path: PathBuf },
    #[error("no default target configured in {store_path} and no --target supplied")]
    NoDefaultTarget { store_path: PathBuf },
    #[error("no targets matched label selector `{selector}`")]
    NoMatchingLabels { selector: String },
    #[error("invalid label filter `{raw}`; expected `key=value`")]
    InvalidLabelFilter { raw: String },
    #[error("failed to read target store {path}: {source}")]
    ReadStore {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write target store {path}: {source}")]
    WriteStore {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse target store {path}: {source}")]
    ParseStore {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("failed to serialize target store: {source}")]
    SerializeStore {
        #[source]
        source: toml::ser::Error,
    },
}

/// Errors opening or driving an async transport (`serial://`, `vsock://`, `helios://`, `helios+tls://`).
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("failed to inspect serial device `{device}`: {source}")]
    InspectSerial {
        device: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to open serial TTY `{device}`: {source}")]
    OpenTty {
        device: String,
        #[source]
        source: serialport::Error,
    },
    #[error("failed to clone serial TTY `{device}`: {source}")]
    CloneTty {
        device: String,
        #[source]
        source: serialport::Error,
    },
    #[error("failed to connect to Unix socket `{path}`: {source}")]
    ConnectUnix {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to connect to TCP endpoint `{address}`: {source}")]
    ConnectTcp {
        address: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to register async transport `{endpoint}`: {source}")]
    RegisterAsync {
        endpoint: String,
        #[source]
        source: io::Error,
    },
    #[error("vsock transport is unsupported on this host OS (AF_VSOCK requires Linux)")]
    VsockUnsupported,
    #[error("failed to connect to vsock cid {cid} port {port}: {source}")]
    ConnectVsock {
        cid: u32,
        port: u32,
        #[source]
        source: io::Error,
    },
    #[error("failed to clone transport handle `{endpoint}`: {source}")]
    CloneHandle {
        endpoint: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to configure nonblocking transport `{endpoint}`: {source}")]
    ConfigureNonblocking {
        endpoint: String,
        #[source]
        source: io::Error,
    },
    #[error(
        "TLS + Ed25519 authentication is required for `helios://{host}:{port}`; supply an identity \
         via `--identity` or `SecurityMode::Authenticated`"
    )]
    AuthRequired { host: String, port: u16 },
    #[error(
        "authenticated connections over plain `tcp://{host}:{port}` are unsupported \
         (the inspector protocol requires TLS channel binding on TCP); use `helios://{host}:{port}`"
    )]
    PlainTcpAuthUnsupported { host: String, port: u16 },
    #[error("TLS 1.3 handshake to `{address}` failed: {source}")]
    TlsHandshake {
        address: String,
        #[source]
        source: TlsError,
    },
    #[error("Ed25519 inspector authentication handshake on `{endpoint}` failed: {source}")]
    AuthHandshake {
        endpoint: String,
        #[source]
        source: ProtocolAuthError,
    },
}

/// Errors loading or exchanging operator identities and capability certificates.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("failed to read identity file {path}: {source}")]
    ReadIdentity {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write identity file {path}: {source}")]
    WriteIdentity {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse identity file {path}: {source}")]
    ParseIdentity {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("failed to serialize identity file: {source}")]
    SerializeIdentity {
        #[source]
        source: toml::ser::Error,
    },
    #[error("identity `{name}` is invalid: {detail}")]
    InvalidIdentity { name: String, detail: String },
    #[error("authority CA at `{url}` returned HTTP {status}: {detail}")]
    AuthorityRejected {
        url: String,
        status: u16,
        detail: String,
    },
}

/// Errors creating, storing, signing with, or removing operator accounts.
#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error(
        "invalid operator username `{username}`: expected POSIX name `[a-z_][a-z0-9_-]{{0,31}}`"
    )]
    InvalidUsername { username: String },
    #[error("operator account `{username}` already exists at {path}")]
    AlreadyExists { username: String, path: PathBuf },
    #[error("operator account `{username}` not found at {path}")]
    NotFound { username: String, path: PathBuf },
    #[error("failed to read account file {path}: {source}")]
    ReadAccount {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write account file {path}: {source}")]
    WriteAccount {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to remove account file {path}: {source}")]
    RemoveAccount {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse account file {path}: {source}")]
    ParseAccount {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("failed to serialize account file: {source}")]
    SerializeAccount {
        #[source]
        source: toml::ser::Error,
    },
    #[error("invalid account `{username}` configuration: {detail}")]
    InvalidAccount { username: String, detail: String },
    #[error("Touch ID is only supported on macOS; use `--fido2` for hardware security keys")]
    TouchIdUnsupported,
    #[error("Touch ID authentication failed: {detail}")]
    TouchIdFailed { detail: String },
    #[error("macOS Keychain operation `{operation}` failed: {detail}")]
    Keychain {
        operation: &'static str,
        detail: String,
    },
    #[error("FIDO2 operation `{operation}` failed: {detail}")]
    Fido2 {
        operation: &'static str,
        detail: String,
    },
    #[error("account verification failed: {source}")]
    Protocol {
        #[from]
        source: ProtocolAuthError,
    },
}

/// Errors returned by [`crate::http`] (`zenwave`).
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("HTTP request `{method} {url}` failed: {detail}")]
    Request {
        method: String,
        url: String,
        detail: String,
    },
    #[error("HTTP `{method} {url}` returned status {status}: {body}")]
    Status {
        method: String,
        url: String,
        status: u16,
        body: String,
    },
    #[error("failed to encode JSON payload: {source}")]
    EncodeJson {
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to decode JSON response from `{url}`: {source}")]
    DecodeJson {
        url: String,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors creating or reading a `.tar.zst` [`crate::DiagnosticBundle`].
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("failed to create bundle file {path}: {source}")]
    CreateFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to open bundle file {path}: {source}")]
    OpenFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to encode bundle metadata JSON: {source}")]
    EncodeJson {
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to write tar.zst archive {path}: {source}")]
    WriteArchive {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to read tar.zst archive {path}: {source}")]
    ReadArchive {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("background archive task panicked: {detail}")]
    TaskJoin { detail: String },
}

pub(crate) fn format_kind_detail(kind: &str, detail: &str) -> String {
    let detail = detail.trim();
    if detail.is_empty() || detail.eq_ignore_ascii_case(kind) {
        kind.to_owned()
    } else if detail
        .get(..kind.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(kind))
        && detail[kind.len()..]
            .chars()
            .next()
            .is_none_or(|c| matches!(c, ':' | ';' | ',' | ' ' | '('))
    {
        detail.to_owned()
    } else {
        format!("{kind}: {detail}")
    }
}

pub(crate) fn format_filter_error(error: &FilterError) -> String {
    match error {
        FilterError::TooManyPrefixes(limit) => {
            format!("too many filter prefixes (maximum {limit})")
        }
        FilterError::PrefixTooLong(limit) => {
            format!("filter prefix too long (maximum {limit} bytes)")
        }
    }
}

pub(crate) const fn format_kill_error(error: KillError) -> &'static str {
    match error {
        KillError::NoSuchInstance => "no such instance",
        KillError::AlreadyStopping => "instance is already stopping",
        KillError::Denied => "permission denied",
    }
}

pub(crate) fn format_trace_target_error(target: &str, error: &TraceTargetError) -> String {
    match error {
        TraceTargetError::UnknownTarget(name) => {
            let trimmed = name.trim();
            if trimmed.is_empty() || trimmed == target {
                "unknown tracing target".to_owned()
            } else {
                format!("unknown tracing target `{trimmed}`")
            }
        }
        TraceTargetError::Denied => "permission denied".to_owned(),
    }
}

pub(crate) const fn format_profiling_control_error(error: ControlError) -> &'static str {
    match error {
        ControlError::Denied => "permission denied",
    }
}

pub(crate) const fn format_instruction_profile_error(
    error: InstructionProfileError,
) -> &'static str {
    match error {
        InstructionProfileError::NotCaptured => {
            "instruction sampling is not supported on this backend"
        }
        InstructionProfileError::Denied => "permission denied",
        InstructionProfileError::Busy => "another instruction sampling session is already active",
    }
}

const fn format_profile_section(section: ProfileSection) -> &'static str {
    match section {
        ProfileSection::Counters => "counters",
        ProfileSection::Data => "data",
        ProfileSection::Names => "names",
    }
}

pub(crate) fn format_raw_profile_error(error: &RawProfileError) -> String {
    match error {
        RawProfileError::NotInstrumented => {
            "kernel is not built with profile instrumentation".to_owned()
        }
        RawProfileError::UnsupportedVersion(version) => {
            format!("unsupported raw profile version {version}")
        }
        RawProfileError::MalformedSection(section) => {
            format!(
                "malformed {} profile section",
                format_profile_section(*section)
            )
        }
        RawProfileError::OutOfRange(length) => {
            format!("offset past end of raw profile ({length} bytes)")
        }
        RawProfileError::ReadTooLarge(limit) => {
            format!("read exceeds maximum window ({limit} bytes)")
        }
        RawProfileError::Denied => "permission denied".to_owned(),
    }
}

fn format_offline_refusal(refusal: &OfflineRefusal) -> String {
    match refusal {
        OfflineRefusal::PinnedTasks(1) => {
            "1 pinned task is still running on this processor".to_owned()
        }
        OfflineRefusal::PinnedTasks(count) => {
            format!("{count} pinned tasks are still running on this processor")
        }
        OfflineRefusal::NetworkStarting => "network interface is still starting".to_owned(),
    }
}

pub(crate) fn format_offline_error(error: &OfflineError) -> String {
    match error {
        OfflineError::NotPossible(possible) => {
            format!("processor out of range ({possible} possible)")
        }
        OfflineError::Bootstrap => "cannot take bootstrap processor offline".to_owned(),
        OfflineError::CurrentProcessor => {
            "cannot take the currently executing processor offline".to_owned()
        }
        OfflineError::NotOnline => "processor is not online".to_owned(),
        OfflineError::Refused(refusal) => format_offline_refusal(refusal),
        OfflineError::Denied => "permission denied".to_owned(),
    }
}

pub(crate) fn format_online_error(error: &OnlineError) -> String {
    match error {
        OnlineError::NotPossible(possible) => {
            format!("processor out of range ({possible} possible)")
        }
        OnlineError::NotOffline => "processor is already online".to_owned(),
        OnlineError::Denied => "permission denied".to_owned(),
    }
}

pub(crate) const fn format_snapshot_error(error: SnapshotError) -> &'static str {
    match error {
        SnapshotError::Denied => "permission denied",
        SnapshotError::Busy => "another snapshot hold is already active",
    }
}

pub(crate) const fn format_component_control_error_kind(
    kind: ComponentControlErrorKind,
) -> &'static str {
    match kind {
        ComponentControlErrorKind::PermissionDenied => "permission denied",
        ComponentControlErrorKind::NotFound => "not found",
        ComponentControlErrorKind::AlreadyExists => "already exists",
        ComponentControlErrorKind::InvalidArgument => "invalid argument",
        ComponentControlErrorKind::Unavailable => "unavailable",
        ComponentControlErrorKind::Internal => "internal error",
    }
}

pub(crate) const fn format_mount_error_kind(kind: MountErrorKind) -> &'static str {
    match kind {
        MountErrorKind::PermissionDenied => "permission denied",
        MountErrorKind::InvalidPoint => "invalid mount point",
        MountErrorKind::AlreadyMounted => "already mounted",
        MountErrorKind::NotMounted => "not mounted",
        MountErrorKind::Busy => "mount point is busy",
        MountErrorKind::TableFull => "mount table is full",
        MountErrorKind::Unavailable => "mount source unavailable",
        MountErrorKind::InvalidPath => "invalid path",
        MountErrorKind::InvalidFilesystem => "invalid filesystem",
        MountErrorKind::Io => "I/O error",
        MountErrorKind::InvalidOption => "invalid mount option",
    }
}

pub(crate) const fn format_btrfs_error_kind(kind: BtrfsErrorKind) -> &'static str {
    match kind {
        BtrfsErrorKind::PermissionDenied => "permission denied",
        BtrfsErrorKind::NotBtrfs => "not a btrfs filesystem",
        BtrfsErrorKind::NotFound => "not found",
        BtrfsErrorKind::AlreadyExists => "already exists",
        BtrfsErrorKind::ReadOnlyFilesystem => "read-only filesystem",
        BtrfsErrorKind::NotDirectory => "not a directory",
        BtrfsErrorKind::IsDirectory => "is a directory",
        BtrfsErrorKind::NotEmpty => "directory not empty",
        BtrfsErrorKind::NoSpace => "no space left on device",
        BtrfsErrorKind::InvalidArgument => "invalid argument",
        BtrfsErrorKind::CrossDevice => "cross-device operation not supported",
        BtrfsErrorKind::Busy => "resource busy",
        BtrfsErrorKind::Io => "I/O error",
        BtrfsErrorKind::NotSubvolume => "not a subvolume",
        BtrfsErrorKind::ReadOnlySubvolume => "subvolume is read-only",
        BtrfsErrorKind::SubvolumeNotReadOnly => "subvolume is not read-only",
        BtrfsErrorKind::SubvolumeNotEmpty => "subvolume is not empty",
        BtrfsErrorKind::DefaultSubvolume => "cannot modify default subvolume",
        BtrfsErrorKind::QuotaNotEnabled => "quotas are not enabled",
        BtrfsErrorKind::QuotaAlreadyEnabled => "quotas are already enabled",
        BtrfsErrorKind::QuotaExceeded => "quota exceeded",
        BtrfsErrorKind::QgroupNotFound => "quota group not found",
        BtrfsErrorKind::QgroupExists => "quota group already exists",
        BtrfsErrorKind::QgroupInvalidRelation => "invalid quota group relation",
        BtrfsErrorKind::DeviceNotFound => "device not found",
        BtrfsErrorKind::LastDevice => "cannot remove the last device",
        BtrfsErrorKind::DeviceTooSmall => "device is too small",
        BtrfsErrorKind::InvalidStream => "invalid send stream",
        BtrfsErrorKind::Alignment => "unaligned extent range",
        BtrfsErrorKind::Overlap => "overlapping extent range",
        BtrfsErrorKind::ChecksumPolicyMismatch => "checksum policy mismatch",
        BtrfsErrorKind::CloneSourceOutOfRange => "clone source out of range",
    }
}

pub(crate) const fn format_exec_error_kind(kind: ExecErrorKind) -> &'static str {
    match kind {
        ExecErrorKind::InvalidBinary => "invalid binary",
        ExecErrorKind::MissingEntry => "missing entry point",
        ExecErrorKind::UnsupportedImport => "unsupported import",
        ExecErrorKind::InvalidSignature => "invalid signature",
        ExecErrorKind::InvalidPath => "invalid path",
        ExecErrorKind::PermissionDenied => "permission denied",
        ExecErrorKind::InvalidHint => "invalid hint",
        ExecErrorKind::OutOfMemory => "out of memory",
        ExecErrorKind::Unavailable => "unavailable",
        ExecErrorKind::Internal => "internal error",
        ExecErrorKind::NotFound => "not found",
        ExecErrorKind::Io => "I/O error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_no_pascal_case_debug_tokens(message: &str) {
        let forbidden = [
            "TooManyPrefixes",
            "PrefixTooLong",
            "NoSuchInstance",
            "AlreadyStopping",
            "UnknownTarget",
            "NotCaptured",
            "NotInstrumented",
            "UnsupportedVersion",
            "MalformedSection",
            "OutOfRange",
            "ReadTooLarge",
            "NotPossible",
            "CurrentProcessor",
            "NotOnline",
            "PinnedTasks",
            "NetworkStarting",
            "NotOffline",
            "PermissionDenied",
            "NotFound",
            "AlreadyExists",
            "InvalidArgument",
            "InvalidPoint",
            "AlreadyMounted",
            "NotMounted",
            "TableFull",
            "InvalidPath",
            "InvalidFilesystem",
            "InvalidOption",
            "NotBtrfs",
            "ReadOnlyFilesystem",
            "NotDirectory",
            "IsDirectory",
            "NotEmpty",
            "NoSpace",
            "CrossDevice",
            "NotSubvolume",
            "ReadOnlySubvolume",
            "SubvolumeNotReadOnly",
            "SubvolumeNotEmpty",
            "DefaultSubvolume",
            "QuotaNotEnabled",
            "QuotaAlreadyEnabled",
            "QuotaExceeded",
            "QgroupNotFound",
            "QgroupExists",
            "QgroupInvalidRelation",
            "DeviceNotFound",
            "LastDevice",
            "DeviceTooSmall",
            "InvalidStream",
            "ChecksumPolicyMismatch",
            "CloneSourceOutOfRange",
            "InvalidBinary",
            "MissingEntry",
            "UnsupportedImport",
            "InvalidSignature",
            "InvalidHint",
            "OutOfMemory",
            "Denied",
            "Busy",
            "Unavailable",
            "Internal",
            "Bootstrap",
            "Refused(",
            "Counters",
            "Names",
            "Alignment",
            "Overlap",
        ];
        for token in forbidden {
            assert!(
                !message.contains(token),
                "error display leaked Debug token `{token}` in: {message}"
            );
        }
    }

    #[test]
    fn wit_refusal_errors_format_as_human_prose() {
        let cases: Vec<(OpsError, &str)> = vec![
            (
                OpsError::FilterRefused {
                    operation: "tracing.recent",
                    error: FilterError::TooManyPrefixes(8),
                },
                "too many filter prefixes (maximum 8)",
            ),
            (
                OpsError::FilterRefused {
                    operation: "tracing.recent",
                    error: FilterError::PrefixTooLong(128),
                },
                "filter prefix too long (maximum 128 bytes)",
            ),
            (
                OpsError::KillRefused {
                    id: 42,
                    error: KillError::NoSuchInstance,
                },
                "no such instance",
            ),
            (
                OpsError::KillRefused {
                    id: 42,
                    error: KillError::AlreadyStopping,
                },
                "instance is already stopping",
            ),
            (
                OpsError::KillRefused {
                    id: 42,
                    error: KillError::Denied,
                },
                "permission denied",
            ),
            (
                OpsError::TraceTargetRefused {
                    target: "helios_kernel::exec".to_owned(),
                    error: TraceTargetError::UnknownTarget("helios_kernel::exec".to_owned()),
                },
                "guest refused tracing target `helios_kernel::exec`: unknown tracing target",
            ),
            (
                OpsError::TraceTargetRefused {
                    target: "helios_kernel::exec".to_owned(),
                    error: TraceTargetError::Denied,
                },
                "permission denied",
            ),
            (
                OpsError::ProfilingControlRefused {
                    operation: "set-enabled",
                    error: ControlError::Denied,
                },
                "permission denied",
            ),
            (
                OpsError::InstructionProfileRefused {
                    operation: "start",
                    error: InstructionProfileError::NotCaptured,
                },
                "instruction sampling is not supported on this backend",
            ),
            (
                OpsError::InstructionProfileRefused {
                    operation: "start",
                    error: InstructionProfileError::Busy,
                },
                "another instruction sampling session is already active",
            ),
            (
                OpsError::RawProfileRefused {
                    operation: "read",
                    error: RawProfileError::NotInstrumented,
                },
                "kernel is not built with profile instrumentation",
            ),
            (
                OpsError::RawProfileRefused {
                    operation: "read",
                    error: RawProfileError::UnsupportedVersion(99),
                },
                "unsupported raw profile version 99",
            ),
            (
                OpsError::RawProfileRefused {
                    operation: "read",
                    error: RawProfileError::MalformedSection(ProfileSection::Counters),
                },
                "malformed counters profile section",
            ),
            (
                OpsError::RawProfileRefused {
                    operation: "read",
                    error: RawProfileError::OutOfRange(4096),
                },
                "offset past end of raw profile (4096 bytes)",
            ),
            (
                OpsError::RawProfileRefused {
                    operation: "read",
                    error: RawProfileError::ReadTooLarge(65536),
                },
                "read exceeds maximum window (65536 bytes)",
            ),
            (
                OpsError::ProcessorOfflineRefused {
                    processor: 3,
                    error: OfflineError::NotPossible(2),
                },
                "processor out of range (2 possible)",
            ),
            (
                OpsError::ProcessorOfflineRefused {
                    processor: 0,
                    error: OfflineError::Bootstrap,
                },
                "cannot take bootstrap processor offline",
            ),
            (
                OpsError::ProcessorOfflineRefused {
                    processor: 1,
                    error: OfflineError::CurrentProcessor,
                },
                "cannot take the currently executing processor offline",
            ),
            (
                OpsError::ProcessorOfflineRefused {
                    processor: 1,
                    error: OfflineError::NotOnline,
                },
                "processor is not online",
            ),
            (
                OpsError::ProcessorOfflineRefused {
                    processor: 1,
                    error: OfflineError::Refused(OfflineRefusal::PinnedTasks(2)),
                },
                "2 pinned tasks are still running on this processor",
            ),
            (
                OpsError::ProcessorOfflineRefused {
                    processor: 1,
                    error: OfflineError::Refused(OfflineRefusal::NetworkStarting),
                },
                "network interface is still starting",
            ),
            (
                OpsError::ProcessorOnlineRefused {
                    processor: 5,
                    error: OnlineError::NotPossible(4),
                },
                "processor out of range (4 possible)",
            ),
            (
                OpsError::ProcessorOnlineRefused {
                    processor: 1,
                    error: OnlineError::NotOffline,
                },
                "processor is already online",
            ),
            (
                OpsError::SnapshotRefused {
                    error: SnapshotError::Busy,
                },
                "another snapshot hold is already active",
            ),
            (
                OpsError::ComponentControlRefused {
                    operation: "start",
                    kind: ComponentControlErrorKind::NotFound,
                    detail: "no component at /core/missing".to_owned(),
                },
                "component-control `start` refused: not found: no component at /core/missing",
            ),
            (
                OpsError::ComponentControlRefused {
                    operation: "start",
                    kind: ComponentControlErrorKind::PermissionDenied,
                    detail: "permission denied".to_owned(),
                },
                "component-control `start` refused: permission denied",
            ),
            (
                OpsError::MountRefused {
                    operation: "mount",
                    path: "/data".to_owned(),
                    kind: MountErrorKind::AlreadyMounted,
                    detail: String::new(),
                },
                "mount `mount` on `/data` refused: already mounted",
            ),
            (
                OpsError::BtrfsRefused {
                    operation: "delete-subvolume",
                    path: "/data/sub".to_owned(),
                    kind: BtrfsErrorKind::SubvolumeNotEmpty,
                    detail: "nested subvolumes remain".to_owned(),
                },
                "btrfs `delete-subvolume` on `/data/sub` refused: subvolume is not empty: nested subvolumes remain",
            ),
            (
                OpsError::ExecRefused {
                    kind: ExecErrorKind::InvalidBinary,
                    detail: "bad wasm magic".to_owned(),
                },
                "program execution refused: invalid binary: bad wasm magic",
            ),
        ];

        for (err, expected_substring) in cases {
            let rendered = err.to_string();
            assert_no_pascal_case_debug_tokens(&rendered);
            assert!(
                rendered.contains(expected_substring),
                "expected `{expected_substring}` in `{rendered}`"
            );
        }

        // Verify duplicate target name is not repeated in TraceTargetRefused.
        let dup_target = OpsError::TraceTargetRefused {
            target: "helios_kernel::net".to_owned(),
            error: TraceTargetError::UnknownTarget("helios_kernel::net".to_owned()),
        }
        .to_string();
        assert_eq!(
            dup_target,
            "guest refused tracing target `helios_kernel::net`: unknown tracing target"
        );

        // Verify duplicate kind prefix in detail is not repeated.
        let dup_detail = OpsError::MountRefused {
            operation: "mount",
            path: "/data".to_owned(),
            kind: MountErrorKind::NotMounted,
            detail: "not mounted: /data".to_owned(),
        }
        .to_string();
        assert_eq!(
            dup_detail,
            "mount `mount` on `/data` refused: not mounted: /data"
        );
    }
}
