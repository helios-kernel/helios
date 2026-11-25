//! Typed error hierarchy for `helios-ops` (`thiserror` only, zero `anyhow`).

use std::io;
use std::path::PathBuf;

use helios_inspector_protocol::auth::AuthError as ProtocolAuthError;
use helios_inspector_protocol::tls::TlsError;
use helios_wit_rpc::RpcError;
use helios_wit_rpc::inspector::helios::system::{
    component_control::ControlError as ComponentControlError,
    filters::FilterError,
    instances::KillError,
    processors::{OfflineError, OnlineError},
    profiling::{ControlError, InstructionProfileError, RawProfileError},
    programs::{ExecError, ExecErrorKind},
    tracing::TargetError as TraceTargetError,
};
use helios_wit_rpc::inspector_fs::FsRpcError;

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
    #[error("remote filter for `{operation}` refused: {error:?}")]
    FilterRefused {
        operation: &'static str,
        error: FilterError,
    },
    #[error("no live instance is named `{name}`")]
    NoInstanceNamed { name: String },
    #[error("guest refused to stop instance {id}: {error:?}")]
    KillRefused { id: u64, error: KillError },
    #[error("guest refused tracing target `{target}`: {error:?}")]
    TraceTargetRefused {
        target: String,
        error: TraceTargetError,
    },
    #[error("guest refused profiling control `{operation}`: {error:?}")]
    ProfilingControlRefused {
        operation: &'static str,
        error: ControlError,
    },
    #[error("guest refused instruction profiling `{operation}`: {error:?}")]
    InstructionProfileRefused {
        operation: &'static str,
        error: InstructionProfileError,
    },
    #[error("guest refused raw profile `{operation}`: {error:?}")]
    RawProfileRefused {
        operation: &'static str,
        error: RawProfileError,
    },
    #[error("guest refused processor offline for CPU {processor}: {error:?}")]
    ProcessorOfflineRefused { processor: u32, error: OfflineError },
    #[error("guest refused processor online for CPU {processor}: {error:?}")]
    ProcessorOnlineRefused { processor: u32, error: OnlineError },
    #[error("guest refused snapshot prepare: {error:?}")]
    SnapshotRefused {
        error: helios_wit_rpc::inspector::helios::system::snapshot::SnapshotError,
    },
    #[error("component-control `{operation}` refused ({kind:?}): {detail}")]
    ComponentControlRefused {
        operation: &'static str,
        kind: helios_wit_rpc::inspector::helios::system::component_control::ControlErrorKind,
        detail: String,
    },
    #[error("program execution refused ({kind:?}): {detail}")]
    ExecRefused { kind: ExecErrorKind, detail: String },
    #[error("path `{path}` is invalid: {reason}")]
    InvalidPath { path: String, reason: &'static str },
    #[error("remote path not found: {path}")]
    NotFound { path: String },
    #[error("capability attenuation denied `{capability}` for scope `{scope}`")]
    AttenuationDenied { capability: String, scope: String },
    #[error("invalid capability grant `{spec}`: {reason}")]
    InvalidGrant { spec: String, reason: String },
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
