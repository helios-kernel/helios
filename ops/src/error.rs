//! Typed error hierarchy for `helios-ops` (`thiserror` only, zero `anyhow`).

use std::io;
use std::path::PathBuf;

use helios_inspector_protocol::RpcError;
use helios_inspector_protocol::system::{
    instances::KillError,
    processors::{OfflineError, OnlineError},
    profiling::{ControlError, InstructionProfileError, RawProfileError},
    programs::{ExecError, ExecErrorKind},
    tracing::{FilterError, TargetError as TraceTargetError},
};

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
    #[error("timed out waiting for {operation}")]
    TimedOut { operation: &'static str },
    #[error("remote RPC `{operation}` failed: {source}")]
    Rpc {
        operation: &'static str,
        #[source]
        source: RpcError,
    },
    #[error("remote filter for `{operation}` refused: {source:?}")]
    FilterRefused {
        operation: &'static str,
        source: FilterError,
    },
    #[error("no live instance is named `{name}`")]
    NoInstanceNamed { name: String },
    #[error("guest refused to stop instance {id}: {source:?}")]
    KillRefused { id: u64, source: KillError },
    #[error("guest refused tracing target `{target}`: {source:?}")]
    TraceTargetRefused {
        target: String,
        source: TraceTargetError,
    },
    #[error("guest refused profiling control `{operation}`: {source:?}")]
    ProfilingControlRefused {
        operation: &'static str,
        source: ControlError,
    },
    #[error("guest refused instruction profiling `{operation}`: {source:?}")]
    InstructionProfileRefused {
        operation: &'static str,
        source: InstructionProfileError,
    },
    #[error("guest refused raw profile `{operation}`: {source:?}")]
    RawProfileRefused {
        operation: &'static str,
        source: RawProfileError,
    },
    #[error("guest refused processor offline for CPU {processor}: {source:?}")]
    ProcessorOfflineRefused {
        processor: u32,
        source: OfflineError,
    },
    #[error("guest refused processor online for CPU {processor}: {source:?}")]
    ProcessorOnlineRefused { processor: u32, source: OnlineError },
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
            _ => None,
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

/// Errors opening or driving an async transport (`serial://`, `vsock://`, `helios://`).
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
        "TLS + Ed25519 CapabilityCert handshake for `helios://{host}:{port}` is not yet implemented \
         (tracked by #1190); use explicit `tcp://{host}:{port}` for plaintext development links"
    )]
    TlsNotYetImplemented { host: String, port: u16 },
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
