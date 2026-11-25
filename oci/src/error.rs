//! Typed error hierarchy for `helios-oci` (`thiserror` only, zero `anyhow`).

use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Errors returned by [`crate::SubvolumeBackend`] implementations.
#[derive(Debug, Error)]
pub enum SubvolumeError {
    /// The target path does not reside on a mounted btrfs volume.
    #[error("path `{path}` is not on a btrfs filesystem")]
    NotBtrfs { path: PathBuf },
    /// The target path is on a btrfs volume, but is a regular directory rather than a subvolume root.
    #[error("path `{path}` is not a btrfs subvolume root")]
    NotSubvolume { path: PathBuf },
    /// Subvolume already exists at the requested path.
    #[error("subvolume already exists at `{path}`")]
    AlreadyExists { path: PathBuf },
    /// Subvolume or path was not found.
    #[error("subvolume not found at `{path}`")]
    NotFound { path: PathBuf },
    /// Caller lacks authority for the subvolume operation.
    #[error("permission denied for subvolume `{path}`: {detail}")]
    PermissionDenied { path: PathBuf, detail: String },
    /// Underlying btrfs or filesystem operation failed.
    #[error("subvolume operation `{operation}` on `{path}` failed: {detail}")]
    Backend {
        operation: &'static str,
        path: PathBuf,
        detail: String,
    },
}

/// Top-level error returned by OCI distribution, unpacking, storage, and VM rootfs helpers.
#[derive(Debug, Error)]
pub enum OciError {
    #[error("invalid OCI image reference `{reference}`: {reason}")]
    InvalidReference {
        reference: String,
        reason: &'static str,
    },
    #[error("invalid OCI digest `{digest}`: {reason}")]
    InvalidDigest {
        digest: String,
        reason: &'static str,
    },
    #[error("digest mismatch for {subject}: expected {expected}, got {actual}")]
    DigestMismatch {
        subject: String,
        expected: String,
        actual: String,
    },
    #[error("manifest index for `{reference}` has no linux/{arch} entry")]
    UnsupportedArchitecture { reference: String, arch: String },
    #[error("unsupported media type `{media_type}` for {subject}")]
    UnsupportedMediaType {
        subject: &'static str,
        media_type: String,
    },
    #[error("HTTP request `{method} {url}` failed: {detail}")]
    Http {
        method: &'static str,
        url: String,
        detail: String,
    },
    #[error("registry returned HTTP {status} for `{method} {url}`: {body}")]
    RegistryStatus {
        method: &'static str,
        url: String,
        status: u16,
        body: String,
    },
    #[error("registry authentication failed for `{url}`: {detail}")]
    Auth { url: String, detail: String },
    #[error("failed to decode OCI JSON for {subject}: {source}")]
    Json {
        subject: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to decompress {compression} layer `{digest}`: {detail}")]
    Decompress {
        compression: &'static str,
        digest: String,
        detail: String,
    },
    #[error("failed to unpack tar layer `{digest}`: {detail}")]
    Tar { digest: String, detail: String },
    #[error("layer `{digest}` contains unsafe path `{path}`: {reason}")]
    UnsafePath {
        digest: String,
        path: String,
        reason: &'static str,
    },
    #[error(
        "layer count mismatch: manifest lists {manifest_layers} layers, config lists {config_diff_ids} diff_ids"
    )]
    LayerCountMismatch {
        manifest_layers: usize,
        config_diff_ids: usize,
    },
    #[error("invalid OCI user specification `{spec}`: {reason}")]
    InvalidUser { spec: String, reason: String },
    #[error("subvolume error: {0}")]
    Subvolume(#[from] SubvolumeError),
    #[error("filesystem operation `{operation}` on `{path}` failed: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid login principal `{principal}`: {reason}")]
    InvalidPrincipal {
        principal: String,
        reason: &'static str,
    },
    #[error("invalid virtio-fs share `{tag}`: {reason}")]
    InvalidShare { tag: String, reason: &'static str },
    #[error("btrfs send stream encoding error: {detail}")]
    SendStream { detail: String },
}

pub type Result<T> = core::result::Result<T, OciError>;
