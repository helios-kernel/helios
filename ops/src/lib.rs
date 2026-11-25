//! Async-first Rust operations SDK for Helios nodes and fleets.
//!
//! `helios-ops` provides:
//! - Target and identity management (`targets.toml`, [`Target`], [`TargetStore`], [`CapabilityCert`], [`Attenuation`])
//! - Unified async transports (`serial://`, `vsock://`, `helios://` / `tcp://`) over `helios-inspector-protocol`
//! - [`Session`] for `/kernel/*` + component inspection, process/instance control, tracing, profiling,
//!   program execution / streaming [`Child`], [`SnapshotHold`], and remote VFS operations
//! - [`Fleet`] for bounded-concurrency multi-node fan-out returning [`NodeOutcome`]
//! - [`DiagnosticBundle`] for `.tar.zst` diagnostic archive collection and export
//! - [`zenwave`] publicly re-exported as the official HTTP client (symmetric with `helios-api`)
//!
//! Zero `block_on` and zero `anyhow` appear in production code.

pub use helios_inspector_protocol;
pub use helios_oci;
pub use helios_wit_rpc;
pub use zenwave;

pub mod bundle;
pub mod error;
pub mod fleet;
pub mod grants;
pub mod http;
pub mod linux;
pub mod session;
pub mod target;
pub mod transport;

pub use bundle::{BundleEntry, BundleManifest, DiagnosticBundle};
pub use error::{AuthError, BundleError, HttpError, OpsError, TargetError, TransportError};
pub use fleet::{DEFAULT_FLEET_CONCURRENCY, Fleet, NodeOutcome};
pub use grants::{Command, NonFsGrant, NonFsGrants, ProcessGrants};
pub use session::{
    Child, RemoteEntry, RemoteStat, Session, SessionOptions, SnapshotHold, SpawnRequest,
};
pub use target::{
    Attenuation, CapabilityCert, GrantRight, Grants, IdentityProfile, Target, TargetStore,
    TargetUri,
};
pub use transport::{RpcConnection, RpcRead, RpcReader, RpcWrite, RpcWriter, SecurityMode};
