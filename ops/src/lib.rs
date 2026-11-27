//! Async-first Rust operations SDK for Helios nodes and fleets.
//!
//! `helios-ops` provides:
//! - Target and identity management (`targets.toml`, [`Target`], [`TargetStore`], [`CapabilityCert`], [`Attenuation`])
//! - Unified async transports (`serial://`, `vsock://`, `helios://` / `tcp://`) over `helios-inspector-protocol`
//! - [`Session`] for `/kernel/*` + component inspection, process/instance control, tracing, profiling
//!   (including standalone RAII [`SamplingSession`] and ELF/DWARF instruction-profile symbolization),
//!   program execution / streaming [`Child`], [`SnapshotHold`], remote VFS, [`ComponentsClient`],
//!   [`OciClient`], [`MountsClient`], [`BtrfsClient`], Linux containers, and [`MicroVm`] orchestration
//! - [`Fleet`] for bounded-concurrency multi-node fan-out returning [`NodeOutcome`], including
//!   [`FleetComponents`] and [`FleetOci`]
//! - [`DiagnosticBundle`] for `.tar.zst` diagnostic archive collection and export
//! - [`zenwave`] publicly re-exported as the official HTTP client (symmetric with `helios-api`)
//!
//! Zero `block_on` and zero `anyhow` appear in production code.

pub use helios_inspector_protocol;
pub use helios_oci;
pub use helios_wit_rpc;
pub use zenwave;

pub mod account;
pub mod bundle;
pub mod components;
pub mod error;
pub mod fleet;
pub mod grants;
pub mod http;
pub mod linux;
pub mod oci;
pub mod session;
pub mod storage;
pub mod symbolize;
pub mod target;
pub mod transport;
pub mod vm;

pub use account::{
    AccountAuthenticatorChoice, AccountStore, AuthenticatorSpec, CreateAccountRequest, Fido2Alg,
    Fido2Enrollment, Fido2Provider, MACOS_CODESIGN_IDENTIFIER, MacOsCodeSigningStatus,
    OpenSshFido2Provider, OperatorAccount, TOUCH_ID_KEYCHAIN_SERVICE, TouchIdProvider,
    current_macos_signing_status, session_grants_from_attenuation, validate_username,
};
pub use bundle::{BundleEntry, BundleManifest, DiagnosticBundle};
pub use components::{ComponentsClient, DynamicDirSource, DynamicSubtreeSource};
pub use error::{
    AccountError, AuthError, BundleError, HttpError, OpsError, TargetError, TransportError,
};
pub use fleet::{DEFAULT_FLEET_CONCURRENCY, Fleet, FleetComponents, FleetOci, NodeOutcome};
pub use grants::{Command, NonFsGrant, NonFsGrants, ProcessGrants};
pub use oci::{DEFAULT_REMOTE_OCI_STORE, OciClient, PullOptions};
pub use session::{
    Child, RemoteEntry, RemoteStat, SamplingSession, Session, SessionOptions, SnapshotHold,
    SpawnRequest,
};
pub use storage::{BtrfsClient, MountInfo, MountsClient, RemoteBtrfsSubvolumeBackend};
pub use symbolize::{
    KernelDebugInfo, KernelImageSymbolizer, KernelSymbols, KernelSymbolsError, LoadedKernelSymbols,
    SymbolizedAddress, SymbolizedInstructionProfile, SymbolizedSample,
    render_folded_instruction_profile, symbolize_instruction_profile,
};
pub use target::{
    Attenuation, CapabilityCert, GrantRight, Grants, IdentityProfile, Target, TargetStore,
    TargetUri,
};
pub use transport::{RpcConnection, RpcRead, RpcReader, RpcWrite, RpcWriter, SecurityMode};
pub use vm::{
    DEFAULT_VMM_BINARY, MicroVm, MicroVmBuilder, MicroVmConfig, VmClient, VmDisk, VmShare,
};
