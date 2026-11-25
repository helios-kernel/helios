#![cfg_attr(target_os = "wasi", feature(wasi_ext))]

//! Pure user-space OCI Image & Distribution library for Helios.
//!
//! Compiles cleanly for both `wasm32-wasip3` (`helios-api`) and host `std` (`helios-ops`)
//! with zero `block_on` in production paths, zero `anyhow`, and zero OCI Runtime Spec
//! (`runc`) compatibility layer:
//! - [`RegistryClient`] speaks the OCI Distribution Spec v2 over [`zenwave`] with
//!   Bearer/Basic authentication (`WWW-Authenticate` challenge parsing), multi-arch
//!   manifest index resolution (`x86_64` / `aarch64`), SHA-256 digest verification,
//!   and streaming gzip/zstd layer decompression.
//! - [`ImageStore`] materializes layers content-addressed by `chain-id` into read-only
//!   `btrfs` subvolumes (via [`SubvolumeBackend`], with full `.wh.*` / `.wh..wh..opq`
//!   whiteouts, Unix `uid`/`gid`/`mode`/suid/sgid, and PAX `SCHILY.xattr.*` capabilities,
//!   falling back to read-only directories when running without a `btrfs` disk).
//! - [`DefaultImageStore`] stores per-user persistent shell default Linux image
//!   preferences keyed by authenticated login identity.
//! - [`vm::OciVmRootfs`] is an optional thin user-space adapter layering an ephemeral
//!   writable overlay over a pulled OCI image for custom `MicroVm`s over `virtio-fs`.

pub use zenwave;

pub mod auth;
pub mod btrfs_send;
pub mod decompress;
pub mod error;
pub mod prefs;
pub mod reference;
pub mod registry;
pub mod spec;
pub mod store;
pub mod unpack;
pub mod vm;

pub use auth::{AuthChallenge, BearerChallenge, RegistryAuth, parse_www_authenticate};
pub use error::{OciError, Result, SubvolumeError};
pub use prefs::{DefaultImageStore, UserDefaultImage};
pub use reference::{DEFAULT_REGISTRY, Digest, ImageReference, ReferenceSelector};
pub use registry::{RegistryClient, ResolvedManifest};
pub use spec::{
    Arch, Descriptor, ImageConfig, ImageIndex, ImageManifest, ImageRuntimeConfig, LayerCompression,
    ManifestDocument, Platform, ResolvedUser, RootFs, media_type,
};
pub use store::{DirectoryBackend, ImageStore, PulledImage, SubvolumeBackend, SubvolumeMeta};
pub use unpack::{EntryUnixMetadata, LayerMetadataIndex, NodeKind};
pub use vm::{DEFAULT_OCI_VM_CMDLINE, OciVmRootfs, ROOTFS_TAG, VmHostShare};
