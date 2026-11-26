//! Atomic compressed hibernate image: wire format, authentication,
//! verification, and snapshot capture.
//!
//! # Security contract
//!
//! - **Authentication key provenance:** Images are authenticated with
//!   [`crate::HibernateAuthKey`] (HMAC-SHA256 derived via HKDF-SHA256 under
//!   [`crate::HIBERNATE_AUTH_INFO`] from the TPM-sealed machine seed). A boot
//!   running on an ephemeral seed has no `HibernateAuthKey`, and snapshot
//!   creation refuses it with [`HibernateError::NoAuthenticationKey`].
//! - **Pre-MAC zero-allocation decoding:** Header decoding checks minimum
//!   length, magic, version, and the constant-time HMAC-SHA256 tag over the
//!   fixed 4096-byte header **before** trusting any count, offset, or length
//!   field and **before** performing any heap allocation.
//! - **Bounded decompression:** Every chunk descriptor is covered by the
//!   header's `chunk_table_sha256`, and every compressed chunk's SHA-256 is
//!   verified before handing it to `zrip` with an exact `uncompressed_len`
//!   limit.
//! - **Identity binding:** Every field of [`HibernateIdentity`] (kernel
//!   immutable sections, boot payload digest & physical placement, firmware
//!   memory map, processor count, device inventory, and negotiated device
//!   features) is checked individually on decode, returning a distinct typed
//!   error on mismatch.

pub mod format;
pub mod snapshot;
pub mod storage;
pub mod verify;

#[cfg(test)]
mod tests;

pub use format::{
    CHUNK_DESCRIPTOR_BYTES, ChunkDescriptor, DEFAULT_CHUNK_FRAMES,
    DEFAULT_HIBERNATE_COMPRESSION_LEVEL, DeviceFeatureRecord, FORMAT_VERSION, HEADER_BYTES,
    HEADER_MAC_BYTES, HEADER_MAC_OFFSET, HEADER_MAGIC, HibernateHeader, HibernateIdentity,
    MAX_CHUNKS, hash_device_inventory, hash_firmware_memory_map, hash_negotiated_features,
};
pub use snapshot::{
    AtomicSnapshotParams, CapturedSnapshot, EncodeParams, FrameRun, ReservationWriter,
    SnapshotConfig, SnapshotOutcome, SnapshotSink, capture_atomic_snapshot,
    collect_snapshot_physical_runs, encode_snapshot, normalize_physical_runs,
};
pub use storage::{
    HIBERNATE_HEADER_SECTORS, HIBERNATE_SECTOR_BYTES, HibernateDeviceController,
    HibernateDeviceError, HibernateOutcome, HibernateStorage, HibernateStorageError,
    VirtioBlockHibernateStorage, hibernate_to_disk, hibernate_to_disk_with_power_off,
    invalidate_hibernate_header, required_disk_bytes, validate_sector_size, write_image_to_storage,
};
pub use verify::{
    VerifiedHibernateImage, decode_image_into, verify_identity, verify_image_header_and_table,
};

use helios_hal::cpu::SnapshotUnsupported;
use thiserror::Error;

use crate::FreezeError;

/// Typed errors returned by hibernate snapshot capture and image decoding.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum HibernateError {
    /// The boot ran without a TPM-sealed signing seed (`SeedSource::Ephemeral`),
    /// so no [`crate::HibernateAuthKey`] exists.
    #[error("hibernate refused: no TPM-sealed authentication key is available for this boot")]
    NoAuthenticationKey,

    /// The kernel was booted without [`helios_hal::boot::BootMemoryMetadata`].
    #[error("hibernate refused: boot memory metadata is unavailable")]
    MissingBootMemoryMetadata,

    /// Freezing the machine failed before snapshot capture could begin.
    #[error("failed to freeze machine for hibernate snapshot: {0}")]
    Freeze(#[from] FreezeError),

    /// The CPU backend does not support capturing BSP snapshot state.
    #[error(transparent)]
    SnapshotUnsupported(#[from] SnapshotUnsupported),

    /// Pre-freeze frame reservation ran out of capacity while compressing the
    /// snapshot; the machine was thawed and all reserved frames were released.
    #[error(
        "hibernate reservation exhausted: needed {needed_bytes} bytes, reserved {capacity_bytes} bytes"
    )]
    ReservationExhausted {
        needed_bytes: usize,
        capacity_bytes: usize,
    },

    /// Pre-freeze frame reservation could not obtain the requested capacity.
    #[error(
        "insufficient free user memory for hibernate reservation: requested {requested_bytes} bytes, available {available_bytes} bytes"
    )]
    ReservationUnavailable {
        requested_bytes: usize,
        available_bytes: usize,
    },

    /// Compression failed inside `zrip`.
    #[error("failed to compress hibernate chunk {chunk_index}: {detail}")]
    CompressFailed {
        chunk_index: u32,
        detail: &'static str,
    },

    /// Image buffer is shorter than the fixed 4096-byte header.
    #[error("truncated hibernate header: got {actual} bytes, expected at least {expected}")]
    TruncatedHeader { actual: usize, expected: usize },

    /// Header magic did not match [`HEADER_MAGIC`].
    #[error("invalid hibernate image magic")]
    InvalidMagic,

    /// Header format version is unsupported.
    #[error("unsupported hibernate image version {version}")]
    UnsupportedVersion { version: u32 },

    /// Header HMAC-SHA256 failed constant-time verification.
    #[error("hibernate header HMAC-SHA256 verification failed")]
    InvalidMac,

    /// Header contained an invalid or unsupported frame size, chunk size,
    /// architecture tag, or BSP context length.
    #[error("invalid hibernate header field: {reason}")]
    InvalidHeaderField { reason: &'static str },

    /// Image claims more frames than the target machine possesses, or an
    /// out-of-range physical frame index.
    #[error(
        "hibernate image claims {image_frames} frames, exceeding machine ceiling of {machine_frames} frames"
    )]
    FrameCountExceedsMachine {
        image_frames: u64,
        machine_frames: u64,
    },

    /// Chunk table offset/length exceeds the image buffer or overflows.
    #[error("truncated or out-of-bounds hibernate chunk table")]
    TruncatedChunkTable,

    /// Header layout fields are inconsistent or overflow.
    #[error("invalid hibernate image layout: {reason}")]
    InvalidLayout { reason: &'static str },

    /// The header's stored `identity_sha256` does not match the digest of its
    /// structured identity fields.
    #[error("hibernate header identity digest does not match its identity fields")]
    IdentityDigestMismatch,

    /// Kernel immutable `.text` section range or SHA-256 differs.
    #[error("hibernate identity mismatch: kernel .text section differs")]
    KernelTextMismatch,

    /// Kernel immutable `.rodata` section range or SHA-256 differs.
    #[error("hibernate identity mismatch: kernel .rodata section differs")]
    KernelRodataMismatch,

    /// Boot payload SHA-256 digest differs.
    #[error("hibernate identity mismatch: boot payload SHA-256 digest differs")]
    BootPayloadDigestMismatch,

    /// Boot payload physical address or length differs.
    #[error("hibernate identity mismatch: boot payload physical address or length differs")]
    BootPayloadAddressMismatch,

    /// Firmware memory map entry count or digest differs.
    #[error("hibernate identity mismatch: firmware memory map differs")]
    FirmwareMemoryMapMismatch,

    /// Configured processor count differs.
    #[error(
        "hibernate identity mismatch: processor count differs (image={image}, machine={machine})"
    )]
    ProcessorCountMismatch { image: u32, machine: u32 },

    /// Device inventory or DMA model differs.
    #[error("hibernate identity mismatch: device inventory differs")]
    DeviceInventoryMismatch,

    /// Negotiated device feature set differs.
    #[error("hibernate identity mismatch: negotiated device features differ")]
    NegotiatedFeaturesMismatch,

    /// Chunk table bytes did not match `header.chunk_table_sha256`.
    #[error("hibernate chunk table SHA-256 mismatch")]
    ChunkTableChecksumMismatch,

    /// Chunk descriptor fields failed validation.
    #[error("invalid chunk descriptor {chunk_index}: {reason}")]
    InvalidChunkDescriptor {
        chunk_index: u32,
        reason: &'static str,
    },

    /// Compressed chunk bytes did not match `descriptor.sha256`.
    #[error("hibernate chunk {chunk_index} SHA-256 checksum mismatch")]
    ChunkChecksumMismatch { chunk_index: u32 },

    /// `zrip` failed to decompress a chunk within its declared limit.
    #[error("hibernate chunk {chunk_index} decompression failed")]
    DecompressFailed { chunk_index: u32 },

    /// Decompressed chunk byte length differed from `descriptor.uncompressed_len`.
    #[error("hibernate chunk {chunk_index} decompressed to {actual} bytes, expected {expected}")]
    DecompressedLengthMismatch {
        chunk_index: u32,
        actual: usize,
        expected: usize,
    },

    /// The hibernate disk is smaller than the required image size.
    #[error(
        "hibernate disk too small: required {required_bytes} bytes, disk has {disk_bytes} bytes"
    )]
    DiskTooSmall {
        required_bytes: u64,
        disk_bytes: u64,
    },

    /// A synchronous hibernate storage operation failed.
    #[error("hibernate storage error: {0}")]
    Storage(#[from] HibernateStorageError),

    /// Quiescing or reinitializing platform devices failed.
    #[error("hibernate device lifecycle error: {0}")]
    Device(#[from] HibernateDeviceError),
}
