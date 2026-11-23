//! Copy-on-write volume management contract: subvolumes, snapshots,
//! replication streams, extent sharing, multi-device administration, resize,
//! balance, scrub and quota groups.
//!
//! # Concurrency contract
//!
//! Every method on [`VolumeManagement`] takes `&self` and may be called from
//! any processor concurrently. Implementations serialize mutating volume
//! operations internally without holding a spin lock across `.await`; read
//! views (`subvolume_info`, `list_subvolumes`, `list_devices`, `send_subvolume`,
//! `quota_status`, `list_qgroups`) run against an immutable snapshot or
//! coordinate cleanly with the volume's transaction owner. Futures borrow
//! their arguments only for the duration of the call.

use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;

use thiserror::Error;

use crate::fs::{BlockSerial, FsError, FsPath};

/// Identity and state of one subvolume inside a volume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubvolumeInfo {
    /// Volume-local tree identifier (5 for the top-level root, 256 and up
    /// for user subvolumes and snapshots).
    pub id: u64,
    /// Tree identifier of the parent subvolume that links this one, or `None`
    /// for the top-level subvolume.
    pub parent_id: Option<u64>,
    /// Normalized path of the subvolume root relative to the volume root
    /// (`""` for the default/top-level subvolume).
    pub path: String,
    /// This subvolume's UUID.
    pub uuid: [u8; 16],
    /// Source subvolume UUID for a snapshot, or `None`.
    pub parent_uuid: Option<[u8; 16]>,
    /// Original subvolume UUID recorded by receive, or `None`.
    pub received_uuid: Option<[u8; 16]>,
    /// Generation of the subvolume's current root tree block.
    pub generation: u64,
    /// Generation at which the subvolume was last changed.
    pub ctransid: u64,
    /// Generation at which the subvolume was created.
    pub otransid: u64,
    /// Sent generation recorded by receive.
    pub stransid: u64,
    /// Local generation recorded by receive.
    pub rtransid: u64,
    /// Whether the subvolume is marked read-only.
    pub read_only: bool,
}

/// Outcome of an extent deduplication request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DedupeOutcome {
    /// Whether the source and destination byte ranges were byte-for-byte
    /// identical and deduplicated.
    pub same: bool,
    /// Bytes whose extents were shared (`length` when `same`, `0` otherwise).
    pub bytes_deduped: u64,
}

/// Target size for a volume device resize operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResizeTarget {
    /// Expand to the full capacity of the backing block device.
    Max,
    /// Set the device size in the volume to an explicit byte length (rounded
    /// down to the volume's sector size).
    Bytes(u64),
}

/// One backing device participating in a volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VolumeDeviceInfo {
    pub devid: u64,
    pub uuid: [u8; 16],
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub serial: Option<BlockSerial>,
}

/// Selection criteria for a chunk balance pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalanceFilter {
    /// Relocate data block groups.
    pub data: bool,
    /// Relocate metadata block groups.
    pub metadata: bool,
    /// Relocate system block groups.
    pub system: bool,
    /// When present, relocate only block groups whose utilization percentage
    /// (`used * 100 / length`) is at most this bound (`0..=100`).
    pub usage_max_percent: Option<u8>,
    /// Maximum number of chunks to relocate in this pass.
    pub limit: Option<u64>,
}

impl Default for BalanceFilter {
    fn default() -> Self {
        Self {
            data: true,
            metadata: true,
            system: true,
            usage_max_percent: None,
            limit: None,
        }
    }
}

/// Summary of a completed balance pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BalanceReport {
    /// Block groups inspected against the filter.
    pub considered: u64,
    /// Block groups relocated.
    pub relocated: u64,
}

/// Summary of a completed scrub pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScrubReport {
    pub data_extents_scrubbed: u64,
    pub tree_extents_scrubbed: u64,
    pub data_bytes_scrubbed: u64,
    pub tree_bytes_scrubbed: u64,
    pub csum_errors: u64,
    pub verify_errors: u64,
    pub uncorrectable_errors: u64,
    pub corrected_errors: u64,
    pub no_csum_sectors: u64,
}

/// A quota group identifier (`level/id`), matching the on-disk 64-bit encoding
/// where the upper 16 bits hold the hierarchy level and the lower 48 bits hold
/// the group id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QgroupId {
    pub level: u16,
    pub id: u64,
}

impl QgroupId {
    /// Maximum 48-bit id value (`(1 << 48) - 1`).
    pub const MAX_ID: u64 = (1_u64 << 48) - 1;

    /// Constructs a quota group identifier, returning `None` if `id` exceeds
    /// the 48-bit on-disk field.
    pub const fn new(level: u16, id: u64) -> Option<Self> {
        if id > Self::MAX_ID {
            return None;
        }
        Some(Self { level, id })
    }

    /// Encodes into the 64-bit on-disk key offset.
    pub const fn to_raw(self) -> u64 {
        ((self.level as u64) << 48) | (self.id & Self::MAX_ID)
    }

    /// Decodes from the 64-bit on-disk key offset.
    pub const fn from_raw(raw: u64) -> Self {
        Self {
            level: (raw >> 48) as u16,
            id: raw & Self::MAX_ID,
        }
    }
}

/// Configured byte limits on a quota group. `None` removes the corresponding
/// limit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QgroupLimit {
    pub max_referenced: Option<u64>,
    pub max_exclusive: Option<u64>,
}

/// Accounting and limits of one quota group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QgroupInfo {
    pub id: QgroupId,
    pub referenced_bytes: u64,
    pub referenced_compressed_bytes: u64,
    pub exclusive_bytes: u64,
    pub exclusive_compressed_bytes: u64,
    pub limit: QgroupLimit,
    pub parents: Vec<QgroupId>,
}

/// Volume-wide quota subsystem state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QuotaStatus {
    pub enabled: bool,
    pub rescanning: bool,
    pub inconsistent: bool,
    pub generation: u64,
}

/// Errors reported by [`VolumeManagement`] operations.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum VolumeManagementError {
    #[error(transparent)]
    Fs(#[from] FsError),
    #[error("path does not name a subvolume root")]
    NotSubvolume,
    #[error("subvolume is read-only")]
    ReadOnlySubvolume,
    #[error("subvolume must be read-only for this operation")]
    SubvolumeNotReadOnly,
    #[error("subvolume contains nested subvolumes and cannot be deleted")]
    SubvolumeNotEmpty,
    #[error("cannot delete the default or top-level subvolume")]
    DefaultSubvolume,
    #[error("quotas are not enabled on this volume")]
    QuotaNotEnabled,
    #[error("quotas are already enabled on this volume")]
    QuotaAlreadyEnabled,
    #[error("quota limit exceeded")]
    QuotaExceeded,
    #[error("quota group {}/{} does not exist", .0.level, .0.id)]
    QgroupNotFound(QgroupId),
    #[error("quota group {}/{} already exists", .0.level, .0.id)]
    QgroupExists(QgroupId),
    #[error("invalid quota group relation")]
    QgroupInvalidRelation,
    #[error("device {0} does not belong to this volume")]
    DeviceNotFound(u64),
    #[error("cannot remove the last remaining device from a volume")]
    LastDevice,
    #[error("target device is too small for this operation")]
    DeviceTooSmall,
    #[error("malformed replication stream: {0}")]
    InvalidStream(String),
    #[error("clone or dedupe range is not sector aligned")]
    Alignment,
    #[error("clone or dedupe ranges overlap in the same file")]
    Overlap,
    #[error("source and destination files have incompatible checksum policies")]
    ChecksumPolicyMismatch,
    #[error("source range extends beyond the end of the file")]
    CloneSourceOutOfRange,
    #[error("caller lacks permission for this volume operation")]
    PermissionDenied,
}

pub type VolumeManagementResult<T> = Result<T, VolumeManagementError>;

/// Copy-on-write volume management interface implemented by filesystems that
/// support subvolumes, snapshots, replication streams, extent sharing,
/// multi-device management, resize, balance, scrub and quota groups.
pub trait VolumeManagement: Send + Sync {
    /// Backing block device handle passed to [`Self::add_device`] and
    /// [`Self::replace_device`].
    type Device: Send;

    /// Creates a new empty subvolume at `path`.
    fn create_subvolume<'a>(
        &'a self,
        path: FsPath<'a>,
        now: u64,
    ) -> impl Future<Output = VolumeManagementResult<SubvolumeInfo>> + Send + 'a;

    /// Deletes the subvolume rooted at `path`.
    fn delete_subvolume<'a>(
        &'a self,
        path: FsPath<'a>,
        now: u64,
    ) -> impl Future<Output = VolumeManagementResult<()>> + Send + 'a;

    /// Creates a snapshot of the subvolume rooted at `source` at `destination`.
    fn snapshot_subvolume<'a>(
        &'a self,
        source: FsPath<'a>,
        destination: FsPath<'a>,
        read_only: bool,
        now: u64,
    ) -> impl Future<Output = VolumeManagementResult<SubvolumeInfo>> + Send + 'a;

    /// Sets or clears the read-only flag on the subvolume rooted at `path`.
    fn set_subvolume_read_only<'a>(
        &'a self,
        path: FsPath<'a>,
        read_only: bool,
        now: u64,
    ) -> impl Future<Output = VolumeManagementResult<()>> + Send + 'a;

    /// Describes the subvolume rooted at `path`, failing with
    /// [`VolumeManagementError::NotSubvolume`] when `path` is not a subvolume
    /// root.
    fn subvolume_info<'a>(
        &'a self,
        path: FsPath<'a>,
    ) -> impl Future<Output = VolumeManagementResult<SubvolumeInfo>> + Send + 'a;

    /// Lists every live subvolume in the volume.
    fn list_subvolumes(
        &self,
    ) -> impl Future<Output = VolumeManagementResult<Vec<SubvolumeInfo>>> + Send + '_;

    /// Produces a replication stream for the read-only subvolume at
    /// `subvolume`, optionally incremental against `parent` and cloning
    /// matching extents from `clone_sources`.
    fn send_subvolume<'a>(
        &'a self,
        subvolume: FsPath<'a>,
        parent: Option<FsPath<'a>>,
        clone_sources: &'a [FsPath<'a>],
    ) -> impl Future<Output = VolumeManagementResult<Vec<u8>>> + Send + 'a;

    /// Applies a replication stream into the directory at `destination`.
    ///
    /// Before reading or snapshotting any existing source subvolume referenced
    /// by the stream (`SNAPSHOT` or `CLONE`), `authorize_source` is called
    /// with that source subvolume's root path inside the volume; returning an
    /// error aborts the receive without reading from that subvolume.
    fn receive_subvolume<'a, F>(
        &'a self,
        destination: FsPath<'a>,
        stream: &'a [u8],
        now: u64,
        authorize_source: F,
    ) -> impl Future<Output = VolumeManagementResult<SubvolumeInfo>> + Send + 'a
    where
        F: FnMut(FsPath<'_>) -> VolumeManagementResult<()> + Send + 'a;

    /// Shares extents from `source` into `destination` (reflink / range clone).
    fn reflink<'a>(
        &'a self,
        source: FsPath<'a>,
        source_offset: u64,
        destination: FsPath<'a>,
        destination_offset: u64,
        length: u64,
        now: u64,
    ) -> impl Future<Output = VolumeManagementResult<()>> + Send + 'a;

    /// Shares extents from `source` into `destination` only if both ranges are
    /// byte-for-byte identical.
    fn dedupe<'a>(
        &'a self,
        source: FsPath<'a>,
        source_offset: u64,
        destination: FsPath<'a>,
        destination_offset: u64,
        length: u64,
        now: u64,
    ) -> impl Future<Output = VolumeManagementResult<DedupeOutcome>> + Send + 'a;

    /// Lists every backing device currently in the volume.
    fn list_devices(
        &self,
    ) -> impl Future<Output = VolumeManagementResult<Vec<VolumeDeviceInfo>>> + Send + '_;

    /// Adds a new backing device to the volume and returns its device info.
    fn add_device(
        &self,
        device: Self::Device,
        now: u64,
    ) -> impl Future<Output = VolumeManagementResult<VolumeDeviceInfo>> + Send + '_;

    /// Relocates all extents off `devid`, removes it from the volume and wipes
    /// its superblock.
    fn remove_device(
        &self,
        devid: u64,
        now: u64,
    ) -> impl Future<Output = VolumeManagementResult<()>> + Send + '_;

    /// Replaces `source_devid` in place with `target`, copying all allocated
    /// device extents, updating chunk metadata and wiping the old device's
    /// superblock.
    fn replace_device(
        &self,
        source_devid: u64,
        target: Self::Device,
        now: u64,
    ) -> impl Future<Output = VolumeManagementResult<VolumeDeviceInfo>> + Send + '_;

    /// Resizes `devid` (or the primary device when `None`) to `target`,
    /// relocating chunks beyond the new boundary when shrinking.
    fn resize_device(
        &self,
        devid: Option<u64>,
        target: ResizeTarget,
        now: u64,
    ) -> impl Future<Output = VolumeManagementResult<VolumeDeviceInfo>> + Send + '_;

    /// Relocates block groups matching `filter`.
    fn balance(
        &self,
        filter: BalanceFilter,
        now: u64,
    ) -> impl Future<Output = VolumeManagementResult<BalanceReport>> + Send + '_;

    /// Verifies checksums across all allocated metadata and data extents (and
    /// superblocks), repairing corrupted mirror copies when `!read_only`.
    fn scrub(
        &self,
        devid: Option<u64>,
        read_only: bool,
    ) -> impl Future<Output = VolumeManagementResult<ScrubReport>> + Send + '_;

    /// Enables quota groups on the volume and scans existing extents.
    fn quota_enable(
        &self,
        now: u64,
    ) -> impl Future<Output = VolumeManagementResult<()>> + Send + '_;

    /// Disables quota groups and removes the quota tree.
    fn quota_disable(
        &self,
        now: u64,
    ) -> impl Future<Output = VolumeManagementResult<()>> + Send + '_;

    /// Recomputes all quota group referenced and exclusive byte counts from
    /// the volume's current extent and backref trees.
    fn quota_rescan(
        &self,
        now: u64,
    ) -> impl Future<Output = VolumeManagementResult<()>> + Send + '_;

    /// Creates a quota group (typically a higher-level aggregation group).
    fn qgroup_create(
        &self,
        id: QgroupId,
        now: u64,
    ) -> impl Future<Output = VolumeManagementResult<()>> + Send + '_;

    /// Destroys a quota group that has no members and is not a live subvolume.
    fn qgroup_destroy(
        &self,
        id: QgroupId,
        now: u64,
    ) -> impl Future<Output = VolumeManagementResult<()>> + Send + '_;

    /// Adds `member` to parent quota group `parent` (`parent.level > member.level`).
    fn qgroup_assign(
        &self,
        member: QgroupId,
        parent: QgroupId,
        now: u64,
    ) -> impl Future<Output = VolumeManagementResult<()>> + Send + '_;

    /// Removes `member` from parent quota group `parent`.
    fn qgroup_remove(
        &self,
        member: QgroupId,
        parent: QgroupId,
        now: u64,
    ) -> impl Future<Output = VolumeManagementResult<()>> + Send + '_;

    /// Updates the referenced and exclusive byte limits for `id`.
    fn qgroup_limit(
        &self,
        id: QgroupId,
        limit: QgroupLimit,
        now: u64,
    ) -> impl Future<Output = VolumeManagementResult<()>> + Send + '_;

    /// Reports whether quotas are enabled and their current status flags.
    fn quota_status(&self)
    -> impl Future<Output = VolumeManagementResult<QuotaStatus>> + Send + '_;

    /// Lists every quota group, its accounting counters, limits and parents.
    fn list_qgroups(
        &self,
    ) -> impl Future<Output = VolumeManagementResult<Vec<QgroupInfo>>> + Send + '_;
}
