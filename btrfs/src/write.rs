//! Writable Btrfs mounts and transaction-owned mutations.
//!
//! A [`Writer`] exclusively owns the writable mount and its running
//! transaction, following Linux: a change is visible at once and durable at
//! commit. Callers serialize access to it. Reads through a
//! [`crate::Filesystem`] view remain concurrent and retain the state they
//! opened, whether a committed generation or the running transaction as of
//! an accepted mutation. No filesystem lock is held across I/O.
//!
//! Mutations exclusively borrow a [`WriteTransaction`] handle on the running
//! transaction. An error or cancellation restores that operation's checkpoint
//! and preserves earlier accepted edits; dropping the handle keeps them all.
//! [`Writer::commit`] makes them durable as one generation; the caller commits
//! on sync, on its commit interval, when [`Writer::dirty`] reaches its bound
//! ([`DEFAULT_DIRTY_METADATA_LIMIT`] unless its operator chose another), and
//! at unmount. File data is allocated late, as Linux's delayed allocation: a
//! write dirties pages and reserves their data space, and
//! [`Writer::writeback`], which every commit runs first, forms the extents
//! from the dirty runs at Linux's sizes, 128 KiB windows for compressed data
//! and up to 128 MiB otherwise. The caller writes back when [`Dirty`] data
//! reaches its bound ([`default_dirty_data_limit`] unless its operator chose
//! another). [`InodeHandle`] binds an inode
//! to its mount and generation. Directory lookup sees staged namespace
//! changes, including subvolume entries.
//!
//! A log tree a crash left behind an fsync is replayed when the writer mounts,
//! in one transaction committed before [`Writer::mount`] returns; a log item
//! the replay does not implement refuses the mount ([`LogReplayError`]).
//! Writable support excludes verity and unknown compat-ro features. Once quotas
//! are enabled (or on a filesystem mounted with an existing quota tree), the
//! writer maintains quota-group accounting (`BTRFS_QUOTA_TREE_OBJECTID`) and
//! enforces configured limits. Multi-device volumes are supported across
//! `SINGLE`, `DUP`, and `RAID1` profiles (see [`ChunkError`] for what is
//! refused). Space comes from the block groups, and the writer allocates a
//! chunk on the device(s) when a type runs short, following Linux's regular
//! policy: a data chunk when no free range holds a reservation, metadata and
//! system chunks ahead of need so a commit never runs out of tree blocks. A
//! write that finds the data space short stores the prefix that fits, and only
//! one that cannot store a sector reports out of space; writeback uses the
//! smaller free ranges that remain for the space reserved. The caller supplies
//! time, compression policy, the inline data limit (Linux's `max_inline`), I/O
//! concurrency and a UUID generator for root records that lack a valid UUID
//! extension.

pub use crate::allocation::AllocationDefect;
pub use crate::allocation::data::DataDefect;
pub use crate::compress::policy::{CompressionOptionError, CompressionPolicy, Compressor};
pub use crate::compress::write::{EncodeError, Encoded, Encoder, Lzo, Zlib, Zstd};
pub use crate::free_space::FreeSpaceDefect;
pub use crate::fs::writer::{
    Attributes, CloneRange, DEFAULT_DIRTY_METADATA_LIMIT, DIRTY_BACKGROUND_RATIO, Dirty,
    InodeHandle, Name, RootUuids, Special, Usage, WriteTransaction, Writer,
    default_dirty_data_limit,
};
pub use crate::receive::stream_referenced_sources;
pub use crate::space::{SpaceDefect, SpaceError};
pub use crate::transaction::chunks::ChunkError;
pub use crate::transaction::fallocate::AllocateMode;
pub use crate::transaction::file::DEFAULT_MAX_INLINE;
pub use crate::transaction::replay::LogReplayError;
pub use crate::transaction::xattr::XattrMode;
pub use crate::tree::edit::EditError;
pub use crate::tree::write::WriteError;
pub use crate::uuid_tree::UuidDefect;
pub use helios_hal::fs_management::{
    BalanceFilter, BalanceReport, DedupeOutcome, QgroupId, QgroupInfo, QgroupLimit, QuotaStatus,
    ResizeTarget, ScrubReport, SubvolumeInfo, VolumeDeviceInfo,
};
pub use miniz_oxide::deflate::CompressionLevel as ZlibLevel;
