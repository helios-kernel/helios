//! Writable Btrfs mounts and transaction-owned mutations.
//!
//! A [`Writer`] exclusively owns the writable mount. Callers serialize access
//! to it; a transaction holds its mutable borrow until commit or abort. Reads
//! through a committed [`crate::Filesystem`] snapshot remain concurrent and
//! retain the generation they opened. No filesystem lock is held across I/O.
//!
//! Mutations exclusively borrow [`WriteTransaction`]. An error or cancellation
//! restores that operation's checkpoint and preserves earlier successful edits.
//! Commit consumes the transaction; dropping it discards the entire batch. [`InodeHandle`] binds an
//! inode to its mount and creation generation; a handle for an uncommitted inode
//! survives its transaction only after that transaction successfully commits.
//! Directory lookup sees staged namespace changes, including subvolume entries.
//!
//! Writable support is single-device and excludes pending log replay, verity,
//! unknown compat-ro features and filesystems with quotas enabled (the writer
//! maintains no quota-group accounting). Space comes from the block groups, and the
//! writer allocates a chunk on the device when a type runs short, following
//! Linux's regular policy and its single and DUP profiles (see
//! [`ChunkError`] for what is refused): a data chunk when no free range
//! holds a reservation, metadata and system chunks ahead of need so a commit
//! never runs out of tree blocks. A data write that finds the device full uses
//! the smaller free ranges that remain, and only a device with no free sector
//! reports out of space. The caller supplies time, compression policy, I/O
//! concurrency and a UUID generator for root records that lack a valid UUID
//! extension.

pub use crate::allocation::AllocationDefect;
pub use crate::allocation::data::DataDefect;
pub use crate::compress::policy::{CompressionOptionError, CompressionPolicy, Compressor};
pub use crate::compress::write::{EncodeError, Encoded, Encoder, Lzo, Plain, Zlib, Zstd};
pub use crate::free_space::FreeSpaceDefect;
pub use crate::fs::writer::{Attributes, CloneRange, InodeHandle, Name, WriteTransaction, Writer};
pub use crate::space::{SpaceDefect, SpaceError};
pub use crate::transaction::chunks::ChunkError;
pub use crate::transaction::file::WriteOptions;
pub use crate::tree::edit::EditError;
pub use crate::tree::write::WriteError;
pub use crate::uuid_tree::UuidDefect;
pub use miniz_oxide::deflate::CompressionLevel as ZlibLevel;
