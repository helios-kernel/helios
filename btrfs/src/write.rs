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
//! Writable support is single-device and excludes pending log replay, verity
//! and unknown compat-ro features. Space currently comes from existing block
//! groups. The caller supplies time, compression policy, I/O concurrency and a
//! UUID generator for root records that lack a valid UUID extension.

pub use crate::allocation::AllocationDefect;
pub use crate::allocation::data::DataDefect;
pub use crate::compress::write::{EncodeError, Encoded, Encoder, Lzo, Plain, Zlib, Zstd};
pub use crate::free_space::FreeSpaceDefect;
pub use crate::fs::writer::{Attributes, CloneRange, InodeHandle, Name, WriteTransaction, Writer};
pub use crate::space::{SpaceDefect, SpaceError};
pub use crate::transaction::file::WriteOptions;
pub use crate::tree::edit::EditError;
pub use crate::tree::write::WriteError;
pub use crate::uuid_tree::UuidDefect;
pub use miniz_oxide::deflate::CompressionLevel as ZlibLevel;
