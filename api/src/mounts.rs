//! Attaching filesystems to the guest path tree.
//!
//! A mount is seen by every program. Attaching or detaching one takes the
//! mount authority a [`crate::programs::mount_grant`] hands a child, and
//! mutate-directory authority over the mount point.
//!
//! A mount is granted as private or shared ([`MountSharing`]), and that
//! never changes while it exists. A WASI program holds the mount's rights
//! either way and sees no owner, group or mode; the choice decides what a
//! Linux container sees of the filesystem.

use crate::bindings::helios::system::mounts as raw;
pub use crate::bindings::helios::system::mounts::{
    MountError, MountErrorKind, MountRequest, MountSharing, MountSource,
};

/// Attaches `request.source` at `request.path`, a directory path in the
/// caller's authority, granted as `request.sharing`. The request's options
/// carry Linux's mount options of the same names for a writable btrfs mount:
/// `compress=` (such as `zstd:3`), `commit=` in seconds and `max_inline=` in
/// bytes.
pub async fn mount(request: MountRequest) -> Result<(), MountError> {
    raw::mount(request).await
}

/// Detaches the filesystem mounted at `path`.
pub async fn unmount(path: impl Into<String>) -> Result<(), MountError> {
    raw::unmount(path.into()).await
}
