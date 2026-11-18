//! Attaching filesystems to the guest path tree.
//!
//! A mount is seen by every program. Attaching or detaching one takes the
//! mount authority a [`crate::programs::mount_grant`] hands a child, and
//! mutate-directory authority over the mount point.

use crate::bindings::helios::system::mounts as raw;
pub use crate::bindings::helios::system::mounts::{
    MountError, MountErrorKind, MountRequest, MountSource,
};

/// Attaches `request.source` at `request.path`, a directory path in the
/// caller's authority. The request's options carry Linux's mount options of
/// the same names for a writable btrfs mount: `compress=` (such as
/// `zstd:3`), `commit=` in seconds and `max_inline=` in bytes.
pub async fn mount(request: MountRequest) -> Result<(), MountError> {
    raw::mount(request).await
}

/// Detaches the filesystem mounted at `path`.
pub async fn unmount(path: impl Into<String>) -> Result<(), MountError> {
    raw::unmount(path.into()).await
}
