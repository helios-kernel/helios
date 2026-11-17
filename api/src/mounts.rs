//! Attaching filesystems to the guest path tree.
//!
//! A mount is seen by every program. Attaching or detaching one takes the
//! mount authority a [`crate::programs::mount_grant`] hands a child, and
//! mutate-directory authority over the mount point.

use crate::bindings::helios::system::mounts as raw;
pub use crate::bindings::helios::system::mounts::{
    MountError, MountErrorKind, MountRequest, MountSource,
};

/// Attaches `source` at `path`, a directory path in the caller's authority.
/// `compress` is the value of Linux's `compress=` option for a writable btrfs
/// mount, such as `zstd:3`, and `commit` the value of its `commit=` option,
/// in seconds.
pub async fn mount(
    source: MountSource,
    path: impl Into<String>,
    read_only: bool,
    compress: Option<String>,
    commit: Option<u32>,
) -> Result<(), MountError> {
    raw::mount(MountRequest {
        source,
        path: path.into(),
        read_only,
        compress,
        commit,
    })
    .await
}

/// Detaches the filesystem mounted at `path`.
pub async fn unmount(path: impl Into<String>) -> Result<(), MountError> {
    raw::unmount(path.into()).await
}
