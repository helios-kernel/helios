//! Releasing the machine's host share for a VMM snapshot.
//!
//! A VMM that snapshots the machine refuses while the 9p host share is
//! attached. [`prepare`] has the kernel give the share back and returns a
//! [`SnapshotHold`] resource keeping it released until the resource is
//! dropped (on the machine that keeps running) or the machine generation
//! advances (on a copy restored from the snapshot).

use crate::bindings::helios::system::snapshot as raw;
pub use crate::bindings::helios::system::snapshot::{SnapshotError, SnapshotHold};

/// Waits for the host-share operations in flight to finish, returns the
/// share to the host, and holds it released until the returned
/// [`SnapshotHold`] drops. Operations issued while the hold is active wait
/// for it to end; none fails.
pub async fn prepare() -> Result<SnapshotHold, SnapshotError> {
    raw::prepare().await
}
