//! Bounded duplex capability channels (`helios:system/ipc`).
//!
//! [`channel`] mints a connected `(Endpoint, Endpoint)` pair. Either endpoint
//! can be handed across `helios:system/programs` launch grants via
//! `programs::ipc_grant` and claimed once inside the child via [`take`].

use crate::bindings::helios::system::ipc as raw;
pub use crate::bindings::helios::system::ipc::{Endpoint, IpcError};

/// Creates a connected pair of bounded duplex capability endpoints.
pub fn channel() -> (Endpoint, Endpoint) {
    raw::channel()
}

/// Claims the endpoint granted to this instance at launch under `name`, or
/// returns `None` if no unclaimed grant carries that name.
pub fn take(name: &str) -> Option<Endpoint> {
    raw::take(name)
}
