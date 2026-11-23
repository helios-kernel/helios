//! Host filesystem client and supporting types.
//!
//! `client` implements the in-kernel 9p client used to drive a virtio
//! host share, and `cache` holds the bounded, time-limited tables that
//! keep it from re-walking the share for every question. `share` exposes the mount tag and guest-side path
//! helpers shared with the wasmtime host bindings.

mod cache;
mod client;
mod share;
mod virtio;

pub use cache::HostFsCacheStats;
pub use client::{FilledHostFsWrite, HostFsClient, HostFsTransport, HostFsWrite};
pub use share::{HOST_SHARE_GUEST_MOUNT_PATH, HOST_SHARE_MOUNT_TAG};
pub use virtio::Virtio9pTransport;
