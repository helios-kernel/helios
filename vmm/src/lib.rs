//! Reusable async micro-VM library over `helios_api::hv`.
//!
//! [`MicroVm::builder`] configures pure custom VMs (`cpus`, `memory`, `kernel`,
//! `initramfs`, `cmdline`, `virtio-console`, `virtio-blk`, `virtio-net`,
//! `virtio-vsock`, and `virtio-fs` directory/rootfs shares) with zero dynamic
//! dispatch, zero `block_on`, and `ioevent`-backed virtqueue notification fast
//! paths.

pub mod boot;
pub mod error;
pub mod file;
pub mod gic;
pub mod hv_backend;
pub mod uart;
pub mod virtio;
pub mod vm;

pub use error::{Error, Result};
pub use virtio::fs::{ROOTFS_TAG, VirtioFsShareConfig};
pub use virtio::net::VirtioNetConfig;
pub use virtio::vsock::VirtioVsockConfig;
pub use vm::{
    DEFAULT_INITRAMFS_CMDLINE, DEFAULT_ROOTFS_CMDLINE, DeviceSet, ExitReason, KickContext, MicroVm,
    MicroVmBuilder, MicroVmConfig, QueueKickTarget, VirtioBlkConfig, VirtioConsoleConfig,
};
