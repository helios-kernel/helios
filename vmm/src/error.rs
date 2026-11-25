//! Typed error definitions for `helios-vmm`.

use helios_api::{
    bindings::wasi::filesystem::types::ErrorCode as FsErrorCode,
    hv::{self, GuestPhysAddr, VmExit},
};
use thiserror::Error;

/// Errors returned while configuring, booting, or running a [`crate::MicroVm`].
#[derive(Debug, Error)]
pub enum Error {
    #[error("virtualization: {0}")]
    Hv(#[from] hv::Error),
    #[error("hypervisor: {0}")]
    RawHv(#[from] hv::HvError),
    #[error("filesystem: {0}")]
    Fs(#[from] FsErrorCode),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("device tree: {0}")]
    Fdt(#[from] vm_fdt::Error),
    #[error("root filesystem preopen '/' missing")]
    MissingRoot,
    #[error("invalid file transfer {offset:#x}+{length:#x}")]
    FileRange { offset: u64, length: usize },
    #[error("unexpected file EOF")]
    ShortRead,
    #[error("file output stream closed early")]
    ShortWrite,
    #[error("invalid Linux image: {0}")]
    Image(&'static str),
    #[error("virtio: {0}")]
    Virtio(&'static str),
    #[error("GICv3: {0}")]
    Gic(&'static str),
    #[error("unexpected vCPU {cpu} exit: {exit:?}")]
    UnexpectedExit { cpu: u32, exit: VmExit },
    #[error("unmapped device MMIO address {0}")]
    UnmappedDevice(GuestPhysAddr),
    #[error("unsupported system register {0:#x}")]
    UnsupportedRegister(u32),
    #[error("invalid VM configuration: {0}")]
    Config(&'static str),
    #[error("invalid share tag {tag:?}: {reason}")]
    InvalidShareTag { tag: String, reason: &'static str },
    #[error("internal VMM event channel closed")]
    ChannelClosed,
}

pub type Result<T> = core::result::Result<T, Error>;
