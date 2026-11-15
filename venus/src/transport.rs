//! Transport used at Vulkan's synchronous ABI boundary.
//!
//! A call may suspend the guest stack. The Helios implementation uses
//! canonical synchronous lowering of asynchronous component imports: the
//! host task awaits I/O while other kernel tasks run. No executor or polling
//! bridge runs inside the component. One connection owns submission order.

use core::num::NonZeroU64;
use core::ptr::NonNull;

use crate::capset::Capset;

/// Constructs independent renderer contexts for Vulkan's global entry points.
///
/// The factory is selected by the entry table's type, not a global variable.
/// Each call owns a fresh context and capability snapshot; concurrent calls
/// must not share submission state. Instance commands subsequently recover
/// their connection from the instance's dispatchable objects.
pub trait TransportFactory {
    type Transport: Transport;

    fn create() -> Result<(Self::Transport, Capset), <Self::Transport as Transport>::Error>;
}

/// An owned, persistently mapped renderer blob.
///
/// # Safety
/// The pointer must stay aligned for 32-bit atomics and valid for `len()`
/// bytes until the owner is dropped. The mapping is coherent with the
/// renderer. Implementations never form references into the shared bytes
/// while the renderer can access them. Dropping removes the mapping before
/// returning its address range to the guest allocator.
pub unsafe trait MappedBlob {
    fn resource_id(&self) -> u32;
    fn pointer(&self) -> NonNull<u8>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One renderer context. Calls are made in order by its single owner.
/// `execute` acknowledges submission; only `wait` acknowledges retirement.
pub trait Transport {
    type Error: std::error::Error;
    type Blob: MappedBlob;

    fn create_blob(&mut self, size: NonZeroU64, blob_id: u64) -> Result<Self::Blob, Self::Error>;
    fn execute(&mut self, commands: &[u8], ring: u8, fence: Option<u64>)
    -> Result<(), Self::Error>;
    fn wait(&mut self, ring: u8, fence: u64) -> Result<(), Self::Error>;
}
