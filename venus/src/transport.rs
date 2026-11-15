//! Transport used at Vulkan's synchronous ABI boundary.
//!
//! A call may suspend the guest stack. The Helios implementation uses
//! canonical synchronous lowering of asynchronous component imports: the
//! host task awaits I/O while other kernel tasks run. No executor or polling
//! bridge runs inside the component. One connection owns submission order.

use core::num::NonZeroU64;
use core::ptr::NonNull;
use core::time::Duration;

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

/// A retained Vulkan allocation export, with an optional coherent CPU mapping.
///
/// # Safety
/// `map` returns an aligned pointer valid for the allocation's full size until
/// this owner drops. Repeated calls return the same mapping. Destruction revokes
/// device mappings before returning guest addresses to the allocator.
pub unsafe trait MemoryResource {
    type Error: std::error::Error;
    fn map(&mut self) -> Result<NonNull<u8>, Self::Error>;
}

/// A read-only timeline; waits own their points and need no connection lock.
/// Host implementations suspend the caller through canonical lowering.
pub trait Timeline: Clone + Send + Sync {
    type Error: std::error::Error;
    fn value(&self) -> Result<u64, Self::Error>;
    /// Returns true for completion, false only when a supplied timeout expires.
    /// With no timeout, success always means completion. Producer closure or
    /// failure is an error; already-completed points take precedence over timeout.
    fn wait(
        points: &[TimelinePoint<Self>],
        wait_all: bool,
        timeout: Option<Duration>,
    ) -> Result<bool, Self::Error>;
}

#[derive(Clone)]
pub struct TimelinePoint<T: Timeline> {
    pub timeline: T,
    pub value: u64,
}

/// Producer ownership is distinct from read-only waits.
pub trait SignalTimeline: Clone + Send + Sync {
    type Error: std::error::Error;
    type Timeline: Timeline<Error = Self::Error>;
    fn reader(&self) -> Self::Timeline;
    fn signal(&self, value: u64) -> Result<(), Self::Error>;
    fn fail(&self);
}

pub struct SignalPoint<'a, S: SignalTimeline> {
    pub source: &'a S,
    pub value: u64,
}

pub struct Completion<'a, S: SignalTimeline> {
    pub fence: u64,
    pub signals: &'a [SignalPoint<'a, S>],
}

pub type WaitPoint<T> = TimelinePoint<<<T as Transport>::Signal as SignalTimeline>::Timeline>;

/// One renderer context. Calls are made in order by its single owner.
/// `execute` acknowledges submission; attached timelines acknowledge retirement.
pub trait Transport {
    type Error: std::error::Error;
    type Blob: MappedBlob;
    type Memory: MemoryResource<Error = Self::Error> + Send;
    type Signal: SignalTimeline<Error = Self::Error>;

    fn timeline(&self, initial: u64) -> Self::Signal;

    fn create_blob(&mut self, size: NonZeroU64, blob_id: u64) -> Result<Self::Blob, Self::Error>;
    fn export_memory(
        &mut self,
        size: NonZeroU64,
        blob_id: u64,
        host_visible: bool,
    ) -> Result<Self::Memory, Self::Error>;
    fn execute(
        &mut self,
        commands: &[u8],
        ring: u8,
        completion: Option<Completion<'_, Self::Signal>>,
    ) -> Result<(), Self::Error>;
}
