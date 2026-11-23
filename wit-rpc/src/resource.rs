use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use async_lock::{Mutex, MutexGuard};
use helios_inspector_protocol::WireError;
use helios_inspector_protocol::mux::PeerHandle;

/// Connection-scoped monotonic `u32` handle allocator shared across all
/// [`ResourceTable`] instances on one connection.
#[derive(Clone, Debug)]
pub struct HandleAllocator {
    next: Arc<AtomicU32>,
}

impl Default for HandleAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl HandleAllocator {
    pub fn new() -> Self {
        Self {
            // Handle 0 is never allocated so forged 0 handles always fail.
            next: Arc::new(AtomicU32::new(1)),
        }
    }

    pub fn next_id(&self) -> u32 {
        loop {
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }
}

/// Static descriptor for concrete server-side resource entries stored in a
/// connection's [`ResourceTable`].
pub trait ResourceEntry: Send + Sync + 'static {
    /// Canonical WIT resource name for diagnostics and [`WireError::ResourceTypeMismatch`].
    fn kind_name(&self) -> &'static str;
}

impl ResourceEntry for core::convert::Infallible {
    fn kind_name(&self) -> &'static str {
        match *self {}
    }
}

/// Sum of two [`ResourceEntry`] sets when composing two [`crate::Dispatcher`]s
/// on one connection.
#[derive(Debug)]
pub enum EitherResource<L, R> {
    Left(L),
    Right(R),
}

impl<L: ResourceEntry, R: ResourceEntry> ResourceEntry for EitherResource<L, R> {
    fn kind_name(&self) -> &'static str {
        match self {
            Self::Left(left) => left.kind_name(),
            Self::Right(right) => right.kind_name(),
        }
    }
}

/// Active server-side `borrow<R>` guard held for the duration of an
/// invocation.
///
/// Releases its `Arc<T>` reference before decrementing the borrow count
/// atomically on drop without acquiring any lock.
pub struct ResourceBorrow<T> {
    value: Option<Arc<T>>,
    borrows: Arc<AtomicUsize>,
}

impl<T> Deref for ResourceBorrow<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.value
            .as_ref()
            .expect("resource borrow value is present until drop")
    }
}

impl<T> Drop for ResourceBorrow<T> {
    fn drop(&mut self) {
        // Release the `Arc<T>` before dropping the borrow count to 0 so a
        // concurrent `ResourceTableInner::take` observing `borrows == 0`
        // cannot race with `Arc::try_unwrap`.
        drop(self.value.take());
        self.borrows.fetch_sub(1, Ordering::AcqRel);
    }
}

struct ResourceSlot<R> {
    value: R,
    borrows: Arc<AtomicUsize>,
}

/// Inner table state mutated during brief, non-yielding critical sections.
pub struct ResourceTableInner<R: ResourceEntry> {
    allocator: HandleAllocator,
    slots: BTreeMap<u32, ResourceSlot<R>>,
}

impl<R: ResourceEntry> Default for ResourceTableInner<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: ResourceEntry> ResourceTableInner<R> {
    pub fn new() -> Self {
        Self::with_allocator(HandleAllocator::new())
    }

    pub fn with_allocator(allocator: HandleAllocator) -> Self {
        Self {
            allocator,
            slots: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    pub fn contains(&self, handle: u32) -> bool {
        self.slots.contains_key(&handle)
    }

    /// Inserts a newly exported resource and returns its connection-local `u32`
    /// handle.
    pub fn insert(&mut self, value: R) -> Result<u32, WireError> {
        for _ in 0..u16::MAX {
            let candidate = self.allocator.next_id();
            if let std::collections::btree_map::Entry::Vacant(vacant) = self.slots.entry(candidate)
            {
                vacant.insert(ResourceSlot {
                    value,
                    borrows: Arc::new(AtomicUsize::new(0)),
                });
                return Ok(candidate);
            }
        }
        Err(WireError::MalformedPayload {
            context: "ResourceTable::insert".to_owned(),
            detail: "connection resource handle table exhausted".to_owned(),
        })
    }

    /// Borrows a live resource for the duration of a server call, failing with
    /// [`WireError::InvalidResourceHandle`] or [`WireError::ResourceTypeMismatch`]
    /// on forged or mismatched handles.
    pub fn borrow<T>(
        &self,
        handle: u32,
        expected: &'static str,
        project: impl FnOnce(&R) -> Option<&Arc<T>>,
    ) -> Result<ResourceBorrow<T>, WireError> {
        let Some(slot) = self.slots.get(&handle) else {
            return Err(WireError::InvalidResourceHandle { handle });
        };
        let Some(arc) = project(&slot.value) else {
            return Err(WireError::ResourceTypeMismatch {
                handle,
                expected: expected.to_owned(),
                actual: slot.value.kind_name().to_owned(),
            });
        };
        slot.borrows.fetch_add(1, Ordering::AcqRel);
        Ok(ResourceBorrow {
            value: Some(Arc::clone(arc)),
            borrows: Arc::clone(&slot.borrows),
        })
    }

    /// Takes ownership (`own<R>`) of a live unborrowed resource from the table.
    pub fn take<T>(
        &mut self,
        handle: u32,
        expected: &'static str,
        extract: impl FnOnce(R) -> Result<Arc<T>, R>,
        restore: impl FnOnce(Arc<T>) -> R,
    ) -> Result<T, WireError> {
        let Some(slot) = self.slots.get(&handle) else {
            return Err(WireError::InvalidResourceHandle { handle });
        };
        if slot.borrows.load(Ordering::Acquire) != 0 {
            return Err(WireError::ResourceBorrowed { handle });
        }
        let removed = self
            .slots
            .remove(&handle)
            .expect("verified resource slot must exist");
        match extract(removed.value) {
            Ok(arc) => match Arc::try_unwrap(arc) {
                Ok(value) => Ok(value),
                Err(arc) => {
                    self.slots.insert(
                        handle,
                        ResourceSlot {
                            value: restore(arc),
                            borrows: removed.borrows,
                        },
                    );
                    Err(WireError::ResourceBorrowed { handle })
                }
            },
            Err(restored) => {
                let actual = restored.kind_name().to_owned();
                self.slots.insert(
                    handle,
                    ResourceSlot {
                        value: restored,
                        borrows: removed.borrows,
                    },
                );
                Err(WireError::ResourceTypeMismatch {
                    handle,
                    expected: expected.to_owned(),
                    actual,
                })
            }
        }
    }

    fn remove_for_drop(&mut self, handle: u32) -> Result<R, WireError> {
        let Some(slot) = self.slots.get(&handle) else {
            return Err(WireError::InvalidResourceHandle { handle });
        };
        if slot.borrows.load(Ordering::Acquire) != 0 {
            return Err(WireError::ResourceBorrowed { handle });
        }
        Ok(self
            .slots
            .remove(&handle)
            .expect("verified resource slot must exist")
            .value)
    }

    fn take_all(&mut self) -> Vec<R> {
        std::mem::take(&mut self.slots)
            .into_values()
            .map(|slot| slot.value)
            .collect()
    }
}

/// Connection-scoped resource handle table.
///
///Synchronized via `async_lock::Mutex` whose guard is never held across an
/// `.await` point; resource `Drop` destructors always execute outside the lock.
pub struct ResourceTable<R: ResourceEntry> {
    inner: Mutex<ResourceTableInner<R>>,
}

impl<R: ResourceEntry> Default for ResourceTable<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: ResourceEntry> ResourceTable<R> {
    pub fn new() -> Self {
        Self::with_allocator(HandleAllocator::new())
    }

    pub fn with_allocator(allocator: HandleAllocator) -> Self {
        Self {
            inner: Mutex::new(ResourceTableInner::with_allocator(allocator)),
        }
    }

    pub async fn lock(&self) -> MutexGuard<'_, ResourceTableInner<R>> {
        self.inner.lock().await
    }

    pub async fn contains(&self, handle: u32) -> bool {
        self.inner.lock().await.contains(handle)
    }

    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }

    pub async fn insert(&self, value: R) -> Result<u32, WireError> {
        self.inner.lock().await.insert(value)
    }

    /// Removes and drops a single connection-local handle in response to
    /// `Frame::ResourceDrop`.
    pub async fn drop_handle(&self, handle: u32) -> Result<(), WireError> {
        let removed = self.inner.lock().await.remove_for_drop(handle)?;
        drop(removed);
        Ok(())
    }

    /// Drops every remaining resource on the connection when the transport
    /// disconnects, returning how many live resources were cleaned up.
    pub async fn clear(&self) -> usize {
        let entries = self.inner.lock().await.take_all();
        let count = entries.len();
        drop(entries);
        count
    }
}

/// Client-side RAII handle to a remote WIT `resource`.
///
/// Dropping [`RemoteResource`] while owned emits `Frame::ResourceDrop` on the
/// connection. Passing it by value (`own<R>`) into an RPC call disarms local
/// `Drop` via [`Self::into_raw_handle`] so ownership transfers cleanly.
pub struct RemoteResource {
    peer: PeerHandle,
    handle: u32,
    owned: bool,
}

impl std::fmt::Debug for RemoteResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteResource")
            .field("handle", &self.handle)
            .field("owned", &self.owned)
            .finish()
    }
}

impl RemoteResource {
    pub fn new(peer: PeerHandle, handle: u32) -> Self {
        Self {
            peer,
            handle,
            owned: true,
        }
    }

    /// Constructs a handle with an arbitrary raw `u32` ID without emitting
    /// `Frame::ResourceDrop` on drop unless `emit_drop` is true. Intended for
    /// generated proxies and negative/forged-handle protocol tests.
    pub fn from_raw_parts(peer: PeerHandle, handle: u32, emit_drop: bool) -> Self {
        Self {
            peer,
            handle,
            owned: emit_drop,
        }
    }

    pub fn handle_id(&self) -> u32 {
        self.handle
    }

    pub fn peer(&self) -> &PeerHandle {
        &self.peer
    }

    pub fn into_raw_handle(mut self) -> u32 {
        self.owned = false;
        self.handle
    }
}

impl Drop for RemoteResource {
    fn drop(&mut self) {
        if self.owned {
            self.peer.drop_remote_resource(self.handle);
        }
    }
}
