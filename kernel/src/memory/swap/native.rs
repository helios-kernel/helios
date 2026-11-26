//! Concrete registry of live native Linux user address spaces for
//! [`SwapService`](super::SwapService).
//!
//! # Concurrency contract
//!
//! - `spaces` is a short-held `spin::Mutex` (never held across `.await`, never
//!   held while acquiring a [`UserSpace`] lock, and never touched from interrupt
//!   context).
//! - `teardown_orphans` is a separate `spin::Mutex` (never nested with `spaces`
//!   or a `UserSpace` lock).
//! - Per-space `last_activity_nanos` is a lock-free `AtomicU64` updated on each
//!   user slice or syscall without acquiring any mutex.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use helios_hal::native::UserSpace;
use helios_hal::vmm::SwapToken;
use spin::{Mutex, Once};

use super::SwapHandle;
use crate::memory::owner::MemoryOwner;

struct RegisteredEntry<Space> {
    space: Weak<Space>,
    owner: MemoryOwner,
    last_activity_nanos: Arc<AtomicU64>,
}

struct NativeSpaceRegistryInner<Space> {
    next_id: AtomicU64,
    spaces: Mutex<BTreeMap<u64, RegisteredEntry<Space>>>,
    teardown_orphans: Mutex<Vec<SwapToken>>,
    swap_handle: Once<SwapHandle>,
}

/// Concrete, zero-`dyn` registry of live native user address spaces shared
/// between the Linux process host and [`SwapService`](super::SwapService).
pub struct NativeSpaceRegistry<Space> {
    inner: Arc<NativeSpaceRegistryInner<Space>>,
}

impl<Space> Clone for NativeSpaceRegistry<Space> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<Space> Default for NativeSpaceRegistry<Space> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Space> NativeSpaceRegistry<Space> {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(NativeSpaceRegistryInner {
                next_id: AtomicU64::new(1),
                spaces: Mutex::new(BTreeMap::new()),
                teardown_orphans: Mutex::new(Vec::new()),
                swap_handle: Once::new(),
            }),
        }
    }

    /// Publishes the [`SwapHandle`] associated with the swap service watching
    /// this registry so teardown orphan draining can wake the service and
    /// callers can issue `fault_in_native` without reaching a global static.
    pub fn attach_swap_handle(&self, handle: SwapHandle) {
        self.inner.swap_handle.call_once(|| handle);
    }

    /// The [`SwapHandle`] attached to this registry, if swap is online.
    pub fn swap_handle(&self) -> Option<SwapHandle> {
        self.inner.swap_handle.get().cloned()
    }

    /// Registers a live native user address space with `owner` and initial
    /// activity timestamp `now_nanos`. Dropping the returned guard unregisters
    /// the space and queues all of its remaining swap tokens for backend
    /// release.
    pub fn register(
        &self,
        space: Arc<Space>,
        owner: MemoryOwner,
        now_nanos: u64,
    ) -> RegisteredNativeSpace<Space>
    where
        Space: UserSpace,
    {
        let space_id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let last_activity_nanos = Arc::new(AtomicU64::new(now_nanos));
        self.inner.spaces.lock().insert(
            space_id,
            RegisteredEntry {
                space: Arc::downgrade(&space),
                owner,
                last_activity_nanos: Arc::clone(&last_activity_nanos),
            },
        );
        RegisteredNativeSpace {
            registry: self.clone(),
            space_id,
            space,
            last_activity_nanos,
        }
    }

    pub(crate) fn get(&self, space_id: u64) -> Option<(Arc<Space>, MemoryOwner)> {
        let guard = self.inner.spaces.lock();
        let entry = guard.get(&space_id)?;
        let space = entry.space.upgrade()?;
        Some((space, entry.owner))
    }

    pub(crate) fn contains(&self, space_id: u64) -> bool {
        self.inner.spaces.lock().contains_key(&space_id)
    }

    /// Live spaces whose last recorded activity is at least `idle_after_nanos`
    /// older than `now_nanos`.
    pub(crate) fn idle_spaces(
        &self,
        now_nanos: u64,
        idle_after_nanos: u64,
    ) -> Vec<(u64, Arc<Space>, MemoryOwner)> {
        let guard = self.inner.spaces.lock();
        let mut out = Vec::new();
        for (&space_id, entry) in guard.iter() {
            let last = entry.last_activity_nanos.load(Ordering::Acquire);
            if now_nanos.saturating_sub(last) >= idle_after_nanos
                && let Some(space) = entry.space.upgrade()
            {
                out.push((space_id, space, entry.owner));
            }
        }
        out
    }

    /// Every currently registered live space.
    pub(crate) fn live_spaces(&self) -> Vec<(u64, Arc<Space>, MemoryOwner)> {
        let guard = self.inner.spaces.lock();
        let mut out = Vec::new();
        for (&space_id, entry) in guard.iter() {
            if let Some(space) = entry.space.upgrade() {
                out.push((space_id, space, entry.owner));
            }
        }
        out
    }

    /// Snapshots `(space_id, resident_bytes, swapped_bytes)` for every live
    /// registered native address space so `/proc/<pid>/status` reports live
    /// `VmRSS` and `VmSwap` even for sleeping or idle processes.
    pub fn space_memory_stats(&self) -> Vec<(u64, u64, u64)>
    where
        Space: UserSpace,
    {
        let live: Vec<(u64, Arc<Space>)> = {
            let guard = self.inner.spaces.lock();
            guard
                .iter()
                .filter_map(|(&space_id, entry)| {
                    entry.space.upgrade().map(|space| (space_id, space))
                })
                .collect()
        };
        live.into_iter()
            .map(|(space_id, space)| (space_id, space.resident_bytes(), space.swapped_bytes()))
            .collect()
    }

    /// Drains all swap tokens queued by torn-down spaces as well as orphan
    /// tokens from every live space into `out`.
    pub(crate) fn drain_all_orphans(&self, out: &mut Vec<SwapToken>)
    where
        Space: UserSpace,
    {
        {
            let mut teardown = self.inner.teardown_orphans.lock();
            out.append(&mut teardown);
        }
        let live: Vec<Arc<Space>> = {
            let guard = self.inner.spaces.lock();
            guard
                .values()
                .filter_map(|entry| entry.space.upgrade())
                .collect()
        };
        for space in live {
            space.drain_orphan_swap_tokens(out);
        }
    }

    fn unregister(&self, space_id: u64, space: &Space)
    where
        Space: UserSpace,
    {
        self.inner.spaces.lock().remove(&space_id);
        let mut tokens = Vec::new();
        space.drain_all_swap_tokens_for_teardown(&mut tokens);
        if !tokens.is_empty() {
            self.inner.teardown_orphans.lock().append(&mut tokens);
            if let Some(handle) = self.inner.swap_handle.get() {
                handle.poke();
            }
        }
    }
}

/// RAII registration of one native user address space in
/// [`NativeSpaceRegistry`]. Unregisters the space on drop and retains all
/// orphaned and still-swapped [`SwapToken`]s so [`SwapService`](super::SwapService)
/// frees every backend extent on its next tick.
pub struct RegisteredNativeSpace<Space: UserSpace> {
    registry: NativeSpaceRegistry<Space>,
    space_id: u64,
    space: Arc<Space>,
    last_activity_nanos: Arc<AtomicU64>,
}

impl<Space: UserSpace> RegisteredNativeSpace<Space> {
    pub const fn space_id(&self) -> u64 {
        self.space_id
    }

    /// Records monotonic activity timestamp `now_nanos` (lock-free).
    pub fn record_activity(&self, now_nanos: u64) {
        self.last_activity_nanos.store(now_nanos, Ordering::Release);
    }

    /// The [`SwapHandle`] attached to this space's registry, if swap is online.
    pub fn swap_handle(&self) -> Option<SwapHandle> {
        self.registry.swap_handle()
    }
}

impl<Space: UserSpace> Drop for RegisteredNativeSpace<Space> {
    fn drop(&mut self) {
        self.registry.unregister(self.space_id, &self.space);
    }
}
