//! Shared reference-counting and seal constants for `memfd_create(2)` inodes.
//!
//! # Concurrency contract
//!
//! [`MemfdHandle`], [`MemfdHold`], and [`MemfdWritableMapHold`] synchronize
//! strictly through lock-free `AtomicUsize` counters with `AcqRel` ordering.
//! Cloning or dropping an open file description or a tracked `mmap(2)` VMA
//! never acquires a spin lock or blocks.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

// Linux UAPI `include/uapi/linux/fcntl.h` `F_SEAL_*` bits.
pub const F_SEAL_SEAL: u32 = 0x0001;
pub const F_SEAL_SHRINK: u32 = 0x0002;
pub const F_SEAL_GROW: u32 = 0x0004;
pub const F_SEAL_WRITE: u32 = 0x0008;
pub const F_SEAL_FUTURE_WRITE: u32 = 0x0010;
pub const F_SEAL_EXEC: u32 = 0x0020;
pub const F_ALL_SEALS: u32 =
    F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE | F_SEAL_EXEC;

#[derive(Debug)]
struct MemfdCounters {
    /// Active open file descriptions (`OpenFile`) and `mmap(2)` VMAs referencing
    /// this memfd inode. When zero, the container's registry can drop the inode
    /// and reclaim all `UserMemoryPool` frames immediately.
    live_holds: AtomicUsize,
    /// Active `MAP_SHARED` VMAs with `VM_MAYWRITE` (`may_write == true`) across
    /// all processes in the container. `fcntl(F_ADD_SEALS, F_SEAL_WRITE)` fails
    /// with `EBUSY` whenever this count is non-zero (`mm/memfd.c`).
    writable_shared_maps: AtomicUsize,
}

/// Lock-free handle to one `memfd_create(2)` inode's live-reference and
/// writable-shared-mapping counters.
#[derive(Clone, Debug)]
pub struct MemfdHandle {
    counters: Arc<MemfdCounters>,
}

impl Default for MemfdHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl MemfdHandle {
    pub fn new() -> Self {
        Self {
            counters: Arc::new(MemfdCounters {
                live_holds: AtomicUsize::new(0),
                writable_shared_maps: AtomicUsize::new(0),
            }),
        }
    }

    /// Acquires an RAII hold keeping the memfd inode alive until dropped.
    pub fn acquire_hold(&self) -> MemfdHold {
        self.counters.live_holds.fetch_add(1, Ordering::AcqRel);
        MemfdHold {
            counters: Arc::clone(&self.counters),
        }
    }

    /// Acquires an RAII hold representing one `MAP_SHARED` VMA with
    /// `VM_MAYWRITE` (`may_write == true`), preventing `F_SEAL_WRITE` until
    /// dropped.
    pub fn acquire_writable_map(&self) -> MemfdWritableMapHold {
        self.counters
            .writable_shared_maps
            .fetch_add(1, Ordering::AcqRel);
        MemfdWritableMapHold {
            counters: Arc::clone(&self.counters),
        }
    }

    /// Number of live open file descriptions and VMAs keeping this memfd alive.
    pub fn live_holds(&self) -> usize {
        self.counters.live_holds.load(Ordering::Acquire)
    }

    /// Number of active `MAP_SHARED` mappings with `VM_MAYWRITE` on this memfd.
    pub fn writable_shared_maps(&self) -> usize {
        self.counters.writable_shared_maps.load(Ordering::Acquire)
    }

    /// Whether `self` and `other` track the same underlying memfd inode.
    pub fn same_memfd(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.counters, &other.counters)
    }
}

/// RAII hold representing one live open file description or tracked VMA on a
/// `memfd_create(2)` inode. Cloning increments the hold count; dropping
/// decrements it.
#[derive(Debug)]
pub struct MemfdHold {
    counters: Arc<MemfdCounters>,
}

impl Clone for MemfdHold {
    fn clone(&self) -> Self {
        self.counters.live_holds.fetch_add(1, Ordering::AcqRel);
        Self {
            counters: Arc::clone(&self.counters),
        }
    }
}

impl Drop for MemfdHold {
    fn drop(&mut self) {
        self.counters.live_holds.fetch_sub(1, Ordering::AcqRel);
    }
}

/// RAII hold representing one `MAP_SHARED` VMA with `VM_MAYWRITE` on a
/// `memfd_create(2)` inode. Cloning (across `fork` or VMA split) increments
/// the count; dropping (`munmap`, `execve`, process exit) decrements it.
#[derive(Debug)]
pub struct MemfdWritableMapHold {
    counters: Arc<MemfdCounters>,
}

impl Clone for MemfdWritableMapHold {
    fn clone(&self) -> Self {
        self.counters
            .writable_shared_maps
            .fetch_add(1, Ordering::AcqRel);
        Self {
            counters: Arc::clone(&self.counters),
        }
    }
}

impl Drop for MemfdWritableMapHold {
    fn drop(&mut self) {
        self.counters
            .writable_shared_maps
            .fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::MemfdHandle;

    #[test]
    fn holds_and_writable_maps_track_clone_and_drop() {
        let handle = MemfdHandle::new();
        assert_eq!(handle.live_holds(), 0);
        assert_eq!(handle.writable_shared_maps(), 0);

        let hold1 = handle.acquire_hold();
        let hold2 = hold1.clone();
        assert_eq!(handle.live_holds(), 2);

        let map1 = handle.acquire_writable_map();
        let map2 = map1.clone();
        assert_eq!(handle.writable_shared_maps(), 2);

        drop(map1);
        assert_eq!(handle.writable_shared_maps(), 1);
        drop(map2);
        assert_eq!(handle.writable_shared_maps(), 0);

        drop(hold1);
        assert_eq!(handle.live_holds(), 1);
        drop(hold2);
        assert_eq!(handle.live_holds(), 0);
    }
}
