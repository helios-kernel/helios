//! Per-container POSIX named-FIFO (`S_IFIFO`) rendezvous registry.
//!
//! Each named FIFO node is keyed by its `(DeviceId, inode)` identity so
//! multiple paths (including hard links and concurrent opens) share one
//! [`FifoPipe`] ring inside the container while remaining isolated from every
//! other container.
//!
//! # Concurrency contract
//!
//! The registry map is guarded by a short synchronous `spin::Mutex`, never
//! held across an `.await`. Blocking `O_RDONLY` and `O_WRONLY` rendezvous
//! waits run on the [`FifoPipe`] itself after releasing the registry lock.

extern crate alloc;

use alloc::collections::BTreeMap;
use helios_hal::fs::DeviceId;
use helios_unix::{FifoPipe, PipeInode};
use triomphe::Arc;

/// Stable node identity of a named FIFO within a container.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FifoKey {
    pub device: u64,
    pub inode: u64,
}

impl FifoKey {
    pub const fn new(device: DeviceId, inode: u64) -> Self {
        Self {
            device: device.raw(),
            inode,
        }
    }
}

/// Container-owned table of active named FIFO rings.
#[derive(Clone, Default)]
pub struct FifoRegistry {
    entries: Arc<spin::Mutex<BTreeMap<FifoKey, FifoPipe>>>,
}

impl FifoRegistry {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(spin::Mutex::new(BTreeMap::new())),
        }
    }

    /// Returns the active [`FifoPipe`] for `key`, creating a fresh ring if none
    /// is currently open, and prunes any idle entries from previous closed
    /// generations.
    pub fn get_or_create(&self, key: FifoKey, uid: u32, gid: u32, mode: u32) -> FifoPipe {
        let mut map = self.entries.lock();
        map.retain(|&existing_key, pipe| existing_key == key || !pipe.is_idle());
        if let Some(existing) = map.get(&key)
            && !existing.is_idle()
        {
            existing.inode().set_owner_and_mode(uid, gid, mode);
            return existing.clone();
        }
        let inode = PipeInode::with_identity(key.device, key.inode, uid, gid, mode);
        let pipe = FifoPipe::new(inode);
        map.insert(key, pipe.clone());
        pipe
    }

    /// Removes the registry entry for `key` if it has no active readers or
    /// writers. Active descriptors keep their own `Arc` to the pipe ring.
    pub fn prune_if_idle(&self, key: FifoKey) {
        let mut map = self.entries.lock();
        if let Some(pipe) = map.get(&key)
            && pipe.is_idle()
        {
            map.remove(&key);
        }
    }
}
