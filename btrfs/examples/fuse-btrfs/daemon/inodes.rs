//! The bidirectional map between btrfs inodes and FUSE inode numbers.
//!
//! The kernel names a file by the `ino` of a past lookup and expects it to
//! stay valid until it forgets it, so the map outlives any one snapshot or
//! transaction. An entry holds the writer's [`InodeHandle`] for the inode:
//! the writer only hands one out through a transaction's lookup or creation,
//! and a mutation needs one.

use std::collections::HashMap;

use fuser::{Errno, INodeNo};
use helios_btrfs::write::InodeHandle;

/// An inode within its subvolume tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Identity {
    pub tree: u64,
    pub number: u64,
}

struct Entry {
    identity: Identity,
    /// The generation the inode was created in, once a lookup or creation
    /// has seen it; a directory listing alone does not know it.
    generation: Option<u64>,
    handle: Option<InodeHandle>,
    /// Lookups the kernel has not yet forgotten.
    lookups: u64,
}

pub struct Inodes {
    by_identity: HashMap<Identity, u64>,
    entries: HashMap<u64, Entry>,
    next: u64,
}

impl Inodes {
    pub fn new(root: Identity, generation: u64, handle: Option<InodeHandle>) -> Self {
        let mut inodes = Self {
            by_identity: HashMap::new(),
            entries: HashMap::new(),
            next: INodeNo::ROOT.0 + 1,
        };
        inodes.by_identity.insert(root, INodeNo::ROOT.0);
        inodes.entries.insert(
            INodeNo::ROOT.0,
            Entry {
                identity: root,
                generation: Some(generation),
                handle,
                // The kernel never forgets the root.
                lookups: 1,
            },
        );
        inodes
    }

    /// Attaches the writer's root [`InodeHandle`] after upgrading a read-only
    /// mount to a writable [`helios_btrfs::write::Writer`].
    pub fn set_root_handle(&mut self, handle: InodeHandle) {
        if let Some(entry) = self.entries.get_mut(&INodeNo::ROOT.0) {
            entry.handle = Some(handle);
        }
    }

    fn entry(&self, ino: INodeNo) -> Result<&Entry, Errno> {
        self.entries.get(&ino.0).ok_or(Errno::ESTALE)
    }

    /// The inode `ino` named, and the generation it must still have.
    pub fn identity(&self, ino: INodeNo) -> Result<(Identity, Option<u64>), Errno> {
        let entry = self.entry(ino)?;
        Ok((entry.identity, entry.generation))
    }

    pub fn handle(&self, ino: INodeNo) -> Result<InodeHandle, Errno> {
        self.entry(ino)?.handle.clone().ok_or(Errno::ESTALE)
    }

    /// Whether a lookup of `identity` at `generation` already has its handle.
    pub fn has_handle(&self, identity: Identity, generation: u64) -> bool {
        self.by_identity
            .get(&identity)
            .and_then(|ino| self.entries.get(ino))
            .is_some_and(|entry| entry.generation == Some(generation) && entry.handle.is_some())
    }

    /// Records a lookup or creation of `identity` at `generation` and returns
    /// its FUSE inode number. A recycled inode number has a different
    /// generation and gets a fresh FUSE number; the old one now fails with
    /// `ESTALE`.
    pub fn record(
        &mut self,
        identity: Identity,
        generation: u64,
        handle: Option<InodeHandle>,
    ) -> INodeNo {
        let known = self
            .by_identity
            .get(&identity)
            .copied()
            .filter(|ino| self.entries[ino].generation.is_none_or(|g| g == generation));
        let ino = known.unwrap_or_else(|| self.allocate(identity));
        let entry = self.entries.get_mut(&ino).expect("recorded entry exists");
        entry.generation = Some(generation);
        if handle.is_some() {
            entry.handle = handle;
        }
        entry.lookups += 1;
        INodeNo(ino)
    }

    /// The FUSE inode number to report for a directory entry the kernel has
    /// not looked up. It carries no lookup count, so the kernel never
    /// forgets it; the cost is one small entry per listed inode.
    pub fn listed(&mut self, identity: Identity) -> INodeNo {
        let ino = match self.by_identity.get(&identity) {
            Some(ino) => *ino,
            None => self.allocate(identity),
        };
        INodeNo(ino)
    }

    fn allocate(&mut self, identity: Identity) -> u64 {
        let ino = self.next;
        self.next += 1;
        self.by_identity.insert(identity, ino);
        self.entries.insert(
            ino,
            Entry {
                identity,
                generation: None,
                handle: None,
                lookups: 0,
            },
        );
        ino
    }

    pub fn forget(&mut self, ino: INodeNo, count: u64) {
        let Some(entry) = self.entries.get_mut(&ino.0) else {
            return;
        };
        entry.lookups = entry.lookups.saturating_sub(count);
        if entry.lookups == 0 && ino != INodeNo::ROOT {
            let identity = entry.identity;
            self.entries.remove(&ino.0);
            if self.by_identity.get(&identity) == Some(&ino.0) {
                self.by_identity.remove(&identity);
            }
        }
    }
}
