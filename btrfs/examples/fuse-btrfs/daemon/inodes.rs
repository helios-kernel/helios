//! The deterministic map between btrfs inodes and FUSE inode numbers.
//!
//! Linux FUSE's `fuse_export_operations` encodes `(nodeid, generation)` into
//! file handles and re-resolves evicted inodes with `FUSE_LOOKUP(nodeid, ".")`,
//! across both `FUSE_FORGET` (`drop_caches`) and full remount. So `INodeNo` is
//! derived deterministically from the inode's `(tree, number)` relative to the
//! mount's root subvolume, never from a sequential counter:
//!
//! - The mount's root directory is `INodeNo::ROOT` (`1`).
//! - Any other inode in the mount's default subvolume keeps its btrfs inode
//!   number in the low 48 bits (`slot = 0`).
//! - An inode in any other subvolume encodes its tree id in the high 16 bits
//!   (`slot = 1` for `FS_TREE`, `slot = 2 + (tree - FIRST_FREE)` for other
//!   subvolumes) and its inode number in the low 48 bits.
//!
//! Every live entry in [`Inodes`] holds the writer's [`InodeHandle`], the
//! inode's creation generation and the kernel's outstanding lookup count.

use std::collections::HashMap;

use fuser::{Errno, INodeNo};
use helios_btrfs::write::InodeHandle;

/// `BTRFS_FS_TREE_OBJECTID` in `include/uapi/linux/btrfs_tree.h`.
const FS_TREE: u64 = 5;

/// `BTRFS_FIRST_FREE_OBJECTID` in `include/uapi/linux/btrfs_tree.h`.
const FIRST_FREE: u64 = 256;

/// Low 48 bits hold the btrfs inode number (up to 2^48 - 1); high 16 bits hold
/// the subvolume slot.
const INODE_BITS: u32 = 48;
const INODE_MASK: u64 = (1 << INODE_BITS) - 1;
const SLOT_MAX: u64 = u16::MAX as u64;
const FS_TREE_SLOT: u64 = 1;
const FIRST_SUBVOL_SLOT: u64 = 2;

/// An inode within its subvolume tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Identity {
    pub tree: u64,
    pub number: u64,
}

fn encode_identity(root: Identity, identity: Identity) -> Result<INodeNo, Errno> {
    if identity == root {
        return Ok(INodeNo::ROOT);
    }
    if identity.number < FIRST_FREE || identity.number > INODE_MASK {
        return Err(Errno::EOVERFLOW);
    }
    let slot = if identity.tree == root.tree {
        0
    } else if identity.tree == FS_TREE {
        FS_TREE_SLOT
    } else if let Some(offset) = identity.tree.checked_sub(FIRST_FREE) {
        FIRST_SUBVOL_SLOT
            .checked_add(offset)
            .filter(|&slot| slot <= SLOT_MAX)
            .ok_or(Errno::EOVERFLOW)?
    } else {
        return Err(Errno::EIO);
    };
    Ok(INodeNo((slot << INODE_BITS) | identity.number))
}

fn decode_ino(root: Identity, ino: INodeNo) -> Result<Identity, Errno> {
    if ino == INodeNo::ROOT {
        return Ok(root);
    }
    let slot = ino.0 >> INODE_BITS;
    let number = ino.0 & INODE_MASK;
    if number < FIRST_FREE {
        return Err(Errno::ESTALE);
    }
    match slot {
        0 => {
            if number == root.number {
                return Err(Errno::ESTALE);
            }
            Ok(Identity {
                tree: root.tree,
                number,
            })
        }
        FS_TREE_SLOT => {
            if root.tree == FS_TREE {
                return Err(Errno::ESTALE);
            }
            Ok(Identity {
                tree: FS_TREE,
                number,
            })
        }
        slot => {
            let tree = FIRST_FREE + (slot - FIRST_SUBVOL_SLOT);
            if tree == root.tree {
                return Err(Errno::ESTALE);
            }
            Ok(Identity { tree, number })
        }
    }
}

struct Entry {
    generation: u64,
    handle: InodeHandle,
    /// Lookups the kernel has not yet forgotten.
    lookups: u64,
}

pub struct Inodes {
    root: Identity,
    entries: HashMap<u64, Entry>,
}

impl Inodes {
    pub fn new(root: Identity, generation: u64, handle: InodeHandle) -> Self {
        let mut entries = HashMap::new();
        entries.insert(
            INodeNo::ROOT.0,
            Entry {
                generation,
                handle,
                // The kernel never forgets the root.
                lookups: 1,
            },
        );
        Self { root, entries }
    }

    pub fn encode(&self, identity: Identity) -> Result<INodeNo, Errno> {
        encode_identity(self.root, identity)
    }

    pub fn decode(&self, ino: INodeNo) -> Result<Identity, Errno> {
        decode_ino(self.root, ino)
    }

    fn entry(&self, ino: INodeNo) -> Result<&Entry, Errno> {
        self.entries.get(&ino.0).ok_or(Errno::ESTALE)
    }

    /// The inode `ino` names, and the generation it must still have.
    pub fn identity(&self, ino: INodeNo) -> Result<(Identity, u64), Errno> {
        let entry = self.entry(ino)?;
        Ok((self.decode(ino)?, entry.generation))
    }

    /// The recorded generation of `ino` if the kernel still holds a lookup on it.
    pub fn generation(&self, ino: INodeNo) -> Option<u64> {
        self.entries.get(&ino.0).map(|entry| entry.generation)
    }

    pub fn handle(&self, ino: INodeNo) -> Result<InodeHandle, Errno> {
        Ok(self.entry(ino)?.handle.clone())
    }

    /// Whether a live lookup of `ino` at `generation` already holds its handle.
    pub fn has_handle(&self, ino: INodeNo, generation: u64) -> bool {
        self.entries
            .get(&ino.0)
            .is_some_and(|entry| entry.generation == generation)
    }

    /// Records a lookup or creation of `ino` at `generation`. A caller that
    /// passes `None` for `handle` must already have a live entry for `ino` at
    /// `generation`.
    pub fn record(&mut self, ino: INodeNo, generation: u64, handle: Option<InodeHandle>) {
        match self.entries.get_mut(&ino.0) {
            Some(entry) => {
                debug_assert!(
                    entry.generation == generation || handle.is_some(),
                    "generation changed without refreshing the writer handle"
                );
                entry.generation = generation;
                if let Some(handle) = handle {
                    entry.handle = handle;
                }
                entry.lookups += 1;
            }
            None => {
                let handle = handle.expect("new inode entry requires a writer handle");
                self.entries.insert(
                    ino.0,
                    Entry {
                        generation,
                        handle,
                        lookups: 1,
                    },
                );
            }
        }
    }

    pub fn forget(&mut self, ino: INodeNo, count: u64) {
        let Some(entry) = self.entries.get_mut(&ino.0) else {
            return;
        };
        entry.lookups = entry.lookups.saturating_sub(count);
        if entry.lookups == 0 && ino != INodeNo::ROOT {
            self.entries.remove(&ino.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_root_encoding_is_bijective_and_alias_free() {
        let root = Identity {
            tree: FS_TREE,
            number: FIRST_FREE,
        };
        assert_eq!(encode_identity(root, root), Ok(INodeNo::ROOT));
        assert_eq!(decode_ino(root, INodeNo::ROOT), Ok(root));

        let file = Identity {
            tree: FS_TREE,
            number: FIRST_FREE + 1,
        };
        let file_ino = encode_identity(root, file).unwrap();
        assert_eq!(file_ino, INodeNo(FIRST_FREE + 1));
        assert_eq!(decode_ino(root, file_ino), Ok(file));

        let subvol_root = Identity {
            tree: FIRST_FREE,
            number: FIRST_FREE,
        };
        let subvol_file = Identity {
            tree: FIRST_FREE,
            number: FIRST_FREE + 1,
        };
        let second_subvol = Identity {
            tree: FIRST_FREE + 1,
            number: FIRST_FREE + 1,
        };
        let subvol_root_ino = encode_identity(root, subvol_root).unwrap();
        let subvol_file_ino = encode_identity(root, subvol_file).unwrap();
        let second_subvol_ino = encode_identity(root, second_subvol).unwrap();
        assert_ne!(subvol_root_ino, INodeNo::ROOT);
        assert_ne!(subvol_file_ino, file_ino);
        assert_ne!(subvol_file_ino, second_subvol_ino);
        assert_eq!(decode_ino(root, subvol_root_ino), Ok(subvol_root));
        assert_eq!(decode_ino(root, subvol_file_ino), Ok(subvol_file));
        assert_eq!(decode_ino(root, second_subvol_ino), Ok(second_subvol));

        // Invalid and non-canonical node IDs must fail with ESTALE rather than
        // alias the root or an unused slot.
        assert_eq!(decode_ino(root, INodeNo(0)), Err(Errno::ESTALE));
        assert_eq!(decode_ino(root, INodeNo(2)), Err(Errno::ESTALE));
        assert_eq!(decode_ino(root, INodeNo(FIRST_FREE)), Err(Errno::ESTALE));
        assert_eq!(
            decode_ino(root, INodeNo((FS_TREE_SLOT << INODE_BITS) | FIRST_FREE)),
            Err(Errno::ESTALE)
        );
    }

    #[test]
    fn non_default_subvolume_root_encoding_avoids_collisions() {
        let root = Identity {
            tree: FIRST_FREE,
            number: FIRST_FREE,
        };
        assert_eq!(encode_identity(root, root), Ok(INodeNo::ROOT));
        assert_eq!(decode_ino(root, INodeNo::ROOT), Ok(root));

        let fs_tree_root = Identity {
            tree: FS_TREE,
            number: FIRST_FREE,
        };
        let fs_tree_ino = encode_identity(root, fs_tree_root).unwrap();
        assert_eq!(
            fs_tree_ino,
            INodeNo((FS_TREE_SLOT << INODE_BITS) | FIRST_FREE)
        );
        assert_eq!(decode_ino(root, fs_tree_ino), Ok(fs_tree_root));

        // Slot 2 corresponds to tree FIRST_FREE, which is already in slot 0.
        assert_eq!(
            decode_ino(
                root,
                INodeNo((FIRST_SUBVOL_SLOT << INODE_BITS) | (FIRST_FREE + 1))
            ),
            Err(Errno::ESTALE)
        );
    }

    #[test]
    fn encoding_rejects_out_of_range_identities() {
        let root = Identity {
            tree: FS_TREE,
            number: FIRST_FREE,
        };
        assert_eq!(
            encode_identity(
                root,
                Identity {
                    tree: FS_TREE,
                    number: INODE_MASK + 1,
                }
            ),
            Err(Errno::EOVERFLOW)
        );
        assert_eq!(
            encode_identity(
                root,
                Identity {
                    tree: FIRST_FREE + (SLOT_MAX - FIRST_SUBVOL_SLOT) + 1,
                    number: FIRST_FREE,
                }
            ),
            Err(Errno::EOVERFLOW)
        );
        assert_eq!(
            encode_identity(
                root,
                Identity {
                    tree: 2,
                    number: FIRST_FREE,
                }
            ),
            Err(Errno::EIO)
        );
    }
}
