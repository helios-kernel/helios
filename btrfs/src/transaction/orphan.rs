//! Orphan items and open-handle inode retention (`fs/btrfs/inode.c` and
//! `fs/btrfs/orphan.c` in Linux).
//!
//! When an inode's last directory entry is removed while an open handle still
//! holds it, or when `O_TMPFILE` creates an unnamed regular file, the subvolume
//! tree records an empty `BTRFS_ORPHAN_ITEM_KEY` (48) under
//! `BTRFS_ORPHAN_OBJECTID` (`-5i64 as u64`) with offset equal to the inode
//! number. The inode keeps its data, metadata and extended attributes until the
//! final open handle releases, when its items and orphan record leave in one
//! transaction, or until `hard_link` gives an `O_TMPFILE` a name and removes
//! its orphan record.
//!
//! If a crash leaves orphan items on disk, a writable mount processes every
//! live writable subvolume's orphans before publishing, deleting zero-link
//! inodes, finishing interrupted truncates on linked inodes, and removing stale
//! orphan records.

use alloc::vec::Vec;
use rpds::RedBlackTreeMapSync;

use super::Transaction;
use super::file::{FirstExtent, aligned_end};
use super::reflink::FileId;
use crate::ondisk::{item_type, objectid};
use crate::source::{BlockSink, BlockSource};
use crate::tree::write::WriteError;
use crate::tree::{Cursor, TreeRoot};
use crate::volume::Volume;
use crate::{Error, FileKind, Key};

/// Live open-handle accounting for one inode on a writable mount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpenInode {
    pub(crate) generation: u64,
    pub(crate) handles: usize,
    /// Linux's `I_LINKABLE`: true only for an `O_TMPFILE` created without
    /// `O_EXCL` that has never been linked into a directory.
    pub(crate) linkable: bool,
    /// Whether the subvolume tree holds `(ORPHAN, ORPHAN_ITEM, inode)` for
    /// this inode.
    pub(crate) orphaned: bool,
}

/// What releasing one open handle on an inode leaves behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReleaseOutcome {
    /// Other open handles still hold the inode.
    StillOpen,
    /// The final handle closed, and the inode still has directory links.
    ClosedLinked,
    /// The final handle closed on an orphaned inode; delete the inode and its
    /// orphan item in one transaction.
    DeleteOrphan,
}

/// Persistent map of open inodes held on one [`crate::write::Writer`].
///
/// Cloning for transaction checkpoints and rollbacks is O(1).
#[derive(Clone, Default)]
pub(crate) struct OpenInodes {
    entries: RedBlackTreeMapSync<FileId, OpenInode>,
}

impl OpenInodes {
    pub(crate) fn new() -> Self {
        Self {
            entries: RedBlackTreeMapSync::new_sync(),
        }
    }

    pub(crate) fn is_open(&self, id: FileId) -> bool {
        self.entries.contains_key(&id)
    }

    pub(crate) fn is_linkable(&self, id: FileId) -> bool {
        self.entries.get(&id).is_some_and(|entry| entry.linkable)
    }

    pub(crate) fn has_orphans(&self) -> bool {
        self.entries.values().any(|entry| entry.orphaned)
    }

    /// Records one more open handle on `id` at `generation`.
    pub(crate) fn retain(&mut self, id: FileId, generation: u64) -> Result<(), WriteError> {
        if let Some(&existing) = self.entries.get(&id) {
            if existing.generation != generation {
                return Err(WriteError::StaleHandle {
                    tree: id.tree,
                    inode: id.inode,
                    generation,
                });
            }
            let handles = existing
                .handles
                .checked_add(1)
                .ok_or(WriteError::FileOverflow)?;
            self.entries.insert_mut(
                id,
                OpenInode {
                    handles,
                    ..existing
                },
            );
        } else {
            self.entries.insert_mut(
                id,
                OpenInode {
                    generation,
                    handles: 1,
                    linkable: false,
                    orphaned: false,
                },
            );
        }
        Ok(())
    }

    /// Records a newly created `O_TMPFILE` with one open handle and its
    /// on-disk orphan item already inserted.
    pub(crate) fn insert_tmpfile(&mut self, id: FileId, generation: u64, linkable: bool) {
        self.entries.insert_mut(
            id,
            OpenInode {
                generation,
                handles: 1,
                linkable,
                orphaned: true,
            },
        );
    }

    /// Marks an open inode as orphaned after its last link was removed.
    pub(crate) fn mark_orphaned(&mut self, id: FileId) {
        if let Some(&existing) = self.entries.get(&id) {
            self.entries.insert_mut(
                id,
                OpenInode {
                    linkable: false,
                    orphaned: true,
                    ..existing
                },
            );
        }
    }

    /// Clears the orphan and linkable flags after `hard_link` gives an
    /// `O_TMPFILE` its first name (`nlink` 0 -> 1).
    pub(crate) fn clear_orphan_and_linkable(&mut self, id: FileId) {
        if let Some(&existing) = self.entries.get(&id) {
            self.entries.insert_mut(
                id,
                OpenInode {
                    linkable: false,
                    orphaned: false,
                    ..existing
                },
            );
        }
    }

    /// Releases one open handle on `id` at `generation`.
    pub(crate) fn release(
        &mut self,
        id: FileId,
        generation: u64,
    ) -> Result<ReleaseOutcome, WriteError> {
        let Some(&existing) = self.entries.get(&id) else {
            return Err(WriteError::NotOpen {
                tree: id.tree,
                inode: id.inode,
            });
        };
        if existing.generation != generation {
            return Err(WriteError::StaleHandle {
                tree: id.tree,
                inode: id.inode,
                generation,
            });
        }
        if existing.handles > 1 {
            self.entries.insert_mut(
                id,
                OpenInode {
                    handles: existing.handles - 1,
                    ..existing
                },
            );
            return Ok(ReleaseOutcome::StillOpen);
        }
        self.entries.remove_mut(&id);
        if existing.orphaned {
            Ok(ReleaseOutcome::DeleteOrphan)
        } else {
            Ok(ReleaseOutcome::ClosedLinked)
        }
    }
}

/// Returns every inode number carrying an orphan item in the committed
/// subvolume tree at `root`, in ascending inode order.
pub(crate) async fn committed_orphans<S: BlockSource>(
    volume: &Volume<S>,
    root: TreeRoot,
) -> Result<Vec<u64>, Error> {
    let mut orphans = Vec::new();
    let mut cursor = Cursor::ceiling(
        volume,
        root,
        Key::new(objectid::ORPHAN, item_type::ORPHAN_ITEM, 0),
    )
    .await?;
    while let Some(key) = cursor.key() {
        if !key.is(objectid::ORPHAN, item_type::ORPHAN_ITEM) {
            break;
        }
        orphans.push(key.offset);
        cursor.advance(volume).await?;
    }
    Ok(orphans)
}

impl<S: BlockSink> Transaction<S> {
    /// Inserts the empty orphan item `(ORPHAN, ORPHAN_ITEM, inode)` into
    /// subvolume `tree`: Linux's `btrfs_insert_orphan_item`.
    pub(crate) async fn add_orphan(&mut self, tree: u64, inode: u64) -> Result<(), WriteError> {
        let root = self.roots.get(tree)?;
        let key = Key::new(objectid::ORPHAN, item_type::ORPHAN_ITEM, inode);
        let root = self
            .trees
            .apply(&self.volume, root, key, Some(&[]), &mut self.space)
            .await?;
        self.roots.set(root)
    }

    /// Deletes the orphan item `(ORPHAN, ORPHAN_ITEM, inode)` from subvolume
    /// `tree` if present: Linux's `btrfs_del_orphan_item`.
    pub(crate) async fn remove_orphan(&mut self, tree: u64, inode: u64) -> Result<(), WriteError> {
        let root = self.roots.get(tree)?;
        let key = Key::new(objectid::ORPHAN, item_type::ORPHAN_ITEM, inode);
        let root = self
            .trees
            .apply(&self.volume, root, key, None, &mut self.space)
            .await?;
        self.roots.set(root)
    }

    /// Deletes an orphaned inode and its orphan item in the running
    /// transaction: final handle release (`btrfs_evict_inode`).
    pub(crate) async fn delete_orphan_inode(
        &mut self,
        tree: u64,
        inode: u64,
    ) -> Result<(), WriteError> {
        self.remove_inode(tree, inode).await?;
        self.remove_orphan(tree, inode).await
    }

    /// Processes one orphan item left behind by a crash at writable mount, as
    /// Linux's `btrfs_orphan_cleanup` (`fs/btrfs/inode.c`):
    ///
    /// - missing inode -> remove the stale orphan item;
    /// - `nlink == 0` -> delete all inode records and the orphan item;
    /// - `nlink > 0` -> drop any extents left past `i_size` by an interrupted
    ///   truncate, update `nbytes`, and remove the orphan item.
    pub(crate) async fn cleanup_orphan(&mut self, tree: u64, inode: u64) -> Result<(), WriteError> {
        let (mut raw, metadata) = match self.inode_item(tree, inode).await {
            Ok(found) => found,
            Err(WriteError::Read(Error::MissingInode { .. })) => {
                return self.remove_orphan(tree, inode).await;
            }
            Err(error) => return Err(error),
        };
        if metadata.nlink == 0 {
            return self.delete_orphan_inode(tree, inode).await;
        }
        if metadata.kind == FileKind::Regular {
            let sector = u64::from(self.volume.superblock().sectorsize());
            match self.first_extent(tree, inode).await? {
                FirstExtent::Inline(inline_bytes, _) if metadata.size == 0 => {
                    self.remove_first_item(tree, inode, inline_bytes, &mut raw)
                        .await?;
                    raw.transid.set(self.trees.generation());
                    self.put_inode(tree, inode, raw).await?;
                }
                FirstExtent::Inline(..) => {}
                FirstExtent::None | FirstExtent::Regular => {
                    let from = aligned_end(metadata.size, sector)?;
                    let removed = self
                        .remove_regular_range(tree, inode, from..u64::MAX - u64::MAX % sector)
                        .await?;
                    if removed > 0 {
                        raw.nbytes.set(
                            raw.nbytes
                                .get()
                                .checked_sub(removed)
                                .ok_or(WriteError::FileOverflow)?,
                        );
                        raw.transid.set(self.trees.generation());
                        self.put_inode(tree, inode, raw).await?;
                    }
                }
            }
        }
        self.remove_orphan(tree, inode).await
    }
}
