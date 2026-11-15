//! Transaction-owned root items. Updating their tree pointers does not publish
//! them: the root tree itself remains in the CoW overlay until superblock commit.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use zerocopy::IntoBytes;

use crate::items::RootRecord;
use crate::ondisk::{RawRootItem, RawRootTail, item_type, objectid, view};
use crate::source::BlockSource;
use crate::space::Space;
use crate::tree::write::{Trees, WriteError};
use crate::tree::{Cursor, TreeRoot};
use crate::volume::Volume;
use crate::{Error, Key};

struct RootItem {
    key: Key,
    root: TreeRoot,
    initial_used: u64,
    bytes: Vec<u8>,
}

impl RootItem {
    fn parse(key: Key, bytes: &[u8], sector: u32) -> Result<Self, Error> {
        let record = RootRecord::parse(key, bytes, sector).map_err(|defect| Error::Item {
            tree: objectid::ROOT_TREE,
            key,
            defect,
        })?;
        let head: &RawRootItem = view(bytes).expect("validated root item");
        Ok(Self {
            key,
            root: record.root,
            initial_used: head.bytes_used.get(),
            bytes: bytes.to_vec(),
        })
    }

    /// Returns the replacement UUID when an old-format or invalid extension
    /// needs initialization. The transaction must update its UUID index before
    /// publication; callers cannot treat this as a purely structural edit.
    fn encode(&mut self, used: u64, new_uuid: &mut impl FnMut() -> [u8; 16]) -> Option<[u8; 16]> {
        let head_size = size_of::<RawRootItem>();
        let full_size = head_size + size_of::<RawRootTail>();
        let mut head = *view::<RawRootItem>(&self.bytes).expect("validated root item");
        let valid_tail = view::<RawRootTail>(&self.bytes[head_size..])
            .is_some_and(|tail| tail.generation_v2.get() == head.generation.get());
        let initialized = if valid_tail {
            None
        } else {
            if self.bytes.len() < full_size {
                self.bytes.resize(full_size, 0);
            }
            self.bytes[head_size..full_size].fill(0);
            Some(new_uuid())
        };
        let mut tail =
            *view::<RawRootTail>(&self.bytes[head_size..]).expect("initialized root extension");
        if let Some(uuid) = initialized {
            tail.uuid = uuid;
        }
        head.generation.set(self.root.generation);
        head.bytenr.set(self.root.bytenr);
        head.level = self.root.level;
        head.bytes_used.set(used);
        tail.generation_v2.set(self.root.generation);
        self.bytes[..head_size].copy_from_slice(head.as_bytes());
        self.bytes[head_size..full_size].copy_from_slice(tail.as_bytes());
        initialized
    }
}

pub(crate) struct Roots {
    pub(crate) root: TreeRoot,
    entries: BTreeMap<u64, RootItem>,
    uuid_updates: BTreeMap<u64, [u8; 16]>,
}

impl Roots {
    pub(crate) async fn load<S: BlockSource>(
        volume: &Volume<S>,
        root: TreeRoot,
    ) -> Result<Self, WriteError> {
        let mut entries = BTreeMap::new();
        let mut cursor = Cursor::ceiling(volume, root, Key::new(0, 0, 0)).await?;
        while let (Some(key), Some(bytes)) = (cursor.key(), cursor.item()) {
            if key.item_type == item_type::ROOT_ITEM {
                // Cursor order selects the newest root-item offset for a tree,
                // matching the read path's find_root lookup.
                entries.insert(
                    key.objectid,
                    RootItem::parse(key, bytes, volume.superblock().sectorsize())?,
                );
            }
            cursor.advance(volume).await?;
        }
        Ok(Self {
            root,
            entries,
            uuid_updates: BTreeMap::new(),
        })
    }

    pub(crate) fn get(&self, tree: u64) -> Result<TreeRoot, WriteError> {
        self.entries
            .get(&tree)
            .map(|entry| entry.root)
            .ok_or_else(|| Error::MissingRoot { tree }.into())
    }

    pub(crate) fn set(&mut self, root: TreeRoot) -> Result<(), WriteError> {
        self.entries
            .get_mut(&root.tree)
            .ok_or(Error::MissingRoot { tree: root.tree })?
            .root = root;
        Ok(())
    }

    pub(crate) fn uuid_updates(&self) -> impl Iterator<Item = (u64, [u8; 16])> + '_ {
        self.uuid_updates.iter().map(|(&tree, &uuid)| (tree, uuid))
    }

    /// Root bytes_used counts tree blocks reachable through that root, including
    /// shared blocks. A replaced committed node stops contributing even while
    /// its physical extent remains pinned for another root or an older reader.
    pub(crate) async fn sync<S: BlockSource>(
        &mut self,
        volume: &Volume<S>,
        trees: &mut Trees,
        space: &mut Space,
        new_uuid: &mut impl FnMut() -> [u8; 16],
    ) -> Result<bool, WriteError> {
        let size = u64::from(volume.superblock().nodesize());
        let mut changes = BTreeMap::<u64, (u64, u64)>::new();
        for (_, record) in space.metadata() {
            changes.entry(record.tree).or_default().0 += size;
        }
        for &(tree, _, _) in trees.retired() {
            changes.entry(tree).or_default().1 += size;
        }
        let mut changed = false;
        for (&tree, entry) in &mut self.entries {
            let (added, removed) = changes.get(&tree).copied().unwrap_or_default();
            let used = entry
                .initial_used
                .checked_add(added)
                .and_then(|used| used.checked_sub(removed))
                .ok_or(WriteError::RootUsage {
                    tree,
                    used: entry.initial_used,
                    added,
                    removed,
                })?;
            let head: &RawRootItem = view(&entry.bytes).expect("validated root item");
            if head.bytenr.get() == entry.root.bytenr
                && head.generation.get() == entry.root.generation
                && head.level == entry.root.level
                && head.bytes_used.get() == used
            {
                continue;
            }
            if let Some(uuid) = entry.encode(used, new_uuid) {
                self.uuid_updates.insert(tree, uuid);
            }
            self.root = trees
                .apply(volume, self.root, entry.key, Some(&entry.bytes), space)
                .await?;
            changed = true;
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use btrfs_disk::items::RootItem as DiskRoot;

    use super::*;

    #[test]
    fn root_updates_preserve_valid_extensions_and_unrelated_fields() {
        let mut reference = DiskRoot::new_internal(42, 1 << 20, 0);
        reference.bytes_used = 4096;
        reference.byte_limit = 1 << 30;
        reference.ctransid = 31;
        reference.otransid = 7;
        reference.last_snapshot = 23;
        reference.inode_data.fill(0x25);
        let mut bytes = reference.to_bytes();
        let uuid_offset = size_of::<RawRootItem>() + size_of::<u64>();
        bytes[uuid_offset..uuid_offset + 16].fill(0x63);
        bytes.extend_from_slice(&[0x91; 16]);
        let before = DiskRoot::parse(&bytes).unwrap();
        let mut item = RootItem::parse(Key::new(5, item_type::ROOT_ITEM, 0), &bytes, 4096).unwrap();
        item.root.bytenr += 4096;
        item.root.generation += 1;
        item.root.level = 1;
        assert!(
            item.encode(12288, &mut || panic!("valid extension needs no UUID"))
                .is_none()
        );
        let after = DiskRoot::parse(&item.bytes).unwrap();
        assert_eq!(after.bytenr, item.root.bytenr);
        assert_eq!(after.generation, 43);
        assert_eq!(after.generation_v2, 43);
        assert_eq!(after.level, 1);
        assert_eq!(after.bytes_used, 12288);
        assert_eq!(after.uuid, before.uuid);
        assert_eq!(after.parent_uuid, before.parent_uuid);
        assert_eq!(after.received_uuid, before.received_uuid);
        assert_eq!(after.inode_data, before.inode_data);
        assert_eq!(after.byte_limit, before.byte_limit);
        assert_eq!(after.last_snapshot, before.last_snapshot);
        assert_eq!(after.ctransid, before.ctransid);
        assert_eq!(after.otransid, before.otransid);
        let full_size = size_of::<RawRootItem>() + size_of::<RawRootTail>();
        assert_eq!(&item.bytes[full_size..], &[0x91; 16]);
    }

    #[test]
    fn legacy_and_stale_root_extensions_get_one_new_uuid() {
        let mut reference = DiskRoot::new_internal(42, 1 << 20, 0);
        reference.bytes_used = 4096;
        reference.generation_v2 = 41;
        reference.ctransid = 29;
        reference.otransid = 5;
        let bytes = reference.to_bytes();
        for length in [
            size_of::<RawRootItem>(),
            size_of::<RawRootItem>() + 9,
            bytes.len(),
        ] {
            let mut item =
                RootItem::parse(Key::new(5, item_type::ROOT_ITEM, 0), &bytes[..length], 4096)
                    .unwrap();
            item.root.generation = 43;
            let uuid = [0x47; 16];
            assert_eq!(item.encode(4096, &mut || uuid), Some(uuid));
            let parsed = DiskRoot::parse(&item.bytes).unwrap();
            assert_eq!(parsed.uuid.as_bytes(), &uuid);
            assert_eq!(parsed.generation_v2, 43);
            assert_eq!(parsed.ctransid, 0);
            assert_eq!(parsed.otransid, 0);
            item.root.generation = 44;
            assert!(
                item.encode(4096, &mut || panic!("extension is already initialized"))
                    .is_none()
            );
            assert_eq!(DiskRoot::parse(&item.bytes).unwrap().uuid.as_bytes(), &uuid);
        }
    }
}
