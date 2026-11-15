extern crate std;

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use std::fs::File;
use std::os::unix::fs::FileExt;

use btrfs_disk::tree::TreeBlock;
use ferrosys::btrfs::{FormatOptions, format_to};
use ferrosys::{Metadata, Timestamp, TreeBuilder};
use futures_lite::future::block_on;
use helios_hal::io::{IoError, IoResult};

use super::Filesystem;
use crate::source::BlockSource;
use crate::tree::edit::{Header, Leaf};
use crate::tree::write::{MetadataAllocator, Trees, WriteError};
use crate::tree::{Expected, Node, TreeRoot};
use crate::{ChecksumType, Key};

struct Disk(File);

impl BlockSource for Disk {
    fn size_bytes(&self) -> u64 {
        self.0.metadata().unwrap().len()
    }
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> IoResult<()> {
        self.0
            .read_exact_at(buf, offset)
            .map_err(|_| IoError::DeviceFault)
    }
}

fn filesystem() -> Filesystem<Disk> {
    filesystem_image().0
}

fn filesystem_image() -> (Filesystem<Disk>, File) {
    filesystem_image_with_features(true, true)
}

fn filesystem_image_with_features(separate: bool, free_tree: bool) -> (Filesystem<Disk>, File) {
    let mut file = tempfile::tempfile().unwrap();
    // ferrosys' default single-device geometry needs at least 109 MiB.
    let size = 128 << 20;
    file.set_len(size).unwrap();
    let timestamp = Timestamp::from_secs(1_700_000_000);
    let tree = TreeBuilder::new().root(Metadata::new(0o755, timestamp));
    let mut options = FormatOptions::new([0x53; 16], timestamp);
    if !separate {
        options.plan.compat_ro_flags = options
            .plan
            .compat_ro_flags
            .without(ferrosys::btrfs::ondisk::CompatRoFlags::BLOCK_GROUP_TREE);
    }
    if !free_tree {
        options.plan.compat_ro_flags = options
            .plan
            .compat_ro_flags
            .without(ferrosys::btrfs::ondisk::CompatRoFlags::FREE_SPACE_TREE)
            .without(ferrosys::btrfs::ondisk::CompatRoFlags::FREE_SPACE_TREE_VALID);
    }
    format_to(&mut file, tree, size, options).unwrap();
    let reference = file.try_clone().unwrap();
    (block_on(Filesystem::mount(Disk(file))).unwrap(), reference)
}

fn root_node(fs: &Filesystem<Disk>) -> Node {
    let root = fs.default_subvolume.root;
    block_on(Node::read(
        &fs.volume,
        root.bytenr,
        Expected {
            level: root.level,
            generation: root.generation,
            first_key: None,
        },
    ))
    .unwrap()
}

struct Allocator {
    next: u64,
    size: u64,
    remaining: usize,
}

impl MetadataAllocator for Allocator {
    fn revise(&mut self, address: u64, _: Key) {
        assert!(address < self.next);
    }

    fn cancel(&mut self, _: u64) {
        self.remaining += 1;
    }

    fn allocate(&mut self, tree: u64, _: u8, _: Key) -> Result<u64, WriteError> {
        if self.remaining == 0 {
            return Err(WriteError::NoSpace { tree });
        }
        self.remaining -= 1;
        let address = self.next;
        self.next += self.size;
        Ok(address)
    }
}

fn contents(trees: &Trees, root: TreeRoot) -> BTreeMap<Key, Vec<u8>> {
    let blocks: BTreeMap<_, _> = trees.blocks().collect();
    let mut pending = vec![(root.bytenr, root.level, root.generation)];
    let mut result = BTreeMap::new();
    while let Some((address, level, generation)) = pending.pop() {
        let block = TreeBlock::parse(blocks[&address]);
        assert_eq!(block.header().bytenr, address);
        assert_eq!(block.header().level, level);
        assert_eq!(block.header().generation, generation);
        assert_eq!(block.header().owner, root.tree);
        assert!(ChecksumType::Crc32c.verifies(&blocks[&address][32..], &block.header().csum));
        match &block {
            TreeBlock::Leaf { items, .. } => {
                let mut previous = None;
                for (slot, item) in items.iter().enumerate() {
                    let key = Key::new(
                        item.key.objectid,
                        item.key.key_type.to_raw(),
                        item.key.offset,
                    );
                    assert!(previous.is_none_or(|previous| previous < key));
                    assert!(
                        result
                            .insert(key, block.item_data(slot).unwrap().to_vec())
                            .is_none()
                    );
                    previous = Some(key);
                }
            }
            TreeBlock::Node { ptrs, .. } => {
                for ptr in ptrs {
                    pending.push((ptr.blockptr, level - 1, ptr.generation));
                }
            }
        }
    }
    result
}

#[test]
fn large_middle_item_can_require_three_leaves_and_preserves_payloads() {
    let fs = filesystem();
    let original = root_node(&fs);
    let mut leaf = Leaf::empty(Header::for_level(&original, 0));
    let capacity = fs.superblock().nodesize() as usize - 101;
    let small = vec![0x31; capacity / 2 - 25];
    let large = vec![0x72; capacity - 25];
    let left = Key::new(1000, 24, 0);
    let middle = Key::new(1001, 24, 0);
    let right = Key::new(1002, 24, 0);
    leaf.set(left, &small).unwrap();
    leaf.set(right, &small).unwrap();
    assert_eq!(leaf.partitions().len(), 1);
    leaf.set(middle, &large).unwrap();
    let ranges = leaf.partitions();
    assert_eq!(ranges.len(), 3);
    for (range, expected) in
        ranges
            .into_iter()
            .zip([small.as_slice(), large.as_slice(), small.as_slice()])
    {
        let bytes = leaf.encode(range, 32 << 20, 2, 5, ChecksumType::Crc32c);
        let parsed = TreeBlock::parse(&bytes);
        assert_eq!(parsed.item_data(0), Some(expected));
    }
    let oversized = vec![0; capacity];
    assert!(leaf.set(middle, &oversized).is_err());
    let bytes = leaf.encode(1..2, 32 << 20, 2, 5, ChecksumType::Crc32c);
    assert_eq!(
        TreeBlock::parse(&bytes).item_data(0),
        Some(large.as_slice())
    );
}

#[test]
fn cow_insert_replace_delete_preserve_the_original_tree_and_collapse_the_root() {
    block_on(async {
        let fs = filesystem();
        let original = root_node(&fs);
        let mut expected: BTreeMap<_, _> = (0..original.nritems())
            .map(|slot| (original.key(slot), original.item(slot).to_vec()))
            .collect();
        let mut root = fs.default_subvolume.root;
        let mut trees = Trees::new(
            fs.superblock().generation() + 1,
            fs.superblock().csum_type(),
        );
        let mut allocator = Allocator {
            next: 32 << 20,
            size: u64::from(fs.superblock().nodesize()),
            remaining: 10_000,
        };
        // Reverse insertion exercises left-edge separator replacement as well as splits.
        for index in (0..300).rev() {
            let key = Key::new(1000 + index, 24, 0);
            let bytes = vec![index as u8; 257 + index as usize % 17 * 199];
            root = trees
                .apply(&fs.volume, root, key, Some(&bytes), &mut allocator)
                .await
                .unwrap();
            expected.insert(key, bytes);
        }
        assert!(root.level > 0);
        assert_eq!(contents(&trees, root), expected);
        for index in (0..300).step_by(3) {
            let key = Key::new(1000 + index, 24, 0);
            let bytes = vec![0xa9; 7000];
            root = trees
                .apply(&fs.volume, root, key, Some(&bytes), &mut allocator)
                .await
                .unwrap();
            expected.insert(key, bytes);
        }
        assert_eq!(contents(&trees, root), expected);
        for key in expected.keys().copied().collect::<Vec<_>>() {
            root = trees
                .apply(&fs.volume, root, key, None, &mut allocator)
                .await
                .unwrap();
        }
        assert_eq!(root.level, 0);
        assert!(contents(&trees, root).is_empty());
        assert!(!trees.retired().is_empty());
        let reread = root_node(&fs);
        assert_eq!(original.nritems(), reread.nritems());
        for slot in 0..original.nritems() {
            assert_eq!(original.key(slot), reread.key(slot));
            assert_eq!(original.item(slot), reread.item(slot));
        }
    });
}

#[test]
fn splits_propagate_through_internal_nodes_and_deletion_shrinks_multiple_levels() {
    block_on(async {
        let fs = filesystem();
        let mut root = fs.default_subvolume.root;
        let mut trees = Trees::new(
            fs.superblock().generation() + 1,
            fs.superblock().csum_type(),
        );
        let nodesize = fs.superblock().nodesize() as usize;
        let mut allocator = Allocator {
            next: 32 << 20,
            size: nodesize as u64,
            remaining: 10_000,
        };
        // Each payload occupies its own leaf. More leaves than a branch's
        // key-pointer capacity forces a split above the leaf level too.
        let leaves = (nodesize - 101) / 33 + 3;
        let payload = vec![0x75; nodesize - 101 - 25];
        for index in 0..leaves {
            root = trees
                .apply(
                    &fs.volume,
                    root,
                    Key::new(1000 + index as u64, 24, 0),
                    Some(&payload),
                    &mut allocator,
                )
                .await
                .unwrap();
        }
        assert_eq!(root.level, 2);
        let records = contents(&trees, root);
        for index in 0..leaves {
            assert_eq!(records[&Key::new(1000 + index as u64, 24, 0)], payload);
        }
        for index in 0..leaves {
            root = trees
                .apply(
                    &fs.volume,
                    root,
                    Key::new(1000 + index as u64, 24, 0),
                    None,
                    &mut allocator,
                )
                .await
                .unwrap();
        }
        assert_eq!(root.level, 0);
        let original = root_node(&fs);
        let expected: BTreeMap<_, _> = (0..original.nritems())
            .map(|slot| (original.key(slot), original.item(slot).to_vec()))
            .collect();
        assert_eq!(contents(&trees, root), expected);
    });
}

#[test]
fn space_reservations_exclude_existing_extents_and_return_private_allocations() {
    use crate::space::{Space, SpaceError};
    use btrfs_disk::reader::{Traversal, filesystem_open, tree_walk};
    use btrfs_disk::tree::KeyType;

    block_on(async {
        let (fs, reference) = filesystem_image();
        let mut independent = filesystem_open(reference).unwrap();
        let mut occupied = Vec::new();
        tree_walk(
            &mut independent.reader,
            independent.tree_roots[&2].0,
            Traversal::Dfs,
            &mut |block| {
                if let TreeBlock::Leaf { items, .. } = block {
                    for item in items {
                        let length = match item.key.key_type {
                            KeyType::ExtentItem => item.key.offset,
                            KeyType::MetadataItem => u64::from(independent.superblock.nodesize),
                            _ => continue,
                        };
                        occupied.push(item.key.objectid..item.key.objectid + length);
                    }
                }
            },
        )
        .unwrap();
        let mut space = Space::load(&fs.volume, fs.root_tree).await.unwrap();
        let free_root = super::find_root(
            &fs.volume,
            fs.root_tree,
            crate::ondisk::objectid::FREE_SPACE_TREE,
        )
        .await
        .unwrap()
        .root;
        let mut records = BTreeMap::new();
        let mut cursor = crate::tree::Cursor::ceiling(&fs.volume, free_root, Key::new(0, 0, 0))
            .await
            .unwrap();
        while let Some(key) = cursor.key() {
            records.insert(key, cursor.item().unwrap().to_vec());
            cursor.advance(&fs.volume).await.unwrap();
        }
        for group in space
            .committed_free(&alloc::collections::BTreeSet::new())
            .unwrap()
        {
            let key = Key::new(
                group.range.start,
                crate::ondisk::item_type::FREE_SPACE_INFO,
                group.range.end - group.range.start,
            );
            let decoded = crate::free_space::FreeGroup::decode(
                key,
                &records[&key],
                &records,
                u64::from(fs.superblock().sectorsize()),
            )
            .unwrap();
            assert_eq!(decoded.free, group.free);
        }
        let original_available = space.available_metadata();
        let size = u64::from(fs.superblock().nodesize());
        let mut allocated = Vec::new();
        loop {
            match space.allocate(5, 0, Key::new(256, 1, 0)) {
                Ok(address) => {
                    assert!(
                        occupied
                            .iter()
                            .all(|range| address + size <= range.start || range.end <= address)
                    );
                    assert!(
                        fs.volume
                            .chunks()
                            .superblock_stripes()
                            .iter()
                            .all(|range| address + size <= range.start || range.end <= address)
                    );
                    assert!(fs.volume.chunks().map(address, size).is_ok());
                    allocated.push(address);
                }
                Err(WriteError::Space(SpaceError::Exhausted { .. })) => break,
                Err(error) => panic!("unexpected allocation failure: {error}"),
            }
        }
        assert!(!allocated.is_empty());
        let mut unique = allocated.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), allocated.len());
        assert_eq!(space.metadata().count(), allocated.len());
        assert!(!space.cancel_metadata(fs.default_subvolume.root.bytenr));
        // Alternating holes exercise coalescing on both sides of each free.
        for &address in allocated.iter().step_by(2) {
            assert!(space.cancel_metadata(address));
            assert!(!space.cancel_metadata(address));
        }
        for &address in allocated.iter().skip(1).step_by(2) {
            assert!(space.cancel_metadata(address));
        }
        assert_eq!(space.available_metadata(), original_available);
        assert_eq!(space.metadata().count(), 0);
        let address = space.allocate(5, 0, Key::new(256, 1, 0)).unwrap();
        assert_eq!(address, allocated[0]);
    });
}

#[test]
fn repeated_cow_edits_recycle_private_space_and_pin_committed_blocks() {
    let fs = filesystem();
    let mut space = block_on(crate::space::Space::load(&fs.volume, fs.root_tree)).unwrap();
    let available = space.available_metadata();
    let original = fs.default_subvolume.root;
    let mut root = original;
    let mut trees = Trees::new(original.generation + 1, ChecksumType::Crc32c);
    let original_node = root_node(&fs);
    let original_key = original_node.key(0);
    assert_eq!(
        block_on(trees.get(&fs.volume, root, original_key)).unwrap(),
        Some(original_node.item(0).to_vec())
    );
    assert_eq!(
        block_on(trees.get(&fs.volume, root, Key::new(u64::MAX, 0, 0))).unwrap(),
        None
    );
    let key = Key::new(900, 1, 0);
    let mut private_address = None;
    for revision in 0_u64..2048 {
        root = block_on(trees.apply(
            &fs.volume,
            root,
            key,
            Some(&revision.to_le_bytes()),
            &mut space,
        ))
        .unwrap();
        assert_eq!(
            block_on(trees.get(&fs.volume, root, key)).unwrap(),
            Some(revision.to_le_bytes().to_vec())
        );
        assert_eq!(*private_address.get_or_insert(root.bytenr), root.bytenr);
        assert_eq!(trees.blocks().count(), 1);
        assert_eq!(space.metadata().count(), 1);
        assert_eq!(
            space.available_metadata(),
            available - u64::from(fs.volume.superblock().nodesize())
        );
        assert_eq!(
            trees.retired(),
            &[(original.tree, original.bytenr, original.level)]
        );
        assert!(!space.cancel_metadata(original.bytenr));
        let (address, reservation) = space.metadata().next().unwrap();
        assert_eq!(address, root.bytenr);
        assert_eq!(reservation.tree, root.tree);
        assert_eq!(reservation.level, root.level);
        let block = trees.blocks().next().unwrap().1;
        let node = TreeBlock::parse(block);
        let TreeBlock::Leaf { items, .. } = node else {
            panic!("expected leaf")
        };
        assert_eq!(reservation.first.objectid, items[0].key.objectid);
    }
    assert_eq!(contents(&trees, root)[&key], 2047_u64.to_le_bytes());
    assert_eq!(root_node(&fs).level(), original.level);
    loop {
        match space.allocate(5, 0, Key::new(256, 1, 0)) {
            Ok(_) => {}
            Err(WriteError::Space(crate::space::SpaceError::Exhausted { .. })) => break,
            Err(error) => panic!("unexpected allocation failure: {error}"),
        }
    }
    assert_eq!(space.available_metadata(), 0);
    let previous = root.bytenr;
    root = block_on(trees.apply(
        &fs.volume,
        root,
        key,
        Some(&2048_u64.to_le_bytes()),
        &mut space,
    ))
    .unwrap();
    assert_eq!(root.bytenr, previous);
    assert_eq!(contents(&trees, root)[&key], 2048_u64.to_le_bytes());
}

#[test]
fn metadata_accounting_removes_inline_and_external_refs_without_releasing_committed_space() {
    use crate::accounting::{Accounting, MetadataBlock};
    use crate::allocation::MetadataReference;
    use crate::ondisk::{item_type, objectid};
    use crate::space::Space;

    block_on(async {
        let fs = filesystem();
        let original_root = super::find_root(&fs.volume, fs.root_tree, objectid::EXTENT_TREE)
            .await
            .unwrap()
            .root;
        let block = MetadataBlock {
            address: fs.default_subvolume.root.bytenr,
            level: fs.default_subvolume.root.level,
        };
        let size = u64::from(fs.superblock().nodesize());
        let mut trees = Trees::new(fs.superblock().generation() + 1, ChecksumType::Crc32c);
        let mut space = Space::load(&fs.volume, fs.root_tree).await.unwrap();
        let mut accounting = Accounting::new(&fs.volume, original_root, &space)
            .await
            .unwrap();
        let mut key = Key::new(
            block.address,
            item_type::METADATA_ITEM,
            u64::from(block.level),
        );
        let original = match trees.get(&fs.volume, original_root, key).await.unwrap() {
            Some(bytes) => bytes,
            None => {
                key = Key::new(block.address, item_type::EXTENT_ITEM, size);
                trees
                    .get(&fs.volume, original_root, key)
                    .await
                    .unwrap()
                    .unwrap()
            }
        };
        let mut bytes = original.clone();
        assert_eq!(u64::from_le_bytes(bytes[..8].try_into().unwrap()), 1);
        bytes[..8].copy_from_slice(&2_u64.to_le_bytes());
        let root = trees
            .apply(&fs.volume, original_root, key, Some(&bytes), &mut space)
            .await
            .unwrap();
        let parent = MetadataReference::parent(fs.root_tree.bytenr);
        let parent_key = parent.key(block.address);
        let root = trees
            .apply(&fs.volume, root, parent_key, Some(&[]), &mut space)
            .await
            .unwrap();
        accounting.root = root;
        assert!(
            !accounting
                .remove_metadata(
                    &fs.volume,
                    &mut trees,
                    &mut space,
                    block,
                    MetadataReference::root(objectid::FS_TREE)
                )
                .await
                .unwrap()
        );
        let bytes = trees
            .get(&fs.volume, accounting.root, key)
            .await
            .unwrap()
            .unwrap();
        let disk_key = btrfs_disk::tree::DiskKey {
            objectid: key.objectid,
            key_type: if key.item_type == item_type::METADATA_ITEM {
                btrfs_disk::tree::KeyType::MetadataItem
            } else {
                btrfs_disk::tree::KeyType::ExtentItem
            },
            offset: key.offset,
        };
        let independent = btrfs_disk::items::ExtentItem::parse(&bytes, &disk_key).unwrap();
        assert_eq!(independent.refs, 1);
        assert!(independent.inline_refs.is_empty());
        assert_eq!(
            trees
                .get(&fs.volume, accounting.root, parent_key)
                .await
                .unwrap(),
            Some(Vec::new())
        );
        assert!(
            accounting
                .remove_metadata(&fs.volume, &mut trees, &mut space, block, parent)
                .await
                .unwrap()
        );
        assert_eq!(
            trees.get(&fs.volume, accounting.root, key).await.unwrap(),
            None
        );
        assert_eq!(
            trees
                .get(&fs.volume, accounting.root, parent_key)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            trees.get(&fs.volume, original_root, key).await.unwrap(),
            Some(original)
        );
        assert!(!space.cancel_metadata(block.address));
        accounting
            .sync_allocations(&fs.volume, &mut trees, &mut space)
            .await
            .unwrap();
        verify_group_usage(&fs, &trees, &accounting, space.group_root()).await;
    });
}

#[test]
fn metadata_registration_converges_across_extent_tree_growth_and_cancellation() {
    use crate::accounting::Accounting;
    use crate::ondisk::{item_type, objectid};
    use crate::space::Space;

    for (separate, free_tree) in [(false, true), (true, true), (false, false)] {
        block_on(async {
            let fs = filesystem_image_with_features(separate, free_tree).0;
            let extent_root = super::find_root(&fs.volume, fs.root_tree, objectid::EXTENT_TREE)
                .await
                .unwrap()
                .root;
            let mut space = Space::load(&fs.volume, fs.root_tree).await.unwrap();
            let mut trees = Trees::new(
                fs.superblock().generation() + 1,
                fs.superblock().csum_type(),
            );
            let size = u64::from(fs.superblock().nodesize());
            let mut accounting = Accounting::new(&fs.volume, extent_root, &space)
                .await
                .unwrap();
            assert_eq!(accounting.free_root().is_some(), free_tree);
            let mut root = fs.default_subvolume.root;
            // Full leaves force enough allocations to split the extent tree as its
            // own allocation records are registered.
            let count = (size as usize - 101) / 33 + 3;
            let payload = vec![0x56; size as usize - 101 - 25];
            for index in 0..count {
                root = trees
                    .apply(
                        &fs.volume,
                        root,
                        Key::new(1000 + index as u64, 24, 0),
                        Some(&payload),
                        &mut space,
                    )
                    .await
                    .unwrap();
            }
            let mut previously_registered: Vec<Key> = Vec::new();
            for shrink in [false, true] {
                if shrink {
                    for index in 0..count {
                        root = trees
                            .apply(
                                &fs.volume,
                                root,
                                Key::new(1000 + index as u64, 24, 0),
                                None,
                                &mut space,
                            )
                            .await
                            .unwrap();
                    }
                }
                accounting
                    .sync_allocations(&fs.volume, &mut trees, &mut space)
                    .await
                    .unwrap();
                verify_group_usage(&fs, &trees, &accounting, space.group_root()).await;
                let current: BTreeMap<_, _> = space.metadata().collect();
                assert_eq!(current.len(), trees.blocks().count());
                if !shrink {
                    assert!(accounting.root.level > 0);
                }
                for (&address, record) in &current {
                    let skinny = fs.superblock().incompat_flags() & (1 << 8) != 0;
                    let key = if skinny {
                        Key::new(address, item_type::METADATA_ITEM, u64::from(record.level))
                    } else {
                        Key::new(address, item_type::EXTENT_ITEM, size)
                    };
                    let bytes = trees
                        .get(&fs.volume, accounting.root, key)
                        .await
                        .unwrap()
                        .unwrap();
                    let disk_key = btrfs_disk::tree::DiskKey {
                        objectid: address,
                        key_type: if skinny {
                            btrfs_disk::tree::KeyType::MetadataItem
                        } else {
                            btrfs_disk::tree::KeyType::ExtentItem
                        },
                        offset: key.offset,
                    };
                    let independent =
                        btrfs_disk::items::ExtentItem::parse(&bytes, &disk_key).unwrap();
                    assert_eq!(independent.refs, 1);
                    assert_eq!(independent.generation, trees.generation());
                    assert_eq!(independent.inline_refs.len(), 1);
                    assert!(
                        matches!(independent.inline_refs[0], btrfs_disk::items::InlineRef::TreeBlockBackref { root, .. } if root == record.tree)
                    );
                    if !skinny {
                        let first = independent.tree_block_key.unwrap();
                        assert_eq!(first.objectid, record.first.objectid);
                        assert_eq!(first.key_type.to_raw(), record.first.item_type);
                        assert_eq!(first.offset, record.first.offset);
                    }
                }
                for key in previously_registered {
                    if !current.contains_key(&key.objectid) {
                        assert_eq!(
                            trees.get(&fs.volume, accounting.root, key).await.unwrap(),
                            None
                        );
                    }
                }
                previously_registered = current
                    .iter()
                    .map(|(&address, record)| {
                        if fs.superblock().incompat_flags() & (1 << 8) != 0 {
                            Key::new(address, item_type::METADATA_ITEM, u64::from(record.level))
                        } else {
                            Key::new(address, item_type::EXTENT_ITEM, size)
                        }
                    })
                    .collect();
                let stable: Vec<_> = trees
                    .blocks()
                    .map(|(address, bytes)| (address, bytes.to_vec()))
                    .collect();
                let available = space.available_metadata();
                accounting
                    .sync_allocations(&fs.volume, &mut trees, &mut space)
                    .await
                    .unwrap();
                assert_eq!(
                    stable,
                    trees
                        .blocks()
                        .map(|(address, bytes)| (address, bytes.to_vec()))
                        .collect::<Vec<_>>()
                );
                assert_eq!(space.available_metadata(), available);
            }
            assert!(!space.cancel_metadata(fs.default_subvolume.root.bytenr));
        });
    }
}

#[test]
fn cow_blocks_take_the_writing_tree_owner_from_a_shared_original() {
    block_on(async {
        let fs = filesystem();
        let original = fs.default_subvolume.root;
        let mut root = TreeRoot {
            tree: 256,
            ..original
        };
        let mut trees = Trees::new(original.generation + 1, fs.superblock().csum_type());
        let mut space = crate::space::Space::load(&fs.volume, fs.root_tree)
            .await
            .unwrap();
        let payload = vec![0x74; fs.superblock().nodesize() as usize - 101 - 25];
        for index in 0..3 {
            root = trees
                .apply(
                    &fs.volume,
                    root,
                    Key::new(1000 + index, 24, 0),
                    Some(&payload),
                    &mut space,
                )
                .await
                .unwrap();
        }
        assert!(root.level > 0);
        contents(&trees, root);
        for (address, reservation) in space.metadata() {
            let bytes = trees
                .blocks()
                .find(|(candidate, _)| *candidate == address)
                .unwrap()
                .1;
            assert_eq!(TreeBlock::parse(bytes).header().owner, reservation.tree);
            assert_eq!(reservation.tree, 256);
        }
        let original_node = root_node(&fs);
        assert_eq!(original_node.key(0), Key::new(256, 1, 0));
        assert!(
            trees
                .blocks()
                .all(|(address, _)| address != original.bytenr)
        );
    });
}

async fn verify_group_usage(
    fs: &Filesystem<Disk>,
    trees: &Trees,
    accounting: &crate::accounting::Accounting,
    original_groups: TreeRoot,
) {
    use crate::ondisk::item_type;
    let extents = contents(trees, accounting.root);
    let free_records = accounting.free_root().map(|root| contents(trees, root));
    let mut cursor = crate::tree::Cursor::ceiling(&fs.volume, original_groups, Key::new(0, 0, 0))
        .await
        .unwrap();
    let mut groups = 0;
    while let Some(key) = cursor.key() {
        if key.item_type == item_type::BLOCK_GROUP_ITEM {
            let original =
                btrfs_disk::items::BlockGroupItem::parse(cursor.item().unwrap()).unwrap();
            let bytes = trees
                .get(&fs.volume, accounting.group_root(), key)
                .await
                .unwrap()
                .unwrap();
            let group = btrfs_disk::items::BlockGroupItem::parse(&bytes).unwrap();
            let expected: u64 = extents
                .keys()
                .filter(|extent| {
                    key.objectid <= extent.objectid && extent.objectid < key.objectid + key.offset
                })
                .map(|extent| match extent.item_type {
                    item_type::METADATA_ITEM => u64::from(fs.superblock().nodesize()),
                    item_type::EXTENT_ITEM => extent.offset,
                    _ => 0,
                })
                .sum();
            assert_eq!(group.used, expected, "group {key}");
            assert_eq!(group.flags, original.flags);
            assert_eq!(group.chunk_objectid, original.chunk_objectid);
            if let Some(records) = &free_records {
                let info_key = Key::new(key.objectid, item_type::FREE_SPACE_INFO, key.offset);
                let info = btrfs_disk::items::FreeSpaceInfo::parse(&records[&info_key]).unwrap();
                let decoded = crate::free_space::FreeGroup::decode(
                    info_key,
                    &records[&info_key],
                    records,
                    u64::from(fs.superblock().sectorsize()),
                )
                .unwrap();
                let mut expected_free = Vec::new();
                let mut address = key.objectid;
                for extent in extents.keys().filter(|extent| {
                    key.objectid <= extent.objectid
                        && extent.objectid < key.objectid + key.offset
                        && matches!(
                            extent.item_type,
                            item_type::EXTENT_ITEM | item_type::METADATA_ITEM
                        )
                }) {
                    if address < extent.objectid {
                        expected_free.push(address..extent.objectid);
                    }
                    address = extent.objectid
                        + if extent.item_type == item_type::METADATA_ITEM {
                            u64::from(fs.superblock().nodesize())
                        } else {
                            extent.offset
                        };
                }
                if address < key.objectid + key.offset {
                    expected_free.push(address..key.objectid + key.offset);
                }
                assert_eq!(decoded.free.iter().collect::<Vec<_>>(), expected_free);
                assert_eq!(info.extent_count as usize, expected_free.len());
                assert_eq!(
                    expected_free
                        .iter()
                        .map(|range| range.end - range.start)
                        .sum::<u64>()
                        + group.used,
                    key.offset
                );
            }
            groups += 1;
        }
        cursor.advance(&fs.volume).await.unwrap();
    }
    assert!(groups > 0);
}

#[test]
fn root_publication_preparation_converges_with_allocation_accounting() {
    use crate::accounting::Accounting;
    use crate::ondisk::objectid;
    use crate::roots::Roots;
    use crate::space::Space;

    block_on(async {
        let fs = filesystem();
        let mut roots = Roots::load(&fs.volume, fs.root_tree).await.unwrap();
        let mut space = Space::load(&fs.volume, fs.root_tree).await.unwrap();
        let mut accounting = Accounting::new(
            &fs.volume,
            roots.get(objectid::EXTENT_TREE).unwrap(),
            &space,
        )
        .await
        .unwrap();
        let mut trees = Trees::new(
            fs.superblock().generation() + 1,
            fs.superblock().csum_type(),
        );
        let size = u64::from(fs.superblock().nodesize());
        let mut root = roots.get(objectid::FS_TREE).unwrap();
        let payload = vec![0x37; size as usize - 101 - 25];
        for shrink in [false, true] {
            for index in 0..4 {
                root = trees
                    .apply(
                        &fs.volume,
                        root,
                        Key::new(1000 + index, 24, 0),
                        (!shrink).then_some(payload.as_slice()),
                        &mut space,
                    )
                    .await
                    .unwrap();
            }
            roots.set(root).unwrap();
            loop {
                accounting
                    .sync_allocations(&fs.volume, &mut trees, &mut space)
                    .await
                    .unwrap();
                roots.set(accounting.root).unwrap();
                roots.set(accounting.group_root()).unwrap();
                if let Some(root) = accounting.free_root() {
                    roots.set(root).unwrap();
                }
                if !roots
                    .sync(&fs.volume, &mut trees, &mut space, &mut || {
                        panic!("fixture roots have valid extensions")
                    })
                    .await
                    .unwrap()
                {
                    break;
                }
            }
            assert_eq!(roots.uuid_updates().count(), 0);
            for tree in [
                objectid::FS_TREE,
                objectid::EXTENT_TREE,
                objectid::BLOCK_GROUP_TREE,
                objectid::FREE_SPACE_TREE,
            ] {
                let cursor = crate::tree::Cursor::floor(
                    &fs.volume,
                    fs.root_tree,
                    Key::new(tree, crate::ondisk::item_type::ROOT_ITEM, u64::MAX),
                )
                .await
                .unwrap();
                let key = cursor.key().unwrap();
                let original = cursor.item().unwrap().to_vec();
                let bytes = trees
                    .get(&fs.volume, roots.root, key)
                    .await
                    .unwrap()
                    .unwrap();
                let parsed = btrfs_disk::items::RootItem::parse(&bytes).unwrap();
                let root = roots.get(tree).unwrap();
                assert_eq!(parsed.bytenr, root.bytenr);
                assert_eq!(parsed.level, root.level);
                assert_eq!(parsed.generation, root.generation);
                assert_eq!(parsed.generation_v2, root.generation);
                let blocks = trees
                    .blocks()
                    .filter(|(_, bytes)| TreeBlock::parse(bytes).header().owner == tree)
                    .count();
                assert_eq!(parsed.bytes_used, blocks as u64 * size);
                assert_eq!(
                    parsed.uuid,
                    btrfs_disk::items::RootItem::parse(&original).unwrap().uuid
                );
                assert_eq!(
                    trees.get(&fs.volume, fs.root_tree, key).await.unwrap(),
                    Some(original)
                );
            }
            verify_group_usage(&fs, &trees, &accounting, space.group_root()).await;
            assert_eq!(root.level, u8::from(!shrink));
        }
    });
}
