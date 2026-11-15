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
    let mut file = tempfile::tempfile().unwrap();
    // ferrosys' default single-device geometry needs at least 109 MiB.
    let size = 128 << 20;
    file.set_len(size).unwrap();
    let timestamp = Timestamp::from_secs(1_700_000_000);
    let tree = TreeBuilder::new().root(Metadata::new(0o755, timestamp));
    format_to(
        &mut file,
        tree,
        size,
        FormatOptions::new([0x53; 16], timestamp),
    )
    .unwrap();
    block_on(Filesystem::mount(Disk(file))).unwrap()
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
        let bytes = leaf.encode(range, 32 << 20, 2, ChecksumType::Crc32c);
        let parsed = TreeBlock::parse(&bytes);
        assert_eq!(parsed.item_data(0), Some(expected));
    }
    let oversized = vec![0; capacity];
    assert!(leaf.set(middle, &oversized).is_err());
    let bytes = leaf.encode(1..2, 32 << 20, 2, ChecksumType::Crc32c);
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
