//! Transaction-owned tree nodes. A writer changes its own records; readers
//! retain the original node. Packing produces fresh blocks and never mutates
//! an address already published by a committed root.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::ops::Range;

use thiserror::Error;
use zerocopy::IntoBytes;

use super::{HEADER_BYTES, ITEM_BYTES, KEY_PTR_BYTES, Node};
use crate::ondisk::{RawHeader, RawItem, RawKey, RawKeyPtr, view};
use crate::{ChecksumType, Key};

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum EditError {
    #[error("item {key} needs {bytes} bytes in a leaf with {capacity} usable bytes")]
    ItemTooLarge {
        key: Key,
        bytes: usize,
        capacity: usize,
    },
}

/// Header identity shared by leaves and branches. The owner supplies a new
/// address and generation only when the transaction allocates its CoW copy.
#[derive(Clone, Copy)]
pub(crate) struct Header {
    raw: RawHeader,
    size: usize,
}

impl Header {
    pub(crate) fn for_level(node: &Node, level: u8) -> Self {
        let mut header = Self::from_node(node);
        header.raw.level = level;
        header
    }

    fn from_node(node: &Node) -> Self {
        Self {
            raw: *view::<RawHeader>(&node.bytes).expect("validated tree header"),
            size: node.bytes.len(),
        }
    }

    fn block(&self, address: u64, generation: u64, owner: u64, count: usize) -> Box<[u8]> {
        let mut bytes = vec![0; self.size].into_boxed_slice();
        let mut raw = self.raw;
        raw.csum.fill(0);
        raw.bytenr.set(address);
        raw.generation.set(generation);
        raw.owner.set(owner);
        raw.nritems.set(count as u32);
        // BTRFS_HEADER_FLAG_WRITTEN: encoded blocks are about to be written. Keep the
        // relocation and backref revision bits while setting the written bit.
        raw.flags.set(raw.flags.get() | 1);
        bytes[..HEADER_BYTES].copy_from_slice(raw.as_bytes());
        bytes
    }

    fn capacity(&self) -> usize {
        self.size - HEADER_BYTES
    }
}

fn raw_key(key: Key) -> RawKey {
    RawKey {
        objectid: key.objectid.into(),
        item_type: key.item_type,
        offset: key.offset.into(),
    }
}

fn checksum(bytes: &mut [u8], kind: ChecksumType) {
    let digest = kind.digest(&bytes[32..]);
    bytes[..32].fill(0);
    bytes[..digest.as_bytes().len()].copy_from_slice(digest.as_bytes());
}

/// A leaf record owns its variable-size payload until the transaction finishes.
#[derive(Clone)]
struct Item {
    key: Key,
    data: Box<[u8]>,
}

impl Item {
    fn bytes(&self) -> usize {
        ITEM_BYTES + self.data.len()
    }
}

pub(crate) struct Leaf {
    header: Header,
    items: Vec<Item>,
}

impl Leaf {
    pub(crate) fn empty(header: Header) -> Self {
        Self {
            header,
            items: Vec::new(),
        }
    }

    pub(crate) fn from_node(node: &Node) -> Self {
        assert_eq!(node.level, 0, "a leaf cannot own branch pointers");
        Self {
            header: Header::from_node(node),
            items: (0..node.nritems)
                .map(|slot| Item {
                    key: node.key(slot),
                    data: node.item(slot).into(),
                })
                .collect(),
        }
    }

    /// Replaces an existing key or inserts one without changing any other key.
    /// Refuse an oversized item before changing the transaction's leaf.
    pub(crate) fn set(&mut self, key: Key, data: &[u8]) -> Result<(), EditError> {
        let capacity = self.header.capacity();
        if data.len() > capacity - ITEM_BYTES {
            return Err(EditError::ItemTooLarge {
                key,
                bytes: data.len(),
                capacity,
            });
        }
        let item = Item {
            key,
            data: data.into(),
        };
        match self.items.binary_search_by_key(&key, |item| item.key) {
            Ok(slot) => self.items[slot] = item,
            Err(slot) => self.items.insert(slot, item),
        }
        Ok(())
    }

    pub(crate) fn remove(&mut self, key: Key) -> bool {
        match self.items.binary_search_by_key(&key, |item| item.key) {
            Ok(slot) => {
                self.items.remove(slot);
                true
            }
            Err(_) => false,
        }
    }

    /// Minimal number of contiguous leaves needed for these ordered items.
    /// A large insertion between two occupied ranges may require three leaves;
    /// assuming a split always produces two loses that case.
    pub(crate) fn partitions(&self) -> Vec<Range<usize>> {
        partitions(self.items.iter().map(Item::bytes), self.header.capacity())
    }

    pub(crate) fn first_key(&self, range: &Range<usize>) -> Option<Key> {
        self.items
            .get(range.start)
            .filter(|_| !range.is_empty())
            .map(|item| item.key)
    }

    pub(crate) fn encode(
        &self,
        range: Range<usize>,
        address: u64,
        generation: u64,
        owner: u64,
        kind: ChecksumType,
    ) -> Box<[u8]> {
        let items = &self.items[range];
        let mut bytes = self.header.block(address, generation, owner, items.len());
        let mut end = bytes.len();
        for (slot, item) in items.iter().enumerate() {
            end -= item.data.len();
            let raw = RawItem {
                key: raw_key(item.key),
                offset: ((end - HEADER_BYTES) as u32).into(),
                size: (item.data.len() as u32).into(),
            };
            let start = HEADER_BYTES + slot * ITEM_BYTES;
            bytes[start..start + ITEM_BYTES].copy_from_slice(raw.as_bytes());
            bytes[end..end + item.data.len()].copy_from_slice(&item.data);
        }
        checksum(&mut bytes, kind);
        bytes
    }
}

/// A child descriptor is independent of the block's allocation lifetime;
/// extent references are updated by the transaction that publishes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Child {
    pub(crate) key: Key,
    pub(crate) address: u64,
    pub(crate) generation: u64,
}

pub(crate) struct Branch {
    header: Header,
    children: Vec<Child>,
}

impl Branch {
    pub(crate) fn new(header: Header, children: Vec<Child>) -> Self {
        Self { header, children }
    }

    pub(crate) fn from_node(node: &Node) -> Self {
        assert_ne!(node.level, 0, "a branch cannot own leaf items");
        Self {
            header: Header::from_node(node),
            children: (0..node.nritems)
                .map(|slot| {
                    let (address, generation) = node.child(slot);
                    Child {
                        key: node.key(slot),
                        address,
                        generation,
                    }
                })
                .collect(),
        }
    }

    /// Replaces one old child with the CoW children produced by its edit.
    /// An empty replacement removes an empty subtree.
    pub(crate) fn replace(&mut self, slot: usize, children: &[Child]) {
        self.children
            .splice(slot..slot + 1, children.iter().copied());
    }

    pub(crate) fn partitions(&self) -> Vec<Range<usize>> {
        partitions(
            self.children.iter().map(|_| KEY_PTR_BYTES),
            self.header.capacity(),
        )
    }

    pub(crate) fn first_key(&self, range: &Range<usize>) -> Option<Key> {
        self.children
            .get(range.start)
            .filter(|_| !range.is_empty())
            .map(|child| child.key)
    }

    pub(crate) fn encode(
        &self,
        range: Range<usize>,
        address: u64,
        generation: u64,
        owner: u64,
        kind: ChecksumType,
    ) -> Box<[u8]> {
        let children = &self.children[range];
        let mut bytes = self
            .header
            .block(address, generation, owner, children.len());
        for (slot, child) in children.iter().enumerate() {
            let raw = RawKeyPtr {
                key: raw_key(child.key),
                blockptr: child.address.into(),
                generation: child.generation.into(),
            };
            let start = HEADER_BYTES + slot * KEY_PTR_BYTES;
            bytes[start..start + KEY_PTR_BYTES].copy_from_slice(raw.as_bytes());
        }
        checksum(&mut bytes, kind);
        bytes
    }
}

fn partitions(sizes: impl Iterator<Item = usize>, capacity: usize) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let (mut start, mut end, mut used) = (0, 0, 0);
    for size in sizes {
        if used + size > capacity {
            ranges.push(start..end);
            start = end;
            used = 0;
        }
        used += size;
        end += 1;
    }
    // An empty root is encoded as an empty leaf; a parent removes an empty
    // child instead of calling encode for it.
    ranges.push(start..end);
    ranges
}
