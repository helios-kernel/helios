//! Data allocation records and counted backreferences. A hash orders ordinary
//! references on disk; the complete identity distinguishes hash collisions.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cmp::Reverse;

use thiserror::Error;
use zerocopy::little_endian::{U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::RawExtent;
use crate::Key;
use crate::csum::data_ref_hash;
use crate::ondisk::{item_type, view};

// BTRFS_EXTENT_FLAG_DATA.
const DATA: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DataReference {
    pub(crate) root: u64,
    pub(crate) inode: u64,
    pub(crate) offset: u64,
}

impl DataReference {
    pub(crate) fn hash(self) -> u64 {
        data_ref_hash(self.root, self.inode, self.offset)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SharedDataReference(pub(crate) u64);

/// The two disk reference layouts share counted update semantics. Ordinary
/// references can collide in their key hash; parent references cannot.
pub(crate) trait DataBackref {
    fn key(&self, address: u64) -> Key;
    fn inline(&self, extent: &DataExtent) -> Option<u32>;
    fn set_inline(&self, extent: &mut DataExtent, count: u32);
    fn decode(&self, bytes: &[u8]) -> Result<Option<u32>, DataDefect>;
    fn encode(&self, count: u32) -> Vec<u8>;
}

impl DataBackref for DataReference {
    fn key(&self, address: u64) -> Key {
        Key::new(address, item_type::EXTENT_DATA_REF, self.hash())
    }
    fn inline(&self, extent: &DataExtent) -> Option<u32> {
        extent.roots.get(self).copied()
    }
    fn set_inline(&self, extent: &mut DataExtent, count: u32) {
        if count == 0 {
            extent.roots.remove(self);
        } else {
            extent.roots.insert(*self, count);
        }
    }
    fn decode(&self, bytes: &[u8]) -> Result<Option<u32>, DataDefect> {
        if bytes.len() != size_of::<RawDataRef>() {
            return Err(DataDefect::Truncated);
        }
        let raw: &RawDataRef = view(bytes).expect("checked data ref size");
        if raw.count.get() == 0 {
            return Err(DataDefect::Count);
        }
        Ok((raw.root.get() == self.root
            && raw.inode.get() == self.inode
            && raw.offset.get() == self.offset)
            .then_some(raw.count.get()))
    }
    fn encode(&self, count: u32) -> Vec<u8> {
        RawDataRef {
            root: self.root.into(),
            inode: self.inode.into(),
            offset: self.offset.into(),
            count: count.into(),
        }
        .as_bytes()
        .to_vec()
    }
}

impl DataBackref for SharedDataReference {
    fn key(&self, address: u64) -> Key {
        Key::new(address, item_type::SHARED_DATA_REF, self.0)
    }
    fn inline(&self, extent: &DataExtent) -> Option<u32> {
        extent.parents.get(&self.0).copied()
    }
    fn set_inline(&self, extent: &mut DataExtent, count: u32) {
        if count == 0 {
            extent.parents.remove(&self.0);
        } else {
            extent.parents.insert(self.0, count);
        }
    }
    fn decode(&self, bytes: &[u8]) -> Result<Option<u32>, DataDefect> {
        let raw: [u8; 4] = bytes.try_into().map_err(|_| DataDefect::Truncated)?;
        let count = u32::from_le_bytes(raw);
        if count == 0 {
            return Err(DataDefect::Count);
        }
        Ok(Some(count))
    }
    fn encode(&self, count: u32) -> Vec<u8> {
        count.to_le_bytes().to_vec()
    }
}

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
struct RawDataRef {
    root: U64,
    inode: U64,
    offset: U64,
    count: U32,
}

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
struct RawSharedRef {
    parent: U64,
    count: U32,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DataDefect {
    #[error("truncated data extent or reference")]
    Truncated,
    #[error("invalid data extent key, flags, or geometry")]
    Geometry,
    #[error("unsupported data reference type {0}")]
    ReferenceType(u8),
    #[error("duplicate data reference")]
    Duplicate,
    #[error("data references are out of order")]
    Order,
    #[error("invalid data reference count")]
    Count,
    #[error("data allocation record is missing")]
    Missing,
}

pub(crate) struct DataExtent {
    pub(crate) refs: u64,
    pub(crate) generation: u64,
    pub(crate) roots: BTreeMap<DataReference, u32>,
    pub(crate) parents: BTreeMap<u64, u32>,
}

impl DataExtent {
    pub(crate) fn new(generation: u64, reference: DataReference) -> Self {
        Self {
            refs: 1,
            generation,
            roots: BTreeMap::from([(reference, 1)]),
            parents: BTreeMap::new(),
        }
    }

    pub(crate) fn parse(key: Key, bytes: &[u8], sector: u32) -> Result<Self, DataDefect> {
        let header: &RawExtent = view(bytes).ok_or(DataDefect::Truncated)?;
        let sector = u64::from(sector);
        if key.item_type != item_type::EXTENT_ITEM
            || header.flags.get() != DATA
            || sector == 0
            || key.objectid == 0
            || key.offset == 0
            || !key.objectid.is_multiple_of(sector)
            || !key.offset.is_multiple_of(sector)
            || key.objectid.checked_add(key.offset).is_none()
        {
            return Err(DataDefect::Geometry);
        }
        let mut result = Self {
            refs: header.refs.get(),
            generation: header.generation.get(),
            roots: BTreeMap::new(),
            parents: BTreeMap::new(),
        };
        let mut rest = &bytes[size_of::<RawExtent>()..];
        let mut previous = None;
        let mut inline = 0_u64;
        while let Some((&kind, payload)) = rest.split_first() {
            let (order, count, size) = match kind {
                item_type::EXTENT_DATA_REF => {
                    let raw: &RawDataRef = view(payload).ok_or(DataDefect::Truncated)?;
                    let reference = DataReference {
                        root: raw.root.get(),
                        inode: raw.inode.get(),
                        offset: raw.offset.get(),
                    };
                    let count = raw.count.get();
                    if result.roots.insert(reference, count).is_some() {
                        return Err(DataDefect::Duplicate);
                    }
                    (reference.hash(), count, size_of::<RawDataRef>())
                }
                item_type::SHARED_DATA_REF => {
                    let raw: &RawSharedRef = view(payload).ok_or(DataDefect::Truncated)?;
                    let parent = raw.parent.get();
                    if parent == 0 || !parent.is_multiple_of(sector) {
                        return Err(DataDefect::Geometry);
                    }
                    let count = raw.count.get();
                    if result.parents.insert(parent, count).is_some() {
                        return Err(DataDefect::Duplicate);
                    }
                    (parent, count, size_of::<RawSharedRef>())
                }
                _ => return Err(DataDefect::ReferenceType(kind)),
            };
            if count == 0 {
                return Err(DataDefect::Count);
            }
            let current = (kind, Reverse(order));
            if previous.is_some_and(|previous| previous > current) {
                return Err(DataDefect::Order);
            }
            previous = Some(current);
            inline = inline
                .checked_add(u64::from(count))
                .ok_or(DataDefect::Count)?;
            rest = &payload[size..];
        }
        // Other references may be stored as independent extent-tree items.
        if result.refs == 0 || result.refs < inline {
            return Err(DataDefect::Count);
        }
        Ok(result)
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut bytes = RawExtent {
            refs: self.refs.into(),
            generation: self.generation.into(),
            flags: DATA.into(),
        }
        .as_bytes()
        .to_vec();
        let mut roots: Vec<_> = self.roots.iter().collect();
        roots.sort_by_key(|(reference, _)| Reverse(reference.hash()));
        for (reference, &count) in roots {
            bytes.push(item_type::EXTENT_DATA_REF);
            bytes.extend_from_slice(
                RawDataRef {
                    root: reference.root.into(),
                    inode: reference.inode.into(),
                    offset: reference.offset.into(),
                    count: count.into(),
                }
                .as_bytes(),
            );
        }
        for (&parent, &count) in self.parents.iter().rev() {
            bytes.push(item_type::SHARED_DATA_REF);
            bytes.extend_from_slice(
                RawSharedRef {
                    parent: parent.into(),
                    count: count.into(),
                }
                .as_bytes(),
            );
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btrfs_disk::items::{ExtentItem, extent_data_ref_hash};
    use btrfs_disk::tree::{DiskKey, KeyType};

    #[test]
    fn data_extent_matches_independent_encoding_and_reference_hashes() {
        let key = Key::new(1 << 20, item_type::EXTENT_ITEM, 16384);
        for (root, inode, offset) in [
            (5, 256, 0),
            (257, 1000, 4096),
            (u64::MAX, u64::MAX, u64::MAX),
        ] {
            let reference = DataReference {
                root,
                inode,
                offset,
            };
            assert_eq!(reference.hash(), extent_data_ref_hash(root, inode, offset));
            let bytes = ExtentItem::to_bytes_data(3, 42, root, inode, offset, 3);
            let parsed = DataExtent::parse(key, &bytes, 4096).unwrap();
            assert_eq!(parsed.roots[&reference], 3);
            assert_eq!(parsed.encode(), bytes);
            for length in 0..bytes.len() {
                let result = DataExtent::parse(key, &bytes[..length], 4096);
                if length == 24 {
                    assert!(result.is_ok());
                } else {
                    assert!(matches!(result, Err(DataDefect::Truncated)));
                }
            }
        }
        let mut extent =
            DataExtent::parse(key, &ExtentItem::to_bytes_data(3, 42, 5, 256, 0, 3), 4096).unwrap();
        extent.parents.insert(4096, 2);
        extent.parents.insert(8192, 4);
        extent.refs += 6;
        let bytes = extent.encode();
        assert_eq!(
            DataExtent::parse(key, &bytes, 4096).unwrap().encode(),
            bytes
        );
        let disk_key = DiskKey {
            objectid: key.objectid,
            key_type: KeyType::ExtentItem,
            offset: key.offset,
        };
        let independent = ExtentItem::parse(&bytes, &disk_key).unwrap();
        assert!(independent.is_data());
        assert_eq!(independent.refs, 9);
        assert_eq!(independent.inline_refs.len(), 3);
    }

    #[test]
    fn data_extents_reject_broken_counts_duplicates_and_order() {
        let key = Key::new(1 << 20, item_type::EXTENT_ITEM, 4096);
        let original = ExtentItem::to_bytes_data(1, 42, 5, 256, 0, 1);
        let mut bytes = original.clone();
        bytes[49..53].fill(0);
        assert!(matches!(
            DataExtent::parse(key, &bytes, 4096),
            Err(DataDefect::Count)
        ));
        bytes[49..53].copy_from_slice(&2_u32.to_le_bytes());
        assert!(matches!(
            DataExtent::parse(key, &bytes, 4096),
            Err(DataDefect::Count)
        ));
        bytes = original.clone();
        bytes.extend_from_slice(&original[24..]);
        assert!(matches!(
            DataExtent::parse(key, &bytes, 4096),
            Err(DataDefect::Duplicate)
        ));
        let mut extent = DataExtent::parse(key, &original, 4096).unwrap();
        extent.parents.insert(4096, 1);
        extent.refs = 2;
        let mut bytes = extent.encode();
        bytes[24..].rotate_left(29);
        assert!(matches!(
            DataExtent::parse(key, &bytes, 4096),
            Err(DataDefect::Order)
        ));
    }
}
