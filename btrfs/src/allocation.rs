//! Extent-tree records. These describe allocated storage, unlike file extent
//! items, which describe a file's mapping into that storage.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use thiserror::Error;
use zerocopy::little_endian::U64;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::Key;
use crate::ondisk::{MAX_LEVEL, RawKey, item_type, view};

// BTRFS_EXTENT_FLAG_TREE_BLOCK and BTRFS_BLOCK_FLAG_FULL_BACKREF.
const TREE_BLOCK: u64 = 2;
const FULL_BACKREF: u64 = 1 << 8;

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
struct RawExtent {
    refs: U64,
    generation: U64,
    flags: U64,
}

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
struct RawTreeInfo {
    first: RawKey,
    level: u8,
}

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
struct RawBlockRef {
    kind: u8,
    offset: U64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum AllocationDefect {
    #[error("truncated extent record or back-reference")]
    Truncated,
    #[error("invalid metadata extent key, size, flags, or level")]
    Metadata,
    #[error("invalid metadata back-reference type {0}")]
    ReferenceType(u8),
    #[error("duplicate metadata back-reference")]
    Duplicate,
    #[error("metadata back-references are out of order")]
    ReferenceOrder,
    #[error("metadata back-reference is missing")]
    MissingReference,
    #[error("external metadata back-reference has a nonempty payload")]
    ExternalPayload,
    #[error("extent reference count does not cover its inline references")]
    References,
}

/// A metadata back-reference key: either a root identity or a parent block.
#[derive(Clone, Copy)]
pub(crate) struct MetadataReference {
    kind: u8,
    identity: u64,
}

impl MetadataReference {
    pub(crate) fn root(tree: u64) -> Self {
        Self {
            kind: item_type::TREE_BLOCK_REF,
            identity: tree,
        }
    }

    pub(crate) fn parent(address: u64) -> Self {
        Self {
            kind: item_type::SHARED_BLOCK_REF,
            identity: address,
        }
    }

    pub(crate) fn key(self, address: u64) -> Key {
        Key::new(address, self.kind, self.identity)
    }
}

/// Metadata references count roots or parent tree blocks, once per identity.
/// External references remain separate extent-tree items. `refs` counts both;
/// parsing an inline payload alone must not assume it has seen every reference.
pub(crate) struct MetadataExtent {
    refs: u64,
    generation: u64,
    flags: u64,
    level: u8,
    first: Option<Key>,
    roots: BTreeSet<u64>,
    parents: BTreeSet<u64>,
}

impl MetadataExtent {
    pub(crate) fn parse(key: Key, bytes: &[u8], nodesize: u64) -> Result<Self, AllocationDefect> {
        let header: &RawExtent = view(bytes).ok_or(AllocationDefect::Truncated)?;
        if header.flags.get() & !FULL_BACKREF != TREE_BLOCK {
            return Err(AllocationDefect::Metadata);
        }
        let mut rest = &bytes[size_of::<RawExtent>()..];
        let (first, level) = match key.item_type {
            item_type::METADATA_ITEM => (None, key.offset),
            item_type::EXTENT_ITEM if key.offset == nodesize => {
                let info: &RawTreeInfo = view(rest).ok_or(AllocationDefect::Truncated)?;
                rest = &rest[size_of::<RawTreeInfo>()..];
                (Some(Key::from_raw(&info.first)), u64::from(info.level))
            }
            _ => return Err(AllocationDefect::Metadata),
        };
        if level >= u64::from(MAX_LEVEL) {
            return Err(AllocationDefect::Metadata);
        }
        let mut extent = Self {
            refs: header.refs.get(),
            generation: header.generation.get(),
            flags: header.flags.get(),
            level: level as u8,
            first,
            roots: BTreeSet::new(),
            parents: BTreeSet::new(),
        };
        let mut previous = None;
        while !rest.is_empty() {
            let reference: &RawBlockRef = view(rest).ok_or(AllocationDefect::Truncated)?;
            let references = match reference.kind {
                item_type::TREE_BLOCK_REF => &mut extent.roots,
                item_type::SHARED_BLOCK_REF => &mut extent.parents,
                kind => return Err(AllocationDefect::ReferenceType(kind)),
            };
            if !references.insert(reference.offset.get()) {
                return Err(AllocationDefect::Duplicate);
            }
            let current = (reference.kind, reference.offset.get());
            if previous.is_some_and(|(kind, offset)| {
                kind > current.0 || (kind == current.0 && offset < current.1)
            }) {
                return Err(AllocationDefect::ReferenceOrder);
            }
            previous = Some(current);
            rest = &rest[size_of::<RawBlockRef>()..];
        }
        let inline = (extent.roots.len() + extent.parents.len()) as u64;
        if extent.refs == 0 || extent.refs < inline {
            return Err(AllocationDefect::References);
        }
        Ok(extent)
    }

    pub(crate) fn level(&self) -> u8 {
        self.level
    }

    /// Remove exactly one reference, after the caller has looked up its external
    /// key in the same transaction. An empty external item is a real reference;
    /// absence and an empty payload must remain distinguishable.
    pub(crate) fn remove(
        &mut self,
        reference: MetadataReference,
        external: Option<&[u8]>,
    ) -> Result<bool, AllocationDefect> {
        if external.is_some_and(|bytes| !bytes.is_empty()) {
            return Err(AllocationDefect::ExternalPayload);
        }
        let inline = if reference.kind == item_type::TREE_BLOCK_REF {
            &mut self.roots
        } else {
            &mut self.parents
        };
        let found = inline.contains(&reference.identity);
        if found && external.is_some() {
            return Err(AllocationDefect::Duplicate);
        }
        if !found && external.is_none() {
            return Err(AllocationDefect::MissingReference);
        }
        let remaining_inline = (self.roots.len() + self.parents.len()) as u64 - u64::from(found);
        let remaining = self
            .refs
            .checked_sub(1)
            .ok_or(AllocationDefect::References)?;
        if remaining < remaining_inline {
            return Err(AllocationDefect::References);
        }
        let inline = if reference.kind == item_type::TREE_BLOCK_REF {
            &mut self.roots
        } else {
            &mut self.parents
        };
        inline.remove(&reference.identity);
        self.refs = remaining;
        Ok(remaining == 0)
    }

    /// A newly allocated tree block starts with its owning tree's reference.
    pub(crate) fn new(generation: u64, tree: u64, level: u8, first: Option<Key>) -> Self {
        assert!(level < MAX_LEVEL);
        Self {
            refs: 1,
            generation,
            flags: TREE_BLOCK,
            level,
            first,
            roots: BTreeSet::from([tree]),
            parents: BTreeSet::new(),
        }
    }

    pub(crate) fn key(&self, address: u64, nodesize: u64) -> Key {
        match self.first {
            Some(_) => Key::new(address, item_type::EXTENT_ITEM, nodesize),
            None => Key::new(address, item_type::METADATA_ITEM, u64::from(self.level)),
        }
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            RawExtent {
                refs: self.refs.into(),
                generation: self.generation.into(),
                flags: self.flags.into(),
            }
            .as_bytes(),
        );
        if let Some(first) = self.first {
            bytes.extend_from_slice(
                RawTreeInfo {
                    first: RawKey {
                        objectid: first.objectid.into(),
                        item_type: first.item_type,
                        offset: first.offset.into(),
                    },
                    level: self.level,
                }
                .as_bytes(),
            );
        }
        // Inline refs sort by increasing type and decreasing offset.
        for (kind, references) in [
            (item_type::TREE_BLOCK_REF, &self.roots),
            (item_type::SHARED_BLOCK_REF, &self.parents),
        ] {
            for &offset in references.iter().rev() {
                bytes.extend_from_slice(
                    RawBlockRef {
                        kind,
                        offset: offset.into(),
                    }
                    .as_bytes(),
                );
            }
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use btrfs_disk::items::ExtentItem;
    use btrfs_disk::tree::{DiskKey, KeyType};

    use super::*;

    #[test]
    fn metadata_layouts_match_independent_encoder_and_parser() {
        let first = Key::new(256, 1, 0);
        let disk_first = DiskKey {
            objectid: 256,
            key_type: KeyType::InodeItem,
            offset: 0,
        };
        for skinny in [false, true] {
            let extent = MetadataExtent::new(42, 5, 2, (!skinny).then_some(first));
            let key = extent.key(1 << 20, 16384);
            let bytes = extent.encode();
            let reference = if skinny {
                ExtentItem::to_bytes_skinny(1, 42, 5)
            } else {
                ExtentItem::to_bytes_non_skinny(1, 42, 5, &disk_first, 2)
            };
            assert_eq!(bytes, reference);
            let parsed = MetadataExtent::parse(key, &reference, 16384).unwrap();
            assert_eq!(parsed.encode(), reference);
            let disk_key = DiskKey {
                objectid: key.objectid,
                key_type: if skinny {
                    KeyType::MetadataItem
                } else {
                    KeyType::ExtentItem
                },
                offset: key.offset,
            };
            let independent = ExtentItem::parse(&bytes, &disk_key).unwrap();
            assert_eq!(independent.refs, 1);
            assert_eq!(independent.generation, 42);
            assert!(independent.is_tree_block());
            assert_eq!(independent.inline_refs.len(), 1);
            assert_eq!(independent.skinny_level, skinny.then_some(2));
            assert_eq!(independent.tree_block_level, (!skinny).then_some(2));
            let header_len = if skinny { 24 } else { 42 };
            for length in 0..bytes.len() {
                let result = MetadataExtent::parse(key, &bytes[..length], 16384);
                if length == header_len {
                    // A record may keep all its references in separate items.
                    assert!(result.is_ok());
                } else {
                    assert!(
                        matches!(result, Err(AllocationDefect::Truncated)),
                        "length {length}"
                    );
                }
            }
        }
    }

    #[test]
    fn metadata_rejects_inconsistent_references_and_geometry() {
        let key = Key::new(1 << 20, item_type::METADATA_ITEM, 0);
        let original = ExtentItem::to_bytes_skinny(1, 42, 5);
        let mut bytes = original.clone();
        bytes.extend_from_slice(&original[24..]);
        assert!(matches!(
            MetadataExtent::parse(key, &bytes, 16384),
            Err(AllocationDefect::Duplicate)
        ));
        bytes[33] = item_type::SHARED_BLOCK_REF;
        assert!(matches!(
            MetadataExtent::parse(key, &bytes, 16384),
            Err(AllocationDefect::References)
        ));
        bytes[..8].copy_from_slice(&2_u64.to_le_bytes());
        let parsed = MetadataExtent::parse(key, &bytes, 16384).unwrap();
        assert_eq!(parsed.roots, BTreeSet::from([5]));
        assert_eq!(parsed.parents, BTreeSet::from([5]));
        assert_eq!(parsed.encode(), bytes);
        bytes[24] = 178; // BTRFS_EXTENT_DATA_REF_KEY is invalid for a metadata block.
        assert!(matches!(
            MetadataExtent::parse(key, &bytes, 16384),
            Err(AllocationDefect::ReferenceType(178))
        ));
        assert!(matches!(
            MetadataExtent::parse(Key::new(key.objectid, key.item_type, 8), &original, 16384),
            Err(AllocationDefect::Metadata)
        ));
        assert!(matches!(
            MetadataExtent::parse(
                Key::new(key.objectid, item_type::EXTENT_ITEM, 4096),
                &original,
                16384
            ),
            Err(AllocationDefect::Metadata)
        ));
        let mut ordered = MetadataExtent::new(42, 5, 0, None);
        ordered.roots.insert(256);
        ordered.refs = 2;
        let mut unordered = ordered.encode();
        let high = unordered[24..33].to_vec();
        let low = unordered[33..42].to_vec();
        unordered[24..33].copy_from_slice(&low);
        unordered[33..42].copy_from_slice(&high);
        assert!(matches!(
            MetadataExtent::parse(key, &unordered, 16384),
            Err(AllocationDefect::ReferenceOrder)
        ));
        bytes = original;
        bytes[..8].fill(0);
        assert!(matches!(
            MetadataExtent::parse(key, &bytes, 16384),
            Err(AllocationDefect::References)
        ));
    }
}
