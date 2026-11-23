//! UUID index edits. A key may name several roots; synchronization replaces the
//! set of mappings, never overwrites another root merely because its UUID matches.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use thiserror::Error;

use crate::Key;
use crate::ondisk::item_type;
use crate::source::BlockSource;
use crate::space::Space;
use crate::tree::write::{Trees, WriteError};
use crate::tree::{Cursor, TreeRoot};
use crate::volume::Volume;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UuidDefect {
    #[error("unsupported UUID index item type {0}")]
    Type(u8),
    #[error("UUID index payload has {0} bytes, expected a nonempty root-ID array")]
    Size(usize),
    #[error("UUID index repeats root {0}")]
    Duplicate(u64),
}

pub(crate) fn key(uuid: [u8; 16], kind: u8) -> Key {
    Key::new(
        u64::from_le_bytes(uuid[..8].try_into().unwrap()),
        kind,
        u64::from_le_bytes(uuid[8..].try_into().unwrap()),
    )
}

#[derive(Clone)]
pub(crate) struct UuidTree {
    pub(crate) root: TreeRoot,
    records: BTreeMap<Key, Vec<u8>>,
}

impl UuidTree {
    pub(crate) fn empty(root: TreeRoot) -> Self {
        Self {
            root,
            records: BTreeMap::new(),
        }
    }

    pub(crate) async fn load<S: BlockSource>(
        volume: &Volume<S>,
        root: TreeRoot,
    ) -> Result<Self, WriteError> {
        let mut records = BTreeMap::new();
        let mut cursor = Cursor::ceiling(volume, root, Key::new(0, 0, 0)).await?;
        while let (Some(key), Some(bytes)) = (cursor.key(), cursor.item()) {
            validate(key, bytes).map_err(|defect| WriteError::Uuid { key, defect })?;
            records.insert(key, bytes.to_vec());
            cursor.advance(volume).await?;
        }
        Ok(Self { root, records })
    }

    pub(crate) async fn sync<S: BlockSource>(
        &mut self,
        volume: &Volume<S>,
        trees: &mut Trees,
        space: &mut Space,
        desired: BTreeMap<Key, Vec<u8>>,
    ) -> Result<bool, WriteError> {
        if desired == self.records {
            return Ok(false);
        }
        for &key in self.records.keys().filter(|key| !desired.contains_key(key)) {
            self.root = trees.apply(volume, self.root, key, None, space).await?;
        }
        for (&key, bytes) in &desired {
            if self.records.get(&key) != Some(bytes) {
                self.root = trees
                    .apply(volume, self.root, key, Some(bytes), space)
                    .await?;
            }
        }
        self.records = desired;
        Ok(true)
    }
}

fn validate(key: Key, bytes: &[u8]) -> Result<(), UuidDefect> {
    if !matches!(
        key.item_type,
        item_type::UUID_SUBVOL | item_type::UUID_RECEIVED
    ) {
        return Err(UuidDefect::Type(key.item_type));
    }
    if bytes.is_empty() || !bytes.len().is_multiple_of(size_of::<u64>()) {
        return Err(UuidDefect::Size(bytes.len()));
    }
    let mut seen = BTreeSet::new();
    for bytes in bytes.as_chunks::<8>().0 {
        let tree = u64::from_le_bytes(*bytes);
        if !seen.insert(tree) {
            return Err(UuidDefect::Duplicate(tree));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_key_uses_two_little_endian_words() {
        assert_eq!(
            key(core::array::from_fn(|i| i as u8), item_type::UUID_SUBVOL),
            Key::new(0x0706050403020100, 251, 0x0f0e0d0c0b0a0908)
        );
    }

    #[test]
    fn uuid_records_allow_collisions_but_reject_malformed_arrays() {
        for kind in [item_type::UUID_SUBVOL, item_type::UUID_RECEIVED] {
            let key = key([1; 16], kind);
            let mut bytes = 5_u64.to_le_bytes().to_vec();
            bytes.extend_from_slice(&256_u64.to_le_bytes());
            assert_eq!(validate(key, &bytes), Ok(()));
            assert_eq!(validate(key, &[]), Err(UuidDefect::Size(0)));
            assert_eq!(validate(key, &bytes[..15]), Err(UuidDefect::Size(15)));
            bytes.extend_from_slice(&5_u64.to_le_bytes());
            assert_eq!(validate(key, &bytes), Err(UuidDefect::Duplicate(5)));
        }
        assert_eq!(
            validate(Key::new(1, 250, 2), &5_u64.to_le_bytes()),
            Err(UuidDefect::Type(250))
        );
    }
}
