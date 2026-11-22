//! Block-group relocation for `balance`, device shrink (`resize`), and device
//! removal (`device_remove`).
//!
//! Relocating a block group excludes it from new allocations via [`Space::pin`],
//! copies every data extent out of the group (preserving raw on-disk bytes,
//! compression, preallocation, and checksums) and updates all `EXTENT_DATA`
//! references, and CoWs every tree block whose address lies inside the group.
//! Once committed, the emptied block group is deleted by
//! [`Transaction::remove_unused_groups`].

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::num::NonZeroUsize;
use zerocopy::IntoBytes;

use super::Transaction;
use crate::accounting::DataChange;
use crate::allocation::data::DataReference;
use crate::data::Reader;
use crate::items::FileExtent;
use crate::ondisk::{RawFileExtentBody, RawFileExtentHead, item_type, objectid, view};
use crate::source::BlockSink;
use crate::space::{DATA, METADATA, SYSTEM};
use crate::tree::Cursor;
use crate::tree::write::WriteError;
use crate::{Error, Key};

impl<S: BlockSink> Transaction<S> {
    /// Relocates every extent (data, metadata, or system) out of the block
    /// group `[logical, logical + length)`.
    ///
    /// Caller must run this on a clean transaction (after committing any
    /// prior changes). After this returns and commits, the block group has
    /// `used == 0`, so a subsequent commit removes the emptied chunk cleanly.
    pub(crate) async fn relocate_chunk(
        &mut self,
        logical: u64,
        length: u64,
        flags: u64,
        concurrency: NonZeroUsize,
    ) -> Result<(), WriteError> {
        let range = logical..logical + length;
        // Prevent any allocation made during relocation from landing back in
        // the chunk we are emptying.
        self.space.pin(range.clone());

        // Ensure another chunk of the same kind exists to receive the moved
        // extents before we start copying or CoWing (and so `remove_unused_groups`
        // sees at least two groups of that type when deleting the emptied one).
        let groups = self.space.group_summaries();
        if flags & DATA != 0 {
            let count = groups.iter().filter(|(_, _, f, _)| f & DATA != 0).count();
            let (_, free) = self.space.totals(DATA);
            if count <= 1 || free < length {
                let _ = self.grow_data().await?;
            }
        }
        if flags & METADATA != 0 {
            let count = groups
                .iter()
                .filter(|(_, _, f, _)| f & METADATA != 0)
                .count();
            let (_, free) = self.space.totals(METADATA);
            if count <= 1 || free < self.metadata_reserve() + length {
                let _ = self.force_metadata_chunk().await;
            }
        }
        if flags & SYSTEM != 0 {
            let count = groups.iter().filter(|(_, _, f, _)| f & SYSTEM != 0).count();
            let nodesize = u64::from(self.volume.superblock().nodesize());
            let (_, free) = self.space.totals(SYSTEM);
            if count <= 1 || free < nodesize * 16 {
                self.allocate_chunk(SYSTEM).await?;
            }
        }

        if flags & DATA != 0 {
            self.relocate_data_range(&range, concurrency).await?;
        }
        if flags & METADATA != 0 {
            self.relocate_metadata_range(&range).await?;
        }
        if flags & SYSTEM != 0 {
            self.chunk_root = self
                .trees
                .cow_range(
                    &self.volume,
                    self.chunk_root,
                    range.clone(),
                    &mut self.space,
                )
                .await?;
            self.accounting
                .sync_references(&self.volume, &mut self.trees, &mut self.space)
                .await?;
        }
        self.force_commit = true;
        Ok(())
    }

    async fn relocate_data_range(
        &mut self,
        range: &core::ops::Range<u64>,
        concurrency: NonZeroUsize,
    ) -> Result<(), WriteError> {
        let sector = self.volume.superblock().sectorsize();
        type ExtentRefs = Vec<(u64, Key, Vec<u8>)>;
        // Group all file extent references pointing into `range` by their
        // `(disk_bytenr, disk_num_bytes)`.
        let mut by_extent: BTreeMap<(u64, u64), ExtentRefs> = BTreeMap::new();
        let subvols = self.roots.live_subvolume_roots();
        {
            let nodes = self.trees.reader(&self.volume);
            for &(subvol_tree, root) in &subvols {
                let mut cursor = Cursor::ceiling(&nodes, root, Key::new(0, 0, 0)).await?;
                while let (Some(key), Some(bytes)) = (cursor.key(), cursor.item()) {
                    if key.item_type == item_type::EXTENT_DATA {
                        FileExtent::parse(key, bytes, sector).map_err(|defect| Error::Item {
                            tree: subvol_tree,
                            key,
                            defect,
                        })?;
                        let head: &RawFileExtentHead = view(bytes).expect("validated extent");
                        if head.extent_type != 0 {
                            let body: &RawFileExtentBody =
                                view(&bytes[size_of::<RawFileExtentHead>()..])
                                    .expect("validated extent body");
                            let disk_bytenr = body.disk_bytenr.get();
                            let disk_num_bytes = body.disk_num_bytes.get();
                            if disk_bytenr != 0 && range.contains(&disk_bytenr) {
                                by_extent
                                    .entry((disk_bytenr, disk_num_bytes))
                                    .or_default()
                                    .push((subvol_tree, key, bytes.to_vec()));
                            }
                        }
                    }
                    cursor.advance(&nodes).await?;
                }
            }
        }

        for ((old_bytenr, disk_num_bytes), refs) in by_extent {
            // Read raw on-disk extent bytes (preserving compression and prealloc).
            let mut raw_bytes = vec![0_u8; disk_num_bytes as usize];
            let digests = {
                let nodes = self.trees.reader(&self.volume);
                Reader::new(&self.volume, &nodes, self.accounting.checksum_root())
                    .lookup_checksums(old_bytenr, disk_num_bytes as usize)
                    .await
                    .ok()
            };
            let csum_type = self.volume.superblock().csum_type();
            let digest_len = csum_type.size();
            let sector_usize = sector as usize;
            self.volume
                .read_verified(old_bytenr, &mut raw_bytes, |buf| {
                    if let Some(expected) = &digests
                        && expected.len() == (buf.len() / sector_usize) * digest_len
                    {
                        for (idx, chunk) in buf.chunks_exact(sector_usize).enumerate() {
                            let stored = &expected[idx * digest_len..(idx + 1) * digest_len];
                            if !csum_type.verifies(chunk, stored) {
                                return Err(Error::DataChecksum {
                                    logical: old_bytenr + (idx * sector_usize) as u64,
                                });
                            }
                        }
                    }
                    Ok(())
                })
                .await?;

            // Allocate new data extent outside `range` and stage its bytes + checksums.
            self.ensure_data(disk_num_bytes).await?;
            let new_bytenr = self.space.reserve_data(disk_num_bytes)?;
            self.volume
                .stage(new_bytenr, &raw_bytes, concurrency)
                .await?;
            if let Some(digests) = &digests
                && !digests.is_empty()
            {
                self.accounting
                    .store_checksums(
                        &self.volume,
                        &mut self.trees,
                        &mut self.space,
                        new_bytenr,
                        digests,
                    )
                    .await?;
            }

            let new_ext_key = Key::new(new_bytenr, item_type::EXTENT_ITEM, disk_num_bytes);
            let old_ext_key = Key::new(old_bytenr, item_type::EXTENT_ITEM, disk_num_bytes);

            // Register all target references on `new_bytenr` before editing leaves.
            for (idx, (subvol_tree, key, bytes)) in refs.iter().enumerate() {
                let body: &RawFileExtentBody =
                    view(&bytes[size_of::<RawFileExtentHead>()..]).expect("validated extent body");
                let offset = key.offset.wrapping_sub(body.offset.get());
                let reference = DataReference {
                    root: *subvol_tree,
                    inode: key.objectid,
                    offset,
                };
                if idx == 0 {
                    self.accounting
                        .insert_reserved_data(
                            &self.volume,
                            &mut self.trees,
                            &mut self.space,
                            new_ext_key,
                            reference,
                        )
                        .await?;
                } else {
                    self.accounting
                        .update_data(
                            &self.volume,
                            &mut self.trees,
                            &mut self.space,
                            DataChange {
                                key: new_ext_key,
                                reference,
                                delta: 1,
                            },
                        )
                        .await?;
                }
            }

            // Rewrite each `EXTENT_DATA` item to point at `new_bytenr`, sync
            // any CoWed shared leaves, and drop the old reference on `old_bytenr`.
            for (subvol_tree, key, mut bytes) in refs {
                let head_size = size_of::<RawFileExtentHead>();
                let mut body =
                    *view::<RawFileExtentBody>(&bytes[head_size..]).expect("validated extent body");
                let offset = key.offset.wrapping_sub(body.offset.get());
                body.disk_bytenr.set(new_bytenr);
                bytes[head_size..head_size + size_of::<RawFileExtentBody>()]
                    .copy_from_slice(body.as_bytes());
                let subvol_root = self.roots.get(subvol_tree)?;
                let updated_root = self
                    .trees
                    .apply(
                        &self.volume,
                        subvol_root,
                        key,
                        Some(&bytes),
                        &mut self.space,
                    )
                    .await?;
                self.roots.set(updated_root)?;
                self.accounting
                    .sync_references(&self.volume, &mut self.trees, &mut self.space)
                    .await?;
                self.accounting
                    .update_data(
                        &self.volume,
                        &mut self.trees,
                        &mut self.space,
                        DataChange {
                            key: old_ext_key,
                            reference: DataReference {
                                root: subvol_tree,
                                inode: key.objectid,
                                offset,
                            },
                            delta: -1,
                        },
                    )
                    .await?;
            }
        }
        Ok(())
    }

    async fn relocate_metadata_range(
        &mut self,
        range: &core::ops::Range<u64>,
    ) -> Result<(), WriteError> {
        // 1. Live subvolume trees.
        for (tree, root) in self.roots.live_subvolume_roots() {
            let moved = self
                .trees
                .cow_range(&self.volume, root, range.clone(), &mut self.space)
                .await?;
            if moved != root {
                self.roots.set(moved)?;
                let _ = tree;
            }
        }
        // 2. Checksum tree.
        let csum = self.accounting.checksum_root();
        let moved = self
            .trees
            .cow_range(&self.volume, csum, range.clone(), &mut self.space)
            .await?;
        if moved != csum {
            self.accounting.set_checksum_root(moved);
            self.roots.set(moved)?;
        }
        // 3. Dev tree.
        let dev = self.roots.get(objectid::DEV_TREE)?;
        let moved = self
            .trees
            .cow_range(&self.volume, dev, range.clone(), &mut self.space)
            .await?;
        if moved != dev {
            self.roots.set(moved)?;
        }
        // 4. UUID tree (if present).
        if let Some(uuid_root) = self.roots.uuid_root() {
            let moved = self
                .trees
                .cow_range(&self.volume, uuid_root, range.clone(), &mut self.space)
                .await?;
            if moved != uuid_root {
                self.roots.set_uuid_root(moved);
            }
        }
        // 5. Free space tree (if present).
        if let Some(free_root) = self.accounting.free_root() {
            let moved = self
                .trees
                .cow_range(&self.volume, free_root, range.clone(), &mut self.space)
                .await?;
            if moved != free_root {
                self.accounting.set_free_root(moved);
                self.roots.set(moved)?;
            }
        }
        // 6. Block group tree (if separate from extent tree).
        let group_root = self.accounting.group_root();
        if group_root.tree != objectid::EXTENT_TREE {
            let moved = self
                .trees
                .cow_range(&self.volume, group_root, range.clone(), &mut self.space)
                .await?;
            if moved != group_root {
                self.accounting.set_group_root(moved);
                self.roots.set(moved)?;
            }
        }
        // 7. Quota tree (if present).
        if let Some(quota) = &mut self.quota {
            let qroot = quota.root;
            let moved = self
                .trees
                .cow_range(&self.volume, qroot, range.clone(), &mut self.space)
                .await?;
            if moved != qroot {
                quota.root = moved;
                self.roots.set(moved)?;
            }
        }
        // 8. Extent tree.
        let ext = self.accounting.root;
        let moved = self
            .trees
            .cow_range(&self.volume, ext, range.clone(), &mut self.space)
            .await?;
        if moved != ext {
            self.accounting.root = moved;
            self.roots.set(moved)?;
        }
        // 9. Root tree.
        let rroot = self.roots.root;
        let moved = self
            .trees
            .cow_range(&self.volume, rroot, range.clone(), &mut self.space)
            .await?;
        if moved != rroot {
            self.roots.root = moved;
        }
        self.accounting
            .sync_references(&self.volume, &mut self.trees, &mut self.space)
            .await?;
        Ok(())
    }
}
