//! Multi-device administration (`device_add`, `device_remove`,
//! `device_replace`, `resize_device`, and `list_devices`).

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use zerocopy::{FromZeros, IntoBytes};

use helios_hal::fs_management::{ResizeTarget, VolumeDeviceInfo};

use super::Transaction;
use super::chunks::ChunkError;
use crate::ondisk::{
    RawChunk, RawDevItem, RawKey, RawStripe, STRIPE_LEN, item_type, objectid, view,
};
use crate::source::{BlockSink, READ_ALIGNMENT};
use crate::space::SYSTEM;
use crate::tree::write::WriteError;
use crate::volume::Volume;
use crate::{Error, Key};

/// Minimum usable size of a btrfs device (`BTRFS_DEVICE_RANGE_RESERVED` = 1 MiB
/// plus at least one 64 KiB stripe).
const MIN_DEVICE_BYTES: u64 = (1 << 20) + STRIPE_LEN;

/// Copy window for `device_replace` extent transfers.
const REPLACE_COPY_WINDOW: usize = 128 * 1024;

impl<S: BlockSink> Transaction<S> {
    /// Lists every `DEV_ITEM` recorded in the chunk tree.
    pub(crate) async fn list_devices(&self) -> Result<Vec<VolumeDeviceInfo>, WriteError> {
        let items = self.all_dev_items().await?;
        Ok(items
            .into_iter()
            .map(|(devid, raw)| VolumeDeviceInfo {
                devid,
                uuid: raw.uuid,
                total_bytes: raw.total_bytes.get(),
                bytes_used: raw.bytes_used.get(),
                serial: None,
            })
            .collect())
    }

    /// Adds a new backing device `device` to the volume, inserting its
    /// `DEV_ITEM` in `CHUNK_TREE` and attaching it to `self.volume` so commit
    /// writes its superblocks.
    pub(crate) async fn add_device(
        &mut self,
        device: Arc<S>,
        new_uuid: [u8; 16],
    ) -> Result<VolumeDeviceInfo, WriteError> {
        let sb = self.volume.superblock();
        let sector = u64::from(sb.sectorsize());
        let total_bytes = device.size_bytes() / sector * sector;
        if total_bytes < MIN_DEVICE_BYTES {
            return Err(WriteError::DeviceTooSmall {
                required: MIN_DEVICE_BYTES,
                available: total_bytes,
            });
        }
        let items = self.all_dev_items().await?;
        let new_devid = items
            .iter()
            .map(|(id, _)| *id)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(WriteError::IdentifierExhausted {
                tree: objectid::CHUNK_TREE,
            })?;

        let mut dev_item = RawDevItem::new_zeroed();
        dev_item.devid.set(new_devid);
        dev_item.total_bytes.set(total_bytes);
        dev_item.bytes_used.set(0);
        dev_item.io_align.set(sb.sectorsize());
        dev_item.io_width.set(sb.sectorsize());
        dev_item.sector_size.set(sb.sectorsize());
        dev_item.uuid = new_uuid;
        dev_item.fsid = sb.metadata_fsid();

        self.chunk_root = self
            .trees
            .apply(
                &self.volume,
                self.chunk_root,
                Key::new(objectid::DEV_ITEMS, item_type::DEV_ITEM, new_devid),
                Some(dev_item.as_bytes()),
                &mut self.space,
            )
            .await?;

        self.volume.add_device(new_devid, device);
        self.force_commit = true;

        Ok(VolumeDeviceInfo {
            devid: new_devid,
            uuid: new_uuid,
            total_bytes,
            bytes_used: 0,
            serial: None,
        })
    }

    /// Removes `devid` once all chunks on it have been relocated off it.
    /// Returns the detached [`Arc<S>`] so the caller can wipe its superblocks
    /// after committing the updated remaining devices.
    pub(crate) async fn finish_remove_device(&mut self, devid: u64) -> Result<Arc<S>, WriteError> {
        let items = self.all_dev_items().await?;
        if items.len() <= 1 {
            return Err(WriteError::LastDevice);
        }
        let Some((_, dev)) = items.iter().find(|(id, _)| *id == devid) else {
            return Err(WriteError::DeviceNotFound { devid });
        };
        let (extents, _) = self.device_extents(devid).await?;
        if !extents.is_empty() || dev.bytes_used.get() != 0 {
            return Err(WriteError::Chunk(ChunkError::NoDeviceSpace {
                flags: 0,
                largest: 0,
                needed: dev.bytes_used.get(),
            }));
        }
        self.chunk_root = self
            .trees
            .apply(
                &self.volume,
                self.chunk_root,
                Key::new(objectid::DEV_ITEMS, item_type::DEV_ITEM, devid),
                None,
                &mut self.space,
            )
            .await?;
        let removed = self
            .volume
            .remove_device(devid)
            .ok_or(WriteError::DeviceNotFound { devid })?;
        self.force_commit = true;
        Ok(removed)
    }

    /// Replaces `source_devid` in place with `target`, copying all allocated
    /// device extents, updating `DEV_ITEM` and every `CHUNK_ITEM` stripe UUID
    /// (and `sys_chunk_array`), and returning the detached source device so the
    /// caller can wipe its superblocks after commit.
    pub(crate) async fn replace_device(
        &mut self,
        source_devid: u64,
        target: Arc<S>,
        new_uuid: [u8; 16],
    ) -> Result<(VolumeDeviceInfo, Arc<S>), WriteError> {
        let items = self.all_dev_items().await?;
        let Some((_, mut dev)) = items.iter().find(|(id, _)| *id == source_devid).copied() else {
            return Err(WriteError::DeviceNotFound {
                devid: source_devid,
            });
        };
        let sector = u64::from(self.volume.superblock().sectorsize());
        let target_bytes = target.size_bytes() / sector * sector;
        let required = dev.total_bytes.get();
        if target_bytes < required {
            return Err(WriteError::DeviceTooSmall {
                required,
                available: target_bytes,
            });
        }
        let source_dev = self
            .volume
            .device(source_devid)
            .ok_or(WriteError::DeviceNotFound {
                devid: source_devid,
            })?
            .clone();

        // Copy every allocated device extent on `source_devid` verbatim to the
        // same physical offset on `target`.
        let (extents, _) = self.device_extents(source_devid).await?;
        let mut buf = vec![0_u8; REPLACE_COPY_WINDOW];
        for extent in extents {
            let mut offset = extent.start;
            while offset < extent.end {
                let len = ((extent.end - offset) as usize).min(buf.len());
                source_dev
                    .read_at(offset, &mut buf[..len])
                    .await
                    .map_err(|source| Error::Io {
                        offset,
                        len,
                        source,
                    })?;
                let mut at = offset;
                for block in buf[..len].as_chunks::<{ READ_ALIGNMENT as usize }>().0 {
                    target
                        .stage(at / READ_ALIGNMENT, block)
                        .await
                        .map_err(|source| Error::Io {
                            offset: at,
                            len: block.len(),
                            source,
                        })?;
                    at += READ_ALIGNMENT;
                }
                offset += len as u64;
            }
        }

        // Update `DEV_ITEM` with the target's UUID and capacity.
        dev.uuid = new_uuid;
        dev.total_bytes.set(target_bytes);
        self.chunk_root = self
            .trees
            .apply(
                &self.volume,
                self.chunk_root,
                Key::new(objectid::DEV_ITEMS, item_type::DEV_ITEM, source_devid),
                Some(dev.as_bytes()),
                &mut self.space,
            )
            .await?;

        // Update `stripe.dev_uuid` on every `CHUNK_ITEM` stripe referencing
        // `source_devid` (and rebuild `sys_chunk_array` entries for SYSTEM chunks).
        let mut chunk_updates = Vec::new();
        let mut search = Key::new(objectid::FIRST_CHUNK_TREE, item_type::CHUNK_ITEM, 0);
        while let Some((found, mut bytes)) = self
            .trees
            .ceiling(&self.volume, self.chunk_root, search)
            .await?
        {
            if !found.is(objectid::FIRST_CHUNK_TREE, item_type::CHUNK_ITEM) {
                break;
            }
            let raw_chunk: RawChunk =
                *view(&bytes).ok_or(ChunkError::Truncated { len: bytes.len() })?;
            let num_stripes = usize::from(raw_chunk.num_stripes.get());
            let mut touched = false;
            for i in 0..num_stripes {
                let off = size_of::<RawChunk>() + i * size_of::<RawStripe>();
                let mut stripe = *view::<RawStripe>(&bytes[off..])
                    .ok_or(ChunkError::Truncated { len: bytes.len() })?;
                if stripe.devid.get() == source_devid {
                    stripe.dev_uuid = new_uuid;
                    bytes[off..off + size_of::<RawStripe>()].copy_from_slice(stripe.as_bytes());
                    touched = true;
                }
            }
            if touched {
                chunk_updates.push((found, raw_chunk.chunk_type.get(), bytes));
            }
            let Some(next) = found.offset.checked_add(1) else {
                break;
            };
            search.offset = next;
        }
        for (key, flags, bytes) in chunk_updates {
            self.chunk_root = self
                .trees
                .apply(
                    &self.volume,
                    self.chunk_root,
                    key,
                    Some(&bytes),
                    &mut self.space,
                )
                .await?;
            if flags & SYSTEM != 0 {
                self.image.remove_system_chunk(key.offset)?;
                self.image.append_system_chunk(key, &bytes)?;
            }
        }

        let old =
            self.volume
                .replace_device(source_devid, target)
                .ok_or(WriteError::DeviceNotFound {
                    devid: source_devid,
                })?;
        self.force_commit = true;

        Ok((
            VolumeDeviceInfo {
                devid: source_devid,
                uuid: new_uuid,
                total_bytes: target_bytes,
                bytes_used: dev.bytes_used.get(),
                serial: None,
            },
            old,
        ))
    }

    /// Updates `DEV_ITEM.total_bytes` for `devid` to `new_size` (once any
    /// device extents past `new_size` have already been relocated).
    pub(crate) async fn finish_resize_device(
        &mut self,
        devid: u64,
        new_size: u64,
    ) -> Result<VolumeDeviceInfo, WriteError> {
        let items = self.all_dev_items().await?;
        let Some((_, mut dev)) = items.iter().find(|(id, _)| *id == devid).copied() else {
            return Err(WriteError::DeviceNotFound { devid });
        };
        let backing = self
            .volume
            .device(devid)
            .ok_or(WriteError::DeviceNotFound { devid })?;
        let sector = u64::from(self.volume.superblock().sectorsize());
        let max_bytes = backing.size_bytes() / sector * sector;
        let aligned = new_size / sector * sector;
        if aligned < MIN_DEVICE_BYTES {
            return Err(WriteError::DeviceTooSmall {
                required: MIN_DEVICE_BYTES,
                available: aligned,
            });
        }
        if aligned > max_bytes {
            return Err(WriteError::DeviceTooSmall {
                required: aligned,
                available: max_bytes,
            });
        }
        let (extents, _) = self.device_extents(devid).await?;
        if let Some(past) = extents.iter().find(|r| r.end > aligned) {
            return Err(WriteError::Chunk(ChunkError::NoDeviceSpace {
                flags: 0,
                largest: aligned,
                needed: past.end,
            }));
        }
        dev.total_bytes.set(aligned);
        self.chunk_root = self
            .trees
            .apply(
                &self.volume,
                self.chunk_root,
                Key::new(objectid::DEV_ITEMS, item_type::DEV_ITEM, devid),
                Some(dev.as_bytes()),
                &mut self.space,
            )
            .await?;
        self.force_commit = true;
        Ok(VolumeDeviceInfo {
            devid,
            uuid: dev.uuid,
            total_bytes: aligned,
            bytes_used: dev.bytes_used.get(),
            serial: None,
        })
    }

    /// Computes the aligned target byte size for `resize_device`.
    pub(crate) async fn resolve_resize_target(
        &self,
        devid: Option<u64>,
        target: ResizeTarget,
    ) -> Result<(u64, u64, u64), WriteError> {
        let devid = devid.unwrap_or_else(|| self.volume.superblock().devid());
        let items = self.all_dev_items().await?;
        let Some((_, dev)) = items.iter().find(|(id, _)| *id == devid) else {
            return Err(WriteError::DeviceNotFound { devid });
        };
        let backing = self
            .volume
            .device(devid)
            .ok_or(WriteError::DeviceNotFound { devid })?;
        let sector = u64::from(self.volume.superblock().sectorsize());
        let max_bytes = backing.size_bytes() / sector * sector;
        let new_size = match target {
            ResizeTarget::Max => max_bytes,
            ResizeTarget::Bytes(b) => b / sector * sector,
        };
        if new_size < MIN_DEVICE_BYTES {
            return Err(WriteError::DeviceTooSmall {
                required: MIN_DEVICE_BYTES,
                available: new_size,
            });
        }
        if new_size > max_bytes {
            return Err(WriteError::DeviceTooSmall {
                required: new_size,
                available: max_bytes,
            });
        }
        Ok((devid, dev.total_bytes.get(), new_size))
    }

    /// Wipes superblock mirrors on a detached device `dev`.
    pub(crate) async fn wipe_detached(dev: &S) -> Result<(), WriteError> {
        Volume::wipe_superblocks(dev).await
    }
}

/// Ensures `RawKey` is referenced cleanly if needed in future checks.
const _: usize = size_of::<RawKey>();
