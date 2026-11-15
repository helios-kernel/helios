//! Superblock publication image. Preserve fields the transaction does not
//! change, while rotating the typed backup roots and checksumming each mirror.

use alloc::boxed::Box;
use zerocopy::{FromZeros, IntoBytes};

use crate::ChecksumType;
use crate::ondisk::{RawRootBackup, RawSuperblock, SUPERBLOCK_BYTES, objectid, view};
use crate::roots::Roots;
use crate::tree::write::WriteError;

pub(crate) struct CommitImage {
    pub(crate) bytes: Box<[u8; SUPERBLOCK_BYTES]>,
}

impl CommitImage {
    pub(crate) fn prepare(&mut self, roots: &Roots, used: u64) -> Result<(), WriteError> {
        let mut raw = *view::<RawSuperblock>(&self.bytes[..]).expect("validated superblock image");
        let extent = roots.get(objectid::EXTENT_TREE)?;
        let fs = roots.get(objectid::FS_TREE)?;
        let device = roots.get(objectid::DEV_TREE)?;
        let checksum = roots.get(objectid::CSUM_TREE)?;
        let generation = roots.root.generation;
        raw.generation.set(generation);
        raw.root.set(roots.root.bytenr);
        raw.root_level = roots.root.level;
        raw.bytes_used.set(used);
        raw.flags.set(raw.flags.get() | 1); // BTRFS_SUPER_FLAG_WRITTEN.
        // Existing v1 free-space cache inodes are stale after our CoW edits.
        raw.cache_generation.set(0);
        raw.uuid_tree_generation.set(generation);
        if raw.compat_ro_flags.get() & 1 != 0 {
            raw.compat_ro_flags.set(raw.compat_ro_flags.get() | 2); // FREE_SPACE_TREE_VALID.
        }
        let offset = size_of::<RawSuperblock>();
        let old = view::<[RawRootBackup; 4]>(&self.bytes[offset..])
            .expect("four backup roots fit superblock");
        let latest = old
            .iter()
            .enumerate()
            .max_by_key(|(_, root)| root.tree_generation.get())
            .map(|(index, _)| index)
            .expect("four roots");
        let slot = if old[latest].tree_generation.get() == generation {
            latest
        } else {
            (latest + 1) % old.len()
        };
        let mut backup = RawRootBackup::new_zeroed();
        backup.tree = raw.root;
        backup.tree_generation = raw.generation;
        backup.chunk = raw.chunk_root;
        backup.chunk_generation = raw.chunk_root_generation;
        backup.extent.set(extent.bytenr);
        backup.extent_generation.set(extent.generation);
        backup.fs.set(fs.bytenr);
        backup.fs_generation.set(fs.generation);
        backup.device.set(device.bytenr);
        backup.device_generation.set(device.generation);
        backup.checksum.set(checksum.bytenr);
        backup.checksum_generation.set(checksum.generation);
        backup.total_bytes = raw.total_bytes;
        backup.bytes_used = raw.bytes_used;
        backup.devices = raw.num_devices;
        backup.tree_level = raw.root_level;
        backup.chunk_level = raw.chunk_root_level;
        backup.extent_level = extent.level;
        backup.fs_level = fs.level;
        backup.device_level = device.level;
        backup.checksum_level = checksum.level;
        let start = offset + slot * size_of::<RawRootBackup>();
        self.bytes[start..start + size_of::<RawRootBackup>()].copy_from_slice(backup.as_bytes());
        self.bytes[..offset].copy_from_slice(raw.as_bytes());
        Ok(())
    }

    pub(crate) fn at(&mut self, offset: u64, algorithm: ChecksumType) -> &[u8; SUPERBLOCK_BYTES] {
        let mut raw = *view::<RawSuperblock>(&self.bytes[..]).expect("validated superblock image");
        raw.bytenr.set(offset);
        raw.csum.fill(0);
        self.bytes[..size_of::<RawSuperblock>()].copy_from_slice(raw.as_bytes());
        let digest = algorithm.digest(&self.bytes[32..]);
        self.bytes[..digest.as_bytes().len()].copy_from_slice(digest.as_bytes());
        &self.bytes
    }
}
