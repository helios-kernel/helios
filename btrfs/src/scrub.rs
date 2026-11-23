//! Volume scrub: verifies every allocated metadata tree block, checksummed data
//! extent, and superblock mirror across the volume (or a selected device), and
//! repairs corrupted mirror copies from healthy mirrors when not read-only.

use alloc::vec;
use alloc::vec::Vec;

use helios_hal::fs_management::ScrubReport;

use crate::data::Reader;
use crate::fs::find_root;
use crate::ondisk::{CSUM_FIELD_BYTES, RawHeader, SUPERBLOCK_BYTES, item_type, objectid, view};
use crate::source::BlockSink;
use crate::superblock::{MIRROR_OFFSETS, Superblock};
use crate::tree::write::WriteError;
use crate::tree::{Cursor, TreeRoot};
use crate::volume::Volume;
use crate::{Error, Key};

/// Maximum data scrub window (128 KiB).
const SCRUB_DATA_WINDOW: usize = 128 * 1024;

/// `BTRFS_EXTENT_FLAG_DATA` and `BTRFS_EXTENT_FLAG_TREE_BLOCK`.
const EXTENT_FLAG_DATA: u64 = 1;
const EXTENT_FLAG_TREE_BLOCK: u64 = 2;

/// Scrubs all superblock mirrors, metadata tree blocks, and checksummed data
/// extents of `volume` (optionally limited to `devid_filter`).
///
/// When `!read_only` and a chunk has multiple copies (DUP or RAID1), any copy
/// that fails verification is overwritten from a verified healthy copy and
/// counted in [`ScrubReport::corrected_errors`].
pub(crate) async fn scrub_volume<S: BlockSink>(
    volume: &Volume<S>,
    root_tree: TreeRoot,
    devid_filter: Option<u64>,
    read_only: bool,
) -> Result<ScrubReport, WriteError> {
    if let Some(devid) = devid_filter
        && volume.device(devid).is_none()
    {
        return Err(WriteError::DeviceNotFound { devid });
    }

    let mut report = ScrubReport::default();
    let sb = volume.superblock();
    let csum_type = sb.csum_type();
    let nodesize = sb.nodesize() as usize;
    let sector = sb.sectorsize() as usize;
    let digest_len = csum_type.size();

    // 1. Scrub superblock mirrors on the targeted device(s).
    let mut sb_buf = [0_u8; SUPERBLOCK_BYTES];
    for &(devid, ref dev) in volume.devices() {
        if devid_filter.is_some_and(|want| want != devid) {
            continue;
        }
        for offset in MIRROR_OFFSETS {
            if offset + SUPERBLOCK_BYTES as u64 > dev.size_bytes() {
                continue;
            }
            match volume.read_raw(devid, offset, &mut sb_buf).await {
                Ok(()) => {
                    if let Err(defect) = Superblock::parse(&sb_buf, offset) {
                        if matches!(defect, crate::SuperblockDefect::Checksum) {
                            report.csum_errors += 1;
                        } else {
                            report.verify_errors += 1;
                        }
                        report.uncorrectable_errors += 1;
                    }
                }
                Err(_) => {
                    report.verify_errors += 1;
                    report.uncorrectable_errors += 1;
                }
            }
        }
    }

    // 2. Walk `EXTENT_TREE` to visit every allocated metadata block and data extent.
    let extent_root = find_root(volume, root_tree, objectid::EXTENT_TREE)
        .await?
        .root;
    let csum_root = find_root(volume, root_tree, objectid::CSUM_TREE)
        .await?
        .root;

    let mut cursor = Cursor::ceiling(volume, extent_root, Key::new(0, 0, 0)).await?;
    let mut tree_buf = vec![0_u8; nodesize];
    let mut good_tree_buf = vec![0_u8; nodesize];
    let mut data_buf = vec![0_u8; SCRUB_DATA_WINDOW];
    let mut good_data_buf = vec![0_u8; SCRUB_DATA_WINDOW];

    while let (Some(key), Some(item)) = (cursor.key(), cursor.item()) {
        if key.item_type == item_type::METADATA_ITEM
            || (key.item_type == item_type::EXTENT_ITEM && item.len() >= 24)
        {
            let flags = if key.item_type == item_type::METADATA_ITEM {
                EXTENT_FLAG_TREE_BLOCK
            } else {
                u64::from_le_bytes(item[16..24].try_into().unwrap())
            };
            let logical = key.objectid;

            if flags & EXTENT_FLAG_TREE_BLOCK != 0 {
                let copies = volume.chunks().map(logical, nodesize as u64)?;
                let mut healthy: Option<usize> = None;
                let mut bad_copies: Vec<(u64, u64)> = Vec::new();
                let mut checked_any = false;

                for (idx, stripe) in copies.iter().enumerate() {
                    let in_scope = devid_filter.is_none_or(|want| want == stripe.devid);
                    if in_scope {
                        checked_any = true;
                        report.tree_bytes_scrubbed += nodesize as u64;
                    }
                    let valid = match volume
                        .read_raw(stripe.devid, stripe.offset, &mut tree_buf)
                        .await
                    {
                        Ok(()) => verify_tree_block(&tree_buf, logical, sb),
                        Err(_) => Err(false),
                    };
                    match valid {
                        Ok(()) => {
                            if healthy.is_none() {
                                good_tree_buf.copy_from_slice(&tree_buf);
                                healthy = Some(idx);
                            }
                        }
                        Err(is_csum) => {
                            if in_scope {
                                if is_csum {
                                    report.csum_errors += 1;
                                } else {
                                    report.verify_errors += 1;
                                }
                                bad_copies.push((stripe.devid, stripe.offset));
                            }
                        }
                    }
                }
                if checked_any {
                    report.tree_extents_scrubbed += 1;
                }
                for (devid, physical) in bad_copies {
                    if !read_only && healthy.is_some() {
                        if volume
                            .stage_raw(devid, physical, &good_tree_buf)
                            .await
                            .is_ok()
                        {
                            report.corrected_errors += 1;
                        } else {
                            report.uncorrectable_errors += 1;
                        }
                    } else {
                        report.uncorrectable_errors += 1;
                    }
                }
            } else if flags & EXTENT_FLAG_DATA != 0 {
                let length = key.offset;
                let copies = volume.chunks().map(logical, length)?;
                let any_in_scope = copies
                    .iter()
                    .any(|s| devid_filter.is_none_or(|want| want == s.devid));
                if any_in_scope {
                    report.data_extents_scrubbed += 1;
                }
                let mut offset = 0_u64;
                while offset < length {
                    let window = ((length - offset) as usize).min(SCRUB_DATA_WINDOW);
                    let window_logical = logical + offset;
                    let digests = Reader::new(volume, volume, csum_root)
                        .lookup_checksums(window_logical, window)
                        .await
                        .ok();
                    let Some(digests) =
                        digests.filter(|d| d.len() == (window / sector) * digest_len)
                    else {
                        if any_in_scope {
                            report.no_csum_sectors += (window / sector) as u64;
                        }
                        offset += window as u64;
                        continue;
                    };

                    // Verify each sector across copies so we can repair individual
                    // corrupted sectors from a healthy mirror copy.
                    let sector_count = window / sector;
                    let mut good_sector = vec![false; sector_count];
                    let mut bad_sectors: Vec<(u64, u64, usize)> = Vec::new();

                    for stripe in &copies {
                        let in_scope = devid_filter.is_none_or(|want| want == stripe.devid);
                        let phys = stripe.offset + offset;
                        if in_scope {
                            report.data_bytes_scrubbed += window as u64;
                        }
                        let read_ok = volume
                            .read_raw(stripe.devid, phys, &mut data_buf[..window])
                            .await
                            .is_ok();
                        for s in 0..sector_count {
                            let s_off = s * sector;
                            let stored = &digests[s * digest_len..(s + 1) * digest_len];
                            let ok = read_ok
                                && csum_type.verifies(&data_buf[s_off..s_off + sector], stored);
                            if ok {
                                if !good_sector[s] {
                                    good_data_buf[s_off..s_off + sector]
                                        .copy_from_slice(&data_buf[s_off..s_off + sector]);
                                    good_sector[s] = true;
                                }
                            } else if in_scope {
                                report.csum_errors += 1;
                                bad_sectors.push((stripe.devid, phys + s_off as u64, s));
                            }
                        }
                    }

                    for (devid, phys, s) in bad_sectors {
                        if !read_only && good_sector[s] {
                            let s_off = s * sector;
                            if volume
                                .stage_raw(devid, phys, &good_data_buf[s_off..s_off + sector])
                                .await
                                .is_ok()
                            {
                                report.corrected_errors += 1;
                            } else {
                                report.uncorrectable_errors += 1;
                            }
                        } else {
                            report.uncorrectable_errors += 1;
                        }
                    }

                    offset += window as u64;
                }
            }
        }
        cursor.advance(volume).await?;
    }

    Ok(report)
}

/// Verifies a raw tree block's checksum, `bytenr`, and `fsid`. Returns
/// `Err(true)` for a checksum mismatch and `Err(false)` for a header mismatch.
fn verify_tree_block(bytes: &[u8], logical: u64, sb: &Superblock) -> Result<(), bool> {
    let header: &RawHeader = view(bytes).ok_or(false)?;
    if !sb
        .csum_type()
        .verifies(&bytes[CSUM_FIELD_BYTES..], &header.csum)
    {
        return Err(true);
    }
    if header.bytenr.get() != logical || header.fsid != sb.metadata_fsid() {
        return Err(false);
    }
    Ok(())
}

/// Ensures `Error` stays cleanly imported for future diagnostics.
const _: fn(Error) -> WriteError = WriteError::Read;
