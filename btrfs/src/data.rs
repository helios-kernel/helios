//! Shared file-data reads for immutable snapshots and transaction overlays.
//! Both use the same extent decoding, decompression and checksum verification.

use crate::compress::decompress;
use crate::items::{ExtentData, FileExtent, INODE_NODATASUM, Metadata};
use crate::ondisk::{MAX_COMPRESSED_EXTENT, item_type, objectid};
use crate::source::BlockSource;
use crate::tree::{Cursor, NodeSource, TreeRoot};
use crate::volume::Volume;
use crate::{Error, ItemDefect, Key};
use alloc::vec;
use alloc::vec::Vec;

const DATA_WINDOW: u64 = MAX_COMPRESSED_EXTENT;

#[derive(Clone, Copy)]
pub(crate) struct File<'a> {
    pub(crate) root: TreeRoot,
    pub(crate) number: u64,
    pub(crate) metadata: &'a Metadata,
}

impl File<'_> {
    fn is_checksummed(self) -> bool {
        self.metadata.flags & INODE_NODATASUM == 0
    }
}

pub(crate) struct Reader<'a, S, N> {
    volume: &'a Volume<S>,
    nodes: &'a N,
    checksums: TreeRoot,
}

impl<'a, S: BlockSource, N: NodeSource> Reader<'a, S, N> {
    pub(crate) fn new(volume: &'a Volume<S>, nodes: &'a N, checksums: TreeRoot) -> Self {
        Self {
            volume,
            nodes,
            checksums,
        }
    }
    /// Every EXTENT_DATA item of the file, in file-offset order.
    #[cfg(feature = "test-support")]
    pub(crate) async fn extents(
        &self,
        file: File<'_>,
    ) -> Result<Vec<crate::fs::ExtentInfo>, Error> {
        use crate::fs::{ExtentInfo, ExtentKind};
        use crate::ondisk::{RawFileExtentBody, RawFileExtentHead, view};
        let mut cursor = Cursor::floor(
            self.nodes,
            file.root,
            Key::new(file.number, item_type::EXTENT_DATA, 0),
        )
        .await?;
        let mut found = Vec::new();
        while let (Some(key), Some(item)) = (cursor.key(), cursor.item()) {
            if key < Key::new(file.number, item_type::EXTENT_DATA, 0) {
                cursor.advance(self.nodes).await?;
                continue;
            }
            if !key.is(file.number, item_type::EXTENT_DATA) {
                break;
            }
            let extent = FileExtent::parse(key, item, self.volume.superblock().sectorsize())
                .map_err(|defect| Error::Item {
                    tree: file.root.tree,
                    key,
                    defect,
                })?;
            // `parse` validated the head, so the view and the codes are valid.
            let head: &RawFileExtentHead = view(item).expect("validated file extent head");
            let kind = match head.extent_type {
                0 => ExtentKind::Inline,
                1 => ExtentKind::Regular,
                _ => ExtentKind::Prealloc,
            };
            let compression = match head.compression {
                0 => None,
                1 => Some(crate::Compression::Zlib),
                2 => Some(crate::Compression::Lzo),
                _ => Some(crate::Compression::Zstd),
            };
            let stored = match extent.data {
                ExtentData::Inline { data, .. } => data.len() as u64,
                ExtentData::Regular { disk_num_bytes, .. } => disk_num_bytes,
                ExtentData::Zero => {
                    view::<RawFileExtentBody>(&item[size_of::<RawFileExtentHead>()..])
                        .expect("validated file extent body")
                        .disk_num_bytes
                        .get()
                }
            };
            found.push(ExtentInfo {
                offset: extent.start,
                len: extent.end - extent.start,
                kind,
                compression,
                stored,
            });
            cursor.advance(self.nodes).await?;
        }
        Ok(found)
    }

    /// The file bytes at `offset`, through the inode's extents.
    pub(crate) async fn read(
        &self,
        file: File<'_>,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        let size = file.metadata.size;
        if offset >= size || buf.is_empty() {
            return Ok(0);
        }
        let len = (size - offset).min(buf.len() as u64) as usize;
        let buf = &mut buf[..len];
        let end = offset + len as u64;
        let first_extent = Key::new(file.number, item_type::EXTENT_DATA, 0);
        let mut cursor = Cursor::floor(
            self.nodes,
            file.root,
            Key::new(file.number, item_type::EXTENT_DATA, offset),
        )
        .await?;
        let mut position = offset;
        let mut previous_end = 0;
        while position < end {
            let (Some(key), Some(item)) = (cursor.key(), cursor.item()) else {
                break;
            };
            if key < first_extent {
                cursor.advance(self.nodes).await?;
                continue;
            }
            if !key.is(file.number, item_type::EXTENT_DATA) {
                break;
            }
            let item_error = |defect| Error::Item {
                tree: file.root.tree,
                key,
                defect,
            };
            let extent = FileExtent::parse(key, item, self.volume.superblock().sectorsize())
                .map_err(item_error)?;
            if extent.start < previous_end {
                return Err(item_error(ItemDefect::ExtentOverlap(previous_end)));
            }
            previous_end = extent.end;
            if extent.end > position {
                if extent.start > position {
                    // A hole the format leaves implicit.
                    let gap_end = extent.start.min(end);
                    buf[(position - offset) as usize..(gap_end - offset) as usize].fill(0);
                    position = gap_end;
                }
                if position < end {
                    let copy_end = extent.end.min(end);
                    let out = &mut buf[(position - offset) as usize..(copy_end - offset) as usize];
                    self.copy_extent(file, &extent, position - extent.start, out)
                        .await?;
                    position = copy_end;
                }
            }
            cursor.advance(self.nodes).await?;
        }
        // Past the last extent the file reads as zeroes up to its size.
        buf[(position - offset) as usize..].fill(0);
        Ok(len)
    }

    /// Copies the bytes of `extent` from `from`, relative to its start,
    /// into `out`.
    async fn copy_extent(
        &self,
        file: File<'_>,
        extent: &FileExtent<'_>,
        from: u64,
        out: &mut [u8],
    ) -> Result<(), Error> {
        let sectorsize = self.volume.superblock().sectorsize() as usize;
        let decompress_error = |algorithm, defect| Error::Decompress {
            algorithm,
            tree: file.root.tree,
            inode: file.number,
            file_offset: extent.start,
            defect,
        };
        match extent.data {
            ExtentData::Zero => out.fill(0),
            ExtentData::Inline {
                data,
                compression: None,
            } => {
                let from = from as usize;
                out.copy_from_slice(&data[from..from + out.len()]);
            }
            ExtentData::Inline {
                data,
                compression: Some(algorithm),
            } => {
                // `FileExtent::parse` bounded this by the sector size.
                let mut plain = vec![0_u8; extent.end as usize];
                decompress(algorithm, data, &mut plain, sectorsize)
                    .map_err(|defect| decompress_error(algorithm, defect))?;
                let from = from as usize;
                out.copy_from_slice(&plain[from..from + out.len()]);
            }
            ExtentData::Regular {
                disk_bytenr,
                offset,
                compression: None,
                ..
            } => {
                self.read_data(disk_bytenr + offset + from, out, file.is_checksummed())
                    .await?;
            }
            ExtentData::Regular {
                disk_bytenr,
                disk_num_bytes,
                offset,
                ram_bytes,
                compression: Some(algorithm),
            } => {
                // Both sizes were bounded by 128 KiB in `FileExtent::parse`.
                let mut stored = vec![0_u8; disk_num_bytes as usize];
                self.read_sectors(disk_bytenr, &mut stored, file.is_checksummed())
                    .await?;
                let mut plain = vec![0_u8; ram_bytes as usize];
                decompress(algorithm, &stored, &mut plain, sectorsize)
                    .map_err(|defect| decompress_error(algorithm, defect))?;
                let from = (offset + from) as usize;
                out.copy_from_slice(&plain[from..from + out.len()]);
            }
        }
        Ok(())
    }

    /// Reads data bytes at `logical`, which need not be sector aligned, in
    /// windows of at most [`DATA_WINDOW`] bytes.
    async fn read_data(
        &self,
        logical: u64,
        out: &mut [u8],
        checksummed: bool,
    ) -> Result<(), Error> {
        let sector = u64::from(self.volume.superblock().sectorsize());
        let mut window = Vec::new();
        let mut done = 0;
        while done < out.len() {
            let at = logical + done as u64;
            let window_start = at - at % sector;
            let wanted_end = at + (out.len() - done) as u64;
            let window_end = wanted_end
                .next_multiple_of(sector)
                .min(window_start + DATA_WINDOW);
            window.resize((window_end - window_start) as usize, 0);
            self.read_sectors(window_start, &mut window, checksummed)
                .await?;
            let skip = (at - window_start) as usize;
            let count = (window.len() - skip).min(out.len() - done);
            out[done..done + count].copy_from_slice(&window[skip..skip + count]);
            done += count;
        }
        Ok(())
    }

    /// Reads whole sectors at `logical` and, for checksummed data, verifies
    /// each against the checksum tree, falling back to the other copy of a
    /// `dup` chunk when one fails.
    async fn read_sectors(
        &self,
        logical: u64,
        buf: &mut [u8],
        checksummed: bool,
    ) -> Result<(), Error> {
        let sector = self.volume.superblock().sectorsize() as usize;
        let csum_type = self.volume.superblock().csum_type();
        let expected = if checksummed {
            Some(self.lookup_checksums(logical, buf.len()).await?)
        } else {
            None
        };
        self.volume
            .read_verified(logical, buf, |data| {
                let Some(expected) = &expected else {
                    return Ok(());
                };
                let size = csum_type.size();
                for (index, (sector_data, stored)) in data
                    .chunks_exact(sector)
                    .zip(expected.chunks_exact(size))
                    .enumerate()
                {
                    if !csum_type.verifies(sector_data, stored) {
                        return Err(Error::DataChecksum {
                            logical: logical + (index * sector) as u64,
                        });
                    }
                }
                Ok(())
            })
            .await
    }

    /// The stored checksum of every sector of `[logical, logical + len)`,
    /// concatenated.
    pub(crate) async fn lookup_checksums(
        &self,
        logical: u64,
        len: usize,
    ) -> Result<Vec<u8>, Error> {
        let sector = u64::from(self.volume.superblock().sectorsize());
        let size = self.volume.superblock().csum_type().size();
        let sectors = len / sector as usize;
        let mut sums = vec![0_u8; sectors * size];
        let mut filled = 0;
        let first = Key::new(objectid::EXTENT_CSUM, item_type::EXTENT_CSUM, 0);
        let mut cursor = Cursor::floor(
            self.nodes,
            self.checksums,
            Key::new(objectid::EXTENT_CSUM, item_type::EXTENT_CSUM, logical),
        )
        .await?;
        while filled < sectors {
            let (Some(key), Some(item)) = (cursor.key(), cursor.item()) else {
                break;
            };
            if key < first {
                cursor.advance(self.nodes).await?;
                continue;
            }
            if !key.is(objectid::EXTENT_CSUM, item_type::EXTENT_CSUM) {
                break;
            }
            let item_error = |defect| Error::Item {
                tree: cursor.tree(),
                key,
                defect,
            };
            if item.len() % size != 0 {
                return Err(item_error(ItemDefect::ChecksumItem(item.len())));
            }
            if !key.offset.is_multiple_of(sector) {
                return Err(item_error(ItemDefect::Unaligned {
                    field: "checksum start",
                    value: key.offset,
                }));
            }
            let item_sectors = (item.len() / size) as u64;
            let item_end = key
                .offset
                .checked_add(item_sectors * sector)
                .ok_or(item_error(ItemDefect::ExtentOverflow))?;
            let wanted = logical + filled as u64 * sector;
            if item_end <= wanted {
                cursor.advance(self.nodes).await?;
                continue;
            }
            if key.offset > wanted {
                break;
            }
            let skip = ((wanted - key.offset) / sector) as usize;
            let count = (item_sectors as usize - skip).min(sectors - filled);
            sums[filled * size..(filled + count) * size]
                .copy_from_slice(&item[skip * size..(skip + count) * size]);
            filled += count;
            cursor.advance(self.nodes).await?;
        }
        if filled < sectors {
            return Err(Error::MissingDataChecksum {
                logical: logical + filled as u64 * sector,
            });
        }
        Ok(sums)
    }
}
