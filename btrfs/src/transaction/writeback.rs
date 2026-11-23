//! Writeback: the dirty runs of an inode become its data extents, as Linux's
//! `btrfs_run_delalloc_range` (`fs/btrfs/inode.c`) turns each delalloc range
//! into ordered extents.
//!
//! - An inode whose data the mount compresses goes through
//!   `run_delalloc_compressed`: its runs are cut into chunks of
//!   [`COMPRESSION_CHUNK`], and `compress_file_range` encodes each chunk in
//!   windows of [`MAX_UNCOMPRESSED`]. A window that saves at least a sector
//!   becomes one compressed extent; the first that does not sends the rest
//!   of its chunk down the uncompressed path, as `cleanup_and_bail_uncompressed`
//!   does. A compressed window no free range can hold contiguously is
//!   written uncompressed, as `submit_one_async_extent` falls back to
//!   `submit_uncompressed_range`.
//! - Every other run goes through `cow_file_range`: extents of up to
//!   [`MAX_EXTENT_SIZE`] (`find_lock_delalloc_range` bounds a range by
//!   `fs_info->max_extent_size`), each as long as a free range can hold, as
//!   `btrfs_reserve_extent` settles it.
//!
//! The data space was reserved when the data was written, so writeback
//! always finds room for it.
//!
//! # Concurrency contract
//!
//! Writeback runs on `&mut Transaction<S>`, owned by the single writer task,
//! and reads a cloned [`DirtyFile`] snapshot while staging sectors through
//! [`BlockSink`] with bounded `concurrency`. No lock is held across `.await`;
//! reader views keep seeing the dirty pages until the transaction publishes
//! its updated view or commits.

use alloc::vec::Vec;
use core::num::NonZeroUsize;
use core::ops::Range;

use super::Transaction;
use super::file::{NewExtent, aligned_end};
use crate::compress::policy::Compressor;
use crate::delalloc::{DirtyFile, MAX_EXTENT_SIZE, MAX_UNCOMPRESSED};
use crate::ondisk::RawInodeItem;
use crate::source::BlockSink;
use crate::space::DATA;
use crate::tree::write::WriteError;

/// `BTRFS_COMPRESSION_CHUNK_SIZE`, `SZ_512K` in `fs/btrfs/compression.h`:
/// the stretch `run_delalloc_compressed` hands to one `compress_file_range`.
const COMPRESSION_CHUNK: u64 = 512 << 10;

/// One inode's writeback: its state as writeback started and its inode item,
/// whose byte count each new extent updates.
struct Inode<'a> {
    tree: u64,
    number: u64,
    dirty: &'a DirtyFile,
    raw: RawInodeItem,
}

impl<S: BlockSink> Transaction<S> {
    /// Writes every inode's dirty data back.
    pub(crate) async fn writeback_all(
        &mut self,
        compressor: &mut Compressor,
        concurrency: NonZeroUsize,
    ) -> Result<(), WriteError> {
        for (tree, inode) in self.delalloc.inodes() {
            self.writeback_range(tree, inode, 0..u64::MAX, compressor, concurrency)
                .await?;
        }
        Ok(())
    }

    /// Writes the dirty data of `inode` within the sector-aligned `range`
    /// back, as `btrfs_fdatawrite_range` does.
    pub(crate) async fn writeback_range(
        &mut self,
        tree: u64,
        inode: u64,
        range: Range<u64>,
        compressor: &mut Compressor,
        concurrency: NonZeroUsize,
    ) -> Result<(), WriteError> {
        let sector = u64::from(self.volume.superblock().sectorsize());
        debug_assert!(
            range.start.is_multiple_of(sector)
                && (range.end == u64::MAX || range.end.is_multiple_of(sector)),
            "writeback range is sector-aligned"
        );
        let Some(dirty) = self.delalloc.file(tree, inode).cloned() else {
            return Ok(());
        };
        let runs = dirty.runs(range);
        if runs.is_empty() {
            return Ok(());
        }
        let (raw, _) = self.file_inode(tree, inode).await?;
        let mut file = Inode {
            tree,
            number: inode,
            dirty: &dirty,
            raw,
        };
        for run in runs {
            if dirty.compresses() {
                let mut chunk = run.start;
                while chunk < run.end {
                    let end = (chunk + COMPRESSION_CHUNK).min(run.end);
                    self.compress_range(&mut file, chunk..end, compressor, concurrency)
                        .await?;
                    chunk = end;
                }
            } else {
                self.cow_range(&mut file, run.clone(), concurrency).await?;
            }
            self.delalloc.remove_range(tree, inode, run);
        }
        // `btrfs_update_inode`: the new byte count, stamped with this
        // transaction.
        let mut raw = file.raw;
        raw.transid.set(self.trees.generation());
        self.put_inode(tree, inode, raw).await
    }

    /// `compress_file_range` over one chunk.
    async fn compress_range(
        &mut self,
        file: &mut Inode<'_>,
        chunk: Range<u64>,
        compressor: &mut Compressor,
        concurrency: NonZeroUsize,
    ) -> Result<(), WriteError> {
        let sector = u64::from(self.volume.superblock().sectorsize());
        let mut input = Vec::new();
        let mut position = chunk.start;
        while position < chunk.end {
            let window = (chunk.end - position).min(MAX_UNCOMPRESSED);
            input.clear();
            for (_, page) in file.dirty.pages(position..position + window) {
                input.extend_from_slice(page);
            }
            let Some(encoded) = compressor.encode(&input, sector as usize)? else {
                return self.cow_range(file, position..chunk.end, concurrency).await;
            };
            let stored = aligned_end(encoded.bytes.len() as u64, sector)?;
            // The encoding must free at least one sector.
            if stored >= window {
                return self.cow_range(file, position..chunk.end, concurrency).await;
            }
            encoded.bytes.resize(stored as usize, 0);
            self.ensure_data(stored).await?;
            if self.space.can_reserve(stored, DATA) {
                let algorithm = encoded.algorithm;
                self.insert_extent(
                    file.tree,
                    file.number,
                    NewExtent {
                        offset: position,
                        length: window,
                        stored: &[encoded.bytes.as_slice()],
                        algorithm: Some(algorithm),
                    },
                    &mut file.raw,
                    concurrency,
                )
                .await?;
            } else {
                self.cow_range(file, position..position + window, concurrency)
                    .await?;
            }
            position += window;
        }
        Ok(())
    }

    /// `cow_file_range` over one stretch of a run.
    async fn cow_range(
        &mut self,
        file: &mut Inode<'_>,
        range: Range<u64>,
        concurrency: NonZeroUsize,
    ) -> Result<(), WriteError> {
        let mut position = range.start;
        while position < range.end {
            let length = self
                .extent_length((range.end - position).min(MAX_EXTENT_SIZE))
                .await?;
            let pages: Vec<&[u8]> = file
                .dirty
                .pages(position..position + length)
                .map(|(_, page)| &**page)
                .collect();
            self.insert_extent(
                file.tree,
                file.number,
                NewExtent {
                    offset: position,
                    length,
                    stored: &pages,
                    algorithm: None,
                },
                &mut file.raw,
                concurrency,
            )
            .await?;
            position += length;
        }
        Ok(())
    }
}
