//! Extent deduplication (`FIDEDUPERANGE`): verifies byte-for-byte equality
//! across the requested ranges before sharing extents via [`Transaction::clone_range`].

use alloc::vec;
use core::num::NonZeroUsize;

use helios_hal::fs_management::DedupeOutcome;

use super::Transaction;
use super::namespace::check_flags;
use super::reflink::CloneRange;
use crate::Timestamp;
use crate::compress::policy::Compressor;
use crate::items::{INODE_APPEND, INODE_IMMUTABLE, INODE_NODATASUM};
use crate::source::BlockSink;
use crate::tree::write::WriteError;

/// Bounded comparison window: matches Linux's 128 KiB compressed extent window.
const COMPARE_WINDOW: usize = 128 * 1024;

impl<S: BlockSink> Transaction<S> {
    /// Deduplicates `request.length` bytes at `request.destination_offset` in
    /// `request.destination` against `request.source_offset` in
    /// `request.source`.
    ///
    /// Returns [`DedupeOutcome { same: false, bytes_deduped: 0 }`] without
    /// modifying `destination` when any byte in the range differs. Preserves
    /// `destination`'s timestamps when deduplicating, matching Linux's
    /// `vfs_dedupe_file_range_one`.
    pub(crate) async fn dedupe_range(
        &mut self,
        request: CloneRange,
        when: Timestamp,
        compressor: &mut Compressor,
        concurrency: NonZeroUsize,
        max_inline: u64,
    ) -> Result<DedupeOutcome, WriteError> {
        let CloneRange {
            source,
            destination,
            source_offset,
            destination_offset,
            length,
        } = request;
        let (_, source_meta) = self.file_inode(source.tree, source.inode).await?;
        let (orig_dst_raw, dst_meta) = self.file_inode(destination.tree, destination.inode).await?;
        check_flags(
            destination.tree,
            destination.inode,
            dst_meta.flags,
            INODE_IMMUTABLE | INODE_APPEND,
        )?;
        let source_end = source_offset
            .checked_add(length)
            .ok_or(WriteError::FileOverflow)?;
        let dst_end = destination_offset
            .checked_add(length)
            .ok_or(WriteError::FileOverflow)?;
        if source_end > source_meta.size {
            return Err(WriteError::CloneSourceRange);
        }
        if dst_end > dst_meta.size {
            return Err(WriteError::DedupeDestinationRange);
        }
        if (source_meta.flags ^ dst_meta.flags) & INODE_NODATASUM != 0 {
            return Err(WriteError::CloneChecksumPolicy);
        }
        let sector = u64::from(self.volume.superblock().sectorsize());
        if !source_offset.is_multiple_of(sector)
            || !destination_offset.is_multiple_of(sector)
            || (!length.is_multiple_of(sector)
                && (source_end != source_meta.size || dst_end != dst_meta.size))
        {
            return Err(WriteError::CloneAlignment);
        }
        if length == 0 {
            return Ok(DedupeOutcome {
                same: true,
                bytes_deduped: 0,
            });
        }
        if source == destination && source_offset == destination_offset {
            return Ok(DedupeOutcome {
                same: true,
                bytes_deduped: length,
            });
        }
        if source == destination && source_offset < dst_end && destination_offset < source_end {
            return Err(WriteError::CloneOverlap);
        }

        // Byte-for-byte comparison in bounded windows before sharing anything.
        let mut src_buf = vec![0_u8; COMPARE_WINDOW.min(length as usize)];
        let mut dst_buf = vec![0_u8; COMPARE_WINDOW.min(length as usize)];
        let mut compared = 0_u64;
        while compared < length {
            let chunk = ((length - compared) as usize).min(src_buf.len());
            let s_read = self
                .read_file(
                    source.tree,
                    source.inode,
                    source_offset + compared,
                    &mut src_buf[..chunk],
                )
                .await?;
            let d_read = self
                .read_file(
                    destination.tree,
                    destination.inode,
                    destination_offset + compared,
                    &mut dst_buf[..chunk],
                )
                .await?;
            if s_read != chunk || d_read != chunk || src_buf[..chunk] != dst_buf[..chunk] {
                return Ok(DedupeOutcome {
                    same: false,
                    bytes_deduped: 0,
                });
            }
            compared += chunk as u64;
        }

        // Bytes match: share extents via `clone_range`, then restore destination
        // timestamps so dedupe does not visibly modify the file's mtime/ctime.
        self.clone_range(request, when, compressor, concurrency, max_inline)
            .await?;
        let (mut updated_raw, _) = self.file_inode(destination.tree, destination.inode).await?;
        updated_raw.mtime = orig_dst_raw.mtime;
        updated_raw.ctime = orig_dst_raw.ctime;
        self.put_inode(destination.tree, destination.inode, updated_raw)
            .await?;
        Ok(DedupeOutcome {
            same: true,
            bytes_deduped: length,
        })
    }
}
