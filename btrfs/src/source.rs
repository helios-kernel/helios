//! What the filesystem reads from.

use core::future::Future;

use helios_hal::io::IoResult;

/// Granularity of every read the filesystem issues: each starts on a
/// multiple of this many bytes and is a multiple of it long.
///
/// The format's smallest sector is 4 KiB, superblock copies sit at 4 KiB
/// multiples, and every chunk, tree block and data extent is aligned to the
/// filesystem's sector size, so no read ever needs a partial block.
pub const READ_ALIGNMENT: u64 = 4096;

/// A device or a cache in front of one, read by byte offset.
///
/// This is the whole of what the read path needs: positional, async reads
/// of whole aligned blocks, and the device's length. It is deliberately not
/// [`helios_hal::fs::BlockDevice`]: the filesystem reads through the
/// kernel's block cache rather than the raw device, addresses bytes rather
/// than device blocks of a size it does not choose, and has no use for the
/// device's flush, discard and identification surface. The kernel's cache
/// implements this trait for a cached device; tests implement it over an
/// image in memory.
///
/// # Concurrency
///
/// `read_at` takes `&self` and may be called from any processor, any
/// number of times concurrently; the filesystem issues independent reads
/// from independent tasks and never serialises them. An implementation
/// that needs exclusion provides it itself.
pub trait BlockSource: Send + Sync {
    /// Bytes the source holds.
    fn size_bytes(&self) -> u64;

    /// Fills `buf` with the bytes starting at `offset`.
    ///
    /// `offset` and `buf.len()` are multiples of [`READ_ALIGNMENT`]. A
    /// range reaching past [`size_bytes`](Self::size_bytes) fails with
    /// [`helios_hal::io::IoError::OutOfBounds`].
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> impl Future<Output = IoResult<()>> + Send;
}

/// Writable storage for copy-on-write transactions.
///
/// # Concurrency
///
/// Independent staging operations may run concurrently on any processor.
/// The transaction owner serializes commits and awaits all of its staging
/// operations before committing. It must not reuse blocks reachable from a
/// published root until every reader of that root has released it.
///
/// The kernel implementation uses the block cache's dirty-block and commit
/// paths. A host implementation must supply the same durability ordering;
/// merely flushing a language-level output buffer is insufficient.
pub trait BlockSink: BlockSource {
    /// Stages one complete aligned block. `block` is an index in units of
    /// [`READ_ALIGNMENT`], not a byte offset. A successful return makes the
    /// bytes visible to reads but does not promise durable storage.
    ///
    /// Only newly allocated, unreachable CoW blocks may be staged. A
    /// superblock must go through [`Self::commit`] instead.
    fn stage(
        &self,
        block: u64,
        bytes: &[u8; READ_ALIGNMENT as usize],
    ) -> impl Future<Output = IoResult<()>> + Send;

    /// Persists every previously staged block, then replaces the specified
    /// superblock and persists it before returning. Neither cache eviction
    /// nor writeback may publish this block ahead of the preceding flush.
    ///
    /// An I/O error or cancellation after commit starts poisons the sink:
    /// subsequent staging and commits must fail until the device is reopened
    /// and its durable state is recovered. The caller must not publish its
    /// new in-memory roots unless this operation succeeds.
    fn commit(
        &self,
        block: u64,
        bytes: &[u8; READ_ALIGNMENT as usize],
    ) -> impl Future<Output = IoResult<()>> + Send;
}
