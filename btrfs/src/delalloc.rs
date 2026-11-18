//! The running transaction's dirty file data, held per inode until writeback
//! forms its extents: Linux's delayed allocation, where a buffered write
//! copies into the page cache and marks the range `EXTENT_DELALLOC` in the
//! inode's `io_tree` (`btrfs_buffered_write` and `btrfs_set_extent_delalloc`
//! in `fs/btrfs/file.c` and `fs/btrfs/inode.c`), and `btrfs_run_delalloc_range`
//! allocates the extents when the range is written back.
//!
//! A file's dirty data is a set of sector-sized pages keyed by file offset,
//! and the maximal runs of contiguous pages, which writeback turns into
//! extents. Each page holds the complete current contents of its sector,
//! zeroes past the end of the file included, as a page-cache folio does.
//!
//! # Concurrency contract
//!
//! The state belongs to the running transaction and changes only through
//! its single owner. Every collection is persistent: a reader's view takes
//! an O(1) clone and keeps reading the pages it saw while the writer
//! replaces them, so no lock guards any of it.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::Range;

use rpds::RedBlackTreeMapSync;

use crate::compress::policy::inode_compresses;
use crate::items::INODE_NODATASUM;

/// One sector of file data.
pub(crate) type Page = Arc<[u8]>;

/// `BTRFS_MAX_EXTENT_SIZE`, `SZ_128M` in `fs/btrfs/fs.h`: the longest data
/// extent writeback forms (`fs_info->max_extent_size`, which bounds each
/// delalloc range `find_lock_delalloc_range` hands to `cow_file_range`).
pub(crate) const MAX_EXTENT_SIZE: u64 = 128 << 20;

/// `BTRFS_MAX_UNCOMPRESSED`, `SZ_128K` in `fs/btrfs/compression.h`: the
/// longest stretch of file data one compressed extent holds, the window
/// `compress_file_range` encodes at a time.
pub(crate) const MAX_UNCOMPRESSED: u64 = 128 << 10;

/// One inode's dirty data.
#[derive(Clone)]
pub(crate) struct DirtyFile {
    /// Sector-aligned file offset to the sector's bytes.
    pages: RedBlackTreeMapSync<u64, Page>,
    /// The maximal runs of contiguous pages, start to end.
    runs: RedBlackTreeMapSync<u64, u64>,
    /// Whether writeback compresses the data.
    compresses: bool,
    /// Whether writeback stores checksums for the data.
    checksummed: bool,
    /// The extents the runs need at [`Self::extent_limit`] each: the
    /// inode's `outstanding_extents` (`count_max_extents` per delalloc
    /// range).
    extents: u64,
}

impl DirtyFile {
    fn new(compresses: bool, checksummed: bool) -> Self {
        Self {
            pages: RedBlackTreeMapSync::new_sync(),
            runs: RedBlackTreeMapSync::new_sync(),
            compresses,
            checksummed,
            extents: 0,
        }
    }

    fn cost(&self, run: Range<u64>) -> u64 {
        (run.end - run.start).div_ceil(self.extent_limit())
    }

    /// The longest extent writeback forms for this inode.
    pub(crate) fn extent_limit(&self) -> u64 {
        if self.compresses {
            MAX_UNCOMPRESSED
        } else {
            MAX_EXTENT_SIZE
        }
    }

    pub(crate) fn compresses(&self) -> bool {
        self.compresses
    }

    /// The pages that start within `range`, in file order.
    pub(crate) fn pages(&self, range: Range<u64>) -> impl Iterator<Item = (u64, &Page)> + '_ {
        self.pages
            .range(range)
            .map(|(&offset, page)| (offset, page))
    }

    /// The dirty runs, clipped to `range`, in file order.
    pub(crate) fn runs(&self, range: Range<u64>) -> Vec<Range<u64>> {
        let mut runs = Vec::new();
        if let Some((_, &end)) = self.runs.range(..range.start).next_back()
            && end > range.start
        {
            runs.push(range.start..end.min(range.end));
        }
        for (&start, &end) in self.runs.range(range.clone()) {
            runs.push(start..end.min(range.end));
        }
        runs
    }

    /// Dirty bytes inside the sector-aligned `range`.
    pub(crate) fn bytes_in(&self, range: Range<u64>) -> u64 {
        self.runs(range)
            .into_iter()
            .map(|run| run.end - run.start)
            .sum()
    }

    /// Upper bound on how many additional extents dirtying any nonempty prefix
    /// of the sector-aligned `range` can add. Merging on the right or absorbing
    /// later runs is deliberately not subtracted, because a short write that
    /// stops before `range.end` leaves those later runs separate.
    fn extent_delta(&self, range: Range<u64>) -> u64 {
        if range.start >= range.end {
            return 0;
        }
        if let Some((&start, &end)) = self.runs.range(..=range.start).next_back()
            && end >= range.start
        {
            if end >= range.end {
                return 0;
            }
            return self.cost(start..range.end) - self.cost(start..end);
        }
        self.cost(range)
    }

    /// Adds `run`, which no run overlaps, merging it with the runs it
    /// touches.
    fn add_run(&mut self, run: Range<u64>) {
        let (mut start, mut end) = (run.start, run.end);
        if let Some((&before, &before_end)) = self.runs.range(..start).next_back()
            && before_end == start
        {
            self.runs.remove_mut(&before);
            self.extents -= self.cost(before..before_end);
            start = before;
        }
        if let Some(&after_end) = self.runs.get(&end) {
            self.runs.remove_mut(&end);
            self.extents -= self.cost(end..after_end);
            end = after_end;
        }
        self.runs.insert_mut(start, end);
        self.extents += self.cost(start..end);
    }

    /// Takes `range` out of the runs, keeping the parts of each run outside
    /// it.
    fn cut_runs(&mut self, range: Range<u64>) {
        let overlapping: Vec<(u64, u64)> = self
            .runs
            .range(..range.start)
            .next_back()
            .filter(|&(_, &end)| end > range.start)
            .into_iter()
            .chain(self.runs.range(range.clone()))
            .map(|(&start, &end)| (start, end))
            .collect();
        for (start, end) in overlapping {
            self.runs.remove_mut(&start);
            self.extents -= self.cost(start..end);
            for kept in [start..range.start, range.end..end] {
                if kept.start < kept.end {
                    self.extents += self.cost(kept.clone());
                    self.runs.insert_mut(kept.start, kept.end);
                }
            }
        }
    }
}

/// Every inode's dirty data, with the totals the transaction's reservations
/// and the writeback bound read.
#[derive(Clone)]
pub(crate) struct Delalloc {
    files: RedBlackTreeMapSync<(u64, u64), DirtyFile>,
    sector: u64,
    /// Checksums one leaf item holds: `csums_per_leaf` in
    /// `btrfs_csum_bytes_to_leaves`.
    csums_per_leaf: u64,
    /// Whether the mount compresses the data of an inode that allows it.
    compresses: bool,
    bytes: u64,
    items: u64,
}

impl Delalloc {
    pub(crate) fn new(sector: u64, csums_per_leaf: u64, compresses: bool) -> Self {
        Self {
            files: RedBlackTreeMapSync::new_sync(),
            sector,
            csums_per_leaf,
            compresses,
            bytes: 0,
            items: 0,
        }
    }

    /// Whether writeback compresses the data of an inode with `flags`, as
    /// `btrfs_run_delalloc_range` takes `run_delalloc_compressed` for an
    /// inode `btrfs_inode_can_compress` and `inode_need_compress` accept.
    pub(crate) fn compresses(&self, flags: u64) -> bool {
        self.compresses && inode_compresses(flags)
    }

    /// The longest extent writeback forms for an inode with `flags`.
    pub(crate) fn extent_limit(&self, flags: u64) -> u64 {
        DirtyFile::new(self.compresses(flags), true).extent_limit()
    }

    /// The tree items writing `file` back inserts: its extents and, for
    /// checksummed data, the checksum leaves of its sectors
    /// (`btrfs_calculate_inode_block_rsv_size`).
    fn file_items(&self, file: &DirtyFile) -> u64 {
        let checksums = if file.checksummed {
            (file.pages.size() as u64).div_ceil(self.csums_per_leaf)
        } else {
            0
        };
        file.extents + checksums
    }

    fn forget(&mut self, file: &DirtyFile) {
        self.bytes -= file.pages.size() as u64 * self.sector;
        self.items -= self.file_items(file);
    }

    fn store(&mut self, key: (u64, u64), file: DirtyFile) {
        if file.pages.is_empty() {
            self.files.remove_mut(&key);
            return;
        }
        self.bytes += file.pages.size() as u64 * self.sector;
        self.items += self.file_items(&file);
        self.files.insert_mut(key, file);
    }

    /// Takes `key`'s state out of the totals, for the caller to change and
    /// store again.
    fn take(&mut self, key: (u64, u64)) -> Option<DirtyFile> {
        let file = self.files.get(&key)?.clone();
        self.forget(&file);
        Some(file)
    }

    pub(crate) fn file(&self, tree: u64, inode: u64) -> Option<&DirtyFile> {
        self.files.get(&(tree, inode))
    }

    /// Dirty bytes of `(tree, inode)`: Linux's `btrfs_inode::delalloc_bytes`,
    /// which `btrfs_getattr` adds to `nbytes` when reporting `st_blocks`.
    pub(crate) fn file_bytes(&self, tree: u64, inode: u64) -> u64 {
        self.file(tree, inode)
            .map_or(0, |file| file.pages.size() as u64 * self.sector)
    }

    pub(crate) fn is_dirty(&self, tree: u64, inode: u64, offset: u64) -> bool {
        self.file(tree, inode)
            .is_some_and(|file| file.pages.contains_key(&offset))
    }

    /// Every inode with dirty data, as `(tree, inode)`.
    pub(crate) fn inodes(&self) -> Vec<(u64, u64)> {
        self.files.keys().copied().collect()
    }

    /// Dirty bytes: what writeback still has to allocate, the data space
    /// reserved for it (`bytes_may_use` of the data space info).
    pub(crate) fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Tree items writeback inserts.
    pub(crate) fn items(&self) -> u64 {
        self.items
    }

    /// Inode items writeback updates, one per dirty inode.
    pub(crate) fn inode_updates(&self) -> u64 {
        self.files.size() as u64
    }

    /// Additional `(items, inode_updates)` writeback may need once a prefix of
    /// the sector-aligned `range` (and an optional `extra_sector` from inline
    /// promotion or tail zeroing) is dirtied on `(tree, inode)`.
    pub(crate) fn reservation_delta(
        &self,
        (tree, inode): (u64, u64),
        flags: u64,
        range: Range<u64>,
        extra_sector: bool,
    ) -> (u64, u64) {
        if range.start >= range.end && !extra_sector {
            return (0, 0);
        }
        let existing = self.file(tree, inode);
        let new_bytes = (range.end - range.start)
            .saturating_sub(existing.map_or(0, |file| file.bytes_in(range.clone())));
        let new_sectors = new_bytes / self.sector + u64::from(extra_sector);
        let extent_delta = match existing {
            Some(file) => file.extent_delta(range),
            None if range.start < range.end => {
                (range.end - range.start).div_ceil(self.extent_limit(flags))
            }
            None => 0,
        } + u64::from(extra_sector);
        let csum_delta = if flags & INODE_NODATASUM == 0 {
            let old = existing.map_or(0, |file| file.pages.size() as u64);
            (old + new_sectors).div_ceil(self.csums_per_leaf) - old.div_ceil(self.csums_per_leaf)
        } else {
            0
        };
        let inode_delta = u64::from(existing.is_none());
        (extent_delta + csum_delta, inode_delta)
    }

    /// Stores `page` as the sector at `offset` of an inode with `flags`.
    pub(crate) fn insert(
        &mut self,
        (tree, inode): (u64, u64),
        flags: u64,
        offset: u64,
        page: Page,
    ) {
        debug_assert_eq!(page.len() as u64, self.sector, "a page is one sector");
        debug_assert!(offset.is_multiple_of(self.sector), "offset is a sector");
        let key = (tree, inode);
        let (compresses, checksummed) = (self.compresses(flags), flags & INODE_NODATASUM == 0);
        let mut file = self
            .take(key)
            .unwrap_or_else(|| DirtyFile::new(compresses, checksummed));
        if !file.pages.contains_key(&offset) {
            file.add_run(offset..offset + self.sector);
        }
        file.pages.insert_mut(offset, page);
        self.store(key, file);
    }

    /// Drops the pages that start within the sector-aligned `range`.
    pub(crate) fn remove_range(&mut self, tree: u64, inode: u64, range: Range<u64>) {
        debug_assert!(
            range.start.is_multiple_of(self.sector)
                && (range.end == u64::MAX || range.end.is_multiple_of(self.sector)),
            "range boundaries are sector-aligned"
        );
        let key = (tree, inode);
        let Some(mut file) = self.take(key) else {
            return;
        };
        let offsets: Vec<u64> = file.pages.range(range.clone()).map(|(&at, _)| at).collect();
        for offset in offsets {
            file.pages.remove_mut(&offset);
        }
        file.cut_runs(range);
        self.store(key, file);
    }

    /// Drops every page of the inode.
    pub(crate) fn remove_file(&mut self, tree: u64, inode: u64) {
        if self.take((tree, inode)).is_some() {
            self.files.remove_mut(&(tree, inode));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(fill: u8) -> Page {
        Arc::from(alloc::vec![fill; 4096])
    }

    #[test]
    fn runs_merge_split_and_count_extents_at_the_inode_limit() {
        let mut dirty = Delalloc::new(4096, 1000, true);
        let file = (5, 257);
        // 160 KiB, then a gap, then one page: compressed windows of 128 KiB.
        for index in (0..40).rev().chain([45]) {
            dirty.insert(file, 0, index * 4096, page(index as u8));
        }
        let state = dirty.file(5, 257).unwrap();
        assert_eq!(state.extent_limit(), MAX_UNCOMPRESSED);
        assert_eq!(
            state.runs(0..u64::MAX),
            [0..40 * 4096, 45 * 4096..46 * 4096]
        );
        assert_eq!(state.extents, 2 + 1);
        assert_eq!(dirty.items(), 3 + 1);
        assert_eq!(dirty.bytes(), 41 * 4096);

        // A cut in the middle of the first window leaves one extent each side.
        dirty.remove_range(5, 257, 4096..2 * 4096);
        let state = dirty.file(5, 257).unwrap();
        assert_eq!(
            state.runs(0..u64::MAX),
            [0..4096, 2 * 4096..40 * 4096, 45 * 4096..46 * 4096]
        );
        assert_eq!(state.runs(2 * 4096 + 1..46 * 4096 - 1).len(), 2);
        assert_eq!(state.extents, 1 + 2 + 1);
        assert_eq!(dirty.bytes(), 40 * 4096);

        // Rewriting a dirty page changes neither the runs nor the totals.
        dirty.insert(file, 0, 0, page(9));
        assert_eq!(dirty.bytes(), 40 * 4096);
        assert_eq!(dirty.file(5, 257).unwrap().pages.get(&0).unwrap()[0], 9);

        dirty.remove_file(5, 257);
        assert!(dirty.file(5, 257).is_none());
        assert_eq!(
            (dirty.bytes(), dirty.items(), dirty.inode_updates()),
            (0, 0, 0)
        );
    }

    #[test]
    fn an_inode_that_does_not_compress_takes_linux_largest_extents() {
        let mut dirty = Delalloc::new(4096, 1000, true);
        dirty.insert((5, 300), INODE_NODATASUM, 0, page(1));
        let file = dirty.file(5, 300).unwrap();
        assert_eq!(file.extent_limit(), MAX_EXTENT_SIZE);
        // No checksum leaf for NODATASUM data.
        assert_eq!(dirty.items(), 1);
        let plain = Delalloc::new(4096, 1000, false);
        assert_eq!(plain.extent_limit(0), MAX_EXTENT_SIZE);
    }

    #[test]
    fn a_view_keeps_the_pages_it_cloned() {
        let mut dirty = Delalloc::new(4096, 1000, false);
        dirty.insert((5, 300), 0, 0, page(1));
        let view = dirty.clone();
        dirty.insert((5, 300), 0, 0, page(2));
        dirty.remove_range(5, 300, 0..4096);
        assert_eq!(view.file(5, 300).unwrap().pages.get(&0).unwrap()[0], 1);
        assert!(dirty.file(5, 300).is_none());
        assert_eq!(view.items(), 2);
    }

    #[test]
    fn reservation_delta_tracks_incremental_growth_and_short_write_splits() {
        let mut dirty = Delalloc::new(4096, 4, false);
        let file = (5, 400);
        // First sector on a clean inode adds 1 extent, 1 csum leaf, 1 inode update.
        assert_eq!(dirty.reservation_delta(file, 0, 0..4096, false), (2, 1));
        dirty.insert(file, 0, 0, page(1));

        // Contiguous appends within one 128 MiB extent and one 4-sector csum leaf
        // add zero new writeback items and zero new inode updates.
        assert_eq!(dirty.reservation_delta(file, 0, 4096..8192, false), (0, 0));
        assert_eq!(dirty.file(5, 400).unwrap().bytes_in(0..8192), 4096);
        for index in 1..4 {
            dirty.insert(file, 0, index * 4096, page(1));
        }
        // Crossing into the second csum leaf adds 1 item.
        assert_eq!(
            dirty.reservation_delta(file, 0, 4 * 4096..5 * 4096, false),
            (1, 0)
        );

        // With a gap between 0..16384 and 24576..28672, a write of 20480..28672
        // that stops short at 20480..24576 leaves a third separate run instead of
        // merging with 24576..28672; `reservation_delta` covers that extra extent.
        dirty.insert(file, 0, 6 * 4096, page(2));
        let before = dirty.items();
        let (delta_items, delta_inodes) =
            dirty.reservation_delta(file, 0, 5 * 4096..7 * 4096, false);
        assert_eq!(delta_inodes, 0);
        dirty.insert(file, 0, 5 * 4096, page(3));
        assert!(dirty.items() - before <= delta_items);
    }
}
