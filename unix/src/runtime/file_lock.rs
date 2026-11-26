//! Advisory file locks shared across processes in one container: BSD whole-file
//! locks (`flock(2)`) and POSIX byte-range record locks (`fcntl(2)` `F_GETLK`,
//! `F_SETLK`, `F_SETLKW`).
//!
//! Semantics follow Linux v6.12 (`fs/locks.c`):
//! - BSD `flock` locks are associated with an open file description
//!   ([`OpenFileId`]), inherited across `dup`/`fork`, independent of POSIX
//!   record locks, and automatically released when the last descriptor for that
//!   open file description drops.
//! - POSIX record locks are associated with a process ([`ProcessIdentity`]),
//!   NOT inherited across `fork`, merged/split atomically per byte range, and
//!   released for `(process, file)` whenever ANY descriptor referring to that
//!   file is closed by that process.
//!
//! # Concurrency contract
//!
//! Lock state lives behind a short synchronous `spin::Mutex` that is never held
//! across an `.await`. Blocking waiters arm a [`NotifyWaiter`] before testing
//! conflict, park cooperatively on [`Notify`], and wake on any unlock or lock
//! downgrade without busy-waiting.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::task::{Context, Poll};

use helios_sync::{Notify, NotifyWaiter};
use spin::Mutex;

use crate::{OpenFileId, ProcessIdentity};

/// Stable underlying-file key `(device, inode)` identifying one lockable file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileLockKey {
    pub dev: u64,
    pub ino: u64,
}

impl FileLockKey {
    pub const fn new(dev: u64, ino: u64) -> Self {
        Self { dev, ino }
    }
}

/// BSD `flock(2)` lock mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlockKind {
    Shared,
    Exclusive,
}

/// POSIX `fcntl(2)` byte-range lock mode (`F_RDLCK`, `F_WRLCK`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PosixLockKind {
    Read,
    Write,
}

/// Inclusive byte range `[start, end]` of a POSIX advisory lock (`end == i64::MAX as u64`
/// denotes "to end of file", matching Linux `OFFSET_MAX`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

impl ByteRange {
    /// Maximum inclusive byte offset (`OFFSET_MAX` in Linux `fs/locks.c`).
    pub const MAX_END: u64 = i64::MAX as u64;

    pub const fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    pub const fn overlaps(self, other: Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    pub const fn touches_or_overlaps(self, other: Self) -> bool {
        self.start <= other.end.saturating_add(1) && other.start <= self.end.saturating_add(1)
    }
}

/// A conflicting POSIX record lock reported by `F_GETLK`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PosixLockConflict {
    pub owner: ProcessIdentity,
    pub kind: PosixLockKind,
    pub range: ByteRange,
}

#[derive(Clone, Copy, Debug)]
struct FlockEntry {
    owner: OpenFileId,
    kind: FlockKind,
}

#[derive(Clone, Copy, Debug)]
struct PosixLockEntry {
    owner: ProcessIdentity,
    kind: PosixLockKind,
    range: ByteRange,
}

#[derive(Default)]
struct FileLocks {
    flocks: Vec<FlockEntry>,
    posix: Vec<PosixLockEntry>,
}

impl FileLocks {
    fn is_empty(&self) -> bool {
        self.flocks.is_empty() && self.posix.is_empty()
    }
}

struct FileLockTableInner {
    files: Mutex<BTreeMap<FileLockKey, FileLocks>>,
    changed: Notify,
}

/// Container-wide advisory file lock registry shared across processes.
#[derive(Clone)]
pub struct FileLockTable {
    inner: Arc<FileLockTableInner>,
}

impl Default for FileLockTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FileLockTable {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(FileLockTableInner {
                files: Mutex::new(BTreeMap::new()),
                changed: Notify::new(),
            }),
        }
    }

    /// Arms a waiter before attempting a potentially blocking lock acquisition.
    pub fn waiter(&self) -> NotifyWaiter {
        self.inner.changed.waiter()
    }

    /// Polls a waiter armed by [`Self::waiter`].
    pub fn poll_changed(&self, cx: &mut Context<'_>, waiter: &mut NotifyWaiter) -> Poll<()> {
        self.inner.changed.poll_notified(cx, waiter)
    }

    /// Attempts to acquire or upgrade/downgrade a BSD `flock` on `key` for open
    /// file description `owner`. Returns `true` if acquired, `false` on conflict.
    ///
    /// Per Linux `fs/locks.c` `flock_lock_inode`: if `owner` already holds a
    /// lock on `key` and upgrading to `Exclusive` conflicts with another
    /// holder, `release_on_conflict` drops `owner`'s prior lock before waiting
    /// so two concurrent upgraders cannot deadlock.
    pub fn try_flock(
        &self,
        key: FileLockKey,
        owner: OpenFileId,
        kind: FlockKind,
        release_on_conflict: bool,
    ) -> bool {
        let mut notify = false;
        let acquired = {
            let mut files = self.inner.files.lock();
            let entry = files.entry(key).or_default();
            let conflict = entry.flocks.iter().any(|held| {
                held.owner != owner
                    && (kind == FlockKind::Exclusive || held.kind == FlockKind::Exclusive)
            });
            if conflict {
                if release_on_conflict
                    && let Some(pos) = entry.flocks.iter().position(|held| held.owner == owner)
                {
                    entry.flocks.swap_remove(pos);
                    notify = true;
                    if entry.is_empty() {
                        files.remove(&key);
                    }
                }
                false
            } else {
                if let Some(held) = entry.flocks.iter_mut().find(|held| held.owner == owner) {
                    if held.kind == FlockKind::Exclusive && kind == FlockKind::Shared {
                        notify = true;
                    }
                    held.kind = kind;
                } else {
                    entry.flocks.push(FlockEntry { owner, kind });
                }
                true
            }
        };
        if notify {
            self.inner.changed.notify_all();
        }
        acquired
    }

    /// Releases any BSD `flock` held by `owner` on `key`.
    pub fn unlock_flock(&self, key: FileLockKey, owner: OpenFileId) {
        let removed = {
            let mut files = self.inner.files.lock();
            let Some(entry) = files.get_mut(&key) else {
                return;
            };
            let before = entry.flocks.len();
            entry.flocks.retain(|held| held.owner != owner);
            let removed = entry.flocks.len() != before;
            if entry.is_empty() {
                files.remove(&key);
            }
            removed
        };
        if removed {
            self.inner.changed.notify_all();
        }
    }

    /// Releases every BSD `flock` held by `owner` across all files (called when
    /// the last descriptor referencing an [`crate::OpenFile`] drops).
    pub fn release_all_flocks_for(&self, owner: OpenFileId) {
        let removed = {
            let mut files = self.inner.files.lock();
            let mut removed = false;
            files.retain(|_, entry| {
                let before = entry.flocks.len();
                entry.flocks.retain(|held| held.owner != owner);
                if entry.flocks.len() != before {
                    removed = true;
                }
                !entry.is_empty()
            });
            removed
        };
        if removed {
            self.inner.changed.notify_all();
        }
    }

    /// Queries the first POSIX record lock conflicting with `(owner, kind, range)`
    /// on `key` (`fcntl(F_GETLK)`).
    pub fn test_posix_lock(
        &self,
        key: FileLockKey,
        owner: ProcessIdentity,
        kind: PosixLockKind,
        range: ByteRange,
    ) -> Option<PosixLockConflict> {
        let files = self.inner.files.lock();
        let entry = files.get(&key)?;
        entry
            .posix
            .iter()
            .find(|held| {
                held.owner != owner
                    && held.range.overlaps(range)
                    && (kind == PosixLockKind::Write || held.kind == PosixLockKind::Write)
            })
            .map(|held| PosixLockConflict {
                owner: held.owner,
                kind: held.kind,
                range: held.range,
            })
    }

    /// Attempts to set a POSIX record lock (`F_RDLCK`/`F_WRLCK`) on `key` for
    /// `owner` over `range`. Returns `true` on success, `false` on conflict.
    pub fn try_set_posix_lock(
        &self,
        key: FileLockKey,
        owner: ProcessIdentity,
        kind: PosixLockKind,
        range: ByteRange,
    ) -> bool {
        let mut downgraded = false;
        let acquired = {
            let mut files = self.inner.files.lock();
            let entry = files.entry(key).or_default();
            let conflict = entry.posix.iter().any(|held| {
                held.owner != owner
                    && held.range.overlaps(range)
                    && (kind == PosixLockKind::Write || held.kind == PosixLockKind::Write)
            });
            if conflict {
                false
            } else {
                // Remove or split any existing locks of `owner` overlapping `range`.
                let mut updated = Vec::with_capacity(entry.posix.len() + 2);
                let mut merged = range;
                for held in entry.posix.drain(..) {
                    if held.owner != owner {
                        updated.push(held);
                        continue;
                    }
                    if held.kind == kind && held.range.touches_or_overlaps(merged) {
                        merged.start = merged.start.min(held.range.start);
                        merged.end = merged.end.max(held.range.end);
                        continue;
                    }
                    if !held.range.overlaps(range) {
                        updated.push(held);
                        continue;
                    }
                    if held.kind == PosixLockKind::Write && kind == PosixLockKind::Read {
                        downgraded = true;
                    }
                    if held.range.start < range.start {
                        updated.push(PosixLockEntry {
                            owner,
                            kind: held.kind,
                            range: ByteRange::new(held.range.start, range.start - 1),
                        });
                    }
                    if held.range.end > range.end {
                        updated.push(PosixLockEntry {
                            owner,
                            kind: held.kind,
                            range: ByteRange::new(range.end + 1, held.range.end),
                        });
                    }
                }
                // Merge `merged` with any same-kind locks of `owner` that now touch it.
                let mut final_list = Vec::with_capacity(updated.len() + 1);
                for held in updated {
                    if held.owner == owner
                        && held.kind == kind
                        && held.range.touches_or_overlaps(merged)
                    {
                        merged.start = merged.start.min(held.range.start);
                        merged.end = merged.end.max(held.range.end);
                    } else {
                        final_list.push(held);
                    }
                }
                final_list.push(PosixLockEntry {
                    owner,
                    kind,
                    range: merged,
                });
                entry.posix = final_list;
                true
            }
        };
        if downgraded {
            self.inner.changed.notify_all();
        }
        acquired
    }

    /// Unlocks `range` of `key` for `owner` (`F_UNLCK`), splitting any lock that
    /// extends past either end of `range`.
    pub fn unlock_posix_range(&self, key: FileLockKey, owner: ProcessIdentity, range: ByteRange) {
        let removed = {
            let mut files = self.inner.files.lock();
            let Some(entry) = files.get_mut(&key) else {
                return;
            };
            let mut changed = false;
            let mut updated = Vec::with_capacity(entry.posix.len() + 1);
            for held in entry.posix.drain(..) {
                if held.owner != owner || !held.range.overlaps(range) {
                    updated.push(held);
                    continue;
                }
                changed = true;
                if held.range.start < range.start {
                    updated.push(PosixLockEntry {
                        owner,
                        kind: held.kind,
                        range: ByteRange::new(held.range.start, range.start - 1),
                    });
                }
                if held.range.end > range.end {
                    updated.push(PosixLockEntry {
                        owner,
                        kind: held.kind,
                        range: ByteRange::new(range.end + 1, held.range.end),
                    });
                }
            }
            entry.posix = updated;
            if entry.is_empty() {
                files.remove(&key);
            }
            changed
        };
        if removed {
            self.inner.changed.notify_all();
        }
    }

    /// Releases every POSIX record lock held by `owner` on `key` (called when
    /// `owner` closes ANY file descriptor referring to `key`).
    pub fn release_posix_for_file(&self, key: FileLockKey, owner: ProcessIdentity) {
        let removed = {
            let mut files = self.inner.files.lock();
            let Some(entry) = files.get_mut(&key) else {
                return;
            };
            let before = entry.posix.len();
            entry.posix.retain(|held| held.owner != owner);
            let removed = entry.posix.len() != before;
            if entry.is_empty() {
                files.remove(&key);
            }
            removed
        };
        if removed {
            self.inner.changed.notify_all();
        }
    }

    /// Releases every POSIX record lock held by `owner` across all files (called
    /// on process exit).
    pub fn release_posix_for_process(&self, owner: ProcessIdentity) {
        let removed = {
            let mut files = self.inner.files.lock();
            let mut removed = false;
            files.retain(|_, entry| {
                let before = entry.posix.len();
                entry.posix.retain(|held| held.owner != owner);
                if entry.posix.len() != before {
                    removed = true;
                }
                !entry.is_empty()
            });
            removed
        };
        if removed {
            self.inner.changed.notify_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;

    fn pid(n: u64) -> ProcessIdentity {
        ProcessIdentity::new(NonZeroU64::new(n).unwrap())
    }

    #[test]
    fn flock_shared_exclusive_upgrade_downgrade_and_release() {
        let table = FileLockTable::new();
        let file = FileLockKey::new(1, 42);
        let fd1 = OpenFileId::new(1);
        let fd2 = OpenFileId::new(2);

        assert!(table.try_flock(file, fd1, FlockKind::Shared, false));
        assert!(table.try_flock(file, fd2, FlockKind::Shared, false));
        // Exclusive blocked by fd2.
        assert!(!table.try_flock(file, fd1, FlockKind::Exclusive, false));
        // Release fd2 -> fd1 can upgrade.
        table.unlock_flock(file, fd2);
        assert!(table.try_flock(file, fd1, FlockKind::Exclusive, false));
        // fd2 blocked while fd1 holds Exclusive.
        assert!(!table.try_flock(file, fd2, FlockKind::Shared, false));
        // Downgrade fd1 -> fd2 can acquire Shared.
        assert!(table.try_flock(file, fd1, FlockKind::Shared, false));
        assert!(table.try_flock(file, fd2, FlockKind::Shared, false));
        // Drop-style release clears all locks for fd1.
        table.release_all_flocks_for(fd1);
        assert!(table.try_flock(file, fd2, FlockKind::Exclusive, false));
    }

    #[test]
    fn posix_record_locks_split_merge_and_release_per_process() {
        let table = FileLockTable::new();
        let file = FileLockKey::new(1, 99);
        let p1 = pid(1);
        let p2 = pid(2);

        // p1 locks [0, 99] exclusively.
        assert!(table.try_set_posix_lock(file, p1, PosixLockKind::Write, ByteRange::new(0, 99)));
        // p2 sees conflict at [10, 20].
        let conflict = table
            .test_posix_lock(file, p2, PosixLockKind::Read, ByteRange::new(10, 20))
            .expect("must conflict");
        assert_eq!(conflict.owner, p1);
        assert_eq!(conflict.range, ByteRange::new(0, 99));

        // p1 unlocks middle [20, 49], splitting into [0, 19] and [50, 99].
        table.unlock_posix_range(file, p1, ByteRange::new(20, 49));
        assert!(
            table
                .test_posix_lock(file, p2, PosixLockKind::Write, ByteRange::new(20, 49))
                .is_none()
        );
        assert!(table.try_set_posix_lock(file, p2, PosixLockKind::Write, ByteRange::new(20, 49)));
        assert_eq!(
            table
                .test_posix_lock(file, p2, PosixLockKind::Read, ByteRange::new(50, 50))
                .unwrap()
                .range,
            ByteRange::new(50, 99)
        );

        // Closing any fd of `file` by p1 releases all p1 locks on `file` without affecting p2.
        table.release_posix_for_file(file, p1);
        assert!(
            table
                .test_posix_lock(file, p2, PosixLockKind::Write, ByteRange::new(0, 19))
                .is_none()
        );
        assert!(
            table
                .test_posix_lock(file, p1, PosixLockKind::Read, ByteRange::new(25, 30))
                .is_some()
        );
    }
}
