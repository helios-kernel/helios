use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use helios_sync::{RawMutex, RawMutexLease};
use spin::Mutex;

use crate::FileLockTable;

static NEXT_OPEN_FILE_ID: AtomicU64 = AtomicU64::new(1);

/// Unique identifier of one POSIX open file description ([`OpenFile`]), shared
/// across `dup`/`dup2`/`fork` duplicates and distinct across separate `open`s.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpenFileId(u64);

impl OpenFileId {
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// The POSIX open file description of a filesystem object: the node handle
/// the platform opened and the file offset every read, write and seek
/// through it moves. A descriptor's status flags live beside it in its
/// [`crate::FileDescriptorEntry`], shared the same way.
///
/// Clones share one description: `dup`, `dup2`, `fork`, spawn descriptor
/// actions and exec inheritance clone it, so every descriptor they produce
/// reads and writes at the same offset, while opening the node again makes
/// a new one. The node handle is the platform's and is never touched here;
/// the platform performs the I/O and reports the offset it reached.
///
/// # Concurrency contract
///
/// Reads, writes and seeks that use or update the file offset acquire
/// [`OpenFile::lock_position`] across reading the current offset, performing
/// the platform I/O that consumes it, and storing the updated offset. The
/// lock is an async [`RawMutex`] from `helios-sync`: waiting tasks park on
/// its wake queue and never spin, and no spin lock is held across an
/// `.await`. Positioned I/O (`pread` and `pwrite`) reads [`OpenFile::node`]
/// directly and never acquires the position lock.
pub struct OpenFile<Node>(Arc<OpenFileDescription<Node>>);

struct OpenFileDescription<Node> {
    id: OpenFileId,
    node: Node,
    offset: AtomicU64,
    position_lock: RawMutex,
    flock_table: Mutex<Option<FileLockTable>>,
}

impl<Node> Drop for OpenFileDescription<Node> {
    fn drop(&mut self) {
        if let Some(table) = self.flock_table.get_mut().take() {
            table.release_all_flocks_for(self.id);
        }
    }
}

/// Exclusive async lease over an [`OpenFile`]'s current file offset.
///
/// Holding this guard serialises offset-using reads, writes and seeks on
/// one open file description without blocking the cooperative executor or
/// holding a spin lock across an `.await`.
pub struct OpenFilePosition<'a> {
    _lease: RawMutexLease<'a>,
    offset: &'a AtomicU64,
}

impl OpenFilePosition<'_> {
    /// The offset the next read or write without an explicit position
    /// starts at.
    pub fn get(&self) -> u64 {
        // The position lock orders every read and write of `offset`.
        self.offset.load(Ordering::Relaxed)
    }

    /// Moves the offset: after a read or write to the offset it reached, or
    /// to where a seek placed it.
    pub fn set(&mut self, offset: u64) {
        self.offset.store(offset, Ordering::Relaxed);
    }
}

impl<Node> OpenFile<Node> {
    /// A new open file description of `node`, at offset 0.
    pub fn new(node: Node) -> Self {
        Self::new_at(node, 0)
    }

    /// A new open file description of `node`, starting at `offset`.
    pub fn new_at(node: Node, offset: u64) -> Self {
        let id = OpenFileId(NEXT_OPEN_FILE_ID.fetch_add(1, Ordering::Relaxed));
        Self(Arc::new(OpenFileDescription {
            id,
            node,
            offset: AtomicU64::new(offset),
            position_lock: RawMutex::new(),
            flock_table: Mutex::new(None),
        }))
    }

    /// Unique identifier of this open file description (shared across `dup`/`fork`).
    pub fn id(&self) -> OpenFileId {
        self.0.id
    }

    /// Registers `table` so any BSD `flock` held by this open file description
    /// is released automatically when its last duplicate descriptor drops.
    pub fn attach_flock_table(&self, table: &FileLockTable) {
        let mut slot = self.0.flock_table.lock();
        if slot.is_none() {
            *slot = Some(table.clone());
        }
    }

    /// The node handle the description was opened on.
    pub fn node(&self) -> &Node {
        &self.0.node
    }

    /// Acquires exclusive access to the open file description's position,
    /// waiting asynchronously until any in-flight offset-using operation
    /// finishes.
    pub async fn lock_position(&self) -> OpenFilePosition<'_> {
        OpenFilePosition {
            _lease: self.0.position_lock.lock().await,
            offset: &self.0.offset,
        }
    }

    /// Acquires exclusive access to the open file description's position
    /// immediately if no other offset-using operation holds it.
    pub fn try_lock_position(&self) -> Option<OpenFilePosition<'_>> {
        self.0
            .position_lock
            .try_lock()
            .map(|lease| OpenFilePosition {
                _lease: lease,
                offset: &self.0.offset,
            })
    }

    /// Whether `self` and `other` are the same open file description.
    pub fn same_description(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl<Node> Clone for OpenFile<Node> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::OpenFile;
    use core::future::Future;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};
    use futures_lite::future::{block_on, poll_once, yield_now, zip};

    #[test]
    fn clones_share_the_offset_and_a_new_open_does_not() {
        let file = OpenFile::new("node");
        let duplicate = file.clone();
        duplicate
            .try_lock_position()
            .expect("the position lock is free")
            .set(12);
        assert_eq!(
            file.try_lock_position()
                .expect("the position lock is free")
                .get(),
            12
        );
        assert!(file.same_description(&duplicate));

        let reopened = OpenFile::new(*file.node());
        assert_eq!(
            reopened
                .try_lock_position()
                .expect("a reopened description has its own lock")
                .get(),
            0
        );
        assert!(!reopened.same_description(&file));

        let split = OpenFile::new_at(*file.node(), 12);
        assert_eq!(
            split
                .try_lock_position()
                .expect("a split description has its own lock")
                .get(),
            12
        );
        assert!(!split.same_description(&file));
    }

    #[test]
    fn overlapping_position_updates_serialise_across_awaits() {
        let file = OpenFile::new("node");
        let duplicate = file.clone();

        let first = async {
            let mut position = file.lock_position().await;
            assert!(
                duplicate.try_lock_position().is_none(),
                "a duplicate sees the held lock"
            );
            let start = position.get();
            yield_now().await;
            position.set(start + 12);
        };
        let second = async {
            let mut position = duplicate.lock_position().await;
            let start = position.get();
            assert_eq!(
                start, 12,
                "second operation must see the first's final offset"
            );
            position.set(start + 8);
        };

        block_on(zip(first, second));
        assert_eq!(
            block_on(file.lock_position()).get(),
            20,
            "final offset reflects both serialised updates"
        );
    }

    #[test]
    fn dropping_a_waiter_or_holder_releases_the_position_lock() {
        let file = OpenFile::new("node");
        let duplicate = file.clone();

        {
            let mut held = pin!(async {
                let mut pos = file.lock_position().await;
                pos.set(5);
                core::future::pending::<()>().await;
            });
            let waker = Waker::noop();
            let mut cx = Context::from_waker(waker);
            assert!(matches!(held.as_mut().poll(&mut cx), Poll::Pending));

            let mut waiting = pin!(duplicate.lock_position());
            assert!(
                matches!(waiting.as_mut().poll(&mut cx), Poll::Pending),
                "second caller parks while first holds the lock"
            );
        }

        let mut pos = block_on(poll_once(duplicate.lock_position()))
            .expect("dropping holder and parked waiter leaves lock acquirable");
        assert_eq!(pos.get(), 5);
        pos.set(9);
        drop(pos);
        assert_eq!(block_on(file.lock_position()).get(), 9);
    }
}
