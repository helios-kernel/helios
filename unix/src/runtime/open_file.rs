use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use helios_sync::{RawMutex, RawMutexLease};
use spin::Mutex;

use crate::{FileLockTable, MemfdHold};

static NEXT_OPEN_FILE_ID: AtomicU64 = AtomicU64::new(1);

/// One cached directory entry captured when a directory stream begins reading
/// at offset 0 (`getdents64`), keeping multi-call iteration stable when entries
/// are unlinked between calls (POSIX `readdir(3)` / `rm -rf`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirCursorEntry {
    pub inode: u64,
    pub d_type: u8,
    pub name: String,
}

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
    dir_snapshot: Mutex<Option<Arc<[DirCursorEntry]>>>,
    flock_table: Mutex<Option<FileLockTable>>,
    memfd_hold: Option<MemfdHold>,
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
    dir_snapshot: &'a Mutex<Option<Arc<[DirCursorEntry]>>>,
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

    /// Returns the cached directory listing snapshot for this open file
    /// description, if `getdents64` has already started iterating it.
    pub fn dir_snapshot(&self) -> Option<Arc<[DirCursorEntry]>> {
        self.dir_snapshot.lock().clone()
    }

    /// Replaces or clears the cached directory listing snapshot.
    pub fn set_dir_snapshot(&mut self, snapshot: Option<Arc<[DirCursorEntry]>>) {
        *self.dir_snapshot.lock() = snapshot;
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
            dir_snapshot: Mutex::new(None),
            flock_table: Mutex::new(None),
            memfd_hold: None,
        }))
    }

    /// A new open file description of a `memfd_create(2)` inode holding an RAII
    /// [`MemfdHold`] so the underlying shared object stays live until the last
    /// duplicate descriptor closes.
    pub fn with_memfd_hold(node: Node, hold: MemfdHold) -> Self {
        let id = OpenFileId(NEXT_OPEN_FILE_ID.fetch_add(1, Ordering::Relaxed));
        Self(Arc::new(OpenFileDescription {
            id,
            node,
            offset: AtomicU64::new(0),
            position_lock: RawMutex::new(),
            dir_snapshot: Mutex::new(None),
            flock_table: Mutex::new(None),
            memfd_hold: Some(hold),
        }))
    }

    /// Unique identifier of this open file description (shared across `dup`/`fork`).
    pub fn id(&self) -> OpenFileId {
        self.0.id
    }

    /// Whether this open file description holds a `memfd_create(2)` lease.
    pub fn is_memfd(&self) -> bool {
        self.0.memfd_hold.is_some()
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
            dir_snapshot: &self.0.dir_snapshot,
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
                dir_snapshot: &self.0.dir_snapshot,
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

    #[test]
    fn directory_snapshot_persists_across_clones_and_clears_on_rewind() {
        use super::DirCursorEntry;
        use alloc::string::String;
        use alloc::sync::Arc;

        let dir = OpenFile::new("dir");
        let dup = dir.clone();
        let entries: Arc<[DirCursorEntry]> = alloc::vec![
            DirCursorEntry {
                inode: 1,
                d_type: 4,
                name: String::from("."),
            },
            DirCursorEntry {
                inode: 2,
                d_type: 8,
                name: String::from("alpha"),
            },
        ]
        .into();

        {
            let mut pos = dir.try_lock_position().expect("lock free");
            assert!(pos.dir_snapshot().is_none());
            pos.set_dir_snapshot(Some(Arc::clone(&entries)));
            pos.set(1);
        }

        {
            let mut pos = dup.try_lock_position().expect("lock free");
            let cached = pos.dir_snapshot().expect("snapshot shared across clones");
            assert_eq!(cached.len(), 2);
            assert_eq!(cached[1].name, "alpha");
            pos.set_dir_snapshot(None);
            pos.set(0);
        }

        assert!(
            dir.try_lock_position()
                .expect("lock free")
                .dir_snapshot()
                .is_none()
        );
    }
}
