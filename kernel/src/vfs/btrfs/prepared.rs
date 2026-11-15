//! Per-inode write leases keep append rounds contiguous without parking the
//! mount service or excluding writes to unrelated inodes.

use alloc::collections::BTreeMap;
use alloc::sync::Arc as MutexArc;
use bytes::BytesMut;
use helios_btrfs::FileKind;
use helios_btrfs::write::InodeHandle;
use helios_hal::fs::{
    BlockDevice, FsError, FsPath, FsResult, OpenFlags, PreparedWrite, WritePosition, WriteProgress,
};
use triomphe::Arc;

use super::{BtrfsFs, Operation, Response};
use crate::{BlockPages, OwnedRawMutexLease, RawMutex};

pub(super) type Leases = Arc<spin::Mutex<BTreeMap<(u64, u64), MutexArc<RawMutex>>>>;

struct Lease {
    table: Leases,
    key: (u64, u64),
    mutex: MutexArc<RawMutex>,
    held: Option<OwnedRawMutexLease>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.held.take();
        let mut table = self.table.lock();
        // The table and this lease are the last owners; no parked writer can
        // still acquire this mutex after its entry is removed.
        if MutexArc::strong_count(&self.mutex) == 2 {
            table.remove(&self.key);
        }
    }
}

/// One staged round, retaining its inode identity across namespace changes.
pub struct BtrfsWrite<Device: BlockDevice<Buffer = BlockPages>> {
    fs: BtrfsFs<Device>,
    inode: InodeHandle,
    position: WritePosition,
    start: Option<u64>,
    completed: usize,
    remaining: usize,
    now: u64,
    bytes: BytesMut,
    _lease: Lease,
}

pub(super) async fn prepare<Device: BlockDevice<Buffer = BlockPages>>(
    fs: &BtrfsFs<Device>,
    path: FsPath<'_>,
    position: WritePosition,
    len: usize,
    now: u64,
) -> FsResult<BtrfsWrite<Device>> {
    let writer = fs.inner.writer.as_ref().ok_or(FsError::ReadOnly)?;
    let Response::Opened { inode, metadata } = writer
        .execute(
            path.as_str(),
            now,
            Operation::Open {
                flags: OpenFlags::empty(),
            },
        )
        .await?
    else {
        unreachable!("open request returns an inode");
    };
    match metadata.kind {
        FileKind::Regular => {}
        FileKind::Directory => return Err(FsError::IsDirectory),
        _ => return Err(FsError::Invalid),
    }
    let key = (inode.tree(), inode.number());
    let mutex = fs
        .inner
        .writes
        .lock()
        .entry(key)
        .or_insert_with(|| MutexArc::new(RawMutex::new()))
        .clone();
    let lease = Lease {
        table: fs.inner.writes.clone(),
        key,
        mutex,
        held: None,
    };
    Ok(BtrfsWrite {
        fs: fs.clone(),
        inode,
        position,
        start: None,
        completed: 0,
        remaining: len,
        now,
        bytes: BytesMut::zeroed(len.min(fs.inner.write_round)),
        _lease: lease,
    })
}

impl<Device: BlockDevice<Buffer = BlockPages>> PreparedWrite for BtrfsWrite<Device> {
    fn staged_len(&self) -> usize {
        self.bytes.len()
    }

    fn submit<F>(
        mut self,
        mut fill: F,
    ) -> impl core::future::Future<Output = FsResult<WriteProgress<Self>>> + Send
    where
        F: FnMut(usize, &mut [u8]),
    {
        fill(self.completed, &mut self.bytes);
        async move {
            if self._lease.held.is_none() {
                self._lease.held = Some(self._lease.mutex.lock_owned().await);
            }
            let length = self.bytes.len();
            let bytes = self.bytes.split().freeze();
            let writer = self
                .fs
                .inner
                .writer
                .as_ref()
                .expect("prepared on writable mount");
            let Response::Written(offset) = writer
                .execute(
                    "",
                    self.now,
                    Operation::Write {
                        inode: self.inode.clone(),
                        position: self.position,
                        bytes,
                    },
                )
                .await?
            else {
                unreachable!("write request returns its offset");
            };
            let start = *self.start.get_or_insert(offset);
            self.completed += length;
            self.remaining -= length;
            if self.remaining == 0 {
                return Ok(WriteProgress::Done(start));
            }
            self.position =
                WritePosition::At(offset.checked_add(length as u64).ok_or(FsError::Overflow)?);
            self.bytes = BytesMut::zeroed(self.remaining.min(self.fs.inner.write_round));
            Ok(WriteProgress::More(self))
        }
    }
}
