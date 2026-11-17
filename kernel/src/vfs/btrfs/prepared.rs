//! Per-inode write leases keep append rounds contiguous without parking the
//! mount service or excluding writes to unrelated inodes.

use alloc::collections::BTreeMap;
use alloc::sync::Arc as MutexArc;
use bytes::BytesMut;
use helios_btrfs::FileKind;
use helios_btrfs::write::InodeHandle;
use helios_hal::fs::{
    BlockDevice, FilledWrite, FsError, FsPath, FsResult, Landed, OpenFlags, PreparedWrite,
    WritePosition, WriteProgress,
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

/// A round whose bytes are in place, waiting for its lease and its submit.
pub struct BtrfsFilled<Device: BlockDevice<Buffer = BlockPages>>(BtrfsWrite<Device>);

impl<Device: BlockDevice<Buffer = BlockPages>> PreparedWrite for BtrfsWrite<Device> {
    type Filled = BtrfsFilled<Device>;

    fn staged_len(&self) -> usize {
        self.bytes.len()
    }

    fn fill<F>(mut self, mut fill: F) -> Self::Filled
    where
        F: FnMut(usize, &mut [u8]),
    {
        fill(self.completed, &mut self.bytes);
        BtrfsFilled(self)
    }
}

impl<Device: BlockDevice<Buffer = BlockPages>> FilledWrite for BtrfsFilled<Device> {
    type Next = BtrfsWrite<Device>;

    async fn submit(self) -> FsResult<WriteProgress<Self::Next>> {
        let mut this = self.0;
        if this._lease.held.is_none() {
            this._lease.held = Some(this._lease.mutex.lock_owned().await);
        }
        let length = this.bytes.len();
        let bytes = this.bytes.split().freeze();
        let writer = this
            .fs
            .inner
            .writer
            .as_ref()
            .expect("prepared on writable mount");
        let written = writer
            .execute(
                "",
                this.now,
                Operation::Write {
                    inode: this.inode.clone(),
                    position: this.position,
                    bytes,
                },
            )
            .await;
        let landed = match written {
            Ok(Response::Written(landed)) => landed,
            Ok(_) => unreachable!("write request returns where and how much landed"),
            // A device that filled exactly at a round's end refuses the
            // next round whole; the rounds before it are stored.
            Err(FsError::NoSpace) if this.completed > 0 => {
                let offset = this.start.expect("a round landed before this one");
                return Ok(WriteProgress::Done(Landed {
                    offset,
                    len: this.completed,
                }));
            }
            Err(error) => return Err(error),
        };
        let start = *this.start.get_or_insert(landed.offset);
        this.completed += landed.len;
        // A round that stores less than it staged found the device
        // full: the write ends with what landed so far. Nothing landing
        // at all is the error, so a short write is never empty.
        if landed.len < length {
            return match this.completed {
                0 => Err(FsError::NoSpace),
                len => Ok(WriteProgress::Done(Landed { offset: start, len })),
            };
        }
        this.remaining -= length;
        if this.remaining == 0 {
            return Ok(WriteProgress::Done(Landed {
                offset: start,
                len: this.completed,
            }));
        }
        this.position = WritePosition::At(
            landed
                .offset
                .checked_add(length as u64)
                .ok_or(FsError::Overflow)?,
        );
        this.bytes = BytesMut::zeroed(this.remaining.min(this.fs.inner.write_round));
        Ok(WriteProgress::More(this))
    }
}
