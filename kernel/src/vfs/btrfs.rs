//! Btrfs over the block cache. Reads pin a published immutable snapshot under
//! a short lock, released before I/O. A kernel task exclusively owns writable
//! transactions; queued requests share durable commits. Per-inode write leases
//! serialize write rounds without blocking unrelated files or the service.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc as SourceArc;
use alloc::vec::Vec;
use core::num::NonZeroUsize;
use core::ops::ControlFlow;

use bytes::{Bytes, BytesMut};
use helios_btrfs::{
    BlockSink, BlockSource, DirPosition, EntryTarget, Error, FileKind, Filesystem, Inode,
    READ_ALIGNMENT, Timestamp,
};
use helios_hal::fs::{
    BlockDevice, BlockSerial, DeviceId, DirCookie, DirEntry, FileSystem, FsError, FsPath, FsResult,
    Metadata, NodeId, NodeKind, OpenFlags, WritePosition,
};
use helios_hal::io::{IoError, IoResult};
use triomphe::Arc;

use crate::{BlockCacheError, BlockPages, CACHE_BLOCK_BYTES, CachedDisk, RootEntropyHandle};
use helios_btrfs::write::{WriteError, Writer};

mod prepared;
mod writer;
pub use prepared::BtrfsWrite;
pub use writer::BtrfsService;
use writer::{Operation, Response};

/// Runtime inputs for writable disk mounts.
#[derive(Clone)]
pub struct BtrfsWriteOptions {
    pub entropy: RootEntropyHandle,
    pub concurrency: NonZeroUsize,
}
type Snapshot<Device> = Filesystem<SourceArc<Image<Device>>>;

#[derive(Debug, thiserror::Error)]
pub enum BtrfsMountError {
    #[error("disk already has an incompatible mount")]
    Busy,
    #[error(transparent)]
    Read(#[from] Error),
    #[error(transparent)]
    Write(#[from] WriteError),
}

// A writable mount excludes independent read snapshots: those snapshots have
// no shared retirement accounting with its writer. Clones of this mount share
// both the image lease and the library's generation pins.
enum MountLease {
    Read {
        _lease: crate::OwnedRawRwLockReadLease,
    },
    Write {
        _lease: crate::OwnedRawRwLockWriteLease,
    },
}

struct Image<Device> {
    disk: CachedDisk<Device>,
    _lease: MountLease,
}

impl<Device: BlockDevice<Buffer = BlockPages>> BlockSource for Image<Device> {
    fn size_bytes(&self) -> u64 {
        self.disk.capacity_blocks() * CACHE_BLOCK_BYTES as u64
    }

    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> IoResult<()> {
        self.disk
            .read_at(offset, buf)
            .await
            .map_err(|error| self.io_error(error))
    }
}

impl<Device: BlockDevice<Buffer = BlockPages>> Image<Device> {
    fn io_error(&self, error: BlockCacheError) -> IoError {
        tracing::warn!(%error, serial = ?self.disk.serial(), "btrfs device operation failed");
        match error {
            BlockCacheError::Device(error) => error,
            BlockCacheError::OutOfRange { .. } | BlockCacheError::ByteRangeOutOfRange { .. } => {
                IoError::OutOfBounds
            }
            BlockCacheError::ReadOnly => IoError::ReadOnly,
            BlockCacheError::Aborted => IoError::DeviceFault,
        }
    }
}

impl<Device: BlockDevice<Buffer = BlockPages>> BlockSink for Image<Device> {
    async fn stage(&self, block: u64, bytes: &[u8; READ_ALIGNMENT as usize]) -> IoResult<()> {
        let mut cached = self
            .disk
            .overwrite(block)
            .await
            .map_err(|error| self.io_error(error))?;
        cached.copy_from_slice(bytes);
        Ok(())
    }

    async fn commit(&self, block: u64, bytes: &[u8; READ_ALIGNMENT as usize]) -> IoResult<()> {
        self.disk
            .commit(block, |cached| cached.copy_from_slice(bytes))
            .await
            .map_err(|error| self.io_error(error))
    }
}

// Both transports address complete cache blocks; no partial-block write can
// accidentally make a superblock visible before its transaction is durable.
const _: () = assert!(READ_ALIGNMENT as usize == CACHE_BLOCK_BYTES);

/// A cloneable Btrfs mount with concurrent snapshot reads.
pub struct BtrfsFs<Device: BlockDevice<Buffer = BlockPages>> {
    inner: Arc<Inner<Device>>,
}

struct Inner<Device: BlockDevice<Buffer = BlockPages>> {
    reader: Arc<spin::Mutex<Snapshot<Device>>>,
    writer: Option<writer::Client>,
    devices: BTreeMap<u64, (DeviceId, u64)>,
    serial: BlockSerial,
    writes: prepared::Leases,
    write_round: usize,
}

impl<Device: BlockDevice<Buffer = BlockPages>> Clone for BtrfsFs<Device> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<Device: BlockDevice<Buffer = BlockPages>> BtrfsFs<Device> {
    /// Validates the image and assigns each subvolume an identity from
    /// the same allocator as every other mount on this machine.
    pub async fn mount(
        disk: CachedDisk<Device>,
        mut allocate_device: impl FnMut() -> DeviceId + Send,
    ) -> Result<Self, BtrfsMountError> {
        let serial = disk.serial();
        let lease = disk.read_mount().ok_or(BtrfsMountError::Busy)?;
        let reader = Filesystem::mount(SourceArc::new(Image {
            disk,
            _lease: MountLease::Read { _lease: lease },
        }))
        .await?;
        let mut devices = BTreeMap::new();
        reader
            .subvolumes(|tree, root_inode| {
                devices.insert(tree, (allocate_device(), root_inode));
            })
            .await?;
        Ok(Self {
            inner: Arc::new(Inner {
                reader: Arc::new(spin::Mutex::new(reader)),
                writer: None,
                devices,
                serial,
                writes: Arc::new(spin::Mutex::new(BTreeMap::new())),
                write_round: CACHE_BLOCK_BYTES,
            }),
        })
    }

    /// Construct a writable mount and its single-owner service. The caller
    /// runs the service on the kernel executor for the mount's lifetime.
    pub async fn mount_writable(
        disk: CachedDisk<Device>,
        mut allocate_device: impl FnMut() -> DeviceId + Send,
        entropy: RootEntropyHandle,
        concurrency: NonZeroUsize,
    ) -> Result<(Self, BtrfsService<Device>), BtrfsMountError> {
        let serial = disk.serial();
        let lease = disk.write_mount().ok_or(BtrfsMountError::Busy)?;
        let writer = Writer::mount(Image {
            disk,
            _lease: MountLease::Write { _lease: lease },
        })
        .await?;
        let reader = writer.snapshot()?;
        let mut devices = BTreeMap::new();
        reader
            .subvolumes(|tree, root_inode| {
                devices.insert(tree, (allocate_device(), root_inode));
            })
            .await?;
        let reader = Arc::new(spin::Mutex::new(reader));
        let (client, receiver) = writer::channel(concurrency);
        let service = BtrfsService {
            writer,
            receiver,
            published: reader.clone(),
            entropy,
            concurrency,
        };
        Ok((
            Self {
                inner: Arc::new(Inner {
                    reader,
                    writer: Some(client),
                    devices,
                    serial,
                    writes: Arc::new(spin::Mutex::new(BTreeMap::new())),
                    write_round: CACHE_BLOCK_BYTES.saturating_mul(concurrency.get()),
                }),
            },
            service,
        ))
    }

    fn snapshot(&self) -> Snapshot<Device> {
        self.inner.reader.lock().clone()
    }

    async fn inode(&self, reader: &Snapshot<Device>, path: FsPath<'_>) -> FsResult<Inode> {
        let mut inode = reader.root().await.map_err(|e| self.fs_error(e))?;
        if !path.is_root() {
            // VFS already normalized the path and owns symlink traversal.
            for name in path.as_str().split('/') {
                inode = reader
                    .lookup(&inode, name.as_bytes())
                    .await
                    .map_err(|e| self.fs_error(e))?
                    .ok_or(FsError::NoEntry)?;
            }
        }
        Ok(inode)
    }

    async fn mutate(&self, path: FsPath<'_>, now: u64, operation: Operation) -> FsResult<()> {
        self.inner
            .writer
            .as_ref()
            .ok_or(FsError::ReadOnly)?
            .execute(path.as_str(), now, operation)
            .await
            .map(drop)
    }

    fn metadata(&self, inode: &Inode) -> FsResult<Metadata> {
        self.inode_metadata(inode.tree(), inode.number(), *inode.metadata())
    }

    fn inode_metadata(
        &self,
        tree: u64,
        number: u64,
        metadata: helios_btrfs::Metadata,
    ) -> FsResult<Metadata> {
        let device = self.inner.devices.get(&tree).ok_or(FsError::Io)?;
        let kind = node_kind(metadata.kind)?;
        Ok(Metadata {
            id: NodeId::new(device.0, number),
            kind,
            link_count: u64::from(metadata.nlink),
            size: if kind == NodeKind::Directory {
                0
            } else {
                metadata.size
            },
            access_nanos: nanos(metadata.atime)?,
            modified_nanos: nanos(metadata.mtime)?,
            status_nanos: nanos(metadata.ctime)?,
        })
    }

    fn fs_error(&self, error: Error) -> FsError {
        match error {
            Error::NotFound { .. } => FsError::NoEntry,
            Error::WrongKind {
                expected: FileKind::Directory,
                ..
            } => FsError::NotDirectory,
            error => {
                tracing::warn!(%error, serial = ?self.inner.serial, "btrfs image is malformed or unreadable");
                FsError::Io
            }
        }
    }
}

fn node_kind(kind: FileKind) -> FsResult<NodeKind> {
    match kind {
        FileKind::Regular => Ok(NodeKind::File),
        FileKind::Directory => Ok(NodeKind::Directory),
        FileKind::Symlink => Ok(NodeKind::Symlink),
        FileKind::CharDevice | FileKind::BlockDevice | FileKind::Fifo | FileKind::Socket => {
            Err(FsError::Unsupported)
        }
    }
}

fn nanos(time: Timestamp) -> FsResult<u64> {
    u64::try_from(time.seconds)
        .ok()
        .and_then(|s| s.checked_mul(1_000_000_000))
        .and_then(|s| s.checked_add(u64::from(time.nanoseconds)))
        .ok_or(FsError::Overflow)
}

impl<Device: BlockDevice<Buffer = BlockPages> + 'static> FileSystem for BtrfsFs<Device> {
    type Write<'a> = BtrfsWrite<Device>;

    async fn stat(&self, path: FsPath<'_>) -> FsResult<Metadata> {
        self.metadata(&self.inode(&self.snapshot(), path).await?)
    }

    async fn open(&self, path: FsPath<'_>, flags: OpenFlags, now: u64) -> FsResult<Metadata> {
        if let Some(writer) = &self.inner.writer {
            return match writer
                .execute(path.as_str(), now, Operation::Open { flags })
                .await?
            {
                Response::Opened { inode, metadata } => {
                    self.inode_metadata(inode.tree(), inode.number(), metadata)
                }
                Response::Done | Response::Written(_) => {
                    unreachable!("open request returns inode metadata")
                }
            };
        }
        let metadata = match self.stat(path).await {
            Ok(metadata) => metadata,
            Err(FsError::NoEntry) if flags.contains(OpenFlags::CREATE) => {
                return Err(FsError::ReadOnly);
            }
            Err(error) => return Err(error),
        };
        if flags.contains(OpenFlags::CREATE | OpenFlags::EXCLUSIVE) {
            return Err(FsError::Exists);
        }
        if flags.contains(OpenFlags::DIRECTORY) && metadata.kind != NodeKind::Directory {
            return Err(FsError::NotDirectory);
        }
        if flags.contains(OpenFlags::TRUNCATE) {
            return Err(FsError::ReadOnly);
        }
        Ok(metadata)
    }

    async fn read_at(&self, path: FsPath<'_>, offset: u64, max_bytes: usize) -> FsResult<Bytes> {
        let reader = self.snapshot();
        let inode = self.inode(&reader, path).await?;
        match node_kind(inode.kind())? {
            NodeKind::File => {}
            NodeKind::Directory => return Err(FsError::IsDirectory),
            NodeKind::Symlink => return Err(FsError::Invalid),
        }
        let len = inode
            .metadata()
            .size
            .saturating_sub(offset)
            .min(max_bytes as u64) as usize;
        let mut bytes = BytesMut::zeroed(len);
        let count = reader
            .read(&inode, offset, &mut bytes)
            .await
            .map_err(|e| self.fs_error(e))?;
        if count != len {
            return Err(FsError::Io);
        }
        Ok(bytes.freeze())
    }

    async fn read_dir(
        &self,
        path: FsPath<'_>,
        cookie: DirCookie,
        max_entries: usize,
    ) -> FsResult<Vec<DirEntry>> {
        let reader = self.snapshot();
        let inode = self.inode(&reader, path).await?;
        let mut entries = Vec::new();
        let mut failure = None;
        reader
            .read_dir(&inode, DirPosition(cookie.raw()), |entry| {
                if entries.len() == max_entries {
                    return ControlFlow::Break(());
                }
                let convert = || -> FsResult<DirEntry> {
                    let number = match entry.target {
                        EntryTarget::Inode(number) => number,
                        EntryTarget::Subvolume(tree) => {
                            self.inner.devices.get(&tree).ok_or(FsError::Io)?.1
                        }
                    };
                    Ok(DirEntry {
                        name: String::from_utf8(entry.name.to_vec())
                            .map_err(|_| FsError::IllegalByteSequence)?,
                        kind: node_kind(entry.kind)?,
                        inode: number,
                        next: DirCookie::new(
                            entry.position.0.checked_add(1).ok_or(FsError::Overflow)?,
                        ),
                    })
                };
                match convert() {
                    Ok(entry) => {
                        entries.push(entry);
                        ControlFlow::Continue(())
                    }
                    Err(error) => {
                        failure = Some(error);
                        ControlFlow::Break(())
                    }
                }
            })
            .await
            .map_err(|e| self.fs_error(e))?;
        match failure {
            Some(error) => Err(error),
            None => Ok(entries),
        }
    }

    async fn read_link(&self, path: FsPath<'_>) -> FsResult<String> {
        let reader = self.snapshot();
        let inode = self.inode(&reader, path).await?;
        if inode.kind() != FileKind::Symlink {
            return Err(FsError::Invalid);
        }
        // BTRFS_PATH_NAME_MAX bounds a symlink's contents before allocating.
        if inode.metadata().size > 4096 {
            return Err(FsError::Io);
        }
        let mut target = alloc::vec![0; inode.metadata().size as usize];
        let count = reader
            .read_link(&inode, &mut target)
            .await
            .map_err(|e| self.fs_error(e))?;
        target.truncate(count);
        String::from_utf8(target).map_err(|_| FsError::IllegalByteSequence)
    }

    async fn prepare_write(
        &self,
        path: FsPath<'_>,
        position: WritePosition,
        len: usize,
        now: u64,
    ) -> FsResult<Self::Write<'_>> {
        prepared::prepare(self, path, position, len, now).await
    }
    async fn set_size(&self, path: FsPath<'_>, size: u64, now: u64) -> FsResult<()> {
        self.mutate(path, now, Operation::Truncate { size }).await
    }
    async fn set_times(
        &self,
        path: FsPath<'_>,
        access: Option<u64>,
        modified: Option<u64>,
        now: u64,
    ) -> FsResult<()> {
        self.mutate(path, now, Operation::Times { access, modified })
            .await
    }
    async fn create_directory(&self, path: FsPath<'_>, now: u64) -> FsResult<()> {
        self.mutate(path, now, Operation::CreateDirectory).await
    }
    async fn remove_directory(&self, path: FsPath<'_>) -> FsResult<()> {
        self.mutate(path, 0, Operation::Remove { directory: true })
            .await
    }
    async fn unlink(&self, path: FsPath<'_>) -> FsResult<()> {
        self.mutate(path, 0, Operation::Remove { directory: false })
            .await
    }
    async fn rename(&self, source: FsPath<'_>, destination: FsPath<'_>, now: u64) -> FsResult<()> {
        self.mutate(
            source,
            now,
            Operation::Rename {
                destination: String::from(destination.as_str()),
            },
        )
        .await
    }
    async fn link(&self, source: FsPath<'_>, destination: FsPath<'_>, now: u64) -> FsResult<()> {
        self.mutate(
            source,
            now,
            Operation::Link {
                destination: String::from(destination.as_str()),
            },
        )
        .await
    }
    async fn symlink(&self, target: &str, path: FsPath<'_>, now: u64) -> FsResult<()> {
        self.mutate(
            path,
            now,
            Operation::Symlink {
                target: String::from(target),
            },
        )
        .await
    }
    async fn sync(&self, path: FsPath<'_>) -> FsResult<()> {
        if self.inner.writer.is_some() {
            self.mutate(path, 0, Operation::Sync).await
        } else {
            self.inode(&self.snapshot(), path).await.map(drop)
        }
    }
    async fn sync_data(&self, path: FsPath<'_>) -> FsResult<()> {
        self.sync(path).await
    }
}

#[cfg(test)]
mod tests;
