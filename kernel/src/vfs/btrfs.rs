//! Btrfs over the block cache. Mounting assigns one device identity per
//! subvolume; all later operations share immutable state and take no
//! adapter lock. The cache supplies the concurrency contract for disk I/O.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::Infallible;
use core::ops::ControlFlow;

use bytes::{Bytes, BytesMut};
use helios_btrfs::{
    BlockSource, DirPosition, EntryTarget, Error, FileKind, Filesystem, Inode, Timestamp,
};
use helios_hal::fs::{
    BlockDevice, BlockSerial, DeviceId, DirCookie, DirEntry, FileSystem, FsError, FsPath, FsResult,
    Metadata, NodeId, NodeKind, OpenFlags, WritePosition,
};
use helios_hal::io::{IoError, IoResult};
use triomphe::Arc;

use crate::{BlockCacheError, BlockPages, CACHE_BLOCK_BYTES, CachedDisk};

struct Image<Device> {
    disk: CachedDisk<Device>,
}

impl<Device: BlockDevice<Buffer = BlockPages>> BlockSource for Image<Device> {
    fn size_bytes(&self) -> u64 {
        self.disk.capacity_blocks() * CACHE_BLOCK_BYTES as u64
    }

    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> IoResult<()> {
        self.disk.read_at(offset, buf).await.map_err(|error| {
            tracing::warn!(%error, serial = ?self.disk.serial(), "btrfs image read failed");
            match error {
                BlockCacheError::Device(error) => error,
                BlockCacheError::OutOfRange { .. }
                | BlockCacheError::ByteRangeOutOfRange { .. } => IoError::OutOfBounds,
                BlockCacheError::ReadOnly => IoError::ReadOnly,
                BlockCacheError::Aborted => IoError::DeviceFault,
            }
        })
    }
}

/// A cloneable, read-only btrfs mount.
pub struct BtrfsFs<Device: BlockDevice<Buffer = BlockPages>> {
    inner: Arc<Inner<Device>>,
}

struct Inner<Device: BlockDevice<Buffer = BlockPages>> {
    reader: Filesystem<Image<Device>>,
    devices: BTreeMap<u64, (DeviceId, u64)>,
    serial: BlockSerial,
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
    ) -> Result<Self, Error> {
        let serial = disk.serial();
        let reader = Filesystem::mount(Image { disk }).await?;
        let mut devices = BTreeMap::new();
        reader
            .subvolumes(|tree, root_inode| {
                devices.insert(tree, (allocate_device(), root_inode));
            })
            .await?;
        Ok(Self {
            inner: Arc::new(Inner {
                reader,
                devices,
                serial,
            }),
        })
    }

    async fn inode(&self, path: FsPath<'_>) -> FsResult<Inode> {
        let mut inode = self
            .inner
            .reader
            .root()
            .await
            .map_err(|e| self.fs_error(e))?;
        if path.is_root() {
            return Ok(inode);
        }
        // VFS already normalized the path and owns symlink traversal.
        for name in path.as_str().split('/') {
            inode = self
                .inner
                .reader
                .lookup(&inode, name.as_bytes())
                .await
                .map_err(|e| self.fs_error(e))?
                .ok_or(FsError::NoEntry)?;
        }
        Ok(inode)
    }

    fn metadata(&self, inode: &Inode) -> FsResult<Metadata> {
        let metadata = inode.metadata();
        let device = self.inner.devices.get(&inode.tree()).ok_or(FsError::Io)?;
        let kind = node_kind(inode.kind())?;
        Ok(Metadata {
            id: NodeId::new(device.0, inode.number()),
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
    type Write = Infallible;

    async fn stat(&self, path: FsPath<'_>) -> FsResult<Metadata> {
        self.metadata(&self.inode(path).await?)
    }

    async fn open(&self, path: FsPath<'_>, flags: OpenFlags, _: u64) -> FsResult<Metadata> {
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
        let inode = self.inode(path).await?;
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
        let count = self
            .inner
            .reader
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
        let inode = self.inode(path).await?;
        let mut entries = Vec::new();
        let mut failure = None;
        self.inner
            .reader
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
        let inode = self.inode(path).await?;
        if inode.kind() != FileKind::Symlink {
            return Err(FsError::Invalid);
        }
        // BTRFS_PATH_NAME_MAX bounds a symlink's contents before allocating.
        if inode.metadata().size > 4096 {
            return Err(FsError::Io);
        }
        let mut target = alloc::vec![0; inode.metadata().size as usize];
        let count = self
            .inner
            .reader
            .read_link(&inode, &mut target)
            .await
            .map_err(|e| self.fs_error(e))?;
        target.truncate(count);
        String::from_utf8(target).map_err(|_| FsError::IllegalByteSequence)
    }

    async fn prepare_write(
        &self,
        _: FsPath<'_>,
        _: WritePosition,
        _: usize,
        _: u64,
    ) -> FsResult<Infallible> {
        Err(FsError::ReadOnly)
    }
    async fn set_size(&self, _: FsPath<'_>, _: u64, _: u64) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }
    async fn set_times(
        &self,
        _: FsPath<'_>,
        _: Option<u64>,
        _: Option<u64>,
        _: u64,
    ) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }
    async fn create_directory(&self, _: FsPath<'_>, _: u64) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }
    async fn remove_directory(&self, _: FsPath<'_>) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }
    async fn unlink(&self, _: FsPath<'_>) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }
    async fn rename(&self, _: FsPath<'_>, _: FsPath<'_>, _: u64) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }
    async fn link(&self, _: FsPath<'_>, _: FsPath<'_>, _: u64) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }
    async fn symlink(&self, _: &str, _: FsPath<'_>, _: u64) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }
    async fn sync(&self, path: FsPath<'_>) -> FsResult<()> {
        self.inode(path).await.map(drop)
    }
    async fn sync_data(&self, path: FsPath<'_>) -> FsResult<()> {
        self.inode(path).await.map(drop)
    }
}

#[cfg(test)]
mod tests;
