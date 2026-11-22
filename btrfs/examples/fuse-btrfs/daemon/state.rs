//! The writer, the inode map and every operation the daemon serves.
//!
//! As Linux's btrfs, a change is visible at once and durable at commit. Each
//! mutation joins the writer's running transaction, and reads go through the
//! writer's view of it, so the next request sees every reply's change. The
//! transaction commits on `fsync`, `fsyncdir`, `remount,ro` and unmount, and
//! when its dirty metadata reaches Linux's bound.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::num::NonZeroUsize;
use std::ops::ControlFlow;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    Errno, FileAttr, FileHandle, FileType, Generation, INodeNo, OpenAccMode, OpenFlags, TimeOrNow,
};
use futures_lite::future::block_on;
use helios_btrfs::write::{
    Attributes, Compressor, DEFAULT_DIRTY_METADATA_LIMIT, InodeHandle, Name, RootUuids, Special,
    WriteError, Writer, XattrMode, default_dirty_data_limit,
};
use helios_btrfs::{
    BlockSink, BlockSource, DirBound, DirPosition, EntryTarget, Error, FileKind, Filesystem, Inode,
    Metadata, Timestamp,
};
use helios_hal::fs::RenameMode;

use super::OpenError;
use super::device::{Claim, Device};
use super::errno::{read_errno, write_errno};
use super::inodes::{Identity, Inodes};

/// The longest directory entry name, `BTRFS_NAME_LEN` in `btrfs_tree.h`.
const NAME_MAX: usize = 255;

/// The first inode number of a subvolume's tree is its root directory's,
/// `BTRFS_FIRST_FREE_OBJECTID` in `btrfs_tree.h`.
const SUBVOLUME_ROOT_INODE: u64 = 256;

/// A listing's first two cookies belong to `.` and `..`, which the format
/// does not store; an entry's cookie is its directory index plus this.
const DOT_COOKIES: u64 = 2;

/// `S_IALLUGO`: the permission, sticky and set-id bits of a mode.
const PERMISSION_BITS: u32 = 0o7777;

type Snapshot<S> = Filesystem<Arc<S>>;

/// Shared synchronization handle between the FUSE event loop and the control
/// socket thread.
pub struct SharedState {
    pub state: Mutex<State>,
    /// Signalled whenever the last open writable file handle is released or
    /// the filesystem is destroyed, so a `remount,ro` waiting on an in-flight
    /// async `FUSE_RELEASE` wakes immediately.
    pub writable_released: Condvar,
}

impl SharedState {
    pub fn new(state: State) -> Self {
        Self {
            state: Mutex::new(state),
            writable_released: Condvar::new(),
        }
    }
}

/// The attributes a `setattr` request changes; `None` leaves one alone.
#[derive(Default)]
pub struct Setattr {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub access: Option<TimeOrNow>,
    pub modified: Option<TimeOrNow>,
}

/// What a creation makes.
pub enum Node<'a> {
    File,
    Directory,
    Symlink(&'a [u8]),
    Special(Special),
}

/// The caller a creation is made for.
#[derive(Clone, Copy)]
pub struct Owner {
    pub uid: u32,
    pub gid: u32,
    /// The caller's umask, which the writer applies as `posix_acl_create`
    /// does.
    pub umask: u32,
}

pub struct Statfs {
    pub blocks: u64,
    pub free: u64,
    pub block_size: u32,
}

enum Storage<S> {
    ReadOnly(Snapshot<S>),
    Writable(Box<Writer<S, RandomUuids>>),
}

/// Device ownership retained for the lifetime of a [`Device`]-backed [`State`]
/// so `remount,rw` can check `BLKROGET` and upgrade a read-only mount to a
/// [`Writer`] without releasing the `O_EXCL` claim.
pub struct DeviceBacking {
    claim: Claim,
    path: PathBuf,
    concurrency: NonZeroUsize,
    #[cfg(test)]
    direct_io: bool,
}

/// State of an open directory stream (`FUSE_OPENDIR` .. `FUSE_RELEASEDIR`),
/// following Linux's `btrfs_opendir` and `btrfs_real_readdir`
/// (`fs/btrfs/inode.c`, commit `9b378f6ad48c`, refreshed on rewind as
/// commit `fd968e683bd9`). Also retains the directory inode in the writer so
/// an open unlinked/overwritten directory survives until `releasedir`.
struct OpenDir {
    ino: INodeNo,
    identity: Identity,
    handle: Option<InodeHandle>,
    bound: DirBound,
    /// Whether this stream has already served a `readdir`. Linux FUSE handles
    /// `lseek(dirfd, 0, SEEK_SET)` (`rewinddir(3)`) in the VFS without sending
    /// a request, so a `readdir` at offset `0` once `started` is true signals
    /// a rewind and refreshes `bound`, while the initial `readdir(0)` keeps
    /// the bound captured at `opendir`.
    started: bool,
}

/// One open file handle (`FUSE_OPEN` / `FUSE_CREATE` / `FUSE_TMPFILE` ..
/// `FUSE_RELEASE`), holding the writer's inode handle until release.
struct OpenFileEntry {
    ino: INodeNo,
    identity: Identity,
    handle: Option<InodeHandle>,
    writable: bool,
}

pub struct State<S = Device, B = DeviceBacking> {
    storage: Storage<S>,
    backing: B,
    inodes: Inodes,
    /// The dirty data the writer holds before it writes it back.
    dirty_data_limit: u64,
    open_dirs: HashMap<u64, OpenDir>,
    next_dir_handle: u64,
    read_only: bool,
    destroyed: bool,
    next_fh: u64,
    open_files: HashMap<u64, OpenFileEntry>,
    /// Total open file and directory handles per FUSE inode number.
    open_counts: HashMap<INodeNo, usize>,
    /// Non-root directories retained for the lifetime of their kernel lookup
    /// count (`FUSE_LOOKUP`/`FUSE_MKDIR` .. `FUSE_FORGET`), keeping unlinked
    /// working directories (`chdir`, `O_PATH`) accessible until forgotten.
    retained_dirs: HashMap<INodeNo, (Identity, Option<InodeHandle>)>,
}

/// The host's memory, which holds the writer's dirty data.
fn host_memory_bytes() -> u64 {
    // SAFETY: `sysinfo` writes only the struct it is given.
    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a valid, writable `struct sysinfo`.
    let status = unsafe { libc::sysinfo(&mut info) };
    assert_eq!(status, 0, "sysinfo(2) cannot fail with a valid buffer");
    let bytes = u128::from(info.totalram) * u128::from(info.mem_unit);
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

impl State<Device, DeviceBacking> {
    pub fn open(
        claim: Claim,
        device_path: PathBuf,
        concurrency: NonZeroUsize,
        read_only: bool,
    ) -> Result<Self, OpenError> {
        Self::open_with_mode(claim, device_path, concurrency, read_only, true)
    }

    #[cfg(test)]
    pub fn open_for_test(
        claim: Claim,
        device_path: PathBuf,
        concurrency: NonZeroUsize,
        read_only: bool,
    ) -> Result<Self, OpenError> {
        Self::open_with_mode(claim, device_path, concurrency, read_only, false)
    }

    fn open_with_mode(
        claim: Claim,
        device_path: PathBuf,
        concurrency: NonZeroUsize,
        read_only: bool,
        direct_io: bool,
    ) -> Result<Self, OpenError> {
        if !read_only {
            return Self::open_writable(claim, device_path, concurrency, false, direct_io);
        }
        if claim.is_writable() {
            match Self::open_writable(
                claim.clone(),
                device_path.clone(),
                concurrency,
                true,
                direct_io,
            ) {
                Ok(state) => return Ok(state),
                Err(OpenError::Write(WriteError::UnsupportedCompatRo { .. })) => {}
                Err(OpenError::Device(error))
                    if matches!(error.raw_os_error(), Some(libc::EROFS | libc::EACCES)) => {}
                Err(error) => return Err(error),
            }
        }
        Self::open_read_only(claim, device_path, concurrency, direct_io)
    }

    fn open_device_rw(path: &Path, claim: Claim, direct_io: bool) -> std::io::Result<Device> {
        #[cfg(test)]
        if !direct_io {
            return Device::open_for_test(path, claim);
        }
        let _ = direct_io;
        Device::open_read_write(path, claim)
    }

    fn open_writable(
        claim: Claim,
        device_path: PathBuf,
        concurrency: NonZeroUsize,
        read_only: bool,
        direct_io: bool,
    ) -> Result<Self, OpenError> {
        let device = Self::open_device_rw(&device_path, claim.clone(), direct_io)?;
        Self::from_writer(
            device,
            DeviceBacking {
                claim,
                path: device_path,
                concurrency,
                #[cfg(test)]
                direct_io,
            },
            concurrency,
            read_only,
        )
    }

    fn open_read_only(
        claim: Claim,
        device_path: PathBuf,
        concurrency: NonZeroUsize,
        direct_io: bool,
    ) -> Result<Self, OpenError> {
        #[cfg(not(test))]
        let _ = direct_io;
        let device = Device::open_read_only(&device_path, claim.clone())?;
        let fs = block_on(Filesystem::mount(Arc::new(device)))?;
        let root = block_on(fs.root())?;
        let identity = Identity {
            tree: root.tree(),
            number: root.number(),
        };
        Ok(Self {
            storage: Storage::ReadOnly(fs),
            backing: DeviceBacking {
                claim,
                path: device_path,
                concurrency,
                #[cfg(test)]
                direct_io,
            },
            inodes: Inodes::new(identity, root.metadata().generation, None),
            dirty_data_limit: default_dirty_data_limit(host_memory_bytes()),
            open_dirs: HashMap::new(),
            next_dir_handle: 1,
            read_only: true,
            destroyed: false,
            next_fh: 1,
            open_files: HashMap::new(),
            open_counts: HashMap::new(),
            retained_dirs: HashMap::new(),
        })
    }

    /// Transitions the daemon to read-write, checking `BLKROGET` (matching
    /// Linux's `reconfigure_super` `bdev_read_only` -> `EACCES` check) and
    /// upgrading a read-only [`Filesystem`] mount to a [`Writer`] when needed.
    pub async fn remount_read_write(&mut self) -> Result<(), Errno> {
        if self.destroyed {
            return Err(Errno::ENODEV);
        }
        match self.backing.claim.is_block_device_read_only() {
            Ok(true) => return Err(Errno::EACCES),
            Ok(false) => {}
            Err(error) => return Err(Errno::from(error)),
        }
        match &mut self.storage {
            Storage::Writable(writer) => {
                writer.snapshot().map_err(|error| write_errno(&error))?;
            }
            Storage::ReadOnly(_) => {
                #[cfg(test)]
                let direct_io = self.backing.direct_io;
                #[cfg(not(test))]
                let direct_io = true;
                let device =
                    Self::open_device_rw(&self.backing.path, self.backing.claim.clone(), direct_io)
                        .map_err(|error| {
                            if matches!(error.raw_os_error(), Some(libc::EROFS | libc::EACCES)) {
                                Errno::EACCES
                            } else {
                                Errno::from(error)
                            }
                        })?;
                let mut writer = Writer::mount(
                    device,
                    RandomUuids,
                    self.backing.concurrency,
                    Compressor::Plain,
                    timestamp(SystemTime::now()),
                )
                .await
                .map_err(|error| write_errno(&error))?;
                let pending = self.inodes.pending_handles();
                let open_file_ids: Vec<(u64, Identity)> = self
                    .open_files
                    .iter()
                    .filter(|(_, entry)| entry.handle.is_none())
                    .map(|(&fh, entry)| (fh, entry.identity))
                    .collect();
                let open_dir_ids: Vec<(u64, Identity)> = self
                    .open_dirs
                    .iter()
                    .filter(|(_, entry)| entry.handle.is_none())
                    .map(|(&fh, entry)| (fh, entry.identity))
                    .collect();
                let retained_dir_ids: Vec<(INodeNo, Identity)> = self
                    .retained_dirs
                    .iter()
                    .filter(|(_, (_, handle))| handle.is_none())
                    .map(|(&ino, &(identity, _))| (ino, identity))
                    .collect();
                let (resolved, attached_files, attached_dirs, attached_retained_dirs) = {
                    let mut transaction =
                        writer.join().await.map_err(|error| write_errno(&error))?;
                    let mut resolved = Vec::with_capacity(pending.len());
                    for entry in pending {
                        let Some(handle) = transaction
                            .inode(entry.identity.tree, entry.identity.number)
                            .await
                            .map_err(|error| write_errno(&error))?
                        else {
                            continue;
                        };
                        let meta = transaction
                            .metadata(&handle)
                            .await
                            .map_err(|error| write_errno(&error))?;
                        if meta.generation != entry.generation {
                            continue;
                        }
                        resolved.push((entry.ino, handle));
                    }
                    let mut attached_files = Vec::with_capacity(open_file_ids.len());
                    for (fh, identity) in open_file_ids {
                        if let Some(handle) = transaction
                            .inode(identity.tree, identity.number)
                            .await
                            .map_err(|error| write_errno(&error))?
                        {
                            transaction
                                .open_inode(&handle)
                                .await
                                .map_err(|error| write_errno(&error))?;
                            attached_files.push((fh, handle));
                        }
                    }
                    let mut attached_dirs = Vec::with_capacity(open_dir_ids.len());
                    for (fh, identity) in open_dir_ids {
                        if let Some(handle) = transaction
                            .inode(identity.tree, identity.number)
                            .await
                            .map_err(|error| write_errno(&error))?
                        {
                            transaction
                                .open_inode(&handle)
                                .await
                                .map_err(|error| write_errno(&error))?;
                            attached_dirs.push((fh, handle));
                        }
                    }
                    let mut attached_retained_dirs = Vec::with_capacity(retained_dir_ids.len());
                    for (ino, identity) in retained_dir_ids {
                        if let Some(handle) = transaction
                            .inode(identity.tree, identity.number)
                            .await
                            .map_err(|error| write_errno(&error))?
                        {
                            transaction
                                .open_inode(&handle)
                                .await
                                .map_err(|error| write_errno(&error))?;
                            attached_retained_dirs.push((ino, handle));
                        }
                    }
                    (
                        resolved,
                        attached_files,
                        attached_dirs,
                        attached_retained_dirs,
                    )
                };
                for (ino, handle) in resolved {
                    self.inodes.attach_handle(ino, handle);
                }
                for (fh, handle) in attached_files {
                    if let Some(entry) = self.open_files.get_mut(&fh) {
                        entry.handle = Some(handle);
                    }
                }
                for (fh, handle) in attached_dirs {
                    if let Some(entry) = self.open_dirs.get_mut(&fh) {
                        entry.handle = Some(handle);
                    }
                }
                for (ino, handle) in attached_retained_dirs {
                    if let Some((_, slot)) = self.retained_dirs.get_mut(&ino) {
                        *slot = Some(handle);
                    }
                }
                self.storage = Storage::Writable(Box::new(writer));
            }
        }
        self.read_only = false;
        Ok(())
    }
}

impl<S: BlockSink, B> State<S, B> {
    fn from_writer(
        device: S,
        backing: B,
        concurrency: NonZeroUsize,
        read_only: bool,
    ) -> Result<Self, OpenError> {
        let mut writer = block_on(Writer::mount(
            device,
            RandomUuids,
            concurrency,
            Compressor::Plain,
            timestamp(SystemTime::now()),
        ))?;
        let snapshot = writer.snapshot()?;
        let root = block_on(snapshot.root())?;
        let handle = {
            let transaction = block_on(writer.join())?;
            block_on(transaction.root())?
        };
        let identity = Identity {
            tree: root.tree(),
            number: root.number(),
        };
        Ok(Self {
            storage: Storage::Writable(Box::new(writer)),
            backing,
            inodes: Inodes::new(identity, root.metadata().generation, Some(handle)),
            dirty_data_limit: default_dirty_data_limit(host_memory_bytes()),
            open_dirs: HashMap::new(),
            next_dir_handle: 1,
            read_only,
            destroyed: false,
            next_fh: 1,
            open_files: HashMap::new(),
            open_counts: HashMap::new(),
            retained_dirs: HashMap::new(),
        })
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    pub fn is_destroyed(&self) -> bool {
        self.destroyed
    }

    pub fn has_open_writable(&self) -> bool {
        self.open_files.values().any(|entry| entry.writable)
    }

    pub fn has_open_orphans(&self) -> bool {
        matches!(&self.storage, Storage::Writable(writer) if writer.has_open_orphans())
    }

    /// Whether active handles prevent transitioning the mount to read-only:
    /// open writable handles or open unlinked/tmpfile orphans whose release
    /// must mutate the filesystem.
    pub fn blocks_read_only_remount(&self) -> bool {
        self.has_open_writable() || self.has_open_orphans()
    }

    fn is_open(&self, ino: INodeNo) -> bool {
        self.open_counts.get(&ino).copied().unwrap_or(0) > 0
    }

    fn increment_open_count(&mut self, ino: INodeNo) {
        *self.open_counts.entry(ino).or_insert(0) += 1;
    }

    fn decrement_open_count(&mut self, ino: INodeNo) {
        if let Some(count) = self.open_counts.get_mut(&ino) {
            if *count <= 1 {
                self.open_counts.remove(&ino);
            } else {
                *count -= 1;
            }
        }
    }

    /// Records a file open and retains the inode on the writer so unlinking
    /// its last directory entry keeps an orphan alive until [`Self::release_file`].
    /// Writable opens (`O_WRONLY` or `O_RDWR`) fail with `EROFS` on a read-only
    /// mount.
    pub async fn open_file(&mut self, ino: INodeNo, flags: OpenFlags) -> Result<FileHandle, Errno> {
        let writable = matches!(
            flags.acc_mode(),
            OpenAccMode::O_WRONLY | OpenAccMode::O_RDWR
        );
        if writable {
            self.writable()?;
        }
        let (identity, _) = self.inodes.identity(ino)?;
        let handle = match &mut self.storage {
            Storage::ReadOnly(_) => None,
            Storage::Writable(writer) => {
                let handle = self.inodes.handle(ino)?;
                let mut transaction = writer.join().await.map_err(|error| write_errno(&error))?;
                transaction
                    .open_inode(&handle)
                    .await
                    .map_err(|error| write_errno(&error))?;
                Some(handle)
            }
        };
        let id = self.next_fh;
        self.next_fh += 1;
        self.open_files.insert(
            id,
            OpenFileEntry {
                ino,
                identity,
                handle,
                writable,
            },
        );
        self.increment_open_count(ino);
        Ok(FileHandle(id))
    }

    /// Releases a file handle, deleting any orphaned inode if this was its
    /// final open handle. Returns `true` if releasing this handle cleared the
    /// last blocker for a waiting `remount,ro`.
    pub async fn release_file(&mut self, fh: FileHandle) -> bool {
        let was_blocking = self.blocks_read_only_remount();
        let Some(entry) = self.open_files.remove(&fh.0) else {
            return false;
        };
        self.decrement_open_count(entry.ino);
        if let Some(handle) = entry.handle {
            self.release_writer_handle(&handle).await;
        }
        was_blocking && !self.blocks_read_only_remount()
    }

    async fn release_writer_handle(&mut self, handle: &InodeHandle) {
        let deleted = match &mut self.storage {
            Storage::Writable(writer) => match writer.join().await {
                Ok(mut transaction) => match transaction.release_inode(handle).await {
                    Ok(deleted) => deleted,
                    Err(error) => {
                        tracing::warn!(%error, "releasing open btrfs inode failed");
                        false
                    }
                },
                Err(error) => {
                    tracing::warn!(%error, "joining transaction for inode release failed");
                    false
                }
            },
            Storage::ReadOnly(_) => false,
        };
        if deleted && let Err(errno) = self.settle().await {
            tracing::warn!(?errno, "settling transaction after orphan deletion failed");
        }
    }

    /// Transitions the daemon to read-only after verifying no writable file
    /// handles or open orphans remain and committing any running transaction.
    pub async fn remount_read_only(&mut self) -> Result<(), Errno> {
        if self.destroyed {
            return Err(Errno::ENODEV);
        }
        if self.blocks_read_only_remount() {
            return Err(Errno::EBUSY);
        }
        self.sync().await?;
        self.read_only = true;
        Ok(())
    }

    /// Restores `read_only = true` when a `remount,rw` succeeded in the daemon
    /// but the subsequent kernel `mount -i -o remount,rw` failed.
    pub fn rollback_read_only(&mut self) -> Result<(), Errno> {
        if self.destroyed {
            return Err(Errno::ENODEV);
        }
        self.read_only = true;
        Ok(())
    }

    /// Commits any pending transaction during unmount and marks the state
    /// destroyed so late control-socket requests fail with `ENODEV`.
    pub async fn destroy(&mut self) -> Result<(), Errno> {
        self.destroyed = true;
        // Release cached directory lookups whose `FUSE_FORGET` is skipped on
        // unmount so any unlinked directory orphan is deleted before commit.
        let retained: Vec<InodeHandle> = self
            .retained_dirs
            .drain()
            .filter_map(|(_, (_, handle))| handle)
            .collect();
        for handle in retained {
            self.release_writer_handle(&handle).await;
        }
        self.sync().await
    }

    /// Drops `count` kernel lookups on `ino`, releasing any directory orphan
    /// retained across lookups once `nlookup` reaches zero. Returns `true` if
    /// doing so cleared the last `remount,ro` blocker.
    pub async fn forget(&mut self, ino: INodeNo, count: u64) -> bool {
        let was_blocking = self.blocks_read_only_remount();
        self.inodes.forget(ino, count);
        if self.inodes.generation(ino).is_none()
            && let Some((_, Some(handle))) = self.retained_dirs.remove(&ino)
        {
            self.release_writer_handle(&handle).await;
        }
        was_blocking && !self.blocks_read_only_remount()
    }

    fn snapshot(&self) -> Result<Snapshot<S>, Errno> {
        match &self.storage {
            Storage::Writable(writer) => writer.snapshot().map_err(|error| write_errno(&error)),
            Storage::ReadOnly(fs) => Ok(fs.clone()),
        }
    }

    fn writable(&self) -> Result<(), Errno> {
        if self.read_only || matches!(self.storage, Storage::ReadOnly(_)) {
            return Err(Errno::EROFS);
        }
        Ok(())
    }

    fn writable_writer(&mut self) -> Result<&mut Writer<S, RandomUuids>, Errno> {
        if self.read_only {
            return Err(Errno::EROFS);
        }
        match &mut self.storage {
            Storage::Writable(writer) => Ok(writer),
            Storage::ReadOnly(_) => Err(Errno::EROFS),
        }
    }

    /// The inode `ino` names in `snapshot`; `ESTALE` once it was deleted or
    /// its number reused.
    async fn open_inode(&self, snapshot: &Snapshot<S>, ino: INodeNo) -> Result<Inode, Errno> {
        let (identity, generation) = self.inodes.identity(ino)?;
        let inode = match snapshot.inode(identity.tree, identity.number).await {
            Ok(inode) => inode,
            Err(Error::MissingInode { .. } | Error::MissingRoot { .. }) => {
                return Err(Errno::ESTALE);
            }
            Err(error) => return Err(read_errno(&error)),
        };
        if inode.metadata().generation != generation
            || (inode.metadata().nlink == 0
                && !self.is_open(ino)
                && !self.retained_dirs.contains_key(&ino))
        {
            return Err(Errno::ESTALE);
        }
        Ok(inode)
    }

    /// The writer's handle for `identity`, refreshed from the running
    /// transaction.
    async fn handle_for(&mut self, identity: Identity) -> Result<InodeHandle, Errno> {
        let Storage::Writable(writer) = &mut self.storage else {
            return Err(Errno::EROFS);
        };
        let transaction = writer.join().await.map_err(|error| write_errno(&error))?;
        transaction
            .inode(identity.tree, identity.number)
            .await
            .map_err(|error| write_errno(&error))?
            .ok_or(Errno::ESTALE)
    }

    /// Makes every change so far durable: `fsync`, `fsyncdir`, `remount,ro`
    /// and unmount. A failure poisons the writer, and the device keeps the
    /// previous generation.
    pub async fn sync(&mut self) -> Result<(), Errno> {
        match &mut self.storage {
            Storage::Writable(writer) => writer.commit().await.map_err(|error| write_errno(&error)),
            Storage::ReadOnly(_) => Ok(()),
        }
    }

    /// Ends a mutation: commits once the running transaction's dirty
    /// metadata reaches Linux's bound.
    async fn settle(&mut self) -> Result<(), Errno> {
        let Storage::Writable(writer) = &mut self.storage else {
            return Ok(());
        };
        if writer.dirty().data_bytes >= self.dirty_data_limit {
            writer
                .writeback()
                .await
                .map_err(|error| write_errno(&error))?;
        }
        if writer.dirty().metadata_bytes >= DEFAULT_DIRTY_METADATA_LIMIT {
            self.sync().await?;
        }
        Ok(())
    }

    /// Ensures a non-root directory inode cached in the kernel stays retained
    /// on the writer until `FUSE_FORGET`, so an active `cwd` or `O_PATH` fd on
    /// an unlinked directory can still stat/chdir out (`generic/011`).
    async fn retain_dir_lookup(&mut self, ino: INodeNo, identity: Identity) -> Result<(), Errno> {
        if ino == INodeNo::ROOT || self.retained_dirs.contains_key(&ino) {
            return Ok(());
        }
        let handle = match &mut self.storage {
            Storage::ReadOnly(_) => None,
            Storage::Writable(writer) => {
                let handle = self.inodes.handle(ino)?;
                let mut transaction = writer.join().await.map_err(|error| write_errno(&error))?;
                transaction
                    .open_inode(&handle)
                    .await
                    .map_err(|error| write_errno(&error))?;
                Some(handle)
            }
        };
        self.retained_dirs.insert(ino, (identity, handle));
        Ok(())
    }

    /// The attributes and generation of `identity` as the writer sees it,
    /// recorded as one more lookup of it.
    async fn entry_of(
        &mut self,
        identity: Identity,
        handle: Option<InodeHandle>,
    ) -> Result<(FileAttr, Generation), Errno> {
        let snapshot = self.snapshot()?;
        let inode = match snapshot.inode(identity.tree, identity.number).await {
            Ok(inode) => inode,
            Err(Error::MissingInode { .. } | Error::MissingRoot { .. }) => {
                return Err(Errno::ESTALE);
            }
            Err(error) => return Err(read_errno(&error)),
        };
        let ino = self.inodes.encode(identity)?;
        let generation = inode.metadata().generation;
        self.inodes.record(ino, generation, handle);
        if inode.kind() == FileKind::Directory {
            self.retain_dir_lookup(ino, identity).await?;
        }
        Ok((
            attr(ino, inode.metadata(), &snapshot),
            fuse_generation(ino, generation),
        ))
    }

    async fn register_lookup(
        &mut self,
        snapshot: &Snapshot<S>,
        inode: &Inode,
    ) -> Result<(FileAttr, Generation), Errno> {
        let identity = Identity {
            tree: inode.tree(),
            number: inode.number(),
        };
        let ino = self.inodes.encode(identity)?;
        let generation = inode.metadata().generation;
        let handle = match &self.storage {
            Storage::ReadOnly(_) => None,
            Storage::Writable(_) => {
                if self.inodes.has_handle(ino, generation) {
                    None
                } else {
                    Some(self.handle_for(identity).await?)
                }
            }
        };
        self.inodes.record(ino, generation, handle);
        if inode.kind() == FileKind::Directory {
            self.retain_dir_lookup(ino, identity).await?;
        }
        Ok((
            attr(ino, inode.metadata(), snapshot),
            fuse_generation(ino, generation),
        ))
    }

    /// Export handle resolution (`FUSE_LOOKUP(nodeid, ".")` in
    /// `fs/fuse/inode.c`): resolves `ino` directly from its stable identity
    /// even after `FUSE_FORGET` or remount, and refreshes the writer handle.
    async fn lookup_self(
        &mut self,
        snapshot: &Snapshot<S>,
        ino: INodeNo,
    ) -> Result<(FileAttr, Generation), Errno> {
        let identity = self.inodes.decode(ino)?;
        let inode = match snapshot.inode(identity.tree, identity.number).await {
            Ok(inode) => inode,
            Err(Error::MissingInode { .. } | Error::MissingRoot { .. }) => {
                return Err(Errno::ESTALE);
            }
            Err(error) => return Err(read_errno(&error)),
        };
        if inode.metadata().nlink == 0 && !self.is_open(ino) {
            return Err(Errno::ESTALE);
        }
        if let Some(known) = self.inodes.generation(ino)
            && known != inode.metadata().generation
        {
            return Err(Errno::ESTALE);
        }
        self.register_lookup(snapshot, &inode).await
    }

    /// Export path reconnection (`fuse_get_parent` -> `FUSE_LOOKUP(ino, "..")`
    /// in `fs/fuse/inode.c`): resolves a directory's parent from its on-disk
    /// backreference.
    async fn lookup_parent(
        &mut self,
        snapshot: &Snapshot<S>,
        ino: INodeNo,
    ) -> Result<(FileAttr, Generation), Errno> {
        let directory = self.open_inode(snapshot, ino).await?;
        if ino == INodeNo::ROOT {
            return self.register_lookup(snapshot, &directory).await;
        }
        let parent = match snapshot.parent(&directory).await {
            Ok(Some(parent)) => parent,
            Ok(None) | Err(Error::MissingInode { .. } | Error::MissingRoot { .. }) => {
                return Err(Errno::ESTALE);
            }
            Err(error) => return Err(read_errno(&error)),
        };
        self.register_lookup(snapshot, &parent).await
    }

    pub async fn lookup(
        &mut self,
        parent: INodeNo,
        name: &OsStr,
    ) -> Result<(FileAttr, Generation), Errno> {
        let name = entry_name(name)?;
        let snapshot = self.snapshot()?;
        if name == b"." {
            return self.lookup_self(&snapshot, parent).await;
        }
        if name == b".." {
            return self.lookup_parent(&snapshot, parent).await;
        }
        let directory = self.open_inode(&snapshot, parent).await?;
        let child = snapshot
            .lookup(&directory, name)
            .await
            .map_err(|error| read_errno(&error))?
            .ok_or(Errno::ENOENT)?;
        self.register_lookup(&snapshot, &child).await
    }

    pub async fn getattr(&self, ino: INodeNo) -> Result<FileAttr, Errno> {
        let snapshot = self.snapshot()?;
        let inode = self.open_inode(&snapshot, ino).await?;
        Ok(attr(ino, inode.metadata(), &snapshot))
    }

    /// Applies a mode, owner, size and time change in one transaction.
    pub async fn setattr(
        &mut self,
        ino: INodeNo,
        change: Setattr,
        now: Timestamp,
    ) -> Result<FileAttr, Errno> {
        let Setattr {
            mode,
            uid,
            gid,
            size,
            access,
            modified,
        } = change;
        if mode.is_none()
            && uid.is_none()
            && gid.is_none()
            && size.is_none()
            && access.is_none()
            && modified.is_none()
        {
            return self.getattr(ino).await;
        }
        self.writable()?;
        let file = self.inodes.handle(ino)?;
        let mut transaction = self
            .writable_writer()?
            .join()
            .await
            .map_err(|error| write_errno(&error))?;
        // Linux applies a new owner before a new mode in one `notify_change`,
        // so a mode sent with it is the one that stays.
        if uid.is_some() || gid.is_some() {
            transaction
                .set_owner(&file, uid, gid, now)
                .await
                .map_err(|error| write_errno(&error))?;
        }
        if let Some(mode) = mode {
            // The kernel sends the file type with the mode; `chmod` keeps the
            // permission, sticky and set-id bits only.
            transaction
                .set_permissions(&file, mode & PERMISSION_BITS, now)
                .await
                .map_err(|error| write_errno(&error))?;
        }
        if let Some(size) = size {
            transaction
                .truncate_file(&file, size, now)
                .await
                .map_err(|error| write_errno(&error))?;
        }
        if access.is_some() || modified.is_some() {
            let resolve = |time: TimeOrNow| match time {
                TimeOrNow::SpecificTime(time) => timestamp(time),
                TimeOrNow::Now => now,
            };
            transaction
                .set_times(&file, access.map(resolve), modified.map(resolve), now)
                .await
                .map_err(|error| write_errno(&error))?;
        }
        self.settle().await?;
        self.getattr(ino).await
    }

    pub async fn readlink(&self, ino: INodeNo) -> Result<Vec<u8>, Errno> {
        let snapshot = self.snapshot()?;
        let link = self.open_inode(&snapshot, ino).await?;
        // PATH_MAX; a longer target is read again at its full length.
        let mut target = vec![0; 4096];
        let length = snapshot
            .read_link(&link, &mut target)
            .await
            .map_err(|error| read_errno(&error))?;
        if length > target.len() {
            target.resize(length, 0);
            snapshot
                .read_link(&link, &mut target)
                .await
                .map_err(|error| read_errno(&error))?;
        }
        target.truncate(length);
        Ok(target)
    }

    pub async fn read(&self, ino: INodeNo, offset: u64, size: u32) -> Result<Vec<u8>, Errno> {
        let snapshot = self.snapshot()?;
        let file = self.open_inode(&snapshot, ino).await?;
        let mut data = vec![0; size as usize];
        let length = snapshot
            .read(&file, offset, &mut data)
            .await
            .map_err(|error| read_errno(&error))?;
        data.truncate(length);
        Ok(data)
    }

    /// Opens a directory stream, retains the directory inode so unlinking or
    /// overwriting it while open keeps it alive until [`Self::releasedir`],
    /// and records its upper `DIR_INDEX` bound as of open time
    /// (`btrfs_opendir` in Linux `fs/btrfs/inode.c`, commit `9b378f6ad48c`).
    pub async fn opendir(&mut self, ino: INodeNo) -> Result<FileHandle, Errno> {
        let (identity, _) = self.inodes.identity(ino)?;
        let snapshot = self.snapshot()?;
        let directory = self.open_inode(&snapshot, ino).await?;
        let bound = snapshot
            .dir_bound(&directory)
            .await
            .map_err(|error| read_errno(&error))?;
        let dir_handle = match &mut self.storage {
            Storage::ReadOnly(_) => None,
            Storage::Writable(writer) => {
                let handle = self.inodes.handle(ino)?;
                let mut transaction = writer.join().await.map_err(|error| write_errno(&error))?;
                transaction
                    .open_inode(&handle)
                    .await
                    .map_err(|error| write_errno(&error))?;
                Some(handle)
            }
        };
        let handle = self.next_dir_handle;
        self.next_dir_handle += 1;
        self.open_dirs.insert(
            handle,
            OpenDir {
                ino,
                identity,
                handle: dir_handle,
                bound,
                started: false,
            },
        );
        self.increment_open_count(ino);
        Ok(FileHandle(handle))
    }

    /// Releases a directory stream opened by [`Self::opendir`], deleting the
    /// directory if it was unlinked while open and this was its last handle.
    /// Returns `true` if releasing it cleared the last `remount,ro` blocker.
    pub async fn releasedir(&mut self, fh: FileHandle) -> bool {
        let was_blocking = self.blocks_read_only_remount();
        let Some(entry) = self.open_dirs.remove(&fh.0) else {
            return false;
        };
        self.decrement_open_count(entry.ino);
        if let Some(handle) = entry.handle {
            self.release_writer_handle(&handle).await;
        }
        was_blocking && !self.blocks_read_only_remount()
    }

    /// Hands the entries of directory `ino` after cookie `offset` up to the
    /// open stream's upper `DIR_INDEX` bound to `emit` until it returns true,
    /// meaning its reply is full.
    pub async fn readdir(
        &mut self,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut emit: impl FnMut(INodeNo, u64, FileType, &OsStr) -> bool,
    ) -> Result<(), Errno> {
        let snapshot = self.snapshot()?;
        let directory = self.open_inode(&snapshot, ino).await?;
        let parent_ino = if ino == INodeNo::ROOT {
            INodeNo::ROOT
        } else {
            match snapshot.parent(&directory).await {
                Ok(Some(parent)) => self.inodes.encode(Identity {
                    tree: parent.tree(),
                    number: parent.number(),
                })?,
                Ok(None) => ino,
                Err(error) => return Err(read_errno(&error)),
            }
        };
        let (open_started, open_bound) = {
            let open = self.open_dirs.get(&fh.0).ok_or(Errno::EBADF)?;
            (open.started, open.bound)
        };
        let bound = if offset == 0 && open_started {
            // Refresh the upper `DIR_INDEX` bound on rewind (`rewinddir(3)` ->
            // `lseek(dirfd, 0, SEEK_SET)` in the Linux VFS, which FUSE does not
            // forward to the daemon), matching Linux `fs/btrfs/inode.c`, commit
            // `fd968e683bd9`.
            let refreshed = snapshot
                .dir_bound(&directory)
                .await
                .map_err(|error| read_errno(&error))?;
            self.open_dirs
                .get_mut(&fh.0)
                .expect("open directory handle checked above")
                .bound = refreshed;
            refreshed
        } else {
            if !open_started {
                self.open_dirs
                    .get_mut(&fh.0)
                    .expect("open directory handle checked above")
                    .started = true;
            }
            open_bound
        };
        // The format stores neither `.` nor `..`; the kernel reports both.
        for (cookie, entry_ino, name) in [(1, ino, "."), (2, parent_ino, "..")] {
            if offset < cookie && emit(entry_ino, cookie, FileType::Directory, OsStr::new(name)) {
                return Ok(());
            }
        }
        let tree = directory.tree();
        let inodes = &self.inodes;
        let mut encode_error = None;
        snapshot
            .read_dir(
                &directory,
                DirPosition(offset.saturating_sub(DOT_COOKIES)),
                bound,
                |entry| {
                    let identity = match entry.target {
                        EntryTarget::Inode(number) => Identity { tree, number },
                        EntryTarget::Subvolume(tree) => Identity {
                            tree,
                            number: SUBVOLUME_ROOT_INODE,
                        },
                    };
                    let listed = match inodes.encode(identity) {
                        Ok(listed) => listed,
                        Err(error) => {
                            encode_error = Some(error);
                            return ControlFlow::Break(());
                        }
                    };
                    let cookie = entry.position.0.saturating_add(DOT_COOKIES + 1);
                    if emit(
                        listed,
                        cookie,
                        file_type(entry.kind),
                        OsStr::from_bytes(entry.name),
                    ) {
                        ControlFlow::Break(())
                    } else {
                        ControlFlow::Continue(())
                    }
                },
            )
            .await
            .map_err(|error| read_errno(&error))?;
        if let Some(error) = encode_error {
            return Err(error);
        }
        Ok(())
    }

    pub async fn write(
        &mut self,
        ino: INodeNo,
        offset: u64,
        data: &[u8],
        now: Timestamp,
    ) -> Result<u32, Errno> {
        self.writable()?;
        let file = self.inodes.handle(ino)?;
        let mut transaction = self
            .writable_writer()?
            .join()
            .await
            .map_err(|error| write_errno(&error))?;
        let written = transaction
            .write_file(&file, offset, data, now)
            .await
            .map_err(|error| write_errno(&error))?;
        self.settle().await?;
        Ok(u32::try_from(written)
            .expect("a write is never longer than the request that asked for it"))
    }

    pub async fn create(
        &mut self,
        parent: INodeNo,
        name: &OsStr,
        node: Node<'_>,
        permissions: u32,
        owner: Owner,
        now: Timestamp,
    ) -> Result<(FileAttr, Generation), Errno> {
        self.writable()?;
        let name = entry_name(name)?;
        let parent = self.inodes.handle(parent)?;
        let mut transaction = self
            .writable_writer()?
            .join()
            .await
            .map_err(|error| write_errno(&error))?;
        let at = Name {
            parent: &parent,
            bytes: name,
        };
        let attributes = Attributes {
            permissions,
            uid: owner.uid,
            gid: owner.gid,
            umask: owner.umask,
        };
        let created = match node {
            Node::File => transaction.create_file(at, attributes, now).await,
            Node::Directory => transaction.create_directory(at, attributes, now).await,
            Node::Symlink(target) => transaction.symlink(at, target, attributes, now).await,
            Node::Special(special) => {
                transaction
                    .create_special(at, special, attributes, now)
                    .await
            }
        }
        .map_err(|error| write_errno(&error))?;
        self.settle().await?;
        let identity = Identity {
            tree: created.tree(),
            number: created.number(),
        };
        self.entry_of(identity, Some(created)).await
    }

    /// Creates and opens an unnamed regular file (`O_TMPFILE`) in `parent`'s
    /// subvolume with an on-disk orphan item and `nlink == 0`.
    pub async fn tmpfile(
        &mut self,
        parent: INodeNo,
        permissions: u32,
        owner: Owner,
        flags: OpenFlags,
        now: Timestamp,
    ) -> Result<(FileAttr, Generation, FileHandle), Errno> {
        let writable = matches!(
            flags.acc_mode(),
            OpenAccMode::O_WRONLY | OpenAccMode::O_RDWR
        );
        if !writable {
            return Err(Errno::EINVAL);
        }
        self.writable()?;
        let parent = self.inodes.handle(parent)?;
        let linkable = (flags.0 & libc::O_EXCL) == 0;
        let attributes = Attributes {
            permissions,
            uid: owner.uid,
            gid: owner.gid,
            umask: owner.umask,
        };
        let created = {
            let mut transaction = self
                .writable_writer()?
                .join()
                .await
                .map_err(|error| write_errno(&error))?;
            transaction
                .create_tmpfile(&parent, attributes, linkable, now)
                .await
                .map_err(|error| write_errno(&error))?
        };
        self.settle().await?;
        let identity = Identity {
            tree: created.tree(),
            number: created.number(),
        };
        let (attr, generation) = self.entry_of(identity, Some(created.clone())).await?;
        let id = self.next_fh;
        self.next_fh += 1;
        self.open_files.insert(
            id,
            OpenFileEntry {
                ino: attr.ino,
                identity,
                handle: Some(created),
                writable: true,
            },
        );
        self.increment_open_count(attr.ino);
        Ok((attr, generation, FileHandle(id)))
    }

    pub async fn link(
        &mut self,
        ino: INodeNo,
        parent: INodeNo,
        name: &OsStr,
        now: Timestamp,
    ) -> Result<(FileAttr, Generation), Errno> {
        self.writable()?;
        let name = entry_name(name)?;
        let file = self.inodes.handle(ino)?;
        let parent = self.inodes.handle(parent)?;
        let (identity, _) = self.inodes.identity(ino)?;
        let mut transaction = self
            .writable_writer()?
            .join()
            .await
            .map_err(|error| write_errno(&error))?;
        transaction
            .hard_link(
                Name {
                    parent: &parent,
                    bytes: name,
                },
                &file,
                now,
            )
            .await
            .map_err(|error| write_errno(&error))?;
        self.settle().await?;
        self.entry_of(identity, None).await
    }

    /// Removes the entry `name` of `parent`: a directory for `rmdir`, any
    /// other kind for `unlink`.
    pub async fn remove(
        &mut self,
        parent: INodeNo,
        name: &OsStr,
        directory: bool,
        now: Timestamp,
    ) -> Result<(), Errno> {
        self.writable()?;
        let name = entry_name(name)?;
        let parent = self.inodes.handle(parent)?;
        let mut transaction = self
            .writable_writer()?
            .join()
            .await
            .map_err(|error| write_errno(&error))?;
        let child = transaction
            .lookup(&parent, name)
            .await
            .map_err(|error| write_errno(&error))?
            .ok_or(Errno::ENOENT)?;
        let kind = transaction
            .metadata(&child)
            .await
            .map_err(|error| write_errno(&error))?
            .kind;
        match (directory, kind == FileKind::Directory) {
            (true, false) => return Err(Errno::ENOTDIR),
            (false, true) => return Err(Errno::EISDIR),
            _ => {}
        }
        transaction
            .unlink_name(
                Name {
                    parent: &parent,
                    bytes: name,
                },
                now,
            )
            .await
            .map_err(|error| write_errno(&error))?;
        self.settle().await
    }

    pub async fn rename(
        &mut self,
        parent: INodeNo,
        name: &OsStr,
        new_parent: INodeNo,
        new_name: &OsStr,
        mode: RenameMode,
        now: Timestamp,
    ) -> Result<(), Errno> {
        self.writable()?;
        let name = entry_name(name)?;
        let new_name = entry_name(new_name)?;
        let parent = self.inodes.handle(parent)?;
        let new_parent = self.inodes.handle(new_parent)?;
        let mut transaction = self
            .writable_writer()?
            .join()
            .await
            .map_err(|error| write_errno(&error))?;
        transaction
            .rename(
                Name {
                    parent: &parent,
                    bytes: name,
                },
                Name {
                    parent: &new_parent,
                    bytes: new_name,
                },
                mode,
                now,
            )
            .await
            .map_err(|error| write_errno(&error))?;
        self.settle().await
    }

    /// The space as the running transaction leaves it: a change is counted
    /// as soon as it is visible, not once it commits.
    pub fn statfs(&self) -> Result<Statfs, Errno> {
        let snapshot = self.snapshot()?;
        let block_size = snapshot.superblock().sectorsize();
        let size = u64::from(block_size);
        let (total_bytes, used_bytes) = match &self.storage {
            Storage::Writable(writer) => {
                let usage = writer.usage().map_err(|error| write_errno(&error))?;
                (usage.total_bytes, usage.used_bytes)
            }
            Storage::ReadOnly(fs) => {
                let sb = fs.superblock();
                (sb.total_bytes(), sb.bytes_used())
            }
        };
        Ok(Statfs {
            blocks: total_bytes / size,
            free: total_bytes.saturating_sub(used_bytes) / size,
            block_size,
        })
    }

    /// `getxattr(2)`: the attribute's length when `size` is zero, or its
    /// bytes when `size` holds them (`ERANGE` when `size` is too small).
    pub async fn getxattr(
        &mut self,
        ino: INodeNo,
        name: &OsStr,
        size: u32,
    ) -> Result<(usize, Vec<u8>), Errno> {
        // Linux's FUSE client (`fs/fuse/xattr.c` in torvalds/linux) uses a
        // catch-all `.prefix = ""` handler, so non-ACL `getxattr` requests
        // reach the daemon for namespace and bare-prefix validation.
        if let Storage::ReadOnly(fs) = &self.storage {
            let snapshot = fs.clone();
            let inode = self.open_inode(&snapshot, ino).await?;
            let mut value = vec![0; size as usize];
            let length = snapshot
                .xattr(&inode, name.as_bytes(), &mut value)
                .await
                .map_err(|error| read_errno(&error))?
                .ok_or(Errno::NO_XATTR)?;
            if size != 0 && length > value.len() {
                return Err(Errno::ERANGE);
            }
            value.truncate(length.min(value.len()));
            return Ok((length, value));
        }
        let file = self.inodes.handle(ino)?;
        let Storage::Writable(writer) = &mut self.storage else {
            return Err(Errno::EROFS);
        };
        let transaction = writer.join().await.map_err(|error| write_errno(&error))?;
        let mut value = vec![0; size as usize];
        let length = transaction
            .xattr(&file, name.as_bytes(), &mut value)
            .await
            .map_err(|error| write_errno(&error))?;
        value.truncate(length.min(value.len()));
        Ok((length, value))
    }

    /// `setxattr(2)`: `flags` is `XATTR_CREATE` or `XATTR_REPLACE` or neither.
    pub async fn setxattr(
        &mut self,
        ino: INodeNo,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        now: Timestamp,
    ) -> Result<(), Errno> {
        let mode = match flags {
            0 => XattrMode::Set,
            libc::XATTR_CREATE => XattrMode::Create,
            libc::XATTR_REPLACE => XattrMode::Replace,
            _ => return Err(Errno::EINVAL),
        };
        self.writable()?;
        let file = self.inodes.handle(ino)?;
        let mut transaction = self
            .writable_writer()?
            .join()
            .await
            .map_err(|error| write_errno(&error))?;
        transaction
            .set_xattr(&file, name.as_bytes(), value, mode, now)
            .await
            .map_err(|error| write_errno(&error))?;
        self.settle().await
    }

    pub async fn removexattr(
        &mut self,
        ino: INodeNo,
        name: &OsStr,
        now: Timestamp,
    ) -> Result<(), Errno> {
        self.writable()?;
        let file = self.inodes.handle(ino)?;
        let mut transaction = self
            .writable_writer()?
            .join()
            .await
            .map_err(|error| write_errno(&error))?;
        transaction
            .remove_xattr(&file, name.as_bytes(), now)
            .await
            .map_err(|error| write_errno(&error))?;
        self.settle().await
    }

    /// The names of the extended attributes, each followed by a NUL.
    pub async fn listxattr(&self, ino: INodeNo) -> Result<Vec<u8>, Errno> {
        let snapshot = self.snapshot()?;
        let inode = self.open_inode(&snapshot, ino).await?;
        let mut names = Vec::new();
        snapshot
            .list_xattrs(&inode, |name| {
                names.extend_from_slice(name);
                names.push(0);
                ControlFlow::Continue(())
            })
            .await
            .map_err(|error| read_errno(&error))?;
        Ok(names)
    }
}

/// A directory entry name as bytes.
fn entry_name(name: &OsStr) -> Result<&[u8], Errno> {
    let bytes = name.as_bytes();
    if bytes.len() > NAME_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    Ok(bytes)
}

/// The target of a symlink as bytes.
pub fn target_bytes(target: &Path) -> &[u8] {
    target.as_os_str().as_bytes()
}

/// Random version 4 UUIDs for the root records that lack one.
struct RandomUuids;

impl RootUuids for RandomUuids {
    fn next_uuid(&mut self) -> [u8; 16] {
        let mut uuid = [0; 16];
        getrandom::fill(&mut uuid).expect("the operating system's random source failed");
        // RFC 9562: version 4 and the RFC variant.
        uuid[6] = (uuid[6] & 0x0f) | 0x40;
        uuid[8] = (uuid[8] & 0x3f) | 0x80;
        uuid
    }
}

fn file_type(kind: FileKind) -> FileType {
    match kind {
        FileKind::Regular => FileType::RegularFile,
        FileKind::Directory => FileType::Directory,
        FileKind::Symlink => FileType::Symlink,
        FileKind::CharDevice => FileType::CharDevice,
        FileKind::BlockDevice => FileType::BlockDevice,
        FileKind::Fifo => FileType::NamedPipe,
        FileKind::Socket => FileType::Socket,
    }
}

fn system_time(time: Timestamp) -> SystemTime {
    let nanoseconds = Duration::from_nanos(u64::from(time.nanoseconds));
    let seconds = Duration::from_secs(time.seconds.unsigned_abs());
    if time.seconds >= 0 {
        UNIX_EPOCH + seconds + nanoseconds
    } else {
        UNIX_EPOCH - seconds + nanoseconds
    }
}

pub fn timestamp(time: SystemTime) -> Timestamp {
    match time.duration_since(UNIX_EPOCH) {
        Ok(since) => Timestamp {
            seconds: since.as_secs() as i64,
            nanoseconds: since.subsec_nanos(),
        },
        Err(error) => {
            let before = error.duration();
            let whole = -(before.as_secs() as i64);
            match before.subsec_nanos() {
                0 => Timestamp {
                    seconds: whole,
                    nanoseconds: 0,
                },
                nanoseconds => Timestamp {
                    seconds: whole - 1,
                    nanoseconds: 1_000_000_000 - nanoseconds,
                },
            }
        }
    }
}

/// Linux's `fuse_lookup_name` requires generation 0 for `FUSE_ROOT_ID`
/// (`fs/fuse/dir.c`).
fn fuse_generation(ino: INodeNo, generation: u64) -> Generation {
    if ino == INodeNo::ROOT {
        Generation(0)
    } else {
        Generation(generation)
    }
}

fn attr<S: BlockSource>(ino: INodeNo, metadata: &Metadata, snapshot: &Snapshot<S>) -> FileAttr {
    FileAttr {
        ino,
        size: metadata.size,
        blocks: metadata.nbytes.div_ceil(512),
        atime: system_time(metadata.atime),
        mtime: system_time(metadata.mtime),
        ctime: system_time(metadata.ctime),
        crtime: system_time(metadata.otime),
        kind: file_type(metadata.kind),
        // The permission and set-id bits, which fit 12 bits.
        perm: metadata.permissions as u16,
        nlink: metadata.nlink,
        uid: metadata.uid,
        gid: metadata.gid,
        // FUSE carries `stat`'s encoding, which the kernel decodes with
        // `new_decode_dev` (`fuse_fillattr` in `fs/fuse/inode.c`).
        rdev: metadata.rdev.encode(),
        blksize: snapshot.superblock().sectorsize(),
        flags: 0,
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs::File;
    use std::os::unix::fs::FileExt;

    use ferrosys::btrfs::{FormatOptions, SubvolumeRequest, format_to};
    use ferrosys::{Metadata as FerrosysMetadata, Timestamp as FerrosysTimestamp, TreeBuilder};
    use helios_btrfs::READ_ALIGNMENT;
    use helios_hal::io::{IoError, IoResult};

    use super::super::device::Claim;
    use super::*;

    struct TempDisk {
        file: File,
        len: u64,
    }

    impl TempDisk {
        fn new(tree: TreeBuilder, options: FormatOptions) -> (Self, File) {
            let len = 128 << 20;
            let mut file = tempfile::tempfile().unwrap();
            file.set_len(len).unwrap();
            format_to(&mut file, tree, len, options).unwrap();
            let backing = file.try_clone().unwrap();
            (Self { file, len }, backing)
        }

        fn from_file(file: File) -> Self {
            let len = file.metadata().unwrap().len();
            Self { file, len }
        }
    }

    impl BlockSource for TempDisk {
        fn size_bytes(&self) -> u64 {
            self.len
        }

        async fn read_at(&self, offset: u64, buf: &mut [u8]) -> IoResult<()> {
            self.file
                .read_exact_at(buf, offset)
                .map_err(|_| IoError::DeviceFault)
        }
    }

    impl BlockSink for TempDisk {
        async fn stage(&self, block: u64, bytes: &[u8; READ_ALIGNMENT as usize]) -> IoResult<()> {
            self.file
                .write_all_at(bytes, block * READ_ALIGNMENT)
                .map_err(|_| IoError::DeviceFault)
        }

        async fn commit(&self, block: u64, bytes: &[u8; READ_ALIGNMENT as usize]) -> IoResult<()> {
            self.file
                .write_all_at(bytes, block * READ_ALIGNMENT)
                .map_err(|_| IoError::DeviceFault)
        }
    }

    fn empty_image() -> (TempDisk, File) {
        let timestamp = FerrosysTimestamp::from_secs(1_700_000_000);
        let tree = TreeBuilder::new().root(FerrosysMetadata::new(0o755, timestamp));
        let options = FormatOptions::new([0x53; 16], timestamp);
        TempDisk::new(tree, options)
    }

    fn open_state(disk: TempDisk) -> State<TempDisk, ()> {
        State::from_writer(disk, (), NonZeroUsize::MIN, false).unwrap()
    }

    fn test_owner() -> Owner {
        Owner {
            uid: 0,
            gid: 0,
            umask: 0,
        }
    }

    fn test_time() -> Timestamp {
        Timestamp {
            seconds: 1_700_000_001,
            nanoseconds: 0,
        }
    }

    #[test]
    fn stable_inode_numbers_and_dot_lookup_survive_forget_and_remount() {
        block_on(async {
            let (disk, backing) = empty_image();
            let mut state = open_state(disk);

            let (dir_attr, dir_gen) = state
                .create(
                    INodeNo::ROOT,
                    OsStr::new("dir"),
                    Node::Directory,
                    0o755,
                    test_owner(),
                    test_time(),
                )
                .await
                .unwrap();
            let (file_attr, file_gen) = state
                .create(
                    dir_attr.ino,
                    OsStr::new("file"),
                    Node::File,
                    0o644,
                    test_owner(),
                    test_time(),
                )
                .await
                .unwrap();
            assert_eq!(
                state
                    .write(file_attr.ino, 0, b"hello", test_time())
                    .await
                    .unwrap(),
                5
            );
            state.sync().await.unwrap();

            // Drop both entries via FUSE_FORGET (drop_caches) and resolve via
            // FUSE_LOOKUP(nodeid, ".").
            state.forget(file_attr.ino, 1).await;
            state.forget(dir_attr.ino, 1).await;
            assert_eq!(state.getattr(file_attr.ino).await, Err(Errno::ESTALE));

            let (resolved_file, resolved_file_gen) =
                state.lookup(file_attr.ino, OsStr::new(".")).await.unwrap();
            assert_eq!(resolved_file.ino, file_attr.ino);
            assert_eq!(resolved_file_gen, file_gen);
            assert_eq!(state.read(file_attr.ino, 0, 16).await.unwrap(), b"hello");
            // Writer handle was refreshed by lookup(".", ...), so mutations work.
            assert_eq!(
                state
                    .write(file_attr.ino, 5, b"-world", test_time())
                    .await
                    .unwrap(),
                6
            );

            let (resolved_dir, resolved_dir_gen) =
                state.lookup(dir_attr.ino, OsStr::new(".")).await.unwrap();
            assert_eq!(resolved_dir.ino, dir_attr.ino);
            assert_eq!(resolved_dir_gen, dir_gen);
            let (parent_attr, parent_gen) =
                state.lookup(dir_attr.ino, OsStr::new("..")).await.unwrap();
            assert_eq!(parent_attr.ino, INodeNo::ROOT);
            assert_eq!(parent_gen, Generation(0));
            state.sync().await.unwrap();
            drop(state);

            // Simulate a full unmount + remount: fresh State with an empty cache.
            let mut remounted = open_state(TempDisk::from_file(backing));
            let (after_file, after_file_gen) = remounted
                .lookup(file_attr.ino, OsStr::new("."))
                .await
                .unwrap();
            assert_eq!(after_file.ino, file_attr.ino);
            assert_eq!(after_file_gen, file_gen);
            assert_eq!(
                remounted.read(file_attr.ino, 0, 16).await.unwrap(),
                b"hello-world"
            );
            assert_eq!(
                remounted
                    .write(file_attr.ino, 11, b"!", test_time())
                    .await
                    .unwrap(),
                1
            );

            let (after_dir, after_dir_gen) = remounted
                .lookup(dir_attr.ino, OsStr::new("."))
                .await
                .unwrap();
            assert_eq!(after_dir.ino, dir_attr.ino);
            assert_eq!(after_dir_gen, dir_gen);
            let (after_child, _) = remounted
                .create(
                    dir_attr.ino,
                    OsStr::new("second"),
                    Node::File,
                    0o644,
                    test_owner(),
                    test_time(),
                )
                .await
                .unwrap();
            assert_ne!(after_child.ino, file_attr.ino);

            // Normal path lookup after remount returns the exact same INodeNo.
            let (by_name_dir, _) = remounted
                .lookup(INodeNo::ROOT, OsStr::new("dir"))
                .await
                .unwrap();
            assert_eq!(by_name_dir.ino, dir_attr.ino);
            let (by_name_file, _) = remounted
                .lookup(dir_attr.ino, OsStr::new("file"))
                .await
                .unwrap();
            assert_eq!(by_name_file.ino, file_attr.ino);
        });
    }

    #[test]
    fn dotdot_reconnects_nested_and_renamed_directories_after_remount() {
        block_on(async {
            let (disk, backing) = empty_image();
            let mut state = open_state(disk);

            let (top, top_gen) = state
                .create(
                    INodeNo::ROOT,
                    OsStr::new("top"),
                    Node::Directory,
                    0o755,
                    test_owner(),
                    test_time(),
                )
                .await
                .unwrap();
            let (nested, nested_gen) = state
                .create(
                    top.ino,
                    OsStr::new("nested"),
                    Node::Directory,
                    0o755,
                    test_owner(),
                    test_time(),
                )
                .await
                .unwrap();
            let (leaf, _) = state
                .create(
                    nested.ino,
                    OsStr::new("leaf"),
                    Node::File,
                    0o644,
                    test_owner(),
                    test_time(),
                )
                .await
                .unwrap();
            state
                .rename(
                    top.ino,
                    OsStr::new("nested"),
                    top.ino,
                    OsStr::new("nested-renamed"),
                    RenameMode::Replace,
                    test_time(),
                )
                .await
                .unwrap();
            state.sync().await.unwrap();
            drop(state);

            let mut remounted = open_state(TempDisk::from_file(backing));
            let (resolved_nested, resolved_gen) =
                remounted.lookup(nested.ino, OsStr::new(".")).await.unwrap();
            assert_eq!(resolved_nested.ino, nested.ino);
            assert_eq!(resolved_gen, nested_gen);

            let (parent, parent_gen) = remounted
                .lookup(nested.ino, OsStr::new(".."))
                .await
                .unwrap();
            assert_eq!(parent.ino, top.ino);
            assert_eq!(parent_gen, top_gen);

            let (grandparent, grandparent_gen) =
                remounted.lookup(top.ino, OsStr::new("..")).await.unwrap();
            assert_eq!(grandparent.ino, INodeNo::ROOT);
            assert_eq!(grandparent_gen, Generation(0));

            let (root_parent, root_parent_gen) = remounted
                .lookup(INodeNo::ROOT, OsStr::new(".."))
                .await
                .unwrap();
            assert_eq!(root_parent.ino, INodeNo::ROOT);
            assert_eq!(root_parent_gen, Generation(0));

            // readdir on `top` reports the stable inode number matching `nested`
            // so Linux exportfs `get_name` can match it back to `nested-renamed`.
            let top_fh = remounted.opendir(top.ino).await.unwrap();
            let mut entries = Vec::new();
            remounted
                .readdir(top.ino, top_fh, 0, |ino, _cookie, _kind, name| {
                    entries.push((name.to_os_string(), ino));
                    false
                })
                .await
                .unwrap();
            remounted.releasedir(top_fh).await;
            assert!(entries.contains(&(OsStr::new("..").to_os_string(), INodeNo::ROOT)));
            assert!(entries.contains(&(OsStr::new("nested-renamed").to_os_string(), nested.ino)));

            // `..` on a non-directory fails with ENOTDIR.
            remounted.lookup(leaf.ino, OsStr::new(".")).await.unwrap();
            assert_eq!(
                remounted.lookup(leaf.ino, OsStr::new("..")).await,
                Err(Errno::ENOTDIR)
            );
        });
    }

    #[test]
    fn dot_lookup_returns_estale_after_unlink_and_reports_recycled_generation() {
        block_on(async {
            let (disk, backing) = empty_image();
            let mut state = open_state(disk);

            let (file, old_gen) = state
                .create(
                    INodeNo::ROOT,
                    OsStr::new("ephemeral"),
                    Node::File,
                    0o644,
                    test_owner(),
                    test_time(),
                )
                .await
                .unwrap();
            state.sync().await.unwrap();

            state
                .remove(INodeNo::ROOT, OsStr::new("ephemeral"), false, test_time())
                .await
                .unwrap();
            assert_eq!(
                state.lookup(file.ino, OsStr::new(".")).await,
                Err(Errno::ESTALE)
            );
            state.forget(file.ino, 1).await;
            assert_eq!(
                state.lookup(file.ino, OsStr::new(".")).await,
                Err(Errno::ESTALE)
            );
            state.sync().await.unwrap();

            // Invalid node IDs fail with ESTALE.
            assert_eq!(
                state.lookup(INodeNo(0), OsStr::new(".")).await,
                Err(Errno::ESTALE)
            );
            assert_eq!(
                state
                    .lookup(INodeNo(SUBVOLUME_ROOT_INODE), OsStr::new("."))
                    .await,
                Err(Errno::ESTALE)
            );

            // Committing the deletion lets the next transaction reuse the freed
            // highest inode number with a strictly higher generation.
            let (recycled, new_gen) = state
                .create(
                    INodeNo::ROOT,
                    OsStr::new("recycled"),
                    Node::File,
                    0o644,
                    test_owner(),
                    test_time(),
                )
                .await
                .unwrap();
            assert_eq!(recycled.ino, file.ino);
            assert_ne!(new_gen, old_gen);
            state.sync().await.unwrap();
            drop(state);

            // After remount, lookup(nodeid, ".") returns the new generation so
            // Linux's fuse_get_dentry rejects the old handle with ESTALE.
            let mut remounted = open_state(TempDisk::from_file(backing));
            let (after, after_gen) = remounted.lookup(file.ino, OsStr::new(".")).await.unwrap();
            assert_eq!(after.ino, file.ino);
            assert_eq!(after_gen, new_gen);
            assert_ne!(after_gen, old_gen);

            // If a stale entry for the old generation is still cached in
            // `inodes`, lookup(nodeid, ".") rejects it directly with ESTALE.
            let stale_handle = remounted.inodes.handle(file.ino).unwrap();
            remounted.forget(file.ino, 1).await;
            remounted
                .inodes
                .record(file.ino, old_gen.0, Some(stale_handle));
            assert_eq!(
                remounted.lookup(file.ino, OsStr::new(".")).await,
                Err(Errno::ESTALE)
            );
        });
    }

    #[test]
    fn nested_subvolume_has_distinct_stable_inode_and_resolves_parent() {
        block_on(async {
            let timestamp = FerrosysTimestamp::from_secs(1_700_000_000);
            let dir_meta = FerrosysMetadata::new(0o755, timestamp);
            let tree = TreeBuilder::new()
                .root(dir_meta)
                .directory("/sub", dir_meta);
            let options = FormatOptions::new([0x53; 16], timestamp)
                .subvolume(SubvolumeRequest::new(b"/sub".to_vec(), [0x42; 16]));
            let (disk, backing) = TempDisk::new(tree, options);
            let mut state = open_state(disk);

            let (sub, sub_gen) = state
                .lookup(INodeNo::ROOT, OsStr::new("sub"))
                .await
                .unwrap();
            assert_ne!(sub.ino, INodeNo::ROOT);
            state.forget(sub.ino, 1).await;
            drop(state);

            let mut remounted = open_state(TempDisk::from_file(backing));
            let (resolved, resolved_gen) =
                remounted.lookup(sub.ino, OsStr::new(".")).await.unwrap();
            assert_eq!(resolved.ino, sub.ino);
            assert_eq!(resolved_gen, sub_gen);

            let (parent, parent_gen) = remounted.lookup(sub.ino, OsStr::new("..")).await.unwrap();
            assert_eq!(parent.ino, INodeNo::ROOT);
            assert_eq!(parent_gen, Generation(0));
        });
    }

    const WHEN: Timestamp = Timestamp {
        seconds: 1_700_000_100,
        nanoseconds: 0,
    };

    fn test_state() -> (tempfile::NamedTempFile, State) {
        let time = FerrosysTimestamp::from_secs(1_700_000_000);
        let mut named = tempfile::NamedTempFile::new().expect("temp image");
        // ferrosys' default single-device geometry needs at least 109 MiB.
        let size = 128 << 20;
        named.as_file_mut().set_len(size).expect("set_len");
        let tree = TreeBuilder::new().root(FerrosysMetadata::new(0o755, time));
        format_to(
            named.as_file_mut(),
            tree,
            size,
            FormatOptions::new([0x44; 16], time),
        )
        .expect("format btrfs");
        let claim = Claim::open(named.path(), false).expect("open test claim");
        let state = State::open_for_test(
            claim,
            named.path().to_path_buf(),
            NonZeroUsize::new(1).unwrap(),
            false,
        )
        .expect("open state");
        (named, state)
    }

    fn list_names(state: &mut State, ino: INodeNo, fh: FileHandle) -> Vec<OsString> {
        let mut names = Vec::new();
        let mut offset = 0;
        loop {
            let mut batch = Vec::new();
            block_on(state.readdir(ino, fh, offset, |_, cookie, _, name| {
                if batch.len() == 2 {
                    return true;
                }
                batch.push((cookie, name.to_os_string()));
                false
            }))
            .expect("readdir");
            let Some((last_cookie, _)) = batch.last() else {
                break;
            };
            offset = *last_cookie;
            names.extend(batch.into_iter().map(|(_, name)| name));
        }
        names
    }

    #[test]
    fn opendir_keeps_open_bound_on_first_readdir_and_refreshes_on_rewind() {
        let (_image, mut state) = test_state();
        let owner = Owner {
            uid: 0,
            gid: 0,
            umask: 0,
        };
        let (dir_attr, _) = block_on(state.create(
            INodeNo::ROOT,
            OsStr::new("work"),
            Node::Directory,
            0o755,
            owner,
            WHEN,
        ))
        .expect("mkdir work");
        let dir = dir_attr.ino;
        for name in ["文件", "ファイル", "파일"] {
            block_on(state.create(dir, OsStr::new(name), Node::File, 0o644, owner, WHEN))
                .expect("create initial cjk");
        }

        // Open `work`, then add an entry before the first `readdir(0)`. The
        // open-time bound hides the entry added after `opendir`.
        let fh = block_on(state.opendir(dir)).expect("opendir");
        block_on(state.create(
            dir,
            OsStr::new("after-open"),
            Node::File,
            0o644,
            owner,
            WHEN,
        ))
        .expect("create after-open");
        let first_pass = list_names(&mut state, dir, fh);
        assert!(
            !first_pass.iter().any(|name| name == "after-open"),
            "first readdir(0) must keep opendir's bound: {first_pass:?}"
        );

        // A second `readdir(0)` on the same handle (`rewinddir(3)`) refreshes
        // the bound and makes `after-open` visible.
        let rewound = list_names(&mut state, dir, fh);
        assert!(
            rewound.iter().any(|name| name == "after-open"),
            "rewound readdir(0) must see entries added since opendir: {rewound:?}"
        );

        // Renaming every yielded entry (`entry -> TEMPFILE -> entry`) while
        // paging through `work` terminates in bounded entries.
        let mut offset = 0;
        let mut seen = Vec::new();
        let safety_cap = 20;
        loop {
            let mut batch = Vec::new();
            block_on(state.readdir(dir, fh, offset, |_, cookie, _, name| {
                if batch.len() == 2 {
                    return true;
                }
                batch.push((cookie, name.to_os_string()));
                false
            }))
            .expect("readdir page");
            let Some((last_cookie, _)) = batch.last() else {
                break;
            };
            offset = *last_cookie;
            for (_, name) in batch {
                if name == "." || name == ".." {
                    continue;
                }
                block_on(state.rename(
                    dir,
                    &name,
                    dir,
                    OsStr::new("TEMPFILE"),
                    RenameMode::Replace,
                    WHEN,
                ))
                .expect("rename to TEMPFILE");
                block_on(state.rename(
                    dir,
                    OsStr::new("TEMPFILE"),
                    dir,
                    &name,
                    RenameMode::Replace,
                    WHEN,
                ))
                .expect("rename back");
                seen.push(name);
                assert!(
                    seen.len() <= safety_cap,
                    "fuse-btrfs readdir looped past safety cap ({safety_cap})"
                );
            }
        }
        assert_eq!(seen.len(), 4, "expected 4 entries, got {seen:?}");

        block_on(state.releasedir(fh));
        assert_eq!(
            block_on(state.readdir(dir, fh, 0, |_, _, _, _| false)),
            Err(Errno::EBADF)
        );
    }

    #[test]
    fn unlinked_open_file_and_dir_stay_accessible_until_final_release() {
        block_on(async {
            let (disk, backing) = empty_image();
            let mut state = open_state(disk);

            let (file, file_gen) = state
                .create(
                    INodeNo::ROOT,
                    OsStr::new("open.txt"),
                    Node::File,
                    0o644,
                    test_owner(),
                    test_time(),
                )
                .await
                .unwrap();
            let fh1 = state
                .open_file(file.ino, OpenFlags(libc::O_RDWR))
                .await
                .unwrap();
            let fh2 = state
                .open_file(file.ino, OpenFlags(libc::O_RDONLY))
                .await
                .unwrap();
            state
                .write(file.ino, 0, b"before-unlink", test_time())
                .await
                .unwrap();

            // Unlink while two handles are open.
            state
                .remove(INodeNo::ROOT, OsStr::new("open.txt"), false, test_time())
                .await
                .unwrap();
            assert_eq!(
                state.lookup(INodeNo::ROOT, OsStr::new("open.txt")).await,
                Err(Errno::ENOENT)
            );
            assert!(state.has_open_orphans());

            // Attributes report nlink == 0, export `.` lookup succeeds, I/O works.
            let attr = state.getattr(file.ino).await.unwrap();
            assert_eq!(attr.nlink, 0);
            let (dot_attr, dot_gen) = state.lookup(file.ino, OsStr::new(".")).await.unwrap();
            assert_eq!(dot_attr.nlink, 0);
            assert_eq!(dot_gen, file_gen);
            assert_eq!(state.read(file.ino, 0, 32).await.unwrap(), b"before-unlink");
            state
                .write(file.ino, 13, b"-after", test_time())
                .await
                .unwrap();
            assert_eq!(
                state.read(file.ino, 0, 32).await.unwrap(),
                b"before-unlink-after"
            );

            // Re-linking a previously named file whose nlink dropped to 0 fails with ENOENT.
            assert_eq!(
                state
                    .link(file.ino, INodeNo::ROOT, OsStr::new("revived"), test_time())
                    .await,
                Err(Errno::ENOENT)
            );

            // Releasing the first handle keeps the orphan alive.
            state.release_file(fh1).await;
            assert!(state.has_open_orphans());
            assert_eq!(
                state.read(file.ino, 0, 32).await.unwrap(),
                b"before-unlink-after"
            );

            // Releasing the last handle deletes the inode and orphan item.
            state.release_file(fh2).await;
            assert!(!state.has_open_orphans());
            assert_eq!(state.getattr(file.ino).await, Err(Errno::ESTALE));
            assert_eq!(
                state.lookup(file.ino, OsStr::new(".")).await,
                Err(Errno::ESTALE)
            );

            // Open directory overwritten by rename keeps nlink == 0 until releasedir.
            let (dir1, _) = state
                .create(
                    INodeNo::ROOT,
                    OsStr::new("dir1"),
                    Node::Directory,
                    0o755,
                    test_owner(),
                    test_time(),
                )
                .await
                .unwrap();
            let (dir2, _) = state
                .create(
                    INodeNo::ROOT,
                    OsStr::new("dir2"),
                    Node::Directory,
                    0o755,
                    test_owner(),
                    test_time(),
                )
                .await
                .unwrap();
            let dir_fh = state.opendir(dir2.ino).await.unwrap();
            state
                .rename(
                    INodeNo::ROOT,
                    OsStr::new("dir1"),
                    INodeNo::ROOT,
                    OsStr::new("dir2"),
                    RenameMode::Replace,
                    test_time(),
                )
                .await
                .unwrap();
            assert_eq!(state.getattr(dir2.ino).await.unwrap().nlink, 0);
            assert_eq!(state.getattr(dir1.ino).await.unwrap().nlink, 1);
            assert!(state.has_open_orphans());
            // Creating entries inside an unlinked directory fails with ENOENT.
            assert_eq!(
                state
                    .create(
                        dir2.ino,
                        OsStr::new("child"),
                        Node::File,
                        0o644,
                        test_owner(),
                        test_time(),
                    )
                    .await,
                Err(Errno::ENOENT)
            );
            // After releasedir, the cached lookup (e.g. a process cwd) still
            // allows getattr while export `.` lookup returns ESTALE.
            state.releasedir(dir_fh).await;
            assert_eq!(state.getattr(dir2.ino).await.unwrap().nlink, 0);
            assert_eq!(
                state.lookup(dir2.ino, OsStr::new(".")).await,
                Err(Errno::ESTALE)
            );
            assert!(state.has_open_orphans());
            // Final forget deletes the unlinked directory and its orphan item.
            state.forget(dir2.ino, 1).await;
            assert!(!state.has_open_orphans());
            assert_eq!(state.getattr(dir2.ino).await, Err(Errno::ESTALE));

            state.sync().await.unwrap();
            drop(state);
            // Remount succeeds cleanly after orphan deletion.
            let remounted = open_state(TempDisk::from_file(backing));
            assert!(!remounted.has_open_orphans());
        });
    }

    #[test]
    fn tmpfile_supports_linking_and_respects_o_excl() {
        block_on(async {
            let (disk, backing) = empty_image();
            let mut state = open_state(disk);

            // O_TMPFILE without O_EXCL can be written and later linked into a directory.
            let (tmp, _, fh) = state
                .tmpfile(
                    INodeNo::ROOT,
                    0o640,
                    test_owner(),
                    OpenFlags(libc::O_RDWR),
                    test_time(),
                )
                .await
                .unwrap();
            assert_eq!(tmp.nlink, 0);
            assert!(state.has_open_orphans());
            state
                .write(tmp.ino, 0, b"staged", test_time())
                .await
                .unwrap();

            let (linked, _) = state
                .link(tmp.ino, INodeNo::ROOT, OsStr::new("final.txt"), test_time())
                .await
                .unwrap();
            assert_eq!(linked.ino, tmp.ino);
            assert_eq!(linked.nlink, 1);
            assert!(!state.has_open_orphans());
            state.release_file(fh).await;

            // O_TMPFILE | O_EXCL refuses link with ENOENT and deletes on release.
            let (excl, _, excl_fh) = state
                .tmpfile(
                    INodeNo::ROOT,
                    0o600,
                    test_owner(),
                    OpenFlags(libc::O_RDWR | libc::O_EXCL),
                    test_time(),
                )
                .await
                .unwrap();
            assert_eq!(excl.nlink, 0);
            assert_eq!(
                state
                    .link(excl.ino, INodeNo::ROOT, OsStr::new("nope"), test_time())
                    .await,
                Err(Errno::ENOENT)
            );
            state.release_file(excl_fh).await;
            assert_eq!(state.getattr(excl.ino).await, Err(Errno::ESTALE));

            // Commit a live tmpfile and drop without release to test mount-time cleanup.
            let (crashed, _, _leaked_fh) = state
                .tmpfile(
                    INodeNo::ROOT,
                    0o600,
                    test_owner(),
                    OpenFlags(libc::O_RDWR),
                    test_time(),
                )
                .await
                .unwrap();
            state
                .write(crashed.ino, 0, b"lost-on-crash", test_time())
                .await
                .unwrap();
            state.sync().await.unwrap();
            drop(state);

            let mut recovered = open_state(TempDisk::from_file(backing));
            assert!(!recovered.has_open_orphans());
            assert_eq!(
                recovered.lookup(crashed.ino, OsStr::new(".")).await,
                Err(Errno::ESTALE)
            );
            let (kept, _) = recovered
                .lookup(INodeNo::ROOT, OsStr::new("final.txt"))
                .await
                .unwrap();
            assert_eq!(recovered.read(kept.ino, 0, 16).await.unwrap(), b"staged");
        });
    }
}
