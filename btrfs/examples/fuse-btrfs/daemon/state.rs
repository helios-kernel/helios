//! The writer, the inode map and every operation the daemon serves.
//!
//! As Linux's btrfs, a change is visible at once and durable at commit. Each
//! mutation joins the writer's running transaction, and reads go through the
//! writer's view of it, so the next request sees every reply's change. The
//! transaction commits on `fsync`, `fsyncdir`, `remount,ro` and unmount, and
//! when its dirty metadata reaches Linux's bound.

use std::collections::{HashMap, HashSet};
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
    Attributes, DEFAULT_DIRTY_METADATA_LIMIT, InodeHandle, Name, RootUuids, Special, WriteError,
    WriteOptions, Writer, XattrMode,
};
use helios_btrfs::{
    DirBound, DirPosition, EntryTarget, Error, FileKind, Filesystem, Inode, Metadata, Timestamp,
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

type Snapshot = Filesystem<Arc<Device>>;

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

enum Storage {
    ReadOnly(Snapshot),
    Writable(Box<Writer<Device, RandomUuids>>),
}

/// State of an open directory stream (`FUSE_OPENDIR` .. `FUSE_RELEASEDIR`),
/// following Linux's `btrfs_opendir` and `btrfs_real_readdir`
/// (`fs/btrfs/inode.c`, commit `9b378f6ad48c`, refreshed on rewind as
/// commit `fd968e683bd9`).
#[derive(Clone, Copy)]
struct OpenDir {
    bound: DirBound,
    /// Whether this stream has already served a `readdir`. Linux FUSE handles
    /// `lseek(dirfd, 0, SEEK_SET)` (`rewinddir(3)`) in the VFS without sending
    /// a request, so a `readdir` at offset `0` once `started` is true signals
    /// a rewind and refreshes `bound`, while the initial `readdir(0)` keeps
    /// the bound captured at `opendir`.
    started: bool,
}

pub struct State {
    storage: Storage,
    claim: Claim,
    device_path: PathBuf,
    inodes: Inodes,
    open_dirs: HashMap<u64, OpenDir>,
    next_dir_handle: u64,
    concurrency: NonZeroUsize,
    read_only: bool,
    destroyed: bool,
    #[cfg(test)]
    direct_io: bool,
    next_fh: u64,
    writable_handles: HashSet<u64>,
}

impl State {
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
                Err(OpenError::Write(
                    WriteError::UnsupportedCompatRo { .. } | WriteError::QuotaTreePresent,
                )) => {}
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
        let mut writer = block_on(Writer::mount(
            device,
            RandomUuids,
            concurrency,
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
            claim,
            device_path,
            inodes: Inodes::new(identity, root.metadata().generation, Some(handle)),
            open_dirs: HashMap::new(),
            next_dir_handle: 1,
            concurrency,
            read_only,
            destroyed: false,
            #[cfg(test)]
            direct_io,
            next_fh: 1,
            writable_handles: HashSet::new(),
        })
    }

    fn open_read_only(
        claim: Claim,
        device_path: PathBuf,
        concurrency: NonZeroUsize,
        direct_io: bool,
    ) -> Result<Self, OpenError> {
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
            claim,
            device_path,
            inodes: Inodes::new(identity, root.metadata().generation, None),
            open_dirs: HashMap::new(),
            next_dir_handle: 1,
            concurrency,
            read_only: true,
            destroyed: false,
            #[cfg(test)]
            direct_io,
            next_fh: 1,
            writable_handles: HashSet::new(),
        })
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    pub fn is_destroyed(&self) -> bool {
        self.destroyed
    }

    pub fn has_open_writable(&self) -> bool {
        !self.writable_handles.is_empty()
    }

    /// Records a file open. Writable opens (`O_WRONLY` or `O_RDWR`) fail with
    /// `EROFS` on a read-only mount and receive a tracked handle so
    /// `remount,ro` can reject active writers with `EBUSY`.
    pub fn open_file(&mut self, flags: OpenFlags) -> Result<FileHandle, Errno> {
        if matches!(
            flags.acc_mode(),
            OpenAccMode::O_WRONLY | OpenAccMode::O_RDWR
        ) {
            self.writable()?;
            let id = self.next_fh;
            self.next_fh += 1;
            self.writable_handles.insert(id);
            Ok(FileHandle(id))
        } else {
            Ok(FileHandle(0))
        }
    }

    /// Releases a file handle. Returns `true` if this released the last open
    /// writable handle.
    pub fn release_file(&mut self, fh: FileHandle) -> bool {
        fh.0 != 0 && self.writable_handles.remove(&fh.0) && self.writable_handles.is_empty()
    }

    /// Transitions the daemon to read-only after verifying no writable file
    /// handles remain open and committing any running transaction.
    pub async fn remount_read_only(&mut self) -> Result<(), Errno> {
        if self.destroyed {
            return Err(Errno::ENODEV);
        }
        if !self.writable_handles.is_empty() {
            return Err(Errno::EBUSY);
        }
        self.sync().await?;
        self.read_only = true;
        Ok(())
    }

    /// Transitions the daemon to read-write, checking `BLKROGET` (matching
    /// Linux's `reconfigure_super` `bdev_read_only` -> `EACCES` check) and
    /// upgrading a read-only [`Filesystem`] mount to a [`Writer`] when needed.
    pub async fn remount_read_write(&mut self) -> Result<(), Errno> {
        if self.destroyed {
            return Err(Errno::ENODEV);
        }
        match self.claim.is_block_device_read_only() {
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
                let direct_io = self.direct_io;
                #[cfg(not(test))]
                let direct_io = true;
                let device = Self::open_device_rw(&self.device_path, self.claim.clone(), direct_io)
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
                    self.concurrency,
                    timestamp(SystemTime::now()),
                )
                .await
                .map_err(|error| write_errno(&error))?;
                let pending = self.inodes.pending_handle_paths();
                let (root_handle, resolved) = {
                    let transaction = writer.join().await.map_err(|error| write_errno(&error))?;
                    let root_handle = transaction
                        .root()
                        .await
                        .map_err(|error| write_errno(&error))?;
                    let mut by_path: HashMap<Vec<Vec<u8>>, InodeHandle> = HashMap::new();
                    by_path.insert(Vec::new(), root_handle.clone());
                    let mut resolved = Vec::with_capacity(pending.len());
                    for entry in pending {
                        let mut current = root_handle.clone();
                        let mut prefix = Vec::with_capacity(entry.path.len());
                        let mut found = true;
                        for component in entry.path {
                            prefix.push(component);
                            if let Some(cached) = by_path.get(&prefix) {
                                current = cached.clone();
                                continue;
                            }
                            let Some(next) = transaction
                                .lookup(&current, prefix.last().expect("component pushed"))
                                .await
                                .map_err(|error| write_errno(&error))?
                            else {
                                found = false;
                                break;
                            };
                            by_path.insert(prefix.clone(), next.clone());
                            current = next;
                        }
                        if !found
                            || current.tree() != entry.identity.tree
                            || current.number() != entry.identity.number
                        {
                            continue;
                        }
                        if let Some(generation) = entry.generation {
                            let meta = transaction
                                .metadata(&current)
                                .await
                                .map_err(|error| write_errno(&error))?;
                            if meta.generation != generation {
                                continue;
                            }
                        }
                        resolved.push((entry.ino, current));
                    }
                    (root_handle, resolved)
                };
                self.inodes.attach_handle(INodeNo::ROOT, root_handle);
                for (ino, handle) in resolved {
                    self.inodes.attach_handle(ino, handle);
                }
                self.storage = Storage::Writable(Box::new(writer));
            }
        }
        self.read_only = false;
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
        self.sync().await
    }

    pub fn forget(&mut self, ino: INodeNo, count: u64) {
        self.inodes.forget(ino, count);
    }

    fn snapshot(&self) -> Result<Snapshot, Errno> {
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

    fn writable_writer(&mut self) -> Result<&mut Writer<Device, RandomUuids>, Errno> {
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
    async fn open_inode(&self, snapshot: &Snapshot, ino: INodeNo) -> Result<Inode, Errno> {
        let (identity, generation) = self.inodes.identity(ino)?;
        let inode = match snapshot.inode(identity.tree, identity.number).await {
            Ok(inode) => inode,
            Err(Error::MissingInode { .. }) => return Err(Errno::ESTALE),
            Err(error) => return Err(read_errno(&error)),
        };
        if generation.is_some_and(|generation| generation != inode.metadata().generation) {
            return Err(Errno::ESTALE);
        }
        Ok(inode)
    }

    /// The writer's handle for the entry `name` of directory `parent`.
    async fn handle_of(&mut self, parent: INodeNo, name: &[u8]) -> Result<InodeHandle, Errno> {
        let parent = self.inodes.handle(parent)?;
        let Storage::Writable(writer) = &mut self.storage else {
            return Err(Errno::EROFS);
        };
        let transaction = writer.join().await.map_err(|error| write_errno(&error))?;
        transaction
            .lookup(&parent, name)
            .await
            .map_err(|error| write_errno(&error))?
            .ok_or(Errno::ENOENT)
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
        let dirty = match &self.storage {
            Storage::Writable(writer) => writer.dirty().metadata_bytes,
            Storage::ReadOnly(_) => 0,
        };
        if dirty >= DEFAULT_DIRTY_METADATA_LIMIT {
            self.sync().await?;
        }
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
            Err(Error::MissingInode { .. }) => return Err(Errno::ESTALE),
            Err(error) => return Err(read_errno(&error)),
        };
        let generation = inode.metadata().generation;
        let ino = self.inodes.record(identity, generation, handle, None);
        Ok((
            attr(ino, inode.metadata(), &snapshot),
            Generation(generation),
        ))
    }

    pub async fn lookup(
        &mut self,
        parent: INodeNo,
        name: &OsStr,
    ) -> Result<(FileAttr, Generation), Errno> {
        let name = entry_name(name)?;
        let snapshot = self.snapshot()?;
        let directory = self.open_inode(&snapshot, parent).await?;
        let child = snapshot
            .lookup(&directory, name)
            .await
            .map_err(|error| read_errno(&error))?
            .ok_or(Errno::ENOENT)?;
        let identity = Identity {
            tree: child.tree(),
            number: child.number(),
        };
        let generation = child.metadata().generation;
        let (handle, origin_path) = match &self.storage {
            Storage::ReadOnly(_) => (None, self.inodes.child_origin_path(parent, name)),
            Storage::Writable(_) => {
                let handle = if self.inodes.has_handle(identity, generation) {
                    None
                } else {
                    Some(self.handle_of(parent, name).await?)
                };
                (handle, None)
            }
        };
        let ino = self
            .inodes
            .record(identity, generation, handle, origin_path);
        Ok((
            attr(ino, child.metadata(), &snapshot),
            Generation(generation),
        ))
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
        let concurrency = self.concurrency;
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
                .truncate_file(&file, size, WriteOptions::plain(now, concurrency))
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

    /// Opens a directory stream and records its upper `DIR_INDEX` bound as of
    /// open time (`btrfs_opendir` in Linux `fs/btrfs/inode.c`, commit
    /// `9b378f6ad48c`).
    pub async fn opendir(&mut self, ino: INodeNo) -> Result<FileHandle, Errno> {
        let snapshot = self.snapshot()?;
        let directory = self.open_inode(&snapshot, ino).await?;
        let bound = snapshot
            .dir_bound(&directory)
            .await
            .map_err(|error| read_errno(&error))?;
        let handle = self.next_dir_handle;
        self.next_dir_handle += 1;
        self.open_dirs.insert(
            handle,
            OpenDir {
                bound,
                started: false,
            },
        );
        Ok(FileHandle(handle))
    }

    /// Releases a directory stream opened by [`Self::opendir`].
    pub fn releasedir(&mut self, fh: FileHandle) {
        self.open_dirs.remove(&fh.0);
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
        let open = *self.open_dirs.get(&fh.0).ok_or(Errno::EBADF)?;
        let bound = if offset == 0 && open.started {
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
            if !open.started {
                self.open_dirs
                    .get_mut(&fh.0)
                    .expect("open directory handle checked above")
                    .started = true;
            }
            open.bound
        };
        // The format stores neither `.` nor `..`; the kernel reports both.
        // The parent is not recorded, so `..` carries the directory's own number.
        for (cookie, name) in [(1, "."), (2, "..")] {
            if offset < cookie && emit(ino, cookie, FileType::Directory, OsStr::new(name)) {
                return Ok(());
            }
        }
        let tree = directory.tree();
        let inodes = &mut self.inodes;
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
                    let listed = inodes.listed(identity);
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
        let concurrency = self.concurrency;
        let mut transaction = self
            .writable_writer()?
            .join()
            .await
            .map_err(|error| write_errno(&error))?;
        let written = transaction
            .write_file(&file, offset, data, WriteOptions::plain(now, concurrency))
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

fn attr(ino: INodeNo, metadata: &Metadata, snapshot: &Snapshot) -> FileAttr {
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
    use std::ffi::{OsStr, OsString};
    use std::num::NonZeroUsize;

    use ferrosys::btrfs::{FormatOptions, format_to};
    use ferrosys::{Metadata as FormatMetadata, Timestamp as FormatTime, TreeBuilder};
    use fuser::{Errno, FileHandle, INodeNo};
    use futures_lite::future::block_on;
    use helios_btrfs::Timestamp;
    use helios_hal::fs::RenameMode;

    use super::super::device::Claim;
    use super::{Node, Owner, State};

    const WHEN: Timestamp = Timestamp {
        seconds: 1_700_000_100,
        nanoseconds: 0,
    };

    fn test_state() -> (tempfile::NamedTempFile, State) {
        let time = FormatTime::from_secs(1_700_000_000);
        let mut named = tempfile::NamedTempFile::new().expect("temp image");
        // ferrosys' default single-device geometry needs at least 109 MiB.
        let size = 128 << 20;
        named.as_file_mut().set_len(size).expect("set_len");
        let tree = TreeBuilder::new().root(FormatMetadata::new(0o755, time));
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

        state.releasedir(fh);
        assert_eq!(
            block_on(state.readdir(dir, fh, 0, |_, _, _, _| false)),
            Err(Errno::EBADF)
        );
    }
}
