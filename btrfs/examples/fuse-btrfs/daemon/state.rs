//! The writer, the inode map and every operation the daemon serves.
//!
//! As Linux's btrfs, a change is visible at once and durable at commit. Each
//! mutation joins the writer's running transaction, and reads go through the
//! writer's view of it, so the next request sees every reply's change. The
//! transaction commits on `fsync`, `fsyncdir` and unmount, and when its dirty
//! metadata reaches Linux's bound.

use std::ffi::OsStr;
use std::num::NonZeroUsize;
use std::ops::ControlFlow;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{Errno, FileAttr, FileType, Generation, INodeNo, TimeOrNow};
use futures_lite::future::block_on;
use helios_btrfs::write::{
    Attributes, DEFAULT_DIRTY_METADATA_LIMIT, InodeHandle, Name, RootUuids, WriteOptions, Writer,
    XattrMode,
};
use helios_btrfs::{
    BlockSink, BlockSource, DirPosition, EntryTarget, Error, FileKind, Filesystem, Inode, Metadata,
    Timestamp,
};
use helios_hal::fs::RenameMode;

use super::OpenError;
use super::device::Device;
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
}

/// The caller a creation is made for.
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

pub struct State<S = Device> {
    writer: Writer<S, RandomUuids>,
    inodes: Inodes,
    concurrency: NonZeroUsize,
    read_only: bool,
}

impl<S: BlockSink> State<S> {
    pub fn open(device: S, concurrency: NonZeroUsize, read_only: bool) -> Result<Self, OpenError> {
        let mut writer = block_on(Writer::mount(device, RandomUuids, concurrency))?;
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
            writer,
            inodes: Inodes::new(identity, root.metadata().generation, handle),
            concurrency,
            read_only,
        })
    }

    pub fn forget(&mut self, ino: INodeNo, count: u64) {
        self.inodes.forget(ino, count);
    }

    fn snapshot(&self) -> Result<Snapshot<S>, Errno> {
        self.writer.snapshot().map_err(|error| write_errno(&error))
    }

    fn writable(&self) -> Result<(), Errno> {
        if self.read_only {
            return Err(Errno::EROFS);
        }
        Ok(())
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
        if inode.metadata().generation != generation || inode.metadata().nlink == 0 {
            return Err(Errno::ESTALE);
        }
        Ok(inode)
    }

    /// The writer's handle for `identity`, refreshed from the running
    /// transaction.
    async fn handle_for(&mut self, identity: Identity) -> Result<InodeHandle, Errno> {
        let transaction = self
            .writer
            .join()
            .await
            .map_err(|error| write_errno(&error))?;
        transaction
            .inode(identity.tree, identity.number)
            .await
            .map_err(|error| write_errno(&error))?
            .ok_or(Errno::ESTALE)
    }

    /// Makes every change so far durable: `fsync`, `fsyncdir` and unmount.
    /// A failure poisons the writer, and the device keeps the previous
    /// generation.
    pub async fn sync(&mut self) -> Result<(), Errno> {
        self.writer
            .commit()
            .await
            .map_err(|error| write_errno(&error))
    }

    /// Ends a mutation: commits once the running transaction's dirty
    /// metadata reaches Linux's bound.
    async fn settle(&mut self) -> Result<(), Errno> {
        if self.writer.dirty().metadata_bytes >= DEFAULT_DIRTY_METADATA_LIMIT {
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
            Err(Error::MissingInode { .. } | Error::MissingRoot { .. }) => {
                return Err(Errno::ESTALE);
            }
            Err(error) => return Err(read_errno(&error)),
        };
        let ino = self.inodes.encode(identity)?;
        let generation = inode.metadata().generation;
        self.inodes.record(ino, generation, handle);
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
        let handle = if self.inodes.has_handle(ino, generation) {
            None
        } else {
            Some(self.handle_for(identity).await?)
        };
        self.inodes.record(ino, generation, handle);
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
        if inode.metadata().nlink == 0 {
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
        let concurrency = self.concurrency;
        let mut transaction = self
            .writer
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

    /// Hands the entries of directory `ino` after cookie `offset` to `emit`
    /// until it returns true, meaning its reply is full.
    pub async fn readdir(
        &self,
        ino: INodeNo,
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
        let concurrency = self.concurrency;
        let mut transaction = self
            .writer
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
            .writer
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
            .writer
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
            .writer
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
            .writer
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
        let block_size = self.snapshot()?.superblock().sectorsize();
        let usage = self.writer.usage().map_err(|error| write_errno(&error))?;
        let size = u64::from(block_size);
        Ok(Statfs {
            blocks: usage.total_bytes / size,
            free: usage.total_bytes.saturating_sub(usage.used_bytes) / size,
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
        let file = self.inodes.handle(ino)?;
        let transaction = self
            .writer
            .join()
            .await
            .map_err(|error| write_errno(&error))?;
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
            .writer
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
            .writer
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
        rdev: metadata.rdev as u32,
        blksize: snapshot.superblock().sectorsize(),
        flags: 0,
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::unix::fs::FileExt;

    use ferrosys::btrfs::{FormatOptions, SubvolumeRequest, format_to};
    use ferrosys::{Metadata as FerrosysMetadata, Timestamp as FerrosysTimestamp, TreeBuilder};
    use helios_btrfs::READ_ALIGNMENT;
    use helios_hal::io::{IoError, IoResult};

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

    fn open_state(disk: TempDisk) -> State<TempDisk> {
        State::open(disk, NonZeroUsize::MIN, false).unwrap()
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
            state.forget(file_attr.ino, 1);
            state.forget(dir_attr.ino, 1);
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
            let mut entries = Vec::new();
            remounted
                .readdir(top.ino, 0, |ino, _cookie, _kind, name| {
                    entries.push((name.to_os_string(), ino));
                    false
                })
                .await
                .unwrap();
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
            state.forget(file.ino, 1);
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
            remounted.forget(file.ino, 1);
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
            state.forget(sub.ino, 1);
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
}
