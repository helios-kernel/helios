//! Linux FUSE 7.31 wire protocol and stateful session engine for `virtio-fs`.
//!
//! All structures match Linux `include/uapi/linux/fuse.h` (little-endian).

use std::collections::BTreeMap;

use tracing::debug;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use super::backend::{
    DT_DIR, EBADF, EINVAL, ENODATA, ENOENT, ENOSYS, ENOTDIR, EROFS, FsBackend, FsMetadata,
    FsOpenOptions, FsResult, FsTimeUpdate, validate_name,
};

pub const FUSE_KERNEL_VERSION: u32 = 7;
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 31;
pub const FUSE_ROOT_ID: u64 = 1;

// FUSE opcodes (Linux include/uapi/linux/fuse.h).
pub const FUSE_LOOKUP: u32 = 1;
pub const FUSE_FORGET: u32 = 2;
pub const FUSE_GETATTR: u32 = 3;
pub const FUSE_SETATTR: u32 = 4;
pub const FUSE_READLINK: u32 = 5;
pub const FUSE_SYMLINK: u32 = 6;
pub const FUSE_MKDIR: u32 = 9;
pub const FUSE_UNLINK: u32 = 10;
pub const FUSE_RMDIR: u32 = 11;
pub const FUSE_RENAME: u32 = 12;
pub const FUSE_LINK: u32 = 13;
pub const FUSE_OPEN: u32 = 14;
pub const FUSE_READ: u32 = 15;
pub const FUSE_WRITE: u32 = 16;
pub const FUSE_STATFS: u32 = 17;
pub const FUSE_RELEASE: u32 = 18;
pub const FUSE_FSYNC: u32 = 20;
pub const FUSE_SETXATTR: u32 = 21;
pub const FUSE_GETXATTR: u32 = 22;
pub const FUSE_LISTXATTR: u32 = 23;
pub const FUSE_REMOVEXATTR: u32 = 24;
pub const FUSE_FLUSH: u32 = 25;
pub const FUSE_INIT: u32 = 26;
pub const FUSE_OPENDIR: u32 = 27;
pub const FUSE_READDIR: u32 = 28;
pub const FUSE_RELEASEDIR: u32 = 29;
pub const FUSE_FSYNCDIR: u32 = 30;
pub const FUSE_ACCESS: u32 = 34;
pub const FUSE_CREATE: u32 = 35;
pub const FUSE_DESTROY: u32 = 38;
pub const FUSE_BATCH_FORGET: u32 = 42;
pub const FUSE_READDIRPLUS: u32 = 44;
pub const FUSE_RENAME2: u32 = 45;
pub const FUSE_LSEEK: u32 = 46;
pub const FUSE_STATX: u32 = 52;

// FUSE_INIT capability flags.
pub const FUSE_ASYNC_READ: u32 = 1 << 0;
pub const FUSE_ATOMIC_O_TRUNC: u32 = 1 << 3;
pub const FUSE_BIG_WRITES: u32 = 1 << 5;
pub const FUSE_DO_READDIRPLUS: u32 = 1 << 13;
pub const FUSE_READDIRPLUS_AUTO: u32 = 1 << 14;
pub const FUSE_ASYNC_DIO: u32 = 1 << 15;
pub const FUSE_MAX_PAGES: u32 = 1 << 22;
pub const FUSE_EXPLICIT_INVAL_DATA: u32 = 1 << 25;

// FUSE_SETATTR valid masks.
pub const FATTR_MODE: u32 = 1 << 0;
pub const FATTR_UID: u32 = 1 << 1;
pub const FATTR_GID: u32 = 1 << 2;
pub const FATTR_SIZE: u32 = 1 << 3;
pub const FATTR_ATIME: u32 = 1 << 4;
pub const FATTR_MTIME: u32 = 1 << 5;
pub const FATTR_FH: u32 = 1 << 6;
pub const FATTR_ATIME_NOW: u32 = 1 << 7;
pub const FATTR_MTIME_NOW: u32 = 1 << 8;

// Linux open flags shared across x86-64 and aarch64.
const O_ACCMODE: u32 = 0o3;
const O_WRONLY: u32 = 0o1;
const O_RDWR: u32 = 0o2;
const O_CREAT: u32 = 0o100;
const O_EXCL: u32 = 0o200;
const O_TRUNC: u32 = 0o1000;
const RENAME_NOREPLACE: u32 = 1 << 0;
const W_OK: u32 = 2;

const MAX_WRITE_BYTES: u32 = 64 * 1024;
const MAX_PAGES: u16 = 32;

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseInHeader {
    pub len: u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub padding: u32,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseOutHeader {
    pub len: u32,
    pub error: i32,
    pub unique: u64,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseAttr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseKstatfs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
    pub padding: u32,
    pub spare: [u32; 6],
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseInitIn {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseInitOut {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub max_background: u16,
    pub congestion_threshold: u16,
    pub max_write: u32,
    pub time_gran: u32,
    pub max_pages: u16,
    pub map_alignment: u16,
    pub flags2: u32,
    pub unused: [u32; 7],
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseEntryOut {
    pub nodeid: u64,
    pub generation: u64,
    pub entry_valid: u64,
    pub attr_valid: u64,
    pub entry_valid_nsec: u32,
    pub attr_valid_nsec: u32,
    pub attr: FuseAttr,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseAttrOut {
    pub attr_valid: u64,
    pub attr_valid_nsec: u32,
    pub dummy: u32,
    pub attr: FuseAttr,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseGetattrIn {
    pub getattr_flags: u32,
    pub dummy: u32,
    pub fh: u64,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseSetattrIn {
    pub valid: u32,
    pub padding: u32,
    pub fh: u64,
    pub size: u64,
    pub lock_owner: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub unused4: u32,
    pub uid: u32,
    pub gid: u32,
    pub unused5: u32,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseOpenIn {
    pub flags: u32,
    pub open_flags: u32,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseOpenOut {
    pub fh: u64,
    pub open_flags: u32,
    pub padding: u32,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseCreateIn {
    pub flags: u32,
    pub mode: u32,
    pub umask: u32,
    pub open_flags: u32,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseMkdirIn {
    pub mode: u32,
    pub umask: u32,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseReadIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub read_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseWriteIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub write_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseWriteOut {
    pub size: u32,
    pub padding: u32,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseReleaseIn {
    pub fh: u64,
    pub flags: u32,
    pub release_flags: u32,
    pub lock_owner: u64,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseFlushIn {
    pub fh: u64,
    pub unused: u32,
    pub padding: u32,
    pub lock_owner: u64,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseFsyncIn {
    pub fh: u64,
    pub fsync_flags: u32,
    pub padding: u32,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseForgetIn {
    pub nlookup: u64,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseBatchForgetIn {
    pub count: u32,
    pub dummy: u32,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseForgetOne {
    pub nodeid: u64,
    pub nlookup: u64,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseRenameIn {
    pub newdir: u64,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseRename2In {
    pub newdir: u64,
    pub flags: u32,
    pub padding: u32,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseAccessIn {
    pub mask: u32,
    pub padding: u32,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseLinkIn {
    pub oldnodeid: u64,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseLseekIn {
    pub fh: u64,
    pub offset: u64,
    pub whence: u32,
    pub padding: u32,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseLseekOut {
    pub offset: u64,
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FuseDirent {
    pub ino: u64,
    pub off: u64,
    pub namelen: u32,
    pub typ: u32,
}

const _: () = {
    assert!(core::mem::size_of::<FuseInHeader>() == 40);
    assert!(core::mem::size_of::<FuseOutHeader>() == 16);
    assert!(core::mem::size_of::<FuseAttr>() == 88);
    assert!(core::mem::size_of::<FuseEntryOut>() == 128);
    assert!(core::mem::size_of::<FuseAttrOut>() == 104);
    assert!(core::mem::size_of::<FuseInitOut>() == 64);
    assert!(core::mem::size_of::<FuseKstatfs>() == 80);
    assert!(core::mem::size_of::<FuseDirent>() == 24);
};

struct InodeEntry {
    path: Vec<String>,
    lookup_count: u64,
    open_handles: u64,
}

struct OpenFile<H> {
    nodeid: u64,
    handle: H,
}

struct DirSnapshotEntry {
    name: String,
    d_type: u32,
    rel_path: Option<Vec<String>>,
}

struct OpenDir {
    nodeid: u64,
    entries: Vec<DirSnapshotEntry>,
}

/// Stateful FUSE 7.31 session driving an [`FsBackend`].
pub struct FuseSession<B: FsBackend> {
    backend: B,
    initialized: bool,
    next_inode: u64,
    next_fh: u64,
    inodes: BTreeMap<u64, InodeEntry>,
    path_to_inode: BTreeMap<Vec<String>, u64>,
    open_files: BTreeMap<u64, OpenFile<B::FileHandle>>,
    open_dirs: BTreeMap<u64, OpenDir>,
}

impl<B: FsBackend> FuseSession<B> {
    pub fn new(backend: B) -> Self {
        let mut inodes = BTreeMap::new();
        inodes.insert(
            FUSE_ROOT_ID,
            InodeEntry {
                path: Vec::new(),
                lookup_count: 1,
                open_handles: 0,
            },
        );
        let mut path_to_inode = BTreeMap::new();
        path_to_inode.insert(Vec::new(), FUSE_ROOT_ID);
        Self {
            backend,
            initialized: false,
            next_inode: FUSE_ROOT_ID + 1,
            next_fh: 1,
            inodes,
            path_to_inode,
            open_files: BTreeMap::new(),
            open_dirs: BTreeMap::new(),
        }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn reset(&mut self) {
        self.initialized = false;
        self.next_inode = FUSE_ROOT_ID + 1;
        self.next_fh = 1;
        self.inodes.clear();
        self.path_to_inode.clear();
        self.open_files.clear();
        self.open_dirs.clear();
        self.inodes.insert(
            FUSE_ROOT_ID,
            InodeEntry {
                path: Vec::new(),
                lookup_count: 1,
                open_handles: 0,
            },
        );
        self.path_to_inode.insert(Vec::new(), FUSE_ROOT_ID);
    }

    /// Number of tracked inodes (including root), exposed for unit tests.
    pub fn inode_count(&self) -> usize {
        self.inodes.len()
    }

    /// Dispatches one FUSE request buffer and returns `Some(reply_bytes)` or
    /// `None` for one-way operations (`FUSE_FORGET`, `FUSE_BATCH_FORGET`).
    pub async fn handle_request(&mut self, request: &[u8]) -> Option<Vec<u8>> {
        if request.len() < core::mem::size_of::<FuseInHeader>() {
            return Some(error_reply(0, EINVAL));
        }
        let header = FuseInHeader::read_from_bytes(&request[..40]).ok()?;
        let opcode = u32::from_le(header.opcode);
        let unique = u64::from_le(header.unique);
        let nodeid = u64::from_le(header.nodeid);
        let body = &request[40..];

        match opcode {
            FUSE_FORGET => {
                if let Ok(req) = FuseForgetIn::read_from_prefix(body).map(|(v, _)| v) {
                    self.forget_inode(nodeid, u64::from_le(req.nlookup));
                }
                return None;
            }
            FUSE_BATCH_FORGET => {
                if let Ok((batch, mut rest)) = FuseBatchForgetIn::read_from_prefix(body) {
                    let count = u32::from_le(batch.count) as usize;
                    for _ in 0..count {
                        let Ok((one, next)) = FuseForgetOne::read_from_prefix(rest) else {
                            break;
                        };
                        self.forget_inode(u64::from_le(one.nodeid), u64::from_le(one.nlookup));
                        rest = next;
                    }
                }
                return None;
            }
            _ => {}
        }

        let result: FsResult<Vec<u8>> = match opcode {
            FUSE_INIT => self.op_init(body),
            FUSE_DESTROY => {
                self.reset();
                Ok(Vec::new())
            }
            FUSE_LOOKUP => self.op_lookup(nodeid, body).await,
            FUSE_GETATTR => self.op_getattr(nodeid, body).await,
            FUSE_SETATTR => self.op_setattr(nodeid, body).await,
            FUSE_READLINK => self.op_readlink(nodeid).await,
            FUSE_SYMLINK => self.op_symlink(nodeid, body).await,
            FUSE_MKDIR => self.op_mkdir(nodeid, body).await,
            FUSE_UNLINK => self.op_unlink(nodeid, body).await,
            FUSE_RMDIR => self.op_rmdir(nodeid, body).await,
            FUSE_RENAME => self.op_rename(nodeid, body, false).await,
            FUSE_RENAME2 => self.op_rename(nodeid, body, true).await,
            FUSE_LINK => self.op_link(nodeid, body).await,
            FUSE_OPEN => self.op_open(nodeid, body).await,
            FUSE_READ => self.op_read(body).await,
            FUSE_WRITE => self.op_write(body).await,
            FUSE_STATFS => self.op_statfs(),
            FUSE_RELEASE => self.op_release(body),
            FUSE_FSYNC => self.op_fsync(body).await,
            FUSE_FLUSH => self.op_flush(body).await,
            FUSE_OPENDIR => self.op_opendir(nodeid).await,
            FUSE_READDIR => self.op_readdir(body, false).await,
            FUSE_READDIRPLUS => self.op_readdir(body, true).await,
            FUSE_RELEASEDIR => self.op_releasedir(body),
            FUSE_FSYNCDIR => Ok(Vec::new()),
            FUSE_ACCESS => self.op_access(nodeid, body).await,
            FUSE_CREATE => self.op_create(nodeid, body).await,
            FUSE_LSEEK => self.op_lseek(body).await,
            FUSE_GETXATTR => Err(ENODATA),
            FUSE_LISTXATTR | FUSE_SETXATTR | FUSE_REMOVEXATTR | FUSE_STATX => Err(ENOSYS),
            other => {
                debug!(opcode = other, unique, nodeid, "unsupported FUSE opcode");
                Err(ENOSYS)
            }
        };

        Some(match result {
            Ok(payload) => ok_reply(unique, &payload),
            Err(errno) => error_reply(unique, errno),
        })
    }

    fn inode_path(&self, nodeid: u64) -> FsResult<Vec<String>> {
        self.inodes
            .get(&nodeid)
            .map(|entry| entry.path.clone())
            .ok_or(ENOENT)
    }

    fn child_path(&self, parent: u64, name: &str) -> FsResult<Vec<String>> {
        validate_name(name)?;
        let mut path = self.inode_path(parent)?;
        path.push(name.to_owned());
        Ok(path)
    }

    fn intern_inode(&mut self, path: Vec<String>, add_lookup: u64) -> u64 {
        if let Some(&existing) = self.path_to_inode.get(&path) {
            if let Some(entry) = self.inodes.get_mut(&existing) {
                entry.lookup_count = entry.lookup_count.saturating_add(add_lookup);
            }
            return existing;
        }
        let id = self.next_inode;
        self.next_inode = self
            .next_inode
            .checked_add(1)
            .expect("inode space exhausted");
        self.path_to_inode.insert(path.clone(), id);
        self.inodes.insert(
            id,
            InodeEntry {
                path,
                lookup_count: add_lookup,
                open_handles: 0,
            },
        );
        id
    }

    fn forget_inode(&mut self, nodeid: u64, nlookup: u64) {
        if nodeid == FUSE_ROOT_ID {
            return;
        }
        let should_evict = if let Some(entry) = self.inodes.get_mut(&nodeid) {
            entry.lookup_count = entry.lookup_count.saturating_sub(nlookup);
            entry.lookup_count == 0 && entry.open_handles == 0
        } else {
            false
        };
        if should_evict
            && let Some(removed) = self.inodes.remove(&nodeid)
            && self.path_to_inode.get(&removed.path) == Some(&nodeid)
        {
            self.path_to_inode.remove(&removed.path);
        }
    }

    fn release_handle_ref(&mut self, nodeid: u64) {
        if nodeid == FUSE_ROOT_ID {
            return;
        }
        let should_evict = if let Some(entry) = self.inodes.get_mut(&nodeid) {
            entry.open_handles = entry.open_handles.saturating_sub(1);
            entry.lookup_count == 0 && entry.open_handles == 0
        } else {
            false
        };
        if should_evict
            && let Some(removed) = self.inodes.remove(&nodeid)
            && self.path_to_inode.get(&removed.path) == Some(&nodeid)
        {
            self.path_to_inode.remove(&removed.path);
        }
    }

    fn alloc_fh(&mut self) -> u64 {
        let fh = self.next_fh;
        self.next_fh = self.next_fh.checked_add(1).expect("file handle overflow");
        fh
    }

    fn op_init(&mut self, body: &[u8]) -> FsResult<Vec<u8>> {
        let (req, _) = FuseInitIn::read_from_prefix(body).map_err(|_| EINVAL)?;
        let major = u32::from_le(req.major);
        if major != FUSE_KERNEL_VERSION {
            return Err(EINVAL);
        }
        let client_minor = u32::from_le(req.minor);
        let client_flags = u32::from_le(req.flags);
        let supported = FUSE_ASYNC_READ
            | FUSE_ATOMIC_O_TRUNC
            | FUSE_BIG_WRITES
            | FUSE_DO_READDIRPLUS
            | FUSE_READDIRPLUS_AUTO
            | FUSE_ASYNC_DIO
            | FUSE_MAX_PAGES
            | FUSE_EXPLICIT_INVAL_DATA;
        let out = FuseInitOut {
            major: FUSE_KERNEL_VERSION.to_le(),
            minor: client_minor.min(FUSE_KERNEL_MINOR_VERSION).to_le(),
            max_readahead: req.max_readahead,
            flags: (client_flags & supported).to_le(),
            max_background: 16u16.to_le(),
            congestion_threshold: 12u16.to_le(),
            max_write: MAX_WRITE_BYTES.to_le(),
            time_gran: 1u32.to_le(),
            max_pages: MAX_PAGES.to_le(),
            map_alignment: 0,
            flags2: 0,
            unused: [0; 7],
        };
        self.initialized = true;
        Ok(out.as_bytes().to_vec())
    }

    async fn op_lookup(&mut self, parent: u64, body: &[u8]) -> FsResult<Vec<u8>> {
        let name = read_cstr(body)?;
        let path = self.child_path(parent, name)?;
        let meta = self.backend.stat(&path).await?;
        let nodeid = self.intern_inode(path, 1);
        Ok(entry_out(nodeid, meta).as_bytes().to_vec())
    }

    async fn op_getattr(&self, nodeid: u64, body: &[u8]) -> FsResult<Vec<u8>> {
        let meta = if let Ok((req, _)) = FuseGetattrIn::read_from_prefix(body)
            && (u32::from_le(req.getattr_flags) & 1 != 0)
            && let Some(open) = self.open_files.get(&u64::from_le(req.fh))
        {
            self.backend.stat_handle(&open.handle).await?
        } else {
            let path = self.inode_path(nodeid)?;
            self.backend.stat(&path).await?
        };
        Ok(attr_out(nodeid, meta).as_bytes().to_vec())
    }

    async fn op_setattr(&self, nodeid: u64, body: &[u8]) -> FsResult<Vec<u8>> {
        if self.backend.read_only() {
            return Err(EROFS);
        }
        let (req, _) = FuseSetattrIn::read_from_prefix(body).map_err(|_| EINVAL)?;
        let valid = u32::from_le(req.valid);
        let path = self.inode_path(nodeid)?;

        if valid & FATTR_SIZE != 0 {
            let new_size = u64::from_le(req.size);
            if valid & FATTR_FH != 0
                && let Some(open) = self.open_files.get(&u64::from_le(req.fh))
            {
                self.backend.set_size_handle(&open.handle, new_size).await?;
            } else {
                self.backend.set_size_path(&path, new_size).await?;
            }
        }
        if valid & FATTR_MODE != 0 {
            self.backend.set_mode(&path, u32::from_le(req.mode)).await?;
        }
        let atime = if valid & FATTR_ATIME_NOW != 0 {
            FsTimeUpdate::Now
        } else if valid & FATTR_ATIME != 0 {
            FsTimeUpdate::Set {
                secs: u64::from_le(req.atime),
                nsecs: u32::from_le(req.atimensec),
            }
        } else {
            FsTimeUpdate::Unchanged
        };
        let mtime = if valid & FATTR_MTIME_NOW != 0 {
            FsTimeUpdate::Now
        } else if valid & FATTR_MTIME != 0 {
            FsTimeUpdate::Set {
                secs: u64::from_le(req.mtime),
                nsecs: u32::from_le(req.mtimensec),
            }
        } else {
            FsTimeUpdate::Unchanged
        };
        if !matches!(atime, FsTimeUpdate::Unchanged) || !matches!(mtime, FsTimeUpdate::Unchanged) {
            self.backend.set_times(&path, atime, mtime).await?;
        }
        let _ = (valid & FATTR_UID, valid & FATTR_GID);

        let meta = if valid & FATTR_FH != 0
            && let Some(open) = self.open_files.get(&u64::from_le(req.fh))
        {
            self.backend.stat_handle(&open.handle).await?
        } else {
            self.backend.stat(&path).await?
        };
        Ok(attr_out(nodeid, meta).as_bytes().to_vec())
    }

    async fn op_readlink(&self, nodeid: u64) -> FsResult<Vec<u8>> {
        let path = self.inode_path(nodeid)?;
        let target = self.backend.readlink(&path).await?;
        Ok(target.into_bytes())
    }

    async fn op_symlink(&mut self, parent: u64, body: &[u8]) -> FsResult<Vec<u8>> {
        let (name, rest) = split_cstr(body)?;
        let target = read_cstr(rest)?;
        let path = self.child_path(parent, name)?;
        let meta = self.backend.symlink(&path, target).await?;
        let nodeid = self.intern_inode(path, 1);
        Ok(entry_out(nodeid, meta).as_bytes().to_vec())
    }

    async fn op_mkdir(&mut self, parent: u64, body: &[u8]) -> FsResult<Vec<u8>> {
        let (req, rest) = FuseMkdirIn::read_from_prefix(body).map_err(|_| EINVAL)?;
        let name = read_cstr(rest)?;
        let path = self.child_path(parent, name)?;
        let mode = u32::from_le(req.mode) & !u32::from_le(req.umask);
        let meta = self.backend.mkdir(&path, mode).await?;
        let nodeid = self.intern_inode(path, 1);
        Ok(entry_out(nodeid, meta).as_bytes().to_vec())
    }

    async fn op_unlink(&mut self, parent: u64, body: &[u8]) -> FsResult<Vec<u8>> {
        let name = read_cstr(body)?;
        let path = self.child_path(parent, name)?;
        self.backend.unlink(&path).await?;
        self.path_to_inode.remove(&path);
        Ok(Vec::new())
    }

    async fn op_rmdir(&mut self, parent: u64, body: &[u8]) -> FsResult<Vec<u8>> {
        let name = read_cstr(body)?;
        let path = self.child_path(parent, name)?;
        self.backend.rmdir(&path).await?;
        self.path_to_inode.remove(&path);
        Ok(Vec::new())
    }

    async fn op_rename(&mut self, parent: u64, body: &[u8], is_rename2: bool) -> FsResult<Vec<u8>> {
        let (newdir, flags, rest) = if is_rename2 {
            let (req, rest) = FuseRename2In::read_from_prefix(body).map_err(|_| EINVAL)?;
            (u64::from_le(req.newdir), u32::from_le(req.flags), rest)
        } else {
            let (req, rest) = FuseRenameIn::read_from_prefix(body).map_err(|_| EINVAL)?;
            (u64::from_le(req.newdir), 0, rest)
        };
        if flags & !RENAME_NOREPLACE != 0 {
            return Err(EINVAL);
        }
        let (old_name, rest) = split_cstr(rest)?;
        let new_name = read_cstr(rest)?;
        let old_path = self.child_path(parent, old_name)?;
        let new_path = self.child_path(newdir, new_name)?;
        self.backend
            .rename(&old_path, &new_path, flags & RENAME_NOREPLACE != 0)
            .await?;

        // Detach any overwritten target path entry, then rewrite moved inode and descendants.
        self.path_to_inode.remove(&new_path);
        let moved: Vec<(u64, Vec<String>, Vec<String>)> = self
            .inodes
            .iter()
            .filter_map(|(&id, entry)| {
                if entry.path.starts_with(&old_path) {
                    let mut updated = new_path.clone();
                    updated.extend_from_slice(&entry.path[old_path.len()..]);
                    Some((id, entry.path.clone(), updated))
                } else {
                    None
                }
            })
            .collect();
        for (id, prev, updated) in moved {
            if self.path_to_inode.get(&prev) == Some(&id) {
                self.path_to_inode.remove(&prev);
            }
            if let Some(entry) = self.inodes.get_mut(&id) {
                entry.path = updated.clone();
            }
            self.path_to_inode.insert(updated, id);
        }
        Ok(Vec::new())
    }

    async fn op_link(&mut self, new_parent: u64, body: &[u8]) -> FsResult<Vec<u8>> {
        let (req, rest) = FuseLinkIn::read_from_prefix(body).map_err(|_| EINVAL)?;
        let name = read_cstr(rest)?;
        let old_path = self.inode_path(u64::from_le(req.oldnodeid))?;
        let new_path = self.child_path(new_parent, name)?;
        let meta = self.backend.link(&old_path, &new_path).await?;
        let nodeid = self.intern_inode(new_path, 1);
        Ok(entry_out(nodeid, meta).as_bytes().to_vec())
    }

    async fn op_open(&mut self, nodeid: u64, body: &[u8]) -> FsResult<Vec<u8>> {
        let (req, _) = FuseOpenIn::read_from_prefix(body).map_err(|_| EINVAL)?;
        let path = self.inode_path(nodeid)?;
        let options = open_options_from_flags(u32::from_le(req.flags), 0);
        let (handle, _) = self.backend.open_file(&path, options).await?;
        let fh = self.alloc_fh();
        if let Some(entry) = self.inodes.get_mut(&nodeid) {
            entry.open_handles = entry.open_handles.saturating_add(1);
        }
        self.open_files.insert(fh, OpenFile { nodeid, handle });
        let out = FuseOpenOut {
            fh: fh.to_le(),
            open_flags: 0,
            padding: 0,
        };
        Ok(out.as_bytes().to_vec())
    }

    async fn op_create(&mut self, parent: u64, body: &[u8]) -> FsResult<Vec<u8>> {
        let (req, rest) = FuseCreateIn::read_from_prefix(body).map_err(|_| EINVAL)?;
        let name = read_cstr(rest)?;
        let path = self.child_path(parent, name)?;
        let mode = u32::from_le(req.mode) & !u32::from_le(req.umask);
        let mut options = open_options_from_flags(u32::from_le(req.flags) | O_CREAT, mode);
        options.write = true;
        let (handle, meta) = self.backend.open_file(&path, options).await?;
        let nodeid = self.intern_inode(path, 1);
        let fh = self.alloc_fh();
        if let Some(entry) = self.inodes.get_mut(&nodeid) {
            entry.open_handles = entry.open_handles.saturating_add(1);
        }
        self.open_files.insert(fh, OpenFile { nodeid, handle });
        let entry = entry_out(nodeid, meta);
        let open = FuseOpenOut {
            fh: fh.to_le(),
            open_flags: 0,
            padding: 0,
        };
        let mut out = Vec::with_capacity(
            core::mem::size_of::<FuseEntryOut>() + core::mem::size_of::<FuseOpenOut>(),
        );
        out.extend_from_slice(entry.as_bytes());
        out.extend_from_slice(open.as_bytes());
        Ok(out)
    }

    async fn op_read(&self, body: &[u8]) -> FsResult<Vec<u8>> {
        let (req, _) = FuseReadIn::read_from_prefix(body).map_err(|_| EINVAL)?;
        let open = self.open_files.get(&u64::from_le(req.fh)).ok_or(EBADF)?;
        self.backend
            .read_file(
                &open.handle,
                u64::from_le(req.offset),
                u32::from_le(req.size),
            )
            .await
    }

    async fn op_write(&self, body: &[u8]) -> FsResult<Vec<u8>> {
        let (req, data) = FuseWriteIn::read_from_prefix(body).map_err(|_| EINVAL)?;
        let open = self.open_files.get(&u64::from_le(req.fh)).ok_or(EBADF)?;
        let declared = u32::from_le(req.size) as usize;
        if data.len() < declared {
            return Err(EINVAL);
        }
        let written = self
            .backend
            .write_file(&open.handle, u64::from_le(req.offset), &data[..declared])
            .await?;
        let out = FuseWriteOut {
            size: written.to_le(),
            padding: 0,
        };
        Ok(out.as_bytes().to_vec())
    }

    fn op_release(&mut self, body: &[u8]) -> FsResult<Vec<u8>> {
        let (req, _) = FuseReleaseIn::read_from_prefix(body).map_err(|_| EINVAL)?;
        if let Some(open) = self.open_files.remove(&u64::from_le(req.fh)) {
            drop(open.handle);
            self.release_handle_ref(open.nodeid);
        }
        Ok(Vec::new())
    }

    async fn op_flush(&self, body: &[u8]) -> FsResult<Vec<u8>> {
        let (req, _) = FuseFlushIn::read_from_prefix(body).map_err(|_| EINVAL)?;
        if let Some(open) = self.open_files.get(&u64::from_le(req.fh)) {
            self.backend.flush_file(&open.handle).await?;
        }
        Ok(Vec::new())
    }

    async fn op_fsync(&self, body: &[u8]) -> FsResult<Vec<u8>> {
        let (req, _) = FuseFsyncIn::read_from_prefix(body).map_err(|_| EINVAL)?;
        let open = self.open_files.get(&u64::from_le(req.fh)).ok_or(EBADF)?;
        self.backend.flush_file(&open.handle).await?;
        Ok(Vec::new())
    }

    async fn op_opendir(&mut self, nodeid: u64) -> FsResult<Vec<u8>> {
        let path = self.inode_path(nodeid)?;
        let meta = self.backend.stat(&path).await?;
        if !meta.is_dir() {
            return Err(ENOTDIR);
        }
        let entries = self.snapshot_dir(&path).await?;
        let fh = self.alloc_fh();
        if let Some(entry) = self.inodes.get_mut(&nodeid) {
            entry.open_handles = entry.open_handles.saturating_add(1);
        }
        self.open_dirs.insert(fh, OpenDir { nodeid, entries });
        let out = FuseOpenOut {
            fh: fh.to_le(),
            open_flags: 0,
            padding: 0,
        };
        Ok(out.as_bytes().to_vec())
    }

    async fn snapshot_dir(&self, path: &[String]) -> FsResult<Vec<DirSnapshotEntry>> {
        let raw_entries = self.backend.read_dir(path).await?;
        let mut list = Vec::with_capacity(raw_entries.len() + 2);
        list.push(DirSnapshotEntry {
            name: ".".to_owned(),
            d_type: DT_DIR,
            rel_path: None,
        });
        list.push(DirSnapshotEntry {
            name: "..".to_owned(),
            d_type: DT_DIR,
            rel_path: None,
        });
        for entry in raw_entries {
            if validate_name(&entry.name).is_err() {
                continue;
            }
            let mut child = path.to_vec();
            child.push(entry.name.clone());
            list.push(DirSnapshotEntry {
                name: entry.name,
                d_type: entry.d_type,
                rel_path: Some(child),
            });
        }
        Ok(list)
    }

    async fn op_readdir(&mut self, body: &[u8], plus: bool) -> FsResult<Vec<u8>> {
        let (req, _) = FuseReadIn::read_from_prefix(body).map_err(|_| EINVAL)?;
        let fh = u64::from_le(req.fh);
        let offset = u64::from_le(req.offset) as usize;
        let max_bytes = u32::from_le(req.size) as usize;

        let dir_nodeid = self.open_dirs.get(&fh).ok_or(EBADF)?.nodeid;
        // Re-snapshot when guest rewinds to offset 0 so fresh mutations appear.
        if offset == 0 {
            let dir_path = self.inode_path(dir_nodeid)?;
            let fresh = self.snapshot_dir(&dir_path).await?;
            if let Some(dir) = self.open_dirs.get_mut(&fh) {
                dir.entries = fresh;
            }
        }

        let parent_nodeid = {
            let dir_path = self.inode_path(dir_nodeid)?;
            if dir_path.is_empty() {
                FUSE_ROOT_ID
            } else {
                let parent_path = &dir_path[..dir_path.len() - 1];
                self.path_to_inode
                    .get(parent_path)
                    .copied()
                    .unwrap_or(FUSE_ROOT_ID)
            }
        };

        let snapshot: Vec<(String, u32, Option<Vec<String>>)> = {
            let dir = self.open_dirs.get(&fh).ok_or(EBADF)?;
            if offset >= dir.entries.len() {
                return Ok(Vec::new());
            }
            dir.entries[offset..]
                .iter()
                .map(|e| (e.name.clone(), e.d_type, e.rel_path.clone()))
                .collect()
        };

        let mut out = Vec::new();
        for (rel_idx, (name, d_type, rel_path)) in snapshot.into_iter().enumerate() {
            let name_bytes = name.as_bytes();
            let header_len = if plus {
                core::mem::size_of::<FuseEntryOut>() + core::mem::size_of::<FuseDirent>()
            } else {
                core::mem::size_of::<FuseDirent>()
            };
            let padded_len = (header_len + name_bytes.len() + 7) & !7;
            if out.len() + padded_len > max_bytes {
                break;
            }
            let next_off = (offset + rel_idx + 1) as u64;
            if plus {
                let (entry, dirent_ino) = if let Some(child_path) = rel_path {
                    let Ok(meta) = self.backend.stat(&child_path).await else {
                        continue;
                    };
                    let child_id = self.intern_inode(child_path, 1);
                    (entry_out(child_id, meta), child_id)
                } else {
                    // Per Linux FUSE spec, `.` and `..` carry `nodeid = 0` in READDIRPLUS
                    // so the guest kernel does not take a lookup reference on them.
                    let ino = if name == "." {
                        dir_nodeid
                    } else {
                        parent_nodeid
                    };
                    (FuseEntryOut::default(), ino)
                };
                out.extend_from_slice(entry.as_bytes());
                let dirent = FuseDirent {
                    ino: dirent_ino.to_le(),
                    off: next_off.to_le(),
                    namelen: (name_bytes.len() as u32).to_le(),
                    typ: d_type.to_le(),
                };
                out.extend_from_slice(dirent.as_bytes());
            } else {
                let ino = if let Some(child_path) = rel_path {
                    self.intern_inode(child_path, 0)
                } else if name == "." {
                    dir_nodeid
                } else {
                    parent_nodeid
                };
                let dirent = FuseDirent {
                    ino: ino.to_le(),
                    off: next_off.to_le(),
                    namelen: (name_bytes.len() as u32).to_le(),
                    typ: d_type.to_le(),
                };
                out.extend_from_slice(dirent.as_bytes());
            }
            out.extend_from_slice(name_bytes);
            let pad = padded_len - (header_len + name_bytes.len());
            out.resize(out.len() + pad, 0);
        }
        Ok(out)
    }

    fn op_releasedir(&mut self, body: &[u8]) -> FsResult<Vec<u8>> {
        let (req, _) = FuseReleaseIn::read_from_prefix(body).map_err(|_| EINVAL)?;
        if let Some(dir) = self.open_dirs.remove(&u64::from_le(req.fh)) {
            self.release_handle_ref(dir.nodeid);
        }
        Ok(Vec::new())
    }

    async fn op_access(&self, nodeid: u64, body: &[u8]) -> FsResult<Vec<u8>> {
        let (req, _) = FuseAccessIn::read_from_prefix(body).map_err(|_| EINVAL)?;
        let path = self.inode_path(nodeid)?;
        let _ = self.backend.stat(&path).await?;
        if self.backend.read_only() && (u32::from_le(req.mask) & W_OK != 0) {
            return Err(EROFS);
        }
        Ok(Vec::new())
    }

    fn op_statfs(&self) -> FsResult<Vec<u8>> {
        let st = FuseKstatfs {
            blocks: (1u64 << 24).to_le(),
            bfree: (1u64 << 23).to_le(),
            bavail: (1u64 << 23).to_le(),
            files: (1u64 << 20).to_le(),
            ffree: (1u64 << 19).to_le(),
            bsize: 4096u32.to_le(),
            namelen: 255u32.to_le(),
            frsize: 4096u32.to_le(),
            padding: 0,
            spare: [0; 6],
        };
        Ok(st.as_bytes().to_vec())
    }

    async fn op_lseek(&self, body: &[u8]) -> FsResult<Vec<u8>> {
        let (req, _) = FuseLseekIn::read_from_prefix(body).map_err(|_| EINVAL)?;
        let open = self.open_files.get(&u64::from_le(req.fh)).ok_or(EBADF)?;
        let size = self.backend.stat_handle(&open.handle).await?.size;
        let offset = u64::from_le(req.offset);
        let result = match u32::from_le(req.whence) {
            3 => {
                // SEEK_DATA
                if offset >= size {
                    return Err(super::backend::ENODATA);
                }
                offset
            }
            4 => {
                // SEEK_HOLE
                if offset >= size {
                    return Err(super::backend::ENODATA);
                }
                size
            }
            _ => return Err(EINVAL),
        };
        let out = FuseLseekOut {
            offset: result.to_le(),
        };
        Ok(out.as_bytes().to_vec())
    }
}

fn open_options_from_flags(flags: u32, mode: u32) -> FsOpenOptions {
    let acc = flags & O_ACCMODE;
    let write = acc == O_WRONLY || acc == O_RDWR;
    let read = acc != O_WRONLY;
    FsOpenOptions {
        read,
        write,
        create: flags & O_CREAT != 0,
        exclusive: flags & O_EXCL != 0,
        truncate: flags & O_TRUNC != 0,
        mode,
    }
}

fn make_attr(nodeid: u64, meta: FsMetadata) -> FuseAttr {
    FuseAttr {
        ino: nodeid.to_le(),
        size: meta.size.to_le(),
        blocks: meta.size.div_ceil(512).to_le(),
        atime: meta.atime_sec.to_le(),
        mtime: meta.mtime_sec.to_le(),
        ctime: meta.ctime_sec.to_le(),
        atimensec: meta.atime_nsec.to_le(),
        mtimensec: meta.mtime_nsec.to_le(),
        ctimensec: meta.ctime_nsec.to_le(),
        mode: meta.mode.to_le(),
        nlink: meta.nlink.to_le(),
        uid: meta.uid.to_le(),
        gid: meta.gid.to_le(),
        rdev: 0,
        blksize: 4096u32.to_le(),
        flags: 0,
    }
}

fn entry_out(nodeid: u64, meta: FsMetadata) -> FuseEntryOut {
    FuseEntryOut {
        nodeid: nodeid.to_le(),
        generation: 0,
        entry_valid: 1u64.to_le(),
        attr_valid: 1u64.to_le(),
        entry_valid_nsec: 0,
        attr_valid_nsec: 0,
        attr: make_attr(nodeid, meta),
    }
}

fn attr_out(nodeid: u64, meta: FsMetadata) -> FuseAttrOut {
    FuseAttrOut {
        attr_valid: 1u64.to_le(),
        attr_valid_nsec: 0,
        dummy: 0,
        attr: make_attr(nodeid, meta),
    }
}

fn read_cstr(bytes: &[u8]) -> FsResult<&str> {
    let nul = bytes.iter().position(|&b| b == 0).ok_or(EINVAL)?;
    core::str::from_utf8(&bytes[..nul]).map_err(|_| EINVAL)
}

fn split_cstr(bytes: &[u8]) -> FsResult<(&str, &[u8])> {
    let nul = bytes.iter().position(|&b| b == 0).ok_or(EINVAL)?;
    let s = core::str::from_utf8(&bytes[..nul]).map_err(|_| EINVAL)?;
    Ok((s, &bytes[nul + 1..]))
}

fn ok_reply(unique: u64, payload: &[u8]) -> Vec<u8> {
    let total = (core::mem::size_of::<FuseOutHeader>() + payload.len()) as u32;
    let header = FuseOutHeader {
        len: total.to_le(),
        error: 0,
        unique: unique.to_le(),
    };
    let mut out = Vec::with_capacity(total as usize);
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(payload);
    out
}

fn error_reply(unique: u64, errno: i32) -> Vec<u8> {
    let header = FuseOutHeader {
        len: (core::mem::size_of::<FuseOutHeader>() as u32).to_le(),
        error: (-errno).to_le(),
        unique: unique.to_le(),
    };
    header.as_bytes().to_vec()
}
