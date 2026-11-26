//! File, path, directory, metadata, and descriptor I/O system calls.
//!
//! All path operations resolve strictly within the process's container root
//! and working directory through [`Filesystem`]; all open file descriptions
//! share offsets and status flags via [`helios_unix::OpenFile`] and
//! [`helios_unix::FileDescriptorEntry`].

use super::*;
use alloc::string::String;
use alloc::vec::Vec;
use helios_hal::fs::{FsError, Landed, NodeKind, RenameMode, WritePosition};
use helios_unix::{
    FDFLAG_APPEND, FDFLAG_DIRECT, FDFLAG_DSYNC, FDFLAG_NOATIME, FDFLAG_NONBLOCK, FDFLAG_PATH,
    FDFLAG_SYNC, OpenFile,
};

// Linux UAPI constants (`include/uapi/linux/fcntl.h`, `limits.h`, `stat.h`, `fs.h`).
pub const AT_FDCWD: i32 = -100;
pub const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
pub const AT_REMOVEDIR: u64 = 0x200;
pub const AT_EACCESS: u64 = 0x200;
pub const AT_SYMLINK_FOLLOW: u64 = 0x400;
pub const AT_NO_AUTOMOUNT: u64 = 0x800;
pub const AT_EMPTY_PATH: u64 = 0x1000;
pub const AT_STATX_SYNC_TYPE: u64 = 0x6000;

pub const O_ACCMODE: u64 = 0x3;
pub const O_RDONLY: u64 = 0;
pub const O_WRONLY: u64 = 1;
pub const O_RDWR: u64 = 2;
pub const O_CREAT: u64 = 1 << 6;
pub const O_EXCL: u64 = 1 << 7;
pub const O_TRUNC: u64 = 1 << 9;
pub const O_APPEND: u64 = 1 << 10;
pub const O_NONBLOCK: u64 = 1 << 11;
pub const O_DSYNC: u64 = 1 << 12;
pub const O_NOATIME: u64 = 1 << 18;
pub const O_CLOEXEC: u64 = 1 << 19;
pub const O_SYNC_BIT: u64 = 1 << 20;
pub const O_SYNC: u64 = O_SYNC_BIT | O_DSYNC;
pub const O_PATH: u64 = 1 << 21;

// Linux `include/uapi/linux/fs.h` RENAME_* flags.
const RENAME_NOREPLACE: u64 = 1 << 0;
const RENAME_EXCHANGE: u64 = 1 << 1;

// Linux `include/uapi/linux/fs.h` RWF_* flags for preadv2/pwritev2.
const RWF_HIPRI: u64 = 0x01;
const RWF_DSYNC: u64 = 0x02;
const RWF_SYNC: u64 = 0x04;
const RWF_NOWAIT: u64 = 0x08;
const RWF_APPEND: u64 = 0x10;

// Linux `include/uapi/linux/close_range.h`.
const CLOSE_RANGE_UNSHARE: u64 = 1 << 1;
const CLOSE_RANGE_CLOEXEC: u64 = 1 << 2;

// Linux `include/uapi/linux/stat.h` special utimensat tv_nsec values.
const UTIME_NOW: i64 = (1 << 30) - 1;
const UTIME_OMIT: i64 = (1 << 30) - 2;

// Linux `include/uapi/linux/stat.h` STATX_* masks.
const STATX_BASIC_STATS: u32 = 0x07ff;

// Linux `include/uapi/linux/limits.h`.
const PATH_MAX: usize = 4096;

// Linux `include/uapi/asm-generic/errno-base.h` and `errno.h`.
const ENOENT: u64 = 2;
const ENXIO: u64 = 6;
const E2BIG: u64 = 7;
const EBUSY: u64 = 16;
const EEXIST: u64 = 17;
const EXDEV: u64 = 18;
const ENOTDIR: u64 = 20;
const EISDIR: u64 = 21;
const ENOSPC: u64 = 28;
const ESPIPE: u64 = 29;
const EROFS: u64 = 30;
const ERANGE: u64 = 34;
const ENAMETOOLONG: u64 = 36;
const ENOTEMPTY: u64 = 39;
const ELOOP: u64 = 40;
const ENODATA: u64 = 61;
const EOVERFLOW: u64 = 75;
const EILSEQ: u64 = 84;

// Linux `include/uapi/linux/xattr.h`.
const XATTR_CREATE: u64 = 0x1;
const XATTR_REPLACE: u64 = 0x2;

/// Typed filesystem syscall error preserving Linux's distinction between
/// `EACCES` (`FsError::NotPermitted`), `EPERM` (`PermissionDenied`),
/// `ENODATA` (`NoData`), `ERANGE` (`Range`), `E2BIG` (`ArgTooBig`), and
/// `ENXIO` (`NoDevice`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FsOpError {
    #[error(transparent)]
    Fs(#[from] FsError),
    #[error("operation not permitted")]
    PermissionDenied,
    #[error("no data available")]
    NoData,
    #[error("result too large")]
    Range,
    #[error("argument list or value too long")]
    ArgTooBig,
    #[error("no such device or address")]
    NoDevice,
}

/// Creation/replacement mode for `setxattr` (`include/uapi/linux/xattr.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XattrSetMode {
    CreateOrReplace,
    Create,
    Replace,
}

// Linux `fs/readdir.c` / `include/linux/fs.h` d_type values.
const DT_UNKNOWN: u8 = 0;
const DT_FIFO: u8 = 1;
const DT_CHR: u8 = 2;
const DT_DIR: u8 = 4;
const DT_BLK: u8 = 6;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;
const DT_SOCK: u8 = 12;

/// Access mode an open file descriptor was created with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileAccess {
    ReadOnly,
    WriteOnly,
    ReadWrite,
    PathOnly,
}

impl FileAccess {
    pub const fn readable(self) -> bool {
        matches!(self, Self::ReadOnly | Self::ReadWrite)
    }

    pub const fn writable(self) -> bool {
        matches!(self, Self::WriteOnly | Self::ReadWrite)
    }

    pub const fn linux_accmode(self) -> u64 {
        match self {
            Self::ReadOnly | Self::PathOnly => O_RDONLY,
            Self::WriteOnly => O_WRONLY,
            Self::ReadWrite => O_RDWR,
        }
    }
}

/// Permission bits checked by [`Filesystem::access_path`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessCheck {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    pub follow: bool,
    /// `true` when `AT_EACCESS` is set (`faccessat2`); `false` checks real IDs
    /// (`fs/open.c` `do_faccessat`).
    pub use_effective: bool,
}

/// Options for [`Filesystem::link`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkOptions {
    pub follow: bool,
    pub empty_path: bool,
}

/// Decoded flags for [`Filesystem::open`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenRequest {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub exclusive: bool,
    pub truncate: bool,
    pub directory: bool,
    pub nofollow: bool,
    pub path_only: bool,
    pub append: bool,
    pub sync: bool,
    pub dsync: bool,
    /// Raw creation permissions (`mode & 0o7777`) before applying `umask`.
    pub mode: u32,
    /// Calling process's `umask` (`0o777`), skipped when the parent directory
    /// carries a POSIX default ACL (`fs/posix_acl.c` `posix_acl_create`).
    pub umask: u32,
}

/// Timestamp update for `utimensat`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeUpdate {
    Omit,
    Now,
    Set(u64),
}

/// One entry returned by [`Filesystem::list_dir`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirListEntry {
    pub name: String,
    pub kind: NodeKind,
    pub inode: u64,
}

/// Container-visible file metadata for `stat` / `fstat` / `lstat` / `newfstatat` / `statx`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileStat {
    pub dev: u64,
    pub ino: u64,
    pub kind: NodeKind,
    pub permissions: u32,
    pub nlink: u64,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    pub size: u64,
    pub access_nanos: u64,
    pub modified_nanos: u64,
    pub status_nanos: u64,
}

impl FileStat {
    pub const fn file_type_bits(kind: NodeKind) -> u32 {
        match kind {
            NodeKind::Fifo => 0o010_000,
            NodeKind::CharacterDevice => 0o020_000,
            NodeKind::Directory => 0o040_000,
            NodeKind::BlockDevice => 0o060_000,
            NodeKind::File => 0o100_000,
            NodeKind::Symlink => 0o120_000,
            NodeKind::Socket => 0o140_000,
        }
    }

    pub const fn mode(self) -> u32 {
        Self::file_type_bits(self.kind) | (self.permissions & 0o7777)
    }

    fn split_nanos(nanos: u64) -> (i64, i64) {
        (
            (nanos / 1_000_000_000) as i64,
            (nanos % 1_000_000_000) as i64,
        )
    }

    /// Encodes `struct stat` for `abi` (`arch/x86/include/uapi/asm/stat.h` 144 B;
    /// `include/uapi/asm-generic/stat.h` 128 B). Returns byte length written.
    pub fn write_stat(self, abi: Abi, out: &mut [u8; 144]) -> usize {
        out.fill(0);
        let mode = self.mode();
        let blocks = self.size.div_ceil(512) as i64;
        let (asec, ansec) = Self::split_nanos(self.access_nanos);
        let (msec, mnsec) = Self::split_nanos(self.modified_nanos);
        let (csec, cnsec) = Self::split_nanos(self.status_nanos);
        match abi {
            Abi::X86_64 => {
                out[0..8].copy_from_slice(&self.dev.to_le_bytes());
                out[8..16].copy_from_slice(&self.ino.to_le_bytes());
                out[16..24].copy_from_slice(&self.nlink.to_le_bytes());
                out[24..28].copy_from_slice(&mode.to_le_bytes());
                out[28..32].copy_from_slice(&self.uid.to_le_bytes());
                out[32..36].copy_from_slice(&self.gid.to_le_bytes());
                out[40..48].copy_from_slice(&self.rdev.to_le_bytes());
                out[48..56].copy_from_slice(&(self.size as i64).to_le_bytes());
                out[56..64].copy_from_slice(&4096_i64.to_le_bytes());
                out[64..72].copy_from_slice(&blocks.to_le_bytes());
                out[72..80].copy_from_slice(&asec.to_le_bytes());
                out[80..88].copy_from_slice(&ansec.to_le_bytes());
                out[88..96].copy_from_slice(&msec.to_le_bytes());
                out[96..104].copy_from_slice(&mnsec.to_le_bytes());
                out[104..112].copy_from_slice(&csec.to_le_bytes());
                out[112..120].copy_from_slice(&cnsec.to_le_bytes());
                144
            }
            Abi::Aarch64 => {
                out[0..8].copy_from_slice(&self.dev.to_le_bytes());
                out[8..16].copy_from_slice(&self.ino.to_le_bytes());
                out[16..20].copy_from_slice(&mode.to_le_bytes());
                out[20..24].copy_from_slice(&(self.nlink as u32).to_le_bytes());
                out[24..28].copy_from_slice(&self.uid.to_le_bytes());
                out[28..32].copy_from_slice(&self.gid.to_le_bytes());
                out[32..40].copy_from_slice(&self.rdev.to_le_bytes());
                out[48..56].copy_from_slice(&(self.size as i64).to_le_bytes());
                out[56..60].copy_from_slice(&4096_i32.to_le_bytes());
                out[64..72].copy_from_slice(&blocks.to_le_bytes());
                out[72..80].copy_from_slice(&asec.to_le_bytes());
                out[80..88].copy_from_slice(&ansec.to_le_bytes());
                out[88..96].copy_from_slice(&msec.to_le_bytes());
                out[96..104].copy_from_slice(&mnsec.to_le_bytes());
                out[104..112].copy_from_slice(&csec.to_le_bytes());
                out[112..120].copy_from_slice(&cnsec.to_le_bytes());
                128
            }
        }
    }

    /// Encodes Linux `struct statx` (`include/uapi/linux/stat.h`, 256 bytes,
    /// identical on x86-64 and aarch64).
    pub fn write_statx(self) -> [u8; 256] {
        let mut out = [0u8; 256];
        let mode = self.mode() as u16;
        let blocks = self.size.div_ceil(512);
        let (asec, ansec) = Self::split_nanos(self.access_nanos);
        let (msec, mnsec) = Self::split_nanos(self.modified_nanos);
        let (csec, cnsec) = Self::split_nanos(self.status_nanos);
        let dev_major = ((self.dev >> 8) & 0xfff) as u32 | (((self.dev >> 32) & !0xfff) as u32);
        let dev_minor = (self.dev & 0xff) as u32 | (((self.dev >> 12) & !0xff) as u32);
        let rdev_major = ((self.rdev >> 8) & 0xfff) as u32 | (((self.rdev >> 32) & !0xfff) as u32);
        let rdev_minor = (self.rdev & 0xff) as u32 | (((self.rdev >> 12) & !0xff) as u32);

        out[0..4].copy_from_slice(&STATX_BASIC_STATS.to_le_bytes());
        out[4..8].copy_from_slice(&4096_u32.to_le_bytes());
        out[16..20].copy_from_slice(&(self.nlink as u32).to_le_bytes());
        out[20..24].copy_from_slice(&self.uid.to_le_bytes());
        out[24..28].copy_from_slice(&self.gid.to_le_bytes());
        out[28..30].copy_from_slice(&mode.to_le_bytes());
        out[32..40].copy_from_slice(&self.ino.to_le_bytes());
        out[40..48].copy_from_slice(&self.size.to_le_bytes());
        out[48..56].copy_from_slice(&blocks.to_le_bytes());
        // stx_atime (64..80)
        out[64..72].copy_from_slice(&asec.to_le_bytes());
        out[72..76].copy_from_slice(&(ansec as u32).to_le_bytes());
        // stx_ctime (96..112)
        out[96..104].copy_from_slice(&csec.to_le_bytes());
        out[104..108].copy_from_slice(&(cnsec as u32).to_le_bytes());
        // stx_mtime (112..128)
        out[112..120].copy_from_slice(&msec.to_le_bytes());
        out[120..124].copy_from_slice(&(mnsec as u32).to_le_bytes());
        // stx_rdev / stx_dev (128..144)
        out[128..132].copy_from_slice(&rdev_major.to_le_bytes());
        out[132..136].copy_from_slice(&rdev_minor.to_le_bytes());
        out[136..140].copy_from_slice(&dev_major.to_le_bytes());
        out[140..144].copy_from_slice(&dev_minor.to_le_bytes());
        out
    }
}

// Linux UAPI `include/uapi/linux/magic.h` filesystem magic numbers.
pub const BTRFS_SUPER_MAGIC: i64 = 0x9123_683e;
pub const TMPFS_MAGIC: i64 = 0x0102_1994;
pub const EROFS_SUPER_MAGIC_V1: i64 = 0xe0f5_e1e2;
pub const V9FS_MAGIC: i64 = 0x0102_1997;
pub const OVERLAYFS_SUPER_MAGIC: i64 = 0x794c_7630;
pub const PROC_SUPER_MAGIC: i64 = 0x9fa0;
pub const SYSFS_MAGIC: i64 = 0x6265_6572;
pub const PIPEFS_MAGIC: i64 = 0x5049_5045;
pub const SOCKFS_MAGIC: i64 = 0x534f_434b;
pub const ANON_INODE_FS_MAGIC: i64 = 0x0904_1934;

// Linux UAPI `include/linux/statfs.h` `ST_*` mount flags.
pub const ST_RDONLY: i64 = 0x0001;
pub const ST_NOSUID: i64 = 0x0002;
pub const ST_NODEV: i64 = 0x0004;
pub const ST_NOEXEC: i64 = 0x0008;
pub const ST_VALID: i64 = 0x0020;

/// Filesystem statistics for `statfs(2)` / `fstatfs(2)`
/// (`include/uapi/asm-generic/statfs.h` LP64 `struct statfs`, 120 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsStat {
    pub f_type: i64,
    pub f_bsize: i64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_fsid: [i32; 2],
    pub f_namelen: i64,
    pub f_frsize: i64,
    pub f_flags: i64,
}

impl FsStat {
    pub const fn synthetic_virtual(f_type: i64) -> Self {
        Self {
            f_type,
            f_bsize: 4096,
            f_blocks: 0,
            f_bfree: 0,
            f_bavail: 0,
            f_files: 0,
            f_ffree: 0,
            f_fsid: [0, 0],
            f_namelen: 255,
            f_frsize: 4096,
            f_flags: ST_VALID,
        }
    }

    /// Encodes LP64 `struct statfs` (120 bytes, identical on x86-64 and aarch64).
    pub fn write_statfs(self) -> [u8; 120] {
        let mut out = [0u8; 120];
        out[0..8].copy_from_slice(&self.f_type.to_le_bytes());
        out[8..16].copy_from_slice(&self.f_bsize.to_le_bytes());
        out[16..24].copy_from_slice(&self.f_blocks.to_le_bytes());
        out[24..32].copy_from_slice(&self.f_bfree.to_le_bytes());
        out[32..40].copy_from_slice(&self.f_bavail.to_le_bytes());
        out[40..48].copy_from_slice(&self.f_files.to_le_bytes());
        out[48..56].copy_from_slice(&self.f_ffree.to_le_bytes());
        out[56..60].copy_from_slice(&self.f_fsid[0].to_le_bytes());
        out[60..64].copy_from_slice(&self.f_fsid[1].to_le_bytes());
        out[64..72].copy_from_slice(&self.f_namelen.to_le_bytes());
        out[72..80].copy_from_slice(&self.f_frsize.to_le_bytes());
        out[80..88].copy_from_slice(&self.f_flags.to_le_bytes());
        // `f_spare[4]` at 88..120 stays zeroed.
        out
    }
}

/// Container-bounded filesystem operations provided by the kernel's Linux host.
pub trait Filesystem<R: Resources> {
    fn file_access(&self, _file: &R::File) -> FileAccess {
        FileAccess::ReadWrite
    }

    fn file_is_directory(&self, _file: &R::File) -> bool {
        false
    }

    fn file_path<'a>(&self, _file: &'a R::File) -> Option<&'a str> {
        None
    }

    fn can_exec_file(&self, _file: &R::File) -> bool {
        true
    }

    fn same_file(&self, _a: &R::File, _b: &R::File) -> bool {
        false
    }

    /// Stable `(dev, ino)` key identifying the underlying file for `flock(2)`
    /// and POSIX `fcntl(2)` record locks.
    fn file_lock_key(&self, _file: &R::File) -> Option<helios_unix::FileLockKey> {
        None
    }

    /// Filesystem statistics for `path` (`statfs(2)`).
    fn statfs_path(
        &self,
        _base: Option<&R::File>,
        _cwd: &str,
        _path: &str,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<FsStat, FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    /// Filesystem statistics for open file descriptor `file` (`fstatfs(2)`).
    fn statfs_file(
        &self,
        _file: &R::File,
    ) -> impl Future<Output = Result<FsStat, FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    /// Flushes all writable mounts in the container (`sync(2)`).
    fn sync_all(&self) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Ok(()) }
    }

    /// Flushes the mount containing `file` (`syncfs(2)`).
    fn sync_fs(&self, _file: &R::File) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Ok(()) }
    }

    fn open(
        &mut self,
        _base: Option<&R::File>,
        _cwd: &str,
        _path: &str,
        _request: OpenRequest,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<R::File, FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    /// Resolves and stats `path`, returning both its [`FileStat`] and its
    /// normalized absolute container path.
    fn stat_path(
        &self,
        _base: Option<&R::File>,
        _cwd: &str,
        _path: &str,
        _follow: bool,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<(FileStat, String), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    fn stat_file(
        &self,
        _file: &R::File,
    ) -> impl Future<Output = Result<FileStat, FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    fn access_path(
        &self,
        _base: Option<&R::File>,
        _cwd: &str,
        _path: &str,
        _check: AccessCheck,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    /// Checks directory search permission (`MAY_EXEC`) for `fchdir(2)`.
    fn can_chdir_file(
        &self,
        _file: &R::File,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Ok(()) }
    }

    fn read_at(
        &self,
        _file: &R::File,
        _offset: u64,
        _max_bytes: usize,
    ) -> impl Future<Output = Result<Bytes, FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    fn write_at(
        &mut self,
        _file: &R::File,
        _position: WritePosition,
        _bytes: &[u8],
        _creds: &Credentials,
    ) -> impl Future<Output = Result<Landed, FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    /// Returns `(self_inode, parent_inode, entries)` for a directory descriptor.
    fn list_dir(
        &self,
        _file: &R::File,
    ) -> impl Future<Output = Result<(u64, u64, Vec<DirListEntry>), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    fn set_size_file(
        &mut self,
        _file: &R::File,
        _size: u64,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    fn set_size_path(
        &mut self,
        _cwd: &str,
        _path: &str,
        _size: u64,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    fn sync(
        &self,
        _file: &R::File,
        _data_only: bool,
    ) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    fn read_link(
        &self,
        _base: Option<&R::File>,
        _cwd: &str,
        _path: &str,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<String, FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    fn mkdir(
        &mut self,
        _base: Option<&R::File>,
        _cwd: &str,
        _path: &str,
        _mode: u32,
        _umask: u32,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    #[allow(clippy::too_many_arguments)]
    fn mknod(
        &mut self,
        _base: Option<&R::File>,
        _cwd: &str,
        _path: &str,
        _kind: NodeKind,
        _mode: u32,
        _umask: u32,
        _rdev: u64,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    fn unlink(
        &mut self,
        _base: Option<&R::File>,
        _cwd: &str,
        _path: &str,
        _remove_dir: bool,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    #[allow(clippy::too_many_arguments)]
    fn rename(
        &mut self,
        _old_base: Option<&R::File>,
        _old_path: &str,
        _new_base: Option<&R::File>,
        _new_path: &str,
        _cwd: &str,
        _mode: RenameMode,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    #[allow(clippy::too_many_arguments)]
    fn link(
        &mut self,
        _old_base: Option<&R::File>,
        _old_path: &str,
        _new_base: Option<&R::File>,
        _new_path: &str,
        _cwd: &str,
        _options: LinkOptions,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    fn symlink(
        &mut self,
        _target: &str,
        _base: Option<&R::File>,
        _cwd: &str,
        _link_path: &str,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    #[allow(clippy::too_many_arguments)]
    fn set_times_path(
        &mut self,
        _base: Option<&R::File>,
        _cwd: &str,
        _path: &str,
        _follow: bool,
        _access: TimeUpdate,
        _modified: TimeUpdate,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    fn set_times_file(
        &mut self,
        _file: &R::File,
        _access: TimeUpdate,
        _modified: TimeUpdate,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    fn chmod_path(
        &mut self,
        _base: Option<&R::File>,
        _cwd: &str,
        _path: &str,
        _follow: bool,
        _mode: u32,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    fn chmod_file(
        &mut self,
        _file: &R::File,
        _mode: u32,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    #[allow(clippy::too_many_arguments)]
    fn chown_path(
        &mut self,
        _base: Option<&R::File>,
        _cwd: &str,
        _path: &str,
        _follow: bool,
        _uid: Option<u32>,
        _gid: Option<u32>,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    fn chown_file(
        &mut self,
        _file: &R::File,
        _uid: Option<u32>,
        _gid: Option<u32>,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    fn get_xattr_path(
        &self,
        _cwd: &str,
        _path: &str,
        _follow: bool,
        _name: &str,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<Vec<u8>, FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    fn get_xattr_file(
        &self,
        _file: &R::File,
        _name: &str,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<Vec<u8>, FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    #[allow(clippy::too_many_arguments)]
    fn set_xattr_path(
        &mut self,
        _cwd: &str,
        _path: &str,
        _follow: bool,
        _name: &str,
        _value: &[u8],
        _mode: XattrSetMode,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    fn set_xattr_file(
        &mut self,
        _file: &R::File,
        _name: &str,
        _value: &[u8],
        _mode: XattrSetMode,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    fn list_xattrs_path(
        &self,
        _cwd: &str,
        _path: &str,
        _follow: bool,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<Vec<String>, FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    fn list_xattrs_file(
        &self,
        _file: &R::File,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<Vec<String>, FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    fn remove_xattr_path(
        &mut self,
        _cwd: &str,
        _path: &str,
        _follow: bool,
        _name: &str,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }

    fn remove_xattr_file(
        &mut self,
        _file: &R::File,
        _name: &str,
        _creds: &Credentials,
    ) -> impl Future<Output = Result<(), FsOpError>> + Send {
        async { Err(FsOpError::Fs(FsError::Unsupported)) }
    }
}

pub(super) fn fs_errno(error: FsOpError) -> u64 {
    errno(match error {
        FsOpError::PermissionDenied => EPERM,
        FsOpError::NoData => ENODATA,
        FsOpError::Range => ERANGE,
        FsOpError::ArgTooBig => E2BIG,
        FsOpError::NoDevice => ENXIO,
        FsOpError::Fs(fs_err) => match fs_err {
            FsError::NoEntry => ENOENT,
            FsError::NotPermitted => EACCES,
            FsError::Exists => EEXIST,
            FsError::CrossDevice => EXDEV,
            FsError::NotDirectory => ENOTDIR,
            FsError::IsDirectory => EISDIR,
            FsError::Invalid => EINVAL,
            FsError::NoSpace => ENOSPC,
            FsError::ReadOnly => EROFS,
            FsError::NameTooLong => ENAMETOOLONG,
            FsError::NotEmpty => ENOTEMPTY,
            FsError::Loop => ELOOP,
            FsError::Overflow => EOVERFLOW,
            FsError::Busy => EBUSY,
            FsError::Unsupported => EOPNOTSUPP,
            FsError::IllegalByteSequence => EILSEQ,
            FsError::OutOfMemory => ENOMEM,
            FsError::Io => EIO,
        },
    })
}

/// Converts shared `helios-unix` open-description status flags to Linux `O_*` bits
/// for `fcntl(F_GETFL)`.
pub(super) fn fdflags_to_linux(abi: Abi, fdflags: u16) -> u64 {
    let mut out = 0u64;
    if fdflags & FDFLAG_APPEND != 0 {
        out |= O_APPEND;
    }
    if fdflags & FDFLAG_NONBLOCK != 0 {
        out |= O_NONBLOCK;
    }
    if fdflags & FDFLAG_DSYNC != 0 {
        out |= O_DSYNC;
    }
    if fdflags & FDFLAG_SYNC != 0 {
        out |= O_SYNC;
    }
    if fdflags & FDFLAG_NOATIME != 0 {
        out |= O_NOATIME;
    }
    if fdflags & FDFLAG_DIRECT != 0 {
        out |= abi.o_direct();
    }
    if fdflags & FDFLAG_PATH != 0 {
        out |= O_PATH;
    }
    out
}

/// Converts Linux `O_*` status flags to shared `helios-unix` `fdflags`.
pub(super) fn linux_to_fdflags(abi: Abi, flags: u64) -> u16 {
    let mut out = 0u16;
    if flags & O_APPEND != 0 {
        out |= FDFLAG_APPEND;
    }
    if flags & O_NONBLOCK != 0 {
        out |= FDFLAG_NONBLOCK;
    }
    if flags & O_DSYNC != 0 {
        out |= FDFLAG_DSYNC;
    }
    if flags & O_SYNC_BIT != 0 {
        out |= FDFLAG_SYNC | FDFLAG_DSYNC;
    }
    if flags & O_NOATIME != 0 {
        out |= FDFLAG_NOATIME;
    }
    if flags & abi.o_direct() != 0 {
        out |= FDFLAG_DIRECT;
    }
    if flags & O_PATH != 0 {
        out |= FDFLAG_PATH;
    }
    out
}

/// Updates only the mutable status flags (`fcntl(F_SETFL)`): `O_APPEND`,
/// `O_NONBLOCK`, `O_NOATIME`, `O_DIRECT`, preserving immutable flags (`O_SYNC`,
/// `O_DSYNC`, `O_PATH`).
pub(super) fn apply_setfl(abi: Abi, current: u16, linux_flags: u64) -> u16 {
    let mutable = FDFLAG_APPEND | FDFLAG_NONBLOCK | FDFLAG_NOATIME | FDFLAG_DIRECT;
    let preserved = current & !mutable;
    preserved | (linux_to_fdflags(abi, linux_flags) & mutable)
}

/// Reads a NUL-terminated path string from user memory, stopping at page
/// boundaries so a NUL byte near the end of a mapped page never reads into an
/// adjacent unmapped page.
pub(super) fn read_user_path<M: UserMemory>(memory: &M, address: u64) -> Result<String, u64> {
    if address == 0 {
        return Err(errno(EFAULT));
    }
    let mut bytes = Vec::new();
    let mut cursor = address;
    let mut chunk = [0u8; 256];
    loop {
        if bytes.len() >= PATH_MAX {
            return Err(errno(ENAMETOOLONG));
        }
        let page_rem = 4096 - (cursor as usize & 4095);
        let max_len = (PATH_MAX - bytes.len()).min(chunk.len()).min(page_rem);
        // Probe incrementally if a larger read crosses into an unmapped sub-range.
        let mut read_len = max_len;
        while memory.read(cursor, &mut chunk[..read_len]).is_err() {
            if read_len == 1 {
                return Err(errno(EFAULT));
            }
            read_len = 1;
        }
        if let Some(nul) = chunk[..read_len].iter().position(|&b| b == 0) {
            bytes.extend_from_slice(&chunk[..nul]);
            return String::from_utf8(bytes).map_err(|_| errno(EINVAL));
        }
        bytes.extend_from_slice(&chunk[..read_len]);
        cursor = cursor.checked_add(read_len as u64).ok_or(errno(EFAULT))?;
    }
}

fn dirfd_file<R: Resources, F: Filesystem<R>>(
    process: &Process<R>,
    dirfd: i32,
    path: &str,
    allow_empty_file: bool,
    fs: &F,
) -> Result<Option<R::File>, u64> {
    if path.starts_with('/') {
        return Ok(None);
    }
    if dirfd == AT_FDCWD {
        return Ok(None);
    }
    let entry = process
        .shared
        .descriptors
        .lock()
        .get_entry(dirfd)
        .cloned()
        .ok_or(errno(EBADF))?;
    let file = match &entry.descriptor {
        FileDescriptor::File(open) => open.node().clone(),
        FileDescriptor::Preopen { descriptor, .. } => descriptor.clone(),
        _ => {
            return Err(errno(if allow_empty_file && path.is_empty() {
                EBADF
            } else {
                ENOTDIR
            }));
        }
    };
    if !allow_empty_file && !path.is_empty() && !fs.file_is_directory(&file) {
        return Err(errno(ENOTDIR));
    }
    Ok(Some(file))
}

pub(super) fn entry_file<R: Resources>(entry: &Entry<R>) -> Option<OpenFile<R::File>> {
    match &entry.descriptor {
        FileDescriptor::File(open) => Some(open.clone()),
        FileDescriptor::Preopen { descriptor, .. } => Some(OpenFile::new(descriptor.clone())),
        _ => None,
    }
}

/// Checks whether normalized container path `path` is equal to or strictly
/// inside normalized chroot prefix `root`.
fn path_within_root(path: &str, root: &str) -> bool {
    if root == "/" {
        return true;
    }
    path == root
        || (path.len() > root.len()
            && path.starts_with(root)
            && path.as_bytes()[root.len()] == b'/')
}

/// Clamps `path` relative to `base_dir` within `root` when `root != "/"`,
/// resolving symlinks strictly inside `root` so neither `..` nor absolute
/// symlink targets can escape the chroot boundary (`fs/namei.c`).
///
/// When `root == "/"`, returns `(cwd, path)` directly with zero extra I/O.
pub(super) async fn resolve_in_chroot<R: Resources, F: Filesystem<R>>(
    process: &Process<R>,
    base: Option<&R::File>,
    raw_path: &str,
    follow_final: bool,
    creds: &Credentials,
    fs: &F,
) -> Result<(String, String), u64> {
    let cwd = process.shared.cwd.lock().clone();
    let root = process.shared.root.lock().clone();
    if root == "/" {
        return Ok((cwd, String::from(raw_path)));
    }
    let base_dir = String::from(base.and_then(|f| fs.file_path(f)).unwrap_or(cwd.as_str()));
    alloc::boxed::Box::pin(resolve_in_chroot_slow(
        cwd,
        root,
        base_dir,
        raw_path,
        follow_final,
        creds,
        fs,
    ))
    .await
}

async fn resolve_in_chroot_slow<R: Resources, F: Filesystem<R>>(
    cwd: String,
    root: String,
    base_dir: String,
    raw_path: &str,
    follow_final: bool,
    creds: &Credentials,
    fs: &F,
) -> Result<(String, String), u64> {
    const MAX_SYMLINK_DEPTH: usize = 40;
    let root_segs: Vec<&str> = root.split('/').filter(|s| !s.is_empty()).collect();
    let clamp_at_root = raw_path.starts_with('/') || path_within_root(&base_dir, &root);
    let min_depth = if clamp_at_root { root_segs.len() } else { 0 };
    let trailing_slash = raw_path.ends_with('/') && raw_path != "/";

    let mut current: Vec<String> = if raw_path.starts_with('/') {
        root_segs.iter().map(|s| String::from(*s)).collect()
    } else {
        base_dir
            .split('/')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()
    };
    let mut pending: Vec<String> = raw_path
        .split('/')
        .filter(|s| !s.is_empty())
        .rev()
        .map(String::from)
        .collect();
    let mut symlinks_followed = 0usize;

    while let Some(seg) = pending.pop() {
        if seg == "." {
            continue;
        }
        if seg == ".." {
            if current.len() > min_depth {
                current.pop();
            }
            continue;
        }
        current.push(seg);
        let is_last = pending.is_empty();
        let should_follow = !is_last || follow_final || trailing_slash;
        if should_follow {
            let candidate = join_segments(&current);
            if let Ok((stat, _)) = fs.stat_path(None, "/", &candidate, false, creds).await
                && stat.kind == NodeKind::Symlink
            {
                symlinks_followed += 1;
                if symlinks_followed > MAX_SYMLINK_DEPTH {
                    return Err(errno(ELOOP));
                }
                let target = fs
                    .read_link(None, "/", &candidate, creds)
                    .await
                    .map_err(fs_errno)?;
                if target.starts_with('/') {
                    current = root_segs.iter().map(|s| String::from(*s)).collect();
                } else {
                    current.pop();
                }
                for tseg in target.split('/').filter(|s| !s.is_empty()).rev() {
                    pending.push(String::from(tseg));
                }
            }
        }
    }

    let mut resolved = join_segments(&current);
    if trailing_slash && resolved != "/" {
        resolved.push('/');
    }
    Ok((cwd, resolved))
}

fn join_segments(segs: &[String]) -> String {
    if segs.is_empty() {
        return String::from("/");
    }
    let mut out = String::new();
    for seg in segs {
        out.push('/');
        out.push_str(seg);
    }
    out
}

fn is_dev_null_path<R: Resources, F: Filesystem<R>>(
    base: Option<&R::File>,
    cwd: &str,
    path: &str,
    fs: &F,
) -> bool {
    // Reject any `..` traversal so paths like `/nonexistent/../dev/null`
    // never bypass directory existence checks.
    if path.split('/').any(|comp| comp == "..") {
        return false;
    }
    let base_dir = base.and_then(|file| fs.file_path(file)).unwrap_or(cwd);
    let mut segments: Vec<&str> = if path.starts_with('/') {
        Vec::new()
    } else {
        base_dir.split('/').filter(|s| !s.is_empty()).collect()
    };
    for comp in path.split('/').filter(|s| !s.is_empty()) {
        if comp != "." {
            segments.push(comp);
        }
    }
    segments.as_slice() == ["dev", "null"]
}

fn synthetic_dev_null_stat() -> FileStat {
    FileStat {
        dev: 1,
        ino: 1,
        kind: NodeKind::CharacterDevice,
        permissions: 0o666,
        nlink: 1,
        uid: 0,
        gid: 0,
        rdev: (1 << 8) | 3, // Linux major 1, minor 3 (`/dev/null`).
        size: 0,
        access_nanos: 0,
        modified_nanos: 0,
        status_nanos: 0,
    }
}

pub(super) fn process_creds<R: Resources>(process: &Process<R>) -> Credentials {
    process.credentials.lock().clone()
}

/// Reads a NUL-terminated xattr name from user memory (`fs/xattr.c`: empty or
/// `> XATTR_NAME_MAX` returns `ERANGE`).
fn read_xattr_name<M: UserMemory>(memory: &M, address: u64) -> Result<String, u64> {
    if address == 0 {
        return Err(errno(EFAULT));
    }
    let mut bytes = Vec::new();
    let mut cursor = address;
    let mut chunk = [0u8; 64];
    loop {
        if bytes.len() > permissions::XATTR_NAME_MAX {
            return Err(errno(ERANGE));
        }
        let page_rem = 4096 - (cursor as usize & 4095);
        let max_len = (permissions::XATTR_NAME_MAX + 1 - bytes.len())
            .min(chunk.len())
            .min(page_rem);
        let mut read_len = max_len;
        while memory.read(cursor, &mut chunk[..read_len]).is_err() {
            if read_len == 1 {
                return Err(errno(EFAULT));
            }
            read_len = 1;
        }
        if let Some(nul) = chunk[..read_len].iter().position(|&b| b == 0) {
            bytes.extend_from_slice(&chunk[..nul]);
            if bytes.is_empty() || bytes.len() > permissions::XATTR_NAME_MAX {
                return Err(errno(ERANGE));
            }
            return String::from_utf8(bytes).map_err(|_| errno(EINVAL));
        }
        bytes.extend_from_slice(&chunk[..read_len]);
        cursor = cursor.checked_add(read_len as u64).ok_or(errno(EFAULT))?;
    }
}

pub(super) async fn openat<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    let abi = process.shared.abi;
    let dirfd = args[0] as u32 as i32;
    let path = match read_user_path(memory, args[1]) {
        Ok(path) => path,
        Err(err) => return err,
    };
    if path.is_empty() {
        return errno(ENOENT);
    }
    let flags = args[2] as u32 as u64;
    let raw_mode = args[3] as u32;
    let umask = process.shared.attributes.lock().umask;
    let mode = raw_mode & permissions::S_IALLUGO;

    let path_only = flags & O_PATH != 0;
    let accmode = flags & O_ACCMODE;
    if !path_only && accmode == 3 {
        return errno(EINVAL);
    }
    let read = !path_only && matches!(accmode, O_RDONLY | O_RDWR);
    let write = !path_only && matches!(accmode, O_WRONLY | O_RDWR);
    let request = OpenRequest {
        read,
        write,
        create: !path_only && (flags & O_CREAT != 0),
        exclusive: !path_only && (flags & O_EXCL != 0),
        truncate: !path_only && (flags & O_TRUNC != 0),
        directory: flags & abi.o_directory() != 0,
        nofollow: flags & abi.o_nofollow() != 0,
        path_only,
        append: !path_only && (flags & O_APPEND != 0),
        sync: !path_only && (flags & O_SYNC_BIT != 0),
        dsync: !path_only && (flags & O_DSYNC != 0),
        mode,
        umask,
    };

    let base = match dirfd_file(process, dirfd, &path, false, fs) {
        Ok(base) => base,
        Err(err) => return err,
    };
    let creds = process_creds(process);
    let (cwd, resolved_path) =
        match resolve_in_chroot(process, base.as_ref(), &path, !request.nofollow, &creds, fs).await
        {
            Ok(pair) => pair,
            Err(err) => return err,
        };
    let open_base = if resolved_path.starts_with('/') {
        None
    } else {
        base.as_ref()
    };
    let cloexec = flags & O_CLOEXEC != 0;
    let descriptor = match fs
        .open(open_base, &cwd, &resolved_path, request, &creds)
        .await
    {
        Ok(file) => FileDescriptor::File(OpenFile::new(file)),
        Err(FsOpError::Fs(FsError::NoEntry))
            if is_dev_null_path(open_base, &cwd, &resolved_path, fs) =>
        {
            if path.ends_with('/') || request.directory {
                return errno(ENOTDIR);
            }
            if request.create && request.exclusive {
                return errno(EEXIST);
            }
            FileDescriptor::NullDevice
        }
        Err(error) => return fs_errno(error),
    };
    let entry = Entry::<R>::new(descriptor, cloexec);
    let mut fdflags = linux_to_fdflags(abi, flags);
    if path_only {
        fdflags = FDFLAG_PATH;
    }
    entry.set_fdflags(fdflags);
    process
        .shared
        .descriptors
        .lock()
        .insert_entry(entry)
        .map_or_else(io::descriptor_errno, u64::from)
}

pub(super) async fn open<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    openat(
        process,
        [AT_FDCWD as u32 as u64, args[0], args[1], args[2], 0, 0],
        memory,
        fs,
    )
    .await
}

pub(super) async fn creat<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    openat(
        process,
        [
            AT_FDCWD as u32 as u64,
            args[0],
            O_CREAT | O_WRONLY | O_TRUNC,
            args[1],
            0,
            0,
        ],
        memory,
        fs,
    )
    .await
}

fn synthetic_stat<R: Resources, T: tty::Tty>(entry: &Entry<R>, tty: &T) -> FileStat {
    let (kind, permissions, uid, gid) = match &entry.descriptor {
        FileDescriptor::PipeRead { inode, .. } | FileDescriptor::PipeWrite { inode, .. } => {
            let attrs = inode.attrs();
            (NodeKind::Fifo, attrs.mode, attrs.uid, attrs.gid)
        }
        FileDescriptor::Stdin { .. } => {
            if tty.is_tty(tty::TtyStream::Stdin) {
                (NodeKind::CharacterDevice, 0o620, 0, 0)
            } else {
                (NodeKind::Fifo, 0o600, 0, 0)
            }
        }
        FileDescriptor::Stdout => {
            if tty.is_tty(tty::TtyStream::Stdout) {
                (NodeKind::CharacterDevice, 0o620, 0, 0)
            } else {
                (NodeKind::Fifo, 0o600, 0, 0)
            }
        }
        FileDescriptor::Stderr => {
            if tty.is_tty(tty::TtyStream::Stderr) {
                (NodeKind::CharacterDevice, 0o620, 0, 0)
            } else {
                (NodeKind::Fifo, 0o600, 0, 0)
            }
        }
        FileDescriptor::NullDevice => (NodeKind::CharacterDevice, 0o666, 0, 0),
        FileDescriptor::Socket(_) => (NodeKind::Socket, 0o777, 0, 0),
        FileDescriptor::Event(_) | FileDescriptor::Epoll(_) => (NodeKind::File, 0o600, 0, 0),
        FileDescriptor::File(_) | FileDescriptor::Preopen { .. } => (NodeKind::File, 0o644, 0, 0),
    };
    FileStat {
        dev: 1,
        ino: 1,
        kind,
        permissions,
        nlink: 1,
        uid,
        gid,
        rdev: 0,
        size: 0,
        access_nanos: 0,
        modified_nanos: 0,
        status_nanos: 0,
    }
}

async fn stat_fd<R: Resources, F: Filesystem<R>, T: tty::Tty>(
    process: &Process<R>,
    fd: i32,
    fs: &F,
    tty: &T,
) -> Result<FileStat, u64> {
    let entry = process
        .shared
        .descriptors
        .lock()
        .get_entry(fd)
        .cloned()
        .ok_or(errno(EBADF))?;
    match &entry.descriptor {
        FileDescriptor::File(open) => fs.stat_file(open.node()).await.map_err(fs_errno),
        FileDescriptor::Preopen { descriptor, .. } => {
            fs.stat_file(descriptor).await.map_err(fs_errno)
        }
        _ => Ok(synthetic_stat::<R, T>(&entry, tty)),
    }
}

pub(super) async fn fstat<R: Resources, M: UserMemory, F: Filesystem<R>, T: tty::Tty>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    fs: &F,
    tty: &T,
) -> u64 {
    let stat = match stat_fd(process, args[0] as u32 as i32, fs, tty).await {
        Ok(stat) => stat,
        Err(err) => return err,
    };
    let mut buf = [0u8; 144];
    let len = stat.write_stat(process.shared.abi, &mut buf);
    match memory.write(args[1], &buf[..len]) {
        Ok(()) => 0,
        Err(_) => errno(EFAULT),
    }
}

pub(super) async fn newfstatat<R: Resources, M: UserMemory, F: Filesystem<R>, T: tty::Tty>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    fs: &F,
    tty: &T,
) -> u64 {
    let dirfd = args[0] as u32 as i32;
    let flags = args[3] as u32 as u64;
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT) != 0 {
        return errno(EINVAL);
    }
    let path = match read_user_path(memory, args[1]) {
        Ok(path) => path,
        Err(err) => return err,
    };
    let stat = if path.is_empty() {
        if flags & AT_EMPTY_PATH == 0 {
            return errno(ENOENT);
        }
        if dirfd == AT_FDCWD {
            let cwd = process.shared.cwd.lock().clone();
            let creds = process_creds(process);
            match fs.stat_path(None, &cwd, "", true, &creds).await {
                Ok((stat, _)) => stat,
                Err(error) => return fs_errno(error),
            }
        } else {
            match stat_fd(process, dirfd, fs, tty).await {
                Ok(stat) => stat,
                Err(err) => return err,
            }
        }
    } else {
        let base = match dirfd_file(process, dirfd, &path, false, fs) {
            Ok(base) => base,
            Err(err) => return err,
        };
        let creds = process_creds(process);
        let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
        let (cwd, resolved_path) =
            match resolve_in_chroot(process, base.as_ref(), &path, follow, &creds, fs).await {
                Ok(pair) => pair,
                Err(err) => return err,
            };
        let stat_base = if resolved_path.starts_with('/') {
            None
        } else {
            base.as_ref()
        };
        match fs
            .stat_path(stat_base, &cwd, &resolved_path, follow, &creds)
            .await
        {
            Ok((stat, _)) => stat,
            Err(FsOpError::Fs(FsError::NoEntry))
                if is_dev_null_path(stat_base, &cwd, &resolved_path, fs) =>
            {
                if path.ends_with('/') {
                    return errno(ENOTDIR);
                }
                synthetic_dev_null_stat()
            }
            Err(error) => return fs_errno(error),
        }
    };
    let mut buf = [0u8; 144];
    let len = stat.write_stat(process.shared.abi, &mut buf);
    match memory.write(args[2], &buf[..len]) {
        Ok(()) => 0,
        Err(_) => errno(EFAULT),
    }
}

pub(super) async fn stat<R: Resources, M: UserMemory, F: Filesystem<R>, T: tty::Tty>(
    process: &Process<R>,
    args: [u64; 6],
    follow: bool,
    memory: &mut M,
    fs: &F,
    tty: &T,
) -> u64 {
    let flags = if follow { 0 } else { AT_SYMLINK_NOFOLLOW };
    newfstatat(
        process,
        [AT_FDCWD as u32 as u64, args[0], args[1], flags, 0, 0],
        memory,
        fs,
        tty,
    )
    .await
}

pub(super) async fn statx<R: Resources, M: UserMemory, F: Filesystem<R>, T: tty::Tty>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    fs: &F,
    tty: &T,
) -> u64 {
    let dirfd = args[0] as u32 as i32;
    let flags = args[2] as u32 as u64;
    let _mask = args[3] as u32;
    let statxbuf = args[4];
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_STATX_SYNC_TYPE) != 0 {
        return errno(EINVAL);
    }
    if (flags & AT_STATX_SYNC_TYPE) == AT_STATX_SYNC_TYPE {
        return errno(EINVAL);
    }
    let path = match read_user_path(memory, args[1]) {
        Ok(path) => path,
        Err(err) => return err,
    };
    let stat = if path.is_empty() {
        if flags & AT_EMPTY_PATH == 0 {
            return errno(ENOENT);
        }
        if dirfd == AT_FDCWD {
            let cwd = process.shared.cwd.lock().clone();
            let creds = process_creds(process);
            match fs.stat_path(None, &cwd, "", true, &creds).await {
                Ok((stat, _)) => stat,
                Err(error) => return fs_errno(error),
            }
        } else {
            match stat_fd(process, dirfd, fs, tty).await {
                Ok(stat) => stat,
                Err(err) => return err,
            }
        }
    } else {
        let base = match dirfd_file(process, dirfd, &path, false, fs) {
            Ok(base) => base,
            Err(err) => return err,
        };
        let creds = process_creds(process);
        let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
        let (cwd, resolved_path) =
            match resolve_in_chroot(process, base.as_ref(), &path, follow, &creds, fs).await {
                Ok(pair) => pair,
                Err(err) => return err,
            };
        let stat_base = if resolved_path.starts_with('/') {
            None
        } else {
            base.as_ref()
        };
        match fs
            .stat_path(stat_base, &cwd, &resolved_path, follow, &creds)
            .await
        {
            Ok((stat, _)) => stat,
            Err(FsOpError::Fs(FsError::NoEntry))
                if is_dev_null_path(stat_base, &cwd, &resolved_path, fs) =>
            {
                if path.ends_with('/') {
                    return errno(ENOTDIR);
                }
                synthetic_dev_null_stat()
            }
            Err(error) => return fs_errno(error),
        }
    };
    let encoded = stat.write_statx();
    match memory.write(statxbuf, &encoded) {
        Ok(()) => 0,
        Err(_) => errno(EFAULT),
    }
}

pub(super) async fn faccessat<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    has_flags: bool,
    memory: &M,
    fs: &F,
) -> u64 {
    let dirfd = args[0] as u32 as i32;
    let mode = args[2] as u32 as u64;
    if mode & !7 != 0 {
        return errno(EINVAL);
    }
    let flags = if has_flags { args[3] as u32 as u64 } else { 0 };
    if flags & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW) != 0 {
        return errno(EINVAL);
    }
    let path = match read_user_path(memory, args[1]) {
        Ok(path) => path,
        Err(err) => return err,
    };
    if path.is_empty() {
        return errno(ENOENT);
    }
    let base = match dirfd_file(process, dirfd, &path, false, fs) {
        Ok(base) => base,
        Err(err) => return err,
    };
    let creds = process_creds(process);
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let use_effective = flags & AT_EACCESS != 0;
    let (cwd, resolved_path) =
        match resolve_in_chroot(process, base.as_ref(), &path, follow, &creds, fs).await {
            Ok(pair) => pair,
            Err(err) => return err,
        };
    let eff_base = if resolved_path.starts_with('/') {
        None
    } else {
        base.as_ref()
    };
    match fs
        .access_path(
            eff_base,
            &cwd,
            &resolved_path,
            AccessCheck {
                read: mode & 4 != 0,
                write: mode & 2 != 0,
                exec: mode & 1 != 0,
                follow,
                use_effective,
            },
            &creds,
        )
        .await
    {
        Ok(()) => 0,
        Err(FsOpError::Fs(FsError::NoEntry))
            if is_dev_null_path(eff_base, &cwd, &resolved_path, fs) =>
        {
            if path.ends_with('/') {
                errno(ENOTDIR)
            } else if mode & 1 != 0 {
                errno(EACCES)
            } else {
                0
            }
        }
        Err(error) => fs_errno(error),
    }
}

pub(super) async fn access<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &F,
) -> u64 {
    faccessat(
        process,
        [AT_FDCWD as u32 as u64, args[0], args[1], 0, 0, 0],
        false,
        memory,
        fs,
    )
    .await
}

pub(super) async fn readlinkat<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    fs: &F,
) -> u64 {
    let dirfd = args[0] as u32 as i32;
    let bufsiz = args[3] as i64;
    if bufsiz <= 0 {
        return errno(EINVAL);
    }
    let path = match read_user_path(memory, args[1]) {
        Ok(path) => path,
        Err(err) => return err,
    };
    if path.is_empty() && dirfd == AT_FDCWD {
        return errno(ENOENT);
    }
    let base = match dirfd_file(process, dirfd, &path, true, fs) {
        Ok(base) => base,
        Err(err) => return err,
    };
    let creds = process_creds(process);
    let (cwd, resolved_path) = if path.is_empty() {
        (process.shared.cwd.lock().clone(), path)
    } else {
        match resolve_in_chroot(process, base.as_ref(), &path, false, &creds, fs).await {
            Ok(pair) => pair,
            Err(err) => return err,
        }
    };
    let eff_base = if resolved_path.starts_with('/') {
        None
    } else {
        base.as_ref()
    };
    let target = match fs.read_link(eff_base, &cwd, &resolved_path, &creds).await {
        Ok(target) => target,
        Err(error) => return fs_errno(error),
    };
    let bytes = target.as_bytes();
    let take = bytes.len().min(bufsiz as usize);
    match memory.write(args[2], &bytes[..take]) {
        Ok(()) => take as u64,
        Err(_) => errno(EFAULT),
    }
}

pub(super) async fn readlink<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    fs: &F,
) -> u64 {
    readlinkat(
        process,
        [AT_FDCWD as u32 as u64, args[0], args[1], args[2], 0, 0],
        memory,
        fs,
    )
    .await
}

pub(super) async fn mkdirat<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    let dirfd = args[0] as u32 as i32;
    let path = match read_user_path(memory, args[1]) {
        Ok(path) => path,
        Err(err) => return err,
    };
    if path.is_empty() {
        return errno(ENOENT);
    }
    let umask = process.shared.attributes.lock().umask;
    // `fs/namei.c` `do_mkdirat`: preserves `0o777 | S_ISVTX` (`0o1777`).
    let mode = (args[2] as u32) & (0o777 | permissions::S_ISVTX);
    let base = match dirfd_file(process, dirfd, &path, false, fs) {
        Ok(base) => base,
        Err(err) => return err,
    };
    let creds = process_creds(process);
    let (cwd, resolved_path) =
        match resolve_in_chroot(process, base.as_ref(), &path, false, &creds, fs).await {
            Ok(pair) => pair,
            Err(err) => return err,
        };
    let eff_base = if resolved_path.starts_with('/') {
        None
    } else {
        base.as_ref()
    };
    match fs
        .mkdir(eff_base, &cwd, &resolved_path, mode, umask, &creds)
        .await
    {
        Ok(()) => 0,
        Err(error) => fs_errno(error),
    }
}

pub(super) async fn mkdir<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    mkdirat(
        process,
        [AT_FDCWD as u32 as u64, args[0], args[1], 0, 0, 0],
        memory,
        fs,
    )
    .await
}

pub(super) async fn unlinkat<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    let dirfd = args[0] as u32 as i32;
    let flags = args[2] as u32 as u64;
    if flags & !AT_REMOVEDIR != 0 {
        return errno(EINVAL);
    }
    let path = match read_user_path(memory, args[1]) {
        Ok(path) => path,
        Err(err) => return err,
    };
    if path.is_empty() {
        return errno(ENOENT);
    }
    let base = match dirfd_file(process, dirfd, &path, false, fs) {
        Ok(base) => base,
        Err(err) => return err,
    };
    let creds = process_creds(process);
    let (cwd, resolved_path) =
        match resolve_in_chroot(process, base.as_ref(), &path, false, &creds, fs).await {
            Ok(pair) => pair,
            Err(err) => return err,
        };
    let eff_base = if resolved_path.starts_with('/') {
        None
    } else {
        base.as_ref()
    };
    match fs
        .unlink(
            eff_base,
            &cwd,
            &resolved_path,
            flags & AT_REMOVEDIR != 0,
            &creds,
        )
        .await
    {
        Ok(()) => 0,
        Err(error) => fs_errno(error),
    }
}

pub(super) async fn unlink<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    remove_dir: bool,
    memory: &M,
    fs: &mut F,
) -> u64 {
    let flags = if remove_dir { AT_REMOVEDIR } else { 0 };
    unlinkat(
        process,
        [AT_FDCWD as u32 as u64, args[0], flags, 0, 0, 0],
        memory,
        fs,
    )
    .await
}

pub(super) async fn renameat2<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    has_flags: bool,
    memory: &M,
    fs: &mut F,
) -> u64 {
    let old_dirfd = args[0] as u32 as i32;
    let new_dirfd = args[2] as u32 as i32;
    let flags = if has_flags { args[4] as u32 as u64 } else { 0 };
    let mode = match flags {
        0 => RenameMode::Replace,
        RENAME_NOREPLACE => RenameMode::NoReplace,
        RENAME_EXCHANGE => RenameMode::Exchange,
        _ => return errno(EINVAL),
    };
    let old_path = match read_user_path(memory, args[1]) {
        Ok(path) => path,
        Err(err) => return err,
    };
    let new_path = match read_user_path(memory, args[3]) {
        Ok(path) => path,
        Err(err) => return err,
    };
    if old_path.is_empty() || new_path.is_empty() {
        return errno(ENOENT);
    }
    let old_base = match dirfd_file(process, old_dirfd, &old_path, false, fs) {
        Ok(base) => base,
        Err(err) => return err,
    };
    let new_base = match dirfd_file(process, new_dirfd, &new_path, false, fs) {
        Ok(base) => base,
        Err(err) => return err,
    };
    let creds = process_creds(process);
    let (cwd, resolved_old) =
        match resolve_in_chroot(process, old_base.as_ref(), &old_path, false, &creds, fs).await {
            Ok(pair) => pair,
            Err(err) => return err,
        };
    let (_, resolved_new) =
        match resolve_in_chroot(process, new_base.as_ref(), &new_path, false, &creds, fs).await {
            Ok(pair) => pair,
            Err(err) => return err,
        };
    let eff_old = if resolved_old.starts_with('/') {
        None
    } else {
        old_base.as_ref()
    };
    let eff_new = if resolved_new.starts_with('/') {
        None
    } else {
        new_base.as_ref()
    };
    match fs
        .rename(
            eff_old,
            &resolved_old,
            eff_new,
            &resolved_new,
            &cwd,
            mode,
            &creds,
        )
        .await
    {
        Ok(()) => 0,
        Err(error) => fs_errno(error),
    }
}

pub(super) async fn rename<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    renameat2(
        process,
        [
            AT_FDCWD as u32 as u64,
            args[0],
            AT_FDCWD as u32 as u64,
            args[1],
            0,
            0,
        ],
        false,
        memory,
        fs,
    )
    .await
}

pub(super) async fn linkat<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    let old_dirfd = args[0] as u32 as i32;
    let new_dirfd = args[2] as u32 as i32;
    let flags = args[4] as u32 as u64;
    if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
        return errno(EINVAL);
    }
    let old_path = match read_user_path(memory, args[1]) {
        Ok(path) => path,
        Err(err) => return err,
    };
    let new_path = match read_user_path(memory, args[3]) {
        Ok(path) => path,
        Err(err) => return err,
    };
    let empty_path = flags & AT_EMPTY_PATH != 0;
    if (old_path.is_empty() && !empty_path) || new_path.is_empty() {
        return errno(ENOENT);
    }
    let old_base = match dirfd_file(process, old_dirfd, &old_path, empty_path, fs) {
        Ok(base) => base,
        Err(err) => return err,
    };
    let new_base = match dirfd_file(process, new_dirfd, &new_path, false, fs) {
        Ok(base) => base,
        Err(err) => return err,
    };
    let creds = process_creds(process);
    let follow_old = flags & AT_SYMLINK_FOLLOW != 0;
    let (cwd, resolved_old) = if old_path.is_empty() {
        (process.shared.cwd.lock().clone(), old_path)
    } else {
        match resolve_in_chroot(
            process,
            old_base.as_ref(),
            &old_path,
            follow_old,
            &creds,
            fs,
        )
        .await
        {
            Ok(pair) => pair,
            Err(err) => return err,
        }
    };
    let (_, resolved_new) =
        match resolve_in_chroot(process, new_base.as_ref(), &new_path, false, &creds, fs).await {
            Ok(pair) => pair,
            Err(err) => return err,
        };
    let eff_old = if resolved_old.starts_with('/') {
        None
    } else {
        old_base.as_ref()
    };
    let eff_new = if resolved_new.starts_with('/') {
        None
    } else {
        new_base.as_ref()
    };
    match fs
        .link(
            eff_old,
            &resolved_old,
            eff_new,
            &resolved_new,
            &cwd,
            LinkOptions {
                follow: follow_old,
                empty_path,
            },
            &creds,
        )
        .await
    {
        Ok(()) => 0,
        Err(error) => fs_errno(error),
    }
}

pub(super) async fn link<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    linkat(
        process,
        [
            AT_FDCWD as u32 as u64,
            args[0],
            AT_FDCWD as u32 as u64,
            args[1],
            0,
            0,
        ],
        memory,
        fs,
    )
    .await
}

pub(super) async fn symlinkat<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    let target = match read_user_path(memory, args[0]) {
        Ok(target) => target,
        Err(err) => return err,
    };
    let new_dirfd = args[1] as u32 as i32;
    let link_path = match read_user_path(memory, args[2]) {
        Ok(path) => path,
        Err(err) => return err,
    };
    if target.is_empty() || link_path.is_empty() {
        return errno(ENOENT);
    }
    let base = match dirfd_file(process, new_dirfd, &link_path, false, fs) {
        Ok(base) => base,
        Err(err) => return err,
    };
    let creds = process_creds(process);
    let (cwd, resolved_link) =
        match resolve_in_chroot(process, base.as_ref(), &link_path, false, &creds, fs).await {
            Ok(pair) => pair,
            Err(err) => return err,
        };
    let eff_base = if resolved_link.starts_with('/') {
        None
    } else {
        base.as_ref()
    };
    match fs
        .symlink(&target, eff_base, &cwd, &resolved_link, &creds)
        .await
    {
        Ok(()) => 0,
        Err(error) => fs_errno(error),
    }
}

pub(super) async fn symlink<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    symlinkat(
        process,
        [args[0], AT_FDCWD as u32 as u64, args[1], 0, 0, 0],
        memory,
        fs,
    )
    .await
}

fn parse_time_update(sec: i64, nsec: i64) -> Result<TimeUpdate, u64> {
    if nsec == UTIME_OMIT {
        return Ok(TimeUpdate::Omit);
    }
    if nsec == UTIME_NOW {
        return Ok(TimeUpdate::Now);
    }
    if !(0..1_000_000_000).contains(&nsec) || sec < 0 {
        return Err(errno(EINVAL));
    }
    let nanos = (sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|s| s.checked_add(nsec as u64))
        .ok_or(errno(EINVAL))?;
    Ok(TimeUpdate::Set(nanos))
}

pub(super) async fn utimensat<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    let dirfd = args[0] as u32 as i32;
    let path_ptr = args[1];
    let times_ptr = args[2];
    let flags = args[3] as u32 as u64;
    if flags & !AT_SYMLINK_NOFOLLOW != 0 {
        return errno(EINVAL);
    }
    let (access, modified) = if times_ptr == 0 {
        (TimeUpdate::Now, TimeUpdate::Now)
    } else {
        let mut raw = [0u8; 32];
        if memory.read(times_ptr, &mut raw).is_err() {
            return errno(EFAULT);
        }
        let asec = i64::from_le_bytes(raw[0..8].try_into().unwrap());
        let ansec = i64::from_le_bytes(raw[8..16].try_into().unwrap());
        let msec = i64::from_le_bytes(raw[16..24].try_into().unwrap());
        let mnsec = i64::from_le_bytes(raw[24..32].try_into().unwrap());
        let access = match parse_time_update(asec, ansec) {
            Ok(update) => update,
            Err(err) => return err,
        };
        let modified = match parse_time_update(msec, mnsec) {
            Ok(update) => update,
            Err(err) => return err,
        };
        (access, modified)
    };

    if path_ptr == 0 {
        if dirfd == AT_FDCWD {
            return errno(EFAULT);
        }
        if flags != 0 {
            return errno(EINVAL);
        }
        let entry = match process.shared.descriptors.lock().get_entry(dirfd).cloned() {
            Some(entry) => entry,
            None => return errno(EBADF),
        };
        if entry.fdflags() & FDFLAG_PATH != 0 {
            return errno(EBADF);
        }
        let Some(open) = entry_file::<R>(&entry) else {
            return errno(EINVAL);
        };
        let creds = process_creds(process);
        return match fs
            .set_times_file(open.node(), access, modified, &creds)
            .await
        {
            Ok(()) => 0,
            Err(error) => fs_errno(error),
        };
    }

    let path = match read_user_path(memory, path_ptr) {
        Ok(path) => path,
        Err(err) => return err,
    };
    if path.is_empty() {
        return errno(ENOENT);
    }
    let base = match dirfd_file(process, dirfd, &path, false, fs) {
        Ok(base) => base,
        Err(err) => return err,
    };
    let creds = process_creds(process);
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let (cwd, resolved_path) =
        match resolve_in_chroot(process, base.as_ref(), &path, follow, &creds, fs).await {
            Ok(pair) => pair,
            Err(err) => return err,
        };
    let eff_base = if resolved_path.starts_with('/') {
        None
    } else {
        base.as_ref()
    };
    match fs
        .set_times_path(
            eff_base,
            &cwd,
            &resolved_path,
            follow,
            access,
            modified,
            &creds,
        )
        .await
    {
        Ok(()) => 0,
        Err(error) => fs_errno(error),
    }
}

pub(super) async fn chdir<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &F,
) -> u64 {
    let path = match read_user_path(memory, args[0]) {
        Ok(path) => path,
        Err(err) => return err,
    };
    if path.is_empty() {
        return errno(ENOENT);
    }
    let creds = process_creds(process);
    let (cwd, resolved_path) = match resolve_in_chroot(process, None, &path, true, &creds, fs).await
    {
        Ok(pair) => pair,
        Err(err) => return err,
    };
    let (stat, canonical) = match fs.stat_path(None, &cwd, &resolved_path, true, &creds).await {
        Ok(pair) => pair,
        Err(error) => return fs_errno(error),
    };
    if stat.kind != NodeKind::Directory {
        return errno(ENOTDIR);
    }
    if let Err(error) = fs
        .access_path(
            None,
            &cwd,
            &resolved_path,
            AccessCheck {
                read: false,
                write: false,
                exec: true,
                follow: true,
                use_effective: true,
            },
            &creds,
        )
        .await
    {
        return fs_errno(error);
    }
    *process.shared.cwd.lock() = canonical;
    0
}

pub(super) async fn fchdir<R: Resources, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    fs: &F,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let entry = match process.shared.descriptors.lock().get_entry(fd).cloned() {
        Some(entry) => entry,
        None => return errno(EBADF),
    };
    let Some(open) = entry_file::<R>(&entry) else {
        return errno(ENOTDIR);
    };
    if !fs.file_is_directory(open.node()) {
        return errno(ENOTDIR);
    }
    let creds = process_creds(process);
    if let Err(error) = fs.can_chdir_file(open.node(), &creds).await {
        return fs_errno(error);
    }
    let Some(path) = fs.file_path(open.node()) else {
        return errno(ENOENT);
    };
    *process.shared.cwd.lock() = String::from(path);
    0
}

pub(super) fn getcwd<R: Resources, M: UserMemory>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
) -> u64 {
    let buf = args[0];
    let size = args[1] as usize;
    let cwd = process.shared.cwd.lock().clone();
    let root = process.shared.root.lock().clone();
    let visible = if root == "/" {
        cwd
    } else if cwd == root {
        String::from("/")
    } else if path_within_root(&cwd, &root) {
        String::from(&cwd[root.len()..])
    } else {
        alloc::format!("(unreachable){cwd}")
    };
    let needed = visible.len() + 1;
    if size < needed {
        return errno(ERANGE);
    }
    let mut out = Vec::with_capacity(needed);
    out.extend_from_slice(visible.as_bytes());
    out.push(0);
    match memory.write(buf, &out) {
        Ok(()) => needed as u64,
        Err(_) => errno(EFAULT),
    }
}

pub(super) async fn read_file<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    entry: &Entry<R>,
    buf: u64,
    count: u64,
    explicit_offset: Option<i64>,
    memory: &mut M,
    fs: &mut F,
) -> u64 {
    if entry.fdflags() & FDFLAG_PATH != 0 {
        return errno(EBADF);
    }
    let Some(open) = entry_file::<R>(entry) else {
        return errno(EBADF);
    };
    if !fs.file_access(open.node()).readable() {
        return errno(EBADF);
    }
    if fs.file_is_directory(open.node()) {
        return errno(EISDIR);
    }
    if let Some(off) = explicit_offset
        && off < 0
    {
        return errno(EINVAL);
    }
    let limit = count.min(MAX_RW_COUNT) as usize;
    if limit == 0 {
        return 0;
    }
    if buf.checked_add(limit as u64).is_none() {
        return errno(EFAULT);
    }
    // Ensure any dirty MAP_SHARED pages for this file are visible to `read`.
    memory::flush_file_shared_mappings(process, open.node(), memory, fs).await;

    const CHUNK: usize = 64 * 1024;
    if let Some(off) = explicit_offset {
        let mut done = 0usize;
        while done < limit {
            let want = (limit - done).min(CHUNK);
            let bytes = match fs
                .read_at(open.node(), (off as u64).saturating_add(done as u64), want)
                .await
            {
                Ok(bytes) => bytes,
                Err(error) => {
                    return if done == 0 {
                        fs_errno(error)
                    } else {
                        done as u64
                    };
                }
            };
            if bytes.is_empty() {
                break;
            }
            if memory.write(buf + done as u64, &bytes).is_err() {
                return if done == 0 {
                    errno(EFAULT)
                } else {
                    done as u64
                };
            }
            done += bytes.len();
            if bytes.len() < want {
                break;
            }
        }
        done as u64
    } else {
        let mut pos = open.lock_position().await;
        let mut done = 0usize;
        while done < limit {
            let want = (limit - done).min(CHUNK);
            let start = pos.get();
            let bytes = match fs.read_at(open.node(), start, want).await {
                Ok(bytes) => bytes,
                Err(error) => {
                    return if done == 0 {
                        fs_errno(error)
                    } else {
                        done as u64
                    };
                }
            };
            if bytes.is_empty() {
                break;
            }
            if memory.write(buf + done as u64, &bytes).is_err() {
                return if done == 0 {
                    errno(EFAULT)
                } else {
                    done as u64
                };
            }
            pos.set(start.saturating_add(bytes.len() as u64));
            done += bytes.len();
            if bytes.len() < want {
                break;
            }
        }
        done as u64
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn write_file<R: Resources, M: VirtualMemory, F: Filesystem<R>>(
    process: &Process<R>,
    entry: &Entry<R>,
    buf: u64,
    count: u64,
    explicit_offset: Option<i64>,
    extra_rwf: u64,
    memory: &mut M,
    fs: &mut F,
) -> u64 {
    if entry.fdflags() & FDFLAG_PATH != 0 {
        return errno(EBADF);
    }
    let Some(open) = entry_file::<R>(entry) else {
        return errno(EBADF);
    };
    if !fs.file_access(open.node()).writable() {
        return errno(EBADF);
    }
    if fs.file_is_directory(open.node()) {
        return errno(EISDIR);
    }
    if let Some(off) = explicit_offset
        && off < 0
    {
        return errno(EINVAL);
    }
    let total_req = count.min(MAX_RW_COUNT);
    if buf.checked_add(total_req).is_none() {
        return errno(EFAULT);
    }
    let fdflags = entry.fdflags();
    let append = (fdflags & FDFLAG_APPEND != 0) || (extra_rwf & RWF_APPEND != 0);
    let creds = process_creds(process);
    let mut chunk = [0u8; 4096];
    let mut written = 0u64;

    if let Some(off) = explicit_offset {
        while written < total_req {
            let addr = buf + written;
            let page_rem = chunk.len() - (addr as usize & (chunk.len() - 1));
            let size = (total_req - written).min(page_rem as u64) as usize;
            if memory.read(addr, &mut chunk[..size]).is_err() {
                return if written == 0 { errno(EFAULT) } else { written };
            }
            let position = if append {
                WritePosition::End
            } else {
                WritePosition::At((off as u64).saturating_add(written))
            };
            let landed = match fs
                .write_at(open.node(), position, &chunk[..size], &creds)
                .await
            {
                Ok(landed) => landed,
                Err(error) => {
                    return if written == 0 {
                        fs_errno(error)
                    } else {
                        written
                    };
                }
            };
            if landed.len > 0 {
                memory::sync_write_to_shared_mappings(
                    process,
                    open.node(),
                    landed.offset,
                    &chunk[..landed.len],
                    memory,
                    fs,
                );
            }
            written += landed.len as u64;
            if landed.len < size {
                break;
            }
        }
    } else {
        let mut pos = open.lock_position().await;
        while written < total_req {
            let addr = buf + written;
            let page_rem = chunk.len() - (addr as usize & (chunk.len() - 1));
            let size = (total_req - written).min(page_rem as u64) as usize;
            if memory.read(addr, &mut chunk[..size]).is_err() {
                return if written == 0 { errno(EFAULT) } else { written };
            }
            let position = if append {
                WritePosition::End
            } else {
                WritePosition::At(pos.get())
            };
            let landed = match fs
                .write_at(open.node(), position, &chunk[..size], &creds)
                .await
            {
                Ok(landed) => landed,
                Err(error) => {
                    return if written == 0 {
                        fs_errno(error)
                    } else {
                        written
                    };
                }
            };
            if let Some(end) = landed.end() {
                pos.set(end);
            }
            if landed.len > 0 {
                memory::sync_write_to_shared_mappings(
                    process,
                    open.node(),
                    landed.offset,
                    &chunk[..landed.len],
                    memory,
                    fs,
                );
            }
            written += landed.len as u64;
            if landed.len < size {
                break;
            }
        }
    }

    let want_sync = (fdflags & FDFLAG_SYNC != 0) || (extra_rwf & RWF_SYNC != 0);
    let want_dsync = (fdflags & FDFLAG_DSYNC != 0) || (extra_rwf & RWF_DSYNC != 0);
    if (want_sync || want_dsync)
        && let Err(error) = fs.sync(open.node(), !want_sync).await
    {
        return if written > 0 {
            written
        } else {
            fs_errno(error)
        };
    }
    written
}

pub(super) async fn pread64<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    fs: &mut F,
) -> u64 {
    let Some(entry) = process
        .shared
        .descriptors
        .lock()
        .get_entry(args[0] as u32 as i32)
        .cloned()
    else {
        return errno(EBADF);
    };
    if entry_file::<R>(&entry).is_none() {
        return errno(ESPIPE);
    }
    read_file(
        process,
        &entry,
        args[1],
        args[2],
        Some(args[3] as i64),
        memory,
        fs,
    )
    .await
}

pub(super) async fn pwrite64<R: Resources, M: VirtualMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    fs: &mut F,
) -> u64 {
    let Some(entry) = process
        .shared
        .descriptors
        .lock()
        .get_entry(args[0] as u32 as i32)
        .cloned()
    else {
        return errno(EBADF);
    };
    if entry_file::<R>(&entry).is_none() {
        return errno(ESPIPE);
    }
    write_file(
        process,
        &entry,
        args[1],
        args[2],
        Some(args[3] as i64),
        0,
        memory,
        fs,
    )
    .await
}

fn read_iovecs<M: UserMemory>(
    memory: &M,
    iov_ptr: u64,
    iovcnt: u64,
) -> Result<Vec<(u64, u64)>, u64> {
    let count = iovcnt as u32;
    if count > 1024 {
        return Err(errno(EINVAL));
    }
    if count == 0 {
        return Ok(Vec::new());
    }
    if iov_ptr.checked_add(u64::from(count) * 16).is_none() {
        return Err(errno(EFAULT));
    }
    let mut iovs = Vec::with_capacity(count as usize);
    let mut raw = [0u8; 16];
    for index in 0..count {
        if memory
            .read(iov_ptr + u64::from(index) * 16, &mut raw)
            .is_err()
        {
            return Err(errno(EFAULT));
        }
        let base = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let len = u64::from_le_bytes(raw[8..16].try_into().unwrap());
        if len > i64::MAX as u64 {
            return Err(errno(EINVAL));
        }
        iovs.push((base, len));
    }
    Ok(iovs)
}

pub(super) async fn readv_common<
    R: Resources,
    M: UserMemory,
    O: Stdio + Filesystem<R> + Network<R::Network>,
>(
    process: &Process<R>,
    args: [u64; 6],
    explicit_offset: Option<i64>,
    rwf_flags: u64,
    memory: &mut M,
    output: &mut O,
) -> SyscallOutcome {
    if rwf_flags & !(RWF_HIPRI | RWF_NOWAIT) != 0 {
        return SyscallOutcome::Return(errno(EOPNOTSUPP));
    }
    let Some(entry) = process
        .shared
        .descriptors
        .lock()
        .get_entry(args[0] as u32 as i32)
        .cloned()
    else {
        return SyscallOutcome::Return(errno(EBADF));
    };
    if explicit_offset.is_some() && entry_file::<R>(&entry).is_none() {
        return SyscallOutcome::Return(errno(ESPIPE));
    }
    if let Some(off) = explicit_offset
        && off < 0
    {
        return SyscallOutcome::Return(errno(EINVAL));
    }
    let iovs = match read_iovecs(memory, args[1], args[2]) {
        Ok(iovs) => iovs,
        Err(err) => return SyscallOutcome::Return(err),
    };
    if iovs.is_empty() {
        // Still validate readable/directory errors on files.
        if let Some(open) = entry_file::<R>(&entry) {
            if entry.fdflags() & FDFLAG_PATH != 0 || !output.file_access(open.node()).readable() {
                return SyscallOutcome::Return(errno(EBADF));
            }
            if output.file_is_directory(open.node()) {
                return SyscallOutcome::Return(errno(EISDIR));
            }
        }
        return SyscallOutcome::Return(0);
    }
    if let FileDescriptor::Socket(sock) = &entry.descriptor {
        let mut total = 0usize;
        for &(base, len) in &iovs {
            let take = len.min(MAX_RW_COUNT - total as u64) as usize;
            if take > 0 && memory.check_writable(base, take).is_err() {
                return SyscallOutcome::Return(errno(EFAULT));
            }
            total = total.saturating_add(take);
            if total as u64 >= MAX_RW_COUNT {
                break;
            }
        }
        let recv = match super::socket::socket_recv(sock, total, 0, output).await {
            Ok(recv) => recv,
            Err(err) => return SyscallOutcome::Return(errno(err)),
        };
        let mut offset = 0usize;
        for (base, len) in iovs {
            if offset >= recv.data.len() {
                break;
            }
            let take = (len as usize).min(recv.data.len() - offset);
            if take > 0 {
                if memory
                    .write(base, &recv.data[offset..offset + take])
                    .is_err()
                {
                    return SyscallOutcome::Return(if offset == 0 {
                        errno(EFAULT)
                    } else {
                        offset as u64
                    });
                }
                offset += take;
            }
        }
        return SyscallOutcome::Return(offset as u64);
    }
    let mut done = 0u64;
    let mut cur_off = explicit_offset;
    for (base, len) in iovs {
        if done == MAX_RW_COUNT {
            break;
        }
        let len = len.min(MAX_RW_COUNT - done);
        if len == 0 {
            continue;
        }
        let outcome = if entry_file::<R>(&entry).is_some() {
            SyscallOutcome::Return(
                read_file(process, &entry, base, len, cur_off, memory, output).await,
            )
        } else {
            super::read(process, [args[0], base, len, 0, 0, 0], memory, output).await
        };
        let res = match outcome {
            SyscallOutcome::Return(res) => res,
            interrupted => {
                return if done == 0 {
                    interrupted
                } else {
                    SyscallOutcome::Return(done)
                };
            }
        };
        if (res as i64) < 0 {
            return SyscallOutcome::Return(if done == 0 { res } else { done });
        }
        done += res;
        if let Some(ref mut off) = cur_off {
            *off = off.saturating_add(res as i64);
        }
        if res < len {
            break;
        }
    }
    SyscallOutcome::Return(done)
}

pub(super) async fn writev_common<
    R: Resources,
    M: VirtualMemory,
    O: Stdio + Filesystem<R> + Network<R::Network>,
>(
    process: &Process<R>,
    args: [u64; 6],
    explicit_offset: Option<i64>,
    rwf_flags: u64,
    memory: &mut M,
    output: &mut O,
) -> SyscallOutcome {
    if rwf_flags & !(RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND) != 0 {
        return SyscallOutcome::Return(errno(EOPNOTSUPP));
    }
    let Some(entry) = process
        .shared
        .descriptors
        .lock()
        .get_entry(args[0] as u32 as i32)
        .cloned()
    else {
        return SyscallOutcome::Return(errno(EBADF));
    };
    if explicit_offset.is_some() && entry_file::<R>(&entry).is_none() {
        return SyscallOutcome::Return(errno(ESPIPE));
    }
    if let Some(off) = explicit_offset
        && off < 0
    {
        return SyscallOutcome::Return(errno(EINVAL));
    }
    let iovs = match read_iovecs(memory, args[1], args[2]) {
        Ok(iovs) => iovs,
        Err(err) => return SyscallOutcome::Return(err),
    };
    if iovs.is_empty() {
        if let Some(open) = entry_file::<R>(&entry) {
            if entry.fdflags() & FDFLAG_PATH != 0 || !output.file_access(open.node()).writable() {
                return SyscallOutcome::Return(errno(EBADF));
            }
            if output.file_is_directory(open.node()) {
                return SyscallOutcome::Return(errno(EISDIR));
            }
        }
        return SyscallOutcome::Return(0);
    }
    if let FileDescriptor::Socket(sock) = &entry.descriptor {
        let mut data = Vec::new();
        let mut chunk = [0u8; 4096];
        for (base, len) in iovs {
            let remaining = MAX_RW_COUNT.saturating_sub(data.len() as u64);
            if remaining == 0 {
                break;
            }
            let take = len.min(remaining) as usize;
            let mut copied = 0usize;
            while copied < take {
                let step = (take - copied).min(chunk.len());
                let Some(addr) = base.checked_add(copied as u64) else {
                    return SyscallOutcome::Return(errno(EFAULT));
                };
                if memory.read(addr, &mut chunk[..step]).is_err() {
                    return SyscallOutcome::Return(errno(EFAULT));
                }
                data.extend_from_slice(&chunk[..step]);
                copied += step;
            }
        }
        let ctx = super::socket_context(process);
        return SyscallOutcome::Return(
            match super::socket::socket_send(sock, data, 0, None, ctx, output).await {
                Ok(written) => written as u64,
                Err(err) => errno(err),
            },
        );
    }
    let mut done = 0u64;
    let mut cur_off = explicit_offset;
    for (base, len) in iovs {
        if done == MAX_RW_COUNT {
            break;
        }
        let len = len.min(MAX_RW_COUNT - done);
        if len == 0 {
            continue;
        }
        let outcome = if entry_file::<R>(&entry).is_some() {
            SyscallOutcome::Return(
                write_file(
                    process, &entry, base, len, cur_off, rwf_flags, memory, output,
                )
                .await,
            )
        } else {
            super::write(process, [args[0], base, len, 0, 0, 0], memory, output).await
        };
        let res = match outcome {
            SyscallOutcome::Return(res) => res,
            interrupted => {
                return if done == 0 {
                    interrupted
                } else {
                    SyscallOutcome::Return(done)
                };
            }
        };
        if (res as i64) < 0 {
            return SyscallOutcome::Return(if done == 0 { res } else { done });
        }
        done += res;
        if let Some(ref mut off) = cur_off {
            *off = off.saturating_add(res as i64);
        }
        if res < len {
            break;
        }
    }
    SyscallOutcome::Return(done)
}

pub(super) async fn lseek<R: Resources, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    fs: &F,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let offset = args[1] as i64;
    let whence = args[2] as u32;
    let Some(entry) = process.shared.descriptors.lock().get_entry(fd).cloned() else {
        return errno(EBADF);
    };
    if entry.fdflags() & FDFLAG_PATH != 0 {
        return errno(EBADF);
    }
    if matches!(entry.descriptor, FileDescriptor::NullDevice) {
        return 0;
    }
    let Some(open) = entry_file::<R>(&entry) else {
        return errno(ESPIPE);
    };
    let mut pos = open.lock_position().await;
    let next: i64 = match whence {
        // SEEK_SET
        0 => offset,
        // SEEK_CUR
        1 => match (pos.get() as i64).checked_add(offset) {
            Some(v) => v,
            None => return errno(EOVERFLOW),
        },
        // SEEK_END
        2 => {
            let size = match fs.stat_file(open.node()).await {
                Ok(stat) => stat.size as i64,
                Err(error) => return fs_errno(error),
            };
            match size.checked_add(offset) {
                Some(v) => v,
                None => return errno(EOVERFLOW),
            }
        }
        // SEEK_DATA (3) / SEEK_HOLE (4)
        3 | 4 => {
            let size = match fs.stat_file(open.node()).await {
                Ok(stat) => stat.size as i64,
                Err(error) => return fs_errno(error),
            };
            if offset < 0 || offset >= size {
                return errno(ENXIO);
            }
            if whence == 3 { offset } else { size }
        }
        _ => return errno(EINVAL),
    };
    if next < 0 {
        return errno(EINVAL);
    }
    pos.set(next as u64);
    next as u64
}

fn node_d_type(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::Fifo => DT_FIFO,
        NodeKind::CharacterDevice => DT_CHR,
        NodeKind::Directory => DT_DIR,
        NodeKind::BlockDevice => DT_BLK,
        NodeKind::File => DT_REG,
        NodeKind::Symlink => DT_LNK,
        NodeKind::Socket => DT_SOCK,
    }
}

pub(super) async fn getdents64<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    fs: &F,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let dirp = args[1];
    let count = args[2] as u32 as usize;
    let Some(entry) = process.shared.descriptors.lock().get_entry(fd).cloned() else {
        return errno(EBADF);
    };
    if entry.fdflags() & FDFLAG_PATH != 0 {
        return errno(EBADF);
    }
    let Some(open) = entry_file::<R>(&entry) else {
        return errno(ENOTDIR);
    };
    if !fs.file_access(open.node()).readable() {
        return errno(EBADF);
    }
    if !fs.file_is_directory(open.node()) {
        return errno(ENOTDIR);
    }
    let (self_ino, parent_ino, listed) = match fs.list_dir(open.node()).await {
        Ok(res) => res,
        Err(error) => return fs_errno(error),
    };
    let mut pos = open.lock_position().await;
    let start_index = pos.get() as usize;
    let total_entries = 2 + listed.len();
    if start_index >= total_entries {
        return 0;
    }

    let mut written = 0usize;
    let mut idx = start_index;
    while idx < total_entries {
        let (ino, d_type, name): (u64, u8, &[u8]) = if idx == 0 {
            (self_ino, DT_DIR, b".")
        } else if idx == 1 {
            (parent_ino, DT_DIR, b"..")
        } else {
            let e = &listed[idx - 2];
            (e.inode, node_d_type(e.kind), e.name.as_bytes())
        };
        // struct linux_dirent64: d_ino (8) + d_off (8) + d_reclen (2) + d_type (1) + name + NUL,
        // padded to 8-byte alignment.
        let raw_len = 19 + name.len() + 1;
        let reclen = (raw_len + 7) & !7;
        if written + reclen > count {
            if written == 0 {
                return errno(EINVAL);
            }
            break;
        }
        let mut record = alloc::vec![0u8; reclen];
        let next_off = (idx + 1) as i64;
        record[0..8].copy_from_slice(&ino.to_le_bytes());
        record[8..16].copy_from_slice(&next_off.to_le_bytes());
        record[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
        record[18] = d_type;
        record[19..19 + name.len()].copy_from_slice(name);
        if memory
            .write(dirp.wrapping_add(written as u64), &record)
            .is_err()
        {
            return if written == 0 {
                errno(EFAULT)
            } else {
                pos.set(idx as u64);
                written as u64
            };
        }
        written += reclen;
        idx += 1;
    }
    pos.set(idx as u64);
    written as u64
}

pub(super) async fn ftruncate<R: Resources, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    fs: &mut F,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let length = args[1] as i64;
    if length < 0 {
        return errno(EINVAL);
    }
    let Some(entry) = process.shared.descriptors.lock().get_entry(fd).cloned() else {
        return errno(EBADF);
    };
    if entry.fdflags() & FDFLAG_PATH != 0 {
        return errno(EBADF);
    }
    let Some(open) = entry_file::<R>(&entry) else {
        return errno(EINVAL);
    };
    if !fs.file_access(open.node()).writable() || fs.file_is_directory(open.node()) {
        return errno(EINVAL);
    }
    let creds = process_creds(process);
    match fs.set_size_file(open.node(), length as u64, &creds).await {
        Ok(()) => 0,
        Err(error) => fs_errno(error),
    }
}

pub(super) async fn truncate<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    let length = args[1] as i64;
    if length < 0 {
        return errno(EINVAL);
    }
    let path = match read_user_path(memory, args[0]) {
        Ok(path) => path,
        Err(err) => return err,
    };
    if path.is_empty() {
        return errno(ENOENT);
    }
    let creds = process_creds(process);
    let (cwd, resolved_path) = match resolve_in_chroot(process, None, &path, true, &creds, fs).await
    {
        Ok(pair) => pair,
        Err(err) => return err,
    };
    match fs
        .set_size_path(&cwd, &resolved_path, length as u64, &creds)
        .await
    {
        Ok(()) => 0,
        Err(error) => fs_errno(error),
    }
}

pub(super) async fn fsync<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    data_only: bool,
    memory: &mut M,
    fs: &mut F,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let Some(entry) = process.shared.descriptors.lock().get_entry(fd).cloned() else {
        return errno(EBADF);
    };
    if entry.fdflags() & FDFLAG_PATH != 0 {
        return errno(EBADF);
    }
    let Some(open) = entry_file::<R>(&entry) else {
        return errno(EINVAL);
    };
    memory::flush_file_shared_mappings(process, open.node(), memory, fs).await;
    match fs.sync(open.node(), data_only).await {
        Ok(()) => 0,
        Err(error) => fs_errno(error),
    }
}

pub(super) fn close_range<R: Resources, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    fs: &F,
) -> u64 {
    let first = args[0] as u32;
    let last = args[1] as u32;
    let flags = args[2] as u32 as u64;
    if flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 || first > last {
        return errno(EINVAL);
    }
    let mut closed_entries = Vec::new();
    {
        let mut table = process.shared.descriptors.lock();
        let len = table.entries.len();
        let start = (first as usize).min(len);
        let end = (last as usize).min(len.saturating_sub(1));
        if start >= len {
            return 0;
        }
        if flags & CLOSE_RANGE_CLOEXEC != 0 {
            for slot in &mut table.entries[start..=end] {
                if let Some(entry) = slot.as_mut() {
                    entry.close_on_exec = true;
                }
            }
        } else {
            for fd in start..=end {
                if let Some(entry) = table.entries[fd].clone() {
                    let _ = table.close(fd as i32);
                    closed_entries.push(entry);
                }
            }
        }
    }
    for entry in &closed_entries {
        super::fs_extra::release_posix_locks_for_entry(process, entry, fs);
    }
    0
}

pub(super) async fn fchmodat2<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    has_flags: bool,
    memory: &M,
    fs: &mut F,
) -> u64 {
    let dirfd = args[0] as u32 as i32;
    let mode = (args[2] as u32) & permissions::S_IALLUGO;
    let flags = if has_flags { args[3] as u32 as u64 } else { 0 };
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return errno(EINVAL);
    }
    let path = match read_user_path(memory, args[1]) {
        Ok(path) => path,
        Err(err) => return err,
    };
    let creds = process_creds(process);
    if path.is_empty() {
        if flags & AT_EMPTY_PATH == 0 {
            return errno(ENOENT);
        }
        if dirfd == AT_FDCWD {
            let cwd = process.shared.cwd.lock().clone();
            return match fs.chmod_path(None, &cwd, "", true, mode, &creds).await {
                Ok(()) => 0,
                Err(error) => fs_errno(error),
            };
        }
        let Some(entry) = process.shared.descriptors.lock().get_entry(dirfd).cloned() else {
            return errno(EBADF);
        };
        let Some(open) = entry_file::<R>(&entry) else {
            return errno(EINVAL);
        };
        return match fs.chmod_file(open.node(), mode, &creds).await {
            Ok(()) => 0,
            Err(error) => fs_errno(error),
        };
    }
    let base = match dirfd_file(process, dirfd, &path, false, fs) {
        Ok(base) => base,
        Err(err) => return err,
    };
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let (cwd, resolved_path) =
        match resolve_in_chroot(process, base.as_ref(), &path, follow, &creds, fs).await {
            Ok(pair) => pair,
            Err(err) => return err,
        };
    let eff_base = if resolved_path.starts_with('/') {
        None
    } else {
        base.as_ref()
    };
    match fs
        .chmod_path(eff_base, &cwd, &resolved_path, follow, mode, &creds)
        .await
    {
        Ok(()) => 0,
        Err(error) => fs_errno(error),
    }
}

pub(super) async fn chmod<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    fchmodat2(
        process,
        [AT_FDCWD as u32 as u64, args[0], args[1], 0, 0, 0],
        false,
        memory,
        fs,
    )
    .await
}

pub(super) async fn fchmod<R: Resources, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    fs: &mut F,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let mode = (args[1] as u32) & permissions::S_IALLUGO;
    let Some(entry) = process.shared.descriptors.lock().get_entry(fd).cloned() else {
        return errno(EBADF);
    };
    if entry.fdflags() & FDFLAG_PATH != 0 {
        return errno(EBADF);
    }
    let creds = process_creds(process);
    if let FileDescriptor::PipeRead { inode, .. } | FileDescriptor::PipeWrite { inode, .. } =
        &entry.descriptor
    {
        let attrs = inode.attrs();
        let meta = permissions::InodeMeta {
            kind: NodeKind::Fifo,
            uid: attrs.uid,
            gid: attrs.gid,
            mode: attrs.mode,
        };
        return match permissions::check_chmod(&creds, meta, mode) {
            Ok(new_mode) => {
                inode.set_mode(new_mode);
                0
            }
            Err(error) => fs_errno(error),
        };
    }
    let Some(open) = entry_file::<R>(&entry) else {
        return errno(EINVAL);
    };
    match fs.chmod_file(open.node(), mode, &creds).await {
        Ok(()) => 0,
        Err(error) => fs_errno(error),
    }
}

pub(super) async fn fchownat<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    let dirfd = args[0] as u32 as i32;
    let uid_raw = args[2] as u32;
    let gid_raw = args[3] as u32;
    let flags = args[4] as u32 as u64;
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return errno(EINVAL);
    }
    let uid = (uid_raw != u32::MAX).then_some(uid_raw);
    let gid = (gid_raw != u32::MAX).then_some(gid_raw);
    let path = match read_user_path(memory, args[1]) {
        Ok(path) => path,
        Err(err) => return err,
    };
    let creds = process_creds(process);
    if path.is_empty() {
        if flags & AT_EMPTY_PATH == 0 {
            return errno(ENOENT);
        }
        if dirfd == AT_FDCWD {
            let cwd = process.shared.cwd.lock().clone();
            return match fs.chown_path(None, &cwd, "", true, uid, gid, &creds).await {
                Ok(()) => 0,
                Err(error) => fs_errno(error),
            };
        }
        let Some(entry) = process.shared.descriptors.lock().get_entry(dirfd).cloned() else {
            return errno(EBADF);
        };
        if let FileDescriptor::PipeRead { inode, .. } | FileDescriptor::PipeWrite { inode, .. } =
            &entry.descriptor
        {
            return chown_pipe(inode, &creds, uid, gid);
        }
        let Some(open) = entry_file::<R>(&entry) else {
            return errno(EINVAL);
        };
        return match fs.chown_file(open.node(), uid, gid, &creds).await {
            Ok(()) => 0,
            Err(error) => fs_errno(error),
        };
    }
    let base = match dirfd_file(process, dirfd, &path, false, fs) {
        Ok(base) => base,
        Err(err) => return err,
    };
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let (cwd, resolved_path) =
        match resolve_in_chroot(process, base.as_ref(), &path, follow, &creds, fs).await {
            Ok(pair) => pair,
            Err(err) => return err,
        };
    let eff_base = if resolved_path.starts_with('/') {
        None
    } else {
        base.as_ref()
    };
    match fs
        .chown_path(eff_base, &cwd, &resolved_path, follow, uid, gid, &creds)
        .await
    {
        Ok(()) => 0,
        Err(error) => fs_errno(error),
    }
}

fn chown_pipe(
    inode: &helios_unix::PipeInode,
    creds: &Credentials,
    uid: Option<u32>,
    gid: Option<u32>,
) -> u64 {
    let attrs = inode.attrs();
    let meta = permissions::InodeMeta {
        kind: NodeKind::Fifo,
        uid: attrs.uid,
        gid: attrs.gid,
        mode: attrs.mode,
    };
    match permissions::check_chown(creds, meta, uid, gid) {
        Ok(result) => {
            let mut new_mode = attrs.mode;
            if result.kill_privs {
                new_mode &= !permissions::S_ISUID;
                if new_mode & permissions::S_IXGRP != 0 {
                    new_mode &= !permissions::S_ISGID;
                }
            }
            inode.set_owner_and_mode(
                result.uid.unwrap_or(attrs.uid),
                result.gid.unwrap_or(attrs.gid),
                new_mode,
            );
            0
        }
        Err(error) => fs_errno(error),
    }
}

pub(super) async fn chown<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    follow: bool,
    memory: &M,
    fs: &mut F,
) -> u64 {
    let flags = if follow { 0 } else { AT_SYMLINK_NOFOLLOW };
    fchownat(
        process,
        [AT_FDCWD as u32 as u64, args[0], args[1], args[2], flags, 0],
        memory,
        fs,
    )
    .await
}

pub(super) async fn fchown<R: Resources, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    fs: &mut F,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let uid_raw = args[1] as u32;
    let gid_raw = args[2] as u32;
    let uid = (uid_raw != u32::MAX).then_some(uid_raw);
    let gid = (gid_raw != u32::MAX).then_some(gid_raw);
    let Some(entry) = process.shared.descriptors.lock().get_entry(fd).cloned() else {
        return errno(EBADF);
    };
    if entry.fdflags() & FDFLAG_PATH != 0 {
        return errno(EBADF);
    }
    let creds = process_creds(process);
    if let FileDescriptor::PipeRead { inode, .. } | FileDescriptor::PipeWrite { inode, .. } =
        &entry.descriptor
    {
        return chown_pipe(inode, &creds, uid, gid);
    }
    let Some(open) = entry_file::<R>(&entry) else {
        return errno(EINVAL);
    };
    match fs.chown_file(open.node(), uid, gid, &creds).await {
        Ok(()) => 0,
        Err(error) => fs_errno(error),
    }
}

pub(super) async fn mknodat<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    let dirfd = args[0] as u32 as i32;
    let path = match read_user_path(memory, args[1]) {
        Ok(path) => path,
        Err(err) => return err,
    };
    if path.is_empty() {
        return errno(ENOENT);
    }
    let raw_mode = args[2] as u32;
    let rdev = args[3] as u32 as u64;
    let creds = process_creds(process);
    let kind = match permissions::check_mknod(&creds, raw_mode) {
        Ok(kind) => kind,
        Err(error) => return fs_errno(error),
    };
    let umask = process.shared.attributes.lock().umask;
    let mode = raw_mode & permissions::S_IALLUGO;
    let base = match dirfd_file(process, dirfd, &path, false, fs) {
        Ok(base) => base,
        Err(err) => return err,
    };
    let (cwd, resolved_path) =
        match resolve_in_chroot(process, base.as_ref(), &path, false, &creds, fs).await {
            Ok(pair) => pair,
            Err(err) => return err,
        };
    let eff_base = if resolved_path.starts_with('/') {
        None
    } else {
        base.as_ref()
    };
    match fs
        .mknod(
            eff_base,
            &cwd,
            &resolved_path,
            kind,
            mode,
            umask,
            rdev,
            &creds,
        )
        .await
    {
        Ok(()) => 0,
        Err(error) => fs_errno(error),
    }
}

pub(super) async fn mknod<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    mknodat(
        process,
        [AT_FDCWD as u32 as u64, args[0], args[1], args[2], 0, 0],
        memory,
        fs,
    )
    .await
}

fn parse_xattr_flags(flags: u64) -> Result<XattrSetMode, u64> {
    match flags {
        0 => Ok(XattrSetMode::CreateOrReplace),
        XATTR_CREATE => Ok(XattrSetMode::Create),
        XATTR_REPLACE => Ok(XattrSetMode::Replace),
        _ => Err(errno(EINVAL)),
    }
}

pub(super) async fn setxattr_path<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    follow: bool,
    memory: &M,
    fs: &mut F,
) -> u64 {
    let path = match read_user_path(memory, args[0]) {
        Ok(path) => path,
        Err(err) => return err,
    };
    if path.is_empty() {
        return errno(ENOENT);
    }
    // `fs/xattr.c` `setxattr_copy`: validate `flags` before copying `name`.
    let mode = match parse_xattr_flags(args[4] as u32 as u64) {
        Ok(mode) => mode,
        Err(err) => return err,
    };
    let name = match read_xattr_name(memory, args[1]) {
        Ok(name) => name,
        Err(err) => return err,
    };
    let size = args[3];
    if size > permissions::XATTR_SIZE_MAX as u64 {
        return errno(E2BIG);
    }
    let mut value = alloc::vec![0u8; size as usize];
    if !value.is_empty() && memory.read(args[2], &mut value).is_err() {
        return errno(EFAULT);
    }
    let creds = process_creds(process);
    let (cwd, resolved_path) =
        match resolve_in_chroot(process, None, &path, follow, &creds, fs).await {
            Ok(pair) => pair,
            Err(err) => return err,
        };
    match fs
        .set_xattr_path(&cwd, &resolved_path, follow, &name, &value, mode, &creds)
        .await
    {
        Ok(()) => 0,
        Err(error) => fs_errno(error),
    }
}

pub(super) async fn fsetxattr<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    let fd = args[0] as u32 as i32;
    // `fs/xattr.c` `setxattr_copy`: validate `flags` before copying `name`.
    let mode = match parse_xattr_flags(args[4] as u32 as u64) {
        Ok(mode) => mode,
        Err(err) => return err,
    };
    let name = match read_xattr_name(memory, args[1]) {
        Ok(name) => name,
        Err(err) => return err,
    };
    let size = args[3];
    if size > permissions::XATTR_SIZE_MAX as u64 {
        return errno(E2BIG);
    }
    let mut value = alloc::vec![0u8; size as usize];
    if !value.is_empty() && memory.read(args[2], &mut value).is_err() {
        return errno(EFAULT);
    }
    let Some(entry) = process.shared.descriptors.lock().get_entry(fd).cloned() else {
        return errno(EBADF);
    };
    if entry.fdflags() & FDFLAG_PATH != 0 {
        return errno(EBADF);
    }
    let Some(open) = entry_file::<R>(&entry) else {
        return errno(EOPNOTSUPP);
    };
    let creds = process_creds(process);
    match fs
        .set_xattr_file(open.node(), &name, &value, mode, &creds)
        .await
    {
        Ok(()) => 0,
        Err(error) => fs_errno(error),
    }
}

fn finish_xattr_read<M: UserMemory>(memory: &mut M, buf: u64, size: u64, data: &[u8]) -> u64 {
    if size == 0 {
        return data.len() as u64;
    }
    if (data.len() as u64) > size {
        return errno(ERANGE);
    }
    if !data.is_empty() && memory.write(buf, data).is_err() {
        return errno(EFAULT);
    }
    data.len() as u64
}

pub(super) async fn getxattr_path<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    follow: bool,
    memory: &mut M,
    fs: &F,
) -> u64 {
    let path = match read_user_path(memory, args[0]) {
        Ok(path) => path,
        Err(err) => return err,
    };
    if path.is_empty() {
        return errno(ENOENT);
    }
    let name = match read_xattr_name(memory, args[1]) {
        Ok(name) => name,
        Err(err) => return err,
    };
    let creds = process_creds(process);
    let (cwd, resolved_path) =
        match resolve_in_chroot(process, None, &path, follow, &creds, fs).await {
            Ok(pair) => pair,
            Err(err) => return err,
        };
    match fs
        .get_xattr_path(&cwd, &resolved_path, follow, &name, &creds)
        .await
    {
        Ok(data) => finish_xattr_read(memory, args[2], args[3], &data),
        Err(error) => fs_errno(error),
    }
}

pub(super) async fn fgetxattr<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    fs: &F,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let name = match read_xattr_name(memory, args[1]) {
        Ok(name) => name,
        Err(err) => return err,
    };
    let Some(entry) = process.shared.descriptors.lock().get_entry(fd).cloned() else {
        return errno(EBADF);
    };
    if entry.fdflags() & FDFLAG_PATH != 0 {
        return errno(EBADF);
    }
    let Some(open) = entry_file::<R>(&entry) else {
        return errno(EOPNOTSUPP);
    };
    let creds = process_creds(process);
    match fs.get_xattr_file(open.node(), &name, &creds).await {
        Ok(data) => finish_xattr_read(memory, args[2], args[3], &data),
        Err(error) => fs_errno(error),
    }
}

fn pack_xattr_list(names: Vec<String>) -> Result<Vec<u8>, u64> {
    let total: usize = names.iter().map(|n| n.len() + 1).sum();
    if total > permissions::XATTR_LIST_MAX {
        return Err(errno(E2BIG));
    }
    let mut packed = Vec::with_capacity(total);
    for name in names {
        packed.extend_from_slice(name.as_bytes());
        packed.push(0);
    }
    Ok(packed)
}

pub(super) async fn listxattr_path<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    follow: bool,
    memory: &mut M,
    fs: &F,
) -> u64 {
    let path = match read_user_path(memory, args[0]) {
        Ok(path) => path,
        Err(err) => return err,
    };
    if path.is_empty() {
        return errno(ENOENT);
    }
    let creds = process_creds(process);
    let (cwd, resolved_path) =
        match resolve_in_chroot(process, None, &path, follow, &creds, fs).await {
            Ok(pair) => pair,
            Err(err) => return err,
        };
    let names = match fs
        .list_xattrs_path(&cwd, &resolved_path, follow, &creds)
        .await
    {
        Ok(names) => names,
        Err(error) => return fs_errno(error),
    };
    let packed = match pack_xattr_list(names) {
        Ok(packed) => packed,
        Err(err) => return err,
    };
    finish_xattr_read(memory, args[1], args[2], &packed)
}

pub(super) async fn flistxattr<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    fs: &F,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let Some(entry) = process.shared.descriptors.lock().get_entry(fd).cloned() else {
        return errno(EBADF);
    };
    if entry.fdflags() & FDFLAG_PATH != 0 {
        return errno(EBADF);
    }
    let Some(open) = entry_file::<R>(&entry) else {
        return errno(EOPNOTSUPP);
    };
    let creds = process_creds(process);
    let names = match fs.list_xattrs_file(open.node(), &creds).await {
        Ok(names) => names,
        Err(error) => return fs_errno(error),
    };
    let packed = match pack_xattr_list(names) {
        Ok(packed) => packed,
        Err(err) => return err,
    };
    finish_xattr_read(memory, args[1], args[2], &packed)
}

pub(super) async fn removexattr_path<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    follow: bool,
    memory: &M,
    fs: &mut F,
) -> u64 {
    let path = match read_user_path(memory, args[0]) {
        Ok(path) => path,
        Err(err) => return err,
    };
    if path.is_empty() {
        return errno(ENOENT);
    }
    let name = match read_xattr_name(memory, args[1]) {
        Ok(name) => name,
        Err(err) => return err,
    };
    let creds = process_creds(process);
    let (cwd, resolved_path) =
        match resolve_in_chroot(process, None, &path, follow, &creds, fs).await {
            Ok(pair) => pair,
            Err(err) => return err,
        };
    match fs
        .remove_xattr_path(&cwd, &resolved_path, follow, &name, &creds)
        .await
    {
        Ok(()) => 0,
        Err(error) => fs_errno(error),
    }
}

pub(super) async fn fremovexattr<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let name = match read_xattr_name(memory, args[1]) {
        Ok(name) => name,
        Err(err) => return err,
    };
    let Some(entry) = process.shared.descriptors.lock().get_entry(fd).cloned() else {
        return errno(EBADF);
    };
    if entry.fdflags() & FDFLAG_PATH != 0 {
        return errno(EBADF);
    }
    let Some(open) = entry_file::<R>(&entry) else {
        return errno(EOPNOTSUPP);
    };
    let creds = process_creds(process);
    match fs.remove_xattr_file(open.node(), &name, &creds).await {
        Ok(()) => 0,
        Err(error) => fs_errno(error),
    }
}

// Keep unused-constant check clean for DT_UNKNOWN.
const _: u8 = DT_UNKNOWN;
