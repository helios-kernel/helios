//! Zero-`dyn` async filesystem backends for `virtio-fs`:
//! - [`WasiFsBackend`] confines all operations to a single opened WASI 0.3
//!   directory `Descriptor`.
//! - [`HostFsBackend`] confines all operations to a canonical host directory
//!   using `std::fs` (used on host targets and unit tests).

use core::future::Future;
#[cfg(not(target_arch = "wasm32"))]
use std::path::PathBuf;
use std::path::{Component, Path};

use futures_lite::future::zip;
use helios_api::bindings::wasi::{
    clocks::system_clock::Instant as WasiInstant,
    filesystem::{
        preopens,
        types::{
            Descriptor, DescriptorFlags, DescriptorStat, DescriptorType, ErrorCode as FsErrorCode,
            NewTimestamp, OpenFlags, PathFlags,
        },
    },
};
use helios_api::hv::TRANSFER_CHUNK_BYTES;

use crate::error::{Error, Result};

// Linux errno values (positive magnitudes; FUSE replies negate them).
pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const EIO: i32 = 5;
pub const ENXIO: i32 = 6;
pub const EBADF: i32 = 9;
pub const ENOMEM: i32 = 12;
pub const EACCES: i32 = 13;
pub const EBUSY: i32 = 16;
pub const EEXIST: i32 = 17;
pub const EXDEV: i32 = 18;
pub const ENOTDIR: i32 = 20;
pub const EISDIR: i32 = 21;
pub const EINVAL: i32 = 22;
pub const EMFILE: i32 = 24;
pub const ENOSPC: i32 = 28;
pub const ESPIPE: i32 = 29;
pub const EROFS: i32 = 30;
pub const EMLINK: i32 = 31;
pub const ENAMETOOLONG: i32 = 36;
pub const ENOSYS: i32 = 38;
pub const ENOTEMPTY: i32 = 39;
pub const ELOOP: i32 = 40;
pub const ENODATA: i32 = 61;
pub const EOVERFLOW: i32 = 75;
pub const EOPNOTSUPP: i32 = 95;

// POSIX file type bits (`st_mode & S_IFMT`).
pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;

// Linux dirent `d_type` values.
pub const DT_UNKNOWN: u32 = 0;
pub const DT_DIR: u32 = 4;
pub const DT_REG: u32 = 8;
pub const DT_LNK: u32 = 10;

/// Portable POSIX-like metadata returned by an [`FsBackend`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsMetadata {
    pub size: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub atime_sec: u64,
    pub atime_nsec: u32,
    pub mtime_sec: u64,
    pub mtime_nsec: u32,
    pub ctime_sec: u64,
    pub ctime_nsec: u32,
}

impl FsMetadata {
    pub const fn file_type(&self) -> u32 {
        self.mode & S_IFMT
    }

    pub const fn is_dir(&self) -> bool {
        self.file_type() == S_IFDIR
    }

    pub const fn dirent_type(&self) -> u32 {
        match self.file_type() {
            S_IFDIR => DT_DIR,
            S_IFREG => DT_REG,
            S_IFLNK => DT_LNK,
            _ => DT_UNKNOWN,
        }
    }
}

/// Directory entry yielded by [`FsBackend::read_dir`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsDirEntry {
    pub name: String,
    pub d_type: u32,
}

/// Timestamp update specification for `SETATTR`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsTimeUpdate {
    Unchanged,
    Now,
    Set { secs: u64, nsecs: u32 },
}

/// Open options translated from Linux `O_*` flags.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FsOpenOptions {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub exclusive: bool,
    pub truncate: bool,
    pub mode: u32,
}

/// Result type for backend operations carrying a positive Linux errno.
pub type FsResult<T> = core::result::Result<T, i32>;

/// Zero-`dyn` async host-directory backend for [`super::fuse::FuseSession`].
///
/// Every `path` slice contains validated single-component relative path segments
/// (no empty names, `.`, `..`, `/`, or `\0`).
pub trait FsBackend {
    type FileHandle;

    fn read_only(&self) -> bool;

    fn stat(&self, path: &[String]) -> impl Future<Output = FsResult<FsMetadata>>;

    fn open_file(
        &self,
        path: &[String],
        options: FsOpenOptions,
    ) -> impl Future<Output = FsResult<(Self::FileHandle, FsMetadata)>>;

    fn read_file(
        &self,
        handle: &Self::FileHandle,
        offset: u64,
        size: u32,
    ) -> impl Future<Output = FsResult<Vec<u8>>>;

    fn write_file(
        &self,
        handle: &Self::FileHandle,
        offset: u64,
        data: &[u8],
    ) -> impl Future<Output = FsResult<u32>>;

    fn flush_file(&self, handle: &Self::FileHandle) -> impl Future<Output = FsResult<()>>;

    fn stat_handle(&self, handle: &Self::FileHandle) -> impl Future<Output = FsResult<FsMetadata>>;

    fn set_size_handle(
        &self,
        handle: &Self::FileHandle,
        size: u64,
    ) -> impl Future<Output = FsResult<()>>;

    fn set_size_path(&self, path: &[String], size: u64) -> impl Future<Output = FsResult<()>>;

    fn set_times(
        &self,
        path: &[String],
        atime: FsTimeUpdate,
        mtime: FsTimeUpdate,
    ) -> impl Future<Output = FsResult<()>>;

    fn set_mode(&self, path: &[String], mode: u32) -> impl Future<Output = FsResult<()>>;

    fn mkdir(&self, path: &[String], mode: u32) -> impl Future<Output = FsResult<FsMetadata>>;

    fn unlink(&self, path: &[String]) -> impl Future<Output = FsResult<()>>;

    fn rmdir(&self, path: &[String]) -> impl Future<Output = FsResult<()>>;

    fn rename(
        &self,
        old_path: &[String],
        new_path: &[String],
        no_replace: bool,
    ) -> impl Future<Output = FsResult<()>>;

    fn read_dir(&self, path: &[String]) -> impl Future<Output = FsResult<Vec<FsDirEntry>>>;

    fn readlink(&self, path: &[String]) -> impl Future<Output = FsResult<String>>;

    fn symlink(
        &self,
        link_path: &[String],
        target: &str,
    ) -> impl Future<Output = FsResult<FsMetadata>>;

    fn link(
        &self,
        old_path: &[String],
        new_path: &[String],
    ) -> impl Future<Output = FsResult<FsMetadata>>;
}

/// Validates a single FUSE path component to prevent traversal outside the share root.
pub fn validate_name(name: &str) -> FsResult<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(EINVAL);
    }
    if name.len() > 255 {
        return Err(ENAMETOOLONG);
    }
    Ok(())
}

/// Validates raw symlink target text stored for guest-side resolution.
///
/// Absolute targets (such as `/usr/bin/busybox` inside a `--rootfs-dir` tree)
/// are permitted because neither [`WasiFsBackend`] nor [`HostFsBackend`] ever
/// follows symlinks during host path traversal; the guest kernel VFS resolves
/// the target returned by `FUSE_READLINK`.
pub fn validate_symlink_target(target: &str) -> FsResult<()> {
    if target.is_empty() || target.contains('\0') {
        return Err(EINVAL);
    }
    Ok(())
}

/// Computes the WASI directory descriptor flags required for a share directory.
///
/// Writable directories must carry `WRITE` alongside `READ | MUTATE_DIRECTORY`
/// so child `open_at(..., DescriptorFlags::WRITE)` calls satisfy the kernel's
/// `base_flags` attenuation check instead of failing with `EROFS`.
pub(crate) fn directory_open_flags(read_only: bool) -> DescriptorFlags {
    if read_only {
        DescriptorFlags::READ
    } else {
        DescriptorFlags::READ | DescriptorFlags::WRITE | DescriptorFlags::MUTATE_DIRECTORY
    }
}

/// Computes the WASI `(OpenFlags, DescriptorFlags)` pair for [`FsOpenOptions`].
pub(crate) fn file_open_flags(options: FsOpenOptions) -> (OpenFlags, DescriptorFlags) {
    let mut open_flags = OpenFlags::empty();
    if options.create {
        open_flags = open_flags | OpenFlags::CREATE;
    }
    if options.exclusive {
        open_flags = open_flags | OpenFlags::EXCLUSIVE;
    }
    if options.truncate {
        open_flags = open_flags | OpenFlags::TRUNCATE;
    }
    let mut desc_flags = DescriptorFlags::empty();
    if options.read || !options.write {
        desc_flags = desc_flags | DescriptorFlags::READ;
    }
    if options.write {
        desc_flags = desc_flags | DescriptorFlags::WRITE;
    }
    (open_flags, desc_flags)
}

/// Validates a host share path into relative components, rejecting `..` traversal.
fn normalize_host_path(path: &str) -> Result<Vec<String>> {
    let mut parts = Vec::new();
    for component in Path::new(path).components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                return Err(Error::Config("share directory path must not contain '..'"));
            }
            Component::Normal(seg) => {
                let s = seg
                    .to_str()
                    .ok_or(Error::Config("share directory path must be valid UTF-8"))?;
                parts.push(s.to_owned());
            }
            Component::Prefix(_) => {
                return Err(Error::Config("unsupported path prefix in share directory"));
            }
        }
    }
    Ok(parts)
}

fn map_wasi_error(code: FsErrorCode) -> i32 {
    match code {
        FsErrorCode::Access => EACCES,
        FsErrorCode::BadDescriptor => EBADF,
        FsErrorCode::Busy => EBUSY,
        FsErrorCode::Exist => EEXIST,
        FsErrorCode::Invalid => EINVAL,
        FsErrorCode::Io => EIO,
        FsErrorCode::IsDirectory => EISDIR,
        FsErrorCode::Loop => ELOOP,
        FsErrorCode::TooManyLinks => EMLINK,
        FsErrorCode::NameTooLong => ENAMETOOLONG,
        FsErrorCode::NoEntry => ENOENT,
        FsErrorCode::InsufficientMemory => ENOMEM,
        FsErrorCode::InsufficientSpace => ENOSPC,
        FsErrorCode::NotDirectory => ENOTDIR,
        FsErrorCode::NotEmpty => ENOTEMPTY,
        FsErrorCode::Unsupported => ENOSYS,
        FsErrorCode::Overflow => EOVERFLOW,
        FsErrorCode::NotPermitted => EPERM,
        FsErrorCode::ReadOnly => EROFS,
        FsErrorCode::InvalidSeek => ESPIPE,
        FsErrorCode::CrossDevice => EXDEV,
        _ => EIO,
    }
}

fn wasi_stat_to_metadata(stat: DescriptorStat, read_only: bool) -> FsMetadata {
    let mode = match stat.type_ {
        DescriptorType::Directory => S_IFDIR | if read_only { 0o555 } else { 0o755 },
        DescriptorType::SymbolicLink => S_IFLNK | 0o777,
        // WASI 0.3 does not carry Unix mode bits. Expose regular files with
        // execute bits so binaries in a `--rootfs-dir` tree remain executable.
        _ => S_IFREG | if read_only { 0o555 } else { 0o755 },
    };
    let ts = |t: Option<WasiInstant>| -> (u64, u32) {
        match t {
            Some(inst) => (inst.seconds.max(0) as u64, inst.nanoseconds),
            None => (0, 0),
        }
    };
    let (atime_sec, atime_nsec) = ts(stat.data_access_timestamp);
    let (mtime_sec, mtime_nsec) = ts(stat.data_modification_timestamp);
    let (ctime_sec, ctime_nsec) = ts(stat.status_change_timestamp);
    FsMetadata {
        size: stat.size,
        mode,
        nlink: u32::try_from(stat.link_count).unwrap_or(u32::MAX).max(1),
        uid: 0,
        gid: 0,
        atime_sec,
        atime_nsec,
        mtime_sec,
        mtime_nsec,
        ctime_sec,
        ctime_nsec,
    }
}

fn to_wasi_timestamp(update: FsTimeUpdate) -> NewTimestamp {
    match update {
        FsTimeUpdate::Unchanged => NewTimestamp::NoChange,
        FsTimeUpdate::Now => NewTimestamp::Now,
        FsTimeUpdate::Set { secs, nsecs } => NewTimestamp::Timestamp(WasiInstant {
            seconds: secs as i64,
            nanoseconds: nsecs,
        }),
    }
}

/// WASI 0.3 capability-confined directory backend.
///
/// Opens the granted share root once and performs every FUSE operation
/// strictly relative to that directory [`Descriptor`].
pub struct WasiFsBackend {
    root: Descriptor,
    read_only: bool,
}

impl WasiFsBackend {
    pub async fn open_root(host_path: &str, read_only: bool) -> Result<Self> {
        let components = normalize_host_path(host_path)?;
        let (mut dir, _) = preopens::get_directories()
            .into_iter()
            .find(|(_, name)| name == "/")
            .ok_or(Error::MissingRoot)?;
        let flags = directory_open_flags(read_only);
        for seg in components {
            dir = dir
                .open_at(PathFlags::SYMLINK_FOLLOW, seg, OpenFlags::DIRECTORY, flags)
                .await?;
        }
        Ok(Self {
            root: dir,
            read_only,
        })
    }

    async fn open_parent<'a>(
        &'a self,
        path: &'a [String],
    ) -> FsResult<(Option<Descriptor>, &'a str)> {
        let (name, parent_parts) = path.split_last().ok_or(EINVAL)?;
        validate_name(name)?;
        if parent_parts.is_empty() {
            return Ok((None, name.as_str()));
        }
        let flags = directory_open_flags(self.read_only);
        let mut current: Option<Descriptor> = None;
        for seg in parent_parts {
            validate_name(seg)?;
            let base = current.as_ref().unwrap_or(&self.root);
            let next = base
                .open_at(PathFlags::empty(), seg.clone(), OpenFlags::DIRECTORY, flags)
                .await
                .map_err(map_wasi_error)?;
            current = Some(next);
        }
        Ok((current, name.as_str()))
    }
}

impl FsBackend for WasiFsBackend {
    type FileHandle = Descriptor;

    fn read_only(&self) -> bool {
        self.read_only
    }

    async fn stat(&self, path: &[String]) -> FsResult<FsMetadata> {
        let stat = if path.is_empty() {
            self.root.stat().await.map_err(map_wasi_error)?
        } else {
            let (parent, name) = self.open_parent(path).await?;
            let base = parent.as_ref().unwrap_or(&self.root);
            base.stat_at(PathFlags::empty(), name.to_owned())
                .await
                .map_err(map_wasi_error)?
        };
        Ok(wasi_stat_to_metadata(stat, self.read_only))
    }

    async fn open_file(
        &self,
        path: &[String],
        options: FsOpenOptions,
    ) -> FsResult<(Self::FileHandle, FsMetadata)> {
        if path.is_empty() {
            return Err(EISDIR);
        }
        if self.read_only && (options.write || options.create || options.truncate) {
            return Err(EROFS);
        }
        let (open_flags, desc_flags) = file_open_flags(options);
        let (parent, name) = self.open_parent(path).await?;
        let base = parent.as_ref().unwrap_or(&self.root);
        let descriptor = base
            .open_at(PathFlags::empty(), name.to_owned(), open_flags, desc_flags)
            .await
            .map_err(map_wasi_error)?;
        let stat = descriptor.stat().await.map_err(map_wasi_error)?;
        Ok((descriptor, wasi_stat_to_metadata(stat, self.read_only)))
    }

    async fn read_file(
        &self,
        handle: &Self::FileHandle,
        offset: u64,
        size: u32,
    ) -> FsResult<Vec<u8>> {
        if size == 0 {
            return Ok(Vec::new());
        }
        let target = size as usize;
        let (mut stream, completion) = handle.read_via_stream(offset);
        let mut out = Vec::with_capacity(target.min(TRANSFER_CHUNK_BYTES));
        let mut hit_eof = false;
        while out.len() < target {
            let want = (target - out.len()).min(TRANSFER_CHUNK_BYTES);
            let (status, chunk) = stream.read(Vec::with_capacity(want)).await;
            out.extend_from_slice(&chunk);
            if helios_api::stream_closed(status) {
                hit_eof = true;
                break;
            }
        }
        drop(stream);
        if hit_eof {
            completion.await.map_err(map_wasi_error)?;
        } else {
            drop(completion);
        }
        Ok(out)
    }

    async fn write_file(
        &self,
        handle: &Self::FileHandle,
        offset: u64,
        data: &[u8],
    ) -> FsResult<u32> {
        if self.read_only {
            return Err(EROFS);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let owned = data.to_vec();
        let total = u32::try_from(owned.len()).map_err(|_| EINVAL)?;
        let (mut tx, rx) = helios_api::bindings::wit_stream::new();
        let (written, remainder) = zip(
            async { handle.write_via_stream(rx, offset).await },
            async move {
                let rest = tx.write_all(owned).await;
                drop(tx);
                rest
            },
        )
        .await;
        written.map_err(map_wasi_error)?;
        if !remainder.is_empty() {
            return Err(EIO);
        }
        Ok(total)
    }

    async fn flush_file(&self, handle: &Self::FileHandle) -> FsResult<()> {
        if !self.read_only {
            handle.sync_data().await.map_err(map_wasi_error)?;
        }
        Ok(())
    }

    async fn stat_handle(&self, handle: &Self::FileHandle) -> FsResult<FsMetadata> {
        let stat = handle.stat().await.map_err(map_wasi_error)?;
        Ok(wasi_stat_to_metadata(stat, self.read_only))
    }

    async fn set_size_handle(&self, handle: &Self::FileHandle, size: u64) -> FsResult<()> {
        if self.read_only {
            return Err(EROFS);
        }
        handle.set_size(size).await.map_err(map_wasi_error)
    }

    async fn set_size_path(&self, path: &[String], size: u64) -> FsResult<()> {
        if self.read_only {
            return Err(EROFS);
        }
        let (handle, _) = self
            .open_file(
                path,
                FsOpenOptions {
                    read: false,
                    write: true,
                    ..FsOpenOptions::default()
                },
            )
            .await?;
        handle.set_size(size).await.map_err(map_wasi_error)
    }

    async fn set_times(
        &self,
        path: &[String],
        atime: FsTimeUpdate,
        mtime: FsTimeUpdate,
    ) -> FsResult<()> {
        if self.read_only {
            return Err(EROFS);
        }
        let atime = to_wasi_timestamp(atime);
        let mtime = to_wasi_timestamp(mtime);
        if path.is_empty() {
            self.root
                .set_times(atime, mtime)
                .await
                .map_err(map_wasi_error)
        } else {
            let (parent, name) = self.open_parent(path).await?;
            let base = parent.as_ref().unwrap_or(&self.root);
            base.set_times_at(PathFlags::empty(), name.to_owned(), atime, mtime)
                .await
                .map_err(map_wasi_error)
        }
    }

    async fn set_mode(&self, _path: &[String], _mode: u32) -> FsResult<()> {
        if self.read_only {
            return Err(EROFS);
        }
        // Shared WASI mounts do not store per-file Unix mode bits (AGENTS.md §3.8).
        Ok(())
    }

    async fn mkdir(&self, path: &[String], _mode: u32) -> FsResult<FsMetadata> {
        if self.read_only {
            return Err(EROFS);
        }
        let (parent, name) = self.open_parent(path).await?;
        let base = parent.as_ref().unwrap_or(&self.root);
        base.create_directory_at(name.to_owned())
            .await
            .map_err(map_wasi_error)?;
        let stat = base
            .stat_at(PathFlags::empty(), name.to_owned())
            .await
            .map_err(map_wasi_error)?;
        Ok(wasi_stat_to_metadata(stat, self.read_only))
    }

    async fn unlink(&self, path: &[String]) -> FsResult<()> {
        if self.read_only {
            return Err(EROFS);
        }
        let (parent, name) = self.open_parent(path).await?;
        let base = parent.as_ref().unwrap_or(&self.root);
        base.unlink_file_at(name.to_owned())
            .await
            .map_err(map_wasi_error)
    }

    async fn rmdir(&self, path: &[String]) -> FsResult<()> {
        if self.read_only {
            return Err(EROFS);
        }
        let (parent, name) = self.open_parent(path).await?;
        let base = parent.as_ref().unwrap_or(&self.root);
        base.remove_directory_at(name.to_owned())
            .await
            .map_err(map_wasi_error)
    }

    async fn rename(
        &self,
        old_path: &[String],
        new_path: &[String],
        no_replace: bool,
    ) -> FsResult<()> {
        if self.read_only {
            return Err(EROFS);
        }
        if no_replace && self.stat(new_path).await.is_ok() {
            return Err(EEXIST);
        }
        let (old_parent, old_name) = self.open_parent(old_path).await?;
        let (new_parent, new_name) = self.open_parent(new_path).await?;
        let old_base = old_parent.as_ref().unwrap_or(&self.root);
        let new_base = new_parent.as_ref().unwrap_or(&self.root);
        old_base
            .rename_at(old_name.to_owned(), new_base, new_name.to_owned())
            .await
            .map_err(map_wasi_error)
    }

    async fn read_dir(&self, path: &[String]) -> FsResult<Vec<FsDirEntry>> {
        let dir_owned = if path.is_empty() {
            None
        } else {
            let (parent, name) = self.open_parent(path).await?;
            let base = parent.as_ref().unwrap_or(&self.root);
            Some(
                base.open_at(
                    PathFlags::empty(),
                    name.to_owned(),
                    OpenFlags::DIRECTORY,
                    DescriptorFlags::READ,
                )
                .await
                .map_err(map_wasi_error)?,
            )
        };
        let dir = dir_owned.as_ref().unwrap_or(&self.root);
        let (mut stream, completion) = dir.read_directory();
        let mut entries = Vec::new();
        loop {
            let (status, batch) = stream.read(Vec::with_capacity(64)).await;
            for entry in batch {
                let d_type = match entry.type_ {
                    DescriptorType::Directory => DT_DIR,
                    DescriptorType::RegularFile => DT_REG,
                    DescriptorType::SymbolicLink => DT_LNK,
                    _ => DT_UNKNOWN,
                };
                entries.push(FsDirEntry {
                    name: entry.name,
                    d_type,
                });
            }
            if helios_api::stream_closed(status) {
                break;
            }
        }
        drop(stream);
        completion.await.map_err(map_wasi_error)?;
        Ok(entries)
    }

    async fn readlink(&self, path: &[String]) -> FsResult<String> {
        let (parent, name) = self.open_parent(path).await?;
        let base = parent.as_ref().unwrap_or(&self.root);
        base.readlink_at(name.to_owned())
            .await
            .map_err(map_wasi_error)
    }

    async fn symlink(&self, link_path: &[String], target: &str) -> FsResult<FsMetadata> {
        if self.read_only {
            return Err(EROFS);
        }
        validate_symlink_target(target)?;
        let (parent, name) = self.open_parent(link_path).await?;
        let base = parent.as_ref().unwrap_or(&self.root);
        base.symlink_at(target.to_owned(), name.to_owned())
            .await
            .map_err(map_wasi_error)?;
        let stat = base
            .stat_at(PathFlags::empty(), name.to_owned())
            .await
            .map_err(map_wasi_error)?;
        Ok(wasi_stat_to_metadata(stat, self.read_only))
    }

    async fn link(&self, old_path: &[String], new_path: &[String]) -> FsResult<FsMetadata> {
        if self.read_only {
            return Err(EROFS);
        }
        let (old_parent, old_name) = self.open_parent(old_path).await?;
        let (new_parent, new_name) = self.open_parent(new_path).await?;
        let old_base = old_parent.as_ref().unwrap_or(&self.root);
        let new_base = new_parent.as_ref().unwrap_or(&self.root);
        old_base
            .link_at(
                PathFlags::empty(),
                old_name.to_owned(),
                new_base,
                new_name.to_owned(),
            )
            .await
            .map_err(map_wasi_error)?;
        let stat = new_base
            .stat_at(PathFlags::empty(), new_name.to_owned())
            .await
            .map_err(map_wasi_error)?;
        Ok(wasi_stat_to_metadata(stat, self.read_only))
    }
}

/// Platform `open(2)` bitmasks for [`HostFsBackend`] Unix leaf opens.
#[cfg(all(unix, not(target_arch = "wasm32")))]
mod unix_open_flags {
    // BSD / macOS `<sys/fcntl.h>`.
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    pub const O_NOFOLLOW: i32 = 0x0100;
    // Linux `<arch/arm64/include/uapi/asm/fcntl.h>`.
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(target_arch = "aarch64", target_arch = "arm"),
    ))]
    pub const O_NOFOLLOW: i32 = 0o100000;
    // Linux `<uapi/asm-generic/fcntl.h>`.
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        not(any(target_arch = "aarch64", target_arch = "arm")),
    ))]
    pub const O_NOFOLLOW: i32 = 0o400000;

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    pub const O_CREAT: i32 = 0x0200;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub const O_CREAT: i32 = 0o100;

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    pub const O_TRUNC: i32 = 0x0400;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub const O_TRUNC: i32 = 0o1000;

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    pub const O_EXCL: i32 = 0x0800;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub const O_EXCL: i32 = 0o200;
}

/// Host `std::fs` backend confined strictly within a canonical root directory.
///
/// Rejects path traversal and refuses to follow any symlink on parent or leaf
/// host operations; symlink targets are stored and returned raw for guest VFS
/// resolution.
#[cfg(not(target_arch = "wasm32"))]
pub struct HostFsBackend {
    root: PathBuf,
    read_only: bool,
}

#[cfg(not(target_arch = "wasm32"))]
impl HostFsBackend {
    pub fn new(root: impl AsRef<Path>, read_only: bool) -> Result<Self> {
        let canonical = std::fs::canonicalize(root.as_ref())?;
        if !canonical.is_dir() {
            return Err(Error::Config("virtio-fs share root must be a directory"));
        }
        Ok(Self {
            root: canonical,
            read_only,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolves `path` under `self.root`, ensuring every component is validated
    /// and no ancestor directory is a symlink or escapes `self.root`.
    fn resolve_confined(&self, path: &[String]) -> FsResult<PathBuf> {
        let mut current = self.root.clone();
        for (idx, seg) in path.iter().enumerate() {
            validate_name(seg)?;
            current.push(seg);
            let is_last = idx + 1 == path.len();
            if !is_last {
                self.verify_not_escaping_symlink(&current)?;
                let meta = std::fs::symlink_metadata(&current).map_err(map_io_error)?;
                if meta.file_type().is_symlink() {
                    return Err(ELOOP);
                }
                if !meta.is_dir() {
                    return Err(ENOTDIR);
                }
            }
        }
        Ok(current)
    }

    /// Rejects a symlink whose resolved host target escapes `self.root` with
    /// `EACCES`. Leaf opens additionally pass `O_NOFOLLOW` on Unix so even a
    /// concurrent symlink swap cannot follow any symlink.
    fn verify_not_escaping_symlink(&self, target: &Path) -> FsResult<()> {
        if let Ok(meta) = std::fs::symlink_metadata(target)
            && meta.file_type().is_symlink()
            && let Ok(canon) = std::fs::canonicalize(target)
            && !canon.starts_with(&self.root)
        {
            return Err(EACCES);
        }
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn map_io_error(error: std::io::Error) -> i32 {
    use std::io::ErrorKind;
    if let Some(raw) = error.raw_os_error() {
        // Normalize common POSIX errnos across macOS and Linux to Linux ABI numbers.
        return match error.kind() {
            ErrorKind::NotFound => ENOENT,
            ErrorKind::PermissionDenied => EACCES,
            ErrorKind::AlreadyExists => EEXIST,
            ErrorKind::InvalidInput => EINVAL,
            ErrorKind::NotADirectory => ENOTDIR,
            ErrorKind::IsADirectory => EISDIR,
            ErrorKind::DirectoryNotEmpty => ENOTEMPTY,
            ErrorKind::ReadOnlyFilesystem => EROFS,
            ErrorKind::StorageFull => ENOSPC,
            ErrorKind::ResourceBusy => EBUSY,
            ErrorKind::CrossesDevices => EXDEV,
            ErrorKind::InvalidFilename => ENAMETOOLONG,
            ErrorKind::Unsupported => ENOSYS,
            _ => match raw {
                // EBADF = 9, EMFILE = 24 on both Linux and macOS;
                // macOS ENOTEMPTY = 66, ELOOP = 62; Linux ELOOP = 40.
                9 => EBADF,
                24 => EMFILE,
                66 => ENOTEMPTY,
                62 | 40 => ELOOP,
                _ => EIO,
            },
        };
    }
    EIO
}

#[cfg(not(target_arch = "wasm32"))]
fn std_metadata(meta: &std::fs::Metadata, read_only: bool) -> FsMetadata {
    use std::time::UNIX_EPOCH;
    let ts = |res: std::io::Result<std::time::SystemTime>| -> (u64, u32) {
        res.ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| (d.as_secs(), d.subsec_nanos()))
            .unwrap_or((0, 0))
    };
    let (atime_sec, atime_nsec) = ts(meta.accessed());
    let (mtime_sec, mtime_nsec) = ts(meta.modified());
    #[cfg(unix)]
    let (mode, nlink, uid, gid, ctime_sec, ctime_nsec) = {
        use std::os::unix::fs::MetadataExt;
        let mut mode = meta.mode();
        if read_only {
            mode &= !0o222;
        }
        (
            mode,
            u32::try_from(meta.nlink()).unwrap_or(u32::MAX).max(1),
            meta.uid(),
            meta.gid(),
            meta.ctime().max(0) as u64,
            meta.ctime_nsec().max(0) as u32,
        )
    };
    #[cfg(not(unix))]
    let (mode, nlink, uid, gid, ctime_sec, ctime_nsec) = {
        let mode = if meta.is_dir() {
            S_IFDIR | if read_only { 0o555 } else { 0o755 }
        } else if meta.file_type().is_symlink() {
            S_IFLNK | 0o777
        } else {
            S_IFREG | if read_only { 0o444 } else { 0o644 }
        };
        (mode, 1, 0, 0, mtime_sec, mtime_nsec)
    };
    FsMetadata {
        size: meta.len(),
        mode,
        nlink,
        uid,
        gid,
        atime_sec,
        atime_nsec,
        mtime_sec,
        mtime_nsec,
        ctime_sec,
        ctime_nsec,
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl FsBackend for HostFsBackend {
    type FileHandle = std::fs::File;

    fn read_only(&self) -> bool {
        self.read_only
    }

    async fn stat(&self, path: &[String]) -> FsResult<FsMetadata> {
        let full = self.resolve_confined(path)?;
        let meta = std::fs::symlink_metadata(&full).map_err(map_io_error)?;
        Ok(std_metadata(&meta, self.read_only))
    }

    async fn open_file(
        &self,
        path: &[String],
        options: FsOpenOptions,
    ) -> FsResult<(Self::FileHandle, FsMetadata)> {
        if path.is_empty() {
            return Err(EISDIR);
        }
        if self.read_only && (options.write || options.create || options.truncate) {
            return Err(EROFS);
        }
        let full = self.resolve_confined(path)?;
        self.verify_not_escaping_symlink(&full)?;
        let mut opts = std::fs::OpenOptions::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            if options.write {
                opts.read(options.read);
                opts.write(true);
                if options.create && options.exclusive {
                    opts.create_new(true);
                } else {
                    opts.create(options.create);
                }
                opts.truncate(options.truncate);
                opts.custom_flags(unix_open_flags::O_NOFOLLOW);
            } else {
                // `std::fs::OpenOptions` rejects `.create(true)` without `.write(true)`
                // with `EINVAL`, whereas POSIX `open(2)` permits `O_RDONLY | O_CREAT`.
                // Pass creation flags via `custom_flags` alongside `O_NOFOLLOW` so the
                // resulting file descriptor stays strictly read-only.
                opts.read(true).write(false);
                let mut extra = unix_open_flags::O_NOFOLLOW;
                if options.create {
                    extra |= unix_open_flags::O_CREAT;
                    if options.exclusive {
                        extra |= unix_open_flags::O_EXCL;
                    }
                }
                if options.truncate {
                    extra |= unix_open_flags::O_TRUNC;
                }
                opts.custom_flags(extra);
            }
            if options.create && options.mode != 0 {
                opts.mode(options.mode & 0o7777);
            }
        }
        #[cfg(not(unix))]
        {
            if let Ok(meta) = std::fs::symlink_metadata(&full)
                && meta.file_type().is_symlink()
            {
                return Err(ELOOP);
            }
            opts.read(options.read || !options.write);
            opts.write(options.write);
            if options.create && options.exclusive {
                opts.create_new(true);
            } else {
                opts.create(options.create);
            }
            opts.truncate(options.truncate);
        }
        let file = opts.open(&full).map_err(map_io_error)?;
        let meta = file.metadata().map_err(map_io_error)?;
        if meta.is_dir() {
            return Err(EISDIR);
        }
        Ok((file, std_metadata(&meta, self.read_only)))
    }

    async fn read_file(
        &self,
        handle: &Self::FileHandle,
        offset: u64,
        size: u32,
    ) -> FsResult<Vec<u8>> {
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; size as usize];
        #[cfg(unix)]
        let n = {
            use std::os::unix::fs::FileExt;
            handle.read_at(&mut buf, offset).map_err(map_io_error)?
        };
        #[cfg(not(unix))]
        let n = {
            use std::io::{Read, Seek, SeekFrom};
            let mut clone = handle.try_clone().map_err(map_io_error)?;
            clone.seek(SeekFrom::Start(offset)).map_err(map_io_error)?;
            clone.read(&mut buf).map_err(map_io_error)?
        };
        buf.truncate(n);
        Ok(buf)
    }

    async fn write_file(
        &self,
        handle: &Self::FileHandle,
        offset: u64,
        data: &[u8],
    ) -> FsResult<u32> {
        if self.read_only {
            return Err(EROFS);
        }
        if data.is_empty() {
            return Ok(0);
        }
        #[cfg(unix)]
        let n = {
            use std::os::unix::fs::FileExt;
            handle.write_at(data, offset).map_err(map_io_error)?
        };
        #[cfg(not(unix))]
        let n = {
            use std::io::{Seek, SeekFrom, Write};
            let mut clone = handle.try_clone().map_err(map_io_error)?;
            clone.seek(SeekFrom::Start(offset)).map_err(map_io_error)?;
            clone.write(data).map_err(map_io_error)?
        };
        Ok(n as u32)
    }

    async fn flush_file(&self, handle: &Self::FileHandle) -> FsResult<()> {
        if !self.read_only {
            handle.sync_data().map_err(map_io_error)?;
        }
        Ok(())
    }

    async fn stat_handle(&self, handle: &Self::FileHandle) -> FsResult<FsMetadata> {
        let meta = handle.metadata().map_err(map_io_error)?;
        Ok(std_metadata(&meta, self.read_only))
    }

    async fn set_size_handle(&self, handle: &Self::FileHandle, size: u64) -> FsResult<()> {
        if self.read_only {
            return Err(EROFS);
        }
        handle.set_len(size).map_err(map_io_error)
    }

    async fn set_size_path(&self, path: &[String], size: u64) -> FsResult<()> {
        if self.read_only {
            return Err(EROFS);
        }
        let full = self.resolve_confined(path)?;
        self.verify_not_escaping_symlink(&full)?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(unix_open_flags::O_NOFOLLOW);
        }
        #[cfg(not(unix))]
        if let Ok(meta) = std::fs::symlink_metadata(&full)
            && meta.file_type().is_symlink()
        {
            return Err(ELOOP);
        }
        let file = opts.open(&full).map_err(map_io_error)?;
        file.set_len(size).map_err(map_io_error)
    }

    async fn set_times(
        &self,
        path: &[String],
        atime: FsTimeUpdate,
        mtime: FsTimeUpdate,
    ) -> FsResult<()> {
        if self.read_only {
            return Err(EROFS);
        }
        let full = self.resolve_confined(path)?;
        self.verify_not_escaping_symlink(&full)?;
        let mut times = std::fs::FileTimes::new();
        let to_sys = |u: FsTimeUpdate| -> Option<std::time::SystemTime> {
            match u {
                FsTimeUpdate::Unchanged => None,
                FsTimeUpdate::Now => Some(std::time::SystemTime::now()),
                FsTimeUpdate::Set { secs, nsecs } => {
                    Some(std::time::UNIX_EPOCH + std::time::Duration::new(secs, nsecs))
                }
            }
        };
        if let Some(t) = to_sys(atime) {
            times = times.set_accessed(t);
        }
        if let Some(t) = to_sys(mtime) {
            times = times.set_modified(t);
        }
        let meta = std::fs::symlink_metadata(&full).map_err(map_io_error)?;
        if meta.file_type().is_symlink() {
            return Err(ELOOP);
        }
        let mut opts = std::fs::OpenOptions::new();
        if meta.is_dir() {
            opts.read(true);
        } else {
            opts.write(true);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(unix_open_flags::O_NOFOLLOW);
        }
        let file = opts.open(&full).map_err(map_io_error)?;
        file.set_times(times).map_err(map_io_error)?;
        Ok(())
    }

    async fn set_mode(&self, path: &[String], mode: u32) -> FsResult<()> {
        if self.read_only {
            return Err(EROFS);
        }
        let full = self.resolve_confined(path)?;
        self.verify_not_escaping_symlink(&full)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(unix_open_flags::O_NOFOLLOW)
                .open(&full)
                .map_err(map_io_error)?;
            let perms = std::fs::Permissions::from_mode(mode & 0o7777);
            file.set_permissions(perms).map_err(map_io_error)?;
        }
        #[cfg(not(unix))]
        let _ = mode;
        Ok(())
    }

    async fn mkdir(&self, path: &[String], mode: u32) -> FsResult<FsMetadata> {
        if self.read_only {
            return Err(EROFS);
        }
        let full = self.resolve_confined(path)?;
        std::fs::create_dir(&full).map_err(map_io_error)?;
        #[cfg(unix)]
        if mode != 0 {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&full, std::fs::Permissions::from_mode(mode & 0o7777));
        }
        #[cfg(not(unix))]
        let _ = mode;
        let meta = std::fs::symlink_metadata(&full).map_err(map_io_error)?;
        Ok(std_metadata(&meta, self.read_only))
    }

    async fn unlink(&self, path: &[String]) -> FsResult<()> {
        if self.read_only {
            return Err(EROFS);
        }
        let full = self.resolve_confined(path)?;
        let meta = std::fs::symlink_metadata(&full).map_err(map_io_error)?;
        if meta.is_dir() {
            return Err(EISDIR);
        }
        std::fs::remove_file(&full).map_err(map_io_error)
    }

    async fn rmdir(&self, path: &[String]) -> FsResult<()> {
        if self.read_only {
            return Err(EROFS);
        }
        let full = self.resolve_confined(path)?;
        let meta = std::fs::symlink_metadata(&full).map_err(map_io_error)?;
        if !meta.is_dir() {
            return Err(ENOTDIR);
        }
        std::fs::remove_dir(&full).map_err(map_io_error)
    }

    async fn rename(
        &self,
        old_path: &[String],
        new_path: &[String],
        no_replace: bool,
    ) -> FsResult<()> {
        if self.read_only {
            return Err(EROFS);
        }
        let old_full = self.resolve_confined(old_path)?;
        let new_full = self.resolve_confined(new_path)?;
        if no_replace && std::fs::symlink_metadata(&new_full).is_ok() {
            return Err(EEXIST);
        }
        std::fs::rename(&old_full, &new_full).map_err(map_io_error)
    }

    async fn read_dir(&self, path: &[String]) -> FsResult<Vec<FsDirEntry>> {
        let full = self.resolve_confined(path)?;
        self.verify_not_escaping_symlink(&full)?;
        let meta = std::fs::symlink_metadata(&full).map_err(map_io_error)?;
        if meta.file_type().is_symlink() {
            return Err(ELOOP);
        }
        let iter = std::fs::read_dir(&full).map_err(map_io_error)?;
        let mut entries = Vec::new();
        for entry in iter {
            let entry = entry.map_err(map_io_error)?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let ft = entry.file_type().map_err(map_io_error)?;
            let d_type = if ft.is_dir() {
                DT_DIR
            } else if ft.is_file() {
                DT_REG
            } else if ft.is_symlink() {
                DT_LNK
            } else {
                DT_UNKNOWN
            };
            entries.push(FsDirEntry { name, d_type });
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    async fn readlink(&self, path: &[String]) -> FsResult<String> {
        let full = self.resolve_confined(path)?;
        let target = std::fs::read_link(&full).map_err(map_io_error)?;
        target.to_str().map(str::to_owned).ok_or(EINVAL)
    }

    async fn symlink(&self, link_path: &[String], target: &str) -> FsResult<FsMetadata> {
        if self.read_only {
            return Err(EROFS);
        }
        validate_symlink_target(target)?;
        let full = self.resolve_confined(link_path)?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, &full).map_err(map_io_error)?;
        #[cfg(not(unix))]
        return Err(ENOSYS);
        let meta = std::fs::symlink_metadata(&full).map_err(map_io_error)?;
        Ok(std_metadata(&meta, self.read_only))
    }

    async fn link(&self, old_path: &[String], new_path: &[String]) -> FsResult<FsMetadata> {
        if self.read_only {
            return Err(EROFS);
        }
        let old_full = self.resolve_confined(old_path)?;
        let new_full = self.resolve_confined(new_path)?;
        self.verify_not_escaping_symlink(&old_full)?;
        std::fs::hard_link(&old_full, &new_full).map_err(map_io_error)?;
        let meta = std::fs::symlink_metadata(&new_full).map_err(map_io_error)?;
        Ok(std_metadata(&meta, self.read_only))
    }
}
