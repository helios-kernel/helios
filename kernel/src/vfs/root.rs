//! Overlay root filesystems: a writable `UserMemoryPool`-backed [`MemoryFs`]
//! upper layer over a shared, read-only lower layer.
//!
//! [`RootFs`] is generic over its lower layer ([`OverlayLower`]):
//! - `RootFs<BootFs>` (the default) layers each namespace's writable tree over
//!   the boot image mounted at `/`.
//! - [`OverlayFs<S>`] (`RootFs<PinnedLower<S>>`) layers a fresh private
//!   in-memory upper tree over any lock-free pinned read-only directory
//!   ([`super::HeldPath`], such as a read-only `btrfs` image subvolume or an
//!   `erofs` mount), enabling concurrent ephemeral Linux container roots with
//!   zero disk writes on creation or teardown.
//!
//! Overlay semantics:
//! - A path names the upper object when the upper tree has one, and the lower
//!   object otherwise, unless the upper tree hid it.
//! - A new name may go into any directory, a lower one included: the directory
//!   and every ancestor above it is copied up first, empty and still merging
//!   the lower layer's entries.
//! - Changing a lower object copies it up first: its data, times, Unix
//!   attributes (`uid`, `gid`, `0o7777` mode bits), device number, and
//!   extended attributes (`security.capability`, `user.*`, `trusted.*`, POSIX
//!   ACLs). Regular file bytes from non-boot lowers are streamed in bounded
//!   chunks directly into `UserMemoryPool` frames under the machine's
//!   [`super::MemoryStorageBudget`], so copy-up never retains file bytes on
//!   the kernel heap and fails cleanly with [`FsError::NoSpace`] /
//!   [`FsError::OutOfMemory`] when memory is exhausted.
//! - Removing a lower object, or an upper object over one, leaves a whiteout
//!   that hides it; a directory made where a whiteout was is opaque and shows
//!   nothing of the lower directory beneath.
//! - Renaming a directory the lower layer has a part in returns
//!   [`FsError::CrossDevice`], as an overlay without redirects answers.
//!
//! # Concurrency contract
//!
//! [`RootFs`] holds no mutable state of its own. The lower layer is read-only
//! and lock-free pinned across concurrent overlays; every mutation to the
//! upper tree, with the whiteouts and opaque marks it carries, runs atomically
//! under that upper tree's own spin lock, and copy-up stages lower bytes into
//! user-pool frames *outside* that lock before inserting the inode. Two
//! copy-ups of the same object race harmlessly: the first wins and the second
//! drops its staged frames outside the lock.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;

use bytes::Bytes;
use helios_btrfs::DeviceNumber;
use helios_btrfs::write::{Attributes, Special};
use helios_hal::fs::{
    DirCookie, DirEntry, DirStream, FileSystem, FsError, FsPath, FsResult, Metadata, NodeKind,
    OpenFlags, Opened, OwnedFsPath, RenameMode, WritePosition,
};

use super::memory::{CopyUpContents, UpperView};
use super::{
    FileContents, MemoryFs, MemoryWrite, UnixAttributes, UnixFsError, UnixNodeMetadata,
    XattrSetMode, read_all,
};
use crate::{BootFs, BootfsBytes};

/// The Unix attributes the boot image's directories hold; its files and
/// links take [`UnixAttributes::inherited`] from this.
pub(super) const BOOT_UNIX: UnixAttributes = UnixAttributes {
    permissions: 0o755,
    uid: 0,
    gid: 0,
};

/// Chunk size used when streaming a regular file from a non-boot lower layer
/// into `UserMemoryPool` frames during copy-up.
const COPY_UP_CHUNK_BYTES: usize = 64 * 1024;

/// A read-only lower filesystem layer beneath a [`RootFs`] overlay.
///
/// Dispatch is static via generics (no `dyn Trait`). Implementations must be
/// safe to share concurrently across arbitrarily many independent overlays
/// without mutating the underlying tree.
pub trait OverlayLower: Clone + Send + Sync + 'static {
    fn lower_stat<'a>(
        &'a self,
        path: FsPath<'a>,
    ) -> impl Future<Output = FsResult<Metadata>> + Send + 'a;

    fn lower_open<'a>(
        &'a self,
        path: FsPath<'a>,
        flags: OpenFlags,
        now: u64,
        payer: &'a crate::StoragePayer,
    ) -> impl Future<Output = FsResult<Opened<OwnedFsPath>>> + Send + 'a;

    fn lower_read_at<'a>(
        &'a self,
        path: FsPath<'a>,
        offset: u64,
        max_bytes: usize,
    ) -> impl Future<Output = FsResult<Bytes>> + Send + 'a;

    fn lower_read_link<'a>(
        &'a self,
        path: FsPath<'a>,
    ) -> impl Future<Output = FsResult<String>> + Send + 'a;

    fn lower_read_dir_batch<'a>(
        &'a self,
        path: FsPath<'a>,
        cookie: DirCookie,
        max_entries: usize,
    ) -> impl Future<Output = FsResult<Vec<DirEntry>>> + Send + 'a;

    fn lower_read_whole<'a>(
        &'a self,
        path: FsPath<'a>,
    ) -> impl Future<Output = FsResult<FileContents>> + Send + 'a;

    /// Zero-copy static boot-image bytes when this lower layer is the boot
    /// image, allowing copy-up to share the boot payload until written.
    fn lower_boot_file_contents(&self, _path: FsPath<'_>) -> Option<BootfsBytes> {
        None
    }

    fn lower_unix_node_metadata<'a>(
        &'a self,
        path: FsPath<'a>,
    ) -> impl Future<Output = Result<UnixNodeMetadata, UnixFsError>> + Send + 'a;

    fn lower_xattr<'a>(
        &'a self,
        path: FsPath<'a>,
        name: &'a str,
    ) -> impl Future<Output = Result<Option<Bytes>, UnixFsError>> + Send + 'a;

    fn lower_list_xattrs<'a>(
        &'a self,
        path: FsPath<'a>,
    ) -> impl Future<Output = Result<Vec<String>, UnixFsError>> + Send + 'a;

    fn lower_sync<'a>(&'a self, path: FsPath<'a>)
    -> impl Future<Output = FsResult<()>> + Send + 'a;

    fn lower_sync_data<'a>(
        &'a self,
        path: FsPath<'a>,
    ) -> impl Future<Output = FsResult<()>> + Send + 'a;
}

impl OverlayLower for BootFs {
    async fn lower_stat<'a>(&'a self, path: FsPath<'a>) -> FsResult<Metadata> {
        self.metadata(path)
    }

    async fn lower_open<'a>(
        &'a self,
        path: FsPath<'a>,
        flags: OpenFlags,
        now: u64,
        payer: &'a crate::StoragePayer,
    ) -> FsResult<Opened<OwnedFsPath>> {
        <Self as FileSystem>::open(self, path, flags, now, payer).await
    }

    async fn lower_read_at<'a>(
        &'a self,
        path: FsPath<'a>,
        offset: u64,
        max_bytes: usize,
    ) -> FsResult<Bytes> {
        <Self as FileSystem>::read_at(self, path, offset, max_bytes).await
    }

    async fn lower_read_link<'a>(&'a self, path: FsPath<'a>) -> FsResult<String> {
        <Self as FileSystem>::read_link(self, path).await
    }

    async fn lower_read_dir_batch<'a>(
        &'a self,
        path: FsPath<'a>,
        cookie: DirCookie,
        max_entries: usize,
    ) -> FsResult<Vec<DirEntry>> {
        let dir = <Self as FileSystem>::open_dir(self, path).await?;
        dir.read(cookie, max_entries).await
    }

    async fn lower_read_whole<'a>(&'a self, path: FsPath<'a>) -> FsResult<FileContents> {
        self.file_contents(path).map(FileContents::Boot)
    }

    fn lower_boot_file_contents(&self, path: FsPath<'_>) -> Option<BootfsBytes> {
        self.file_contents(path).ok()
    }

    async fn lower_unix_node_metadata<'a>(
        &'a self,
        path: FsPath<'a>,
    ) -> Result<UnixNodeMetadata, UnixFsError> {
        let metadata = self.metadata(path)?;
        Ok(UnixNodeMetadata {
            kind: metadata.kind,
            attributes: BOOT_UNIX.inherited(metadata.kind),
            rdev: 0,
        })
    }

    async fn lower_xattr<'a>(
        &'a self,
        path: FsPath<'a>,
        _name: &'a str,
    ) -> Result<Option<Bytes>, UnixFsError> {
        let _ = self.metadata(path)?;
        Ok(None)
    }

    async fn lower_list_xattrs<'a>(&'a self, path: FsPath<'a>) -> Result<Vec<String>, UnixFsError> {
        let _ = self.metadata(path)?;
        Ok(Vec::new())
    }

    async fn lower_sync<'a>(&'a self, path: FsPath<'a>) -> FsResult<()> {
        <Self as FileSystem>::sync(self, path).await
    }

    async fn lower_sync_data<'a>(&'a self, path: FsPath<'a>) -> FsResult<()> {
        <Self as FileSystem>::sync_data(self, path).await
    }
}

/// An overlay filesystem: a private writable [`MemoryFs`] upper tree over a
/// shared read-only lower layer `L` (defaulting to [`BootFs`]).
#[derive(Clone)]
pub struct RootFs<L = BootFs> {
    upper: MemoryFs,
    lower: L,
}

/// A staged write into a [`RootFs`] overlay: lower files are copied up into
/// the `UserMemoryPool`-backed upper [`MemoryFs`] during `prepare_write`, and
/// the write lands directly into the upper tree.
pub type RootWrite = MemoryWrite;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Layer {
    Upper,
    Lower,
}

/// An object the overlay shows, with what the upper tree knows of its path.
struct Found {
    layer: Layer,
    metadata: Metadata,
    upper: UpperView,
}

/// A cookie with this bit set resumes in the lower layer's listing; one
/// without it resumes in the upper tree's.
const LOWER_COOKIE: u64 = 1 << 63;

impl<L: OverlayLower> RootFs<L> {
    pub fn new(upper: MemoryFs, lower: L) -> Self {
        Self { upper, lower }
    }

    pub fn upper(&self) -> &MemoryFs {
        &self.upper
    }

    pub fn lower(&self) -> &L {
        &self.lower
    }

    /// The Unix attributes of the object at `path`, from whichever layer
    /// serves it.
    pub async fn unix_attributes(&self, path: FsPath<'_>) -> FsResult<UnixAttributes> {
        let found = self.find(path).await?;
        match found.layer {
            Layer::Upper => Ok(self.upper.unix_metadata(path)?.attributes),
            Layer::Lower => self
                .lower
                .lower_unix_node_metadata(path)
                .await
                .map(|md| md.attributes)
                .map_err(UnixFsError::into_fs_error),
        }
    }

    pub async fn unix_node_metadata(
        &self,
        path: FsPath<'_>,
    ) -> Result<UnixNodeMetadata, UnixFsError> {
        let found = self.find(path).await?;
        match found.layer {
            Layer::Upper => self.upper.unix_node_metadata(path),
            Layer::Lower => self.lower.lower_unix_node_metadata(path).await,
        }
    }

    pub async fn open_unix(
        &self,
        path: FsPath<'_>,
        flags: OpenFlags,
        attributes: Attributes,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<Opened<OwnedFsPath>, UnixFsError> {
        alloc::boxed::Box::pin(async move {
            match self.find(path).await {
                Ok(found) => {
                    if flags.contains(OpenFlags::CREATE | OpenFlags::EXCLUSIVE) {
                        return Err(FsError::Exists.into());
                    }
                    if flags.contains(OpenFlags::DIRECTORY)
                        && found.metadata.kind != NodeKind::Directory
                    {
                        return Err(FsError::NotDirectory.into());
                    }
                    if flags.contains(OpenFlags::TRUNCATE) {
                        self.copy_up(path, true, payer).await?;
                        return self.upper.open_unix(path, flags, attributes, now, payer);
                    }
                    Ok(Opened {
                        metadata: found.metadata,
                        handle: path.into(),
                    })
                }
                Err(FsError::NoEntry) if flags.contains(OpenFlags::CREATE) => {
                    self.creatable(path).await?;
                    self.upper.open_unix(path, flags, attributes, now, payer)
                }
                Err(error) => Err(error.into()),
            }
        })
        .await
    }

    pub async fn create_directory_unix(
        &self,
        path: FsPath<'_>,
        attributes: Attributes,
        now: u64,
    ) -> Result<(), UnixFsError> {
        alloc::boxed::Box::pin(async move {
            self.creatable(path).await?;
            self.upper.create_directory_unix(path, attributes, now)
        })
        .await
    }

    pub async fn symlink_unix(
        &self,
        target: &str,
        path: FsPath<'_>,
        attributes: Attributes,
        now: u64,
    ) -> Result<(), UnixFsError> {
        alloc::boxed::Box::pin(async move {
            self.creatable(path).await?;
            self.upper.symlink_unix(target, path, attributes, now)
        })
        .await
    }

    pub async fn create_special_unix(
        &self,
        path: FsPath<'_>,
        special: Special,
        attributes: Attributes,
        now: u64,
    ) -> Result<(), UnixFsError> {
        alloc::boxed::Box::pin(async move {
            self.creatable(path).await?;
            self.upper
                .create_special_unix(path, special, attributes, now)
        })
        .await
    }

    pub async fn set_permissions(
        &self,
        path: FsPath<'_>,
        permissions: u32,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), UnixFsError> {
        alloc::boxed::Box::pin(async move {
            self.copy_up(path, false, payer).await?;
            self.upper.set_permissions(path, permissions, now)?;
            Ok(())
        })
        .await
    }

    pub async fn set_owner(
        &self,
        path: FsPath<'_>,
        uid: Option<u32>,
        gid: Option<u32>,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), UnixFsError> {
        alloc::boxed::Box::pin(async move {
            self.copy_up(path, false, payer).await?;
            self.upper.set_owner(path, uid, gid, now)?;
            Ok(())
        })
        .await
    }

    pub async fn xattr(&self, path: FsPath<'_>, name: &str) -> Result<Option<Bytes>, UnixFsError> {
        alloc::boxed::Box::pin(async move {
            let found = self.find(path).await?;
            match found.layer {
                Layer::Upper => Ok(self.upper.xattr(path, name)?),
                Layer::Lower => match self.lower.lower_xattr(path, name).await {
                    Ok(value) => Ok(value),
                    Err(UnixFsError::Fs(FsError::Unsupported)) => Ok(None),
                    Err(error) => Err(error),
                },
            }
        })
        .await
    }

    pub async fn list_xattrs(&self, path: FsPath<'_>) -> Result<Vec<String>, UnixFsError> {
        alloc::boxed::Box::pin(async move {
            let found = self.find(path).await?;
            match found.layer {
                Layer::Upper => Ok(self.upper.list_xattrs(path)?),
                Layer::Lower => match self.lower.lower_list_xattrs(path).await {
                    Ok(names) => Ok(names),
                    Err(UnixFsError::Fs(FsError::Unsupported)) => Ok(Vec::new()),
                    Err(error) => Err(error),
                },
            }
        })
        .await
    }

    pub async fn set_xattr(
        &self,
        path: FsPath<'_>,
        name: &str,
        value: Bytes,
        mode: XattrSetMode,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), UnixFsError> {
        alloc::boxed::Box::pin(async move {
            self.copy_up(path, false, payer).await?;
            self.upper.set_xattr_unix(path, name, value, mode, now)
        })
        .await
    }

    pub async fn remove_xattr(
        &self,
        path: FsPath<'_>,
        name: &str,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), UnixFsError> {
        alloc::boxed::Box::pin(async move {
            let found = self.find(path).await?;
            match found.layer {
                Layer::Upper => self.upper.remove_xattr_unix(path, name, now),
                Layer::Lower => {
                    let existing = match self.lower.lower_xattr(path, name).await {
                        Ok(value) => value,
                        Err(UnixFsError::Fs(FsError::Unsupported)) => None,
                        Err(error) => return Err(error),
                    };
                    if existing.is_none() {
                        return Err(UnixFsError::NoData);
                    }
                    self.copy_up(path, false, payer).await?;
                    self.upper.remove_xattr_unix(path, name, now)
                }
            }
        })
        .await
    }

    /// The whole of the file at `path`, typed by the layer that served it:
    /// the lower layer's own bytes, or the upper tree's.
    pub async fn read_whole(&self, path: FsPath<'_>) -> FsResult<FileContents> {
        match self.find(path).await?.layer {
            Layer::Upper => read_all(&self.upper, path).await.map(FileContents::Written),
            Layer::Lower => self.lower.lower_read_whole(path).await,
        }
    }

    /// The object `path` names, and the layer it comes from.
    async fn find(&self, path: FsPath<'_>) -> FsResult<Found> {
        let upper = self.upper.view(path)?;
        let (layer, metadata) = match &upper.object {
            Some(metadata) => (Layer::Upper, *metadata),
            None if upper.beneath => (Layer::Lower, self.lower.lower_stat(path).await?),
            None => return Err(FsError::NoEntry),
        };
        Ok(Found {
            layer,
            metadata,
            upper,
        })
    }

    /// Whether the lower layer has an object at `path` that shows once the
    /// upper tree's object there is gone: what a removal must hide.
    async fn lower_beneath(&self, path: FsPath<'_>, found: &Found) -> bool {
        found.upper.beneath
            && (found.layer == Layer::Lower || self.lower.lower_stat(path).await.is_ok())
    }

    /// Reads all extended attributes stored on the lower node at `path`,
    /// returning an empty map when the lower filesystem does not support
    /// extended attributes.
    async fn read_lower_xattrs(&self, path: FsPath<'_>) -> FsResult<BTreeMap<String, Bytes>> {
        let names = match self.lower.lower_list_xattrs(path).await {
            Ok(names) => names,
            Err(UnixFsError::Fs(FsError::Unsupported)) => return Ok(BTreeMap::new()),
            Err(error) => return Err(error.into_fs_error()),
        };
        let mut map = BTreeMap::new();
        for name in names {
            match self.lower.lower_xattr(path, &name).await {
                Ok(Some(value)) => {
                    map.insert(name, value);
                }
                Ok(None) | Err(UnixFsError::Fs(FsError::Unsupported)) => {}
                Err(error) => return Err(error.into_fs_error()),
            }
        }
        Ok(map)
    }

    /// Makes `directory` and every directory above it the upper tree's,
    /// copying up any lower directories among them with their stored Unix
    /// attributes and extended attributes.
    async fn copy_up_directories(&self, directory: FsPath<'_>) -> FsResult<()> {
        alloc::boxed::Box::pin(self.copy_up_directories_inner(directory)).await
    }

    async fn copy_up_directories_inner(&self, directory: FsPath<'_>) -> FsResult<()> {
        let full = directory.as_str();
        let ends = full
            .match_indices('/')
            .map(|(end, _)| end)
            .chain((!directory.is_root()).then_some(full.len()));
        for end in ends {
            let prefix = FsPath::new(&full[..end]).ok_or(FsError::Invalid)?;
            let found = self.find(prefix).await?;
            if found.metadata.kind != NodeKind::Directory {
                return Err(FsError::NotDirectory);
            }
            if found.layer == Layer::Lower {
                let unix_md = self
                    .lower
                    .lower_unix_node_metadata(prefix)
                    .await
                    .map_err(UnixFsError::into_fs_error)?;
                let xattrs = self.read_lower_xattrs(prefix).await?;
                self.upper.copy_up(
                    prefix,
                    NodeKind::Directory,
                    unix_md.attributes,
                    DeviceNumber::decode(unix_md.rdev),
                    xattrs,
                    CopyUpContents::Empty,
                    &found.metadata,
                    None,
                )?;
            }
        }
        Ok(())
    }

    /// Makes the object at `path` the upper tree's, copying a lower object up
    /// with its data (in `UserMemoryPool` frames for non-boot lowers), times,
    /// Unix metadata, device number, and extended attributes before anything
    /// changes it.
    ///
    /// When `truncate` is `true` for a regular file, lower data bytes are
    /// skipped so an `O_TRUNC` open or zero-length truncate does not allocate
    /// frames for bytes that are immediately discarded.
    async fn copy_up(
        &self,
        path: FsPath<'_>,
        truncate: bool,
        payer: &crate::StoragePayer,
    ) -> FsResult<Found> {
        alloc::boxed::Box::pin(self.copy_up_inner(path, truncate, payer)).await
    }

    async fn copy_up_inner(
        &self,
        path: FsPath<'_>,
        truncate: bool,
        payer: &crate::StoragePayer,
    ) -> FsResult<Found> {
        let found = self.find(path).await?;
        if found.layer == Layer::Upper {
            return Ok(found);
        }
        let unix_md = self
            .lower
            .lower_unix_node_metadata(path)
            .await
            .map_err(UnixFsError::into_fs_error)?;
        let xattrs = self.read_lower_xattrs(path).await?;
        let contents = match found.metadata.kind {
            NodeKind::File if truncate => {
                CopyUpContents::Paged(self.upper.new_paged_file(Some(payer)))
            }
            NodeKind::File => {
                if let Some(boot) = self.lower.lower_boot_file_contents(path) {
                    // The boot image's static bytes, not a copy of them: the
                    // upper tree copies a page out into user-pool frames only
                    // when written.
                    CopyUpContents::BootBase(boot.to_bytes())
                } else {
                    // Stream lower file bytes directly into `UserMemoryPool`
                    // frames outside the tree lock, respecting the machine's
                    // memory-storage budget and user-pool capacity.
                    let mut paged = self.upper.new_paged_file(Some(payer));
                    let total = found.metadata.size;
                    let mut offset = 0u64;
                    while offset < total {
                        let want = usize::try_from(total - offset)
                            .map_or(COPY_UP_CHUNK_BYTES, |left| left.min(COPY_UP_CHUNK_BYTES));
                        let chunk = self.lower.lower_read_at(path, offset, want).await?;
                        if chunk.is_empty() {
                            break;
                        }
                        paged.write_chunk(offset, &chunk)?;
                        offset = offset
                            .checked_add(chunk.len() as u64)
                            .ok_or(FsError::Overflow)?;
                    }
                    if offset < total {
                        let _ = paged.set_len(total);
                    }
                    CopyUpContents::Paged(paged)
                }
            }
            NodeKind::Symlink => CopyUpContents::Symlink(Bytes::from(
                self.lower.lower_read_link(path).await?.into_bytes(),
            )),
            NodeKind::Directory
            | NodeKind::CharacterDevice
            | NodeKind::BlockDevice
            | NodeKind::Fifo
            | NodeKind::Socket => CopyUpContents::Empty,
        };
        if let Some((parent, _)) = path.split_last() {
            self.copy_up_directories(parent).await?;
        }
        self.upper.copy_up(
            path,
            found.metadata.kind,
            unix_md.attributes,
            DeviceNumber::decode(unix_md.rdev),
            xattrs,
            contents,
            &found.metadata,
            Some(payer),
        )?;
        self.find(path).await
    }

    /// Checks that `path` names nothing and readies its directory in the
    /// upper tree for the new name.
    async fn creatable(&self, path: FsPath<'_>) -> FsResult<()> {
        let Some((parent, _)) = path.split_last() else {
            return Err(FsError::Exists);
        };
        match self.find(path).await {
            Ok(_) => return Err(FsError::Exists),
            Err(FsError::NoEntry) => {}
            Err(error) => return Err(error),
        }
        self.copy_up_directories(parent).await
    }

    /// Whether the directory `found` names is one the lower layer has a
    /// part in: a lower directory, or an upper one merging a lower one.
    async fn merges_lower(&self, path: FsPath<'_>, found: &Found) -> bool {
        match found.layer {
            Layer::Lower => true,
            Layer::Upper => {
                !found.upper.opaque
                    && found.upper.beneath
                    && self
                        .lower
                        .lower_stat(path)
                        .await
                        .is_ok_and(|lower| lower.kind == NodeKind::Directory)
            }
        }
    }

    async fn read_lower(
        &self,
        path: FsPath<'_>,
        cookie: DirCookie,
        max_entries: usize,
    ) -> FsResult<Vec<DirEntry>> {
        let mut entries = Vec::new();
        let mut cookie = cookie;
        // Lower entries the upper tree shadows or hides are skipped, so one
        // pass may come back short of `max_entries` without being the last.
        while entries.len() < max_entries {
            let batch = self
                .lower
                .lower_read_dir_batch(path, cookie, max_entries - entries.len())
                .await?;
            let complete = batch.len() < max_entries - entries.len();
            for mut entry in batch {
                cookie = entry.next;
                let child = super::join_fs_path(path, &entry.name);
                let child = FsPath::new(&child).ok_or(FsError::Invalid)?;
                let upper = self.upper.view(child)?;
                if upper.object.is_some() || !upper.beneath {
                    continue;
                }
                entry.next = DirCookie::new(entry.next.raw() | LOWER_COOKIE);
                entries.push(entry);
            }
            if complete {
                break;
            }
        }
        Ok(entries)
    }

    async fn read_dir_at(
        &self,
        path: FsPath<'_>,
        cookie: DirCookie,
        max_entries: usize,
    ) -> FsResult<Vec<DirEntry>> {
        alloc::boxed::Box::pin(self.read_dir_at_inner(path, cookie, max_entries)).await
    }

    async fn read_dir_at_inner(
        &self,
        path: FsPath<'_>,
        cookie: DirCookie,
        max_entries: usize,
    ) -> FsResult<Vec<DirEntry>> {
        let found = self.find(path).await?;
        if found.metadata.kind != NodeKind::Directory {
            return Err(FsError::NotDirectory);
        }
        let in_upper = found.layer == Layer::Upper;
        let merges = !found.upper.opaque && found.upper.beneath;
        if cookie.raw() & LOWER_COOKIE != 0 || !in_upper {
            if !merges {
                // The directory turned opaque since the listing began.
                return Ok(Vec::new());
            }
            let lower_cookie = DirCookie::new(cookie.raw() & !LOWER_COOKIE);
            return self.read_lower(path, lower_cookie, max_entries).await;
        }
        let mut entries = self.upper.read_dir_at(path, cookie, max_entries)?;
        if merges && entries.len() < max_entries {
            match self
                .read_lower(path, DirCookie::START, max_entries - entries.len())
                .await
            {
                Ok(lower) => entries.extend(lower),
                // An upper directory the lower layer does not have.
                Err(FsError::NoEntry) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(entries)
    }
}

/// An open directory stream over a [`RootFs`].
pub struct RootDir<L = BootFs> {
    fs: RootFs<L>,
    path: OwnedFsPath,
}

impl<L: OverlayLower> DirStream for RootDir<L> {
    async fn read(&self, cookie: DirCookie, max_entries: usize) -> FsResult<Vec<DirEntry>> {
        self.fs
            .read_dir_at(self.path.as_path(), cookie, max_entries)
            .await
    }

    async fn rewind(&mut self) -> FsResult<()> {
        Ok(())
    }
}

impl<L: OverlayLower> FileSystem for RootFs<L> {
    type Payer = crate::StoragePayer;
    super::delegate_path_handles!();
    type Write = RootWrite;
    type Dir = RootDir<L>;

    async fn stat(&self, path: FsPath<'_>) -> FsResult<Metadata> {
        self.find(path).await.map(|found| found.metadata)
    }

    async fn open(
        &self,
        path: FsPath<'_>,
        flags: OpenFlags,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> FsResult<Opened<OwnedFsPath>> {
        alloc::boxed::Box::pin(async move {
            match self.find(path).await {
                Ok(found) if found.layer == Layer::Upper => {
                    self.upper.open(path, flags, now, payer).await
                }
                Ok(_) if flags.contains(OpenFlags::TRUNCATE) => {
                    self.copy_up(path, true, payer).await?;
                    self.upper.open(path, flags, now, payer).await
                }
                Ok(_) => self.lower.lower_open(path, flags, now, payer).await,
                Err(FsError::NoEntry) if flags.contains(OpenFlags::CREATE) => {
                    self.creatable(path).await?;
                    self.upper.open(path, flags, now, payer).await
                }
                Err(error) => Err(error),
            }
        })
        .await
    }

    async fn read_at(&self, path: FsPath<'_>, offset: u64, max_bytes: usize) -> FsResult<Bytes> {
        match self.find(path).await?.layer {
            Layer::Upper => self.upper.read_at(path, offset, max_bytes).await,
            Layer::Lower => self.lower.lower_read_at(path, offset, max_bytes).await,
        }
    }

    async fn prepare_write(
        &self,
        path: FsPath<'_>,
        position: WritePosition,
        len: usize,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> FsResult<RootWrite> {
        alloc::boxed::Box::pin(async move {
            self.find(path).await?.metadata.kind.require_regular()?;
            self.copy_up(path, false, payer).await?;
            MemoryWrite::prepare(&self.upper, path, position, len, now, payer)
        })
        .await
    }

    async fn set_size(
        &self,
        path: FsPath<'_>,
        size: u64,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> FsResult<()> {
        alloc::boxed::Box::pin(async move {
            self.copy_up(path, size == 0, payer).await?;
            self.upper.set_size(path, size, now, payer).await
        })
        .await
    }

    async fn set_times(
        &self,
        path: FsPath<'_>,
        access_nanos: Option<u64>,
        modified_nanos: Option<u64>,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> FsResult<()> {
        alloc::boxed::Box::pin(async move {
            self.copy_up(path, false, payer).await?;
            self.upper
                .set_times(path, access_nanos, modified_nanos, now, payer)
                .await
        })
        .await
    }

    async fn open_dir(&self, path: FsPath<'_>) -> FsResult<RootDir<L>> {
        let found = self.find(path).await?;
        if found.metadata.kind != NodeKind::Directory {
            return Err(FsError::NotDirectory);
        }
        Ok(RootDir {
            fs: self.clone(),
            path: OwnedFsPath::from(path),
        })
    }

    async fn create_directory(
        &self,
        path: FsPath<'_>,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> FsResult<()> {
        alloc::boxed::Box::pin(async move {
            self.creatable(path).await?;
            self.upper.create_directory(path, now, payer).await
        })
        .await
    }

    async fn remove_directory(
        &self,
        path: FsPath<'_>,
        now: u64,
        _payer: &crate::StoragePayer,
    ) -> FsResult<()> {
        alloc::boxed::Box::pin(async move {
            let Some((parent, _)) = path.split_last() else {
                return Err(FsError::NotPermitted);
            };
            let found = self.find(path).await?;
            if found.metadata.kind != NodeKind::Directory {
                return Err(FsError::NotDirectory);
            }
            // The upper tree refuses a directory of its own that holds a name;
            // the lower entries still showing are this layer's to count.
            if !self
                .read_dir_at(path, DirCookie::START, 1)
                .await?
                .is_empty()
            {
                return Err(FsError::NotEmpty);
            }
            let whiteout = self.lower_beneath(path, &found).await;
            if whiteout {
                self.copy_up_directories(parent).await?;
            }
            self.upper.remove(path, true, whiteout, now)
        })
        .await
    }

    async fn unlink(
        &self,
        path: FsPath<'_>,
        now: u64,
        _payer: &crate::StoragePayer,
    ) -> FsResult<()> {
        alloc::boxed::Box::pin(async move {
            let Some((parent, _)) = path.split_last() else {
                return Err(FsError::IsDirectory);
            };
            let found = self.find(path).await?;
            if found.metadata.kind == NodeKind::Directory {
                return Err(FsError::IsDirectory);
            }
            let whiteout = self.lower_beneath(path, &found).await;
            if whiteout {
                self.copy_up_directories(parent).await?;
            }
            self.upper.remove(path, false, whiteout, now)
        })
        .await
    }

    async fn rename(
        &self,
        source: FsPath<'_>,
        destination: FsPath<'_>,
        mode: RenameMode,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> FsResult<()> {
        alloc::boxed::Box::pin(async move {
            let found = self.find(source).await?;
            if mode == RenameMode::Exchange {
                // Both names stay, so the swap needs no whiteout. A directory
                // merging the lower layer's would carry that merge to its new
                // name, which an overlay without redirects cannot express.
                let other = self.find(destination).await?;
                for (path, found) in [(source, &found), (destination, &other)] {
                    if found.metadata.kind == NodeKind::Directory
                        && self.merges_lower(path, found).await
                    {
                        return Err(FsError::CrossDevice);
                    }
                }
                self.copy_up(source, false, payer).await?;
                self.copy_up(destination, false, payer).await?;
                return self
                    .upper
                    .rename_over(source, destination, mode, now, false);
            }
            if source == destination {
                return match mode {
                    RenameMode::NoReplace => Err(FsError::Exists),
                    RenameMode::Replace | RenameMode::Exchange => Ok(()),
                };
            }
            if found.metadata.kind == NodeKind::Directory && self.merges_lower(source, &found).await
            {
                return Err(FsError::CrossDevice);
            }
            if mode == RenameMode::NoReplace {
                self.creatable(destination).await?;
            } else {
                let Some((parent, _)) = destination.split_last() else {
                    return Err(FsError::NotPermitted);
                };
                match self.find(destination).await {
                    Ok(dest_found) => {
                        match (
                            found.metadata.kind == NodeKind::Directory,
                            dest_found.metadata.kind == NodeKind::Directory,
                        ) {
                            (true, false) => return Err(FsError::NotDirectory),
                            (false, true) => return Err(FsError::IsDirectory),
                            (true, true)
                                if !self
                                    .read_dir_at(destination, DirCookie::START, 1)
                                    .await?
                                    .is_empty() =>
                            {
                                return Err(FsError::NotEmpty);
                            }
                            _ => {}
                        }
                        self.copy_up_directories(parent).await?;
                    }
                    Err(FsError::NoEntry) => {
                        self.copy_up_directories(parent).await?;
                    }
                    Err(error) => return Err(error),
                }
            }
            let found = self.copy_up(source, false, payer).await?;
            let whiteout = self.lower_beneath(source, &found).await;
            self.upper
                .rename_over(source, destination, mode, now, whiteout)
        })
        .await
    }

    async fn link(
        &self,
        existing: FsPath<'_>,
        link: FsPath<'_>,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> FsResult<()> {
        alloc::boxed::Box::pin(async move {
            if self.find(existing).await?.metadata.kind == NodeKind::Directory {
                return Err(FsError::NotPermitted);
            }
            self.creatable(link).await?;
            self.copy_up(existing, false, payer).await?;
            self.upper.link(existing, link, now, payer).await
        })
        .await
    }

    async fn symlink(
        &self,
        target: &str,
        link: FsPath<'_>,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> FsResult<()> {
        alloc::boxed::Box::pin(async move {
            self.creatable(link).await?;
            self.upper.symlink(target, link, now, payer).await
        })
        .await
    }

    async fn read_link(&self, path: FsPath<'_>) -> FsResult<String> {
        match self.find(path).await?.layer {
            Layer::Upper => self.upper.read_link(path).await,
            Layer::Lower => self.lower.lower_read_link(path).await,
        }
    }

    async fn sync(&self, path: FsPath<'_>) -> FsResult<()> {
        match self.find(path).await?.layer {
            Layer::Upper => self.upper.sync(path).await,
            Layer::Lower => self.lower.lower_sync(path).await,
        }
    }

    async fn sync_data(&self, path: FsPath<'_>) -> FsResult<()> {
        match self.find(path).await?.layer {
            Layer::Upper => self.upper.sync_data(path).await,
            Layer::Lower => self.lower.lower_sync_data(path).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;

    use futures_lite::future::block_on;
    use helios_hal::fs::{
        DeviceId, DirCookie, DirStream, FileSystem, FsError, FsPath, OpenFlags, RenameMode,
        WritePosition,
    };

    use super::RootFs;
    use crate::vfs::{FileContents, MemoryFs, write_bytes};
    use crate::{BootFs, EmbeddedBootDirectory, EmbeddedBootFile, EmbeddedBootFs};

    const IMAGE: EmbeddedBootFs = EmbeddedBootFs::new(
        &[EmbeddedBootDirectory::new("bin/empty", 43)],
        &[
            EmbeddedBootFile::new("bin/tool", b"tool", 42),
            EmbeddedBootFile::new("etc/motd", "日本語 한국어 中文".as_bytes(), 7),
            EmbeddedBootFile::new("init.txt", b"hello", 1),
        ],
    );

    fn root() -> RootFs {
        RootFs::new(
            MemoryFs::new(DeviceId::new(4)),
            BootFs::new(IMAGE, DeviceId::new(1)),
        )
    }

    fn path(path: &str) -> FsPath<'_> {
        FsPath::new(path).expect("test paths are valid")
    }

    fn listing(fs: &RootFs, directory: &str, batch: usize) -> Vec<String> {
        let dir = block_on(fs.open_dir(path(directory))).expect("opens directory");
        let mut names = Vec::new();
        let mut cookie = DirCookie::START;
        loop {
            let entries = block_on(dir.read(cookie, batch)).expect("directory lists");
            let complete = entries.len() < batch;
            for entry in entries {
                cookie = entry.next;
                names.push(entry.name);
            }
            if complete {
                names.sort();
                return names;
            }
        }
    }

    fn write(fs: &RootFs, file: &str, position: WritePosition, data: &[u8], now: u64) -> u64 {
        block_on(write_bytes(fs, path(file), position, data, now)).expect("writes")
    }

    fn contents(fs: &RootFs, file: &str) -> Vec<u8> {
        block_on(fs.read_at(path(file), 0, 64))
            .expect("reads")
            .to_vec()
    }

    #[test]
    fn the_root_merges_both_layers_in_every_batch_size() {
        let fs = root();
        block_on(fs.create_directory(path("d"), 1, &crate::StoragePayer::for_test()))
            .expect("creates in the upper root");
        block_on(fs.open(
            path("d/f"),
            OpenFlags::CREATE,
            1,
            &crate::StoragePayer::for_test(),
        ))
        .expect("creates");
        for batch in [1, 2, 64] {
            assert_eq!(
                listing(&fs, "", batch),
                ["bin", "d", "etc", "init.txt"],
                "batch of {batch}"
            );
        }
        assert_eq!(listing(&fs, "bin", 1), ["empty", "tool"]);
        assert_eq!(listing(&fs, "d", 8), ["f"]);
    }

    #[test]
    fn a_boot_file_is_copied_up_before_it_changes() {
        let lower = BootFs::new(IMAGE, DeviceId::new(1));
        let fs = RootFs::new(MemoryFs::new(DeviceId::new(4)), lower.clone());
        let boot_id = block_on(fs.stat(path("init.txt"))).expect("stats").id;

        write(&fs, "init.txt", WritePosition::At(0), b"J", 2);
        assert_eq!(contents(&fs, "init.txt"), b"Jello");
        assert_eq!(write(&fs, "init.txt", WritePosition::End, b"!", 3), 5);
        block_on(fs.set_size(path("etc/motd"), 9, 4, &crate::StoragePayer::for_test()))
            .expect("truncates a copy");
        assert_eq!(contents(&fs, "etc/motd"), "日本語".as_bytes());
        let copy = block_on(fs.stat(path("init.txt"))).expect("stats");
        assert_ne!(copy.id, boot_id, "the copy is the upper tree's object");
        assert!(matches!(
            block_on(fs.read_whole(path("init.txt"))),
            Ok(FileContents::Written(bytes)) if bytes.as_ref() == b"Jello!"
        ));

        let untouched = RootFs::new(MemoryFs::new(DeviceId::new(4)), lower);
        assert_eq!(contents(&untouched, "init.txt"), b"hello");
        assert!(matches!(
            block_on(untouched.read_whole(path("init.txt"))),
            Ok(FileContents::Boot(_))
        ));
        assert_eq!(listing(&fs, "etc", 8), ["motd"]);
    }

    #[test]
    fn a_new_name_goes_into_a_boot_directory() {
        let fs = root();
        let payer = crate::StoragePayer::for_test();
        block_on(fs.open(path("bin/new"), OpenFlags::CREATE, 1, &payer)).expect("creates");
        block_on(fs.create_directory(path("bin/empty/inner"), 1, &payer)).expect("creates");
        block_on(fs.symlink("tool", path("bin/alias"), 1, &payer)).expect("links");
        assert_eq!(listing(&fs, "bin", 1), ["alias", "empty", "new", "tool"]);
        assert_eq!(listing(&fs, "bin/empty", 8), ["inner"]);
        assert_eq!(
            block_on(fs.create_directory(path("bin"), 1, &payer)),
            Err(FsError::Exists)
        );
        assert_eq!(
            block_on(fs.open(path("init.txt/x"), OpenFlags::CREATE, 1, &payer)).map(drop),
            Err(FsError::NotDirectory)
        );
    }

    #[test]
    fn removing_a_boot_object_leaves_a_whiteout() {
        let fs = root();
        let payer = crate::StoragePayer::for_test();
        assert_eq!(
            block_on(fs.remove_directory(path("bin"), 7_000_000_000, &payer)),
            Err(FsError::NotEmpty)
        );
        block_on(fs.unlink(path("bin/tool"), 7_000_000_000, &payer)).expect("removes a boot file");
        assert_eq!(
            block_on(fs.stat(path("bin/tool"))).map(drop),
            Err(FsError::NoEntry)
        );
        assert_eq!(listing(&fs, "bin", 1), ["empty"]);
        block_on(fs.remove_directory(path("bin/empty"), 7_000_000_000, &payer))
            .expect("removes a boot directory");
        block_on(fs.remove_directory(path("bin"), 7_000_000_000, &payer)).expect("now empty");
        assert_eq!(listing(&fs, "", 8), ["etc", "init.txt"]);

        // A copied-up file removed is hidden too, not uncovered.
        write(&fs, "init.txt", WritePosition::At(0), b"J", 1);
        block_on(fs.unlink(path("init.txt"), 7_000_000_000, &payer)).expect("removes the copy");
        assert_eq!(
            block_on(fs.stat(path("init.txt"))).map(drop),
            Err(FsError::NoEntry)
        );

        // A name made where a whiteout is starts afresh.
        block_on(fs.open(path("init.txt"), OpenFlags::CREATE, 2, &payer)).expect("creates");
        assert_eq!(contents(&fs, "init.txt"), b"");
    }

    #[test]
    fn a_directory_made_over_a_whiteout_shows_nothing_beneath() {
        let fs = root();
        let payer = crate::StoragePayer::for_test();
        block_on(fs.unlink(path("etc/motd"), 7_000_000_000, &payer)).expect("removes");
        block_on(fs.remove_directory(path("etc"), 7_000_000_000, &payer)).expect("removes");
        block_on(fs.create_directory(path("etc"), 1, &payer)).expect("makes it again");
        assert_eq!(listing(&fs, "etc", 8), Vec::<String>::new());
        assert_eq!(
            block_on(fs.stat(path("etc/motd"))).map(drop),
            Err(FsError::NoEntry)
        );
    }

    #[test]
    fn renaming_copies_a_boot_file_up_and_refuses_a_boot_directory() {
        let fs = root();
        let payer = crate::StoragePayer::for_test();
        block_on(fs.rename(
            path("init.txt"),
            path("moved.txt"),
            RenameMode::Replace,
            1,
            &payer,
        ))
        .expect("renames");
        assert_eq!(contents(&fs, "moved.txt"), b"hello");
        assert_eq!(
            block_on(fs.stat(path("init.txt"))).map(drop),
            Err(FsError::NoEntry)
        );
        assert_eq!(
            block_on(fs.rename(path("bin"), path("sbin"), RenameMode::Replace, 1, &payer)),
            Err(FsError::CrossDevice)
        );
        // Copied up by the new name, `bin` still merges the image.
        block_on(fs.open(path("bin/new"), OpenFlags::CREATE, 1, &payer)).expect("creates");
        assert_eq!(
            block_on(fs.rename(path("bin"), path("sbin"), RenameMode::Replace, 1, &payer)),
            Err(FsError::CrossDevice)
        );
        block_on(fs.rename(
            path("bin/tool"),
            path("bin/empty/tool"),
            RenameMode::Replace,
            1,
            &payer,
        ))
        .expect("renames");
        assert_eq!(listing(&fs, "bin", 8), ["empty", "new"]);
        assert_eq!(contents(&fs, "bin/empty/tool"), b"tool");

        block_on(fs.create_directory(path("d"), 1, &payer)).expect("creates");
        block_on(fs.rename(path("d"), path("bin/d"), RenameMode::Replace, 1, &payer))
            .expect("an upper directory moves");
    }

    #[test]
    fn noreplace_sees_a_boot_destination_and_exchange_copies_boot_files_up() {
        let fs = root();
        let payer = crate::StoragePayer::for_test();
        assert_eq!(
            block_on(fs.rename(
                path("init.txt"),
                path("etc/motd"),
                RenameMode::NoReplace,
                1,
                &payer,
            )),
            Err(FsError::Exists)
        );
        assert_eq!(
            block_on(fs.rename(
                path("init.txt"),
                path("init.txt"),
                RenameMode::NoReplace,
                1,
                &payer,
            )),
            Err(FsError::Exists)
        );
        block_on(fs.rename(
            path("init.txt"),
            path("fresh"),
            RenameMode::NoReplace,
            1,
            &payer,
        ))
        .expect("renames");
        assert_eq!(contents(&fs, "fresh"), b"hello");
        // Two boot files swap contents between their names.
        block_on(fs.rename(
            path("fresh"),
            path("etc/motd"),
            RenameMode::Exchange,
            2,
            &payer,
        ))
        .expect("exchanges");
        assert_eq!(contents(&fs, "etc/motd"), b"hello");
        assert_eq!(contents(&fs, "fresh"), "日本語 한국어 中文".as_bytes());
        block_on(fs.rename(
            path("bin/tool"),
            path("fresh"),
            RenameMode::Exchange,
            3,
            &payer,
        ))
        .expect("exchanges");
        assert_eq!(contents(&fs, "bin/tool"), "日本語 한국어 中文".as_bytes());
        assert_eq!(contents(&fs, "fresh"), b"tool");
        // A directory merging the boot image's cannot change places, as for
        // any rename of one; a missing name is not found.
        assert_eq!(
            block_on(fs.rename(path("bin"), path("fresh"), RenameMode::Exchange, 4, &payer)),
            Err(FsError::CrossDevice)
        );
        assert_eq!(
            block_on(fs.rename(path("fresh"), path("none"), RenameMode::Exchange, 4, &payer)),
            Err(FsError::NoEntry)
        );
    }

    #[test]
    fn a_hard_link_to_a_boot_file_copies_it_up() {
        let fs = root();
        let payer = crate::StoragePayer::for_test();
        block_on(fs.link(path("etc/motd"), path("motd"), 1, &payer)).expect("links");
        let original = block_on(fs.stat(path("etc/motd"))).expect("stats");
        let link = block_on(fs.stat(path("motd"))).expect("stats");
        assert_eq!((original.id, original.link_count), (link.id, 2));
        write(&fs, "motd", WritePosition::At(0), "中文".as_bytes(), 2);
        assert_eq!(&contents(&fs, "etc/motd")[..6], "中文".as_bytes());
        assert_eq!(
            block_on(fs.link(path("bin"), path("bin2"), 1, &payer)),
            Err(FsError::NotPermitted)
        );
    }

    #[test]
    fn two_roots_over_one_image_keep_their_writes_apart() {
        let lower = BootFs::new(IMAGE, DeviceId::new(1));
        let first = RootFs::new(MemoryFs::new(DeviceId::new(4)), lower.clone());
        let second = RootFs::new(MemoryFs::new(DeviceId::new(4)), lower);
        let payer = crate::StoragePayer::for_test();
        block_on(first.open(path("mine"), OpenFlags::CREATE, 1, &payer)).expect("creates");
        block_on(first.unlink(path("bin/tool"), 7_000_000_000, &payer)).expect("removes");
        assert_eq!(
            block_on(second.stat(path("mine"))).map(drop),
            Err(FsError::NoEntry)
        );
        assert_eq!(contents(&second, "bin/tool"), b"tool");
    }

    #[test]
    fn overlay_copy_up_and_writes_charge_user_memory_pool_and_enforce_nospace_and_oom() {
        use crate::test_support::UnsupportedStorage;
        use crate::vfs::memory::{
            MemoryStorageBudget, MemoryStorageSetting, tests::isolated_user_pool,
        };
        use crate::vfs::{
            MountGrant, MountSharing, MountTable, MountedFs, Namespace, OverlayFs, PinnedLower,
            XattrSetMode,
        };
        use helios_hal::fs::FileSystemRights;

        let page = helios_hal::pmm::PhysFrame::SIZE as u64;
        // Build a read-only lower directory holding a 3-page file with Unix
        // metadata (uid/gid/suid) and security.capability + CJK xattrs.
        let lower_mem = MemoryFs::new(DeviceId::new(21));
        let lower_payer = crate::StoragePayer::for_test();
        let three_pages = alloc::vec![0x5a_u8; 3 * page as usize];
        block_on(lower_mem.open(path("payload.bin"), OpenFlags::CREATE, 1, &lower_payer))
            .expect("create lower file");
        block_on(helios_hal::fs::write_with(
            &lower_mem,
            path("payload.bin"),
            WritePosition::At(0),
            three_pages.len(),
            2,
            &lower_payer,
            |offset, dst| dst.copy_from_slice(&three_pages[offset..offset + dst.len()]),
        ))
        .expect("write lower payload");
        lower_mem
            .set_owner(path("payload.bin"), Some(42), Some(43), 3)
            .expect("chown lower");
        lower_mem
            .set_permissions(path("payload.bin"), 0o4755, 4)
            .expect("chmod lower");
        lower_mem
            .set_xattr_unix(
                path("payload.bin"),
                "security.capability",
                bytes::Bytes::from_static(b"\x01\x00\x00\x02"),
                XattrSetMode::Any,
                5,
            )
            .expect("setxattr cap");
        lower_mem
            .set_xattr_unix(
                path("payload.bin"),
                "user.greeting",
                bytes::Bytes::from_static("日本語 한국어 中文".as_bytes()),
                XattrSetMode::Any,
                6,
            )
            .expect("setxattr cjk");

        const IMG_BOOT: EmbeddedBootFs =
            EmbeddedBootFs::new(&[EmbeddedBootDirectory::new("img", 0)], &[]);
        let boot_fs = BootFs::new(IMG_BOOT, DeviceId::new(1));
        let ns = Namespace::<UnsupportedStorage>::new(MountTable::new(boot_fs, 4));
        let root_auth = crate::ProcessAuthority::root();
        block_on(ns.mount(
            &root_auth.derive_mount_cap("/img").unwrap(),
            MountedFs::Memory(lower_mem.clone()),
            MountGrant {
                rights: FileSystemRights::READ,
                sharing: MountSharing::Shared,
            },
        ))
        .expect("mount lower");
        let held = ns.resolve("/img").expect("resolve /img").held();
        let pinned = PinnedLower::from_held(held).expect("pin lower");

        // Isolated pool drained to 3 free frames; live setting starts at 2 pages.
        let pool = isolated_user_pool(64);
        let free_frames = (pool.stats().total_bytes - pool.stats().allocated_bytes) / page as usize;
        let _drain = crate::memory::FrameReservation::take(pool, (free_frames - 3) as u64)
            .expect("drain leaves 3 free frames");
        let drained_allocated = pool.stats().allocated_bytes as u64;

        let settings =
            triomphe::Arc::new(crossbeam_utils::CachePadded::new(crate::Settings::default()));
        let mut op = crate::ProcessAuthority::empty();
        op.grant_settings_rights(crate::SettingsAuthorityRights::WRITE);
        let proof = op.derive_write_settings_cap().expect("write settings cap");
        settings.set::<MemoryStorageSetting>(&proof, 2 * page);

        let budget = MemoryStorageBudget::new(pool, settings.clone());
        let upper = MemoryFs::with_budget(DeviceId::new(22), budget.clone());
        let overlay = OverlayFs::new(upper, pinned.clone());
        let registry = crate::InstanceRegistry::new();
        let inst = registry.register("overlay-user", 0);
        let payer = inst.storage_payer();

        // 1. Copy-up of the 3-page lower file exceeds the 2-page budget -> NoSpace,
        //    leaving zero leaked frames or budget and lower untouched.
        assert_eq!(
            block_on(overlay.set_owner(path("payload.bin"), Some(100), None, 7, &payer)),
            Err(crate::vfs::UnixFsError::Fs(FsError::NoSpace))
        );
        assert_eq!(budget.used_bytes(), 0);
        assert_eq!(inst.storage_bytes(), 0);
        assert_eq!(pool.stats().allocated_bytes as u64, drained_allocated);

        // 2. Raise budget to 16 pages (above the 3 free frames left in the pool):
        //    copying up a 3-page file needs 3 data + 1 index frame = 4 frames -> OutOfMemory!
        settings.set::<MemoryStorageSetting>(&proof, 16 * page);
        assert_eq!(
            block_on(overlay.set_owner(path("payload.bin"), Some(100), None, 8, &payer)),
            Err(crate::vfs::UnixFsError::Fs(FsError::OutOfMemory))
        );
        assert_eq!(budget.used_bytes(), 0);
        assert_eq!(inst.storage_bytes(), 0);
        assert_eq!(pool.stats().allocated_bytes as u64, drained_allocated);

        // 3. Truncating open (`O_TRUNC`) skips lower data bytes, so it succeeds
        //    within the 3 free frames and does NOT allocate for discarded lower pages.
        block_on(overlay.open(path("payload.bin"), OpenFlags::TRUNCATE, 9, &payer))
            .expect("O_TRUNC skips lower data copy-up");
        assert_eq!(
            block_on(overlay.stat(path("payload.bin")))
                .expect("stat")
                .size,
            0
        );
        // Preserves lower Unix metadata & xattrs even on truncate copy-up!
        let md = block_on(overlay.unix_node_metadata(path("payload.bin"))).expect("unix md");
        assert_eq!(md.attributes.uid, 42);
        assert_eq!(md.attributes.gid, 43);
        assert_eq!(md.attributes.permissions, 0o4755);
        assert_eq!(
            block_on(overlay.xattr(path("payload.bin"), "security.capability")).expect("xattr"),
            Some(bytes::Bytes::from_static(b"\x01\x00\x00\x02"))
        );
        assert_eq!(
            block_on(overlay.xattr(path("payload.bin"), "user.greeting")).expect("xattr cjk"),
            Some(bytes::Bytes::from_static("日本語 한국어 中文".as_bytes()))
        );

        // 4. Write 1 page into the upper file -> charges budget, instance, and UserMemoryPool.
        let one_page = alloc::vec![0xcd_u8; page as usize];
        block_on(helios_hal::fs::write_with(
            &overlay,
            path("payload.bin"),
            WritePosition::At(0),
            one_page.len(),
            10,
            &payer,
            |offset, dst| dst.copy_from_slice(&one_page[offset..offset + dst.len()]),
        ))
        .expect("1-page upper write succeeds");
        assert_eq!(budget.used_bytes(), page);
        assert_eq!(inst.storage_bytes(), page);

        // 5. Lower file is completely untouched; dropping the overlay reclaims all frames.
        assert_eq!(
            block_on(lower_mem.stat(path("payload.bin")))
                .expect("lower stat")
                .size,
            3 * page
        );
        drop(overlay);
        assert_eq!(budget.used_bytes(), 0);
        assert_eq!(inst.storage_bytes(), 0);
        assert_eq!(pool.stats().allocated_bytes as u64, drained_allocated);
    }

    #[test]
    fn overlay_whiteout_opaque_dir_and_xattr_removal_preserve_readonly_lower() {
        use crate::test_support::UnsupportedStorage;
        use crate::vfs::{
            MountGrant, MountSharing, MountTable, MountedFs, Namespace, OverlayFs, PinnedLower,
            XattrSetMode,
        };
        use helios_hal::fs::FileSystemRights;

        let lower_mem = MemoryFs::new(DeviceId::new(31));
        let payer = crate::StoragePayer::for_test();
        block_on(lower_mem.create_directory(path("dir"), 1, &payer)).expect("mkdir");
        block_on(lower_mem.open(path("dir/old"), OpenFlags::CREATE, 2, &payer)).expect("create");
        lower_mem
            .set_xattr_unix(
                path("dir/old"),
                "security.capability",
                bytes::Bytes::from_static(b"cap"),
                XattrSetMode::Any,
                3,
            )
            .expect("setxattr");
        block_on(lower_mem.open(path("keep"), OpenFlags::CREATE, 4, &payer)).expect("create keep");
        lower_mem
            .set_xattr_unix(
                path("keep"),
                "security.capability",
                bytes::Bytes::from_static(b"keepcap"),
                XattrSetMode::Any,
                5,
            )
            .expect("setxattr keep");

        const LOWER_BOOT: EmbeddedBootFs =
            EmbeddedBootFs::new(&[EmbeddedBootDirectory::new("lower", 0)], &[]);
        let boot_fs = BootFs::new(LOWER_BOOT, DeviceId::new(1));
        let ns = Namespace::<UnsupportedStorage>::new(MountTable::new(boot_fs, 4));
        block_on(
            ns.mount(
                &crate::ProcessAuthority::root()
                    .derive_mount_cap("/lower")
                    .unwrap(),
                MountedFs::Memory(lower_mem.clone()),
                MountGrant {
                    rights: FileSystemRights::READ,
                    sharing: MountSharing::Shared,
                },
            ),
        )
        .expect("mount");
        let pinned = PinnedLower::from_held(ns.resolve("/lower").unwrap().held()).unwrap();
        let overlay = OverlayFs::new(MemoryFs::new(DeviceId::new(32)), pinned);

        // Removing an xattr from a lower file copies it up and strips only in upper.
        block_on(overlay.remove_xattr(path("keep"), "security.capability", 6, &payer))
            .expect("remove xattr in overlay");
        assert_eq!(
            block_on(overlay.xattr(path("keep"), "security.capability")).unwrap(),
            None
        );
        assert_eq!(
            lower_mem
                .xattr(path("keep"), "security.capability")
                .unwrap(),
            Some(bytes::Bytes::from_static(b"keepcap"))
        );

        // Unlink + rmdir + mkdir creates an opaque directory hiding lower entries.
        block_on(overlay.unlink(path("dir/old"), 7, &payer)).expect("unlink");
        block_on(overlay.remove_directory(path("dir"), 8, &payer)).expect("rmdir");
        block_on(overlay.create_directory(path("dir"), 9, &payer)).expect("mkdir opaque");
        assert_eq!(
            block_on(overlay.stat(path("dir/old"))).map(drop),
            Err(FsError::NoEntry)
        );
        // Lower still intact.
        assert!(block_on(lower_mem.stat(path("dir/old"))).is_ok());
    }
}
