//! Linux containers: the Linux system a native process sees, bounded by the
//! [`ProcessAuthority`] it was created with (AGENTS.md §3.8).
//!
//! Every native Linux process runs inside a [`LinuxContainer`], and any thread
//! or child process it creates stays inside the same container:
//!
//! - **Authority ceiling.** The container holds the attenuated
//!   [`ProcessAuthority`] derived from its creator. Linux's own permission
//!   model (UIDs, GIDs, capabilities, file modes, setuid) only narrows within
//!   that ceiling and never widens it: `uid 0` holds no more than its
//!   container was granted.
//! - **Isolated filesystem.** Each container has its own root and explicit
//!   mounts (`MountSharing::Private` or `MountSharing::Shared`). Paths resolve
//!   strictly within the container's mount table and never escape into the
//!   creator's namespace or another container's mounts. A private mount is
//!   exclusively claimed for the container's lifetime; a shared mount presents
//!   every node owned by the container's [`SharedOwner`] with modes derived
//!   from the mount's rights and `NO_SUID | NO_DEV` flags.
//! - **Isolated PID namespace.** Each container owns a [`PidNamespace`] whose
//!   process IDs start at 1 and whose `sysinfo().procs` counts only live
//!   processes inside that container.
//! - **Isolated UTS names.** Each container owns its own hostname and domain
//!   name (`uname`, `sethostname`, `setdomainname`).
//!
//! # Concurrency contract
//!
//! - `id`, `authority`, `filesystem`, `shared_owner` and `default_credentials`
//!   are immutable after creation and read lock-free across processors.
//! - `uts` is guarded by a short synchronous `spin::Mutex`, never held across
//!   an `.await`.
//! - `pids` and `futex` synchronize internally with short synchronous locks
//!   never held across an `.await`.

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use bytes::Bytes;
use core::num::{NonZeroU32, NonZeroU64};

use helios_hal::fs::{
    DirCookie, DirEntry, DirStream, FileSystem, FileSystemRights, FsError, FsPath, FsResult,
    Landed, Metadata, NodeKind, OpenFlags, RenameMode, WritePosition, write_with,
};
use helios_linux::syscall::{AccessCheck, Credentials, OpenRequest, PidNamespace, UtsField};
use helios_unix::FutexTable;
use thiserror::Error;

use crate::vfs::{
    FileContents, Follow, HeldPath, MAX_MOUNTS, MAX_SYMLINK_DEPTH, MountFlags, MountGrant,
    MountHold, MountSharing, MountedFs, Namespace, PrivateMountClaim, PrivateMountClaimError,
    SharedOwner, Storage, UnixAttributes, join_fs_path, within_directory,
};
use crate::{DirectoryAuthorityRights, DirectoryPreopen, ProcessAuthority, ProcessAuthorityError};

/// Unique identifier of a [`LinuxContainer`] within one kernel instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContainerId(NonZeroU64);

impl ContainerId {
    pub const fn new(raw: NonZeroU64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0.get()
    }
}

/// Specification of one mount inside a container at creation time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerMountSpec {
    /// Directory path in the creator's namespace and authority.
    pub source_path: String,
    /// Normalized absolute mount point inside the container (`"/"` for root).
    pub target_path: String,
    /// Rights granted on this mount, attenuated from the creator's authority
    /// and bounded by the backing mount's rights.
    pub rights: DirectoryAuthorityRights,
    /// Whether this mount is private to the container or shared. Must match
    /// the backing mount's sharing kind, which never changes while it exists.
    pub sharing: MountSharing,
}

/// Configuration used to create a [`LinuxContainer`].
#[derive(Clone, Debug)]
pub struct ContainerConfig {
    /// Container root mount (`target_path` must be `"/"`).
    pub root: ContainerMountSpec,
    /// Additional mounts below `"/"`.
    pub mounts: Vec<ContainerMountSpec>,
    /// Owner and group presented on every [`MountSharing::Shared`] mount.
    pub shared_owner: SharedOwner,
    /// Default Linux credentials for processes started in this container.
    pub credentials: Credentials,
    /// Initial UTS hostname (`uname().nodename`).
    pub hostname: UtsField,
    /// Initial UTS domain name (`uname().domainname`).
    pub domainname: UtsField,
}

/// Why creating a [`LinuxContainer`] was refused.
#[derive(Debug, Error)]
pub enum ContainerError {
    #[error("container root mount target must be \"/\", got {0:?}")]
    InvalidRootTarget(String),
    #[error("container mount target {0:?} is not a normalized absolute path below \"/\"")]
    InvalidMountTarget(String),
    #[error("container mount target {0:?} was specified more than once")]
    DuplicateMountTarget(String),
    #[error("container exceeds the limit of {MAX_MOUNTS} additional mounts")]
    TooManyMounts,
    #[error("container authority refused mount {path:?}: {source}")]
    Authority {
        path: String,
        #[source]
        source: ProcessAuthorityError,
    },
    #[error("container mount source {path:?} is not a directory")]
    NotADirectory { path: String },
    #[error(
        "container mount source {path:?} has sharing {actual:?}, cannot be granted as {requested:?}"
    )]
    MountSharingMismatch {
        path: String,
        actual: MountSharing,
        requested: MountSharing,
    },
    #[error("private mount {path:?} is already claimed by another container")]
    PrivateMountBusy { path: String },
    #[error("container mount source {path:?} is read-only and cannot grant write rights")]
    ReadOnlyMount { path: String },
    #[error("container mount source {path:?} failed: {error}")]
    Filesystem { path: String, error: FsError },
}

/// One active mount inside a [`ContainerFilesystem`].
pub struct ContainerMount<S: Storage> {
    target: String,
    backing: HeldPath<S>,
    grant: MountGrant,
    authority_rights: DirectoryAuthorityRights,
    _private_claim: Option<PrivateMountClaim>,
}

impl<S: Storage> ContainerMount<S> {
    /// Normalized absolute mount point inside the container.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Mount rights and sharing kind inside this container.
    pub fn grant(&self) -> MountGrant {
        self.grant
    }

    /// Full directory authority rights granted to this container on this mount.
    pub fn authority_rights(&self) -> DirectoryAuthorityRights {
        self.authority_rights
    }

    /// Mount flags (`READ_ONLY`, `NO_SUID`, `NO_DEV`) visible inside this container.
    pub fn flags(&self) -> MountFlags {
        self.grant.flags()
    }
}

/// A path resolved inside a container's own mount table.
pub struct ContainerResolved<'a, S: Storage> {
    mount: &'a ContainerMount<S>,
    container_path: String,
    fs_path: String,
    shared_owner: SharedOwner,
}

impl<'a, S: Storage> ContainerResolved<'a, S> {
    /// Normalized path inside the container.
    pub fn container_path(&self) -> &str {
        &self.container_path
    }

    /// Mount point inside the container that owns this path.
    pub fn mount_point(&self) -> &str {
        self.mount.target()
    }

    /// The underlying mounted filesystem.
    pub fn fs(&self) -> &'a MountedFs<S> {
        self.mount.backing.resolved().fs()
    }

    /// Path inside the underlying filesystem, strictly within the mount's
    /// source prefix.
    pub fn fs_path(&self) -> FsPath<'_> {
        FsPath::new(&self.fs_path).expect("a container-resolved fs path is normalized")
    }

    /// Mount grant (`rights` and `sharing`).
    pub fn grant(&self) -> MountGrant {
        self.mount.grant
    }

    /// Directory authority rights granted to the container on this mount.
    pub fn authority_rights(&self) -> DirectoryAuthorityRights {
        self.mount.authority_rights
    }

    /// Mount flags (`READ_ONLY`, `NO_SUID`, `NO_DEV`).
    pub fn flags(&self) -> MountFlags {
        self.mount.grant.flags()
    }

    /// Container's view of `stored` Unix attributes on a node of `kind`.
    /// Private mounts show stored attributes; shared mounts show the
    /// container's `SharedOwner` and modes derived from the mount's rights.
    pub fn container_view(&self, kind: NodeKind, stored: UnixAttributes) -> UnixAttributes {
        self.mount
            .grant
            .container_view(kind, stored, self.shared_owner)
    }

    /// File capability (`security.capability`) honoured on this mount: `None`
    /// on shared (`NO_SUID`) mounts.
    pub fn file_capability<'b>(&self, stored: Option<&'b [u8]>) -> Option<&'b [u8]> {
        self.mount.grant.file_capability(stored)
    }

    /// Whether `self` and `other` lie on the same container mount.
    pub fn same_mount(&self, other: &ContainerResolved<'_, S>) -> bool {
        core::ptr::eq(self.mount, other.mount)
    }

    /// Whether this path is the root directory of its container mount.
    pub fn is_mount_root(&self) -> bool {
        self.container_path == self.mount.target()
    }

    /// Clones a hold on the underlying mount so an open descriptor keeps it busy.
    pub fn mount_hold(&self) -> Option<MountHold> {
        self.mount.backing.resolved().hold()
    }

    fn require_read(&self) -> FsResult<()> {
        if !self
            .authority_rights()
            .contains(DirectoryAuthorityRights::READ)
        {
            return Err(FsError::NotPermitted);
        }
        Ok(())
    }

    fn require_write(&self) -> FsResult<()> {
        if self.flags().contains(MountFlags::READ_ONLY) {
            return Err(FsError::ReadOnly);
        }
        if !self
            .authority_rights()
            .contains(DirectoryAuthorityRights::WRITE)
        {
            return Err(FsError::NotPermitted);
        }
        Ok(())
    }

    fn require_mutate_dir(&self) -> FsResult<()> {
        if self.flags().contains(MountFlags::READ_ONLY) {
            return Err(FsError::ReadOnly);
        }
        if !self
            .authority_rights()
            .contains(DirectoryAuthorityRights::MUTATE_DIRECTORY)
        {
            return Err(FsError::NotPermitted);
        }
        Ok(())
    }

    async fn describe(&self) -> FsResult<ContainerNodeInfo> {
        let metadata = self.fs().stat(self.fs_path()).await?;
        let stored = self.fs().unix_attributes(self.fs_path()).await?;
        let unix = self.container_view(metadata.kind, stored);
        Ok(ContainerNodeInfo {
            metadata,
            unix,
            flags: self.flags(),
            mount_point: self.mount_point().to_owned(),
            grant: self.grant(),
        })
    }
}

/// Container-visible description of a resolved filesystem node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerNodeInfo {
    pub metadata: Metadata,
    pub unix: UnixAttributes,
    pub flags: MountFlags,
    pub mount_point: String,
    pub grant: MountGrant,
}

/// A container's isolated mount table: its own root `"/"` plus explicitly
/// granted mounts, with no inherited host mounts.
pub struct ContainerFilesystem<S: Storage> {
    /// Mounts visible inside the container; index 0 is always `"/"`.
    mounts: Vec<ContainerMount<S>>,
    shared_owner: SharedOwner,
}

impl<S: Storage> ContainerFilesystem<S> {
    /// Every mount visible inside this container.
    pub fn mounts(&self) -> &[ContainerMount<S>] {
        &self.mounts
    }

    /// Owner and group presented on every shared mount in this container.
    pub fn shared_owner(&self) -> SharedOwner {
        self.shared_owner
    }

    /// Resolves `path` within this container's mount table without following a
    /// final symbolic link. `..` is clamped at the container's `"/"`.
    pub fn resolve(&self, path: &str) -> FsResult<ContainerResolved<'_, S>> {
        let normalized = normalize_container_path(path)?;
        let mount = self.longest_mount(&normalized);
        let relative = relative_within_mount(mount.target(), &normalized);
        let resolved = mount.backing.resolved();
        let base = resolved.path();
        let fs_path = if relative.is_empty() {
            base.as_str().to_owned()
        } else {
            join_fs_path(base, relative)
        };
        Ok(ContainerResolved {
            mount,
            container_path: normalized,
            fs_path,
            shared_owner: self.shared_owner,
        })
    }

    /// Resolves `path` within this container, following symbolic links strictly
    /// inside this container's root (never escaping to the host namespace).
    pub async fn resolve_following(&self, path: &str) -> FsResult<ContainerResolved<'_, S>> {
        let mut current = normalize_container_path(path)?;
        for _ in 0..MAX_SYMLINK_DEPTH {
            let resolved = self.resolve(&current)?;
            match resolved.fs().stat(resolved.fs_path()).await {
                Ok(meta) if meta.kind == NodeKind::Symlink => {
                    let target = resolved.fs().read_link(resolved.fs_path()).await?;
                    current = resolve_container_symlink(&current, &target)?;
                }
                Ok(_) | Err(FsError::NoEntry) => return Ok(resolved),
                Err(error) => return Err(error),
            }
        }
        Err(FsError::Loop)
    }

    /// Describes `path` inside this container, applying the mount's sharing
    /// view (`Private` stored metadata vs `Shared` container identity & modes).
    pub async fn stat(&self, path: &str) -> FsResult<ContainerNodeInfo> {
        let resolved = self.resolve_following(path).await?;
        if !resolved
            .authority_rights()
            .contains(DirectoryAuthorityRights::READ)
        {
            return Err(FsError::NotPermitted);
        }
        let metadata = resolved.fs().stat(resolved.fs_path()).await?;
        let stored = resolved.fs().unix_attributes(resolved.fs_path()).await?;
        let unix = resolved.container_view(metadata.kind, stored);
        Ok(ContainerNodeInfo {
            metadata,
            unix,
            flags: resolved.flags(),
            mount_point: resolved.mount_point().to_owned(),
            grant: resolved.grant(),
        })
    }

    /// Lists directory entries at `path` inside this container, including any
    /// direct child mount points of this container.
    pub async fn list(&self, path: &str) -> FsResult<Vec<DirEntry>> {
        const BATCH: usize = 256;
        let resolved = self.resolve_following(path).await?;
        if !resolved
            .authority_rights()
            .contains(DirectoryAuthorityRights::READ)
        {
            return Err(FsError::NotPermitted);
        }
        let dir_stream = resolved.fs().open_dir(resolved.fs_path()).await?;
        let mut entries = Vec::new();
        let mut cookie = DirCookie::START;
        loop {
            let batch = dir_stream.read(cookie, BATCH).await?;
            let complete = batch.len() < BATCH;
            if let Some(last) = batch.last() {
                cookie = last.next;
            }
            entries.extend(batch);
            if complete {
                break;
            }
        }
        let dir = resolved.container_path();
        for mount in &self.mounts {
            let target = mount.target();
            if target == "/" {
                continue;
            }
            if let Some((parent, name)) = target.rsplit_once('/') {
                let parent = if parent.is_empty() { "/" } else { parent };
                if parent == dir && !entries.iter().any(|entry| entry.name == name) {
                    entries.push(DirEntry {
                        name: name.to_owned(),
                        kind: NodeKind::Directory,
                        inode: 0,
                        next: DirCookie::START,
                    });
                }
            }
        }
        Ok(entries)
    }

    /// Reads an executable image at `path` inside this container, requiring
    /// both `READ` and `EXECUTE` authority on its mount.
    pub async fn read_executable(&self, path: &str) -> FsResult<FileContents> {
        let resolved = self.resolve_following(path).await?;
        let required = DirectoryAuthorityRights::READ | DirectoryAuthorityRights::EXECUTE;
        if !resolved.authority_rights().contains(required) {
            return Err(FsError::NotPermitted);
        }
        resolved.fs().read_whole(resolved.fs_path()).await
    }

    /// Whether the container's mount for `container_path` grants execute rights.
    pub fn can_exec(&self, container_path: &str) -> bool {
        self.resolve(container_path).is_ok_and(|resolved| {
            resolved
                .authority_rights()
                .contains(DirectoryAuthorityRights::EXECUTE)
        })
    }

    /// Walks `raw_path` component by component relative to `base_dir` (a
    /// normalized absolute container path) strictly within this container's
    /// root. Enforces intermediate directory existence, intermediate symlink
    /// expansion (`ELOOP` past `MAX_SYMLINK_DEPTH`), and trailing-slash
    /// directory checks. Returns `(resolved, trailing_slash)`.
    pub async fn walk_path(
        &self,
        base_dir: &str,
        raw_path: &str,
        follow_final: bool,
    ) -> FsResult<(ContainerResolved<'_, S>, bool)> {
        if raw_path.is_empty() || raw_path.as_bytes().contains(&0) {
            return Err(FsError::Invalid);
        }
        let mut trailing_slash = raw_path.ends_with('/');
        let mut segments: Vec<String> = if raw_path.starts_with('/') {
            Vec::new()
        } else {
            let normalized_base = normalize_container_path(base_dir)?;
            normalized_base
                .split('/')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        };
        let mut pending: Vec<String> = raw_path
            .split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        pending.reverse();

        if pending.is_empty() {
            return Ok((self.resolve("/")?, true));
        }

        let mut symlink_expansions = 0usize;
        while let Some(component) = pending.pop() {
            let is_final = pending.is_empty();
            match component.as_str() {
                "." | ".." => {
                    let cur_path = build_container_path(&segments);
                    let cur = self.resolve(&cur_path)?;
                    let meta = cur.fs().stat(cur.fs_path()).await?;
                    if meta.kind != NodeKind::Directory {
                        return Err(FsError::NotDirectory);
                    }
                    if component == ".." {
                        segments.pop();
                    }
                }
                name => {
                    if name.len() > 255 {
                        return Err(FsError::NameTooLong);
                    }
                    segments.push(component);
                    let cur_path = build_container_path(&segments);
                    let resolved = self.resolve(&cur_path)?;
                    if !is_final {
                        let meta = resolved.fs().stat(resolved.fs_path()).await?;
                        match meta.kind {
                            NodeKind::Directory => {}
                            NodeKind::Symlink => {
                                symlink_expansions += 1;
                                if symlink_expansions > MAX_SYMLINK_DEPTH {
                                    return Err(FsError::Loop);
                                }
                                let target = resolved.fs().read_link(resolved.fs_path()).await?;
                                if target.is_empty() || target.as_bytes().contains(&0) {
                                    return Err(FsError::Invalid);
                                }
                                segments.pop();
                                if target.starts_with('/') {
                                    segments.clear();
                                }
                                let mut parts: Vec<String> = target
                                    .split('/')
                                    .filter(|s| !s.is_empty())
                                    .map(str::to_owned)
                                    .collect();
                                parts.reverse();
                                pending.extend(parts);
                            }
                            _ => return Err(FsError::NotDirectory),
                        }
                    } else if follow_final || trailing_slash {
                        match resolved.fs().stat(resolved.fs_path()).await {
                            Ok(meta) if meta.kind == NodeKind::Symlink => {
                                symlink_expansions += 1;
                                if symlink_expansions > MAX_SYMLINK_DEPTH {
                                    return Err(FsError::Loop);
                                }
                                let target = resolved.fs().read_link(resolved.fs_path()).await?;
                                if target.is_empty() || target.as_bytes().contains(&0) {
                                    return Err(FsError::Invalid);
                                }
                                segments.pop();
                                if target.starts_with('/') {
                                    segments.clear();
                                }
                                if target.ends_with('/') {
                                    trailing_slash = true;
                                }
                                let mut parts: Vec<String> = target
                                    .split('/')
                                    .filter(|s| !s.is_empty())
                                    .map(str::to_owned)
                                    .collect();
                                parts.reverse();
                                pending.extend(parts);
                            }
                            Ok(meta) if trailing_slash && meta.kind != NodeKind::Directory => {
                                return Err(FsError::NotDirectory);
                            }
                            Ok(_) | Err(FsError::NoEntry) => {}
                            Err(error) => return Err(error),
                        }
                    }
                }
            }
        }

        let final_path = build_container_path(&segments);
        Ok((self.resolve(&final_path)?, trailing_slash))
    }

    /// Resolves and stats `raw_path` relative to `base_dir`, returning both
    /// container-visible metadata and the normalized container path.
    pub async fn stat_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        follow_final: bool,
    ) -> FsResult<(ContainerNodeInfo, String)> {
        let (resolved, _) = self.walk_path(base_dir, raw_path, follow_final).await?;
        resolved.require_read()?;
        let info = resolved.describe().await?;
        Ok((info, resolved.container_path().to_owned()))
    }

    /// Stats an already-resolved container path (used for `fstat` on open
    /// descriptors, including `O_PATH | O_NOFOLLOW` symlink descriptors).
    pub async fn stat_resolved(&self, container_path: &str) -> FsResult<ContainerNodeInfo> {
        let resolved = self.resolve(container_path)?;
        resolved.describe().await
    }

    /// Checks access permissions for `raw_path` relative to `base_dir` within
    /// the container's authority ceiling.
    pub async fn access_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        check: AccessCheck,
    ) -> FsResult<()> {
        let (resolved, _) = self.walk_path(base_dir, raw_path, check.follow).await?;
        let info = resolved.describe().await?;
        if check.read {
            resolved.require_read()?;
        }
        if check.write {
            resolved.require_write()?;
        }
        if check.exec {
            if !resolved
                .authority_rights()
                .contains(DirectoryAuthorityRights::EXECUTE)
            {
                return Err(FsError::NotPermitted);
            }
            if info.metadata.kind == NodeKind::File && (info.unix.permissions & 0o111) == 0 {
                return Err(FsError::NotPermitted);
            }
        }
        Ok(())
    }

    /// Opens or creates a file or directory for Linux `open`/`openat`/`creat`.
    pub async fn open_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        request: OpenRequest,
        now: u64,
    ) -> FsResult<(ContainerNodeInfo, String, Option<MountHold>)> {
        let follow_final = !(request.nofollow || (request.create && request.exclusive));
        let (resolved, trailing_slash) = self.walk_path(base_dir, raw_path, follow_final).await?;
        let existing = resolved.fs().stat(resolved.fs_path()).await;

        if request.path_only {
            let meta = existing?;
            if (request.directory || trailing_slash) && meta.kind != NodeKind::Directory {
                return Err(FsError::NotDirectory);
            }
            let info = resolved.describe().await?;
            return Ok((
                info,
                resolved.container_path().to_owned(),
                resolved.mount_hold(),
            ));
        }

        if request.create && request.exclusive && existing.is_ok() {
            return Err(FsError::Exists);
        }

        match existing {
            Ok(meta) => {
                if meta.kind == NodeKind::Symlink {
                    return Err(FsError::Loop);
                }
                if meta.kind == NodeKind::Directory {
                    if request.write || request.truncate {
                        return Err(FsError::IsDirectory);
                    }
                    resolved.require_read()?;
                } else {
                    if request.directory || trailing_slash {
                        return Err(FsError::NotDirectory);
                    }
                    if request.read {
                        resolved.require_read()?;
                    }
                    if request.write || request.truncate {
                        resolved.require_write()?;
                    }
                    let mut flags = OpenFlags::empty();
                    if request.truncate {
                        flags |= OpenFlags::TRUNCATE;
                    }
                    resolved.fs().open(resolved.fs_path(), flags, now).await?;
                }
            }
            Err(FsError::NoEntry) => {
                if !request.create {
                    return Err(FsError::NoEntry);
                }
                if trailing_slash {
                    return Err(FsError::IsDirectory);
                }
                if request.directory {
                    return Err(FsError::NotDirectory);
                }
                resolved.require_mutate_dir()?;
                if request.write {
                    resolved.require_write()?;
                }
                let mut flags = OpenFlags::CREATE;
                if request.exclusive {
                    flags |= OpenFlags::EXCLUSIVE;
                }
                if request.truncate {
                    flags |= OpenFlags::TRUNCATE;
                }
                resolved.fs().open(resolved.fs_path(), flags, now).await?;
                resolved
                    .fs()
                    .apply_created_permissions(resolved.fs_path(), request.mode, now);
            }
            Err(error) => return Err(error),
        }

        let info = resolved.describe().await?;
        Ok((
            info,
            resolved.container_path().to_owned(),
            resolved.mount_hold(),
        ))
    }

    /// Reads up to `max_bytes` from `container_path` at `offset`.
    pub async fn read_at(
        &self,
        container_path: &str,
        offset: u64,
        max_bytes: usize,
    ) -> FsResult<Bytes> {
        let resolved = self.resolve(container_path)?;
        resolved.require_read()?;
        resolved
            .fs()
            .read_at(resolved.fs_path(), offset, max_bytes)
            .await
    }

    /// Writes `bytes` to `container_path` at `position`.
    pub async fn write_at(
        &self,
        container_path: &str,
        position: WritePosition,
        bytes: &[u8],
        now: u64,
    ) -> FsResult<Landed> {
        let resolved = self.resolve(container_path)?;
        resolved.require_write()?;
        write_with(
            resolved.fs(),
            resolved.fs_path(),
            position,
            bytes.len(),
            now,
            |at, destination| {
                destination.copy_from_slice(&bytes[at..at + destination.len()]);
            },
        )
        .await
    }

    /// Truncates or zero-extends an open file at `container_path`.
    pub async fn set_size(&self, container_path: &str, size: u64, now: u64) -> FsResult<()> {
        let resolved = self.resolve(container_path)?;
        resolved.require_write()?;
        resolved.fs().set_size(resolved.fs_path(), size, now).await
    }

    /// Truncates or zero-extends the file at `raw_path` relative to `base_dir`.
    pub async fn set_size_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        size: u64,
        now: u64,
    ) -> FsResult<()> {
        let (resolved, _) = self.walk_path(base_dir, raw_path, true).await?;
        resolved.require_write()?;
        resolved.fs().set_size(resolved.fs_path(), size, now).await
    }

    /// Updates access/modified timestamps at `raw_path` relative to `base_dir`.
    pub async fn set_times_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        follow_final: bool,
        access: Option<u64>,
        modified: Option<u64>,
        now: u64,
    ) -> FsResult<()> {
        let (resolved, _) = self.walk_path(base_dir, raw_path, follow_final).await?;
        resolved.require_write()?;
        resolved
            .fs()
            .set_times(resolved.fs_path(), access, modified, now)
            .await
    }

    /// Updates access/modified timestamps on an already-resolved container path.
    pub async fn set_times_resolved(
        &self,
        container_path: &str,
        access: Option<u64>,
        modified: Option<u64>,
        now: u64,
    ) -> FsResult<()> {
        let resolved = self.resolve(container_path)?;
        resolved.require_write()?;
        resolved
            .fs()
            .set_times(resolved.fs_path(), access, modified, now)
            .await
    }

    /// Syncs data (and metadata if `!data_only`) for `container_path`.
    pub async fn sync(&self, container_path: &str, data_only: bool) -> FsResult<()> {
        let resolved = self.resolve(container_path)?;
        if data_only {
            resolved.fs().sync_data(resolved.fs_path()).await
        } else {
            resolved.fs().sync(resolved.fs_path()).await
        }
    }

    /// Reads the symbolic link target at `raw_path` relative to `base_dir`.
    pub async fn read_link_at(&self, base_dir: &str, raw_path: &str) -> FsResult<String> {
        let (resolved, trailing_slash) = self.walk_path(base_dir, raw_path, false).await?;
        resolved.require_read()?;
        if trailing_slash {
            return Err(FsError::Invalid);
        }
        resolved.fs().read_link(resolved.fs_path()).await
    }

    /// Reads the symbolic link target for an already-resolved container path
    /// (used by `readlinkat(fd, "", ...)` on an `O_PATH | O_NOFOLLOW` symlink).
    pub async fn read_link_resolved(&self, container_path: &str) -> FsResult<String> {
        let resolved = self.resolve(container_path)?;
        resolved.require_read()?;
        resolved.fs().read_link(resolved.fs_path()).await
    }

    /// Creates a directory at `raw_path` relative to `base_dir`.
    pub async fn mkdir_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        mode: u32,
        now: u64,
    ) -> FsResult<()> {
        if matches!(last_raw_component(raw_path), None | Some(".") | Some("..")) {
            return Err(FsError::Exists);
        }
        let (resolved, _) = self.walk_path(base_dir, raw_path, false).await?;
        resolved.require_mutate_dir()?;
        resolved
            .fs()
            .create_directory(resolved.fs_path(), now)
            .await?;
        resolved
            .fs()
            .apply_created_permissions(resolved.fs_path(), mode, now);
        Ok(())
    }

    /// Unlinks a file (`remove_dir == false`) or removes an empty directory
    /// (`remove_dir == true`) at `raw_path` relative to `base_dir`.
    pub async fn unlink_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        remove_dir: bool,
        now: u64,
    ) -> FsResult<()> {
        match last_raw_component(raw_path) {
            None => {
                return Err(if remove_dir {
                    FsError::Busy
                } else {
                    FsError::IsDirectory
                });
            }
            Some(".") => {
                return Err(if remove_dir {
                    FsError::Invalid
                } else {
                    FsError::IsDirectory
                });
            }
            Some("..") => {
                return Err(if remove_dir {
                    FsError::NotEmpty
                } else {
                    FsError::IsDirectory
                });
            }
            Some(_) => {}
        }
        let (resolved, _) = self.walk_path(base_dir, raw_path, false).await?;
        if remove_dir {
            if resolved.is_mount_root() {
                return Err(FsError::Busy);
            }
            resolved.require_mutate_dir()?;
            let meta = resolved.fs().stat(resolved.fs_path()).await?;
            if meta.kind != NodeKind::Directory {
                return Err(FsError::NotDirectory);
            }
            resolved
                .fs()
                .remove_directory(resolved.fs_path(), now)
                .await
        } else {
            resolved.require_mutate_dir()?;
            let meta = resolved.fs().stat(resolved.fs_path()).await?;
            if meta.kind == NodeKind::Directory {
                return Err(FsError::IsDirectory);
            }
            resolved.fs().unlink(resolved.fs_path(), now).await
        }
    }

    /// Renames `old_raw` (relative to `old_base`) to `new_raw` (relative to
    /// `new_base`) within the same container mount.
    pub async fn rename_at(
        &self,
        old_base: &str,
        old_raw: &str,
        new_base: &str,
        new_raw: &str,
        mode: RenameMode,
        now: u64,
    ) -> FsResult<()> {
        if matches!(last_raw_component(old_raw), None | Some(".") | Some(".."))
            || matches!(last_raw_component(new_raw), None | Some(".") | Some(".."))
        {
            return Err(FsError::Busy);
        }
        let (old_resolved, old_slash) = self.walk_path(old_base, old_raw, false).await?;
        let (new_resolved, new_slash) = self.walk_path(new_base, new_raw, false).await?;
        let old_meta = old_resolved.fs().stat(old_resolved.fs_path()).await?;
        if (old_slash || new_slash) && old_meta.kind != NodeKind::Directory {
            return Err(FsError::NotDirectory);
        }
        if !old_resolved.same_mount(&new_resolved) {
            return Err(FsError::CrossDevice);
        }
        if old_resolved.is_mount_root() || new_resolved.is_mount_root() {
            return Err(FsError::Busy);
        }
        old_resolved.require_mutate_dir()?;
        new_resolved.require_mutate_dir()?;
        old_resolved
            .fs()
            .rename(old_resolved.fs_path(), new_resolved.fs_path(), mode, now)
            .await
    }

    /// Creates a hard link from `old_raw` (or `old_base` when `empty_old`) to
    /// `new_raw` within the same container mount.
    #[allow(clippy::too_many_arguments)]
    pub async fn link_at(
        &self,
        old_base: &str,
        old_raw: &str,
        new_base: &str,
        new_raw: &str,
        follow_old: bool,
        empty_old: bool,
        now: u64,
    ) -> FsResult<()> {
        if matches!(last_raw_component(new_raw), None | Some(".") | Some("..")) {
            return Err(FsError::Exists);
        }
        let old_resolved = if empty_old {
            self.resolve(old_base)?
        } else {
            self.walk_path(old_base, old_raw, follow_old).await?.0
        };
        let (new_resolved, new_slash) = self.walk_path(new_base, new_raw, false).await?;
        if new_slash {
            return match new_resolved.fs().stat(new_resolved.fs_path()).await {
                Ok(_) => Err(FsError::Exists),
                Err(_) => Err(FsError::NoEntry),
            };
        }
        if !old_resolved.same_mount(&new_resolved) {
            return Err(FsError::CrossDevice);
        }
        old_resolved.require_read()?;
        new_resolved.require_mutate_dir()?;
        old_resolved
            .fs()
            .link(old_resolved.fs_path(), new_resolved.fs_path(), now)
            .await
    }

    /// Creates a symbolic link at `raw_path` (relative to `base_dir`) pointing
    /// to `target`.
    pub async fn symlink_at(
        &self,
        target: &str,
        base_dir: &str,
        raw_path: &str,
        now: u64,
    ) -> FsResult<()> {
        if target.is_empty() {
            return Err(FsError::NoEntry);
        }
        if matches!(last_raw_component(raw_path), None | Some(".") | Some("..")) {
            return Err(FsError::Exists);
        }
        let (resolved, trailing_slash) = self.walk_path(base_dir, raw_path, false).await?;
        if trailing_slash {
            return match resolved.fs().stat(resolved.fs_path()).await {
                Ok(_) => Err(FsError::Exists),
                Err(_) => Err(FsError::NoEntry),
            };
        }
        resolved.require_mutate_dir()?;
        resolved.fs().symlink(target, resolved.fs_path(), now).await
    }

    /// Lists entries in `container_path` along with `(self_inode, parent_inode)`.
    pub async fn list_with_inodes(
        &self,
        container_path: &str,
    ) -> FsResult<(u64, u64, Vec<DirEntry>)> {
        let self_info = self.stat(container_path).await?;
        if self_info.metadata.kind != NodeKind::Directory {
            return Err(FsError::NotDirectory);
        }
        let parent_path = crate::parent_path(container_path);
        let parent_ino = if parent_path == container_path {
            self_info.metadata.id.inode
        } else {
            self.stat(parent_path)
                .await
                .map_or(self_info.metadata.id.inode, |info| info.metadata.id.inode)
        };
        let entries = self.list(container_path).await?;
        Ok((self_info.metadata.id.inode, parent_ino, entries))
    }

    fn longest_mount(&self, normalized: &str) -> &ContainerMount<S> {
        let mut best = &self.mounts[0];
        for candidate in &self.mounts[1..] {
            if within_directory(candidate.target(), normalized)
                && candidate.target().len() > best.target().len()
            {
                best = candidate;
            }
        }
        best
    }
}

struct ContainerUts {
    hostname: UtsField,
    domainname: UtsField,
}

/// RAII guard holding one live process slot in a [`LinuxContainer`]'s
/// [`PidNamespace`]. Dropped once every thread of the process has exited so
/// its PID stays reserved for the full thread-group lifetime.
pub struct ContainerProcessGuard {
    pids: PidNamespace,
    pid: NonZeroU32,
}

impl ContainerProcessGuard {
    /// The container-local process ID (starting at 1).
    pub const fn pid(&self) -> NonZeroU32 {
        self.pid
    }
}

impl Drop for ContainerProcessGuard {
    fn drop(&mut self) {
        self.pids.release_process(self.pid);
    }
}

/// A kernel Linux container: the bounded Linux system every native Linux
/// process runs inside.
pub struct LinuxContainer<S: Storage> {
    id: ContainerId,
    authority: ProcessAuthority,
    filesystem: ContainerFilesystem<S>,
    shared_owner: SharedOwner,
    default_credentials: Credentials,
    uts: spin::Mutex<ContainerUts>,
    pids: PidNamespace,
    futex: FutexTable,
}

impl<S: Storage> LinuxContainer<S> {
    /// Creates a new isolated Linux container from `config`, validating and
    /// attenuating every mount against `caller_authority` and
    /// `caller_namespace`, and combining those directory grants with
    /// `non_fs_authority` (which must carry no directory grants of its own).
    pub async fn create(
        id: ContainerId,
        caller_authority: &ProcessAuthority,
        caller_namespace: &Namespace<S>,
        mut authority: ProcessAuthority,
        config: ContainerConfig,
    ) -> Result<Self, ContainerError> {
        if config.root.target_path != "/" {
            return Err(ContainerError::InvalidRootTarget(config.root.target_path));
        }
        if config.mounts.len() > MAX_MOUNTS {
            return Err(ContainerError::TooManyMounts);
        }

        let mut seen_targets = vec![String::from("/")];
        for spec in &config.mounts {
            if !is_valid_submount_target(&spec.target_path) {
                return Err(ContainerError::InvalidMountTarget(spec.target_path.clone()));
            }
            if seen_targets
                .iter()
                .any(|existing| existing == &spec.target_path)
            {
                return Err(ContainerError::DuplicateMountTarget(
                    spec.target_path.clone(),
                ));
            }
            seen_targets.push(spec.target_path.clone());
        }

        let mut mounts = Vec::with_capacity(1 + config.mounts.len());
        let root_mount = attach_container_mount(
            id,
            caller_authority,
            caller_namespace,
            &config.root,
            &mut authority,
        )
        .await?;
        mounts.push(root_mount);

        for spec in &config.mounts {
            let mount = attach_container_mount(
                id,
                caller_authority,
                caller_namespace,
                spec,
                &mut authority,
            )
            .await?;
            mounts.push(mount);
        }

        Ok(Self {
            id,
            authority,
            filesystem: ContainerFilesystem {
                mounts,
                shared_owner: config.shared_owner,
            },
            shared_owner: config.shared_owner,
            default_credentials: config.credentials,
            uts: spin::Mutex::new(ContainerUts {
                hostname: config.hostname,
                domainname: config.domainname,
            }),
            pids: PidNamespace::new(),
            futex: FutexTable::new(),
        })
    }

    /// Creates a single-process container for a direct Linux ELF launch
    /// (such as through a shell or direct program exec), bounded by
    /// `authority` and rooted at the `guest_name == "/"` preopen's
    /// `source_path` in `namespace` (or `namespace`'s `"/"` with empty rights
    /// when no resolvable `"/"` preopen was granted), attaching any additional
    /// non-`"/"` directory preopens from `authority` that resolve in
    /// `namespace`, all pinned to `MountSharing::Shared`.
    pub fn ephemeral(
        id: ContainerId,
        authority: ProcessAuthority,
        namespace: &Namespace<S>,
    ) -> Self {
        let root_mount = {
            let root_binding = authority
                .directory_preopens()
                .iter()
                .filter(|preopen| preopen.guest_name() == "/")
                .find_map(|preopen| {
                    namespace
                        .resolve(preopen.source_path())
                        .ok()
                        .map(|resolved| (preopen.source_path(), resolved))
                });
            let (root_resolved, root_rights) = match root_binding {
                Some((root_source, resolved)) => {
                    let rights = authority
                        .directory_preopens()
                        .iter()
                        .filter(|preopen| {
                            preopen.guest_name() == "/" && preopen.source_path() == root_source
                        })
                        .fold(DirectoryAuthorityRights::empty(), |acc, preopen| {
                            acc | preopen.rights()
                        });
                    (resolved, rights)
                }
                None => (
                    namespace
                        .resolve("/")
                        .expect("every namespace resolves its root \"/\""),
                    DirectoryAuthorityRights::empty(),
                ),
            };
            let fs_rights = effective_fs_rights(root_rights, root_resolved.grant().rights);
            ContainerMount {
                target: String::from("/"),
                backing: root_resolved.held(),
                grant: MountGrant {
                    rights: fs_rights,
                    sharing: MountSharing::Shared,
                },
                authority_rights: root_rights,
                _private_claim: None,
            }
        };
        let mut mounts = vec![root_mount];
        for preopen in authority.directory_preopens() {
            if preopen.guest_name() == "/" {
                continue;
            }
            let Ok(target) = normalize_container_path(preopen.guest_name()) else {
                continue;
            };
            if target == "/" || mounts.iter().any(|existing| existing.target == target) {
                continue;
            }
            if mounts.len() > MAX_MOUNTS {
                break;
            }
            if let Ok(resolved) = namespace.resolve(preopen.source_path()) {
                let rights = effective_fs_rights(preopen.rights(), resolved.grant().rights);
                mounts.push(ContainerMount {
                    target,
                    backing: resolved.held(),
                    grant: MountGrant {
                        rights,
                        sharing: MountSharing::Shared,
                    },
                    authority_rights: preopen.rights(),
                    _private_claim: None,
                });
            }
        }
        let shared_owner = SharedOwner { uid: 0, gid: 0 };
        Self {
            id,
            authority,
            filesystem: ContainerFilesystem {
                mounts,
                shared_owner,
            },
            shared_owner,
            default_credentials: Credentials::root(),
            uts: spin::Mutex::new(ContainerUts {
                hostname: UtsField::UNSET,
                domainname: UtsField::UNSET,
            }),
            pids: PidNamespace::new(),
            futex: FutexTable::new(),
        }
    }

    pub const fn id(&self) -> ContainerId {
        self.id
    }

    /// The authority ceiling of every process running in this container.
    pub fn authority(&self) -> &ProcessAuthority {
        &self.authority
    }

    /// This container's isolated filesystem (root and mounts).
    pub fn filesystem(&self) -> &ContainerFilesystem<S> {
        &self.filesystem
    }

    /// The owner and group presented on every shared mount in this container.
    pub const fn shared_owner(&self) -> SharedOwner {
        self.shared_owner
    }

    /// Default Linux credentials for processes started in this container.
    pub fn default_credentials(&self) -> &Credentials {
        &self.default_credentials
    }

    /// This container's isolated PID namespace (starts at 1).
    pub fn pid_namespace(&self) -> &PidNamespace {
        &self.pids
    }

    /// This container's futex wait table.
    pub fn futex_table(&self) -> &FutexTable {
        &self.futex
    }

    /// Allocates the next container-local PID (starting at 1) and returns an
    /// RAII guard that releases it once all threads of the process have exited.
    pub fn allocate_process(&self) -> Result<ContainerProcessGuard, u64> {
        let pid = self.pids.allocate_process()?;
        Ok(ContainerProcessGuard {
            pids: self.pids.clone(),
            pid,
        })
    }

    /// Live process count inside this container (`sysinfo().procs`).
    pub fn process_count(&self) -> u32 {
        self.pids.process_count()
    }

    /// Container UTS hostname (`uname().nodename`).
    pub fn hostname(&self) -> UtsField {
        self.uts.lock().hostname
    }

    /// Container UTS domain name (`uname().domainname`).
    pub fn domainname(&self) -> UtsField {
        self.uts.lock().domainname
    }

    /// Updates this container's UTS hostname (`sethostname`).
    pub fn set_hostname(&self, name: UtsField) {
        self.uts.lock().hostname = name;
    }

    /// Updates this container's UTS domain name (`setdomainname`).
    pub fn set_domainname(&self, name: UtsField) {
        self.uts.lock().domainname = name;
    }

    /// Renders `/etc/resolv.conf` for this container from `dns_servers`
    /// (the resolver addresses returned by `ComponentNetworkService::dns_servers`).
    ///
    /// Returns an empty document if the container was not granted
    /// [`crate::NetworkAuthorityRights::DNS`].
    pub fn resolv_conf(&self, dns_servers: &[crate::NetworkIpAddress]) -> String {
        if self.authority.derive_dns_cap().is_err() {
            return String::new();
        }
        format_resolv_conf(dns_servers)
    }

    /// Renders `/etc/hosts` for this container, mapping `127.0.0.1` and `::1`
    /// to `localhost` and the container's current UTS hostname.
    pub fn hosts(&self) -> String {
        let hostname = self.hostname();
        let host = core::str::from_utf8(hostname.as_bytes()).unwrap_or("");
        format_hosts(host)
    }

    /// Returns the synthesized bytes for container-managed `/etc` name
    /// resolution files (`/etc/resolv.conf`, `/etc/hosts`), or `None` for any
    /// other path.
    pub fn synthetic_etc_file(
        &self,
        path: &str,
        dns_servers: &[crate::NetworkIpAddress],
    ) -> Option<Vec<u8>> {
        let normalized = normalize_container_path(path).ok()?;
        match normalized.as_str() {
            "/etc/resolv.conf" => Some(self.resolv_conf(dns_servers).into_bytes()),
            "/etc/hosts" => Some(self.hosts().into_bytes()),
            _ => None,
        }
    }
}

/// Formats `/etc/resolv.conf` with one `nameserver <ip>` line per resolver.
pub fn format_resolv_conf(dns_servers: &[crate::NetworkIpAddress]) -> String {
    use core::fmt::Write;
    let mut out = String::new();
    for server in dns_servers {
        match *server {
            crate::NetworkIpAddress::Ipv4(addr) => {
                let ip = core::net::Ipv4Addr::from(addr.octets());
                let _ = writeln!(out, "nameserver {ip}");
            }
            crate::NetworkIpAddress::Ipv6(addr) => {
                let ip = core::net::Ipv6Addr::from(addr.octets());
                let _ = writeln!(out, "nameserver {ip}");
            }
        }
    }
    out
}

/// Formats `/etc/hosts` for loopback IPv4/IPv6 and the container's hostname.
pub fn format_hosts(hostname: &str) -> String {
    use core::fmt::Write;
    let mut out = String::new();
    let trimmed = hostname.trim();
    if trimmed.is_empty() || trimmed == "localhost" || trimmed == "(none)" {
        let _ = writeln!(out, "127.0.0.1 localhost");
        let _ = writeln!(out, "::1 localhost");
    } else {
        let _ = writeln!(out, "127.0.0.1 localhost {trimmed}");
        let _ = writeln!(out, "::1 localhost {trimmed}");
    }
    out
}

async fn attach_container_mount<S: Storage>(
    container_id: ContainerId,
    caller_authority: &ProcessAuthority,
    caller_namespace: &Namespace<S>,
    spec: &ContainerMountSpec,
    container_authority: &mut ProcessAuthority,
) -> Result<ContainerMount<S>, ContainerError> {
    let preopen = caller_authority
        .derive_directory_preopen(&spec.source_path, &spec.target_path, spec.rights)
        .map_err(|source| ContainerError::Authority {
            path: spec.source_path.clone(),
            source,
        })?;
    let source = preopen.source_path();
    let resolved = caller_namespace
        .resolve_following(source, Follow::Within(source))
        .await
        .map_err(|error| ContainerError::Filesystem {
            path: source.to_owned(),
            error,
        })?;
    let metadata =
        resolved
            .fs()
            .stat(resolved.path())
            .await
            .map_err(|error| ContainerError::Filesystem {
                path: source.to_owned(),
                error,
            })?;
    if metadata.kind != NodeKind::Directory {
        return Err(ContainerError::NotADirectory {
            path: source.to_owned(),
        });
    }

    let backing_grant = resolved.grant();
    let wants_write = spec.rights.contains(DirectoryAuthorityRights::WRITE)
        || spec
            .rights
            .contains(DirectoryAuthorityRights::MUTATE_DIRECTORY);
    if wants_write && !backing_grant.rights.contains(FileSystemRights::WRITE) {
        return Err(ContainerError::ReadOnlyMount {
            path: source.to_owned(),
        });
    }
    if backing_grant.sharing != spec.sharing {
        return Err(ContainerError::MountSharingMismatch {
            path: source.to_owned(),
            actual: backing_grant.sharing,
            requested: spec.sharing,
        });
    }
    let private_claim = if spec.sharing == MountSharing::Private {
        match resolved.claim_private(container_id.raw()) {
            Ok(claim) => Some(claim),
            Err(PrivateMountClaimError::AlreadyClaimed) => {
                return Err(ContainerError::PrivateMountBusy {
                    path: source.to_owned(),
                });
            }
            Err(PrivateMountClaimError::NotPrivate) => {
                return Err(ContainerError::MountSharingMismatch {
                    path: source.to_owned(),
                    actual: backing_grant.sharing,
                    requested: spec.sharing,
                });
            }
        }
    } else {
        None
    };

    let container_preopen = DirectoryPreopen::new(
        spec.target_path.clone(),
        spec.target_path.clone(),
        spec.rights,
    )
    .map_err(|source| ContainerError::Authority {
        path: spec.target_path.clone(),
        source,
    })?;
    container_authority.insert_directory_preopen(container_preopen);

    let grant = MountGrant {
        rights: effective_fs_rights(spec.rights, backing_grant.rights),
        sharing: spec.sharing,
    };
    Ok(ContainerMount {
        target: spec.target_path.clone(),
        backing: resolved.held(),
        grant,
        authority_rights: spec.rights,
        _private_claim: private_claim,
    })
}

fn effective_fs_rights(
    requested: DirectoryAuthorityRights,
    backing: FileSystemRights,
) -> FileSystemRights {
    let mut rights = FileSystemRights::empty();
    if requested.contains(DirectoryAuthorityRights::READ)
        && backing.contains(FileSystemRights::READ)
    {
        rights |= FileSystemRights::READ;
    }
    if (requested.contains(DirectoryAuthorityRights::WRITE)
        || requested.contains(DirectoryAuthorityRights::MUTATE_DIRECTORY))
        && backing.contains(FileSystemRights::WRITE)
    {
        rights |= FileSystemRights::WRITE;
    }
    rights
}

fn is_valid_submount_target(target: &str) -> bool {
    target.len() > 1 && target.strip_prefix('/').and_then(FsPath::new).is_some()
}

fn build_container_path(segments: &[String]) -> String {
    if segments.is_empty() {
        return String::from("/");
    }
    let total_len: usize = segments.iter().map(|s| 1 + s.len()).sum();
    let mut out = String::with_capacity(total_len);
    for seg in segments {
        out.push('/');
        out.push_str(seg);
    }
    out
}

fn last_raw_component(raw_path: &str) -> Option<&str> {
    raw_path.rsplit('/').find(|s| !s.is_empty())
}

/// Normalizes an absolute path strictly within a container's `"/"`, clamping
/// `".."` at `"/"` as Linux does so no path can escape the container's root.
fn normalize_container_path(path: &str) -> FsResult<String> {
    if !path.starts_with('/') || path.as_bytes().contains(&0) {
        return Err(FsError::Invalid);
    }
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            name => segments.push(name),
        }
    }
    if segments.is_empty() {
        return Ok(String::from("/"));
    }
    let mut normalized = String::new();
    for segment in segments {
        normalized.push('/');
        normalized.push_str(segment);
    }
    Ok(normalized)
}

fn resolve_container_symlink(link: &str, target: &str) -> FsResult<String> {
    if target.is_empty() || target.as_bytes().contains(&0) {
        return Err(FsError::Invalid);
    }
    if target.starts_with('/') {
        return normalize_container_path(target);
    }
    let parent = crate::parent_path(link);
    let mut joined = String::with_capacity(parent.len() + 1 + target.len());
    joined.push_str(parent);
    if !parent.ends_with('/') {
        joined.push('/');
    }
    joined.push_str(target);
    normalize_container_path(&joined)
}

fn relative_within_mount<'a>(mount_point: &str, normalized: &'a str) -> &'a str {
    if mount_point == "/" {
        normalized.strip_prefix('/').unwrap_or(normalized)
    } else {
        normalized
            .strip_prefix(mount_point)
            .and_then(|rest| rest.strip_prefix('/').or(Some(rest)))
            .unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::UnsupportedStorage;
    use crate::vfs::{BOOT_DEVICE, MemoryFs, MountTable, write_bytes};
    use crate::{BootFs, ClockAuthorityRights, EmbeddedBootDirectory, EmbeddedBootFs};

    const TEST_BOOT_IMAGE: EmbeddedBootFs = EmbeddedBootFs::new(
        &[
            EmbeddedBootDirectory::new("root-a", 0),
            EmbeddedBootDirectory::new("root-b", 0),
            EmbeddedBootDirectory::new("shared", 0),
            EmbeddedBootDirectory::new("host-secret", 0),
            EmbeddedBootDirectory::new("priv", 0),
            EmbeddedBootDirectory::new("ro", 0),
            EmbeddedBootDirectory::new("noexec", 0),
        ],
        &[],
    );

    fn test_namespace() -> Namespace<UnsupportedStorage> {
        Namespace::new(MountTable::new(
            BootFs::new(TEST_BOOT_IMAGE, BOOT_DEVICE),
            4,
        ))
    }

    const RWX: DirectoryAuthorityRights = DirectoryAuthorityRights::READ
        .union(DirectoryAuthorityRights::WRITE)
        .union(DirectoryAuthorityRights::MUTATE_DIRECTORY)
        .union(DirectoryAuthorityRights::EXECUTE);
    const RX: DirectoryAuthorityRights =
        DirectoryAuthorityRights::READ.union(DirectoryAuthorityRights::EXECUTE);

    fn block_on<T>(future: impl core::future::Future<Output = T>) -> T {
        let mut future = core::pin::pin!(future);
        let waker = futures::task::noop_waker_ref();
        let mut cx = core::task::Context::from_waker(waker);
        loop {
            if let core::task::Poll::Ready(value) = future.as_mut().poll(&mut cx) {
                return value;
            }
        }
    }

    fn mount_memory(
        ns: &Namespace<UnsupportedStorage>,
        point: &str,
        rights: FileSystemRights,
        sharing: MountSharing,
    ) -> MemoryFs {
        let fs = MemoryFs::new(ns.table().allocate_device());
        let cap = ProcessAuthority::root().derive_mount_cap(point).unwrap();
        block_on(ns.mount(
            &cap,
            MountedFs::Memory(fs.clone()),
            MountGrant { rights, sharing },
        ))
        .expect("mount memory fs");
        fs
    }

    async fn create_file(fs: &MemoryFs, path: &str, data: &[u8]) {
        let path = FsPath::new(path).unwrap();
        let _ = fs
            .open(path, helios_hal::fs::OpenFlags::CREATE, 0)
            .await
            .unwrap();
        write_bytes(fs, path, helios_hal::fs::WritePosition::At(0), data, 0)
            .await
            .unwrap();
    }

    #[test]
    fn side_by_side_containers_have_isolated_roots_mounts_pids_and_hostnames() {
        let host_ns = test_namespace();
        let rw = FileSystemRights::READ | FileSystemRights::WRITE;

        let root_a = mount_memory(&host_ns, "/root-a", rw, MountSharing::Private);
        let root_b = mount_memory(&host_ns, "/root-b", rw, MountSharing::Private);
        let shared = mount_memory(&host_ns, "/shared", rw, MountSharing::Shared);
        let host_only = mount_memory(&host_ns, "/host-secret", rw, MountSharing::Shared);

        block_on(async {
            create_file(&root_a, "marker", b"container-a").await;
            create_file(&root_b, "marker", b"container-b").await;
            create_file(&shared, "note", b"shared-data").await;
            create_file(&host_only, "secret", b"host-secret").await;
        });
        root_a
            .set_owner(FsPath::new("marker").unwrap(), Some(500), Some(501), 0)
            .unwrap();
        root_a
            .set_permissions(FsPath::new("marker").unwrap(), 0o4755, 0)
            .unwrap();
        shared
            .set_permissions(FsPath::new("note").unwrap(), 0o4755, 0)
            .unwrap();

        let container_a = block_on(LinuxContainer::create(
            ContainerId::new(NonZeroU64::new(1).unwrap()),
            &ProcessAuthority::root(),
            &host_ns,
            ProcessAuthority::empty(),
            ContainerConfig {
                root: ContainerMountSpec {
                    source_path: String::from("/root-a"),
                    target_path: String::from("/"),
                    rights: RWX,
                    sharing: MountSharing::Private,
                },
                mounts: vec![ContainerMountSpec {
                    source_path: String::from("/shared"),
                    target_path: String::from("/data"),
                    rights: RX,
                    sharing: MountSharing::Shared,
                }],
                shared_owner: SharedOwner {
                    uid: 1000,
                    gid: 1000,
                },
                credentials: Credentials::for_ids(0, 0, Vec::new()),
                hostname: UtsField::from_configured("alpha").unwrap(),
                domainname: UtsField::from_configured("a.local").unwrap(),
            },
        ))
        .expect("container A creates");

        let container_b = block_on(LinuxContainer::create(
            ContainerId::new(NonZeroU64::new(2).unwrap()),
            &ProcessAuthority::root(),
            &host_ns,
            ProcessAuthority::empty(),
            ContainerConfig {
                root: ContainerMountSpec {
                    source_path: String::from("/root-b"),
                    target_path: String::from("/"),
                    rights: RWX,
                    sharing: MountSharing::Private,
                },
                mounts: vec![ContainerMountSpec {
                    source_path: String::from("/shared"),
                    target_path: String::from("/shared"),
                    rights: RX,
                    sharing: MountSharing::Shared,
                }],
                shared_owner: SharedOwner {
                    uid: 2000,
                    gid: 2000,
                },
                credentials: Credentials::for_ids(1001, 1001, vec![10]),
                hostname: UtsField::from_configured("beta").unwrap(),
                domainname: UtsField::from_configured("b.local").unwrap(),
            },
        ))
        .expect("container B creates");

        // Each container starts its own PID namespace at 1 and counts only its
        // own processes.
        let pid_a1 = container_a.allocate_process().unwrap();
        let pid_b1 = container_b.allocate_process().unwrap();
        assert_eq!(pid_a1.pid().get(), 1);
        assert_eq!(pid_b1.pid().get(), 1);
        assert_eq!(container_a.process_count(), 1);
        assert_eq!(container_b.process_count(), 1);
        let pid_a2 = container_a.allocate_process().unwrap();
        assert_eq!(pid_a2.pid().get(), 2);
        assert_eq!(container_a.process_count(), 2);
        assert_eq!(container_b.process_count(), 1);

        // Isolated hostnames and domain names.
        assert_eq!(container_a.hostname().as_bytes(), b"alpha");
        assert_eq!(container_b.hostname().as_bytes(), b"beta");
        container_a.set_hostname(UtsField::from_configured("alpha-2").unwrap());
        assert_eq!(container_a.hostname().as_bytes(), b"alpha-2");
        assert_eq!(container_b.hostname().as_bytes(), b"beta");

        // Each container sees only its own root and mounts; neither can see the
        // other's root or unmounted host paths, even via `..`.
        block_on(async {
            let a_marker = container_a
                .filesystem()
                .read_executable("/marker")
                .await
                .unwrap();
            let b_marker = container_b
                .filesystem()
                .read_executable("/marker")
                .await
                .unwrap();
            assert!(
                matches!(a_marker, FileContents::Written(bytes) if bytes.as_ref() == b"container-a")
            );
            assert!(
                matches!(b_marker, FileContents::Written(bytes) if bytes.as_ref() == b"container-b")
            );

            // Neither container can see `/host-secret` or the other's mount point.
            assert_eq!(
                container_a.filesystem().stat("/host-secret/secret").await,
                Err(FsError::NoEntry)
            );
            assert_eq!(
                container_a
                    .filesystem()
                    .stat("/../../../root-b/marker")
                    .await,
                Err(FsError::NoEntry)
            );
            assert_eq!(
                container_a.filesystem().stat("/shared/note").await,
                Err(FsError::NoEntry)
            );
            assert_eq!(
                container_b.filesystem().stat("/data/note").await,
                Err(FsError::NoEntry)
            );

            // Private mount preserves stored metadata and honours suid; shared
            // mount presents each container's own `SharedOwner` with NO_SUID | NO_DEV.
            let a_priv = container_a.filesystem().stat("/marker").await.unwrap();
            assert_eq!(
                a_priv.unix,
                UnixAttributes {
                    permissions: 0o4755,
                    uid: 500,
                    gid: 501,
                }
            );
            assert!(a_priv.flags.honours_exec_privileges());

            let a_shared = container_a.filesystem().stat("/data/note").await.unwrap();
            assert_eq!(
                a_shared.unix,
                UnixAttributes {
                    permissions: 0o555,
                    uid: 1000,
                    gid: 1000,
                }
            );
            assert!(
                a_shared
                    .flags
                    .contains(MountFlags::READ_ONLY | MountFlags::NO_SUID | MountFlags::NO_DEV)
            );

            let b_shared = container_b.filesystem().stat("/shared/note").await.unwrap();
            assert_eq!(
                b_shared.unix,
                UnixAttributes {
                    permissions: 0o555,
                    uid: 2000,
                    gid: 2000,
                }
            );
        });

        // A second container cannot claim `/root-a` while container A is alive.
        let conflict = block_on(LinuxContainer::create(
            ContainerId::new(NonZeroU64::new(3).unwrap()),
            &ProcessAuthority::root(),
            &host_ns,
            ProcessAuthority::empty(),
            ContainerConfig {
                root: ContainerMountSpec {
                    source_path: String::from("/root-a"),
                    target_path: String::from("/"),
                    rights: RWX,
                    sharing: MountSharing::Private,
                },
                mounts: Vec::new(),
                shared_owner: SharedOwner { uid: 0, gid: 0 },
                credentials: Credentials::root(),
                hostname: UtsField::UNSET,
                domainname: UtsField::UNSET,
            },
        ));
        assert!(matches!(
            conflict,
            Err(ContainerError::PrivateMountBusy { .. })
        ));

        // Dropping container A releases `/root-a` so a new container can claim it.
        drop(pid_a1);
        drop(pid_a2);
        drop(container_a);
        let reclaimed = block_on(LinuxContainer::create(
            ContainerId::new(NonZeroU64::new(4).unwrap()),
            &ProcessAuthority::root(),
            &host_ns,
            ProcessAuthority::empty(),
            ContainerConfig {
                root: ContainerMountSpec {
                    source_path: String::from("/root-a"),
                    target_path: String::from("/"),
                    rights: RWX,
                    sharing: MountSharing::Private,
                },
                mounts: Vec::new(),
                shared_owner: SharedOwner { uid: 0, gid: 0 },
                credentials: Credentials::root(),
                hostname: UtsField::UNSET,
                domainname: UtsField::UNSET,
            },
        ));
        assert!(reclaimed.is_ok());
    }

    #[test]
    fn container_refuses_sharing_mismatch_and_widening_beyond_caller_authority() {
        let host_ns = test_namespace();
        let rw = FileSystemRights::READ | FileSystemRights::WRITE;
        let _priv_fs = mount_memory(&host_ns, "/priv", rw, MountSharing::Private);
        let _ro_shared = mount_memory(
            &host_ns,
            "/ro",
            FileSystemRights::READ,
            MountSharing::Shared,
        );

        // Shared backing mount cannot be promoted to Private.
        let promote = block_on(LinuxContainer::create(
            ContainerId::new(NonZeroU64::new(1).unwrap()),
            &ProcessAuthority::root(),
            &host_ns,
            ProcessAuthority::empty(),
            ContainerConfig {
                root: ContainerMountSpec {
                    source_path: String::from("/ro"),
                    target_path: String::from("/"),
                    rights: RX,
                    sharing: MountSharing::Private,
                },
                mounts: Vec::new(),
                shared_owner: SharedOwner { uid: 0, gid: 0 },
                credentials: Credentials::root(),
                hostname: UtsField::UNSET,
                domainname: UtsField::UNSET,
            },
        ));
        assert!(matches!(
            promote,
            Err(ContainerError::MountSharingMismatch { .. })
        ));

        // Private backing mount cannot be downgraded to Shared.
        let demote = block_on(LinuxContainer::create(
            ContainerId::new(NonZeroU64::new(2).unwrap()),
            &ProcessAuthority::root(),
            &host_ns,
            ProcessAuthority::empty(),
            ContainerConfig {
                root: ContainerMountSpec {
                    source_path: String::from("/priv"),
                    target_path: String::from("/"),
                    rights: RWX,
                    sharing: MountSharing::Shared,
                },
                mounts: Vec::new(),
                shared_owner: SharedOwner { uid: 0, gid: 0 },
                credentials: Credentials::root(),
                hostname: UtsField::UNSET,
                domainname: UtsField::UNSET,
            },
        ));
        assert!(matches!(
            demote,
            Err(ContainerError::MountSharingMismatch { .. })
        ));

        // Read-only backing mount cannot grant WRITE.
        let write_on_ro = block_on(LinuxContainer::create(
            ContainerId::new(NonZeroU64::new(3).unwrap()),
            &ProcessAuthority::root(),
            &host_ns,
            ProcessAuthority::empty(),
            ContainerConfig {
                root: ContainerMountSpec {
                    source_path: String::from("/ro"),
                    target_path: String::from("/"),
                    rights: RWX,
                    sharing: MountSharing::Shared,
                },
                mounts: Vec::new(),
                shared_owner: SharedOwner { uid: 0, gid: 0 },
                credentials: Credentials::root(),
                hostname: UtsField::UNSET,
                domainname: UtsField::UNSET,
            },
        ));
        assert!(matches!(
            write_on_ro,
            Err(ContainerError::ReadOnlyMount { .. })
        ));

        // Caller with narrow authority cannot grant a mount outside its authority.
        let mut narrow_caller = ProcessAuthority::empty();
        narrow_caller.insert_directory_preopen(DirectoryPreopen::new("/ro", "/ro", RX).unwrap());
        let widened = block_on(LinuxContainer::create(
            ContainerId::new(NonZeroU64::new(4).unwrap()),
            &narrow_caller,
            &host_ns,
            ProcessAuthority::empty(),
            ContainerConfig {
                root: ContainerMountSpec {
                    source_path: String::from("/priv"),
                    target_path: String::from("/"),
                    rights: RX,
                    sharing: MountSharing::Private,
                },
                mounts: Vec::new(),
                shared_owner: SharedOwner { uid: 0, gid: 0 },
                credentials: Credentials::root(),
                hostname: UtsField::UNSET,
                domainname: UtsField::UNSET,
            },
        ));
        assert!(matches!(widened, Err(ContainerError::Authority { .. })));

        // A uid 0 container built with narrow authority lacks clock/network rights
        // and cannot read an executable from a mount without EXECUTE right.
        let read_only_no_exec = mount_memory(
            &host_ns,
            "/noexec",
            FileSystemRights::READ | FileSystemRights::WRITE,
            MountSharing::Shared,
        );
        block_on(create_file(&read_only_no_exec, "bin", b"\x7fELF"));
        let container = block_on(LinuxContainer::create(
            ContainerId::new(NonZeroU64::new(5).unwrap()),
            &ProcessAuthority::root(),
            &host_ns,
            ProcessAuthority::empty(),
            ContainerConfig {
                root: ContainerMountSpec {
                    source_path: String::from("/noexec"),
                    target_path: String::from("/"),
                    rights: DirectoryAuthorityRights::READ,
                    sharing: MountSharing::Shared,
                },
                mounts: Vec::new(),
                shared_owner: SharedOwner { uid: 0, gid: 0 },
                credentials: Credentials::root(),
                hostname: UtsField::from_configured("narrow").unwrap(),
                domainname: UtsField::UNSET,
            },
        ))
        .unwrap();
        assert_eq!(container.default_credentials().user.effective, 0);
        assert!(container.authority().derive_set_wall_clock_cap().is_err());
        assert!(container.authority().derive_tcp_cap().is_err());
        assert_eq!(
            container.authority().clock_rights(),
            ClockAuthorityRights::empty()
        );
        assert!(matches!(
            block_on(container.filesystem().read_executable("/bin")),
            Err(FsError::NotPermitted)
        ));
    }

    #[test]
    fn ephemeral_container_pins_shared_and_attaches_additional_preopens() {
        let host_ns = test_namespace();
        let rw = FileSystemRights::READ | FileSystemRights::WRITE;
        let extra = mount_memory(&host_ns, "/shared", rw, MountSharing::Shared);
        block_on(create_file(&extra, "tool", b"\x7fELF-tool"));

        let mut authority = ProcessAuthority::empty();
        authority.insert_directory_preopen(DirectoryPreopen::new("/", "/", RX).unwrap());
        authority.insert_directory_preopen(DirectoryPreopen::new("/shared", "/opt", RX).unwrap());

        let container = LinuxContainer::ephemeral(
            ContainerId::new(NonZeroU64::new(7).unwrap()),
            authority,
            &host_ns,
        );
        for mount in container.filesystem().mounts() {
            assert_eq!(mount.grant().sharing, MountSharing::Shared);
        }
        assert!(block_on(container.filesystem().read_executable("/opt/tool")).is_ok());
        assert!(matches!(
            block_on(container.filesystem().read_executable("/shared/tool")),
            Err(FsError::NoEntry)
        ));

        // A sandboxed `"/"` preopen (`source_path != "/"`) binds `"/"` to that
        // source directory alone and never widens access to the host `"/"`.
        let host_secret = mount_memory(&host_ns, "/host-secret", rw, MountSharing::Shared);
        block_on(create_file(&host_secret, "secret", b"\x7fELF-secret"));
        let mut sandboxed_authority = ProcessAuthority::empty();
        sandboxed_authority
            .insert_directory_preopen(DirectoryPreopen::new("/shared", "/", RX).unwrap());
        let sandboxed = LinuxContainer::ephemeral(
            ContainerId::new(NonZeroU64::new(8).unwrap()),
            sandboxed_authority,
            &host_ns,
        );
        assert!(block_on(sandboxed.filesystem().read_executable("/tool")).is_ok());
        assert!(matches!(
            block_on(
                sandboxed
                    .filesystem()
                    .read_executable("/host-secret/secret")
            ),
            Err(FsError::NoEntry)
        ));
    }

    #[test]
    fn container_path_walker_enforces_symlinks_boundaries_and_errors() {
        let host_ns = test_namespace();
        let rw = FileSystemRights::READ | FileSystemRights::WRITE;
        let ro = FileSystemRights::READ;

        let root_fs = mount_memory(&host_ns, "/root-a", rw, MountSharing::Private);
        let ro_fs = mount_memory(&host_ns, "/ro", ro, MountSharing::Shared);
        block_on(async {
            create_file(&root_fs, "alpha", b"hello").await;
            create_file(&ro_fs, "fixed", b"ro-data").await;
        });

        let container = block_on(LinuxContainer::create(
            ContainerId::new(NonZeroU64::new(9).unwrap()),
            &ProcessAuthority::root(),
            &host_ns,
            ProcessAuthority::empty(),
            ContainerConfig {
                root: ContainerMountSpec {
                    source_path: String::from("/root-a"),
                    target_path: String::from("/"),
                    rights: RWX,
                    sharing: MountSharing::Private,
                },
                mounts: vec![ContainerMountSpec {
                    source_path: String::from("/ro"),
                    target_path: String::from("/ro"),
                    rights: RX,
                    sharing: MountSharing::Shared,
                }],
                shared_owner: SharedOwner { uid: 0, gid: 0 },
                credentials: Credentials::root(),
                hostname: UtsField::UNSET,
                domainname: UtsField::UNSET,
            },
        ))
        .expect("container creates");
        let fs = container.filesystem();

        block_on(async {
            // Component walker catches missing and non-directory intermediate components.
            assert!(matches!(
                fs.stat_at("/", "nonexistent/..", true).await,
                Err(FsError::NoEntry)
            ));
            assert!(matches!(
                fs.stat_at("/", "alpha/..", true).await,
                Err(FsError::NotDirectory)
            ));
            assert!(matches!(
                fs.stat_at("/", "alpha/", true).await,
                Err(FsError::NotDirectory)
            ));

            // Intermediate symlink expands before `..`, and symlink loop returns `Loop`.
            fs.mkdir_at("/", "sub", 0o755, 1).await.unwrap();
            fs.symlink_at("sub", "/", "sym_sub", 1).await.unwrap();
            let (_, resolved) = fs.stat_at("/", "sym_sub/../alpha", true).await.unwrap();
            assert_eq!(resolved, "/alpha");

            // `O_PATH | O_NOFOLLOW` opens the symlink itself, and `read_link_resolved`
            // reads its target without re-walking.
            let path_nofollow = OpenRequest {
                read: false,
                write: false,
                create: false,
                exclusive: false,
                truncate: false,
                directory: false,
                nofollow: true,
                path_only: true,
                append: false,
                sync: false,
                dsync: false,
                mode: 0,
            };
            let (_, sym_path, _) = fs.open_at("/", "sym_sub", path_nofollow, 1).await.unwrap();
            assert_eq!(sym_path, "/sym_sub");
            assert_eq!(fs.read_link_resolved(&sym_path).await.unwrap(), "sub");

            fs.symlink_at("loop_b", "/", "loop_a", 1).await.unwrap();
            fs.symlink_at("loop_a", "/", "loop_b", 1).await.unwrap();
            assert!(matches!(
                fs.stat_at("/", "loop_a", true).await,
                Err(FsError::Loop)
            ));

            // Dangling symlink with O_CREAT | O_EXCL fails with Exists.
            fs.symlink_at("missing_target", "/", "dangling", 1)
                .await
                .unwrap();
            let excl = OpenRequest {
                read: true,
                write: true,
                create: true,
                exclusive: true,
                truncate: false,
                directory: false,
                nofollow: false,
                path_only: false,
                append: false,
                sync: false,
                dsync: false,
                mode: 0o644,
            };
            assert!(matches!(
                fs.open_at("/", "dangling", excl, 1).await,
                Err(FsError::Exists)
            ));

            // Cross-mount rename and link fail with CrossDevice, and read-only mount fails with ReadOnly.
            assert!(matches!(
                fs.rename_at("/", "alpha", "/", "/ro/moved", RenameMode::Replace, 1)
                    .await,
                Err(FsError::CrossDevice)
            ));
            assert!(matches!(
                fs.link_at("/", "alpha", "/", "/ro/linked", false, false, 1)
                    .await,
                Err(FsError::CrossDevice)
            ));
            assert!(matches!(
                fs.write_at("/ro/fixed", WritePosition::At(0), b"x", 1)
                    .await,
                Err(FsError::ReadOnly)
            ));
            assert!(matches!(
                fs.unlink_at("/", "/ro/fixed", false, 1).await,
                Err(FsError::ReadOnly)
            ));
        });
    }

    #[test]
    fn synthetic_etc_resolv_conf_and_hosts_reflect_authority_and_resolvers() {
        let host_ns = test_namespace();
        let resolvers = [
            crate::NetworkIpAddress::Ipv4(crate::Ipv4Address::new([10, 0, 2, 3])),
            crate::NetworkIpAddress::Ipv6(helios_netstack::Ipv6Address::new([
                0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
            ])),
        ];

        // Container without DNS authority sees an empty /etc/resolv.conf.
        let no_dns = LinuxContainer::ephemeral(
            ContainerId::new(NonZeroU64::new(9).unwrap()),
            ProcessAuthority::empty(),
            &host_ns,
        );
        assert_eq!(
            no_dns.synthetic_etc_file("/etc/resolv.conf", &resolvers),
            Some(Vec::new())
        );

        // Container with DNS authority sees both IPv4 and IPv6 resolvers.
        let mut with_dns_auth = ProcessAuthority::empty();
        with_dns_auth.grant_network_rights(crate::NetworkAuthorityRights::DNS);
        let with_dns = LinuxContainer::ephemeral(
            ContainerId::new(NonZeroU64::new(10).unwrap()),
            with_dns_auth,
            &host_ns,
        );
        let resolv = String::from_utf8(
            with_dns
                .synthetic_etc_file("/etc/resolv.conf", &resolvers)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            resolv,
            "nameserver 10.0.2.3\nnameserver 2001:4860:4860::8888\n"
        );

        // Default unset UTS hostname ("(none)") is omitted from /etc/hosts.
        let default_hosts = String::from_utf8(
            with_dns
                .synthetic_etc_file("/etc/hosts", &resolvers)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(default_hosts, "127.0.0.1 localhost\n::1 localhost\n");

        // /etc/hosts reflects the container's current UTS hostname.
        with_dns.set_hostname(UtsField::from_bytes(b"app-box").unwrap());
        let hosts = String::from_utf8(
            with_dns
                .synthetic_etc_file("/etc/hosts", &resolvers)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            hosts,
            "127.0.0.1 localhost app-box\n::1 localhost app-box\n"
        );
        assert!(
            with_dns
                .synthetic_etc_file("/etc/passwd", &resolvers)
                .is_none()
        );
    }
}
