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

use helios_btrfs::DeviceNumber;
use helios_btrfs::write::{Attributes as BtrfsAttributes, Special};
use helios_hal::fs::{
    DirCookie, DirEntry, DirStream, FileSystem, FileSystemRights, FsError, FsPath, FsResult,
    Landed, Metadata, NodeKind, OpenFlags, RenameMode, WritePosition, write_with,
};
use helios_linux::syscall::{
    AccessCheck, CAP_FSETID, CAP_FULL_SET, CAP_NET_ADMIN, CAP_NET_BIND_SERVICE, CAP_NET_RAW,
    CAP_SYS_TIME, Credentials, FsOpError, OpenRequest, PidNamespace, TimeUpdate, UtsField,
    XattrSetMode as LinuxXattrSetMode, permissions,
};
use helios_unix::FutexTable;
use thiserror::Error;

use crate::vfs::{
    FileContents, Follow, HeldPath, MAX_MOUNTS, MAX_SYMLINK_DEPTH, MemoryFs, MountFlags,
    MountGrant, MountHold, MountSharing, MountedFs, Namespace, OverlayFs, PinnedLower,
    PrivateMountClaim, PrivateMountClaimError, SharedOwner, Storage, UnixAttributes, UnixFsError,
    XattrSetMode, join_fs_path, within_directory,
};
use crate::{
    ClockAuthorityRights, DirectoryAuthorityRights, DirectoryPreopen, NetworkAuthorityRights,
    ProcessAuthority, ProcessAuthorityError,
};

fn authority_cap_ceiling_for(authority: &ProcessAuthority) -> u64 {
    let mut mask = CAP_FULL_SET;
    if !authority
        .clock_rights()
        .contains(ClockAuthorityRights::SET_WALL_CLOCK)
    {
        mask &= !(1u64 << CAP_SYS_TIME);
    }
    if !authority
        .network_rights()
        .contains(NetworkAuthorityRights::PRIVILEGED_BIND)
    {
        mask &= !(1u64 << CAP_NET_BIND_SERVICE);
    }
    if !authority
        .network_rights()
        .contains(NetworkAuthorityRights::ADMIN)
    {
        mask &= !((1u64 << CAP_NET_ADMIN) | (1u64 << CAP_NET_RAW));
    }
    mask
}

fn unix_to_op(error: UnixFsError) -> FsOpError {
    match error {
        UnixFsError::Fs(error) => FsOpError::Fs(error),
        UnixFsError::PermissionDenied => FsOpError::PermissionDenied,
        UnixFsError::NoData => FsOpError::NoData,
        UnixFsError::Range => FsOpError::Range,
        UnixFsError::ArgTooBig => FsOpError::ArgTooBig,
    }
}

/// Masks a non-directory creation mode to `S_IALLUGO` (`0o7777`) and clears
/// `S_ISGID` when the new inode inherits a group the caller neither belongs to
/// nor overrides with `CAP_FSETID` (`fs/inode.c` `inode_init_owner`, Linux
/// v6.12).
fn sanitize_create_mode(
    mode: u32,
    parent: Option<permissions::InodeMeta>,
    creds: &Credentials,
) -> u32 {
    let mut perm = mode & permissions::S_IALLUGO;
    if let Some(parent) = parent
        && (parent.mode & permissions::S_ISGID) != 0
        && (perm & (permissions::S_ISGID | permissions::S_IXGRP))
            == (permissions::S_ISGID | permissions::S_IXGRP)
        && !creds.in_group(parent.gid)
        && !creds.capabilities.has_effective(CAP_FSETID)
    {
        perm &= !permissions::S_ISGID;
    }
    perm
}

fn resolve_time_update(update: TimeUpdate, now: u64) -> Option<u64> {
    match update {
        TimeUpdate::Omit => None,
        TimeUpdate::Now => Some(now),
        TimeUpdate::Set(nanos) => Some(nanos),
    }
}

fn to_vfs_xattr_mode(mode: LinuxXattrSetMode) -> XattrSetMode {
    match mode {
        LinuxXattrSetMode::CreateOrReplace => XattrSetMode::Any,
        LinuxXattrSetMode::Create => XattrSetMode::Create,
        LinuxXattrSetMode::Replace => XattrSetMode::Replace,
    }
}

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

/// How a container mount accesses its backing directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerMountSharing {
    /// Exclusive claim over a [`MountSharing::Private`] backing mount.
    Private,
    /// Shared access to a [`MountSharing::Shared`] backing mount.
    Shared,
    /// Fresh private `UserMemoryPool`-backed [`OverlayFs`] upper tree layered
    /// over a lock-free pinned read-only lower directory (`HeldPath<S>`).
    /// Requires only read (and optional execute) authority on the lower
    /// directory and performs zero disk writes on creation or teardown.
    EphemeralOverlay,
}

impl From<MountSharing> for ContainerMountSharing {
    fn from(sharing: MountSharing) -> Self {
        match sharing {
            MountSharing::Private => Self::Private,
            MountSharing::Shared => Self::Shared,
        }
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
    /// How this mount is shared or overlaid over its backing directory.
    pub sharing: ContainerMountSharing,
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

    fn is_private(&self) -> bool {
        self.mount.grant.sharing == MountSharing::Private
    }

    async fn inode_meta(&self) -> Result<permissions::InodeMeta, FsOpError> {
        let md = self
            .fs()
            .unix_metadata(self.fs_path())
            .await
            .map_err(unix_to_op)?;
        Ok(permissions::InodeMeta {
            kind: md.kind,
            mode: md.attributes.permissions,
            uid: md.attributes.uid,
            gid: md.attributes.gid,
        })
    }

    async fn access_acl(&self) -> Option<Bytes> {
        self.fs()
            .xattr(self.fs_path(), permissions::XATTR_POSIX_ACL_ACCESS)
            .await
            .ok()
            .flatten()
    }

    /// Checks that `creds` may execute this resolved regular file (enforcing
    /// mount `READ | EXECUTE` authority and private-mount `MAY_EXEC` DAC/ACL
    /// rules) and reads its entire image (`fs/exec.c` `do_open_execat`).
    pub async fn check_exec_and_read(
        &self,
        creds: &Credentials,
    ) -> Result<FileContents, FsOpError> {
        let required = DirectoryAuthorityRights::READ | DirectoryAuthorityRights::EXECUTE;
        if !self.authority_rights().contains(required) {
            return Err(FsError::NotPermitted.into());
        }
        let meta = self.inode_meta().await?;
        if meta.kind != NodeKind::File {
            return Err(FsError::NotPermitted.into());
        }
        self.check_permission(creds, permissions::MAY_EXEC).await?;
        Ok(self.fs().read_whole(self.fs_path()).await?)
    }

    /// Computes the post-`execve` [`Credentials`] for executing this resolved
    /// regular file (`fs/exec.c` `bprm_fill_uid` + `security/commoncap.c`
    /// `cap_bprm_creds_from_file`), bounded by `authority_cap_ceiling`, the
    /// mount's `NO_SUID` flag, and `creds.no_new_privs`.
    pub async fn exec_credentials(
        &self,
        creds: &Credentials,
        authority_cap_ceiling: u64,
    ) -> Result<Credentials, FsOpError> {
        let required = DirectoryAuthorityRights::READ | DirectoryAuthorityRights::EXECUTE;
        if !self.authority_rights().contains(required) {
            return Err(FsError::NotPermitted.into());
        }
        let meta = self.inode_meta().await?;
        if meta.kind != NodeKind::File {
            return Err(FsError::NotPermitted.into());
        }
        self.check_permission(creds, permissions::MAY_EXEC).await?;
        let honours = self.flags().honours_exec_privileges();
        let cap_bytes = if honours && !creds.no_new_privs && self.is_private() {
            self.fs()
                .xattr(self.fs_path(), permissions::XATTR_SECURITY_CAPABILITY)
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        let effective_cap = self.file_capability(cap_bytes.as_deref());
        Ok(permissions::apply_exec_credentials(
            creds,
            meta,
            effective_cap,
            honours,
            authority_cap_ceiling,
        ))
    }

    async fn check_permission(&self, creds: &Credentials, want: u32) -> Result<(), FsOpError> {
        if !self.is_private() {
            return Ok(());
        }
        let meta = self.inode_meta().await?;
        let acl = self.access_acl().await;
        permissions::generic_permission(creds, meta, acl.as_deref(), want)
    }

    /// Strips `S_ISUID`/`S_ISGID` (without `CAP_FSETID`) and
    /// `security.capability` on writes and truncates of regular files on a
    /// private mount (`fs/inode.c` `file_remove_privs`, Linux v6.12).
    async fn strip_privs_on_write(
        &self,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        if !self.is_private() {
            return Ok(());
        }
        let meta = self.inode_meta().await?;
        if meta.kind != NodeKind::File {
            return Ok(());
        }
        if let Some(new_mode) = permissions::stripped_mode_on_write(creds, meta) {
            self.fs()
                .set_permissions(self.fs_path(), new_mode, now, payer)
                .await
                .map_err(unix_to_op)?;
        }
        match self
            .fs()
            .remove_xattr(
                self.fs_path(),
                permissions::XATTR_SECURITY_CAPABILITY,
                now,
                payer,
            )
            .await
        {
            Ok(()) | Err(UnixFsError::NoData) | Err(UnixFsError::Fs(FsError::Unsupported)) => {
                Ok(())
            }
            Err(error) => Err(unix_to_op(error)),
        }
    }

    async fn describe(&self) -> FsResult<ContainerNodeInfo> {
        let metadata = self.fs().stat(self.fs_path()).await?;
        let unix_md = self
            .fs()
            .unix_metadata(self.fs_path())
            .await
            .map_err(UnixFsError::into_fs_error)?;
        let unix = self.container_view(metadata.kind, unix_md.attributes);
        let rdev = if self.is_private() {
            u64::from(unix_md.rdev)
        } else {
            0
        };
        Ok(ContainerNodeInfo {
            metadata,
            unix,
            rdev,
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
    /// Encoded device number (`new_encode_dev`) on private mounts; zero on
    /// shared mounts.
    pub rdev: u64,
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
        let unix_md = resolved
            .fs()
            .unix_metadata(resolved.fs_path())
            .await
            .map_err(UnixFsError::into_fs_error)?;
        let unix = resolved.container_view(metadata.kind, unix_md.attributes);
        let rdev = if resolved.is_private() {
            u64::from(unix_md.rdev)
        } else {
            0
        };
        Ok(ContainerNodeInfo {
            metadata,
            unix,
            rdev,
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

    async fn check_parent_permission(
        &self,
        child_path: &str,
        creds: &Credentials,
        want: u32,
    ) -> Result<Option<permissions::InodeMeta>, FsOpError> {
        let parent_path = crate::parent_path(child_path);
        let parent = self.resolve(parent_path)?;
        if !parent.is_private() {
            return Ok(None);
        }
        let meta = parent.inode_meta().await?;
        let acl = parent.access_acl().await;
        permissions::generic_permission(creds, meta, acl.as_deref(), want)?;
        Ok(Some(meta))
    }

    /// Walks `raw_path` relative to `base_dir` with root credentials.
    pub async fn walk_path(
        &self,
        base_dir: &str,
        raw_path: &str,
        follow_final: bool,
    ) -> FsResult<(ContainerResolved<'_, S>, bool)> {
        self.walk_path_for(base_dir, raw_path, follow_final, &Credentials::root())
            .await
            .map_err(|error| match error {
                FsOpError::Fs(fs_err) => fs_err,
                FsOpError::PermissionDenied => FsError::NotPermitted,
                FsOpError::NoData => FsError::NoEntry,
                FsOpError::Range | FsOpError::ArgTooBig => FsError::Overflow,
                FsOpError::NoDevice => FsError::Invalid,
            })
    }

    /// Walks `raw_path` component by component relative to `base_dir` (a
    /// normalized absolute container path) strictly within this container's
    /// root, checking `MAY_EXEC` search permission on every traversed
    /// directory that resides on a [`MountSharing::Private`] mount.
    /// Returns `(resolved, trailing_slash)`.
    pub async fn walk_path_for(
        &self,
        base_dir: &str,
        raw_path: &str,
        follow_final: bool,
        creds: &Credentials,
    ) -> Result<(ContainerResolved<'_, S>, bool), FsOpError> {
        if raw_path.is_empty() || raw_path.as_bytes().contains(&0) {
            return Err(FsError::Invalid.into());
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
            // Every lookup inside a directory requires search (`MAY_EXEC`)
            // permission on that directory (`fs/namei.c` `may_lookup`).
            let cur_dir_path = build_container_path(&segments);
            let cur_dir = self.resolve(&cur_dir_path)?;
            if cur_dir.is_private() {
                let dir_meta = cur_dir.inode_meta().await?;
                if dir_meta.kind != NodeKind::Directory {
                    return Err(FsError::NotDirectory.into());
                }
                let acl = cur_dir.access_acl().await;
                permissions::generic_permission(
                    creds,
                    dir_meta,
                    acl.as_deref(),
                    permissions::MAY_EXEC,
                )?;
            }
            match component.as_str() {
                "." | ".." => {
                    let meta = cur_dir.fs().stat(cur_dir.fs_path()).await?;
                    if meta.kind != NodeKind::Directory {
                        return Err(FsError::NotDirectory.into());
                    }
                    if component == ".." {
                        segments.pop();
                    }
                }
                name => {
                    if name.len() > 255 {
                        return Err(FsError::NameTooLong.into());
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
                                    return Err(FsError::Loop.into());
                                }
                                let target = resolved.fs().read_link(resolved.fs_path()).await?;
                                if target.is_empty() || target.as_bytes().contains(&0) {
                                    return Err(FsError::Invalid.into());
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
                            _ => return Err(FsError::NotDirectory.into()),
                        }
                    } else if follow_final || trailing_slash {
                        match resolved.fs().stat(resolved.fs_path()).await {
                            Ok(meta) if meta.kind == NodeKind::Symlink => {
                                symlink_expansions += 1;
                                if symlink_expansions > MAX_SYMLINK_DEPTH {
                                    return Err(FsError::Loop.into());
                                }
                                let target = resolved.fs().read_link(resolved.fs_path()).await?;
                                if target.is_empty() || target.as_bytes().contains(&0) {
                                    return Err(FsError::Invalid.into());
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
                                return Err(FsError::NotDirectory.into());
                            }
                            Ok(_) | Err(FsError::NoEntry) => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                }
            }
        }

        let final_path = build_container_path(&segments);
        Ok((self.resolve(&final_path)?, trailing_slash))
    }

    /// Resolves and stats `raw_path` relative to `base_dir`, returning both
    /// container-visible metadata and the normalized container path. An empty
    /// `raw_path` operates directly on `base_dir` without directory search
    /// (`AT_EMPTY_PATH` on `AT_FDCWD`, `fs/stat.c` `vfs_statx`).
    pub async fn stat_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        follow_final: bool,
        creds: &Credentials,
    ) -> Result<(ContainerNodeInfo, String), FsOpError> {
        let resolved = if raw_path.is_empty() {
            self.resolve(base_dir)?
        } else {
            self.walk_path_for(base_dir, raw_path, follow_final, creds)
                .await?
                .0
        };
        resolved.require_read()?;
        let info = resolved.describe().await?;
        Ok((info, resolved.container_path().to_owned()))
    }

    /// Stats an already-resolved container path (used for `fstat` on open
    /// descriptors, including `O_PATH | O_NOFOLLOW` symlink descriptors).
    pub async fn stat_resolved(
        &self,
        container_path: &str,
    ) -> Result<ContainerNodeInfo, FsOpError> {
        let resolved = self.resolve(container_path)?;
        Ok(resolved.describe().await?)
    }

    /// Checks directory search permission (`MAY_EXEC`) for `fchdir(2)`.
    pub async fn can_chdir(
        &self,
        container_path: &str,
        creds: &Credentials,
    ) -> Result<(), FsOpError> {
        let resolved = self.resolve(container_path)?;
        resolved
            .check_permission(creds, permissions::MAY_EXEC)
            .await
    }

    /// Checks access permissions for `raw_path` relative to `base_dir` within
    /// the container's authority ceiling (`fs/open.c` `do_faccessat`).
    pub async fn access_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        check: AccessCheck,
        creds: &Credentials,
    ) -> Result<(), FsOpError> {
        let eff = if check.use_effective {
            creds.clone()
        } else {
            creds.for_real_access()
        };
        let (resolved, _) = self
            .walk_path_for(base_dir, raw_path, check.follow, &eff)
            .await?;
        let info = resolved.describe().await?;
        if check.read {
            resolved.require_read()?;
        }
        if check.write {
            resolved.require_write()?;
        }
        if check.exec
            && !resolved
                .authority_rights()
                .contains(DirectoryAuthorityRights::EXECUTE)
        {
            return Err(FsError::NotPermitted.into());
        }
        if resolved.is_private() {
            let mut want = 0u32;
            if check.read {
                want |= permissions::MAY_READ;
            }
            if check.write {
                want |= permissions::MAY_WRITE;
            }
            if check.exec {
                want |= permissions::MAY_EXEC;
            }
            resolved.check_permission(&eff, want).await?;
        } else if check.exec
            && info.metadata.kind == NodeKind::File
            && (info.unix.permissions & 0o111) == 0
        {
            return Err(FsError::NotPermitted.into());
        }
        Ok(())
    }

    /// Opens or creates a file or directory for Linux `open`/`openat`/`creat`.
    pub async fn open_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        request: OpenRequest,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(ContainerNodeInfo, String, Option<MountHold>), FsOpError> {
        let follow_final = !(request.nofollow || (request.create && request.exclusive));
        let (resolved, trailing_slash) = self
            .walk_path_for(base_dir, raw_path, follow_final, creds)
            .await?;
        let existing = resolved.fs().stat(resolved.fs_path()).await;

        if request.path_only {
            let meta = existing?;
            if (request.directory || trailing_slash) && meta.kind != NodeKind::Directory {
                return Err(FsError::NotDirectory.into());
            }
            let info = resolved.describe().await?;
            return Ok((
                info,
                resolved.container_path().to_owned(),
                resolved.mount_hold(),
            ));
        }

        if request.create && request.exclusive && existing.is_ok() {
            return Err(FsError::Exists.into());
        }

        match existing {
            Ok(meta) => {
                if meta.kind == NodeKind::Symlink {
                    return Err(FsError::Loop.into());
                }
                if matches!(meta.kind, NodeKind::CharacterDevice | NodeKind::BlockDevice) {
                    if request.directory || trailing_slash {
                        return Err(FsError::NotDirectory.into());
                    }
                    if !resolved.flags().opens_devices() {
                        // `fs/namei.c` `may_open_dev`: `MNT_NODEV` returns `EACCES`.
                        return Err(FsError::NotPermitted.into());
                    }
                    if request.read {
                        resolved.require_read()?;
                    }
                    if request.write || request.truncate {
                        resolved.require_write()?;
                    }
                    let mut want = 0u32;
                    if request.read {
                        want |= permissions::MAY_READ;
                    }
                    if request.write || request.truncate {
                        want |= permissions::MAY_WRITE;
                    }
                    resolved.check_permission(creds, want).await?;
                    return Err(FsOpError::NoDevice);
                }
                if meta.kind == NodeKind::Directory {
                    if request.write || request.truncate {
                        return Err(FsError::IsDirectory.into());
                    }
                    resolved.require_read()?;
                    resolved
                        .check_permission(creds, permissions::MAY_READ)
                        .await?;
                } else {
                    if request.directory || trailing_slash {
                        return Err(FsError::NotDirectory.into());
                    }
                    if request.read {
                        resolved.require_read()?;
                    }
                    if request.write || request.truncate {
                        resolved.require_write()?;
                    }
                    let mut want = 0u32;
                    if request.read {
                        want |= permissions::MAY_READ;
                    }
                    if request.write || request.truncate {
                        want |= permissions::MAY_WRITE;
                    }
                    resolved.check_permission(creds, want).await?;
                    if request.truncate {
                        resolved.strip_privs_on_write(creds, now, payer).await?;
                    }
                    let mut flags = OpenFlags::empty();
                    if request.truncate {
                        flags |= OpenFlags::TRUNCATE;
                    }
                    resolved
                        .fs()
                        .open(resolved.fs_path(), flags, now, payer)
                        .await?;
                }
            }
            Err(FsError::NoEntry) => {
                if !request.create {
                    return Err(FsError::NoEntry.into());
                }
                if trailing_slash {
                    return Err(FsError::IsDirectory.into());
                }
                if request.directory {
                    return Err(FsError::NotDirectory.into());
                }
                resolved.require_mutate_dir()?;
                if request.write {
                    resolved.require_write()?;
                }
                let parent_meta = self
                    .check_parent_permission(
                        resolved.container_path(),
                        creds,
                        permissions::MAY_WRITE | permissions::MAY_EXEC,
                    )
                    .await?;
                let mut flags = OpenFlags::CREATE;
                if request.exclusive {
                    flags |= OpenFlags::EXCLUSIVE;
                }
                if request.truncate {
                    flags |= OpenFlags::TRUNCATE;
                }
                if resolved.is_private() {
                    let attrs = BtrfsAttributes {
                        permissions: sanitize_create_mode(request.mode, parent_meta, creds),
                        uid: creds.user.effective,
                        gid: creds.group.effective,
                        umask: request.umask,
                    };
                    resolved
                        .fs()
                        .open_unix(resolved.fs_path(), flags, attrs, now, payer)
                        .await
                        .map_err(unix_to_op)?;
                } else {
                    resolved
                        .fs()
                        .open(resolved.fs_path(), flags, now, payer)
                        .await?;
                    resolved.fs().apply_created_permissions(
                        resolved.fs_path(),
                        (request.mode & 0o777) & !request.umask,
                        now,
                    );
                }
            }
            Err(error) => return Err(error.into()),
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
    ) -> Result<Bytes, FsOpError> {
        let resolved = self.resolve(container_path)?;
        resolved.require_read()?;
        Ok(resolved
            .fs()
            .read_at(resolved.fs_path(), offset, max_bytes)
            .await?)
    }

    /// Writes `bytes` to `container_path` at `position`, stripping set-id bits
    /// and `security.capability` on private mounts (`fs/inode.c`
    /// `file_remove_privs`).
    pub async fn write_at(
        &self,
        container_path: &str,
        position: WritePosition,
        bytes: &[u8],
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<Landed, FsOpError> {
        let resolved = self.resolve(container_path)?;
        resolved.require_write()?;
        let landed = write_with(
            resolved.fs(),
            resolved.fs_path(),
            position,
            bytes.len(),
            now,
            payer,
            |at, destination| {
                destination.copy_from_slice(&bytes[at..at + destination.len()]);
            },
        )
        .await?;
        if landed.len > 0 {
            resolved.strip_privs_on_write(creds, now, payer).await?;
        }
        Ok(landed)
    }

    /// Truncates or zero-extends an open file at `container_path`.
    pub async fn set_size(
        &self,
        container_path: &str,
        size: u64,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        let resolved = self.resolve(container_path)?;
        resolved.require_write()?;
        resolved.strip_privs_on_write(creds, now, payer).await?;
        Ok(resolved
            .fs()
            .set_size(resolved.fs_path(), size, now, payer)
            .await?)
    }

    /// Truncates or zero-extends the file at `raw_path` relative to `base_dir`.
    pub async fn set_size_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        size: u64,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        let (resolved, _) = self.walk_path_for(base_dir, raw_path, true, creds).await?;
        resolved.require_write()?;
        resolved
            .check_permission(creds, permissions::MAY_WRITE)
            .await?;
        resolved.strip_privs_on_write(creds, now, payer).await?;
        Ok(resolved
            .fs()
            .set_size(resolved.fs_path(), size, now, payer)
            .await?)
    }

    /// Updates access/modified timestamps at `raw_path` relative to `base_dir`.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_times_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        follow_final: bool,
        access: TimeUpdate,
        modified: TimeUpdate,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        let (resolved, _) = self
            .walk_path_for(base_dir, raw_path, follow_final, creds)
            .await?;
        if access == TimeUpdate::Omit && modified == TimeUpdate::Omit {
            let _ = resolved.fs().stat(resolved.fs_path()).await?;
            return Ok(());
        }
        resolved.require_write()?;
        if resolved.is_private() {
            let meta = resolved.inode_meta().await?;
            let acl = resolved.access_acl().await;
            permissions::check_utimens(creds, meta, acl.as_deref(), access, modified)?;
        }
        Ok(resolved
            .fs()
            .set_times(
                resolved.fs_path(),
                resolve_time_update(access, now),
                resolve_time_update(modified, now),
                now,
                payer,
            )
            .await?)
    }

    /// Updates access/modified timestamps on an already-resolved container path.
    pub async fn set_times_resolved(
        &self,
        container_path: &str,
        access: TimeUpdate,
        modified: TimeUpdate,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        let resolved = self.resolve(container_path)?;
        if access == TimeUpdate::Omit && modified == TimeUpdate::Omit {
            return Ok(());
        }
        resolved.require_write()?;
        if resolved.is_private() {
            let meta = resolved.inode_meta().await?;
            let acl = resolved.access_acl().await;
            permissions::check_utimens(creds, meta, acl.as_deref(), access, modified)?;
        }
        Ok(resolved
            .fs()
            .set_times(
                resolved.fs_path(),
                resolve_time_update(access, now),
                resolve_time_update(modified, now),
                now,
                payer,
            )
            .await?)
    }

    /// Syncs data (and metadata if `!data_only`) for `container_path`.
    pub async fn sync(&self, container_path: &str, data_only: bool) -> Result<(), FsOpError> {
        let resolved = self.resolve(container_path)?;
        if data_only {
            Ok(resolved.fs().sync_data(resolved.fs_path()).await?)
        } else {
            Ok(resolved.fs().sync(resolved.fs_path()).await?)
        }
    }

    /// Reads the symbolic link target at `raw_path` relative to `base_dir`.
    pub async fn read_link_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        creds: &Credentials,
    ) -> Result<String, FsOpError> {
        let (resolved, trailing_slash) =
            self.walk_path_for(base_dir, raw_path, false, creds).await?;
        resolved.require_read()?;
        if trailing_slash {
            return Err(FsError::Invalid.into());
        }
        Ok(resolved.fs().read_link(resolved.fs_path()).await?)
    }

    /// Reads the symbolic link target for an already-resolved container path
    /// (used by `readlinkat(fd, "", ...)` on an `O_PATH | O_NOFOLLOW` symlink).
    pub async fn read_link_resolved(&self, container_path: &str) -> Result<String, FsOpError> {
        let resolved = self.resolve(container_path)?;
        resolved.require_read()?;
        Ok(resolved.fs().read_link(resolved.fs_path()).await?)
    }

    /// Creates a directory at `raw_path` relative to `base_dir`.
    #[allow(clippy::too_many_arguments)]
    pub async fn mkdir_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        mode: u32,
        umask: u32,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        if matches!(last_raw_component(raw_path), None | Some(".") | Some("..")) {
            return Err(FsError::Exists.into());
        }
        let (resolved, _) = self.walk_path_for(base_dir, raw_path, false, creds).await?;
        resolved.require_mutate_dir()?;
        self.check_parent_permission(
            resolved.container_path(),
            creds,
            permissions::MAY_WRITE | permissions::MAY_EXEC,
        )
        .await?;
        if resolved.is_private() {
            let attrs = BtrfsAttributes {
                permissions: mode & (0o777 | permissions::S_ISVTX),
                uid: creds.user.effective,
                gid: creds.group.effective,
                umask,
            };
            resolved
                .fs()
                .create_directory_unix(resolved.fs_path(), attrs, now, payer)
                .await
                .map_err(unix_to_op)?;
        } else {
            resolved
                .fs()
                .create_directory(resolved.fs_path(), now, payer)
                .await?;
            resolved.fs().apply_created_permissions(
                resolved.fs_path(),
                (mode & 0o777) & !umask,
                now,
            );
        }
        Ok(())
    }

    /// Creates a regular file, FIFO, socket, or device node (`mknod`/`mknodat`).
    #[allow(clippy::too_many_arguments)]
    pub async fn mknod_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        kind: NodeKind,
        mode: u32,
        umask: u32,
        rdev: u64,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        if matches!(last_raw_component(raw_path), None | Some(".") | Some("..")) {
            return Err(FsError::Exists.into());
        }
        let (resolved, trailing_slash) =
            self.walk_path_for(base_dir, raw_path, false, creds).await?;
        if trailing_slash {
            return Err(FsError::IsDirectory.into());
        }
        resolved.require_mutate_dir()?;
        if !resolved.is_private()
            && matches!(kind, NodeKind::CharacterDevice | NodeKind::BlockDevice)
        {
            return Err(FsOpError::PermissionDenied);
        }
        let parent_meta = self
            .check_parent_permission(
                resolved.container_path(),
                creds,
                permissions::MAY_WRITE | permissions::MAY_EXEC,
            )
            .await?;
        let attrs = BtrfsAttributes {
            permissions: sanitize_create_mode(mode, parent_meta, creds),
            uid: creds.user.effective,
            gid: creds.group.effective,
            umask,
        };
        match kind {
            NodeKind::File => {
                if resolved.is_private() {
                    resolved
                        .fs()
                        .open_unix(
                            resolved.fs_path(),
                            OpenFlags::CREATE | OpenFlags::EXCLUSIVE,
                            attrs,
                            now,
                            payer,
                        )
                        .await
                        .map_err(unix_to_op)?;
                } else {
                    resolved
                        .fs()
                        .open(
                            resolved.fs_path(),
                            OpenFlags::CREATE | OpenFlags::EXCLUSIVE,
                            now,
                            payer,
                        )
                        .await?;
                    resolved.fs().apply_created_permissions(
                        resolved.fs_path(),
                        (mode & 0o777) & !umask,
                        now,
                    );
                }
            }
            NodeKind::Fifo => {
                resolved
                    .fs()
                    .create_special(resolved.fs_path(), Special::Fifo, attrs, now)
                    .await
                    .map_err(unix_to_op)?;
            }
            NodeKind::Socket => {
                resolved
                    .fs()
                    .create_special(resolved.fs_path(), Special::Socket, attrs, now)
                    .await
                    .map_err(unix_to_op)?;
            }
            NodeKind::CharacterDevice => {
                let dev = DeviceNumber::decode(rdev as u32);
                resolved
                    .fs()
                    .create_special(resolved.fs_path(), Special::CharDevice(dev), attrs, now)
                    .await
                    .map_err(unix_to_op)?;
            }
            NodeKind::BlockDevice => {
                let dev = DeviceNumber::decode(rdev as u32);
                resolved
                    .fs()
                    .create_special(resolved.fs_path(), Special::BlockDevice(dev), attrs, now)
                    .await
                    .map_err(unix_to_op)?;
            }
            _ => return Err(FsError::Invalid.into()),
        }
        Ok(())
    }

    /// Unlinks a file (`remove_dir == false`) or removes an empty directory
    /// (`remove_dir == true`) at `raw_path` relative to `base_dir`.
    pub async fn unlink_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        remove_dir: bool,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        match last_raw_component(raw_path) {
            None => {
                return Err(if remove_dir {
                    FsError::Busy.into()
                } else {
                    FsError::IsDirectory.into()
                });
            }
            Some(".") => {
                return Err(if remove_dir {
                    FsError::Invalid.into()
                } else {
                    FsError::IsDirectory.into()
                });
            }
            Some("..") => {
                return Err(if remove_dir {
                    FsError::NotEmpty.into()
                } else {
                    FsError::IsDirectory.into()
                });
            }
            Some(_) => {}
        }
        let (resolved, _) = self.walk_path_for(base_dir, raw_path, false, creds).await?;
        if remove_dir {
            if resolved.is_mount_root() {
                return Err(FsError::Busy.into());
            }
            resolved.require_mutate_dir()?;
            let parent_meta = self
                .check_parent_permission(
                    resolved.container_path(),
                    creds,
                    permissions::MAY_WRITE | permissions::MAY_EXEC,
                )
                .await?;
            let meta = resolved.fs().stat(resolved.fs_path()).await?;
            if meta.kind != NodeKind::Directory {
                return Err(FsError::NotDirectory.into());
            }
            if let Some(parent_meta) = parent_meta {
                let child_meta = resolved.inode_meta().await?;
                permissions::check_sticky(creds, parent_meta, child_meta.uid)?;
            }
            Ok(resolved
                .fs()
                .remove_directory(resolved.fs_path(), now, payer)
                .await?)
        } else {
            resolved.require_mutate_dir()?;
            let parent_meta = self
                .check_parent_permission(
                    resolved.container_path(),
                    creds,
                    permissions::MAY_WRITE | permissions::MAY_EXEC,
                )
                .await?;
            let meta = resolved.fs().stat(resolved.fs_path()).await?;
            if meta.kind == NodeKind::Directory {
                return Err(FsError::IsDirectory.into());
            }
            if let Some(parent_meta) = parent_meta {
                let child_meta = resolved.inode_meta().await?;
                permissions::check_sticky(creds, parent_meta, child_meta.uid)?;
            }
            Ok(resolved.fs().unlink(resolved.fs_path(), now, payer).await?)
        }
    }

    /// Renames `old_raw` (relative to `old_base`) to `new_raw` (relative to
    /// `new_base`) within the same container mount.
    #[allow(clippy::too_many_arguments)]
    pub async fn rename_at(
        &self,
        old_base: &str,
        old_raw: &str,
        new_base: &str,
        new_raw: &str,
        mode: RenameMode,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        if matches!(last_raw_component(old_raw), None | Some(".") | Some(".."))
            || matches!(last_raw_component(new_raw), None | Some(".") | Some(".."))
        {
            return Err(FsError::Busy.into());
        }
        let (old_resolved, old_slash) = self.walk_path_for(old_base, old_raw, false, creds).await?;
        let (new_resolved, new_slash) = self.walk_path_for(new_base, new_raw, false, creds).await?;
        let old_meta = old_resolved.fs().stat(old_resolved.fs_path()).await?;
        if (old_slash || new_slash) && old_meta.kind != NodeKind::Directory {
            return Err(FsError::NotDirectory.into());
        }
        if !old_resolved.same_mount(&new_resolved) {
            return Err(FsError::CrossDevice.into());
        }
        if old_resolved.is_mount_root() || new_resolved.is_mount_root() {
            return Err(FsError::Busy.into());
        }
        old_resolved.require_mutate_dir()?;
        new_resolved.require_mutate_dir()?;
        let old_parent_meta = self
            .check_parent_permission(
                old_resolved.container_path(),
                creds,
                permissions::MAY_WRITE | permissions::MAY_EXEC,
            )
            .await?;
        let new_parent_meta = self
            .check_parent_permission(
                new_resolved.container_path(),
                creds,
                permissions::MAY_WRITE | permissions::MAY_EXEC,
            )
            .await?;
        let old_parent = crate::parent_path(old_resolved.container_path());
        let new_parent = crate::parent_path(new_resolved.container_path());
        let dst_exists = new_resolved.fs().stat(new_resolved.fs_path()).await.is_ok();
        if mode == RenameMode::NoReplace && dst_exists {
            // `fs/namei.c` `do_renameat2`: `RENAME_NOREPLACE` fails with
            // `EEXIST` before checking sticky-bit deletion rights on the
            // existing target.
            return Err(FsError::Exists.into());
        }
        if mode == RenameMode::Exchange && !dst_exists {
            return Err(FsError::NoEntry.into());
        }
        if let Some(old_parent_meta) = old_parent_meta {
            let src_unix = old_resolved.inode_meta().await?;
            permissions::check_sticky(creds, old_parent_meta, src_unix.uid)?;
            if src_unix.kind == NodeKind::Directory && old_parent != new_parent {
                old_resolved
                    .check_permission(creds, permissions::MAY_WRITE)
                    .await?;
            }
        }
        if let Some(new_parent_meta) = new_parent_meta
            && dst_exists
        {
            let dst_unix = new_resolved.inode_meta().await?;
            permissions::check_sticky(creds, new_parent_meta, dst_unix.uid)?;
            if mode == RenameMode::Exchange
                && dst_unix.kind == NodeKind::Directory
                && old_parent != new_parent
            {
                // `fs/namei.c` `vfs_rename`: exchanging a directory across
                // parents rewrites its `..` entry, requiring `MAY_WRITE` on it.
                new_resolved
                    .check_permission(creds, permissions::MAY_WRITE)
                    .await?;
            }
        }
        Ok(old_resolved
            .fs()
            .rename(
                old_resolved.fs_path(),
                new_resolved.fs_path(),
                mode,
                now,
                payer,
            )
            .await?)
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
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        if matches!(last_raw_component(new_raw), None | Some(".") | Some("..")) {
            return Err(FsError::Exists.into());
        }
        let old_resolved = if empty_old {
            self.resolve(old_base)?
        } else {
            self.walk_path_for(old_base, old_raw, follow_old, creds)
                .await?
                .0
        };
        let (new_resolved, new_slash) = self.walk_path_for(new_base, new_raw, false, creds).await?;
        if new_slash {
            return match new_resolved.fs().stat(new_resolved.fs_path()).await {
                Ok(_) => Err(FsError::Exists.into()),
                Err(_) => Err(FsError::NoEntry.into()),
            };
        }
        if !old_resolved.same_mount(&new_resolved) {
            return Err(FsError::CrossDevice.into());
        }
        old_resolved.require_read()?;
        new_resolved.require_mutate_dir()?;
        self.check_parent_permission(
            new_resolved.container_path(),
            creds,
            permissions::MAY_WRITE | permissions::MAY_EXEC,
        )
        .await?;
        if old_resolved.is_private() {
            let old_meta = old_resolved.inode_meta().await?;
            if old_meta.kind == NodeKind::Directory {
                return Err(FsOpError::PermissionDenied);
            }
        }
        Ok(old_resolved
            .fs()
            .link(old_resolved.fs_path(), new_resolved.fs_path(), now, payer)
            .await?)
    }

    /// Creates a symbolic link at `raw_path` (relative to `base_dir`) pointing
    /// to `target`.
    pub async fn symlink_at(
        &self,
        target: &str,
        base_dir: &str,
        raw_path: &str,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        if target.is_empty() {
            return Err(FsError::NoEntry.into());
        }
        if matches!(last_raw_component(raw_path), None | Some(".") | Some("..")) {
            return Err(FsError::Exists.into());
        }
        let (resolved, trailing_slash) =
            self.walk_path_for(base_dir, raw_path, false, creds).await?;
        if trailing_slash {
            return match resolved.fs().stat(resolved.fs_path()).await {
                Ok(_) => Err(FsError::Exists.into()),
                Err(_) => Err(FsError::NoEntry.into()),
            };
        }
        resolved.require_mutate_dir()?;
        self.check_parent_permission(
            resolved.container_path(),
            creds,
            permissions::MAY_WRITE | permissions::MAY_EXEC,
        )
        .await?;
        if resolved.is_private() {
            let attrs = BtrfsAttributes {
                permissions: 0o777,
                uid: creds.user.effective,
                gid: creds.group.effective,
                umask: 0,
            };
            resolved
                .fs()
                .symlink_unix(target, resolved.fs_path(), attrs, now, payer)
                .await
                .map_err(unix_to_op)
        } else {
            Ok(resolved
                .fs()
                .symlink(target, resolved.fs_path(), now, payer)
                .await?)
        }
    }

    /// Changes permission bits at `raw_path` (`chmod`/`fchmodat`/`fchmodat2`).
    /// An empty `raw_path` operates directly on `base_dir` without directory
    /// search (`AT_EMPTY_PATH` on `AT_FDCWD`).
    #[allow(clippy::too_many_arguments)]
    pub async fn chmod_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        follow_final: bool,
        mode: u32,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        let resolved = if raw_path.is_empty() {
            self.resolve(base_dir)?
        } else {
            self.walk_path_for(base_dir, raw_path, follow_final, creds)
                .await?
                .0
        };
        self.apply_chmod(&resolved, mode, creds, now, payer).await
    }

    /// Changes permission bits on an already-resolved container path (`fchmod`).
    pub async fn chmod_resolved(
        &self,
        container_path: &str,
        mode: u32,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        let resolved = self.resolve(container_path)?;
        self.apply_chmod(&resolved, mode, creds, now, payer).await
    }

    async fn apply_chmod(
        &self,
        resolved: &ContainerResolved<'_, S>,
        mode: u32,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        resolved.require_write()?;
        if !resolved.is_private() {
            let md = resolved.fs().stat(resolved.fs_path()).await?;
            if md.kind == NodeKind::Symlink {
                return Err(FsError::Unsupported.into());
            }
            if !permissions::inode_owner_or_capable(creds, self.shared_owner.uid) {
                return Err(FsOpError::PermissionDenied);
            }
            return Ok(());
        }
        let meta = resolved.inode_meta().await?;
        let effective = permissions::check_chmod(creds, meta, mode)?;
        resolved
            .fs()
            .set_permissions(resolved.fs_path(), effective, now, payer)
            .await
            .map_err(unix_to_op)
    }

    /// Changes owner/group at `raw_path` (`chown`/`lchown`/`fchownat`). An
    /// empty `raw_path` operates directly on `base_dir` without directory
    /// search (`AT_EMPTY_PATH` on `AT_FDCWD`).
    #[allow(clippy::too_many_arguments)]
    pub async fn chown_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        follow_final: bool,
        uid: Option<u32>,
        gid: Option<u32>,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        let resolved = if raw_path.is_empty() {
            self.resolve(base_dir)?
        } else {
            self.walk_path_for(base_dir, raw_path, follow_final, creds)
                .await?
                .0
        };
        self.apply_chown(&resolved, uid, gid, creds, now, payer)
            .await
    }

    /// Changes owner/group on an already-resolved container path (`fchown`).
    pub async fn chown_resolved(
        &self,
        container_path: &str,
        uid: Option<u32>,
        gid: Option<u32>,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        let resolved = self.resolve(container_path)?;
        self.apply_chown(&resolved, uid, gid, creds, now, payer)
            .await
    }

    async fn apply_chown(
        &self,
        resolved: &ContainerResolved<'_, S>,
        uid: Option<u32>,
        gid: Option<u32>,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        resolved.require_write()?;
        if !resolved.is_private() {
            let md = resolved.fs().stat(resolved.fs_path()).await?;
            let meta = permissions::InodeMeta {
                kind: md.kind,
                mode: 0o644,
                uid: self.shared_owner.uid,
                gid: self.shared_owner.gid,
            };
            let _ = permissions::check_chown(creds, meta, uid, gid)?;
            return Ok(());
        }
        let meta = resolved.inode_meta().await?;
        let plan = permissions::check_chown(creds, meta, uid, gid)?;
        if plan.uid.is_some() || plan.gid.is_some() {
            resolved
                .fs()
                .set_owner(resolved.fs_path(), plan.uid, plan.gid, now, payer)
                .await
                .map_err(unix_to_op)?;
        }
        Ok(())
    }

    /// Reads extended attribute `name` at `raw_path`.
    pub async fn get_xattr_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        follow_final: bool,
        name: &str,
        creds: &Credentials,
    ) -> Result<Vec<u8>, FsOpError> {
        let (resolved, _) = self
            .walk_path_for(base_dir, raw_path, follow_final, creds)
            .await?;
        self.get_xattr_inner(&resolved, name, creds).await
    }

    /// Reads extended attribute `name` on an already-resolved container path.
    pub async fn get_xattr_resolved(
        &self,
        container_path: &str,
        name: &str,
        creds: &Credentials,
    ) -> Result<Vec<u8>, FsOpError> {
        let resolved = self.resolve(container_path)?;
        self.get_xattr_inner(&resolved, name, creds).await
    }

    async fn get_xattr_inner(
        &self,
        resolved: &ContainerResolved<'_, S>,
        name: &str,
        creds: &Credentials,
    ) -> Result<Vec<u8>, FsOpError> {
        resolved.require_read()?;
        if !resolved.is_private() {
            let _ = resolved.fs().stat(resolved.fs_path()).await?;
            return Err(FsError::Unsupported.into());
        }
        let meta = resolved.inode_meta().await?;
        let acl = resolved.access_acl().await;
        permissions::check_xattr_permission(creds, meta, acl.as_deref(), name, false)?;
        let value = resolved
            .fs()
            .xattr(resolved.fs_path(), name)
            .await
            .map_err(unix_to_op)?
            .ok_or(FsOpError::NoData)?;
        Ok(value.to_vec())
    }

    /// Sets extended attribute `name` at `raw_path`.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_xattr_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        follow_final: bool,
        name: &str,
        value: &[u8],
        mode: LinuxXattrSetMode,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        let (resolved, _) = self
            .walk_path_for(base_dir, raw_path, follow_final, creds)
            .await?;
        self.set_xattr_inner(&resolved, name, value, mode, creds, now, payer)
            .await
    }

    /// Sets extended attribute `name` on an already-resolved container path.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_xattr_resolved(
        &self,
        container_path: &str,
        name: &str,
        value: &[u8],
        mode: LinuxXattrSetMode,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        let resolved = self.resolve(container_path)?;
        self.set_xattr_inner(&resolved, name, value, mode, creds, now, payer)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn set_xattr_inner(
        &self,
        resolved: &ContainerResolved<'_, S>,
        name: &str,
        value: &[u8],
        mode: LinuxXattrSetMode,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        resolved.require_write()?;
        if !resolved.is_private() {
            let _ = resolved.fs().stat(resolved.fs_path()).await?;
            return Err(FsError::Unsupported.into());
        }
        let meta = resolved.inode_meta().await?;
        let acl = resolved.access_acl().await;
        let ns = permissions::check_xattr_permission(creds, meta, acl.as_deref(), name, true)?;
        if ns == permissions::XattrNamespace::SecurityCapability {
            permissions::parse_vfs_cap_data(value)?;
        }
        resolved
            .fs()
            .set_xattr(
                resolved.fs_path(),
                name,
                Bytes::copy_from_slice(value),
                to_vfs_xattr_mode(mode),
                now,
                payer,
            )
            .await
            .map_err(unix_to_op)?;
        // `fs/posix_acl.c` `posix_acl_update_mode`: setting an access ACL
        // clears `S_ISGID` when the caller is neither in the file's group nor
        // holds `CAP_FSETID`.
        if ns == permissions::XattrNamespace::PosixAclAccess
            && !creds.in_group(meta.gid)
            && !creds.capabilities.has_effective(CAP_FSETID)
        {
            let refreshed = resolved.inode_meta().await?;
            if (refreshed.mode & permissions::S_ISGID) != 0 {
                resolved
                    .fs()
                    .set_permissions(
                        resolved.fs_path(),
                        refreshed.mode & !permissions::S_ISGID,
                        now,
                        payer,
                    )
                    .await
                    .map_err(unix_to_op)?;
            }
        }
        Ok(())
    }

    /// Lists extended attribute names at `raw_path`, omitting `trusted.*`
    /// unless `creds` holds `CAP_SYS_ADMIN`.
    pub async fn list_xattrs_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        follow_final: bool,
        creds: &Credentials,
    ) -> Result<Vec<String>, FsOpError> {
        let (resolved, _) = self
            .walk_path_for(base_dir, raw_path, follow_final, creds)
            .await?;
        self.list_xattrs_inner(&resolved, creds).await
    }

    /// Lists extended attribute names on an already-resolved container path.
    pub async fn list_xattrs_resolved(
        &self,
        container_path: &str,
        creds: &Credentials,
    ) -> Result<Vec<String>, FsOpError> {
        let resolved = self.resolve(container_path)?;
        self.list_xattrs_inner(&resolved, creds).await
    }

    async fn list_xattrs_inner(
        &self,
        resolved: &ContainerResolved<'_, S>,
        creds: &Credentials,
    ) -> Result<Vec<String>, FsOpError> {
        resolved.require_read()?;
        if !resolved.is_private() {
            let _ = resolved.fs().stat(resolved.fs_path()).await?;
            return Ok(Vec::new());
        }
        let mut names = resolved
            .fs()
            .list_xattrs(resolved.fs_path())
            .await
            .map_err(unix_to_op)?;
        names.retain(|name| permissions::xattr_visible_in_list(creds, name));
        Ok(names)
    }

    /// Removes extended attribute `name` at `raw_path`.
    #[allow(clippy::too_many_arguments)]
    pub async fn remove_xattr_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        follow_final: bool,
        name: &str,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        let (resolved, _) = self
            .walk_path_for(base_dir, raw_path, follow_final, creds)
            .await?;
        self.remove_xattr_inner(&resolved, name, creds, now, payer)
            .await
    }

    /// Removes extended attribute `name` on an already-resolved container path.
    pub async fn remove_xattr_resolved(
        &self,
        container_path: &str,
        name: &str,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        let resolved = self.resolve(container_path)?;
        self.remove_xattr_inner(&resolved, name, creds, now, payer)
            .await
    }

    async fn remove_xattr_inner(
        &self,
        resolved: &ContainerResolved<'_, S>,
        name: &str,
        creds: &Credentials,
        now: u64,
        payer: &crate::StoragePayer,
    ) -> Result<(), FsOpError> {
        resolved.require_write()?;
        if !resolved.is_private() {
            let _ = resolved.fs().stat(resolved.fs_path()).await?;
            return Err(FsError::Unsupported.into());
        }
        let meta = resolved.inode_meta().await?;
        let acl = resolved.access_acl().await;
        permissions::check_xattr_permission(creds, meta, acl.as_deref(), name, true)?;
        resolved
            .fs()
            .remove_xattr(resolved.fs_path(), name, now, payer)
            .await
            .map_err(unix_to_op)
    }

    /// Resolves an executable at `raw_path`, checks execute permission (within
    /// mount rights and private-mount DAC/ACL rules), and computes the
    /// post-`execve` [`Credentials`] (`fs/exec.c` `bprm_fill_uid` +
    /// `security/commoncap.c` `cap_bprm_creds_from_file`), bounded by
    /// `authority_cap_ceiling`, the mount's `NO_SUID` flag, and
    /// `creds.no_new_privs`.
    pub async fn exec_credentials_at(
        &self,
        base_dir: &str,
        raw_path: &str,
        creds: &Credentials,
        authority_cap_ceiling: u64,
    ) -> Result<Credentials, FsOpError> {
        let (resolved, _) = self.walk_path_for(base_dir, raw_path, true, creds).await?;
        resolved
            .exec_credentials(creds, authority_cap_ceiling)
            .await
    }

    /// Lists entries in `container_path` along with `(self_inode, parent_inode)`.
    pub async fn list_with_inodes(
        &self,
        container_path: &str,
    ) -> Result<(u64, u64, Vec<DirEntry>), FsOpError> {
        let self_info = self.stat(container_path).await?;
        if self_info.metadata.kind != NodeKind::Directory {
            return Err(FsError::NotDirectory.into());
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

/// Point-in-time snapshot of one mount inside a [`LinuxContainer`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerMountSnapshot {
    pub target: String,
    pub kind: &'static str,
    pub sharing: &'static str,
    pub read_only: bool,
    pub overlay_pages: u64,
}

/// Point-in-time telemetry snapshot of a live [`LinuxContainer`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxContainerSnapshot {
    pub id: u64,
    pub hostname: String,
    pub domainname: String,
    pub live_processes: u32,
    pub allocated_pids: u32,
    pub live_threads: u32,
    pub overlay_pages: u64,
    pub mounts: Vec<ContainerMountSnapshot>,
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

        let mut default_credentials = config.credentials;
        default_credentials
            .capabilities
            .clamp(authority_cap_ceiling_for(&authority));

        Ok(Self {
            id,
            authority,
            filesystem: ContainerFilesystem {
                mounts,
                shared_owner: config.shared_owner,
            },
            shared_owner: config.shared_owner,
            default_credentials,
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
        let mut default_credentials = Credentials::root();
        default_credentials
            .capabilities
            .clamp(authority_cap_ceiling_for(&authority));
        Self {
            id,
            authority,
            filesystem: ContainerFilesystem {
                mounts,
                shared_owner,
            },
            shared_owner,
            default_credentials,
            uts: spin::Mutex::new(ContainerUts {
                hostname: UtsField::UNSET,
                domainname: UtsField::UNSET,
            }),
            pids: PidNamespace::new(),
            futex: FutexTable::new(),
        }
    }

    /// Creates a single-binary ephemeral Linux container whose `"/"` is a
    /// fresh private `UserMemoryPool`-backed [`OverlayFs`] over a lock-free
    /// pinned read-only `lower` directory (`HeldPath<S>`), with the child's
    /// granted Helios host directories (`guest_name != "/"`) bind-mounted on
    /// top for direct persistent host I/O.
    ///
    /// Performs zero disk writes on creation or teardown and takes no
    /// exclusive claim on `lower`, allowing unrestricted concurrent containers
    /// over the same read-only image tree.
    pub fn ephemeral_with_overlay(
        id: ContainerId,
        authority: ProcessAuthority,
        namespace: &Namespace<S>,
        lower: HeldPath<S>,
        credentials: Option<Credentials>,
    ) -> Result<Self, ContainerError> {
        let pinned = PinnedLower::from_held(lower).map_err(|error| ContainerError::Filesystem {
            path: String::from("/"),
            error,
        })?;
        let upper = MemoryFs::with_budget(
            namespace.table().allocate_device(),
            namespace.table().memory_storage(),
        );
        let overlay = OverlayFs::new(upper, pinned);
        let overlay_grant = MountGrant {
            rights: FileSystemRights::READ | FileSystemRights::WRITE,
            sharing: MountSharing::Private,
        };
        let root_mount = ContainerMount {
            target: String::from("/"),
            backing: HeldPath::from_overlay(overlay, overlay_grant),
            grant: overlay_grant,
            authority_rights: DirectoryAuthorityRights::all(),
            _private_claim: None,
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
        let mut default_credentials = credentials.unwrap_or_else(Credentials::root);
        default_credentials
            .capabilities
            .clamp(authority_cap_ceiling_for(&authority));
        Ok(Self {
            id,
            authority,
            filesystem: ContainerFilesystem {
                mounts,
                shared_owner,
            },
            shared_owner,
            default_credentials,
            uts: spin::Mutex::new(ContainerUts {
                hostname: UtsField::UNSET,
                domainname: UtsField::UNSET,
            }),
            pids: PidNamespace::new(),
            futex: FutexTable::new(),
        })
    }

    pub const fn id(&self) -> ContainerId {
        self.id
    }

    /// The authority ceiling of every process running in this container.
    pub fn authority(&self) -> &ProcessAuthority {
        &self.authority
    }

    /// Linux capability mask bounded by this container's [`ProcessAuthority`].
    /// `uid 0`, setuid binaries, and file capabilities inside this container
    /// never exceed this ceiling.
    pub fn authority_cap_ceiling(&self) -> u64 {
        authority_cap_ceiling_for(&self.authority)
    }

    /// Clamps `creds`' capability sets to this container's
    /// [`Self::authority_cap_ceiling`], ensuring neither initial process
    /// credentials nor overrides exceed the container's [`ProcessAuthority`].
    pub fn clamp_credentials(&self, creds: &mut Credentials) {
        creds.capabilities.clamp(self.authority_cap_ceiling());
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

    /// Returns a point-in-time telemetry snapshot of this container's mounts,
    /// PID namespace counts, UTS names, and overlay page occupancy.
    pub fn telemetry(&self) -> LinuxContainerSnapshot {
        let uts = self.uts.lock();
        let hostname = core::str::from_utf8(uts.hostname.as_bytes())
            .unwrap_or("")
            .to_owned();
        let domainname = core::str::from_utf8(uts.domainname.as_bytes())
            .unwrap_or("")
            .to_owned();
        drop(uts);
        let pids = self.pids.telemetry();
        let mut total_overlay_pages = 0u64;
        let mut mounts = Vec::with_capacity(self.filesystem.mounts.len());
        for mount in &self.filesystem.mounts {
            let fs = mount.backing.resolved().fs();
            let overlay_pages = fs.overlay_pages();
            total_overlay_pages = total_overlay_pages.saturating_add(overlay_pages);
            mounts.push(ContainerMountSnapshot {
                target: mount.target.clone(),
                kind: fs.kind_name(),
                sharing: match mount.grant.sharing {
                    MountSharing::Private => "private",
                    MountSharing::Shared => "shared",
                },
                read_only: mount.grant.flags().contains(MountFlags::READ_ONLY),
                overlay_pages,
            });
        }
        LinuxContainerSnapshot {
            id: self.id.raw(),
            hostname,
            domainname,
            live_processes: pids.live_processes,
            allocated_pids: pids.allocated_pids,
            live_threads: pids.live_threads,
            overlay_pages: total_overlay_pages,
            mounts,
        }
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
    if spec.sharing == ContainerMountSharing::EphemeralOverlay {
        // An ephemeral overlay never mutates its read-only lower directory, so
        // the caller only needs READ (plus EXECUTE when requested) on the lower
        // path; writes stay in the container's private UserMemoryPool upper.
        let lower_rights =
            spec.rights & (DirectoryAuthorityRights::READ | DirectoryAuthorityRights::EXECUTE);
        let preopen = caller_authority
            .derive_directory_preopen(&spec.source_path, &spec.target_path, lower_rights)
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
        let metadata = resolved.fs().stat(resolved.path()).await.map_err(|error| {
            ContainerError::Filesystem {
                path: source.to_owned(),
                error,
            }
        })?;
        if metadata.kind != NodeKind::Directory {
            return Err(ContainerError::NotADirectory {
                path: source.to_owned(),
            });
        }
        let pinned = PinnedLower::from_held(resolved.held()).map_err(|error| {
            ContainerError::Filesystem {
                path: source.to_owned(),
                error,
            }
        })?;
        let upper = MemoryFs::with_budget(
            caller_namespace.table().allocate_device(),
            caller_namespace.table().memory_storage(),
        );
        let overlay = OverlayFs::new(upper, pinned);
        let grant = MountGrant {
            rights: effective_fs_rights(
                spec.rights,
                FileSystemRights::READ | FileSystemRights::WRITE,
            ),
            sharing: MountSharing::Private,
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
        return Ok(ContainerMount {
            target: spec.target_path.clone(),
            backing: HeldPath::from_overlay(overlay, grant),
            grant,
            authority_rights: spec.rights,
            _private_claim: None,
        });
    }

    let requested_sharing = match spec.sharing {
        ContainerMountSharing::Private => MountSharing::Private,
        ContainerMountSharing::Shared => MountSharing::Shared,
        ContainerMountSharing::EphemeralOverlay => unreachable!("handled above"),
    };

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
    if backing_grant.sharing != requested_sharing {
        return Err(ContainerError::MountSharingMismatch {
            path: source.to_owned(),
            actual: backing_grant.sharing,
            requested: requested_sharing,
        });
    }
    let private_claim = if requested_sharing == MountSharing::Private {
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
                    requested: requested_sharing,
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
        sharing: requested_sharing,
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
            .open(
                path,
                helios_hal::fs::OpenFlags::CREATE,
                0,
                &crate::StoragePayer::for_test(),
            )
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
                    sharing: ContainerMountSharing::Private,
                },
                mounts: vec![ContainerMountSpec {
                    source_path: String::from("/shared"),
                    target_path: String::from("/data"),
                    rights: RX,
                    sharing: ContainerMountSharing::Shared,
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
                    sharing: ContainerMountSharing::Private,
                },
                mounts: vec![ContainerMountSpec {
                    source_path: String::from("/shared"),
                    target_path: String::from("/shared"),
                    rights: RX,
                    sharing: ContainerMountSharing::Shared,
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
                    sharing: ContainerMountSharing::Private,
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
                    sharing: ContainerMountSharing::Private,
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
                    sharing: ContainerMountSharing::Private,
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
                    sharing: ContainerMountSharing::Shared,
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
                    sharing: ContainerMountSharing::Shared,
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
                    sharing: ContainerMountSharing::Private,
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
                    sharing: ContainerMountSharing::Shared,
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
                    sharing: ContainerMountSharing::Private,
                },
                mounts: vec![ContainerMountSpec {
                    source_path: String::from("/ro"),
                    target_path: String::from("/ro"),
                    rights: RX,
                    sharing: ContainerMountSharing::Shared,
                }],
                shared_owner: SharedOwner { uid: 0, gid: 0 },
                credentials: Credentials::root(),
                hostname: UtsField::UNSET,
                domainname: UtsField::UNSET,
            },
        ))
        .expect("container creates");
        let fs = container.filesystem();

        let root = Credentials::root();
        let payer = crate::StoragePayer::for_test();
        block_on(async {
            // Component walker catches missing and non-directory intermediate components.
            assert!(matches!(
                fs.stat_at("/", "nonexistent/..", true, &root).await,
                Err(FsOpError::Fs(FsError::NoEntry))
            ));
            assert!(matches!(
                fs.stat_at("/", "alpha/..", true, &root).await,
                Err(FsOpError::Fs(FsError::NotDirectory))
            ));
            assert!(matches!(
                fs.stat_at("/", "alpha/", true, &root).await,
                Err(FsOpError::Fs(FsError::NotDirectory))
            ));

            // Intermediate symlink expands before `..`, and symlink loop returns `Loop`.
            fs.mkdir_at("/", "sub", 0o755, 0, &root, 1, &payer)
                .await
                .unwrap();
            fs.symlink_at("sub", "/", "sym_sub", &root, 1, &payer)
                .await
                .unwrap();
            let (_, resolved) = fs
                .stat_at("/", "sym_sub/../alpha", true, &root)
                .await
                .unwrap();
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
                umask: 0,
            };
            let (_, sym_path, _) = fs
                .open_at("/", "sym_sub", path_nofollow, &root, 1, &payer)
                .await
                .unwrap();
            assert_eq!(sym_path, "/sym_sub");
            assert_eq!(fs.read_link_resolved(&sym_path).await.unwrap(), "sub");

            fs.symlink_at("loop_b", "/", "loop_a", &root, 1, &payer)
                .await
                .unwrap();
            fs.symlink_at("loop_a", "/", "loop_b", &root, 1, &payer)
                .await
                .unwrap();
            assert!(matches!(
                fs.stat_at("/", "loop_a", true, &root).await,
                Err(FsOpError::Fs(FsError::Loop))
            ));

            // Dangling symlink with O_CREAT | O_EXCL fails with Exists.
            fs.symlink_at("missing_target", "/", "dangling", &root, 1, &payer)
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
                umask: 0,
            };
            assert!(matches!(
                fs.open_at("/", "dangling", excl, &root, 1, &payer).await,
                Err(FsOpError::Fs(FsError::Exists))
            ));

            // Cross-mount rename and link fail with CrossDevice, and read-only mount fails with ReadOnly.
            assert!(matches!(
                fs.rename_at(
                    "/",
                    "alpha",
                    "/",
                    "/ro/moved",
                    RenameMode::Replace,
                    &root,
                    1,
                    &payer
                )
                .await,
                Err(FsOpError::Fs(FsError::CrossDevice))
            ));
            assert!(matches!(
                fs.link_at(
                    "/",
                    "alpha",
                    "/",
                    "/ro/linked",
                    false,
                    false,
                    &root,
                    1,
                    &payer
                )
                .await,
                Err(FsOpError::Fs(FsError::CrossDevice))
            ));
            assert!(matches!(
                fs.write_at("/ro/fixed", WritePosition::At(0), b"x", &root, 1, &payer)
                    .await,
                Err(FsOpError::Fs(FsError::ReadOnly))
            ));
            assert!(matches!(
                fs.unlink_at("/", "/ro/fixed", false, &root, 1, &payer)
                    .await,
                Err(FsOpError::Fs(FsError::ReadOnly))
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

    #[test]
    fn ephemeral_overlay_containers_share_readonly_lower_with_isolated_upper_and_direct_host_mounts()
     {
        let host_ns = test_namespace();
        let ro = FileSystemRights::READ;
        let rw = FileSystemRights::READ | FileSystemRights::WRITE;

        let lower_img = mount_memory(&host_ns, "/root-a", ro, MountSharing::Shared);
        let host_shared = mount_memory(&host_ns, "/shared", rw, MountSharing::Shared);
        let payer = crate::StoragePayer::for_test();
        block_on(async {
            create_file(&lower_img, "conf", b"lower-v1").await;
            create_file(&lower_img, "dropme", b"delete-in-a").await;
            lower_img
                .create_directory(FsPath::new("sub").unwrap(), 1, &payer)
                .await
                .unwrap();
            create_file(&lower_img, "sub/old", b"hidden-by-opaque").await;
            lower_img
                .set_owner(FsPath::new("conf").unwrap(), Some(100), Some(101), 2)
                .unwrap();
            lower_img
                .set_permissions(FsPath::new("conf").unwrap(), 0o4755, 3)
                .unwrap();
            lower_img
                .set_xattr_unix(
                    FsPath::new("conf").unwrap(),
                    "security.capability",
                    Bytes::from_static(b"cap-v2"),
                    crate::vfs::XattrSetMode::Any,
                    4,
                )
                .unwrap();
        });

        // Caller holds ONLY READ | EXECUTE on the read-only lower image (no WRITE!)
        // and READ | WRITE | MUTATE_DIRECTORY on the host share.
        let mut narrow_caller = ProcessAuthority::empty();
        narrow_caller
            .insert_directory_preopen(DirectoryPreopen::new("/root-a", "/root-a", RX).unwrap());
        narrow_caller.insert_directory_preopen(
            DirectoryPreopen::new(
                "/shared",
                "/shared",
                DirectoryAuthorityRights::READ
                    | DirectoryAuthorityRights::WRITE
                    | DirectoryAuthorityRights::MUTATE_DIRECTORY,
            )
            .unwrap(),
        );

        let make_config = |host_name: &str| ContainerConfig {
            root: ContainerMountSpec {
                source_path: String::from("/root-a"),
                target_path: String::from("/"),
                rights: RWX,
                sharing: ContainerMountSharing::EphemeralOverlay,
            },
            mounts: vec![ContainerMountSpec {
                source_path: String::from("/shared"),
                target_path: String::from("/work"),
                rights: DirectoryAuthorityRights::READ
                    | DirectoryAuthorityRights::WRITE
                    | DirectoryAuthorityRights::MUTATE_DIRECTORY,
                sharing: ContainerMountSharing::Shared,
            }],
            shared_owner: SharedOwner {
                uid: 1000,
                gid: 1000,
            },
            credentials: Credentials::root(),
            hostname: UtsField::from_configured(host_name).unwrap(),
            domainname: UtsField::UNSET,
        };

        // Two containers concurrently mount the exact same read-only lower tree.
        let container_a = block_on(LinuxContainer::create(
            ContainerId::new(NonZeroU64::new(501).unwrap()),
            &narrow_caller,
            &host_ns,
            ProcessAuthority::empty(),
            make_config("overlay-a"),
        ))
        .expect("container A creates over shared RO lower");
        let container_b = block_on(LinuxContainer::create(
            ContainerId::new(NonZeroU64::new(502).unwrap()),
            &narrow_caller,
            &host_ns,
            ProcessAuthority::empty(),
            make_config("overlay-b"),
        ))
        .expect("container B creates concurrently over same RO lower");

        let root_creds = Credentials::root();
        block_on(async {
            // 1. Container A sees full Private Unix metadata & honours exec privileges.
            let st_a = container_a.filesystem().stat("/conf").await.unwrap();
            assert_eq!(st_a.unix.permissions, 0o4755);
            assert_eq!(st_a.unix.uid, 100);
            assert_eq!(st_a.unix.gid, 101);
            assert!(st_a.flags.honours_exec_privileges());

            // 2. Container A mutates its upper: modifies /conf, unlinks /dropme,
            //    replaces /sub with an opaque dir, and writes a new suid + xattr file.
            let trunc_open = OpenRequest {
                read: true,
                write: true,
                create: false,
                exclusive: false,
                truncate: true,
                directory: false,
                nofollow: false,
                path_only: false,
                append: false,
                sync: false,
                dsync: false,
                mode: 0o644,
                umask: 0,
            };
            container_a
                .filesystem()
                .open_at("/", "/conf", trunc_open, &root_creds, 10, &payer)
                .await
                .unwrap();
            let landed = container_a
                .filesystem()
                .write_at(
                    "/conf",
                    WritePosition::At(0),
                    b"upper-a",
                    &root_creds,
                    11,
                    &payer,
                )
                .await
                .unwrap();
            assert_eq!(landed.len, 7);

            container_a
                .filesystem()
                .unlink_at("/", "/dropme", false, &root_creds, 12, &payer)
                .await
                .unwrap();
            container_a
                .filesystem()
                .unlink_at("/", "/sub/old", false, &root_creds, 13, &payer)
                .await
                .unwrap();
            container_a
                .filesystem()
                .unlink_at("/", "/sub", true, &root_creds, 14, &payer)
                .await
                .unwrap();
            container_a
                .filesystem()
                .mkdir_at("/", "/sub", 0o755, 0, &root_creds, 15, &payer)
                .await
                .unwrap();

            // 3. Container A writes persistent data through direct host bind mount `/work`.
            let create_open = OpenRequest {
                create: true,
                ..trunc_open
            };
            container_a
                .filesystem()
                .open_at(
                    "/",
                    "/work/persisted.txt",
                    create_open,
                    &root_creds,
                    16,
                    &payer,
                )
                .await
                .unwrap();
            let cjk = "日本語 한국어 中文".as_bytes();
            container_a
                .filesystem()
                .write_at(
                    "/work/persisted.txt",
                    WritePosition::At(0),
                    cjk,
                    &root_creds,
                    17,
                    &payer,
                )
                .await
                .unwrap();

            // 4. Container B is completely isolated from A's upper mutations,
            //    yet sees A's direct host write on `/work/persisted.txt` immediately.
            assert!(matches!(
                container_a.filesystem().stat("/dropme").await,
                Err(FsError::NoEntry)
            ));
            assert!(matches!(
                container_a.filesystem().stat("/sub/old").await,
                Err(FsError::NoEntry)
            ));
            assert!(container_b.filesystem().stat("/dropme").await.is_ok());
            assert!(container_b.filesystem().stat("/sub/old").await.is_ok());
            let b_conf = container_b
                .filesystem()
                .read_executable("/conf")
                .await
                .unwrap();
            assert!(
                matches!(b_conf, FileContents::Written(bytes) if bytes.as_ref() == b"lower-v1")
            );
            let b_read = container_b
                .filesystem()
                .read_at("/work/persisted.txt", 0, 64)
                .await
                .unwrap();
            assert_eq!(b_read.as_ref(), cjk);

            // 5. Lower image was never written to.
            let lower_conf = lower_img
                .read_at(FsPath::new("conf").unwrap(), 0, 64)
                .await
                .unwrap();
            assert_eq!(lower_conf.as_ref(), b"lower-v1");
            assert!(lower_img.stat(FsPath::new("dropme").unwrap()).await.is_ok());
            assert!(
                lower_img
                    .stat(FsPath::new("sub/old").unwrap())
                    .await
                    .is_ok()
            );

            // 6. Unmounting `/root-a` is refused while overlays hold it, and succeeds
            //    once both containers drop; `/shared/persisted.txt` persists on host.
            let root_auth = ProcessAuthority::root();
            assert!(
                host_ns
                    .unmount(&root_auth.derive_unmount_cap("/root-a").unwrap())
                    .await
                    .is_err()
            );
            drop(container_a);
            assert!(
                host_ns
                    .unmount(&root_auth.derive_unmount_cap("/root-a").unwrap())
                    .await
                    .is_err()
            );
            drop(container_b);
            host_ns
                .unmount(&root_auth.derive_unmount_cap("/root-a").unwrap())
                .await
                .expect("unmount succeeds once overlays drop");
            let host_persisted = host_shared
                .read_at(FsPath::new("persisted.txt").unwrap(), 0, 64)
                .await
                .unwrap();
            assert_eq!(host_persisted.as_ref(), cjk);
        });
    }
}

#[cfg(test)]
mod private_btrfs_tests {
    extern crate std;

    use super::*;
    use alloc::boxed::Box;
    use alloc::collections::BTreeMap;
    use core::ops::ControlFlow;
    use std::io::{Read, Seek, SeekFrom};

    use ferrosys::btrfs::{FormatOptions, format_to};
    use ferrosys::{Metadata as FerrosysMetadata, Timestamp as FerrosysTimestamp, TreeBuilder};
    use futures_lite::future::block_on;
    use helios_hal::fs::DeviceId;
    use helios_hal::vmm::PageFlags;
    use helios_linux::abi::{Abi, Operation};
    use helios_linux::syscall::{
        CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER, CAP_FSETID, CAP_MKNOD,
        CAP_NET_ADMIN, CAP_NET_BIND_SERVICE, CAP_SETFCAP, CAP_SYS_ADMIN, CAP_SYS_TIME, Call, Clock,
        Denied, DirListEntry, FileAccess, FileStat, Filesystem, LinkOptions, MapError, MemoryFault,
        MemoryTotals, Process, Region, Resources, SpawnError, SpawnedThread, Start, Stdio, Stream,
        SyscallOutcome, System, Thread, Tty, UserMemory, VirtualMemory, WriteError,
        XattrSetMode as LinuxXattrSetMode, dispatch,
    };
    use helios_unix::NoNetwork;

    use crate::io::{MemoryDisk, cache_over};
    use crate::test_support::{TestCpu, UnsupportedHostFileSystem, test_root_entropy, test_timer};
    use crate::vfs::{
        BOOT_DEVICE, BtrfsFs, BtrfsWriteOptions, CommitPolicy, MemoryFs, MountTable, MountedFs,
    };
    use crate::{BootFs, EmbeddedBootDirectory, EmbeddedBootFs};

    const FORMATTED_BYTES: usize = 128 << 20;

    #[derive(Clone, Copy)]
    struct BtrfsTestStorage;
    impl Storage for BtrfsTestStorage {
        type HostShare = UnsupportedHostFileSystem;
        type Disk = MemoryDisk;
    }

    const BTRFS_TEST_BOOT: EmbeddedBootFs = EmbeddedBootFs::new(
        &[
            EmbeddedBootDirectory::new("priv", 0),
            EmbeddedBootDirectory::new("shared", 0),
            EmbeddedBootDirectory::new("ro_priv", 0),
        ],
        &[],
    );

    const RWX: DirectoryAuthorityRights = DirectoryAuthorityRights::READ
        .union(DirectoryAuthorityRights::WRITE)
        .union(DirectoryAuthorityRights::MUTATE_DIRECTORY)
        .union(DirectoryAuthorityRights::EXECUTE);
    const RX: DirectoryAuthorityRights =
        DirectoryAuthorityRights::READ.union(DirectoryAuthorityRights::EXECUTE);

    fn format_btrfs_disk(seed: u8, read_only: bool) -> crate::BlockCache<MemoryDisk> {
        let time = FerrosysTimestamp::from_secs(1_700_000_000);
        let tree = TreeBuilder::new().root(FerrosysMetadata::new(0o755, time));
        let mut image = tempfile::tempfile().expect("temp btrfs image");
        image.set_len(FORMATTED_BYTES as u64).expect("set_len");
        format_to(
            &mut image,
            tree,
            FORMATTED_BYTES as u64,
            FormatOptions::new([seed; 16], time),
        )
        .expect("format btrfs");
        image.seek(SeekFrom::Start(0)).expect("rewind");
        let mut bytes = Vec::new();
        image.read_to_end(&mut bytes).expect("read image");
        let disk = if read_only {
            MemoryDisk::holding("btrfs-priv-ro", &bytes, false)
        } else {
            MemoryDisk::holding_writable("btrfs-priv-rw", &bytes)
        };
        cache_over(&disk, 256, 1)
    }

    fn write_options() -> BtrfsWriteOptions {
        BtrfsWriteOptions {
            entropy: test_root_entropy(),
            concurrency: core::num::NonZeroUsize::new(2).unwrap(),
            compress: None,
            commit: Some(CommitPolicy::for_machine(1 << 30)),
            max_inline: None,
            now: 1_700_000_000_000_000_000,
        }
    }

    fn encode_acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + entries.len() * 8);
        out.extend_from_slice(&2u32.to_le_bytes());
        for &(tag, perm, id) in entries {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&perm.to_le_bytes());
            out.extend_from_slice(&id.to_le_bytes());
        }
        out
    }

    fn encode_vfs_cap_v2(effective: bool, permitted: u64, inheritable: u64) -> [u8; 20] {
        let mut out = [0u8; 20];
        let magic = 0x0200_0000u32 | if effective { 1 } else { 0 };
        out[0..4].copy_from_slice(&magic.to_le_bytes());
        out[4..8].copy_from_slice(&(permitted as u32).to_le_bytes());
        out[8..12].copy_from_slice(&(inheritable as u32).to_le_bytes());
        out[12..16].copy_from_slice(&((permitted >> 32) as u32).to_le_bytes());
        out[16..20].copy_from_slice(&((inheritable >> 32) as u32).to_le_bytes());
        out
    }

    // Minimal Linux syscall harness wired directly to a real LinuxContainer.
    #[derive(Clone)]
    struct TestFile {
        path: String,
        kind: NodeKind,
        access: FileAccess,
    }

    struct TestRes;
    impl Resources for TestRes {
        type File = TestFile;
        type Network = NoNetwork;
        type Data = u64;
    }

    #[derive(Default)]
    struct TestMem(BTreeMap<u64, u8>);
    impl TestMem {
        fn write_bytes(&mut self, addr: u64, bytes: &[u8]) {
            for (i, &b) in bytes.iter().enumerate() {
                self.0.insert(addr + i as u64, b);
            }
        }
        fn write_cstr(&mut self, addr: u64, s: &str) {
            self.write_bytes(addr, s.as_bytes());
            self.0.insert(addr + s.len() as u64, 0);
        }
        fn read_bytes(&self, addr: u64, len: usize) -> Vec<u8> {
            (0..len)
                .map(|i| *self.0.get(&(addr + i as u64)).unwrap_or(&0))
                .collect()
        }
    }
    impl UserMemory for TestMem {
        fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault> {
            for (i, slot) in output.iter_mut().enumerate() {
                *slot = *self.0.get(&(address + i as u64)).ok_or(MemoryFault)?;
            }
            Ok(())
        }
        fn check_writable(&self, address: u64, length: usize) -> Result<(), MemoryFault> {
            if address == 0 && length > 0 {
                return Err(MemoryFault);
            }
            Ok(())
        }
        fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryFault> {
            if address == 0 {
                return Err(MemoryFault);
            }
            self.write_bytes(address, bytes);
            Ok(())
        }
        fn atomic_load_u32(&self, address: u64) -> Result<u32, MemoryFault> {
            let mut raw = [0u8; 4];
            self.read(address, &mut raw)?;
            Ok(u32::from_le_bytes(raw))
        }
        fn atomic_store_u32(&mut self, address: u64, value: u32) -> Result<(), MemoryFault> {
            self.write(address, &value.to_le_bytes())
        }
        fn atomic_compare_exchange_u32(
            &mut self,
            address: u64,
            expected: u32,
            desired: u32,
        ) -> Result<Result<u32, u32>, MemoryFault> {
            let cur = self.atomic_load_u32(address)?;
            if cur == expected {
                self.atomic_store_u32(address, desired)?;
                Ok(Ok(cur))
            } else {
                Ok(Err(cur))
            }
        }
    }
    impl VirtualMemory for TestMem {
        fn lowest_address(&self) -> u64 {
            0x1000
        }
        fn map_anywhere(&mut self, _: u64, _: u64, _: PageFlags) -> Result<u64, MapError> {
            Err(MapError::OutOfMemory)
        }
        fn map_at(&mut self, _: u64, _: u64, _: PageFlags) -> Result<(), MapError> {
            Err(MapError::OutOfMemory)
        }
        fn unmap(&mut self, _: u64, _: u64) {}
        fn protect(&mut self, _: u64, _: u64, _: PageFlags) -> Result<(), MapError> {
            Ok(())
        }
        fn discard(&mut self, _: u64, _: u64) {}
        fn remap(&mut self, _: u64, _: u64, _: u64, _: u64) -> Result<(), MapError> {
            Err(MapError::OutOfMemory)
        }
        fn region(&self, _: u64, _: u64) -> Option<Region> {
            None
        }
        fn free_range(&self, _: u64, _: u64) -> Option<u64> {
            None
        }
    }

    struct TestThread;
    impl Thread<TestRes> for TestThread {
        fn thread_pointer(&self) -> u64 {
            0
        }
        fn set_thread_pointer(&mut self, _: u64) -> Result<(), Denied> {
            Ok(())
        }
        fn spawn_thread(
            &mut self,
            _: Process<TestRes>,
            _: SpawnedThread,
        ) -> Result<(), SpawnError> {
            Err(SpawnError::Busy)
        }
    }

    struct ContainerHost<'a> {
        container: &'a LinuxContainer<BtrfsTestStorage>,
        now: u64,
    }

    fn info_to_stat(info: &ContainerNodeInfo) -> FileStat {
        FileStat {
            dev: info.metadata.id.device.raw(),
            ino: info.metadata.id.inode,
            kind: info.metadata.kind,
            permissions: info.unix.permissions,
            nlink: info.metadata.link_count,
            uid: info.unix.uid,
            gid: info.unix.gid,
            rdev: info.rdev,
            size: info.metadata.size,
            access_nanos: info.metadata.access_nanos,
            modified_nanos: info.metadata.modified_nanos,
            status_nanos: info.metadata.status_nanos,
        }
    }

    impl Stdio for ContainerHost<'_> {
        async fn read_input(&mut self, _: usize) -> Result<Bytes, Denied> {
            Ok(Bytes::new())
        }
        async fn write(&mut self, _: Stream, bytes: &[u8]) -> Result<usize, WriteError> {
            Ok(bytes.len())
        }
    }
    impl Clock for ContainerHost<'_> {
        fn now_nanos(&self) -> u64 {
            self.now
        }
        async fn sleep_until(&self, _: u64) {}
    }
    impl System for ContainerHost<'_> {
        fn realtime_nanos(&self) -> u64 {
            self.now
        }
        fn set_realtime_nanos(&mut self, _: u64) -> Result<(), Denied> {
            Err(Denied)
        }
        fn cpu_nanos(&self) -> u64 {
            0
        }
        fn fill_random(&mut self, out: &mut [u8]) {
            out.fill(0);
        }
        fn memory(&self) -> MemoryTotals {
            MemoryTotals {
                total_bytes: 0,
                free_bytes: 0,
            }
        }
        fn process_count(&self) -> u32 {
            1
        }
        fn kernel_version(&self) -> &str {
            "test"
        }
    }
    impl Tty for ContainerHost<'_> {}
    impl helios_linux::syscall::Network<NoNetwork> for ContainerHost<'_> {
        fn to_ip(&self, a: core::convert::Infallible) -> helios_linux::syscall::IpAddr {
            match a {}
        }
        fn encode_ip(&self, _: helios_linux::syscall::IpAddr) -> core::convert::Infallible {
            unreachable!()
        }
    }
    impl Filesystem<TestRes> for ContainerHost<'_> {
        fn file_access(&self, file: &TestFile) -> FileAccess {
            file.access
        }
        fn file_is_directory(&self, file: &TestFile) -> bool {
            file.kind == NodeKind::Directory
        }
        fn file_path<'b>(&self, file: &'b TestFile) -> Option<&'b str> {
            Some(&file.path)
        }
        fn same_file(&self, a: &TestFile, b: &TestFile) -> bool {
            a.path == b.path
        }
        async fn open(
            &mut self,
            base: Option<&TestFile>,
            cwd: &str,
            path: &str,
            request: OpenRequest,
            creds: &Credentials,
        ) -> Result<TestFile, FsOpError> {
            let base_dir = base.map_or(cwd, |f| f.path.as_str());
            let (info, container_path, _) = self
                .container
                .filesystem()
                .open_at(
                    base_dir,
                    path,
                    request,
                    creds,
                    self.now,
                    &crate::StoragePayer::for_test(),
                )
                .await?;
            let access = match (request.read, request.write) {
                (true, true) => FileAccess::ReadWrite,
                (true, false) => FileAccess::ReadOnly,
                (false, true) => FileAccess::WriteOnly,
                (false, false) => FileAccess::PathOnly,
            };
            Ok(TestFile {
                path: container_path,
                kind: info.metadata.kind,
                access,
            })
        }
        async fn stat_path(
            &self,
            base: Option<&TestFile>,
            cwd: &str,
            path: &str,
            follow: bool,
            creds: &Credentials,
        ) -> Result<(FileStat, String), FsOpError> {
            let base_dir = base.map_or(cwd, |f| f.path.as_str());
            let (info, resolved) = self
                .container
                .filesystem()
                .stat_at(base_dir, path, follow, creds)
                .await?;
            Ok((info_to_stat(&info), resolved))
        }
        async fn stat_file(&self, file: &TestFile) -> Result<FileStat, FsOpError> {
            let info = self
                .container
                .filesystem()
                .stat_resolved(&file.path)
                .await?;
            Ok(info_to_stat(&info))
        }
        async fn access_path(
            &self,
            base: Option<&TestFile>,
            cwd: &str,
            path: &str,
            check: AccessCheck,
            creds: &Credentials,
        ) -> Result<(), FsOpError> {
            let base_dir = base.map_or(cwd, |f| f.path.as_str());
            self.container
                .filesystem()
                .access_at(base_dir, path, check, creds)
                .await
        }
        async fn can_chdir_file(
            &self,
            file: &TestFile,
            creds: &Credentials,
        ) -> Result<(), FsOpError> {
            self.container
                .filesystem()
                .can_chdir(&file.path, creds)
                .await
        }
        async fn read_at(
            &self,
            file: &TestFile,
            offset: u64,
            max_bytes: usize,
        ) -> Result<Bytes, FsOpError> {
            self.container
                .filesystem()
                .read_at(&file.path, offset, max_bytes)
                .await
        }
        async fn write_at(
            &mut self,
            file: &TestFile,
            position: WritePosition,
            bytes: &[u8],
            creds: &Credentials,
        ) -> Result<Landed, FsOpError> {
            self.container
                .filesystem()
                .write_at(
                    &file.path,
                    position,
                    bytes,
                    creds,
                    self.now,
                    &crate::StoragePayer::for_test(),
                )
                .await
        }
        async fn list_dir(
            &self,
            file: &TestFile,
        ) -> Result<(u64, u64, Vec<DirListEntry>), FsOpError> {
            let (a, b, entries) = self
                .container
                .filesystem()
                .list_with_inodes(&file.path)
                .await?;
            Ok((
                a,
                b,
                entries
                    .into_iter()
                    .map(|e| DirListEntry {
                        name: e.name,
                        kind: e.kind,
                        inode: e.inode,
                    })
                    .collect(),
            ))
        }
        async fn set_size_file(
            &mut self,
            file: &TestFile,
            size: u64,
            creds: &Credentials,
        ) -> Result<(), FsOpError> {
            self.container
                .filesystem()
                .set_size(
                    &file.path,
                    size,
                    creds,
                    self.now,
                    &crate::StoragePayer::for_test(),
                )
                .await
        }
        async fn set_size_path(
            &mut self,
            cwd: &str,
            path: &str,
            size: u64,
            creds: &Credentials,
        ) -> Result<(), FsOpError> {
            self.container
                .filesystem()
                .set_size_at(
                    cwd,
                    path,
                    size,
                    creds,
                    self.now,
                    &crate::StoragePayer::for_test(),
                )
                .await
        }
        async fn sync(&self, file: &TestFile, data_only: bool) -> Result<(), FsOpError> {
            self.container
                .filesystem()
                .sync(&file.path, data_only)
                .await
        }
        async fn read_link(
            &self,
            base: Option<&TestFile>,
            cwd: &str,
            path: &str,
            creds: &Credentials,
        ) -> Result<String, FsOpError> {
            let base_dir = base.map_or(cwd, |f| f.path.as_str());
            self.container
                .filesystem()
                .read_link_at(base_dir, path, creds)
                .await
        }
        async fn mkdir(
            &mut self,
            base: Option<&TestFile>,
            cwd: &str,
            path: &str,
            mode: u32,
            umask: u32,
            creds: &Credentials,
        ) -> Result<(), FsOpError> {
            let base_dir = base.map_or(cwd, |f| f.path.as_str());
            self.container
                .filesystem()
                .mkdir_at(
                    base_dir,
                    path,
                    mode,
                    umask,
                    creds,
                    self.now,
                    &crate::StoragePayer::for_test(),
                )
                .await
        }
        async fn mknod(
            &mut self,
            base: Option<&TestFile>,
            cwd: &str,
            path: &str,
            kind: NodeKind,
            mode: u32,
            umask: u32,
            rdev: u64,
            creds: &Credentials,
        ) -> Result<(), FsOpError> {
            let base_dir = base.map_or(cwd, |f| f.path.as_str());
            self.container
                .filesystem()
                .mknod_at(
                    base_dir,
                    path,
                    kind,
                    mode,
                    umask,
                    rdev,
                    creds,
                    self.now,
                    &crate::StoragePayer::for_test(),
                )
                .await
        }
        async fn unlink(
            &mut self,
            base: Option<&TestFile>,
            cwd: &str,
            path: &str,
            remove_dir: bool,
            creds: &Credentials,
        ) -> Result<(), FsOpError> {
            let base_dir = base.map_or(cwd, |f| f.path.as_str());
            self.container
                .filesystem()
                .unlink_at(
                    base_dir,
                    path,
                    remove_dir,
                    creds,
                    self.now,
                    &crate::StoragePayer::for_test(),
                )
                .await
        }
        async fn rename(
            &mut self,
            old_base: Option<&TestFile>,
            old_path: &str,
            new_base: Option<&TestFile>,
            new_path: &str,
            cwd: &str,
            mode: RenameMode,
            creds: &Credentials,
        ) -> Result<(), FsOpError> {
            let old_dir = old_base.map_or(cwd, |f| f.path.as_str());
            let new_dir = new_base.map_or(cwd, |f| f.path.as_str());
            self.container
                .filesystem()
                .rename_at(
                    old_dir,
                    old_path,
                    new_dir,
                    new_path,
                    mode,
                    creds,
                    self.now,
                    &crate::StoragePayer::for_test(),
                )
                .await
        }
        async fn link(
            &mut self,
            old_base: Option<&TestFile>,
            old_path: &str,
            new_base: Option<&TestFile>,
            new_path: &str,
            cwd: &str,
            options: LinkOptions,
            creds: &Credentials,
        ) -> Result<(), FsOpError> {
            let old_dir = old_base.map_or(cwd, |f| f.path.as_str());
            let new_dir = new_base.map_or(cwd, |f| f.path.as_str());
            self.container
                .filesystem()
                .link_at(
                    old_dir,
                    old_path,
                    new_dir,
                    new_path,
                    options.follow,
                    options.empty_path,
                    creds,
                    self.now,
                    &crate::StoragePayer::for_test(),
                )
                .await
        }
        async fn symlink(
            &mut self,
            target: &str,
            base: Option<&TestFile>,
            cwd: &str,
            link_path: &str,
            creds: &Credentials,
        ) -> Result<(), FsOpError> {
            let base_dir = base.map_or(cwd, |f| f.path.as_str());
            self.container
                .filesystem()
                .symlink_at(
                    target,
                    base_dir,
                    link_path,
                    creds,
                    self.now,
                    &crate::StoragePayer::for_test(),
                )
                .await
        }
        async fn set_times_path(
            &mut self,
            base: Option<&TestFile>,
            cwd: &str,
            path: &str,
            follow: bool,
            access: TimeUpdate,
            modified: TimeUpdate,
            creds: &Credentials,
        ) -> Result<(), FsOpError> {
            let base_dir = base.map_or(cwd, |f| f.path.as_str());
            self.container
                .filesystem()
                .set_times_at(
                    base_dir,
                    path,
                    follow,
                    access,
                    modified,
                    creds,
                    self.now,
                    &crate::StoragePayer::for_test(),
                )
                .await
        }
        async fn set_times_file(
            &mut self,
            file: &TestFile,
            access: TimeUpdate,
            modified: TimeUpdate,
            creds: &Credentials,
        ) -> Result<(), FsOpError> {
            self.container
                .filesystem()
                .set_times_resolved(
                    &file.path,
                    access,
                    modified,
                    creds,
                    self.now,
                    &crate::StoragePayer::for_test(),
                )
                .await
        }
        async fn chmod_path(
            &mut self,
            base: Option<&TestFile>,
            cwd: &str,
            path: &str,
            follow: bool,
            mode: u32,
            creds: &Credentials,
        ) -> Result<(), FsOpError> {
            let base_dir = base.map_or(cwd, |f| f.path.as_str());
            self.container
                .filesystem()
                .chmod_at(
                    base_dir,
                    path,
                    follow,
                    mode,
                    creds,
                    self.now,
                    &crate::StoragePayer::for_test(),
                )
                .await
        }
        async fn chmod_file(
            &mut self,
            file: &TestFile,
            mode: u32,
            creds: &Credentials,
        ) -> Result<(), FsOpError> {
            self.container
                .filesystem()
                .chmod_resolved(
                    &file.path,
                    mode,
                    creds,
                    self.now,
                    &crate::StoragePayer::for_test(),
                )
                .await
        }
        async fn chown_path(
            &mut self,
            base: Option<&TestFile>,
            cwd: &str,
            path: &str,
            follow: bool,
            uid: Option<u32>,
            gid: Option<u32>,
            creds: &Credentials,
        ) -> Result<(), FsOpError> {
            let base_dir = base.map_or(cwd, |f| f.path.as_str());
            self.container
                .filesystem()
                .chown_at(
                    base_dir,
                    path,
                    follow,
                    uid,
                    gid,
                    creds,
                    self.now,
                    &crate::StoragePayer::for_test(),
                )
                .await
        }
        async fn chown_file(
            &mut self,
            file: &TestFile,
            uid: Option<u32>,
            gid: Option<u32>,
            creds: &Credentials,
        ) -> Result<(), FsOpError> {
            self.container
                .filesystem()
                .chown_resolved(
                    &file.path,
                    uid,
                    gid,
                    creds,
                    self.now,
                    &crate::StoragePayer::for_test(),
                )
                .await
        }
        async fn get_xattr_path(
            &self,
            cwd: &str,
            path: &str,
            follow: bool,
            name: &str,
            creds: &Credentials,
        ) -> Result<Vec<u8>, FsOpError> {
            self.container
                .filesystem()
                .get_xattr_at(cwd, path, follow, name, creds)
                .await
        }
        async fn get_xattr_file(
            &self,
            file: &TestFile,
            name: &str,
            creds: &Credentials,
        ) -> Result<Vec<u8>, FsOpError> {
            self.container
                .filesystem()
                .get_xattr_resolved(&file.path, name, creds)
                .await
        }
        async fn set_xattr_path(
            &mut self,
            cwd: &str,
            path: &str,
            follow: bool,
            name: &str,
            value: &[u8],
            mode: LinuxXattrSetMode,
            creds: &Credentials,
        ) -> Result<(), FsOpError> {
            self.container
                .filesystem()
                .set_xattr_at(
                    cwd,
                    path,
                    follow,
                    name,
                    value,
                    mode,
                    creds,
                    self.now,
                    &crate::StoragePayer::for_test(),
                )
                .await
        }
        async fn set_xattr_file(
            &mut self,
            file: &TestFile,
            name: &str,
            value: &[u8],
            mode: LinuxXattrSetMode,
            creds: &Credentials,
        ) -> Result<(), FsOpError> {
            self.container
                .filesystem()
                .set_xattr_resolved(
                    &file.path,
                    name,
                    value,
                    mode,
                    creds,
                    self.now,
                    &crate::StoragePayer::for_test(),
                )
                .await
        }
        async fn list_xattrs_path(
            &self,
            cwd: &str,
            path: &str,
            follow: bool,
            creds: &Credentials,
        ) -> Result<Vec<String>, FsOpError> {
            self.container
                .filesystem()
                .list_xattrs_at(cwd, path, follow, creds)
                .await
        }
        async fn list_xattrs_file(
            &self,
            file: &TestFile,
            creds: &Credentials,
        ) -> Result<Vec<String>, FsOpError> {
            self.container
                .filesystem()
                .list_xattrs_resolved(&file.path, creds)
                .await
        }
        async fn remove_xattr_path(
            &mut self,
            cwd: &str,
            path: &str,
            follow: bool,
            name: &str,
            creds: &Credentials,
        ) -> Result<(), FsOpError> {
            self.container
                .filesystem()
                .remove_xattr_at(
                    cwd,
                    path,
                    follow,
                    name,
                    creds,
                    self.now,
                    &crate::StoragePayer::for_test(),
                )
                .await
        }
        async fn remove_xattr_file(
            &mut self,
            file: &TestFile,
            name: &str,
            creds: &Credentials,
        ) -> Result<(), FsOpError> {
            self.container
                .filesystem()
                .remove_xattr_resolved(
                    &file.path,
                    name,
                    creds,
                    self.now,
                    &crate::StoragePayer::for_test(),
                )
                .await
        }
    }

    fn syscall_num(abi: Abi, op: Operation) -> u64 {
        (0..500)
            .find(|&n| abi.operation(n) == op)
            .unwrap_or_else(|| panic!("missing {op:?} on {abi:?}"))
    }

    async fn call(
        proc: &mut Process<TestRes>,
        op: Operation,
        args: [u64; 6],
        mem: &mut TestMem,
        host: &mut ContainerHost<'_>,
    ) -> u64 {
        let mut thread = TestThread;
        let call = Call {
            number: syscall_num(Abi::X86_64, op),
            arguments: args,
        };
        match Box::pin(dispatch(proc, call, mem, &mut thread, host)).await {
            ControlFlow::Continue(SyscallOutcome::Return(v)) => v,
            other => panic!("unexpected outcome for {op:?}: {other:?}"),
        }
    }

    fn err(code: u64) -> u64 {
        code.wrapping_neg()
    }

    const EPERM: u64 = 1;
    const ENXIO: u64 = 6;
    const EACCES: u64 = 13;
    const EEXIST: u64 = 17;
    const ENOTDIR: u64 = 20;
    const EINVAL: u64 = 22;
    const EROFS: u64 = 30;
    const ENODATA: u64 = 61;
    const EOPNOTSUPP: u64 = 95;
    const AT_FDCWD: u64 = (-100i32) as u32 as u64;
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_EACCESS: u64 = 0x200;
    const AT_EMPTY_PATH: u64 = 0x1000;
    const RENAME_NOREPLACE: u64 = 1;
    const RENAME_EXCHANGE: u64 = 2;

    fn make_proc(id: u32, creds: Credentials) -> Process<TestRes> {
        let start = Start {
            credentials: creds,
            ..Start::default()
        };
        Process::<TestRes>::with_descriptors(
            Abi::X86_64,
            NonZeroU32::new(id).unwrap(),
            0x40_0000,
            helios_linux::syscall::standard_streams::<TestRes>(),
            start,
        )
    }

    /// End-to-end integration test exercising every Unix permission, POSIX ACL,
    /// sticky bit, S_ISGID inheritance, chmod/chown/write/truncate privilege
    /// stripping, exec setuid/file-cap authority ceiling, privileged xattr
    /// namespace, mknod/rdev/NO_DEV, and capget/capset rule on a REAL writable
    /// Btrfs filesystem mounted as `MountSharing::Private` inside a container.
    #[test]
    fn private_btrfs_mount_enforces_full_linux_permission_model() {
        let rw_cache = format_btrfs_disk(0x61, false);
        let ro_cache = format_btrfs_disk(0x62, true);
        let timer = test_timer(TestCpu::without_entropy());

        block_on(async {
            let (btrfs_rw, service) =
                BtrfsFs::mount_writable(rw_cache.disk(0), || DeviceId::new(200), write_options())
                    .await
                    .expect("writable btrfs mount");
            let btrfs_ro = BtrfsFs::mount(ro_cache.disk(0), || DeviceId::new(201))
                .await
                .expect("read-only btrfs mount");

            let client = async move {
                let host_ns = Namespace::<BtrfsTestStorage>::new(MountTable::new(
                    BootFs::new(BTRFS_TEST_BOOT, BOOT_DEVICE),
                    4,
                ));
                let root_auth = ProcessAuthority::root();
                let rw = FileSystemRights::READ | FileSystemRights::WRITE;
                let cap_priv = root_auth.derive_mount_cap("/priv").unwrap();
                let cap_ro_priv = root_auth.derive_mount_cap("/ro_priv").unwrap();
                let cap_shared = root_auth.derive_mount_cap("/shared").unwrap();
                host_ns
                    .mount(
                        &cap_priv,
                        MountedFs::Btrfs(btrfs_rw),
                        MountGrant {
                            rights: rw,
                            sharing: MountSharing::Private,
                        },
                    )
                    .await
                    .expect("mount private btrfs");
                host_ns
                    .mount(
                        &cap_ro_priv,
                        MountedFs::Btrfs(btrfs_ro),
                        MountGrant {
                            rights: FileSystemRights::READ,
                            sharing: MountSharing::Private,
                        },
                    )
                    .await
                    .expect("mount ro private btrfs");
                let shared_mem = MemoryFs::new(DeviceId::new(202));
                host_ns
                    .mount(
                        &cap_shared,
                        MountedFs::Memory(shared_mem),
                        MountGrant {
                            rights: rw,
                            sharing: MountSharing::Shared,
                        },
                    )
                    .await
                    .expect("mount shared memory");

                // Container authority: grants PRIVILEGED_BIND, omits SET_WALL_CLOCK & ADMIN.
                let mut container_auth = ProcessAuthority::empty();
                container_auth.grant_network_rights(NetworkAuthorityRights::PRIVILEGED_BIND);
                let container = LinuxContainer::create(
                    ContainerId::new(NonZeroU64::new(42).unwrap()),
                    &ProcessAuthority::root(),
                    &host_ns,
                    container_auth,
                    ContainerConfig {
                        root: ContainerMountSpec {
                            source_path: String::from("/priv"),
                            target_path: String::from("/"),
                            rights: RWX,
                            sharing: ContainerMountSharing::Private,
                        },
                        mounts: vec![
                            ContainerMountSpec {
                                source_path: String::from("/ro_priv"),
                                target_path: String::from("/ro"),
                                rights: RX,
                                sharing: ContainerMountSharing::Private,
                            },
                            ContainerMountSpec {
                                source_path: String::from("/shared"),
                                target_path: String::from("/shared"),
                                rights: RWX,
                                sharing: ContainerMountSharing::Shared,
                            },
                        ],
                        shared_owner: SharedOwner { uid: 0, gid: 0 },
                        credentials: Credentials::root(),
                        hostname: UtsField::UNSET,
                        domainname: UtsField::UNSET,
                    },
                )
                .await
                .expect("create container");

                let mut host = ContainerHost {
                    container: &container,
                    now: 1_700_000_000_000_000_000,
                };
                let mut mem = TestMem::default();
                let mut root_p = make_proc(1, Credentials::root());
                let mut u1000 = make_proc(2, Credentials::for_ids(1000, 100, vec![300]));
                let mut u1001 = make_proc(3, Credentials::for_ids(1001, 200, vec![]));
                let mut u2000 = make_proc(4, Credentials::for_ids(2000, 200, vec![300]));

                // --- 1. DAC, owner non-fallthrough, dir search, CAP_DAC_OVERRIDE exec rule ---
                mem.write_cstr(0x1000, "/secret_dir");
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Mkdirat,
                        [AT_FDCWD, 0x1000, 0o700, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Fchownat,
                        [AT_FDCWD, 0x1000, 1000, 100, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );

                mem.write_cstr(0x1100, "/secret_dir/note");
                let fd = call(
                    &mut u1000,
                    Operation::Openat,
                    [AT_FDCWD, 0x1100, 0x42, 0o644, 0, 0], // O_CREAT | O_RDWR
                    &mut mem,
                    &mut host,
                )
                .await;
                assert!(fd < 1024);
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Close,
                        [fd, 0, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );

                // u1001 cannot traverse /secret_dir (0o700 owned by 1000) for stat, open, or chdir.
                assert_eq!(
                    call(
                        &mut u1001,
                        Operation::Newfstatat,
                        [AT_FDCWD, 0x1100, 0x5000, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EACCES)
                );
                assert_eq!(
                    call(
                        &mut u1001,
                        Operation::Chdir,
                        [0x1000, 0, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EACCES)
                );

                // Owner mode 0o077 denies owner read (no fallthrough to group/other).
                mem.write_cstr(0x1200, "/owner_locked");
                let fd = call(
                    &mut root_p,
                    Operation::Openat,
                    [AT_FDCWD, 0x1200, 0x42, 0o644, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                assert!(fd < 1024);
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Fchown,
                        [fd, 1000, 300, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Fchmod,
                        [fd, 0o077, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Close,
                        [fd, 0, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Openat,
                        [AT_FDCWD, 0x1200, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EACCES)
                );
                // u2000 in supplementary group 300 CAN read/write /owner_locked.
                let fd2 = call(
                    &mut u2000,
                    Operation::Openat,
                    [AT_FDCWD, 0x1200, 2, 0, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                assert!(fd2 < 1024);
                assert_eq!(
                    call(
                        &mut u2000,
                        Operation::Close,
                        [fd2, 0, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );

                // Root with CAP_DAC_OVERRIDE cannot execute a 0o644 file (zero 0o111 bits),
                // but CAN execute a 0o001 file.
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Faccessat2,
                        [AT_FDCWD, 0x1100, 1, AT_EACCESS, 0, 0], // X_OK on 0o644
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EACCES)
                );
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Fchmodat2,
                        [AT_FDCWD, 0x1100, 0o001, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Faccessat2,
                        [AT_FDCWD, 0x1100, 1, AT_EACCESS, 0, 0], // X_OK on 0o001
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );

                // faccessat (real UID 1001) vs faccessat2(AT_EACCESS) (effective UID 0).
                let mut mixed_creds = Credentials::root();
                mixed_creds.user.real = 1001;
                mixed_creds.group.real = 200;
                let mut mixed_p = make_proc(5, mixed_creds);
                assert_eq!(
                    call(
                        &mut mixed_p,
                        Operation::Faccessat,
                        [AT_FDCWD, 0x1100, 4, 0, 0, 0], // R_OK as real uid 1001 -> denied
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EACCES)
                );
                assert_eq!(
                    call(
                        &mut mixed_p,
                        Operation::Faccessat2,
                        [AT_FDCWD, 0x1100, 4, AT_EACCESS, 0, 0], // R_OK as euid 0 -> allowed
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );

                // --- 2. POSIX access & default ACLs on real Btrfs ---
                mem.write_cstr(0x1300, "/acl_dir");
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Mkdirat,
                        [AT_FDCWD, 0x1300, 0o755, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                // Set default ACL granting named user 1001 rw- (masked by mask rwx).
                let default_acl = encode_acl(&[
                    (0x01, 7, u32::MAX), // USER_OBJ rwx
                    (0x02, 6, 1001),     // USER 1001 rw-
                    (0x04, 5, u32::MAX), // GROUP_OBJ r-x
                    (0x10, 7, u32::MAX), // MASK rwx
                    (0x20, 0, u32::MAX), // OTHER ---
                ]);
                mem.write_cstr(0x2000, "system.posix_acl_default");
                mem.write_bytes(0x2100, &default_acl);
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Setxattr,
                        [0x1300, 0x2000, 0x2100, default_acl.len() as u64, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                // Create file inside /acl_dir with umask 0o077: default ACL bypasses umask!
                call(
                    &mut root_p,
                    Operation::Umask,
                    [0o077, 0, 0, 0, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                mem.write_cstr(0x1320, "/acl_dir/inherited");
                let fd = call(
                    &mut root_p,
                    Operation::Openat,
                    [AT_FDCWD, 0x1320, 0x42, 0o660, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                assert!(fd < 1024);
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Close,
                        [fd, 0, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                call(
                    &mut root_p,
                    Operation::Umask,
                    [0o022, 0, 0, 0, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                // u1001 can read+write /acl_dir/inherited via inherited ACL_USER(1001)!
                let fd_acl = call(
                    &mut u1001,
                    Operation::Openat,
                    [AT_FDCWD, 0x1320, 2, 0, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                assert!(fd_acl < 1024);
                assert_eq!(
                    call(
                        &mut u1001,
                        Operation::Close,
                        [fd_acl, 0, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                // u2000 is denied by ACL_OTHER (0).
                assert_eq!(
                    call(
                        &mut u2000,
                        Operation::Openat,
                        [AT_FDCWD, 0x1320, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EACCES)
                );
                // chmod(0o640) narrows ACL_MASK to r-- (`posix_acl_chmod`): u1001 can still read
                // but can no longer write!
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Chmod,
                        [0x1320, 0o640, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                let fd_ro = call(
                    &mut u1001,
                    Operation::Openat,
                    [AT_FDCWD, 0x1320, 0, 0, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                assert!(fd_ro < 1024);
                assert_eq!(
                    call(
                        &mut u1001,
                        Operation::Close,
                        [fd_ro, 0, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut u1001,
                        Operation::Openat,
                        [AT_FDCWD, 0x1320, 1, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EACCES)
                );

                // --- 3. Sticky bit (S_ISVTX) & S_ISGID directory inheritance ---
                mem.write_cstr(0x1400, "/sticky");
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Mkdirat,
                        [AT_FDCWD, 0x1400, 0o777, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Chmod,
                        [0x1400, 0o1777, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                mem.write_cstr(0x1420, "/sticky/a");
                mem.write_cstr(0x1440, "/sticky/b");
                let fd = call(
                    &mut u1000,
                    Operation::Openat,
                    [AT_FDCWD, 0x1420, 0x42, 0o644, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                assert!(fd < 1024);
                call(
                    &mut u1000,
                    Operation::Close,
                    [fd, 0, 0, 0, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                // u2000 cannot unlink or rename u1000's file in sticky directory -> EPERM.
                assert_eq!(
                    call(
                        &mut u2000,
                        Operation::Unlinkat,
                        [AT_FDCWD, 0x1420, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EPERM)
                );
                assert_eq!(
                    call(
                        &mut u2000,
                        Operation::Renameat,
                        [AT_FDCWD, 0x1420, AT_FDCWD, 0x1440, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EPERM)
                );
                // u1000 (file owner) CAN unlink it.
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Unlinkat,
                        [AT_FDCWD, 0x1420, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );

                // S_ISGID directory inheritance (group 500 + S_ISGID bit on subdir).
                mem.write_cstr(0x1500, "/sgid_dir");
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Mkdirat,
                        [AT_FDCWD, 0x1500, 0o777, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Chown,
                        [0x1500, 0, 500, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Chmod,
                        [0x1500, 0o2777, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                mem.write_cstr(0x1520, "/sgid_dir/child_file");
                mem.write_cstr(0x1540, "/sgid_dir/child_sub");
                let fd = call(
                    &mut u1000,
                    Operation::Openat,
                    [AT_FDCWD, 0x1520, 0x42, 0o644, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                assert!(fd < 1024);
                call(
                    &mut u1000,
                    Operation::Close,
                    [fd, 0, 0, 0, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Mkdirat,
                        [AT_FDCWD, 0x1540, 0o755, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                let (file_info, _) = container
                    .filesystem()
                    .stat_at("/", "/sgid_dir/child_file", true, &Credentials::root())
                    .await
                    .unwrap();
                assert_eq!(file_info.unix.uid, 1000);
                assert_eq!(file_info.unix.gid, 500);
                assert_eq!(file_info.unix.permissions & 0o2000, 0);
                let (sub_info, _) = container
                    .filesystem()
                    .stat_at("/", "/sgid_dir/child_sub", true, &Credentials::root())
                    .await
                    .unwrap();
                assert_eq!(sub_info.unix.uid, 1000);
                assert_eq!(sub_info.unix.gid, 500);
                assert_ne!(sub_info.unix.permissions & 0o2000, 0);

                // --- 4. chmod/chown/write/truncate privilege stripping + exec creds + authority ceiling ---
                mem.write_cstr(0x1600, "/priv_bin");
                let fd = call(
                    &mut root_p,
                    Operation::Openat,
                    [AT_FDCWD, 0x1600, 0x42, 0o755, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                assert!(fd < 1024);
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Fchmod,
                        [fd, 0o6777, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                let fcap = encode_vfs_cap_v2(
                    true,
                    (1u64 << CAP_NET_BIND_SERVICE)
                        | (1u64 << CAP_SYS_ADMIN)
                        | (1u64 << CAP_SYS_TIME),
                    0,
                );
                mem.write_cstr(0x2200, "security.capability");
                mem.write_bytes(0x2240, &fcap);
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Fsetxattr,
                        [fd, 0x2200, 0x2240, fcap.len() as u64, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                call(
                    &mut root_p,
                    Operation::Close,
                    [fd, 0, 0, 0, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;

                // Exec calculation on private btrfs mount honours setuid + file caps, bounded by
                // container.authority_cap_ceiling() (has PRIVILEGED_BIND, lacks SET_WALL_CLOCK & ADMIN).
                let exec_creds = container
                    .filesystem()
                    .exec_credentials_at(
                        "/",
                        "/priv_bin",
                        &Credentials::for_ids(1000, 100, vec![]),
                        container.authority_cap_ceiling(),
                    )
                    .await
                    .unwrap();
                assert_eq!(exec_creds.user.effective, 0);
                assert_eq!(exec_creds.group.effective, 0);
                assert!(exec_creds.capabilities.has_effective(CAP_NET_BIND_SERVICE));
                assert!(!exec_creds.capabilities.has_effective(CAP_SYS_TIME));
                assert!(!exec_creds.capabilities.has_effective(CAP_NET_ADMIN));

                // Same setuid binary on /shared (MountSharing::Shared -> NO_SUID) confers nothing!
                mem.write_cstr(0x1680, "/shared/bin");
                let sfd = call(
                    &mut root_p,
                    Operation::Openat,
                    [AT_FDCWD, 0x1680, 0x42, 0o755, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                call(
                    &mut root_p,
                    Operation::Close,
                    [sfd, 0, 0, 0, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                let shared_exec = container
                    .filesystem()
                    .exec_credentials_at(
                        "/",
                        "/shared/bin",
                        &Credentials::for_ids(1000, 100, vec![]),
                        container.authority_cap_ceiling(),
                    )
                    .await
                    .unwrap();
                assert_eq!(shared_exec.user.effective, 1000);
                assert_eq!(shared_exec.capabilities.effective, 0);

                // Non-CAP_FSETID write strips S_ISUID, S_ISGID (with S_IXGRP) AND security.capability.
                let ufd = call(
                    &mut u1000,
                    Operation::Openat,
                    [AT_FDCWD, 0x1600, 2, 0, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                assert!(ufd < 1024);
                mem.write_bytes(0x2300, b"data");
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Write,
                        [ufd, 0x2300, 4, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    4
                );
                call(
                    &mut u1000,
                    Operation::Close,
                    [ufd, 0, 0, 0, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                let after_write = container
                    .filesystem()
                    .stat_resolved("/priv_bin")
                    .await
                    .unwrap();
                assert_eq!(after_write.unix.permissions & (0o4000 | 0o2000), 0);
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Getxattr,
                        [0x1600, 0x2200, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(ENODATA)
                );

                // Re-arm S_ISUID + security.capability, then chown(-1, -1) preserves both,
                // while chown(0, 0) clears both!
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Chmod,
                        [0x1600, 0o4755, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Setxattr,
                        [0x1600, 0x2200, 0x2240, fcap.len() as u64, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Chown,
                        [0x1600, u32::MAX as u64, u32::MAX as u64, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_ne!(
                    container
                        .filesystem()
                        .stat_resolved("/priv_bin")
                        .await
                        .unwrap()
                        .unix
                        .permissions
                        & 0o4000,
                    0
                );
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Chown,
                        [0x1600, 0, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    container
                        .filesystem()
                        .stat_resolved("/priv_bin")
                        .await
                        .unwrap()
                        .unix
                        .permissions
                        & 0o4000,
                    0
                );
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Getxattr,
                        [0x1600, 0x2200, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(ENODATA)
                );

                // --- 5. Privileged xattr namespaces (trusted.*, security.*, user.*) ---
                mem.write_cstr(0x2400, "trusted.secret");
                mem.write_cstr(0x2420, "user.cjk");
                mem.write_cstr(0x2440, "security.selinux");
                let cjk = "中文 日本語 한국어".as_bytes();
                mem.write_bytes(0x2500, cjk);

                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Setxattr,
                        [0x1600, 0x2400, 0x2500, cjk.len() as u64, 1, 0], // XATTR_CREATE
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                // Duplicate XATTR_CREATE -> EEXIST.
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Setxattr,
                        [0x1600, 0x2400, 0x2500, cjk.len() as u64, 1, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EEXIST)
                );
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Setxattr,
                        [0x1600, 0x2420, 0x2500, cjk.len() as u64, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                // Unprivileged user: trusted.* write -> EPERM, read -> ENODATA, omitted from listxattr!
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Setxattr,
                        [0x1600, 0x2400, 0x2500, 3, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EPERM)
                );
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Getxattr,
                        [0x1600, 0x2400, 0x3000, 64, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(ENODATA)
                );
                // Unprivileged user: security.capability & security.selinux write -> EPERM; malformed -> EINVAL for root.
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Setxattr,
                        [0x1600, 0x2200, 0x2240, fcap.len() as u64, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EPERM)
                );
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Setxattr,
                        [0x1600, 0x2440, 0x2500, 4, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EPERM)
                );
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Setxattr,
                        [0x1600, 0x2200, 0x2500, 4, 0, 0], // malformed vfs_cap_data
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EINVAL)
                );
                // listxattr as u1000 omits trusted.secret, shows user.cjk.
                let u_list_len = call(
                    &mut u1000,
                    Operation::Listxattr,
                    [0x1600, 0x3100, 256, 0, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await as usize;
                let u_list = mem.read_bytes(0x3100, u_list_len);
                let u_names: Vec<&str> = u_list
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| core::str::from_utf8(s).unwrap())
                    .collect();
                assert!(u_names.contains(&"user.cjk"));
                assert!(!u_names.contains(&"trusted.secret"));
                // listxattr as root includes trusted.secret.
                let r_list_len = call(
                    &mut root_p,
                    Operation::Listxattr,
                    [0x1600, 0x3200, 256, 0, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await as usize;
                let r_list = mem.read_bytes(0x3200, r_list_len);
                let r_names: Vec<&str> = r_list
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| core::str::from_utf8(s).unwrap())
                    .collect();
                assert!(r_names.contains(&"trusted.secret"));
                assert!(r_names.contains(&"user.cjk"));

                // --- 6. Device nodes (mknodat, CAP_MKNOD, rdev in stat/statx, ENXIO vs EACCES) ---
                mem.write_cstr(0x1700, "/dev_null_priv");
                mem.write_cstr(0x1720, "/dev_blk_priv");
                mem.write_cstr(0x1740, "/sticky/fifo_u1000");
                // Unprivileged u1000 can create FIFO, refused char device -> EPERM.
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Mknodat,
                        [AT_FDCWD, 0x1740, 0o010_644, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Mknodat,
                        [AT_FDCWD, 0x1700, 0o020_666, 0x0103, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EPERM)
                );
                // Root with CAP_MKNOD creates char (1, 3) and block (8, 0) device nodes.
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Mknodat,
                        [AT_FDCWD, 0x1700, 0o020_666, 0x0103, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Mknodat,
                        [AT_FDCWD, 0x1720, 0o060_660, 0x0800, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                // stat & statx report exact rdev (major=1, minor=3).
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Statx,
                        [AT_FDCWD, 0x1700, 0, 0x7ff, 0x4000, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                let statx_raw = mem.read_bytes(0x4000, 256);
                let rdev_major = u32::from_le_bytes(statx_raw[128..132].try_into().unwrap());
                let rdev_minor = u32::from_le_bytes(statx_raw[132..136].try_into().unwrap());
                assert_eq!((rdev_major, rdev_minor), (1, 3));
                // Opening char device on private mount -> ENXIO; O_PATH succeeds.
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Openat,
                        [AT_FDCWD, 0x1700, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(ENXIO)
                );
                let pfd = call(
                    &mut root_p,
                    Operation::Openat,
                    [AT_FDCWD, 0x1700, 1 << 21, 0, 0, 0], // O_PATH
                    &mut mem,
                    &mut host,
                )
                .await;
                assert!(pfd < 1024);
                call(
                    &mut root_p,
                    Operation::Close,
                    [pfd, 0, 0, 0, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;

                // Read-only private mount refuses chmod/mknod/setxattr even for uid 0 -> EROFS.
                mem.write_cstr(0x1800, "/ro/new");
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Mknodat,
                        [AT_FDCWD, 0x1800, 0o020_666, 0x0103, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EROFS)
                );
                mem.write_cstr(0x1820, "/ro");
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Chmod,
                        [0x1820, 0o777, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EROFS)
                );

                // Symlink fchmodat2(AT_SYMLINK_NOFOLLOW) -> EOPNOTSUPP.
                mem.write_cstr(0x1900, "/sym_chmod");
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Symlinkat,
                        [0x1600, AT_FDCWD, 0x1900, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Fchmodat2,
                        [AT_FDCWD, 0x1900, 0o644, AT_SYMLINK_NOFOLLOW, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EOPNOTSUPP)
                );

                // --- 7. capset live capability drop (CAP_MKNOD & CAP_SYS_ADMIN) ---
                let hdr = 0x4500;
                let cap_data = 0x4520;
                mem.write_bytes(hdr, &0x2008_0522u32.to_le_bytes());
                mem.write_bytes(hdr + 4, &0i32.to_le_bytes());
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Capget,
                        [hdr, cap_data, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                let mut raw_caps = mem.read_bytes(cap_data, 24);
                let lo_eff = u32::from_le_bytes(raw_caps[0..4].try_into().unwrap())
                    & !((1u32 << CAP_MKNOD) | (1u32 << CAP_SYS_ADMIN) | (1u32 << CAP_SETFCAP));
                raw_caps[0..4].copy_from_slice(&lo_eff.to_le_bytes());
                raw_caps[4..8].copy_from_slice(&lo_eff.to_le_bytes());
                mem.write_bytes(cap_data, &raw_caps);
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Capset,
                        [hdr, cap_data, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                // Dropping CAP_MKNOD, CAP_SYS_ADMIN, CAP_SETFCAP immediately takes effect on root_p!
                mem.write_cstr(0x1920, "/dev_after_drop");
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Mknodat,
                        [AT_FDCWD, 0x1920, 0o020_666, 0x0103, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EPERM)
                );
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Getxattr,
                        [0x1600, 0x2400, 0x3300, 64, 0, 0], // trusted.secret -> ENODATA
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(ENODATA)
                );
                assert_eq!(
                    call(
                        &mut root_p,
                        Operation::Setxattr,
                        [0x1600, 0x2200, 0x2240, fcap.len() as u64, 0, 0], // security.capability -> EPERM
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EPERM)
                );

                // Unused cap imports check in case tests are pared down.
                let _ = (
                    CAP_CHOWN,
                    CAP_DAC_OVERRIDE,
                    CAP_DAC_READ_SEARCH,
                    CAP_FOWNER,
                    CAP_FSETID,
                );

                // --- 8. CAP_FSETID write/truncate, S_ISGID-without-S_IXGRP, utimensat, ACL S_ISGID strip ---
                // Re-make a fresh root process (with CAP_FSETID) for privileged checks.
                let mut root_full = make_proc(6, Credentials::root());
                mem.write_cstr(0x1a00, "/fsetid_file");
                let ffd = call(
                    &mut root_full,
                    Operation::Openat,
                    [AT_FDCWD, 0x1a00, 0x42, 0o666, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                assert!(ffd < 1024);
                assert_eq!(
                    call(
                        &mut root_full,
                        Operation::Fchmod,
                        [ffd, 0o6755, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut root_full,
                        Operation::Fsetxattr,
                        [ffd, 0x2200, 0x2240, fcap.len() as u64, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                // CAP_FSETID write keeps S_ISUID|S_ISGID, but STILL removes security.capability!
                assert_eq!(
                    call(
                        &mut root_full,
                        Operation::Write,
                        [ffd, 0x2300, 4, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    4
                );
                let after_fsetid = container
                    .filesystem()
                    .stat_resolved("/fsetid_file")
                    .await
                    .unwrap();
                assert_eq!(after_fsetid.unix.permissions & 0o6000, 0o6000);
                assert_eq!(
                    call(
                        &mut root_full,
                        Operation::Fgetxattr,
                        [ffd, 0x2200, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(ENODATA)
                );
                // Mandatory-locking mode 0o2666 (S_ISGID without S_IXGRP): unprivileged write keeps S_ISGID.
                assert_eq!(
                    call(
                        &mut root_full,
                        Operation::Fchmod,
                        [ffd, 0o2666, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                call(
                    &mut root_full,
                    Operation::Close,
                    [ffd, 0, 0, 0, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                let ufd2 = call(
                    &mut u1000,
                    Operation::Openat,
                    [AT_FDCWD, 0x1a00, 2, 0, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                assert!(ufd2 < 1024);
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Write,
                        [ufd2, 0x2300, 4, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    4
                );
                call(
                    &mut u1000,
                    Operation::Close,
                    [ufd2, 0, 0, 0, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                assert_eq!(
                    container
                        .filesystem()
                        .stat_resolved("/fsetid_file")
                        .await
                        .unwrap()
                        .unix
                        .permissions
                        & 0o2000,
                    0o2000
                );

                // utimensat on 0o2666 file owned by uid 0:
                // - u1000 with explicit timestamp -> EPERM
                // - u1000 with times == NULL (UTIME_NOW) -> succeeds (file is writable!)
                let mut explicit_ts = [0u8; 32];
                explicit_ts[0..8].copy_from_slice(&1_700_000_010i64.to_le_bytes());
                explicit_ts[16..24].copy_from_slice(&1_700_000_010i64.to_le_bytes());
                mem.write_bytes(0x4600, &explicit_ts);
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Utimensat,
                        [AT_FDCWD, 0x1a00, 0x4600, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EPERM)
                );
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Utimensat,
                        [AT_FDCWD, 0x1a00, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                // Make it 0o644 -> u1000 with times == NULL now fails with EACCES.
                assert_eq!(
                    call(
                        &mut root_full,
                        Operation::Chmod,
                        [0x1a00, 0o644, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Utimensat,
                        [AT_FDCWD, 0x1a00, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EACCES)
                );

                // Setting system.posix_acl_access by owner not in file's group and without CAP_FSETID
                // strips S_ISGID (`fs/posix_acl.c` `posix_acl_update_mode`).
                assert_eq!(
                    call(
                        &mut root_full,
                        Operation::Chown,
                        [0x1a00, 1000, 999, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut root_full,
                        Operation::Chmod,
                        [0x1a00, 0o2644, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                let access_acl = encode_acl(&[
                    (0x01, 6, u32::MAX),
                    (0x04, 4, u32::MAX),
                    (0x20, 4, u32::MAX),
                ]);
                mem.write_cstr(0x2600, "system.posix_acl_access");
                mem.write_bytes(0x2640, &access_acl);
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Setxattr,
                        [0x1a00, 0x2600, 0x2640, access_acl.len() as u64, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    container
                        .filesystem()
                        .stat_resolved("/fsetid_file")
                        .await
                        .unwrap()
                        .unix
                        .permissions
                        & 0o2000,
                    0
                );

                // --- 9. Review regressions: authority cap clamp, create special bits, device DAC,
                // AT_EMPTY_PATH on AT_FDCWD, and renameat2 NOREPLACE/EXCHANGE checks ---
                // 9a. Container default_credentials and clamp_credentials enforce authority ceiling.
                let expected_ceiling = container.authority_cap_ceiling();
                assert_ne!(expected_ceiling & (1u64 << CAP_NET_BIND_SERVICE), 0);
                assert_eq!(expected_ceiling & (1u64 << CAP_SYS_TIME), 0);
                assert_eq!(expected_ceiling & (1u64 << CAP_NET_ADMIN), 0);
                assert_eq!(expected_ceiling & (1u64 << CAP_NET_RAW), 0);
                let default_caps = container.default_credentials().capabilities;
                assert_eq!(default_caps.effective, expected_ceiling);
                assert_eq!(default_caps.permitted, expected_ceiling);
                assert_eq!(default_caps.bounding, expected_ceiling);

                let mut override_creds = Credentials::root();
                container.clamp_credentials(&mut override_creds);
                assert_eq!(override_creds.capabilities.effective, expected_ceiling);
                assert_eq!(override_creds.capabilities.permitted, expected_ceiling);
                assert_eq!(override_creds.capabilities.bounding, expected_ceiling);

                let mut clamped_root = make_proc(7, container.default_credentials().clone());
                let mut cap_hdr = [0u8; 8];
                cap_hdr[0..4].copy_from_slice(&0x2008_0522u32.to_le_bytes()); // _LINUX_CAPABILITY_VERSION_3
                mem.write_bytes(0x4700, &cap_hdr);
                mem.write_bytes(0x4710, &[0u8; 24]);
                assert_eq!(
                    call(
                        &mut clamped_root,
                        Operation::Capget,
                        [0x4700, 0x4710, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                let mut cap_data = [0u8; 24];
                mem.read(0x4710, &mut cap_data).unwrap();
                let eff_lo = u32::from_le_bytes(cap_data[0..4].try_into().unwrap()) as u64;
                let eff_hi = u32::from_le_bytes(cap_data[12..16].try_into().unwrap()) as u64;
                let perm_lo = u32::from_le_bytes(cap_data[4..8].try_into().unwrap()) as u64;
                let perm_hi = u32::from_le_bytes(cap_data[16..20].try_into().unwrap()) as u64;
                assert_eq!(eff_lo | (eff_hi << 32), expected_ceiling);
                assert_eq!(perm_lo | (perm_hi << 32), expected_ceiling);
                // Trying to raise CAP_SYS_TIME back via capset fails with EPERM.
                let raised = expected_ceiling | (1u64 << CAP_SYS_TIME);
                cap_data[0..4].copy_from_slice(&(raised as u32).to_le_bytes());
                cap_data[4..8].copy_from_slice(&(raised as u32).to_le_bytes());
                cap_data[12..16].copy_from_slice(&((raised >> 32) as u32).to_le_bytes());
                cap_data[16..20].copy_from_slice(&((raised >> 32) as u32).to_le_bytes());
                mem.write_bytes(0x4710, &cap_data);
                assert_eq!(
                    call(
                        &mut clamped_root,
                        Operation::Capset,
                        [0x4700, 0x4710, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EPERM)
                );

                let ephemeral = LinuxContainer::ephemeral(
                    ContainerId::new(NonZeroU64::new(43).unwrap()),
                    ProcessAuthority::empty(),
                    &host_ns,
                );
                let eph_eff = ephemeral.default_credentials().capabilities.effective;
                assert_eq!(eph_eff & (1u64 << CAP_SYS_TIME), 0);
                assert_eq!(eph_eff & (1u64 << CAP_NET_BIND_SERVICE), 0);
                assert_eq!(eph_eff & (1u64 << CAP_NET_ADMIN), 0);
                assert_eq!(eph_eff & (1u64 << CAP_NET_RAW), 0);

                // 9b. mkdirat/openat/mknodat preserve S_ISVTX / S_IALLUGO and strip S_ISGID
                // on non-dir creation when inheriting an unowned group without CAP_FSETID.
                mem.write_cstr(0x1b00, "/sticky_direct");
                assert_eq!(
                    call(
                        &mut root_full,
                        Operation::Mkdirat,
                        [AT_FDCWD, 0x1b00, 0o1777, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                // Default umask 0o022 narrows 0o1777 -> 0o1755 while preserving S_ISVTX.
                assert_eq!(
                    container
                        .filesystem()
                        .stat_resolved("/sticky_direct")
                        .await
                        .unwrap()
                        .unix
                        .permissions,
                    0o1755
                );
                assert_eq!(
                    call(
                        &mut root_full,
                        Operation::Chmod,
                        [0x1b00, 0o1777, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );

                // Allow u1000 to create inside /sticky_direct.
                mem.write_cstr(0x1b20, "/sticky_direct/suid_created");
                let sfd = call(
                    &mut u1000,
                    Operation::Openat,
                    [AT_FDCWD, 0x1b20, 0x42, 0o4755, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                assert!(sfd < 1024);
                call(
                    &mut u1000,
                    Operation::Close,
                    [sfd, 0, 0, 0, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                assert_eq!(
                    container
                        .filesystem()
                        .stat_resolved("/sticky_direct/suid_created")
                        .await
                        .unwrap()
                        .unix
                        .permissions,
                    0o4755
                );

                mem.write_cstr(0x1b60, "/sticky_direct/sgid_fifo");
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Mknodat,
                        [AT_FDCWD, 0x1b60, 0o010_000 | 0o2644, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    container
                        .filesystem()
                        .stat_resolved("/sticky_direct/sgid_fifo")
                        .await
                        .unwrap()
                        .unix
                        .permissions,
                    0o2644
                );

                // S_ISGID parent owned by group 999: u1000 (not in gid 999, no CAP_FSETID)
                // creating a non-directory with S_ISGID | S_IXGRP has S_ISGID stripped.
                mem.write_cstr(0x1ba0, "/sgid_strip_dir");
                assert_eq!(
                    call(
                        &mut root_full,
                        Operation::Mkdirat,
                        [AT_FDCWD, 0x1ba0, 0o777, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut root_full,
                        Operation::Chown,
                        [0x1ba0, 0, 999, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut root_full,
                        Operation::Chmod,
                        [0x1ba0, 0o2777, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                mem.write_cstr(0x1bc0, "/sgid_strip_dir/exec_file");
                let efd = call(
                    &mut u1000,
                    Operation::Openat,
                    [AT_FDCWD, 0x1bc0, 0x42, 0o2755, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                assert!(efd < 1024);
                call(
                    &mut u1000,
                    Operation::Close,
                    [efd, 0, 0, 0, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                let exec_stat = container
                    .filesystem()
                    .stat_resolved("/sgid_strip_dir/exec_file")
                    .await
                    .unwrap();
                assert_eq!(exec_stat.unix.gid, 999);
                assert_eq!(exec_stat.unix.permissions, 0o0755);

                mem.write_cstr(0x1c00, "/sgid_strip_dir/exec_fifo");
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Mknodat,
                        [AT_FDCWD, 0x1c00, 0o010_000 | 0o2755, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                let fifo_stat = container
                    .filesystem()
                    .stat_resolved("/sgid_strip_dir/exec_fifo")
                    .await
                    .unwrap();
                assert_eq!(fifo_stat.unix.gid, 999);
                assert_eq!(fifo_stat.unix.permissions, 0o0755);

                // 9c. Device-node open enforces O_DIRECTORY and DAC before returning ENXIO.
                mem.write_cstr(0x1c40, "/dev_perm_test");
                let rdev = DeviceNumber::new(1, 3).unwrap().encode() as u64;
                assert_eq!(
                    call(
                        &mut root_full,
                        Operation::Mknodat,
                        [AT_FDCWD, 0x1c40, 0o020_000 | 0o600, rdev, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                // O_DIRECTORY fails with ENOTDIR.
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Openat,
                        [AT_FDCWD, 0x1c40, Abi::X86_64.o_directory(), 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(ENOTDIR)
                );
                // u1000 lacks read permission on 0o600 root-owned char device -> EACCES, not ENXIO.
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Openat,
                        [AT_FDCWD, 0x1c40, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EACCES)
                );
                // Root passes DAC and reaches ENXIO.
                assert_eq!(
                    call(
                        &mut root_full,
                        Operation::Openat,
                        [AT_FDCWD, 0x1c40, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(ENXIO)
                );
                // After chmod 0o644, u1000 O_RDONLY passes DAC -> ENXIO, O_WRONLY -> EACCES.
                assert_eq!(
                    call(
                        &mut root_full,
                        Operation::Chmod,
                        [0x1c40, 0o644, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Openat,
                        [AT_FDCWD, 0x1c40, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(ENXIO)
                );
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Openat,
                        [AT_FDCWD, 0x1c40, 1, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EACCES)
                );

                // 9d. AT_EMPTY_PATH on AT_FDCWD operates on cwd without directory search.
                mem.write_cstr(0x1c80, "/cwd_noexec");
                assert_eq!(
                    call(
                        &mut root_full,
                        Operation::Mkdirat,
                        [AT_FDCWD, 0x1c80, 0o700, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut root_full,
                        Operation::Chown,
                        [0x1c80, 1000, 100, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Chdir,
                        [0x1c80, 0, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Chmod,
                        [0x1c80, 0o000, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                mem.write_cstr(0x1ca0, ".");
                mem.write_cstr(0x1ca8, "");
                // "." traverses cwd and requires MAY_EXEC -> EACCES.
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Newfstatat,
                        [AT_FDCWD, 0x1ca0, 0x5200, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EACCES)
                );
                // "" with AT_EMPTY_PATH operates directly on cwd -> succeeds for stat/statx/chown/chmod.
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Newfstatat,
                        [AT_FDCWD, 0x1ca8, 0x5200, AT_EMPTY_PATH, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Statx,
                        [AT_FDCWD, 0x1ca8, AT_EMPTY_PATH, 0x07ff, 0x5300, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Fchownat,
                        [AT_FDCWD, 0x1ca8, 1000, 100, AT_EMPTY_PATH, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Fchmodat2,
                        [AT_FDCWD, 0x1ca8, 0o700, AT_EMPTY_PATH, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );
                // Restore u1000 cwd to "/".
                mem.write_cstr(0x1cb0, "/");
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Chdir,
                        [0x1cb0, 0, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );

                // 9e. renameat2 RENAME_NOREPLACE returns EEXIST before sticky-bit EPERM,
                // and RENAME_EXCHANGE across parents requires MAY_WRITE on destination dir.
                mem.write_cstr(0x1cc0, "/sticky_direct/a");
                mem.write_cstr(0x1ce0, "/sticky_direct/b");
                let afd = call(
                    &mut u1000,
                    Operation::Openat,
                    [AT_FDCWD, 0x1cc0, 0x42, 0o644, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                assert!(afd < 1024);
                call(
                    &mut u1000,
                    Operation::Close,
                    [afd, 0, 0, 0, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                let bfd = call(
                    &mut u1001,
                    Operation::Openat,
                    [AT_FDCWD, 0x1ce0, 0x42, 0o644, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                assert!(bfd < 1024);
                call(
                    &mut u1001,
                    Operation::Close,
                    [bfd, 0, 0, 0, 0, 0],
                    &mut mem,
                    &mut host,
                )
                .await;
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Renameat2,
                        [AT_FDCWD, 0x1cc0, AT_FDCWD, 0x1ce0, RENAME_NOREPLACE, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EEXIST)
                );
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Renameat2,
                        [AT_FDCWD, 0x1cc0, AT_FDCWD, 0x1ce0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EPERM)
                );

                // Set umask 0 on root_full so 0o777 test directories are world-writable.
                assert_eq!(
                    call(
                        &mut root_full,
                        Operation::Umask,
                        [0, 0, 0, 0, 0, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0o022
                );
                mem.write_cstr(0x1d00, "/ex_p1");
                mem.write_cstr(0x1d10, "/ex_p2");
                mem.write_cstr(0x1d20, "/ex_p1/src_dir");
                mem.write_cstr(0x1d40, "/ex_p2/ro_dst_dir");
                mem.write_cstr(0x1d60, "/ex_p2/sib_dir");
                for (path_addr, mode) in [
                    (0x1d00, 0o777),
                    (0x1d10, 0o777),
                    (0x1d20, 0o777),
                    (0x1d40, 0o555),
                    (0x1d60, 0o777),
                ] {
                    assert_eq!(
                        call(
                            &mut root_full,
                            Operation::Mkdirat,
                            [AT_FDCWD, path_addr, mode, 0, 0, 0],
                            &mut mem,
                            &mut host
                        )
                        .await,
                        0
                    );
                }
                // Cross-parent RENAME_EXCHANGE onto read-only destination dir fails with EACCES.
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Renameat2,
                        [AT_FDCWD, 0x1d20, AT_FDCWD, 0x1d40, RENAME_EXCHANGE, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    err(EACCES)
                );
                // Same-parent RENAME_EXCHANGE of read-only dir does not rewrite `..` -> succeeds.
                assert_eq!(
                    call(
                        &mut u1000,
                        Operation::Renameat2,
                        [AT_FDCWD, 0x1d60, AT_FDCWD, 0x1d40, RENAME_EXCHANGE, 0],
                        &mut mem,
                        &mut host
                    )
                    .await,
                    0
                );

                drop(container);
                host_ns
                    .unmount(&root_auth.derive_unmount_cap("/priv").unwrap())
                    .await
                    .expect("unmount /priv");
                host_ns
                    .unmount(&root_auth.derive_unmount_cap("/ro_priv").unwrap())
                    .await
                    .expect("unmount /ro_priv");
                host_ns
                    .unmount(&root_auth.derive_unmount_cap("/shared").unwrap())
                    .await
                    .expect("unmount /shared");
            };

            futures::future::join(Box::pin(client), Box::pin(service.run(timer))).await;
        });
    }
}
