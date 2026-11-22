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
use core::num::{NonZeroU32, NonZeroU64};

use helios_hal::fs::{
    DirCookie, DirEntry, DirStream, FileSystem, FileSystemRights, FsError, FsPath, FsResult,
    Metadata, NodeKind,
};
use helios_linux::syscall::{Credentials, PidNamespace, UtsField};
use helios_unix::FutexTable;
use thiserror::Error;

use crate::vfs::{
    FileContents, Follow, HeldPath, MAX_MOUNTS, MAX_SYMLINK_DEPTH, MountFlags, MountGrant,
    MountSharing, MountedFs, Namespace, PrivateMountClaim, PrivateMountClaimError, SharedOwner,
    Storage, UnixAttributes, join_fs_path, within_directory,
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
}
