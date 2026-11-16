//! The guest filesystem as every WASI surface sees it.
//!
//! The functions here are the one implementation of WASI filesystem
//! semantics: descriptor rights, open flags, symbolic-link following and
//! directory listing order. They resolve every path through the store's
//! [`Namespace`], so the mount that owns a path decides which filesystem
//! answers; no surface knows which filesystems exist. Preview3 below,
//! preview2 (`preview2.rs`) and preview1 (`component_host::service`) call
//! them and only translate types.

use helios_hal::fs::{
    FileSystem, FilledWrite, FsError as VfsError, FsResult, Landed, Metadata, NodeKind, OpenFlags,
    PreparedWrite, WritePosition, WriteProgress,
};
use pin_project_lite::pin_project;

use crate::{
    ComponentHostNetwork, FileContents, Follow, HeldPath, MountHold, MountedWrite, Namespace,
    Resolved, object_identity,
};

use super::*;

pub(super) struct ComponentFsProfile<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    pub(super) runtime_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
    pub(super) cpu: CpuImpl,
    pub(super) started_ticks: u64,
}

pub(super) fn component_fs_profile<CpuImpl, Net, StorageImpl>(
    store: &StoreData<CpuImpl, Net, StorageImpl>,
) -> Option<ComponentFsProfile<CpuImpl, Net, StorageImpl>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    store
        .runtime_state
        .profiling_enabled()
        .then(|| ComponentFsProfile {
            runtime_state: store.runtime_state.clone(),
            cpu: store.cpu.clone(),
            started_ticks: store.cpu.now().ticks(),
        })
}

pub(super) fn record_component_fs_profile<CpuImpl, Net, StorageImpl>(
    profile: Option<ComponentFsProfile<CpuImpl, Net, StorageImpl>>,
    operation: &'static str,
) where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    if let Some(profile) = profile {
        profile.runtime_state.record_profile_stack_parts(
            crate::ProfileScope::Kernel,
            "kernel;component-fs;",
            operation,
            profile
                .cpu
                .now()
                .ticks()
                .saturating_sub(profile.started_ticks),
        );
    }
}

/// An open guest descriptor: the guest path it names, what it named when
/// it was opened, and the rights it was opened with.
#[derive(Clone)]
pub struct FsDescriptor {
    pub(crate) path: String,
    pub(crate) kind: FsNodeKind,
    pub(crate) flags: fs_types::DescriptorFlags,
    pub(crate) identity: Option<ObjectIdentity>,
    /// The hold on the mount `open-at` resolved this through, which keeps
    /// that mount from being unmounted while the descriptor lives. `None`
    /// for a preopen or a working directory, which the process's authority
    /// names rather than an open, and for the namespace's root.
    #[expect(
        dead_code,
        reason = "held for its effect: a live share is what makes unmount busy"
    )]
    pub(crate) mount: Option<MountHold>,
}

/// What every filesystem operation here resolves with.
pub(crate) type FsOpResult<T> = core::result::Result<T, fs_types::ErrorCode>;

pub(crate) fn fs_error_code(error: VfsError) -> fs_types::ErrorCode {
    match error {
        VfsError::NoEntry => fs_types::ErrorCode::NoEntry,
        VfsError::Exists => fs_types::ErrorCode::Exist,
        VfsError::NotDirectory => fs_types::ErrorCode::NotDirectory,
        VfsError::IsDirectory => fs_types::ErrorCode::IsDirectory,
        VfsError::NotEmpty => fs_types::ErrorCode::NotEmpty,
        VfsError::ReadOnly => fs_types::ErrorCode::ReadOnly,
        VfsError::NotPermitted => fs_types::ErrorCode::NotPermitted,
        VfsError::CrossDevice => fs_types::ErrorCode::CrossDevice,
        VfsError::Busy => fs_types::ErrorCode::Busy,
        VfsError::Loop => fs_types::ErrorCode::Loop,
        VfsError::Invalid => fs_types::ErrorCode::Invalid,
        VfsError::Overflow => fs_types::ErrorCode::Overflow,
        VfsError::IllegalByteSequence => fs_types::ErrorCode::IllegalByteSequence,
        VfsError::NameTooLong => fs_types::ErrorCode::NameTooLong,
        VfsError::Unsupported => fs_types::ErrorCode::Unsupported,
        VfsError::NoSpace => fs_types::ErrorCode::InsufficientSpace,
        VfsError::Io => fs_types::ErrorCode::Io,
    }
}

pub(crate) fn node_kind(kind: NodeKind) -> FsNodeKind {
    match kind {
        NodeKind::Directory => FsNodeKind::Directory,
        NodeKind::File => FsNodeKind::File,
        NodeKind::Symlink => FsNodeKind::Symlink,
    }
}

pub(crate) fn descriptor_type_from_node_kind(kind: FsNodeKind) -> fs_types::DescriptorType {
    match kind {
        FsNodeKind::Directory => fs_types::DescriptorType::Directory,
        FsNodeKind::File => fs_types::DescriptorType::RegularFile,
        FsNodeKind::Symlink => fs_types::DescriptorType::SymbolicLink,
    }
}

pub(crate) fn descriptor_stat(metadata: &Metadata) -> fs_types::DescriptorStat {
    fs_types::DescriptorStat {
        type_: descriptor_type_from_node_kind(node_kind(metadata.kind)),
        link_count: metadata.link_count,
        size: metadata.size,
        data_access_timestamp: Some(system_time_from_nanos(metadata.access_nanos)),
        data_modification_timestamp: Some(system_time_from_nanos(metadata.modified_nanos)),
        status_change_timestamp: Some(system_time_from_nanos(metadata.status_nanos)),
    }
}

pub(crate) fn metadata_hash_value(
    identity: ObjectIdentity,
    upper_entropy: u64,
) -> fs_types::MetadataHashValue {
    fs_types::MetadataHashValue {
        lower: identity.local(),
        upper: identity.domain().raw() ^ upper_entropy,
    }
}

/// A hash that changes when the object's identity, size or modification
/// time does.
pub(crate) fn metadata_hash(metadata: &Metadata) -> fs_types::MetadataHashValue {
    metadata_hash_value(
        object_identity(metadata),
        metadata.modified_nanos ^ metadata.size,
    )
}

fn resolve<'a, StorageImpl>(
    namespace: &'a Namespace<StorageImpl>,
    absolute: &'a str,
) -> FsOpResult<Resolved<'a, StorageImpl>>
where
    StorageImpl: crate::Storage,
{
    namespace.resolve(absolute).map_err(fs_error_code)
}

pub(crate) fn child_path(base: &FsDescriptor, path: &str) -> FsOpResult<String> {
    crate::resolve_child_path(&base.path, path).map_err(map_component_fs_path_error)
}

/// Opens `path` below `base` as WASI `open-at` does.
///
/// The lookup itself needs `base`'s `read`, which the signature proves
/// before anything is resolved.
///
/// A descriptor may be opened with any rights `base` holds, whatever the
/// filesystem would let it do: a file on a read-only filesystem opens for
/// writing, and the write itself is what fails. Creating changes the
/// directory, so it needs `base`'s `mutate-directory` and a writable
/// mount; truncating also changes the file's data, so it needs `base`'s
/// `write` as well. Both rights are demanded whether or not the file
/// exists, and before the path is resolved: a refused open reaches no
/// filesystem and leaves it as it was.
pub(crate) async fn open_at<StorageImpl>(
    namespace: &Namespace<StorageImpl>,
    base: Granted<'_, Directory, Read>,
    path_flags: fs_types::PathFlags,
    path: &str,
    open_flags: fs_types::OpenFlags,
    requested: fs_types::DescriptorFlags,
    now: u64,
) -> FsOpResult<FsDescriptor>
where
    StorageImpl: crate::Storage,
{
    let grant = base.prepare_open(open_flags)?;
    let absolute = child_path(grant.base().descriptor(), path)?;
    open_prepared(
        namespace, &grant, path_flags, &absolute, open_flags, requested, now,
    )
    .await
}

async fn open_prepared<StorageImpl, D>(
    namespace: &Namespace<StorageImpl>,
    grant: &OpenGrant<D>,
    path_flags: fs_types::PathFlags,
    absolute: &str,
    open_flags: fs_types::OpenFlags,
    requested: fs_types::DescriptorFlags,
    now: u64,
) -> FsOpResult<FsDescriptor>
where
    StorageImpl: crate::Storage,
    D: core::borrow::Borrow<FsDescriptor>,
{
    let base = grant.base().descriptor();
    let truncate = grant.truncate();
    let create = grant.create();
    let resolved = namespace
        .resolve_following(absolute, follow_within(base, path_flags))
        .await
        .map_err(fs_error_code)?;
    let fs = resolved.fs();
    let (metadata, flags) = match fs.stat(resolved.path()).await {
        Ok(existing) => {
            if open_flags.contains(fs_types::OpenFlags::EXCLUSIVE)
                && open_flags.contains(fs_types::OpenFlags::CREATE)
            {
                return Err(fs_types::ErrorCode::Exist);
            }
            let directory = existing.kind == NodeKind::Directory;
            if open_flags.contains(fs_types::OpenFlags::DIRECTORY) && !directory {
                return Err(fs_types::ErrorCode::NotDirectory);
            }
            if !open_flags.contains(fs_types::OpenFlags::DIRECTORY) && directory {
                return Err(fs_types::ErrorCode::IsDirectory);
            }
            let flags =
                effective_open_descriptor_flags(base.flags, requested, node_kind(existing.kind))?;
            match truncate {
                None => (existing, flags),
                Some(rights) => {
                    if existing.kind != NodeKind::File {
                        return Err(fs_types::ErrorCode::IsDirectory);
                    }
                    (truncate_file(&resolved, rights, now).await?, flags)
                }
            }
        }
        Err(VfsError::NoEntry) => {
            let Some(mutate) = create else {
                return Err(fs_types::ErrorCode::NoEntry);
            };
            if open_flags.contains(fs_types::OpenFlags::DIRECTORY) {
                return Err(fs_types::ErrorCode::Unsupported);
            }
            let flags = effective_open_descriptor_flags(base.flags, requested, FsNodeKind::File)?;
            (create_file(&resolved, mutate, now).await?, flags)
        }
        Err(error) => return Err(fs_error_code(error)),
    };
    let kind = node_kind(metadata.kind);
    Ok(FsDescriptor {
        path: String::from(resolved.absolute()),
        kind,
        flags,
        identity: Some(object_identity(&metadata)),
        mount: resolved.hold(),
    })
}

pub struct PreparedOpenAt<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    target: FsOpResult<(OpenGrant<FsDescriptor>, Namespace<StorageImpl>, String)>,
    path_flags: fs_types::PathFlags,
    open_flags: fs_types::OpenFlags,
    flags: fs_types::DescriptorFlags,
    now: u64,
    profile: Option<ComponentFsProfile<CpuImpl, Net, StorageImpl>>,
}

pub(crate) fn prepare_open<CpuImpl, Net, StorageImpl>(
    store: &mut StoreData<CpuImpl, Net, StorageImpl>,
    descriptor: Resource<FsDescriptor>,
    path_flags: fs_types::PathFlags,
    path: &str,
    open_flags: fs_types::OpenFlags,
    flags: fs_types::DescriptorFlags,
) -> PreparedOpenAt<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let profile = component_fs_profile(store);
    let now = store.now_nanos();
    let target = descriptor_in(store, &descriptor).and_then(|(base, namespace)| {
        let grant = base.prepare_open(open_flags)?;
        let absolute = child_path(grant.base().descriptor(), path)?;
        Ok((grant, namespace, absolute))
    });
    PreparedOpenAt {
        target,
        path_flags,
        open_flags,
        flags,
        now,
        profile,
    }
}

pub(crate) async fn execute_open<CpuImpl, Net, StorageImpl>(
    prepared: PreparedOpenAt<CpuImpl, Net, StorageImpl>,
) -> FsOpResult<FsDescriptor>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let (grant, namespace, absolute) = prepared.target?;
    let opened = open_prepared(
        &namespace,
        &grant,
        prepared.path_flags,
        &absolute,
        prepared.open_flags,
        prepared.flags,
        prepared.now,
    )
    .await?;
    record_component_fs_profile(prepared.profile, "open-at");
    Ok(opened)
}

/// Creates the file `resolved` names, in the directory `_mutate` proves the
/// guest may change.
async fn create_file<StorageImpl>(
    resolved: &Resolved<'_, StorageImpl>,
    _mutate: Granted<'_, Directory, Mutate>,
    now: u64,
) -> FsOpResult<Metadata>
where
    StorageImpl: crate::Storage,
{
    resolved
        .writable()
        .map_err(fs_error_code)?
        .open(resolved.path(), OpenFlags::CREATE, now)
        .await
        .map_err(fs_error_code)
}

/// Truncates the file `resolved` names: the guest may change its directory
/// and write through the same base.
async fn truncate_file<StorageImpl>(
    resolved: &Resolved<'_, StorageImpl>,
    _rights: (
        Granted<'_, Directory, Mutate>,
        Granted<'_, Directory, Write>,
    ),
    now: u64,
) -> FsOpResult<Metadata>
where
    StorageImpl: crate::Storage,
{
    resolved
        .writable()
        .map_err(fs_error_code)?
        .open(resolved.path(), OpenFlags::TRUNCATE, now)
        .await
        .map_err(fs_error_code)
}

/// How a path below `base` follows a final symbolic link: when the guest
/// asks it to, and then never out of `base`.
pub(crate) fn follow_within(base: &FsDescriptor, path_flags: fs_types::PathFlags) -> Follow<'_> {
    if path_flags.contains(fs_types::PathFlags::SYMLINK_FOLLOW) {
        Follow::Within(&base.path)
    } else {
        Follow::No
    }
}

/// Describes the object `absolute` names, following a final symbolic link
/// as `follow` says.
pub(crate) async fn stat_path<StorageImpl>(
    namespace: &Namespace<StorageImpl>,
    absolute: &str,
    follow: Follow<'_>,
) -> FsOpResult<Metadata>
where
    StorageImpl: crate::Storage,
{
    namespace
        .stat(absolute, follow)
        .await
        .map_err(fs_error_code)
}

/// The metadata of `path` below `base`, which must be readable.
pub(crate) async fn stat_at<StorageImpl>(
    namespace: &Namespace<StorageImpl>,
    base: Granted<'_, Directory, Read>,
    path_flags: fs_types::PathFlags,
    path: &str,
) -> FsOpResult<Metadata>
where
    StorageImpl: crate::Storage,
{
    let base = base.descriptor();
    let absolute = child_path(base, path)?;
    stat_path(namespace, &absolute, follow_within(base, path_flags)).await
}

pub struct PreparedStat<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    target: FsOpResult<(FsDescriptor, Namespace<StorageImpl>, String)>,
    path_flags: fs_types::PathFlags,
    profile: Option<ComponentFsProfile<CpuImpl, Net, StorageImpl>>,
}

pub(crate) fn prepare_stat<CpuImpl, Net, StorageImpl>(
    store: &mut StoreData<CpuImpl, Net, StorageImpl>,
    descriptor: Resource<FsDescriptor>,
    path_flags: fs_types::PathFlags,
    path: &str,
) -> PreparedStat<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let profile = component_fs_profile(store);
    let target = descriptor_in(store, &descriptor).and_then(|(base, namespace)| {
        let read = base.grant::<Directory, Read>()?;
        let absolute = child_path(read.descriptor(), path)?;
        Ok((base, namespace, absolute))
    });
    PreparedStat {
        target,
        path_flags,
        profile,
    }
}

pub(crate) async fn stat_prepared<CpuImpl, Net, StorageImpl>(
    prepared: PreparedStat<CpuImpl, Net, StorageImpl>,
    operation: &'static str,
) -> FsOpResult<Metadata>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let (base, namespace, absolute) = prepared.target?;
    let result = stat_path(
        &namespace,
        &absolute,
        follow_within(&base, prepared.path_flags),
    )
    .await;
    record_component_fs_profile(prepared.profile, operation);
    result
}

/// The path below `base` that `path` names, refused when it names `base`
/// itself (an empty path, `.`, or one that climbs back to it): the
/// directory a descriptor stands for is never removed, renamed, or
/// replaced through that descriptor.
fn child_below(base: &FsDescriptor, path: &str) -> FsOpResult<String> {
    let absolute = child_path(base, path)?;
    if absolute == base.path {
        return Err(fs_types::ErrorCode::Invalid);
    }
    Ok(absolute)
}

/// Reads at most `max_bytes` at `offset`; an empty result is end of file.
pub(crate) async fn read<StorageImpl>(
    namespace: &Namespace<StorageImpl>,
    file: Granted<'_, RegularFile, Read>,
    offset: u64,
    max_bytes: usize,
) -> FsOpResult<Bytes>
where
    StorageImpl: crate::Storage,
{
    read_resolved(
        &resolve(namespace, &file.descriptor().path)?,
        offset,
        max_bytes,
    )
    .await
}

/// The file a stream reads across polls.
pub(crate) fn read_stream_target<StorageImpl>(
    namespace: &Namespace<StorageImpl>,
    file: Granted<'_, RegularFile, Read>,
) -> FsOpResult<HeldPath<StorageImpl>>
where
    StorageImpl: crate::Storage,
{
    resolve(namespace, &file.descriptor().path).map(|resolved| resolved.held())
}

/// The file a stream writes across polls.
pub(crate) fn write_stream_target<StorageImpl>(
    namespace: &Namespace<StorageImpl>,
    file: Granted<'_, RegularFile, Write>,
) -> FsOpResult<HeldPath<StorageImpl>>
where
    StorageImpl: crate::Storage,
{
    resolve(namespace, &file.descriptor().path).map(|resolved| resolved.held())
}

/// One positional read through `resolved`.
pub(crate) async fn read_resolved<StorageImpl>(
    resolved: &Resolved<'_, StorageImpl>,
    offset: u64,
    max_bytes: usize,
) -> FsOpResult<Bytes>
where
    StorageImpl: crate::Storage,
{
    resolved
        .fs()
        .read_at(resolved.path(), offset, max_bytes)
        .await
        .map_err(fs_error_code)
}

/// One positional read through a held path, for a stream that must own
/// its read across polls.
pub(crate) async fn read_held<StorageImpl>(
    held: HeldPath<StorageImpl>,
    offset: u64,
    max_bytes: usize,
) -> FsOpResult<Bytes>
where
    StorageImpl: crate::Storage,
{
    read_resolved(&held.resolved(), offset, max_bytes).await
}

/// Writes `bytes` to the file `descriptor` names, and resolves with where
/// they landed and how many did: fewer than `bytes` only when the
/// filesystem ran out of space after storing a prefix.
pub(crate) async fn write<StorageImpl>(
    namespace: &Namespace<StorageImpl>,
    file: Granted<'_, RegularFile, Write>,
    position: WritePosition,
    bytes: &[u8],
    now: u64,
) -> FsOpResult<Landed>
where
    StorageImpl: crate::Storage,
{
    write_resolved(&writable_file(namespace, file)?, position, bytes, now).await
}

/// The file `file` names, resolved for a write.
pub(crate) fn writable_file<'a, StorageImpl>(
    namespace: &'a Namespace<StorageImpl>,
    file: Granted<'a, RegularFile, Write>,
) -> FsOpResult<Resolved<'a, StorageImpl>>
where
    StorageImpl: crate::Storage,
{
    resolve(namespace, &file.descriptor().path)
}

/// Writes `bytes` through `resolved`, and resolves with where they landed
/// and how many did ([`Landed`]).
pub(crate) async fn write_resolved<StorageImpl>(
    resolved: &Resolved<'_, StorageImpl>,
    position: WritePosition,
    bytes: &[u8],
    now: u64,
) -> FsOpResult<Landed>
where
    StorageImpl: crate::Storage,
{
    write_resolved_with(resolved, position, bytes.len(), now, |at, destination| {
        destination.copy_from_slice(&bytes[at..at + destination.len()]);
    })
    .await
}

/// Stages a write of `len` bytes at `position` through `resolved`, for a
/// caller that fills each round itself straight from where its bytes are
/// ([`helios_hal::fs::PreparedWrite::fill`]) and has to wait before a
/// round for those bytes to be readable, as guest pages back from swap.
/// The rounds land at consecutive offsets from the one the write begins
/// at, which the last submit answers.
pub(crate) async fn prepare_resolved_write<'a, StorageImpl>(
    resolved: &'a Resolved<'_, StorageImpl>,
    position: WritePosition,
    len: usize,
    now: u64,
) -> FsOpResult<impl helios_hal::fs::PreparedWrite + 'a>
where
    StorageImpl: crate::Storage,
{
    resolved
        .writable()
        .map_err(fs_error_code)?
        .prepare_write(resolved.path(), position, len, now)
        .await
        .map_err(fs_error_code)
}

/// Writes `len` bytes that `source` copies straight into the
/// filesystem's destination ([`helios_hal::fs::write_with`]), and
/// resolves with where they landed and how many did ([`Landed::end`] is
/// where a sequential writer continues). An append lands at the end of
/// the file as the filesystem sees it when the write arrives, so its end
/// is the filesystem's answer, never the caller's idea of where the file
/// ended.
///
/// `source(at, destination)` fills `destination` with the write's bytes
/// from offset `at`. It runs between awaits, never across one, once per
/// destination region; what it reads must stay valid for the whole call,
/// which guest memory does for the host call that holds it.
pub(crate) async fn write_resolved_with<StorageImpl, S>(
    resolved: &Resolved<'_, StorageImpl>,
    position: WritePosition,
    len: usize,
    now: u64,
    source: S,
) -> FsOpResult<Landed>
where
    StorageImpl: crate::Storage,
    S: FnMut(usize, &mut [u8]),
{
    let fs = resolved.writable().map_err(fs_error_code)?;
    helios_hal::fs::write_with(fs, resolved.path(), position, len, now, source)
        .await
        .map_err(fs_error_code)
}

pub(crate) async fn set_size<StorageImpl>(
    namespace: &Namespace<StorageImpl>,
    file: Granted<'_, RegularFile, Write>,
    size: u64,
    now: u64,
) -> FsOpResult<()>
where
    StorageImpl: crate::Storage,
{
    let resolved = resolve(namespace, &file.descriptor().path)?;
    resolved
        .writable()
        .map_err(fs_error_code)?
        .set_size(resolved.path(), size, now)
        .await
        .map_err(fs_error_code)
}

/// Sets the times of the object `target` names; `None` leaves one alone.
pub(crate) async fn set_times<StorageImpl>(
    namespace: &Namespace<StorageImpl>,
    target: Granted<'_, AnyKind, Touch>,
    access_nanos: Option<u64>,
    modified_nanos: Option<u64>,
    now: u64,
) -> FsOpResult<()>
where
    StorageImpl: crate::Storage,
{
    set_times_of(
        namespace,
        &target.descriptor().path,
        access_nanos,
        modified_nanos,
        now,
    )
    .await
}

/// Sets the times of the object at `path` below `base`; `None` leaves one
/// alone.
pub struct PreparedSetTimesAt<StorageImpl: crate::Storage> {
    namespace: Namespace<StorageImpl>,
    absolute: String,
    access_nanos: Option<u64>,
    modified_nanos: Option<u64>,
    now: u64,
}

impl<StorageImpl: crate::Storage> PreparedSetTimesAt<StorageImpl> {
    pub(crate) fn new(
        namespace: Namespace<StorageImpl>,
        base: Granted<'_, Directory, Retime>,
        path: &str,
        access_nanos: Option<u64>,
        modified_nanos: Option<u64>,
        now: u64,
    ) -> FsOpResult<Self> {
        let absolute = child_path(base.descriptor(), path)?;
        Ok(Self {
            namespace,
            absolute,
            access_nanos,
            modified_nanos,
            now,
        })
    }

    pub(crate) async fn execute(self) -> FsOpResult<()> {
        set_times_of(
            &self.namespace,
            &self.absolute,
            self.access_nanos,
            self.modified_nanos,
            self.now,
        )
        .await
    }
}

pub(crate) async fn set_times_at<StorageImpl: crate::Storage>(
    namespace: &Namespace<StorageImpl>,
    base: Granted<'_, Directory, Retime>,
    path: &str,
    access_nanos: Option<u64>,
    modified_nanos: Option<u64>,
    now: u64,
) -> FsOpResult<()> {
    PreparedSetTimesAt::new(
        namespace.clone(),
        base,
        path,
        access_nanos,
        modified_nanos,
        now,
    )?
    .execute()
    .await
}

async fn set_times_of<StorageImpl>(
    namespace: &Namespace<StorageImpl>,
    absolute: &str,
    access_nanos: Option<u64>,
    modified_nanos: Option<u64>,
    now: u64,
) -> FsOpResult<()>
where
    StorageImpl: crate::Storage,
{
    let resolved = resolve(namespace, absolute)?;
    resolved
        .writable()
        .map_err(fs_error_code)?
        .set_times(resolved.path(), access_nanos, modified_nanos, now)
        .await
        .map_err(fs_error_code)
}

/// Every entry of the directory `descriptor` names, directories first and
/// each group by name, with the mount points inside it.
pub(crate) async fn read_directory<StorageImpl>(
    namespace: &Namespace<StorageImpl>,
    directory: Granted<'_, Directory, Read>,
) -> FsOpResult<Vec<fs_types::DirectoryEntry>>
where
    StorageImpl: crate::Storage,
{
    let mut entries: Vec<fs_types::DirectoryEntry> = namespace
        .list(&directory.descriptor().path)
        .await
        .map_err(fs_error_code)?
        .into_iter()
        .map(|entry| fs_types::DirectoryEntry {
            type_: descriptor_type_from_node_kind(node_kind(entry.kind)),
            name: entry.name,
        })
        .collect();
    entries.sort_by(|left, right| {
        is_dir_first(left.type_.clone())
            .cmp(&is_dir_first(right.type_.clone()))
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(entries)
}

pub struct PreparedCreateDirectoryAt<StorageImpl: crate::Storage> {
    namespace: Namespace<StorageImpl>,
    absolute: String,
    now: u64,
}

impl<StorageImpl: crate::Storage> PreparedCreateDirectoryAt<StorageImpl> {
    pub(crate) fn new(
        namespace: Namespace<StorageImpl>,
        base: Granted<'_, Directory, Mutate>,
        path: &str,
        now: u64,
    ) -> FsOpResult<Self> {
        let absolute = child_path(base.descriptor(), path)?;
        Ok(Self {
            namespace,
            absolute,
            now,
        })
    }

    pub(crate) async fn execute(self) -> FsOpResult<()> {
        let resolved = resolve(&self.namespace, &self.absolute)?;
        if resolved.is_mount_root() {
            return Err(fs_types::ErrorCode::Exist);
        }
        resolved
            .writable()
            .map_err(fs_error_code)?
            .create_directory(resolved.path(), self.now)
            .await
            .map_err(fs_error_code)
    }
}

pub(crate) async fn create_directory_at<StorageImpl: crate::Storage>(
    namespace: &Namespace<StorageImpl>,
    base: Granted<'_, Directory, Mutate>,
    path: &str,
    now: u64,
) -> FsOpResult<()> {
    PreparedCreateDirectoryAt::new(namespace.clone(), base, path, now)?
        .execute()
        .await
}

pub struct PreparedRemoveDirectoryAt<StorageImpl: crate::Storage> {
    namespace: Namespace<StorageImpl>,
    absolute: String,
    now: u64,
}

impl<StorageImpl: crate::Storage> PreparedRemoveDirectoryAt<StorageImpl> {
    pub(crate) fn new(
        namespace: Namespace<StorageImpl>,
        base: Granted<'_, Directory, Mutate>,
        path: &str,
        now: u64,
    ) -> FsOpResult<Self> {
        let absolute = child_below(base.descriptor(), path)?;
        Ok(Self {
            namespace,
            absolute,
            now,
        })
    }

    pub(crate) async fn execute(self) -> FsOpResult<()> {
        self.namespace
            .remove_directory(&self.absolute, self.now)
            .await
            .map_err(fs_error_code)
    }
}

pub(crate) async fn remove_directory_at<StorageImpl: crate::Storage>(
    namespace: &Namespace<StorageImpl>,
    base: Granted<'_, Directory, Mutate>,
    path: &str,
    now: u64,
) -> FsOpResult<()> {
    PreparedRemoveDirectoryAt::new(namespace.clone(), base, path, now)?
        .execute()
        .await
}

pub struct PreparedUnlinkFileAt<StorageImpl: crate::Storage> {
    namespace: Namespace<StorageImpl>,
    absolute: String,
    now: u64,
}

impl<StorageImpl: crate::Storage> PreparedUnlinkFileAt<StorageImpl> {
    pub(crate) fn new(
        namespace: Namespace<StorageImpl>,
        base: Granted<'_, Directory, Mutate>,
        path: &str,
        now: u64,
    ) -> FsOpResult<Self> {
        let absolute = child_below(base.descriptor(), path)?;
        Ok(Self {
            namespace,
            absolute,
            now,
        })
    }

    pub(crate) async fn execute(self) -> FsOpResult<()> {
        let resolved = resolve(&self.namespace, &self.absolute)?;
        if resolved.is_mount_root() {
            return Err(fs_types::ErrorCode::IsDirectory);
        }
        resolved
            .writable()
            .map_err(fs_error_code)?
            .unlink(resolved.path(), self.now)
            .await
            .map_err(fs_error_code)
    }
}

pub(crate) async fn unlink_file_at<StorageImpl: crate::Storage>(
    namespace: &Namespace<StorageImpl>,
    base: Granted<'_, Directory, Mutate>,
    path: &str,
    now: u64,
) -> FsOpResult<()> {
    PreparedUnlinkFileAt::new(namespace.clone(), base, path, now)?
        .execute()
        .await
}

/// Renames within one mount; across two, `cross-device`. A rename is a link
/// that also removes the source entry, so it follows the link's rule.
pub struct PreparedRenameAt<StorageImpl: crate::Storage> {
    namespace: Namespace<StorageImpl>,
    absolute: String,
    destination: String,
    now: u64,
}

impl<StorageImpl: crate::Storage> PreparedRenameAt<StorageImpl> {
    pub(crate) fn new(
        namespace: Namespace<StorageImpl>,
        rename: RenameGrant<'_, '_>,
        source_path: &str,
        destination_path: &str,
        now: u64,
    ) -> FsOpResult<Self> {
        let absolute = child_below(rename.source(), source_path)?;
        let destination = child_below(rename.destination(), destination_path)?;
        Ok(Self {
            namespace,
            absolute,
            destination,
            now,
        })
    }

    pub(crate) async fn execute(self) -> FsOpResult<()> {
        self.namespace
            .rename(&self.absolute, &self.destination, self.now)
            .await
            .map_err(fs_error_code)
    }
}

pub(crate) async fn rename_at<StorageImpl: crate::Storage>(
    namespace: &Namespace<StorageImpl>,
    rename: RenameGrant<'_, '_>,
    source_path: &str,
    destination_path: &str,
    now: u64,
) -> FsOpResult<()> {
    PreparedRenameAt::new(
        namespace.clone(),
        rename,
        source_path,
        destination_path,
        now,
    )?
    .execute()
    .await
}

/// Links within one mount; across two, `cross-device`.
pub struct PreparedLinkAt<StorageImpl: crate::Storage> {
    namespace: Namespace<StorageImpl>,
    absolute: String,
    destination: String,
    now: u64,
}

impl<StorageImpl: crate::Storage> PreparedLinkAt<StorageImpl> {
    pub(crate) fn new(
        namespace: Namespace<StorageImpl>,
        link: AliasGrant<'_, '_>,
        source_path: &str,
        destination_path: &str,
        now: u64,
    ) -> FsOpResult<Self> {
        let absolute = child_path(link.source(), source_path)?;
        let destination = child_path(link.destination(), destination_path)?;
        Ok(Self {
            namespace,
            absolute,
            destination,
            now,
        })
    }

    pub(crate) async fn execute(self) -> FsOpResult<()> {
        self.namespace
            .link(&self.absolute, &self.destination, self.now)
            .await
            .map_err(fs_error_code)
    }
}

pub(crate) async fn link_at<StorageImpl: crate::Storage>(
    namespace: &Namespace<StorageImpl>,
    link: AliasGrant<'_, '_>,
    source_path: &str,
    destination_path: &str,
    now: u64,
) -> FsOpResult<()> {
    PreparedLinkAt::new(namespace.clone(), link, source_path, destination_path, now)?
        .execute()
        .await
}

/// Creates a symbolic link at `path` below `base` whose target text is
/// `target`. The target must name something inside the link's directory.
pub struct PreparedSymlinkAt<StorageImpl: crate::Storage> {
    namespace: Namespace<StorageImpl>,
    absolute: String,
    target: String,
    now: u64,
}

impl<StorageImpl: crate::Storage> PreparedSymlinkAt<StorageImpl> {
    pub(crate) fn new(
        namespace: Namespace<StorageImpl>,
        base: Granted<'_, Directory, Mutate>,
        target: &str,
        path: &str,
        now: u64,
    ) -> FsOpResult<Self> {
        let absolute = child_below(base.descriptor(), path)?;
        crate::symlink_target(&absolute, target).map_err(fs_error_code)?;
        Ok(Self {
            namespace,
            absolute,
            target: target.to_owned(),
            now,
        })
    }

    pub(crate) async fn execute(self) -> FsOpResult<()> {
        let resolved = resolve(&self.namespace, &self.absolute)?;
        resolved
            .writable()
            .map_err(fs_error_code)?
            .symlink(&self.target, resolved.path(), self.now)
            .await
            .map_err(fs_error_code)
    }
}

pub(crate) async fn symlink_at<StorageImpl: crate::Storage>(
    namespace: &Namespace<StorageImpl>,
    base: Granted<'_, Directory, Mutate>,
    target: &str,
    path: &str,
    now: u64,
) -> FsOpResult<()> {
    PreparedSymlinkAt::new(namespace.clone(), base, target, path, now)?
        .execute()
        .await
}

/// The target text of the symbolic link at `path` below `base`, refused
/// when it would name something outside the link's directory.
pub struct PreparedReadlinkAt<StorageImpl: crate::Storage> {
    namespace: Namespace<StorageImpl>,
    absolute: String,
}

impl<StorageImpl: crate::Storage> PreparedReadlinkAt<StorageImpl> {
    pub(crate) fn new(
        namespace: Namespace<StorageImpl>,
        base: Granted<'_, Directory, Read>,
        path: &str,
    ) -> FsOpResult<Self> {
        let absolute = child_path(base.descriptor(), path)?;
        Ok(Self {
            namespace,
            absolute,
        })
    }

    pub(crate) async fn execute(self) -> FsOpResult<String> {
        let resolved = resolve(&self.namespace, &self.absolute)?;
        let target = resolved
            .fs()
            .read_link(resolved.path())
            .await
            .map_err(fs_error_code)?;
        crate::symlink_target(resolved.absolute(), &target).map_err(fs_error_code)?;
        Ok(target)
    }
}

pub(crate) async fn readlink_at<StorageImpl: crate::Storage>(
    namespace: &Namespace<StorageImpl>,
    base: Granted<'_, Directory, Read>,
    path: &str,
) -> FsOpResult<String> {
    PreparedReadlinkAt::new(namespace.clone(), base, path)?
        .execute()
        .await
}

/// Makes the descriptor's object durable: its data, and its metadata
/// unless `data_only`.
pub(crate) async fn sync<StorageImpl>(
    namespace: &Namespace<StorageImpl>,
    descriptor: &FsDescriptor,
    data_only: bool,
) -> FsOpResult<()>
where
    StorageImpl: crate::Storage,
{
    let resolved = resolve(namespace, &descriptor.path)?;
    let fs = resolved.fs();
    if data_only {
        fs.sync_data(resolved.path()).await
    } else {
        fs.sync(resolved.path()).await
    }
    .map_err(fs_error_code)
}

/// Reads the whole of the program file `absolute` names, typed by the
/// layer that produced its bytes: only the boot image's own bytes may
/// skip signature verification (#483).
///
/// `floor` is the directory whose grant admits the load
/// ([`crate::ProcessAuthority::program_load_floor`]); a symbolic link
/// that leads out of it is refused. The filesystem's own error comes back
/// untranslated: the caller decides what each kind means to its surface.
pub(crate) async fn read_program_file<StorageImpl>(
    namespace: &Namespace<StorageImpl>,
    absolute: &str,
    floor: &str,
) -> FsResult<FileContents>
where
    StorageImpl: crate::Storage,
{
    let resolved = namespace
        .resolve_following(absolute, Follow::Within(floor))
        .await?;
    resolved.read_whole().await
}

/// Creates or replaces the file `absolute` names with `bytes`.
pub(crate) async fn write_program_file<StorageImpl>(
    namespace: &Namespace<StorageImpl>,
    absolute: &str,
    bytes: &[u8],
    now: u64,
) -> FsOpResult<()>
where
    StorageImpl: crate::Storage,
{
    let resolved = resolve(namespace, absolute)?;
    let fs = resolved.writable().map_err(fs_error_code)?;
    fs.open(
        resolved.path(),
        OpenFlags::CREATE | OpenFlags::TRUNCATE,
        now,
    )
    .await
    .map_err(fs_error_code)?;
    let landed = write_resolved(&resolved, WritePosition::At(0), bytes, now).await?;
    // A file replaced in part is not the file the caller asked for.
    if landed.len != bytes.len() {
        return Err(fs_types::ErrorCode::InsufficientSpace);
    }
    Ok(())
}

/// What one bounded read resolves with.
type ChunkReadResult = FsOpResult<Bytes>;

/// Prepares destinations without taking bytes from the stream.
async fn prepare_stream_write<S: crate::Storage>(
    held: HeldPath<S>,
    mode: WritePosition,
    len: usize,
    now: u64,
) -> FsOpResult<MountedWrite<S>> {
    let resolved = held.resolved();
    resolved
        .writable()
        .map_err(fs_error_code)?
        .prepare_write(resolved.path(), mode, len, now)
        .await
        .map_err(fs_error_code)
}

async fn submit_stream_write<S: crate::Storage>(
    filled: <MountedWrite<S> as PreparedWrite>::Filled,
) -> FsOpResult<WriteProgress<MountedWrite<S>>> {
    filled.submit().await.map_err(fs_error_code)
}

/// Answers the `future<result>` a `read-via-stream`, `write-via-stream`,
/// `append-via-stream` or `read-directory` handed the guest, once. A
/// dropped receiver means the guest stopped caring, which is not this
/// side's problem.
fn complete_file_transfer(
    result: &mut Option<oneshot::Sender<FsOpResult<()>>>,
    outcome: FsOpResult<()>,
) {
    if let Some(sender) = result.take() {
        let _ = sender.send(outcome);
    }
}

pin_project! {
    /// The `read-via-stream` source for one file.
    ///
    /// The in-flight read is held by value under a `Fut` parameter that
    /// [`file_read_producer`] infers from [`read_held`], and `start`
    /// mints the next one: only one chunk is ever in flight, so a stream
    /// over a large file never holds more than one chunk of kernel memory.
    pub(super) struct FileReadStreamProducer<StorageImpl: crate::Storage, Fut> {
        pub(super) held: HeldPath<StorageImpl>,
        pub(super) offset: u64,
        pub(super) chunk_bytes: usize,
        pub(super) start: fn(HeldPath<StorageImpl>, u64, usize) -> Fut,
        #[pin]
        pub(super) pending: Option<Fut>,
        pub(super) result: Option<oneshot::Sender<FsOpResult<()>>>,
    }

    impl<StorageImpl: crate::Storage, Fut> PinnedDrop for FileReadStreamProducer<StorageImpl, Fut> {
        fn drop(this: Pin<&mut Self>) {
            complete_file_transfer(this.project().result, Ok(()));
        }
    }
}

/// The `read-via-stream` source for `held`, from `offset`.
pub(super) fn file_read_producer<StorageImpl>(
    held: HeldPath<StorageImpl>,
    offset: u64,
    chunk_bytes: usize,
    result: oneshot::Sender<FsOpResult<()>>,
) -> FileReadStreamProducer<StorageImpl, impl core::future::Future<Output = ChunkReadResult> + Send>
where
    StorageImpl: crate::Storage,
{
    FileReadStreamProducer {
        held,
        offset,
        chunk_bytes,
        start: read_held::<StorageImpl>,
        pending: None,
        result: Some(result),
    }
}

impl<T: 'static, StorageImpl, Fut> StreamProducer<T> for FileReadStreamProducer<StorageImpl, Fut>
where
    StorageImpl: crate::Storage,
    Fut: core::future::Future<Output = ChunkReadResult> + Send + 'static,
{
    type Item = u8;
    type Buffer = BytesStreamBuffer;

    fn poll_produce<'a>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut store: wasmtime::StoreContextMut<'_, T>,
        mut destination: Destination<'a, Self::Item, Self::Buffer>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        let mut this = self.project();
        if finish {
            complete_file_transfer(this.result, Ok(()));
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        if this.pending.is_none() {
            let capacity = destination.remaining(&mut store);
            if capacity == Some(0) {
                return Poll::Ready(Ok(StreamResult::Completed));
            }
            let request = capacity.unwrap_or(*this.chunk_bytes).min(*this.chunk_bytes);
            let read = (*this.start)(this.held.clone(), *this.offset, request);
            this.pending.set(Some(read));
        }
        let bytes = match this.pending.as_mut().as_pin_mut() {
            Some(pending) => match pending.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result,
            },
            None => unreachable!("a read future was started above"),
        };
        this.pending.set(None);
        match bytes {
            Ok(bytes) if bytes.is_empty() => {
                complete_file_transfer(this.result, Ok(()));
                Poll::Ready(Ok(StreamResult::Dropped))
            }
            Ok(bytes) => {
                *this.offset = this
                    .offset
                    .checked_add(bytes.len() as u64)
                    .ok_or_else(|| wasmtime::Error::new(WasiAdapterTrap::FileReadOffsetOverflow))?;
                destination.set_buffer(BytesStreamBuffer::new(bytes));
                Poll::Ready(Ok(StreamResult::Completed))
            }
            Err(error) => {
                complete_file_transfer(this.result, Err(error));
                Poll::Ready(Ok(StreamResult::Dropped))
            }
        }
    }
}

pin_project! {
    #[project = FileWriteStateProjection]
    enum FileWriteState<Prepare, Submit> {
        Idle,
        Preparing { #[pin] future: Prepare },
        /// `len` is the round being submitted, `taken` the bytes of the whole
        /// write the stream has handed over so far, this round's included.
        Submitting { #[pin] future: Submit, len: usize, taken: usize },
    }
}

pin_project! {
    /// A file stream fills filesystem-owned destinations between awaits.
    /// The held resolution keeps its mount busy throughout the stream.
    pub(super) struct FileWriteConsumer<T, CpuImpl, Net, StorageImpl, W, Prepare, Submit>
    where
        CpuImpl: Cpu,
        CpuImpl: Clone,
        Net: ComponentHostNetwork,
        StorageImpl: crate::Storage,
        W: PreparedWrite,
    {
        getter: fn(&mut T) -> &mut StoreData<CpuImpl, Net, StorageImpl>,
        held: HeldPath<StorageImpl>,
        mode: WritePosition,
        prepare: fn(HeldPath<StorageImpl>, WritePosition, usize, u64) -> Prepare,
        submit: fn(W::Filled) -> Submit,
        #[pin]
        state: FileWriteState<Prepare, Submit>,
        result: Option<oneshot::Sender<FsOpResult<()>>>,
    }

    impl<T, CpuImpl, Net, StorageImpl, W, Prepare, Submit> PinnedDrop
        for FileWriteConsumer<T, CpuImpl, Net, StorageImpl, W, Prepare, Submit>
    where
        CpuImpl: Cpu,
        CpuImpl: Clone,
        Net: ComponentHostNetwork,
        StorageImpl: crate::Storage,
        W: PreparedWrite,
    {
        fn drop(this: Pin<&mut Self>) {
            complete_file_transfer(this.project().result, Ok(()));
        }
    }
}

/// The `write-via-stream` and `append-via-stream` sink for `held`.
pub(super) fn file_write_consumer<T, CpuImpl, Net, StorageImpl>(
    getter: fn(&mut T) -> &mut StoreData<CpuImpl, Net, StorageImpl>,
    held: HeldPath<StorageImpl>,
    mode: WritePosition,
    result: oneshot::Sender<FsOpResult<()>>,
) -> impl StreamConsumer<T, Item = u8>
where
    T: 'static,
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    FileWriteConsumer {
        getter,
        held,
        mode,
        prepare: prepare_stream_write::<StorageImpl>,
        submit: submit_stream_write::<StorageImpl>,
        state: FileWriteState::Idle,
        result: Some(result),
    }
}

impl<T: 'static, CpuImpl, Net, StorageImpl, W, Prepare, Submit> StreamConsumer<T>
    for FileWriteConsumer<T, CpuImpl, Net, StorageImpl, W, Prepare, Submit>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
    W: PreparedWrite + 'static,
    Prepare: core::future::Future<Output = FsOpResult<W>> + Send + 'static,
    Submit: core::future::Future<Output = FsOpResult<WriteProgress<W>>> + Send + 'static,
{
    type Item = u8;

    fn poll_consume(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut store: wasmtime::StoreContextMut<'_, T>,
        source: Source<'_, Self::Item>,
        finish: bool,
    ) -> Poll<Result<StreamResult>> {
        let mut this = self.project();
        let now = (*this.getter)(store.data_mut()).now_nanos();
        let mut source = source.as_direct(store);
        // The bytes of the write in flight the earlier rounds took.
        let mut taken = 0;
        loop {
            let staged = match this.state.as_mut().project() {
                FileWriteStateProjection::Idle => {
                    if finish {
                        return Poll::Ready(Ok(StreamResult::Cancelled));
                    }
                    let available = source.remaining().len();
                    if available == 0 {
                        return Poll::Ready(Ok(StreamResult::Completed));
                    }
                    let future = (*this.prepare)(this.held.clone(), *this.mode, available, now);
                    this.state.set(FileWriteState::Preparing { future });
                    continue;
                }
                FileWriteStateProjection::Preparing { future } => {
                    if finish {
                        this.state.set(FileWriteState::Idle);
                        return Poll::Ready(Ok(StreamResult::Cancelled));
                    }
                    let result = match future.poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(result) => result,
                    };
                    this.state.set(FileWriteState::Idle);
                    result
                }
                FileWriteStateProjection::Submitting {
                    future,
                    len,
                    taken: submitted,
                } => {
                    let result = match future.poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(result) => result,
                    };
                    let len = *len;
                    taken = *submitted;
                    this.state.set(FileWriteState::Idle);
                    match result {
                        Ok(progress) => {
                            if let WritePosition::At(offset) = this.mode {
                                *offset = offset.checked_add(len as u64).ok_or_else(|| {
                                    wasmtime::Error::new(WasiAdapterTrap::FileWriteOffsetOverflow)
                                })?;
                            }
                            match progress {
                                WriteProgress::More(next) if !finish => Ok(next),
                                // A write that ran out of space stored a prefix of
                                // bytes the stream already took, so the stream can
                                // only end with the out-of-space error.
                                WriteProgress::Done(landed) if landed.len != taken => {
                                    Err(fs_types::ErrorCode::InsufficientSpace)
                                }
                                // Cancellation completes the consumed round and drops any
                                // unfilled next round without taking more guest bytes.
                                _ => return Poll::Ready(Ok(StreamResult::Completed)),
                            }
                        }
                        Err(error) => Err(error),
                    }
                }
            };
            let staged = match staged {
                Ok(staged) => staged,
                Err(error) => {
                    complete_file_transfer(this.result, Err(error));
                    return Poll::Ready(Ok(StreamResult::Dropped));
                }
            };
            let len = staged.staged_len();
            let filled = {
                let bytes = source.remaining();
                let mut cursor = 0;
                let filled = staged.fill(|_, destination| {
                    let end = cursor + destination.len();
                    destination.copy_from_slice(&bytes[cursor..end]);
                    cursor = end;
                });
                source.mark_read(cursor);
                filled
            };
            let future = (*this.submit)(filled);
            this.state.set(FileWriteState::Submitting {
                future,
                len,
                taken: taken + len,
            });
        }
    }
}

pin_project! {
    /// The `read-directory` stream: the whole listing, once it arrives.
    pub(super) struct DirectoryStreamProducer<Fut> {
        #[pin]
        listing: Fut,
        result: Option<oneshot::Sender<FsOpResult<()>>>,
    }

    impl<Fut> PinnedDrop for DirectoryStreamProducer<Fut> {
        fn drop(this: Pin<&mut Self>) {
            complete_file_transfer(this.project().result, Ok(()));
        }
    }
}

/// Lists `descriptor` through an owned namespace, for a stream that must
/// own the listing across polls.
async fn list_owned<StorageImpl>(
    namespace: Namespace<StorageImpl>,
    descriptor: FsDescriptor,
) -> FsOpResult<Vec<fs_types::DirectoryEntry>>
where
    StorageImpl: crate::Storage,
{
    read_directory(&namespace, descriptor.grant()?).await
}

pub(super) fn directory_producer<StorageImpl>(
    namespace: Namespace<StorageImpl>,
    descriptor: FsDescriptor,
    result: oneshot::Sender<FsOpResult<()>>,
) -> DirectoryStreamProducer<
    impl core::future::Future<Output = FsOpResult<Vec<fs_types::DirectoryEntry>>> + Send,
>
where
    StorageImpl: crate::Storage,
{
    DirectoryStreamProducer {
        listing: list_owned(namespace, descriptor),
        result: Some(result),
    }
}

impl<T: 'static, Fut> StreamProducer<T> for DirectoryStreamProducer<Fut>
where
    Fut: core::future::Future<Output = FsOpResult<Vec<fs_types::DirectoryEntry>>> + Send + 'static,
{
    type Item = fs_types::DirectoryEntry;
    type Buffer = wasmtime::component::VecBuffer<fs_types::DirectoryEntry>;

    fn poll_produce<'a>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        _: wasmtime::StoreContextMut<'_, T>,
        mut destination: Destination<'a, Self::Item, Self::Buffer>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        let this = self.project();
        let listing = match this.listing.poll(cx) {
            Poll::Ready(listing) => listing,
            Poll::Pending if finish => {
                complete_file_transfer(this.result, Ok(()));
                return Poll::Ready(Ok(StreamResult::Cancelled));
            }
            Poll::Pending => return Poll::Pending,
        };
        match listing {
            Ok(entries) => {
                destination.set_buffer(entries.into());
                complete_file_transfer(this.result, Ok(()));
            }
            Err(error) => complete_file_transfer(this.result, Err(error)),
        }
        Poll::Ready(Ok(StreamResult::Dropped))
    }
}

pub(crate) fn preopen_descriptor(preopen: &crate::DirectoryPreopen) -> FsDescriptor {
    FsDescriptor {
        path: preopen.source_path().to_owned(),
        kind: FsNodeKind::Directory,
        flags: descriptor_flags_from_authority(preopen.rights()),
        identity: None,
        mount: None,
    }
}

pub(super) fn descriptor_flags_from_authority(
    rights: crate::DirectoryAuthorityRights,
) -> fs_types::DescriptorFlags {
    let mut flags = fs_types::DescriptorFlags::empty();
    if rights.contains(crate::DirectoryAuthorityRights::READ) {
        flags |= fs_types::DescriptorFlags::READ;
    }
    if rights.contains(crate::DirectoryAuthorityRights::WRITE) {
        flags |= fs_types::DescriptorFlags::WRITE;
    }
    if rights.contains(crate::DirectoryAuthorityRights::MUTATE_DIRECTORY) {
        flags |= fs_types::DescriptorFlags::MUTATE_DIRECTORY;
    }
    flags
}

pub(crate) fn validate_descriptor_flags_within_base(
    base_flags: fs_types::DescriptorFlags,
    requested: fs_types::DescriptorFlags,
) -> FsOpResult<()> {
    let authority_flags = fs_types::DescriptorFlags::READ
        | fs_types::DescriptorFlags::WRITE
        | fs_types::DescriptorFlags::MUTATE_DIRECTORY;
    if !base_flags.contains(requested & authority_flags) {
        return Err(fs_types::ErrorCode::ReadOnly);
    }
    Ok(())
}

pub(crate) fn effective_open_descriptor_flags(
    base_flags: fs_types::DescriptorFlags,
    requested: fs_types::DescriptorFlags,
    kind: FsNodeKind,
) -> FsOpResult<fs_types::DescriptorFlags> {
    let mut effective = fs_types::DescriptorFlags::empty();
    if requested.contains(fs_types::DescriptorFlags::READ) {
        effective |= fs_types::DescriptorFlags::READ;
    }
    if requested.contains(fs_types::DescriptorFlags::WRITE) {
        effective |= fs_types::DescriptorFlags::WRITE;
    }
    if kind == FsNodeKind::Directory
        && requested.contains(fs_types::DescriptorFlags::MUTATE_DIRECTORY)
    {
        effective |= fs_types::DescriptorFlags::MUTATE_DIRECTORY;
    }
    validate_descriptor_flags_within_base(base_flags, effective)?;
    Ok(effective)
}

/// A descriptor of the store's table and the store's namespace, for an
/// operation to run on after the store is released.
pub(crate) fn descriptor_in<CpuImpl, Net, StorageImpl>(
    store: &mut StoreData<CpuImpl, Net, StorageImpl>,
    resource: &Resource<FsDescriptor>,
) -> FsOpResult<(FsDescriptor, Namespace<StorageImpl>)>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let descriptor = get_fs_descriptor(store, resource)?;
    Ok((descriptor, store.filesystem().clone()))
}

/// Two descriptors of the store's table and the store's namespace.
pub(crate) fn descriptor_pair_in<CpuImpl, Net, StorageImpl>(
    store: &mut StoreData<CpuImpl, Net, StorageImpl>,
    first: &Resource<FsDescriptor>,
    second: &Resource<FsDescriptor>,
) -> FsOpResult<(FsDescriptor, FsDescriptor, Namespace<StorageImpl>)>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let first = get_fs_descriptor(store, first)?;
    let second = get_fs_descriptor(store, second)?;
    Ok((first, second, store.filesystem().clone()))
}

/// Answers a stream's `future<result>` with what its producer reports, or
/// success when the producer went away without reporting.
fn transfer_outcome<S: wasmtime::AsContextMut>(
    store: S,
    receiver: oneshot::Receiver<FsOpResult<()>>,
) -> Result<FutureReader<FsOpResult<()>>> {
    FutureReader::new(store, async move {
        Ok::<_, wasmtime::Error>(receiver.await.unwrap_or(Ok(())))
    })
}

/// A `future<result>` that already failed with `error`.
fn failed_transfer<S: wasmtime::AsContextMut>(
    store: S,
    error: fs_types::ErrorCode,
) -> Result<FutureReader<FsOpResult<()>>> {
    FutureReader::new(store, async move { Ok::<_, wasmtime::Error>(Err(error)) })
}

impl<CpuImpl, Net, StorageImpl> wasi::filesystem::preopens::Host
    for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn get_directories(&mut self) -> Result<Vec<(Resource<FsDescriptor>, String)>> {
        let preopens = self.process_authority().directory_preopens().to_vec();
        preopens
            .iter()
            .map(|preopen| {
                let descriptor = preopen_descriptor(preopen);
                let resource = self.table.push(descriptor)?;
                Ok((resource, preopen.guest_name().to_owned()))
            })
            .collect()
    }
}

impl<CpuImpl, Net, StorageImpl> wasi::filesystem::types::Host
    for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn convert_error_code(&mut self, error: FsError) -> Result<fs_types::ErrorCode> {
        error.downcast()
    }
}

impl<CpuImpl, Net, StorageImpl> wasi::filesystem::types::HostDescriptor
    for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn drop(&mut self, descriptor: Resource<FsDescriptor>) -> Result<()> {
        self.table.delete(descriptor)?;
        Ok(())
    }
}

impl<CpuImpl, Net, StorageImpl, U> wasi::filesystem::types::HostDescriptorWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn read_via_stream(
        mut accessor: Access<'_, U, Self>,
        descriptor: Resource<FsDescriptor>,
        offset: u64,
    ) -> Result<(StreamReader<u8>, FutureReader<FsOpResult<()>>)> {
        let resolved =
            descriptor_in(accessor.get(), &descriptor).and_then(|(descriptor, namespace)| {
                read_stream_target(&namespace, descriptor.grant()?)
            });
        match resolved {
            Ok(resolved) => {
                let (tx, rx) = oneshot::channel();
                let stream = StreamReader::new(
                    &mut accessor,
                    file_read_producer(resolved, offset, FILE_READ_CHUNK_BYTES, tx),
                )?;
                Ok((stream, transfer_outcome(&mut accessor, rx)?))
            }
            Err(error) => {
                let stream = StreamReader::new(&mut accessor, Vec::<u8>::new())?;
                Ok((stream, failed_transfer(&mut accessor, error)?))
            }
        }
    }

    fn write_via_stream(
        accessor: Access<'_, U, Self>,
        descriptor: Resource<FsDescriptor>,
        data: StreamReader<u8>,
        offset: u64,
    ) -> Result<FutureReader<FsOpResult<()>>> {
        pipe_into_file(accessor, descriptor, data, WritePosition::At(offset))
    }

    fn append_via_stream(
        accessor: Access<'_, U, Self>,
        descriptor: Resource<FsDescriptor>,
        data: StreamReader<u8>,
    ) -> Result<FutureReader<FsOpResult<()>>> {
        pipe_into_file(accessor, descriptor, data, WritePosition::End)
    }

    async fn advise(
        accessor: &Accessor<U, Self>,
        descriptor: Resource<FsDescriptor>,
        _: u64,
        _: u64,
        _: fs_types::Advice,
    ) -> Result<(), FsError> {
        accessor.with(|mut access| {
            get_fs_descriptor(access.get(), &descriptor)?;
            Ok(())
        })
    }

    async fn sync_data(
        accessor: &Accessor<U, Self>,
        descriptor: Resource<FsDescriptor>,
    ) -> Result<(), FsError> {
        let (descriptor, namespace) =
            accessor.with(|mut access| descriptor_in(access.get(), &descriptor))?;
        Ok(sync(&namespace, &descriptor, true).await?)
    }

    async fn get_flags(
        accessor: &Accessor<U, Self>,
        descriptor: Resource<FsDescriptor>,
    ) -> Result<fs_types::DescriptorFlags, FsError> {
        accessor.with(|mut access| {
            let descriptor = get_fs_descriptor(access.get(), &descriptor)?;
            Ok(descriptor.flags)
        })
    }

    async fn get_type(
        accessor: &Accessor<U, Self>,
        descriptor: Resource<FsDescriptor>,
    ) -> Result<fs_types::DescriptorType, FsError> {
        let profile = accessor.with(|mut access| component_fs_profile(access.get()));
        let result = accessor.with(|mut access| {
            let descriptor = get_fs_descriptor(access.get(), &descriptor)?;
            Ok(descriptor_type_from_node_kind(descriptor.kind))
        });
        record_component_fs_profile(profile, "get-type");
        result
    }

    async fn set_size(
        accessor: &Accessor<U, Self>,
        descriptor: Resource<FsDescriptor>,
        size: u64,
    ) -> Result<(), FsError> {
        let (descriptor, namespace, now) = accessor.with(|mut access| {
            let (descriptor, namespace) = descriptor_in(access.get(), &descriptor)?;
            Ok::<_, fs_types::ErrorCode>((descriptor, namespace, access.get().now_nanos()))
        })?;
        Ok(self::set_size(&namespace, descriptor.grant()?, size, now).await?)
    }

    async fn set_times(
        accessor: &Accessor<U, Self>,
        descriptor: Resource<FsDescriptor>,
        data_access_timestamp: fs_types::NewTimestamp,
        data_modification_timestamp: fs_types::NewTimestamp,
    ) -> Result<(), FsError> {
        let (descriptor, namespace, access_nanos, modified_nanos, now) =
            accessor.with(|mut access| {
                let now = access.get().system_time_nanos();
                let access_nanos = p3_new_timestamp_nanos(data_access_timestamp, now)?;
                let modified_nanos = p3_new_timestamp_nanos(data_modification_timestamp, now)?;
                let (descriptor, namespace) = descriptor_in(access.get(), &descriptor)?;
                Ok::<_, fs_types::ErrorCode>((
                    descriptor,
                    namespace,
                    access_nanos,
                    modified_nanos,
                    now,
                ))
            })?;
        Ok(self::set_times(
            &namespace,
            descriptor.grant_touch()?,
            access_nanos,
            modified_nanos,
            now,
        )
        .await?)
    }

    fn read_directory(
        mut accessor: Access<'_, U, Self>,
        descriptor: Resource<FsDescriptor>,
    ) -> Result<(
        StreamReader<fs_types::DirectoryEntry>,
        FutureReader<FsOpResult<()>>,
    )> {
        match descriptor_in(accessor.get(), &descriptor) {
            Ok((descriptor, namespace)) => {
                let (tx, rx) = oneshot::channel();
                let stream = StreamReader::new(
                    &mut accessor,
                    directory_producer(namespace, descriptor, tx),
                )?;
                Ok((stream, transfer_outcome(&mut accessor, rx)?))
            }
            Err(error) => {
                let stream =
                    StreamReader::new(&mut accessor, Vec::<fs_types::DirectoryEntry>::new())?;
                Ok((stream, failed_transfer(&mut accessor, error)?))
            }
        }
    }

    async fn sync(
        accessor: &Accessor<U, Self>,
        descriptor: Resource<FsDescriptor>,
    ) -> Result<(), FsError> {
        let (descriptor, namespace) =
            accessor.with(|mut access| descriptor_in(access.get(), &descriptor))?;
        Ok(self::sync(&namespace, &descriptor, false).await?)
    }

    type CreateDirectoryAtPrepared = FsOpResult<PreparedCreateDirectoryAt<StorageImpl>>;
    fn prepare_create_directory_at(
        store: &mut &mut StoreData<CpuImpl, Net, StorageImpl>,
        descriptor: Resource<FsDescriptor>,
        path: &str,
    ) -> Result<Self::CreateDirectoryAtPrepared> {
        Ok((|| -> FsOpResult<_> {
            let (base, namespace, now) = (|| {
                let (base, namespace) = descriptor_in(store, &descriptor)?;
                Ok::<_, fs_types::ErrorCode>((base, namespace, store.now_nanos()))
            })()?;
            PreparedCreateDirectoryAt::new(namespace, base.grant()?, path, now)
        })())
    }
    async fn create_directory_at(
        _accessor: &Accessor<U, Self>,
        prepared: Self::CreateDirectoryAtPrepared,
    ) -> Result<(), FsError> {
        Ok(prepared?.execute().await?)
    }

    async fn stat(
        accessor: &Accessor<U, Self>,
        descriptor: Resource<FsDescriptor>,
    ) -> Result<fs_types::DescriptorStat, FsError> {
        let profile = accessor.with(|mut access| component_fs_profile(access.get()));
        let (descriptor, namespace) =
            accessor.with(|mut access| descriptor_in(access.get(), &descriptor))?;
        let result = stat_path(&namespace, &descriptor.path, Follow::No)
            .await
            .map(|metadata| descriptor_stat(&metadata));
        record_component_fs_profile(profile, "stat");
        Ok(result?)
    }

    type StatAtPrepared = PreparedStat<CpuImpl, Net, StorageImpl>;

    fn prepare_stat_at(
        store: &mut &mut StoreData<CpuImpl, Net, StorageImpl>,
        descriptor: Resource<FsDescriptor>,
        path_flags: fs_types::PathFlags,
        path: &str,
    ) -> Result<Self::StatAtPrepared> {
        Ok(prepare_stat(store, descriptor, path_flags, path))
    }

    async fn stat_at(
        _accessor: &Accessor<U, Self>,
        prepared: Self::StatAtPrepared,
    ) -> Result<fs_types::DescriptorStat, FsError> {
        Ok(descriptor_stat(&stat_prepared(prepared, "stat-at").await?))
    }

    type SetTimesAtPrepared = FsOpResult<PreparedSetTimesAt<StorageImpl>>;
    fn prepare_set_times_at(
        store: &mut &mut StoreData<CpuImpl, Net, StorageImpl>,
        descriptor: Resource<FsDescriptor>,
        _: fs_types::PathFlags,
        path: &str,
        data_access_timestamp: fs_types::NewTimestamp,
        data_modification_timestamp: fs_types::NewTimestamp,
    ) -> Result<Self::SetTimesAtPrepared> {
        Ok((|| -> FsOpResult<_> {
            let (base, namespace, access_nanos, modified_nanos, now) = (|| {
                let now = store.system_time_nanos();
                let access_nanos = p3_new_timestamp_nanos(data_access_timestamp, now)?;
                let modified_nanos = p3_new_timestamp_nanos(data_modification_timestamp, now)?;
                let (base, namespace) = descriptor_in(store, &descriptor)?;
                Ok::<_, fs_types::ErrorCode>((base, namespace, access_nanos, modified_nanos, now))
            })()?;
            PreparedSetTimesAt::new(
                namespace,
                base.grant()?,
                path,
                access_nanos,
                modified_nanos,
                now,
            )
        })())
    }
    async fn set_times_at(
        _accessor: &Accessor<U, Self>,
        prepared: Self::SetTimesAtPrepared,
    ) -> Result<(), FsError> {
        Ok(prepared?.execute().await?)
    }

    type LinkAtPrepared = FsOpResult<PreparedLinkAt<StorageImpl>>;
    fn prepare_link_at(
        store: &mut &mut StoreData<CpuImpl, Net, StorageImpl>,
        source_descriptor: Resource<FsDescriptor>,
        _: fs_types::PathFlags,
        source_path: &str,
        destination_descriptor: Resource<FsDescriptor>,
        destination_path: &str,
    ) -> Result<Self::LinkAtPrepared> {
        Ok((|| -> FsOpResult<_> {
            let (source_base, destination_base, namespace, now) = (|| {
                let authority = store.process_authority();
                if authority.derive_link_source_cap().is_err()
                    || authority.derive_link_target_directory_cap().is_err()
                {
                    return Err(fs_types::ErrorCode::NotPermitted);
                }
                let (source, destination, namespace) =
                    descriptor_pair_in(store, &source_descriptor, &destination_descriptor)?;
                Ok((source, destination, namespace, store.now_nanos()))
            })()?;
            PreparedLinkAt::new(
                namespace,
                source_base.grant()?.alias_into(destination_base.grant()?)?,
                source_path,
                destination_path,
                now,
            )
        })())
    }
    async fn link_at(
        _accessor: &Accessor<U, Self>,
        prepared: Self::LinkAtPrepared,
    ) -> Result<(), FsError> {
        Ok(prepared?.execute().await?)
    }

    type OpenAtPrepared = PreparedOpenAt<CpuImpl, Net, StorageImpl>;

    fn prepare_open_at(
        store: &mut &mut StoreData<CpuImpl, Net, StorageImpl>,
        descriptor: Resource<FsDescriptor>,
        path_flags: fs_types::PathFlags,
        path: &str,
        open_flags: fs_types::OpenFlags,
        flags: fs_types::DescriptorFlags,
    ) -> Result<Self::OpenAtPrepared> {
        Ok(prepare_open(
            store, descriptor, path_flags, path, open_flags, flags,
        ))
    }

    async fn open_at(
        accessor: &Accessor<U, Self>,
        prepared: Self::OpenAtPrepared,
    ) -> Result<Resource<FsDescriptor>, FsError> {
        let opened = execute_open(prepared).await?;
        accessor
            .with(|mut access| access.get().table.push(opened))
            .map_err(FsError::trap)
    }

    type ReadlinkAtPrepared = FsOpResult<PreparedReadlinkAt<StorageImpl>>;
    fn prepare_readlink_at(
        store: &mut &mut StoreData<CpuImpl, Net, StorageImpl>,
        descriptor: Resource<FsDescriptor>,
        path: &str,
    ) -> Result<Self::ReadlinkAtPrepared> {
        Ok((|| -> FsOpResult<_> {
            let (base, namespace) = (|| {
                if store.process_authority().derive_symlink_read_cap().is_err() {
                    return Err(fs_types::ErrorCode::NotPermitted);
                }
                descriptor_in(store, &descriptor)
            })()?;
            PreparedReadlinkAt::new(namespace, base.grant()?, path)
        })())
    }
    async fn readlink_at(
        _accessor: &Accessor<U, Self>,
        prepared: Self::ReadlinkAtPrepared,
    ) -> Result<String, FsError> {
        Ok(prepared?.execute().await?)
    }

    type RemoveDirectoryAtPrepared = FsOpResult<PreparedRemoveDirectoryAt<StorageImpl>>;
    fn prepare_remove_directory_at(
        store: &mut &mut StoreData<CpuImpl, Net, StorageImpl>,
        descriptor: Resource<FsDescriptor>,
        path: &str,
    ) -> Result<Self::RemoveDirectoryAtPrepared> {
        Ok((|| -> FsOpResult<_> {
            let (base, namespace) = descriptor_in(store, &descriptor)?;
            PreparedRemoveDirectoryAt::new(namespace, base.grant()?, path, store.now_nanos())
        })())
    }
    async fn remove_directory_at(
        _accessor: &Accessor<U, Self>,
        prepared: Self::RemoveDirectoryAtPrepared,
    ) -> Result<(), FsError> {
        Ok(prepared?.execute().await?)
    }

    type RenameAtPrepared = FsOpResult<PreparedRenameAt<StorageImpl>>;
    fn prepare_rename_at(
        store: &mut &mut StoreData<CpuImpl, Net, StorageImpl>,
        source_descriptor: Resource<FsDescriptor>,
        source_path: &str,
        destination_descriptor: Resource<FsDescriptor>,
        destination_path: &str,
    ) -> Result<Self::RenameAtPrepared> {
        Ok((|| -> FsOpResult<_> {
            let (source_base, destination_base, namespace, now) = (|| {
                let (source, destination, namespace) =
                    descriptor_pair_in(store, &source_descriptor, &destination_descriptor)?;
                Ok::<_, fs_types::ErrorCode>((source, destination, namespace, store.now_nanos()))
            })()?;
            PreparedRenameAt::new(
                namespace,
                source_base
                    .grant()?
                    .alias_into(destination_base.grant()?)?
                    .removing_source()?,
                source_path,
                destination_path,
                now,
            )
        })())
    }
    async fn rename_at(
        _accessor: &Accessor<U, Self>,
        prepared: Self::RenameAtPrepared,
    ) -> Result<(), FsError> {
        Ok(prepared?.execute().await?)
    }

    type SymlinkAtPrepared = FsOpResult<PreparedSymlinkAt<StorageImpl>>;
    fn prepare_symlink_at(
        store: &mut &mut StoreData<CpuImpl, Net, StorageImpl>,
        descriptor: Resource<FsDescriptor>,
        old_path: &str,
        new_path: &str,
    ) -> Result<Self::SymlinkAtPrepared> {
        Ok((|| -> FsOpResult<_> {
            let (base, namespace, now) = (|| {
                if store
                    .process_authority()
                    .derive_symlink_create_cap()
                    .is_err()
                {
                    return Err(fs_types::ErrorCode::NotPermitted);
                }
                let (base, namespace) = descriptor_in(store, &descriptor)?;
                Ok((base, namespace, store.now_nanos()))
            })()?;
            PreparedSymlinkAt::new(namespace, base.grant()?, old_path, new_path, now)
        })())
    }
    async fn symlink_at(
        _accessor: &Accessor<U, Self>,
        prepared: Self::SymlinkAtPrepared,
    ) -> Result<(), FsError> {
        Ok(prepared?.execute().await?)
    }

    type UnlinkFileAtPrepared = FsOpResult<PreparedUnlinkFileAt<StorageImpl>>;
    fn prepare_unlink_file_at(
        store: &mut &mut StoreData<CpuImpl, Net, StorageImpl>,
        descriptor: Resource<FsDescriptor>,
        path: &str,
    ) -> Result<Self::UnlinkFileAtPrepared> {
        Ok((|| -> FsOpResult<_> {
            let (base, namespace) = descriptor_in(store, &descriptor)?;
            PreparedUnlinkFileAt::new(namespace, base.grant()?, path, store.now_nanos())
        })())
    }
    async fn unlink_file_at(
        _accessor: &Accessor<U, Self>,
        prepared: Self::UnlinkFileAtPrepared,
    ) -> Result<(), FsError> {
        Ok(prepared?.execute().await?)
    }

    async fn is_same_object(
        accessor: &Accessor<U, Self>,
        a: Resource<FsDescriptor>,
        b: Resource<FsDescriptor>,
    ) -> Result<bool> {
        accessor.with(|mut access| {
            let left = access.get().table.get(&a)?.clone();
            let right = access.get().table.get(&b)?.clone();
            Ok(left
                .identity
                .zip(right.identity)
                .is_some_and(|(left, right)| left == right))
        })
    }

    async fn metadata_hash(
        accessor: &Accessor<U, Self>,
        descriptor: Resource<FsDescriptor>,
    ) -> Result<fs_types::MetadataHashValue, FsError> {
        let profile = accessor.with(|mut access| component_fs_profile(access.get()));
        let (descriptor, namespace) =
            accessor.with(|mut access| descriptor_in(access.get(), &descriptor))?;
        let result = stat_path(&namespace, &descriptor.path, Follow::No)
            .await
            .map(|metadata| self::metadata_hash(&metadata));
        record_component_fs_profile(profile, "metadata-hash");
        Ok(result?)
    }

    type MetadataHashAtPrepared = PreparedStat<CpuImpl, Net, StorageImpl>;

    fn prepare_metadata_hash_at(
        store: &mut &mut StoreData<CpuImpl, Net, StorageImpl>,
        descriptor: Resource<FsDescriptor>,
        path_flags: fs_types::PathFlags,
        path: &str,
    ) -> Result<Self::MetadataHashAtPrepared> {
        Ok(prepare_stat(store, descriptor, path_flags, path))
    }

    async fn metadata_hash_at(
        _accessor: &Accessor<U, Self>,
        prepared: Self::MetadataHashAtPrepared,
    ) -> Result<fs_types::MetadataHashValue, FsError> {
        Ok(self::metadata_hash(
            &stat_prepared(prepared, "metadata-hash-at").await?,
        ))
    }
}

/// Pipes the guest's `data` into the file `descriptor` names, at an
/// offset or at the end of file as `mode` says.
fn pipe_into_file<U, CpuImpl, Net, StorageImpl>(
    mut accessor: Access<'_, U, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>,
    descriptor: Resource<FsDescriptor>,
    mut data: StreamReader<u8>,
    mode: WritePosition,
) -> Result<FutureReader<FsOpResult<()>>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let resolved = descriptor_in(accessor.get(), &descriptor)
        .and_then(|(descriptor, namespace)| write_stream_target(&namespace, descriptor.grant()?));
    let getter = accessor.getter();
    match resolved {
        Ok(resolved) => {
            let (tx, rx) = oneshot::channel();
            data.pipe(
                &mut accessor,
                file_write_consumer(getter, resolved, mode, tx),
            )?;
            transfer_outcome(&mut accessor, rx)
        }
        Err(error) => {
            data.close(&mut accessor)?;
            failed_transfer(&mut accessor, error)
        }
    }
}

pub(super) fn get_fs_descriptor<CpuImpl, Net, StorageImpl>(
    store: &mut StoreData<CpuImpl, Net, StorageImpl>,
    resource: &Resource<FsDescriptor>,
) -> FsOpResult<FsDescriptor>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    store
        .table
        .get(resource)
        .cloned()
        .map_err(fs_resource_error)
}

pub(crate) fn fs_resource_error(
    error: wasmtime::component::ResourceTableError,
) -> fs_types::ErrorCode {
    let mapped = match error {
        wasmtime::component::ResourceTableError::NotPresent => {
            crate::ComponentResourceTableError::NotPresent
        }
        wasmtime::component::ResourceTableError::WrongType => {
            crate::ComponentResourceTableError::WrongType
        }
        wasmtime::component::ResourceTableError::HasChildren => {
            crate::ComponentResourceTableError::HasChildren
        }
        wasmtime::component::ResourceTableError::Full => crate::ComponentResourceTableError::Full,
    };
    match crate::map_resource_table_error(mapped) {
        crate::ComponentFsResourceError::BadDescriptor => fs_types::ErrorCode::BadDescriptor,
        crate::ComponentFsResourceError::Busy => fs_types::ErrorCode::Busy,
        crate::ComponentFsResourceError::Overflow => fs_types::ErrorCode::Overflow,
    }
}

pub(super) fn is_dir_first(kind: fs_types::DescriptorType) -> u8 {
    match kind {
        fs_types::DescriptorType::Directory => 0,
        _ => 1,
    }
}

pub(super) fn map_component_fs_path_error(
    error: crate::ComponentFsPathError,
) -> fs_types::ErrorCode {
    match error {
        crate::ComponentFsPathError::InvalidBasePath => fs_types::ErrorCode::Invalid,
        crate::ComponentFsPathError::NotPermitted => fs_types::ErrorCode::NotPermitted,
    }
}

#[cfg(test)]
mod direct_write_tests {
    use super::*;
    use crate::UnsupportedStorage;
    use crate::wasmtime_adapter::component_host::service::test_store;
    use crate::wasmtime_adapter::wasi::stream::test_source::{Reads, TrackedBuffer};
    use core::sync::atomic::Ordering;
    use futures_lite::future::{block_on, yield_now};
    use std::sync::Arc;

    type TestHeld = HeldPath<UnsupportedStorage>;

    struct RoundWrite {
        offset: usize,
        len: usize,
    }

    struct FilledRound(RoundWrite);

    impl PreparedWrite for RoundWrite {
        type Filled = FilledRound;

        fn staged_len(&self) -> usize {
            // Two-byte test destinations force three rounds for the test source.
            (self.len - self.offset).min(2)
        }

        fn fill<F>(mut self, mut fill: F) -> Self::Filled
        where
            F: FnMut(usize, &mut [u8]),
        {
            let mut destination = [0; 2];
            let len = self.staged_len();
            fill(self.offset, &mut destination[..len]);
            assert_eq!(
                &destination[..len],
                &b"abcdef"[self.offset..self.offset + len]
            );
            self.offset += len;
            FilledRound(self)
        }
    }

    impl FilledWrite for FilledRound {
        type Next = RoundWrite;

        async fn submit(self) -> FsResult<WriteProgress<Self::Next>> {
            yield_now().await;
            Ok(if self.0.offset == self.0.len {
                WriteProgress::Done(Landed {
                    offset: 0,
                    len: self.0.len,
                })
            } else {
                WriteProgress::More(self.0)
            })
        }
    }

    async fn prepare_ready(
        _: TestHeld,
        _: WritePosition,
        len: usize,
        _: u64,
    ) -> FsOpResult<RoundWrite> {
        Ok(RoundWrite { offset: 0, len })
    }

    async fn prepare_pending(
        held: TestHeld,
        mode: WritePosition,
        len: usize,
        now: u64,
    ) -> FsOpResult<RoundWrite> {
        yield_now().await;
        prepare_ready(held, mode, len, now).await
    }

    async fn submit(filled: FilledRound) -> FsOpResult<WriteProgress<RoundWrite>> {
        filled.submit().await.map_err(fs_error_code)
    }

    /// A filesystem that stores one byte less than the write staged, as a
    /// device that ran out of space part way does.
    async fn submit_short(filled: FilledRound) -> FsOpResult<WriteProgress<RoundWrite>> {
        match filled.submit().await.map_err(fs_error_code)? {
            WriteProgress::Done(landed) => Ok(WriteProgress::Done(Landed {
                offset: landed.offset,
                len: landed.len - 1,
            })),
            more => Ok(more),
        }
    }

    pin_project! {
        struct FinishAfterPending<C> {
            #[pin]
            consumer: C,
            cancel: bool,
            finish: bool,
        }
    }

    impl<C: StreamConsumer<test_store::TestStoreData, Item = u8>>
        StreamConsumer<test_store::TestStoreData> for FinishAfterPending<C>
    {
        type Item = u8;

        fn poll_consume(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            store: wasmtime::StoreContextMut<'_, test_store::TestStoreData>,
            source: Source<'_, u8>,
            _: bool,
        ) -> Poll<Result<StreamResult>> {
            let this = self.project();
            let result = this.consumer.poll_consume(cx, store, source, *this.finish);
            match result {
                Poll::Pending => {
                    *this.finish = *this.cancel;
                    Poll::Pending
                }
                Poll::Ready(Ok(result)) if *this.finish => {
                    assert!(matches!(
                        result,
                        StreamResult::Cancelled | StreamResult::Completed
                    ));
                    Poll::Ready(Ok(StreamResult::Dropped))
                }
                result => result,
            }
        }
    }

    fn exercise<P>(
        prepare: fn(TestHeld, WritePosition, usize, u64) -> P,
        cancel: bool,
        consumed: usize,
    ) where
        P: core::future::Future<Output = FsOpResult<RoundWrite>> + Send + 'static,
    {
        let (outcome, skipped) = run(prepare, submit, cancel);
        outcome.expect("write completed");
        assert_eq!(skipped, consumed);
    }

    /// Pipes `abcdef` into a file write consumer, and returns how the
    /// stream ended and how many source bytes it took.
    fn run<P, S>(
        prepare: fn(TestHeld, WritePosition, usize, u64) -> P,
        submit: fn(FilledRound) -> S,
        cancel: bool,
    ) -> (FsOpResult<()>, usize)
    where
        P: core::future::Future<Output = FsOpResult<RoundWrite>> + Send + 'static,
        S: core::future::Future<Output = FsOpResult<WriteProgress<RoundWrite>>> + Send + 'static,
    {
        let mut config = wasmtime::Config::new();
        config
            .wasm_component_model(true)
            .wasm_component_model_async(true);
        let engine = wasmtime::Engine::new(&config).expect("stream engine");
        let mut store = wasmtime::Store::new(&engine, test_store::store_data_with(|_| {}));
        let held = store
            .data()
            .runtime_state
            .root_namespace()
            .resolve("/file")
            .expect("resolution")
            .held();
        let (tx, rx) = oneshot::channel();
        let consumer = FileWriteConsumer {
            getter: |state| state,
            held,
            mode: WritePosition::At(0),
            prepare,
            submit,
            state: FileWriteState::Idle,
            result: Some(tx),
        };
        let consumer = FinishAfterPending {
            consumer,
            cancel,
            finish: false,
        };
        let reads = Arc::new(Reads::default());
        let source = TrackedBuffer {
            bytes: b"abcdef",
            reads: reads.clone(),
        };
        let outcome = block_on(store.run_concurrent(async |accessor| {
            accessor
                .with(|mut store| StreamReader::new(&mut store, source)?.pipe(store, consumer))
                .expect("connect stream");
            rx.await.expect("completion sent")
        }))
        .expect("stream event loop");
        assert_eq!(reads.moved.load(Ordering::Relaxed), 0);
        (outcome, reads.skipped.load(Ordering::Relaxed))
    }

    #[test]
    fn a_short_write_ends_the_stream_with_insufficient_space() {
        let (outcome, skipped) = run(prepare_ready, submit_short, false);
        assert!(matches!(
            outcome,
            Err(fs_types::ErrorCode::InsufficientSpace)
        ));
        assert_eq!(skipped, 6);
    }

    #[test]
    fn pending_rounds_consume_each_source_byte_once() {
        exercise(prepare_ready, false, 6);
    }

    #[test]
    fn cancellation_while_preparing_leaves_source_unconsumed() {
        exercise(prepare_pending, true, 0);
    }

    #[test]
    fn cancellation_while_submitting_finishes_only_the_consumed_round() {
        exercise(prepare_ready, true, 2);
    }
}

#[cfg(test)]
mod borrowed_request_tests {
    use super::*;
    use crate::wasmtime_adapter::component_host::service::test_store;
    use futures_lite::future::block_on;

    #[test]
    fn prepared_mutations_own_names_and_preserve_link_semantics() {
        let store = test_store::store_data_with(|_| {});
        let namespace = store.filesystem().clone();
        let root = FsDescriptor {
            path: String::from("/"),
            kind: FsNodeKind::Directory,
            flags: fs_types::DescriptorFlags::READ
                | fs_types::DescriptorFlags::WRITE
                | fs_types::DescriptorFlags::MUTATE_DIRECTORY,
            identity: None,
            mount: None,
        };
        let directory = String::from("中文-日本語-한국어");
        let create =
            PreparedCreateDirectoryAt::new(namespace.clone(), root.grant().unwrap(), &directory, 1)
                .unwrap();
        drop(directory);
        block_on(create.execute()).unwrap();
        let opened = block_on(open_at(
            &namespace,
            root.grant().unwrap(),
            fs_types::PathFlags::empty(),
            "中文-日本語-한국어/file",
            fs_types::OpenFlags::CREATE,
            fs_types::DescriptorFlags::READ,
            2,
        ))
        .unwrap();
        let source = String::from("中文-日本語-한국어/file");
        let destination = String::from("中文-日本語-한국어/linked");
        let link = PreparedLinkAt::new(
            namespace.clone(),
            root.grant()
                .unwrap()
                .alias_into(root.grant().unwrap())
                .unwrap(),
            &source,
            &destination,
            3,
        )
        .unwrap();
        drop(source);
        drop(destination);
        block_on(link.execute()).unwrap();
        let rename = PreparedRenameAt::new(
            namespace.clone(),
            root.grant()
                .unwrap()
                .alias_into(root.grant().unwrap())
                .unwrap()
                .removing_source()
                .unwrap(),
            "中文-日本語-한국어/linked",
            "中文-日本語-한국어/renamed",
            4,
        )
        .unwrap();
        block_on(rename.execute()).unwrap();
        let metadata = block_on(stat_path(
            &namespace,
            "/中文-日本語-한국어/renamed",
            Follow::No,
        ))
        .unwrap();
        assert_eq!(object_identity(&metadata), opened.identity.unwrap());
        let times = PreparedSetTimesAt::new(
            namespace.clone(),
            root.grant().unwrap(),
            "中文-日本語-한국어/renamed",
            Some(5),
            Some(6),
            7,
        )
        .unwrap();
        block_on(times.execute()).unwrap();
        let target = String::from("renamed");
        let path = String::from("中文-日本語-한국어/symbolic");
        let symbolic =
            PreparedSymlinkAt::new(namespace.clone(), root.grant().unwrap(), &target, &path, 8)
                .unwrap();
        drop(target);
        drop(path);
        block_on(symbolic.execute()).unwrap();
        let readlink = PreparedReadlinkAt::new(
            namespace.clone(),
            root.grant().unwrap(),
            "中文-日本語-한국어/symbolic",
        )
        .unwrap();
        assert_eq!(block_on(readlink.execute()).unwrap(), "renamed");
        for path in [
            "中文-日本語-한국어/file",
            "中文-日本語-한국어/renamed",
            "中文-日本語-한국어/symbolic",
        ] {
            block_on(
                PreparedUnlinkFileAt::new(namespace.clone(), root.grant().unwrap(), path, 7)
                    .unwrap()
                    .execute(),
            )
            .unwrap();
        }
        block_on(
            PreparedRemoveDirectoryAt::new(
                namespace.clone(),
                root.grant().unwrap(),
                "中文-日本語-한국어",
                7,
            )
            .unwrap()
            .execute(),
        )
        .unwrap();
        assert!(matches!(
            block_on(stat_path(&namespace, "/中文-日本語-한국어", Follow::No)),
            Err(fs_types::ErrorCode::NoEntry)
        ));
    }

    #[test]
    fn cancelling_prepared_mutations_does_not_modify_the_namespace() {
        let store = test_store::store_data_with(|_| {});
        let namespace = store.filesystem().clone();
        let root = FsDescriptor {
            path: String::from("/"),
            kind: FsNodeKind::Directory,
            flags: fs_types::DescriptorFlags::READ
                | fs_types::DescriptorFlags::WRITE
                | fs_types::DescriptorFlags::MUTATE_DIRECTORY,
            identity: None,
            mount: None,
        };
        drop(
            PreparedCreateDirectoryAt::new(
                namespace.clone(),
                root.grant().unwrap(),
                "cancelled",
                1,
            )
            .unwrap(),
        );
        drop(
            PreparedSymlinkAt::new(
                namespace.clone(),
                root.grant().unwrap(),
                "target",
                "cancelled-link",
                1,
            )
            .unwrap(),
        );
        for path in ["/cancelled", "/cancelled-link"] {
            assert!(matches!(
                block_on(stat_path(&namespace, path, Follow::No)),
                Err(fs_types::ErrorCode::NoEntry)
            ));
        }
        assert!(matches!(
            PreparedCreateDirectoryAt::new(
                namespace.clone(),
                root.grant().unwrap(),
                "../outside",
                1
            ),
            Err(fs_types::ErrorCode::NotPermitted)
        ));
        assert!(matches!(
            PreparedSymlinkAt::new(namespace, root.grant().unwrap(), "../outside", "link", 1),
            Err(fs_types::ErrorCode::NotPermitted)
        ));
        let readonly = FsDescriptor {
            flags: fs_types::DescriptorFlags::READ,
            ..root
        };
        assert!(matches!(
            readonly.grant::<Directory, Mutate>(),
            Err(fs_types::ErrorCode::ReadOnly)
        ));
    }

    #[test]
    fn prepared_paths_own_resolved_names_and_preserve_directory_rights() {
        let mut store = test_store::store_data_with(|_| {});
        let root = store
            .table
            .push(FsDescriptor {
                path: String::from("/"),
                kind: FsNodeKind::Directory,
                flags: fs_types::DescriptorFlags::READ
                    | fs_types::DescriptorFlags::WRITE
                    | fs_types::DescriptorFlags::MUTATE_DIRECTORY,
                identity: None,
                mount: None,
            })
            .unwrap();
        let path = String::from("中文-日本語-한국어");
        let request = prepare_open(
            &mut store,
            Resource::new_borrow(root.rep()),
            fs_types::PathFlags::empty(),
            &path,
            fs_types::OpenFlags::CREATE,
            fs_types::DescriptorFlags::READ,
        );
        drop(path);
        let opened = block_on(execute_open(request)).unwrap();
        assert_eq!(opened.path, "/中文-日本語-한국어");
        let stat = prepare_stat(
            &mut store,
            Resource::new_borrow(root.rep()),
            fs_types::PathFlags::empty(),
            "中文-日本語-한국어",
        );
        assert_eq!(
            object_identity(&block_on(stat_prepared(stat, "stat-at")).unwrap()),
            opened.identity.unwrap()
        );

        let escaped = prepare_open(
            &mut store,
            Resource::new_borrow(root.rep()),
            fs_types::PathFlags::empty(),
            "../outside",
            fs_types::OpenFlags::CREATE,
            fs_types::DescriptorFlags::READ,
        );
        assert!(matches!(
            block_on(execute_open(escaped)),
            Err(fs_types::ErrorCode::NotPermitted)
        ));
        store.table.get_mut(&root).unwrap().flags = fs_types::DescriptorFlags::READ;
        let denied = prepare_open(
            &mut store,
            Resource::new_borrow(root.rep()),
            fs_types::PathFlags::empty(),
            "refused",
            fs_types::OpenFlags::CREATE,
            fs_types::DescriptorFlags::READ,
        );
        assert!(matches!(
            block_on(execute_open(denied)),
            Err(fs_types::ErrorCode::ReadOnly)
        ));
        let absent = prepare_stat(
            &mut store,
            Resource::new_borrow(root.rep()),
            fs_types::PathFlags::empty(),
            "refused",
        );
        assert!(matches!(
            block_on(stat_prepared(absent, "stat-at")),
            Err(fs_types::ErrorCode::NoEntry)
        ));
    }
}
