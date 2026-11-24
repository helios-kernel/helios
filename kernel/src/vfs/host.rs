//! The host share as a mountable filesystem.
//!
//! [`HostShare`] adapts the kernel's 9p client ([`crate::HostFileSystem`])
//! to the filesystem contract. The client speaks host-relative paths whose
//! root is `/`; a [`FsPath`] is relative to the share's root already, so
//! the root maps to `/` and every other path passes through unchanged.
//!
//! Concurrency contract: the client is a cheap handle whose transport
//! serialises requests on its own; this adapter adds no state.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use bytes::Bytes;
use helios_hal::fs::{
    DeviceId, DirCookie, DirEntry, DirStream, FileSystem, FilledWrite, FsError, FsPath, FsResult,
    Metadata, NodeId, NodeKind, OpenFlags, OwnedFsPath, PreparedWrite, RenameMode, WritePosition,
    WriteProgress,
};

use super::UnixAttributes;
use crate::{
    HostCreation, HostDirEntry, HostDirLimit, HostFileSystem, HostFilledWrite, HostFsError,
    HostFsErrorKind, HostMetadata, HostWrite,
};

/// The most of one host directory a listing holds in kernel memory.
///
/// The share lists a whole directory per request and pages the guest's
/// cookie over it, so the guest's buffer bounds nothing. This is a policy
/// bound, not one derived from a stated budget: it keeps a host that never
/// ends a listing from growing kernel memory without limit, while a real
/// directory of tens of thousands of names still lists.
const HOST_DIRECTORY_LIMIT: HostDirLimit = HostDirLimit {
    max_entries: 65_536,
    max_name_bytes: 4 * 1024 * 1024,
};

/// The host share, mounted.
#[derive(Clone)]
pub struct HostShare<H> {
    client: H,
}

impl<H> HostShare<H> {
    pub fn new(client: H) -> Self {
        Self { client }
    }

    pub fn client(&self) -> &H {
        &self.client
    }
}

fn host_path(path: FsPath<'_>) -> &str {
    if path.is_root() { "/" } else { path.as_str() }
}

impl<H: HostFileSystem> HostShare<H> {
    /// How a node of `kind` at `path` is made: a request reaching the
    /// share carries no creator identity, so the node inherits its mode and
    /// group from the directory it is made in ([`UnixAttributes::inherited`]).
    async fn creation(&self, path: FsPath<'_>, kind: NodeKind) -> FsResult<HostCreation> {
        let (parent, _) = path.split_last().ok_or(FsError::Exists)?;
        let directory = self
            .client
            .stat_path(host_path(parent))
            .await
            .map_err(fs_error_from_host)?;
        let node = UnixAttributes {
            permissions: directory.mode & 0o7777,
            uid: directory.uid,
            gid: directory.gid,
        }
        .inherited(kind);
        Ok(HostCreation {
            permissions: node.permissions,
            gid: node.gid,
        })
    }

    /// The stored Unix ownership and mode bits reported by the host share for
    /// `path`.
    pub async fn unix_attributes(&self, path: FsPath<'_>) -> FsResult<UnixAttributes> {
        let metadata = self
            .client
            .stat_path(host_path(path))
            .await
            .map_err(fs_error_from_host)?;
        Ok(UnixAttributes {
            permissions: metadata.mode & 0o7777,
            uid: metadata.uid,
            gid: metadata.gid,
        })
    }
}

pub(crate) fn fs_error_from_host(error: HostFsError) -> FsError {
    match error.kind() {
        HostFsErrorKind::NoEntry => FsError::NoEntry,
        HostFsErrorKind::Exist => FsError::Exists,
        HostFsErrorKind::NotDirectory => FsError::NotDirectory,
        HostFsErrorKind::IsDirectory => FsError::IsDirectory,
        HostFsErrorKind::NotEmpty => FsError::NotEmpty,
        HostFsErrorKind::ReadOnly => FsError::ReadOnly,
        HostFsErrorKind::Unsupported => FsError::Unsupported,
        HostFsErrorKind::NameTooLong => FsError::NameTooLong,
        HostFsErrorKind::NoSpace => FsError::NoSpace,
        HostFsErrorKind::Io => FsError::Io,
        HostFsErrorKind::Refused(refusal) => refusal,
    }
}

/// The host's attributes as the contract's metadata. The kind comes from
/// the file type bits of the mode: the qid type names no device, FIFO or
/// socket, and would pass each of them off as a regular file.
fn metadata_from_host(metadata: &HostMetadata) -> FsResult<Metadata> {
    Ok(Metadata {
        id: NodeId::new(
            DeviceId::new(metadata.identity.domain().raw()),
            metadata.identity.local(),
        ),
        kind: metadata.kind().map_err(fs_error_from_host)?,
        link_count: metadata.link_count,
        size: metadata.size,
        access_nanos: metadata.access_nanos,
        modified_nanos: metadata.modified_nanos,
        status_nanos: metadata.status_nanos,
    })
}

/// A host-share write, staged by the client: the filler writes the
/// guest's bytes straight into the client's destinations (the 9p request
/// frames), one round at a time.
pub struct HostShareWrite<W> {
    write: W,
}

impl<W: HostWrite> PreparedWrite for HostShareWrite<W> {
    type Filled = FilledHostShareWrite<W::Filled>;

    fn staged_len(&self) -> usize {
        self.write.staged_len()
    }

    fn fill<F>(self, fill: F) -> Self::Filled
    where
        F: FnMut(usize, &mut [u8]),
    {
        FilledHostShareWrite(self.write.fill(fill))
    }
}

/// A host-share round whose transport destinations contain their bytes.
pub struct FilledHostShareWrite<W>(W);

impl<W: HostFilledWrite> FilledWrite for FilledHostShareWrite<W>
where
    W::Next: HostWrite,
{
    type Next = HostShareWrite<W::Next>;

    async fn submit(self) -> FsResult<WriteProgress<Self::Next>> {
        match self.0.submit().await.map_err(fs_error_from_host)? {
            WriteProgress::More(write) => Ok(WriteProgress::More(HostShareWrite { write })),
            WriteProgress::Done(landed) => Ok(WriteProgress::Done(landed)),
        }
    }
}

/// An open directory stream over a [`HostShare`].
///
/// 9p lists a whole directory per request, so the stream fetches the entries
/// at open (and on `rewind`) and pages cookies over that snapshot.
pub struct HostDir<H> {
    fs: HostShare<H>,
    path: OwnedFsPath,
    entries: Vec<HostDirEntry>,
}

impl<H: HostFileSystem> DirStream for HostDir<H> {
    async fn read(&self, cookie: DirCookie, max_entries: usize) -> FsResult<Vec<DirEntry>> {
        let skip = usize::try_from(cookie.raw()).map_err(|_| FsError::Invalid)?;
        let path = self.path.as_path();
        let mut listed = Vec::new();
        for (position, entry) in self.entries.iter().enumerate().skip(skip).take(max_entries) {
            let kind = match entry.kind {
                Some(kind) => kind,
                // The host's listing did not say: its attributes do.
                None => {
                    let child = if path.is_root() {
                        alloc::format!("/{}", entry.name)
                    } else {
                        alloc::format!("{}/{}", path.as_str(), entry.name)
                    };
                    let metadata = self
                        .fs
                        .client
                        .stat_path(&child)
                        .await
                        .map_err(fs_error_from_host)?;
                    metadata_from_host(&metadata)?.kind
                }
            };
            listed.push(DirEntry {
                name: entry.name.clone(),
                kind,
                inode: 0,
                next: DirCookie::new(position as u64 + 1),
            });
        }
        Ok(listed)
    }

    async fn rewind(&mut self) -> FsResult<()> {
        self.entries = self
            .fs
            .client
            .read_dir(host_path(self.path.as_path()), HOST_DIRECTORY_LIMIT)
            .await
            .map_err(fs_error_from_host)?;
        Ok(())
    }
}

impl<H: HostFileSystem> FileSystem for HostShare<H> {
    type Payer = crate::StoragePayer;
    super::delegate_path_handles!();
    type Write = HostShareWrite<H::Write>;
    type Dir = HostDir<H>;

    async fn stat(&self, path: FsPath<'_>) -> FsResult<Metadata> {
        let metadata = self
            .client
            .stat_path(host_path(path))
            .await
            .map_err(fs_error_from_host)?;
        metadata_from_host(&metadata)
    }

    async fn open(
        &self,
        path: FsPath<'_>,
        flags: OpenFlags,
        _now: u64,
        _payer: &crate::StoragePayer,
    ) -> FsResult<helios_hal::fs::Opened<OwnedFsPath>> {
        let host = host_path(path);
        let metadata = match self
            .client
            .stat_path(host)
            .await
            .map_err(fs_error_from_host)
        {
            Ok(metadata) => {
                let metadata = metadata_from_host(&metadata)?;
                if flags.contains(OpenFlags::CREATE | OpenFlags::EXCLUSIVE) {
                    return Err(FsError::Exists);
                }
                if let Some(refusal) = metadata.kind.open_refusal() {
                    return Err(refusal);
                }
                if flags.contains(OpenFlags::DIRECTORY) && metadata.kind != NodeKind::Directory {
                    return Err(FsError::NotDirectory);
                }
                if flags.contains(OpenFlags::TRUNCATE) {
                    if metadata.kind != NodeKind::File {
                        return Err(FsError::IsDirectory);
                    }
                    self.client
                        .truncate_file(host)
                        .await
                        .map_err(fs_error_from_host)?;
                }
                metadata
            }
            Err(FsError::NoEntry) if flags.contains(OpenFlags::CREATE) => {
                if flags.contains(OpenFlags::DIRECTORY) {
                    return Err(FsError::Invalid);
                }
                let creation = self.creation(path, NodeKind::File).await?;
                self.client
                    .create_file(host, creation)
                    .await
                    .map_err(fs_error_from_host)?;
                self.stat(path).await?
            }
            Err(error) => return Err(error),
        };
        Ok(helios_hal::fs::Opened {
            metadata,
            handle: OwnedFsPath::from(path),
        })
    }

    async fn read_at(&self, path: FsPath<'_>, offset: u64, max_bytes: usize) -> FsResult<Bytes> {
        if max_bytes == 0 {
            return Ok(Bytes::new());
        }
        let max_bytes = u32::try_from(max_bytes).unwrap_or(u32::MAX);
        self.client
            .read_file_range(host_path(path), offset, max_bytes)
            .await
            .map(Bytes::from)
            .map_err(fs_error_from_host)
    }

    async fn prepare_write<'a>(
        &'a self,
        path: FsPath<'a>,
        position: WritePosition,
        len: usize,
        _now: u64,
        _payer: &'a crate::StoragePayer,
    ) -> FsResult<HostShareWrite<H::Write>> {
        self.client
            .prepare_write(host_path(path), position, len)
            .await
            .map(|write| HostShareWrite { write })
            .map_err(fs_error_from_host)
    }

    async fn set_size(
        &self,
        path: FsPath<'_>,
        size: u64,
        _now: u64,
        _payer: &crate::StoragePayer,
    ) -> FsResult<()> {
        self.client
            .set_file_size(host_path(path), size)
            .await
            .map_err(fs_error_from_host)
    }

    async fn set_times(
        &self,
        path: FsPath<'_>,
        access_nanos: Option<u64>,
        modified_nanos: Option<u64>,
        _now: u64,
        _payer: &crate::StoragePayer,
    ) -> FsResult<()> {
        self.client
            .set_times(host_path(path), access_nanos, modified_nanos)
            .await
            .map_err(fs_error_from_host)
    }

    async fn open_dir(&self, path: FsPath<'_>) -> FsResult<HostDir<H>> {
        let entries = self
            .client
            .read_dir(host_path(path), HOST_DIRECTORY_LIMIT)
            .await
            .map_err(fs_error_from_host)?;
        Ok(HostDir {
            fs: self.clone(),
            path: OwnedFsPath::from(path),
            entries,
        })
    }

    async fn create_directory(
        &self,
        path: FsPath<'_>,
        _now: u64,
        _payer: &crate::StoragePayer,
    ) -> FsResult<()> {
        let creation = self.creation(path, NodeKind::Directory).await?;
        self.client
            .create_directory(host_path(path), creation)
            .await
            .map_err(fs_error_from_host)
    }

    async fn remove_directory(
        &self,
        path: FsPath<'_>,
        _now: u64,
        _payer: &crate::StoragePayer,
    ) -> FsResult<()> {
        self.client
            .remove(host_path(path), true)
            .await
            .map_err(fs_error_from_host)
    }

    async fn unlink(
        &self,
        path: FsPath<'_>,
        _now: u64,
        _payer: &crate::StoragePayer,
    ) -> FsResult<()> {
        self.client
            .remove(host_path(path), false)
            .await
            .map_err(fs_error_from_host)
    }

    /// 9p2000.L's `Trenameat` carries no flags (it is `olddirfid`,
    /// `oldname`, `newdirfid`, `newname`), and the hosted backend's
    /// `std::fs::rename` has no atomic no-replace or exchange form, so the
    /// share can honour only [`RenameMode::Replace`]. Anything else would
    /// have to be composed from separate calls, which is not atomic.
    async fn rename(
        &self,
        source: FsPath<'_>,
        destination: FsPath<'_>,
        mode: RenameMode,
        _now: u64,
        _payer: &crate::StoragePayer,
    ) -> FsResult<()> {
        if mode != RenameMode::Replace {
            return Err(FsError::Unsupported);
        }
        self.client
            .rename(host_path(source), host_path(destination))
            .await
            .map_err(fs_error_from_host)
    }

    async fn link(
        &self,
        existing: FsPath<'_>,
        link: FsPath<'_>,
        _now: u64,
        _payer: &crate::StoragePayer,
    ) -> FsResult<()> {
        self.client
            .hard_link(host_path(existing), host_path(link))
            .await
            .map_err(fs_error_from_host)
    }

    async fn symlink(
        &self,
        target: &str,
        link: FsPath<'_>,
        _now: u64,
        _payer: &crate::StoragePayer,
    ) -> FsResult<()> {
        let creation = self.creation(link, NodeKind::Symlink).await?;
        self.client
            .symlink(target, host_path(link), creation.gid)
            .await
            .map_err(fs_error_from_host)
    }

    async fn read_link(&self, path: FsPath<'_>) -> FsResult<String> {
        self.client
            .read_link(host_path(path))
            .await
            .map_err(fs_error_from_host)
    }

    async fn sync(&self, path: FsPath<'_>) -> FsResult<()> {
        // 9p has one `Tfsync`, which the host turns into `fsync`: data and
        // metadata both, which also satisfies `sync_data`.
        self.client
            .sync_file(host_path(path))
            .await
            .map_err(fs_error_from_host)
    }

    async fn sync_data(&self, path: FsPath<'_>) -> FsResult<()> {
        self.sync(path).await
    }
}

#[cfg(test)]
mod tests {
    use helios_hal::fs::{FsError, NodeKind};

    use super::{fs_error_from_host, metadata_from_host};
    use crate::{AuthorityDomain, HostFsError, HostMetadata, ObjectIdentity, object_identity};

    /// A name the host share's wire cannot carry stays "name too long"
    /// through the mount, rather than collapsing into an I/O error.
    #[test]
    fn a_name_the_host_share_cannot_carry_is_name_too_long() {
        let error = HostFsError::NameTooLong {
            len: 65_536,
            max_len: 65_535,
        };
        assert_eq!(fs_error_from_host(error), FsError::NameTooLong);
    }

    fn host_metadata(identity: ObjectIdentity, qid_type: u8, mode: u32) -> HostMetadata {
        HostMetadata {
            identity,
            qid_path: identity.local(),
            qid_type,
            mode,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            size: 17,
            link_count: 2,
            access_nanos: 3_000_000_004,
            modified_nanos: 5_000_000_006,
            status_nanos: 7_000_000_008,
        }
    }

    /// A host-share stat carries the host's own timestamps, link count and
    /// identity: `make`, `rsync` and every other mtime-driven tool treat a
    /// shared file as ageless otherwise.
    #[test]
    fn host_metadata_keeps_timestamps_link_count_and_identity() {
        let identity = ObjectIdentity::new(AuthorityDomain::HOST_SHARE_9P, 4242);

        let metadata =
            metadata_from_host(&host_metadata(identity, 0, 0o100_644)).expect("a regular file");

        assert_eq!(metadata.kind, NodeKind::File);
        assert_eq!(metadata.link_count, 2);
        assert_eq!(metadata.size, 17);
        assert_eq!(metadata.access_nanos, 3_000_000_004);
        assert_eq!(metadata.modified_nanos, 5_000_000_006);
        assert_eq!(metadata.status_nanos, 7_000_000_008);
        assert_eq!(object_identity(&metadata), identity);
    }

    /// The kind is the mode's, not the qid's: the qid type of a device,
    /// FIFO or socket is that of a regular file.
    #[test]
    fn host_metadata_kind_is_the_modes_file_type() {
        let identity = ObjectIdentity::new(AuthorityDomain::HOST_SHARE_9P, 9);
        for (mode, kind) in [
            (0o040_755, NodeKind::Directory),
            (0o100_644, NodeKind::File),
            (0o120_777, NodeKind::Symlink),
            (0o020_666, NodeKind::CharacterDevice),
            (0o060_660, NodeKind::BlockDevice),
            (0o010_644, NodeKind::Fifo),
            (0o140_755, NodeKind::Socket),
        ] {
            let metadata = metadata_from_host(&host_metadata(identity, 0, mode)).expect("a kind");
            assert_eq!(metadata.kind, kind, "mode {mode:o}");
        }
    }

    #[test]
    fn host_share_unix_attributes_returns_stored_mode_uid_and_gid() {
        use alloc::string::String;
        use alloc::vec::Vec;
        use helios_hal::fs::{FsPath, WritePosition};

        use super::{HostCreation, HostFileSystem, HostShare, UnixAttributes};
        use crate::runtime::{HostDirEntry, HostDirLimit, HostShareRestore};

        #[derive(Clone)]
        struct StubHost(HostMetadata);

        impl HostFileSystem for StubHost {
            type Write = core::convert::Infallible;

            fn cache_stats(&self) -> Option<crate::HostFsCacheStats> {
                None
            }
            async fn after_machine_restore(&self, _restore: HostShareRestore) {}
            async fn prepare_snapshot(&self) {}
            fn snapshot_finished(&self) {}
            async fn stat_path(&self, _path: &str) -> Result<HostMetadata, HostFsError> {
                Ok(self.0.clone())
            }
            async fn read_dir(
                &self,
                _path: &str,
                _limit: HostDirLimit,
            ) -> Result<Vec<HostDirEntry>, HostFsError> {
                unreachable!()
            }
            async fn read_file(&self, _path: &str) -> Result<Vec<u8>, HostFsError> {
                unreachable!()
            }
            async fn read_file_range(
                &self,
                _path: &str,
                _offset: u64,
                _max_bytes: u32,
            ) -> Result<Vec<u8>, HostFsError> {
                unreachable!()
            }
            async fn prepare_write(
                &self,
                _path: &str,
                _position: WritePosition,
                _len: usize,
            ) -> Result<Self::Write, HostFsError> {
                unreachable!()
            }
            async fn sync_file(&self, _path: &str) -> Result<(), HostFsError> {
                unreachable!()
            }
            async fn truncate_file(&self, _path: &str) -> Result<(), HostFsError> {
                unreachable!()
            }
            async fn set_file_size(&self, _path: &str, _size: u64) -> Result<(), HostFsError> {
                unreachable!()
            }
            async fn set_times(
                &self,
                _path: &str,
                _access_nanos: Option<u64>,
                _modified_nanos: Option<u64>,
            ) -> Result<(), HostFsError> {
                unreachable!()
            }
            async fn create_file(
                &self,
                _path: &str,
                _creation: HostCreation,
            ) -> Result<(), HostFsError> {
                unreachable!()
            }
            async fn create_directory(
                &self,
                _path: &str,
                _creation: HostCreation,
            ) -> Result<(), HostFsError> {
                unreachable!()
            }
            async fn remove(&self, _path: &str, _directory: bool) -> Result<(), HostFsError> {
                unreachable!()
            }
            async fn rename(&self, _source: &str, _destination: &str) -> Result<(), HostFsError> {
                unreachable!()
            }
            async fn hard_link(
                &self,
                _source: &str,
                _destination: &str,
            ) -> Result<(), HostFsError> {
                unreachable!()
            }
            async fn symlink(
                &self,
                _target: &str,
                _link_path: &str,
                _gid: u32,
            ) -> Result<(), HostFsError> {
                unreachable!()
            }
            async fn read_link(&self, _path: &str) -> Result<String, HostFsError> {
                unreachable!()
            }
        }

        let mut meta = host_metadata(
            ObjectIdentity::new(AuthorityDomain::HOST_SHARE_9P, 77),
            0,
            0o104_755,
        );
        meta.uid = 1234;
        meta.gid = 5678;
        let share = HostShare::new(StubHost(meta));
        let attrs = futures_lite::future::block_on(
            share.unix_attributes(FsPath::new("suid-tool").unwrap()),
        )
        .expect("unix attributes");
        assert_eq!(
            attrs,
            UnixAttributes {
                permissions: 0o4755,
                uid: 1234,
                gid: 5678,
            }
        );
    }

    #[test]
    fn read_all_gathers_chunked_host_reads_without_zero_length_tail() {
        use alloc::string::String;
        use alloc::vec::Vec;
        use helios_hal::fs::{FileSystem as _, FsPath, WritePosition};

        use super::{HostCreation, HostFileSystem, HostShare};
        use crate::runtime::{HostDirEntry, HostDirLimit, HostShareRestore};

        #[derive(Clone)]
        struct ChunkedHost {
            data: Vec<u8>,
            chunk_limit: usize,
        }

        impl HostFileSystem for ChunkedHost {
            type Write = core::convert::Infallible;

            fn cache_stats(&self) -> Option<crate::HostFsCacheStats> {
                None
            }
            async fn after_machine_restore(&self, _restore: HostShareRestore) {}
            async fn prepare_snapshot(&self) {}
            fn snapshot_finished(&self) {}
            async fn stat_path(&self, _path: &str) -> Result<HostMetadata, HostFsError> {
                let mut meta = host_metadata(
                    ObjectIdentity::new(AuthorityDomain::HOST_SHARE_9P, 88),
                    0,
                    0o100_644,
                );
                meta.size = self.data.len() as u64;
                Ok(meta)
            }
            async fn read_dir(
                &self,
                _path: &str,
                _limit: HostDirLimit,
            ) -> Result<Vec<HostDirEntry>, HostFsError> {
                unreachable!()
            }
            async fn read_file(&self, _path: &str) -> Result<Vec<u8>, HostFsError> {
                unreachable!()
            }
            async fn read_file_range(
                &self,
                _path: &str,
                offset: u64,
                max_bytes: u32,
            ) -> Result<Vec<u8>, HostFsError> {
                assert_ne!(
                    max_bytes, 0,
                    "read_all / HostShare::read_at must never issue a zero-length 9p read"
                );
                let start = offset as usize;
                let len = (max_bytes as usize)
                    .min(self.chunk_limit)
                    .min(self.data.len() - start);
                Ok(self.data[start..start + len].to_vec())
            }
            async fn prepare_write(
                &self,
                _path: &str,
                _position: WritePosition,
                _len: usize,
            ) -> Result<Self::Write, HostFsError> {
                unreachable!()
            }
            async fn sync_file(&self, _path: &str) -> Result<(), HostFsError> {
                unreachable!()
            }
            async fn truncate_file(&self, _path: &str) -> Result<(), HostFsError> {
                unreachable!()
            }
            async fn set_file_size(&self, _path: &str, _size: u64) -> Result<(), HostFsError> {
                unreachable!()
            }
            async fn set_times(
                &self,
                _path: &str,
                _access_nanos: Option<u64>,
                _modified_nanos: Option<u64>,
            ) -> Result<(), HostFsError> {
                unreachable!()
            }
            async fn create_file(
                &self,
                _path: &str,
                _creation: HostCreation,
            ) -> Result<(), HostFsError> {
                unreachable!()
            }
            async fn create_directory(
                &self,
                _path: &str,
                _creation: HostCreation,
            ) -> Result<(), HostFsError> {
                unreachable!()
            }
            async fn remove(&self, _path: &str, _directory: bool) -> Result<(), HostFsError> {
                unreachable!()
            }
            async fn rename(&self, _source: &str, _destination: &str) -> Result<(), HostFsError> {
                unreachable!()
            }
            async fn hard_link(
                &self,
                _source: &str,
                _destination: &str,
            ) -> Result<(), HostFsError> {
                unreachable!()
            }
            async fn symlink(
                &self,
                _target: &str,
                _link_path: &str,
                _gid: u32,
            ) -> Result<(), HostFsError> {
                unreachable!()
            }
            async fn read_link(&self, _path: &str) -> Result<String, HostFsError> {
                unreachable!()
            }
        }

        let empty = HostShare::new(ChunkedHost {
            data: Vec::new(),
            chunk_limit: 4,
        });
        let got_empty = futures_lite::future::block_on(crate::vfs::read_all(
            &empty,
            FsPath::new("empty").unwrap(),
        ))
        .expect("empty read_all");
        assert!(got_empty.is_empty());

        let expected: Vec<u8> = (0u8..12).collect();
        let multi = HostShare::new(ChunkedHost {
            data: expected.clone(),
            chunk_limit: 4,
        });
        let got_multi = futures_lite::future::block_on(crate::vfs::read_all(
            &multi,
            FsPath::new("multi").unwrap(),
        ))
        .expect("multi-chunk read_all");
        assert_eq!(got_multi.as_ref(), expected.as_slice());

        // Direct zero-length `HostShare::read_at` must also short-circuit cleanly.
        let zero =
            futures_lite::future::block_on(multi.read_at(FsPath::new("multi").unwrap(), 12, 0))
                .expect("zero-length read_at");
        assert!(zero.is_empty());
    }
}
