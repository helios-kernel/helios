//! One owner serializes transactions; readers own independent immutable views.
//! No mutex is held across I/O. A publication guard restores the previous view
//! on abort until durable commit starts, after which recovery requires reopen.

use alloc::sync::Arc;
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicBool, Ordering};

use super::Filesystem;
use crate::compress::write::Encoder;
use crate::retirement::Retirements;
use crate::source::BlockSink;
use crate::transaction::Transaction;
use crate::transaction::file::WriteOptions;
use crate::transaction::namespace::{Attributes as RawAttributes, Name as RawName};
use crate::transaction::reflink::{CloneRange as RawCloneRange, FileId};
use crate::tree::write::WriteError;
use crate::{Error, FileKind, Metadata, Timestamp};

#[derive(Debug)]
struct MountIdentity;

/// A mount-bound inode identity. Its generation detects reuse after deletion;
/// newly created identities also retain their transaction's publication token.
#[derive(Clone, Debug)]
pub struct InodeHandle {
    mount: Arc<MountIdentity>,
    creation: Option<Arc<AtomicBool>>,
    id: FileId,
    generation: u64,
}

impl InodeHandle {
    pub fn tree(&self) -> u64 {
        self.id.tree
    }
    pub fn number(&self) -> u64 {
        self.id.inode
    }
}

/// Permissions and ownership for a newly created entry. File type is selected
/// by create_file, create_directory or symlink, never by permission bits.
#[derive(Clone, Copy, Debug)]
pub struct Attributes {
    pub permissions: u32,
    pub uid: u32,
    pub gid: u32,
}

impl Attributes {
    fn raw(self, kind: u32) -> Result<RawAttributes, WriteError> {
        if self.permissions & !0o7777 != 0 {
            return Err(WriteError::InvalidPermissions {
                permissions: self.permissions,
            });
        }
        Ok(RawAttributes {
            mode: kind | self.permissions,
            uid: self.uid,
            gid: self.gid,
        })
    }
}

#[derive(Clone, Copy)]
pub struct Name<'a> {
    pub parent: &'a InodeHandle,
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy)]
pub struct CloneRange<'a> {
    pub source: &'a InodeHandle,
    pub destination: &'a InodeHandle,
    pub source_offset: u64,
    pub destination_offset: u64,
    pub length: u64,
}

pub struct Writer<S> {
    current: Option<Filesystem<Arc<S>>>,
    retirements: Retirements,
    mount: Arc<MountIdentity>,
}

impl<S: BlockSink> Writer<S> {
    pub async fn mount(source: S) -> Result<Self, WriteError> {
        let current = Filesystem::mount(Arc::new(source)).await?;
        current.superblock().check_writable()?;
        Ok(Self {
            current: Some(current),
            retirements: Retirements::default(),
            mount: Arc::new(MountIdentity),
        })
    }

    pub fn snapshot(&self) -> Result<Filesystem<Arc<S>>, WriteError> {
        self.current.clone().ok_or(WriteError::WriterPoisoned)
    }

    pub async fn begin(&mut self) -> Result<WriteTransaction<'_, S>, WriteError> {
        let base = self.current.take().ok_or(WriteError::WriterPoisoned)?;
        let publication = Publication {
            current: &mut self.current,
            base: Some(base),
            publishing: false,
        };
        let base = publication
            .base
            .as_ref()
            .expect("publication owns its base");
        let inner = Transaction::new(
            base.volume.clone(),
            base.snapshot.clone(),
            &mut self.retirements,
        )
        .await?;
        Ok(WriteTransaction {
            inner,
            publication,
            mount: self.mount.clone(),
            creation: Arc::new(AtomicBool::new(false)),
        })
    }
}

struct Publication<'a, S> {
    current: &'a mut Option<Filesystem<Arc<S>>>,
    base: Option<Filesystem<Arc<S>>>,
    publishing: bool,
}

impl<S> Drop for Publication<'_, S> {
    fn drop(&mut self) {
        if !self.publishing
            && let Some(base) = self.base.take()
        {
            *self.current = Some(base);
        }
    }
}

/// Every mutation consumes this capability and returns it only on success.
/// Dropping a pending mutation or returning an error discards all edits in the
/// transaction. Reads borrow the capability and cannot publish its overlay.
#[must_use = "a transaction must be committed to publish its changes"]
pub struct WriteTransaction<'a, S> {
    inner: Transaction<'a, Arc<S>>,
    publication: Publication<'a, S>,
    mount: Arc<MountIdentity>,
    creation: Arc<AtomicBool>,
}

impl<'a, S: BlockSink> WriteTransaction<'a, S> {
    #[cfg(test)]
    pub(crate) fn edits(&mut self) -> &mut Transaction<'a, Arc<S>> {
        &mut self.inner
    }

    async fn load_handle(&self, id: FileId) -> Result<InodeHandle, WriteError> {
        let metadata = self.inner.inode_metadata(id).await?;
        Ok(InodeHandle {
            mount: self.mount.clone(),
            creation: (metadata.generation == self.inner.generation())
                .then(|| self.creation.clone()),
            id,
            generation: metadata.generation,
        })
    }

    #[cfg(test)]
    pub(crate) async fn fixture_handle(&self, id: FileId) -> Result<InodeHandle, WriteError> {
        self.load_handle(id).await
    }

    async fn checked(&self, handle: &InodeHandle) -> Result<Metadata, WriteError> {
        if !Arc::ptr_eq(&self.mount, &handle.mount) {
            return Err(WriteError::ForeignHandle);
        }
        if handle.creation.as_ref().is_some_and(|creation| {
            !Arc::ptr_eq(creation, &self.creation) && !creation.load(Ordering::Acquire)
        }) {
            return Err(WriteError::AbortedHandle);
        }
        let stale = || WriteError::StaleHandle {
            tree: handle.id.tree,
            inode: handle.id.inode,
            generation: handle.generation,
        };
        let metadata = match self.inner.inode_metadata(handle.id).await {
            Err(WriteError::Read(Error::MissingInode { .. })) => return Err(stale()),
            result => result?,
        };
        if metadata.generation != handle.generation {
            return Err(stale());
        }
        Ok(metadata)
    }

    async fn entry_name<'b>(&self, name: Name<'b>) -> Result<RawName<'b>, WriteError> {
        let metadata = self.checked(name.parent).await?;
        if metadata.kind != FileKind::Directory {
            return Err(Error::WrongKind {
                tree: name.parent.tree(),
                inode: name.parent.number(),
                expected: FileKind::Directory,
                found: metadata.kind,
            }
            .into());
        }
        Ok(RawName {
            tree: name.parent.tree(),
            parent: name.parent.number(),
            bytes: name.bytes,
        })
    }

    pub async fn root(&self) -> Result<InodeHandle, WriteError> {
        let record = self
            .publication
            .base
            .as_ref()
            .expect("publication owns its base")
            .snapshot
            .default_subvolume;
        self.load_handle(FileId {
            tree: record.root.tree,
            inode: record.root_dirid,
        })
        .await
    }

    pub async fn metadata(&self, handle: &InodeHandle) -> Result<Metadata, WriteError> {
        self.checked(handle).await
    }

    pub async fn lookup(
        &self,
        parent: &InodeHandle,
        bytes: &[u8],
    ) -> Result<Option<InodeHandle>, WriteError> {
        let name = self.entry_name(Name { parent, bytes }).await?;
        match self.inner.lookup_file(name).await? {
            Some(id) => self.load_handle(id).await.map(Some),
            None => Ok(None),
        }
    }

    pub async fn read_file(
        &self,
        file: &InodeHandle,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, WriteError> {
        self.checked(file).await?;
        let file = file.id;
        self.inner
            .read_file(file.tree, file.inode, offset, output)
            .await
    }

    pub async fn write_file<E: Encoder>(
        mut self,
        file: &InodeHandle,
        offset: u64,
        data: &[u8],
        options: WriteOptions<E>,
    ) -> Result<(Self, usize), WriteError> {
        self.checked(file).await?;
        let file = file.id;
        self.inner.roots.check_writable(file.tree)?;
        let written = self
            .inner
            .write_file(file.tree, file.inode, offset, data, options)
            .await?;
        Ok((self, written))
    }

    pub async fn truncate_file(
        mut self,
        file: &InodeHandle,
        size: u64,
        when: Timestamp,
        concurrency: NonZeroUsize,
    ) -> Result<Self, WriteError> {
        self.checked(file).await?;
        let file = file.id;
        self.inner.roots.check_writable(file.tree)?;
        self.inner
            .truncate_file(file.tree, file.inode, size, when, concurrency)
            .await?;
        Ok(self)
    }

    pub async fn clone_range(
        mut self,
        range: CloneRange<'_>,
        when: Timestamp,
        concurrency: NonZeroUsize,
    ) -> Result<Self, WriteError> {
        self.checked(range.source).await?;
        self.checked(range.destination).await?;
        let range = RawCloneRange {
            source: range.source.id,
            destination: range.destination.id,
            source_offset: range.source_offset,
            destination_offset: range.destination_offset,
            length: range.length,
        };
        self.inner.roots.check_writable(range.destination.tree)?;
        self.inner.clone_range(range, when, concurrency).await?;
        Ok(self)
    }

    pub async fn set_times(
        mut self,
        file: &InodeHandle,
        access: Option<Timestamp>,
        modified: Option<Timestamp>,
        changed: Timestamp,
    ) -> Result<Self, WriteError> {
        self.checked(file).await?;
        let file = file.id;
        self.inner.roots.check_writable(file.tree)?;
        self.inner
            .set_times(file.tree, file.inode, access, modified, changed)
            .await?;
        Ok(self)
    }

    pub async fn create_file(
        self,
        name: Name<'_>,
        attributes: Attributes,
        when: Timestamp,
    ) -> Result<(Self, InodeHandle), WriteError> {
        self.create(name, attributes.raw(0o100000)?, when).await
    }

    pub async fn create_directory(
        self,
        name: Name<'_>,
        attributes: Attributes,
        when: Timestamp,
    ) -> Result<(Self, InodeHandle), WriteError> {
        self.create(name, attributes.raw(0o040000)?, when).await
    }

    async fn create(
        mut self,
        name: Name<'_>,
        attributes: RawAttributes,
        when: Timestamp,
    ) -> Result<(Self, InodeHandle), WriteError> {
        let name = self.entry_name(name).await?;
        self.inner.roots.check_writable(name.tree)?;
        let inode = self.inner.create_node(name, attributes, when).await?;
        let handle = self
            .load_handle(FileId {
                tree: name.tree,
                inode,
            })
            .await?;
        Ok((self, handle))
    }

    pub async fn hard_link(
        mut self,
        name: Name<'_>,
        file: &InodeHandle,
        when: Timestamp,
    ) -> Result<Self, WriteError> {
        self.checked(file).await?;
        let name = self.entry_name(name).await?;
        if file.tree() != name.tree {
            return Err(WriteError::CrossSubvolume);
        }
        let inode = file.number();
        self.inner.roots.check_writable(name.tree)?;
        self.inner.hard_link(name, inode, when).await?;
        Ok(self)
    }

    pub async fn symlink(
        mut self,
        name: Name<'_>,
        target: &[u8],
        attributes: Attributes,
        when: Timestamp,
    ) -> Result<(Self, InodeHandle), WriteError> {
        let name = self.entry_name(name).await?;
        self.inner.roots.check_writable(name.tree)?;
        let inode = self
            .inner
            .symlink(name, target, attributes.raw(0o120000)?, when)
            .await?;
        let handle = self
            .load_handle(FileId {
                tree: name.tree,
                inode,
            })
            .await?;
        Ok((self, handle))
    }

    pub async fn rename(
        mut self,
        source: Name<'_>,
        destination: Name<'_>,
        when: Timestamp,
    ) -> Result<Self, WriteError> {
        let source = self.entry_name(source).await?;
        let destination = self.entry_name(destination).await?;
        self.inner.roots.check_writable(source.tree)?;
        self.inner.roots.check_writable(destination.tree)?;
        self.inner.rename(source, destination, when).await?;
        Ok(self)
    }

    pub async fn unlink_name(
        mut self,
        name: Name<'_>,
        when: Timestamp,
    ) -> Result<Self, WriteError> {
        let name = self.entry_name(name).await?;
        self.inner.roots.check_writable(name.tree)?;
        self.inner.unlink_name(name, when).await?;
        Ok(self)
    }

    pub async fn commit(
        self,
        uuid: impl FnMut() -> [u8; 16],
        concurrency: NonZeroUsize,
    ) -> Result<(), WriteError> {
        let Self {
            inner,
            mut publication,
            creation,
            mount: _,
        } = self;
        let committed = inner
            .commit(uuid, concurrency, || {
                publication.publishing = true;
            })
            .await?;
        let mut current = publication.base.take().expect("publication owns its base");
        current.publish(committed);
        *publication.current = Some(current);
        creation.store(true, Ordering::Release);
        Ok(())
    }
}
