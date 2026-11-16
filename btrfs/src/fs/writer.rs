//! One owner serializes transactions; readers own independent immutable views.
//! No mutex is held across I/O. A publication guard restores the previous view
//! on abort until durable commit starts, after which recovery requires reopen.

use alloc::sync::Arc;
use core::num::NonZeroUsize;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use super::Filesystem;
use crate::accounting::Allocation;
use crate::compress::write::Encoder;
use crate::retirement::Retirements;
use crate::source::BlockSink;
use crate::transaction::file::WriteOptions;
use crate::transaction::namespace::{Attributes as RawAttributes, Name as RawName};
use crate::transaction::reflink::{CloneRange as RawCloneRange, FileId};
use crate::transaction::{Checkpoint, Transaction};
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
    /// Allocation state of `current`'s generation, loaded and validated once
    /// at mount and replaced only by a commit that published.
    allocation: Allocation,
    retirements: Retirements,
    mount: Arc<MountIdentity>,
}

impl<S: BlockSink> Writer<S> {
    pub async fn mount(source: S) -> Result<Self, WriteError> {
        let current = Filesystem::mount(Arc::new(source)).await?;
        current.superblock().check_writable()?;
        let allocation = Allocation::load(&current.volume, current.snapshot.root_tree).await?;
        Ok(Self {
            current: Some(current),
            allocation,
            retirements: Retirements::default(),
            mount: Arc::new(MountIdentity),
        })
    }

    #[cfg(test)]
    pub(crate) fn committed_allocation(&self) -> &Allocation {
        &self.allocation
    }

    pub fn snapshot(&self) -> Result<Filesystem<Arc<S>>, WriteError> {
        self.current.clone().ok_or(WriteError::WriterPoisoned)
    }

    pub async fn begin(&mut self) -> Result<WriteTransaction<'_, S>, WriteError> {
        let base = self.current.take().ok_or(WriteError::WriterPoisoned)?;
        let publication = Publication {
            current: &mut self.current,
            allocation: &mut self.allocation,
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
            publication.allocation,
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
    allocation: &'a mut Allocation,
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

/// Each mutation borrows this capability exclusively. An error or cancellation
/// restores its operation checkpoint, preserving earlier successful mutations.
/// Dropping the transaction discards the whole batch; commit consumes it.
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

    /// Writes `data` at `offset` and returns the bytes stored, as `write(2)`:
    /// fewer than `data.len()` only when the device ran out of free sectors
    /// partway, never zero for a nonempty write, which fails instead.
    pub async fn write_file<E: Encoder>(
        &mut self,
        file: &InodeHandle,
        offset: u64,
        data: &[u8],
        options: WriteOptions<E>,
    ) -> Result<usize, WriteError> {
        let mut operation = Mutation::new(self).await?;
        operation.checked(file).await?;
        let file = file.id;
        operation.inner.roots.check_writable(file.tree)?;
        let written = operation
            .inner
            .write_file(file.tree, file.inode, offset, data, options)
            .await?;
        operation.accept();
        Ok(written)
    }

    pub async fn truncate_file(
        &mut self,
        file: &InodeHandle,
        size: u64,
        when: Timestamp,
        concurrency: NonZeroUsize,
    ) -> Result<(), WriteError> {
        let mut operation = Mutation::new(self).await?;
        operation.checked(file).await?;
        let file = file.id;
        operation.inner.roots.check_writable(file.tree)?;
        operation
            .inner
            .truncate_file(file.tree, file.inode, size, when, concurrency)
            .await?;
        operation.accept();
        Ok(())
    }

    pub async fn clone_range(
        &mut self,
        range: CloneRange<'_>,
        when: Timestamp,
        concurrency: NonZeroUsize,
    ) -> Result<(), WriteError> {
        let mut operation = Mutation::new(self).await?;
        operation.checked(range.source).await?;
        operation.checked(range.destination).await?;
        let range = RawCloneRange {
            source: range.source.id,
            destination: range.destination.id,
            source_offset: range.source_offset,
            destination_offset: range.destination_offset,
            length: range.length,
        };
        operation
            .inner
            .roots
            .check_writable(range.destination.tree)?;
        operation
            .inner
            .clone_range(range, when, concurrency)
            .await?;
        operation.accept();
        Ok(())
    }

    pub async fn set_times(
        &mut self,
        file: &InodeHandle,
        access: Option<Timestamp>,
        modified: Option<Timestamp>,
        changed: Timestamp,
    ) -> Result<(), WriteError> {
        let mut operation = Mutation::new(self).await?;
        operation.checked(file).await?;
        let file = file.id;
        operation.inner.roots.check_writable(file.tree)?;
        operation
            .inner
            .set_times(file.tree, file.inode, access, modified, changed)
            .await?;
        operation.accept();
        Ok(())
    }

    pub async fn create_file(
        &mut self,
        name: Name<'_>,
        attributes: Attributes,
        when: Timestamp,
    ) -> Result<InodeHandle, WriteError> {
        self.create(name, attributes.raw(0o100000)?, when).await
    }

    pub async fn create_directory(
        &mut self,
        name: Name<'_>,
        attributes: Attributes,
        when: Timestamp,
    ) -> Result<InodeHandle, WriteError> {
        self.create(name, attributes.raw(0o040000)?, when).await
    }

    async fn create(
        &mut self,
        name: Name<'_>,
        attributes: RawAttributes,
        when: Timestamp,
    ) -> Result<InodeHandle, WriteError> {
        let mut operation = Mutation::new(self).await?;
        let name = operation.entry_name(name).await?;
        operation.inner.roots.check_writable(name.tree)?;
        let inode = operation.inner.create_node(name, attributes, when).await?;
        let handle = operation
            .load_handle(FileId {
                tree: name.tree,
                inode,
            })
            .await?;
        operation.accept();
        Ok(handle)
    }

    pub async fn hard_link(
        &mut self,
        name: Name<'_>,
        file: &InodeHandle,
        when: Timestamp,
    ) -> Result<(), WriteError> {
        let mut operation = Mutation::new(self).await?;
        operation.checked(file).await?;
        let name = operation.entry_name(name).await?;
        if file.tree() != name.tree {
            return Err(WriteError::CrossSubvolume);
        }
        let inode = file.number();
        operation.inner.roots.check_writable(name.tree)?;
        operation.inner.hard_link(name, inode, when).await?;
        operation.accept();
        Ok(())
    }

    pub async fn symlink(
        &mut self,
        name: Name<'_>,
        target: &[u8],
        attributes: Attributes,
        when: Timestamp,
    ) -> Result<InodeHandle, WriteError> {
        let mut operation = Mutation::new(self).await?;
        let name = operation.entry_name(name).await?;
        operation.inner.roots.check_writable(name.tree)?;
        let inode = operation
            .inner
            .symlink(name, target, attributes.raw(0o120000)?, when)
            .await?;
        let handle = operation
            .load_handle(FileId {
                tree: name.tree,
                inode,
            })
            .await?;
        operation.accept();
        Ok(handle)
    }

    pub async fn rename(
        &mut self,
        source: Name<'_>,
        destination: Name<'_>,
        when: Timestamp,
    ) -> Result<(), WriteError> {
        let mut operation = Mutation::new(self).await?;
        let source = operation.entry_name(source).await?;
        let destination = operation.entry_name(destination).await?;
        operation.inner.roots.check_writable(source.tree)?;
        operation.inner.roots.check_writable(destination.tree)?;
        operation.inner.rename(source, destination, when).await?;
        operation.accept();
        Ok(())
    }

    pub async fn unlink_name(&mut self, name: Name<'_>, when: Timestamp) -> Result<(), WriteError> {
        let mut operation = Mutation::new(self).await?;
        let name = operation.entry_name(name).await?;
        operation.inner.roots.check_writable(name.tree)?;
        operation.inner.unlink_name(name, when).await?;
        operation.accept();
        Ok(())
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
        let mut committed = inner
            .commit(uuid, concurrency, || {
                publication.publishing = true;
            })
            .await?;
        if let Some(allocation) = committed.allocation.take() {
            *publication.allocation = allocation;
        }
        let mut current = publication.base.take().expect("publication owns its base");
        current.publish(committed);
        *publication.current = Some(current);
        creation.store(true, Ordering::Release);
        Ok(())
    }
}

/// The mutation future owns this guard. Its drop restores the complete private
/// state after the future's in-flight I/O has been dropped. No durable root has
/// been published, and committed extents remain pinned throughout rollback.
struct Mutation<'op, 'tx, S: BlockSink> {
    transaction: &'op mut WriteTransaction<'tx, S>,
    saved: Option<Checkpoint>,
}

impl<'op, 'tx, S: BlockSink> Mutation<'op, 'tx, S> {
    /// Checkpoints the transaction, then makes the space the operation may
    /// need: a failure here restores the checkpoint like any other.
    async fn new(transaction: &'op mut WriteTransaction<'tx, S>) -> Result<Self, WriteError> {
        let saved = Some(transaction.inner.checkpoint());
        let operation = Self { transaction, saved };
        operation.transaction.inner.prepare_mutation().await?;
        Ok(operation)
    }
    fn accept(mut self) {
        self.transaction.inner.space.accept_operation();
        self.saved = None;
    }
}

impl<'tx, S: BlockSink> Deref for Mutation<'_, 'tx, S> {
    type Target = WriteTransaction<'tx, S>;
    fn deref(&self) -> &Self::Target {
        self.transaction
    }
}

impl<S: BlockSink> DerefMut for Mutation<'_, '_, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.transaction
    }
}

impl<S: BlockSink> Drop for Mutation<'_, '_, S> {
    fn drop(&mut self) {
        if let Some(saved) = self.saved.take() {
            self.transaction.inner.restore(saved);
        }
    }
}
