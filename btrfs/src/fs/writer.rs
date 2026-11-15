//! One owner serializes transactions; readers own independent immutable views.
//! No mutex is held across I/O. A publication guard restores the previous view
//! on abort until durable commit starts, after which recovery requires reopen.

use alloc::sync::Arc;
use core::num::NonZeroUsize;

use super::Filesystem;
use crate::Timestamp;
use crate::compress::write::Encoder;
use crate::retirement::Retirements;
use crate::source::BlockSink;
use crate::transaction::Transaction;
use crate::transaction::file::WriteOptions;
use crate::transaction::namespace::{Attributes, Name};
use crate::transaction::reflink::{CloneRange, FileId};
use crate::tree::write::WriteError;

pub(crate) struct Writer<S> {
    current: Option<Filesystem<Arc<S>>>,
    retirements: Retirements,
}

impl<S: BlockSink> Writer<S> {
    pub(crate) async fn mount(source: S) -> Result<Self, WriteError> {
        let current = Filesystem::mount(Arc::new(source)).await?;
        current.superblock().check_writable()?;
        Ok(Self {
            current: Some(current),
            retirements: Retirements::default(),
        })
    }

    pub(crate) fn snapshot(&self) -> Result<Filesystem<Arc<S>>, WriteError> {
        self.current.clone().ok_or(WriteError::WriterPoisoned)
    }

    pub(crate) async fn begin(&mut self) -> Result<WriteTransaction<'_, S>, WriteError> {
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
        Ok(WriteTransaction { inner, publication })
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
pub(crate) struct WriteTransaction<'a, S> {
    inner: Transaction<'a, Arc<S>>,
    publication: Publication<'a, S>,
}

impl<'a, S: BlockSink> WriteTransaction<'a, S> {
    #[cfg(test)]
    pub(crate) fn edits(&mut self) -> &mut Transaction<'a, Arc<S>> {
        &mut self.inner
    }

    pub(crate) async fn read_file(
        &self,
        file: FileId,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, WriteError> {
        self.inner
            .read_file(file.tree, file.inode, offset, output)
            .await
    }

    pub(crate) async fn write_file<E: Encoder>(
        mut self,
        file: FileId,
        offset: u64,
        data: &[u8],
        options: WriteOptions<E>,
    ) -> Result<(Self, usize), WriteError> {
        self.inner.roots.check_writable(file.tree)?;
        let written = self
            .inner
            .write_file(file.tree, file.inode, offset, data, options)
            .await?;
        Ok((self, written))
    }

    pub(crate) async fn truncate_file(
        mut self,
        file: FileId,
        size: u64,
        when: Timestamp,
        concurrency: NonZeroUsize,
    ) -> Result<Self, WriteError> {
        self.inner.roots.check_writable(file.tree)?;
        self.inner
            .truncate_file(file.tree, file.inode, size, when, concurrency)
            .await?;
        Ok(self)
    }

    pub(crate) async fn clone_range(
        mut self,
        range: CloneRange,
        when: Timestamp,
        concurrency: NonZeroUsize,
    ) -> Result<Self, WriteError> {
        self.inner.roots.check_writable(range.destination.tree)?;
        self.inner.clone_range(range, when, concurrency).await?;
        Ok(self)
    }

    pub(crate) async fn set_times(
        mut self,
        file: FileId,
        access: Option<Timestamp>,
        modified: Option<Timestamp>,
        changed: Timestamp,
    ) -> Result<Self, WriteError> {
        self.inner.roots.check_writable(file.tree)?;
        self.inner
            .set_times(file.tree, file.inode, access, modified, changed)
            .await?;
        Ok(self)
    }

    pub(crate) async fn create_node(
        mut self,
        name: Name<'_>,
        attributes: Attributes,
        when: Timestamp,
    ) -> Result<(Self, FileId), WriteError> {
        self.inner.roots.check_writable(name.tree)?;
        let inode = self.inner.create_node(name, attributes, when).await?;
        Ok((
            self,
            FileId {
                tree: name.tree,
                inode,
            },
        ))
    }

    pub(crate) async fn hard_link(
        mut self,
        name: Name<'_>,
        inode: u64,
        when: Timestamp,
    ) -> Result<Self, WriteError> {
        self.inner.roots.check_writable(name.tree)?;
        self.inner.hard_link(name, inode, when).await?;
        Ok(self)
    }

    pub(crate) async fn symlink(
        mut self,
        name: Name<'_>,
        target: &[u8],
        attributes: Attributes,
        when: Timestamp,
    ) -> Result<(Self, FileId), WriteError> {
        self.inner.roots.check_writable(name.tree)?;
        let inode = self.inner.symlink(name, target, attributes, when).await?;
        Ok((
            self,
            FileId {
                tree: name.tree,
                inode,
            },
        ))
    }

    pub(crate) async fn rename(
        mut self,
        source: Name<'_>,
        destination: Name<'_>,
        when: Timestamp,
    ) -> Result<Self, WriteError> {
        self.inner.roots.check_writable(source.tree)?;
        self.inner.roots.check_writable(destination.tree)?;
        self.inner.rename(source, destination, when).await?;
        Ok(self)
    }

    pub(crate) async fn unlink_name(
        mut self,
        name: Name<'_>,
        when: Timestamp,
    ) -> Result<Self, WriteError> {
        self.inner.roots.check_writable(name.tree)?;
        self.inner.unlink_name(name, when).await?;
        Ok(self)
    }

    pub(crate) async fn commit(
        self,
        uuid: impl FnMut() -> [u8; 16],
        concurrency: NonZeroUsize,
    ) -> Result<(), WriteError> {
        let Self {
            inner,
            mut publication,
        } = self;
        let committed = inner
            .commit(uuid, concurrency, || {
                publication.publishing = true;
            })
            .await?;
        let mut current = publication.base.take().expect("publication owns its base");
        current.publish(committed);
        *publication.current = Some(current);
        Ok(())
    }
}
