//! One owner serializes transactions; readers own independent immutable views.
//! No mutex is held across I/O. A publication guard restores the previous view
//! on abort until durable commit starts, after which recovery requires reopen.

use alloc::sync::Arc;
use core::num::NonZeroUsize;

use super::Filesystem;
use crate::retirement::Retirements;
use crate::source::BlockSink;
use crate::transaction::Transaction;
use crate::tree::write::WriteError;

pub(crate) struct Writer<S> {
    current: Option<Filesystem<Arc<S>>>,
    retirements: Retirements,
}

impl<S: BlockSink> Writer<S> {
    pub(crate) async fn mount(source: S) -> Result<Self, WriteError> {
        Ok(Self {
            current: Some(Filesystem::mount(Arc::new(source)).await?),
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

pub(crate) struct WriteTransaction<'a, S> {
    inner: Transaction<'a, Arc<S>>,
    publication: Publication<'a, S>,
}

impl<'a, S: BlockSink> WriteTransaction<'a, S> {
    pub(crate) fn edits(&mut self) -> &mut Transaction<'a, Arc<S>> {
        &mut self.inner
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
