//! The device, the superblock chosen for it, and the chunk map: everything
//! needed to turn a logical address into verified bytes.

use crate::chunk::ChunkMap;
use crate::error::Error;
use crate::source::BlockSource;
use crate::superblock::Superblock;
use alloc::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Mapping {
    pub(crate) superblock: Superblock,
    chunks: Arc<ChunkMap>,
}

impl Mapping {
    #[cfg(feature = "write")]
    pub(crate) fn advance(&self, superblock: Superblock) -> Arc<Self> {
        Arc::new(Self {
            superblock,
            chunks: self.chunks.clone(),
        })
    }
}

/// A mounted device's address space.
///
/// Immutable once built: every method takes `&self`, holds no lock and may
/// run on any number of processors at once.
#[derive(Clone)]
pub(crate) struct Volume<S> {
    source: S,
    mapping: Arc<Mapping>,
}

impl<S: BlockSource> Volume<S> {
    pub(crate) fn new(source: S, superblock: Superblock, chunks: ChunkMap) -> Self {
        Self {
            source,
            mapping: Arc::new(Mapping {
                superblock,
                chunks: Arc::new(chunks),
            }),
        }
    }

    pub(crate) fn superblock(&self) -> &Superblock {
        &self.mapping.superblock
    }

    pub(crate) fn chunks(&self) -> &ChunkMap {
        &self.mapping.chunks
    }

    /// Swaps in the chunk map read from the chunk tree, returning the
    /// bootstrap map it was read through.
    pub(crate) fn replace_chunks(&mut self, chunks: ChunkMap) -> Arc<ChunkMap> {
        let mapping = Arc::get_mut(&mut self.mapping).expect("bootstrap mapping is not published");
        core::mem::replace(&mut mapping.chunks, Arc::new(chunks))
    }

    #[cfg(feature = "write")]
    pub(crate) fn install(&mut self, mapping: Arc<Mapping>) {
        self.mapping = mapping;
    }

    pub(crate) fn mapping(&self) -> Arc<Mapping> {
        self.mapping.clone()
    }

    pub(crate) fn view(&self, mapping: &Arc<Mapping>) -> Volume<&S> {
        Volume {
            source: &self.source,
            mapping: mapping.clone(),
        }
    }

    /// Reads `buf.len()` bytes at `logical` into `buf` and runs `check`
    /// over them, trying each copy of the chunk in turn until one passes.
    ///
    /// Fails with the first copy's error when no copy passes: the primary
    /// copy's defect is the one a reader of the format expects to hear
    /// about.
    pub(crate) async fn read_verified<T>(
        &self,
        logical: u64,
        buf: &mut [u8],
        check: impl Fn(&[u8]) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let copies = self.chunks().map(logical, buf.len() as u64)?;
        let mut first_error = None;
        for physical in copies {
            let outcome = match self.source.read_at(physical, buf).await {
                Ok(()) => check(buf),
                Err(source) => Err(Error::Io {
                    offset: physical,
                    len: buf.len(),
                    source,
                }),
            };
            match outcome {
                Ok(value) => return Ok(value),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        Err(first_error.unwrap_or(Error::Unmapped {
            logical,
            len: buf.len() as u64,
        }))
    }
}

#[cfg(feature = "write")]
impl<S: crate::source::BlockSink> Volume<S> {
    pub(crate) async fn commit_image(
        &self,
    ) -> Result<crate::commit::CommitImage, crate::tree::write::WriteError> {
        let selected = crate::superblock::select(&self.source).await?;
        if selected.superblock != *self.superblock() {
            return Err(crate::tree::write::WriteError::StaleSnapshot);
        }
        Ok(crate::commit::CommitImage {
            bytes: alloc::sync::Arc::new(
                selected
                    .bytes
                    .as_slice()
                    .try_into()
                    .expect("selected superblock has fixed size"),
            ),
        })
    }

    /// Mirrors are ordered: each sink commit flushes the staged tree blocks,
    /// and the primary becomes authoritative only after the backups persist.
    pub(crate) async fn publish(
        &self,
        mut image: crate::commit::CommitImage,
    ) -> Result<(), crate::tree::write::WriteError> {
        use crate::source::READ_ALIGNMENT;
        for offset in crate::superblock::MIRROR_OFFSETS.into_iter().rev() {
            if offset + crate::ondisk::SUPERBLOCK_BYTES as u64 > self.source.size_bytes() {
                continue;
            }
            self.source
                .commit(
                    offset / READ_ALIGNMENT,
                    image.at(offset, self.superblock().csum_type()),
                )
                .await
                .map_err(|source| Error::Io {
                    offset,
                    len: crate::ondisk::SUPERBLOCK_BYTES,
                    source,
                })?;
        }
        Ok(())
    }

    /// Stage every physical copy of an unreachable allocation. The caller owns
    /// the allocation and supplies the maximum number of in-flight block writes.
    pub(crate) async fn stage(
        &self,
        logical: u64,
        bytes: &[u8],
        concurrency: core::num::NonZeroUsize,
    ) -> Result<(), crate::tree::write::WriteError> {
        use crate::source::{PendingWrites, READ_ALIGNMENT};
        use crate::tree::write::WriteError;

        if bytes.is_empty()
            || !logical.is_multiple_of(READ_ALIGNMENT)
            || !bytes.len().is_multiple_of(READ_ALIGNMENT as usize)
        {
            return Err(WriteError::StagingRange {
                logical,
                bytes: bytes.len(),
            });
        }
        let copies = self.chunks().map(logical, bytes.len() as u64)?;
        let mut writes = PendingWrites::new(concurrency);
        for physical in copies {
            for (index, bytes) in bytes
                .as_chunks::<{ READ_ALIGNMENT as usize }>()
                .0
                .iter()
                .enumerate()
            {
                let offset = physical + index as u64 * READ_ALIGNMENT;
                writes
                    .push(async move {
                        self.source
                            .stage(offset / READ_ALIGNMENT, bytes)
                            .await
                            .map_err(|source| Error::Io {
                                offset,
                                len: bytes.len(),
                                source,
                            })
                    })
                    .await?;
            }
        }
        writes.finish().await?;
        Ok(())
    }
}
