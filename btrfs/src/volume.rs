//! The backing device(s), the superblock chosen for them, and the chunk map:
//! everything needed to turn a logical address into verified bytes.

use crate::chunk::ChunkMap;
use crate::error::Error;
use crate::source::BlockSource;
use crate::superblock::Superblock;
use alloc::sync::Arc;
use alloc::vec::Vec;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Mapping {
    pub(crate) superblock: Superblock,
    chunks: Arc<ChunkMap>,
}

impl Mapping {
    /// The mapping of the generation a transaction publishes: its superblock
    /// and the chunks the transaction's own volume holds, including any it
    /// allocated.
    #[cfg(feature = "write")]
    pub(crate) fn advance(superblock: Superblock, chunks: Arc<ChunkMap>) -> Arc<Self> {
        Arc::new(Self { superblock, chunks })
    }
}

/// A mounted volume's address space, backed by one or more devices.
///
/// Immutable once built: every method takes `&self`, holds no lock and may
/// run on any number of processors at once. Cloning is O(1) reference-count
/// increments and requires no `Clone` bound on `S`.
pub(crate) struct Volume<S> {
    devices: Arc<Vec<(u64, Arc<S>)>>,
    mapping: Arc<Mapping>,
}

impl<S> Clone for Volume<S> {
    fn clone(&self) -> Self {
        Self {
            devices: self.devices.clone(),
            mapping: self.mapping.clone(),
        }
    }
}

impl<S: BlockSource> Volume<S> {
    pub(crate) fn new_multi(
        devices: Vec<(u64, Arc<S>)>,
        superblock: Superblock,
        chunks: ChunkMap,
    ) -> Self {
        Self {
            devices: Arc::new(devices),
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

    /// Looks up the backing device for `devid`.
    pub(crate) fn device(&self, devid: u64) -> Option<&Arc<S>> {
        self.devices
            .iter()
            .find(|(id, _)| *id == devid)
            .map(|(_, dev)| dev)
    }

    /// All live devices attached to this volume, as `(devid, source)` pairs.
    #[cfg(feature = "write")]
    pub(crate) fn devices(&self) -> &[(u64, Arc<S>)] {
        &self.devices
    }

    /// Shared handle to the current device list, used when publishing a
    /// committed transaction that added, removed or replaced a device.
    #[cfg(feature = "write")]
    pub(crate) fn shared_devices(&self) -> Arc<Vec<(u64, Arc<S>)>> {
        self.devices.clone()
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

    #[cfg(feature = "write")]
    pub(crate) fn install_devices(&mut self, devices: Arc<Vec<(u64, Arc<S>)>>) {
        self.devices = devices;
    }

    #[cfg(feature = "write")]
    pub(crate) fn add_device(&mut self, devid: u64, source: Arc<S>) {
        let mut next = (*self.devices).clone();
        next.push((devid, source));
        next.sort_unstable_by_key(|(id, _)| *id);
        self.devices = Arc::new(next);
    }

    #[cfg(feature = "write")]
    pub(crate) fn remove_device(&mut self, devid: u64) -> Option<Arc<S>> {
        let mut next = (*self.devices).clone();
        let pos = next.iter().position(|(id, _)| *id == devid)?;
        let (_, removed) = next.remove(pos);
        self.devices = Arc::new(next);
        Some(removed)
    }

    #[cfg(feature = "write")]
    pub(crate) fn replace_device(&mut self, devid: u64, target: Arc<S>) -> Option<Arc<S>> {
        let mut next = (*self.devices).clone();
        let slot = next.iter_mut().find(|(id, _)| *id == devid)?;
        let old = core::mem::replace(&mut slot.1, target);
        self.devices = Arc::new(next);
        Some(old)
    }

    #[cfg(feature = "write")]
    pub(crate) fn shared_chunks(&self) -> Arc<ChunkMap> {
        self.mapping.chunks.clone()
    }

    /// Learn a chunk the transaction allocated. Readers of older generations
    /// keep the mapping they opened; only this volume sees the new chunk.
    #[cfg(feature = "write")]
    pub(crate) fn add_chunk(
        &mut self,
        chunk: crate::chunk::Chunk,
    ) -> Result<(), crate::error::ChunkDefect> {
        let mut chunks = (*self.mapping.chunks).clone();
        chunks.insert(chunk)?;
        self.mapping = Arc::new(Mapping {
            superblock: self.mapping.superblock.clone(),
            chunks: Arc::new(chunks),
        });
        Ok(())
    }

    /// Forget a chunk the transaction removed. Readers of older generations
    /// keep the mapping they opened.
    #[cfg(feature = "write")]
    pub(crate) fn remove_chunk(&mut self, logical: u64) -> Option<crate::chunk::Chunk> {
        let mut chunks = (*self.mapping.chunks).clone();
        let removed = chunks.remove(logical)?;
        self.mapping = Arc::new(Mapping {
            superblock: self.mapping.superblock.clone(),
            chunks: Arc::new(chunks),
        });
        Some(removed)
    }

    pub(crate) fn mapping(&self) -> Arc<Mapping> {
        self.mapping.clone()
    }

    pub(crate) fn view(&self, mapping: &Arc<Mapping>) -> Volume<S> {
        Volume {
            devices: self.devices.clone(),
            mapping: mapping.clone(),
        }
    }

    /// Reads `buf.len()` bytes directly from `devid` at `physical`.
    #[cfg(feature = "write")]
    pub(crate) async fn read_raw(
        &self,
        devid: u64,
        physical: u64,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        let Some(dev) = self.device(devid) else {
            return Err(Error::Chunk {
                logical: physical,
                defect: crate::error::ChunkDefect::Device(devid),
            });
        };
        dev.read_at(physical, buf)
            .await
            .map_err(|source| Error::Io {
                offset: physical,
                len: buf.len(),
                source,
            })
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
        for stripe in copies {
            let physical = stripe.offset;
            let outcome = match self.device(stripe.devid) {
                Some(dev) => match dev.read_at(physical, buf).await {
                    Ok(()) => check(buf),
                    Err(source) => Err(Error::Io {
                        offset: physical,
                        len: buf.len(),
                        source,
                    }),
                },
                None => Err(Error::Chunk {
                    logical,
                    defect: crate::error::ChunkDefect::Device(stripe.devid),
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
        let primary = self
            .device(self.superblock().devid())
            .or_else(|| self.devices.first().map(|(_, dev)| dev))
            .ok_or(crate::tree::write::WriteError::StaleSnapshot)?;
        let selected = crate::superblock::select(primary.as_ref()).await?;
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
    /// When `dev_items` is non-empty, each live device receives a superblock
    /// carrying its own `RawDevItem`.
    pub(crate) async fn publish(
        &self,
        mut image: crate::commit::CommitImage,
        dev_items: &[(u64, crate::ondisk::RawDevItem)],
    ) -> Result<(), crate::tree::write::WriteError> {
        use crate::source::READ_ALIGNMENT;
        let algorithm = self.superblock().csum_type();
        for (devid, dev) in self.devices.iter() {
            if let Some((_, item)) = dev_items.iter().find(|(id, _)| id == devid) {
                image.set_dev_item(*item);
            }
            let max_bytes = dev_items.iter().find(|(id, _)| id == devid).map_or_else(
                || dev.size_bytes(),
                |(_, item)| item.total_bytes.get().min(dev.size_bytes()),
            );
            for offset in crate::superblock::MIRROR_OFFSETS.into_iter().rev() {
                if offset + crate::ondisk::SUPERBLOCK_BYTES as u64 > max_bytes {
                    continue;
                }
                dev.commit(offset / READ_ALIGNMENT, image.at(offset, algorithm))
                    .await
                    .map_err(|source| Error::Io {
                        offset,
                        len: crate::ondisk::SUPERBLOCK_BYTES,
                        source,
                    })?;
            }
        }
        Ok(())
    }

    /// Zeroes all superblock mirror slots on `dev` so Linux's `btrfs device scan`
    /// no longer sees a stale superblock on a removed or replaced device.
    pub(crate) async fn wipe_superblocks(dev: &S) -> Result<(), crate::tree::write::WriteError> {
        use crate::source::READ_ALIGNMENT;
        let zeroed = [0_u8; READ_ALIGNMENT as usize];
        for offset in crate::superblock::MIRROR_OFFSETS {
            if offset + crate::ondisk::SUPERBLOCK_BYTES as u64 > dev.size_bytes() {
                continue;
            }
            dev.commit(offset / READ_ALIGNMENT, &zeroed)
                .await
                .map_err(|source| Error::Io {
                    offset,
                    len: crate::ondisk::SUPERBLOCK_BYTES,
                    source,
                })?;
        }
        Ok(())
    }

    /// Writes `bytes` directly to `(devid, physical)` in aligned blocks
    /// (used by scrub repair and device replace).
    pub(crate) async fn stage_raw(
        &self,
        devid: u64,
        physical: u64,
        bytes: &[u8],
    ) -> Result<(), crate::tree::write::WriteError> {
        use crate::source::READ_ALIGNMENT;
        let Some(dev) = self.device(devid) else {
            return Err(Error::Chunk {
                logical: physical,
                defect: crate::error::ChunkDefect::Device(devid),
            }
            .into());
        };
        let mut offset = physical;
        for chunk in bytes.as_chunks::<{ READ_ALIGNMENT as usize }>().0 {
            dev.stage(offset / READ_ALIGNMENT, chunk)
                .await
                .map_err(|source| Error::Io {
                    offset,
                    len: chunk.len(),
                    source,
                })?;
            offset += READ_ALIGNMENT;
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
        self.stage_pieces(logical, &[bytes], concurrency).await
    }

    /// [`Self::stage`] for an allocation whose bytes are `pieces` laid end
    /// to end, each a whole number of blocks.
    pub(crate) async fn stage_pieces<P: AsRef<[u8]> + Sync>(
        &self,
        logical: u64,
        pieces: &[P],
        concurrency: core::num::NonZeroUsize,
    ) -> Result<(), crate::tree::write::WriteError> {
        use crate::source::{PendingWrites, READ_ALIGNMENT};
        use crate::tree::write::WriteError;

        let length: usize = pieces.iter().map(|piece| piece.as_ref().len()).sum();
        if length == 0
            || !logical.is_multiple_of(READ_ALIGNMENT)
            || pieces
                .iter()
                .any(|piece| !piece.as_ref().len().is_multiple_of(READ_ALIGNMENT as usize))
        {
            return Err(WriteError::StagingRange {
                logical,
                bytes: length,
            });
        }
        let copies = self.chunks().map(logical, length as u64)?;
        let mut writes = PendingWrites::new(concurrency);
        for stripe in copies {
            let Some(dev) = self.device(stripe.devid) else {
                return Err(Error::Chunk {
                    logical,
                    defect: crate::error::ChunkDefect::Device(stripe.devid),
                }
                .into());
            };
            let mut next = stripe.offset;
            for piece in pieces {
                for bytes in piece.as_ref().as_chunks::<{ READ_ALIGNMENT as usize }>().0 {
                    let offset = next;
                    next += READ_ALIGNMENT;
                    writes
                        .push(async move {
                            dev.stage(offset / READ_ALIGNMENT, bytes)
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
        }
        writes.finish().await?;
        Ok(())
    }
}
