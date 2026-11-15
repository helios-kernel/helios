//! A single-owner transaction. Its owner serializes writers and retains the
//! mounted generation's reader pins; this module never reuses retired extents.

mod extents;

use core::num::NonZeroUsize;
use futures::{
    future,
    stream::{self, StreamExt, TryStreamExt},
};

use crate::accounting::Accounting;
use crate::commit::CommitImage;
use crate::fs::Snapshot;
use crate::ondisk::objectid;
use crate::retirement::Retirements;
use crate::roots::Roots;
use crate::source::BlockSink;
use crate::space::Space;
use crate::tree::write::{Trees, WriteError};
use crate::volume::Volume;
use alloc::sync::Arc;

/// Produced only once the new roots are durable, or for an unchanged view.
pub(crate) struct Committed {
    pub(crate) snapshot: Arc<Snapshot>,
}

pub(crate) struct Transaction<'a, S> {
    generation: Arc<Snapshot>,
    retirements: &'a mut Retirements,
    volume: Volume<S>,
    image: CommitImage,
    pub(crate) roots: Roots,
    pub(crate) trees: Trees,
    pub(crate) space: Space,
    pub(crate) accounting: Accounting,
}

impl<'a, S: BlockSink> Transaction<'a, S> {
    pub(crate) async fn new(
        volume: Volume<S>,
        pin: Arc<Snapshot>,
        retirements: &'a mut Retirements,
    ) -> Result<Self, WriteError> {
        let root = pin.root_tree;
        let image = volume.commit_image().await?;
        let generation = volume
            .superblock()
            .generation()
            .checked_add(1)
            .ok_or(WriteError::GenerationOverflow)?;
        let (roots, mut space) = future::try_join(Roots::load(&volume, root), async {
            Space::load(&volume, root).await.map_err(WriteError::from)
        })
        .await?;
        retirements.protect(&pin, &mut space);
        let accounting = Accounting::new(
            &volume,
            roots.get(objectid::EXTENT_TREE)?,
            &space,
            roots.get(objectid::CSUM_TREE)?,
        )
        .await?;
        let trees = Trees::new(generation, volume.superblock().csum_type());
        Ok(Self {
            generation: pin,
            retirements,
            volume,
            image,
            roots,
            space,
            accounting,
            trees,
        })
    }

    /// Consume the overlay. Any failure/cancellation prevents in-memory root
    /// publication; BlockSink's commit contract poisons failed durable commits.
    pub(crate) async fn commit(
        mut self,
        mut uuid: impl FnMut() -> [u8; 16],
        concurrency: NonZeroUsize,
        publishing: impl FnOnce(),
    ) -> Result<Committed, WriteError> {
        loop {
            self.accounting
                .sync_allocations(&self.volume, &mut self.trees, &mut self.space)
                .await?;
            self.roots.set(self.accounting.root)?;
            self.roots.set(self.accounting.group_root())?;
            self.roots.set(self.accounting.checksum_root())?;
            if let Some(root) = self.accounting.free_root() {
                self.roots.set(root)?;
            }
            if !self
                .roots
                .sync(&self.volume, &mut self.trees, &mut self.space, &mut uuid)
                .await?
            {
                break;
            }
        }
        if self.trees.blocks().next().is_none() {
            return Ok(Committed {
                snapshot: self.generation.clone(),
            });
        }
        self.image
            .prepare(&self.roots, self.accounting.bytes_used(&self.space)?)?;
        let superblock = self
            .image
            .superblock(self.volume.superblock().csum_type())?;
        let snapshot = self.generation.advance(superblock, &self.roots)?;
        // Register before the first await that can publish the new generation.
        // Cancellation or a failed mirror write must not lose these pins.
        self.retirements
            .record(&self.generation, self.accounting.take_retired());
        // Bound the total in-flight I/O by staging one block per concurrent
        // stream item. Volume::stage handles this block's physical copies.
        let writes = self.trees.blocks().flat_map(|(logical, bytes)| {
            bytes
                .chunks(crate::source::READ_ALIGNMENT as usize)
                .enumerate()
                .map(move |(index, bytes)| {
                    (
                        logical + index as u64 * crate::source::READ_ALIGNMENT,
                        bytes,
                    )
                })
        });
        stream::iter(writes)
            .map(|(logical, bytes)| self.volume.stage(logical, bytes, NonZeroUsize::MIN))
            .buffer_unordered(concurrency.get())
            .try_for_each(|()| async { Ok(()) })
            .await?;
        publishing();
        self.volume.publish(self.image).await?;
        Ok(Committed { snapshot })
    }
}
