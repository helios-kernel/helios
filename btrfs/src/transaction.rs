//! A single-owner transaction. Its owner serializes writers and retains the
//! mounted generation's reader pins; this module never reuses retired extents.

use core::num::NonZeroUsize;
use futures::{
    future,
    stream::{self, StreamExt, TryStreamExt},
};

use crate::accounting::Accounting;
use crate::commit::CommitImage;
use crate::ondisk::objectid;
use crate::roots::Roots;
use crate::source::BlockSink;
use crate::space::Space;
use crate::tree::{
    TreeRoot,
    write::{Trees, WriteError},
};
use crate::volume::Volume;

pub(crate) struct Transaction<'a, S> {
    volume: &'a Volume<S>,
    image: CommitImage,
    pub(crate) roots: Roots,
    pub(crate) trees: Trees,
    pub(crate) space: Space,
    pub(crate) accounting: Accounting,
}

impl<'a, S: BlockSink> Transaction<'a, S> {
    pub(crate) async fn new(volume: &'a Volume<S>, root: TreeRoot) -> Result<Self, WriteError> {
        let image = volume.commit_image().await?;
        let generation = volume
            .superblock()
            .generation()
            .checked_add(1)
            .ok_or(WriteError::GenerationOverflow)?;
        let (roots, space) = future::try_join(Roots::load(volume, root), async {
            Space::load(volume, root).await.map_err(WriteError::from)
        })
        .await?;
        let accounting = Accounting::new(
            volume,
            roots.get(objectid::EXTENT_TREE)?,
            &space,
            roots.get(objectid::CSUM_TREE)?,
        )
        .await?;
        Ok(Self {
            volume,
            image,
            roots,
            space,
            accounting,
            trees: Trees::new(generation, volume.superblock().csum_type()),
        })
    }

    /// Consume the overlay. Any failure/cancellation prevents in-memory root
    /// publication; BlockSink's commit contract poisons failed durable commits.
    pub(crate) async fn commit(
        mut self,
        mut uuid: impl FnMut() -> [u8; 16],
        concurrency: NonZeroUsize,
    ) -> Result<(), WriteError> {
        loop {
            self.accounting
                .sync_allocations(self.volume, &mut self.trees, &mut self.space)
                .await?;
            self.roots.set(self.accounting.root)?;
            self.roots.set(self.accounting.group_root())?;
            self.roots.set(self.accounting.checksum_root())?;
            if let Some(root) = self.accounting.free_root() {
                self.roots.set(root)?;
            }
            if !self
                .roots
                .sync(self.volume, &mut self.trees, &mut self.space, &mut uuid)
                .await?
            {
                break;
            }
        }
        if self.trees.blocks().next().is_none() {
            return Ok(());
        }
        self.image
            .prepare(&self.roots, self.accounting.bytes_used(&self.space)?)?;
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
        self.volume.publish(self.image).await
    }
}
