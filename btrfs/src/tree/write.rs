//! Single-owner CoW edits. One transaction owns its node overlay and allocator;
//! reads through a published root never observe this overlay. No lock is held
//! during device I/O. Publication and reclamation belong to the transaction.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use arrayvec::ArrayVec;
use thiserror::Error;

use super::edit::{Branch, Child, EditError, Header, Leaf};
use super::{Expected, Node, TreeRoot};
use crate::ondisk::{MAX_LEVEL, RawHeader, view};
use crate::source::BlockSource;
use crate::volume::Volume;
use crate::{ChecksumType, Error, Key};

#[derive(Debug, Error)]
pub(crate) enum WriteError {
    #[error(transparent)]
    Read(#[from] Error),
    #[error(transparent)]
    Space(#[from] crate::space::SpaceError),
    #[error(transparent)]
    Item(#[from] EditError),
    #[error("free-space item {key}: {defect}")]
    FreeSpace {
        key: Key,
        defect: crate::free_space::FreeSpaceDefect,
    },
    #[error("UUID item {key}: {defect}")]
    Uuid {
        key: Key,
        defect: crate::uuid_tree::UuidDefect,
    },
    #[error("allocation item {key}: {defect}")]
    Allocation {
        key: Key,
        defect: crate::allocation::AllocationDefect,
    },
    #[error("data allocation item {key}: {defect}")]
    Data {
        key: Key,
        defect: crate::allocation::data::DataDefect,
    },
    #[error("tree {tree} metadata usage {used} cannot add {added} and remove {removed} bytes")]
    RootUsage {
        tree: u64,
        used: u64,
        added: u64,
        removed: u64,
    },
    #[error("metadata extent for block {address} at level {level} is missing")]
    MissingExtent { address: u64, level: u8 },
    #[error("no metadata space remains for tree {tree}")]
    NoSpace { tree: u64 },
    #[error("tree {tree} cannot grow beyond {MAX_LEVEL} levels")]
    Height { tree: u64 },
}

/// Allocation is transaction-owned: reservations, extent references and abort
/// cleanup all follow the same transaction lifetime, including failed edits.
pub(crate) trait MetadataAllocator {
    fn allocate(&mut self, tree: u64, level: u8, first: Key) -> Result<u64, WriteError>;

    /// Update the first key of a block that remains private to this transaction.
    fn revise(&mut self, address: u64, first: Key);

    /// Return an unpublished allocation after its overlay block is discarded.
    fn cancel(&mut self, address: u64);
}

pub(crate) struct Trees {
    generation: u64,
    checksum: ChecksumType,
    blocks: BTreeMap<u64, Node>,
    retired: Vec<(u64, u64, u8)>,
}

impl Trees {
    pub(crate) fn new(generation: u64, checksum: ChecksumType) -> Self {
        Self {
            generation,
            checksum,
            blocks: BTreeMap::new(),
            retired: Vec::new(),
        }
    }

    async fn read<S: BlockSource>(
        &self,
        volume: &Volume<S>,
        address: u64,
        expected: Expected,
    ) -> Result<Node, WriteError> {
        if let Some(node) = self.blocks.get(&address) {
            return Ok(node.clone());
        }
        Ok(Node::read(volume, address, expected).await?)
    }

    fn retire<A: MetadataAllocator>(
        &mut self,
        tree: u64,
        address: u64,
        level: u8,
        allocator: &mut A,
    ) {
        if self.blocks.remove(&address).is_some() {
            allocator.cancel(address);
        } else {
            self.retired.push((tree, address, level));
        }
    }

    fn insert(&mut self, bytes: alloc::boxed::Box<[u8]>) {
        let header: &RawHeader = view(&bytes).expect("encoded header");
        self.blocks.insert(
            header.bytenr.get(),
            Node {
                level: header.level,
                nritems: header.nritems.get() as usize,
                bytes,
            },
        );
    }

    async fn path<S: BlockSource>(
        &self,
        volume: &Volume<S>,
        root: TreeRoot,
        key: Key,
    ) -> Result<ArrayVec<(u64, Node, usize), { MAX_LEVEL as usize }>, WriteError> {
        let mut path = ArrayVec::new();
        let mut address = root.bytenr;
        let mut expected = Expected {
            level: root.level,
            generation: root.generation,
            first_key: None,
        };
        loop {
            let node = self.read(volume, address, expected).await?;
            let slot = node.floor_slot(key);
            if node.level == 0 {
                path.push((address, node, slot));
                return Ok(path);
            }
            let (child, generation) = node.child(slot);
            expected = Expected {
                level: node.level - 1,
                generation,
                first_key: Some(node.key(slot)),
            };
            path.push((address, node, slot));
            address = child;
        }
    }

    /// Reads the transaction's current value, including unpublished edits.
    pub(crate) async fn get<S: BlockSource>(
        &self,
        volume: &Volume<S>,
        root: TreeRoot,
        key: Key,
    ) -> Result<Option<Vec<u8>>, WriteError> {
        let path = self.path(volume, root, key).await?;
        let (_, node, slot) = path.last().expect("path includes a leaf");
        Ok((node.nritems > 0 && node.key(*slot) == key).then(|| node.item(*slot).to_vec()))
    }

    /// First item at or above a key in the current transaction. Ascending to
    /// the next sibling is necessary when the selected leaf ends below it.
    pub(crate) async fn ceiling<S: BlockSource>(
        &self,
        volume: &Volume<S>,
        root: TreeRoot,
        key: Key,
    ) -> Result<Option<(Key, Vec<u8>)>, WriteError> {
        let mut path = self.path(volume, root, key).await?;
        let (_, leaf, mut slot) = path.pop().expect("path includes leaf");
        if leaf.nritems > 0 {
            slot += usize::from(leaf.key(slot) < key);
            if slot < leaf.nritems {
                return Ok(Some((leaf.key(slot), leaf.item(slot).to_vec())));
            }
        }
        while let Some((_, mut node, slot)) = path.pop() {
            if slot + 1 == node.nritems {
                continue;
            }
            let mut next = slot + 1;
            loop {
                let (address, generation) = node.child(next);
                node = self
                    .read(
                        volume,
                        address,
                        Expected {
                            level: node.level - 1,
                            generation,
                            first_key: Some(node.key(next)),
                        },
                    )
                    .await?;
                if node.level == 0 {
                    return Ok(Some((node.key(0), node.item(0).to_vec())));
                }
                next = 0;
            }
        }
        Ok(None)
    }

    /// Applies one insertion, replacement, or deletion. On error the owner
    /// aborts the entire transaction, releasing all reservations; no partial
    /// root or block from this overlay has been published to readers.
    pub(crate) async fn apply<S: BlockSource, A: MetadataAllocator>(
        &mut self,
        volume: &Volume<S>,
        root: TreeRoot,
        key: Key,
        value: Option<&[u8]>,
        allocator: &mut A,
    ) -> Result<TreeRoot, WriteError> {
        let mut path = self.path(volume, root, key).await?;
        let original_root = path[0].1.clone();
        let (address, node, _) = path.pop().expect("path includes a leaf");
        let mut leaf = Leaf::from_node(&node);
        match value {
            Some(bytes) => leaf.set(key, bytes)?,
            None if !leaf.remove(key) => return Ok(root),
            None => {}
        }
        let mut children = Vec::new();
        let mut reusable = self.blocks.contains_key(&address).then_some(address);
        for range in leaf.partitions() {
            let Some(first) = leaf.first_key(&range) else {
                continue;
            };
            let fresh = destination(&mut reusable, allocator, root.tree, 0, first)?;
            self.insert(leaf.encode(range, fresh, self.generation, root.tree, self.checksum));
            children.push(Child {
                key: first,
                address: fresh,
                generation: self.generation,
            });
        }
        if children
            .first()
            .is_none_or(|child| child.address != address)
        {
            self.retire(root.tree, address, 0, allocator);
        }
        let mut level = 0;
        while let Some((address, node, slot)) = path.pop() {
            level = node.level;
            let mut branch = Branch::from_node(&node);
            branch.replace(slot, &children);
            children.clear();
            let mut reusable = self.blocks.contains_key(&address).then_some(address);
            for range in branch.partitions() {
                let Some(first) = branch.first_key(&range) else {
                    continue;
                };
                let fresh = destination(&mut reusable, allocator, root.tree, level, first)?;
                self.insert(branch.encode(range, fresh, self.generation, root.tree, self.checksum));
                children.push(Child {
                    key: first,
                    address: fresh,
                    generation: self.generation,
                });
            }
            if children
                .first()
                .is_none_or(|child| child.address != address)
            {
                self.retire(root.tree, address, level, allocator);
            }
        }
        if children.is_empty() {
            let fresh = allocator.allocate(root.tree, 0, Key::new(0, 0, 0))?;
            let leaf = Leaf::empty(Header::for_level(&original_root, 0));
            self.insert(leaf.encode(0..0, fresh, self.generation, root.tree, self.checksum));
            return Ok(TreeRoot {
                tree: root.tree,
                bytenr: fresh,
                generation: self.generation,
                level: 0,
            });
        }
        while children.len() > 1 {
            level += 1;
            if level >= MAX_LEVEL {
                return Err(WriteError::Height { tree: root.tree });
            }
            let branch = Branch::new(
                Header::for_level(&original_root, level),
                core::mem::take(&mut children),
            );
            for range in branch.partitions() {
                let first = branch.first_key(&range).expect("nonempty new root");
                let fresh = allocator.allocate(root.tree, level, first)?;
                self.insert(branch.encode(range, fresh, self.generation, root.tree, self.checksum));
                children.push(Child {
                    key: first,
                    address: fresh,
                    generation: self.generation,
                });
            }
        }
        let mut child = children[0];
        // Remove a unary root after deletion; its only child already names a
        // complete subtree with the same key range and owner.
        while level > 0 {
            let node = self
                .read(
                    volume,
                    child.address,
                    Expected {
                        level,
                        generation: child.generation,
                        first_key: None,
                    },
                )
                .await?;
            if node.nritems != 1 {
                break;
            }
            let (address, generation) = node.child(0);
            self.retire(root.tree, child.address, level, allocator);
            child = Child {
                key: node.key(0),
                address,
                generation,
            };
            level -= 1;
        }
        Ok(TreeRoot {
            tree: root.tree,
            bytenr: child.address,
            generation: child.generation,
            level,
        })
    }

    pub(crate) async fn create<S: BlockSource, A: MetadataAllocator>(
        &mut self,
        volume: &Volume<S>,
        template: TreeRoot,
        tree: u64,
        allocator: &mut A,
    ) -> Result<TreeRoot, WriteError> {
        let node = self
            .read(
                volume,
                template.bytenr,
                Expected {
                    level: template.level,
                    generation: template.generation,
                    first_key: None,
                },
            )
            .await?;
        let address = allocator.allocate(tree, 0, Key::new(0, 0, 0))?;
        let leaf = Leaf::empty(Header::new_tree(&node));
        self.insert(leaf.encode(0..0, address, self.generation, tree, self.checksum));
        Ok(TreeRoot {
            tree,
            bytenr: address,
            generation: self.generation,
            level: 0,
        })
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn blocks(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.blocks
            .iter()
            .map(|(&address, node)| (address, &*node.bytes))
    }

    pub(crate) fn retired(&self) -> &[(u64, u64, u8)] {
        &self.retired
    }
}

/// An overlay block is unreachable from every published root. Retaining its
/// address lets allocation-tree accounting converge without changing the set of
/// reservations on each edit. Splits still reserve their additional blocks.
fn destination<A: MetadataAllocator>(
    reusable: &mut Option<u64>,
    allocator: &mut A,
    tree: u64,
    level: u8,
    first: Key,
) -> Result<u64, WriteError> {
    if let Some(address) = reusable.take() {
        allocator.revise(address, first);
        Ok(address)
    } else {
        allocator.allocate(tree, level, first)
    }
}
