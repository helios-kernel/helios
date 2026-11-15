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
    Item(#[from] EditError),
    #[error("no metadata space remains for tree {tree}")]
    NoSpace { tree: u64 },
    #[error("tree {tree} cannot grow beyond {MAX_LEVEL} levels")]
    Height { tree: u64 },
}

/// Allocation is transaction-owned: reservations, extent references and abort
/// cleanup all follow the same transaction lifetime, including failed edits.
pub(crate) trait MetadataAllocator {
    fn allocate(&mut self, tree: u64, level: u8, first: Key) -> Result<u64, WriteError>;
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

    fn retire(&mut self, tree: u64, address: u64, level: u8) {
        // Even a transaction-local block has an allocation/reference record.
        // The allocator must cancel that record rather than leak its reservation.
        self.blocks.remove(&address);
        self.retired.push((tree, address, level));
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
        let mut path = ArrayVec::<(u64, Node, usize), { MAX_LEVEL as usize }>::new();
        let mut address = root.bytenr;
        let mut expected = Expected {
            level: root.level,
            generation: root.generation,
            first_key: None,
        };
        let original_root = self.read(volume, address, expected).await?;
        let mut node = original_root.clone();
        while node.level > 0 {
            let slot = node.floor_slot(key);
            let (child, generation) = node.child(slot);
            expected = Expected {
                level: node.level - 1,
                generation,
                first_key: Some(node.key(slot)),
            };
            path.push((address, node, slot));
            address = child;
            node = self.read(volume, address, expected).await?;
        }
        let mut leaf = Leaf::from_node(&node);
        match value {
            Some(bytes) => leaf.set(key, bytes)?,
            None if !leaf.remove(key) => return Ok(root),
            None => {}
        }
        let mut children = Vec::new();
        for range in leaf.partitions() {
            let Some(first) = leaf.first_key(&range) else {
                continue;
            };
            let fresh = allocator.allocate(root.tree, 0, first)?;
            self.insert(leaf.encode(range, fresh, self.generation, self.checksum));
            children.push(Child {
                key: first,
                address: fresh,
                generation: self.generation,
            });
        }
        self.retire(root.tree, address, 0);
        let mut level = 0;
        while let Some((address, node, slot)) = path.pop() {
            level = node.level;
            let mut branch = Branch::from_node(&node);
            branch.replace(slot, &children);
            children.clear();
            for range in branch.partitions() {
                let Some(first) = branch.first_key(&range) else {
                    continue;
                };
                let fresh = allocator.allocate(root.tree, level, first)?;
                self.insert(branch.encode(range, fresh, self.generation, self.checksum));
                children.push(Child {
                    key: first,
                    address: fresh,
                    generation: self.generation,
                });
            }
            self.retire(root.tree, address, level);
        }
        if children.is_empty() {
            let fresh = allocator.allocate(root.tree, 0, Key::new(0, 0, 0))?;
            let leaf = Leaf::empty(Header::for_level(&original_root, 0));
            self.insert(leaf.encode(0..0, fresh, self.generation, self.checksum));
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
                self.insert(branch.encode(range, fresh, self.generation, self.checksum));
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
            self.retire(root.tree, child.address, level);
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

    pub(crate) fn blocks(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.blocks
            .iter()
            .map(|(&address, node)| (address, &*node.bytes))
    }

    pub(crate) fn retired(&self) -> &[(u64, u64, u8)] {
        &self.retired
    }
}
