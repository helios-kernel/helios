//! The writer alone owns reclamation state. Readers clone a generation pin
//! without a lock; dropping the final pin makes its retired ranges eligible
//! for reuse at the next transaction boundary.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use crate::fs::Snapshot;
use crate::space::Space;

struct Retired {
    generation: u64,
    extents: BTreeMap<u64, u64>,
}

#[derive(Default)]
pub(crate) struct Retirements {
    readers: Vec<Weak<Snapshot>>,
    retired: Vec<Retired>,
}

impl Retirements {
    pub(crate) fn protect(&mut self, generation: &Arc<Snapshot>, space: &mut Space) {
        self.readers.retain(|pin| pin.strong_count() != 0);
        let pin = Arc::downgrade(generation);
        if !self.readers.iter().any(|reader| reader.ptr_eq(&pin)) {
            self.readers.push(pin);
        }
        // A block removed in generation N may still be shared by any older
        // read view, not only the immediate predecessor of the new commit.
        let oldest = self
            .readers
            .iter()
            .filter_map(Weak::upgrade)
            .map(|pin| pin.mapping.superblock.generation())
            .min()
            .expect("current transaction pins a generation");
        self.retired.retain(|retired| retired.generation >= oldest);
        for retired in &self.retired {
            for (&address, &length) in &retired.extents {
                space.pin(address..address + length);
            }
        }
    }

    pub(crate) fn record(&mut self, generation: &Arc<Snapshot>, extents: BTreeMap<u64, u64>) {
        if !extents.is_empty() {
            self.retired.push(Retired {
                generation: generation.mapping.superblock.generation(),
                extents,
            });
        }
    }
}
