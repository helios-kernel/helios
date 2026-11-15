//! The writer alone owns reclamation state. Readers clone a generation pin
//! without a lock; dropping the final pin makes its retired ranges eligible
//! for reuse at the next transaction boundary.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use crate::space::Space;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Generation(Arc<u64>);

impl Generation {
    pub(crate) fn new(generation: u64) -> Self {
        Self(Arc::new(generation))
    }
}

struct Retired {
    generation: u64,
    extents: BTreeMap<u64, u64>,
}

#[derive(Default)]
pub(crate) struct Retirements {
    readers: Vec<Weak<u64>>,
    retired: Vec<Retired>,
}

impl Retirements {
    pub(crate) fn protect(&mut self, generation: &Generation, space: &mut Space) {
        self.readers.retain(|pin| pin.strong_count() != 0);
        let pin = Arc::downgrade(&generation.0);
        if !self.readers.iter().any(|reader| reader.ptr_eq(&pin)) {
            self.readers.push(pin);
        }
        // A block removed in generation N may still be shared by any older
        // read view, not only the immediate predecessor of the new commit.
        let oldest = self
            .readers
            .iter()
            .filter_map(Weak::upgrade)
            .map(|pin| *pin)
            .min()
            .expect("current transaction pins a generation");
        self.retired.retain(|retired| retired.generation >= oldest);
        for retired in &self.retired {
            for (&address, &length) in &retired.extents {
                space.pin(address..address + length);
            }
        }
    }

    pub(crate) fn record(&mut self, generation: &Generation, extents: BTreeMap<u64, u64>) {
        if !extents.is_empty() {
            self.retired.push(Retired {
                generation: *generation.0,
                extents,
            });
        }
    }
}
