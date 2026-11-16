//! Shared Stage-2 participation and acknowledgement bookkeeping for backends.
//!
//! A backend owns the page-table mutation lock and hardware invalidation/IPIs.
//! These slots track every processor that can retain translations, not merely
//! the processor currently running a vCPU. Entry, detach and publication use
//! a total atomic order so an entrant either joins the target set or observes
//! the new generation before loading the root.

use crate::exec::Notify;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crossbeam_utils::CachePadded;
use helios_hal::cpu::ProcessorId;

struct Participant {
    resident: AtomicBool,
    acknowledged: AtomicU64,
}

/// Each padded slot is entered/detached/acknowledged by its owning processor;
/// mutators on any processor read the slots. Generation and notification are
/// shared across processors. Methods never wait on a software spin loop.
pub struct Stage2Tracker {
    generation: CachePadded<AtomicU64>,
    processors: Box<[CachePadded<Participant>]>,
    progress: Notify,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Stage2Generation(u64);

/// Snapshot to send to each target's IPI handler. Dropping this future/snapshot
/// does not clear participant state; a subsequent revocation includes those
/// processors again and can acknowledge both generations with one invalidation.
pub struct Stage2Shootdown<'a> {
    tracker: &'a Stage2Tracker,
    generation: Stage2Generation,
    targets: Vec<ProcessorId>,
}

impl Stage2Tracker {
    pub fn new(processors: NonZeroUsize) -> Self {
        assert!(
            processors.get() <= usize::from(u16::MAX) + 1,
            "processor count exceeds ProcessorId domain"
        );
        Self {
            generation: CachePadded::new(AtomicU64::new(0)),
            processors: (0..processors.get())
                .map(|_| {
                    CachePadded::new(Participant {
                        resident: AtomicBool::new(false),
                        acknowledged: AtomicU64::new(0),
                    })
                })
                .collect(),
            progress: Notify::new(),
        }
    }
    /// Register before loading a root. Invalidate local stale translations
    /// through the returned generation, then recheck `generation` before entry.
    /// The backend's latched IPI/entry handshake handles a later revocation.
    pub fn enter(&self, processor: ProcessorId) -> Stage2Generation {
        self.processors[usize::from(processor.id())]
            .resident
            .store(true, Ordering::SeqCst);
        self.generation()
    }
    pub fn generation(&self) -> Stage2Generation {
        Stage2Generation(self.generation.load(Ordering::SeqCst))
    }
    /// Call only after unloading the root AND locally invalidating all cached
    /// translations. Never mark a processor detached while another vCPU using
    /// this space is running there. No await may split unload and detach.
    pub fn detach(&self, processor: ProcessorId) {
        let slot = &self.processors[usize::from(processor.id())];
        slot.resident.store(false, Ordering::SeqCst);
        self.acknowledge(processor, self.generation());
    }
    /// Publish after updating PTEs. The caller invalidates locally and sends
    /// an IPI to every remote target, then awaits `wait` before releasing RAM.
    /// Mutation serialization belongs to the owning Stage-2 implementation.
    pub fn invalidate(&self) -> Stage2Shootdown<'_> {
        let previous = self
            .generation
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |old| old.checked_add(1))
            .expect("Stage-2 invalidation generation exhausted");
        let targets = self
            .processors
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                slot.resident
                    .load(Ordering::SeqCst)
                    .then_some(ProcessorId::new(index as u16))
            })
            .collect();
        Stage2Shootdown {
            tracker: self,
            generation: Stage2Generation(previous + 1),
            targets,
        }
    }
    /// Called by the target after hardware invalidation through `generation`.
    /// Sample the generation before invalidating, never afterwards: a newer
    /// publication may otherwise be acknowledged without flushing its entries.
    pub fn acknowledge(&self, processor: ProcessorId, generation: Stage2Generation) {
        self.processors[usize::from(processor.id())]
            .acknowledged
            .fetch_max(generation.0, Ordering::Release);
        self.progress.notify_all();
    }
}

impl Stage2Shootdown<'_> {
    pub fn generation(&self) -> Stage2Generation {
        self.generation
    }
    pub fn targets(&self) -> &[ProcessorId] {
        &self.targets
    }
    pub async fn wait(&self) {
        loop {
            let changed = self.tracker.progress.notified();
            if self.targets.iter().all(|id| {
                self.tracker.processors[usize::from(id.id())]
                    .acknowledged
                    .load(Ordering::Acquire)
                    >= self.generation.0
            }) {
                return;
            }
            changed.await;
        }
    }
}
