//! Single-producer Venus command ring shared with an external renderer.
//!
//! The driver alone writes the command bytes and tail; the renderer alone
//! writes head and status. Head is acquired before reusing bytes. Publishing
//! tail and then reading status uses sequential consistency, as required by
//! Mesa's `vn_ring_store_tail`/`vn_ring_load_status` handshake. A full ring
//! returns its outstanding sequence number so the transport can await a
//! fenced `vkWaitRingSeqnoMESA`, without polling or holding a lock.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::num::NonZeroU32;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::protocol::{VK_RING_STATUS_FATAL_BIT_MESA, VK_RING_STATUS_IDLE_BIT_MESA};

/// Layout advertised by `VkRingCreateInfoMESA`.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    capacity: NonZeroU32,
}

/// Mesa's `vn_ring_get_layout` places each shared control word on its own
/// 64-byte line. These offsets are protocol layout, independent of the
/// processor running the guest.
const CONTROL_STRIDE: usize = 64;

impl Layout {
    pub const HEAD: usize = 0;
    pub const TAIL: usize = CONTROL_STRIDE;
    pub const STATUS: usize = 2 * CONTROL_STRIDE;
    pub const BUFFER: usize = 3 * CONTROL_STRIDE;

    /// Ring capacity must be a power of two below half the sequence space,
    /// so wrapping sequence comparisons remain unambiguous.
    pub fn new(capacity: NonZeroU32) -> Result<Self, RingError> {
        let size = capacity.get();
        if !size.is_power_of_two() || !(4..(1 << 31)).contains(&size) {
            return Err(RingError::Capacity { size });
        }
        Ok(Self { capacity })
    }

    pub const fn capacity(self) -> u32 {
        self.capacity.get()
    }

    pub const fn size(self) -> usize {
        Self::BUFFER + self.capacity.get() as usize
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RingError {
    #[error("ring capacity {size} is not a power of two in 4..2^31")]
    Capacity { size: u32 },
    #[error("command has {size} bytes; ring accepts aligned commands up to {capacity} bytes")]
    CommandSize { size: usize, capacity: u32 },
    #[error("renderer reported a fatal ring error")]
    Fatal,
    #[error(
        "renderer head {head} is outside the outstanding ring range ending at {tail} (capacity {capacity})"
    )]
    Head { head: u32, tail: u32, capacity: u32 },
}

/// A published batch; `notify` means the renderer was idle after publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Published {
    pub sequence: u32,
    pub notify: bool,
}

/// Borrow of an externally shared mapping. It never creates a Rust slice
/// over memory concurrently written by the renderer.
pub struct Ring<'a> {
    base: NonNull<u8>,
    layout: Layout,
    tail: u32,
    mapping: PhantomData<&'a UnsafeCell<[u8]>>,
}

impl<'a> Ring<'a> {
    /// Initialise the ring before handing it to the renderer.
    ///
    /// # Safety
    /// `base` is aligned for `AtomicU32`, has at least `layout.size()` bytes,
    /// and remains mapped and coherent for `'a`. No reference aliases the
    /// mapping. The renderer is not using it yet; afterwards it obeys the
    /// Venus ring ownership and memory-ordering protocol. On wasm this code
    /// must be compiled with atomics enabled, so the shared words are atomic
    /// against the renderer outside the wasm instance.
    pub unsafe fn new(base: NonNull<u8>, layout: Layout) -> Self {
        // SAFETY: the caller owns the whole mapping before registration.
        unsafe { base.as_ptr().write_bytes(0, layout.size()) };
        Self {
            base,
            layout,
            tail: 0,
            mapping: PhantomData,
        }
    }

    fn word(&self, offset: usize) -> &AtomicU32 {
        // SAFETY: all control offsets preserve alignment, remain inside the
        // mapping, and are only accessed atomically after initialisation.
        unsafe { &*self.base.as_ptr().add(offset).cast::<AtomicU32>() }
    }

    fn status(&self) -> Result<u32, RingError> {
        let status = self.word(Layout::STATUS).load(Ordering::SeqCst);
        if status & VK_RING_STATUS_FATAL_BIT_MESA.0 as u32 != 0 {
            return Err(RingError::Fatal);
        }
        Ok(status)
    }

    fn outstanding(&self) -> Result<u32, RingError> {
        let head = self.word(Layout::HEAD).load(Ordering::Acquire);
        let used = self.tail.wrapping_sub(head);
        if used > self.layout.capacity() {
            return Err(RingError::Head {
                head,
                tail: self.tail,
                capacity: self.layout.capacity(),
            });
        }
        Ok(used)
    }

    pub const fn capacity(&self) -> u32 {
        self.layout.capacity()
    }

    /// Current tail, suitable for `vkWaitRingSeqnoMESA` when a publish finds
    /// insufficient space. Waiting for it drains all outstanding bytes.
    pub const fn sequence(&self) -> u32 {
        self.tail
    }

    /// Whether the renderer has consumed all bytes published so far.
    pub fn is_drained(&self) -> Result<bool, RingError> {
        self.status()?;
        Ok(self.outstanding()? == 0)
    }

    /// Publish one complete, encoded command stream. `None` means no bytes
    /// were changed: await `sequence()` and retry. Large streams use Venus's
    /// indirect command-stream submission instead of this direct path.
    pub fn publish(&mut self, commands: &[u8]) -> Result<Option<Published>, RingError> {
        let capacity = self.layout.capacity();
        if commands.is_empty() || commands.len() % 4 != 0 || commands.len() > capacity as usize {
            return Err(RingError::CommandSize {
                size: commands.len(),
                capacity,
            });
        }
        self.status()?;
        if commands.len() > (capacity - self.outstanding()?) as usize {
            return Ok(None);
        }
        let offset = (self.tail & (capacity - 1)) as usize;
        let first = commands.len().min(capacity as usize - offset);
        // SAFETY: the acquired head released these bytes to the producer.
        // The renderer cannot read them until tail is published below. The
        // source cannot alias the mapping under `new`'s contract.
        unsafe {
            let buffer = self.base.as_ptr().add(Layout::BUFFER);
            buffer
                .add(offset)
                .copy_from_nonoverlapping(commands.as_ptr(), first);
            buffer.copy_from_nonoverlapping(commands.as_ptr().add(first), commands.len() - first);
        }
        self.tail = self.tail.wrapping_add(commands.len() as u32);
        self.word(Layout::TAIL).store(self.tail, Ordering::SeqCst);
        let status = self.status()?;
        Ok(Some(Published {
            sequence: self.tail,
            notify: status & VK_RING_STATUS_IDLE_BIT_MESA.0 as u32 != 0,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Mapping(Box<[UnsafeCell<u32>]>);

    // SAFETY: tests access control words only atomically and access buffer
    // bytes only while owning them according to the head/tail handshake.
    unsafe impl Sync for Mapping {}

    impl Mapping {
        fn new(layout: Layout) -> Self {
            Self((0..layout.size() / 4).map(|_| UnsafeCell::new(0)).collect())
        }

        fn base(&self) -> NonNull<u8> {
            NonNull::new(self.0.as_ptr().cast_mut().cast()).unwrap()
        }

        fn word(&self, offset: usize) -> &AtomicU32 {
            // SAFETY: callers name control words, which are aligned and
            // exclusively accessed through atomic operations.
            unsafe { &*self.base().as_ptr().add(offset).cast::<AtomicU32>() }
        }

        fn read(&self, offset: usize, count: usize) -> Vec<u8> {
            // SAFETY: callers have acquired the published tail and have not
            // released head yet, so these bytes belong to the renderer.
            unsafe {
                core::slice::from_raw_parts(
                    self.base().as_ptr().add(Layout::BUFFER + offset),
                    count,
                )
                .to_vec()
            }
        }
    }

    fn layout(capacity: u32) -> Layout {
        Layout::new(NonZeroU32::new(capacity).unwrap()).unwrap()
    }

    #[test]
    fn full_ring_does_not_change_tail_or_unconsumed_bytes() {
        let layout = layout(16);
        let mapping = Mapping::new(layout);
        // SAFETY: fresh, aligned mapping, kept alive through the test.
        let mut ring = unsafe { Ring::new(mapping.base(), layout) };
        mapping
            .word(Layout::STATUS)
            .store(VK_RING_STATUS_IDLE_BIT_MESA.0 as u32, Ordering::SeqCst);
        assert_eq!(
            ring.publish(&[7; 16]).unwrap(),
            Some(Published {
                sequence: 16,
                notify: true
            })
        );
        assert_eq!(mapping.word(Layout::TAIL).load(Ordering::Acquire), 16);
        assert_eq!(ring.publish(&[8; 4]).unwrap(), None);
        assert_eq!(mapping.read(0, 16), [7; 16]);
        assert_eq!(ring.sequence(), 16);
        assert!(!ring.is_drained().unwrap());
        mapping.word(Layout::HEAD).store(16, Ordering::Release);
        assert!(ring.is_drained().unwrap());
    }

    #[test]
    fn a_stream_wraps_at_the_buffer_end_and_at_u32_max() {
        let layout = layout(16);
        let mapping = Mapping::new(layout);
        // SAFETY: fresh, aligned mapping, kept alive through the test.
        let mut ring = unsafe { Ring::new(mapping.base(), layout) };
        // Set up an empty ring at the last dword of the sequence space.
        ring.tail = u32::MAX - 3;
        mapping
            .word(Layout::HEAD)
            .store(ring.tail, Ordering::Release);
        mapping
            .word(Layout::TAIL)
            .store(ring.tail, Ordering::Release);
        assert_eq!(
            ring.publish(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap(),
            Some(Published {
                sequence: 4,
                notify: false
            })
        );
        assert_eq!(mapping.word(Layout::TAIL).load(Ordering::Acquire), 4);
        assert_eq!(mapping.read(12, 4), [1, 2, 3, 4]);
        assert_eq!(mapping.read(0, 4), [5, 6, 7, 8]);
        assert!(!ring.is_drained().unwrap());
        mapping.word(Layout::HEAD).store(4, Ordering::Release);
        assert!(ring.is_drained().unwrap());
    }

    #[test]
    fn renderer_refusals_and_bad_stream_lengths_surface() {
        let layout = layout(16);
        let mapping = Mapping::new(layout);
        // SAFETY: fresh, aligned mapping, kept alive through the test.
        let mut ring = unsafe { Ring::new(mapping.base(), layout) };
        for size in [0, 3, 20] {
            assert_eq!(
                ring.publish(&vec![0; size]),
                Err(RingError::CommandSize { size, capacity: 16 })
            );
        }
        mapping
            .word(Layout::STATUS)
            .store(VK_RING_STATUS_FATAL_BIT_MESA.0 as u32, Ordering::SeqCst);
        assert_eq!(ring.publish(&[0; 4]), Err(RingError::Fatal));
        mapping.word(Layout::STATUS).store(0, Ordering::SeqCst);
        mapping.word(Layout::HEAD).store(4, Ordering::Release);
        assert_eq!(
            ring.publish(&[0; 4]),
            Err(RingError::Head {
                head: 4,
                tail: 0,
                capacity: 16
            })
        );
    }

    #[test]
    fn renderer_thread_sees_each_published_command_before_releasing_space() {
        let layout = layout(64);
        let mapping = Mapping::new(layout);
        // SAFETY: mapping outlives both participants, which honour the ring
        // protocol. The driver is the sole producer.
        let mut ring = unsafe { Ring::new(mapping.base(), layout) };
        let (wake, notified) = std::sync::mpsc::channel();
        let (consumed, ready) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let mapping = &mapping;
            scope.spawn(move || {
                let mut head = 0u32;
                for expected in 0..128u32 {
                    notified.recv().unwrap();
                    let tail = mapping.word(Layout::TAIL).load(Ordering::Acquire);
                    assert_eq!(tail.wrapping_sub(head), 4);
                    let bytes = mapping.read((head & (layout.capacity() - 1)) as usize, 4);
                    assert_eq!(bytes, expected.to_le_bytes());
                    head = head.wrapping_add(4);
                    mapping.word(Layout::HEAD).store(head, Ordering::Release);
                    consumed.send(()).unwrap();
                }
            });
            for value in 0..128u32 {
                assert!(ring.publish(&value.to_le_bytes()).unwrap().is_some());
                wake.send(()).unwrap();
                ready.recv().unwrap();
                assert!(ring.is_drained().unwrap());
            }
        });
    }
}
