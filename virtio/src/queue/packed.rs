//! The packed virtqueue layout of virtio 1.1 (§2.8).
//!
//! One descriptor ring carries both directions: the driver marks a
//! descriptor available by writing its AVAIL/USED flag pair to its own
//! wrap counter, and the device marks it used by writing both bits to
//! the device wrap counter. Chains are identified by a driver-chosen
//! buffer id rather than by a descriptor index, so a chain of `n`
//! buffers costs `n` ring positions but only one identifier — or one
//! ring position when it goes through an indirect table.

use core::alloc::Layout;
use core::sync::atomic::{Ordering, fence};

use alloc::boxed::Box;

use helios_hal::dma::{DmaBuffer, DmaMemory};

use crate::bus::DeviceBus;
use crate::features::NegotiatedFeatures;
use crate::transport::VirtioTransport;

use super::{
    ChainEntry, DESCRIPTOR_BYTES, READ_WRITE, RingCore, RingOps, TransportBuffer, VirtqueueError,
    need_event,
};

const DESC_F_NEXT: u16 = 1;
const DESC_F_WRITE: u16 = 2;
const DESC_F_INDIRECT: u16 = 1 << 2;
const DESC_F_AVAIL: u16 = 1 << 7;
const DESC_F_USED: u16 = 1 << 15;

const EVENT_FLAG_ENABLE: u16 = 0;
const EVENT_FLAG_DISABLE: u16 = 1;
const EVENT_FLAG_DESC: u16 = 2;
const EVENT_WRAP_SHIFT: u16 = 15;
const EVENT_OFFSET_MASK: u16 = (1 << EVENT_WRAP_SHIFT) - 1;

/// Both event suppression structures are `{ le16 off_wrap, le16 flags }`.
const EVENT_SUPPRESS_BYTES: usize = 4;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct PackedDescriptor {
    pub(super) addr: u64,
    pub(super) len: u32,
    pub(super) id: u16,
    pub(super) flags: u16,
}

pub(super) struct PackedRing<T: VirtioTransport> {
    core: RingCore<TransportBuffer<T>>,
    descriptors: TransportBuffer<T>,
    driver_event: TransportBuffer<T>,
    device_event: TransportBuffer<T>,
    /// Ring positions each in-flight chain occupies, indexed by buffer
    /// id. Zero means the identifier is not in flight.
    slots: Box<[u16]>,
    next_avail: u16,
    avail_wrap: bool,
    next_used: u16,
    used_wrap: bool,
    free_slots: u16,
}

impl<T: VirtioTransport> RingOps<T> for PackedRing<T> {
    fn new(
        transport: &T,
        index: u16,
        size: u16,
        chain_limit: u16,
        features: NegotiatedFeatures,
    ) -> Result<Self, VirtqueueError> {
        let dma = transport.bus().dma();
        let descriptor_layout =
            Layout::from_size_align(DESCRIPTOR_BYTES * usize::from(size), DESCRIPTOR_BYTES)
                .map_err(|_| VirtqueueError::RingAllocation)?;
        let event_layout = Layout::from_size_align(EVENT_SUPPRESS_BYTES, 4)
            .map_err(|_| VirtqueueError::RingAllocation)?;

        let ring = Self {
            core: RingCore::new(dma, size, chain_limit, features)?,
            descriptors: dma
                .allocate_resident(descriptor_layout, READ_WRITE)
                .map_err(|_| VirtqueueError::RingAllocation)?,
            driver_event: dma
                .allocate_resident(event_layout, READ_WRITE)
                .map_err(|_| VirtqueueError::RingAllocation)?,
            device_event: dma
                .allocate_resident(event_layout, READ_WRITE)
                .map_err(|_| VirtqueueError::RingAllocation)?,
            slots: alloc::vec![0_u16; usize::from(size)].into_boxed_slice(),
            next_avail: 0,
            avail_wrap: true,
            next_used: 0,
            used_wrap: true,
            free_slots: size,
        };
        ring.publish_used_event();
        ring.program(transport, index);
        Ok(ring)
    }

    /// Writes one chain into the ring.
    ///
    /// The packed layout has no aggregate available index: a chain
    /// becomes visible the moment its head descriptor's flags are
    /// written, which happens here behind a release fence. `publish`
    /// therefore only matters to the split layout; batching in this
    /// layout is expressed by deferring the kick, not the visibility.
    fn submit(&mut self, chain: &[ChainEntry], _publish: bool) -> Result<u16, VirtqueueError> {
        self.core.check_chain(chain)?;
        let indirect = self.core.use_indirect(chain.len());
        let needed = self.core.descriptors_needed(chain.len());
        if usize::from(self.free_slots) < needed || self.core.ids.available() == 0 {
            return Err(VirtqueueError::Full { needed });
        }

        let id = self
            .core
            .ids
            .allocate()
            .expect("identifier capacity was checked");
        let head_position = self.next_avail;
        let mut position = self.next_avail;
        let mut wrap = self.avail_wrap;

        let head_flags = if indirect {
            let tables = self
                .core
                .indirect
                .as_ref()
                .expect("indirect submission without indirect tables");
            assert!(
                chain.len() <= tables.entries(),
                "indirect chain exceeds the table capacity"
            );
            let table = tables.table_ptr(id).cast::<PackedDescriptor>();
            for (slot, entry) in chain.iter().enumerate() {
                // Indirect tables carry no chaining and no identifier:
                // the device reads `len / 16` descriptors in order.
                let descriptor = PackedDescriptor {
                    addr: entry.addr,
                    len: entry.len,
                    id: 0,
                    flags: if entry.writable { DESC_F_WRITE } else { 0 },
                };
                // SAFETY: `slot < chain.len() <= tables.entries()`, so
                // the offset stays inside `id`'s pre-allocated indirect
                // table.
                let dst = unsafe { table.add(slot) };
                // SAFETY: `dst` points to a valid, aligned
                // `PackedDescriptor` slot in `id`'s indirect table, and
                // `id` is freshly allocated so the device cannot read it
                // until the head descriptor is published below.
                unsafe { dst.write_volatile(descriptor) };
            }
            self.write_descriptor_body(
                head_position,
                tables.table_addr(id),
                (chain.len() * DESCRIPTOR_BYTES) as u32,
                id,
            );
            self.advance(&mut position, &mut wrap);
            DESC_F_INDIRECT | availability(self.avail_wrap)
        } else {
            let mut head_flags = 0;
            for (offset, entry) in chain.iter().enumerate() {
                let last = offset + 1 == chain.len();
                let mut flags = availability(wrap);
                if entry.writable {
                    flags |= DESC_F_WRITE;
                }
                if !last {
                    flags |= DESC_F_NEXT;
                }
                self.write_descriptor_body(position, entry.addr, entry.len, id);
                if offset == 0 {
                    head_flags = flags;
                } else {
                    self.write_descriptor_flags(position, flags);
                }
                self.advance(&mut position, &mut wrap);
            }
            head_flags
        };

        // The chain's descriptors and the buffers they name must be
        // visible before the head descriptor hands ownership over.
        fence(Ordering::Release);
        self.write_descriptor_flags(head_position, head_flags);

        self.next_avail = position;
        self.avail_wrap = wrap;
        let occupied = u16::try_from(needed).expect("chain length fits a ring position count");
        self.slots[usize::from(id)] = occupied;
        self.free_slots -= occupied;
        self.core.num_added = self.core.num_added.wrapping_add(occupied);
        self.core.record_chain(id, chain);
        Ok(id)
    }

    fn publish(&mut self) {}

    fn has_pending_used(&self) -> bool {
        is_used(self.read_descriptor(self.next_used).flags, self.used_wrap)
    }

    fn pop_used(&mut self) -> Result<Option<(u16, u32)>, VirtqueueError> {
        if self.core.features.in_order() {
            self.pop_used_in_order()
        } else {
            self.pop_used_unordered()
        }
    }

    fn should_notify(&self) -> bool {
        // Store-load barrier: the head descriptor's ownership store must
        // reach the device before its suppression state is read.
        fence(Ordering::SeqCst);
        let (off_wrap, flags) = self.read_device_event();
        if flags != EVENT_FLAG_DESC {
            return flags != EVENT_FLAG_DISABLE;
        }

        let new = self.next_avail;
        let old = new.wrapping_sub(self.core.num_added);
        let event_wrap = off_wrap >> EVENT_WRAP_SHIFT != 0;
        let mut event = off_wrap & EVENT_OFFSET_MASK;
        if event_wrap != self.avail_wrap {
            event = event.wrapping_sub(self.core.size);
        }
        need_event(event, new, old)
    }

    fn notification_data(&self, index: u16) -> u32 {
        let offset =
            (self.next_avail & EVENT_OFFSET_MASK) | ((self.avail_wrap as u16) << EVENT_WRAP_SHIFT);
        u32::from(index) | (u32::from(offset) << 16)
    }

    fn clear_added(&mut self) {
        self.core.num_added = 0;
    }

    fn available(&self) -> usize {
        usize::from(self.free_slots.min(self.core.ids.available()))
    }

    fn has_room_for(&self, buffers: usize) -> bool {
        usize::from(self.free_slots) >= self.core.descriptors_needed(buffers)
            && self.core.ids.available() != 0
    }

    fn next_id(&self) -> u16 {
        self.core.ids.peek()
    }

    fn in_flight_chains(&self) -> usize {
        self.core.in_flight.count()
    }

    fn reprogram(&mut self, transport: &T, index: u16) {
        zero(&self.descriptors);
        zero(&self.driver_event);
        zero(&self.device_event);
        self.slots.fill(0);
        self.next_avail = 0;
        self.avail_wrap = true;
        self.next_used = 0;
        self.used_wrap = true;
        self.free_slots = self.core.size;
        self.core.clear();
        self.publish_used_event();
        self.program(transport, index);
    }
}

impl<T: VirtioTransport> PackedRing<T> {
    fn program(&self, transport: &T, index: u16) {
        transport.set_queue(
            index,
            self.core.size,
            self.descriptors.device_address().get(),
            self.driver_event.device_address().get(),
            self.device_event.device_address().get(),
        );
    }

    fn advance(&self, position: &mut u16, wrap: &mut bool) {
        *position += 1;
        if *position >= self.core.size {
            *position = 0;
            *wrap = !*wrap;
        }
    }

    fn pop_used_unordered(&mut self) -> Result<Option<(u16, u32)>, VirtqueueError> {
        let descriptor = self.read_descriptor(self.next_used);
        if !is_used(descriptor.flags, self.used_wrap) {
            return Ok(None);
        }
        fence(Ordering::Acquire);
        let id = self.core.complete_head(u32::from(descriptor.id))?;
        self.finish_completion(id);
        Ok(Some((id, descriptor.len)))
    }

    /// VIRTIO_F_IN_ORDER completion (virtio 1.2 §2.8.9).
    ///
    /// The device may collapse a batch of chains into a single used
    /// descriptor, written at the position of the batch's first
    /// descriptor and naming the batch's last buffer id. Whether it did
    /// is unambiguous here: every used descriptor carries the device's
    /// wrap counter, so the driver knows exactly one entry was written
    /// and expands it back into the chains it submitted before that id.
    fn pop_used_in_order(&mut self) -> Result<Option<(u16, u32)>, VirtqueueError> {
        if self.core.batch.remaining == 0 {
            let descriptor = self.read_descriptor(self.next_used);
            if !is_used(descriptor.flags, self.used_wrap) {
                return Ok(None);
            }
            fence(Ordering::Acquire);
            self.core
                .begin_in_order_batch(u32::from(descriptor.id), descriptor.len)?;
        }

        let (id, len) = self.core.next_in_order_completion();
        let id = self.core.complete_head(u32::from(id))?;
        self.finish_completion(id);
        Ok(Some((id, len)))
    }

    /// `id` has already been taken out of the in-flight set, so it is a
    /// chain this driver submitted and `slots` holds its ring positions.
    fn finish_completion(&mut self, id: u16) {
        let occupied = self.slots[usize::from(id)];
        debug_assert!(
            occupied != 0,
            "in-flight buffer id {id} occupies no ring position"
        );
        self.slots[usize::from(id)] = 0;
        self.free_slots += occupied;
        let mut position = self.next_used;
        let mut wrap = self.used_wrap;
        for _ in 0..occupied {
            self.advance(&mut position, &mut wrap);
        }
        self.next_used = position;
        self.used_wrap = wrap;
        self.core.ids.release(id);
        if self.core.features.event_idx() {
            self.publish_used_event();
            // Store-load barrier: the device must see how far the driver
            // has consumed before the driver decides the ring is empty
            // and parks.
            fence(Ordering::SeqCst);
        }
    }

    /// Publishes the driver's used-buffer suppression state.
    fn publish_used_event(&self) {
        let (off_wrap, flags) = if self.core.features.event_idx() {
            (
                (self.next_used & EVENT_OFFSET_MASK)
                    | ((self.used_wrap as u16) << EVENT_WRAP_SHIFT),
                EVENT_FLAG_DESC,
            )
        } else {
            (0, EVENT_FLAG_ENABLE)
        };
        let base = self.driver_event.as_ptr().cast::<u16>();
        // SAFETY: `driver_event` is a resident 4-byte, 4-byte-aligned
        // DMA buffer owned by `self`, so offset 0 is a valid, aligned
        // `u16` field written only by the driver.
        unsafe { base.write_volatile(off_wrap) };
        // SAFETY: `driver_event` holds two `u16` fields (4 bytes), so
        // `base.add(1)` stays within the allocation.
        let flags_ptr = unsafe { base.add(1) };
        // SAFETY: `flags_ptr` is valid and 2-byte-aligned inside
        // `driver_event` and written only by the driver.
        unsafe { flags_ptr.write_volatile(flags) };
    }

    fn read_device_event(&self) -> (u16, u16) {
        let base = self.device_event.as_ptr().cast::<u16>();
        // SAFETY: `device_event` is a resident 4-byte, 4-byte-aligned
        // DMA buffer owned by `self`, so offset 0 is a valid, aligned
        // `u16` field.
        let off_wrap = unsafe { base.read_volatile() };
        // SAFETY: `device_event` holds two `u16` fields (4 bytes), so
        // `base.add(1)` stays within the allocation.
        let flags_ptr = unsafe { base.add(1) };
        // SAFETY: `flags_ptr` is valid and 2-byte-aligned inside
        // `device_event`.
        let flags = unsafe { flags_ptr.read_volatile() };
        (off_wrap, flags)
    }

    fn descriptor_ptr(&self, position: u16) -> *mut PackedDescriptor {
        assert!(
            position < self.core.size,
            "virtqueue ring position {position} is outside the ring"
        );
        // SAFETY: `position < self.core.size` was just checked, and
        // `self.descriptors` holds `self.core.size` `PackedDescriptor`s.
        unsafe {
            self.descriptors
                .as_ptr()
                .cast::<PackedDescriptor>()
                .add(usize::from(position))
        }
    }

    fn read_descriptor(&self, position: u16) -> PackedDescriptor {
        let ptr = self.descriptor_ptr(position);
        // SAFETY: `descriptor_ptr` verified `position < self.core.size`,
        // and `self.descriptors` is resident and aligned for
        // `PackedDescriptor` for the lifetime of `self`.
        unsafe { ptr.read_volatile() }
    }

    /// Writes everything but the ownership flags, which the caller
    /// publishes afterwards.
    fn write_descriptor_body(&self, position: u16, addr: u64, len: u32, id: u16) {
        let base = self.descriptor_ptr(position).cast::<u8>();
        // SAFETY: `descriptor_ptr` checked `position < self.core.size`,
        // the descriptor is 16-byte aligned, and `addr` is at offset 0
        // before the head flags expose this descriptor to the device.
        unsafe { base.cast::<u64>().write_volatile(addr) };
        // SAFETY: offset 8 stays within the 16-byte `PackedDescriptor`.
        let len_ptr = unsafe { base.add(8) };
        // SAFETY: `len_ptr` is 4-byte aligned (descriptor is 16-byte
        // aligned + 8) and inside the descriptor at `position`.
        unsafe { len_ptr.cast::<u32>().write_volatile(len) };
        // SAFETY: offset 12 stays within the 16-byte `PackedDescriptor`.
        let id_ptr = unsafe { base.add(12) };
        // SAFETY: `id_ptr` is 2-byte aligned (descriptor is 16-byte
        // aligned + 12) and inside the descriptor at `position`.
        unsafe { id_ptr.cast::<u16>().write_volatile(id) };
    }

    fn write_descriptor_flags(&self, position: u16, flags: u16) {
        let base = self.descriptor_ptr(position).cast::<u8>();
        // SAFETY: offset 14 (`flags`) stays within the 16-byte
        // `PackedDescriptor` at `position`.
        let flags_ptr = unsafe { base.add(14) };
        // SAFETY: `flags_ptr` is 2-byte aligned (16-byte aligned + 14)
        // and inside the resident descriptor ring.
        unsafe { flags_ptr.cast::<u16>().write_volatile(flags) };
    }
}

/// The AVAIL/USED pair a driver writes for the given wrap counter.
fn availability(wrap: bool) -> u16 {
    if wrap { DESC_F_AVAIL } else { DESC_F_USED }
}

fn is_used(flags: u16, used_wrap: bool) -> bool {
    let avail = flags & DESC_F_AVAIL != 0;
    let used = flags & DESC_F_USED != 0;
    avail == used && used == used_wrap
}

fn zero<B: DmaBuffer>(buffer: &B) {
    // SAFETY: `buffer` is a resident DMA allocation of `buffer.len()`
    // bytes, and `zero` is only called during `reprogram` under `&mut
    // self` after the device queue has been reset.
    unsafe {
        buffer.as_ptr().write_bytes(0, buffer.len());
    }
}

#[cfg(test)]
impl<T: VirtioTransport> PackedRing<T> {
    pub(super) fn descriptor(&self, position: u16) -> PackedDescriptor {
        self.read_descriptor(position)
    }

    pub(super) fn indirect_descriptor(&self, id: u16, slot: usize) -> PackedDescriptor {
        let tables = self
            .core
            .indirect
            .as_ref()
            .expect("queue has no indirect tables");
        let base = tables.table_ptr(id).cast::<PackedDescriptor>();
        // SAFETY: `table_ptr` checked `id` is in range, and test callers
        // index `slot < tables.entries()` inside `id`'s indirect table.
        let ptr = unsafe { base.add(slot) };
        // SAFETY: `ptr` points to a valid, aligned `PackedDescriptor`
        // inside `id`'s resident indirect table.
        unsafe { ptr.read_volatile() }
    }

    /// The used-buffer suppression state the driver published.
    pub(super) fn driver_event(&self) -> (u16, u16) {
        let base = self.driver_event.as_ptr().cast::<u16>();
        // SAFETY: `driver_event` is a resident 4-byte, 4-byte-aligned
        // DMA buffer owned by `self`, so offset 0 is a valid, aligned
        // `u16` field.
        let off_wrap = unsafe { base.read_volatile() };
        // SAFETY: `driver_event` holds two `u16` fields (4 bytes), so
        // `base.add(1)` stays within the allocation.
        let flags_ptr = unsafe { base.add(1) };
        // SAFETY: `flags_ptr` is valid and 2-byte-aligned inside
        // `driver_event`.
        let flags = unsafe { flags_ptr.read_volatile() };
        (off_wrap, flags)
    }

    /// Device side: publish an available-buffer suppression state.
    pub(super) fn device_set_event(&self, off_wrap: u16, flags: u16) {
        let base = self.device_event.as_ptr().cast::<u16>();
        // SAFETY: `device_event` is a resident 4-byte, 4-byte-aligned
        // DMA buffer owned by `self`, so offset 0 is a valid, aligned
        // `u16` field written only by the test device in single-threaded
        // tests.
        unsafe { base.write_volatile(off_wrap) };
        // SAFETY: `device_event` holds two `u16` fields (4 bytes), so
        // `base.add(1)` stays within the allocation.
        let flags_ptr = unsafe { base.add(1) };
        // SAFETY: `flags_ptr` is valid and 2-byte-aligned inside
        // `device_event`.
        unsafe { flags_ptr.write_volatile(flags) };
    }

    /// Device side: mark the chain `id` used at ring position `position`
    /// with the device wrap counter `wrap`.
    pub(super) fn device_complete(&self, position: u16, wrap: bool, id: u16, len: u32) {
        let descriptor = self.read_descriptor(position);
        self.write_descriptor_body(position, descriptor.addr, len, id);
        let flags = if wrap { DESC_F_AVAIL | DESC_F_USED } else { 0 };
        self.write_descriptor_flags(position, flags);
    }

    pub(super) fn avail_position(&self) -> (u16, bool) {
        (self.next_avail, self.avail_wrap)
    }
}
