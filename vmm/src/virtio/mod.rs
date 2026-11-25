//! Virtio 1.2 MMIO transport, split virtqueues, `ioevent` registration, and
//! concrete device models (`console`, `block`, `net`, `vsock`, `fs`).

pub mod block;
pub mod console;
pub mod fs;
pub mod net;
pub mod vsock;

use helios_api::hv::{
    GuestMemory, GuestPhysAddr, IoAccess, IoEvent, IoWidth, MmioDevice, MmioRange,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::boot::{VIRTIO_MMIO_STRIDE, VirtioSlot};
use crate::error::{Error, Result};
use crate::hv_backend::IoEventRegistrar;

/// Virtio MMIO v2 `QueueNotify` register offset (Virtio 1.2 §4.2.2).
pub const QUEUE_NOTIFY_OFFSET: u64 = 0x050;

// Virtio split queue size is a power of two, at most 32768.
pub const QUEUE_MAX: u16 = 256;
pub const VERSION_1: u64 = 1 << 32;
pub const DRIVER_OK: u32 = 4;
pub const FEATURES_OK: u32 = 8;

/// Raw Virtio 1.2 split virtqueue descriptor (`struct virtq_desc`, 16 bytes).
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct RawDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

/// Raw Virtio 1.2 split virtqueue used element (`struct virtq_used_elem`, 8 bytes).
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct RawUsedElem {
    id: u32,
    len: u32,
}

/// Validated guest-RAM descriptor entry popped from a split virtqueue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub address: GuestPhysAddr,
    pub length: u32,
    pub writable: bool,
}

/// Validated descriptor chain popped from a split virtqueue.
#[derive(Debug)]
pub struct Chain {
    pub head: u16,
    pub descriptors: Vec<Descriptor>,
}

/// Split virtqueue state owned by a single device task.
#[derive(Default, Debug)]
pub struct Queue {
    pub size: u16,
    pub ready: bool,
    pub descriptor: u64,
    pub available: u64,
    pub used: u64,
    pub next_available: u16,
    pub next_used: u16,
}

impl Queue {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Returns whether the guest has at least one unconsumed descriptor chain
    /// posted to this queue's available ring.
    pub fn has_available(&self, memory: &impl GuestMemory) -> Result<bool> {
        if !self.ready {
            return Ok(false);
        }
        let available = memory.read_u16(GuestPhysAddr::new(self.available + 2))?;
        Ok(available != self.next_available)
    }

    pub fn pop(&mut self, memory: &impl GuestMemory) -> Result<Option<Chain>> {
        if !self.ready {
            return Ok(None);
        }
        let available = memory.read_u16(GuestPhysAddr::new(self.available + 2))?;
        if available == self.next_available {
            return Ok(None);
        }
        if available.wrapping_sub(self.next_available) > self.size {
            return Err(Error::Virtio("available index exceeds queue size"));
        }
        let ring_slot = u64::from(self.next_available % self.size) * 2;
        let head = memory.read_u16(GuestPhysAddr::new(self.available + 4 + ring_slot))?;
        let mut index = head;
        let mut descriptors = Vec::new();
        loop {
            if index >= self.size || descriptors.len() >= usize::from(self.size) {
                return Err(Error::Virtio("descriptor chain index or cycle"));
            }
            let desc_addr = GuestPhysAddr::new(self.descriptor + u64::from(index) * 16);
            let raw: RawDesc = memory.read_pod(desc_addr)?;
            let address = GuestPhysAddr::new(u64::from_le(raw.addr));
            let length = u32::from_le(raw.len);
            let flags = u16::from_le(raw.flags);
            let next = u16::from_le(raw.next);
            if flags & !3 != 0 {
                return Err(Error::Virtio("unnegotiated descriptor flags"));
            }
            memory.validate_range(address, u64::from(length))?;
            descriptors.push(Descriptor {
                address,
                length,
                writable: flags & 2 != 0,
            });
            if flags & 1 == 0 {
                break;
            }
            index = next;
        }
        self.next_available = self.next_available.wrapping_add(1);
        Ok(Some(Chain { head, descriptors }))
    }

    /// Publishes one completed chain to the used ring. Returns `true` if the
    /// guest has not suppressed interrupts (`AVAIL_F_NO_INTERRUPT == 0`).
    pub fn complete(&mut self, memory: &impl GuestMemory, head: u16, length: u32) -> Result<bool> {
        let address = GuestPhysAddr::new(self.used + 4 + u64::from(self.next_used % self.size) * 8);
        let elem = RawUsedElem {
            id: u32::from(head).to_le(),
            len: length.to_le(),
        };
        memory.write_pod(address, &elem)?;
        self.next_used = self.next_used.wrapping_add(1);
        memory.write_u16(GuestPhysAddr::new(self.used + 2), self.next_used)?;
        Ok(memory.read_u16(GuestPhysAddr::new(self.available))? & 1 == 0)
    }

    pub fn enable(&mut self, memory: &impl GuestMemory) -> Result<()> {
        if self.size == 0 || self.size > QUEUE_MAX || !self.size.is_power_of_two() {
            return Err(Error::Virtio("invalid negotiated size"));
        }
        if self.descriptor & 15 != 0 || self.available & 1 != 0 || self.used & 3 != 0 {
            return Err(Error::Virtio("misaligned ring"));
        }
        memory.validate_range(
            GuestPhysAddr::new(self.descriptor),
            u64::from(self.size) * 16,
        )?;
        memory.validate_range(
            GuestPhysAddr::new(self.available),
            6 + u64::from(self.size) * 2,
        )?;
        memory.validate_range(GuestPhysAddr::new(self.used), 6 + u64::from(self.size) * 8)?;
        self.ready = true;
        Ok(())
    }
}

/// Static device-specific half of a Virtio 1.2 MMIO transport.
pub trait VirtioModel {
    const ID: u32;
    const FEATURES: u64;
    const REQUIRED: u64;

    /// Device feature bits offered to the guest; defaults to [`Self::FEATURES`].
    fn features(&self) -> u64 {
        Self::FEATURES
    }

    fn queues(&self) -> &[Queue];
    fn queues_mut(&mut self) -> &mut [Queue];
    fn configuration(&self, offset: u64, width: IoWidth) -> u64;
    /// Resets transient guest state and queues while preserving host-side configuration.
    fn reset(&mut self);
}

/// Reads 1, 2, 4, or 8 little-endian bytes from a device's configuration space
/// starting at MMIO offset `0x100`.
pub fn read_config_bytes(config: &[u8], mmio_offset: u64, width: IoWidth) -> u64 {
    let Some(rel) = mmio_offset.checked_sub(0x100) else {
        return 0;
    };
    let start = rel as usize;
    let count = match width {
        IoWidth::Byte => 1,
        IoWidth::Word => 2,
        IoWidth::Dword => 4,
        IoWidth::Qword => 8,
    };
    let mut out = [0u8; 8];
    for (i, slot) in out.iter_mut().take(count).enumerate() {
        if let Some(&byte) = config.get(start + i) {
            *slot = byte;
        }
    }
    u64::from_le_bytes(out)
}

/// Virtio 1.2 MMIO v2 transport wrapping a concrete [`VirtioModel`].
pub struct VirtioMmio<M: VirtioModel> {
    slot: VirtioSlot,
    range: MmioRange,
    pub model: M,
    feature_select: u32,
    driver_select: u32,
    driver_features: u64,
    queue_select: u32,
    pub status: u32,
    pub interrupt: u32,
}

impl<M: VirtioModel> VirtioMmio<M> {
    pub fn new(slot: VirtioSlot, model: M) -> Self {
        let range =
            MmioRange::new(slot.base, VIRTIO_MMIO_STRIDE).expect("virtio MMIO range is valid");
        Self {
            slot,
            range,
            model,
            feature_select: 0,
            driver_select: 0,
            driver_features: 0,
            queue_select: 0,
            status: 0,
            interrupt: 0,
        }
    }

    pub const fn slot(&self) -> VirtioSlot {
        self.slot
    }

    pub const fn irq(&self) -> u32 {
        self.slot.irq
    }

    pub const fn irq_asserted(&self) -> bool {
        self.interrupt != 0
    }

    pub const fn driver_ok(&self) -> bool {
        self.status & DRIVER_OK != 0
    }

    pub fn notify_address(&self) -> GuestPhysAddr {
        self.slot
            .base
            .checked_add(QUEUE_NOTIFY_OFFSET)
            .expect("virtio QueueNotify address does not overflow")
    }

    /// Registers one `ioevent` per virtqueue on this transport's `QueueNotify`
    /// register (`base + 0x050`, 32-bit write matching the queue index).
    ///
    /// Matching writes complete inside the kernel without blocking the vCPU on
    /// synchronous MMIO exit completion; invalid queue indices remain unhandled
    /// by `ioevent` and trap to [`Self::access`] so they still fail fast.
    pub fn register_queue_ioevents<R: IoEventRegistrar>(
        &self,
        registrar: &R,
    ) -> Result<Vec<(u16, IoEvent<R::Backend>)>> {
        let notify_addr = self.notify_address();
        let count = self.model.queues().len();
        let mut events = Vec::with_capacity(count);
        for queue in 0..count {
            let event =
                registrar.register_ioevent(notify_addr, IoWidth::Dword, Some(queue as u64))?;
            events.push((queue as u16, event));
        }
        Ok(events)
    }

    fn reset_transport(&mut self) {
        self.model.reset();
        self.feature_select = 0;
        self.driver_select = 0;
        self.driver_features = 0;
        self.queue_select = 0;
        self.status = 0;
        self.interrupt = 0;
    }

    pub fn mmio_access(
        &mut self,
        offset: u64,
        access: IoAccess,
        memory: &impl GuestMemory,
    ) -> Result<u64> {
        let (width, value) = match access {
            IoAccess::Read(width) => (width, None),
            IoAccess::Write(write) => (write.width, Some(write.value as u32)),
        };
        if offset < 0x100 && (!matches!(width, IoWidth::Dword) || offset & 3 != 0) {
            return Err(Error::Virtio("MMIO transport register access width"));
        }
        let queue_count = self.model.queues().len() as u32;
        if let Some(value) = value {
            match offset {
                0x014 => self.feature_select = value,
                0x020 => {
                    if self.driver_select < 2 {
                        let shift = self.driver_select * 32;
                        self.driver_features = (self.driver_features
                            & !(u64::from(u32::MAX) << shift))
                            | (u64::from(value) << shift);
                    }
                }
                0x024 => self.driver_select = value,
                0x030 => self.queue_select = value,
                0x038 | 0x044 | 0x080 | 0x084 | 0x090 | 0x094 | 0x0a0 | 0x0a4 => {
                    let queue = self
                        .model
                        .queues_mut()
                        .get_mut(self.queue_select as usize)
                        .filter(|_| self.queue_select < queue_count)
                        .ok_or(Error::Virtio("queue selector"))?;
                    if offset != 0x044 && queue.ready {
                        return Err(Error::Virtio("configuration of a ready queue"));
                    }
                    match offset {
                        0x038 => {
                            queue.size = value
                                .try_into()
                                .map_err(|_| Error::Virtio("queue size overflow"))?;
                        }
                        0x044 => {
                            if value == 0 {
                                queue.reset();
                            } else if value == 1 && !queue.ready {
                                queue.enable(memory)?;
                            } else {
                                return Err(Error::Virtio("queue ready transition"));
                            }
                        }
                        0x080 => {
                            queue.descriptor =
                                (queue.descriptor & !u64::from(u32::MAX)) | u64::from(value);
                        }
                        0x084 => {
                            queue.descriptor =
                                (queue.descriptor & u64::from(u32::MAX)) | (u64::from(value) << 32);
                        }
                        0x090 => {
                            queue.available =
                                (queue.available & !u64::from(u32::MAX)) | u64::from(value);
                        }
                        0x094 => {
                            queue.available =
                                (queue.available & u64::from(u32::MAX)) | (u64::from(value) << 32);
                        }
                        0x0a0 => {
                            queue.used = (queue.used & !u64::from(u32::MAX)) | u64::from(value);
                        }
                        0x0a4 => {
                            queue.used =
                                (queue.used & u64::from(u32::MAX)) | (u64::from(value) << 32);
                        }
                        _ => unreachable!(),
                    }
                }
                QUEUE_NOTIFY_OFFSET => {
                    if value >= queue_count {
                        return Err(Error::Virtio("notify queue selector"));
                    }
                }
                0x064 => self.interrupt &= !value,
                0x070 => {
                    if value == 0 {
                        self.reset_transport();
                    } else {
                        self.status = value;
                        let offered = self.model.features();
                        if value & FEATURES_OK != 0
                            && (self.driver_features & !offered != 0
                                || self.driver_features & M::REQUIRED != M::REQUIRED)
                        {
                            self.status &= !FEATURES_OK;
                        }
                    }
                }
                // Virtio 1.2 reserved registers ignore writes.
                _ => {}
            }
            return Ok(0);
        }
        let queue = self
            .model
            .queues()
            .get(self.queue_select as usize)
            .filter(|_| self.queue_select < queue_count);
        Ok(match offset {
            0x000 => 0x7472_6976, // "virt"
            0x004 => 2,           // MMIO v2
            0x008 => u64::from(M::ID),
            0x00c => 0x4845_4c49, // "HELI"
            0x010 => {
                if self.feature_select < 2 {
                    (self.model.features() >> (self.feature_select * 32)) & u64::from(u32::MAX)
                } else {
                    0
                }
            }
            0x034 => {
                if queue.is_some() {
                    u64::from(QUEUE_MAX)
                } else {
                    0
                }
            }
            0x044 => u64::from(queue.is_some_and(|q| q.ready)),
            0x060 => u64::from(self.interrupt),
            0x070 => u64::from(self.status),
            0x0fc => 0,
            _ => self.model.configuration(offset, width),
        })
    }
}

impl<M: VirtioModel, G: GuestMemory> MmioDevice<G> for VirtioMmio<M> {
    type Error = Error;

    fn range(&self) -> MmioRange {
        self.range
    }

    fn access(&mut self, offset: u64, access: IoAccess, memory: &G) -> Result<u64> {
        self.mmio_access(offset, access, memory)
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use helios_api::hv::{GuestRange, GuestRegion, MemoryBackend};
    use std::cell::RefCell;

    pub struct VecMemory(pub RefCell<Vec<u8>>);

    impl MemoryBackend for VecMemory {
        fn read_offset(&self, offset: u64, length: u32) -> helios_api::hv::Result<Vec<u8>> {
            let start = offset as usize;
            let end = start + length as usize;
            Ok(self.0.borrow()[start..end].to_vec())
        }

        fn write_offset(&self, offset: u64, bytes: &[u8]) -> helios_api::hv::Result<()> {
            let start = offset as usize;
            let end = start + bytes.len();
            self.0.borrow_mut()[start..end].copy_from_slice(bytes);
            Ok(())
        }

        fn publish_offset(&self, _offset: u64, _length: u64) -> helios_api::hv::Result<()> {
            Ok(())
        }
    }

    pub fn test_ram(bytes: usize) -> GuestRegion<VecMemory> {
        let range = GuestRange::new(GuestPhysAddr::new(0), bytes as u64).unwrap();
        GuestRegion::from_backend(range, VecMemory(RefCell::new(vec![0; bytes])))
    }

    pub fn enable_queue(ram: &GuestRegion<VecMemory>, base: u64, size: u16) -> Queue {
        let mut queue = Queue {
            size,
            descriptor: base,
            available: base + 128,
            used: base + 256,
            ..Queue::default()
        };
        queue.enable(ram).unwrap();
        queue
    }

    pub fn write_desc(
        ram: &GuestRegion<VecMemory>,
        queue: &Queue,
        index: u16,
        address: u64,
        length: u32,
        flags: u16,
        next: u16,
    ) {
        let raw = RawDesc {
            addr: address.to_le(),
            len: length.to_le(),
            flags: flags.to_le(),
            next: next.to_le(),
        };
        ram.write_pod(
            GuestPhysAddr::new(queue.descriptor + u64::from(index) * 16),
            &raw,
        )
        .unwrap();
    }

    pub fn push_avail(ram: &GuestRegion<VecMemory>, queue: &Queue, slot: u16, head: u16) {
        ram.write_u16(
            GuestPhysAddr::new(queue.available + 4 + u64::from(slot % queue.size) * 2),
            head,
        )
        .unwrap();
        ram.write_u16(
            GuestPhysAddr::new(queue.available + 2),
            slot.wrapping_add(1),
        )
        .unwrap();
    }

    pub fn used_idx(ram: &GuestRegion<VecMemory>, queue: &Queue) -> u16 {
        ram.read_u16(GuestPhysAddr::new(queue.used + 2)).unwrap()
    }

    pub fn used_len(ram: &GuestRegion<VecMemory>, queue: &Queue, slot: u16) -> u32 {
        ram.read_u32(GuestPhysAddr::new(
            queue.used + 4 + u64::from(slot % queue.size) * 8 + 4,
        ))
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::console::ConsoleModel;
    use super::test_support::*;
    use super::*;
    use helios_api::hv::{IoEventBackend, IoWrite};

    #[test]
    fn rejects_reconfiguring_enabled_ring_and_invalid_chains() {
        let ram = test_ram(4096);
        let queue = enable_queue(&ram, 0, 4);
        let mut dev = VirtioMmio::new(VirtioSlot::at(0).unwrap(), ConsoleModel::new(80, 25));
        dev.model.queues_mut()[0] = queue;
        let write = IoAccess::Write(IoWrite {
            width: IoWidth::Dword,
            value: u64::MAX,
        });
        assert!(matches!(
            dev.mmio_access(0x080, write, &ram),
            Err(Error::Virtio(_))
        ));
        assert_eq!(dev.model.queues()[0].descriptor, 0);

        let mut q = enable_queue(&ram, 0, 4);
        ram.write_u16(GuestPhysAddr::new(130), 1).unwrap();
        write_desc(&ram, &q, 0, 1024, 16, 1, 0);
        assert!(matches!(q.pop(&ram), Err(Error::Virtio(_))));
        write_desc(&ram, &q, 0, 4090, 16, 0, 0);
        assert!(matches!(q.pop(&ram), Err(Error::Hv(_))));
        assert_eq!(q.next_available, 0);

        ram.write_u16(GuestPhysAddr::new(130), 5).unwrap();
        assert!(matches!(q.pop(&ram), Err(Error::Virtio(_))));
    }

    #[test]
    fn queue_wrap_and_interrupt_suppression() {
        let ram = test_ram(4096);
        let mut queue = enable_queue(&ram, 0, 4);
        queue.next_available = u16::MAX;
        queue.next_used = u16::MAX;
        write_desc(&ram, &queue, 0, 1024, 16, 0, 0);
        ram.write_u16(GuestPhysAddr::new(128), 1).unwrap();
        ram.write_u16(GuestPhysAddr::new(130), 0).unwrap();
        let chain = queue.pop(&ram).unwrap().unwrap();
        assert_eq!(queue.next_available, 0);
        assert!(!queue.complete(&ram, chain.head, 0).unwrap());
        assert_eq!(used_idx(&ram, &queue), 0);
    }

    #[test]
    fn registers_per_queue_ioevents_at_queue_notify_offset() {
        struct MockEvent;
        impl IoEventBackend for MockEvent {
            async fn wait(&self) -> helios_api::hv::Result<()> {
                Ok(())
            }
        }
        struct RecordingRegistrar {
            calls: std::cell::RefCell<Vec<(GuestPhysAddr, IoWidth, Option<u64>)>>,
        }
        impl IoEventRegistrar for RecordingRegistrar {
            type Backend = MockEvent;
            fn register_ioevent(
                &self,
                address: GuestPhysAddr,
                width: IoWidth,
                match_value: Option<u64>,
            ) -> Result<IoEvent<Self::Backend>> {
                self.calls.borrow_mut().push((address, width, match_value));
                Ok(IoEvent::from_backend(
                    address,
                    width,
                    match_value,
                    MockEvent,
                ))
            }
        }

        let slot = VirtioSlot::at(2).unwrap();
        let dev = VirtioMmio::new(slot, ConsoleModel::new(80, 25));
        let registrar = RecordingRegistrar {
            calls: std::cell::RefCell::new(Vec::new()),
        };
        let events = dev.register_queue_ioevents(&registrar).unwrap();
        assert_eq!(events.len(), 4);
        let calls = registrar.calls.borrow();
        for q in 0..4u64 {
            assert_eq!(
                calls[q as usize],
                (
                    slot.base.checked_add(QUEUE_NOTIFY_OFFSET).unwrap(),
                    IoWidth::Dword,
                    Some(q)
                )
            );
        }
    }
}
