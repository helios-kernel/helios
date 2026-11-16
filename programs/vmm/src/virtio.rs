//! Virtio 1.2 MMIO transport and split queues. The device task is the sole
//! owner; vCPU exits and terminal input arrive over bounded channels.
use crate::memory::GuestMemory;
use crate::{Error, Result, file::File, memory::TRANSFER};
use helios_api::hv::{IoAccess, IoWidth};
use std::collections::VecDeque;

// Virtio split queue size is a power of two, at most 32768. This device
// advertises 256 entries, and implements neither indirect nor event-index.
const QUEUE_MAX: u16 = 256;
const VERSION_1: u64 = 1 << 32;
const CONSOLE_SIZE: u64 = 1;
const CONSOLE_MULTIPORT: u64 = 1 << 1;
const DRIVER_OK: u32 = 4;
const FEATURES_OK: u32 = 8;
// Virtio 1.2 console control events, section 5.3.6.2.
const DEVICE_READY: u16 = 0;
const PORT_ADD: u16 = 1;
const PORT_READY: u16 = 3;
const CONSOLE_PORT: u16 = 4;
const RESIZE: u16 = 5;
const PORT_OPEN: u16 = 6;

#[derive(Default)]
pub(super) struct Queue {
    size: u16,
    ready: bool,
    descriptor: u64,
    available: u64,
    used: u64,
    next_available: u16,
    next_used: u16,
}

pub struct Descriptor {
    address: u64,
    length: u32,
    writable: bool,
}
struct Chain {
    head: u16,
    descriptors: Vec<Descriptor>,
}

impl Queue {
    fn pop(&mut self, memory: &impl GuestMemory) -> Result<Option<Chain>> {
        if !self.ready {
            return Ok(None);
        }
        let available = memory.u16(self.available + 2)?;
        if available == self.next_available {
            return Ok(None);
        }
        if available.wrapping_sub(self.next_available) > self.size {
            return Err(Error::Queue("available index exceeds queue size"));
        }
        let head =
            memory.u16(self.available + 4 + u64::from(self.next_available % self.size) * 2)?;
        let mut index = head;
        let mut descriptors = Vec::new();
        loop {
            if index >= self.size || descriptors.len() >= usize::from(self.size) {
                return Err(Error::Queue("descriptor chain index or cycle"));
            }
            let bytes = memory.read(self.descriptor + u64::from(index) * 16, 16)?;
            let address = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
            let length = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
            let flags = u16::from_le_bytes(bytes[12..14].try_into().unwrap());
            if flags & !3 != 0 {
                return Err(Error::Queue("unnegotiated descriptor flags"));
            }
            memory.offset(address, u64::from(length))?;
            descriptors.push(Descriptor {
                address,
                length,
                writable: flags & 2 != 0,
            });
            if flags & 1 == 0 {
                break;
            }
            index = u16::from_le_bytes(bytes[14..16].try_into().unwrap());
        }
        self.next_available = self.next_available.wrapping_add(1);
        Ok(Some(Chain { head, descriptors }))
    }

    fn complete(&mut self, memory: &impl GuestMemory, head: u16, length: u32) -> Result<bool> {
        let address = self.used + 4 + u64::from(self.next_used % self.size) * 8;
        memory.write(address, &u32::from(head).to_le_bytes())?;
        memory.write(address + 4, &length.to_le_bytes())?;
        self.next_used = self.next_used.wrapping_add(1);
        memory.write(self.used + 2, &self.next_used.to_le_bytes())?;
        Ok(memory.u16(self.available)? & 1 == 0)
    }

    fn enable(&mut self, memory: &impl GuestMemory) -> Result<()> {
        if self.size == 0 || self.size > QUEUE_MAX || !self.size.is_power_of_two() {
            return Err(Error::Queue("invalid negotiated size"));
        }
        if self.descriptor & 15 != 0 || self.available & 1 != 0 || self.used & 3 != 0 {
            return Err(Error::Queue("misaligned ring"));
        }
        memory.offset(self.descriptor, u64::from(self.size) * 16)?;
        memory.offset(self.available, 6 + u64::from(self.size) * 2)?;
        memory.offset(self.used, 6 + u64::from(self.size) * 8)?;
        self.ready = true;
        Ok(())
    }
}

pub(super) trait Model: Default {
    const ID: u32;
    const FEATURES: u64;
    const REQUIRED: u64;
    fn queues(&self) -> &[Queue];
    fn queues_mut(&mut self) -> &mut [Queue];
    fn configuration(&self, offset: u64, width: IoWidth, capacity: u64) -> u64;
}

#[derive(Default)]
pub(super) struct Console {
    queues: [Queue; 4],
    device_ready: bool,
    port_ready: bool,
    guest_open: bool,
    // One pending response per handshake event; repeats coalesce.
    pending: u8,
}

#[derive(Default)]
pub(super) struct Block {
    queues: [Queue; 1],
}

impl Console {
    fn receive_control(&mut self, packet: [u8; 8]) -> Result<()> {
        let id = u32::from_le_bytes(packet[..4].try_into().unwrap());
        let event = u16::from_le_bytes(packet[4..6].try_into().unwrap());
        let value = u16::from_le_bytes(packet[6..].try_into().unwrap());
        match event {
            DEVICE_READY if value == 1 => {
                self.device_ready = true;
                self.pending |= 1;
            }
            PORT_READY if id == 0 && value == 1 && self.device_ready => {
                self.port_ready = true;
                // Identify the console, connect its host end, then size it.
                self.pending |= 0b1110;
            }
            PORT_OPEN if id == 0 && value <= 1 && self.port_ready => {
                self.guest_open = value == 1;
            }
            _ => return Err(Error::Queue("invalid console control transition")),
        }
        Ok(())
    }

    fn response(&self) -> ([u8; 12], usize, u8) {
        let index = self.pending.trailing_zeros();
        let event = [PORT_ADD, CONSOLE_PORT, PORT_OPEN, RESIZE][index as usize];
        let mut bytes = [0; 12];
        bytes[4..6].copy_from_slice(&event.to_le_bytes());
        bytes[6..8].copy_from_slice(&1u16.to_le_bytes());
        let length = if event == RESIZE {
            bytes[8..10].copy_from_slice(&25u16.to_le_bytes());
            bytes[10..12].copy_from_slice(&80u16.to_le_bytes());
            12
        } else {
            8
        };
        (bytes, length, 1 << index)
    }
}

impl Model for Console {
    const ID: u32 = 3;
    const FEATURES: u64 = VERSION_1 | CONSOLE_SIZE | CONSOLE_MULTIPORT;
    const REQUIRED: u64 = VERSION_1 | CONSOLE_MULTIPORT;
    fn queues(&self) -> &[Queue] {
        &self.queues
    }
    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }
    fn configuration(&self, offset: u64, _: IoWidth, _: u64) -> u64 {
        match offset {
            0x100 => 80 | (25 << 16),
            0x102 => 25,
            0x104 => 1, // One console port, with the four multiport queues.
            _ => 0,
        }
    }
}

impl Model for Block {
    const ID: u32 = 2;
    const FEATURES: u64 = VERSION_1;
    const REQUIRED: u64 = VERSION_1;
    fn queues(&self) -> &[Queue] {
        &self.queues
    }
    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }
    fn configuration(&self, offset: u64, width: IoWidth, capacity: u64) -> u64 {
        if !(0x100..=0x107).contains(&offset) {
            return 0;
        }
        let mask = match width {
            IoWidth::Byte => 0xff,
            IoWidth::Word => 0xffff,
            IoWidth::Dword => 0xffff_ffff,
            IoWidth::Qword => u64::MAX,
        };
        (capacity >> ((offset - 0x100) * 8)) & mask
    }
}

pub(super) struct Device<M: Model> {
    model: M,
    feature_select: u32,
    driver_select: u32,
    driver_features: u64,
    queue_select: u32,
    status: u32,
    pub interrupt: u32,
}

impl<M: Model> Device<M> {
    fn new() -> Self {
        Self {
            model: M::default(),
            feature_select: 0,
            driver_select: 0,
            driver_features: 0,
            queue_select: 0,
            status: 0,
            interrupt: 0,
        }
    }

    pub fn access(
        &mut self,
        offset: u64,
        access: IoAccess,
        capacity: u64,
        memory: &impl GuestMemory,
    ) -> Result<u64> {
        let (width, value) = match access {
            IoAccess::Read(width) => (width, None),
            IoAccess::Write(write) => (write.width, Some(write.value as u32)),
        };
        if offset < 0x100 && (!matches!(width, IoWidth::Dword) || offset & 3 != 0) {
            return Err(Error::Queue("MMIO transport register access width"));
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
                        .ok_or(Error::Queue("queue selector"))?;
                    if offset != 0x044 && queue.ready {
                        return Err(Error::Queue("configuration of a ready queue"));
                    }
                    match offset {
                        0x038 => {
                            queue.size = value
                                .try_into()
                                .map_err(|_| Error::Queue("queue size overflow"))?
                        }
                        0x044 => {
                            if value == 0 {
                                *queue = Queue::default();
                            } else if value == 1 && !queue.ready {
                                queue.enable(memory)?;
                            } else {
                                return Err(Error::Queue("queue ready transition"));
                            }
                        }
                        0x080 => {
                            queue.descriptor =
                                (queue.descriptor & !u64::from(u32::MAX)) | u64::from(value)
                        }
                        0x084 => {
                            queue.descriptor =
                                (queue.descriptor & u64::from(u32::MAX)) | (u64::from(value) << 32)
                        }
                        0x090 => {
                            queue.available =
                                (queue.available & !u64::from(u32::MAX)) | u64::from(value)
                        }
                        0x094 => {
                            queue.available =
                                (queue.available & u64::from(u32::MAX)) | (u64::from(value) << 32)
                        }
                        0x0a0 => {
                            queue.used = (queue.used & !u64::from(u32::MAX)) | u64::from(value)
                        }
                        0x0a4 => {
                            queue.used =
                                (queue.used & u64::from(u32::MAX)) | (u64::from(value) << 32)
                        }
                        _ => unreachable!(),
                    }
                }
                0x050 => {
                    if value >= queue_count {
                        return Err(Error::Queue("notify queue selector"));
                    }
                }
                0x064 => self.interrupt &= !value,
                0x070 => {
                    if value == 0 {
                        *self = Self::new();
                    } else {
                        self.status = value;
                        if value & FEATURES_OK != 0
                            && (self.driver_features & !M::FEATURES != 0
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
            0x000 => 0x7472_6976,
            0x004 => 2,
            0x008 => u64::from(M::ID),
            0x00c => 0x4845_4c49,
            0x010 => {
                if self.feature_select < 2 {
                    (M::FEATURES >> (self.feature_select * 32)) & u64::from(u32::MAX)
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
            0x044 => u64::from(queue.is_some_and(|queue| queue.ready)),
            0x060 => u64::from(self.interrupt),
            0x070 => u64::from(self.status),
            0x0fc => 0,
            _ => self.model.configuration(offset, width, capacity),
        })
    }
}

impl Device<Console> {
    pub fn console() -> Self {
        Self::new()
    }

    pub fn console_control(&mut self, memory: &impl GuestMemory) -> Result<()> {
        if self.status & DRIVER_OK == 0 {
            return Ok(());
        }
        while let Some(chain) = self.model.queues[3].pop(memory)? {
            let mut packet = [0; 8];
            let mut copied = 0;
            for descriptor in chain.descriptors {
                let end = copied + descriptor.length as usize;
                if descriptor.writable || end > packet.len() {
                    return Err(Error::Queue("console control request direction or length"));
                }
                packet[copied..end]
                    .copy_from_slice(&memory.read(descriptor.address, descriptor.length)?);
                copied = end;
            }
            if copied != packet.len() {
                return Err(Error::Queue("short console control request"));
            }
            self.model.receive_control(packet)?;
            if self.model.queues[3].complete(memory, chain.head, 0)? {
                self.interrupt |= 1;
            }
        }
        while self.model.pending != 0 {
            let Some(chain) = self.model.queues[2].pop(memory)? else {
                break;
            };
            let (bytes, length, bit) = self.model.response();
            let mut copied = 0;
            for descriptor in chain.descriptors {
                if !descriptor.writable {
                    return Err(Error::Queue("read-only console control response"));
                }
                let count = (descriptor.length as usize).min(length - copied);
                memory.write(descriptor.address, &bytes[copied..copied + count])?;
                copied += count;
                if copied == length {
                    break;
                }
            }
            if copied != length {
                return Err(Error::Queue("short console control response buffer"));
            }
            if self.model.queues[2].complete(memory, chain.head, length as u32)? {
                self.interrupt |= 1;
            }
            self.model.pending &= !bit;
        }
        Ok(())
    }

    pub async fn console_output(&mut self, memory: &impl GuestMemory) -> Result<()> {
        if self.status & DRIVER_OK == 0 {
            return Ok(());
        }
        while let Some(chain) = self.model.queues[1].pop(memory)? {
            for descriptor in chain.descriptors {
                if descriptor.writable {
                    return Err(Error::Queue("writable console output"));
                }
                let mut offset = 0;
                while offset < descriptor.length {
                    let count = (descriptor.length - offset).min(TRANSFER as u32);
                    let bytes = memory.read(descriptor.address + u64::from(offset), count)?;
                    helios_api::io::stdout().write_all(bytes).await?;
                    offset += count;
                }
            }
            // Output descriptors are read-only: no bytes are written by device.
            if self.model.queues[1].complete(memory, chain.head, 0)? {
                self.interrupt |= 1;
            }
        }
        Ok(())
    }

    pub fn console_input(
        &mut self,
        memory: &impl GuestMemory,
        input: &mut VecDeque<u8>,
    ) -> Result<()> {
        if self.status & DRIVER_OK == 0 || !self.model.guest_open {
            return Ok(());
        }
        while !input.is_empty() {
            let Some(chain) = self.model.queues[0].pop(memory)? else {
                break;
            };
            let mut length = 0;
            for descriptor in chain.descriptors {
                if !descriptor.writable {
                    return Err(Error::Queue("read-only console input"));
                }
                let count = (descriptor.length as usize).min(input.len()).min(TRANSFER);
                let bytes: Vec<_> = input.drain(..count).collect();
                memory.write(descriptor.address, &bytes)?;
                length += count as u32;
                if input.is_empty() {
                    break;
                }
            }
            if self.model.queues[0].complete(memory, chain.head, length)? {
                self.interrupt |= 1;
            }
        }
        Ok(())
    }
}

impl Device<Block> {
    pub fn block() -> Self {
        Self::new()
    }

    pub async fn block_requests(&mut self, memory: &impl GuestMemory, file: &File) -> Result<()> {
        if self.status & DRIVER_OK == 0 {
            return Ok(());
        }
        while let Some(chain) = self.model.queues[0].pop(memory)? {
            let descriptors = &chain.descriptors;
            if descriptors.len() < 2 {
                return Err(Error::Queue("block header/status descriptors"));
            }
            let header = &descriptors[0];
            let status = descriptors.last().unwrap();
            if header.writable || header.length != 16 || !status.writable || status.length == 0 {
                return Err(Error::Queue("block header/status direction or length"));
            }
            let request = memory.read(header.address, 16)?;
            let kind = u32::from_le_bytes(request[..4].try_into().unwrap());
            let sector = u64::from_le_bytes(request[8..].try_into().unwrap());
            let payload = &descriptors[1..descriptors.len() - 1];
            let mut written = 1u32;
            let result = if kind == 0 || kind == 1 {
                let mut position = sector
                    .checked_mul(512)
                    .ok_or(Error::Queue("sector overflow"))?;
                let total: u64 = payload.iter().map(|item| u64::from(item.length)).sum();
                if payload.iter().any(|item| item.writable != (kind == 0)) {
                    return Err(Error::Queue("block payload direction"));
                }
                if total % 512 != 0
                    || position
                        .checked_add(total)
                        .is_none_or(|end| end > file.size)
                {
                    1
                } else {
                    for descriptor in payload {
                        let mut offset = 0;
                        while offset < descriptor.length {
                            let count = (descriptor.length - offset).min(TRANSFER as u32);
                            if kind == 0 {
                                let bytes = file.read(position, count as usize).await?;
                                memory.write(descriptor.address + u64::from(offset), &bytes)?;
                                written = written
                                    .checked_add(count)
                                    .ok_or(Error::Queue("used length overflow"))?;
                            } else {
                                let bytes =
                                    memory.read(descriptor.address + u64::from(offset), count)?;
                                file.write(position, bytes).await?;
                            }
                            position += u64::from(count);
                            offset += count;
                        }
                    }
                    0
                }
            } else {
                2
            };
            memory.write(status.address, &[result])?;
            if self.model.queues[0].complete(memory, chain.head, written)? {
                self.interrupt |= 1;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Ram(RefCell<Vec<u8>>);
    impl GuestMemory for Ram {
        fn offset(&self, address: u64, length: u64) -> Result<u64> {
            if address
                .checked_add(length)
                .is_none_or(|end| end > self.0.borrow().len() as u64)
            {
                return Err(Error::Memory(address, length));
            }
            Ok(address)
        }
        fn read(&self, address: u64, length: u32) -> Result<Vec<u8>> {
            self.offset(address, u64::from(length))?;
            Ok(self.0.borrow()[address as usize..address as usize + length as usize].to_vec())
        }
        fn write(&self, address: u64, bytes: &[u8]) -> Result<()> {
            self.offset(address, bytes.len() as u64)?;
            self.0.borrow_mut()[address as usize..address as usize + bytes.len()]
                .copy_from_slice(bytes);
            Ok(())
        }
    }
    fn ring() -> (Ram, Queue) {
        let ram = Ram(RefCell::new(vec![0; 4096]));
        let mut queue = Queue {
            size: 4,
            descriptor: 0,
            available: 128,
            used: 256,
            ..Queue::default()
        };
        queue.enable(&ram).unwrap();
        (ram, queue)
    }
    fn descriptor(
        ram: &Ram,
        queue: &Queue,
        index: u16,
        address: u64,
        length: u32,
        flags: u16,
        next: u16,
    ) {
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&address.to_le_bytes());
        bytes[8..12].copy_from_slice(&length.to_le_bytes());
        bytes[12..14].copy_from_slice(&flags.to_le_bytes());
        bytes[14..].copy_from_slice(&next.to_le_bytes());
        ram.write(queue.descriptor + u64::from(index) * 16, &bytes)
            .unwrap();
    }
    #[test]
    fn rejects_reconfiguring_an_enabled_ring() {
        let (ram, queue) = ring();
        let mut device = Device::console();
        device.model.queues[0] = queue;
        let write = IoAccess::Write(helios_api::hv::IoWrite {
            width: IoWidth::Dword,
            value: u64::MAX,
        });
        assert!(matches!(
            device.access(0x080, write, 0, &ram),
            Err(Error::Queue(_))
        ));
        assert_eq!(device.model.queues[0].descriptor, 0);
    }

    #[test]
    fn rejects_cyclic_and_out_of_ram_chains() {
        let (ram, mut queue) = ring();
        ram.write(130, &1u16.to_le_bytes()).unwrap();
        descriptor(&ram, &queue, 0, 1024, 16, 1, 0);
        assert!(matches!(queue.pop(&ram), Err(Error::Queue(_))));
        descriptor(&ram, &queue, 0, 4090, 16, 0, 0);
        assert!(matches!(queue.pop(&ram), Err(Error::Memory(_, _))));
        assert_eq!(queue.next_available, 0);
    }
    #[test]
    fn rejects_available_index_overrun() {
        let (ram, mut queue) = ring();
        ram.write(130, &5u16.to_le_bytes()).unwrap();
        assert!(matches!(queue.pop(&ram), Err(Error::Queue(_))));
    }
    fn control_packet(event: u16, value: u16) -> [u8; 8] {
        let mut bytes = [0; 8];
        bytes[4..6].copy_from_slice(&event.to_le_bytes());
        bytes[6..8].copy_from_slice(&value.to_le_bytes());
        bytes
    }

    #[test]
    fn console_buffers_input_until_multiport_handshake_opens_port() {
        let (ram, data) = ring();
        let mut device = Device::console();
        device.status = DRIVER_OK;
        device.model.queues[0] = data;
        for (index, base) in [(2, 512), (3, 1024)] {
            let mut queue = Queue {
                size: 4,
                descriptor: base,
                available: base + 128,
                used: base + 256,
                ..Queue::default()
            };
            queue.enable(&ram).unwrap();
            device.model.queues[index] = queue;
        }
        descriptor(&ram, &device.model.queues[0], 0, 2048, 16, 2, 0);
        ram.write(130, &1u16.to_le_bytes()).unwrap();
        for index in 0..4u16 {
            descriptor(
                &ram,
                &device.model.queues[2],
                index,
                3072 + u64::from(index) * 16,
                16,
                2,
                0,
            );
            ram.write(644 + u64::from(index) * 2, &index.to_le_bytes())
                .unwrap();
        }
        ram.write(642, &4u16.to_le_bytes()).unwrap();
        let mut input = VecDeque::from(Vec::from(b"uname\n"));
        for (index, event) in [DEVICE_READY, PORT_READY, PORT_OPEN]
            .into_iter()
            .enumerate()
        {
            device.console_input(&ram, &mut input).unwrap();
            assert_eq!(input.len(), 6);
            assert_eq!(ram.u16(258).unwrap(), 0);
            let address = 2304 + index as u64 * 16;
            ram.write(address, &control_packet(event, 1)).unwrap();
            descriptor(
                &ram,
                &device.model.queues[3],
                index as u16,
                address,
                8,
                0,
                0,
            );
            ram.write(1156 + index as u64 * 2, &(index as u16).to_le_bytes())
                .unwrap();
            ram.write(1154, &(index as u16 + 1).to_le_bytes()).unwrap();
            device.console_control(&ram).unwrap();
            assert_eq!(ram.u16(1282).unwrap(), index as u16 + 1);
            assert_eq!(ram.u16(770).unwrap(), if index == 0 { 1 } else { 4 });
        }
        for (index, event) in [PORT_ADD, CONSOLE_PORT, PORT_OPEN, RESIZE]
            .into_iter()
            .enumerate()
        {
            let address = 3072 + index as u64 * 16;
            assert_eq!(ram.read(address, 8).unwrap(), control_packet(event, 1));
            let length = if event == RESIZE { 12u32 } else { 8 };
            assert_eq!(
                ram.read(776 + index as u64 * 8, 4).unwrap(),
                length.to_le_bytes()
            );
        }
        assert_eq!(ram.read(3128, 4).unwrap(), [25, 0, 80, 0]);
        device.console_input(&ram, &mut input).unwrap();
        assert!(input.is_empty());
        assert_eq!(ram.read(2048, 6).unwrap(), b"uname\n");
        assert_eq!(ram.u16(258).unwrap(), 1);
        assert_eq!(ram.read(264, 4).unwrap(), 6u32.to_le_bytes());
        assert_eq!(device.interrupt, 1);
        device
            .model
            .receive_control(control_packet(PORT_OPEN, 0))
            .unwrap();
        input.push_back(b'x');
        device.console_input(&ram, &mut input).unwrap();
        assert_eq!(input.len(), 1);
    }
    #[test]
    fn queue_wrap_and_interrupt_suppression() {
        let (ram, mut queue) = ring();
        queue.next_available = u16::MAX;
        queue.next_used = u16::MAX;
        descriptor(&ram, &queue, 0, 1024, 16, 0, 0);
        ram.write(128, &1u16.to_le_bytes()).unwrap();
        ram.write(130, &0u16.to_le_bytes()).unwrap();
        let chain = queue.pop(&ram).unwrap().unwrap();
        assert_eq!(queue.next_available, 0);
        assert!(!queue.complete(&ram, chain.head, 0).unwrap());
        assert_eq!(ram.u16(258).unwrap(), 0);
    }
}
