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
const DRIVER_OK: u32 = 4;
const FEATURES_OK: u32 = 8;

#[derive(Default)]
struct Queue {
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

pub struct Device {
    id: u32,
    features: u64,
    feature_select: u32,
    driver_select: u32,
    driver_features: u64,
    queue_select: u32,
    queues: [Queue; 2],
    status: u32,
    pub interrupt: u32,
}

impl Device {
    pub fn console() -> Self {
        Self::new(3, VERSION_1 | 1)
    }
    pub fn block() -> Self {
        Self::new(2, VERSION_1)
    }
    fn new(id: u32, features: u64) -> Self {
        Self {
            id,
            features,
            feature_select: 0,
            driver_select: 0,
            driver_features: 0,
            queue_select: 0,
            queues: Default::default(),
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
        let queue_count = if self.id == 3 { 2 } else { 1 };
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
                        .queues
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
                        *self = Self::new(self.id, self.features);
                    } else {
                        self.status = value;
                        if value & FEATURES_OK != 0
                            && (self.driver_features & !self.features != 0
                                || self.driver_features & VERSION_1 == 0)
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
            .queues
            .get(self.queue_select as usize)
            .filter(|_| self.queue_select < queue_count);
        Ok(match offset {
            0x000 => 0x7472_6976,
            0x004 => 2,
            0x008 => u64::from(self.id),
            0x00c => 0x4845_4c49,
            0x010 => {
                if self.feature_select < 2 {
                    (self.features >> (self.feature_select * 32)) & u64::from(u32::MAX)
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
            0x100..=0x107 if self.id == 2 => {
                let shift = (offset - 0x100) * 8;
                let mask = match width {
                    IoWidth::Byte => 0xff,
                    IoWidth::Word => 0xffff,
                    IoWidth::Dword => 0xffff_ffff,
                    IoWidth::Qword => u64::MAX,
                };
                (capacity >> shift) & mask
            }
            0x100 if self.id == 3 => 80 | (25 << 16),
            0x102 if self.id == 3 => 25,
            _ => 0,
        })
    }

    pub async fn console_output(&mut self, memory: &impl GuestMemory) -> Result<()> {
        if self.status & DRIVER_OK == 0 {
            return Ok(());
        }
        while let Some(chain) = self.queues[1].pop(memory)? {
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
            if self.queues[1].complete(memory, chain.head, 0)? {
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
        if self.status & DRIVER_OK == 0 {
            return Ok(());
        }
        while !input.is_empty() {
            let Some(chain) = self.queues[0].pop(memory)? else {
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
            if self.queues[0].complete(memory, chain.head, length)? {
                self.interrupt |= 1;
            }
        }
        Ok(())
    }

    pub async fn block_requests(&mut self, memory: &impl GuestMemory, file: &File) -> Result<()> {
        if self.status & DRIVER_OK == 0 {
            return Ok(());
        }
        while let Some(chain) = self.queues[0].pop(memory)? {
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
            if self.queues[0].complete(memory, chain.head, written)? {
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
    fn descriptor(ram: &Ram, index: u16, address: u64, length: u32, flags: u16, next: u16) {
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&address.to_le_bytes());
        bytes[8..12].copy_from_slice(&length.to_le_bytes());
        bytes[12..14].copy_from_slice(&flags.to_le_bytes());
        bytes[14..].copy_from_slice(&next.to_le_bytes());
        ram.write(u64::from(index) * 16, &bytes).unwrap();
    }
    #[test]
    fn rejects_cyclic_and_out_of_ram_chains() {
        let (ram, mut queue) = ring();
        ram.write(130, &1u16.to_le_bytes()).unwrap();
        descriptor(&ram, 0, 1024, 16, 1, 0);
        assert!(matches!(queue.pop(&ram), Err(Error::Queue(_))));
        descriptor(&ram, 0, 4090, 16, 0, 0);
        assert!(matches!(queue.pop(&ram), Err(Error::Memory(_, _))));
        assert_eq!(queue.next_available, 0);
    }
    #[test]
    fn rejects_available_index_overrun() {
        let (ram, mut queue) = ring();
        ram.write(130, &5u16.to_le_bytes()).unwrap();
        assert!(matches!(queue.pop(&ram), Err(Error::Queue(_))));
    }
    #[test]
    fn console_input_writes_payload_then_used_ring() {
        let (ram, queue) = ring();
        let mut device = Device::console();
        device.status = DRIVER_OK;
        device.queues[0] = queue;
        descriptor(&ram, 0, 1024, 16, 2, 0);
        ram.write(130, &1u16.to_le_bytes()).unwrap();
        let mut input = VecDeque::from(Vec::from(b"uname\n"));
        device.console_input(&ram, &mut input).unwrap();
        assert!(input.is_empty());
        assert_eq!(ram.read(1024, 6).unwrap(), b"uname\n");
        assert_eq!(ram.u16(258).unwrap(), 1);
        assert_eq!(ram.read(264, 4).unwrap(), 6u32.to_le_bytes());
        assert_eq!(device.interrupt, 1);
    }
    #[test]
    fn queue_wrap_and_interrupt_suppression() {
        let (ram, mut queue) = ring();
        queue.next_available = u16::MAX;
        queue.next_used = u16::MAX;
        descriptor(&ram, 0, 1024, 16, 0, 0);
        ram.write(128, &1u16.to_le_bytes()).unwrap();
        ram.write(130, &0u16.to_le_bytes()).unwrap();
        let chain = queue.pop(&ram).unwrap().unwrap();
        assert_eq!(queue.next_available, 0);
        assert!(!queue.complete(&ram, chain.head, 0).unwrap());
        assert_eq!(ram.u16(258).unwrap(), 0);
    }
}
