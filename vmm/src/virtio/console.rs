//! Virtio 1.2 multiport console device (`VIRTIO_ID_CONSOLE = 3`).

use core::future::Future;
use std::collections::VecDeque;

use helios_api::hv::{GuestMemory, IoWidth, TRANSFER_CHUNK_BYTES};

use super::{Queue, VERSION_1, VirtioMmio, VirtioModel, read_config_bytes};
use crate::boot::VirtioSlot;
use crate::error::{Error, Result};

const CONSOLE_SIZE: u64 = 1;
const CONSOLE_MULTIPORT: u64 = 1 << 1;

// Virtio 1.2 console control events, section 5.3.6.2.
const DEVICE_READY: u16 = 0;
const PORT_ADD: u16 = 1;
const PORT_READY: u16 = 3;
const CONSOLE_PORT: u16 = 4;
const RESIZE: u16 = 5;
const PORT_OPEN: u16 = 6;

/// Zero-`dyn` async output sink for console writes.
pub trait ConsoleSink {
    fn write_all(&mut self, bytes: Vec<u8>) -> impl Future<Output = Result<()>> + '_;
}

/// Production sink writing directly to WASI stdout.
#[derive(Default)]
pub struct StdoutConsoleSink;

impl ConsoleSink for StdoutConsoleSink {
    async fn write_all(&mut self, bytes: Vec<u8>) -> Result<()> {
        helios_api::io::stdout().write_all(bytes).await?;
        Ok(())
    }
}

/// Virtio multiport console model with 4 split queues (rx, tx, ctrl-rx, ctrl-tx).
pub struct ConsoleModel {
    queues: [Queue; 4],
    cols: u16,
    rows: u16,
    device_ready: bool,
    port_ready: bool,
    guest_open: bool,
    // One pending response per handshake event; repeats coalesce.
    pending: u8,
}

impl ConsoleModel {
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            queues: core::array::from_fn(|_| Queue::default()),
            cols,
            rows,
            device_ready: false,
            port_ready: false,
            guest_open: false,
            pending: 0,
        }
    }

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
            _ => return Err(Error::Virtio("invalid console control transition")),
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
            bytes[8..10].copy_from_slice(&self.rows.to_le_bytes());
            bytes[10..12].copy_from_slice(&self.cols.to_le_bytes());
            12
        } else {
            8
        };
        (bytes, length, 1 << index)
    }
}

impl VirtioModel for ConsoleModel {
    const ID: u32 = 3;
    const FEATURES: u64 = VERSION_1 | CONSOLE_SIZE | CONSOLE_MULTIPORT;
    const REQUIRED: u64 = VERSION_1 | CONSOLE_MULTIPORT;

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn configuration(&self, offset: u64, width: IoWidth) -> u64 {
        let mut config = [0u8; 8];
        config[0..2].copy_from_slice(&self.cols.to_le_bytes());
        config[2..4].copy_from_slice(&self.rows.to_le_bytes());
        config[4..8].copy_from_slice(&1u32.to_le_bytes()); // max_nr_ports = 1
        read_config_bytes(&config, offset, width)
    }

    fn reset(&mut self) {
        for queue in &mut self.queues {
            queue.reset();
        }
        self.device_ready = false;
        self.port_ready = false;
        self.guest_open = false;
        self.pending = 0;
    }
}

pub type VirtioConsole = VirtioMmio<ConsoleModel>;

impl VirtioConsole {
    pub fn console(slot: VirtioSlot, cols: u16, rows: u16) -> Self {
        Self::new(slot, ConsoleModel::new(cols, rows))
    }

    pub fn process_control(&mut self, memory: &impl GuestMemory) -> Result<()> {
        if !self.driver_ok() {
            return Ok(());
        }
        while let Some(chain) = self.model.queues[3].pop(memory)? {
            let mut packet = [0; 8];
            let mut copied = 0usize;
            for descriptor in chain.descriptors {
                let desc_len = usize::try_from(descriptor.length)
                    .map_err(|_| Error::Virtio("console control request direction or length"))?;
                let end = copied
                    .checked_add(desc_len)
                    .ok_or(Error::Virtio("console control request direction or length"))?;
                if descriptor.writable || end > packet.len() {
                    return Err(Error::Virtio("console control request direction or length"));
                }
                memory.read_slice(descriptor.address, &mut packet[copied..end])?;
                copied = end;
            }
            if copied != packet.len() {
                return Err(Error::Virtio("short console control request"));
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
                    return Err(Error::Virtio("read-only console control response"));
                }
                let count = (descriptor.length as usize).min(length - copied);
                memory.write_slice(descriptor.address, &bytes[copied..copied + count])?;
                copied += count;
                if copied == length {
                    break;
                }
            }
            if copied != length {
                return Err(Error::Virtio("short console control response buffer"));
            }
            if self.model.queues[2].complete(memory, chain.head, length as u32)? {
                self.interrupt |= 1;
            }
            self.model.pending &= !bit;
        }
        Ok(())
    }

    pub async fn process_output(
        &mut self,
        memory: &impl GuestMemory,
        sink: &mut impl ConsoleSink,
    ) -> Result<()> {
        if !self.driver_ok() {
            return Ok(());
        }
        while let Some(chain) = self.model.queues[1].pop(memory)? {
            for descriptor in chain.descriptors {
                if descriptor.writable {
                    return Err(Error::Virtio("writable console output"));
                }
                let mut offset = 0u32;
                while offset < descriptor.length {
                    let count = (descriptor.length - offset).min(TRANSFER_CHUNK_BYTES as u32);
                    let addr = descriptor
                        .address
                        .checked_add(u64::from(offset))
                        .ok_or(Error::Virtio("console descriptor address overflow"))?;
                    let bytes = memory.read_bytes(addr, count as usize)?;
                    sink.write_all(bytes).await?;
                    offset += count;
                }
            }
            if self.model.queues[1].complete(memory, chain.head, 0)? {
                self.interrupt |= 1;
            }
        }
        Ok(())
    }

    pub fn process_input(
        &mut self,
        memory: &impl GuestMemory,
        input: &mut VecDeque<u8>,
    ) -> Result<()> {
        if !self.driver_ok() || !self.model.guest_open {
            return Ok(());
        }
        while !input.is_empty() {
            let Some(chain) = self.model.queues[0].pop(memory)? else {
                break;
            };
            let mut length = 0u32;
            for descriptor in chain.descriptors {
                if !descriptor.writable {
                    return Err(Error::Virtio("read-only console input"));
                }
                let count = (descriptor.length as usize)
                    .min(input.len())
                    .min(TRANSFER_CHUNK_BYTES);
                let bytes: Vec<u8> = input.drain(..count).collect();
                memory.write_slice(descriptor.address, &bytes)?;
                length = length
                    .checked_add(count as u32)
                    .ok_or(Error::Virtio("console input used length overflow"))?;
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

#[cfg(test)]
mod tests {
    use super::super::DRIVER_OK;
    use super::super::test_support::*;
    use super::*;
    use helios_api::hv::GuestPhysAddr;

    fn control_packet(event: u16, value: u16) -> [u8; 8] {
        let mut bytes = [0; 8];
        bytes[4..6].copy_from_slice(&event.to_le_bytes());
        bytes[6..8].copy_from_slice(&value.to_le_bytes());
        bytes
    }

    #[test]
    fn console_buffers_input_until_multiport_handshake_opens_port() {
        let ram = test_ram(4096);
        let mut device = VirtioConsole::console(VirtioSlot::at(0).unwrap(), 80, 25);
        device.status = DRIVER_OK;
        device.model.queues[0] = enable_queue(&ram, 0, 4);
        device.model.queues[2] = enable_queue(&ram, 512, 4);
        device.model.queues[3] = enable_queue(&ram, 1024, 4);

        write_desc(&ram, &device.model.queues[0], 0, 2048, 16, 2, 0);
        push_avail(&ram, &device.model.queues[0], 0, 0);
        for index in 0..4u16 {
            write_desc(
                &ram,
                &device.model.queues[2],
                index,
                3072 + u64::from(index) * 16,
                16,
                2,
                0,
            );
            push_avail(&ram, &device.model.queues[2], index, index);
        }

        let mut input = VecDeque::from(Vec::from(b"uname\n"));
        for (index, event) in [DEVICE_READY, PORT_READY, PORT_OPEN]
            .into_iter()
            .enumerate()
        {
            device.process_input(&ram, &mut input).unwrap();
            assert_eq!(input.len(), 6);
            assert_eq!(used_idx(&ram, &device.model.queues[0]), 0);
            let address = 2304 + index as u64 * 16;
            ram.write_slice(GuestPhysAddr::new(address), &control_packet(event, 1))
                .unwrap();
            write_desc(
                &ram,
                &device.model.queues[3],
                index as u16,
                address,
                8,
                0,
                0,
            );
            push_avail(&ram, &device.model.queues[3], index as u16, index as u16);
            device.process_control(&ram).unwrap();
            assert_eq!(used_idx(&ram, &device.model.queues[3]), index as u16 + 1);
            assert_eq!(
                used_idx(&ram, &device.model.queues[2]),
                if index == 0 { 1 } else { 4 }
            );
        }

        for (index, event) in [PORT_ADD, CONSOLE_PORT, PORT_OPEN, RESIZE]
            .into_iter()
            .enumerate()
        {
            let address = GuestPhysAddr::new(3072 + index as u64 * 16);
            assert_eq!(
                ram.read_bytes(address, 8).unwrap(),
                control_packet(event, 1)
            );
            let expected = if event == RESIZE { 12 } else { 8 };
            assert_eq!(
                used_len(&ram, &device.model.queues[2], index as u16),
                expected
            );
        }
        assert_eq!(
            ram.read_bytes(GuestPhysAddr::new(3128), 4).unwrap(),
            [25, 0, 80, 0]
        );
        device.process_input(&ram, &mut input).unwrap();
        assert!(input.is_empty());
        assert_eq!(
            ram.read_bytes(GuestPhysAddr::new(2048), 6).unwrap(),
            b"uname\n"
        );
        assert_eq!(used_idx(&ram, &device.model.queues[0]), 1);
        assert_eq!(used_len(&ram, &device.model.queues[0], 0), 6);
        assert_eq!(device.interrupt, 1);

        device
            .model
            .receive_control(control_packet(PORT_OPEN, 0))
            .unwrap();
        input.push_back(b'x');
        device.process_input(&ram, &mut input).unwrap();
        assert_eq!(input.len(), 1);
    }

    #[test]
    fn console_control_rejects_oversized_multi_descriptor_chain() {
        let ram = test_ram(4096);
        let mut device = VirtioConsole::console(VirtioSlot::at(0).unwrap(), 80, 25);
        device.status = DRIVER_OK;
        device.model.queues[3] = enable_queue(&ram, 0, 4);
        write_desc(&ram, &device.model.queues[3], 0, 1024, 4, 1, 1);
        write_desc(&ram, &device.model.queues[3], 1, 1028, 8, 0, 0);
        push_avail(&ram, &device.model.queues[3], 0, 0);
        assert!(matches!(
            device.process_control(&ram),
            Err(Error::Virtio(_))
        ));
    }
}
