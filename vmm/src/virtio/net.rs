//! Virtio 1.2 network device (`VIRTIO_ID_NET = 1`, §5.1).

use std::collections::VecDeque;

use helios_api::hv::{GuestMemory, IoWidth};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use super::{Queue, VERSION_1, VirtioMmio, VirtioModel, read_config_bytes};
use crate::boot::VirtioSlot;
use crate::error::{Error, Result};

const VIRTIO_NET_F_MTU: u64 = 1 << 3;
const VIRTIO_NET_F_MAC: u64 = 1 << 5;
const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
const VIRTIO_NET_S_LINK_UP: u16 = 1;

/// Virtio 1.2 network packet header (`struct virtio_net_hdr_v1`, 12 bytes).
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

const NET_HDR_LEN: usize = core::mem::size_of::<VirtioNetHdr>();

/// Maximum total byte length of one guest TX descriptor chain (`virtio_net_hdr_v1`
/// plus a 64 KiB Ethernet/IP frame), preventing unbounded VMM allocation.
pub const MAX_NET_TX_BYTES: usize = NET_HDR_LEN + 65_536;

/// Zero-`dyn` Ethernet frame transport attached to [`VirtioNet`].
pub trait NetBackend {
    fn try_recv_frame(&mut self) -> Option<Vec<u8>>;
    fn send_frame(&mut self, frame: Vec<u8>) -> Result<()>;
}

/// Queue-backed network backend for host tests or channel-bridged networking.
#[derive(Default)]
pub struct ChannelNetBackend {
    pub rx: VecDeque<Vec<u8>>,
    pub tx: VecDeque<Vec<u8>>,
}

impl NetBackend for ChannelNetBackend {
    fn try_recv_frame(&mut self) -> Option<Vec<u8>> {
        self.rx.pop_front()
    }

    fn send_frame(&mut self, frame: Vec<u8>) -> Result<()> {
        self.tx.push_back(frame);
        Ok(())
    }
}

/// Virtio 1.2 network device configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioNetConfig {
    pub mac: [u8; 6],
    pub mtu: u16,
}

impl Default for VirtioNetConfig {
    fn default() -> Self {
        Self {
            // Locally administered unicast MAC (02:48:45:4c:00:01 -> "HEL").
            mac: [0x02, 0x48, 0x45, 0x4c, 0x00, 0x01],
            mtu: 1500,
        }
    }
}

/// Virtio network device model (queue 0 = receiveq, queue 1 = transmitq).
pub struct NetModel {
    queues: [Queue; 2],
    config: VirtioNetConfig,
    link_up: bool,
    pending_rx: Option<Vec<u8>>,
}

impl NetModel {
    pub fn new(config: VirtioNetConfig) -> Self {
        Self {
            queues: [Queue::default(), Queue::default()],
            config,
            link_up: true,
            pending_rx: None,
        }
    }

    pub const fn config(&self) -> VirtioNetConfig {
        self.config
    }
}

impl VirtioModel for NetModel {
    const ID: u32 = 1;
    const FEATURES: u64 = VERSION_1 | VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS | VIRTIO_NET_F_MTU;
    const REQUIRED: u64 = VERSION_1;

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn configuration(&self, offset: u64, width: IoWidth) -> u64 {
        // struct virtio_net_config: mac[6], status(u16), max_virtqueue_pairs(u16), mtu(u16)
        let mut bytes = [0u8; 12];
        bytes[0..6].copy_from_slice(&self.config.mac);
        let status = if self.link_up {
            VIRTIO_NET_S_LINK_UP
        } else {
            0
        };
        bytes[6..8].copy_from_slice(&status.to_le_bytes());
        bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
        bytes[10..12].copy_from_slice(&self.config.mtu.to_le_bytes());
        read_config_bytes(&bytes, offset, width)
    }

    fn reset(&mut self) {
        for queue in &mut self.queues {
            queue.reset();
        }
        self.pending_rx = None;
    }
}

pub type VirtioNet = VirtioMmio<NetModel>;

impl VirtioNet {
    pub fn net(slot: VirtioSlot, config: VirtioNetConfig) -> Self {
        Self::new(slot, NetModel::new(config))
    }

    /// Drains guest TX frames from queue 1 and hands Ethernet payloads to `backend`.
    pub fn process_tx(
        &mut self,
        memory: &impl GuestMemory,
        backend: &mut impl NetBackend,
    ) -> Result<()> {
        if !self.driver_ok() {
            return Ok(());
        }
        while let Some(chain) = self.model.queues[1].pop(memory)? {
            let mut total_len = 0usize;
            for desc in &chain.descriptors {
                if desc.writable {
                    return Err(Error::Virtio("writable descriptor in net tx chain"));
                }
                let desc_len = usize::try_from(desc.length)
                    .map_err(|_| Error::Virtio("net tx descriptor length overflow"))?;
                total_len = total_len
                    .checked_add(desc_len)
                    .filter(|&n| n <= MAX_NET_TX_BYTES)
                    .ok_or(Error::Virtio("net tx frame exceeds maximum length"))?;
            }
            let mut packet = Vec::with_capacity(total_len);
            for desc in &chain.descriptors {
                let chunk = memory.read_bytes(desc.address, desc.length as usize)?;
                packet.extend_from_slice(&chunk);
            }
            if packet.len() < NET_HDR_LEN {
                return Err(Error::Virtio("short virtio-net tx header"));
            }
            let frame = packet.split_off(NET_HDR_LEN);
            backend.send_frame(frame)?;
            if self.model.queues[1].complete(memory, chain.head, 0)? {
                self.interrupt |= 1;
            }
        }
        Ok(())
    }

    /// Delivers pending host RX frames from `backend` into guest RX descriptors (queue 0).
    pub fn process_rx(
        &mut self,
        memory: &impl GuestMemory,
        backend: &mut impl NetBackend,
    ) -> Result<()> {
        if !self.driver_ok() {
            return Ok(());
        }
        loop {
            if !self.model.queues[0].has_available(memory)? {
                break;
            }
            let frame = match self.model.pending_rx.take() {
                Some(frame) => frame,
                None => match backend.try_recv_frame() {
                    Some(frame) => frame,
                    None => break,
                },
            };
            let Some(chain) = self.model.queues[0].pop(memory)? else {
                self.model.pending_rx = Some(frame);
                break;
            };
            let hdr = VirtioNetHdr {
                num_buffers: 1u16.to_le(),
                ..VirtioNetHdr::default()
            };
            let total_len = NET_HDR_LEN
                .checked_add(frame.len())
                .ok_or(Error::Virtio("virtio-net rx frame length overflow"))?;
            let used_len = u32::try_from(total_len)
                .map_err(|_| Error::Virtio("virtio-net rx frame length overflow"))?;
            let mut full = Vec::with_capacity(total_len);
            full.extend_from_slice(hdr.as_bytes());
            full.extend_from_slice(&frame);

            let mut offset = 0usize;
            for desc in &chain.descriptors {
                if !desc.writable {
                    return Err(Error::Virtio("read-only descriptor in net rx chain"));
                }
                let take = (desc.length as usize).min(full.len() - offset);
                if take > 0 {
                    memory.write_slice(desc.address, &full[offset..offset + take])?;
                    offset += take;
                }
                if offset == full.len() {
                    break;
                }
            }
            if offset != full.len() {
                return Err(Error::Virtio("virtio-net rx buffer shorter than frame"));
            }
            if self.model.queues[0].complete(memory, chain.head, used_len)? {
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

    #[test]
    fn net_transfers_tx_and_rx_frames_with_virtio_net_hdr() {
        let ram = test_ram(8192);
        let cfg = VirtioNetConfig::default();
        let mut net = VirtioNet::net(VirtioSlot::at(2).unwrap(), cfg);
        net.status = DRIVER_OK;
        net.model.queues[0] = enable_queue(&ram, 0, 4);
        net.model.queues[1] = enable_queue(&ram, 512, 4);

        // Verify config space MAC & MTU.
        for (i, &byte) in cfg.mac.iter().enumerate() {
            assert_eq!(
                net.model.configuration(0x100 + i as u64, IoWidth::Byte),
                u64::from(byte)
            );
        }
        assert_eq!(net.model.configuration(0x10a, IoWidth::Word), 1500);

        let mut backend = ChannelNetBackend::default();
        // Guest TX frame.
        let mut tx_buf = vec![0u8; NET_HDR_LEN];
        tx_buf.extend_from_slice(b"eth-tx-frame");
        ram.write_slice(GuestPhysAddr::new(2048), &tx_buf).unwrap();
        write_desc(
            &ram,
            &net.model.queues[1],
            0,
            2048,
            tx_buf.len() as u32,
            0,
            0,
        );
        push_avail(&ram, &net.model.queues[1], 0, 0);
        net.process_tx(&ram, &mut backend).unwrap();
        assert_eq!(
            backend.tx.pop_front().as_deref(),
            Some(b"eth-tx-frame".as_slice())
        );

        // Host RX frame -> guest.
        backend.rx.push_back(b"eth-rx-frame".to_vec());
        write_desc(&ram, &net.model.queues[0], 0, 3072, 256, 2, 0);
        push_avail(&ram, &net.model.queues[0], 0, 0);
        net.process_rx(&ram, &mut backend).unwrap();
        let rx_len = used_len(&ram, &net.model.queues[0], 0) as usize;
        assert_eq!(rx_len, NET_HDR_LEN + 12);
        let got = ram.read_bytes(GuestPhysAddr::new(3072), rx_len).unwrap();
        assert_eq!(&got[NET_HDR_LEN..], b"eth-rx-frame");
    }

    #[test]
    fn net_rejects_oversized_tx_chain_and_preserves_rx_when_ring_empty() {
        let ram = test_ram(128 * 1024);
        let mut net = VirtioNet::net(VirtioSlot::at(2).unwrap(), VirtioNetConfig::default());
        net.status = DRIVER_OK;
        net.model.queues[0] = enable_queue(&ram, 0, 4);
        net.model.queues[1] = enable_queue(&ram, 512, 4);
        let mut backend = ChannelNetBackend::default();

        // 1. Oversized TX descriptor chain (> MAX_NET_TX_BYTES) fails cleanly.
        write_desc(
            &ram,
            &net.model.queues[1],
            0,
            4096,
            (MAX_NET_TX_BYTES + 1) as u32,
            0,
            0,
        );
        push_avail(&ram, &net.model.queues[1], 0, 0);
        assert!(matches!(
            net.process_tx(&ram, &mut backend),
            Err(Error::Virtio(_))
        ));
        assert!(backend.tx.is_empty());

        // 2. Host RX frames are preserved while guest RX ring is empty and delivered on refill.
        backend.rx.push_back(b"frame-one".to_vec());
        backend.rx.push_back(b"frame-two".to_vec());
        net.process_rx(&ram, &mut backend).unwrap();
        assert_eq!(used_idx(&ram, &net.model.queues[0]), 0);

        write_desc(&ram, &net.model.queues[0], 0, 2048, 256, 2, 0);
        push_avail(&ram, &net.model.queues[0], 0, 0);
        net.process_rx(&ram, &mut backend).unwrap();
        assert_eq!(used_idx(&ram, &net.model.queues[0]), 1);
        let len1 = used_len(&ram, &net.model.queues[0], 0) as usize;
        let got1 = ram.read_bytes(GuestPhysAddr::new(2048), len1).unwrap();
        assert_eq!(&got1[NET_HDR_LEN..], b"frame-one");

        write_desc(&ram, &net.model.queues[0], 1, 3072, 256, 2, 0);
        push_avail(&ram, &net.model.queues[0], 1, 1);
        net.process_rx(&ram, &mut backend).unwrap();
        assert_eq!(used_idx(&ram, &net.model.queues[0]), 2);
        let len2 = used_len(&ram, &net.model.queues[0], 1) as usize;
        let got2 = ram.read_bytes(GuestPhysAddr::new(3072), len2).unwrap();
        assert_eq!(&got2[NET_HDR_LEN..], b"frame-two");
    }
}
