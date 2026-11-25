//! Virtio 1.2 socket device (`VIRTIO_ID_VSOCK = 19`, §5.10).

use std::collections::VecDeque;

use helios_api::hv::{GuestMemory, IoWidth};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout,
    little_endian::{U16, U32, U64},
};

use super::{Queue, VERSION_1, VirtioMmio, VirtioModel, read_config_bytes};
use crate::boot::VirtioSlot;
use crate::error::{Error, Result};

/// Host context ID fixed by Virtio 1.2 §5.10.4.
pub const VSOCK_HOST_CID: u64 = 2;
/// Minimum legal guest context ID (0 = hypervisor, 1 = reserved, 2 = host).
pub const VSOCK_MIN_GUEST_CID: u64 = 3;

pub const VIRTIO_VSOCK_TYPE_STREAM: u16 = 1;
pub const VIRTIO_VSOCK_OP_REQUEST: u16 = 1;
pub const VIRTIO_VSOCK_OP_RESPONSE: u16 = 2;
pub const VIRTIO_VSOCK_OP_RST: u16 = 3;
pub const VIRTIO_VSOCK_OP_SHUTDOWN: u16 = 4;
pub const VIRTIO_VSOCK_OP_RW: u16 = 5;
pub const VIRTIO_VSOCK_OP_CREDIT_UPDATE: u16 = 6;
pub const VIRTIO_VSOCK_OP_CREDIT_REQUEST: u16 = 7;

/// Virtio 1.2 vsock packet header (`struct virtio_vsock_hdr`, 44 bytes, zero padding).
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct VirtioVsockHdr {
    pub src_cid: U64,
    pub dst_cid: U64,
    pub src_port: U32,
    pub dst_port: U32,
    pub len: U32,
    pub kind: U16,
    pub op: U16,
    pub flags: U32,
    pub buf_alloc: U32,
    pub fwd_cnt: U32,
}

pub const VSOCK_HDR_LEN: usize = core::mem::size_of::<VirtioVsockHdr>();
const _: () = assert!(VSOCK_HDR_LEN == 44);

/// One framed vsock packet (header + payload).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VsockPacket {
    pub header: VirtioVsockHdr,
    pub payload: Vec<u8>,
}

/// Zero-`dyn` vsock transport backend.
pub trait VsockBackend {
    fn on_guest_tx(&mut self, packet: VsockPacket) -> Result<()>;
    fn try_recv_rx(&mut self) -> Option<VsockPacket>;
}

/// Queue-backed vsock backend that rejects unaccepted stream requests cleanly
/// with `VIRTIO_VSOCK_OP_RST` unless a host handler enqueues responses.
#[derive(Default)]
pub struct ChannelVsockBackend {
    pub tx_packets: VecDeque<VsockPacket>,
    pub rx_packets: VecDeque<VsockPacket>,
    pub auto_reset_requests: bool,
}

impl ChannelVsockBackend {
    pub fn rejecting_unknown_ports() -> Self {
        Self {
            tx_packets: VecDeque::new(),
            rx_packets: VecDeque::new(),
            auto_reset_requests: true,
        }
    }
}

impl VsockBackend for ChannelVsockBackend {
    fn on_guest_tx(&mut self, packet: VsockPacket) -> Result<()> {
        if self.auto_reset_requests && packet.header.op.get() == VIRTIO_VSOCK_OP_REQUEST {
            let rst = VirtioVsockHdr {
                src_cid: packet.header.dst_cid,
                dst_cid: packet.header.src_cid,
                src_port: packet.header.dst_port,
                dst_port: packet.header.src_port,
                len: U32::new(0),
                kind: U16::new(VIRTIO_VSOCK_TYPE_STREAM),
                op: U16::new(VIRTIO_VSOCK_OP_RST),
                flags: U32::new(0),
                buf_alloc: U32::new(0),
                fwd_cnt: U32::new(0),
            };
            self.rx_packets.push_back(VsockPacket {
                header: rst,
                payload: Vec::new(),
            });
        } else {
            self.tx_packets.push_back(packet);
        }
        Ok(())
    }

    fn try_recv_rx(&mut self) -> Option<VsockPacket> {
        self.rx_packets.pop_front()
    }
}

/// Virtio 1.2 vsock device configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioVsockConfig {
    pub guest_cid: u64,
}

impl VirtioVsockConfig {
    pub fn new(guest_cid: u64) -> Result<Self> {
        if guest_cid < VSOCK_MIN_GUEST_CID {
            return Err(Error::Config("virtio-vsock guest CID must be >= 3"));
        }
        Ok(Self { guest_cid })
    }
}

/// Virtio vsock device model (queue 0 = rx, queue 1 = tx, queue 2 = event).
pub struct VsockModel {
    queues: [Queue; 3],
    config: VirtioVsockConfig,
}

impl VsockModel {
    pub fn new(config: VirtioVsockConfig) -> Self {
        Self {
            queues: core::array::from_fn(|_| Queue::default()),
            config,
        }
    }

    pub const fn guest_cid(&self) -> u64 {
        self.config.guest_cid
    }
}

impl VirtioModel for VsockModel {
    const ID: u32 = 19;
    const FEATURES: u64 = VERSION_1;
    const REQUIRED: u64 = VERSION_1;

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn configuration(&self, offset: u64, width: IoWidth) -> u64 {
        let bytes = self.config.guest_cid.to_le_bytes();
        read_config_bytes(&bytes, offset, width)
    }

    fn reset(&mut self) {
        for queue in &mut self.queues {
            queue.reset();
        }
    }
}

pub type VirtioVsock = VirtioMmio<VsockModel>;

impl VirtioVsock {
    pub fn vsock(slot: VirtioSlot, config: VirtioVsockConfig) -> Self {
        Self::new(slot, VsockModel::new(config))
    }

    pub fn process_tx(
        &mut self,
        memory: &impl GuestMemory,
        backend: &mut impl VsockBackend,
    ) -> Result<()> {
        if !self.driver_ok() {
            return Ok(());
        }
        while let Some(chain) = self.model.queues[1].pop(memory)? {
            let mut raw = Vec::new();
            for desc in &chain.descriptors {
                if desc.writable {
                    return Err(Error::Virtio("writable descriptor in vsock tx chain"));
                }
                let chunk = memory.read_bytes(desc.address, desc.length as usize)?;
                raw.extend_from_slice(&chunk);
            }
            if raw.len() < VSOCK_HDR_LEN {
                return Err(Error::Virtio("short virtio-vsock tx header"));
            }
            let header = VirtioVsockHdr::read_from_bytes(&raw[..VSOCK_HDR_LEN])
                .map_err(|_| Error::Virtio("invalid virtio-vsock header"))?;
            let declared_len = header.len.get() as usize;
            if raw.len() < VSOCK_HDR_LEN + declared_len {
                return Err(Error::Virtio("truncated virtio-vsock tx payload"));
            }
            let payload = raw[VSOCK_HDR_LEN..VSOCK_HDR_LEN + declared_len].to_vec();
            backend.on_guest_tx(VsockPacket { header, payload })?;
            if self.model.queues[1].complete(memory, chain.head, 0)? {
                self.interrupt |= 1;
            }
        }
        Ok(())
    }

    pub fn process_rx(
        &mut self,
        memory: &impl GuestMemory,
        backend: &mut impl VsockBackend,
    ) -> Result<()> {
        if !self.driver_ok() {
            return Ok(());
        }
        while let Some(packet) = backend.try_recv_rx() {
            let Some(chain) = self.model.queues[0].pop(memory)? else {
                break;
            };
            let mut bytes = Vec::with_capacity(VSOCK_HDR_LEN + packet.payload.len());
            bytes.extend_from_slice(packet.header.as_bytes());
            bytes.extend_from_slice(&packet.payload);

            let mut offset = 0usize;
            for desc in &chain.descriptors {
                if !desc.writable {
                    return Err(Error::Virtio("read-only descriptor in vsock rx chain"));
                }
                let take = (desc.length as usize).min(bytes.len() - offset);
                if take > 0 {
                    memory.write_slice(desc.address, &bytes[offset..offset + take])?;
                    offset += take;
                }
                if offset == bytes.len() {
                    break;
                }
            }
            if offset != bytes.len() {
                return Err(Error::Virtio("virtio-vsock rx buffer shorter than packet"));
            }
            if self.model.queues[0].complete(memory, chain.head, bytes.len() as u32)? {
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
    fn vsock_exposes_cid_and_replies_with_rst_for_unhandled_port() {
        let ram = test_ram(8192);
        let cfg = VirtioVsockConfig::new(42).unwrap();
        let mut vsock = VirtioVsock::vsock(VirtioSlot::at(3).unwrap(), cfg);
        vsock.status = DRIVER_OK;
        vsock.model.queues[0] = enable_queue(&ram, 0, 4);
        vsock.model.queues[1] = enable_queue(&ram, 512, 4);

        assert_eq!(vsock.model.configuration(0x100, IoWidth::Qword), 42);
        assert!(VirtioVsockConfig::new(2).is_err());

        let mut backend = ChannelVsockBackend::rejecting_unknown_ports();
        let req = VirtioVsockHdr {
            src_cid: U64::new(42),
            dst_cid: U64::new(VSOCK_HOST_CID),
            src_port: U32::new(1024),
            dst_port: U32::new(9999),
            len: U32::new(0),
            kind: U16::new(VIRTIO_VSOCK_TYPE_STREAM),
            op: U16::new(VIRTIO_VSOCK_OP_REQUEST),
            flags: U32::new(0),
            buf_alloc: U32::new(65536),
            fwd_cnt: U32::new(0),
        };
        ram.write_pod(GuestPhysAddr::new(2048), &req).unwrap();
        write_desc(
            &ram,
            &vsock.model.queues[1],
            0,
            2048,
            VSOCK_HDR_LEN as u32,
            0,
            0,
        );
        push_avail(&ram, &vsock.model.queues[1], 0, 0);
        vsock.process_tx(&ram, &mut backend).unwrap();

        write_desc(&ram, &vsock.model.queues[0], 0, 3072, 128, 2, 0);
        push_avail(&ram, &vsock.model.queues[0], 0, 0);
        vsock.process_rx(&ram, &mut backend).unwrap();
        assert_eq!(
            used_len(&ram, &vsock.model.queues[0], 0) as usize,
            VSOCK_HDR_LEN
        );
        let reply: VirtioVsockHdr = ram.read_pod(GuestPhysAddr::new(3072)).unwrap();
        assert_eq!(reply.op.get(), VIRTIO_VSOCK_OP_RST);
        assert_eq!(reply.src_cid.get(), VSOCK_HOST_CID);
        assert_eq!(reply.dst_cid.get(), 42);
    }
}
