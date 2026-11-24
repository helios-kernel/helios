//! Virtio 1.2 block device (`VIRTIO_ID_BLOCK = 2`).

use helios_api::hv::{GuestMemory, IoWidth, TRANSFER_CHUNK_BYTES};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use super::{Queue, VERSION_1, VirtioMmio, VirtioModel, read_config_bytes};
use crate::boot::VirtioSlot;
use crate::error::{Error, Result};
use crate::file::BlockBackend;

const VIRTIO_BLK_F_RO: u64 = 1 << 5;
const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct BlkReqHeader {
    kind: u32,
    reserved: u32,
    sector: u64,
}

/// Virtio block model with a single request queue.
pub struct BlockModel {
    queues: [Queue; 1],
    capacity_sectors: u64,
    read_only: bool,
}

impl BlockModel {
    pub fn new(capacity_sectors: u64, read_only: bool) -> Self {
        Self {
            queues: [Queue::default()],
            capacity_sectors,
            read_only,
        }
    }
}

impl VirtioModel for BlockModel {
    const ID: u32 = 2;
    const FEATURES: u64 = VERSION_1 | VIRTIO_BLK_F_RO;
    const REQUIRED: u64 = VERSION_1;

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn configuration(&self, offset: u64, width: IoWidth) -> u64 {
        let config = self.capacity_sectors.to_le_bytes();
        read_config_bytes(&config, offset, width)
    }

    fn reset(&mut self) {
        self.queues[0].reset();
    }
}

pub type VirtioBlock = VirtioMmio<BlockModel>;

impl VirtioBlock {
    pub fn block(slot: VirtioSlot, capacity_sectors: u64, read_only: bool) -> Self {
        Self::new(slot, BlockModel::new(capacity_sectors, read_only))
    }

    pub async fn process_requests(
        &mut self,
        memory: &impl GuestMemory,
        backend: &impl BlockBackend,
    ) -> Result<()> {
        if !self.driver_ok() {
            return Ok(());
        }
        while let Some(chain) = self.model.queues[0].pop(memory)? {
            let descriptors = &chain.descriptors;
            if descriptors.len() < 2 {
                return Err(Error::Virtio("block header/status descriptors"));
            }
            let header = &descriptors[0];
            let status = descriptors.last().unwrap();
            if header.writable || header.length != 16 || !status.writable || status.length == 0 {
                return Err(Error::Virtio("block header/status direction or length"));
            }
            let req: BlkReqHeader = memory.read_pod(header.address)?;
            let kind = u32::from_le(req.kind);
            let sector = u64::from_le(req.sector);
            let payload = &descriptors[1..descriptors.len() - 1];
            let mut written = 1u32;
            let result = if kind == VIRTIO_BLK_T_IN || kind == VIRTIO_BLK_T_OUT {
                if kind == VIRTIO_BLK_T_OUT && self.model.read_only {
                    VIRTIO_BLK_S_IOERR
                } else {
                    let mut position = sector
                        .checked_mul(512)
                        .ok_or(Error::Virtio("sector overflow"))?;
                    let total: u64 = payload.iter().map(|item| u64::from(item.length)).sum();
                    if payload
                        .iter()
                        .any(|item| item.writable != (kind == VIRTIO_BLK_T_IN))
                    {
                        return Err(Error::Virtio("block payload direction"));
                    }
                    if total % 512 != 0
                        || position
                            .checked_add(total)
                            .is_none_or(|end| end > backend.size())
                    {
                        VIRTIO_BLK_S_IOERR
                    } else {
                        for descriptor in payload {
                            let mut offset = 0u32;
                            while offset < descriptor.length {
                                let count =
                                    (descriptor.length - offset).min(TRANSFER_CHUNK_BYTES as u32);
                                let addr = descriptor
                                    .address
                                    .checked_add(u64::from(offset))
                                    .ok_or(Error::Virtio("block descriptor address overflow"))?;
                                if kind == VIRTIO_BLK_T_IN {
                                    let bytes = backend.read(position, count as usize).await?;
                                    memory.write_slice(addr, &bytes)?;
                                    written = written
                                        .checked_add(count)
                                        .ok_or(Error::Virtio("used length overflow"))?;
                                } else {
                                    let bytes = memory.read_bytes(addr, count as usize)?;
                                    backend.write(position, bytes).await?;
                                }
                                position += u64::from(count);
                                offset += count;
                            }
                        }
                        VIRTIO_BLK_S_OK
                    }
                }
            } else {
                VIRTIO_BLK_S_UNSUPP
            };
            memory.write_u8(status.address, result)?;
            if self.model.queues[0].complete(memory, chain.head, written)? {
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
    use std::cell::RefCell;

    struct VecBlock(RefCell<Vec<u8>>);
    impl BlockBackend for VecBlock {
        fn size(&self) -> u64 {
            self.0.borrow().len() as u64
        }
        async fn read(&self, offset: u64, length: usize) -> Result<Vec<u8>> {
            let start = offset as usize;
            Ok(self.0.borrow()[start..start + length].to_vec())
        }
        async fn write(&self, offset: u64, bytes: Vec<u8>) -> Result<()> {
            let start = offset as usize;
            self.0.borrow_mut()[start..start + bytes.len()].copy_from_slice(&bytes);
            Ok(())
        }
    }

    #[test]
    fn block_handles_write_read_and_read_only_rejection() {
        let ram = test_ram(8192);
        let backend = VecBlock(RefCell::new(vec![0u8; 4096]));
        let mut blk = VirtioBlock::block(VirtioSlot::at(1).unwrap(), 8, false);
        blk.status = DRIVER_OK;
        blk.model.queues[0] = enable_queue(&ram, 0, 8);

        // Write 512 bytes to sector 1.
        let hdr = BlkReqHeader {
            kind: VIRTIO_BLK_T_OUT.to_le(),
            reserved: 0,
            sector: 1u64.to_le(),
        };
        ram.write_pod(GuestPhysAddr::new(1024), &hdr).unwrap();
        let mut payload = vec![0u8; 512];
        payload[..12].copy_from_slice(b"helios-block");
        ram.write_slice(GuestPhysAddr::new(2048), &payload).unwrap();
        write_desc(&ram, &blk.model.queues[0], 0, 1024, 16, 1, 1);
        write_desc(&ram, &blk.model.queues[0], 1, 2048, 512, 1, 2);
        write_desc(&ram, &blk.model.queues[0], 2, 3072, 1, 2, 0);
        push_avail(&ram, &blk.model.queues[0], 0, 0);
        futures_lite::future::block_on(blk.process_requests(&ram, &backend)).unwrap();
        assert_eq!(
            ram.read_u8(GuestPhysAddr::new(3072)).unwrap(),
            VIRTIO_BLK_S_OK
        );
        assert_eq!(&backend.0.borrow()[512..524], b"helios-block");

        // Read back sector 1.
        let rd_hdr = BlkReqHeader {
            kind: VIRTIO_BLK_T_IN.to_le(),
            reserved: 0,
            sector: 1u64.to_le(),
        };
        ram.write_pod(GuestPhysAddr::new(1024), &rd_hdr).unwrap();
        write_desc(&ram, &blk.model.queues[0], 3, 1024, 16, 1, 4);
        write_desc(&ram, &blk.model.queues[0], 4, 4096, 512, 3, 5);
        write_desc(&ram, &blk.model.queues[0], 5, 3073, 1, 2, 0);
        push_avail(&ram, &blk.model.queues[0], 1, 3);
        futures_lite::future::block_on(blk.process_requests(&ram, &backend)).unwrap();
        assert_eq!(
            ram.read_u8(GuestPhysAddr::new(3073)).unwrap(),
            VIRTIO_BLK_S_OK
        );
        assert_eq!(
            ram.read_bytes(GuestPhysAddr::new(4096), 12).unwrap(),
            b"helios-block"
        );

        // Read-only block rejects writes with IOERR.
        let mut ro_blk = VirtioBlock::block(VirtioSlot::at(1).unwrap(), 8, true);
        ro_blk.status = DRIVER_OK;
        ro_blk.model.queues[0] = enable_queue(&ram, 0, 8);
        ram.write_pod(GuestPhysAddr::new(1024), &hdr).unwrap();
        write_desc(&ram, &ro_blk.model.queues[0], 0, 1024, 16, 1, 1);
        write_desc(&ram, &ro_blk.model.queues[0], 1, 2048, 512, 1, 2);
        write_desc(&ram, &ro_blk.model.queues[0], 2, 3074, 1, 2, 0);
        push_avail(&ram, &ro_blk.model.queues[0], 0, 0);
        futures_lite::future::block_on(ro_blk.process_requests(&ram, &backend)).unwrap();
        assert_eq!(
            ram.read_u8(GuestPhysAddr::new(3074)).unwrap(),
            VIRTIO_BLK_S_IOERR
        );
    }
}
