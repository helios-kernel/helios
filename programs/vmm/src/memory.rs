use helios_api::hv::{MemoryRegion, Permissions, Vm};

use crate::{Error, Result};

pub const RAM_BASE: u64 = 0x4000_0000;
pub const TRANSFER: usize = 64 * 1024;

/// Guest physical addresses are translated only into offsets passed to WIT.
/// No host pointer or Wasm slice ever aliases guest RAM.
pub struct Memory {
    region: MemoryRegion,
    pub size: u64,
}

impl Memory {
    pub fn new(vm: &Vm, size: u64) -> Result<Self> {
        let region = vm.allocate_memory(
            RAM_BASE,
            size,
            Permissions::READ | Permissions::WRITE | Permissions::EXECUTE,
        )?;
        Ok(Self { region, size })
    }

    pub fn publish(&self, address: u64, length: u64) -> Result<()> {
        self.region.publish(self.offset(address, length)?, length)?;
        Ok(())
    }
}

pub trait GuestMemory {
    fn offset(&self, address: u64, length: u64) -> Result<u64>;
    fn read(&self, address: u64, length: u32) -> Result<Vec<u8>>;
    fn write(&self, address: u64, bytes: &[u8]) -> Result<()>;
    fn u16(&self, address: u64) -> Result<u16> {
        Ok(u16::from_le_bytes(
            self.read(address, 2)?.try_into().unwrap(),
        ))
    }
}

impl GuestMemory for Memory {
    fn offset(&self, address: u64, length: u64) -> Result<u64> {
        let offset = address
            .checked_sub(RAM_BASE)
            .ok_or(Error::Memory(address, length))?;
        if offset.checked_add(length).is_none_or(|end| end > self.size) {
            return Err(Error::Memory(address, length));
        }
        Ok(offset)
    }

    fn read(&self, address: u64, length: u32) -> Result<Vec<u8>> {
        Ok(self
            .region
            .read(self.offset(address, u64::from(length))?, length)?)
    }

    fn write(&self, address: u64, bytes: &[u8]) -> Result<()> {
        self.region
            .write(self.offset(address, bytes.len() as u64)?, bytes)?;
        Ok(())
    }
}
