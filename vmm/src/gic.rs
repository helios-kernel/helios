//! GICv3 distributor and redistributor emulation on the static MMIO bus.
//!
//! One device task owns all MMIO state; virtual CPU interfaces, timer
//! interrupts, and EOI run in the kernel/HAL backend.

use helios_api::hv::{GuestPhysAddr, IoAccess, IoWidth, IrqLevel, MmioDevice, MmioRange};

use crate::boot::{GICD, GICD_SIZE, GICR, GICR_STRIDE};
use crate::error::{Error, Result};
use crate::hv_backend::IrqTarget;

#[derive(Default)]
struct Bank {
    group: u32,
    enabled: u32,
    pending: u32,
    active: u32,
    priority: [u8; 32],
    config: [u32; 2],
}

impl Bank {
    fn access(&mut self, offset: u64, width: usize, value: Option<u64>) -> Option<u64> {
        let register = match offset {
            0x80 => &mut self.group,
            0x100 | 0x180 => &mut self.enabled,
            0x200 | 0x280 => &mut self.pending,
            0x300 | 0x380 => &mut self.active,
            0xc00 => &mut self.config[0],
            0xc04 => &mut self.config[1],
            0x400..=0x41f => {
                let start = offset as usize - 0x400;
                let end = start.checked_add(width)?;
                let bytes = self.priority.get_mut(start..end)?;
                if let Some(value) = value {
                    bytes.copy_from_slice(&value.to_le_bytes()[..width]);
                }
                let mut data = [0; 8];
                data[..width].copy_from_slice(bytes);
                return Some(u64::from_le_bytes(data));
            }
            _ => return None,
        };
        if width != 4 {
            return None;
        }
        if let Some(value) = value {
            match offset {
                0x100 | 0x200 | 0x300 => *register |= value as u32,
                0x180 | 0x280 | 0x380 => *register &= !(value as u32),
                _ => *register = value as u32,
            }
        }
        Some(u64::from(*register))
    }
}

/// Emulated ARM GICv3 distributor (SPIs 32..63) and per-vCPU redistributors.
pub struct Gic {
    control: u32,
    shared: Bank,
    local: Vec<Bank>,
    awake: Vec<bool>,
    routes: [u64; 32],
    lines: u32,
    delivered: [Option<u32>; 32],
}

impl Gic {
    pub fn new(cpus: u32) -> Self {
        Self {
            control: 0,
            shared: Bank::default(),
            local: (0..cpus).map(|_| Bank::default()).collect(),
            awake: vec![false; cpus as usize],
            routes: [0; 32],
            lines: 0,
            delivered: [None; 32],
        }
    }

    pub fn distributor_range(&self) -> MmioRange {
        MmioRange::new(GICD, GICD_SIZE).expect("GICD MMIO range is valid")
    }

    pub fn redistributor_range(&self) -> MmioRange {
        MmioRange::new(GICR, (self.local.len() as u64) * GICR_STRIDE)
            .expect("GICR MMIO range is valid")
    }

    pub fn access_distributor(&mut self, offset: u64, access: IoAccess) -> Result<u64> {
        let address = GICD
            .checked_add(offset)
            .ok_or(Error::Gic("distributor address overflow"))?;
        self.access(address, access)
    }

    pub fn access_redistributor(&mut self, offset: u64, access: IoAccess) -> Result<u64> {
        let address = GICR
            .checked_add(offset)
            .ok_or(Error::Gic("redistributor address overflow"))?;
        self.access(address, access)
    }

    pub fn access(&mut self, address: GuestPhysAddr, access: IoAccess) -> Result<u64> {
        let raw_addr = address.raw();
        let (width, value) = match access {
            IoAccess::Read(width) => (width, None),
            IoAccess::Write(write) => (write.width, Some(write.value)),
        };
        let width = match width {
            IoWidth::Byte => 1,
            IoWidth::Word => 2,
            IoWidth::Dword => 4,
            IoWidth::Qword => 8,
        };
        if !raw_addr.is_multiple_of(width as u64) {
            return Err(Error::Gic("unaligned access"));
        }
        if let Some(offset) = self.distributor_range().offset(address) {
            if (0x6100..0x6200).contains(&offset) {
                let index = ((offset - 0x6100) / 8) as usize;
                let shift = (offset & 7) * 8;
                if let Some(value) = value {
                    let mask = if width == 8 {
                        u64::MAX
                    } else {
                        (1u64 << (width * 8)) - 1
                    };
                    self.routes[index] =
                        (self.routes[index] & !(mask << shift)) | ((value & mask) << shift);
                }
                return Ok(self.routes[index] >> shift);
            }
            // SPIs 32..63 occupy bank 1; SGI/PPI distributor registers are
            // RAZ/WI with affinity routing enabled (GICv3 architecture).
            let bank_offset = match offset {
                0x84 | 0x104 | 0x184 | 0x204 | 0x284 | 0x304 | 0x384 => Some(offset - 4),
                0x420..=0x43f => Some(offset - 32),
                0xc08..=0xc0f => Some(offset - 8),
                _ => None,
            };
            if let Some(offset) = bank_offset {
                return self
                    .shared
                    .access(offset, width, value)
                    .ok_or(Error::Gic("SPI register width"));
            }
            return Ok(match offset {
                0 => {
                    if let Some(value) = value {
                        self.control = value as u32 & 0x12;
                    }
                    // DS and ARE_NS are RES1 in this single security state model.
                    u64::from(self.control | 0x50)
                }
                4 => 1, // ITLinesNumber=1: 64 INTIDs, no LPIs or security extensions.
                8 => 0x0102_043b,
                0xffe8 => 0x30, // PIDR2.ArchRev = GICv3.
                _ => 0,
            });
        }
        let relative = self
            .redistributor_range()
            .offset(address)
            .ok_or(Error::Gic("address"))?;
        let index = (relative / GICR_STRIDE) as usize;
        let offset = relative % GICR_STRIDE;
        let bank = self
            .local
            .get_mut(index)
            .ok_or(Error::Gic("redistributor index"))?;
        if offset >= 0x10000 {
            return Ok(bank.access(offset - 0x10000, width, value).unwrap_or(0));
        }
        Ok(match offset {
            0 => 0,
            4 => 0x0102_043b,
            8 | 12 => {
                // Linear Aff0 CPU topology, matching VMPIDR and the DTB.
                let typer = ((index as u64) << 32)
                    | ((index as u64) << 8)
                    | if index + 1 == self.local.len() {
                        1 << 4
                    } else {
                        0
                    };
                if offset == 12 {
                    typer >> 32
                } else if width == 8 {
                    typer
                } else {
                    typer & u64::from(u32::MAX)
                }
            }
            0x14 => {
                if let Some(value) = value {
                    self.awake[index] = value & 2 == 0;
                }
                if self.awake[index] { 0 } else { 6 }
            }
            0xffe8 => 0x30,
            _ => 0,
        })
    }

    pub fn line(&mut self, number: u32, asserted: bool) {
        if !(32..64).contains(&number) {
            return;
        }
        let bit = 1u32 << (number - 32);
        if asserted {
            self.lines |= bit;
        } else {
            self.lines &= !bit;
        }
    }

    pub fn sync(&mut self, target_vm: &impl IrqTarget) -> Result<()> {
        for index in 0..32 {
            let bit = 1 << index;
            let route = self.routes[index];
            let target = if route & (1 << 31) != 0 {
                0
            } else {
                route as u32 & 0xff
            };
            let active = self.control & 2 != 0
                && self.shared.enabled & self.shared.group & bit != 0
                && (self.lines | self.shared.pending) & bit != 0
                && self.awake.get(target as usize).copied().unwrap_or(false);
            let desired = active.then_some(target);
            if self.delivered[index] != desired {
                if let Some(cpu) = self.delivered[index] {
                    target_vm.set_irq_line(cpu, index as u32 + 32, IrqLevel::Deassert)?;
                }
                if let Some(cpu) = desired {
                    target_vm.set_irq_line(cpu, index as u32 + 32, IrqLevel::Assert)?;
                }
                self.delivered[index] = desired;
            }
        }
        for (cpu, bank) in self.local.iter_mut().enumerate() {
            let pending = bank.pending & bank.enabled & bank.group;
            for number in 0..32 {
                if pending & (1 << number) != 0 {
                    target_vm.set_irq_line(cpu as u32, number, IrqLevel::Pulse)?;
                    bank.pending &= !(1 << number);
                }
            }
        }
        Ok(())
    }

    pub fn sgi(&mut self, source: u32, value: u64) {
        let number = (value >> 24) & 15;
        let all_others = value & (1 << 40) != 0;
        let affinity =
            ((value >> 16) & 0xff) | (((value >> 32) & 0xff) << 8) | (((value >> 48) & 0xff) << 16);
        let range = ((value >> 44) & 15) * 16;
        for (cpu, bank) in self.local.iter_mut().enumerate() {
            let cpu = cpu as u64;
            if if all_others {
                cpu != u64::from(source)
            } else {
                affinity == 0
                    && cpu >= range
                    && cpu - range < 16
                    && value & (1 << (cpu - range)) != 0
            } {
                bank.pending |= 1 << number;
            }
        }
    }
}

/// Static MMIO bus wrapper for [`Gic`] covering both GICD and GICR windows.
pub struct GicBus<'a>(pub &'a mut Gic);

impl<Ctx> helios_api::hv::MmioBus<Ctx> for GicBus<'_> {
    type Error = Error;

    fn dispatch(
        &mut self,
        address: GuestPhysAddr,
        access: IoAccess,
        _ctx: &Ctx,
    ) -> Result<Option<u64>> {
        if self.0.distributor_range().contains(address)
            || self.0.redistributor_range().contains(address)
        {
            self.0.access(address, access).map(Some)
        } else {
            Ok(None)
        }
    }
}

/// Single-range distributor adapter when mounting GICD directly as an [`MmioDevice`].
pub struct GicDistributor<'a>(pub &'a mut Gic);

impl<Ctx> MmioDevice<Ctx> for GicDistributor<'_> {
    type Error = Error;

    fn range(&self) -> MmioRange {
        self.0.distributor_range()
    }

    fn access(&mut self, offset: u64, access: IoAccess, _ctx: &Ctx) -> Result<u64> {
        self.0.access_distributor(offset, access)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helios_api::hv::IoWrite;

    #[test]
    fn sgi_routes_target_list_and_all_others() {
        let mut gic = Gic::new(3);
        gic.sgi(0, (5 << 24) | 0b110);
        assert_eq!(gic.local[0].pending, 0);
        assert_eq!(gic.local[1].pending, 1 << 5);
        assert_eq!(gic.local[2].pending, 1 << 5);
        gic.sgi(1, (1 << 40) | (7 << 24));
        assert_eq!(gic.local[0].pending, 1 << 7);
        assert_eq!(gic.local[1].pending, 1 << 5);
        assert_eq!(gic.local[2].pending, (1 << 5) | (1 << 7));
        // No CPUs in Aff1=1 exist in the advertised single-cluster topology.
        gic.sgi(0, (9 << 24) | (1 << 16) | 0xffff);
        assert!(gic.local.iter().all(|bank| bank.pending & (1 << 9) == 0));
    }

    #[test]
    fn redistributors_have_distinct_affinity_and_last_flags() {
        let mut gic = Gic::new(2);
        let read = IoAccess::Read(IoWidth::Qword);
        let first = gic.access(GICR.checked_add(8).unwrap(), read).unwrap();
        let second = gic
            .access(GICR.checked_add(GICR_STRIDE + 8).unwrap(), read)
            .unwrap();
        assert_eq!(first >> 32, 0);
        assert_eq!(second >> 32, 1);
        assert_eq!(first & 16, 0);
        assert_eq!(second & 16, 16);
        gic.access(
            GICR.checked_add(0x14).unwrap(),
            IoAccess::Write(IoWrite {
                width: IoWidth::Dword,
                value: 0,
            }),
        )
        .unwrap();
        assert_eq!(
            gic.access(
                GICR.checked_add(0x14).unwrap(),
                IoAccess::Read(IoWidth::Dword)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            gic.access(
                GICR.checked_add(GICR_STRIDE + 0x14).unwrap(),
                IoAccess::Read(IoWidth::Dword),
            )
            .unwrap(),
            6
        );
    }
}
