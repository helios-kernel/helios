//! Per-vCPU GICv3 virtual CPU interface. Only the owning vCPU accesses
//! this state. System registers are installed with local IRQs masked and
//! detached before host IRQ dispatch or an executor suspension.

use core::arch::asm;
use helios_hal::hv::{HvError, IoAccess, IrqLevel, VirtualIrq};

// GIC architecture: 16 List Registers at most, 1020 usable INTIDs in the
// non-LPI range. INTIDs 1020..1023 are special CPU-interface responses.
const MAX_LRS: usize = 16;
const MAX_INTID: u32 = 1020;
const PENDING: u64 = 1 << 62;
const ACTIVE: u64 = 1 << 63;
const STATE: u64 = PENDING | ACTIVE;
const GROUP1: u64 = 1 << 60;
const EOI_MAINTENANCE: u64 = 1 << 41;

macro_rules! read {
    ($reg:ident) => {{
        let value;
        unsafe { asm!(concat!("mrs {value}, ", stringify!($reg)), value = out(reg) value,
            options(nomem, nostack, preserves_flags)); }
        value
    }};
}
macro_rules! write {
    ($reg:ident, $value:expr) => {{
        unsafe { asm!(concat!("msr ", stringify!($reg), ", {value}"), value = in(reg) $value,
            options(nomem, nostack, preserves_flags)); }
    }};
}

macro_rules! register_bank {
    ($read:ident, $write:ident, $($index:literal => $reg:ident),+ $(,)?) => {
        fn $read(index: usize) -> u64 {
            match index { $($index => read!($reg),)+ _ => unreachable!("GIC register bank index") }
        }
        fn $write(index: usize, value: u64) {
            match index { $($index => write!($reg, value),)+ _ => unreachable!("GIC register bank index") }
        }
    };
}
register_bank!(read_lr, write_lr,
    0 => ich_lr0_el2, 1 => ich_lr1_el2, 2 => ich_lr2_el2, 3 => ich_lr3_el2,
    4 => ich_lr4_el2, 5 => ich_lr5_el2, 6 => ich_lr6_el2, 7 => ich_lr7_el2,
    8 => ich_lr8_el2, 9 => ich_lr9_el2, 10 => ich_lr10_el2, 11 => ich_lr11_el2,
    12 => ich_lr12_el2, 13 => ich_lr13_el2, 14 => ich_lr14_el2, 15 => ich_lr15_el2,
);
register_bank!(read_ap0, write_ap0,
    0 => ich_ap0r0_el2, 1 => ich_ap0r1_el2, 2 => ich_ap0r2_el2, 3 => ich_ap0r3_el2,
);
register_bank!(read_ap1, write_ap1,
    0 => ich_ap1r0_el2, 1 => ich_ap1r1_el2, 2 => ich_ap1r2_el2, 3 => ich_ap1r3_el2,
);

#[derive(Clone, Copy)]
pub(super) struct Capabilities {
    lrs: usize,
    aprs: usize,
    priority_bits: usize,
}

impl Capabilities {
    pub(super) fn read() -> Self {
        let vtr: u64 = read!(ich_vtr_el2);
        let lrs = (vtr & 31) as usize + 1;
        let priority_bits = ((vtr >> 29) & 7) as usize + 1;
        assert!(
            (1..=MAX_LRS).contains(&lrs) && (5..=7).contains(&priority_bits),
            "GICv3 ICH_VTR_EL2 has unsupported register counts: {vtr:#x}"
        );
        Self {
            lrs,
            aprs: 1 << (priority_bits - 5),
            priority_bits,
        }
    }
}

pub(super) struct Vgic {
    capabilities: Capabilities,
    lrs: [u64; MAX_LRS],
    ap0: [u64; 4],
    ap1: [u64; 4],
    asserted: [u64; 16],
    vmcr: u64,
    window: bool,
}

impl Vgic {
    pub(super) fn new(capabilities: Capabilities) -> Self {
        Self {
            capabilities,
            lrs: [0; MAX_LRS],
            ap0: [0; 4],
            ap1: [0; 4],
            asserted: [0; 16],
            // GICv3: VENG1 enables Group 1; VPMR initially admits all priorities.
            vmcr: 2 | (0xff << 24),
            window: false,
        }
    }

    pub(super) fn inject(&mut self, irq: VirtualIrq) -> Result<bool, HvError> {
        if irq.number >= MAX_INTID {
            return Err(HvError::InvalidInterrupt);
        }
        let word = irq.number as usize / 64;
        let bit = 1 << (irq.number % 64);
        let existing = self.lrs[..self.capabilities.lrs]
            .iter()
            .position(|lr| lr & STATE != 0 && *lr as u32 == irq.number);
        if irq.level == IrqLevel::Deassert {
            self.asserted[word] &= !bit;
            if let Some(index) = existing {
                self.lrs[index] &= !PENDING;
                if self.lrs[index] & ACTIVE == 0 {
                    self.lrs[index] = 0;
                }
            }
            return Ok(true);
        }
        let slot = existing.or_else(|| {
            self.lrs[..self.capabilities.lrs]
                .iter()
                .position(|lr| lr & STATE == 0)
        });
        let Some(slot) = slot else {
            return Ok(false);
        };
        if irq.level == IrqLevel::Assert {
            self.asserted[word] |= bit;
        }
        let active = if existing.is_some() {
            self.lrs[slot] & ACTIVE
        } else {
            0
        };
        self.lrs[slot] = active | PENDING | GROUP1 | EOI_MAINTENANCE | u64::from(irq.number);
        Ok(true)
    }

    /// TC traps the common CPU-interface registers alongside SGIs. Their
    /// state is already banked in VMCR/APRs; IAR/EOIR/DIR stay in hardware.
    pub(super) fn register(&mut self, encoding: u32, access: IoAccess) -> Option<u64> {
        let (register, shift, mask) = match encoding {
            0xc230 => (&mut self.vmcr, 24, 0xff), // ICC_PMR_EL1 / VPMR.
            0xc643 => (&mut self.vmcr, 21, 7),    // ICC_BPR0_EL1 / VBPR0.
            0xc663 => (&mut self.vmcr, 18, 7),    // ICC_BPR1_EL1 / VBPR1.
            0xc666 => (&mut self.vmcr, 0, 1),     // ICC_IGRPEN0_EL1 / VENG0.
            0xc667 => (&mut self.vmcr, 1, 1),     // ICC_IGRPEN1_EL1 / VENG1.
            0xc644..=0xc64b => {
                let index = (encoding & 3) as usize;
                if index >= self.capabilities.aprs {
                    // GICv3 APR banks beyond the implemented priority bits
                    // are RAZ/WI, and are never installed on the hardware.
                    return Some(0);
                }
                let bank = if encoding < 0xc648 {
                    &mut self.ap0
                } else {
                    &mut self.ap1
                };
                (&mut bank[index], 0, u64::MAX)
            }
            0xc664 => {
                return Some(match access {
                    IoAccess::Read { .. } => {
                        ((self.capabilities.priority_bits as u64 - 1) << 8)
                            | ((self.vmcr >> 4) & 1)
                            | (((self.vmcr >> 9) & 1) << 1)
                    }
                    IoAccess::Write { value, .. } => {
                        self.vmcr = (self.vmcr & !((1 << 4) | (1 << 9)))
                            | ((value & 1) << 4)
                            | ((value & 2) << 8);
                        0
                    }
                });
            }
            _ => return None,
        };
        Some(match access {
            IoAccess::Read { .. } => (*register >> shift) & mask,
            IoAccess::Write { value, .. } => {
                *register = (*register & !(mask << shift)) | ((value & mask) << shift);
                0
            }
        })
    }

    pub(super) fn set_window(&mut self, enabled: bool) {
        self.window = enabled;
    }

    pub(super) fn install(&self) {
        write!(ich_hcr_el2, 0u64);
        write!(ich_vmcr_el2, self.vmcr);
        for index in 0..self.capabilities.aprs {
            write_ap0(index, self.ap0[index]);
            write_ap1(index, self.ap1[index]);
        }
        for (index, &lr) in self.lrs[..self.capabilities.lrs].iter().enumerate() {
            write_lr(index, lr);
        }
        // En enables the virtual interface; UIE requests a maintenance exit
        // when the LR backlog drops far enough to accept queued interrupts.
        // TC traps ICC_SGI1R/ICC_CTLR so the VMM routes IPIs between its
        // virtual redistributors instead of sending them to physical CPUs.
        write!(
            ich_hcr_el2,
            1u64 | (1 << 10) | if self.window { 1 << 1 } else { 0 }
        );
        unsafe {
            asm!("isb", options(nostack, preserves_flags));
        }
    }

    pub(super) fn detach(&mut self) {
        write!(ich_hcr_el2, 0u64);
        unsafe {
            asm!("isb", options(nostack, preserves_flags));
        }
        self.vmcr = read!(ich_vmcr_el2);
        for index in 0..self.capabilities.aprs {
            self.ap0[index] = read_ap0(index);
            self.ap1[index] = read_ap1(index);
            write_ap0(index, 0);
            write_ap1(index, 0);
        }
        for index in 0..self.capabilities.lrs {
            let mut lr = read_lr(index);
            let intid = lr as u32;
            if lr & STATE == 0 {
                if intid < MAX_INTID
                    && self.asserted[intid as usize / 64] & (1 << (intid % 64)) != 0
                {
                    lr |= PENDING;
                } else {
                    // An invalid LR with EOI set keeps the maintenance
                    // interrupt asserted. Retire completed pulse/deasserted
                    // interrupts instead of reinstalling their EOI state.
                    lr = 0;
                }
            }
            self.lrs[index] = lr;
            write_lr(index, 0);
        }
    }
}
