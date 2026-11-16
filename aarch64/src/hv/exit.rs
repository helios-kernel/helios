//! Decode AArch64 exception syndromes without touching live processor state.

use helios_hal::hv::{GuestAddress, HvError, IoAccess, IoWidth, VmExit};
use helios_hal::vmm::PageFlags;

use super::Registers;

/// One trapped instruction, retained until the VMM supplies its result.
pub(super) struct Completion {
    register: usize,
    read: bool,
    width: IoWidth,
    sign_extend: bool,
    wide_register: bool,
}

impl Completion {
    pub(super) fn apply(self, registers: &mut Registers, value: u64) {
        if self.read && self.register != 31 {
            let bits = self.width.bytes() * 8;
            let value = if self.sign_extend {
                ((value << (64 - bits)) as i64 >> (64 - bits)) as u64
            } else {
                value & (u64::MAX >> (64 - bits))
            };
            registers.x[self.register] = if self.wide_register {
                value
            } else {
                u64::from(value as u32)
            };
        }
        // Traps accepted here are A64 instructions, all four bytes long.
        registers.pc = registers.pc.wrapping_add(4);
    }
}

fn width(syndrome: u64) -> IoWidth {
    match (syndrome >> 22) & 3 {
        0 => IoWidth::Byte,
        1 => IoWidth::Word,
        2 => IoWidth::Dword,
        3 => IoWidth::Qword,
        _ => unreachable!(),
    }
}

fn access(registers: &Registers, completion: &Completion) -> IoAccess {
    if completion.read {
        IoAccess::Read {
            width: completion.width,
        }
    } else {
        let value = if completion.register == 31 {
            0
        } else {
            registers.x[completion.register]
        };
        IoAccess::Write {
            width: completion.width,
            value: value & (u64::MAX >> (64 - completion.width.bytes() * 8)),
        }
    }
}

/// `ESR_EL2`, `HPFAR_EL2` and `FAR_EL2` belong to the same saved exception.
/// The caller decides whether an IPA belongs to RAM before treating an abort
/// as emulated MMIO. Access-flag/permission faults on RAM stay Stage2Faults.
pub(super) fn decode(
    registers: &mut Registers,
    syndrome: u64,
    hpfar: u64,
    far: u64,
    mapped: impl FnOnce(GuestAddress) -> bool,
) -> Result<(VmExit, Option<Completion>), HvError> {
    // Arm ARM ESR_EL2.EC (bits 31:26) and its exception-specific ISS.
    let class = (syndrome >> 26) & 0x3f;
    match class {
        0x01 => {
            registers.pc = registers.pc.wrapping_add(4);
            let exit = if syndrome & 1 == 0 {
                VmExit::Halt
            } else {
                VmExit::Preempted
            };
            Ok((exit, None))
        }
        // HVC's preferred return address already follows the instruction.
        0x16 => Ok((
            VmExit::Hypercall {
                number: registers.x[0],
            },
            None,
        )),
        0x17 => {
            registers.pc = registers.pc.wrapping_add(4);
            Ok((
                VmExit::Hypercall {
                    number: registers.x[0],
                },
                None,
            ))
        }
        0x18 => {
            let completion = Completion {
                register: ((syndrome >> 5) & 31) as usize,
                read: syndrome & 1 != 0,
                width: IoWidth::Qword,
                sign_extend: false,
                wide_register: true,
            };
            // Architectural op0:op1:CRn:CRm:op2 encoding, independent of ESR.
            let register = (((syndrome >> 20) & 3) << 14)
                | (((syndrome >> 14) & 7) << 11)
                | (((syndrome >> 10) & 15) << 7)
                | (((syndrome >> 1) & 15) << 3)
                | ((syndrome >> 17) & 7);
            Ok((
                VmExit::SysReg {
                    register: register as u32,
                    access: access(registers, &completion),
                },
                Some(completion),
            ))
        }
        0x20 | 0x24 => {
            if syndrome & 0x3f >= 0x10 {
                return Err(HvError::EntryFailed { status: syndrome });
            }
            // HPFAR.FIPA is IPA[47:12] in bits [39:4]. FAR contributes
            // the page offset only for a final access, not a table walk.
            let table_walk = syndrome & (1 << 7) != 0;
            let address = GuestAddress(
                ((hpfar & 0x0000_00ff_ffff_fff0) << 8) | if table_walk { 0 } else { far & 0xfff },
            );
            let write = syndrome & (1 << 6) != 0;
            let fault_access = if class == 0x20 {
                PageFlags::EXECUTE
            } else if write {
                PageFlags::WRITE
            } else {
                PageFlags::READ
            };
            // ISV describes a single register transfer. Translation faults
            // have FSC 0b0001xx. Other aborts must not reach a device model.
            if class == 0x24
                && syndrome & (1 << 24) != 0
                && syndrome & 0x3c == 4
                && !table_walk
                && !mapped(address)
            {
                let completion = Completion {
                    register: ((syndrome >> 16) & 31) as usize,
                    read: !write,
                    width: width(syndrome),
                    sign_extend: syndrome & (1 << 21) != 0,
                    wide_register: syndrome & (1 << 15) != 0,
                };
                Ok((
                    VmExit::Mmio {
                        address,
                        access: access(registers, &completion),
                    },
                    Some(completion),
                ))
            } else {
                Ok((
                    VmExit::Stage2Fault {
                        address,
                        access: fault_access,
                    },
                    None,
                ))
            }
        }
        _ => Err(HvError::EntryFailed { status: syndrome }),
    }
}
