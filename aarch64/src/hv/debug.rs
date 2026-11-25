//! Bank the architecturally implemented breakpoint/watchpoint registers.
//! The vCPU owner swaps them with IRQs masked and debug monitors disabled;
//! guest access is trapped, including OS Lock, which never changes host locks.
use core::arch::asm;
use helios_hal::hv::IoAccess;

macro_rules! read {
    ($reg:ident) => {{
        let value: u64;
        // SAFETY: reading an EL1/EL2 debug system register via `mrs` at EL2
        // touches no memory and only reads the calling CPU's register.
        unsafe { asm!(concat!("mrs {value}, ", stringify!($reg)), value = out(reg) value,
            options(nomem, nostack, preserves_flags)); }
        value
    }};
}
macro_rules! write {
    ($reg:ident, $value:expr) => {{
        // SAFETY: writing an EL1 debug system register affects only the
        // calling CPU's debug state while local IRQs are masked and debug
        // monitors are disabled.
        unsafe { asm!(concat!("msr ", stringify!($reg), ", {value}"), value = in(reg) $value,
            options(nomem, nostack, preserves_flags)); }
    }};
}

macro_rules! banks {
    ($($index:literal => ($bvr:ident, $bcr:ident, $wvr:ident, $wcr:ident)),+ $(,)?) => {
        fn read_breakpoint(index: usize) -> [u64; 2] {
            match index { $($index => [read!($bvr), read!($bcr)],)+ _ => unreachable!() }
        }
        fn read_watchpoint(index: usize) -> [u64; 2] {
            match index { $($index => [read!($wvr), read!($wcr)],)+ _ => unreachable!() }
        }
        fn write_breakpoint(index: usize, value: [u64; 2]) {
            match index { $($index => { write!($bvr, value[0]); write!($bcr, value[1]); },)+ _ => unreachable!() }
        }
        fn write_watchpoint(index: usize, value: [u64; 2]) {
            match index { $($index => { write!($wvr, value[0]); write!($wcr, value[1]); },)+ _ => unreachable!() }
        }
    };
}

banks! {
    0 => (dbgbvr0_el1, dbgbcr0_el1, dbgwvr0_el1, dbgwcr0_el1),
    1 => (dbgbvr1_el1, dbgbcr1_el1, dbgwvr1_el1, dbgwcr1_el1),
    2 => (dbgbvr2_el1, dbgbcr2_el1, dbgwvr2_el1, dbgwcr2_el1),
    3 => (dbgbvr3_el1, dbgbcr3_el1, dbgwvr3_el1, dbgwcr3_el1),
    4 => (dbgbvr4_el1, dbgbcr4_el1, dbgwvr4_el1, dbgwcr4_el1),
    5 => (dbgbvr5_el1, dbgbcr5_el1, dbgwvr5_el1, dbgwcr5_el1),
    6 => (dbgbvr6_el1, dbgbcr6_el1, dbgwvr6_el1, dbgwcr6_el1),
    7 => (dbgbvr7_el1, dbgbcr7_el1, dbgwvr7_el1, dbgwcr7_el1),
    8 => (dbgbvr8_el1, dbgbcr8_el1, dbgwvr8_el1, dbgwcr8_el1),
    9 => (dbgbvr9_el1, dbgbcr9_el1, dbgwvr9_el1, dbgwcr9_el1),
    10 => (dbgbvr10_el1, dbgbcr10_el1, dbgwvr10_el1, dbgwcr10_el1),
    11 => (dbgbvr11_el1, dbgbcr11_el1, dbgwvr11_el1, dbgwcr11_el1),
    12 => (dbgbvr12_el1, dbgbcr12_el1, dbgwvr12_el1, dbgwcr12_el1),
    13 => (dbgbvr13_el1, dbgbcr13_el1, dbgwvr13_el1, dbgwcr13_el1),
    14 => (dbgbvr14_el1, dbgbcr14_el1, dbgwvr14_el1, dbgwcr14_el1),
    15 => (dbgbvr15_el1, dbgbcr15_el1, dbgwvr15_el1, dbgwcr15_el1),
}

#[derive(Clone, Copy)]
pub(super) struct Capabilities {
    breakpoints: usize,
    watchpoints: usize,
    pub(super) id: u64,
}
impl Capabilities {
    pub(super) fn discover() -> Self {
        let host = read!(id_aa64dfr0_el1);
        // Arm ARM ID_AA64DFR0: counts are encoded as N-1. DebugVer=6
        // is v8.0 debug; DoubleLock and MTPMU use 0xf for not implemented.
        let breakpoints = ((host >> 12) & 15) as usize + 1;
        let watchpoints = ((host >> 20) & 15) as usize + 1;
        let id = 6 | (host & ((15 << 12) | (15 << 20) | (15 << 28))) | (15 << 36) | (15 << 48);
        Self {
            breakpoints,
            watchpoints,
            id,
        }
    }
}

pub(super) struct State {
    capabilities: Capabilities,
    // Arm debug register indices are four bits: at most 16 of each kind.
    breakpoints: [[u64; 2]; 16],
    watchpoints: [[u64; 2]; 16],
    locked: bool,
}

impl State {
    pub(super) fn new(capabilities: Capabilities) -> Self {
        Self {
            capabilities,
            breakpoints: [[0; 2]; 16],
            watchpoints: [[0; 2]; 16],
            locked: true,
        }
    }
    pub(super) fn register(&mut self, encoding: u32, access: IoAccess) -> Option<u64> {
        // OSDLR is RES0 with FEAT_DoubleLock absent. OS Lock is virtual and
        // protects only this vCPU's debug bank, never the host's registers.
        match encoding {
            0x809c => return Some(0),
            0x8084 => {
                if let IoAccess::Write { value, .. } = access {
                    self.locked = value & 1 != 0;
                }
                return Some(0);
            }
            0x808c => return Some(8 | (u64::from(self.locked) << 1)),
            _ => {}
        }
        if encoding & 0xff80 != 0x8000 {
            return None;
        }
        let index = ((encoding >> 3) & 15) as usize;
        let op2 = encoding & 7;
        let register = match op2 {
            4 | 5 if index < self.capabilities.breakpoints => {
                &mut self.breakpoints[index][(op2 - 4) as usize]
            }
            6 | 7 if index < self.capabilities.watchpoints => {
                &mut self.watchpoints[index][(op2 - 6) as usize]
            }
            _ => return None,
        };
        Some(match access {
            IoAccess::Read { .. } => *register,
            IoAccess::Write { value, .. } => {
                if !self.locked {
                    // DBGBCR/DBGWCR.HMC enables matching EL2; the guest has
                    // no EL2, so that bit is RES0 in its register view.
                    *register = if op2 & 1 != 0 {
                        value & !(1 << 13)
                    } else {
                        value
                    };
                }
                0
            }
        })
    }
    fn capture(capabilities: Capabilities) -> Self {
        let mut state = Self::new(capabilities);
        state.locked = read!(oslsr_el1) & 2 != 0;
        write!(oslar_el1, 0u64);
        // SAFETY: `isb` synchronizes the OS Lock unlock before reading the
        // breakpoint and watchpoint registers.
        unsafe {
            asm!("isb", options(nomem, nostack, preserves_flags));
        }
        for (index, value) in state.breakpoints[..capabilities.breakpoints]
            .iter_mut()
            .enumerate()
        {
            *value = read_breakpoint(index);
        }
        for (index, value) in state.watchpoints[..capabilities.watchpoints]
            .iter_mut()
            .enumerate()
        {
            *value = read_watchpoint(index);
        }
        state
    }
    fn install(&self) {
        for (index, value) in self.breakpoints[..self.capabilities.breakpoints]
            .iter()
            .enumerate()
        {
            write_breakpoint(index, *value);
        }
        for (index, value) in self.watchpoints[..self.capabilities.watchpoints]
            .iter()
            .enumerate()
        {
            write_watchpoint(index, *value);
        }
        // SAFETY: `isb` orders the debug register writes before guest entry
        // or host resume.
        unsafe {
            asm!("isb", options(nomem, nostack, preserves_flags));
        }
    }
    pub(super) fn enter(&self) -> Host {
        let mdscr = read!(mdscr_el1);
        write!(mdscr_el1, 0u64);
        // SAFETY: `isb` ensures debug monitors are disabled before capturing
        // and replacing the breakpoint/watchpoint bank.
        unsafe {
            asm!("isb", options(nomem, nostack, preserves_flags));
        }
        let state = Self::capture(self.capabilities);
        self.install();
        Host { state, mdscr }
    }
}

pub(super) struct Host {
    state: State,
    mdscr: u64,
}
impl Host {
    pub(super) fn restore(self) {
        // The assembly has restored the disabled host MDSCR by this point.
        self.state.install();
        write!(oslar_el1, u64::from(self.state.locked));
        write!(mdscr_el1, self.mdscr);
        // SAFETY: `isb` orders restoring host `mdscr_el1` before resuming host
        // execution.
        unsafe {
            asm!("isb", options(nomem, nostack, preserves_flags));
        }
    }
}
