//! Architectural state owned by one detached vCPU. The register list below
//! generates both directions of the switch; EL12 accessors name the guest
//! bank even while the host runs with VHE enabled.

use core::arch::global_asm;
use core::mem::{offset_of, size_of};

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Registers {
    pub x: [u64; 31],
    pub pc: u64,
    pub pstate: u64,
    pub sp: u64,
}

impl Default for Registers {
    fn default() -> Self {
        // EL1h, with D/A/I/F masked, as the Linux AArch64 boot protocol requires.
        Self {
            x: [0; 31],
            pc: 0,
            pstate: 0x3c5,
            sp: 0,
        }
    }
}

macro_rules! system_registers {
    ($($field:ident: $register:ident),+ $(,)?) => {
        #[derive(Default)]
        #[repr(C)]
        pub(super) struct SystemRegisters { $(pub(super) $field: u64,)+ }

        global_asm!(
            concat!(
                ".macro save_system base\n",
                $("mrs x10, ", stringify!($register), "\nstr x10, [\\base, #{",
                    stringify!($field), "}]\n",)+
                ".endm\n.macro load_system base\n",
                $("ldr x10, [\\base, #{", stringify!($field), "}]\nmsr ",
                    stringify!($register), ", x10\n",)+
                "isb\n.endm\n",
            ),
            include_str!("enter.S"),
            $($field = const offset_of!(Context, system) + offset_of!(SystemRegisters, $field),)+
            context_bytes = const size_of::<Context>(),
            frame_bytes = const size_of::<Context>() + 16,
            pc = const offset_of!(Context, registers) + offset_of!(Registers, pc),
            pstate = const offset_of!(Context, registers) + offset_of!(Registers, pstate),
            sp = const offset_of!(Context, registers) + offset_of!(Registers, sp),
            vectors = const offset_of!(Context, vectors),
            fpcr = const offset_of!(Context, fpcr),
            fpsr = const offset_of!(Context, fpsr),
            hcr = const offset_of!(Context, hcr),
            esr = const offset_of!(Context, esr),
            far = const offset_of!(Context, far),
            hpfar = const offset_of!(Context, hpfar),
            exit_kind = const offset_of!(Context, exit_kind),
            host_vbar = const offset_of!(Context, host_vbar),
        );
    };
}

system_registers! {
    sctlr: sctlr_el12, cpacr: cpacr_el12,
    ttbr0: ttbr0_el12, ttbr1: ttbr1_el12, tcr: tcr_el12,
    mair: mair_el12, amair: amair_el12, vbar: vbar_el12,
    contextidr: contextidr_el12, elr: elr_el12, spsr: spsr_el12,
    esr_el1: esr_el12, far_el1: far_el12, afsr0: afsr0_el12, afsr1: afsr1_el12,
    par: par_el1, sp_el0: sp_el0,
    tpidr_el0: tpidr_el0, tpidrro_el0: tpidrro_el0, tpidr_el1: tpidr_el1,
    cntkctl: cntkctl_el12,
    cntv_cval: cntv_cval_el02, cntv_ctl: cntv_ctl_el02,
    cntp_cval: cntp_cval_el02, cntp_ctl: cntp_ctl_el02,
    csselr: csselr_el1, mdscr: mdscr_el1,
    apia_lo: apiakeylo_el1, apia_hi: apiakeyhi_el1,
    apib_lo: apibkeylo_el1, apib_hi: apibkeyhi_el1,
    apda_lo: apdakeylo_el1, apda_hi: apdakeyhi_el1,
    apdb_lo: apdbkeylo_el1, apdb_hi: apdbkeyhi_el1,
    apga_lo: apgakeylo_el1, apga_hi: apgakeyhi_el1,
}

#[repr(C, align(16))]
pub(super) struct Context {
    pub(super) registers: Registers,
    pub(super) system: SystemRegisters,
    vectors: [u128; 32],
    fpcr: u64,
    fpsr: u64,
    pub(super) hcr: u64,
    pub(super) esr: u64,
    pub(super) far: u64,
    pub(super) hpfar: u64,
    pub(super) exit_kind: u64,
    host_vbar: u64,
}

impl Context {
    pub(super) fn new(hcr: u64) -> Self {
        Self {
            registers: Registers::default(),
            system: SystemRegisters {
                // SCTLR_EL1 RES1 bits for an MMU-off AArch64 EL1 reset.
                sctlr: 0x30d0_0800,
                ..SystemRegisters::default()
            },
            vectors: [0; 32],
            fpcr: 0,
            fpsr: 0,
            hcr,
            esr: 0,
            far: 0,
            hpfar: 0,
            exit_kind: 0,
            host_vbar: 0,
        }
    }
}

unsafe extern "C" {
    /// Caller has masked host IRQs, installed Stage-2 and a bounded timer,
    /// and validated the return mode. Restores host state before returning.
    pub(super) fn helios_aarch64_enter_guest(context: *mut Context);
}
