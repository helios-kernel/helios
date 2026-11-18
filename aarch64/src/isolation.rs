//! The AArch64 half of `helios_hal::native`'s isolation contract: PAN
//! keeps EL1 from accessing EL0 pages, PXN (set by `native` on every EL0
//! mapping) from fetching from them, and FEAT_CSV3 declares the processor
//! unaffected by rogue data cache load.
//!
//! Every processor runs with PAN when it has it, whether or not native
//! execution is built, as Linux's `cpu_enable_pan`
//! (arch/arm64/kernel/cpufeature.c) does: no kernel mapping is
//! EL0-accessible (`vmm`'s `AP_KERNEL_*`), so PAN refuses nothing the
//! kernel itself does. The bootstrap processor's answer decides whether
//! native execution is offered, and every other processor must give the
//! same one before it runs anything.

use core::arch::asm;

use arm_sysregs::el1::accessors::{read_id_aa64mmfr1_el1, read_id_aa64pfr0_el1, read_mpidr_el1};
use arm_sysregs::el1::registers::SctlrEl1;
#[cfg(feature = "native-users")]
use helios_hal::native::{NativeUnavailable, Protection};

/// Which of the isolation contract's protections a processor offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UserIsolation {
    pan: bool,
    csv3: bool,
}

impl UserIsolation {
    /// What the executing processor offers: FEAT_PAN when
    /// `ID_AA64MMFR1_EL1.PAN` is nonzero, FEAT_CSV3 when
    /// `ID_AA64PFR0_EL1.CSV3` is (Arm ARM D19.2).
    pub(crate) fn probe() -> Self {
        Self {
            pan: read_id_aa64mmfr1_el1().pan() != 0,
            csv3: read_id_aa64pfr0_el1().csv3() != 0,
        }
    }

    /// Enables the bootstrap processor's protections on the executing
    /// processor, after checking it offers the same ones. Every processor
    /// runs it once it is up, and again each time it is restarted, which
    /// resets PSTATE.
    pub(crate) fn enable_on_current_processor(self) {
        let own = Self::probe();
        assert_eq!(
            own,
            self,
            "AArch64 processor with MPIDR {:#x} offers kernel isolation {own:?}, the bootstrap \
             processor {self:?}; Helios requires every processor to offer the same",
            read_mpidr_el1().bits()
        );
        if !self.pan {
            return;
        }
        let span = SctlrEl1::SPAN.bits();
        // SAFETY: clearing SCTLR_EL1.SPAN sets PSTATE.PAN on every
        // exception taken to EL1, and `msr pan, #1` sets it now, so EL1
        // can reach no EL0-accessible page, of which the kernel maps none
        // of its own. The `isb` orders the SCTLR write before what
        // follows. The PSTATE write is spelled as its encoding,
        // 0xd500419f, because the base target does not enable FEAT_PAN
        // in the assembler.
        unsafe {
            asm!(
                "mrs {sctlr}, sctlr_el1",
                "bic {sctlr}, {sctlr}, {span}",
                "msr sctlr_el1, {sctlr}",
                "isb",
                ".inst 0xd500419f",
                sctlr = out(reg) _,
                span = in(reg) span,
                options(nostack, preserves_flags),
            );
        }
    }

    /// Whether the isolation contract holds, naming the first protection
    /// it lacks.
    #[cfg(feature = "native-users")]
    pub(crate) fn require(self) -> Result<(), NativeUnavailable> {
        let missing = if !self.pan {
            Protection::Pan
        } else if !self.csv3 {
            Protection::Csv3
        } else {
            return Ok(());
        };
        Err(NativeUnavailable::MissingProtection(missing))
    }
}
