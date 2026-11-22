//! The x86 half of `helios_hal::native`'s isolation contract: SMEP and
//! SMAP keep ring 0 from fetching from and accessing user pages, and
//! `IA32_ARCH_CAPABILITIES.RDCL_NO` declares the processor unaffected by
//! rogue data cache load.
//!
//! Every processor enables SMEP and SMAP when it has them, whether or not
//! native execution is built, as Linux's `setup_smep` and `setup_smap`
//! (arch/x86/kernel/cpu/common.c) do. No kernel mapping is
//! user-accessible (`vmm::page_flags_to_pt`), so neither changes what the
//! kernel itself can reach. The bootstrap processor's answer decides
//! whether native execution is offered, and every other processor must
//! give the same one before it runs anything.

use core::arch::x86_64::{__cpuid, __cpuid_count};

#[cfg(feature = "native-users")]
use helios_hal::native::{NativeUnavailable, Protection};
use x86::msr::rdmsr;
use x86_64::registers::control::{Cr4, Cr4Flags};

// CPUID leaf 07H, subleaf 0 (Intel SDM vol. 2A, "CPUID"): EBX[7] SMEP,
// EBX[20] SMAP, EDX[29] the IA32_ARCH_CAPABILITIES MSR.
const STRUCTURED_EXTENDED_FEATURES: u32 = 0x7;
const SMEP: u32 = 1 << 7;
const SMAP: u32 = 1 << 20;
const ARCH_CAPABILITIES: u32 = 1 << 29;
// IA32_ARCH_CAPABILITIES (Intel SDM vol. 4, table 2-2): bit 0 RDCL_NO.
const IA32_ARCH_CAPABILITIES: u32 = 0x10a;
const RDCL_NO: u64 = 1 << 0;

/// Which of the isolation contract's protections a processor offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UserIsolation {
    smep: bool,
    smap: bool,
    rdcl_no: bool,
}

impl UserIsolation {
    /// What the executing processor offers.
    fn probe() -> Self {
        if __cpuid(0).eax < STRUCTURED_EXTENDED_FEATURES {
            return Self {
                smep: false,
                smap: false,
                rdcl_no: false,
            };
        }
        let leaf = __cpuid_count(STRUCTURED_EXTENDED_FEATURES, 0);
        let rdcl_no = leaf.edx & ARCH_CAPABILITIES != 0
            // SAFETY: CPUID declares the MSR, and reading it has no side
            // effect.
            && unsafe { rdmsr(IA32_ARCH_CAPABILITIES) } & RDCL_NO != 0;
        Self {
            smep: leaf.ebx & SMEP != 0,
            smap: leaf.ebx & SMAP != 0,
            rdcl_no,
        }
    }

    /// Probes the bootstrap processor and enables what it offers; the
    /// answer is the one every other processor is held to.
    pub(crate) fn enable_on_bootstrap_processor() -> Self {
        let isolation = Self::probe();
        isolation.enable();
        isolation
    }

    /// Enables the bootstrap processor's protections on a processor that
    /// is starting or restarting, after checking it offers the same ones.
    /// A restart needs it as much as a first start: INIT clears CR4.
    pub(crate) fn enable_on_secondary_processor(self) {
        let own = Self::probe();
        assert_eq!(
            own,
            self,
            "x86 processor with initial APIC ID {} offers kernel isolation {own:?}, the \
             bootstrap processor {self:?}; Helios requires every processor to offer the same",
            __cpuid(1).ebx >> 24
        );
        self.enable();
    }

    fn enable(self) {
        // SAFETY: no kernel mapping is user-accessible, so neither bit
        // refuses an access the kernel makes; RFLAGS.AC is clear
        // everywhere the kernel runs.
        unsafe {
            Cr4::update(|flags| {
                if self.smep {
                    flags.insert(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION);
                }
                if self.smap {
                    flags.insert(Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION);
                }
            });
        }
    }

    /// Whether the isolation contract holds, naming the first protection
    /// it lacks.
    #[cfg(feature = "native-users")]
    pub(crate) fn require(self) -> Result<(), NativeUnavailable> {
        let missing = if !self.smep {
            Protection::Smep
        } else if !self.smap {
            Protection::Smap
        } else if !self.rdcl_no {
            Protection::RdclNo
        } else {
            return Ok(());
        };
        Err(NativeUnavailable::MissingProtection(missing))
    }
}
