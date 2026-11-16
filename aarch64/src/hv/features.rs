//! Guest ID registers describe the state this backend switches, rather than
//! exposing host extensions with additional unsaved architectural state.

use core::arch::asm;

pub(super) struct Features {
    pfr0: u64,
    isar0: u64,
    isar1: u64,
    mmfr0: u64,
    mmfr1: u64,
    mmfr2: u64,
}

macro_rules! read {
    ($reg:ident) => {{
        let value: u64;
        unsafe { asm!(concat!("mrs {value}, ", stringify!($reg)), value = out(reg) value,
            options(nomem, nostack, preserves_flags)); }
        value
    }};
}

// Each architectural ID feature occupies a four-bit field.
fn fields(shifts: &[u32]) -> u64 {
    shifts.iter().fold(0, |mask, shift| mask | (15u64 << shift))
}

impl Features {
    pub(super) fn discover(address_bits_encoding: u64) -> Self {
        Self {
            // EL0/EL1, FP/SIMD, GIC, DIT. EL2/EL3 are absent in this VM.
            pfr0: (read!(id_aa64pfr0_el1) & fields(&[16, 20, 24, 48])) | 0x11,
            // Integer/crypto/atomic instructions add no context; TME does.
            isar0: read!(id_aa64isar0_el1) & !fields(&[24]),
            // DPB, PAuth, JSCVT, FCMA, LRCPC, FRINTTS, SB, SPECRES.
            // LS64 and XS are not advertised by this context format.
            isar1: read!(id_aa64isar1_el1)
                & fields(&[0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52]),
            // Preserve endian and base granule capabilities; omit LPA2 and
            // the host's Stage-2 granule fields. Stage-1 PA is bounded by IPA.
            mmfr0: {
                let host = read!(id_aa64mmfr0_el1);
                // Base 4K/64K supported encodings are zero; 16K is one.
                // Remove LPA2 (4K=1, 16K=2) from the guest's stage one.
                let granule4 = if (host >> 28) & 15 == 15 { 15 } else { 0 };
                let granule16 = if (host >> 20) & 15 == 0 { 0 } else { 1 };
                (host & fields(&[4, 8, 12, 16, 24]))
                    | (granule4 << 28)
                    | (granule16 << 20)
                    | address_bits_encoding
            },
            // HAFDBS, HPDS, PAN: all state is in saved SCTLR/TCR/PSTATE.
            mmfr1: read!(id_aa64mmfr1_el1) & fields(&[0, 12, 20]),
            // CnP, UAO, IESB, AT: no new register banks.
            mmfr2: read!(id_aa64mmfr2_el1) & fields(&[0, 4, 12, 32]),
        }
    }

    pub(super) fn register(&self, encoding: u32) -> Option<u64> {
        // ID_AA64* are S3_0_C0_C4..7_*. Reserved IDs read as zero.
        if encoding & 0xff80 != 0xc000 {
            return None;
        }
        let crm = (encoding >> 3) & 15;
        let op2 = encoding & 7;
        Some(match (crm, op2) {
            (4, 0) => self.pfr0,
            (5, 0) => 0, // Debug, PMU and trace are absent.
            (6, 0) => self.isar0,
            (6, 1) => self.isar1,
            (7, 0) => self.mmfr0,
            (7, 1) => self.mmfr1,
            (7, 2) => self.mmfr2,
            (4..=7, _) => 0,
            _ => return None,
        })
    }
}
