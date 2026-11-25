//! PL031 real-time clock for the AArch64 backend.
//!
//! The platform exposes an ARM PL031 next to the PL011 UART. Its data
//! register holds a free-running 32-bit counter of seconds since the
//! Unix epoch, which firmware loads from the host clock, so the kernel
//! reads one register once at boot and never touches the device again.
//!
//! Concurrency contract: discovery and the single read both happen on
//! the bootstrap processor before secondaries start, and the device is
//! never interrupt-driven, so nothing here is shared.

use helios_hal::rtc::{RealTimeClock, RtcError, UnixSeconds};

use crate::LimineBootHandoff;
use crate::platform::MmioRegion;

/// `RTCDR`, the current counter value.
const PL031_DATA: usize = 0x00;

#[derive(Clone, Copy)]
pub(crate) struct Pl031Rtc {
    base: usize,
}

impl RealTimeClock for Pl031Rtc {
    const SOURCE: &'static str = "pl031";

    fn read(&self) -> Result<UnixSeconds, RtcError> {
        let data_register = (self.base + PL031_DATA) as *const u32;
        // SAFETY: `map` verified `self.base` is mapped over at least
        // `PL031_DATA + size_of::<u32>()` bytes of Device-nGnRnE memory and
        // `data_register` is 4-byte aligned for reading `RTCDR`.
        let seconds = unsafe { data_register.read_volatile() };
        Ok(UnixSeconds::new(u64::from(seconds)))
    }
}

/// Maps the register window of the platform's PL031.
///
/// A machine that describes no PL031 has no calendar to read, and the
/// caller leaves the kernel's wall clock unseeded.
pub(crate) fn map(
    region: MmioRegion,
    physical_memory_offset: usize,
    handoff: &LimineBootHandoff,
) -> Pl031Rtc {
    assert!(
        region.size >= PL031_DATA + core::mem::size_of::<u32>(),
        "AArch64 PL031 window size {} is smaller than RTCDR",
        region.size
    );
    crate::map_mmio_range(region.base, region.size, physical_memory_offset, handoff);
    let base = crate::mmio_virtual_base(region.base, physical_memory_offset);
    assert!(
        (base + PL031_DATA).is_multiple_of(core::mem::align_of::<u32>()),
        "AArch64 PL031 RTCDR address {:#x} is not 4-byte aligned",
        base + PL031_DATA
    );
    Pl031Rtc { base }
}
