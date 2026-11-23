//! libFuzzer drives one input at a time in a host process. Coverage retains
//! HAL functions even when the reader never calls them, so the final binary
//! supplies the same single-processor linkage as the host benchmarks.
use helios_hal::cpu::ProcessorId;
use helios_hal::critical_section::LocalInterruptMask;

#[unsafe(no_mangle)]
extern "Rust" fn helios_current_processor() -> ProcessorId {
    ProcessorId::new(0)
}

struct HostInterruptMask;

impl LocalInterruptMask for HostInterruptMask {
    fn mask() -> bool {
        false
    }

    unsafe fn restore(_was_enabled: bool) {}
}

helios_hal::critical_section::set_local_interrupt_mask_impl!(HostInterruptMask);
