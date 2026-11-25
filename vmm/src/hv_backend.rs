//! Zero-`dyn` hypervisor control contracts for IRQ injection and `ioevent` registration.
//!
//! Implementing these traits for [`helios_api::hv::Vm`] keeps production calls
//! monomorphized while allowing host unit tests to drive the GIC, virtqueues,
//! and `ioevent` fast path directly.

use helios_api::hv::{self, GuestPhysAddr, IoEvent, IoEventBackend, IoWidth, IrqLevel, Vm};

use crate::error::Result;

/// Target capable of asserting, deasserting, or pulsing virtual IRQ lines.
pub trait IrqTarget {
    fn set_irq_line(&self, vcpu_id: u32, number: u32, level: IrqLevel) -> Result<()>;
}

impl IrqTarget for Vm {
    fn set_irq_line(&self, vcpu_id: u32, number: u32, level: IrqLevel) -> Result<()> {
        Ok(Vm::set_irq_line(self, vcpu_id, number, level)?)
    }
}

/// Target capable of registering kernel-completed MMIO write notifications.
pub trait IoEventRegistrar {
    type Backend: IoEventBackend;

    fn register_ioevent(
        &self,
        address: GuestPhysAddr,
        width: IoWidth,
        match_value: Option<u64>,
    ) -> Result<IoEvent<Self::Backend>>;
}

impl IoEventRegistrar for Vm {
    type Backend = hv::raw::Ioevent;

    fn register_ioevent(
        &self,
        address: GuestPhysAddr,
        width: IoWidth,
        match_value: Option<u64>,
    ) -> Result<IoEvent<Self::Backend>> {
        Ok(Vm::register_ioevent(self, address, width, match_value)?)
    }
}
