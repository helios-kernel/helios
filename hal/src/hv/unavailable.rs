use core::convert::Infallible;
use core::time::Duration;
use triomphe::Arc;

use super::*;

impl Hypervisor for Infallible {
    type Space = Self;
    fn capabilities(&self) -> HvCapabilities {
        match *self {}
    }
    fn create_space(&self) -> Result<Self, HvError> {
        match *self {}
    }
    unsafe fn synchronize_memory(&self, _: &[PhysFrame]) {
        match *self {}
    }
}

// SAFETY: no value of this type can exist, so none of these methods can execute.
unsafe impl Stage2Space for Infallible {
    type Vcpu = Self;
    fn capabilities(&self) -> HvCapabilities {
        match *self {}
    }
    fn create_vcpu(space: &Arc<Self>, _: u32) -> Result<Self, HvError> {
        match **space {}
    }
    unsafe fn map_pages(
        &self,
        _: GuestRange,
        _: &[PhysFrame],
        _: PageFlags,
    ) -> Result<(), HvError> {
        match *self {}
    }
    async fn unmap_pages(&self, _: GuestRange) -> Result<(), HvError> {
        match *self {}
    }
    async fn protect_pages(&self, _: GuestRange, _: PageFlags) -> Result<(), HvError> {
        match *self {}
    }
}

impl VcpuKick for Infallible {
    fn kick(&self) {
        match *self {}
    }
}

impl GuestRegisters for Infallible {
    fn read(&self, _: RegisterId) -> Result<u64, HvError> {
        match *self {}
    }
    fn write(&mut self, _: RegisterId, _: u64) -> Result<(), HvError> {
        match *self {}
    }
}

// SAFETY: uninhabited; there is no guest execution or state to detach.
unsafe impl GuestVcpu for Infallible {
    type Registers = Self;
    type Kick = Self;
    fn kick_handle(&self) -> Arc<Self> {
        match *self {}
    }
    fn prepare_run(
        &mut self,
        _: ProcessorId,
        _: Option<ProcessorId>,
        _: Duration,
    ) -> Result<(), HvError> {
        match *self {}
    }
    fn run(&mut self) -> Result<VmExit, HvError> {
        match *self {}
    }
    async fn wait_for_interrupt(&mut self) -> Result<(), HvError> {
        match *self {}
    }
    fn inject_irq(&mut self, _: VirtualIrq) -> Result<bool, HvError> {
        match *self {}
    }
    fn set_irq_window(&mut self, _: bool) {
        match *self {}
    }
    fn get_regs(&mut self) -> Result<Self, HvError> {
        match *self {}
    }
    fn set_regs(&mut self, _: &Self) -> Result<(), HvError> {
        match *self {}
    }
    fn complete_exit(&mut self, _: u64) -> Result<(), HvError> {
        match *self {}
    }
}
