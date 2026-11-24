//! Component resources retain concrete backend owners. Async calls take an
//! exclusive, cancellation-safe lease before releasing the store borrow.

use helios_hal::hv as hal;
use helios_hal::vmm::PageFlags;

use crate::hv::{GuestMemoryError, LeaseError, VmError};
use crate::wasmtime_adapter::bindings::hv::bindings::helios::hv::virtualization as wire;

impl From<hal::HvError> for wire::HvError {
    fn from(error: hal::HvError) -> Self {
        match error {
            hal::HvError::Unavailable => Self::Unavailable,
            hal::HvError::InvalidRange => Self::InvalidRange,
            hal::HvError::AddressWidth => Self::AddressWidth,
            hal::HvError::Overlap => Self::Overlap,
            hal::HvError::NotMapped => Self::NotMapped,
            hal::HvError::OutOfMemory => Self::OutOfMemory,
            hal::HvError::InvalidPermissions => Self::InvalidPermissions,
            hal::HvError::InvalidVcpu => Self::InvalidVcpu,
            hal::HvError::InvalidRegister => Self::InvalidRegister,
            hal::HvError::InvalidInterrupt => Self::InvalidInterrupt,
            hal::HvError::InterruptQueueFull => Self::InterruptQueueFull,
            hal::HvError::Stopped => Self::Stopped,
            hal::HvError::InvalidCompletion => Self::InvalidCompletion,
            hal::HvError::EntryFailed { status } => Self::EntryFailed(status),
        }
    }
}

impl From<GuestMemoryError> for wire::HvError {
    fn from(error: GuestMemoryError) -> Self {
        match error {
            GuestMemoryError::Budget { .. } => Self::MemoryBudget,
            GuestMemoryError::Frames(_) => Self::OutOfMemory,
            GuestMemoryError::Contended => Self::Busy,
            GuestMemoryError::Bounds | GuestMemoryError::Length => Self::Bounds,
        }
    }
}

impl From<VmError> for wire::HvError {
    fn from(error: VmError) -> Self {
        match error {
            VmError::Hardware(error) => error.into(),
            VmError::Memory(error) => error.into(),
        }
    }
}

impl From<LeaseError> for wire::HvError {
    fn from(error: LeaseError) -> Self {
        match error {
            LeaseError::Busy => Self::Busy,
            LeaseError::Closed => Self::Stopped,
        }
    }
}

impl From<wire::RegisterId> for hal::RegisterId {
    fn from(id: wire::RegisterId) -> Self {
        match id {
            wire::RegisterId::Aarch64X(index) => Self::Aarch64X(index),
            wire::RegisterId::Aarch64Sp => Self::Aarch64Sp,
            wire::RegisterId::Aarch64Pc => Self::Aarch64Pc,
            wire::RegisterId::Aarch64Pstate => Self::Aarch64Pstate,
            wire::RegisterId::X86Gpr(index) => Self::X86Gpr(index),
            wire::RegisterId::X86Rip => Self::X86Rip,
            wire::RegisterId::X86Rflags => Self::X86Rflags,
            wire::RegisterId::X86Control(index) => Self::X86Control(index),
            wire::RegisterId::X86Msr(index) => Self::X86Msr(index),
        }
    }
}

impl From<wire::IoWidth> for hal::IoWidth {
    fn from(width: wire::IoWidth) -> Self {
        match width {
            wire::IoWidth::Byte => Self::Byte,
            wire::IoWidth::Word => Self::Word,
            wire::IoWidth::Dword => Self::Dword,
            wire::IoWidth::Qword => Self::Qword,
        }
    }
}

impl From<hal::IoWidth> for wire::IoWidth {
    fn from(width: hal::IoWidth) -> Self {
        match width {
            hal::IoWidth::Byte => Self::Byte,
            hal::IoWidth::Word => Self::Word,
            hal::IoWidth::Dword => Self::Dword,
            hal::IoWidth::Qword => Self::Qword,
        }
    }
}

impl From<hal::IoAccess> for wire::IoAccess {
    fn from(access: hal::IoAccess) -> Self {
        match access {
            hal::IoAccess::Read { width } => Self::Read(width.into()),
            hal::IoAccess::Write { width, value } => Self::Write(wire::IoWrite {
                width: width.into(),
                value,
            }),
        }
    }
}

impl From<wire::Permissions> for PageFlags {
    fn from(access: wire::Permissions) -> Self {
        let mut flags = Self::empty();
        flags.set(Self::READ, access.contains(wire::Permissions::READ));
        flags.set(Self::WRITE, access.contains(wire::Permissions::WRITE));
        flags.set(Self::EXECUTE, access.contains(wire::Permissions::EXECUTE));
        flags
    }
}

impl From<PageFlags> for wire::Permissions {
    fn from(access: PageFlags) -> Self {
        let mut flags = Self::empty();
        if access.contains(PageFlags::READ) {
            flags |= Self::READ;
        }
        if access.contains(PageFlags::WRITE) {
            flags |= Self::WRITE;
        }
        if access.contains(PageFlags::EXECUTE) {
            flags |= Self::EXECUTE;
        }
        flags
    }
}

impl From<hal::VmExit> for wire::VmExit {
    fn from(exit: hal::VmExit) -> Self {
        match exit {
            hal::VmExit::Preempted => Self::Preempted,
            hal::VmExit::Halt => Self::Halt,
            hal::VmExit::IrqWindow => Self::IrqWindow,
            hal::VmExit::Mmio { address, access } => Self::Mmio(wire::MmioExit {
                address: address.0,
                access: access.into(),
            }),
            hal::VmExit::IoPort { port, access } => Self::IoPort(wire::PortExit {
                port,
                access: access.into(),
            }),
            hal::VmExit::Stage2Fault { address, access } => Self::Stage2Fault(wire::MemoryFault {
                address: address.0,
                access: access.into(),
            }),
            hal::VmExit::SysReg { register, access } => Self::SystemRegister(wire::RegisterExit {
                register,
                access: access.into(),
            }),
            hal::VmExit::Msr { register, access } => Self::Msr(wire::RegisterExit {
                register,
                access: access.into(),
            }),
            hal::VmExit::Hypercall { number } => Self::Hypercall(number),
            hal::VmExit::Shutdown => Self::Shutdown,
        }
    }
}

use super::super::StoreData;
use crate::hv::{GuestMemoryRegion, IoEvent, ResourceSlot, Vcpu, VcpuControl, VirtualMachine};
use crate::{ComponentHostNetwork, Storage};
use alloc::vec::Vec;
use core::num::NonZeroUsize;
use helios_hal::cpu::Cpu;
use helios_hal::hv::{GuestRegisters, GuestVcpu, Hypervisor, Stage2Space};
use wasmtime::component::{Accessor, HasSelf, Linker, Resource};

type Space<C> = <<C as Cpu>::Hypervisor as Hypervisor>::Space;
struct VmHandle<S: Stage2Space> {
    slot: ResourceSlot<VirtualMachine<S>>,
    control: crate::hv::VmControl<S>,
}
impl<S: Stage2Space> Drop for VmHandle<S> {
    fn drop(&mut self) {
        self.control.stop();
    }
}

type Kick<S> = <<S as Stage2Space>::Vcpu as GuestVcpu>::Kick;

struct VcpuHandle<S: Stage2Space> {
    slot: ResourceSlot<Vcpu<S>>,
    control: VcpuControl<Kick<S>>,
}
impl<S: Stage2Space> Drop for VcpuHandle<S> {
    fn drop(&mut self) {
        self.control.stop();
    }
}

fn typed<T, U: 'static>(handle: Resource<T>) -> Resource<U> {
    if handle.owned() {
        Resource::new_own(handle.rep())
    } else {
        Resource::new_borrow(handle.rep())
    }
}
fn range(address: u64, size: u64) -> Result<hal::GuestRange, wire::HvError> {
    hal::GuestRange::new(
        hal::GuestAddress(address),
        usize::try_from(size).map_err(|_| wire::HvError::InvalidRange)?,
    )
    .map_err(Into::into)
}

fn write_registers<S: Stage2Space>(
    cpu: &mut Vcpu<S>,
    values: Vec<wire::RegisterValue>,
) -> Result<(), hal::HvError> {
    let mut registers = cpu.get_regs()?;
    for register in values {
        registers.write(register.id.into(), register.value)?;
    }
    cpu.set_regs(&registers)
}

pub(in crate::wasmtime_adapter::component_host) fn add_hv_to_linker<
    C: Cpu + Clone,
    N: ComponentHostNetwork,
    S: Storage,
>(
    linker: &mut Linker<StoreData<C, N, S>>,
) -> wasmtime::Result<()> {
    wire::add_to_linker::<_, HasSelf<StoreData<C, N, S>>>(linker, |state| state)
}

impl<C: Cpu + Clone, N: ComponentHostNetwork, S: Storage> wire::Host for StoreData<C, N, S> {}

impl<C: Cpu + Clone, N: ComponentHostNetwork, S: Storage> wire::HostVm for StoreData<C, N, S> {
    fn create(
        &mut self,
        memory_limit: u64,
    ) -> wasmtime::Result<Result<Resource<wire::Vm>, wire::HvError>> {
        let Ok(cap) = self.process_authority().derive_virtualize_cap() else {
            return Ok(Err(wire::HvError::PermissionDenied));
        };
        let Ok(limit) = usize::try_from(memory_limit) else {
            return Ok(Err(wire::HvError::MemoryBudget));
        };
        if self.cpu.hv().is_none() {
            return Ok(Err(wire::HvError::Unavailable));
        }
        let vm =
            match crate::hv::create_vm(&self.cpu, crate::memory::user_memory_pool(), limit, cap) {
                Ok(vm) => vm,
                Err(error) => return Ok(Err(error.into())),
            };
        Ok(Ok(typed(self.table.push(VmHandle {
            control: vm.control(),
            slot: ResourceSlot::new(vm),
        })?)))
    }
    fn allocate_memory(
        &mut self,
        handle: Resource<wire::Vm>,
        address: u64,
        size: u64,
        access: wire::Permissions,
    ) -> wasmtime::Result<Result<Resource<wire::MemoryRegion>, wire::HvError>> {
        let range = match range(address, size) {
            Ok(range) => range,
            Err(error) => return Ok(Err(error)),
        };
        let slot = self.table.get(&typed::<_, VmHandle<Space<C>>>(handle))?;
        let mut vm = match slot.slot.take() {
            Ok(vm) => vm,
            Err(error) => return Ok(Err(error.into())),
        };
        let region = match vm.allocate_memory(range, access.into()) {
            Ok(region) => region,
            Err(error) => return Ok(Err(error.into())),
        };
        Ok(Ok(typed(self.table.push(region)?)))
    }
    fn create_vcpu(
        &mut self,
        handle: Resource<wire::Vm>,
        id: u32,
        pending_interrupts: u32,
    ) -> wasmtime::Result<Result<Resource<wire::Vcpu>, wire::HvError>> {
        let Some(capacity) = NonZeroUsize::new(pending_interrupts as usize) else {
            return Ok(Err(wire::HvError::InvalidInterrupt));
        };
        let slot = self.table.get(&typed::<_, VmHandle<Space<C>>>(handle))?;
        let mut vm = match slot.slot.take() {
            Ok(vm) => vm,
            Err(error) => return Ok(Err(error.into())),
        };
        let vcpu = match vm.create_vcpu(id, capacity) {
            Ok(vcpu) => vcpu,
            Err(error) => return Ok(Err(error.into())),
        };
        let control = vcpu.control();
        Ok(Ok(typed(self.table.push(VcpuHandle {
            slot: ResourceSlot::new(vcpu),
            control,
        })?)))
    }
    fn set_irq_line(
        &mut self,
        handle: Resource<wire::Vm>,
        vcpu_id: u32,
        number: u32,
        level: wire::IrqLevel,
    ) -> wasmtime::Result<Result<(), wire::HvError>> {
        let slot = self.table.get(&typed::<_, VmHandle<Space<C>>>(handle))?;
        let level = match level {
            wire::IrqLevel::Assert => hal::IrqLevel::Assert,
            wire::IrqLevel::Deassert => hal::IrqLevel::Deassert,
            wire::IrqLevel::Pulse => hal::IrqLevel::Pulse,
        };
        Ok(slot
            .control
            .set_irq_line(vcpu_id, hal::VirtualIrq { number, level })
            .map_err(Into::into))
    }
    fn register_ioevent(
        &mut self,
        handle: Resource<wire::Vm>,
        address: u64,
        width: wire::IoWidth,
        value: Option<u64>,
    ) -> wasmtime::Result<Result<Resource<wire::Ioevent>, wire::HvError>> {
        let slot = self.table.get(&typed::<_, VmHandle<Space<C>>>(handle))?;
        let vm = match slot.slot.take() {
            Ok(vm) => vm,
            Err(error) => return Ok(Err(error.into())),
        };
        let event = match vm.register_ioevent(hal::GuestAddress(address), width.into(), value) {
            Ok(event) => event,
            Err(error) => return Ok(Err(error.into())),
        };
        Ok(Ok(typed(self.table.push(ResourceSlot::new(event))?)))
    }
    fn drop(&mut self, handle: Resource<wire::Vm>) -> wasmtime::Result<()> {
        self.table.delete(typed::<_, VmHandle<Space<C>>>(handle))?;
        Ok(())
    }
}

impl<C: Cpu + Clone, N: ComponentHostNetwork, S: Storage, U: 'static> wire::HostVmWithStore<U>
    for HasSelf<StoreData<C, N, S>>
{
    async fn unmap_memory(
        accessor: &Accessor<U, Self>,
        handle: Resource<wire::Vm>,
        address: u64,
        size: u64,
    ) -> wasmtime::Result<Result<(), wire::HvError>> {
        let range = match range(address, size) {
            Ok(range) => range,
            Err(error) => return Ok(Err(error)),
        };
        let lease = accessor.with(|mut access| -> wasmtime::Result<_> {
            Ok(access
                .get()
                .table
                .get(&typed::<_, VmHandle<Space<C>>>(handle))?
                .slot
                .take())
        })?;
        let mut vm = match lease {
            Ok(vm) => vm,
            Err(error) => return Ok(Err(error.into())),
        };
        Ok(vm.unmap_memory(range).await.map_err(Into::into))
    }
    async fn protect_memory(
        accessor: &Accessor<U, Self>,
        handle: Resource<wire::Vm>,
        address: u64,
        size: u64,
        access: wire::Permissions,
    ) -> wasmtime::Result<Result<(), wire::HvError>> {
        let range = match range(address, size) {
            Ok(range) => range,
            Err(error) => return Ok(Err(error)),
        };
        let lease = accessor.with(|mut access| -> wasmtime::Result<_> {
            Ok(access
                .get()
                .table
                .get(&typed::<_, VmHandle<Space<C>>>(handle))?
                .slot
                .take())
        })?;
        let mut vm = match lease {
            Ok(vm) => vm,
            Err(error) => return Ok(Err(error.into())),
        };
        Ok(vm
            .protect_memory(range, access.into())
            .await
            .map_err(Into::into))
    }
}

impl<C: Cpu + Clone, N: ComponentHostNetwork, S: Storage> wire::HostMemoryRegion
    for StoreData<C, N, S>
{
    fn publish(
        &mut self,
        handle: Resource<wire::MemoryRegion>,
        offset: u64,
        length: u64,
    ) -> wasmtime::Result<Result<(), wire::HvError>> {
        let region = self.table.get(&typed::<_, GuestMemoryRegion>(handle))?;
        let Some(hardware) = self.cpu.hv() else {
            return Ok(Err(wire::HvError::Unavailable));
        };
        let (Ok(offset), Ok(length)) = (usize::try_from(offset), usize::try_from(length)) else {
            return Ok(Err(wire::HvError::Bounds));
        };
        Ok(region.publish(hardware, offset, length).map_err(Into::into))
    }
    fn read(
        &mut self,
        handle: Resource<wire::MemoryRegion>,
        offset: u64,
        length: u32,
    ) -> wasmtime::Result<Result<Vec<u8>, wire::HvError>> {
        let region = self.table.get(&typed::<_, GuestMemoryRegion>(handle))?;
        let Ok(offset) = usize::try_from(offset) else {
            return Ok(Err(wire::HvError::Bounds));
        };
        let length = length as usize;
        if offset
            .checked_add(length)
            .is_none_or(|end| end > region.range().byte_len())
        {
            return Ok(Err(wire::HvError::Bounds));
        }
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(length).is_err() {
            return Ok(Err(wire::HvError::OutOfMemory));
        }
        bytes.resize(length, 0);
        match region.read(offset, &mut bytes) {
            Ok(()) => Ok(Ok(bytes)),
            Err(error) => Ok(Err(error.into())),
        }
    }
    fn write(
        &mut self,
        handle: Resource<wire::MemoryRegion>,
        offset: u64,
        bytes: Vec<u8>,
    ) -> wasmtime::Result<Result<(), wire::HvError>> {
        let region = self.table.get(&typed::<_, GuestMemoryRegion>(handle))?;
        let Ok(offset) = usize::try_from(offset) else {
            return Ok(Err(wire::HvError::Bounds));
        };
        Ok(region.write(offset, &bytes).map_err(Into::into))
    }
    fn drop(&mut self, handle: Resource<wire::MemoryRegion>) -> wasmtime::Result<()> {
        self.table.delete(typed::<_, GuestMemoryRegion>(handle))?;
        Ok(())
    }
}

impl<C: Cpu + Clone, N: ComponentHostNetwork, S: Storage> wire::HostVcpu for StoreData<C, N, S> {
    fn reset(
        &mut self,
        handle: Resource<wire::Vcpu>,
    ) -> wasmtime::Result<Result<(), wire::HvError>> {
        let handle = self.table.get(&typed::<_, VcpuHandle<Space<C>>>(handle))?;
        let mut cpu = match handle.slot.take() {
            Ok(cpu) => cpu,
            Err(error) => return Ok(Err(error.into())),
        };
        Ok(cpu.reset().map_err(Into::into))
    }
    fn get_regs(
        &mut self,
        handle: Resource<wire::Vcpu>,
        ids: Vec<wire::RegisterId>,
    ) -> wasmtime::Result<Result<Vec<wire::RegisterValue>, wire::HvError>> {
        let handle = self.table.get(&typed::<_, VcpuHandle<Space<C>>>(handle))?;
        let mut cpu = match handle.slot.take() {
            Ok(cpu) => cpu,
            Err(error) => return Ok(Err(error.into())),
        };
        let registers = match cpu.get_regs() {
            Ok(registers) => registers,
            Err(error) => return Ok(Err(error.into())),
        };
        Ok(ids
            .into_iter()
            .map(|id| {
                registers
                    .read(id.into())
                    .map(|value| wire::RegisterValue { id, value })
                    .map_err(Into::into)
            })
            .collect())
    }
    fn set_regs(
        &mut self,
        handle: Resource<wire::Vcpu>,
        values: Vec<wire::RegisterValue>,
    ) -> wasmtime::Result<Result<(), wire::HvError>> {
        let handle = self.table.get(&typed::<_, VcpuHandle<Space<C>>>(handle))?;
        let mut cpu = match handle.slot.take() {
            Ok(cpu) => cpu,
            Err(error) => return Ok(Err(error.into())),
        };
        Ok(write_registers(&mut cpu, values).map_err(Into::into))
    }
    fn complete_exit(
        &mut self,
        handle: Resource<wire::Vcpu>,
        value: u64,
    ) -> wasmtime::Result<Result<(), wire::HvError>> {
        let handle = self.table.get(&typed::<_, VcpuHandle<Space<C>>>(handle))?;
        let mut cpu = match handle.slot.take() {
            Ok(cpu) => cpu,
            Err(error) => return Ok(Err(error.into())),
        };
        Ok(cpu.complete_exit(value).map_err(Into::into))
    }
    fn kick(&mut self, handle: Resource<wire::Vcpu>) -> wasmtime::Result<()> {
        self.table
            .get(&typed::<_, VcpuHandle<Space<C>>>(handle))?
            .control
            .kick();
        Ok(())
    }
    fn drop(&mut self, handle: Resource<wire::Vcpu>) -> wasmtime::Result<()> {
        self.table
            .delete(typed::<_, VcpuHandle<Space<C>>>(handle))?;
        Ok(())
    }
}
impl<C: Cpu + Clone, N: ComponentHostNetwork, S: Storage, U: 'static> wire::HostVcpuWithStore<U>
    for HasSelf<StoreData<C, N, S>>
{
    async fn run(
        accessor: &Accessor<U, Self>,
        handle: Resource<wire::Vcpu>,
    ) -> wasmtime::Result<Result<wire::VmExit, wire::HvError>> {
        let lease = accessor.with(|mut access| -> wasmtime::Result<_> {
            Ok(access
                .get()
                .table
                .get(&typed::<_, VcpuHandle<Space<C>>>(handle))?
                .slot
                .take())
        })?;
        let mut cpu = match lease {
            Ok(cpu) => cpu,
            Err(error) => return Ok(Err(error.into())),
        };
        Ok(cpu.run_vcpu().await.map(Into::into).map_err(Into::into))
    }
}
impl<C: Cpu + Clone, N: ComponentHostNetwork, S: Storage> wire::HostIoevent for StoreData<C, N, S> {
    fn drop(&mut self, handle: Resource<wire::Ioevent>) -> wasmtime::Result<()> {
        self.table
            .delete(typed::<_, ResourceSlot<IoEvent>>(handle))?;
        Ok(())
    }
}
impl<C: Cpu + Clone, N: ComponentHostNetwork, S: Storage, U: 'static> wire::HostIoeventWithStore<U>
    for HasSelf<StoreData<C, N, S>>
{
    async fn wait(
        accessor: &Accessor<U, Self>,
        handle: Resource<wire::Ioevent>,
    ) -> wasmtime::Result<Result<(), wire::HvError>> {
        let lease = accessor.with(|mut access| -> wasmtime::Result<_> {
            Ok(access
                .get()
                .table
                .get(&typed::<_, ResourceSlot<IoEvent>>(handle))?
                .take())
        })?;
        let event = match lease {
            Ok(event) => event,
            Err(error) => return Ok(Err(error.into())),
        };
        Ok(event.wait().await.map_err(Into::into))
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_store::{DiscardPort, store_data_authorized, store_data_with};
    use super::*;
    use crate::component::{ComponentOutputMode, ComponentStoreData};
    use crate::hv::tests::TestHypervisor;
    use crate::isa::GuestIsa;
    use crate::memory::{UserMemoryPool, install_user_memory_pool, installed_user_memory_pool};
    use crate::test_support::{TestCpu, TestNetworkService, UnsupportedStorage};
    use crate::wasmtime_adapter::component_host::HostRuntimeState;
    use crate::{
        Executor, InstanceRegistry, MachineAuthorityRights, ProcessAuthority, TaskFunding,
    };
    use core::alloc::Layout;
    use helios_hal::cpu::{Instant, ProcessorId, Timebase, TimerInterrupt};
    use helios_hal::entropy::{EntropyQuality, EntropyUnavailable};
    use helios_hal::pmm::PhysFrame;
    use helios_hal::watchdog::ProgressCounter;
    use triomphe::Arc;
    use wasmtime::component::ResourceTable;
    use wire::{HostMemoryRegion, HostVm};

    #[derive(Clone)]
    struct HvTestCpu {
        inner: TestCpu,
        hv: TestHypervisor,
    }

    impl HvTestCpu {
        fn new() -> Self {
            Self {
                inner: TestCpu::with_entropy(0x5a),
                hv: TestHypervisor::default(),
            }
        }
    }

    impl Cpu for HvTestCpu {
        type Hypervisor = TestHypervisor;
        type Native = core::convert::Infallible;
        const TIMER_INTERRUPT: TimerInterrupt = TimerInterrupt::Deadline;

        fn has_lazy_commit_virtual_memory(&self) -> bool {
            self.inner.has_lazy_commit_virtual_memory()
        }

        fn processor_count(&self) -> usize {
            self.inner.processor_count()
        }

        fn bootstrap_processor(&self) -> ProcessorId {
            self.inner.bootstrap_processor()
        }

        fn park_current(&self) {
            self.inner.park_current();
        }

        type WakeOnlyMask = ();

        fn mask_to_wake_only(&self) {
            self.inner.mask_to_wake_only();
        }

        fn park_wake_only(&self, slot: &core::sync::atomic::AtomicU8, expected: u8) {
            self.inner.park_wake_only(slot, expected);
        }

        fn start_processor(&self, id: ProcessorId) {
            self.inner.start_processor(id);
        }

        fn wake_processor(&self, id: ProcessorId) {
            self.inner.wake_processor(id);
        }

        fn stop_current(&self) {
            self.inner.stop_current();
        }

        fn restart_processor(&self, id: ProcessorId) {
            self.inner.restart_processor(id);
        }

        fn now(&self) -> Instant {
            self.inner.now()
        }

        fn timebase(&self) -> Timebase {
            self.inner.timebase()
        }

        fn set_deadline(&self, deadline: Instant) {
            self.inner.set_deadline(deadline);
        }

        fn publish_executable(&self, ptr: *const u8, len: usize) {
            self.inner.publish_executable(ptr, len);
        }

        fn unpublish_executable(&self, ptr: *const u8, len: usize) {
            self.inner.unpublish_executable(ptr, len);
        }

        fn native_feature_probe(&self) -> Option<fn(&str) -> Option<bool>> {
            self.inner.native_feature_probe()
        }

        fn fill_entropy(&self, buffer: &mut [u8]) -> Result<EntropyQuality, EntropyUnavailable> {
            self.inner.fill_entropy(buffer)
        }

        fn hv(&self) -> Option<&Self::Hypervisor> {
            Some(&self.hv)
        }

        fn shutdown(&self) -> ! {
            self.inner.shutdown()
        }

        fn reboot(&self) -> ! {
            self.inner.reboot()
        }
    }

    fn read_nothing(_: &mut Vec<u8>, _: u32) {}

    fn ensure_user_pool() {
        const POOL_BYTES: usize = 4 * 1024 * 1024;
        if installed_user_memory_pool().is_some() {
            return;
        }
        let layout = Layout::from_size_align(POOL_BYTES, PhysFrame::SIZE).expect("pool layout");
        // SAFETY: nonzero size, leaked for the lifetime of the test process.
        let base = unsafe { alloc::alloc::alloc_zeroed(layout) } as usize;
        assert!(base != 0, "pool backing");
        install_user_memory_pool(UserMemoryPool::single_node(1, &[(base, base + POOL_BYTES)]));
    }

    fn hv_store_data(
        authority: ProcessAuthority,
    ) -> StoreData<HvTestCpu, TestNetworkService, UnsupportedStorage> {
        let cpu = HvTestCpu::new();
        let runtime_state: HostRuntimeState<HvTestCpu, TestNetworkService, UnsupportedStorage> =
            crate::RuntimeState::new(
                cpu.timebase(),
                1,
                0,
                crate::BootPayload::for_tests(),
                GuestIsa::for_build_target(cpu.native_feature_probe()),
            );
        runtime_state.install_root_entropy(Arc::new(
            crate::RootEntropy::from_platform(
                &cpu,
                None,
                None,
                crate::MachineGeneration::new(None),
            )
            .expect("the fixture CPU has an entropy source"),
        ));
        let executor = Executor::new(
            ProgressCounter::new(),
            crate::test_support::single_node_pool(1),
            ProcessorId::new(0),
        );
        let registry = InstanceRegistry::new();
        let instance = registry.register("hv-store", 0);
        ComponentStoreData::new(
            ResourceTable::new(),
            cpu.clone(),
            executor.timer(cpu.clone()),
            executor
                .spawner(cpu)
                .instance_spawner(TaskFunding::Instance, &instance),
            runtime_state.clone(),
            registry,
            instance,
            runtime_state.root_namespace().descend(),
            Vec::new(),
            Vec::new(),
            authority,
            ComponentOutputMode::Serial,
            read_nothing,
            crate::DebugSerialWriter::of::<DiscardPort>(),
        )
    }

    #[test]
    fn invalid_register_batch_preserves_the_original_snapshot() {
        let mut vm = crate::hv::tests::vm([], 0);
        let mut cpu = vm.create_vcpu(0, NonZeroUsize::new(1).unwrap()).unwrap();
        let values = alloc::vec![
            wire::RegisterValue {
                id: wire::RegisterId::Aarch64X(0),
                value: 42
            },
            wire::RegisterValue {
                id: wire::RegisterId::Aarch64X(31),
                value: 7
            },
        ];
        assert_eq!(
            write_registers(&mut cpu, values),
            Err(hal::HvError::InvalidRegister)
        );
        assert_eq!(
            cpu.get_regs().unwrap().read(hal::RegisterId::Aarch64X(0)),
            Ok(0)
        );
    }

    #[test]
    fn create_refuses_callers_without_virtualize_authority() {
        let mut empty_store = store_data_with(|_| {});
        assert!(matches!(
            HostVm::create(&mut empty_store, 128 << 20).unwrap(),
            Err(wire::HvError::PermissionDenied)
        ));

        let mut root_store = hv_store_data(ProcessAuthority::root());
        assert!(matches!(
            HostVm::create(&mut root_store, 128 << 20).unwrap(),
            Err(wire::HvError::PermissionDenied)
        ));

        let mut cpu_ctrl_only = ProcessAuthority::root();
        cpu_ctrl_only.grant_machine_rights(MachineAuthorityRights::CONTROL);
        let mut cpu_ctrl_store = hv_store_data(cpu_ctrl_only);
        assert!(matches!(
            HostVm::create(&mut cpu_ctrl_store, 128 << 20).unwrap(),
            Err(wire::HvError::PermissionDenied)
        ));
    }

    #[test]
    fn unavailable_platform_does_not_access_the_user_pool() {
        let mut authority = ProcessAuthority::empty();
        authority.grant_machine_rights(MachineAuthorityRights::VIRTUALIZE);
        let mut store = store_data_authorized(authority, |_| {});
        assert!(matches!(
            HostVm::create(&mut store, 128 << 20).unwrap(),
            Err(wire::HvError::Unavailable)
        ));
    }

    #[test]
    fn create_succeeds_when_virtualize_authority_is_granted() {
        ensure_user_pool();
        let mut authority = ProcessAuthority::empty();
        authority.grant_machine_rights(MachineAuthorityRights::VIRTUALIZE);
        let mut store = hv_store_data(authority);
        let handle = HostVm::create(&mut store, PhysFrame::SIZE as u64)
            .unwrap()
            .expect("authorized caller on HV-capable platform may create a VM");
        HostVm::drop(&mut store, handle).unwrap();
    }

    #[test]
    fn memory_resource_checks_bounds_and_retains_its_user_frames_after_vm_drop() {
        let mut store = store_data_with(|_| {});
        let mut vm = crate::hv::tests::vm([], 1);
        let region = vm
            .allocate_memory(
                range(0, PhysFrame::SIZE as u64).unwrap(),
                PageFlags::READ | PageFlags::WRITE,
            )
            .unwrap();
        let account = vm.memory_account().clone();
        let handle: Resource<wire::MemoryRegion> = typed(store.table.push(region).unwrap());
        let id = handle.rep();
        drop(vm);
        assert_eq!(account.allocated_bytes(), PhysFrame::SIZE);
        assert!(
            HostMemoryRegion::write(
                &mut store,
                Resource::new_borrow(id),
                3,
                alloc::vec![1, 2, 3]
            )
            .unwrap()
            .is_ok()
        );
        assert_eq!(
            HostMemoryRegion::read(&mut store, Resource::new_borrow(id), 2, 4)
                .unwrap()
                .unwrap(),
            [0, 1, 2, 3]
        );
        assert!(matches!(
            HostMemoryRegion::read(&mut store, Resource::new_borrow(id), u64::MAX, u32::MAX)
                .unwrap(),
            Err(wire::HvError::Bounds)
        ));
        assert!(matches!(
            HostMemoryRegion::write(
                &mut store,
                Resource::new_borrow(id),
                PhysFrame::SIZE as u64 - 1,
                alloc::vec![9, 9]
            )
            .unwrap(),
            Err(wire::HvError::Bounds)
        ));
        assert_eq!(
            HostMemoryRegion::read(
                &mut store,
                Resource::new_borrow(id),
                PhysFrame::SIZE as u64 - 1,
                1
            )
            .unwrap()
            .unwrap(),
            [0]
        );
        HostMemoryRegion::drop(&mut store, handle).unwrap();
        assert_eq!(account.allocated_bytes(), 0);
    }
}
