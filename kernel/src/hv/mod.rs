//! Kernel-owned virtual machines and their asynchronous execution boundary.
//!
//! One `VirtualMachine` serializes map/protect/unmap operations through `&mut`.
//! Each vCPU runs independently on one executor task and retains the VM's RAM.
//! Brief IRQ-safe locks protect the live-resource lists only, never span an
//! await or guest entry. Guest bytes use atomic copies, so accessors expose no
//! Rust references into memory hardware can concurrently change. Hardware
//! backends own the Stage-2 participant set and acknowledgement protocol.

use alloc::vec::Vec;
use core::num::NonZeroUsize;
use helios_hal::cpu::Cpu;
use helios_hal::hv::{
    GuestAddress, GuestRange, GuestVcpu, HvError, Hypervisor, IoWidth, Stage2Space, VirtualIrq,
};
use helios_hal::vmm::PageFlags;
use thiserror::Error;
use triomphe::Arc;

use crate::memory::{IrqSafeMutex, UserMemoryPool};

mod ioevent;
mod lease;
mod memory;
mod telemetry;
pub use ioevent::IoEvent;
use ioevent::IoEvents;
pub use lease::{LeaseError, ResourceLease, ResourceSlot};
mod shootdown;
pub use shootdown::{Stage2Generation, Stage2Shootdown, Stage2Tracker};
pub use telemetry::{HvTelemetryRegistry, HvVmSnapshot};
use telemetry::{VmTelemetry, VmTelemetryGuard};
#[cfg(test)]
pub(crate) mod tests;
mod vcpu;

use memory::GuestPages;
pub use memory::{GuestMemoryAccount, GuestMemoryError, GuestMemoryRegion, GuestSlice};
use vcpu::VcpuSignals;
pub use vcpu::{Vcpu, VcpuControl};

type KickOf<S> = <<S as Stage2Space>::Vcpu as GuestVcpu>::Kick;

#[derive(Debug, Error)]
pub enum VmError {
    #[error(transparent)]
    Hardware(#[from] HvError),
    #[error(transparent)]
    Memory(#[from] GuestMemoryError),
}

type LiveVcpus<S> = Vec<(u32, Arc<VcpuSignals<KickOf<S>>>)>;

struct VmShared<S: Stage2Space> {
    // Field order matters: invalidate/release Stage-2 before releasing RAM.
    space: Arc<S>,
    regions: IrqSafeMutex<Vec<GuestMemoryRegion>>,
    vcpus: IrqSafeMutex<LiveVcpus<S>>,
    ioevents: Arc<IoEvents>,
    telemetry: VmTelemetryGuard,
}

/// Unique VM control owner. Dropping it requests termination of all its vCPUs;
/// their leases retain mappings until each detached vCPU has been dropped.
/// WIT resource destruction must drop both these leases and region handles.
pub struct VirtualMachine<S: Stage2Space> {
    shared: Arc<VmShared<S>>,
    pool: &'static UserMemoryPool,
    account: Arc<GuestMemoryAccount>,
}

pub struct VmControl<S: Stage2Space> {
    shared: Arc<VmShared<S>>,
}

impl<S: Stage2Space> VmControl<S> {
    pub fn stop(&self) {
        self.shared.ioevents.stop();
        self.shared.vcpus.with(|vcpus| {
            for (_, signals) in vcpus {
                signals.stop();
            }
        });
    }

    pub fn set_irq_line(&self, vcpu_id: u32, irq: VirtualIrq) -> Result<(), HvError> {
        let signals = self
            .shared
            .vcpus
            .with(|vcpus| {
                vcpus
                    .iter()
                    .find(|(id, _)| *id == vcpu_id)
                    .map(|(_, signals)| signals.clone())
            })
            .ok_or(HvError::InvalidVcpu)?;
        VcpuControl::from_signals(signals).inject_irq(irq)
    }
}

impl<S: Stage2Space> VirtualMachine<S> {
    pub fn control(&self) -> VmControl<S> {
        VmControl {
            shared: self.shared.clone(),
        }
    }
    pub fn new(space: S, pool: &'static UserMemoryPool, memory_limit: usize) -> Self {
        let account = Arc::new(GuestMemoryAccount::new(memory_limit));
        let telemetry = VmTelemetryGuard::unregistered(space.vmid(), account.clone());
        Self::with_telemetry(space, pool, account, telemetry)
    }

    pub fn new_observed(
        space: S,
        pool: &'static UserMemoryPool,
        memory_limit: usize,
        registry: &HvTelemetryRegistry,
        owner_instance: Option<crate::InstanceId>,
    ) -> Self {
        let account = Arc::new(GuestMemoryAccount::new(memory_limit));
        let telemetry = registry.register(owner_instance, space.vmid(), account.clone());
        Self::with_telemetry(space, pool, account, telemetry)
    }

    fn with_telemetry(
        space: S,
        pool: &'static UserMemoryPool,
        account: Arc<GuestMemoryAccount>,
        telemetry: VmTelemetryGuard,
    ) -> Self {
        let ioevents = Arc::new(IoEvents::new(telemetry.telemetry().clone()));
        Self {
            shared: Arc::new(VmShared {
                space: Arc::new(space),
                regions: IrqSafeMutex::new(Vec::new()),
                vcpus: IrqSafeMutex::new(Vec::new()),
                ioevents,
                telemetry,
            }),
            pool,
            account,
        }
    }
    pub fn memory_account(&self) -> &Arc<GuestMemoryAccount> {
        &self.account
    }

    pub fn register_ioevent(
        &self,
        address: GuestAddress,
        width: IoWidth,
        value: Option<u64>,
    ) -> Result<IoEvent, HvError> {
        IoEvents::register(&self.shared.ioevents, address, width, value)
    }

    pub fn set_irq_line(&self, vcpu_id: u32, irq: VirtualIrq) -> Result<(), HvError> {
        self.control().set_irq_line(vcpu_id, irq)
    }

    pub fn allocate_memory(
        &mut self,
        range: GuestRange,
        flags: PageFlags,
    ) -> Result<GuestMemoryRegion, VmError> {
        let bits = self.shared.space.capabilities().guest_address_bits.get();
        if bits < u64::BITS as u8 && range.end().0 > (1u64 << bits) {
            return Err(HvError::AddressWidth.into());
        }
        if self
            .shared
            .regions
            .with(|regions| regions.iter().any(|region| region.range.overlaps(range)))
        {
            return Err(HvError::Overlap.into());
        }
        let pages = GuestPages::allocate(self.pool, &self.account, range.byte_len())?;
        // SAFETY: GuestPages owns zeroed user-domain frames. It stays in the
        // region list until unmap has acknowledged every shootdown, or the
        // last vCPU has detached and the Stage-2 space has been destroyed.
        unsafe {
            self.shared.space.map_pages(range, pages.frames(), flags)?;
        }
        let region = GuestMemoryRegion { range, pages };
        self.shared
            .regions
            .with(|regions| regions.push(region.clone()));
        self.shared
            .telemetry
            .telemetry()
            .add_stage2_pages(range.page_count());
        Ok(region)
    }

    pub async fn unmap_memory(&mut self, range: GuestRange) -> Result<(), VmError> {
        self.check_region(range)?;
        // Cancellation leaves ownership in regions. Reissuing unmap is
        // idempotent at the HAL boundary, including in-flight invalidations.
        self.shared.space.unmap_pages(range).await?;
        let retired = self.shared.regions.with(|regions| {
            let index = regions
                .iter()
                .position(|region| region.range == range)
                .expect("exclusive VM owner lost a mapped region");
            regions.swap_remove(index)
        });
        self.shared
            .telemetry
            .telemetry()
            .sub_stage2_pages(range.page_count());
        drop(retired);
        Ok(())
    }

    pub async fn protect_memory(
        &mut self,
        range: GuestRange,
        flags: PageFlags,
    ) -> Result<(), VmError> {
        self.check_region(range)?;
        self.shared.space.protect_pages(range, flags).await?;
        Ok(())
    }

    fn check_region(&self, range: GuestRange) -> Result<(), HvError> {
        self.shared.regions.with(|regions| {
            if regions.iter().any(|region| region.range == range) {
                Ok(())
            } else {
                Err(HvError::NotMapped)
            }
        })
    }

    pub fn create_vcpu(
        &mut self,
        id: u32,
        pending_interrupts: NonZeroUsize,
    ) -> Result<Vcpu<S>, HvError> {
        if id as usize >= self.shared.space.capabilities().max_vcpus.get()
            || self
                .shared
                .vcpus
                .with(|vcpus| vcpus.iter().any(|(existing, _)| *existing == id))
        {
            return Err(HvError::InvalidVcpu);
        }
        let backend = S::create_vcpu(&self.shared.space, id)?;
        let signals = Arc::new(VcpuSignals::new(backend.kick_handle(), pending_interrupts));
        self.shared
            .vcpus
            .with(|vcpus| vcpus.push((id, signals.clone())));
        self.shared.telemetry.telemetry().inc_vcpus();
        Ok(Vcpu::new(id, backend, signals, self.shared.clone()))
    }
}

impl<S: Stage2Space> Drop for VirtualMachine<S> {
    fn drop(&mut self) {
        self.control().stop();
    }
}

/// Construct through the backend capability, refusing unsupported platforms.
pub fn create_vm<C: Cpu>(
    cpu: &C,
    pool: &'static UserMemoryPool,
    memory_limit: usize,
    _cap: crate::VirtualizeCap,
) -> Result<VirtualMachine<<C::Hypervisor as Hypervisor>::Space>, VmError> {
    let hv = cpu.hv().ok_or(HvError::Unavailable)?;
    Ok(VirtualMachine::new(hv.create_space()?, pool, memory_limit))
}

/// Construct a VM registered with `registry` so `/kernel/hv/*` reflects its
/// live Stage-2 pages, VMID, vCPU exits, and ioevent hits.
pub fn create_vm_observed<C: Cpu>(
    cpu: &C,
    pool: &'static UserMemoryPool,
    memory_limit: usize,
    _cap: crate::VirtualizeCap,
    registry: &HvTelemetryRegistry,
    owner_instance: Option<crate::InstanceId>,
) -> Result<VirtualMachine<<C::Hypervisor as Hypervisor>::Space>, VmError> {
    let hv = cpu.hv().ok_or(HvError::Unavailable)?;
    Ok(VirtualMachine::new_observed(
        hv.create_space()?,
        pool,
        memory_limit,
        registry,
        owner_instance,
    ))
}
