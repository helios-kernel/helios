//! Lock-free per-VM telemetry counters and kernel-wide VM telemetry registry.
//!
//! # Concurrency contract
//!
//! - Every counter written by a vCPU or memory mutation path is a lock-free
//!   atomic (`CachePadded<AtomicU64>` for hot cross-processor counters).
//! - Registering and unregistering a VM takes a short `IrqSafeMutex` on the
//!   registry; snapshot reads clone `Arc<VmTelemetry>` handles under that lock
//!   and read every counter lock-free after releasing it.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crossbeam_utils::CachePadded;
use helios_hal::hv::VmExit;
use helios_hal::pmm::PhysFrame;
use triomphe::Arc;

use crate::InstanceId;
use crate::memory::IrqSafeMutex;

/// Point-in-time telemetry snapshot of one live virtual machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HvVmSnapshot {
    pub id: u64,
    pub owner_instance: Option<InstanceId>,
    pub vmid: Option<u32>,
    pub stage2_pages: u64,
    pub stage2_bytes: u64,
    pub allocated_bytes: u64,
    pub memory_limit_bytes: u64,
    pub vcpus: u64,
    pub vcpu_exits_total: u64,
    pub vcpu_exits_preempted: u64,
    pub vcpu_exits_halt: u64,
    pub vcpu_exits_irq_window: u64,
    pub vcpu_exits_mmio: u64,
    pub vcpu_exits_io_port: u64,
    pub vcpu_exits_stage2_fault: u64,
    pub vcpu_exits_sysreg: u64,
    pub vcpu_exits_msr: u64,
    pub vcpu_exits_hypercall: u64,
    pub vcpu_exits_shutdown: u64,
    pub ioevent_registrations: u64,
    pub ioevent_hits: u64,
}

/// Live atomic telemetry counters owned by one [`super::VirtualMachine`].
///
/// Hot counters (`stage2_pages`, `vcpu_exits_total`, `ioevent_hits`) sit on
/// padded cache lines so vCPU threads and memory mutations on distinct
/// processors do not false-share with each other or with static metadata.
pub(crate) struct VmTelemetry {
    id: u64,
    owner_instance: Option<InstanceId>,
    vmid: Option<u32>,
    account: Arc<super::GuestMemoryAccount>,
    stage2_pages: CachePadded<AtomicU64>,
    vcpus: AtomicU64,
    vcpu_exits_total: CachePadded<AtomicU64>,
    vcpu_exits_preempted: AtomicU64,
    vcpu_exits_halt: AtomicU64,
    vcpu_exits_irq_window: AtomicU64,
    vcpu_exits_mmio: AtomicU64,
    vcpu_exits_io_port: AtomicU64,
    vcpu_exits_stage2_fault: AtomicU64,
    vcpu_exits_sysreg: AtomicU64,
    vcpu_exits_msr: AtomicU64,
    vcpu_exits_hypercall: AtomicU64,
    vcpu_exits_shutdown: AtomicU64,
    ioevent_registrations: AtomicU64,
    ioevent_hits: CachePadded<AtomicU64>,
}

impl VmTelemetry {
    pub(crate) fn new(
        id: u64,
        owner_instance: Option<InstanceId>,
        vmid: Option<u32>,
        account: Arc<super::GuestMemoryAccount>,
    ) -> Self {
        Self {
            id,
            owner_instance,
            vmid,
            account,
            stage2_pages: CachePadded::new(AtomicU64::new(0)),
            vcpus: AtomicU64::new(0),
            vcpu_exits_total: CachePadded::new(AtomicU64::new(0)),
            vcpu_exits_preempted: AtomicU64::new(0),
            vcpu_exits_halt: AtomicU64::new(0),
            vcpu_exits_irq_window: AtomicU64::new(0),
            vcpu_exits_mmio: AtomicU64::new(0),
            vcpu_exits_io_port: AtomicU64::new(0),
            vcpu_exits_stage2_fault: AtomicU64::new(0),
            vcpu_exits_sysreg: AtomicU64::new(0),
            vcpu_exits_msr: AtomicU64::new(0),
            vcpu_exits_hypercall: AtomicU64::new(0),
            vcpu_exits_shutdown: AtomicU64::new(0),
            ioevent_registrations: AtomicU64::new(0),
            ioevent_hits: CachePadded::new(AtomicU64::new(0)),
        }
    }

    pub(crate) const fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn add_stage2_pages(&self, pages: usize) {
        self.stage2_pages.fetch_add(pages as u64, Ordering::Relaxed);
    }

    pub(crate) fn sub_stage2_pages(&self, pages: usize) {
        self.stage2_pages.fetch_sub(pages as u64, Ordering::Relaxed);
    }

    pub(crate) fn inc_vcpus(&self) {
        self.vcpus.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dec_vcpus(&self) {
        self.vcpus.fetch_sub(1, Ordering::Relaxed);
    }

    pub(crate) fn record_exit(&self, exit: VmExit) {
        self.vcpu_exits_total.fetch_add(1, Ordering::Relaxed);
        let bucket = match exit {
            VmExit::Preempted => &self.vcpu_exits_preempted,
            VmExit::Halt => &self.vcpu_exits_halt,
            VmExit::IrqWindow => &self.vcpu_exits_irq_window,
            VmExit::Mmio { .. } => &self.vcpu_exits_mmio,
            VmExit::IoPort { .. } => &self.vcpu_exits_io_port,
            VmExit::Stage2Fault { .. } => &self.vcpu_exits_stage2_fault,
            VmExit::SysReg { .. } => &self.vcpu_exits_sysreg,
            VmExit::Msr { .. } => &self.vcpu_exits_msr,
            VmExit::Hypercall { .. } => &self.vcpu_exits_hypercall,
            VmExit::Shutdown => &self.vcpu_exits_shutdown,
        };
        bucket.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_ioevents(&self) {
        self.ioevent_registrations.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dec_ioevents(&self) {
        self.ioevent_registrations.fetch_sub(1, Ordering::Relaxed);
    }

    pub(crate) fn record_ioevent_hit(&self) {
        self.ioevent_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> HvVmSnapshot {
        let stage2_pages = self.stage2_pages.load(Ordering::Relaxed);
        HvVmSnapshot {
            id: self.id,
            owner_instance: self.owner_instance,
            vmid: self.vmid,
            stage2_pages,
            stage2_bytes: stage2_pages.saturating_mul(PhysFrame::SIZE as u64),
            allocated_bytes: self.account.allocated_bytes() as u64,
            memory_limit_bytes: self.account.limit() as u64,
            vcpus: self.vcpus.load(Ordering::Relaxed),
            vcpu_exits_total: self.vcpu_exits_total.load(Ordering::Relaxed),
            vcpu_exits_preempted: self.vcpu_exits_preempted.load(Ordering::Relaxed),
            vcpu_exits_halt: self.vcpu_exits_halt.load(Ordering::Relaxed),
            vcpu_exits_irq_window: self.vcpu_exits_irq_window.load(Ordering::Relaxed),
            vcpu_exits_mmio: self.vcpu_exits_mmio.load(Ordering::Relaxed),
            vcpu_exits_io_port: self.vcpu_exits_io_port.load(Ordering::Relaxed),
            vcpu_exits_stage2_fault: self.vcpu_exits_stage2_fault.load(Ordering::Relaxed),
            vcpu_exits_sysreg: self.vcpu_exits_sysreg.load(Ordering::Relaxed),
            vcpu_exits_msr: self.vcpu_exits_msr.load(Ordering::Relaxed),
            vcpu_exits_hypercall: self.vcpu_exits_hypercall.load(Ordering::Relaxed),
            vcpu_exits_shutdown: self.vcpu_exits_shutdown.load(Ordering::Relaxed),
            ioevent_registrations: self.ioevent_registrations.load(Ordering::Relaxed),
            ioevent_hits: self.ioevent_hits.load(Ordering::Relaxed),
        }
    }
}

struct HvTelemetryInner {
    next_id: AtomicU64,
    vms: IrqSafeMutex<Vec<Arc<VmTelemetry>>>,
}

/// Kernel-wide registry of live virtual machines exposed under `/kernel/hv/*`.
#[derive(Clone)]
pub struct HvTelemetryRegistry {
    inner: Arc<HvTelemetryInner>,
}

impl Default for HvTelemetryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl HvTelemetryRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(HvTelemetryInner {
                next_id: AtomicU64::new(1),
                vms: IrqSafeMutex::new(Vec::new()),
            }),
        }
    }

    pub(crate) fn register(
        &self,
        owner_instance: Option<InstanceId>,
        vmid: Option<u32>,
        account: Arc<super::GuestMemoryAccount>,
    ) -> VmTelemetryGuard {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let telemetry = Arc::new(VmTelemetry::new(id, owner_instance, vmid, account));
        self.inner.vms.with(|vms| vms.push(telemetry.clone()));
        VmTelemetryGuard {
            registry: Some(self.clone()),
            telemetry,
        }
    }

    /// Snapshots every live virtual machine ordered by kernel VM identifier.
    pub fn snapshot(&self) -> Vec<HvVmSnapshot> {
        let handles: Vec<Arc<VmTelemetry>> = self.inner.vms.with(|vms| vms.clone());
        let mut snapshots: Vec<HvVmSnapshot> = handles.iter().map(|vm| vm.snapshot()).collect();
        snapshots.sort_unstable_by_key(|vm| vm.id);
        snapshots
    }
}

/// RAII guard unregistering a VM from [`HvTelemetryRegistry`] when its shared
/// state drops (after all vCPUs and regions have detached).
pub(crate) struct VmTelemetryGuard {
    registry: Option<HvTelemetryRegistry>,
    telemetry: Arc<VmTelemetry>,
}

impl VmTelemetryGuard {
    pub(crate) fn unregistered(vmid: Option<u32>, account: Arc<super::GuestMemoryAccount>) -> Self {
        Self {
            registry: None,
            telemetry: Arc::new(VmTelemetry::new(0, None, vmid, account)),
        }
    }

    pub(crate) fn telemetry(&self) -> &Arc<VmTelemetry> {
        &self.telemetry
    }
}

impl Drop for VmTelemetryGuard {
    fn drop(&mut self) {
        if let Some(registry) = &self.registry {
            let id = self.telemetry.id();
            registry.inner.vms.with(|vms| {
                vms.retain(|entry| entry.id() != id);
            });
        }
    }
}
