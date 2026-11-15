//! Hardware virtualization contracts, independent of the guest's software.
//!
//! A vCPU has one executor owner. Entry is bounded by a hardware timer and
//! returns with processor-local state detached, so the owner can migrate at
//! its next poll. Only its kick handle is shared with other processors.
//! Stage-2 mutations serialize in the VM owner; hardware walks and vCPU entry
//! can proceed on other processors. Revocations await explicit shootdown
//! acknowledgements. No page or page-table storage is reclaimed before them.
//!
//! Consumers: the kernel owns memory and scheduling; device emulation uses
//! exits and register snapshots. The split follows KVM's VM/vCPU/memory-slot
//! model, without its userspace-pointer ABI.

use core::future::Future;
use core::num::{NonZeroU8, NonZeroUsize};
use core::time::Duration;
use thiserror::Error;
use triomphe::Arc;

use crate::cpu::ProcessorId;
use crate::pmm::PhysFrame;
use crate::vmm::PageFlags;

mod unavailable;

/// Hardware limits, reported only when bounded execution and Stage-2 are usable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HvCapabilities {
    pub guest_address_bits: NonZeroU8,
    pub max_vcpus: NonZeroUsize,
}

/// A byte address in a guest's physical address space, never a host pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct GuestAddress(pub u64);

/// Nonempty, page-aligned, nonwrapping guest range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestRange {
    start: GuestAddress,
    bytes: usize,
}

impl GuestRange {
    pub fn new(start: GuestAddress, bytes: usize) -> Result<Self, HvError> {
        if bytes == 0
            || !bytes.is_multiple_of(PhysFrame::SIZE)
            || !start.0.is_multiple_of(PhysFrame::SIZE as u64)
            || start.0.checked_add(bytes as u64).is_none()
        {
            return Err(HvError::InvalidRange);
        }
        Ok(Self { start, bytes })
    }

    pub const fn start(self) -> GuestAddress {
        self.start
    }
    pub const fn byte_len(self) -> usize {
        self.bytes
    }
    pub const fn page_count(self) -> usize {
        self.bytes / PhysFrame::SIZE
    }
    pub const fn end(self) -> GuestAddress {
        GuestAddress(self.start.0 + self.bytes as u64)
    }
    pub fn overlaps(self, other: Self) -> bool {
        self.start < other.end() && other.start < self.end()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum HvError {
    #[error("hardware virtualization is unavailable")]
    Unavailable,
    #[error("guest range is empty, unaligned or overflows")]
    InvalidRange,
    #[error("guest range exceeds the hardware address width")]
    AddressWidth,
    #[error("guest mapping overlaps an existing region")]
    Overlap,
    #[error("guest region is not mapped")]
    NotMapped,
    #[error("virtualization control storage is exhausted")]
    OutOfMemory,
    #[error("invalid guest page permissions")]
    InvalidPermissions,
    #[error("vCPU identifier is already in use or exceeds the hardware limit")]
    InvalidVcpu,
    #[error("register value or register identifier is invalid")]
    InvalidRegister,
    #[error("virtual interrupt is invalid")]
    InvalidInterrupt,
    #[error("virtual interrupt queue is full")]
    InterruptQueueFull,
    #[error("vCPU has stopped")]
    Stopped,
    #[error("no matching exit is awaiting completion")]
    InvalidCompletion,
    #[error("hardware entry failed with status {status:#x}")]
    EntryFailed { status: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqLevel {
    Assert,
    Deassert,
    Pulse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtualIrq {
    pub number: u32,
    pub level: IrqLevel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoWidth {
    Byte,
    Word,
    Dword,
    Qword,
}

impl IoWidth {
    pub const fn bytes(self) -> usize {
        match self {
            Self::Byte => 1,
            Self::Word => 2,
            Self::Dword => 4,
            Self::Qword => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoAccess {
    Read { width: IoWidth },
    Write { width: IoWidth, value: u64 },
}

/// An architectural exit. Emulated instructions remain pending until
/// `complete_exit`; the backend owns PC advancement and register updates.
/// String/compound I/O is split into individual transfers by the backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmExit {
    Preempted,
    Halt,
    IrqWindow,
    Mmio {
        address: GuestAddress,
        access: IoAccess,
    },
    IoPort {
        port: u16,
        access: IoAccess,
    },
    Stage2Fault {
        address: GuestAddress,
        access: PageFlags,
    },
    SysReg {
        register: u32,
        access: IoAccess,
    },
    Msr {
        register: u32,
        access: IoAccess,
    },
    /// Arguments and results are in the architecture's register snapshot.
    Hypercall {
        number: u64,
    },
    Shutdown,
}

/// Cross-processor, interrupt-safe request for a vCPU to leave guest mode.
/// Implementations latch the request before sending an IPI and close the
/// check/entry race: a kick concurrent with entry must force an exit too.
/// A kick while detached must not target the previously owning processor.
/// The handle may outlive the vCPU; destruction revokes its hardware target.
pub trait VcpuKick: Send + Sync + 'static {
    fn kick(&self);
}

/// Single-owner architectural vCPU context. Registers stay typed per backend:
/// x86 segment/control state and ARM system registers are not interchangeable.
///
/// # Safety
/// Implementations retain their Stage-2 space until destruction. `run` and
/// `prepare_run` must leave no active guest, timer, VMCS or processor-local
/// reference on return (including errors). Preparation records configuration;
/// only `run` installs it on hardware. Entry without valid preparation returns
/// an error, never unbounded execution. `run` restores host
/// state, disarms its timer, and detaches before returning. Cached Stage-2
/// translations on a detached processor must be invalidated or acknowledged
/// through the space's shootdown protocol before storage can be reclaimed.
/// Dropping a detached vCPU must never access another processor's active state.
pub unsafe trait GuestVcpu: Send + 'static {
    type Registers: Send;
    type Kick: VcpuKick;

    fn kick_handle(&self) -> Arc<Self::Kick>;
    /// Called immediately before entry, without an await between the calls.
    /// Configures a hardware-enforced bound, armed inside `run` independently
    /// of guest IRQ masks. Hardware state cannot be left installed by this call.
    /// `previous` is diagnostic migration history, never permission to touch
    /// remote live state. A zero time slice must be refused.
    fn prepare_run(
        &mut self,
        current: ProcessorId,
        previous: Option<ProcessorId>,
        slice: Duration,
    ) -> Result<(), HvError>;
    fn run(&mut self) -> Result<VmExit, HvError>;
    /// Wait for an architectural wake source while detached (for example a
    /// guest timer). The runtime races this against externally injected IRQs.
    /// Cancellation must retain the deadline and all pending interrupt state.
    fn wait_for_interrupt(&mut self) -> impl Future<Output = Result<(), HvError>> + Send + '_;
    /// `false` leaves ownership with the caller: retry at an IRQ-window exit.
    fn inject_irq(&mut self, irq: VirtualIrq) -> Result<bool, HvError>;
    fn set_irq_window(&mut self, enabled: bool);
    fn get_regs(&mut self) -> Result<Self::Registers, HvError>;
    fn set_regs(&mut self, registers: &Self::Registers) -> Result<(), HvError>;
    /// Supply read data (or acknowledge a write) for the pending emulated exit.
    /// Reject a mismatched/no pending exit; never re-execute a completed write.
    fn complete_exit(&mut self, value: u64) -> Result<(), HvError>;
}

/// Stage-2 page tables and their processor participation/shootdown state.
///
/// # Safety
/// `map_pages` publishes only the supplied frames and permissions and is atomic
/// on error. Every mutation invalidates locally. Revocation snapshots all
/// processors that may cache the space and sends remote invalidations; entry
/// registers participation before loading the root, rechecks the generation,
/// and cannot race past a revocation. `unmap_pages`/`protect_pages` return only
/// after every required acknowledgement. Their futures are cancellation safe:
/// reissuing an interrupted operation converges, and dropping the future cannot
/// lose in-flight shootdown state. Neither operation releases guest frames.
/// `Drop` releases page-table storage only after all vCPUs are detached and no
/// processor can retain a stale translation. It must not busy-wait for software
/// work; remote invalidation must already be discharged by detach or revocation.
pub unsafe trait Stage2Space: Send + Sync + 'static {
    type Vcpu: GuestVcpu;

    fn capabilities(&self) -> HvCapabilities;
    fn create_vcpu(space: &Arc<Self>, id: u32) -> Result<Self::Vcpu, HvError>;
    /// # Safety
    /// Frames are initialized normal RAM, owned for the mapping's lifetime.
    /// No exclusive or non-atomic shared Rust reference may alias hardware
    /// access to the mapped bytes. Atomic host accesses are permitted.
    unsafe fn map_pages(
        &self,
        range: GuestRange,
        frames: &[PhysFrame],
        flags: PageFlags,
    ) -> Result<(), HvError>;
    /// Idempotent removal, including retry after cancellation. An unmapped
    /// range succeeds only once prior invalidations of it have completed.
    fn unmap_pages(
        &self,
        range: GuestRange,
    ) -> impl Future<Output = Result<(), HvError>> + Send + '_;
    fn protect_pages(
        &self,
        range: GuestRange,
        flags: PageFlags,
    ) -> impl Future<Output = Result<(), HvError>> + Send + '_;
}

/// Platform factory. `Cpu::hv` exposes it only when all required mechanisms
/// (including bounded entry) are available. Unsupported platforms use the
/// uninhabited `Infallible` implementation, never an executable stub.
pub trait Hypervisor: Send + Sync + 'static {
    type Space: Stage2Space;
    fn capabilities(&self) -> HvCapabilities;
    fn create_space(&self) -> Result<Self::Space, HvError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_ranges_reject_empty_unaligned_and_wrapping_input() {
        for (start, bytes) in [
            (0, 0),
            (1, PhysFrame::SIZE),
            (0, 1),
            (u64::MAX - PhysFrame::SIZE as u64 + 1, PhysFrame::SIZE),
        ] {
            assert_eq!(
                GuestRange::new(GuestAddress(start), bytes),
                Err(HvError::InvalidRange)
            );
        }
        let first = GuestRange::new(GuestAddress(0), PhysFrame::SIZE).unwrap();
        let next = GuestRange::new(first.end(), PhysFrame::SIZE).unwrap();
        assert!(!first.overlaps(next));
        assert!(first.overlaps(first));
    }
}
