//! VHE hardware virtualization. A vCPU has one owner; only its latched kick
//! handle is shared. Entry holds a local interrupt mask, never a VM lock.
//! Each space owns a unique VMID until its final broadcast invalidation.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::arch::asm;
use core::num::{NonZeroU8, NonZeroUsize};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::time::Duration;
use crossbeam_utils::CachePadded;
use helios_hal::cpu::{ProcessorId, Timebase, current_processor};
use helios_hal::critical_section::with_local_interrupts_masked;
use helios_hal::hv::{
    GuestRange, GuestVcpu, HvCapabilities, HvError, Hypervisor as HypervisorContract, IrqLevel,
    Stage2Space, VcpuKick, VirtualIrq, VmExit,
};
use helios_hal::pmm::PhysFrame;
use helios_hal::vmm::PageFlags;
use triomphe::Arc;

use crate::{Aarch64PlatformState, current_processor_runtime, gic};
use context::{Context, helios_aarch64_enter_guest};
use exit::Completion;
use tables::Tables;
use vgic::Vgic;

mod context;
mod debug;
mod exit;
mod features;
#[cfg(helios_hv_self_test)]
pub(super) mod self_test;
mod tables;
mod vgic;
pub use context::Registers;

macro_rules! read {
    ($reg:ident) => {{
        let value: u64;
        unsafe { asm!(concat!("mrs {value}, ", stringify!($reg)),
            value = out(reg) value, options(nomem, nostack, preserves_flags)); }
        value
    }};
}
macro_rules! write {
    ($reg:ident, $value:expr) => {{
        let value: u64 = $value;
        unsafe { asm!(concat!("msr ", stringify!($reg), ", {value}"),
            value = in(reg) value, options(nomem, nostack, preserves_flags)); }
    }};
}

// HCR bits from the Arm ARM: VHE and AArch64 guest, Stage-2, physical
// interrupt routing, WFx and ID-register traps, and guest PAuth access.
const GUEST_HCR: u64 =
    (1 << 34) | (1 << 31) | 1 | (7 << 3) | (3 << 13) | (1 << 18) | (1 << 19) | (3 << 40);

struct Hardware {
    timebase: Timebase,
    mpidrs: Box<[u64]>,
    // All processors allocate/release shared bitmap words. Separate words
    // occupy separate lines so unrelated VMID ranges do not contend.
    vmids: Box<[CachePadded<AtomicU64>]>,
    capabilities: HvCapabilities,
    vtcr: u64,
    vgic: vgic::Capabilities,
    features: features::Features,
    debug: debug::Capabilities,
}

pub struct Hypervisor {
    hardware: Arc<Hardware>,
}

impl Hypervisor {
    pub(super) fn discover(platform: &'static Aarch64PlatformState) -> Option<Self> {
        if crate::current_exception_level() != 2 << 2 {
            return None;
        }
        let hcr = read!(hcr_el2);
        assert_eq!(
            hcr & ((1 << 34) | (1 << 27)),
            (1 << 34) | (1 << 27),
            "EL2 host requires HCR_EL2.E2H and TGE, got {hcr:#x}"
        );
        let mmfr0 = read!(id_aa64mmfr0_el1);
        let ps = (mmfr0 & 15).min(5) as usize;
        // ID_AA64MMFR0_EL1.PARange encodings through 48 bits. The
        // four-level, 4 KiB Stage-2 format does not use LPA2 descriptors.
        let address_bits = [32, 36, 40, 42, 44, 48][ps];
        let vmid16 = (read!(id_aa64mmfr1_el1) >> 4) & 15 == 2;
        let vmid_count = 1usize << if vmid16 { 16 } else { 8 };
        let capabilities = HvCapabilities {
            guest_address_bits: NonZeroU8::new(address_bits).unwrap(),
            // MPIDR has four eight-bit affinity fields.
            max_vcpus: NonZeroUsize::new(1usize << 32).unwrap(),
        };
        // VTCR: RES1, PS, inner-shareable write-back walks, level-zero
        // or level-one root, 4 KiB granule, T0SZ, and VMID width.
        let vtcr = (1 << 31)
            | ((ps as u64) << 16)
            | (3 << 12)
            | (1 << 10)
            | (1 << 8)
            | (if address_bits > 39 { 2 } else { 1 } << 6)
            | u64::from(64 - address_bits)
            | if vmid16 { 1 << 19 } else { 0 };
        Some(Self {
            hardware: Arc::new(Hardware {
                timebase: platform.timebase,
                mpidrs: platform.processor_mpidrs().collect(),
                vmids: (0..vmid_count / 64)
                    .map(|index| CachePadded::new(AtomicU64::new(u64::from(index == 0))))
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                capabilities,
                vtcr,
                vgic: vgic::Capabilities::read(),
                features: features::Features::discover(ps as u64),
                debug: debug::Capabilities::discover(),
            }),
        })
    }
}

impl HypervisorContract for Hypervisor {
    unsafe fn synchronize_memory(&self, frames: &[PhysFrame]) {
        let line = crate::cache_line_bytes();
        for frame in frames {
            for offset in (0..PhysFrame::SIZE).step_by(line) {
                let address = frame.phys_addr() + offset;
                // Clean to PoC, as required for an EL1 Linux Image with its
                // MMU disabled; PoU alone does not establish that contract.
                unsafe {
                    asm!("dc cvac, {address}", address = in(reg) address, options(nostack));
                }
            }
        }
        // Guest instruction addresses need not match the host aliases used
        // above, so invalidate all inner-shareable instruction caches.
        unsafe {
            asm!("dsb ish", "ic ialluis", "dsb ish", "isb", options(nostack));
        }
    }
    type Space = Space;
    fn capabilities(&self) -> HvCapabilities {
        self.hardware.capabilities
    }
    fn create_space(&self) -> Result<Space, HvError> {
        let id = self
            .hardware
            .vmids
            .iter()
            .enumerate()
            .find_map(|(index, used)| {
                used.try_update(Ordering::AcqRel, Ordering::Relaxed, |bits| {
                    (bits != u64::MAX).then(|| bits | (1 << bits.trailing_ones()))
                })
                .ok()
                .map(|old| (index * 64 + old.trailing_ones() as usize) as u16)
            })
            .ok_or(HvError::OutOfMemory)?;
        Ok(Space {
            tables: Tables::new(
                id,
                crate::physical_memory_offset(),
                self.hardware.capabilities.guest_address_bits.get(),
            ),
            lease: VmidLease {
                id,
                hardware: self.hardware.clone(),
            },
        })
    }
}

struct VmidLease {
    id: u16,
    hardware: Arc<Hardware>,
}
impl Drop for VmidLease {
    fn drop(&mut self) {
        self.hardware.vmids[usize::from(self.id) / 64]
            .fetch_and(!(1 << (self.id % 64)), Ordering::Release);
    }
}

pub struct Space {
    // Invalidate/drop page tables before allowing another VM to reuse the ID.
    tables: Tables,
    lease: VmidLease,
}

// SAFETY: tables serialize publication and complete broadcast invalidation
// before returning or freeing storage; each vCPU retains this space by Arc.
unsafe impl Stage2Space for Space {
    type Vcpu = Vcpu;
    fn capabilities(&self) -> HvCapabilities {
        self.lease.hardware.capabilities
    }
    fn create_vcpu(space: &Arc<Self>, id: u32) -> Result<Vcpu, HvError> {
        Ok(Vcpu {
            space: space.clone(),
            kick: Arc::new(Kick {
                hardware: space.lease.hardware.clone(),
                pending: CachePadded::new(AtomicBool::new(false)),
                target: CachePadded::new(AtomicUsize::new(0)),
            }),
            context: Context::new(GUEST_HCR),
            debug: debug::State::new(space.lease.hardware.debug),
            vgic: Vgic::new(space.lease.hardware.vgic),
            id,
            prepared: None,
            completion: None,
            timer_signalled: [false; 2],
            failed: false,
        })
    }
    unsafe fn map_pages(
        &self,
        range: GuestRange,
        frames: &[PhysFrame],
        flags: PageFlags,
    ) -> Result<(), HvError> {
        unsafe { self.tables.map(range, frames, flags) }
    }
    async fn unmap_pages(&self, range: GuestRange) -> Result<(), HvError> {
        self.tables.unmap(range)
    }
    async fn protect_pages(&self, range: GuestRange, flags: PageFlags) -> Result<(), HvError> {
        self.tables.protect(range, flags)
    }
}

pub struct Kick {
    hardware: Arc<Hardware>,
    // Remote producers write pending; the owner publishes/revokes target.
    pending: CachePadded<AtomicBool>,
    target: CachePadded<AtomicUsize>,
}
impl VcpuKick for Kick {
    fn kick(&self) {
        self.pending.store(true, Ordering::SeqCst);
        let target = self.target.load(Ordering::SeqCst);
        if target != 0 {
            gic::send_wake(self.hardware.mpidrs[target - 1]);
        }
    }
}

pub struct Vcpu {
    space: Arc<Space>,
    kick: Arc<Kick>,
    context: Context,
    debug: debug::State,
    vgic: Vgic,
    id: u32,
    prepared: Option<(ProcessorId, Duration)>,
    completion: Option<Completion>,
    timer_signalled: [bool; 2],
    failed: bool,
}

impl Vcpu {
    fn timer_state(&self) -> [(u64, u64, u32); 2] {
        let system = &self.context.system;
        [
            (system.cntv_ctl, system.cntv_cval, 27),
            (system.cntp_ctl, system.cntp_cval, 30),
        ]
    }
    fn refresh_timers(&mut self) -> Result<(), HvError> {
        let now = read!(cntpct_el0);
        for (index, (control, deadline, number)) in self.timer_state().into_iter().enumerate() {
            let asserted = control & 3 == 1 && deadline <= now;
            self.timer_signalled[index] = asserted;
            if !self.vgic.inject(VirtualIrq {
                number,
                level: if asserted {
                    IrqLevel::Assert
                } else {
                    IrqLevel::Deassert
                },
            })? {
                self.vgic.set_window(true);
            }
        }
        Ok(())
    }
    fn enter(&mut self, processor: ProcessorId, slice: Duration) -> Result<VmExit, HvError> {
        self.kick
            .target
            .store(usize::from(processor.id()) + 1, Ordering::SeqCst);
        if self.kick.pending.swap(false, Ordering::SeqCst) {
            self.kick.target.store(0, Ordering::SeqCst);
            return Ok(VmExit::Preempted);
        }
        let saved_vttbr = read!(vttbr_el2);
        let saved_vtcr = read!(vtcr_el2);
        let saved_offset = read!(cntvoff_el2);
        let saved_cnthctl = read!(cnthctl_el2);
        let saved_vmpidr = read!(vmpidr_el2);
        let saved_vpidr = read!(vpidr_el2);
        let saved_cptr = read!(cptr_el2);
        let saved_mdcr = read!(mdcr_el2);
        write!(vtcr_el2, self.space.lease.hardware.vtcr);
        write!(vttbr_el2, self.space.tables.vttbr() as u64);
        // VMIDs retain translations across switches. Table mutations and
        // final VMID release complete their own broadcast invalidation.
        write!(cntvoff_el2, 0u64);
        // E2H shifts EL1 physical-counter/timer access enables to bits 10/11.
        write!(cnthctl_el2, 3u64 << 10);
        let affinity =
            u64::from(self.id & 0x00ff_ffff) | (u64::from(self.id & 0xff00_0000) << 8) | (1 << 31);
        write!(vmpidr_el2, affinity);
        write!(vpidr_el2, read!(midr_el1));
        // Permit FP/SIMD. SVE/SME accesses remain trapped; their state is not
        // part of this virtual CPU's advertised feature set.
        write!(cptr_el2, 3u64 << 20);
        // Trap debug register access, PMU and OS Lock. Debug exceptions remain
        // directed to guest EL1 (TDE=0), where its own debugger handles them.
        write!(mdcr_el2, (1u64 << 6) | (1 << 9) | (1 << 10));
        self.vgic.install();
        self.context.slice_ticks = self
            .space
            .lease
            .hardware
            .timebase
            .duration_to_ticks(slice)
            .max(1);
        let now = read!(cntpct_el0);
        // The switch arms the host timer after context restoration, so host
        // setup cannot consume the guest's execution slice. It also observes
        // the next guest deadline; guest timer PPIs stay masked in the GIC.
        self.context.timer_deadline = self
            .timer_state()
            .into_iter()
            .filter(|(control, deadline, _)| control & 3 == 1 && *deadline > now)
            .map(|(_, deadline, _)| deadline)
            .min()
            .unwrap_or(0);
        unsafe {
            asm!("isb", options(nostack, preserves_flags));
        }
        // SAFETY: preparation validated the mode, Stage-2 owns all guest
        // translations, and CNTHP plus HCR.IMO bound entry independently of
        // the guest's interrupt masks. The assembly restores the host first.
        let host_debug = self.debug.enter();
        unsafe {
            helios_aarch64_enter_guest(&mut self.context);
        }
        host_debug.restore();
        write!(cnthp_ctl_el2, 0u64);
        self.vgic.detach();
        write!(vttbr_el2, saved_vttbr);
        write!(vtcr_el2, saved_vtcr);
        write!(cntvoff_el2, saved_offset);
        write!(cnthctl_el2, saved_cnthctl);
        write!(vmpidr_el2, saved_vmpidr);
        write!(vpidr_el2, saved_vpidr);
        write!(cptr_el2, saved_cptr);
        write!(mdcr_el2, saved_mdcr);
        unsafe {
            asm!("isb", options(nostack, preserves_flags));
        }
        self.kick.target.store(0, Ordering::SeqCst);
        match self.context.exit_kind {
            0 => {
                let (exit, completion) = exit::decode(
                    &mut self.context.registers,
                    self.context.esr,
                    self.context.hpfar,
                    self.context.far,
                    |address| self.space.tables.contains(address),
                )?;
                if let VmExit::SysReg {
                    register,
                    access: helios_hal::hv::IoAccess::Read { .. },
                } = exit
                    && let Some(value) = if register == 0xc028 {
                        Some(self.space.lease.hardware.debug.id)
                    } else {
                        self.space.lease.hardware.features.register(register)
                    }
                {
                    completion
                        .expect("ID register trap carries completion")
                        .apply(&mut self.context.registers, value);
                    return Ok(VmExit::Preempted);
                }
                // MDSCR_EL1 is already banked with the guest context. TDA
                // traps access so no guest can access host debug state.
                if let VmExit::SysReg {
                    register: 0x8012,
                    access,
                } = exit
                {
                    let value = match access {
                        helios_hal::hv::IoAccess::Read { .. } => self.context.system.mdscr,
                        helios_hal::hv::IoAccess::Write { value, .. } => {
                            self.context.system.mdscr = value;
                            0
                        }
                    };
                    completion
                        .expect("MDSCR trap carries completion")
                        .apply(&mut self.context.registers, value);
                    return Ok(VmExit::Preempted);
                }
                if let VmExit::SysReg { register, access } = exit
                    && let Some(value) = self
                        .debug
                        .register(register, access)
                        .or_else(|| self.vgic.register(register, access))
                {
                    completion
                        .expect("GIC CPU-interface trap carries completion")
                        .apply(&mut self.context.registers, value);
                    return Ok(VmExit::Preempted);
                }
                self.completion = completion;
                Ok(exit)
            }
            1 | 5 => Ok(VmExit::Preempted),
            _ => Err(HvError::EntryFailed {
                status: self.context.esr,
            }),
        }
    }
}

// SAFETY: the sole owner installs context only under the local interrupt
// mask; every return restores host state, disables the slice timer, unloads
// Stage-2 and revokes the kick target. Arc retains all mapped storage.
unsafe impl GuestVcpu for Vcpu {
    type Registers = Registers;
    type Kick = Kick;
    fn kick_handle(&self) -> Arc<Kick> {
        self.kick.clone()
    }
    fn prepare_run(
        &mut self,
        current: ProcessorId,
        _: Option<ProcessorId>,
        slice: Duration,
    ) -> Result<(), HvError> {
        if slice.is_zero() || current != current_processor() {
            return Err(HvError::InvalidVcpu);
        }
        self.prepared = Some((current, slice));
        Ok(())
    }
    fn run(&mut self) -> Result<VmExit, HvError> {
        if self.failed {
            return Err(HvError::Stopped);
        }
        if self.completion.is_some() {
            return Err(HvError::InvalidCompletion);
        }
        let (processor, slice) = self.prepared.take().ok_or(HvError::InvalidVcpu)?;
        self.refresh_timers()?;
        let result = with_local_interrupts_masked(|| self.enter(processor, slice));
        self.failed = result.is_err();
        result
    }
    async fn wait_for_interrupt(&mut self) -> Result<(), HvError> {
        let deadline = self
            .timer_state()
            .into_iter()
            .enumerate()
            .filter(|(index, (control, _, _))| control & 3 == 1 && !self.timer_signalled[*index])
            .map(|(_, (_, deadline, _))| deadline)
            .min();
        if let Some(deadline) = deadline {
            let remaining = deadline.saturating_sub(read!(cntpct_el0));
            let duration =
                Duration::from_nanos(self.space.lease.hardware.timebase.ticks_to_nanos(remaining));
            let timer = current_processor_runtime()
                .timer
                .get()
                .expect("vCPU wait requires an installed kernel timer")
                .clone();
            timer.sleep_for(duration).await;
            Ok(())
        } else {
            core::future::pending().await
        }
    }
    fn inject_irq(&mut self, irq: VirtualIrq) -> Result<bool, HvError> {
        self.vgic.inject(irq)
    }
    fn set_irq_window(&mut self, enabled: bool) {
        self.vgic.set_window(enabled);
    }
    fn reset(&mut self) -> Result<(), HvError> {
        self.context = Context::new(GUEST_HCR);
        self.debug = debug::State::new(self.space.lease.hardware.debug);
        self.vgic = Vgic::new(self.space.lease.hardware.vgic);
        self.prepared = None;
        self.completion = None;
        self.timer_signalled = [false; 2];
        self.failed = false;
        self.kick.pending.store(false, Ordering::Release);
        Ok(())
    }
    fn get_regs(&mut self) -> Result<Registers, HvError> {
        if self.failed {
            return Err(HvError::Stopped);
        }
        Ok(self.context.registers)
    }
    fn set_regs(&mut self, registers: &Registers) -> Result<(), HvError> {
        if self.failed {
            return Err(HvError::Stopped);
        }
        // Never permit a VMM to return into EL2, AArch32, or an unaligned PC.
        if !matches!(registers.pstate & 31, 0 | 4 | 5) || registers.pc & 3 != 0 {
            return Err(HvError::InvalidRegister);
        }
        self.context.registers = *registers;
        Ok(())
    }
    fn complete_exit(&mut self, value: u64) -> Result<(), HvError> {
        self.completion
            .take()
            .ok_or(HvError::InvalidCompletion)?
            .apply(&mut self.context.registers, value);
        Ok(())
    }
}

impl Drop for Vcpu {
    fn drop(&mut self) {
        self.kick.target.store(0, Ordering::SeqCst);
    }
}
