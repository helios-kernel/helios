use concurrent_queue::{ConcurrentQueue, PushError};
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicBool, Ordering};
use crossbeam_utils::CachePadded;
use helios_hal::cpu::{ProcessorId, current_processor};
use helios_hal::hv::{GuestVcpu, HvError, Stage2Space, VcpuKick, VirtualIrq, VmExit};
use triomphe::Arc;

use super::{KickOf, VmShared};
use crate::exec::{GUEST_TIME_SLICE, Notify, yield_now};

pub(super) struct VcpuSignals<K: VcpuKick> {
    kick: Arc<K>,
    irqs: ConcurrentQueue<VirtualIrq>,
    capacity: usize,
    // Shared by remote producers and the owner, isolated from queue indices.
    requested: CachePadded<AtomicBool>,
    stopped: CachePadded<AtomicBool>,
    wake: Notify,
}

impl<K: VcpuKick> VcpuSignals<K> {
    pub(super) fn new(kick: Arc<K>, capacity: NonZeroUsize) -> Self {
        Self {
            kick,
            irqs: ConcurrentQueue::bounded(capacity.get()),
            capacity: capacity.get(),
            requested: CachePadded::new(AtomicBool::new(false)),
            stopped: CachePadded::new(AtomicBool::new(false)),
            wake: Notify::new(),
        }
    }
    fn wake(&self) {
        self.kick.kick();
        self.wake.notify_all();
    }
    pub(super) fn stop(&self) {
        self.irqs.close();
        self.stopped.store(true, Ordering::Release);
        self.wake();
    }
    fn ready(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
            || self.requested.load(Ordering::Acquire)
            || !self.irqs.is_empty()
    }
}

/// Interrupt-safe sender; remote callers never borrow the architectural vCPU.
/// Virtual timer/device IRQ producers use this same route to wake a halted CPU.
pub struct VcpuControl<K: VcpuKick> {
    signals: Arc<VcpuSignals<K>>,
}
impl<K: VcpuKick> Clone for VcpuControl<K> {
    fn clone(&self) -> Self {
        Self {
            signals: self.signals.clone(),
        }
    }
}
impl<K: VcpuKick> VcpuControl<K> {
    pub fn inject_irq(&self, irq: VirtualIrq) -> Result<(), HvError> {
        self.signals.irqs.push(irq).map_err(|error| match error {
            PushError::Full(_) => HvError::InterruptQueueFull,
            PushError::Closed(_) => HvError::Stopped,
        })?;
        self.signals.wake();
        Ok(())
    }
    /// Interrupt this run, returning `Preempted` to the VMM after yielding.
    pub fn kick(&self) {
        self.signals.requested.store(true, Ordering::Release);
        self.signals.wake();
    }
    pub fn stop(&self) {
        self.signals.stop();
    }
}

pub struct Vcpu<S: Stage2Space> {
    // Drop architectural references before the VM's final memory lease.
    backend: S::Vcpu,
    _registration: VcpuRegistration<S>,
    signals: Arc<VcpuSignals<KickOf<S>>>,
    previous: Option<ProcessorId>,
    pending: Option<VirtualIrq>,
}
impl<S: Stage2Space> Vcpu<S> {
    pub(super) fn new(
        id: u32,
        backend: S::Vcpu,
        signals: Arc<VcpuSignals<KickOf<S>>>,
        shared: Arc<VmShared<S>>,
    ) -> Self {
        Self {
            backend,
            _registration: VcpuRegistration { shared, id },
            signals,
            previous: None,
            pending: None,
        }
    }
    pub fn control(&self) -> VcpuControl<KickOf<S>> {
        VcpuControl {
            signals: self.signals.clone(),
        }
    }
    pub fn previous_processor(&self) -> Option<ProcessorId> {
        self.previous
    }
    pub fn get_regs(&mut self) -> Result<<S::Vcpu as GuestVcpu>::Registers, HvError> {
        self.backend.get_regs()
    }
    pub fn set_regs(
        &mut self,
        registers: &<S::Vcpu as GuestVcpu>::Registers,
    ) -> Result<(), HvError> {
        self.backend.set_regs(registers)
    }
    pub fn complete_exit(&mut self, value: u64) -> Result<(), HvError> {
        self.backend.complete_exit(value)
    }

    /// Hardware preemption becomes a cooperative yield. An emulation exit is
    /// returned to the owner; halt parks with the notification armed before the
    /// IRQ/kick check. Each entry is detached before any suspension, including
    /// cancellation and migration to another executor processor.
    pub async fn run_vcpu(&mut self) -> Result<VmExit, HvError> {
        loop {
            if self.signals.stopped.load(Ordering::Acquire) {
                return Ok(VmExit::Shutdown);
            }
            if self.signals.requested.swap(false, Ordering::AcqRel) {
                yield_now().await;
                return Ok(VmExit::Preempted);
            }
            // Bounded draining prevents an IRQ producer monopolizing this poll.
            for _ in 0..self.signals.capacity {
                if self.pending.is_none() {
                    self.pending = self.signals.irqs.pop().ok();
                }
                let Some(irq) = self.pending else { break };
                if !self.backend.inject_irq(irq)? {
                    break;
                }
                self.pending = None;
            }
            self.backend.set_irq_window(self.pending.is_some());
            let processor = current_processor();
            self.backend
                .prepare_run(processor, self.previous, GUEST_TIME_SLICE)?;
            self.previous = Some(processor);
            let exit = self.backend.run()?;
            match exit {
                VmExit::Preempted | VmExit::IrqWindow => yield_now().await,
                VmExit::Halt => {
                    let wake = self.signals.wake.notified();
                    if !self.signals.ready() && self.pending.is_none() {
                        wake.await;
                    } else {
                        yield_now().await;
                    }
                }
                exit => return Ok(exit),
            }
        }
    }
}
impl<S: Stage2Space> Drop for Vcpu<S> {
    fn drop(&mut self) {
        self.signals.stop();
    }
}

// Dropped after the architectural context: the VM must not reuse an ID while
// the previous backend is still releasing its interrupt/controller state.
struct VcpuRegistration<S: Stage2Space> {
    shared: Arc<VmShared<S>>,
    id: u32,
}
impl<S: Stage2Space> Drop for VcpuRegistration<S> {
    fn drop(&mut self) {
        self.shared
            .vcpus
            .with(|vcpus| vcpus.retain(|(id, _)| *id != self.id));
    }
}
