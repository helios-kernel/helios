use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use helios_hal::hv::{GuestAddress, HvError, IoWidth};
use triomphe::Arc;

use super::VmTelemetry;
use crate::exec::Notify;
use crate::memory::IrqSafeMutex;

/// The VM owns registrations; vCPUs briefly inspect them under an IRQ-safe
/// lock. Waiters hold no lock. Each event has a lock-free completion count.
pub(super) struct IoEvents {
    entries: IrqSafeMutex<Vec<Registration>>,
    telemetry: Arc<VmTelemetry>,
}

struct Registration {
    address: GuestAddress,
    width: IoWidth,
    value: Option<u64>,
    signal: Arc<EventSignal>,
}

pub(super) struct EventSignal {
    pending: AtomicUsize,
    stopped: AtomicBool,
    wake: Notify,
}

impl EventSignal {
    pub(super) fn complete(&self) {
        self.pending
            .try_update(Ordering::Release, Ordering::Relaxed, |count| {
                count.checked_add(1)
            })
            .expect("ioevent completion count overflow");
        self.wake.notify_all();
    }

    async fn wait(&self) -> Result<(), HvError> {
        loop {
            let wake = self.wake.notified();
            if self.stopped.load(Ordering::Acquire) {
                return Err(HvError::Stopped);
            }
            if self
                .pending
                .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    count.checked_sub(1)
                })
                .is_ok()
            {
                return Ok(());
            }
            wake.await;
        }
    }
}

impl IoEvents {
    pub(super) fn new(telemetry: Arc<VmTelemetry>) -> Self {
        Self {
            entries: IrqSafeMutex::new(Vec::new()),
            telemetry,
        }
    }

    pub(super) fn register(
        registry: &Arc<Self>,
        address: GuestAddress,
        width: IoWidth,
        value: Option<u64>,
    ) -> Result<IoEvent, HvError> {
        address
            .0
            .checked_add(width.bytes() as u64)
            .ok_or(HvError::InvalidRange)?;
        let signal = Arc::new(EventSignal {
            pending: AtomicUsize::new(0),
            stopped: AtomicBool::new(false),
            wake: Notify::new(),
        });
        registry.entries.with(|entries| {
            if entries.iter().any(|entry| {
                entry.address == address
                    && entry.width == width
                    && (entry.value.is_none() || value.is_none() || entry.value == value)
            }) {
                return Err(HvError::Overlap);
            }
            entries.push(Registration {
                address,
                width,
                value,
                signal: signal.clone(),
            });
            Ok(())
        })?;
        registry.telemetry.inc_ioevents();
        Ok(IoEvent {
            registry: registry.clone(),
            signal,
        })
    }

    pub(super) fn matching(
        &self,
        address: GuestAddress,
        width: IoWidth,
        value: u64,
    ) -> Option<Arc<EventSignal>> {
        self.entries.with(|entries| {
            entries
                .iter()
                .find(|entry| {
                    entry.address == address
                        && entry.width == width
                        && entry.value.is_none_or(|expected| expected == value)
                })
                .map(|entry| entry.signal.clone())
        })
    }

    pub(super) fn stop(&self) {
        self.entries.with(|entries| {
            for entry in entries {
                entry.signal.stopped.store(true, Ordering::Release);
                entry.signal.wake.notify_all();
            }
        });
    }
}

/// Dropping the registration removes the kernel fast path. An active wait
/// retains the resource through the component call's borrow.
pub struct IoEvent {
    registry: Arc<IoEvents>,
    signal: Arc<EventSignal>,
}

impl IoEvent {
    pub async fn wait(&self) -> Result<(), HvError> {
        self.signal.wait().await
    }
}

impl Drop for IoEvent {
    fn drop(&mut self) {
        self.registry.entries.with(|entries| {
            entries.retain(|entry| !Arc::ptr_eq(&entry.signal, &self.signal));
        });
        self.registry.telemetry.dec_ioevents();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hv::GuestMemoryAccount;
    use futures_lite::future::{block_on, poll_once};

    fn test_events() -> Arc<IoEvents> {
        let account = Arc::new(GuestMemoryAccount::new(0));
        Arc::new(IoEvents::new(Arc::new(VmTelemetry::new(
            0, None, None, account,
        ))))
    }

    #[test]
    fn matching_respects_width_and_value_and_drop_unregisters() {
        let registry = test_events();
        let address = GuestAddress(0x1000);
        let event = IoEvents::register(&registry, address, IoWidth::Dword, Some(4)).unwrap();
        assert!(registry.matching(address, IoWidth::Word, 4).is_none());
        assert!(registry.matching(address, IoWidth::Dword, 3).is_none());
        assert!(registry.matching(address, IoWidth::Dword, 4).is_some());
        assert!(matches!(
            IoEvents::register(&registry, address, IoWidth::Dword, None),
            Err(HvError::Overlap)
        ));
        let other = IoEvents::register(&registry, address, IoWidth::Dword, Some(5)).unwrap();
        drop(event);
        assert!(registry.matching(address, IoWidth::Dword, 4).is_none());
        assert!(registry.matching(address, IoWidth::Dword, 5).is_some());
        drop(other);
        assert!(IoEvents::register(&registry, address, IoWidth::Dword, None).is_ok());
    }

    #[test]
    fn cancellation_preserves_completions_and_vm_stop_wakes_waiters() {
        let registry = test_events();
        let event = IoEvents::register(&registry, GuestAddress(0), IoWidth::Dword, None).unwrap();
        {
            let mut wait = core::pin::pin!(event.wait());
            assert!(block_on(poll_once(wait.as_mut())).is_none());
            event.signal.complete();
            event.signal.complete();
        }
        assert_eq!(block_on(event.wait()), Ok(()));
        assert_eq!(block_on(event.wait()), Ok(()));
        let mut wait = core::pin::pin!(event.wait());
        assert!(block_on(poll_once(wait.as_mut())).is_none());
        registry.stop();
        assert_eq!(block_on(wait), Err(HvError::Stopped));
    }
}
