use alloc::sync::Arc;
use core::task::{Context, Poll};
use helios_sync::Notify;
use spin::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EventError {
    #[error("event counter increment is reserved")]
    InvalidIncrement,
    #[error("event counter would overflow")]
    WouldBlock,
}
/// Shared event counter. Task-context operations take a bounded spin lock;
/// readers release it before awaiting and writes broadcast after unlocking.
pub struct EventFd {
    state: Arc<Mutex<EventFdState>>,
    notify: Arc<Notify>,
    semaphore: bool,
}

struct EventFdState {
    pub value: u64,
}

impl EventFd {
    pub fn new(value: u64, semaphore: bool) -> Self {
        Self {
            state: Arc::new(Mutex::new(EventFdState { value })),
            notify: Arc::new(Notify::new()),
            semaphore,
        }
    }

    pub fn write(&self, increment: u64) -> Result<(), EventError> {
        if increment == u64::MAX {
            return Err(EventError::InvalidIncrement);
        }
        let mut state = self.state.lock();
        let next = state
            .value
            .checked_add(increment)
            .filter(|value| *value != u64::MAX)
            .ok_or(EventError::WouldBlock)?;
        state.value = next;
        drop(state);
        self.notify.notify_all();
        Ok(())
    }

    pub fn is_readable(&self) -> bool {
        self.state.lock().value != 0
    }

    pub fn wait_state(&self) -> helios_sync::NotifyWaiter {
        self.notify.waiter()
    }

    pub fn poll_readable(
        &self,
        cx: &mut Context<'_>,
        wait: &mut helios_sync::NotifyWaiter,
    ) -> Poll<()> {
        loop {
            if self.is_readable() {
                return Poll::Ready(());
            }
            match self.notify.poll_notified(cx, wait) {
                Poll::Ready(()) => continue,
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    pub fn is_writable(&self) -> bool {
        self.state.lock().value < u64::MAX - 1
    }
    pub fn try_read(&self) -> Result<u64, EventError> {
        let mut state = self.state.lock();
        if state.value == 0 {
            return Err(EventError::WouldBlock);
        }
        let value = if self.semaphore {
            state.value -= 1;
            1
        } else {
            core::mem::take(&mut state.value)
        };
        drop(state);
        self.notify.notify_all();
        Ok(value)
    }
    pub fn poll_changed(
        &self,
        cx: &mut Context<'_>,
        wait: &mut helios_sync::NotifyWaiter,
    ) -> Poll<()> {
        self.notify.poll_notified(cx, wait)
    }
    pub async fn read(&self) -> u64 {
        loop {
            let changed = self.notify.notified();
            if let Ok(value) = self.try_read() {
                return value;
            }
            changed.await;
        }
    }
}
impl Clone for EventFd {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            notify: self.notify.clone(),
            semaphore: self.semaphore,
        }
    }
}
