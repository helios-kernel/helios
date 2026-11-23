//! Single-owner resources borrowed by cancellable component calls.
//!
//! Taking and returning ownership are lock-free. The resource table owns the
//! slot; an asynchronous call owns a lease, never a mutex guard. Closing the
//! slot races safely with either operation and prevents a returned lease from
//! resurrecting a destroyed resource.

use concurrent_queue::{ConcurrentQueue, PopError};
use core::ops::{Deref, DerefMut};
use thiserror::Error;
use triomphe::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum LeaseError {
    #[error("resource is in use by another call")]
    Busy,
    #[error("resource has been destroyed")]
    Closed,
}

pub struct ResourceSlot<T> {
    queue: Arc<ConcurrentQueue<T>>,
}

impl<T> ResourceSlot<T> {
    pub fn new(value: T) -> Self {
        // One slot expresses exclusive ownership, not an operational quota.
        let queue = ConcurrentQueue::bounded(1);
        assert!(queue.push(value).is_ok(), "new resource slot is empty");
        Self {
            queue: Arc::new(queue),
        }
    }

    pub fn take(&self) -> Result<ResourceLease<T>, LeaseError> {
        let value = self.queue.pop().map_err(|error| match error {
            PopError::Empty => LeaseError::Busy,
            PopError::Closed => LeaseError::Closed,
        })?;
        Ok(ResourceLease {
            value: Some(value),
            queue: self.queue.clone(),
        })
    }
}

impl<T> Drop for ResourceSlot<T> {
    fn drop(&mut self) {
        self.queue.close();
        // A taken lease drops its value when it returns to the closed queue.
        drop(self.queue.pop());
    }
}

pub struct ResourceLease<T> {
    value: Option<T>,
    queue: Arc<ConcurrentQueue<T>>,
}

impl<T> Deref for ResourceLease<T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.value.as_ref().expect("live lease owns its value")
    }
}

impl<T> DerefMut for ResourceLease<T> {
    fn deref_mut(&mut self) -> &mut T {
        self.value.as_mut().expect("live lease owns its value")
    }
}

impl<T> Drop for ResourceLease<T> {
    fn drop(&mut self) {
        let value = self.value.take().expect("live lease owns its value");
        if let Err(error) = self.queue.push(value) {
            assert!(
                error.is_closed(),
                "exclusive resource slot was already full"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use futures_lite::future::{block_on, poll_once};

    struct CountDrop(Arc<AtomicUsize>);
    impl Drop for CountDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn cancelled_call_returns_exclusive_ownership() {
        let slot = ResourceSlot::new(7);
        let lease = slot.take().unwrap();
        {
            let mut call = core::pin::pin!(async move {
                let mut lease = lease;
                *lease = 11;
                core::future::pending::<()>().await;
            });
            assert!(block_on(poll_once(call.as_mut())).is_none());
            assert!(matches!(slot.take(), Err(LeaseError::Busy)));
        }
        assert_eq!(*slot.take().unwrap(), 11);
    }

    #[test]
    fn returning_a_lease_releases_the_next_caller() {
        let slot = ResourceSlot::new(7);
        let mut first = slot.take().unwrap();
        *first = 11;
        assert!(matches!(slot.take(), Err(LeaseError::Busy)));
        drop(first);
        assert_eq!(*slot.take().unwrap(), 11);
    }

    #[test]
    fn destroying_a_borrowed_resource_drops_it_once_on_return() {
        let drops = Arc::new(AtomicUsize::new(0));
        let slot = ResourceSlot::new(CountDrop(drops.clone()));
        let lease = slot.take().unwrap();
        drop(slot);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        drop(lease);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn destroying_an_idle_resource_drops_it_immediately() {
        let drops = Arc::new(AtomicUsize::new(0));
        drop(ResourceSlot::new(CountDrop(drops.clone())));
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}
