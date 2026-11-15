//! Async synchronization primitives backed by Helios host syscalls.
//!
//! The protected values stay in guest memory. Lock acquisition and wakeups are
//! delegated to kernel-managed WIT resources, so user tasks never spin.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

use crate::bindings::helios::system::sync::{
    self as host_sync, RawMutex, RawMutexGuard, RawRwLock, RawRwLockReadGuard, RawRwLockWriteGuard,
};

/// Async mutex using kernel-managed scheduling.
pub struct Mutex<T> {
    raw: RawMutex,
    value: UnsafeCell<T>,
}

/// Guard returned by [`Mutex::lock`].
pub struct MutexGuard<'a, T> {
    _raw_guard: RawMutexGuard,
    value: *mut T,
    _marker: PhantomData<&'a mut T>,
}

/// Async reader/writer lock using kernel-managed scheduling.
pub struct RwLock<T> {
    raw: RawRwLock,
    value: UnsafeCell<T>,
}

/// Shared read guard returned by [`RwLock::read`].
pub struct RwLockReadGuard<'a, T> {
    _raw_guard: RawRwLockReadGuard,
    value: *const T,
    _marker: PhantomData<&'a T>,
}

/// Exclusive write guard returned by [`RwLock::write`].
pub struct RwLockWriteGuard<'a, T> {
    _raw_guard: RawRwLockWriteGuard,
    value: *mut T,
    _marker: PhantomData<&'a mut T>,
}

impl<T> Mutex<T> {
    pub fn new(value: T) -> Self {
        Self {
            raw: RawMutex::new(),
            value: UnsafeCell::new(value),
        }
    }

    pub async fn lock(&self) -> MutexGuard<'_, T> {
        let raw_guard = self.raw.lock().await;
        MutexGuard {
            _raw_guard: raw_guard,
            value: self.value.get(),
            _marker: PhantomData,
        }
    }

    pub fn get_mut(&mut self) -> &mut T {
        self.value.get_mut()
    }

    pub fn into_inner(self) -> T {
        self.value.into_inner()
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<'a, T> Deref for MutexGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: the host only yields this guard after acquiring exclusive
        // access for the lifetime of the guard resource.
        unsafe { &*self.value }
    }
}

impl<'a, T> DerefMut for MutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: same as above, with exclusive mutable access.
        unsafe { &mut *self.value }
    }
}

impl<T> RwLock<T> {
    pub fn new(value: T) -> Self {
        Self {
            raw: RawRwLock::new(),
            value: UnsafeCell::new(value),
        }
    }

    pub async fn read(&self) -> RwLockReadGuard<'_, T> {
        let raw_guard = self.raw.read().await;
        RwLockReadGuard {
            _raw_guard: raw_guard,
            value: self.value.get().cast_const(),
            _marker: PhantomData,
        }
    }

    pub async fn write(&self) -> RwLockWriteGuard<'_, T> {
        let raw_guard = self.raw.write().await;
        RwLockWriteGuard {
            _raw_guard: raw_guard,
            value: self.value.get(),
            _marker: PhantomData,
        }
    }

    pub fn get_mut(&mut self) -> &mut T {
        self.value.get_mut()
    }

    pub fn into_inner(self) -> T {
        self.value.into_inner()
    }
}

impl<T: Default> Default for RwLock<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<'a, T> Deref for RwLockReadGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: the host only yields this guard after acquiring shared read
        // access for the lifetime of the guard resource.
        unsafe { &*self.value }
    }
}

impl<'a, T> Deref for RwLockWriteGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: the host only yields this guard after acquiring exclusive
        // write access for the lifetime of the guard resource.
        unsafe { &*self.value }
    }
}

impl<'a, T> DerefMut for RwLockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: same as above, with mutable access.
        unsafe { &mut *self.value }
    }
}

unsafe impl<T: Send> Send for Mutex<T> {}
unsafe impl<T: Send> Sync for Mutex<T> {}

unsafe impl<T: Send + Sync> Send for RwLock<T> {}
unsafe impl<T: Send + Sync> Sync for RwLock<T> {}

/// Absolute nanoseconds in the WASI monotonic clock's epoch.
pub type Deadline = crate::bindings::wasi::clocks::monotonic_clock::Mark;

/// A completion producer closed or reported failure.
pub use crate::bindings::helios::system::sync::Error as TimelineError;

/// Read-only access to a shared completion timeline.
pub struct Timeline {
    raw: host_sync::Timeline,
}

/// Authority to advance a timeline. Dropping the last producer closes it.
pub struct SignalSource {
    raw: host_sync::SignalSource,
}

/// A value to await on a timeline.
pub struct TimelinePoint<'a> {
    pub timeline: &'a Timeline,
    pub value: u64,
}

/// A producer value to attach to an asynchronous operation.
pub struct SignalPoint<'a> {
    pub source: &'a SignalSource,
    pub value: u64,
}

#[cfg(feature = "gpu")]
impl SignalPoint<'_> {
    pub(crate) fn raw(&self) -> host_sync::SignalPoint<'_> {
        host_sync::SignalPoint {
            source: &self.source.raw,
            value: self.value,
        }
    }
}

impl SignalSource {
    pub fn new(initial: u64) -> Self {
        Self {
            raw: host_sync::SignalSource::new(initial),
        }
    }

    pub fn point(&self, value: u64) -> SignalPoint<'_> {
        SignalPoint {
            source: self,
            value,
        }
    }

    pub fn reader(&self) -> Timeline {
        Timeline {
            raw: self.raw.reader(),
        }
    }

    pub fn signal(&self, value: u64) -> Result<(), TimelineError> {
        self.raw.signal(value)
    }

    pub fn fail(&self) {
        self.raw.fail();
    }
}

impl Timeline {
    pub fn value(&self) -> Result<u64, TimelineError> {
        self.raw.value()
    }

    pub fn point(&self, value: u64) -> TimelinePoint<'_> {
        TimelinePoint {
            timeline: self,
            value,
        }
    }
}

/// Wait for every point, returning false if the absolute deadline expires.
pub async fn wait_all(
    points: &[TimelinePoint<'_>],
    deadline: Option<Deadline>,
) -> Result<bool, TimelineError> {
    wait_points(points, true, deadline).await
}

/// Wait for any point, returning false if the absolute deadline expires.
pub async fn wait_any(
    points: &[TimelinePoint<'_>],
    deadline: Option<Deadline>,
) -> Result<bool, TimelineError> {
    wait_points(points, false, deadline).await
}

async fn wait_points(
    points: &[TimelinePoint<'_>],
    all: bool,
    deadline: Option<Deadline>,
) -> Result<bool, TimelineError> {
    let points: Vec<_> = points
        .iter()
        .map(|point| host_sync::TimelinePoint {
            timeline: &point.timeline.raw,
            value: point.value,
        })
        .collect();
    host_sync::wait(points, all, deadline).await
}
