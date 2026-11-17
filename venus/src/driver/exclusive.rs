use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

use super::SubmissionLock;

pub(super) struct Exclusive<T, L> {
    lock: L,
    value: UnsafeCell<T>,
}

pub(super) struct Guard<'a, T, L: SubmissionLock + 'a> {
    _lock: L::Guard<'a>,
    value: &'a mut T,
    // A host guard is released on the thread that acquired it.
    _thread: PhantomData<*mut ()>,
}

impl<T, L: SubmissionLock> Exclusive<T, L> {
    pub(super) fn new(value: T) -> Self {
        Self {
            lock: L::new(),
            value: UnsafeCell::new(value),
        }
    }

    pub(super) fn lock(&self) -> Guard<'_, T, L> {
        let lock = self.lock.lock();
        Guard {
            _lock: lock,
            // SAFETY: SubmissionLock's contract excludes every other guard
            // and acquires prior writes before this reference is formed.
            value: unsafe { &mut *self.value.get() },
            _thread: PhantomData,
        }
    }
}

// SAFETY: moving ownership requires T: Send; L owns its synchronization state.
unsafe impl<T: Send, L: Send> Send for Exclusive<T, L> {}
// SAFETY: access to T is possible only while holding the exclusive host guard.
unsafe impl<T: Send, L: SubmissionLock> Sync for Exclusive<T, L> {}

impl<T, L: SubmissionLock> Deref for Guard<'_, T, L> {
    type Target = T;
    fn deref(&self) -> &T {
        self.value
    }
}

impl<T, L: SubmissionLock> DerefMut for Guard<'_, T, L> {
    fn deref_mut(&mut self) -> &mut T {
        self.value
    }
}
