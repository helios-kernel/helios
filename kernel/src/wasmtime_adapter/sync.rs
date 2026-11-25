use core::hint::spin_loop;
use core::sync::atomic::{AtomicUsize, Ordering};

const MUTEX_UNLOCKED: usize = 0;
const MUTEX_LOCKED: usize = 1;
const RWLOCK_WRITER: usize = usize::MAX;

/// Iteration cap for adapter synchronisation primitives.
///
/// Genuine contention on these locks is single-digit-microsecond
/// territory because callers do nothing but flip a flag and continue.
/// A spin that stretches into seconds is always a bug — typically a
/// PTE / cache-coherence mismatch under the custom virtual-memory
/// path or a deadlock in upper-layer runtime code. Crashing with a
/// clear panic is strictly better than the silent 4-core CPU burn the
/// previous unbounded-spin form produced; AGENTS §3 demands explicit
/// failure over silent deadlock.
///
/// At 4 GHz, 1 << 32 iterations is ~1 second of pure-CPU work; the
/// real-world ceiling on contention is microseconds, so this cap is
/// six orders of magnitude beyond the legitimate range.
const SYNC_SPIN_LIMIT: u64 = 1u64 << 32;

#[cold]
#[inline(never)]
fn sync_deadlock(primitive: &'static str) -> ! {
    panic!("runtime adapter {primitive} spin lock exceeded SYNC_SPIN_LIMIT — deadlock detected");
}

/// Borrows Wasmtime's lock storage slot as an [`AtomicUsize`].
///
/// # Safety
///
/// `storage` must be non-null, aligned to `align_of::<AtomicUsize>()`, and
/// point to live lock storage for at least `'a` where all concurrent accesses
/// are atomic.
#[inline]
unsafe fn atomic_from_storage<'a>(storage: *mut usize) -> &'a AtomicUsize {
    // SAFETY: caller guarantees `storage` is valid, aligned, and exclusively
    // accessed via atomics for `'a`; `AtomicUsize` shares the layout of `usize`.
    unsafe { &*storage.cast::<AtomicUsize>() }
}

/// Acquires the mutex backed by `lock`.
///
/// # Safety
///
/// `lock` must be a valid, aligned pointer to Wasmtime's lock storage word
/// for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasmtime_sync_lock_acquire(lock: *mut usize) {
    // SAFETY: caller guarantees `lock` points to valid, aligned lock storage
    // for the duration of this call.
    let lock = unsafe { atomic_from_storage(lock) };
    let mut iterations = 0u64;
    while lock
        .compare_exchange(
            MUTEX_UNLOCKED,
            MUTEX_LOCKED,
            Ordering::Acquire,
            Ordering::Relaxed,
        )
        .is_err()
    {
        iterations += 1;
        if iterations >= SYNC_SPIN_LIMIT {
            sync_deadlock("mutex");
        }
        spin_loop();
    }
}

/// Releases the mutex backed by `lock`.
///
/// # Safety
///
/// `lock` must be a valid, aligned pointer to Wasmtime's lock storage word
/// previously acquired via [`wasmtime_sync_lock_acquire`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasmtime_sync_lock_release(lock: *mut usize) {
    // SAFETY: caller guarantees `lock` points to valid, aligned lock storage
    // for the duration of this call.
    let lock = unsafe { atomic_from_storage(lock) };
    lock.store(MUTEX_UNLOCKED, Ordering::Release);
}

/// Releases any resources associated with the mutex at `_lock`.
///
/// # Safety
///
/// `_lock` must point to lock storage that is no longer in use.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasmtime_sync_lock_free(_lock: *mut usize) {}

/// Acquires a shared read lock on the rwlock backed by `lock`.
///
/// # Safety
///
/// `lock` must be a valid, aligned pointer to Wasmtime's rwlock storage word
/// for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasmtime_sync_rwlock_read(lock: *mut usize) {
    // SAFETY: caller guarantees `lock` points to valid, aligned lock storage
    // for the duration of this call.
    let lock = unsafe { atomic_from_storage(lock) };
    let mut iterations = 0u64;
    loop {
        let state = lock.load(Ordering::Acquire);
        if state != RWLOCK_WRITER
            && lock
                .compare_exchange_weak(state, state + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        {
            return;
        }
        iterations += 1;
        if iterations >= SYNC_SPIN_LIMIT {
            sync_deadlock("rwlock-read");
        }
        spin_loop();
    }
}

/// Releases a shared read lock on the rwlock backed by `lock`.
///
/// # Safety
///
/// `lock` must be a valid, aligned pointer to Wasmtime's rwlock storage word
/// previously acquired via [`wasmtime_sync_rwlock_read`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasmtime_sync_rwlock_read_release(lock: *mut usize) {
    // SAFETY: caller guarantees `lock` points to valid, aligned lock storage
    // for the duration of this call.
    let lock = unsafe { atomic_from_storage(lock) };
    lock.fetch_sub(1, Ordering::Release);
}

/// Acquires an exclusive write lock on the rwlock backed by `lock`.
///
/// # Safety
///
/// `lock` must be a valid, aligned pointer to Wasmtime's rwlock storage word
/// for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasmtime_sync_rwlock_write(lock: *mut usize) {
    // SAFETY: caller guarantees `lock` points to valid, aligned lock storage
    // for the duration of this call.
    let lock = unsafe { atomic_from_storage(lock) };
    let mut iterations = 0u64;
    while lock
        .compare_exchange(0, RWLOCK_WRITER, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        iterations += 1;
        if iterations >= SYNC_SPIN_LIMIT {
            sync_deadlock("rwlock-write");
        }
        spin_loop();
    }
}

/// Releases an exclusive write lock on the rwlock backed by `lock`.
///
/// # Safety
///
/// `lock` must be a valid, aligned pointer to Wasmtime's rwlock storage word
/// previously acquired via [`wasmtime_sync_rwlock_write`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasmtime_sync_rwlock_write_release(lock: *mut usize) {
    // SAFETY: caller guarantees `lock` points to valid, aligned lock storage
    // for the duration of this call.
    let lock = unsafe { atomic_from_storage(lock) };
    lock.store(0, Ordering::Release);
}

/// Releases any resources associated with the rwlock at `_lock`.
///
/// # Safety
///
/// `_lock` must point to rwlock storage that is no longer in use.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasmtime_sync_rwlock_free(_lock: *mut usize) {}
