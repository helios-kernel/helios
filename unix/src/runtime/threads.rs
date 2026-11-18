use crate::{InterruptTarget, SignalState};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use helios_sync::Notify;
use spin::Mutex;
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ThreadAdmissionError {
    #[error("process has ended")]
    Ended,
    #[error("thread id exceeds the ABI range")]
    IdOverflow,
}
/// The threads of one WASIX process: its main thread's mailbox, every
/// thread any store of the process spawned and nobody has joined, the
/// next thread id, and the end a spawned thread chose for the whole
/// process.
///
/// The process owns its threads, not the store that spawned each one,
/// so any thread joins or signals any other and the process's end
/// ([`Self::end`]) reaches all of them, those whose spawner has itself
/// returned included. A spawned thread that exits, execs, takes a
/// fatal signal or fails (a trap, an out-of-memory kill) ends the
/// process the same way main does ([`Self::end_from_thread`]): `Image`
/// is what an exec hands the process's main thread to run next.
///
/// # Concurrency
///
/// Every store of the process, each driven on whichever processor runs
/// it, admits, joins, signals and ends the process through one table.
/// Each of those takes the spin lock for one lookup, push, removal or
/// record and releases it before anything is awaited or raised; no
/// interrupt handler touches the table. A thread's end is published
/// lock-free through its own [`ThreadExit`], which the joiner and
/// the process's end wait on outside the lock.
pub struct ProcessThreads<T: InterruptTarget, Image, Failure> {
    table: Arc<Mutex<ThreadGroupTable<T, Image, Failure>>>,
    /// The main thread's own mailbox, through which a spawned thread
    /// that ends the process ends main's image.
    main: SignalState<T>,
    futex: crate::FutexTable,
}

impl<T: InterruptTarget, Image, Failure> Clone for ProcessThreads<T, Image, Failure> {
    fn clone(&self) -> Self {
        Self {
            table: self.table.clone(),
            main: self.main.clone(),
            futex: self.futex.clone(),
        }
    }
}

struct ThreadGroupTable<T: InterruptTarget, Image, Failure> {
    next_tid: u32,
    threads: Vec<GroupThread<T>>,
    /// Set by [`ProcessThreads::end`] and by
    /// [`ProcessThreads::end_from_thread`]; no thread is admitted
    /// after, and no second end is recorded.
    ended: bool,
    /// The end a spawned thread chose for the process, recorded before
    /// main's image is ended and taken by main once its call has
    /// stopped.
    process_end: Option<ProcessEnd<Image, Failure>>,
}

/// How a spawned thread ended its whole process: each is the end the
/// same call would have given main's image (`run_core_module_image`).
#[derive(Debug, PartialEq, Eq)]
pub enum ProcessEnd<Image, Failure> {
    /// `proc_exit`, a fatal signal's default action, a trap, or a kill
    /// by the process's owner, with the termination the process reports.
    Exit(crate::ChildTermination),
    /// `proc_exec*`: the image the process runs next, in place of the
    /// one every thread of it was running.
    Exec(Image),
    /// A runtime failure (such as an out-of-memory kill), with the
    /// failure main reports for it.
    Fail(Failure),
}

struct GroupThread<T: InterruptTarget> {
    tid: u32,
    /// The thread's own mailbox: `thread_signal` raises on it and the
    /// process's end ends the thread through it.
    mailbox: SignalState<T>,
    exit: Arc<ThreadExit>,
}

impl<T: InterruptTarget, Image, Failure> ProcessThreads<T, Image, Failure> {
    pub fn futex(&self) -> &crate::FutexTable {
        &self.futex
    }

    /// The table of a new process, whose main thread is thread 0.
    pub fn new() -> Self {
        Self::starting_at(core::num::NonZeroU32::MIN)
    }
    pub fn starting_at(first: core::num::NonZeroU32) -> Self {
        Self {
            table: Arc::new(Mutex::new(ThreadGroupTable {
                next_tid: first.get(),
                threads: Vec::new(),
                ended: false,
                process_end: None,
            })),
            main: SignalState::new(),
            futex: crate::FutexTable::new(),
        }
    }

    /// The main thread's own mailbox, for its store to read.
    pub fn main_mailbox(&self) -> SignalState<T> {
        self.main.clone()
    }

    /// Ends the whole process from spawned thread `tid`, whose own call
    /// has ended with `end`, as POSIX `exit`, `execve`, a fatal signal
    /// and a fault's default action do from any thread.
    ///
    /// The end is recorded first, then main's image is ended through
    /// its mailbox, which stops main's call and makes main's completion
    /// take the end ([`Self::take_process_end`]): the exit status or the
    /// failure it reports, or the image it runs next once every thread
    /// has ended; every other thread is
    /// ended in the same pass, so none runs on after the process's end
    /// and they stop concurrently. Main's completion path then waits for
    /// all of them through [`Self::end`], as for any other end of the
    /// image.
    ///
    /// The first end wins. One that comes after the process has already
    /// ended, by main's own end or another thread's, is dropped: the
    /// thread raising it is being ended with the rest.
    pub fn end_from_thread(&self, tid: u32, end: ProcessEnd<Image, Failure>) {
        let others: Vec<SignalState<T>> = {
            let mut table = self.table.lock();
            if table.ended {
                return;
            }
            table.ended = true;
            table.process_end = Some(end);
            table
                .threads
                .iter()
                .filter(|thread| thread.tid != tid)
                .map(|thread| thread.mailbox.clone())
                .collect()
        };
        // Recorded under the lock before main is stopped, so main finds
        // the end once its call meets the stop.
        self.main.end_thread();
        for mailbox in &others {
            mailbox.end_thread();
        }
    }

    /// The end a spawned thread recorded for the process, taken by main
    /// once its call has stopped on its mailbox's end.
    pub fn take_process_end(&self) -> Option<ProcessEnd<Image, Failure>> {
        self.table.lock().process_end.take()
    }

    /// Admits a thread whose mailbox is `mailbox` and whose end `exit`
    /// will publish, and returns its id, which fits the `i32` that
    /// `wasi_thread_start` takes. A process that has ended admits
    /// nothing: the caller is one of its threads, ended already, and it
    /// gets `AGAIN`, `pthread_create`'s answer for a thread it cannot
    /// have.
    pub fn admit(
        &self,
        mailbox: SignalState<T>,
        exit: Arc<ThreadExit>,
    ) -> Result<u32, ThreadAdmissionError> {
        let mut table = self.table.lock();
        if table.ended {
            return Err(ThreadAdmissionError::Ended);
        }
        let tid = table.next_tid;
        i32::try_from(tid).map_err(|_| ThreadAdmissionError::IdOverflow)?;
        table.next_tid = tid + 1;
        table.threads.push(GroupThread { tid, mailbox, exit });
        Ok(tid)
    }

    /// Removes thread `tid` from the table, if it is still there.
    pub fn withdraw(&self, tid: u32) {
        let mut table = self.table.lock();
        if let Some(index) = table.threads.iter().position(|thread| thread.tid == tid) {
            table.threads.swap_remove(index);
        }
    }

    /// The end of thread `tid`, for a join to wait on.
    pub fn exit_of(&self, tid: u32) -> Option<Arc<ThreadExit>> {
        self.table
            .lock()
            .threads
            .iter()
            .find(|thread| thread.tid == tid)
            .map(|thread| thread.exit.clone())
    }

    /// The mailbox of thread `tid`, while it is still running.
    pub fn live_mailbox(&self, tid: u32) -> Option<SignalState<T>> {
        self.table
            .lock()
            .threads
            .iter()
            .find(|thread| thread.tid == tid && thread.exit.code().is_none())
            .map(|thread| thread.mailbox.clone())
    }

    /// Ends every thread the process still has and returns once each one
    /// has ended, its store, fiber stack and registry handle dropped.
    ///
    /// Called once, by the process's main thread after its own call has
    /// ended and before the process's completion is reported, whether
    /// main ended on its own or a spawned thread ended it
    /// ([`Self::end_from_thread`]). The table is closed and emptied
    /// under the lock, so a thread admitted later cannot exist; then
    /// every thread is ended (again, harmlessly, for those a spawned
    /// thread's end already reached), and only then is any
    /// awaited, so the threads stop concurrently and the wait is the
    /// slowest one's. A parked thread is reached through the wake its
    /// turn is armed on, which drops the call it is parked in, and a
    /// running one through its interrupt check (see
    /// [`SignalState::end_thread`]).
    pub async fn end(&self) {
        let threads = {
            let mut table = self.table.lock();
            table.ended = true;
            core::mem::take(&mut table.threads)
        };
        for thread in &threads {
            thread.mailbox.end_thread();
        }
        futures::future::join_all(threads.iter().map(|thread| thread.exit.wait())).await;
    }
}

/// The end of one WASIX thread: its exit status, published once, after
/// the thread's store is gone.
///
/// # Concurrency
///
/// The thread's task publishes from whichever processor ran it; any
/// number of waiters (a joiner, the process's end) wait on any other.
/// The status is one atomic and the broadcast stores nothing, so a
/// waiter arms its wait before it reads the status.
pub struct ThreadExit {
    status: AtomicU64,
    ended: Notify,
}

impl ThreadExit {
    const RUNNING: u64 = u64::MAX;

    pub fn new() -> Self {
        Self {
            status: AtomicU64::new(Self::RUNNING),
            ended: Notify::new(),
        }
    }

    /// Publishes the thread's exit status and wakes every waiter.
    pub fn publish(&self, code: u32) {
        self.status.store(u64::from(code), Ordering::Release);
        self.ended.notify_all();
    }

    /// The thread's exit status, once it has ended.
    pub fn code(&self) -> Option<u32> {
        match self.status.load(Ordering::Acquire) {
            Self::RUNNING => None,
            code => Some(code as u32),
        }
    }

    /// Waits for the thread's end and returns its exit status.
    pub async fn wait(&self) -> u32 {
        loop {
            // Armed before the status is read, so a publish between the
            // read and the park still completes the wait.
            let ended = self.ended.notified();
            if let Some(code) = self.code() {
                return code;
            }
            ended.await;
        }
    }
}

impl Default for ThreadExit {
    fn default() -> Self {
        Self::new()
    }
}
impl<T: InterruptTarget, Image, Failure> Default for ProcessThreads<T, Image, Failure> {
    fn default() -> Self {
        Self::new()
    }
}
