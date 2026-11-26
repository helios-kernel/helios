use super::*;
#[derive(Clone)]
pub(crate) struct SignalTarget {
    pub(crate) interrupts: Arc<GuestInterrupts>,
    pub(crate) instance: crate::InstanceId,
}
impl helios_unix::InterruptTarget for SignalTarget {
    fn interrupt(&self) {
        self.interrupts.interrupt_instance(self.instance);
    }
}
pub(crate) type WasixSignalState = helios_unix::SignalState<SignalTarget>;
pub(super) type WasixProcessThreads<Image> =
    helios_unix::ProcessThreads<SignalTarget, Image, ProgramExecError>;
pub(super) type WasixProcessEnd<Image> = helios_unix::ProcessEnd<Image, ProgramExecError>;
pub(super) type WasixThreadExit = helios_unix::ThreadExit;
pub(super) type EventFd = helios_unix::EventFd;

/// The exit report a child's launch task sends its parent.
pub(super) type WasixChildExit =
    futures::channel::oneshot::Receiver<Result<ChildExit, ProgramExecError>>;

/// A process's children, in spawn order, until each one is joined.
///
/// Owned by the process and shared by every store of the process (`Arc::clone`),
/// so a child spawned on any thread can be joined or signaled by any other
/// thread of the process.
///
/// # Concurrency contract
///
/// Every caller runs in task context (never an interrupt handler). The
/// `spin::Mutex` guards only in-memory table reads, inserts, `try_recv`
/// probes, and synchronous `oneshot` polls, and is always dropped before any
/// `.await`, filesystem layer adoption, or waiter wakeup.
///
/// Non-blocking probes ([`Self::poll_signal_target`] and [`Self::try_join`])
/// inspect `oneshot::Receiver::try_recv` rather than polling with a no-op
/// waker, so they never overwrite a waker registered by another thread
/// blocked in `proc_join`. Whenever a child is inserted, transitions to
/// `Completed`, is reaped, or a blocking joiner returns or drops (through
/// [`WasixChildrenJoinGuard`]), `changed.notify_all()` wakes any remaining
/// blocking joiners so they re-register their wakers on the remaining running
/// children without lost wakeups.
#[derive(Clone)]
pub(super) struct WasixChildren {
    inner: Arc<WasixChildrenInner>,
}

struct WasixChildrenInner {
    table: Mutex<Vec<WasixChildProcess>>,
    changed: crate::Notify,
}

/// RAII guard held by a blocking `proc_join` future. Dropping it wakes any
/// sibling thread also blocked in `proc_join` so it re-registers its waker
/// on the remaining children's `oneshot` receivers if this joiner overwrote
/// them before returning, returning `EINTR`, or being cancelled.
pub(super) struct WasixChildrenJoinGuard {
    children: WasixChildren,
}

impl Drop for WasixChildrenJoinGuard {
    fn drop(&mut self) {
        self.children.inner.changed.notify_all();
    }
}

struct WasixChildProcess {
    pid: u32,
    signal_state: WasixSignalState,
    state: WasixChildState,
}

enum WasixChildState {
    Running(WasixChildExit),
    /// Completed and not joined yet: either how the child ended or the
    /// errno its failed launch or lost report gives the joiner.
    Completed(Result<helios_unix::ChildTermination, i32>),
}

/// The child a join took off the table, and what came of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct WasixJoinedChild {
    pub(super) pid: u32,
    pub(super) outcome: Result<helios_unix::ChildTermination, i32>,
}

impl WasixChildren {
    pub(super) fn new() -> Self {
        Self {
            inner: Arc::new(WasixChildrenInner {
                table: Mutex::new(Vec::new()),
                changed: crate::Notify::new(),
            }),
        }
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.inner.table.lock().is_empty()
    }

    pub(super) fn insert(&self, pid: u32, signal_state: WasixSignalState, exit: WasixChildExit) {
        self.inner.table.lock().push(WasixChildProcess {
            pid,
            signal_state,
            state: WasixChildState::Running(exit),
        });
        self.inner.changed.notify_all();
    }

    /// Arms a change waiter and a drop guard for a blocking `proc_join`.
    pub(super) fn begin_blocking_join(&self) -> (crate::NotifyWaiter, WasixChildrenJoinGuard) {
        (
            self.inner.changed.waiter(),
            WasixChildrenJoinGuard {
                children: self.clone(),
            },
        )
    }

    /// The signal mailbox of child `pid` while it is still running: `None`
    /// for a pid that names no child and for a child whose completion has
    /// already arrived on its exit channel. Any completion observed here is
    /// recorded in place without reaping the child, so a subsequent
    /// [`Self::poll_join`] still reports its termination or launch error.
    pub(super) fn poll_signal_target(
        &self,
        pid: u32,
        mut adopt: impl FnMut(MemoryFs),
    ) -> Option<WasixSignalState> {
        let mut adopted = None;
        let mut completed_now = false;
        let mailbox = {
            let mut table = self.inner.table.lock();
            let child = table.iter_mut().find(|child| child.pid == pid)?;
            if let WasixChildState::Running(exit) = &mut child.state {
                match exit.try_recv() {
                    Ok(Some(result)) => {
                        child.state = WasixChildState::Completed(child_exit_outcome(
                            Ok(result),
                            &mut |layer| adopted = Some(layer),
                        ));
                        completed_now = true;
                    }
                    Err(canceled) => {
                        child.state = WasixChildState::Completed(child_exit_outcome(
                            Err(canceled),
                            &mut |layer| adopted = Some(layer),
                        ));
                        completed_now = true;
                    }
                    Ok(None) => {}
                }
            }
            matches!(child.state, WasixChildState::Running(_)).then(|| child.signal_state.clone())
        };
        if let Some(layer) = adopted {
            adopt(layer);
        }
        if completed_now {
            self.inner.changed.notify_all();
        }
        mailbox
    }

    /// Non-blocking join (`WNOHANG`) of `pid`, or any child for `None`.
    /// Uses `try_recv` so it never clobbers a blocking joiner's waker.
    pub(super) fn try_join(
        &self,
        pid: Option<u32>,
        mut adopt: impl FnMut(MemoryFs),
    ) -> Poll<Option<WasixJoinedChild>> {
        let mut adopted: SmallVec<[MemoryFs; 1]> = SmallVec::new();
        let mut changed = false;
        let outcome = {
            let mut table = self.inner.table.lock();
            let mut named = false;
            let mut completed = None;
            for (index, child) in table.iter_mut().enumerate() {
                if pid.is_some_and(|pid| child.pid != pid) {
                    continue;
                }
                named = true;
                if let WasixChildState::Running(exit) = &mut child.state {
                    match exit.try_recv() {
                        Ok(Some(result)) => {
                            child.state = WasixChildState::Completed(child_exit_outcome(
                                Ok(result),
                                &mut |layer| adopted.push(layer),
                            ));
                            changed = true;
                        }
                        Err(canceled) => {
                            child.state = WasixChildState::Completed(child_exit_outcome(
                                Err(canceled),
                                &mut |layer| adopted.push(layer),
                            ));
                            changed = true;
                        }
                        Ok(None) => {}
                    }
                }
                if completed.is_none() && matches!(child.state, WasixChildState::Completed(_)) {
                    completed = Some(index);
                }
            }
            match completed {
                Some(index) => {
                    let child = table.remove(index);
                    let WasixChildState::Completed(outcome) = child.state else {
                        unreachable!("a joined child was just seen to have completed");
                    };
                    changed = true;
                    Poll::Ready(Some(WasixJoinedChild {
                        pid: child.pid,
                        outcome,
                    }))
                }
                None if named => Poll::Pending,
                None => Poll::Ready(None),
            }
        };
        for layer in adopted {
            adopt(layer);
        }
        if changed {
            self.inner.changed.notify_all();
        }
        outcome
    }

    /// Joins the child `pid` names, or any child for `None`.
    ///
    /// Every running child the join names is polled, so each completion
    /// that has arrived is recorded and `cx` is registered with every
    /// child still running: an any-child join takes the oldest child
    /// that has completed, never waits on one child while another has
    /// already completed, and is woken by whichever completes first. A
    /// shell reaps each foreground command this way while its background
    /// jobs, older children, keep running.
    ///
    /// `Ready(None)` when `pid` names no child, `Ready(Some)` with the
    /// child taken off the table once one it names has completed, and
    /// `Pending` while every child it names is still running. `adopt`
    /// receives the filesystem layer each exit observed here hands back
    /// to the parent.
    pub(super) fn poll_join(
        &self,
        pid: Option<u32>,
        cx: &mut Context<'_>,
        wait: &mut crate::NotifyWaiter,
        mut adopt: impl FnMut(MemoryFs),
    ) -> Poll<Option<WasixJoinedChild>> {
        loop {
            let mut adopted: SmallVec<[MemoryFs; 1]> = SmallVec::new();
            let mut changed = false;
            let outcome = {
                let mut table = self.inner.table.lock();
                let mut named = false;
                let mut completed = None;
                for (index, child) in table.iter_mut().enumerate() {
                    if pid.is_some_and(|pid| child.pid != pid) {
                        continue;
                    }
                    named = true;
                    if let WasixChildState::Running(exit) = &mut child.state
                        && let Poll::Ready(result) = Pin::new(exit).poll(cx)
                    {
                        child.state =
                            WasixChildState::Completed(child_exit_outcome(result, &mut |layer| {
                                adopted.push(layer)
                            }));
                        changed = true;
                    }
                    if completed.is_none() && matches!(child.state, WasixChildState::Completed(_)) {
                        completed = Some(index);
                    }
                }
                match completed {
                    Some(index) => {
                        let child = table.remove(index);
                        let WasixChildState::Completed(outcome) = child.state else {
                            unreachable!("a joined child was just seen to have completed");
                        };
                        changed = true;
                        Poll::Ready(Some(WasixJoinedChild {
                            pid: child.pid,
                            outcome,
                        }))
                    }
                    None if named => Poll::Pending,
                    None => Poll::Ready(None),
                }
            };
            for layer in adopted {
                adopt(layer);
            }
            if changed {
                self.inner.changed.notify_all();
            }
            if outcome.is_ready() {
                return outcome;
            }
            if self.inner.changed.poll_notified(cx, wait).is_pending() {
                return Poll::Pending;
            }
        }
    }
}

/// What a child's exit report gives its parent: the child's termination,
/// or the errno for a launch failure or dropped exit channel.
fn child_exit_outcome(
    result: Result<Result<ChildExit, ProgramExecError>, futures::channel::oneshot::Canceled>,
    adopt: &mut impl FnMut(MemoryFs),
) -> Result<helios_unix::ChildTermination, i32> {
    match result {
        Ok(Ok(exit)) => {
            if let Some(filesystem) = exit.filesystem {
                adopt(filesystem);
            }
            Ok(exit.termination)
        }
        Ok(Err(error)) => Err(p1_errno_from_program_exec_error(&error)),
        Err(_) => Err(p1::errno::IO),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct WasixSignalDisposition {
    pub(super) signal: u8,
    pub(super) action: WasixSignalDispositionAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WasixSignalDispositionAction {
    Default,
    Ignore,
}

/// Process-wide WASIX signal state shared by every thread of one process
/// image: the initial `Ignore` set inherited from spawn or exec plus the guest
/// handler export registered through `callback_signal`, if any.
///
/// # Concurrency
///
/// Any thread of the process may register or clear `callback_signal`, and any
/// thread's store may sample the state at an interrupt check, turn epilogue,
/// or safe point. Every caller runs in task context (never an interrupt
/// handler), copies an 8-byte [`helios_unix::SignalSet`] and optional
/// [`Arc<str>`] under the spin lock, and drops the guard before any `.await`
/// or guest call.
#[derive(Clone, Default)]
pub(super) struct WasixProcessSignals {
    inner: Arc<Mutex<WasixProcessSignalsState>>,
}

#[derive(Default)]
struct WasixProcessSignalsState {
    ignored: helios_unix::SignalSet,
    callback: Option<Arc<str>>,
}

impl WasixProcessSignals {
    pub(super) fn from_dispositions(dispositions: &[WasixSignalDisposition]) -> Self {
        let mut ignored = helios_unix::SignalSet::EMPTY;
        for disposition in dispositions {
            let Some(signal) = helios_unix::Signal::from_standard(disposition.signal) else {
                continue;
            };
            if signal.is_uncatchable() {
                continue;
            }
            match disposition.action {
                WasixSignalDispositionAction::Ignore => ignored.insert(signal),
                WasixSignalDispositionAction::Default => {
                    ignored.remove(signal);
                }
            }
        }
        Self {
            inner: Arc::new(Mutex::new(WasixProcessSignalsState {
                ignored,
                callback: None,
            })),
        }
    }

    pub(super) fn set_callback(&self, callback: Option<Arc<str>>) {
        self.inner.lock().callback = callback;
    }

    pub(super) fn callback(&self) -> Option<Arc<str>> {
        self.inner.lock().callback.clone()
    }

    fn summary(&self) -> (helios_unix::SignalSet, bool) {
        let state = self.inner.lock();
        (state.ignored, state.callback.is_some())
    }

    fn snapshot(&self) -> (helios_unix::SignalSet, Option<Arc<str>>) {
        let state = self.inner.lock();
        (state.ignored, state.callback.clone())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WasixResolvedAction<H> {
    Ignore,
    Catch(H),
    Terminate,
}

fn resolve_wasix_signal<H: Copy>(
    signal: helios_unix::Signal,
    ignored: helios_unix::SignalSet,
    callback: Option<H>,
) -> WasixResolvedAction<H> {
    let disposition = if ignored.contains(signal) {
        helios_unix::SignalDisposition::Ignore
    } else if let Some(handler) = callback {
        helios_unix::SignalDisposition::Catch(handler)
    } else {
        helios_unix::SignalDisposition::Default
    };
    match signal.resolve(disposition) {
        helios_unix::ResolvedSignal::Ignore
        | helios_unix::ResolvedSignal::Default(
            helios_unix::DefaultSignalAction::Ignore | helios_unix::DefaultSignalAction::Continue,
        ) => WasixResolvedAction::Ignore,
        helios_unix::ResolvedSignal::Catch(handler) => WasixResolvedAction::Catch(handler),
        helios_unix::ResolvedSignal::Default(
            helios_unix::DefaultSignalAction::Terminate
            | helios_unix::DefaultSignalAction::CoreDump
            | helios_unix::DefaultSignalAction::Stop,
        ) => WasixResolvedAction::Terminate,
    }
}

#[derive(Clone, Copy)]
pub(super) struct WasixTtyState {
    pub(super) cols: u32,
    pub(super) rows: u32,
    pub(super) width: u32,
    pub(super) height: u32,
    pub(super) stdin_tty: bool,
    pub(super) stdout_tty: bool,
    pub(super) stderr_tty: bool,
    pub(super) echo: bool,
    pub(super) line_buffered: bool,
    pub(super) line_feeds: bool,
}

#[derive(Clone)]
pub(super) struct Preview1Cwd {
    pub(super) guest_name: String,
    pub(super) descriptor: FsDescriptor,
}

/// Process-wide working directory shared by every store of one WASIX process.
///
/// # Concurrency contract
///
/// Every caller runs in task context (never an interrupt handler). The
/// `spin::Mutex` is held only to clone or replace `Option<Preview1Cwd>` and
/// is always dropped before any `.await` (path resolution and `stat_path`
/// run outside the lock).
#[derive(Clone)]
pub(super) struct SharedCwd {
    inner: Arc<Mutex<Option<Preview1Cwd>>>,
}

impl SharedCwd {
    pub(super) fn new(cwd: Option<Preview1Cwd>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(cwd)),
        }
    }

    pub(super) fn get(&self) -> Option<Preview1Cwd> {
        self.inner.lock().clone()
    }

    pub(super) fn set(&self, cwd: Option<Preview1Cwd>) {
        *self.inner.lock() = cwd;
    }

    pub(super) fn with<R>(&self, f: impl FnOnce(Option<&Preview1Cwd>) -> R) -> R {
        f(self.inner.lock().as_ref())
    }
}

/// Process-wide descriptor table shared by every store of one WASIX process.
///
/// # Concurrency contract
///
/// Every caller runs in task context (never an interrupt handler). The
/// `spin::Mutex` guards only in-memory slot lookups, insertions,
/// duplications, flag reads/writes, closes, and table snapshots, and is
/// always dropped before any `.await` or guest call. Open file descriptions
/// (`OpenFile` with its async `RawMutex` position lock, `FileDescriptorEntry`'s
/// atomic `fdflags`, and shared `Socket` handles) are cloned out under the
/// lock so concurrent I/O across threads shares offsets, status flags, and
/// socket state without holding the table spin lock across `.await`.
pub(super) struct SharedDescriptorTable<Net: ComponentHostNetwork> {
    inner: Arc<Mutex<Preview1DescriptorTable<Net>>>,
}

impl<Net: ComponentHostNetwork> Clone for SharedDescriptorTable<Net> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<Net: ComponentHostNetwork> SharedDescriptorTable<Net> {
    pub(super) fn new(table: Preview1DescriptorTable<Net>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(table)),
        }
    }

    pub(super) fn with<R>(&self, f: impl FnOnce(&Preview1DescriptorTable<Net>) -> R) -> R {
        f(&self.inner.lock())
    }

    pub(super) fn with_mut<R>(&self, f: impl FnOnce(&mut Preview1DescriptorTable<Net>) -> R) -> R {
        f(&mut self.inner.lock())
    }

    /// Clones a descriptor handle out of slot `fd` and drops the table lock
    /// immediately so callers can await I/O on the handle without holding the
    /// spin lock.
    pub(super) fn get_cloned(&self, fd: i32) -> Option<Preview1Descriptor<Net>> {
        self.inner.lock().get(fd).cloned()
    }

    /// Point-in-time snapshot of the process's descriptor table (preserving
    /// open-file-description sharing on every slot) for `fork`, `proc_snapshot`,
    /// or `proc_spawn2` fd-op evaluation.
    pub(super) fn snapshot(&self) -> Preview1DescriptorTable<Net> {
        self.inner.lock().clone()
    }

    /// Snapshot with `close_on_exec` slots cleared for `proc_exec*` from any
    /// thread of the process.
    pub(super) fn clone_for_exec(&self) -> Preview1DescriptorTable<Net> {
        self.inner.lock().clone_for_exec()
    }

    pub(super) fn insert(&self, descriptor: Preview1Descriptor<Net>) -> Result<u32, i32> {
        self.inner.lock().insert(descriptor)
    }

    #[cfg(test)]
    pub(super) fn insert_with_close_on_exec(
        &self,
        descriptor: Preview1Descriptor<Net>,
        close_on_exec: bool,
    ) -> Result<u32, i32> {
        self.inner
            .lock()
            .insert_with_close_on_exec(descriptor, close_on_exec)
    }

    pub(super) fn insert_with_fdflags(
        &self,
        descriptor: Preview1Descriptor<Net>,
        close_on_exec: bool,
        fdflags: u16,
    ) -> Result<u32, i32> {
        self.inner
            .lock()
            .insert_with_fdflags(descriptor, close_on_exec, fdflags)
    }

    pub(super) fn dup(&self, fd: i32) -> Result<u32, i32> {
        self.inner.lock().dup(fd)
    }

    pub(super) fn dup2(&self, from: i32, to: i32) -> i32 {
        self.inner.lock().dup2(from, to)
    }

    pub(super) fn dup_to(&self, fd: i32, to_fd: i32, close_on_exec: bool) -> Result<u32, i32> {
        self.inner.lock().dup_to(fd, to_fd, close_on_exec)
    }

    pub(super) fn renumber(&self, from: i32, to: i32) -> i32 {
        self.inner.lock().renumber(from, to)
    }

    pub(super) fn close(&self, fd: i32) -> i32 {
        self.inner.lock().close(fd)
    }

    pub(super) fn fdflags(&self, fd: i32) -> Result<u16, i32> {
        self.inner.lock().fdflags(fd)
    }

    #[cfg(test)]
    pub(super) fn set_fdflags(&self, fd: i32, fdflags: u16) -> i32 {
        self.inner.lock().set_fdflags(fd, fdflags)
    }

    pub(super) fn close_on_exec(&self, fd: i32) -> Result<bool, i32> {
        self.inner.lock().close_on_exec(fd)
    }

    pub(super) fn set_close_on_exec(&self, fd: i32, close_on_exec: bool) -> i32 {
        self.inner.lock().set_close_on_exec(fd, close_on_exec)
    }

    pub(super) fn limit(&self) -> helios_unix::DescriptorLimit {
        self.inner.lock().limit
    }
}

#[derive(Clone)]
pub(super) struct Preview1DescriptorTable<Net: ComponentHostNetwork> {
    slots: helios_unix::DescriptorSlots<Preview1DescriptorEntry<Net>>,
}

impl<Net: ComponentHostNetwork> core::ops::Deref for Preview1DescriptorTable<Net> {
    type Target = helios_unix::DescriptorSlots<Preview1DescriptorEntry<Net>>;
    fn deref(&self) -> &Self::Target {
        &self.slots
    }
}
impl<Net: ComponentHostNetwork> core::ops::DerefMut for Preview1DescriptorTable<Net> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.slots
    }
}

/// Where a process's descriptor table comes from. Every place that builds
/// a process names one, because the case decides which descriptor limit the
/// process runs with.
pub(super) enum DescriptorOrigin<Net: ComponentHostNetwork> {
    /// A process that inherits nothing: its table holds the standard
    /// streams and the authority's directories, under the machine's
    /// current limit.
    Fresh,
    /// A new process (a fork child, a spawn child) that inherits its
    /// parent's descriptors. It is a new process, so it takes the machine's
    /// current limit, not its parent's; descriptors it inherits at or past
    /// that limit stay open.
    NewProcess(Preview1DescriptorTable<Net>),
    /// The same process continuing in a new image, store or thread (exec,
    /// a new thread). It keeps the limit it has.
    SameProcess(Preview1DescriptorTable<Net>),
}

/// The descriptor table a process starts with, under the limit its origin
/// gives it. A spawn's descriptor actions read the setting once more,
/// earlier, because they run on the child's table before it reaches here.
pub(super) fn process_descriptors<Net: ComponentHostNetwork>(
    origin: DescriptorOrigin<Net>,
    authority: &ProcessAuthority,
    settings: &Settings,
    inherited_sockets: Vec<UnixSocket<Net>>,
) -> Preview1DescriptorTable<Net> {
    match origin {
        DescriptorOrigin::Fresh => Preview1DescriptorTable::from_authority_with_sockets(
            authority,
            settings.get::<DescriptorLimitSetting>(),
            inherited_sockets,
        ),
        DescriptorOrigin::NewProcess(mut table) => {
            table = table.for_new_process(settings.get::<DescriptorLimitSetting>());
            install_preview1_inherited_sockets(&mut table, inherited_sockets);
            table
        }
        DescriptorOrigin::SameProcess(mut table) => {
            install_preview1_inherited_sockets(&mut table, inherited_sockets);
            table
        }
    }
}

pub(super) fn install_preview1_inherited_sockets<Net: ComponentHostNetwork>(
    table: &mut Preview1DescriptorTable<Net>,
    sockets: Vec<UnixSocket<Net>>,
) {
    if sockets.is_empty() {
        return;
    }
    // Shift existing preopens (installed starting at fd = 3) so inherited
    // sockets deterministically occupy fd = 3, 4, ... without clobbering
    // directory preopens.
    let tail = if table.entries.len() > 3 {
        table.entries.split_off(3)
    } else {
        Vec::new()
    };
    while table.entries.len() < 3 {
        table.entries.push(None);
    }
    for socket in sockets {
        table.entries.push(Some(Preview1DescriptorEntry::new(
            Preview1Descriptor::Socket(socket),
            false,
        )));
    }
    table.entries.extend(tail);
}
fn descriptor_errno(error: helios_unix::DescriptorTableError) -> i32 {
    match error {
        helios_unix::DescriptorTableError::BadDescriptor(_) => p1::errno::BADF,
        helios_unix::DescriptorTableError::TooManyDescriptors { .. } => p1::errno::MFILE,
        helios_unix::DescriptorTableError::IndexOverflow => p1::errno::OVERFLOW,
        helios_unix::DescriptorTableError::RightsWidening => p1::errno::NOTCAPABLE,
    }
}
pub(super) type Preview1DescriptorEntry<Net> =
    helios_unix::FileDescriptorEntry<FsDescriptor, crate::UnixNetwork<Net>, EpollUserData>;
pub(super) type Preview1Descriptor<Net> =
    helios_unix::FileDescriptor<FsDescriptor, crate::UnixNetwork<Net>, EpollUserData>;

/// The shared UNIX socket objects on the machine's network, as every
/// descriptor table in this host (WASIX's and the Linux host's) holds them.
pub(super) type UnixSocket<Net> = helios_unix::Socket<crate::UnixNetwork<Net>>;
pub(super) type UnixTcpSocket<Net> = helios_unix::TcpSocket<crate::UnixNetwork<Net>>;
pub(super) type UnixUdpSocket<Net> = helios_unix::UdpSocket<crate::UnixNetwork<Net>>;
pub(super) type UnixSocketHandle<Net> = helios_unix::SocketHandle<crate::UnixNetwork<Net>>;
/// The options a new socket on the machine's network starts with.
pub(super) const fn unix_socket_options<Net: ComponentHostNetwork>() -> SocketOptions {
    SocketOptions::for_network::<crate::UnixNetwork<Net>>()
}
#[cfg(feature = "linux")]
pub(super) use helios_unix::OwnedVsockStream;
pub(super) use helios_unix::{
    OwnedTcpListener, OwnedTcpStream, OwnedUdpSocket, OwnedVsockListener, SocketFamily, SocketFlag,
    SocketKind, SocketOptionError, SocketOptions, SocketSize, SocketTime, VsockSocket,
};

pub(super) type EpollDescriptor = helios_unix::Epoll<EpollUserData>;
pub(super) type EpollInterest = helios_unix::Interest<EpollUserData>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct EpollUserData {
    pub(super) ptr: u32,
    pub(super) fd: u32,
    pub(super) data1: u32,
    pub(super) data2: u64,
}

pub(super) enum EpollWaitTarget {
    ByteReader {
        reader: crate::ByteReader,
        wait: crate::ByteReadWait,
    },
    /// A pipe/socketpair write end whose channel is at capacity. The
    /// waiter sleeps until the peer drains, exactly like the read side
    /// sleeps until bytes arrive.
    ByteWriter {
        writer: crate::ByteWriter,
        wait: crate::ByteWriteWait,
    },
    Event {
        event: EventFd,
        wait: crate::NotifyWaiter,
    },
    /// Serial-backed stdin: the debug console's receive signal is the
    /// wakeup source, parked on through the writer handle's poll form.
    SerialInput {
        serial: crate::DebugSerialWriter,
        wait: crate::NotifyWaiter,
    },
}

impl EpollWaitTarget {
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        match self {
            Self::ByteReader { reader, wait } => reader.poll_readable(cx, wait),
            Self::ByteWriter { writer, wait } => writer.poll_writable(cx, wait),
            Self::Event { event, wait } => event.poll_readable(cx, wait),
            Self::SerialInput { serial, wait } => serial.poll_debug_serial_input(cx, wait),
        }
    }
}

/// How long a waiter sleeps between re-probing descriptors that have no
/// wakeup source of their own.
///
/// Network sockets only advance when the device is driven, so a waiter
/// registered on one of them has to come back and look. This matches the
/// network service's own progress cadence; it is a bounded sleep, not a
/// spin.
pub(super) const P1_READINESS_REPOLL_INTERVAL: Duration = Duration::from_micros(50);

/// Everything a `poll_oneoff`/`epoll_wait` sleep has to watch.
pub(super) struct P1WaitSet {
    /// Descriptors that wake the task themselves (pipes, socketpairs,
    /// eventfds, child stdin).
    pub(super) notified: Vec<EpollWaitTarget>,
    /// Set when at least one descriptor only reveals readiness by being
    /// re-probed (network sockets).
    pub(super) repoll: bool,
}

impl P1WaitSet {
    pub(super) fn new() -> Self {
        Self {
            notified: Vec::new(),
            repoll: false,
        }
    }

    /// True when nothing in the set can ever report readiness, so a waiter
    /// with no deadline would block forever.
    pub(super) fn is_empty(&self) -> bool {
        self.notified.is_empty() && !self.repoll
    }
}

/// Sleep until a watched descriptor wakes us, a catchable handled signal
/// arrives, the re-probe cadence elapses, or `remaining` runs out.
///
/// The caller re-probes after every step, so this only has to guarantee that
/// it yields control and comes back when something might have changed.
/// `remaining` of `None` means "no deadline": block until a descriptor makes
/// progress or a handled signal interrupts the wait.
pub(super) async fn p1_wait_step<CpuImpl>(
    timer: &crate::Timer<CpuImpl>,
    wait: &mut P1WaitSet,
    remaining: Option<Duration>,
    signals: &WasixStoreSignals,
    active_handlers: helios_unix::SignalSet,
) -> bool
where
    CpuImpl: Cpu + Clone,
{
    let mut catch_signal = core::pin::pin!(signals.wait_for_catch_signal(active_handlers));
    if wait.is_empty() && remaining.is_none() {
        // Nothing subscribed can ever become ready and no deadline will end
        // the call; only a caught signal (or a fatal stop on the outer turn)
        // can wake it.
        catch_signal.await;
        return true;
    }

    // A descriptor without a wakeup source needs us back on a fixed cadence;
    // otherwise sleep the whole remaining budget in one go.
    let sleep = match (wait.repoll, remaining) {
        (true, Some(remaining)) => remaining.min(P1_READINESS_REPOLL_INTERVAL),
        (true, None) => P1_READINESS_REPOLL_INTERVAL,
        (false, Some(remaining)) => remaining,
        (false, None) => {
            // Every subscribed descriptor can wake us, so wait on them and
            // any caught signal.
            let targets = &mut wait.notified;
            return core::future::poll_fn(|cx| {
                if catch_signal.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(true);
                }
                if poll_epoll_wait_targets(targets, cx).is_ready() {
                    return Poll::Ready(false);
                }
                Poll::Pending
            })
            .await;
        }
    };

    if sleep.is_zero() {
        return signals.has_deliverable_catch(active_handlers);
    }

    let mut timer = core::pin::pin!(timer.sleep_for(sleep));
    if wait.notified.is_empty() {
        return core::future::poll_fn(|cx| {
            if catch_signal.as_mut().poll(cx).is_ready() {
                return Poll::Ready(true);
            }
            if timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(false);
            }
            Poll::Pending
        })
        .await;
    }

    // Race the wakeup sources against the sleep and caught signals: whichever
    // comes first ends this step and sends the caller back to re-probe.
    let targets = &mut wait.notified;
    core::future::poll_fn(|cx| {
        if catch_signal.as_mut().poll(cx).is_ready() {
            return Poll::Ready(true);
        }
        if poll_epoll_wait_targets(targets, cx).is_ready() {
            return Poll::Ready(false);
        }
        if timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(false);
        }
        Poll::Pending
    })
    .await
}

/// Register whatever wakes `fd` into `wait`.
///
/// Descriptors backed by a kernel channel register a real waiter, and
/// serial-backed stdin parks on the console's receive signal. Network
/// sockets have no wakeup source, so they only set the re-probe flag.
pub(super) fn p1_add_wait_target<CpuImpl, Net, StorageImpl>(
    store: &Preview1ProgramStore<CpuImpl, Net, StorageImpl>,
    fd: i32,
    event_type: u8,
    wait: &mut P1WaitSet,
) where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    store
        .descriptors
        .with(|descriptors| match descriptors.get(fd) {
            Some(Preview1Descriptor::PipeRead { reader, .. })
                if event_type == P1_EVENTTYPE_FD_READ =>
            {
                wait.notified.push(EpollWaitTarget::ByteReader {
                    reader: reader.clone(),
                    wait: reader.wait_state(),
                });
            }
            Some(Preview1Descriptor::Socket(socket)) => {
                if let Some((reader, carry_len)) = socket.pair_read_probe() {
                    if event_type == P1_EVENTTYPE_FD_READ && carry_len == 0 {
                        wait.notified.push(EpollWaitTarget::ByteReader {
                            reader: reader.clone(),
                            wait: reader.wait_state(),
                        });
                    } else if event_type == P1_EVENTTYPE_FD_WRITE
                        && let Some(writer) = socket.pair_writer()
                        && !writer.is_writable()
                    {
                        wait.notified.push(EpollWaitTarget::ByteWriter {
                            writer: writer.clone(),
                            wait: writer.wait_state(),
                        });
                    }
                } else if socket.handle().is_some() {
                    wait.repoll = true;
                }
            }
            Some(Preview1Descriptor::PipeWrite { writer, .. })
                if event_type == P1_EVENTTYPE_FD_WRITE && !writer.is_writable() =>
            {
                wait.notified.push(EpollWaitTarget::ByteWriter {
                    writer: writer.clone(),
                    wait: writer.wait_state(),
                });
            }
            Some(Preview1Descriptor::Event(event))
                if event_type == P1_EVENTTYPE_FD_READ && !event.is_readable() =>
            {
                wait.notified.push(EpollWaitTarget::Event {
                    event: event.clone(),
                    wait: event.wait_state(),
                });
            }
            Some(Preview1Descriptor::Stdin { carry })
                if carry.is_empty() && event_type == P1_EVENTTYPE_FD_READ =>
            {
                match store.output_mode.stdin_route() {
                    // A child's stdin is a byte channel, so it can wake us.
                    crate::ComponentInputRoute::Child(stdin_rx) => {
                        wait.notified.push(EpollWaitTarget::ByteReader {
                            wait: stdin_rx.wait_state(),
                            reader: stdin_rx,
                        });
                    }
                    // The serial console's receive signal is the wakeup
                    // source, parked on the same way a channel's is.
                    crate::ComponentInputRoute::Serial => {
                        wait.notified.push(EpollWaitTarget::SerialInput {
                            serial: store.write_serial,
                            wait: store.write_serial.debug_serial_input_waiter(),
                        })
                    }
                    // Trace or closed input never delivers input; the probe reports
                    // it as an immediate hangup, so there is nothing to wait for.
                    crate::ComponentInputRoute::Closed => {}
                }
            }
            _ => {}
        });
}

/// Resolve a descriptor's readiness, consulting the network service when the
/// descriptor is a socket and the console when it is serial-backed stdin.
pub(super) async fn p1_descriptor_readiness<CpuImpl, Net, StorageImpl>(
    caller: &mut Caller<'_, Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    fd: i32,
    event_type: u8,
) -> Result<P1Readiness, i32>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    if event_type == P1_EVENTTYPE_FD_READ
        && caller.data().descriptors.with(|descriptors| {
            matches!(descriptors.get(fd), Some(Preview1Descriptor::Stdin { .. }))
        })
    {
        return Ok(caller.data_mut().probe_stdin(fd));
    }
    let probe = match caller
        .data()
        .descriptors
        .with(|descriptors| p1_probe_descriptor(descriptors.get(fd), event_type))?
    {
        P1Probe::Local(readiness) => return Ok(readiness),
        P1Probe::Network(probe) => probe,
    };
    let readiness = match probe {
        UnixSocketHandle::<Net>::TcpStream(stream) => {
            let Some(service) = caller.data().runtime_state.network_service() else {
                return Err(p1::errno::NETDOWN);
            };
            service
                .tcp_readiness(stream)
                .await
                .map_err(p1_errno_from_tcp_error)?
        }
        UnixSocketHandle::<Net>::TcpListener(listener) => {
            let Some(service) = caller.data().runtime_state.network_service() else {
                return Err(p1::errno::NETDOWN);
            };
            service
                .tcp_listener_readiness(listener)
                .await
                .map_err(p1_errno_from_tcp_error)?
        }
        UnixSocketHandle::<Net>::UdpSocket(socket) => {
            let Some(service) = caller.data().runtime_state.network_service() else {
                return Err(p1::errno::NETDOWN);
            };
            service
                .udp_readiness(socket)
                .await
                .map_err(p1_errno_from_udp_error)?
        }
        UnixSocketHandle::<Net>::PacketSocket(socket) => {
            let Some(service) = caller.data().runtime_state.network_service() else {
                return Err(p1::errno::NETDOWN);
            };
            service
                .packet_readiness(socket)
                .await
                .map_err(p1_errno_from_udp_error)?
        }
        UnixSocketHandle::<Net>::IcmpSocket(socket) => {
            let Some(service) = caller.data().runtime_state.network_service() else {
                return Err(p1::errno::NETDOWN);
            };
            service
                .icmp_readiness(socket)
                .await
                .map_err(p1_errno_from_udp_error)?
        }
        UnixSocketHandle::<Net>::VsockListener(listener) => {
            let Some(vsock) = caller.data().runtime_state.vsock_service() else {
                return Err(p1::errno::NETDOWN);
            };
            let readable = vsock
                .listener_readable(crate::VsockListenerId::from_u64(listener))
                .map_err(|_| p1::errno::IO)?;
            crate::SocketReadiness {
                readable,
                writable: false,
                hangup: false,
            }
        }
        UnixSocketHandle::<Net>::VsockStream(stream) => {
            let Some(vsock) = caller.data().runtime_state.vsock_service() else {
                return Err(p1::errno::NETDOWN);
            };
            vsock
                .stream_readiness(crate::VsockStreamId::from_u64(stream))
                .map_err(|_| p1::errno::IO)?
        }
    };
    Ok(p1_readiness_from_socket(readiness, event_type))
}

pub(super) fn p1_readiness_from_socket(
    readiness: crate::SocketReadiness,
    event_type: u8,
) -> P1Readiness {
    let ready = if event_type == P1_EVENTTYPE_FD_WRITE {
        readiness.writable
    } else {
        readiness.readable
    };
    if !ready {
        return P1Readiness::Pending;
    }
    if event_type == P1_EVENTTYPE_FD_READ && readiness.hangup {
        return P1Readiness::Hangup;
    }
    // The stack reports "something is queued" without a length, and a
    // send is window-limited rather than byte-counted; report one byte so
    // callers see a non-zero count and read what is actually there.
    P1Readiness::Ready { bytes: 1 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WasixSocketAuthority {
    LocalOnly,
    Tcp,
    Udp,
}

#[derive(Debug, Error)]
#[error("guest requested wasi preview1 exit")]
pub(super) struct Preview1Exit;

/// The guest ended its own thread (`thread_exit`) with the status it
/// requested. A spawned thread ends alone, as `pthread_exit` does; on
/// main the image ends with the status, as it does on `proc_exit`.
/// Every other requested end ([`Preview1Exit`]) ends the whole process,
/// whichever thread asks for it.
#[derive(Debug, Error)]
#[error("guest requested wasix thread exit")]
pub(super) struct WasixThreadExitRequested;

impl WasixThreadExitRequested {
    /// Whether `error` is a thread's own exit.
    pub(super) fn is(error: &wasmtime::Error) -> bool {
        error.downcast_ref::<Self>().is_some()
    }
}

/// A pending WASIX signal raised on the process ended the guest. The
/// program ends with that signal, whatever the guest asked for before it,
/// and on any thread the whole process does.
#[derive(Debug, Error)]
#[error("guest ended by wasix signal {signal}")]
pub(crate) struct Preview1SignalExit {
    pub(crate) signal: u8,
}

/// A WASIX signal raised on one thread alone (`thread_signal`) ended
/// that thread's call. A spawned thread ends alone with `128 + signal`,
/// so a joiner sees the status, and main ends the image with the signal.
#[derive(Debug, Error)]
#[error("wasix thread ended by thread-directed signal {signal}")]
pub(super) struct WasixThreadSignalExit {
    pub(super) signal: u8,
}

impl WasixThreadSignalExit {
    pub(super) fn exit_code(&self) -> u32 {
        128u32.saturating_add(u32::from(self.signal))
    }
}

/// The process a WASIX thread belongs to ended, and the thread ends with
/// it ([`WasixSignalState::end_thread`]). On main it means a spawned
/// thread ended the process ([`WasixProcessThreads::end_from_thread`]),
/// and main completes the way that thread chose.
#[derive(Debug, Error)]
#[error("wasix thread ended with its process")]
pub(super) struct WasixThreadEnded;

impl WasixThreadEnded {
    /// The status the ended thread reports: a SIGKILL's, since nothing
    /// the thread did ended it. Nobody can join it any more, so the
    /// status is only ever seen by the process's own end.
    pub(super) const EXIT_CODE: u32 = 128 + 9;

    /// Whether `error` is a thread's end.
    pub(super) fn is(error: &wasmtime::Error) -> bool {
        error.downcast_ref::<Self>().is_some()
    }
}

/// The termination of a program whose call ended in `error`, given the
/// status the guest `requested` before: the signal that ended it, raised
/// on its process or its thread, otherwise an owner kill, otherwise the
/// requested exit status, otherwise none.
pub(super) fn preview1_exit_status(
    error: &wasmtime::Error,
    requested: Option<u32>,
) -> Option<helios_unix::ChildTermination> {
    if let Some(exit) = error.downcast_ref::<Preview1SignalExit>() {
        return Some(helios_unix::ChildTermination::Signaled(
            helios_unix::SignalTermination {
                signal: exit.signal,
                core_dumped: false,
            },
        ));
    }
    if let Some(exit) = error.downcast_ref::<WasixThreadSignalExit>() {
        return Some(helios_unix::ChildTermination::Signaled(
            helios_unix::SignalTermination {
                signal: exit.signal,
                core_dumped: false,
            },
        ));
    }
    if let Some(killed) = error.downcast_ref::<crate::InstanceKilled>() {
        return match killed.reason {
            crate::KillReason::Operator | crate::KillReason::RequesterGone => {
                Some(helios_unix::ChildTermination::Killed)
            }
            crate::KillReason::OutOfMemory
            | crate::KillReason::SupervisorRestart
            | crate::KillReason::StoreFailed => None,
        };
    }
    if caused_by_out_of_memory(error) {
        return None;
    }
    requested.map(helios_unix::ChildTermination::Exited)
}

/// How a running process ends when one of its guest calls ended in `error`,
/// given the status the guest `requested` before: the signal, owner kill or
/// requested exit [`preview1_exit_status`] finds, otherwise an out-of-memory
/// or supervisor failure when condemned for one, otherwise a guest trap.
/// Main's own end, a spawned thread's end of its process, and a component's
/// `run` all report through this, so every guest kind classifies endings
/// identically.
pub(super) fn preview1_process_end(
    error: wasmtime::Error,
    requested: Option<u32>,
) -> Result<helios_unix::ChildTermination, ProgramExecError> {
    if let Some(termination) = preview1_exit_status(&error, requested) {
        return Ok(termination);
    }
    if caused_by_out_of_memory(&error) || error.downcast_ref::<crate::InstanceKilled>().is_some() {
        return Err(map_program_runtime_error(error));
    }
    tracing::debug!(?error, "guest program trapped");
    Ok(helios_unix::ChildTermination::Trapped)
}

/// Next safe-point signal action claimed from a store's mailboxes.
pub(super) enum WasixPendingDelivery {
    ThreadEnded,
    TerminateThread(u8),
    TerminateProcess(u8),
    Catch {
        signal: helios_unix::Signal,
        callback: Arc<str>,
        thread_directed: bool,
    },
}

/// The signals one store answers to: those raised on its own thread and
/// those raised on its process, resolved through the process's shared
/// [`WasixProcessSignals`]. A thread-directed raise reaches only this
/// store's turn; a process-directed one goes to whichever store of the
/// process takes it first.
///
/// # Concurrency
///
/// As [`WasixSignalState`] and [`WasixProcessSignals`]: either mailbox is
/// raised from any processor, dispositions are sampled under a short
/// task-context spin lock never held across `.await`, and atomic bitmask
/// compare-exchange ensures each signal is claimed once.
#[derive(Clone)]
pub(super) struct WasixStoreSignals {
    thread: WasixSignalState,
    process: WasixSignalState,
    dispositions: WasixProcessSignals,
}

impl WasixStoreSignals {
    #[cfg(test)]
    pub(super) fn new(thread: WasixSignalState, process: WasixSignalState) -> Self {
        Self::with_dispositions(thread, process, WasixProcessSignals::default())
    }

    pub(super) fn with_dispositions(
        thread: WasixSignalState,
        process: WasixSignalState,
        dispositions: WasixProcessSignals,
    ) -> Self {
        Self {
            thread,
            process,
            dispositions,
        }
    }

    /// The fatal stop this store owes its guest now, if any: the end of its
    /// thread's process, which stays owed, then a pending signal whose
    /// disposition is to terminate. Ignored signals are dropped in place and
    /// caught signals stay pending in the bitmask until the next safe point.
    pub(super) fn owed_stop(&self) -> Option<wasmtime::Error> {
        if self.thread.thread_ended() {
            return Some(wasmtime::Error::new(WasixThreadEnded));
        }
        let (ignored, has_callback) = self.dispositions.summary();
        let classify = |signal: helios_unix::Signal| match resolve_wasix_signal(
            signal,
            ignored,
            has_callback.then_some(()),
        ) {
            WasixResolvedAction::Ignore => helios_unix::SignalSweep::Drop,
            WasixResolvedAction::Catch(()) => helios_unix::SignalSweep::Retain,
            WasixResolvedAction::Terminate => helios_unix::SignalSweep::Take,
        };
        if let Some(signal) = self.thread.sweep_pending(classify) {
            return Some(wasmtime::Error::new(WasixThreadSignalExit {
                signal: signal.raw(),
            }));
        }
        self.process.sweep_pending(classify).map(|signal| {
            wasmtime::Error::new(Preview1SignalExit {
                signal: signal.raw(),
            })
        })
    }

    /// Claims the next deliverable action at a safe point, prioritizing fatal
    /// signals ahead of caught handlers and skipping caught signals already
    /// masked in `active_handlers` while their own callback runs.
    pub(super) fn take_next_delivery(
        &self,
        active_handlers: helios_unix::SignalSet,
    ) -> Option<WasixPendingDelivery> {
        if self.thread.thread_ended() {
            return Some(WasixPendingDelivery::ThreadEnded);
        }
        let (ignored, callback) = self.dispositions.snapshot();
        let has_callback = callback.is_some();
        let classify_fatal = |signal: helios_unix::Signal| match resolve_wasix_signal(
            signal,
            ignored,
            has_callback.then_some(()),
        ) {
            WasixResolvedAction::Ignore => helios_unix::SignalSweep::Drop,
            WasixResolvedAction::Catch(()) => helios_unix::SignalSweep::Retain,
            WasixResolvedAction::Terminate => helios_unix::SignalSweep::Take,
        };
        if let Some(signal) = self.thread.sweep_pending(classify_fatal) {
            return Some(WasixPendingDelivery::TerminateThread(signal.raw()));
        }
        if let Some(signal) = self.process.sweep_pending(classify_fatal) {
            return Some(WasixPendingDelivery::TerminateProcess(signal.raw()));
        }
        let callback = callback?;
        let classify_catch =
            |signal: helios_unix::Signal| match resolve_wasix_signal(signal, ignored, Some(())) {
                WasixResolvedAction::Ignore => helios_unix::SignalSweep::Drop,
                WasixResolvedAction::Terminate => helios_unix::SignalSweep::Retain,
                WasixResolvedAction::Catch(()) if active_handlers.contains(signal) => {
                    helios_unix::SignalSweep::Retain
                }
                WasixResolvedAction::Catch(()) => helios_unix::SignalSweep::Take,
            };
        if let Some(signal) = self.thread.sweep_pending(classify_catch) {
            return Some(WasixPendingDelivery::Catch {
                signal,
                callback,
                thread_directed: true,
            });
        }
        self.process
            .sweep_pending(classify_catch)
            .map(|signal| WasixPendingDelivery::Catch {
                signal,
                callback,
                thread_directed: false,
            })
    }

    /// Sweeps any ignored signals and reports whether an unmasked caught
    /// signal is waiting for safe-point delivery.
    pub(super) fn has_deliverable_catch(&self, active_handlers: helios_unix::SignalSet) -> bool {
        if self.thread.thread_ended() {
            return false;
        }
        let (ignored, has_callback) = self.dispositions.summary();
        let drop_ignored = |signal: helios_unix::Signal| match resolve_wasix_signal(
            signal,
            ignored,
            has_callback.then_some(()),
        ) {
            WasixResolvedAction::Ignore => helios_unix::SignalSweep::Drop,
            WasixResolvedAction::Catch(()) | WasixResolvedAction::Terminate => {
                helios_unix::SignalSweep::Retain
            }
        };
        let _ = self.thread.sweep_pending(drop_ignored);
        let _ = self.process.sweep_pending(drop_ignored);
        if !has_callback {
            return false;
        }
        let mut candidates = self
            .thread
            .pending_set()
            .union(self.process.pending_set())
            .difference(active_handlers);
        while let Some(signal) = candidates.take_first() {
            if matches!(
                resolve_wasix_signal(signal, ignored, Some(())),
                WasixResolvedAction::Catch(())
            ) {
                return true;
            }
        }
        false
    }

    /// Waits until an unmasked caught signal is ready for safe-point delivery,
    /// arming its broadcast waiter before inspecting the mailboxes.
    pub(super) async fn wait_for_catch_signal(&self, active_handlers: helios_unix::SignalSet) {
        use crate::component::StopWake as _;

        let mut wait = self.arm_stop_wait();
        core::future::poll_fn(|cx| {
            loop {
                if self.has_deliverable_catch(active_handlers) {
                    return Poll::Ready(());
                }
                if self.poll_stop_wait(cx, &mut wait).is_pending() {
                    return Poll::Pending;
                }
            }
        })
        .await;
    }
}

/// A raise on either mailbox, and the end of the thread, wakes the turn
/// driving this store, so a guest suspended in a host call is stopped
/// without waiting for the call.
impl crate::component::StopWake for WasixStoreSignals {
    type Wait = (crate::NotifyWaiter, crate::NotifyWaiter);

    fn arm_stop_wait(&self) -> Self::Wait {
        (self.thread.wait_state(), self.process.wait_state())
    }

    fn poll_stop_wait(
        &self,
        cx: &mut core::task::Context<'_>,
        (thread, process): &mut Self::Wait,
    ) -> core::task::Poll<()> {
        // Both are polled, so each re-arms on `Ready` as the trait asks
        // and each registers its listener on `Pending`.
        let thread = self.thread.poll_changed(cx, thread);
        let process = self.process.poll_changed(cx, process);
        if thread.is_ready() || process.is_ready() {
            core::task::Poll::Ready(())
        } else {
            core::task::Poll::Pending
        }
    }
}

/// A WASIX store delivers its thread's end and a pending signal wherever
/// its turn reads them: before the guest is resumed, when a raise or an
/// end wakes a suspended call, and when the call completes, which is
/// where a stop raised in the guest's last host call arrives, the guest
/// having gone back to the host without meeting the interrupt check that
/// would otherwise have delivered it.
impl<RuntimeStateImpl> crate::component::TurnEpilogue<RuntimeStateImpl, wasmtime::Error>
    for WasixStoreSignals
{
    fn end_turn(&self, _: &RuntimeStateImpl) {}

    fn take_stop(&self) -> Option<wasmtime::Error> {
        self.owed_stop()
    }
}

pub(super) fn preview1_cwd_from_authority(authority: &ProcessAuthority) -> Option<Preview1Cwd> {
    authority.cwd().map(|preopen| Preview1Cwd {
        guest_name: preopen.guest_name().to_owned(),
        descriptor: FsDescriptor {
            path: preopen.source_path().to_owned(),
            kind: FsNodeKind::Directory,
            flags: directory_authority_to_descriptor_flags(preopen.rights()),
            identity: None,
            mount: None,
            open: None,
        },
    })
}

pub(super) fn guest_path_is_within_preopen(path: &str, preopen: &str) -> bool {
    if path == preopen {
        return true;
    }
    let prefix = crate::directory_prefix(preopen);
    path.starts_with(&prefix)
}

pub(super) fn guest_path_suffix<'a>(path: &'a str, preopen: &str) -> &'a str {
    if preopen == "/" {
        path.strip_prefix('/').unwrap_or(path)
    } else {
        path.strip_prefix(preopen)
            .and_then(|suffix| suffix.strip_prefix('/'))
            .unwrap_or("")
    }
}

impl<Net: ComponentHostNetwork> Preview1DescriptorTable<Net> {
    pub(super) fn from_authority_with_sockets(
        authority: &ProcessAuthority,
        limit: DescriptorLimit,
        inherited_sockets: Vec<UnixSocket<Net>>,
    ) -> Self {
        let preopens = authority.directory_preopens();
        let mut entries = Vec::with_capacity(3 + inherited_sockets.len() + preopens.len());
        entries.push(Some(Preview1DescriptorEntry::new(
            Preview1Descriptor::Stdin {
                carry: Bytes::new(),
            },
            false,
        )));
        entries.push(Some(Preview1DescriptorEntry::new(
            Preview1Descriptor::Stdout,
            false,
        )));
        entries.push(Some(Preview1DescriptorEntry::new(
            Preview1Descriptor::Stderr,
            false,
        )));
        for socket in inherited_sockets {
            entries.push(Some(Preview1DescriptorEntry::new(
                Preview1Descriptor::Socket(socket),
                false,
            )));
        }
        let mut table = Self::from_entries_with_limit(entries, limit);
        for preopen in preopens {
            let descriptor = FsDescriptor {
                path: preopen.source_path().to_owned(),
                kind: FsNodeKind::Directory,
                flags: directory_authority_to_descriptor_flags(preopen.rights()),
                identity: None,
                mount: None,
                open: None,
            };
            table.entries.push(Some(Preview1DescriptorEntry::new(
                Preview1Descriptor::Preopen {
                    guest_name: preopen.guest_name().to_owned(),
                    descriptor,
                },
                false,
            )));
        }
        table
    }

    /// A table of `entries` whose numbers are admitted below `limit`.
    pub(super) fn from_entries_with_limit(
        entries: Vec<Option<Preview1DescriptorEntry<Net>>>,
        limit: DescriptorLimit,
    ) -> Self {
        let mut slots = helios_unix::DescriptorSlots::from_entries(entries);
        slots.limit = limit;
        Self { slots }
    }

    /// A fixture table of `entries` under the default limit. Production
    /// tables take their limit from the machine's setting.
    #[cfg(test)]
    pub(super) fn from_entries(entries: Vec<Option<Preview1DescriptorEntry<Net>>>) -> Self {
        Self::from_entries_with_limit(entries, DescriptorLimit::DEFAULT)
    }

    /// The same descriptors under `limit`, for a new process that inherits
    /// them. Descriptors open at or past a lowered limit stay open; no new
    /// number at or past it is handed out.
    pub(super) fn for_new_process(mut self, limit: DescriptorLimit) -> Self {
        self.limit = limit;
        self
    }

    pub(super) fn get(&self, fd: i32) -> Option<&Preview1Descriptor<Net>> {
        usize::try_from(fd)
            .ok()
            .and_then(|index| self.slots.entries.get(index))
            .and_then(Option::as_ref)
            .map(|entry| &entry.descriptor)
    }

    pub(super) fn get_mut(&mut self, fd: i32) -> Option<&mut Preview1Descriptor<Net>> {
        usize::try_from(fd)
            .ok()
            .and_then(|index| self.slots.entries.get_mut(index))
            .and_then(Option::as_mut)
            .map(|entry| &mut entry.descriptor)
    }

    pub(super) fn insert(&mut self, descriptor: Preview1Descriptor<Net>) -> Result<u32, i32> {
        self.insert_with_close_on_exec(descriptor, false)
    }

    pub(super) fn insert_with_close_on_exec(
        &mut self,
        descriptor: Preview1Descriptor<Net>,
        close_on_exec: bool,
    ) -> Result<u32, i32> {
        self.insert_entry(Preview1DescriptorEntry::new(descriptor, close_on_exec))
    }

    pub(super) fn insert_with_fdflags(
        &mut self,
        descriptor: Preview1Descriptor<Net>,
        close_on_exec: bool,
        fdflags: u16,
    ) -> Result<u32, i32> {
        let entry = Preview1DescriptorEntry::new(descriptor, close_on_exec);
        entry.set_fdflags(fdflags);
        self.insert_entry(entry)
    }

    pub(super) fn insert_entry(&mut self, entry: Preview1DescriptorEntry<Net>) -> Result<u32, i32> {
        self.slots.insert_entry(entry).map_err(descriptor_errno)
    }

    /// The slot a guest-named descriptor number `fd` denotes as the target
    /// of a dup2, renumber or spawn action: `BADF` when it is negative or
    /// at or past the limit. Every caller that accepts a number checks it
    /// here before touching the table.
    pub(super) fn target_index(&self, fd: i32) -> Result<usize, i32> {
        self.slots.target_index(fd).map_err(descriptor_errno)
    }

    pub(super) fn dup(&mut self, fd: i32) -> Result<u32, i32> {
        let mut entry = self.get_entry(fd).cloned().ok_or(p1::errno::BADF)?;
        entry.close_on_exec = false;
        self.insert_entry(entry)
    }

    pub(super) fn dup_to(&mut self, fd: i32, to_fd: i32, close_on_exec: bool) -> Result<u32, i32> {
        self.target_index(to_fd)?;
        let mut entry = self.get_entry(fd).cloned().ok_or(p1::errno::BADF)?;
        entry.close_on_exec = close_on_exec;
        self.insert_entry_at(to_fd, entry)
    }

    pub(super) fn insert_entry_at(
        &mut self,
        fd: i32,
        entry: Preview1DescriptorEntry<Net>,
    ) -> Result<u32, i32> {
        self.slots
            .insert_entry_at(fd, entry)
            .map_err(descriptor_errno)
    }

    pub(super) fn get_entry(&self, fd: i32) -> Option<&Preview1DescriptorEntry<Net>> {
        self.slots.get_entry(fd)
    }

    pub(super) fn get_entry_mut(&mut self, fd: i32) -> Option<&mut Preview1DescriptorEntry<Net>> {
        self.slots.get_entry_mut(fd)
    }

    pub(super) fn fdflags(&self, fd: i32) -> Result<u16, i32> {
        self.get_entry(fd)
            .map(|entry| entry.fdflags())
            .ok_or(p1::errno::BADF)
    }

    pub(super) fn set_fdflags(&mut self, fd: i32, fdflags: u16) -> i32 {
        let Some(entry) = self.get_entry_mut(fd) else {
            return p1::errno::BADF;
        };
        entry.set_fdflags(fdflags);
        p1::errno::SUCCESS
    }

    pub(super) fn close_on_exec(&self, fd: i32) -> Result<bool, i32> {
        usize::try_from(fd)
            .ok()
            .and_then(|index| self.slots.entries.get(index))
            .and_then(Option::as_ref)
            .map(|entry| entry.close_on_exec)
            .ok_or(p1::errno::BADF)
    }

    pub(super) fn set_close_on_exec(&mut self, fd: i32, close_on_exec: bool) -> i32 {
        match usize::try_from(fd)
            .ok()
            .and_then(|index| self.slots.entries.get_mut(index))
            .and_then(Option::as_mut)
        {
            Some(entry) => {
                entry.close_on_exec = close_on_exec;
                p1::errno::SUCCESS
            }
            None => p1::errno::BADF,
        }
    }

    /// The descriptor slots themselves, for a process of another ABI that
    /// takes this table over whole.
    #[cfg(feature = "linux")]
    pub(super) fn into_slots(self) -> helios_unix::DescriptorSlots<Preview1DescriptorEntry<Net>> {
        self.slots
    }

    /// Reconstructs a preview1 descriptor table from shared `helios-unix`
    /// slots when a Linux process executes a Wasm/WASIX image (`execve`).
    #[cfg(feature = "linux")]
    pub(super) fn from_slots(
        slots: helios_unix::DescriptorSlots<Preview1DescriptorEntry<Net>>,
    ) -> Self {
        Self { slots }
    }

    pub(super) fn clone_for_exec(&self) -> Self {
        Self::from_entries_with_limit(
            self.slots
                .entries
                .iter()
                .map(|entry| match entry {
                    Some(entry) if entry.close_on_exec => None,
                    _ => entry.clone(),
                })
                .collect(),
            self.slots.limit,
        )
    }

    pub(super) fn close(&mut self, fd: i32) -> i32 {
        self.slots
            .close(fd)
            .map_or_else(descriptor_errno, |_| p1::errno::SUCCESS)
    }

    pub(super) fn get_owned_entry(
        &mut self,
        fd: i32,
    ) -> Result<(usize, Preview1DescriptorEntry<Net>), i32> {
        let index = usize::try_from(fd).map_err(|_| p1::errno::BADF)?;
        let entry = self
            .slots
            .entries
            .get_mut(index)
            .and_then(Option::take)
            .ok_or(p1::errno::BADF)?;
        Ok((index, entry))
    }

    pub(super) fn close_slot(&mut self, index: usize) {
        self.slots.entries[index] = None;
        self.slots.free.release(index);
    }

    pub(super) fn renumber(&mut self, from: i32, to: i32) -> i32 {
        let Ok(to) = self.target_index(to) else {
            return p1::errno::BADF;
        };
        let Ok((from, mut entry)) = self.get_owned_entry(from) else {
            return p1::errno::BADF;
        };
        entry.close_on_exec = false;
        if from == to {
            self.slots.entries[from] = Some(entry);
            return p1::errno::SUCCESS;
        }
        if self.slots.entries.len() <= to {
            let previous_len = self.slots.entries.len();
            self.slots.entries.resize_with(to + 1, || None);
            self.slots.free.release_range(previous_len..to);
        }
        self.close_slot(from);
        self.slots.entries[to] = Some(entry);
        p1::errno::SUCCESS
    }

    /// POSIX `dup2`: `to` becomes a copy of `from`, which stays open, and
    /// whatever `to` held is closed. Naming the same descriptor twice
    /// leaves it as it is.
    pub(super) fn dup2(&mut self, from: i32, to: i32) -> i32 {
        if from == to {
            return match self.get_entry(from) {
                Some(_) => p1::errno::SUCCESS,
                None => p1::errno::BADF,
            };
        }
        match self.dup_to(from, to, false) {
            Ok(_) => p1::errno::SUCCESS,
            Err(errno) => errno,
        }
    }

    /// The stdio a component program launched over this table gets:
    /// `wasi:cli` stdin, stdout and stderr are descriptors 0, 1 and 2,
    /// whatever the launching process left in them. `inherited` is the
    /// launching process's own stdio, which the `Stdin`, `Stdout` and
    /// `Stderr` descriptors name; a table whose three slots are exactly
    /// those hands the component `inherited` itself.
    ///
    /// A closed slot is a closed stream: stdin reads end of file and a
    /// write to stdout or stderr fails, as a write to a closed descriptor
    /// does.
    pub(super) fn component_output_mode(
        &self,
        inherited: &OutputMode,
    ) -> Result<OutputMode, ComponentStdioRefusal> {
        let inherits_stdin = matches!(
            self.get(0),
            Some(Preview1Descriptor::Stdin { carry }) if carry.is_empty()
        );
        if inherits_stdin
            && matches!(self.get(1), Some(Preview1Descriptor::Stdout))
            && matches!(self.get(2), Some(Preview1Descriptor::Stderr))
        {
            return Ok(inherited.clone());
        }
        Ok(OutputMode::RoutedChild {
            stdin: self.component_stdin(inherited)?,
            stdout: self.component_output(1, inherited)?,
            stderr: self.component_output(2, inherited)?,
        })
    }

    fn component_stdin(
        &self,
        inherited: &OutputMode,
    ) -> Result<crate::ComponentInputRoute, ComponentStdioRefusal> {
        match self.get(0) {
            None | Some(Preview1Descriptor::NullDevice) => Ok(crate::ComponentInputRoute::Closed),
            Some(Preview1Descriptor::Stdin { carry }) if carry.is_empty() => {
                Ok(inherited.stdin_route())
            }
            Some(Preview1Descriptor::PipeRead { reader, .. }) => {
                Ok(crate::ComponentInputRoute::Child(reader.clone()))
            }
            Some(descriptor) => Err(ComponentStdioRefusal {
                fd: 0,
                held: unbindable_stdio(descriptor),
            }),
        }
    }

    fn component_output(
        &self,
        fd: u8,
        inherited: &OutputMode,
    ) -> Result<OutputRoute, ComponentStdioRefusal> {
        match self.get(i32::from(fd)) {
            None => Ok(OutputRoute::Child(crate::byte_channel().0)),
            Some(Preview1Descriptor::Stdout) => {
                Ok(inherited.route(crate::ComponentOutputStreamKind::Stdout))
            }
            Some(Preview1Descriptor::Stderr) => {
                Ok(inherited.route(crate::ComponentOutputStreamKind::Stderr))
            }
            Some(Preview1Descriptor::PipeWrite { writer, .. }) => {
                Ok(OutputRoute::Child(writer.clone()))
            }
            Some(Preview1Descriptor::NullDevice) => Ok(OutputRoute::Discard),
            Some(descriptor) => Err(ComponentStdioRefusal {
                fd,
                held: unbindable_stdio(descriptor),
            }),
        }
    }
}

/// What a descriptor that cannot be a component's standard stream holds.
fn unbindable_stdio<Net: ComponentHostNetwork>(
    descriptor: &Preview1Descriptor<Net>,
) -> UnbindableStdio {
    match descriptor {
        Preview1Descriptor::Stdin { carry } if !carry.is_empty() => UnbindableStdio::ReadAhead,
        Preview1Descriptor::Stdin { .. }
        | Preview1Descriptor::PipeRead { .. }
        | Preview1Descriptor::FifoRead(_)
        | Preview1Descriptor::Stdout
        | Preview1Descriptor::Stderr
        | Preview1Descriptor::PipeWrite { .. }
        | Preview1Descriptor::FifoWrite(_)
        | Preview1Descriptor::FifoReadWrite(_)
        | Preview1Descriptor::NullDevice
        | Preview1Descriptor::PseudoDevice(_)
        | Preview1Descriptor::PtyMaster(_)
        | Preview1Descriptor::PtySlave(_) => UnbindableStdio::WrongDirection,
        Preview1Descriptor::File(_) => UnbindableStdio::File,
        Preview1Descriptor::Preopen { .. } => UnbindableStdio::Directory,
        Preview1Descriptor::Socket(_) => UnbindableStdio::Socket,
        Preview1Descriptor::Event(_) => UnbindableStdio::Event,
        Preview1Descriptor::Epoll(_) => UnbindableStdio::Epoll,
    }
}

impl WasixTtyState {
    pub(super) fn from_authority(authority: &ProcessAuthority) -> Self {
        let rights = authority.terminal_rights();
        let input = rights.contains(TerminalAuthorityRights::INPUT);
        let output = rights.contains(TerminalAuthorityRights::OUTPUT);
        Self {
            cols: 80,
            rows: 24,
            width: 0,
            height: 0,
            stdin_tty: input,
            stdout_tty: output,
            stderr_tty: output,
            echo: input,
            line_buffered: input,
            line_feeds: true,
        }
    }
}

pub(super) fn directory_authority_to_descriptor_flags(
    rights: DirectoryAuthorityRights,
) -> FsDescriptorFlags {
    let mut flags = FsDescriptorFlags::empty();
    if rights.contains(DirectoryAuthorityRights::READ) {
        flags |= FsDescriptorFlags::READ;
    }
    if rights.contains(DirectoryAuthorityRights::WRITE) {
        flags |= FsDescriptorFlags::WRITE;
    }
    if rights.contains(DirectoryAuthorityRights::MUTATE_DIRECTORY) {
        flags |= FsDescriptorFlags::MUTATE_DIRECTORY;
    }
    flags
}

pub(super) fn descriptor_flags_to_directory_authority(
    flags: FsDescriptorFlags,
) -> DirectoryAuthorityRights {
    let mut rights = DirectoryAuthorityRights::empty();
    if flags.contains(FsDescriptorFlags::READ) {
        rights |= DirectoryAuthorityRights::READ;
    }
    if flags.contains(FsDescriptorFlags::WRITE) {
        rights |= DirectoryAuthorityRights::WRITE;
    }
    if flags.contains(FsDescriptorFlags::MUTATE_DIRECTORY) {
        rights |= DirectoryAuthorityRights::MUTATE_DIRECTORY;
    }
    rights
}

pub(super) fn p1_descriptor_rights<Net: ComponentHostNetwork>(
    descriptor: &Preview1Descriptor<Net>,
) -> u64 {
    match descriptor {
        Preview1Descriptor::Stdin { .. } => P1_RIGHT_FD_READ | P1_RIGHT_POLL_FD_READWRITE,
        Preview1Descriptor::Stdout | Preview1Descriptor::Stderr => {
            P1_RIGHT_FD_WRITE | P1_RIGHT_POLL_FD_READWRITE
        }
        Preview1Descriptor::PipeRead { .. } | Preview1Descriptor::FifoRead(_) => {
            P1_RIGHT_FD_READ | P1_RIGHT_POLL_FD_READWRITE
        }
        Preview1Descriptor::PipeWrite { .. } | Preview1Descriptor::FifoWrite(_) => {
            P1_RIGHT_FD_WRITE | P1_RIGHT_POLL_FD_READWRITE
        }
        Preview1Descriptor::FifoReadWrite(_)
        | Preview1Descriptor::PtyMaster(_)
        | Preview1Descriptor::PtySlave(_) => {
            P1_RIGHT_FD_READ | P1_RIGHT_FD_WRITE | P1_RIGHT_POLL_FD_READWRITE
        }
        Preview1Descriptor::Event(_) => {
            P1_RIGHT_FD_READ | P1_RIGHT_FD_WRITE | P1_RIGHT_POLL_FD_READWRITE
        }
        Preview1Descriptor::NullDevice | Preview1Descriptor::PseudoDevice(_) => {
            P1_RIGHT_FD_READ
                | P1_RIGHT_FD_WRITE
                | P1_RIGHT_FD_FDSTAT_SET_FLAGS
                | P1_RIGHT_FD_FILESTAT_GET
                | P1_RIGHT_POLL_FD_READWRITE
        }
        Preview1Descriptor::Epoll(_) => P1_RIGHT_FD_READ | P1_RIGHT_POLL_FD_READWRITE,
        Preview1Descriptor::Socket(_) => {
            P1_RIGHT_FD_READ | P1_RIGHT_FD_WRITE | P1_RIGHT_POLL_FD_READWRITE
        }
        Preview1Descriptor::Preopen { descriptor, .. } => p1_node_rights(descriptor),
        Preview1Descriptor::File(file) => p1_node_rights(file.node()),
    }
}

/// The preview1 rights a filesystem node handle's flags grant.
fn p1_node_rights(descriptor: &FsDescriptor) -> u64 {
    let mut rights = P1_RIGHT_FD_ADVISE | P1_RIGHT_FD_FILESTAT_GET;
    if descriptor.flags.contains(FsDescriptorFlags::READ) {
        rights |= P1_RIGHT_FD_READ
            | P1_RIGHT_FD_SEEK
            | P1_RIGHT_FD_TELL
            | P1_RIGHT_FD_READDIR
            | P1_RIGHT_POLL_FD_READWRITE
            | P1_RIGHT_PATH_READ_MASK;
    }
    if descriptor.flags.contains(FsDescriptorFlags::WRITE) {
        rights |= P1_RIGHT_FD_DATASYNC
            | P1_RIGHT_FD_SYNC
            | P1_RIGHT_FD_WRITE
            | P1_RIGHT_FD_ALLOCATE
            | P1_RIGHT_FD_FDSTAT_SET_FLAGS
            | P1_RIGHT_FD_FILESTAT_SET_SIZE
            | P1_RIGHT_FD_FILESTAT_SET_TIMES
            | P1_RIGHT_PATH_FILE_WRITE_MASK;
    }
    if descriptor
        .flags
        .contains(FsDescriptorFlags::MUTATE_DIRECTORY)
    {
        rights |= P1_RIGHT_PATH_MUTATE_MASK;
    }
    rights
}

pub(super) fn p1_filetype(kind: FsNodeKind) -> u8 {
    match kind {
        FsNodeKind::Directory => 3,
        FsNodeKind::File => 4,
        FsNodeKind::Symlink => 7,
        FsNodeKind::CharacterDevice => 2,
        FsNodeKind::BlockDevice => 1,
        // `filetype` has no FIFO, and a socket there is a datagram or a
        // stream one, which a filesystem node does not say: `unknown`.
        FsNodeKind::Fifo | FsNodeKind::Socket => 0,
    }
}

pub(super) fn p1_filetype_from_descriptor_type(type_: fs_types::DescriptorType) -> u8 {
    match type_ {
        fs_types::DescriptorType::Directory => 3,
        fs_types::DescriptorType::RegularFile => 4,
        fs_types::DescriptorType::SymbolicLink => 7,
        fs_types::DescriptorType::CharacterDevice => 2,
        fs_types::DescriptorType::BlockDevice => 1,
        _ => 0,
    }
}

pub(super) fn p1_null_device_stat() -> fs_types::DescriptorStat {
    fs_types::DescriptorStat {
        type_: fs_types::DescriptorType::CharacterDevice,
        link_count: 1,
        size: 0,
        data_access_timestamp: None,
        data_modification_timestamp: None,
        status_change_timestamp: None,
    }
}

/// Stable identity of the synthetic `/dev/null` character device.
///
/// It has no backing filesystem object, so it gets the guest-device authority
/// domain and a fixed inode: two `stat` calls on `/dev/null` must agree, and
/// its `st_dev` must not collide with bootfs or the host share.
pub(super) fn p1_null_device_identity() -> crate::ObjectIdentity {
    crate::ObjectIdentity::new(crate::AuthorityDomain::GUEST_DEVICES, 1)
}

/// Synthetic `filestat` for open descriptors with no backing filesystem path
/// (`/dev/null`, standard streams, and pipes), so `fstat(0..=2)` in Preview 1
/// runtimes (`wasi-libc` / CPython `init_sys_streams`) sees valid character
/// descriptors rather than `EBADF`.
pub(super) fn p1_synthetic_descriptor_stat<Net: ComponentHostNetwork>(
    descriptor: &Preview1Descriptor<Net>,
) -> Option<(crate::ObjectIdentity, fs_types::DescriptorStat)> {
    let identity = match descriptor {
        Preview1Descriptor::NullDevice => p1_null_device_identity(),
        Preview1Descriptor::Stdin { .. } => {
            crate::ObjectIdentity::new(crate::AuthorityDomain::GUEST_DEVICES, 2)
        }
        Preview1Descriptor::Stdout => {
            crate::ObjectIdentity::new(crate::AuthorityDomain::GUEST_DEVICES, 3)
        }
        Preview1Descriptor::Stderr => {
            crate::ObjectIdentity::new(crate::AuthorityDomain::GUEST_DEVICES, 4)
        }
        Preview1Descriptor::PipeRead { .. } | Preview1Descriptor::PipeWrite { .. } => {
            crate::ObjectIdentity::new(crate::AuthorityDomain::GUEST_DEVICES, 5)
        }
        _ => return None,
    };
    Some((identity, p1_null_device_stat()))
}

pub(super) fn p1_directory_descriptor<Net: ComponentHostNetwork>(
    descriptor: Option<&Preview1Descriptor<Net>>,
) -> Option<&FsDescriptor> {
    p1_fs_descriptor(descriptor).filter(|descriptor| descriptor.kind == FsNodeKind::Directory)
}

/// Readiness of one descriptor for a single `poll_oneoff`/`epoll` interest.
///
/// The probe used to return `Result<u64, i32>`, where `Ok(0)` meant both
/// "ready, nothing buffered" and "not ready at all". `poll_oneoff` read that
/// as ready and reported every subscription; `epoll_wait` read it as not
/// ready and never reported a socket. The tri-state removes the ambiguity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum P1Readiness {
    /// The operation would block; the caller has to wait for this descriptor.
    Pending,
    /// A non-blocking operation would make progress now. `bytes` is a
    /// best-effort count of what is immediately available; zero is valid
    /// (a regular file at end-of-file is always ready with nothing left).
    Ready { bytes: u64 },
    /// The stream ended: the peer hung up, or a read yields end-of-file.
    /// Ready for reporting purposes, and additionally flagged as a hangup.
    Hangup,
}

impl P1Readiness {
    pub(super) fn is_ready(self) -> bool {
        !matches!(self, Self::Pending)
    }

    pub(super) fn bytes(self) -> u64 {
        match self {
            Self::Ready { bytes } => bytes,
            Self::Pending | Self::Hangup => 0,
        }
    }

    pub(super) fn is_hangup(self) -> bool {
        matches!(self, Self::Hangup)
    }
}

/// Outcome of the synchronous readiness probe.
///
/// Descriptors backed by kernel-owned buffers answer immediately. Network
/// sockets cannot: the stack only advances when the device is driven, so
/// their readiness has to be resolved through the async network service.
/// Making that an explicit variant keeps a caller from silently reading a
/// socket as "not ready" when it simply never asked the network.
pub(super) enum P1Probe<Net: ComponentHostNetwork> {
    Local(P1Readiness),
    Network(UnixSocketHandle<Net>),
}

/// Probe every descriptor whose readiness is answerable from local state.
///
/// `event_type` is one of `P1_EVENTTYPE_FD_READ` / `P1_EVENTTYPE_FD_WRITE`.
pub(super) fn p1_probe_descriptor<Net: ComponentHostNetwork>(
    descriptor: Option<&Preview1Descriptor<Net>>,
    event_type: u8,
) -> Result<P1Probe<Net>, i32> {
    let local = |readiness| Ok(P1Probe::Local(readiness));
    match (descriptor, event_type) {
        (Some(Preview1Descriptor::Stdin { carry }), P1_EVENTTYPE_FD_READ) => {
            // Buffered stdin is ready; an empty carry means the backing
            // source has to be polled, which only the waiter can do.
            if carry.is_empty() {
                local(P1Readiness::Pending)
            } else {
                local(P1Readiness::Ready {
                    bytes: carry.len() as u64,
                })
            }
        }
        (Some(Preview1Descriptor::PipeRead { reader, .. }), P1_EVENTTYPE_FD_READ) => {
            local(if reader.is_readable() {
                P1Readiness::Ready { bytes: 1 }
            } else {
                P1Readiness::Pending
            })
        }
        (Some(Preview1Descriptor::Socket(socket)), P1_EVENTTYPE_FD_READ) if socket.is_pair() => {
            let Some((reader, carry_len)) = socket.pair_read_probe() else {
                return Err(p1::errno::INVAL);
            };
            if carry_len != 0 {
                return local(P1Readiness::Ready {
                    bytes: carry_len as u64,
                });
            }
            // `is_readable` covers queued bytes and a closed writer alike;
            // the channel exposes no queue length, so report one byte
            // available and let the read itself surface end-of-stream.
            if reader.is_readable() {
                local(P1Readiness::Ready { bytes: 1 })
            } else {
                local(P1Readiness::Pending)
            }
        }
        (Some(Preview1Descriptor::Event(event)), P1_EVENTTYPE_FD_READ) => {
            if event.is_readable() {
                local(P1Readiness::Ready { bytes: 8 })
            } else {
                local(P1Readiness::Pending)
            }
        }
        // Reading /dev/null returns end-of-file immediately, so it never
        // blocks.
        (Some(Preview1Descriptor::NullDevice), P1_EVENTTYPE_FD_READ) => {
            local(P1Readiness::Ready { bytes: 0 })
        }
        // POSIX: regular files and directories are always ready for both
        // directions. The byte count is advisory and the descriptor does not
        // carry a cached size, so report readiness without one rather than
        // paying a filesystem round-trip per poll.
        (
            Some(Preview1Descriptor::File(_)) | Some(Preview1Descriptor::Preopen { .. }),
            P1_EVENTTYPE_FD_READ | P1_EVENTTYPE_FD_WRITE,
        ) => local(P1Readiness::Ready { bytes: 0 }),
        // A guest-owned pipe or socketpair write end is a bounded channel:
        // report it writable only while it can actually take a chunk, so a
        // guest that polls for `POLLOUT` sleeps instead of spinning on a
        // full pipe. `is_writable` also covers a vanished peer, where the
        // write itself reports the error.
        (Some(Preview1Descriptor::PipeWrite { writer, .. }), P1_EVENTTYPE_FD_WRITE) => {
            if writer.is_writable() {
                local(P1Readiness::Ready {
                    bytes: usize::MAX as u64,
                })
            } else {
                local(P1Readiness::Pending)
            }
        }
        (Some(Preview1Descriptor::Socket(socket)), P1_EVENTTYPE_FD_WRITE) if socket.is_pair() => {
            let Some(writer) = socket.pair_writer() else {
                return Err(p1::errno::INVAL);
            };
            if writer.is_writable() {
                local(P1Readiness::Ready {
                    bytes: usize::MAX as u64,
                })
            } else {
                local(P1Readiness::Pending)
            }
        }
        // stdout/stderr routing lives on the store, not on the descriptor,
        // so it is not resolvable here; those descriptors report the
        // always-writable behaviour of a terminal and the write itself
        // applies whatever backpressure the route has.
        (Some(Preview1Descriptor::Stdout), P1_EVENTTYPE_FD_WRITE)
        | (Some(Preview1Descriptor::Stderr), P1_EVENTTYPE_FD_WRITE)
        | (Some(Preview1Descriptor::Event(_)), P1_EVENTTYPE_FD_WRITE)
        | (Some(Preview1Descriptor::NullDevice), P1_EVENTTYPE_FD_WRITE) => {
            local(P1Readiness::Ready {
                bytes: usize::MAX as u64,
            })
        }
        // A network socket's readiness is the network's answer for the
        // endpoint it owns. One with no endpoint yet can never make
        // progress; it is not an error to poll it, it simply never becomes
        // ready.
        (
            Some(Preview1Descriptor::Socket(socket)),
            P1_EVENTTYPE_FD_READ | P1_EVENTTYPE_FD_WRITE,
        ) if !socket.is_pair() => match socket.handle() {
            Some(handle) => Ok(P1Probe::Network(handle)),
            None => local(P1Readiness::Pending),
        },
        (Some(_), _) => Err(p1::errno::INVAL),
        (None, _) => Err(p1::errno::BADF),
    }
}
