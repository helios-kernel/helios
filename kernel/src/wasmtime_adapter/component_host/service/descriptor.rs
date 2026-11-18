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

pub(super) struct WasixChildProcess {
    pub(super) pid: u32,
    pub(super) signal_state: WasixSignalState,
    pub(super) exit:
        Option<futures::channel::oneshot::Receiver<Result<ChildExit, ProgramExecError>>>,
    pub(super) completed: Option<helios_unix::ChildTermination>,
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
pub(super) use helios_unix::{
    OwnedTcpListener, OwnedTcpStream, OwnedUdpSocket, SocketFamily, SocketFlag, SocketKind,
    SocketOptionError, SocketOptions, SocketSize, SocketTime,
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

/// Sleep until a watched descriptor wakes us, the re-probe cadence elapses,
/// or `remaining` runs out.
///
/// The caller re-probes after every step, so this only has to guarantee that
/// it yields control and comes back when something might have changed.
/// `remaining` of `None` means "no deadline": block until a descriptor makes
/// progress.
pub(super) async fn p1_wait_step<CpuImpl>(
    timer: &crate::Timer<CpuImpl>,
    wait: &mut P1WaitSet,
    remaining: Option<Duration>,
) where
    CpuImpl: Cpu + Clone,
{
    if wait.is_empty() && remaining.is_none() {
        // Nothing subscribed can ever become ready and no deadline will end
        // the call. Park rather than spin; the task is dropped with the
        // instance.
        core::future::pending::<()>().await;
        return;
    }

    // A descriptor without a wakeup source needs us back on a fixed cadence;
    // otherwise sleep the whole remaining budget in one go.
    let sleep = match (wait.repoll, remaining) {
        (true, Some(remaining)) => remaining.min(P1_READINESS_REPOLL_INTERVAL),
        (true, None) => P1_READINESS_REPOLL_INTERVAL,
        (false, Some(remaining)) => remaining,
        (false, None) => {
            // Every subscribed descriptor can wake us, so wait on them alone.
            let targets = &mut wait.notified;
            core::future::poll_fn(|cx| poll_epoll_wait_targets(targets, cx)).await;
            return;
        }
    };

    if sleep.is_zero() {
        return;
    }

    let mut timer = core::pin::pin!(timer.sleep_for(sleep));
    if wait.notified.is_empty() {
        timer.await;
        return;
    }

    // Race the wakeup sources against the sleep: whichever comes first ends
    // this step and sends the caller back to re-probe.
    let targets = &mut wait.notified;
    core::future::poll_fn(|cx| {
        if poll_epoll_wait_targets(targets, cx).is_ready() {
            return Poll::Ready(());
        }
        if timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(());
        }
        Poll::Pending
    })
    .await;
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
    match store.descriptors.get(fd) {
        Some(Preview1Descriptor::PipeRead { reader }) if event_type == P1_EVENTTYPE_FD_READ => {
            wait.notified.push(EpollWaitTarget::ByteReader {
                reader: reader.clone(),
                wait: reader.wait_state(),
            });
        }
        Some(Preview1Descriptor::Socket(UnixSocket::Pair { reader, carry, .. }))
            if carry.is_empty() && event_type == P1_EVENTTYPE_FD_READ =>
        {
            wait.notified.push(EpollWaitTarget::ByteReader {
                reader: reader.clone(),
                wait: reader.wait_state(),
            });
        }
        Some(Preview1Descriptor::PipeWrite { writer })
        | Some(Preview1Descriptor::Socket(UnixSocket::Pair { writer, .. }))
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
        Some(Preview1Descriptor::Socket(
            UnixSocket::Tcp(UnixTcpSocket::Connected { .. } | UnixTcpSocket::Listening { .. })
            | UnixSocket::Udp(UnixUdpSocket::Bound { .. }),
        )) => wait.repoll = true,
        _ => {}
    }
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
        && matches!(
            caller.data().descriptors.get(fd),
            Some(Preview1Descriptor::Stdin { .. })
        )
    {
        return Ok(caller.data_mut().probe_stdin(fd));
    }
    let probe = match p1_probe_descriptor(caller.data().descriptors.get(fd), event_type)? {
        P1Probe::Local(readiness) => return Ok(readiness),
        P1Probe::Network(probe) => probe,
    };
    let Some(service) = caller.data().runtime_state.network_service() else {
        return Err(p1::errno::NETDOWN);
    };
    let readiness = match probe {
        UnixSocketHandle::<Net>::TcpStream(stream) => service
            .tcp_readiness(stream)
            .await
            .map_err(p1_errno_from_tcp_error)?,
        UnixSocketHandle::<Net>::TcpListener(listener) => service
            .tcp_listener_readiness(listener)
            .await
            .map_err(p1_errno_from_tcp_error)?,
        UnixSocketHandle::<Net>::UdpSocket(socket) => service
            .udp_readiness(socket)
            .await
            .map_err(p1_errno_from_udp_error)?,
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

/// The signals one store answers to: those raised on its own thread and
/// those raised on its process. A thread-directed raise reaches only this
/// store's turn; a process-directed one goes to whichever store of the
/// process takes it first.
///
/// # Concurrency
///
/// As [`WasixSignalState`]: either mailbox is raised from any processor,
/// and one turn of this store at a time takes.
#[derive(Clone)]
pub(super) struct WasixStoreSignals {
    thread: WasixSignalState,
    process: WasixSignalState,
}

impl WasixStoreSignals {
    pub(super) fn new(thread: WasixSignalState, process: WasixSignalState) -> Self {
        Self { thread, process }
    }

    /// The stop this store owes its guest, if any: the end of its
    /// thread's process, which stays owed, then a pending signal, which
    /// is delivered once. The interrupt callback and the turn both read
    /// it, so a running guest and a suspended one meet the same stop.
    pub(super) fn owed_stop(&self) -> Option<wasmtime::Error> {
        if self.thread.thread_ended() {
            return Some(wasmtime::Error::new(WasixThreadEnded));
        }
        if let Some(signal) = self.thread.take_pending() {
            return Some(wasmtime::Error::new(WasixThreadSignalExit {
                signal: u8::try_from(signal).unwrap_or(u8::MAX),
            }));
        }
        self.process.take_pending().map(|signal| {
            wasmtime::Error::new(Preview1SignalExit {
                signal: u8::try_from(signal).unwrap_or(u8::MAX),
            })
        })
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
    pub(super) fn from_authority(authority: &ProcessAuthority) -> Self {
        let preopens = authority.directory_preopens();
        let mut entries = Vec::with_capacity(3 + preopens.len());
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
        let mut table = Self::from_entries(entries);
        for preopen in preopens {
            let descriptor = FsDescriptor {
                path: preopen.source_path().to_owned(),
                kind: FsNodeKind::Directory,
                flags: directory_authority_to_descriptor_flags(preopen.rights()),
                identity: None,
                mount: None,
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

    pub(super) fn from_entries(entries: Vec<Option<Preview1DescriptorEntry<Net>>>) -> Self {
        Self {
            slots: helios_unix::DescriptorSlots::from_entries(entries),
        }
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

    pub(super) fn clone_for_exec(&self) -> Self {
        let mut table = Self::from_entries(
            self.slots
                .entries
                .iter()
                .map(|entry| match entry {
                    Some(entry) if entry.close_on_exec => None,
                    _ => entry.clone(),
                })
                .collect(),
        );
        table.limit = self.slots.limit;
        table
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
            Some(Preview1Descriptor::PipeRead { reader }) => {
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
            Some(Preview1Descriptor::PipeWrite { writer }) => {
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
        | Preview1Descriptor::Stdout
        | Preview1Descriptor::Stderr
        | Preview1Descriptor::PipeWrite { .. }
        | Preview1Descriptor::NullDevice => UnbindableStdio::WrongDirection,
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
        Preview1Descriptor::PipeRead { .. } => P1_RIGHT_FD_READ | P1_RIGHT_POLL_FD_READWRITE,
        Preview1Descriptor::PipeWrite { .. } => P1_RIGHT_FD_WRITE | P1_RIGHT_POLL_FD_READWRITE,
        Preview1Descriptor::Event(_) => {
            P1_RIGHT_FD_READ | P1_RIGHT_FD_WRITE | P1_RIGHT_POLL_FD_READWRITE
        }
        Preview1Descriptor::NullDevice => {
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

pub(super) fn p1_descriptor_path<Net: ComponentHostNetwork>(
    descriptor: Option<&Preview1Descriptor<Net>>,
) -> Option<&str> {
    p1_fs_descriptor(descriptor).map(|descriptor| descriptor.path.as_str())
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
        (Some(Preview1Descriptor::PipeRead { reader }), P1_EVENTTYPE_FD_READ) => {
            local(if reader.is_readable() {
                P1Readiness::Ready { bytes: 1 }
            } else {
                P1Readiness::Pending
            })
        }
        (
            Some(Preview1Descriptor::Socket(UnixSocket::Pair { reader, carry, .. })),
            P1_EVENTTYPE_FD_READ,
        ) => {
            if !carry.is_empty() {
                return local(P1Readiness::Ready {
                    bytes: carry.len() as u64,
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
        (Some(Preview1Descriptor::PipeWrite { writer }), P1_EVENTTYPE_FD_WRITE)
        | (
            Some(Preview1Descriptor::Socket(UnixSocket::Pair { writer, .. })),
            P1_EVENTTYPE_FD_WRITE,
        ) => {
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
            Some(Preview1Descriptor::Socket(
                socket @ (UnixSocket::<Net>::Tcp(_) | UnixSocket::<Net>::Udp(_)),
            )),
            P1_EVENTTYPE_FD_READ | P1_EVENTTYPE_FD_WRITE,
        ) => match socket.handle() {
            Some(handle) => Ok(P1Probe::Network(handle)),
            None => local(P1Readiness::Pending),
        },
        (Some(_), _) => Err(p1::errno::INVAL),
        (None, _) => Err(p1::errno::BADF),
    }
}
