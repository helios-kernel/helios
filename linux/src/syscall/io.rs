use super::signal::{ThreadSignalSlot, WaitOutcome};
use super::*;
use crate::signal_frame::SigInfo;
use alloc::vec::Vec;
use core::future::{Future, poll_fn};
use core::task::{Context, Poll};
use helios_sync::{
    ByteReadWait, ByteReader, ByteWriteWait, ByteWriter, NotifyWaiter, TryRead, TryWrite,
    byte_channel,
};
use helios_unix::{
    DescriptorTableError, Epoll, EventError, EventFd, Interest, InterestError, Signal, SignalSet,
};

/// Monotonic time and async deadline waits supplied by the execution owner.
pub trait Clock {
    fn now_nanos(&self) -> u64;
    fn sleep_until(&self, deadline: u64) -> impl Future<Output = ()> + Send;
}
// Linux UAPI: O_NONBLOCK, O_CLOEXEC and eventfd's semaphore bit.
const NONBLOCK: u16 = 0x800;
const CLOEXEC: u64 = 0x80000;
const EAGAIN: u64 = 11;
const EPIPE: u64 = 32;
const EEXIST: u64 = 17;
const ENOENT: u64 = 2;
const EPOLLIN: u32 = 1;
const EPOLLOUT: u32 = 4;
const EPOLLERR: u32 = 8;
const EPOLLHUP: u32 = 16;
const EPOLLONESHOT: u32 = 1 << 30; // Linux eventpoll.h

pub(super) fn descriptor_errno(error: DescriptorTableError) -> u64 {
    errno(match error {
        DescriptorTableError::BadDescriptor(_) => EBADF,
        DescriptorTableError::TooManyDescriptors { .. } => 24, // EMFILE
        DescriptorTableError::IndexOverflow => 75,             // EOVERFLOW
        DescriptorTableError::RightsWidening => EPERM,
    })
}
fn insert<R: Resources>(table: &mut Descriptors<R>, descriptor: Descriptor<R>, flags: u64) -> u64 {
    let entry = Entry::<R>::new(descriptor, flags & CLOEXEC != 0);
    entry.set_fdflags(flags as u16 & NONBLOCK);
    table
        .insert_entry(entry)
        .map_or_else(descriptor_errno, u64::from)
}
pub(super) fn event<R: Resources>(
    table: &mut Descriptors<R>,
    args: [u64; 6],
    has_flags: bool,
) -> u64 {
    let flags = if has_flags { args[1] as u32 as u64 } else { 0 };
    if flags & !(CLOEXEC | u64::from(NONBLOCK) | 1) != 0 {
        return errno(EINVAL);
    }
    insert::<R>(
        table,
        FileDescriptor::Event(EventFd::new(args[0] as u32 as u64, flags & 1 != 0)),
        flags,
    )
}
pub(super) fn pipe<R: Resources, M: UserMemory>(
    table: &mut Descriptors<R>,
    args: [u64; 6],
    memory: &mut M,
    has_flags: bool,
) -> u64 {
    let flags = if has_flags { args[1] as u32 as u64 } else { 0 };
    if flags & !(CLOEXEC | u64::from(NONBLOCK)) != 0 {
        return errno(EINVAL);
    }
    let (writer, reader) = byte_channel();
    let read = insert::<R>(table, FileDescriptor::PipeRead { reader }, flags);
    if read > i32::MAX as u64 {
        return read;
    }
    let write = insert::<R>(table, FileDescriptor::PipeWrite { writer }, flags);
    if write > i32::MAX as u64 {
        let _ = table.close(read as i32);
        return write;
    }
    let mut fds = [0; 8];
    fds[..4].copy_from_slice(&(read as u32).to_le_bytes());
    fds[4..].copy_from_slice(&(write as u32).to_le_bytes());
    if memory.write(args[0], &fds).is_err() {
        let _ = table.close(read as i32);
        let _ = table.close(write as i32);
        return errno(EFAULT);
    }
    0
}
pub(super) fn duplicate<R: Resources>(
    table: &mut Descriptors<R>,
    operation: Operation,
    arguments: [u64; 6],
) -> u64 {
    let [fd, arg, flags, ..] = arguments;
    let Some(mut entry) = table.get_entry(fd as u32 as i32).cloned() else {
        return errno(EBADF);
    };
    if operation == Operation::Fcntl {
        return match arg as u32 {
            1 => u64::from(entry.close_on_exec), // F_GETFD
            2 => {
                table.get_entry_mut(fd as u32 as i32).unwrap().close_on_exec = flags & 1 != 0;
                0
            }
            3 => {
                // F_GETFL: access mode belongs to the open resource.
                let (mode, extra) = match &entry.descriptor {
                    FileDescriptor::PipeRead { .. } | FileDescriptor::Stdin { .. } => (0, 0),
                    FileDescriptor::PipeWrite { .. }
                    | FileDescriptor::Stdout
                    | FileDescriptor::Stderr => (1, 0),
                    FileDescriptor::Socket(sock) => (
                        2,
                        if sock.is_nonblocking() {
                            u64::from(NONBLOCK)
                        } else {
                            0
                        },
                    ),
                    _ => (2, 0),
                };
                mode | u64::from(entry.fdflags()) | extra
            }
            4 => {
                let nb = flags as u16 & NONBLOCK;
                let slot = table.get_entry(fd as u32 as i32).unwrap();
                slot.set_fdflags(nb);
                if let FileDescriptor::Socket(sock) = &slot.descriptor {
                    sock.set_nonblocking(nb != 0);
                }
                0
            }
            _ => errno(EINVAL),
        };
    }
    entry.close_on_exec = false;
    match operation {
        Operation::Dup => table
            .insert_entry(entry)
            .map_or_else(descriptor_errno, u64::from),
        Operation::Dup2 | Operation::Dup3 => {
            if operation == Operation::Dup3 {
                if flags & !CLOEXEC != 0 || fd as u32 == arg as u32 {
                    return errno(EINVAL);
                }
                entry.close_on_exec = flags & CLOEXEC != 0;
            } else if fd as u32 == arg as u32 {
                return fd as u32 as u64;
            }
            table
                .insert_entry_at(arg as u32 as i32, entry)
                .map_or_else(descriptor_errno, u64::from)
        }
        _ => unreachable!("only duplication syscalls reach this dispatcher"),
    }
}
pub(super) async fn write_resource<R: Resources, M: UserMemory>(
    signals: &ThreadSignalSlot,
    entry: &Entry<R>,
    args: [u64; 6],
    memory: &M,
) -> SyscallOutcome {
    match &entry.descriptor {
        FileDescriptor::Event(event) => {
            if args[2] < 8 {
                return SyscallOutcome::Return(errno(EINVAL));
            }
            let mut bytes = [0; 8];
            if memory.read(args[1], &mut bytes).is_err() {
                return SyscallOutcome::Return(errno(EFAULT));
            }
            let value = u64::from_le_bytes(bytes);
            loop {
                let mut wait = event.wait_state();
                match event.write(value) {
                    Ok(()) => return SyscallOutcome::Return(8),
                    Err(EventError::InvalidIncrement) => {
                        return SyscallOutcome::Return(errno(EINVAL));
                    }
                    Err(EventError::WouldBlock) if entry.fdflags() & NONBLOCK != 0 => {
                        return SyscallOutcome::Return(errno(EAGAIN));
                    }
                    Err(EventError::WouldBlock) => {
                        if matches!(
                            signals
                                .interruptible(poll_fn(|cx| event.poll_changed(cx, &mut wait)))
                                .await,
                            WaitOutcome::Interrupted
                        ) {
                            return SyscallOutcome::RestartSys;
                        }
                    }
                }
            }
        }
        FileDescriptor::PipeWrite { writer } => {
            let mut total = 0;
            let mut bytes = [0; 4096];
            while total < args[2].min(MAX_RW_COUNT) {
                let size = (args[2].min(MAX_RW_COUNT) - total).min(bytes.len() as u64) as usize;
                if memory
                    .read(args[1].wrapping_add(total), &mut bytes[..size])
                    .is_err()
                {
                    return SyscallOutcome::Return(if total == 0 { errno(EFAULT) } else { total });
                }
                let chunk = Bytes::copy_from_slice(&bytes[..size]);
                let result = if entry.fdflags() & NONBLOCK != 0 {
                    match writer.try_write(chunk) {
                        TryWrite::Written => Ok(()),
                        TryWrite::Closed => Err(Some(EPIPE)),
                        TryWrite::Full(_) => Err(Some(EAGAIN)),
                    }
                } else {
                    match signals.interruptible(writer.write(chunk)).await {
                        WaitOutcome::Ready(Ok(())) => Ok(()),
                        WaitOutcome::Ready(Err(_)) => Err(Some(EPIPE)),
                        WaitOutcome::Interrupted => Err(None),
                    }
                };
                match result {
                    Ok(()) => total += size as u64,
                    Err(Some(EPIPE)) => {
                        // Linux `fs/pipe.c` `pipe_write`: broken pipe raises
                        // `SIGPIPE` on the writing thread and returns `-EPIPE`.
                        signals
                            .process()
                            .raise_thread(signals, SigInfo::from_kernel(Signal::SIGPIPE));
                        return SyscallOutcome::Return(if total == 0 {
                            errno(EPIPE)
                        } else {
                            total
                        });
                    }
                    Err(Some(error)) => {
                        return SyscallOutcome::Return(if total == 0 {
                            errno(error)
                        } else {
                            total
                        });
                    }
                    Err(None) => {
                        return if total == 0 {
                            SyscallOutcome::RestartSys
                        } else {
                            SyscallOutcome::Return(total)
                        };
                    }
                }
            }
            SyscallOutcome::Return(total)
        }
        FileDescriptor::NullDevice => SyscallOutcome::Return(args[2].min(MAX_RW_COUNT)),
        _ => SyscallOutcome::Return(errno(EBADF)),
    }
}
pub(super) async fn read_resource<R: Resources, M: UserMemory>(
    signals: &ThreadSignalSlot,
    entry: &Entry<R>,
    args: [u64; 6],
    memory: &mut M,
) -> SyscallOutcome {
    let nonblock = entry.fdflags() & NONBLOCK != 0;
    match &entry.descriptor {
        FileDescriptor::Event(event) => {
            if args[2] < 8 {
                return SyscallOutcome::Return(errno(EINVAL));
            }
            // Validate the destination before consuming the counter.
            if memory.check_writable(args[1], 8).is_err() {
                return SyscallOutcome::Return(errno(EFAULT));
            }
            let value = if nonblock {
                match event.try_read() {
                    Ok(value) => value,
                    Err(_) => return SyscallOutcome::Return(errno(EAGAIN)),
                }
            } else {
                match signals.interruptible(event.read()).await {
                    WaitOutcome::Ready(value) => value,
                    WaitOutcome::Interrupted => return SyscallOutcome::RestartSys,
                }
            };
            if memory.write(args[1], &value.to_le_bytes()).is_err() {
                return SyscallOutcome::Return(errno(EFAULT));
            }
            SyscallOutcome::Return(8)
        }
        FileDescriptor::PipeRead { reader } => {
            let limit = args[2].min(MAX_RW_COUNT) as usize;
            if memory.check_writable(args[1], limit).is_err() {
                return SyscallOutcome::Return(errno(EFAULT));
            }
            let next = if nonblock {
                match reader.try_read_limit(limit) {
                    TryRead::Ready(bytes) => Some(bytes),
                    TryRead::Eof => None,
                    TryRead::Pending => return SyscallOutcome::Return(errno(EAGAIN)),
                }
            } else {
                match signals.interruptible(reader.read_limit(limit)).await {
                    WaitOutcome::Ready(bytes) => bytes,
                    WaitOutcome::Interrupted => return SyscallOutcome::RestartSys,
                }
            };
            let Some(bytes) = next else {
                return SyscallOutcome::Return(0);
            };
            if memory.write(args[1], &bytes).is_err() {
                return SyscallOutcome::Return(errno(EFAULT));
            }
            SyscallOutcome::Return(bytes.len() as u64)
        }
        FileDescriptor::NullDevice => SyscallOutcome::Return(0),
        _ => SyscallOutcome::Return(errno(EBADF)),
    }
}
pub(super) fn epoll_create<R: Resources>(
    table: &mut Descriptors<R>,
    args: [u64; 6],
    has_flags: bool,
) -> u64 {
    let flags = if has_flags {
        args[0] as u32 as u64
    } else {
        if (args[0] as i32) <= 0 {
            return errno(EINVAL);
        }
        0
    };
    if flags & !CLOEXEC != 0 {
        return errno(EINVAL);
    }
    insert::<R>(table, FileDescriptor::Epoll(Epoll::new()), flags)
}
pub(super) fn epoll_ctl<R: Resources, M: UserMemory>(
    abi: Abi,
    table: &mut Descriptors<R>,
    args: [u64; 6],
    memory: &M,
) -> u64 {
    let epfd = args[0] as u32 as i32;
    let fd = args[2] as u32 as i32;
    let Some(entry) = table.get_entry(epfd) else {
        return errno(EBADF);
    };
    let FileDescriptor::Epoll(epoll) = &entry.descriptor else {
        return errno(EINVAL);
    };
    let Some(target) = table.get_entry(fd) else {
        return errno(EBADF);
    };
    if fd == epfd {
        return errno(EINVAL);
    }
    if matches!(
        target.descriptor,
        FileDescriptor::Stdin { .. }
            | FileDescriptor::Stdout
            | FileDescriptor::Stderr
            | FileDescriptor::NullDevice
    ) {
        return errno(EPERM);
    }
    let op = args[1] as u32;
    if let FileDescriptor::Epoll(target) = &target.descriptor {
        if target.same_object(epoll) {
            return errno(EINVAL);
        }
        if op == 1 && !valid_nesting::<R>(target, epoll, table, 1) {
            return errno(40);
        } // ELOOP
    }
    let result = if op == 2 {
        epoll.remove(fd)
    } else {
        if op != 1 && op != 3 {
            return errno(EINVAL);
        }
        let data = abi.epoll_data_offset();
        let mut event = [0; 16];
        let bytes = &mut event[..data + 8];
        if memory.read(args[3], bytes).is_err() {
            return errno(EFAULT);
        }
        let events = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        if events & !(EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLONESHOT) != 0 {
            return errno(EINVAL);
        }
        let interest = Interest {
            fd,
            events: events & !EPOLLONESHOT,
            one_shot: events & EPOLLONESHOT != 0,
            data: R::Data::from_linux(u64::from_le_bytes(bytes[data..].try_into().unwrap())),
        };
        if op == 1 {
            match epoll.add(interest) {
                Ok(()) => {
                    let valid = table.entries.iter().flatten().all(|entry| {
                        let FileDescriptor::Epoll(root) = &entry.descriptor else {
                            return true;
                        };
                        root.registrations().iter().all(|interest| {
                            match table.get_entry(interest.fd).map(|entry| &entry.descriptor) {
                                Some(FileDescriptor::Epoll(child)) => {
                                    valid_nesting::<R>(child, root, table, 1)
                                }
                                _ => true,
                            }
                        })
                    });
                    if !valid {
                        epoll.remove(fd).expect("new registration exists");
                        return errno(40); // ELOOP
                    }
                    Ok(())
                }
                error => error,
            }
        } else {
            epoll.modify(interest)
        }
    };
    match result {
        Ok(()) => 0,
        Err(InterestError::Exists) => errno(EEXIST),
        Err(InterestError::NotFound) => errno(ENOENT),
    }
}
fn ready_mask<R: Resources>(entry: &Entry<R>, table: &Descriptors<R>) -> u32 {
    match &entry.descriptor {
        FileDescriptor::Event(event) => {
            (if event.is_readable() { EPOLLIN } else { 0 })
                | (if event.is_writable() { EPOLLOUT } else { 0 })
        }
        FileDescriptor::PipeRead { reader } => {
            (if reader.has_buffered_data() {
                EPOLLIN
            } else {
                0
            }) | (if reader.is_writer_closed() {
                EPOLLHUP
            } else {
                0
            })
        }
        FileDescriptor::PipeWrite { writer } => {
            if writer.is_reader_closed() {
                EPOLLERR
            } else if writer.is_writable() {
                EPOLLOUT
            } else {
                0
            }
        }
        FileDescriptor::Epoll(epoll) => {
            if epoll.interests().iter().any(|interest| {
                table.get_entry(interest.fd).is_some_and(|entry| {
                    ready_mask::<R>(entry, table) & (interest.events | EPOLLERR | EPOLLHUP) != 0
                })
            }) {
                EPOLLIN
            } else {
                0
            }
        }
        FileDescriptor::Stdout | FileDescriptor::Stderr => EPOLLOUT,
        _ => 0,
    }
}
// Linux limits nested epoll traversal to five levels (eventpoll.c EP_MAX_NESTS).
fn valid_nesting<R: Resources>(
    target: &Epoll<R::Data>,
    parent: &Epoll<R::Data>,
    table: &Descriptors<R>,
    depth: usize,
) -> bool {
    depth <= 4
        && !target.same_object(parent)
        && target.registrations().iter().all(|interest| {
            match table.get_entry(interest.fd).map(|entry| &entry.descriptor) {
                Some(FileDescriptor::Epoll(child)) => {
                    valid_nesting::<R>(child, parent, table, depth + 1)
                }
                _ => true,
            }
        })
}
fn arm_waits<R: Resources>(
    epoll: &Epoll<R::Data>,
    table: &Descriptors<R>,
    waits: &mut Vec<Wait>,
    repoll: &mut bool,
) {
    for interest in epoll.interests() {
        if let Some(entry) = table.get_entry(interest.fd) {
            match &entry.descriptor {
                FileDescriptor::Epoll(child) if interest.events & EPOLLIN != 0 => {
                    arm_waits::<R>(child, table, waits, repoll)
                }
                FileDescriptor::Socket(sock) => {
                    if let Some((reader, carry_len)) = sock.pair_read_probe() {
                        if interest.events & EPOLLIN != 0 && carry_len == 0 {
                            waits.push(Wait::Read(reader.clone(), reader.wait_state()));
                        }
                        if interest.events & EPOLLOUT != 0
                            && let Some(writer) = sock.pair_writer()
                            && !writer.is_writable()
                        {
                            waits.push(Wait::Write(writer.clone(), writer.wait_state()));
                        }
                    } else if sock.handle().is_some() {
                        *repoll = true;
                    }
                }
                _ => {
                    if let Some(wait) = Wait::arm::<R>(entry, interest.events) {
                        waits.push(wait);
                    }
                }
            }
        }
    }
}
enum Wait {
    Event(EventFd, NotifyWaiter),
    Read(ByteReader, ByteReadWait),
    Write(ByteWriter, ByteWriteWait),
}
impl Wait {
    fn arm<R: Resources>(entry: &Entry<R>, events: u32) -> Option<Self> {
        match &entry.descriptor {
            FileDescriptor::Event(event) => Some(Self::Event(event.clone(), event.wait_state())),
            FileDescriptor::PipeRead { reader, .. } if events & EPOLLIN != 0 => {
                Some(Self::Read(reader.clone(), reader.wait_state()))
            }
            FileDescriptor::PipeWrite { writer } if events & EPOLLOUT != 0 => {
                Some(Self::Write(writer.clone(), writer.wait_state()))
            }
            _ => None,
        }
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        match self {
            Self::Event(event, wait) => event.poll_changed(cx, wait),
            Self::Read(reader, wait) => reader.poll_readable(cx, wait),
            Self::Write(writer, wait) => writer.poll_writable(cx, wait),
        }
    }
}
pub(super) async fn epoll_wait<
    R: Resources,
    M: UserMemory,
    C: Clock + super::socket::Network<R::Network>,
>(
    abi: Abi,
    signals: &ThreadSignalSlot,
    table: &spin::Mutex<Descriptors<R>>,
    args: [u64; 6],
    memory: &mut M,
    clock: &C,
    has_mask: bool,
) -> SyscallOutcome {
    const NETWORK_REPOLL_NANOS: u64 = 1_000_000;
    let epoll = {
        let table = table.lock();
        let Some(entry) = table.get_entry(args[0] as u32 as i32) else {
            return SyscallOutcome::Return(errno(EBADF));
        };
        let FileDescriptor::Epoll(epoll) = &entry.descriptor else {
            return SyscallOutcome::Return(errno(EINVAL));
        };
        epoll.clone()
    };
    let data = abi.epoll_data_offset();
    let size = data + 8;
    let maxevents = args[2] as i32;
    if maxevents <= 0 || maxevents as u64 > i32::MAX as u64 / size as u64 {
        return SyscallOutcome::Return(errno(EINVAL));
    }
    let installed_mask = if has_mask && args[4] != 0 {
        if args[5] != 8 {
            return SyscallOutcome::Return(errno(EINVAL));
        }
        let mut mask_bytes = [0u8; 8];
        if memory.read(args[4], &mut mask_bytes).is_err() {
            return SyscallOutcome::Return(errno(EFAULT));
        }
        signals.push_temp_mask(SignalSet::from_bits(u64::from_le_bytes(mask_bytes)));
        true
    } else {
        false
    };
    let timeout = args[3] as i32;
    let deadline =
        (timeout >= 0).then(|| clock.now_nanos().saturating_add(timeout as u64 * 1_000_000));
    loop {
        let mut waits = Vec::new();
        let mut repoll = false;
        // Snapshot interests and their non-socket readiness synchronously under
        // the descriptor table lock; socket readiness probes are async and run
        // after the spin lock is dropped.
        let snapshot: Vec<_> = {
            let guard = table.lock();
            let interests = epoll.interests();
            arm_waits::<R>(&epoll, &guard, &mut waits, &mut repoll);
            interests
                .into_iter()
                .filter_map(|interest| {
                    let target = guard.get_entry(interest.fd)?;
                    if matches!(target.descriptor, FileDescriptor::Socket(_)) {
                        Some((interest, Some(target.clone()), 0))
                    } else {
                        let events = ready_mask::<R>(target, &guard)
                            & (interest.events | EPOLLERR | EPOLLHUP);
                        Some((interest, None, events))
                    }
                })
                .collect()
        };
        let mut count = 0;
        for (interest, socket_entry, sync_events) in snapshot {
            let events = match socket_entry {
                Some(entry) => match &entry.descriptor {
                    FileDescriptor::Socket(sock) => {
                        super::socket::socket_epoll_ready(sock, interest.events, clock).await
                    }
                    _ => sync_events,
                },
                None => sync_events,
            };
            if events == 0 {
                continue;
            }
            let mut event = [0; 16];
            let bytes = &mut event[..size];
            bytes[..4].copy_from_slice(&events.to_le_bytes());
            bytes[data..].copy_from_slice(&interest.data.to_linux().to_le_bytes());
            if memory
                .write(args[1].wrapping_add(count * size as u64), bytes)
                .is_err()
            {
                if installed_mask {
                    signals.restore_temp_mask();
                }
                return SyscallOutcome::Return(if count == 0 { errno(EFAULT) } else { count });
            }
            epoll.delivered(interest.fd);
            count += 1;
            if count == maxevents as u64 {
                break;
            }
        }
        if count != 0 {
            if installed_mask {
                signals.restore_temp_mask();
            }
            return SyscallOutcome::Return(count);
        }
        let now = clock.now_nanos();
        if deadline.is_some_and(|end| now >= end) {
            if installed_mask {
                signals.restore_temp_mask();
            }
            return SyscallOutcome::Return(0);
        }
        let wake_at = match (deadline, repoll) {
            (Some(end), true) => Some(end.min(now.saturating_add(NETWORK_REPOLL_NANOS))),
            (Some(end), false) => Some(end),
            (None, true) => Some(now.saturating_add(NETWORK_REPOLL_NANOS)),
            (None, false) => None,
        };
        let timer = async {
            match wake_at {
                Some(end) => clock.sleep_until(end).await,
                None => core::future::pending().await,
            }
        };
        let mut timer = core::pin::pin!(timer);
        let mut sig = core::pin::pin!(signals.wait_deliverable());
        let interrupted = poll_fn(|cx| {
            let mut ready = timer.as_mut().poll(cx).is_ready();
            for wait in &mut waits {
                ready |= wait.poll(cx).is_ready();
            }
            if ready {
                return Poll::Ready(false);
            }
            if sig.as_mut().poll(cx).is_ready() {
                return Poll::Ready(true);
            }
            Poll::Pending
        })
        .await;
        if interrupted {
            // Leave `saved_mask` active (`TIF_RESTORE_SIGMASK`) so signal
            // delivery writes the original mask into `uc_sigmask`.
            return SyscallOutcome::RestartNoHand;
        }
    }
}

/// `ppoll(fds, nfds, tmo_p, sigmask, sigsetsize)` (`fs/select.c`
/// `SYSCALL_DEFINE5(ppoll)`).
///
/// musl implements `pause(2)` on AArch64 as `ppoll(NULL, 0, NULL, NULL, 0)`.
pub(super) async fn ppoll<R: Resources, M: UserMemory, C: Clock>(
    signals: &ThreadSignalSlot,
    table: &spin::Mutex<Descriptors<R>>,
    args: [u64; 6],
    memory: &mut M,
    clock: &C,
) -> SyscallOutcome {
    const POLLNVAL: u32 = 0x20;
    const POLLFD_BYTES: usize = 8;
    const NANOS_PER_SEC: u64 = 1_000_000_000;

    let fds_ptr = args[0];
    let nfds = args[1];
    let tmo_ptr = args[2];
    let sigmask_ptr = args[3];
    let sigsetsize = args[4];

    if nfds > 1024 * 1024 {
        return SyscallOutcome::Return(errno(EINVAL));
    }
    let nfds = nfds as usize;

    let deadline = if tmo_ptr != 0 {
        let mut ts = [0u8; 16];
        if memory.read(tmo_ptr, &mut ts).is_err() {
            return SyscallOutcome::Return(errno(EFAULT));
        }
        let sec = i64::from_le_bytes(ts[..8].try_into().unwrap());
        let nsec = i64::from_le_bytes(ts[8..].try_into().unwrap());
        if sec < 0 || !(0..NANOS_PER_SEC as i64).contains(&nsec) {
            return SyscallOutcome::Return(errno(EINVAL));
        }
        let delta = (sec as u64)
            .saturating_mul(NANOS_PER_SEC)
            .saturating_add(nsec as u64);
        Some(clock.now_nanos().saturating_add(delta))
    } else {
        None
    };

    let temp_mask = if sigmask_ptr != 0 {
        if sigsetsize != 8 {
            return SyscallOutcome::Return(errno(EINVAL));
        }
        let mut mask_bytes = [0u8; 8];
        if memory.read(sigmask_ptr, &mut mask_bytes).is_err() {
            return SyscallOutcome::Return(errno(EFAULT));
        }
        Some(SignalSet::from_bits(u64::from_le_bytes(mask_bytes)))
    } else {
        None
    };

    let mut pollfds = Vec::with_capacity(nfds);
    for i in 0..nfds {
        let mut raw = [0u8; POLLFD_BYTES];
        if memory
            .read(fds_ptr.wrapping_add((i * POLLFD_BYTES) as u64), &mut raw)
            .is_err()
        {
            return SyscallOutcome::Return(errno(EFAULT));
        }
        let fd = i32::from_le_bytes(raw[0..4].try_into().unwrap());
        let events = u16::from_le_bytes(raw[4..6].try_into().unwrap());
        pollfds.push((fd, events, 0u16));
    }

    let installed_mask = if let Some(mask) = temp_mask {
        signals.push_temp_mask(mask);
        true
    } else {
        false
    };

    loop {
        let mut waits = Vec::new();
        let mut count = 0u64;
        {
            let table = table.lock();
            for (fd, events, revents) in &mut pollfds {
                if *fd < 0 {
                    *revents = 0;
                    continue;
                }
                let Some(entry) = table.get_entry(*fd) else {
                    *revents = POLLNVAL as u16;
                    count += 1;
                    continue;
                };
                let mask = u32::from(*events) & (EPOLLIN | EPOLLOUT);
                let ready = ready_mask::<R>(entry, &table) & (mask | EPOLLERR | EPOLLHUP);
                *revents = ready as u16;
                if ready != 0 {
                    count += 1;
                } else if let Some(wait) = Wait::arm::<R>(entry, mask) {
                    waits.push(wait);
                }
            }
        }
        if count != 0 || deadline.is_some_and(|end| clock.now_nanos() >= end) {
            if installed_mask {
                signals.restore_temp_mask();
            }
            for (i, (_, _, revents)) in pollfds.iter().enumerate() {
                if memory
                    .write(
                        fds_ptr.wrapping_add((i * POLLFD_BYTES + 6) as u64),
                        &revents.to_le_bytes(),
                    )
                    .is_err()
                {
                    return SyscallOutcome::Return(errno(EFAULT));
                }
            }
            return SyscallOutcome::Return(count);
        }
        let timer = async {
            match deadline {
                Some(end) => clock.sleep_until(end).await,
                None => core::future::pending().await,
            }
        };
        let mut timer = core::pin::pin!(timer);
        let mut sig = core::pin::pin!(signals.wait_deliverable());
        let interrupted = poll_fn(|cx| {
            let mut ready = timer.as_mut().poll(cx).is_ready();
            for wait in &mut waits {
                ready |= wait.poll(cx).is_ready();
            }
            if ready {
                return Poll::Ready(false);
            }
            if sig.as_mut().poll(cx).is_ready() {
                return Poll::Ready(true);
            }
            Poll::Pending
        })
        .await;
        if interrupted {
            return SyscallOutcome::RestartNoHand;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::Waker;

    struct Memory([u8; 64]);
    impl UserMemory for Memory {
        fn check_writable(&self, address: u64, length: usize) -> Result<(), MemoryFault> {
            let end = address.checked_add(length as u64).ok_or(MemoryFault)?;
            if end <= self.0.len() as u64 {
                Ok(())
            } else {
                Err(MemoryFault)
            }
        }
        fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault> {
            self.check_writable(address, output.len())?;
            output.copy_from_slice(&self.0[address as usize..address as usize + output.len()]);
            Ok(())
        }
        fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryFault> {
            self.check_writable(address, bytes.len())?;
            self.0[address as usize..address as usize + bytes.len()].copy_from_slice(bytes);
            Ok(())
        }
        fn atomic_load_u32(&self, address: u64) -> Result<u32, MemoryFault> {
            let mut bytes = [0; 4];
            self.read(address, &mut bytes)?;
            Ok(u32::from_le_bytes(bytes))
        }
        fn atomic_store_u32(&mut self, address: u64, value: u32) -> Result<(), MemoryFault> {
            self.write(address, &value.to_le_bytes())
        }
        fn atomic_compare_exchange_u32(
            &mut self,
            address: u64,
            expected: u32,
            desired: u32,
        ) -> Result<Result<u32, u32>, MemoryFault> {
            let current = self.atomic_load_u32(address)?;
            if current == expected {
                self.atomic_store_u32(address, desired)?;
                Ok(Ok(current))
            } else {
                Ok(Err(current))
            }
        }
    }
    struct Clock;
    impl super::Clock for Clock {
        fn now_nanos(&self) -> u64 {
            0
        }
        async fn sleep_until(&self, _: u64) {
            core::future::pending().await
        }
    }
    impl super::super::socket::Network<helios_unix::NoNetwork> for Clock {
        fn to_ip(&self, address: core::convert::Infallible) -> super::super::socket::IpAddr {
            match address {}
        }
        fn encode_ip(&self, _: super::super::socket::IpAddr) -> core::convert::Infallible {
            unreachable!()
        }
    }
    struct Wakes(AtomicUsize);
    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    #[test]
    fn nested_epoll_suspends_and_event_write_wakes_its_waiter() {
        let event = EventFd::new(0, false);
        let child = Epoll::new();
        let parent = Epoll::new();
        child
            .add(Interest {
                fd: 0,
                events: EPOLLIN,
                data: 123,
                one_shot: false,
            })
            .unwrap();
        parent
            .add(Interest {
                fd: 1,
                events: EPOLLIN,
                data: 456,
                one_shot: false,
            })
            .unwrap();
        let table = spin::Mutex::new(DescriptorSlots::<Entry<NoBacking>>::from_entries(
            alloc::vec![
                Some(Entry::<NoBacking>::new(
                    FileDescriptor::Event(event.clone()),
                    false
                )),
                Some(Entry::<NoBacking>::new(FileDescriptor::Epoll(child), false)),
                Some(Entry::<NoBacking>::new(
                    FileDescriptor::Epoll(parent),
                    false
                )),
            ],
        ));
        let mut memory = Memory([0; 64]);
        let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
        let waker = Waker::from(wakes.clone());
        let mut context = Context::from_waker(&waker);
        let process_signals = super::signal::ProcessSignals::new(NonZeroU32::new(1).unwrap());
        let thread_signals =
            process_signals.register_thread(NonZeroU32::new(1).unwrap(), SignalSet::EMPTY);
        {
            let mut future = core::pin::pin!(epoll_wait::<NoBacking, _, _>(
                Abi::X86_64,
                &thread_signals,
                &table,
                [2, 0, 1, u64::MAX, 0, 0],
                &mut memory,
                &Clock,
                false
            ));
            assert!(future.as_mut().poll(&mut context).is_pending());
            event.write(1).unwrap();
            assert!(wakes.0.load(Ordering::Relaxed) > 0);
            assert_eq!(
                future.as_mut().poll(&mut context),
                Poll::Ready(SyscallOutcome::Return(1))
            );
        }
        assert_eq!(
            u32::from_le_bytes(memory.0[..4].try_into().unwrap()),
            EPOLLIN
        );
        assert_eq!(u64::from_le_bytes(memory.0[4..12].try_into().unwrap()), 456);
        assert_eq!(event.try_read(), Ok(1));
    }
}
