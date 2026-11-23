use super::signal::{ThreadSignalSlot, WaitOutcome};
use super::*;
use crate::signal_frame::SigInfo;
use alloc::vec::Vec;
use core::future::{Future, poll_fn};
use helios_sync::{TryRead, TryWrite, byte_channel};
use helios_unix::{
    DescriptorTableError, Epoll, EventError, EventFd, FDFLAG_NONBLOCK, FDFLAG_PATH, Interest,
    InterestError, Signal, SignalSet,
};

/// Monotonic time and async deadline waits supplied by the execution owner.
pub trait Clock {
    fn now_nanos(&self) -> u64;
    fn sleep_until(&self, deadline: u64) -> impl Future<Output = ()> + Send;
}
// Linux UAPI: O_NONBLOCK, O_CLOEXEC and eventfd's semaphore bit.
const O_NONBLOCK_LINUX: u64 = 0x800;
const CLOEXEC: u64 = 0x80000;
const EAGAIN: u64 = 11;
const EPIPE: u64 = 32;
const EEXIST: u64 = 17;
const ENOENT: u64 = 2;
const EPOLLIN: u32 = poll::POLLIN;
const EPOLLOUT: u32 = poll::POLLOUT;
const EPOLLERR: u32 = poll::POLLERR;
const EPOLLHUP: u32 = poll::POLLHUP;
const EPOLLRDNORM: u32 = poll::POLLRDNORM;
const EPOLLWRNORM: u32 = poll::POLLWRNORM;
const EPOLLRDHUP: u32 = 0x2000;
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
    if flags & O_NONBLOCK_LINUX != 0 {
        entry.set_fdflags(FDFLAG_NONBLOCK);
    }
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
    if flags & !(CLOEXEC | O_NONBLOCK_LINUX | 1) != 0 {
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
    uid: u32,
    gid: u32,
) -> u64 {
    let flags = if has_flags { args[1] as u32 as u64 } else { 0 };
    if flags & !(CLOEXEC | O_NONBLOCK_LINUX) != 0 {
        return errno(EINVAL);
    }
    let (writer, reader) = byte_channel();
    let inode = helios_unix::PipeInode::new(uid, gid);
    let read = insert::<R>(
        table,
        FileDescriptor::PipeRead {
            reader,
            inode: inode.clone(),
        },
        flags,
    );
    if read > i32::MAX as u64 {
        return read;
    }
    let write = insert::<R>(table, FileDescriptor::PipeWrite { writer, inode }, flags);
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
pub(super) fn duplicate<R: Resources, F: fs::Filesystem<R>>(
    abi: Abi,
    table: &mut Descriptors<R>,
    operation: Operation,
    arguments: [u64; 6],
    fs: &F,
) -> u64 {
    let [fd, arg, flags, ..] = arguments;
    let Some(mut entry) = table.get_entry(fd as u32 as i32).cloned() else {
        return errno(EBADF);
    };
    if operation == Operation::Fcntl {
        return match arg as u32 {
            // F_DUPFD (0) and F_DUPFD_CLOEXEC (1030)
            cmd @ (0 | 1030) => {
                let min_fd = flags as i32;
                if min_fd < 0 || (min_fd as usize) >= table.limit.get() {
                    return errno(EINVAL);
                }
                entry.close_on_exec = cmd == 1030;
                table
                    .insert_entry_from(min_fd, entry)
                    .map_or_else(descriptor_errno, u64::from)
            }
            // F_GETFD
            1 => u64::from(entry.close_on_exec),
            // F_SETFD
            2 => {
                table.get_entry_mut(fd as u32 as i32).unwrap().close_on_exec = flags & 1 != 0;
                0
            }
            // F_GETFL: access mode belongs to the open resource; status flags
            // live on the shared open file description.
            3 => {
                let mut fdflags = entry.fdflags();
                let mode = match &entry.descriptor {
                    FileDescriptor::File(open) => fs.file_access(open.node()).linux_accmode(),
                    FileDescriptor::Preopen { descriptor, .. } => {
                        fs.file_access(descriptor).linux_accmode()
                    }
                    FileDescriptor::PipeRead { .. } | FileDescriptor::Stdin { .. } => fs::O_RDONLY,
                    FileDescriptor::PipeWrite { .. }
                    | FileDescriptor::Stdout
                    | FileDescriptor::Stderr => fs::O_WRONLY,
                    FileDescriptor::Socket(sock) => {
                        if sock.is_nonblocking() {
                            fdflags |= FDFLAG_NONBLOCK;
                        }
                        fs::O_RDWR
                    }
                    _ => fs::O_RDWR,
                };
                mode | fs::fdflags_to_linux(abi, fdflags)
            }
            // F_SETFL
            4 => {
                if entry.fdflags() & FDFLAG_PATH != 0 {
                    return errno(EBADF);
                }
                let updated = fs::apply_setfl(abi, entry.fdflags(), flags);
                let slot = table.get_entry(fd as u32 as i32).unwrap();
                slot.set_fdflags(updated);
                if let FileDescriptor::Socket(sock) = &slot.descriptor {
                    sock.set_nonblocking(updated & FDFLAG_NONBLOCK != 0);
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
                    Err(EventError::WouldBlock) if entry.fdflags() & FDFLAG_NONBLOCK != 0 => {
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
        FileDescriptor::PipeWrite { writer, .. } => {
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
                let result = if entry.fdflags() & FDFLAG_NONBLOCK != 0 {
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
    let nonblock = entry.fdflags() & FDFLAG_NONBLOCK != 0;
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
        FileDescriptor::PipeRead { reader, .. } => {
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
    if target.fdflags() & FDFLAG_PATH != 0 {
        return errno(EBADF);
    }
    if fd == epfd {
        return errno(EINVAL);
    }
    // Regular files, directories and `/dev/null` cannot be monitored by epoll
    // (`EPERM`), whereas standard streams (pipes or terminals) can.
    if matches!(
        target.descriptor,
        FileDescriptor::File(_) | FileDescriptor::Preopen { .. } | FileDescriptor::NullDevice
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
        if events
            & !(EPOLLIN
                | EPOLLOUT
                | EPOLLERR
                | EPOLLHUP
                | EPOLLRDNORM
                | EPOLLWRNORM
                | EPOLLRDHUP
                | EPOLLONESHOT)
            != 0
        {
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
pub(super) async fn epoll_wait<
    R: Resources,
    M: UserMemory,
    O: Stdio + Clock + super::socket::Network<R::Network>,
>(
    abi: Abi,
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    io: &O,
    has_mask: bool,
) -> SyscallOutcome {
    const NETWORK_REPOLL_NANOS: u64 = 1_000_000;
    let epoll = {
        let table = process.shared.descriptors.lock();
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
        process
            .signals
            .push_temp_mask(SignalSet::from_bits(u64::from_le_bytes(mask_bytes)));
        true
    } else {
        false
    };
    let timeout = args[3] as i32;
    let deadline =
        (timeout >= 0).then(|| io.now_nanos().saturating_add(timeout as u64 * 1_000_000));
    loop {
        let mut waits = Vec::new();
        let mut watch_stdin = false;
        let mut repoll = false;
        // Snapshot interests and their non-socket readiness synchronously under
        // the descriptor table lock; socket readiness probes are async and run
        // after the spin lock is dropped.
        let snapshot: Vec<_> = {
            let guard = process.shared.descriptors.lock();
            let interests = epoll.interests();
            poll::arm_epoll_waits::<R, O>(
                process,
                &epoll,
                &guard,
                io,
                &mut waits,
                &mut watch_stdin,
                &mut repoll,
            );
            interests
                .into_iter()
                .filter_map(|interest| {
                    let target = guard.get_entry(interest.fd)?;
                    if matches!(target.descriptor, FileDescriptor::Socket(_)) {
                        Some((interest, Some(target.clone()), 0))
                    } else {
                        let events = poll::ready_mask::<R, O>(process, target, &guard, io, true)
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
                        super::socket::socket_epoll_ready(sock, interest.events, io).await
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
                    process.signals.restore_temp_mask();
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
                process.signals.restore_temp_mask();
            }
            return SyscallOutcome::Return(count);
        }
        let now = io.now_nanos();
        if deadline.is_some_and(|end| now >= end) {
            if installed_mask {
                process.signals.restore_temp_mask();
            }
            return SyscallOutcome::Return(0);
        }
        let wake_at = match (deadline, repoll) {
            (Some(end), true) => Some(end.min(now.saturating_add(NETWORK_REPOLL_NANOS))),
            (Some(end), false) => Some(end),
            (None, true) => Some(now.saturating_add(NETWORK_REPOLL_NANOS)),
            (None, false) => None,
        };
        if poll::wait_once(&process.signals, wake_at, &mut waits, watch_stdin, io).await {
            // Leave `saved_mask` active (`TIF_RESTORE_SIGMASK`) so signal
            // delivery writes the original mask into `uc_sigmask`.
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
    struct TestIo;
    impl super::Clock for TestIo {
        fn now_nanos(&self) -> u64 {
            0
        }
        async fn sleep_until(&self, _: u64) {
            core::future::pending().await
        }
    }
    impl Stdio for TestIo {
        async fn write(&mut self, _: Stream, bytes: &[u8]) -> Result<usize, WriteError> {
            Ok(bytes.len())
        }
        async fn read_input(&mut self, _: usize) -> Result<Bytes, Denied> {
            Ok(Bytes::new())
        }
    }
    impl super::super::socket::Network<helios_unix::NoNetwork> for TestIo {
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
        let descriptors = DescriptorSlots::<Entry<NoBacking>>::from_entries(alloc::vec![
            Some(Entry::<NoBacking>::new(
                FileDescriptor::Event(event.clone()),
                false
            )),
            Some(Entry::<NoBacking>::new(FileDescriptor::Epoll(child), false)),
            Some(Entry::<NoBacking>::new(
                FileDescriptor::Epoll(parent),
                false
            )),
        ]);
        let process = Process::<NoBacking>::with_descriptors(
            Abi::X86_64,
            NonZeroU32::new(1).unwrap(),
            0x40_0000,
            descriptors,
            Start::default(),
        );
        let mut memory = Memory([0; 64]);
        let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
        let waker = Waker::from(wakes.clone());
        let mut context = Context::from_waker(&waker);
        {
            let mut future = core::pin::pin!(epoll_wait::<NoBacking, _, _>(
                Abi::X86_64,
                &process,
                [2, 0, 1, u64::MAX, 0, 0],
                &mut memory,
                &TestIo,
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
