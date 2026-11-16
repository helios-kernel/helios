use super::*;
use alloc::vec::Vec;
use bytes::Bytes;
use core::future::{Future, poll_fn};
use core::task::{Context, Poll};
use helios_sync::{
    ByteReadWait, ByteReader, ByteWriteWait, ByteWriter, NotifyWaiter, TryRead, TryWrite,
    byte_channel,
};
use helios_unix::{DescriptorTableError, Epoll, EventError, EventFd, Interest, InterestError};

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
fn insert<File: Clone>(
    table: &mut Descriptors<File>,
    descriptor: Descriptor<File>,
    flags: u64,
) -> u64 {
    let entry = Entry::new(descriptor, flags & CLOEXEC != 0);
    entry.set_fdflags(flags as u16 & NONBLOCK);
    table
        .insert_entry(entry)
        .map_or_else(descriptor_errno, u64::from)
}
pub(super) fn event<File: Clone>(
    table: &mut Descriptors<File>,
    args: [u64; 6],
    has_flags: bool,
) -> u64 {
    let flags = if has_flags { args[1] as u32 as u64 } else { 0 };
    if flags & !(CLOEXEC | u64::from(NONBLOCK) | 1) != 0 {
        return errno(EINVAL);
    }
    insert(
        table,
        Descriptor::Event(EventFd::new(args[0] as u32 as u64, flags & 1 != 0)),
        flags,
    )
}
pub(super) fn pipe<File: Clone, M: UserMemory>(
    table: &mut Descriptors<File>,
    args: [u64; 6],
    memory: &mut M,
    has_flags: bool,
) -> u64 {
    let flags = if has_flags { args[1] as u32 as u64 } else { 0 };
    if flags & !(CLOEXEC | u64::from(NONBLOCK)) != 0 {
        return errno(EINVAL);
    }
    let (writer, reader) = byte_channel();
    let read = insert(table, Descriptor::PipeRead { reader }, flags);
    if read > i32::MAX as u64 {
        return read;
    }
    let write = insert(table, Descriptor::PipeWrite { writer }, flags);
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
pub(super) fn duplicate<File: Clone>(table: &mut Descriptors<File>, call: Call) -> u64 {
    let [fd, arg, flags, ..] = call.arguments;
    let Some(mut entry) = table.get_entry(fd as u32 as i32).cloned() else {
        return errno(EBADF);
    };
    if call.number == 72 {
        return match arg as u32 {
            1 => u64::from(entry.close_on_exec), // F_GETFD
            2 => {
                table.get_entry_mut(fd as u32 as i32).unwrap().close_on_exec = flags & 1 != 0;
                0
            }
            3 => {
                // F_GETFL: access mode belongs to the open resource.
                let mode = match entry.descriptor {
                    Descriptor::PipeRead { .. } => 0,
                    Descriptor::PipeWrite { .. } | Descriptor::Stdout | Descriptor::Stderr => 1,
                    _ => 2,
                };
                mode | u64::from(entry.fdflags())
            }
            4 => {
                table
                    .get_entry(fd as u32 as i32)
                    .unwrap()
                    .set_fdflags(flags as u16 & NONBLOCK);
                0
            }
            _ => errno(EINVAL),
        };
    }
    entry.close_on_exec = false;
    match call.number {
        32 => table
            .insert_entry(entry)
            .map_or_else(descriptor_errno, u64::from),
        33 | 292 => {
            if call.number == 292 {
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
pub(super) async fn write_resource<File: Clone, M: UserMemory>(
    entry: &Entry<File>,
    args: [u64; 6],
    memory: &M,
) -> u64 {
    match &entry.descriptor {
        Descriptor::Event(event) => {
            if args[2] < 8 {
                return errno(EINVAL);
            }
            let mut bytes = [0; 8];
            if memory.read(args[1], &mut bytes).is_err() {
                return errno(EFAULT);
            }
            let value = u64::from_le_bytes(bytes);
            loop {
                let mut wait = event.wait_state();
                match event.write(value) {
                    Ok(()) => return 8,
                    Err(EventError::InvalidIncrement) => return errno(EINVAL),
                    Err(EventError::WouldBlock) if entry.fdflags() & NONBLOCK != 0 => {
                        return errno(EAGAIN);
                    }
                    Err(EventError::WouldBlock) => {
                        poll_fn(|cx| event.poll_changed(cx, &mut wait)).await
                    }
                }
            }
        }
        Descriptor::PipeWrite { writer } => {
            let mut total = 0;
            let mut bytes = [0; 4096];
            while total < args[2].min(MAX_RW_COUNT) {
                let size = (args[2].min(MAX_RW_COUNT) - total).min(bytes.len() as u64) as usize;
                if memory
                    .read(args[1].wrapping_add(total), &mut bytes[..size])
                    .is_err()
                {
                    return if total == 0 { errno(EFAULT) } else { total };
                }
                let chunk = Bytes::copy_from_slice(&bytes[..size]);
                let result = if entry.fdflags() & NONBLOCK != 0 {
                    match writer.try_write(chunk) {
                        TryWrite::Written => Ok(()),
                        TryWrite::Closed => Err(EPIPE),
                        TryWrite::Full(_) => Err(EAGAIN),
                    }
                } else {
                    writer.write(chunk).await.map_err(|_| EPIPE)
                };
                if let Err(error) = result {
                    return if total == 0 { errno(error) } else { total };
                }
                total += size as u64;
            }
            total
        }
        Descriptor::NullDevice => args[2].min(MAX_RW_COUNT),
        _ => errno(EBADF),
    }
}
pub(super) async fn read<File: Clone, M: UserMemory>(
    table: &mut Descriptors<File>,
    args: [u64; 6],
    memory: &mut M,
) -> u64 {
    let Some(entry) = table.get_entry_mut(args[0] as u32 as i32) else {
        return errno(EBADF);
    };
    let nonblock = entry.fdflags() & NONBLOCK != 0;
    match &mut entry.descriptor {
        Descriptor::Event(event) => {
            if args[2] < 8 {
                return errno(EINVAL);
            }
            // Validate the destination before consuming the counter.
            if memory.check_writable(args[1], 8).is_err() {
                return errno(EFAULT);
            }
            let value = if nonblock {
                match event.try_read() {
                    Ok(value) => value,
                    Err(_) => return errno(EAGAIN),
                }
            } else {
                event.read().await
            };
            if memory.write(args[1], &value.to_le_bytes()).is_err() {
                return errno(EFAULT);
            }
            8
        }
        Descriptor::PipeRead { reader } => {
            let limit = args[2].min(MAX_RW_COUNT) as usize;
            if memory.check_writable(args[1], limit).is_err() {
                return errno(EFAULT);
            }
            let next = if nonblock {
                match reader.try_read_limit(limit) {
                    TryRead::Ready(bytes) => Some(bytes),
                    TryRead::Eof => None,
                    TryRead::Pending => return errno(EAGAIN),
                }
            } else {
                reader.read_limit(limit).await
            };
            let Some(bytes) = next else {
                return 0;
            };
            if memory.write(args[1], &bytes).is_err() {
                return errno(EFAULT);
            }
            bytes.len() as u64
        }
        Descriptor::NullDevice => 0,
        _ => errno(EBADF),
    }
}
pub(super) fn epoll_create<File: Clone>(
    table: &mut Descriptors<File>,
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
    insert(table, Descriptor::Epoll(Epoll::new()), flags)
}
pub(super) fn epoll_ctl<File: Clone, M: UserMemory>(
    table: &mut Descriptors<File>,
    args: [u64; 6],
    memory: &M,
) -> u64 {
    let epfd = args[0] as u32 as i32;
    let fd = args[2] as u32 as i32;
    let Some(entry) = table.get_entry(epfd) else {
        return errno(EBADF);
    };
    let Descriptor::Epoll(epoll) = &entry.descriptor else {
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
        Descriptor::Stdout | Descriptor::Stderr | Descriptor::NullDevice
    ) {
        return errno(EPERM);
    }
    let op = args[1] as u32;
    if let Descriptor::Epoll(target) = &target.descriptor {
        if target.same_object(epoll) {
            return errno(EINVAL);
        }
        if op == 1 && !valid_nesting(target, epoll, table, 1) {
            return errno(40);
        } // ELOOP
    }
    let result = if op == 2 {
        epoll.remove(fd)
    } else {
        if op != 1 && op != 3 {
            return errno(EINVAL);
        }
        let mut bytes = [0; 12]; // x86-64 Linux epoll_event is packed: u32 + u64.
        if memory.read(args[3], &mut bytes).is_err() {
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
            data: u64::from_le_bytes(bytes[4..].try_into().unwrap()),
        };
        if op == 1 {
            match epoll.add(interest) {
                Ok(()) => {
                    let valid = table.entries.iter().flatten().all(|entry| {
                        let Descriptor::Epoll(root) = &entry.descriptor else {
                            return true;
                        };
                        root.registrations().iter().all(|interest| {
                            match table.get_entry(interest.fd).map(|entry| &entry.descriptor) {
                                Some(Descriptor::Epoll(child)) => {
                                    valid_nesting(child, root, table, 1)
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
fn ready_mask<File: Clone>(entry: &Entry<File>, table: &Descriptors<File>) -> u32 {
    match &entry.descriptor {
        Descriptor::Event(event) => {
            (if event.is_readable() { EPOLLIN } else { 0 })
                | (if event.is_writable() { EPOLLOUT } else { 0 })
        }
        Descriptor::PipeRead { reader } => {
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
        Descriptor::PipeWrite { writer } => {
            if writer.is_reader_closed() {
                EPOLLERR
            } else if writer.is_writable() {
                EPOLLOUT
            } else {
                0
            }
        }
        Descriptor::Epoll(epoll) => {
            if epoll.interests().iter().any(|interest| {
                table.get_entry(interest.fd).is_some_and(|entry| {
                    ready_mask(entry, table) & (interest.events | EPOLLERR | EPOLLHUP) != 0
                })
            }) {
                EPOLLIN
            } else {
                0
            }
        }
        Descriptor::Stdout | Descriptor::Stderr => EPOLLOUT,
        _ => 0,
    }
}
// Linux limits nested epoll traversal to five levels (eventpoll.c EP_MAX_NESTS).
fn valid_nesting<File: Clone>(
    target: &Epoll<u64>,
    parent: &Epoll<u64>,
    table: &Descriptors<File>,
    depth: usize,
) -> bool {
    depth <= 4
        && !target.same_object(parent)
        && target.registrations().iter().all(|interest| {
            match table.get_entry(interest.fd).map(|entry| &entry.descriptor) {
                Some(Descriptor::Epoll(child)) => valid_nesting(child, parent, table, depth + 1),
                _ => true,
            }
        })
}
fn arm_waits<File: Clone>(epoll: &Epoll<u64>, table: &Descriptors<File>, waits: &mut Vec<Wait>) {
    for interest in epoll.interests() {
        if let Some(entry) = table.get_entry(interest.fd) {
            match &entry.descriptor {
                Descriptor::Epoll(child) if interest.events & EPOLLIN != 0 => {
                    arm_waits(child, table, waits)
                }
                _ => {
                    if let Some(wait) = Wait::arm(entry, interest.events) {
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
    fn arm<File: Clone>(entry: &Entry<File>, events: u32) -> Option<Self> {
        match &entry.descriptor {
            Descriptor::Event(event) => Some(Self::Event(event.clone(), event.wait_state())),
            Descriptor::PipeRead { reader, .. } if events & EPOLLIN != 0 => {
                Some(Self::Read(reader.clone(), reader.wait_state()))
            }
            Descriptor::PipeWrite { writer } if events & EPOLLOUT != 0 => {
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
pub(super) async fn epoll_wait<File: Clone, M: UserMemory, C: Clock>(
    table: &Descriptors<File>,
    args: [u64; 6],
    memory: &mut M,
    clock: &C,
    has_mask: bool,
) -> u64 {
    let Some(entry) = table.get_entry(args[0] as u32 as i32) else {
        return errno(EBADF);
    };
    let Descriptor::Epoll(epoll) = &entry.descriptor else {
        return errno(EINVAL);
    };
    let maxevents = args[2] as i32;
    if maxevents <= 0 || maxevents as u64 > i32::MAX as u64 / 12 {
        return errno(EINVAL);
    }
    if has_mask && args[4] != 0 {
        return errno(EOPNOTSUPP);
    }
    let timeout = args[3] as i32;
    let deadline =
        (timeout >= 0).then(|| clock.now_nanos().saturating_add(timeout as u64 * 1_000_000));
    loop {
        let interests = epoll.interests();
        let mut waits = Vec::new();
        arm_waits(epoll, table, &mut waits);
        let mut count = 0;
        for interest in interests {
            let Some(target) = table.get_entry(interest.fd) else {
                continue;
            };
            let events = ready_mask(target, table) & (interest.events | EPOLLERR | EPOLLHUP);
            if events == 0 {
                continue;
            }
            let mut bytes = [0; 12];
            bytes[..4].copy_from_slice(&events.to_le_bytes());
            bytes[4..].copy_from_slice(&interest.data.to_le_bytes());
            if memory
                .write(args[1].wrapping_add(count * 12), &bytes)
                .is_err()
            {
                return if count == 0 { errno(EFAULT) } else { count };
            }
            epoll.delivered(interest.fd);
            count += 1;
            if count == maxevents as u64 {
                break;
            }
        }
        if count != 0 {
            return count;
        }
        if deadline.is_some_and(|end| clock.now_nanos() >= end) {
            return 0;
        }
        let timer = async {
            match deadline {
                Some(end) => clock.sleep_until(end).await,
                None => core::future::pending().await,
            }
        };
        let mut timer = core::pin::pin!(timer);
        poll_fn(|cx| {
            let mut ready = timer.as_mut().poll(cx).is_ready();
            for wait in &mut waits {
                ready |= wait.poll(cx).is_ready();
            }
            if ready {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
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
        let table = Descriptors::<Infallible>::from_entries(alloc::vec![
            Some(Entry::new(Descriptor::Event(event.clone()), false)),
            Some(Entry::new(Descriptor::Epoll(child), false)),
            Some(Entry::new(Descriptor::Epoll(parent), false)),
        ]);
        let mut memory = Memory([0; 64]);
        let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
        let waker = Waker::from(wakes.clone());
        let mut context = Context::from_waker(&waker);
        {
            let mut future = core::pin::pin!(epoll_wait(
                &table,
                [2, 0, 1, u64::MAX, 0, 0],
                &mut memory,
                &Clock,
                false
            ));
            assert!(future.as_mut().poll(&mut context).is_pending());
            event.write(1).unwrap();
            assert!(wakes.0.load(Ordering::Relaxed) > 0);
            assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(1));
        }
        assert_eq!(
            u32::from_le_bytes(memory.0[..4].try_into().unwrap()),
            EPOLLIN
        );
        assert_eq!(u64::from_le_bytes(memory.0[4..12].try_into().unwrap()), 456);
        assert_eq!(event.try_read(), Ok(1));
    }
}
