use crate::{Epoll, EventFd};
use alloc::string::String;
use alloc::sync::Arc;
use bytes::Bytes;
use core::sync::atomic::{AtomicU16, Ordering};
use helios_sync::{ByteReader, ByteWriter};
/// ABI-independent descriptor resources. File and socket adapters provide the
/// platform's backing objects; UNIX object ownership is common to every ABI.
#[derive(Clone)]
pub struct FileDescriptorEntry<File: Clone, Socket: Clone, Data: Clone> {
    pub descriptor: FileDescriptor<File, Socket, Data>,
    pub close_on_exec: bool,
    fdflags: Arc<AtomicU16>,
}

#[derive(Clone)]
pub enum FileDescriptor<File: Clone, Socket: Clone, Data: Clone> {
    Stdin {
        carry: Bytes,
    },
    Stdout,
    Stderr,
    PipeRead {
        reader: ByteReader,
    },
    PipeWrite {
        writer: ByteWriter,
    },
    Event(EventFd),
    Preopen {
        guest_name: String,
        descriptor: File,
    },
    File {
        descriptor: File,
        offset: u64,
        fdflags: u16,
    },
    NullDevice,
    Socket(Socket),
    Epoll(Epoll<Data>),
}

impl<File: Clone, Socket: Clone, Data: Clone> FileDescriptorEntry<File, Socket, Data> {
    pub fn new(descriptor: FileDescriptor<File, Socket, Data>, close_on_exec: bool) -> Self {
        let fdflags = match &descriptor {
            FileDescriptor::File { fdflags, .. } => *fdflags,
            _ => 0,
        };
        Self {
            descriptor,
            close_on_exec,
            fdflags: Arc::new(AtomicU16::new(fdflags)),
        }
    }
    /// Status flags belong to the open description and are shared by dup/fork.
    /// Atomic loads/stores are lock-free; no lock spans asynchronous I/O.
    pub fn fdflags(&self) -> u16 {
        self.fdflags.load(Ordering::Acquire)
    }
    pub fn set_fdflags(&self, flags: u16) {
        self.fdflags.store(flags, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::{FileDescriptor, FileDescriptorEntry};
    use core::convert::Infallible;
    #[test]
    fn duplicate_shares_status_flags_but_not_close_on_exec() {
        let entry = FileDescriptorEntry::<Infallible, Infallible, u64>::new(
            FileDescriptor::NullDevice,
            false,
        );
        let mut duplicate = entry.clone();
        duplicate.set_fdflags(8);
        duplicate.close_on_exec = true;
        assert_eq!(entry.fdflags(), 8);
        assert!(!entry.close_on_exec);
    }
}
