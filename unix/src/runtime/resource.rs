use crate::{Epoll, EventFd, OpenFile, Socket, SocketNetwork};
use alloc::string::String;
use alloc::sync::Arc;
use bytes::Bytes;
use core::sync::atomic::{AtomicU16, Ordering};
use helios_sync::{ByteReader, ByteWriter};
/// ABI-independent descriptor resources. The file adapter provides the
/// platform's backing file object and `Net` the network its sockets live
/// on; UNIX object ownership, sockets included, is common to every ABI.
///
/// One entry is one descriptor slot. Cloning it is POSIX duplication: the
/// clone shares the open description, its status flags, for a file the
/// [`OpenFile`] that holds the node and the offset, and for a socket the
/// [`Socket`] that holds its state, options, endpoint and socket-pair carry
/// buffer; only `close_on_exec` belongs to the slot.
#[derive(Clone)]
pub struct FileDescriptorEntry<File: Clone, Net: SocketNetwork, Data: Clone> {
    pub descriptor: FileDescriptor<File, Net, Data>,
    pub close_on_exec: bool,
    fdflags: Arc<AtomicU16>,
}

#[derive(Clone)]
pub enum FileDescriptor<File: Clone, Net: SocketNetwork, Data: Clone> {
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
    File(OpenFile<File>),
    NullDevice,
    Socket(Socket<Net>),
    Epoll(Epoll<Data>),
}

impl<File: Clone, Net: SocketNetwork, Data: Clone> FileDescriptorEntry<File, Net, Data> {
    /// A slot for a new open description, with no status flags set.
    pub fn new(descriptor: FileDescriptor<File, Net, Data>, close_on_exec: bool) -> Self {
        Self {
            descriptor,
            close_on_exec,
            fdflags: Arc::new(AtomicU16::new(0)),
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
    use crate::{NoNetwork, OpenFile};
    use core::convert::Infallible;

    #[test]
    fn duplicate_shares_the_file_offset() {
        let entry = FileDescriptorEntry::<&str, NoNetwork, u64>::new(
            FileDescriptor::File(OpenFile::new("node")),
            false,
        );
        let duplicate = entry.clone();
        let (FileDescriptor::File(file), FileDescriptor::File(copy)) =
            (&entry.descriptor, &duplicate.descriptor)
        else {
            unreachable!("both slots hold the file");
        };
        copy.try_lock_position()
            .expect("the position lock is free")
            .set(5);
        assert_eq!(
            file.try_lock_position()
                .expect("the position lock is free")
                .get(),
            5
        );
        assert!(file.same_description(copy));
    }

    #[test]
    fn duplicate_shares_status_flags_but_not_close_on_exec() {
        let entry = FileDescriptorEntry::<Infallible, NoNetwork, u64>::new(
            FileDescriptor::NullDevice,
            false,
        );
        let mut duplicate = entry.clone();
        duplicate.set_fdflags(8);
        duplicate.close_on_exec = true;
        assert_eq!(entry.fdflags(), 8);
        assert!(!entry.close_on_exec);
    }

    #[test]
    fn duplicate_shares_socket_description() {
        use crate::{Socket, SocketFamily, SocketTime};

        let entry = FileDescriptorEntry::<Infallible, NoNetwork, u64>::new(
            FileDescriptor::Socket(Socket::tcp(SocketFamily::Ipv4)),
            false,
        );
        let duplicate = entry.clone();
        let (FileDescriptor::Socket(sock), FileDescriptor::Socket(dup_sock)) =
            (&entry.descriptor, &duplicate.descriptor)
        else {
            unreachable!("both slots hold the socket");
        };
        dup_sock.set_time(SocketTime::ReceiveTimeout, Some(42));
        assert_eq!(sock.options().time(SocketTime::ReceiveTimeout), Some(42));
        assert!(sock.same_description(dup_sock));
    }
}
