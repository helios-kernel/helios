use std::io;
use std::thread::JoinHandle;

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::future;
use helios_wit_rpc::{Endpoint, PeerHandle};

use crate::runtime;

/// Owns the WIT-RPC connection driver independently of any RPC future. Dropping
/// the last session handle stops the driver, closes the connection and joins
/// its thread. The executor races a stop channel, without polling or a Tokio
/// runtime.
pub(crate) struct FrameReader {
    stop: async_channel::Sender<()>,
    thread: Option<JoinHandle<()>>,
}

impl FrameReader {
    pub(crate) fn start<R, W>(read: R, write: W) -> io::Result<(PeerHandle, Self)>
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let (stop, stopped) = async_channel::bounded::<()>(1);
        let endpoint = Endpoint::new(read, write, ());
        let handle = endpoint.handle();
        let thread = std::thread::Builder::new()
            .name("rpc-frame-reader".to_owned())
            .spawn(move || {
                runtime::block_on(future::or(
                    async {
                        // A transport that fails or closes is recorded on
                        // the peer handle, and every call in flight or made
                        // later reports it.
                        let _ = endpoint.drive().await;
                    },
                    async {
                        let _ = stopped.recv().await;
                    },
                ));
            })?;
        Ok((
            handle,
            Self {
                stop,
                thread: Some(thread),
            },
        ))
    }
}

impl Drop for FrameReader {
    fn drop(&mut self) {
        self.stop.close();
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            panic!("the rpc frame reader thread panicked");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::time::Duration;

    use async_io::Async;

    use super::FrameReader;

    /// Bytes the fake guest sends unprompted. Far beyond what a socket
    /// pair buffers, so a host that reads nothing stalls the guest.
    const UNSOLICITED_BYTES: usize = 8 << 20;

    /// How long the guest may take to finish writing. Generous for a
    /// loaded machine; a host that never reads misses it for certain.
    const GUEST_DEADLINE: Duration = Duration::from_secs(20);

    /// A wire frame for an invocation nobody opened: the 8 magic bytes,
    /// a little-endian payload length of 5, then tag 1 (`Accept`) and
    /// invocation 0.
    const STRAY_ACCEPT: [u8; 17] = [
        0xff, 0x00, b'H', b'R', b'P', b'C', 0xaa, 0x55, 5, 0, 0, 0, 1, 0, 0, 0, 0,
    ];

    #[test]
    fn guest_is_drained_while_no_call_is_in_flight() {
        let (host, mut guest) = UnixStream::pair().expect("create socket pair");
        let (_handle, reader) = FrameReader::start(
            Async::new(host.try_clone().expect("clone read half")).expect("register read half"),
            Async::new(host).expect("register write half"),
        )
        .expect("start reader");

        let (done, finished) = mpsc::channel();
        let guest_thread = std::thread::spawn(move || {
            let burst = STRAY_ACCEPT.repeat(UNSOLICITED_BYTES / STRAY_ACCEPT.len());
            let _ = done.send(guest.write_all(&burst).is_ok());
            // Closing the socket ends the reader's read with end of file.
        });

        assert_eq!(
            finished.recv_timeout(GUEST_DEADLINE),
            Ok(true),
            "the guest blocked writing to a host that made no call: nothing read the transport"
        );
        guest_thread.join().expect("guest thread");
        drop(reader);
    }
}
