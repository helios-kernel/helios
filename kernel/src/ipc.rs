//! Bounded duplex capability channels (`helios:system/ipc`).
//!
//! A channel is a pair of [`IpcEndpoint`] values backed by two
//! single-direction [`helios_sync::byte_channel`] queues (`A -> B` and
//! `B -> A`). Possession of an endpoint is the sole authority required
//! to read from or write to its half of the connection; endpoints carry
//! no global names and can be transferred to a spawned child only
//! through explicit launch grants ([`IpcEndpointGrants`]).
//!
//! # Flow control and memory bounds
//!
//! Writes larger than [`IPC_MAX_CHUNK_BYTES`] are sliced into chunks of
//! at most [`IPC_MAX_CHUNK_BYTES`] bytes before entering the bounded
//! 256-slot [`ByteWriter`] queue, capping each direction's buffered
//! payload while suspending fast writers cooperatively without
//! blocking a processor.
//!
//! # Concurrency contract
//!
//! [`IpcEndpoint`] is `Send + Sync`:
//! - `writer` sits behind a short `spin::Mutex<Option<ByteWriter>>`
//!   held only to clone the handle or take it in [`IpcEndpoint::close_write`],
//!   never across an `.await`.
//! - `reader` is a [`ByteReader`] whose internal queue and wakeups are
//!   already SMP-safe.
//! - Dropping an [`IpcEndpoint`] drops both its `ByteWriter` (delivering
//!   EOF to the peer's reader once drained) and its `ByteReader`
//!   (discarding unread inbound chunks and waking any parked peer writer
//!   with [`IpcError::Closed`]).

extern crate alloc;

use alloc::string::String;
use arrayvec::{ArrayString, ArrayVec};
use bytes::Bytes;
use spin::Mutex;
use thiserror::Error;
use triomphe::Arc;

use crate::io::{ByteReader, ByteWriter, byte_channel};

/// Largest chunk pushed into one [`ByteWriter`] slot by [`IpcEndpoint::write`].
pub const IPC_MAX_CHUNK_BYTES: usize = 64 * 1024;

/// Maximum number of named IPC endpoints a single spawn may hand a child.
pub const MAX_IPC_GRANTS: usize = 16;

/// Maximum UTF-8 byte length of an IPC endpoint grant name.
pub const MAX_IPC_GRANT_NAME_BYTES: usize = 64;

/// Failure on a duplex IPC endpoint operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum IpcError {
    /// Either the peer dropped its endpoint or the local write half was closed.
    #[error("the IPC channel direction is closed")]
    Closed,
}

/// Why an IPC grant list on a child spawn could not be assembled.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum IpcGrantError {
    #[error("IPC grant name must not be empty")]
    EmptyName,
    #[error("IPC grant name exceeds {max} bytes")]
    NameTooLong { max: usize },
    #[error("duplicate IPC grant name {0:?}")]
    DuplicateName(String),
    #[error("an instance accepts at most {max} IPC endpoint grants")]
    TooManyGrants { max: usize },
}

struct IpcEndpointInner {
    writer: Mutex<Option<ByteWriter>>,
    reader: Mutex<Option<ByteReader>>,
}

impl IpcEndpointInner {
    async fn read(&self, max_bytes: u32) -> Result<Option<Bytes>, IpcError> {
        let Some(reader) = self.reader.lock().clone() else {
            return Ok(None);
        };
        if max_bytes == 0 {
            if !reader.has_buffered_data() && reader.is_writer_closed() {
                return Ok(None);
            }
            return Ok(Some(Bytes::new()));
        }
        Ok(reader.read_limit(max_bytes as usize).await)
    }

    async fn write(&self, bytes: &[u8]) -> Result<(), IpcError> {
        let writer = self.writer.lock().clone().ok_or(IpcError::Closed)?;
        if bytes.is_empty() {
            return writer
                .write(Bytes::new())
                .await
                .map_err(|_| IpcError::Closed);
        }
        for chunk in bytes.chunks(IPC_MAX_CHUNK_BYTES) {
            writer
                .write(Bytes::copy_from_slice(chunk))
                .await
                .map_err(|_| IpcError::Closed)?;
        }
        Ok(())
    }

    fn close_write(&self) {
        if let Some(writer) = self.writer.lock().take() {
            writer.close();
        }
    }

    fn close_both(&self) {
        self.close_write();
        if let Some(reader) = self.reader.lock().take() {
            reader.close();
        }
    }
}

/// Shared borrow handle used by async host methods so a guest fiber may
/// await `read` and `write` concurrently without holding a store lock.
#[derive(Clone)]
pub(crate) struct IpcEndpointRef {
    inner: Arc<IpcEndpointInner>,
}

impl IpcEndpointRef {
    pub(crate) async fn read(&self, max_bytes: u32) -> Result<Option<Bytes>, IpcError> {
        self.inner.read(max_bytes).await
    }

    pub(crate) async fn write(&self, bytes: &[u8]) -> Result<(), IpcError> {
        self.inner.write(bytes).await
    }
}

/// One end of a bounded duplex capability channel.
pub struct IpcEndpoint {
    inner: Arc<IpcEndpointInner>,
}

impl core::fmt::Debug for IpcEndpoint {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("IpcEndpoint")
            .field("write_open", &self.inner.writer.lock().is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for IpcEndpoint {
    fn drop(&mut self) {
        self.inner.close_both();
    }
}

/// Creates a connected pair of bounded duplex capability endpoints.
pub fn ipc_channel() -> (IpcEndpoint, IpcEndpoint) {
    let (tx_ab, rx_ab) = byte_channel();
    let (tx_ba, rx_ba) = byte_channel();
    let first = IpcEndpoint {
        inner: Arc::new(IpcEndpointInner {
            writer: Mutex::new(Some(tx_ab)),
            reader: Mutex::new(Some(rx_ba)),
        }),
    };
    let second = IpcEndpoint {
        inner: Arc::new(IpcEndpointInner {
            writer: Mutex::new(Some(tx_ba)),
            reader: Mutex::new(Some(rx_ab)),
        }),
    };
    (first, second)
}

impl IpcEndpoint {
    #[cfg(feature = "wasmtime-runtime")]
    pub(crate) fn shared(&self) -> IpcEndpointRef {
        IpcEndpointRef {
            inner: self.inner.clone(),
        }
    }

    /// Reads up to `max_bytes` from the peer.
    ///
    /// Returns `Ok(None)` once the peer has closed its write half (or
    /// dropped its endpoint) and all buffered bytes have been consumed.
    pub async fn read(&self, max_bytes: u32) -> Result<Option<Bytes>, IpcError> {
        self.inner.read(max_bytes).await
    }

    /// Writes `bytes` to the peer, suspending cooperatively while the
    /// channel's bounded buffer is full.
    pub async fn write(&self, bytes: &[u8]) -> Result<(), IpcError> {
        self.inner.write(bytes).await
    }

    /// Half-closes the outbound direction, delivering EOF (`Ok(None)`) to
    /// the peer's reader once queued bytes drain while keeping the inbound
    /// direction open.
    pub fn close_write(&self) {
        self.inner.close_write();
    }
}

/// Named [`IpcEndpoint`] capabilities handed to a newly spawned instance.
///
/// Each endpoint can be claimed at most once via [`Self::take`]; any
/// unclaimed endpoints are dropped automatically when the instance's
/// store is torn down, closing both directions cleanly for their peers.
#[derive(Debug, Default)]
pub struct IpcEndpointGrants {
    entries: Mutex<ArrayVec<(ArrayString<MAX_IPC_GRANT_NAME_BYTES>, IpcEndpoint), MAX_IPC_GRANTS>>,
}

impl IpcEndpointGrants {
    pub const fn new() -> Self {
        Self {
            entries: Mutex::new(ArrayVec::new_const()),
        }
    }

    pub fn insert(&mut self, name: &str, endpoint: IpcEndpoint) -> Result<(), IpcGrantError> {
        if name.is_empty() {
            return Err(IpcGrantError::EmptyName);
        }
        let key = ArrayString::<MAX_IPC_GRANT_NAME_BYTES>::from(name).map_err(|_| {
            IpcGrantError::NameTooLong {
                max: MAX_IPC_GRANT_NAME_BYTES,
            }
        })?;
        let entries = self.entries.get_mut();
        if entries
            .iter()
            .any(|(existing, _)| existing.as_str() == name)
        {
            return Err(IpcGrantError::DuplicateName(String::from(name)));
        }
        entries
            .try_push((key, endpoint))
            .map_err(|_| IpcGrantError::TooManyGrants {
                max: MAX_IPC_GRANTS,
            })
    }

    /// Claims and removes the endpoint granted under `name`, or returns
    /// `None` if no unclaimed grant carries that name.
    pub fn take(&self, name: &str) -> Option<IpcEndpoint> {
        let mut entries = self.entries.lock();
        let index = entries
            .iter()
            .position(|(existing, _)| existing.as_str() == name)?;
        Some(entries.remove(index).1)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};

    use super::{
        IPC_MAX_CHUNK_BYTES, IpcEndpointGrants, IpcError, IpcGrantError, MAX_IPC_GRANT_NAME_BYTES,
        MAX_IPC_GRANTS, ipc_channel,
    };
    use crate::test_support::CountingWaker;

    #[test]
    fn duplex_channel_transfers_frames_both_ways_and_preserves_read_limits() {
        futures_lite::future::block_on(async {
            let (left, right) = ipc_channel();
            left.write(b"ping-from-left").await.unwrap();
            right.write(b"pong-from-right").await.unwrap();

            let head = right.read(4).await.unwrap().expect("bytes available");
            assert_eq!(&head[..], b"ping");
            let tail = right.read(64).await.unwrap().expect("remainder available");
            assert_eq!(&tail[..], b"-from-left");

            let reply = left.read(64).await.unwrap().expect("reply available");
            assert_eq!(&reply[..], b"pong-from-right");
        });
    }

    #[test]
    fn close_write_delivers_eof_after_buffered_bytes_while_keeping_reverse_open() {
        futures_lite::future::block_on(async {
            let (left, right) = ipc_channel();
            left.write(b"final").await.unwrap();
            left.close_write();

            assert_eq!(left.write(b"more").await, Err(IpcError::Closed));
            assert_eq!(
                right.read(16).await.unwrap().as_deref(),
                Some(b"final".as_slice())
            );
            assert_eq!(right.read(16).await.unwrap(), None);
            assert_eq!(right.read(0).await.unwrap(), None);

            // Reverse direction (`right -> left`) stays open.
            right.write(b"ack").await.unwrap();
            assert_eq!(
                left.read(16).await.unwrap().as_deref(),
                Some(b"ack".as_slice())
            );
        });
    }

    #[test]
    fn dropping_peer_wakes_parked_reader_with_eof_and_parked_writer_with_closed() {
        let (left, right) = ipc_channel();

        // Park a reader on `left` before `right` drops.
        let reader_waker = Arc::new(CountingWaker::default());
        let waker = Waker::from(reader_waker.clone());
        let mut cx = Context::from_waker(&waker);
        let mut read_fut = pin!(left.read(32));
        assert_eq!(read_fut.as_mut().poll(&mut cx), Poll::Pending);

        drop(right);
        assert!(reader_waker.wakes() >= 1);
        assert_eq!(read_fut.as_mut().poll(&mut cx), Poll::Ready(Ok(None)));
        assert_eq!(
            futures_lite::future::block_on(left.write(b"orphan")),
            Err(IpcError::Closed)
        );
    }

    #[test]
    fn dropping_endpoint_wakes_parked_local_reader_clone_and_backpressured_peer_writer() {
        // Case 1: parked local `IpcEndpointRef::read` wakes with EOF when the
        // owning `IpcEndpoint` drops even though the read future cloned `ByteReader`.
        let (left, right) = ipc_channel();
        let left_ref = left.shared();
        let reader_waker = Arc::new(CountingWaker::default());
        let waker = Waker::from(reader_waker.clone());
        let mut cx = Context::from_waker(&waker);
        let mut read_fut = pin!(left_ref.read(64));
        assert_eq!(read_fut.as_mut().poll(&mut cx), Poll::Pending);

        drop(left);
        assert!(
            reader_waker.wakes() >= 1,
            "closing the endpoint must wake its own parked read future"
        );
        assert_eq!(read_fut.as_mut().poll(&mut cx), Poll::Ready(Ok(None)));
        assert_eq!(
            futures_lite::future::block_on(right.write(b"after-drop")),
            Err(IpcError::Closed)
        );
        drop(right);

        // Case 2: a backpressured peer `write` wakes with `IpcError::Closed`
        // when the receiver `IpcEndpoint` drops while a local `IpcEndpointRef::read`
        // holds a live `ByteReader` clone.
        let (rx_end, tx_end) = ipc_channel();
        let rx_ref = rx_end.shared();
        // Hold a parked read future on an initially empty channel? No: first park
        // the peer writer on a full queue while a live `ByteReader` clone exists
        // inside a second future, then drop `rx_end`.
        let payload = vec![0x3c_u8; IPC_MAX_CHUNK_BYTES * 260];
        let writer_waker = Arc::new(CountingWaker::default());
        let w_waker = Waker::from(writer_waker.clone());
        let mut w_cx = Context::from_waker(&w_waker);
        let mut write_fut = pin!(tx_end.write(&payload));
        assert_eq!(write_fut.as_mut().poll(&mut w_cx), Poll::Pending);

        // Also hold a cloned `ByteReader` via `rx_end.inner` (simulating an in-flight
        // `IpcEndpointRef::read` task that cloned `ByteReader` before `rx_end` dropped).
        let extra_reader_clone = rx_end.inner.reader.lock().clone().expect("reader is open");
        drop(rx_end);
        assert!(
            writer_waker.wakes() >= 1,
            "closing the endpoint must wake a backpressured peer writer even with live reader clones"
        );
        assert_eq!(
            write_fut.as_mut().poll(&mut w_cx),
            Poll::Ready(Err(IpcError::Closed))
        );
        assert_eq!(futures_lite::future::block_on(rx_ref.read(64)), Ok(None));
        drop(extra_reader_clone);
    }

    #[test]
    fn bounded_queue_suspends_fast_writer_and_resumes_on_drain() {
        let (left, right) = ipc_channel();
        // Fill all 256 chunk slots (256 * 1 byte) plus one oversized write
        // that parks once the queue hits capacity.
        let payload = vec![0x5a_u8; IPC_MAX_CHUNK_BYTES * 260];
        let writer_waker = Arc::new(CountingWaker::default());
        let waker = Waker::from(writer_waker.clone());
        let mut cx = Context::from_waker(&waker);
        let mut write_fut = pin!(left.write(&payload));

        assert_eq!(
            write_fut.as_mut().poll(&mut cx),
            Poll::Pending,
            "bounded IPC queue must apply backpressure rather than buffering without bound"
        );

        let mut received = Vec::with_capacity(payload.len());
        let mut write_done = false;
        futures_lite::future::block_on(async {
            while received.len() < payload.len() {
                if !write_done && let Poll::Ready(res) = write_fut.as_mut().poll(&mut cx) {
                    res.expect("peer stays open");
                    write_done = true;
                }
                if let Some(chunk) = right
                    .read((IPC_MAX_CHUNK_BYTES * 8) as u32)
                    .await
                    .expect("read succeeds")
                {
                    received.extend_from_slice(&chunk);
                }
            }
            if !write_done {
                write_fut.await.expect("peer stays open");
                write_done = true;
            }
        });
        assert!(write_done);
        assert!(writer_waker.wakes() >= 1);
        assert_eq!(received.len(), payload.len());
        assert!(received.iter().all(|&b| b == 0x5a));
    }

    #[test]
    fn endpoint_grants_enforce_unique_bounded_names_and_drop_unclaimed_peers() {
        let mut grants = IpcEndpointGrants::new();
        let (a1, b1) = ipc_channel();
        assert_eq!(grants.insert("", a1), Err(IpcGrantError::EmptyName));
        drop(b1);

        let (a2, b2) = ipc_channel();
        let oversized = "x".repeat(MAX_IPC_GRANT_NAME_BYTES + 1);
        assert_eq!(
            grants.insert(&oversized, a2),
            Err(IpcGrantError::NameTooLong {
                max: MAX_IPC_GRANT_NAME_BYTES
            })
        );
        drop(b2);

        let (parent_end, child_end) = ipc_channel();
        grants.insert("control", child_end).unwrap();

        let (dup_a, dup_b) = ipc_channel();
        assert_eq!(
            grants.insert("control", dup_a),
            Err(IpcGrantError::DuplicateName("control".into()))
        );
        drop(dup_b);

        // Claiming once returns the endpoint; claiming a second time answers None.
        let claimed = grants.take("control").expect("grant exists");
        assert!(grants.take("control").is_none());
        futures_lite::future::block_on(async {
            parent_end.write(b"hello").await.unwrap();
            assert_eq!(
                claimed.read(16).await.unwrap().as_deref(),
                Some(b"hello".as_slice())
            );
        });
        drop(claimed);
        drop(parent_end);

        // Unclaimed endpoints in `IpcEndpointGrants` close their peers when dropped.
        let mut drop_grants = IpcEndpointGrants::new();
        let mut parent_peers = Vec::new();
        for index in 0..MAX_IPC_GRANTS {
            let (parent, child) = ipc_channel();
            drop_grants
                .insert(&alloc::format!("ch-{index}"), child)
                .unwrap();
            parent_peers.push(parent);
        }
        let (extra_a, extra_b) = ipc_channel();
        assert_eq!(
            drop_grants.insert("overflow", extra_a),
            Err(IpcGrantError::TooManyGrants {
                max: MAX_IPC_GRANTS
            })
        );
        drop(extra_b);

        drop(drop_grants);
        for peer in parent_peers {
            assert_eq!(
                futures_lite::future::block_on(peer.read(8)).unwrap(),
                None,
                "dropping unclaimed child grants must close the peer"
            );
        }
    }
}
