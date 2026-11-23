use std::collections::VecDeque;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_core::Stream;
use helios_inspector_protocol::WireError;

use crate::codec::{
    Decoder, Encoder, InboundPipe, OutboundPipe, PendingInboundSubpath, PendingOutboundSubpath,
    RpcDecode, RpcEncode, activate_inbound_subpaths, activate_outbound_subpaths,
};
use crate::error::RpcError;
use crate::resource::ResourceEntry;

type PollFuture<T> = Pin<Box<dyn Future<Output = Result<T, RpcError>> + Send + 'static>>;

/// Creates a credit-flow-controlled WIT `stream<T>` pair `(StreamWriter<T>, StreamReader<T>)`.
///
/// Pass the [`StreamReader`] across any WIT-RPC parameter or return value and
/// write items into [`StreamWriter`]; each `send` awaits explicit receiver
/// credit on the sub-path before transmitting.
pub fn stream<T>() -> (StreamWriter<T>, StreamReader<T>) {
    let pipe = Arc::new(OutboundPipe::new());
    (
        StreamWriter {
            pipe: Arc::clone(&pipe),
            closed: false,
            _marker: PhantomData,
        },
        StreamReader {
            state: StreamReaderState::Outbound(Some(pipe)),
            buffered: VecDeque::new(),
            poll_fut: None,
        },
    )
}

/// Creates a single-shot WIT `future<T>` pair `(FutureWriter<T>, FutureReader<T>)`.
pub fn future<T>() -> (FutureWriter<T>, FutureReader<T>) {
    let pipe = Arc::new(OutboundPipe::new());
    (
        FutureWriter {
            pipe: Arc::clone(&pipe),
            resolved: false,
            _marker: PhantomData,
        },
        FutureReader {
            state: FutureReaderState::Outbound(Some(pipe)),
            poll_fut: None,
        },
    )
}

/// Producer half of a WIT `stream<T>`.
pub struct StreamWriter<T> {
    pipe: Arc<OutboundPipe>,
    closed: bool,
    _marker: PhantomData<fn(T)>,
}

impl<T> std::fmt::Debug for StreamWriter<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamWriter")
            .field("closed", &self.closed)
            .finish()
    }
}

impl<T> Drop for StreamWriter<T> {
    fn drop(&mut self) {
        if !self.closed {
            self.pipe.mark_writer_dropped();
        }
    }
}

impl<T: RpcEncode<core::convert::Infallible>> StreamWriter<T> {
    /// Sends a single item on the stream, waiting for per-stream credit from
    /// the remote consumer when the window is full.
    pub async fn send(&mut self, item: T) -> Result<(), RpcError> {
        self.send_batch(vec![item]).await
    }

    /// Sends a non-empty batch of items in a single wire frame consuming 1
    /// stream credit.
    pub async fn send_batch(&mut self, items: Vec<T>) -> Result<(), RpcError> {
        if items.is_empty() {
            return Ok(());
        }
        if self.closed || self.pipe.is_closed_for_writer() {
            return Err(RpcError::StreamClosed);
        }
        self.pipe.wait_until_bound().await?;
        let mut guard = self.pipe.lock_writer().await;
        let Some(writer) = guard.as_mut() else {
            return Err(RpcError::StreamClosed);
        };
        if writer.is_peer_stopped() {
            return Err(RpcError::StreamClosed);
        }

        let call = writer.call_handle();
        let (payload, subpaths) = {
            let mut enc = Encoder::<core::convert::Infallible>::new(Some(&call), None);
            T::rpc_encode_vec(items, &mut enc)?;
            enc.finish()
        };
        activate_outbound_subpaths(&call, subpaths).await;
        writer
            .send(payload)
            .await
            .map_err(|err| match err.wire_error() {
                Some(wire) => RpcError::Wire(wire.clone()),
                None => RpcError::StreamClosed,
            })
    }

    /// Sends orderly EOF on the stream.
    pub async fn close(mut self) -> Result<(), RpcError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        if self.pipe.wait_until_bound().await.is_err() {
            return Ok(());
        }
        let writer = self.pipe.lock_writer().await.take();
        if let Some(writer) = writer {
            writer.close().await?;
        }
        Ok(())
    }

    /// Whether the remote consumer dropped its [`StreamReader`] or cancelled
    /// the invocation.
    pub async fn is_closed(&self) -> bool {
        if self.closed || self.pipe.is_closed_for_writer() {
            return true;
        }
        let guard = self.pipe.lock_writer().await;
        guard.as_ref().is_some_and(|w| w.is_peer_stopped())
    }

    /// Waits until the remote consumer stops reading or disconnects.
    pub async fn closed(&self) {
        if self.pipe.wait_until_bound().await.is_err() {
            return;
        }
        let guard = self.pipe.lock_writer().await;
        if let Some(writer) = guard.as_ref() {
            writer.wait_peer_stopped().await;
        }
    }
}

enum StreamReaderState<T> {
    Outbound(Option<Arc<OutboundPipe>>),
    Buffered(Vec<T>),
    Empty,
    Inbound(Arc<InboundPipe>),
}

/// Consumer half of a WIT `stream<T>`.
pub struct StreamReader<T> {
    state: StreamReaderState<T>,
    buffered: VecDeque<T>,
    poll_fut: Option<PollFuture<Option<Vec<T>>>>,
}

impl<T> std::fmt::Debug for StreamReader<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamReader").finish()
    }
}

impl<T> Drop for StreamReader<T> {
    fn drop(&mut self) {
        if let StreamReaderState::Outbound(Some(pipe)) = &mut self.state {
            pipe.mark_reader_dropped();
        }
    }
}

impl<T> StreamReader<T> {
    /// Creates an immediately-closed empty stream.
    pub fn empty() -> Self {
        Self {
            state: StreamReaderState::Empty,
            buffered: VecDeque::new(),
            poll_fut: None,
        }
    }

    /// Creates a finite stream backed by `items`, delivered lazily according to
    /// receiver credits once sent over RPC.
    pub fn from_vec(items: Vec<T>) -> Self {
        if items.is_empty() {
            return Self::empty();
        }
        Self {
            state: StreamReaderState::Buffered(items),
            buffered: VecDeque::new(),
            poll_fut: None,
        }
    }
}

impl<T: RpcEncode<core::convert::Infallible>> StreamReader<T> {
    pub(crate) fn encode_into_subpath<R: ResourceEntry>(
        mut self,
        enc: &mut Encoder<'_, R>,
    ) -> Result<(), WireError> {
        let sub_id = enc.alloc_subpath_id()?;
        enc.write_u32(sub_id);
        match &mut self.state {
            StreamReaderState::Outbound(slot) => {
                let pipe = slot.take().ok_or_else(|| WireError::MalformedPayload {
                    context: "StreamReader::encode".to_owned(),
                    detail: "stream reader already consumed".to_owned(),
                })?;
                enc.push_outbound_subpath(PendingOutboundSubpath::Live { sub_id, pipe });
            }
            StreamReaderState::Buffered(items) => {
                let drained = std::mem::take(items);
                let mut frames = VecDeque::with_capacity(drained.len());
                for item in drained {
                    let mut item_enc =
                        Encoder::<core::convert::Infallible>::new(enc.call_handle(), None);
                    T::rpc_encode_vec(vec![item], &mut item_enc)?;
                    let (bytes, nested) = item_enc.finish();
                    for sub in nested {
                        enc.push_outbound_subpath(sub);
                    }
                    frames.push_back(bytes);
                }
                enc.push_outbound_subpath(PendingOutboundSubpath::Buffered { sub_id, frames });
            }
            StreamReaderState::Empty => {
                enc.push_outbound_subpath(PendingOutboundSubpath::Empty { sub_id });
            }
            StreamReaderState::Inbound(_) => {
                return Err(WireError::MalformedPayload {
                    context: "StreamReader::encode".to_owned(),
                    detail: "inbound stream reader must be forwarded explicitly".to_owned(),
                });
            }
        }
        Ok(())
    }
}

impl<T: RpcDecode<core::convert::Infallible>> StreamReader<T> {
    pub(crate) fn decode_from_subpath<R: ResourceEntry>(
        dec: &mut Decoder<'_, R>,
    ) -> Result<Self, WireError> {
        let sub_id = dec.read_u32()?;
        if sub_id == 0 {
            return Err(WireError::MalformedPayload {
                context: "StreamReader::decode".to_owned(),
                detail: "invalid zero stream sub-path id".to_owned(),
            });
        }
        let pipe = Arc::new(InboundPipe::new());
        dec.push_inbound_subpath(PendingInboundSubpath {
            sub_id,
            credit_window: dec.default_stream_window(),
            pipe: Arc::clone(&pipe),
        });
        Ok(Self {
            state: StreamReaderState::Inbound(pipe),
            buffered: VecDeque::new(),
            poll_fut: None,
        })
    }

    /// Reads the next single item from the stream, replenishing credit to the
    /// remote producer when a batch frame is consumed.
    pub async fn next(&mut self) -> Result<Option<T>, RpcError> {
        loop {
            if let Some(item) = self.buffered.pop_front() {
                return Ok(Some(item));
            }
            match self.next_frame_batch().await? {
                Some(batch) => {
                    self.buffered.extend(batch);
                }
                None => return Ok(None),
            }
        }
    }

    /// Reads the next non-empty batch of items from the stream.
    pub async fn next_batch(&mut self) -> Result<Option<Vec<T>>, RpcError> {
        if !self.buffered.is_empty() {
            return Ok(Some(self.buffered.drain(..).collect()));
        }
        self.next_frame_batch().await
    }

    /// Drains all remaining items on the stream into a `Vec<T>`.
    pub async fn collect_all(mut self) -> Result<Vec<T>, RpcError> {
        let mut all = Vec::new();
        while let Some(batch) = self.next_batch().await? {
            all.extend(batch);
        }
        Ok(all)
    }

    async fn next_frame_batch(&mut self) -> Result<Option<Vec<T>>, RpcError> {
        match &mut self.state {
            StreamReaderState::Empty => Ok(None),
            StreamReaderState::Buffered(items) => {
                if items.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(std::mem::take(items)))
                }
            }
            StreamReaderState::Outbound(_) => Err(RpcError::StreamClosed),
            StreamReaderState::Inbound(pipe) => recv_stream_batch::<T>(Arc::clone(pipe)).await,
        }
    }
}

async fn recv_stream_batch<T: RpcDecode<core::convert::Infallible>>(
    pipe: Arc<InboundPipe>,
) -> Result<Option<Vec<T>>, RpcError> {
    loop {
        let mut guard = pipe.lock_reader().await;
        let Some(reader) = guard.as_mut() else {
            return Ok(None);
        };
        let Some(chunk) = reader.recv().await? else {
            return Ok(None);
        };
        let peer = reader.peer();
        let call = reader.call_handle();
        drop(guard);

        let mut dec = Decoder::<core::convert::Infallible>::new(&chunk, peer, None);
        let batch = T::rpc_decode_vec(&mut dec)?;
        let subpaths = dec.finish()?;
        activate_inbound_subpaths(&call, subpaths).await?;
        if !batch.is_empty() {
            return Ok(Some(batch));
        }
    }
}

impl<T: RpcDecode<core::convert::Infallible> + Unpin + Send + 'static> Stream for StreamReader<T> {
    type Item = Result<T, RpcError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(item) = this.buffered.pop_front() {
                return Poll::Ready(Some(Ok(item)));
            }

            if this.poll_fut.is_none() {
                match &mut this.state {
                    StreamReaderState::Empty => return Poll::Ready(None),
                    StreamReaderState::Buffered(items) => {
                        if items.is_empty() {
                            return Poll::Ready(None);
                        }
                        this.buffered.extend(std::mem::take(items));
                        continue;
                    }
                    StreamReaderState::Outbound(_) => {
                        return Poll::Ready(Some(Err(RpcError::StreamClosed)));
                    }
                    StreamReaderState::Inbound(pipe) => {
                        let pipe = Arc::clone(pipe);
                        this.poll_fut = Some(Box::pin(recv_stream_batch::<T>(pipe)));
                    }
                }
            }

            let fut = this
                .poll_fut
                .as_mut()
                .expect("stream poll future must exist");
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(Some(batch))) => {
                    this.poll_fut = None;
                    this.buffered.extend(batch);
                }
                Poll::Ready(Ok(None)) => {
                    this.poll_fut = None;
                    return Poll::Ready(None);
                }
                Poll::Ready(Err(err)) => {
                    this.poll_fut = None;
                    return Poll::Ready(Some(Err(err)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Completer half of a single-shot WIT `future<T>`.
pub struct FutureWriter<T> {
    pipe: Arc<OutboundPipe>,
    resolved: bool,
    _marker: PhantomData<fn(T)>,
}

impl<T> std::fmt::Debug for FutureWriter<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FutureWriter")
            .field("resolved", &self.resolved)
            .finish()
    }
}

impl<T> Drop for FutureWriter<T> {
    fn drop(&mut self) {
        if !self.resolved {
            self.pipe.mark_writer_dropped();
        }
    }
}

impl<T: RpcEncode<core::convert::Infallible>> FutureWriter<T> {
    /// Resolves the remote [`FutureReader`] with `value` and closes the
    /// sub-path.
    pub async fn resolve(mut self, value: T) -> Result<(), RpcError> {
        self.resolved = true;
        if self.pipe.is_closed_for_writer() {
            return Err(RpcError::Cancelled);
        }
        self.pipe
            .wait_until_bound()
            .await
            .map_err(|_| RpcError::Cancelled)?;
        let writer = self.pipe.lock_writer().await.take();
        let Some(mut writer) = writer else {
            return Err(RpcError::Cancelled);
        };
        if writer.is_peer_stopped() {
            return Err(RpcError::Cancelled);
        }

        let call = writer.call_handle();
        let (payload, subpaths) = {
            let mut enc = Encoder::<core::convert::Infallible>::new(Some(&call), None);
            value.rpc_encode(&mut enc)?;
            enc.finish()
        };
        activate_outbound_subpaths(&call, subpaths).await;
        writer
            .send(payload)
            .await
            .map_err(|err| match err.wire_error() {
                Some(wire) => RpcError::Wire(wire.clone()),
                None => RpcError::Cancelled,
            })?;
        writer.close().await?;
        Ok(())
    }

    /// Whether the remote consumer dropped its [`FutureReader`] or cancelled
    /// the invocation.
    pub async fn is_cancelled(&self) -> bool {
        if self.pipe.is_closed_for_writer() {
            return true;
        }
        let guard = self.pipe.lock_writer().await;
        guard.as_ref().is_some_and(|w| w.is_peer_stopped())
    }

    /// Waits until the remote consumer cancels or drops its [`FutureReader`].
    pub async fn cancelled(&self) {
        if self.pipe.wait_until_bound().await.is_err() {
            return;
        }
        let guard = self.pipe.lock_writer().await;
        if let Some(writer) = guard.as_ref() {
            writer.wait_peer_stopped().await;
        }
    }
}

enum FutureReaderState<T> {
    Outbound(Option<Arc<OutboundPipe>>),
    Ready(Option<T>),
    Inbound(Arc<InboundPipe>),
}

/// Consumer half of a single-shot WIT `future<T>`.
///
/// Directly awaits to `Result<T, RpcError>`; dropping before resolution
/// propagates cancellation on the sub-path to the remote [`FutureWriter`].
pub struct FutureReader<T> {
    state: FutureReaderState<T>,
    poll_fut: Option<PollFuture<T>>,
}

impl<T> std::fmt::Debug for FutureReader<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FutureReader").finish()
    }
}

impl<T> Drop for FutureReader<T> {
    fn drop(&mut self) {
        if let FutureReaderState::Outbound(Some(pipe)) = &mut self.state {
            pipe.mark_reader_dropped();
        }
    }
}

impl<T> FutureReader<T> {
    /// Constructs an immediately-resolved `FutureReader` without needing a
    /// separate background task to drive [`FutureWriter`].
    pub fn ready(value: T) -> Self {
        Self {
            state: FutureReaderState::Ready(Some(value)),
            poll_fut: None,
        }
    }
}

impl<T: RpcEncode<core::convert::Infallible>> FutureReader<T> {
    pub(crate) fn encode_into_subpath<R: ResourceEntry>(
        mut self,
        enc: &mut Encoder<'_, R>,
    ) -> Result<(), WireError> {
        let sub_id = enc.alloc_subpath_id()?;
        enc.write_u32(sub_id);
        match &mut self.state {
            FutureReaderState::Outbound(slot) => {
                let pipe = slot.take().ok_or_else(|| WireError::MalformedPayload {
                    context: "FutureReader::encode".to_owned(),
                    detail: "future reader already consumed".to_owned(),
                })?;
                enc.push_outbound_subpath(PendingOutboundSubpath::Live { sub_id, pipe });
            }
            FutureReaderState::Ready(slot) => {
                let value = slot.take().ok_or_else(|| WireError::MalformedPayload {
                    context: "FutureReader::encode".to_owned(),
                    detail: "ready future reader already consumed".to_owned(),
                })?;
                let mut val_enc =
                    Encoder::<core::convert::Infallible>::new(enc.call_handle(), None);
                value.rpc_encode(&mut val_enc)?;
                let (payload, nested) = val_enc.finish();
                for sub in nested {
                    enc.push_outbound_subpath(sub);
                }
                let mut frames = VecDeque::with_capacity(1);
                frames.push_back(payload);
                enc.push_outbound_subpath(PendingOutboundSubpath::Buffered { sub_id, frames });
            }
            FutureReaderState::Inbound(_) => {
                return Err(WireError::MalformedPayload {
                    context: "FutureReader::encode".to_owned(),
                    detail: "inbound future reader must be awaited and re-wrapped explicitly"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }
}

impl<T: RpcDecode<core::convert::Infallible>> FutureReader<T> {
    pub(crate) fn decode_from_subpath<R: ResourceEntry>(
        dec: &mut Decoder<'_, R>,
    ) -> Result<Self, WireError> {
        let sub_id = dec.read_u32()?;
        if sub_id == 0 {
            return Err(WireError::MalformedPayload {
                context: "FutureReader::decode".to_owned(),
                detail: "invalid zero future sub-path id".to_owned(),
            });
        }
        let pipe = Arc::new(InboundPipe::new());
        dec.push_inbound_subpath(PendingInboundSubpath {
            sub_id,
            credit_window: 1,
            pipe: Arc::clone(&pipe),
        });
        Ok(Self {
            state: FutureReaderState::Inbound(pipe),
            poll_fut: None,
        })
    }
}

async fn recv_future_value<T: RpcDecode<core::convert::Infallible>>(
    pipe: Arc<InboundPipe>,
) -> Result<T, RpcError> {
    let mut guard = pipe.lock_reader().await;
    let Some(reader) = guard.as_mut() else {
        return Err(RpcError::FutureDropped);
    };
    let Some(bytes) = reader.recv().await? else {
        return Err(RpcError::FutureDropped);
    };
    // Drain the trailing EOF frame if already queued so `Drop` does not emit an
    // unnecessary stop-reading notification.
    let _ = reader.recv().await;
    let peer = reader.peer();
    let call = reader.call_handle();
    drop(guard);

    let mut dec = Decoder::<core::convert::Infallible>::new(&bytes, peer, None);
    let value = T::rpc_decode(&mut dec)?;
    let subpaths = dec.finish()?;
    activate_inbound_subpaths(&call, subpaths).await?;
    Ok(value)
}

impl<T: RpcDecode<core::convert::Infallible> + Unpin + Send + 'static> Future for FutureReader<T> {
    type Output = Result<T, RpcError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.poll_fut.is_none() {
            match &mut this.state {
                FutureReaderState::Ready(slot) => {
                    return match slot.take() {
                        Some(val) => Poll::Ready(Ok(val)),
                        None => Poll::Ready(Err(RpcError::FutureDropped)),
                    };
                }
                FutureReaderState::Outbound(_) => {
                    return Poll::Ready(Err(RpcError::FutureDropped));
                }
                FutureReaderState::Inbound(pipe) => {
                    let pipe = Arc::clone(pipe);
                    this.poll_fut = Some(Box::pin(recv_future_value::<T>(pipe)));
                }
            }
        }

        let fut = this
            .poll_fut
            .as_mut()
            .expect("future reader poll state must exist");
        fut.as_mut().poll(cx)
    }
}
