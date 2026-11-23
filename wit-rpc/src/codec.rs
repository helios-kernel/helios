use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_lock::Mutex;
use event_listener::{Event, EventListener};
use helios_inspector_protocol::WireError;
use helios_inspector_protocol::mux::{
    CallHandle, InboundCall, OutboundCall, PeerHandle, SubpathReader, SubpathWriter,
};

use crate::error::RpcError;
use crate::resource::{RemoteResource, ResourceEntry, ResourceTable, ResourceTableInner};
use crate::stream::{FutureReader, StreamReader};

/// WIT 0.3 `error-context` payload carried over RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorContext {
    pub debug_message: String,
}

/// Shared non-generic pipe connecting a [`crate::StreamWriter`] or
/// [`crate::FutureWriter`] to the wire sub-path allocated when its reader half
/// is encoded onto an invocation.
pub struct OutboundPipe {
    writer: Mutex<Option<SubpathWriter>>,
    bound: AtomicBool,
    writer_dropped: AtomicBool,
    reader_dropped: AtomicBool,
    event: Event,
}

impl Default for OutboundPipe {
    fn default() -> Self {
        Self::new()
    }
}

impl OutboundPipe {
    pub fn new() -> Self {
        Self {
            writer: Mutex::new(None),
            bound: AtomicBool::new(false),
            writer_dropped: AtomicBool::new(false),
            reader_dropped: AtomicBool::new(false),
            event: Event::new(),
        }
    }

    pub(crate) async fn bind(&self, writer: SubpathWriter) {
        if self.writer_dropped.load(Ordering::Acquire) {
            let _ = writer.close().await;
            return;
        }
        *self.writer.lock().await = Some(writer);
        self.bound.store(true, Ordering::Release);
        self.event.notify(usize::MAX);
    }

    pub(crate) fn mark_writer_dropped(&self) {
        self.writer_dropped.store(true, Ordering::Release);
        if let Some(mut guard) = self.writer.try_lock() {
            // Dropping `SubpathWriter` enqueues `Frame::Close` on the wire.
            let _ = guard.take();
        }
        self.event.notify(usize::MAX);
    }

    pub(crate) fn mark_reader_dropped(&self) {
        self.reader_dropped.store(true, Ordering::Release);
        self.event.notify(usize::MAX);
    }

    pub(crate) fn is_closed_for_writer(&self) -> bool {
        self.reader_dropped.load(Ordering::Acquire)
    }

    pub(crate) async fn wait_until_bound(&self) -> Result<(), RpcError> {
        let mut listener: Option<EventListener> = None;
        std::future::poll_fn(|cx| {
            loop {
                if self.reader_dropped.load(Ordering::Acquire) {
                    return std::task::Poll::Ready(Err(RpcError::StreamClosed));
                }
                if self.bound.load(Ordering::Acquire) {
                    return std::task::Poll::Ready(Ok(()));
                }
                if listener.is_none() {
                    listener = Some(self.event.listen());
                    continue;
                }
                let active = listener
                    .as_mut()
                    .expect("outbound pipe listener must exist while parked");
                match std::pin::Pin::new(active).poll(cx) {
                    std::task::Poll::Ready(()) => {
                        listener = None;
                    }
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                }
            }
        })
        .await
    }

    pub(crate) async fn lock_writer(&self) -> async_lock::MutexGuard<'_, Option<SubpathWriter>> {
        self.writer.lock().await
    }
}

/// Shared non-generic pipe receiving the [`SubpathReader`] opened when a
/// [`StreamReader`] or [`FutureReader`] is decoded from an incoming payload.
pub struct InboundPipe {
    reader: Mutex<Option<SubpathReader>>,
}

impl Default for InboundPipe {
    fn default() -> Self {
        Self::new()
    }
}

impl InboundPipe {
    pub fn new() -> Self {
        Self {
            reader: Mutex::new(None),
        }
    }

    pub(crate) async fn install(&self, reader: SubpathReader) {
        *self.reader.lock().await = Some(reader);
    }

    pub(crate) async fn lock_reader(&self) -> async_lock::MutexGuard<'_, Option<SubpathReader>> {
        self.reader.lock().await
    }
}

/// Deferred outbound sub-path registration collected during synchronous
/// encoding and activated before the enclosing frame is transmitted.
pub enum PendingOutboundSubpath {
    Live {
        sub_id: u32,
        pipe: Arc<OutboundPipe>,
    },
    Buffered {
        sub_id: u32,
        frames: VecDeque<Vec<u8>>,
    },
    Empty {
        sub_id: u32,
    },
}

/// Deferred inbound sub-path registration collected during synchronous
/// decoding and activated before returning decoded values to caller/handler.
pub struct PendingInboundSubpath {
    pub sub_id: u32,
    pub credit_window: u32,
    pub pipe: Arc<InboundPipe>,
}

/// Binary wire encoder carrying connection resource-table access and sub-path
/// allocation for an invocation.
pub struct Encoder<'a, R: ResourceEntry = core::convert::Infallible> {
    bytes: Vec<u8>,
    call: Option<&'a CallHandle>,
    resources: Option<&'a mut ResourceTableInner<R>>,
    outbound_subpaths: Vec<PendingOutboundSubpath>,
}

impl<'a, R: ResourceEntry> Encoder<'a, R> {
    pub fn new(
        call: Option<&'a CallHandle>,
        resources: Option<&'a mut ResourceTableInner<R>>,
    ) -> Self {
        Self {
            bytes: Vec::new(),
            call,
            resources,
            outbound_subpaths: Vec::new(),
        }
    }

    pub fn call_handle(&self) -> Option<&'a CallHandle> {
        self.call
    }

    pub fn resources_mut(&mut self) -> Result<&mut ResourceTableInner<R>, WireError> {
        self.resources
            .as_deref_mut()
            .ok_or_else(|| WireError::MalformedPayload {
                context: "Encoder::resources_mut".to_owned(),
                detail: "resource table is unavailable in this encoding context".to_owned(),
            })
    }

    pub fn alloc_subpath_id(&self) -> Result<u32, WireError> {
        self.call
            .map(CallHandle::alloc_subpath_id)
            .ok_or_else(|| WireError::MalformedPayload {
                context: "Encoder::alloc_subpath_id".to_owned(),
                detail: "stream or future cannot be encoded outside an active invocation"
                    .to_owned(),
            })
    }

    pub fn push_outbound_subpath(&mut self, pending: PendingOutboundSubpath) {
        self.outbound_subpaths.push(pending);
    }

    pub fn finish(self) -> (Vec<u8>, Vec<PendingOutboundSubpath>) {
        (self.bytes, self.outbound_subpaths)
    }

    pub fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub fn write_u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_bytes(&mut self, slice: &[u8]) -> Result<(), WireError> {
        let len = u32::try_from(slice.len()).map_err(|_| WireError::MalformedPayload {
            context: "Encoder::write_bytes".to_owned(),
            detail: "byte slice length exceeds u32::MAX".to_owned(),
        })?;
        self.write_u32(len);
        self.bytes.extend_from_slice(slice);
        Ok(())
    }
}

/// Binary wire decoder with overflow-checked length bounds, connection
/// resource-table access, and sub-path registration.
pub struct Decoder<'a, R: ResourceEntry = core::convert::Infallible> {
    cursor: &'a [u8],
    peer: PeerHandle,
    default_stream_window: u32,
    resources: Option<&'a mut ResourceTableInner<R>>,
    inbound_subpaths: Vec<PendingInboundSubpath>,
}

impl<'a, R: ResourceEntry> Decoder<'a, R> {
    pub fn new(
        bytes: &'a [u8],
        peer: PeerHandle,
        resources: Option<&'a mut ResourceTableInner<R>>,
    ) -> Self {
        let default_stream_window = peer.stream_credit_window();
        Self {
            cursor: bytes,
            peer,
            default_stream_window,
            resources,
            inbound_subpaths: Vec::new(),
        }
    }

    pub fn peer(&self) -> &PeerHandle {
        &self.peer
    }

    pub fn default_stream_window(&self) -> u32 {
        self.default_stream_window
    }

    pub fn resources(&self) -> Result<&ResourceTableInner<R>, WireError> {
        self.resources
            .as_deref()
            .ok_or_else(|| WireError::MalformedPayload {
                context: "Decoder::resources".to_owned(),
                detail: "resource table is unavailable in this decoding context".to_owned(),
            })
    }

    pub fn resources_mut(&mut self) -> Result<&mut ResourceTableInner<R>, WireError> {
        self.resources
            .as_deref_mut()
            .ok_or_else(|| WireError::MalformedPayload {
                context: "Decoder::resources_mut".to_owned(),
                detail: "resource table is unavailable in this decoding context".to_owned(),
            })
    }

    pub fn push_inbound_subpath(&mut self, pending: PendingInboundSubpath) {
        self.inbound_subpaths.push(pending);
    }

    pub fn finish(self) -> Result<Vec<PendingInboundSubpath>, WireError> {
        if !self.cursor.is_empty() {
            return Err(WireError::MalformedPayload {
                context: "Decoder::finish".to_owned(),
                detail: format!("{} trailing unconsumed byte(s)", self.cursor.len()),
            });
        }
        Ok(self.inbound_subpaths)
    }

    pub fn read_exact(
        &mut self,
        count: usize,
        context: &'static str,
    ) -> Result<&'a [u8], WireError> {
        if self.cursor.len() < count {
            return Err(WireError::MalformedPayload {
                context: context.to_owned(),
                detail: format!(
                    "expected {count} byte(s), only {} remaining",
                    self.cursor.len()
                ),
            });
        }
        let (head, tail) = self.cursor.split_at(count);
        self.cursor = tail;
        Ok(head)
    }

    pub fn read_u8(&mut self) -> Result<u8, WireError> {
        Ok(self.read_exact(1, "u8")?[0])
    }

    pub fn read_u16(&mut self) -> Result<u16, WireError> {
        let raw = self.read_exact(2, "u16")?;
        Ok(u16::from_le_bytes([raw[0], raw[1]]))
    }

    pub fn read_u32(&mut self) -> Result<u32, WireError> {
        let raw = self.read_exact(4, "u32")?;
        Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }

    pub fn read_u64(&mut self) -> Result<u64, WireError> {
        let raw = self.read_exact(8, "u64")?;
        Ok(u64::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ]))
    }

    /// Reads a `u32` element count after verifying `count * min_elem_bytes`
    /// cannot exceed remaining input bytes.
    pub fn read_checked_len(
        &mut self,
        field: &'static str,
        min_elem_bytes: usize,
    ) -> Result<usize, WireError> {
        let count = self.read_u32()?;
        let remaining = self.cursor.len();
        let needed = usize::try_from(count)
            .ok()
            .and_then(|n| n.checked_mul(min_elem_bytes))
            .unwrap_or(usize::MAX);
        if needed > remaining {
            return Err(WireError::LengthExceedsInput {
                field,
                len: count,
                needed,
                remaining,
            });
        }
        usize::try_from(count).map_err(|_| WireError::LengthExceedsInput {
            field,
            len: count,
            needed: usize::MAX,
            remaining,
        })
    }

    pub fn read_bytes(&mut self, field: &'static str) -> Result<&'a [u8], WireError> {
        let len = self.read_checked_len(field, 1)?;
        self.read_exact(len, field)
    }
}

/// Activates all outbound sub-paths allocated during an [`Encoder`] pass
/// before the message referencing their IDs hits the wire.
pub async fn activate_outbound_subpaths(call: &CallHandle, subpaths: Vec<PendingOutboundSubpath>) {
    for pending in subpaths {
        match pending {
            PendingOutboundSubpath::Live { sub_id, pipe } => {
                let writer = call.register_writer(sub_id).await;
                pipe.bind(writer).await;
            }
            PendingOutboundSubpath::Buffered { sub_id, frames } => {
                call.register_buffered(sub_id, frames).await;
            }
            PendingOutboundSubpath::Empty { sub_id } => {
                call.register_empty(sub_id);
            }
        }
    }
}

/// Activates all inbound sub-paths decoded during a [`Decoder`] pass and sends
/// their initial credit grants before returning the decoded values.
pub async fn activate_inbound_subpaths(
    call: &CallHandle,
    subpaths: Vec<PendingInboundSubpath>,
) -> Result<(), RpcError> {
    for pending in subpaths {
        let reader = call
            .open_reader(pending.sub_id, pending.credit_window)
            .await?;
        pending.pipe.install(reader).await;
    }
    Ok(())
}

/// Encodes a client-side request value onto `call` and activates any nested
/// outbound `stream<T>` / `future<T>` sub-paths.
pub async fn encode_client_value<T: RpcEncode<core::convert::Infallible>>(
    call: &OutboundCall,
    value: T,
) -> Result<Vec<u8>, RpcError> {
    let handle = call.call_handle();
    let mut encoder = Encoder::<core::convert::Infallible>::new(Some(&handle), None);
    value.rpc_encode(&mut encoder)?;
    let (bytes, subpaths) = encoder.finish();
    activate_outbound_subpaths(&handle, subpaths).await;
    Ok(bytes)
}

/// Decodes a client-side response value from `bytes` on `call` and activates
/// any nested inbound `stream<T>` / `future<T>` sub-paths.
pub async fn decode_client_value<T: RpcDecode<core::convert::Infallible>>(
    call: &OutboundCall,
    bytes: &[u8],
) -> Result<T, RpcError> {
    let handle = call.call_handle();
    let mut decoder = Decoder::<core::convert::Infallible>::new(bytes, call.peer(), None);
    let value = T::rpc_decode(&mut decoder)?;
    let subpaths = decoder.finish()?;
    activate_inbound_subpaths(&handle, subpaths).await?;
    Ok(value)
}

/// Server-side helper to decode request parameters with access to the
/// connection's [`ResourceTable`], releasing the table lock before `.await`.
pub async fn decode_server_request<R, T>(
    call: &InboundCall,
    resources: &ResourceTable<R>,
    bytes: &[u8],
) -> Result<T, WireError>
where
    R: ResourceEntry,
    T: RpcDecode<R>,
{
    let handle = call.call_handle();
    let (value, subpaths) = {
        let mut table = resources.lock().await;
        let mut decoder = Decoder::new(bytes, call.peer().clone(), Some(&mut *table));
        let value = T::rpc_decode(&mut decoder)?;
        let subpaths = decoder.finish()?;
        (value, subpaths)
    };
    for pending in subpaths {
        let reader = handle
            .open_reader(pending.sub_id, pending.credit_window)
            .await
            .map_err(|err| match err.wire_error() {
                Some(wire) => wire.clone(),
                None => WireError::MalformedPayload {
                    context: "open_reader".to_owned(),
                    detail: err.to_string(),
                },
            })?;
        pending.pipe.install(reader).await;
    }
    Ok(value)
}

/// Server-side helper to encode response values with access to the
/// connection's [`ResourceTable`], releasing the table lock before `.await`.
pub async fn encode_server_response<R, T>(
    call: &InboundCall,
    resources: &ResourceTable<R>,
    value: T,
) -> Result<Vec<u8>, WireError>
where
    R: ResourceEntry,
    T: RpcEncode<R>,
{
    let handle = call.call_handle();
    let (bytes, subpaths) = {
        let mut table = resources.lock().await;
        let mut encoder = Encoder::new(Some(&handle), Some(&mut *table));
        value.rpc_encode(&mut encoder)?;
        encoder.finish()
    };
    activate_outbound_subpaths(&handle, subpaths).await;
    Ok(bytes)
}

/// Wire encoding contract for WIT values, handles, streams, and futures.
pub trait RpcEncode<R: ResourceEntry = core::convert::Infallible>: Sized {
    /// Minimum wire size in bytes of one encoded element (used for checked
    /// `Vec<T>` length pre-validation).
    const MIN_WIRE_SIZE: usize = 1;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError>;

    /// Fast-path slice encoding hook overridden by `u8`.
    fn rpc_encode_vec(items: Vec<Self>, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        let len = u32::try_from(items.len()).map_err(|_| WireError::MalformedPayload {
            context: "Vec::rpc_encode".to_owned(),
            detail: "list length exceeds u32::MAX".to_owned(),
        })?;
        enc.write_u32(len);
        for item in items {
            item.rpc_encode(enc)?;
        }
        Ok(())
    }
}

/// Wire decoding contract for WIT values, handles, streams, and futures.
pub trait RpcDecode<R: ResourceEntry = core::convert::Infallible>: Sized {
    const MIN_WIRE_SIZE: usize = 1;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError>;

    fn rpc_decode_vec(dec: &mut Decoder<'_, R>) -> Result<Vec<Self>, WireError> {
        let len = dec.read_checked_len("list", Self::MIN_WIRE_SIZE)?;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(Self::rpc_decode(dec)?);
        }
        Ok(out)
    }
}

impl<R: ResourceEntry> RpcEncode<R> for () {
    const MIN_WIRE_SIZE: usize = 0;

    fn rpc_encode(self, _enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for () {
    const MIN_WIRE_SIZE: usize = 0;

    fn rpc_decode(_dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        Ok(())
    }
}

impl<R: ResourceEntry> RpcEncode<R> for bool {
    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u8(u8::from(self));
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for bool {
    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        match dec.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(WireError::MalformedPayload {
                context: "bool".to_owned(),
                detail: format!("invalid bool discriminant {other}"),
            }),
        }
    }
}

impl<R: ResourceEntry> RpcEncode<R> for u8 {
    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u8(self);
        Ok(())
    }

    fn rpc_encode_vec(items: Vec<Self>, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_bytes(&items)
    }
}

impl<R: ResourceEntry> RpcDecode<R> for u8 {
    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        dec.read_u8()
    }

    fn rpc_decode_vec(dec: &mut Decoder<'_, R>) -> Result<Vec<Self>, WireError> {
        Ok(dec.read_bytes("byte slice")?.to_vec())
    }
}

impl<R: ResourceEntry> RpcEncode<R> for i8 {
    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u8(self.to_le_bytes()[0]);
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for i8 {
    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        Ok(Self::from_le_bytes([dec.read_u8()?]))
    }
}

impl<R: ResourceEntry> RpcEncode<R> for u16 {
    const MIN_WIRE_SIZE: usize = 2;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u16(self);
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for u16 {
    const MIN_WIRE_SIZE: usize = 2;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        dec.read_u16()
    }
}

impl<R: ResourceEntry> RpcEncode<R> for i16 {
    const MIN_WIRE_SIZE: usize = 2;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u16(u16::from_le_bytes(self.to_le_bytes()));
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for i16 {
    const MIN_WIRE_SIZE: usize = 2;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        Ok(Self::from_le_bytes(dec.read_u16()?.to_le_bytes()))
    }
}

impl<R: ResourceEntry> RpcEncode<R> for u32 {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u32(self);
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for u32 {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        dec.read_u32()
    }
}

impl<R: ResourceEntry> RpcEncode<R> for i32 {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u32(u32::from_le_bytes(self.to_le_bytes()));
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for i32 {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        Ok(Self::from_le_bytes(dec.read_u32()?.to_le_bytes()))
    }
}

impl<R: ResourceEntry> RpcEncode<R> for u64 {
    const MIN_WIRE_SIZE: usize = 8;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u64(self);
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for u64 {
    const MIN_WIRE_SIZE: usize = 8;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        dec.read_u64()
    }
}

impl<R: ResourceEntry> RpcEncode<R> for i64 {
    const MIN_WIRE_SIZE: usize = 8;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u64(u64::from_le_bytes(self.to_le_bytes()));
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for i64 {
    const MIN_WIRE_SIZE: usize = 8;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        Ok(Self::from_le_bytes(dec.read_u64()?.to_le_bytes()))
    }
}

impl<R: ResourceEntry> RpcEncode<R> for f32 {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u32(self.to_bits());
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for f32 {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        Ok(Self::from_bits(dec.read_u32()?))
    }
}

impl<R: ResourceEntry> RpcEncode<R> for f64 {
    const MIN_WIRE_SIZE: usize = 8;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u64(self.to_bits());
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for f64 {
    const MIN_WIRE_SIZE: usize = 8;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        Ok(Self::from_bits(dec.read_u64()?))
    }
}

impl<R: ResourceEntry> RpcEncode<R> for char {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u32(u32::from(self));
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for char {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        let raw = dec.read_u32()?;
        Self::from_u32(raw).ok_or_else(|| WireError::MalformedPayload {
            context: "char".to_owned(),
            detail: format!("invalid Unicode scalar value {raw:#x}"),
        })
    }
}

impl<R: ResourceEntry> RpcEncode<R> for String {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_bytes(self.as_bytes())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for String {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        let bytes = dec.read_bytes("string")?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|err| WireError::MalformedPayload {
                context: "string".to_owned(),
                detail: err.to_string(),
            })
    }
}

impl<R: ResourceEntry> RpcEncode<R> for ErrorContext {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        self.debug_message.rpc_encode(enc)
    }
}

impl<R: ResourceEntry> RpcDecode<R> for ErrorContext {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        Ok(Self {
            debug_message: String::rpc_decode(dec)?,
        })
    }
}

impl<R: ResourceEntry, T: RpcEncode<R>> RpcEncode<R> for Vec<T> {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        T::rpc_encode_vec(self, enc)
    }
}

impl<R: ResourceEntry, T: RpcDecode<R>> RpcDecode<R> for Vec<T> {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        T::rpc_decode_vec(dec)
    }
}

impl<R: ResourceEntry, T: RpcEncode<R>, const N: usize> RpcEncode<R> for [T; N] {
    const MIN_WIRE_SIZE: usize = N * T::MIN_WIRE_SIZE;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        for item in self {
            item.rpc_encode(enc)?;
        }
        Ok(())
    }
}

impl<R: ResourceEntry, T: RpcDecode<R>, const N: usize> RpcDecode<R> for [T; N] {
    const MIN_WIRE_SIZE: usize = N * T::MIN_WIRE_SIZE;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        let mut items = Vec::with_capacity(N);
        for _ in 0..N {
            items.push(T::rpc_decode(dec)?);
        }
        items.try_into().map_err(|_| WireError::MalformedPayload {
            context: "fixed-length list".to_owned(),
            detail: "fixed-length array conversion failed".to_owned(),
        })
    }
}

impl<R: ResourceEntry, T: RpcEncode<R>> RpcEncode<R> for Option<T> {
    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        match self {
            None => enc.write_u8(0),
            Some(val) => {
                enc.write_u8(1);
                val.rpc_encode(enc)?;
            }
        }
        Ok(())
    }
}

impl<R: ResourceEntry, T: RpcDecode<R>> RpcDecode<R> for Option<T> {
    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        match dec.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(T::rpc_decode(dec)?)),
            other => Err(WireError::MalformedPayload {
                context: "option".to_owned(),
                detail: format!("invalid option discriminant {other}"),
            }),
        }
    }
}

impl<R: ResourceEntry, O: RpcEncode<R>, E: RpcEncode<R>> RpcEncode<R> for Result<O, E> {
    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        match self {
            Ok(ok) => {
                enc.write_u8(0);
                ok.rpc_encode(enc)
            }
            Err(err) => {
                enc.write_u8(1);
                err.rpc_encode(enc)
            }
        }
    }
}

impl<R: ResourceEntry, O: RpcDecode<R>, E: RpcDecode<R>> RpcDecode<R> for Result<O, E> {
    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        match dec.read_u8()? {
            0 => Ok(Ok(O::rpc_decode(dec)?)),
            1 => Ok(Err(E::rpc_decode(dec)?)),
            other => Err(WireError::MalformedPayload {
                context: "result".to_owned(),
                detail: format!("invalid result discriminant {other}"),
            }),
        }
    }
}

impl<R: ResourceEntry> RpcEncode<R> for RemoteResource {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u32(self.into_raw_handle());
        Ok(())
    }
}

impl<R: ResourceEntry> RpcEncode<R> for &RemoteResource {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u32(self.handle_id());
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for RemoteResource {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        let handle = dec.read_u32()?;
        if handle == 0 {
            return Err(WireError::InvalidResourceHandle { handle });
        }
        Ok(Self::new(dec.peer().clone(), handle))
    }
}

impl<R: ResourceEntry, T: RpcEncode<core::convert::Infallible>> RpcEncode<R> for StreamReader<T> {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        self.encode_into_subpath(enc)
    }
}

impl<R: ResourceEntry, T: RpcDecode<core::convert::Infallible>> RpcDecode<R> for StreamReader<T> {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        Self::decode_from_subpath(dec)
    }
}

impl<R: ResourceEntry, T: RpcEncode<core::convert::Infallible>> RpcEncode<R> for FutureReader<T> {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        self.encode_into_subpath(enc)
    }
}

impl<R: ResourceEntry, T: RpcDecode<core::convert::Infallible>> RpcDecode<R> for FutureReader<T> {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        Self::decode_from_subpath(dec)
    }
}

macro_rules! impl_tuple_codec {
    ($(($($idx:tt : $T:ident),+)),+ $(,)?) => {
        $(
            impl<R: ResourceEntry, $($T: RpcEncode<R>),+> RpcEncode<R> for ($($T,)+) {
                const MIN_WIRE_SIZE: usize = 0 $(+ <$T as RpcEncode<R>>::MIN_WIRE_SIZE)+;

                fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
                    $(self.$idx.rpc_encode(enc)?;)+
                    Ok(())
                }
            }

            impl<R: ResourceEntry, $($T: RpcDecode<R>),+> RpcDecode<R> for ($($T,)+) {
                const MIN_WIRE_SIZE: usize = 0 $(+ <$T as RpcDecode<R>>::MIN_WIRE_SIZE)+;

                fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
                    Ok(($(<$T as RpcDecode<R>>::rpc_decode(dec)?,)+))
                }
            }
        )+
    };
}

impl_tuple_codec!(
    (0: T0),
    (0: T0, 1: T1),
    (0: T0, 1: T1, 2: T2),
    (0: T0, 1: T1, 2: T2, 3: T3),
    (0: T0, 1: T1, 2: T2, 3: T3, 4: T4),
    (0: T0, 1: T1, 2: T2, 3: T3, 4: T4, 5: T5),
    (0: T0, 1: T1, 2: T2, 3: T3, 4: T4, 5: T5, 6: T6),
    (0: T0, 1: T1, 2: T2, 3: T3, 4: T4, 5: T5, 6: T6, 7: T7),
    (0: T0, 1: T1, 2: T2, 3: T3, 4: T4, 5: T5, 6: T6, 7: T7, 8: T8),
    (0: T0, 1: T1, 2: T2, 3: T3, 4: T4, 5: T5, 6: T6, 7: T7, 8: T8, 9: T9),
);
