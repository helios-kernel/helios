//! The exchange's `wasi:http` request as the `http` request zenwave sends.
//!
//! Method, target and fields are converted here, and the body is adapted: its
//! frames are pulled from the caller's stream as the client writes them. The
//! verdict on the body, which the caller waits on, is settled by
//! [`Verdict::settle`]: from the caller's stream when it ends, or from the
//! exchange when it fails first. Framing is the client's: the caller's own
//! `content-length` decides it, and a body that differs from it fails the
//! exchange.

use std::future::Future;
use std::pin::pin;
use std::string::String;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::vec::Vec;

use futures_channel::oneshot;
use futures_lite::{future, stream};
use helios_api::bindings::wit_future;
use helios_api::http::types::{self, Method};
use helios_api::http::{ErrorCode, Fields, Scheme};
use helios_api::stream_closed;
use helios_api::wit_bindgen::rt::async_support::{
    FutureReader, FutureWriter, StreamReader, StreamResult,
};
use http::header::{HeaderMap, HeaderName, HeaderValue};
use thiserror::Error;
use zenwave::{Body, BodyError, BodyFrame};

/// Bytes pulled from the caller's body stream in one step.
const BODY_CHUNK_BYTES: usize = 64 * 1024;

/// What happened to the caller's request body, shared between the body the
/// client reads and the code that maps the client's errors.
#[derive(Debug, Default)]
pub struct BodyOutcome {
    sent: AtomicU64,
    failure: OnceLock<ErrorCode>,
}

impl BodyOutcome {
    /// Bytes of the body handed to the client so far.
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    /// The code the caller's own body failed with, if it did.
    pub fn failure(&self) -> Option<ErrorCode> {
        self.failure.get().cloned()
    }

    #[cfg(test)]
    pub fn record_sent(&self, bytes: u64) {
        self.sent.store(bytes, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub fn record_failure(&self, code: ErrorCode) {
        let _ = self.failure.set(code);
    }
}

/// The caller's body stream reported a failure instead of its trailers.
#[derive(Debug, Error)]
#[error("the request body failed: {0:?}")]
struct BodyFailed(ErrorCode);

/// The caller's wait for the verdict on its request body, and the report of
/// how the body stream ended.
pub struct Verdict {
    writer: FutureWriter<Result<(), ErrorCode>>,
    body: oneshot::Receiver<Result<(), ErrorCode>>,
}

/// Which of the two reports a verdict waits on came first.
enum First {
    Body(Result<Result<(), ErrorCode>, oneshot::Canceled>),
    Exchange(Result<ErrorCode, oneshot::Canceled>),
}

impl Verdict {
    /// Settle the caller's verdict. The caller's stream ending decides it;
    /// an exchange that fails first decides it with its own code, since the
    /// client then stops reading the body. `exchange` carries that code and
    /// is dropped unsent when the exchange succeeds; a body the client
    /// dropped after a successful exchange was never fully sent.
    pub async fn settle(self, mut exchange: oneshot::Receiver<ErrorCode>) {
        let Self {
            writer,
            body: mut ended,
        } = self;
        let first = future::or(async { First::Body((&mut ended).await) }, async {
            First::Exchange((&mut exchange).await)
        })
        .await;
        let verdict = match first {
            First::Body(Ok(verdict)) => verdict,
            First::Body(Err(oneshot::Canceled)) => {
                Err(exchange.await.unwrap_or(ErrorCode::ConnectionTerminated))
            }
            First::Exchange(Ok(code)) => Err(code),
            First::Exchange(Err(oneshot::Canceled)) => {
                ended.await.unwrap_or(Err(ErrorCode::ConnectionTerminated))
            }
        };
        // An error here means the caller dropped its end and wants no verdict.
        let _ = writer.write(verdict).await;
    }
}

/// Turn a `wasi:http` request into the request the client sends, the
/// outcome of its body and the caller's verdict on it.
///
/// The request is consumed. The scheme is returned beside it because the
/// client takes the request out of its slot.
///
/// `wasi:http/types.request.consume-body` always returns a content stream even
/// when the caller constructed the request with `contents: none`. Probing that
/// stream without blocking distinguishes an already-empty request (which must
/// use [`Body::empty`] so HTTP/1.1 does not add `Transfer-Encoding: chunked`
/// and a trailing `0\r\n\r\n` to bodiless requests such as `GET`) from a
/// streaming upload whose bytes arrive asynchronously.
pub async fn into_http(
    request: types::Request,
) -> Result<(http::Request<Body>, Scheme, Arc<BodyOutcome>, Verdict), ErrorCode> {
    let method = convert_method(&request.get_method())?;
    let scheme = request.get_scheme().unwrap_or(Scheme::Http);
    let scheme_text = match &scheme {
        Scheme::Http => "http",
        Scheme::Https => "https",
        Scheme::Other(_) => return Err(ErrorCode::HttpRequestUriInvalid),
    };
    let authority = request
        .get_authority()
        .ok_or(ErrorCode::HttpRequestUriInvalid)?;
    let target = request
        .get_path_with_query()
        .unwrap_or_else(|| String::from("/"));
    let uri = http::Uri::builder()
        .scheme(scheme_text)
        .authority(authority)
        .path_and_query(target)
        .build()
        .map_err(|_| ErrorCode::HttpRequestUriInvalid)?;
    let headers = convert_fields(request.get_headers().copy_all())?;

    // `settle` always writes; the default is only what a caller sees if the
    // plugin's task is torn down first, and nothing was then sent in full.
    let (writer, verdict_reader) =
        wit_future::new::<Result<(), ErrorCode>>(|| Err(ErrorCode::ConnectionTerminated));
    let (contents, trailers) = types::Request::consume_body(request, verdict_reader);
    let outcome = Arc::new(BodyOutcome::default());
    let (end, ended) = oneshot::channel();
    let source = WasiBodySource { contents, trailers };
    let body = match build_body(source, end, Arc::clone(&outcome)).await {
        Ok(body) => body,
        Err(code) => {
            let _ = writer.write(Err(code.clone())).await;
            return Err(code);
        }
    };

    let mut http = http::Request::new(body);
    *http.method_mut() = method;
    *http.uri_mut() = uri;
    *http.headers_mut() = headers;
    let verdict = Verdict {
        writer,
        body: ended,
    };
    Ok((http, scheme, outcome, verdict))
}

fn convert_method(method: &Method) -> Result<http::Method, ErrorCode> {
    Ok(match method {
        Method::Get => http::Method::GET,
        Method::Head => http::Method::HEAD,
        Method::Post => http::Method::POST,
        Method::Put => http::Method::PUT,
        Method::Delete => http::Method::DELETE,
        Method::Connect => http::Method::CONNECT,
        Method::Options => http::Method::OPTIONS,
        Method::Trace => http::Method::TRACE,
        Method::Patch => http::Method::PATCH,
        Method::Other(other) => http::Method::from_bytes(other.as_bytes())
            .map_err(|_| ErrorCode::HttpRequestMethodInvalid)?,
    })
}

/// The caller's fields as a header map. `wasi:http` has validated them, so a
/// name or value that does not convert is a protocol violation.
fn convert_fields(fields: Vec<(String, Vec<u8>)>) -> Result<HeaderMap, ErrorCode> {
    let mut map = HeaderMap::with_capacity(fields.len());
    for (name, value) in fields {
        map.append(
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| ErrorCode::HttpProtocolError)?,
            HeaderValue::from_bytes(&value).map_err(|_| ErrorCode::HttpProtocolError)?,
        );
    }
    Ok(map)
}

/// Outcome of a non-blocking probe on a request's content stream.
enum InitialContents {
    /// The stream is already closed with zero bytes.
    Closed,
    /// A non-empty first chunk was already queued.
    Chunk(Vec<u8>),
    /// The stream is still open with no bytes queued yet.
    Pending,
}

/// Source of a request's content stream and trailing headers, abstracted so the
/// body-framing state machine can be tested on the host without wasm32 hostcalls.
trait RequestBodySource: Send + Sync + 'static {
    fn probe(&mut self) -> impl Future<Output = InitialContents> + Send + Sync + '_;
    fn next_chunk(&mut self) -> impl Future<Output = Option<Vec<u8>>> + Send + Sync + '_;
    fn trailers(self) -> impl Future<Output = Result<Option<HeaderMap>, ErrorCode>> + Send + Sync;
}

struct WasiBodySource {
    contents: StreamReader<u8>,
    trailers: FutureReader<Result<Option<Fields>, ErrorCode>>,
}

impl RequestBodySource for WasiBodySource {
    async fn probe(&mut self) -> InitialContents {
        let mut read = pin!(self.contents.read(Vec::with_capacity(BODY_CHUNK_BYTES)));
        let (result, chunk) = match future::poll_once(read.as_mut()).await {
            Some(done) => done,
            None => read.as_mut().cancel(),
        };
        if !chunk.is_empty() {
            return InitialContents::Chunk(chunk);
        }
        match result {
            StreamResult::Dropped => InitialContents::Closed,
            StreamResult::Cancelled | StreamResult::Complete(_) => InitialContents::Pending,
        }
    }

    async fn next_chunk(&mut self) -> Option<Vec<u8>> {
        loop {
            let (result, chunk) = self
                .contents
                .read(Vec::with_capacity(BODY_CHUNK_BYTES))
                .await;
            if !chunk.is_empty() {
                return Some(chunk);
            }
            if stream_closed(result) {
                return None;
            }
        }
    }

    async fn trailers(self) -> Result<Option<HeaderMap>, ErrorCode> {
        match self.trailers.await {
            Ok(Some(fields)) => convert_fields(fields.copy_all()).map(Some),
            Ok(None) => Ok(None),
            Err(code) => Err(code),
        }
    }
}

/// Build the `zenwave::Body` for a request from `source`.
///
/// An already-closed empty stream with no trailers yields [`Body::empty`]
/// (`len() == Some(0)`), keeping `GET`/`HEAD`/`DELETE` bodiless on the wire
/// and framing empty `POST`/`PUT`/`PATCH` with `Content-Length: 0`. Any stream
/// that has data, is still pending, or carries non-empty trailers stays a
/// streaming [`Body::from_frames`].
async fn build_body<S: RequestBodySource>(
    mut source: S,
    end: oneshot::Sender<Result<(), ErrorCode>>,
    outcome: Arc<BodyOutcome>,
) -> Result<Body, ErrorCode> {
    match source.probe().await {
        InitialContents::Closed => match source.trailers().await {
            Ok(Some(map)) if !map.is_empty() => {
                let _ = end.send(Ok(()));
                Ok(Body::from_frames(stream::once(Ok::<BodyFrame, BodyError>(
                    BodyFrame::Trailers(map),
                ))))
            }
            Ok(_) => {
                let _ = end.send(Ok(()));
                Ok(Body::empty())
            }
            Err(code) => {
                let _ = outcome.failure.set(code.clone());
                let _ = end.send(Err(code.clone()));
                Err(code)
            }
        },
        InitialContents::Chunk(chunk) => {
            outcome
                .sent
                .fetch_add(chunk.len() as u64, Ordering::Relaxed);
            Ok(Body::from_frames(body_frames(
                Some(chunk),
                source,
                end,
                outcome,
            )))
        }
        InitialContents::Pending => Ok(Body::from_frames(body_frames(None, source, end, outcome))),
    }
}

/// What the stream of body frames is driven by.
struct BodyState<S> {
    first_chunk: Option<Vec<u8>>,
    source: S,
    end: oneshot::Sender<Result<(), ErrorCode>>,
    outcome: Arc<BodyOutcome>,
}

/// The caller's body as the frames the client writes: data as it arrives,
/// then the trailers the caller ends with.
///
/// When the stream ends, how it ended is reported through `end`, whether or
/// not the client has written all of it yet: the verdict is about the
/// caller's own stream. A body the client drops before then reports nothing.
fn body_frames<S: RequestBodySource>(
    first_chunk: Option<Vec<u8>>,
    source: S,
    end: oneshot::Sender<Result<(), ErrorCode>>,
    outcome: Arc<BodyOutcome>,
) -> impl stream::Stream<Item = Result<BodyFrame, BodyError>> + Send + Sync + 'static {
    let state = BodyState {
        first_chunk,
        source,
        end,
        outcome,
    };
    stream::unfold(Some(state), |state| async move {
        let mut state = state?;
        if let Some(chunk) = state.first_chunk.take() {
            return Some((Ok(BodyFrame::Data(chunk.into())), Some(state)));
        }
        if let Some(chunk) = state.source.next_chunk().await {
            state
                .outcome
                .sent
                .fetch_add(chunk.len() as u64, Ordering::Relaxed);
            return Some((Ok(BodyFrame::Data(chunk.into())), Some(state)));
        }
        // The trailers future resolves only after the body stream closes,
        // and it is also how the caller reports that its body could not
        // be produced.
        let trailers = state.source.trailers().await;
        let verdict = trailers.as_ref().map(|_| ()).map_err(Clone::clone);
        // An error here means the verdict was already settled by a
        // failed exchange.
        let _ = state.end.send(verdict);
        match trailers {
            Ok(Some(map)) if !map.is_empty() => Some((Ok(BodyFrame::Trailers(map)), None)),
            Ok(_) => None,
            Err(code) => {
                let _ = state.outcome.failure.set(code.clone());
                Some((Err(BodyError::Other(Box::new(BodyFailed(code)))), None))
            }
        }
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::borrow::Borrow;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::fs::File;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::num::NonZeroU16;
    #[cfg(unix)]
    use std::path::Path;
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};
    use std::time::Instant;

    use executor_core::LocalExecutor;
    use executor_core::async_task::{AsyncTask, Runnable, spawn_local};
    use futures_channel::{mpsc, oneshot};
    use futures_lite::future::block_on;
    use futures_lite::stream::{self, Stream, StreamExt};
    use helios_api::http::ErrorCode;
    use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
    #[cfg(unix)]
    use http_kit_io::DialUnix;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    use http_kit_io::splice::{FilledPipe, Pipe, Spliced};
    use http_kit_io::{
        Answer, BufResult, Datagram, DatagramSocket, Dial, IoBuf, IoBufMut, IoVectoredBuf, NoBuf,
        Read, ReadAhead, ReadOwned, Received, RecvMeta, Resolve, SendFile, SpliceRead, SpliceWrite,
        Split, TcpOptions, Timer, Write,
    };
    use zenwave::backend::NativeBackend;
    use zenwave::dns::{HttpsRecord, ResolveHttps};
    use zenwave::transport::Proxy;
    use zenwave::{BodyFrame, Endpoint, ResolveError, Transport};

    use super::{BodyOutcome, InitialContents, RequestBodySource, build_body};

    struct ScriptedSource {
        probe_result: Option<InitialContents>,
        chunks: VecDeque<Vec<u8>>,
        trailers: Result<Option<HeaderMap>, ErrorCode>,
    }

    impl RequestBodySource for ScriptedSource {
        async fn probe(&mut self) -> InitialContents {
            self.probe_result
                .take()
                .expect("probe should be called once")
        }

        async fn next_chunk(&mut self) -> Option<Vec<u8>> {
            self.chunks.pop_front()
        }

        async fn trailers(self) -> Result<Option<HeaderMap>, ErrorCode> {
            self.trailers
        }
    }

    #[test]
    fn closed_empty_stream_without_trailers_produces_known_empty_body() {
        let outcome = Arc::new(BodyOutcome::default());
        let (end, mut ended) = oneshot::channel();
        let source = ScriptedSource {
            probe_result: Some(InitialContents::Closed),
            chunks: VecDeque::new(),
            trailers: Ok(None),
        };
        let body = block_on(build_body(source, end, Arc::clone(&outcome)))
            .expect("empty closed stream must succeed");
        assert_eq!(body.len(), Some(0));
        assert_eq!(body.is_empty(), Some(true));
        assert_eq!(outcome.sent(), 0);
        assert!(matches!(ended.try_recv(), Ok(Some(Ok(())))));
    }

    #[test]
    fn closed_empty_stream_with_trailers_stays_streaming_with_trailers_frame() {
        let outcome = Arc::new(BodyOutcome::default());
        let (end, mut ended) = oneshot::channel();
        let mut trailers = HeaderMap::new();
        trailers.insert(
            HeaderName::from_static("x-checksum"),
            HeaderValue::from_static("ok"),
        );
        let source = ScriptedSource {
            probe_result: Some(InitialContents::Closed),
            chunks: VecDeque::new(),
            trailers: Ok(Some(trailers)),
        };
        let mut body = block_on(build_body(source, end, Arc::clone(&outcome)))
            .expect("empty stream with trailers must succeed");
        assert_eq!(body.len(), None);
        let frame = block_on(body.next())
            .expect("trailer frame expected")
            .expect("trailer frame ok");
        match frame {
            BodyFrame::Trailers(map) => {
                assert_eq!(map.get("x-checksum"), Some(&HeaderValue::from_static("ok")));
            }
            other => panic!("expected trailers frame, got {other:?}"),
        }
        assert!(block_on(body.next()).is_none());
        assert!(matches!(ended.try_recv(), Ok(Some(Ok(())))));
    }

    #[test]
    fn closed_empty_stream_with_trailer_error_fails_fast_and_settles_verdict() {
        let outcome = Arc::new(BodyOutcome::default());
        let (end, mut ended) = oneshot::channel();
        let source = ScriptedSource {
            probe_result: Some(InitialContents::Closed),
            chunks: VecDeque::new(),
            trailers: Err(ErrorCode::HttpRequestBodySize(Some(0))),
        };
        let err = block_on(build_body(source, end, Arc::clone(&outcome)))
            .expect_err("trailer error must propagate");
        assert!(matches!(err, ErrorCode::HttpRequestBodySize(Some(0))));
        assert!(matches!(
            outcome.failure(),
            Some(ErrorCode::HttpRequestBodySize(Some(0)))
        ));
        assert!(matches!(
            ended.try_recv(),
            Ok(Some(Err(ErrorCode::HttpRequestBodySize(Some(0)))))
        ));
    }

    #[test]
    fn chunked_and_pending_streams_preserve_order_and_byte_counts() {
        for initial in [
            InitialContents::Chunk(b"hello ".to_vec()),
            InitialContents::Pending,
        ] {
            let expected: &[u8] = match &initial {
                InitialContents::Chunk(_) => b"hello world",
                InitialContents::Pending => b"world",
                InitialContents::Closed => unreachable!(),
            };
            let outcome = Arc::new(BodyOutcome::default());
            let (end, mut ended) = oneshot::channel();
            let source = ScriptedSource {
                probe_result: Some(initial),
                chunks: VecDeque::from([b"world".to_vec()]),
                trailers: Ok(None),
            };
            let mut body = block_on(build_body(source, end, Arc::clone(&outcome)))
                .expect("streaming body must build");
            assert_eq!(body.len(), None);
            let mut collected = Vec::new();
            while let Some(frame) = block_on(body.next()) {
                match frame.expect("frame ok") {
                    BodyFrame::Data(bytes) => collected.extend_from_slice(&bytes),
                    other => panic!("unexpected frame: {other:?}"),
                }
            }
            assert_eq!(collected, expected);
            assert_eq!(outcome.sent(), expected.len() as u64);
            assert!(matches!(ended.try_recv(), Ok(Some(Ok(())))));
        }
    }

    struct LocalScheduler {
        sender: mpsc::UnboundedSender<Runnable>,
        receiver: RefCell<mpsc::UnboundedReceiver<Runnable>>,
    }

    impl LocalScheduler {
        fn new() -> Rc<Self> {
            let (sender, receiver) = mpsc::unbounded();
            Rc::new(Self {
                sender,
                receiver: RefCell::new(receiver),
            })
        }

        fn drive<F: std::future::Future>(&self, future: F) -> F::Output {
            let mut future = std::pin::pin!(future);
            let waker = Waker::noop();
            let mut cx = Context::from_waker(waker);
            loop {
                if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
                    return output;
                }
                let mut progressed = false;
                while let Ok(runnable) = self.receiver.borrow_mut().try_recv() {
                    runnable.run();
                    progressed = true;
                }
                assert!(progressed, "local executor stalled with unfinished future");
            }
        }
    }

    #[derive(Clone)]
    struct TestExec(Rc<LocalScheduler>);

    impl LocalExecutor for TestExec {
        type Task<T: 'static> = AsyncTask<T>;

        fn spawn_local<Fut>(&self, future: Fut) -> Self::Task<Fut::Output>
        where
            Fut: std::future::Future + 'static,
        {
            let sender = self.0.sender.clone();
            let (runnable, task) = spawn_local(future, move |runnable| {
                let _ = sender.unbounded_send(runnable);
            });
            runnable.schedule();
            task
        }
    }

    #[derive(Clone)]
    struct CaptureState {
        written: Arc<Mutex<Vec<u8>>>,
        response: Arc<Vec<u8>>,
    }

    struct CaptureRead {
        response: Arc<Vec<u8>>,
        pos: usize,
    }

    struct CaptureWrite {
        written: Arc<Mutex<Vec<u8>>>,
    }

    struct CaptureConn {
        read: CaptureRead,
        write: CaptureWrite,
    }

    impl Split for CaptureConn {
        type ReadHalf = CaptureRead;
        type WriteHalf = CaptureWrite;

        fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
            (self.read, self.write)
        }
    }

    impl Read for CaptureRead {
        async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
            let remaining = &self.response[self.pos..];
            let dst = buf.as_uninit();
            let n = remaining.len().min(dst.len());
            for (slot, byte) in dst[..n].iter_mut().zip(&remaining[..n]) {
                slot.write(*byte);
            }
            // SAFETY: the first `n` bytes of `buf` were initialized above.
            unsafe { buf.set_len(n) };
            self.pos += n;
            BufResult(Ok(n), buf)
        }
    }

    impl ReadOwned for CaptureRead {
        type Buf = NoBuf;

        async fn read_owned(&mut self) -> io::Result<Received<NoBuf>> {
            if self.pos >= self.response.len() {
                return Ok(Received::End);
            }
            let bytes = self.response[self.pos..].to_vec();
            self.pos = self.response.len();
            Ok(Received::Owned(bytes.into()))
        }
    }

    impl ReadAhead for CaptureRead {
        async fn stop_read_ahead(&mut self) -> Vec<u8> {
            Vec::new()
        }
    }

    impl SpliceRead for CaptureRead {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        fn can_splice(&self) -> bool {
            false
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        async fn splice_to_pipe(
            &mut self,
            pipe: Pipe,
            _max: usize,
        ) -> Result<Spliced, (io::Error, Pipe)> {
            Err((io::Error::other("unsplicable"), pipe))
        }
    }

    impl Write for CaptureWrite {
        async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
            let bytes = buf.as_init();
            self.written.lock().unwrap().extend_from_slice(bytes);
            BufResult(Ok(bytes.len()), buf)
        }

        async fn write_vectored<B: IoVectoredBuf>(&mut self, buf: B) -> BufResult<usize, B> {
            let mut total = 0;
            let mut guard = self.written.lock().unwrap();
            for slice in buf.iter_slice() {
                guard.extend_from_slice(slice);
                total += slice.len();
            }
            BufResult(Ok(total), buf)
        }

        async fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }

        async fn shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl SendFile for CaptureWrite {
        async fn send_file<F: Borrow<File> + 'static>(
            &mut self,
            file: F,
            _offset: u64,
            _len: usize,
        ) -> BufResult<usize, F> {
            BufResult(Err(io::Error::other("unsupported")), file)
        }
    }

    impl SpliceWrite for CaptureWrite {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        fn can_splice(&self) -> bool {
            false
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        async fn splice_from_pipe(&mut self, _filled: FilledPipe) -> io::Result<Pipe> {
            Err(io::Error::other("unsplicable"))
        }
    }

    impl Read for CaptureConn {
        fn read<B: IoBufMut>(
            &mut self,
            buf: B,
        ) -> impl std::future::Future<Output = BufResult<usize, B>> {
            self.read.read(buf)
        }
    }

    impl ReadOwned for CaptureConn {
        type Buf = NoBuf;

        fn read_owned(&mut self) -> impl std::future::Future<Output = io::Result<Received<NoBuf>>> {
            self.read.read_owned()
        }
    }

    impl ReadAhead for CaptureConn {
        fn stop_read_ahead(&mut self) -> impl std::future::Future<Output = Vec<u8>> {
            self.read.stop_read_ahead()
        }
    }

    impl SpliceRead for CaptureConn {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        fn can_splice(&self) -> bool {
            false
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        fn splice_to_pipe(
            &mut self,
            pipe: Pipe,
            max: usize,
        ) -> impl std::future::Future<Output = Result<Spliced, (io::Error, Pipe)>> {
            self.read.splice_to_pipe(pipe, max)
        }
    }

    impl Write for CaptureConn {
        fn write<B: IoBuf>(
            &mut self,
            buf: B,
        ) -> impl std::future::Future<Output = BufResult<usize, B>> {
            self.write.write(buf)
        }

        fn write_vectored<B: IoVectoredBuf>(
            &mut self,
            buf: B,
        ) -> impl std::future::Future<Output = BufResult<usize, B>> {
            self.write.write_vectored(buf)
        }

        fn flush(&mut self) -> impl std::future::Future<Output = io::Result<()>> {
            self.write.flush()
        }

        fn shutdown(&mut self) -> impl std::future::Future<Output = io::Result<()>> {
            self.write.shutdown()
        }
    }

    impl SendFile for CaptureConn {
        fn send_file<F: Borrow<File> + 'static>(
            &mut self,
            file: F,
            offset: u64,
            len: usize,
        ) -> impl std::future::Future<Output = BufResult<usize, F>> {
            self.write.send_file(file, offset, len)
        }
    }

    impl SpliceWrite for CaptureConn {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        fn can_splice(&self) -> bool {
            false
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        fn splice_from_pipe(
            &mut self,
            filled: FilledPipe,
        ) -> impl std::future::Future<Output = io::Result<Pipe>> {
            self.write.splice_from_pipe(filled)
        }
    }

    impl TcpOptions for CaptureConn {
        fn set_nodelay(&self, _nodelay: bool) -> io::Result<()> {
            Ok(())
        }

        fn nodelay(&self) -> io::Result<bool> {
            Ok(true)
        }
    }

    struct UnusedUdp;

    impl DatagramSocket for UnusedUdp {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Err(io::Error::other("unused"))
        }
        fn max_send_segments(&self) -> usize {
            1
        }
        async fn send_from<B: IoBuf>(
            &self,
            buf: B,
            _target: SocketAddr,
            _source: Option<IpAddr>,
        ) -> BufResult<usize, B> {
            BufResult(Err(io::Error::other("unused")), buf)
        }
        async fn send_segments_from<B: IoBuf>(
            &self,
            buf: B,
            _segment_size: NonZeroU16,
            _target: SocketAddr,
            _source: Option<IpAddr>,
        ) -> BufResult<usize, B> {
            BufResult(Err(io::Error::other("unused")), buf)
        }
        async fn recv_from<B: IoBufMut>(&self, buf: B) -> BufResult<RecvMeta, B> {
            BufResult(Err(io::Error::other("unused")), buf)
        }
    }

    impl Dial for CaptureState {
        type Connection = CaptureConn;

        async fn connect(&self, _addr: SocketAddr) -> io::Result<CaptureConn> {
            Ok(CaptureConn {
                read: CaptureRead {
                    response: Arc::clone(&self.response),
                    pos: 0,
                },
                write: CaptureWrite {
                    written: Arc::clone(&self.written),
                },
            })
        }
    }

    #[cfg(unix)]
    impl DialUnix for CaptureState {
        type UnixConnection = CaptureConn;

        async fn connect_unix(&self, _path: &Path) -> io::Result<CaptureConn> {
            Err(io::Error::other("unsupported"))
        }
    }

    impl Datagram for CaptureState {
        type UdpSocket = UnusedUdp;

        async fn bind_udp(&self, _addr: SocketAddr) -> io::Result<UnusedUdp> {
            Err(io::Error::other("unused"))
        }
    }

    impl Resolve for CaptureState {
        fn lookup(&self, _host: &str) -> impl Stream<Item = Answer> {
            stream::once(Answer::Ranked(Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])))
        }
    }

    impl ResolveHttps for CaptureState {
        async fn https_record(
            &self,
            _host: &str,
            _port: u16,
        ) -> Result<Option<HttpsRecord>, ResolveError> {
            Ok(None)
        }
    }

    impl Timer for CaptureState {
        async fn sleep_until(&self, _deadline: Instant) {
            std::future::pending::<()>().await;
        }
    }

    fn capture_wire_request(method: Method, uri: &str) -> String {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls_pure::provider().install_default();
        }
        let scheduler = LocalScheduler::new();
        let exec = TestExec(Rc::clone(&scheduler));
        let capture = CaptureState {
            written: Arc::new(Mutex::new(Vec::new())),
            response: Arc::new(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()),
        };
        let transport = Transport::builder()
            .proxy(Proxy::none())
            .build()
            .expect("transport");
        let mut backend =
            NativeBackend::on_current_thread(transport, capture.clone(), capture.clone(), &exec);

        scheduler.drive(async {
            let outcome = Arc::new(BodyOutcome::default());
            let (end, _ended) = oneshot::channel();
            let source = ScriptedSource {
                probe_result: Some(InitialContents::Closed),
                chunks: VecDeque::new(),
                trailers: Ok(None),
            };
            let body = build_body(source, end, outcome)
                .await
                .expect("build empty body");
            let mut request = Request::builder()
                .method(method)
                .uri(uri)
                .header("user-agent", "helios-curl/0.1")
                .body(body)
                .expect("build request");

            let response = backend
                .respond(&mut request)
                .await
                .expect("request succeeds");
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = response.into_body().into_bytes().await.expect("read body");
            assert_eq!(&bytes[..], b"ok");
        });

        String::from_utf8(capture.written.lock().unwrap().clone())
            .expect("HTTP/1.1 request is ASCII")
    }

    #[test]
    fn get_with_empty_body_sends_no_chunked_encoding_or_trailing_bytes() {
        let wire = capture_wire_request(Method::GET, "http://127.0.0.1:8080/payload-64m.bin");
        let lower = wire.to_ascii_lowercase();
        assert!(
            !lower.contains("transfer-encoding"),
            "bodiless GET must not send Transfer-Encoding: {wire:?}"
        );
        assert!(
            !lower.contains("content-length"),
            "bodiless GET must not synthesize Content-Length: {wire:?}"
        );
        assert!(
            wire.ends_with("\r\n\r\n"),
            "bodiless GET must end at header terminator with zero body bytes: {wire:?}"
        );
    }

    #[test]
    fn post_with_empty_body_sends_content_length_zero_without_chunked_encoding() {
        let wire = capture_wire_request(Method::POST, "http://127.0.0.1:8080/submit");
        let lower = wire.to_ascii_lowercase();
        assert!(
            !lower.contains("transfer-encoding"),
            "empty POST must not send Transfer-Encoding: {wire:?}"
        );
        assert!(
            lower.contains("content-length: 0\r\n"),
            "empty POST must announce Content-Length: 0: {wire:?}"
        );
        assert!(
            wire.ends_with("\r\n\r\n"),
            "empty POST must end at header terminator with zero body bytes: {wire:?}"
        );
    }
}
