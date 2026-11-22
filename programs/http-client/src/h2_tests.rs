//! End-to-end HTTP/2 ALPN, multiplexing, and error-mapping tests over
//! `zenwave`'s `NativeBackend` with `native-http2`, driven on a local
//! single-threaded executor and in-memory duplex transport.

use std::borrow::Borrow;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::fs::File;
use std::future::{Future, poll_fn};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::pin::pin;
use std::process::Command;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use executor_core::async_task::{AsyncTask, Runnable, spawn_local};
use executor_core::{LocalExecutor, Task as _};
use futures_channel::{mpsc, oneshot};
use futures_lite::future::zip;
use futures_lite::stream::{self, Stream};
use helios_api::http::ErrorCode;
use http::{HeaderValue, Method, Request, Response, StatusCode, Version};
use http_kit_h2::{ServerConfig, ServerConnection};
#[cfg(unix)]
use http_kit_io::DialUnix;
#[cfg(any(target_os = "linux", target_os = "android"))]
use http_kit_io::splice::{FilledPipe, Pipe, Spliced};
use http_kit_io::{
    Answer, BufResult, Dial, IoBuf, IoBufMut, IoVectoredBuf, NoBuf, Read, ReadAhead, ReadOwned,
    Received, Resolve, SendFile, SpliceRead, SpliceWrite, Split, TcpOptions, Timer, Write,
};
use http_kit_tls::TlsAcceptor;
use http_kit_tls::rustls::pki_types::pem::PemObject;
use http_kit_tls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use zenwave::backend::NativeBackend;
use zenwave::transport::Proxy;
use zenwave::{Body, Endpoint, Transport};

use crate::error::{body_code, code};
use crate::request::BodyOutcome;

const OPENSSL_CA_CNF: &str = include_str!("../testdata/ca.cnf");
const OPENSSL_LEAF_CNF: &str = include_str!("../testdata/leaf.cnf");

/// CJK payload covering Chinese, Japanese, and Korean.
const CJK_GREETING: &str = "你好，世界。こんにちは、世界。안녕하세요, 세계.";

struct TimerEntry {
    deadline: Instant,
    waker: Waker,
}

struct Scheduler {
    sender: mpsc::UnboundedSender<Runnable>,
    receiver: RefCell<mpsc::UnboundedReceiver<Runnable>>,
    timers: RefCell<Vec<TimerEntry>>,
}

impl Default for Scheduler {
    fn default() -> Self {
        let (sender, receiver) = mpsc::unbounded();
        Self {
            sender,
            receiver: RefCell::new(receiver),
            timers: RefCell::new(Vec::new()),
        }
    }
}

#[derive(Clone, Default)]
struct TestExecutor {
    scheduler: Rc<Scheduler>,
}

impl TestExecutor {
    fn drain_ready(&self) -> bool {
        let mut ran = false;
        while let Ok(runnable) = self.scheduler.receiver.borrow_mut().try_recv() {
            ran = true;
            runnable.run();
        }
        ran
    }

    fn run_until<F: Future>(&self, future: F) -> F::Output {
        let mut future = pin!(future);
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        loop {
            self.drain_ready();
            if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
                return output;
            }
            if self.drain_ready() {
                continue;
            }
            let now = Instant::now();
            let mut next_deadline: Option<Instant> = None;
            let mut ready_wakers = Vec::new();
            {
                let mut timers = self.scheduler.timers.borrow_mut();
                let mut remaining = Vec::with_capacity(timers.len());
                for entry in timers.drain(..) {
                    if entry.deadline <= now {
                        ready_wakers.push(entry.waker);
                    } else {
                        next_deadline = Some(match next_deadline {
                            Some(current) => current.min(entry.deadline),
                            None => entry.deadline,
                        });
                        remaining.push(entry);
                    }
                }
                *timers = remaining;
            }
            if !ready_wakers.is_empty() {
                for waker in ready_wakers {
                    waker.wake();
                }
                continue;
            }
            let Some(deadline) = next_deadline else {
                panic!("test executor deadlocked with no runnable tasks or timers");
            };
            let wait = deadline.saturating_duration_since(Instant::now());
            if !wait.is_zero() {
                std::thread::sleep(wait);
            }
        }
    }
}

impl LocalExecutor for TestExecutor {
    type Task<T: 'static> = AsyncTask<T>;

    fn spawn_local<Fut>(&self, future: Fut) -> AsyncTask<Fut::Output>
    where
        Fut: Future + 'static,
    {
        let sender = self.scheduler.sender.clone();
        let (runnable, task) = spawn_local(future, move |runnable| {
            let _ = sender.unbounded_send(runnable);
        });
        runnable.schedule();
        task
    }
}

#[derive(Default)]
struct PipeBuffer {
    bytes: VecDeque<u8>,
    closed: bool,
    read_waker: Option<Waker>,
}

struct DuplexRead {
    inbound: Rc<RefCell<PipeBuffer>>,
}

struct DuplexWrite {
    outbound: Rc<RefCell<PipeBuffer>>,
}

impl Drop for DuplexWrite {
    fn drop(&mut self) {
        let mut pipe = self.outbound.borrow_mut();
        pipe.closed = true;
        if let Some(waker) = pipe.read_waker.take() {
            waker.wake();
        }
    }
}

struct DuplexStream {
    read: DuplexRead,
    write: DuplexWrite,
}

fn duplex_pair() -> (DuplexStream, DuplexStream) {
    let client_to_server = Rc::new(RefCell::new(PipeBuffer::default()));
    let server_to_client = Rc::new(RefCell::new(PipeBuffer::default()));
    let client = DuplexStream {
        read: DuplexRead {
            inbound: Rc::clone(&server_to_client),
        },
        write: DuplexWrite {
            outbound: Rc::clone(&client_to_server),
        },
    };
    let server = DuplexStream {
        read: DuplexRead {
            inbound: client_to_server,
        },
        write: DuplexWrite {
            outbound: server_to_client,
        },
    };
    (client, server)
}

impl DuplexRead {
    async fn pull(&mut self, max_bytes: usize) -> io::Result<Vec<u8>> {
        poll_fn(|cx| {
            let mut pipe = self.inbound.borrow_mut();
            if !pipe.bytes.is_empty() {
                let take = pipe.bytes.len().min(max_bytes);
                let out: Vec<u8> = pipe.bytes.drain(..take).collect();
                return Poll::Ready(Ok(out));
            }
            if pipe.closed {
                return Poll::Ready(Ok(Vec::new()));
            }
            pipe.read_waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }
}

impl DuplexWrite {
    fn push(&self, data: &[u8]) -> io::Result<usize> {
        let mut pipe = self.outbound.borrow_mut();
        if pipe.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "duplex write half is closed",
            ));
        }
        pipe.bytes.extend(data);
        if let Some(waker) = pipe.read_waker.take() {
            waker.wake();
        }
        Ok(data.len())
    }
}

impl Read for DuplexRead {
    async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
        let cap = buf.as_uninit().len();
        if cap == 0 {
            return BufResult(Ok(0), buf);
        }
        match self.pull(cap).await {
            Ok(bytes) => {
                let len = bytes.len();
                for (slot, byte) in buf.as_uninit().iter_mut().zip(&bytes) {
                    slot.write(*byte);
                }
                // SAFETY: the first `len` bytes were initialized in the loop above.
                unsafe { buf.set_len(len) };
                BufResult(Ok(len), buf)
            }
            Err(error) => BufResult(Err(error), buf),
        }
    }
}

impl ReadOwned for DuplexRead {
    type Buf = NoBuf;

    async fn read_owned(&mut self) -> io::Result<Received<NoBuf>> {
        let bytes = self.pull(64 * 1024).await?;
        Ok(if bytes.is_empty() {
            Received::End
        } else {
            Received::Owned(bytes.into())
        })
    }
}

impl ReadAhead for DuplexRead {
    async fn stop_read_ahead(&mut self) -> Vec<u8> {
        Vec::new()
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn unsplicable() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "in-memory duplex stream does not support splice",
    )
}

impl SpliceRead for DuplexRead {
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
        Err((unsplicable(), pipe))
    }
}

impl Write for DuplexWrite {
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let result = self.push(buf.as_init());
        BufResult(result, buf)
    }

    async fn write_vectored<B: IoVectoredBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let result = (|| {
            let mut total = 0usize;
            for slice in buf.iter_slice() {
                total += self.push(slice)?;
            }
            Ok(total)
        })();
        BufResult(result, buf)
    }

    async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        let mut pipe = self.outbound.borrow_mut();
        pipe.closed = true;
        if let Some(waker) = pipe.read_waker.take() {
            waker.wake();
        }
        Ok(())
    }
}

impl SendFile for DuplexWrite {
    async fn send_file<F: Borrow<File> + 'static>(
        &mut self,
        file: F,
        _offset: u64,
        _len: usize,
    ) -> BufResult<usize, F> {
        BufResult(
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "send_file not used by test duplex stream",
            )),
            file,
        )
    }
}

impl SpliceWrite for DuplexWrite {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn can_splice(&self) -> bool {
        false
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    async fn splice_from_pipe(&mut self, _filled: FilledPipe) -> io::Result<Pipe> {
        Err(unsplicable())
    }
}

impl Split for DuplexStream {
    type ReadHalf = DuplexRead;
    type WriteHalf = DuplexWrite;

    fn split(self) -> (DuplexRead, DuplexWrite) {
        (self.read, self.write)
    }
}

impl Read for DuplexStream {
    fn read<B: IoBufMut>(&mut self, buf: B) -> impl Future<Output = BufResult<usize, B>> {
        self.read.read(buf)
    }
}

impl ReadOwned for DuplexStream {
    type Buf = NoBuf;

    fn read_owned(&mut self) -> impl Future<Output = io::Result<Received<NoBuf>>> {
        self.read.read_owned()
    }
}

impl ReadAhead for DuplexStream {
    fn stop_read_ahead(&mut self) -> impl Future<Output = Vec<u8>> {
        self.read.stop_read_ahead()
    }
}

impl Write for DuplexStream {
    fn write<B: IoBuf>(&mut self, buf: B) -> impl Future<Output = BufResult<usize, B>> {
        self.write.write(buf)
    }

    fn write_vectored<B: IoVectoredBuf>(
        &mut self,
        buf: B,
    ) -> impl Future<Output = BufResult<usize, B>> {
        self.write.write_vectored(buf)
    }

    fn flush(&mut self) -> impl Future<Output = io::Result<()>> {
        self.write.flush()
    }

    fn shutdown(&mut self) -> impl Future<Output = io::Result<()>> {
        self.write.shutdown()
    }
}

impl SendFile for DuplexStream {
    fn send_file<F: Borrow<File> + 'static>(
        &mut self,
        file: F,
        offset: u64,
        len: usize,
    ) -> impl Future<Output = BufResult<usize, F>> {
        self.write.send_file(file, offset, len)
    }
}

impl SpliceRead for DuplexStream {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn can_splice(&self) -> bool {
        self.read.can_splice()
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn splice_to_pipe(
        &mut self,
        pipe: Pipe,
        max: usize,
    ) -> impl Future<Output = Result<Spliced, (io::Error, Pipe)>> {
        self.read.splice_to_pipe(pipe, max)
    }
}

impl SpliceWrite for DuplexStream {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn can_splice(&self) -> bool {
        self.write.can_splice()
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn splice_from_pipe(&mut self, filled: FilledPipe) -> impl Future<Output = io::Result<Pipe>> {
        self.write.splice_from_pipe(filled)
    }
}

impl TcpOptions for DuplexStream {
    fn set_nodelay(&self, _nodelay: bool) -> io::Result<()> {
        Ok(())
    }

    fn nodelay(&self) -> io::Result<bool> {
        Ok(true)
    }
}

type ServerHandler = Rc<dyn Fn(DuplexStream)>;

#[derive(Clone)]
struct InMemoryNet {
    scheduler: Rc<Scheduler>,
    dials: Rc<Cell<usize>>,
    on_accept: ServerHandler,
}

impl InMemoryNet {
    fn new(executor: &TestExecutor, on_accept: impl Fn(DuplexStream) + 'static) -> Self {
        Self {
            scheduler: Rc::clone(&executor.scheduler),
            dials: Rc::new(Cell::new(0)),
            on_accept: Rc::new(on_accept),
        }
    }

    fn dial_count(&self) -> usize {
        self.dials.get()
    }
}

impl Dial for InMemoryNet {
    type Connection = DuplexStream;

    async fn connect(&self, _addr: SocketAddr) -> io::Result<DuplexStream> {
        self.dials.set(self.dials.get() + 1);
        let (client, server) = duplex_pair();
        (self.on_accept)(server);
        Ok(client)
    }
}

#[cfg(unix)]
impl DialUnix for InMemoryNet {
    type UnixConnection = DuplexStream;

    async fn connect_unix(&self, _path: &Path) -> io::Result<DuplexStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unix sockets are not used in in-memory h2 tests",
        ))
    }
}

impl Resolve for InMemoryNet {
    fn lookup(&self, _host: &str) -> impl Stream<Item = Answer> {
        stream::once(Answer::Ranked(Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])))
    }
}

impl Timer for InMemoryNet {
    async fn sleep_until(&self, deadline: Instant) {
        poll_fn(|cx| {
            if Instant::now() >= deadline {
                Poll::Ready(())
            } else {
                self.scheduler.timers.borrow_mut().push(TimerEntry {
                    deadline,
                    waker: cx.waker().clone(),
                });
                Poll::Pending
            }
        })
        .await;
    }
}

struct TestPki {
    ca_pem: Vec<u8>,
    server_config: Arc<rustls::ServerConfig>,
}

fn generate_test_pki() -> TestPki {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls_pure::provider().install_default();
    }
    let dir = tempfile::tempdir().expect("create tempdir for test pki");
    let ca_cnf = dir.path().join("ca.cnf");
    let leaf_cnf = dir.path().join("leaf.cnf");
    std::fs::write(&ca_cnf, OPENSSL_CA_CNF).expect("write ca.cnf");
    std::fs::write(&leaf_cnf, OPENSSL_LEAF_CNF).expect("write leaf.cnf");

    let run_openssl = |args: &[&str]| {
        let output = Command::new("openssl")
            .current_dir(dir.path())
            .args(args)
            .output()
            .expect("spawn openssl");
        assert!(
            output.status.success(),
            "openssl {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    };

    run_openssl(&[
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-nodes",
        "-keyout",
        "ca.key",
        "-out",
        "ca.crt",
        "-days",
        "2",
        "-subj",
        "/CN=helios-test-ca",
        "-extensions",
        "v3_ca",
        "-config",
        "ca.cnf",
    ]);
    run_openssl(&[
        "req",
        "-new",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-nodes",
        "-keyout",
        "leaf.key",
        "-out",
        "leaf.csr",
        "-subj",
        "/CN=localhost",
    ]);
    run_openssl(&[
        "x509",
        "-req",
        "-in",
        "leaf.csr",
        "-CA",
        "ca.crt",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-out",
        "leaf.crt",
        "-days",
        "2",
        "-extensions",
        "v3_leaf",
        "-extfile",
        "leaf.cnf",
    ]);

    let ca_pem = std::fs::read(dir.path().join("ca.crt")).expect("read ca.crt");
    let leaf_pem = std::fs::read(dir.path().join("leaf.crt")).expect("read leaf.crt");
    let key_pem = std::fs::read(dir.path().join("leaf.key")).expect("read leaf.key");

    let certs = CertificateDer::pem_slice_iter(&leaf_pem)
        .collect::<Result<Vec<_>, _>>()
        .expect("parse leaf cert pem");
    let key = PrivateKeyDer::from_pem_slice(&key_pem).expect("parse leaf key pem");

    let mut server_config =
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls_pure::provider()))
            .with_safe_default_protocol_versions()
            .expect("safe default TLS versions")
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("build server TLS config");
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    TestPki {
        ca_pem,
        server_config: Arc::new(server_config),
    }
}

#[test]
fn alpn_negotiates_http2_and_multiplexes_concurrent_requests() {
    let pki = generate_test_pki();
    let executor = TestExecutor::default();
    let acceptor = TlsAcceptor::new(Arc::clone(&pki.server_config));
    let negotiated_alpn = Rc::new(RefCell::new(Vec::<Option<Vec<u8>>>::new()));
    let server_exec = executor.clone();
    let server_alpn = Rc::clone(&negotiated_alpn);

    let net = InMemoryNet::new(&executor, move |stream| {
        let acceptor = acceptor.clone();
        let timer = InMemoryNet {
            scheduler: Rc::clone(&server_exec.scheduler),
            dials: Rc::new(Cell::new(0)),
            on_accept: Rc::new(|_| {}),
        };
        let alpn = Rc::clone(&server_alpn);
        server_exec
            .spawn_local(async move {
                let tls = acceptor.accept(stream, &timer).await.expect("TLS accept");
                alpn.borrow_mut()
                    .push(tls.alpn_protocol().map(ToOwned::to_owned));
                let service = |request: Request<Body>| async move {
                    let path = request.uri().path().to_owned();
                    let body = request
                        .into_body()
                        .into_bytes()
                        .await
                        .expect("read request body");
                    let mut reply = path.into_bytes();
                    if !body.is_empty() {
                        reply.push(b':');
                        reply.extend_from_slice(&body);
                    }
                    Response::new(Body::from_bytes(reply))
                };
                let _ = ServerConnection::from_stream(tls, timer, ServerConfig::default())
                    .serve(&service)
                    .await;
            })
            .detach();
    });

    let transport = Transport::builder()
        .proxy(Proxy::none())
        .extra_root_certificates_pem(&pki.ca_pem)
        .expect("load test CA")
        .build()
        .expect("build transport");

    let backend = NativeBackend::on_current_thread(transport, net.clone(), net.clone(), &executor);

    executor.run_until(async {
        let mut first_backend = backend.clone();
        let mut second_backend = backend.clone();
        let mut third_backend = backend.clone();

        let first = async move {
            let mut req = Request::new(Body::empty());
            *req.uri_mut() = "https://localhost:443/alpha".parse().expect("valid uri");
            let resp = first_backend.respond(&mut req).await.expect("first h2");
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(resp.version(), Version::HTTP_2);
            resp.into_body().into_bytes().await.expect("first body")
        };

        let second = async move {
            let mut req = Request::new(Body::from_bytes(CJK_GREETING.as_bytes().to_vec()));
            *req.method_mut() = Method::POST;
            *req.uri_mut() = "https://localhost:443/beta".parse().expect("valid uri");
            let resp = second_backend.respond(&mut req).await.expect("second h2");
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(resp.version(), Version::HTTP_2);
            resp.into_body().into_bytes().await.expect("second body")
        };

        let third = async move {
            let mut req = Request::new(Body::empty());
            *req.uri_mut() = "https://localhost:443/gamma".parse().expect("valid uri");
            let resp = third_backend.respond(&mut req).await.expect("third h2");
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(resp.version(), Version::HTTP_2);
            resp.into_body().into_bytes().await.expect("third body")
        };

        let ((body1, body2), body3) = zip(zip(first, second), third).await;
        assert_eq!(body1.as_ref(), b"/alpha");
        assert_eq!(body2.as_ref(), format!("/beta:{CJK_GREETING}").as_bytes());
        assert_eq!(body3.as_ref(), b"/gamma");
    });

    assert_eq!(
        net.dial_count(),
        1,
        "concurrent HTTPS requests to an h2 origin must coalesce and multiplex on one connection"
    );
    assert_eq!(
        RefCell::borrow(&negotiated_alpn).as_slice(),
        &[Some(b"h2".to_vec())]
    );
}

#[test]
fn h2_oversized_response_headers_map_to_header_section_size() {
    let pki = generate_test_pki();
    let executor = TestExecutor::default();
    let acceptor = TlsAcceptor::new(Arc::clone(&pki.server_config));
    let server_exec = executor.clone();

    let net = InMemoryNet::new(&executor, move |stream| {
        let acceptor = acceptor.clone();
        let timer = InMemoryNet {
            scheduler: Rc::clone(&server_exec.scheduler),
            dials: Rc::new(Cell::new(0)),
            on_accept: Rc::new(|_| {}),
        };
        server_exec
            .spawn_local(async move {
                let tls = acceptor.accept(stream, &timer).await.expect("TLS accept");
                let service = |_request: Request<Body>| async move {
                    let mut resp = Response::new(Body::empty());
                    // Exceeds http-kit-h2's 64 KiB default max_header_list_size.
                    let value = HeaderValue::from_bytes(&vec![b'a'; 70 * 1024])
                        .expect("valid header value");
                    resp.headers_mut().insert("x-oversized", value);
                    resp
                };
                let _ = ServerConnection::from_stream(tls, timer, ServerConfig::default())
                    .serve(&service)
                    .await;
            })
            .detach();
    });

    let transport = Transport::builder()
        .proxy(Proxy::none())
        .extra_root_certificates_pem(&pki.ca_pem)
        .expect("load test CA")
        .build()
        .expect("build transport");

    let mut backend =
        NativeBackend::on_current_thread(transport, net.clone(), net.clone(), &executor);

    let err = executor.run_until(async {
        let mut req = Request::new(Body::empty());
        *req.uri_mut() = "https://localhost:443/oversized"
            .parse()
            .expect("valid uri");
        backend
            .respond(&mut req)
            .await
            .expect_err("oversized h2 response headers must fail")
    });

    let mapped = code(&err, &BodyOutcome::default());
    assert!(
        matches!(
            mapped,
            ErrorCode::HttpResponseHeaderSectionSize(Some(65_536))
        ),
        "expected HttpResponseHeaderSectionSize(Some(65536)), got {mapped:?} from {err:?}"
    );
}

#[test]
fn h2_abrupt_connection_drop_maps_head_and_body_errors() {
    let pki = generate_test_pki();
    let executor = TestExecutor::default();
    let acceptor = TlsAcceptor::new(Arc::clone(&pki.server_config));
    let server_exec = executor.clone();

    // Case 1: server drops connection before sending response headers.
    let net_head_drop = InMemoryNet::new(&executor, move |stream| {
        let acceptor = acceptor.clone();
        let timer = InMemoryNet {
            scheduler: Rc::clone(&server_exec.scheduler),
            dials: Rc::new(Cell::new(0)),
            on_accept: Rc::new(|_| {}),
        };
        server_exec
            .spawn_local(async move {
                let tls = acceptor.accept(stream, &timer).await.expect("TLS accept");
                assert_eq!(tls.alpn_protocol(), Some(&b"h2"[..]));
                drop(tls);
            })
            .detach();
    });

    let transport = Transport::builder()
        .proxy(Proxy::none())
        .extra_root_certificates_pem(&pki.ca_pem)
        .expect("load test CA")
        .build()
        .expect("build transport");

    let mut backend = NativeBackend::on_current_thread(
        transport,
        net_head_drop.clone(),
        net_head_drop.clone(),
        &executor,
    );

    let head_err = executor.run_until(async {
        let mut req = Request::new(Body::empty());
        *req.uri_mut() = "https://localhost:443/drop-head"
            .parse()
            .expect("valid uri");
        backend
            .respond(&mut req)
            .await
            .expect_err("dropped h2 connection must fail")
    });
    assert!(
        matches!(
            code(&head_err, &BodyOutcome::default()),
            ErrorCode::ConnectionTerminated
        ),
        "expected ConnectionTerminated for dropped h2 head, got {head_err:?}"
    );

    // Case 2: server sends response head and partial body, then shuts down abruptly.
    let acceptor = TlsAcceptor::new(Arc::clone(&pki.server_config));
    let server_exec = executor.clone();
    let (drop_tx, drop_rx) = oneshot::channel::<()>();
    let drop_rx = Rc::new(RefCell::new(Some(drop_rx)));

    let net_body_drop = InMemoryNet::new(&executor, move |stream| {
        let acceptor = acceptor.clone();
        let timer = InMemoryNet {
            scheduler: Rc::clone(&server_exec.scheduler),
            dials: Rc::new(Cell::new(0)),
            on_accept: Rc::new(|_| {}),
        };
        let drop_rx = Rc::clone(&drop_rx);
        server_exec
            .spawn_local(async move {
                let tls = acceptor.accept(stream, &timer).await.expect("TLS accept");
                let shutdown = drop_rx.borrow_mut().take().expect("single connection");
                let service = |_request: Request<Body>| async move {
                    let body = Body::from_frames(stream::unfold(
                        Some(b"partial".to_vec()),
                        |state| async move {
                            if let Some(chunk) = state {
                                Some((
                                    Ok::<_, zenwave::BodyError>(zenwave::BodyFrame::Data(
                                        chunk.into(),
                                    )),
                                    None,
                                ))
                            } else {
                                std::future::pending().await
                            }
                        },
                    ));
                    Response::new(body)
                };
                let serve = ServerConnection::from_stream(tls, timer, ServerConfig::default())
                    .serve(&service);
                let _ = futures_lite::future::or(
                    async move {
                        let _ = serve.await;
                    },
                    async move {
                        let _ = shutdown.await;
                    },
                )
                .await;
            })
            .detach();
    });

    let transport = Transport::builder()
        .proxy(Proxy::none())
        .extra_root_certificates_pem(&pki.ca_pem)
        .expect("load test CA")
        .build()
        .expect("build transport");

    let mut backend = NativeBackend::on_current_thread(
        transport,
        net_body_drop.clone(),
        net_body_drop.clone(),
        &executor,
    );

    let body_err = executor.run_until(async {
        use futures_lite::StreamExt;

        let mut req = Request::new(Body::empty());
        *req.uri_mut() = "https://localhost:443/drop-body"
            .parse()
            .expect("valid uri");
        let resp = backend.respond(&mut req).await.expect("response head");
        assert_eq!(resp.version(), Version::HTTP_2);
        let mut body = resp.into_body();
        let first = body
            .next()
            .await
            .expect("first frame")
            .expect("first frame ok");
        assert!(matches!(first, zenwave::BodyFrame::Data(bytes) if bytes.as_ref() == b"partial"));
        let _ = drop_tx.send(());
        body.next()
            .await
            .expect("error frame after abrupt server drop")
            .expect_err("truncated h2 body must fail")
    });

    let mapped = body_code(&body_err, true);
    assert!(
        matches!(
            mapped,
            ErrorCode::ConnectionTerminated | ErrorCode::HttpResponseIncomplete
        ),
        "expected ConnectionTerminated or HttpResponseIncomplete, got {mapped:?} from {body_err:?}"
    );
}
