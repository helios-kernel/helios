//! End-to-end HTTP/3 tests over `zenwave`'s `NativeBackend` with
//! `native-http3`, exercising RFC 9460 `HTTPS` record discovery, `Alt-Svc`
//! discovery, QUIC request multiplexing, and certificate verification error
//! mapping on a local single-threaded executor and in-memory UDP/TCP transport.

use std::cell::{Cell, RefCell};
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use executor_core::{LocalExecutor as _, Task as _};
use futures_lite::future::{or, zip};
use helios_api::http::ErrorCode;
use http::{HeaderValue, Method, Request, Response, StatusCode, Version, header};
use http_kit_h2::{ServerConfig as H2ServerConfig, ServerConnection as H2ServerConnection};
use http_kit_h3::{
    Client as H3Client, ClientConfig as H3ClientConfig, Identity, Rejection, Server as H3Server,
    ServerConfig as H3ServerConfig, Verifier,
};
use http_kit_io::Datagram as _;
use http_kit_tls::TlsAcceptor;
use zenwave::backend::NativeBackend;
use zenwave::dns::HttpsRecord;
use zenwave::transport::Proxy;
use zenwave::{Body, Cause, ConnectError, ConnectFailure, Endpoint, Error, Hop, Transport};

use crate::error::code;
use crate::h2_tests::{
    CJK_GREETING, InMemoryNet, TestExecutor, TestPki, generate_test_pki, generate_test_pki_named,
};
use crate::request::BodyOutcome;

const H3_PORT: u16 = 8443;
const MAX_FIELD_SECTION_SIZE: u64 = 64 * 1024;

fn spawn_h3_server(executor: &TestExecutor, net: &InMemoryNet, pki: &TestPki, port: u16) {
    let addr: SocketAddr = format!("[::1]:{port}").parse().expect("valid IPv6 addr");
    let socket = net.udp_hub().bind(addr).expect("bind in-memory h3 socket");
    let timer = InMemoryNet::timer_only(executor);
    let identity = Identity::from_pem(pki.leaf_pem.clone(), pki.key_pem.clone());
    let server = H3Server::new(
        socket,
        timer,
        &H3ServerConfig::new(identity, MAX_FIELD_SECTION_SIZE),
    )
    .expect("build h3 server");
    executor
        .spawn_local(async move {
            let service = |request: Request<Body>| async move {
                let path = request.uri().path().to_owned();
                let body = request
                    .into_body()
                    .into_bytes()
                    .await
                    .expect("read h3 request body");
                let mut reply = path.into_bytes();
                if !body.is_empty() {
                    reply.push(b':');
                    reply.extend_from_slice(&body);
                }
                Response::new(Body::from_bytes(reply))
            };
            let _ = server.serve(&service).await;
        })
        .detach();
}

/// Spawns an HTTP/2 TLS server on accepted TCP connections that serves one
/// request (optionally attaching an `Alt-Svc` header) and then drops the
/// connection so the next request performs a fresh checkout.
fn build_one_shot_h2_net(
    executor: &TestExecutor,
    pki: &TestPki,
    alt_svc: Option<&'static str>,
) -> InMemoryNet {
    let acceptor = TlsAcceptor::new(Arc::clone(&pki.server_config));
    let server_exec = executor.clone();
    InMemoryNet::new(executor, move |stream| {
        let acceptor = acceptor.clone();
        let timer = InMemoryNet::timer_only(&server_exec);
        let server_exec_inner = server_exec.clone();
        server_exec
            .spawn_local(async move {
                let Ok(tls) = acceptor.accept(stream, &timer).await else {
                    return;
                };
                let (done_tx, done_rx) = futures_channel::oneshot::channel::<()>();
                let done_tx = Rc::new(RefCell::new(Some(done_tx)));
                let service = move |request: Request<Body>| {
                    let done_tx = Rc::clone(&done_tx);
                    let server_exec_inner = server_exec_inner.clone();
                    async move {
                        let path = request.uri().path().to_owned();
                        let mut resp = Response::new(Body::from_bytes(format!("h2:{path}")));
                        if let Some(value) = alt_svc {
                            resp.headers_mut()
                                .insert(header::ALT_SVC, HeaderValue::from_static(value));
                        }
                        if let Some(tx) = done_tx.borrow_mut().take() {
                            // Let the response finish flushing before closing the H2 session.
                            let timer = InMemoryNet::timer_only(&server_exec_inner);
                            server_exec_inner
                                .spawn_local(async move {
                                    http_kit_io::Timer::sleep(&timer, Duration::from_millis(5))
                                        .await;
                                    let _ = tx.send(());
                                })
                                .detach();
                        }
                        resp
                    }
                };
                let serve = H2ServerConnection::from_stream(tls, timer, H2ServerConfig::default())
                    .serve(&service);
                let _ = or(
                    async move {
                        let _ = serve.await;
                    },
                    async move {
                        let _ = done_rx.await;
                    },
                )
                .await;
            })
            .detach();
    })
}

#[test]
fn https_record_discovery_upgrades_and_multiplexes_http3() {
    let pki = generate_test_pki();
    let executor = TestExecutor::default();
    let https_queries = Rc::new(Cell::new(0usize));
    let queries_ref = Rc::clone(&https_queries);

    let net = build_one_shot_h2_net(&executor, &pki, None).with_https_lookup(move |host, port| {
        assert_eq!(host, "localhost");
        assert_eq!(port, 443);
        queries_ref.set(queries_ref.get() + 1);
        Ok(Some(HttpsRecord {
            alpn: vec!["h3".to_owned(), "h2".to_owned()],
            port: Some(H3_PORT),
            ttl: Duration::from_secs(300),
        }))
    });
    spawn_h3_server(&executor, &net, &pki, H3_PORT);

    let transport = Transport::builder()
        .proxy(Proxy::none())
        .extra_root_certificates_pem(&pki.ca_pem)
        .expect("load test CA")
        .build()
        .expect("build transport");

    let backend = NativeBackend::on_current_thread(transport, net.clone(), net.clone(), &executor);

    executor.run_until(async {
        let mut first_backend = backend.clone();
        // First request populates HTTPS RR discovery while completing over TCP/H2.
        let mut bootstrap = Request::new(Body::empty());
        *bootstrap.uri_mut() = "https://localhost:443/bootstrap"
            .parse()
            .expect("valid uri");
        let resp = first_backend
            .respond(&mut bootstrap)
            .await
            .expect("bootstrap");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.version(), Version::HTTP_2);
        let body = resp.into_body().into_bytes().await.expect("bootstrap body");
        assert_eq!(body.as_ref(), b"h2:/bootstrap");

        // Let the one-shot H2 connection close and force subsequent requests
        // onto the discovered HTTP/3 endpoint.
        http_kit_io::Timer::sleep(&net, Duration::from_millis(20)).await;
        net.set_refuse_tcp(true);

        let mut b1 = backend.clone();
        let mut b2 = backend.clone();
        let mut b3 = backend.clone();

        let r1 = async move {
            let mut req = Request::new(Body::empty());
            *req.uri_mut() = "https://localhost:443/alpha".parse().expect("valid uri");
            let resp = b1.respond(&mut req).await.expect("first h3");
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(resp.version(), Version::HTTP_3);
            resp.into_body().into_bytes().await.expect("first h3 body")
        };
        let r2 = async move {
            let mut req = Request::new(Body::from_bytes(CJK_GREETING.as_bytes().to_vec()));
            *req.method_mut() = Method::POST;
            *req.uri_mut() = "https://localhost:443/beta".parse().expect("valid uri");
            let resp = b2.respond(&mut req).await.expect("second h3");
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(resp.version(), Version::HTTP_3);
            resp.into_body().into_bytes().await.expect("second h3 body")
        };
        let r3 = async move {
            let mut req = Request::new(Body::empty());
            *req.uri_mut() = "https://localhost:443/gamma".parse().expect("valid uri");
            let resp = b3.respond(&mut req).await.expect("third h3");
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(resp.version(), Version::HTTP_3);
            resp.into_body().into_bytes().await.expect("third h3 body")
        };

        let ((body1, body2), body3) = zip(zip(r1, r2), r3).await;
        assert_eq!(body1.as_ref(), b"/alpha");
        assert_eq!(body2.as_ref(), format!("/beta:{CJK_GREETING}").as_bytes());
        assert_eq!(body3.as_ref(), b"/gamma");
    });

    assert_eq!(
        https_queries.get(),
        1,
        "HTTPS record discovery should run once and be cached for its TTL"
    );
    // 1 server UDP socket + 1 client UDP socket for the single multiplexed QUIC connection.
    assert_eq!(
        net.udp_hub().bind_count(),
        2,
        "concurrent HTTP/3 requests must coalesce and multiplex onto one QUIC connection"
    );
}

#[test]
fn alt_svc_discovery_upgrades_to_http3() {
    let pki = generate_test_pki();
    let executor = TestExecutor::default();

    let net = build_one_shot_h2_net(&executor, &pki, Some("h3=\":8443\"; ma=300"));
    spawn_h3_server(&executor, &net, &pki, H3_PORT);

    let transport = Transport::builder()
        .proxy(Proxy::none())
        .extra_root_certificates_pem(&pki.ca_pem)
        .expect("load test CA")
        .build()
        .expect("build transport");

    let mut backend =
        NativeBackend::on_current_thread(transport, net.clone(), net.clone(), &executor);

    executor.run_until(async {
        let mut first = Request::new(Body::empty());
        *first.uri_mut() = "https://localhost:443/discover".parse().expect("valid uri");
        let resp = backend.respond(&mut first).await.expect("first h2");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.version(), Version::HTTP_2);
        let _ = resp.into_body().into_bytes().await.expect("first body");

        http_kit_io::Timer::sleep(&net, Duration::from_millis(20)).await;
        net.set_refuse_tcp(true);

        let mut second = Request::new(Body::from_bytes(CJK_GREETING.as_bytes().to_vec()));
        *second.method_mut() = Method::POST;
        *second.uri_mut() = "https://localhost:443/alt".parse().expect("valid uri");
        let resp = backend
            .respond(&mut second)
            .await
            .expect("Alt-Svc upgraded request must succeed over HTTP/3");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.version(), Version::HTTP_3);
        let body = resp.into_body().into_bytes().await.expect("alt h3 body");
        assert_eq!(body.as_ref(), format!("/alt:{CJK_GREETING}").as_bytes());
    });
}

#[test]
fn h3_untrusted_certificate_rejection_maps_to_tls_certificate_error() {
    let trusted_pki = generate_test_pki_named("helios-trusted-ca");
    let stranger_pki = generate_test_pki_named("helios-stranger-ca");
    let executor = TestExecutor::default();

    // Part 1: direct QUIC handshake where the verifier rejects the stranger
    // chain with `Rejection::UnknownCa` produces `LocallyClosed` with QUIC
    // `CRYPTO_ERROR` (0x100 + 48), which maps to `TlsCertificateError` both
    // directly and when wrapped inside Happy Eyeballs' `io::Error::other`.
    let net = InMemoryNet::timer_only(&executor);
    spawn_h3_server(&executor, &net, &stranger_pki, H3_PORT);

    let handshake_err = executor.run_until(async {
        let client_cfg = H3ClientConfig::with_verifier(
            Verifier::new(|_presented| Err(Rejection::UnknownCa)),
            MAX_FIELD_SECTION_SIZE,
        );
        let mut client = H3Client::new(&client_cfg).expect("build h3 client");
        let socket = net
            .bind_udp("[::1]:0".parse().expect("valid addr"))
            .await
            .expect("bind client udp");
        let peer: SocketAddr = format!("[::1]:{H3_PORT}").parse().expect("valid peer");
        let (send, conn) = client
            .connect(socket, net.clone(), "localhost", peer)
            .expect("start quic connect");
        let run = conn.run();
        let ready = send.ready();
        or(
            async move { ready.await.expect_err("untrusted cert must fail handshake") },
            async move {
                run.await
                    .expect_err("connection driver exits on rejected handshake")
            },
        )
        .await
    });

    assert!(
        matches!(
            handshake_err,
            http_kit_h3::Error::LocallyClosed {
                application: false,
                code: 0x130, // 0x100 + TLS alert unknown_ca (48)
            }
        ),
        "expected QUIC CRYPTO_ERROR unknown_ca (0x130), got {handshake_err:?}"
    );

    let outcome = BodyOutcome::default();
    let direct_err = Error::Connect(Box::new(ConnectError::new(
        Hop::Origin,
        "localhost",
        H3_PORT,
        ConnectFailure::Quic(Cause::H3(handshake_err)),
    )));
    assert!(matches!(
        code(&direct_err, &outcome),
        ErrorCode::TlsCertificateError
    ));

    let happy_eyeballs_wrapped = Error::Connect(Box::new(ConnectError::new(
        Hop::Origin,
        "localhost",
        H3_PORT,
        ConnectFailure::Quic(Cause::Io(Arc::new(io::Error::other(direct_err)))),
    )));
    assert!(matches!(
        code(&happy_eyeballs_wrapped, &outcome),
        ErrorCode::TlsCertificateError
    ));

    // Part 2: end-to-end `NativeBackend` against an untrusted H3 server with
    // a trusted TCP fallback: QUIC rejects the stranger certificate, enters
    // backoff, and the request succeeds over TCP/H2.
    let net_fallback =
        build_one_shot_h2_net(&executor, &trusted_pki, None).with_https_lookup(|_, _| {
            Ok(Some(HttpsRecord {
                alpn: vec!["h3".to_owned()],
                port: Some(H3_PORT),
                ttl: Duration::from_secs(300),
            }))
        });
    spawn_h3_server(&executor, &net_fallback, &stranger_pki, H3_PORT);

    let transport = Transport::builder()
        .proxy(Proxy::none())
        .extra_root_certificates_pem(&trusted_pki.ca_pem)
        .expect("load trusted CA")
        .build()
        .expect("build transport");
    let mut backend = NativeBackend::on_current_thread(
        transport,
        net_fallback.clone(),
        net_fallback.clone(),
        &executor,
    );

    executor.run_until(async {
        let mut first = Request::new(Body::empty());
        *first.uri_mut() = "https://localhost:443/first".parse().expect("valid uri");
        let resp = backend.respond(&mut first).await.expect("first h2");
        assert_eq!(resp.version(), Version::HTTP_2);
        let _ = resp.into_body().into_bytes().await.expect("first body");

        http_kit_io::Timer::sleep(&net_fallback, Duration::from_millis(20)).await;

        let mut second = Request::new(Body::empty());
        *second.uri_mut() = "https://localhost:443/fallback".parse().expect("valid uri");
        let resp = backend
            .respond(&mut second)
            .await
            .expect("untrusted QUIC must fall back to trusted TCP/H2");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.version(), Version::HTTP_2);
        let body = resp.into_body().into_bytes().await.expect("fallback body");
        assert_eq!(body.as_ref(), b"h2:/fallback");
    });
}
