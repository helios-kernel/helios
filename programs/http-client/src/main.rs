//! The `http-client` kernel plugin.
//!
//! `wasi:http/client.send` in the kernel is a forwarder: it turns a caller's
//! request into a transport-neutral exchange and hands it to whoever exports
//! `wasi:http/handler`. This component is that exporter. It is an ordinary
//! user-mode wasm program with the ordinary isolation model — the kernel just
//! provisions it from bootfs and keeps one instance alive — so all of HTTP
//! lives out here, and none of it lives in the kernel.
//!
//! The plugin carries no protocol code of its own. It hosts zenwave's native
//! backend (HTTP/1.1 framing, TLS through rustls with the Mozilla roots
//! compiled in) over `helios_api::http_kit::HeliosNet`, which is
//! `http-kit-io` on `wasi:sockets` and the monotonic clock. What is left
//! here is the translation between `wasi:http` and `http` messages, the
//! `request-options` timeouts, and the choice of `wasi:http` error code for
//! each failure.
//!
//! One persistent connection pool (`NativeBackend`) is lazily built per shard
//! on the first exchange (loading the Mozilla roots plus optional
//! `/etc/ssl/certs/ca-certificates.crt` once) and retained across requests on
//! that processor core so HTTP keep-alive sockets and TLS sessions are reused.

mod error;
mod fields;
mod request;
mod response;

use std::cell::RefCell;
use std::future::Future;
use std::io::ErrorKind;
use std::time::Duration;

use futures_channel::oneshot;
use helios_api::http::handler::Guest;
use helios_api::http::types;
use helios_api::http::{ErrorCode, RequestOptions, Scheme};
use helios_api::http_kit::{HeliosExecutor, HeliosNet};
use helios_api::task::spawn;
use http::StatusCode;
use zenwave::backend::NativeBackend;
use zenwave::transport::Proxy;
use zenwave::{Body, Endpoint, Timeouts, Transport};

use crate::error::code;
use crate::request::BodyOutcome;

mod bindings {
    pub use ::helios_api::bindings::*;
}

/// Applied when the caller supplied no `request-options`.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(600);
const DEFAULT_BETWEEN_BYTES_TIMEOUT: Duration = Duration::from_secs(600);

/// The system's optional PEM bundle, added to Mozilla's built-in roots.
const SYSTEM_CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

struct HttpClient;

::helios_api::bindings::export!(HttpClient);

impl Guest for HttpClient {
    async fn handle(request: types::Request) -> Result<types::Response, ErrorCode> {
        handle(request).await
    }
}

/// The client's timeouts for one exchange: the connect timeout, the time to
/// the first byte of the response head, and the time between the bytes of
/// its body.
fn timeouts(options: Option<&RequestOptions>) -> Timeouts {
    let nanos = |value: Option<u64>, default: Duration| value.map_or(default, Duration::from_nanos);
    Timeouts::default()
        .with_connect(nanos(
            options.and_then(RequestOptions::get_connect_timeout),
            DEFAULT_CONNECT_TIMEOUT,
        ))
        .with_response_head(nanos(
            options.and_then(RequestOptions::get_first_byte_timeout),
            DEFAULT_FIRST_BYTE_TIMEOUT,
        ))
        .with_body_idle(nanos(
            options.and_then(RequestOptions::get_between_bytes_timeout),
            DEFAULT_BETWEEN_BYTES_TIMEOUT,
        ))
}

async fn handle(request: types::Request) -> Result<types::Response, ErrorCode> {
    // The options resource is a child of the request and must be dropped
    // before the request is consumed.
    let timeouts = {
        let options = request.get_options();
        timeouts(options.as_ref())
    };
    let (mut http, scheme, outcome, verdict) = request::into_http(request)?;
    http.extensions_mut().insert(timeouts);
    // The caller's verdict on its body settles from the body or from the
    // exchange, whichever ends first, so it waits on both in a task of its
    // own.
    let (failed, failure) = oneshot::channel();
    spawn(verdict.settle(failure));
    let exchanged = exchange(http, scheme, &outcome).await;
    if let Err(code) = &exchanged {
        // An error here means the body already decided the verdict.
        let _ = failed.send(code.clone());
    }
    exchanged
}

enum BackendState<T> {
    Empty,
    Initializing(Vec<oneshot::Sender<()>>),
    Ready(T),
}

struct ShardBackendCell<T> {
    state: RefCell<BackendState<T>>,
}

struct InitGuard<'a, T> {
    cell: &'a ShardBackendCell<T>,
    completed: bool,
}

impl<T> Drop for InitGuard<'_, T> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let waiters = {
            let mut state = self.cell.state.borrow_mut();
            match std::mem::replace(&mut *state, BackendState::Empty) {
                BackendState::Initializing(waiters) => waiters,
                other => {
                    *state = other;
                    Vec::new()
                }
            }
        };
        for tx in waiters {
            let _ = tx.send(());
        }
    }
}

impl<T: Clone> ShardBackendCell<T> {
    const fn new() -> Self {
        Self {
            state: RefCell::new(BackendState::Empty),
        }
    }

    async fn get_or_init<F, Fut, E>(&self, mut init: F) -> Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        loop {
            let waiter = {
                let mut state = self.state.borrow_mut();
                match &mut *state {
                    BackendState::Ready(value) => return Ok(value.clone()),
                    BackendState::Initializing(waiters) => {
                        let (tx, rx) = oneshot::channel();
                        waiters.push(tx);
                        Some(rx)
                    }
                    BackendState::Empty => {
                        *state = BackendState::Initializing(Vec::new());
                        None
                    }
                }
            };
            if let Some(rx) = waiter {
                let _ = rx.await;
                continue;
            }
            let mut guard = InitGuard {
                cell: self,
                completed: false,
            };
            let result = init().await;
            guard.completed = true;
            let waiters = {
                let mut state = self.state.borrow_mut();
                let previous = match &result {
                    Ok(value) => std::mem::replace(&mut *state, BackendState::Ready(value.clone())),
                    Err(_) => std::mem::replace(&mut *state, BackendState::Empty),
                };
                match previous {
                    BackendState::Initializing(waiters) => waiters,
                    _ => unreachable!("single initializer owns Initializing state"),
                }
            };
            for tx in waiters {
                let _ = tx.send(());
            }
            return result;
        }
    }
}

thread_local! {
    static SHARD_BACKEND: std::rc::Rc<ShardBackendCell<NativeBackend>> =
        std::rc::Rc::new(ShardBackendCell::new());
}

async fn init_shard_backend(outcome: &BodyOutcome) -> Result<NativeBackend, ErrorCode> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls_pure::provider().install_default();
    }
    // No proxy: a guest reaches the network directly.
    let mut transport = Transport::builder().proxy(Proxy::none());
    match helios_api::fs::read(SYSTEM_CA_BUNDLE).await {
        Ok(pem) => {
            transport = transport
                .extra_root_certificates_pem(&pem)
                .map_err(|error| code(&error, outcome))?;
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(ErrorCode::InternalError(Some(format!(
                "reading {SYSTEM_CA_BUNDLE}: {error}"
            ))));
        }
    }
    let transport = transport.build().map_err(|error| code(&error, outcome))?;
    Ok(NativeBackend::on_current_thread(
        transport,
        HeliosNet,
        HeliosNet,
        &HeliosExecutor,
    ))
}

async fn shard_backend(outcome: &BodyOutcome) -> Result<NativeBackend, ErrorCode> {
    let cell = SHARD_BACKEND.with(std::rc::Rc::clone);
    cell.get_or_init(|| init_shard_backend(outcome)).await
}

/// Send the request and turn the response head into the caller's response,
/// leaving its body to stream in a task of its own.
async fn exchange(
    mut http: http::Request<Body>,
    scheme: Scheme,
    outcome: &BodyOutcome,
) -> Result<types::Response, ErrorCode> {
    let mut backend = shard_backend(outcome).await?;
    let response = backend
        .respond(&mut http)
        .await
        .map_err(|error| code(&error, outcome))?;
    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        // Nothing in this client asks for an upgrade, so a switch leaves the
        // connection speaking a protocol it cannot read.
        return Err(ErrorCode::HttpUpgradeFailed);
    }

    let (wasi, contents_writer, trailers_writer) = response::to_wasi(&response)?;
    // The body is still on the wire. Draining it has to outlive this call, so
    // it continues in a task the component-model executor keeps polling after
    // `handle` has produced its response.
    spawn(response::pump(
        response.into_body(),
        scheme,
        contents_writer,
        trailers_writer,
    ));
    Ok(wasi)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use futures_lite::future::{block_on, poll_once, yield_now, zip};

    use super::*;

    #[test]
    fn concurrent_cold_starts_initialize_shard_once() {
        let cell = ShardBackendCell::<u32>::new();
        let calls = Cell::new(0usize);

        let (first, second) = block_on(zip(
            cell.get_or_init(|| async {
                calls.set(calls.get() + 1);
                yield_now().await;
                Ok::<u32, &'static str>(42)
            }),
            cell.get_or_init(|| async {
                calls.set(calls.get() + 1);
                Ok::<u32, &'static str>(99)
            }),
        ));

        assert_eq!(first, Ok(42));
        assert_eq!(second, Ok(42));
        assert_eq!(calls.get(), 1);

        // Subsequent calls hit the cached value directly without re-running init.
        let third = block_on(cell.get_or_init(|| async {
            calls.set(calls.get() + 1);
            Ok::<u32, &'static str>(7)
        }));
        assert_eq!(third, Ok(42));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn failed_or_cancelled_init_resets_and_wakes_waiters() {
        let cell = ShardBackendCell::<u32>::new();
        let calls = Cell::new(0usize);

        // Cancelled cold start resets back to Empty so the waiter can initialize.
        {
            let pending_leader = std::pin::pin!(cell.get_or_init(|| async {
                calls.set(calls.get() + 1);
                yield_now().await;
                Ok::<u32, &'static str>(1)
            }));
            assert!(block_on(poll_once(pending_leader)).is_none());
        }

        // First real attempt fails; second retries and succeeds.
        let failed = block_on(cell.get_or_init(|| async {
            calls.set(calls.get() + 1);
            Err::<u32, &'static str>("boom")
        }));
        assert_eq!(failed, Err("boom"));

        let succeeded = block_on(cell.get_or_init(|| async {
            calls.set(calls.get() + 1);
            Ok::<u32, &'static str>(77)
        }));
        assert_eq!(succeeded, Ok(77));
        assert_eq!(calls.get(), 3);
    }
}
