//! Privilege-separated inspector host component (`/inspector`, `inspector-host`).
//!
//! Responsibilities:
//! 1. Loads `/etc/inspector/policy.postcard` (`AuthPolicy`).
//! 2. Listens on inbound `tcp` (default port 9443), `vsock` (port 1024), or
//!    `serial` (when vsock is absent), honoring any inherited sockets from
//!    `component-manager` first.
//! 3. Authenticates every inbound connection via unified Ed25519 + `postcard`
//!    (`StaticKey` or CA-signed short-lived `CapabilityCert` + offline monotonic
//!    attenuation), signing handshake challenges with `helios:system/machine-identity`.
//! 4. For TCP: spawns zero-authority `/bin/inspector-tls` (`ProcessAuthority::empty()`)
//!    with `InheritedSocket::TcpStream` + `control` and `data` IPC channels;
//!    after verifying `ClientAuth`, spawns attenuated `/bin/inspector-worker`
//!    with the peer half of `data` (`ipc::take("rpc")`), drops `control`, and
//!    exits the post-handshake data path completely.
//! 5. For vsock/serial: verifies `ClientAuth` directly over an unbuffered stream,
//!    spawns attenuated `/bin/inspector-worker` with `InheritedSocket::VsockStream`
//!    or `InheritedSocket::Serial`, and exits the post-handshake data path.

mod component_control;
mod grants;
mod transport_io;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::stream::{FuturesUnordered, StreamExt as _};
use helios_api::ipc;
use helios_api::machine_identity;
use helios_api::net::{IpAddress, TcpListener, TcpStream};
use helios_api::programs::{
    self, Child, InheritedSocket, SpawnRequest, ipc_grant, take_inherited_sockets,
};
use helios_api::serial::{self, DebugPort};
use helios_api::vsock::{self, VsockListener, VsockStream};
use helios_component_manager::OomTier;
use helios_inspector_protocol::VSOCK_RPC_PORT;
use helios_inspector_protocol::auth::{
    AUTH_PROTOCOL_VERSION, AccountPolicy, AuthError, AuthPolicy, AuthorizedAccount,
    DEFAULT_INSPECTOR_TCP_PORT, HELIOS_ACCOUNTS_POLICY_PATH, INSPECTOR_POLICY_PATH,
    MACHINE_IDENTITY_HANDSHAKE_DOMAIN, ServerAuthResult, ServerHello, SessionGrants,
    TlsControlRequest, TlsControlResponse, TransportKind, compute_handshake_challenge, random_32,
    read_auth_message, server_handshake_with_accounts, verify_client_auth_with_accounts,
    write_auth_message,
};

use crate::grants::{
    compiled_tls_ceiling, compiled_tls_oom_tier, compiled_worker_ceiling, compiled_worker_oom_tier,
    session_grants_to_kernel,
};
use crate::transport_io::{IpcIo, UnbufferedSerialIo, UnbufferedVsockIo};

const INSPECTOR_TLS_PATH: &str = "/bin/inspector-tls";
const INSPECTOR_WORKER_PATH: &str = "/bin/inspector-worker";
const LISTENER_BACKLOG: u16 = 32;
const VSOCK_BACKLOG: u32 = 32;
/// Maximum concurrent in-flight unauthenticated handshakes across TCP and vsock.
const MAX_CONCURRENT_HANDSHAKES: usize = 16;
/// Deadline for completing the TLS/auth handshake before aborting the session
/// and terminating `inspector-tls`.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Brief grace window for `inspector-tls` to flush an `AuthDecision::Rejected`
/// or final TLS `close_notify` before `SIGKILL`.
const TLS_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
/// POSIX `SIGKILL` signal number delivered via `Child::signal`.
const SIGKILL: u8 = 9;

struct HandshakeLimiter {
    tx: helios_api::channel::Sender<()>,
    rx: helios_api::channel::Receiver<()>,
}

struct HandshakePermit {
    tx: helios_api::channel::Sender<()>,
}

impl HandshakeLimiter {
    fn new(limit: usize) -> Self {
        let cap = limit.max(1);
        let (tx, rx) = helios_api::channel::bounded(cap);
        for _ in 0..cap {
            let _ = tx.try_send(());
        }
        Self { tx, rx }
    }

    async fn acquire(&self) -> HandshakePermit {
        let _ = self.rx.recv().await;
        HandshakePermit {
            tx: self.tx.clone(),
        }
    }
}

impl Drop for HandshakePermit {
    fn drop(&mut self) {
        let _ = self.tx.try_send(());
    }
}

async fn with_timeout<F, T>(duration: Duration, fut: F) -> Option<T>
where
    F: Future<Output = T>,
{
    let mut fut = std::pin::pin!(fut);
    let mut timer = std::pin::pin!(helios_api::task::sleep(duration));
    match futures_util::future::select(fut.as_mut(), timer.as_mut()).await {
        futures_util::future::Either::Left((val, _)) => Some(val),
        futures_util::future::Either::Right(((), _)) => None,
    }
}

/// Immediately sends `SIGKILL` to `child` and waits for the kernel to reap it.
async fn kill_and_reap(child: Child) {
    let _ = child.signal(SIGKILL);
    let _ = child.wait().await;
}

/// Gives `child` a short grace period to exit cleanly, then force-kills and
/// reaps it so a stalled remote TCP peer cannot pin a `tls_child` forever.
async fn reap_with_grace_or_kill(child: Child, grace: Duration) {
    if with_timeout(grace, child.wait_exit()).await.is_some() {
        return;
    }
    kill_and_reap(child).await;
}

/// Generates a fresh CSPRNG `server_nonce` inside `inspector-host` and signs
/// the TLS 1.3 channel binding and ephemeral cert digest with `MachineIdentity`.
fn sign_tls_handshake_with<F>(
    machine_public_key: [u8; 32],
    now_unix: u64,
    channel_binding: [u8; 32],
    tls_spki_sha256: [u8; 32],
    sign_challenge: F,
) -> Result<ServerHello, AuthError>
where
    F: FnOnce(&[u8; 32]) -> Result<[u8; 64], AuthError>,
{
    let server_nonce = random_32()?;
    let challenge = compute_handshake_challenge(
        AUTH_PROTOCOL_VERSION,
        TransportKind::TcpTls,
        server_nonce,
        now_unix,
        Some(channel_binding),
        Some(tls_spki_sha256),
    );
    let machine_signature = sign_challenge(&challenge)?;
    Ok(ServerHello {
        protocol_version: AUTH_PROTOCOL_VERSION,
        transport: TransportKind::TcpTls,
        machine_public_key,
        server_nonce,
        server_unix_time: now_unix,
        tls_binding_required: true,
        machine_signature,
    })
}

struct HostContext {
    policy: AuthPolicy,
    accounts: Vec<AuthorizedAccount>,
    tls_ceiling: SessionGrants,
    worker_ceiling: SessionGrants,
    machine_public_key: [u8; 32],
    next_session_id: AtomicU64,
    handshake_limiter: HandshakeLimiter,
    component_control_upstream: Option<Arc<helios_wit_rpc::PeerHandle>>,
}

impl HostContext {
    fn next_session(&self) -> u64 {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
    }

    fn sign_challenge(&self, challenge: &[u8; 32]) -> Result<[u8; 64], AuthError> {
        let sig = machine_identity::sign(MACHINE_IDENTITY_HANDSHAKE_DOMAIN, challenge).map_err(
            |err| AuthError::Malformed {
                detail: format!("machine-identity.sign failed: {err:?}"),
            },
        )?;
        sig.try_into().map_err(|raw: Vec<u8>| AuthError::Malformed {
            detail: format!("machine-identity returned {}-byte signature", raw.len()),
        })
    }
}

fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load_policy() -> Result<AuthPolicy, String> {
    let bytes = std::fs::read(INSPECTOR_POLICY_PATH).map_err(|err| {
        format!("failed to read inspector auth policy `{INSPECTOR_POLICY_PATH}`: {err}")
    })?;
    AuthPolicy::decode_postcard(&bytes)
        .map_err(|err| format!("failed to decode `{INSPECTOR_POLICY_PATH}`: {err}"))
}

fn load_accounts_from_path(path: &std::path::Path) -> Result<Vec<AuthorizedAccount>, String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(format!(
                "failed to read operator accounts policy `{}`: {err}",
                path.display()
            ));
        }
    };
    AccountPolicy::decode_postcard(&bytes)
        .map(|policy| policy.accounts)
        .map_err(|err| {
            format!(
                "failed to decode operator accounts policy `{}`: {err}",
                path.display()
            )
        })
}

fn load_accounts() -> Result<Vec<AuthorizedAccount>, String> {
    load_accounts_from_path(std::path::Path::new(HELIOS_ACCOUNTS_POLICY_PATH))
}

fn read_machine_public_key() -> Result<[u8; 32], String> {
    let raw = machine_identity::public_key()
        .map_err(|err| format!("machine-identity.public-key failed: {err:?}"))?;
    raw.try_into().map_err(|bytes: Vec<u8>| {
        format!(
            "machine-identity returned {}-byte public key (expected 32)",
            bytes.len()
        )
    })
}

fn configured_tcp_port() -> u16 {
    std::env::var("HELIOS_INSPECTOR_TCP_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(DEFAULT_INSPECTOR_TCP_PORT)
}

type LoopFuture = Pin<Box<dyn Future<Output = Result<(), String>>>>;

struct ComponentControlBridge {
    host_endpoint: ipc::Endpoint,
    upstream: Arc<helios_wit_rpc::PeerHandle>,
    scope: helios_inspector_protocol::auth::ScopeRule,
}

#[helios_api::main]
async fn main() -> Result<(), String> {
    let policy = load_policy()?;
    let accounts = load_accounts()?;
    let machine_public_key = read_machine_public_key()?;

    let mut loops: FuturesUnordered<LoopFuture> = FuturesUnordered::new();

    let component_control_upstream = if let Some(ep) = ipc::take("component-control") {
        let (peer, driver) = component_control::connect_upstream(ep);
        loops.push(Box::pin(async move {
            driver.await;
            Ok(())
        }));
        Some(Arc::new(peer))
    } else {
        None
    };

    if compiled_tls_oom_tier() != OomTier::User {
        return Err(format!(
            "unsupported /inspector/tls oom_tier `{}` (expected `user`)",
            compiled_tls_oom_tier().as_str()
        ));
    }
    if compiled_worker_oom_tier() != OomTier::User {
        return Err(format!(
            "unsupported /inspector/worker oom_tier `{}` (expected `user`)",
            compiled_worker_oom_tier().as_str()
        ));
    }

    let ctx = Arc::new(HostContext {
        policy,
        accounts,
        tls_ceiling: compiled_tls_ceiling(),
        worker_ceiling: compiled_worker_ceiling(),
        machine_public_key,
        next_session_id: AtomicU64::new(1),
        handshake_limiter: HandshakeLimiter::new(MAX_CONCURRENT_HANDSHAKES),
        component_control_upstream,
    });

    let mut tcp_listener: Option<TcpListener> = None;
    let mut vsock_listener: Option<VsockListener> = None;

    for sock in take_inherited_sockets() {
        match sock {
            InheritedSocket::Tcp(raw) if tcp_listener.is_none() => {
                let mut listener = TcpListener::from_raw(raw);
                listener.set_timeout(Duration::from_nanos(u64::MAX));
                tcp_listener = Some(listener);
            }
            InheritedSocket::Vsock(raw) if vsock_listener.is_none() => {
                let mut listener = VsockListener::from_raw(raw);
                listener.set_timeout(vsock::NO_DEADLINE);
                vsock_listener = Some(listener);
            }
            _ => {}
        }
    }

    if vsock_listener.is_none() && vsock::guest_cid().await.is_some() {
        let mut listener = VsockListener::bind(VSOCK_RPC_PORT, VSOCK_BACKLOG)
            .await
            .map_err(|err| {
                format!("failed to bind inspector vsock port {VSOCK_RPC_PORT}: {err}")
            })?;
        listener.set_timeout(vsock::NO_DEADLINE);
        vsock_listener = Some(listener);
    }

    if tcp_listener.is_none() {
        let port = configured_tcp_port();
        if let Ok(mut listener) =
            TcpListener::listen(IpAddress::Ipv4((0, 0, 0, 0)), port, LISTENER_BACKLOG).await
        {
            listener.set_timeout(Duration::from_nanos(u64::MAX));
            tcp_listener = Some(listener);
        }
    }

    let use_serial = vsock_listener.is_none();

    if let Some(listener) = tcp_listener {
        let ctx = Arc::clone(&ctx);
        loops.push(Box::pin(run_tcp_accept_loop(ctx, listener)));
    }
    if let Some(listener) = vsock_listener {
        let ctx = Arc::clone(&ctx);
        loops.push(Box::pin(run_vsock_accept_loop(ctx, listener)));
    }
    if use_serial {
        let ctx = Arc::clone(&ctx);
        loops.push(Box::pin(run_serial_loop(ctx)));
    }

    if loops.is_empty() {
        return Err("inspector-host has no available tcp, vsock, or serial transport".to_owned());
    }

    while let Some(res) = loops.next().await {
        if let Err(err) = res {
            eprintln!("inspector-host transport loop ended: {err}");
        }
    }
    Ok(())
}

async fn run_tcp_accept_loop(ctx: Arc<HostContext>, listener: TcpListener) -> Result<(), String> {
    let mut sessions: FuturesUnordered<Pin<Box<dyn Future<Output = ()>>>> = FuturesUnordered::new();
    let mut next_accept = Box::pin(accept_tcp_owned(Arc::clone(&ctx), listener));

    loop {
        if sessions.is_empty() {
            let (listener_back, permit, accepted) = next_accept.await;
            next_accept = Box::pin(accept_tcp_owned(Arc::clone(&ctx), listener_back));
            match accepted {
                Ok(stream) => {
                    let ctx = Arc::clone(&ctx);
                    sessions.push(Box::pin(handle_tcp_session(ctx, stream, permit)));
                }
                Err(err) => {
                    drop(permit);
                    eprintln!("inspector-host tcp accept error: {err}");
                }
            }
        } else {
            match futures_util::future::select(next_accept.as_mut(), sessions.next()).await {
                futures_util::future::Either::Left(((listener_back, permit, accepted), _)) => {
                    next_accept.set(accept_tcp_owned(Arc::clone(&ctx), listener_back));
                    match accepted {
                        Ok(stream) => {
                            let ctx = Arc::clone(&ctx);
                            sessions.push(Box::pin(handle_tcp_session(ctx, stream, permit)));
                        }
                        Err(err) => {
                            drop(permit);
                            eprintln!("inspector-host tcp accept error: {err}");
                        }
                    }
                }
                futures_util::future::Either::Right((_, _)) => {}
            }
        }
    }
}

async fn accept_tcp_owned(
    ctx: Arc<HostContext>,
    listener: TcpListener,
) -> (TcpListener, HandshakePermit, std::io::Result<TcpStream>) {
    let permit = ctx.handshake_limiter.acquire().await;
    let res = listener.accept().await;
    (listener, permit, res)
}

enum TcpHandshakeOutcome {
    Accepted(Child, Option<ComponentControlBridge>),
    Rejected,
    Abort,
}

async fn run_tcp_control_handshake(
    ctx: &HostContext,
    session_id: u64,
    ctrl_io: &mut IpcIo,
    worker_data: ipc::Endpoint,
) -> TcpHandshakeOutcome {
    // Step 1: Receive `SignHandshake` from `inspector-tls`, generate a fresh
    // CSPRNG `server_nonce` inside `inspector-host`, and sign via `MachineIdentity`.
    let req: TlsControlRequest = match read_auth_message(ctrl_io).await {
        Ok(req) => req,
        Err(err) => {
            eprintln!("inspector-host session {session_id}: control read failed: {err}");
            return TcpHandshakeOutcome::Abort;
        }
    };
    let (expected_binding, signed_hello) = match req {
        TlsControlRequest::SignHandshake {
            channel_binding,
            tls_spki_sha256,
        } => {
            let now = current_unix_time();
            match sign_tls_handshake_with(
                ctx.machine_public_key,
                now,
                channel_binding,
                tls_spki_sha256,
                |challenge| ctx.sign_challenge(challenge),
            ) {
                Ok(hello) => (channel_binding, hello),
                Err(err) => {
                    let _ =
                        write_auth_message(ctrl_io, &TlsControlResponse::Error(err.to_string()))
                            .await;
                    return TcpHandshakeOutcome::Abort;
                }
            }
        }
        other => {
            let _ = write_auth_message(
                ctrl_io,
                &TlsControlResponse::Error(format!("expected SignHandshake, got {other:?}")),
            )
            .await;
            return TcpHandshakeOutcome::Abort;
        }
    };

    if write_auth_message(
        ctrl_io,
        &TlsControlResponse::HandshakeSigned(signed_hello.clone()),
    )
    .await
    .is_err()
    {
        return TcpHandshakeOutcome::Abort;
    }

    // Step 2: Receive `ClientAuth` forwarded by `inspector-tls`, verify Ed25519
    // credentials + RFC 8446 channel binding, and spawn attenuated `inspector-worker`.
    let auth_req: TlsControlRequest = match read_auth_message(ctrl_io).await {
        Ok(req) => req,
        Err(_) => return TcpHandshakeOutcome::Abort,
    };
    match auth_req {
        TlsControlRequest::Authenticate {
            server_hello,
            channel_binding,
            client_auth,
        } => {
            if server_hello != signed_hello || channel_binding != expected_binding {
                let decision = ServerAuthResult::Rejected {
                    code: helios_inspector_protocol::auth::AuthRejectCode::WrongChannelBinding,
                    detail: "TLS handshake transcript or channel binding mismatch".to_owned(),
                };
                let _ =
                    write_auth_message(ctrl_io, &TlsControlResponse::AuthDecision(decision)).await;
                TcpHandshakeOutcome::Rejected
            } else {
                let now = current_unix_time();
                match verify_client_auth_with_accounts(
                    &ctx.policy,
                    &ctx.accounts,
                    &ctx.worker_ceiling,
                    &signed_hello,
                    Some(expected_binding),
                    &client_auth,
                    now,
                ) {
                    Ok(verified) => {
                        let effective = verified.granted.intersect(&ctx.worker_ceiling);
                        let mut grants = session_grants_to_kernel(&effective);
                        grants.push(ipc_grant("rpc", worker_data));
                        let cc_task = attach_component_control(
                            ctx,
                            &effective.component_control,
                            &mut grants,
                        );
                        match programs::spawn(SpawnRequest {
                            name: format!("inspector-worker-{session_id}"),
                            args: Vec::new(),
                            env: Vec::new(),
                            path: INSPECTOR_WORKER_PATH.to_owned(),
                            cwd: None,
                            sockets: Vec::new(),
                            capability_grants: grants,
                        })
                        .await
                        {
                            Ok(worker) => {
                                let decision = ServerAuthResult::Accepted {
                                    granted: effective,
                                    session_id,
                                };
                                let _ = write_auth_message(
                                    ctrl_io,
                                    &TlsControlResponse::AuthDecision(decision),
                                )
                                .await;
                                TcpHandshakeOutcome::Accepted(worker, cc_task)
                            }
                            Err(err) => {
                                let decision = ServerAuthResult::Rejected {
                                    code: helios_inspector_protocol::auth::AuthRejectCode::Internal,
                                    detail: format!("failed to spawn inspector-worker: {err:?}"),
                                };
                                let _ = write_auth_message(
                                    ctrl_io,
                                    &TlsControlResponse::AuthDecision(decision),
                                )
                                .await;
                                TcpHandshakeOutcome::Rejected
                            }
                        }
                    }
                    Err(err) => {
                        let decision = ServerAuthResult::Rejected {
                            code: err.reject_code(),
                            detail: err.to_string(),
                        };
                        let _ = write_auth_message(
                            ctrl_io,
                            &TlsControlResponse::AuthDecision(decision),
                        )
                        .await;
                        TcpHandshakeOutcome::Rejected
                    }
                }
            }
        }
        other => {
            let _ = write_auth_message(
                ctrl_io,
                &TlsControlResponse::Error(format!("expected Authenticate, got {other:?}")),
            )
            .await;
            TcpHandshakeOutcome::Abort
        }
    }
}

async fn handle_tcp_session(
    ctx: Arc<HostContext>,
    stream: TcpStream,
    handshake_permit: HandshakePermit,
) {
    let session_id = ctx.next_session();
    let (host_ctrl, tls_ctrl) = ipc::channel();
    let (tls_data, worker_data) = ipc::channel();

    // Spawn `inspector-tls` strictly bounded by the compiled `/inspector/tls`
    // manifest ceiling (empty authority by default) plus only the session's
    // accepted TCP stream and `control`/`data` IPC endpoints.
    let mut tls_grants = session_grants_to_kernel(&ctx.tls_ceiling);
    tls_grants.push(ipc_grant("control", tls_ctrl));
    tls_grants.push(ipc_grant("data", tls_data));
    let tls_child = match programs::spawn(SpawnRequest {
        name: format!("inspector-tls-{session_id}"),
        args: Vec::new(),
        env: Vec::new(),
        path: INSPECTOR_TLS_PATH.to_owned(),
        cwd: None,
        sockets: vec![InheritedSocket::TcpStream(stream.into_raw())],
        capability_grants: tls_grants,
    })
    .await
    {
        Ok(child) => child,
        Err(err) => {
            eprintln!("inspector-host failed to spawn inspector-tls: {err:?}");
            return;
        }
    };

    let mut ctrl_io = IpcIo::new(host_ctrl);
    let outcome = with_timeout(
        HANDSHAKE_TIMEOUT,
        run_tcp_control_handshake(&ctx, session_id, &mut ctrl_io, worker_data),
    )
    .await;

    // Drop the control channel immediately — `inspector-host` is now 100% off
    // the post-handshake data path (`inspector-tls` <-> `inspector-worker` flow
    // directly over `data`/`rpc` IPC).
    drop(ctrl_io);

    match outcome {
        Some(TcpHandshakeOutcome::Accepted(worker, cc_task)) => {
            // Release the handshake slot as soon as authentication succeeds so
            // long-lived sessions never starve new handshakes.
            drop(handshake_permit);
            wait_worker_and_control(worker, cc_task).await;
            reap_with_grace_or_kill(tls_child, TLS_SHUTDOWN_GRACE).await;
        }
        Some(TcpHandshakeOutcome::Rejected) => {
            reap_with_grace_or_kill(tls_child, TLS_SHUTDOWN_GRACE).await;
            drop(handshake_permit);
        }
        Some(TcpHandshakeOutcome::Abort) => {
            kill_and_reap(tls_child).await;
            drop(handshake_permit);
        }
        None => {
            eprintln!("inspector-host session {session_id}: handshake timed out");
            kill_and_reap(tls_child).await;
            drop(handshake_permit);
        }
    }
}

fn attach_component_control(
    ctx: &HostContext,
    scope: &Option<helios_inspector_protocol::auth::ScopeRule>,
    grants: &mut Vec<programs::CapabilityGrant>,
) -> Option<ComponentControlBridge> {
    let upstream = ctx.component_control_upstream.as_ref()?;
    let scope = scope.clone()?;
    let (host_cc, worker_cc) = ipc::channel();
    grants.push(ipc_grant("component-control", worker_cc));
    Some(ComponentControlBridge {
        host_endpoint: host_cc,
        upstream: Arc::clone(upstream),
        scope,
    })
}

async fn wait_worker_and_control(worker: Child, cc_bridge: Option<ComponentControlBridge>) {
    match cc_bridge {
        Some(bridge) => {
            let wait_fut = async move {
                let _ = worker.wait().await;
            };
            let cc_fut = component_control::serve_worker_control(
                bridge.host_endpoint,
                bridge.upstream,
                bridge.scope,
            );
            futures_util::future::join(wait_fut, cc_fut).await;
        }
        None => {
            let _ = worker.wait().await;
        }
    }
}

async fn run_vsock_accept_loop(
    ctx: Arc<HostContext>,
    listener: VsockListener,
) -> Result<(), String> {
    let mut sessions: FuturesUnordered<Pin<Box<dyn Future<Output = ()>>>> = FuturesUnordered::new();
    let mut next_accept = Box::pin(accept_vsock_owned(Arc::clone(&ctx), listener));

    loop {
        if sessions.is_empty() {
            let (listener_back, permit, accepted) = next_accept.await;
            next_accept = Box::pin(accept_vsock_owned(Arc::clone(&ctx), listener_back));
            match accepted {
                Ok(stream) => {
                    let ctx = Arc::clone(&ctx);
                    sessions.push(Box::pin(handle_vsock_session(ctx, stream, permit)));
                }
                Err(err) => {
                    drop(permit);
                    eprintln!("inspector-host vsock accept error: {err}");
                }
            }
        } else {
            match futures_util::future::select(next_accept.as_mut(), sessions.next()).await {
                futures_util::future::Either::Left(((listener_back, permit, accepted), _)) => {
                    next_accept.set(accept_vsock_owned(Arc::clone(&ctx), listener_back));
                    match accepted {
                        Ok(stream) => {
                            let ctx = Arc::clone(&ctx);
                            sessions.push(Box::pin(handle_vsock_session(ctx, stream, permit)));
                        }
                        Err(err) => {
                            drop(permit);
                            eprintln!("inspector-host vsock accept error: {err}");
                        }
                    }
                }
                futures_util::future::Either::Right((_, _)) => {}
            }
        }
    }
}

async fn accept_vsock_owned(
    ctx: Arc<HostContext>,
    listener: VsockListener,
) -> (VsockListener, HandshakePermit, std::io::Result<VsockStream>) {
    let permit = ctx.handshake_limiter.acquire().await;
    let res = listener.accept().await;
    (listener, permit, res)
}

async fn handle_vsock_session(
    ctx: Arc<HostContext>,
    mut stream: VsockStream,
    handshake_permit: HandshakePermit,
) {
    stream.set_timeout(vsock::NO_DEADLINE);
    let session_id = ctx.next_session();
    let mut io = UnbufferedVsockIo::new(stream);
    let now = current_unix_time();

    let verified = {
        let (mut read, mut write) = futures_util::AsyncReadExt::split(&mut io);
        match with_timeout(
            HANDSHAKE_TIMEOUT,
            server_handshake_with_accounts(
                &mut read,
                &mut write,
                TransportKind::Vsock,
                &ctx.policy,
                &ctx.accounts,
                &ctx.worker_ceiling,
                ctx.machine_public_key,
                now,
                session_id,
                None,
                None,
                |challenge| ctx.sign_challenge(challenge),
            ),
        )
        .await
        {
            Some(Ok(v)) => v,
            Some(Err(err)) => {
                eprintln!("inspector-host vsock session {session_id} rejected: {err}");
                return;
            }
            None => {
                eprintln!("inspector-host vsock session {session_id} handshake timed out");
                return;
            }
        }
    };

    drop(handshake_permit);

    // Hand the connected `VsockStream` directly to the attenuated worker and
    // exit the post-handshake data path completely.
    let stream = io.into_inner();
    let effective = verified.granted.intersect(&ctx.worker_ceiling);
    let mut grants = session_grants_to_kernel(&effective);
    let cc_task = attach_component_control(&ctx, &effective.component_control, &mut grants);
    match programs::spawn(SpawnRequest {
        name: format!("inspector-worker-{session_id}"),
        args: Vec::new(),
        env: Vec::new(),
        path: INSPECTOR_WORKER_PATH.to_owned(),
        cwd: None,
        sockets: vec![InheritedSocket::VsockStream(stream.into_raw())],
        capability_grants: grants,
    })
    .await
    {
        Ok(worker) => {
            wait_worker_and_control(worker, cc_task).await;
        }
        Err(err) => {
            eprintln!("inspector-host failed to spawn vsock worker {session_id}: {err:?}");
        }
    }
}

async fn run_serial_loop(ctx: Arc<HostContext>) -> Result<(), String> {
    loop {
        let Some(port) = serial::debug_port().await else {
            return Err("debug serial port is unavailable".to_owned());
        };
        handle_serial_session(Arc::clone(&ctx), port).await;
    }
}

async fn handle_serial_session(ctx: Arc<HostContext>, port: DebugPort) {
    let session_id = ctx.next_session();
    let mut io = UnbufferedSerialIo::new(port);
    let now = current_unix_time();

    let verified = {
        let (mut read, mut write) = futures_util::AsyncReadExt::split(&mut io);
        match server_handshake_with_accounts(
            &mut read,
            &mut write,
            TransportKind::Serial,
            &ctx.policy,
            &ctx.accounts,
            &ctx.worker_ceiling,
            ctx.machine_public_key,
            now,
            session_id,
            None,
            None,
            |challenge| ctx.sign_challenge(challenge),
        )
        .await
        {
            Ok(v) => v,
            Err(err) => {
                eprintln!("inspector-host serial session {session_id} rejected: {err}");
                return;
            }
        }
    };

    // Move `DebugPort` straight into the attenuated `inspector-worker` so
    // `inspector-host` exits the post-handshake data path.
    let port = io.into_inner();
    let effective = verified.granted.intersect(&ctx.worker_ceiling);
    let mut grants = session_grants_to_kernel(&effective);
    let cc_task = attach_component_control(&ctx, &effective.component_control, &mut grants);
    match programs::spawn(SpawnRequest {
        name: format!("inspector-worker-{session_id}"),
        args: Vec::new(),
        env: Vec::new(),
        path: INSPECTOR_WORKER_PATH.to_owned(),
        cwd: None,
        sockets: vec![InheritedSocket::Serial(port.into_raw())],
        capability_grants: grants,
    })
    .await
    {
        Ok(worker) => {
            wait_worker_and_control(worker, cc_task).await;
        }
        Err(err) => {
            eprintln!("inspector-host failed to spawn serial worker {session_id}: {err:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use helios_inspector_protocol::auth::{sign_machine_identity_seed, verify_server_hello};

    use super::*;

    #[test]
    fn host_generates_fresh_server_nonce_independently_of_tls_request() {
        let machine_seed = [0x42; 32];
        let machine_pub =
            helios_inspector_protocol::auth::ClientIdentity::from_static_seed(machine_seed)
                .public_key();
        let binding = [0x11; 32];
        let spki = [0x22; 32];

        let hello_a =
            sign_tls_handshake_with(machine_pub, 1_700_000_000, binding, spki, |challenge| {
                Ok(sign_machine_identity_seed(
                    &machine_seed,
                    MACHINE_IDENTITY_HANDSHAKE_DOMAIN,
                    challenge,
                ))
            })
            .expect("first host-signed hello");
        let hello_b =
            sign_tls_handshake_with(machine_pub, 1_700_000_000, binding, spki, |challenge| {
                Ok(sign_machine_identity_seed(
                    &machine_seed,
                    MACHINE_IDENTITY_HANDSHAKE_DOMAIN,
                    challenge,
                ))
            })
            .expect("second host-signed hello");

        assert_ne!(hello_a.server_nonce, [0u8; 32]);
        assert_ne!(hello_b.server_nonce, [0u8; 32]);
        assert_ne!(
            hello_a.server_nonce, hello_b.server_nonce,
            "inspector-host must generate a fresh CSPRNG server_nonce per handshake"
        );
        verify_server_hello(
            &hello_a,
            TransportKind::TcpTls,
            Some(machine_pub),
            Some(binding),
            Some(spki),
        )
        .expect("hello_a signature must verify");
        verify_server_hello(
            &hello_b,
            TransportKind::TcpTls,
            Some(machine_pub),
            Some(binding),
            Some(spki),
        )
        .expect("hello_b signature must verify");
    }

    #[test]
    fn handshake_limiter_enforces_concurrency_cap_and_releases_on_drop() {
        futures_lite::future::block_on(async {
            let limiter = HandshakeLimiter::new(2);
            let p1 = limiter.acquire().await;
            let p2 = limiter.acquire().await;
            let mut third = std::pin::pin!(limiter.acquire());
            assert!(
                futures_lite::future::poll_once(third.as_mut())
                    .await
                    .is_none(),
                "third handshake must park when cap is reached"
            );
            drop(p1);
            let p3 = third.await;
            drop(p2);
            drop(p3);
        });
    }

    #[test]
    fn load_accounts_handles_missing_valid_and_corrupt_policy_files() {
        use helios_inspector_protocol::auth::{AuthPublicKey, TransportMask};

        let temp_dir = std::env::temp_dir().join(format!(
            "helios-inspector-host-accounts-test-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&temp_dir);

        let missing = temp_dir.join("missing.postcard");
        assert!(
            load_accounts_from_path(&missing)
                .expect("missing accounts policy yields empty vec")
                .is_empty()
        );

        let seed = [0x33; 32];
        let pub_key = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let account = AuthorizedAccount {
            username: "lexo".to_owned(),
            public_key: AuthPublicKey::Ed25519(pub_key),
            grants: SessionGrants::full_worker_ceiling(),
            allowed_transports: TransportMask::ALL,
        };
        let policy = AccountPolicy::single_account(account.clone());
        let valid_path = temp_dir.join("valid.postcard");
        std::fs::write(
            &valid_path,
            policy.encode_postcard().expect("encode account policy"),
        )
        .expect("write valid policy");
        let loaded = load_accounts_from_path(&valid_path).expect("load valid policy");
        assert_eq!(loaded, vec![account]);

        let corrupt_path = temp_dir.join("corrupt.postcard");
        std::fs::write(&corrupt_path, b"\xff\xfe\xfd").expect("write corrupt policy");
        assert!(
            load_accounts_from_path(&corrupt_path).is_err(),
            "corrupt accounts policy must fail fast"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
