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
use helios_inspector_protocol::VSOCK_RPC_PORT;
use helios_inspector_protocol::auth::{
    AUTH_PROTOCOL_VERSION, AuthError, AuthPolicy, DEFAULT_INSPECTOR_TCP_PORT,
    INSPECTOR_POLICY_PATH, MACHINE_IDENTITY_HANDSHAKE_DOMAIN, ServerAuthResult, ServerHello,
    SessionGrants, TlsControlRequest, TlsControlResponse, TransportKind,
    compute_handshake_challenge, read_auth_message, server_handshake, verify_client_auth,
    write_auth_message,
};

use crate::grants::session_grants_to_kernel;
use crate::transport_io::{IpcIo, UnbufferedSerialIo, UnbufferedVsockIo};

const INSPECTOR_TLS_PATH: &str = "/bin/inspector-tls";
const INSPECTOR_WORKER_PATH: &str = "/bin/inspector-worker";
const LISTENER_BACKLOG: u16 = 32;
const VSOCK_BACKLOG: u32 = 32;

struct HostContext {
    policy: AuthPolicy,
    worker_ceiling: SessionGrants,
    machine_public_key: [u8; 32],
    next_session_id: AtomicU64,
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

    let ctx = Arc::new(HostContext {
        policy,
        worker_ceiling: SessionGrants::full_worker_ceiling(),
        machine_public_key,
        next_session_id: AtomicU64::new(1),
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
    let mut next_accept = Box::pin(accept_tcp_owned(listener));

    loop {
        if sessions.is_empty() {
            let (listener_back, accepted) = next_accept.await;
            next_accept = Box::pin(accept_tcp_owned(listener_back));
            match accepted {
                Ok(stream) => {
                    let ctx = Arc::clone(&ctx);
                    sessions.push(Box::pin(handle_tcp_session(ctx, stream)));
                }
                Err(err) => {
                    eprintln!("inspector-host tcp accept error: {err}");
                }
            }
        } else {
            match futures_util::future::select(next_accept.as_mut(), sessions.next()).await {
                futures_util::future::Either::Left(((listener_back, accepted), _)) => {
                    next_accept.set(accept_tcp_owned(listener_back));
                    match accepted {
                        Ok(stream) => {
                            let ctx = Arc::clone(&ctx);
                            sessions.push(Box::pin(handle_tcp_session(ctx, stream)));
                        }
                        Err(err) => {
                            eprintln!("inspector-host tcp accept error: {err}");
                        }
                    }
                }
                futures_util::future::Either::Right((_, _)) => {}
            }
        }
    }
}

async fn accept_tcp_owned(listener: TcpListener) -> (TcpListener, std::io::Result<TcpStream>) {
    let res = listener.accept().await;
    (listener, res)
}

async fn handle_tcp_session(ctx: Arc<HostContext>, stream: TcpStream) {
    let session_id = ctx.next_session();
    let (host_ctrl, tls_ctrl) = ipc::channel();
    let (tls_data, worker_data) = ipc::channel();

    // Spawn zero-authority `inspector-tls` (`ProcessAuthority::empty()`):
    // holds ONLY the accepted TCP stream plus `control` and `data` IPC endpoints.
    let tls_child = match programs::spawn(SpawnRequest {
        name: format!("inspector-tls-{session_id}"),
        args: Vec::new(),
        env: Vec::new(),
        path: INSPECTOR_TLS_PATH.to_owned(),
        cwd: None,
        sockets: vec![InheritedSocket::TcpStream(stream.into_raw())],
        capability_grants: vec![ipc_grant("control", tls_ctrl), ipc_grant("data", tls_data)],
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

    // Step 1: Receive `SignHandshake` from `inspector-tls` and sign via `MachineIdentity`.
    let req: TlsControlRequest = match read_auth_message(&mut ctrl_io).await {
        Ok(req) => req,
        Err(err) => {
            eprintln!("inspector-host session {session_id}: control read failed: {err}");
            let _ = tls_child.wait().await;
            return;
        }
    };
    let (expected_binding, signed_hello) = match req {
        TlsControlRequest::SignHandshake {
            channel_binding,
            tls_spki_sha256,
            server_nonce,
        } => {
            let now = current_unix_time();
            let challenge = compute_handshake_challenge(
                AUTH_PROTOCOL_VERSION,
                TransportKind::TcpTls,
                server_nonce,
                now,
                Some(channel_binding),
                Some(tls_spki_sha256),
            );
            match ctx.sign_challenge(&challenge) {
                Ok(machine_signature) => {
                    let hello = ServerHello {
                        protocol_version: AUTH_PROTOCOL_VERSION,
                        transport: TransportKind::TcpTls,
                        machine_public_key: ctx.machine_public_key,
                        server_nonce,
                        server_unix_time: now,
                        tls_binding_required: true,
                        machine_signature,
                    };
                    (channel_binding, hello)
                }
                Err(err) => {
                    let _ = write_auth_message(
                        &mut ctrl_io,
                        &TlsControlResponse::Error(err.to_string()),
                    )
                    .await;
                    let _ = tls_child.wait().await;
                    return;
                }
            }
        }
        other => {
            let _ = write_auth_message(
                &mut ctrl_io,
                &TlsControlResponse::Error(format!("expected SignHandshake, got {other:?}")),
            )
            .await;
            let _ = tls_child.wait().await;
            return;
        }
    };

    if write_auth_message(
        &mut ctrl_io,
        &TlsControlResponse::HandshakeSigned(signed_hello.clone()),
    )
    .await
    .is_err()
    {
        let _ = tls_child.wait().await;
        return;
    }

    // Step 2: Receive `ClientAuth` forwarded by `inspector-tls`, verify Ed25519
    // credentials + RFC 8446 channel binding, and spawn attenuated `inspector-worker`.
    let auth_req: TlsControlRequest = match read_auth_message(&mut ctrl_io).await {
        Ok(req) => req,
        Err(_) => {
            let _ = tls_child.wait().await;
            return;
        }
    };
    let worker_child: Option<(Child, Option<ComponentControlBridge>)> = match auth_req {
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
                    write_auth_message(&mut ctrl_io, &TlsControlResponse::AuthDecision(decision))
                        .await;
                None
            } else {
                let now = current_unix_time();
                match verify_client_auth(
                    &ctx.policy,
                    &ctx.worker_ceiling,
                    &signed_hello,
                    Some(expected_binding),
                    &client_auth,
                    now,
                ) {
                    Ok(verified) => {
                        let mut grants = session_grants_to_kernel(&verified.granted);
                        grants.push(ipc_grant("rpc", worker_data));
                        let cc_task = attach_component_control(
                            &ctx,
                            &verified.granted.component_control,
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
                                    granted: verified.granted,
                                    session_id,
                                };
                                let _ = write_auth_message(
                                    &mut ctrl_io,
                                    &TlsControlResponse::AuthDecision(decision),
                                )
                                .await;
                                Some((worker, cc_task))
                            }
                            Err(err) => {
                                let decision = ServerAuthResult::Rejected {
                                    code: helios_inspector_protocol::auth::AuthRejectCode::Internal,
                                    detail: format!("failed to spawn inspector-worker: {err:?}"),
                                };
                                let _ = write_auth_message(
                                    &mut ctrl_io,
                                    &TlsControlResponse::AuthDecision(decision),
                                )
                                .await;
                                None
                            }
                        }
                    }
                    Err(err) => {
                        let decision = ServerAuthResult::Rejected {
                            code: err.reject_code(),
                            detail: err.to_string(),
                        };
                        let _ = write_auth_message(
                            &mut ctrl_io,
                            &TlsControlResponse::AuthDecision(decision),
                        )
                        .await;
                        None
                    }
                }
            }
        }
        other => {
            let _ = write_auth_message(
                &mut ctrl_io,
                &TlsControlResponse::Error(format!("expected Authenticate, got {other:?}")),
            )
            .await;
            None
        }
    };

    // Drop the control channel immediately — `inspector-host` is now 100% off
    // the post-handshake data path (`inspector-tls` <-> `inspector-worker` flow
    // directly over `data`/`rpc` IPC).
    drop(ctrl_io);

    if let Some((worker, cc_task)) = worker_child {
        wait_worker_and_control(worker, cc_task).await;
    }
    let _ = tls_child.wait().await;
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
    let mut next_accept = Box::pin(accept_vsock_owned(listener));

    loop {
        if sessions.is_empty() {
            let (listener_back, accepted) = next_accept.await;
            next_accept = Box::pin(accept_vsock_owned(listener_back));
            match accepted {
                Ok(stream) => {
                    let ctx = Arc::clone(&ctx);
                    sessions.push(Box::pin(handle_vsock_session(ctx, stream)));
                }
                Err(err) => {
                    eprintln!("inspector-host vsock accept error: {err}");
                }
            }
        } else {
            match futures_util::future::select(next_accept.as_mut(), sessions.next()).await {
                futures_util::future::Either::Left(((listener_back, accepted), _)) => {
                    next_accept.set(accept_vsock_owned(listener_back));
                    match accepted {
                        Ok(stream) => {
                            let ctx = Arc::clone(&ctx);
                            sessions.push(Box::pin(handle_vsock_session(ctx, stream)));
                        }
                        Err(err) => {
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
    listener: VsockListener,
) -> (VsockListener, std::io::Result<VsockStream>) {
    let res = listener.accept().await;
    (listener, res)
}

async fn handle_vsock_session(ctx: Arc<HostContext>, mut stream: VsockStream) {
    stream.set_timeout(vsock::NO_DEADLINE);
    let session_id = ctx.next_session();
    let mut io = UnbufferedVsockIo::new(stream);
    let now = current_unix_time();

    let verified = {
        let (mut read, mut write) = futures_util::AsyncReadExt::split(&mut io);
        match server_handshake(
            &mut read,
            &mut write,
            TransportKind::Vsock,
            &ctx.policy,
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
                eprintln!("inspector-host vsock session {session_id} rejected: {err}");
                return;
            }
        }
    };

    // Hand the connected `VsockStream` directly to the attenuated worker and
    // exit the post-handshake data path completely.
    let stream = io.into_inner();
    let mut grants = session_grants_to_kernel(&verified.granted);
    let cc_task = attach_component_control(&ctx, &verified.granted.component_control, &mut grants);
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
        match server_handshake(
            &mut read,
            &mut write,
            TransportKind::Serial,
            &ctx.policy,
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
    let mut grants = session_grants_to_kernel(&verified.granted);
    let cc_task = attach_component_control(&ctx, &verified.granted.component_control, &mut grants);
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
