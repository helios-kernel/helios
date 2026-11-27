//! Privilege-separated interactive VT2 console session daemon (`/console-session`).
//!
//! Speaks the framed `helios:console/tty` IPC protocol with `/plugins/compositor`
//! and owns all login authentication and `/bin/nu` shell spawning so the
//! compositor itself needs zero filesystem, process, or identity authority.
//!
//! # Operating modes
//!
//! 1. **`--console-shell` mode** (`/etc/helios/console-shell` exists):
//!    Sends `Mode { console_shell: true }` and spawns a fresh `/bin/nu` shell on
//!    every `Attach` (including compositor restarts), echoing typed bytes and
//!    forwarding stdout/stderr back over IPC.
//! 2. **Authenticated operator login mode** (`/etc/helios/accounts.postcard`
//!    present and non-empty):
//!    Prompts `helios login`, publishes a `MachineIdentity`-bound
//!    [`ConsoleLoginChallenge`] via lock-free `helios:system/inspect` under
//!    `console-auth`, waits for the host GUI broker to write a signed
//!    [`ConsoleLoginAuthReply`] to `/run/console-auth/reply.postcard`, verifies
//!    the proof via [`verify_console_login`], and spawns an attenuated `/bin/nu`
//!    shell bounded by the account's grants (never delegating
//!    `MachineRight::Identity`, `Display`, or `Input`).
//! 3. **Locked / unconfigured mode** (neither flag nor enrolled accounts):
//!    Displays instructions on VT2 explaining how to enroll a Touch ID or FIDO2
//!    operator account with `helios account create`.

mod grants;

use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use helios_api::bindings::wit_stream;
use helios_api::channel::{Receiver, Sender, bounded};
use helios_api::inspect::InspectPublisher;
use helios_api::ipc::{self, Endpoint};
use helios_api::machine_identity;
use helios_api::programs::{Child, SpawnRequest};
use helios_api::task::{sleep, spawn};
use helios_compositor_render::tty::{
    CONSOLE_TTY_CHANNEL, FrameDecoder, TtyClientMsg, TtyServerMsg, encode_frame,
};
use helios_inspector_protocol::auth::{
    AccountPolicy, CONSOLE_AUTH_REPLY_PATH, CONSOLE_SHELL_FLAG_PATH, ConsoleLoginAuthReply,
    ConsoleLoginChallenge, HELIOS_ACCOUNTS_POLICY_PATH, SessionGrants, random_32,
    verify_console_login,
};

use crate::grants::{console_shell_ceiling, session_grants_to_kernel};

const SHELL_PATH: &str = "/bin/nu";
const IPC_READ_CHUNK: u32 = 4096;
const SHELL_READ_CHUNK: usize = 4096;
const EVENT_QUEUE_DEPTH: usize = 256;
const INSPECT_BUFFER_BYTES: u64 = 64 * 1024;
const AUTH_POLL_INTERVAL: Duration = Duration::from_millis(100);
const AUTH_WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const SIGKILL: u8 = 9;

#[derive(Debug, Clone, PartialEq, Eq)]
enum SessionMode {
    ConsoleShell,
    AccountLogin(AccountPolicy),
    Locked,
}

enum SessionEvent {
    Client(TtyClientMsg),
    ClientClosed,
    ShellOutput { session_id: u64, bytes: Vec<u8> },
    ShellEnded { session_id: u64 },
}

struct ActiveShell {
    session_id: u64,
    child: Child,
    stdin: helios_api::wit_bindgen::StreamWriter<u8>,
}

/// Interactive line editor for the VT2 `helios login` prompt.
#[derive(Debug, Default)]
struct LoginLineEditor {
    buf: String,
}

#[derive(Debug, PartialEq, Eq)]
enum LineEditStep {
    Echo(Vec<u8>),
    Submitted(String),
    Cancelled,
}

impl LoginLineEditor {
    fn feed(&mut self, bytes: &[u8]) -> Vec<LineEditStep> {
        let mut steps = Vec::new();
        let mut echo = Vec::new();
        for &b in bytes {
            match b {
                b'\x03' => {
                    if !echo.is_empty() {
                        steps.push(LineEditStep::Echo(core::mem::take(&mut echo)));
                    }
                    self.buf.clear();
                    steps.push(LineEditStep::Cancelled);
                }
                b'\r' | b'\n' => {
                    echo.extend_from_slice(b"\r\n");
                    steps.push(LineEditStep::Echo(core::mem::take(&mut echo)));
                    let line = core::mem::take(&mut self.buf);
                    steps.push(LineEditStep::Submitted(line));
                }
                b'\x08' | b'\x7f' => {
                    if self.buf.pop().is_some() {
                        echo.extend_from_slice(b"\x08 \x08");
                    }
                }
                0x20..=0x7e if self.buf.len() < 64 => {
                    self.buf.push(b as char);
                    echo.push(b);
                }
                _ => {}
            }
        }
        if !echo.is_empty() {
            steps.push(LineEditStep::Echo(echo));
        }
        steps
    }

    fn clear(&mut self) {
        self.buf.clear();
    }
}

fn determine_mode(flag_path: &Path, accounts_path: &Path) -> Result<SessionMode, String> {
    if flag_path.exists() {
        return Ok(SessionMode::ConsoleShell);
    }
    match fs::read(accounts_path) {
        Ok(bytes) => {
            let policy = AccountPolicy::decode_postcard(&bytes).map_err(|err| {
                format!(
                    "failed to decode operator accounts policy `{}`: {err}",
                    accounts_path.display()
                )
            })?;
            if policy.accounts.is_empty() {
                Ok(SessionMode::Locked)
            } else {
                Ok(SessionMode::AccountLogin(policy))
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(SessionMode::Locked),
        Err(err) => Err(format!(
            "failed to read operator accounts policy `{}`: {err}",
            accounts_path.display()
        )),
    }
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

fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn send_server_msg(endpoint: &Endpoint, msg: &TtyServerMsg) -> Result<(), String> {
    let frame = encode_frame(msg).map_err(|err| format!("encode tty frame: {err}"))?;
    endpoint
        .write(frame)
        .await
        .map_err(|err| format!("ipc write failed: {err:?}"))
}

async fn send_text(endpoint: &Endpoint, text: &str) -> Result<(), String> {
    send_server_msg(endpoint, &TtyServerMsg::Output(text.as_bytes().to_vec())).await
}

fn login_banner(policy: &AccountPolicy) -> String {
    let mut out = String::from("Helios Console (VT2) - Touch ID / FIDO2 Login\r\n");
    if policy.accounts.len() > 1 {
        let names: Vec<&str> = policy
            .accounts
            .iter()
            .map(|acct| acct.username.as_str())
            .collect();
        out.push_str("Enrolled accounts: ");
        out.push_str(&names.join(", "));
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out
}

fn login_prompt(policy: &AccountPolicy) -> String {
    if policy.accounts.len() == 1 {
        format!("helios login [{}]: ", policy.accounts[0].username)
    } else {
        String::from("helios login: ")
    }
}

fn resolve_submitted_username(policy: &AccountPolicy, submitted: &str) -> Option<String> {
    let trimmed = submitted.trim();
    if trimmed.is_empty() {
        if policy.accounts.len() == 1 {
            return Some(policy.accounts[0].username.clone());
        }
        return None;
    }
    Some(trimmed.to_owned())
}

const LOCKED_BANNER: &str = "\
Helios Console (VT2) - Console Login Locked\r\n\
\r\n\
No operator accounts are enrolled in this guest image.\r\n\
To enable Touch ID or FIDO2 login on VT2:\r\n\
  1. Enroll an operator account on the host:\r\n\
       helios account create <username> --touch-id\r\n\
       helios account create <username> --fido2\r\n\
  2. Boot with interactive GUI brokering:\r\n\
       helios vm --gui\r\n\
\r\n\
Press Alt+F1 to return to the VT1 system log.\r\n";

fn publish_challenge(
    publisher: &mut Option<InspectPublisher>,
    challenge: Option<&ConsoleLoginChallenge>,
) -> Result<(), String> {
    let Some(pub_handle) = publisher.as_mut() else {
        return Err("console-auth inspect publisher is unavailable".to_owned());
    };
    match challenge {
        Some(ch) => {
            let encoded = ch
                .encode_postcard()
                .map_err(|err| format!("encode console login challenge: {err}"))?;
            pub_handle
                .update(|writer| {
                    writer
                        .u64("request_id", ch.request_id)
                        .text("username", &ch.username)
                        .blob("challenge", &encoded);
                })
                .map_err(|err| format!("update console-auth inspect publication: {err}"))?;
        }
        None => {
            pub_handle
                .update(|writer| {
                    writer.u64("request_id", 0);
                })
                .map_err(|err| format!("clear console-auth inspect publication: {err}"))?;
        }
    }
    Ok(())
}

async fn kill_active_shell(shell: &mut Option<ActiveShell>) {
    if let Some(active) = shell.take() {
        drop(active.stdin);
        let _ = active.child.signal(SIGKILL);
        let _ = active.child.wait().await;
    }
}

async fn spawn_shell(
    events: &Sender<SessionEvent>,
    session_id: u64,
    grants: &SessionGrants,
    username: Option<&str>,
) -> Result<ActiveShell, String> {
    let mut env = vec![
        (String::from("TERM"), String::from("dumb")),
        (String::from("PS1"), String::from("helios$ ")),
        (String::from("HOME"), String::from("/")),
    ];
    if let Some(user) = username {
        env.push((String::from("USER"), user.to_owned()));
    }
    let child = Child::spawn(SpawnRequest {
        name: String::from("nu"),
        args: Vec::new(),
        env,
        path: String::from(SHELL_PATH),
        cwd: None,
        sockets: Vec::new(),
        capability_grants: session_grants_to_kernel(grants),
    })
    .await
    .map_err(|err| format!("failed to spawn `{SHELL_PATH}`: {err:?}"))?;

    let (stdin, stdin_reader) = wit_stream::new::<u8>();
    let stdin_done = child.pipe_stdin(stdin_reader);
    spawn(async move {
        let _ = std::future::IntoFuture::into_future(stdin_done).await;
    });

    for (stream, _done) in [child.stdout(), child.stderr()] {
        let events = events.clone();
        spawn(async move {
            read_shell_stream(stream, session_id, events).await;
        });
    }

    Ok(ActiveShell {
        session_id,
        child,
        stdin,
    })
}

async fn read_shell_stream(
    mut stream: helios_api::wit_bindgen::StreamReader<u8>,
    session_id: u64,
    events: Sender<SessionEvent>,
) {
    loop {
        let (result, chunk) = stream.read(Vec::with_capacity(SHELL_READ_CHUNK)).await;
        if !chunk.is_empty()
            && events
                .send(SessionEvent::ShellOutput {
                    session_id,
                    bytes: chunk,
                })
                .await
                .is_err()
        {
            return;
        }
        if helios_api::stream_closed(result) {
            let _ = events.send(SessionEvent::ShellEnded { session_id }).await;
            return;
        }
    }
}

async fn read_client_loop(endpoint: Arc<Endpoint>, events: Sender<SessionEvent>) {
    let mut decoder = FrameDecoder::new();
    loop {
        match endpoint.read(IPC_READ_CHUNK).await {
            Ok(Some(bytes)) if !bytes.is_empty() => {
                decoder.push(&bytes);
                loop {
                    match decoder.next_frame::<TtyClientMsg>() {
                        Ok(Some(msg)) => {
                            if events.send(SessionEvent::Client(msg)).await.is_err() {
                                return;
                            }
                        }
                        Ok(None) => break,
                        Err(error) => {
                            eprintln!("console-session: malformed tty client frame: {error}");
                            break;
                        }
                    }
                }
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                let _ = events.send(SessionEvent::ClientClosed).await;
                return;
            }
        }
    }
}

enum AuthWaitOutcome {
    Reply(ConsoleLoginAuthReply),
    Cancelled,
    Reattached,
    TimedOut,
    ClientClosed,
}

async fn wait_for_auth_reply(request_id: u64, rx: &Receiver<SessionEvent>) -> AuthWaitOutcome {
    let deadline = Instant::now() + AUTH_WAIT_TIMEOUT;
    loop {
        // Check shared `/run/console-auth/reply.postcard` first.
        if let Ok(bytes) = fs::read(CONSOLE_AUTH_REPLY_PATH) {
            let _ = fs::remove_file(CONSOLE_AUTH_REPLY_PATH);
            match ConsoleLoginAuthReply::decode_postcard(&bytes) {
                Ok(reply) if reply.request_id() == request_id => {
                    return AuthWaitOutcome::Reply(reply);
                }
                Ok(_) => {
                    // Stale reply for an older request_id; keep waiting.
                }
                Err(err) => {
                    return AuthWaitOutcome::Reply(ConsoleLoginAuthReply::Rejected {
                        request_id,
                        reason: format!("malformed host auth reply: {err}"),
                    });
                }
            }
        }

        let now = Instant::now();
        if now >= deadline {
            return AuthWaitOutcome::TimedOut;
        }
        let step = AUTH_POLL_INTERVAL.min(deadline.saturating_duration_since(now));

        enum WaitPoll {
            Event(Result<SessionEvent, helios_api::channel::RecvError>),
            Tick,
        }
        let polled = futures_lite::future::or(async { WaitPoll::Event(rx.recv().await) }, async {
            sleep(step).await;
            WaitPoll::Tick
        })
        .await;

        match polled {
            WaitPoll::Tick => {}
            WaitPoll::Event(Err(_)) | WaitPoll::Event(Ok(SessionEvent::ClientClosed)) => {
                return AuthWaitOutcome::ClientClosed;
            }
            WaitPoll::Event(Ok(SessionEvent::Client(TtyClientMsg::Attach { .. }))) => {
                return AuthWaitOutcome::Reattached;
            }
            WaitPoll::Event(Ok(SessionEvent::Client(TtyClientMsg::Input(bytes)))) => {
                if bytes.contains(&b'\x03') {
                    return AuthWaitOutcome::Cancelled;
                }
            }
            WaitPoll::Event(Ok(
                SessionEvent::Client(TtyClientMsg::Resize { .. })
                | SessionEvent::ShellOutput { .. }
                | SessionEvent::ShellEnded { .. },
            )) => {}
        }
    }
}

#[helios_api::main]
async fn main() -> Result<(), String> {
    let mode = determine_mode(
        Path::new(CONSOLE_SHELL_FLAG_PATH),
        Path::new(HELIOS_ACCOUNTS_POLICY_PATH),
    )?;
    let endpoint = Arc::new(
        ipc::take(CONSOLE_TTY_CHANNEL)
            .ok_or_else(|| format!("missing `{CONSOLE_TTY_CHANNEL}` IPC grant"))?,
    );

    if let Some(parent) = Path::new(CONSOLE_AUTH_REPLY_PATH).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::remove_file(CONSOLE_AUTH_REPLY_PATH);

    let mut publisher = if matches!(mode, SessionMode::AccountLogin(_)) {
        let mut pub_handle = InspectPublisher::create("console-auth", INSPECT_BUFFER_BYTES)
            .map_err(|err| format!("failed to publish console-auth inspect buffer: {err}"))?;
        let _ = pub_handle.update(|writer| {
            writer.u64("request_id", 0);
        });
        Some(pub_handle)
    } else {
        None
    };

    let (events_tx, events_rx) = bounded::<SessionEvent>(EVENT_QUEUE_DEPTH);
    let reader_ep = Arc::clone(&endpoint);
    let reader_tx = events_tx.clone();
    spawn(async move {
        read_client_loop(reader_ep, reader_tx).await;
    });

    match mode {
        SessionMode::ConsoleShell => {
            run_console_shell_mode(&endpoint, &events_tx, &events_rx).await
        }
        SessionMode::AccountLogin(policy) => {
            run_account_login_mode(&endpoint, &policy, &mut publisher, &events_tx, &events_rx).await
        }
        SessionMode::Locked => run_locked_mode(&endpoint, &events_rx).await,
    }
}

async fn run_console_shell_mode(
    endpoint: &Endpoint,
    events_tx: &Sender<SessionEvent>,
    events_rx: &Receiver<SessionEvent>,
) -> Result<(), String> {
    let mut active_shell: Option<ActiveShell> = None;
    let mut next_session_id = 1_u64;
    let mut shell_ended_reported = false;

    while let Ok(event) = events_rx.recv().await {
        match event {
            SessionEvent::Client(TtyClientMsg::Attach { .. }) => {
                kill_active_shell(&mut active_shell).await;
                send_server_msg(
                    endpoint,
                    &TtyServerMsg::Mode {
                        console_shell: true,
                    },
                )
                .await?;
                send_server_msg(endpoint, &TtyServerMsg::ClearScreen).await?;
                let session_id = next_session_id;
                next_session_id = next_session_id.saturating_add(1);
                shell_ended_reported = false;
                let shell =
                    spawn_shell(events_tx, session_id, &console_shell_ceiling(), None).await?;
                active_shell = Some(shell);
            }
            SessionEvent::Client(TtyClientMsg::Input(bytes)) => {
                if let Some(shell) = active_shell.as_mut() {
                    send_server_msg(endpoint, &TtyServerMsg::Output(bytes.clone())).await?;
                    let _ = shell.stdin.write_all(bytes).await;
                }
            }
            SessionEvent::Client(TtyClientMsg::Resize { .. }) => {}
            SessionEvent::ShellOutput { session_id, bytes } => {
                if active_shell
                    .as_ref()
                    .is_some_and(|shell| shell.session_id == session_id)
                {
                    send_server_msg(endpoint, &TtyServerMsg::Output(bytes)).await?;
                }
            }
            SessionEvent::ShellEnded { session_id } => {
                if active_shell
                    .as_ref()
                    .is_some_and(|shell| shell.session_id == session_id)
                    && !shell_ended_reported
                {
                    shell_ended_reported = true;
                    send_text(endpoint, "\r\n[the shell exited; the desktop stays up]\r\n").await?;
                    kill_active_shell(&mut active_shell).await;
                }
            }
            SessionEvent::ClientClosed => {
                kill_active_shell(&mut active_shell).await;
                return Ok(());
            }
        }
    }
    kill_active_shell(&mut active_shell).await;
    Ok(())
}

async fn run_account_login_mode(
    endpoint: &Endpoint,
    policy: &AccountPolicy,
    publisher: &mut Option<InspectPublisher>,
    events_tx: &Sender<SessionEvent>,
    events_rx: &Receiver<SessionEvent>,
) -> Result<(), String> {
    let machine_public_key = read_machine_public_key()?;
    let mut active_shell: Option<ActiveShell> = None;
    let mut editor = LoginLineEditor::default();
    let mut next_session_id = 1_u64;
    let mut next_request_id = 1_u64;
    let mut shell_ended_reported = false;

    while let Ok(event) = events_rx.recv().await {
        match event {
            SessionEvent::Client(TtyClientMsg::Attach { .. }) => {
                kill_active_shell(&mut active_shell).await;
                let _ = publish_challenge(publisher, None);
                editor.clear();
                send_server_msg(
                    endpoint,
                    &TtyServerMsg::Mode {
                        console_shell: false,
                    },
                )
                .await?;
                send_server_msg(endpoint, &TtyServerMsg::ClearScreen).await?;
                send_text(endpoint, &login_banner(policy)).await?;
                send_text(endpoint, &login_prompt(policy)).await?;
            }
            SessionEvent::Client(TtyClientMsg::Input(bytes)) => {
                if let Some(shell) = active_shell.as_mut() {
                    send_server_msg(endpoint, &TtyServerMsg::Output(bytes.clone())).await?;
                    let _ = shell.stdin.write_all(bytes).await;
                    continue;
                }

                for step in editor.feed(&bytes) {
                    match step {
                        LineEditStep::Echo(out) => {
                            send_server_msg(endpoint, &TtyServerMsg::Output(out)).await?;
                        }
                        LineEditStep::Cancelled => {
                            send_text(endpoint, "^C\r\n").await?;
                            send_text(endpoint, &login_prompt(policy)).await?;
                        }
                        LineEditStep::Submitted(line) => {
                            let Some(username) = resolve_submitted_username(policy, &line) else {
                                send_text(endpoint, &login_prompt(policy)).await?;
                                continue;
                            };
                            if policy.find_account(&username).is_none() {
                                send_text(endpoint, "Login incorrect\r\n").await?;
                                send_text(endpoint, &login_prompt(policy)).await?;
                                continue;
                            }

                            let request_id = next_request_id;
                            next_request_id = next_request_id.saturating_add(1);
                            let challenge_nonce = random_32()
                                .map_err(|err| format!("failed to generate login nonce: {err}"))?;
                            let challenge = ConsoleLoginChallenge {
                                request_id,
                                username: username.clone(),
                                machine_public_key,
                                challenge_nonce,
                                issued_at_unix: current_unix_time(),
                            };

                            let _ = fs::remove_file(CONSOLE_AUTH_REPLY_PATH);
                            publish_challenge(publisher, Some(&challenge))?;
                            send_text(
                                endpoint,
                                &format!(
                                    "Waiting for host Touch ID / FIDO2 verification for '{username}'...\r\n"
                                ),
                            )
                            .await?;

                            let outcome = wait_for_auth_reply(request_id, events_rx).await;
                            let _ = publish_challenge(publisher, None);

                            match outcome {
                                AuthWaitOutcome::Reply(ConsoleLoginAuthReply::Approved(proof)) => {
                                    match verify_console_login(&policy.accounts, &challenge, &proof)
                                    {
                                        Ok(verified) => {
                                            send_text(
                                                endpoint,
                                                &format!(
                                                    "Authenticated as {} ({})\r\n",
                                                    verified.username,
                                                    verified.public_key.algorithm_name()
                                                ),
                                            )
                                            .await?;
                                            let session_id = next_session_id;
                                            next_session_id = next_session_id.saturating_add(1);
                                            shell_ended_reported = false;
                                            match spawn_shell(
                                                events_tx,
                                                session_id,
                                                &verified.grants,
                                                Some(&verified.username),
                                            )
                                            .await
                                            {
                                                Ok(shell) => {
                                                    active_shell = Some(shell);
                                                    break;
                                                }
                                                Err(err) => {
                                                    send_text(
                                                        endpoint,
                                                        &format!(
                                                            "Failed to start shell: {err}\r\n"
                                                        ),
                                                    )
                                                    .await?;
                                                    send_text(endpoint, &login_prompt(policy))
                                                        .await?;
                                                }
                                            }
                                        }
                                        Err(err) => {
                                            send_text(
                                                endpoint,
                                                &format!("Authentication rejected: {err}\r\n"),
                                            )
                                            .await?;
                                            send_text(endpoint, &login_prompt(policy)).await?;
                                        }
                                    }
                                }
                                AuthWaitOutcome::Reply(ConsoleLoginAuthReply::Rejected {
                                    reason,
                                    ..
                                }) => {
                                    send_text(
                                        endpoint,
                                        &format!("Authentication failed: {reason}\r\n"),
                                    )
                                    .await?;
                                    send_text(endpoint, &login_prompt(policy)).await?;
                                }
                                AuthWaitOutcome::Cancelled => {
                                    send_text(endpoint, "^C\r\nLogin cancelled.\r\n").await?;
                                    send_text(endpoint, &login_prompt(policy)).await?;
                                }
                                AuthWaitOutcome::TimedOut => {
                                    send_text(
                                        endpoint,
                                        "Authentication timed out waiting for host verification.\r\n",
                                    )
                                    .await?;
                                    send_text(endpoint, &login_prompt(policy)).await?;
                                }
                                AuthWaitOutcome::Reattached => {
                                    editor.clear();
                                    send_server_msg(
                                        endpoint,
                                        &TtyServerMsg::Mode {
                                            console_shell: false,
                                        },
                                    )
                                    .await?;
                                    send_server_msg(endpoint, &TtyServerMsg::ClearScreen).await?;
                                    send_text(endpoint, &login_banner(policy)).await?;
                                    send_text(endpoint, &login_prompt(policy)).await?;
                                    break;
                                }
                                AuthWaitOutcome::ClientClosed => {
                                    return Ok(());
                                }
                            }
                        }
                    }
                }
            }
            SessionEvent::Client(TtyClientMsg::Resize { .. }) => {}
            SessionEvent::ShellOutput { session_id, bytes } => {
                if active_shell
                    .as_ref()
                    .is_some_and(|shell| shell.session_id == session_id)
                {
                    send_server_msg(endpoint, &TtyServerMsg::Output(bytes)).await?;
                }
            }
            SessionEvent::ShellEnded { session_id } => {
                if active_shell
                    .as_ref()
                    .is_some_and(|shell| shell.session_id == session_id)
                    && !shell_ended_reported
                {
                    shell_ended_reported = true;
                    kill_active_shell(&mut active_shell).await;
                    editor.clear();
                    send_text(endpoint, "\r\n[session closed]\r\n").await?;
                    send_text(endpoint, &login_prompt(policy)).await?;
                }
            }
            SessionEvent::ClientClosed => {
                kill_active_shell(&mut active_shell).await;
                let _ = publish_challenge(publisher, None);
                return Ok(());
            }
        }
    }
    kill_active_shell(&mut active_shell).await;
    Ok(())
}

async fn run_locked_mode(
    endpoint: &Endpoint,
    events_rx: &Receiver<SessionEvent>,
) -> Result<(), String> {
    while let Ok(event) = events_rx.recv().await {
        match event {
            SessionEvent::Client(TtyClientMsg::Attach { .. }) => {
                send_server_msg(
                    endpoint,
                    &TtyServerMsg::Mode {
                        console_shell: false,
                    },
                )
                .await?;
                send_server_msg(endpoint, &TtyServerMsg::ClearScreen).await?;
                send_text(endpoint, LOCKED_BANNER).await?;
            }
            SessionEvent::ClientClosed => return Ok(()),
            SessionEvent::Client(_)
            | SessionEvent::ShellOutput { .. }
            | SessionEvent::ShellEnded { .. } => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use helios_inspector_protocol::auth::{AuthPublicKey, AuthorizedAccount, TransportMask};

    use super::*;

    fn test_account(username: &str, seed_byte: u8) -> AuthorizedAccount {
        let key = SigningKey::from_bytes(&[seed_byte; 32])
            .verifying_key()
            .to_bytes();
        AuthorizedAccount {
            username: username.to_owned(),
            public_key: AuthPublicKey::Ed25519(key),
            grants: SessionGrants::full_worker_ceiling(),
            allowed_transports: TransportMask::ALL,
        }
    }

    #[test]
    fn mode_selection_prefers_console_shell_then_accounts_then_locked() {
        let dir = std::env::temp_dir().join(format!(
            "helios-console-session-mode-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");

        let flag = dir.join("console-shell");
        let accounts = dir.join("accounts.postcard");

        assert_eq!(
            determine_mode(&flag, &accounts).expect("no files -> locked"),
            SessionMode::Locked
        );

        let empty_policy = AccountPolicy::empty();
        fs::write(
            &accounts,
            empty_policy.encode_postcard().expect("encode empty policy"),
        )
        .expect("write empty policy");
        assert_eq!(
            determine_mode(&flag, &accounts).expect("empty policy -> locked"),
            SessionMode::Locked
        );

        let policy = AccountPolicy::single_account(test_account("lexo", 0x11));
        fs::write(&accounts, policy.encode_postcard().expect("encode policy"))
            .expect("write account policy");
        assert_eq!(
            determine_mode(&flag, &accounts).expect("accounts -> login"),
            SessionMode::AccountLogin(policy)
        );

        fs::write(&flag, b"enabled\n").expect("write console-shell flag");
        assert_eq!(
            determine_mode(&flag, &accounts).expect("flag overrides accounts"),
            SessionMode::ConsoleShell
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn login_line_editor_handles_backspace_submit_and_ctrl_c() {
        let mut ed = LoginLineEditor::default();
        let steps = ed.feed(b"lexx\x7fo\n");
        assert_eq!(
            steps,
            vec![
                LineEditStep::Echo(b"lexx\x08 \x08o\r\n".to_vec()),
                LineEditStep::Submitted("lexo".to_owned()),
            ]
        );

        let cancel = ed.feed(b"ab\x03");
        assert_eq!(
            cancel,
            vec![LineEditStep::Echo(b"ab".to_vec()), LineEditStep::Cancelled,]
        );
    }

    #[test]
    fn single_account_prompt_defaults_on_empty_enter() {
        let single = AccountPolicy::single_account(test_account("lexo", 0x22));
        assert_eq!(login_prompt(&single), "helios login [lexo]: ");
        assert_eq!(
            resolve_submitted_username(&single, ""),
            Some("lexo".to_owned())
        );
        assert_eq!(
            resolve_submitted_username(&single, "other"),
            Some("other".to_owned())
        );

        let multi = AccountPolicy {
            version: helios_inspector_protocol::auth::AUTH_PROTOCOL_VERSION,
            accounts: vec![test_account("alice", 0x33), test_account("bob", 0x44)],
        };
        assert_eq!(login_prompt(&multi), "helios login: ");
        assert_eq!(resolve_submitted_username(&multi, ""), None);
        assert_eq!(
            resolve_submitted_username(&multi, "bob"),
            Some("bob".to_owned())
        );
    }
}
