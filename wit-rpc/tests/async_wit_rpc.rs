use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::task::{Context, Poll};

use async_channel::{Receiver, Sender};
use event_listener::Event;
use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::future::{block_on, or, poll_once, yield_now, zip};
use helios_inspector_protocol::wire::{Frame, read_frame, write_frame};
use helios_wit_rpc::{
    Endpoint, EndpointConfig, FutureReader, RpcError, StreamReader, WireError, future, stream,
};

mod generated {
    helios_wit_rpc::generate!({
        inline: r#"
            package helios:rpc-test@0.1.0;

            interface types {
                flags permissions {
                    read,
                    write,
                    execute,
                }

                enum mode {
                    fast,
                    accurate,
                }

                record packet {
                    seq: u32,
                    label: string,
                    perms: permissions,
                    mode: mode,
                }

                variant rpc-err {
                    denied(string),
                    overflow,
                }
            }

            interface lab {
                use types.{permissions, mode, packet, rpc-err};

                resource accumulator {
                    constructor(initial: s64);
                    add: async func(delta: s64) -> s64;
                    snapshot: func() -> s64;
                    hold-slow: async func() -> s64;
                }

                resource lease {
                    constructor(tag: string);
                    tag: func() -> string;
                }

                consume-accumulator: async func(acc: accumulator) -> s64;

                transform: async func(
                    input: stream<packet>,
                    prefix: string,
                ) -> tuple<stream<string>, future<result<u64, rpc-err>>>;

                await-ticket: async func(succeed: bool) -> future<result<string, rpc-err>>;

                await-cancellable-ticket: async func() -> future<string>;

                never-returns: async func() -> u32;
            }

            world lab-world {
                export types;
                export lab;
            }
        "#,
        world: "lab-world",
    });
}

mod system_wit {
    helios_wit_rpc::generate!({
        path: "../wit",
        world: "inspector-system",
    });
}

use generated::LabWorldClient;
use generated::helios::rpc_test::lab::{self, Accumulator, Lease};
use generated::helios::rpc_test::types::{Mode, Packet, Permissions, RpcErr};

/// Pure `futures_io` in-memory full-duplex byte stream pair for exercising
/// arbitrary `AsyncRead + AsyncWrite` transports without Tokio.
struct PipeReader {
    rx: Pin<Box<Receiver<Vec<u8>>>>,
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
}

type PipeSendFuture = Pin<
    Box<dyn std::future::Future<Output = Result<(), async_channel::SendError<Vec<u8>>>> + Send>,
>;

struct PipeWriter {
    tx: Sender<Vec<u8>>,
    pending_send: Option<(usize, PipeSendFuture)>,
}

fn duplex_pipe(capacity_chunks: usize) -> ((PipeReader, PipeWriter), (PipeReader, PipeWriter)) {
    let (a_tx, b_rx) = async_channel::bounded(capacity_chunks);
    let (b_tx, a_rx) = async_channel::bounded(capacity_chunks);
    (
        (
            PipeReader {
                rx: Box::pin(a_rx),
                buf: Vec::new(),
                pos: 0,
                eof: false,
            },
            PipeWriter {
                tx: a_tx,
                pending_send: None,
            },
        ),
        (
            PipeReader {
                rx: Box::pin(b_rx),
                buf: Vec::new(),
                pos: 0,
                eof: false,
            },
            PipeWriter {
                tx: b_tx,
                pending_send: None,
            },
        ),
    )
}

impl AsyncRead for PipeReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if out.is_empty() || this.eof {
            return Poll::Ready(Ok(0));
        }
        loop {
            if this.pos < this.buf.len() {
                let count = (this.buf.len() - this.pos).min(out.len());
                out[..count].copy_from_slice(&this.buf[this.pos..this.pos + count]);
                this.pos += count;
                if this.pos == this.buf.len() {
                    this.buf.clear();
                    this.pos = 0;
                }
                return Poll::Ready(Ok(count));
            }
            match futures_core::Stream::poll_next(this.rx.as_mut(), cx) {
                Poll::Ready(Some(chunk)) => {
                    if chunk.is_empty() {
                        continue;
                    }
                    this.buf = chunk;
                    this.pos = 0;
                }
                Poll::Ready(None) => {
                    this.eof = true;
                    return Poll::Ready(Ok(0));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for PipeWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        if this.pending_send.is_none() {
            let tx = this.tx.clone();
            let chunk = buf.to_vec();
            let len = chunk.len();
            this.pending_send = Some((len, Box::pin(async move { tx.send(chunk).await })));
        }
        let (len, send_fut) = this
            .pending_send
            .as_mut()
            .expect("pending send future must exist");
        match send_fut.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                let written = *len;
                this.pending_send = None;
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(_)) => {
                this.pending_send = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "duplex pipe closed",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().tx.close();
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct LabTelemetry {
    live_accumulators: AtomicUsize,
    live_leases: AtomicUsize,
    resource_dropped: Event,
    slow_entered: Event,
    slow_release: Event,
    slow_cancelled: AtomicBool,
    slow_dropped_event: Event,
    future_cancelled: AtomicBool,
    future_cancelled_event: Event,
}

struct ServerAccumulator {
    value: AtomicI64,
    telemetry: Arc<LabTelemetry>,
}

impl Drop for ServerAccumulator {
    fn drop(&mut self) {
        self.telemetry
            .live_accumulators
            .fetch_sub(1, Ordering::AcqRel);
        self.telemetry.resource_dropped.notify(usize::MAX);
    }
}

struct ServerLease {
    tag: String,
    telemetry: Arc<LabTelemetry>,
}

impl Drop for ServerLease {
    fn drop(&mut self) {
        self.telemetry.live_leases.fetch_sub(1, Ordering::AcqRel);
        self.telemetry.resource_dropped.notify(usize::MAX);
    }
}

struct CancelDropTracker {
    telemetry: Arc<LabTelemetry>,
    completed: bool,
}

impl Drop for CancelDropTracker {
    fn drop(&mut self) {
        if !self.completed {
            self.telemetry.slow_cancelled.store(true, Ordering::Release);
            self.telemetry.slow_dropped_event.notify(usize::MAX);
        }
    }
}

type BgTask = Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

#[derive(Clone)]
struct LabService {
    name: String,
    telemetry: Arc<LabTelemetry>,
    bg_tasks_tx: Sender<BgTask>,
}

impl LabService {
    fn new(name: impl Into<String>, telemetry: Arc<LabTelemetry>) -> (Self, Receiver<BgTask>) {
        let (tx, rx) = async_channel::unbounded();
        (
            Self {
                name: name.into(),
                telemetry,
                bg_tasks_tx: tx,
            },
            rx,
        )
    }
}

impl lab::Handler for LabService {
    type Accumulator = ServerAccumulator;
    type Lease = ServerLease;

    async fn accumulator_new(&self, initial: i64) -> Self::Accumulator {
        self.telemetry
            .live_accumulators
            .fetch_add(1, Ordering::AcqRel);
        ServerAccumulator {
            value: AtomicI64::new(initial),
            telemetry: Arc::clone(&self.telemetry),
        }
    }

    async fn accumulator_add(&self, self_: &Self::Accumulator, delta: i64) -> i64 {
        self_.value.fetch_add(delta, Ordering::AcqRel) + delta
    }

    async fn accumulator_snapshot(&self, self_: &Self::Accumulator) -> i64 {
        self_.value.load(Ordering::Acquire)
    }

    async fn accumulator_hold_slow(&self, self_: &Self::Accumulator) -> i64 {
        let mut tracker = CancelDropTracker {
            telemetry: Arc::clone(&self.telemetry),
            completed: false,
        };
        let wait_release = self.telemetry.slow_release.listen();
        self.telemetry.slow_entered.notify(usize::MAX);
        wait_release.await;
        tracker.completed = true;
        self_.value.load(Ordering::Acquire)
    }

    async fn lease_new(&self, tag: String) -> Self::Lease {
        self.telemetry.live_leases.fetch_add(1, Ordering::AcqRel);
        ServerLease {
            tag,
            telemetry: Arc::clone(&self.telemetry),
        }
    }

    async fn lease_tag(&self, self_: &Self::Lease) -> String {
        format!("{}:{}", self.name, self_.tag)
    }

    async fn consume_accumulator(&self, acc: Self::Accumulator) -> i64 {
        acc.value.load(Ordering::Acquire)
    }

    async fn transform(
        &self,
        mut input: StreamReader<Packet>,
        prefix: String,
    ) -> (StreamReader<String>, FutureReader<Result<u64, RpcErr>>) {
        let (mut out_tx, out_rx) = stream::<String>();
        let (done_tx, done_rx) = future::<Result<u64, RpcErr>>();
        let peer_tag = self.name.clone();

        let _ = self.bg_tasks_tx.try_send(Box::pin(async move {
            let mut total = 0_u64;
            loop {
                match input.next().await {
                    Ok(Some(pkt)) => {
                        if !pkt.perms.contains(Permissions::READ) {
                            let _ = done_tx
                                .resolve(Err(RpcErr::Denied("missing READ permission".to_owned())))
                                .await;
                            return;
                        }
                        total += 1;
                        let formatted = format!(
                            "[{peer_tag}:{prefix}#{} {:?}] {}",
                            pkt.seq, pkt.mode, pkt.label
                        );
                        if out_tx.send(formatted).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        let _ = out_tx.close().await;
                        let _ = done_tx.resolve(Ok(total)).await;
                        return;
                    }
                    Err(_) => {
                        return;
                    }
                }
            }
        }));

        (out_rx, done_rx)
    }

    async fn await_ticket(&self, succeed: bool) -> FutureReader<Result<String, RpcErr>> {
        let (tx, rx) = future::<Result<String, RpcErr>>();
        let _ = self.bg_tasks_tx.try_send(Box::pin(async move {
            if succeed {
                let _ = tx
                    .resolve(Ok("ticket-ok-中文日本語한국어".to_owned()))
                    .await;
            } else {
                drop(tx);
            }
        }));
        rx
    }

    async fn await_cancellable_ticket(&self) -> FutureReader<String> {
        let (tx, rx) = future::<String>();
        let telemetry = Arc::clone(&self.telemetry);
        let _ = self.bg_tasks_tx.try_send(Box::pin(async move {
            tx.cancelled().await;
            telemetry.future_cancelled.store(true, Ordering::Release);
            telemetry.future_cancelled_event.notify(usize::MAX);
        }));
        rx
    }

    async fn never_returns(&self) -> u32 {
        let mut tracker = CancelDropTracker {
            telemetry: Arc::clone(&self.telemetry),
            completed: false,
        };
        let wait_forever = self.telemetry.slow_release.listen();
        self.telemetry.slow_entered.notify(usize::MAX);
        wait_forever.await;
        tracker.completed = true;
        99
    }
}

async fn pump_bg_tasks(rx: Receiver<Pin<Box<dyn std::future::Future<Output = ()> + Send>>>) {
    use futures_util::stream::{FuturesUnordered, StreamExt as _};
    let mut running = FuturesUnordered::new();
    loop {
        if running.is_empty() {
            let Ok(task) = rx.recv().await else {
                return;
            };
            running.push(task);
        } else {
            enum Next {
                Spawned(Option<Pin<Box<dyn std::future::Future<Output = ()> + Send>>>),
                Done,
            }
            let step = or(async { Next::Spawned(rx.recv().await.ok()) }, async {
                let _ = running.next().await;
                Next::Done
            })
            .await;
            match step {
                Next::Spawned(Some(task)) => running.push(task),
                Next::Spawned(None) if running.is_empty() => return,
                Next::Spawned(None) | Next::Done => {}
            }
        }
    }
}

#[test]
fn symmetric_peer_to_peer_streams_futures_and_resources_round_trip() {
    block_on(async {
        let ((a_read, a_write), (b_read, b_write)) = duplex_pipe(32);
        let telemetry_a = Arc::new(LabTelemetry::default());
        let telemetry_b = Arc::new(LabTelemetry::default());
        let (service_a, bg_a) = LabService::new("peer-a", Arc::clone(&telemetry_a));
        let (service_b, bg_b) = LabService::new("peer-b", Arc::clone(&telemetry_b));

        let endpoint_a = Endpoint::new(a_read, a_write, lab::Server::new(service_a));
        let endpoint_b = Endpoint::new(b_read, b_write, lab::Server::new(service_b));

        let handle_a = endpoint_a.handle();
        let handle_b = endpoint_b.handle();
        let world_a = LabWorldClient::new(handle_a.clone());
        let world_b = LabWorldClient::new(handle_b.clone());

        let test_logic = async {
            // Both peers open invocation 1 and mint resource handle 1 towards each other simultaneously!
            let ((acc_on_b, lease_on_b), (acc_on_a, lease_on_a)) = zip(
                async {
                    let lab = world_a.lab();
                    let acc = lab.accumulator_new(10).await.expect("create acc on B");
                    let lease = Lease::new(world_a.peer(), "session-α-中文日本語한국어".to_owned())
                        .await
                        .expect("create lease on B");
                    (acc, lease)
                },
                async {
                    let lab = world_b.lab();
                    let acc = lab.accumulator_new(100).await.expect("create acc on A");
                    let lease = Lease::new(world_b.peer(), "session-β-中文日本語한국어".to_owned())
                        .await
                        .expect("create lease on A");
                    (acc, lease)
                },
            )
            .await;

            assert_eq!(telemetry_b.live_accumulators.load(Ordering::Acquire), 1);
            assert_eq!(telemetry_a.live_accumulators.load(Ordering::Acquire), 1);
            assert_eq!(
                lease_on_b.tag().await.expect("tag B"),
                "peer-b:session-α-中文日本語한국어"
            );
            assert_eq!(
                lease_on_a.tag().await.expect("tag A"),
                "peer-a:session-β-中文日本語한국어"
            );

            assert_eq!(acc_on_b.add(25).await.expect("add B"), 35);
            assert_eq!(acc_on_a.add(50).await.expect("add A"), 150);
            assert_eq!(acc_on_b.snapshot().await.expect("snap B"), 35);
            assert_eq!(acc_on_a.snapshot().await.expect("snap A"), 150);

            // Bidirectional stream<packet> -> (stream<string>, future<result<u64, rpc-err>>).
            let (mut pkt_tx, pkt_rx) = stream::<Packet>();
            let (mut out_rx, summary_fut) = world_a
                .lab()
                .transform(pkt_rx, "cjk".to_owned())
                .await
                .expect("open transform");

            let producer = async move {
                for seq in 1..=4 {
                    pkt_tx
                        .send(Packet {
                            seq,
                            label: format!("payload-{seq}-中文日本語한국어"),
                            perms: Permissions::READ | Permissions::WRITE,
                            mode: if seq % 2 == 0 {
                                Mode::Fast
                            } else {
                                Mode::Accurate
                            },
                        })
                        .await
                        .expect("send packet");
                }
                pkt_tx.close().await.expect("close packet stream");
            };

            let consumer = async move {
                let mut collected = Vec::new();
                while let Some(item) = out_rx.next().await.expect("read transformed string") {
                    collected.push(item);
                }
                let count = summary_fut
                    .await
                    .expect("await transform future")
                    .expect("transform succeeded");
                (collected, count)
            };

            let ((), (lines, count)) = zip(producer, consumer).await;
            assert_eq!(count, 4);
            assert_eq!(lines.len(), 4);
            assert_eq!(
                lines[0],
                "[peer-b:cjk#1 Accurate] payload-1-中文日本語한국어"
            );
            assert_eq!(lines[3], "[peer-b:cjk#4 Fast] payload-4-中文日本語한국어");

            // Test resolved future<T> vs dropped FutureWriter (`FutureDropped`).
            let ticket_ok = world_a
                .lab()
                .await_ticket(true)
                .await
                .expect("call await_ticket(true)")
                .await
                .expect("resolve ticket")
                .expect("ticket ok");
            assert_eq!(ticket_ok, "ticket-ok-中文日本語한국어");

            let ticket_dropped = world_a
                .lab()
                .await_ticket(false)
                .await
                .expect("call await_ticket(false)")
                .await;
            assert!(
                matches!(ticket_dropped, Err(RpcError::FutureDropped)),
                "expected FutureDropped, got {ticket_dropped:?}"
            );

            // Dropping a FutureReader early propagates sub-path cancellation to FutureWriter.
            let fut_cancel_wait = telemetry_b.future_cancelled_event.listen();
            let cancellable_ticket = world_a
                .lab()
                .await_cancellable_ticket()
                .await
                .expect("call await_cancellable_ticket");
            drop(cancellable_ticket);
            fut_cancel_wait.await;
            assert!(telemetry_b.future_cancelled.load(Ordering::Acquire));

            // Client Drop emits Frame::ResourceDrop and cleans up server resource while live.
            let drop_listener = telemetry_b.resource_dropped.listen();
            drop(lease_on_b);
            drop_listener.await;
            assert_eq!(telemetry_b.live_leases.load(Ordering::Acquire), 0);

            // Moving `own<accumulator>` into `consume_accumulator` transfers ownership cleanly.
            let final_b = world_a
                .lab()
                .consume_accumulator(acc_on_b)
                .await
                .expect("consume acc_on_b");
            assert_eq!(final_b, 35);
            assert_eq!(telemetry_b.live_accumulators.load(Ordering::Acquire), 0);

            drop(acc_on_a);
            drop(lease_on_a);
            handle_a.close();
            handle_b.close();
        };

        let drive_all = zip(
            zip(endpoint_a.drive(), endpoint_b.drive()),
            zip(pump_bg_tasks(bg_a), pump_bg_tasks(bg_b)),
        );

        or(
            async {
                test_logic.await;
            },
            async {
                let _ = drive_all.await;
            },
        )
        .await;
    });
}

#[test]
fn explicit_per_stream_credit_backpressure_and_credit_violation() {
    block_on(async {
        // Configure explicit credit window of 2 items per stream.
        let config = EndpointConfig {
            stream_credit_window: 2,
        };

        let (received_gate_tx, received_gate_rx) = async_channel::bounded::<()>(1);
        let (item_ack_tx, item_ack_rx) = async_channel::unbounded::<u32>();

        // Custom slow-draining service to prove exact credit stalling at window = 2.
        struct SlowDrainService {
            gate_rx: Receiver<()>,
            ack_tx: Sender<u32>,
            bg_tx: Sender<Pin<Box<dyn std::future::Future<Output = ()> + Send>>>,
        }

        impl lab::Handler for SlowDrainService {
            type Accumulator = ();
            type Lease = ();

            async fn accumulator_new(&self, _initial: i64) -> Self::Accumulator {}
            async fn accumulator_add(&self, _self_: &Self::Accumulator, delta: i64) -> i64 {
                delta
            }
            async fn accumulator_snapshot(&self, _self_: &Self::Accumulator) -> i64 {
                0
            }
            async fn accumulator_hold_slow(&self, _self_: &Self::Accumulator) -> i64 {
                0
            }
            async fn lease_new(&self, _tag: String) -> Self::Lease {}
            async fn lease_tag(&self, _self_: &Self::Lease) -> String {
                String::new()
            }
            async fn consume_accumulator(&self, _acc: Self::Accumulator) -> i64 {
                0
            }
            async fn transform(
                &self,
                mut input: StreamReader<Packet>,
                _prefix: String,
            ) -> (StreamReader<String>, FutureReader<Result<u64, RpcErr>>) {
                let gate_rx = self.gate_rx.clone();
                let ack_tx = self.ack_tx.clone();
                let (done_tx, done_rx) = future();
                let _ = self.bg_tx.try_send(Box::pin(async move {
                    // Wait until test tells us to start draining!
                    let _ = gate_rx.recv().await;
                    let mut count = 0_u64;
                    while let Ok(Some(pkt)) = input.next().await {
                        count += 1;
                        let _ = ack_tx.send(pkt.seq).await;
                    }
                    let _ = done_tx.resolve(Ok(count)).await;
                }));
                (StreamReader::empty(), done_rx)
            }
            async fn await_ticket(&self, _succeed: bool) -> FutureReader<Result<String, RpcErr>> {
                FutureReader::ready(Ok(String::new()))
            }
            async fn await_cancellable_ticket(&self) -> FutureReader<String> {
                FutureReader::ready(String::new())
            }
            async fn never_returns(&self) -> u32 {
                0
            }
        }

        let ((a_read, a_write), (b_read, b_write)) = duplex_pipe(64);
        let endpoint_a = Endpoint::with_config(a_read, a_write, (), config);
        let handle_a = endpoint_a.handle();
        let client = lab::Client::new(handle_a.clone());

        let (bg_tx, bg_rx) = async_channel::unbounded();
        let slow_service = SlowDrainService {
            gate_rx: received_gate_rx,
            ack_tx: item_ack_tx,
            bg_tx,
        };
        let endpoint_b =
            Endpoint::with_config(b_read, b_write, lab::Server::new(slow_service), config);
        let handle_b = endpoint_b.handle();

        let make_pkt = |seq: u32| Packet {
            seq,
            label: format!("p-{seq}"),
            perms: Permissions::READ,
            mode: Mode::Fast,
        };

        let check = async {
            let (mut tx, rx) = stream::<Packet>();
            let (_empty_out, done_fut) = client
                .transform(rx, "bp".to_owned())
                .await
                .expect("open transform");

            // Window is 2: items 1 and 2 have credit and complete immediately!
            tx.send(make_pkt(1)).await.expect("send 1 within credit");
            tx.send(make_pkt(2)).await.expect("send 2 within credit");

            // Item 3 MUST park (`Poll::Pending`) because receiver has not drained any item yet!
            let mut send_3 = Box::pin(tx.send(make_pkt(3)));
            for _ in 0..5 {
                assert!(
                    poll_once(&mut send_3).await.is_none(),
                    "3rd stream item must block when 2-credit window is exhausted"
                );
                yield_now().await;
            }

            // Unblock server consumer -> server drains items 1 & 2, sending Credit(1) each,
            // which unblocks item 3 and 30 more items across credit replenishment cycles!
            received_gate_tx.send(()).await.unwrap();
            send_3.await.expect("send 3 after credit replenished");

            for seq in 4..=25 {
                tx.send(make_pkt(seq)).await.expect("send paced packet");
            }
            tx.close().await.expect("close stream");

            let total = done_fut
                .await
                .expect("done future")
                .expect("transform result");
            assert_eq!(total, 25);

            let mut seen = Vec::new();
            while let Ok(seq) = item_ack_rx.try_recv() {
                seen.push(seq);
            }
            assert_eq!(seen, (1..=25).collect::<Vec<u32>>());

            handle_a.close();
            handle_b.close();
        };

        or(check, async {
            let _ = zip(
                zip(endpoint_a.drive(), endpoint_b.drive()),
                pump_bg_tasks(bg_rx),
            )
            .await;
        })
        .await;
    });

    // Also verify a misbehaving raw peer sending sub-path Data without credit
    // fails with typed `WireError::StreamCreditExceeded`.
    block_on(async {
        let ((client_read, client_write), (mut raw_read, mut raw_write)) = duplex_pipe(32);
        let config = EndpointConfig {
            stream_credit_window: 1,
        };
        let endpoint = Endpoint::with_config(client_read, client_write, (), config);
        let handle = endpoint.handle();
        let client = lab::Client::new(handle.clone());

        let caller = async {
            let res = client.await_ticket(true).await;
            match res {
                Ok(fut_reader) => {
                    let err = fut_reader
                        .await
                        .expect_err("uncredited sub-path flood must fail");
                    assert_eq!(
                        err.wire_error(),
                        Some(&WireError::StreamCreditExceeded {
                            invocation: 1,
                            path: vec![1, 1],
                        })
                    );
                }
                Err(err) => {
                    assert_eq!(
                        err.wire_error(),
                        Some(&WireError::StreamCreditExceeded {
                            invocation: 1,
                            path: vec![1, 1],
                        })
                    );
                }
            }
            handle.close();
        };

        let raw_peer = async {
            // Read Open(1), Data([0]), Close([0]).
            assert!(matches!(
                read_frame(&mut raw_read).await.unwrap(),
                Some(Frame::Open { invocation: 1, .. })
            ));
            write_frame(&mut raw_write, &Frame::Accept { invocation: 1 })
                .await
                .unwrap();
            let _ = read_frame(&mut raw_read).await.unwrap();
            let _ = read_frame(&mut raw_read).await.unwrap();

            // Return FutureReader pointing to sub_id = 1.
            write_frame(
                &mut raw_write,
                &Frame::Data {
                    invocation: 1,
                    path: vec![1],
                    payload: 1_u32.to_le_bytes().to_vec(),
                },
            )
            .await
            .unwrap();
            write_frame(
                &mut raw_write,
                &Frame::Close {
                    invocation: 1,
                    path: vec![1],
                },
            )
            .await
            .unwrap();

            // Wait for the 1 credit grant on [1, 1], then violate flow control by sending TWO Data frames!
            assert_eq!(
                read_frame(&mut raw_read).await.unwrap(),
                Some(Frame::Credit {
                    invocation: 1,
                    path: vec![1, 1],
                    credits: 1,
                })
            );
            for _ in 0..2 {
                write_frame(
                    &mut raw_write,
                    &Frame::Data {
                        invocation: 1,
                        path: vec![1, 1],
                        payload: vec![1, 0],
                    },
                )
                .await
                .unwrap();
            }
        };

        or(
            async {
                zip(caller, raw_peer).await;
            },
            async {
                let _ = endpoint.drive().await;
            },
        )
        .await;
    });
}

#[test]
fn dropping_inflight_future_propagates_root_close_and_releases_borrows() {
    block_on(async {
        let ((a_read, a_write), (b_read, b_write)) = duplex_pipe(32);
        let telemetry = Arc::new(LabTelemetry::default());
        let (service, bg_rx) = LabService::new("cancel-peer", Arc::clone(&telemetry));

        let client_ep = Endpoint::new(a_read, a_write, ());
        let server_ep = Endpoint::new(b_read, b_write, lab::Server::new(service));
        let client_handle = client_ep.handle();
        let server_handle = server_ep.handle();
        let client = lab::Client::new(client_handle.clone());

        let test_body = async {
            let acc = client.accumulator_new(77).await.expect("create acc");

            // Start `hold_slow(&acc)` which borrows `acc` on the server and parks.
            let entered_listener = telemetry.slow_entered.listen();
            let dropped_listener = telemetry.slow_dropped_event.listen();
            {
                let mut slow_call = Box::pin(acc.hold_slow());
                let wait_entered = async {
                    entered_listener.await;
                };
                // Drive `slow_call` until the server handler has entered and borrowed `acc`.
                or(
                    async {
                        let _ = slow_call.as_mut().await;
                    },
                    wait_entered,
                )
                .await;

                // While `acc` is actively borrowed on the server, attempting to move/consume
                // the same handle ID via a forged owned wrapper must fail with `ResourceBorrowed`!
                let forged_own =
                    Accumulator::from_raw_handle(client_handle.clone(), acc.handle_id(), false);
                let borrow_conflict = client
                    .consume_accumulator(forged_own)
                    .await
                    .expect_err("cannot consume actively borrowed resource");
                assert_eq!(
                    borrow_conflict.wire_error(),
                    Some(&WireError::ResourceBorrowed {
                        handle: acc.handle_id(),
                    })
                );

                // Drop the in-flight `slow_call` future! This emits root `Frame::Close { path: [] }`.
                drop(slow_call);
            }

            // Server must cancel and drop the in-flight handler future promptly!
            dropped_listener.await;
            assert!(telemetry.slow_cancelled.load(Ordering::Acquire));

            // Borrow was released when the cancelled handler dropped, so `consume_accumulator`
            // now succeeds cleanly on the same connection!
            let value = client
                .consume_accumulator(acc)
                .await
                .expect("consume after cancel");
            assert_eq!(value, 77);

            client_handle.close();
            server_handle.close();
        };

        or(test_body, async {
            let _ = zip(
                zip(client_ep.drive(), server_ep.drive()),
                pump_bg_tasks(bg_rx),
            )
            .await;
        })
        .await;
    });
}

#[test]
fn invalid_forged_and_mismatched_resource_handles_fail_with_typed_wire_error() {
    block_on(async {
        let ((a_read, a_write), (b_read, b_write)) = duplex_pipe(32);
        let telemetry = Arc::new(LabTelemetry::default());
        let (service, bg_rx) = LabService::new("handle-sec", Arc::clone(&telemetry));

        let client_ep = Endpoint::new(a_read, a_write, ());
        let server_ep = Endpoint::new(b_read, b_write, lab::Server::new(service));
        let client_handle = client_ep.handle();
        let client = lab::Client::new(client_handle.clone());

        let test_body = async {
            // 1. Forged non-existent handle ID (9999) on borrow<accumulator>.
            let bogus = Accumulator::from_raw_handle(client_handle.clone(), 9999, false);
            let err = bogus
                .snapshot()
                .await
                .expect_err("forged handle 9999 must fail");
            assert_eq!(
                err.wire_error(),
                Some(&WireError::InvalidResourceHandle { handle: 9999 })
            );

            // 2. Forged zero handle ID (0) on own<accumulator>.
            let zero_acc = Accumulator::from_raw_handle(client_handle.clone(), 0, false);
            let err_zero = client
                .consume_accumulator(zero_acc)
                .await
                .expect_err("forged handle 0 must fail");
            assert_eq!(
                err_zero.wire_error(),
                Some(&WireError::InvalidResourceHandle { handle: 0 })
            );

            // 3. Wrong resource type handle (`Lease` handle passed as `Accumulator`!).
            let real_lease = Lease::new(&client_handle, "valid-lease".to_owned())
                .await
                .expect("create lease");
            let lease_id = real_lease.handle_id();

            let type_confused_borrow =
                Accumulator::from_raw_handle(client_handle.clone(), lease_id, false);
            let mismatch_err = type_confused_borrow
                .add(1)
                .await
                .expect_err("mismatched handle type on borrow must fail");
            assert_eq!(
                mismatch_err.wire_error(),
                Some(&WireError::ResourceTypeMismatch {
                    handle: lease_id,
                    expected: "accumulator".to_owned(),
                    actual: "lease".to_owned(),
                })
            );

            let type_confused_own =
                Accumulator::from_raw_handle(client_handle.clone(), lease_id, false);
            let mismatch_own_err = client
                .consume_accumulator(type_confused_own)
                .await
                .expect_err("mismatched handle type on own must fail and preserve original");
            assert_eq!(
                mismatch_own_err.wire_error(),
                Some(&WireError::ResourceTypeMismatch {
                    handle: lease_id,
                    expected: "accumulator".to_owned(),
                    actual: "lease".to_owned(),
                })
            );

            // Original `Lease` must still be intact after rejected type-confused take!
            assert_eq!(
                real_lease.tag().await.expect("lease still alive"),
                "handle-sec:valid-lease"
            );

            // 4. Use-after-drop handle ID.
            let drop_wait = telemetry.resource_dropped.listen();
            drop(real_lease);
            drop_wait.await;

            let stale = Lease::from_raw_handle(client_handle.clone(), lease_id, false);
            let stale_err = stale
                .tag()
                .await
                .expect_err("use-after-drop handle must fail");
            assert_eq!(
                stale_err.wire_error(),
                Some(&WireError::InvalidResourceHandle { handle: lease_id })
            );

            // 5. Forged `Frame::ResourceDrop` surfaces `WireError::InvalidResourceHandle` on server!
            client_handle.drop_remote_resource(7777);
        };

        let server_outcome = async {
            let res = server_ep.drive().await;
            let err = res.expect_err("forged Frame::ResourceDrop must fail server drive");
            assert_eq!(
                err.wire_error(),
                Some(&WireError::InvalidResourceHandle { handle: 7777 })
            );
            client_handle.close();
        };

        let _ = zip(
            test_body,
            or(
                async {
                    let ((), _) = zip(server_outcome, client_ep.drive()).await;
                },
                pump_bg_tasks(bg_rx),
            ),
        )
        .await;
    });
}

#[test]
fn transport_disconnect_drops_every_live_resource_and_wakes_callers() {
    block_on(async {
        let ((a_read, a_write), (b_read, b_write)) = duplex_pipe(32);
        let telemetry = Arc::new(LabTelemetry::default());
        let (service, bg_rx) = LabService::new("disconnect-peer", Arc::clone(&telemetry));

        let client_ep = Endpoint::new(a_read, a_write, ());
        let server_ep = Endpoint::new(b_read, b_write, lab::Server::new(service));
        let client_handle = client_ep.handle();
        let client = lab::Client::new(client_handle.clone());

        let (arm_disconnect_tx, arm_disconnect_rx) = async_channel::bounded::<()>(1);
        let (armed_tx, armed_rx) = async_channel::bounded::<()>(1);

        let client_side = async {
            let mut held_accumulators = Vec::new();
            let mut held_leases = Vec::new();
            for i in 0..4 {
                held_accumulators.push(client.accumulator_new(i).await.expect("create acc"));
                held_leases.push(
                    Lease::new(&client_handle, format!("lease-{i}"))
                        .await
                        .expect("create lease"),
                );
            }
            assert_eq!(telemetry.live_accumulators.load(Ordering::Acquire), 4);
            assert_eq!(telemetry.live_leases.load(Ordering::Acquire), 4);

            // Tell `drive_client` to arm its `slow_entered` listener BEFORE we
            // invoke `never_returns`, then drive `never_returns` until the
            // server enters it and `drive_client` drops the client endpoint!
            arm_disconnect_tx.send(()).await.unwrap();
            armed_rx.recv().await.unwrap();

            let call_err = client
                .never_returns()
                .await
                .expect_err("in-flight call must wake with error on disconnect");
            assert!(matches!(
                call_err,
                RpcError::Transport(_) | RpcError::Rejected(_)
            ));

            // Prevent client `Drop` from sending `ResourceDrop` so we prove
            // `on_disconnect` itself dropped all 8 server resources!
            for acc in held_accumulators {
                let _ = acc.into_remote().into_raw_handle();
            }
            for lease in held_leases {
                let _ = lease.into_remote().into_raw_handle();
            }
        };

        let drive_client = async {
            or(
                async {
                    let _ = client_ep.drive().await;
                },
                async {
                    let _ = arm_disconnect_rx.recv().await;
                    let entered = telemetry.slow_entered.listen();
                    armed_tx.send(()).await.unwrap();
                    entered.await;
                },
            )
            .await;
        };

        let (((), ()), ()) = zip(
            zip(client_side, drive_client),
            or(
                async {
                    server_ep.drive().await.expect("clean EOF teardown");
                },
                async {
                    pump_bg_tasks(bg_rx).await;
                },
            ),
        )
        .await;

        assert_eq!(
            telemetry.live_accumulators.load(Ordering::Acquire),
            0,
            "every live accumulator must be dropped on transport disconnect"
        );
        assert_eq!(
            telemetry.live_leases.load(Ordering::Acquire),
            0,
            "every live lease must be dropped on transport disconnect"
        );
    });
}

#[test]
fn real_workspace_inspector_system_wit_world_generates_and_streams_child_stdio() {
    use system_wit::InspectorSystemClient;
    use system_wit::helios::system::programs::{
        self, AotRequest, AotResult, ChildTermination, ContainerConfig, ContainerExecRequest,
        ContainerSpawnRequest, ExecError, ExecOutput, ExecRequest, ExecResult, ExitStatus,
        SpawnError, SpawnRequest,
    };

    struct MockChild {
        id: u64,
    }

    struct MockProgramsServer;

    impl programs::Handler for MockProgramsServer {
        type Child = MockChild;
        type Container = ();
        type Endpoint = ();

        async fn child_stdin(
            &self,
            _self_: &Self::Child,
            data: StreamReader<u8>,
        ) -> FutureReader<Result<(), ()>> {
            FutureReader::ready(
                data.collect_all()
                    .await
                    .map(|bytes| assert_eq!(bytes, b"hello stdin"))
                    .map_err(|_| ()),
            )
        }

        async fn child_stdout(
            &self,
            self_: &Self::Child,
        ) -> (StreamReader<u8>, FutureReader<Result<(), ()>>) {
            (
                StreamReader::from_vec(format!("stdout-from-{}", self_.id).into_bytes()),
                FutureReader::ready(Ok(())),
            )
        }

        async fn child_stderr(
            &self,
            _self_: &Self::Child,
        ) -> (StreamReader<u8>, FutureReader<Result<(), ()>>) {
            (StreamReader::empty(), FutureReader::ready(Ok(())))
        }

        async fn child_wait(&self, self_: &Self::Child) -> Result<ExitStatus, SpawnError> {
            Ok(ExitStatus {
                instance_id: self_.id,
                termination: ChildTermination::Exited(0),
            })
        }

        async fn container_spawn(
            &self,
            _self_: &Self::Container,
            _request: ContainerSpawnRequest,
        ) -> Result<Self::Child, SpawnError> {
            Ok(MockChild { id: 2 })
        }

        async fn container_exec(
            &self,
            _self_: &Self::Container,
            _request: ContainerExecRequest,
        ) -> Result<ExecResult, ExecError> {
            unreachable!()
        }

        async fn create_container(
            &self,
            _config: ContainerConfig<Self::Endpoint>,
        ) -> Result<Self::Container, SpawnError> {
            Ok(())
        }

        async fn spawn(
            &self,
            request: SpawnRequest<Self::Endpoint>,
        ) -> Result<Self::Child, SpawnError> {
            assert_eq!(request.name, "nu");
            Ok(MockChild { id: 42 })
        }

        async fn exec(
            &self,
            _request: ExecRequest<Self::Endpoint>,
        ) -> Result<ExecResult, ExecError> {
            Ok(ExecResult {
                instance_id: 1,
                exit_code: 0,
                output: ExecOutput {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                },
                launch_nanos: 100,
            })
        }

        async fn aot(&self, _request: AotRequest) -> Result<AotResult, ExecError> {
            unreachable!()
        }
    }

    block_on(async {
        let ((c_read, c_write), (s_read, s_write)) = duplex_pipe(16);
        let client_ep = Endpoint::new(c_read, c_write, ());
        let server_ep = Endpoint::new(s_read, s_write, programs::Server::new(MockProgramsServer));

        let client_handle = client_ep.handle();
        let server_handle = server_ep.handle();
        let sys = InspectorSystemClient::new(client_handle.clone());

        let caller = async {
            let child = sys
                .programs()
                .spawn(SpawnRequest {
                    name: "nu".to_owned(),
                    args: vec!["-c".to_owned(), "ls".to_owned()],
                    env: Vec::new(),
                    path: "/bin/nu".to_owned(),
                    capability_grants: Vec::new(),
                })
                .await
                .expect("rpc call")
                .expect("spawn ok");

            let stdin_done = child
                .stdin(StreamReader::from_vec(b"hello stdin".to_vec()))
                .await
                .expect("stdin call");
            let (stdout_rx, stdout_done) = child.stdout().await.expect("stdout call");
            let (stderr_rx, stderr_done) = child.stderr().await.expect("stderr call");

            stdin_done.await.expect("stdin fut").expect("stdin ok");
            let out_bytes = stdout_rx.collect_all().await.expect("collect stdout");
            assert_eq!(out_bytes, b"stdout-from-42");
            stdout_done.await.expect("stdout fut").expect("stdout ok");
            assert!(
                stderr_rx
                    .collect_all()
                    .await
                    .expect("collect stderr")
                    .is_empty()
            );
            stderr_done.await.expect("stderr fut").expect("stderr ok");

            let exit = child.wait().await.expect("wait call").expect("wait ok");
            assert_eq!(exit.instance_id, 42);
            assert_eq!(exit.termination, ChildTermination::Exited(0));

            drop(child);
            client_handle.close();
            server_handle.close();
        };

        or(caller, async {
            let _ = zip(client_ep.drive(), server_ep.drive()).await;
        })
        .await;
    });
}

#[test]
fn composed_multi_interface_dispatchers_share_connection_handle_namespace() {
    mod extra {
        helios_wit_rpc::generate!({
            inline: r#"
                package helios:extra@0.1.0;

                interface vault {
                    resource secret {
                        constructor(name: string);
                        reveal: func() -> string;
                    }
                }
            "#,
            interface: "helios:extra/vault",
        });
    }

    use extra::helios::extra::vault;

    struct SecretImpl {
        name: String,
        live: Arc<AtomicUsize>,
        dropped: Arc<Event>,
    }

    impl Drop for SecretImpl {
        fn drop(&mut self) {
            self.live.fetch_sub(1, Ordering::AcqRel);
            self.dropped.notify(usize::MAX);
        }
    }

    struct VaultService {
        live: Arc<AtomicUsize>,
        dropped: Arc<Event>,
    }

    impl vault::Handler for VaultService {
        type Secret = SecretImpl;

        async fn secret_new(&self, name: String) -> Self::Secret {
            self.live.fetch_add(1, Ordering::AcqRel);
            SecretImpl {
                name,
                live: Arc::clone(&self.live),
                dropped: Arc::clone(&self.dropped),
            }
        }

        async fn secret_reveal(&self, self_: &Self::Secret) -> String {
            self_.name.clone()
        }
    }

    block_on(async {
        let ((c_read, c_write), (s_read, s_write)) = duplex_pipe(16);
        let lab_telemetry = Arc::new(LabTelemetry::default());
        let (lab_service, bg_rx) = LabService::new("composed", Arc::clone(&lab_telemetry));
        let vault_live = Arc::new(AtomicUsize::new(0));
        let vault_dropped = Arc::new(Event::new());
        let vault_service = VaultService {
            live: Arc::clone(&vault_live),
            dropped: Arc::clone(&vault_dropped),
        };

        let client_ep = Endpoint::new(c_read, c_write, ());
        let server_ep = Endpoint::new(
            s_read,
            s_write,
            (
                lab::Server::new(lab_service),
                vault::Server::new(vault_service),
            ),
        );
        let client_handle = client_ep.handle();
        let server_handle = server_ep.handle();

        let caller = async {
            let acc = Accumulator::new(&client_handle, 5)
                .await
                .expect("create acc");
            let sec = vault::Secret::new(&client_handle, "key-中文日本語한국어".to_owned())
                .await
                .expect("create secret");
            assert_ne!(
                acc.handle_id(),
                sec.handle_id(),
                "composed dispatchers must draw distinct handles from one connection allocator"
            );
            assert_eq!(acc.add(7).await.expect("add"), 12);
            assert_eq!(sec.reveal().await.expect("reveal"), "key-中文日本語한국어");

            let wait_vault_drop = vault_dropped.listen();
            drop(sec);
            wait_vault_drop.await;
            assert_eq!(vault_live.load(Ordering::Acquire), 0);

            let wait_acc_drop = lab_telemetry.resource_dropped.listen();
            drop(acc);
            wait_acc_drop.await;
            assert_eq!(lab_telemetry.live_accumulators.load(Ordering::Acquire), 0);

            client_handle.close();
            server_handle.close();
        };

        or(caller, async {
            let _ = zip(
                zip(client_ep.drive(), server_ep.drive()),
                pump_bg_tasks(bg_rx),
            )
            .await;
        })
        .await;
    });
}

#[test]
fn oneshot_future_omits_credit_replenishment_returns_without_eof_and_rejects_second_data() {
    block_on(async {
        let ((client_read, client_write), (mut raw_read, mut raw_write)) = duplex_pipe(32);
        let config = EndpointConfig {
            stream_credit_window: 2,
        };
        let endpoint = Endpoint::with_config(client_read, client_write, (), config);
        let handle = endpoint.handle();
        let client = lab::Client::new(handle.clone());

        let (resolved_tx, resolved_rx) = async_channel::bounded::<()>(1);
        let (second_sent_tx, second_sent_rx) = async_channel::bounded::<()>(1);

        let caller = async {
            let (mut out_stream, done_fut) = client
                .transform(StreamReader::empty(), "oneshot".to_owned())
                .await
                .expect("open transform");

            // Raw peer omits trailing `Frame::Close` on `[1, 2]`; single-shot
            // `FutureReader` must still resolve immediately with `Ok(77)`.
            let total = done_fut
                .await
                .expect("oneshot future must resolve without trailing Close")
                .expect("result ok");
            assert_eq!(total, 77);
            resolved_tx.send(()).await.unwrap();

            // Open a second call as an in-order wire barrier so `raw_peer` can
            // prove no spurious `Credit(1)` or stop-reading `Close` was emitted
            // for `[1, 2]` before `Open(2)`.
            let sentinel = client.await_ticket(true).await.expect("sentinel open");
            drop(sentinel);

            // Wait until the raw peer transmits a delayed second `Frame::Data`
            // on the exhausted single-shot future path `[1, 2]`.
            second_sent_rx.recv().await.unwrap();
            let err = out_stream.next().await.expect_err(
                "delayed second Data on oneshot future must fail with StreamCreditExceeded",
            );
            assert_eq!(
                err.wire_error(),
                Some(&WireError::StreamCreditExceeded {
                    invocation: 1,
                    path: vec![1, 2],
                })
            );

            handle.close();
        };

        let raw_peer = async {
            assert!(matches!(
                read_frame(&mut raw_read).await.unwrap(),
                Some(Frame::Open { invocation: 1, .. })
            ));
            write_frame(&mut raw_write, &Frame::Accept { invocation: 1 })
                .await
                .unwrap();

            // Drain request frames (`Data([0])`, `Close([0])`, empty input stream `Close([0, 1])`)
            // and initial credits (`Credit([1, 1], 2)` and `Credit([1, 2], 1)`).
            let mut saw_root_close = false;
            while !saw_root_close {
                match read_frame(&mut raw_read).await.unwrap() {
                    Some(Frame::Close {
                        invocation: 1,
                        path,
                    }) if path == vec![0] => saw_root_close = true,
                    Some(_) => {}
                    None => panic!("unexpected EOF reading request"),
                }
            }

            // Return `(out_stream: sub_id = 1, done_fut: sub_id = 2)`.
            let mut root_resp = Vec::with_capacity(8);
            root_resp.extend_from_slice(&1_u32.to_le_bytes());
            root_resp.extend_from_slice(&2_u32.to_le_bytes());
            write_frame(
                &mut raw_write,
                &Frame::Data {
                    invocation: 1,
                    path: vec![1],
                    payload: root_resp,
                },
            )
            .await
            .unwrap();
            write_frame(
                &mut raw_write,
                &Frame::Close {
                    invocation: 1,
                    path: vec![1],
                },
            )
            .await
            .unwrap();

            let mut saw_stream_credit = false;
            let mut saw_future_credit = false;
            while !(saw_stream_credit && saw_future_credit) {
                match read_frame(&mut raw_read).await.unwrap() {
                    Some(Frame::Credit {
                        invocation: 1,
                        path,
                        credits: 2,
                    }) if path == vec![1, 1] => saw_stream_credit = true,
                    Some(Frame::Credit {
                        invocation: 1,
                        path,
                        credits: 1,
                    }) if path == vec![1, 2] => saw_future_credit = true,
                    Some(Frame::Close {
                        invocation: 1,
                        path,
                    }) if path == vec![0, 1] => {}
                    other => panic!("unexpected frame waiting for initial credits: {other:?}"),
                }
            }

            // Send single `Result::Ok(77_u64)` payload on future sub-path `[1, 2]`
            // WITHOUT any `Frame::Close`.
            let mut fut_payload = Vec::with_capacity(9);
            fut_payload.push(0); // Result::Ok
            fut_payload.extend_from_slice(&77_u64.to_le_bytes());
            write_frame(
                &mut raw_write,
                &Frame::Data {
                    invocation: 1,
                    path: vec![1, 2],
                    payload: fut_payload.clone(),
                },
            )
            .await
            .unwrap();

            // Wait until the client has already consumed the oneshot future and
            // opened invocation 2, verifying ZERO spurious `Credit` or stop-reading
            // `Close` frames were emitted for `[1, 2]`.
            resolved_rx.recv().await.unwrap();
            loop {
                match read_frame(&mut raw_read).await.unwrap() {
                    Some(Frame::Open { invocation: 2, .. }) => {
                        write_frame(&mut raw_write, &Frame::Accept { invocation: 2 })
                            .await
                            .unwrap();
                        write_frame(
                            &mut raw_write,
                            &Frame::Data {
                                invocation: 2,
                                path: vec![1],
                                payload: 1_u32.to_le_bytes().to_vec(),
                            },
                        )
                        .await
                        .unwrap();
                        write_frame(
                            &mut raw_write,
                            &Frame::Close {
                                invocation: 2,
                                path: vec![1],
                            },
                        )
                        .await
                        .unwrap();
                        break;
                    }
                    Some(Frame::Credit {
                        invocation: 1,
                        path,
                        credits,
                    }) if path == vec![1, 2] => {
                        panic!(
                            "oneshot future must never replenish credit (got Credit({credits}))"
                        );
                    }
                    Some(Frame::Close {
                        invocation: 1,
                        path,
                    }) if path == vec![2, 2] => {
                        panic!("resolved oneshot future must not emit stop-reading Close");
                    }
                    Some(_) => {}
                    None => panic!("unexpected EOF before sentinel Open(2)"),
                }
            }

            // Now send a delayed second `Frame::Data` on `[1, 2]` (credit is 0!).
            write_frame(
                &mut raw_write,
                &Frame::Data {
                    invocation: 1,
                    path: vec![1, 2],
                    payload: fut_payload,
                },
            )
            .await
            .unwrap();
            second_sent_tx.send(()).await.unwrap();
        };

        or(zip(caller, raw_peer), async {
            let _ = endpoint.drive().await;
            ((), ())
        })
        .await;
    });
}

#[test]
fn resource_take_restores_slot_on_extra_arc_and_writer_closed_does_not_block_is_closed() {
    use helios_wit_rpc::{ResourceEntry, ResourceTableInner};

    struct TestEntry(Arc<AtomicUsize>);
    impl ResourceEntry for TestEntry {
        fn kind_name(&self) -> &'static str {
            "test-entry"
        }
    }

    let mut table = ResourceTableInner::new();
    let shared = Arc::new(AtomicUsize::new(42));
    let extra_ref = Arc::clone(&shared);
    let handle = table.insert(TestEntry(shared)).expect("insert");

    // Simulate an extra `Arc` reference surviving when `borrows == 0`: `take`
    // must fail with `ResourceBorrowed` AND restore the slot without dropping
    // the live resource.
    let err = table
        .take(handle, "test-entry", |TestEntry(arc)| Ok(arc), TestEntry)
        .expect_err("extra Arc ref must fail take with ResourceBorrowed");
    assert_eq!(err, WireError::ResourceBorrowed { handle });
    assert!(
        table.contains(handle),
        "failed take must restore slot instead of destroying live resource"
    );

    // Borrowing and dropping releases the borrow's Arc before decrementing
    // `borrows`, so an immediate `take` after dropping `extra_ref` and `borrow`
    // succeeds cleanly.
    let borrow = table
        .borrow(handle, "test-entry", |TestEntry(arc)| Some(arc))
        .expect("borrow restored slot");
    assert_eq!(borrow.load(Ordering::Acquire), 42);
    drop(extra_ref);
    drop(borrow);

    let owned = table
        .take(handle, "test-entry", |TestEntry(arc)| Ok(arc), TestEntry)
        .expect("take after borrow drop");
    assert_eq!(owned.load(Ordering::Acquire), 42);
    assert!(!table.contains(handle));

    // Also verify `StreamWriter::closed()` parked on `.await` does not block
    // concurrent `StreamWriter::is_closed()` both before and after binding
    // (no MutexGuard held across `.await`).
    block_on(async {
        let (writer, reader) = stream::<u32>();
        let mut closed_fut = Box::pin(writer.closed());
        assert!(poll_once(&mut closed_fut).await.is_none());
        assert!(!writer.is_closed().await);
        drop(reader);
        assert!(writer.is_closed().await);
        closed_fut.await;
    });

    block_on(async {
        let ((a_read, a_write), (b_read, b_write)) = duplex_pipe(16);
        let endpoint_a = Endpoint::new(a_read, a_write, ());
        let handle_a = endpoint_a.handle();
        let client = lab::Client::new(handle_a.clone());

        let telemetry = Arc::new(LabTelemetry::default());
        let (service, bg_rx) = LabService::new("bound-closed", telemetry);
        let endpoint_b = Endpoint::new(b_read, b_write, lab::Server::new(service));
        let handle_b = endpoint_b.handle();

        let check = async {
            let (mut writer, reader) = stream::<Packet>();
            let (_out, _done) = client
                .transform(reader, "bound".to_owned())
                .await
                .expect("open transform");
            writer
                .send(Packet {
                    seq: 1,
                    label: "ok".to_owned(),
                    perms: Permissions::READ,
                    mode: Mode::Fast,
                })
                .await
                .expect("send first item");
            let mut closed_fut = Box::pin(writer.closed());
            assert!(poll_once(&mut closed_fut).await.is_none());
            assert!(!writer.is_closed().await);
            drop(closed_fut);
            writer.close().await.expect("close writer");
            handle_a.close();
            handle_b.close();
        };

        or(check, async {
            let _ = zip(
                zip(endpoint_a.drive(), endpoint_b.drive()),
                pump_bg_tasks(bg_rx),
            )
            .await;
        })
        .await;
    });
}
