//! The `compositor` kernel plugin: boot splash, VT1 system log console, and VT2 desktop.
//!
//! `helios:system/surface` in the kernel is a forwarder — it pins a
//! client's frame buffer, mints an identity and hands both here. This
//! component is what is on the other end. It is an ordinary user-mode
//! wasm program with the ordinary isolation model; its authority ceiling
//! carries ONLY `devices = ["display", "input"]`, `inspect_read = "machine"`,
//! `trace_read = "machine"`, and the routed `console-tty` IPC channel to
//! `/console-session`. It holds zero filesystem, network, process, or identity
//! authority.
//!
//! # Screen state machine
//!
//! 1. **Boot splash** (`0.00s..2.00s`): analytical SDF emblem and progress bar
//!    rendered at ~60 fps into the single scanout surface with tight damage
//!    rectangles.
//! 2. **Cross-fade** (`0.60s`): fixed-point pixel blend from the settled splash
//!    into either VT1 (full-screen dark system log console, normal boot) or VT2
//!    (desktop terminal, when `/console-session` signals `--console-shell`).
//! 3. **Active VT**:
//!    - **VT1 (`Alt+F1`)**: real-time kernel & component `TraceLog` stream plus
//!      `[  OK  ]` service readiness lines from `/components/*` inspect. Press
//!      `Enter` or `Alt+F2` to switch to VT2.
//!    - **VT2 (`Alt+F2`)**: wallpaper, client windows (`helios:system/surface`),
//!      and the interactive terminal whose byte stream is carried over IPC to
//!      the privilege-separated `/console-session` daemon.

use std::collections::BTreeSet;
use std::string::String;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::vec::Vec;

use helios_api::channel::{Receiver, Sender, bounded};
use helios_api::compositor::{
    BlockError, Error, Guest, GuestDesktop, Image as RawImage, Rect,
    SignalSource as RawSignalSource, Span,
};
use helios_api::display::{Display, DisplayError, Mode, PixelFormat, Point, Rect as DisplayRect};
use helios_api::image::Image;
use helios_api::input::{Device, InputError, InputEvent, available, codes, ends_frame};
use helios_api::inspect::{self, Value as InspectValue};
use helios_api::ipc::{self, Endpoint};
use helios_api::surface;
use helios_api::sync::{SignalSource, TimelineError};
use helios_api::task::{sleep, spawn};
use helios_api::tracing::{self, Event as TraceEvent, Filter as TraceFilter, Value as TraceValue};
use thiserror::Error;

use helios_compositor_render::console::{LogConsole, ServiceStatus};
use helios_compositor_render::damage::Region;
use helios_compositor_render::desktop::{Desktop, Focus};
use helios_compositor_render::font::{CELL_HEIGHT, CELL_WIDTH};
use helios_compositor_render::keys::{KeyAction, Keyboard};
use helios_compositor_render::splash::{CROSSFADE_DURATION_SECS, SplashRenderer};
use helios_compositor_render::tty::{
    CONSOLE_TTY_CHANNEL, FrameDecoder, TtyClientMsg, TtyServerMsg, encode_frame,
};

mod presentation;
use presentation::Presentation;

mod bindings {
    pub use ::helios_api::bindings::*;
}

/// Events waiting to be folded into the next frame.
const EVENT_QUEUE_DEPTH: usize = 256;

/// Outbound TTY IPC queue depth.
const TTY_OUT_QUEUE_DEPTH: usize = 64;

/// Bytes read from the `console-tty` IPC endpoint in one pass.
const IPC_READ_CHUNK: u32 = 4096;

/// The scanout the desktop draws on. One display, one output.
const SCANOUT: u32 = 0;

/// Duration of the four-stage boot splash before cross-fading into the active VT.
const SPLASH_DURATION_SECS: f32 = 2.0;

/// Animation tick period (~60 fps) while the boot splash or cross-fade is active.
const SPLASH_TICK_INTERVAL: Duration = Duration::from_millis(16);

/// Cadence for polling `/components/*` inspect readiness for VT1 status lines.
const COMPONENT_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Maximum initial tracing backlog events pulled onto VT1 at startup.
const INITIAL_TRACE_LIMIT: u32 = 256;

/// Maximum `/components/` inspect entries read per readiness poll.
const COMPONENT_INSPECT_LIMIT: u32 = 512;

/// Why the desktop gave up.
#[derive(Debug, Error)]
enum DesktopError {
    #[error("frame retirement failed: {0}")]
    Timeline(#[from] TimelineError),
    #[error("the display refused: {0}")]
    Display(#[from] DisplayError),
    #[error("the input service refused: {0}")]
    Input(#[from] InputError),
    #[error("this machine has no input device, so nothing could reach the desktop")]
    NoInput,
    #[error("the output reports a {width}x{height} mode, which has no pixels to draw")]
    EmptyMode { width: u32, height: u32 },
    #[error("everything that feeds the desktop has stopped")]
    Starved,
}

impl DesktopError {
    /// How this reads to the kernel, and through it to a client.
    const fn as_wit(&self) -> Error {
        match self {
            Self::Timeline(_)
            | Self::Display(_)
            | Self::Input(_)
            | Self::NoInput
            | Self::EmptyMode { .. }
            | Self::Starved => Error::NoCompositor,
        }
    }
}

/// Which virtual terminal is active once the boot splash settles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActiveVt {
    /// VT1: full-screen kernel & component log console.
    Log,
    /// VT2: interactive terminal and client surface desktop.
    Terminal,
}

/// Top-level display state machine sharing the compositor's single `Surface`.
enum ScreenState {
    Splash {
        started_at: Instant,
        renderer: SplashRenderer,
        pixels: Vec<u32>,
    },
    Crossfade {
        started_at: Instant,
        splash_pixels: Vec<u32>,
        target_pixels: Vec<u32>,
        blended: Vec<u32>,
        target: ActiveVt,
    },
    Active(ActiveVt),
}

/// One thing that happened, to be folded into the next frame.
enum Event {
    CreateImage {
        id: u64,
        size: surface::Size,
        reply: Sender<Result<(), Error>>,
    },
    PresentImage {
        id: u64,
        image: Image,
        retired: SignalSource,
        reply: Sender<Result<(), Error>>,
    },
    /// An input device reported an event, with absolute axes already in
    /// scanout pixels.
    Input(InputEvent),
    /// A framed message received over `console-tty` from `/console-session`.
    Tty(TtyServerMsg),
    /// The `console-tty` IPC stream closed.
    TtyClosed,
    /// A kernel or component tracing record for VT1.
    Trace(TraceEvent),
    /// Resolved kernel `InstanceId` for `/plugins/compositor`, used to filter
    /// self-emitted log records out of VT1.
    SelfInstanceId(u64),
    /// A supervised component entered `running` state under `/components/*`.
    ComponentReady(String),
    /// 60 fps frame tick while the boot splash or cross-fade is active.
    SplashTick,
    /// A client asked for a window.
    Create {
        id: u64,
        width: u32,
        height: u32,
        reply: Sender<Result<Span, Error>>,
    },
    /// A client published pixels in one.
    Commit {
        id: u64,
        region: Region,
        reply: Sender<Result<(), Error>>,
    },
    /// A client's window is gone.
    Destroy { id: u64, reply: Sender<()> },
}

struct Compositor;

::helios_api::bindings::export!(Compositor);

impl Guest for Compositor {
    type Desktop = DesktopSession;
}

struct DesktopSession {
    events: Sender<Event>,
    queue: Receiver<Event>,
}

impl GuestDesktop for DesktopSession {
    fn new() -> Self {
        let (events, queue) = bounded(EVENT_QUEUE_DEPTH);
        Self { events, queue }
    }

    async fn run(&self) -> Result<(), Error> {
        match run_desktop(&self.events, &self.queue).await {
            Ok(()) => Ok(()),
            Err(error) => {
                println!("compositor:failed {error}");
                Err(error.as_wit())
            }
        }
    }

    async fn create_image(&self, id: u64, dimensions: Rect) -> Result<(), Error> {
        let (reply, answer) = bounded(1);
        self.ask(Event::CreateImage {
            id,
            size: surface::Size {
                width: dimensions.width,
                height: dimensions.height,
            },
            reply,
        })
        .await?;
        answer.recv().await.map_err(|_| Error::NoCompositor)?
    }

    async fn present_image(
        &self,
        id: u64,
        image: RawImage,
        retired: RawSignalSource,
    ) -> Result<(), Error> {
        let (reply, answer) = bounded(1);
        self.ask(Event::PresentImage {
            id,
            image: image.into(),
            retired: retired.into(),
            reply,
        })
        .await?;
        answer.recv().await.map_err(|_| Error::NoCompositor)?
    }

    async fn create(&self, id: u64, dimensions: Rect) -> Result<Span, Error> {
        let (reply, answer) = bounded(1);
        self.ask(Event::Create {
            id,
            width: dimensions.width,
            height: dimensions.height,
            reply,
        })
        .await?;
        answer.recv().await.map_err(|_| Error::NoCompositor)?
    }

    async fn commit(&self, id: u64, region: Rect) -> Result<(), Error> {
        let (reply, answer) = bounded(1);
        self.ask(Event::Commit {
            id,
            region: Region::new(region.x, region.y, region.width, region.height),
            reply,
        })
        .await?;
        answer.recv().await.map_err(|_| Error::NoCompositor)?
    }

    async fn destroy(&self, id: u64) {
        let (reply, answer) = bounded(1);
        if self.ask(Event::Destroy { id, reply }).await.is_ok() {
            let _ = answer.recv().await;
        }
    }
}

impl DesktopSession {
    async fn ask(&self, event: Event) -> Result<(), Error> {
        self.events
            .send(event)
            .await
            .map_err(|_| Error::NoCompositor)
    }
}

/// Own the desktop until it can no longer be owned.
async fn run_desktop(events: &Sender<Event>, queue: &Receiver<Event>) -> Result<(), DesktopError> {
    let display = Display::claim()?;
    let mode = display.preferred_mode(SCANOUT).await?;
    if mode.width == 0 || mode.height == 0 {
        return Err(DesktopError::EmptyMode {
            width: mode.width,
            height: mode.height,
        });
    }
    let surface = display.create(SCANOUT, mode, PixelFormat::Bgrx8888).await?;
    let mut desktop = Desktop::new(surface, mode);

    // Publish the cursor image and initial pointer position BEFORE any
    // `compositor:frame` log line so the display engine trace always sees an
    // `UPDATE_CURSOR` + `MOVE_CURSOR` covering the starting pointer position.
    desktop.set_cursor().await?;
    desktop.present_cursor().await?;

    let columns = desktop.terminal().columns() as u16;
    let rows = desktop.terminal().rows() as u16;
    let origin = desktop.terminal_origin();
    println!(
        "compositor:online scanout={SCANOUT} width={} height={}",
        mode.width, mode.height
    );
    println!(
        "compositor:terminal columns={columns} rows={rows} cell-width={CELL_WIDTH} cell-height={CELL_HEIGHT} origin={},{}",
        origin.0, origin.1
    );

    start_input(events, mode)?;
    let tty_out = start_tty_bridge(events, columns, rows);
    start_trace_feed(events);
    start_component_poller(events);

    let splash_done = Arc::new(AtomicBool::new(false));
    start_splash_ticker(events, Arc::clone(&splash_done));

    let mut log_console = LogConsole::new(mode);
    let mut presentation = Presentation::new(display);
    serve(
        &mut desktop,
        &mut log_console,
        &mut presentation,
        queue,
        tty_out.as_ref(),
        &splash_done,
    )
    .await
}

/// Connects to the supervisor-routed `console-tty` IPC channel if present.
fn start_tty_bridge(
    events: &Sender<Event>,
    columns: u16,
    rows: u16,
) -> Option<Sender<TtyClientMsg>> {
    let endpoint = ipc::take(CONSOLE_TTY_CHANNEL)?;
    let endpoint = Arc::new(endpoint);
    let (out_tx, out_rx) = bounded::<TtyClientMsg>(TTY_OUT_QUEUE_DEPTH);
    let _ = out_tx.try_send(TtyClientMsg::Attach { columns, rows });

    let reader_ep = Arc::clone(&endpoint);
    let reader_events = events.clone();
    spawn(async move {
        read_tty_endpoint(reader_ep, reader_events).await;
    });

    spawn(async move {
        write_tty_endpoint(endpoint, out_rx).await;
    });

    Some(out_tx)
}

async fn read_tty_endpoint(endpoint: Arc<Endpoint>, events: Sender<Event>) {
    let mut decoder = FrameDecoder::new();
    loop {
        match endpoint.read(IPC_READ_CHUNK).await {
            Ok(Some(bytes)) if !bytes.is_empty() => {
                decoder.push(&bytes);
                loop {
                    match decoder.next_frame::<TtyServerMsg>() {
                        Ok(Some(msg)) => {
                            if events.send(Event::Tty(msg)).await.is_err() {
                                return;
                            }
                        }
                        Ok(None) => break,
                        Err(error) => {
                            println!("compositor:tty-frame-error {error}");
                            break;
                        }
                    }
                }
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                let _ = events.send(Event::TtyClosed).await;
                return;
            }
        }
    }
}

async fn write_tty_endpoint(endpoint: Arc<Endpoint>, rx: Receiver<TtyClientMsg>) {
    while let Ok(msg) = rx.recv().await {
        let Ok(frame) = encode_frame(&msg) else {
            continue;
        };
        if endpoint.write(frame).await.is_err() {
            return;
        }
    }
}

/// Streams kernel and component tracing records into VT1.
fn start_trace_feed(events: &Sender<Event>) {
    let events = events.clone();
    spawn(async move {
        let filter = TraceFilter {
            min_level: None,
            target_prefixes: Vec::new(),
        };
        if let Ok(backlog) = tracing::recent(&filter, INITIAL_TRACE_LIMIT) {
            for event in backlog {
                if events.send(Event::Trace(event)).await.is_err() {
                    return;
                }
            }
        }
        let Ok(mut stream) = tracing::subscribe(&filter) else {
            return;
        };
        loop {
            let (result, batch) = stream.read(Vec::with_capacity(32)).await;
            for event in batch {
                if events.send(Event::Trace(event)).await.is_err() {
                    return;
                }
            }
            if helios_api::stream_closed(result) {
                return;
            }
        }
    });
}

/// Polls `/components/*` inspect state for compositor instance ID and service
/// readiness transitions shown on VT1.
fn start_component_poller(events: &Sender<Event>) {
    let events = events.clone();
    spawn(async move {
        let mut seen_running = BTreeSet::<String>::new();
        let mut known_self_id: Option<u64> = None;
        loop {
            if let Ok(snapshot) =
                inspect::snapshot_prefixes(&["/components/"], COMPONENT_INSPECT_LIMIT)
            {
                for entry in &snapshot.entries {
                    if entry.path == "/components/plugins/compositor/instance_id"
                        && let InspectValue::Unsigned64(id) = entry.value
                        && id > 0
                        && known_self_id != Some(id)
                    {
                        known_self_id = Some(id);
                        if events.send(Event::SelfInstanceId(id)).await.is_err() {
                            return;
                        }
                    }
                    if let Some(rest) = entry.path.strip_prefix("/components/")
                        && let Some(prefix) = rest.strip_suffix("/state")
                        && let InspectValue::Text(state) = &entry.value
                        && state == "running"
                    {
                        let moniker = if prefix == "root" {
                            String::from("/")
                        } else {
                            format!("/{prefix}")
                        };
                        if seen_running.insert(moniker.clone())
                            && events.send(Event::ComponentReady(moniker)).await.is_err()
                        {
                            return;
                        }
                    }
                }
            }
            sleep(COMPONENT_POLL_INTERVAL).await;
        }
    });
}

/// Drives ~60 fps ticks while the boot splash or cross-fade is active.
fn start_splash_ticker(events: &Sender<Event>, done: Arc<AtomicBool>) {
    let events = events.clone();
    spawn(async move {
        while !done.load(Ordering::Relaxed) {
            sleep(SPLASH_TICK_INTERVAL).await;
            if done.load(Ordering::Relaxed) {
                return;
            }
            match events.try_send(Event::SplashTick) {
                Ok(()) | Err(helios_api::channel::TrySendError::Full(_)) => {}
                Err(helios_api::channel::TrySendError::Closed(_)) => return,
            }
        }
    });
}

/// Claim every input device and read it into the desktop's queue.
fn start_input(events: &Sender<Event>, mode: Mode) -> Result<(), DesktopError> {
    let mut claimed = 0;
    for capabilities in available() {
        match Device::claim(&capabilities.name) {
            Ok(device) => {
                let axes = AbsoluteAxes::of(&device);
                println!("compositor:device name={}", capabilities.name);
                claimed += 1;
                let events = events.clone();
                spawn(async move {
                    read_device(device, axes, mode, events).await;
                });
            }
            Err(error) => {
                println!(
                    "compositor:device-refused name={} error={error}",
                    capabilities.name
                );
            }
        }
    }
    if claimed == 0 {
        return Err(DesktopError::NoInput);
    }
    Ok(())
}

/// The range a tablet reports its position over.
#[derive(Clone, Copy, Debug)]
struct AbsoluteAxes {
    x: Option<(i32, i32)>,
    y: Option<(i32, i32)>,
}

impl AbsoluteAxes {
    fn of(device: &Device) -> Self {
        let capabilities = device.capabilities();
        let range = |code: u16| {
            capabilities
                .abs_info
                .iter()
                .find(|axis| axis.code == code)
                .map(|axis| (axis.min, axis.max))
        };
        Self {
            x: range(codes::ABS_X),
            y: range(codes::ABS_Y),
        }
    }

    fn to_pixels(self, code: u16, value: i32, mode: Mode) -> Option<i32> {
        let (range, extent) = match code {
            codes::ABS_X => (self.x?, mode.width),
            codes::ABS_Y => (self.y?, mode.height),
            _ => return None,
        };
        let (min, max) = range;
        let span = i64::from(max) - i64::from(min);
        if span <= 0 {
            return None;
        }
        let offset = (i64::from(value) - i64::from(min)).clamp(0, span);
        let extent = i64::from(extent.saturating_sub(1));
        Some((offset * extent / span) as i32)
    }
}

/// Read one device for as long as its stream lasts.
async fn read_device(device: Device, axes: AbsoluteAxes, mode: Mode, events: Sender<Event>) {
    let mut stream = device.events();
    loop {
        let (result, burst) = stream.read(Vec::with_capacity(64)).await;
        for mut event in burst {
            if event.kind == codes::EV_ABS {
                let Some(pixels) = axes.to_pixels(event.code, event.value, mode) else {
                    continue;
                };
                event.value = pixels;
            }
            if events.send(Event::Input(event)).await.is_err() {
                return;
            }
        }
        if helios_api::stream_closed(result) {
            return;
        }
    }
}

/// Mutable state owned exclusively by the single desktop event loop.
struct LoopState<'a> {
    desktop: &'a mut Desktop,
    log_console: &'a mut LogConsole,
    presentation: &'a mut Presentation,
    tty_out: Option<&'a Sender<TtyClientMsg>>,
    splash_done: &'a AtomicBool,
    screen: ScreenState,
    console_shell_mode: Option<bool>,
    pending_early_input: Vec<u8>,
    user_switched_vt: bool,
    self_instance_id: Option<u64>,
    keyboard: Keyboard,
    input_frame: InputFrame,
    frames: u64,
}

impl<'a> LoopState<'a> {
    fn new(
        desktop: &'a mut Desktop,
        log_console: &'a mut LogConsole,
        presentation: &'a mut Presentation,
        tty_out: Option<&'a Sender<TtyClientMsg>>,
        splash_done: &'a AtomicBool,
    ) -> Self {
        let mode = desktop.mode();
        let pixel_count = (mode.width as usize) * (mode.height as usize);
        Self {
            desktop,
            log_console,
            presentation,
            tty_out,
            splash_done,
            screen: ScreenState::Splash {
                started_at: Instant::now(),
                renderer: SplashRenderer::new(mode.width, mode.height),
                pixels: vec![0_u32; pixel_count],
            },
            console_shell_mode: None,
            pending_early_input: Vec::new(),
            user_switched_vt: false,
            self_instance_id: None,
            keyboard: Keyboard::new(),
            input_frame: InputFrame::default(),
            frames: 0,
        }
    }

    fn finish_splash_to(&mut self, target: ActiveVt) {
        self.splash_done.store(true, Ordering::Relaxed);
        self.screen = ScreenState::Active(target);
        match target {
            ActiveVt::Log => self.log_console.damage_all(),
            ActiveVt::Terminal => self.desktop.damage_all(),
        }
    }

    fn switch_vt(&mut self, target: ActiveVt) {
        self.user_switched_vt = true;
        if matches!(self.screen, ScreenState::Active(current) if current == target) {
            return;
        }
        self.finish_splash_to(target);
    }

    async fn send_tty_input(&self, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        if let Some(tx) = self.tty_out {
            let _ = tx.send(TtyClientMsg::Input(bytes)).await;
        }
    }

    /// Presents the current splash or cross-fade frame if active.
    async fn step_splash_frame(&mut self) -> Result<(), DesktopError> {
        let mode = self.desktop.mode();
        let width = mode.width as usize;
        let height = mode.height as usize;

        enum Transition {
            None,
            StartCrossfade {
                splash_pixels: Vec<u32>,
                target: ActiveVt,
            },
            FinishCrossfade(ActiveVt),
        }

        let mut transition = Transition::None;
        let mut dirty_region: Option<Region> = None;

        let surface_stride = self.desktop.surface().stride();
        match &mut self.screen {
            ScreenState::Splash {
                started_at,
                renderer,
                pixels,
            } => {
                let elapsed = started_at.elapsed().as_secs_f32();
                if let Some(region) = renderer.render_frame(elapsed, pixels, width) {
                    blit_u32_region_to_surface(
                        pixels,
                        width,
                        self.desktop.surface_mut().pixels(),
                        surface_stride,
                        region,
                    );
                    dirty_region = Some(region);
                }
                if elapsed >= SPLASH_DURATION_SECS {
                    let target = if self.console_shell_mode == Some(true) {
                        ActiveVt::Terminal
                    } else {
                        ActiveVt::Log
                    };
                    transition = Transition::StartCrossfade {
                        splash_pixels: core::mem::take(pixels),
                        target,
                    };
                }
            }
            ScreenState::Crossfade {
                started_at,
                splash_pixels,
                target_pixels,
                blended,
                target,
            } => {
                let elapsed = started_at.elapsed().as_secs_f32();
                let alpha = SplashRenderer::crossfade_alpha(elapsed);
                SplashRenderer::render_crossfade(splash_pixels, target_pixels, blended, alpha);
                let full = Region::new(0, 0, mode.width, mode.height);
                blit_u32_region_to_surface(
                    blended,
                    width,
                    self.desktop.surface_mut().pixels(),
                    surface_stride,
                    full,
                );
                dirty_region = Some(full);
                if elapsed >= CROSSFADE_DURATION_SECS {
                    transition = Transition::FinishCrossfade(*target);
                }
            }
            ScreenState::Active(_) => return Ok(()),
        }

        if let Some(region) = dirty_region {
            self.desktop
                .surface()
                .present(DisplayRect {
                    x: region.x,
                    y: region.y,
                    width: region.width,
                    height: region.height,
                })
                .await?;
            self.record_presented_frame(1);
        }

        match transition {
            Transition::None => {}
            Transition::StartCrossfade {
                splash_pixels,
                target,
            } => {
                let mut target_pixels = vec![0_u32; width * height];
                match target {
                    ActiveVt::Log => {
                        self.log_console.damage_all();
                        let _ = self.log_console.render_u32(&mut target_pixels, width);
                    }
                    ActiveVt::Terminal => {
                        self.desktop.damage_terminal_rows();
                        self.desktop.render_u32(&mut target_pixels, width);
                    }
                }
                let blended = vec![0_u32; width * height];
                self.screen = ScreenState::Crossfade {
                    started_at: Instant::now(),
                    splash_pixels,
                    target_pixels,
                    blended,
                    target,
                };
            }
            Transition::FinishCrossfade(target) => {
                self.finish_splash_to(target);
            }
        }
        Ok(())
    }

    async fn present_active(&mut self) -> Result<(), DesktopError> {
        match self.screen {
            ScreenState::Splash { .. } | ScreenState::Crossfade { .. } => Ok(()),
            ScreenState::Active(ActiveVt::Log) => {
                let stride = self.desktop.surface().stride();
                let regions = {
                    let pixels = self.desktop.surface_mut().pixels();
                    self.log_console.render(pixels, stride)
                };
                if regions.is_empty() {
                    return Ok(());
                }
                for region in &regions {
                    self.desktop
                        .surface()
                        .present(DisplayRect {
                            x: region.x,
                            y: region.y,
                            width: region.width,
                            height: region.height,
                        })
                        .await?;
                }
                self.record_presented_frame(regions.len());
                Ok(())
            }
            ScreenState::Active(ActiveVt::Terminal) => {
                self.desktop.damage_terminal_rows();
                let presented = self.desktop.present().await?;
                if presented > 0 {
                    self.record_presented_frame(presented);
                }
                Ok(())
            }
        }
    }

    fn record_presented_frame(&mut self, regions: usize) {
        self.frames += 1;
        let pointer = self.desktop.pointer();
        println!(
            "compositor:frame sequence={} regions={regions} cursor={},{}",
            self.frames, pointer.x, pointer.y
        );
    }
}

/// The desktop's own loop: fold everything that happened into one frame.
async fn serve(
    desktop: &mut Desktop,
    log_console: &mut LogConsole,
    presentation: &mut Presentation,
    queue: &Receiver<Event>,
    tty_out: Option<&Sender<TtyClientMsg>>,
    splash_done: &AtomicBool,
) -> Result<(), DesktopError> {
    let mut state = LoopState::new(desktop, log_console, presentation, tty_out, splash_done);
    // Render the opening splash frame immediately so the scanout is never blank.
    state.step_splash_frame().await?;

    loop {
        let Ok(event) = queue.recv().await else {
            return Err(DesktopError::Starved);
        };
        let (mut moved, mut tick) = handle(&mut state, event).await?;
        // Coalesce everything already queued into one repaint pass.
        while let Ok(event) = queue.try_recv() {
            let (m, t) = handle(&mut state, event).await?;
            moved |= m;
            tick |= t;
        }
        if moved {
            state.desktop.present_cursor().await?;
        }
        if tick {
            state.step_splash_frame().await?;
        }
        state.present_active().await?;
    }
}

/// What one input report is accumulating.
#[derive(Default)]
struct InputFrame {
    x: Option<u32>,
    y: Option<u32>,
    events: Vec<InputEvent>,
}

/// Fold one event into the desktop state. Reports `(pointer_moved, splash_tick)`.
async fn handle(state: &mut LoopState<'_>, event: Event) -> Result<(bool, bool), DesktopError> {
    match event {
        Event::CreateImage { id, size, reply } => {
            state.presentation.create(id, size);
            let _ = reply.send(Ok(())).await;
            Ok((false, false))
        }
        Event::PresentImage {
            id,
            image,
            retired,
            reply,
        } => {
            let answer = if state.presentation.holds(id) {
                if !matches!(state.screen, ScreenState::Active(ActiveVt::Terminal)) {
                    state.finish_splash_to(ActiveVt::Terminal);
                }
                state.presentation.present(id, image, retired).await?;
                Ok(())
            } else {
                Err(Error::Gone)
            };
            let _ = reply.send(answer).await;
            Ok((false, false))
        }
        Event::Input(event) => {
            if ends_frame(event) {
                let moved = apply_frame(state).await?;
                return Ok((moved, false));
            }
            match (event.kind, event.code) {
                (codes::EV_ABS, codes::ABS_X) => {
                    state.input_frame.x = Some(event.value.max(0) as u32)
                }
                (codes::EV_ABS, codes::ABS_Y) => {
                    state.input_frame.y = Some(event.value.max(0) as u32)
                }
                _ => {}
            }
            state.input_frame.events.push(event);
            Ok((false, false))
        }
        Event::Tty(msg) => {
            match msg {
                TtyServerMsg::Mode { console_shell } => {
                    state.console_shell_mode = Some(console_shell);
                    if console_shell {
                        let pending = core::mem::take(&mut state.pending_early_input);
                        state.send_tty_input(pending).await;
                        if !state.user_switched_vt
                            && matches!(state.screen, ScreenState::Active(ActiveVt::Log))
                        {
                            state.finish_splash_to(ActiveVt::Terminal);
                        }
                    } else {
                        state.pending_early_input.clear();
                    }
                }
                TtyServerMsg::ClearScreen => {
                    state.desktop.terminal().clear();
                }
                TtyServerMsg::Output(bytes) => {
                    state.desktop.terminal().write(&bytes);
                }
            }
            Ok((false, false))
        }
        Event::TtyClosed => {
            state
                .desktop
                .terminal()
                .write(b"\r\n[console session disconnected]\r\n");
            Ok((false, false))
        }
        Event::Trace(trace_event) => {
            if !should_suppress_trace_event(&trace_event, state.self_instance_id) {
                let (origin, message) = format_trace_fields(&trace_event);
                state
                    .log_console
                    .push_log(trace_event.timestamp, origin.as_deref(), &message);
            }
            Ok((false, false))
        }
        Event::SelfInstanceId(id) => {
            state.self_instance_id = Some(id);
            Ok((false, false))
        }
        Event::ComponentReady(moniker) => {
            state
                .log_console
                .push_status(ServiceStatus::Ok, &format!("Reached component {moniker}"));
            Ok((false, false))
        }
        Event::SplashTick => Ok((false, true)),
        Event::Create {
            id,
            width,
            height,
            reply,
        } => {
            let answer = state
                .desktop
                .add_client(id, width, height)
                .map_err(client_error);
            if answer.is_ok() {
                println!("compositor:window id={id} width={width} height={height}");
            }
            let _ = reply.send(answer).await;
            Ok((false, false))
        }
        Event::Commit { id, region, reply } => {
            let answer = if state.desktop.holds_client(id) {
                state.desktop.damage_client(id, region);
                Ok(())
            } else {
                Err(Error::Gone)
            };
            let _ = reply.send(answer).await;
            Ok((false, false))
        }
        Event::Destroy { id, reply } => {
            if !state.presentation.remove(id, state.desktop).await? {
                state.desktop.remove_client(id);
            }
            let _ = reply.send(()).await;
            Ok((false, false))
        }
    }
}

const fn client_error(error: BlockError) -> Error {
    match error {
        BlockError::Empty | BlockError::TooLarge => Error::UnsupportedSize,
        BlockError::OutOfMemory { .. } => Error::OutOfMemory,
    }
}

/// Act on one whole input report.
async fn apply_frame(state: &mut LoopState<'_>) -> Result<bool, DesktopError> {
    let events = core::mem::take(&mut state.input_frame.events);
    let moved = state.input_frame.x.is_some() || state.input_frame.y.is_some();
    if moved {
        let previous = state.desktop.pointer();
        state.desktop.move_pointer(Point {
            x: state.input_frame.x.unwrap_or(previous.x),
            y: state.input_frame.y.unwrap_or(previous.y),
        });
    }
    state.input_frame.x = None;
    state.input_frame.y = None;

    if let Some((id, pointer)) = state.presentation.focused(state.desktop) {
        let report = translate_report(events, Some((pointer.x, pointer.y)));
        let _ = surface::deliver(id, report).await;
        return Ok(moved);
    }

    // Intercept global VT switch chords (`Alt+F1`, `Alt+F2`) and splash skip
    // before forwarding to the focused window.
    let mut actions = Vec::new();
    for event in &events {
        if event.kind == codes::EV_KEY
            && let Some(action) = state.keyboard.translate(event.code, event.value)
        {
            actions.push(action);
        }
    }

    match state.screen {
        ScreenState::Splash { .. } | ScreenState::Crossfade { .. } => {
            let mut typed = Vec::new();
            for action in actions {
                match action {
                    KeyAction::SwitchVt(1) => state.switch_vt(ActiveVt::Log),
                    KeyAction::SwitchVt(2) => state.switch_vt(ActiveVt::Terminal),
                    KeyAction::Escape => {
                        let target = if state.console_shell_mode == Some(true) {
                            ActiveVt::Terminal
                        } else {
                            ActiveVt::Log
                        };
                        state.switch_vt(target);
                    }
                    KeyAction::Char(ch) if state.desktop.focus() == Focus::Terminal => {
                        let mut buf = [0_u8; 4];
                        typed.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                    }
                    _ => {}
                }
            }
            if !typed.is_empty() {
                match state.console_shell_mode {
                    Some(true) => state.send_tty_input(typed).await,
                    None => state.pending_early_input.extend_from_slice(&typed),
                    Some(false) => {}
                }
            }
        }
        ScreenState::Active(ActiveVt::Log) => {
            for action in actions {
                match action {
                    KeyAction::SwitchVt(2) | KeyAction::Char('\n' | '\r') => {
                        state.switch_vt(ActiveVt::Terminal);
                    }
                    KeyAction::SwitchVt(1) => {}
                    KeyAction::PageUp => state.log_console.scroll_page_up(),
                    KeyAction::PageDown => state.log_console.scroll_page_down(),
                    KeyAction::ScrollLineUp => state.log_console.scroll_up(1),
                    KeyAction::ScrollLineDown => state.log_console.scroll_down(1),
                    KeyAction::ScrollTop => state.log_console.scroll_to_top(),
                    KeyAction::ScrollBottom => state.log_console.scroll_to_bottom(),
                    KeyAction::Escape | KeyAction::Char(_) => {}
                    KeyAction::SwitchVt(_) => {}
                }
            }
        }
        ScreenState::Active(ActiveVt::Terminal) => {
            let mut switched_to_vt1 = false;
            for &action in &actions {
                if action == KeyAction::SwitchVt(1) {
                    state.switch_vt(ActiveVt::Log);
                    switched_to_vt1 = true;
                }
            }
            if switched_to_vt1 {
                return Ok(moved);
            }

            match state.desktop.focus() {
                Focus::Desktop => {}
                Focus::Terminal => {
                    let mut typed = Vec::new();
                    let page = state.desktop.terminal().rows().saturating_sub(1).max(1);
                    for action in actions {
                        match action {
                            KeyAction::PageUp => state.desktop.terminal().scroll_up(page),
                            KeyAction::PageDown => state.desktop.terminal().scroll_down(page),
                            KeyAction::ScrollLineUp => state.desktop.terminal().scroll_up(1),
                            KeyAction::ScrollLineDown => state.desktop.terminal().scroll_down(1),
                            KeyAction::ScrollTop => state.desktop.terminal().scroll_to_top(),
                            KeyAction::ScrollBottom => state.desktop.terminal().scroll_to_bottom(),
                            KeyAction::Char(character) => {
                                state.desktop.terminal().scroll_to_bottom();
                                let mut buffer = [0_u8; 4];
                                typed.extend_from_slice(
                                    character.encode_utf8(&mut buffer).as_bytes(),
                                );
                            }
                            KeyAction::Escape | KeyAction::SwitchVt(_) => {}
                        }
                    }
                    if !typed.is_empty() {
                        state.send_tty_input(typed).await;
                    }
                }
                Focus::Client(id) => {
                    let report = client_report(state.desktop, id, events);
                    let _ = surface::deliver(id, report).await;
                }
            }
        }
    }
    Ok(moved)
}

/// Copies a `Region` of `bgrx8888` `u32` pixels into the scanout surface byte buffer.
fn blit_u32_region_to_surface(
    src: &[u32],
    src_stride_pixels: usize,
    dst: &mut [u8],
    dst_stride_bytes: usize,
    region: Region,
) {
    for y in region.y..region.bottom() {
        let src_row = (y as usize) * src_stride_pixels;
        let dst_row = (y as usize) * dst_stride_bytes;
        for x in region.x..region.right() {
            let px = src[src_row + x as usize].to_le_bytes();
            let off = dst_row + (x as usize) * 4;
            if let Some(slot) = dst.get_mut(off..off + 4) {
                slot.copy_from_slice(&px);
            }
        }
    }
}

/// Returns `true` when `event` must be suppressed from VT1 to avoid a
/// self-sustaining frame-logging repaint loop.
fn should_suppress_trace_event(event: &TraceEvent, self_instance_id: Option<u64>) -> bool {
    if let Some(self_id) = self_instance_id
        && event.fields.iter().any(|field| {
            matches!(field.key.as_str(), "instance" | "instance_id")
                && matches!(field.value, TraceValue::Unsigned64(id) if id == self_id)
        })
    {
        return true;
    }
    event.fields.iter().any(|field| {
        field.key == "message"
            && matches!(&field.value, TraceValue::Text(text) if text.starts_with("compositor:frame "))
    })
}

/// Extracts `(origin, message)` from a tracing event for `LogConsole::push_log`.
fn format_trace_fields(event: &TraceEvent) -> (Option<String>, String) {
    let origin = (!event.target.is_empty()).then(|| event.target.clone());
    let mut message = String::new();
    let mut extras = Vec::new();
    for field in &event.fields {
        if field.key == "message"
            && let TraceValue::Text(text) = &field.value
        {
            message = text.clone();
            continue;
        }
        let rendered = match &field.value {
            TraceValue::Boolean(v) => format!("{}={v}", field.key),
            TraceValue::Signed64(v) => format!("{}={v}", field.key),
            TraceValue::Unsigned64(v) => format!("{}={v}", field.key),
            TraceValue::Float64(v) => format!("{}={v}", field.key),
            TraceValue::Text(v) => format!("{}={v}", field.key),
            TraceValue::Blob(v) => format!("{}=<{}B>", field.key, v.len()),
        };
        extras.push(rendered);
    }
    if !extras.is_empty() {
        if !message.is_empty() {
            message.push(' ');
        }
        message.push_str(&extras.join(" "));
    }
    (origin, message)
}

fn client_report(desktop: &Desktop, id: u64, events: Vec<InputEvent>) -> Vec<InputEvent> {
    translate_report(events, desktop.pointer_in_client(id))
}

fn translate_report(events: Vec<InputEvent>, local: Option<(u32, u32)>) -> Vec<InputEvent> {
    events
        .into_iter()
        .map(|mut event| {
            if let (Some((x, y)), codes::EV_ABS) = (local, event.kind) {
                match event.code {
                    codes::ABS_X => event.value = x as i32,
                    codes::ABS_Y => event.value = y as i32,
                    _ => {}
                }
            }
            event
        })
        .chain(core::iter::once(InputEvent {
            kind: codes::EV_SYN,
            code: codes::SYN_REPORT,
            value: 0,
        }))
        .collect()
}

#[cfg(test)]
mod tests {
    use helios_api::tracing::{Field, Level};

    use super::*;

    #[test]
    fn suppresses_compositor_frame_lines_and_self_instance_events() {
        let frame_event = TraceEvent {
            timestamp: 100,
            level: Level::Info,
            target: String::from("console"),
            fields: vec![Field {
                key: String::from("message"),
                value: TraceValue::Text(String::from(
                    "compositor:frame sequence=4 regions=1 cursor=640,400",
                )),
            }],
        };
        assert!(should_suppress_trace_event(&frame_event, None));

        let self_event = TraceEvent {
            timestamp: 101,
            level: Level::Info,
            target: String::from("helios_kernel::exec"),
            fields: vec![
                Field {
                    key: String::from("instance_id"),
                    value: TraceValue::Unsigned64(9),
                },
                Field {
                    key: String::from("message"),
                    value: TraceValue::Text(String::from("tick")),
                },
            ],
        };
        assert!(should_suppress_trace_event(&self_event, Some(9)));
        assert!(!should_suppress_trace_event(&self_event, Some(10)));

        let kernel_event = TraceEvent {
            timestamp: 102,
            level: Level::Info,
            target: String::from("helios_kernel::virtio"),
            fields: vec![Field {
                key: String::from("message"),
                value: TraceValue::Text(String::from("virtio-gpu online")),
            }],
        };
        assert!(!should_suppress_trace_event(&kernel_event, Some(9)));
        let (origin, msg) = format_trace_fields(&kernel_event);
        assert_eq!(origin.as_deref(), Some("helios_kernel::virtio"));
        assert_eq!(msg, "virtio-gpu online");
    }
}
