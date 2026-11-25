//! The `compositor` kernel plugin: the machine's desktop.
//!
//! `helios:system/surface` in the kernel is a forwarder — it pins a
//! client's frame buffer, mints an identity and hands both here. This
//! component is what is on the other end. It is an ordinary user-mode
//! wasm program with the ordinary isolation model; what makes it the
//! desktop is that the kernel provisions it from bootfs, keeps one
//! instance alive, and hands it the display and every input device.
//!
//! # What it does
//!
//! Claims the display, creates one surface at the output's preferred
//! mode and draws a wallpaper into it. Claims every input device and
//! reads them: the tablet's absolute position moves the display engine's
//! own cursor plane, and focus follows it, so the keyboard talks to
//! whatever the pointer is over. Spawns the guest shell and draws its
//! output as a terminal window — a monospace grid with a scrollback —
//! so the desktop boots into something a person can use. Composes every
//! client window that asks for one.
//!
//! Every frame is damage-tracked: what reaches `present` is the
//! rectangles that changed, never the screen. A keystroke costs one
//! glyph cell of traffic; a pointer move costs none at all, because the
//! pointer is a plane and `move-cursor` is the whole of moving it.
//!
//! # How the calls reach the desktop
//!
//! `create`, `commit` and `destroy` are separate calls into this
//! component, running concurrently with `run` inside one store. They own
//! none of the desktop: each puts a request on a queue and waits for the
//! answer, and `run` owns the state and is the only thing that touches
//! it. The exported desktop resource owns the queue, so each request
//! reaches its instance without a global registry.

use std::string::String;
use std::vec::Vec;

use helios_api::bindings::wit_stream;
use helios_api::channel::{Receiver, Sender, bounded};
use helios_api::compositor::{
    BlockError, Error, Guest, GuestDesktop, Image as RawImage, Rect,
    SignalSource as RawSignalSource, Span,
};
use helios_api::image::Image;
use helios_api::sync::{SignalSource, TimelineError};

mod presentation;
use helios_api::display::{Display, DisplayError, Mode, PixelFormat, Point};
use helios_api::input::{Device, InputError, InputEvent, available, codes, ends_frame};
use helios_api::programs::{
    Child, SpawnError, SpawnRequest, root_directory_grant, root_link_grant, root_process_grant,
    root_terminal_grant,
};
use helios_api::surface;
use helios_api::task::spawn;
use presentation::Presentation;
use thiserror::Error;

use helios_compositor_render::damage::Region;
use helios_compositor_render::desktop::{Desktop, Focus};
use helios_compositor_render::font::{CELL_HEIGHT, CELL_WIDTH};
use helios_compositor_render::keys::Keyboard;

mod bindings {
    pub use ::helios_api::bindings::*;
}

/// The shell the desktop boots into.
const SHELL_PATH: &str = "/bin/nu";

/// Events waiting to be folded into the next frame.
///
/// Deep enough to hold a burst of input and a chunk of shell output
/// without making either wait, and bounded so that a desktop that has
/// stopped drawing applies backpressure to whatever is producing rather
/// than growing.
const EVENT_QUEUE_DEPTH: usize = 256;

/// Bytes read from the shell in one go.
const SHELL_CHUNK: usize = 4096;

/// The scanout the desktop draws on. One display, one output.
const SCANOUT: u32 = 0;

/// Why the desktop gave up.
#[derive(Debug, Error)]
enum DesktopError {
    #[error("frame retirement failed: {0}")]
    Timeline(#[from] TimelineError),
    #[error("the display refused: {0}")]
    Display(#[from] DisplayError),
    #[error("the input service refused: {0}")]
    Input(#[from] InputError),
    #[error("the shell could not be started: {0:?}")]
    Shell(SpawnError),
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
            // The desktop could not be built or could not go on. From a
            // client's side that is one fact: there is no compositor.
            Self::Timeline(_)
            | Self::Display(_)
            | Self::Input(_)
            | Self::Shell(_)
            | Self::NoInput
            | Self::EmptyMode { .. }
            | Self::Starved => Error::NoCompositor,
        }
    }
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
    /// The shell printed something.
    Shell(Vec<u8>),
    /// The shell's output ended, which is the shell having exited.
    ShellEnded,
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
    /// A client's window is gone. The kernel has already made this
    /// component's view of its pages ordinary memory again, so the
    /// desktop frees them and stops reading the window.
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
            // The window's pages are freed by the desktop, so the answer
            // is waited for rather than assumed.
            let _ = answer.recv().await;
        }
    }
}

impl DesktopSession {
    /// Apply backpressure until the desktop accepts the request.
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

    desktop.set_cursor().await?;
    desktop.damage_all();
    desktop.present().await?;
    desktop.present_cursor().await?;

    let origin = desktop.terminal_origin();
    println!(
        "compositor:online scanout={SCANOUT} width={} height={}",
        mode.width, mode.height
    );
    println!(
        "compositor:terminal columns={} rows={} cell-width={CELL_WIDTH} cell-height={CELL_HEIGHT} origin={},{}",
        desktop.terminal().columns(),
        desktop.terminal().rows(),
        origin.0,
        origin.1
    );

    start_input(events, mode)?;
    // The handle is held for as long as the desktop is: dropping it
    // would take the shell down with it.
    let (_shell, mut keystrokes) = start_shell(events).await?;

    let mut presentation = Presentation::new(display);
    serve(&mut desktop, &mut presentation, queue, &mut keystrokes).await
}

/// Claim every input device and read it into the desktop's queue.
fn start_input(events: &Sender<Event>, mode: Mode) -> Result<(), DesktopError> {
    let mut claimed = 0;
    for capabilities in available() {
        // Each device is named as it is taken, and a refusal is named
        // too: a desktop running with no keyboard because something else
        // holds it is a fact about the machine, not a detail to keep.
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

    /// Where `value` on `code` falls on a screen of `mode`.
    ///
    /// A tablet reports over its own range — QEMU's is `0..=32767` — and
    /// the host cannot know what mode the guest chose, so the scaling is
    /// the compositor's to do. It is done here, at the device, so that
    /// everything above works in the pixels it draws in.
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

/// Start the guest shell and read what it prints into the queue.
async fn start_shell(
    events: &Sender<Event>,
) -> Result<(Child, helios_api::wit_bindgen::StreamWriter<u8>), DesktopError> {
    let child = Child::spawn(SpawnRequest {
        name: String::from("nu"),
        args: Vec::new(),
        env: vec![
            (String::from("TERM"), String::from("dumb")),
            (String::from("PS1"), String::from("helios$ ")),
            (String::from("HOME"), String::from("/")),
        ],
        path: String::from(SHELL_PATH),
        cwd: None,
        sockets: Vec::new(),
        capability_grants: vec![
            root_directory_grant(),
            root_terminal_grant(),
            root_process_grant(),
            root_link_grant(),
        ],
    })
    .await
    .map_err(DesktopError::Shell)?;
    println!("compositor:shell path={SHELL_PATH}");

    let (stdin, stdin_reader) = wit_stream::new::<u8>();
    let stdin_done = child.pipe_stdin(stdin_reader);
    spawn(async move {
        // Nothing here acts on the outcome: the shell's stdin closing is
        // the shell having gone, which its output ending reports too.
        let _ = std::future::IntoFuture::into_future(stdin_done).await;
    });

    for (stream, _done) in [child.stdout(), child.stderr()] {
        let events = events.clone();
        spawn(async move {
            read_shell(stream, events).await;
        });
    }

    Ok((child, stdin))
}

/// Read one of the shell's output streams into the queue.
async fn read_shell(mut stream: helios_api::wit_bindgen::StreamReader<u8>, events: Sender<Event>) {
    loop {
        let (result, chunk) = stream.read(Vec::with_capacity(SHELL_CHUNK)).await;
        if !chunk.is_empty() && events.send(Event::Shell(chunk)).await.is_err() {
            return;
        }
        if helios_api::stream_closed(result) {
            let _ = events.send(Event::ShellEnded).await;
            return;
        }
    }
}

/// The desktop's own loop: fold everything that happened into one frame.
async fn serve(
    desktop: &mut Desktop,
    presentation: &mut Presentation,
    queue: &Receiver<Event>,
    keystrokes: &mut helios_api::wit_bindgen::StreamWriter<u8>,
) -> Result<(), DesktopError> {
    let mut keyboard = Keyboard::new();
    let mut frame = InputFrame::default();
    let mut frames = 0_u64;
    loop {
        let Ok(event) = queue.recv().await else {
            return Err(DesktopError::Starved);
        };
        let mut moved = handle(
            desktop,
            presentation,
            keystrokes,
            &mut keyboard,
            &mut frame,
            event,
        )
        .await?;
        // Everything already queued belongs to this frame too: a burst
        // of shell output is one repaint, not one per chunk.
        while let Ok(event) = queue.try_recv() {
            moved |= handle(
                desktop,
                presentation,
                keystrokes,
                &mut keyboard,
                &mut frame,
                event,
            )
            .await?;
        }
        if moved {
            desktop.present_cursor().await?;
        }
        desktop.damage_terminal_rows();
        let presented = desktop.present().await?;
        if presented > 0 {
            frames += 1;
            // One line per frame, carrying where the pointer was put and
            // how many rectangles carried the change. A capture cannot
            // show either: the pointer is the engine's own plane, and a
            // full-screen flush looks exactly like a damage-tracked one
            // in a still. The device's trace and this line together are
            // what say otherwise.
            let pointer = desktop.pointer();
            println!(
                "compositor:frame sequence={frames} regions={presented} cursor={},{}",
                pointer.x, pointer.y
            );
        }
    }
}

/// What one input report is accumulating.
#[derive(Default)]
struct InputFrame {
    x: Option<u32>,
    y: Option<u32>,
    events: Vec<InputEvent>,
}

/// Fold one event into the desktop. Reports whether the pointer moved.
async fn handle(
    desktop: &mut Desktop,
    presentation: &mut Presentation,
    keystrokes: &mut helios_api::wit_bindgen::StreamWriter<u8>,
    keyboard: &mut Keyboard,
    frame: &mut InputFrame,
    event: Event,
) -> Result<bool, DesktopError> {
    match event {
        Event::CreateImage { id, size, reply } => {
            presentation.create(id, size);
            let _ = reply.send(Ok(())).await;
            Ok(false)
        }
        Event::PresentImage {
            id,
            image,
            retired,
            reply,
        } => {
            let answer = if presentation.holds(id) {
                presentation.present(id, image, retired).await?;
                Ok(())
            } else {
                Err(Error::Gone)
            };
            let _ = reply.send(answer).await;
            Ok(false)
        }
        Event::Input(event) => {
            if ends_frame(event) {
                return apply_frame(desktop, presentation, keystrokes, keyboard, frame).await;
            }
            match (event.kind, event.code) {
                (codes::EV_ABS, codes::ABS_X) => frame.x = Some(event.value.max(0) as u32),
                (codes::EV_ABS, codes::ABS_Y) => frame.y = Some(event.value.max(0) as u32),
                _ => {}
            }
            frame.events.push(event);
            Ok(false)
        }
        Event::Shell(bytes) => {
            desktop.terminal().write(&bytes);
            Ok(false)
        }
        Event::ShellEnded => {
            let terminal = desktop.terminal();
            terminal.write(b"\r\n[the shell exited; the desktop stays up]\r\n");
            println!(
                "compositor:shell-ended scrollback={}",
                terminal.scrollback()
            );
            Ok(false)
        }
        Event::Create {
            id,
            width,
            height,
            reply,
        } => {
            let answer = desktop.add_client(id, width, height).map_err(client_error);
            if answer.is_ok() {
                println!("compositor:window id={id} width={width} height={height}");
            }
            let _ = reply.send(answer).await;
            Ok(false)
        }
        Event::Commit { id, region, reply } => {
            let answer = if desktop.holds_client(id) {
                desktop.damage_client(id, region);
                Ok(())
            } else {
                Err(Error::Gone)
            };
            let _ = reply.send(answer).await;
            Ok(false)
        }
        Event::Destroy { id, reply } => {
            if !presentation.remove(id, desktop).await? {
                desktop.remove_client(id);
            }
            let _ = reply.send(()).await;
            Ok(false)
        }
    }
}

/// How a failure to take pages for a client's window reads to that
/// client.
const fn client_error(error: BlockError) -> Error {
    match error {
        // The window has no pixels, or more than any memory could hold.
        BlockError::Empty | BlockError::TooLarge => Error::UnsupportedSize,
        BlockError::OutOfMemory { .. } => Error::OutOfMemory,
    }
}

/// Act on one whole input report.
///
/// A report is the unit because a pointer that moved in both axes
/// reports them separately: acting on the first alone would draw a
/// diagonal as a staircase, and would move focus through a window the
/// pointer never stopped in.
async fn apply_frame(
    desktop: &mut Desktop,
    presentation: &Presentation,
    keystrokes: &mut helios_api::wit_bindgen::StreamWriter<u8>,
    keyboard: &mut Keyboard,
    frame: &mut InputFrame,
) -> Result<bool, DesktopError> {
    let events = core::mem::take(&mut frame.events);
    let moved = frame.x.is_some() || frame.y.is_some();
    if moved {
        let previous = desktop.pointer();
        desktop.move_pointer(Point {
            x: frame.x.unwrap_or(previous.x),
            y: frame.y.unwrap_or(previous.y),
        });
    }
    frame.x = None;
    frame.y = None;

    if let Some((id, pointer)) = presentation.focused(desktop) {
        let report = translate_report(events, Some((pointer.x, pointer.y)));
        let _ = surface::deliver(id, report).await;
        return Ok(moved);
    }

    match desktop.focus() {
        Focus::Desktop => {}
        Focus::Terminal => {
            let mut typed = Vec::new();
            for event in &events {
                if event.kind != codes::EV_KEY {
                    continue;
                }
                if let Some(character) = keyboard.press(event.code, event.value) {
                    let mut buffer = [0_u8; 4];
                    typed.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
                }
            }
            if !typed.is_empty() {
                // The terminal echoes what was typed itself. There is no
                // line discipline between this program and the shell —
                // the shell reads a stream, not a terminal, and prints
                // back only what it produces — so a desktop that did not
                // echo would show nothing at all until a command ran.
                desktop.terminal().write(&typed);
                let _ = keystrokes.write_all(typed).await;
            }
        }
        Focus::Client(id) => {
            let report = client_report(desktop, id, events);
            // A client that has gone is one the kernel will tell this
            // component about; until then a refused delivery is not an
            // error the desktop acts on.
            let _ = surface::deliver(id, report).await;
        }
    }
    Ok(moved)
}

/// One report as the client that owns the focused window sees it.
///
/// Everything is evdev's own, unchanged, except the absolute axes: those
/// are rewritten to the window's own pixel range, because a window is
/// not a screen and a client has no way to know where its window sits.
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
