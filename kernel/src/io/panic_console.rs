//! The panic console.
//!
//! The last thing a machine says is its panic report, and every backend
//! says it the same way: wrap a byte writer in a `fmt::Write` and push
//! the report through it. What differs is only which port a panicking
//! machine can still reach.
//!
//! When firmware handed over a linear RGB framebuffer at boot
//! ([`BootFramebuffer`]), a backend may also publish it via
//! [`attach_panic_framebuffer`] while keeping its pixels untouched during
//! normal bring-up. If the kernel panics before a native display driver takes
//! ownership (which calls [`detach_panic_framebuffer`]), the panic report is
//! rendered onto that framebuffer alongside serial output using pure integer
//! bitmap glyphs so early boot failures are visible on screen without relying
//! on the heap, the executor, or floating-point instructions.
//!
//! # Concurrency contract
//!
//! [`attach_panic_framebuffer`] and [`detach_panic_framebuffer`] execute on
//! the bootstrap processor during bring-up and transition a lock-free atomic
//! state word (`EMPTY -> WRITING -> READY -> DETACHED`). A panic handler can
//! run on any processor at any time with interrupts masked and arbitrary locks
//! held, so [`emit_panic_report`] never acquires a mutex: it reads the state
//! with `Acquire`, copies out the `BootFramebuffer` value if `READY`, and uses
//! a single atomic `swap` on `PANIC_FB_CLAIMED` so the first panicking
//! processor owns the framebuffer while every panicking processor still writes
//! its full report to serial.

use core::cell::UnsafeCell;
use core::fmt::{self, Write};
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use helios_hal::boot::BootFramebuffer;
use noto_sans_mono_bitmap::{FontWeight, RasterHeight, get_raster, get_raster_width};

/// The byte sink a panic report reaches on this machine.
///
/// A panic runs with nothing left to rely on: the executor may be gone,
/// the heap may be what broke, and the processors that share this port
/// are not going to stop for it. So a backend supplies a register-level
/// writer and nothing more — no allocation, no async lock, and at most
/// the sub-microsecond spin on a transmit FIFO that the async-first
/// rules allow.
///
/// The port a backend names here need not be the one its debugger
/// transport uses. riscv panics over SBI rather than over the transport
/// it hands the debugger, because SBI answers from firmware whatever
/// state the kernel left the machine in.
///
/// An implementation drops the bytes when the port is not up yet: a
/// panic raised inside the panic handler loses the report entirely.
pub trait PanicSerial {
    fn write_bytes(bytes: &[u8]);
}

const FB_EMPTY: u8 = 0;
const FB_WRITING: u8 = 1;
const FB_READY: u8 = 2;
const FB_DETACHED: u8 = 3;

struct PanicFramebufferSlot {
    state: AtomicU8,
    claimed: AtomicBool,
    framebuffer: UnsafeCell<MaybeUninit<BootFramebuffer>>,
}

// SAFETY: `framebuffer` is written only while `state == FB_WRITING` (entered
// via a single winning `compare_exchange` from `FB_EMPTY`) and read only after
// observing `state == FB_READY` with `Acquire` ordering.
unsafe impl Sync for PanicFramebufferSlot {}

impl PanicFramebufferSlot {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(FB_EMPTY),
            claimed: AtomicBool::new(false),
            framebuffer: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn attach(&self, framebuffer: BootFramebuffer) {
        if !framebuffer.is_valid() {
            return;
        }
        if self
            .state
            .compare_exchange(FB_EMPTY, FB_WRITING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        // SAFETY: the `compare_exchange` above granted exclusive write access
        // before `FB_READY` is published with `Release`.
        unsafe {
            (*self.framebuffer.get()).write(framebuffer);
        }
        self.state.store(FB_READY, Ordering::Release);
    }

    fn detach(&self) {
        let mut current = self.state.load(Ordering::Acquire);
        while current != FB_DETACHED {
            if current == FB_WRITING {
                core::hint::spin_loop();
                current = self.state.load(Ordering::Acquire);
                continue;
            }
            match self.state.compare_exchange(
                current,
                FB_DETACHED,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(next) => current = next,
            }
        }
    }

    fn claim_for_panic(&self) -> Option<BootFramebuffer> {
        if self.state.load(Ordering::Acquire) != FB_READY {
            return None;
        }
        if self.claimed.swap(true, Ordering::AcqRel) {
            return None;
        }
        // Re-check after claiming in case `detach` raced before this panic.
        if self.state.load(Ordering::Acquire) != FB_READY {
            return None;
        }
        // SAFETY: `state == FB_READY` observed with `Acquire` guarantees
        // `framebuffer` was initialised and is never overwritten afterwards.
        let slot = unsafe { &*self.framebuffer.get() };
        // SAFETY: `slot` was written before `FB_READY` was published with `Release`.
        Some(unsafe { slot.assume_init_read() })
    }
}

static PANIC_FRAMEBUFFER: PanicFramebufferSlot = PanicFramebufferSlot::new();

/// Publishes the firmware linear framebuffer for early fatal panic output.
///
/// Does not touch any pixel in `framebuffer`: the bootloader splash stays on
/// screen untouched throughout normal bring-up. Invalid geometries are ignored
/// so early boot cannot fail on a malformed firmware mode.
pub fn attach_panic_framebuffer(framebuffer: BootFramebuffer) {
    PANIC_FRAMEBUFFER.attach(framebuffer);
}

/// Detaches the firmware linear framebuffer once a native display driver
/// claims display ownership, preventing post-handoff panics from writing into
/// stale GOP scanout memory.
pub fn detach_panic_framebuffer() {
    PANIC_FRAMEBUFFER.detach();
}

const FONT_WEIGHT: FontWeight = FontWeight::Regular;
const FONT_HEIGHT: RasterHeight = RasterHeight::Size16;
const GLYPH_WIDTH: usize = get_raster_width(FONT_WEIGHT, FONT_HEIGHT);
const GLYPH_HEIGHT: usize = FONT_HEIGHT.val();
const CELL_ADVANCE_X: usize = GLYPH_WIDTH + 1;
const LINE_ADVANCE_Y: usize = GLYPH_HEIGHT + 4;
const MARGIN_X: usize = 24;
const HEADER_HEIGHT: usize = 44;
const BODY_TOP_Y: usize = HEADER_HEIGHT + 20;
const TAB_STOP: usize = 4;

const BG_RGB: (u8, u8, u8) = (0x16, 0x09, 0x0B);
const HEADER_BG_RGB: (u8, u8, u8) = (0x99, 0x1B, 0x1B);
const HEADER_FG_RGB: (u8, u8, u8) = (0xFF, 0xFF, 0xFF);
const BODY_FG_RGB: (u8, u8, u8) = (0xF8, 0xFA, 0xFC);

/// Pure-integer linear framebuffer text renderer for fatal panic output.
///
/// Uses only `u8`/`u32`/`usize` arithmetic (no floating-point or vector state)
/// and volatile pixel writes so it is safe to run from the x86-64, AArch64,
/// and RISC-V panic paths before any runtime or heap exists.
struct PanicFramebufferWriter {
    fb: BootFramebuffer,
    cursor_x: usize,
    cursor_y: usize,
    max_x: usize,
    max_y: usize,
    bg_pixel: u32,
    fg_pixel: u32,
}

impl PanicFramebufferWriter {
    fn new(fb: BootFramebuffer) -> Self {
        let width = fb.width as usize;
        let height = fb.height as usize;
        let bg_pixel = fb.pack_rgb(BG_RGB.0, BG_RGB.1, BG_RGB.2);
        let fg_pixel = fb.pack_rgb(BODY_FG_RGB.0, BODY_FG_RGB.1, BODY_FG_RGB.2);
        let margin_x = MARGIN_X.min(width / 8);
        let max_x = width.saturating_sub(margin_x);
        let max_y = height.saturating_sub(MARGIN_X.min(height / 8));
        let mut writer = Self {
            fb,
            cursor_x: margin_x,
            cursor_y: BODY_TOP_Y.min(height),
            max_x,
            max_y,
            bg_pixel,
            fg_pixel,
        };
        writer.paint_chrome(margin_x);
        writer
    }

    fn paint_chrome(&mut self, margin_x: usize) {
        let width = self.fb.width as usize;
        let height = self.fb.height as usize;
        let header_h = HEADER_HEIGHT.min(height);
        let header_pixel = self
            .fb
            .pack_rgb(HEADER_BG_RGB.0, HEADER_BG_RGB.1, HEADER_BG_RGB.2);
        self.fill_rect(0, 0, width, header_h, header_pixel);
        self.fill_rect(
            0,
            header_h,
            width,
            height.saturating_sub(header_h),
            self.bg_pixel,
        );
        if header_h >= GLYPH_HEIGHT {
            let title_y = (header_h - GLYPH_HEIGHT) / 2;
            let mut x = margin_x;
            for ch in "HELIOS KERNEL PANIC".chars() {
                if x + GLYPH_WIDTH > self.max_x {
                    break;
                }
                self.draw_glyph(
                    x,
                    title_y,
                    ch,
                    HEADER_FG_RGB,
                    HEADER_BG_RGB,
                    self.fb
                        .pack_rgb(HEADER_FG_RGB.0, HEADER_FG_RGB.1, HEADER_FG_RGB.2),
                    header_pixel,
                );
                x += CELL_ADVANCE_X;
            }
        }
        if height <= BODY_TOP_Y + GLYPH_HEIGHT {
            self.cursor_y = header_h.saturating_add(4).min(height);
        }
    }

    fn write_text(&mut self, text: &str) {
        let margin_x = MARGIN_X.min((self.fb.width as usize) / 8);
        for ch in text.chars() {
            match ch {
                '\n' => self.newline(margin_x),
                '\r' => self.cursor_x = margin_x,
                '\t' => {
                    let col = self.cursor_x.saturating_sub(margin_x) / CELL_ADVANCE_X;
                    let spaces = TAB_STOP - (col % TAB_STOP);
                    for _ in 0..spaces {
                        self.put_char(' ', margin_x);
                    }
                }
                other => self.put_char(other, margin_x),
            }
        }
    }

    fn newline(&mut self, margin_x: usize) {
        self.cursor_x = margin_x;
        self.cursor_y = self.cursor_y.saturating_add(LINE_ADVANCE_Y);
    }

    fn put_char(&mut self, ch: char, margin_x: usize) {
        if self.cursor_x + GLYPH_WIDTH > self.max_x {
            self.newline(margin_x);
        }
        if self.cursor_y + GLYPH_HEIGHT > self.max_y {
            return;
        }
        let printable = if ch.is_ascii() && !ch.is_ascii_control() {
            ch
        } else {
            '?'
        };
        self.draw_glyph(
            self.cursor_x,
            self.cursor_y,
            printable,
            BODY_FG_RGB,
            BG_RGB,
            self.fg_pixel,
            self.bg_pixel,
        );
        self.cursor_x = self.cursor_x.saturating_add(CELL_ADVANCE_X);
    }

    #[allow(clippy::too_many_arguments)]
    fn draw_glyph(
        &mut self,
        x0: usize,
        y0: usize,
        ch: char,
        fg_rgb: (u8, u8, u8),
        bg_rgb: (u8, u8, u8),
        fg_pixel: u32,
        bg_pixel: u32,
    ) {
        let Some(raster) = get_raster(ch, FONT_WEIGHT, FONT_HEIGHT)
            .or_else(|| get_raster('?', FONT_WEIGHT, FONT_HEIGHT))
            .or_else(|| get_raster(' ', FONT_WEIGHT, FONT_HEIGHT))
        else {
            return;
        };
        for (row_idx, row) in raster.raster().iter().enumerate() {
            let py = y0 + row_idx;
            if py >= self.fb.height as usize {
                break;
            }
            for (col_idx, &alpha) in row.iter().enumerate() {
                let px = x0 + col_idx;
                if px >= self.fb.width as usize {
                    break;
                }
                let pixel = match alpha {
                    0 => bg_pixel,
                    255 => fg_pixel,
                    intensity => self.fb.pack_rgb(
                        blend_channel(fg_rgb.0, bg_rgb.0, intensity),
                        blend_channel(fg_rgb.1, bg_rgb.1, intensity),
                        blend_channel(fg_rgb.2, bg_rgb.2, intensity),
                    ),
                };
                self.write_pixel(px, py, pixel);
            }
        }
    }

    fn fill_rect(&mut self, x0: usize, y0: usize, w: usize, h: usize, pixel: u32) {
        let x1 = x0.saturating_add(w).min(self.fb.width as usize);
        let y1 = y0.saturating_add(h).min(self.fb.height as usize);
        for y in y0..y1 {
            for x in x0..x1 {
                self.write_pixel(x, y, pixel);
            }
        }
    }

    fn write_pixel(&mut self, x: usize, y: usize, pixel: u32) {
        let Some(bpp_bytes) = self.fb.bytes_per_pixel() else {
            return;
        };
        let Some(row_offset) = y.checked_mul(self.fb.pitch as usize) else {
            return;
        };
        let Some(col_offset) = x.checked_mul(bpp_bytes) else {
            return;
        };
        let Some(offset) = row_offset.checked_add(col_offset) else {
            return;
        };
        let Some(total_len) = self.fb.byte_len() else {
            return;
        };
        if offset
            .checked_add(bpp_bytes)
            .is_none_or(|end| end > total_len)
        {
            return;
        }
        // SAFETY: `offset + bpp_bytes <= total_len`, `self.fb` was validated
        // by `BootFramebuffer::is_valid()`, and the backing firmware
        // framebuffer is mapped writable in HHDM until detached.
        let dst = unsafe { self.fb.base.as_ptr().add(offset) };
        let bytes = pixel.to_le_bytes();
        match bpp_bytes {
            4 => {
                if (dst as usize).is_multiple_of(core::mem::align_of::<u32>()) {
                    // SAFETY: `dst` is 4-byte aligned and within the mapped framebuffer.
                    unsafe { dst.cast::<u32>().write_volatile(pixel) };
                } else {
                    // SAFETY: `offset + 4 <= total_len` within the writable mapped framebuffer.
                    unsafe { write_volatile_bytes(dst, &bytes) };
                }
            }
            3 => {
                // SAFETY: `offset + 3 <= total_len` within the writable mapped framebuffer.
                unsafe { write_volatile_bytes(dst, &bytes[..3]) };
            }
            2 => {
                if (dst as usize).is_multiple_of(core::mem::align_of::<u16>()) {
                    // SAFETY: `dst` is 2-byte aligned and within the mapped framebuffer.
                    unsafe { dst.cast::<u16>().write_volatile(pixel as u16) };
                } else {
                    // SAFETY: `offset + 2 <= total_len` within the writable mapped framebuffer.
                    unsafe { write_volatile_bytes(dst, &bytes[..2]) };
                }
            }
            _ => {}
        }
    }
}

/// Writes `bytes` byte-by-byte with volatile stores starting at `dst`.
///
/// # Safety
///
/// `dst..dst.add(bytes.len())` must lie within a valid, writable memory-mapped
/// framebuffer.
unsafe fn write_volatile_bytes(dst: *mut u8, bytes: &[u8]) {
    for (index, &byte) in bytes.iter().enumerate() {
        // SAFETY: caller guarantees `dst..dst.add(bytes.len())` is in bounds.
        let ptr = unsafe { dst.add(index) };
        // SAFETY: caller guarantees the destination range is writable.
        unsafe { ptr.write_volatile(byte) };
    }
}

const fn blend_channel(fg: u8, bg: u8, alpha: u8) -> u8 {
    let a = alpha as u32;
    let inv = 255 - a;
    ((fg as u32 * a + bg as u32 * inv + 127) / 255) as u8
}

struct PanicConsole<Serial> {
    framebuffer: Option<PanicFramebufferWriter>,
    _serial: PhantomData<Serial>,
}

impl<Serial: PanicSerial> Write for PanicConsole<Serial> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        Serial::write_bytes(text.as_bytes());
        if let Some(framebuffer) = &mut self.framebuffer {
            framebuffer.write_text(text);
        }
        Ok(())
    }
}

/// Writes one panic report to the machine's panic console.
///
/// It is the one record on this machine that does not go through
/// [`DebugConsole`](super::DebugConsole), for the reason that module
/// gives: a panicking processor cannot wait for a port another
/// processor may never release, and it cannot wait for a gate either.
/// The report goes straight at the register and accepts that it may cut
/// into whatever was on the wire.
///
/// The record names itself twice: `panicked at …` lets the readiness
/// reader recognize a failed boot, and `Kernel panic:` terminates the
/// host frame scanner's report. The terminal marker follows the body
/// so the scanner's look-back includes the message, not just its
/// location. Smoke checks recognize that same terminal marker.
pub fn emit_panic_report<Serial: PanicSerial>(info: &PanicInfo<'_>) {
    let framebuffer = PANIC_FRAMEBUFFER.claim_for_panic();
    emit_report_with_framebuffer::<Serial>(info, framebuffer);
}

/// The body of the report, over anything that renders like one.
///
/// A `PanicInfo` cannot be built outside a real panic, so this is where
/// the record's shape is testable.
#[cfg(test)]
fn emit_report<Serial: PanicSerial>(report: impl fmt::Display) {
    emit_report_with_framebuffer::<Serial>(report, None);
}

fn emit_report_with_framebuffer<Serial: PanicSerial>(
    report: impl fmt::Display,
    framebuffer: Option<BootFramebuffer>,
) {
    let mut console = PanicConsole::<Serial> {
        framebuffer: framebuffer.map(PanicFramebufferWriter::new),
        _serial: PhantomData,
    };
    let _ = writeln!(console, "{report}");
    let _ = writeln!(console, "Kernel panic:");
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::vec;
    use alloc::vec::Vec;
    use core::ptr::NonNull;
    use std::sync::Mutex;

    use helios_hal::boot::{BootFramebuffer, BootPixelChannel, BootPixelLayout};

    use super::{
        BG_RGB, BODY_TOP_Y, GLYPH_HEIGHT, HEADER_BG_RGB, HEADER_HEIGHT, PanicFramebufferSlot,
        PanicSerial, blend_channel, emit_report, emit_report_with_framebuffer,
    };

    static CAPTURED: Mutex<Vec<u8>> = Mutex::new(Vec::new());

    struct CapturingPort;

    impl PanicSerial for CapturingPort {
        fn write_bytes(bytes: &[u8]) {
            CAPTURED
                .lock()
                .expect("the capture buffer is never poisoned")
                .extend_from_slice(bytes);
        }
    }

    struct SinkPort;

    impl PanicSerial for SinkPort {
        fn write_bytes(_bytes: &[u8]) {}
    }

    #[test]
    fn a_report_carries_both_names_the_tooling_watches_for() {
        CAPTURED
            .lock()
            .expect("the capture buffer is never poisoned")
            .clear();
        emit_report::<CapturingPort>(format_args!(
            "panicked at kernel/src/lib.rs:1:1:\nthe machine gave up"
        ));

        let captured = CAPTURED
            .lock()
            .expect("the capture buffer is never poisoned")
            .clone();
        let text = core::str::from_utf8(&captured).expect("the report is UTF-8");
        assert_eq!(
            text,
            "panicked at kernel/src/lib.rs:1:1:\nthe machine gave up\nKernel panic:\n"
        );
    }

    #[test]
    fn integer_channel_blending_matches_endpoints_and_midpoint() {
        assert_eq!(blend_channel(255, 10, 0), 10);
        assert_eq!(blend_channel(255, 10, 255), 255);
        assert_eq!(blend_channel(200, 0, 128), 100);
    }

    #[test]
    fn framebuffer_panic_renders_header_and_body_pixels_on_bgrx8888() {
        let width = 320usize;
        let height = 160usize;
        let pitch = width * 4;
        let mut pixels = vec![0xFFu8; height * pitch];
        let fb = BootFramebuffer {
            base: NonNull::new(pixels.as_mut_ptr()).expect("vec pointer is non-null"),
            width: width as u32,
            height: height as u32,
            pitch: pitch as u32,
            bpp: 32,
            layout: BootPixelLayout::BGRX8888,
        };

        emit_report_with_framebuffer::<SinkPort>(
            format_args!("panicked at kernel/src/lib.rs:42:5:\nearly boot failure\twith tab"),
            Some(fb),
        );

        let header_bg = fb.pack_rgb(HEADER_BG_RGB.0, HEADER_BG_RGB.1, HEADER_BG_RGB.2);
        let body_bg = fb.pack_rgb(BG_RGB.0, BG_RGB.1, BG_RGB.2);

        let read_px = |x: usize, y: usize| -> u32 {
            let off = y * pitch + x * 4;
            u32::from_le_bytes([
                pixels[off],
                pixels[off + 1],
                pixels[off + 2],
                pixels[off + 3],
            ])
        };

        // Top-left corner sits inside the crimson header strip.
        assert_eq!(read_px(0, 0), header_bg);
        // Bottom-right corner sits on the dark panic background (no white splash left behind).
        assert_eq!(read_px(width - 1, height - 1), body_bg);

        // Header text produced pixels distinct from the header background.
        let mut header_ink = 0usize;
        for y in 0..HEADER_HEIGHT {
            for x in 0..width {
                if read_px(x, y) != header_bg {
                    header_ink += 1;
                }
            }
        }
        assert!(header_ink > 100, "expected rendered header banner glyphs");

        // Body text produced pixels distinct from the body background across multiple lines.
        let mut body_ink = 0usize;
        for y in BODY_TOP_Y..(BODY_TOP_Y + GLYPH_HEIGHT * 4) {
            for x in 0..width {
                if read_px(x, y) != body_bg {
                    body_ink += 1;
                }
            }
        }
        assert!(body_ink > 100, "expected rendered panic body glyphs");
    }

    #[test]
    fn framebuffer_panic_handles_rgb565_24bpp_and_narrow_wrap_without_oob() {
        // 16-bpp RGB565 on a tiny viewport that forces wrapping and vertical clamping.
        let width = 80usize;
        let height = 80usize;
        let pitch_16 = width * 2;
        let mut buf_16 = vec![0u8; height * pitch_16];
        let fb_16 = BootFramebuffer {
            base: NonNull::new(buf_16.as_mut_ptr()).expect("vec pointer is non-null"),
            width: width as u32,
            height: height as u32,
            pitch: pitch_16 as u32,
            bpp: 16,
            layout: BootPixelLayout::new(
                BootPixelChannel::new(5, 11),
                BootPixelChannel::new(6, 5),
                BootPixelChannel::new(5, 0),
            ),
        };
        emit_report_with_framebuffer::<SinkPort>(
            format_args!(
                "panicked at a/very/long/path/that/wraps/repeatedly/across/lines\n\
                 line2\nline3\nline4\nline5\nline6\nline7\nline8"
            ),
            Some(fb_16),
        );
        assert!(
            buf_16.iter().any(|&b| b != 0),
            "16-bpp framebuffer received rendered pixels"
        );

        // 24-bpp RGB888.
        let pitch_24 = width * 3;
        let mut buf_24 = vec![0u8; height * pitch_24];
        let fb_24 = BootFramebuffer {
            base: NonNull::new(buf_24.as_mut_ptr()).expect("vec pointer is non-null"),
            width: width as u32,
            height: height as u32,
            pitch: pitch_24 as u32,
            bpp: 24,
            layout: BootPixelLayout::RGBX8888,
        };
        emit_report_with_framebuffer::<SinkPort>(format_args!("24-bit panic"), Some(fb_24));
        assert!(
            buf_24.iter().any(|&b| b != 0),
            "24-bpp framebuffer received rendered pixels"
        );
    }

    #[test]
    fn slot_lifecycle_claims_once_and_respects_detach() {
        let mut backing = vec![0u8; 64 * 64 * 4];
        let fb = BootFramebuffer {
            base: NonNull::new(backing.as_mut_ptr()).expect("vec pointer is non-null"),
            width: 64,
            height: 64,
            pitch: 64 * 4,
            bpp: 32,
            layout: BootPixelLayout::BGRX8888,
        };

        let slot = PanicFramebufferSlot::new();
        assert!(slot.claim_for_panic().is_none());
        slot.attach(fb);
        assert_eq!(slot.claim_for_panic(), Some(fb));
        // Second panic claim on the same slot returns None so the primary panic stays intact.
        assert!(slot.claim_for_panic().is_none());

        let detached = PanicFramebufferSlot::new();
        detached.attach(fb);
        detached.detach();
        assert!(detached.claim_for_panic().is_none());
    }
}
