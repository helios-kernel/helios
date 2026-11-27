//! Full-screen dark kernel and service log console (`#070A0F` / `#101218`).
//!
//! Wraps a borderless [`Terminal`] sized to the display [`Mode`] with
//! damage-tracked `bgrx8888` rendering, optional bottom shortcut hint strip,
//! and ANSI SGR formatters for kernel log records and service readiness lines.

use std::fmt::Write as _;
use std::string::String;
use std::vec::Vec;

use helios_api::display::Mode;

use crate::damage::{Damage, Region};
use crate::font::{self, CELL_HEIGHT, CELL_WIDTH};
use crate::paint::{Colour, blend};
use crate::term::Terminal;

/// Bytes occupied by one `bgrx8888` pixel.
const BYTES_PER_PIXEL: usize = 4;

/// Primary dark background of the log console (`#070A0F`).
pub const CONSOLE_BACKGROUND: Colour = Colour::new(0x07, 0x0A, 0x0F);
/// Secondary dark background used by the subtle bottom hint strip (`#101218`).
pub const CONSOLE_HINT_BACKGROUND: Colour = Colour::new(0x10, 0x12, 0x18);
/// Default log body foreground (`#E8EAED`).
pub const CONSOLE_FOREGROUND: Colour = Colour::new(0xE8, 0xEA, 0xED);
/// Muted foreground for the bottom hint strip (`#8B949E`).
pub const CONSOLE_HINT_FOREGROUND: Colour = Colour::new(0x8B, 0x94, 0x9E);

/// Default keyboard shortcut hint shown on the bottom console strip.
pub const DEFAULT_CONSOLE_HINT: &str = "[Enter / Alt+F2: Terminal  |  Shift+PgUp/PgDn: Scroll]";

/// Service readiness badge printed on console startup lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceStatus {
    Ok,
    Warn,
    Failed,
}

/// Formats `(uptime_nanos, origin, message)` into an ANSI SGR console line.
///
/// Renders `[   0.123456] ` in dim intensity, an optional cyan `origin:` tag,
/// and the message body in default foreground, terminated with `\n`.
pub fn format_log_line(uptime_nanos: u64, origin: Option<&str>, message: &str) -> String {
    let total_us = uptime_nanos / 1_000;
    let secs = total_us / 1_000_000;
    let usecs = total_us % 1_000_000;
    let mut line = String::with_capacity(64 + message.len());
    let _ = write!(line, "\x1b[2m[{secs:>5}.{usecs:06}]\x1b[22m ");
    if let Some(origin) = origin
        && !origin.is_empty()
    {
        let _ = write!(line, "\x1b[36m{origin}\x1b[39m: ");
    }
    line.push_str(message);
    if !line.ends_with('\n') {
        line.push('\n');
    }
    line
}

/// Formats a systemd/Linux-style service readiness line with ANSI SGR badge.
pub fn format_service_line(status: ServiceStatus, message: &str) -> String {
    let badge = match status {
        ServiceStatus::Ok => "\x1b[1;32m  OK  \x1b[0m",
        ServiceStatus::Warn => "\x1b[1;33m WARN \x1b[0m",
        ServiceStatus::Failed => "\x1b[1;31mFAILED\x1b[0m",
    };
    let mut line = String::with_capacity(32 + message.len());
    let _ = write!(line, "[{badge}] {message}");
    if !line.ends_with('\n') {
        line.push('\n');
    }
    line
}

/// Full-screen borderless log console with damage tracking and scrollback.
pub struct LogConsole {
    mode: Mode,
    terminal: Terminal,
    damage: Damage,
    hint: Option<String>,
    has_hint_row: bool,
}

impl LogConsole {
    /// Creates a full-screen log console sized to `mode` with the default hint strip.
    pub fn new(mode: Mode) -> Self {
        Self::with_hint(mode, Some(DEFAULT_CONSOLE_HINT))
    }

    /// Creates a full-screen log console sized to `mode` with an optional bottom hint strip.
    pub fn with_hint(mode: Mode, hint: Option<&str>) -> Self {
        let columns = (mode.width as usize / CELL_WIDTH).max(1);
        let total_rows = (mode.height as usize / CELL_HEIGHT).max(1);
        let has_hint_row = hint.is_some() && total_rows > 1;
        let log_rows = if has_hint_row {
            total_rows - 1
        } else {
            total_rows
        };
        let mut damage = Damage::new(Region::new(0, 0, mode.width, mode.height));
        damage.add_all();
        Self {
            mode,
            terminal: Terminal::with_default_colours(
                columns,
                log_rows,
                CONSOLE_FOREGROUND,
                CONSOLE_BACKGROUND,
            ),
            damage,
            hint: hint.map(String::from),
            has_hint_row,
        }
    }

    pub const fn mode(&self) -> Mode {
        self.mode
    }

    pub const fn terminal(&self) -> &Terminal {
        &self.terminal
    }

    pub const fn terminal_mut(&mut self) -> &mut Terminal {
        &mut self.terminal
    }

    /// Updates or hides the bottom hint strip and damages the strip row.
    pub fn set_hint(&mut self, hint: Option<&str>) {
        self.hint = hint.map(String::from);
        if self.has_hint_row {
            let y = (self.terminal.rows() * CELL_HEIGHT) as u32;
            let height = self.mode.height.saturating_sub(y);
            self.damage.add(Region::new(0, y, self.mode.width, height));
        }
    }

    /// Marks the entire console surface dirty so the next render repaints everything.
    pub fn damage_all(&mut self) {
        self.damage.add_all();
        self.terminal.dirty_all();
    }

    /// Appends raw ANSI-capable UTF-8 bytes to the console terminal.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.terminal.write(bytes);
    }

    /// Appends a formatted kernel/subsystem log entry.
    pub fn push_log(&mut self, uptime_nanos: u64, origin: Option<&str>, message: &str) {
        let line = format_log_line(uptime_nanos, origin, message);
        self.terminal.write(line.as_bytes());
    }

    /// Appends a formatted service readiness transition line.
    pub fn push_status(&mut self, status: ServiceStatus, message: &str) {
        let line = format_service_line(status, message);
        self.terminal.write(line.as_bytes());
    }

    pub fn scroll_up(&mut self, lines: usize) {
        self.terminal.scroll_up(lines);
    }

    pub fn scroll_down(&mut self, lines: usize) {
        self.terminal.scroll_down(lines);
    }

    pub fn scroll_page_up(&mut self) {
        let page = self.terminal.rows().saturating_sub(1).max(1);
        self.terminal.scroll_up(page);
    }

    pub fn scroll_page_down(&mut self) {
        let page = self.terminal.rows().saturating_sub(1).max(1);
        self.terminal.scroll_down(page);
    }

    pub fn scroll_to_top(&mut self) {
        self.terminal.scroll_to_top();
    }

    pub fn scroll_to_bottom(&mut self) {
        self.terminal.scroll_to_bottom();
    }

    /// Blits any damaged console regions into `pixels` (`bgrx8888` bytes, `stride_bytes` per row).
    pub fn render(&mut self, pixels: &mut [u8], stride_bytes: usize) -> Vec<Region> {
        self.collect_terminal_damage();
        let regions = self.damage.take();
        for &region in &regions {
            self.compose_region(region, pixels, stride_bytes);
        }
        regions
    }

    /// Blits any damaged console regions into `pixels` (`bgrx8888` `u32` words, `stride_pixels` per row).
    pub fn render_u32(&mut self, pixels: &mut [u32], stride_pixels: usize) -> Vec<Region> {
        self.collect_terminal_damage();
        let regions = self.damage.take();
        if regions.is_empty() {
            return regions;
        }
        let row_bytes = (self.mode.width as usize) * BYTES_PER_PIXEL;
        let mut scratch = vec![0_u8; row_bytes * (self.mode.height as usize)];
        for &region in &regions {
            self.compose_region(region, &mut scratch, row_bytes);
            for y in region.y..region.bottom() {
                let src_row = (y as usize) * row_bytes;
                let dst_row = (y as usize) * stride_pixels;
                for x in region.x..region.right() {
                    let src_off = src_row + (x as usize) * BYTES_PER_PIXEL;
                    let dst_off = dst_row + x as usize;
                    if let (Some(bytes), Some(dst)) =
                        (scratch.get(src_off..src_off + 4), pixels.get_mut(dst_off))
                    {
                        *dst = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]);
                    }
                }
            }
        }
        regions
    }

    fn collect_terminal_damage(&mut self) {
        for row in self.terminal.take_dirty_rows() {
            self.damage.add(Region::new(
                0,
                (row * CELL_HEIGHT) as u32,
                self.mode.width,
                CELL_HEIGHT as u32,
            ));
        }
    }

    fn compose_region(&self, region: Region, pixels: &mut [u8], stride_bytes: usize) {
        fill_rect_bytes(pixels, stride_bytes, region, CONSOLE_BACKGROUND);

        let log_rows = self.terminal.rows();
        let first_row = (region.y as usize) / CELL_HEIGHT;
        let last_row = (region.bottom().saturating_sub(1) as usize) / CELL_HEIGHT;
        for row in first_row..=last_row.min(log_rows.saturating_sub(1)) {
            self.terminal.render_row(
                row,
                pixels,
                stride_bytes,
                (0, 0),
                CONSOLE_FOREGROUND,
                CONSOLE_BACKGROUND,
            );
        }

        if self.has_hint_row {
            let hint_y = (log_rows * CELL_HEIGHT) as u32;
            let hint_rect = Region::new(
                0,
                hint_y,
                self.mode.width,
                self.mode.height.saturating_sub(hint_y),
            )
            .intersection(region);
            if !hint_rect.is_empty()
                && let Some(hint) = &self.hint
            {
                let strip = Region::new(0, hint_y, self.mode.width, CELL_HEIGHT as u32)
                    .intersection(region);
                fill_rect_bytes(pixels, stride_bytes, strip, CONSOLE_HINT_BACKGROUND);
                draw_hint_text(
                    pixels,
                    stride_bytes,
                    hint_y as usize,
                    self.terminal.columns(),
                    hint,
                );
            }
        }
    }
}

fn draw_hint_text(target: &mut [u8], stride_bytes: usize, top: usize, columns: usize, text: &str) {
    for (col, ch) in text.chars().take(columns).enumerate() {
        let left = col * CELL_WIDTH;
        let raster = font::glyph(ch).raster();
        for y in 0..CELL_HEIGHT {
            let start = (top + y) * stride_bytes + left * BYTES_PER_PIXEL;
            let Some(strip) = target.get_mut(start..start + CELL_WIDTH * BYTES_PER_PIXEL) else {
                return;
            };
            let coverage = raster.get(y).copied().unwrap_or(&[]);
            for (x, pixel) in strip.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                let alpha = coverage.get(x).copied().unwrap_or(0);
                blend(CONSOLE_HINT_BACKGROUND, CONSOLE_HINT_FOREGROUND, alpha).write(pixel);
            }
        }
    }
}

fn fill_rect_bytes(pixels: &mut [u8], stride_bytes: usize, region: Region, colour: Colour) {
    for y in region.y..region.bottom() {
        let start = (y as usize) * stride_bytes + (region.x as usize) * BYTES_PER_PIXEL;
        let width = (region.width as usize) * BYTES_PER_PIXEL;
        let Some(strip) = pixels.get_mut(start..start + width) else {
            return;
        };
        let Some(first) = strip.get_mut(..BYTES_PER_PIXEL) else {
            continue;
        };
        colour.write(first);
        let mut painted = BYTES_PER_PIXEL;
        while painted < strip.len() {
            let step = painted.min(strip.len() - painted);
            strip.copy_within(..step, painted);
            painted += step;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::term::Cell;

    fn row_string(console: &LogConsole, row: usize) -> String {
        console
            .terminal()
            .visible_row(row)
            .iter()
            .map(Cell::character)
            .collect()
    }

    #[test]
    fn formats_uptime_origin_and_service_status_with_sgr() {
        let line = format_log_line(123_456_000, Some("kernel"), "SMP initialized");
        assert!(line.contains("[    0.123456]"));
        assert!(line.contains("\x1b[36mkernel\x1b[39m: SMP initialized"));

        let ok = format_service_line(ServiceStatus::Ok, "Started /inspector");
        assert!(ok.contains("\x1b[1;32m  OK  \x1b[0m"));
        let warn = format_service_line(ServiceStatus::Warn, "Slow disk");
        assert!(warn.contains("\x1b[1;33m WARN \x1b[0m"));
        let fail = format_service_line(ServiceStatus::Failed, "Mount failed");
        assert!(fail.contains("\x1b[1;31mFAILED\x1b[0m"));
    }

    #[test]
    fn log_console_renders_dark_surface_and_tracks_row_damage() {
        let mode = Mode {
            width: 640,
            height: 240,
        };
        let mut console = LogConsole::new(mode);
        console.push_log(123_456_000, Some("virtio"), "online");
        console.push_status(ServiceStatus::Ok, "Started /inspector");

        let stride = (mode.width as usize) * BYTES_PER_PIXEL;
        let mut fb = vec![0_u8; stride * (mode.height as usize)];
        let initial = console.render(&mut fb, stride);
        assert_eq!(initial, vec![Region::new(0, 0, 640, 240)]);

        // Unwritten top-right background pixel must match CONSOLE_BACKGROUND (#070A0F).
        let bg_off = 2 * stride + (630 * BYTES_PER_PIXEL);
        assert_eq!(&fb[bg_off..bg_off + 3], &[0x0F, 0x0A, 0x07]);

        // Second render with no writes produces zero damage.
        assert!(console.render(&mut fb, stride).is_empty());

        // Appending a newline-terminated log entry damages only the written row and the new cursor row.
        console.push_log(500_000_000, None, "ready");
        let delta = console.render(&mut fb, stride);
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].height, (CELL_HEIGHT * 2) as u32);

        // Writing characters on the current row without a newline damages a single cell height.
        console.write_bytes(b"ok");
        let single_row = console.render(&mut fb, stride);
        assert_eq!(single_row.len(), 1);
        assert_eq!(single_row[0].height, CELL_HEIGHT as u32);

        assert!(row_string(&console, 0).contains("[    0.123456] virtio: online"));
        assert!(row_string(&console, 1).contains("[  OK  ] Started /inspector"));
    }

    #[test]
    fn render_u32_produces_bgrx_words_compatible_with_crossfade() {
        let mode = Mode {
            width: 320,
            height: 160,
        };
        let mut console = LogConsole::new(mode);
        console.push_status(ServiceStatus::Ok, "Ready");
        let mut fb = vec![0_u32; (mode.width * mode.height) as usize];
        let regions = console.render_u32(&mut fb, mode.width as usize);
        assert!(!regions.is_empty());
        assert_eq!(fb[319], CONSOLE_BACKGROUND.to_bgrx_u32());
    }
}
