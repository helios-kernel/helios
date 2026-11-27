//! The terminal the desktop boots into: a grid of character cells, a
//! scrollback behind it, and the shell whose bytes fill both.
//!
//! This is a character grid and nothing more. It knows how to place a
//! byte the shell printed, how to apply ANSI SGR colours and intensity,
//! how to scroll when the last line is full, how to navigate scrollback,
//! and how to skip unsupported escape sequences so that a colouring `ls`
//! or system service log prints styled text rather than punctuation. It
//! does not know what a pixel is: [`Terminal::render_row`] is given a
//! frame buffer and writes the glyphs of one row into it, and everything
//! about where that row sits on the desktop belongs to the caller.
//!
//! # What scrolls and what is kept
//!
//! Lines are appended, never overwritten in place, so the live screen is
//! the last [`Terminal::rows`] of them and everything before is
//! scrollback. [`SCROLLBACK_LINES`] of it is kept, and the oldest line
//! is dropped when a new one would take the count past that: a terminal
//! that kept everything would grow without bound in a program that is
//! meant to run for the life of the machine.

use std::collections::VecDeque;
use std::vec::Vec;

use crate::desktop::{TERMINAL_BACKGROUND, TERMINAL_FOREGROUND};
use crate::font::{self, CELL_HEIGHT, CELL_WIDTH};
use crate::paint::{Colour, blend};

/// Lines kept behind the screen.
pub const SCROLLBACK_LINES: usize = 512;

/// Where a horizontal tab lands.
const TAB_WIDTH: usize = 8;

/// Maximum numeric parameters retained per CSI sequence without allocation.
const MAX_CSI_PARAMS: usize = 16;

/// Default foreground colour in `bgrx8888` `u32`.
const DEFAULT_FG_U32: u32 = TERMINAL_FOREGROUND.to_bgrx_u32();

/// Default background colour in `bgrx8888` `u32`.
const DEFAULT_BG_U32: u32 = TERMINAL_BACKGROUND.to_bgrx_u32();

/// Standard 16-colour ANSI palette (0..=7 normal, 8..=15 bright).
const ANSI_PALETTE: [Colour; 16] = [
    Colour::new(0x18, 0x1A, 0x20), // 0: black
    Colour::new(0xE0, 0x55, 0x61), // 1: red
    Colour::new(0x4E, 0xC9, 0x70), // 2: green
    Colour::new(0xE5, 0xB5, 0x4B), // 3: yellow
    Colour::new(0x4D, 0x9C, 0xF0), // 4: blue
    Colour::new(0xC6, 0x78, 0xDD), // 5: magenta
    Colour::new(0x39, 0xC5, 0xCF), // 6: cyan
    Colour::new(0xD4, 0xD7, 0xDD), // 7: white
    Colour::new(0x5C, 0x63, 0x70), // 8: bright black
    Colour::new(0xFF, 0x6B, 0x6B), // 9: bright red
    Colour::new(0x6E, 0xE7, 0x87), // 10: bright green
    Colour::new(0xFF, 0xD1, 0x66), // 11: bright yellow
    Colour::new(0x72, 0xB8, 0xFF), // 12: bright blue
    Colour::new(0xDF, 0x9B, 0xF5), // 13: bright magenta
    Colour::new(0x67, 0xE8, 0xF9), // 14: bright cyan
    Colour::new(0xFF, 0xFF, 0xFF), // 15: bright white
];

/// A single character cell in the terminal grid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    ch: char,
    /// Cell foreground colour in `bgrx8888` (`u32`).
    pub fg: u32,
    /// Cell background colour in `bgrx8888` (`u32`).
    pub bg: u32,
    /// Whether bold intensity is active for this cell.
    pub bold: bool,
}

impl Cell {
    /// Creates a character cell with explicit `bgrx8888` colours and intensity.
    pub const fn new(ch: char, fg: u32, bg: u32, bold: bool) -> Self {
        Self { ch, fg, bg, bold }
    }

    /// The character stored in this cell as a single ASCII byte, or `b'?'`
    /// for non-ASCII characters.
    pub const fn glyph(&self) -> u8 {
        if self.ch.is_ascii() {
            self.ch as u8
        } else {
            b'?'
        }
    }

    /// The Unicode scalar value stored in this cell.
    pub const fn character(&self) -> char {
        self.ch
    }
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            ch: ' ',
            fg: DEFAULT_FG_U32,
            bg: DEFAULT_BG_U32,
            bold: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Foreground {
    Default,
    Ansi(u8),
    Rgb(Colour),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Style {
    fg: Foreground,
    bg: Option<Colour>,
    bold: bool,
    dim: bool,
}

impl Default for Style {
    fn default() -> Self {
        Self {
            fg: Foreground::Default,
            bg: None,
            bold: false,
            dim: false,
        }
    }
}

impl Style {
    fn resolve(self, default_fg: Colour, default_bg: Colour) -> (u32, u32, bool) {
        let bg = self.bg.unwrap_or(default_bg);
        let fg = match self.fg {
            Foreground::Default => default_fg,
            Foreground::Ansi(idx) => {
                let resolved = if self.bold && idx < 8 { idx + 8 } else { idx };
                ANSI_PALETTE[resolved as usize]
            }
            Foreground::Rgb(colour) => colour,
        };
        let fg = if self.dim { blend(bg, fg, 150) } else { fg };
        (fg.to_bgrx_u32(), bg.to_bgrx_u32(), self.bold)
    }
}

/// What the terminal is in the middle of reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Escape {
    /// Ordinary text.
    None,
    /// An `ESC` was seen and the next byte says what kind.
    Introducer,
    /// A `CSI` sequence, which ends at a byte in `0x40..=0x7e`.
    ControlSequence,
    /// An `OSC` string, which ends at `BEL` or at `ESC \`.
    OperatingSystem,
    /// An `OSC` string that has seen its terminating `ESC`.
    OperatingSystemEnd,
    /// A two-byte sequence whose second byte carries no meaning here.
    Discard,
}

/// One line of the terminal, as styled cells.
type Line = Vec<Cell>;

/// A character grid with a scrollback, scrollback viewport offset, and SGR attributes.
pub struct Terminal {
    columns: usize,
    rows: usize,
    /// Every line, oldest first. The last `rows` are the live bottom.
    lines: VecDeque<Line>,
    /// Where the next character goes on the last line.
    column: usize,
    /// How many lines the viewport is scrolled up from the live bottom (`0` = live).
    scroll_offset: usize,
    escape: Escape,
    csi_params: [u16; MAX_CSI_PARAMS],
    csi_len: usize,
    csi_current: u16,
    csi_has_digits: bool,
    csi_private: bool,
    style: Style,
    default_fg: Colour,
    default_bg: Colour,
    /// Bytes of a character whose encoding is not complete yet.
    pending: Vec<u8>,
    /// Which visible rows have changed since the last render.
    dirty: Vec<bool>,
}

impl Terminal {
    /// An empty terminal of `columns` by `rows` cells using the desktop's
    /// default foreground and background colours.
    ///
    /// # Panics
    ///
    /// Panics on a grid with no cells: a terminal of no columns could
    /// never place a character, and the caller sized it from a window
    /// that has to be at least one cell across to be worth drawing.
    pub fn new(columns: usize, rows: usize) -> Self {
        Self::with_default_colours(columns, rows, TERMINAL_FOREGROUND, TERMINAL_BACKGROUND)
    }

    /// An empty terminal of `columns` by `rows` cells with explicit default
    /// foreground and background colours.
    ///
    /// # Panics
    ///
    /// Panics when `columns == 0 || rows == 0`.
    pub fn with_default_colours(
        columns: usize,
        rows: usize,
        default_fg: Colour,
        default_bg: Colour,
    ) -> Self {
        assert!(
            columns > 0 && rows > 0,
            "a terminal grid is at least one cell, not {columns}x{rows}"
        );
        let mut lines = VecDeque::with_capacity(rows);
        lines.push_back(Line::new());
        Self {
            columns,
            rows,
            lines,
            column: 0,
            scroll_offset: 0,
            escape: Escape::None,
            csi_params: [0; MAX_CSI_PARAMS],
            csi_len: 0,
            csi_current: 0,
            csi_has_digits: false,
            csi_private: false,
            style: Style::default(),
            default_fg,
            default_bg,
            pending: Vec::new(),
            dirty: vec![true; rows],
        }
    }

    pub const fn columns(&self) -> usize {
        self.columns
    }

    pub const fn rows(&self) -> usize {
        self.rows
    }

    /// Resizes the visible character grid while preserving retained lines and
    /// scrollback up to [`SCROLLBACK_LINES`] behind the new viewport height.
    ///
    /// # Panics
    ///
    /// Panics when `columns == 0 || rows == 0`.
    pub fn resize(&mut self, columns: usize, rows: usize) {
        assert!(
            columns > 0 && rows > 0,
            "a terminal grid is at least one cell, not {columns}x{rows}"
        );
        if self.columns == columns && self.rows == rows {
            return;
        }
        self.columns = columns;
        self.rows = rows;
        let max_lines = SCROLLBACK_LINES + rows;
        while self.lines.len() > max_lines {
            self.lines.pop_front();
        }
        self.column = self.column.min(columns);
        self.scroll_offset = self.scroll_offset.min(self.scrollback());
        self.dirty.resize(rows, true);
        self.dirty_all();
    }

    /// How many lines are behind the screen.
    pub fn scrollback(&self) -> usize {
        self.lines.len().saturating_sub(self.rows)
    }

    /// How many lines the viewport is currently scrolled up into history.
    pub const fn scroll_offset(&self) -> usize {
        self.scroll_offset
    }

    /// Scrolls the viewport up into scrollback history by `lines`.
    pub fn scroll_up(&mut self, lines: usize) {
        let next = self
            .scroll_offset
            .saturating_add(lines)
            .min(self.scrollback());
        if next != self.scroll_offset {
            self.scroll_offset = next;
            self.dirty_all();
        }
    }

    /// Scrolls the viewport down toward the live bottom by `lines`.
    pub fn scroll_down(&mut self, lines: usize) {
        let next = self.scroll_offset.saturating_sub(lines);
        if next != self.scroll_offset {
            self.scroll_offset = next;
            self.dirty_all();
        }
    }

    /// Scrolls the viewport to the oldest retained scrollback line.
    pub fn scroll_to_top(&mut self) {
        let max = self.scrollback();
        if self.scroll_offset != max {
            self.scroll_offset = max;
            self.dirty_all();
        }
    }

    /// Returns the viewport to the live bottom (`scroll_offset = 0`).
    pub fn scroll_to_bottom(&mut self) {
        if self.scroll_offset != 0 {
            self.scroll_offset = 0;
            self.dirty_all();
        }
    }

    /// Clears all lines, scrollback, pending UTF-8 bytes, and escape state.
    pub fn clear(&mut self) {
        self.lines.clear();
        self.lines.push_back(Line::new());
        self.column = 0;
        self.scroll_offset = 0;
        self.escape = Escape::None;
        self.csi_len = 0;
        self.csi_current = 0;
        self.csi_has_digits = false;
        self.csi_private = false;
        self.style = Style::default();
        self.pending.clear();
        self.dirty_all();
    }

    /// Where the cursor is on screen, as a `(column, row)` cell.
    pub fn cursor(&self) -> (usize, usize) {
        let row = self.lines.len().min(self.rows) - 1;
        (self.column.min(self.columns - 1), row)
    }

    /// The cells of one visible row, top row first, accounting for [`Self::scroll_offset`].
    ///
    /// Empty for a row the terminal has not reached yet, which is every
    /// row of a terminal that has just started.
    pub fn visible_row(&self, row: usize) -> &[Cell] {
        let max_scroll = self.scrollback();
        let clamped_offset = self.scroll_offset.min(max_scroll);
        let first = max_scroll - clamped_offset;
        self.lines
            .get(first + row)
            .map_or(&[][..], |line| line.as_slice())
    }

    /// Which rows have changed since the last time this was asked.
    pub fn take_dirty_rows(&mut self) -> Vec<usize> {
        let rows = self
            .dirty
            .iter()
            .enumerate()
            .filter_map(|(row, dirty)| dirty.then_some(row))
            .collect();
        self.dirty.iter_mut().for_each(|dirty| *dirty = false);
        rows
    }

    /// Mark every row as needing a redraw.
    pub fn dirty_all(&mut self) {
        self.dirty.iter_mut().for_each(|dirty| *dirty = true);
    }

    /// Take everything the shell printed.
    ///
    /// The bytes are a stream, so a character split across two reads is
    /// held until the rest of it arrives rather than drawn as the
    /// substitute.
    pub fn write(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
        loop {
            match core::str::from_utf8(&self.pending) {
                Ok(text) => {
                    let characters: Vec<char> = text.chars().collect();
                    self.pending.clear();
                    for character in characters {
                        self.put(character);
                    }
                    return;
                }
                Err(error) => {
                    let valid = error.valid_up_to();
                    let characters: Vec<char> = core::str::from_utf8(&self.pending[..valid])
                        .expect("the prefix the decoder reported as valid is valid")
                        .chars()
                        .collect();
                    for character in characters {
                        self.put(character);
                    }
                    match error.error_len() {
                        // The rest of this character has not arrived yet.
                        None => {
                            self.pending.drain(..valid);
                            return;
                        }
                        // A byte that cannot start or continue a
                        // character. The terminal shows the shell's
                        // output, so it shows that something was there.
                        Some(length) => {
                            self.pending.drain(..valid + length);
                            self.put(char::REPLACEMENT_CHARACTER);
                        }
                    }
                }
            }
        }
    }

    /// Place one character, or act on it when it is a control.
    fn put(&mut self, character: char) {
        match self.escape {
            Escape::None => {}
            Escape::Introducer => {
                self.escape = match character {
                    '[' => {
                        self.reset_csi();
                        Escape::ControlSequence
                    }
                    ']' => Escape::OperatingSystem,
                    // A designator: the byte after it names a character
                    // set this terminal has exactly one of.
                    '(' | ')' | '*' | '+' | '#' | '%' => Escape::Discard,
                    _ => Escape::None,
                };
                return;
            }
            Escape::ControlSequence => {
                self.feed_csi(character);
                return;
            }
            Escape::OperatingSystem => {
                self.escape = match character {
                    '\u{07}' => Escape::None,
                    '\u{1b}' => Escape::OperatingSystemEnd,
                    _ => Escape::OperatingSystem,
                };
                return;
            }
            Escape::OperatingSystemEnd => {
                self.escape = if character == '\\' {
                    Escape::None
                } else {
                    Escape::OperatingSystem
                };
                return;
            }
            Escape::Discard => {
                self.escape = Escape::None;
                return;
            }
        }

        match character {
            '\u{1b}' => self.escape = Escape::Introducer,
            '\n' => self.newline(),
            '\r' => self.column = 0,
            '\u{08}' => self.backspace(),
            '\t' => {
                let target = ((self.column / TAB_WIDTH) + 1) * TAB_WIDTH;
                for _ in self.column..target.min(self.columns) {
                    self.place(' ');
                }
            }
            character if font::is_printable(character) => self.place(character),
            // Every other control byte — a bell, a shift-out — is
            // something this terminal has no cell for. Dropping it is
            // what it means for a grid to show text.
            _ => {}
        }
    }

    fn reset_csi(&mut self) {
        self.csi_len = 0;
        self.csi_current = 0;
        self.csi_has_digits = false;
        self.csi_private = false;
    }

    fn push_csi_param(&mut self) {
        if self.csi_len < MAX_CSI_PARAMS {
            let value = if self.csi_has_digits {
                self.csi_current
            } else {
                0
            };
            self.csi_params[self.csi_len] = value;
            self.csi_len += 1;
        }
        self.csi_current = 0;
        self.csi_has_digits = false;
    }

    fn feed_csi(&mut self, character: char) {
        if character == '\u{1b}' {
            self.escape = Escape::Introducer;
            return;
        }
        if !character.is_ascii() {
            self.escape = Escape::None;
            return;
        }
        let byte = character as u8;
        match byte {
            b'0'..=b'9' => {
                self.csi_current = self
                    .csi_current
                    .saturating_mul(10)
                    .saturating_add(u16::from(byte - b'0'));
                self.csi_has_digits = true;
            }
            b';' | b':' => self.push_csi_param(),
            0x3c..=0x3f | 0x20..=0x2f => {
                self.csi_private = true;
            }
            0x40..=0x7e => {
                if self.csi_has_digits || self.csi_len > 0 {
                    self.push_csi_param();
                }
                if !self.csi_private {
                    match byte {
                        b'm' => self.apply_sgr(),
                        b'J' if self.csi_len == 1 && self.csi_params[0] == 2 => {
                            let start = self.lines.len().saturating_sub(self.rows);
                            for line in self.lines.iter_mut().skip(start) {
                                line.clear();
                            }
                            self.column = 0;
                            self.scroll_offset = 0;
                            self.dirty_all();
                        }
                        b'H' | b'f' => {
                            self.column = 0;
                        }
                        _ => {}
                    }
                }
                self.escape = Escape::None;
            }
            _ => {}
        }
    }

    fn apply_sgr(&mut self) {
        let len = self.csi_len;
        if len == 0 {
            self.style = Style::default();
            return;
        }
        let mut idx = 0;
        while idx < len {
            let code = self.csi_params[idx];
            match code {
                0 => self.style = Style::default(),
                1 => {
                    self.style.bold = true;
                    self.style.dim = false;
                }
                2 => {
                    self.style.dim = true;
                    self.style.bold = false;
                }
                22 => {
                    self.style.bold = false;
                    self.style.dim = false;
                }
                30..=37 => self.style.fg = Foreground::Ansi((code - 30) as u8),
                39 => self.style.fg = Foreground::Default,
                40..=47 => self.style.bg = Some(ANSI_PALETTE[(code - 40) as usize]),
                49 => self.style.bg = None,
                90..=97 => self.style.fg = Foreground::Ansi((code - 90 + 8) as u8),
                100..=107 => self.style.bg = Some(ANSI_PALETTE[(code - 100 + 8) as usize]),
                38 | 48 => {
                    let is_fg = code == 38;
                    if let Some(colour) = self.parse_extended_colour(&mut idx) {
                        if is_fg {
                            self.style.fg = Foreground::Rgb(colour);
                        } else {
                            self.style.bg = Some(colour);
                        }
                    }
                }
                _ => {}
            }
            idx += 1;
        }
    }

    fn parse_extended_colour(&self, idx: &mut usize) -> Option<Colour> {
        let kind = *self.csi_params.get(*idx + 1)?;
        match kind {
            5 => {
                let n = *self.csi_params.get(*idx + 2)?;
                *idx += 2;
                Some(palette_256(n.min(255) as u8))
            }
            2 => {
                let r = *self.csi_params.get(*idx + 2)?;
                let g = *self.csi_params.get(*idx + 3)?;
                let b = *self.csi_params.get(*idx + 4)?;
                *idx += 4;
                Some(Colour::new(
                    r.min(255) as u8,
                    g.min(255) as u8,
                    b.min(255) as u8,
                ))
            }
            _ => None,
        }
    }

    /// Put a printable character in the current cell and advance.
    fn place(&mut self, character: char) {
        if self.column >= self.columns {
            self.newline();
        }
        let column = self.column;
        let (fg, bg, bold) = self.style.resolve(self.default_fg, self.default_bg);
        let default_cell = Cell::new(
            ' ',
            self.default_fg.to_bgrx_u32(),
            self.default_bg.to_bgrx_u32(),
            false,
        );
        let line = self
            .lines
            .back_mut()
            .expect("a terminal always has a line to write on");
        if line.len() <= column {
            line.resize(column + 1, default_cell);
        }
        line[column] = Cell::new(character, fg, bg, bold);
        self.column += 1;
        self.mark_last_row();
    }

    fn backspace(&mut self) {
        if self.column == 0 {
            return;
        }
        // A backspace moves the cursor and rubs out nothing. Erasing
        // here would rub out two cells for every one the shell means to
        // erase, because what a shell sends to erase a character is a
        // backspace, a space, and a backspace again.
        self.column -= 1;
        self.mark_last_row();
    }

    fn newline(&mut self) {
        self.column = 0;
        let was_full = self.lines.len() >= self.rows;
        self.lines.push_back(Line::new());
        let dropped_oldest = if self.lines.len() > SCROLLBACK_LINES + self.rows {
            self.lines.pop_front();
            true
        } else {
            false
        };
        if was_full {
            if self.scroll_offset > 0 {
                // Anchor the user's inspected scrollback viewport when new lines arrive.
                let max_scroll = self.scrollback();
                let at_top = dropped_oldest && self.scroll_offset >= max_scroll;
                self.scroll_offset = (self.scroll_offset + 1).min(max_scroll);
                if at_top {
                    self.dirty_all();
                }
            } else {
                // Everything on screen moved up by a row, so everything on
                // screen has to be drawn again.
                self.dirty_all();
            }
        } else {
            self.mark_last_row();
        }
    }

    fn mark_last_row(&mut self) {
        if self.scroll_offset > 0 {
            return;
        }
        let row = self.lines.len().min(self.rows) - 1;
        self.dirty[row] = true;
    }

    /// Draw one visible row into `target`.
    ///
    /// `target` is a frame buffer of `stride` bytes per row in the
    /// display's four-byte pixels; `origin` is the pixel the terminal's
    /// top-left cell sits at. Only the row's own strip is touched, which
    /// is what makes a keystroke cost one glyph cell of traffic rather
    /// than a screen.
    pub fn render_row(
        &self,
        row: usize,
        target: &mut [u8],
        stride: usize,
        origin: (usize, usize),
        foreground: Colour,
        background: Colour,
    ) {
        let cells = self.visible_row(row);
        let top = origin.1 + row * CELL_HEIGHT;
        let default_fg_u32 = self.default_fg.to_bgrx_u32();
        let default_bg_u32 = self.default_bg.to_bgrx_u32();
        for column in 0..self.columns {
            let left = origin.0 + column * CELL_WIDTH;
            let (character, fg, bg, bold) = match cells.get(column) {
                Some(cell) => {
                    let fg = if cell.fg == default_fg_u32 {
                        foreground
                    } else {
                        Colour::from_bgrx_u32(cell.fg)
                    };
                    let bg = if cell.bg == default_bg_u32 {
                        background
                    } else {
                        Colour::from_bgrx_u32(cell.bg)
                    };
                    (cell.character(), fg, bg, cell.bold)
                }
                None => (' ', foreground, background, false),
            };
            draw_cell(target, stride, left, top, character, fg, bg, bold);
        }
    }

    /// Draw the block the cursor sits under.
    pub fn render_cursor(
        &self,
        target: &mut [u8],
        stride: usize,
        origin: (usize, usize),
        colour: Colour,
    ) {
        if self.scroll_offset > 0 {
            return;
        }
        let (column, row) = self.cursor();
        let left = origin.0 + column * CELL_WIDTH;
        let top = origin.1 + row * CELL_HEIGHT;
        for y in 0..CELL_HEIGHT {
            let start = (top + y) * stride + left * 4;
            let Some(strip) = target.get_mut(start..start + CELL_WIDTH * 4) else {
                return;
            };
            for pixel in strip.as_chunks_mut::<4>().0 {
                colour.write(pixel);
            }
        }
    }
}

fn palette_256(index: u8) -> Colour {
    if index < 16 {
        return ANSI_PALETTE[index as usize];
    }
    if index < 232 {
        let idx = index - 16;
        let r = idx / 36;
        let g = (idx / 6) % 6;
        let b = idx % 6;
        let level = |v: u8| if v == 0 { 0 } else { 55 + v * 40 };
        return Colour::new(level(r), level(g), level(b));
    }
    let v = 8 + (index - 232) * 10;
    Colour::new(v, v, v)
}

/// Draw one character cell, glyph over background.
#[expect(
    clippy::too_many_arguments,
    reason = "cell coordinates, colours, and bold flag are explicit per-cell parameters"
)]
fn draw_cell(
    target: &mut [u8],
    stride: usize,
    left: usize,
    top: usize,
    character: char,
    foreground: Colour,
    background: Colour,
    bold: bool,
) {
    let raster = font::glyph(character).raster();
    for y in 0..CELL_HEIGHT {
        let start = (top + y) * stride + left * 4;
        let Some(strip) = target.get_mut(start..start + CELL_WIDTH * 4) else {
            return;
        };
        let coverage = raster.get(y).copied().unwrap_or(&[]);
        for (x, pixel) in strip.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let cur = coverage.get(x).copied().unwrap_or(0);
            let alpha = if bold && x > 0 {
                let prev = coverage.get(x - 1).copied().unwrap_or(0);
                cur.saturating_add(prev / 2)
            } else {
                cur
            };
            blend(background, foreground, alpha).write(pixel);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row_text(terminal: &Terminal, row: usize) -> String {
        terminal
            .visible_row(row)
            .iter()
            .map(Cell::character)
            .collect()
    }

    #[test]
    fn printed_text_lands_on_the_first_row() {
        let mut terminal = Terminal::new(20, 4);
        terminal.write(b"hello");
        assert_eq!(row_text(&terminal, 0), "hello");
        assert_eq!(terminal.cursor(), (5, 0));
    }

    #[test]
    fn a_newline_starts_the_next_row_and_a_return_rewrites_this_one() {
        let mut terminal = Terminal::new(20, 4);
        terminal.write(b"one\ntwo");
        assert_eq!(row_text(&terminal, 0), "one");
        assert_eq!(row_text(&terminal, 1), "two");
        terminal.write(b"\rTWO");
        assert_eq!(row_text(&terminal, 1), "TWO");
    }

    #[test]
    fn a_backspace_moves_the_cursor_back_over_what_is_overwritten_next() {
        let mut terminal = Terminal::new(20, 4);
        terminal.write(b"helo\x08lo");
        assert_eq!(row_text(&terminal, 0), "hello");
        assert_eq!(terminal.cursor(), (5, 0));
    }

    #[test]
    fn the_sequence_a_shell_sends_to_erase_a_character_erases_one() {
        let mut terminal = Terminal::new(20, 4);
        terminal.write(b"hello\x08 \x08");
        // The cell the character was in is a blank the row still holds:
        // erasing a character is writing a space over it.
        assert_eq!(row_text(&terminal, 0), "hell ");
        assert_eq!(terminal.cursor(), (4, 0));
    }

    #[test]
    fn text_wider_than_the_grid_wraps_onto_the_next_row() {
        let mut terminal = Terminal::new(4, 4);
        terminal.write(b"abcdef");
        assert_eq!(row_text(&terminal, 0), "abcd");
        assert_eq!(row_text(&terminal, 1), "ef");
    }

    #[test]
    fn the_screen_scrolls_and_what_left_it_is_scrollback() {
        let mut terminal = Terminal::new(20, 3);
        terminal.write(b"one\ntwo\nthree\nfour");
        // The screen holds the last three lines...
        assert_eq!(row_text(&terminal, 0), "two");
        assert_eq!(row_text(&terminal, 1), "three");
        assert_eq!(row_text(&terminal, 2), "four");
        // ...and the first is behind it rather than gone.
        assert_eq!(terminal.scrollback(), 1);
    }

    #[test]
    fn the_scrollback_stops_growing_once_it_is_full() {
        let mut terminal = Terminal::new(20, 2);
        for index in 0..(SCROLLBACK_LINES + 32) {
            terminal.write(format!("line {index}\n").as_bytes());
        }
        assert_eq!(terminal.scrollback(), SCROLLBACK_LINES);
        // The newest lines are still the ones on screen.
        assert_eq!(
            row_text(&terminal, 0),
            format!("line {}", SCROLLBACK_LINES + 31)
        );
    }

    #[test]
    fn a_scroll_marks_every_row_for_redraw_and_a_keystroke_marks_one() {
        let mut terminal = Terminal::new(20, 3);
        let _ = terminal.take_dirty_rows();
        terminal.write(b"a");
        assert_eq!(terminal.take_dirty_rows(), vec![0]);
        terminal.write(b"\nb\nc\n");
        // The fourth line scrolled the screen, so everything moved.
        assert_eq!(terminal.take_dirty_rows(), vec![0, 1, 2]);
    }

    #[test]
    fn a_colour_escape_is_skipped_rather_than_printed() {
        let mut terminal = Terminal::new(20, 3);
        terminal.write(b"\x1b[1;32mgreen\x1b[0m done");
        assert_eq!(row_text(&terminal, 0), "green done");
    }

    #[test]
    fn a_window_title_sequence_is_skipped_whichever_way_it_ends() {
        let mut terminal = Terminal::new(20, 3);
        terminal.write(b"\x1b]0;a title\x07x");
        assert_eq!(row_text(&terminal, 0), "x");
        terminal.write(b"\r\x1b]0;another\x1b\\y");
        assert_eq!(row_text(&terminal, 0), "y");
    }

    #[test]
    fn a_character_split_across_two_reads_is_drawn_once_it_is_whole() {
        let mut terminal = Terminal::new(20, 3);
        let bytes = "é".as_bytes();
        terminal.write(&bytes[..1]);
        assert_eq!(row_text(&terminal, 0), "");
        terminal.write(&bytes[1..]);
        assert_eq!(row_text(&terminal, 0), "é");
    }

    #[test]
    fn a_byte_that_can_never_be_a_character_is_shown_as_the_replacement() {
        let mut terminal = Terminal::new(20, 3);
        terminal.write(&[b'a', 0xff, b'b']);
        assert_eq!(row_text(&terminal, 0), "a\u{fffd}b");
    }

    #[test]
    fn a_tab_advances_to_the_next_stop() {
        let mut terminal = Terminal::new(20, 3);
        terminal.write(b"ab\tc");
        assert_eq!(row_text(&terminal, 0), "ab      c");
    }

    #[test]
    fn sgr_colours_bold_dim_256_and_truecolour_update_cells_and_strip_unknown_csi() {
        let mut terminal = Terminal::new(40, 4);
        terminal.write(b"\x1b[32mOK\x1b[0m \x1b[1;31mERR\x1b[22m \x1b[38;5;196mC\x1b[48;2;1;2;3mT\x1b[0m\x1b[?25hX");
        assert_eq!(row_text(&terminal, 0), "OK ERR CTX");

        let row = terminal.visible_row(0);
        assert_eq!(row[0].glyph(), b'O');
        assert_eq!(row[0].fg, ANSI_PALETTE[2].to_bgrx_u32());
        assert_eq!(row[0].bg, TERMINAL_BACKGROUND.to_bgrx_u32());
        assert!(!row[0].bold);

        // Reset restores defaults.
        assert_eq!(row[2].fg, TERMINAL_FOREGROUND.to_bgrx_u32());
        assert_eq!(row[2].bg, TERMINAL_BACKGROUND.to_bgrx_u32());

        // Bold + ANSI red (1) brightens to bright red (9) and marks bold.
        assert_eq!(row[3].glyph(), b'E');
        assert_eq!(row[3].fg, ANSI_PALETTE[9].to_bgrx_u32());
        assert!(row[3].bold);

        // 256-colour (196 = bright cube red: 255, 0, 0).
        assert_eq!(row[7].glyph(), b'C');
        assert_eq!(row[7].fg, Colour::new(255, 0, 0).to_bgrx_u32());

        // 24-bit truecolour bg (1, 2, 3), keeping previous fg (255, 0, 0).
        assert_eq!(row[8].glyph(), b'T');
        assert_eq!(row[8].bg, Colour::new(1, 2, 3).to_bgrx_u32());

        // After reset + private CSI (?25h), 'X' renders cleanly with default colours.
        assert_eq!(row[9].glyph(), b'X');
        assert_eq!(row[9].fg, TERMINAL_FOREGROUND.to_bgrx_u32());
        assert_eq!(row[9].bg, TERMINAL_BACKGROUND.to_bgrx_u32());
    }

    #[test]
    fn default_cell_rendering_is_bit_identical_to_baseline_glyph_blend() {
        let mut terminal = Terminal::new(10, 1);
        terminal.write(b"echo hello");
        let width = 10 * CELL_WIDTH;
        let stride = width * 4;
        let mut actual = vec![0_u8; stride * CELL_HEIGHT];
        terminal.render_row(
            0,
            &mut actual,
            stride,
            (0, 0),
            TERMINAL_FOREGROUND,
            TERMINAL_BACKGROUND,
        );

        let mut expected = vec![0_u8; stride * CELL_HEIGHT];
        for (col, ch) in "echo hello".chars().enumerate() {
            let raster = font::glyph(ch).raster();
            for y in 0..CELL_HEIGHT {
                let start = y * stride + col * CELL_WIDTH * 4;
                let strip = &mut expected[start..start + CELL_WIDTH * 4];
                let coverage = raster.get(y).copied().unwrap_or(&[]);
                for (x, pixel) in strip.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                    let alpha = coverage.get(x).copied().unwrap_or(0);
                    blend(TERMINAL_BACKGROUND, TERMINAL_FOREGROUND, alpha).write(pixel);
                }
            }
        }
        assert_eq!(actual, expected);
    }

    #[test]
    fn scroll_up_anchors_history_when_new_lines_arrive() {
        let mut terminal = Terminal::new(20, 3);
        terminal.write(b"L0\nL1\nL2\nL3\nL4");
        assert_eq!(terminal.scroll_offset(), 0);
        assert_eq!(row_text(&terminal, 0), "L2");
        assert_eq!(row_text(&terminal, 2), "L4");

        let _ = terminal.take_dirty_rows();
        terminal.scroll_up(2);
        assert_eq!(terminal.scroll_offset(), 2);
        assert_eq!(terminal.take_dirty_rows(), vec![0, 1, 2]);
        assert_eq!(row_text(&terminal, 0), "L0");
        assert_eq!(row_text(&terminal, 2), "L2");

        // Writing new lines while scrolled up keeps the inspected viewport anchored.
        terminal.write(b"\nL5\nL6");
        assert_eq!(terminal.scroll_offset(), 4);
        assert_eq!(row_text(&terminal, 0), "L0");
        assert_eq!(row_text(&terminal, 2), "L2");

        terminal.scroll_down(1);
        assert_eq!(terminal.scroll_offset(), 3);
        assert_eq!(row_text(&terminal, 0), "L1");

        terminal.scroll_to_bottom();
        assert_eq!(terminal.scroll_offset(), 0);
        assert_eq!(row_text(&terminal, 0), "L4");
        assert_eq!(row_text(&terminal, 2), "L6");
    }

    #[test]
    fn resize_preserves_content_clamps_cursor_and_scrollback_and_marks_all_rows_dirty() {
        let mut terminal = Terminal::new(20, 3);
        terminal.write(b"L0\nL1\nL2\nL3\n0123456789abcdef");
        let _ = terminal.take_dirty_rows();

        // Scroll into history, then grow the viewport so scrollback shrinks.
        terminal.scroll_up(2);
        assert_eq!(terminal.scroll_offset(), 2);
        let _ = terminal.take_dirty_rows();

        terminal.resize(40, 5);
        assert_eq!(terminal.columns(), 40);
        assert_eq!(terminal.rows(), 5);
        assert_eq!(terminal.scroll_offset(), 0);
        assert_eq!(terminal.take_dirty_rows(), vec![0, 1, 2, 3, 4]);
        assert_eq!(row_text(&terminal, 0), "L0");
        assert_eq!(row_text(&terminal, 4), "0123456789abcdef");

        // Shrink columns below the current cursor column and verify wrapping still works.
        terminal.resize(8, 2);
        assert_eq!(terminal.columns(), 8);
        assert_eq!(terminal.rows(), 2);
        assert_eq!(terminal.cursor(), (7, 1));
        assert_eq!(terminal.take_dirty_rows(), vec![0, 1]);
        assert_eq!(row_text(&terminal, 0), "L3");
        assert_eq!(row_text(&terminal, 1), "0123456789abcdef");

        // Writing at the clamped right edge wraps onto a fresh line cleanly.
        terminal.write(b"Z");
        assert_eq!(row_text(&terminal, 1), "Z");
        assert_eq!(terminal.cursor(), (1, 1));
    }

    #[test]
    fn resize_trims_excess_scrollback_to_the_new_viewport_bound() {
        let mut terminal = Terminal::new(16, 10);
        for index in 0..(SCROLLBACK_LINES + 10) {
            terminal.write(format!("line-{index}\n").as_bytes());
        }
        assert_eq!(terminal.scrollback(), SCROLLBACK_LINES);

        terminal.resize(16, 2);
        assert_eq!(terminal.scrollback(), SCROLLBACK_LINES);
        assert_eq!(terminal.take_dirty_rows(), vec![0, 1]);
    }
}
