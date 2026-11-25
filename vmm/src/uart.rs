//! Minimal ARM PL011 early-boot console on the static MMIO bus.
//!
//! Writes coalesce bytes until newline or [`TRANSFER_CHUNK_BYTES`] so the
//! async device loop flushes complete lines without blocking inside MMIO dispatch.

use helios_api::hv::{IoAccess, MmioDevice, MmioRange, TRANSFER_CHUNK_BYTES};

use crate::boot::{UART, UART_SIZE};
use crate::error::Error;

/// Emulated PL011 UART for Linux `earlycon=pl011,0x9000000`.
pub struct Pl011 {
    range: MmioRange,
    buffer: Vec<u8>,
    flush_ready: bool,
}

impl Default for Pl011 {
    fn default() -> Self {
        Self::new()
    }
}

impl Pl011 {
    pub fn new() -> Self {
        Self {
            range: MmioRange::new(UART, UART_SIZE).expect("PL011 MMIO range is valid"),
            buffer: Vec::new(),
            flush_ready: false,
        }
    }

    /// Takes buffered output when a newline or chunk boundary was reached.
    pub fn take_ready(&mut self) -> Option<Vec<u8>> {
        if !self.flush_ready {
            return None;
        }
        self.flush_ready = false;
        Some(core::mem::take(&mut self.buffer))
    }

    /// Drains any remaining partial line (used on VM shutdown).
    pub fn take_all(&mut self) -> Option<Vec<u8>> {
        self.flush_ready = false;
        if self.buffer.is_empty() {
            None
        } else {
            Some(core::mem::take(&mut self.buffer))
        }
    }
}

impl<Ctx> MmioDevice<Ctx> for Pl011 {
    type Error = Error;

    fn range(&self) -> MmioRange {
        self.range
    }

    fn access(&mut self, offset: u64, access: IoAccess, _ctx: &Ctx) -> Result<u64, Error> {
        let value = match (offset, access) {
            (0, IoAccess::Write(write)) => {
                let byte = write.value as u8;
                self.buffer.push(byte);
                if byte == b'\n' || self.buffer.len() >= TRANSFER_CHUNK_BYTES {
                    self.flush_ready = true;
                }
                0
            }
            (0x18, IoAccess::Read(_)) => 0x90, // TXFE | RXFE.
            (0xfe0, IoAccess::Read(_)) => 0x11,
            (0xfe4, IoAccess::Read(_)) => 0x10,
            (0xfe8, IoAccess::Read(_)) => 0x14,
            (0xfec, IoAccess::Read(_)) => 0,
            (0xff0, IoAccess::Read(_)) => 0x0d,
            (0xff4, IoAccess::Read(_)) => 0xf0,
            (0xff8, IoAccess::Read(_)) => 0x05,
            (0xffc, IoAccess::Read(_)) => 0xb1,
            _ => 0,
        };
        Ok(value)
    }
}
