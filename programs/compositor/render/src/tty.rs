//! Framed IPC wire protocol (`helios:console/tty`) between `/plugins/compositor`
//! and `/console-session`.
//!
//! Each message is encoded as a 4-byte little-endian length prefix followed by
//! a `postcard` payload, bounded by [`MAX_TTY_FRAME_BYTES`]. Both the compositor
//! and `/console-session` link this module so their framing cannot drift.

use std::vec::Vec;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// IPC channel name exported by `/plugins/compositor` and consumed by `/console-session`.
pub const CONSOLE_TTY_CHANNEL: &str = "console-tty";

/// Maximum encoded payload size of a single TTY IPC frame (64 KiB).
pub const MAX_TTY_FRAME_BYTES: usize = 64 * 1024;

/// Messages sent from `/plugins/compositor` to `/console-session`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TtyClientMsg {
    /// Initial handshake (and compositor-restart notification) announcing VT2 dimensions.
    Attach { columns: u16, rows: u16 },
    /// Raw UTF-8 / control keystrokes typed into VT2.
    Input(Vec<u8>),
    /// Terminal grid resize notification.
    Resize { columns: u16, rows: u16 },
}

/// Messages sent from `/console-session` to `/plugins/compositor`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TtyServerMsg {
    /// Reports whether the guest booted with `--console-shell` (direct VT2 shell)
    /// or standard login/VT1 boot flow.
    Mode { console_shell: bool },
    /// Clears VT2 terminal scrollback and resets the cursor to `(0, 0)`.
    ClearScreen,
    /// Raw UTF-8 / ANSI terminal output bytes to write into VT2.
    Output(Vec<u8>),
}

/// Why encoding or decoding a TTY IPC frame failed.
#[derive(Debug, Error)]
pub enum TtyFrameError {
    #[error("TTY frame length {len} exceeds maximum {MAX_TTY_FRAME_BYTES}")]
    FrameTooLarge { len: usize },
    #[error("failed to encode TTY frame: {0}")]
    Encode(#[from] postcard::Error),
    #[error("failed to decode TTY frame: {0}")]
    Decode(postcard::Error),
}

/// Encodes `message` as `len_le_u32 || postcard_bytes`.
pub fn encode_frame<T: Serialize>(message: &T) -> Result<Vec<u8>, TtyFrameError> {
    let payload = postcard::to_allocvec(message)?;
    if payload.len() > MAX_TTY_FRAME_BYTES {
        return Err(TtyFrameError::FrameTooLarge { len: payload.len() });
    }
    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Incremental stream decoder for length-prefixed `postcard` TTY IPC frames.
#[derive(Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    #[must_use]
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Appends raw bytes read from an `ipc::Endpoint` into the internal buffer.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Pops and decodes the next complete frame if all its bytes have arrived.
    pub fn next_frame<T: for<'de> Deserialize<'de>>(&mut self) -> Result<Option<T>, TtyFrameError> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_le_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len > MAX_TTY_FRAME_BYTES {
            self.buf.clear();
            return Err(TtyFrameError::FrameTooLarge { len });
        }
        let total = 4 + len;
        if self.buf.len() < total {
            return Ok(None);
        }
        let decoded = postcard::from_bytes(&self.buf[4..total]).map_err(TtyFrameError::Decode)?;
        self.buf.drain(..total);
        Ok(Some(decoded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_decoder_handles_split_and_coalesced_chunks() {
        let m1 = TtyClientMsg::Attach {
            columns: 120,
            rows: 40,
        };
        let m2 = TtyClientMsg::Input(b"echo hello\n".to_vec());
        let mut wire = encode_frame(&m1).expect("encode m1");
        wire.extend_from_slice(&encode_frame(&m2).expect("encode m2"));

        let mut decoder = FrameDecoder::new();
        let mut decoded = Vec::new();
        for chunk in wire.chunks(3) {
            decoder.push(chunk);
            while let Some(msg) = decoder
                .next_frame::<TtyClientMsg>()
                .expect("decode valid frame")
            {
                decoded.push(msg);
            }
        }
        assert_eq!(decoded, vec![m1, m2]);
    }

    #[test]
    fn frame_decoder_roundtrips_server_messages_and_rejects_oversized() {
        let msgs = vec![
            TtyServerMsg::Mode {
                console_shell: true,
            },
            TtyServerMsg::ClearScreen,
            TtyServerMsg::Output(b"helios$ ".to_vec()),
        ];
        let mut decoder = FrameDecoder::new();
        for msg in &msgs {
            decoder.push(&encode_frame(msg).expect("encode server msg"));
        }
        for expected in msgs {
            let actual: TtyServerMsg = decoder
                .next_frame()
                .expect("decode server msg")
                .expect("complete frame");
            assert_eq!(actual, expected);
        }

        let mut bad = FrameDecoder::new();
        let huge = (MAX_TTY_FRAME_BYTES as u32 + 1).to_le_bytes();
        bad.push(&huge);
        assert!(matches!(
            bad.next_frame::<TtyServerMsg>(),
            Err(TtyFrameError::FrameTooLarge { .. })
        ));
    }
}
