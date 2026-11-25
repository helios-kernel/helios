//! Lock-free binary wire format and atomic seqlock reader for component
//! inspect spans.
//!
//! A component allocates a bounded span of whole pages in its own unshared
//! linear memory and writes structured `(relative_path, value)` records behind
//! a 32-byte header containing an even/odd 64-bit generation counter:
//!
//! - Offset `0..4`:   magic `b"HINS"` (`0x534E4948` LE)
//! - Offset `4..6`:   version `1` (`u16` LE)
//! - Offset `6..8`:   flags `0` (`u16` LE)
//! - Offset `8..16`:  even/odd generation counter (`u64` LE); odd while writing
//! - Offset `16..20`: payload length in bytes (`u32` LE)
//! - Offset `20..24`: entry count (`u32` LE, at most [`MAX_COMPONENT_ENTRIES`])
//! - Offset `24..32`: reserved `0` (`u64` LE)
//!
//! # Concurrency contract
//!
//! The reader never manufactures a Rust `&[u8]` slice over guest memory that a
//! guest processor may concurrently mutate. Every byte is copied through
//! naturally aligned 64-bit [`AtomicU64::load`] calls with [`Ordering::Acquire`]
//! ordering, bracketed by generation checks and bounded to
//! [`MAX_SEQLOCK_RETRIES`] attempts so an active or adversarial writer never
//! stalls a reader.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering, fence};

use thiserror::Error;

use super::InspectValue;

/// Four-byte magic identifying a Helios inspect span header (`b"HINS"`).
pub const INSPECT_HEADER_MAGIC: [u8; 4] = *b"HINS";

/// Current binary format version.
pub const INSPECT_FORMAT_VERSION: u16 = 1;

/// Fixed byte length of the inspect span header (four 8-byte words).
pub const INSPECT_HEADER_BYTES: usize = 32;

/// Maximum span length one component publication may register (256 KiB = 4
/// linear-memory pages).
pub const MAX_INSPECT_SPAN_BYTES: usize = 256 * 1024;

/// Maximum byte length of a publication name segment.
pub const MAX_PUBLICATION_NAME_BYTES: usize = 64;

/// Maximum simultaneous inspect publications one instance may hold.
pub const MAX_PUBLICATIONS_PER_INSTANCE: usize = 4;

/// Maximum entries decoded from a single component publication.
pub const MAX_COMPONENT_ENTRIES: usize = 1024;

/// Maximum byte length of one entry's relative path inside a component tree.
pub const MAX_RELATIVE_PATH_BYTES: usize = 256;

/// Maximum byte length of a single text property value.
pub const MAX_TEXT_VALUE_BYTES: usize = 1024;

/// Maximum byte length of a single binary blob property value.
pub const MAX_BLOB_VALUE_BYTES: usize = 4096;

/// Maximum lock-free read attempts before classifying a contended publication
/// as busy and moving on without stalling the reader.
pub const MAX_SEQLOCK_RETRIES: usize = 4;

/// Default entry ceiling when a snapshot caller passes `limit == 0`.
pub const DEFAULT_INSPECT_LIMIT: usize = 4096;

/// Hard upper bound on entries returned by one inspect snapshot call.
pub const MAX_INSPECT_LIMIT: usize = 16_384;

const VALUE_TAG_BOOLEAN: u8 = 0;
const VALUE_TAG_SIGNED64: u8 = 1;
const VALUE_TAG_UNSIGNED64: u8 = 2;
const VALUE_TAG_FLOAT64: u8 = 3;
const VALUE_TAG_TEXT: u8 = 4;
const VALUE_TAG_BLOB: u8 = 5;

/// Validated outcome of one bounded lock-free read of a component inspect span.
#[derive(Debug)]
pub(crate) enum SpanReadOutcome {
    Ok {
        generation: u64,
        entries: Vec<(String, InspectValue)>,
    },
    Busy {
        generation: u64,
    },
    Corrupt {
        generation: u64,
    },
}

/// Validates a component publication name (one path segment under
/// `/instances/<id>/<name>`).
pub fn is_valid_publication_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_PUBLICATION_NAME_BYTES || name == "." || name == ".." {
        return false;
    }
    name.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Validates a relative slash-delimited property path inside a component's
/// inspect buffer.
pub fn is_valid_relative_path(path: &str) -> bool {
    if path.is_empty() || path.len() > MAX_RELATIVE_PATH_BYTES {
        return false;
    }
    if path.starts_with('/') || path.ends_with('/') {
        return false;
    }
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return false;
        }
        if segment.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return false;
        }
    }
    true
}

#[derive(Clone, Copy)]
struct ParsedHeader {
    generation: u64,
    payload_len: usize,
    entry_count: usize,
}

fn load_aligned_word(base: usize, word_index: usize) -> u64 {
    let address = base + word_index * 8;
    let ptr = core::ptr::with_exposed_provenance_mut(address);
    // SAFETY: Caller verified `base` is 8-byte aligned, mapped, resident, and
    // covers `word_index * 8 + 8` bytes for the duration of this copy. Using
    // `AtomicU64::load` avoids forming non-atomic Rust references over memory
    // that another processor may concurrently write.
    let cell = unsafe { AtomicU64::from_ptr(ptr) };
    cell.load(Ordering::Acquire)
}

fn parse_header_words(w0: u64, w1: u64, w2: u64, w3: u64, span_len: usize) -> Option<ParsedHeader> {
    let b0 = w0.to_le_bytes();
    if b0[0..4] != INSPECT_HEADER_MAGIC {
        return None;
    }
    let version = u16::from_le_bytes([b0[4], b0[5]]);
    let flags = u16::from_le_bytes([b0[6], b0[7]]);
    if version != INSPECT_FORMAT_VERSION || flags != 0 || w3 != 0 {
        return None;
    }
    let b2 = w2.to_le_bytes();
    let payload_len = u32::from_le_bytes([b2[0], b2[1], b2[2], b2[3]]) as usize;
    let entry_count = u32::from_le_bytes([b2[4], b2[5], b2[6], b2[7]]) as usize;
    if entry_count > MAX_COMPONENT_ENTRIES {
        return None;
    }
    let max_payload = span_len
        .min(MAX_INSPECT_SPAN_BYTES)
        .checked_sub(INSPECT_HEADER_BYTES)?;
    if payload_len > max_payload {
        return None;
    }
    Some(ParsedHeader {
        generation: w1,
        payload_len,
        entry_count,
    })
}

/// Performs a bounded, non-blocking lock-free read of a component inspect span
/// starting at host virtual address `base` of byte length `span_len`.
///
/// # Safety
///
/// `base..base + span_len` must remain mapped and resident for the entire
/// duration of this call (enforced by holding the publication's read lock and
/// the owning instance's swap read-pin after verifying residency).
pub(crate) unsafe fn read_span_snapshot(base: usize, span_len: usize) -> SpanReadOutcome {
    let span_len = span_len.min(MAX_INSPECT_SPAN_BYTES);
    if !base.is_multiple_of(8)
        || !span_len.is_multiple_of(8)
        || span_len < INSPECT_HEADER_BYTES
        || base.checked_add(span_len).is_none()
    {
        return SpanReadOutcome::Corrupt { generation: 0 };
    }
    let mut last_generation = 0u64;

    for _ in 0..MAX_SEQLOCK_RETRIES {
        let gen_before = load_aligned_word(base, 1);
        last_generation = gen_before;
        if gen_before & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }
        fence(Ordering::Acquire);

        let w0 = load_aligned_word(base, 0);
        let w2 = load_aligned_word(base, 2);
        let w3 = load_aligned_word(base, 3);
        let Some(header) = parse_header_words(w0, gen_before, w2, w3, span_len) else {
            fence(Ordering::Acquire);
            let gen_after = load_aligned_word(base, 1);
            last_generation = gen_after;
            if gen_after != gen_before {
                continue;
            }
            return SpanReadOutcome::Corrupt {
                generation: gen_before,
            };
        };

        let mut payload = vec![0u8; header.payload_len];
        let full_words = header.payload_len / 8;
        for index in 0..full_words {
            let word = load_aligned_word(base, 4 + index);
            let start = index * 8;
            payload[start..start + 8].copy_from_slice(&word.to_le_bytes());
        }
        let remainder = header.payload_len % 8;
        if remainder != 0 {
            let word = load_aligned_word(base, 4 + full_words);
            let bytes = word.to_le_bytes();
            let start = full_words * 8;
            payload[start..start + remainder].copy_from_slice(&bytes[..remainder]);
        }

        fence(Ordering::Acquire);
        let gen_after = load_aligned_word(base, 1);
        last_generation = gen_after;
        if gen_after != gen_before {
            continue;
        }

        return match decode_payload(&payload, header.entry_count) {
            Some(entries) => SpanReadOutcome::Ok {
                generation: header.generation,
                entries,
            },
            None => SpanReadOutcome::Corrupt {
                generation: header.generation,
            },
        };
    }

    SpanReadOutcome::Busy {
        generation: last_generation,
    }
}

fn take<'a>(slice: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    if slice.len() < len {
        return None;
    }
    let (head, tail) = slice.split_at(len);
    *slice = tail;
    Some(head)
}

fn take_u8(slice: &mut &[u8]) -> Option<u8> {
    Some(take(slice, 1)?[0])
}

fn take_u16(slice: &mut &[u8]) -> Option<u16> {
    let bytes: [u8; 2] = take(slice, 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn take_u32(slice: &mut &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = take(slice, 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn take_u64(slice: &mut &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = take(slice, 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn decode_payload(mut bytes: &[u8], entry_count: usize) -> Option<Vec<(String, InspectValue)>> {
    let mut entries = Vec::with_capacity(entry_count.min(64));
    for _ in 0..entry_count {
        let path_len = usize::from(take_u16(&mut bytes)?);
        let tag = take_u8(&mut bytes)?;
        let reserved = take_u8(&mut bytes)?;
        if reserved != 0 || path_len == 0 || path_len > MAX_RELATIVE_PATH_BYTES {
            return None;
        }
        let path_bytes = take(&mut bytes, path_len)?;
        let path = core::str::from_utf8(path_bytes).ok()?;
        if !is_valid_relative_path(path) {
            return None;
        }
        let value = match tag {
            VALUE_TAG_BOOLEAN => match take_u8(&mut bytes)? {
                0 => InspectValue::Boolean(false),
                1 => InspectValue::Boolean(true),
                _ => return None,
            },
            VALUE_TAG_SIGNED64 => {
                InspectValue::Signed64(i64::from_le_bytes(take(&mut bytes, 8)?.try_into().ok()?))
            }
            VALUE_TAG_UNSIGNED64 => InspectValue::Unsigned64(take_u64(&mut bytes)?),
            VALUE_TAG_FLOAT64 => InspectValue::Float64(f64::from_bits(take_u64(&mut bytes)?)),
            VALUE_TAG_TEXT => {
                let len = take_u32(&mut bytes)? as usize;
                if len > MAX_TEXT_VALUE_BYTES {
                    return None;
                }
                let raw = take(&mut bytes, len)?;
                let text = core::str::from_utf8(raw).ok()?;
                InspectValue::Text(String::from(text))
            }
            VALUE_TAG_BLOB => {
                let len = take_u32(&mut bytes)? as usize;
                if len > MAX_BLOB_VALUE_BYTES {
                    return None;
                }
                let raw = take(&mut bytes, len)?;
                InspectValue::Blob(raw.to_vec())
            }
            _ => return None,
        };
        entries.push((String::from(path), value));
    }
    if !bytes.is_empty() {
        return None;
    }
    Some(entries)
}

/// Why encoding an inspect buffer failed (used by tests and in-kernel writers).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum BufferEncodeError {
    #[error("destination buffer is too small for header and payload")]
    BufferTooSmall,
    #[error("entry count exceeds {MAX_COMPONENT_ENTRIES}")]
    TooManyEntries,
    #[error("entry relative path is invalid")]
    InvalidPath,
    #[error("property value exceeds maximum byte length")]
    ValueTooLarge,
}

/// Encodes `entries` with `generation` into `dst` using the inspect wire format.
#[cfg(test)]
pub fn encode_buffer(
    generation: u64,
    entries: &[(&str, InspectValue)],
    dst: &mut [u8],
) -> Result<usize, BufferEncodeError> {
    if dst.len() < INSPECT_HEADER_BYTES {
        return Err(BufferEncodeError::BufferTooSmall);
    }
    if entries.len() > MAX_COMPONENT_ENTRIES {
        return Err(BufferEncodeError::TooManyEntries);
    }
    let mut cursor = INSPECT_HEADER_BYTES;
    for (path, value) in entries {
        if !is_valid_relative_path(path) {
            return Err(BufferEncodeError::InvalidPath);
        }
        let path_bytes = path.as_bytes();
        let (tag, value_len) = match value {
            InspectValue::Boolean(_) => (VALUE_TAG_BOOLEAN, 1usize),
            InspectValue::Signed64(_) => (VALUE_TAG_SIGNED64, 8),
            InspectValue::Unsigned64(_) => (VALUE_TAG_UNSIGNED64, 8),
            InspectValue::Float64(_) => (VALUE_TAG_FLOAT64, 8),
            InspectValue::Text(text) => {
                if text.len() > MAX_TEXT_VALUE_BYTES {
                    return Err(BufferEncodeError::ValueTooLarge);
                }
                (VALUE_TAG_TEXT, 4 + text.len())
            }
            InspectValue::Blob(blob) => {
                if blob.len() > MAX_BLOB_VALUE_BYTES {
                    return Err(BufferEncodeError::ValueTooLarge);
                }
                (VALUE_TAG_BLOB, 4 + blob.len())
            }
        };
        let record_len = 4 + path_bytes.len() + value_len;
        if cursor
            .checked_add(record_len)
            .is_none_or(|end| end > dst.len())
        {
            return Err(BufferEncodeError::BufferTooSmall);
        }
        dst[cursor..cursor + 2].copy_from_slice(&(path_bytes.len() as u16).to_le_bytes());
        dst[cursor + 2] = tag;
        dst[cursor + 3] = 0;
        cursor += 4;
        dst[cursor..cursor + path_bytes.len()].copy_from_slice(path_bytes);
        cursor += path_bytes.len();
        match value {
            InspectValue::Boolean(flag) => {
                dst[cursor] = u8::from(*flag);
                cursor += 1;
            }
            InspectValue::Signed64(v) => {
                dst[cursor..cursor + 8].copy_from_slice(&v.to_le_bytes());
                cursor += 8;
            }
            InspectValue::Unsigned64(v) => {
                dst[cursor..cursor + 8].copy_from_slice(&v.to_le_bytes());
                cursor += 8;
            }
            InspectValue::Float64(v) => {
                dst[cursor..cursor + 8].copy_from_slice(&v.to_bits().to_le_bytes());
                cursor += 8;
            }
            InspectValue::Text(text) => {
                dst[cursor..cursor + 4].copy_from_slice(&(text.len() as u32).to_le_bytes());
                cursor += 4;
                dst[cursor..cursor + text.len()].copy_from_slice(text.as_bytes());
                cursor += text.len();
            }
            InspectValue::Blob(blob) => {
                dst[cursor..cursor + 4].copy_from_slice(&(blob.len() as u32).to_le_bytes());
                cursor += 4;
                dst[cursor..cursor + blob.len()].copy_from_slice(blob);
                cursor += blob.len();
            }
        }
    }
    let payload_len = (cursor - INSPECT_HEADER_BYTES) as u32;
    let entry_count = entries.len() as u32;
    dst[0..4].copy_from_slice(&INSPECT_HEADER_MAGIC);
    dst[4..6].copy_from_slice(&INSPECT_FORMAT_VERSION.to_le_bytes());
    dst[6..8].copy_from_slice(&0u16.to_le_bytes());
    dst[8..16].copy_from_slice(&generation.to_le_bytes());
    dst[16..20].copy_from_slice(&payload_len.to_le_bytes());
    dst[20..24].copy_from_slice(&entry_count.to_le_bytes());
    dst[24..32].copy_from_slice(&0u64.to_le_bytes());
    Ok(cursor)
}
