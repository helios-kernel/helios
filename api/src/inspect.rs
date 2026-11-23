//! Lock-free component and kernel state inspection (`helios:system/inspect`).
//!
//! Components publish structured telemetry in their own user memory pool via
//! [`InspectPublisher`], which holds a page-aligned [`Block`] together with its
//! kernel [`Publication`] resource so updates happen in place with zero system
//! calls under an even/odd 64-bit generation counter.

use core::sync::atomic::{AtomicU64, Ordering, fence};

use thiserror::Error;

use crate::bindings::helios::system::inspect as raw;
use crate::memory::{Backed, Block, BlockError, Span};

pub use crate::bindings::helios::system::filters::FilterError;
pub use crate::bindings::helios::system::inspect::{
    ComponentPublication, Entry, MonoNanos, Publication, PublicationStatus, PublishError, Query,
    SnapshotResult, Value,
};

/// Four-byte magic identifying an inspect buffer header (`b"HINS"`).
pub const HEADER_MAGIC: [u8; 4] = *b"HINS";

/// Current inspect span binary format version.
pub const FORMAT_VERSION: u16 = 1;

/// Byte length of the inspect span header.
pub const HEADER_BYTES: usize = 32;

/// Maximum span size accepted by `helios:system/inspect.publish` (256 KiB).
pub const MAX_SPAN_BYTES: usize = 256 * 1024;

/// Maximum entries encoded in one published component buffer.
pub const MAX_ENTRIES: usize = 1024;

/// Maximum byte length of a relative entry path.
pub const MAX_PATH_BYTES: usize = 256;

/// Maximum byte length of a text property value.
pub const MAX_TEXT_BYTES: usize = 1024;

/// Maximum byte length of a binary blob property value.
pub const MAX_BLOB_BYTES: usize = 4096;

const TAG_BOOLEAN: u8 = 0;
const TAG_SIGNED64: u8 = 1;
const TAG_UNSIGNED64: u8 = 2;
const TAG_FLOAT64: u8 = 3;
const TAG_TEXT: u8 = 4;
const TAG_BLOB: u8 = 5;

/// Registers `region` in the caller's unshared linear memory under
/// `/instances/<self>/<name>`.
pub fn publish(name: &str, region: Span) -> Result<Publication, PublishError> {
    raw::publish(name, region)
}

/// Queries inspect entries within the caller's `InspectReadCap` scope.
pub fn snapshot(query: &Query, limit: u32) -> Result<SnapshotResult, FilterError> {
    raw::snapshot(query, limit)
}

/// Convenience wrapper for [`snapshot`] taking borrowed prefix slices.
pub fn snapshot_prefixes(prefixes: &[&str], limit: u32) -> Result<SnapshotResult, FilterError> {
    let query = Query {
        prefixes: prefixes.iter().map(|p| (*p).to_owned()).collect(),
    };
    raw::snapshot(&query, limit)
}

/// Why creating an [`InspectPublisher`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum InspectPublisherError {
    #[error(transparent)]
    Block(#[from] BlockError),
    #[error("kernel refused inspect publication: {0:?}")]
    Publish(PublishError),
}

/// Why writing a snapshot generation into an [`InspectPublisher`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum InspectWriteError {
    #[error("inspect payload exceeds the published span capacity")]
    BufferFull,
    #[error("inspect entry count exceeds {MAX_ENTRIES}")]
    TooManyEntries,
    #[error("inspect relative path is invalid")]
    InvalidPath,
    #[error("inspect value exceeds the maximum byte length")]
    ValueTooLarge,
}

/// Owns a page-aligned linear-memory buffer and its kernel [`Publication`].
///
/// Updates mutate the buffer directly under an even/odd 64-bit generation
/// header with zero system calls. Dropping this value releases the kernel
/// publication before freeing the backing pages.
pub struct InspectPublisher {
    backed: Backed<Publication>,
    generation: u64,
}

impl InspectPublisher {
    /// Allocates a page-aligned buffer of at least `bytes` (rounded up to whole
    /// wasm pages, at most [`MAX_SPAN_BYTES`]), initializes its header, and
    /// registers it with the kernel under `name`.
    pub fn create(name: &str, bytes: u64) -> Result<Self, InspectPublisherError> {
        let mut block = Block::whole_pages(bytes)?;
        initialize_header(block.bytes_mut());
        let publication = publish(name, block.span()).map_err(InspectPublisherError::Publish)?;
        Ok(Self {
            backed: Backed::new(publication, block),
            generation: 0,
        })
    }

    /// Current even generation published in the buffer header.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Replaces the published tree in place with zero system calls.
    ///
    /// Transitions the generation counter to odd while writing, commits
    /// `payload_len` and `entry_count`, and advances the generation counter to
    /// the next even value. If `write` encounters an error, the buffer is
    /// restored to an empty valid payload before publishing the even generation
    /// so readers never observe torn state.
    pub fn update(
        &mut self,
        write: impl FnOnce(&mut InspectWriter<'_>),
    ) -> Result<u64, InspectWriteError> {
        let odd = self.generation.wrapping_add(1);
        let even = self.generation.wrapping_add(2);
        let bytes = self.backed.bytes_mut();
        store_generation(bytes, odd);
        fence(Ordering::Release);

        let mut writer = InspectWriter::new(&mut bytes[HEADER_BYTES..]);
        write(&mut writer);

        let result = match writer.finish() {
            Ok((payload_len, entry_count)) => {
                bytes[16..20].copy_from_slice(&(payload_len as u32).to_le_bytes());
                bytes[20..24].copy_from_slice(&(entry_count as u32).to_le_bytes());
                Ok(even)
            }
            Err(error) => {
                bytes[16..20].copy_from_slice(&0u32.to_le_bytes());
                bytes[20..24].copy_from_slice(&0u32.to_le_bytes());
                Err(error)
            }
        };

        fence(Ordering::Release);
        store_generation(bytes, even);
        self.generation = even;
        result
    }
}

/// Incremental binary encoder for one generation of an [`InspectPublisher`].
pub struct InspectWriter<'a> {
    buf: &'a mut [u8],
    cursor: usize,
    entries: usize,
    error: Option<InspectWriteError>,
}

impl<'a> InspectWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            cursor: 0,
            entries: 0,
            error: None,
        }
    }

    pub fn bool(&mut self, path: &str, value: bool) -> &mut Self {
        self.write_entry(path, TAG_BOOLEAN, &[u8::from(value)], None);
        self
    }

    pub fn i64(&mut self, path: &str, value: i64) -> &mut Self {
        self.write_entry(path, TAG_SIGNED64, &value.to_le_bytes(), None);
        self
    }

    pub fn u64(&mut self, path: &str, value: u64) -> &mut Self {
        self.write_entry(path, TAG_UNSIGNED64, &value.to_le_bytes(), None);
        self
    }

    pub fn f64(&mut self, path: &str, value: f64) -> &mut Self {
        self.write_entry(path, TAG_FLOAT64, &value.to_bits().to_le_bytes(), None);
        self
    }

    pub fn text(&mut self, path: &str, value: &str) -> &mut Self {
        if value.len() > MAX_TEXT_BYTES {
            self.fail(InspectWriteError::ValueTooLarge);
            return self;
        }
        let len = (value.len() as u32).to_le_bytes();
        self.write_entry(path, TAG_TEXT, &len, Some(value.as_bytes()));
        self
    }

    pub fn blob(&mut self, path: &str, value: &[u8]) -> &mut Self {
        if value.len() > MAX_BLOB_BYTES {
            self.fail(InspectWriteError::ValueTooLarge);
            return self;
        }
        let len = (value.len() as u32).to_le_bytes();
        self.write_entry(path, TAG_BLOB, &len, Some(value));
        self
    }

    fn fail(&mut self, error: InspectWriteError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    fn write_entry(&mut self, path: &str, tag: u8, head: &[u8], tail: Option<&[u8]>) {
        if self.error.is_some() {
            return;
        }
        if self.entries >= MAX_ENTRIES {
            self.fail(InspectWriteError::TooManyEntries);
            return;
        }
        if !is_valid_relative_path(path) {
            self.fail(InspectWriteError::InvalidPath);
            return;
        }
        let path_bytes = path.as_bytes();
        let tail_len = tail.map_or(0, <[u8]>::len);
        let needed = 4 + path_bytes.len() + head.len() + tail_len;
        if self
            .cursor
            .checked_add(needed)
            .is_none_or(|end| end > self.buf.len())
        {
            self.fail(InspectWriteError::BufferFull);
            return;
        }
        self.buf[self.cursor..self.cursor + 2]
            .copy_from_slice(&(path_bytes.len() as u16).to_le_bytes());
        self.buf[self.cursor + 2] = tag;
        self.buf[self.cursor + 3] = 0;
        self.cursor += 4;
        self.buf[self.cursor..self.cursor + path_bytes.len()].copy_from_slice(path_bytes);
        self.cursor += path_bytes.len();
        self.buf[self.cursor..self.cursor + head.len()].copy_from_slice(head);
        self.cursor += head.len();
        if let Some(tail) = tail {
            self.buf[self.cursor..self.cursor + tail.len()].copy_from_slice(tail);
            self.cursor += tail.len();
        }
        self.entries += 1;
    }

    fn finish(self) -> Result<(usize, usize), InspectWriteError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        Ok((self.cursor, self.entries))
    }
}

fn initialize_header(bytes: &mut [u8]) {
    bytes[0..4].copy_from_slice(&HEADER_MAGIC);
    bytes[4..6].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes[6..8].copy_from_slice(&0u16.to_le_bytes());
    bytes[8..16].copy_from_slice(&0u64.to_le_bytes());
    bytes[16..20].copy_from_slice(&0u32.to_le_bytes());
    bytes[20..24].copy_from_slice(&0u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0u64.to_le_bytes());
}

fn store_generation(bytes: &mut [u8], generation: u64) {
    let ptr = bytes.as_mut_ptr().wrapping_add(8).cast::<u64>();
    debug_assert!(ptr.is_aligned());
    // SAFETY: `bytes` comes from a page-aligned `Block` of at least 64 KiB, so
    // offset 8 is 8-byte aligned and uniquely owned during `update`.
    let atomic = unsafe { AtomicU64::from_ptr(ptr) };
    atomic.store(generation, Ordering::Release);
}

fn is_valid_relative_path(path: &str) -> bool {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || path.starts_with('/')
        || path.ends_with('/')
    {
        return false;
    }
    for segment in path.split('/') {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.bytes().any(|b| b < 0x20 || b == 0x7f)
        {
            return false;
        }
    }
    true
}
