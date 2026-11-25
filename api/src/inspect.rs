//! Lock-free component and kernel state inspection (`helios:system/inspect`).
//!
//! Components that publish structured telemetry into their own user memory pool
//! enable the `inspect-publish` Cargo feature and build with
//! `-C target-feature=+atomics` (`[package.metadata.helios] target-features = ["atomics"]`)
//! so [`InspectPublisher`] emits real atomic seqlock stores and hardware
//! release fences on weakly-ordered SMP targets. Reading snapshots via
//! [`snapshot`] / [`snapshot_prefixes`] works on any component build with the
//! `inspect` feature.

use crate::bindings::helios::system::inspect as raw;

pub use crate::bindings::helios::system::filters::FilterError;
pub use crate::bindings::helios::system::inspect::{
    ComponentPublication, Entry, MonoNanos, Publication, PublicationStatus, PublishError, Query,
    SnapshotResult, Value,
};
pub use crate::bindings::helios::system::memory::Span;

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

/// Registers `region` in the caller's unshared linear memory under
/// `/instances/<self>/<name>`.
///
/// Writers mutating the published buffer must use atomic stores and release
/// fences compiled with `-C target-feature=+atomics`; prefer
/// [`InspectPublisher`] (feature `inspect-publish`), which enforces that build
/// requirement at compile time.
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

#[cfg(feature = "inspect-publish")]
mod publisher {
    #[cfg(all(target_arch = "wasm32", not(target_feature = "atomics")))]
    compile_error!(
        "helios-api feature `inspect-publish` requires -Ctarget-feature=+atomics \
         (set `[package.metadata.helios] target-features = [\"atomics\"]`)"
    );

    use core::sync::atomic::{AtomicU64, Ordering, fence};

    use thiserror::Error;

    use super::{
        FORMAT_VERSION, HEADER_BYTES, HEADER_MAGIC, MAX_BLOB_BYTES, MAX_ENTRIES, MAX_PATH_BYTES,
        MAX_TEXT_BYTES, Publication, PublishError, publish,
    };
    use crate::memory::{Backed, Block, BlockError};

    const TAG_BOOLEAN: u8 = 0;
    const TAG_SIGNED64: u8 = 1;
    const TAG_UNSIGNED64: u8 = 2;
    const TAG_FLOAT64: u8 = 3;
    const TAG_TEXT: u8 = 4;
    const TAG_BLOB: u8 = 5;

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
        /// wasm pages, at most [`super::MAX_SPAN_BYTES`]), initializes its header, and
        /// registers it with the kernel under `name`.
        pub fn create(name: &str, bytes: u64) -> Result<Self, InspectPublisherError> {
            let mut block = Block::whole_pages(bytes)?;
            initialize_header(block.bytes_mut());
            let publication =
                publish(name, block.span()).map_err(InspectPublisherError::Publish)?;
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
        let ptr = bytes[8..16].as_mut_ptr().cast::<u64>();
        debug_assert!(ptr.is_aligned());
        // SAFETY: `bytes` comes from a page-aligned `Block` of at least 64 KiB
        // (or an 8-byte-aligned test buffer), so `bytes[8..16]` is 8 initialized
        // bytes at an 8-byte-aligned address and uniquely borrowed during `update`.
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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn writer_encodes_valid_header_and_entries() {
            let mut words = [0u64; 64];
            let ptr = words.as_mut_ptr().cast::<u8>();
            let len = words.len() * 8;
            // SAFETY: `words` is 64 initialized `u64` values (`len` contiguous
            // bytes) uniquely borrowed for the lifetime of `bytes`.
            let bytes = unsafe { core::slice::from_raw_parts_mut(ptr, len) };
            initialize_header(bytes);
            assert_eq!(&bytes[0..4], &HEADER_MAGIC);
            assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), FORMAT_VERSION);

            let mut writer = InspectWriter::new(&mut bytes[HEADER_BYTES..]);
            writer
                .u64("requests/total", 42)
                .bool("ready", true)
                .text("mode", "fast");
            let (payload_len, entries) = writer.finish().unwrap();
            assert_eq!(entries, 3);
            assert!(payload_len > 0);

            store_generation(bytes, 2);
            assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 2);
        }
    }
}

#[cfg(feature = "inspect-publish")]
pub use publisher::{InspectPublisher, InspectPublisherError, InspectWriteError, InspectWriter};
