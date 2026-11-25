//! Streaming gzip and zstd decompression with incremental SHA-256 `diff_id` hashing.

use std::io::{self, Read};

use flate2::read::MultiGzDecoder;
use sha2::{Digest as Sha2Digest, Sha256};
use zrip_decode::streaming::FrameDecoder;

use crate::reference::Digest;
use crate::spec::LayerCompression;

/// Upper bound on uncompressed bytes yielded by a single layer (4 GiB on 64-bit,
/// capped to 1 GiB on 32-bit `wasm32-wasip3`).
pub const MAX_LAYER_BYTES: usize = {
    #[cfg(target_pointer_width = "32")]
    {
        1024 * 1024 * 1024 // 1 GiB
    }
    #[cfg(not(target_pointer_width = "32"))]
    {
        4 * 1024 * 1024 * 1024 // 4 GiB
    }
};

/// Typed error attached to [`io::Error`] when a layer stream exceeds its uncompressed byte limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("uncompressed layer exceeds maximum size of {limit} bytes")]
pub struct LayerSizeLimitError {
    pub limit: u64,
}

enum LayerDecoderInner<R: Read> {
    None(R),
    Gzip(Box<MultiGzDecoder<R>>),
    Zstd(Box<FrameDecoder<R>>),
}

/// Streaming layer decoder over any `std::io::Read` source, bounded by [`MAX_LAYER_BYTES`].
pub struct LayerDecoder<R: Read> {
    inner: LayerDecoderInner<R>,
    bytes_read: u64,
    max_bytes: u64,
}

impl<R: Read> LayerDecoder<R> {
    /// Wrap `reader` with the streaming decompressor matching `compression`, bounded by [`MAX_LAYER_BYTES`].
    pub fn new(reader: R, compression: LayerCompression) -> Self {
        Self::with_limit(reader, compression, MAX_LAYER_BYTES)
    }

    /// Wrap `reader` with the streaming decompressor matching `compression`, enforcing an explicit
    /// `max_bytes` uncompressed output limit across all compression formats.
    pub fn with_limit(reader: R, compression: LayerCompression, max_bytes: usize) -> Self {
        let inner = match compression {
            LayerCompression::None => LayerDecoderInner::None(reader),
            LayerCompression::Gzip => {
                LayerDecoderInner::Gzip(Box::new(MultiGzDecoder::new(reader)))
            }
            LayerCompression::Zstd => {
                LayerDecoderInner::Zstd(Box::new(FrameDecoder::with_limit(reader, max_bytes)))
            }
        };
        Self {
            inner,
            bytes_read: 0,
            max_bytes: max_bytes as u64,
        }
    }

    fn read_inner(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.inner {
            LayerDecoderInner::None(inner) => inner.read(buf),
            LayerDecoderInner::Gzip(inner) => inner.read(buf),
            LayerDecoderInner::Zstd(inner) => inner.read(buf),
        }
    }
}

impl<R: Read> Read for LayerDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let remaining = self.max_bytes.saturating_sub(self.bytes_read);
        if remaining == 0 {
            let mut probe = [0u8; 1];
            let n = self.read_inner(&mut probe)?;
            if n == 0 {
                return Ok(0);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                LayerSizeLimitError {
                    limit: self.max_bytes,
                },
            ));
        }

        let max_read = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .saturating_add(1);
        let cap = buf.len().min(max_read);
        let n = self.read_inner(&mut buf[..cap])?;
        if n as u64 > remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                LayerSizeLimitError {
                    limit: self.max_bytes,
                },
            ));
        }
        self.bytes_read += n as u64;
        Ok(n)
    }
}

/// Pass-through [`Read`] wrapper that computes a streaming SHA-256 digest and byte count
/// of every byte read (used to verify OCI `rootfs.diff_ids`).
pub struct HashingReader<R: Read> {
    inner: R,
    hasher: Sha256,
    bytes_read: u64,
}

impl<R: Read> HashingReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes_read: 0,
        }
    }

    /// Consume any remaining trailing bytes (such as tar end-of-archive zero padding)
    /// so the SHA-256 matches the complete uncompressed layer tar stream.
    pub fn drain_to_eof(&mut self) -> io::Result<u64> {
        let mut scratch = [0u8; 16 * 1024];
        loop {
            let n = self.read(&mut scratch)?;
            if n == 0 {
                return Ok(self.bytes_read);
            }
        }
    }

    /// Finalize the SHA-256 digest and return `(digest, total_bytes)`.
    #[must_use]
    pub fn finalize(self) -> (Digest, u64) {
        let digest = Digest::from_sha256_bytes(self.hasher.finalize().into());
        (digest, self.bytes_read)
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.hasher.update(&buf[..n]);
            self.bytes_read = self.bytes_read.saturating_add(n as u64);
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write as _;

    #[test]
    fn streams_gzip_and_zstd_and_computes_exact_diff_id() {
        let payload = b"helios oci layer \xe4\xb8\xad\xe6\x96\x87 \xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e \xed\x95\x9c\xea\xb5\xad\xec\x96\xb4\n"
            .repeat(512);
        let expected_digest = Digest::sha256(&payload);

        // Gzip
        let mut gz_encoder = GzEncoder::new(Vec::new(), Compression::default());
        gz_encoder.write_all(&payload).unwrap();
        let gz_bytes = gz_encoder.finish().unwrap();

        let mut gz_reader = HashingReader::new(LayerDecoder::new(
            io::Cursor::new(&gz_bytes),
            LayerCompression::Gzip,
        ));
        let mut gz_out = Vec::new();
        gz_reader.read_to_end(&mut gz_out).unwrap();
        let (gz_diff_id, gz_len) = gz_reader.finalize();
        assert_eq!(gz_out, payload);
        assert_eq!(gz_len, payload.len() as u64);
        assert_eq!(gz_diff_id, expected_digest);

        // Zstd (using zrip-encode)
        let zst_bytes = zrip_encode::compress(&payload, 1).unwrap();
        let mut zst_reader = HashingReader::new(LayerDecoder::new(
            io::Cursor::new(&zst_bytes),
            LayerCompression::Zstd,
        ));
        let mut zst_out = Vec::new();
        zst_reader.read_to_end(&mut zst_out).unwrap();
        let (zst_diff_id, zst_len) = zst_reader.finalize();
        assert_eq!(zst_out, payload);
        assert_eq!(zst_len, payload.len() as u64);
        assert_eq!(zst_diff_id, expected_digest);
    }

    #[test]
    fn enforces_byte_limit_across_none_gzip_and_zstd() {
        let limit = 4096;
        let exact = vec![0x5Au8; limit];
        let over = vec![0x5Au8; limit + 1];

        let mut gz_exact_enc = GzEncoder::new(Vec::new(), Compression::default());
        gz_exact_enc.write_all(&exact).unwrap();
        let gz_exact = gz_exact_enc.finish().unwrap();

        let mut gz_bomb_enc = GzEncoder::new(Vec::new(), Compression::default());
        gz_bomb_enc.write_all(&vec![0u8; 256 * 1024]).unwrap();
        let gz_bomb = gz_bomb_enc.finish().unwrap();

        let zst_exact = zrip_encode::compress(&exact, 1).unwrap();
        let zst_over = zrip_encode::compress(&over, 1).unwrap();

        for (compression, exact_bytes, over_bytes) in [
            (LayerCompression::None, exact.as_slice(), over.as_slice()),
            (
                LayerCompression::Gzip,
                gz_exact.as_slice(),
                gz_bomb.as_slice(),
            ),
            (
                LayerCompression::Zstd,
                zst_exact.as_slice(),
                zst_over.as_slice(),
            ),
        ] {
            let mut ok_out = Vec::new();
            LayerDecoder::with_limit(io::Cursor::new(exact_bytes), compression, limit)
                .read_to_end(&mut ok_out)
                .expect("exact limit payload should succeed");
            assert_eq!(ok_out.len(), limit);

            let mut too_big = Vec::new();
            let err = LayerDecoder::with_limit(io::Cursor::new(over_bytes), compression, limit)
                .read_to_end(&mut too_big)
                .expect_err("oversized payload must be cut off");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }
    }
}
