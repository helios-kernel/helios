//! Streaming gzip and zstd decompression with incremental SHA-256 `diff_id` hashing.

use std::io::{self, Read};

use flate2::read::MultiGzDecoder;
use sha2::{Digest as Sha2Digest, Sha256};
use zrip_decode::streaming::FrameDecoder;

use crate::reference::Digest;
use crate::spec::LayerCompression;

/// Upper bound on uncompressed bytes yielded by a single zstd layer (2 GiB on 64-bit,
/// capped cleanly to `usize::MAX / 2` on 32-bit `wasm32-wasip3`).
const MAX_ZSTD_LAYER_BYTES: usize = {
    #[cfg(target_pointer_width = "32")]
    {
        1024 * 1024 * 1024 // 1 GiB
    }
    #[cfg(not(target_pointer_width = "32"))]
    {
        4 * 1024 * 1024 * 1024 // 4 GiB
    }
};

/// Streaming layer decoder over any `std::io::Read` source.
pub enum LayerDecoder<R: Read> {
    None(R),
    Gzip(Box<MultiGzDecoder<R>>),
    Zstd(Box<FrameDecoder<R>>),
}

impl<R: Read> LayerDecoder<R> {
    /// Wrap `reader` with the streaming decompressor matching `compression`.
    pub fn new(reader: R, compression: LayerCompression) -> Self {
        match compression {
            LayerCompression::None => Self::None(reader),
            LayerCompression::Gzip => Self::Gzip(Box::new(MultiGzDecoder::new(reader))),
            LayerCompression::Zstd => Self::Zstd(Box::new(FrameDecoder::with_limit(
                reader,
                MAX_ZSTD_LAYER_BYTES,
            ))),
        }
    }
}

impl<R: Read> Read for LayerDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::None(inner) => inner.read(buf),
            Self::Gzip(inner) => inner.read(buf),
            Self::Zstd(inner) => inner.read(buf),
        }
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
}
