//! Reusable encoders for one bounded Btrfs extent. The transaction owns each
//! encoder and its workspace; independent transactions never share mutable state.

use alloc::boxed::Box;
use alloc::vec::Vec;
use miniz_oxide::DataFormat;
use miniz_oxide::deflate::CompressionLevel;
use miniz_oxide::deflate::core::{CompressorOxide, TDEFLFlush, TDEFLStatus, compress_to_output};
use thiserror::Error;
use zrip_core::error::CompressError;
use zrip_encode::context::CompressContext;

use crate::Compression;

#[derive(Debug, Error)]
pub enum EncodeError {
    #[error("zlib encoding stopped with {status:?} after consuming {consumed} of {length} bytes")]
    Zlib {
        status: TDEFLStatus,
        consumed: usize,
        length: usize,
    },
    #[error("LZO encoding: {0}")]
    Lzo(#[from] lzokay::Error),
    #[error("zstd encoding: {0}")]
    Zstd(CompressError),
}

pub struct Encoded<'a> {
    pub bytes: &'a mut Vec<u8>,
    pub algorithm: Compression,
}

pub trait Encoder: Send {
    const ALGORITHM: Option<Compression>;
    /// None means that this encoding cannot save space for the supplied input.
    fn encode(&mut self, input: &[u8], sector: usize) -> Result<Option<Encoded<'_>>, EncodeError>;
}

impl<E: Encoder> Encoder for &mut E {
    const ALGORITHM: Option<Compression> = E::ALGORITHM;
    fn encode(&mut self, input: &[u8], sector: usize) -> Result<Option<Encoded<'_>>, EncodeError> {
        E::encode(self, input, sector)
    }
}

pub struct Plain;
impl Encoder for Plain {
    const ALGORITHM: Option<Compression> = None;
    fn encode(&mut self, _: &[u8], _: usize) -> Result<Option<Encoded<'_>>, EncodeError> {
        Ok(None)
    }
}

pub struct Zlib {
    state: Box<CompressorOxide>,
    output: Vec<u8>,
}

impl Zlib {
    pub fn new(level: CompressionLevel) -> Self {
        Self::at_level(level as u8)
    }

    /// A zlib encoder at deflate level `level`, 0 to 10, as Linux's
    /// `compress=zlib:<level>` selects.
    pub fn at_level(level: u8) -> Self {
        let mut state = Box::<CompressorOxide>::default();
        state.set_format_and_level(DataFormat::Zlib, level);
        Self {
            state,
            output: Vec::new(),
        }
    }
}

impl Encoder for Zlib {
    const ALGORITHM: Option<Compression> = Some(Compression::Zlib);
    fn encode(&mut self, input: &[u8], _: usize) -> Result<Option<Encoded<'_>>, EncodeError> {
        self.state.reset();
        self.output.clear();
        let (status, consumed) =
            compress_to_output(&mut self.state, input, TDEFLFlush::Finish, |bytes| {
                self.output.extend_from_slice(bytes);
                true
            });
        if status != TDEFLStatus::Done || consumed != input.len() {
            return Err(EncodeError::Zlib {
                status,
                consumed,
                length: input.len(),
            });
        }
        Ok(Some(Encoded {
            bytes: &mut self.output,
            algorithm: Compression::Zlib,
        }))
    }
}

pub struct Lzo {
    dictionary: Box<lzokay::compress::Dict>,
    segment: Vec<u8>,
    output: Vec<u8>,
}

impl Lzo {
    pub fn new() -> Self {
        Self {
            dictionary: lzokay::compress::Dict::new(),
            segment: Vec::new(),
            output: Vec::new(),
        }
    }
}

impl Default for Lzo {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder for Lzo {
    const ALGORITHM: Option<Compression> = Some(Compression::Lzo);
    fn encode(&mut self, input: &[u8], sector: usize) -> Result<Option<Encoded<'_>>, EncodeError> {
        // Btrfs LZO wraps each sector's stream in a little-endian u32 length.
        // The container starts with its total length, including these headers.
        const HEADER: usize = size_of::<u32>();
        self.output.clear();
        self.output.resize(HEADER, 0);
        self.segment
            .resize(lzokay::compress::compress_worst_size(sector), 0);
        for bytes in input.chunks(sector) {
            let remaining = sector - self.output.len() % sector;
            if remaining < HEADER {
                self.output.resize(self.output.len() + remaining, 0);
            }
            let length = lzokay::compress::compress_no_alloc(
                bytes,
                &mut self.segment,
                &mut self.dictionary,
            )?;
            self.output
                .extend_from_slice(&(length as u32).to_le_bytes());
            self.output.extend_from_slice(&self.segment[..length]);
        }
        let length = self.output.len() as u32;
        self.output[..HEADER].copy_from_slice(&length.to_le_bytes());
        Ok(Some(Encoded {
            bytes: &mut self.output,
            algorithm: Compression::Lzo,
        }))
    }
}

pub struct Zstd {
    context: CompressContext,
    output: Vec<u8>,
}

impl Zstd {
    pub fn new(level: i32) -> Result<Self, EncodeError> {
        let mut context = CompressContext::new(level).map_err(EncodeError::Zstd)?;
        // Btrfs checksums the complete encoded sectors in its checksum tree.
        context.set_content_checksum(false);
        Ok(Self {
            context,
            output: Vec::new(),
        })
    }
}

impl Encoder for Zstd {
    const ALGORITHM: Option<Compression> = Some(Compression::Zstd);
    fn encode(&mut self, input: &[u8], _: usize) -> Result<Option<Encoded<'_>>, EncodeError> {
        // A frame as large as its input cannot save a sector. Bound the output
        // to that size instead of allocating space for an expanded frame.
        self.output.resize(input.len(), 0);
        match self.context.compress_into(input, &mut self.output) {
            Ok(length) => self.output.truncate(length),
            Err(CompressError::OutputTooSmall) => return Ok(None),
            Err(error) => return Err(EncodeError::Zstd(error)),
        }
        Ok(Some(Encoded {
            bytes: &mut self.output,
            algorithm: Compression::Zstd,
        }))
    }
}
