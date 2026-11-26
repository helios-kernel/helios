//! Authenticated verification and bounded decompression of hibernate images.
//!
//! Decoding strictly enforces the security ordering:
//! 1. Header length, magic, and format version (zero allocations).
//! 2. Constant-time HMAC-SHA256 over the header (zero allocations).
//! 3. Arithmetic bounds and machine frame-ceiling checks (zero allocations).
//! 4. Individual verification of every [`HibernateIdentity`] field.
//! 5. Chunk table SHA-256 verification against the authenticated header.
//! 6. Per-chunk descriptor validation and compressed payload SHA-256
//!    verification **before** bounded `zrip` decompression.

use alloc::vec::Vec;

use sha2::{Digest, Sha256};
use zrip::DecompressContext;

use super::HibernateError;
use super::format::{
    CHUNK_DESCRIPTOR_BYTES, ChunkDescriptor, HEADER_BYTES, HibernateHeader, HibernateIdentity,
    MAX_CHUNKS,
};
use crate::HibernateAuthKey;

/// Parsed and authenticated header plus verified chunk descriptor table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedHibernateImage {
    pub header: HibernateHeader,
    pub chunks: Vec<ChunkDescriptor>,
}

/// Verifies every field of `image_identity` against `expected`, returning a
/// distinct typed [`HibernateError`] variant for each mismatch.
pub fn verify_identity(
    image_identity: &HibernateIdentity,
    header_identity_digest: &[u8; 32],
    expected: &HibernateIdentity,
) -> Result<(), HibernateError> {
    if !constant_time_eq_32(&image_identity.digest(), header_identity_digest) {
        return Err(HibernateError::IdentityDigestMismatch);
    }
    // Physical load addresses of `.text`, `.rodata`, and `boot_payload` are
    // allowed to shift between UEFI boots; virtual addresses, lengths, and
    // SHA-256 digests must match identically, and the resume loader relocates
    // the immutable bytes into the image's expected physical addresses.
    if image_identity.kernel_text_virt_start != expected.kernel_text_virt_start
        || image_identity.kernel_text_len != expected.kernel_text_len
        || !constant_time_eq_32(
            &image_identity.kernel_text_sha256,
            &expected.kernel_text_sha256,
        )
    {
        return Err(HibernateError::KernelTextMismatch);
    }
    if image_identity.kernel_rodata_virt_start != expected.kernel_rodata_virt_start
        || image_identity.kernel_rodata_len != expected.kernel_rodata_len
        || !constant_time_eq_32(
            &image_identity.kernel_rodata_sha256,
            &expected.kernel_rodata_sha256,
        )
    {
        return Err(HibernateError::KernelRodataMismatch);
    }
    if !constant_time_eq_32(
        &image_identity.boot_payload_sha256,
        &expected.boot_payload_sha256,
    ) {
        return Err(HibernateError::BootPayloadDigestMismatch);
    }
    if image_identity.boot_payload_len != expected.boot_payload_len {
        return Err(HibernateError::BootPayloadAddressMismatch);
    }
    if image_identity.firmware_memory_map_count != expected.firmware_memory_map_count
        || !constant_time_eq_32(
            &image_identity.firmware_memory_map_sha256,
            &expected.firmware_memory_map_sha256,
        )
    {
        return Err(HibernateError::FirmwareMemoryMapMismatch);
    }
    if image_identity.processor_count != expected.processor_count {
        return Err(HibernateError::ProcessorCountMismatch {
            image: image_identity.processor_count,
            machine: expected.processor_count,
        });
    }
    if !constant_time_eq_32(
        &image_identity.device_inventory_sha256,
        &expected.device_inventory_sha256,
    ) {
        return Err(HibernateError::DeviceInventoryMismatch);
    }
    if !constant_time_eq_32(
        &image_identity.negotiated_features_sha256,
        &expected.negotiated_features_sha256,
    ) {
        return Err(HibernateError::NegotiatedFeaturesMismatch);
    }
    Ok(())
}

/// Validates overflow-safe header bounds and layout offsets against
/// `backing_bytes` (image slice length or disk capacity) and
/// `machine_max_frames` without performing any heap allocation.
pub(crate) fn validate_header_bounds(
    header: &HibernateHeader,
    backing_bytes: u64,
    machine_max_frames: u64,
) -> Result<u64, HibernateError> {
    if header.total_frames > machine_max_frames || header.total_frames > header.machine_max_frames {
        return Err(HibernateError::FrameCountExceedsMachine {
            image_frames: header.total_frames,
            machine_frames: machine_max_frames.min(header.machine_max_frames),
        });
    }
    if header.chunk_count > MAX_CHUNKS {
        return Err(HibernateError::InvalidLayout {
            reason: "chunk_count exceeds MAX_CHUNKS",
        });
    }
    let expected_table_len = u64::from(header.chunk_count)
        .checked_mul(CHUNK_DESCRIPTOR_BYTES as u64)
        .ok_or(HibernateError::InvalidLayout {
            reason: "chunk table byte length overflow",
        })?;
    if header.chunk_table_len != expected_table_len {
        return Err(HibernateError::InvalidLayout {
            reason: "chunk_table_len does not equal chunk_count * CHUNK_DESCRIPTOR_BYTES",
        });
    }
    let header_bytes_u64 = HEADER_BYTES as u64;
    if header.chunk_table_offset < header_bytes_u64 {
        return Err(HibernateError::InvalidLayout {
            reason: "chunk_table_offset overlaps header",
        });
    }
    let payload_end = header_bytes_u64.checked_add(header.payload_bytes).ok_or(
        HibernateError::InvalidLayout {
            reason: "payload_bytes overflows image offset",
        },
    )?;
    if payload_end > header.chunk_table_offset {
        return Err(HibernateError::InvalidLayout {
            reason: "compressed payload overlaps chunk table",
        });
    }
    let table_end = header
        .chunk_table_offset
        .checked_add(header.chunk_table_len)
        .ok_or(HibernateError::TruncatedChunkTable)?;
    if table_end > header.total_image_bytes {
        return Err(HibernateError::InvalidLayout {
            reason: "chunk table extends past total_image_bytes",
        });
    }
    if table_end > backing_bytes || header.total_image_bytes > backing_bytes {
        return Err(HibernateError::TruncatedChunkTable);
    }
    Ok(table_end)
}

/// Verifies `table_bytes` against `header.chunk_table_sha256` and parses +
/// validates every [`ChunkDescriptor`].
pub(crate) fn verify_and_parse_chunk_table(
    header: &HibernateHeader,
    table_bytes: &[u8],
    machine_max_frames: u64,
) -> Result<Vec<ChunkDescriptor>, HibernateError> {
    if table_bytes.len() as u64 != header.chunk_table_len {
        return Err(HibernateError::TruncatedChunkTable);
    }
    let table_digest: [u8; 32] = Sha256::digest(table_bytes).into();
    if !constant_time_eq_32(&table_digest, &header.chunk_table_sha256) {
        return Err(HibernateError::ChunkTableChecksumMismatch);
    }

    let header_bytes_u64 = HEADER_BYTES as u64;
    let chunk_count = header.chunk_count as usize;
    let mut chunks = Vec::with_capacity(chunk_count);
    let mut total_frames_acc = 0_u64;
    let mut prev_end_frame = 0_u64;

    let (chunk_slices, remainder) = table_bytes.as_chunks::<CHUNK_DESCRIPTOR_BYTES>();
    debug_assert!(remainder.is_empty());
    for (idx, raw) in chunk_slices.iter().enumerate() {
        let chunk_index = idx as u32;
        let desc = ChunkDescriptor::decode(raw);
        if desc.flags != 0 {
            return Err(HibernateError::InvalidChunkDescriptor {
                chunk_index,
                reason: "unsupported chunk encoding flags",
            });
        }
        if desc.frame_count == 0 || desc.frame_count > header.chunk_frames {
            return Err(HibernateError::InvalidChunkDescriptor {
                chunk_index,
                reason: "chunk frame_count out of bounds",
            });
        }
        let expected_uncompressed = desc.frame_count.checked_mul(header.frame_size).ok_or(
            HibernateError::InvalidChunkDescriptor {
                chunk_index,
                reason: "uncompressed_len overflow",
            },
        )?;
        if desc.uncompressed_len != expected_uncompressed {
            return Err(HibernateError::InvalidChunkDescriptor {
                chunk_index,
                reason: "uncompressed_len does not equal frame_count * frame_size",
            });
        }
        let chunk_end_frame = desc
            .start_phys_frame
            .checked_add(u64::from(desc.frame_count))
            .ok_or(HibernateError::FrameCountExceedsMachine {
                image_frames: u64::MAX,
                machine_frames: machine_max_frames,
            })?;
        if chunk_end_frame > machine_max_frames {
            return Err(HibernateError::FrameCountExceedsMachine {
                image_frames: chunk_end_frame,
                machine_frames: machine_max_frames,
            });
        }
        if idx > 0 && desc.start_phys_frame < prev_end_frame {
            return Err(HibernateError::InvalidChunkDescriptor {
                chunk_index,
                reason: "chunk physical frame ranges are overlapping or unsorted",
            });
        }
        prev_end_frame = chunk_end_frame;

        if desc.data_offset < header_bytes_u64 {
            return Err(HibernateError::InvalidChunkDescriptor {
                chunk_index,
                reason: "chunk data_offset overlaps header",
            });
        }
        let chunk_data_end = desc
            .data_offset
            .checked_add(u64::from(desc.compressed_len))
            .ok_or(HibernateError::InvalidChunkDescriptor {
                chunk_index,
                reason: "chunk data range overflow",
            })?;
        if chunk_data_end > header.chunk_table_offset {
            return Err(HibernateError::InvalidChunkDescriptor {
                chunk_index,
                reason: "chunk payload extends past payload section",
            });
        }

        total_frames_acc = total_frames_acc
            .checked_add(u64::from(desc.frame_count))
            .ok_or(HibernateError::FrameCountExceedsMachine {
                image_frames: u64::MAX,
                machine_frames: machine_max_frames,
            })?;
        if total_frames_acc > machine_max_frames {
            return Err(HibernateError::FrameCountExceedsMachine {
                image_frames: total_frames_acc,
                machine_frames: machine_max_frames,
            });
        }
        chunks.push(desc);
    }

    if total_frames_acc != header.total_frames {
        return Err(HibernateError::InvalidLayout {
            reason: "sum of chunk frame counts does not match header.total_frames",
        });
    }

    Ok(chunks)
}

/// Verifies a compressed chunk's SHA-256 **before** bounded `zrip`
/// decompression and checks that the decompressed length equals
/// `desc.uncompressed_len`.
pub(crate) fn verify_and_decompress_chunk<'a>(
    decoder: &'a mut DecompressContext,
    desc: &ChunkDescriptor,
    chunk_index: u32,
    compressed: &'a [u8],
) -> Result<alloc::borrow::Cow<'a, [u8]>, HibernateError> {
    let digest: [u8; 32] = Sha256::digest(compressed).into();
    if !constant_time_eq_32(&digest, &desc.sha256) {
        return Err(HibernateError::ChunkChecksumMismatch { chunk_index });
    }
    let expected_len = desc.uncompressed_len as usize;
    let decompressed = decoder
        .decompress_with_limit(compressed, expected_len)
        .map_err(|_| HibernateError::DecompressFailed { chunk_index })?;
    if decompressed.len() != expected_len {
        return Err(HibernateError::DecompressedLengthMismatch {
            chunk_index,
            actual: decompressed.len(),
            expected: expected_len,
        });
    }
    Ok(decompressed)
}

/// Verifies the hibernate header MAC, bounds, machine identity, and chunk
/// table integrity, returning the authenticated header and descriptors.
///
/// No heap allocation is performed until the header HMAC-SHA256, bounds,
/// identity, and chunk table SHA-256 have all verified.
pub fn verify_image_header_and_table(
    image: &[u8],
    auth_key: &HibernateAuthKey,
    expected_identity: &HibernateIdentity,
    machine_max_frames: u64,
) -> Result<VerifiedHibernateImage, HibernateError> {
    // Steps 1-2: length, magic, version, and constant-time HMAC-SHA256.
    // ZERO allocations happen before or inside this call.
    let header = HibernateHeader::decode_verified(image, auth_key)?;

    // Step 3: overflow-safe bounds checks before any allocation.
    let table_end = validate_header_bounds(&header, image.len() as u64, machine_max_frames)?;

    // Step 4: verify every identity field individually.
    verify_identity(&header.identity, &header.identity_sha256, expected_identity)?;

    // Steps 5-6: verify chunk table SHA-256 BEFORE allocating or decoding entries.
    let table_start = usize::try_from(header.chunk_table_offset)
        .map_err(|_| HibernateError::TruncatedChunkTable)?;
    let table_end_usize =
        usize::try_from(table_end).map_err(|_| HibernateError::TruncatedChunkTable)?;
    let table_bytes = &image[table_start..table_end_usize];
    let chunks = verify_and_parse_chunk_table(&header, table_bytes, machine_max_frames)?;

    Ok(VerifiedHibernateImage { header, chunks })
}

/// Verifies the hibernate image end-to-end and streams each decompressed
/// chunk's bytes to `write_chunk(start_phys_frame, decompressed_bytes)`.
///
/// Every chunk's SHA-256 is verified **before** calling `zrip` decompression
/// with the exact `uncompressed_len` limit.
pub fn decode_image_into<F>(
    image: &[u8],
    auth_key: &HibernateAuthKey,
    expected_identity: &HibernateIdentity,
    machine_max_frames: u64,
    mut write_chunk: F,
) -> Result<HibernateHeader, HibernateError>
where
    F: FnMut(u64, &[u8]) -> Result<(), HibernateError>,
{
    let verified =
        verify_image_header_and_table(image, auth_key, expected_identity, machine_max_frames)?;
    let mut decoder = DecompressContext::new();

    for (idx, desc) in verified.chunks.iter().enumerate() {
        let chunk_index = idx as u32;
        let start = usize::try_from(desc.data_offset).map_err(|_| {
            HibernateError::InvalidChunkDescriptor {
                chunk_index,
                reason: "chunk data_offset does not fit usize",
            }
        })?;
        let end = start + desc.compressed_len as usize;
        let compressed = &image[start..end];

        let decompressed =
            verify_and_decompress_chunk(&mut decoder, desc, chunk_index, compressed)?;
        write_chunk(desc.start_phys_frame, &decompressed)?;
    }

    Ok(verified.header)
}

/// Constant-time comparison of two 32-byte digests.
fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0_u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}
