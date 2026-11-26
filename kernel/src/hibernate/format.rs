//! Deterministic wire format for Helios hibernate images.
//!
//! Every multi-byte integer is encoded in explicit little-endian byte order
//! at fixed offsets with zero uninitialized padding. No `#[repr(C)]` struct
//! is ever cast directly to bytes.
//!
//! Layout of a complete hibernate image:
//!
//! ```text
//! [ 0 .. 4096 )                                 HibernateHeader (4064B body + 32B HMAC-SHA256)
//! [ 4096 .. chunk_table_offset )                Compressed chunk payloads (zstd via `zrip`)
//! [ chunk_table_offset .. total_image_bytes )   ChunkDescriptor[chunk_count] (64B each)
//! ```

use helios_hal::boot::BootMemoryRegion;
use helios_hal::cpu::{BSP_SNAPSHOT_CONTEXT_BYTES, BspSnapshotContext, SnapshotArch};
use helios_hal::pmm::PhysFrame;
use helios_hal::{DeviceInventory, DmaModel};
use sha2::{Digest, Sha256};

use super::HibernateError;
use crate::HibernateAuthKey;

/// Magic identifying a Helios hibernate image (version 1).
pub const HEADER_MAGIC: [u8; 8] = *b"HLSHIB01";

/// Current wire format version.
pub const FORMAT_VERSION: u32 = 1;

/// Fixed byte length of the serialized header (one 4 KiB page).
pub const HEADER_BYTES: usize = 4096;

/// Length of the trailing header HMAC-SHA256 tag.
pub const HEADER_MAC_BYTES: usize = 32;

/// Byte offset where the header HMAC-SHA256 tag begins.
pub const HEADER_MAC_OFFSET: usize = HEADER_BYTES - HEADER_MAC_BYTES;

/// Fixed byte length of one serialized [`ChunkDescriptor`].
pub const CHUNK_DESCRIPTOR_BYTES: usize = 64;

/// Default maximum contiguous physical frames grouped into one compressed
/// chunk (`64 * 4 KiB = 256 KiB`).
pub const DEFAULT_CHUNK_FRAMES: u32 = 64;

/// Default zstd compression level for hibernate snapshots.
pub const DEFAULT_HIBERNATE_COMPRESSION_LEVEL: i32 = 1;

/// Hard upper bound on chunk descriptors in an image header (covers up to
/// 1 TiB at 256 KiB chunks).
pub const MAX_CHUNKS: u32 = 4 * 1024 * 1024;

/// One device's negotiated feature bits included in [`HibernateIdentity`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeviceFeatureRecord {
    /// Device class identifier (e.g., virtio device ID).
    pub device_kind: u32,
    /// Zero-based instance index within `device_kind`.
    pub instance_index: u32,
    /// Full 64-bit negotiated feature bitmask.
    pub features: u64,
}

/// Canonical SHA-256 of the firmware memory map entries.
pub fn hash_firmware_memory_map(entries: &[BootMemoryRegion]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"helios.hibernate.fwmap.v1\0");
    hasher.update((entries.len() as u64).to_le_bytes());
    for entry in entries {
        hasher.update(entry.start.to_le_bytes());
        hasher.update(entry.end.to_le_bytes());
        hasher.update(entry.kind.tag().to_le_bytes());
    }
    hasher.finalize().into()
}

/// Canonical SHA-256 of the platform's [`DeviceInventory`] and [`DmaModel`].
pub fn hash_device_inventory(inventory: DeviceInventory, dma_model: DmaModel) -> [u8; 32] {
    let dma_tag: u32 = match dma_model {
        DmaModel::Identity => 0,
        DmaModel::Translated => 1,
        DmaModel::Iommu => 2,
    };
    let mut hasher = Sha256::new();
    hasher.update(b"helios.hibernate.devices.v1\0");
    hasher.update(dma_tag.to_le_bytes());
    hasher.update([
        u8::from(inventory.has_debug_serial),
        u8::from(inventory.has_network),
        u8::from(inventory.has_host_share),
        u8::from(inventory.has_entropy_device),
        u8::from(inventory.has_memory_balloon),
        u8::from(inventory.has_vsock),
    ]);
    hasher.update((inventory.block_device_count as u64).to_le_bytes());
    hasher.finalize().into()
}

/// Canonical SHA-256 of the negotiated device feature records.
pub fn hash_negotiated_features(records: &[DeviceFeatureRecord]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"helios.hibernate.features.v1\0");
    hasher.update((records.len() as u64).to_le_bytes());
    for record in records {
        hasher.update(record.device_kind.to_le_bytes());
        hasher.update(record.instance_index.to_le_bytes());
        hasher.update(record.features.to_le_bytes());
    }
    hasher.finalize().into()
}

/// Complete machine and kernel identity committed to by a hibernate header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HibernateIdentity {
    pub kernel_text_phys_start: u64,
    pub kernel_text_virt_start: u64,
    pub kernel_text_len: u64,
    pub kernel_text_sha256: [u8; 32],

    pub kernel_rodata_phys_start: u64,
    pub kernel_rodata_virt_start: u64,
    pub kernel_rodata_len: u64,
    pub kernel_rodata_sha256: [u8; 32],

    pub boot_payload_phys_addr: u64,
    pub boot_payload_len: u64,
    pub boot_payload_sha256: [u8; 32],

    pub firmware_memory_map_count: u32,
    pub firmware_memory_map_sha256: [u8; 32],

    pub processor_count: u32,
    pub device_inventory_sha256: [u8; 32],
    pub negotiated_features_sha256: [u8; 32],
}

impl HibernateIdentity {
    /// Computes the canonical SHA-256 digest over every identity field.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"helios.hibernate.identity.v1\0");
        hasher.update(self.kernel_text_phys_start.to_le_bytes());
        hasher.update(self.kernel_text_virt_start.to_le_bytes());
        hasher.update(self.kernel_text_len.to_le_bytes());
        hasher.update(self.kernel_text_sha256);
        hasher.update(self.kernel_rodata_phys_start.to_le_bytes());
        hasher.update(self.kernel_rodata_virt_start.to_le_bytes());
        hasher.update(self.kernel_rodata_len.to_le_bytes());
        hasher.update(self.kernel_rodata_sha256);
        hasher.update(self.boot_payload_phys_addr.to_le_bytes());
        hasher.update(self.boot_payload_len.to_le_bytes());
        hasher.update(self.boot_payload_sha256);
        hasher.update(self.firmware_memory_map_count.to_le_bytes());
        hasher.update(self.firmware_memory_map_sha256);
        hasher.update(self.processor_count.to_le_bytes());
        hasher.update(self.device_inventory_sha256);
        hasher.update(self.negotiated_features_sha256);
        hasher.finalize().into()
    }
}

/// Authenticated 4096-byte header at the start of every hibernate image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HibernateHeader {
    pub version: u32,
    pub flags: u32,
    /// Fresh random 128-bit ID per snapshot, passed to
    /// `AdvanceCause::ImageRestored { image_id }` after resume.
    pub image_id: [u8; 16],
    pub identity: HibernateIdentity,
    pub identity_sha256: [u8; 32],
    pub frame_size: u32,
    pub chunk_frames: u32,
    pub total_frames: u64,
    pub machine_max_frames: u64,
    pub chunk_count: u32,
    pub chunk_table_offset: u64,
    pub chunk_table_len: u64,
    pub chunk_table_sha256: [u8; 32],
    pub payload_bytes: u64,
    pub total_image_bytes: u64,
    pub bsp_context: BspSnapshotContext,
}

impl HibernateHeader {
    /// Serializes the header deterministically into 4096 bytes and writes
    /// the trailing HMAC-SHA256 authenticated by `auth_key`.
    pub fn encode_signed(&self, auth_key: &HibernateAuthKey) -> [u8; HEADER_BYTES] {
        let mut buf = [0_u8; HEADER_BYTES];
        let mut w = CursorWriter::new(&mut buf[..HEADER_MAC_OFFSET]);
        w.write_bytes(&HEADER_MAGIC);
        w.write_u32(self.version);
        w.write_u32(self.flags);
        w.write_bytes(&self.image_id);

        // Structured identity fields.
        w.write_u64(self.identity.kernel_text_phys_start);
        w.write_u64(self.identity.kernel_text_virt_start);
        w.write_u64(self.identity.kernel_text_len);
        w.write_bytes(&self.identity.kernel_text_sha256);

        w.write_u64(self.identity.kernel_rodata_phys_start);
        w.write_u64(self.identity.kernel_rodata_virt_start);
        w.write_u64(self.identity.kernel_rodata_len);
        w.write_bytes(&self.identity.kernel_rodata_sha256);

        w.write_u64(self.identity.boot_payload_phys_addr);
        w.write_u64(self.identity.boot_payload_len);
        w.write_bytes(&self.identity.boot_payload_sha256);

        w.write_u32(self.identity.firmware_memory_map_count);
        w.write_bytes(&self.identity.firmware_memory_map_sha256);

        w.write_u32(self.identity.processor_count);
        w.write_bytes(&self.identity.device_inventory_sha256);
        w.write_bytes(&self.identity.negotiated_features_sha256);
        w.write_bytes(&self.identity_sha256);

        // Snapshot geometry & chunk table commitment.
        w.write_u32(self.frame_size);
        w.write_u32(self.chunk_frames);
        w.write_u64(self.total_frames);
        w.write_u64(self.machine_max_frames);
        w.write_u32(self.chunk_count);
        w.write_u64(self.chunk_table_offset);
        w.write_u64(self.chunk_table_len);
        w.write_bytes(&self.chunk_table_sha256);
        w.write_u64(self.payload_bytes);
        w.write_u64(self.total_image_bytes);

        // BSP saved context (unused tail stays zero).
        w.write_u32(self.bsp_context.arch as u32);
        w.write_u32(self.bsp_context.len);
        let ctx_len = (self.bsp_context.len as usize).min(BSP_SNAPSHOT_CONTEXT_BYTES);
        w.write_bytes(&self.bsp_context.data[..ctx_len]);
        // Advance past the fixed 512-byte slot (already zeroed).
        w.skip(BSP_SNAPSHOT_CONTEXT_BYTES - ctx_len);

        let mac = auth_key.compute_mac(&buf[..HEADER_MAC_OFFSET]);
        buf[HEADER_MAC_OFFSET..HEADER_BYTES].copy_from_slice(&mac);
        buf
    }

    /// Validates header length, magic, version, and constant-time HMAC-SHA256
    /// **before** parsing any header fields or performing any allocation.
    pub fn decode_verified(
        bytes: &[u8],
        auth_key: &HibernateAuthKey,
    ) -> Result<Self, HibernateError> {
        if bytes.len() < HEADER_BYTES {
            return Err(HibernateError::TruncatedHeader {
                actual: bytes.len(),
                expected: HEADER_BYTES,
            });
        }
        if bytes[..8] != HEADER_MAGIC {
            return Err(HibernateError::InvalidMagic);
        }
        let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        if version != FORMAT_VERSION {
            return Err(HibernateError::UnsupportedVersion { version });
        }

        // SECURITY INVARIANT: verify constant-time MAC over all preceding
        // header bytes BEFORE decoding any count, offset, or length field and
        // BEFORE any heap allocation.
        let stored_mac: [u8; HEADER_MAC_BYTES] =
            bytes[HEADER_MAC_OFFSET..HEADER_BYTES].try_into().unwrap();
        if !auth_key.verify_mac(&bytes[..HEADER_MAC_OFFSET], &stored_mac) {
            return Err(HibernateError::InvalidMac);
        }

        let mut r = CursorReader::new(&bytes[..HEADER_MAC_OFFSET]);
        let _magic = r.read_array::<8>();
        let version = r.read_u32();
        let flags = r.read_u32();
        let image_id = r.read_array::<16>();

        let identity = HibernateIdentity {
            kernel_text_phys_start: r.read_u64(),
            kernel_text_virt_start: r.read_u64(),
            kernel_text_len: r.read_u64(),
            kernel_text_sha256: r.read_array::<32>(),

            kernel_rodata_phys_start: r.read_u64(),
            kernel_rodata_virt_start: r.read_u64(),
            kernel_rodata_len: r.read_u64(),
            kernel_rodata_sha256: r.read_array::<32>(),

            boot_payload_phys_addr: r.read_u64(),
            boot_payload_len: r.read_u64(),
            boot_payload_sha256: r.read_array::<32>(),

            firmware_memory_map_count: r.read_u32(),
            firmware_memory_map_sha256: r.read_array::<32>(),

            processor_count: r.read_u32(),
            device_inventory_sha256: r.read_array::<32>(),
            negotiated_features_sha256: r.read_array::<32>(),
        };
        let identity_sha256 = r.read_array::<32>();

        let frame_size = r.read_u32();
        let chunk_frames = r.read_u32();
        let total_frames = r.read_u64();
        let machine_max_frames = r.read_u64();
        let chunk_count = r.read_u32();
        let chunk_table_offset = r.read_u64();
        let chunk_table_len = r.read_u64();
        let chunk_table_sha256 = r.read_array::<32>();
        let payload_bytes = r.read_u64();
        let total_image_bytes = r.read_u64();

        let arch_raw = r.read_u32();
        let bsp_len = r.read_u32();
        let bsp_data = r.read_array::<BSP_SNAPSHOT_CONTEXT_BYTES>();

        if frame_size != PhysFrame::SIZE as u32 {
            return Err(HibernateError::InvalidHeaderField {
                reason: "frame_size does not match machine page size",
            });
        }
        if chunk_frames == 0 {
            return Err(HibernateError::InvalidHeaderField {
                reason: "chunk_frames must be non-zero",
            });
        }
        let arch = SnapshotArch::from_u32(arch_raw).ok_or(HibernateError::InvalidHeaderField {
            reason: "unknown BSP snapshot architecture tag",
        })?;
        if bsp_len as usize > BSP_SNAPSHOT_CONTEXT_BYTES {
            return Err(HibernateError::InvalidHeaderField {
                reason: "BSP snapshot context length exceeds fixed buffer capacity",
            });
        }

        Ok(Self {
            version,
            flags,
            image_id,
            identity,
            identity_sha256,
            frame_size,
            chunk_frames,
            total_frames,
            machine_max_frames,
            chunk_count,
            chunk_table_offset,
            chunk_table_len,
            chunk_table_sha256,
            payload_bytes,
            total_image_bytes,
            bsp_context: BspSnapshotContext {
                arch,
                len: bsp_len,
                data: bsp_data,
            },
        })
    }
}

/// Fixed 64-byte descriptor for one compressed physical frame chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkDescriptor {
    /// Starting physical frame index (`physical_address / 4096`).
    pub start_phys_frame: u64,
    /// Number of contiguous physical frames in this chunk (`1..=chunk_frames`).
    pub frame_count: u32,
    /// Byte length of the compressed zstd payload in the image.
    pub compressed_len: u32,
    /// Exact byte length after decompression (`frame_count * frame_size`).
    pub uncompressed_len: u32,
    /// Chunk encoding flags (`0` = zstd via `zrip`).
    pub flags: u32,
    /// Byte offset of the compressed payload from the start of the image.
    pub data_offset: u64,
    /// SHA-256 of the compressed payload bytes at `data_offset..data_offset + compressed_len`.
    pub sha256: [u8; 32],
}

impl ChunkDescriptor {
    pub fn encode(&self) -> [u8; CHUNK_DESCRIPTOR_BYTES] {
        let mut buf = [0_u8; CHUNK_DESCRIPTOR_BYTES];
        let mut w = CursorWriter::new(&mut buf);
        w.write_u64(self.start_phys_frame);
        w.write_u32(self.frame_count);
        w.write_u32(self.compressed_len);
        w.write_u32(self.uncompressed_len);
        w.write_u32(self.flags);
        w.write_u64(self.data_offset);
        w.write_bytes(&self.sha256);
        debug_assert_eq!(w.offset, CHUNK_DESCRIPTOR_BYTES);
        buf
    }

    pub fn decode(bytes: &[u8; CHUNK_DESCRIPTOR_BYTES]) -> Self {
        let mut r = CursorReader::new(bytes);
        let start_phys_frame = r.read_u64();
        let frame_count = r.read_u32();
        let compressed_len = r.read_u32();
        let uncompressed_len = r.read_u32();
        let flags = r.read_u32();
        let data_offset = r.read_u64();
        let sha256 = r.read_array::<32>();
        debug_assert_eq!(r.offset, CHUNK_DESCRIPTOR_BYTES);
        Self {
            start_phys_frame,
            frame_count,
            compressed_len,
            uncompressed_len,
            flags,
            data_offset,
            sha256,
        }
    }
}

struct CursorWriter<'a> {
    buf: &'a mut [u8],
    offset: usize,
}

impl<'a> CursorWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        let end = self.offset + bytes.len();
        self.buf[self.offset..end].copy_from_slice(bytes);
        self.offset = end;
    }

    fn write_u32(&mut self, value: u32) {
        self.write_bytes(&value.to_le_bytes());
    }

    fn write_u64(&mut self, value: u64) {
        self.write_bytes(&value.to_le_bytes());
    }

    fn skip(&mut self, len: usize) {
        self.offset += len;
    }
}

struct CursorReader<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> CursorReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    fn read_array<const N: usize>(&mut self) -> [u8; N] {
        let end = self.offset + N;
        let arr: [u8; N] = self.buf[self.offset..end].try_into().unwrap();
        self.offset = end;
        arr
    }

    fn read_u32(&mut self) -> u32 {
        u32::from_le_bytes(self.read_array::<4>())
    }

    fn read_u64(&mut self) -> u64 {
        u64::from_le_bytes(self.read_array::<8>())
    }
}
