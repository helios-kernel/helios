//! Hardware-independent early-boot hibernate resume planner and loader.
//!
//! # Placement invariants
//!
//! [`plan_frame_placement`] assigns every frame in a verified hibernate image
//! either:
//! - **direct placement** at its original `dst_phys` when `dst_phys` does not
//!   collide with any boot-kernel protected range, or
//! - **displaced placement** into a free usable physical frame `src_phys`
//!   chosen strictly OUTSIDE both the image's target frames AND the boot
//!   kernel's protected ranges, recording a
//!   [`DisplacedFrameCopy { src_phys, dst_phys }`] entry for the architecture
//!   restore trampoline.
//!
//! Because every `src_phys`, the trampoline page (`trampoline_phys`), the
//! trampoline's temporary page-table frames (`trampoline_table_frames`), and
//! the displaced copy table (`copy_table_phys`) come exclusively from the
//! disjoint safe frame pool, the restore trampoline's linear copy loop is
//! guaranteed cycle-free and cannot overwrite any not-yet-copied source frame,
//! its active page tables, its copy table, or its own stack/context.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;
use core::ops::Range;

use helios_hal::boot::{BootMemoryKind, BootMemoryMetadata};
use helios_hal::cpu::DisplacedFrameCopy;
use helios_hal::pmm::PhysFrame;
use helios_hal::{DeviceInventory, DmaModel};
use sha2::{Digest, Sha256};
use zrip::DecompressContext;

use super::HibernateError;
use super::format::{
    ChunkDescriptor, DeviceFeatureRecord, HEADER_BYTES, HEADER_MAGIC, HibernateHeader,
    HibernateIdentity, hash_device_inventory, hash_firmware_memory_map, hash_negotiated_features,
};
use super::snapshot::{FrameRun, normalize_physical_runs};
use super::storage::{HibernateStorage, invalidate_hibernate_header, validate_sector_size};
use super::verify::{
    validate_header_bounds, verify_and_decompress_chunk, verify_and_parse_chunk_table,
    verify_identity,
};
use crate::memory::UserMemoryPool;
use crate::{HibernateAuthKey, kernel_heap_regions};

/// Planned staging physical addresses for every frame belonging to one
/// verified [`ChunkDescriptor`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkPlacement {
    /// Starting destination physical frame index (`dst_phys / 4096`).
    pub start_phys_frame: u64,
    /// Staging physical address (`u64`, 4 KiB aligned) where frame `i` of this
    /// chunk should be written during boot-kernel decompression. Equal to
    /// `(start_phys_frame + i) * 4096` for direct placement, or to the safe
    /// displaced `src_phys` for colliding frames.
    pub staging_phys: Vec<u64>,
}

/// Cycle-free physical placement plan produced by [`plan_frame_placement`] for
/// the architecture restore trampoline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramePlacementPlan {
    /// Physical address of the dedicated 4 KiB restore trampoline parameter,
    /// context, handoff, and private-stack page.
    pub trampoline_phys: u64,
    /// Physical addresses of extra safe 4 KiB frames reserved for the restore
    /// trampoline's temporary page tables.
    pub trampoline_table_frames: Vec<u64>,
    /// Physical address of the contiguous [`DisplacedFrameCopy`] table
    /// (`0` when `displaced_copies` is empty).
    pub copy_table_phys: u64,
    /// Number of contiguous 4 KiB frames reserved starting at
    /// `copy_table_phys`.
    pub copy_table_pages: u64,
    /// Per-chunk staging physical addresses used while decompressing chunks.
    pub chunk_placements: Vec<ChunkPlacement>,
    /// Linear, cycle-free list of 4 KiB physical copies for the restore
    /// trampoline.
    pub displaced_copies: Vec<DisplacedFrameCopy>,
    /// Number of image frames placed directly at their final `dst_phys`.
    pub direct_frames: u64,
}

/// Verified and decompressed hibernate image ready to hand off to the
/// architecture restore trampoline.
#[derive(Clone, Debug)]
pub struct LoadedHibernateImage {
    pub header: HibernateHeader,
    pub plan: FramePlacementPlan,
}

/// Outcome of probing the hibernate block device during early BSP bring-up.
#[derive(Debug)]
pub enum ResumeProbe {
    /// Sector 0 does not carry [`HEADER_MAGIC`]; continue cold boot silently.
    NoImage,
    /// Sector 0 carried [`HEADER_MAGIC`], but verification or loading failed.
    /// Sector `0..8` was invalidated on disk and the refusal was logged;
    /// continue cold boot.
    Refused(HibernateError),
    /// A valid, authenticated hibernate image has been verified and loaded
    /// into its planned direct/displaced physical frames.
    Ready(Box<LoadedHibernateImage>),
}

/// Computes the machine's [`HibernateIdentity`] from `boot_memory`,
/// `processor_count`, `devices`, `dma_model`, and `feature_records`, using
/// caller-supplied `.text` and `.rodata` SHA-256 digests.
pub fn build_machine_identity_with_hashes(
    boot_memory: &BootMemoryMetadata,
    processor_count: u32,
    devices: DeviceInventory,
    dma_model: DmaModel,
    feature_records: &[DeviceFeatureRecord],
    kernel_text_sha256: [u8; 32],
    kernel_rodata_sha256: [u8; 32],
) -> Result<HibernateIdentity, HibernateError> {
    let payload = boot_memory
        .boot_payload
        .ok_or(HibernateError::InvalidIdentityInput {
            reason: "boot payload metadata is unavailable",
        })?;
    let sections = &boot_memory.kernel_sections;
    let mut sorted_features: Vec<DeviceFeatureRecord> = feature_records.to_vec();
    sorted_features.sort_unstable();
    Ok(HibernateIdentity {
        kernel_text_phys_start: sections.text.physical_start,
        kernel_text_virt_start: sections.text.virtual_start,
        kernel_text_len: sections.text.len,
        kernel_text_sha256,

        kernel_rodata_phys_start: sections.rodata.physical_start,
        kernel_rodata_virt_start: sections.rodata.virtual_start,
        kernel_rodata_len: sections.rodata.len,
        kernel_rodata_sha256,

        boot_payload_phys_addr: payload.physical_address,
        boot_payload_len: payload.len,
        boot_payload_sha256: payload.sha256,

        firmware_memory_map_count: boot_memory.firmware_memory_map.len() as u32,
        firmware_memory_map_sha256: hash_firmware_memory_map(&boot_memory.firmware_memory_map),

        processor_count,
        device_inventory_sha256: hash_device_inventory(devices, dma_model),
        negotiated_features_sha256: hash_negotiated_features(&sorted_features),
    })
}

/// Computes the running bare-metal kernel's [`HibernateIdentity`], hashing
/// the immutable `.text` and `.rodata` sections in place from their mapped
/// kernel virtual addresses.
///
/// # Safety
///
/// `boot_memory.kernel_sections.text` and `rodata` must describe valid,
/// readable, immutable mapped virtual ranges of the running kernel image.
pub unsafe fn build_machine_identity(
    boot_memory: &BootMemoryMetadata,
    processor_count: u32,
    devices: DeviceInventory,
    dma_model: DmaModel,
    feature_records: &[DeviceFeatureRecord],
) -> Result<HibernateIdentity, HibernateError> {
    let text = boot_memory.kernel_sections.text;
    let rodata = boot_memory.kernel_sections.rodata;
    if text.is_empty() || rodata.is_empty() {
        return Err(HibernateError::InvalidIdentityInput {
            reason: "kernel .text or .rodata section metadata is empty",
        });
    }
    let text_len = usize::try_from(text.len).map_err(|_| HibernateError::InvalidIdentityInput {
        reason: "kernel .text length exceeds usize",
    })?;
    let rodata_len =
        usize::try_from(rodata.len).map_err(|_| HibernateError::InvalidIdentityInput {
            reason: "kernel .rodata length exceeds usize",
        })?;
    let text_ptr =
        usize::try_from(text.virtual_start).map_err(|_| HibernateError::InvalidIdentityInput {
            reason: "kernel .text virtual start exceeds usize",
        })?;
    let rodata_ptr = usize::try_from(rodata.virtual_start).map_err(|_| {
        HibernateError::InvalidIdentityInput {
            reason: "kernel .rodata virtual start exceeds usize",
        }
    })?;

    // SAFETY: caller guarantees `kernel_sections.text` is a valid readable
    // immutable mapped slice of the running kernel image.
    let text_bytes = unsafe {
        core::slice::from_raw_parts(core::ptr::with_exposed_provenance::<u8>(text_ptr), text_len)
    };
    // SAFETY: caller guarantees `kernel_sections.rodata` is a valid readable
    // immutable mapped slice of the running kernel image.
    let rodata_bytes = unsafe {
        core::slice::from_raw_parts(
            core::ptr::with_exposed_provenance::<u8>(rodata_ptr),
            rodata_len,
        )
    };

    let text_sha256: [u8; 32] = Sha256::digest(text_bytes).into();
    let rodata_sha256: [u8; 32] = Sha256::digest(rodata_bytes).into();

    build_machine_identity_with_hashes(
        boot_memory,
        processor_count,
        devices,
        dma_model,
        feature_records,
        text_sha256,
        rodata_sha256,
    )
}

/// Extracts all firmware-reported usable physical RAM regions from
/// `boot_memory` as normalized, sorted, non-overlapping [`FrameRun`]s.
pub fn usable_physical_frame_runs(boot_memory: &BootMemoryMetadata) -> Vec<FrameRun> {
    let page = PhysFrame::SIZE as u64;
    let mut runs: Vec<Range<u64>> = boot_memory
        .firmware_memory_map
        .iter()
        .filter(|region| region.kind == BootMemoryKind::Usable && region.end > region.start)
        .filter_map(|region| {
            // Round inward so only wholly usable 4 KiB frames are handed to
            // the restore planner.
            let start = region.start.div_ceil(page);
            let end = region.end / page;
            (end > start).then_some(start..end)
        })
        .collect();
    if runs.is_empty() {
        return Vec::new();
    }
    runs.sort_unstable_by_key(|r| r.start);
    let mut merged: Vec<FrameRun> = Vec::with_capacity(runs.len());
    for range in runs {
        if let Some(last) = merged.last_mut()
            && range.start <= last.end_phys_frame()
        {
            let new_end = last.end_phys_frame().max(range.end);
            last.frame_count = new_end - last.start_phys_frame;
            continue;
        }
        merged.push(FrameRun::new(range.start, range.end - range.start));
    }
    merged
}

/// Collects every physical byte range currently occupied by the boot kernel
/// so [`plan_frame_placement`] never overwrites live boot-kernel code, stack,
/// heap, page tables, DMA rings, DTB, or boot payload during decompression.
pub fn collect_boot_protected_ranges(
    boot_memory: &BootMemoryMetadata,
    user_pool: &UserMemoryPool,
    extra_protected: &[Range<u64>],
) -> Vec<Range<u64>> {
    let offset = boot_memory.physical_memory_offset as u64;
    let direct_to_phys = |addr: usize| -> u64 {
        (addr as u64)
            .checked_sub(offset)
            .unwrap_or_else(|| panic!("direct-map address {addr:#x} lies below offset {offset:#x}"))
    };

    let mut protected = Vec::new();

    // 1. All boot-kernel linked sections (text, rodata, data, bss, uninit, stack).
    let sections = &boot_memory.kernel_sections;
    for section in [
        Some(sections.text),
        Some(sections.rodata),
        Some(sections.data),
        Some(sections.bss),
        sections.uninit,
        sections.stack,
    ]
    .into_iter()
    .flatten()
    {
        if !section.is_empty() {
            protected.push(section.physical_start..section.physical_end());
        }
    }

    // 2. Boot kernel heap regions (all claimed chunks).
    for (start, end) in kernel_heap_regions() {
        if end > start {
            protected.push(direct_to_phys(start)..direct_to_phys(end));
        }
    }

    // 3. Boot user-pool allocated frames (buddy metadata, per-processor arenas,
    //    DMA rings/buffers used by the boot kernel's virtio-blk/iommu drivers).
    for range in user_pool.allocated_ranges(&[]) {
        if range.end > range.start {
            protected.push(direct_to_phys(range.start)..direct_to_phys(range.end));
        }
    }

    // 4. Bootloader-reclaimable ranges (Limine/firmware page tables & structures).
    for range in &boot_memory.bootloader_reclaimable {
        if !range.is_empty() {
            protected.push(range.start..range.end);
        }
    }

    // 5. Device tree blob and boot payload.
    if let Some(dtb) = boot_memory.device_tree_blob
        && !dtb.is_empty()
    {
        protected.push(dtb.start..dtb.end);
    }
    if let Some(payload) = boot_memory.boot_payload
        && payload.len > 0
    {
        protected
            .push(payload.physical_address..payload.physical_address.saturating_add(payload.len));
    }

    // 6. Any backend-specific protected ranges (e.g., x86 AP wakeup page, live stack).
    for range in extra_protected {
        if range.end > range.start {
            protected.push(range.clone());
        }
    }

    protected
}

/// Plans direct vs displaced frame placement for every frame in `chunks`.
///
/// - Frames whose destination `dst_phys` does not overlap `protected_ranges`
///   are placed directly at `dst_phys`.
/// - Colliding frames, the dedicated `trampoline_phys` page,
///   `trampoline_table_pages` temporary page-table frames, and the contiguous
///   `copy_table_phys` array are all allocated exclusively from usable frames
///   disjoint from BOTH `protected_ranges` AND all image target frames in
///   `chunks`.
pub fn plan_frame_placement(
    chunks: &[ChunkDescriptor],
    usable_frames: &[FrameRun],
    protected_ranges: &[Range<u64>],
    trampoline_table_pages: usize,
) -> Result<FramePlacementPlan, HibernateError> {
    let page = PhysFrame::SIZE as u64;

    // Normalize protected physical ranges outward to whole 4 KiB frames.
    let protected_frames = normalize_outward_frames(protected_ranges, page);

    // Collect image target physical frame ranges (from verified chunks).
    let mut image_target_bytes: Vec<Range<u64>> = Vec::with_capacity(chunks.len());
    let mut displaced_count = 0_u64;
    let mut direct_frames = 0_u64;
    for desc in chunks {
        let start_frame = desc.start_phys_frame;
        let end_frame = start_frame.saturating_add(u64::from(desc.frame_count));
        image_target_bytes.push(start_frame.saturating_mul(page)..end_frame.saturating_mul(page));
        for frame in start_frame..end_frame {
            if frame_in_sorted_ranges(frame, &protected_frames) {
                displaced_count += 1;
            } else {
                direct_frames += 1;
            }
        }
    }

    // Build the safe staging pool: usable frames minus BOTH protected ranges
    // AND every image target frame.
    let usable_bytes: Vec<Range<u64>> = usable_frames
        .iter()
        .filter(|run| run.frame_count > 0)
        .map(|run| {
            run.start_phys_frame.saturating_mul(page)..run.end_phys_frame().saturating_mul(page)
        })
        .collect();
    let mut excluded_bytes: Vec<Range<u64>> =
        Vec::with_capacity(protected_frames.len() + image_target_bytes.len());
    for range in &protected_frames {
        excluded_bytes.push(range.start.saturating_mul(page)..range.end.saturating_mul(page));
    }
    excluded_bytes.extend(image_target_bytes);
    let mut safe_runs = normalize_physical_runs(&usable_bytes, &excluded_bytes);

    let copy_table_bytes = (displaced_count as usize)
        .checked_mul(size_of::<DisplacedFrameCopy>())
        .ok_or(HibernateError::InvalidLayout {
            reason: "displaced frame copy table size overflow",
        })?;
    let copy_table_pages = copy_table_bytes.div_ceil(PhysFrame::SIZE) as u64;
    let total_needed_safe_frames = 1_u64
        .saturating_add(trampoline_table_pages as u64)
        .saturating_add(copy_table_pages)
        .saturating_add(displaced_count);
    let total_available_safe_frames: u64 = safe_runs.iter().map(|r| r.frame_count).sum();
    if total_available_safe_frames < total_needed_safe_frames {
        return Err(HibernateError::InsufficientRestoreMemory {
            needed_frames: total_needed_safe_frames,
            available_frames: total_available_safe_frames,
        });
    }

    // 1. Allocate contiguous frames for the copy table first so fragmentation
    //    from single-frame allocations cannot prevent finding a contiguous run.
    let copy_table_phys = if copy_table_pages == 0 {
        0
    } else {
        take_contiguous_frames(&mut safe_runs, copy_table_pages).ok_or(
            HibernateError::InsufficientRestoreMemory {
                needed_frames: total_needed_safe_frames,
                available_frames: total_available_safe_frames,
            },
        )? * page
    };

    // 2. Allocate the dedicated 4 KiB trampoline page.
    let trampoline_phys =
        take_single_frame(&mut safe_runs).ok_or(HibernateError::InsufficientRestoreMemory {
            needed_frames: total_needed_safe_frames,
            available_frames: total_available_safe_frames,
        })? * page;

    // 3. Allocate safe frames for temporary trampoline page tables.
    let mut trampoline_table_frames = Vec::with_capacity(trampoline_table_pages);
    for _ in 0..trampoline_table_pages {
        let frame =
            take_single_frame(&mut safe_runs).ok_or(HibernateError::InsufficientRestoreMemory {
                needed_frames: total_needed_safe_frames,
                available_frames: total_available_safe_frames,
            })?;
        trampoline_table_frames.push(frame * page);
    }

    // 4. Assign direct or safe displaced physical addresses to every frame in
    //    every chunk.
    let mut chunk_placements = Vec::with_capacity(chunks.len());
    let mut displaced_copies = Vec::with_capacity(displaced_count as usize);

    for desc in chunks {
        let count = desc.frame_count as usize;
        let mut staging_phys = Vec::with_capacity(count);
        for i in 0..count {
            let dst_frame = desc.start_phys_frame + i as u64;
            let dst_phys = dst_frame * page;
            if frame_in_sorted_ranges(dst_frame, &protected_frames) {
                let src_frame = take_single_frame(&mut safe_runs).ok_or(
                    HibernateError::InsufficientRestoreMemory {
                        needed_frames: total_needed_safe_frames,
                        available_frames: total_available_safe_frames,
                    },
                )?;
                let src_phys = src_frame * page;
                staging_phys.push(src_phys);
                displaced_copies.push(DisplacedFrameCopy { src_phys, dst_phys });
            } else {
                staging_phys.push(dst_phys);
            }
        }
        chunk_placements.push(ChunkPlacement {
            start_phys_frame: desc.start_phys_frame,
            staging_phys,
        });
    }

    Ok(FramePlacementPlan {
        trampoline_phys,
        trampoline_table_frames,
        copy_table_phys,
        copy_table_pages,
        chunk_placements,
        displaced_copies,
        direct_frames,
    })
}

/// Probes `storage` at sector 0 for a valid hibernate image and, if present,
/// verifies its MAC, bounds, machine identity, chunk table, and every chunk's
/// SHA-256 before decompressing each 4 KiB frame into its planned physical
/// destination through `write_phys_frame`.
///
/// - If sector 0 does not start with [`HEADER_MAGIC`]: returns
///   [`ResumeProbe::NoImage`] without modifying the disk.
/// - On ANY verification, identity, planning, storage, or decompression error
///   after observing [`HEADER_MAGIC`]: invalidates sector `0..8` on disk via
///   [`invalidate_hibernate_header`], logs the explicit refusal reason, and
///   returns [`ResumeProbe::Refused`].
#[expect(
    clippy::too_many_arguments,
    reason = "explicit static-dispatch dependencies keep early-boot resume free of global state and dynamic dispatch"
)]
pub fn probe_and_load_hibernate_image<Storage, WritePhysFrame, PetWatchdog>(
    storage: &mut Storage,
    auth_key: Option<&HibernateAuthKey>,
    expected_identity: &HibernateIdentity,
    machine_max_frames: u64,
    usable_frames: &[FrameRun],
    protected_ranges: &[Range<u64>],
    trampoline_table_pages: usize,
    mut write_phys_frame: WritePhysFrame,
    mut pet_watchdog: PetWatchdog,
) -> ResumeProbe
where
    Storage: HibernateStorage,
    WritePhysFrame: FnMut(u64, &[u8; PhysFrame::SIZE]),
    PetWatchdog: FnMut(),
{
    let sector_size = storage.sector_size();
    if let Err(err) = validate_sector_size(sector_size) {
        let error = HibernateError::Storage(err);
        tracing::warn!(%error, "hibernate resume probe skipped due to invalid sector size");
        return ResumeProbe::Refused(error);
    }

    let mut header_buf = [0_u8; HEADER_BYTES];
    if let Err(err) = storage.read_sectors(0, &mut header_buf) {
        let error = HibernateError::Storage(err);
        tracing::warn!(%error, "failed reading sector 0 during hibernate resume probe");
        return ResumeProbe::Refused(error);
    }

    // Absent magic is the normal cold-boot path: return silently without
    // touching the disk.
    if header_buf[..HEADER_MAGIC.len()] != HEADER_MAGIC {
        return ResumeProbe::NoImage;
    }

    match load_verified_image_body(
        storage,
        &header_buf,
        auth_key,
        expected_identity,
        machine_max_frames,
        usable_frames,
        protected_ranges,
        trampoline_table_pages,
        &mut write_phys_frame,
        &mut pet_watchdog,
    ) {
        Ok(loaded) => ResumeProbe::Ready(Box::new(loaded)),
        Err(error) => {
            tracing::warn!(
                %error,
                "hibernate image refused; invalidating header on disk and continuing cold boot"
            );
            if let Err(inv_err) = invalidate_hibernate_header(storage) {
                tracing::error!(
                    error = %inv_err,
                    "failed to invalidate refused hibernate header on disk"
                );
            }
            ResumeProbe::Refused(error)
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "internal helper forwarding explicit static-dispatch resume parameters"
)]
fn load_verified_image_body<Storage, WritePhysFrame, PetWatchdog>(
    storage: &mut Storage,
    header_buf: &[u8; HEADER_BYTES],
    auth_key: Option<&HibernateAuthKey>,
    expected_identity: &HibernateIdentity,
    machine_max_frames: u64,
    usable_frames: &[FrameRun],
    protected_ranges: &[Range<u64>],
    trampoline_table_pages: usize,
    write_phys_frame: &mut WritePhysFrame,
    pet_watchdog: &mut PetWatchdog,
) -> Result<LoadedHibernateImage, HibernateError>
where
    Storage: HibernateStorage,
    WritePhysFrame: FnMut(u64, &[u8; PhysFrame::SIZE]),
    PetWatchdog: FnMut(),
{
    let auth_key = auth_key.ok_or(HibernateError::NoAuthenticationKey)?;
    let header = HibernateHeader::decode_verified(header_buf, auth_key)?;
    let _table_end = validate_header_bounds(&header, storage.capacity_bytes(), machine_max_frames)?;
    verify_identity(&header.identity, &header.identity_sha256, expected_identity)?;

    let table_len =
        usize::try_from(header.chunk_table_len).map_err(|_| HibernateError::TruncatedChunkTable)?;
    let table_bytes = read_unaligned_range(storage, header.chunk_table_offset, table_len)?;
    let chunks = verify_and_parse_chunk_table(&header, &table_bytes, machine_max_frames)?;
    drop(table_bytes);

    let plan = plan_frame_placement(
        &chunks,
        usable_frames,
        protected_ranges,
        trampoline_table_pages,
    )?;

    let mut decoder = DecompressContext::new();
    let mut read_buf: Vec<u8> = Vec::new();
    let sector_size = storage.sector_size() as u64;

    for (idx, (desc, placement)) in chunks.iter().zip(plan.chunk_placements.iter()).enumerate() {
        let chunk_index = idx as u32;
        let comp_len = desc.compressed_len as usize;
        let start_sector = desc.data_offset / sector_size;
        let head_pad = (desc.data_offset % sector_size) as usize;
        let read_bytes = (head_pad + comp_len).next_multiple_of(sector_size as usize);
        if read_buf.len() < read_bytes {
            read_buf.resize(read_bytes, 0);
        }
        storage.read_sectors(start_sector, &mut read_buf[..read_bytes])?;
        let compressed = &read_buf[head_pad..head_pad + comp_len];

        let decompressed =
            verify_and_decompress_chunk(&mut decoder, desc, chunk_index, compressed)?;
        let (frames, remainder) = decompressed.as_chunks::<{ PhysFrame::SIZE }>();
        debug_assert!(remainder.is_empty());
        debug_assert_eq!(frames.len(), placement.staging_phys.len());
        for (frame_bytes, &dst_phys) in frames.iter().zip(placement.staging_phys.iter()) {
            write_phys_frame(dst_phys, frame_bytes);
        }
        pet_watchdog();
    }

    Ok(LoadedHibernateImage { header, plan })
}

/// Reads an arbitrary byte range `[byte_offset, byte_offset + byte_len)` from
/// sector-addressed `storage`.
fn read_unaligned_range<Storage: HibernateStorage>(
    storage: &mut Storage,
    byte_offset: u64,
    byte_len: usize,
) -> Result<Vec<u8>, HibernateError> {
    if byte_len == 0 {
        return Ok(Vec::new());
    }
    let sector_size = storage.sector_size() as u64;
    let start_sector = byte_offset / sector_size;
    let head_pad = (byte_offset % sector_size) as usize;
    let aligned_len = (head_pad + byte_len).next_multiple_of(sector_size as usize);
    let mut buf = vec![0_u8; aligned_len];
    storage.read_sectors(start_sector, &mut buf)?;
    Ok(buf[head_pad..head_pad + byte_len].to_vec())
}

fn normalize_outward_frames(ranges: &[Range<u64>], page: u64) -> Vec<Range<u64>> {
    let mut frames: Vec<Range<u64>> = ranges
        .iter()
        .filter(|r| r.end > r.start)
        .map(|r| (r.start / page)..r.end.div_ceil(page))
        .collect();
    if frames.is_empty() {
        return Vec::new();
    }
    frames.sort_unstable_by_key(|r| r.start);
    let mut merged: Vec<Range<u64>> = Vec::with_capacity(frames.len());
    for range in frames {
        if let Some(last) = merged.last_mut()
            && range.start <= last.end
        {
            last.end = last.end.max(range.end);
            continue;
        }
        merged.push(range);
    }
    merged
}

fn frame_in_sorted_ranges(frame: u64, sorted_ranges: &[Range<u64>]) -> bool {
    let idx = sorted_ranges.partition_point(|r| r.end <= frame);
    sorted_ranges
        .get(idx)
        .is_some_and(|r| frame >= r.start && frame < r.end)
}

fn take_single_frame(runs: &mut [FrameRun]) -> Option<u64> {
    for run in runs.iter_mut() {
        if run.frame_count > 0 {
            let frame = run.start_phys_frame;
            run.start_phys_frame += 1;
            run.frame_count -= 1;
            return Some(frame);
        }
    }
    None
}

fn take_contiguous_frames(runs: &mut [FrameRun], count: u64) -> Option<u64> {
    for run in runs.iter_mut() {
        if run.frame_count >= count {
            let start = run.start_phys_frame;
            run.start_phys_frame += count;
            run.frame_count -= count;
            return Some(start);
        }
    }
    None
}
