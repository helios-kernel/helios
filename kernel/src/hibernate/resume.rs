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
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;
use core::ops::Range;

use helios_hal::boot::{BootMemoryKind, BootMemoryMetadata, KernelSectionRange};
use helios_hal::cpu::DisplacedFrameCopy;
use helios_hal::pmm::PhysFrame;
use helios_hal::{DeviceInventory, DmaModel};
use sha2::{Digest, Sha256};
use zrip::DecompressContext;

use super::HibernateError;
use super::format::{
    ChunkDescriptor, DeviceFeatureRecord, HEADER_BYTES, HEADER_MAGIC, HibernateHeader,
    HibernateIdentity, canonical_dram_regions, canonical_firmware_memory_map_count,
    hash_device_inventory, hash_firmware_memory_map, hash_negotiated_features,
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

/// Immutable physical region (kernel `.text`/`.rodata`/RELRO or `boot_payload`)
/// whose physical load address shifted between the hibernated boot and the
/// resuming boot and must be relocated to `image_dst_phys`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelocatedRegion {
    /// Physical start address (4 KiB aligned) in the currently running boot kernel.
    pub boot_src_phys: u64,
    /// Target physical start address (4 KiB aligned) expected by the hibernated image.
    pub image_dst_phys: u64,
    /// Byte length of the immutable region.
    pub byte_len: u64,
}

/// Planned staging assignment for one relocated immutable 4 KiB frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelocatedFramePlacement {
    /// Source physical address (4 KiB aligned) in the boot kernel.
    pub boot_src_phys: u64,
    /// Staging physical address (4 KiB aligned) written during boot-kernel
    /// preparation: equal to `dst_phys` for direct placement, or to a safe
    /// disjoint `src_phys` in `displaced_copies` for colliding frames.
    pub staging_phys: u64,
    /// Final target physical address (4 KiB aligned) expected by the image.
    pub dst_phys: u64,
    /// Number of valid bytes (`1..=4096`) to copy from `boot_src_phys`; any
    /// trailing bytes up to 4096 are zero-filled.
    pub valid_bytes: usize,
}

/// Cycle-free physical placement plan produced by [`plan_frame_placement`] for
/// the architecture restore trampoline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramePlacementPlan {
    /// Physical address of the dedicated 4 KiB restore trampoline parameter,
    /// context, handoff, and private-stack page.
    pub trampoline_phys: u64,
    /// Physical address of the dedicated 4 KiB safe copy of the restore
    /// trampoline's entry page (`V_enter`), mapped at `V_enter` in the
    /// trampoline's temporary page tables so the copy loop can overwrite Boot
    /// 2's kernel `.text` without faulting its own instruction stream.
    pub trampoline_enter_copy_phys: u64,
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
    /// Staging physical addresses for immutable regions relocated from Boot 2's
    /// physical load addresses into Boot 1's target physical addresses.
    pub relocated_placements: Vec<RelocatedFramePlacement>,
    /// Linear, cycle-free list of 4 KiB physical copies for the restore
    /// trampoline (covering both displaced chunks and displaced relocated frames).
    pub displaced_copies: Vec<DisplacedFrameCopy>,
    /// Number of image frames (chunks + relocated) placed directly at their
    /// final `dst_phys`.
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

        firmware_memory_map_count: canonical_firmware_memory_map_count(
            &boot_memory.firmware_memory_map,
        ),
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

/// Extracts all canonical physical DRAM banks from `boot_memory` as
/// normalized, sorted, non-overlapping inward-rounded 4 KiB [`FrameRun`]s.
///
/// Used by [`plan_frame_placement`] to validate that every restored chunk and
/// relocated immutable frame targets real physical DRAM on the resuming machine
/// even when firmware shifted sub-splits (`KernelAndModules`,
/// `BootloaderReclaimable`, `AcpiReclaimable`, `AcpiNvs`, or adjacent UEFI
/// Runtime Services `Reserved`) inside the same DRAM bank.
pub fn dram_physical_frame_runs(boot_memory: &BootMemoryMetadata) -> Vec<FrameRun> {
    let page = PhysFrame::SIZE as u64;
    canonical_dram_regions(&boot_memory.firmware_memory_map)
        .into_iter()
        .filter_map(|range| {
            let start = range.start.div_ceil(page);
            let end = range.end / page;
            (end > start).then_some(FrameRun::new(start, end - start))
        })
        .collect()
}

/// Computes the immutable physical regions (kernel image / `.text` / `.rodata`
/// and `boot_payload`) whose physical load addresses shifted between the
/// hibernated boot (`image`) and the resuming boot (`boot`) and must be copied
/// into the physical addresses expected by the hibernated image.
pub fn build_relocated_regions(
    boot_kernel_image: Option<KernelSectionRange>,
    image: &HibernateIdentity,
    boot: &HibernateIdentity,
) -> Result<Vec<RelocatedRegion>, HibernateError> {
    let page = PhysFrame::SIZE as u64;
    let mut regions = Vec::new();
    let push_aligned_pair = |regions: &mut Vec<RelocatedRegion>,
                             boot_start: u64,
                             image_start: u64,
                             len: u64|
     -> Result<(), HibernateError> {
        if len == 0 {
            return Ok(());
        }
        let boot_off = boot_start % page;
        let image_off = image_start % page;
        if boot_off != image_off {
            return Err(HibernateError::InvalidLayout {
                reason: "relocated section has mismatched sub-page alignment",
            });
        }
        let aligned_boot_start = boot_start - boot_off;
        let aligned_image_start = image_start - image_off;
        let aligned_len = boot_off
            .checked_add(len)
            .ok_or(HibernateError::InvalidLayout {
                reason: "relocated section length overflow",
            })?
            .next_multiple_of(page);
        regions.push(RelocatedRegion {
            boot_src_phys: aligned_boot_start,
            image_dst_phys: aligned_image_start,
            byte_len: aligned_len,
        });
        Ok(())
    };

    if image.kernel_text_phys_start != boot.kernel_text_phys_start {
        let delta =
            i128::from(image.kernel_text_phys_start) - i128::from(boot.kernel_text_phys_start);
        if delta.rem_euclid(i128::from(page)) != 0 {
            return Err(HibernateError::InvalidLayout {
                reason: "relocated kernel physical delta is not page-aligned",
            });
        }
        if let Some(img) = boot_kernel_image
            && !img.is_empty()
        {
            let boot_start = img.physical_start & !(page - 1);
            let boot_end = img.physical_end().next_multiple_of(page);
            let image_start = u64::try_from(i128::from(boot_start) + delta).map_err(|_| {
                HibernateError::InvalidLayout {
                    reason: "relocated kernel image physical address overflow",
                }
            })?;
            regions.push(RelocatedRegion {
                boot_src_phys: boot_start,
                image_dst_phys: image_start,
                byte_len: boot_end - boot_start,
            });
        } else {
            push_aligned_pair(
                &mut regions,
                boot.kernel_text_phys_start,
                image.kernel_text_phys_start,
                image.kernel_text_len,
            )?;
            if image.kernel_rodata_phys_start != boot.kernel_rodata_phys_start {
                push_aligned_pair(
                    &mut regions,
                    boot.kernel_rodata_phys_start,
                    image.kernel_rodata_phys_start,
                    image.kernel_rodata_len,
                )?;
            }
        }
    } else if image.kernel_rodata_phys_start != boot.kernel_rodata_phys_start {
        push_aligned_pair(
            &mut regions,
            boot.kernel_rodata_phys_start,
            image.kernel_rodata_phys_start,
            image.kernel_rodata_len,
        )?;
    }

    if image.boot_payload_phys_addr != boot.boot_payload_phys_addr && image.boot_payload_len > 0 {
        if !boot.boot_payload_phys_addr.is_multiple_of(page)
            || !image.boot_payload_phys_addr.is_multiple_of(page)
        {
            return Err(HibernateError::InvalidLayout {
                reason: "relocated boot payload physical address is not page-aligned",
            });
        }
        regions.push(RelocatedRegion {
            boot_src_phys: boot.boot_payload_phys_addr,
            image_dst_phys: image.boot_payload_phys_addr,
            byte_len: image.boot_payload_len,
        });
    }

    Ok(regions)
}

/// Collects every physical byte range currently occupied by the boot kernel
/// so [`plan_frame_placement`] never overwrites live boot-kernel code, stack,
/// heap, page tables, DMA rings, firmware tables, DTB, or boot payload during
/// decompression.
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

    // 1. Full boot-kernel ELF image and all linked sections.
    let sections = &boot_memory.kernel_sections;
    for section in [
        sections.image,
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

    // 4. Bootloader-reclaimable ranges and every non-Usable firmware memory-map
    //    region (page tables, kernel/modules, ACPI tables, NVS, reserved).
    for range in &boot_memory.bootloader_reclaimable {
        if !range.is_empty() {
            protected.push(range.start..range.end);
        }
    }
    for region in &boot_memory.firmware_memory_map {
        if region.kind != BootMemoryKind::Usable && region.end > region.start {
            protected.push(region.start..region.end);
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

/// Plans direct vs displaced frame placement for every frame in `chunks` and
/// every relocated immutable frame in `relocated_regions`.
///
/// - Every target frame (both `chunks` and `relocated_regions`, after skipping
///   relocated frames already covered by `chunks`) must lie inside `dram_frames`
///   or `HibernateError::FirmwareMemoryMapMismatch` is returned.
/// - Frames whose destination `dst_phys` does not overlap `protected_ranges`
///   (or any relocated `boot_src_phys` range) are placed directly at `dst_phys`.
/// - Colliding frames, the dedicated `trampoline_phys` page, the dedicated
///   `trampoline_enter_copy_phys` page, `trampoline_table_pages` temporary
///   page-table frames, and the contiguous `copy_table_phys` array are all
///   allocated exclusively from `usable_frames` disjoint from BOTH
///   `protected_ranges` (including relocated sources) AND all image target
///   frames (`chunks` + `relocated_regions`).
pub fn plan_frame_placement(
    chunks: &[ChunkDescriptor],
    relocated_regions: &[RelocatedRegion],
    usable_frames: &[FrameRun],
    dram_frames: &[FrameRun],
    protected_ranges: &[Range<u64>],
    trampoline_table_pages: usize,
) -> Result<FramePlacementPlan, HibernateError> {
    let page = PhysFrame::SIZE as u64;

    // Build sorted canonical DRAM frame ranges for target validation.
    let mut dram_frame_ranges: Vec<Range<u64>> = dram_frames
        .iter()
        .filter(|run| run.frame_count > 0)
        .map(|run| run.start_phys_frame..run.end_phys_frame())
        .collect();
    dram_frame_ranges.sort_unstable_by_key(|r| r.start);

    // Build sorted chunk target frame ranges and verify every chunk frame lies
    // inside physical DRAM.
    let mut chunk_frame_ranges: Vec<Range<u64>> = Vec::with_capacity(chunks.len());
    for desc in chunks {
        let start_frame = desc.start_phys_frame;
        let end_frame = start_frame.saturating_add(u64::from(desc.frame_count));
        for frame in start_frame..end_frame {
            if !frame_in_sorted_ranges(frame, &dram_frame_ranges) {
                return Err(HibernateError::FirmwareMemoryMapMismatch);
            }
        }
        chunk_frame_ranges.push(start_frame..end_frame);
    }
    chunk_frame_ranges.sort_unstable_by_key(|r| r.start);

    // Expand relocated immutable regions into deduplicated target 4 KiB frames,
    // skipping any frame already owned by `chunks` (for example a boundary page
    // shared between read-only RELRO and writable `.data`).
    let mut relocated_frames: BTreeMap<u64, (u64, usize)> = BTreeMap::new();
    for region in relocated_regions {
        if region.byte_len == 0 {
            continue;
        }
        if !region.boot_src_phys.is_multiple_of(page) || !region.image_dst_phys.is_multiple_of(page)
        {
            return Err(HibernateError::InvalidLayout {
                reason: "relocated region physical address is not page-aligned",
            });
        }
        let frame_count = region.byte_len.div_ceil(page);
        let src_start_frame = region.boot_src_phys / page;
        let dst_start_frame = region.image_dst_phys / page;
        for i in 0..frame_count {
            let dst_frame =
                dst_start_frame
                    .checked_add(i)
                    .ok_or(HibernateError::InvalidLayout {
                        reason: "relocated destination frame overflow",
                    })?;
            if frame_in_sorted_ranges(dst_frame, &chunk_frame_ranges) {
                continue;
            }
            if !frame_in_sorted_ranges(dst_frame, &dram_frame_ranges) {
                return Err(HibernateError::FirmwareMemoryMapMismatch);
            }
            let src_frame =
                src_start_frame
                    .checked_add(i)
                    .ok_or(HibernateError::InvalidLayout {
                        reason: "relocated source frame overflow",
                    })?;
            let remaining = region.byte_len.saturating_sub(i * page);
            let valid_bytes = remaining.min(page) as usize;
            relocated_frames
                .entry(dst_frame)
                .or_insert((src_frame * page, valid_bytes));
        }
    }

    // Protect all boot-kernel protected ranges PLUS every relocated source
    // range so direct writes during decompression never clobber a not-yet-read
    // relocated source frame (even when Boot 1 and Boot 2 partially overlap).
    let mut effective_protected_bytes: Vec<Range<u64>> =
        Vec::with_capacity(protected_ranges.len() + relocated_regions.len());
    effective_protected_bytes.extend(protected_ranges.iter().cloned());
    for region in relocated_regions {
        if region.byte_len > 0 {
            effective_protected_bytes
                .push(region.boot_src_phys..region.boot_src_phys.saturating_add(region.byte_len));
        }
    }
    let protected_frames = normalize_outward_frames(&effective_protected_bytes, page);

    // Collect image target physical frame ranges (chunks + relocated frames).
    let mut image_target_bytes: Vec<Range<u64>> =
        Vec::with_capacity(chunks.len() + relocated_frames.len());
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
    for &dst_frame in relocated_frames.keys() {
        image_target_bytes
            .push(dst_frame.saturating_mul(page)..dst_frame.saturating_add(1).saturating_mul(page));
        if frame_in_sorted_ranges(dst_frame, &protected_frames) {
            displaced_count += 1;
        } else {
            direct_frames += 1;
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
    // 2 dedicated trampoline frames: `trampoline_phys` (params/handoff/ctx/stack)
    // and `trampoline_enter_copy_phys` (safe copy of `V_enter`).
    let total_needed_safe_frames = 2_u64
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

    // 2. Allocate the dedicated 4 KiB trampoline data/stack page and the
    //    dedicated 4 KiB safe copy of the trampoline's entry code page.
    let trampoline_phys =
        take_single_frame(&mut safe_runs).ok_or(HibernateError::InsufficientRestoreMemory {
            needed_frames: total_needed_safe_frames,
            available_frames: total_available_safe_frames,
        })? * page;
    let trampoline_enter_copy_phys =
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

    // 5. Assign direct or safe displaced physical addresses to every relocated
    //    immutable frame (kernel image / `.text` / `.rodata` / `boot_payload`).
    let mut relocated_placements = Vec::with_capacity(relocated_frames.len());
    for (dst_frame, (boot_src_phys, valid_bytes)) in relocated_frames {
        let dst_phys = dst_frame * page;
        let staging_phys = if frame_in_sorted_ranges(dst_frame, &protected_frames) {
            let src_frame = take_single_frame(&mut safe_runs).ok_or(
                HibernateError::InsufficientRestoreMemory {
                    needed_frames: total_needed_safe_frames,
                    available_frames: total_available_safe_frames,
                },
            )?;
            let src_phys = src_frame * page;
            displaced_copies.push(DisplacedFrameCopy { src_phys, dst_phys });
            src_phys
        } else {
            dst_phys
        };
        relocated_placements.push(RelocatedFramePlacement {
            boot_src_phys,
            staging_phys,
            dst_phys,
            valid_bytes,
        });
    }

    Ok(FramePlacementPlan {
        trampoline_phys,
        trampoline_enter_copy_phys,
        trampoline_table_frames,
        copy_table_phys,
        copy_table_pages,
        chunk_placements,
        relocated_placements,
        displaced_copies,
        direct_frames,
    })
}

/// Probes `storage` at sector 0 for a valid hibernate image and, if present,
/// verifies its MAC, bounds, machine identity, chunk table, and every chunk's
/// SHA-256 before decompressing each 4 KiB frame into its planned physical
/// destination through `write_phys_frame` and staging any relocated immutable
/// kernel/payload frames read through `read_phys_frame`.
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
pub fn probe_and_load_hibernate_image<Storage, ReadPhysFrame, WritePhysFrame, PetWatchdog>(
    storage: &mut Storage,
    auth_key: Option<&HibernateAuthKey>,
    expected_identity: &HibernateIdentity,
    machine_max_frames: u64,
    usable_frames: &[FrameRun],
    dram_frames: &[FrameRun],
    boot_kernel_image: Option<KernelSectionRange>,
    protected_ranges: &[Range<u64>],
    trampoline_table_pages: usize,
    mut read_phys_frame: ReadPhysFrame,
    mut write_phys_frame: WritePhysFrame,
    mut pet_watchdog: PetWatchdog,
) -> ResumeProbe
where
    Storage: HibernateStorage,
    ReadPhysFrame: FnMut(u64, &mut [u8; PhysFrame::SIZE]),
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
        dram_frames,
        boot_kernel_image,
        protected_ranges,
        trampoline_table_pages,
        &mut read_phys_frame,
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
fn load_verified_image_body<Storage, ReadPhysFrame, WritePhysFrame, PetWatchdog>(
    storage: &mut Storage,
    header_buf: &[u8; HEADER_BYTES],
    auth_key: Option<&HibernateAuthKey>,
    expected_identity: &HibernateIdentity,
    machine_max_frames: u64,
    usable_frames: &[FrameRun],
    dram_frames: &[FrameRun],
    boot_kernel_image: Option<KernelSectionRange>,
    protected_ranges: &[Range<u64>],
    trampoline_table_pages: usize,
    read_phys_frame: &mut ReadPhysFrame,
    write_phys_frame: &mut WritePhysFrame,
    pet_watchdog: &mut PetWatchdog,
) -> Result<LoadedHibernateImage, HibernateError>
where
    Storage: HibernateStorage,
    ReadPhysFrame: FnMut(u64, &mut [u8; PhysFrame::SIZE]),
    WritePhysFrame: FnMut(u64, &[u8; PhysFrame::SIZE]),
    PetWatchdog: FnMut(),
{
    let auth_key = auth_key.ok_or(HibernateError::NoAuthenticationKey)?;
    let header = HibernateHeader::decode_verified(header_buf, auth_key)?;
    let _table_end = validate_header_bounds(&header, storage.capacity_bytes(), machine_max_frames)?;
    verify_identity(&header.identity, &header.identity_sha256, expected_identity)?;

    let relocated_regions =
        build_relocated_regions(boot_kernel_image, &header.identity, expected_identity)?;

    let table_len =
        usize::try_from(header.chunk_table_len).map_err(|_| HibernateError::TruncatedChunkTable)?;
    let table_bytes = read_unaligned_range(storage, header.chunk_table_offset, table_len)?;
    let chunks = verify_and_parse_chunk_table(&header, &table_bytes, machine_max_frames)?;
    drop(table_bytes);

    let plan = plan_frame_placement(
        &chunks,
        &relocated_regions,
        usable_frames,
        dram_frames,
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

    if !plan.relocated_placements.is_empty() {
        let mut frame_buf = [0_u8; PhysFrame::SIZE];
        for (idx, reloc) in plan.relocated_placements.iter().enumerate() {
            read_phys_frame(reloc.boot_src_phys, &mut frame_buf);
            if reloc.valid_bytes < PhysFrame::SIZE {
                frame_buf[reloc.valid_bytes..].fill(0);
            }
            write_phys_frame(reloc.staging_phys, &frame_buf);
            if idx % 64 == 63 {
                pet_watchdog();
            }
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
