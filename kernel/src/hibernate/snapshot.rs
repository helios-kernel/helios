//! Atomic compressed snapshot assembly into pre-reserved free user frames.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::ops::Range;
use core::time::Duration;

use helios_hal::boot::BootMemoryMetadata;
use helios_hal::cpu::{BspSnapshotContext, Cpu, ResumeHandoff, SnapshotPoint};
use helios_hal::measured_boot::MeasuredBoot;
use helios_hal::pmm::{PhysFrame, PhysFrameRange};
use helios_hal::watchdog::Watchdog;
use sha2::{Digest, Sha256};
use zrip::{CompressContext, CompressError};

use super::HibernateError;
use super::format::{
    CHUNK_DESCRIPTOR_BYTES, ChunkDescriptor, DEFAULT_CHUNK_FRAMES,
    DEFAULT_HIBERNATE_COMPRESSION_LEVEL, FORMAT_VERSION, HEADER_BYTES, HibernateHeader,
    HibernateIdentity,
};
use crate::memory::{BalloonHandle, HibernateReservation, UserMemoryPool};
use crate::{FrozenMachine, HibernateAuthKey, Kernel, kernel_heap_regions};

/// A contiguous run of physical frames `[start_phys_frame, start_phys_frame + frame_count)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameRun {
    pub start_phys_frame: u64,
    pub frame_count: u64,
}

impl FrameRun {
    pub const fn new(start_phys_frame: u64, frame_count: u64) -> Self {
        Self {
            start_phys_frame,
            frame_count,
        }
    }

    pub const fn end_phys_frame(self) -> u64 {
        self.start_phys_frame + self.frame_count
    }
}

/// Destination sink accepting sequential hibernate image bytes and a final
/// fixed-size header write at byte offset 0.
pub trait SnapshotSink {
    fn capacity_bytes(&self) -> usize;
    fn written_bytes(&self) -> usize;
    fn reserve_header(&mut self) -> Result<(), HibernateError>;
    fn append(&mut self, bytes: &[u8]) -> Result<(), HibernateError>;
    fn write_header(&mut self, header: &[u8; HEADER_BYTES]) -> Result<(), HibernateError>;
}

/// Writes an assembled hibernate image across the discontiguous direct-map
/// blocks held by a [`HibernateReservation`].
pub struct ReservationWriter<'a> {
    reservation: HibernateReservation<'a>,
    written: usize,
    block_index: usize,
    block_offset: usize,
}

impl<'a> ReservationWriter<'a> {
    pub fn new(reservation: HibernateReservation<'a>) -> Self {
        Self {
            reservation,
            written: 0,
            block_index: 0,
            block_offset: 0,
        }
    }

    pub fn reservation(&self) -> &HibernateReservation<'a> {
        &self.reservation
    }

    pub fn into_reservation(self) -> HibernateReservation<'a> {
        self.reservation
    }

    /// Copies the assembled image bytes (`0..self.written`) into a contiguous
    /// `Vec<u8>`. Useful for verification and tests.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.written);
        self.for_each_segment(|segment| out.extend_from_slice(segment));
        out
    }

    /// Visits every contiguous slice of written image bytes in order without
    /// allocating.
    pub fn for_each_segment(&self, mut visit: impl FnMut(&[u8])) {
        let mut remaining = self.written;
        for &(ptr, size) in self.reservation.blocks() {
            if remaining == 0 {
                break;
            }
            let take = remaining.min(size);
            // SAFETY: `ptr..ptr + size` is exclusively owned by
            // `self.reservation` and the first `take` bytes were written.
            let slice = unsafe { core::slice::from_raw_parts(ptr.as_ptr(), take) };
            visit(slice);
            remaining -= take;
        }
    }

    /// Copies up to `dst.len()` bytes starting at `byte_offset` from the
    /// assembled image (`0..self.written`) into `dst`, returning the number of
    /// bytes copied.
    pub fn copy_range(&self, byte_offset: usize, dst: &mut [u8]) -> usize {
        if byte_offset >= self.written || dst.is_empty() {
            return 0;
        }
        let available = self.written - byte_offset;
        let to_copy = dst.len().min(available);
        let mut skip = byte_offset;
        let mut copied = 0;
        for &(ptr, size) in self.reservation.blocks() {
            if copied == to_copy {
                break;
            }
            if skip >= size {
                skip -= size;
                continue;
            }
            let block_avail = size - skip;
            let take = block_avail.min(to_copy - copied);
            // SAFETY: `skip < size` and the block is exclusively owned by
            // `self.reservation`.
            let src_ptr = unsafe { ptr.as_ptr().add(skip) };
            // SAFETY: `skip + take <= size` and bytes up to `self.written` are
            // initialized and exclusively owned by `self.reservation`.
            let src = unsafe { core::slice::from_raw_parts(src_ptr, take) };
            dst[copied..copied + take].copy_from_slice(src);
            copied += take;
            skip = 0;
        }
        copied
    }
}

impl SnapshotSink for ReservationWriter<'_> {
    fn capacity_bytes(&self) -> usize {
        self.reservation.capacity_bytes()
    }

    fn written_bytes(&self) -> usize {
        self.written
    }

    fn reserve_header(&mut self) -> Result<(), HibernateError> {
        debug_assert_eq!(self.written, 0);
        let zeros = [0_u8; HEADER_BYTES];
        self.append(&zeros)
    }

    fn append(&mut self, mut bytes: &[u8]) -> Result<(), HibernateError> {
        let needed = self.written.saturating_add(bytes.len());
        let capacity = self.capacity_bytes();
        if needed > capacity {
            return Err(HibernateError::ReservationExhausted {
                needed_bytes: needed,
                capacity_bytes: capacity,
            });
        }
        let blocks = self.reservation.blocks();
        while !bytes.is_empty() {
            let (ptr, block_size) = blocks[self.block_index];
            let avail = block_size - self.block_offset;
            let take = avail.min(bytes.len());
            // SAFETY: `self.block_offset < block_size` and the block is
            // exclusively owned by `self.reservation`.
            let dst = unsafe { ptr.as_ptr().add(self.block_offset) };
            // SAFETY: `self.block_offset + take <= block_size`, so `dst` is
            // valid for `take` non-overlapping writable bytes.
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, take);
            }
            bytes = &bytes[take..];
            self.written += take;
            self.block_offset += take;
            if self.block_offset == block_size {
                self.block_index += 1;
                self.block_offset = 0;
            }
        }
        Ok(())
    }

    fn write_header(&mut self, header: &[u8; HEADER_BYTES]) -> Result<(), HibernateError> {
        if self.written < HEADER_BYTES {
            return Err(HibernateError::ReservationExhausted {
                needed_bytes: HEADER_BYTES,
                capacity_bytes: self.capacity_bytes(),
            });
        }
        let mut remaining = &header[..];
        let mut block_index = 0_usize;
        while !remaining.is_empty() {
            let (ptr, block_size) = self.reservation.blocks()[block_index];
            let take = block_size.min(remaining.len());
            // SAFETY: `take <= block_size` and the block is exclusively owned
            // by `self.reservation`.
            unsafe {
                core::ptr::copy_nonoverlapping(remaining.as_ptr(), ptr.as_ptr(), take);
            }
            remaining = &remaining[take..];
            block_index += 1;
        }
        Ok(())
    }
}

/// Bounded in-memory [`SnapshotSink`] backed by a `Vec<u8>` with an explicit
/// capacity cap, used by host tests and synthetic image construction.
pub struct BoundedVecSink {
    buf: Vec<u8>,
    capacity: usize,
}

impl BoundedVecSink {
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: Vec::new(),
            capacity,
        }
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

impl SnapshotSink for BoundedVecSink {
    fn capacity_bytes(&self) -> usize {
        self.capacity
    }

    fn written_bytes(&self) -> usize {
        self.buf.len()
    }

    fn reserve_header(&mut self) -> Result<(), HibernateError> {
        debug_assert!(self.buf.is_empty());
        if HEADER_BYTES > self.capacity {
            return Err(HibernateError::ReservationExhausted {
                needed_bytes: HEADER_BYTES,
                capacity_bytes: self.capacity,
            });
        }
        self.buf.resize(HEADER_BYTES, 0);
        Ok(())
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), HibernateError> {
        let needed = self.buf.len().saturating_add(bytes.len());
        if needed > self.capacity {
            return Err(HibernateError::ReservationExhausted {
                needed_bytes: needed,
                capacity_bytes: self.capacity,
            });
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    fn write_header(&mut self, header: &[u8; HEADER_BYTES]) -> Result<(), HibernateError> {
        if self.buf.len() < HEADER_BYTES {
            return Err(HibernateError::ReservationExhausted {
                needed_bytes: HEADER_BYTES,
                capacity_bytes: self.capacity,
            });
        }
        self.buf[..HEADER_BYTES].copy_from_slice(header);
        Ok(())
    }
}

/// Normalizes physical byte ranges into sorted, non-overlapping, merged
/// [`FrameRun`]s with every range in `excluded` subtracted.
///
/// Included ranges are rounded outward to full 4 KiB frames; excluded ranges
/// are rounded inward (only frames wholly inside an excluded range are
/// dropped, so a shared boundary frame is never lost).
pub fn normalize_physical_runs(included: &[Range<u64>], excluded: &[Range<u64>]) -> Vec<FrameRun> {
    let page = PhysFrame::SIZE as u64;
    let mut frame_ranges: Vec<Range<u64>> = included
        .iter()
        .filter(|r| r.end > r.start)
        .map(|r| (r.start / page)..r.end.div_ceil(page))
        .collect();
    if frame_ranges.is_empty() {
        return Vec::new();
    }
    frame_ranges.sort_unstable_by_key(|r| r.start);

    // Merge overlapping or adjacent frame ranges.
    let mut merged: Vec<Range<u64>> = Vec::with_capacity(frame_ranges.len());
    for range in frame_ranges {
        if let Some(last) = merged.last_mut()
            && range.start <= last.end
        {
            last.end = last.end.max(range.end);
            continue;
        }
        merged.push(range);
    }

    if excluded.is_empty() {
        return merged
            .into_iter()
            .map(|r| FrameRun::new(r.start, r.end - r.start))
            .collect();
    }

    let mut ex_frames: Vec<Range<u64>> = excluded
        .iter()
        .filter(|r| r.end > r.start)
        .filter_map(|r| {
            let start = r.start.div_ceil(page);
            let end = r.end / page;
            (end > start).then_some(start..end)
        })
        .collect();
    ex_frames.sort_unstable_by_key(|r| r.start);

    let mut out = Vec::with_capacity(merged.len());
    let mut ex_idx = 0_usize;
    for range in merged {
        let mut cursor = range.start;
        while ex_idx < ex_frames.len() && ex_frames[ex_idx].end <= cursor {
            ex_idx += 1;
        }
        let mut scan = ex_idx;
        while scan < ex_frames.len() && ex_frames[scan].start < range.end {
            let ex = &ex_frames[scan];
            if ex.start > cursor {
                out.push(FrameRun::new(cursor, ex.start - cursor));
            }
            if ex.end > cursor {
                cursor = ex.end;
            }
            if cursor >= range.end {
                break;
            }
            scan += 1;
        }
        if cursor < range.end {
            out.push(FrameRun::new(cursor, range.end - cursor));
        }
    }
    out
}

/// Parameters controlling snapshot compression and chunking.
#[derive(Clone, Copy, Debug)]
pub struct SnapshotConfig {
    pub chunk_frames: u32,
    pub compression_level: i32,
    pub image_id: [u8; 16],
}

impl SnapshotConfig {
    pub const fn new(image_id: [u8; 16]) -> Self {
        Self {
            chunk_frames: DEFAULT_CHUNK_FRAMES,
            compression_level: DEFAULT_HIBERNATE_COMPRESSION_LEVEL,
            image_id,
        }
    }
}

/// Inputs to [`encode_snapshot`].
#[derive(Clone, Copy, Debug)]
pub struct EncodeParams<'a> {
    pub auth_key: Option<&'a HibernateAuthKey>,
    pub identity: HibernateIdentity,
    pub machine_max_frames: u64,
    pub bsp_context: BspSnapshotContext,
    pub config: SnapshotConfig,
}

/// Encodes a verified, compressed hibernate image from `frame_runs` into
/// `sink`, reading frame contents through `read_frame`.
///
/// Refuses immediately with [`HibernateError::NoAuthenticationKey`] when
/// `params.auth_key` is `None`. Calls `pet_watchdog` once per compressed
/// chunk so large snapshots never trip the hardware watchdog while frozen.
pub fn encode_snapshot<Sink, ReadFrame, PetWatchdog>(
    params: EncodeParams<'_>,
    frame_runs: &[FrameRun],
    sink: &mut Sink,
    mut read_frame: ReadFrame,
    mut pet_watchdog: PetWatchdog,
) -> Result<HibernateHeader, HibernateError>
where
    Sink: SnapshotSink,
    ReadFrame: FnMut(u64, &mut [u8; PhysFrame::SIZE]),
    PetWatchdog: FnMut(),
{
    let EncodeParams {
        auth_key,
        identity,
        machine_max_frames,
        bsp_context,
        config,
    } = params;
    let auth_key = auth_key.ok_or(HibernateError::NoAuthenticationKey)?;
    if config.chunk_frames == 0 {
        return Err(HibernateError::InvalidHeaderField {
            reason: "chunk_frames must be non-zero",
        });
    }

    let max_chunk_bytes = (config.chunk_frames as usize) * PhysFrame::SIZE;
    let mut raw_buf = vec![0_u8; max_chunk_bytes];
    let mut comp_buf = vec![0_u8; zrip::compress_bound(max_chunk_bytes)];
    let mut compressor = CompressContext::new(config.compression_level).map_err(|_| {
        HibernateError::CompressFailed {
            chunk_index: 0,
            detail: "invalid zstd compression level",
        }
    })?;

    sink.reserve_header()?;

    let mut descriptors = Vec::new();
    let mut total_frames = 0_u64;
    let mut payload_bytes = 0_u64;

    for &run in frame_runs {
        if run.frame_count == 0 {
            continue;
        }
        let end_frame = run.start_phys_frame.checked_add(run.frame_count).ok_or(
            HibernateError::FrameCountExceedsMachine {
                image_frames: u64::MAX,
                machine_frames: machine_max_frames,
            },
        )?;
        if end_frame > machine_max_frames {
            return Err(HibernateError::FrameCountExceedsMachine {
                image_frames: end_frame,
                machine_frames: machine_max_frames,
            });
        }

        let mut offset_in_run = 0_u64;
        while offset_in_run < run.frame_count {
            let chunk_frames =
                (run.frame_count - offset_in_run).min(u64::from(config.chunk_frames)) as u32;
            let start_frame = run.start_phys_frame + offset_in_run;
            let uncompressed_len = (chunk_frames as usize) * PhysFrame::SIZE;

            for i in 0..chunk_frames as usize {
                let dst: &mut [u8; PhysFrame::SIZE] = (&mut raw_buf
                    [i * PhysFrame::SIZE..(i + 1) * PhysFrame::SIZE])
                    .try_into()
                    .unwrap();
                read_frame(start_frame + i as u64, dst);
            }

            let chunk_index = descriptors.len() as u32;
            let compressed_len = compressor
                .compress_into(&raw_buf[..uncompressed_len], &mut comp_buf)
                .map_err(|err| HibernateError::CompressFailed {
                    chunk_index,
                    detail: match err {
                        CompressError::OutputTooSmall => "compression bound exceeded",
                        _ => "zstd encoder error",
                    },
                })?;

            let compressed_slice = &comp_buf[..compressed_len];
            let chunk_sha256: [u8; 32] = Sha256::digest(compressed_slice).into();
            let data_offset = sink.written_bytes() as u64;
            sink.append(compressed_slice)?;

            descriptors.push(ChunkDescriptor {
                start_phys_frame: start_frame,
                frame_count: chunk_frames,
                compressed_len: compressed_len as u32,
                uncompressed_len: uncompressed_len as u32,
                flags: 0,
                data_offset,
                sha256: chunk_sha256,
            });
            total_frames += u64::from(chunk_frames);
            payload_bytes += compressed_len as u64;
            offset_in_run += u64::from(chunk_frames);
            pet_watchdog();
        }
    }

    // Stream chunk descriptor table after compressed payloads and hash it.
    let chunk_table_offset = sink.written_bytes() as u64;
    let mut table_hasher = Sha256::new();
    for desc in &descriptors {
        let encoded = desc.encode();
        table_hasher.update(encoded);
        sink.append(&encoded)?;
    }
    let chunk_table_sha256: [u8; 32] = table_hasher.finalize().into();
    let chunk_table_len = (descriptors.len() as u64) * (CHUNK_DESCRIPTOR_BYTES as u64);
    let total_image_bytes = sink.written_bytes() as u64;

    let identity_sha256 = identity.digest();
    let header = HibernateHeader {
        version: FORMAT_VERSION,
        flags: 0,
        image_id: config.image_id,
        identity,
        identity_sha256,
        frame_size: PhysFrame::SIZE as u32,
        chunk_frames: config.chunk_frames,
        total_frames,
        machine_max_frames,
        chunk_count: descriptors.len() as u32,
        chunk_table_offset,
        chunk_table_len,
        chunk_table_sha256,
        payload_bytes,
        total_image_bytes,
        bsp_context,
    };

    let signed_header = header.encode_signed(auth_key);
    sink.write_header(&signed_header)?;
    Ok(header)
}

/// Collects every physical frame run that must be saved in an atomic
/// snapshot of the live machine:
/// - allocated frames from `user_pool` (after draining all frame slabs,
///   excluding balloon inflated runs and the hibernate reservation itself),
/// - every claimed kernel-heap region (`kernel_heap_regions()`),
/// - kernel writable image sections (`data`, `bss`, optional `uninit` and
///   `stack`),
/// - bootloader-reclaimable ranges, and
/// - the device tree blob (when present).
pub fn collect_snapshot_physical_runs(
    user_pool: &UserMemoryPool,
    boot_memory: &BootMemoryMetadata,
    balloon: Option<&BalloonHandle>,
    reservation_ranges: &[PhysFrameRange],
) -> Vec<FrameRun> {
    let offset = boot_memory.physical_memory_offset as u64;
    let direct_to_phys = |addr: usize| -> u64 {
        (addr as u64)
            .checked_sub(offset)
            .unwrap_or_else(|| panic!("direct-map address {addr:#x} lies below offset {offset:#x}"))
    };

    let mut excluded_direct = Vec::new();
    if let Some(balloon) = balloon {
        excluded_direct.extend(balloon.inflated_runs());
    }
    excluded_direct.extend_from_slice(reservation_ranges);

    let mut included_phys = Vec::new();

    // 1. User pool (buddy metadata, live user allocations, per-processor
    //    `NodeArenas`, and lent chunks), minus slab caches, balloon, and
    //    reservation.
    for range in user_pool.allocated_ranges(&excluded_direct) {
        included_phys.push(direct_to_phys(range.start)..direct_to_phys(range.end));
    }

    // 2. Kernel heap regions (initial boot share + every growth chunk).
    for (start, end) in kernel_heap_regions() {
        included_phys.push(direct_to_phys(start)..direct_to_phys(end));
    }

    // 3. Kernel writable image sections.
    let sections = &boot_memory.kernel_sections;
    for section in [
        Some(sections.data),
        Some(sections.bss),
        sections.uninit,
        sections.stack,
    ]
    .into_iter()
    .flatten()
    {
        if !section.is_empty() {
            included_phys.push(section.physical_start..section.physical_end());
        }
    }

    // 4. Bootloader-reclaimable ranges (e.g. bootloader page tables).
    for range in &boot_memory.bootloader_reclaimable {
        if !range.is_empty() {
            included_phys.push(range.start..range.end);
        }
    }

    // 5. Device tree blob, if present.
    if let Some(dtb) = boot_memory.device_tree_blob
        && !dtb.is_empty()
    {
        included_phys.push(dtb.start..dtb.end);
    }

    // Convert exclusions to physical ranges as well so kernel heap or
    // overlapping ranges never accidentally re-include excluded frames.
    let excluded_phys: Vec<Range<u64>> = excluded_direct
        .iter()
        .filter(|run| !run.is_empty())
        .map(|run| {
            let start = direct_to_phys(run.start.phys_addr());
            start..start + run.byte_size() as u64
        })
        .collect();

    normalize_physical_runs(&included_phys, &excluded_phys)
}

/// Completed atomic hibernate snapshot still holding the frozen machine
/// and its reserved compressed image bytes.
///
/// Dropping `CapturedSnapshot` thaws the machine and releases the reserved
/// user-memory frames back to the pool.
pub struct CapturedSnapshot<'pool, CpuImpl: Cpu + Clone, WatchdogImpl: Watchdog> {
    pub header: HibernateHeader,
    pub writer: ReservationWriter<'pool>,
    pub frozen: FrozenMachine<CpuImpl, WatchdogImpl>,
}

/// Outcome of [`capture_atomic_snapshot`], reflecting the double-return BSP
/// snapshot point.
pub enum SnapshotOutcome<'pool, CpuImpl: Cpu + Clone, WatchdogImpl: Watchdog> {
    /// Initial capture succeeded; the compressed, authenticated image sits in
    /// `CapturedSnapshot::writer` while `CapturedSnapshot::frozen` holds the
    /// machine still so the caller can write the image to storage.
    Captured(Box<CapturedSnapshot<'pool, CpuImpl, WatchdogImpl>>),
    /// Control resumed from a restored hibernate image on the BSP, carrying
    /// the boot kernel's [`ResumeHandoff`].
    Resumed(ResumeHandoff),
}

/// Parameters for [`capture_atomic_snapshot`].
pub struct AtomicSnapshotParams<'a> {
    pub balloon: Option<&'a BalloonHandle>,
    pub auth_key: Option<&'a HibernateAuthKey>,
    pub identity: HibernateIdentity,
    pub reservation_bytes: usize,
    pub arrival_deadline: Duration,
    pub config: SnapshotConfig,
}

/// Atomically captures a compressed, HMAC-authenticated hibernate snapshot
/// into pre-reserved free user frames.
///
/// # Ordering and cleanup
///
/// 1. Refuses immediately if `params.auth_key` is `None`
///    (`SeedSource::Ephemeral`) or `kernel.boot_memory()` is missing.
/// 2. Reserves `params.reservation_bytes` of free frames from `user_pool`
///    **before** freezing the machine.
/// 3. Freezes every online processor via [`Kernel::freeze`].
/// 4. Captures the BSP double-return state via [`Cpu::capture_bsp_state`].
///    On resume, drops the reservation and thaws cleanly, returning
///    [`SnapshotOutcome::Resumed`].
/// 5. Collects all reachable physical frames, compresses them with `zrip`
///    into the reserved frames while petting the watchdog, and signs the
///    header with `auth_key`.
/// 6. If compression exceeds the reserved frames (or any error occurs),
///    `frozen` is dropped (thawing all processors) and `reservation` is
///    dropped (returning every reserved frame) before returning the error.
pub async fn capture_atomic_snapshot<'pool, CpuImpl, WatchdogImpl, MeasuredBootImpl>(
    kernel: &Kernel<CpuImpl, WatchdogImpl, MeasuredBootImpl>,
    cpu: &CpuImpl,
    user_pool: &'pool UserMemoryPool,
    params: AtomicSnapshotParams<'_>,
    interrupt_guests: impl FnOnce(),
) -> Result<SnapshotOutcome<'pool, CpuImpl, WatchdogImpl>, HibernateError>
where
    CpuImpl: Cpu + Clone,
    WatchdogImpl: Watchdog + Clone,
    MeasuredBootImpl: MeasuredBoot,
{
    let AtomicSnapshotParams {
        balloon,
        auth_key,
        identity,
        reservation_bytes,
        arrival_deadline,
        config,
    } = params;
    let auth_key = auth_key.ok_or(HibernateError::NoAuthenticationKey)?;
    let boot_memory = kernel
        .boot_memory()
        .ok_or(HibernateError::MissingBootMemoryMetadata)?;

    // Reserve free user frames BEFORE freezing so snapshot encoding never
    // needs to grow memory while the machine is stopped.
    let reservation = user_pool
        .reserve_hibernate_frames(reservation_bytes)
        .map_err(|oom| HibernateError::ReservationUnavailable {
            requested_bytes: oom.requested_bytes,
            available_bytes: oom.available_bytes,
        })?;
    let reservation_ranges = reservation.frame_ranges();
    let mut writer = ReservationWriter::new(reservation);

    // Freeze all other processors at a scheduler boundary.
    let frozen = kernel.freeze(arrival_deadline, interrupt_guests).await?;

    // Double-return snapshot point on the BSP.
    let mut bsp_context = BspSnapshotContext::empty();
    match cpu.capture_bsp_state(&mut bsp_context)? {
        SnapshotPoint::Resumed(handoff) => {
            // Returning here drops `frozen` (thawing all processors) and
            // `writer` (returning reserved frames to the user pool).
            return Ok(SnapshotOutcome::Resumed(handoff));
        }
        SnapshotPoint::Captured => {}
    }

    let frame_runs =
        collect_snapshot_physical_runs(user_pool, boot_memory, balloon, &reservation_ranges);
    let max_phys = boot_memory.max_physical_address();
    let machine_max_frames = max_phys.div_ceil(PhysFrame::SIZE as u64);
    let direct_offset = boot_memory.physical_memory_offset;

    let header = encode_snapshot(
        EncodeParams {
            auth_key: Some(auth_key),
            identity,
            machine_max_frames,
            bsp_context,
            config,
        },
        &frame_runs,
        &mut writer,
        |phys_frame, dst| {
            let direct_addr = (phys_frame as usize) * PhysFrame::SIZE + direct_offset;
            // SAFETY: `phys_frame` came from `collect_snapshot_physical_runs`
            // while the machine is frozen (`FrozenMachine`), and every live
            // RAM frame is mapped readable at `phys + physical_memory_offset`.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    core::ptr::with_exposed_provenance::<u8>(direct_addr),
                    dst.as_mut_ptr(),
                    PhysFrame::SIZE,
                );
            }
        },
        || frozen.pet_watchdog(),
    )?;

    Ok(SnapshotOutcome::Captured(Box::new(CapturedSnapshot {
        header,
        writer,
        frozen,
    })))
}
