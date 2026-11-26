//! Hibernate disk persistence, crash-consistent write ordering, and power-off
//! orchestration.
//!
//! # On-disk layout (512-byte sector aligned)
//!
//! ```text
//! Offset 0 .. 4096    (sectors 0..8)   HibernateHeader (4096B, HMAC-SHA256 authenticated)
//! Offset 4096 .. end  (sectors 8..)    Compressed chunks + chunk descriptor table,
//!                                      zero-padded to a sector boundary
//! ```
//!
//! # Crash-consistency write order
//!
//! 1. Pre-freeze capacity check rejects an undersized disk **before** freezing
//!    the machine or reserving user memory.
//! 2. After freezing, quiescing all devices, and capturing the compressed
//!    snapshot into reserved user frames, **only** the hibernate disk is
//!    brought back online (`HibernateStorage::reinitialize_for_write`).
//! 3. All compressed chunks and the chunk descriptor table (offsets `>= 4096`)
//!    are written in sector-aligned batches while petting the hardware watchdog
//!    between writes.
//! 4. `HibernateStorage::flush()` is issued and MUST succeed **before** sector
//!    0 (`HibernateHeader`) is written.
//! 5. `HibernateHeader` is written to sectors `0..8` (`0..4096`), followed by
//!    a second `HibernateStorage::flush()`.
//! 6. Only after the final flush succeeds is the machine powered off.
//! 7. On any failure after freeze, the frame reservation is dropped, all
//!    devices are reinitialized (`virtio-iommu` first when present), the
//!    machine is thawed, and the typed error is returned to the caller.

use alloc::vec;

use helios_hal::cpu::{BspSnapshotContext, Cpu, SnapshotPoint};
use helios_hal::fs::{BlockBuffer, BlockDevice};
use helios_hal::io::IoError;
use helios_hal::measured_boot::MeasuredBoot;
use helios_hal::pmm::PhysFrame;
use helios_hal::watchdog::Watchdog;
use helios_virtio::{PolledBlockError, QueueAffinity, VirtioBlockResource, VirtioTransport};
use thiserror::Error;

use super::HibernateError;
use super::format::{HEADER_BYTES, HibernateHeader};
use super::snapshot::{
    AtomicSnapshotParams, EncodeParams, ReservationWriter, SnapshotSink,
    collect_snapshot_physical_runs, encode_snapshot,
};
use crate::Kernel;
use crate::memory::UserMemoryPool;

/// Canonical 512-byte sector size for the hibernate on-disk layout.
pub const HIBERNATE_SECTOR_BYTES: usize = 512;

/// Number of 512-byte sectors occupied by [`HibernateHeader`] at offset 0.
pub const HIBERNATE_HEADER_SECTORS: u64 = (HEADER_BYTES / HIBERNATE_SECTOR_BYTES) as u64;

/// Maximum staging buffer size per polled disk write batch (64 KiB).
const MAX_WRITE_BATCH_BYTES: usize = 64 * 1024;

/// Typed errors returned by [`HibernateStorage`] implementations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum HibernateStorageError {
    /// Storage reported a zero, non-power-of-two, or non-header-dividing sector size.
    #[error("hibernate storage reported invalid sector size {sector_size} bytes")]
    InvalidSectorSize { sector_size: usize },

    /// Reinitializing the hibernate block device for polled writes failed.
    #[error("hibernate storage reinitialization failed: {detail}")]
    Reinitialize { detail: &'static str },

    /// Writing sectors to the hibernate disk failed.
    #[error("hibernate storage write at sector {start_sector} ({byte_len} bytes) failed: {error}")]
    Write {
        start_sector: u64,
        byte_len: usize,
        error: IoError,
    },

    /// Reading sectors from the hibernate disk failed.
    #[error("hibernate storage read at sector {start_sector} ({byte_len} bytes) failed: {error}")]
    Read {
        start_sector: u64,
        byte_len: usize,
        error: IoError,
    },

    /// Flushing volatile device caches to durable storage failed.
    #[error("hibernate storage flush failed: {error}")]
    Flush { error: IoError },

    /// Polled storage command timed out while waiting for device completion.
    #[error("hibernate storage command timed out waiting for device completion")]
    TimedOut,

    /// Storage queue lock was held while the machine was frozen.
    #[error("hibernate storage queue was busy while frozen")]
    QueueBusy,
}

/// Typed errors returned by [`HibernateDeviceController`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum HibernateDeviceError {
    /// Stopping a device before snapshot capture failed.
    #[error("failed to quiesce device {device}: {detail}")]
    Quiesce {
        device: &'static str,
        detail: &'static str,
    },

    /// Bringing a device back online after snapshot abort or resume failed.
    #[error("failed to reinitialize device {device}: {detail}")]
    Reinitialize {
        device: &'static str,
        detail: &'static str,
    },
}

/// Outcome of [`hibernate_to_disk`] and [`hibernate_to_disk_with_power_off`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HibernateOutcome {
    /// The hibernate image was written, flushed, committed via sector 0, and
    /// flushed again before invoking the power-off action. On real hardware
    /// [`Cpu::shutdown`] diverges and never returns.
    PoweredOff {
        /// Exact unpadded serialized hibernate image length (`header.total_image_bytes`).
        image_bytes: u64,
        /// Total sector-aligned bytes written to the hibernate disk.
        written_bytes: u64,
        /// Number of compressed chunks written.
        chunk_count: u32,
    },
    /// Execution resumed from a restored hibernate image on the bootstrap
    /// processor; reserved frames were released, all devices were reinitialized,
    /// and the machine has thawed.
    Resumed,
}

/// Static-dispatch synchronous block storage contract for hibernate image
/// persistence and early-boot verification.
///
/// Every method runs synchronously while the machine is frozen (no executor
/// tasks or device interrupts active) or during early-boot resume.
pub trait HibernateStorage {
    /// Total byte capacity of the hibernate disk.
    fn capacity_bytes(&self) -> u64;

    /// Sector size in bytes used to address [`Self::write_sectors`] and
    /// [`Self::read_sectors`]. Must be a power of two that divides
    /// [`HEADER_BYTES`] (512 bytes for standard virtio-blk).
    fn sector_size(&self) -> usize;

    /// Maximum bytes to pass in a single [`Self::write_sectors`] call.
    /// Rounded down to a multiple of [`Self::sector_size`] by the writer.
    fn max_write_bytes(&self) -> usize {
        MAX_WRITE_BATCH_BYTES
    }

    /// Brings **only** the hibernate block device back online after devices
    /// have been quiesced, without waking any other device.
    fn reinitialize_for_write(&mut self) -> Result<(), HibernateStorageError>;

    /// Synchronously writes `data` starting at `start_sector` (in units of
    /// [`Self::sector_size`]). `data.len()` is a non-zero multiple of
    /// [`Self::sector_size`].
    fn write_sectors(
        &mut self,
        start_sector: u64,
        data: &[u8],
    ) -> Result<(), HibernateStorageError>;

    /// Synchronously flushes volatile device caches to durable storage.
    fn flush(&mut self) -> Result<(), HibernateStorageError>;

    /// Synchronously reads into `dst` starting at `start_sector` (in units of
    /// [`Self::sector_size`]). `dst.len()` is a non-zero multiple of
    /// [`Self::sector_size`].
    fn read_sectors(
        &mut self,
        start_sector: u64,
        dst: &mut [u8],
    ) -> Result<(), HibernateStorageError>;

    /// Overwrites offset `0..HEADER_BYTES` (sectors `0..8` for 512-byte
    /// sectors) with zeroes and flushes so the image cannot be resumed again.
    fn invalidate_header(&mut self) -> Result<(), HibernateStorageError> {
        invalidate_hibernate_header(self)
    }
}

/// Static-dispatch platform device lifecycle controller for hibernation.
///
/// # Ordering contract
///
/// When a platform carries `virtio-iommu`, [`Self::reinitialize_all`] MUST
/// reinitialize `virtio-iommu` **first** so every DMA domain and translation
/// mapping is restored before any DMA-capable endpoint (`virtio-blk`,
/// `virtio-net`, `virtio-gpu`, etc.) is brought back online.
pub trait HibernateDeviceController {
    /// Quiesces every platform device while the machine is frozen, draining
    /// in-flight DMA request queues before RAM is snapshotted.
    fn quiesce_all(&mut self) -> Result<(), HibernateDeviceError>;

    /// Reinitializes every platform device while the machine is still frozen
    /// (`virtio-iommu` first when present), before thawing.
    fn reinitialize_all(&mut self) -> Result<(), HibernateDeviceError>;
}

/// Static-dispatch [`HibernateStorage`] adapter over a [`VirtioBlockResource`]
/// using polled queue-0 I/O.
pub struct VirtioBlockHibernateStorage<T, C, B, E>
where
    T: VirtioTransport,
    C: QueueAffinity,
    B: BlockBuffer,
    E: FnMut() -> bool,
{
    device: VirtioBlockResource<T, C, B>,
    expired: E,
}

impl<T, C, B, E> VirtioBlockHibernateStorage<T, C, B, E>
where
    T: VirtioTransport,
    C: QueueAffinity,
    B: BlockBuffer,
    E: FnMut() -> bool,
{
    pub fn new(device: VirtioBlockResource<T, C, B>, expired: E) -> Self {
        Self { device, expired }
    }

    pub fn device(&self) -> &VirtioBlockResource<T, C, B> {
        &self.device
    }

    fn virtio_sector(&self, start_sector: u64) -> Result<u64, HibernateStorageError> {
        let sector_size = self.sector_size();
        validate_sector_size(sector_size)?;
        let scale = (sector_size / helios_virtio::SECTOR_SIZE) as u64;
        start_sector
            .checked_mul(scale)
            .ok_or(HibernateStorageError::Write {
                start_sector,
                byte_len: 0,
                error: IoError::OutOfBounds,
            })
    }
}

impl<T, C, B, E> HibernateStorage for VirtioBlockHibernateStorage<T, C, B, E>
where
    T: VirtioTransport,
    C: QueueAffinity,
    B: BlockBuffer,
    E: FnMut() -> bool,
{
    fn capacity_bytes(&self) -> u64 {
        self.device.geometry().capacity_bytes()
    }

    fn sector_size(&self) -> usize {
        self.device.geometry().logical_block_bytes
    }

    fn max_write_bytes(&self) -> usize {
        self.device
            .geometry()
            .max_transfer_bytes
            .min(MAX_WRITE_BATCH_BYTES)
    }

    fn reinitialize_for_write(&mut self) -> Result<(), HibernateStorageError> {
        self.device
            .reinitialize()
            .map(|_| ())
            .map_err(|_| HibernateStorageError::Reinitialize {
                detail: "virtio-blk reinitialize failed",
            })
    }

    fn write_sectors(
        &mut self,
        start_sector: u64,
        data: &[u8],
    ) -> Result<(), HibernateStorageError> {
        let virtio_sector = self.virtio_sector(start_sector)?;
        self.device
            .write_sectors_polled(virtio_sector, data, &mut self.expired)
            .map_err(|err| map_polled_write_error(start_sector, data.len(), err))
    }

    fn flush(&mut self) -> Result<(), HibernateStorageError> {
        self.device
            .flush_polled(&mut self.expired)
            .map_err(|err| match err {
                PolledBlockError::Io(error) => HibernateStorageError::Flush { error },
                PolledBlockError::QueueBusy => HibernateStorageError::QueueBusy,
                PolledBlockError::TimedOut => HibernateStorageError::TimedOut,
            })
    }

    fn read_sectors(
        &mut self,
        start_sector: u64,
        dst: &mut [u8],
    ) -> Result<(), HibernateStorageError> {
        let virtio_sector = self.virtio_sector(start_sector)?;
        self.device
            .read_sectors_polled(virtio_sector, dst, &mut self.expired)
            .map_err(|err| match err {
                PolledBlockError::Io(error) => HibernateStorageError::Read {
                    start_sector,
                    byte_len: dst.len(),
                    error,
                },
                PolledBlockError::QueueBusy => HibernateStorageError::QueueBusy,
                PolledBlockError::TimedOut => HibernateStorageError::TimedOut,
            })
    }
}

fn map_polled_write_error(
    start_sector: u64,
    byte_len: usize,
    err: PolledBlockError,
) -> HibernateStorageError {
    match err {
        PolledBlockError::Io(error) => HibernateStorageError::Write {
            start_sector,
            byte_len,
            error,
        },
        PolledBlockError::QueueBusy => HibernateStorageError::QueueBusy,
        PolledBlockError::TimedOut => HibernateStorageError::TimedOut,
    }
}

/// Validates that `sector_size` is a non-zero power of two that evenly divides
/// [`HEADER_BYTES`] (4096 bytes).
pub fn validate_sector_size(sector_size: usize) -> Result<(), HibernateStorageError> {
    if sector_size == 0
        || !sector_size.is_power_of_two()
        || !HEADER_BYTES.is_multiple_of(sector_size)
    {
        return Err(HibernateStorageError::InvalidSectorSize { sector_size });
    }
    Ok(())
}

/// Computes the minimum hibernate disk capacity in bytes required to hold an
/// image of up to `reservation_bytes`, rounded up to `sector_size`.
pub fn required_disk_bytes(
    reservation_bytes: usize,
    sector_size: usize,
) -> Result<u64, HibernateStorageError> {
    validate_sector_size(sector_size)?;
    let min_bytes = reservation_bytes.max(HEADER_BYTES) as u64;
    Ok(min_bytes.next_multiple_of(sector_size as u64))
}

/// Overwrites byte offset `0..HEADER_BYTES` (sectors `0..8` for 512-byte
/// sectors) with zeroes and flushes the device so no future boot can resume
/// from an invalidated or already-consumed hibernate image.
pub fn invalidate_hibernate_header<Storage: HibernateStorage + ?Sized>(
    storage: &mut Storage,
) -> Result<(), HibernateStorageError> {
    validate_sector_size(storage.sector_size())?;
    let zeros = [0_u8; HEADER_BYTES];
    storage.write_sectors(0, &zeros)?;
    storage.flush()
}

/// Writes an already-encoded hibernate image from `writer` to `storage`
/// following the strict crash-consistent write ordering:
///
/// 1. Validates layout and disk capacity.
/// 2. Calls `storage.reinitialize_for_write()` to bring **only** the hibernate
///    disk back up, then re-checks capacity.
/// 3. Streams bytes `[HEADER_BYTES .. total_image_bytes]` (compressed chunks +
///    chunk descriptor table), zero-padded to a sector boundary, starting at
///    offset `HEADER_BYTES` (sector `8` for 512-byte sectors), calling
///    `pet_watchdog` between writes.
/// 4. Calls `storage.flush()` and requires it to succeed BEFORE sector 0 is
///    written.
/// 5. Writes the signed 4096-byte `HibernateHeader` at sector 0 (`0..4096`).
/// 6. Calls `storage.flush()` again so the header commit is durable before
///    power-off.
///
/// Returns the total sector-aligned byte count written on success.
pub fn write_image_to_storage<Storage, PetWatchdog>(
    header: &HibernateHeader,
    writer: &ReservationWriter<'_>,
    storage: &mut Storage,
    mut pet_watchdog: PetWatchdog,
) -> Result<u64, HibernateError>
where
    Storage: HibernateStorage,
    PetWatchdog: FnMut(),
{
    let sector_size = storage.sector_size();
    validate_sector_size(sector_size)?;

    let total_image_bytes = header.total_image_bytes;
    let written_bytes = writer.written_bytes() as u64;
    if total_image_bytes < HEADER_BYTES as u64 || total_image_bytes != written_bytes {
        return Err(HibernateError::InvalidLayout {
            reason: "hibernate header total_image_bytes does not match serialized snapshot length",
        });
    }
    let padded_bytes = total_image_bytes.next_multiple_of(sector_size as u64);
    let disk_bytes = storage.capacity_bytes();
    if disk_bytes < padded_bytes {
        return Err(HibernateError::DiskTooSmall {
            required_bytes: padded_bytes,
            disk_bytes,
        });
    }

    // Bring ONLY the hibernate block device back online for polled writes.
    storage.reinitialize_for_write()?;

    // Re-check disk capacity after reinitialization: a device is untrusted.
    let post_reinit_bytes = storage.capacity_bytes();
    if post_reinit_bytes < padded_bytes {
        return Err(HibernateError::DiskTooSmall {
            required_bytes: padded_bytes,
            disk_bytes: post_reinit_bytes,
        });
    }

    let mut header_bytes = [0_u8; HEADER_BYTES];
    let copied_header = writer.copy_range(0, &mut header_bytes);
    if copied_header != HEADER_BYTES {
        return Err(HibernateError::InvalidLayout {
            reason: "hibernate snapshot writer did not contain a complete header",
        });
    }

    // Stream compressed chunks + chunk descriptor table starting at offset 4096
    // (sector 8 for 512-byte sectors), zero-padding the final partial sector.
    let batch_bytes = storage
        .max_write_bytes()
        .min(MAX_WRITE_BATCH_BYTES)
        .max(sector_size)
        / sector_size
        * sector_size;
    let mut staging = vec![0_u8; batch_bytes];

    let total_image_usize =
        usize::try_from(total_image_bytes).map_err(|_| HibernateError::InvalidLayout {
            reason: "hibernate image length exceeds addressable usize",
        })?;
    let padded_usize =
        usize::try_from(padded_bytes).map_err(|_| HibernateError::InvalidLayout {
            reason: "padded hibernate image length exceeds addressable usize",
        })?;

    let mut byte_offset = HEADER_BYTES;
    while byte_offset < padded_usize {
        let this_len = (padded_usize - byte_offset).min(batch_bytes);
        debug_assert!(this_len.is_multiple_of(sector_size));
        let buf = &mut staging[..this_len];
        let payload_avail = total_image_usize.saturating_sub(byte_offset).min(this_len);
        if payload_avail > 0 {
            let copied = writer.copy_range(byte_offset, &mut buf[..payload_avail]);
            debug_assert_eq!(copied, payload_avail);
        }
        if payload_avail < this_len {
            buf[payload_avail..].fill(0);
        }
        let start_sector = (byte_offset / sector_size) as u64;
        storage.write_sectors(start_sector, buf)?;
        pet_watchdog();
        byte_offset += this_len;
    }

    // Pre-header durability barrier: all compressed chunks and the chunk
    // descriptor table MUST reach durable storage BEFORE sector 0 is written.
    storage.flush()?;
    pet_watchdog();

    // Commit point: write the authenticated 4096-byte header to sectors 0..8.
    storage.write_sectors(0, &header_bytes)?;
    pet_watchdog();

    // Final durability barrier before powering off the machine.
    storage.flush()?;
    pet_watchdog();

    Ok(padded_bytes)
}

/// Reinitializes all platform devices on an error recovery path while still
/// frozen, logging any secondary failure without masking the primary error.
fn recover_devices_after_abort<Devices: HibernateDeviceController>(devices: &mut Devices) {
    if let Err(reinit_error) = devices.reinitialize_all() {
        tracing::error!(
            error = %reinit_error,
            "failed to reinitialize devices while recovering from aborted hibernate"
        );
    }
}

/// Orchestrates the complete hibernate-to-disk workflow and invokes `power_off`
/// only after the final header flush succeeds while the machine is still frozen.
///
/// Production callers should use [`hibernate_to_disk`], which passes
/// `|| cpu.shutdown()`. Tests that cannot exit the host process use this
/// entry point with a recording power-off hook.
#[expect(
    clippy::too_many_arguments,
    reason = "explicit static-dispatch dependencies keep the kernel free of global state and dynamic dispatch"
)]
pub async fn hibernate_to_disk_with_power_off<
    CpuImpl,
    WatchdogImpl,
    MeasuredBootImpl,
    Storage,
    Devices,
    InterruptGuests,
    PowerOff,
>(
    kernel: &Kernel<CpuImpl, WatchdogImpl, MeasuredBootImpl>,
    cpu: &CpuImpl,
    user_pool: &UserMemoryPool,
    params: AtomicSnapshotParams<'_>,
    storage: &mut Storage,
    devices: &mut Devices,
    interrupt_guests: InterruptGuests,
    power_off: PowerOff,
) -> Result<HibernateOutcome, HibernateError>
where
    CpuImpl: Cpu + Clone,
    WatchdogImpl: Watchdog + Clone,
    MeasuredBootImpl: MeasuredBoot,
    Storage: HibernateStorage,
    Devices: HibernateDeviceController,
    InterruptGuests: FnOnce(),
    PowerOff: FnOnce(),
{
    let AtomicSnapshotParams {
        balloon,
        auth_key,
        identity,
        reservation_bytes,
        arrival_deadline,
        config,
    } = params;

    // 1. Verify authentication key and boot metadata exist before doing work.
    let auth_key = auth_key.ok_or(HibernateError::NoAuthenticationKey)?;
    let boot_memory = kernel
        .boot_memory()
        .ok_or(HibernateError::MissingBootMemoryMetadata)?;

    // 2. Pre-freeze disk capacity check: refuse an undersized disk BEFORE
    //    reserving memory or calling `Kernel::freeze(...)`.
    let sector_size = storage.sector_size();
    let required_bytes = required_disk_bytes(reservation_bytes, sector_size)?;
    let disk_bytes = storage.capacity_bytes();
    if disk_bytes < required_bytes {
        return Err(HibernateError::DiskTooSmall {
            required_bytes,
            disk_bytes,
        });
    }

    // 3. Reserve free user memory BEFORE freezing.
    let reservation = user_pool
        .reserve_hibernate_frames(reservation_bytes)
        .map_err(|oom| HibernateError::ReservationUnavailable {
            requested_bytes: oom.requested_bytes,
            available_bytes: oom.available_bytes,
        })?;
    let reservation_ranges = reservation.frame_ranges();
    let mut writer = ReservationWriter::new(reservation);

    // 4. Freeze all processors at a scheduler boundary and quiesce all devices.
    let frozen = kernel.freeze(arrival_deadline, interrupt_guests).await?;
    if let Err(error) = devices.quiesce_all() {
        drop(writer);
        frozen.thaw();
        return Err(error.into());
    }

    // 5. Double-return BSP snapshot point.
    let mut bsp_context = BspSnapshotContext::empty();
    let point = match cpu.capture_bsp_state(&mut bsp_context) {
        Ok(point) => point,
        Err(error) => {
            drop(writer);
            recover_devices_after_abort(devices);
            frozen.thaw();
            return Err(error.into());
        }
    };
    if point == SnapshotPoint::Resumed {
        // Resumed from a restored hibernate image: release reserved frames,
        // reinitialize all devices (`virtio-iommu` first when present), then
        // thaw all processors.
        drop(writer);
        let reinit_result = devices.reinitialize_all();
        frozen.thaw();
        reinit_result?;
        return Ok(HibernateOutcome::Resumed);
    }

    // 6. Compress all reachable live frames into reserved user memory.
    let frame_runs =
        collect_snapshot_physical_runs(user_pool, boot_memory, balloon, &reservation_ranges);
    let max_phys = boot_memory.max_physical_address();
    let machine_max_frames = max_phys.div_ceil(PhysFrame::SIZE as u64);
    let direct_offset = boot_memory.physical_memory_offset;

    let header = match encode_snapshot(
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
            // while the machine is frozen (`FrozenMachine`) and all devices are
            // quiesced, and every live RAM frame is mapped readable at
            // `phys + physical_memory_offset`.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    core::ptr::with_exposed_provenance::<u8>(direct_addr),
                    dst.as_mut_ptr(),
                    PhysFrame::SIZE,
                );
            }
        },
        || frozen.pet_watchdog(),
    ) {
        Ok(header) => header,
        Err(error) => {
            drop(writer);
            recover_devices_after_abort(devices);
            frozen.thaw();
            return Err(error);
        }
    };

    // 7. Bring only the hibernate disk back up, write compressed chunks + table,
    //    flush, write sector 0 header, flush again. On ANY failure, drop the
    //    reservation, reinitialize all devices, thaw, and return the error.
    let written_bytes = match write_image_to_storage(&header, &writer, storage, || {
        frozen.pet_watchdog();
    }) {
        Ok(written_bytes) => written_bytes,
        Err(error) => {
            drop(writer);
            recover_devices_after_abort(devices);
            frozen.thaw();
            return Err(error);
        }
    };

    // 8. Final flush succeeded: power off while the machine is still frozen.
    power_off();

    // Reached only when a test supplies a returning `power_off` hook.
    drop(writer);
    frozen.thaw();
    Ok(HibernateOutcome::PoweredOff {
        image_bytes: header.total_image_bytes,
        written_bytes,
        chunk_count: header.chunk_count,
    })
}

/// Full production hibernate-to-disk entry point: writes and flushes the
/// authenticated hibernate image and powers off the machine via
/// [`Cpu::shutdown`].
///
/// Returns `Ok(HibernateOutcome::Resumed)` when execution resumes from the
/// saved image on a future boot, or `Err(HibernateError)` if hibernation was
/// refused or aborted cleanly without powering off.
pub async fn hibernate_to_disk<
    CpuImpl,
    WatchdogImpl,
    MeasuredBootImpl,
    Storage,
    Devices,
    InterruptGuests,
>(
    kernel: &Kernel<CpuImpl, WatchdogImpl, MeasuredBootImpl>,
    cpu: &CpuImpl,
    user_pool: &UserMemoryPool,
    params: AtomicSnapshotParams<'_>,
    storage: &mut Storage,
    devices: &mut Devices,
    interrupt_guests: InterruptGuests,
) -> Result<HibernateOutcome, HibernateError>
where
    CpuImpl: Cpu + Clone,
    WatchdogImpl: Watchdog + Clone,
    MeasuredBootImpl: MeasuredBoot,
    Storage: HibernateStorage,
    Devices: HibernateDeviceController,
    InterruptGuests: FnOnce(),
{
    hibernate_to_disk_with_power_off(
        kernel,
        cpu,
        user_pool,
        params,
        storage,
        devices,
        interrupt_guests,
        || cpu.shutdown(),
    )
    .await
}
