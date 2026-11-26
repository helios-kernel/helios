//! End-to-end hibernate-to-disk tests on the real multi-processor hosted
//! executor (`HostedCpu` + `Kernel::freeze` + concurrent active async tasks).

#![cfg(test)]

use std::alloc::Layout;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender, bounded, unbounded};
use helios_hal::boot::{BootMemoryKind, BootMemoryMetadata, BootMemoryRegion};
use helios_hal::cpu::{Cpu, ProcessorId, ResumeHandoff};
use helios_hal::io::IoError;
use helios_hal::measured_boot::{
    MeasuredBoot, MeasuredBootError, MeasurementAlgorithm, MeasurementBank, MeasurementDigest,
    MeasurementRegister, MeasurementSet, SealedSecret, UnsealRefused,
};
use helios_hal::numa::SingleNode;
use helios_hal::pmm::PhysFrame;
use helios_hal::{DeviceInventory, DmaModel, Platform, ProcessorStartupPolicy, ProcessorTopology};
use helios_kernel::hibernate::{
    AtomicSnapshotParams, FrameRun, HEADER_BYTES, HEADER_MAC_OFFSET, HIBERNATE_HEADER_SECTORS,
    HIBERNATE_SECTOR_BYTES, HibernateDeviceController, HibernateDeviceError, HibernateError,
    HibernateHeader, HibernateIdentity, HibernateOutcome, HibernateStorage, HibernateStorageError,
    ResumeProbe, ResumeTargets, SnapshotConfig, decode_image_into,
    hibernate_to_disk_with_power_off, invalidate_hibernate_header, probe_and_load_hibernate_image,
    verify_image_header_and_table,
};
use helios_kernel::{
    HibernateAuthKey, Kernel, MachineGeneration, RootEntropy, UserMemoryPool, settle_signing_key,
    yield_now,
};

use crate::console::HostedConsole;
use crate::cpu::HostedCpu;
use crate::runtime::HostedMachine;

const PROCESSORS: usize = 4;
const TEST_HEAP_BYTES: usize = 32 * 1024 * 1024;
const RESERVATION_BYTES: usize = 4 * 1024 * 1024;
const PATIENCE: Duration = Duration::from_secs(20);
const ARRIVAL_DEADLINE: Duration = Duration::from_secs(10);

type Job = Box<dyn FnOnce(&'static Kernel<HostedCpu>, &HostedCpu) + Send>;

struct HibernateTestMachine {
    machine: Arc<HostedMachine>,
    mailboxes: Vec<Sender<Job>>,
    pool: &'static UserMemoryPool,
    phys_offset: usize,
    phys_bytes: u64,
    auth_key: HibernateAuthKey,
    turn: Mutex<()>,
}

impl HibernateTestMachine {
    fn on(
        &self,
        index: usize,
        job: impl FnOnce(&'static Kernel<HostedCpu>, &HostedCpu) + Send + 'static,
    ) {
        self.mailboxes[index]
            .send(Box::new(job))
            .expect("the processor thread is gone");
        self.machine
            .wake_processor(ProcessorId::new(u16::try_from(index).unwrap()));
    }
}

/// Minimal in-memory `MeasuredBoot` implementation so hosted hibernate tests
/// derive a real TPM-sealed [`HibernateAuthKey`] through [`settle_signing_key`].
struct TestMeasuredBoot {
    banks: [MeasurementBank; 1],
    sealed: Option<SealedSecret>,
}

impl TestMeasuredBoot {
    fn new() -> Self {
        let mut registers = MeasurementSet::empty();
        for idx in 0..16 {
            registers = registers.with(MeasurementRegister::new(idx));
        }
        Self {
            banks: [MeasurementBank {
                algorithm: MeasurementAlgorithm::Sha256,
                registers,
            }],
            sealed: None,
        }
    }
}

impl MeasuredBoot for TestMeasuredBoot {
    fn kernel_image_registers(&self) -> MeasurementSet {
        MeasurementSet::of(&[MeasurementRegister::new(8)])
    }

    fn banks(&self) -> &[MeasurementBank] {
        &self.banks
    }

    async fn extend(
        &mut self,
        _register: MeasurementRegister,
        _digests: &[MeasurementDigest],
    ) -> Result<(), MeasuredBootError> {
        Ok(())
    }

    async fn load_sealed(
        &mut self,
        _bound_to: MeasurementSet,
    ) -> Result<SealedSecret, UnsealRefused> {
        self.sealed
            .as_ref()
            .map(|secret| SealedSecret::new(*secret.expose()))
            .ok_or(UnsealRefused::Empty)
    }

    async fn store_sealed(
        &mut self,
        _bound_to: MeasurementSet,
        secret: &SealedSecret,
    ) -> Result<(), MeasuredBootError> {
        self.sealed = Some(SealedSecret::new(*secret.expose()));
        Ok(())
    }
}

fn machine() -> (&'static HibernateTestMachine, MutexGuard<'static, ()>) {
    static MACHINE: OnceLock<HibernateTestMachine> = OnceLock::new();
    let machine = MACHINE.get_or_init(boot);
    let turn = machine
        .turn
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    (machine, turn)
}

fn boot() -> HibernateTestMachine {
    let machine = HostedMachine::new(PROCESSORS, ProcessorId::new(0), TEST_HEAP_BYTES);
    let region = machine
        .bootstrap_memory_regions()
        .next()
        .expect("hosted machine exposes one contiguous memory region");
    let phys_offset = region.start();
    let phys_bytes = region.len() as u64;

    let (registered, registrations) = unbounded();
    let (online, onlines) = bounded(PROCESSORS);
    let (boot_info_tx, boot_info_rx) = bounded::<(&'static UserMemoryPool, HibernateAuthKey)>(1);
    let mut mailboxes = Vec::new();

    for index in 0..PROCESSORS {
        let processor = ProcessorId::new(u16::try_from(index).unwrap());
        let (mailbox, jobs) = unbounded::<Job>();
        mailboxes.push(mailbox);
        let machine = machine.clone();
        let registered = registered.clone();
        let online = online.clone();
        let boot_info_tx = boot_info_tx.clone();
        thread::Builder::new()
            .name(format!("helios-hibernate-test-p{index}"))
            .spawn(move || {
                machine.register_thread(processor, thread::current());
                registered.send(processor).unwrap();
                thread::park();

                let cpu = HostedCpu::new(processor, machine.clone());
                let pool_and_key = if processor == machine.bootstrap_processor() {
                    let pool = helios_kernel::prime_bootstrap_allocator(
                        machine.bootstrap_memory_regions(),
                        &SingleNode::new(machine.processor_count()),
                        processor,
                    );
                    let entropy =
                        RootEntropy::from_platform(&cpu, None, None, MachineGeneration::new(None))
                            .expect("hosted CPU provides cryptographic entropy");
                    let mut measured = TestMeasuredBoot::new();
                    let settled = futures_lite::future::block_on(settle_signing_key(
                        Some(&mut measured),
                        b"hosted-hibernate-test-payload",
                        &entropy,
                    ))
                    .expect("settle signing key succeeds");
                    let key = settled
                        .hibernate_auth
                        .expect("provisioned measured-boot seed yields HibernateAuthKey");
                    Some((pool, key))
                } else {
                    None
                };

                let mut boot_memory = BootMemoryMetadata {
                    physical_memory_offset: phys_offset,
                    ..BootMemoryMetadata::default()
                };
                boot_memory.firmware_memory_map.push(BootMemoryRegion {
                    start: 0,
                    end: phys_bytes,
                    kind: BootMemoryKind::Usable,
                });

                let platform = Platform::new(HostedConsole::new(), cpu.clone())
                    .with_topology(
                        ProcessorTopology::start_all_secondaries(
                            machine.bootstrap_processor(),
                            machine.processor_count(),
                        )
                        .with_startup_policy(ProcessorStartupPolicy::BootstrapOnly),
                    )
                    .with_dma_model(DmaModel::Translated)
                    .with_devices(DeviceInventory::new())
                    .with_boot_memory(boot_memory);

                let kernel: &'static Kernel<HostedCpu> =
                    Box::leak(Box::new(helios_kernel::init(platform)));
                cpu.install_timer(kernel.timer());
                if let Some(info) = pool_and_key {
                    boot_info_tx.send(info).unwrap();
                    for other in (0..machine.processor_count())
                        .map(|other| ProcessorId::new(u16::try_from(other).unwrap()))
                        .filter(|other| *other != processor)
                    {
                        cpu.start_processor(other);
                    }
                }
                online.send(index).unwrap();

                loop {
                    while let Ok(job) = jobs.try_recv() {
                        job(kernel, &cpu);
                    }
                    let stats = kernel.run_until_stalled_with_stats();
                    if stats.progress_count() == 0 {
                        kernel.park_until_work();
                    }
                }
            })
            .expect("a processor thread starts");
    }

    drop((registered, online, boot_info_tx));
    for _ in 0..PROCESSORS {
        registrations
            .recv_timeout(PATIENCE)
            .expect("a processor thread did not register");
    }
    machine.wake_processor(machine.bootstrap_processor());
    for _ in 0..PROCESSORS {
        onlines
            .recv_timeout(PATIENCE)
            .expect("a processor did not come online");
    }
    let (pool, auth_key) = boot_info_rx
        .recv_timeout(PATIENCE)
        .expect("bootstrap processor did not publish pool and auth key");

    HibernateTestMachine {
        machine,
        mailboxes,
        pool,
        phys_offset,
        phys_bytes,
        auth_key,
        turn: Mutex::new(()),
    }
}

#[track_caller]
fn recv<T>(receiver: &Receiver<T>) -> T {
    receiver
        .recv_timeout(PATIENCE)
        .expect("hibernate task did not report in time")
}

/// Ordered event recorded across the hibernate disk, device controller, and
/// power-off hook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiskEvent {
    QuiesceAll,
    ReinitializeIommu,
    ReinitializeHibernateDisk,
    WriteSectors { start_sector: u64, byte_len: usize },
    Flush,
    PowerOff,
    ReinitializeAll,
}

/// In-memory hibernate disk that records every operation and supports
/// deterministic fault injection at any storage operation index.
struct MemoryHibernateDisk {
    bytes: Vec<u8>,
    max_write_bytes: usize,
    events: Arc<Mutex<Vec<DiskEvent>>>,
    op_index: usize,
    fail_at_op: Option<usize>,
}

impl MemoryHibernateDisk {
    fn new(
        capacity_bytes: usize,
        max_write_bytes: usize,
        events: Arc<Mutex<Vec<DiskEvent>>>,
        fail_at_op: Option<usize>,
    ) -> Self {
        Self {
            bytes: vec![0_u8; capacity_bytes],
            max_write_bytes,
            events,
            op_index: 0,
            fail_at_op,
        }
    }

    fn take_op_index(&mut self) -> usize {
        let idx = self.op_index;
        self.op_index += 1;
        idx
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn total_ops(&self) -> usize {
        self.op_index
    }
}

impl HibernateStorage for MemoryHibernateDisk {
    fn capacity_bytes(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn sector_size(&self) -> usize {
        HIBERNATE_SECTOR_BYTES
    }

    fn max_write_bytes(&self) -> usize {
        self.max_write_bytes
    }

    fn reinitialize_for_write(&mut self) -> Result<(), HibernateStorageError> {
        let idx = self.take_op_index();
        self.events
            .lock()
            .unwrap()
            .push(DiskEvent::ReinitializeHibernateDisk);
        if self.fail_at_op == Some(idx) {
            return Err(HibernateStorageError::Reinitialize {
                detail: "injected reinitialize failure",
            });
        }
        Ok(())
    }

    fn write_sectors(
        &mut self,
        start_sector: u64,
        data: &[u8],
    ) -> Result<(), HibernateStorageError> {
        let idx = self.take_op_index();
        self.events.lock().unwrap().push(DiskEvent::WriteSectors {
            start_sector,
            byte_len: data.len(),
        });
        if self.fail_at_op == Some(idx) {
            return Err(HibernateStorageError::Write {
                start_sector,
                byte_len: data.len(),
                error: IoError::DeviceFault,
            });
        }
        let offset = (start_sector as usize) * HIBERNATE_SECTOR_BYTES;
        if offset + data.len() > self.bytes.len() {
            return Err(HibernateStorageError::Write {
                start_sector,
                byte_len: data.len(),
                error: IoError::OutOfBounds,
            });
        }
        self.bytes[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), HibernateStorageError> {
        let idx = self.take_op_index();
        self.events.lock().unwrap().push(DiskEvent::Flush);
        if self.fail_at_op == Some(idx) {
            return Err(HibernateStorageError::Flush {
                error: IoError::DeviceFault,
            });
        }
        Ok(())
    }

    fn read_sectors(
        &mut self,
        start_sector: u64,
        dst: &mut [u8],
    ) -> Result<(), HibernateStorageError> {
        let offset = (start_sector as usize) * HIBERNATE_SECTOR_BYTES;
        if offset + dst.len() > self.bytes.len() {
            return Err(HibernateStorageError::Read {
                start_sector,
                byte_len: dst.len(),
                error: IoError::OutOfBounds,
            });
        }
        dst.copy_from_slice(&self.bytes[offset..offset + dst.len()]);
        Ok(())
    }
}

struct RecordingDeviceController {
    events: Arc<Mutex<Vec<DiskEvent>>>,
    quiesce_count: usize,
    reinit_iommu_count: usize,
    reinit_all_count: usize,
    fail_quiesce: bool,
    fail_reinit_iommu: bool,
}

impl RecordingDeviceController {
    fn new(events: Arc<Mutex<Vec<DiskEvent>>>) -> Self {
        Self {
            events,
            quiesce_count: 0,
            reinit_iommu_count: 0,
            reinit_all_count: 0,
            fail_quiesce: false,
            fail_reinit_iommu: false,
        }
    }
}

impl HibernateDeviceController for RecordingDeviceController {
    fn quiesce_all(&mut self) -> Result<(), HibernateDeviceError> {
        self.quiesce_count += 1;
        self.events.lock().unwrap().push(DiskEvent::QuiesceAll);
        if self.fail_quiesce {
            return Err(HibernateDeviceError::Quiesce {
                device: "virtio-net",
                detail: "injected quiesce failure",
            });
        }
        Ok(())
    }

    fn reinitialize_iommu(&mut self) -> Result<(), HibernateDeviceError> {
        self.reinit_iommu_count += 1;
        self.events
            .lock()
            .unwrap()
            .push(DiskEvent::ReinitializeIommu);
        if self.fail_reinit_iommu {
            return Err(HibernateDeviceError::Reinitialize {
                device: "virtio-iommu",
                detail: "injected iommu reinitialize failure",
            });
        }
        Ok(())
    }

    fn reinitialize_all(&mut self) -> Result<(), HibernateDeviceError> {
        self.reinit_all_count += 1;
        self.events.lock().unwrap().push(DiskEvent::ReinitializeAll);
        Ok(())
    }
}

fn sample_identity() -> HibernateIdentity {
    HibernateIdentity {
        kernel_text_phys_start: 0x0010_0000,
        kernel_text_virt_start: 0xffff_8000_0010_0000,
        kernel_text_len: 0x0008_0000,
        kernel_text_sha256: [0x11; 32],
        kernel_rodata_phys_start: 0x0018_0000,
        kernel_rodata_virt_start: 0xffff_8000_0018_0000,
        kernel_rodata_len: 0x0004_0000,
        kernel_rodata_sha256: [0x22; 32],
        boot_payload_phys_addr: 0x0040_0000,
        boot_payload_len: 0x0002_0000,
        boot_payload_sha256: [0x33; 32],
        firmware_memory_map_count: 1,
        firmware_memory_map_sha256: [0x44; 32],
        processor_count: PROCESSORS as u32,
        device_inventory_sha256: [0x55; 32],
        negotiated_features_sha256: [0x66; 32],
    }
}

/// Spawns one active yielding async task on every processor and returns handles
/// to observe their progress and stop them at test end.
fn start_background_tasks(
    machine: &'static HibernateTestMachine,
) -> (Arc<AtomicBool>, Arc<[AtomicUsize]>) {
    let stop = Arc::new(AtomicBool::new(false));
    let progress: Arc<[AtomicUsize]> = (0..PROCESSORS).map(|_| AtomicUsize::new(0)).collect();
    let (started_tx, started_rx) = unbounded();
    for index in 0..PROCESSORS {
        let stop = stop.clone();
        let progress = progress.clone();
        let started_tx = started_tx.clone();
        machine.on(index, move |kernel, _cpu| {
            kernel.spawn_local_detached(async move {
                progress[index].fetch_add(1, Ordering::SeqCst);
                let _ = started_tx.send(index);
                while !stop.load(Ordering::Acquire) {
                    progress[index].fetch_add(1, Ordering::SeqCst);
                    yield_now().await;
                }
            });
        });
    }
    for _ in 0..PROCESSORS {
        recv(&started_rx);
    }
    (stop, progress)
}

fn wait_for_all_tasks_to_advance(progress: &[AtomicUsize], baseline: &[usize]) {
    let deadline = std::time::Instant::now() + PATIENCE;
    loop {
        if progress
            .iter()
            .zip(baseline)
            .all(|(counter, &before)| counter.load(Ordering::SeqCst) > before)
        {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "concurrent async tasks stalled after hibernate recovery: before={baseline:?}, now={:?}",
            progress
                .iter()
                .map(|c| c.load(Ordering::SeqCst))
                .collect::<Vec<_>>()
        );
        thread::yield_now();
    }
}

/// Full hibernate write path on the real multi-processor hosted executor:
/// - quiesces all devices before snapshot,
/// - brings ONLY the hibernate disk back up for writes (not `reinitialize_all`),
/// - writes every compressed chunk + chunk table at sector >= 8 and flushes
///   strictly BEFORE writing sector 0 (`HibernateHeader`) and flushing again,
/// - invokes power-off ONLY after the final flush while tasks remain frozen,
/// - verifies the written disk image decodes bit-for-bit via
///   `kernel::hibernate::verify`, and
/// - verifies `invalidate_hibernate_header` clears sector 0..8.
#[test]
fn hibernate_full_write_path_orders_flushes_powers_off_and_round_trips() {
    let (machine, _turn) = machine();
    let (stop, progress) = start_background_tasks(machine);

    // Allocate 64 KiB of identifiable pattern pages in user memory so the
    // snapshot contains real, verifiable non-zero user pages.
    let pattern_pages = 16_usize;
    let pattern_len = pattern_pages * PhysFrame::SIZE;
    let pattern_layout = Layout::from_size_align(pattern_len, PhysFrame::SIZE).unwrap();
    let (pattern_tx, pattern_rx) = bounded::<(usize, Vec<u8>)>(1);
    let pool = machine.pool;
    machine.on(0, move |_kernel, _cpu| {
        let ptr = pool
            .allocate_zeroed_on(ProcessorId::new(0), pattern_layout)
            .expect("allocate pattern user pages");
        let mut expected = vec![0_u8; pattern_len];
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for byte in &mut expected {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        // SAFETY: `ptr` is an exclusively owned `pattern_len`-byte user allocation.
        unsafe {
            core::ptr::copy_nonoverlapping(expected.as_ptr(), ptr.as_ptr(), pattern_len);
        }
        pattern_tx.send((ptr.as_ptr() as usize, expected)).unwrap();
    });
    let (pattern_addr, pattern_expected) = recv(&pattern_rx);
    let pattern_start_frame = ((pattern_addr - machine.phys_offset) / PhysFrame::SIZE) as u64;

    let events = Arc::new(Mutex::new(Vec::new()));
    let events_for_task = events.clone();
    let progress_for_task = progress.clone();
    let (report_tx, report_rx) = bounded(1);
    let identity = sample_identity();

    machine.on(0, move |kernel, cpu| {
        let cpu = cpu.clone();
        kernel.spawn_local_detached(async move {
            let mut disk =
                MemoryHibernateDisk::new(8 * 1024 * 1024, 4096, events_for_task.clone(), None);
            let mut devices = RecordingDeviceController::new(events_for_task.clone());
            let mut progress_during_poweroff = None;

            let generation = MachineGeneration::new(None);
            let entropy = RootEntropy::from_platform(&cpu, None, None, generation.clone())
                .expect("hosted entropy");
            let outcome = hibernate_to_disk_with_power_off(
                kernel,
                &cpu,
                machine.pool,
                AtomicSnapshotParams {
                    balloon: None,
                    auth_key: Some(&machine.auth_key),
                    identity,
                    reservation_bytes: RESERVATION_BYTES,
                    arrival_deadline: ARRIVAL_DEADLINE,
                    config: SnapshotConfig::new([0x76; 16]),
                },
                ResumeTargets {
                    machine_generation: &generation,
                    root_entropy: &entropy,
                    reseed_wall_clock: |_, _| {},
                },
                &mut disk,
                &mut devices,
                || {},
                || {
                    events_for_task.lock().unwrap().push(DiskEvent::PowerOff);
                    let before: Vec<usize> = progress_for_task
                        .iter()
                        .map(|c| c.load(Ordering::SeqCst))
                        .collect();
                    thread::sleep(Duration::from_millis(20));
                    let after: Vec<usize> = progress_for_task
                        .iter()
                        .map(|c| c.load(Ordering::SeqCst))
                        .collect();
                    progress_during_poweroff = Some((before, after));
                },
            )
            .await;

            let disk_bytes = disk.bytes().to_vec();
            let quiesce_count = devices.quiesce_count;
            let reinit_all_count = devices.reinit_all_count;
            let invalidate_res = invalidate_hibernate_header(&mut disk);
            let invalidated_header = disk.bytes()[..HEADER_BYTES].to_vec();

            report_tx
                .send((
                    outcome,
                    disk_bytes,
                    quiesce_count,
                    reinit_all_count,
                    progress_during_poweroff,
                    invalidate_res,
                    invalidated_header,
                ))
                .unwrap();
        });
    });

    let (
        outcome,
        disk_bytes,
        quiesce_count,
        reinit_all_count,
        progress_during_poweroff,
        invalidate_res,
        invalidated_header,
    ) = recv(&report_rx);

    let (image_bytes, written_bytes, chunk_count) = match outcome {
        Ok(HibernateOutcome::PoweredOff {
            image_bytes,
            written_bytes,
            chunk_count,
        }) => (image_bytes, written_bytes, chunk_count),
        other => panic!("expected PoweredOff outcome, got {other:?}"),
    };
    assert!(chunk_count >= 1);
    assert!(written_bytes >= image_bytes);
    assert_eq!(written_bytes % HIBERNATE_SECTOR_BYTES as u64, 0);
    assert_eq!(quiesce_count, 1);
    assert_eq!(
        reinit_all_count, 0,
        "only the hibernate disk should be brought back up on the happy path"
    );

    let (frozen_before, frozen_after) =
        progress_during_poweroff.expect("power_off hook must have executed");
    assert_eq!(
        frozen_before, frozen_after,
        "concurrent tasks must remain frozen through power-off"
    );

    // Check strict event timeline (excluding the trailing invalidate write+flush):
    // QuiesceAll -> ReinitializeIommu -> ReinitializeHibernateDisk ->
    // WriteSectors(sector >= 8)* -> Flush -> WriteSectors(sector 0, 4096B) ->
    // Flush -> PowerOff
    let recorded = events.lock().unwrap().clone();
    let power_off_pos = recorded
        .iter()
        .position(|e| *e == DiskEvent::PowerOff)
        .expect("PowerOff event must be recorded");
    let pre_poweroff = &recorded[..=power_off_pos];
    let n = pre_poweroff.len();
    assert!(
        n >= 8,
        "expected quiesce, iommu reinit, disk reinit, >=1 payload write, pre-header flush, header write, final flush, poweroff; got {pre_poweroff:?}"
    );
    assert_eq!(pre_poweroff[0], DiskEvent::QuiesceAll);
    assert_eq!(pre_poweroff[1], DiskEvent::ReinitializeIommu);
    assert_eq!(pre_poweroff[2], DiskEvent::ReinitializeHibernateDisk);
    assert_eq!(pre_poweroff[n - 1], DiskEvent::PowerOff);
    assert_eq!(pre_poweroff[n - 2], DiskEvent::Flush);
    assert_eq!(
        pre_poweroff[n - 3],
        DiskEvent::WriteSectors {
            start_sector: 0,
            byte_len: HEADER_BYTES,
        }
    );
    assert_eq!(pre_poweroff[n - 4], DiskEvent::Flush);
    for event in &pre_poweroff[3..n - 4] {
        match *event {
            DiskEvent::WriteSectors {
                start_sector,
                byte_len,
            } => {
                assert!(
                    start_sector >= HIBERNATE_HEADER_SECTORS,
                    "sector 0 must never be written before pre-header flush"
                );
                assert_eq!(byte_len % HIBERNATE_SECTOR_BYTES, 0);
            }
            other => panic!("unexpected event before pre-header flush: {other:?}"),
        }
    }

    // Verify full `kernel::hibernate::verify` round-trip directly from disk bytes.
    let machine_max_frames = machine.phys_bytes.div_ceil(PhysFrame::SIZE as u64);
    let verified = verify_image_header_and_table(
        &disk_bytes[..written_bytes as usize],
        &machine.auth_key,
        &identity,
        machine_max_frames,
    )
    .expect("written disk image header and chunk table must verify");
    assert_eq!(verified.header.total_image_bytes, image_bytes);
    assert_eq!(verified.header.chunk_count, chunk_count);

    let mut decoded_pattern_frames: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    decode_image_into(
        &disk_bytes[..written_bytes as usize],
        &machine.auth_key,
        &identity,
        machine_max_frames,
        |start_frame, bytes| {
            let count = (bytes.len() / PhysFrame::SIZE) as u64;
            for i in 0..count {
                let frame = start_frame + i;
                if frame >= pattern_start_frame
                    && frame < pattern_start_frame + pattern_pages as u64
                {
                    let off = (i as usize) * PhysFrame::SIZE;
                    decoded_pattern_frames
                        .insert(frame, bytes[off..off + PhysFrame::SIZE].to_vec());
                }
            }
            Ok(())
        },
    )
    .expect("written disk image chunks must decode cleanly");

    assert_eq!(
        decoded_pattern_frames.len(),
        pattern_pages,
        "every allocated user pattern frame must be present in the decoded image"
    );
    for i in 0..pattern_pages {
        let frame = pattern_start_frame + i as u64;
        let expected_slice = &pattern_expected[i * PhysFrame::SIZE..(i + 1) * PhysFrame::SIZE];
        assert_eq!(
            decoded_pattern_frames[&frame].as_slice(),
            expected_slice,
            "decoded frame {frame} differs from live memory"
        );
    }

    // Verify header invalidation zeroed sector 0..8 and causes decode to fail.
    invalidate_res.expect("invalidate_hibernate_header succeeds");
    assert!(invalidated_header.iter().all(|&b| b == 0));
    assert_eq!(
        HibernateHeader::decode_verified(&invalidated_header, &machine.auth_key),
        Err(HibernateError::InvalidMagic)
    );

    // Free pattern allocation and stop background tasks cleanly.
    let (freed_tx, freed_rx) = bounded(1);
    machine.on(0, move |_kernel, _cpu| {
        let ptr = core::ptr::NonNull::new(pattern_addr as *mut u8).unwrap();
        machine
            .pool
            .deallocate_bytes_on(ProcessorId::new(0), ptr, pattern_layout);
        freed_tx.send(()).unwrap();
    });
    recv(&freed_rx);
    stop.store(true, Ordering::Release);
}

/// Exhaustive fault injection across EVERY single storage operation index
/// (reinit, every chunk/table write, pre-header flush, header write, final
/// flush): every failure releases the reservation (free frames restored), does
/// NOT power off, reinitializes devices, returns the typed error, thaws the
/// machine, and every concurrent async task continues completing work.
#[test]
fn hibernate_fault_injection_at_every_op_recovers_reservation_devices_and_tasks() {
    let (machine, _turn) = machine();
    let (stop, progress) = start_background_tasks(machine);
    let identity = sample_identity();

    // Determine the exact storage op count for this snapshot with 4 KiB write batches.
    let (probe_tx, probe_rx) = bounded(1);
    machine.on(0, move |kernel, cpu| {
        let cpu = cpu.clone();
        kernel.spawn_local_detached(async move {
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut disk = MemoryHibernateDisk::new(8 * 1024 * 1024, 4096, events.clone(), None);
            let mut devices = RecordingDeviceController::new(events);
            let generation = MachineGeneration::new(None);
            let entropy = RootEntropy::from_platform(&cpu, None, None, generation.clone())
                .expect("hosted entropy");
            let res = hibernate_to_disk_with_power_off(
                kernel,
                &cpu,
                machine.pool,
                AtomicSnapshotParams {
                    balloon: None,
                    auth_key: Some(&machine.auth_key),
                    identity,
                    reservation_bytes: RESERVATION_BYTES,
                    arrival_deadline: ARRIVAL_DEADLINE,
                    config: SnapshotConfig::new([0x88; 16]),
                },
                ResumeTargets {
                    machine_generation: &generation,
                    root_entropy: &entropy,
                    reseed_wall_clock: |_, _| {},
                },
                &mut disk,
                &mut devices,
                || {},
                || {},
            )
            .await;
            probe_tx.send((res, disk.total_ops())).unwrap();
        });
    });
    let (probe_res, total_ops) = recv(&probe_rx);
    assert!(matches!(probe_res, Ok(HibernateOutcome::PoweredOff { .. })));
    assert!(
        total_ops >= 5,
        "expected reinit + payload/table writes + pre-header flush + header write + final flush, got {total_ops}"
    );

    // Inject a failure at EVERY operation index `0..total_ops`.
    for fault_index in 0..total_ops {
        let (done_tx, done_rx) = bounded(1);
        let progress_baseline: Vec<usize> =
            progress.iter().map(|c| c.load(Ordering::SeqCst)).collect();

        machine.on(0, move |kernel, cpu| {
            let cpu = cpu.clone();
            kernel.spawn_local_detached(async move {
                machine.pool.drain_all_frame_slabs();
                let allocated_before = machine.pool.stats().allocated_bytes;

                let events = Arc::new(Mutex::new(Vec::new()));
                let mut disk = MemoryHibernateDisk::new(
                    8 * 1024 * 1024,
                    4096,
                    events.clone(),
                    Some(fault_index),
                );
                let mut devices = RecordingDeviceController::new(events.clone());
                let power_off_called = Arc::new(AtomicBool::new(false));
                let power_off_flag = power_off_called.clone();

                let generation = MachineGeneration::new(None);
                let entropy = RootEntropy::from_platform(&cpu, None, None, generation.clone())
                    .expect("hosted entropy");
                let outcome = hibernate_to_disk_with_power_off(
                    kernel,
                    &cpu,
                    machine.pool,
                    AtomicSnapshotParams {
                        balloon: None,
                        auth_key: Some(&machine.auth_key),
                        identity,
                        reservation_bytes: RESERVATION_BYTES,
                        arrival_deadline: ARRIVAL_DEADLINE,
                        config: SnapshotConfig::new([0x99; 16]),
                    },
                    ResumeTargets {
                        machine_generation: &generation,
                        root_entropy: &entropy,
                        reseed_wall_clock: |_, _| {},
                    },
                    &mut disk,
                    &mut devices,
                    || {},
                    || {
                        power_off_flag.store(true, Ordering::SeqCst);
                    },
                )
                .await;

                machine.pool.drain_all_frame_slabs();
                let allocated_after = machine.pool.stats().allocated_bytes;

                done_tx
                    .send((
                        outcome,
                        allocated_before,
                        allocated_after,
                        power_off_called.load(Ordering::SeqCst),
                        devices.quiesce_count,
                        devices.reinit_all_count,
                    ))
                    .unwrap();
            });
        });

        let (
            outcome,
            allocated_before,
            allocated_after,
            powered_off,
            quiesce_count,
            reinit_all_count,
        ) = recv(&done_rx);

        assert!(
            matches!(outcome, Err(HibernateError::Storage(_))),
            "fault at op {fault_index}/{total_ops} must return HibernateError::Storage, got {outcome:?}"
        );
        assert!(
            !powered_off,
            "fault at op {fault_index}/{total_ops} must never power off"
        );
        assert_eq!(quiesce_count, 1);
        assert_eq!(
            reinit_all_count, 1,
            "fault at op {fault_index}/{total_ops} must reinitialize all devices before thaw"
        );
        assert_eq!(
            allocated_after, allocated_before,
            "fault at op {fault_index}/{total_ops} must release every reserved frame"
        );

        // Verify the machine thawed cleanly and EVERY concurrent async task
        // across all 4 processors keeps running and completing work.
        wait_for_all_tasks_to_advance(&progress, &progress_baseline);
    }

    stop.store(true, Ordering::Release);
}

/// Disk-too-small refusal must fail BEFORE entering `Kernel::freeze(...)` or
/// reserving user frames.
#[test]
fn hibernate_disk_too_small_refuses_before_freeze() {
    let (machine, _turn) = machine();
    let identity = sample_identity();

    let (report_tx, report_rx) = bounded(1);
    machine.on(0, move |kernel, cpu| {
        let cpu = cpu.clone();
        kernel.spawn_local_detached(async move {
            machine.pool.drain_all_frame_slabs();
            let allocated_before = machine.pool.stats().allocated_bytes;

            let events = Arc::new(Mutex::new(Vec::new()));
            let tiny_disk_bytes = 64 * 1024;
            let mut disk = MemoryHibernateDisk::new(tiny_disk_bytes, 4096, events.clone(), None);
            let mut devices = RecordingDeviceController::new(events.clone());
            let freeze_counter = Arc::new(AtomicUsize::new(0));
            let freeze_counter_inner = freeze_counter.clone();
            let power_off_called = Arc::new(AtomicBool::new(false));
            let power_off_inner = power_off_called.clone();

            let generation = MachineGeneration::new(None);
            let entropy = RootEntropy::from_platform(&cpu, None, None, generation.clone())
                .expect("hosted entropy");
            let outcome = hibernate_to_disk_with_power_off(
                kernel,
                &cpu,
                machine.pool,
                AtomicSnapshotParams {
                    balloon: None,
                    auth_key: Some(&machine.auth_key),
                    identity,
                    reservation_bytes: RESERVATION_BYTES,
                    arrival_deadline: ARRIVAL_DEADLINE,
                    config: SnapshotConfig::new([0xaa; 16]),
                },
                ResumeTargets {
                    machine_generation: &generation,
                    root_entropy: &entropy,
                    reseed_wall_clock: |_, _| {},
                },
                &mut disk,
                &mut devices,
                || {
                    freeze_counter_inner.fetch_add(1, Ordering::SeqCst);
                },
                || {
                    power_off_inner.store(true, Ordering::SeqCst);
                },
            )
            .await;

            machine.pool.drain_all_frame_slabs();
            let allocated_after = machine.pool.stats().allocated_bytes;

            report_tx
                .send((
                    outcome,
                    freeze_counter.load(Ordering::SeqCst),
                    devices.quiesce_count,
                    devices.reinit_all_count,
                    events.lock().unwrap().clone(),
                    power_off_called.load(Ordering::SeqCst),
                    allocated_before,
                    allocated_after,
                ))
                .unwrap();
        });
    });

    let (
        outcome,
        freeze_count,
        quiesce_count,
        reinit_all_count,
        recorded_events,
        powered_off,
        allocated_before,
        allocated_after,
    ) = recv(&report_rx);

    assert_eq!(
        outcome,
        Err(HibernateError::DiskTooSmall {
            required_bytes: RESERVATION_BYTES as u64,
            disk_bytes: 64 * 1024,
        })
    );
    assert_eq!(
        freeze_count, 0,
        "DiskTooSmall must be returned BEFORE entering Kernel::freeze"
    );
    assert_eq!(quiesce_count, 0);
    assert_eq!(reinit_all_count, 0);
    assert!(recorded_events.is_empty());
    assert!(!powered_off);
    assert_eq!(allocated_after, allocated_before);
}

/// End-to-end hosted resume simulation:
/// 1. Hibernate writes an authenticated image containing identifiable CJK +
///    binary user pages to `MemoryHibernateDisk`.
/// 2. Boot kernel probes the disk via `probe_and_load_hibernate_image` with
///    colliding boot-kernel protected ranges, verifies direct + displaced
///    placement, and replays `DisplacedFrameCopy` into simulated RAM so every
///    pattern frame matches byte-for-byte.
/// 3. Returning into `SnapshotPoint::Resumed(handoff)` runs the full ordered
///    continuation: restores BSP state, advances `MachineGeneration` with
///    `AdvanceCause::ImageRestored`, mixes `fresh_entropy` into `RootEntropy`
///    (causing immediate output divergence from pre-hibernate state), reseeds
///    wall clock from RTC, reinitializes devices, invalidates the disk header
///    so a second boot probe returns `ResumeProbe::NoImage`, restarts all
///    stopped secondary processors, and thaws so every task keeps running.
#[test]
fn hibernate_end_to_end_boot_probe_restore_and_post_resume_continuation() {
    let (machine, _turn) = machine();
    let (stop, progress) = start_background_tasks(machine);
    let identity = sample_identity();
    let image_id = [0x57; 16];

    // Allocate 8 identifiable user frames containing Chinese + Japanese + Korean
    // text and structured bytes.
    let pattern_pages = 8_usize;
    let pattern_len = pattern_pages * PhysFrame::SIZE;
    let pattern_layout = Layout::from_size_align(pattern_len, PhysFrame::SIZE).unwrap();
    let (pattern_tx, pattern_rx) = bounded::<(usize, Vec<u8>)>(1);
    let pool = machine.pool;
    machine.on(0, move |_kernel, _cpu| {
        let ptr = pool
            .allocate_zeroed_on(ProcessorId::new(0), pattern_layout)
            .expect("allocate CJK pattern user pages");
        let seed_phrase = "冬眠恢复 / 冬眠復帰 / 동면 복귀 / hibernate-resume-577\n".as_bytes();
        let mut expected = vec![0_u8; pattern_len];
        for (i, byte) in expected.iter_mut().enumerate() {
            *byte = seed_phrase[i % seed_phrase.len()] ^ ((i / PhysFrame::SIZE) as u8);
        }
        // SAFETY: `ptr` is an exclusively owned `pattern_len`-byte user allocation.
        unsafe {
            core::ptr::copy_nonoverlapping(expected.as_ptr(), ptr.as_ptr(), pattern_len);
        }
        pattern_tx.send((ptr.as_ptr() as usize, expected)).unwrap();
    });
    let (pattern_addr, pattern_expected) = recv(&pattern_rx);
    let pattern_start_frame = ((pattern_addr - machine.phys_offset) / PhysFrame::SIZE) as u64;

    // Step 1: Hibernate to disk.
    let (hib_tx, hib_rx) = bounded(1);
    machine.on(0, move |kernel, cpu| {
        let cpu = cpu.clone();
        kernel.spawn_local_detached(async move {
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut disk = MemoryHibernateDisk::new(8 * 1024 * 1024, 4096, events.clone(), None);
            let mut devices = RecordingDeviceController::new(events);
            let generation = MachineGeneration::new(None);
            let entropy = RootEntropy::from_platform(&cpu, None, None, generation.clone())
                .expect("hosted entropy");
            let outcome = hibernate_to_disk_with_power_off(
                kernel,
                &cpu,
                machine.pool,
                AtomicSnapshotParams {
                    balloon: None,
                    auth_key: Some(&machine.auth_key),
                    identity,
                    reservation_bytes: RESERVATION_BYTES,
                    arrival_deadline: ARRIVAL_DEADLINE,
                    config: SnapshotConfig::new(image_id),
                },
                ResumeTargets {
                    machine_generation: &generation,
                    root_entropy: &entropy,
                    reseed_wall_clock: |_, _| {},
                },
                &mut disk,
                &mut devices,
                || {},
                || {},
            )
            .await;
            hib_tx.send((outcome, disk.bytes().to_vec())).unwrap();
        });
    });
    let (hib_outcome, disk_bytes) = recv(&hib_rx);
    assert!(matches!(
        hib_outcome,
        Ok(HibernateOutcome::PoweredOff { .. })
    ));

    // Step 2: Simulate fresh boot kernel probing & loading the hibernate image.
    // Give the boot kernel a simulated physical RAM pool matching the machine
    // size plus extra headroom, with a protected range colliding with the first
    // half of our user pattern frames so both direct and displaced paths run!
    let machine_max_frames = machine.phys_bytes.div_ceil(PhysFrame::SIZE as u64);
    let usable_frames = [FrameRun::new(0, machine_max_frames + 4096)];
    let p = PhysFrame::SIZE as u64;
    let boot_protected_range = (pattern_start_frame * p)..((pattern_start_frame + 4) * p);

    let events = Arc::new(Mutex::new(Vec::new()));
    let mut boot_disk = MemoryHibernateDisk::new(disk_bytes.len(), 4096, events, None);
    boot_disk.bytes.copy_from_slice(&disk_bytes);

    let mut staged_ram: BTreeMap<u64, [u8; PhysFrame::SIZE]> = BTreeMap::new();
    let loaded = match probe_and_load_hibernate_image(
        &mut boot_disk,
        Some(&machine.auth_key),
        &identity,
        machine_max_frames,
        &usable_frames,
        core::slice::from_ref(&boot_protected_range),
        4,
        |dst_phys, frame_bytes| {
            staged_ram.insert(dst_phys, *frame_bytes);
        },
        || {},
    ) {
        ResumeProbe::Ready(loaded) => loaded,
        other => panic!("expected ResumeProbe::Ready, got {other:?}"),
    };
    assert_eq!(loaded.header.image_id, image_id);
    assert!(
        loaded.plan.direct_frames > 0,
        "expected non-colliding direct frames"
    );
    assert!(
        loaded.plan.displaced_copies.len() >= 4,
        "expected colliding pattern frames to be displaced"
    );

    // Simulate the restore trampoline's linear `DisplacedFrameCopy` loop.
    for copy in &loaded.plan.displaced_copies {
        let src_bytes = *staged_ram
            .get(&copy.src_phys)
            .expect("displaced source frame staged");
        staged_ram.insert(copy.dst_phys, src_bytes);
    }
    for i in 0..pattern_pages {
        let phys = (pattern_start_frame + i as u64) * p;
        let restored_frame = staged_ram
            .get(&phys)
            .expect("restored user pattern frame present in RAM");
        let expected_slice = &pattern_expected[i * PhysFrame::SIZE..(i + 1) * PhysFrame::SIZE];
        assert_eq!(
            restored_frame.as_slice(),
            expected_slice,
            "restored frame {i} differs after trampoline copy loop"
        );
    }

    // Step 3: Trigger the real `SnapshotPoint::Resumed(handoff)` continuation
    // on the 4-processor hosted machine and verify every post-resume invariant.
    let progress_baseline: Vec<usize> = progress.iter().map(|c| c.load(Ordering::SeqCst)).collect();
    let restores_before = machine.machine.bsp_post_resume_restores();
    let fresh_entropy = [0xec; 32];
    let rtc_nanos = 1_795_000_000_000_000_000_u64;
    machine.machine.set_next_resume_handoff(ResumeHandoff {
        image_id,
        fresh_entropy,
        rtc_unix_nanos: Some(rtc_nanos),
        boot_monotonic_ticks: 99_999,
    });

    let (res_tx, res_rx) = bounded(1);
    machine.on(0, move |kernel, cpu| {
        let cpu = cpu.clone();
        kernel.spawn_local_detached(async move {
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut disk = MemoryHibernateDisk::new(disk_bytes.len(), 4096, events.clone(), None);
            disk.bytes.copy_from_slice(&disk_bytes);
            let mut devices = RecordingDeviceController::new(events);

            // Seed two deterministic-comparison-free RootEntropy state checks:
            // record generation, pre-resume draw + rekey/reseed stats.
            let generation = MachineGeneration::new(None);
            let gen_before = generation.current().get();
            let entropy = RootEntropy::from_platform(&cpu, None, None, generation.clone())
                .expect("hosted entropy");
            let mut pre_draw = [0_u8; 32];
            entropy.fill(&mut pre_draw);
            let rekeys_before = entropy.rekey_count();

            let reseeded_wall = Arc::new(Mutex::new(None::<(u64, u64)>));
            let reseeded_wall_cb = reseeded_wall.clone();

            let outcome = hibernate_to_disk_with_power_off(
                kernel,
                &cpu,
                machine.pool,
                AtomicSnapshotParams {
                    balloon: None,
                    auth_key: Some(&machine.auth_key),
                    identity,
                    reservation_bytes: RESERVATION_BYTES,
                    arrival_deadline: ARRIVAL_DEADLINE,
                    config: SnapshotConfig::new(image_id),
                },
                ResumeTargets {
                    machine_generation: &generation,
                    root_entropy: &entropy,
                    reseed_wall_clock: move |ticks, nanos| {
                        *reseeded_wall_cb.lock().unwrap() = Some((ticks, nanos));
                    },
                },
                &mut disk,
                &mut devices,
                || {},
                || panic!("power_off must NOT run on SnapshotPoint::Resumed"),
            )
            .await;

            let (latest_gen, latest_cause_bytes) = generation.latest_advance();
            let gen_after = latest_gen.get();
            let mut post_draw = [0_u8; 32];
            entropy.fill(&mut post_draw);
            let rekeys_after = entropy.rekey_count();

            // Probe the SAME disk a second time: header must have been
            // invalidated so a second boot cold-boots (`ResumeProbe::NoImage`).
            let second_boot_probe = probe_and_load_hibernate_image(
                &mut disk,
                Some(&machine.auth_key),
                &identity,
                machine_max_frames,
                &usable_frames,
                core::slice::from_ref(&boot_protected_range),
                4,
                |_, _| {},
                || {},
            );

            res_tx
                .send((
                    outcome,
                    gen_before,
                    gen_after,
                    latest_cause_bytes,
                    pre_draw,
                    post_draw,
                    rekeys_before,
                    rekeys_after,
                    *reseeded_wall.lock().unwrap(),
                    devices.reinit_all_count,
                    matches!(second_boot_probe, ResumeProbe::NoImage),
                    disk.bytes()[..HEADER_BYTES].to_vec(),
                ))
                .unwrap();
        });
    });

    let (
        outcome,
        gen_before,
        gen_after,
        latest_cause_bytes,
        pre_draw,
        post_draw,
        rekeys_before,
        rekeys_after,
        reseeded_wall,
        reinit_all_count,
        second_boot_is_cold,
        post_resume_header,
    ) = recv(&res_rx);

    assert_eq!(outcome, Ok(HibernateOutcome::Resumed));
    assert_eq!(
        machine.machine.bsp_post_resume_restores(),
        restores_before + 1,
        "BSP architectural state restore must run on resume"
    );
    assert_eq!(
        gen_after,
        gen_before + 1,
        "MachineGeneration must advance on resume"
    );
    assert_eq!(
        latest_cause_bytes, image_id,
        "MachineGeneration advance must record the restored image_id"
    );
    assert_ne!(
        post_draw, pre_draw,
        "RootEntropy output must differ immediately after resume"
    );
    assert!(
        rekeys_after > rekeys_before,
        "RootEntropy must rekey immediately on resume"
    );
    assert_eq!(
        reseeded_wall.map(|(_, nanos)| nanos),
        Some(rtc_nanos),
        "wall clock must be reseeded from boot kernel's RTC reading"
    );
    assert_eq!(
        reinit_all_count, 1,
        "devices.reinitialize_all() must run once on resume"
    );
    assert!(
        second_boot_is_cold,
        "second boot from the same disk must see ResumeProbe::NoImage (cold boot)"
    );
    assert!(
        post_resume_header.iter().all(|&b| b == 0),
        "disk header sector 0..8 must be zeroed on resume"
    );

    // Every processor (including all 3 restarted secondaries) must resume running tasks!
    wait_for_all_tasks_to_advance(&progress, &progress_baseline);

    // Clean up allocation and stop background tasks.
    let (freed_tx, freed_rx) = bounded(1);
    machine.on(0, move |_kernel, _cpu| {
        let ptr = core::ptr::NonNull::new(pattern_addr as *mut u8).unwrap();
        machine
            .pool
            .deallocate_bytes_on(ProcessorId::new(0), ptr, pattern_layout);
        freed_tx.send(()).unwrap();
    });
    recv(&freed_rx);
    stop.store(true, Ordering::Release);
}

/// Boot probe refusal tests:
/// - Flipped header MAC byte -> `ResumeProbe::Refused(InvalidMac)`, header
///   invalidated on disk, second probe returns `ResumeProbe::NoImage`.
/// - Flipped chunk payload byte -> `ResumeProbe::Refused(ChunkChecksumMismatch)`,
///   header invalidated on disk, second probe returns `ResumeProbe::NoImage`.
/// - Different kernel build / mismatched `HibernateIdentity` ->
///   `ResumeProbe::Refused(KernelTextMismatch)`, header invalidated on disk,
///   second probe returns `ResumeProbe::NoImage`.
#[test]
fn hibernate_resume_probe_refuses_tampered_or_mismatched_images_and_invalidates_disk() {
    let (machine, _turn) = machine();
    let identity = sample_identity();

    // Write one real valid hibernate image to copy into each tampered scenario.
    let (hib_tx, hib_rx) = bounded(1);
    machine.on(0, move |kernel, cpu| {
        let cpu = cpu.clone();
        kernel.spawn_local_detached(async move {
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut disk = MemoryHibernateDisk::new(8 * 1024 * 1024, 4096, events.clone(), None);
            let mut devices = RecordingDeviceController::new(events);
            let generation = MachineGeneration::new(None);
            let entropy = RootEntropy::from_platform(&cpu, None, None, generation.clone())
                .expect("hosted entropy");
            let outcome = hibernate_to_disk_with_power_off(
                kernel,
                &cpu,
                machine.pool,
                AtomicSnapshotParams {
                    balloon: None,
                    auth_key: Some(&machine.auth_key),
                    identity,
                    reservation_bytes: RESERVATION_BYTES,
                    arrival_deadline: ARRIVAL_DEADLINE,
                    config: SnapshotConfig::new([0x3c; 16]),
                },
                ResumeTargets {
                    machine_generation: &generation,
                    root_entropy: &entropy,
                    reseed_wall_clock: |_, _| {},
                },
                &mut disk,
                &mut devices,
                || {},
                || {},
            )
            .await;
            hib_tx.send((outcome, disk.bytes().to_vec())).unwrap();
        });
    });
    let (outcome, valid_disk) = recv(&hib_rx);
    assert!(matches!(outcome, Ok(HibernateOutcome::PoweredOff { .. })));

    let machine_max_frames = machine.phys_bytes.div_ceil(PhysFrame::SIZE as u64);
    let usable = [FrameRun::new(0, machine_max_frames + 4096)];

    // 1. Flipped MAC byte -> InvalidMac + invalidated on disk.
    let mut bad_mac_disk = MemoryHibernateDisk::new(
        valid_disk.len(),
        4096,
        Arc::new(Mutex::new(Vec::new())),
        None,
    );
    bad_mac_disk.bytes.copy_from_slice(&valid_disk);
    bad_mac_disk.bytes[HEADER_MAC_OFFSET + 3] ^= 0x40;
    let probe = probe_and_load_hibernate_image(
        &mut bad_mac_disk,
        Some(&machine.auth_key),
        &identity,
        machine_max_frames,
        &usable,
        &[],
        2,
        |_, _| {},
        || {},
    );
    assert!(matches!(
        probe,
        ResumeProbe::Refused(HibernateError::InvalidMac)
    ));
    assert!(bad_mac_disk.bytes[..HEADER_BYTES].iter().all(|&b| b == 0));
    assert!(matches!(
        probe_and_load_hibernate_image(
            &mut bad_mac_disk,
            Some(&machine.auth_key),
            &identity,
            machine_max_frames,
            &usable,
            &[],
            2,
            |_, _| {},
            || {},
        ),
        ResumeProbe::NoImage
    ));

    // 2. Flipped chunk payload byte -> ChunkChecksumMismatch + invalidated on disk.
    let mut bad_chunk_disk = MemoryHibernateDisk::new(
        valid_disk.len(),
        4096,
        Arc::new(Mutex::new(Vec::new())),
        None,
    );
    bad_chunk_disk.bytes.copy_from_slice(&valid_disk);
    bad_chunk_disk.bytes[HEADER_BYTES + 16] ^= 0xff;
    let probe = probe_and_load_hibernate_image(
        &mut bad_chunk_disk,
        Some(&machine.auth_key),
        &identity,
        machine_max_frames,
        &usable,
        &[],
        2,
        |_, _| {},
        || {},
    );
    assert!(matches!(
        probe,
        ResumeProbe::Refused(HibernateError::ChunkChecksumMismatch { chunk_index: 0 })
    ));
    assert!(bad_chunk_disk.bytes[..HEADER_BYTES].iter().all(|&b| b == 0));
    assert!(matches!(
        probe_and_load_hibernate_image(
            &mut bad_chunk_disk,
            Some(&machine.auth_key),
            &identity,
            machine_max_frames,
            &usable,
            &[],
            2,
            |_, _| {},
            || {},
        ),
        ResumeProbe::NoImage
    ));

    // 3. Different kernel build (mismatched kernel `.text` SHA-256) ->
    //    KernelTextMismatch + invalidated on disk.
    let mut different_kernel_identity = identity;
    different_kernel_identity.kernel_text_sha256[0] ^= 0xaa;
    let mut wrong_id_disk = MemoryHibernateDisk::new(
        valid_disk.len(),
        4096,
        Arc::new(Mutex::new(Vec::new())),
        None,
    );
    wrong_id_disk.bytes.copy_from_slice(&valid_disk);
    let probe = probe_and_load_hibernate_image(
        &mut wrong_id_disk,
        Some(&machine.auth_key),
        &different_kernel_identity,
        machine_max_frames,
        &usable,
        &[],
        2,
        |_, _| {},
        || {},
    );
    assert!(matches!(
        probe,
        ResumeProbe::Refused(HibernateError::KernelTextMismatch)
    ));
    assert!(wrong_id_disk.bytes[..HEADER_BYTES].iter().all(|&b| b == 0));
    assert!(matches!(
        probe_and_load_hibernate_image(
            &mut wrong_id_disk,
            Some(&machine.auth_key),
            &different_kernel_identity,
            machine_max_frames,
            &usable,
            &[],
            2,
            |_, _| {},
            || {},
        ),
        ResumeProbe::NoImage
    ));
}

/// Verifies that `Cpu::continue_timebase(floor)` keeps `Cpu::now()` strictly
/// monotonic even when the underlying hardware counter resets near zero on a
/// new boot after hibernate/resume.
#[test]
fn monotonic_timebase_continues_strictly_across_counter_reset() {
    let test_machine = HostedMachine::new(1, ProcessorId::new(0), 64 * 1024);
    let cpu = HostedCpu::new(ProcessorId::new(0), test_machine.clone());

    test_machine.set_raw_ticks_override(Some(5_000_000));
    let pre_hibernate = cpu.now();
    assert_eq!(pre_hibernate.ticks(), 5_000_000);

    // Simulate a new boot whose raw counter starts near zero.
    test_machine.set_raw_ticks_override(Some(42));
    cpu.continue_timebase(pre_hibernate);
    let immediately_after = cpu.now();
    assert!(
        immediately_after > pre_hibernate,
        "Cpu::now() must advance strictly past pre-hibernate floor: before={}, after={}",
        pre_hibernate.ticks(),
        immediately_after.ticks(),
    );
    assert_eq!(immediately_after.ticks(), pre_hibernate.ticks() + 1);

    // Subsequent counter ticks must continue advancing at 1:1 rate.
    test_machine.set_raw_ticks_override(Some(100));
    assert_eq!(cpu.now().ticks(), immediately_after.ticks() + 58);

    // A second resume whose raw counter is already higher than floor must also
    // stay monotonic without going backwards.
    let second_floor = cpu.now();
    test_machine.set_raw_ticks_override(Some(20_000_000));
    cpu.continue_timebase(second_floor);
    assert!(cpu.now() > second_floor);
    assert_eq!(cpu.now().ticks(), 20_000_000);

    test_machine.set_raw_ticks_override(None);
    test_machine.reset_timebase_offset();
}

/// Verifies that a mid-way `quiesce_all` failure or `reinitialize_iommu`
/// failure calls `reinitialize_all`, releases the frame reservation, thaws the
/// machine without powering off, and returns the typed error.
#[test]
fn hibernate_device_failures_recover_and_thaw() {
    let (machine, _turn) = machine();
    let (stop, progress) = start_background_tasks(machine);
    let identity = sample_identity();

    for (fail_quiesce, fail_reinit_iommu) in [(true, false), (false, true)] {
        let baseline: Vec<usize> = progress.iter().map(|c| c.load(Ordering::SeqCst)).collect();
        let (tx, rx) = bounded(1);
        machine.on(0, move |kernel, cpu| {
            let cpu = cpu.clone();
            kernel.spawn_local_detached(async move {
                machine.pool.drain_all_frame_slabs();
                let allocated_before = machine.pool.stats().allocated_bytes;
                let events = Arc::new(Mutex::new(Vec::new()));
                let mut disk =
                    MemoryHibernateDisk::new(8 * 1024 * 1024, 4096, events.clone(), None);
                let mut devices = RecordingDeviceController::new(events.clone());
                devices.fail_quiesce = fail_quiesce;
                devices.fail_reinit_iommu = fail_reinit_iommu;
                let generation = MachineGeneration::new(None);
                let entropy = RootEntropy::from_platform(&cpu, None, None, generation.clone())
                    .expect("hosted entropy");
                let mut powered_off = false;
                let outcome = hibernate_to_disk_with_power_off(
                    kernel,
                    &cpu,
                    machine.pool,
                    AtomicSnapshotParams {
                        balloon: None,
                        auth_key: Some(&machine.auth_key),
                        identity,
                        reservation_bytes: RESERVATION_BYTES,
                        arrival_deadline: ARRIVAL_DEADLINE,
                        config: SnapshotConfig::new([0x5a; 16]),
                    },
                    ResumeTargets {
                        machine_generation: &generation,
                        root_entropy: &entropy,
                        reseed_wall_clock: |_, _| {},
                    },
                    &mut disk,
                    &mut devices,
                    || {},
                    || powered_off = true,
                )
                .await;
                machine.pool.drain_all_frame_slabs();
                let allocated_after = machine.pool.stats().allocated_bytes;
                let recorded = events.lock().unwrap().clone();
                tx.send((
                    outcome,
                    powered_off,
                    devices.reinit_all_count,
                    devices.reinit_iommu_count,
                    allocated_before,
                    allocated_after,
                    recorded,
                ))
                .unwrap();
            });
        });

        let (
            outcome,
            powered_off,
            reinit_all_count,
            reinit_iommu_count,
            allocated_before,
            allocated_after,
            recorded,
        ) = recv(&rx);
        assert!(
            !powered_off,
            "power_off must not run when device lifecycle fails"
        );
        assert_eq!(
            reinit_all_count, 1,
            "recover_devices_after_abort must call reinitialize_all"
        );
        if fail_quiesce {
            assert!(matches!(
                outcome,
                Err(HibernateError::Device(HibernateDeviceError::Quiesce { .. }))
            ));
            assert_eq!(reinit_iommu_count, 0);
            assert_eq!(
                recorded,
                vec![DiskEvent::QuiesceAll, DiskEvent::ReinitializeAll]
            );
        } else {
            assert!(matches!(
                outcome,
                Err(HibernateError::Device(HibernateDeviceError::Reinitialize {
                    device: "virtio-iommu",
                    ..
                }))
            ));
            assert_eq!(reinit_iommu_count, 1);
            assert_eq!(
                recorded,
                vec![
                    DiskEvent::QuiesceAll,
                    DiskEvent::ReinitializeIommu,
                    DiskEvent::ReinitializeAll,
                ]
            );
        }
        assert_eq!(
            allocated_after, allocated_before,
            "reservation must be released after device failure"
        );
        wait_for_all_tasks_to_advance(&progress, &baseline);
    }

    stop.store(true, Ordering::Release);
}
