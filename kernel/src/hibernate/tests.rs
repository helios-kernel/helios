use alloc::alloc::{Layout, alloc_zeroed, dealloc};
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::ptr::NonNull;

use helios_hal::boot::{BootMemoryKind, BootMemoryRegion, KernelSectionRange};
use helios_hal::cpu::{
    Aarch64SnapshotContext, BspSnapshotContext, ProcessorId, ResumeHandoff, Riscv64SnapshotContext,
    X86_64SnapshotContext,
};
use helios_hal::measured_boot::{NoMeasuredBoot, SealedSecret};
use helios_hal::numa::{NodeId, SingleNode};
use helios_hal::pmm::{PhysFrame, PhysFrameRange};
use helios_hal::{DeviceInventory, DmaModel};

use super::HibernateError;
use super::format::{
    DeviceFeatureRecord, FORMAT_VERSION, HEADER_BYTES, HEADER_MAC_OFFSET, HEADER_MAGIC,
    HibernateHeader, HibernateIdentity, canonical_dram_regions,
    canonical_firmware_memory_map_count, hash_device_inventory, hash_firmware_memory_map,
    hash_negotiated_features,
};
use super::snapshot::{
    BoundedVecSink, EncodeParams, FrameRun, ReservationWriter, SnapshotConfig,
    SnapshotEncodeScratch, encode_snapshot, encode_snapshot_with_scratch, normalize_physical_runs,
};
use super::verify::{decode_image_into, verify_image_header_and_table};
use crate::machine::MachineGeneration;
use crate::memory::{NodeRun, UserMemoryPool};
use crate::signing_key::{HibernateAuthKey, SeedSource, settle_signing_key};
use crate::test_support::TestCpu;
use crate::{KernelAllocator, RootEntropy};

fn auth_key(seed_byte: u8) -> HibernateAuthKey {
    HibernateAuthKey::from_seed(&SealedSecret::new([seed_byte; SealedSecret::LEN]))
}

fn sample_identity() -> HibernateIdentity {
    let fw_map = [
        BootMemoryRegion {
            start: 0x0010_0000,
            end: 0x0020_0000,
            kind: BootMemoryKind::BootloaderReclaimable,
        },
        BootMemoryRegion {
            start: 0x0020_0000,
            end: 0x1000_0000,
            kind: BootMemoryKind::Usable,
        },
    ];
    let devices = DeviceInventory::new()
        .with_debug_serial()
        .with_network()
        .with_block_devices(2)
        .with_memory_balloon();
    let features = [
        DeviceFeatureRecord {
            device_kind: 1,
            instance_index: 0,
            features: 0x0001_0023_0000_0005,
        },
        DeviceFeatureRecord {
            device_kind: 2,
            instance_index: 0,
            features: 0x0000_0001_0000_0400,
        },
    ];
    HibernateIdentity {
        kernel_text_phys_start: 0x0020_0000,
        kernel_text_virt_start: 0xffff_ffff_8000_0000,
        kernel_text_len: 0x0018_0000,
        kernel_text_sha256: [0x11; 32],

        kernel_rodata_phys_start: 0x0038_0000,
        kernel_rodata_virt_start: 0xffff_ffff_8018_0000,
        kernel_rodata_len: 0x0004_0000,
        kernel_rodata_sha256: [0x22; 32],

        boot_payload_phys_addr: 0x0100_0000,
        boot_payload_len: 0x0020_0000,
        boot_payload_sha256: [0x33; 32],

        firmware_memory_map_count: canonical_firmware_memory_map_count(&fw_map),
        firmware_memory_map_sha256: hash_firmware_memory_map(&fw_map),

        processor_count: 4,
        device_inventory_sha256: hash_device_inventory(devices, DmaModel::Translated),
        negotiated_features_sha256: hash_negotiated_features(&features),
    }
}

fn synthetic_frame(frame_idx: u64) -> [u8; PhysFrame::SIZE] {
    match frame_idx % 4 {
        // Compressible CJK text (Chinese + Japanese + Korean).
        0 => {
            let text =
                "hibernation snapshot / 春眠不覚暁 / 春はあけぼの / 봄날은 간다\n".as_bytes();
            core::array::from_fn(|i| text[(i + frame_idx as usize) % text.len()])
        }
        // Structured binary pattern.
        1 => core::array::from_fn(|i| ((frame_idx as usize + i * 7) & 0xff) as u8),
        // All-zero page.
        2 => [0_u8; PhysFrame::SIZE],
        // Deterministic pseudo-random (incompressible) page.
        _ => {
            let mut s = (frame_idx.wrapping_mul(0x9e37_79b9_7f4a_7c15)) | 1;
            core::array::from_fn(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                s as u8
            })
        }
    }
}

fn build_synthetic_image(
    key: &HibernateAuthKey,
    identity: HibernateIdentity,
    runs: &[FrameRun],
    machine_max_frames: u64,
    chunk_frames: u32,
) -> (
    Vec<u8>,
    HibernateHeader,
    BTreeMap<u64, [u8; PhysFrame::SIZE]>,
) {
    let mut frames = BTreeMap::new();
    for run in runs {
        for f in run.start_phys_frame..run.end_phys_frame() {
            frames.insert(f, synthetic_frame(f));
        }
    }
    let bsp = BspSnapshotContext::from_x86_64(&X86_64SnapshotContext {
        rbx: 0x1111_2222_3333_4444,
        rbp: 0x5555_6666_7777_8888,
        r12: 0x12,
        r13: 0x13,
        r14: 0x14,
        r15: 0x15,
        rsp: 0xffff_ffff_8040_0ff0,
        rip: 0xffff_ffff_8001_2340,
        rflags: 0x202,
        cr3: 0x0010_5000,
        cr0: 0x8005_0033,
        cr4: 0x0000_06f8,
        efer: 0x0000_0d01,
        fs_base: 0xffff_8000_0010_0000,
        gs_base: 0,
        mxcsr: 0x1f80,
        fcw: 0x037f,
        reserved: 0,
    });
    let mut config = SnapshotConfig::new([0xab; 16]);
    config.chunk_frames = chunk_frames;
    let mut sink = BoundedVecSink::new(16 * 1024 * 1024);
    let mut watchdog_pets = 0_usize;
    let header = encode_snapshot(
        EncodeParams {
            auth_key: Some(key),
            identity,
            machine_max_frames,
            bsp_context: bsp,
            config,
        },
        runs,
        &mut sink,
        |frame, dst| {
            *dst = *frames.get(&frame).expect("frame present in synthetic RAM");
        },
        || watchdog_pets += 1,
    )
    .expect("synthetic snapshot encodes cleanly");
    assert_eq!(watchdog_pets, header.chunk_count as usize);
    (sink.into_inner(), header, frames)
}

#[test]
fn round_trip_encode_and_decode_restores_every_frame_byte_for_byte() {
    let key = auth_key(0x41);
    let identity = sample_identity();
    let runs = [
        FrameRun::new(4, 10),  // 10 frames -> 3 chunks at chunk_frames=4 (4, 4, 2)
        FrameRun::new(100, 6), // 6 frames -> 2 chunks (4, 2)
        FrameRun::new(250, 1), // 1 frame -> 1 chunk (1)
    ];
    let machine_max_frames = 512;
    let (image, encoded_header, original_frames) =
        build_synthetic_image(&key, identity, &runs, machine_max_frames, 4);

    assert_eq!(encoded_header.chunk_count, 6);
    assert_eq!(encoded_header.total_frames, 17);

    let mut restored = BTreeMap::new();
    let decoded_header = decode_image_into(
        &image,
        &key,
        &identity,
        machine_max_frames,
        |start_frame, bytes| {
            let (frame_chunks, remainder) = bytes.as_chunks::<{ PhysFrame::SIZE }>();
            assert!(remainder.is_empty());
            for (i, &frame_bytes) in frame_chunks.iter().enumerate() {
                let prev = restored.insert(start_frame + i as u64, frame_bytes);
                assert!(prev.is_none(), "frame decoded twice");
            }
            Ok(())
        },
    )
    .expect("valid authenticated image decodes cleanly");

    assert_eq!(decoded_header, encoded_header);
    assert_eq!(decoded_header.image_id, [0xab; 16]);
    assert_eq!(decoded_header.bsp_context, encoded_header.bsp_context);
    assert_eq!(restored.len(), original_frames.len());
    for (frame, expected) in &original_frames {
        assert_eq!(
            restored.get(frame).expect("frame restored"),
            expected,
            "frame {frame} bytes mismatch after round-trip"
        );
    }
}

#[test]
fn bsp_snapshot_contexts_round_trip_for_every_architecture() {
    let x86 = X86_64SnapshotContext {
        rbx: 1,
        rbp: 2,
        r12: 3,
        r13: 4,
        r14: 5,
        r15: 6,
        rsp: 7,
        rip: 8,
        rflags: 9,
        cr3: 10,
        cr0: 11,
        cr4: 12,
        efer: 13,
        fs_base: 14,
        gs_base: 15,
        mxcsr: 0x1f80,
        fcw: 0x037f,
        reserved: 0,
    };
    assert_eq!(BspSnapshotContext::from_x86_64(&x86).as_x86_64(), Some(x86));

    let arm = Aarch64SnapshotContext {
        callee_saved: core::array::from_fn(|i| 0x100 + i as u64),
        sp: 0x200,
        fp_callee_saved: core::array::from_fn(|i| 0x300 + i as u64),
        fpcr: 0x400,
        tpidr_el1: 0x401,
        sp_el0: 0x402,
        ttbr0_el1: 0x403,
        ttbr1_el1: 0x404,
        mair_el1: 0x405,
        tcr_el1: 0x406,
        sctlr_el1: 0x407,
        vbar_el1: 0x408,
        cpacr_el1: 0x409,
        daif: 0x40a,
        apia_lo: 0x40b,
        apia_hi: 0x40c,
        mte_enabled: 1,
        gcr_el1: 0x40d,
        rgsr_el1: 0x40e,
    };
    assert_eq!(
        BspSnapshotContext::from_aarch64(&arm).as_aarch64(),
        Some(arm)
    );

    let rv = Riscv64SnapshotContext {
        ra: 1,
        sp: 2,
        gp: 3,
        tp: 4,
        s: core::array::from_fn(|i| 10 + i as u64),
        fs: core::array::from_fn(|i| 30 + i as u64),
        fcsr: 50,
        sscratch: 51,
        sie: 52,
        satp: 53,
        stvec: 54,
        sstatus: 55,
    };
    assert_eq!(BspSnapshotContext::from_riscv64(&rv).as_riscv64(), Some(rv));
}

#[test]
fn flipped_byte_in_first_middle_or_last_chunk_is_refused() {
    let key = auth_key(0x52);
    let identity = sample_identity();
    let runs = [FrameRun::new(0, 12)];
    let (image, _, _) = build_synthetic_image(&key, identity, &runs, 64, 4);
    let verified = verify_image_header_and_table(&image, &key, &identity, 64).unwrap();
    assert_eq!(verified.chunks.len(), 3);

    for target_chunk in [0_usize, 1, 2] {
        let desc = verified.chunks[target_chunk];
        let mut tampered = image.clone();
        let flip_at = desc.data_offset as usize + (desc.compressed_len as usize / 2);
        tampered[flip_at] ^= 0x01;

        let err = decode_image_into(&tampered, &key, &identity, 64, |_, _| Ok(())).unwrap_err();
        assert_eq!(
            err,
            HibernateError::ChunkChecksumMismatch {
                chunk_index: target_chunk as u32
            },
            "tampered chunk {target_chunk} must fail checksum verification before decompression"
        );
    }
}

#[test]
fn wrong_mac_and_flipped_header_byte_are_refused() {
    let key = auth_key(0x63);
    let wrong_key = auth_key(0x64);
    let identity = sample_identity();
    let runs = [FrameRun::new(0, 4)];
    let (image, _, _) = build_synthetic_image(&key, identity, &runs, 64, 4);

    // Wrong key -> InvalidMac.
    assert_eq!(
        decode_image_into(&image, &wrong_key, &identity, 64, |_, _| Ok(())).unwrap_err(),
        HibernateError::InvalidMac
    );

    // Flipped byte inside header body (past magic+version, inside identity/flags).
    let mut flipped_body = image.clone();
    flipped_body[20] ^= 0x80;
    assert_eq!(
        decode_image_into(&flipped_body, &key, &identity, 64, |_, _| Ok(())).unwrap_err(),
        HibernateError::InvalidMac
    );

    // Flipped byte inside trailing MAC itself.
    let mut flipped_mac = image.clone();
    flipped_mac[HEADER_MAC_OFFSET + 15] ^= 0x01;
    assert_eq!(
        decode_image_into(&flipped_mac, &key, &identity, 64, |_, _| Ok(())).unwrap_err(),
        HibernateError::InvalidMac
    );
}

#[test]
fn truncated_header_and_truncated_chunk_table_are_refused() {
    let key = auth_key(0x74);
    let identity = sample_identity();
    let runs = [FrameRun::new(0, 8)];
    let (image, _, _) = build_synthetic_image(&key, identity, &runs, 64, 4);

    assert_eq!(
        decode_image_into(&image[..HEADER_BYTES - 1], &key, &identity, 64, |_, _| Ok(
            ()
        ))
        .unwrap_err(),
        HibernateError::TruncatedHeader {
            actual: HEADER_BYTES - 1,
            expected: HEADER_BYTES,
        }
    );

    assert_eq!(
        decode_image_into(
            &image[..image.len() - 1],
            &key,
            &identity,
            64,
            |_, _| Ok(())
        )
        .unwrap_err(),
        HibernateError::TruncatedChunkTable
    );
}

#[test]
fn image_claiming_more_frames_than_machine_is_refused() {
    let key = auth_key(0x85);
    let identity = sample_identity();
    let runs = [FrameRun::new(0, 16)];
    let (image, _, _) = build_synthetic_image(&key, identity, &runs, 64, 4);

    // Machine ceiling lower than image's total_frames.
    assert_eq!(
        decode_image_into(&image, &key, &identity, 12, |_, _| Ok(())).unwrap_err(),
        HibernateError::FrameCountExceedsMachine {
            image_frames: 16,
            machine_frames: 12,
        }
    );

    // Machine ceiling allows total_frames (4), but chunk starts at frame 200.
    let high_runs = [FrameRun::new(200, 4)];
    let (high_image, _, _) = build_synthetic_image(&key, identity, &high_runs, 256, 4);
    assert_eq!(
        decode_image_into(&high_image, &key, &identity, 100, |_, _| Ok(())).unwrap_err(),
        HibernateError::FrameCountExceedsMachine {
            image_frames: 204,
            machine_frames: 100,
        }
    );
}

#[test]
fn every_identity_mismatch_returns_its_own_typed_error() {
    let key = auth_key(0x96);
    let base = sample_identity();
    let runs = [FrameRun::new(0, 4)];
    let (image, _, _) = build_synthetic_image(&key, base, &runs, 64, 4);

    let mut wrong_text = base;
    wrong_text.kernel_text_sha256[0] ^= 1;
    assert_eq!(
        decode_image_into(&image, &key, &wrong_text, 64, |_, _| Ok(())).unwrap_err(),
        HibernateError::KernelTextMismatch
    );

    let mut wrong_rodata = base;
    wrong_rodata.kernel_rodata_len += 4096;
    assert_eq!(
        decode_image_into(&image, &key, &wrong_rodata, 64, |_, _| Ok(())).unwrap_err(),
        HibernateError::KernelRodataMismatch
    );

    let mut wrong_payload_digest = base;
    wrong_payload_digest.boot_payload_sha256[31] ^= 1;
    assert_eq!(
        decode_image_into(&image, &key, &wrong_payload_digest, 64, |_, _| Ok(())).unwrap_err(),
        HibernateError::BootPayloadDigestMismatch
    );

    let mut wrong_payload_len = base;
    wrong_payload_len.boot_payload_len += 0x1000;
    assert_eq!(
        decode_image_into(&image, &key, &wrong_payload_len, 64, |_, _| Ok(())).unwrap_err(),
        HibernateError::BootPayloadAddressMismatch
    );

    let mut wrong_fw_map = base;
    wrong_fw_map.firmware_memory_map_count += 1;
    assert_eq!(
        decode_image_into(&image, &key, &wrong_fw_map, 64, |_, _| Ok(())).unwrap_err(),
        HibernateError::FirmwareMemoryMapMismatch
    );

    let mut wrong_cpus = base;
    wrong_cpus.processor_count = 8;
    assert_eq!(
        decode_image_into(&image, &key, &wrong_cpus, 64, |_, _| Ok(())).unwrap_err(),
        HibernateError::ProcessorCountMismatch {
            image: 4,
            machine: 8,
        }
    );

    let mut wrong_devices = base;
    wrong_devices.device_inventory_sha256[5] ^= 0xff;
    assert_eq!(
        decode_image_into(&image, &key, &wrong_devices, 64, |_, _| Ok(())).unwrap_err(),
        HibernateError::DeviceInventoryMismatch
    );

    let mut wrong_features = base;
    wrong_features.negotiated_features_sha256[7] ^= 0xff;
    assert_eq!(
        decode_image_into(&image, &key, &wrong_features, 64, |_, _| Ok(())).unwrap_err(),
        HibernateError::NegotiatedFeaturesMismatch
    );

    // Header signed with a bogus identity_sha256 that doesn't match its own identity block.
    let mut bad_digest_header = HibernateHeader::decode_verified(&image, &key).unwrap();
    bad_digest_header.identity_sha256[0] ^= 0x55;
    let mut bad_image = image.clone();
    bad_image[..HEADER_BYTES].copy_from_slice(&bad_digest_header.encode_signed(&key));
    assert_eq!(
        decode_image_into(&bad_image, &key, &base, 64, |_, _| Ok(())).unwrap_err(),
        HibernateError::IdentityDigestMismatch
    );
}

#[test]
fn crafted_header_with_huge_counts_and_wrong_mac_fails_before_any_allocation() {
    let key = auth_key(0xa7);
    let identity = sample_identity();

    // Craft a 4096-byte header with valid magic & version, absurd counts/lengths
    // (u32::MAX chunks, u64::MAX table_len, u64::MAX total_frames), and bogus MAC.
    let mut crafted = vec![0xff_u8; HEADER_BYTES];
    crafted[..8].copy_from_slice(&HEADER_MAGIC);
    crafted[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());

    // Must return InvalidMac immediately without attempting to allocate
    // `u32::MAX` chunk descriptors or panicking on overflow.
    assert_eq!(
        verify_image_header_and_table(&crafted, &key, &identity, 64).unwrap_err(),
        HibernateError::InvalidMac
    );
    assert_eq!(
        decode_image_into(&crafted, &key, &identity, 64, |_, _| Ok(())).unwrap_err(),
        HibernateError::InvalidMac
    );
}

#[test]
fn ephemeral_seed_produces_no_hibernate_key_and_refuses_snapshot() {
    let entropy = RootEntropy::from_platform(
        &TestCpu::with_entropy(9),
        None,
        None,
        MachineGeneration::new(None),
    )
    .expect("test entropy");
    let settled = futures_lite::future::block_on(settle_signing_key(
        None::<&mut NoMeasuredBoot>,
        b"payload",
        &entropy,
    ))
    .expect("ephemeral settle succeeds");
    assert_eq!(settled.source, SeedSource::Ephemeral);
    assert!(settled.hibernate_auth.is_none());

    let mut sink = BoundedVecSink::new(1024 * 1024);
    let err = encode_snapshot(
        EncodeParams {
            auth_key: settled.hibernate_auth.as_ref(),
            identity: sample_identity(),
            machine_max_frames: 64,
            bsp_context: BspSnapshotContext::hosted(1),
            config: SnapshotConfig::new([1; 16]),
        },
        &[FrameRun::new(0, 1)],
        &mut sink,
        |_, dst| dst.fill(0),
        || {},
    )
    .unwrap_err();
    assert_eq!(err, HibernateError::NoAuthenticationKey);
}

struct AlignedPoolBacking {
    ptr: NonNull<u8>,
    layout: Layout,
}

impl AlignedPoolBacking {
    fn new(bytes: usize) -> Self {
        let layout = Layout::from_size_align(bytes, bytes).expect("pool backing layout");
        // SAFETY: `bytes` is a non-zero power of two.
        let raw = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(raw).expect("alloc pool backing");
        Self { ptr, layout }
    }

    fn range(&self) -> (usize, usize) {
        let start = self.ptr.as_ptr().expose_provenance();
        (start, start + self.layout.size())
    }
}

impl Drop for AlignedPoolBacking {
    fn drop(&mut self) {
        // SAFETY: matches `alloc_zeroed(self.layout)` in `new`.
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

#[test]
fn reservation_exhaustion_returns_typed_error_and_releases_all_reserved_frames() {
    let backing = AlignedPoolBacking::new(2 * 1024 * 1024);
    let (start, end) = backing.range();
    let pool = UserMemoryPool::new(
        &SingleNode::new(1),
        ProcessorId::new(0),
        &[NodeRun {
            start,
            end,
            node: NodeId::FIRST,
        }],
    );

    let before_stats = pool.stats();

    // Reserve only 2 frames (8 KiB) — enough for header (4 KiB) + 4 KiB payload,
    // deliberately too small for 16 incompressible frames (~64 KiB).
    let reservation = pool
        .reserve_hibernate_frames(2 * PhysFrame::SIZE)
        .expect("pool has 2 free frames");
    assert_eq!(reservation.capacity_bytes(), 2 * PhysFrame::SIZE);
    assert_eq!(
        pool.stats().allocated_bytes,
        before_stats.allocated_bytes + 2 * PhysFrame::SIZE
    );

    let mut writer = ReservationWriter::new(reservation);
    let key = auth_key(0xb8);
    let identity = sample_identity();
    let runs = [FrameRun::new(0, 16)];
    let err = encode_snapshot(
        EncodeParams {
            auth_key: Some(&key),
            identity,
            machine_max_frames: 64,
            bsp_context: BspSnapshotContext::hosted(42),
            config: SnapshotConfig::new([0x55; 16]),
        },
        &runs,
        &mut writer,
        |frame, dst| {
            // Incompressible noise guarantees output exceeds 4 KiB.
            let mut s = (frame.wrapping_mul(0x9e37_79b9_7f4a_7c15)) | 1;
            for byte in dst.iter_mut() {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                *byte = s as u8;
            }
        },
        || {},
    )
    .unwrap_err();
    assert!(matches!(err, HibernateError::ReservationExhausted { .. }));

    // Dropping the writer releases every reserved frame cleanly.
    drop(writer);
    pool.drain_all_frame_slabs();
    assert_eq!(pool.stats().allocated_bytes, before_stats.allocated_bytes);
}

#[test]
fn user_pool_allocated_ranges_drains_slabs_and_excludes_balloon_and_reservation() {
    let backing = AlignedPoolBacking::new(2 * 1024 * 1024);
    let (start, end) = backing.range();
    let pool = UserMemoryPool::new(
        &SingleNode::new(1),
        ProcessorId::new(0),
        &[NodeRun {
            start,
            end,
            node: NodeId::FIRST,
        }],
    );

    // Allocate two frames; free one so it sits cached in FrameSlabCache.
    let frame_layout = Layout::from_size_align(PhysFrame::SIZE, PhysFrame::SIZE).unwrap();
    let live = pool
        .allocate_zeroed_on(ProcessorId::new(0), frame_layout)
        .expect("live frame");
    let cached_free = pool
        .allocate_zeroed_on(ProcessorId::new(0), frame_layout)
        .expect("cached free frame");
    pool.deallocate_bytes_on(ProcessorId::new(0), cached_free, frame_layout);

    // Simulate a balloon-inflated frame and a hibernate reservation.
    let balloon_ptr = pool
        .allocate_zeroed_on(ProcessorId::new(0), frame_layout)
        .expect("balloon frame");
    let balloon_run =
        PhysFrameRange::from_phys_addr(balloon_ptr.as_ptr() as usize, PhysFrame::SIZE);
    let reservation = pool
        .reserve_hibernate_frames(4 * PhysFrame::SIZE)
        .expect("reservation");

    let mut excluded = reservation.frame_ranges();
    excluded.push(balloon_run);
    let ranges = pool.allocated_ranges(&excluded);

    let contains = |addr: usize| ranges.iter().any(|r| r.contains(&addr));
    assert!(
        contains(live.as_ptr() as usize),
        "live allocated frame must be included"
    );
    assert!(
        !contains(cached_free.as_ptr() as usize),
        "slab-cached free frame must be drained and excluded"
    );
    assert!(
        !contains(balloon_ptr.as_ptr() as usize),
        "balloon-inflated frame must be excluded"
    );
    for res_run in reservation.frame_ranges() {
        assert!(
            !contains(res_run.start.phys_addr()),
            "hibernate reservation frames must be excluded"
        );
    }

    drop(reservation);
    pool.deallocate_bytes_on(ProcessorId::new(0), live, frame_layout);
    pool.deallocate_bytes_on(ProcessorId::new(0), balloon_ptr, frame_layout);
}

#[test]
fn kernel_allocator_records_all_claimed_regions_without_allocating() {
    let first = AlignedPoolBacking::new(256 * 1024);
    let second = AlignedPoolBacking::new(256 * 1024);
    let allocator = KernelAllocator::empty();
    let (s1, e1) = first.range();
    let (s2, e2) = second.range();
    // SAFETY: `first` is an exclusively owned backing valid for this test.
    unsafe { allocator.add_to_heap(s1, e1) };
    // SAFETY: `second` is an exclusively owned backing disjoint from `first`.
    unsafe { allocator.add_to_heap(s2, e2) };
    let regions = allocator.claimed_regions();
    assert_eq!(regions.as_slice(), &[(s1, e1), (s2, e2)]);
}

#[test]
fn normalize_physical_runs_merges_and_subtracts_exclusions() {
    let p = PhysFrame::SIZE as u64;
    let runs = normalize_physical_runs(
        &[
            (2 * p)..(10 * p),
            (8 * p)..(14 * p),
            (20 * p + 123)..(22 * p - 1),
        ],
        &[(4 * p)..(6 * p), (12 * p)..(15 * p)],
    );
    assert_eq!(
        runs,
        vec![
            FrameRun::new(2, 2),
            FrameRun::new(6, 6),
            FrameRun::new(20, 2),
        ]
    );
}

#[test]
fn encode_snapshot_with_scratch_preserves_preallocated_buffers() {
    let key = auth_key(0x73);
    let identity = sample_identity();
    let runs = [FrameRun::new(8, 130), FrameRun::new(300, 5)];
    let machine_max_frames = 512;
    let config = SnapshotConfig::new([0x5c; 16]);
    let mut scratch = SnapshotEncodeScratch::for_runs(&runs, config.chunk_frames)
        .expect("pre-allocated encode scratch");
    let before = scratch.buffer_ptrs_and_caps();

    let mut sink = BoundedVecSink::new(16 * 1024 * 1024);
    let header = encode_snapshot_with_scratch(
        EncodeParams {
            auth_key: Some(&key),
            identity,
            machine_max_frames,
            bsp_context: BspSnapshotContext::hosted(11),
            config,
        },
        &runs,
        &mut scratch,
        &mut sink,
        |frame, dst| {
            *dst = synthetic_frame(frame);
        },
        || {},
    )
    .expect("zero-alloc LZ4 snapshot encode succeeds");

    assert_eq!(
        scratch.buffer_ptrs_and_caps(),
        before,
        "encode_snapshot_with_scratch must not reallocate any pre-allocated scratch buffer"
    );
    assert_eq!(header.chunk_count, 4);
    assert_eq!(header.total_frames, 135);

    let image = sink.into_inner();
    let mut restored_frames = 0_u64;
    let decoded = decode_image_into(
        &image,
        &key,
        &identity,
        machine_max_frames,
        |start_frame, bytes| {
            let (chunks, remainder) = bytes.as_chunks::<{ PhysFrame::SIZE }>();
            assert!(remainder.is_empty());
            for (idx, frame_bytes) in chunks.iter().enumerate() {
                assert_eq!(*frame_bytes, synthetic_frame(start_frame + idx as u64));
                restored_frames += 1;
            }
            Ok(())
        },
    )
    .expect("LZ4 snapshot decodes and verifies");
    assert_eq!(decoded, header);
    assert_eq!(restored_frames, 135);
}

#[test]
fn atomic_snapshot_reservation_exhaustion_thaws_and_releases_frames() {
    use super::snapshot::{AtomicSnapshotParams, SnapshotOutcome, capture_atomic_snapshot};
    use core::fmt;
    use core::sync::atomic::AtomicU8;
    use core::time::Duration;
    use helios_hal::Platform;
    use helios_hal::boot::BootMemoryMetadata;
    use helios_hal::cpu::{
        Cpu, Instant, SnapshotPoint, SnapshotUnsupported, Timebase, TimerInterrupt,
    };
    use helios_hal::memory::MemoryRegion;

    struct SinkConsole;
    impl fmt::Write for SinkConsole {
        fn write_str(&mut self, _: &str) -> fmt::Result {
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    struct SnapshotTestCpu {
        timebase: Timebase,
        resume_mode: bool,
    }

    impl Cpu for SnapshotTestCpu {
        type Hypervisor = core::convert::Infallible;
        type Native = core::convert::Infallible;
        const TIMER_INTERRUPT: TimerInterrupt = TimerInterrupt::Deadline;

        fn processor_count(&self) -> usize {
            1
        }
        fn bootstrap_processor(&self) -> ProcessorId {
            ProcessorId::new(0)
        }
        fn park_current(&self) {}
        type WakeOnlyMask = ();
        fn mask_to_wake_only(&self) {}
        fn park_wake_only(&self, _: &AtomicU8, _: u8) {}
        fn start_processor(&self, _: ProcessorId) {}
        fn wake_processor(&self, _: ProcessorId) {}
        fn stop_current(&self) {}
        fn restart_processor(&self, _: ProcessorId) {}
        fn now(&self) -> Instant {
            Instant::new(0)
        }
        fn timebase(&self) -> Timebase {
            self.timebase
        }
        fn set_deadline(&self, _: Instant) {}
        fn publish_executable(&self, _: *const u8, _: usize) {}
        fn unpublish_executable(&self, _: *const u8, _: usize) {}
        fn native_feature_probe(&self) -> Option<fn(&str) -> Option<bool>> {
            None
        }
        fn capture_bsp_state(
            &self,
            context: &mut BspSnapshotContext,
        ) -> Result<SnapshotPoint, SnapshotUnsupported> {
            *context = BspSnapshotContext::hosted(7);
            if self.resume_mode {
                Ok(SnapshotPoint::Resumed(ResumeHandoff {
                    image_id: [0x44; 16],
                    fresh_entropy: [0x99; 32],
                    rtc_unix_nanos: Some(1_760_000_000_000_000_000),
                    boot_monotonic_ticks: 12345,
                }))
            } else {
                Ok(SnapshotPoint::Captured)
            }
        }
        fn shutdown(&self) -> ! {
            panic!("unexpected shutdown")
        }
        fn reboot(&self) -> ! {
            panic!("unexpected reboot")
        }
    }

    // Prime a 16 MiB synthetic machine so `prime_bootstrap_allocator` and
    // `Kernel::freeze` run against real allocator + pool structures.
    let backing = AlignedPoolBacking::new(16 * 1024 * 1024);
    let (start, end) = backing.range();
    let span = NonNull::slice_from_raw_parts(backing.ptr, end - start);
    // SAFETY: `backing` stays alive for the rest of this test process.
    let region = unsafe { MemoryRegion::new(span, NodeId::FIRST) };
    let pool = crate::prime_bootstrap_allocator(
        core::iter::once(region),
        &SingleNode::new(1),
        ProcessorId::new(0),
    );
    let mut boot_memory = BootMemoryMetadata {
        physical_memory_offset: start,
        ..BootMemoryMetadata::default()
    };
    boot_memory.firmware_memory_map.push(BootMemoryRegion {
        start: 0,
        end: (end - start) as u64,
        kind: BootMemoryKind::Usable,
    });
    let cpu = SnapshotTestCpu {
        timebase: Timebase::new(1_000_000),
        resume_mode: false,
    };
    let kernel = crate::init(Platform::new(SinkConsole, cpu).with_boot_memory(boot_memory));
    let key = auth_key(0xc9);
    let identity = sample_identity();

    // Fill a few user pages with incompressible noise so a 2-frame (8 KiB)
    // reservation is guaranteed to exhaust during compression.
    let noise_layout = Layout::from_size_align(8 * PhysFrame::SIZE, PhysFrame::SIZE).unwrap();
    let noise_ptr = pool
        .allocate_zeroed_on(ProcessorId::new(0), noise_layout)
        .expect("noise pages");
    // SAFETY: `noise_ptr` is an exclusively owned 8-frame user allocation.
    let noise_slice =
        unsafe { core::slice::from_raw_parts_mut(noise_ptr.as_ptr(), 8 * PhysFrame::SIZE) };
    let mut s = 0xdead_beef_cafe_babe_u64;
    for byte in noise_slice.iter_mut() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        *byte = s as u8;
    }

    pool.drain_all_frame_slabs();
    let allocated_before = pool.stats().allocated_bytes;

    // 1. Reservation exhaustion: must return ReservationExhausted, thaw
    //    the machine cleanly, and release every reserved frame.
    let err = futures_lite::future::block_on(capture_atomic_snapshot(
        &kernel,
        &cpu,
        pool,
        AtomicSnapshotParams {
            balloon: None,
            auth_key: Some(&key),
            identity,
            reservation_bytes: 2 * PhysFrame::SIZE,
            arrival_deadline: Duration::from_secs(1),
            config: SnapshotConfig::new([0x33; 16]),
        },
        || {},
    ))
    .err()
    .expect("2-frame reservation must exhaust");
    assert!(matches!(err, HibernateError::ReservationExhausted { .. }));

    pool.drain_all_frame_slabs();
    assert_eq!(
        pool.stats().allocated_bytes,
        allocated_before,
        "exhausted reservation must return every reserved frame on failure"
    );

    // Confirm the machine thawed cleanly: a subsequent freeze succeeds immediately.
    let refreeze = futures_lite::future::block_on(kernel.freeze(Duration::from_secs(1), || {}))
        .expect("machine must be thawed after ReservationExhausted");
    refreeze.thaw();

    // 2. Resumed path returns `SnapshotOutcome::Resumed`, thaws, and releases frames.
    let resume_cpu = SnapshotTestCpu {
        timebase: Timebase::new(1_000_000),
        resume_mode: true,
    };
    let resumed = futures_lite::future::block_on(capture_atomic_snapshot(
        &kernel,
        &resume_cpu,
        pool,
        AtomicSnapshotParams {
            balloon: None,
            auth_key: Some(&key),
            identity,
            reservation_bytes: 4 * PhysFrame::SIZE,
            arrival_deadline: Duration::from_secs(1),
            config: SnapshotConfig::new([0x44; 16]),
        },
        || {},
    ))
    .expect("resume path succeeds");
    assert!(matches!(resumed, SnapshotOutcome::Resumed(h) if h.image_id == [0x44; 16]));
    pool.drain_all_frame_slabs();
    assert_eq!(pool.stats().allocated_bytes, allocated_before);

    pool.deallocate_bytes_on(ProcessorId::new(0), noise_ptr, noise_layout);
    // Keep `backing` alive past process exit because `prime_bootstrap_allocator`
    // installs a `'static` user pool referencing it.
    core::mem::forget(backing);
}

#[test]
fn write_image_to_storage_orders_payload_flush_before_header_and_invalidation_clears_sector_zero() {
    use super::storage::{
        HIBERNATE_HEADER_SECTORS, HIBERNATE_SECTOR_BYTES, HibernateStorage, HibernateStorageError,
        invalidate_hibernate_header, write_image_to_storage,
    };
    use helios_hal::io::IoError;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        Reinit,
        Write { start_sector: u64, byte_len: usize },
        Flush,
    }

    struct VecStorage {
        data: Vec<u8>,
        events: Vec<Event>,
        max_write: usize,
    }

    impl VecStorage {
        fn new(bytes: usize, max_write: usize) -> Self {
            Self {
                data: vec![0xaa; bytes],
                events: Vec::new(),
                max_write,
            }
        }
    }

    impl HibernateStorage for VecStorage {
        fn capacity_bytes(&self) -> u64 {
            self.data.len() as u64
        }
        fn sector_size(&self) -> usize {
            HIBERNATE_SECTOR_BYTES
        }
        fn max_write_bytes(&self) -> usize {
            self.max_write
        }
        fn reinitialize_for_write(&mut self) -> Result<(), HibernateStorageError> {
            self.events.push(Event::Reinit);
            Ok(())
        }
        fn write_sectors(
            &mut self,
            start_sector: u64,
            data: &[u8],
        ) -> Result<(), HibernateStorageError> {
            let offset = (start_sector as usize) * HIBERNATE_SECTOR_BYTES;
            if offset + data.len() > self.data.len() {
                return Err(HibernateStorageError::Write {
                    start_sector,
                    byte_len: data.len(),
                    error: IoError::OutOfBounds,
                });
            }
            self.data[offset..offset + data.len()].copy_from_slice(data);
            self.events.push(Event::Write {
                start_sector,
                byte_len: data.len(),
            });
            Ok(())
        }
        fn flush(&mut self) -> Result<(), HibernateStorageError> {
            self.events.push(Event::Flush);
            Ok(())
        }
        fn read_sectors(
            &mut self,
            start_sector: u64,
            dst: &mut [u8],
        ) -> Result<(), HibernateStorageError> {
            let offset = (start_sector as usize) * HIBERNATE_SECTOR_BYTES;
            dst.copy_from_slice(&self.data[offset..offset + dst.len()]);
            Ok(())
        }
    }

    let backing = AlignedPoolBacking::new(8 * 1024 * 1024);
    let (start, end) = backing.range();
    let pool = UserMemoryPool::new(
        &SingleNode::new(1),
        ProcessorId::new(0),
        &[NodeRun {
            start,
            end,
            node: NodeId::FIRST,
        }],
    );
    let reservation = pool
        .reserve_hibernate_frames(512 * 1024)
        .expect("reserve 512 KiB");
    let mut writer = ReservationWriter::new(reservation);

    let key = auth_key(0x7e);
    let identity = sample_identity();
    let mut frames = vec![0_u8; 8 * PhysFrame::SIZE];
    for (idx, byte) in frames.iter_mut().enumerate() {
        *byte = ((idx * 131) ^ (idx >> 4)) as u8;
    }
    let header = encode_snapshot(
        EncodeParams {
            auth_key: Some(&key),
            identity,
            machine_max_frames: 64,
            bsp_context: BspSnapshotContext::hosted(0x576),
            config: SnapshotConfig::new([0x5a; 16]),
        },
        &[FrameRun::new(0, 8)],
        &mut writer,
        |phys_frame, dst| {
            let off = (phys_frame as usize) * PhysFrame::SIZE;
            dst.copy_from_slice(&frames[off..off + PhysFrame::SIZE]);
        },
        || {},
    )
    .expect("encode snapshot");

    let mut storage = VecStorage::new(1024 * 1024, 2048);
    let mut pets = 0_usize;
    let written = write_image_to_storage(&header, &writer, &mut storage, || pets += 1)
        .expect("write image to storage");
    assert!(pets >= 3);
    assert!(written >= header.total_image_bytes);
    assert_eq!(written % HIBERNATE_SECTOR_BYTES as u64, 0);

    // Check strict crash-consistent ordering:
    // Reinit -> payload writes (sector >= 8) -> Flush -> Header write (sector 0, 4096B) -> Flush
    assert_eq!(storage.events[0], Event::Reinit);
    let n = storage.events.len();
    assert_eq!(storage.events[n - 1], Event::Flush);
    assert_eq!(
        storage.events[n - 2],
        Event::Write {
            start_sector: 0,
            byte_len: HEADER_BYTES,
        }
    );
    assert_eq!(storage.events[n - 3], Event::Flush);
    for event in &storage.events[1..n - 3] {
        match *event {
            Event::Write {
                start_sector,
                byte_len,
            } => {
                assert!(start_sector >= HIBERNATE_HEADER_SECTORS);
                assert_eq!(byte_len % HIBERNATE_SECTOR_BYTES, 0);
            }
            other => panic!("unexpected event before pre-header flush: {other:?}"),
        }
    }

    // Verify sector-padding tail is zeroed.
    let unpadded = header.total_image_bytes as usize;
    let padded = written as usize;
    assert!(storage.data[unpadded..padded].iter().all(|&b| b == 0));

    // Full decode round-trip directly from disk bytes.
    let mut restored = vec![0_u8; frames.len()];
    let decoded_header = decode_image_into(
        &storage.data[..padded],
        &key,
        &identity,
        64,
        |start_frame, bytes| {
            let off = (start_frame as usize) * PhysFrame::SIZE;
            restored[off..off + bytes.len()].copy_from_slice(bytes);
            Ok(())
        },
    )
    .expect("written disk bytes must verify and decode cleanly");
    assert_eq!(decoded_header, header);
    assert_eq!(restored, frames);

    // Invalidate header zeroes sector 0..8 and causes decode to reject with InvalidMagic.
    invalidate_hibernate_header(&mut storage).expect("invalidate header");
    assert!(storage.data[..HEADER_BYTES].iter().all(|&b| b == 0));
    assert_eq!(
        HibernateHeader::decode_verified(&storage.data[..HEADER_BYTES], &key),
        Err(HibernateError::InvalidMagic)
    );
}

#[test]
fn plan_frame_placement_keeps_displaced_trampoline_and_table_disjoint_from_targets_and_boot() {
    use super::format::ChunkDescriptor;
    use super::resume::plan_frame_placement;
    use alloc::collections::BTreeSet;

    let p = PhysFrame::SIZE as u64;
    // Usable physical RAM: frames 0..64.
    let usable = [FrameRun::new(0, 64)];
    // Boot kernel occupies frames 0..8 (kernel image + stack) and 20..26 (boot heap).
    let protected = [0..(8 * p), (20 * p)..(26 * p)];

    // Image chunks target:
    // - frames 2..10 (2..8 collide with boot, 8..10 are direct!)
    // - frames 18..24 (18..20 direct, 20..24 collide with boot!)
    // - frames 30..34 (30..34 direct!)
    let chunks = [
        ChunkDescriptor {
            start_phys_frame: 2,
            frame_count: 8,
            uncompressed_len: 8 * PhysFrame::SIZE as u32,
            compressed_len: 100,
            flags: 0,
            data_offset: HEADER_BYTES as u64,
            sha256: [0; 32],
        },
        ChunkDescriptor {
            start_phys_frame: 18,
            frame_count: 6,
            uncompressed_len: 6 * PhysFrame::SIZE as u32,
            compressed_len: 100,
            flags: 0,
            data_offset: (HEADER_BYTES + 100) as u64,
            sha256: [0; 32],
        },
        ChunkDescriptor {
            start_phys_frame: 30,
            frame_count: 4,
            uncompressed_len: 4 * PhysFrame::SIZE as u32,
            compressed_len: 100,
            flags: 0,
            data_offset: (HEADER_BYTES + 200) as u64,
            sha256: [0; 32],
        },
    ];

    let plan = plan_frame_placement(&chunks, &[], &usable, &usable, &protected, 5)
        .expect("64 usable frames easily satisfy 10 displaced + 5 table + 2 tramp + 1 copy table");

    // 2..8 (6 frames) + 20..24 (4 frames) = 10 displaced frames;
    // 8..10 (2) + 18..20 (2) + 30..34 (4) = 8 direct frames.
    assert_eq!(plan.direct_frames, 8);
    assert_eq!(plan.displaced_copies.len(), 10);
    assert_eq!(plan.trampoline_table_frames.len(), 5);
    assert_ne!(plan.copy_table_phys, 0);
    assert_eq!(plan.copy_table_pages, 1);

    // Collect every forbidden frame for safe allocations: all image targets + all boot protected.
    let mut forbidden = BTreeSet::new();
    for f in 0..8 {
        forbidden.insert(f * p);
    }
    for f in 20..26 {
        forbidden.insert(f * p);
    }
    for f in 2..10 {
        forbidden.insert(f * p);
    }
    for f in 18..24 {
        forbidden.insert(f * p);
    }
    for f in 30..34 {
        forbidden.insert(f * p);
    }

    // Verify every safe allocation is unique and strictly outside `forbidden`.
    let mut safe_used = BTreeSet::new();
    assert!(!forbidden.contains(&plan.trampoline_phys));
    assert!(safe_used.insert(plan.trampoline_phys));
    assert!(!forbidden.contains(&plan.trampoline_enter_copy_phys));
    assert!(safe_used.insert(plan.trampoline_enter_copy_phys));

    for &tbl in &plan.trampoline_table_frames {
        assert!(!forbidden.contains(&tbl), "table frame {tbl:#x} collides");
        assert!(safe_used.insert(tbl), "duplicate table frame {tbl:#x}");
    }

    for i in 0..plan.copy_table_pages {
        let addr = plan.copy_table_phys + i * p;
        assert!(!forbidden.contains(&addr), "copy table {addr:#x} collides");
        assert!(safe_used.insert(addr), "duplicate copy table {addr:#x}");
    }

    let mut displaced_dsts = BTreeSet::new();
    for copy in &plan.displaced_copies {
        assert!(
            !forbidden.contains(&copy.src_phys),
            "displaced src {:#x} overlaps image targets or boot protected memory",
            copy.src_phys
        );
        assert!(
            safe_used.insert(copy.src_phys),
            "displaced src {:#x} reused across safe pool",
            copy.src_phys
        );
        assert!(
            displaced_dsts.insert(copy.dst_phys),
            "duplicate displaced dst {:#x}",
            copy.dst_phys
        );
    }

    // Verify chunk placements match direct vs displaced exactly.
    let mut seen_displaced = 0_usize;
    for (chunk, placement) in chunks.iter().zip(&plan.chunk_placements) {
        assert_eq!(placement.start_phys_frame, chunk.start_phys_frame);
        assert_eq!(placement.staging_phys.len(), chunk.frame_count as usize);
        for (i, &staging) in placement.staging_phys.iter().enumerate() {
            let dst = (chunk.start_phys_frame + i as u64) * p;
            if staging != dst {
                assert_eq!(plan.displaced_copies[seen_displaced].src_phys, staging);
                assert_eq!(plan.displaced_copies[seen_displaced].dst_phys, dst);
                seen_displaced += 1;
            }
        }
    }
    assert_eq!(seen_displaced, plan.displaced_copies.len());
}

#[test]
fn plan_frame_placement_reports_insufficient_restore_memory_when_pool_exhausted() {
    use super::format::ChunkDescriptor;
    use super::resume::plan_frame_placement;

    let p = PhysFrame::SIZE as u64;
    // Only 10 usable frames total, 4 protected, image needs 4 displaced + 5 table + 1 trampoline.
    let usable = [FrameRun::new(0, 10)];
    let protected_range = 0..(4 * p);
    let chunks = [ChunkDescriptor {
        start_phys_frame: 0,
        frame_count: 4,
        uncompressed_len: 4 * PhysFrame::SIZE as u32,
        compressed_len: 100,
        flags: 0,
        data_offset: HEADER_BYTES as u64,
        sha256: [0; 32],
    }];

    let err = plan_frame_placement(
        &chunks,
        &[],
        &usable,
        &usable,
        core::slice::from_ref(&protected_range),
        5,
    )
    .expect_err("6 free frames cannot satisfy 5 table + 2 tramp + 1 copy table + 4 displaced");
    assert!(matches!(
        err,
        HibernateError::InsufficientRestoreMemory { .. }
    ));
}

#[test]
fn iommu_first_device_controller_ordering_is_enforced_on_quiesce_and_reinit() {
    use super::storage::{HibernateDeviceController, HibernateDeviceError};

    struct OrderedDeviceController {
        log: Vec<&'static str>,
        has_iommu: bool,
    }

    impl HibernateDeviceController for OrderedDeviceController {
        fn quiesce_all(&mut self) -> Result<(), HibernateDeviceError> {
            self.log.push("quiesce:virtio-blk");
            self.log.push("quiesce:virtio-net");
            self.log.push("quiesce:virtio-gpu");
            if self.has_iommu {
                self.log.push("quiesce:virtio-iommu");
            }
            Ok(())
        }

        fn reinitialize_all(&mut self) -> Result<(), HibernateDeviceError> {
            if self.has_iommu {
                self.log.push("reinit:virtio-iommu");
            }
            self.log.push("reinit:virtio-blk");
            self.log.push("reinit:virtio-net");
            self.log.push("reinit:virtio-gpu");
            Ok(())
        }
    }

    let mut controller = OrderedDeviceController {
        log: Vec::new(),
        has_iommu: true,
    };
    controller.quiesce_all().expect("quiesce succeeds");
    controller.reinitialize_all().expect("reinit succeeds");

    let quiesce_iommu = controller
        .log
        .iter()
        .position(|&e| e == "quiesce:virtio-iommu")
        .expect("iommu quiesced");
    let reinit_iommu = controller
        .log
        .iter()
        .position(|&e| e == "reinit:virtio-iommu")
        .expect("iommu reinitialized");
    for (idx, &entry) in controller.log.iter().enumerate() {
        if entry.starts_with("quiesce:") && entry != "quiesce:virtio-iommu" {
            assert!(
                idx < quiesce_iommu,
                "{entry} must quiesce BEFORE virtio-iommu"
            );
        }
        if entry.starts_with("reinit:") && entry != "reinit:virtio-iommu" {
            assert!(
                idx > reinit_iommu,
                "{entry} must reinitialize AFTER virtio-iommu"
            );
        }
    }
}

#[test]
fn probe_and_load_returns_no_image_on_blank_disk_and_invalidates_on_refusal() {
    use super::resume::{ResumeProbe, probe_and_load_hibernate_image};
    use super::storage::{HIBERNATE_SECTOR_BYTES, HibernateStorage, HibernateStorageError};

    struct MemDisk(Vec<u8>);
    impl HibernateStorage for MemDisk {
        fn capacity_bytes(&self) -> u64 {
            self.0.len() as u64
        }
        fn sector_size(&self) -> usize {
            HIBERNATE_SECTOR_BYTES
        }
        fn reinitialize_for_write(&mut self) -> Result<(), HibernateStorageError> {
            Ok(())
        }
        fn write_sectors(
            &mut self,
            start_sector: u64,
            data: &[u8],
        ) -> Result<(), HibernateStorageError> {
            let off = (start_sector as usize) * HIBERNATE_SECTOR_BYTES;
            self.0[off..off + data.len()].copy_from_slice(data);
            Ok(())
        }
        fn flush(&mut self) -> Result<(), HibernateStorageError> {
            Ok(())
        }
        fn read_sectors(
            &mut self,
            start_sector: u64,
            dst: &mut [u8],
        ) -> Result<(), HibernateStorageError> {
            let off = (start_sector as usize) * HIBERNATE_SECTOR_BYTES;
            dst.copy_from_slice(&self.0[off..off + dst.len()]);
            Ok(())
        }
    }

    let key = auth_key(0xd1);
    let identity = sample_identity();
    let usable = [FrameRun::new(0, 128)];

    // 1. Blank disk -> NoImage.
    let mut blank = MemDisk(vec![0_u8; 256 * 1024]);
    let probe = probe_and_load_hibernate_image(
        &mut blank,
        Some(&key),
        &identity,
        128,
        &usable,
        &usable,
        None,
        &[],
        2,
        |_, _| {},
        |_, _| {},
        || {},
    );
    assert!(matches!(probe, ResumeProbe::NoImage));

    // 2. Valid image probed with NO TPM key -> Refused(NoAuthenticationKey) AND
    //    sector 0..8 invalidated on disk so second probe returns NoImage.
    let runs = [FrameRun::new(4, 6)];
    let (mut image, _, _) = build_synthetic_image(&key, identity, &runs, 128, 4);
    image.resize(256 * 1024, 0);
    let mut disk = MemDisk(image);
    let probe = probe_and_load_hibernate_image(
        &mut disk,
        None,
        &identity,
        128,
        &usable,
        &usable,
        None,
        &[],
        2,
        |_, _| {},
        |_, _| {},
        || {},
    );
    assert!(matches!(
        probe,
        ResumeProbe::Refused(HibernateError::NoAuthenticationKey)
    ));
    assert!(
        disk.0[..HEADER_BYTES].iter().all(|&b| b == 0),
        "refusal must invalidate header on disk"
    );
    let second_probe = probe_and_load_hibernate_image(
        &mut disk,
        Some(&key),
        &identity,
        128,
        &usable,
        &usable,
        None,
        &[],
        2,
        |_, _| {},
        |_, _| {},
        || {},
    );
    assert!(matches!(second_probe, ResumeProbe::NoImage));
}

#[test]
fn canonical_dram_identity_tolerates_uefi_subsplits_and_refuses_ram_size_change() {
    use super::verify::verify_identity;

    // Boot 1 (OVMF 2 GiB): DRAM bank [0x10_0000..0x8000_0000] subdivided across
    // Usable, KernelAndModules, BootloaderReclaimable, AcpiReclaimable, AcpiNvs,
    // and top-of-RAM UEFI Runtime Services (`Reserved`), plus an Unusable PCI
    // framebuffer at 0x8000_0000 and standalone Reserved firmware flash.
    let boot1_map = [
        BootMemoryRegion {
            start: 0x0000_0000,
            end: 0x000a_0000,
            kind: BootMemoryKind::Usable,
        },
        BootMemoryRegion {
            start: 0x0010_0000,
            end: 0x784e_b000,
            kind: BootMemoryKind::Usable,
        },
        BootMemoryRegion {
            start: 0x784e_b000,
            end: 0x7ab0_0000,
            kind: BootMemoryKind::KernelAndModules,
        },
        BootMemoryRegion {
            start: 0x7ab0_0000,
            end: 0x7f80_0000,
            kind: BootMemoryKind::BootloaderReclaimable,
        },
        BootMemoryRegion {
            start: 0x7f80_0000,
            end: 0x7fa0_0000,
            kind: BootMemoryKind::AcpiReclaimable,
        },
        BootMemoryRegion {
            start: 0x7fa0_0000,
            end: 0x7fc0_0000,
            kind: BootMemoryKind::AcpiNvs,
        },
        BootMemoryRegion {
            start: 0x7fc0_0000,
            end: 0x8000_0000,
            kind: BootMemoryKind::Reserved,
        },
        BootMemoryRegion {
            start: 0x8000_0000,
            end: 0x8040_0000,
            kind: BootMemoryKind::Unusable,
        },
        BootMemoryRegion {
            start: 0xffc0_0000,
            end: 0x1_0000_0000,
            kind: BootMemoryKind::Reserved,
        },
    ];

    // Boot 2 (OVMF 2 GiB after NVRAM update): kernel shifted +1 MiB, ACPI NVS
    // & UEFI Runtime Services boundary shifted -128 KiB inside the same 2 GiB DRAM.
    let boot2_map = [
        BootMemoryRegion {
            start: 0x0000_0000,
            end: 0x000a_0000,
            kind: BootMemoryKind::Usable,
        },
        BootMemoryRegion {
            start: 0x0010_0000,
            end: 0x785e_b000,
            kind: BootMemoryKind::Usable,
        },
        BootMemoryRegion {
            start: 0x785e_b000,
            end: 0x7ac0_0000,
            kind: BootMemoryKind::KernelAndModules,
        },
        BootMemoryRegion {
            start: 0x7ac0_0000,
            end: 0x7f7e_0000,
            kind: BootMemoryKind::BootloaderReclaimable,
        },
        BootMemoryRegion {
            start: 0x7f7e_0000,
            end: 0x7f9e_0000,
            kind: BootMemoryKind::AcpiReclaimable,
        },
        BootMemoryRegion {
            start: 0x7f9e_0000,
            end: 0x7fbe_0000,
            kind: BootMemoryKind::AcpiNvs,
        },
        BootMemoryRegion {
            start: 0x7fbe_0000,
            end: 0x8000_0000,
            kind: BootMemoryKind::Reserved,
        },
        BootMemoryRegion {
            start: 0x8000_0000,
            end: 0x8040_0000,
            kind: BootMemoryKind::Unusable,
        },
        BootMemoryRegion {
            start: 0xffc0_0000,
            end: 0x1_0000_0000,
            kind: BootMemoryKind::Reserved,
        },
    ];

    assert_eq!(
        canonical_dram_regions(&boot1_map),
        vec![0x0000_0000..0x000a_0000, 0x0010_0000..0x8000_0000]
    );
    assert_eq!(
        canonical_dram_regions(&boot1_map),
        canonical_dram_regions(&boot2_map)
    );
    assert_eq!(
        canonical_firmware_memory_map_count(&boot1_map),
        canonical_firmware_memory_map_count(&boot2_map)
    );
    assert_eq!(
        hash_firmware_memory_map(&boot1_map),
        hash_firmware_memory_map(&boot2_map)
    );

    // Adding a second 2 GiB bank (-m 4G) or shrinking RAM (-m 1G) MUST fail.
    let mut ram_4g = boot2_map.to_vec();
    ram_4g.push(BootMemoryRegion {
        start: 0x1_0000_0000,
        end: 0x1_8000_0000,
        kind: BootMemoryKind::Usable,
    });
    assert_ne!(
        hash_firmware_memory_map(&boot1_map),
        hash_firmware_memory_map(&ram_4g)
    );

    let mut id_boot1 = sample_identity();
    id_boot1.firmware_memory_map_count = canonical_firmware_memory_map_count(&boot1_map);
    id_boot1.firmware_memory_map_sha256 = hash_firmware_memory_map(&boot1_map);
    let digest = id_boot1.digest();

    let mut id_boot2 = id_boot1;
    id_boot2.kernel_text_phys_start += 0x0010_0000;
    id_boot2.kernel_rodata_phys_start += 0x0010_0000;
    id_boot2.boot_payload_phys_addr += 0x0008_0000;
    id_boot2.firmware_memory_map_count = canonical_firmware_memory_map_count(&boot2_map);
    id_boot2.firmware_memory_map_sha256 = hash_firmware_memory_map(&boot2_map);
    verify_identity(&id_boot1, &digest, &id_boot2)
        .expect("shifted UEFI subsplits and physical load addresses must pass verify_identity");

    let mut id_4g = id_boot2;
    id_4g.firmware_memory_map_count = canonical_firmware_memory_map_count(&ram_4g);
    id_4g.firmware_memory_map_sha256 = hash_firmware_memory_map(&ram_4g);
    assert_eq!(
        verify_identity(&id_boot1, &digest, &id_4g),
        Err(HibernateError::FirmwareMemoryMapMismatch)
    );
}

#[test]
fn relocated_kernel_and_payload_pass_identity_and_restore_byte_for_byte_with_overlap() {
    use super::resume::{ResumeProbe, probe_and_load_hibernate_image};
    use super::storage::{HIBERNATE_SECTOR_BYTES, HibernateStorage, HibernateStorageError};
    use alloc::collections::BTreeSet;

    struct MemDisk(Vec<u8>);
    impl HibernateStorage for MemDisk {
        fn capacity_bytes(&self) -> u64 {
            self.0.len() as u64
        }
        fn sector_size(&self) -> usize {
            HIBERNATE_SECTOR_BYTES
        }
        fn reinitialize_for_write(&mut self) -> Result<(), HibernateStorageError> {
            Ok(())
        }
        fn write_sectors(
            &mut self,
            start_sector: u64,
            data: &[u8],
        ) -> Result<(), HibernateStorageError> {
            let off = (start_sector as usize) * HIBERNATE_SECTOR_BYTES;
            self.0[off..off + data.len()].copy_from_slice(data);
            Ok(())
        }
        fn flush(&mut self) -> Result<(), HibernateStorageError> {
            Ok(())
        }
        fn read_sectors(
            &mut self,
            start_sector: u64,
            dst: &mut [u8],
        ) -> Result<(), HibernateStorageError> {
            let off = (start_sector as usize) * HIBERNATE_SECTOR_BYTES;
            dst.copy_from_slice(&self.0[off..off + dst.len()]);
            Ok(())
        }
    }

    let p = PhysFrame::SIZE as u64;
    let key = auth_key(0xe2);

    // Boot 1 layout (inside 128 frames of DRAM):
    // - Full kernel ELF image: frames 16..26
    //   - .rodata: frames 16..18 (unaligned sub-page start +0x400 to mirror real ELF!)
    //   - .text:   frames 18..22
    //   - .data.rel.ro / .got: frames 22..24
    //   - writable .data/.bss: frames 24..26 (saved in chunks!)
    // - boot_payload: frames 30..34 (3 full pages + 512 bytes tail)
    // - user memory:  frames 4..8 (saved in chunks!)
    let mut boot1_id = sample_identity();
    boot1_id.kernel_rodata_phys_start = 16 * p + 0x400;
    boot1_id.kernel_rodata_virt_start = 0xffff_ffff_8000_0400;
    boot1_id.kernel_rodata_len = 2 * p - 0x400;
    boot1_id.kernel_text_phys_start = 18 * p;
    boot1_id.kernel_text_virt_start = 0xffff_ffff_8000_2000;
    boot1_id.kernel_text_len = 4 * p;
    boot1_id.boot_payload_phys_addr = 30 * p;
    boot1_id.boot_payload_len = 3 * p + 512;

    let chunk_runs = [FrameRun::new(4, 4), FrameRun::new(24, 2)];
    let (mut image_bytes, _header, expected_chunk_frames) =
        build_synthetic_image(&key, boot1_id, &chunk_runs, 128, 4);
    image_bytes.resize(512 * 1024, 0);
    let mut disk = MemDisk(image_bytes);

    // Boot 2 shifts the kernel image +4 frames (frames 20..30, overlapping Boot
    // 1's 16..26!) and shifts boot_payload +2 frames (frames 32..36, overlapping
    // Boot 1's 30..34!).
    let mut boot2_id = boot1_id;
    boot2_id.kernel_rodata_phys_start = 20 * p + 0x400;
    boot2_id.kernel_text_phys_start = 22 * p;
    boot2_id.boot_payload_phys_addr = 32 * p;
    let boot2_kernel_image = KernelSectionRange::new(20 * p, 0xffff_ffff_8000_0000, 10 * p);

    // Populate Boot 2's simulated physical RAM with distinct immutable bytes in
    // its kernel image (frames 20..30) and boot payload (frames 32..36).
    let mut ram: BTreeMap<u64, [u8; PhysFrame::SIZE]> = BTreeMap::new();
    let mut expected_relocated_kernel: BTreeMap<u64, [u8; PhysFrame::SIZE]> = BTreeMap::new();
    for offset in 0..10_u64 {
        let mut frame = [0_u8; PhysFrame::SIZE];
        for (i, b) in frame.iter_mut().enumerate() {
            *b = ((offset as usize * 37 + i * 13) ^ 0x5a) as u8;
        }
        ram.insert((20 + offset) * p, frame);
        if offset < 8 {
            // Frames 16..24 (read-only + RELRO/GOT) must match Boot 2's image
            // bytes; frames 24..26 (.data/.bss) MUST come from Boot 1's chunks!
            expected_relocated_kernel.insert((16 + offset) * p, frame);
        }
    }
    let mut expected_relocated_payload: BTreeMap<u64, [u8; PhysFrame::SIZE]> = BTreeMap::new();
    for offset in 0..4_u64 {
        let mut frame = [0_u8; PhysFrame::SIZE];
        for (i, b) in frame.iter_mut().enumerate() {
            *b = ((offset as usize * 71 + i * 3) ^ 0xa5) as u8;
        }
        ram.insert((32 + offset) * p, frame);
        let mut expected = frame;
        if offset == 3 {
            expected[512..].fill(0);
        }
        expected_relocated_payload.insert((30 + offset) * p, expected);
    }

    let dram = [FrameRun::new(0, 128)];
    // Boot 2's Usable RAM excludes its own kernel (20..30) and payload (32..36).
    let usable = [
        FrameRun::new(0, 20),
        FrameRun::new(30, 2),
        FrameRun::new(36, 92),
    ];
    let protected = [(20 * p)..(30 * p), (32 * p)..(36 * p)];

    let ram = core::cell::RefCell::new(ram);
    let loaded = match probe_and_load_hibernate_image(
        &mut disk,
        Some(&key),
        &boot2_id,
        128,
        &usable,
        &dram,
        Some(boot2_kernel_image),
        &protected,
        6,
        |src_phys, dst| {
            *dst = *ram
                .borrow()
                .get(&src_phys)
                .unwrap_or_else(|| panic!("missing relocated source frame {src_phys:#x}"));
        },
        |dst_phys, src| {
            ram.borrow_mut().insert(dst_phys, *src);
        },
        || {},
    ) {
        ResumeProbe::Ready(loaded) => loaded,
        other => panic!("expected ResumeProbe::Ready for relocated boot, got {other:?}"),
    };
    let mut ram = ram.into_inner();

    // 8 relocated kernel frames (16..24, skipping 24..26 owned by chunks) +
    // 4 relocated payload frames (30..34) = 12 relocated frames.
    assert_eq!(loaded.plan.relocated_placements.len(), 12);

    // Every safe allocation (trampoline, enter_copy, tables, copy_table,
    // displaced srcs) must be unique and disjoint from Boot 2 protected ranges
    // AND all Boot 1 targets (chunks + relocated).
    let mut forbidden = BTreeSet::new();
    for f in (4..8)
        .chain(16..26)
        .chain(20..30)
        .chain(30..34)
        .chain(32..36)
    {
        forbidden.insert(f * p);
    }
    let mut safe_used = BTreeSet::new();
    assert!(!forbidden.contains(&loaded.plan.trampoline_phys));
    assert!(safe_used.insert(loaded.plan.trampoline_phys));
    assert!(!forbidden.contains(&loaded.plan.trampoline_enter_copy_phys));
    assert!(safe_used.insert(loaded.plan.trampoline_enter_copy_phys));
    for &tbl in &loaded.plan.trampoline_table_frames {
        assert!(!forbidden.contains(&tbl));
        assert!(safe_used.insert(tbl));
    }
    for i in 0..loaded.plan.copy_table_pages {
        let addr = loaded.plan.copy_table_phys + i * p;
        assert!(!forbidden.contains(&addr));
        assert!(safe_used.insert(addr));
    }
    for copy in &loaded.plan.displaced_copies {
        assert!(!forbidden.contains(&copy.src_phys));
        assert!(safe_used.insert(copy.src_phys));
    }

    // Execute the restore trampoline's linear copy loop on simulated RAM.
    for copy in &loaded.plan.displaced_copies {
        let bytes = *ram
            .get(&copy.src_phys)
            .expect("displaced source frame staged");
        ram.insert(copy.dst_phys, bytes);
    }

    // Verify all chunks (user 4..8 AND mutated .data 24..26) restored intact.
    for (frame, expected) in &expected_chunk_frames {
        assert_eq!(
            ram.get(&(frame * p)).expect("chunk frame present"),
            expected,
            "chunk frame {frame} mismatch after relocation restore"
        );
    }
    // Verify all read-only/RELRO kernel pages (16..24) restored intact.
    for (phys, expected) in &expected_relocated_kernel {
        assert_eq!(
            ram.get(phys).expect("relocated kernel frame present"),
            expected,
            "relocated kernel frame {phys:#x} mismatch"
        );
    }
    // Verify all boot payload pages (30..34, including zero-padded tail) intact.
    for (phys, expected) in &expected_relocated_payload {
        assert_eq!(
            ram.get(phys).expect("relocated payload frame present"),
            expected,
            "relocated payload frame {phys:#x} mismatch"
        );
    }
}

#[test]
fn plan_frame_placement_refuses_target_outside_dram_regions() {
    use super::format::ChunkDescriptor;
    use super::resume::{RelocatedRegion, plan_frame_placement};

    let p = PhysFrame::SIZE as u64;
    // DRAM is only frames 0..64; frames 64..80 are outside DRAM (MMIO/Unusable).
    let dram = [FrameRun::new(0, 64)];
    let usable = [FrameRun::new(0, 64)];

    let bad_chunk = [ChunkDescriptor {
        start_phys_frame: 62,
        frame_count: 4, // 64..66 lie outside DRAM
        uncompressed_len: 4 * PhysFrame::SIZE as u32,
        compressed_len: 100,
        flags: 0,
        data_offset: HEADER_BYTES as u64,
        sha256: [0; 32],
    }];
    assert_eq!(
        plan_frame_placement(&bad_chunk, &[], &usable, &dram, &[], 4),
        Err(HibernateError::FirmwareMemoryMapMismatch)
    );

    let bad_reloc = [RelocatedRegion {
        boot_src_phys: 10 * p,
        image_dst_phys: 64 * p,
        byte_len: 2 * p,
    }];
    assert_eq!(
        plan_frame_placement(&[], &bad_reloc, &usable, &dram, &[], 4),
        Err(HibernateError::FirmwareMemoryMapMismatch)
    );
}
