use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicU64, Ordering};

use helios_hal::hv::{GuestAddress, GuestRange, IoWidth, VmExit};
use helios_hal::pmm::PhysFrame;
use helios_hal::vmm::{PageFlags, VirtAddr};

use crate::buffer::{GuestMemory, Span, WASM_PAGE_BYTES};
use crate::hv::{HvTelemetryRegistry, VirtualMachine};
use crate::inspect::buffer::encode_buffer;
use crate::inspect::{
    INSPECT_HEADER_BYTES, INSPECT_HEADER_MAGIC, InspectPublishError, InspectRegistry, InspectValue,
    KernelTelemetrySnapshot, MAX_INSPECT_SPAN_BYTES, MAX_PUBLICATIONS_PER_INSTANCE,
    PublicationStatus, emit_kernel_entries, is_valid_publication_name, is_valid_relative_path,
};
use crate::{AuthorityScope, InstanceRegistry, PrefixSet};

/// Page-aligned (64 KiB) mock guest linear memory backed by `Box<[AtomicU64]>`
/// so every offset is 8-byte aligned with interior mutability for atomic
/// 64-bit loads.
struct MockGuestMemory {
    words: Box<[AtomicU64]>,
}

impl MockGuestMemory {
    fn pages(page_count: usize) -> Self {
        let total_bytes = page_count * (WASM_PAGE_BYTES as usize);
        Self {
            words: (0..total_bytes / 8)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }

    fn guest_memory(&self) -> GuestMemory {
        GuestMemory::new(
            VirtAddr::new(self.words.as_ptr() as usize),
            (self.words.len() * 8) as u64,
        )
    }

    fn page_bytes_mut(&mut self, page_index: usize) -> &mut [u8] {
        let start = page_index * (WASM_PAGE_BYTES as usize / 8);
        let len = WASM_PAGE_BYTES as usize / 8;
        let slice = &mut self.words[start..start + len];
        let ptr = slice.as_mut_ptr().cast::<u8>();
        // SAFETY: `AtomicU64` has the same size (8) and alignment (8) as `u64`
        // with no padding, and `slice` is uniquely borrowed from `&mut self`.
        unsafe { core::slice::from_raw_parts_mut(ptr, len * 8) }
    }

    fn generation_word(&self, page_index: usize) -> &AtomicU64 {
        let start = page_index * (WASM_PAGE_BYTES as usize / 8);
        &self.words[start + 1]
    }
}

#[test]
fn publication_name_and_relative_path_validation_enforce_bounds() {
    assert!(is_valid_publication_name("vmm"));
    assert!(is_valid_publication_name("http_client-0.1"));
    assert!(!is_valid_publication_name(""));
    assert!(!is_valid_publication_name("."));
    assert!(!is_valid_publication_name(".."));
    assert!(!is_valid_publication_name("a/b"));
    assert!(!is_valid_publication_name("bad space"));
    assert!(!is_valid_publication_name(&"a".repeat(65)));

    assert!(is_valid_relative_path("requests/total"));
    assert!(is_valid_relative_path("status"));
    assert!(!is_valid_relative_path(""));
    assert!(!is_valid_relative_path("/leading"));
    assert!(!is_valid_relative_path("trailing/"));
    assert!(!is_valid_relative_path("a//b"));
    assert!(!is_valid_relative_path("a/../b"));
    assert!(!is_valid_relative_path("a/./b"));
    assert!(!is_valid_relative_path("bad\0nul"));
}

#[test]
fn publish_validates_span_duplicates_overlap_and_capacity() {
    let instances = InstanceRegistry::new();
    let inst = instances.register("vmm", 1);
    let registry = InspectRegistry::new();
    let memory = MockGuestMemory::pages(8);
    let gm = memory.guest_memory();

    // Misaligned / empty / out-of-bounds / oversized spans are refused.
    assert_eq!(
        registry
            .publish(inst.id(), "vmm", "a", gm, Span::new(0, 0))
            .err(),
        Some(InspectPublishError::BadSpan)
    );
    assert_eq!(
        registry
            .publish(inst.id(), "vmm", "a", gm, Span::new(4096, WASM_PAGE_BYTES))
            .err(),
        Some(InspectPublishError::BadSpan)
    );
    assert_eq!(
        registry
            .publish(
                inst.id(),
                "vmm",
                "a",
                gm,
                Span::new(0, MAX_INSPECT_SPAN_BYTES as u64 + WASM_PAGE_BYTES),
            )
            .err(),
        Some(InspectPublishError::BadSpan)
    );
    assert_eq!(
        registry
            .publish(
                inst.id(),
                "vmm",
                "a",
                gm,
                Span::new(8 * WASM_PAGE_BYTES, WASM_PAGE_BYTES),
            )
            .err(),
        Some(InspectPublishError::BadSpan)
    );
    assert_eq!(
        registry
            .publish(
                inst.id(),
                "vmm",
                "bad/name",
                gm,
                Span::new(0, WASM_PAGE_BYTES)
            )
            .err(),
        Some(InspectPublishError::InvalidName)
    );

    let p0 = registry
        .publish(inst.id(), "vmm", "slot0", gm, Span::new(0, WASM_PAGE_BYTES))
        .expect("first publication succeeds");
    assert_eq!(
        registry
            .publish(
                inst.id(),
                "vmm",
                "slot0",
                gm,
                Span::new(WASM_PAGE_BYTES, WASM_PAGE_BYTES),
            )
            .err(),
        Some(InspectPublishError::DuplicateName)
    );
    assert_eq!(
        registry
            .publish(
                inst.id(),
                "vmm",
                "overlap",
                gm,
                Span::new(0, WASM_PAGE_BYTES)
            )
            .err(),
        Some(InspectPublishError::BadSpan)
    );

    let mut held = vec![p0];
    for idx in 1..MAX_PUBLICATIONS_PER_INSTANCE {
        held.push(
            registry
                .publish(
                    inst.id(),
                    "vmm",
                    alloc::format!("slot{idx}"),
                    gm,
                    Span::new(idx as u64 * WASM_PAGE_BYTES, WASM_PAGE_BYTES),
                )
                .expect("within per-instance limit"),
        );
    }
    assert_eq!(
        registry
            .publish(
                inst.id(),
                "vmm",
                "overflow",
                gm,
                Span::new(
                    MAX_PUBLICATIONS_PER_INSTANCE as u64 * WASM_PAGE_BYTES,
                    WASM_PAGE_BYTES,
                ),
            )
            .err(),
        Some(InspectPublishError::TooManyPublications)
    );

    assert_eq!(registry.publication_count(), MAX_PUBLICATIONS_PER_INSTANCE);
    drop(held);
    assert_eq!(registry.publication_count(), 0);

    // Distinct linear memories publishing at the same guest offset (0) have
    // disjoint host virtual addresses and must not collide.
    let second_backing = MockGuestMemory::pages(1);
    let gm_second = second_backing.guest_memory();
    let _m0 = registry
        .publish(inst.id(), "vmm", "mem0", gm, Span::new(0, WASM_PAGE_BYTES))
        .expect("offset 0 in first memory succeeds");
    let _m1 = registry
        .publish(
            inst.id(),
            "vmm",
            "mem1",
            gm_second,
            Span::new(0, WASM_PAGE_BYTES),
        )
        .expect("offset 0 in distinct second memory must not collide");
    assert_eq!(registry.publication_count(), 2);
}

#[test]
fn lock_free_component_updates_are_visible_without_re_registering() {
    let instances = InstanceRegistry::new();
    let vmm = instances.register("vmm", 10);
    let registry = InspectRegistry::new();
    let mut memory = MockGuestMemory::pages(2);
    let gm = memory.guest_memory();

    // Generation 2 initial publish.
    encode_buffer(
        2,
        &[
            ("vm/running", InspectValue::Boolean(true)),
            ("vm/exits", InspectValue::Unsigned64(12)),
            ("vm/temp-delta", InspectValue::Signed64(-5)),
            ("vm/load", InspectValue::Float64(0.75)),
            (
                "vm/label",
                InspectValue::Text(String::from("你好・こんにちは・안녕하세요")),
            ),
            (
                "vm/cookie",
                InspectValue::Blob(vec![0xde, 0xad, 0xbe, 0xef]),
            ),
        ],
        memory.page_bytes_mut(0),
    )
    .expect("encode gen 2");

    let pub_handle = registry
        .publish(vmm.id(), "vmm", "state", gm, Span::new(0, WASM_PAGE_BYTES))
        .expect("publish");

    let snap = registry.snapshot(
        100,
        vmm.id(),
        Some(AuthorityScope::Own),
        &instances,
        None,
        None,
        &PrefixSet::default(),
        0,
    );
    assert!(!snap.truncated);
    assert_eq!(snap.publications.len(), 1);
    assert_eq!(snap.publications[0].status, PublicationStatus::Ok);
    assert_eq!(snap.publications[0].generation, 2);
    assert_eq!(snap.entries.len(), 6);
    assert!(snap.entries.iter().any(|e| {
        e.path == alloc::format!("/instances/{}/state/vm/exits", vmm.id().raw())
            && e.value == InspectValue::Unsigned64(12)
    }));
    assert!(snap.entries.iter().any(|e| {
        e.path == alloc::format!("/instances/{}/state/vm/label", vmm.id().raw())
            && e.value == InspectValue::Text(String::from("你好・こんにちは・안녕하세요"))
    }));

    // Zero-syscall in-place update to generation 4.
    encode_buffer(
        4,
        &[("vm/exits", InspectValue::Unsigned64(99))],
        memory.page_bytes_mut(0),
    )
    .expect("encode gen 4");

    let snap2 = registry.snapshot(
        200,
        vmm.id(),
        Some(AuthorityScope::Own),
        &instances,
        None,
        None,
        &PrefixSet::default(),
        0,
    );
    assert_eq!(snap2.publications[0].status, PublicationStatus::Ok);
    assert_eq!(snap2.publications[0].generation, 4);
    assert_eq!(snap2.entries.len(), 1);
    assert_eq!(snap2.entries[0].value, InspectValue::Unsigned64(99));

    drop(pub_handle);
    let after_drop = registry.snapshot(
        300,
        vmm.id(),
        Some(AuthorityScope::Own),
        &instances,
        None,
        None,
        &PrefixSet::default(),
        0,
    );
    assert!(after_drop.entries.is_empty());
    assert!(after_drop.publications.is_empty());
}

#[test]
fn torn_writes_and_corrupt_buffers_are_isolated_without_stalling_healthy_peers() {
    let instances = InstanceRegistry::new();
    let healthy = instances.register("healthy", 1);
    let busy = instances.register("busy-writer", 2);
    let corrupt_magic = instances.register("corrupt-magic", 3);
    let corrupt_payload = instances.register("corrupt-payload", 4);
    let registry = InspectRegistry::new();
    let mut mem = MockGuestMemory::pages(4);
    let gm = mem.guest_memory();

    encode_buffer(
        6,
        &[("ok", InspectValue::Unsigned64(7))],
        mem.page_bytes_mut(0),
    )
    .unwrap();
    // Odd generation simulates an active writer holding the seqlock open.
    encode_buffer(
        7,
        &[("in-flight", InspectValue::Unsigned64(1))],
        mem.page_bytes_mut(1),
    )
    .unwrap();
    // Bad magic in page 2.
    mem.page_bytes_mut(2)[0..4].copy_from_slice(b"NOPE");
    // Valid header in page 3, but truncated / invalid value tag in payload.
    encode_buffer(
        8,
        &[("x", InspectValue::Unsigned64(1))],
        mem.page_bytes_mut(3),
    )
    .unwrap();
    // Corrupt value tag byte at header + 2 (`path_len` is 2 bytes, tag is byte 2).
    mem.page_bytes_mut(3)[INSPECT_HEADER_BYTES + 2] = 0xff;

    let _p0 = registry
        .publish(
            healthy.id(),
            "healthy",
            "root",
            gm,
            Span::new(0, WASM_PAGE_BYTES),
        )
        .unwrap();
    let _p1 = registry
        .publish(
            busy.id(),
            "busy-writer",
            "root",
            gm,
            Span::new(WASM_PAGE_BYTES, WASM_PAGE_BYTES),
        )
        .unwrap();
    let _p2 = registry
        .publish(
            corrupt_magic.id(),
            "corrupt-magic",
            "root",
            gm,
            Span::new(2 * WASM_PAGE_BYTES, WASM_PAGE_BYTES),
        )
        .unwrap();
    let _p3 = registry
        .publish(
            corrupt_payload.id(),
            "corrupt-payload",
            "root",
            gm,
            Span::new(3 * WASM_PAGE_BYTES, WASM_PAGE_BYTES),
        )
        .unwrap();

    // Even with busy + corrupt buffers in the registry, the snapshot returns
    // immediately with the healthy buffer's entries intact and each faulty
    // publication classified cleanly.
    assert_eq!(mem.generation_word(1).load(Ordering::Acquire), 7);
    let snap = registry.snapshot(
        500,
        healthy.id(),
        Some(AuthorityScope::Machine),
        &instances,
        None,
        None,
        &PrefixSet::default(),
        0,
    );
    assert_eq!(snap.entries.len(), 1);
    assert_eq!(
        snap.entries[0].path,
        alloc::format!("/instances/{}/root/ok", healthy.id().raw())
    );
    assert_eq!(snap.publications.len(), 4);
    let status_of = |id| {
        snap.publications
            .iter()
            .find(|p| p.instance_id == id)
            .map(|p| p.status)
    };
    assert_eq!(status_of(healthy.id()), Some(PublicationStatus::Ok));
    assert_eq!(status_of(busy.id()), Some(PublicationStatus::Busy));
    assert_eq!(
        status_of(corrupt_magic.id()),
        Some(PublicationStatus::Corrupt)
    );
    assert_eq!(
        status_of(corrupt_payload.id()),
        Some(PublicationStatus::Corrupt)
    );

    // Also verify invalid payload_len past span end is rejected as Corrupt.
    let mut mem2 = MockGuestMemory::pages(1);
    mem2.page_bytes_mut(0)[0..4].copy_from_slice(&INSPECT_HEADER_MAGIC);
    mem2.page_bytes_mut(0)[4..6].copy_from_slice(&1u16.to_le_bytes());
    mem2.page_bytes_mut(0)[16..20].copy_from_slice(&(WASM_PAGE_BYTES as u32).to_le_bytes());
    let overflower = instances.register("overflower", 5);
    let _p4 = registry
        .publish(
            overflower.id(),
            "overflower",
            "root",
            mem2.guest_memory(),
            Span::new(0, WASM_PAGE_BYTES),
        )
        .unwrap();
    let snap2 = registry.snapshot(
        501,
        overflower.id(),
        Some(AuthorityScope::Own),
        &instances,
        None,
        None,
        &PrefixSet::default(),
        0,
    );
    assert!(snap2.entries.is_empty());
    assert_eq!(snap2.publications[0].status, PublicationStatus::Corrupt);
}

#[test]
fn authority_scopes_and_prefix_set_filter_kernel_and_subtree_publications() {
    let instances = InstanceRegistry::new();
    let sibling = instances.register("sibling", 1);
    let parent = instances.register("parent", 2);
    let child = instances.register_child(Some(parent.id()), "child", 3);
    let grandchild = instances.register_child(Some(child.id()), "grandchild", 4);

    let registry = InspectRegistry::new();
    let mut mem = MockGuestMemory::pages(4);
    let gm = mem.guest_memory();
    for (page, label) in [(0, "sib"), (1, "par"), (2, "chi"), (3, "gc")] {
        encode_buffer(
            2,
            &[("role", InspectValue::Text(String::from(label)))],
            mem.page_bytes_mut(page),
        )
        .unwrap();
    }
    let _ps = registry
        .publish(
            sibling.id(),
            "sibling",
            "info",
            gm,
            Span::new(0, WASM_PAGE_BYTES),
        )
        .unwrap();
    let _pp = registry
        .publish(
            parent.id(),
            "parent",
            "info",
            gm,
            Span::new(WASM_PAGE_BYTES, WASM_PAGE_BYTES),
        )
        .unwrap();
    let _pc = registry
        .publish(
            child.id(),
            "child",
            "info",
            gm,
            Span::new(2 * WASM_PAGE_BYTES, WASM_PAGE_BYTES),
        )
        .unwrap();
    let _pg = registry
        .publish(
            grandchild.id(),
            "grandchild",
            "info",
            gm,
            Span::new(3 * WASM_PAGE_BYTES, WASM_PAGE_BYTES),
        )
        .unwrap();

    let kernel = minimal_kernel_snapshot();

    // No InspectReadCap => empty snapshot.
    let none = registry.snapshot(
        10,
        parent.id(),
        None,
        &instances,
        None,
        Some(&kernel),
        &PrefixSet::default(),
        0,
    );
    assert!(none.entries.is_empty());
    assert!(none.publications.is_empty());

    // Own => only parent, never kernel or children or siblings.
    let own = registry.snapshot(
        10,
        parent.id(),
        Some(AuthorityScope::Own),
        &instances,
        None,
        Some(&kernel),
        &PrefixSet::default(),
        0,
    );
    assert_eq!(own.publications.len(), 1);
    assert_eq!(own.publications[0].instance_id, parent.id());
    assert!(!own.entries.iter().any(|e| e.path.starts_with("/kernel/")));

    // Subtree(parent) => parent + child + grandchild; excludes sibling & /kernel/*.
    let subtree = registry.snapshot(
        10,
        parent.id(),
        Some(AuthorityScope::Subtree(parent.id())),
        &instances,
        None,
        Some(&kernel),
        &PrefixSet::default(),
        0,
    );
    let ids: Vec<_> = subtree.publications.iter().map(|p| p.instance_id).collect();
    assert_eq!(ids, vec![parent.id(), child.id(), grandchild.id()]);
    assert!(
        !subtree
            .entries
            .iter()
            .any(|e| e.path.starts_with("/kernel/"))
    );

    // Machine + prefix selector ["/kernel/memory"] => only /kernel/memory/*, zero component reads.
    let mem_only = PrefixSet::from_prefixes(["/kernel/memory"]).unwrap();
    let machine_mem = registry.snapshot(
        10,
        parent.id(),
        Some(AuthorityScope::Machine),
        &instances,
        None,
        Some(&kernel),
        &mem_only,
        0,
    );
    assert!(machine_mem.publications.is_empty());
    assert!(!machine_mem.entries.is_empty());
    assert!(
        machine_mem
            .entries
            .iter()
            .all(|e| e.path.starts_with("/kernel/memory"))
    );

    // Limit & truncated flag.
    let capped = registry.snapshot(
        10,
        parent.id(),
        Some(AuthorityScope::Machine),
        &instances,
        None,
        Some(&kernel),
        &PrefixSet::default(),
        2,
    );
    assert_eq!(capped.entries.len(), 2);
    assert!(capped.truncated);
}

#[test]
fn kernel_hv_telemetry_reports_stage2_pages_vmid_vcpu_exits_and_ioevent_hits() {
    use crate::hv::tests::TestSpace;
    use crate::test_support::single_node_pool;
    use futures_lite::future::block_on;

    let hv_registry = HvTelemetryRegistry::new();
    let pool = single_node_pool(16);
    let owner = crate::InstanceId::from_raw(77);

    let exits = [
        VmExit::Mmio {
            address: GuestAddress(0x2000),
            access: helios_hal::hv::IoAccess::Write {
                width: helios_hal::hv::IoWidth::Dword,
                value: 1,
            },
        },
        VmExit::Hypercall { number: 9 },
    ];
    let space = TestSpace::new(exits);
    let mut vm =
        VirtualMachine::new_observed(space, pool, 4 * PhysFrame::SIZE, &hv_registry, Some(owner));
    let _region = vm
        .allocate_memory(
            GuestRange::new(GuestAddress(0), 2 * PhysFrame::SIZE).unwrap(),
            PageFlags::READ | PageFlags::WRITE,
        )
        .unwrap();
    let ioevent = vm
        .register_ioevent(GuestAddress(0x2000), IoWidth::Dword, Some(1))
        .unwrap();
    let mut vcpu = vm.create_vcpu(0, NonZeroUsize::new(4).unwrap()).unwrap();

    // First exit matches ioevent fast-path, second returns Hypercall(9).
    let exit = block_on(vcpu.run_vcpu()).unwrap();
    assert_eq!(exit, VmExit::Hypercall { number: 9 });
    block_on(ioevent.wait()).unwrap();

    let mut snapshot = minimal_kernel_snapshot();
    snapshot.hv_vms = hv_registry.snapshot();
    assert_eq!(snapshot.hv_vms.len(), 1);

    let mut entries = Vec::new();
    let hv_prefix = PrefixSet::from_prefixes(["/kernel/hv"]).unwrap();
    emit_kernel_entries(&snapshot, &hv_prefix, &mut entries);

    let find_u64 = |suffix: &str| {
        entries.iter().find_map(|e| {
            if e.path.ends_with(suffix) {
                match e.value {
                    InspectValue::Unsigned64(v) => Some(v),
                    _ => None,
                }
            } else {
                None
            }
        })
    };

    assert_eq!(find_u64("/kernel/hv/vm-count"), Some(1));
    assert_eq!(find_u64("/vmid"), Some(42));
    assert_eq!(find_u64("/owner-instance-id"), Some(77));
    assert_eq!(find_u64("/stage2-pages"), Some(2));
    assert_eq!(find_u64("/stage2-bytes"), Some(2 * PhysFrame::SIZE as u64));
    assert_eq!(find_u64("/vcpus"), Some(1));
    assert_eq!(find_u64("/vcpu-exits/total"), Some(2));
    assert_eq!(find_u64("/vcpu-exits/mmio"), Some(1));
    assert_eq!(find_u64("/vcpu-exits/hypercall"), Some(1));
    assert_eq!(find_u64("/ioevent-registrations"), Some(1));
    assert_eq!(find_u64("/ioevent-hits"), Some(1));

    // Unmapping pages and dropping resources updates telemetry and unregisters VM.
    drop(ioevent);
    drop(vcpu);
    block_on(vm.unmap_memory(GuestRange::new(GuestAddress(0), 2 * PhysFrame::SIZE).unwrap()))
        .unwrap();
    let mid = hv_registry.snapshot();
    assert_eq!(mid[0].stage2_pages, 0);
    assert_eq!(mid[0].vcpus, 0);
    assert_eq!(mid[0].ioevent_registrations, 0);
    drop(vm);
    assert!(hv_registry.snapshot().is_empty());
}

#[cfg(feature = "linux")]
#[test]
fn kernel_containers_telemetry_reports_mounts_pids_uts_and_overlay_pages() {
    use crate::linux_container::{
        ContainerConfig, ContainerId, ContainerMountSpec, LinuxContainer,
    };
    use crate::test_support::UnsupportedStorage;
    use crate::vfs::{
        BOOT_DEVICE, MemoryFs, MountGrant, MountSharing, MountTable, Namespace, SharedOwner,
        write_bytes,
    };
    use crate::{
        BootFs, DirectoryAuthorityRights, EmbeddedBootDirectory, EmbeddedBootFs, ProcessAuthority,
    };
    use core::num::NonZeroU64;
    use futures_lite::future::block_on;
    use helios_hal::fs::{FileSystem, FsPath, OpenFlags, WritePosition};
    use helios_linux::syscall::{Credentials, UtsField};

    const TEST_BOOT: EmbeddedBootFs =
        EmbeddedBootFs::new(&[EmbeddedBootDirectory::new("box", 0)], &[]);
    let bootfs = BootFs::new(TEST_BOOT, BOOT_DEVICE);
    let table: MountTable<UnsupportedStorage> = MountTable::new(bootfs, 4);
    let mem_root = MemoryFs::new(table.allocate_device());
    // Write 5000 bytes into a file: `PagedBytes` stores 2 data frames plus 1 radix-tree
    // node frame (height 1) = 3 resident user-pool frames.
    block_on(async {
        let path = FsPath::new("payload.bin").unwrap();
        let _ = mem_root
            .open(path, OpenFlags::CREATE, 0, &crate::StoragePayer::for_test())
            .await
            .unwrap();
        let payload = vec![0xabu8; 5000];
        write_bytes(&mem_root, path, WritePosition::At(0), &payload, 0)
            .await
            .unwrap();
    });

    let namespace = Namespace::new(table);
    let mount_cap = ProcessAuthority::root().derive_mount_cap("/box").unwrap();
    block_on(namespace.mount(
        &mount_cap,
        crate::vfs::MountedFs::Memory(mem_root),
        MountGrant {
            rights: helios_hal::fs::FileSystemRights::READ
                | helios_hal::fs::FileSystemRights::WRITE,
            sharing: MountSharing::Private,
        },
    ))
    .unwrap();

    let caller_auth = ProcessAuthority::root();

    let container = block_on(LinuxContainer::create(
        ContainerId::new(NonZeroU64::new(9).unwrap()),
        &caller_auth,
        &namespace,
        ProcessAuthority::empty(),
        ContainerConfig {
            root: ContainerMountSpec {
                source_path: String::from("/box"),
                target_path: String::from("/"),
                rights: DirectoryAuthorityRights::READ | DirectoryAuthorityRights::WRITE,
                sharing: MountSharing::Private,
            },
            mounts: Vec::new(),
            shared_owner: SharedOwner {
                uid: 1000,
                gid: 1000,
            },
            credentials: Credentials::root(),
            hostname: UtsField::from_bytes(b"helios-box").unwrap(),
            domainname: UtsField::from_bytes(b"local").unwrap(),
        },
    ))
    .unwrap();

    let _pid1 = container.allocate_process().unwrap();
    let _pid2 = container.allocate_process().unwrap();

    let mut snapshot = minimal_kernel_snapshot();
    snapshot.containers = vec![container.telemetry()];

    let mut entries = Vec::new();
    let prefix = PrefixSet::from_prefixes(["/kernel/containers"]).unwrap();
    emit_kernel_entries(&snapshot, &prefix, &mut entries);

    let find = |path: &str| entries.iter().find(|e| e.path == path).map(|e| &e.value);
    assert_eq!(
        find("/kernel/containers/count"),
        Some(&InspectValue::Unsigned64(1))
    );
    assert_eq!(
        find("/kernel/containers/9/uts/hostname"),
        Some(&InspectValue::Text(String::from("helios-box")))
    );
    assert_eq!(
        find("/kernel/containers/9/uts/domainname"),
        Some(&InspectValue::Text(String::from("local")))
    );
    assert_eq!(
        find("/kernel/containers/9/pids/live"),
        Some(&InspectValue::Unsigned64(2))
    );
    assert_eq!(
        find("/kernel/containers/9/pids/allocated"),
        Some(&InspectValue::Unsigned64(2))
    );
    assert_eq!(
        find("/kernel/containers/9/overlay-pages"),
        Some(&InspectValue::Unsigned64(3))
    );
    assert_eq!(
        find("/kernel/containers/9/mounts/0/target"),
        Some(&InspectValue::Text(String::from("/")))
    );
    assert_eq!(
        find("/kernel/containers/9/mounts/0/kind"),
        Some(&InspectValue::Text(String::from("memory")))
    );
    assert_eq!(
        find("/kernel/containers/9/mounts/0/sharing"),
        Some(&InspectValue::Text(String::from("private")))
    );
    assert_eq!(
        find("/kernel/containers/9/mounts/0/overlay-pages"),
        Some(&InspectValue::Unsigned64(3))
    );
}

fn minimal_kernel_snapshot() -> KernelTelemetrySnapshot {
    KernelTelemetrySnapshot {
        timestamp: 1234,
        uptime: 1234,
        wall_clock: 5678,
        configured_processors: 2,
        online_processors: 2,
        guest_isa_level: "x86-64-v3",
        guest_isa_extras: vec!["avx2"],
        memory_total_bytes: 1024 * 1024,
        memory_available_bytes: 512 * 1024,
        memory_nodes: Vec::new(),
        block: None,
        iommu: None,
        balloon: None,
        swap: None,
        host_share: None,
        network: None,
        devices: Vec::new(),
        inputs: Vec::new(),
        audio: Vec::new(),
        #[cfg(feature = "linux")]
        containers: Vec::new(),
        hv_vms: Vec::new(),
    }
}
