use futures_lite::future::block_on;
use helios_hal::cpu::{Cpu, ProcessorId};
use helios_hal::fs::{FileSystemRights, WritePosition};
use helios_hal::watchdog::ProgressCounter;

use super::*;
use crate::test_support::{TestCpu, TestNetworkService, UnsupportedStorage};
use crate::{Executor, InstanceRegistry, MountedFs, ProcessAuthority, TaskFunding};

fn discard_serial_read(_: &mut Vec<u8>, _: u32) {}

fn test_program_store(
    wasix_abi: bool,
    cwd: Option<Preview1Cwd>,
    descriptors: Preview1DescriptorTable<TestNetworkService>,
) -> Preview1ProgramStore<TestCpu, TestNetworkService, UnsupportedStorage> {
    let cpu = TestCpu::with_entropy(0x5a);
    let runtime_state: HostRuntimeState<TestCpu, TestNetworkService, UnsupportedStorage> =
        crate::RuntimeState::new(
            cpu.timebase(),
            1,
            0,
            crate::BootPayload::for_tests(),
            GuestIsa::for_build_target(cpu.native_feature_probe()),
        );
    runtime_state.install_root_entropy(triomphe::Arc::new(
        crate::RootEntropy::from_platform(&cpu, None, None, crate::MachineGeneration::new(None))
            .expect("test CPU has an entropy source"),
    ));
    let executor = Executor::new(
        ProgressCounter::new(),
        crate::test_support::single_node_pool(1),
        ProcessorId::new(0),
    );
    let registry = InstanceRegistry::new();
    let instance = registry.register("path-lookup-test", 0);
    let store = Preview1ProgramStore::new(
        cpu,
        executor.timer(cpu),
        executor
            .spawner(cpu)
            .instance_spawner(TaskFunding::Instance, &instance),
        runtime_state.clone(),
        Arc::new(GuestInterrupts::new(1, cpu.timebase())),
        instance,
        None,
        Vec::new(),
        Vec::new(),
        ProcessAuthority::root(),
        OutputMode::Serial,
        discard_serial_read,
        crate::DebugSerialWriter::of::<test_store::DiscardPort>(),
        None,
        Some(runtime_state.root_namespace().descend()),
        Some(descriptors),
        WasixSignalState::new(),
        WasixSignalState::new(),
        Vec::new(),
        None,
        wasix_abi,
        WasixImageThreads::new(),
    );
    store.cwd.set(cwd);
    store
}

fn dir_descriptor(path: &str) -> FsDescriptor {
    FsDescriptor {
        path: String::from(path),
        kind: FsNodeKind::Directory,
        flags: FsDescriptorFlags::READ
            | FsDescriptorFlags::WRITE
            | FsDescriptorFlags::MUTATE_DIRECTORY,
        identity: None,
        mount: None,
    }
}

fn file_descriptor(path: &str) -> FsDescriptor {
    FsDescriptor {
        path: String::from(path),
        kind: FsNodeKind::File,
        flags: FsDescriptorFlags::READ | FsDescriptorFlags::WRITE,
        identity: None,
        mount: None,
    }
}

#[test]
fn wasix_relative_paths_use_cwd_only_for_at_fdcwd_and_honor_explicit_dirfd() {
    let descriptors = Preview1DescriptorTable::from_entries(vec![
        Some(Preview1DescriptorEntry::new(
            Preview1Descriptor::Stdin {
                carry: Bytes::new(),
            },
            false,
        )),
        None,
        None,
        Some(Preview1DescriptorEntry::new(
            Preview1Descriptor::Preopen {
                guest_name: String::from("/workspace"),
                descriptor: dir_descriptor("/workspace"),
            },
            false,
        )),
        Some(Preview1DescriptorEntry::new(
            Preview1Descriptor::File(OpenFile::new(dir_descriptor("/workspace/other"))),
            false,
        )),
        Some(Preview1DescriptorEntry::new(
            Preview1Descriptor::File(OpenFile::new(file_descriptor("/workspace/sub/file"))),
            false,
        )),
    ]);
    let cwd = Preview1Cwd {
        guest_name: String::from("/workspace/sub"),
        descriptor: dir_descriptor("/workspace/sub"),
    };
    let store = test_program_store(true, Some(cwd), descriptors);

    // AT_FDCWD (-2) resolves relative paths against cwd.
    let (base, rel) = store
        .resolve_wasix_path_base(
            Preview1ProgramStore::<TestCpu, TestNetworkService, UnsupportedStorage>::WASIX_AT_FDCWD,
            "note.txt",
        )
        .expect("AT_FDCWD resolves against cwd");
    assert_eq!(base.path, "/workspace/sub");
    assert_eq!(rel, "note.txt");

    // An explicit directory descriptor overrides cwd and resolves against that fd.
    let (base, rel) = store
        .resolve_wasix_path_base(4, "note.txt")
        .expect("explicit dirfd resolves against its own directory");
    assert_eq!(base.path, "/workspace/other");
    assert_eq!(rel, "note.txt");

    let (base, rel) = store
        .resolve_wasix_path_base(3, "sub/note.txt")
        .expect("preopen dirfd resolves against preopen");
    assert_eq!(base.path, "/workspace");
    assert_eq!(rel, "sub/note.txt");

    // Non-directory descriptors fail with NOTDIR.
    assert_eq!(
        store.resolve_wasix_path_base(5, "note.txt").err(),
        Some(p1::errno::NOTDIR)
    );
    assert_eq!(
        store.resolve_wasix_path_base(0, "note.txt").err(),
        Some(p1::errno::NOTDIR)
    );

    // Closed / invalid descriptors (including -1 and Linux's -100) fail with BADF.
    for bad_fd in [1, 99, -1, -100] {
        assert_eq!(
            store.resolve_wasix_path_base(bad_fd, "note.txt").err(),
            Some(p1::errno::BADF),
            "fd {bad_fd} must fail with BADF"
        );
    }

    // Absolute paths still resolve through preopens/cwd regardless of fd.
    let (base, rel) = store
        .resolve_wasix_path_base(99, "/workspace/other/file")
        .expect("absolute path resolves via preopen");
    assert_eq!(base.path, "/workspace");
    assert_eq!(rel, "other/file");

    // AT_FDCWD with no cwd fails with BADF.
    store.cwd.set(None);
    assert_eq!(
        store
            .resolve_wasix_path_base(
                Preview1ProgramStore::<TestCpu, TestNetworkService, UnsupportedStorage>::WASIX_AT_FDCWD,
                "note.txt",
            )
            .err(),
        Some(p1::errno::BADF)
    );
}

#[test]
fn wasix_and_preview1_lookup_operations_honor_dirfd_and_symlink_follow() {
    let descriptors = Preview1DescriptorTable::from_entries(vec![
        None,
        None,
        None,
        Some(Preview1DescriptorEntry::new(
            Preview1Descriptor::Preopen {
                guest_name: String::from("/workspace"),
                descriptor: dir_descriptor("/workspace"),
            },
            false,
        )),
        Some(Preview1DescriptorEntry::new(
            Preview1Descriptor::File(OpenFile::new(dir_descriptor("/workspace/other"))),
            false,
        )),
        Some(Preview1DescriptorEntry::new(
            Preview1Descriptor::File(OpenFile::new(file_descriptor("/workspace/sub/in-sub"))),
            false,
        )),
    ]);
    let cwd = Preview1Cwd {
        guest_name: String::from("/workspace/sub"),
        descriptor: dir_descriptor("/workspace/sub"),
    };
    let store = test_program_store(true, Some(cwd), descriptors);
    let ns = store.filesystem.clone();
    let mem_fs = MountedFs::Memory(MemoryFs::new(ns.table().allocate_device()));
    let cap = ProcessAuthority::root()
        .derive_mount_cap("/workspace")
        .expect("mount cap");
    block_on(async {
        ns.mount(
            &cap,
            mem_fs,
            FileSystemRights::READ | FileSystemRights::WRITE,
        )
        .await
        .expect("mount");
        let root_dir = dir_descriptor("/workspace");
        wasi_fs::create_directory_at(&ns, root_dir.grant().unwrap(), "sub", 1)
            .await
            .unwrap();
        wasi_fs::create_directory_at(&ns, root_dir.grant().unwrap(), "other", 1)
            .await
            .unwrap();
        let sub_file = wasi_fs::open_at(
            &ns,
            dir_descriptor("/workspace/sub").grant().unwrap(),
            fs_types::PathFlags::empty(),
            "in-sub",
            fs_types::OpenFlags::CREATE,
            FsDescriptorFlags::READ | FsDescriptorFlags::WRITE,
            1,
        )
        .await
        .unwrap();
        wasi_fs::write(
            &ns,
            sub_file.grant().unwrap(),
            WritePosition::At(0),
            b"sub",
            1,
        )
        .await
        .unwrap();
        let other_file = wasi_fs::open_at(
            &ns,
            dir_descriptor("/workspace/other").grant().unwrap(),
            fs_types::PathFlags::empty(),
            "in-other",
            fs_types::OpenFlags::CREATE,
            FsDescriptorFlags::READ | FsDescriptorFlags::WRITE,
            1,
        )
        .await
        .unwrap();
        wasi_fs::write(
            &ns,
            other_file.grant().unwrap(),
            WritePosition::At(0),
            b"payload",
            1,
        )
        .await
        .unwrap();
        wasi_fs::symlink_at(
            &ns,
            dir_descriptor("/workspace/other").grant().unwrap(),
            "in-other",
            "link",
            1,
        )
        .await
        .unwrap();
    });

    let at_fdcwd =
        Preview1ProgramStore::<TestCpu, TestNetworkService, UnsupportedStorage>::WASIX_AT_FDCWD;

    // 1. Open resolution: AT_FDCWD uses cwd (/workspace/sub); explicit dirfd 4 uses /workspace/other.
    let (base, rel) = store
        .resolve_preview1_open_base(at_fdcwd, "in-other")
        .expect("AT_FDCWD resolves against cwd");
    assert!(matches!(
        block_on(wasi_fs::open_at(
            &ns,
            base.grant().unwrap(),
            fs_types::PathFlags::empty(),
            &rel,
            fs_types::OpenFlags::empty(),
            FsDescriptorFlags::READ,
            1,
        )),
        Err(fs_types::ErrorCode::NoEntry)
    ));

    let (base, rel) = store
        .resolve_preview1_open_base(4, "in-other")
        .expect("explicit dirfd resolves against /workspace/other");
    let opened = block_on(wasi_fs::open_at(
        &ns,
        base.grant().unwrap(),
        fs_types::PathFlags::empty(),
        &rel,
        fs_types::OpenFlags::empty(),
        FsDescriptorFlags::READ,
        1,
    ))
    .expect("in-other opens via dirfd 4");
    assert_eq!(opened.path, "/workspace/other/in-other");

    assert_eq!(
        store.resolve_preview1_open_base(5, "x").err(),
        Some(p1::errno::NOTDIR)
    );
    assert_eq!(
        store.resolve_preview1_open_base(99, "x").err(),
        Some(p1::errno::BADF)
    );

    // 2. preview1 path_filestat_get & path_filestat_set_times honor SYMLINK_FOLLOW and dirfd.
    let (_, link_stat) = block_on(store.stat_preview1_path(4, 0, "link")).expect("lstat link");
    assert!(matches!(
        link_stat.type_,
        fs_types::DescriptorType::SymbolicLink
    ));

    let (_, target_stat) =
        block_on(store.stat_preview1_path(4, 1, "link")).expect("stat link target");
    assert!(matches!(
        target_stat.type_,
        fs_types::DescriptorType::RegularFile
    ));
    assert_eq!(target_stat.size, 7);

    // Without SYMLINK_FOLLOW: updates link times only.
    assert_eq!(
        block_on(store.set_preview1_path_times(
            4,
            fs_types::PathFlags::empty(),
            "link",
            111,
            222,
            P1_FSTFLAG_ATIM | P1_FSTFLAG_MTIM,
        )),
        p1::errno::SUCCESS
    );
    let (_, link_stat) = block_on(store.stat_preview1_path(4, 0, "link")).unwrap();
    assert_eq!(link_stat.data_access_timestamp.unwrap().nanoseconds, 111);
    assert_eq!(
        link_stat.data_modification_timestamp.unwrap().nanoseconds,
        222
    );
    let (_, target_stat) = block_on(store.stat_preview1_path(4, 0, "in-other")).unwrap();
    assert_ne!(
        target_stat.data_modification_timestamp.unwrap().nanoseconds,
        222
    );

    // With SYMLINK_FOLLOW: updates target times only, leaving link times intact.
    assert_eq!(
        block_on(store.set_preview1_path_times(
            4,
            fs_types::PathFlags::SYMLINK_FOLLOW,
            "link",
            333,
            444,
            P1_FSTFLAG_ATIM | P1_FSTFLAG_MTIM,
        )),
        p1::errno::SUCCESS
    );
    let (_, target_stat) = block_on(store.stat_preview1_path(4, 0, "in-other")).unwrap();
    assert_eq!(target_stat.data_access_timestamp.unwrap().nanoseconds, 333);
    assert_eq!(
        target_stat.data_modification_timestamp.unwrap().nanoseconds,
        444
    );
    let (_, link_stat) = block_on(store.stat_preview1_path(4, 0, "link")).unwrap();
    assert_eq!(link_stat.data_access_timestamp.unwrap().nanoseconds, 111);
    assert_eq!(
        link_stat.data_modification_timestamp.unwrap().nanoseconds,
        222
    );
}
