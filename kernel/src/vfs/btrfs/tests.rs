extern crate std;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use std::io::{Read, Seek, SeekFrom};

use ferrosys::btrfs::{FormatOptions, SubvolumeRequest, format_to};
use ferrosys::{Metadata, Timestamp, TreeBuilder};
use futures_lite::future::block_on;
use helios_hal::fs::{
    BlockSerial, DeviceId, DirCookie, FileSystem, FsError, FsPath, NodeKind, OpenFlags,
    PreparedWrite, WritePosition, WriteProgress, write_with,
};

use super::BtrfsFs;
use crate::io::{MemoryDisk, cache_over};
use crate::vfs::{
    AttachedStorage, BOOT_DEVICE, Follow, MountSource, MountTable, Namespace, Storage,
};
use crate::{
    BootFs, EmbeddedBootDirectory, EmbeddedBootFs, ProcessAuthority, UnsupportedHostFileSystem,
    request_mount,
};

#[derive(Clone, Copy)]
struct MemoryStorage;

impl Storage for MemoryStorage {
    type HostShare = UnsupportedHostFileSystem;
    type Disk = MemoryDisk;
}

fn options(time: Timestamp) -> FormatOptions {
    FormatOptions::new([0x51; 16], time)
        .subvolume(SubvolumeRequest::new(b"/@home".to_vec(), [0x52; 16]))
}

fn formatted_image(tree: TreeBuilder, options: FormatOptions) -> crate::BlockCache<MemoryDisk> {
    formatted_cache(tree, options, true)
}

fn formatted_writable_image(
    tree: TreeBuilder,
    options: FormatOptions,
) -> crate::BlockCache<MemoryDisk> {
    formatted_cache(tree, options, false)
}

fn formatted_cache(
    tree: TreeBuilder,
    options: FormatOptions,
    read_only: bool,
) -> crate::BlockCache<MemoryDisk> {
    // ferrosys' default geometry requires a volume above 109 MiB.
    let size = 128 << 20;
    let mut image = tempfile::tempfile().expect("image file");
    image.set_len(size).expect("image length");
    format_to(&mut image, tree, size, options).expect("formats btrfs");
    image.seek(SeekFrom::Start(0)).expect("rewinds");
    let mut bytes = Vec::new();
    image.read_to_end(&mut bytes).expect("reads image");
    let disk = if read_only {
        MemoryDisk::holding("btrfs-test", &bytes, false)
    } else {
        MemoryDisk::holding_writable("btrfs-test", &bytes)
    };
    drop(bytes);
    cache_over(&disk, 256, 1)
}

fn path(value: &str) -> FsPath<'_> {
    FsPath::new(value).expect("normalized path")
}

#[test]
fn mounted_image_preserves_subvolume_identity_links_and_directory_cookies() {
    let time = Timestamp::from_secs(1_700_000_000);
    let file = Metadata::new(0o644, time);
    let dir = Metadata::new(0o755, time);
    let tree = TreeBuilder::new()
        .root(dir)
        .file("/hello", b"hello btrfs\n", file)
        .hardlink("/hard", "/hello", file)
        .symlink("/link", "hello", Metadata::new(0o777, time))
        .directory("/@home", dir)
        .file("/@home/notes", b"subvolume\n", file);
    let cache = formatted_image(tree, options(time));
    let mut next_device = 100;
    let fs = block_on(BtrfsFs::mount(cache.disk(0), || {
        next_device += 1;
        DeviceId::new(next_device)
    }))
    .expect("mounts");

    let root = block_on(fs.stat(path(""))).expect("root");
    let home = block_on(fs.stat(path("@home"))).expect("subvolume");
    assert_eq!(root.id.inode, home.id.inode);
    assert_ne!(root.id.device, home.id.device);
    let hello = block_on(fs.stat(path("hello"))).expect("file");
    assert_eq!(
        hello.id,
        block_on(fs.stat(path("hard"))).expect("hardlink").id
    );
    assert_eq!(
        block_on(fs.stat(path("link"))).expect("link").kind,
        NodeKind::Symlink
    );
    assert_eq!(
        block_on(fs.read_link(path("link"))).expect("target"),
        "hello"
    );
    assert_eq!(
        block_on(fs.read_at(path("hello"), 6, 99)).expect("read"),
        &b"btrfs\n"[..]
    );
    assert_eq!(
        block_on(fs.read_at(path("@home/notes"), 0, 99)).expect("subvolume file"),
        &b"subvolume\n"[..]
    );
    assert!(
        block_on(fs.read_at(path("hello"), u64::MAX, 99))
            .expect("past EOF")
            .is_empty()
    );
    assert_eq!(
        block_on(fs.read_at(path("link"), 0, 1)),
        Err(FsError::Invalid)
    );
    assert_eq!(
        block_on(fs.open(path("hello"), OpenFlags::TRUNCATE, 0)),
        Err(FsError::ReadOnly)
    );
    assert_eq!(
        block_on(fs.open(path("absent"), OpenFlags::CREATE, 0)),
        Err(FsError::ReadOnly)
    );

    let mut names = BTreeSet::new();
    let mut cookie = DirCookie::new(0);
    loop {
        let entries = block_on(fs.read_dir(path(""), cookie, 1)).expect("directory page");
        let Some(entry) = entries.first() else {
            break;
        };
        assert!(entry.next.raw() > cookie.raw());
        assert!(names.insert(entry.name.clone()));
        cookie = entry.next;
    }
    assert_eq!(
        names.into_iter().collect::<Vec<_>>(),
        ["@home", "hard", "hello", "link"]
    );
    const BOOT: EmbeddedBootFs = EmbeddedBootFs::new(&[EmbeddedBootDirectory::new("mnt", 0)], &[]);
    let namespace =
        Namespace::<MemoryStorage>::new(MountTable::new(BootFs::new(BOOT, BOOT_DEVICE), 1));
    block_on(request_mount(
        &ProcessAuthority::root(),
        &namespace,
        AttachedStorage {
            host_share: None,
            disks: Some(cache),
        },
        MountSource::Btrfs {
            serial: BlockSerial::new(b"btrfs-test").unwrap(),
        },
        "/mnt",
        true,
        crate::vfs::BtrfsWriteOptions {
            entropy: crate::test_support::test_root_entropy(),
            concurrency: core::num::NonZeroUsize::new(1).unwrap(),
        },
    ))
    .expect("mount request");
    let resolved = namespace.resolve("/mnt/hello").expect("mounted file");
    assert_eq!(resolved.mount_point(), "/mnt");
    assert_eq!(resolved.writable().map(drop), Err(FsError::ReadOnly));
    assert_eq!(
        block_on(resolved.fs().read_at(resolved.path(), 0, 99)).expect("read through mount"),
        &b"hello btrfs\n"[..]
    );
    let followed = block_on(namespace.resolve_following("/mnt/link", Follow::Within("/mnt")))
        .expect("follows the mounted symlink");
    assert_eq!(followed.absolute(), "/mnt/hello");
    assert_eq!(
        block_on(followed.fs().read_at(followed.path(), 0, 99)).expect("read through symlink"),
        &b"hello btrfs\n"[..]
    );
}

/// The guest smoke's sequence through a writable namespace mount and the
/// WASI link path a preview1 program reaches.
#[test]
fn a_writable_mount_links_a_file_created_through_the_namespace() {
    use crate::wasmtime_adapter::wasi::{
        FsDescriptor, FsNodeKind, bindings::filesystem::types as fs_types, link_at,
    };

    let time = Timestamp::from_secs(1_700_000_000);
    let tree = TreeBuilder::new().root(Metadata::new(0o755, time));
    let cache = formatted_writable_image(tree, FormatOptions::new([0x61; 16], time));
    const BOOT: EmbeddedBootFs = EmbeddedBootFs::new(&[EmbeddedBootDirectory::new("mnt", 0)], &[]);
    let namespace =
        Namespace::<MemoryStorage>::new(MountTable::new(BootFs::new(BOOT, BOOT_DEVICE), 1));
    let service = block_on(request_mount(
        &ProcessAuthority::root(),
        &namespace,
        AttachedStorage {
            host_share: None,
            disks: Some(cache),
        },
        MountSource::Btrfs {
            serial: BlockSerial::new(b"btrfs-test").unwrap(),
        },
        "/mnt",
        false,
        crate::vfs::BtrfsWriteOptions {
            entropy: crate::test_support::test_root_entropy(),
            concurrency: core::num::NonZeroUsize::new(1).unwrap(),
        },
    ))
    .expect("mount request")
    .expect("a writable btrfs mount returns its service");
    let client = async {
        let resolved = namespace.resolve("/mnt/written").unwrap();
        resolved
            .writable()
            .unwrap()
            .create_directory(resolved.path(), 1_000_000_000)
            .await
            .expect("mkdir");
        let resolved = namespace.resolve("/mnt/written/original").unwrap();
        let fs = resolved.writable().unwrap();
        fs.open(
            resolved.path(),
            OpenFlags::CREATE | OpenFlags::TRUNCATE,
            1_000_000_001,
        )
        .await
        .expect("create");
        write_with(
            fs,
            resolved.path(),
            WritePosition::At(0),
            4096,
            1_000_000_002,
            |_, bytes| bytes.fill(0x50),
        )
        .await
        .expect("write");
        fs.sync(resolved.path()).await.expect("fsync");
        let root = FsDescriptor {
            path: alloc::string::String::from("/"),
            kind: FsNodeKind::Directory,
            flags: fs_types::DescriptorFlags::READ
                | fs_types::DescriptorFlags::WRITE
                | fs_types::DescriptorFlags::MUTATE_DIRECTORY,
            identity: None,
            mount: None,
        };
        let proof = root
            .grant()
            .unwrap()
            .alias_into(root.grant().unwrap())
            .unwrap();
        link_at(
            &namespace,
            proof,
            "mnt/written/original",
            "mnt/written/hard",
            1_000_000_003,
        )
        .await
        .expect("link through the WASI path");
        assert_eq!(
            namespace
                .resolve("/mnt/written/hard")
                .unwrap()
                .fs()
                .stat(path("written/hard"))
                .await
                .unwrap()
                .link_count,
            2
        );
    };
    let service = service.run();
    futures::pin_mut!(client, service);
    match block_on(futures::future::select(client, service)) {
        futures::future::Either::Left(((), _)) => {}
        futures::future::Either::Right(_) => panic!("the write service stopped first"),
    }
}

#[test]
fn writable_service_publishes_namespace_and_survives_remount() {
    let time = Timestamp::from_secs(1_700_000_000);
    let tree = TreeBuilder::new().root(Metadata::new(0o755, time)).file(
        "/file",
        b"durable contents",
        Metadata::new(0o644, time),
    );
    let cache = formatted_writable_image(tree, FormatOptions::new([0x61; 16], time));
    block_on(async {
        let (fs, service) = BtrfsFs::mount_writable(
            cache.disk(0),
            || DeviceId::new(100),
            crate::test_support::test_root_entropy(),
            core::num::NonZeroUsize::new(2).unwrap(),
        )
        .await
        .expect("writable mount");
        assert!(matches!(
            BtrfsFs::mount(cache.disk(0), || DeviceId::new(102)).await,
            Err(super::BtrfsMountError::Busy)
        ));
        assert!(matches!(
            BtrfsFs::mount_writable(
                cache.disk(0),
                || DeviceId::new(103),
                crate::test_support::test_root_entropy(),
                core::num::NonZeroUsize::new(1).unwrap()
            )
            .await,
            Err(super::BtrfsMountError::Busy)
        ));
        let client = async move {
            fs.open(
                path("created"),
                OpenFlags::CREATE | OpenFlags::EXCLUSIVE,
                1_000_000_000,
            )
            .await
            .expect("create file");
            assert_eq!(
                fs.open(
                    path("created"),
                    OpenFlags::CREATE | OpenFlags::EXCLUSIVE,
                    1_000_000_000
                )
                .await,
                Err(FsError::Exists)
            );
            let payload = alloc::vec![0x53; 19_000];
            let start = write_with(
                &fs,
                path("created"),
                WritePosition::At(0),
                payload.len(),
                1_000_000_001,
                |offset, bytes| bytes.copy_from_slice(&payload[offset..offset + bytes.len()]),
            )
            .await
            .expect("multiple rounds");
            assert_eq!(start, 0);
            assert_eq!(
                fs.read_at(path("created"), 0, payload.len()).await.unwrap(),
                payload.as_slice()
            );
            let staged = fs
                .prepare_write(path("created"), WritePosition::End, 5, 1_000_000_002)
                .await
                .expect("stage without mutation");
            drop(staged);
            assert_eq!(
                fs.stat(path("created")).await.unwrap().size,
                payload.len() as u64
            );
            let first = fs
                .prepare_write(path("created"), WritePosition::End, 3, 1_000_000_003)
                .await
                .unwrap();
            let second = fs
                .prepare_write(path("created"), WritePosition::End, 2, 1_000_000_004)
                .await
                .unwrap();
            fs.rename(path("created"), path("renamed"), 1_000_000_005)
                .await
                .expect("rename prepared inode");
            let (first, second) = futures::future::join(
                first.submit(|_, bytes| bytes.fill(0x41)),
                second.submit(|_, bytes| bytes.fill(0x42)),
            )
            .await;
            assert!(matches!(first, Ok(WriteProgress::Done(19_000))));
            assert!(matches!(second, Ok(WriteProgress::Done(19_003))));
            assert_eq!(
                fs.read_at(path("renamed"), 19_000, 5).await.unwrap(),
                &b"AAABB"[..]
            );
            fs.create_directory(path("dir"), 2_000_000_000)
                .await
                .expect("mkdir");
            fs.link(path("file"), path("dir/link"), 3_000_000_000)
                .await
                .expect("link");
            fs.rename(path("dir/link"), path("dir/moved"), 4_000_000_000)
                .await
                .expect("rename");
            fs.set_size(path("dir/moved"), 7, 5_000_000_000)
                .await
                .expect("truncate");
            fs.symlink("moved", path("dir/symlink"), 6_000_000_000)
                .await
                .expect("symlink");
            assert_eq!(
                fs.remove_directory(path("dir"), 7_000_000_000).await,
                Err(FsError::NotEmpty)
            );
            assert_eq!(
                fs.unlink(path("dir"), 7_000_000_000).await,
                Err(FsError::IsDirectory)
            );
            fs.open(path("dir/deleted"), OpenFlags::CREATE, 7_000_000_000)
                .await
                .unwrap();
            fs.unlink(path("dir/deleted"), 8_000_000_000).await.unwrap();
            let parent = fs.stat(path("dir")).await.unwrap();
            assert_eq!(parent.modified_nanos, 8_000_000_000);
            assert_eq!(parent.status_nanos, 8_000_000_000);
            fs.open(
                path("dir/fresh"),
                OpenFlags::CREATE | OpenFlags::EXCLUSIVE,
                9_000_000_000,
            )
            .await
            .expect("create in a created directory");
            write_with(
                &fs,
                path("dir/fresh"),
                WritePosition::At(0),
                4096,
                9_000_000_001,
                |_, bytes| bytes.fill(0x46),
            )
            .await
            .expect("write the fresh file");
            fs.sync(path("dir/fresh")).await.expect("fsync");
            fs.link(path("dir/fresh"), path("dir/fresh-link"), 9_000_000_002)
                .await
                .expect("link a file created and synced in this mount");
            fs.sync(path("file")).await.expect("sync commit");
            assert_eq!(
                fs.read_at(path("file"), 0, 99).await.unwrap(),
                &b"durable"[..]
            );
            drop(fs);
        };
        futures::future::join(client, service.run()).await;
        let reopened = BtrfsFs::mount(cache.disk(0), || DeviceId::new(101))
            .await
            .expect("reopen");
        assert_eq!(
            reopened.read_at(path("dir/moved"), 0, 99).await.unwrap(),
            &b"durable"[..]
        );
        assert_eq!(
            reopened.read_at(path("renamed"), 19_000, 5).await.unwrap(),
            &b"AAABB"[..]
        );
        assert_eq!(
            reopened.read_link(path("dir/symlink")).await.unwrap(),
            "moved"
        );
    });
}
