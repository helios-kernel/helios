extern crate std;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use std::io::{Read, Seek, SeekFrom};

use ferrosys::btrfs::{FormatOptions, SubvolumeRequest, format_to};
use ferrosys::{Metadata, Timestamp, TreeBuilder};
use futures_lite::future::block_on;
use helios_hal::fs::{
    BlockSerial, DeviceId, DirCookie, DirStream, FileSystem, FilledWrite, FsError, FsPath, Landed,
    NodeKind, OpenFlags, PreparedWrite, RenameMode, WritePosition, WriteProgress, write_with,
};

use super::BtrfsFs;
use crate::io::{MemoryDisk, cache_over};
use crate::test_support::UnsupportedHostFileSystem;
use crate::vfs::{
    AttachedStorage, BOOT_DEVICE, Follow, MountRequest, MountSource, MountTable, Namespace, Storage,
};
use crate::{BootFs, EmbeddedBootDirectory, EmbeddedBootFs, ProcessAuthority, request_mount};

#[derive(Clone, Copy)]
struct MemoryStorage;

impl Storage for MemoryStorage {
    type HostShare = UnsupportedHostFileSystem;
    type Disk = MemoryDisk;
}

/// A shared mount of `source` at `/mnt` with `write`.
fn mount_request(
    source: MountSource,
    read_only: bool,
    write: crate::vfs::BtrfsWriteOptions,
) -> MountRequest<'static> {
    MountRequest {
        source,
        point: "/mnt",
        read_only,
        sharing: crate::MountSharing::Shared,
        write,
    }
}

/// The btrfs image on the test disk.
fn btrfs_source() -> MountSource {
    MountSource::Btrfs {
        serial: BlockSerial::new(b"btrfs-test").unwrap(),
    }
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
    cache_over(&formatted_disk(tree, options, read_only), 256, 1)
}

/// The bytes of a formatted volume: ferrosys' default geometry requires a
/// volume above 109 MiB.
const FORMATTED_BYTES: usize = 128 << 20;

fn formatted_disk(tree: TreeBuilder, options: FormatOptions, read_only: bool) -> MemoryDisk {
    let size = FORMATTED_BYTES as u64;
    let mut image = tempfile::tempfile().expect("image file");
    image.set_len(size).expect("image length");
    format_to(&mut image, tree, size, options).expect("formats btrfs");
    image.seek(SeekFrom::Start(0)).expect("rewinds");
    let mut bytes = Vec::new();
    image.read_to_end(&mut bytes).expect("reads image");
    if read_only {
        MemoryDisk::holding("btrfs-test", &bytes, false)
    } else {
        MemoryDisk::holding_writable("btrfs-test", &bytes)
    }
}

fn path(value: &str) -> FsPath<'_> {
    FsPath::new(value).expect("normalized path")
}

/// A timer nothing fires: the commit interval never expires, so a test sees
/// only the commits a sync, the dirty bound or the unmount makes.
fn idle_timer() -> crate::Timer<crate::test_support::TestCpu> {
    crate::test_support::test_timer(crate::test_support::TestCpu::without_entropy())
}

fn write_options(
    concurrency: usize,
    compress: Option<helios_btrfs::write::CompressionPolicy>,
) -> crate::vfs::BtrfsWriteOptions {
    crate::vfs::BtrfsWriteOptions {
        entropy: crate::test_support::test_root_entropy(),
        concurrency: core::num::NonZeroUsize::new(concurrency).unwrap(),
        compress,
        commit: None,
        max_inline: None,
        now: 1_700_000_000_000_000_000,
    }
}

/// A writable mount with a compression policy stores compressible data in
/// compressed extents: the reader returns the same bytes, every regular
/// extent item names the policy's algorithm (a plain mount's name none), and the superblock
/// records the algorithm's incompat bit.
#[test]
fn a_compressing_mount_writes_extents_the_reader_reads_back() {
    use helios_btrfs::write::CompressionPolicy;
    use helios_btrfs::{Compression, ExtentKind};

    // Text with CJK, repeated past one 128 KiB extent so several extents form.
    let payload: Vec<u8> = "压缩 圧縮 압축 compressible line\n"
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(300_000)
        .collect();
    // The incompat bits of btrfs_tree.h: COMPRESS_LZO and COMPRESS_ZSTD.
    for (algorithm, level, bit) in [
        (None, 0, 0),
        (Some(Compression::Zlib), 0, 0),
        (Some(Compression::Zlib), 9, 0),
        (Some(Compression::Lzo), 0, 1 << 3),
        (Some(Compression::Zstd), 0, 1 << 4),
        (Some(Compression::Zstd), -5, 1 << 4),
    ] {
        let policy = algorithm.map(|algorithm| CompressionPolicy::new(algorithm, level));
        let time = Timestamp::from_secs(1_700_000_000);
        let tree = TreeBuilder::new().root(Metadata::new(0o755, time));
        let cache = formatted_writable_image(tree, FormatOptions::new([0x61; 16], time));
        block_on(async {
            // Linux's bounds on a 1 GiB machine: the 8 KiB write rounds stay
            // dirty until the sync writes them back as one run.
            let (fs, service) = BtrfsFs::mount_writable(
                cache.disk(0),
                || DeviceId::new(100),
                crate::vfs::BtrfsWriteOptions {
                    commit: Some(crate::vfs::CommitPolicy::for_machine(1 << 30)),
                    ..write_options(2, policy)
                },
            )
            .await
            .expect("writable mount");
            let payload = &payload;
            let client = async move {
                let payer = crate::StoragePayer::for_test();
                fs.open(
                    path("text"),
                    OpenFlags::CREATE | OpenFlags::EXCLUSIVE,
                    1_000_000_000,
                    &payer,
                )
                .await
                .expect("create");
                write_with(
                    &fs,
                    path("text"),
                    WritePosition::At(0),
                    payload.len(),
                    1_000_000_001,
                    &payer,
                    |offset, bytes| bytes.copy_from_slice(&payload[offset..offset + bytes.len()]),
                )
                .await
                .expect("write");
                fs.sync(path("text")).await.expect("sync");
                assert_eq!(
                    fs.read_at(path("text"), 0, payload.len()).await.unwrap(),
                    payload.as_slice()
                );
                drop(fs);
            };
            futures::future::join(
                alloc::boxed::Box::pin(client),
                alloc::boxed::Box::pin(service.run(idle_timer())),
            )
            .await;
            let reopened = BtrfsFs::mount(cache.disk(0), || DeviceId::new(101))
                .await
                .expect("reopen");
            assert_eq!(
                reopened
                    .read_at(path("text"), 0, payload.len())
                    .await
                    .unwrap(),
                payload.as_slice(),
                "{policy:?}"
            );
            let snapshot = reopened.inner.reader.lock().clone();
            let inode = snapshot.resolve(b"/text").await.unwrap();
            assert_eq!(inode.metadata().size, payload.len() as u64);
            // Read the stored form off the extent items: this payload
            // shrinks in every extent under every algorithm, so each regular
            // extent carries the policy's algorithm and a plain mount's
            // carry none.
            let extents = snapshot.file_extents(&inode).await.unwrap();
            assert!(!extents.is_empty(), "{policy:?} wrote no extents");
            assert_eq!(
                extents.iter().map(|extent| extent.len).sum::<u64>(),
                payload.len().next_multiple_of(4096) as u64,
                "{policy:?} extents cover the file"
            );
            for extent in &extents {
                assert_eq!(extent.kind, ExtentKind::Regular, "{policy:?} {extent:?}");
                assert_eq!(extent.compression, algorithm, "{policy:?} {extent:?}");
            }
            // Extents form at writeback, whatever the rounds: windows of
            // BTRFS_MAX_UNCOMPRESSED when compressed, one extent otherwise.
            let window = 128 << 10;
            let lengths: Vec<u64> = extents.iter().map(|extent| extent.len).collect();
            if algorithm.is_some() {
                assert!(
                    lengths.iter().rev().skip(1).all(|&len| len == window)
                        && lengths.last().is_some_and(|&len| len <= window),
                    "{policy:?} {lengths:?}"
                );
            } else {
                assert_eq!(
                    lengths,
                    [payload.len().next_multiple_of(4096) as u64],
                    "{policy:?}"
                );
            }
            assert_eq!(
                snapshot.superblock().incompat_flags() & (1 << 3 | 1 << 4),
                bit
            );
        });
    }
}

/// Streamed guest writes that arrive in 4096-byte chunks coalesce in delayed
/// allocation under `compress=zstd:3` and become 128 KiB zstd extents at
/// writeback (#1052, #1060).
#[test]
fn chunked_stream_writes_coalesce_into_zstd_extents() {
    use helios_btrfs::write::CompressionPolicy;
    use helios_btrfs::{Compression, ExtentKind};

    const ADAPTER_CHUNK: usize = 4096;
    const WINDOW: u64 = 128 << 10;
    let payload: Vec<u8> = "compressible line of text, 中文 日本語 한국어\n"
        .repeat(8000)
        .into_bytes();
    let policy = Some(CompressionPolicy::new(Compression::Zstd, 3));
    let time = Timestamp::from_secs(1_700_000_000);
    let tree = TreeBuilder::new().root(Metadata::new(0o755, time));
    let cache = formatted_writable_image(tree, FormatOptions::new([0x63; 16], time));
    block_on(async {
        let (fs, service) = BtrfsFs::mount_writable(
            cache.disk(0),
            || DeviceId::new(100),
            crate::vfs::BtrfsWriteOptions {
                commit: Some(crate::vfs::CommitPolicy::for_machine(2 << 30)),
                ..write_options(2, policy)
            },
        )
        .await
        .expect("writable mount");
        let payload = &payload;
        let client = async move {
            let payer = crate::StoragePayer::for_test();
            fs.open(
                path("compressible"),
                OpenFlags::CREATE | OpenFlags::EXCLUSIVE,
                1_000_000_000,
                &payer,
            )
            .await
            .expect("create");
            for (index, chunk) in payload.chunks(ADAPTER_CHUNK).enumerate() {
                let landed = write_with(
                    &fs,
                    path("compressible"),
                    WritePosition::End,
                    chunk.len(),
                    1_000_000_001 + index as u64,
                    &payer,
                    |_, bytes| bytes.copy_from_slice(chunk),
                )
                .await
                .expect("4 KiB chunk write");
                assert_eq!(landed.offset, (index * ADAPTER_CHUNK) as u64);
                assert_eq!(landed.len, chunk.len());
            }
            // Before sync, reads return all written bytes from dirty pages,
            // and only the initial 4 KiB promotion left no regular extents.
            assert_eq!(
                fs.read_at(path("compressible"), 0, payload.len())
                    .await
                    .unwrap(),
                payload.as_slice()
            );
            {
                let snapshot = fs.inner.reader.lock().clone();
                let inode = snapshot.resolve(b"/compressible").await.unwrap();
                assert!(snapshot.file_extents(&inode).await.unwrap().is_empty());
            }
            fs.sync(path("compressible")).await.expect("fsync");
            drop(fs);
        };
        futures::future::join(
            alloc::boxed::Box::pin(client),
            alloc::boxed::Box::pin(service.run(idle_timer())),
        )
        .await;

        let reopened = BtrfsFs::mount(cache.disk(0), || DeviceId::new(101))
            .await
            .expect("reopen");
        assert_eq!(
            reopened
                .read_at(path("compressible"), 0, payload.len())
                .await
                .unwrap(),
            payload.as_slice()
        );
        let snapshot = reopened.inner.reader.lock().clone();
        let inode = snapshot.resolve(b"/compressible").await.unwrap();
        let extents = snapshot.file_extents(&inode).await.unwrap();
        let aligned = payload.len().next_multiple_of(4096) as u64;
        assert_eq!(extents.len() as u64, aligned.div_ceil(WINDOW));
        for (index, extent) in extents.iter().enumerate() {
            assert_eq!(extent.kind, ExtentKind::Regular);
            assert_eq!(extent.compression, Some(Compression::Zstd));
            if index + 1 < extents.len() {
                assert_eq!(extent.len, WINDOW);
            } else {
                assert_eq!(extent.len, aligned - WINDOW * index as u64);
            }
        }
    });
}

/// Multi-round prepared writes fill each round synchronously at its cumulative
/// offset, preserve their initial `Landed::offset` across rounds under
/// concurrent append contention, and coalesce into one extent at writeback.
#[test]
fn prepared_writes_fill_rounds_synchronously_keep_start_offset_and_coalesce() {
    use helios_btrfs::ExtentKind;

    const ROUND: usize = crate::CACHE_BLOCK_BYTES * 2;
    const FIRST_LEN: usize = ROUND * 3 + 1234;
    const SECOND_LEN: usize = ROUND * 2 + 567;
    let first_bytes: Vec<u8> = (0..FIRST_LEN).map(|i| (i % 251) as u8).collect();
    let second_bytes: Vec<u8> = (0..SECOND_LEN).map(|i| ((i + 97) % 251) as u8).collect();

    let time = Timestamp::from_secs(1_700_000_000);
    let tree = TreeBuilder::new().root(Metadata::new(0o755, time));
    let cache = formatted_writable_image(tree, FormatOptions::new([0x64; 16], time));
    block_on(async {
        let (fs, service) = BtrfsFs::mount_writable(
            cache.disk(0),
            || DeviceId::new(100),
            crate::vfs::BtrfsWriteOptions {
                commit: Some(crate::vfs::CommitPolicy::for_machine(1 << 30)),
                ..write_options(2, None)
            },
        )
        .await
        .expect("writable mount");
        let (first_bytes, second_bytes) = (&first_bytes, &second_bytes);
        let client = async move {
            let payer = crate::StoragePayer::for_test();
            fs.open(
                path("rounds"),
                OpenFlags::CREATE | OpenFlags::EXCLUSIVE,
                1_000_000_000,
                &payer,
            )
            .await
            .expect("create");
            let drive = async |fs: &BtrfsFs<MemoryDisk>, data: &[u8], stamp: u64| {
                let mut current = fs
                    .prepare_write(
                        path("rounds"),
                        WritePosition::End,
                        data.len(),
                        stamp,
                        &crate::StoragePayer::for_test(),
                    )
                    .await
                    .expect("prepare");
                let mut seen_offsets = Vec::new();
                loop {
                    let expected_staged = (data.len()
                        - seen_offsets.iter().map(|&(_, len)| len).sum::<usize>())
                    .min(ROUND);
                    assert_eq!(current.staged_len(), expected_staged);
                    let filled = current.fill(|offset, buf| {
                        seen_offsets.push((offset, buf.len()));
                        buf.copy_from_slice(&data[offset..offset + buf.len()]);
                    });
                    match filled.submit().await.expect("round submit") {
                        WriteProgress::More(next) => current = next,
                        WriteProgress::Done(landed) => return (landed, seen_offsets),
                    }
                }
            };
            let ((first_landed, first_rounds), (second_landed, second_rounds)) =
                futures::future::join(
                    drive(&fs, first_bytes, 1_000_000_001),
                    drive(&fs, second_bytes, 1_000_000_002),
                )
                .await;
            assert_eq!(
                first_rounds,
                [
                    (0, ROUND),
                    (ROUND, ROUND),
                    (ROUND * 2, ROUND),
                    (ROUND * 3, 1234)
                ]
            );
            assert_eq!(
                second_rounds,
                [(0, ROUND), (ROUND, ROUND), (ROUND * 2, 567)]
            );
            assert_eq!(first_landed.len, FIRST_LEN);
            assert_eq!(second_landed.len, SECOND_LEN);
            let mut expected = Vec::with_capacity(FIRST_LEN + SECOND_LEN);
            if first_landed.offset == 0 {
                assert_eq!(second_landed.offset, FIRST_LEN as u64);
                expected.extend_from_slice(first_bytes);
                expected.extend_from_slice(second_bytes);
            } else {
                assert_eq!(second_landed.offset, 0);
                assert_eq!(first_landed.offset, SECOND_LEN as u64);
                expected.extend_from_slice(second_bytes);
                expected.extend_from_slice(first_bytes);
            }
            assert_eq!(
                fs.read_at(path("rounds"), 0, expected.len()).await.unwrap(),
                expected.as_slice()
            );
            fs.sync(path("rounds")).await.expect("sync");
            let snapshot = fs.inner.reader.lock().clone();
            let inode = snapshot.resolve(b"/rounds").await.unwrap();
            let extents = snapshot.file_extents(&inode).await.unwrap();
            assert_eq!(extents.len(), 1, "all rounds coalesce into one extent");
            assert_eq!(extents[0].kind, ExtentKind::Regular);
            assert_eq!(extents[0].len, expected.len().next_multiple_of(4096) as u64);
            drop(fs);
        };
        futures::future::join(
            alloc::boxed::Box::pin(client),
            alloc::boxed::Box::pin(service.run(idle_timer())),
        )
        .await;
    });
}

/// The bytes of a btrfs volume holding `tree`.
fn format_image(tree: TreeBuilder, options: FormatOptions) -> Vec<u8> {
    // ferrosys' default geometry requires a volume above 109 MiB.
    let size = 128 << 20;
    let mut image = tempfile::tempfile().expect("image file");
    image.set_len(size).expect("image length");
    format_to(&mut image, tree, size, options).expect("formats btrfs");
    image.seek(SeekFrom::Start(0)).expect("rewinds");
    let mut bytes = Vec::new();
    image.read_to_end(&mut bytes).expect("reads image");
    bytes
}

fn mount(cache: &crate::io::BlockCache<MemoryDisk>) -> BtrfsFs<MemoryDisk> {
    let mut next_device = 100;
    block_on(BtrfsFs::mount(cache.disk(0), || {
        next_device += 1;
        DeviceId::new(next_device)
    }))
    .expect("mounts")
}

/// A directory holding a device node of each kind, a FIFO and a socket
/// lists and stats them as what they are, and opening or reading one is
/// refused; the Chinese, Japanese and Korean files beside them read.
#[test]
fn special_nodes_are_listed_and_statted_and_never_opened() {
    let time = Timestamp::from_secs(1_700_000_000);
    let file = Metadata::new(0o644, time);
    let special = Metadata::new(0o600, time);
    let cjk = [
        ("中文.txt", "你好，世界\n"),
        ("日本語.txt", "こんにちは世界\n"),
        ("한국어.txt", "안녕하세요 세계\n"),
    ];
    let mut tree = TreeBuilder::new().root(Metadata::new(0o755, time));
    for (name, content) in cjk {
        tree = tree.file(alloc::format!("/{name}"), content.as_bytes(), file);
    }
    let tree = tree
        .char_device("/tty0", 4, 0, special)
        .block_device("/sda", 8, 0, special)
        .fifo("/fifo", special)
        .socket("/socket", special);
    let options = FormatOptions::new([0x51; 16], time);
    let disk = MemoryDisk::holding("btrfs-special", &format_image(tree, options), false);
    let cache = cache_over(&disk, 256, 1);
    let fs = mount(&cache);
    let nodes = [
        ("tty0", NodeKind::CharacterDevice, FsError::NotPermitted),
        ("sda", NodeKind::BlockDevice, FsError::NotPermitted),
        ("fifo", NodeKind::Fifo, FsError::Unsupported),
        ("socket", NodeKind::Socket, FsError::Unsupported),
    ];

    let mut listed = Vec::new();
    let dir = block_on(fs.open_dir(path(""))).expect("opens root");
    let mut cookie = DirCookie::new(0);
    loop {
        let entries = block_on(dir.read(cookie, 2)).expect("directory page");
        let Some(last) = entries.last() else {
            break;
        };
        cookie = last.next;
        listed.extend(entries.into_iter().map(|entry| (entry.name, entry.kind)));
    }
    listed.sort_by(|a, b| a.0.cmp(&b.0));
    let mut expected: Vec<(alloc::string::String, NodeKind)> = cjk
        .iter()
        .map(|(name, _)| ((*name).into(), NodeKind::File))
        .chain(nodes.iter().map(|(name, kind, _)| ((*name).into(), *kind)))
        .collect();
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(listed, expected);

    for (name, kind, refusal) in nodes {
        assert_eq!(
            block_on(fs.stat(path(name)))
                .expect("stat reports the node")
                .kind,
            kind,
            "{name}"
        );
        assert_eq!(
            block_on(fs.open(
                path(name),
                OpenFlags::empty(),
                0,
                &crate::StoragePayer::for_test(),
            ))
            .map(|_| ()),
            Err(refusal),
            "open {name}"
        );
        assert_eq!(
            block_on(fs.read_at(path(name), 0, 16)).map(|_| ()),
            Err(refusal),
            "read {name}"
        );
    }
    for (name, content) in cjk {
        assert_eq!(
            block_on(fs.read_at(path(name), 0, 99)).expect("a regular file reads"),
            content.as_bytes()
        );
    }
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
    let fs = mount(&cache);

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
    let payer = crate::StoragePayer::for_test();
    assert_eq!(
        block_on(fs.open(path("hello"), OpenFlags::TRUNCATE, 0, &payer)).map(drop),
        Err(FsError::ReadOnly)
    );
    assert_eq!(
        block_on(fs.open(path("absent"), OpenFlags::CREATE, 0, &payer)).map(drop),
        Err(FsError::ReadOnly)
    );

    let mut names = BTreeSet::new();
    let dir = block_on(fs.open_dir(path(""))).expect("opens root");
    let mut cookie = DirCookie::new(0);
    loop {
        let entries = block_on(dir.read(cookie, 1)).expect("directory page");
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
        mount_request(btrfs_source(), true, write_options(1, None)),
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

/// The guest smoke's sequence through a writable namespace mount, ending in
/// the namespace link every guest ABI's link call reaches.
#[test]
fn a_writable_mount_links_a_file_created_through_the_namespace() {
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
        mount_request(btrfs_source(), false, write_options(1, None)),
    ))
    .expect("mount request")
    .expect("a writable btrfs mount returns its service");
    let client = async {
        let payer = crate::StoragePayer::for_test();
        let resolved = namespace.resolve("/mnt/written").unwrap();
        resolved
            .writable()
            .unwrap()
            .create_directory(resolved.path(), 1_000_000_000, &payer)
            .await
            .expect("mkdir");
        let resolved = namespace.resolve("/mnt/written/original").unwrap();
        let fs = resolved.writable().unwrap();
        fs.open(
            resolved.path(),
            OpenFlags::CREATE | OpenFlags::TRUNCATE,
            1_000_000_001,
            &payer,
        )
        .await
        .expect("create");
        write_with(
            fs,
            resolved.path(),
            WritePosition::At(0),
            4096,
            1_000_000_002,
            &payer,
            |_, bytes| bytes.fill(0x50),
        )
        .await
        .expect("write");
        fs.sync(resolved.path()).await.expect("fsync");
        namespace
            .link(
                "/mnt/written/original",
                "/mnt/written/hard",
                1_000_000_003,
                &payer,
            )
            .await
            .expect("link through the namespace");
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
    let service = service.run(idle_timer());
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
        let (fs, service) =
            BtrfsFs::mount_writable(cache.disk(0), || DeviceId::new(100), write_options(2, None))
                .await
                .expect("writable mount");
        assert!(matches!(
            BtrfsFs::mount(cache.disk(0), || DeviceId::new(102)).await,
            Err(super::BtrfsMountError::Busy)
        ));
        assert!(matches!(
            BtrfsFs::mount_writable(cache.disk(0), || DeviceId::new(103), write_options(1, None))
                .await,
            Err(super::BtrfsMountError::Busy)
        ));
        let client = async move {
            let payer = crate::StoragePayer::for_test();
            fs.open(
                path("created"),
                OpenFlags::CREATE | OpenFlags::EXCLUSIVE,
                1_000_000_000,
                &payer,
            )
            .await
            .expect("create file");
            assert_eq!(
                fs.open(
                    path("created"),
                    OpenFlags::CREATE | OpenFlags::EXCLUSIVE,
                    1_000_000_000,
                    &payer,
                )
                .await
                .map(drop),
                Err(FsError::Exists)
            );
            let payload = alloc::vec![0x53; 19_000];
            let start = write_with(
                &fs,
                path("created"),
                WritePosition::At(0),
                payload.len(),
                1_000_000_001,
                &payer,
                |offset, bytes| bytes.copy_from_slice(&payload[offset..offset + bytes.len()]),
            )
            .await
            .expect("multiple rounds");
            assert_eq!(
                start,
                Landed {
                    offset: 0,
                    len: payload.len()
                }
            );
            assert_eq!(
                fs.read_at(path("created"), 0, payload.len()).await.unwrap(),
                payload.as_slice()
            );
            let staged = fs
                .prepare_write(
                    path("created"),
                    WritePosition::End,
                    5,
                    1_000_000_002,
                    &payer,
                )
                .await
                .expect("stage without mutation");
            drop(staged);
            assert_eq!(
                fs.stat(path("created")).await.unwrap().size,
                payload.len() as u64
            );
            let first = fs
                .prepare_write(
                    path("created"),
                    WritePosition::End,
                    3,
                    1_000_000_003,
                    &payer,
                )
                .await
                .unwrap();
            let second = fs
                .prepare_write(
                    path("created"),
                    WritePosition::End,
                    2,
                    1_000_000_004,
                    &payer,
                )
                .await
                .unwrap();
            fs.rename(
                path("created"),
                path("renamed"),
                RenameMode::Replace,
                1_000_000_005,
                &payer,
            )
            .await
            .expect("rename prepared inode");
            let (first, second) = futures::future::join(
                first.fill(|_, bytes| bytes.fill(0x41)).submit(),
                second.fill(|_, bytes| bytes.fill(0x42)).submit(),
            )
            .await;
            assert!(matches!(
                first,
                Ok(WriteProgress::Done(Landed {
                    offset: 19_000,
                    len: 3
                }))
            ));
            assert!(matches!(
                second,
                Ok(WriteProgress::Done(Landed {
                    offset: 19_003,
                    len: 2
                }))
            ));
            assert_eq!(
                fs.read_at(path("renamed"), 19_000, 5).await.unwrap(),
                &b"AAABB"[..]
            );
            fs.create_directory(path("dir"), 2_000_000_000, &payer)
                .await
                .expect("mkdir");
            fs.link(path("file"), path("dir/link"), 3_000_000_000, &payer)
                .await
                .expect("link");
            fs.rename(
                path("dir/link"),
                path("dir/moved"),
                RenameMode::Replace,
                4_000_000_000,
                &payer,
            )
            .await
            .expect("rename");
            fs.set_size(path("dir/moved"), 7, 5_000_000_000, &payer)
                .await
                .expect("truncate");
            fs.symlink("moved", path("dir/symlink"), 6_000_000_000, &payer)
                .await
                .expect("symlink");
            assert_eq!(
                fs.remove_directory(path("dir"), 7_000_000_000, &payer)
                    .await,
                Err(FsError::NotEmpty)
            );
            assert_eq!(
                fs.unlink(path("dir"), 7_000_000_000, &payer).await,
                Err(FsError::IsDirectory)
            );
            fs.open(
                path("dir/deleted"),
                OpenFlags::CREATE,
                7_000_000_000,
                &payer,
            )
            .await
            .unwrap();
            fs.unlink(path("dir/deleted"), 8_000_000_000, &payer)
                .await
                .unwrap();
            let parent = fs.stat(path("dir")).await.unwrap();
            assert_eq!(parent.modified_nanos, 8_000_000_000);
            assert_eq!(parent.status_nanos, 8_000_000_000);
            fs.open(
                path("dir/fresh"),
                OpenFlags::CREATE | OpenFlags::EXCLUSIVE,
                9_000_000_000,
                &payer,
            )
            .await
            .expect("create in a created directory");
            write_with(
                &fs,
                path("dir/fresh"),
                WritePosition::At(0),
                4096,
                9_000_000_001,
                &payer,
                |_, bytes| bytes.fill(0x46),
            )
            .await
            .expect("write the fresh file");
            fs.sync(path("dir/fresh")).await.expect("fsync");
            fs.link(
                path("dir/fresh"),
                path("dir/fresh-link"),
                9_000_000_002,
                &payer,
            )
            .await
            .expect("link a file created and synced in this mount");
            fs.sync(path("file")).await.expect("sync commit");
            assert_eq!(
                fs.read_at(path("file"), 0, 99).await.unwrap(),
                &b"durable"[..]
            );
            drop(fs);
        };
        futures::future::join(
            alloc::boxed::Box::pin(client),
            alloc::boxed::Box::pin(service.run(idle_timer())),
        )
        .await;
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

/// The device's bytes as a source the btrfs reader mounts, to read back the
/// Unix metadata the filesystem contract does not report.
struct Bytes(Vec<u8>);

impl helios_btrfs::BlockSource for Bytes {
    fn size_bytes(&self) -> u64 {
        self.0.len() as u64
    }

    async fn read_at(&self, offset: u64, output: &mut [u8]) -> helios_hal::io::IoResult<()> {
        let start = offset as usize;
        output.copy_from_slice(&self.0[start..start + output.len()]);
        Ok(())
    }
}

/// A node created through the filesystem contract, which carries no creator
/// identity, takes its owner and group from its parent directory, and its
/// mode from the parent's with the execute bits cleared for a regular file
/// (lexoliu/helios#1037).
#[test]
fn a_node_created_without_an_identity_inherits_from_its_parent() {
    let time = Timestamp::from_secs(1_700_000_000);
    let directories: [(&str, u16, u32, u32); 3] = [
        ("中文目录", 0o2775, 1000, 100),
        ("日本語のディレクトリ", 0o1777, 0, 0),
        ("한국어디렉터리", 0o750, 7, 8),
    ];
    let mut tree = TreeBuilder::new().root(Metadata::new(0o755, time));
    for (name, mode, uid, gid) in directories {
        tree = tree.directory(
            alloc::format!("/{name}"),
            Metadata::new(mode, time).owned_by(uid, gid),
        );
    }
    let disk = formatted_disk(tree, FormatOptions::new([0x63; 16], time), false);
    let cache = cache_over(&disk, 256, 1);
    block_on(async {
        let (fs, service) =
            BtrfsFs::mount_writable(cache.disk(0), || DeviceId::new(120), write_options(1, None))
                .await
                .expect("writable mount");
        let client = async move {
            let payer = crate::StoragePayer::for_test();
            for (name, ..) in directories {
                let file = alloc::format!("{name}/ファイル");
                fs.open(path(&file), OpenFlags::CREATE, 1_000_000_000, &payer)
                    .await
                    .expect("create");
                let child = alloc::format!("{name}/하위");
                fs.create_directory(path(&child), 1_000_000_000, &payer)
                    .await
                    .expect("mkdir");
                let link = alloc::format!("{name}/链接");
                fs.symlink("ファイル", path(&link), 1_000_000_000, &payer)
                    .await
                    .expect("symlink");
            }
            drop(fs);
        };
        futures::future::join(
            alloc::boxed::Box::pin(client),
            alloc::boxed::Box::pin(service.run(idle_timer())),
        )
        .await;
    });
    let view = block_on(helios_btrfs::Filesystem::mount(Bytes(
        disk.bytes_at(0, FORMATTED_BYTES),
    )))
    .expect("the committed image mounts");
    for (name, mode, uid, gid) in directories {
        let parent = block_on(view.resolve(alloc::format!("/{name}").as_bytes())).unwrap();
        let made = |child: &str| {
            let inode = block_on(view.lookup(&parent, child.as_bytes()))
                .unwrap()
                .expect("created");
            let metadata = *inode.metadata();
            (metadata.permissions, metadata.uid, metadata.gid)
        };
        let mode = u32::from(mode);
        // Execute cleared, and no set-id or sticky bit, for the file.
        assert_eq!(made("ファイル"), (mode & 0o666, uid, gid), "{name}");
        // The directory keeps the set-group-id bit and only that.
        assert_eq!(made("하위"), (mode & 0o2777, uid, gid), "{name}");
        assert_eq!(made("链接"), (0o777, uid, gid), "{name}");
    }

    // Re-mounting through `BtrfsFs` exposes the same stored Unix owner and mode bits.
    let cache = cache_over(&disk, 256, 1);
    let mounted = mount(&cache);
    for (name, mode, uid, gid) in directories {
        assert_eq!(
            block_on(mounted.unix_attributes(path(name))).expect("dir unix attrs"),
            crate::UnixAttributes {
                permissions: u32::from(mode) & 0o7777,
                uid,
                gid,
            },
            "{name}"
        );
        let file = alloc::format!("{name}/ファイル");
        assert_eq!(
            block_on(mounted.unix_attributes(path(&file))).expect("file unix attrs"),
            crate::UnixAttributes {
                permissions: u32::from(mode) & 0o666,
                uid,
                gid,
            },
            "{name}"
        );
    }
}

#[test]
fn writable_mount_refuses_to_open_special_nodes_and_keeps_them_across_writes() {
    let time = Timestamp::from_secs(1_700_000_000);
    let tree = TreeBuilder::new()
        .root(Metadata::new(0o755, time))
        .char_device("/chr", 1, 3, Metadata::new(0o660, time))
        .block_device("/blk", 8, 0, Metadata::new(0o660, time))
        .fifo("/fifo", Metadata::new(0o640, time))
        .socket("/sock", Metadata::new(0o600, time));
    let disk = formatted_disk(tree, FormatOptions::new([0x64; 16], time), false);
    let cache = cache_over(&disk, 256, 1);
    block_on(async {
        let (fs, service) =
            BtrfsFs::mount_writable(cache.disk(0), || DeviceId::new(121), write_options(1, None))
                .await
                .expect("writable mount");
        let client = async move {
            let payer = crate::StoragePayer::for_test();
            for (name, expected_kind, expected_err) in [
                (
                    "chr",
                    helios_hal::fs::NodeKind::CharacterDevice,
                    helios_hal::fs::FsError::NotPermitted,
                ),
                (
                    "blk",
                    helios_hal::fs::NodeKind::BlockDevice,
                    helios_hal::fs::FsError::NotPermitted,
                ),
                (
                    "fifo",
                    helios_hal::fs::NodeKind::Fifo,
                    helios_hal::fs::FsError::Unsupported,
                ),
                (
                    "sock",
                    helios_hal::fs::NodeKind::Socket,
                    helios_hal::fs::FsError::Unsupported,
                ),
            ] {
                assert_eq!(fs.stat(path(name)).await.unwrap().kind, expected_kind);
                assert_eq!(
                    fs.open(path(name), OpenFlags::empty(), 1_000_000_000, &payer)
                        .await
                        .map(drop),
                    Err(expected_err),
                    "{name}"
                );
            }
            fs.open(path("neighbor"), OpenFlags::CREATE, 1_000_000_000, &payer)
                .await
                .expect("creates regular file beside special nodes");
            drop(fs);
        };
        futures::future::join(
            alloc::boxed::Box::pin(client),
            alloc::boxed::Box::pin(service.run(idle_timer())),
        )
        .await;
    });
}

#[test]
fn writable_service_renames_with_noreplace_and_exchange_and_survives_remount() {
    let time = Timestamp::from_secs(1_700_000_000);
    let tree = TreeBuilder::new().root(Metadata::new(0o755, time)).file(
        "/中文",
        b"zhongwen",
        Metadata::new(0o644, time),
    );
    let cache = formatted_writable_image(tree, FormatOptions::new([0x62; 16], time));
    block_on(async {
        let (fs, service) =
            BtrfsFs::mount_writable(cache.disk(0), || DeviceId::new(110), write_options(2, None))
                .await
                .expect("writable mount");
        let client = async move {
            let payer = crate::StoragePayer::for_test();
            fs.create_directory(path("日本語"), 1_000_000_000, &payer)
                .await
                .expect("mkdir");
            fs.open(
                path("日本語/한국어"),
                OpenFlags::CREATE,
                1_000_000_001,
                &payer,
            )
            .await
            .expect("create");
            assert_eq!(
                fs.rename(
                    path("中文"),
                    path("日本語/한국어"),
                    RenameMode::NoReplace,
                    2_000_000_000,
                    &payer,
                )
                .await,
                Err(FsError::Exists)
            );
            assert_eq!(
                fs.rename(
                    path("none"),
                    path("none2"),
                    RenameMode::Exchange,
                    2_000_000_000,
                    &payer,
                )
                .await,
                Err(FsError::NoEntry)
            );
            assert_eq!(
                fs.rename(
                    path("中文"),
                    path("none2"),
                    RenameMode::Exchange,
                    2_000_000_000,
                    &payer,
                )
                .await,
                Err(FsError::NoEntry)
            );
            assert_eq!(
                fs.rename(
                    path("日本語"),
                    path("日本語/한국어"),
                    RenameMode::Exchange,
                    2_000_000_000,
                    &payer,
                )
                .await,
                Err(FsError::Invalid)
            );
            fs.rename(
                path("中文"),
                path("日本語/한국어"),
                RenameMode::Exchange,
                3_000_000_000,
                &payer,
            )
            .await
            .expect("exchange a file with a file in another directory");
            fs.rename(
                path("日本語"),
                path("中文"),
                RenameMode::Exchange,
                4_000_000_000,
                &payer,
            )
            .await
            .expect("exchange a directory with a file");
            fs.sync(path("日本語")).await.expect("commit");
            drop(fs);
        };
        futures::future::join(
            alloc::boxed::Box::pin(client),
            alloc::boxed::Box::pin(service.run(idle_timer())),
        )
        .await;
        let reopened = BtrfsFs::mount(cache.disk(0), || DeviceId::new(111))
            .await
            .expect("reopen");
        // 日本語 holds what 中文 held, and 中文 the directory.
        assert_eq!(
            reopened.read_at(path("日本語"), 0, 99).await.unwrap(),
            &b""[..]
        );
        assert_eq!(
            reopened.read_at(path("中文/한국어"), 0, 99).await.unwrap(),
            &b"zhongwen"[..]
        );
    });
}

/// The byte every sector of the full-device test's file holds at `offset`:
/// one value per 4 KiB sector, so a shifted or repeated sector reads wrong.
fn sector_pattern(offset: usize) -> u8 {
    ((offset / 4096) % 251) as u8 + 1
}

#[test]
fn a_full_device_stores_a_prefix_then_refuses_with_no_space() {
    let time = Timestamp::from_secs(1_700_000_000);
    let tree = TreeBuilder::new().root(Metadata::new(0o755, time));
    let cache = formatted_writable_image(tree, FormatOptions::new([0x61; 16], time));
    // Far more than the 128 MiB image can hold.
    const REQUESTED: usize = 160 << 20;
    const NAME: &str = "容量-容量-용량";
    let stored = block_on(async {
        let (fs, service) = BtrfsFs::mount_writable(
            cache.disk(0),
            || DeviceId::new(100),
            write_options(64, None),
        )
        .await
        .expect("writable mount");
        let client = async move {
            let payer = crate::StoragePayer::for_test();
            fs.open(
                path(NAME),
                OpenFlags::CREATE | OpenFlags::EXCLUSIVE,
                1_000_000_000,
                &payer,
            )
            .await
            .expect("create file");
            let landed = write_with(
                &fs,
                path(NAME),
                WritePosition::At(0),
                REQUESTED,
                1_000_000_001,
                &payer,
                |offset, bytes| {
                    // Rounds and sectors both start on sector boundaries.
                    for (index, sector) in bytes.chunks_mut(4096).enumerate() {
                        sector.fill(sector_pattern(offset + index * 4096));
                    }
                },
            )
            .await
            .expect("a prefix of the write lands");
            assert_eq!(landed.offset, 0);
            assert!(landed.len > 0, "something landed");
            assert!(landed.len < REQUESTED, "the device ran out of space");
            assert_eq!(
                fs.stat(path(NAME)).await.unwrap().size,
                landed.len as u64,
                "the file holds exactly the prefix"
            );
            // No sector is left, so the next write stores nothing.
            let refused = write_with(
                &fs,
                path(NAME),
                WritePosition::End,
                4096,
                1_000_000_002,
                &payer,
                |_, bytes| bytes.fill(0x5a),
            )
            .await;
            assert_eq!(refused, Err(FsError::NoSpace));
            fs.sync(path(NAME)).await.expect("the prefix commits");
            drop(fs);
            landed.len
        };
        futures::future::join(client, service.run(idle_timer()))
            .await
            .0
    });
    block_on(async {
        let reopened = BtrfsFs::mount(cache.disk(0), || DeviceId::new(101))
            .await
            .expect("remount");
        assert_eq!(reopened.stat(path(NAME)).await.unwrap().size, stored as u64);
        const READ: usize = 1 << 20;
        let mut offset = 0;
        while offset < stored {
            let chunk = reopened
                .read_at(path(NAME), offset as u64, READ)
                .await
                .expect("reads the prefix");
            assert!(!chunk.is_empty(), "the file is shorter than its size");
            for (index, sector) in chunk.chunks(4096).enumerate() {
                let at = offset + index * 4096;
                assert!(
                    sector.iter().all(|byte| *byte == sector_pattern(at)),
                    "sector at {at}"
                );
            }
            offset += chunk.len();
        }
        assert_eq!(offset, stored);
    });
}

/// The bytes of a writable btrfs volume holding only its root directory.
fn empty_image() -> Vec<u8> {
    let time = Timestamp::from_secs(1_700_000_000);
    format_image(
        TreeBuilder::new().root(Metadata::new(0o755, time)),
        FormatOptions::new([0x61; 16], time),
    )
}

/// The generation the primary superblock on `disk` records: what the last
/// commit made durable. `struct btrfs_super_block` (`btrfs_tree.h`) puts
/// `generation` after `csum[32]`, `fsid[16]`, `bytenr`, `flags` and `magic`,
/// at byte 72.
fn durable_generation(disk: &MemoryDisk) -> u64 {
    let offset = helios_btrfs::MIRROR_OFFSETS[0] as usize + 72;
    u64::from_le_bytes(disk.bytes_at(offset, 8).try_into().unwrap())
}

/// Lets the service task run, beside the test's own, until `done` holds.
/// Every device answer in these tests is immediate, so a commit finishes
/// within a bounded number of polls; one that does not is a hang.
async fn settle(mut done: impl FnMut() -> bool) {
    // Far more polls than one commit of these small transactions takes.
    for _ in 0..10_000 {
        if done() {
            return;
        }
        crate::yield_now().await;
    }
    panic!("the service did not reach the expected state");
}

/// Lets the service task run for a while with nothing expected to change.
async fn idle() {
    // As many polls as `settle` allows a commit.
    for _ in 0..10_000 {
        crate::yield_now().await;
    }
}

fn commit_options(policy: crate::vfs::CommitPolicy) -> crate::vfs::BtrfsWriteOptions {
    crate::vfs::BtrfsWriteOptions {
        commit: Some(policy),
        ..write_options(4, None)
    }
}

/// A write is visible to every reader once it is applied and stays off the
/// device until a sync asks for it; the syncs in flight together share one
/// commit, and a sync with nothing left to write writes nothing.
#[test]
fn a_change_is_visible_at_once_and_durable_once_a_sync_covers_it() {
    let disk = MemoryDisk::holding_writable("btrfs-test", &empty_image());
    let cache = cache_over(&disk, 256, 1);
    let start = durable_generation(&disk);
    let names = ["中文.txt", "日本語.txt", "한국어.txt"];
    block_on(async {
        let (fs, service) =
            BtrfsFs::mount_writable(cache.disk(0), || DeviceId::new(100), write_options(4, None))
                .await
                .expect("writable mount");
        let disk = &disk;
        let client = async move {
            let payer = crate::StoragePayer::for_test();
            for (index, name) in names.iter().enumerate() {
                fs.open(
                    path(name),
                    OpenFlags::CREATE | OpenFlags::EXCLUSIVE,
                    1_000_000_000,
                    &payer,
                )
                .await
                .expect("create");
                write_with(
                    &fs,
                    path(name),
                    WritePosition::At(0),
                    4096,
                    1_000_000_001,
                    &payer,
                    |_, bytes| bytes.fill(0x41 + index as u8),
                )
                .await
                .expect("write");
            }
            for (index, name) in names.iter().enumerate() {
                assert_eq!(
                    fs.read_at(path(name), 0, 4096).await.unwrap(),
                    alloc::vec![0x41 + index as u8; 4096],
                    "{name} reads back before any commit"
                );
            }
            assert_eq!(durable_generation(disk), start);
            let syncs =
                futures::future::join_all(names.iter().map(|name| fs.sync(path(name)))).await;
            assert!(syncs.iter().all(Result::is_ok), "{syncs:?}");
            assert_eq!(durable_generation(disk), start + 1, "one commit covers all");
            fs.sync(path(names[0])).await.expect("a clean sync");
            assert_eq!(durable_generation(disk), start + 1);
            assert_eq!(fs.sync(path("absent")).await, Err(FsError::NoEntry));
            drop(fs);
        };
        futures::future::join(
            alloc::boxed::Box::pin(client),
            alloc::boxed::Box::pin(service.run(idle_timer())),
        )
        .await;
    });
}

/// The interval commits a change once it has waited that long, measured from
/// the change; an operator who shortens it below the time already waited
/// gets the commit at once.
#[test]
fn the_commit_interval_commits_a_waiting_change_and_follows_its_operator() {
    use crate::test_support::ManualClockCpu;
    use crate::vfs::CommitPolicy;
    use core::time::Duration;

    let disk = MemoryDisk::holding_writable("btrfs-test", &empty_image());
    let cache = cache_over(&disk, 256, 1);
    let start = durable_generation(&disk);
    let clock = ManualClockCpu::new();
    let timer = crate::test_support::test_timer(clock.clone());
    let policy = |seconds| CommitPolicy {
        interval: Duration::from_secs(seconds),
        ..CommitPolicy::machine_default()
    };
    block_on(async {
        let (fs, service) = BtrfsFs::mount_writable(
            cache.disk(0),
            || DeviceId::new(100),
            commit_options(policy(5)),
        )
        .await
        .expect("writable mount");
        let disk = &disk;
        let advance = |seconds: u64| {
            clock.advance(seconds * 1_000_000_000);
            timer.fire_expired();
        };
        let client = async {
            const NAME: &str = "间隔-間隔-간격";
            let payer = crate::StoragePayer::for_test();
            fs.open(path(NAME), OpenFlags::CREATE, 1_000_000_000, &payer)
                .await
                .expect("create");
            advance(4);
            idle().await;
            assert_eq!(durable_generation(disk), start, "four seconds in");
            advance(1);
            settle(|| durable_generation(disk) == start + 1).await;

            fs.set_commit_policy(policy(60)).expect("writable mount");
            fs.set_times(path(NAME), None, Some(2_000_000_000), 2_000_000_000, &payer)
                .await
                .expect("touch");
            advance(30);
            idle().await;
            assert_eq!(
                durable_generation(disk),
                start + 1,
                "thirty of sixty seconds"
            );
            fs.set_commit_policy(policy(10)).expect("writable mount");
            settle(|| durable_generation(disk) == start + 2).await;
            assert_eq!(fs.commit_policy(), Some(policy(10)));
            drop(fs);
        };
        futures::future::join(client, service.run(timer.clone())).await;
    });
}

/// Dirty data past its bound is written back into extents without a commit,
/// and the bound is the operator's to move.
#[test]
fn the_dirty_data_bound_writes_back_without_a_commit() {
    use crate::vfs::CommitPolicy;

    let disk = MemoryDisk::holding_writable("btrfs-test", &empty_image());
    let cache = cache_over(&disk, 256, 1);
    let start = durable_generation(&disk);
    let bound = |dirty_data_limit| CommitPolicy {
        dirty_data_limit,
        ..CommitPolicy::for_machine(1 << 30)
    };
    const NAME: &str = "回写-書き戻し-되쓰기";
    let payload = "延迟分配 遅延割り当て 지연 할당\n"
        .repeat(4000)
        .into_bytes();
    block_on(async {
        let (fs, service) = BtrfsFs::mount_writable(
            cache.disk(0),
            || DeviceId::new(100),
            commit_options(bound(u64::MAX)),
        )
        .await
        .expect("writable mount");
        let disk = &disk;
        let payload = &payload;
        let client = async {
            let extents = || async {
                let snapshot = fs.inner.reader.lock().clone();
                let inode = snapshot.resolve(NAME.as_bytes()).await.unwrap();
                snapshot.file_extents(&inode).await.unwrap()
            };
            let payer = crate::StoragePayer::for_test();
            fs.open(path(NAME), OpenFlags::CREATE, 1_000_000_000, &payer)
                .await
                .expect("create");
            write_with(
                &fs,
                path(NAME),
                WritePosition::At(0),
                payload.len(),
                1_000_000_001,
                &payer,
                |offset, bytes| bytes.copy_from_slice(&payload[offset..offset + bytes.len()]),
            )
            .await
            .expect("write");
            idle().await;
            assert!(extents().await.is_empty(), "dirty within its bound");
            assert_eq!(
                fs.read_at(path(NAME), 0, payload.len()).await.unwrap(),
                payload.as_slice()
            );
            fs.set_commit_policy(bound(1)).expect("writable mount");
            idle().await;
            let written = extents().await;
            assert_eq!(
                written.iter().map(|extent| extent.len).sum::<u64>(),
                payload.len().next_multiple_of(4096) as u64,
                "written back past its bound: {written:?}"
            );
            assert_eq!(durable_generation(disk), start, "writeback is no commit");
            assert_eq!(
                fs.read_at(path(NAME), 0, payload.len()).await.unwrap(),
                payload.as_slice()
            );
            fs.sync(path(NAME)).await.expect("sync");
            assert_eq!(durable_generation(disk), start + 1);
            drop(fs);
        };
        futures::future::join(
            alloc::boxed::Box::pin(client),
            alloc::boxed::Box::pin(service.run(idle_timer())),
        )
        .await;
    });
}

/// Dirty metadata past the bound commits without a sync, and the bound is the
/// operator's to move.
#[test]
fn the_dirty_bound_commits_without_a_sync() {
    use crate::vfs::CommitPolicy;

    let disk = MemoryDisk::holding_writable("btrfs-test", &empty_image());
    let cache = cache_over(&disk, 256, 1);
    let start = durable_generation(&disk);
    let bound = |dirty_metadata_limit| CommitPolicy {
        dirty_metadata_limit,
        ..CommitPolicy::machine_default()
    };
    block_on(async {
        // One dirty byte is past this bound: every change commits.
        let (fs, service) = BtrfsFs::mount_writable(
            cache.disk(0),
            || DeviceId::new(100),
            commit_options(bound(1)),
        )
        .await
        .expect("writable mount");
        let disk = &disk;
        let client = async {
            let payer = crate::StoragePayer::for_test();
            fs.create_directory(path("目录-ディレクトリ-디렉터리"), 1_000_000_000, &payer)
                .await
                .expect("mkdir");
            settle(|| durable_generation(disk) == start + 1).await;
            fs.set_commit_policy(CommitPolicy::machine_default())
                .expect("writable mount");
            fs.create_directory(path("目录-ディレクトリ-디렉터리/内"), 2_000_000_000, &payer)
                .await
                .expect("mkdir");
            idle().await;
            assert_eq!(durable_generation(disk), start + 1, "within Linux's bound");
            fs.set_commit_policy(bound(1)).expect("writable mount");
            settle(|| durable_generation(disk) == start + 2).await;
            drop(fs);
        };
        futures::future::join(
            alloc::boxed::Box::pin(client),
            alloc::boxed::Box::pin(service.run(idle_timer())),
        )
        .await;
    });
}

/// Unmounting commits what the running transaction holds.
#[test]
fn unmounting_commits_the_running_transaction() {
    let disk = MemoryDisk::holding_writable("btrfs-test", &empty_image());
    let cache = cache_over(&disk, 256, 1);
    let start = durable_generation(&disk);
    const NAME: &str = "卸载-アンマウント-언마운트";
    let contents = "卸载前写入 アンマウント前に書いた 언마운트 전에 썼다\n".repeat(100);
    block_on(async {
        let (fs, service) =
            BtrfsFs::mount_writable(cache.disk(0), || DeviceId::new(100), write_options(2, None))
                .await
                .expect("writable mount");
        let contents = contents.as_bytes();
        let client = async move {
            let payer = crate::StoragePayer::for_test();
            fs.open(path(NAME), OpenFlags::CREATE, 1_000_000_000, &payer)
                .await
                .expect("create");
            write_with(
                &fs,
                path(NAME),
                WritePosition::At(0),
                contents.len(),
                1_000_000_001,
                &payer,
                |offset, bytes| bytes.copy_from_slice(&contents[offset..offset + bytes.len()]),
            )
            .await
            .expect("write");
            drop(fs);
        };
        futures::future::join(
            alloc::boxed::Box::pin(client),
            alloc::boxed::Box::pin(service.run(idle_timer())),
        )
        .await;
    });
    assert_eq!(durable_generation(&disk), start + 1);
    let reopened = mount(&cache_over(&disk, 256, 1));
    assert_eq!(
        block_on(reopened.read_at(path(NAME), 0, contents.len())).unwrap(),
        contents.as_bytes()
    );
}

/// A commit that fails fails the sync waiting on it and ends the writable
/// mount; the device keeps the previous complete generation.
#[test]
fn a_failed_commit_fails_its_sync_and_leaves_the_previous_tree() {
    // The first superblock copy a commit writes is the 64 MiB mirror, in
    // 512-byte device blocks: refusing it fails the commit before any copy
    // records the new generation.
    let mirror = (helios_btrfs::MIRROR_OFFSETS[1] / 512) as usize;
    let disk = MemoryDisk::holding_writable_failing_at("btrfs-test", &empty_image(), mirror);
    let cache = cache_over(&disk, 256, 1);
    let start = durable_generation(&disk);
    const NAME: &str = "丢失-失われた-잃어버린";
    block_on(async {
        let (fs, service) =
            BtrfsFs::mount_writable(cache.disk(0), || DeviceId::new(100), write_options(2, None))
                .await
                .expect("writable mount");
        let client = async move {
            let payer = crate::StoragePayer::for_test();
            fs.open(path(NAME), OpenFlags::CREATE, 1_000_000_000, &payer)
                .await
                .expect("create");
            assert!(
                fs.stat(path(NAME)).await.is_ok(),
                "visible before its commit"
            );
            assert_eq!(fs.sync(path(NAME)).await, Err(FsError::Io));
            assert_eq!(
                fs.create_directory(path("后来-後で-나중"), 2_000_000_000, &payer)
                    .await,
                Err(FsError::Io)
            );
            drop(fs);
        };
        futures::future::join(
            alloc::boxed::Box::pin(client),
            alloc::boxed::Box::pin(service.run(idle_timer())),
        )
        .await;
    });
    assert_eq!(durable_generation(&disk), start);
    let reopened = mount(&cache_over(&disk, 256, 1));
    assert_eq!(
        block_on(reopened.stat(path(NAME))).map(drop),
        Err(FsError::NoEntry)
    );
}

/// A namespace with an empty `/mnt` to mount the test disk on.
fn mount_point_namespace() -> Namespace<MemoryStorage> {
    const BOOT: EmbeddedBootFs = EmbeddedBootFs::new(&[EmbeddedBootDirectory::new("mnt", 0)], &[]);
    Namespace::new(MountTable::new(BootFs::new(BOOT, BOOT_DEVICE), 1))
}

/// Mounts `disk` writable at `/mnt` in `namespace`, with `commit` as the
/// request's `commit=` option.
fn request_writable(
    namespace: &Namespace<MemoryStorage>,
    disk: &MemoryDisk,
    commit: Option<crate::vfs::CommitPolicy>,
) -> crate::vfs::BtrfsService<MemoryDisk> {
    block_on(request_mount(
        &ProcessAuthority::root(),
        namespace,
        AttachedStorage {
            host_share: None,
            disks: Some(cache_over(disk, 256, 1)),
        },
        mount_request(
            btrfs_source(),
            false,
            crate::vfs::BtrfsWriteOptions {
                commit,
                ..write_options(1, None)
            },
        ),
    ))
    .expect("mount request")
    .expect("a writable btrfs mount returns its service")
}

/// Creates `name` under the namespace's `/mnt` holding `contents`.
async fn create_in_namespace(namespace: &Namespace<MemoryStorage>, name: &str, contents: &[u8]) {
    let point = alloc::format!("/mnt/{name}");
    let resolved = namespace.resolve(&point).unwrap();
    let fs = resolved.writable().unwrap();
    let payer = crate::StoragePayer::for_test();
    fs.open(resolved.path(), OpenFlags::CREATE, 1_000_000_000, &payer)
        .await
        .expect("create");
    write_with(
        fs,
        resolved.path(),
        WritePosition::At(0),
        contents.len(),
        1_000_000_001,
        &payer,
        |offset, bytes| bytes.copy_from_slice(&contents[offset..offset + bytes.len()]),
    )
    .await
    .expect("write");
}

/// As Linux's unmount, a namespace unmount returns only once what the mount
/// held is on its device.
#[test]
fn a_namespace_unmount_returns_once_its_commit_is_durable() {
    let disk = MemoryDisk::holding_writable("btrfs-test", &empty_image());
    let start = durable_generation(&disk);
    let namespace = mount_point_namespace();
    let service = request_writable(&namespace, &disk, None);
    const NAME: &str = "卸载-アンマウント-언마운트";
    let contents = "卸载前 アンマウント前 언마운트 전\n".repeat(64);
    let client = async {
        create_in_namespace(&namespace, NAME, contents.as_bytes()).await;
        assert_eq!(durable_generation(&disk), start, "nothing synced yet");
        crate::request_unmount(&ProcessAuthority::root(), &namespace, "/mnt")
            .await
            .expect("unmount");
        assert_eq!(
            durable_generation(&disk),
            start + 1,
            "the unmount returned with its commit durable"
        );
    };
    block_on(futures::future::join(client, service.run(idle_timer())));
    let reopened = mount(&cache_over(&disk, 256, 1));
    assert_eq!(
        block_on(reopened.read_at(path(NAME), 0, contents.len())).unwrap(),
        contents.as_bytes()
    );
}

/// What the kernel runs before power-off commits every writable mount on the
/// machine, a descendant tree's included, and leaves the mounts serving.
#[test]
fn powering_off_commits_every_writable_mount_on_the_machine() {
    let disk = MemoryDisk::holding_writable("btrfs-test", &empty_image());
    let start = durable_generation(&disk);
    let root = mount_point_namespace();
    let child = root.descend();
    let service = request_writable(&child, &disk, None);
    const NAME: &str = "关机-電源断-전원끄기";
    let client = async {
        create_in_namespace(&child, NAME, "关机前 電源断の前 전원 끄기 전\n".as_bytes()).await;
        assert_eq!(durable_generation(&disk), start);
        root.sync_writable_mounts().await;
        assert_eq!(
            durable_generation(&disk),
            start + 1,
            "the child's mount committed"
        );
        // A clean mount has nothing to commit, and still answers.
        root.sync_writable_mounts().await;
        assert_eq!(durable_generation(&disk), start + 1);
        crate::request_unmount(&ProcessAuthority::root(), &child, "/mnt")
            .await
            .expect("unmount");
        // An ended mount is not waited on again.
        root.sync_writable_mounts().await;
    };
    block_on(futures::future::join(client, service.run(idle_timer())));
}

/// A mount request's `commit=` option is the interval the mount commits on;
/// zero is Linux's default.
#[test]
fn the_commit_option_of_a_mount_request_sets_its_interval() {
    use crate::test_support::ManualClockCpu;
    use crate::vfs::CommitPolicy;
    use core::time::Duration;

    let linux = CommitPolicy::machine_default();
    assert_eq!(linux.with_commit_option(0), linux);
    assert_eq!(
        linux.with_commit_option(600).interval,
        Duration::from_secs(600),
        "past Linux's warning, still taken"
    );
    let disk = MemoryDisk::holding_writable("btrfs-test", &empty_image());
    let start = durable_generation(&disk);
    let namespace = mount_point_namespace();
    let service = request_writable(&namespace, &disk, Some(linux.with_commit_option(5)));
    let clock = ManualClockCpu::new();
    let timer = crate::test_support::test_timer(clock.clone());
    let client = async {
        create_in_namespace(&namespace, "间隔-間隔-간격", b"five seconds").await;
        clock.advance(4 * 1_000_000_000);
        timer.fire_expired();
        idle().await;
        assert_eq!(durable_generation(&disk), start, "four seconds in");
        clock.advance(1_000_000_000);
        timer.fire_expired();
        settle(|| durable_generation(&disk) == start + 1).await;
        crate::request_unmount(&ProcessAuthority::root(), &namespace, "/mnt")
            .await
            .expect("unmount");
    };
    block_on(futures::future::join(client, service.run(timer.clone())));

    let namespace = mount_point_namespace();
    assert!(matches!(
        block_on(request_mount(
            &ProcessAuthority::root(),
            &namespace,
            AttachedStorage {
                host_share: None,
                disks: None,
            },
            mount_request(
                MountSource::Memory,
                false,
                crate::vfs::BtrfsWriteOptions {
                    commit: Some(linux.with_commit_option(5)),
                    ..write_options(1, None)
                },
            ),
        )),
        Err(crate::MountRequestError::CommitUnsupported)
    ));
}

/// A mount's `max_inline` decides which small files its writes keep inline,
/// and its operator changes it on the running mount, as Linux's
/// `remount,max_inline=`. A source other than btrfs refuses the option.
#[test]
fn the_max_inline_option_bounds_inline_files_and_follows_its_operator() {
    use helios_btrfs::ExtentKind;

    let disk = MemoryDisk::holding_writable("btrfs-test", &empty_image());
    // Between the two limits the test sets: 45 lines of 33 bytes.
    let contents = "内联 インライン 인라인\n".repeat(45);
    assert_eq!(contents.len(), 1485);
    const BEFORE: &str = "之前-前-이전";
    const AFTER: &str = "之后-後-이후";
    block_on(async {
        let (fs, service) = BtrfsFs::mount_writable(
            cache_over(&disk, 256, 1).disk(0),
            || DeviceId::new(100),
            crate::vfs::BtrfsWriteOptions {
                max_inline: Some(1024),
                ..write_options(1, None)
            },
        )
        .await
        .expect("writable mount");
        let contents = contents.as_bytes();
        let client = async move {
            let payer = crate::StoragePayer::for_test();
            assert_eq!(fs.max_inline(), Some(1024));
            for (name, max_inline) in [(BEFORE, 1024), (AFTER, 2048)] {
                fs.set_max_inline(max_inline).expect("writable mount");
                fs.open(path(name), OpenFlags::CREATE, 1_000_000_000, &payer)
                    .await
                    .expect("create");
                write_with(
                    &fs,
                    path(name),
                    WritePosition::At(0),
                    contents.len(),
                    1_000_000_001,
                    &payer,
                    |offset, bytes| bytes.copy_from_slice(&contents[offset..offset + bytes.len()]),
                )
                .await
                .expect("write");
            }
            assert_eq!(fs.max_inline(), Some(2048));
            fs.sync(path(AFTER)).await.expect("sync");
            drop(fs);
        };
        futures::future::join(
            alloc::boxed::Box::pin(client),
            alloc::boxed::Box::pin(service.run(idle_timer())),
        )
        .await;
    });
    let reopened = mount(&cache_over(&disk, 256, 1));
    let snapshot = reopened.inner.reader.lock().clone();
    for (name, kind) in [(BEFORE, ExtentKind::Regular), (AFTER, ExtentKind::Inline)] {
        assert_eq!(
            block_on(reopened.read_at(path(name), 0, contents.len())).unwrap(),
            contents.as_bytes()
        );
        let inode = block_on(snapshot.resolve(alloc::format!("/{name}").as_bytes())).unwrap();
        let extents = block_on(snapshot.file_extents(&inode)).unwrap();
        assert_eq!(extents.len(), 1, "{name}: {extents:?}");
        assert_eq!(extents[0].kind, kind, "{name}: {extents:?}");
    }
    assert_eq!(reopened.max_inline(), None, "a read-only mount has none");

    let namespace = mount_point_namespace();
    assert!(matches!(
        block_on(request_mount(
            &ProcessAuthority::root(),
            &namespace,
            AttachedStorage {
                host_share: None,
                disks: None,
            },
            mount_request(
                MountSource::Memory,
                false,
                crate::vfs::BtrfsWriteOptions {
                    max_inline: Some(2048),
                    ..write_options(1, None)
                },
            ),
        )),
        Err(crate::MountRequestError::MaxInlineUnsupported)
    ));
}

/// Opening a btrfs directory stream records the upper `DIR_INDEX` bound so
/// renaming entries (`entry -> TEMPFILE -> entry`) while iterating finishes
/// in bounded entries, and `rewind` refreshes the bound for newly created
/// entries.
#[test]
fn open_dir_bounds_iteration_during_renames_and_refreshes_on_rewind() {
    let disk = MemoryDisk::holding_writable("btrfs-test", &empty_image());
    block_on(async {
        let (fs, service) = BtrfsFs::mount_writable(
            cache_over(&disk, 256, 1).disk(0),
            || DeviceId::new(100),
            write_options(1, None),
        )
        .await
        .expect("writable mount");
        let client = async move {
            let payer = crate::StoragePayer::for_test();
            fs.create_directory(path("work"), 1_000_000_000, &payer)
                .await
                .expect("mkdir work");
            fs.create_directory(path("empty"), 1_000_000_000, &payer)
                .await
                .expect("mkdir empty");
            let mut expected = Vec::new();
            for name in ["中文", "日本語", "한국어"] {
                let full = alloc::format!("work/{name}");
                fs.open(path(&full), OpenFlags::CREATE, 1_000_000_001, &payer)
                    .await
                    .expect("create cjk file");
                expected.push(alloc::string::String::from(name));
            }
            for i in 0..32 {
                let name = alloc::format!("entry-{i:02}");
                let full = alloc::format!("work/{name}");
                fs.open(path(&full), OpenFlags::CREATE, 1_000_000_001, &payer)
                    .await
                    .expect("create file");
                expected.push(name);
            }

            // Opening a non-directory fails with `NotDirectory`.
            assert_eq!(
                fs.open_dir(path("work/entry-00")).await.map(drop),
                Err(FsError::NotDirectory)
            );

            // An open stream on an empty directory sees nothing added after
            // open until `rewind` refreshes its bound.
            let mut empty_stream = fs.open_dir(path("empty")).await.expect("open empty");
            fs.open(
                path("empty/added"),
                OpenFlags::CREATE,
                1_000_000_002,
                &payer,
            )
            .await
            .expect("create after open");
            assert!(
                empty_stream
                    .read(DirCookie::START, 8)
                    .await
                    .expect("read empty")
                    .is_empty()
            );
            empty_stream.rewind().await.expect("rewind empty");
            let after_rewind = empty_stream
                .read(DirCookie::START, 8)
                .await
                .expect("read after rewind");
            assert_eq!(after_rewind.len(), 1);
            assert_eq!(after_rewind[0].name, "added");

            // Rename every yielded entry (`entry -> TEMPFILE -> entry`) while
            // paging through `work`; iteration terminates with the initial set.
            let mut stream = fs.open_dir(path("work")).await.expect("open work");
            let mut cookie = DirCookie::START;
            let mut seen = Vec::new();
            let safety_cap = expected.len() * 3;
            loop {
                let batch = stream.read(cookie, 2).await.expect("read page");
                let Some(last) = batch.last() else {
                    break;
                };
                cookie = last.next;
                for entry in batch {
                    let from = alloc::format!("work/{}", entry.name);
                    fs.rename(
                        path(&from),
                        path("work/TEMPFILE"),
                        RenameMode::Replace,
                        1_000_000_003,
                        &payer,
                    )
                    .await
                    .expect("rename to TEMPFILE");
                    fs.rename(
                        path("work/TEMPFILE"),
                        path(&from),
                        RenameMode::Replace,
                        1_000_000_004,
                        &payer,
                    )
                    .await
                    .expect("rename back");
                    seen.push(entry.name);
                    assert!(
                        seen.len() <= safety_cap,
                        "directory stream looped past safety cap ({safety_cap})"
                    );
                }
            }
            seen.sort();
            expected.sort();
            assert_eq!(seen, expected);

            // After adding a new entry and calling `rewind`, the new entry appears.
            fs.open(path("work/after"), OpenFlags::CREATE, 1_000_000_005, &payer)
                .await
                .expect("create after");
            stream.rewind().await.expect("rewind work");
            let mut refreshed = Vec::new();
            let mut cookie = DirCookie::START;
            loop {
                let batch = stream.read(cookie, 16).await.expect("read refreshed");
                let Some(last) = batch.last() else {
                    break;
                };
                cookie = last.next;
                refreshed.extend(batch.into_iter().map(|entry| entry.name));
            }
            assert!(refreshed.iter().any(|name| name == "after"));
            drop(stream);
            drop(empty_stream);
            drop(fs);
        };
        futures::future::join(
            alloc::boxed::Box::pin(client),
            alloc::boxed::Box::pin(service.run(idle_timer())),
        )
        .await;
    });
}

fn mgmt_auth(
    dirs: &[(&str, crate::DirectoryAuthorityRights)],
    mount: bool,
    devices: &[&str],
) -> ProcessAuthority {
    use crate::device::DeviceName;
    use crate::{DirectoryPreopen, MountAuthorityRights};

    let mut auth = ProcessAuthority::empty();
    for &(dir, rights) in dirs {
        auth.insert_directory_preopen(DirectoryPreopen::new(dir, dir, rights).unwrap());
    }
    if mount {
        auth.grant_mount_rights(MountAuthorityRights::MOUNT);
    }
    for &dev in devices {
        auth.grant_device(DeviceName::new(dev).unwrap()).unwrap();
    }
    auth
}

fn mgmt_req<'a>(
    authority: &'a ProcessAuthority,
    namespace: &'a Namespace<MemoryStorage>,
    cache: &crate::BlockCache<MemoryDisk>,
) -> crate::vfs::BtrfsVolumeRequest<'a, MemoryStorage> {
    crate::vfs::BtrfsVolumeRequest {
        authority,
        namespace,
        attached: AttachedStorage {
            host_share: None,
            disks: Some(cache.clone()),
        },
        now: 1_750_000_000_000_000_000,
    }
}

/// Authority and execution test for subvolume create/delete, RO/RW snapshot,
/// read-only toggle, info, and list.
#[test]
fn btrfs_management_subvolume_and_snapshot_grants() {
    use helios_hal::fs_management::VolumeManagementError;

    use crate::vfs::BtrfsManagementError;
    use crate::{DirectoryAuthorityRights, request_unmount};

    let dev1 = MemoryDisk::holding_writable("btrfs-test", &empty_image());
    let cache = cache_over(&dev1, 512, 1);
    let namespace = mount_point_namespace();
    let root_auth = ProcessAuthority::root();

    block_on(async {
        let service = request_mount(
            &root_auth,
            &namespace,
            AttachedStorage {
                host_share: None,
                disks: Some(cache.clone()),
            },
            mount_request(btrfs_source(), false, write_options(1, None)),
        )
        .await
        .expect("mount writable btrfs")
        .expect("btrfs service");

        let client = async {
            let rw_no_mutate = mgmt_auth(
                &[(
                    "/mnt",
                    DirectoryAuthorityRights::READ | DirectoryAuthorityRights::WRITE,
                )],
                false,
                &[],
            );
            let mutate_mnt = mgmt_auth(
                &[("/mnt", DirectoryAuthorityRights::MUTATE_DIRECTORY)],
                false,
                &[],
            );

            // Subvolume create: READ+WRITE without MUTATE_DIRECTORY refused.
            assert!(matches!(
                mgmt_req(&rw_no_mutate, &namespace, &cache)
                    .create_subvolume("/mnt/sub")
                    .await,
                Err(BtrfsManagementError::Authority(_))
            ));
            let sub_info = mgmt_req(&mutate_mnt, &namespace, &cache)
                .create_subvolume("/mnt/sub")
                .await
                .expect("create subvolume with MUTATE_DIRECTORY");
            assert_eq!(sub_info.path, "sub");

            for dir in ["/mnt/sub/inner", "/mnt/snaps"] {
                let res = namespace.resolve(dir).unwrap();
                res.fs()
                    .create_directory(
                        res.path(),
                        1_750_000_001_000_000_000,
                        &crate::StoragePayer::for_test(),
                    )
                    .await
                    .unwrap();
            }

            // Snapshot: narrower READ grant inside `/mnt/sub/inner` is REFUSED.
            let narrow_snap = mgmt_auth(
                &[
                    ("/mnt/sub/inner", DirectoryAuthorityRights::READ),
                    ("/mnt/snaps", DirectoryAuthorityRights::MUTATE_DIRECTORY),
                ],
                false,
                &[],
            );
            assert!(matches!(
                mgmt_req(&narrow_snap, &namespace, &cache)
                    .snapshot_subvolume("/mnt/sub", "/mnt/snaps/s1", true)
                    .await,
                Err(BtrfsManagementError::Authority(_))
            ));
            assert!(matches!(
                mgmt_req(&narrow_snap, &namespace, &cache)
                    .snapshot_subvolume("/mnt/sub/inner", "/mnt/snaps/s1", true)
                    .await,
                Err(BtrfsManagementError::Volume(
                    VolumeManagementError::NotSubvolume
                ))
            ));
            let snap_no_dest_mutate = mgmt_auth(
                &[
                    ("/mnt/sub", DirectoryAuthorityRights::READ),
                    ("/mnt/snaps", DirectoryAuthorityRights::READ),
                ],
                false,
                &[],
            );
            assert!(matches!(
                mgmt_req(&snap_no_dest_mutate, &namespace, &cache)
                    .snapshot_subvolume("/mnt/sub", "/mnt/snaps/s1", true)
                    .await,
                Err(BtrfsManagementError::Authority(_))
            ));
            let exact_snap = mgmt_auth(
                &[
                    ("/mnt/sub", DirectoryAuthorityRights::READ),
                    ("/mnt/snaps", DirectoryAuthorityRights::MUTATE_DIRECTORY),
                ],
                false,
                &[],
            );
            let ro1 = mgmt_req(&exact_snap, &namespace, &cache)
                .snapshot_subvolume("/mnt/sub", "/mnt/snaps/ro1", true)
                .await
                .expect("RO snapshot");
            assert!(ro1.read_only);
            let rw1 = mgmt_req(&exact_snap, &namespace, &cache)
                .snapshot_subvolume("/mnt/sub", "/mnt/snaps/rw1", false)
                .await
                .expect("RW snapshot");
            assert!(!rw1.read_only);

            // set_subvolume_read_only, subvolume_info, list_subvolumes, delete_subvolume.
            let ro_narrow = mgmt_auth(
                &[(
                    "/mnt/snaps/rw1/inner",
                    DirectoryAuthorityRights::MUTATE_DIRECTORY,
                )],
                false,
                &[],
            );
            assert!(matches!(
                mgmt_req(&ro_narrow, &namespace, &cache)
                    .set_subvolume_read_only("/mnt/snaps/rw1", true)
                    .await,
                Err(BtrfsManagementError::Authority(_))
            ));
            assert!(matches!(
                mgmt_req(&rw_no_mutate, &namespace, &cache)
                    .set_subvolume_read_only("/mnt/snaps/rw1", true)
                    .await,
                Err(BtrfsManagementError::Authority(_))
            ));
            mgmt_req(&mutate_mnt, &namespace, &cache)
                .set_subvolume_read_only("/mnt/snaps/rw1", true)
                .await
                .expect("set RO");
            assert!(matches!(
                mgmt_req(&narrow_snap, &namespace, &cache)
                    .subvolume_info("/mnt/sub")
                    .await,
                Err(BtrfsManagementError::Authority(_))
            ));
            assert!(matches!(
                mgmt_req(&exact_snap, &namespace, &cache)
                    .list_subvolumes("/mnt")
                    .await,
                Err(BtrfsManagementError::Authority(_))
            ));
            let listed = mgmt_req(&rw_no_mutate, &namespace, &cache)
                .list_subvolumes("/mnt")
                .await
                .expect("list subvolumes");
            assert!(listed.len() >= 4);

            let del_sub_only = mgmt_auth(
                &[("/mnt/snaps/rw1", DirectoryAuthorityRights::MUTATE_DIRECTORY)],
                false,
                &[],
            );
            assert!(matches!(
                mgmt_req(&del_sub_only, &namespace, &cache)
                    .delete_subvolume("/mnt/snaps/rw1")
                    .await,
                Err(BtrfsManagementError::Authority(_))
            ));
            let del_both = mgmt_auth(
                &[("/mnt/snaps", DirectoryAuthorityRights::MUTATE_DIRECTORY)],
                false,
                &[],
            );
            mgmt_req(&del_both, &namespace, &cache)
                .delete_subvolume("/mnt/snaps/rw1")
                .await
                .expect("delete subvolume");

            request_unmount(&root_auth, &namespace, "/mnt")
                .await
                .expect("unmount");
        };

        futures::future::join(
            alloc::boxed::Box::pin(client),
            alloc::boxed::Box::pin(service.run(idle_timer())),
        )
        .await;
    });
}

/// Authority and execution test for full and incremental send & receive.
#[test]
fn btrfs_management_send_and_receive_grants() {
    use helios_hal::fs_management::VolumeManagementError;

    use crate::vfs::BtrfsManagementError;
    use crate::{DirectoryAuthorityRights, request_unmount};

    let dev1 = MemoryDisk::holding_writable("btrfs-test", &empty_image());
    let cache = cache_over(&dev1, 512, 1);
    let namespace = mount_point_namespace();
    let root_auth = ProcessAuthority::root();

    block_on(async {
        let service = request_mount(
            &root_auth,
            &namespace,
            AttachedStorage {
                host_share: None,
                disks: Some(cache.clone()),
            },
            mount_request(btrfs_source(), false, write_options(1, None)),
        )
        .await
        .expect("mount writable btrfs")
        .expect("btrfs service");

        let client = async {
            let full_dir = mgmt_auth(
                &[(
                    "/mnt",
                    DirectoryAuthorityRights::READ | DirectoryAuthorityRights::MUTATE_DIRECTORY,
                )],
                false,
                &[],
            );
            mgmt_req(&full_dir, &namespace, &cache)
                .create_subvolume("/mnt/sub")
                .await
                .expect("create sub");
            for dir in ["/mnt/sub/inner", "/mnt/snaps", "/mnt/recv"] {
                let res = namespace.resolve(dir).unwrap();
                res.fs()
                    .create_directory(
                        res.path(),
                        1_750_000_001_000_000_000,
                        &crate::StoragePayer::for_test(),
                    )
                    .await
                    .unwrap();
            }
            mgmt_req(&full_dir, &namespace, &cache)
                .snapshot_subvolume("/mnt/sub", "/mnt/snaps/ro1", true)
                .await
                .expect("ro1");
            mgmt_req(&full_dir, &namespace, &cache)
                .snapshot_subvolume("/mnt/sub", "/mnt/snaps/ro2", true)
                .await
                .expect("ro2");

            // Send: narrower READ inside subvolume or missing parent READ is refused.
            let send_narrow_inner = mgmt_auth(
                &[("/mnt/snaps/ro1/inner", DirectoryAuthorityRights::READ)],
                false,
                &[],
            );
            assert!(matches!(
                mgmt_req(&send_narrow_inner, &namespace, &cache)
                    .send_subvolume("/mnt/snaps/ro1", None, &[])
                    .await,
                Err(BtrfsManagementError::Authority(_))
            ));
            let send_child_only = mgmt_auth(
                &[("/mnt/snaps/ro2", DirectoryAuthorityRights::READ)],
                false,
                &[],
            );
            assert!(matches!(
                mgmt_req(&send_child_only, &namespace, &cache)
                    .send_subvolume("/mnt/snaps/ro2", Some("/mnt/snaps/ro1"), &[])
                    .await,
                Err(BtrfsManagementError::Authority(_))
            ));
            let send_both = mgmt_auth(
                &[
                    ("/mnt/snaps/ro1", DirectoryAuthorityRights::READ),
                    ("/mnt/snaps/ro2", DirectoryAuthorityRights::READ),
                ],
                false,
                &[],
            );
            let full_stream = mgmt_req(&send_both, &namespace, &cache)
                .send_subvolume("/mnt/snaps/ro1", None, &[])
                .await
                .expect("full send");
            let inc_stream = mgmt_req(&send_both, &namespace, &cache)
                .send_subvolume("/mnt/snaps/ro2", Some("/mnt/snaps/ro1"), &[])
                .await
                .expect("incremental send");

            // Receive: requires MUTATE_DIRECTORY at destination + READ on referenced parent.
            let rw_no_mutate = mgmt_auth(
                &[(
                    "/mnt",
                    DirectoryAuthorityRights::READ | DirectoryAuthorityRights::WRITE,
                )],
                false,
                &[],
            );
            assert!(matches!(
                mgmt_req(&rw_no_mutate, &namespace, &cache)
                    .receive_subvolume("/mnt/recv", &full_stream)
                    .await,
                Err(BtrfsManagementError::Authority(_))
            ));
            let recv_only = mgmt_auth(
                &[("/mnt/recv", DirectoryAuthorityRights::MUTATE_DIRECTORY)],
                false,
                &[],
            );
            let rec1 = mgmt_req(&recv_only, &namespace, &cache)
                .receive_subvolume("/mnt/recv", &full_stream)
                .await
                .expect("full receive");
            assert!(rec1.read_only);
            assert!(matches!(
                mgmt_req(&recv_only, &namespace, &cache)
                    .receive_subvolume("/mnt/recv", &inc_stream)
                    .await,
                Err(BtrfsManagementError::Volume(
                    VolumeManagementError::PermissionDenied
                ))
            ));
            let recv_with_source = mgmt_auth(
                &[
                    ("/mnt/recv", DirectoryAuthorityRights::MUTATE_DIRECTORY),
                    ("/mnt/snaps/ro1", DirectoryAuthorityRights::READ),
                    ("/mnt/recv/ro1", DirectoryAuthorityRights::READ),
                ],
                false,
                &[],
            );
            let rec2 = mgmt_req(&recv_with_source, &namespace, &cache)
                .receive_subvolume("/mnt/recv", &inc_stream)
                .await
                .expect("incremental receive with source READ");
            assert!(rec2.read_only);

            request_unmount(&root_auth, &namespace, "/mnt")
                .await
                .expect("unmount");
        };

        futures::future::join(
            alloc::boxed::Box::pin(client),
            alloc::boxed::Box::pin(service.run(idle_timer())),
        )
        .await;
    });
}

/// Authority and execution test for reflink and dedupe (`READ` on source +
/// `WRITE` on destination).
#[test]
fn btrfs_management_reflink_and_dedupe_grants() {
    use crate::vfs::BtrfsManagementError;
    use crate::{DirectoryAuthorityRights, request_unmount};

    let dev1 = MemoryDisk::holding_writable("btrfs-test", &empty_image());
    let cache = cache_over(&dev1, 512, 1);
    let namespace = mount_point_namespace();
    let root_auth = ProcessAuthority::root();

    block_on(async {
        let service = request_mount(
            &root_auth,
            &namespace,
            AttachedStorage {
                host_share: None,
                disks: Some(cache.clone()),
            },
            mount_request(btrfs_source(), false, write_options(1, None)),
        )
        .await
        .expect("mount writable btrfs")
        .expect("btrfs service");

        let client = async {
            let payload = alloc::vec![0x33u8; 8192];
            for file in ["/mnt/a.bin", "/mnt/b.bin", "/mnt/c.bin"] {
                let f = namespace.resolve(file).unwrap();
                f.fs()
                    .open(
                        f.path(),
                        OpenFlags::CREATE,
                        1_750_000_001_000_000_000,
                        &crate::StoragePayer::for_test(),
                    )
                    .await
                    .unwrap();
                if file != "/mnt/c.bin" {
                    crate::vfs::write_bytes(
                        f.fs(),
                        f.path(),
                        WritePosition::At(0),
                        &payload,
                        1_750_000_001_000_000_000,
                    )
                    .await
                    .unwrap();
                }
            }

            let read_only = mgmt_auth(&[("/mnt", DirectoryAuthorityRights::READ)], false, &[]);
            let write_only = mgmt_auth(&[("/mnt", DirectoryAuthorityRights::WRITE)], false, &[]);
            let rw = mgmt_auth(
                &[(
                    "/mnt",
                    DirectoryAuthorityRights::READ | DirectoryAuthorityRights::WRITE,
                )],
                false,
                &[],
            );

            assert!(matches!(
                mgmt_req(&read_only, &namespace, &cache)
                    .reflink("/mnt/a.bin", 0, "/mnt/c.bin", 0, 8192)
                    .await,
                Err(BtrfsManagementError::Authority(_))
            ));
            assert!(matches!(
                mgmt_req(&write_only, &namespace, &cache)
                    .reflink("/mnt/a.bin", 0, "/mnt/c.bin", 0, 8192)
                    .await,
                Err(BtrfsManagementError::Authority(_))
            ));
            mgmt_req(&rw, &namespace, &cache)
                .reflink("/mnt/a.bin", 0, "/mnt/c.bin", 0, 8192)
                .await
                .expect("reflink");

            assert!(matches!(
                mgmt_req(&read_only, &namespace, &cache)
                    .dedupe("/mnt/a.bin", 0, "/mnt/b.bin", 0, 8192)
                    .await,
                Err(BtrfsManagementError::Authority(_))
            ));
            assert!(matches!(
                mgmt_req(&write_only, &namespace, &cache)
                    .dedupe("/mnt/a.bin", 0, "/mnt/b.bin", 0, 8192)
                    .await,
                Err(BtrfsManagementError::Authority(_))
            ));
            let outcome = mgmt_req(&rw, &namespace, &cache)
                .dedupe("/mnt/a.bin", 0, "/mnt/b.bin", 0, 8192)
                .await
                .expect("dedupe");
            assert!(outcome.same);
            assert_eq!(outcome.bytes_deduped, 8192);

            request_unmount(&root_auth, &namespace, "/mnt")
                .await
                .expect("unmount");
        };

        futures::future::join(
            alloc::boxed::Box::pin(client),
            alloc::boxed::Box::pin(service.run(idle_timer())),
        )
        .await;
    });
}

/// Authority and execution test for device-naming operations: add, replace,
/// remove, device-targeted resize, and device-targeted scrub.
#[test]
fn btrfs_management_device_and_resize_grants() {
    use helios_hal::fs_management::ResizeTarget;

    use crate::io::cache_over_many;
    use crate::vfs::BtrfsManagementError;
    use crate::{DirectoryAuthorityRights, request_unmount};

    let dev1 = MemoryDisk::holding_writable("btrfs-test", &empty_image());
    let blank = alloc::vec![0u8; FORMATTED_BYTES];
    let dev2 = MemoryDisk::holding_writable("btrfs-dev2", &blank);
    let dev3 = MemoryDisk::holding_writable("btrfs-dev3", &blank);
    let cache = cache_over_many(&[dev1, dev2, dev3], 512, 1);

    let namespace = mount_point_namespace();
    let root_auth = ProcessAuthority::root();

    block_on(async {
        let service = request_mount(
            &root_auth,
            &namespace,
            AttachedStorage {
                host_share: None,
                disks: Some(cache.clone()),
            },
            mount_request(btrfs_source(), false, write_options(1, None)),
        )
        .await
        .expect("mount writable btrfs")
        .expect("btrfs service");

        let client = async {
            let mutate_only = mgmt_auth(
                &[("/mnt", DirectoryAuthorityRights::MUTATE_DIRECTORY)],
                false,
                &[],
            );
            let mount_no_dir = mgmt_auth(&[], true, &["btrfs-test", "btrfs-dev2", "btrfs-dev3"]);
            let mount_no_dev = mgmt_auth(
                &[("/mnt", DirectoryAuthorityRights::MUTATE_DIRECTORY)],
                true,
                &[],
            );

            for denied in [&mutate_only, &mount_no_dir] {
                assert!(matches!(
                    mgmt_req(denied, &namespace, &cache)
                        .list_devices("/mnt")
                        .await,
                    Err(BtrfsManagementError::Authority(_))
                ));
                assert!(matches!(
                    mgmt_req(denied, &namespace, &cache)
                        .resize_device("/mnt", None, ResizeTarget::Max)
                        .await,
                    Err(BtrfsManagementError::Authority(_))
                ));
            }

            // Device-naming ops require explicit device grants on top of mount authority.
            assert!(matches!(
                mgmt_req(&mount_no_dev, &namespace, &cache)
                    .add_device("/mnt", "btrfs-dev2")
                    .await,
                Err(BtrfsManagementError::Authority(_))
            ));
            let with_dev2 = mgmt_auth(
                &[("/mnt", DirectoryAuthorityRights::MUTATE_DIRECTORY)],
                true,
                &["btrfs-dev2"],
            );
            let added = mgmt_req(&with_dev2, &namespace, &cache)
                .add_device("/mnt", "btrfs-dev2")
                .await
                .expect("add_device");
            assert_eq!(added.devid, 2);

            assert!(matches!(
                mgmt_req(&mount_no_dev, &namespace, &cache)
                    .resize_device("/mnt", Some(2), ResizeTarget::Bytes(112 << 20))
                    .await,
                Err(BtrfsManagementError::Authority(_))
            ));
            let resized = mgmt_req(&with_dev2, &namespace, &cache)
                .resize_device("/mnt", Some(2), ResizeTarget::Bytes(112 << 20))
                .await
                .expect("resize dev 2");
            assert_eq!(resized.total_bytes, 112 << 20);

            assert!(matches!(
                mgmt_req(&mount_no_dev, &namespace, &cache)
                    .scrub("/mnt", Some(2), true)
                    .await,
                Err(BtrfsManagementError::Authority(_))
            ));
            let scrub_dev2 = mgmt_req(&with_dev2, &namespace, &cache)
                .scrub("/mnt", Some(2), true)
                .await
                .expect("scrub dev 2");
            assert_eq!(scrub_dev2.uncorrectable_errors, 0);

            assert!(matches!(
                mgmt_req(&with_dev2, &namespace, &cache)
                    .replace_device("/mnt", 2, "btrfs-dev3")
                    .await,
                Err(BtrfsManagementError::Authority(_))
            ));
            let with_dev3_only = mgmt_auth(
                &[("/mnt", DirectoryAuthorityRights::MUTATE_DIRECTORY)],
                true,
                &["btrfs-dev3"],
            );
            assert!(matches!(
                mgmt_req(&with_dev3_only, &namespace, &cache)
                    .replace_device("/mnt", 2, "btrfs-dev3")
                    .await,
                Err(BtrfsManagementError::Authority(_))
            ));
            let with_dev2_and_3 = mgmt_auth(
                &[("/mnt", DirectoryAuthorityRights::MUTATE_DIRECTORY)],
                true,
                &["btrfs-dev2", "btrfs-dev3"],
            );
            let replaced = mgmt_req(&with_dev2_and_3, &namespace, &cache)
                .replace_device("/mnt", 2, "btrfs-dev3")
                .await
                .expect("replace dev 2 -> dev 3");
            assert_eq!(replaced.devid, 2);

            assert!(matches!(
                mgmt_req(&with_dev2, &namespace, &cache)
                    .remove_device("/mnt", 2)
                    .await,
                Err(BtrfsManagementError::Authority(_))
            ));
            mgmt_req(&with_dev3_only, &namespace, &cache)
                .remove_device("/mnt", 2)
                .await
                .expect("remove dev 2");

            request_unmount(&root_auth, &namespace, "/mnt")
                .await
                .expect("unmount");
        };

        futures::future::join(
            alloc::boxed::Box::pin(client),
            alloc::boxed::Box::pin(service.run(idle_timer())),
        )
        .await;
    });
}

/// Authority and execution test for balance, whole-volume scrub, and quota
/// group lifecycle operations.
#[test]
fn btrfs_management_balance_scrub_and_quota_grants() {
    use helios_hal::fs_management::{BalanceFilter, QgroupId, QgroupLimit};

    use crate::vfs::BtrfsManagementError;
    use crate::{DirectoryAuthorityRights, request_unmount};

    let dev1 = MemoryDisk::holding_writable("btrfs-test", &empty_image());
    let cache = cache_over(&dev1, 512, 1);
    let namespace = mount_point_namespace();
    let root_auth = ProcessAuthority::root();

    block_on(async {
        let service = request_mount(
            &root_auth,
            &namespace,
            AttachedStorage {
                host_share: None,
                disks: Some(cache.clone()),
            },
            mount_request(btrfs_source(), false, write_options(1, None)),
        )
        .await
        .expect("mount writable btrfs")
        .expect("btrfs service");

        let client = async {
            let mutate_only = mgmt_auth(
                &[("/mnt", DirectoryAuthorityRights::MUTATE_DIRECTORY)],
                false,
                &[],
            );
            let mount_no_dir = mgmt_auth(&[], true, &[]);
            let mount_admin = mgmt_auth(
                &[("/mnt", DirectoryAuthorityRights::MUTATE_DIRECTORY)],
                true,
                &[],
            );

            for denied in [&mutate_only, &mount_no_dir] {
                assert!(matches!(
                    mgmt_req(denied, &namespace, &cache)
                        .balance("/mnt", BalanceFilter::default())
                        .await,
                    Err(BtrfsManagementError::Authority(_))
                ));
                assert!(matches!(
                    mgmt_req(denied, &namespace, &cache)
                        .scrub("/mnt", None, true)
                        .await,
                    Err(BtrfsManagementError::Authority(_))
                ));
                assert!(matches!(
                    mgmt_req(denied, &namespace, &cache)
                        .quota_enable("/mnt")
                        .await,
                    Err(BtrfsManagementError::Authority(_))
                ));
                assert!(matches!(
                    mgmt_req(denied, &namespace, &cache)
                        .quota_status("/mnt")
                        .await,
                    Err(BtrfsManagementError::Authority(_))
                ));
                assert!(matches!(
                    mgmt_req(denied, &namespace, &cache)
                        .list_qgroups("/mnt")
                        .await,
                    Err(BtrfsManagementError::Authority(_))
                ));
            }

            let bal = mgmt_req(&mount_admin, &namespace, &cache)
                .balance(
                    "/mnt",
                    BalanceFilter {
                        data: true,
                        metadata: false,
                        system: false,
                        usage_max_percent: None,
                        limit: Some(1),
                    },
                )
                .await
                .expect("balance");
            assert!(bal.considered >= 1);
            let scrub_all = mgmt_req(&mount_admin, &namespace, &cache)
                .scrub("/mnt", None, true)
                .await
                .expect("scrub all");
            assert_eq!(scrub_all.uncorrectable_errors, 0);

            let qg = QgroupId::new(1, 7).unwrap();
            let root_qg = QgroupId::new(0, 5).unwrap();
            mgmt_req(&mount_admin, &namespace, &cache)
                .quota_enable("/mnt")
                .await
                .expect("quota enable");
            assert!(
                mgmt_req(&mount_admin, &namespace, &cache)
                    .quota_status("/mnt")
                    .await
                    .unwrap()
                    .enabled
            );
            mgmt_req(&mount_admin, &namespace, &cache)
                .qgroup_create("/mnt", qg)
                .await
                .expect("qgroup create");
            mgmt_req(&mount_admin, &namespace, &cache)
                .qgroup_assign("/mnt", root_qg, qg)
                .await
                .expect("qgroup assign");
            mgmt_req(&mount_admin, &namespace, &cache)
                .qgroup_limit(
                    "/mnt",
                    qg,
                    QgroupLimit {
                        max_referenced: Some(64 << 20),
                        max_exclusive: None,
                    },
                )
                .await
                .expect("qgroup limit");
            mgmt_req(&mount_admin, &namespace, &cache)
                .quota_rescan("/mnt")
                .await
                .expect("quota rescan");
            assert!(
                mgmt_req(&mount_admin, &namespace, &cache)
                    .list_qgroups("/mnt")
                    .await
                    .unwrap()
                    .iter()
                    .any(|g| g.id == qg)
            );
            mgmt_req(&mount_admin, &namespace, &cache)
                .qgroup_remove("/mnt", root_qg, qg)
                .await
                .expect("qgroup remove");
            mgmt_req(&mount_admin, &namespace, &cache)
                .qgroup_destroy("/mnt", qg)
                .await
                .expect("qgroup destroy");
            mgmt_req(&mount_admin, &namespace, &cache)
                .quota_disable("/mnt")
                .await
                .expect("quota disable");

            request_unmount(&root_auth, &namespace, "/mnt")
                .await
                .expect("unmount");
        };

        futures::future::join(
            alloc::boxed::Box::pin(client),
            alloc::boxed::Box::pin(service.run(idle_timer())),
        )
        .await;
    });
}

#[test]
fn unlinked_open_handle_retains_inode_until_final_drop_and_isolates_recreated_path() {
    let disk = MemoryDisk::holding_writable("btrfs-orphan", &empty_image());
    block_on(async {
        let (fs, service) = BtrfsFs::mount_writable(
            cache_over(&disk, 256, 1).disk(0),
            || DeviceId::new(100),
            write_options(1, None),
        )
        .await
        .expect("writable mount");
        let client = async move {
            let payer = crate::StoragePayer::for_test();
            let opened = fs
                .open(path("target"), OpenFlags::CREATE, 1_000_000_000, &payer)
                .await
                .expect("create target");
            let dup = opened.handle.clone();
            helios_hal::fs::write_handle_with(
                &fs,
                &opened.handle,
                WritePosition::At(0),
                b"original-data".len(),
                1_000_000_001,
                &payer,
                |at, dst| dst.copy_from_slice(&b"original-data"[at..at + dst.len()]),
            )
            .await
            .expect("write original");

            // Unlink while two handle clones are live.
            fs.unlink(path("target"), 1_000_000_002, &payer)
                .await
                .expect("unlink target");
            assert_eq!(fs.stat(path("target")).await, Err(FsError::NoEntry));
            let unlinked_meta = fs
                .stat_handle(&opened.handle)
                .await
                .expect("stat unlinked handle");
            assert_eq!(unlinked_meta.link_count, 0);
            assert_eq!(
                fs.read_handle_at(&opened.handle, 0, 64)
                    .await
                    .expect("read unlinked")
                    .as_ref(),
                b"original-data"
            );

            // Recreate a new file at the same path; the open handle still refers
            // to the unlinked inode.
            let recreated = fs
                .open(path("target"), OpenFlags::CREATE, 1_000_000_003, &payer)
                .await
                .expect("recreate target");
            assert_ne!(recreated.metadata.id, opened.metadata.id);
            helios_hal::fs::write_handle_with(
                &fs,
                &recreated.handle,
                WritePosition::At(0),
                b"replacement".len(),
                1_000_000_003,
                &payer,
                |at, dst| dst.copy_from_slice(&b"replacement"[at..at + dst.len()]),
            )
            .await
            .expect("write replacement");

            // Writes, truncate, times, and sync through the old handle affect
            // only the unlinked inode.
            helios_hal::fs::write_handle_with(
                &fs,
                &opened.handle,
                WritePosition::End,
                b"-more".len(),
                1_000_000_004,
                &payer,
                |at, dst| dst.copy_from_slice(&b"-more"[at..at + dst.len()]),
            )
            .await
            .expect("append to unlinked");
            assert_eq!(
                fs.read_handle_at(&opened.handle, 0, 64)
                    .await
                    .expect("read updated unlinked")
                    .as_ref(),
                b"original-data-more"
            );
            assert_eq!(
                fs.read_at(path("target"), 0, 64)
                    .await
                    .expect("read recreated")
                    .as_ref(),
                b"replacement"
            );
            fs.set_size_handle(&opened.handle, 8, 1_000_000_005, &payer)
                .await
                .expect("truncate unlinked");
            fs.set_times_handle(
                &opened.handle,
                Some(2_000_000_000),
                Some(3_000_000_000),
                1_000_000_006,
                &payer,
            )
            .await
            .expect("set_times unlinked");
            fs.sync_handle(&opened.handle).await.expect("sync unlinked");
            let after_meta = fs
                .stat_handle(&opened.handle)
                .await
                .expect("stat after mutations");
            assert_eq!(after_meta.link_count, 0);
            assert_eq!(after_meta.size, 8);
            assert_eq!(after_meta.modified_nanos, 3_000_000_000);

            // Previously named unlinked files cannot be re-linked.
            assert_eq!(
                fs.link_handle(&opened.handle, path("revived"), 1_000_000_007, &payer)
                    .await,
                Err(FsError::NoEntry)
            );

            // Dropping the first clone leaves the inode alive via `dup`.
            drop(opened);
            fs.sync(FsPath::ROOT).await.expect("sync with dup alive");
            assert_eq!(
                fs.read_handle_at(&dup, 0, 16)
                    .await
                    .expect("read via dup")
                    .as_ref(),
                b"original"
            );

            // Dropping the final clone schedules deletion, drained before sync.
            drop(dup);
            fs.sync(FsPath::ROOT).await.expect("sync after final drop");
            drop(recreated);
            fs.unmount().await;
        };
        futures::future::join(client, service.run(idle_timer())).await;
    });
}

#[test]
fn tmpfile_handle_supports_io_linking_exclusive_refusal_and_crash_cleanup() {
    let disk = MemoryDisk::holding_writable("btrfs-tmpfile", &empty_image());
    let leaked_inode_id = block_on(async {
        let (fs, service) = BtrfsFs::mount_writable(
            cache_over(&disk, 256, 1).disk(0),
            || DeviceId::new(100),
            write_options(1, None),
        )
        .await
        .expect("writable mount");
        let client = async move {
            let payer = crate::StoragePayer::for_test();
            // Linkable O_TMPFILE.
            let tmp = fs
                .open_tmpfile(FsPath::ROOT, false, 1_000_000_000, &payer)
                .await
                .expect("open_tmpfile");
            assert_eq!(tmp.metadata.link_count, 0);
            helios_hal::fs::write_handle_with(
                &fs,
                &tmp.handle,
                WritePosition::At(0),
                b"staged-via-tmpfile".len(),
                1_000_000_001,
                &payer,
                |at, dst| dst.copy_from_slice(&b"staged-via-tmpfile"[at..at + dst.len()]),
            )
            .await
            .expect("write tmpfile");
            fs.link_handle(&tmp.handle, path("linked"), 1_000_000_002, &payer)
                .await
                .expect("link tmpfile");
            assert_eq!(
                fs.stat_handle(&tmp.handle)
                    .await
                    .expect("stat linked")
                    .link_count,
                1
            );
            assert_eq!(
                fs.read_at(path("linked"), 0, 64)
                    .await
                    .expect("read linked")
                    .as_ref(),
                b"staged-via-tmpfile"
            );
            drop(tmp);

            // Exclusive O_TMPFILE refuses link_handle and cleans up on drop.
            let excl = fs
                .open_tmpfile(FsPath::ROOT, true, 1_000_000_003, &payer)
                .await
                .expect("open exclusive tmpfile");
            assert_eq!(
                fs.link_handle(&excl.handle, path("cannot-link"), 1_000_000_004, &payer)
                    .await,
                Err(FsError::NoEntry)
            );
            drop(excl);

            // Keep one O_TMPFILE open across unmount to simulate a crash with
            // an active orphan item committed on disk.
            let crashed = fs
                .open_tmpfile(FsPath::ROOT, false, 1_000_000_005, &payer)
                .await
                .expect("open crash tmpfile");
            helios_hal::fs::write_handle_with(
                &fs,
                &crashed.handle,
                WritePosition::At(0),
                b"lost".len(),
                1_000_000_006,
                &payer,
                |at, dst| dst.copy_from_slice(&b"lost"[at..at + dst.len()]),
            )
            .await
            .expect("write crash tmpfile");
            fs.unmount().await;
            let id = crashed.metadata.id;
            drop(crashed);
            id
        };
        let (id, ()) = futures::future::join(client, service.run(idle_timer())).await;
        id
    });

    // Writable remount cleans up the orphan left on disk while keeping `linked`.
    block_on(async {
        let (fs, service) = BtrfsFs::mount_writable(
            cache_over(&disk, 256, 1).disk(0),
            || DeviceId::new(100),
            write_options(1, None),
        )
        .await
        .expect("remount after crash");
        let client = async move {
            let linked = fs.stat(path("linked")).await.expect("linked survived");
            assert_ne!(linked.id, leaked_inode_id);
            assert_eq!(
                fs.read_at(path("linked"), 0, 64)
                    .await
                    .expect("read survived")
                    .as_ref(),
                b"staged-via-tmpfile"
            );
            fs.unmount().await;
        };
        futures::future::join(client, service.run(idle_timer())).await;
    });
}
