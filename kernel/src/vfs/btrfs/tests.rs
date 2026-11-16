extern crate std;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use std::io::{Read, Seek, SeekFrom};

use ferrosys::btrfs::{FormatOptions, SubvolumeRequest, format_to};
use ferrosys::{Metadata, Timestamp, TreeBuilder};
use futures_lite::future::block_on;
use helios_hal::fs::{
    BlockSerial, DeviceId, DirCookie, FileSystem, FsError, FsPath, NodeKind, OpenFlags,
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

fn path(value: &str) -> FsPath<'_> {
    FsPath::new(value).expect("normalized path")
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
    let mut cookie = DirCookie::new(0);
    loop {
        let entries = block_on(fs.read_dir(path(""), cookie, 2)).expect("directory page");
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
            block_on(fs.open(path(name), OpenFlags::empty(), 0)).map(|_| ()),
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
    let options = FormatOptions::new([0x51; 16], time)
        .subvolume(SubvolumeRequest::new(b"/@home".to_vec(), [0x52; 16]));
    let disk = MemoryDisk::holding("btrfs-test", &format_image(tree, options), false);
    let cache = cache_over(&disk, 256, 1);
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
        false,
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
