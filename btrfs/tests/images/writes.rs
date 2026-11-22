//! Uses only the public writable API against the independent image fixture.

use std::sync::Mutex;

use helios_btrfs::write::{
    AllocateMode, Attributes, CloneRange, Compressor, DEFAULT_MAX_INLINE, Name, WriteError, Writer,
    Zstd,
};
use helios_btrfs::{BlockSink, BlockSource, READ_ALIGNMENT, Timestamp};
use helios_hal::fs::RenameMode;
use helios_hal::io::IoResult;

use super::fixture::{SparseImage, base_image, block_on};

struct WritableImage(Mutex<SparseImage>);

impl BlockSource for WritableImage {
    fn size_bytes(&self) -> u64 {
        self.0.lock().unwrap().size_bytes()
    }

    async fn read_at(&self, offset: u64, output: &mut [u8]) -> IoResult<()> {
        self.0.lock().unwrap().read_bytes(offset, output);
        Ok(())
    }
}

impl BlockSink for WritableImage {
    async fn stage(&self, block: u64, bytes: &[u8; READ_ALIGNMENT as usize]) -> IoResult<()> {
        self.0
            .lock()
            .unwrap()
            .write_bytes(block * READ_ALIGNMENT, bytes);
        Ok(())
    }

    async fn commit(&self, block: u64, bytes: &[u8; READ_ALIGNMENT as usize]) -> IoResult<()> {
        self.stage(block, bytes).await
    }
}

fn assert_send<T: Send>(_: &T) {}

/// The images' root records carry valid UUIDs, so no commit asks for one.
fn no_uuid() -> [u8; 16] {
    panic!("the image's root records carry valid UUIDs")
}

type ImageWriter = Writer<WritableImage, fn() -> [u8; 16]>;

async fn mount(image: SparseImage) -> Result<ImageWriter, WriteError> {
    mount_compressing(image, Compressor::Plain).await
}

async fn mount_compressing(
    image: SparseImage,
    compressor: Compressor,
) -> Result<ImageWriter, WriteError> {
    Writer::mount(
        WritableImage(Mutex::new(image)),
        no_uuid as fn() -> [u8; 16],
        std::thread::available_parallelism().unwrap(),
        compressor,
        MOUNTED,
    )
    .await
}

/// When the images are mounted; none has a log for it to stamp.
const MOUNTED: Timestamp = Timestamp {
    seconds: 1_700_000_000,
    nanoseconds: 0,
};

/// A writer over the image `mkfs.btrfs` produces for the guest smoke (128 MiB,
/// default features) commits a created file and reads it back.
#[test]
#[ignore = "needs mkfs.btrfs from btrfs-progs; the Linux CI lane runs it with --run-ignored"]
fn writer_commits_over_a_mkfs_image() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("hello.txt"), b"hello btrfs\n").unwrap();
    let image = super::mkfs::mkfs_sized(tree.path(), 128 << 20, &[]);
    block_on(async {
        let mut writer = mount(image).await.unwrap();
        let mut tx = writer.join().await.unwrap();
        let root = tx.root().await.unwrap();
        let when = Timestamp {
            seconds: 1_700_000_100,
            nanoseconds: 0,
        };
        let file = tx
            .create_file(
                Name {
                    parent: &root,
                    bytes: b"written",
                },
                Attributes {
                    permissions: 0o644,
                    uid: 0,
                    gid: 0,
                    umask: 0,
                },
                when,
            )
            .await
            .unwrap();
        tx.write_file(&file, 0, b"guest bytes", when).await.unwrap();
        tx.commit().await.unwrap();
        let snapshot = writer.snapshot().unwrap();
        let written = snapshot.resolve(b"/written").await.unwrap();
        let mut output = [0; 11];
        snapshot.read(&written, 0, &mut output).await.unwrap();
        assert_eq!(&output, b"guest bytes");

        // The guest smoke's sequence: a directory, a file in it, then a hard
        // link to that file once both are committed.
        let mut tx = writer.join().await.unwrap();
        let root = tx.root().await.unwrap();
        let directory = tx
            .create_directory(
                Name {
                    parent: &root,
                    bytes: "目录-ディレクトリ-디렉터리".as_bytes(),
                },
                Attributes {
                    permissions: 0o755,
                    uid: 0,
                    gid: 0,
                    umask: 0,
                },
                when,
            )
            .await
            .unwrap();
        let original = tx
            .create_file(
                Name {
                    parent: &directory,
                    bytes: b"original",
                },
                Attributes {
                    permissions: 0o644,
                    uid: 0,
                    gid: 0,
                    umask: 0,
                },
                when,
            )
            .await
            .unwrap();
        tx.write_file(&original, 0, &[0x47; 8192], when)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let mut tx = writer.join().await.unwrap();
        let root = tx.root().await.unwrap();
        let directory = tx
            .lookup(&root, "目录-ディレクトリ-디렉터리".as_bytes())
            .await
            .unwrap()
            .unwrap();
        let original = tx.lookup(&directory, b"original").await.unwrap().unwrap();
        assert_eq!(
            tx.metadata(&original).await.unwrap().kind,
            helios_btrfs::FileKind::Regular
        );
        tx.hard_link(
            Name {
                parent: &directory,
                bytes: b"hard",
            },
            &original,
            when,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            writer
                .snapshot()
                .unwrap()
                .resolve("/目录-ディレクトリ-디렉터리/hard".as_bytes())
                .await
                .unwrap()
                .metadata()
                .nlink,
            2
        );
    });
}

#[test]
fn public_writer_preserves_snapshots_and_committed_handles() {
    block_on(async {
        let compressor = Compressor::Zstd(Box::new(Zstd::new(3).unwrap()));
        let mut writer = mount_compressing(base_image(), compressor).await.unwrap();
        let before = writer.snapshot().unwrap();
        let join = writer.join();
        assert_send(&join);
        let mut tx = join.await.unwrap();
        let root = tx.root().await.unwrap();
        let when = Timestamp {
            seconds: 1_700_000_100,
            nanoseconds: 123,
        };
        let attributes = |permissions| Attributes {
            permissions,
            uid: 1000,
            gid: 1000,
            umask: 0,
        };
        let directory = tx
            .create_directory(
                Name {
                    parent: &root,
                    bytes: "中文-日本語-한국어".as_bytes(),
                },
                attributes(0o755),
                when,
            )
            .await
            .unwrap();
        let name = |bytes| Name {
            parent: &directory,
            bytes,
        };
        let source = tx
            .create_file(name(b"source"), attributes(0o640), when)
            .await
            .unwrap();
        let data = vec![0x53; 32768];
        let write = tx.write_file(&source, 0, &data, when);
        assert_send(&write);
        let count = write.await.unwrap();
        assert_eq!(count, data.len());
        let destination = tx
            .create_file(name(b"clone"), attributes(0o640), when)
            .await
            .unwrap();
        tx.clone_range(
            CloneRange {
                source: &source,
                destination: &destination,
                source_offset: 0,
                destination_offset: 0,
                length: data.len() as u64,
            },
            when,
        )
        .await
        .unwrap();
        let looked_up = tx.lookup(&directory, b"clone").await.unwrap().unwrap();
        assert_eq!(looked_up.number(), destination.number());
        assert_eq!(
            tx.metadata(&looked_up).await.unwrap().size,
            data.len() as u64
        );
        let mut output = vec![0; data.len()];
        assert_eq!(
            tx.read_file(&looked_up, 0, &mut output).await.unwrap(),
            data.len()
        );
        assert_eq!(output, data);
        let commit = tx.commit();
        assert_send(&commit);
        commit.await.unwrap();
        assert!(
            before
                .lookup(
                    &before.root().await.unwrap(),
                    "中文-日本語-한국어".as_bytes()
                )
                .await
                .unwrap()
                .is_none()
        );
        let shared = writer.snapshot().unwrap();
        let old_source = shared
            .resolve("/中文-日本語-한국어/source".as_bytes())
            .await
            .unwrap();
        let mut tx = writer.join().await.unwrap();
        let _ = tx.write_file(&source, 0, b"changed", when).await.unwrap();
        tx.rename(name(b"clone"), name(b"kept"), RenameMode::Replace, when)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let current = writer.snapshot().unwrap();
        let kept = current
            .resolve("/中文-日本語-한국어/kept".as_bytes())
            .await
            .unwrap();
        current.read(&kept, 0, &mut output).await.unwrap();
        assert_eq!(output, data);
        current.read(&old_source, 0, &mut output).await.unwrap();
        assert_eq!(output, data);
        let source = current
            .resolve("/中文-日本語-한국어/source".as_bytes())
            .await
            .unwrap();
        current.read(&source, 0, &mut output).await.unwrap();
        assert_eq!(&output[..7], b"changed");
        assert_eq!(&output[7..], &data[7..]);
    });
}

/// `mkfs.btrfs -O quota` creates the quota tree. A writable mount refuses it,
/// since the writer keeps no qgroup counts, and a read-only mount still opens
/// the image. `-O squota` sets the simple-quota incompat bit, which neither
/// mount supports.
#[test]
#[ignore = "needs mkfs.btrfs from btrfs-progs; the Linux CI lane runs it with --run-ignored"]
fn writer_refuses_mkfs_images_with_quotas_and_the_reader_mounts_them() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("hello.txt"), b"hello btrfs\n").unwrap();

    let image = super::mkfs::mkfs_sized(tree.path(), 128 << 20, &["-O", "quota"]);
    super::fixture::mount(image.clone()).expect("a read-only mount ignores quotas");
    let refused = block_on(mount(image));
    assert!(
        matches!(refused, Err(WriteError::QuotaTreePresent)),
        "-O quota: refused with {:?}",
        refused.err()
    );

    let image = super::mkfs::mkfs_sized(tree.path(), 128 << 20, &["-O", "squota"]);
    let squota = |error: &helios_btrfs::Error| {
        matches!(
            error,
            helios_btrfs::Error::UnsupportedIncompat { name: "squota", .. }
        )
    };
    let read = super::fixture::mount(image.clone()).err();
    assert!(
        read.as_ref().is_some_and(squota),
        "-O squota read-only: {read:?}"
    );
    let write = block_on(mount(image)).err();
    assert!(
        matches!(&write, Some(WriteError::Read(error)) if squota(error)),
        "-O squota writable: {write:?}"
    );
}

/// The image a test keeps a handle on while the writer owns the other.
struct SharedImage(std::sync::Arc<WritableImage>);

impl BlockSource for SharedImage {
    fn size_bytes(&self) -> u64 {
        self.0.size_bytes()
    }

    async fn read_at(&self, offset: u64, output: &mut [u8]) -> IoResult<()> {
        self.0.read_at(offset, output).await
    }
}

impl BlockSink for SharedImage {
    async fn stage(&self, block: u64, bytes: &[u8; READ_ALIGNMENT as usize]) -> IoResult<()> {
        self.0.stage(block, bytes).await
    }

    async fn commit(&self, block: u64, bytes: &[u8; READ_ALIGNMENT as usize]) -> IoResult<()> {
        self.0.commit(block, bytes).await
    }
}

/// Runs `sudo` without a password prompt and returns stdout; the nodes and
/// attributes below need privileges the test user lacks.
fn sudo_output(args: &[&str]) -> Vec<u8> {
    let output = std::process::Command::new("sudo")
        .arg("-n")
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("running sudo {args:?}: {error}"));
    assert!(
        output.status.success(),
        "sudo {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn sudo(args: &[&str]) {
    let _ = sudo_output(args);
}

fn hex_value(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(2 + bytes.len() * 2);
    encoded.push_str("0x");
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").unwrap();
    }
    encoded
}

fn load_sparse_image(path: &std::path::Path, bytes: u64) -> SparseImage {
    use std::io::Read as _;
    let mut image = SparseImage::new(bytes);
    let mut file = std::fs::File::open(path).unwrap();
    let mut block = vec![0; 1 << 16];
    let mut offset = 0;
    loop {
        let count = file.read(&mut block).unwrap();
        if count == 0 {
            break;
        }
        if block[..count].iter().any(|byte| *byte != 0) {
            image.write_bytes(offset, &block[..count]);
        }
        offset += count as u64;
    }
    image
}

/// What a file's metadata and extended attributes say, for comparing views.
#[derive(Debug, PartialEq)]
struct Authority {
    kind: helios_btrfs::FileKind,
    permissions: u32,
    uid: u32,
    gid: u32,
    rdev: helios_btrfs::DeviceNumber,
    nlink: u32,
    size: u64,
    ctime: Timestamp,
    mtime: Timestamp,
    capability: Option<Vec<u8>>,
    acl: Option<Vec<u8>>,
    trusted: Option<Vec<u8>>,
    security: Option<Vec<u8>>,
}

/// A Linux image carries a setuid file, a character device node, a file
/// capability (`security.capability`), a POSIX access ACL
/// (`system.posix_acl_access`), a `trusted.*` attribute and a `security.*`
/// label (lexoliu/helios#1037). Mounted writable, the writer keeps all of
/// them intact through unrelated writes, `btrfs check` is clean, and Linux
/// reads them back identically.
#[test]
#[ignore = "needs mkfs.btrfs and btrfs check from btrfs-progs, passwordless sudo, a Linux kernel with btrfs, and setfattr/getfattr; the Linux CI lane runs it with --run-ignored"]
fn linux_authority_survives_unrelated_writes() {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    use helios_btrfs::DeviceNumber;

    const IMAGE_BYTES: u64 = 128 << 20;
    const NAMES: [&str; 3] = ["中文新文件", "日本語の新しいファイル", "한국어새파일"];
    const LABEL: &[u8] = b"system_u:object_r:helios_t:s0";
    const TRUSTED: &[u8] = b"private-mount-authority";
    // `vfs_cap_data` (`VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE`,
    // `CAP_NET_RAW` permitted) from `include/uapi/linux/capability.h`.
    const VFS_CAP_V2: &[u8] = &[
        0x01, 0x00, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    // Canonical 5-entry `posix_acl_xattr_header` v2 (`u::rwx,u:1000:r-x,g::r-x,m::r-x,o::r-x`)
    // from `include/uapi/linux/posix_acl_xattr.h`.
    const POSIX_ACL_V2: &[u8] = &[
        0x02, 0x00, 0x00, 0x00, // version 2
        0x01, 0x00, 0x07, 0x00, 0xff, 0xff, 0xff, 0xff, // ACL_USER_OBJ rwx
        0x02, 0x00, 0x05, 0x00, 0xe8, 0x03, 0x00, 0x00, // ACL_USER 1000 r-x
        0x04, 0x00, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff, // ACL_GROUP_OBJ r-x
        0x10, 0x00, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff, // ACL_MASK r-x
        0x20, 0x00, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff, // ACL_OTHER r-x
    ];

    let seeded = tempfile::NamedTempFile::new().unwrap();
    seeded.as_file().set_len(IMAGE_BYTES).unwrap();
    let mkfs = std::process::Command::new("mkfs.btrfs")
        .args(["-q", "-f"])
        .arg(seeded.path())
        .output()
        .expect("btrfs-progs must be installed");
    assert!(
        mkfs.status.success(),
        "mkfs.btrfs failed: {}",
        String::from_utf8_lossy(&mkfs.stderr)
    );

    let mount_dir = tempfile::tempdir().unwrap();
    let point = mount_dir.path().to_str().unwrap().to_owned();
    sudo(&[
        "mount",
        "-t",
        "btrfs",
        "-o",
        "loop,acl",
        seeded.path().to_str().unwrap(),
        &point,
    ]);
    let populated = (|| -> std::io::Result<()> {
        sudo(&["chmod", "0777", &point]);
        let path = |name: &str| mount_dir.path().join(name);
        let utf8 = |name: &str| path(name).to_str().unwrap().to_owned();
        std::fs::write(path("suid"), b"#!/bin/sh\n")?;
        sudo(&[
            "setfattr",
            "-n",
            "system.posix_acl_access",
            "-v",
            &hex_value(POSIX_ACL_V2),
            &utf8("suid"),
        ]);
        std::fs::set_permissions(path("suid"), std::fs::Permissions::from_mode(0o4755))?;
        sudo(&[
            "setfattr",
            "-n",
            "security.capability",
            "-v",
            &hex_value(VFS_CAP_V2),
            &utf8("suid"),
        ]);
        // /dev/null's numbers; the node is never opened.
        sudo(&["mknod", &utf8("中文设备"), "c", "1", "3"]);
        std::fs::write(path("日本語のファイル"), "こんにちは\n")?;
        std::fs::write(path("한국어파일"), "안녕하세요\n")?;
        std::fs::write(path("doomed"), b"unlinked below")?;
        std::fs::write(path("moved"), b"renamed below")?;
        for name in ["suid", "中文设备"] {
            sudo(&[
                "setfattr",
                "-h",
                "-n",
                "security.helios",
                "-v",
                &hex_value(LABEL),
                &utf8(name),
            ]);
            sudo(&[
                "setfattr",
                "-h",
                "-n",
                "trusted.helios",
                "-v",
                &hex_value(TRUSTED),
                &utf8(name),
            ]);
        }
        Ok(())
    })();
    sudo(&["umount", &point]);
    populated.unwrap();

    let image = load_sparse_image(seeded.path(), IMAGE_BYTES);
    let shared = std::sync::Arc::new(WritableImage(Mutex::new(image)));
    let null = DeviceNumber::new(1, 3).unwrap();

    block_on(async {
        let mut writer = Writer::mount(
            SharedImage(shared.clone()),
            no_uuid as fn() -> [u8; 16],
            std::thread::available_parallelism().unwrap(),
            Compressor::Plain,
            MOUNTED,
        )
        .await
        .unwrap();
        let authority = async |writer: &Writer<SharedImage, fn() -> [u8; 16]>, name: &str| {
            let view = writer.snapshot().unwrap();
            let inode = view.resolve(format!("/{name}").as_bytes()).await.unwrap();
            let metadata = *inode.metadata();
            let read_attr = async |attr: &[u8]| {
                let mut value = [0; 128];
                view.xattr(&inode, attr, &mut value)
                    .await
                    .unwrap()
                    .map(|length| value[..length].to_vec())
            };
            Authority {
                kind: metadata.kind,
                permissions: metadata.permissions,
                uid: metadata.uid,
                gid: metadata.gid,
                rdev: metadata.rdev,
                nlink: metadata.nlink,
                size: metadata.size,
                ctime: metadata.ctime,
                mtime: metadata.mtime,
                capability: read_attr(b"security.capability").await,
                acl: read_attr(b"system.posix_acl_access").await,
                trusted: read_attr(b"trusted.helios").await,
                security: read_attr(b"security.helios").await,
            }
        };
        let suid = authority(&writer, "suid").await;
        let device = authority(&writer, "中文设备").await;
        assert_eq!(suid.permissions, 0o4755);
        assert_eq!(suid.capability.as_deref(), Some(VFS_CAP_V2));
        assert_eq!(suid.acl.as_deref(), Some(POSIX_ACL_V2));
        assert_eq!(suid.trusted.as_deref(), Some(TRUSTED));
        assert_eq!(suid.security.as_deref(), Some(LABEL));
        assert_eq!(device.kind, helios_btrfs::FileKind::CharDevice);
        assert_eq!(device.rdev, null);
        assert_eq!(device.trusted.as_deref(), Some(TRUSTED));
        assert_eq!(device.security.as_deref(), Some(LABEL));

        // Create, write, rename and unlink elsewhere.
        let when = Timestamp {
            seconds: 1_800_000_000,
            nanoseconds: 0,
        };
        let mut tx = writer.join().await.unwrap();
        let root = tx.root().await.unwrap();
        let at = |parent, bytes| Name { parent, bytes };
        let directory = tx
            .create_directory(
                at(&root, "目录-ディレクトリ-디렉터리".as_bytes()),
                Attributes {
                    permissions: 0o755,
                    uid: 0,
                    gid: 0,
                    umask: 0,
                },
                when,
            )
            .await
            .unwrap();
        for name in NAMES {
            let file = tx
                .create_file(
                    at(&directory, name.as_bytes()),
                    Attributes {
                        permissions: 0o644,
                        uid: 0,
                        gid: 0,
                        umask: 0,
                    },
                    when,
                )
                .await
                .unwrap();
            tx.write_file(&file, 0, name.as_bytes(), when)
                .await
                .unwrap();
        }
        let (source, destination) = (at(&root, b"moved"), at(&directory, b"moved"));
        tx.rename(source, destination, RenameMode::Replace, when)
            .await
            .unwrap();
        tx.unlink_name(at(&root, b"doomed"), when).await.unwrap();
        tx.commit().await.unwrap();

        assert_eq!(authority(&writer, "suid").await, suid);
        assert_eq!(authority(&writer, "中文设备").await, device);
        let view = writer.snapshot().unwrap();
        assert!(view.resolve(b"/doomed").await.is_err());
        view.resolve("/目录-ディレクトリ-디렉터리/moved".as_bytes())
            .await
            .unwrap();
    });

    let checked = btrfs_check(&shared);
    let readback_dir = tempfile::tempdir().unwrap();
    let readback_point = readback_dir.path().to_str().unwrap().to_owned();
    sudo(&[
        "mount",
        "-t",
        "btrfs",
        "-o",
        "loop,ro,acl",
        checked.path().to_str().unwrap(),
        &readback_point,
    ]);
    let linux_readback = (|| -> std::io::Result<_> {
        let suid_path = readback_dir.path().join("suid");
        let dev_path = readback_dir.path().join("中文设备");
        let suid_meta = std::fs::symlink_metadata(&suid_path)?;
        let dev_meta = std::fs::symlink_metadata(&dev_path)?;
        let get_attr = |target: &std::path::Path, attr: &str| {
            sudo_output(&[
                "getfattr",
                "-h",
                "--absolute-names",
                "--only-values",
                "-n",
                attr,
                target.to_str().unwrap(),
            ])
        };
        Ok((
            suid_meta.mode(),
            get_attr(&suid_path, "security.capability"),
            get_attr(&suid_path, "system.posix_acl_access"),
            get_attr(&suid_path, "trusted.helios"),
            get_attr(&suid_path, "security.helios"),
            dev_meta.file_type().is_char_device(),
            dev_meta.rdev(),
            get_attr(&dev_path, "trusted.helios"),
            get_attr(&dev_path, "security.helios"),
        ))
    })();
    sudo(&["umount", &readback_point]);
    let (
        suid_mode,
        suid_cap,
        suid_acl,
        suid_trusted,
        suid_sec,
        dev_is_chr,
        dev_rdev,
        dev_trusted,
        dev_sec,
    ) = linux_readback.unwrap();
    assert_eq!(suid_mode, 0o104_755);
    assert_eq!(suid_cap, VFS_CAP_V2);
    assert_eq!(suid_acl, POSIX_ACL_V2);
    assert_eq!(suid_trusted, TRUSTED);
    assert_eq!(suid_sec, LABEL);
    assert!(dev_is_chr);
    assert_eq!(dev_rdev, u64::from(null.encode()));
    assert_eq!(dev_trusted, TRUSTED);
    assert_eq!(dev_sec, LABEL);
}

/// Copies the image to a file, which `btrfs check` must find clean.
fn btrfs_check(image: &WritableImage) -> tempfile::NamedTempFile {
    check_sparse_image(&image.0)
}

fn assert_btrfs_check(shared: &Mutex<SparseImage>) {
    let _ = check_sparse_image(shared);
}

fn check_sparse_image(shared: &Mutex<SparseImage>) -> tempfile::NamedTempFile {
    let scratch = tempfile::NamedTempFile::new().unwrap();
    {
        use std::io::Seek;
        let mut image = shared.lock().unwrap();
        image.seek(std::io::SeekFrom::Start(0)).unwrap();
        std::io::copy(&mut *image, &mut scratch.reopen().unwrap()).unwrap();
    }
    let check = std::process::Command::new("btrfs")
        .args(["check", "--readonly"])
        .arg(scratch.path())
        .output()
        .expect("btrfs-progs must be installed");
    assert!(
        check.status.success(),
        "btrfs check\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
    scratch
}

/// Helios sets and removes the Unix authority Linux stores (lexoliu/helios#1037):
/// set-id and sticky bits by chmod and at creation, device nodes, FIFOs and
/// sockets by mknod, and the set-id bits a chown drops. `btrfs check` is
/// clean, and Linux's btrfs mounts the image and reads back what Helios
/// wrote.
#[test]
#[ignore = "needs mkfs.btrfs and btrfs check from btrfs-progs, passwordless sudo, and a Linux kernel with btrfs to loop-mount; the Linux CI lane runs it with --run-ignored"]
fn linux_reads_back_the_authority_helios_sets() {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    use helios_btrfs::DeviceNumber;
    use helios_btrfs::write::Special;

    const NAMES: [&str; 3] = ["中文", "日本語", "한국어"];
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("chmod-me"), b"#!/bin/sh\n").unwrap();
    let initial = std::fs::metadata(tree.path().join("chmod-me")).unwrap();
    let (initial_uid, initial_gid) = (initial.uid(), initial.gid());
    std::fs::write(tree.path().join("chown-me"), b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(
        tree.path().join("chown-me"),
        std::os::unix::fs::PermissionsExt::from_mode(0o6755),
    )
    .unwrap();
    let image = super::mkfs::mkfs_sized(tree.path(), 128 << 20, &[]);
    let shared = std::sync::Arc::new(WritableImage(Mutex::new(image)));
    let null = DeviceNumber::new(1, 3).unwrap();
    let wide = DeviceNumber::new(259, 0x1_2345).unwrap();
    let when = Timestamp {
        seconds: 1_800_000_000,
        nanoseconds: 0,
    };
    // What Linux must read back: name, file type and permission bits of
    // `st_mode`, owner, group and `st_rdev`.
    let mut expected: Vec<(String, u32, u32, u32, u64)> = Vec::new();
    block_on(async {
        let mut writer = Writer::mount(
            SharedImage(shared.clone()),
            no_uuid as fn() -> [u8; 16],
            std::thread::available_parallelism().unwrap(),
            Compressor::Plain,
            MOUNTED,
        )
        .await
        .unwrap();
        let mut tx = writer.join().await.unwrap();
        let root = tx.root().await.unwrap();
        fn at<'a>(parent: &'a helios_btrfs::write::InodeHandle, name: &'a str) -> Name<'a> {
            Name {
                parent,
                bytes: name.as_bytes(),
            }
        }
        let chmod = tx.lookup(&root, b"chmod-me").await.unwrap().unwrap();
        tx.set_permissions(&chmod, 0o7755, when).await.unwrap();
        expected.push((
            "chmod-me".to_owned(),
            0o107_755,
            initial_uid,
            initial_gid,
            0,
        ));
        let chown = tx.lookup(&root, b"chown-me").await.unwrap().unwrap();
        tx.set_owner(&chown, Some(1000), Some(1000), when)
            .await
            .unwrap();
        expected.push(("chown-me".to_owned(), 0o100_755, 1000, 1000, 0));
        for name in NAMES {
            let owner = |permissions| Attributes {
                permissions,
                uid: 1000,
                gid: 100,
                umask: 0,
            };
            let file = format!("suid-{name}");
            tx.create_file(at(&root, &file), owner(0o4755), when)
                .await
                .unwrap();
            expected.push((file, 0o104_755, 1000, 100, 0));
            let directory = format!("sgid-{name}");
            tx.create_directory(at(&root, &directory), owner(0o3775), when)
                .await
                .unwrap();
            expected.push((directory, 0o043_775, 1000, 100, 0));
            for (prefix, special, mode, rdev) in [
                ("chr", Special::CharDevice(null), 0o020_660, null),
                ("blk", Special::BlockDevice(wide), 0o060_660, wide),
                ("fifo", Special::Fifo, 0o010_660, DeviceNumber::default()),
                ("sock", Special::Socket, 0o140_660, DeviceNumber::default()),
            ] {
                let node = format!("{prefix}-{name}");
                tx.create_special(at(&root, &node), special, owner(0o660), when)
                    .await
                    .unwrap();
                expected.push((node, mode, 1000, 100, u64::from(rdev.encode())));
            }
            // Made and removed again, as `rm` takes a node away.
            let gone = format!("gone-{name}");
            let device = Special::CharDevice(null);
            tx.create_special(at(&root, &gone), device, owner(0o600), when)
                .await
                .unwrap();
            tx.unlink_name(at(&root, &gone), when).await.unwrap();
        }
        tx.commit().await.unwrap();
    });

    let image = btrfs_check(&shared);
    let mount = tempfile::tempdir().unwrap();
    let point = mount.path().to_str().unwrap().to_owned();
    sudo(&[
        "mount",
        "-t",
        "btrfs",
        "-o",
        "loop,ro",
        image.path().to_str().unwrap(),
        &point,
    ]);
    // Read everything before asserting anything, so the image is always
    // unmounted.
    let read = (|| {
        let mut seen = Vec::new();
        for (name, ..) in &expected {
            let metadata = std::fs::symlink_metadata(mount.path().join(name))?;
            seen.push((
                name.clone(),
                metadata.mode(),
                metadata.uid(),
                metadata.gid(),
                metadata.rdev(),
            ));
        }
        let mut removed = Vec::new();
        for name in NAMES {
            removed.push(!mount.path().join(format!("gone-{name}")).exists());
            let fifo = std::fs::symlink_metadata(mount.path().join(format!("fifo-{name}")))?;
            removed.push(fifo.file_type().is_fifo());
        }
        std::io::Result::Ok((seen, removed))
    })();
    sudo(&["umount", &point]);
    let (seen, checks) = read.unwrap();
    assert_eq!(seen, expected);
    assert!(checks.into_iter().all(|held| held));
}

/// 4 KiB chunked writes (as issued by WASI preview1's component adapter for
/// CPython) over a `mkfs.btrfs` image form 128 KiB zstd extents under
/// `compress=zstd:3` and a single extent when uncompressed, and pass
/// `btrfs check` and `btrfs inspect-internal dump-tree` (#1052, #1060).
#[test]
#[ignore = "needs mkfs.btrfs and btrfs check from btrfs-progs; the Linux CI lane runs it with --run-ignored"]
fn chunked_writes_form_zstd_and_plain_extents_over_mkfs_image() {
    const CHUNK: usize = 4096;
    let payload = "compressible line of text, 中文 日本語 한국어\n"
        .repeat(8000)
        .into_bytes();
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("hello.txt"), b"hello btrfs\n").unwrap();

    for (zstd, compressor) in [
        (true, Compressor::Zstd(Box::new(Zstd::new(3).unwrap()))),
        (false, Compressor::Plain),
    ] {
        let image = super::mkfs::mkfs_sized(tree.path(), 128 << 20, &[]);
        let shared = std::sync::Arc::new(WritableImage(Mutex::new(image)));
        block_on(async {
            let mut writer = Writer::mount(
                SharedImage(shared.clone()),
                no_uuid as fn() -> [u8; 16],
                std::thread::available_parallelism().unwrap(),
                compressor,
                MOUNTED,
            )
            .await
            .unwrap();
            let when = Timestamp {
                seconds: 1_800_000_100,
                nanoseconds: 0,
            };
            let mut tx = writer.join().await.unwrap();
            let root = tx.root().await.unwrap();
            let file = tx
                .create_file(
                    Name {
                        parent: &root,
                        bytes: b"compressible",
                    },
                    Attributes {
                        permissions: 0o644,
                        uid: 0,
                        gid: 0,
                        umask: 0,
                    },
                    when,
                )
                .await
                .unwrap();
            for (index, chunk) in payload.chunks(CHUNK).enumerate() {
                assert_eq!(
                    tx.write_file(&file, (index * CHUNK) as u64, chunk, when)
                        .await
                        .unwrap(),
                    chunk.len()
                );
            }
            tx.commit().await.unwrap();
            let view = writer.snapshot().unwrap();
            let inode = view.resolve(b"/compressible").await.unwrap();
            let mut readback = vec![0; payload.len()];
            assert_eq!(
                view.read(&inode, 0, &mut readback).await.unwrap(),
                payload.len()
            );
            assert_eq!(readback, payload);
        });

        let scratch = tempfile::NamedTempFile::new().unwrap();
        {
            use std::io::Seek;
            let mut image = shared.0.lock().unwrap();
            image.seek(std::io::SeekFrom::Start(0)).unwrap();
            std::io::copy(&mut *image, &mut scratch.reopen().unwrap()).unwrap();
        }
        let check = std::process::Command::new("btrfs")
            .args(["check", "--readonly"])
            .arg(scratch.path())
            .output()
            .expect("btrfs-progs must be installed");
        assert!(
            check.status.success(),
            "btrfs check (zstd={zstd})\n{}\n{}",
            String::from_utf8_lossy(&check.stdout),
            String::from_utf8_lossy(&check.stderr)
        );
        let dump = std::process::Command::new("btrfs")
            .args(["inspect-internal", "dump-tree", "-t", "5"])
            .arg(scratch.path())
            .output()
            .expect("btrfs-progs must be installed");
        assert!(dump.status.success());
        let text = String::from_utf8_lossy(&dump.stdout);
        if zstd {
            assert!(
                text.contains("extent compression 3 (zstd)"),
                "expected zstd extents in fs-tree dump:\n{text}"
            );
        } else {
            assert!(
                !text.contains("extent compression 3 (zstd)"),
                "plain mount must not write zstd extents:\n{text}"
            );
        }
    }
}

/// Names that hash to one XATTR_ITEM key, found by search (CRC32C `0x4e84071b`).
const COLLIDING: [&str; 2] = ["user.k1371838", "user.k2000402"];

/// A version 2 `security.capability` value (revision, then four zero words).
const CAPABILITY: [u8; 20] = [1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// Runs a tool and returns its standard output, failing the test when it
/// fails.
fn run(program: &str, args: &[&std::ffi::OsStr]) -> Vec<u8> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("running {program}: {error}"));
    assert!(
        output.status.success(),
        "{program} {args:?}: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn os(text: &str) -> &std::ffi::OsStr {
    std::ffi::OsStr::new(text)
}

/// A loop mount of an image, unmounted when dropped.
struct Mounted(std::path::PathBuf);

impl Drop for Mounted {
    fn drop(&mut self) {
        let _ = std::process::Command::new("sudo")
            .arg("umount")
            .arg(&self.0)
            .status();
    }
}

/// Every attribute `helios_btrfs` reads from `path`.
fn helios_attributes<S: BlockSource>(
    fs: &helios_btrfs::Filesystem<S>,
    path: &str,
) -> std::collections::BTreeMap<Vec<u8>, Vec<u8>> {
    block_on(async {
        let inode = fs.resolve(path.as_bytes()).await.unwrap();
        let mut names = Vec::new();
        fs.list_xattrs(&inode, |name| {
            names.push(name.to_vec());
            std::ops::ControlFlow::Continue(())
        })
        .await
        .unwrap();
        let mut found = std::collections::BTreeMap::new();
        for name in names {
            let mut value = vec![0; 70_000];
            let length = fs.xattr(&inode, &name, &mut value).await.unwrap().unwrap();
            value.truncate(length);
            found.insert(name, value);
        }
        found
    })
}

/// A version 2 `security.capability` granting `CAP_NET_RAW` (bit 13).
const NET_RAW: [u8; 20] = [
    1, 0, 0, 2, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// ACL entry tags (`include/uapi/linux/posix_acl.h`) and `ACL_UNDEFINED_ID`.
const ACL_USER_OBJ: u16 = 0x01;
const ACL_USER: u16 = 0x02;
const ACL_GROUP_OBJ: u16 = 0x04;
const ACL_GROUP: u16 = 0x08;
const ACL_MASK: u16 = 0x10;
const ACL_OTHER: u16 = 0x20;
const NO_ID: u32 = u32::MAX;

/// An ACL in the encoding `posix_acl_to_xattr` produces and `setfacl` hands
/// to `setxattr(2)`.
fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
    let mut bytes = 2u32.to_le_bytes().to_vec();
    for (tag, perm, id) in entries {
        bytes.extend_from_slice(&tag.to_le_bytes());
        bytes.extend_from_slice(&perm.to_le_bytes());
        bytes.extend_from_slice(&id.to_le_bytes());
    }
    bytes
}

/// `setfattr -v`'s hexadecimal form of `bytes`.
fn hex(bytes: &[u8]) -> String {
    let digits: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("0x{digits}")
}

/// Writes `image` out as an image file at `path`.
fn save(image: &SparseImage, path: &std::path::Path) {
    use std::io::Write;
    let mut out = std::fs::File::create(path).unwrap();
    let mut block = vec![0; 1 << 20];
    let mut offset = 0;
    let size = image.size_bytes();
    while offset < size {
        let length = block.len().min((size - offset) as usize);
        image.read_bytes(offset, &mut block[..length]);
        out.write_all(&block[..length]).unwrap();
        offset += length as u64;
    }
}

/// Loop-mounts the image file at `path` on a new directory beside it.
fn loop_mount(path: &std::path::Path, options: &str) -> Mounted {
    let mount = path.with_extension("mount");
    std::fs::create_dir(&mount).unwrap();
    run(
        "sudo",
        &[
            os("mount"),
            os("-o"),
            os(&format!("loop,{options}")),
            path.as_os_str(),
            mount.as_os_str(),
        ],
    );
    Mounted(mount)
}

/// The attributes Linux and Helios write, in every namespace Linux's btrfs
/// stores, in both directions, and `btrfs check` over the result. Linux's
/// own btrfs writes the `security.capability`, the `trusted.*` value and
/// the ACLs, through the `setxattr(2)` path `setfacl` takes. Needs
/// btrfs-progs, sudo (for `mount`, `umount` and the privileged namespaces)
/// and `setfattr`/`getfattr` from the attr package.
#[test]
#[ignore = "needs btrfs-progs, sudo and attr; the Linux CI lane runs it with --run-ignored"]
fn attributes_cross_between_linux_and_helios() {
    use helios_btrfs::write::XattrMode;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    // `setfacl -m u:1000:rw-,g:1001:r--` on a 0644 file: the mask is the
    // union of the group class, and the mode's group bits become the mask.
    let linux_access = acl(&[
        (ACL_USER_OBJ, 6, NO_ID),
        (ACL_USER, 6, 1000),
        (ACL_GROUP_OBJ, 4, NO_ID),
        (ACL_GROUP, 4, 1001),
        (ACL_MASK, 6, NO_ID),
        (ACL_OTHER, 4, NO_ID),
    ]);
    // `setfacl -d -m u:1000:rwx` on a 0755 directory.
    let linux_default = acl(&[
        (ACL_USER_OBJ, 7, NO_ID),
        (ACL_USER, 7, 1000),
        (ACL_GROUP_OBJ, 5, NO_ID),
        (ACL_MASK, 7, NO_ID),
        (ACL_OTHER, 5, NO_ID),
    ]);

    // A directory on the build's own disk: tmpfs keeps no user.* attributes
    // before Linux 6.6.
    let source = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let file = source.path().join("file");
    let directory = source.path().join("dir");
    std::fs::write(&file, b"data").unwrap();
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&file, PermissionsExt::from_mode(0o644)).unwrap();
    std::fs::set_permissions(&directory, PermissionsExt::from_mode(0o755)).unwrap();
    let setfattr = |path: &std::path::Path, name: &str, value: &str| {
        run(
            "setfattr",
            &[os("-n"), os(name), os("-v"), os(value), path.as_os_str()],
        );
    };
    setfattr(&file, "user.中文", "Linux 写的");
    setfattr(&file, "user.한국어", "리눅스가 씀");
    setfattr(&directory, "user.日本語", "Linux ディレクトリ");
    let image = super::mkfs::mkfs_sized(source.path(), 128 << 20, &[]);

    // Linux's btrfs writes the privileged namespaces and the ACLs.
    let scratch = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let path = scratch.path().join("image");
    save(&image, &path);
    {
        let mounted = loop_mount(&path, "rw");
        let sudo_setfattr = |relative: &str, name: &str, value: &str| {
            run(
                "sudo",
                &[
                    os("setfattr"),
                    os("-n"),
                    os(name),
                    os("-v"),
                    os(value),
                    mounted.0.join(relative).as_os_str(),
                ],
            );
        };
        sudo_setfattr("file", "security.capability", &hex(&CAPABILITY));
        sudo_setfattr("file", "trusted.中文", "Linux 信任的值");
        sudo_setfattr("file", "system.posix_acl_access", &hex(&linux_access));
        sudo_setfattr("dir", "system.posix_acl_default", &hex(&linux_default));
    }
    let image = super::mkfs::load_image(&path, 128 << 20);
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(path.with_extension("mount")).unwrap();

    // Helios reads what Linux wrote.
    let linux = super::fixture::mount(image.clone()).expect("mounts");
    assert_eq!(
        helios_attributes(&linux, "/file"),
        BTreeMap::from([
            (
                "user.中文".as_bytes().to_vec(),
                "Linux 写的".as_bytes().to_vec()
            ),
            (
                "user.한국어".as_bytes().to_vec(),
                "리눅스가 씀".as_bytes().to_vec(),
            ),
            (b"security.capability".to_vec(), CAPABILITY.to_vec()),
            (
                "trusted.中文".as_bytes().to_vec(),
                "Linux 信任的值".as_bytes().to_vec()
            ),
            (b"system.posix_acl_access".to_vec(), linux_access.clone()),
        ])
    );
    assert_eq!(
        helios_attributes(&linux, "/dir"),
        BTreeMap::from([
            (
                "user.日本語".as_bytes().to_vec(),
                "Linux ディレクトリ".as_bytes().to_vec()
            ),
            (b"system.posix_acl_default".to_vec(), linux_default.clone()),
        ])
    );
    let linux_file = block_on(linux.resolve(b"/file")).unwrap();
    assert_eq!(linux_file.metadata().permissions, 0o664);

    // `u::rw-,u:1000:r--,g::r--,m::r--,o::---`, which makes the mode 0640.
    let helios_access = acl(&[
        (ACL_USER_OBJ, 6, NO_ID),
        (ACL_USER, 4, 1000),
        (ACL_GROUP_OBJ, 4, NO_ID),
        (ACL_MASK, 4, NO_ID),
        (ACL_OTHER, 0, NO_ID),
    ]);
    let helios_default = acl(&[
        (ACL_USER_OBJ, 7, NO_ID),
        (ACL_GROUP_OBJ, 5, NO_ID),
        (ACL_GROUP, 7, 1001),
        (ACL_MASK, 7, NO_ID),
        (ACL_OTHER, 0, NO_ID),
    ]);

    // Helios replaces, creates and removes beside them.
    let shared = std::sync::Arc::new(WritableImage(Mutex::new(image)));
    let when = Timestamp {
        seconds: 1_700_000_100,
        nanoseconds: 0,
    };
    block_on(async {
        let mut writer = Writer::mount(
            SharedImage(shared.clone()),
            no_uuid as fn() -> [u8; 16],
            std::thread::available_parallelism().unwrap(),
            Compressor::Plain,
            MOUNTED,
        )
        .await
        .unwrap();
        let mut tx = writer.join().await.unwrap();
        let root = tx.root().await.unwrap();
        let file = tx.lookup(&root, b"file").await.unwrap().unwrap();
        let directory = tx.lookup(&root, b"dir").await.unwrap().unwrap();
        tx.set_xattr(
            &file,
            "user.中文".as_bytes(),
            "Helios が書いた".as_bytes(),
            XattrMode::Replace,
            when,
        )
        .await
        .unwrap();
        tx.set_xattr(
            &file,
            "user.日本語".as_bytes(),
            "ヘリオス".as_bytes(),
            XattrMode::Create,
            when,
        )
        .await
        .unwrap();
        for (index, name) in COLLIDING.iter().enumerate() {
            tx.set_xattr(
                &file,
                name.as_bytes(),
                format!("collision {index}").as_bytes(),
                XattrMode::Create,
                when,
            )
            .await
            .unwrap();
        }
        tx.remove_xattr(&file, "user.한국어".as_bytes(), when)
            .await
            .unwrap();
        tx.set_xattr(
            &directory,
            "user.目录".as_bytes(),
            "헬리오스".as_bytes(),
            XattrMode::Set,
            when,
        )
        .await
        .unwrap();
        // Every namespace Linux's btrfs stores is Helios's to write too.
        tx.set_xattr(
            &file,
            b"security.capability",
            &NET_RAW,
            XattrMode::Replace,
            when,
        )
        .await
        .unwrap();
        tx.set_xattr(
            &file,
            "trusted.日本語".as_bytes(),
            "ヘリオスの信頼".as_bytes(),
            XattrMode::Create,
            when,
        )
        .await
        .unwrap();
        tx.remove_xattr(&file, "trusted.中文".as_bytes(), when)
            .await
            .unwrap();
        tx.set_xattr(
            &file,
            b"system.posix_acl_access",
            &helios_access,
            XattrMode::Set,
            when,
        )
        .await
        .unwrap();
        assert_eq!(tx.metadata(&file).await.unwrap().permissions, 0o640);
        tx.set_xattr(
            &directory,
            b"system.posix_acl_default",
            &helios_default,
            XattrMode::Set,
            when,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    });
    let expected_file = BTreeMap::from([
        (
            "user.中文".to_string(),
            "Helios が書いた".as_bytes().to_vec(),
        ),
        ("user.日本語".to_string(), "ヘリオス".as_bytes().to_vec()),
        (COLLIDING[0].to_string(), b"collision 0".to_vec()),
        (COLLIDING[1].to_string(), b"collision 1".to_vec()),
        ("security.capability".to_string(), NET_RAW.to_vec()),
        (
            "trusted.日本語".to_string(),
            "ヘリオスの信頼".as_bytes().to_vec(),
        ),
        ("system.posix_acl_access".to_string(), helios_access),
    ]);
    let expected_directory = BTreeMap::from([
        (
            "user.日本語".to_string(),
            "Linux ディレクトリ".as_bytes().to_vec(),
        ),
        ("user.目录".to_string(), "헬리오스".as_bytes().to_vec()),
        ("system.posix_acl_default".to_string(), helios_default),
    ]);

    // Write the image out for Linux.
    save(&shared.0.lock().unwrap(), &path);
    run("btrfs", &[os("check"), os("--readonly"), path.as_os_str()]);

    // Linux mounts it and reads what Helios wrote.
    let mounted = loop_mount(&path, "ro");
    let mode = std::fs::metadata(mounted.0.join("file"))
        .unwrap()
        .permissions();
    assert_eq!(mode.mode() & 0o7777, 0o640);
    for (relative, expected) in [("file", &expected_file), ("dir", &expected_directory)] {
        let target = mounted.0.join(relative);
        for (name, value) in expected {
            let found = run(
                "sudo",
                &[
                    os("getfattr"),
                    os("--only-values"),
                    os("--absolute-names"),
                    os("-n"),
                    os(name),
                    target.as_os_str(),
                ],
            );
            assert_eq!(&found, value, "{relative} {name}");
        }
        let listing = run(
            "sudo",
            &[
                os("getfattr"),
                os("-d"),
                os("-m"),
                os("-"),
                os("-e"),
                os("hex"),
                os("--absolute-names"),
                target.as_os_str(),
            ],
        );
        let listed = String::from_utf8_lossy(&listing)
            .lines()
            .filter(|line| !line.starts_with('#') && line.contains('='))
            .count();
        assert_eq!(listed, expected.len(), "{relative}: {listing:?}");
    }
    // The attribute Helios removed is gone for Linux too.
    let removed = std::process::Command::new("sudo")
        .args(["getfattr", "--absolute-names", "-n", "user.한국어"])
        .arg(mounted.0.join("file"))
        .output()
        .unwrap();
    assert!(!removed.status.success());
}

fn inline_text(length: usize) -> Vec<u8> {
    let mut bytes = "内联数据 インラインデータ 인라인 데이터 "
        .repeat(length)
        .into_bytes();
    bytes.truncate(length);
    bytes
}

fn inline_noise(length: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..length)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect()
}

fn zstd_stored_len(content: &[u8]) -> u64 {
    use helios_btrfs::write::Encoder;
    Zstd::new(3)
        .unwrap()
        .encode(content, 4096)
        .unwrap()
        .expect("compressible content")
        .bytes
        .len() as u64
}

fn exercise_inline_limits(image: SparseImage) -> std::sync::Arc<WritableImage> {
    use helios_btrfs::{Compression, ExtentKind};
    use std::collections::BTreeMap;

    const SECTOR: u64 = 4096;
    const WHEN: Timestamp = Timestamp {
        seconds: 1_700_000_200,
        nanoseconds: 0,
    };

    let shared = std::sync::Arc::new(WritableImage(Mutex::new(image)));
    block_on(async {
        let concurrency = std::thread::available_parallelism().unwrap();
        let mut writer = Writer::mount(
            SharedImage(shared.clone()),
            no_uuid as fn() -> [u8; 16],
            concurrency,
            Compressor::Plain,
            MOUNTED,
        )
        .await
        .unwrap();
        let nodesize = u64::from(writer.snapshot().unwrap().superblock().nodesize());
        // `BTRFS_MAX_INLINE_DATA_SIZE` (`fs/btrfs/ctree.h`): `nodesize` minus
        // `btrfs_header` (101) + `btrfs_item` (25) + inline `btrfs_file_extent_item` header (21).
        let max_node_inline = (SECTOR - 1).min(nodesize - 147);
        let zstd = || Compressor::Zstd(Box::new(Zstd::new(3).unwrap()));
        let mut expected: BTreeMap<&str, (Vec<u8>, Option<Option<Compression>>)> = BTreeMap::new();

        let attrs = Attributes {
            permissions: 0o644,
            uid: 1000,
            gid: 1000,
            umask: 0,
        };

        // Write paths: uncompressed & compressed, at and across limits.
        let mut tx = writer.join().await.unwrap();
        let root = tx.root().await.unwrap();
        let dir = tx
            .create_directory(
                Name {
                    parent: &root,
                    bytes: "内联-インライン-인라인".as_bytes(),
                },
                Attributes {
                    permissions: 0o755,
                    uid: 1000,
                    gid: 1000,
                    umask: 0,
                },
                WHEN,
            )
            .await
            .unwrap();
        for (name, content, max_inline, layout) in [
            (
                "plain_at",
                inline_noise(2048, 1),
                DEFAULT_MAX_INLINE,
                Some(None),
            ),
            (
                "plain_over",
                inline_noise(2049, 2),
                DEFAULT_MAX_INLINE,
                None,
            ),
            ("plain_sector", inline_noise(4096, 3), 4096, None),
            (
                "plain_node_at",
                inline_noise(max_node_inline as usize, 4),
                4096,
                Some(None),
            ),
            (
                "plain_node_over",
                inline_noise(max_node_inline as usize + 1, 5),
                4096,
                None,
            ),
            ("plain_zero", inline_noise(16, 6), 0, None),
            (
                "append_plain_at",
                inline_noise(2000, 7),
                DEFAULT_MAX_INLINE,
                Some(None),
            ),
            (
                "append_plain_over",
                inline_noise(2000, 8),
                DEFAULT_MAX_INLINE,
                None,
            ),
            (
                "trunc_plain_at",
                inline_noise(100, 9),
                DEFAULT_MAX_INLINE,
                Some(None),
            ),
            (
                "trunc_plain_over",
                inline_noise(100, 10),
                DEFAULT_MAX_INLINE,
                None,
            ),
            ("trunc_plain_sector", inline_noise(100, 11), 4096, None),
            (
                "clone_dest_inline",
                inline_noise(100, 12),
                DEFAULT_MAX_INLINE,
                Some(None),
            ),
            (
                "clone_dest_off_sector",
                inline_noise(100, 13),
                DEFAULT_MAX_INLINE,
                None,
            ),
        ] {
            let file = tx
                .create_file(
                    Name {
                        parent: &dir,
                        bytes: name.as_bytes(),
                    },
                    attrs,
                    WHEN,
                )
                .await
                .unwrap();
            tx.set_max_inline(max_inline);
            tx.write_file(&file, 0, &content, WHEN).await.unwrap();
            expected.insert(name, (content, layout));
        }

        tx.set_compressor(zstd()).await.unwrap();
        let comp_3000 = inline_text(3000);
        let comp_3000_len = zstd_stored_len(&comp_3000);
        let mut padded_trunc = inline_text(2000);
        padded_trunc.resize(SECTOR as usize, 0);
        let padded_trunc_len = zstd_stored_len(&padded_trunc);
        for (name, content, max_inline, layout) in [
            (
                "comp_sector",
                inline_text(4096),
                DEFAULT_MAX_INLINE,
                Some(Some(Compression::Zstd)),
            ),
            (
                "comp_over_sector",
                inline_text(4097),
                DEFAULT_MAX_INLINE,
                None,
            ),
            (
                "comp_at",
                comp_3000.clone(),
                comp_3000_len,
                Some(Some(Compression::Zstd)),
            ),
            ("comp_over", comp_3000, comp_3000_len - 1, None),
            (
                "comp_noise",
                inline_noise(3000, 14),
                DEFAULT_MAX_INLINE,
                None,
            ),
            (
                "append_comp_at",
                inline_text(2000),
                DEFAULT_MAX_INLINE,
                Some(Some(Compression::Zstd)),
            ),
            (
                "append_comp_over",
                inline_text(2000),
                DEFAULT_MAX_INLINE,
                None,
            ),
            (
                "trunc_comp_at",
                inline_text(2000),
                DEFAULT_MAX_INLINE,
                Some(Some(Compression::Zstd)),
            ),
            (
                "trunc_comp_over",
                inline_text(2000),
                DEFAULT_MAX_INLINE,
                None,
            ),
            (
                "trunc_comp_sector_over",
                inline_text(2000),
                DEFAULT_MAX_INLINE,
                None,
            ),
        ] {
            let file = tx
                .create_file(
                    Name {
                        parent: &dir,
                        bytes: name.as_bytes(),
                    },
                    attrs,
                    WHEN,
                )
                .await
                .unwrap();
            tx.set_max_inline(max_inline);
            tx.write_file(&file, 0, &content, WHEN).await.unwrap();
            expected.insert(name, (content, layout));
        }
        tx.set_compressor(Compressor::Plain).await.unwrap();
        tx.commit().await.unwrap();

        // Append & truncate up paths.
        let mut tx = writer.join().await.unwrap();
        let root = tx.root().await.unwrap();
        let dir = tx
            .lookup(&root, "内联-インライン-인라인".as_bytes())
            .await
            .unwrap()
            .unwrap();
        let open = async |tx: &helios_btrfs::write::WriteTransaction<'_, _, _>, name: &str| {
            tx.lookup(&dir, name.as_bytes()).await.unwrap().unwrap()
        };

        tx.set_max_inline(DEFAULT_MAX_INLINE);
        let f = open(&tx, "append_plain_at").await;
        let tail_48 = inline_noise(48, 15);
        tx.write_file(&f, 2000, &tail_48, WHEN).await.unwrap();
        expected
            .get_mut("append_plain_at")
            .unwrap()
            .0
            .extend_from_slice(&tail_48);

        let f = open(&tx, "append_plain_over").await;
        let tail_49 = inline_noise(49, 16);
        tx.write_file(&f, 2000, &tail_49, WHEN).await.unwrap();
        expected
            .get_mut("append_plain_over")
            .unwrap()
            .0
            .extend_from_slice(&tail_49);

        tx.set_compressor(zstd()).await.unwrap();
        let comp_joined = inline_text(4096);
        let comp_joined_len = zstd_stored_len(&comp_joined);
        let comp_tail = &comp_joined[2000..];
        let f = open(&tx, "append_comp_at").await;
        tx.set_max_inline(comp_joined_len);
        tx.write_file(&f, 2000, comp_tail, WHEN).await.unwrap();
        expected
            .get_mut("append_comp_at")
            .unwrap()
            .0
            .extend_from_slice(comp_tail);

        let f = open(&tx, "append_comp_over").await;
        tx.set_max_inline(comp_joined_len - 1);
        tx.write_file(&f, 2000, comp_tail, WHEN).await.unwrap();
        expected
            .get_mut("append_comp_over")
            .unwrap()
            .0
            .extend_from_slice(comp_tail);

        tx.set_compressor(Compressor::Plain).await.unwrap();
        for (name, size, max_inline) in [
            ("trunc_plain_at", 2048, DEFAULT_MAX_INLINE),
            ("trunc_plain_over", 2049, DEFAULT_MAX_INLINE),
            ("trunc_plain_sector", SECTOR, 4096),
        ] {
            let f = open(&tx, name).await;
            tx.set_max_inline(max_inline);
            tx.truncate_file(&f, size, WHEN).await.unwrap();
            expected.get_mut(name).unwrap().0.resize(size as usize, 0);
        }
        tx.set_compressor(zstd()).await.unwrap();
        for (name, size, max_inline) in [
            ("trunc_comp_at", SECTOR, padded_trunc_len),
            ("trunc_comp_over", SECTOR, padded_trunc_len - 1),
            ("trunc_comp_sector_over", SECTOR + 1, DEFAULT_MAX_INLINE),
        ] {
            let f = open(&tx, name).await;
            tx.set_max_inline(max_inline);
            tx.truncate_file(&f, size, WHEN).await.unwrap();
            expected.get_mut(name).unwrap().0.resize(size as usize, 0);
        }
        tx.set_compressor(Compressor::Plain).await.unwrap();
        tx.commit().await.unwrap();

        // Reflink paths: inline source at/across `max_inline`, at offset 4096,
        // and regular source promoting an inline destination.
        let mut tx = writer.join().await.unwrap();
        let root = tx.root().await.unwrap();
        let dir = tx
            .lookup(&root, "内联-インライン-인라인".as_bytes())
            .await
            .unwrap()
            .unwrap();
        let open = async |tx: &helios_btrfs::write::WriteTransaction<'_, _, _>, name: &str| {
            tx.lookup(&dir, name.as_bytes()).await.unwrap().unwrap()
        };

        let comp_sector_len = zstd_stored_len(&inline_text(4096));
        for (source_name, dest_name, dest_offset, max_inline, layout) in [
            (
                "plain_at",
                "clone_plain_at",
                0,
                DEFAULT_MAX_INLINE,
                Some(None),
            ),
            (
                "plain_at",
                "clone_plain_over",
                0,
                DEFAULT_MAX_INLINE - 1,
                None,
            ),
            (
                "plain_at",
                "clone_plain_off_sector",
                SECTOR,
                DEFAULT_MAX_INLINE,
                None,
            ),
            (
                "comp_sector",
                "clone_comp_at",
                0,
                comp_sector_len,
                Some(Some(Compression::Zstd)),
            ),
            (
                "comp_sector",
                "clone_comp_over",
                0,
                comp_sector_len - 1,
                None,
            ),
        ] {
            let from = open(&tx, source_name).await;
            let to = tx
                .create_file(
                    Name {
                        parent: &dir,
                        bytes: dest_name.as_bytes(),
                    },
                    attrs,
                    WHEN,
                )
                .await
                .unwrap();
            let src_bytes = expected[source_name].0.clone();
            tx.set_max_inline(max_inline);
            tx.clone_range(
                CloneRange {
                    source: &from,
                    destination: &to,
                    source_offset: 0,
                    destination_offset: dest_offset,
                    length: src_bytes.len() as u64,
                },
                WHEN,
            )
            .await
            .unwrap();
            let mut content = vec![0; dest_offset as usize];
            content.extend_from_slice(&src_bytes);
            expected.insert(dest_name, (content, layout));
        }

        tx.set_max_inline(DEFAULT_MAX_INLINE);
        let from_plain = open(&tx, "plain_at").await;
        let to_inline = open(&tx, "clone_dest_inline").await;
        let src_bytes = expected["plain_at"].0.clone();
        tx.clone_range(
            CloneRange {
                source: &from_plain,
                destination: &to_inline,
                source_offset: 0,
                destination_offset: 0,
                length: src_bytes.len() as u64,
            },
            WHEN,
        )
        .await
        .unwrap();
        expected.get_mut("clone_dest_inline").unwrap().0 = src_bytes;

        let from_reg = open(&tx, "plain_over").await;
        let to_off = open(&tx, "clone_dest_off_sector").await;
        let reg_bytes = expected["plain_over"].0.clone();
        tx.clone_range(
            CloneRange {
                source: &from_reg,
                destination: &to_off,
                source_offset: 0,
                destination_offset: SECTOR,
                length: reg_bytes.len() as u64,
            },
            WHEN,
        )
        .await
        .unwrap();
        let dest_bytes = &mut expected.get_mut("clone_dest_off_sector").unwrap().0;
        dest_bytes.resize(SECTOR as usize, 0);
        dest_bytes.extend_from_slice(&reg_bytes);

        tx.commit().await.unwrap();

        let view = writer.snapshot().unwrap();
        for (name, (bytes, layout)) in &expected {
            let path = format!("/内联-インライン-인라인/{name}");
            let inode = view.resolve(path.as_bytes()).await.unwrap();
            assert_eq!(inode.metadata().size, bytes.len() as u64, "{name}");
            let mut actual = vec![0; bytes.len()];
            assert_eq!(
                view.read(&inode, 0, &mut actual).await.unwrap(),
                bytes.len(),
                "{name}"
            );
            assert!(actual == *bytes, "{name}: content mismatch");
            let extents = view.file_extents(&inode).await.unwrap();
            for extent in extents.iter().filter(|e| e.kind == ExtentKind::Inline) {
                assert!(extent.stored <= max_node_inline, "{name}: {extent:?}");
                if extent.compression.is_none() {
                    assert_eq!(extent.stored, extent.len, "{name}: {extent:?}");
                } else {
                    assert!(extent.len <= SECTOR, "{name}: {extent:?}");
                }
            }
            match layout {
                Some(compression) => {
                    assert_eq!(extents.len(), 1, "{name}: {extents:?}");
                    assert_eq!(extents[0].kind, ExtentKind::Inline, "{name}: {extents:?}");
                    assert_eq!(extents[0].compression, *compression, "{name}: {extents:?}");
                }
                None => assert!(
                    extents.iter().all(|e| e.kind != ExtentKind::Inline),
                    "{name}: {extents:?}"
                ),
            }
        }
    });
    shared
}

#[test]
fn public_writer_enforces_inline_extent_limits() {
    let _ = exercise_inline_limits(base_image());
}

#[test]
#[ignore = "needs mkfs.btrfs and btrfs check from btrfs-progs; the Linux CI lane runs it with --run-ignored"]
fn inline_extent_limits_pass_btrfs_check() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("seed.txt"), b"seed\n").unwrap();
    for args in [&[][..], &["--nodesize", "4096"][..]] {
        let image = super::mkfs::mkfs_sized(tree.path(), 128 << 20, args);
        let shared = exercise_inline_limits(image);
        assert_btrfs_check(&shared.0);
    }
}

/// Exercises preallocation (`Allocate`, `KeepSize`), `PunchHole`, and
/// `ZeroRange` across compressed, reflinked, preallocated and inline extents,
/// verifying read-back bytes and extent kinds.
fn exercise_fallocate(image: SparseImage) -> std::sync::Arc<WritableImage> {
    use helios_btrfs::ExtentKind;
    let shared = std::sync::Arc::new(WritableImage(Mutex::new(image)));
    let compressor = Compressor::Zstd(Box::new(Zstd::new(3).unwrap()));
    block_on(async {
        let mut writer = Writer::mount(
            SharedImage(shared.clone()),
            no_uuid as fn() -> [u8; 16],
            std::thread::available_parallelism().unwrap(),
            compressor,
            MOUNTED,
        )
        .await
        .unwrap();
        let when = |sec: i64| Timestamp {
            seconds: 1_700_000_100 + sec,
            nanoseconds: 0,
        };
        let attrs = Attributes {
            permissions: 0o644,
            uid: 0,
            gid: 0,
            umask: 0,
        };

        let mut tx = writer.join().await.unwrap();
        let root = tx.root().await.unwrap();
        let dir = tx
            .create_directory(
                Name {
                    parent: &root,
                    bytes: "空间-領域-공간".as_bytes(),
                },
                Attributes {
                    permissions: 0o755,
                    uid: 0,
                    gid: 0,
                    umask: 0,
                },
                when(1),
            )
            .await
            .unwrap();
        let name = |bytes| Name {
            parent: &dir,
            bytes,
        };

        // 1. Compressed file, reflinked to two siblings, then punched & zeroed.
        let compressed = tx
            .create_file(name(b"compressed"), attrs, when(1))
            .await
            .unwrap();
        let mut payload = vec![0x42_u8; 65536];
        for (i, chunk) in payload.as_chunks_mut::<4096>().0.iter_mut().enumerate() {
            chunk[0] = (i as u8).wrapping_add(1);
            chunk[4095] = (i as u8).wrapping_add(0x90);
        }
        tx.write_file(&compressed, 0, &payload, when(2))
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let mut tx = writer.join().await.unwrap();
        let root = tx.root().await.unwrap();
        let dir = tx
            .lookup(&root, "空间-領域-공간".as_bytes())
            .await
            .unwrap()
            .unwrap();
        let name = |bytes| Name {
            parent: &dir,
            bytes,
        };
        let compressed = tx.lookup(&dir, b"compressed").await.unwrap().unwrap();
        let clone_a = tx
            .create_file(name(b"clone-a"), attrs, when(3))
            .await
            .unwrap();
        let clone_b = tx
            .create_file(name(b"clone-b"), attrs, when(3))
            .await
            .unwrap();
        for dst in [&clone_a, &clone_b] {
            tx.clone_range(
                CloneRange {
                    source: &compressed,
                    destination: dst,
                    source_offset: 0,
                    destination_offset: 0,
                    length: payload.len() as u64,
                },
                when(4),
            )
            .await
            .unwrap();
        }

        // Punch holes through compressed + reflinked extents (aligned and unaligned).
        tx.fallocate(&compressed, 8192, 16384, AllocateMode::PunchHole, when(5))
            .await
            .unwrap();
        tx.fallocate(&clone_a, 5000, 21000, AllocateMode::PunchHole, when(6))
            .await
            .unwrap();
        // Zero range through compressed + reflinked extent + extend past EOF.
        tx.fallocate(&clone_b, 10000, 20000, AllocateMode::ZeroRange, when(7))
            .await
            .unwrap();
        tx.fallocate(
            &clone_b,
            65536,
            16384,
            AllocateMode::ZeroRangeKeepSize,
            when(8),
        )
        .await
        .unwrap();

        // 2. Preallocate (mode 0 + KeepSize), reflink the PREALLOC extent, write & punch it.
        let prealloc = tx
            .create_file(name(b"prealloc"), attrs, when(9))
            .await
            .unwrap();
        tx.fallocate(&prealloc, 4096, 24576, AllocateMode::Allocate, when(10))
            .await
            .unwrap();
        tx.fallocate(&prealloc, 28672, 8192, AllocateMode::KeepSize, when(11))
            .await
            .unwrap();
        let prealloc_clone = tx
            .create_file(name(b"prealloc-clone"), attrs, when(12))
            .await
            .unwrap();
        tx.clone_range(
            CloneRange {
                source: &prealloc,
                destination: &prealloc_clone,
                source_offset: 4096,
                destination_offset: 0,
                length: 24576,
            },
            when(13),
        )
        .await
        .unwrap();
        tx.write_file(&prealloc, 8192, &[0xCC; 4096], when(14))
            .await
            .unwrap();
        tx.fallocate(
            &prealloc_clone,
            4096,
            8192,
            AllocateMode::PunchHole,
            when(15),
        )
        .await
        .unwrap();

        tx.commit().await.unwrap();

        let view = writer.snapshot().unwrap();
        let mut expected_compressed = payload.clone();
        expected_compressed[8192..24576].fill(0);
        let mut expected_a = payload.clone();
        expected_a[5000..26000].fill(0);
        let mut expected_b = payload.clone();
        expected_b[10000..30000].fill(0);
        let mut expected_prealloc = vec![0; 28672];
        expected_prealloc[8192..12288].fill(0xCC);
        let expected_prealloc_clone = vec![0; 24576];

        for (file_name, expected) in [
            ("compressed", expected_compressed),
            ("clone-a", expected_a),
            ("clone-b", expected_b),
            ("prealloc", expected_prealloc),
            ("prealloc-clone", expected_prealloc_clone),
        ] {
            let path = format!("/空间-領域-공간/{file_name}");
            let inode = view.resolve(path.as_bytes()).await.unwrap();
            assert_eq!(inode.metadata().size, expected.len() as u64, "{file_name}");
            let mut actual = vec![0; expected.len()];
            assert_eq!(
                view.read(&inode, 0, &mut actual).await.unwrap(),
                expected.len(),
                "{file_name}"
            );
            assert_eq!(actual, expected, "{file_name}");
        }

        let pre_inode = view
            .resolve("/空间-領域-공간/prealloc".as_bytes())
            .await
            .unwrap();
        let pre_extents = view.file_extents(&pre_inode).await.unwrap();
        assert!(
            pre_extents.iter().any(|e| e.kind == ExtentKind::Prealloc),
            "expected PREALLOC extents on prealloc: {pre_extents:?}"
        );
    });
    shared
}

#[test]
fn public_writer_fallocate_compressed_and_reflinked() {
    let _ = exercise_fallocate(base_image());
}

#[test]
#[ignore = "needs mkfs.btrfs and btrfs check from btrfs-progs; the Linux CI lane runs it with --run-ignored"]
fn fallocate_compressed_and_reflinked_pass_btrfs_check() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("seed.txt"), b"seed\n").unwrap();
    for args in [&[][..], &["-O", "^no-holes,^block-group-tree"][..]] {
        let image = super::mkfs::mkfs_sized(tree.path(), 128 << 20, args);
        let shared = exercise_fallocate(image);
        assert_btrfs_check(&shared.0);
    }
}
