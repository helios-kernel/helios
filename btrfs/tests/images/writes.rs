//! Uses only the public writable API against the independent image fixture.

use std::sync::Mutex;

use helios_btrfs::write::{Attributes, CloneRange, Name, WriteError, WriteOptions, Writer, Zstd};
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
    Writer::mount(
        WritableImage(Mutex::new(image)),
        no_uuid as fn() -> [u8; 16],
        std::thread::available_parallelism().unwrap(),
    )
    .await
}

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
        let concurrency = std::thread::available_parallelism().unwrap();
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
        tx.write_file(
            &file,
            0,
            b"guest bytes",
            WriteOptions::plain(when, concurrency),
        )
        .await
        .unwrap();
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
        tx.write_file(
            &original,
            0,
            &[0x47; 8192],
            WriteOptions::plain(when, concurrency),
        )
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
        let mut writer = mount(base_image()).await.unwrap();
        let before = writer.snapshot().unwrap();
        let join = writer.join();
        assert_send(&join);
        let mut tx = join.await.unwrap();
        let root = tx.root().await.unwrap();
        let when = Timestamp {
            seconds: 1_700_000_100,
            nanoseconds: 123,
        };
        let concurrency = std::thread::available_parallelism().unwrap();
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
        let mut encoder = Zstd::new(3).unwrap();
        let write = tx.write_file(
            &source,
            0,
            &data,
            WriteOptions {
                when,
                concurrency,
                encoder: &mut encoder,
            },
        );
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
            concurrency,
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
        let _ = tx
            .write_file(
                &source,
                0,
                b"changed",
                WriteOptions::plain(when, concurrency),
            )
            .await
            .unwrap();
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

/// Runs `sudo` without a password prompt; the node and the attribute below
/// need privileges the test user lacks.
fn sudo(args: &[&str]) {
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
}

/// What a file's metadata and security attribute say, for comparing views.
#[derive(Debug, PartialEq)]
struct Authority {
    kind: helios_btrfs::FileKind,
    permissions: u32,
    uid: u32,
    gid: u32,
    rdev: u64,
    nlink: u32,
    size: u64,
    ctime: Timestamp,
    mtime: Timestamp,
    security: Option<Vec<u8>>,
}

/// A Linux image carries a setuid file, a character device node and a
/// `security.*` attribute (lexoliu/helios#1037). Mounted writable, the writer
/// keeps all three intact through unrelated writes, and `btrfs check` is clean.
#[test]
#[ignore = "needs mkfs.btrfs and btrfs check from btrfs-progs, passwordless sudo, and setfattr; the Linux CI lane runs it with --run-ignored"]
fn linux_authority_survives_unrelated_writes() {
    const NAMES: [&str; 3] = ["中文新文件", "日本語の新しいファイル", "한국어새파일"];
    const LABEL: &[u8] = b"system_u:object_r:helios_t:s0";

    let tree = tempfile::tempdir().unwrap();
    let path = |name: &str| tree.path().join(name);
    let utf8 = |name: &str| path(name).to_str().unwrap().to_owned();
    std::fs::write(path("suid"), b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(
        path("suid"),
        std::os::unix::fs::PermissionsExt::from_mode(0o4755),
    )
    .unwrap();
    // /dev/null's numbers; the node is never opened.
    sudo(&["mknod", &utf8("中文设备"), "c", "1", "3"]);
    std::fs::write(path("日本語のファイル"), "こんにちは\n").unwrap();
    std::fs::write(path("한국어파일"), "안녕하세요\n").unwrap();
    std::fs::write(path("doomed"), b"unlinked below").unwrap();
    std::fs::write(path("moved"), b"renamed below").unwrap();
    for name in ["suid", "中文设备"] {
        sudo(&[
            "setfattr",
            "-n",
            "security.helios",
            "-v",
            std::str::from_utf8(LABEL).unwrap(),
            &utf8(name),
        ]);
    }
    let image = super::mkfs::mkfs_sized(tree.path(), 128 << 20, &[]);
    let shared = std::sync::Arc::new(WritableImage(Mutex::new(image)));

    block_on(async {
        let mut writer = Writer::mount(
            SharedImage(shared.clone()),
            no_uuid as fn() -> [u8; 16],
            std::thread::available_parallelism().unwrap(),
        )
        .await
        .unwrap();
        let authority = async |writer: &Writer<SharedImage, fn() -> [u8; 16]>, name: &str| {
            let view = writer.snapshot().unwrap();
            let inode = view.resolve(format!("/{name}").as_bytes()).await.unwrap();
            let metadata = *inode.metadata();
            let mut value = [0; 64];
            let security = view
                .xattr(&inode, b"security.helios", &mut value)
                .await
                .unwrap()
                .map(|length| value[..length].to_vec());
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
                security,
            }
        };
        let suid = authority(&writer, "suid").await;
        let device = authority(&writer, "中文设备").await;
        assert_eq!(suid.permissions, 0o4755);
        assert_eq!(device.kind, helios_btrfs::FileKind::CharDevice);
        // `mkfs.btrfs --rootdir` stores every rdev as 0 (btrfs-progs
        // mkfs/rootdir.c), so only its preservation below is checked.
        assert_eq!(suid.security.as_deref(), Some(LABEL));
        assert_eq!(device.security.as_deref(), Some(LABEL));

        // Create, write, rename and unlink elsewhere.
        let when = Timestamp {
            seconds: 1_800_000_000,
            nanoseconds: 0,
        };
        let concurrency = std::thread::available_parallelism().unwrap();
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
            tx.write_file(
                &file,
                0,
                name.as_bytes(),
                WriteOptions::plain(when, concurrency),
            )
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
        "btrfs check\n{}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
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
