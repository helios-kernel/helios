//! Uses only the public writable API against the independent image fixture.

use std::sync::Mutex;

use helios_btrfs::write::{Attributes, CloneRange, Name, WriteOptions, Writer, Zstd};
use helios_btrfs::{BlockSink, BlockSource, READ_ALIGNMENT, Timestamp};
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

/// A writer over the image `mkfs.btrfs` produces for the guest smoke (128 MiB,
/// default features) commits a created file and reads it back.
#[test]
#[ignore = "needs mkfs.btrfs from btrfs-progs; the Linux CI lane runs it with --run-ignored"]
fn writer_commits_over_a_mkfs_image() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("hello.txt"), b"hello btrfs\n").unwrap();
    let image = super::mkfs::mkfs_sized(tree.path(), 128 << 20, &[]);
    block_on(async {
        let mut writer = Writer::mount(WritableImage(Mutex::new(image)))
            .await
            .unwrap();
        let mut tx = writer.begin().await.unwrap();
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
        tx.commit(|| panic!("mkfs UUIDs are valid"), concurrency)
            .await
            .unwrap();
        let snapshot = writer.snapshot().unwrap();
        let written = snapshot.resolve(b"/written").await.unwrap();
        let mut output = [0; 11];
        snapshot.read(&written, 0, &mut output).await.unwrap();
        assert_eq!(&output, b"guest bytes");

        // The guest smoke's sequence: a directory, a file in it, then a hard
        // link to that file once both are committed.
        let mut tx = writer.begin().await.unwrap();
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
        tx.commit(|| panic!("mkfs UUIDs are valid"), concurrency)
            .await
            .unwrap();
        let mut tx = writer.begin().await.unwrap();
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
        tx.commit(|| panic!("mkfs UUIDs are valid"), concurrency)
            .await
            .unwrap();
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
        let mut writer = Writer::mount(WritableImage(Mutex::new(base_image())))
            .await
            .unwrap();
        let before = writer.snapshot().unwrap();
        let begin = writer.begin();
        assert_send(&begin);
        let mut tx = begin.await.unwrap();
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
        let commit = tx.commit(|| panic!("fixture UUIDs are valid"), concurrency);
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
        let mut tx = writer.begin().await.unwrap();
        let _ = tx
            .write_file(
                &source,
                0,
                b"changed",
                WriteOptions::plain(when, concurrency),
            )
            .await
            .unwrap();
        tx.rename(name(b"clone"), name(b"kept"), when)
            .await
            .unwrap();
        tx.commit(|| panic!("fixture UUIDs are valid"), concurrency)
            .await
            .unwrap();
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
    use helios_btrfs::write::WriteError;

    let tree = tempfile::tempdir().unwrap();
    std::fs::write(tree.path().join("hello.txt"), b"hello btrfs\n").unwrap();

    let image = super::mkfs::mkfs_sized(tree.path(), 128 << 20, &["-O", "quota"]);
    super::fixture::mount(image.clone()).expect("a read-only mount ignores quotas");
    let refused = block_on(Writer::mount(WritableImage(Mutex::new(image))));
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
    let write = block_on(Writer::mount(WritableImage(Mutex::new(image)))).err();
    assert!(
        matches!(&write, Some(WriteError::Read(error)) if squota(error)),
        "-O squota writable: {write:?}"
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

/// The image, shared so the test can read it after the writer is done.
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

/// The attributes Linux and Helios write, in both directions, and
/// `btrfs check` over the result. Needs btrfs-progs, sudo (for `mount`,
/// `umount` and a `security.capability` write) and `setfattr`/`getfattr`
/// from the attr package.
#[test]
#[ignore = "needs btrfs-progs, sudo and attr; the Linux CI lane runs it with --run-ignored"]
fn user_attributes_cross_between_linux_and_helios() {
    use helios_btrfs::write::{WriteError, XattrMode};
    use std::collections::BTreeMap;

    // A directory on the build's own disk: tmpfs keeps no user.* attributes
    // before Linux 6.6.
    let source = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let file = source.path().join("file");
    let directory = source.path().join("dir");
    std::fs::write(&file, b"data").unwrap();
    std::fs::create_dir(&directory).unwrap();
    let setfattr = |path: &std::path::Path, name: &str, value: &str| {
        run(
            "setfattr",
            &[os("-n"), os(name), os("-v"), os(value), path.as_os_str()],
        );
    };
    setfattr(&file, "user.中文", "Linux 写的");
    setfattr(&file, "user.한국어", "리눅스가 씀");
    setfattr(&directory, "user.日本語", "Linux ディレクトリ");
    let capability: String = CAPABILITY
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    run(
        "sudo",
        &[
            os("setfattr"),
            os("-n"),
            os("security.capability"),
            os("-v"),
            os(&format!("0x{capability}")),
            file.as_os_str(),
        ],
    );
    let image = super::mkfs::mkfs_sized(source.path(), 128 << 20, &[]);

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
        ])
    );
    assert_eq!(
        helios_attributes(&linux, "/dir"),
        BTreeMap::from([(
            "user.日本語".as_bytes().to_vec(),
            "Linux ディレクトリ".as_bytes().to_vec()
        )])
    );

    // Helios replaces, creates and removes beside them.
    let shared = std::sync::Arc::new(WritableImage(Mutex::new(image)));
    let concurrency = std::thread::available_parallelism().unwrap();
    let when = Timestamp {
        seconds: 1_700_000_100,
        nanoseconds: 0,
    };
    block_on(async {
        let mut writer = Writer::mount(SharedImage(shared.clone())).await.unwrap();
        let mut tx = writer.begin().await.unwrap();
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
        // The capability Linux wrote is kept, and cannot be changed.
        assert!(matches!(
            tx.set_xattr(&file, b"security.capability", b"", XattrMode::Replace, when)
                .await,
            Err(WriteError::XattrNotPermitted { .. })
        ));
        tx.commit(|| panic!("mkfs UUIDs are valid"), concurrency)
            .await
            .unwrap();
    });
    let expected_file = BTreeMap::from([
        (
            "user.中文".to_string(),
            "Helios が書いた".as_bytes().to_vec(),
        ),
        ("user.日本語".to_string(), "ヘリオス".as_bytes().to_vec()),
        (COLLIDING[0].to_string(), b"collision 0".to_vec()),
        (COLLIDING[1].to_string(), b"collision 1".to_vec()),
        ("security.capability".to_string(), CAPABILITY.to_vec()),
    ]);
    let expected_directory = BTreeMap::from([
        (
            "user.日本語".to_string(),
            "Linux ディレクトリ".as_bytes().to_vec(),
        ),
        ("user.目录".to_string(), "헬리오스".as_bytes().to_vec()),
    ]);

    // Write the image out for Linux.
    let scratch = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let path = scratch.path().join("image");
    {
        use std::io::Write;
        let mut out = std::fs::File::create(&path).unwrap();
        let mut block = vec![0; 1 << 20];
        let mut offset = 0;
        let size = shared.size_bytes();
        while offset < size {
            let length = block.len().min((size - offset) as usize);
            shared
                .0
                .lock()
                .unwrap()
                .read_bytes(offset, &mut block[..length]);
            out.write_all(&block[..length]).unwrap();
            offset += length as u64;
        }
    }
    run("btrfs", &[os("check"), os("--readonly"), path.as_os_str()]);

    // Linux mounts it and reads what Helios wrote.
    let mount = scratch.path().join("mount");
    std::fs::create_dir(&mount).unwrap();
    run(
        "sudo",
        &[
            os("mount"),
            os("-o"),
            os("loop,ro"),
            path.as_os_str(),
            mount.as_os_str(),
        ],
    );
    let mounted = Mounted(mount);
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
