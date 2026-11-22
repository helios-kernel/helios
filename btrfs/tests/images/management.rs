//! End-to-end tests for btrfs volume management operations: subvolumes,
//! snapshots (RO and RW), send/receive (full and incremental), reflink,
//! dedupe, multi-device add/remove/replace, resize, balance, scrub, and quota
//! groups, plus Linux `btrfs check --readonly`, Linux kernel mount readback,
//! and bidirectional `btrfs send`/`btrfs receive` interoperability.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use helios_btrfs::write::{
    Attributes, CloneRange, Compressor, Name, Special, WriteError, Writer, XattrMode,
};
use helios_btrfs::{
    BlockSink, BlockSource, DeviceNumber, FileKind, Filesystem, READ_ALIGNMENT, Timestamp,
};
use helios_hal::fs_management::{
    BalanceFilter, DedupeOutcome, QgroupId, QgroupLimit, ResizeTarget,
};
use helios_hal::io::IoResult;

use super::fixture::{SparseImage, VOLUME_BYTES, base_image, block_on};

const WHEN: Timestamp = Timestamp {
    seconds: 1_750_000_000,
    nanoseconds: 0,
};

struct SharedDisk(Arc<Mutex<SparseImage>>);

impl Clone for SharedDisk {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl SharedDisk {
    fn new(image: SparseImage) -> Self {
        Self(Arc::new(Mutex::new(image)))
    }

    fn blank(bytes: u64) -> Self {
        Self::new(SparseImage::new(bytes))
    }
}

impl BlockSource for SharedDisk {
    fn size_bytes(&self) -> u64 {
        self.0.lock().unwrap().size_bytes()
    }

    async fn read_at(&self, offset: u64, output: &mut [u8]) -> IoResult<()> {
        self.0.lock().unwrap().read_bytes(offset, output);
        Ok(())
    }
}

impl BlockSink for SharedDisk {
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

struct DeterministicUuids(u64);

impl DeterministicUuids {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> [u8; 16] {
        self.0 += 1;
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&self.0.to_le_bytes());
        bytes[8..16].copy_from_slice(&(self.0.wrapping_mul(0x9e37_79b9_7f4a_7c15)).to_le_bytes());
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        bytes
    }
}

impl helios_btrfs::write::RootUuids for DeterministicUuids {
    fn next_uuid(&mut self) -> [u8; 16] {
        self.next()
    }
}

async fn mount_writer(disk: SharedDisk) -> Writer<SharedDisk, DeterministicUuids> {
    Writer::mount(
        disk,
        DeterministicUuids::new(0x1043),
        NonZeroUsize::new(2).unwrap(),
        Compressor::Plain,
        WHEN,
    )
    .await
    .unwrap()
}

fn attrs(permissions: u32, uid: u32, gid: u32) -> Attributes {
    Attributes {
        permissions,
        uid,
        gid,
        umask: 0,
    }
}

/// Extended POSIX ACL v2 blob (`user::rwx`, `user:1000:r-x`, `group::r-x`,
/// `mask::r-x`, `other::r-x`) — non-minimal so Linux stores it in
/// `system.posix_acl_access` rather than collapsing it into mode bits.
const POSIX_ACL_V2: &[u8] = &[
    0x02, 0x00, 0x00, 0x00, // version 2
    0x01, 0x00, 0x07, 0x00, 0xff, 0xff, 0xff, 0xff, // ACL_USER_OBJ rwx
    0x02, 0x00, 0x05, 0x00, 0xe8, 0x03, 0x00, 0x00, // ACL_USER 1000 r-x
    0x04, 0x00, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff, // ACL_GROUP_OBJ r-x
    0x10, 0x00, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff, // ACL_MASK r-x
    0x20, 0x00, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff, // ACL_OTHER r-x
];

async fn read_all(fs: &Filesystem<SharedDisk>, path: &str) -> Vec<u8> {
    let inode = fs.resolve(path.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; inode.metadata().size as usize];
    let n = fs.read(&inode, 0, &mut buf).await.unwrap();
    buf.truncate(n);
    buf
}

async fn read_xattr(
    fs: &Filesystem<SharedDisk>,
    inode: &helios_btrfs::Inode,
    name: &[u8],
) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 256];
    let n = fs.xattr(inode, name, &mut buf).await.unwrap()?;
    buf.truncate(n);
    Some(buf)
}

#[test]
fn subvolume_create_snapshot_and_delete() {
    block_on(async {
        let disk = SharedDisk::new(base_image());
        let mut writer = mount_writer(disk.clone()).await;

        let work = writer
            .create_subvolume("", b"work", attrs(0o755, 0, 0), WHEN)
            .await
            .unwrap();
        assert_eq!(work.path, "work");
        assert!(!work.read_only);

        // Stage dirty (uncommitted) writes inside `work`, including CJK names
        // across Chinese, Japanese, and Korean, to prove snapshot flushes
        // delalloc before sharing the root.
        {
            let mut tx = writer.join().await.unwrap();
            let root = tx.root().await.unwrap();
            let work_dir = tx.lookup(&root, b"work").await.unwrap().unwrap();
            for (name, body) in [
                ("中文.txt", b"chinese-payload".as_slice()),
                ("日本語.txt", b"japanese-payload".as_slice()),
                ("한국어.txt", b"korean-payload".as_slice()),
            ] {
                let file = tx
                    .create_file(
                        Name {
                            parent: &work_dir,
                            bytes: name.as_bytes(),
                        },
                        attrs(0o644, 1000, 1000),
                        WHEN,
                    )
                    .await
                    .unwrap();
                tx.write_file(&file, 0, body, WHEN).await.unwrap();
            }
        }

        let snap_ro = writer
            .snapshot_subvolume(work.id, "", b"snap-ro", true, WHEN)
            .await
            .unwrap();
        assert!(snap_ro.read_only);
        assert_eq!(snap_ro.parent_uuid, Some(work.uuid));

        let snap_rw = writer
            .snapshot_subvolume(work.id, "", b"snap-rw", false, WHEN)
            .await
            .unwrap();
        assert!(!snap_rw.read_only);

        // RO snapshot refuses writes until flipped writable.
        {
            let mut tx = writer.join().await.unwrap();
            let root = tx.root().await.unwrap();
            let ro = tx.lookup(&root, b"snap-ro").await.unwrap().unwrap();
            let err = tx
                .create_file(
                    Name {
                        parent: &ro,
                        bytes: b"blocked",
                    },
                    attrs(0o644, 0, 0),
                    WHEN,
                )
                .await
                .unwrap_err();
            assert!(matches!(err, WriteError::ReadOnlySubvolume { .. }));
        }

        writer
            .set_subvolume_read_only(snap_ro.id, false)
            .await
            .unwrap();
        assert!(!writer.subvolume_info(snap_ro.id).await.unwrap().read_only);
        writer
            .set_subvolume_read_only(snap_ro.id, true)
            .await
            .unwrap();
        assert!(writer.subvolume_info(snap_ro.id).await.unwrap().read_only);

        // Diverge `work` and `snap-rw` via CoW while keeping `snap-ro` intact.
        {
            let mut tx = writer.join().await.unwrap();
            let root = tx.root().await.unwrap();
            let work_dir = tx.lookup(&root, b"work").await.unwrap().unwrap();
            let f_work = tx
                .lookup(&work_dir, "中文.txt".as_bytes())
                .await
                .unwrap()
                .unwrap();
            tx.write_file(&f_work, 0, b"work-mutated!!!", WHEN)
                .await
                .unwrap();

            let rw_dir = tx.lookup(&root, b"snap-rw").await.unwrap().unwrap();
            let f_rw = tx
                .lookup(&rw_dir, "中文.txt".as_bytes())
                .await
                .unwrap()
                .unwrap();
            tx.write_file(&f_rw, 0, b"rw-mutated!!!!!", WHEN)
                .await
                .unwrap();
        }
        writer.commit().await.unwrap();

        // Nested subvolume prevents deleting its parent until removed first.
        let nested = writer
            .create_subvolume("work", b"nested", attrs(0o755, 0, 0), WHEN)
            .await
            .unwrap();
        assert_eq!(nested.path, "work/nested");
        let err = writer
            .delete_subvolume("", b"work", WHEN)
            .await
            .unwrap_err();
        assert!(matches!(err, WriteError::SubvolumeNotEmpty { .. }));

        writer
            .delete_subvolume("work", b"nested", WHEN)
            .await
            .unwrap();
        writer.delete_subvolume("", b"work", WHEN).await.unwrap();

        // Remount read-only and verify both surviving snapshots kept their exact bytes.
        drop(writer);
        let reader = Filesystem::mount(disk).await.unwrap();
        assert!(reader.resolve(b"/work").await.is_err());
        assert_eq!(
            read_all(&reader, "/snap-ro/中文.txt").await,
            b"chinese-payload"
        );
        assert_eq!(
            read_all(&reader, "/snap-ro/日本語.txt").await,
            b"japanese-payload"
        );
        assert_eq!(
            read_all(&reader, "/snap-ro/한국어.txt").await,
            b"korean-payload"
        );
        assert_eq!(
            read_all(&reader, "/snap-rw/中文.txt").await,
            b"rw-mutated!!!!!"
        );
    });
}

#[test]
fn send_and_receive_full_and_incremental_with_unix_metadata() {
    block_on(async {
        let disk = SharedDisk::new(base_image());
        let mut writer = mount_writer(disk.clone()).await;

        let src = writer
            .create_subvolume("", b"src", attrs(0o755, 0, 0), WHEN)
            .await
            .unwrap();
        let recv_dir = {
            let mut tx = writer.join().await.unwrap();
            let root = tx.root().await.unwrap();
            tx.create_directory(
                Name {
                    parent: &root,
                    bytes: b"recv",
                },
                attrs(0o755, 0, 0),
                WHEN,
            )
            .await
            .unwrap();

            let src_dir = tx.lookup(&root, b"src").await.unwrap().unwrap();
            let sub = tx
                .create_directory(
                    Name {
                        parent: &src_dir,
                        bytes: "目录".as_bytes(),
                    },
                    attrs(0o1777, 0, 0),
                    WHEN,
                )
                .await
                .unwrap();

            // Regular file with hole, setuid, uid/gid, and all xattr namespaces + ACL.
            let regular = tx
                .create_file(
                    Name {
                        parent: &sub,
                        bytes: "中文-日本語-한국어.bin".as_bytes(),
                    },
                    attrs(0o4755, 1000, 2000),
                    WHEN,
                )
                .await
                .unwrap();
            tx.write_file(&regular, 0, &vec![0xaa; 8192], WHEN)
                .await
                .unwrap();
            tx.write_file(&regular, 24576, &vec![0xbb; 4096], WHEN)
                .await
                .unwrap();
            tx.set_xattr(&regular, b"user.helios", b"uval", XattrMode::Set, WHEN)
                .await
                .unwrap();
            tx.set_xattr(&regular, b"security.helios", b"sval", XattrMode::Set, WHEN)
                .await
                .unwrap();
            tx.set_xattr(&regular, b"trusted.helios", b"tval", XattrMode::Set, WHEN)
                .await
                .unwrap();
            tx.set_xattr(
                &regular,
                b"system.posix_acl_access",
                POSIX_ACL_V2,
                XattrMode::Set,
                WHEN,
            )
            .await
            .unwrap();

            // Hardlink to the regular file.
            tx.hard_link(
                Name {
                    parent: &src_dir,
                    bytes: b"hardlink.bin",
                },
                &regular,
                WHEN,
            )
            .await
            .unwrap();

            // Symlink.
            tx.symlink(
                Name {
                    parent: &src_dir,
                    bytes: b"sym",
                },
                "目录/中文-日本語-한국어.bin".as_bytes(),
                attrs(0o777, 1000, 2000),
                WHEN,
            )
            .await
            .unwrap();

            // Special nodes: char device, block device, FIFO, socket.
            tx.create_special(
                Name {
                    parent: &src_dir,
                    bytes: b"null-chr",
                },
                Special::CharDevice(DeviceNumber::new(1, 3).unwrap()),
                attrs(0o666, 0, 0),
                WHEN,
            )
            .await
            .unwrap();
            tx.create_special(
                Name {
                    parent: &src_dir,
                    bytes: b"sda-blk",
                },
                Special::BlockDevice(DeviceNumber::new(8, 0).unwrap()),
                attrs(0o660, 0, 6),
                WHEN,
            )
            .await
            .unwrap();
            tx.create_special(
                Name {
                    parent: &src_dir,
                    bytes: b"pipe",
                },
                Special::Fifo,
                attrs(0o640, 1000, 1000),
                WHEN,
            )
            .await
            .unwrap();
            tx.create_special(
                Name {
                    parent: &src_dir,
                    bytes: b"sock",
                },
                Special::Socket,
                attrs(0o755, 1000, 1000),
                WHEN,
            )
            .await
            .unwrap();
            "recv"
        };
        writer.commit().await.unwrap();

        let v1 = writer
            .snapshot_subvolume(src.id, "", b"v1", true, WHEN)
            .await
            .unwrap();
        let full_stream = writer.send_subvolume(v1.id, None, &[]).await.unwrap();
        assert!(full_stream.starts_with(b"btrfs-stream\0"));

        let received_v1 = writer
            .receive_subvolume(recv_dir, &full_stream, WHEN, |_| Ok(()))
            .await
            .unwrap();
        assert!(received_v1.read_only);
        assert_eq!(received_v1.received_uuid, Some(v1.uuid));
        assert_eq!(received_v1.stransid, v1.ctransid);

        // Mutate `src` and take `v2` for an incremental send.
        {
            let mut tx = writer.join().await.unwrap();
            let root = tx.root().await.unwrap();
            let src_dir = tx.lookup(&root, b"src").await.unwrap().unwrap();
            tx.unlink_name(
                Name {
                    parent: &src_dir,
                    bytes: b"pipe",
                },
                WHEN,
            )
            .await
            .unwrap();
            let added = tx
                .create_file(
                    Name {
                        parent: &src_dir,
                        bytes: b"delta.txt",
                    },
                    attrs(0o2755, 500, 600),
                    WHEN,
                )
                .await
                .unwrap();
            tx.write_file(&added, 0, b"incremental-change", WHEN)
                .await
                .unwrap();
        }
        writer.commit().await.unwrap();

        let v2 = writer
            .snapshot_subvolume(src.id, "", b"v2", true, WHEN)
            .await
            .unwrap();
        let inc_stream = writer
            .send_subvolume(v2.id, Some(v1.id), &[])
            .await
            .unwrap();

        // Refusing authorization of the parent subvolume must abort receive.
        let refused = writer
            .receive_subvolume(recv_dir, &inc_stream, WHEN, |_| {
                Err(WriteError::PermissionDenied)
            })
            .await
            .unwrap_err();
        assert!(matches!(refused, WriteError::PermissionDenied));

        // Authorizing parent allows incremental receive to succeed.
        let mut saw_parent = false;
        let received_v2 = writer
            .receive_subvolume(recv_dir, &inc_stream, WHEN, |path| {
                assert!(!path.is_empty());
                saw_parent = true;
                Ok(())
            })
            .await
            .unwrap();
        assert!(saw_parent);
        assert!(received_v2.read_only);
        assert_eq!(received_v2.received_uuid, Some(v2.uuid));

        drop(writer);
        let fs = Filesystem::mount(disk).await.unwrap();

        // Verify v1 received metadata, sparse data, hardlink, symlink, special nodes, xattrs.
        let reg = fs
            .resolve("/recv/v1/目录/中文-日本語-한국어.bin".as_bytes())
            .await
            .unwrap();
        let hl = fs.resolve(b"/recv/v1/hardlink.bin").await.unwrap();
        assert_eq!(reg.number(), hl.number());
        assert_eq!(reg.metadata().nlink, 2);
        assert_eq!(reg.metadata().uid, 1000);
        assert_eq!(reg.metadata().gid, 2000);
        assert_eq!(reg.metadata().permissions & 0o4000, 0o4000);
        assert_eq!(
            read_xattr(&fs, &reg, b"user.helios").await.as_deref(),
            Some(b"uval".as_slice())
        );
        assert_eq!(
            read_xattr(&fs, &reg, b"security.helios").await.as_deref(),
            Some(b"sval".as_slice())
        );
        assert_eq!(
            read_xattr(&fs, &reg, b"trusted.helios").await.as_deref(),
            Some(b"tval".as_slice())
        );
        assert_eq!(
            read_xattr(&fs, &reg, b"system.posix_acl_access")
                .await
                .as_deref(),
            Some(POSIX_ACL_V2)
        );
        let data = read_all(&fs, "/recv/v1/目录/中文-日本語-한국어.bin").await;
        assert_eq!(data.len(), 28672);
        assert!(data[..8192].iter().all(|&b| b == 0xaa));
        assert!(data[8192..24576].iter().all(|&b| b == 0));
        assert!(data[24576..].iter().all(|&b| b == 0xbb));

        let chr = fs.resolve(b"/recv/v1/null-chr").await.unwrap();
        assert_eq!(chr.kind(), FileKind::CharDevice);
        assert_eq!(chr.metadata().rdev, DeviceNumber::new(1, 3).unwrap());
        let blk = fs.resolve(b"/recv/v1/sda-blk").await.unwrap();
        assert_eq!(blk.kind(), FileKind::BlockDevice);
        assert_eq!(blk.metadata().rdev, DeviceNumber::new(8, 0).unwrap());
        assert_eq!(
            fs.resolve(b"/recv/v1/pipe").await.unwrap().kind(),
            FileKind::Fifo
        );
        assert_eq!(
            fs.resolve(b"/recv/v1/sock").await.unwrap().kind(),
            FileKind::Socket
        );

        // Verify incremental v2 removed `pipe`, added `delta.txt` with setgid,
        // and retained the regular file.
        assert!(fs.resolve(b"/recv/v2/pipe").await.is_err());
        let delta = fs.resolve(b"/recv/v2/delta.txt").await.unwrap();
        assert_eq!(delta.metadata().permissions, 0o2755);
        assert_eq!(delta.metadata().uid, 500);
        assert_eq!(delta.metadata().gid, 600);
        assert_eq!(
            read_all(&fs, "/recv/v2/delta.txt").await,
            b"incremental-change"
        );
        assert_eq!(
            read_all(&fs, "/recv/v2/目录/中文-日本語-한국어.bin")
                .await
                .len(),
            28672
        );
    });
}

#[test]
fn send_receive_cross_depth_hardlinks_truncated_clone_and_error_cleanup() {
    block_on(async {
        let disk = SharedDisk::new(base_image());
        let mut writer = mount_writer(disk.clone()).await;

        let src = writer
            .create_subvolume("", b"src", attrs(0o755, 0, 0), WHEN)
            .await
            .unwrap();
        let recv_dir = "recv";
        {
            let mut tx = writer.join().await.unwrap();
            let root = tx.root().await.unwrap();
            tx.create_directory(
                Name {
                    parent: &root,
                    bytes: recv_dir.as_bytes(),
                },
                attrs(0o755, 0, 0),
                WHEN,
            )
            .await
            .unwrap();
            let src_dir = tx.lookup(&root, b"src").await.unwrap().unwrap();
            let dir_a = tx
                .create_directory(
                    Name {
                        parent: &src_dir,
                        bytes: b"a",
                    },
                    attrs(0o755, 0, 0),
                    WHEN,
                )
                .await
                .unwrap();

            // Regression #1: cross-depth hardlinks `"z"` (depth 1) and `"a/b"`
            // (depth 2, lexicographically smaller than `"z"`).
            let file_z = tx
                .create_file(
                    Name {
                        parent: &src_dir,
                        bytes: b"z",
                    },
                    attrs(0o644, 0, 0),
                    WHEN,
                )
                .await
                .unwrap();
            tx.write_file(&file_z, 0, b"cross-depth-hardlink", WHEN)
                .await
                .unwrap();
            tx.hard_link(
                Name {
                    parent: &dir_a,
                    bytes: b"b",
                },
                &file_z,
                WHEN,
            )
            .await
            .unwrap();

            // Regression #2: 8 KiB file later truncated to 5000 B in a snapshot.
            let big = tx
                .create_file(
                    Name {
                        parent: &src_dir,
                        bytes: b"trunc.bin",
                    },
                    attrs(0o644, 0, 0),
                    WHEN,
                )
                .await
                .unwrap();
            let mut body = vec![0x33_u8; 4096];
            body.extend_from_slice(&vec![0x44_u8; 4096]);
            tx.write_file(&big, 0, &body, WHEN).await.unwrap();
        }
        writer.commit().await.unwrap();

        let snap1 = writer
            .snapshot_subvolume(src.id, "", b"snap1", true, WHEN)
            .await
            .unwrap();

        // Full send/receive exercises cross-depth hardlinks `"z"` + `"a/b"`.
        let full_stream = writer.send_subvolume(snap1.id, None, &[]).await.unwrap();
        let recv1 = writer
            .receive_subvolume(recv_dir, &full_stream, WHEN, |_| Ok(()))
            .await
            .unwrap();
        assert!(recv1.read_only);

        // Truncate `trunc.bin` from 8192 B to 5000 B and snapshot for incremental send.
        {
            let mut tx = writer.join().await.unwrap();
            let root = tx.root().await.unwrap();
            let src_dir = tx.lookup(&root, b"src").await.unwrap().unwrap();
            let big = tx.lookup(&src_dir, b"trunc.bin").await.unwrap().unwrap();
            tx.truncate_file(&big, 5000, WHEN).await.unwrap();
        }
        writer.commit().await.unwrap();

        let snap2 = writer
            .snapshot_subvolume(src.id, "", b"snap2", true, WHEN)
            .await
            .unwrap();
        let inc_stream = writer
            .send_subvolume(snap2.id, Some(snap1.id), &[])
            .await
            .unwrap();
        let recv2 = writer
            .receive_subvolume(recv_dir, &inc_stream, WHEN, |_| Ok(()))
            .await
            .unwrap();
        assert!(recv2.read_only);

        // Regression #4a: unauthorized external CLONE source must fail before
        // creating any target subvolume on disk.
        let clone_stream = writer
            .send_subvolume(snap2.id, None, &[snap1.id])
            .await
            .unwrap();
        let before_count = writer.list_subvolumes().await.unwrap().len();
        let denied = writer
            .receive_subvolume(recv_dir, &clone_stream, WHEN, |_| {
                Err(WriteError::PermissionDenied)
            })
            .await
            .unwrap_err();
        assert!(matches!(denied, WriteError::PermissionDenied));
        assert_eq!(writer.list_subvolumes().await.unwrap().len(), before_count);

        // Regression #4b: mid-stream failure after SUBVOL creation must clean up
        // the half-received writable subvolume so nothing stray remains.
        let mut failing_stream = Vec::new();
        failing_stream.extend_from_slice(b"btrfs-stream\0");
        failing_stream.extend_from_slice(&1_u32.to_le_bytes());
        let push_cmd = |out: &mut Vec<u8>, code: u16, tlvs: &[(u16, &[u8])]| {
            let mut body = Vec::new();
            for &(kind, data) in tlvs {
                body.extend_from_slice(&kind.to_le_bytes());
                body.extend_from_slice(&(data.len() as u16).to_le_bytes());
                body.extend_from_slice(data);
            }
            let start = out.len();
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&code.to_le_bytes());
            out.extend_from_slice(&0_u32.to_le_bytes());
            out.extend_from_slice(&body);
            // CRC32C (Castagnoli) over the command with zeroed CRC field.
            let mut crc = 0_u32;
            for &byte in &out[start..] {
                crc ^= u32::from(byte);
                for _ in 0..8 {
                    let mask = (crc & 1).wrapping_neg();
                    crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
                }
            }
            out[start + 6..start + 10].copy_from_slice(&crc.to_le_bytes());
        };
        let bad_uuid = [0x99_u8; 16];
        push_cmd(
            &mut failing_stream,
            1, // BTRFS_SEND_C_SUBVOL
            &[
                (15, b"leaked-subvol"),
                (1, &bad_uuid),
                (2, &42_u64.to_le_bytes()),
            ],
        );
        push_cmd(
            &mut failing_stream,
            11, // BTRFS_SEND_C_UNLINK of nonexistent file triggers NoEntry
            &[(15, b"does-not-exist")],
        );
        push_cmd(&mut failing_stream, 21, &[]); // BTRFS_SEND_C_END

        let err = writer
            .receive_subvolume(recv_dir, &failing_stream, WHEN, |_| Ok(()))
            .await
            .unwrap_err();
        assert!(matches!(err, WriteError::NoEntry { .. }));
        let subvols = writer.list_subvolumes().await.unwrap();
        assert_eq!(subvols.len(), before_count);
        assert!(!subvols.iter().any(|s| s.path.ends_with("leaked-subvol")));

        drop(writer);
        let fs = Filesystem::mount(disk).await.unwrap();
        let rz = fs.resolve(b"/recv/snap1/z").await.unwrap();
        let rab = fs.resolve(b"/recv/snap1/a/b").await.unwrap();
        assert_eq!(rz.number(), rab.number());
        assert_eq!(rz.metadata().nlink, 2);
        assert_eq!(
            read_all(&fs, "/recv/snap1/z").await,
            b"cross-depth-hardlink"
        );

        let trunc_data = read_all(&fs, "/recv/snap2/trunc.bin").await;
        assert_eq!(trunc_data.len(), 5000);
        assert!(trunc_data[..4096].iter().all(|&b| b == 0x33));
        assert!(trunc_data[4096..].iter().all(|&b| b == 0x44));
    });
}

#[test]
fn reflink_and_dedupe_verify_equality_and_share_extents() {
    block_on(async {
        let disk = SharedDisk::new(base_image());
        let mut writer = mount_writer(disk.clone()).await;

        let payload = vec![0x7c; 32768];
        let mut differing = payload.clone();
        *differing.last_mut().unwrap() ^= 0xff;
        let orig_mtime = Timestamp {
            seconds: 1_700_123_456,
            nanoseconds: 0,
        };
        let later = Timestamp {
            seconds: 1_750_999_000,
            nanoseconds: 0,
        };

        {
            let mut tx = writer.join().await.unwrap();
            let root = tx.root().await.unwrap();
            let a = tx
                .create_file(
                    Name {
                        parent: &root,
                        bytes: b"a.bin",
                    },
                    attrs(0o644, 0, 0),
                    orig_mtime,
                )
                .await
                .unwrap();
            let b = tx
                .create_file(
                    Name {
                        parent: &root,
                        bytes: b"b.bin",
                    },
                    attrs(0o644, 0, 0),
                    orig_mtime,
                )
                .await
                .unwrap();
            let c = tx
                .create_file(
                    Name {
                        parent: &root,
                        bytes: b"c.bin",
                    },
                    attrs(0o644, 0, 0),
                    orig_mtime,
                )
                .await
                .unwrap();
            let cloned = tx
                .create_file(
                    Name {
                        parent: &root,
                        bytes: b"reflinked.bin",
                    },
                    attrs(0o644, 0, 0),
                    orig_mtime,
                )
                .await
                .unwrap();
            tx.write_file(&a, 0, &payload, orig_mtime).await.unwrap();
            tx.write_file(&b, 0, &payload, orig_mtime).await.unwrap();
            tx.write_file(&c, 0, &differing, orig_mtime).await.unwrap();

            tx.clone_range(
                CloneRange {
                    source: &a,
                    destination: &cloned,
                    source_offset: 0,
                    destination_offset: 0,
                    length: payload.len() as u64,
                },
                later,
            )
            .await
            .unwrap();

            // Differing files must NOT dedupe.
            let diff_out = tx
                .dedupe_range(
                    CloneRange {
                        source: &a,
                        destination: &c,
                        source_offset: 0,
                        destination_offset: 0,
                        length: payload.len() as u64,
                    },
                    later,
                )
                .await
                .unwrap();
            assert_eq!(
                diff_out,
                DedupeOutcome {
                    same: false,
                    bytes_deduped: 0
                }
            );

            // Identical files dedupe and preserve destination mtime.
            let same_out = tx
                .dedupe_range(
                    CloneRange {
                        source: &a,
                        destination: &b,
                        source_offset: 0,
                        destination_offset: 0,
                        length: payload.len() as u64,
                    },
                    later,
                )
                .await
                .unwrap();
            assert_eq!(
                same_out,
                DedupeOutcome {
                    same: true,
                    bytes_deduped: payload.len() as u64
                }
            );
            assert_eq!(tx.metadata(&b).await.unwrap().mtime, orig_mtime);
        }
        writer.commit().await.unwrap();

        drop(writer);
        let fs = Filesystem::mount(disk).await.unwrap();
        assert_eq!(read_all(&fs, "/reflinked.bin").await, payload);
        assert_eq!(read_all(&fs, "/b.bin").await, payload);
        assert_eq!(read_all(&fs, "/c.bin").await, differing);
    });
}

#[test]
fn multi_device_balance_resize_replace_remove_and_scrub() {
    block_on(async {
        let dev1 = SharedDisk::new(base_image());
        let dev2 = SharedDisk::blank(VOLUME_BYTES);
        let dev3 = SharedDisk::blank(VOLUME_BYTES);
        let mut writer = mount_writer(dev1.clone()).await;

        let payload = vec![0x5c; 65536];
        {
            let mut tx = writer.join().await.unwrap();
            let root = tx.root().await.unwrap();
            let file = tx
                .create_file(
                    Name {
                        parent: &root,
                        bytes: b"volume-data.bin",
                    },
                    attrs(0o644, 0, 0),
                    WHEN,
                )
                .await
                .unwrap();
            tx.write_file(&file, 0, &payload, WHEN).await.unwrap();
        }
        writer.commit().await.unwrap();

        // Add device 2.
        let added = writer.add_device(dev2.clone()).await.unwrap();
        assert_eq!(added.devid, 2);
        assert_eq!(writer.list_devices().await.unwrap().len(), 2);

        // Balance data chunks.
        let report = writer
            .balance(BalanceFilter {
                data: true,
                metadata: false,
                system: false,
                usage_max_percent: None,
                limit: Some(2),
            })
            .await
            .unwrap();
        assert!(report.considered >= 1);

        // Resize device 2 down and back up.
        let shrunk = writer
            .resize_device(Some(2), ResizeTarget::Bytes(96 << 20))
            .await
            .unwrap();
        assert_eq!(shrunk.total_bytes, 96 << 20);
        let grown = writer
            .resize_device(Some(2), ResizeTarget::Max)
            .await
            .unwrap();
        assert_eq!(grown.total_bytes, VOLUME_BYTES);

        // Replace device 2 with device 3.
        let replaced = writer.replace_device(2, dev3.clone()).await.unwrap();
        assert_eq!(replaced.devid, 2);
        // Old dev2 superblock must be wiped.
        assert!(Filesystem::mount(dev2.clone()).await.is_err());

        // Multi-device read-only mount sees the full file intact.
        let multi_ro = Filesystem::mount_devices(vec![dev1.clone(), dev3.clone()])
            .await
            .unwrap();
        assert_eq!(read_all(&multi_ro, "/volume-data.bin").await, payload);
        drop(multi_ro);

        // Remove device 2 (dev3): relocates any chunks off dev3 and wipes dev3.
        writer.remove_device(2).await.unwrap();
        assert_eq!(writer.list_devices().await.unwrap().len(), 1);
        assert!(Filesystem::mount(dev3.clone()).await.is_err());

        // Removing the last remaining device must fail with LastDevice.
        assert!(matches!(
            writer.remove_device(1).await,
            Err(WriteError::LastDevice)
        ));

        // Clean scrub reports zero errors and non-zero scrubbed bytes.
        let clean = writer.scrub(None, true).await.unwrap();
        assert_eq!(clean.csum_errors, 0);
        assert_eq!(clean.verify_errors, 0);
        assert_eq!(clean.uncorrectable_errors, 0);
        assert!(clean.tree_extents_scrubbed > 0);
        assert!(clean.data_extents_scrubbed > 0);

        drop(writer);
        let single_ro = Filesystem::mount(dev1).await.unwrap();
        assert_eq!(read_all(&single_ro, "/volume-data.bin").await, payload);
    });
}

#[test]
fn quota_groups_lifecycle_limits_and_remount() {
    block_on(async {
        let disk = SharedDisk::new(base_image());
        let mut writer = mount_writer(disk.clone()).await;

        assert!(!writer.quota_status().await.unwrap().enabled);
        writer.quota_enable().await.unwrap();
        assert!(writer.quota_status().await.unwrap().enabled);
        assert!(matches!(
            writer.quota_enable().await,
            Err(WriteError::QuotaAlreadyEnabled)
        ));

        let s1 = writer
            .create_subvolume("", b"s1", attrs(0o755, 0, 0), WHEN)
            .await
            .unwrap();
        let s2 = writer
            .create_subvolume("", b"s2", attrs(0o755, 0, 0), WHEN)
            .await
            .unwrap();

        let q1 = QgroupId::new(0, s1.id).unwrap();
        let q2 = QgroupId::new(0, s2.id).unwrap();
        let parent_qg = QgroupId::new(1, 100).unwrap();
        writer.qgroup_create(parent_qg).await.unwrap();
        writer.qgroup_assign(q1, parent_qg).await.unwrap();
        writer.qgroup_assign(q2, parent_qg).await.unwrap();

        {
            let mut tx = writer.join().await.unwrap();
            let root = tx.root().await.unwrap();
            let d1 = tx.lookup(&root, b"s1").await.unwrap().unwrap();
            let f1 = tx
                .create_file(
                    Name {
                        parent: &d1,
                        bytes: b"data.bin",
                    },
                    attrs(0o644, 0, 0),
                    WHEN,
                )
                .await
                .unwrap();
            tx.write_file(&f1, 0, &vec![0x11; 32768], WHEN)
                .await
                .unwrap();
        }
        writer.commit().await.unwrap();

        let groups = writer.list_qgroups().await.unwrap();
        let info_q1 = groups.iter().find(|g| g.id == q1).unwrap();
        let info_parent = groups.iter().find(|g| g.id == parent_qg).unwrap();
        assert!(info_q1.referenced_bytes >= 32768);
        assert!(info_parent.referenced_bytes >= info_q1.referenced_bytes);

        // Enforce tight limit on s2 and verify write is rejected with QuotaExceeded.
        writer
            .qgroup_limit(
                q2,
                QgroupLimit {
                    max_referenced: Some(4096),
                    max_exclusive: None,
                },
            )
            .await
            .unwrap();
        {
            let mut tx = writer.join().await.unwrap();
            let root = tx.root().await.unwrap();
            let d2 = tx.lookup(&root, b"s2").await.unwrap().unwrap();
            let f2 = tx
                .create_file(
                    Name {
                        parent: &d2,
                        bytes: b"over.bin",
                    },
                    attrs(0o644, 0, 0),
                    WHEN,
                )
                .await
                .unwrap();
            let err = tx
                .write_file(&f2, 0, &vec![0x22; 65536], WHEN)
                .await
                .unwrap_err();
            assert!(matches!(err, WriteError::QuotaExceeded));
        }

        // Remount writable and verify quota tree loads cleanly.
        drop(writer);
        let mut remounted = mount_writer(disk).await;
        assert!(remounted.quota_status().await.unwrap().enabled);
        remounted.quota_rescan().await.unwrap();
        remounted.qgroup_remove(q1, parent_qg).await.unwrap();
        remounted.qgroup_remove(q2, parent_qg).await.unwrap();
        remounted.qgroup_destroy(parent_qg).await.unwrap();
        remounted.quota_disable().await.unwrap();
        assert!(!remounted.quota_status().await.unwrap().enabled);
    });
}

#[cfg(target_os = "linux")]
mod linux_interop {
    use std::io::{Seek, SeekFrom};
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::process::{Command, Stdio};

    use super::*;

    fn sudo(args: &[&str]) {
        let out = Command::new("sudo")
            .args(args)
            .output()
            .expect("sudo must be installed");
        assert!(
            out.status.success(),
            "sudo {args:?} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn sudo_output(args: &[&str]) -> Vec<u8> {
        let out = Command::new("sudo")
            .args(args)
            .output()
            .expect("sudo must be installed");
        assert!(
            out.status.success(),
            "sudo {args:?} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    fn dump_and_btrfs_check(disk: &SharedDisk) -> tempfile::NamedTempFile {
        let scratch = tempfile::NamedTempFile::new().unwrap();
        {
            let mut guard = disk.0.lock().unwrap();
            guard.seek(SeekFrom::Start(0)).unwrap();
            std::io::copy(&mut *guard, &mut scratch.reopen().unwrap()).unwrap();
        }
        let check = Command::new("btrfs")
            .args(["check", "--readonly"])
            .arg(scratch.path())
            .output()
            .expect("btrfs-progs must be installed");
        assert!(
            check.status.success(),
            "btrfs check failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&check.stdout),
            String::from_utf8_lossy(&check.stderr)
        );
        scratch
    }

    fn copy_file_to_disk(path: &Path) -> SharedDisk {
        let bytes = std::fs::read(path).unwrap();
        let mut sparse = SparseImage::new(bytes.len() as u64);
        sparse.write_bytes(0, &bytes);
        SharedDisk::new(sparse)
    }

    /// Proves Linux `btrfs check --readonly` AND a real Linux kernel mount read
    /// the result of every Helios management operation cleanly: subvolume
    /// create/delete, RO & RW snapshots, reflink, dedupe, balance, resize,
    /// multi-device add/replace/remove, scrub, and quota groups.
    #[test]
    #[ignore = "needs mkfs.btrfs, btrfs-progs and sudo mount on Linux; CI runs it in test-btrfs-mkfs / test-btrfs-fstests"]
    fn linux_reads_every_helios_management_operation_and_btrfs_check_is_clean() {
        let seed = tempfile::tempdir().unwrap();
        std::fs::write(seed.path().join("seed.txt"), b"initial\n").unwrap();
        let image = super::super::mkfs::mkfs_sized(seed.path(), 128 << 20, &[]);
        let dev1 = SharedDisk::new(image);
        let dev2 = SharedDisk::blank(128 << 20);
        let dev3 = SharedDisk::blank(128 << 20);

        block_on(async {
            let mut writer = mount_writer(dev1.clone()).await;

            // 1. Subvolume create, write, RO + RW snapshots, CoW divergence, delete.
            let sub = writer
                .create_subvolume("", b"sub-a", attrs(0o755, 0, 0), WHEN)
                .await
                .unwrap();
            {
                let mut tx = writer.join().await.unwrap();
                let root = tx.root().await.unwrap();
                let dir = tx.lookup(&root, b"sub-a").await.unwrap().unwrap();
                let f1 = tx
                    .create_file(
                        Name {
                            parent: &dir,
                            bytes: "中文-日本語-한국어.dat".as_bytes(),
                        },
                        attrs(0o644, 0, 0),
                        WHEN,
                    )
                    .await
                    .unwrap();
                tx.write_file(&f1, 0, &vec![0x42; 32768], WHEN)
                    .await
                    .unwrap();
                let f2 = tx
                    .create_file(
                        Name {
                            parent: &dir,
                            bytes: b"dup.dat",
                        },
                        attrs(0o644, 0, 0),
                        WHEN,
                    )
                    .await
                    .unwrap();
                tx.write_file(&f2, 0, &vec![0x42; 32768], WHEN)
                    .await
                    .unwrap();
                let f3 = tx
                    .create_file(
                        Name {
                            parent: &dir,
                            bytes: b"reflink.dat",
                        },
                        attrs(0o644, 0, 0),
                        WHEN,
                    )
                    .await
                    .unwrap();
                tx.clone_range(
                    CloneRange {
                        source: &f1,
                        destination: &f3,
                        source_offset: 0,
                        destination_offset: 0,
                        length: 32768,
                    },
                    WHEN,
                )
                .await
                .unwrap();
                let dedupe = tx
                    .dedupe_range(
                        CloneRange {
                            source: &f1,
                            destination: &f2,
                            source_offset: 0,
                            destination_offset: 0,
                            length: 32768,
                        },
                        WHEN,
                    )
                    .await
                    .unwrap();
                assert!(dedupe.same);
            }
            writer.commit().await.unwrap();

            let _snap_ro = writer
                .snapshot_subvolume(sub.id, "", b"snap-ro", true, WHEN)
                .await
                .unwrap();
            let snap_rw = writer
                .snapshot_subvolume(sub.id, "", b"snap-rw", false, WHEN)
                .await
                .unwrap();
            let temp_sub = writer
                .create_subvolume("", b"temp-del", attrs(0o755, 0, 0), WHEN)
                .await
                .unwrap();
            assert_eq!(temp_sub.path, "temp-del");
            writer
                .delete_subvolume("", b"temp-del", WHEN)
                .await
                .unwrap();

            // 2. Multi-device add, balance, resize, replace, remove, scrub.
            writer.add_device(dev2.clone()).await.unwrap();
            writer
                .balance(BalanceFilter {
                    data: true,
                    metadata: false,
                    system: false,
                    usage_max_percent: None,
                    limit: Some(1),
                })
                .await
                .unwrap();
            writer
                .resize_device(Some(2), ResizeTarget::Bytes(112 << 20))
                .await
                .unwrap();
            writer.replace_device(2, dev3.clone()).await.unwrap();
            writer.remove_device(2).await.unwrap();
            let scrub = writer.scrub(None, true).await.unwrap();
            assert_eq!(scrub.uncorrectable_errors, 0);

            // 3. Quota groups enabled and assigned.
            writer.quota_enable().await.unwrap();
            let parent_qg = QgroupId::new(1, 50).unwrap();
            writer.qgroup_create(parent_qg).await.unwrap();
            writer
                .qgroup_assign(QgroupId::new(0, snap_rw.id).unwrap(), parent_qg)
                .await
                .unwrap();
            writer.quota_rescan().await.unwrap();
        });

        let checked = dump_and_btrfs_check(&dev1);
        let mnt = tempfile::tempdir().unwrap();
        let mnt_str = mnt.path().to_str().unwrap();
        sudo(&[
            "mount",
            "-t",
            "btrfs",
            "-o",
            "loop,ro",
            checked.path().to_str().unwrap(),
            mnt_str,
        ]);
        let check_mount = (|| -> std::io::Result<()> {
            assert_eq!(
                std::fs::read(mnt.path().join("snap-ro/中文-日本語-한국어.dat"))?,
                vec![0x42; 32768]
            );
            assert_eq!(
                std::fs::read(mnt.path().join("snap-rw/reflink.dat"))?,
                vec![0x42; 32768]
            );
            assert_eq!(
                std::fs::read(mnt.path().join("sub-a/dup.dat"))?,
                vec![0x42; 32768]
            );
            assert!(!mnt.path().join("temp-del").exists());
            let subs =
                String::from_utf8(sudo_output(&["btrfs", "subvolume", "list", mnt_str])).unwrap();
            assert!(subs.contains("sub-a"), "subvolume list: {subs}");
            assert!(subs.contains("snap-ro"), "subvolume list: {subs}");
            assert!(subs.contains("snap-rw"), "subvolume list: {subs}");
            let qgroups =
                String::from_utf8(sudo_output(&["btrfs", "qgroup", "show", mnt_str])).unwrap();
            assert!(qgroups.contains("1/50"), "qgroup show: {qgroups}");
            Ok(())
        })();
        sudo(&["umount", mnt_str]);
        check_mount.unwrap();
    }

    /// Proves bidirectional interoperability:
    /// 1. Linux `btrfs send` (full & incremental) -> Helios `receive_subvolume`
    ///    -> `btrfs check --readonly` + Linux mount verification.
    /// 2. Helios `send_subvolume` (full & incremental) -> Linux `btrfs receive`
    ///    on a real Linux btrfs mount + metadata/data/xattr verification.
    #[test]
    #[ignore = "needs mkfs.btrfs, btrfs send/receive and sudo mount on Linux; CI runs it in test-btrfs-mkfs / test-btrfs-fstests"]
    fn bidirectional_send_receive_interop_with_linux() {
        let work = tempfile::tempdir().unwrap();

        // === Direction 1: Linux `btrfs send` (full + incremental) -> Helios receive ===
        let linux_img = work.path().join("linux-src.img");
        let linux_mnt = work.path().join("linux-mnt");
        std::fs::create_dir(&linux_mnt).unwrap();
        let f = std::fs::File::create(&linux_img).unwrap();
        f.set_len(256 << 20).unwrap();
        drop(f);
        sudo(&["mkfs.btrfs", "-f", linux_img.to_str().unwrap()]);
        sudo(&[
            "mount",
            "-t",
            "btrfs",
            "-o",
            "loop,acl",
            linux_img.to_str().unwrap(),
            linux_mnt.to_str().unwrap(),
        ]);

        let linux_full_path = work.path().join("linux-full.stream");
        let linux_inc_path = work.path().join("linux-inc.stream");
        let make_linux_streams = (|| -> std::io::Result<()> {
            let sub = linux_mnt.join("src");
            let v1 = linux_mnt.join("v1");
            let v2 = linux_mnt.join("v2");
            sudo(&["btrfs", "subvolume", "create", sub.to_str().unwrap()]);
            sudo(&["mkdir", "-p", sub.join("目录").to_str().unwrap()]);
            let file_path = sub.join("目录/中文-日本語-한국어.txt");
            sudo(&[
                "sh",
                "-c",
                &format!(
                    "printf 'hello-from-linux-v1' > '{}' && chown 1000:2000 '{}' && chmod 4755 '{}'",
                    file_path.display(),
                    file_path.display(),
                    file_path.display(),
                ),
            ]);
            sudo(&[
                "setfattr",
                "-n",
                "user.origin",
                "-v",
                "linux",
                file_path.to_str().unwrap(),
            ]);
            sudo(&[
                "setfattr",
                "-n",
                "trusted.helios",
                "-v",
                "tr-val",
                file_path.to_str().unwrap(),
            ]);
            sudo(&[
                "setfattr",
                "-n",
                "security.helios",
                "-v",
                "sec-val",
                file_path.to_str().unwrap(),
            ]);
            sudo(&["setfacl", "-m", "u:1000:r-x", file_path.to_str().unwrap()]);
            sudo(&["chmod", "4755", file_path.to_str().unwrap()]);
            sudo(&[
                "ln",
                file_path.to_str().unwrap(),
                sub.join("hl.txt").to_str().unwrap(),
            ]);
            sudo(&[
                "ln",
                "-s",
                "目录/中文-日本語-한국어.txt",
                sub.join("sym.txt").to_str().unwrap(),
            ]);
            sudo(&[
                "mknod",
                sub.join("chr-null").to_str().unwrap(),
                "c",
                "1",
                "3",
            ]);
            sudo(&[
                "btrfs",
                "subvolume",
                "snapshot",
                "-r",
                sub.to_str().unwrap(),
                v1.to_str().unwrap(),
            ]);

            // Incremental change for v2.
            sudo(&[
                "sh",
                "-c",
                &format!("printf 'v2-added' > '{}'", sub.join("v2.txt").display()),
            ]);
            sudo(&[
                "btrfs",
                "subvolume",
                "snapshot",
                "-r",
                sub.to_str().unwrap(),
                v2.to_str().unwrap(),
            ]);

            let full = sudo_output(&["btrfs", "send", v1.to_str().unwrap()]);
            std::fs::write(&linux_full_path, &full)?;
            let inc = sudo_output(&[
                "btrfs",
                "send",
                "-p",
                v1.to_str().unwrap(),
                v2.to_str().unwrap(),
            ]);
            std::fs::write(&linux_inc_path, &inc)?;
            Ok(())
        })();
        sudo(&["umount", linux_mnt.to_str().unwrap()]);
        make_linux_streams.unwrap();

        let linux_full = std::fs::read(&linux_full_path).unwrap();
        let linux_inc = std::fs::read(&linux_inc_path).unwrap();

        // Receive both Linux streams into a fresh Helios-written btrfs image.
        let helios_dst_img = work.path().join("helios-recv.img");
        let f = std::fs::File::create(&helios_dst_img).unwrap();
        f.set_len(256 << 20).unwrap();
        drop(f);
        sudo(&["mkfs.btrfs", "-f", helios_dst_img.to_str().unwrap()]);
        let helios_disk = copy_file_to_disk(&helios_dst_img);

        let (helios_full_stream, helios_inc_stream) = block_on(async {
            let mut writer = mount_writer(helios_disk.clone()).await;
            let recv1 = writer
                .receive_subvolume("", &linux_full, WHEN, |_| Ok(()))
                .await
                .unwrap();
            let recv2 = writer
                .receive_subvolume("", &linux_inc, WHEN, |_| Ok(()))
                .await
                .unwrap();

            // === Direction 2: Helios `send_subvolume` (full + incremental) ===
            let h_full = writer.send_subvolume(recv1.id, None, &[]).await.unwrap();
            let h_inc = writer
                .send_subvolume(recv2.id, Some(recv1.id), &[])
                .await
                .unwrap();
            (h_full, h_inc)
        });

        // Verify Helios-received image with `btrfs check --readonly` AND Linux mount!
        let checked = dump_and_btrfs_check(&helios_disk);
        let verify_mnt = work.path().join("verify-helios");
        std::fs::create_dir(&verify_mnt).unwrap();
        sudo(&[
            "mount",
            "-t",
            "btrfs",
            "-o",
            "loop,ro",
            checked.path().to_str().unwrap(),
            verify_mnt.to_str().unwrap(),
        ]);
        let check_helios_recv = (|| -> std::io::Result<()> {
            let p1 = verify_mnt.join("v1/目录/中文-日本語-한국어.txt");
            let meta = std::fs::symlink_metadata(&p1)?;
            assert_eq!(meta.uid(), 1000);
            assert_eq!(meta.gid(), 2000);
            assert_eq!(meta.mode() & 0o7777, 0o4755);
            assert_eq!(std::fs::read(&p1)?, b"hello-from-linux-v1");
            assert_eq!(
                std::fs::symlink_metadata(verify_mnt.join("v1/hl.txt"))?.ino(),
                meta.ino()
            );
            assert_eq!(
                std::fs::read_link(verify_mnt.join("v1/sym.txt"))?,
                Path::new("目录/中文-日本語-한국어.txt")
            );
            let chr = std::fs::symlink_metadata(verify_mnt.join("v1/chr-null"))?;
            assert_eq!(
                chr.rdev(),
                u64::from(DeviceNumber::new(1, 3).unwrap().encode())
            );
            assert_eq!(
                sudo_output(&[
                    "getfattr",
                    "-h",
                    "--absolute-names",
                    "--only-values",
                    "-n",
                    "user.origin",
                    p1.to_str().unwrap(),
                ]),
                b"linux"
            );
            assert_eq!(
                sudo_output(&[
                    "getfattr",
                    "-h",
                    "--absolute-names",
                    "--only-values",
                    "-n",
                    "trusted.helios",
                    p1.to_str().unwrap(),
                ]),
                b"tr-val"
            );
            assert_eq!(
                sudo_output(&[
                    "getfattr",
                    "-h",
                    "--absolute-names",
                    "--only-values",
                    "-n",
                    "security.helios",
                    p1.to_str().unwrap(),
                ]),
                b"sec-val"
            );
            assert!(
                !sudo_output(&[
                    "getfattr",
                    "-h",
                    "--absolute-names",
                    "--only-values",
                    "-n",
                    "system.posix_acl_access",
                    p1.to_str().unwrap(),
                ])
                .is_empty()
            );
            assert_eq!(std::fs::read(verify_mnt.join("v2/v2.txt"))?, b"v2-added");
            Ok(())
        })();
        sudo(&["umount", verify_mnt.to_str().unwrap()]);
        check_helios_recv.unwrap();

        // Feed Helios's full and incremental send streams into Linux `btrfs receive`!
        let linux_recv_img = work.path().join("linux-recv.img");
        let linux_recv_mnt = work.path().join("linux-recv-mnt");
        std::fs::create_dir(&linux_recv_mnt).unwrap();
        let f = std::fs::File::create(&linux_recv_img).unwrap();
        f.set_len(256 << 20).unwrap();
        drop(f);
        sudo(&["mkfs.btrfs", "-f", linux_recv_img.to_str().unwrap()]);
        sudo(&[
            "mount",
            "-t",
            "btrfs",
            "-o",
            "loop,acl",
            linux_recv_img.to_str().unwrap(),
            linux_recv_mnt.to_str().unwrap(),
        ]);

        let pipe_to_linux_receive = |stream: &[u8]| {
            use std::io::Write;
            let mut child = Command::new("sudo")
                .args(["btrfs", "receive", linux_recv_mnt.to_str().unwrap()])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn btrfs receive");
            child.stdin.as_mut().unwrap().write_all(stream).unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "Linux btrfs receive failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        };

        let check_linux_recv = (|| -> std::io::Result<()> {
            pipe_to_linux_receive(&helios_full_stream);
            pipe_to_linux_receive(&helios_inc_stream);
            let p1 = linux_recv_mnt.join("v1/目录/中文-日本語-한국어.txt");
            let meta = std::fs::symlink_metadata(&p1)?;
            assert_eq!(meta.uid(), 1000);
            assert_eq!(meta.gid(), 2000);
            assert_eq!(meta.mode() & 0o7777, 0o4755);
            assert_eq!(std::fs::read(&p1)?, b"hello-from-linux-v1");
            assert_eq!(
                std::fs::symlink_metadata(linux_recv_mnt.join("v1/hl.txt"))?.ino(),
                meta.ino()
            );
            assert_eq!(
                std::fs::read_link(linux_recv_mnt.join("v1/sym.txt"))?,
                Path::new("目录/中文-日本語-한국어.txt")
            );
            let chr = std::fs::symlink_metadata(linux_recv_mnt.join("v1/chr-null"))?;
            assert_eq!(
                chr.rdev(),
                u64::from(DeviceNumber::new(1, 3).unwrap().encode())
            );
            assert_eq!(
                sudo_output(&[
                    "getfattr",
                    "-h",
                    "--absolute-names",
                    "--only-values",
                    "-n",
                    "user.origin",
                    p1.to_str().unwrap(),
                ]),
                b"linux"
            );
            assert_eq!(
                sudo_output(&[
                    "getfattr",
                    "-h",
                    "--absolute-names",
                    "--only-values",
                    "-n",
                    "trusted.helios",
                    p1.to_str().unwrap(),
                ]),
                b"tr-val"
            );
            assert_eq!(
                sudo_output(&[
                    "getfattr",
                    "-h",
                    "--absolute-names",
                    "--only-values",
                    "-n",
                    "security.helios",
                    p1.to_str().unwrap(),
                ]),
                b"sec-val"
            );
            assert!(
                !sudo_output(&[
                    "getfattr",
                    "-h",
                    "--absolute-names",
                    "--only-values",
                    "-n",
                    "system.posix_acl_access",
                    p1.to_str().unwrap(),
                ])
                .is_empty()
            );
            assert_eq!(
                std::fs::read(linux_recv_mnt.join("v2/v2.txt"))?,
                b"v2-added"
            );
            Ok(())
        })();
        sudo(&["umount", linux_recv_mnt.to_str().unwrap()]);
        check_linux_recv.unwrap();
    }
}
