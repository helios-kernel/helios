//! Unlinked-but-open files, `O_TMPFILE`, and mount-time orphan cleanup.

extern crate std;

use alloc::vec;
use ferrosys::{Metadata, Timestamp as ImageTime, TreeBuilder};
use futures_lite::future::block_on;
use helios_hal::fs::RenameMode;

use super::{Disk, FixtureUuids, assert_btrfs_check, filesystem_image_tree_file, mount_writer};
use crate::fs::Filesystem;
use crate::fs::writer::{Attributes, Name, Writer};
use crate::ondisk::{item_type, objectid};
use crate::tree::Cursor;
use crate::tree::write::WriteError;
use crate::write::XattrMode;
use crate::{Key, Timestamp};

fn when(second: i64) -> Timestamp {
    Timestamp {
        seconds: 1_700_000_000 + second,
        nanoseconds: 11,
    }
}

type DiskWriter = Writer<Disk, FixtureUuids>;

fn mounted(tree: TreeBuilder) -> (tempfile::NamedTempFile, DiskWriter) {
    let named = tempfile::NamedTempFile::new().unwrap();
    drop(filesystem_image_tree_file(
        true,
        true,
        tree,
        named.reopen().unwrap(),
    ));
    let writer = block_on(mount_writer(Disk(named.reopen().unwrap()))).unwrap();
    (named, writer)
}

fn empty_image() -> (tempfile::NamedTempFile, DiskWriter) {
    let stamp = ImageTime::from_secs(1_700_000_000);
    let tree = TreeBuilder::new().root(Metadata::new(0o755, stamp));
    mounted(tree)
}

async fn has_orphan_item(fs: &Filesystem<Disk>, tree: u64, inode: u64) -> bool {
    let key = Key::new(objectid::ORPHAN, item_type::ORPHAN_ITEM, inode);
    let nodes = fs.snapshot.nodes(&fs.volume);
    let record = fs.snapshot.find_root(&nodes, tree).await.unwrap();
    let cursor = Cursor::ceiling(&nodes, record.root, key).await.unwrap();
    match cursor.key() {
        Some(found) if found == key => {
            assert!(
                cursor.item().unwrap().is_empty(),
                "orphan item payload must be 0 bytes"
            );
            true
        }
        _ => false,
    }
}

#[test]
fn unlinked_open_file_keeps_orphan_item_io_and_space_until_final_release() {
    let (image, mut writer) = empty_image();
    block_on(async {
        let mut tx = writer.join().await.unwrap();
        let root = tx.root().await.unwrap();
        let attrs = Attributes {
            permissions: 0o644,
            uid: 0,
            gid: 0,
            umask: 0,
        };
        let file = tx
            .create_file(
                Name {
                    parent: &root,
                    bytes: b"ephemeral.bin",
                },
                attrs,
                when(1),
            )
            .await
            .unwrap();
        let payload = vec![0x5a; 32 * 1024];
        tx.write_file(&file, 0, &payload, when(1)).await.unwrap();
        tx.set_xattr(&file, b"user.tag", b"alive", XattrMode::Create, when(1))
            .await
            .unwrap();
        // Retain two open handles before unlinking.
        tx.open_inode(&file).await.unwrap();
        tx.open_inode(&file).await.unwrap();
        tx.commit().await.unwrap();

        let used_while_linked = writer.usage().unwrap().used_bytes;

        // Unlink the only name while two handles remain open.
        let mut tx = writer.join().await.unwrap();
        let root = tx.root().await.unwrap();
        tx.unlink_name(
            Name {
                parent: &root,
                bytes: b"ephemeral.bin",
            },
            when(2),
        )
        .await
        .unwrap();
        assert!(tx.lookup(&root, b"ephemeral.bin").await.unwrap().is_none());
        let meta = tx.metadata(&file).await.unwrap();
        assert_eq!(meta.nlink, 0);
        tx.commit().await.unwrap();

        assert!(writer.has_open_orphans());
        // Space stays allocated while an open handle retains the inode.
        assert!(writer.usage().unwrap().used_bytes >= used_while_linked);

        let ro = Filesystem::mount(Disk(image.reopen().unwrap()))
            .await
            .unwrap();
        assert!(has_orphan_item(&ro, file.tree(), file.number()).await);
        drop(ro);

        // Reads, writes, truncate, metadata, xattrs all keep working through the handle.
        let mut tx = writer.join().await.unwrap();
        let mut buf = vec![0; payload.len()];
        assert_eq!(tx.read_file(&file, 0, &mut buf).await.unwrap(), buf.len());
        assert_eq!(buf, payload);
        tx.write_file(&file, 0, b"updated", when(3)).await.unwrap();
        tx.truncate_file(&file, 16 * 1024, when(3)).await.unwrap();
        tx.set_permissions(&file, 0o600, when(3)).await.unwrap();
        tx.set_owner(&file, Some(1000), Some(1000), when(3))
            .await
            .unwrap();
        tx.set_times(&file, Some(when(4)), Some(when(5)), when(5))
            .await
            .unwrap();
        tx.set_xattr(&file, b"user.tag", b"mutated", XattrMode::Replace, when(5))
            .await
            .unwrap();
        let mut xval = [0; 16];
        let xlen = tx.xattr(&file, b"user.tag", &mut xval).await.unwrap();
        assert_eq!(&xval[..xlen], b"mutated");
        let meta = tx.metadata(&file).await.unwrap();
        assert_eq!(meta.nlink, 0);
        assert_eq!(meta.size, 16 * 1024);
        assert_eq!(meta.permissions, 0o600);
        assert_eq!((meta.uid, meta.gid), (1000, 1000));

        // Re-linking a previously named file whose nlink dropped to 0 is refused.
        let root = tx.root().await.unwrap();
        assert!(matches!(
            tx.hard_link(
                Name {
                    parent: &root,
                    bytes: b"revived",
                },
                &file,
                when(6),
            )
            .await,
            Err(WriteError::UnlinkedInode { .. })
        ));

        // First release keeps the orphan alive.
        assert!(!tx.release_inode(&file).await.unwrap());
        tx.commit().await.unwrap();
        assert!(writer.has_open_orphans());

        // Final release deletes the inode, extents, xattrs, and orphan item.
        let mut tx = writer.join().await.unwrap();
        assert!(tx.release_inode(&file).await.unwrap());
        tx.commit().await.unwrap();
        assert!(!writer.has_open_orphans());

        let snapshot = writer.snapshot().unwrap();
        assert!(snapshot.inode(file.tree(), file.number()).await.is_err());
        let ro = Filesystem::mount(Disk(image.reopen().unwrap()))
            .await
            .unwrap();
        assert!(!has_orphan_item(&ro, file.tree(), file.number()).await);
        drop(ro);
    });
}

#[test]
fn rename_overwrite_of_open_file_and_open_directory_defers_deletion() {
    let (_image, mut writer) = empty_image();
    block_on(async {
        let mut tx = writer.join().await.unwrap();
        let root = tx.root().await.unwrap();
        let file_attrs = Attributes {
            permissions: 0o644,
            uid: 0,
            gid: 0,
            umask: 0,
        };
        let dir_attrs = Attributes {
            permissions: 0o755,
            uid: 0,
            gid: 0,
            umask: 0,
        };
        let src = tx
            .create_file(
                Name {
                    parent: &root,
                    bytes: b"src",
                },
                file_attrs,
                when(1),
            )
            .await
            .unwrap();
        let dst = tx
            .create_file(
                Name {
                    parent: &root,
                    bytes: b"dst",
                },
                file_attrs,
                when(1),
            )
            .await
            .unwrap();
        tx.write_file(&src, 0, b"new", when(1)).await.unwrap();
        tx.write_file(&dst, 0, b"old", when(1)).await.unwrap();
        tx.open_inode(&dst).await.unwrap();

        let _dir_src = tx
            .create_directory(
                Name {
                    parent: &root,
                    bytes: b"dir_src",
                },
                dir_attrs,
                when(1),
            )
            .await
            .unwrap();
        let dir_dst = tx
            .create_directory(
                Name {
                    parent: &root,
                    bytes: b"dir_dst",
                },
                dir_attrs,
                when(1),
            )
            .await
            .unwrap();
        tx.open_inode(&dir_dst).await.unwrap();

        tx.rename(
            Name {
                parent: &root,
                bytes: b"src",
            },
            Name {
                parent: &root,
                bytes: b"dst",
            },
            RenameMode::Replace,
            when(2),
        )
        .await
        .unwrap();
        tx.rename(
            Name {
                parent: &root,
                bytes: b"dir_src",
            },
            Name {
                parent: &root,
                bytes: b"dir_dst",
            },
            RenameMode::Replace,
            when(2),
        )
        .await
        .unwrap();

        assert_eq!(tx.metadata(&dst).await.unwrap().nlink, 0);
        assert_eq!(tx.metadata(&dir_dst).await.unwrap().nlink, 0);
        let mut old = [0; 3];
        assert_eq!(tx.read_file(&dst, 0, &mut old).await.unwrap(), 3);
        assert_eq!(&old, b"old");
        tx.commit().await.unwrap();

        assert!(writer.has_open_orphans());
        let mut tx = writer.join().await.unwrap();
        assert!(tx.release_inode(&dst).await.unwrap());
        assert!(tx.release_inode(&dir_dst).await.unwrap());
        tx.commit().await.unwrap();
        assert!(!writer.has_open_orphans());
    });
}

#[test]
fn tmpfile_creates_orphan_inherits_sgid_and_links_cleanly() {
    let (image, mut writer) = empty_image();
    block_on(async {
        let mut tx = writer.join().await.unwrap();
        let root = tx.root().await.unwrap();
        let parent = tx
            .create_directory(
                Name {
                    parent: &root,
                    bytes: b"sgid",
                },
                Attributes {
                    permissions: 0o2755,
                    uid: 0,
                    gid: 42,
                    umask: 0,
                },
                when(1),
            )
            .await
            .unwrap();
        let parent_before = tx.metadata(&parent).await.unwrap();

        // Create linkable O_TMPFILE under `parent`.
        let tmp = tx
            .create_tmpfile(
                &parent,
                Attributes {
                    permissions: 0o644,
                    uid: 1000,
                    gid: 1000,
                    umask: 0o022,
                },
                true,
                when(2),
            )
            .await
            .unwrap();
        let tmp_meta = tx.metadata(&tmp).await.unwrap();
        assert_eq!(tmp_meta.nlink, 0);
        assert_eq!(tmp_meta.gid, 42, "O_TMPFILE inherits S_ISGID parent gid");
        assert_eq!(tmp_meta.permissions, 0o644 & !0o022);
        // Parent directory metadata is unchanged by O_TMPFILE.
        assert_eq!(
            tx.metadata(&parent).await.unwrap().mtime,
            parent_before.mtime
        );
        assert_eq!(tx.metadata(&parent).await.unwrap().size, parent_before.size);

        tx.write_file(&tmp, 0, b"staged-tmpfile", when(2))
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(writer.has_open_orphans());
        let ro = Filesystem::mount(Disk(image.reopen().unwrap()))
            .await
            .unwrap();
        assert!(has_orphan_item(&ro, tmp.tree(), tmp.number()).await);
        drop(ro);

        // Materialize via hard_link: nlink 0 -> 1, orphan item removed.
        let mut tx = writer.join().await.unwrap();
        tx.hard_link(
            Name {
                parent: &parent,
                bytes: b"materialized",
            },
            &tmp,
            when(3),
        )
        .await
        .unwrap();
        assert_eq!(tx.metadata(&tmp).await.unwrap().nlink, 1);
        tx.commit().await.unwrap();
        assert!(!writer.has_open_orphans());

        let ro = Filesystem::mount(Disk(image.reopen().unwrap()))
            .await
            .unwrap();
        assert!(!has_orphan_item(&ro, tmp.tree(), tmp.number()).await);
        drop(ro);

        // Unlinking the now-named file while still open creates an orphan that
        // can no longer be re-linked.
        let mut tx = writer.join().await.unwrap();
        tx.unlink_name(
            Name {
                parent: &parent,
                bytes: b"materialized",
            },
            when(4),
        )
        .await
        .unwrap();
        assert_eq!(tx.metadata(&tmp).await.unwrap().nlink, 0);
        assert!(matches!(
            tx.hard_link(
                Name {
                    parent: &parent,
                    bytes: b"again",
                },
                &tmp,
                when(4),
            )
            .await,
            Err(WriteError::UnlinkedInode { .. })
        ));
        assert!(tx.release_inode(&tmp).await.unwrap());

        // Non-linkable O_TMPFILE | O_EXCL refuses hard_link from the start.
        let excl = tx
            .create_tmpfile(
                &parent,
                Attributes {
                    permissions: 0o600,
                    uid: 0,
                    gid: 0,
                    umask: 0,
                },
                false,
                when(5),
            )
            .await
            .unwrap();
        assert!(matches!(
            tx.hard_link(
                Name {
                    parent: &parent,
                    bytes: b"forbidden",
                },
                &excl,
                when(5),
            )
            .await,
            Err(WriteError::UnlinkedInode { .. })
        ));
        assert!(tx.release_inode(&excl).await.unwrap());
        tx.commit().await.unwrap();
        assert!(!writer.has_open_orphans());
    });
}

#[test]
fn mount_cleans_up_orphans_left_by_crash_and_passes_btrfs_check() {
    let (image, mut writer) = empty_image();
    block_on(async {
        let mut tx = writer.join().await.unwrap();
        let root = tx.root().await.unwrap();
        let attrs = Attributes {
            permissions: 0o644,
            uid: 0,
            gid: 0,
            umask: 0,
        };
        let surviving = tx
            .create_file(
                Name {
                    parent: &root,
                    bytes: "中文-日本語-한국어".as_bytes(),
                },
                attrs,
                when(1),
            )
            .await
            .unwrap();
        tx.write_file(&surviving, 0, b"keep-me", when(1))
            .await
            .unwrap();

        // 1. Unlinked-while-open regular file with extents and xattrs.
        let unlinked = tx
            .create_file(
                Name {
                    parent: &root,
                    bytes: b"doomed",
                },
                attrs,
                when(1),
            )
            .await
            .unwrap();
        tx.write_file(&unlinked, 0, &vec![0xab; 32 * 1024], when(1))
            .await
            .unwrap();
        tx.set_xattr(&unlinked, b"user.k", b"v", XattrMode::Create, when(1))
            .await
            .unwrap();
        tx.open_inode(&unlinked).await.unwrap();
        tx.unlink_name(
            Name {
                parent: &root,
                bytes: b"doomed",
            },
            when(2),
        )
        .await
        .unwrap();

        // 2. Live O_TMPFILE with data.
        let tmp = tx
            .create_tmpfile(&root, attrs, true, when(2))
            .await
            .unwrap();
        tx.write_file(&tmp, 0, &vec![0xcd; 16 * 1024], when(2))
            .await
            .unwrap();

        // 3. Unlinked-while-open empty directory.
        let doomed_dir = tx
            .create_directory(
                Name {
                    parent: &root,
                    bytes: b"doomed-dir",
                },
                Attributes {
                    permissions: 0o755,
                    uid: 0,
                    gid: 0,
                    umask: 0,
                },
                when(2),
            )
            .await
            .unwrap();
        tx.open_inode(&doomed_dir).await.unwrap();
        tx.unlink_name(
            Name {
                parent: &root,
                bytes: b"doomed-dir",
            },
            when(2),
        )
        .await
        .unwrap();

        tx.commit().await.unwrap();
        // Simulate crash: drop the writer without releasing any open handle.
        drop(writer);

        // Confirm all three orphan items are on disk before recovery.
        let ro = Filesystem::mount(Disk(image.reopen().unwrap()))
            .await
            .unwrap();
        assert!(has_orphan_item(&ro, unlinked.tree(), unlinked.number()).await);
        assert!(has_orphan_item(&ro, tmp.tree(), tmp.number()).await);
        assert!(has_orphan_item(&ro, doomed_dir.tree(), doomed_dir.number()).await);
        drop(ro);

        // Writable remount processes all orphans before publishing.
        let recovered = mount_writer(Disk(image.reopen().unwrap())).await.unwrap();
        assert!(!recovered.has_open_orphans());
        let snap = recovered.snapshot().unwrap();
        assert!(
            snap.inode(unlinked.tree(), unlinked.number())
                .await
                .is_err()
        );
        assert!(snap.inode(tmp.tree(), tmp.number()).await.is_err());
        assert!(
            snap.inode(doomed_dir.tree(), doomed_dir.number())
                .await
                .is_err()
        );
        let kept = snap
            .resolve("/中文-日本語-한국어".as_bytes())
            .await
            .unwrap();
        let mut out = [0; 7];
        assert_eq!(snap.read(&kept, 0, &mut out).await.unwrap(), 7);
        assert_eq!(&out, b"keep-me");
        let generation_after_recovery = snap.superblock().generation();
        drop(recovered);

        // Clean remount with no orphans leaves generation untouched.
        let clean = mount_writer(Disk(image.reopen().unwrap())).await.unwrap();
        assert_eq!(
            clean.snapshot().unwrap().superblock().generation(),
            generation_after_recovery
        );
        drop(clean);

        let ro = Filesystem::mount(Disk(image.reopen().unwrap()))
            .await
            .unwrap();
        assert!(!has_orphan_item(&ro, unlinked.tree(), unlinked.number()).await);
        assert!(!has_orphan_item(&ro, tmp.tree(), tmp.number()).await);
        assert!(!has_orphan_item(&ro, doomed_dir.tree(), doomed_dir.number()).await);
        drop(ro);
    });
}

#[test]
#[ignore = "needs btrfs-progs; the Linux CI lane runs it with --run-ignored"]
fn orphan_lifecycle_and_crash_recovery_pass_btrfs_check() {
    let (image, mut writer) = empty_image();
    block_on(async {
        let mut tx = writer.join().await.unwrap();
        let root = tx.root().await.unwrap();
        let attrs = Attributes {
            permissions: 0o644,
            uid: 0,
            gid: 0,
            umask: 0,
        };
        let file = tx
            .create_file(
                Name {
                    parent: &root,
                    bytes: b"orphan.bin",
                },
                attrs,
                when(1),
            )
            .await
            .unwrap();
        tx.write_file(&file, 0, &vec![0x33; 16 * 1024], when(1))
            .await
            .unwrap();
        tx.open_inode(&file).await.unwrap();
        tx.unlink_name(
            Name {
                parent: &root,
                bytes: b"orphan.bin",
            },
            when(2),
        )
        .await
        .unwrap();
        let tmp = tx
            .create_tmpfile(&root, attrs, true, when(2))
            .await
            .unwrap();
        tx.write_file(&tmp, 0, &vec![0x77; 16 * 1024], when(2))
            .await
            .unwrap();
        tx.commit().await.unwrap();
        // Live orphan items committed on disk must pass `btrfs check --readonly`.
        assert_btrfs_check(image.path());

        // Materialize tmpfile and drop writer while `file` is still orphaned.
        let mut tx = writer.join().await.unwrap();
        let root = tx.root().await.unwrap();
        tx.hard_link(
            Name {
                parent: &root,
                bytes: b"kept",
            },
            &tmp,
            when(3),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        drop(writer);
        assert_btrfs_check(image.path());

        // Remount writable to clean up the leaked orphan, then verify again.
        let recovered = mount_writer(Disk(image.reopen().unwrap())).await.unwrap();
        drop(recovered);
        assert_btrfs_check(image.path());
    });
}
