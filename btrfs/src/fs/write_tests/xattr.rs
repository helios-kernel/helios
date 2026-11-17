//! Extended attributes through the writer: the operations, Linux's limits and
//! errors, hash-sharing items, namespaces, removal with the inode, and what the
//! reader sees after a commit.

extern crate std;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use ferrosys::{Metadata, Timestamp as ImageTime, TreeBuilder};
use futures_lite::future::block_on;
use zerocopy::{FromZeros, IntoBytes};

use super::{Disk, assert_btrfs_check, filesystem_image_tree_file};
use crate::csum::name_hash;
use crate::fs::writer::{Attributes, InodeHandle, Name, WriteTransaction, Writer};
use crate::ondisk::{RawDirItem, RawInodeItem, RawKey, item_type, view};
use crate::tree::write::WriteError;
use crate::write::XattrMode;
use crate::{Key, Timestamp};

/// Two names with one CRC32C name hash (`0x4e84071b`), found by search.
const COLLIDING: [&[u8]; 2] = [b"user.k1371838", b"user.k2000402"];

const CJK: [(&str, &str); 3] = [
    ("user.中文", "你好，世界"),
    ("user.日本語", "こんにちは世界"),
    ("user.한국어", "안녕하세요 세계"),
];

const ACL: &[u8] = b"system.posix_acl_access";

fn when(second: i64) -> Timestamp {
    Timestamp {
        seconds: 1_700_000_000 + second,
        nanoseconds: 7,
    }
}

/// An image whose `/file` carries attributes in every namespace, written by
/// the independent formatter the way Linux stores them.
fn image() -> (tempfile::NamedTempFile, Writer<Disk>) {
    let stamp = ImageTime::from_secs(1_700_000_000);
    let named = tempfile::NamedTempFile::new().unwrap();
    let tree = TreeBuilder::new()
        .root(Metadata::new(0o755, stamp))
        .file("/file", b"data".to_vec(), Metadata::new(0o644, stamp))
        .xattr(
            "security.capability",
            vec![1, 0, 0, 2, 0xff, 0, 0, 0, 0, 0, 0, 0],
        )
        .xattr("trusted.zone", "中日韓")
        .xattr(ACL, vec![2, 0, 0, 0])
        .xattr("user.existing", "old")
        .directory("/dir", Metadata::new(0o755, stamp))
        .symlink("/link", "file", Metadata::new(0o777, stamp))
        .fifo("/pipe", Metadata::new(0o644, stamp));
    drop(filesystem_image_tree_file(
        true,
        true,
        tree,
        named.reopen().unwrap(),
    ));
    let writer = block_on(Writer::mount(Disk(named.reopen().unwrap()))).unwrap();
    (named, writer)
}

async fn lookup(tx: &WriteTransaction<'_, Disk>, name: &str) -> InodeHandle {
    let root = tx.root().await.unwrap();
    tx.lookup(&root, name.as_bytes()).await.unwrap().unwrap()
}

async fn value(tx: &WriteTransaction<'_, Disk>, file: &InodeHandle, name: &[u8]) -> Vec<u8> {
    let length = tx.xattr(file, name, &mut []).await.unwrap();
    let mut buffer = vec![0; length];
    // A zero-length value has no buffer to ask for.
    if length > 0 {
        assert_eq!(tx.xattr(file, name, &mut buffer).await.unwrap(), length);
    }
    buffer
}

async fn names(tx: &WriteTransaction<'_, Disk>, file: &InodeHandle) -> Vec<Vec<u8>> {
    let length = tx.list_xattrs(file, &mut []).await.unwrap();
    let mut buffer = vec![0; length];
    if length > 0 {
        assert_eq!(tx.list_xattrs(file, &mut buffer).await.unwrap(), length);
    }
    buffer
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

/// Everything the reader sees for `inode`, name and value, in listing order.
async fn read_back(
    snapshot: &crate::Filesystem<alloc::sync::Arc<Disk>>,
    path: &str,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let inode = snapshot.resolve(path.as_bytes()).await.unwrap();
    let mut listed = Vec::new();
    snapshot
        .list_xattrs(&inode, |name| {
            listed.push(name.to_vec());
            core::ops::ControlFlow::Continue(())
        })
        .await
        .unwrap();
    let mut all = Vec::new();
    for name in listed {
        let mut buffer = vec![0; 70_000];
        let length = snapshot
            .xattr(&inode, &name, &mut buffer)
            .await
            .unwrap()
            .expect("a listed attribute is found by name");
        buffer.truncate(length);
        all.push((name, buffer));
    }
    all
}

/// Writes an attribute of any namespace, as an image written by Linux has it.
async fn inject(
    tx: &mut WriteTransaction<'_, Disk>,
    file: &InodeHandle,
    name: &[u8],
    value: &[u8],
) {
    let edits = tx.edits();
    let root = edits.roots.get(file.tree()).unwrap();
    let key = Key::new(file.number(), item_type::XATTR_ITEM, name_hash(name));
    let mut item = edits
        .trees
        .get(&edits.volume, root, key)
        .await
        .unwrap()
        .unwrap_or_default();
    let record = RawDirItem {
        location: RawKey::new_zeroed(),
        transid: 1.into(),
        data_len: (value.len() as u16).into(),
        name_len: (name.len() as u16).into(),
        entry_type: 8,
    };
    item.extend_from_slice(record.as_bytes());
    item.extend_from_slice(name);
    item.extend_from_slice(value);
    let root = edits
        .trees
        .apply(&edits.volume, root, key, Some(&item), &mut edits.space)
        .await
        .unwrap();
    edits.roots.set(root).unwrap();
}

async fn raw_inode(tx: &mut WriteTransaction<'_, Disk>, file: &InodeHandle) -> RawInodeItem {
    let edits = tx.edits();
    let root = edits.roots.get(file.tree()).unwrap();
    let bytes = edits
        .trees
        .get(
            &edits.volume,
            root,
            Key::new(file.number(), item_type::INODE_ITEM, 0),
        )
        .await
        .unwrap()
        .unwrap();
    *view::<RawInodeItem>(&bytes).unwrap()
}

/// The `XATTR_ITEM`s stored for `file`: key offset and record count.
async fn items(tx: &mut WriteTransaction<'_, Disk>, file: &InodeHandle) -> Vec<(u64, usize)> {
    let edits = tx.edits();
    let root = edits.roots.get(file.tree()).unwrap();
    let mut found = Vec::new();
    let mut next = Key::new(file.number(), item_type::XATTR_ITEM, 0);
    while let Some((key, bytes)) = edits
        .trees
        .ceiling(&edits.volume, root, next)
        .await
        .unwrap()
    {
        if !key.is(file.number(), item_type::XATTR_ITEM) {
            break;
        }
        let records = crate::items::dir_records(&bytes, crate::items::RecordKind::Xattr)
            .inspect(|record| assert!(record.is_ok()))
            .count();
        found.push((key.offset, records));
        next = Key::new(file.number(), item_type::XATTR_ITEM, key.offset + 1);
    }
    found
}

#[test]
fn set_get_list_and_remove_round_trip_through_the_reader() {
    let (_named, mut writer) = image();
    let concurrency = std::thread::available_parallelism().unwrap();
    block_on(async {
        let mut tx = writer.begin().await.unwrap();
        let file = lookup(&tx, "file").await;
        let directory = lookup(&tx, "dir").await;
        let before = raw_inode(&mut tx, &file).await;
        for (index, (name, text)) in CJK.iter().enumerate() {
            tx.set_xattr(
                &file,
                name.as_bytes(),
                text.as_bytes(),
                XattrMode::Create,
                when(10 + index as i64),
            )
            .await
            .unwrap();
        }
        tx.set_xattr(&file, b"user.ascii", b"plain", XattrMode::Set, when(20))
            .await
            .unwrap();
        tx.set_xattr(&file, b"user.empty", b"", XattrMode::Set, when(21))
            .await
            .unwrap();
        tx.set_xattr(
            &directory,
            "user.目录".as_bytes(),
            b"dir",
            XattrMode::Set,
            when(22),
        )
        .await
        .unwrap();
        for (name, text) in CJK {
            assert_eq!(value(&tx, &file, name.as_bytes()).await, text.as_bytes());
        }
        assert_eq!(value(&tx, &file, b"user.empty").await, b"");
        // A size query, an exact buffer and a short one.
        assert_eq!(tx.xattr(&file, b"user.ascii", &mut []).await.unwrap(), 5);
        let mut short = [0; 4];
        assert!(matches!(
            tx.xattr(&file, b"user.ascii", &mut short).await,
            Err(WriteError::XattrBuffer {
                needed: 5,
                provided: 4
            })
        ));
        let mut listed = names(&tx, &file).await;
        listed.sort();
        let mut expected: Vec<Vec<u8>> = vec![
            b"security.capability".to_vec(),
            b"system.posix_acl_access".to_vec(),
            b"trusted.zone".to_vec(),
            b"user.ascii".to_vec(),
            b"user.empty".to_vec(),
            b"user.existing".to_vec(),
        ];
        expected.extend(CJK.iter().map(|(name, _)| name.as_bytes().to_vec()));
        expected.sort();
        assert_eq!(listed, expected);
        let mut short = vec![0; 10];
        assert!(matches!(
            tx.list_xattrs(&file, &mut short).await,
            Err(WriteError::XattrBuffer { .. })
        ));
        // Setting changes the inode: ctime, transid and sequence.
        let after = raw_inode(&mut tx, &file).await;
        assert_eq!(after.ctime.sec.get(), when(21).seconds as u64);
        assert_eq!(after.ctime.nsec.get(), 7);
        assert_eq!(after.transid.get(), tx.edits().generation());
        assert_eq!(
            after.sequence.get(),
            before.sequence.get().wrapping_add(5),
            "five sets on the file"
        );
        tx.remove_xattr(&file, "user.中文".as_bytes(), when(30))
            .await
            .unwrap();
        tx.remove_xattr(&file, b"user.existing", when(31))
            .await
            .unwrap();
        assert!(matches!(
            tx.xattr(&file, "user.中文".as_bytes(), &mut []).await,
            Err(WriteError::XattrMissing { .. })
        ));
        tx.commit(|| panic!("valid fixture UUID"), concurrency)
            .await
            .unwrap();
    });
    block_on(async {
        let snapshot = writer.snapshot().unwrap();
        let mut found = read_back(&snapshot, "/file").await;
        found.sort();
        let mut expected: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (
                b"security.capability".to_vec(),
                vec![1, 0, 0, 2, 0xff, 0, 0, 0, 0, 0, 0, 0],
            ),
            (ACL.to_vec(), vec![2, 0, 0, 0]),
            (b"trusted.zone".to_vec(), "中日韓".as_bytes().to_vec()),
            (b"user.ascii".to_vec(), b"plain".to_vec()),
            (b"user.empty".to_vec(), Vec::new()),
            (
                "user.日本語".as_bytes().to_vec(),
                "こんにちは世界".as_bytes().to_vec(),
            ),
            (
                "user.한국어".as_bytes().to_vec(),
                "안녕하세요 세계".as_bytes().to_vec(),
            ),
        ];
        expected.sort();
        assert_eq!(found, expected);
        assert_eq!(
            read_back(&snapshot, "/dir").await,
            vec![("user.目录".as_bytes().to_vec(), b"dir".to_vec())]
        );
    });
}

#[test]
fn flags_and_missing_attributes_fail_as_on_linux() {
    let (_named, mut writer) = image();
    block_on(async {
        let mut tx = writer.begin().await.unwrap();
        let file = lookup(&tx, "file").await;
        // XATTR_CREATE over an existing name is EEXIST.
        assert!(matches!(
            tx.set_xattr(&file, b"user.existing", b"new", XattrMode::Create, when(1))
                .await,
            Err(WriteError::XattrExists { .. })
        ));
        // XATTR_REPLACE of an absent name is ENODATA.
        assert!(matches!(
            tx.set_xattr(&file, b"user.absent", b"new", XattrMode::Replace, when(1))
                .await,
            Err(WriteError::XattrMissing { .. })
        ));
        // Failed calls leave the value and the inode alone.
        assert_eq!(value(&tx, &file, b"user.existing").await, b"old");
        assert!(matches!(
            tx.xattr(&file, b"user.absent", &mut []).await,
            Err(WriteError::XattrMissing { .. })
        ));
        // Removing an absent name is ENODATA, as XATTR_REPLACE with no value.
        assert!(matches!(
            tx.remove_xattr(&file, b"user.absent", when(1)).await,
            Err(WriteError::XattrMissing { .. })
        ));
        // Replace keeps the name and swaps the value, longer or shorter.
        tx.set_xattr(
            &file,
            b"user.existing",
            "新しい値".as_bytes(),
            XattrMode::Replace,
            when(2),
        )
        .await
        .unwrap();
        assert_eq!(
            value(&tx, &file, b"user.existing").await,
            "新しい値".as_bytes()
        );
        tx.set_xattr(&file, b"user.existing", b"x", XattrMode::Set, when(3))
            .await
            .unwrap();
        assert_eq!(value(&tx, &file, b"user.existing").await, b"x");
        tx.set_xattr(&file, b"user.fresh", b"v", XattrMode::Create, when(4))
            .await
            .unwrap();
        // Names: empty and over 255 bytes are ERANGE, a bare prefix EINVAL.
        let long = [b"user.".as_slice(), &[b'n'; 251]].concat();
        assert_eq!(long.len(), 256);
        for name in [&b""[..], &long] {
            assert!(matches!(
                tx.set_xattr(&file, name, b"v", XattrMode::Set, when(5))
                    .await,
                Err(WriteError::XattrNameLength { .. })
            ));
            assert!(matches!(
                tx.xattr(&file, name, &mut []).await,
                Err(WriteError::XattrNameLength { .. })
            ));
        }
        assert!(matches!(
            tx.set_xattr(&file, b"user.", b"v", XattrMode::Set, when(5))
                .await,
            Err(WriteError::XattrName)
        ));
        let longest = [b"user.".as_slice(), &[b'n'; 250]].concat();
        tx.set_xattr(&file, &longest, b"v", XattrMode::Set, when(5))
            .await
            .unwrap();
        assert_eq!(value(&tx, &file, &longest).await, b"v");
    });
}

#[test]
fn colliding_names_share_one_item() {
    assert_eq!(name_hash(COLLIDING[0]), name_hash(COLLIDING[1]));
    assert_eq!(name_hash(COLLIDING[0]), 0x4e84_071b);
    assert_ne!(COLLIDING[0], COLLIDING[1]);
    let (named, mut writer) = image();
    let concurrency = std::thread::available_parallelism().unwrap();
    block_on(async {
        let mut tx = writer.begin().await.unwrap();
        let file = lookup(&tx, "file").await;
        let hash = name_hash(COLLIDING[0]);
        tx.set_xattr(&file, COLLIDING[0], b"first", XattrMode::Create, when(1))
            .await
            .unwrap();
        tx.set_xattr(&file, COLLIDING[1], b"second", XattrMode::Create, when(2))
            .await
            .unwrap();
        let stored = items(&mut tx, &file).await;
        assert!(stored.contains(&(hash, 2)), "{stored:?}");
        // Each is found by name, and replacing one leaves the other.
        assert_eq!(value(&tx, &file, COLLIDING[0]).await, b"first");
        assert_eq!(value(&tx, &file, COLLIDING[1]).await, b"second");
        tx.set_xattr(
            &file,
            COLLIDING[0],
            "長い値になる".as_bytes(),
            XattrMode::Replace,
            when(3),
        )
        .await
        .unwrap();
        assert_eq!(value(&tx, &file, COLLIDING[1]).await, b"second");
        assert_eq!(
            value(&tx, &file, COLLIDING[0]).await,
            "長い値になる".as_bytes()
        );
        assert!(items(&mut tx, &file).await.contains(&(hash, 2)));
        // Removing one keeps the item, removing the second deletes it.
        tx.remove_xattr(&file, COLLIDING[0], when(4)).await.unwrap();
        assert!(items(&mut tx, &file).await.contains(&(hash, 1)));
        assert_eq!(value(&tx, &file, COLLIDING[1]).await, b"second");
        assert!(matches!(
            tx.xattr(&file, COLLIDING[0], &mut []).await,
            Err(WriteError::XattrMissing { .. })
        ));
        tx.set_xattr(&file, COLLIDING[0], b"again", XattrMode::Create, when(5))
            .await
            .unwrap();
        tx.commit(|| panic!("valid fixture UUID"), concurrency)
            .await
            .unwrap();
    });
    block_on(async {
        let snapshot = writer.snapshot().unwrap();
        let found = read_back(&snapshot, "/file").await;
        for (name, expected) in [(COLLIDING[0], &b"again"[..]), (COLLIDING[1], b"second")] {
            assert!(found.contains(&(name.to_vec(), expected.to_vec())));
        }
        let mut tx = writer.begin().await.unwrap();
        let file = lookup(&tx, "file").await;
        for name in COLLIDING {
            tx.remove_xattr(&file, name, when(6)).await.unwrap();
        }
        let hash = name_hash(COLLIDING[0]);
        assert!(
            items(&mut tx, &file)
                .await
                .iter()
                .all(|(key, _)| *key != hash)
        );
    });
    drop(named);
}

#[test]
fn sizes_are_limited_as_linux_limits_them() {
    let (_named, mut writer) = image();
    block_on(async {
        let nodesize = writer.snapshot().unwrap().superblock().nodesize() as usize;
        let mut tx = writer.begin().await.unwrap();
        let file = lookup(&tx, "file").await;
        // BTRFS_MAX_XATTR_SIZE: a leaf's item capacity less one dir item.
        let maximum = nodesize
            - size_of::<crate::ondisk::RawHeader>()
            - size_of::<crate::ondisk::RawItem>()
            - size_of::<RawDirItem>();
        let name = b"user.big";
        let fits = vec![0xAB; maximum - name.len()];
        tx.set_xattr(&file, name, &fits, XattrMode::Create, when(1))
            .await
            .unwrap();
        assert_eq!(tx.xattr(&file, name, &mut []).await.unwrap(), fits.len());
        let mut buffer = vec![0; fits.len()];
        tx.xattr(&file, name, &mut buffer).await.unwrap();
        assert_eq!(buffer, fits);
        tx.remove_xattr(&file, name, when(2)).await.unwrap();
        // One byte more is ENOSPC, and more than XATTR_SIZE_MAX is E2BIG.
        assert!(matches!(
            tx.set_xattr(
                &file,
                name,
                &vec![0; fits.len() + 1],
                XattrMode::Set,
                when(3)
            )
            .await,
            Err(WriteError::XattrNoSpace { .. })
        ));
        assert!(matches!(
            tx.set_xattr(&file, name, &vec![0; 65_537], XattrMode::Set, when(3))
                .await,
            Err(WriteError::XattrValueTooBig {
                length: 65_537,
                maximum: 65_536
            })
        ));
        // A name sharing an item with a full one overflows the leaf.
        let half = vec![1; maximum / 2];
        tx.set_xattr(&file, COLLIDING[0], &half, XattrMode::Set, when(4))
            .await
            .unwrap();
        assert!(matches!(
            tx.set_xattr(&file, COLLIDING[1], &half, XattrMode::Set, when(5))
                .await,
            Err(WriteError::XattrNoSpace { .. })
        ));
        assert_eq!(value(&tx, &file, COLLIDING[0]).await, half);
        assert!(matches!(
            tx.xattr(&file, COLLIDING[1], &mut []).await,
            Err(WriteError::XattrMissing { .. })
        ));
    });
}

#[test]
fn only_user_attributes_are_written_and_every_namespace_reads() {
    let (named, mut writer) = image();
    let concurrency = std::thread::available_parallelism().unwrap();
    block_on(async {
        let mut tx = writer.begin().await.unwrap();
        let file = lookup(&tx, "file").await;
        for name in [
            &b"security.capability"[..],
            b"security.selinux",
            b"trusted.zone",
            b"trusted.new",
            ACL,
            b"system.posix_acl_default",
        ] {
            for mode in [XattrMode::Set, XattrMode::Create, XattrMode::Replace] {
                assert!(
                    matches!(
                        tx.set_xattr(&file, name, b"x", mode, when(1)).await,
                        Err(WriteError::XattrNotPermitted { .. })
                    ),
                    "{}",
                    String::from_utf8_lossy(name)
                );
            }
            assert!(
                matches!(
                    tx.remove_xattr(&file, name, when(1)).await,
                    Err(WriteError::XattrNotPermitted { .. })
                ),
                "{}",
                String::from_utf8_lossy(name)
            );
        }
        // No handler: EOPNOTSUPP.
        for name in [
            &b"system.other"[..],
            b"btrfs.compression",
            b"os2.x",
            b"plain",
        ] {
            assert!(matches!(
                tx.set_xattr(&file, name, b"x", XattrMode::Set, when(1))
                    .await,
                Err(WriteError::XattrNamespace)
            ));
            assert!(matches!(
                tx.remove_xattr(&file, name, when(1)).await,
                Err(WriteError::XattrNamespace)
            ));
        }
        // Existing values are preserved and read back, and so is the inode.
        assert_eq!(
            value(&tx, &file, b"trusted.zone").await,
            "中日韓".as_bytes()
        );
        assert_eq!(value(&tx, &file, ACL).await, [2, 0, 0, 0]);
        assert_eq!(names(&tx, &file).await.len(), 4);
        assert_eq!(
            raw_inode(&mut tx, &file).await.ctime.sec.get(),
            1_700_000_000
        );
        // `user.*` beside them is written.
        tx.set_xattr(&file, b"user.beside", b"ok", XattrMode::Set, when(2))
            .await
            .unwrap();
        tx.commit(|| panic!("valid fixture UUID"), concurrency)
            .await
            .unwrap();
    });
    block_on(async {
        let snapshot = writer.snapshot().unwrap();
        assert_eq!(read_back(&snapshot, "/file").await.len(), 5);
    });
    drop(named);
}

#[test]
fn user_attributes_need_a_regular_file_or_directory() {
    let (_named, mut writer) = image();
    block_on(async {
        let mut tx = writer.begin().await.unwrap();
        let root = tx.root().await.unwrap();
        for path in ["link", "pipe"] {
            let node = lookup(&tx, path).await;
            // Writing is EPERM, reading ENODATA (`xattr_permission`).
            assert!(matches!(
                tx.set_xattr(&node, b"user.x", b"v", XattrMode::Set, when(1))
                    .await,
                Err(WriteError::XattrNotPermitted { .. })
            ));
            assert!(matches!(
                tx.remove_xattr(&node, b"user.x", when(1)).await,
                Err(WriteError::XattrNotPermitted { .. })
            ));
            assert!(matches!(
                tx.xattr(&node, b"user.x", &mut []).await,
                Err(WriteError::XattrMissing { .. })
            ));
        }
        // A symlink created by the writer is the same.
        let link = tx
            .symlink(
                Name {
                    parent: &root,
                    bytes: "链接".as_bytes(),
                },
                b"file",
                Attributes {
                    permissions: 0o777,
                    uid: 0,
                    gid: 0,
                },
                when(1),
            )
            .await
            .unwrap();
        assert!(matches!(
            tx.set_xattr(&link, b"user.x", b"v", XattrMode::Set, when(2))
                .await,
            Err(WriteError::XattrNotPermitted { .. })
        ));
    });
}

#[test]
fn immutable_and_append_only_inodes_refuse_changes() {
    use crate::items::{INODE_APPEND, INODE_IMMUTABLE};
    let (_named, mut writer) = image();
    block_on(async {
        let mut tx = writer.begin().await.unwrap();
        let file = lookup(&tx, "file").await;
        tx.set_xattr(&file, b"user.kept", b"v", XattrMode::Set, when(1))
            .await
            .unwrap();
        for flag in [INODE_IMMUTABLE, INODE_APPEND] {
            let mut raw = raw_inode(&mut tx, &file).await;
            raw.flags.set(flag);
            let edits = tx.edits();
            let root = edits.roots.get(file.tree()).unwrap();
            let root = edits
                .trees
                .apply(
                    &edits.volume,
                    root,
                    Key::new(file.number(), item_type::INODE_ITEM, 0),
                    Some(raw.as_bytes()),
                    &mut edits.space,
                )
                .await
                .unwrap();
            edits.roots.set(root).unwrap();
            assert!(matches!(
                tx.set_xattr(&file, b"user.kept", b"w", XattrMode::Set, when(2))
                    .await,
                Err(WriteError::InodeFlags { .. })
            ));
            assert!(matches!(
                tx.remove_xattr(&file, b"user.kept", when(2)).await,
                Err(WriteError::InodeFlags { .. })
            ));
            assert_eq!(value(&tx, &file, b"user.kept").await, b"v");
        }
    });
}

#[test]
fn removing_the_inode_removes_its_attributes() {
    let (named, mut writer) = image();
    let concurrency = std::thread::available_parallelism().unwrap();
    block_on(async {
        let mut tx = writer.begin().await.unwrap();
        let root = tx.root().await.unwrap();
        let attributes = Attributes {
            permissions: 0o644,
            uid: 1000,
            gid: 1000,
        };
        let doomed = tx
            .create_file(
                Name {
                    parent: &root,
                    bytes: b"doomed",
                },
                attributes,
                when(1),
            )
            .await
            .unwrap();
        let folder = tx
            .create_directory(
                Name {
                    parent: &root,
                    bytes: b"folder",
                },
                attributes,
                when(1),
            )
            .await
            .unwrap();
        for node in [&doomed, &folder] {
            for (name, text) in CJK {
                tx.set_xattr(
                    node,
                    name.as_bytes(),
                    text.as_bytes(),
                    XattrMode::Set,
                    when(2),
                )
                .await
                .unwrap();
            }
            for name in COLLIDING {
                tx.set_xattr(node, name, b"v", XattrMode::Set, when(2))
                    .await
                    .unwrap();
            }
            inject(&mut tx, node, b"security.capability", &[1; 20]).await;
            inject(&mut tx, node, b"trusted.x", b"t").await;
            assert!(!items(&mut tx, node).await.is_empty());
        }
        tx.commit(|| panic!("valid fixture UUID"), concurrency)
            .await
            .unwrap();
        let mut tx = writer.begin().await.unwrap();
        let root = tx.root().await.unwrap();
        let doomed = tx.lookup(&root, b"doomed").await.unwrap().unwrap();
        let folder = tx.lookup(&root, b"folder").await.unwrap().unwrap();
        tx.unlink_name(
            Name {
                parent: &root,
                bytes: b"doomed",
            },
            when(3),
        )
        .await
        .unwrap();
        tx.unlink_name(
            Name {
                parent: &root,
                bytes: b"folder",
            },
            when(3),
        )
        .await
        .unwrap();
        for node in [&doomed, &folder] {
            let edits = tx.edits();
            let tree = edits.roots.get(node.tree()).unwrap();
            let left = edits
                .trees
                .ceiling(&edits.volume, tree, Key::new(node.number(), 0, 0))
                .await
                .unwrap();
            assert!(
                left.is_none_or(|(key, _)| key.objectid != node.number()),
                "every item of the removed inode is gone"
            );
        }
        tx.commit(|| panic!("valid fixture UUID"), concurrency)
            .await
            .unwrap();
    });
    drop(named);
}

#[test]
fn a_hard_linked_inode_keeps_its_attributes_until_the_last_link() {
    let (_named, mut writer) = image();
    block_on(async {
        let mut tx = writer.begin().await.unwrap();
        let root = tx.root().await.unwrap();
        let file = lookup(&tx, "file").await;
        tx.hard_link(
            Name {
                parent: &root,
                bytes: b"alias",
            },
            &file,
            when(1),
        )
        .await
        .unwrap();
        tx.unlink_name(
            Name {
                parent: &root,
                bytes: b"file",
            },
            when(2),
        )
        .await
        .unwrap();
        let alias = lookup(&tx, "alias").await;
        assert_eq!(value(&tx, &alias, b"user.existing").await, b"old");
        assert_eq!(
            value(&tx, &alias, b"trusted.zone").await,
            "中日韓".as_bytes()
        );
    });
}

#[test]
fn an_owner_change_kills_the_file_capability_of_a_non_directory() {
    let (_named, mut writer) = image();
    block_on(async {
        let mut tx = writer.begin().await.unwrap();
        let file = lookup(&tx, "file").await;
        let directory = lookup(&tx, "dir").await;
        inject(&mut tx, &directory, b"security.capability", &[1; 12]).await;
        let edits = tx.edits();
        edits
            .kill_privileges(file.tree(), file.number())
            .await
            .unwrap();
        // A directory keeps it (`cap_inode_killpriv` is for files), and a file
        // without one is not an error.
        edits
            .kill_privileges(directory.tree(), directory.number())
            .await
            .unwrap();
        edits
            .kill_privileges(file.tree(), file.number())
            .await
            .unwrap();
        assert!(matches!(
            tx.xattr(&file, b"security.capability", &mut []).await,
            Err(WriteError::XattrMissing { .. })
        ));
        // The rest of the file's attributes stay.
        assert_eq!(value(&tx, &file, b"user.existing").await, b"old");
        assert_eq!(value(&tx, &file, ACL).await, [2, 0, 0, 0]);
        assert_eq!(
            value(&tx, &directory, b"security.capability").await,
            [1; 12]
        );
    });
}

#[test]
#[ignore = "needs btrfs-progs; the Linux CI lane runs it with --run-ignored"]
fn attribute_edits_pass_btrfs_check() {
    let (named, mut writer) = image();
    let concurrency = std::thread::available_parallelism().unwrap();
    assert_btrfs_check(named.path());
    block_on(async {
        let mut tx = writer.begin().await.unwrap();
        let file = lookup(&tx, "file").await;
        for (name, text) in CJK {
            tx.set_xattr(
                &file,
                name.as_bytes(),
                text.as_bytes(),
                XattrMode::Set,
                when(1),
            )
            .await
            .unwrap();
        }
        for name in COLLIDING {
            tx.set_xattr(&file, name, b"v", XattrMode::Set, when(2))
                .await
                .unwrap();
        }
        tx.remove_xattr(&file, COLLIDING[0], when(3)).await.unwrap();
        tx.commit(|| panic!("valid fixture UUID"), concurrency)
            .await
            .unwrap();
    });
    assert_btrfs_check(named.path());
}
