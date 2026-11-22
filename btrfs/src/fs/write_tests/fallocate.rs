//! `fallocate(2)`: preallocation, hole punching and range zeroing through the
//! writer, with and without `NO_HOLES`, across inline, regular, compressed,
//! preallocated, dirty (delalloc) and reflinked extents.

extern crate std;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use ferrosys::btrfs::FormatOptions;
use ferrosys::btrfs::ondisk::{CompatRoFlags, IncompatFlags};
use ferrosys::{Metadata, Timestamp as ImageTime, TreeBuilder};
use futures_lite::future::block_on;

use super::{
    Disk, FixtureUuids, assert_btrfs_check, filesystem_image_options, mount_compressing_writer,
    mount_writer,
};
use crate::compress::policy::Compressor;
use crate::compress::write::Zstd;
use crate::data::Reader;
use crate::fs::writer::{Attributes, CloneRange, InodeHandle, Name, WriteTransaction, Writer};
use crate::fs::{ExtentInfo, ExtentKind};
use crate::ondisk::{RawFileExtentBody, RawFileExtentHead, item_type, view};
use crate::space::SpaceError;
use crate::tree::Cursor;
use crate::tree::write::WriteError;
use crate::write::AllocateMode;
use crate::{Error, FileKind, Key, Timestamp};

const SECTOR: u64 = 4096;

type DiskWriter = Writer<Disk, FixtureUuids>;
type Transaction<'a> = WriteTransaction<'a, Disk, FixtureUuids>;

fn when(second: i64) -> Timestamp {
    Timestamp {
        seconds: 1_700_000_000 + second,
        nanoseconds: 11,
    }
}

fn attrs() -> Attributes {
    Attributes {
        permissions: 0o644,
        uid: 0,
        gid: 0,
        umask: 0,
    }
}

fn mount_image(no_holes: bool, compressor: Compressor) -> (tempfile::NamedTempFile, DiskWriter) {
    let stamp = ImageTime::from_secs(1_700_000_000);
    let tree = TreeBuilder::new()
        .root(Metadata::new(0o755, stamp))
        .directory("/dir", Metadata::new(0o755, stamp));
    let mut options = FormatOptions::new([0x42; 16], stamp);
    if !no_holes {
        options.plan.incompat_flags = options.plan.incompat_flags.without(IncompatFlags::NO_HOLES);
        options.plan.compat_ro_flags = options
            .plan
            .compat_ro_flags
            .without(CompatRoFlags::BLOCK_GROUP_TREE);
    }
    let named = tempfile::NamedTempFile::new().unwrap();
    drop(filesystem_image_options(
        tree,
        named.reopen().unwrap(),
        options,
    ));
    let writer = block_on(mount_compressing_writer(
        Disk(named.reopen().unwrap()),
        compressor,
    ))
    .unwrap();
    (named, writer)
}

async fn create(tx: &mut Transaction<'_>, name: &[u8]) -> InodeHandle {
    let root = tx.root().await.unwrap();
    tx.create_file(
        Name {
            parent: &root,
            bytes: name,
        },
        attrs(),
        when(0),
    )
    .await
    .unwrap()
}

async fn read_all(writer: &DiskWriter, path: &[u8]) -> Vec<u8> {
    let snapshot = writer.snapshot().unwrap();
    let inode = snapshot.resolve(path).await.unwrap();
    let mut buf = vec![0; inode.metadata().size as usize];
    let read = snapshot.read(&inode, 0, &mut buf).await.unwrap();
    assert_eq!(read, buf.len());
    buf
}

async fn extents_of(writer: &DiskWriter, path: &[u8]) -> Vec<ExtentInfo> {
    let snapshot = writer.snapshot().unwrap();
    let inode = snapshot.resolve(path).await.unwrap();
    snapshot.file_extents(&inode).await.unwrap()
}

/// Checks that no `EXTENT_CSUM` entry covers any sector of `PREALLOC` extents
/// on `path`.
async fn assert_prealloc_has_no_csums(writer: &DiskWriter, path: &[u8]) {
    let snapshot = writer.snapshot().unwrap();
    let inode = snapshot.resolve(path).await.unwrap();
    let nodes = inode.snapshot.nodes(&snapshot.volume);
    let reader = Reader::new(&nodes.volume, &nodes, inode.snapshot.csum_tree);
    let mut cursor = Cursor::floor(
        &nodes,
        inode.root,
        Key::new(inode.number(), item_type::EXTENT_DATA, 0),
    )
    .await
    .unwrap();
    while let (Some(key), Some(item)) = (cursor.key(), cursor.item()) {
        if key < Key::new(inode.number(), item_type::EXTENT_DATA, 0) {
            cursor.advance(&nodes).await.unwrap();
            continue;
        }
        if !key.is(inode.number(), item_type::EXTENT_DATA) {
            break;
        }
        let head = view::<RawFileExtentHead>(item).unwrap();
        if head.extent_type == 2 {
            let body = view::<RawFileExtentBody>(&item[size_of::<RawFileExtentHead>()..]).unwrap();
            let bytenr = body.disk_bytenr.get();
            let disk_len = body.disk_num_bytes.get();
            assert_ne!(bytenr, 0, "PREALLOC must own a real data extent");
            assert_eq!(head.compression, 0, "PREALLOC cannot be compressed");
            for off in (0..disk_len).step_by(SECTOR as usize) {
                let result = reader.lookup_checksums(bytenr + off, SECTOR as usize).await;
                assert!(
                    matches!(result, Err(Error::MissingDataChecksum { .. })),
                    "PREALLOC sector at {:#x} must have no EXTENT_CSUM, got {result:?}",
                    bytenr + off
                );
            }
        }
        cursor.advance(&nodes).await.unwrap();
    }
}

#[test]
fn preallocate_writes_prealloc_extents_without_csums_and_handles_writes_and_truncate() {
    for no_holes in [true, false] {
        let (_named, mut writer) = mount_image(no_holes, Compressor::Plain);
        block_on(async {
            let mut tx = writer.join().await.unwrap();

            // 1. Mode 0 (Allocate): extends i_size, creates PREALLOC, updates mtime & ctime.
            let f1 = create(&mut tx, "预分配-事前割当-사전할당".as_bytes()).await;
            tx.fallocate(&f1, 4096, 12288, AllocateMode::Allocate, when(10))
                .await
                .unwrap();
            let meta = tx.metadata(&f1).await.unwrap();
            assert_eq!(meta.size, 16384);
            assert_eq!(meta.nbytes, 12288);
            assert_eq!(meta.mtime, when(10));
            assert_eq!(meta.ctime, when(10));

            // 2. KeepSize past EOF: keeps i_size, updates ctime only, adds PREALLOC.
            tx.fallocate(&f1, 16384, 8192, AllocateMode::KeepSize, when(20))
                .await
                .unwrap();
            let meta = tx.metadata(&f1).await.unwrap();
            assert_eq!(meta.size, 16384);
            assert_eq!(meta.nbytes, 20480);
            assert_eq!(meta.mtime, when(10));
            assert_eq!(meta.ctime, when(20));

            // 3. Allocate inside existing i_size: preserves mtime, updates ctime, fills hole at 0..4096.
            tx.fallocate(&f1, 0, 16384, AllocateMode::Allocate, when(30))
                .await
                .unwrap();
            let meta = tx.metadata(&f1).await.unwrap();
            assert_eq!(meta.size, 16384);
            assert_eq!(meta.nbytes, 24576);
            assert_eq!(meta.mtime, when(10));
            assert_eq!(meta.ctime, when(30));

            tx.commit().await.unwrap();

            let path = "/预分配-事前割当-사전할당".as_bytes();
            assert_eq!(read_all(&writer, path).await, vec![0; 16384]);
            let extents = extents_of(&writer, path).await;
            assert!(
                extents.iter().all(|e| e.kind == ExtentKind::Prealloc),
                "no_holes={no_holes}: expected only PREALLOC extents, got {extents:?}"
            );
            assert_prealloc_has_no_csums(&writer, path).await;

            // 4. Write into the middle of the PREALLOC extent, then commit: splits/CoWs cleanly.
            let mut tx = writer.join().await.unwrap();
            let root = tx.root().await.unwrap();
            let f1 = tx
                .lookup(&root, "预分配-事前割当-사전할당".as_bytes())
                .await
                .unwrap()
                .unwrap();
            tx.write_file(&f1, 4096, &[0xAB; 4096], when(40))
                .await
                .unwrap();
            tx.commit().await.unwrap();

            let mut expected = vec![0; 16384];
            expected[4096..8192].fill(0xAB);
            assert_eq!(read_all(&writer, path).await, expected);
            assert_prealloc_has_no_csums(&writer, path).await;

            // 5. Truncating to current i_size drops PREALLOC extents past EOF.
            let mut tx = writer.join().await.unwrap();
            let root = tx.root().await.unwrap();
            let f1 = tx
                .lookup(&root, "预分配-事前割当-사전할당".as_bytes())
                .await
                .unwrap()
                .unwrap();
            tx.truncate_file(&f1, 16384, when(50)).await.unwrap();
            assert_eq!(tx.metadata(&f1).await.unwrap().nbytes, 16384);
            tx.commit().await.unwrap();
            assert_eq!(read_all(&writer, path).await, expected);

            // 6. Inline-to-regular promotion and delalloc coherence on preallocate.
            let mut tx = writer.join().await.unwrap();
            let f2 = create(&mut tx, b"inline-promote").await;
            tx.write_file(&f2, 0, b"hello inline", when(60))
                .await
                .unwrap();
            tx.fallocate(&f2, 100, 5000, AllocateMode::Allocate, when(61))
                .await
                .unwrap();
            let meta = tx.metadata(&f2).await.unwrap();
            assert_eq!(meta.size, 5100);
            assert_eq!(meta.nbytes, 8192);

            let f3 = create(&mut tx, b"delalloc-coherent").await;
            tx.write_file(&f3, 0, &[0x11; 4096], when(62))
                .await
                .unwrap();
            tx.write_file(&f3, 8192, &[0x22; 4096], when(63))
                .await
                .unwrap();
            // Dirty pages at 0..4096 and 8192..12288; gap at 4096..8192 gets PREALLOC.
            tx.fallocate(&f3, 0, 16384, AllocateMode::Allocate, when(64))
                .await
                .unwrap();
            tx.commit().await.unwrap();

            let mut expected_f2 = vec![0; 5100];
            expected_f2[..12].copy_from_slice(b"hello inline");
            assert_eq!(read_all(&writer, b"/inline-promote").await, expected_f2);
            let f2_extents = extents_of(&writer, b"/inline-promote").await;
            assert_eq!(f2_extents.len(), 2);
            assert_eq!(f2_extents[0].kind, ExtentKind::Regular);
            assert_eq!(f2_extents[1].kind, ExtentKind::Prealloc);

            let mut expected_f3 = vec![0; 16384];
            expected_f3[..4096].fill(0x11);
            expected_f3[8192..12288].fill(0x22);
            assert_eq!(read_all(&writer, b"/delalloc-coherent").await, expected_f3);
            assert_prealloc_has_no_csums(&writer, b"/delalloc-coherent").await;
        });
    }
}

#[test]
fn punch_hole_handles_regular_compressed_prealloc_reflinked_inline_and_partial_sectors() {
    for no_holes in [true, false] {
        let compressor = Compressor::Zstd(Box::new(Zstd::new(3).unwrap()));
        let (_named, mut writer) = mount_image(no_holes, compressor);
        block_on(async {
            let mut tx = writer.join().await.unwrap();

            // 1. Compressed 64 KiB file, reflinked into a second file.
            let src = create(&mut tx, b"compressed").await;
            let mut payload = vec![0x5A_u8; 65536];
            for (i, chunk) in payload.as_chunks_mut::<4096>().0.iter_mut().enumerate() {
                chunk[0] = (i as u8).wrapping_add(1);
                chunk[4095] = (i as u8).wrapping_add(0x80);
            }
            tx.write_file(&src, 0, &payload, when(1)).await.unwrap();
            tx.commit().await.unwrap();

            let mut tx = writer.join().await.unwrap();
            let root = tx.root().await.unwrap();
            let src = tx.lookup(&root, b"compressed").await.unwrap().unwrap();
            let dst = create(&mut tx, b"reflink-copy").await;
            tx.clone_range(
                CloneRange {
                    source: &src,
                    destination: &dst,
                    source_offset: 0,
                    destination_offset: 0,
                    length: 65536,
                },
                when(2),
            )
            .await
            .unwrap();

            // Dirty one sector inside the range we are about to punch to verify delalloc drop.
            tx.write_file(&src, 16384, &[0xFF; 4096], when(3))
                .await
                .unwrap();

            // Punch unaligned range: head 5000..8192, whole 8192..24576, tail 24576..26000.
            tx.fallocate(&src, 5000, 21000, AllocateMode::PunchHole, when(4))
                .await
                .unwrap();
            // Punch sub-sector range inside a single sector: 30000..30200.
            tx.fallocate(&src, 30000, 200, AllocateMode::PunchHole, when(5))
                .await
                .unwrap();
            // Punch straddling one sector boundary with no whole sector: 40000..42000.
            tx.fallocate(&src, 40000, 2000, AllocateMode::PunchHole, when(6))
                .await
                .unwrap();

            let mut expected = payload.clone();
            expected[5000..26000].fill(0);
            expected[30000..30200].fill(0);
            expected[40000..42000].fill(0);

            // Size must be preserved by PUNCH_HOLE.
            assert_eq!(tx.metadata(&src).await.unwrap().size, 65536);

            // 2. Punching a preallocated extent beyond i_size frees it.
            let pre = create(&mut tx, b"prealloc-punch").await;
            tx.fallocate(&pre, 0, 32768, AllocateMode::KeepSize, when(7))
                .await
                .unwrap();
            assert_eq!(tx.metadata(&pre).await.unwrap().size, 0);
            assert_eq!(tx.metadata(&pre).await.unwrap().nbytes, 32768);
            tx.fallocate(&pre, 8192, 16384, AllocateMode::PunchHole, when(8))
                .await
                .unwrap();
            assert_eq!(tx.metadata(&pre).await.unwrap().size, 0);
            assert_eq!(tx.metadata(&pre).await.unwrap().nbytes, 16384);

            // 3. Inline file: partial punch, and full-sector punch.
            let inl_part = create(&mut tx, b"inline-partial").await;
            tx.write_file(&inl_part, 0, b"abcdefghij", when(9))
                .await
                .unwrap();
            tx.fallocate(&inl_part, 3, 4, AllocateMode::PunchHole, when(10))
                .await
                .unwrap();

            let inl_full = create(&mut tx, b"inline-full").await;
            tx.write_file(&inl_full, 0, b"abcdefghij", when(11))
                .await
                .unwrap();
            tx.fallocate(&inl_full, 0, 4096, AllocateMode::PunchHole, when(12))
                .await
                .unwrap();
            assert_eq!(tx.metadata(&inl_full).await.unwrap().size, 10);
            assert_eq!(tx.metadata(&inl_full).await.unwrap().nbytes, 0);

            tx.commit().await.unwrap();

            assert_eq!(read_all(&writer, b"/compressed").await, expected);
            // Reflinked sibling must remain completely intact.
            assert_eq!(read_all(&writer, b"/reflink-copy").await, payload);
            assert_eq!(
                read_all(&writer, b"/inline-partial").await,
                b"abc\0\0\0\0hij"
            );
            assert_eq!(read_all(&writer, b"/inline-full").await, vec![0; 10]);

            // Check NO_HOLES vs explicit hole items on /compressed.
            let extents = extents_of(&writer, b"/compressed").await;
            let has_explicit_hole = extents.iter().any(|e| e.stored == 0);
            assert_eq!(has_explicit_hole, !no_holes, "extents={extents:?}");
        });
    }
}

#[test]
fn zero_range_with_and_without_keep_size() {
    for no_holes in [true, false] {
        let (_named, mut writer) = mount_image(no_holes, Compressor::Plain);
        block_on(async {
            let mut tx = writer.join().await.unwrap();

            // 1. Zero range over existing written data (unaligned head + aligned middle + tail).
            let f1 = create(&mut tx, b"zero-existing").await;
            let initial = vec![0x77_u8; 20000];
            tx.write_file(&f1, 0, &initial, when(1)).await.unwrap();
            tx.commit().await.unwrap();

            let mut tx = writer.join().await.unwrap();
            let root = tx.root().await.unwrap();
            let f1 = tx.lookup(&root, b"zero-existing").await.unwrap().unwrap();
            tx.fallocate(&f1, 1000, 14000, AllocateMode::ZeroRange, when(2))
                .await
                .unwrap();
            let meta = tx.metadata(&f1).await.unwrap();
            assert_eq!(meta.size, 20000);

            // 2. Zero range extending past EOF without KEEP_SIZE.
            tx.fallocate(&f1, 20000, 10000, AllocateMode::ZeroRange, when(3))
                .await
                .unwrap();
            assert_eq!(tx.metadata(&f1).await.unwrap().size, 30000);

            // 3. Zero range past EOF with KEEP_SIZE preserves i_size and allocates PREALLOC.
            tx.fallocate(&f1, 32768, 8192, AllocateMode::ZeroRangeKeepSize, when(4))
                .await
                .unwrap();
            let meta = tx.metadata(&f1).await.unwrap();
            assert_eq!(meta.size, 30000);
            assert!(meta.nbytes >= 30000 + 8192);

            // 4. Sub-sector zero range on an empty file allocates a PREALLOC sector and extends size.
            let f2 = create(&mut tx, b"zero-subsector-hole").await;
            tx.fallocate(&f2, 100, 200, AllocateMode::ZeroRange, when(5))
                .await
                .unwrap();
            let meta2 = tx.metadata(&f2).await.unwrap();
            assert_eq!(meta2.size, 300);
            assert_eq!(meta2.nbytes, SECTOR);

            // 5. Sub-sector zero range on an inline file preserves surrounding bytes.
            let f3 = create(&mut tx, b"zero-inline").await;
            tx.write_file(&f3, 0, b"0123456789", when(6)).await.unwrap();
            tx.fallocate(&f3, 2, 5, AllocateMode::ZeroRange, when(7))
                .await
                .unwrap();

            tx.commit().await.unwrap();

            let mut expected = vec![0; 30000];
            expected[..1000].fill(0x77);
            expected[15000..20000].fill(0x77);
            assert_eq!(read_all(&writer, b"/zero-existing").await, expected);
            assert_prealloc_has_no_csums(&writer, b"/zero-existing").await;

            assert_eq!(
                read_all(&writer, b"/zero-subsector-hole").await,
                vec![0; 300]
            );
            let f2_extents = extents_of(&writer, b"/zero-subsector-hole").await;
            assert_eq!(f2_extents.len(), 1);
            assert_eq!(f2_extents[0].kind, ExtentKind::Prealloc);
            assert_prealloc_has_no_csums(&writer, b"/zero-subsector-hole").await;

            assert_eq!(
                read_all(&writer, b"/zero-inline").await,
                b"01\x00\x00\x00\x00\x00789"
            );
        });
    }
}

#[test]
fn fallocate_rejects_invalid_ranges_kinds_flags_and_rolls_back_enospc() {
    let (_named, mut writer) = mount_image(true, Compressor::Plain);
    block_on(async {
        let mut tx = writer.join().await.unwrap();
        let file = create(&mut tx, b"target").await;
        let root = tx.root().await.unwrap();
        let dir = tx.lookup(&root, b"dir").await.unwrap().unwrap();

        // len == 0 -> FallocateRange
        for mode in [
            AllocateMode::Allocate,
            AllocateMode::KeepSize,
            AllocateMode::PunchHole,
            AllocateMode::ZeroRange,
            AllocateMode::ZeroRangeKeepSize,
        ] {
            assert!(matches!(
                tx.fallocate(&file, 0, 0, mode, when(1)).await,
                Err(WriteError::FallocateRange)
            ));
        }

        // offset + len overflow -> FileOverflow
        assert!(matches!(
            tx.fallocate(&file, u64::MAX - 10, 20, AllocateMode::Allocate, when(2))
                .await,
            Err(WriteError::FileOverflow)
        ));

        // Directory -> WrongKind
        assert!(matches!(
            tx.fallocate(&dir, 0, 4096, AllocateMode::Allocate, when(3))
                .await,
            Err(WriteError::Read(Error::WrongKind {
                expected: FileKind::Regular,
                found: FileKind::Directory,
                ..
            }))
        ));

        // ENOSPC rolls back cleanly without changing file metadata or space usage.
        tx.write_file(&file, 0, &[0x33; 8192], when(4))
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let usage_before = writer.usage().unwrap();
        let mut tx = writer.join().await.unwrap();
        let root = tx.root().await.unwrap();
        let file = tx.lookup(&root, b"target").await.unwrap().unwrap();
        let err = tx
            .fallocate(&file, 8192, 1 << 40, AllocateMode::Allocate, when(5))
            .await
            .unwrap_err();
        assert!(
            matches!(err, WriteError::Space(SpaceError::Exhausted { .. })),
            "expected ENOSPC, got {err:?}"
        );
        let meta = tx.metadata(&file).await.unwrap();
        assert_eq!(meta.size, 8192);
        assert_eq!(meta.nbytes, 8192);
        tx.commit().await.unwrap();
        assert_eq!(writer.usage().unwrap(), usage_before);
    });
}

#[test]
fn fallocate_respects_immutable_and_append_inode_flags() {
    use btrfs_disk::items::{InodeFlags, Timespec};

    let stamp = ImageTime::from_secs(1_700_000_000);
    let named = tempfile::NamedTempFile::new().unwrap();
    let tree = TreeBuilder::new().root(Metadata::new(0o755, stamp));
    let options = FormatOptions::new([0x55; 16], stamp);
    let (formatted, _) = filesystem_image_options(tree, named.reopen().unwrap(), options);
    let root = block_on(formatted.root()).unwrap();
    let fs_tree = root.tree();
    let first = root.number() + 1;
    drop(formatted);

    let mut external =
        btrfs_transaction::filesystem::Filesystem::open(named.reopen().unwrap()).unwrap();
    let mut fixture = btrfs_transaction::transaction::Transaction::start(&mut external).unwrap();
    let ts = Timespec {
        sec: 1_700_000_000,
        nsec: 0,
    };
    for (idx, (name, flags)) in [
        ("immutable", InodeFlags::IMMUTABLE),
        ("append", InodeFlags::APPEND),
    ]
    .into_iter()
    .enumerate()
    {
        let ino = first + idx as u64;
        let mut args = btrfs_transaction::inode::InodeArgs::new(fixture.transid, 0o100644)
            .with_uniform_time(ts);
        args.flags = flags;
        fixture
            .create_inode(&mut external, fs_tree, ino, &args)
            .unwrap();
        fixture
            .link_dir_entry(
                &mut external,
                fs_tree,
                root.number(),
                ino,
                name.as_bytes(),
                1,
                idx as u64 + 2,
                ts,
            )
            .unwrap();
    }
    fixture.commit(&mut external).unwrap();
    drop(external);

    let mut writer = block_on(mount_writer(Disk(named.reopen().unwrap()))).unwrap();
    block_on(async {
        let mut tx = writer.join().await.unwrap();
        let root = tx.root().await.unwrap();
        let immutable = tx.lookup(&root, b"immutable").await.unwrap().unwrap();
        let append = tx.lookup(&root, b"append").await.unwrap().unwrap();

        for mode in [
            AllocateMode::Allocate,
            AllocateMode::KeepSize,
            AllocateMode::PunchHole,
            AllocateMode::ZeroRange,
            AllocateMode::ZeroRangeKeepSize,
        ] {
            assert!(matches!(
                tx.fallocate(&immutable, 0, 4096, mode, when(1)).await,
                Err(WriteError::InodeFlags { .. })
            ));
        }

        // APPEND permits preallocation (Allocate & KeepSize) and forbids PunchHole & ZeroRange.
        tx.fallocate(&append, 0, 4096, AllocateMode::KeepSize, when(2))
            .await
            .unwrap();
        tx.fallocate(&append, 0, 4096, AllocateMode::Allocate, when(3))
            .await
            .unwrap();
        for mode in [
            AllocateMode::PunchHole,
            AllocateMode::ZeroRange,
            AllocateMode::ZeroRangeKeepSize,
        ] {
            assert!(matches!(
                tx.fallocate(&append, 0, 4096, mode, when(4)).await,
                Err(WriteError::InodeFlags { .. })
            ));
        }
        tx.commit().await.unwrap();
    });
}

#[test]
#[ignore = "needs btrfs-progs; the Linux CI lane runs it with --run-ignored"]
fn fallocate_passes_btrfs_check() {
    for no_holes in [true, false] {
        let compressor = Compressor::Zstd(Box::new(Zstd::new(3).unwrap()));
        let (named, mut writer) = mount_image(no_holes, compressor);
        block_on(async {
            let mut tx = writer.join().await.unwrap();
            let a = create(&mut tx, b"a").await;
            let _b = create(&mut tx, b"b").await;
            let _c = create(&mut tx, b"c").await;

            // Compressed data + reflink + punch hole + zero range + prealloc.
            tx.write_file(&a, 0, &[0x23; 65536], when(1)).await.unwrap();
            tx.commit().await.unwrap();

            let mut tx = writer.join().await.unwrap();
            let root = tx.root().await.unwrap();
            let a = tx.lookup(&root, b"a").await.unwrap().unwrap();
            let b = tx.lookup(&root, b"b").await.unwrap().unwrap();
            let c = tx.lookup(&root, b"c").await.unwrap().unwrap();
            tx.clone_range(
                CloneRange {
                    source: &a,
                    destination: &b,
                    source_offset: 0,
                    destination_offset: 0,
                    length: 65536,
                },
                when(2),
            )
            .await
            .unwrap();
            tx.fallocate(&a, 5000, 20000, AllocateMode::PunchHole, when(3))
                .await
                .unwrap();
            tx.fallocate(&b, 12000, 16000, AllocateMode::ZeroRange, when(4))
                .await
                .unwrap();
            tx.fallocate(&b, 65536, 16384, AllocateMode::KeepSize, when(5))
                .await
                .unwrap();
            tx.fallocate(&c, 8192, 16384, AllocateMode::Allocate, when(6))
                .await
                .unwrap();
            tx.write_file(&c, 12288, &[0xEE; 4096], when(7))
                .await
                .unwrap();
            tx.commit().await.unwrap();
        });
        assert_btrfs_check(named.path());
    }
}
