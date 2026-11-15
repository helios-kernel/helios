extern crate std;

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use std::fs::File;
use std::os::unix::fs::FileExt;

use btrfs_disk::tree::TreeBlock;
use ferrosys::btrfs::{FormatOptions, format_to};
use ferrosys::{Metadata, Timestamp, TreeBuilder};
use futures_lite::future::block_on;
use helios_hal::io::{IoError, IoResult};

use super::Filesystem;
use crate::source::BlockSource;
use crate::tree::edit::{Header, Leaf};
use crate::tree::write::{MetadataAllocator, Trees, WriteError};
use crate::tree::{Expected, Node, TreeRoot};
use crate::{ChecksumType, Key};

struct Disk(File);

#[cfg(feature = "write")]
struct FaultDisk {
    disk: Disk,
    fail_at: usize,
    operations: std::sync::Arc<std::sync::Mutex<Vec<(bool, u64)>>>,
    poisoned: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "write")]
impl FaultDisk {
    fn operation(&self, commit: bool, block: u64) -> IoResult<()> {
        use std::sync::atomic::Ordering;
        if self.poisoned.load(Ordering::SeqCst) {
            return Err(IoError::DeviceFault);
        }
        let mut operations = self.operations.lock().unwrap();
        operations.push((commit, block));
        if operations.len() == self.fail_at {
            self.poisoned.store(true, Ordering::SeqCst);
            return Err(IoError::DeviceFault);
        }
        Ok(())
    }
}

#[cfg(feature = "write")]
impl BlockSource for FaultDisk {
    fn size_bytes(&self) -> u64 {
        self.disk.size_bytes()
    }

    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> IoResult<()> {
        self.disk.read_at(offset, buf).await
    }
}

#[cfg(feature = "write")]
impl crate::source::BlockSink for FaultDisk {
    async fn stage(&self, block: u64, bytes: &[u8; 4096]) -> IoResult<()> {
        self.operation(false, block)?;
        self.disk.stage(block, bytes).await
    }

    async fn commit(&self, block: u64, bytes: &[u8; 4096]) -> IoResult<()> {
        self.operation(true, block)?;
        self.disk.commit(block, bytes).await
    }
}

#[cfg(feature = "write")]
async fn change_root_mode<S: crate::source::BlockSink>(
    fs: &Filesystem<S>,
) -> Result<TreeRoot, WriteError> {
    change_root_mode_with_retirements(fs, &mut crate::retirement::Retirements::default()).await
}

#[cfg(feature = "write")]
async fn change_root_mode_with_retirements<S: crate::source::BlockSink>(
    fs: &Filesystem<S>,
    retirements: &mut crate::retirement::Retirements,
) -> Result<TreeRoot, WriteError> {
    use crate::ondisk::{RawInodeItem, item_type, objectid, view};
    use crate::transaction::Transaction;
    use zerocopy::IntoBytes;

    let inode = fs.resolve(b"/").await?;
    let mut transaction =
        Transaction::new(&fs.volume, fs.snapshot.root_tree, &fs.snapshot, retirements).await?;
    let root = transaction.roots.get(objectid::FS_TREE)?;
    let key = Key::new(inode.number(), item_type::INODE_ITEM, 0);
    let bytes = transaction.trees.get(&fs.volume, root, key).await?.unwrap();
    let mut raw = *view::<RawInodeItem>(&bytes).unwrap();
    raw.mode.set((raw.mode.get() & !0o777) | 0o700);
    raw.transid.set(fs.superblock().generation() + 1);
    let root = transaction
        .trees
        .apply(
            &fs.volume,
            root,
            key,
            Some(raw.as_bytes()),
            &mut transaction.space,
        )
        .await?;
    transaction.roots.set(root)?;
    transaction
        .commit(
            || panic!("formatted fixture already has valid UUIDs"),
            std::thread::available_parallelism().unwrap(),
        )
        .await?;
    Ok(root)
}

#[cfg(feature = "write")]
#[test]
fn transaction_io_failures_recover_a_complete_generation() {
    block_on(async {
        // First record the complete write sequence, then fail each boundary.
        let mut count = 0;
        let mut first_commit = 0;
        for fail_at in core::iter::once(usize::MAX).chain(1..) {
            if fail_at != usize::MAX && fail_at > count {
                break;
            }
            let (_, image) = filesystem_image();
            let operations = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let fs = Filesystem::mount(FaultDisk {
                disk: Disk(image.try_clone().unwrap()),
                fail_at,
                operations: operations.clone(),
                poisoned: std::sync::atomic::AtomicBool::new(false),
            })
            .await
            .unwrap();
            let generation = fs.superblock().generation();
            let result = change_root_mode(&fs).await;
            let operations = operations.lock().unwrap().clone();
            if fail_at == usize::MAX {
                result.unwrap();
                count = operations.len();
                first_commit = operations.iter().position(|(commit, _)| *commit).unwrap() + 1;
                assert!(
                    operations[..first_commit - 1]
                        .iter()
                        .all(|(commit, _)| !commit)
                );
                let published: Vec<_> = operations[first_commit - 1..]
                    .iter()
                    .map(|(commit, block)| {
                        assert!(*commit);
                        block * crate::source::READ_ALIGNMENT
                    })
                    .collect();
                assert_eq!(published, vec![64 << 20, 64 << 10]);
            } else {
                assert!(result.is_err(), "operation {fail_at}");
                assert_eq!(operations.len(), fail_at);
            }
            let recovered = Filesystem::mount(Disk(image.try_clone().unwrap()))
                .await
                .unwrap();
            let published = fail_at == usize::MAX;
            assert_eq!(
                recovered.superblock().generation(),
                generation + u64::from(published)
            );
            assert_eq!(
                recovered
                    .resolve(b"/")
                    .await
                    .unwrap()
                    .metadata()
                    .permissions,
                if published { 0o700 } else { 0o755 }
            );
            // A torn primary selects the newest valid backup. If its commit
            // completed before failure, all of that generation must be readable.
            image
                .write_all_at(&[0; 4096], crate::superblock::MIRROR_OFFSETS[0])
                .unwrap();
            let recovered = Filesystem::mount(Disk(image)).await.unwrap();
            let backup_published = fail_at == usize::MAX || fail_at > first_commit;
            assert_eq!(
                recovered.superblock().generation(),
                generation + u64::from(backup_published)
            );
            assert_eq!(
                recovered
                    .resolve(b"/")
                    .await
                    .unwrap()
                    .metadata()
                    .permissions,
                if backup_published { 0o700 } else { 0o755 }
            );
        }
    });
}

#[cfg(feature = "write")]
#[test]
#[ignore = "needs btrfs-progs; the Linux CI lane runs it with --run-ignored"]
fn committed_transaction_passes_btrfs_check() {
    use std::io::{Seek, SeekFrom};
    use std::process::Command;

    block_on(async {
        for (separate, free_tree) in [(true, true), (false, true), (false, false)] {
            let (_, mut image) = filesystem_image_with_features(separate, free_tree);
            let mut named = tempfile::NamedTempFile::new().unwrap();
            image.seek(SeekFrom::Start(0)).unwrap();
            std::io::copy(&mut image, named.as_file_mut()).unwrap();
            for commit in [false, true] {
                if commit {
                    let fs = Filesystem::mount(Disk(named.reopen().unwrap()))
                        .await
                        .unwrap();
                    change_root_mode(&fs).await.unwrap();
                }
                let output = Command::new("btrfs")
                    .args(["check", "--readonly"])
                    .arg(named.path())
                    .output()
                    .expect("btrfs-progs must be installed");
                assert!(
                    output.status.success(),
                    "btrfs check: separate={separate}, free_tree={free_tree}, committed={commit}\n{}\n{}",
                    std::string::String::from_utf8_lossy(&output.stdout),
                    std::string::String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    });
}

#[cfg(feature = "write")]
#[test]
fn old_inodes_read_their_own_extent_and_checksum_generation() {
    use crate::accounting::DataChange;
    use crate::allocation::data::DataReference;
    use crate::ondisk::{RawFileExtentBody, RawFileExtentHead, item_type, view};
    use crate::retirement::Retirements;
    use crate::transaction::Transaction;
    use zerocopy::IntoBytes;

    block_on(async {
        let before = vec![0x53; 32768];
        let after = vec![0xa7; before.len()];
        let timestamp = Timestamp::from_secs(1_700_000_000);
        let tree = TreeBuilder::new()
            .root(Metadata::new(0o755, timestamp))
            .file("/data.bin", before.clone(), Metadata::new(0o644, timestamp));
        let (fs, image) = filesystem_image_tree(true, true, tree);
        let old_dir = fs.root().await.unwrap();
        let old_file = fs.lookup(&old_dir, b"data.bin").await.unwrap().unwrap();
        let mut retirements = Retirements::default();
        let mut transaction = Transaction::new(
            &fs.volume,
            fs.snapshot.root_tree,
            &fs.snapshot,
            &mut retirements,
        )
        .await
        .unwrap();
        let root = old_file.root;
        let key = Key::new(old_file.number(), item_type::EXTENT_DATA, 0);
        let mut bytes = transaction
            .trees
            .get(&fs.volume, root, key)
            .await
            .unwrap()
            .unwrap();
        let mut head = *view::<RawFileExtentHead>(&bytes).unwrap();
        let head_len = size_of::<RawFileExtentHead>();
        let mut body = *view::<RawFileExtentBody>(&bytes[head_len..]).unwrap();
        assert_eq!(head.extent_type, 1);
        assert_eq!(head.compression, 0);
        assert_eq!(body.offset.get(), 0);
        assert_eq!(body.num_bytes.get(), before.len() as u64);
        let old_data = Key::new(
            body.disk_bytenr.get(),
            item_type::EXTENT_ITEM,
            body.disk_num_bytes.get(),
        );
        let reference = DataReference {
            root: root.tree,
            inode: old_file.number(),
            offset: 0,
        };
        let concurrency = std::thread::available_parallelism().unwrap();
        let allocation = transaction
            .accounting
            .stage_data(
                &fs.volume,
                &mut transaction.trees,
                &mut transaction.space,
                &after,
                reference,
                concurrency,
            )
            .await
            .unwrap();
        head.generation.set(transaction.trees.generation());
        body.disk_bytenr.set(allocation.objectid);
        body.disk_num_bytes.set(allocation.offset);
        bytes[..head_len].copy_from_slice(head.as_bytes());
        bytes[head_len..].copy_from_slice(body.as_bytes());
        let root = transaction
            .trees
            .apply(&fs.volume, root, key, Some(&bytes), &mut transaction.space)
            .await
            .unwrap();
        transaction.roots.set(root).unwrap();
        transaction
            .accounting
            .update_data(
                &fs.volume,
                &mut transaction.trees,
                &mut transaction.space,
                DataChange {
                    key: old_data,
                    reference,
                    delta: -1,
                },
            )
            .await
            .unwrap();
        transaction
            .commit(|| panic!("valid fixture UUID"), concurrency)
            .await
            .unwrap();
        drop(fs);

        let current = Filesystem::mount(Disk(image)).await.unwrap();
        let new_file = current.resolve(b"/data.bin").await.unwrap();
        let mut output = vec![0; after.len()];
        assert_eq!(
            current.read(&new_file, 0, &mut output).await.unwrap(),
            after.len()
        );
        assert_eq!(output, after);
        // The new checksum tree has removed the old allocation's checksums.
        assert!(matches!(
            current
                .lookup_checksums(&current.snapshot, old_data.objectid, before.len())
                .await,
            Err(crate::Error::MissingDataChecksum { .. })
        ));
        assert_eq!(
            current.read(&old_file, 0, &mut output).await.unwrap(),
            before.len()
        );
        assert_eq!(output, before);
        // Descendants opened through an old directory must retain that view too.
        let from_old_dir = current
            .lookup(&old_dir, b"data.bin")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(from_old_dir, old_file);
        assert_eq!(
            current.read(&from_old_dir, 0, &mut output).await.unwrap(),
            before.len()
        );
        assert_eq!(output, before);
    });
}

#[cfg(feature = "write")]
#[test]
fn old_inode_clones_pin_retired_blocks_across_multiple_commits() {
    use crate::retirement::Retirements;
    use crate::space::Space;
    use crate::transaction::Transaction;

    fn allocates(space: &mut Space, wanted: u64, nodesize: u64) -> bool {
        let count = space.available_metadata() / nodesize;
        let mut found = false;
        for _ in 0..count {
            let address = space
                .allocate(crate::ondisk::objectid::FS_TREE, 0, Key::new(0, 0, 0))
                .unwrap();
            found |= address == wanted;
        }
        found
    }

    block_on(async {
        let (first, image) = filesystem_image();
        let inode = first.root().await.unwrap();
        let clone = inode.clone();
        let old_block = inode.root.bytenr;
        let mut retirements = Retirements::default();
        change_root_mode_with_retirements(&first, &mut retirements)
            .await
            .unwrap();
        drop(first);
        drop(inode);
        let second = Filesystem::mount(Disk(image.try_clone().unwrap()))
            .await
            .unwrap();
        change_root_mode_with_retirements(&second, &mut retirements)
            .await
            .unwrap();
        drop(second);
        let current = Filesystem::mount(Disk(image)).await.unwrap();
        let raw_space = Space::load(&current.volume, current.snapshot.root_tree)
            .await
            .unwrap();
        let raw_free = raw_space.committed_free(&BTreeMap::new()).unwrap();
        {
            let mut transaction = Transaction::new(
                &current.volume,
                current.snapshot.root_tree,
                &current.snapshot,
                &mut retirements,
            )
            .await
            .unwrap();
            // Excluding reader pins must not change on-disk free-space accounting.
            let pinned_free = transaction.space.committed_free(&BTreeMap::new()).unwrap();
            assert_eq!(raw_free.len(), pinned_free.len());
            for (raw, pinned) in raw_free.iter().zip(&pinned_free) {
                assert_eq!(raw.range, pinned.range);
                assert_eq!(raw.free, pinned.free);
            }
            assert!(!allocates(
                &mut transaction.space,
                old_block,
                u64::from(current.superblock().nodesize())
            ));
        }
        drop(clone);
        let mut transaction = Transaction::new(
            &current.volume,
            current.snapshot.root_tree,
            &current.snapshot,
            &mut retirements,
        )
        .await
        .unwrap();
        assert!(allocates(
            &mut transaction.space,
            old_block,
            u64::from(current.superblock().nodesize())
        ));
    });
}

#[cfg(feature = "write")]
#[test]
fn empty_transaction_does_not_publish() {
    block_on(async {
        let (_, image) = filesystem_image();
        let operations = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let fs = Filesystem::mount(FaultDisk {
            disk: Disk(image),
            fail_at: usize::MAX,
            operations: operations.clone(),
            poisoned: std::sync::atomic::AtomicBool::new(false),
        })
        .await
        .unwrap();
        crate::transaction::Transaction::new(
            &fs.volume,
            fs.snapshot.root_tree,
            &fs.snapshot,
            &mut crate::retirement::Retirements::default(),
        )
        .await
        .unwrap()
        .commit(
            || panic!("no new UUID required"),
            core::num::NonZeroUsize::MIN,
        )
        .await
        .unwrap();
        assert!(operations.lock().unwrap().is_empty());
    });
}

impl BlockSource for Disk {
    fn size_bytes(&self) -> u64 {
        self.0.metadata().unwrap().len()
    }
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> IoResult<()> {
        self.0
            .read_exact_at(buf, offset)
            .map_err(|_| IoError::DeviceFault)
    }
}

#[cfg(feature = "write")]
impl crate::source::BlockSink for Disk {
    async fn stage(&self, block: u64, bytes: &[u8; 4096]) -> IoResult<()> {
        self.0
            .write_all_at(bytes, block * crate::source::READ_ALIGNMENT)
            .map_err(|_| IoError::DeviceFault)
    }
    async fn commit(&self, block: u64, bytes: &[u8; 4096]) -> IoResult<()> {
        self.0.sync_all().map_err(|_| IoError::DeviceFault)?;
        self.stage(block, bytes).await?;
        self.0.sync_all().map_err(|_| IoError::DeviceFault)
    }
}

fn filesystem() -> Filesystem<Disk> {
    filesystem_image().0
}

fn filesystem_image() -> (Filesystem<Disk>, File) {
    filesystem_image_with_features(true, true)
}

fn filesystem_image_with_features(separate: bool, free_tree: bool) -> (Filesystem<Disk>, File) {
    let timestamp = Timestamp::from_secs(1_700_000_000);
    let tree = TreeBuilder::new().root(Metadata::new(0o755, timestamp));
    filesystem_image_tree(separate, free_tree, tree)
}

fn filesystem_image_tree(
    separate: bool,
    free_tree: bool,
    tree: TreeBuilder,
) -> (Filesystem<Disk>, File) {
    let mut file = tempfile::tempfile().unwrap();
    // ferrosys' default single-device geometry needs at least 109 MiB.
    let size = 128 << 20;
    file.set_len(size).unwrap();
    let timestamp = Timestamp::from_secs(1_700_000_000);
    let mut options = FormatOptions::new([0x53; 16], timestamp);
    if !separate {
        options.plan.compat_ro_flags = options
            .plan
            .compat_ro_flags
            .without(ferrosys::btrfs::ondisk::CompatRoFlags::BLOCK_GROUP_TREE);
    }
    if !free_tree {
        options.plan.compat_ro_flags = options
            .plan
            .compat_ro_flags
            .without(ferrosys::btrfs::ondisk::CompatRoFlags::FREE_SPACE_TREE)
            .without(ferrosys::btrfs::ondisk::CompatRoFlags::FREE_SPACE_TREE_VALID);
    }
    format_to(&mut file, tree, size, options).unwrap();
    let reference = file.try_clone().unwrap();
    (block_on(Filesystem::mount(Disk(file))).unwrap(), reference)
}

#[cfg(feature = "write")]
#[test]
fn transaction_publishes_roots_and_preserves_previous_generation() {
    use crate::transaction::Transaction;
    use btrfs_disk::superblock::{
        read_superblock_at, read_superblock_bytes_at, superblock_is_valid,
    };

    block_on(async {
        for (separate, free_tree) in [(true, true), (false, true), (false, false)] {
            let (fs, mut image) = filesystem_image_with_features(separate, free_tree);
            let generation = fs.superblock().generation();
            let root = change_root_mode(&fs).await.unwrap();

            let mounted = Filesystem::mount(Disk(image.try_clone().unwrap()))
                .await
                .unwrap();
            assert_eq!(mounted.superblock().generation(), generation + 1);
            assert_eq!(
                mounted.resolve(b"/").await.unwrap().metadata().permissions,
                0o700
            );
            assert_eq!(
                fs.resolve(b"/").await.unwrap().metadata().permissions,
                0o755
            );
            assert!(matches!(
                Transaction::new(
                    &fs.volume,
                    fs.snapshot.root_tree,
                    &fs.snapshot,
                    &mut crate::retirement::Retirements::default()
                )
                .await,
                Err(WriteError::StaleSnapshot)
            ));
            for offset in crate::superblock::MIRROR_OFFSETS {
                if offset + 4096 > image.metadata().unwrap().len() {
                    continue;
                }
                let bytes = read_superblock_bytes_at(&mut image, offset).unwrap();
                assert!(superblock_is_valid(&bytes));
                let disk = read_superblock_at(&mut image, offset).unwrap();
                assert_eq!(disk.bytenr, offset);
                assert_eq!(disk.generation, generation + 1);
                assert_eq!(disk.root, mounted.snapshot.root_tree.bytenr);
                let backup = disk
                    .backup_roots
                    .iter()
                    .find(|backup| backup.tree_root_gen == generation + 1)
                    .unwrap();
                assert_eq!(backup.tree_root, disk.root);
                assert_eq!(backup.fs_root, root.bytenr);
                assert_eq!(backup.fs_root_gen, root.generation);
                assert_eq!(backup.csum_root, mounted.snapshot.csum_tree.bytenr);
                assert_eq!(backup.bytes_used, disk.bytes_used);
                assert_eq!(backup.total_bytes, disk.total_bytes);
            }
        }
    });
}

#[test]
fn space_load_validates_formatted_file_data_references() {
    block_on(async {
        use crate::accounting::{Accounting, DataChange};
        use crate::allocation::data::{
            DataBackref, DataExtent, DataReference, SharedDataReference,
        };
        use crate::ondisk::{item_type, objectid};

        let timestamp = Timestamp::from_secs(1_700_000_000);
        let tree = TreeBuilder::new()
            .root(Metadata::new(0o755, timestamp))
            .file(
                "/data.bin",
                vec![0x53; 32768],
                Metadata::new(0o644, timestamp),
            );
        let (fs, _) = filesystem_image_tree(true, true, tree);
        let inode = fs.resolve(b"/data.bin").await.unwrap();
        let mut space = crate::space::Space::load(&fs.volume, fs.snapshot.root_tree)
            .await
            .unwrap();
        let root = super::find_root(&fs.volume, fs.snapshot.root_tree, objectid::EXTENT_TREE)
            .await
            .unwrap()
            .root;
        let mut cursor = crate::tree::Cursor::ceiling(&fs.volume, root, Key::new(0, 0, 0))
            .await
            .unwrap();
        let mut allocations = Vec::new();
        while let (Some(key), Some(bytes)) = (cursor.key(), cursor.item()) {
            if key.item_type == item_type::EXTENT_ITEM
                && u64::from_le_bytes(bytes[16..24].try_into().unwrap()) == 1
            {
                let extent = DataExtent::parse(key, bytes, fs.superblock().sectorsize()).unwrap();
                assert_eq!(extent.refs, 1);
                assert_eq!(extent.roots.len(), 1);
                let (reference, references) = extent.roots.first_key_value().unwrap();
                assert_eq!(reference.root, objectid::FS_TREE);
                assert_eq!(reference.inode, inode.number());
                assert_eq!(*references, 1);
                allocations.push((key, *reference));
            }
            cursor.advance(&fs.volume).await.unwrap();
        }
        assert!(!allocations.is_empty());
        let (key, original) = allocations[0];
        assert!(key.offset > u64::from(fs.superblock().nodesize()));
        let mut accounting = Accounting::new(&fs.volume, root, &space, fs.snapshot.csum_tree)
            .await
            .unwrap();
        let mut trees = Trees::new(
            fs.superblock().generation() + 1,
            fs.superblock().csum_type(),
        );
        // Fixed CRC32C collision with sector-aligned file offsets. Check the
        // identities against the independent disk-format implementation too.
        let other = DataReference {
            root: 256,
            inode: 218670021594820,
            offset: 249879179472896,
        };
        let collision = DataReference {
            root: 256,
            inode: 125603394931414,
            offset: 70811665399808,
        };
        assert_eq!(other.hash(), collision.hash());
        assert_eq!(
            other.hash(),
            btrfs_disk::items::extent_data_ref_hash(
                collision.root,
                collision.inode,
                collision.offset
            )
        );
        let shared = SharedDataReference(fs.default_subvolume.root.bytenr);
        assert!(
            !accounting
                .update_data(
                    &fs.volume,
                    &mut trees,
                    &mut space,
                    DataChange {
                        key,
                        reference: other,
                        delta: 1
                    }
                )
                .await
                .unwrap()
        );
        assert!(
            !accounting
                .update_data(
                    &fs.volume,
                    &mut trees,
                    &mut space,
                    DataChange {
                        key,
                        reference: collision,
                        delta: 1
                    }
                )
                .await
                .unwrap()
        );
        let displaced = Key::new(
            key.objectid,
            item_type::EXTENT_DATA_REF,
            collision.hash() + 1,
        );
        assert!(
            trees
                .get(&fs.volume, accounting.root, displaced)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            !accounting
                .update_data(
                    &fs.volume,
                    &mut trees,
                    &mut space,
                    DataChange {
                        key,
                        reference: other,
                        delta: -1
                    }
                )
                .await
                .unwrap()
        );
        assert!(
            trees
                .get(&fs.volume, accounting.root, other.key(key.objectid))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !accounting
                .update_data(
                    &fs.volume,
                    &mut trees,
                    &mut space,
                    DataChange {
                        key,
                        reference: shared,
                        delta: 2
                    }
                )
                .await
                .unwrap()
        );
        assert!(
            !accounting
                .update_data(
                    &fs.volume,
                    &mut trees,
                    &mut space,
                    DataChange {
                        key,
                        reference: original,
                        delta: -1
                    }
                )
                .await
                .unwrap()
        );
        assert!(
            !accounting
                .update_data(
                    &fs.volume,
                    &mut trees,
                    &mut space,
                    DataChange {
                        key,
                        reference: shared,
                        delta: -2
                    }
                )
                .await
                .unwrap()
        );
        assert!(
            accounting
                .update_data(
                    &fs.volume,
                    &mut trees,
                    &mut space,
                    DataChange {
                        key,
                        reference: collision,
                        delta: -1
                    }
                )
                .await
                .unwrap()
        );
        assert!(
            trees
                .get(&fs.volume, accounting.root, key)
                .await
                .unwrap()
                .is_none()
        );
        let checksum_key = crate::checksums::key(key.objectid);
        assert!(
            trees
                .get(&fs.volume, fs.snapshot.csum_tree, checksum_key)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            trees
                .get(&fs.volume, accounting.checksum_root(), checksum_key)
                .await
                .unwrap()
                .is_none()
        );
        accounting
            .sync_allocations(&fs.volume, &mut trees, &mut space)
            .await
            .unwrap();
        verify_group_usage(&fs, &trees, &accounting, space.group_root()).await;
        // Retired bytes appear in the next disk free-space tree, but remain
        // unavailable to this transaction's allocator.
        for group in space.committed_free(&BTreeMap::new()).unwrap() {
            assert!(
                group
                    .free
                    .iter()
                    .all(|range| range.end <= key.objectid
                        || range.start >= key.objectid + key.offset)
            );
        }
        assert!(trees.get(&fs.volume, root, key).await.unwrap().is_some());
    });
}

fn root_node(fs: &Filesystem<Disk>) -> Node {
    let root = fs.default_subvolume.root;
    block_on(Node::read(
        &fs.volume,
        root.bytenr,
        Expected {
            level: root.level,
            generation: root.generation,
            first_key: None,
        },
    ))
    .unwrap()
}

#[cfg(feature = "write")]
#[test]
fn data_staging_writes_all_copies_without_publishing_roots() {
    block_on(async {
        use crate::accounting::Accounting;
        use crate::allocation::data::DataReference;
        use crate::ondisk::objectid;

        let (fs, image) = filesystem_image();
        let mut space = crate::space::Space::load(&fs.volume, fs.snapshot.root_tree)
            .await
            .unwrap();
        let extent_root =
            super::find_root(&fs.volume, fs.snapshot.root_tree, objectid::EXTENT_TREE)
                .await
                .unwrap()
                .root;
        let mut accounting =
            Accounting::new(&fs.volume, extent_root, &space, fs.snapshot.csum_tree)
                .await
                .unwrap();
        let mut trees = Trees::new(
            fs.superblock().generation() + 1,
            fs.superblock().csum_type(),
        );
        let concurrency = std::thread::available_parallelism().unwrap();
        let bytes: Vec<_> = (0..32768).map(|index| (index % 251) as u8).collect();
        let reference = DataReference {
            root: 5,
            inode: 256,
            offset: 0,
        };
        let key = accounting
            .stage_data(
                &fs.volume,
                &mut trees,
                &mut space,
                &bytes,
                reference,
                concurrency,
            )
            .await
            .unwrap();
        let mut actual = vec![0; bytes.len()];
        for physical in fs.volume.chunks().map(key.objectid, key.offset).unwrap() {
            image.read_exact_at(&mut actual, physical).unwrap();
            assert_eq!(actual, bytes);
        }
        let sums = trees
            .get(
                &fs.volume,
                accounting.checksum_root(),
                crate::checksums::key(key.objectid),
            )
            .await
            .unwrap()
            .unwrap();
        let algorithm = fs.superblock().csum_type();
        for (sector, digest) in bytes
            .chunks_exact(fs.superblock().sectorsize() as usize)
            .zip(sums.chunks_exact(algorithm.size()))
        {
            assert!(algorithm.verifies(sector, digest));
        }
        accounting
            .sync_allocations(&fs.volume, &mut trees, &mut space)
            .await
            .unwrap();
        let mut copies_seen = 0;
        for (logical, bytes) in trees.blocks() {
            fs.volume.stage(logical, bytes, concurrency).await.unwrap();
            let copies = fs.volume.chunks().map(logical, bytes.len() as u64).unwrap();
            copies_seen = copies_seen.max(copies.len());
            let mut actual = vec![0; bytes.len()];
            for physical in copies {
                image.read_exact_at(&mut actual, physical).unwrap();
                assert_eq!(actual, bytes);
            }
        }
        assert_eq!(copies_seen, 2);
        let reopened = Filesystem::mount(Disk(image)).await.unwrap();
        assert_eq!(
            reopened.superblock().generation(),
            fs.superblock().generation()
        );
        assert_eq!(
            reopened.default_subvolume.root.bytenr,
            fs.default_subvolume.root.bytenr
        );
        assert!(
            trees
                .get(&fs.volume, extent_root, key)
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn private_data_allocations_register_cancel_and_reuse_their_full_ranges() {
    block_on(async {
        use crate::accounting::{Accounting, DataChange};
        use crate::allocation::data::{DataExtent, DataReference};
        use crate::ondisk::objectid;
        use crate::space::SpaceError;

        for (separate, free_tree) in [(true, true), (false, true), (false, false)] {
            let (fs, _) = filesystem_image_with_features(separate, free_tree);
            let mut space = crate::space::Space::load(&fs.volume, fs.snapshot.root_tree)
                .await
                .unwrap();
            let root = super::find_root(&fs.volume, fs.snapshot.root_tree, objectid::EXTENT_TREE)
                .await
                .unwrap()
                .root;
            let mut accounting = Accounting::new(&fs.volume, root, &space, fs.snapshot.csum_tree)
                .await
                .unwrap();
            let mut trees = Trees::new(
                fs.superblock().generation() + 1,
                fs.superblock().csum_type(),
            );
            let sector = u64::from(fs.superblock().sectorsize());
            assert!(matches!(
                space.reserve_data(0),
                Err(SpaceError::DataLength { .. })
            ));
            assert!(matches!(
                space.reserve_data(sector + 1),
                Err(SpaceError::DataLength { .. })
            ));
            let reference = DataReference {
                root: 5,
                inode: 256,
                offset: 0,
            };
            let first = accounting
                .allocate_data(&fs.volume, &mut trees, &mut space, 3 * sector, reference)
                .await
                .unwrap();
            let second = accounting
                .allocate_data(&fs.volume, &mut trees, &mut space, 5 * sector, reference)
                .await
                .unwrap();
            assert_eq!(second.objectid, first.objectid + first.offset);
            assert!(matches!(
                space.reserve_data(u64::MAX - (sector - 1)),
                Err(SpaceError::Exhausted { .. })
            ));
            accounting
                .sync_allocations(&fs.volume, &mut trees, &mut space)
                .await
                .unwrap();
            verify_group_usage(&fs, &trees, &accounting, space.group_root()).await;
            for key in [first, second] {
                let bytes = trees
                    .get(&fs.volume, accounting.root, key)
                    .await
                    .unwrap()
                    .unwrap();
                let extent = DataExtent::parse(key, &bytes, fs.superblock().sectorsize()).unwrap();
                assert_eq!(extent.refs, 1);
                assert_eq!(extent.generation, trees.generation());
                assert_eq!(extent.roots[&reference], 1);
                let independent = btrfs_disk::items::ExtentItem::parse(
                    &bytes,
                    &btrfs_disk::tree::DiskKey {
                        objectid: key.objectid,
                        key_type: btrfs_disk::tree::KeyType::ExtentItem,
                        offset: key.offset,
                    },
                )
                .unwrap();
                assert!(independent.is_data());
                assert_eq!(independent.refs, 1);
                assert!(trees.get(&fs.volume, root, key).await.unwrap().is_none());
                assert!(
                    accounting
                        .update_data(
                            &fs.volume,
                            &mut trees,
                            &mut space,
                            DataChange {
                                key,
                                reference,
                                delta: -1
                            }
                        )
                        .await
                        .unwrap()
                );
            }
            accounting
                .sync_allocations(&fs.volume, &mut trees, &mut space)
                .await
                .unwrap();
            verify_group_usage(&fs, &trees, &accounting, space.group_root()).await;
            let combined = accounting
                .allocate_data(&fs.volume, &mut trees, &mut space, 8 * sector, reference)
                .await
                .unwrap();
            assert_eq!(combined.objectid, first.objectid);
            accounting
                .sync_allocations(&fs.volume, &mut trees, &mut space)
                .await
                .unwrap();
            verify_group_usage(&fs, &trees, &accounting, space.group_root()).await;
            assert!(!space.cancel_data(fs.default_subvolume.root.bytenr));
        }
    });
}

#[test]
fn shared_tree_cow_converts_data_references_and_retires_only_the_last_owner() {
    block_on(async {
        use crate::accounting::{Accounting, MetadataBlock};
        use crate::allocation::MetadataReference;
        use crate::allocation::data::{DataExtent, DataReference};
        use crate::items::{ExtentData, FileExtent};
        use crate::ondisk::{item_type, objectid};

        for siblings in [0, 512] {
            let timestamp = Timestamp::from_secs(1_700_000_000);
            let mut tree = TreeBuilder::new()
                .root(Metadata::new(0o755, timestamp))
                .file(
                    "/data.bin",
                    vec![0x53; 32768],
                    Metadata::new(0o644, timestamp),
                );
            for index in 0..siblings {
                tree = tree.file(
                    alloc::format!("/sibling-{index}"),
                    b"inline data",
                    Metadata::new(0o644, timestamp),
                );
            }
            let (fs, _) = filesystem_image_tree(true, true, tree);
            let inode = fs.resolve(b"/data.bin").await.unwrap();
            let mut trees = Trees::new(
                fs.superblock().generation() + 1,
                fs.superblock().csum_type(),
            );
            let original = fs.default_subvolume.root;
            assert_eq!(original.level == 0, siblings == 0);
            let file_key = Key::new(inode.number(), item_type::EXTENT_DATA, 0);
            let bytes = trees
                .get(&fs.volume, original, file_key)
                .await
                .unwrap()
                .unwrap();
            let original_file = bytes.clone();
            let file = FileExtent::parse(file_key, &bytes, fs.superblock().sectorsize()).unwrap();
            let ExtentData::Regular {
                disk_bytenr,
                disk_num_bytes,
                ..
            } = file.data
            else {
                panic!("regular fixture extent")
            };
            let data_key = Key::new(disk_bytenr, item_type::EXTENT_ITEM, disk_num_bytes);
            let mut space = crate::space::Space::load(&fs.volume, fs.snapshot.root_tree)
                .await
                .unwrap();
            let extent_root =
                super::find_root(&fs.volume, fs.snapshot.root_tree, objectid::EXTENT_TREE)
                    .await
                    .unwrap()
                    .root;
            let mut accounting =
                Accounting::new(&fs.volume, extent_root, &space, fs.snapshot.csum_tree)
                    .await
                    .unwrap();
            let block = MetadataBlock {
                address: original.bytenr,
                level: original.level,
            };
            // Model two roots sharing this committed tree. Their extent pointers
            // initially have only the original owner's implicit data references.
            accounting
                .add_metadata(
                    &fs.volume,
                    &mut trees,
                    &mut space,
                    block,
                    MetadataReference::root(256),
                )
                .await
                .unwrap();
            let first = trees
                .apply(
                    &fs.volume,
                    original,
                    file_key,
                    Some(&original_file),
                    &mut space,
                )
                .await
                .unwrap();
            accounting
                .sync_allocations(&fs.volume, &mut trees, &mut space)
                .await
                .unwrap();
            let (_, old) = accounting
                .metadata(&fs.volume, &trees, block)
                .await
                .unwrap();
            assert_eq!(old.references(), 1);
            assert!(old.full_backrefs());
            let bytes = trees
                .get(&fs.volume, accounting.root, data_key)
                .await
                .unwrap()
                .unwrap();
            let data = DataExtent::parse(data_key, &bytes, fs.superblock().sectorsize()).unwrap();
            assert_eq!(data.refs, 2);
            // The old leaf's parent reference is external; the owner's reference
            // remains inline and now belongs to the new copy.
            assert_eq!(
                data.roots[&DataReference {
                    root: 5,
                    inode: inode.number(),
                    offset: 0
                }],
                1
            );
            let (parent_key, _) = trees
                .ceiling(
                    &fs.volume,
                    accounting.root,
                    Key::new(disk_bytenr, item_type::SHARED_DATA_REF, 0),
                )
                .await
                .unwrap()
                .unwrap();
            assert!(parent_key.is(disk_bytenr, item_type::SHARED_DATA_REF));

            let second = trees
                .apply(
                    &fs.volume,
                    TreeRoot {
                        tree: 256,
                        ..original
                    },
                    file_key,
                    Some(&original_file),
                    &mut space,
                )
                .await
                .unwrap();
            accounting
                .sync_allocations(&fs.volume, &mut trees, &mut space)
                .await
                .unwrap();
            assert!(matches!(
                accounting.metadata(&fs.volume, &trees, block).await,
                Err(WriteError::MissingExtent { .. })
            ));
            let bytes = trees
                .get(&fs.volume, accounting.root, data_key)
                .await
                .unwrap()
                .unwrap();
            let data = DataExtent::parse(data_key, &bytes, fs.superblock().sectorsize()).unwrap();
            assert_eq!(data.refs, 2);
            assert!(
                trees
                    .get(&fs.volume, accounting.root, parent_key)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                trees
                    .get(&fs.volume, first, file_key)
                    .await
                    .unwrap()
                    .is_some()
            );
            assert!(
                trees
                    .get(&fs.volume, second, file_key)
                    .await
                    .unwrap()
                    .is_some()
            );
            assert!(
                trees
                    .get(
                        &fs.volume,
                        fs.snapshot.csum_tree,
                        crate::checksums::key(disk_bytenr)
                    )
                    .await
                    .unwrap()
                    .is_some()
            );
            verify_group_usage(&fs, &trees, &accounting, space.group_root()).await;
        }
    });
}

#[test]
fn checksum_deletion_splits_items_preserves_neighbors_and_crosses_holes() {
    block_on(async {
        use crate::checksums::{Checksums, key};
        let fs = filesystem();
        let mut space = crate::space::Space::load(&fs.volume, fs.snapshot.root_tree)
            .await
            .unwrap();
        let mut trees = Trees::new(
            fs.superblock().generation() + 1,
            fs.superblock().csum_type(),
        );
        let mut checksums = Checksums {
            root: fs.snapshot.csum_tree,
        };
        let sector = u64::from(fs.superblock().sectorsize());
        let start = 16 << 20;
        let digests: Vec<_> = (0..20)
            .map(|index| {
                fs.superblock()
                    .csum_type()
                    .digest(&vec![index; sector as usize])
                    .as_bytes()
                    .to_vec()
            })
            .collect();
        for range in [0..8, 12..16, 16..20] {
            let bytes = digests[range.clone()].concat();
            checksums.root = trees
                .apply(
                    &fs.volume,
                    checksums.root,
                    key(start + range.start as u64 * sector),
                    Some(&bytes),
                    &mut space,
                )
                .await
                .unwrap();
        }
        checksums
            .remove(
                &fs.volume,
                &mut trees,
                &mut space,
                start + 2 * sector..start + 5 * sector,
            )
            .await
            .unwrap();
        assert_eq!(
            trees
                .get(&fs.volume, checksums.root, key(start))
                .await
                .unwrap()
                .unwrap(),
            digests[0..2].concat()
        );
        assert_eq!(
            trees
                .get(&fs.volume, checksums.root, key(start + 5 * sector))
                .await
                .unwrap()
                .unwrap(),
            digests[5..8].concat()
        );
        checksums
            .remove(
                &fs.volume,
                &mut trees,
                &mut space,
                start + 7 * sector..start + 17 * sector,
            )
            .await
            .unwrap();
        assert_eq!(
            contents(&trees, checksums.root),
            BTreeMap::from([
                (key(start), digests[0..2].concat()),
                (key(start + 5 * sector), digests[5..7].concat()),
                (key(start + 17 * sector), digests[17..20].concat()),
            ])
        );
        // Removing a missing checksum range is valid and does not allocate.
        let address = checksums.root.bytenr;
        checksums
            .remove(
                &fs.volume,
                &mut trees,
                &mut space,
                start + 8 * sector..start + 12 * sector,
            )
            .await
            .unwrap();
        assert_eq!(checksums.root.bytenr, address);
        let replacement = vec![0x91; 17 * sector as usize];
        checksums
            .set(
                &fs.volume,
                &mut trees,
                &mut space,
                start + sector,
                &replacement,
            )
            .await
            .unwrap();
        let digest = fs
            .superblock()
            .csum_type()
            .digest(&replacement[..sector as usize]);
        assert_eq!(
            contents(&trees, checksums.root),
            BTreeMap::from([
                (key(start), digests[0].clone()),
                (key(start + sector), digest.as_bytes().repeat(17)),
                (key(start + 18 * sector), digests[18..20].concat()),
            ])
        );
        checksums
            .remove(
                &fs.volume,
                &mut trees,
                &mut space,
                start..start + 20 * sector,
            )
            .await
            .unwrap();
        assert!(contents(&trees, checksums.root).is_empty());
        assert!(
            trees
                .ceiling(&fs.volume, fs.snapshot.csum_tree, key(0))
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn checksum_deletion_rejects_overlapping_or_partial_digest_items() {
    block_on(async {
        use crate::checksums::{Checksums, key};
        for overlap in [false, true] {
            let fs = filesystem();
            let mut space = crate::space::Space::load(&fs.volume, fs.snapshot.root_tree)
                .await
                .unwrap();
            let mut trees = Trees::new(
                fs.superblock().generation() + 1,
                fs.superblock().csum_type(),
            );
            let mut checksums = Checksums {
                root: fs.snapshot.csum_tree,
            };
            let sector = u64::from(fs.superblock().sectorsize());
            let start = 16 << 20;
            let width = fs.superblock().csum_type().size();
            let bytes = vec![0; if overlap { width * 4 } else { width + 1 }];
            checksums.root = trees
                .apply(
                    &fs.volume,
                    checksums.root,
                    key(start),
                    Some(&bytes),
                    &mut space,
                )
                .await
                .unwrap();
            if overlap {
                checksums.root = trees
                    .apply(
                        &fs.volume,
                        checksums.root,
                        key(start + sector),
                        Some(&vec![0; width]),
                        &mut space,
                    )
                    .await
                    .unwrap();
            }
            assert!(matches!(
                checksums
                    .remove(
                        &fs.volume,
                        &mut trees,
                        &mut space,
                        start..start + 4 * sector
                    )
                    .await,
                Err(WriteError::Checksum { .. })
            ));
        }
    });
}

#[test]
fn checksum_writes_span_full_leaf_items() {
    block_on(async {
        use crate::checksums::Checksums;
        let fs = filesystem();
        let mut space = crate::space::Space::load(&fs.volume, fs.snapshot.root_tree)
            .await
            .unwrap();
        let mut trees = Trees::new(
            fs.superblock().generation() + 1,
            fs.superblock().csum_type(),
        );
        let mut checksums = Checksums {
            root: fs.snapshot.csum_tree,
        };
        let sector = fs.superblock().sectorsize() as usize;
        let algorithm = fs.superblock().csum_type();
        // Enough digests to fill a complete node before accounting for headers.
        let sectors = fs.superblock().nodesize() as usize / algorithm.size();
        let bytes = vec![0x37; sector * sectors];
        let start = 16 << 20;
        checksums
            .set(&fs.volume, &mut trees, &mut space, start, &bytes)
            .await
            .unwrap();
        assert!(checksums.root.level > 0);
        let mut expected = start;
        let digest = algorithm.digest(&bytes[..sector]);
        for (key, payload) in contents(&trees, checksums.root) {
            assert_eq!(key.offset, expected);
            assert!(
                payload
                    .chunks_exact(algorithm.size())
                    .all(|stored| stored == digest.as_bytes())
            );
            expected += (payload.len() / algorithm.size() * sector) as u64;
        }
        assert_eq!(expected, start + bytes.len() as u64);
    });
}

#[test]
fn new_uuid_tree_supports_collisions_replacement_and_deletion() {
    block_on(async {
        use crate::ondisk::{item_type, objectid};
        use crate::uuid_tree::{UuidTree, key};

        let fs = filesystem();
        let mut space = crate::space::Space::load(&fs.volume, fs.snapshot.root_tree)
            .await
            .unwrap();
        let mut trees = Trees::new(fs.snapshot.root_tree.generation + 1, ChecksumType::Crc32c);
        let root = trees
            .create(
                &fs.volume,
                fs.snapshot.root_tree,
                objectid::UUID_TREE,
                &mut space,
            )
            .await
            .unwrap();
        assert!(contents(&trees, root).is_empty());
        let mut index = UuidTree::empty(root);
        let shared = key([1; 16], item_type::UUID_SUBVOL);
        let received = key([2; 16], item_type::UUID_RECEIVED);
        let both: Vec<_> = [5_u64, 256]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let desired = BTreeMap::from([(shared, both), (received, 5_u64.to_le_bytes().to_vec())]);
        assert!(
            index
                .sync(&fs.volume, &mut trees, &mut space, desired.clone())
                .await
                .unwrap()
        );
        assert_eq!(contents(&trees, index.root), desired);
        assert!(
            !index
                .sync(&fs.volume, &mut trees, &mut space, desired)
                .await
                .unwrap()
        );
        let desired = BTreeMap::from([(shared, 256_u64.to_le_bytes().to_vec())]);
        assert!(
            index
                .sync(&fs.volume, &mut trees, &mut space, desired.clone())
                .await
                .unwrap()
        );
        assert_eq!(contents(&trees, index.root), desired);
        assert_eq!(index.root.bytenr, root.bytenr);
        assert!(trees.retired().is_empty());
    });
}

struct Allocator {
    next: u64,
    size: u64,
    remaining: usize,
}

impl MetadataAllocator for Allocator {
    fn revise(&mut self, address: u64, _: Key) {
        assert!(address < self.next);
    }

    fn cancel(&mut self, _: u64) {
        self.remaining += 1;
    }

    fn allocate(&mut self, tree: u64, _: u8, _: Key) -> Result<u64, WriteError> {
        if self.remaining == 0 {
            return Err(WriteError::NoSpace { tree });
        }
        self.remaining -= 1;
        let address = self.next;
        self.next += self.size;
        Ok(address)
    }
}

fn contents(trees: &Trees, root: TreeRoot) -> BTreeMap<Key, Vec<u8>> {
    let blocks: BTreeMap<_, _> = trees.blocks().collect();
    let mut pending = vec![(root.bytenr, root.level, root.generation)];
    let mut result = BTreeMap::new();
    while let Some((address, level, generation)) = pending.pop() {
        let block = TreeBlock::parse(blocks[&address]);
        assert_eq!(block.header().bytenr, address);
        assert_eq!(block.header().level, level);
        assert_eq!(block.header().generation, generation);
        assert_eq!(block.header().owner, root.tree);
        assert!(ChecksumType::Crc32c.verifies(&blocks[&address][32..], &block.header().csum));
        match &block {
            TreeBlock::Leaf { items, .. } => {
                let mut previous = None;
                for (slot, item) in items.iter().enumerate() {
                    let key = Key::new(
                        item.key.objectid,
                        item.key.key_type.to_raw(),
                        item.key.offset,
                    );
                    assert!(previous.is_none_or(|previous| previous < key));
                    assert!(
                        result
                            .insert(key, block.item_data(slot).unwrap().to_vec())
                            .is_none()
                    );
                    previous = Some(key);
                }
            }
            TreeBlock::Node { ptrs, .. } => {
                for ptr in ptrs {
                    pending.push((ptr.blockptr, level - 1, ptr.generation));
                }
            }
        }
    }
    result
}

#[test]
fn large_middle_item_can_require_three_leaves_and_preserves_payloads() {
    let fs = filesystem();
    let original = root_node(&fs);
    let mut leaf = Leaf::empty(Header::for_level(&original, 0));
    let capacity = fs.superblock().nodesize() as usize - 101;
    let small = vec![0x31; capacity / 2 - 25];
    let large = vec![0x72; capacity - 25];
    let left = Key::new(1000, 24, 0);
    let middle = Key::new(1001, 24, 0);
    let right = Key::new(1002, 24, 0);
    leaf.set(left, &small).unwrap();
    leaf.set(right, &small).unwrap();
    assert_eq!(leaf.partitions().len(), 1);
    leaf.set(middle, &large).unwrap();
    let ranges = leaf.partitions();
    assert_eq!(ranges.len(), 3);
    for (range, expected) in
        ranges
            .into_iter()
            .zip([small.as_slice(), large.as_slice(), small.as_slice()])
    {
        let bytes = leaf.encode(range, 32 << 20, 2, 5, ChecksumType::Crc32c);
        let parsed = TreeBlock::parse(&bytes);
        assert_eq!(parsed.item_data(0), Some(expected));
    }
    let oversized = vec![0; capacity];
    assert!(leaf.set(middle, &oversized).is_err());
    let bytes = leaf.encode(1..2, 32 << 20, 2, 5, ChecksumType::Crc32c);
    assert_eq!(
        TreeBlock::parse(&bytes).item_data(0),
        Some(large.as_slice())
    );
}

#[test]
fn cow_insert_replace_delete_preserve_the_original_tree_and_collapse_the_root() {
    block_on(async {
        let fs = filesystem();
        let original = root_node(&fs);
        let mut expected: BTreeMap<_, _> = (0..original.nritems())
            .map(|slot| (original.key(slot), original.item(slot).to_vec()))
            .collect();
        let mut root = fs.default_subvolume.root;
        let mut trees = Trees::new(
            fs.superblock().generation() + 1,
            fs.superblock().csum_type(),
        );
        let mut allocator = Allocator {
            next: 32 << 20,
            size: u64::from(fs.superblock().nodesize()),
            remaining: 10_000,
        };
        // Reverse insertion exercises left-edge separator replacement as well as splits.
        for index in (0..300).rev() {
            let key = Key::new(1000 + index, 24, 0);
            let bytes = vec![index as u8; 257 + index as usize % 17 * 199];
            root = trees
                .apply(&fs.volume, root, key, Some(&bytes), &mut allocator)
                .await
                .unwrap();
            expected.insert(key, bytes);
        }
        assert!(root.level > 0);
        assert_eq!(contents(&trees, root), expected);
        for (&query, _) in expected.iter().step_by(31) {
            for key in [
                query,
                Key::new(query.objectid, query.item_type, query.offset + 1),
            ] {
                let wanted = expected
                    .range(key..)
                    .next()
                    .map(|(&key, bytes)| (key, bytes.clone()));
                assert_eq!(trees.ceiling(&fs.volume, root, key).await.unwrap(), wanted);
            }
        }
        assert!(
            trees
                .ceiling(&fs.volume, root, Key::new(u64::MAX, u8::MAX, u64::MAX))
                .await
                .unwrap()
                .is_none()
        );

        for index in (0..300).step_by(3) {
            let key = Key::new(1000 + index, 24, 0);
            let bytes = vec![0xa9; 7000];
            root = trees
                .apply(&fs.volume, root, key, Some(&bytes), &mut allocator)
                .await
                .unwrap();
            expected.insert(key, bytes);
        }
        assert_eq!(contents(&trees, root), expected);
        for key in expected.keys().copied().collect::<Vec<_>>() {
            root = trees
                .apply(&fs.volume, root, key, None, &mut allocator)
                .await
                .unwrap();
        }
        assert_eq!(root.level, 0);
        assert!(contents(&trees, root).is_empty());
        assert!(!trees.retired().is_empty());
        let reread = root_node(&fs);
        assert_eq!(original.nritems(), reread.nritems());
        for slot in 0..original.nritems() {
            assert_eq!(original.key(slot), reread.key(slot));
            assert_eq!(original.item(slot), reread.item(slot));
        }
    });
}

#[test]
fn splits_propagate_through_internal_nodes_and_deletion_shrinks_multiple_levels() {
    block_on(async {
        let fs = filesystem();
        let mut root = fs.default_subvolume.root;
        let mut trees = Trees::new(
            fs.superblock().generation() + 1,
            fs.superblock().csum_type(),
        );
        let nodesize = fs.superblock().nodesize() as usize;
        let mut allocator = Allocator {
            next: 32 << 20,
            size: nodesize as u64,
            remaining: 10_000,
        };
        // Each payload occupies its own leaf. More leaves than a branch's
        // key-pointer capacity forces a split above the leaf level too.
        let leaves = (nodesize - 101) / 33 + 3;
        let payload = vec![0x75; nodesize - 101 - 25];
        for index in 0..leaves {
            root = trees
                .apply(
                    &fs.volume,
                    root,
                    Key::new(1000 + index as u64, 24, 0),
                    Some(&payload),
                    &mut allocator,
                )
                .await
                .unwrap();
        }
        assert_eq!(root.level, 2);
        let records = contents(&trees, root);
        for index in 0..leaves {
            assert_eq!(records[&Key::new(1000 + index as u64, 24, 0)], payload);
        }
        for index in 0..leaves {
            root = trees
                .apply(
                    &fs.volume,
                    root,
                    Key::new(1000 + index as u64, 24, 0),
                    None,
                    &mut allocator,
                )
                .await
                .unwrap();
        }
        assert_eq!(root.level, 0);
        let original = root_node(&fs);
        let expected: BTreeMap<_, _> = (0..original.nritems())
            .map(|slot| (original.key(slot), original.item(slot).to_vec()))
            .collect();
        assert_eq!(contents(&trees, root), expected);
    });
}

#[test]
fn space_reservations_exclude_existing_extents_and_return_private_allocations() {
    use crate::space::{Space, SpaceError};
    use btrfs_disk::reader::{Traversal, filesystem_open, tree_walk};
    use btrfs_disk::tree::KeyType;

    block_on(async {
        let (fs, reference) = filesystem_image();
        let mut independent = filesystem_open(reference).unwrap();
        let mut occupied = Vec::new();
        tree_walk(
            &mut independent.reader,
            independent.tree_roots[&2].0,
            Traversal::Dfs,
            &mut |block| {
                if let TreeBlock::Leaf { items, .. } = block {
                    for item in items {
                        let length = match item.key.key_type {
                            KeyType::ExtentItem => item.key.offset,
                            KeyType::MetadataItem => u64::from(independent.superblock.nodesize),
                            _ => continue,
                        };
                        occupied.push(item.key.objectid..item.key.objectid + length);
                    }
                }
            },
        )
        .unwrap();
        let mut space = Space::load(&fs.volume, fs.snapshot.root_tree)
            .await
            .unwrap();
        let free_root = super::find_root(
            &fs.volume,
            fs.snapshot.root_tree,
            crate::ondisk::objectid::FREE_SPACE_TREE,
        )
        .await
        .unwrap()
        .root;
        let mut records = BTreeMap::new();
        let mut cursor = crate::tree::Cursor::ceiling(&fs.volume, free_root, Key::new(0, 0, 0))
            .await
            .unwrap();
        while let Some(key) = cursor.key() {
            records.insert(key, cursor.item().unwrap().to_vec());
            cursor.advance(&fs.volume).await.unwrap();
        }
        for group in space.committed_free(&BTreeMap::new()).unwrap() {
            let key = Key::new(
                group.range.start,
                crate::ondisk::item_type::FREE_SPACE_INFO,
                group.range.end - group.range.start,
            );
            let decoded = crate::free_space::FreeGroup::decode(
                key,
                &records[&key],
                &records,
                u64::from(fs.superblock().sectorsize()),
            )
            .unwrap();
            assert_eq!(decoded.free, group.free);
        }
        let original_available = space.available_metadata();
        let size = u64::from(fs.superblock().nodesize());
        let mut allocated = Vec::new();
        loop {
            match space.allocate(5, 0, Key::new(256, 1, 0)) {
                Ok(address) => {
                    assert!(
                        occupied
                            .iter()
                            .all(|range| address + size <= range.start || range.end <= address)
                    );
                    assert!(
                        fs.volume
                            .chunks()
                            .superblock_stripes()
                            .iter()
                            .all(|range| address + size <= range.start || range.end <= address)
                    );
                    assert!(fs.volume.chunks().map(address, size).is_ok());
                    allocated.push(address);
                }
                Err(WriteError::Space(SpaceError::Exhausted { .. })) => break,
                Err(error) => panic!("unexpected allocation failure: {error}"),
            }
        }
        assert!(!allocated.is_empty());
        let mut unique = allocated.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), allocated.len());
        assert_eq!(space.metadata().count(), allocated.len());
        assert!(!space.cancel_metadata(fs.default_subvolume.root.bytenr));
        // Alternating holes exercise coalescing on both sides of each free.
        for &address in allocated.iter().step_by(2) {
            assert!(space.cancel_metadata(address));
            assert!(!space.cancel_metadata(address));
        }
        for &address in allocated.iter().skip(1).step_by(2) {
            assert!(space.cancel_metadata(address));
        }
        assert_eq!(space.available_metadata(), original_available);
        assert_eq!(space.metadata().count(), 0);
        let address = space.allocate(5, 0, Key::new(256, 1, 0)).unwrap();
        assert_eq!(address, allocated[0]);
    });
}

#[test]
fn repeated_cow_edits_recycle_private_space_and_pin_committed_blocks() {
    let fs = filesystem();
    let mut space = block_on(crate::space::Space::load(&fs.volume, fs.snapshot.root_tree)).unwrap();
    let available = space.available_metadata();
    let original = fs.default_subvolume.root;
    let mut root = original;
    let mut trees = Trees::new(original.generation + 1, ChecksumType::Crc32c);
    let original_node = root_node(&fs);
    let original_key = original_node.key(0);
    assert_eq!(
        block_on(trees.get(&fs.volume, root, original_key)).unwrap(),
        Some(original_node.item(0).to_vec())
    );
    assert_eq!(
        block_on(trees.get(&fs.volume, root, Key::new(u64::MAX, 0, 0))).unwrap(),
        None
    );
    let key = Key::new(900, 1, 0);
    let mut private_address = None;
    for revision in 0_u64..2048 {
        root = block_on(trees.apply(
            &fs.volume,
            root,
            key,
            Some(&revision.to_le_bytes()),
            &mut space,
        ))
        .unwrap();
        assert_eq!(
            block_on(trees.get(&fs.volume, root, key)).unwrap(),
            Some(revision.to_le_bytes().to_vec())
        );
        assert_eq!(*private_address.get_or_insert(root.bytenr), root.bytenr);
        assert_eq!(trees.blocks().count(), 1);
        assert_eq!(space.metadata().count(), 1);
        assert_eq!(
            space.available_metadata(),
            available - u64::from(fs.volume.superblock().nodesize())
        );
        assert_eq!(
            trees.retired(),
            &[crate::tree::write::RetiredBlock {
                tree: original.tree,
                address: original.bytenr,
                level: original.level,
                generation: original.generation
            }]
        );
        assert!(!space.cancel_metadata(original.bytenr));
        let (address, reservation) = space.metadata().next().unwrap();
        assert_eq!(address, root.bytenr);
        assert_eq!(reservation.tree, root.tree);
        assert_eq!(reservation.level, root.level);
        let block = trees.blocks().next().unwrap().1;
        let node = TreeBlock::parse(block);
        let TreeBlock::Leaf { items, .. } = node else {
            panic!("expected leaf")
        };
        assert_eq!(reservation.first.objectid, items[0].key.objectid);
    }
    assert_eq!(contents(&trees, root)[&key], 2047_u64.to_le_bytes());
    assert_eq!(root_node(&fs).level(), original.level);
    loop {
        match space.allocate(5, 0, Key::new(256, 1, 0)) {
            Ok(_) => {}
            Err(WriteError::Space(crate::space::SpaceError::Exhausted { .. })) => break,
            Err(error) => panic!("unexpected allocation failure: {error}"),
        }
    }
    assert_eq!(space.available_metadata(), 0);
    let previous = root.bytenr;
    root = block_on(trees.apply(
        &fs.volume,
        root,
        key,
        Some(&2048_u64.to_le_bytes()),
        &mut space,
    ))
    .unwrap();
    assert_eq!(root.bytenr, previous);
    assert_eq!(contents(&trees, root)[&key], 2048_u64.to_le_bytes());
}

#[test]
fn metadata_accounting_removes_inline_and_external_refs_without_releasing_committed_space() {
    use crate::accounting::{Accounting, MetadataBlock};
    use crate::allocation::MetadataReference;
    use crate::ondisk::{item_type, objectid};
    use crate::space::Space;

    block_on(async {
        let fs = filesystem();
        let original_root =
            super::find_root(&fs.volume, fs.snapshot.root_tree, objectid::EXTENT_TREE)
                .await
                .unwrap()
                .root;
        let block = MetadataBlock {
            address: fs.default_subvolume.root.bytenr,
            level: fs.default_subvolume.root.level,
        };
        let size = u64::from(fs.superblock().nodesize());
        let mut trees = Trees::new(fs.superblock().generation() + 1, ChecksumType::Crc32c);
        let mut space = Space::load(&fs.volume, fs.snapshot.root_tree)
            .await
            .unwrap();
        let mut accounting =
            Accounting::new(&fs.volume, original_root, &space, fs.snapshot.csum_tree)
                .await
                .unwrap();
        let mut key = Key::new(
            block.address,
            item_type::METADATA_ITEM,
            u64::from(block.level),
        );
        let original = match trees.get(&fs.volume, original_root, key).await.unwrap() {
            Some(bytes) => bytes,
            None => {
                key = Key::new(block.address, item_type::EXTENT_ITEM, size);
                trees
                    .get(&fs.volume, original_root, key)
                    .await
                    .unwrap()
                    .unwrap()
            }
        };
        let parent = MetadataReference::parent(fs.snapshot.root_tree.bytenr);
        let parent_key = parent.key(block.address);
        accounting
            .add_metadata(&fs.volume, &mut trees, &mut space, block, parent)
            .await
            .unwrap();
        let (_, extent) = accounting
            .metadata(&fs.volume, &trees, block)
            .await
            .unwrap();
        assert_eq!(extent.references(), 2);
        assert!(!extent.full_backrefs());
        accounting
            .set_full_backrefs(&fs.volume, &mut trees, &mut space, block)
            .await
            .unwrap();
        let (_, extent) = accounting
            .metadata(&fs.volume, &trees, block)
            .await
            .unwrap();
        assert!(extent.full_backrefs());
        assert_eq!(extent.references(), 2);
        assert!(
            !accounting
                .remove_metadata(
                    &fs.volume,
                    &mut trees,
                    &mut space,
                    block,
                    MetadataReference::root(objectid::FS_TREE)
                )
                .await
                .unwrap()
        );
        let bytes = trees
            .get(&fs.volume, accounting.root, key)
            .await
            .unwrap()
            .unwrap();
        let disk_key = btrfs_disk::tree::DiskKey {
            objectid: key.objectid,
            key_type: if key.item_type == item_type::METADATA_ITEM {
                btrfs_disk::tree::KeyType::MetadataItem
            } else {
                btrfs_disk::tree::KeyType::ExtentItem
            },
            offset: key.offset,
        };
        let independent = btrfs_disk::items::ExtentItem::parse(&bytes, &disk_key).unwrap();
        assert_eq!(independent.refs, 1);
        assert!(independent.inline_refs.is_empty());
        assert_eq!(
            trees
                .get(&fs.volume, accounting.root, parent_key)
                .await
                .unwrap(),
            Some(Vec::new())
        );
        assert!(
            accounting
                .remove_metadata(&fs.volume, &mut trees, &mut space, block, parent)
                .await
                .unwrap()
        );
        assert_eq!(
            trees.get(&fs.volume, accounting.root, key).await.unwrap(),
            None
        );
        assert_eq!(
            trees
                .get(&fs.volume, accounting.root, parent_key)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            trees.get(&fs.volume, original_root, key).await.unwrap(),
            Some(original)
        );
        assert!(!space.cancel_metadata(block.address));
        accounting
            .sync_allocations(&fs.volume, &mut trees, &mut space)
            .await
            .unwrap();
        verify_group_usage(&fs, &trees, &accounting, space.group_root()).await;
    });
}

#[test]
fn metadata_registration_converges_across_extent_tree_growth_and_cancellation() {
    use crate::accounting::Accounting;
    use crate::ondisk::{item_type, objectid};
    use crate::space::Space;

    for (separate, free_tree) in [(false, true), (true, true), (false, false)] {
        block_on(async {
            let fs = filesystem_image_with_features(separate, free_tree).0;
            let extent_root =
                super::find_root(&fs.volume, fs.snapshot.root_tree, objectid::EXTENT_TREE)
                    .await
                    .unwrap()
                    .root;
            let mut space = Space::load(&fs.volume, fs.snapshot.root_tree)
                .await
                .unwrap();
            let mut trees = Trees::new(
                fs.superblock().generation() + 1,
                fs.superblock().csum_type(),
            );
            let size = u64::from(fs.superblock().nodesize());
            let mut accounting =
                Accounting::new(&fs.volume, extent_root, &space, fs.snapshot.csum_tree)
                    .await
                    .unwrap();
            assert_eq!(accounting.free_root().is_some(), free_tree);
            let mut root = fs.default_subvolume.root;
            // Full leaves force enough allocations to split the extent tree as its
            // own allocation records are registered.
            let count = (size as usize - 101) / 33 + 3;
            let payload = vec![0x56; size as usize - 101 - 25];
            for index in 0..count {
                root = trees
                    .apply(
                        &fs.volume,
                        root,
                        Key::new(1000 + index as u64, 24, 0),
                        Some(&payload),
                        &mut space,
                    )
                    .await
                    .unwrap();
            }
            let mut previously_registered: Vec<Key> = Vec::new();
            for shrink in [false, true] {
                if shrink {
                    for index in 0..count {
                        root = trees
                            .apply(
                                &fs.volume,
                                root,
                                Key::new(1000 + index as u64, 24, 0),
                                None,
                                &mut space,
                            )
                            .await
                            .unwrap();
                    }
                }
                accounting
                    .sync_allocations(&fs.volume, &mut trees, &mut space)
                    .await
                    .unwrap();
                verify_group_usage(&fs, &trees, &accounting, space.group_root()).await;
                let current: BTreeMap<_, _> = space.metadata().collect();
                assert_eq!(current.len(), trees.blocks().count());
                if !shrink {
                    assert!(accounting.root.level > 0);
                }
                for (&address, record) in &current {
                    let skinny = fs.superblock().incompat_flags() & (1 << 8) != 0;
                    let key = if skinny {
                        Key::new(address, item_type::METADATA_ITEM, u64::from(record.level))
                    } else {
                        Key::new(address, item_type::EXTENT_ITEM, size)
                    };
                    let bytes = trees
                        .get(&fs.volume, accounting.root, key)
                        .await
                        .unwrap()
                        .unwrap();
                    let disk_key = btrfs_disk::tree::DiskKey {
                        objectid: address,
                        key_type: if skinny {
                            btrfs_disk::tree::KeyType::MetadataItem
                        } else {
                            btrfs_disk::tree::KeyType::ExtentItem
                        },
                        offset: key.offset,
                    };
                    let independent =
                        btrfs_disk::items::ExtentItem::parse(&bytes, &disk_key).unwrap();
                    assert_eq!(independent.refs, 1);
                    assert_eq!(independent.generation, trees.generation());
                    assert_eq!(independent.inline_refs.len(), 1);
                    assert!(
                        matches!(independent.inline_refs[0], btrfs_disk::items::InlineRef::TreeBlockBackref { root, .. } if root == record.tree)
                    );
                    if !skinny {
                        let first = independent.tree_block_key.unwrap();
                        assert_eq!(first.objectid, record.first.objectid);
                        assert_eq!(first.key_type.to_raw(), record.first.item_type);
                        assert_eq!(first.offset, record.first.offset);
                    }
                }
                for key in previously_registered {
                    if !current.contains_key(&key.objectid) {
                        assert_eq!(
                            trees.get(&fs.volume, accounting.root, key).await.unwrap(),
                            None
                        );
                    }
                }
                previously_registered = current
                    .iter()
                    .map(|(&address, record)| {
                        if fs.superblock().incompat_flags() & (1 << 8) != 0 {
                            Key::new(address, item_type::METADATA_ITEM, u64::from(record.level))
                        } else {
                            Key::new(address, item_type::EXTENT_ITEM, size)
                        }
                    })
                    .collect();
                let stable: Vec<_> = trees
                    .blocks()
                    .map(|(address, bytes)| (address, bytes.to_vec()))
                    .collect();
                let available = space.available_metadata();
                accounting
                    .sync_allocations(&fs.volume, &mut trees, &mut space)
                    .await
                    .unwrap();
                assert_eq!(
                    stable,
                    trees
                        .blocks()
                        .map(|(address, bytes)| (address, bytes.to_vec()))
                        .collect::<Vec<_>>()
                );
                assert_eq!(space.available_metadata(), available);
            }
            assert!(!space.cancel_metadata(fs.default_subvolume.root.bytenr));
        });
    }
}

#[test]
fn cow_blocks_take_the_writing_tree_owner_from_a_shared_original() {
    block_on(async {
        let fs = filesystem();
        let original = fs.default_subvolume.root;
        let mut root = TreeRoot {
            tree: 256,
            ..original
        };
        let mut trees = Trees::new(original.generation + 1, fs.superblock().csum_type());
        let mut space = crate::space::Space::load(&fs.volume, fs.snapshot.root_tree)
            .await
            .unwrap();
        let payload = vec![0x74; fs.superblock().nodesize() as usize - 101 - 25];
        for index in 0..3 {
            root = trees
                .apply(
                    &fs.volume,
                    root,
                    Key::new(1000 + index, 24, 0),
                    Some(&payload),
                    &mut space,
                )
                .await
                .unwrap();
        }
        assert!(root.level > 0);
        contents(&trees, root);
        for (address, reservation) in space.metadata() {
            let bytes = trees
                .blocks()
                .find(|(candidate, _)| *candidate == address)
                .unwrap()
                .1;
            assert_eq!(TreeBlock::parse(bytes).header().owner, reservation.tree);
            assert_eq!(reservation.tree, 256);
        }
        let original_node = root_node(&fs);
        assert_eq!(original_node.key(0), Key::new(256, 1, 0));
        assert!(
            trees
                .blocks()
                .all(|(address, _)| address != original.bytenr)
        );
    });
}

async fn verify_group_usage(
    fs: &Filesystem<Disk>,
    trees: &Trees,
    accounting: &crate::accounting::Accounting,
    original_groups: TreeRoot,
) {
    use crate::ondisk::item_type;
    let extents = contents(trees, accounting.root);
    let free_records = accounting.free_root().map(|root| contents(trees, root));
    let mut cursor = crate::tree::Cursor::ceiling(&fs.volume, original_groups, Key::new(0, 0, 0))
        .await
        .unwrap();
    let mut groups = 0;
    while let Some(key) = cursor.key() {
        if key.item_type == item_type::BLOCK_GROUP_ITEM {
            let original =
                btrfs_disk::items::BlockGroupItem::parse(cursor.item().unwrap()).unwrap();
            let bytes = trees
                .get(&fs.volume, accounting.group_root(), key)
                .await
                .unwrap()
                .unwrap();
            let group = btrfs_disk::items::BlockGroupItem::parse(&bytes).unwrap();
            let expected: u64 = extents
                .keys()
                .filter(|extent| {
                    key.objectid <= extent.objectid && extent.objectid < key.objectid + key.offset
                })
                .map(|extent| match extent.item_type {
                    item_type::METADATA_ITEM => u64::from(fs.superblock().nodesize()),
                    item_type::EXTENT_ITEM => extent.offset,
                    _ => 0,
                })
                .sum();
            assert_eq!(group.used, expected, "group {key}");
            assert_eq!(group.flags, original.flags);
            assert_eq!(group.chunk_objectid, original.chunk_objectid);
            if let Some(records) = &free_records {
                let info_key = Key::new(key.objectid, item_type::FREE_SPACE_INFO, key.offset);
                let info = btrfs_disk::items::FreeSpaceInfo::parse(&records[&info_key]).unwrap();
                let decoded = crate::free_space::FreeGroup::decode(
                    info_key,
                    &records[&info_key],
                    records,
                    u64::from(fs.superblock().sectorsize()),
                )
                .unwrap();
                let mut expected_free = Vec::new();
                let mut address = key.objectid;
                for extent in extents.keys().filter(|extent| {
                    key.objectid <= extent.objectid
                        && extent.objectid < key.objectid + key.offset
                        && matches!(
                            extent.item_type,
                            item_type::EXTENT_ITEM | item_type::METADATA_ITEM
                        )
                }) {
                    if address < extent.objectid {
                        expected_free.push(address..extent.objectid);
                    }
                    address = extent.objectid
                        + if extent.item_type == item_type::METADATA_ITEM {
                            u64::from(fs.superblock().nodesize())
                        } else {
                            extent.offset
                        };
                }
                if address < key.objectid + key.offset {
                    expected_free.push(address..key.objectid + key.offset);
                }
                assert_eq!(decoded.free.iter().collect::<Vec<_>>(), expected_free);
                assert_eq!(info.extent_count as usize, expected_free.len());
                assert_eq!(
                    expected_free
                        .iter()
                        .map(|range| range.end - range.start)
                        .sum::<u64>()
                        + group.used,
                    key.offset
                );
            }
            groups += 1;
        }
        cursor.advance(&fs.volume).await.unwrap();
    }
    assert!(groups > 0);
}

#[test]
fn root_publication_preparation_converges_with_allocation_accounting() {
    use crate::accounting::Accounting;
    use crate::ondisk::objectid;
    use crate::roots::Roots;
    use crate::space::Space;

    block_on(async {
        let fs = filesystem();
        let mut roots = Roots::load(&fs.volume, fs.snapshot.root_tree)
            .await
            .unwrap();
        let mut space = Space::load(&fs.volume, fs.snapshot.root_tree)
            .await
            .unwrap();
        let mut accounting = Accounting::new(
            &fs.volume,
            roots.get(objectid::EXTENT_TREE).unwrap(),
            &space,
            fs.snapshot.csum_tree,
        )
        .await
        .unwrap();
        let mut trees = Trees::new(
            fs.superblock().generation() + 1,
            fs.superblock().csum_type(),
        );
        let size = u64::from(fs.superblock().nodesize());
        let mut root = roots.get(objectid::FS_TREE).unwrap();
        let payload = vec![0x37; size as usize - 101 - 25];
        for shrink in [false, true] {
            for index in 0..4 {
                root = trees
                    .apply(
                        &fs.volume,
                        root,
                        Key::new(1000 + index, 24, 0),
                        (!shrink).then_some(payload.as_slice()),
                        &mut space,
                    )
                    .await
                    .unwrap();
            }
            roots.set(root).unwrap();
            loop {
                accounting
                    .sync_allocations(&fs.volume, &mut trees, &mut space)
                    .await
                    .unwrap();
                roots.set(accounting.root).unwrap();
                roots.set(accounting.checksum_root()).unwrap();
                roots.set(accounting.group_root()).unwrap();
                if let Some(root) = accounting.free_root() {
                    roots.set(root).unwrap();
                }
                if !roots
                    .sync(&fs.volume, &mut trees, &mut space, &mut || {
                        panic!("fixture roots have valid extensions")
                    })
                    .await
                    .unwrap()
                {
                    break;
                }
            }
            for tree in [
                objectid::FS_TREE,
                objectid::EXTENT_TREE,
                objectid::BLOCK_GROUP_TREE,
                objectid::FREE_SPACE_TREE,
            ] {
                let cursor = crate::tree::Cursor::floor(
                    &fs.volume,
                    fs.snapshot.root_tree,
                    Key::new(tree, crate::ondisk::item_type::ROOT_ITEM, u64::MAX),
                )
                .await
                .unwrap();
                let key = cursor.key().unwrap();
                let original = cursor.item().unwrap().to_vec();
                let bytes = trees
                    .get(&fs.volume, roots.root, key)
                    .await
                    .unwrap()
                    .unwrap();
                let parsed = btrfs_disk::items::RootItem::parse(&bytes).unwrap();
                let root = roots.get(tree).unwrap();
                assert_eq!(parsed.bytenr, root.bytenr);
                assert_eq!(parsed.level, root.level);
                assert_eq!(parsed.generation, root.generation);
                assert_eq!(parsed.generation_v2, root.generation);
                let blocks = trees
                    .blocks()
                    .filter(|(_, bytes)| TreeBlock::parse(bytes).header().owner == tree)
                    .count();
                assert_eq!(parsed.bytes_used, blocks as u64 * size);
                assert_eq!(
                    parsed.uuid,
                    btrfs_disk::items::RootItem::parse(&original).unwrap().uuid
                );
                assert_eq!(
                    trees
                        .get(&fs.volume, fs.snapshot.root_tree, key)
                        .await
                        .unwrap(),
                    Some(original)
                );
            }
            verify_group_usage(&fs, &trees, &accounting, space.group_root()).await;
            assert_eq!(root.level, u8::from(!shrink));
        }
    });
}
