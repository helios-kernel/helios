//! The mounted filesystem: inodes, directories, file data, symlinks and
//! extended attributes.

#[cfg(feature = "write")]
pub(crate) mod writer;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::ops::ControlFlow;

use crate::chunk::ChunkMap;
use crate::csum::name_hash;
use crate::error::{Error, FileKind, ItemDefect};
use crate::items::{
    DirRecord, EntryTarget, Metadata, RecordKind, RootRecord, dir_index_record, dir_records,
};
use crate::key::Key;
use crate::ondisk::{NAME_MAX, SYMLINK_MAX, item_type, objectid};
use crate::source::BlockSource;
use crate::superblock::{self, Superblock};
use crate::tree::{Cursor, TreeRoot};
use crate::volume::{Mapping, Volume};

/// Most symlinks one path resolution follows, as Linux's `MAXSYMLINKS`.
pub const MAX_SYMLINK_FOLLOWS: usize = 40;

/// A btrfs filesystem mounted read-only from one device.
///
/// # Concurrency
///
/// Mounting builds everything the filesystem needs to find data — the
/// verified superblock, the chunk map, the roots of the root, checksum and
/// default-subvolume trees — and none of it changes afterwards. Every
/// operation takes `&self`, holds no lock, keeps its walk state in its own
/// future, and may run on any processor concurrently with any other; the
/// only shared resource is the [`BlockSource`], whose reads are themselves
/// independent. Each walk allocates the tree blocks on its path (at most
/// eight, each one node size) and a bounded data window, and frees them
/// when it finishes.
///
/// An [`Inode`] records the tree root of the commit it was read from, so
/// operations on it see that commit's state whatever happens afterwards.
#[derive(Clone)]
pub struct Filesystem<S> {
    snapshot: Arc<Snapshot>,
    volume: Volume<S>,
}

/// Every tree and address translation needed to read a committed generation.
/// Inodes retain this whole view, including its retirement pin.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub(crate) mapping: Arc<Mapping>,
    pub(crate) root_tree: TreeRoot,
    csum_tree: TreeRoot,
    default_subvolume: RootRecord,
}

#[cfg(feature = "write")]
impl Snapshot {
    pub(crate) fn advance(
        &self,
        superblock: Superblock,
        chunks: Arc<ChunkMap>,
        roots: &crate::roots::Roots,
    ) -> Result<Arc<Self>, crate::tree::write::WriteError> {
        Ok(Arc::new(Self {
            mapping: Mapping::advance(superblock, chunks),
            root_tree: roots.root,
            csum_tree: roots.get(objectid::CSUM_TREE)?,
            default_subvolume: RootRecord {
                root: roots.get(self.default_subvolume.root.tree)?,
                root_dirid: self.default_subvolume.root_dirid,
            },
        }))
    }
}

/// How a file extent item stores its range.
#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtentKind {
    /// The bytes are in the item itself.
    Inline,
    /// The bytes are in a data extent (a `disk_bytenr` of zero is a hole).
    Regular,
    /// Preallocated, never written.
    Prealloc,
}

/// One file extent item, as returned by [`Filesystem::file_extents`]: a test
/// inspection API.
#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtentInfo {
    /// File offset of the range the item covers.
    pub offset: u64,
    /// Length of that range in bytes.
    pub len: u64,
    pub kind: ExtentKind,
    /// The item's compression type; `None` for stored plain.
    pub compression: Option<crate::Compression>,
}

/// An inode, as of the commit it was read from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inode {
    snapshot: Arc<Snapshot>,
    root: TreeRoot,
    number: u64,
    metadata: Metadata,
}

impl Inode {
    /// The id of the subvolume tree the inode lives in.
    pub fn tree(&self) -> u64 {
        self.root.tree
    }

    /// The inode number within its subvolume.
    pub fn number(&self) -> u64 {
        self.number
    }

    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    pub fn kind(&self) -> FileKind {
        self.metadata.kind
    }

    fn expect_kind(&self, expected: FileKind) -> Result<(), Error> {
        if self.metadata.kind != expected {
            return Err(Error::WrongKind {
                tree: self.root.tree,
                inode: self.number,
                expected,
                found: self.metadata.kind,
            });
        }
        Ok(())
    }
}

/// A place in a directory listing to resume from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DirPosition(pub u64);

impl DirPosition {
    /// The start of a listing.
    pub const START: Self = Self(0);
}

/// One entry of a directory listing. `.` and `..` are not stored by the
/// format and are not listed.
#[derive(Clone, Copy, Debug)]
pub struct DirEntry<'a> {
    pub name: &'a [u8],
    pub kind: FileKind,
    pub target: EntryTarget,
    /// Where this entry sits in the listing.
    pub position: DirPosition,
}

impl<S: BlockSource> Filesystem<S> {
    /// Mounts the filesystem on `source`.
    ///
    /// Chooses and verifies the superblock, refuses features this crate
    /// does not implement, reads the chunk tree through the bootstrap
    /// chunks the superblock carries and checks the two agree, and finds
    /// the checksum tree and the default subvolume.
    pub async fn mount(source: S) -> Result<Self, Error> {
        let selected = superblock::select(&source).await?;
        let superblock = selected.superblock;
        superblock.check_supported()?;
        let bootstrap = ChunkMap::from_sys_chunk_array(&superblock, &selected.bytes)?;
        let chunk_root = superblock.chunk_tree();
        let root_tree = TreeRoot {
            tree: objectid::ROOT_TREE,
            bytenr: superblock.root_tree().bytenr,
            level: superblock.root_tree().level,
            generation: superblock.generation(),
        };
        let mut volume = Volume::new(source, superblock, bootstrap);

        let chunks = read_chunk_tree(
            &volume,
            TreeRoot {
                tree: objectid::CHUNK_TREE,
                bytenr: chunk_root.bytenr,
                level: chunk_root.level,
                generation: chunk_root.generation,
            },
        )
        .await?;
        let bootstrap = volume.replace_chunks(chunks);
        volume.chunks().check_contains(&bootstrap)?;

        let csum_tree = find_root(&volume, root_tree, objectid::CSUM_TREE)
            .await?
            .root;
        let default_tree = default_subvolume(&volume, root_tree).await?;
        let default_subvolume = find_root(&volume, root_tree, default_tree).await?;
        Ok(Self {
            snapshot: Arc::new(Snapshot {
                mapping: volume.mapping(),
                root_tree,
                csum_tree,
                default_subvolume,
            }),
            volume,
        })
    }

    #[cfg(feature = "write")]
    pub(crate) fn publish(&mut self, committed: crate::transaction::Committed) {
        self.volume.install(committed.snapshot.mapping.clone());
        self.snapshot = committed.snapshot;
    }

    pub fn superblock(&self) -> &Superblock {
        self.volume.superblock()
    }

    /// The id of the subvolume a mount lands in.
    pub fn default_subvolume(&self) -> u64 {
        self.snapshot.default_subvolume.root.tree
    }

    /// Visits each subvolume once, in tree-id order. A mount uses this
    /// inventory to assign distinct device identities before publishing
    /// the filesystem; inode numbers are unique only within a subvolume.
    pub async fn subvolumes<F>(&self, mut visit: F) -> Result<(), Error>
    where
        F: FnMut(u64, u64),
    {
        let mut cursor =
            Cursor::ceiling(&self.volume, self.snapshot.root_tree, Key::new(0, 0, 0)).await?;
        let mut previous: Option<(u64, u64)> = None;
        while let (Some(key), Some(item)) = (cursor.key(), cursor.item()) {
            if key.item_type == item_type::ROOT_ITEM
                && (key.objectid == objectid::FS_TREE
                    || (objectid::FIRST_FREE..=objectid::LAST_FREE).contains(&key.objectid))
            {
                let record = RootRecord::parse(key, item, self.volume.superblock().sectorsize())
                    .map_err(|defect| Error::Item {
                        tree: self.snapshot.root_tree.tree,
                        key,
                        defect,
                    })?;
                if let Some((tree, root_inode)) = previous
                    && tree != key.objectid
                {
                    visit(tree, root_inode);
                }
                previous = Some((key.objectid, record.root_dirid));
            }
            cursor.advance(&self.volume).await?;
        }
        if let Some((tree, root_inode)) = previous {
            visit(tree, root_inode);
        }
        Ok(())
    }

    /// The root directory of the default subvolume.
    pub async fn root(&self) -> Result<Inode, Error> {
        self.load_inode(
            self.snapshot.default_subvolume.root,
            self.snapshot.default_subvolume.root_dirid,
            &self.snapshot,
        )
        .await
    }

    /// The root directory of subvolume `tree`.
    pub async fn subvolume_root(&self, tree: u64) -> Result<Inode, Error> {
        let record = find_root(&self.volume, self.snapshot.root_tree, tree).await?;
        self.load_inode(record.root, record.root_dirid, &self.snapshot)
            .await
    }

    /// Inode `number` of subvolume `tree`, as of this view's commit. For a
    /// caller that holds an inode's identity across commits and needs its
    /// current state, such as a network or FUSE server.
    pub async fn inode(&self, tree: u64, number: u64) -> Result<Inode, Error> {
        let record = find_root(&self.volume, self.snapshot.root_tree, tree).await?;
        self.load_inode(record.root, number, &self.snapshot).await
    }

    async fn load_inode(
        &self,
        root: TreeRoot,
        number: u64,
        snapshot: &Arc<Snapshot>,
    ) -> Result<Inode, Error> {
        let volume = self.volume.view(&snapshot.mapping);
        let key = Key::new(number, item_type::INODE_ITEM, 0);
        let cursor = Cursor::ceiling(&volume, root, key).await?;
        let (Some(found), Some(item)) = (cursor.key(), cursor.item()) else {
            return Err(Error::MissingInode {
                tree: root.tree,
                inode: number,
            });
        };
        if found != key {
            return Err(Error::MissingInode {
                tree: root.tree,
                inode: number,
            });
        }
        let metadata = Metadata::parse(item).map_err(|defect| Error::Item {
            tree: root.tree,
            key,
            defect,
        })?;
        Ok(Inode {
            snapshot: snapshot.clone(),
            root,
            number,
            metadata,
        })
    }

    async fn open_target(&self, dir: &Inode, target: EntryTarget) -> Result<Inode, Error> {
        match target {
            EntryTarget::Inode(number) => self.load_inode(dir.root, number, &dir.snapshot).await,
            EntryTarget::Subvolume(tree) => {
                let volume = self.volume.view(&dir.snapshot.mapping);
                let record = find_root(&volume, dir.snapshot.root_tree, tree).await?;
                self.load_inode(record.root, record.root_dirid, &dir.snapshot)
                    .await
            }
        }
    }

    /// Opens what directory entry `entry` of `dir` names.
    pub async fn open_entry(&self, dir: &Inode, entry: &DirEntry<'_>) -> Result<Inode, Error> {
        self.open_target(dir, entry.target).await
    }

    /// Looks `name` up in directory `dir`. `None` when no entry has that
    /// name; `.` and `..` are not stored and are never found.
    pub async fn lookup(&self, dir: &Inode, name: &[u8]) -> Result<Option<Inode>, Error> {
        let volume = self.volume.view(&dir.snapshot.mapping);
        dir.expect_kind(FileKind::Directory)?;
        if name.is_empty() || name.len() > NAME_MAX {
            return Ok(None);
        }
        let key = Key::new(dir.number, item_type::DIR_ITEM, name_hash(name));
        let target = {
            let cursor = Cursor::ceiling(&volume, dir.root, key).await?;
            find_record(&cursor, key, name, RecordKind::Entry)?.map(|record| record.target())
        };
        match target {
            Some(target) => self.open_target(dir, target).await.map(Some),
            None => Ok(None),
        }
    }

    /// Lists directory `dir` from `from`, handing each entry to `visit`.
    ///
    /// `visit` returns [`ControlFlow::Continue`] to take the entry and go
    /// on, or [`ControlFlow::Break`] to stop without taking it. Returns the
    /// position to resume from when `visit` stopped the listing, `None`
    /// once every entry has been visited.
    pub async fn read_dir<F>(
        &self,
        dir: &Inode,
        from: DirPosition,
        mut visit: F,
    ) -> Result<Option<DirPosition>, Error>
    where
        F: FnMut(DirEntry<'_>) -> ControlFlow<()>,
    {
        let volume = self.volume.view(&dir.snapshot.mapping);
        dir.expect_kind(FileKind::Directory)?;
        let start = Key::new(dir.number, item_type::DIR_INDEX, from.0);
        let mut cursor = Cursor::ceiling(&volume, dir.root, start).await?;
        while let (Some(key), Some(item)) = (cursor.key(), cursor.item()) {
            if !key.is(dir.number, item_type::DIR_INDEX) {
                break;
            }
            let record = dir_index_record(item).map_err(|defect| Error::Item {
                tree: dir.root.tree,
                key,
                defect,
            })?;
            let entry = DirEntry {
                name: record.name,
                kind: record.kind(),
                target: record.target(),
                position: DirPosition(key.offset),
            };
            if visit(entry).is_break() {
                return Ok(Some(DirPosition(key.offset)));
            }
            cursor.advance(&volume).await?;
        }
        Ok(None)
    }

    /// Reads file data at `offset` into `buf`. Returns the bytes read,
    /// fewer than `buf.len()` only at the end of the file.
    pub async fn read(&self, file: &Inode, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        file.expect_kind(FileKind::Regular)?;
        self.read_range(file, offset, buf).await
    }

    /// The file extents of `file`, in file-offset order, as stored.
    ///
    /// A test inspection API: it exposes the on-disk layout (extent kind and
    /// compression) that reads deliberately hide.
    #[cfg(feature = "test-support")]
    pub async fn file_extents(&self, file: &Inode) -> Result<Vec<ExtentInfo>, Error> {
        file.expect_kind(FileKind::Regular)?;
        let volume = self.volume.view(&file.snapshot.mapping);
        crate::data::Reader::new(&volume, &volume, file.snapshot.csum_tree)
            .extents(crate::data::File {
                root: file.root,
                number: file.number,
                metadata: &file.metadata,
            })
            .await
    }

    /// Reads the target of symlink `link` into `buf`. Returns the target's
    /// length; the target is complete when that is at most `buf.len()`.
    pub async fn read_link(&self, link: &Inode, buf: &mut [u8]) -> Result<usize, Error> {
        link.expect_kind(FileKind::Symlink)?;
        let size = link.metadata.size;
        if size == 0 || size > SYMLINK_MAX {
            return Err(Error::Item {
                tree: link.root.tree,
                key: Key::new(link.number, item_type::INODE_ITEM, 0),
                defect: ItemDefect::SymlinkSize(size),
            });
        }
        let len = size as usize;
        let take = len.min(buf.len());
        self.read_range(link, 0, &mut buf[..take]).await?;
        Ok(len)
    }

    /// Reads extended attribute `name` of `inode` into `buf`. Returns the
    /// value's length, `None` when the inode has no such attribute; the
    /// value is complete when its length is at most `buf.len()`.
    pub async fn xattr(
        &self,
        inode: &Inode,
        name: &[u8],
        buf: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        let volume = self.volume.view(&inode.snapshot.mapping);
        if name.is_empty() || name.len() > NAME_MAX {
            return Ok(None);
        }
        let key = Key::new(inode.number, item_type::XATTR_ITEM, name_hash(name));
        let cursor = Cursor::ceiling(&volume, inode.root, key).await?;
        let Some(record) = find_record(&cursor, key, name, RecordKind::Xattr)? else {
            return Ok(None);
        };
        let take = record.data.len().min(buf.len());
        buf[..take].copy_from_slice(&record.data[..take]);
        Ok(Some(record.data.len()))
    }

    /// Hands the name of every extended attribute of `inode` to `visit`,
    /// until it returns [`ControlFlow::Break`].
    pub async fn list_xattrs<F>(&self, inode: &Inode, mut visit: F) -> Result<(), Error>
    where
        F: FnMut(&[u8]) -> ControlFlow<()>,
    {
        let volume = self.volume.view(&inode.snapshot.mapping);
        let start = Key::new(inode.number, item_type::XATTR_ITEM, 0);
        let mut cursor = Cursor::ceiling(&volume, inode.root, start).await?;
        while let (Some(key), Some(item)) = (cursor.key(), cursor.item()) {
            if !key.is(inode.number, item_type::XATTR_ITEM) {
                break;
            }
            for record in dir_records(item, RecordKind::Xattr) {
                let record = record.map_err(|defect| Error::Item {
                    tree: inode.root.tree,
                    key,
                    defect,
                })?;
                if visit(record.name).is_break() {
                    return Ok(());
                }
            }
            cursor.advance(&volume).await?;
        }
        Ok(())
    }

    /// Resolves `path` from the default subvolume's root directory,
    /// following symlinks, the last component's included, up to
    /// [`MAX_SYMLINK_FOLLOWS`] of them. An absolute symlink target restarts
    /// from that root; `..` never climbs above it.
    pub async fn resolve(&self, path: &[u8]) -> Result<Inode, Error> {
        let root = self.root().await?;
        let mut parents: Vec<Inode> = Vec::new();
        let mut current = root.clone();
        let mut remaining: Vec<u8> = path.to_vec();
        let mut cursor = 0;
        let mut component_index = 0;
        let mut follows = 0;
        while cursor < remaining.len() {
            let rest = &remaining[cursor..];
            let length = rest
                .iter()
                .position(|byte| *byte == b'/')
                .unwrap_or(rest.len());
            let component = &rest[..length];
            let next_cursor = cursor + length + 1;
            match component {
                b"" | b"." => {
                    cursor = next_cursor;
                    continue;
                }
                b".." => {
                    if let Some(parent) = parents.pop() {
                        current = parent;
                    }
                    cursor = next_cursor;
                    component_index += 1;
                    continue;
                }
                _ => {}
            }
            let found = self
                .lookup(&current, component)
                .await?
                .ok_or(Error::NotFound {
                    component: component_index,
                })?;
            component_index += 1;
            if found.kind() == FileKind::Symlink {
                follows += 1;
                if follows > MAX_SYMLINK_FOLLOWS {
                    return Err(Error::SymlinkLimit {
                        limit: MAX_SYMLINK_FOLLOWS,
                    });
                }
                let mut target = vec![0_u8; SYMLINK_MAX as usize];
                let len = self.read_link(&found, &mut target).await?;
                target.truncate(len);
                if target.first() == Some(&b'/') {
                    parents.clear();
                    current = root.clone();
                }
                target.push(b'/');
                if next_cursor < remaining.len() {
                    target.extend_from_slice(&remaining[next_cursor..]);
                }
                remaining = target;
                cursor = 0;
                continue;
            }
            parents.push(core::mem::replace(&mut current, found));
            cursor = next_cursor;
        }
        Ok(current)
    }

    async fn read_range(&self, inode: &Inode, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let volume = self.volume.view(&inode.snapshot.mapping);
        crate::data::Reader::new(&volume, &volume, inode.snapshot.csum_tree)
            .read(
                crate::data::File {
                    root: inode.root,
                    number: inode.number,
                    metadata: &inode.metadata,
                },
                offset,
                buf,
            )
            .await
    }

    #[cfg(all(test, feature = "write"))]
    async fn lookup_checksums(
        &self,
        snapshot: &Arc<Snapshot>,
        logical: u64,
        len: usize,
    ) -> Result<Vec<u8>, Error> {
        let volume = self.volume.view(&snapshot.mapping);
        crate::data::Reader::new(&volume, &volume, snapshot.csum_tree)
            .lookup_checksums(logical, len)
            .await
    }
}

/// The record named `name` in the directory or xattr item at `key`, which
/// the cursor sits on or past.
fn find_record<'a>(
    cursor: &'a Cursor,
    key: Key,
    name: &[u8],
    kind: RecordKind,
) -> Result<Option<DirRecord<'a>>, Error> {
    let (Some(found), Some(item)) = (cursor.key(), cursor.item()) else {
        return Ok(None);
    };
    if found != key {
        return Ok(None);
    }
    for record in dir_records(item, kind) {
        let record = record.map_err(|defect| Error::Item {
            tree: cursor.tree(),
            key,
            defect,
        })?;
        if record.name == name {
            return Ok(Some(record));
        }
    }
    Ok(None)
}

/// Every chunk item of the chunk tree, read through the bootstrap map.
async fn read_chunk_tree<S: BlockSource>(
    volume: &Volume<S>,
    root: TreeRoot,
) -> Result<ChunkMap, Error> {
    let mut chunks = ChunkMap::default();
    let start = Key::new(objectid::FIRST_CHUNK_TREE, item_type::CHUNK_ITEM, 0);
    let mut cursor = Cursor::ceiling(volume, root, start).await?;
    while let (Some(key), Some(item)) = (cursor.key(), cursor.item()) {
        if !key.is(objectid::FIRST_CHUNK_TREE, item_type::CHUNK_ITEM) {
            break;
        }
        chunks.insert_item(key, item, volume.superblock())?;
        cursor.advance(volume).await?;
    }
    Ok(chunks)
}

/// The newest root item of tree `tree`.
pub(crate) async fn find_root<S: BlockSource>(
    volume: &Volume<S>,
    root_tree: TreeRoot,
    tree: u64,
) -> Result<RootRecord, Error> {
    let cursor = Cursor::floor(
        volume,
        root_tree,
        Key::new(tree, item_type::ROOT_ITEM, u64::MAX),
    )
    .await?;
    let (Some(key), Some(item)) = (cursor.key(), cursor.item()) else {
        return Err(Error::MissingRoot { tree });
    };
    if !key.is(tree, item_type::ROOT_ITEM) {
        return Err(Error::MissingRoot { tree });
    }
    RootRecord::parse(key, item, volume.superblock().sectorsize()).map_err(|defect| Error::Item {
        tree: objectid::ROOT_TREE,
        key,
        defect,
    })
}

/// The subvolume the root tree's `default` directory entry names, or the
/// top-level one when the filesystem records none.
async fn default_subvolume<S: BlockSource>(
    volume: &Volume<S>,
    root_tree: TreeRoot,
) -> Result<u64, Error> {
    const NAME: &[u8] = b"default";
    let key = Key::new(
        objectid::ROOT_TREE_DIR,
        item_type::DIR_ITEM,
        name_hash(NAME),
    );
    let cursor = Cursor::ceiling(volume, root_tree, key).await?;
    let tree = match find_record(&cursor, key, NAME, RecordKind::Entry)? {
        Some(record) => record.location.objectid,
        None => objectid::FS_TREE,
    };
    let is_subvolume =
        tree == objectid::FS_TREE || (objectid::FIRST_FREE..=objectid::LAST_FREE).contains(&tree);
    if !is_subvolume {
        return Err(Error::Item {
            tree: objectid::ROOT_TREE,
            key,
            defect: ItemDefect::LocationType(item_type::ROOT_ITEM),
        });
    }
    Ok(tree)
}

#[cfg(all(test, feature = "write"))]
mod write_tests;
