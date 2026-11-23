//! Test-only entry points shared by corpus replay and coverage-guided fuzzing.
//! No input is trusted. Typed format/I/O errors are normal outcomes; panics,
//! sanitizer failures and libFuzzer timeouts remain failures.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use core::future::Future;
use core::ops::ControlFlow;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

use helios_hal::io::{IoError, IoResult};

use crate::items::{FileExtent, Metadata, RecordKind, RootRecord, dir_index_record, dir_records};
use crate::{BlockSource, Compression, DirBound, DirPosition, Error, FileKind, Filesystem, Key};

const SECTOR: usize = 4096;

/// Corpus representation: device length (LE u64), then records containing a
/// physical byte offset (LE u64) followed by one 4 KiB sector. Missing sectors
/// read as zero. Storage is proportional to the input, never the device size.
struct SparseImage<'a> {
    len: u64,
    sectors: BTreeMap<u64, &'a [u8]>,
}

impl BlockSource for SparseImage<'_> {
    fn size_bytes(&self) -> u64 {
        self.len
    }

    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> IoResult<()> {
        assert!(offset.is_multiple_of(SECTOR as u64));
        assert!(buf.len().is_multiple_of(SECTOR));
        if offset
            .checked_add(buf.len() as u64)
            .is_none_or(|end| end > self.len)
        {
            return Err(IoError::OutOfBounds);
        }
        for (index, chunk) in buf.as_chunks_mut::<SECTOR>().0.iter_mut().enumerate() {
            let at = offset + (index * SECTOR) as u64;
            match self.sectors.get(&at) {
                Some(bytes) => chunk.copy_from_slice(bytes),
                None => chunk.fill(0),
            }
        }
        Ok(())
    }
}

/// All futures below have an immediately ready source. Pending is a harness
/// contract violation, not an input rejection, and must fail the fuzz run.
fn ready<T>(future: impl Future<Output = T>) -> T {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("in-memory filesystem I/O unexpectedly yielded"),
    }
}

/// Traverse reachable metadata and exercise bounded reads at the start, middle,
/// last byte and EOF of each file. File sizes are untrusted and may be enormous;
/// sampling offsets explores those values without expanding sparse files.
pub async fn walk<S: BlockSource>(source: S) -> Result<(), Error> {
    let fs = Filesystem::mount(source).await?;
    let mut roots = vec![];
    fs.subvolumes(|tree, _| roots.push(tree)).await?;
    let mut pending = vec![fs.root().await?];
    for tree in roots {
        pending.push(fs.subvolume_root(tree).await?);
    }
    let mut visited = BTreeSet::new();
    let mut buffer = vec![0; 128 * 1024]; // BTRFS_MAX_UNCOMPRESSED.
    while let Some(inode) = pending.pop() {
        if !visited.insert((inode.tree(), inode.number())) {
            continue;
        }
        let mut attrs = vec![];
        fs.list_xattrs(&inode, |name| {
            attrs.push(name.to_vec());
            ControlFlow::Continue(())
        })
        .await?;
        for name in attrs {
            fs.xattr(&inode, &name, &mut buffer).await?;
        }
        match inode.kind() {
            FileKind::Directory => {
                let mut entries = vec![];
                fs.read_dir(&inode, DirPosition::START, DirBound::UNBOUNDED, |entry| {
                    entries.push((entry.name.to_vec(), entry.target, entry.kind));
                    ControlFlow::Continue(())
                })
                .await?;
                for (name, target, kind) in entries {
                    // Exercise both the directory-index and name-hash lookup paths.
                    let entry = crate::DirEntry {
                        name: &name,
                        target,
                        kind,
                        position: DirPosition::START,
                    };
                    pending.push(fs.open_entry(&inode, &entry).await?);
                    let _ = fs.lookup(&inode, &name).await?;
                }
            }
            FileKind::Regular => {
                let size = inode.metadata().size;
                for offset in [0, 1, size / 2, size.saturating_sub(1), size, u64::MAX] {
                    let count = fs.read(&inode, offset, &mut buffer).await?;
                    assert!(count <= buffer.len());
                    assert!(count as u64 <= size.saturating_sub(offset));
                }
            }
            FileKind::Symlink => {
                fs.read_link(&inode, &mut buffer).await?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Replay a sparse filesystem corpus input, including truncated records.
pub fn image(data: &[u8]) -> Result<(), Error> {
    let (header, rest) = data.split_at(data.len().min(8));
    let mut length = [0; 8];
    length[..header.len()].copy_from_slice(header);
    let mut sectors = BTreeMap::new();
    for record in rest.as_chunks::<{ SECTOR + 8 }>().0 {
        let offset = u64::from_le_bytes(record[..8].try_into().unwrap());
        sectors.insert(offset, &record[8..]);
    }
    ready(walk(SparseImage {
        len: u64::from_le_bytes(length),
        sectors,
    }))
}

/// Parse individual records without a checksum gate. Compressed data gets a
/// caller-owned output buffer bounded by the btrfs extent format.
pub fn record(data: &[u8]) {
    let Some((&kind, payload)) = data.split_first() else {
        return;
    };
    let key = Key::new(256, 108, 0);
    match kind % 6 {
        0 => {
            let _ = Metadata::parse(payload);
        }
        1 => {
            let _ = RootRecord::parse(key, payload, 4096);
        }
        2 => {
            for record in dir_records(payload, RecordKind::Entry) {
                let _ = record;
            }
            for record in dir_records(payload, RecordKind::Xattr) {
                let _ = record;
            }
            let _ = dir_index_record(payload);
        }
        3 => {
            let _ = FileExtent::parse(key, payload, 4096);
        }
        4 => {
            if payload.len() == 4096 {
                // Recompute only the checksum, so mutations reach semantic checks.
                let mut block = payload.to_vec();
                if let Some(kind) =
                    crate::ChecksumType::from_raw(u16::from_le_bytes([block[196], block[197]]))
                {
                    let digest = kind.digest(&block[32..]);
                    block[..32].fill(0);
                    block[..digest.as_bytes().len()].copy_from_slice(digest.as_bytes());
                }
                let _ = crate::Superblock::parse(&block, 65536);
            }
        }
        5 => {
            if payload.len() < 5 {
                return;
            }
            let algorithm = match payload[0] % 3 {
                0 => Compression::Zlib,
                1 => Compression::Lzo,
                _ => Compression::Zstd,
            };
            // BTRFS_MAX_UNCOMPRESSED; include zero and the full 128 KiB boundary.
            let len = u32::from_le_bytes([payload[1], payload[2], payload[3], 0]) as usize
                % (128 * 1024 + 1);
            let sector = 4096 << (payload[4] % 5);
            let mut output = vec![0; len];
            let _ = crate::compress::decompress(algorithm, &payload[5..], &mut output, sector);
        }
        _ => unreachable!(),
    }
}
