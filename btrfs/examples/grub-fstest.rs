//! Reader transport for the unmodified GRUB filesystem test assertions.
//! Only `ls` and `cmp` are used by its single-device btrfs configurations.
mod support;

use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::ops::ControlFlow;

use chrono::DateTime;
use futures_lite::future::block_on;
use helios_btrfs::{DirBound, DirPosition, FileKind, Filesystem};
use thiserror::Error;

use support::Image;

#[derive(Debug, Error)]
enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Filesystem(#[from] helios_btrfs::Error),
    #[error("unsupported GRUB test invocation: {0:?}")]
    Arguments(Vec<String>),
    #[error("reader and Linux disagree at byte {0}")]
    Contents(u64),
    #[error("invalid UTF-8 from the upstream test image")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("invalid timestamp in the upstream test image")]
    Timestamp,
}

fn image_path(path: &str) -> Result<&str, Error> {
    path.strip_prefix("(loop0)")
        .ok_or_else(|| Error::Arguments(vec![path.to_owned()]))
}

async fn run(args: &[String]) -> Result<(), Error> {
    let [count, one, image, command, rest @ ..] = args else {
        return Err(Error::Arguments(args.to_vec()));
    };
    if count != "-c" || one != "1" {
        return Err(Error::Arguments(args.to_vec()));
    }
    let fs = Filesystem::mount(Image::open(image)?).await?;
    let mut output = io::stdout().lock();
    match (command.as_str(), rest) {
        ("cmp", [path, reference]) => {
            let inode = fs.resolve(image_path(path)?.as_bytes()).await?;
            let mut reference = File::open(reference)?;
            if inode.metadata().size != reference.metadata()?.len() {
                return Err(Error::Contents(0));
            }
            // Cross both the format's 4 KiB sectors and 128 KiB compressed extents.
            let mut actual = vec![0; 128 * 1024 + 17];
            let mut expected = vec![0; actual.len()];
            let mut offset = 0;
            while offset < inode.metadata().size {
                let count = fs.read(&inode, offset, &mut actual).await?;
                if count == 0 {
                    return Err(Error::Contents(offset));
                }
                reference.read_exact(&mut expected[..count])?;
                if actual[..count] != expected[..count] {
                    return Err(Error::Contents(offset));
                }
                offset += count as u64;
            }
        }
        ("ls", [separator, flags, paths @ ..])
            if separator == "--" && (flags == "-l" || flags == "-la") && paths.len() <= 1 =>
        {
            if paths.is_empty() || paths[0] == "(loop0)" {
                let sb = fs.superblock();
                let label = String::from_utf8(sb.label().to_vec())?;
                let uuid = sb.fsid();
                write!(
                    output,
                    "(loop0): Filesystem type btrfs - Label `{label}', UUID "
                )?;
                for (index, byte) in uuid.into_iter().enumerate() {
                    if [4, 6, 8, 10].contains(&index) {
                        write!(output, "-")?;
                    }
                    write!(output, "{byte:02x}")?;
                }
                writeln!(output, " - Sector size {}", sb.sectorsize())?;
            } else {
                let inode = fs.resolve(image_path(&paths[0])?.as_bytes()).await?;
                let mut entries = Vec::new();
                fs.read_dir(&inode, DirPosition::START, DirBound::UNBOUNDED, |entry| {
                    entries.push((entry.name.to_vec(), entry.target));
                    ControlFlow::Continue(())
                })
                .await?;
                for (name, _) in entries {
                    let child = fs
                        .lookup(&inode, &name)
                        .await?
                        .expect("listed inode exists");
                    let metadata = child.metadata();
                    let time = DateTime::from_timestamp(
                        metadata.mtime.seconds,
                        metadata.mtime.nanoseconds,
                    )
                    .ok_or(Error::Timestamp)?;
                    let suffix = if metadata.kind == FileKind::Directory {
                        "/"
                    } else {
                        ""
                    };
                    writeln!(
                        output,
                        "{:>12} {} {}{suffix}",
                        metadata.size,
                        time.format("%Y%m%d%H%M%S"),
                        String::from_utf8(name)?
                    )?;
                }
            }
        }
        _ => return Err(Error::Arguments(args.to_vec())),
    }
    Ok(())
}

fn main() -> Result<(), Error> {
    block_on(run(&env::args().skip(1).collect::<Vec<_>>()))
}
