//! The writable-mount compression policy: Linux's `compress=<algorithm>[:<level>]`
//! mount option (`btrfs_parse_compress` in `fs/btrfs/super.c`, with the level
//! rules of `btrfs_compress_str2level` and `btrfs_compress_set_level` in
//! `fs/btrfs/compression.c`), and the encoder it selects for one writer.

use thiserror::Error;

use alloc::boxed::Box;

use super::write::{EncodeError, Lzo, Zlib, Zstd};
use crate::Compression;

/// The levels an algorithm accepts, from its `struct btrfs_compress_levels`.
struct Levels {
    min: i32,
    max: i32,
    default: i32,
}

/// `btrfs_zlib_compress` in `zlib.c`, with `BTRFS_ZLIB_DEFAULT_LEVEL` from
/// `compression.h`.
const ZLIB: Levels = Levels {
    min: 1,
    max: 9,
    default: 3,
};

/// `btrfs_lzo_compress` in `lzo.c` sets only the maximum and default levels;
/// the minimum is the zero of a static initializer. LZO ignores its level.
const LZO: Levels = Levels {
    min: 0,
    max: 1,
    default: 1,
};

/// `btrfs_zstd_compress` in `zstd.c`: `ZSTD_BTRFS_MIN_LEVEL`,
/// `ZSTD_BTRFS_MAX_LEVEL` and `ZSTD_BTRFS_DEFAULT_LEVEL`.
const ZSTD: Levels = Levels {
    min: -15,
    max: 15,
    default: 3,
};

impl Levels {
    /// `btrfs_compress_set_level`: zero selects the default, anything else is
    /// clamped to the range.
    fn resolve(&self, requested: i32) -> i32 {
        if requested == 0 {
            self.default
        } else {
            requested.clamp(self.min, self.max)
        }
    }
}

fn levels(algorithm: Compression) -> &'static Levels {
    match algorithm {
        Compression::Zlib => &ZLIB,
        Compression::Lzo => &LZO,
        Compression::Zstd => &ZSTD,
    }
}

#[derive(Debug, Error)]
pub enum CompressionOptionError {
    #[error(
        "compression option `{option}` is not no, none, zlib, lzo or zstd with an optional :level"
    )]
    Unrecognized { option: alloc::string::String },
    #[error("compression level `{level}` in option `{option}` is not a decimal integer")]
    Level {
        option: alloc::string::String,
        level: alloc::string::String,
    },
}

/// A compression algorithm and the level a mount asked for, already resolved
/// to Linux's range for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressionPolicy {
    algorithm: Compression,
    level: i32,
}

impl Default for CompressionPolicy {
    /// What the bare `compress` option selects: zlib at its default level.
    fn default() -> Self {
        Self::new(Compression::Zlib, 0)
    }
}

impl CompressionPolicy {
    /// `level` zero selects the algorithm's default; any other level is
    /// clamped to the algorithm's range, as Linux does.
    pub fn new(algorithm: Compression, level: i32) -> Self {
        Self {
            algorithm,
            level: levels(algorithm).resolve(level),
        }
    }

    /// Parses the value of `compress=`. `no` and `none` select no
    /// compression. A level after `:` follows `kstrtoint`: an optional sign,
    /// decimal digits and an optional trailing newline.
    pub fn parse(option: &str) -> Result<Option<Self>, CompressionOptionError> {
        if option == "no" || option == "none" {
            return Ok(None);
        }
        for (name, algorithm) in [
            ("zlib", Compression::Zlib),
            ("lzo", Compression::Lzo),
            ("zstd", Compression::Zstd),
        ] {
            let Some(rest) = option.strip_prefix(name) else {
                continue;
            };
            let level = match rest.strip_prefix(':') {
                None if rest.is_empty() => 0,
                None => continue,
                Some(level) => level
                    .strip_suffix('\n')
                    .unwrap_or(level)
                    .parse()
                    .map_err(|_| CompressionOptionError::Level {
                        option: option.into(),
                        level: level.into(),
                    })?,
            };
            return Ok(Some(Self::new(algorithm, level)));
        }
        Err(CompressionOptionError::Unrecognized {
            option: option.into(),
        })
    }

    pub fn algorithm(&self) -> Compression {
        self.algorithm
    }

    /// The resolved level; meaningless for LZO, which ignores it.
    pub fn level(&self) -> i32 {
        self.level
    }
}

/// The encoder one writer owns for its mount's policy, with the workspace it
/// reuses across extents.
pub enum Compressor {
    Plain,
    Zlib(Zlib),
    Lzo(Lzo),
    /// Boxed: its hash tables make it hundreds of times larger than the rest.
    Zstd(Box<Zstd>),
}

impl Compressor {
    /// The encoder for `policy`; `None` writes every extent uncompressed.
    /// Fails when the encoder cannot produce the policy's level.
    pub fn new(policy: Option<CompressionPolicy>) -> Result<Self, EncodeError> {
        Ok(match policy {
            None => Self::Plain,
            Some(CompressionPolicy {
                algorithm: Compression::Zlib,
                level,
            }) => Self::Zlib(Zlib::at_level(level as u8)),
            Some(CompressionPolicy {
                algorithm: Compression::Lzo,
                ..
            }) => Self::Lzo(Lzo::new()),
            Some(CompressionPolicy {
                algorithm: Compression::Zstd,
                level,
            }) => Self::Zstd(Box::new(Zstd::new(level)?)),
        })
    }
}

/// Whether Linux compresses data of an inode with these `BTRFS_INODE_*`
/// flags: `btrfs_inode_can_compress` refuses NODATACOW and NODATASUM, and
/// `inode_need_compress` honors NOCOMPRESS unless compression is forced.
pub(crate) fn inode_compresses(flags: u64) -> bool {
    use crate::items::{INODE_NOCOMPRESS, INODE_NODATACOW, INODE_NODATASUM};
    flags & (INODE_NODATASUM | INODE_NODATACOW | INODE_NOCOMPRESS) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(option: &str) -> (Compression, i32) {
        let policy = CompressionPolicy::parse(option).unwrap().unwrap();
        (policy.algorithm(), policy.level())
    }

    #[test]
    fn defaults_and_clamping_follow_linux() {
        assert_eq!(parsed("zlib"), (Compression::Zlib, 3));
        assert_eq!(parsed("zlib:0"), (Compression::Zlib, 3));
        assert_eq!(parsed("zlib:1"), (Compression::Zlib, 1));
        assert_eq!(parsed("zlib:9"), (Compression::Zlib, 9));
        assert_eq!(parsed("zlib:12"), (Compression::Zlib, 9));
        assert_eq!(parsed("zlib:-4"), (Compression::Zlib, 1));
        assert_eq!(parsed("zstd"), (Compression::Zstd, 3));
        assert_eq!(parsed("zstd:15"), (Compression::Zstd, 15));
        assert_eq!(parsed("zstd:99"), (Compression::Zstd, 15));
        assert_eq!(parsed("zstd:-15"), (Compression::Zstd, -15));
        assert_eq!(parsed("zstd:-99"), (Compression::Zstd, -15));
        assert_eq!(parsed("zstd:+7"), (Compression::Zstd, 7));
        assert_eq!(parsed("zstd:5\n"), (Compression::Zstd, 5));
        assert_eq!(parsed("lzo"), (Compression::Lzo, 1));
        assert_eq!(parsed("lzo:9"), (Compression::Lzo, 1));
        assert_eq!(parsed("lzo:-3"), (Compression::Lzo, 0));
        assert_eq!(
            CompressionPolicy::default(),
            CompressionPolicy::new(Compression::Zlib, 3)
        );
    }

    #[test]
    fn no_and_none_select_nothing_and_malformed_options_fail() {
        assert_eq!(CompressionPolicy::parse("no").unwrap(), None);
        assert_eq!(CompressionPolicy::parse("none").unwrap(), None);
        for option in ["", "zst", "zstdx", "none:1", "no:3", "ZLIB", "zlib "] {
            assert!(
                matches!(
                    CompressionPolicy::parse(option),
                    Err(CompressionOptionError::Unrecognized { .. })
                ),
                "{option:?}"
            );
        }
        for option in ["zlib:", "zlib:x", "zstd:3.5", "lzo:--1", "zstd:99999999999"] {
            assert!(
                matches!(
                    CompressionPolicy::parse(option),
                    Err(CompressionOptionError::Level { .. })
                ),
                "{option:?}"
            );
        }
    }

    #[test]
    fn inode_flags_that_forbid_compression() {
        use crate::items::{INODE_NOCOMPRESS, INODE_NODATACOW, INODE_NODATASUM};
        assert!(inode_compresses(0));
        assert!(inode_compresses(1 << 11));
        for flag in [INODE_NODATASUM, INODE_NODATACOW, INODE_NOCOMPRESS] {
            assert!(!inode_compresses(flag));
        }
    }

    #[test]
    fn every_linux_zlib_level_and_the_zstd_levels_the_encoder_supports_build() {
        for level in 1..=9 {
            Compressor::new(Some(CompressionPolicy::new(Compression::Zlib, level))).unwrap();
        }
        for level in -7..=4 {
            Compressor::new(Some(CompressionPolicy::new(Compression::Zstd, level))).unwrap();
        }
        Compressor::new(Some(CompressionPolicy::new(Compression::Lzo, 0))).unwrap();
        Compressor::new(None).unwrap();
    }

    #[test]
    fn zstd_levels_beyond_the_encoder_are_refused_not_clamped() {
        for level in [5, 15, -15] {
            assert!(matches!(
                Compressor::new(Some(CompressionPolicy::new(Compression::Zstd, level))),
                Err(EncodeError::Zstd(_))
            ));
        }
    }
}
