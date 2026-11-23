//! Replay upstream malformed images through the same traversal as the fuzzer.
mod support;
use futures_lite::future::block_on;
use std::{
    env,
    io::{self, Write},
};

fn main() -> io::Result<()> {
    let path = env::args_os().nth(1).expect("usage: btrfs-corpus IMAGE");
    let result = block_on(helios_btrfs::testing::walk(support::Image::open(path)?));
    // The upstream corpus exercises fsck invariants too. A reader may accept
    // an image whose defect lives in an unused tree. Both acceptance and typed
    // rejection are recorded; panics or sanitizer failures must fail the job.
    writeln!(io::stdout().lock(), "{result:?}")
}
