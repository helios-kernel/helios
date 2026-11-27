//! `stack-test`: exercises guest fiber-stack growth, host calls at deep
//! stack depth, large (> 16 KiB) native stack frames, and stack overflow.
//!
//! Fiber stacks commit ahead of the guest through the runtime's
//! stack-reserve callback rather than through page faults (#535, #538).
//! Each subcommand targets one edge of that path:
//!
//! - `host-call`: recurses megabytes down the fiber stack and invokes host
//!   calls (`Instant::now`, stdout) at full depth.
//! - `large-frame`: recurses with frames carrying > 20 KiB of live locals
//!   across calls (> `CWASM_STACK_LIMIT_LARGE_FRAME`), verifying the
//!   prologue reserve check commits ahead of large frames.
//! - `recurse`: recurses until stack exhaustion, verifying the guest traps
//!   with stack overflow without panicking the kernel.
//! - `large-frame-overflow`: recurses with > 20 KiB frames until exhaustion,
//!   verifying the large-frame prologue check traps cleanly before touching
//!   uncommitted pages or the guard.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use thiserror::Error;

const HOST_CALL_DEPTH: u32 = 32_768;
const LARGE_FRAME_DEPTH: u32 = 64;

#[derive(Debug, Error)]
enum StackTestError {
    #[error("usage: stack-test <host-call|large-frame|recurse|large-frame-overflow>")]
    Usage,
    #[error(
        "unknown mode `{0}` (expected host-call, large-frame, recurse, or large-frame-overflow)"
    )]
    UnknownMode(String),
    #[error("unbounded recursion returned {0} instead of trapping with stack overflow")]
    OverflowDidNotTrap(u64),
}

/// Runs the host calls at the bottom of `recurse_and_host_call` in its own
/// non-inlined frame so LLVM does not reserve a linear-memory shadow-stack
/// frame for `Instant` / `println!` in every recursive call above it.
#[inline(never)]
fn host_call_leaf() -> u64 {
    let now = Instant::now();
    println!("stack-test:host-call:ok");
    now.elapsed().as_nanos() as u64
}

#[inline(never)]
fn large_frame_leaf() -> u64 {
    Instant::now().elapsed().as_nanos() as u64
}

#[inline(never)]
fn opaque(salt: &AtomicU64, value: u64) -> u64 {
    salt.load(Ordering::Relaxed) ^ value
}

#[inline(never)]
fn recurse_and_host_call(depth: u32, seed: u64, salt: &AtomicU64) -> u64 {
    let a = opaque(salt, seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let b = opaque(salt, a ^ 0x517c_c1b7_2722_0a95);
    let c = opaque(salt, b.wrapping_add(u64::from(depth)));
    let d = opaque(salt, c.rotate_left(13));
    if depth == 0 {
        return host_call_leaf() ^ a ^ b ^ c ^ d;
    }
    opaque(salt, recurse_and_host_call(depth - 1, a ^ b, salt)).wrapping_add(c ^ d)
}

#[inline(never)]
fn recurse_to_overflow(remaining: u64, seed: u64, salt: &AtomicU64) -> u64 {
    let a = opaque(salt, seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let b = opaque(salt, a ^ 0x517c_c1b7_2722_0a95);
    let c = opaque(salt, b.wrapping_add(remaining));
    let d = opaque(salt, c.rotate_left(13));
    if remaining == 0 {
        return a ^ b ^ c ^ d;
    }
    opaque(salt, recurse_to_overflow(remaining - 1, a ^ b, salt)).wrapping_add(c ^ d)
}

macro_rules! mix_into {
    ($r:ident, $($v:ident),+ $(,)?) => {
        $(
            $r = $r.rotate_left(5).wrapping_add($v) ^ $v;
        )+
    };
}

macro_rules! with_64_live_u64s {
    ($salt:expr, $seed:expr, $base:expr, $body:expr) => {{
        let salt: &AtomicU64 = $salt;
        let s: u64 = $seed;
        let b: u64 = $base;
        let v00 = opaque(salt, s.wrapping_add(b));
        let v01 = opaque(salt, s.wrapping_add(b + 1));
        let v02 = opaque(salt, s.wrapping_add(b + 2));
        let v03 = opaque(salt, s.wrapping_add(b + 3));
        let v04 = opaque(salt, s.wrapping_add(b + 4));
        let v05 = opaque(salt, s.wrapping_add(b + 5));
        let v06 = opaque(salt, s.wrapping_add(b + 6));
        let v07 = opaque(salt, s.wrapping_add(b + 7));
        let v08 = opaque(salt, s.wrapping_add(b + 8));
        let v09 = opaque(salt, s.wrapping_add(b + 9));
        let v10 = opaque(salt, s.wrapping_add(b + 10));
        let v11 = opaque(salt, s.wrapping_add(b + 11));
        let v12 = opaque(salt, s.wrapping_add(b + 12));
        let v13 = opaque(salt, s.wrapping_add(b + 13));
        let v14 = opaque(salt, s.wrapping_add(b + 14));
        let v15 = opaque(salt, s.wrapping_add(b + 15));
        let v16 = opaque(salt, s.wrapping_add(b + 16));
        let v17 = opaque(salt, s.wrapping_add(b + 17));
        let v18 = opaque(salt, s.wrapping_add(b + 18));
        let v19 = opaque(salt, s.wrapping_add(b + 19));
        let v20 = opaque(salt, s.wrapping_add(b + 20));
        let v21 = opaque(salt, s.wrapping_add(b + 21));
        let v22 = opaque(salt, s.wrapping_add(b + 22));
        let v23 = opaque(salt, s.wrapping_add(b + 23));
        let v24 = opaque(salt, s.wrapping_add(b + 24));
        let v25 = opaque(salt, s.wrapping_add(b + 25));
        let v26 = opaque(salt, s.wrapping_add(b + 26));
        let v27 = opaque(salt, s.wrapping_add(b + 27));
        let v28 = opaque(salt, s.wrapping_add(b + 28));
        let v29 = opaque(salt, s.wrapping_add(b + 29));
        let v30 = opaque(salt, s.wrapping_add(b + 30));
        let v31 = opaque(salt, s.wrapping_add(b + 31));
        let v32 = opaque(salt, s.wrapping_add(b + 32));
        let v33 = opaque(salt, s.wrapping_add(b + 33));
        let v34 = opaque(salt, s.wrapping_add(b + 34));
        let v35 = opaque(salt, s.wrapping_add(b + 35));
        let v36 = opaque(salt, s.wrapping_add(b + 36));
        let v37 = opaque(salt, s.wrapping_add(b + 37));
        let v38 = opaque(salt, s.wrapping_add(b + 38));
        let v39 = opaque(salt, s.wrapping_add(b + 39));
        let v40 = opaque(salt, s.wrapping_add(b + 40));
        let v41 = opaque(salt, s.wrapping_add(b + 41));
        let v42 = opaque(salt, s.wrapping_add(b + 42));
        let v43 = opaque(salt, s.wrapping_add(b + 43));
        let v44 = opaque(salt, s.wrapping_add(b + 44));
        let v45 = opaque(salt, s.wrapping_add(b + 45));
        let v46 = opaque(salt, s.wrapping_add(b + 46));
        let v47 = opaque(salt, s.wrapping_add(b + 47));
        let v48 = opaque(salt, s.wrapping_add(b + 48));
        let v49 = opaque(salt, s.wrapping_add(b + 49));
        let v50 = opaque(salt, s.wrapping_add(b + 50));
        let v51 = opaque(salt, s.wrapping_add(b + 51));
        let v52 = opaque(salt, s.wrapping_add(b + 52));
        let v53 = opaque(salt, s.wrapping_add(b + 53));
        let v54 = opaque(salt, s.wrapping_add(b + 54));
        let v55 = opaque(salt, s.wrapping_add(b + 55));
        let v56 = opaque(salt, s.wrapping_add(b + 56));
        let v57 = opaque(salt, s.wrapping_add(b + 57));
        let v58 = opaque(salt, s.wrapping_add(b + 58));
        let v59 = opaque(salt, s.wrapping_add(b + 59));
        let v60 = opaque(salt, s.wrapping_add(b + 60));
        let v61 = opaque(salt, s.wrapping_add(b + 61));
        let v62 = opaque(salt, s.wrapping_add(b + 62));
        let v63 = opaque(salt, s.wrapping_add(b + 63));
        let mut r: u64 = $body;
        mix_into!(
            r, v00, v01, v02, v03, v04, v05, v06, v07, v08, v09, v10, v11, v12, v13, v14, v15, v16,
            v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33,
            v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50,
            v51, v52, v53, v54, v55, v56, v57, v58, v59, v60, v61, v62, v63,
        );
        r
    }};
}

macro_rules! with_320_live_u64s {
    ($salt:expr, $seed:expr, $base:expr, $body:expr) => {
        with_64_live_u64s!(
            $salt,
            $seed,
            $base,
            with_64_live_u64s!(
                $salt,
                $seed,
                $base + 64,
                with_64_live_u64s!(
                    $salt,
                    $seed,
                    $base + 128,
                    with_64_live_u64s!(
                        $salt,
                        $seed,
                        $base + 192,
                        with_64_live_u64s!($salt, $seed, $base + 256, $body)
                    )
                )
            )
        )
    };
}

/// Keeps 2,560 `u64` wasm locals live across the recursive call (~20 KiB of
/// native spill slots, exceeding `CWASM_STACK_LIMIT_LARGE_FRAME` = 16 KiB)
/// without spilling onto the wasm linear-memory shadow stack.
#[inline(never)]
fn recurse_large_frame(remaining: u32, seed: u64, salt: &AtomicU64) -> u64 {
    with_320_live_u64s!(
        salt,
        seed,
        0,
        with_320_live_u64s!(
            salt,
            seed,
            320,
            with_320_live_u64s!(
                salt,
                seed,
                640,
                with_320_live_u64s!(
                    salt,
                    seed,
                    960,
                    with_320_live_u64s!(
                        salt,
                        seed,
                        1280,
                        with_320_live_u64s!(
                            salt,
                            seed,
                            1600,
                            with_320_live_u64s!(
                                salt,
                                seed,
                                1920,
                                with_320_live_u64s!(
                                    salt,
                                    seed,
                                    2240,
                                    if remaining == 0 {
                                        large_frame_leaf()
                                    } else {
                                        recurse_large_frame(
                                            remaining - 1,
                                            seed.wrapping_add(1),
                                            salt,
                                        )
                                    }
                                )
                            )
                        )
                    )
                )
            )
        )
    )
}

#[helios_api::main]
async fn main() -> Result<(), StackTestError> {
    let mut args = std::env::args().skip(1);
    let Some(mode) = args.next() else {
        return Err(StackTestError::Usage);
    };
    if args.next().is_some() {
        return Err(StackTestError::Usage);
    }

    let salt = AtomicU64::new(0x9e37_79b9_7f4a_7c15);
    match mode.as_str() {
        "host-call" => {
            salt.store(
                recurse_and_host_call(HOST_CALL_DEPTH, 1, &salt),
                Ordering::Relaxed,
            );
            Ok(())
        }
        "large-frame" => {
            salt.store(
                recurse_large_frame(LARGE_FRAME_DEPTH, 1, &salt),
                Ordering::Relaxed,
            );
            println!("stack-test:large-frame:ok");
            Ok(())
        }
        "recurse" => {
            println!("stack-test:recurse:before");
            let value = recurse_to_overflow(u64::MAX, 1, &salt);
            Err(StackTestError::OverflowDidNotTrap(value))
        }
        "large-frame-overflow" => {
            println!("stack-test:large-frame-overflow:before");
            let value = recurse_large_frame(u32::MAX, 1, &salt);
            Err(StackTestError::OverflowDidNotTrap(value))
        }
        other => Err(StackTestError::UnknownMode(other.to_owned())),
    }
}
