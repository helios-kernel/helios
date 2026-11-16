//! Mounts a btrfs block device through FUSE with Helios's writer, so Linux's
//! own filesystem tests can run against it. Invoked the way `mount(8)` runs a
//! `mount.fuse.helios-btrfs` helper: `fuse-btrfs <block-device> <mountpoint>
//! [-o option[,option...]]`. It serves in the foreground until unmounted.

#[cfg(target_os = "linux")]
mod daemon;

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    // fuser reports through the `log` crate; route it to `tracing`.
    tracing_log::LogTracer::init().expect("no other logger is installed");
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .init();
    match daemon::run(std::env::args_os().skip(1)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "fuse-btrfs failed");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    panic!("fuse-btrfs mounts through Linux FUSE; this host has none");
}
