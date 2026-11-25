//! Thin CLI frontend over [`helios_vmm::MicroVm`].

use clap::Parser;
use helios_vmm::{ExitReason, MicroVm};
use thiserror::Error;

#[derive(Debug, Error)]
enum CliError {
    #[error(transparent)]
    Vmm(#[from] helios_vmm::Error),
    #[error("invalid --share-dir {spec:?}: expected <tag>:<path>")]
    InvalidShareSpec { spec: String },
}

#[derive(Parser)]
#[command(about = "Boot an ARM64 Linux virtual machine through helios:hv")]
struct Cli {
    /// Path to the ARM64 Linux `Image` file.
    #[arg(long)]
    kernel: String,
    /// Optional path to an initramfs archive.
    #[arg(long)]
    initramfs: Option<String>,
    /// Optional path to a raw disk image attached as `virtio-blk`.
    #[arg(long)]
    disk: Option<String>,
    /// Guest RAM size in MiB.
    #[arg(long, default_value_t = 128)]
    memory_mib: u64,
    /// Number of vCPUs (1..=256).
    #[arg(long, default_value_t = 1)]
    cpus: u32,
    /// Kernel command line override.
    #[arg(long)]
    cmdline: Option<String>,
    /// Share a granted host directory over `virtio-fs` (`<tag>:<path>`, repeatable).
    #[arg(long = "share-dir", value_name = "TAG:PATH")]
    share_dirs: Vec<String>,
    /// Mount a granted host directory tree as `virtio-fs` rootfs (`tag=rootfs`).
    #[arg(long = "rootfs-dir", value_name = "PATH")]
    rootfs_dir: Option<String>,
}

fn parse_share_dir(spec: &str) -> Result<(&str, &str), CliError> {
    let (tag, path) = spec
        .split_once(':')
        .ok_or_else(|| CliError::InvalidShareSpec {
            spec: spec.to_owned(),
        })?;
    if tag.is_empty() || path.is_empty() {
        return Err(CliError::InvalidShareSpec {
            spec: spec.to_owned(),
        });
    }
    Ok((tag, path))
}

fn build_vm(cli: Cli) -> Result<MicroVm, CliError> {
    let mut builder = MicroVm::builder()
        .cpus(cli.cpus)
        .memory_mib(cli.memory_mib)?
        .kernel(cli.kernel);
    if let Some(initramfs) = cli.initramfs {
        builder = builder.initramfs(initramfs);
    }
    if let Some(cmdline) = cli.cmdline {
        builder = builder.cmdline(cmdline);
    }
    if let Some(disk) = cli.disk {
        builder = builder.disk(disk);
    }
    if let Some(rootfs) = cli.rootfs_dir {
        builder = builder.rootfs_dir(rootfs)?;
    }
    for spec in &cli.share_dirs {
        let (tag, path) = parse_share_dir(spec)?;
        builder = builder.share_dir(tag, path)?;
    }
    Ok(builder.build_vm()?)
}

#[helios_api::main]
async fn main() -> Result<(), CliError> {
    let vm = build_vm(Cli::parse())?;
    if vm.run().await? == ExitReason::GuestShutdown {
        println!("vmm: guest requested shutdown");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_share_dir_and_rootfs_flags() {
        let cli = Cli::try_parse_from([
            "vmm",
            "--kernel",
            "/host/Image",
            "--rootfs-dir",
            "/host/root",
            "--share-dir",
            "data:/host/data",
            "--cpus",
            "2",
        ])
        .unwrap();
        let vm = build_vm(cli).unwrap();
        assert_eq!(vm.config().cpus, 2);
        assert_eq!(vm.config().fs_shares.len(), 2);
        assert_eq!(vm.config().fs_shares[0].tag, "rootfs");
        assert_eq!(vm.config().fs_shares[1].tag, "data");
        assert_eq!(vm.config().fs_shares[1].host_path, "/host/data");
        assert!(parse_share_dir("missing-colon").is_err());
        assert!(parse_share_dir(":/path").is_err());
        assert!(parse_share_dir("tag:").is_err());
    }
}
