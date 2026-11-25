//! `helios image` subcommands (`build` and `codegen`), delegating to `helios-cli`.

use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Args as ClapArgs, Subcommand};
use thiserror::Error;

/// Why a `helios image` command failed.
#[derive(Debug, Error)]
pub(crate) enum ImageError {
    #[error("HELIOS_CLI_BIN does not point to a file: {path}")]
    InvalidCliEnv { path: String },
    #[error("failed to invoke `helios-cli`: {source}")]
    SpawnCli {
        #[source]
        source: std::io::Error,
    },
    #[error("`helios-cli {subcommand}` failed with exit status {status}")]
    CliFailed {
        subcommand: &'static str,
        status: std::process::ExitStatus,
    },
}

/// Top-level `helios image` subcommands.
#[derive(Debug, Clone, Subcommand)]
pub(crate) enum ImageCommand {
    /// Validate a `component.toml` directory tree, compile static Rust routing tables into
    /// `component-manager`, and package the three-part system image (`helios-kernel`,
    /// signed `component-manager.cwasm`, and signed `userspace-components.bootfs`).
    Build(ImageBuildArgs),
    /// Parse and validate a `component.toml` directory tree and emit static native Rust code.
    Codegen(ImageCodegenArgs),
}

#[derive(Debug, Clone, ClapArgs)]
pub(crate) struct ImageBuildArgs {
    /// Root directory of the `component.toml` component tree.
    #[arg(long, default_value = "components")]
    pub components: PathBuf,

    /// Output directory for the three-part image artifacts and `image-manifest.json`.
    #[arg(long)]
    pub out_dir: PathBuf,

    /// Target triple for precompiled `cwasm` artifacts (defaults to the host triple).
    #[arg(long)]
    pub target: Option<String>,

    /// Build profile (`debug` or `release`).
    #[arg(long, default_value = "debug", value_parser = ["debug", "release"])]
    pub profile: String,

    /// Enable runtime TOML parsing and bounded dynamic component subtree mounting
    /// (`--features dynamic-components`). Off by default for zero runtime TOML parser overhead.
    #[arg(long, default_value_t = false)]
    pub dynamic_components: bool,

    /// Optional built `helios-kernel` ELF image to package as Part 1 of the bundle.
    #[arg(long)]
    pub kernel: Option<PathBuf>,

    /// Root bootfs template directory overlaid into the signed payload.
    #[arg(long)]
    pub bootfs_root: Option<PathBuf>,

    /// Restrict packaged user-space programs to the named entries (repeatable).
    #[arg(long = "boot-program")]
    pub boot_programs: Vec<String>,

    /// Skip building the in-kernel compiler plugin.
    #[arg(long, default_value_t = false)]
    pub no_compiler_plugin: bool,

    /// Prebuilt userspace wasm directory.
    #[arg(long, value_name = "DIR", env = "HELIOS_PREBUILT_WASM")]
    pub prebuilt_wasm: Option<PathBuf>,

    /// Root Ed25519 secret key used to sign `component-manager.cwasm` and the user-space payload.
    #[arg(long, value_name = "PATH", env = "HELIOS_ROOT_SECRET_KEY")]
    pub root_secret_key: Option<PathBuf>,

    /// Optional artifact cache directory.
    #[arg(long, value_name = "DIR", env = "HELIOS_ARTIFACT_CACHE")]
    pub cache_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, ClapArgs)]
pub(crate) struct ImageCodegenArgs {
    /// Root directory of the `component.toml` component tree.
    #[arg(long, default_value = "components")]
    pub components: PathBuf,

    /// Output `.rs` file path.
    #[arg(long)]
    pub out: PathBuf,

    /// Verify exact parity against an existing generated `.rs` file.
    #[arg(long)]
    pub verify_matches: Option<PathBuf>,
}

pub(crate) fn run(command: &ImageCommand) -> Result<(), ImageError> {
    match command {
        ImageCommand::Build(args) => {
            let cli_args = build_cli_args(args);
            run_helios_cli("image-build", &cli_args)
        }
        ImageCommand::Codegen(args) => {
            let cli_args = codegen_cli_args(args);
            run_helios_cli("component-codegen", &cli_args)
        }
    }
}

pub(crate) fn build_cli_args(args: &ImageBuildArgs) -> Vec<String> {
    let mut out = vec![
        "image-build".to_owned(),
        "--components".to_owned(),
        args.components.display().to_string(),
        "--out-dir".to_owned(),
        args.out_dir.display().to_string(),
        "--profile".to_owned(),
        args.profile.clone(),
    ];
    if let Some(target) = &args.target {
        out.push("--target".to_owned());
        out.push(target.clone());
    }
    if args.dynamic_components {
        out.push("--dynamic-components".to_owned());
    }
    if let Some(kernel) = &args.kernel {
        out.push("--kernel".to_owned());
        out.push(kernel.display().to_string());
    }
    if let Some(bootfs_root) = &args.bootfs_root {
        out.push("--bootfs-root".to_owned());
        out.push(bootfs_root.display().to_string());
    }
    for prog in &args.boot_programs {
        out.push("--boot-program".to_owned());
        out.push(prog.clone());
    }
    if args.no_compiler_plugin {
        out.push("--no-compiler-plugin".to_owned());
    }
    if let Some(prebuilt) = &args.prebuilt_wasm {
        out.push("--prebuilt-wasm".to_owned());
        out.push(prebuilt.display().to_string());
    }
    if let Some(key) = &args.root_secret_key {
        out.push("--root-secret-key".to_owned());
        out.push(key.display().to_string());
    }
    if let Some(cache_dir) = &args.cache_dir {
        out.push("--cache-dir".to_owned());
        out.push(cache_dir.display().to_string());
    }
    out
}

pub(crate) fn codegen_cli_args(args: &ImageCodegenArgs) -> Vec<String> {
    let mut out = vec![
        "component-codegen".to_owned(),
        "--components".to_owned(),
        args.components.display().to_string(),
        "--out".to_owned(),
        args.out.display().to_string(),
    ];
    if let Some(expected) = &args.verify_matches {
        out.push("--verify-matches".to_owned());
        out.push(expected.display().to_string());
    }
    out
}

fn run_helios_cli(subcommand: &'static str, args: &[String]) -> Result<(), ImageError> {
    let mut cmd = resolve_cli_command()?;
    cmd.args(args);
    let status = cmd
        .status()
        .map_err(|source| ImageError::SpawnCli { source })?;
    if !status.success() {
        return Err(ImageError::CliFailed { subcommand, status });
    }
    Ok(())
}

fn resolve_cli_command() -> Result<Command, ImageError> {
    if let Some(path) = std::env::var_os("HELIOS_CLI_BIN").map(PathBuf::from) {
        if !path.is_file() {
            return Err(ImageError::InvalidCliEnv {
                path: path.display().to_string(),
            });
        }
        return Ok(Command::new(path));
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(sibling) = exe.parent().map(|dir| dir.join("helios-cli"))
        && sibling.is_file()
    {
        return Ok(Command::new(sibling));
    }
    if let Some(in_path) = find_in_path("helios-cli") {
        return Ok(Command::new(in_path));
    }
    let mut cargo = Command::new("cargo");
    cargo.args(["run", "-p", "helios-cli", "--quiet", "--"]);
    Ok(cargo)
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file() && Path::new(candidate).exists())
}
