//! Human-friendly terminal diagnostics, deduplicated causal chains,
//! remediation hints, and TTY-aware status formatting for `helios-cli`.

use std::error::Error as StdError;
use std::fmt::Write as _;
use std::path::Path;

use console::Style;

use crate::artifact_cache::CacheStats;
use crate::components::ComponentBuildError;
use crate::prebuilt_artifact::{ArtifactFetchError, ArtifactStageError};
use crate::wasi_sdk::WasiSdkError;
use crate::{
    BootProgramError, BootfsError, CliError, LimineError, PrebuildError, ProfileFetchError,
    WasmBuildError, WasmProgramsError,
};

/// Returns `true` when stderr is a terminal that accepts ANSI color escapes
/// and `NO_COLOR` is unset.
pub(crate) fn stderr_colors_enabled() -> bool {
    console::colors_enabled_stderr() && std::env::var_os("NO_COLOR").is_none()
}

/// Returns `true` when stdout is a terminal that accepts ANSI color escapes
/// and `NO_COLOR` is unset.
pub(crate) fn stdout_colors_enabled() -> bool {
    console::colors_enabled() && std::env::var_os("NO_COLOR").is_none()
}

/// Formats `error` as a diagnostic with a styled `error:` prefix, a
/// deduplicated `caused by:` chain, and an optional remediation `hint:`.
///
/// Styling is controlled explicitly via `colors` rather than probing the TTY,
/// keeping the formatter pure and deterministically testable.
pub(crate) fn format_cli_error(error: &CliError, colors: bool) -> String {
    format_error_with_hint(error, hint_for_error(error).as_deref(), colors)
}

/// Formats any `std::error::Error` chain with optional `hint` text.
fn format_error_with_hint<E: StdError>(error: &E, hint: Option<&str>, colors: bool) -> String {
    let dim = Style::new().dim().force_styling(colors);
    let error_label = Style::new().red().bold().force_styling(colors);
    let bold = Style::new().bold().force_styling(colors);
    let cyan_bold = Style::new().cyan().bold().force_styling(colors);

    let headline = error.to_string();
    let mut out = format!(
        "{}{}{} {}",
        dim.apply_to("helios-cli: "),
        error_label.apply_to("error"),
        bold.apply_to(":"),
        headline
    );

    let mut last_rendered = headline;
    let mut current = error.source();
    while let Some(cause) = current {
        let message = cause.to_string();
        if !message.is_empty() && !is_already_inlined(&last_rendered, &message) {
            let _ = write!(out, "\n  {} {}", dim.apply_to("caused by:"), message);
            last_rendered = message;
        }
        current = cause.source();
    }

    if let Some(hint) = hint {
        let _ = write!(
            out,
            "\n  {}{} {}",
            cyan_bold.apply_to("hint"),
            bold.apply_to(":"),
            hint
        );
    }

    out
}

/// Returns `true` when `inner` is already present verbatim inside `outer`
/// (e.g. `#[error("{0}")]` or `#[error("...: {source}")]`).
fn is_already_inlined(outer: &str, inner: &str) -> bool {
    outer == inner || outer.ends_with(&format!(": {inner}")) || outer.contains(inner)
}

/// Returns a contextual remediation hint for common operator/developer errors.
pub(crate) fn hint_for_error(error: &CliError) -> Option<String> {
    if let Some(component) = component_build_error(error) {
        match component {
            ComponentBuildError::DriftDetected { expected } => {
                return Some(format!(
                    "run `helios image codegen --out {expected}` (or `helios-cli component-codegen --out {expected}`) to regenerate the static topology"
                ));
            }
            ComponentBuildError::KernelMissing { path } => {
                return Some(format!(
                    "build the kernel ELF at `{path}` first, or omit `--kernel` when packaging userspace artifacts only"
                ));
            }
            _ => {}
        }
    }

    if let Some(wasm) = wasm_build_error(error) {
        match wasm {
            WasmBuildError::PrebuiltMissing { profile, .. } => {
                return Some(format!(
                    "run `helios-cli wasm-build --profile {profile} --out-dir <DIR>` first, or omit `--prebuilt-wasm` to compile from source"
                ));
            }
            WasmBuildError::PrebuiltProfileMismatch { expected, .. } => {
                return Some(format!(
                    "run `helios-cli wasm-build --profile {expected} --out-dir <DIR>` or pass `--profile {expected}` to match the prebuilt directory"
                ));
            }
            WasmBuildError::LlvmArMissing { .. } => {
                return Some(
                    "install the toolchain's LLVM tools with `rustup component add llvm-tools`"
                        .to_owned(),
                );
            }
            WasmBuildError::WasiSdk(WasiSdkError::UnsupportedHost { .. }) => {
                return Some("install `wasi-sdk-34`+ manually and set `WASI_SDK_PATH`".to_owned());
            }
            _ => {}
        }
    }

    if let Some(boot) = boot_program_error(error)
        && matches!(
            boot,
            BootProgramError::EmptyFlagSelection
                | BootProgramError::EmptyEnvSelection
                | BootProgramError::UnknownPrograms { .. }
        )
    {
        return Some("check available guest program directories under `programs/`".to_owned());
    }

    if matches!(
        error,
        CliError::WasmBuild(WasmProgramsError::UnknownPrograms { .. })
    ) {
        return Some("check available guest program directories under `programs/`".to_owned());
    }

    if let Some(limine) = limine_error(error) {
        match limine {
            LimineError::ToolchainMissing => {
                return Some("install `limine` on `PATH` or set `HELIOS_LIMINE_BIN`".to_owned());
            }
            LimineError::ShareDirMissing => {
                return Some(
                    "set `HELIOS_LIMINE_SHARE` to the directory containing Limine's UEFI bootloaders"
                        .to_owned(),
                );
            }
            _ => {}
        }
    }

    if let CliError::ArtifactFetch(fetch) = error {
        match fetch {
            ArtifactFetchError::NotFound { .. } => {
                return Some(
                    "verify `gh auth status` or `GITHUB_TOKEN`, pass `--run <RUN_ID>` / `--ref <REF>`, or use a local `--prebuilt-dir`"
                        .to_owned(),
                );
            }
            ArtifactFetchError::NoCacheDir => {
                return Some(
                    "set `HELIOS_PREBUILT_CACHE_DIR` or pass `--out-dir <DIR>`".to_owned(),
                );
            }
            ArtifactFetchError::ProfileMismatch { expected, .. } => {
                return Some(format!(
                    "pass `--profile {expected}` or fetch an artifact built for `{expected}`"
                ));
            }
            ArtifactFetchError::ArchMismatch {
                expected: Some(expected),
                ..
            } => {
                return Some(format!(
                    "pass `--arch {expected}` or fetch an artifact built for `{expected}`"
                ));
            }
            _ => {}
        }
    }

    if let Some(fetch) = profile_fetch_error(error) {
        return hint_for_profile_fetch(fetch);
    }

    None
}

fn hint_for_profile_fetch(error: &ProfileFetchError) -> Option<String> {
    match error {
        ProfileFetchError::Token { variable } => Some(format!(
            "check `{variable}` for whitespace, quotes, or backslashes, or re-authenticate with `gh auth login`"
        )),
        ProfileFetchError::Curl { .. } | ProfileFetchError::CurlExited { .. } => Some(
            "ensure `curl` is installed and can reach GitHub over HTTPS, or check `gh auth status`"
                .to_owned(),
        ),
        ProfileFetchError::HttpStatus { status, .. } if status == "401" || status == "403" => Some(
            "check `gh auth status` or set `GITHUB_TOKEN` with `actions:read` access".to_owned(),
        ),
        ProfileFetchError::HttpStatus { .. }
        | ProfileFetchError::NotFound { .. }
        | ProfileFetchError::NoRelease { .. }
        | ProfileFetchError::NoCollection { .. }
        | ProfileFetchError::NoRunCollection { .. } => Some(
            "check `gh auth status`, repository name, and workflow run / branch / tag arguments"
                .to_owned(),
        ),
        _ => None,
    }
}

fn component_build_error(error: &CliError) -> Option<&ComponentBuildError> {
    match error {
        CliError::ComponentBuild(err) => Some(err),
        _ => None,
    }
}

fn wasm_build_error(error: &CliError) -> Option<&WasmBuildError> {
    match error {
        CliError::WasmBuild(WasmProgramsError::WasmBuild(err)) => Some(err),
        CliError::KernelPrebuild(prebuild) => prebuild_wasm_build_error(prebuild),
        CliError::ComponentBuild(ComponentBuildError::WasmBuild(err)) => Some(err),
        CliError::ComponentBuild(ComponentBuildError::Prebuild(prebuild)) => {
            prebuild_wasm_build_error(prebuild)
        }
        _ => None,
    }
}

fn prebuild_wasm_build_error(error: &PrebuildError) -> Option<&WasmBuildError> {
    match error {
        PrebuildError::WasmBuild(err) => Some(err),
        PrebuildError::Bootfs(BootfsError::WasmBuild(err)) => Some(err),
        _ => None,
    }
}

fn boot_program_error(error: &CliError) -> Option<&BootProgramError> {
    match error {
        CliError::WasmBuild(WasmProgramsError::BootPrograms(err)) => Some(err),
        CliError::KernelPrebuild(prebuild) => prebuild_boot_program_error(prebuild),
        CliError::ComponentBuild(ComponentBuildError::Prebuild(prebuild)) => {
            prebuild_boot_program_error(prebuild)
        }
        _ => None,
    }
}

fn prebuild_boot_program_error(error: &PrebuildError) -> Option<&BootProgramError> {
    match error {
        PrebuildError::BootPrograms(err) => Some(err),
        PrebuildError::Bootfs(BootfsError::BootPrograms(err)) => Some(err),
        _ => None,
    }
}

fn limine_error(error: &CliError) -> Option<&LimineError> {
    match error {
        CliError::LimineUefiImage(err) => Some(err),
        CliError::ArtifactStage(ArtifactStageError::Limine(err)) => Some(err),
        _ => None,
    }
}

fn profile_fetch_error(error: &CliError) -> Option<&ProfileFetchError> {
    match error {
        CliError::ProfileFetch(err) => Some(err),
        CliError::ArtifactFetch(ArtifactFetchError::Http(err)) => Some(err),
        _ => None,
    }
}

/// Formats `helios-cli: artifact cache: <stats>` for stderr.
pub(crate) fn format_cache_stats(stats: &CacheStats, colors: bool) -> String {
    let dim = Style::new().dim().force_styling(colors);
    let cyan = Style::new().cyan().force_styling(colors);
    format!(
        "{}{} {}",
        dim.apply_to("helios-cli: "),
        cyan.apply_to("artifact cache:"),
        stats
    )
}

/// Formats `helios-cli: artifact cache: pruned <N> entries from <dir>` for stderr.
pub(crate) fn format_cache_pruned(removed: usize, cache_dir: &Path, colors: bool) -> String {
    let dim = Style::new().dim().force_styling(colors);
    let cyan = Style::new().cyan().force_styling(colors);
    let green = Style::new().green().force_styling(colors);
    format!(
        "{}{} {} from {}",
        dim.apply_to("helios-cli: "),
        cyan.apply_to("artifact cache:"),
        green.apply_to(format!("pruned {removed} entries")),
        cache_dir.display()
    )
}

/// Formats the human-readable `artifact-fetch` status line for stdout.
pub(crate) fn format_fetch_status(
    cached: bool,
    artifact_name: &str,
    run_id: u64,
    short_sha: &str,
    dir: &Path,
    colors: bool,
) -> String {
    let state = if cached {
        Style::new()
            .green()
            .force_styling(colors)
            .apply_to("cached")
    } else {
        Style::new()
            .cyan()
            .force_styling(colors)
            .apply_to("fetched")
    };
    let bold = Style::new().bold().force_styling(colors);
    let dim = Style::new().dim().force_styling(colors);
    format!(
        "{} {} (run {}, sha {}) {} {}",
        state,
        bold.apply_to(artifact_name),
        run_id,
        short_sha,
        dim.apply_to("->"),
        dir.display(),
    )
}

/// Formats the `profile-fetch` status line for stdout.
pub(crate) fn format_profile_fetch_status(
    label: &str,
    repository: &str,
    path: &Path,
    colors: bool,
) -> String {
    let green = Style::new().green().force_styling(colors);
    let bold = Style::new().bold().force_styling(colors);
    format!(
        "{} {} {}",
        green.apply_to(label),
        bold.apply_to(repository),
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use std::fmt;
    use std::io;

    use super::*;
    use crate::artifact_cache::CacheError;

    #[derive(Debug)]
    struct SyntheticChainError {
        message: &'static str,
        source: Option<Box<SyntheticChainError>>,
    }

    impl fmt::Display for SyntheticChainError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.message)
        }
    }

    impl StdError for SyntheticChainError {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            self.source
                .as_deref()
                .map(|err| err as &(dyn StdError + 'static))
        }
    }

    #[test]
    fn plain_and_colored_error_rendering() {
        let err = CliError::ComponentBuild(ComponentBuildError::DriftDetected {
            expected: "programs/init/src/default_topology.rs".to_owned(),
        });

        let plain = format_cli_error(&err, false);
        assert!(
            !plain.contains('\x1b'),
            "plain output must not contain ANSI escapes: {plain:?}"
        );
        assert!(plain.starts_with("helios-cli: error: "));
        assert!(plain.contains("programs/init/src/default_topology.rs"));
        assert!(plain.contains(
            "\n  hint: run `helios image codegen --out programs/init/src/default_topology.rs`"
        ));

        let colored = format_cli_error(&err, true);
        assert!(
            colored.contains('\x1b'),
            "colored output must contain ANSI escapes: {colored:?}"
        );
        assert_eq!(console::strip_ansi_codes(&colored), plain);
    }

    #[test]
    fn causal_chain_deduplicates_inlined_sources_and_keeps_distinct_causes() {
        // `CliError::ArtifactCachePrune` (`#[error("{0}")]`) wraps `CacheError::Read`
        // (`#[error("failed to read {path}: {source}")]`) which wraps an `io::Error`.
        // Both inner causes are already present in the headline, so no `caused by:`
        // line should be emitted.
        let io_err = CliError::ArtifactCachePrune(CacheError::Read {
            path: "/tmp/missing.json".to_owned(),
            source: io::Error::new(io::ErrorKind::NotFound, "no such file"),
        });
        let plain_io = format_cli_error(&io_err, false);
        assert_eq!(
            plain_io,
            "helios-cli: error: failed to read /tmp/missing.json: no such file"
        );
        assert!(!plain_io.contains("caused by:"));

        // Multi-level synthetic chain:
        // outer -> middle (inlines inlined_leaf) -> inlined_leaf -> distinct_root
        let synthetic = SyntheticChainError {
            message: "high-level step failed",
            source: Some(Box::new(SyntheticChainError {
                message: "middle layer failed: inlined leaf detail",
                source: Some(Box::new(SyntheticChainError {
                    message: "inlined leaf detail",
                    source: Some(Box::new(SyntheticChainError {
                        message: "distinct root cause",
                        source: None,
                    })),
                })),
            })),
        };
        let rendered = format_error_with_hint(&synthetic, Some("retry later"), false);
        assert_eq!(
            rendered,
            "helios-cli: error: high-level step failed\n  \
             caused by: middle layer failed: inlined leaf detail\n  \
             caused by: distinct root cause\n  \
             hint: retry later"
        );

        let rendered_colored = format_error_with_hint(&synthetic, Some("retry later"), true);
        assert!(rendered_colored.contains('\x1b'));
        assert_eq!(console::strip_ansi_codes(&rendered_colored), rendered);
    }

    #[test]
    fn hint_for_error_covers_actionable_variants() {
        let drift = CliError::ComponentBuild(ComponentBuildError::DriftDetected {
            expected: "out.rs".to_owned(),
        });
        let drift_hint = hint_for_error(&drift).expect("drift hint");
        assert!(drift_hint.contains("helios image codegen --out out.rs"));
        assert!(drift_hint.contains("helios-cli component-codegen --out out.rs"));

        let kernel_missing = CliError::ComponentBuild(ComponentBuildError::KernelMissing {
            path: "target/helios".to_owned(),
        });
        let kernel_hint = hint_for_error(&kernel_missing).expect("kernel missing hint");
        assert!(kernel_hint.contains("target/helios"));
        assert!(kernel_hint.contains("--kernel"));

        let prebuilt_missing_wasm = CliError::WasmBuild(WasmProgramsError::WasmBuild(
            WasmBuildError::PrebuiltMissing {
                path: "/tmp/wasm/release/helios_init.wasm".to_owned(),
                profile: "release".to_owned(),
            },
        ));
        let prebuilt_hint = hint_for_error(&prebuilt_missing_wasm).expect("prebuilt missing hint");
        assert!(prebuilt_hint.contains("helios-cli wasm-build --profile release --out-dir <DIR>"));
        assert!(prebuilt_hint.contains("--prebuilt-wasm"));

        let prebuilt_missing_nested = CliError::ComponentBuild(ComponentBuildError::Prebuild(
            PrebuildError::Bootfs(BootfsError::WasmBuild(WasmBuildError::PrebuiltMissing {
                path: "/tmp/wasm/debug/helios_init.wasm".to_owned(),
                profile: "debug".to_owned(),
            })),
        ));
        assert!(
            hint_for_error(&prebuilt_missing_nested)
                .expect("nested prebuilt missing hint")
                .contains("--profile debug")
        );

        let llvm_ar =
            CliError::KernelPrebuild(PrebuildError::WasmBuild(WasmBuildError::LlvmArMissing {
                path: "/toolchain/bin/llvm-ar".to_owned(),
            }));
        assert!(
            hint_for_error(&llvm_ar)
                .expect("llvm-ar hint")
                .contains("rustup component add llvm-tools")
        );

        for boot_err in [
            CliError::KernelPrebuild(PrebuildError::BootPrograms(
                BootProgramError::EmptyFlagSelection,
            )),
            CliError::KernelPrebuild(PrebuildError::BootPrograms(
                BootProgramError::EmptyEnvSelection,
            )),
            CliError::KernelPrebuild(PrebuildError::BootPrograms(
                BootProgramError::UnknownPrograms {
                    missing: "bogus".to_owned(),
                },
            )),
            CliError::WasmBuild(WasmProgramsError::UnknownPrograms {
                unknown: "bogus".to_owned(),
            }),
        ] {
            assert!(
                hint_for_error(&boot_err)
                    .expect("boot program hint")
                    .contains("programs/")
            );
        }

        let fetch_not_found = CliError::ArtifactFetch(ArtifactFetchError::NotFound {
            repo: "owner/repo".to_owned(),
            candidates: "helios-image-x86-64-release".to_owned(),
            target: "default branch `main`".to_owned(),
        });
        let fetch_hint = hint_for_error(&fetch_not_found).expect("fetch not found hint");
        assert!(fetch_hint.contains("gh auth status"));
        assert!(fetch_hint.contains("--prebuilt-dir"));

        let fetch_http_403 =
            CliError::ArtifactFetch(ArtifactFetchError::Http(ProfileFetchError::HttpStatus {
                url: "https://api.github.com/example".to_owned(),
                status: "403".to_owned(),
                body: "forbidden".to_owned(),
            }));
        assert!(
            hint_for_error(&fetch_http_403)
                .expect("http 403 hint")
                .contains("GITHUB_TOKEN")
        );

        let fetch_curl =
            CliError::ArtifactFetch(ArtifactFetchError::Http(ProfileFetchError::CurlExited {
                url: "https://api.github.com/example".to_owned(),
                status: "exit status 6".to_owned(),
                stderr: "Could not resolve host".to_owned(),
            }));
        assert!(
            hint_for_error(&fetch_curl)
                .expect("curl hint")
                .contains("curl")
        );
    }

    #[test]
    fn status_formatters_strip_to_identical_plain_text() {
        let stats = CacheStats { hits: 3, misses: 1 };
        let plain_stats = format_cache_stats(&stats, false);
        assert_eq!(plain_stats, "helios-cli: artifact cache: 3 hits, 1 misses");
        let colored_stats = format_cache_stats(&stats, true);
        assert!(colored_stats.contains('\x1b'));
        assert_eq!(console::strip_ansi_codes(&colored_stats), plain_stats);

        let dir = Path::new("/tmp/cache");
        let plain_pruned = format_cache_pruned(4, dir, false);
        assert_eq!(
            plain_pruned,
            "helios-cli: artifact cache: pruned 4 entries from /tmp/cache"
        );
        let colored_pruned = format_cache_pruned(4, dir, true);
        assert!(colored_pruned.contains('\x1b'));
        assert_eq!(console::strip_ansi_codes(&colored_pruned), plain_pruned);

        let plain_fetch = format_fetch_status(
            false,
            "helios-image-x86-64-release",
            123,
            "abcdef123456",
            dir,
            false,
        );
        assert_eq!(
            plain_fetch,
            "fetched helios-image-x86-64-release (run 123, sha abcdef123456) -> /tmp/cache"
        );
        let colored_fetch = format_fetch_status(
            false,
            "helios-image-x86-64-release",
            123,
            "abcdef123456",
            dir,
            true,
        );
        assert!(colored_fetch.contains('\x1b'));
        assert_eq!(console::strip_ansi_codes(&colored_fetch), plain_fetch);

        let plain_profile = format_profile_fetch_status("release", "owner/repo", dir, false);
        assert_eq!(plain_profile, "release owner/repo /tmp/cache");
        let colored_profile = format_profile_fetch_status("release", "owner/repo", dir, true);
        assert!(colored_profile.contains('\x1b'));
        assert_eq!(console::strip_ansi_codes(&colored_profile), plain_profile);
    }
}
