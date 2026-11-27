//! Colored CLI diagnostics, exit-code mapping, and human-friendly formatting
//! helpers shared across `helios` subcommands.

use std::error::Error;
use std::fmt::{Display, Write as _};
use std::process::ExitCode;

use console::Style;
use helios_ops::{AccountError, OpsError, TargetError, TransportError};
use helios_wit_rpc::RpcError;
use helios_wit_rpc::inspector_fs::FsRpcError;
use time::OffsetDateTime;

use crate::ops_cli::OpsCliError;
use crate::programs::ProgramError;
use crate::remote::RemoteError;
use crate::system::SystemError;
use crate::vm::{BuildStepError, VmConfigError};
use crate::workload_bench::WorkloadBenchError;
use crate::{InspectorError, SessionError};

/// Returns whether ANSI colors should be emitted on stdout.
#[must_use]
pub(crate) fn stdout_colors_enabled() -> bool {
    console::colors_enabled() && std::env::var_os("NO_COLOR").is_none()
}

/// Returns whether ANSI colors should be emitted on stderr.
#[must_use]
pub(crate) fn stderr_colors_enabled() -> bool {
    console::colors_enabled_stderr() && std::env::var_os("NO_COLOR").is_none()
}

/// Lightweight TTY-aware ANSI styling helper for `helios` CLI output.
///
/// Every method honors `colors` explicitly via `Style::force_styling`, guaranteeing
/// zero ANSI escape sequences when piped or when `NO_COLOR` is set, and deterministic
/// output in unit tests.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CliTheme {
    colors: bool,
}

impl CliTheme {
    #[must_use]
    pub(crate) fn stdout() -> Self {
        Self {
            colors: stdout_colors_enabled(),
        }
    }

    #[must_use]
    pub(crate) fn stderr() -> Self {
        Self {
            colors: stderr_colors_enabled(),
        }
    }

    #[must_use]
    pub(crate) const fn with_colors(colors: bool) -> Self {
        Self { colors }
    }

    fn style(&self) -> Style {
        Style::new().force_styling(self.colors)
    }

    #[must_use]
    pub(crate) fn bold(&self, text: impl Display) -> String {
        self.style().bold().apply_to(text).to_string()
    }

    #[must_use]
    pub(crate) fn dim(&self, text: impl Display) -> String {
        self.style().dim().apply_to(text).to_string()
    }

    #[must_use]
    pub(crate) fn red(&self, text: impl Display) -> String {
        self.style().red().apply_to(text).to_string()
    }

    #[must_use]
    pub(crate) fn bold_red(&self, text: impl Display) -> String {
        self.style().bold().red().apply_to(text).to_string()
    }

    #[must_use]
    pub(crate) fn green(&self, text: impl Display) -> String {
        self.style().green().apply_to(text).to_string()
    }

    #[must_use]
    pub(crate) fn bold_green(&self, text: impl Display) -> String {
        self.style().bold().green().apply_to(text).to_string()
    }

    #[must_use]
    pub(crate) fn yellow(&self, text: impl Display) -> String {
        self.style().yellow().apply_to(text).to_string()
    }

    #[must_use]
    pub(crate) fn cyan(&self, text: impl Display) -> String {
        self.style().cyan().apply_to(text).to_string()
    }

    #[must_use]
    pub(crate) fn bold_cyan(&self, text: impl Display) -> String {
        self.style().bold().cyan().apply_to(text).to_string()
    }

    #[must_use]
    pub(crate) fn check(&self) -> String {
        self.bold_green("✓")
    }

    /// Styles a pre-padded state column string based on the raw component/instance state.
    #[must_use]
    pub(crate) fn state(&self, raw_state: &str, padded: &str) -> String {
        match raw_state.to_ascii_lowercase().as_str() {
            "running" | "ready" | "online" | "active" => self.green(padded),
            "failed" | "crashed" | "error" | "dead" | "oom" => self.bold_red(padded),
            "starting" | "stopping" | "restarting" | "degraded" => self.yellow(padded),
            "stopped" | "idle" | "exited" | "pending" | "unknown" => self.dim(padded),
            _ => padded.to_owned(),
        }
    }
}

/// Maps a non-zero `u32` child exit code into `1..=255`, never wrapping to `0`.
#[must_use]
const fn nonzero_exit_u32(code: u32) -> u8 {
    if code >= 1 && code <= 255 {
        code as u8
    } else {
        1
    }
}

/// Maps a non-zero `i32` child exit code into `1..=255`, never wrapping to `0`.
#[must_use]
const fn nonzero_exit_i32(code: i32) -> u8 {
    if code >= 1 && code <= 255 {
        code as u8
    } else {
        1
    }
}

/// Returns the direct child exit code when `err` represents a child process that
/// already streamed its own stdout/stderr and exited non-zero, so `main` can
/// propagate that code without printing a redundant wrapper error.
#[must_use]
pub(crate) fn direct_exit_code_u8(err: &InspectorError) -> Option<u8> {
    match err {
        InspectorError::Ops(OpsCliError::PythonExited { code })
        | InspectorError::Session(SessionError::Ops(OpsCliError::PythonExited { code })) => {
            Some(nonzero_exit_i32(*code))
        }
        InspectorError::Ops(OpsCliError::RemoteExited { code })
        | InspectorError::Session(SessionError::Ops(OpsCliError::RemoteExited { code })) => {
            Some(nonzero_exit_u32(*code))
        }
        InspectorError::Session(SessionError::RemoteShellExited { exit_code }) => {
            Some(nonzero_exit_u32(*exit_code))
        }
        _ => None,
    }
}

/// Convenience wrapper converting [`direct_exit_code_u8`] into [`ExitCode`].
#[must_use]
pub(crate) fn direct_exit_code(err: &InspectorError) -> Option<ExitCode> {
    direct_exit_code_u8(err).map(ExitCode::from)
}

/// Renders `err` for stderr, auto-detecting color support and `NO_COLOR`.
#[must_use]
pub(crate) fn render_error(err: &InspectorError) -> String {
    format_error(err, stderr_colors_enabled())
}

/// Renders `err` as a human-friendly diagnostic block with optional ANSI styling.
#[must_use]
pub(crate) fn format_error(err: &InspectorError, colors: bool) -> String {
    let theme = CliTheme::with_colors(colors);
    let headline = err.to_string();
    let mut out = String::new();
    let _ = write!(
        &mut out,
        "{}{} {headline}",
        theme.bold_red("error"),
        theme.bold(":")
    );

    let mut prev = headline;
    let mut current = err.source();
    while let Some(source) = current {
        let msg = source.to_string();
        if !msg.is_empty() && msg != prev && !prev.contains(&msg) {
            let _ = write!(&mut out, "\n  {} {msg}", theme.dim("caused by:"));
            prev = msg;
        }
        current = source.source();
    }

    if let Some(panic_text) = find_guest_panic(err) {
        let trimmed = panic_text.trim();
        if !trimmed.is_empty() {
            let _ = write!(
                &mut out,
                "\n\n{}{}",
                theme.bold_red("guest panic"),
                theme.bold(":")
            );
            for line in trimmed.lines() {
                let _ = write!(&mut out, "\n  {}", theme.dim(line));
            }
        }
    }

    if let Some(hint) = find_hint(err) {
        let _ = write!(
            &mut out,
            "\n{}{} {hint}",
            theme.bold_cyan("hint"),
            theme.bold(":")
        );
    }

    out
}

/// Formats a millisecond duration into a compact human-readable uptime string
/// (`450ms`, `12.3s`, `4m 12s`, `1h 05m`, `2d 03h`).
#[must_use]
pub(crate) fn format_duration_ms(ms: u64) -> String {
    if ms < 1_000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1_000.0)
    } else if ms < 3_600_000 {
        let total_secs = ms / 1_000;
        let mins = total_secs / 60;
        let secs = total_secs % 60;
        format!("{mins}m {secs:02}s")
    } else if ms < 86_400_000 {
        let total_mins = ms / 60_000;
        let hours = total_mins / 60;
        let mins = total_mins % 60;
        format!("{hours}h {mins:02}m")
    } else {
        let total_hours = ms / 3_600_000;
        let days = total_hours / 24;
        let hours = total_hours % 24;
        format!("{days}d {hours:02}h")
    }
}

/// Formats a Unix timestamp in seconds as `YYYY-MM-DD HH:MM:SS UTC`.
#[must_use]
pub(crate) fn format_unix_timestamp(unix_secs: u64) -> String {
    let Ok(secs) = i64::try_from(unix_secs) else {
        return unix_secs.to_string();
    };
    let Ok(dt) = OffsetDateTime::from_unix_timestamp(secs) else {
        return unix_secs.to_string();
    };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

fn find_guest_panic(err: &InspectorError) -> Option<&str> {
    let mut current: Option<&(dyn Error + 'static)> = Some(err);
    while let Some(node) = current {
        if let Some(ops) = node.downcast_ref::<OpsError>()
            && let Some(panic) = ops.guest_panic()
        {
            return Some(panic);
        }
        if let Some(rpc) = node.downcast_ref::<RpcError>()
            && let Some(panic) = rpc.guest_panic()
        {
            return Some(panic);
        }
        if let Some(fs) = node.downcast_ref::<FsRpcError>()
            && let Some(panic) = fs.guest_panic()
        {
            return Some(panic);
        }
        if let Some(sys) = node.downcast_ref::<SystemError>()
            && let Some(panic) = sys.guest_panic()
        {
            return Some(panic);
        }
        if let Some(prog) = node.downcast_ref::<ProgramError>()
            && let Some(panic) = prog.guest_panic()
        {
            return Some(panic);
        }
        if let Some(remote) = node.downcast_ref::<RemoteError>()
            && let Some(panic) = remote.guest_panic()
        {
            return Some(panic);
        }
        if let Some(bench) = node.downcast_ref::<WorkloadBenchError>()
            && let Some(panic) = bench.guest_panic()
        {
            return Some(panic);
        }
        current = node.source();
    }
    None
}

const VALID_ONLY_CAPABILITIES_HINT: &str = "valid `--only` capabilities: \
    `inspect`, `trace` (`tracing`), `profile` (`profiling`), \
    `instance-read` (`ps`, `instances`), `instance-control` (`kill`), \
    `exec` (`spawn`, `programs`), `filesystem-read` (`fs-read`, `read`), \
    `filesystem-write` (`fs-write`, `write`), `snapshot`, `processors` (`cpu`), \
    `net` (`network`), `http`, `virtualize` (`vm`)";

fn find_hint(err: &InspectorError) -> Option<String> {
    if matches!(err, InspectorError::MissingTarget) {
        return Some(
            "pass `-t <NAME|URI>`, boot a local guest with `helios vm`, or configure a default \
             target via `helios target add <name> <uri> && helios target use <name>`"
                .to_owned(),
        );
    }

    let mut current: Option<&(dyn Error + 'static)> = Some(err);
    while let Some(node) = current {
        if let Some(acct) = node.downcast_ref::<AccountError>() {
            match acct {
                AccountError::AlreadyExists { username, .. } => {
                    return Some(format!(
                        "run `helios account inspect {username}` to view it, or pass `--replace` \
                         (`helios account create {username} --replace ...`) to re-enroll"
                    ));
                }
                AccountError::NotFound { username, .. } => {
                    return Some(format!(
                        "run `helios account ls` to see enrolled accounts, or \
                         `helios account create {username}` to enroll one"
                    ));
                }
                AccountError::InvalidUsername { .. } => {
                    return Some(
                        "usernames must match `[a-z_][a-z0-9_-]{0,31}` (for example `lexo`)"
                            .to_owned(),
                    );
                }
                AccountError::TouchIdUnsupported => {
                    return Some(
                        "pass `--fido2` to enroll a FIDO2 hardware security key on this host"
                            .to_owned(),
                    );
                }
                AccountError::TouchIdFailed { .. } => {
                    return Some(
                        "retry and confirm the macOS Touch ID prompt, or enroll a hardware key \
                         with `--fido2`"
                            .to_owned(),
                    );
                }
                AccountError::Fido2 { .. } => {
                    return Some(
                        "ensure your FIDO2 security key is connected and OpenSSH `ssh-keygen` \
                         supports `-sk` keys"
                            .to_owned(),
                    );
                }
                _ => {}
            }
        }

        if let Some(target) = node.downcast_ref::<TargetError>() {
            match target {
                TargetError::NoDefaultTarget { .. } => {
                    return Some(
                        "pass `-t <NAME|URI>`, boot a local guest with `helios vm`, or configure \
                         a default target via `helios target add <name> <uri> && helios target \
                         use <name>`"
                            .to_owned(),
                    );
                }
                TargetError::NotFound { .. } => {
                    return Some("run `helios target ls` to list configured targets".to_owned());
                }
                TargetError::InvalidLabelFilter { .. } => {
                    return Some("pass label selectors as `-l key=value`".to_owned());
                }
                _ => {}
            }
        }

        if let Some(vm_cfg) = node.downcast_ref::<VmConfigError>() {
            match vm_cfg {
                VmConfigError::NoNativeAccelerator(_) => {
                    return Some(
                        "on Apple Silicon pass `--arch aarch64` for native HVF acceleration, or \
                         pass `--accel tcg` explicitly for software emulation"
                            .to_owned(),
                    );
                }
                VmConfigError::GuiWithDisplayNone => {
                    return Some(
                        "omit `--display none`, or use `--desktop` instead of `--gui` for \
                         headless display attachment"
                            .to_owned(),
                    );
                }
                VmConfigError::HvfNeedsAarch64Host => {
                    return Some("pass `--accel tcg` to emulate aarch64 on this host".to_owned());
                }
                VmConfigError::WritableShareWithoutDir => {
                    return Some(
                        "pass `--shared-dir <DIR>` alongside `--shared-dir-writable`".to_owned(),
                    );
                }
                _ => {}
            }
        }

        if let Some(transport) = node.downcast_ref::<TransportError>() {
            match transport {
                TransportError::AuthRequired { .. } => {
                    return Some(
                        "enroll an operator account with `helios account create`, pass \
                         `--identity <NAME|PATH>`, or run `helios login`"
                            .to_owned(),
                    );
                }
                TransportError::PlainTcpAuthUnsupported { host, port } => {
                    return Some(format!(
                        "use `helios://{host}:{port}` so TLS channel binding protects \
                         authentication"
                    ));
                }
                _ => {}
            }
        }

        if let Some(cli) = node.downcast_ref::<OpsCliError>() {
            match cli {
                OpsCliError::UnknownCapability { .. } => {
                    return Some(VALID_ONLY_CAPABILITIES_HINT.to_owned());
                }
                OpsCliError::UnknownTraceLevel { .. } => {
                    return Some(
                        "expected one of `trace`, `debug`, `info`, `warn`, `error`, or `none`"
                            .to_owned(),
                    );
                }
                OpsCliError::ContainerNeedsRoot => {
                    return Some("pass `--image <OCI_REF>` or `--root <GUEST_PATH>`".to_owned());
                }
                OpsCliError::BridgeNeedsSink => {
                    return Some(
                        "pass `--prometheus-listen <ADDR>` and/or `--otlp-endpoint <URL>`"
                            .to_owned(),
                    );
                }
                OpsCliError::PythonNotFound => {
                    return Some(
                        "install `python3` on `PATH` or set `HELIOS_PYTHON=/path/to/python`"
                            .to_owned(),
                    );
                }
                _ => {}
            }
        }

        if let Some(build_step) = node.downcast_ref::<BuildStepError>()
            && let BuildStepError::Exited { label, .. } = build_step
        {
            if label == "prebuilding kernel bootfs" {
                return Some(
                    "if external WASI/WASIX boot artifacts under `artifacts/` are missing, run \
                     `./tools/wasi-apps/build.sh` first"
                        .to_owned(),
                );
            }
            if label.contains("Limine") || label.contains("limine") {
                return Some(
                    "install `limine` on `PATH` (with UEFI bootloaders under `../share/limine`) \
                     or set `HELIOS_LIMINE_BIN` and `HELIOS_LIMINE_SHARE`"
                        .to_owned(),
                );
            }
        }

        if let Some(SystemError::UnknownLevel { .. }) = node.downcast_ref::<SystemError>() {
            return Some(
                "expected one of `trace`, `debug`, `info`, `warn`, `error`, or `none`".to_owned(),
            );
        }

        current = node.source();
    }

    None
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::PathBuf;

    use helios_ops::{AccountError, OpsError, TargetError, TransportError};

    use super::{direct_exit_code_u8, format_duration_ms, format_error, format_unix_timestamp};
    use crate::ops_cli::OpsCliError;
    use crate::vm::{VmConfigError, VmError, VmNetworkSetupError};
    use crate::{InspectorError, SessionError};

    #[test]
    fn account_already_exists_formats_clean_headline_and_replace_hint() {
        let err = InspectorError::Ops(OpsCliError::Account(AccountError::AlreadyExists {
            username: "lexo".to_owned(),
            path: PathBuf::from("/Users/lexo/.config/helios/accounts/lexo.toml"),
        }));

        let plain = format_error(&err, false);
        assert!(
            !plain.contains('\x1b'),
            "colors=false must emit zero ANSI escape sequences: {plain:?}"
        );
        assert!(
            plain.starts_with("error: operator account `lexo` already exists"),
            "unexpected plain headline: {plain}"
        );
        assert!(
            plain.contains("hint: run `helios account inspect lexo`"),
            "missing inspect hint: {plain}"
        );
        assert!(
            plain.contains("--replace"),
            "missing --replace hint: {plain}"
        );
        assert!(
            !plain.contains("Ops(Account(AlreadyExists"),
            "Debug formatting leaked into error output: {plain}"
        );
        assert!(
            !plain.contains("caused by:"),
            "transparent wrappers must not emit duplicate caused-by lines: {plain}"
        );

        let colored = format_error(&err, true);
        assert!(
            colored.contains('\x1b'),
            "colors=true must emit ANSI styling: {colored:?}"
        );
        assert_eq!(
            console::strip_ansi_codes(&colored),
            plain,
            "stripping ANSI codes must match plain rendering verbatim"
        );
    }

    #[test]
    fn deduplicates_transparent_wrappers_and_prints_distinct_io_cause() {
        // 1. Deep transparent chain: InspectorError -> OpsCliError -> OpsError -> AccountError
        let wrapped_account = InspectorError::Ops(OpsCliError::Ops(OpsError::Account(
            AccountError::AlreadyExists {
                username: "alice".to_owned(),
                path: PathBuf::from("/tmp/alice.toml"),
            },
        )));
        let rendered = format_error(&wrapped_account, false);
        assert_eq!(
            rendered
                .matches("operator account `alice` already exists")
                .count(),
            1,
            "transparent wrapper chain must print headline exactly once: {rendered}"
        );
        assert!(
            !rendered.contains("caused by:"),
            "transparent wrapper chain must not emit redundant caused-by: {rendered}"
        );

        // 2. Error whose Display does not inline its `#[source]` io::Error
        let with_io_cause = InspectorError::Vm(VmError::NetworkSetup(
            VmNetworkSetupError::StateUnreadable {
                path: PathBuf::from("/var/run/helios/net.json"),
                source: io::Error::new(io::ErrorKind::PermissionDenied, "access denied"),
            },
        ));
        let rendered_io = format_error(&with_io_cause, false);
        assert!(
            rendered_io.contains("error: failed to read the host state record"),
            "missing outer headline: {rendered_io}"
        );
        assert!(
            rendered_io.contains("  caused by: access denied"),
            "distinct underlying io::Error must appear under caused by: {rendered_io}"
        );
    }

    #[test]
    fn direct_exit_code_maps_child_exits_and_never_wraps_to_zero() {
        let remote_42 = InspectorError::Ops(OpsCliError::RemoteExited { code: 42 });
        assert_eq!(direct_exit_code_u8(&remote_42), Some(42));

        let remote_256 =
            InspectorError::Session(SessionError::Ops(OpsCliError::RemoteExited { code: 256 }));
        assert_eq!(direct_exit_code_u8(&remote_256), Some(1));

        let py_3 = InspectorError::Ops(OpsCliError::PythonExited { code: 3 });
        assert_eq!(direct_exit_code_u8(&py_3), Some(3));

        let py_neg =
            InspectorError::Session(SessionError::Ops(OpsCliError::PythonExited { code: -9 }));
        assert_eq!(direct_exit_code_u8(&py_neg), Some(1));

        let shell_7 = InspectorError::Session(SessionError::RemoteShellExited { exit_code: 7 });
        assert_eq!(direct_exit_code_u8(&shell_7), Some(7));

        let shell_512 = InspectorError::Session(SessionError::RemoteShellExited { exit_code: 512 });
        assert_eq!(direct_exit_code_u8(&shell_512), Some(1));

        let missing = InspectorError::MissingTarget;
        assert_eq!(direct_exit_code_u8(&missing), None);
    }

    #[test]
    fn hints_cover_target_transport_vm_and_cli_errors() {
        let target_missing =
            InspectorError::Ops(OpsCliError::Target(TargetError::NoDefaultTarget {
                store_path: PathBuf::from("/tmp/targets.toml"),
            }));
        assert!(format_error(&target_missing, false).contains("helios target add"));

        let auth_req = InspectorError::Ops(OpsCliError::Ops(OpsError::Transport(
            TransportError::AuthRequired {
                host: "10.0.0.1".to_owned(),
                port: 9443,
            },
        )));
        assert!(format_error(&auth_req, false).contains("helios account create"));

        let plain_tcp = InspectorError::Ops(OpsCliError::Ops(OpsError::Transport(
            TransportError::PlainTcpAuthUnsupported {
                host: "node1".to_owned(),
                port: 9443,
            },
        )));
        assert!(format_error(&plain_tcp, false).contains("helios://node1:9443"));

        let bad_cap = InspectorError::Ops(OpsCliError::UnknownCapability {
            raw: "bogus".to_owned(),
        });
        let bad_cap_rendered = format_error(&bad_cap, false);
        for cap in [
            "inspect",
            "trace",
            "profile",
            "instance-read",
            "instance-control",
            "exec",
            "filesystem-read",
            "filesystem-write",
            "snapshot",
            "processors",
            "net",
            "http",
            "virtualize",
        ] {
            assert!(
                bad_cap_rendered.contains(cap),
                "capability hint missing `{cap}`: {bad_cap_rendered}"
            );
        }

        let gui_none = InspectorError::Vm(VmError::Config(VmConfigError::GuiWithDisplayNone));
        assert!(format_error(&gui_none, false).contains("--desktop"));
    }

    #[test]
    fn format_duration_ms_and_unix_timestamp_produce_human_strings() {
        assert_eq!(format_duration_ms(0), "0ms");
        assert_eq!(format_duration_ms(450), "450ms");
        assert_eq!(format_duration_ms(12_300), "12.3s");
        assert_eq!(format_duration_ms(252_000), "4m 12s");
        assert_eq!(format_duration_ms(3_900_000), "1h 05m");
        assert_eq!(format_duration_ms(183_600_000), "2d 03h");

        assert_eq!(format_unix_timestamp(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(
            format_unix_timestamp(1_795_742_100),
            "2026-11-27 01:15:00 UTC"
        );
    }
}
