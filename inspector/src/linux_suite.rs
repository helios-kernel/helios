//! `vm … linux-suite`: runs conformance-suite cases against the guest's
//! Linux subsystem, one case per process, each under a bound.
//!
//! A case is one gtest case of one static Linux test binary, started
//! through `helios:system/programs.exec` with `--gtest_filter=<Suite.Case>`, the
//! way gVisor's own runner starts a case natively
//! (`test/runner/main.go`, `runTestCaseNative`). A case that outlives its
//! bound is killed by the instance name its launch registered, so an
//! unimplemented call that blocks, or a loop that never ends, costs that
//! case and nothing after it.
//!
//! The action records what happened and judges nothing: each line of
//! `--results` is the exit code or the refusal, whether the bound expired,
//! the time the case took and what it printed. Whether that is a pass, a
//! skip or a failure is the suite tooling's call (`tools/gvisor-syscalls`),
//! which reads the native Linux run of the same binaries the same way.
//!
//! A guest that stops answering ends the action with an error after the
//! cases it completed were written, so a caller that boots a fresh guest
//! knows which case it lost and where to resume.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::Args as ClapArgs;
use helios_wit_rpc::inspector::helios::system::programs::{ExecErrorKind, ExecResult};
use helios_wit_rpc::inspector_fs::{self, FsRpcError, MountBtrfsRequest};
use serde::Serialize;

use crate::programs::{ContainerMountBind, ExecInContainerRequest, ProgramError};
use crate::serial::RpcClient;
use crate::system::{self, SystemError};
use crate::vm::VcpuStateCapture;

/// How many bytes of each output stream a record keeps, from its end.
///
/// A gtest failure report is a few lines; the bound exists for the case
/// that loops writing, which would otherwise put megabytes of one line
/// into a report artifact read for thousands of cases.
const OUTPUT_TAIL_BYTES: usize = 64 * 1024;

/// Runs the cases a file lists, one guest process per case.
#[derive(Debug, Clone, ClapArgs)]
pub(crate) struct LinuxSuiteCommand {
    /// The cases to run, one per line: the binary's file name, a space,
    /// and the gtest case (`Suite.Case`). Blank lines and lines starting
    /// with `#` are ignored.
    cases: PathBuf,

    /// The guest directory holding the binaries, such as the `/host`
    /// mount of `--shared-dir`.
    #[arg(long, value_name = "GUEST_DIR")]
    guest_dir: String,

    /// How long one case may run before it is killed and recorded as
    /// having timed out.
    #[arg(long, value_name = "SECONDS")]
    case_timeout_seconds: u64,

    /// How long a killed case may take to end before the guest is taken
    /// to have stopped answering.
    #[arg(long, value_name = "SECONDS", default_value_t = 10)]
    kill_grace_seconds: u64,

    /// Where to append one JSON line per completed case. Each line is
    /// flushed before the next case starts.
    #[arg(long, value_name = "PATH")]
    results: PathBuf,

    /// Optional virtio-blk serial of a writable btrfs disk to mount as a
    /// private container mount at `/tmp` so every case runs inside a Linux
    /// container with `/tmp` (private, writable), `guest_dir` (shared,
    /// read-only executable), and `TEST_TMPDIR` on that private btrfs mount.
    #[arg(long, value_name = "SERIAL")]
    private_btrfs: Option<String>,
}

/// Why the suite run stopped before its last case.
#[derive(Debug, thiserror::Error)]
pub(crate) enum LinuxSuiteError {
    #[error("failed to read the case list {path}: {source}")]
    ReadCases {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("line {line} of the case list {path} is not `<binary> <Suite.Case>`: {text:?}")]
    MalformedCase {
        path: String,
        line: usize,
        text: String,
    },
    #[error("failed to open the results file {path}: {source}")]
    OpenResults {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to write the result of {binary} {case} to {path}: {source}")]
    WriteResult {
        binary: String,
        case: String,
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to mount private btrfs disk {serial:?} at /tmp: {source}")]
    MountPrivateBtrfs {
        serial: String,
        #[source]
        source: FsRpcError,
    },
    #[error("the guest stopped answering while it ran {binary} {case}: {source}")]
    GuestLost {
        binary: String,
        case: String,
        // Boxed, as is the kill's: either one inline makes every
        // session error as large as the RPC failure it carries.
        #[source]
        source: Box<ProgramError>,
    },
    #[error("failed to kill {binary} {case} after its {seconds}s bound: {source}")]
    Kill {
        binary: String,
        case: String,
        seconds: u64,
        #[source]
        source: Box<SystemError>,
    },
    #[error(
        "{binary} {case} was killed after its {seconds}s bound and had not ended {grace}s later; \
         the guest is taken to have stopped answering"
    )]
    KillUnanswered {
        binary: String,
        case: String,
        seconds: u64,
        grace: u64,
    },
}

/// One case the list names.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Case {
    binary: String,
    case: String,
}

/// What one case did, as the results file records it.
#[derive(Debug, Serialize)]
struct CaseRecord<'a> {
    binary: &'a str,
    case: &'a str,
    #[serde(flatten)]
    end: &'a CaseEnd,
    /// Whether the case was still running when its bound expired.
    timed_out: bool,
    seconds: f64,
}

/// How the case's process ended.
#[derive(Debug, Serialize)]
#[serde(tag = "end", rename_all = "kebab-case")]
enum CaseEnd {
    /// The process ran and exited, or was ended by a signal, which the
    /// program service reports as `128 + signal`.
    Exited {
        exit_code: u32,
        stdout: String,
        stderr: String,
    },
    /// The program service refused to start the binary.
    Refused {
        #[serde(serialize_with = "serialize_exec_error_kind")]
        kind: ExecErrorKind,
        detail: String,
    },
}

fn serialize_exec_error_kind<S>(kind: &ExecErrorKind, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!("{kind:?}"))
}

pub(crate) async fn run(
    client: &RpcClient,
    command: &LinuxSuiteCommand,
    vcpus: &VcpuStateCapture,
) -> Result<(), LinuxSuiteError> {
    let cases = read_cases(&command.cases)?;
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&command.results)
        .map_err(|source| LinuxSuiteError::OpenResults {
            path: command.results.display().to_string(),
            source,
        })?;
    let mut results = BufWriter::new(file);
    let guest_dir = command.guest_dir.trim_end_matches('/');
    if let Some(serial) = command.private_btrfs.as_deref() {
        inspector_fs::mount_btrfs(
            client,
            &MountBtrfsRequest {
                disk: serial.to_owned(),
                path: "/tmp".to_owned(),
                read_only: false,
                shared: false,
                compress: None,
                commit: None,
                max_inline: None,
            },
        )
        .await
        .map_err(|source| LinuxSuiteError::MountPrivateBtrfs {
            serial: serial.to_owned(),
            source,
        })?;
    }
    for (index, case) in cases.iter().enumerate() {
        // Printed before the launch, so a caller whose guest died can tell
        // a case that took the guest down from a session that never
        // reached its first case.
        eprintln!("linux-suite: running {} {}", case.binary, case.case);
        let record = run_case(client, command, guest_dir, index, case, vcpus).await?;
        write_record(&mut results, &command.results, case, &record)?;
        eprintln!(
            "linux-suite: {} {} {}",
            case.binary,
            case.case,
            record.summary()
        );
    }
    Ok(())
}

async fn run_case(
    client: &RpcClient,
    command: &LinuxSuiteCommand,
    guest_dir: &str,
    index: usize,
    case: &Case,
    vcpus: &VcpuStateCapture,
) -> Result<Finished, LinuxSuiteError> {
    let path = format!("{guest_dir}/{}", case.binary);
    let args = vec![format!("--gtest_filter={}", case.case)];
    let started = Instant::now();
    let mut exec = core::pin::pin!(async {
        if command.private_btrfs.is_some() {
            let scratch_dir = format!("/tmp/gvisor-case-{index}");
            crate::programs::exec_in_container(
                client,
                ExecInContainerRequest {
                    path: path.clone(),
                    args: args.clone(),
                    env: vec![("TEST_TMPDIR".to_owned(), scratch_dir.clone())],
                    mounts: vec![
                        ContainerMountBind {
                            source_path: "/tmp".to_owned(),
                            target_path: "/tmp".to_owned(),
                            writable: true,
                            private: true,
                        },
                        ContainerMountBind {
                            source_path: guest_dir.to_owned(),
                            target_path: guest_dir.to_owned(),
                            writable: false,
                            private: false,
                        },
                    ],
                    scratch_dir: Some(scratch_dir),
                },
            )
            .await
        } else {
            crate::programs::exec(client, &path, &args).await
        }
    });
    let bound = Duration::from_secs(command.case_timeout_seconds);
    if let Some(outcome) = crate::runtime::timeout(bound, exec.as_mut()).await {
        return finish(case, outcome, false, started);
    }
    // The launch registers the instance under the path it was started
    // from, and one case runs at a time, so the name is this case's. The
    // exec stays polled while the kill travels: its reply is what says
    // the process has ended.
    let killed = futures_lite::future::or(async { KillRace::Ended(exec.as_mut().await) }, async {
        KillRace::Killed(system::kill_named_instance(client, &path).await)
    })
    .await;
    let outcome = match killed {
        KillRace::Ended(outcome) => outcome,
        // Killed, or already gone or stopping by the time the kill
        // arrived: either way its exec reply is on its way.
        KillRace::Killed(
            Ok(_) | Err(SystemError::NoInstanceNamed { .. } | SystemError::KillRefused { .. }),
        ) => {
            let grace = Duration::from_secs(command.kill_grace_seconds);
            match crate::runtime::timeout(grace, exec.as_mut()).await {
                Some(outcome) => outcome,
                None => {
                    let lost = LinuxSuiteError::KillUnanswered {
                        binary: case.binary.clone(),
                        case: case.case.clone(),
                        seconds: command.case_timeout_seconds,
                        grace: command.kill_grace_seconds,
                    };
                    record_vcpus(vcpus, &lost).await;
                    return Err(lost);
                }
            }
        }
        KillRace::Killed(Err(source)) => {
            return Err(LinuxSuiteError::Kill {
                binary: case.binary.clone(),
                case: case.case.clone(),
                seconds: command.case_timeout_seconds,
                source: Box::new(source),
            });
        }
    };
    finish(case, outcome, true, started)
}

/// Which of the exec reply and the kill's answer arrived first.
enum KillRace {
    Ended(Result<ExecResult, ProgramError>),
    Killed(Result<u64, SystemError>),
}

/// A case's end, before it is written.
struct Finished {
    end: CaseEnd,
    timed_out: bool,
    seconds: f64,
}

impl Finished {
    fn summary(&self) -> String {
        let bound = if self.timed_out {
            " after its bound"
        } else {
            ""
        };
        match &self.end {
            CaseEnd::Exited { exit_code, .. } => {
                format!("exited {exit_code}{bound} in {:.3}s", self.seconds)
            }
            CaseEnd::Refused { kind, .. } => format!("refused ({kind:?}){bound}"),
        }
    }
}

fn finish(
    case: &Case,
    outcome: Result<ExecResult, ProgramError>,
    timed_out: bool,
    started: Instant,
) -> Result<Finished, LinuxSuiteError> {
    let seconds = started.elapsed().as_secs_f64();
    let end = match outcome {
        Ok(result) => CaseEnd::Exited {
            exit_code: result.exit_code,
            stdout: output_tail(&result.output.stdout),
            stderr: output_tail(&result.output.stderr),
        },
        Err(ProgramError::Refused { kind, detail }) => CaseEnd::Refused { kind, detail },
        Err(source) => {
            return Err(LinuxSuiteError::GuestLost {
                binary: case.binary.clone(),
                case: case.case.clone(),
                source: Box::new(source),
            });
        }
    };
    Ok(Finished {
        end,
        timed_out,
        seconds,
    })
}

async fn record_vcpus(vcpus: &VcpuStateCapture, lost: &LinuxSuiteError) {
    let capture = vcpus.clone();
    let trigger = lost.to_string();
    // QMP is a blocking socket; the capture stays off the executor thread.
    if let Err(error) = blocking::unblock(move || capture.capture_after(&trigger)).await {
        eprintln!("helios-inspector: {error}");
    }
}

/// The last [`OUTPUT_TAIL_BYTES`] of `bytes`, decoded lossily.
fn output_tail(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(OUTPUT_TAIL_BYTES);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

fn write_record(
    results: &mut BufWriter<File>,
    path: &Path,
    case: &Case,
    finished: &Finished,
) -> Result<(), LinuxSuiteError> {
    let record = CaseRecord {
        binary: &case.binary,
        case: &case.case,
        end: &finished.end,
        timed_out: finished.timed_out,
        seconds: finished.seconds,
    };
    let mut write = || -> io::Result<()> {
        serde_json::to_writer(&mut *results, &record)?;
        results.write_all(b"\n")?;
        results.flush()
    };
    write().map_err(|source| LinuxSuiteError::WriteResult {
        binary: case.binary.clone(),
        case: case.case.clone(),
        path: path.display().to_string(),
        source,
    })
}

fn read_cases(path: &Path) -> Result<Vec<Case>, LinuxSuiteError> {
    let text = fs::read_to_string(path).map_err(|source| LinuxSuiteError::ReadCases {
        path: path.display().to_string(),
        source,
    })?;
    parse_cases(&text).map_err(|(line, text)| LinuxSuiteError::MalformedCase {
        path: path.display().to_string(),
        line,
        text,
    })
}

/// Parses a case list; a malformed line comes back as its 1-based number
/// and text.
fn parse_cases(text: &str) -> Result<Vec<Case>, (usize, String)> {
    text.lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.trim()))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .map(|(number, line)| {
            let malformed = || (number, line.to_owned());
            let (binary, case) = line.split_once(' ').ok_or_else(malformed)?;
            let case = case.trim();
            // A binary is a file name in the guest directory and a case is
            // one gtest name; a slash in the first or a space in the
            // second means the line is not one case.
            if binary.is_empty() || binary.contains('/') || case.is_empty() || case.contains(' ') {
                return Err(malformed());
            }
            Ok(Case {
                binary: binary.to_owned(),
                case: case.to_owned(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cases_and_skips_comments() {
        let cases = parse_cases(
            "# header\n\nread_test ReadTest.ZeroBuffer\n  pipe_test Pipes/PipeTest.Flags/0  \n",
        )
        .expect("well-formed list");
        assert_eq!(
            cases,
            vec![
                Case {
                    binary: "read_test".to_owned(),
                    case: "ReadTest.ZeroBuffer".to_owned(),
                },
                Case {
                    binary: "pipe_test".to_owned(),
                    case: "Pipes/PipeTest.Flags/0".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn refuses_a_line_that_is_not_one_case() {
        assert_eq!(parse_cases("read_test\n"), Err((1, "read_test".to_owned())));
        assert_eq!(
            parse_cases("ok_test A.B\nlinux/read_test A.B\n"),
            Err((2, "linux/read_test A.B".to_owned()))
        );
        assert_eq!(
            parse_cases("read_test A.B C.D\n"),
            Err((1, "read_test A.B C.D".to_owned()))
        );
    }

    #[test]
    fn keeps_the_end_of_a_long_output() {
        let long = vec![b'x'; OUTPUT_TAIL_BYTES + 3];
        assert_eq!(output_tail(&long).len(), OUTPUT_TAIL_BYTES);
        assert_eq!(output_tail(b"short"), "short");
    }

    #[test]
    fn records_an_exit_as_one_json_line() {
        let end = CaseEnd::Exited {
            exit_code: 0,
            stdout: "[  PASSED  ] 1 test.\n".to_owned(),
            stderr: String::new(),
        };
        let record = CaseRecord {
            binary: "read_test",
            case: "ReadTest.ZeroBuffer",
            end: &end,
            timed_out: false,
            seconds: 0.5,
        };
        let value = serde_json::to_value(&record).expect("serialisable");
        assert_eq!(value["end"], "exited");
        assert_eq!(value["exit_code"], 0);
        assert_eq!(value["timed_out"], false);
        assert_eq!(value["case"], "ReadTest.ZeroBuffer");
    }
}
