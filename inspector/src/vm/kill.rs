//! Ends the guest abruptly once it has recorded enough progress.
//!
//! A crash-consistency check needs the machine to die while a guest
//! program is mid-burst, at a point the guest itself marks: the program
//! appends one line to a file the host can read (a writable
//! `--shared-dir`) after each unit of work it completed, and the host
//! SIGKILLs QEMU when that file holds the requested number of complete
//! lines. The guest gets no chance to flush, unmount or shut down, which
//! is the whole point; bytes it already handed to QEMU's disk backend are
//! in the host's page cache and stay, exactly as after a guest crash.

use std::fs;
use std::io::ErrorKind;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// How often the watched file is read. Short against a guest that syncs
/// a file every few milliseconds, so the kill lands within a unit or two
/// of the requested line.
const POLL_INTERVAL: Duration = Duration::from_millis(2);

/// `--kill-after-lines <FILE>:<COUNT>`: SIGKILL QEMU once `FILE` holds
/// `COUNT` newline-terminated lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KillAfterLines {
    file: PathBuf,
    lines: NonZeroUsize,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum KillAfterLinesError {
    #[error("expected `<FILE>:<COUNT>`, got `{value}`")]
    Shape { value: String },
    #[error("line count `{count}` is not a positive integer")]
    Count { count: String },
}

impl FromStr for KillAfterLines {
    type Err = KillAfterLinesError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (file, count) = value
            .rsplit_once(':')
            .filter(|(file, _)| !file.is_empty())
            .ok_or_else(|| KillAfterLinesError::Shape {
                value: value.to_owned(),
            })?;
        let lines = count.parse().map_err(|_| KillAfterLinesError::Count {
            count: count.to_owned(),
        })?;
        Ok(Self {
            file: PathBuf::from(file),
            lines,
        })
    }
}

impl KillAfterLines {
    /// Starts watching on behalf of the QEMU process `qemu_pid`. The
    /// watch ends when the returned handle is dropped.
    pub(crate) fn watch(&self, qemu_pid: u32) -> KillWatch {
        let (stop, stopped) = mpsc::channel::<()>();
        let target = self.clone();
        let thread = thread::spawn(move || {
            // The sender is dropped, never sent on: a disconnect is the
            // stop signal, a timeout is the poll tick.
            while let Err(mpsc::RecvTimeoutError::Timeout) = stopped.recv_timeout(POLL_INTERVAL) {
                let complete = match fs::read(&target.file) {
                    Ok(bytes) => bytes.iter().filter(|byte| **byte == b'\n').count(),
                    // The guest has not created it yet.
                    Err(error) if error.kind() == ErrorKind::NotFound => continue,
                    Err(error) => {
                        eprintln!(
                            "kill-after-lines: reading {}: {error}; the guest is left running",
                            target.file.display()
                        );
                        return;
                    }
                };
                if complete < target.lines.get() {
                    continue;
                }
                let pid = i32::try_from(qemu_pid).expect("a process id fits in pid_t");
                // SAFETY: `kill` takes no pointers. The pid is QEMU's own
                // child, which stays unreaped, so unkillable-by-reuse,
                // until the runtime waits on it after this watch ends.
                let status = unsafe { libc::kill(pid, libc::SIGKILL) };
                if status == 0 {
                    println!(
                        "kill-after-lines: SIGKILL sent to QEMU (pid {qemu_pid}) with {complete} \
                         complete lines in {}",
                        target.file.display()
                    );
                } else {
                    eprintln!(
                        "kill-after-lines: kill({qemu_pid}) failed: {}",
                        std::io::Error::last_os_error()
                    );
                }
                return;
            }
        });
        KillWatch {
            stop: Some(stop),
            thread: Some(thread),
        }
    }
}

/// A running watch. Dropping it stops the thread.
pub(crate) struct KillWatch {
    stop: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for KillWatch {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            thread.join().expect("the kill watch thread does not panic");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flag_value_splits_at_its_last_colon() {
        let parsed: KillAfterLines = "/tmp/a:b/ledger:7".parse().unwrap();
        assert_eq!(parsed.file, PathBuf::from("/tmp/a:b/ledger"));
        assert_eq!(parsed.lines.get(), 7);
    }

    #[test]
    fn a_value_without_a_file_or_a_positive_count_is_refused() {
        assert!(matches!(
            "7".parse::<KillAfterLines>(),
            Err(KillAfterLinesError::Shape { .. })
        ));
        assert!(matches!(
            ":7".parse::<KillAfterLines>(),
            Err(KillAfterLinesError::Shape { .. })
        ));
        assert!(matches!(
            "ledger:0".parse::<KillAfterLines>(),
            Err(KillAfterLinesError::Count { .. })
        ));
        assert!(matches!(
            "ledger:x".parse::<KillAfterLines>(),
            Err(KillAfterLinesError::Count { .. })
        ));
    }

    #[test]
    fn a_watch_without_enough_lines_ends_when_dropped() {
        let directory = tempfile::tempdir().unwrap();
        let ledger = directory.path().join("ledger");
        fs::write(&ledger, "one\npartial").unwrap();
        let target = KillAfterLines {
            file: ledger,
            lines: NonZeroUsize::new(2).unwrap(),
        };
        // The watch must not fire, because only one line is complete; the
        // pid is the largest one `pid_t` holds, which no process has.
        drop(target.watch(i32::MAX.unsigned_abs()));
    }
}
