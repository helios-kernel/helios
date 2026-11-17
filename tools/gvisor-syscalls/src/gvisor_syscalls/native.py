"""The native Linux run: each case on the host, the way gVisor's runner
runs a case natively (test/runner/main.go, `runTestCaseNative`): its own
process, `--gtest_filter` naming the case, and a fresh `TEST_TMPDIR`."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from gvisor_syscalls.cases import Case
from gvisor_syscalls.records import SIGNAL_EXIT_BASE, append_record

# The tail of each output stream a record keeps, the bound the inspector's
# records use (`OUTPUT_TAIL_BYTES` in inspector/src/linux_suite.rs).
OUTPUT_TAIL_BYTES = 64 * 1024


def tail(data: bytes) -> str:
    return data[-OUTPUT_TAIL_BYTES:].decode("utf-8", errors="replace")


def run_case(bin_dir: Path, case: Case, timeout: float) -> dict:
    scratch = tempfile.mkdtemp(prefix="gvisor-case-")
    env = dict(os.environ, TEST_TMPDIR=scratch)
    started = time.monotonic()
    # Its own session, so a bound that expires ends every process the case
    # started, not only the first.
    process = subprocess.Popen(
        [str(bin_dir / case.binary), f"--gtest_filter={case.name}"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
    seconds = time.monotonic() - started
    # gVisor's runner removes the directory the same way and ignores what a
    # case left unremovable (`defer os.RemoveAll(tmpDir)`).
    shutil.rmtree(scratch, ignore_errors=True)
    code = process.returncode
    return {
        "binary": case.binary,
        "case": case.name,
        "end": "exited",
        # Popen reports a signal as its negative number; the record uses the
        # program service's convention, 128 plus the signal.
        "exit_code": SIGNAL_EXIT_BASE - code if code < 0 else code,
        "stdout": tail(stdout),
        "stderr": tail(stderr),
        "timed_out": timed_out,
        "seconds": seconds,
    }


def run(bin_dir: Path, cases: list[Case], timeout: float, results: Path) -> None:
    if results.exists():
        raise FileExistsError(f"{results} already holds a run")
    results.touch()
    for case in cases:
        record = run_case(bin_dir, case, timeout)
        append_record(results, record)
        print(f"native: {case.line()} exited {record['exit_code']} in {record['seconds']:.3f}s", flush=True)
