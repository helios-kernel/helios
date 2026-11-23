"""The Helios run: the cases the native run did not fail, through
`helios-inspector vm … linux-suite`, one guest process per case.

A case that takes the guest down ends the inspector's session. The case
it was running is recorded as lost, and a fresh guest resumes with the
case after it, so a crash costs one case and one boot.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from gvisor_syscalls.cases import Case, write_case_list
from gvisor_syscalls.records import append_record, read_records

RUNNING_PREFIX = "linux-suite: running "


class SessionError(RuntimeError):
    pass


def run_session(inspector: list[str], cases: list[Case], results: Path, log: Path) -> tuple[int, Case | None]:
    """Runs one guest session over `cases`, appending the inspector's
    output to `log`. Returns its exit status and the last case it began."""
    with tempfile.NamedTemporaryFile("w", suffix=".cases", delete=False) as listing:
        path = Path(listing.name)
    write_case_list(path, cases)
    began = None
    command = [*inspector, str(path), "--results", str(results)]
    with log.open("a") as sink:
        sink.write(f"$ {' '.join(command)}\n")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        assert process.stdout is not None
        for line in process.stdout:
            sink.write(line)
            sys.stderr.write(line)
            if line.startswith(RUNNING_PREFIX):
                binary, _, name = line[len(RUNNING_PREFIX) :].strip().partition(" ")
                began = Case(binary, name)
        status = process.wait()
    path.unlink()
    return status, began


def run(inspector: list[str], cases: list[Case], results: Path, log: Path) -> None:
    if results.exists():
        raise FileExistsError(f"{results} already holds a run")
    results.touch()
    while True:
        # A lost case is recorded too, so it is never run a second time.
        done = set(read_records([results]))
        remaining = [case for case in sorted(cases) if case not in done]
        if not remaining:
            return
        status, began = run_session(inspector, remaining, results, log)
        done = set(read_records([results]))
        unrecorded = [case for case in remaining if case not in done]
        if not unrecorded:
            if status != 0:
                raise SessionError(f"the inspector exited {status} after recording every case")
            return
        if status == 0:
            raise SessionError(f"the inspector exited 0 without recording {unrecorded[0].line()}")
        first = unrecorded[0]
        if began != first:
            # Nothing was running when the session ended, so no case is to
            # blame: the guest never came up, or the inspector failed.
            raise SessionError(f"the inspector exited {status} before it began {first.line()}; see {log}")
        append_record(
            results,
            {
                "binary": first.binary,
                "case": first.name,
                "end": "guest-lost",
                "detail": f"the inspector's session exited {status}",
                "timed_out": False,
                "seconds": 0.0,
            },
        )
        print(f"helios: {first.line()} took the guest down; booting a fresh one", flush=True)
