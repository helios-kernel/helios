"""Case records and what they mean.

A record is one JSON line saying how one case's process ended. The
inspector's `linux-suite` action writes them for Helios
(inspector/src/linux_suite.rs); `native` writes the same shape for the
host. Both are judged here, by the same rules, so a verdict never differs
between the two sides for any reason but the kernel underneath.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from gvisor_syscalls.cases import Case

# googletest's summary lines for a run of exactly one test
# (googletest/src/gtest.cc, `PrettyUnitTestResultPrinter::OnTestIterationEnd`).
PASSED_LINE = "[  PASSED  ] 1 test."
SKIPPED_LINE = "[  SKIPPED ] 1 test,"

# The program service and a POSIX shell both report a process a signal
# ended as 128 plus the signal's number.
SIGNAL_EXIT_BASE = 128


class Verdict(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class Judged:
    verdict: Verdict
    # Why a failed case failed; empty otherwise.
    reason: str


def judge(record: dict) -> Judged:
    end = record["end"]
    if record["timed_out"]:
        return Judged(Verdict.FAILED, f"timed out after {record['seconds']:.0f}s")
    if end == "refused":
        return Judged(Verdict.FAILED, f"launch refused ({record['kind']}): {record['detail']}")
    if end == "guest-lost":
        return Judged(Verdict.FAILED, f"guest stopped answering: {record['detail']}")
    if end != "exited":
        raise ValueError(f"record of {record['binary']} {record['case']} has unknown end {end!r}")
    code = record["exit_code"]
    if code > SIGNAL_EXIT_BASE:
        return Judged(Verdict.FAILED, f"exited {code}, signal {code - SIGNAL_EXIT_BASE}")
    if code != 0:
        return Judged(Verdict.FAILED, f"exited {code}")
    stdout = record["stdout"]
    if SKIPPED_LINE in stdout:
        return Judged(Verdict.SKIPPED, "")
    if PASSED_LINE in stdout:
        return Judged(Verdict.PASSED, "")
    return Judged(Verdict.FAILED, "exited 0 without running its one test")


def case_of(record: dict) -> Case:
    return Case(record["binary"], record["case"])


def read_records(paths: list[Path]) -> dict[Case, dict]:
    """Every record in `paths`; a case recorded twice is a broken run."""
    records: dict[Case, dict] = {}
    for path in paths:
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            case = case_of(record)
            if case in records:
                raise ValueError(f"{path}:{number}: {case.line()} is recorded twice")
            records[case] = record
    return records


def append_record(path: Path, record: dict) -> None:
    with path.open("a") as results:
        results.write(json.dumps(record, ensure_ascii=False))
        results.write("\n")
