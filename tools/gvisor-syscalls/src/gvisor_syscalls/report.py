"""The report of one architecture's run, and the gate on the passing list.

Every case of the run's case list is counted once, per binary and in
total: excluded when it does not pass or skip on native Linux (with the
native reason), and otherwise passed, failed or skipped on Helios. A
listed case that does not pass on Helios fails the gate; in a full run, so
does a case that passes and is not listed, because the list is the
record of what passes and a change that makes a case pass extends it.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from jinja2 import Environment, PackageLoader, StrictUndefined

from gvisor_syscalls.cases import Case, write_case_list
from gvisor_syscalls.records import Verdict, judge

COLUMNS = ("passed", "failed", "skipped", "excluded")


class Mode(StrEnum):
    # Every case of the suite: the dispatched and nightly run.
    FULL = "full"
    # The listed cases only: the pull-request run.
    LISTED = "listed"


@dataclass
class Report:
    arch: str
    mode: Mode
    revision: str
    totals: Counter = field(default_factory=Counter)
    binaries: dict[str, Counter] = field(default_factory=dict)
    excluded: list[dict] = field(default_factory=list)
    failed: list[dict] = field(default_factory=list)
    passing: list[Case] = field(default_factory=list)
    # Listed cases that did not pass on Helios, with why.
    regressions: list[dict] = field(default_factory=list)
    # Cases that passed on Helios and are not listed (full runs only).
    unlisted: list[Case] = field(default_factory=list)

    def gate_holds(self) -> bool:
        return not self.regressions and not self.unlisted

    def as_json(self) -> dict:
        return {
            "arch": self.arch,
            "mode": self.mode.value,
            "revision": self.revision,
            "totals": {column: self.totals[column] for column in COLUMNS},
            "binaries": {
                binary: {column: counts[column] for column in COLUMNS}
                for binary, counts in sorted(self.binaries.items())
            },
            "excluded": self.excluded,
            "failed": self.failed,
            "regressions": self.regressions,
            "unlisted": [case.line() for case in self.unlisted],
        }


class IncompleteRunError(ValueError):
    pass


def build(
    arch: str,
    mode: Mode,
    revision: str,
    cases: list[Case],
    native: dict[Case, dict],
    helios: dict[Case, dict],
    listed: list[Case],
) -> Report:
    report = Report(arch, mode, revision)
    suite = set(cases)
    for case in sorted(suite):
        counts = report.binaries.setdefault(case.binary, Counter())
        if case not in native:
            raise IncompleteRunError(f"{case.line()} has no native record")
        on_linux = judge(native[case])
        if on_linux.verdict == Verdict.FAILED:
            column = "excluded"
            report.excluded.append({"case": case.line(), "reason": on_linux.reason})
        else:
            if case not in helios:
                raise IncompleteRunError(f"{case.line()} passed natively and has no Helios record")
            on_helios = judge(helios[case])
            column = on_helios.verdict.value
            if on_helios.verdict == Verdict.FAILED:
                report.failed.append({"case": case.line(), "reason": on_helios.reason})
            elif on_helios.verdict == Verdict.PASSED:
                report.passing.append(case)
        counts[column] += 1
        report.totals[column] += 1
    passing = set(report.passing)
    reasons = {entry["case"]: entry["reason"] for entry in report.failed + report.excluded}
    for case in sorted(set(listed)):
        if case in passing:
            continue
        if case not in suite:
            reason = "not a case of this run's suite"
        elif case.line() in reasons:
            reason = reasons[case.line()]
        else:
            reason = "skipped"
        report.regressions.append({"case": case.line(), "reason": reason})
    if mode == Mode.FULL:
        report.unlisted = sorted(passing - set(listed))
    return report


def render_summary(report: Report) -> str:
    environment = Environment(
        loader=PackageLoader("gvisor_syscalls"),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        autoescape=False,
    )
    return environment.get_template("summary.md.j2").render(report=report, columns=COLUMNS)


def write(report: Report, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"report-{report.arch}.json").write_text(json.dumps(report.as_json(), indent=2) + "\n")
    (out_dir / f"summary-{report.arch}.md").write_text(render_summary(report))
    # The list this run supports, to replace the committed one with when a
    # full run's gate names unlisted passes.
    write_case_list(
        out_dir / f"passing-{report.arch}.txt",
        report.passing,
        header=passing_header(report.arch, report.revision),
    )


def passing_header(arch: str, revision: str) -> str:
    return (
        f"gVisor syscall cases that pass on Helios ({arch}), at gVisor {revision}.\n"
        "A run fails when one of them stops passing; extend the list when a change makes more pass.\n"
        f"A full run publishes this file as passing-{arch}.txt in its report artifact."
    )
