"""Cases: one gtest case of one suite binary, and the lists that name them.

A case list is one case per line, the binary's file name and the gtest
name separated by a space, the format `helios-inspector vm … linux-suite`
reads. The committed passing lists use it too.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, order=True)
class Case:
    binary: str
    name: str

    def line(self) -> str:
        return f"{self.binary} {self.name}"


class CaseListError(ValueError):
    pass


def parse_case_lines(text: str, source: str) -> list[Case]:
    """Parses a case list, refusing any line that is not one case."""
    cases = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        binary, _, name = line.partition(" ")
        name = name.strip()
        if not binary or "/" in binary or not name or " " in name:
            raise CaseListError(f"line {number} of {source} is not `<binary> <Suite.Case>`: {raw!r}")
        cases.append(Case(binary, name))
    return cases


def read_case_list(path: Path) -> list[Case]:
    return parse_case_lines(path.read_text(), str(path))


def write_case_list(path: Path, cases: list[Case], header: str = "") -> None:
    lines = [f"# {line}" for line in header.splitlines()]
    lines.extend(case.line() for case in sorted(set(cases)))
    path.write_text("".join(f"{line}\n" for line in lines))


def parse_gtest_listing(binary: str, listing: str) -> list[Case]:
    """Reads `--gtest_list_tests` output: an unindented `Suite.` line, then
    one indented case per line, each optionally followed by a `#` comment
    naming its type or parameter (googletest's `ListTestsMatchingFilter`)."""
    cases = []
    suite = None
    for raw in listing.splitlines():
        text = raw.split("#", 1)[0].rstrip()
        if not text:
            continue
        if not raw.startswith(" "):
            if not text.endswith("."):
                raise CaseListError(f"{binary}: unexpected listing line {raw!r}")
            suite = text
            continue
        if suite is None:
            raise CaseListError(f"{binary}: case {raw!r} listed before any suite")
        cases.append(Case(binary, f"{suite}{text.strip()}"))
    return cases


def list_binary(path: Path) -> list[Case]:
    """Lists the cases one binary holds, by running it on this host."""
    listed = subprocess.run(
        [str(path), "--gtest_list_tests"], capture_output=True, text=True, check=True, timeout=60
    )
    return parse_gtest_listing(path.name, listed.stdout)


def binaries_in(directory: Path) -> list[Path]:
    return sorted(path for path in directory.iterdir() if path.name.endswith("_test") and path.is_file())


def shard(cases: list[Case], index: int, count: int) -> list[Case]:
    """The cases shard `index` of `count` runs: every `count`th of the sorted
    list, so neighbouring cases of one slow binary spread across shards."""
    if count < 1 or not 0 <= index < count:
        raise ValueError(f"shard {index} of {count} does not exist")
    return sorted(cases)[index::count]
