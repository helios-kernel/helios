"""`gvisor-syscalls`: lists, runs, reports and gates gVisor's syscall suite."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from gvisor_syscalls import helios, native, report
from gvisor_syscalls.cases import (
    Case,
    binaries_in,
    list_binary,
    read_case_list,
    shard,
    write_case_list,
)
from gvisor_syscalls.records import Verdict, judge, read_records


def parse_shard(text: str) -> tuple[int, int]:
    index, _, count = text.partition("/")
    return int(index), int(count)


def listed_cases(paths: list[Path]) -> list[Case]:
    return sorted({case for path in paths for case in read_case_list(path)})


def command_binaries(args: argparse.Namespace) -> int:
    for binary in sorted({case.binary for case in listed_cases(args.passing)}):
        print(binary)
    return 0


def command_list(args: argparse.Namespace) -> int:
    cases = [case for binary in binaries_in(args.bin_dir) for case in list_binary(binary)]
    if args.only:
        wanted = set(listed_cases(args.only))
        cases = [case for case in cases if case in wanted]
    write_case_list(args.out, cases)
    print(f"{len(cases)} cases in {len({case.binary for case in cases})} binaries", file=sys.stderr)
    return 0


def command_native(args: argparse.Namespace) -> int:
    cases = shard(read_case_list(args.cases), *args.shard)
    native.run(args.bin_dir, cases, args.timeout, args.results)
    return 0


def command_helios(args: argparse.Namespace) -> int:
    records = read_records(args.native)
    cases = [
        case
        for case in shard(read_case_list(args.cases), *args.shard)
        if judge(records[case]).verdict != Verdict.FAILED
    ]
    if not args.inspector:
        raise SystemExit("the inspector command follows `--`")
    helios.run(args.inspector, cases, args.results, args.log)
    return 0


def command_report(args: argparse.Namespace) -> int:
    revision = json.loads(args.pin.read_text())["revision"]
    built = report.build(
        arch=args.arch,
        mode=report.Mode(args.mode),
        revision=revision,
        cases=read_case_list(args.cases),
        native=read_records(args.native),
        helios=read_records(args.helios),
        listed=read_case_list(args.passing),
    )
    report.write(built, args.out_dir)
    if args.summary is not None:
        with args.summary.open("a") as summary:
            summary.write(report.render_summary(built))
    if not built.gate_holds():
        print(
            f"{len(built.regressions)} listed case(s) stopped passing and "
            f"{len(built.unlisted)} passing case(s) are unlisted; see {args.out_dir}",
            file=sys.stderr,
        )
        return 1
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="gvisor-syscalls", description=__doc__)
    commands = root.add_subparsers(required=True)

    binaries = commands.add_parser("binaries", help="print the binaries the passing lists name")
    binaries.add_argument("passing", type=Path, nargs="+")
    binaries.set_defaults(run=command_binaries)

    listing = commands.add_parser("list", help="list the cases the built binaries hold")
    listing.add_argument("--bin-dir", type=Path, required=True)
    listing.add_argument("--out", type=Path, required=True)
    listing.add_argument("--only", type=Path, nargs="*", default=[], help="keep only these lists' cases")
    listing.set_defaults(run=command_list)

    on_linux = commands.add_parser("native", help="run a shard of the cases on this Linux host")
    on_linux.add_argument("--bin-dir", type=Path, required=True)
    on_linux.add_argument("--cases", type=Path, required=True)
    on_linux.add_argument("--shard", type=parse_shard, default=(0, 1), metavar="INDEX/COUNT")
    on_linux.add_argument("--timeout", type=float, required=True, help="seconds one case may run")
    on_linux.add_argument("--results", type=Path, required=True)
    on_linux.set_defaults(run=command_native)

    on_helios = commands.add_parser(
        "helios", help="run the shard's natively passing cases on Helios through the inspector"
    )
    on_helios.add_argument("--cases", type=Path, required=True)
    on_helios.add_argument("--native", type=Path, nargs="+", required=True)
    on_helios.add_argument("--shard", type=parse_shard, default=(0, 1), metavar="INDEX/COUNT")
    on_helios.add_argument("--results", type=Path, required=True)
    on_helios.add_argument("--log", type=Path, required=True)
    on_helios.add_argument(
        "inspector",
        nargs=argparse.REMAINDER,
        help="after `--`: the inspector command up to and including `linux-suite` and its options",
    )
    on_helios.set_defaults(run=command_helios)

    gate = commands.add_parser("report", help="count, publish and gate one architecture's run")
    gate.add_argument("--arch", required=True, choices=["x86_64", "aarch64"])
    gate.add_argument("--mode", required=True, choices=[mode.value for mode in report.Mode])
    gate.add_argument("--cases", type=Path, required=True)
    gate.add_argument("--native", type=Path, nargs="+", required=True)
    gate.add_argument("--helios", type=Path, nargs="+", required=True)
    gate.add_argument("--passing", type=Path, required=True)
    gate.add_argument("--pin", type=Path, required=True, help="the pin.json the binaries were built from")
    gate.add_argument("--out-dir", type=Path, required=True)
    gate.add_argument("--summary", type=Path, help="append the Markdown summary here")
    gate.set_defaults(run=command_report)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if getattr(args, "inspector", None) and args.inspector[0] == "--":
        args.inspector = args.inspector[1:]
    return args.run(args)
