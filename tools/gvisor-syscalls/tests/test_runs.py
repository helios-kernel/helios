import sys
import textwrap

import pytest

from gvisor_syscalls import helios, native
from gvisor_syscalls.cases import Case
from gvisor_syscalls.records import Verdict, judge, read_records

# Stands in for `helios-inspector vm … linux-suite`: it records each case it
# is given and, on a case named `*.Crash`, stops answering the way a guest
# that went down does.
FAKE_INSPECTOR = textwrap.dedent(
    """\
    import json, sys
    cases, results = sys.argv[1], sys.argv[3]
    with open(cases) as listing:
        lines = [line.split() for line in listing if line.strip() and not line.startswith("#")]
    for binary, case in lines:
        print(f"linux-suite: running {binary} {case}", file=sys.stderr, flush=True)
        if case.endswith(".Crash"):
            sys.exit(1)
        record = {"binary": binary, "case": case, "end": "exited", "exit_code": 0,
                  "stdout": "[  PASSED  ] 1 test.\\n", "stderr": "", "timed_out": False, "seconds": 0.0}
        with open(results, "a") as out:
            out.write(json.dumps(record) + "\\n")
    """
)


@pytest.fixture
def inspector(tmp_path):
    script = tmp_path / "inspector.py"
    script.write_text(FAKE_INSPECTOR)
    return [sys.executable, str(script)]


def test_a_crash_costs_one_case_and_the_rest_resume(tmp_path, inspector):
    cases = [Case("a_test", "A.One"), Case("a_test", "A.Crash"), Case("b_test", "B.Two")]
    results = tmp_path / "helios.jsonl"
    helios.run(inspector, cases, results, tmp_path / "inspector.log")
    records = read_records([results])
    assert set(records) == set(cases)
    assert records[Case("a_test", "A.Crash")]["end"] == "guest-lost"
    assert judge(records[Case("b_test", "B.Two")]).verdict == Verdict.PASSED


def test_a_session_that_never_began_a_case_is_an_error(tmp_path):
    results = tmp_path / "helios.jsonl"
    with pytest.raises(helios.SessionError, match="before it began"):
        helios.run(
            [sys.executable, "-c", "raise SystemExit(2)"],
            [Case("a_test", "A.One")],
            results,
            tmp_path / "inspector.log",
        )


def write_binary(directory, name, body):
    path = directory / name
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)


def test_a_native_case_runs_in_its_own_tmpdir_and_reports_its_end(tmp_path):
    write_binary(tmp_path, "ok_test", 'test -d "$TEST_TMPDIR" && echo "[  PASSED  ] 1 test."')
    write_binary(tmp_path, "segv_test", "kill -SEGV $$")
    results = tmp_path / "native.jsonl"
    native.run(tmp_path, [Case("ok_test", "Ok.Case"), Case("segv_test", "Segv.Case")], 30, results)
    records = read_records([results])
    assert judge(records[Case("ok_test", "Ok.Case")]).verdict == Verdict.PASSED
    assert records[Case("segv_test", "Segv.Case")]["exit_code"] == 139


def test_a_native_case_past_its_bound_is_killed(tmp_path):
    write_binary(tmp_path, "hang_test", "sleep 30 & wait")
    record = native.run_case(tmp_path, Case("hang_test", "Hang.Case"), 0.5)
    assert record["timed_out"]
    assert record["seconds"] < 10
