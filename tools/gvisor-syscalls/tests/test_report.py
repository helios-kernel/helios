from gvisor_syscalls.cases import Case
from gvisor_syscalls.report import Mode, build, render_summary

PASSED = "[  PASSED  ] 1 test.\n"
SKIPPED = "[  PASSED  ] 0 tests.\n[  SKIPPED ] 1 test, listed below:\n"


def record(case, code, stdout=""):
    return {
        "binary": case.binary,
        "case": case.name,
        "end": "exited",
        "exit_code": code,
        "stdout": stdout,
        "stderr": "",
        "timed_out": False,
        "seconds": 0.1,
    }


READ = Case("read_test", "ReadTest.ZeroBuffer")
EOF = Case("read_test", "ReadTest.Eof")
PIPE = Case("pipe_test", "PipeTest.Flags")
PROC = Case("proc_test", "ProcTest.Self")
CASES = [READ, EOF, PIPE, PROC]
NATIVE = {
    READ: record(READ, 0, PASSED),
    EOF: record(EOF, 0, PASSED),
    PIPE: record(PIPE, 0, SKIPPED),
    PROC: record(PROC, 1),
}
HELIOS = {
    READ: record(READ, 0, PASSED),
    EOF: record(EOF, 1),
    PIPE: record(PIPE, 0, SKIPPED),
}


def test_counts_each_case_once_per_binary_and_in_total():
    report = build("x86_64", Mode.FULL, "rev", CASES, NATIVE, HELIOS, [READ])
    assert dict(report.totals) == {"passed": 1, "failed": 1, "skipped": 1, "excluded": 1}
    assert dict(report.binaries["read_test"]) == {"passed": 1, "failed": 1}
    assert report.excluded == [{"case": PROC.line(), "reason": "exited 1"}]
    assert report.gate_holds()


def test_a_listed_case_that_stops_passing_fails_the_gate():
    report = build("x86_64", Mode.LISTED, "rev", CASES, NATIVE, HELIOS, [READ, EOF])
    assert report.regressions == [{"case": EOF.line(), "reason": "exited 1"}]
    assert not report.gate_holds()


def test_a_full_run_refuses_an_unlisted_pass():
    report = build("x86_64", Mode.FULL, "rev", CASES, NATIVE, HELIOS, [])
    assert report.unlisted == [READ]
    assert not report.gate_holds()


def test_a_listed_run_does_not_ask_for_unlisted_passes():
    report = build("x86_64", Mode.LISTED, "rev", CASES, NATIVE, HELIOS, [])
    assert report.gate_holds()


def test_a_listed_case_the_suite_lacks_fails_the_gate():
    gone = Case("gone_test", "Gone.Case")
    report = build("x86_64", Mode.FULL, "rev", CASES, NATIVE, HELIOS, [READ, gone])
    assert report.regressions == [{"case": gone.line(), "reason": "not a case of this run's suite"}]


def test_the_summary_carries_the_counts_and_the_regressions():
    report = build("aarch64", Mode.LISTED, "rev", CASES, NATIVE, HELIOS, [READ, EOF])
    summary = render_summary(report)
    assert "| **total** | **1** | **1** | **1** | **1** |" in summary
    assert "| `read_test` | 1 | 1 | 0 | 0 |" in summary
    assert f"- `{EOF.line()}`: exited 1" in summary
