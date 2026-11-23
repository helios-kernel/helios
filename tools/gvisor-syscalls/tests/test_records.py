from gvisor_syscalls.records import Verdict, judge


def exited(code, stdout="", timed_out=False):
    return {
        "binary": "read_test",
        "case": "ReadTest.ZeroBuffer",
        "end": "exited",
        "exit_code": code,
        "stdout": stdout,
        "stderr": "",
        "timed_out": timed_out,
        "seconds": 1.0,
    }


# googletest's closing lines for one passing and one skipped test.
PASSED = "[==========] 1 test from 1 test suite ran. (0 ms total)\n[  PASSED  ] 1 test.\n"
SKIPPED = (
    "[==========] 1 test from 1 test suite ran. (0 ms total)\n[  PASSED  ] 0 tests.\n"
    "[  SKIPPED ] 1 test, listed below:\n[  SKIPPED ] ReadTest.ZeroBuffer\n"
)


def test_a_passing_case_passes():
    assert judge(exited(0, PASSED)).verdict == Verdict.PASSED


def test_a_skipped_case_is_skipped():
    assert judge(exited(0, SKIPPED)).verdict == Verdict.SKIPPED


def test_a_clean_exit_that_ran_nothing_fails():
    judged = judge(exited(0, "[==========] 0 tests from 0 test suites ran.\n"))
    assert judged.verdict == Verdict.FAILED
    assert "without running" in judged.reason


def test_a_signal_names_itself():
    judged = judge(exited(139))
    assert judged.verdict == Verdict.FAILED
    assert judged.reason == "exited 139, signal 11"


def test_a_bound_fails_the_case_whatever_it_printed():
    assert judge(exited(0, PASSED, timed_out=True)).reason.startswith("timed out")


def test_a_refusal_and_a_lost_guest_fail():
    refused = {**exited(0), "end": "refused", "kind": "InvalidBinary", "detail": "not ET_EXEC"}
    lost = {**exited(0), "end": "guest-lost", "detail": "the inspector's session exited 1"}
    assert judge(refused).reason == "launch refused (InvalidBinary): not ET_EXEC"
    assert judge(lost).verdict == Verdict.FAILED
