import pytest

from gvisor_syscalls.cases import Case, CaseListError, parse_case_lines, parse_gtest_listing, shard

# The shape `--gtest_list_tests` prints for plain, typed and parameterised
# cases (googletest/src/gtest.cc, `ListTestsMatchingFilter`).
LISTING = """\
ReadTest.
  ZeroBuffer
  EofAfterRead
AllPipeTypes/PipeTest.
  Flags/0  # GetParam() = 4-byte object <00-00 00-00>
  Flags/1  # GetParam() = 4-byte object <01-00 00-00>
"""


def test_reads_a_gtest_listing():
    assert parse_gtest_listing("pipe_test", LISTING) == [
        Case("pipe_test", "ReadTest.ZeroBuffer"),
        Case("pipe_test", "ReadTest.EofAfterRead"),
        Case("pipe_test", "AllPipeTypes/PipeTest.Flags/0"),
        Case("pipe_test", "AllPipeTypes/PipeTest.Flags/1"),
    ]


def test_refuses_a_case_before_its_suite():
    with pytest.raises(CaseListError):
        parse_gtest_listing("read_test", "  ZeroBuffer\n")


def test_parses_a_case_list():
    text = "# header\n\nread_test ReadTest.ZeroBuffer\n"
    assert parse_case_lines(text, "list") == [Case("read_test", "ReadTest.ZeroBuffer")]


@pytest.mark.parametrize("line", ["read_test", "linux/read_test A.B", "read_test A.B C.D"])
def test_refuses_a_line_that_is_not_one_case(line):
    with pytest.raises(CaseListError):
        parse_case_lines(line, "list")


def test_shards_cover_every_case_once():
    cases = [Case(f"b{index % 3}_test", f"S.C{index}") for index in range(10)]
    shards = [shard(cases, index, 4) for index in range(4)]
    assert sorted(case for part in shards for case in part) == sorted(cases)
    assert max(map(len, shards)) - min(map(len, shards)) <= 1


def test_refuses_a_shard_outside_the_count():
    with pytest.raises(ValueError):
        shard([], 4, 4)
