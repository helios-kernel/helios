import json
import os
import re
import subprocess
from fnmatch import fnmatchcase

import pytest
import yaml

from helios_bench.manifest import REPO_ROOT


@pytest.fixture
def ci_workflow():
    return yaml.load((REPO_ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)


@pytest.fixture
def ci_jobs(ci_workflow):
    return ci_workflow["jobs"]


def select_lanes(ci_jobs, tmp_path, changed, draft=False, heavy=False):
    select = next(step for step in ci_jobs["changes"]["steps"] if step.get("id") == "select")
    output = tmp_path / "outputs"
    subprocess.run(
        ["bash", "-c", select["run"]],
        cwd=REPO_ROOT,
        env={
            **os.environ,
            "CHANGED": json.dumps(changed),
            "DRAFT": json.dumps(draft),
            "HEAVY": json.dumps(heavy),
            "GITHUB_OUTPUT": str(output),
        },
        check=True,
        capture_output=True,
    )
    return dict(line.split("=", 1) for line in output.read_text().splitlines())


def path_matches(path, pattern):
    # A leading globstar also matches zero directories in paths-filter.
    return fnmatchcase(path, pattern) or (
        pattern.startswith("**/") and fnmatchcase(path, pattern.removeprefix("**/"))
    )


def changed_surfaces(ci_jobs, paths):
    filtering = next(step for step in ci_jobs["changes"]["steps"] if step.get("id") == "filter")
    assert filtering["with"]["predicate-quantifier"] == "some-with-excludes"
    filters = yaml.safe_load(filtering["with"]["filters"])
    return [
        name
        for name, patterns in filters.items()
        if any(
            any(path_matches(path, pattern) for pattern in patterns if not pattern.startswith("!"))
            and all(not path_matches(path, pattern[1:]) for pattern in patterns if pattern.startswith("!"))
            for path in paths
        )
    ]


@pytest.mark.parametrize(
    "changed", [[], ["host_tools"], ["shared"], ["aarch64"], ["btrfs"], ["btrfs_src"], None]
)
@pytest.mark.parametrize("draft", [False, True])
@pytest.mark.parametrize("heavy", [False, True])
def test_selected_checks_keep_their_commands_and_only_payload_tests_wait(
    ci_jobs, tmp_path, changed, draft, heavy
):
    selected = select_lanes(ci_jobs, tmp_path, changed, draft, heavy)
    lanes = json.loads(selected["lanes"])
    checks = json.loads(selected["checks"])
    tests = json.loads(selected["tests"])
    catalog = json.loads((REPO_ROOT / ".github/ci-lanes.json").read_text())
    assert {entry["name"]: entry["command"] for entry in checks + tests} == {
        name: catalog[name]["command"] for name in lanes if "command" in catalog[name]
    }
    assert all(entry["guest-wasm"] == "" for entry in checks)
    assert all(entry["guest-wasm"] == "debug" for entry in tests)
    if not heavy:
        assert not any(catalog[name].get("heavy", False) for name in lanes)
    if heavy and changed is None and not draft:
        assert set(lanes) == set(catalog)
    if draft:
        assert set(lanes) <= {"lint-fmt"}
    if changed == []:
        assert lanes == []
    if changed == ["btrfs_src"] and not draft:
        assert "test-libraries" in lanes
    assert ci_jobs["checks"]["needs"] == "changes"
    # The payload tests start with `changes` and wait for the guest wasm in
    # a step, after their tests have compiled and before their command runs.
    assert ci_jobs["tests"]["needs"] == "changes"
    steps = [step.get("uses", step.get("name", "")) for step in ci_jobs["tests"]["steps"]]
    wait = steps.index("./helios/.github/actions/prebuilt-wasm")
    assert steps.index("Compile the tests of ${{ matrix.name }}") < wait
    assert steps.index("${{ matrix.name }}") > wait
    for name in lanes:
        if name.startswith("smoke-"):
            assert f"wasm-{catalog[name]['guest-wasm']}" in ci_jobs[name]["needs"]


@pytest.mark.parametrize(
    "lane", ["", "test-libraries", "test-kernel", "missing", "test-btrfs-fuzz", "smoke-x86-64"]
)
def test_manual_lane_validates_selection_and_keeps_dependencies(ci_workflow, ci_jobs, tmp_path, lane):
    dispatch_input = ci_workflow["on"]["workflow_dispatch"]["inputs"]["check_lane"]
    assert dispatch_input["required"] == "true"
    assert "default" not in dispatch_input

    select = next(step for step in ci_jobs["changes"]["steps"] if step.get("id") == "select")
    output = tmp_path / "outputs"
    result = subprocess.run(
        ["bash", "-c", select["run"]],
        cwd=REPO_ROOT,
        env={
            **os.environ,
            "CHANGED": "null",
            "DRAFT": "false",
            "HEAVY": "true",
            "EVENT": "workflow_dispatch",
            "CHECK_LANE": lane,
            "GITHUB_OUTPUT": str(output),
        },
        capture_output=True,
    )
    if lane == "":
        assert result.returncode != 0
        assert b"check_lane" in result.stderr
        return
    if lane == "missing":
        assert result.returncode != 0
        assert b"Unknown lane" in result.stderr
        return
    assert result.returncode == 0, result.stderr.decode()
    selected = dict(line.split("=", 1) for line in output.read_text().splitlines())
    assert json.loads(selected["lanes"]) == [lane]
    catalog = json.loads((REPO_ROOT / ".github/ci-lanes.json").read_text())
    profile = catalog[lane].get("guest-wasm")
    assert json.loads(selected["wasm_profiles"]) == ([profile] if profile else [])
    checks = json.loads(selected["checks"]) + json.loads(selected["tests"])
    assert [check["name"] for check in checks] == ([lane] if "command" in catalog[lane] else [])


def test_schedule_still_selects_full_suite(ci_jobs, tmp_path):
    select = next(step for step in ci_jobs["changes"]["steps"] if step.get("id") == "select")
    output = tmp_path / "outputs"
    result = subprocess.run(
        ["bash", "-c", select["run"]],
        cwd=REPO_ROOT,
        env={
            **os.environ,
            "CHANGED": "null",
            "DRAFT": "false",
            "HEAVY": "true",
            "EVENT": "schedule",
            "CHECK_LANE": "",
            "GITHUB_OUTPUT": str(output),
        },
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr.decode()
    selected = dict(line.split("=", 1) for line in output.read_text().splitlines())
    catalog = json.loads((REPO_ROOT / ".github/ci-lanes.json").read_text())
    assert set(json.loads(selected["lanes"])) == set(catalog)
    assert selected["linux_suite_mode"] == "full"


def test_every_selected_review_job_has_a_fifteen_minute_limit(ci_jobs, tmp_path):
    selected = select_lanes(ci_jobs, tmp_path, changed=None, heavy=False)
    jobs = {"changes", "checks", "tests", "gate"}
    jobs.update(name for name in json.loads(selected["lanes"]) if name in ci_jobs)
    jobs.update(f"wasm-{profile}" for profile in json.loads(selected["wasm_profiles"]))
    mode = selected["linux_suite_mode"]
    assert mode == "listed"
    listed_shards = json.loads(selected["linux_suite_shards"])
    assert sum(1 for entry in listed_shards if entry["arch"] == "x86_64") == 8
    assert sum(1 for entry in listed_shards if entry["arch"] == "aarch64") == 16
    jobs.update({"linux-syscalls-build", "linux-syscalls", "linux-syscalls-report"})
    # The suite's jobs take their limit from the mode: a full run's shards
    # are heavy and run on dispatch and nightly only.
    by_mode = re.compile(
        r"\$\{\{ needs\.changes\.outputs\.linux_suite_mode == 'full' && (\d+) \|\| (\d+) \}\}"
    )
    for name in jobs:
        limit = ci_jobs[name]["timeout-minutes"]
        if matched := by_mode.fullmatch(limit):
            limit = matched[1] if mode == "full" else matched[2]
        assert int(limit) <= 15, name


@pytest.mark.parametrize(
    ("paths", "rust"),
    [
        (["tools/bench/src/helios_bench/cli.py", "tools/bench/tests/test_gate.py"], False),
        (["tools/bench/native/sched-tasks.c", "tools/bench/manifest.toml"], False),
        (["tools/bench/src/helios_bench/cli.py", "kernel/src/lib.rs"], True),
        (["new-shared-input.toml"], True),
    ],
)
def test_benchmark_inputs_select_tooling_without_unrelated_rust(ci_jobs, tmp_path, paths, rust):
    changed = changed_surfaces(ci_jobs, paths)
    selected = select_lanes(ci_jobs, tmp_path, changed)
    lanes = json.loads(selected["lanes"])
    assert ("test-kernel" in lanes) == rust
    if not rust:
        assert lanes == []
        assert json.loads(selected["wasm_profiles"]) == []

    benchmark = yaml.load(
        (REPO_ROOT / ".github/workflows/bench-suite.yml").read_text(), Loader=yaml.BaseLoader
    )
    filtering = next(step for step in benchmark["jobs"]["changes"]["steps"] if step.get("id") == "filter")
    patterns = yaml.safe_load(filtering["with"]["filters"])["tooling"]
    if any(path.startswith("tools/bench/") for path in paths):
        assert any(fnmatchcase(path, pattern) for path in paths for pattern in patterns)


@pytest.mark.parametrize("result", ["success", "skipped", "failure", "cancelled"])
def test_ci_gate_rejects_failed_or_cancelled_dependencies(ci_jobs, result):
    gate = ci_jobs["gate"]
    assert set(gate["needs"]) == set(ci_jobs) - {"gate"}
    results = {name: {"result": "success"} for name in gate["needs"]}
    results["wasm-debug"]["result"] = result
    completed = subprocess.run(
        ["bash", "-c", gate["steps"][0]["run"]],
        env={**os.environ, "RESULTS": json.dumps(results)},
        capture_output=True,
    )
    assert (completed.returncode == 0) == (result in {"success", "skipped"})


@pytest.mark.parametrize(
    "path",
    [
        "README.md",
        "AGENTS.md",
        "docs/networking.md",
        "api/README.md",
        "api-macro/README.md",
        "programs/init/README.md",
        "compiler-plugin/README.md",
        "aarch64/README.md",
        "riscv/README.md",
        "x86/README.md",
        "hosted/README.md",
        "inspector/README.md",
        "inspector-protocol/README.md",
        "cli/README.md",
        "compiler-support/README.md",
        "profdata/README.md",
        "workspace-root/README.md",
        "hal/README.md",
        "kernel/README.md",
        "btrfs/README.md",
        "tools/btrfs/README.md",
        "tools/bench/README.md",
        "programs/gpu-test/README.md",
        "kernel/src/profiling/README.md",
        ".github/actions/checkout-wasmtime/README.md",
    ],
)
def test_prose_selects_no_build_lanes(ci_jobs, tmp_path, path):
    changed = changed_surfaces(ci_jobs, [path])
    assert changed == []
    selected = select_lanes(ci_jobs, tmp_path, changed)
    assert json.loads(selected["lanes"]) == []
    assert json.loads(selected["wasm_profiles"]) == []


def test_wasmtime_pin_keeps_every_existing_consumer(ci_jobs, tmp_path):
    changed = changed_surfaces(ci_jobs, ["docs/wasmtime.md"])
    assert changed == ["pin"]
    selected = select_lanes(ci_jobs, tmp_path, changed, heavy=True)
    catalog = json.loads((REPO_ROOT / ".github/ci-lanes.json").read_text())
    assert set(json.loads(selected["lanes"])) == set(catalog) - {
        "smoke-x86-64-venus",
        "test-btrfs-fstests",
        "linux-syscalls",
        "linux-syscalls-full",
    }


@pytest.mark.parametrize(
    "path",
    ["api/src/lib.rs", "aarch64/src/lib.rs", "inspector/src/main.rs", "btrfs/src/lib.rs"],
)
def test_mixed_prose_and_code_keeps_code_selection(ci_jobs, tmp_path, path):
    code = changed_surfaces(ci_jobs, [path])
    mixed = changed_surfaces(ci_jobs, ["api/README.md", "btrfs/README.md", path])
    assert mixed == code
    assert code
    selected = select_lanes(ci_jobs, tmp_path, mixed)
    assert json.loads(selected["lanes"])
