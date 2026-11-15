import json
import os
import subprocess
from fnmatch import fnmatchcase

import pytest
import yaml

from helios_bench.manifest import REPO_ROOT


@pytest.fixture
def ci_jobs():
    return yaml.load((REPO_ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)["jobs"]


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


@pytest.mark.parametrize("changed", [[], ["host_tools"], ["shared"], ["aarch64"], None])
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
    assert ci_jobs["checks"]["needs"] == "changes"
    assert ci_jobs["tests"]["needs"] == ["changes", "wasm-debug"]
    for name in lanes:
        if name.startswith("smoke-"):
            assert f"wasm-{catalog[name]['guest-wasm']}" in ci_jobs[name]["needs"]


def test_every_selected_review_job_has_a_fifteen_minute_limit(ci_jobs, tmp_path):
    selected = select_lanes(ci_jobs, tmp_path, changed=None, heavy=False)
    jobs = {"changes", "checks", "tests", "gate"}
    jobs.update(name for name in json.loads(selected["lanes"]) if name in ci_jobs)
    jobs.update(f"wasm-{profile}" for profile in json.loads(selected["wasm_profiles"]))
    for name in jobs:
        assert int(ci_jobs[name]["timeout-minutes"]) <= 15, name


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
    filtering = next(step for step in ci_jobs["changes"]["steps"] if step.get("id") == "filter")
    assert filtering["with"]["predicate-quantifier"] == "some-with-excludes"
    filters = yaml.safe_load(filtering["with"]["filters"])
    changed = [
        name
        for name, patterns in filters.items()
        if any(
            any(fnmatchcase(path, pattern) for pattern in patterns if not pattern.startswith("!"))
            and all(not fnmatchcase(path, pattern[1:]) for pattern in patterns if pattern.startswith("!"))
            for path in paths
        )
    ]
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
