import json
import os
import subprocess

import pytest
import yaml

from helios_bench.manifest import REPO_ROOT


@pytest.fixture
def ci_jobs():
    return yaml.load((REPO_ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)["jobs"]


@pytest.mark.parametrize("changed", [[], ["host_tools"], ["shared"], ["aarch64"], None])
@pytest.mark.parametrize("draft", [False, True])
@pytest.mark.parametrize("heavy", [False, True])
def test_selected_checks_keep_their_commands_and_only_payload_tests_wait(
    ci_jobs, tmp_path, changed, draft, heavy
):
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
    selected = dict(line.split("=", 1) for line in output.read_text().splitlines())
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
