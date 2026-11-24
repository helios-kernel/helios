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
    checks_no_cli = json.loads(selected["checks_no_cli"])
    checks = json.loads(selected["checks"])
    tests = json.loads(selected["tests"])
    catalog = json.loads((REPO_ROOT / ".github/ci-lanes.json").read_text())
    assert {entry["name"]: entry["command"] for entry in checks_no_cli + checks + tests} == {
        name: catalog[name]["command"] for name in lanes if "command" in catalog[name]
    }
    assert all(entry["guest-wasm"] == "" and not entry["helios-cli"] for entry in checks_no_cli)
    assert all(entry["guest-wasm"] == "" and entry["helios-cli"] for entry in checks)
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
    assert ci_jobs["checks-no-cli"]["needs"] == "changes"
    assert ci_jobs["checks"]["needs"] == ["changes", "build-helios-cli-x64"]
    # The payload tests start beside `wasm-debug` after `build-helios-cli-x64`
    # and wait for the guest wasm in a step, after their tests have compiled
    # and before their command runs.
    assert ci_jobs["tests"]["needs"] == ["changes", "build-helios-cli-x64"]
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
    checks = (
        json.loads(selected["checks_no_cli"]) + json.loads(selected["checks"]) + json.loads(selected["tests"])
    )
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
    jobs = {
        "changes",
        "build-helios-cli-x64",
        "build-helios-cli-arm64",
        "wasi-artifacts",
        "checks-no-cli",
        "checks",
        "tests",
        "gate",
    }
    jobs.update(name for name in json.loads(selected["lanes"]) if name in ci_jobs)
    jobs.update(f"wasm-{profile}" for profile in json.loads(selected["wasm_profiles"]))
    mode = selected["linux_suite_mode"]
    assert mode == "listed"
    assert len(json.loads(selected["linux_suite_x86_64_shards"])) == 8
    assert len(json.loads(selected["linux_suite_aarch64_shards"])) == 16
    jobs.update(
        {
            "linux-syscalls-build-x86-64",
            "linux-syscalls-build-aarch64",
            "linux-syscalls-image-x86-64",
            "linux-syscalls-image-aarch64",
            "linux-syscalls-x86-64",
            "linux-syscalls-aarch64",
            "linux-syscalls-report",
        }
    )
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


def test_helios_cli_producer_covers_every_selected_consumer_and_consumers_only_download(ci_jobs, tmp_path):
    assert ci_jobs["build-helios-cli-x64"]["runs-on"] == "ubuntu-24.04"
    assert ci_jobs["build-helios-cli-arm64"]["runs-on"] == "ubuntu-24.04-arm"
    assert "linux-syscalls-build-x86-64" in ci_jobs["linux-syscalls-x86-64"]["needs"]
    assert "linux-syscalls-image-x86-64" in ci_jobs["linux-syscalls-x86-64"]["needs"]
    assert "linux-syscalls-build-aarch64" not in ci_jobs["linux-syscalls-x86-64"]["needs"]
    assert "linux-syscalls-image-aarch64" not in ci_jobs["linux-syscalls-x86-64"]["needs"]
    assert "linux-syscalls-build-aarch64" in ci_jobs["linux-syscalls-aarch64"]["needs"]
    assert "linux-syscalls-image-aarch64" in ci_jobs["linux-syscalls-aarch64"]["needs"]
    assert "linux-syscalls-build-x86-64" not in ci_jobs["linux-syscalls-aarch64"]["needs"]
    assert "linux-syscalls-image-x86-64" not in ci_jobs["linux-syscalls-aarch64"]["needs"]
    assert "kernel-profile" not in ci_jobs["linux-syscalls-image-aarch64"]["needs"]
    assert "kernel-profile" not in ci_jobs["linux-syscalls-aarch64"]["needs"]
    for name, job in ci_jobs.items():
        cli_steps = [
            step for step in job.get("steps", []) if step.get("uses") == "./helios/.github/actions/helios-cli"
        ]
        if cli_steps:
            runner = job.get("runs-on", "")
            expected_builder = "build-helios-cli-arm64" if "arm" in runner else "build-helios-cli-x64"
            other_builder = (
                "build-helios-cli-x64"
                if expected_builder == "build-helios-cli-arm64"
                else "build-helios-cli-arm64"
            )
            needs = job["needs"] if isinstance(job["needs"], list) else [job["needs"]]
            assert expected_builder in needs, name
            assert other_builder not in needs, name
            for step in cli_steps:
                assert step["with"].get("profile") == "debug", name
                assert step["with"].get("download-only") == "true", name

    catalog = json.loads((REPO_ROOT / ".github/ci-lanes.json").read_text())
    cases = [
        (["docs"], True, False),
        (["kernel"], True, False),
        (["kernel"], False, False),
        (["linux_abi"], False, False),
        (["gpu"], False, True),
        (None, False, True),
    ]
    for changed, draft, heavy in cases:
        selected = select_lanes(ci_jobs, tmp_path, changed, draft=draft, heavy=heavy)
        lanes = set(json.loads(selected["lanes"]))
        wasm_profiles = json.loads(selected["wasm_profiles"])
        expected_x64 = bool(wasm_profiles) or any(
            "x64" in catalog[lane].get("helios-cli", []) for lane in lanes
        )
        expected_arm64 = any("arm64" in catalog[lane].get("helios-cli", []) for lane in lanes)
        assert (selected["cli_x64"] == "true") == expected_x64, (changed, draft, heavy)
        assert (selected["cli_arm64"] == "true") == expected_arm64, (changed, draft, heavy)


def test_wasm_jobs_drop_host_rust_cache_and_subset_programs_safely(ci_jobs, tmp_path):
    catalog = json.loads((REPO_ROOT / ".github/ci-lanes.json").read_text())
    for lane, entry in catalog.items():
        if "guest-wasm" in entry:
            assert "guest-programs" in entry, lane

    for name in ("wasm-debug", "wasm-release"):
        steps = ci_jobs[name]["steps"]
        assert not any(step.get("uses", "").startswith("Swatinem/rust-cache") for step in steps), name
        assert not any("rustup toolchain uninstall" in step.get("run", "") for step in steps), name
        prune = next(
            step for step in steps if step.get("uses") == "./helios/.github/actions/prune-artifact-cache"
        )
        assert "matrix.programs == 'all'" in prune["if"], name

    # Draft PR (`lint-fmt` only): no wasm, no cli, no wasi-artifacts.
    draft_sel = select_lanes(ci_jobs, tmp_path, ["kernel"], draft=True, heavy=False)
    assert json.loads(draft_sel["lanes"]) == ["lint-fmt"]
    assert draft_sel["cli_x64"] == "false"
    assert draft_sel["cli_arm64"] == "false"
    assert draft_sel["wasm_debug_programs"] == ""
    assert draft_sel["wasm_release_programs"] == ""
    assert draft_sel["wasi_artifacts"] == "false"

    # Kernel PR: debug subset only (`init`, `debugger`), no compiler-plugin, no wasi-artifacts.
    kernel_sel = select_lanes(ci_jobs, tmp_path, ["kernel"], draft=False, heavy=False)
    assert json.loads(kernel_sel["wasm_debug_programs"]) == ["debugger", "init"]
    assert kernel_sel["wasm_release_programs"] == ""
    assert kernel_sel["wasi_artifacts"] == "false"

    # Kernel + linux_abi PR: reuses debug subset (`init`, `debugger`) without triggering
    # a separate `wasm-release` build, and needs no wasi-artifacts.
    linux_sel = select_lanes(ci_jobs, tmp_path, ["kernel", "linux_abi"], draft=False, heavy=False)
    assert json.loads(linux_sel["wasm_debug_programs"]) == ["debugger", "init"]
    assert linux_sel["wasm_release_programs"] == ""
    assert linux_sel["wasi_artifacts"] == "false"

    # Venus smoke: debug subset includes GPU/desktop programs, needs wasi-artifacts.
    venus_sel = select_lanes(ci_jobs, tmp_path, ["gpu"], draft=False, heavy=True)
    assert json.loads(venus_sel["wasm_debug_programs"]) == [
        "compositor",
        "debugger",
        "gpu-test",
        "init",
        "pride-flag",
    ]
    assert venus_sel["wasi_artifacts"] == "true"

    # Full nightly: release builds `all`, wasi-artifacts produced once.
    full_sel = select_lanes(ci_jobs, tmp_path, None, draft=False, heavy=True)
    assert full_sel["wasm_release_programs"] == "all"
    assert full_sel["wasi_artifacts"] == "true"


def test_wasi_artifacts_produced_once_and_decoupled_from_root_cargo(ci_jobs):
    producer = ci_jobs["wasi-artifacts"]
    cache_step = next(
        step for step in producer["steps"] if step.get("name") == "Restore WASI tooling artifacts"
    )
    key = cache_step["with"]["key"]
    assert "Cargo.toml" not in key
    assert "Cargo.lock" not in key
    assert "docs/wasmtime.md" not in key
    assert ".cargo/config.toml" not in key

    for name, job in ci_jobs.items():
        if name == "wasi-artifacts":
            continue
        for step in job.get("steps", []):
            assert "tools/wasi-apps/build.sh" not in step.get("run", ""), name


def test_container_job_bash_steps_declare_shell_bash(ci_jobs):
    # GitHub Actions defaults to `sh` (`dash`) inside `container:` jobs.
    bashisms = re.compile(r"pipefail|\[\[|<<<|<\(|\+=|\bmapfile\b|\bshopt\b|\$\{\w+\[")
    for name, job in ci_jobs.items():
        if "container" not in job:
            continue
        for step in job.get("steps", []):
            run = step.get("run", "")
            if bashisms.search(run):
                assert step.get("shell") == "bash", (name, step.get("name"))


def test_prebuilt_ci_artifacts_and_linux_syscalls_deduplication(ci_jobs):
    # Tier 1 userspace artifacts retain 14 days.
    for name in ("wasm-debug", "wasm-release"):
        upload = next(
            step for step in ci_jobs[name]["steps"] if step.get("uses") == "actions/upload-artifact@v4"
        )
        assert upload["with"]["name"] == "helios-wasm-${{ matrix.profile }}"
        assert int(upload["with"]["retention-days"]) == 14

    # No legacy `helios-guest-*` upload remains and no upload ever includes a secret key.
    for job_name, job in ci_jobs.items():
        for step in job.get("steps", []):
            if step.get("uses") == "actions/upload-artifact@v4":
                artifact_name = step["with"]["name"]
                assert not artifact_name.startswith("helios-guest-"), (job_name, artifact_name)
                assert "helios-root-secret.key" not in str(step["with"].get("path", "")), (
                    job_name,
                    artifact_name,
                )

    # Heavy smoke lanes upload 90-day kernel + image artifacts.
    for job_name, arch in (
        ("smoke-riscv64", "riscv64"),
        ("smoke-aarch64", "aarch64"),
        ("smoke-x86-64", "x86-64"),
    ):
        uploads = {
            step["with"]["name"]: int(step["with"]["retention-days"])
            for step in ci_jobs[job_name]["steps"]
            if step.get("uses") == "actions/upload-artifact@v4"
        }
        assert uploads[f"helios-kernel-{arch}-release"] == 90
        assert uploads[f"helios-image-{arch}-release"] == 90

    # Other kernel-building smoke lanes upload 14-day kernel + image artifacts without colliding.
    cpu_stage = next(
        step for step in ci_jobs["smoke-x86-64-cpu-lifecycle"]["steps"] if step.get("id") == "stage-prebuilt"
    )
    assert "!contains(fromJSON(needs.changes.outputs.lanes), 'smoke-x86-64')" in cpu_stage["if"]
    venus_uploads = {
        step["with"]["name"]: int(step["with"]["retention-days"])
        for step in ci_jobs["smoke-x86-64-venus"]["steps"]
        if step.get("uses") == "actions/upload-artifact@v4"
    }
    assert venus_uploads["helios-kernel-x86-64-debug"] == 14
    assert venus_uploads["helios-image-x86-64-debug"] == 14
    cfi_uploads = {
        step["with"]["name"]: int(step["with"]["retention-days"])
        for step in ci_jobs["smoke-aarch64-cfi"]["steps"]
        if step.get("uses") == "actions/upload-artifact@v4"
    }
    assert cfi_uploads["helios-kernel-aarch64-debug-cfi"] == 14
    assert cfi_uploads["helios-image-aarch64-debug-cfi"] == 14

    # `linux-syscalls-image-*` builds once per arch using `wasm-debug` (`--guest-programs-profile debug`)
    # and shards boot the prebuilt image directly with zero local Rust/Limine compilation.
    for image_job_name, shard_job_name in (
        ("linux-syscalls-image-x86-64", "linux-syscalls-x86-64"),
        ("linux-syscalls-image-aarch64", "linux-syscalls-aarch64"),
    ):
        image_job = ci_jobs[image_job_name]
        assert "wasm-debug" in image_job["needs"]
        assert "wasm-release" not in image_job["needs"]
        build_step = next(
            step for step in image_job["steps"] if step.get("name") == "Build the Linux guest image"
        )
        assert "--guest-programs-profile debug" in build_step["run"]

        shard_job = ci_jobs[shard_job_name]
        assert image_job_name in shard_job["needs"]
        for step in shard_job["steps"]:
            run = step.get("run", "")
            assert "cargo build" not in run, (shard_job_name, step.get("name"))
            assert "profile-fetch" not in run, (shard_job_name, step.get("name"))
            assert "limine-binary" not in run, (shard_job_name, step.get("name"))
        helios_step = next(
            step for step in shard_job["steps"] if step.get("name") == "Run the shard on Helios"
        )
        assert "--prebuilt image --prebuilt-dir" in helios_step["run"]


def test_workflows_target_single_main_branch():
    workflows_dir = REPO_ROOT / ".github/workflows"
    assert not (workflows_dir / "pr-base-gate.yml").exists()
    for name in ("ci.yml", "ci-image.yml", "bench-suite.yml"):
        workflow = yaml.load((workflows_dir / name).read_text(), Loader=yaml.BaseLoader)
        assert workflow["on"]["push"]["branches"] == ["main"], name
    release = yaml.load((workflows_dir / "release.yml").read_text(), Loader=yaml.BaseLoader)
    assert "push" not in release["on"]
    assert release["on"]["workflow_run"]["branches"] == ["main"]
    assert release["on"]["workflow_run"]["workflows"] == ["CI"]
    assert "refs/heads/dev" not in (workflows_dir / "ci.yml").read_text()
    assert "refs/heads/dev" not in (workflows_dir / "ci-image.yml").read_text()
    assert "'dev'" not in (workflows_dir / "bench-lane.yml").read_text()
    assert "origin/dev" not in (workflows_dir / "bench-suite.yml").read_text()
    assert "--branch dev" not in (workflows_dir / "bench-suite.yml").read_text()


def test_prebuilt_wasm_action_downloads_via_rest_and_retries_transient_lag(tmp_path):
    action_path = REPO_ROOT / ".github/actions/prebuilt-wasm/action.yml"
    action = yaml.load(action_path.read_text(), Loader=yaml.BaseLoader)
    steps = action["runs"]["steps"]
    assert all(step.get("uses") != "actions/download-artifact@v4" for step in steps)
    script = steps[0]["run"]

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    sleep_shim = bin_dir / "sleep"
    sleep_shim.write_text("#!/bin/sh\nexit 0\n")
    sleep_shim.chmod(0o755)

    # Case 1: REST listing reports the artifact while the first download fails
    # transiently, then succeeds on retry.
    state_file = tmp_path / "download_attempts"
    gh_retry = bin_dir / "gh"
    gh_retry.write_text(
        "#!/usr/bin/env python3\n"
        "import os, pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "if args[:2] == ['api', '--paginate']:\n"
        "    endpoint = args[2]\n"
        "    if endpoint.endswith('/artifacts'):\n"
        "        print('14894939174')\n"
        "    elif endpoint.endswith('/jobs'):\n"
        "        print('completed success')\n"
        "    sys.exit(0)\n"
        "if args[:2] == ['run', 'download']:\n"
        "    counter = pathlib.Path(os.environ['STATE_FILE'])\n"
        "    attempt = int(counter.read_text()) + 1 if counter.exists() else 1\n"
        "    counter.write_text(str(attempt))\n"
        "    if attempt == 1:\n"
        "        sys.stderr.write('artifact not ready yet\\n')\n"
        "        sys.exit(1)\n"
        "    dest = pathlib.Path(args[args.index('--dir') + 1])\n"
        "    (dest / 'helios_debugger.wasm').write_bytes(b'wasm')\n"
        "    sys.exit(0)\n"
        "sys.exit(2)\n"
    )
    gh_retry.chmod(0o755)

    dest = tmp_path / "out/wasm-programs/debug"
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "STATE_FILE": str(state_file),
        "GITHUB_REPOSITORY": "lexoliu/helios",
        "GITHUB_RUN_ID": "45338743742",
        "GITHUB_RUN_ATTEMPT": "1",
        "PROFILE": "debug",
        "DEST": str(dest),
        "TIMEOUT_SECONDS": "60",
    }
    res = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    assert (dest / "helios_debugger.wasm").read_bytes() == b"wasm"
    assert int(state_file.read_text()) == 2

    # Case 2: producer job fails without uploading -> fails fast.
    gh_fail = bin_dir / "gh"
    gh_fail.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "args = sys.argv[1:]\n"
        "if args[:2] == ['api', '--paginate'] and args[2].endswith('/jobs'):\n"
        "    print('completed failure')\n"
        "sys.exit(0)\n"
    )
    gh_fail.chmod(0o755)

    res_fail = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    assert res_fail.returncode != 0
    assert "::error::" in res_fail.stdout
    assert "concluded 'failure'" in res_fail.stdout


def test_btrfs_fuzz_installs_toolchain_before_running_fuzz():
    workflow = yaml.load(
        (REPO_ROOT / ".github/workflows/ci.yml").read_text(),
        Loader=yaml.BaseLoader,
    )
    steps = workflow["jobs"]["test-btrfs-fuzz"]["steps"]
    install_idx = next(
        (i for i, step in enumerate(steps) if "rustup toolchain install" in step.get("run", "")),
        None,
    )
    fuzz_idx = next(
        (i for i, step in enumerate(steps) if "tools/btrfs/run.py fuzz" in step.get("run", "")),
        None,
    )
    assert install_idx is not None, "test-btrfs-fuzz must install the pinned Rust toolchain"
    assert fuzz_idx is not None
    assert install_idx < fuzz_idx
