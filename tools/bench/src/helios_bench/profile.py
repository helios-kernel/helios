"""Collect workload instrumentation with the benchmark's host services."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from helios_bench.manifest import Lane
from helios_bench.wasi_apps import gap_bench, workload_runner


def validate_workloads(log: Path, workloads: list[dict]) -> None:
    expected = {workload["name"] for workload in workloads}
    completed = set()
    with log.open() as records:
        for line in records:
            record = json.loads(line)
            if record["type"] == "failure":
                raise SystemExit(f"profile workload {record['workload']} failed: {record['error']}")
            if record["type"] == "summary":
                name = record["workload"]
                if record["validation"]["ok"] is not True:
                    raise SystemExit(f"profile workload {name} failed validation")
                if name not in expected or name in completed:
                    raise SystemExit(f"unexpected or repeated profile workload: {name}")
                completed.add(name)
    if missing := expected - completed:
        raise SystemExit(f"profile workloads have no successful summary: {sorted(missing)}")


def collect_workloads(
    lane: Lane,
    checkout: Path,
    output: Path,
    ifname: str,
    bridge: str,
    queues: int,
    timeout_seconds: int,
) -> None:
    driver = gap_bench()
    manifest = checkout / "tools/wasi-apps/workloads.json"
    workloads = workload_runner().load_manifest(manifest)["workloads"]
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="profile-http-", dir=output.parent) as directory:
        http_root = Path(directory)
        driver.write_http_payloads(http_root)
        services = driver.HostServices(
            http_root=http_root,
            http_host=lane.net_host,
            tcp_host=lane.net_host,
            http=any(workload.get("requires_host_http", False) for workload in workloads),
            tcp=any(workload.get("requires_host_tcp", False) for workload in workloads),
            tcp_echo=any(workload.get("requires_host_tcp_echo", False) for workload in workloads),
        )
        log = output.with_suffix(".jsonl")
        with services.serve() as endpoints, log.open("w") as records:
            command = [
                str(checkout / "target/release/helios-inspector"),
                "vm",
                "--arch",
                lane.helios_arch,
                "--profile-generate",
                "--accel",
                lane.accelerator,
                "--memory",
                lane.memory,
                "--smp",
                str(lane.vcpus),
                "--rpc-transport",
                lane.rpc_transport,
                "--net-backend",
                lane.net_backend,
                "--net-queues",
                str(queues),
                "--net-ifname",
                ifname,
                "--net-bridge",
                bridge,
                "--runtime-dir",
                str(output.parent / "workload-runtime"),
                "--keep-runtime-dir",
                "workload-bench",
                "--manifest",
                str(manifest),
                "--iterations",
                "1",
                "--keep-going",
                "--llvm-raw-profile-output",
                str(output),
            ]
            for flag, value in (
                ("--host-http-url", endpoints.http_url),
                ("--host-tcp-host", endpoints.tcp_host),
                ("--host-tcp-port", endpoints.tcp_port),
                ("--host-tcp-upload-port", endpoints.tcp_upload_port),
                ("--host-tcp-echo-port", endpoints.tcp_echo_port),
            ):
                if value is not None:
                    command.extend([flag, str(value)])
            driver.run_isolated(command, cwd=checkout, timeout_seconds=timeout_seconds, stdout=records)
    validate_workloads(log, workloads)
