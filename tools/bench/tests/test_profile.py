import json
import socket
from pathlib import Path
from urllib.request import urlopen

import pytest

from helios_bench import REPO_ROOT
from helios_bench.manifest import load_manifest
from helios_bench.profile import collect_workloads, validate_workloads
from helios_bench.wasi_apps import gap_bench
from helios_bench.workloads import load_workloads


def test_profile_serves_network_endpoints_and_validates_all_workloads(tmp_path, monkeypatch):
    driver = gap_bench()
    lane = load_manifest().lane("x86-64-kvm").model_copy(update={"net_host": "127.0.0.1"})
    workloads = load_workloads()["workloads"]

    def inspect(command, *, cwd, timeout_seconds, stdout):
        def option(name):
            return command[command.index(name) + 1]

        assert cwd == REPO_ROOT
        assert Path(command[0]) == REPO_ROOT / "target/release/helios"
        assert option("--memory") == lane.memory
        assert int(option("--smp")) == lane.vcpus
        assert option("--rpc-transport") == lane.rpc_transport
        assert timeout_seconds == 60
        with urlopen(option("--host-http-url"), timeout=5) as response:
            assert response.read() == driver.HTTP_PAYLOAD
        host = option("--host-tcp-host")
        for name in ("--host-tcp-port", "--host-tcp-upload-port", "--host-tcp-echo-port"):
            assert int(option(name)) > 0
        with socket.create_connection((host, int(option("--host-tcp-echo-port"))), timeout=5) as stream:
            stream.sendall(b"profile-echo")
            with stream.makefile("rb") as response:
                assert response.read(12) == b"profile-echo"
        for workload in workloads:
            stdout.write(
                json.dumps({"type": "summary", "workload": workload["name"], "validation": {"ok": True}})
                + "\n"
            )

    monkeypatch.setattr(driver, "run_isolated", inspect)
    collect_workloads(lane, REPO_ROOT, tmp_path / "workloads.profraw", "helios0", "helios-br0", 4, 60)


@pytest.mark.parametrize(
    "record",
    [
        {"type": "failure", "workload": "tcp-throughput", "error": "missing endpoint"},
        {"type": "summary", "workload": "tcp-throughput", "validation": {"ok": False}},
    ],
)
def test_profile_rejects_failed_workloads_even_with_successful_process_exit(tmp_path, record):
    log = tmp_path / "workloads.jsonl"
    log.write_text(json.dumps(record) + "\n")
    with pytest.raises(SystemExit, match="failed"):
        validate_workloads(log, [{"name": "tcp-throughput"}])


def test_profile_rejects_missing_network_summary(tmp_path):
    log = tmp_path / "workloads.jsonl"
    log.write_text(
        json.dumps({"type": "summary", "workload": "hostcall-loop", "validation": {"ok": True}}) + "\n"
    )
    with pytest.raises(SystemExit, match="tcp-throughput"):
        validate_workloads(log, [{"name": "hostcall-loop"}, {"name": "tcp-throughput"}])
