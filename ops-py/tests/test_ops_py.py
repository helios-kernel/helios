"""End-to-end pytest suite for ``helios-ops-py`` (PyO3 extension + ``helios._cli_entry``)."""

from __future__ import annotations

import ast
import asyncio
import os
import sys
from pathlib import Path

import helios
import pytest
from mock_guest import MockHeliosGuest


def test_exports_stubs_and_exception_hierarchy() -> None:
    expected = {
        "AttenuationDeniedError",
        "DiagnosticBundle",
        "Fleet",
        "HeliosError",
        "NodeOutcome",
        "RpcError",
        "Session",
        "Target",
        "TargetError",
        "TargetStore",
        "TransportError",
        "connect",
        "fleet",
    }
    assert expected.issubset(set(helios.__all__))

    assert issubclass(helios.AttenuationDeniedError, helios.HeliosError)
    assert issubclass(helios.TransportError, helios.HeliosError)
    assert issubclass(helios.RpcError, helios.HeliosError)
    assert issubclass(helios.TargetError, helios.HeliosError)

    pkg_dir = Path(helios.__file__).resolve().parent
    assert (pkg_dir / "py.typed").is_file()
    stub_path = pkg_dir / "_native.pyi"
    assert stub_path.is_file()
    ast.parse(stub_path.read_text(encoding="utf-8"))


def test_target_uri_parsing_and_store_round_trip(tmp_path: Path) -> None:
    t_tcp = helios.Target("dev-1", "tcp://127.0.0.1:9443", labels={"env": "dev", "arch": "x86_64"})
    assert t_tcp.name == "dev-1"
    assert t_tcp.uri == "tcp://127.0.0.1:9443"
    assert t_tcp.scheme == "tcp"
    assert t_tcp.matches_labels(["env=dev", "arch=x86_64"])
    assert not t_tcp.matches_labels(["env=prod"])

    t_helios = helios.Target.from_uri("helios://node-a.internal")
    assert t_helios.scheme == "helios"
    assert t_helios.uri == "helios://node-a.internal:9443"

    t_serial = helios.Target.from_uri("serial:///tmp/vm.sock?baud=115200")
    assert t_serial.scheme == "serial"

    t_vsock = helios.Target.from_uri("vsock://42:9000")
    assert t_vsock.scheme == "vsock"

    with pytest.raises(helios.TargetError):
        helios.Target.from_uri("http://unsupported.example")

    store_path = tmp_path / "targets.toml"
    store = helios.TargetStore.load(str(store_path))
    store.upsert(t_tcp)
    store.upsert(t_helios)
    store.set_default("dev-1")
    store.save()

    reloaded = helios.TargetStore.load(str(store_path))
    assert reloaded.default_target_name == "dev-1"
    assert reloaded.resolve().uri == "tcp://127.0.0.1:9443"
    matched = reloaded.select_by_labels(["env=dev"])
    assert [t.name for t in matched] == ["dev-1"]


async def test_helios_tls_uri_fails_fast_instead_of_cleartext() -> None:
    with pytest.raises(helios.TransportError):
        await helios.connect("helios://127.0.0.1:9443")


async def test_live_session_all_operations_and_attenuation(tmp_path: Path) -> None:
    async with MockHeliosGuest() as guest, helios.connect(guest.uri) as session:
        assert session.scope == "/"
        assert session.target.uri == guest.uri

        # Inspect & kernel_snapshot
        snap = await session.inspect(["/kernel/"])
        assert len(snap) >= 5
        snap_dict = snap.to_dict()
        assert snap_dict["/kernel/processors/online"] == 4
        assert snap_dict["/core/http-client/status"] == "healthy"
        assert snap.publications[0].instance_name == "http-client"
        assert snap.publications[0].status == "ok"

        ksnap = await session.kernel_snapshot()
        assert ksnap["processors"]["online"] == 4
        assert ksnap["memory"]["total_bytes"] == 2 * 1024 * 1024 * 1024

        # ps & kill
        procs = await session.ps()
        assert [p.id for p in procs] == [1, 7]
        killed = await session.kill(7)
        assert killed == 7
        assert guest.killed_ids == [7]

        # tracing
        events = await session.trace_recent(limit=16, min_level="info")
        assert len(events) == 1
        assert events[0].level == "info"
        assert events[0].target == "helios_kernel::net::tcp"
        assert events[0].fields["message"] == "link up"
        await session.set_trace_target_enabled("helios_kernel::net::tcp", True)

        # exec & spawn (with capability grants)
        exec_res = await session.exec("/bin/ping", ["-c", "1"])
        assert exec_res.exit_code == 0
        assert exec_res.stdout_text == "exec ok\n"

        child = await session.spawn(
            "/bin/ping",
            ["-c", "2"],
            env={"MODE": "test"},
            stdin=b"input",
            grants=["dir:/tmp:rw", "net:tcp,dns"],
        )
        out_chunk = await child.read_stdout()
        err_chunk = await child.read_stderr()
        spawn_res = await child.wait()
        assert out_chunk == b"spawned ok\n"
        assert err_chunk == b"warn line\n"
        assert spawn_res.instance_id == 99
        assert spawn_res.exit_code == 0

        with pytest.raises(helios.HeliosError):
            await session.spawn("/bin/ping", grants=["unknown:bad"])

        # Remote VFS
        root_entries = await session.list_dir("/")
        assert {e.name for e in root_entries} >= {"bin", "etc", "tmp"}
        rc = await session.read_file("/etc/rc.nu")
        assert rc == b"echo hello from mock guest\n"
        await session.write_file("/tmp/hello.txt", b"hello ")
        await session.write_file("/tmp/hello.txt", b"helios", append=True)
        assert await session.read_file("/tmp/hello.txt") == b"hello helios"
        st = await session.stat("/tmp/hello.txt")
        assert st.kind == "file"
        assert st.size == len(b"hello helios")

        # Diagnostic bundle (.tar.zst)
        bundle_out = tmp_path / "diag.tar.zst"
        bundle = await session.bundle(str(bundle_out))
        assert bundle_out.is_file()
        assert bundle_out.stat().st_size > 0
        assert "inspect.json" in bundle.manifest.entries

        # Monotonic attenuation
        scoped = session.attenuated(scope="/core/http-client", only=["inspect", "ps"])
        assert scoped.scope == "/core/http-client"
        scoped_snap = await scoped.inspect()
        assert set(scoped_snap.to_dict().keys()) == {
            "/core/http-client/requests-total",
            "/core/http-client/status",
        }
        scoped_procs = await scoped.ps()
        assert [p.name for p in scoped_procs] == ["/core/http-client"]

        with pytest.raises(helios.AttenuationDeniedError):
            await scoped.inspect(["/kernel/"])
        with pytest.raises(helios.AttenuationDeniedError):
            await scoped.inspect(["/core/http-client-admin"])
        with pytest.raises(helios.AttenuationDeniedError):
            scoped.attenuated(scope="/")
        with pytest.raises(helios.AttenuationDeniedError):
            scoped.attenuated(only=["inspect", "kill"])
        with pytest.raises(helios.AttenuationDeniedError):
            await scoped.kill(7)


async def test_fleet_from_targets_and_labels(tmp_path: Path) -> None:
    async with MockHeliosGuest() as g1, MockHeliosGuest() as g2:
        t1 = helios.Target("node-1", g1.uri, labels={"role": "edge"})
        t2 = helios.Target("node-2", g2.uri, labels={"role": "edge"})
        store_path = tmp_path / "targets.toml"
        store = helios.TargetStore.load(str(store_path))
        store.upsert(t1)
        store.upsert(t2)
        store.save()

        fl = helios.Fleet.from_labels(["role=edge"], concurrency=2, targets_path=str(store_path))
        assert fl.concurrency == 2
        assert [t.name for t in fl.targets] == ["node-1", "node-2"]

        ps_outcomes = await fl.ps()
        assert len(ps_outcomes) == 2
        assert all(o.ok for o in ps_outcomes)
        assert [len(o.unwrap()) for o in ps_outcomes] == [2, 2]

        inspect_outcomes = await fl.inspect(["/kernel/processors/online"])
        assert all(o.ok for o in inspect_outcomes)
        assert all(o.unwrap().to_dict()["/kernel/processors/online"] == 4 for o in inspect_outcomes)

        exec_outcomes = await fl.exec("/bin/ping", ["-c", "1"])
        assert all(o.ok and o.unwrap().exit_code == 0 for o in exec_outcomes)


async def _run_subproc(
    args: list[str],
    *,
    env: dict[str, str],
    stdin_text: str | None = None,
) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *args,
        env=env,
        stdin=asyncio.subprocess.PIPE if stdin_text is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out_bytes, err_bytes = await proc.communicate(
        stdin_text.encode("utf-8") if stdin_text is not None else None
    )
    return int(proc.returncode or 0), out_bytes.decode("utf-8"), err_bytes.decode("utf-8")


async def test_cli_entry_inline_script_and_repl(tmp_path: Path) -> None:
    async with MockHeliosGuest() as guest:
        env = dict(os.environ)
        env["HELIOS_TARGET"] = guest.uri
        env["HELIOS_CONCURRENCY"] = "4"

        # 1. Inline -c with top-level await
        rc, out, err = await _run_subproc(
            [
                sys.executable,
                "-m",
                "helios._cli_entry",
                "-c",
                "procs = await ps(); print(len(procs), procs[0].name)",
            ],
            env=env,
        )
        assert rc == 0, err
        assert out.strip() == "2 init"

        # 2. Script file with positional arguments
        script = tmp_path / "check_node.py"
        script.write_text(
            "import sys\n"
            "snap = await inspect(['/core/http-client'])\n"
            "print(sys.argv[1], snap.to_dict()['/core/http-client/requests-total'])\n",
            encoding="utf-8",
        )
        rc, out, err = await _run_subproc(
            [sys.executable, "-m", "helios._cli_entry", str(script), "ok-arg"],
            env=env,
        )
        assert rc == 0, err
        assert out.strip() == "ok-arg 42"

        # 3. Interactive REPL over piped stdin with top-level await & multiline block
        repl_input = (
            "async def count_procs():\n"
            "    return len(await ps())\n"
            "\n"
            "n = await count_procs()\n"
            "print('repl-procs:', n)\n"
        )
        rc, out, err = await _run_subproc(
            [sys.executable, "-m", "helios._cli_entry"],
            env=env,
            stdin_text=repl_input,
        )
        assert rc == 0, err
        assert "repl-procs: 2" in out

        # 4. Attenuation via HELIOS_SCOPE + HELIOS_ONLY
        env_scoped = dict(env)
        env_scoped["HELIOS_SCOPE"] = "/core/http-client"
        env_scoped["HELIOS_ONLY"] = "inspect"
        rc, _out, err = await _run_subproc(
            [
                sys.executable,
                "-m",
                "helios._cli_entry",
                "-c",
                "await inspect(['/kernel/'])",
            ],
            env=env_scoped,
        )
        assert rc != 0
        assert "attenuation" in err.lower()
