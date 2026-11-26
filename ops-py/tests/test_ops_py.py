"""End-to-end pytest suite for ``helios-ops-py`` (PyO3 extension + ``helios._cli_entry``)."""

from __future__ import annotations

import ast
import asyncio
import os
import sys
import types
from pathlib import Path
from typing import Any

import helios
import pytest
from helios import _cli_entry
from mock_guest import MockHeliosGuest


def test_exports_stubs_and_exception_hierarchy() -> None:
    expected = {
        "AttenuationDeniedError",
        "BtrfsClient",
        "ByteStream",
        "ComponentStatus",
        "ComponentsClient",
        "Container",
        "DefaultLinuxImage",
        "DiagnosticBundle",
        "Fleet",
        "FleetComponents",
        "FleetOci",
        "Grants",
        "HeliosError",
        "HvVm",
        "InspectNode",
        "InstructionProfile",
        "LinuxClient",
        "MicroVm",
        "MountInfo",
        "MountSpec",
        "MountsClient",
        "NodeOutcome",
        "OciClient",
        "PulledImage",
        "RpcError",
        "SamplingSession",
        "Session",
        "SubvolumeInfo",
        "Target",
        "TargetError",
        "TargetStore",
        "TransportError",
        "VmClient",
        "VmDisk",
        "VmShare",
        "connect",
        "fleet",
        "inspect_tree",
    }
    assert expected.issubset(set(helios.__all__))

    assert issubclass(helios.AttenuationDeniedError, helios.HeliosError)
    assert issubclass(helios.TransportError, helios.HeliosError)
    assert issubclass(helios.RpcError, helios.HeliosError)
    assert issubclass(helios.TargetError, helios.HeliosError)

    pkg_dir = Path(helios.__file__).resolve().parent
    assert (pkg_dir / "py.typed").is_file()
    assert (pkg_dir / "__main__.py").is_file()
    stub_path = pkg_dir / "_native.pyi"
    assert stub_path.is_file()
    ast.parse(stub_path.read_text(encoding="utf-8"))


def test_typed_builders_validation() -> None:
    grants = helios.Grants(
        directories={"/tmp": "rw", "/etc": "r", "/var/log": "rx"},
        net=["tcp", "dns"],
        clock=["set-wall-clock"],
        terminal=["input", "output"],
        process=["spawn", "exec"],
        mount=["mount", "unmount"],
        device=["gpu"],
        machine=["virtualize"],
        diagnostics=["inspect:subtree", "trace:own", "profile:machine", "diagnostics:control"],
        instance_control="subtree",
        settings=True,
    )
    assert len(grants.specs) >= 12
    assert "dir:/tmp:rw" in grants.specs
    assert "dir:/var/log:rx" in grants.specs
    assert "machine:virtualize" in grants.specs

    with pytest.raises(ValueError):
        helios.Grants(directories={"relative/path": "rw"})

    mount = helios.MountSpec(
        "/var/lib/data",
        "/data",
        mode="rw",
        sharing="shared",
    )
    assert mount.source == "/var/lib/data"
    assert mount.target == "/data"
    assert mount.mode == "rw"
    assert mount.sharing == "shared"

    with pytest.raises(ValueError):
        helios.MountSpec("/a", "/b", sharing="bogus")

    disk = helios.VmDisk("/images/root.img", writable=False)
    assert disk.path == "/images/root.img"
    assert disk.writable is False

    share = helios.VmShare("/var/lib/rootfs", tag="rootfs", writable=True)
    assert share.tag == "rootfs"
    assert share.path == "/var/lib/rootfs"
    assert share.writable is True


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

        # Inspect, InspectNode dynamic __dir__ & kernel_snapshot
        snap = await session.inspect(["/kernel/"])
        assert len(snap) >= 5
        snap_dict = snap.to_dict()
        assert snap_dict["/kernel/processors/online"] == 4
        assert snap_dict["/core/http-client/status"] == "healthy"
        assert snap.publications[0].instance_name == "http-client"
        assert snap.publications[0].status == "ok"

        tree = snap.tree()
        assert isinstance(tree, helios.InspectNode)
        assert "kernel" in dir(tree)
        assert "core" in dir(tree)
        assert "http_client" in dir(tree.core)
        assert tree.core.http_client.status == "healthy"
        assert tree.core.http_client.requests_total == 42
        assert tree["/kernel/processors/online"] == 4
        assert "http-client" in repr(tree.core)

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

        # exec & spawn with cwd, argv list, Grants, async context manager, AsyncIterator, write_stdin
        exec_res = await session.exec(["/bin/ping", "-c", "1"], cwd="/tmp")
        assert exec_res.exit_code == 0
        assert exec_res.stdout_text == "exec ok\n"
        assert guest.exec_calls[-1] == ("/bin/ping", ["-c", "1"], "/tmp")

        cjk_stdin = "你好世界 こんにちは 세계\n".encode()
        async with await session.spawn(
            "/bin/ping",
            ["-c", "2"],
            cwd="/tmp",
            env={"MODE": "test"},
            grants=helios.Grants(directories={"/tmp": "rw"}, net=["tcp", "dns"]),
        ) as child:
            assert child.instance_id == 99
            await child.write_stdin(cjk_stdin)
            await child.close_stdin()
            await child.signal("TERM")
            assert (99, 15) in guest.signals_sent
            out_chunks = [chunk async for chunk in child.stdout]
            err_chunks = [chunk async for chunk in child.stderr]
            spawn_res = await child.wait()
            assert b"".join(out_chunks) == b"spawned ok\n"
            assert b"".join(err_chunks) == b"warn line\n"
            assert spawn_res.instance_id == 99
            assert spawn_res.exit_code == 0

        assert cjk_stdin in guest.child_stdin_received.values()
        assert guest.spawn_calls[-1] == ("/bin/ping", ["-c", "2"], "/tmp")

        with pytest.raises(helios.HeliosError):
            await session.spawn("/bin/ping", grants=["unknown:bad"])

        # Components client
        comps = await session.components.list()
        assert [c.moniker for c in comps] == ["/core/http-client", "/core/logger"]
        started = await session.components.start("/core/logger")
        assert started.state == "running"
        restarted = await session.components.restart("/core/http-client")
        assert restarted.restarts == 1
        await session.components.stop("/core/logger")
        status = await session.components.status("/core/logger")
        assert status.state == "stopped"
        mounted_dir = await session.components.mount_dynamic(
            "/core", guest_dir="/data/edge", subtree_name="edge"
        )
        assert mounted_dir == "/core/edge"
        mounted_inline = await session.components.mount_dynamic(
            "/core", manifests={"helper/component.toml": 'program = "/bin/helper"\n'}
        )
        assert mounted_inline == "/core/helper"
        await session.components.unmount_dynamic(mounted_dir)
        await session.components.unmount_dynamic(mounted_inline)

        # OCI client (list, inspect, remove against seeded guest store)
        images = await session.oci.list()
        assert len(images) == 1
        assert images[0].reference.endswith("library/alpine:latest")
        inspected = await session.oci.inspect("alpine:latest")
        assert inspected.btrfs_backed is True
        assert inspected.working_dir == "/app"
        removed_img = await session.oci.remove("alpine:latest")
        assert removed_img.reference.endswith("library/alpine:latest")
        assert await session.oci.list() == []

        # Linux client: default_image & container AsyncContextManager
        assert await session.linux.default_image() is None
        await session.linux.set_default_image(
            "/var/lib/rootfs",
            env={"LANG": "C.UTF-8"},
            uid=1000,
            gid=1000,
            supplementary_groups=[27],
        )
        default_img = await session.linux.default_image()
        assert default_img is not None
        assert default_img.root_path == "/var/lib/rootfs"
        assert default_img.uid == 1000
        assert default_img.supplementary_groups == [27]

        async with await session.linux.container(
            "/var/lib/rootfs",
            mounts=[helios.MountSpec("/data", "/mnt/data", mode="rw", sharing="shared")],
            hostname="worker-1",
            grants=helios.Grants(net=["tcp", "dns"]),
            uid=1000,
            gid=1000,
        ) as container:
            cex = await container.exec(["/bin/sh", "-c", "echo hi"], cwd="/mnt/data")
            assert cex.stdout_text == "container exec ok\n"
            async with await container.spawn(["/bin/sh"], cwd="/mnt/data") as cchild:
                cout = [chunk async for chunk in cchild.stdout]
                assert b"".join(cout) == b"container child out\n"
                cres = await cchild.wait()
                assert cres.exit_code == 0

        await session.linux.set_default_image(None)
        assert await session.linux.default_image() is None

        # Mounts & Btrfs clients
        mounts_before = await session.mounts.list()
        assert any(m.path == "/data" and m.source == "btrfs:disk0" for m in mounts_before)
        await session.mounts.mount("memory", "/mnt/scratch", sharing="private")
        mounts_after = await session.mounts.list()
        assert any(m.path == "/mnt/scratch" for m in mounts_after)
        await session.mounts.unmount("/mnt/scratch")

        sub = await session.btrfs.create_subvolume("/data/app")
        assert sub.path == "app"
        snap_sub = await session.btrfs.snapshot_subvolume("/data/app", "/data/app-ro", read_only=True)
        assert snap_sub.read_only is True
        await session.btrfs.set_subvolume_read_only("/data/app-ro", False)
        sub_info = await session.btrfs.subvolume_info("/data/app-ro")
        assert sub_info.read_only is False
        subvols = await session.btrfs.list_subvolumes("/data")
        assert len(subvols) >= 3
        stream = await session.btrfs.send_subvolume("/data/app-ro")
        assert stream.startswith(b"btrfs-stream")
        recv = await session.btrfs.receive_subvolume("/data", stream)
        assert recv.read_only is True
        await session.btrfs.reflink("/data/a", 0, "/data/b", 0, 4096)
        dedupe = await session.btrfs.dedupe("/data/a", 0, "/data/b", 0, 4096)
        assert dedupe.same is True
        assert dedupe.bytes_deduped == 4096
        devs = await session.btrfs.list_devices("/data")
        assert devs[0].serial == "disk0"
        added_dev = await session.btrfs.add_device("/data", "disk1")
        assert added_dev.serial == "disk1"
        bal = await session.btrfs.balance("/data", data=True, metadata=True)
        assert bal.relocated == 2
        scrub = await session.btrfs.scrub("/data")
        assert scrub.csum_errors == 0
        await session.btrfs.quota_enable("/data")
        qstatus = await session.btrfs.quota_status("/data")
        assert qstatus.enabled is True
        await session.btrfs.qgroup_create("/data", 1, 100)
        qgroups = await session.btrfs.qgroup_list("/data")
        assert any(q.level == 1 and q.id == 100 for q in qgroups)
        await session.btrfs.qgroup_destroy("/data", 1, 100)
        await session.btrfs.delete_subvolume("/data/app-ro")

        # MicroVm client
        hv_vms = await session.vm.list()
        assert len(hv_vms) == 1
        assert hv_vms[0].vcpus == 2
        async with await session.vm.spawn(
            kernel="/boot/vmlinux",
            memory_mib=256,
            cpus=2,
            cmdline="console=ttyS0",
            disks=[helios.VmDisk("/data/root.img", writable=False)],
            shares=[helios.VmShare("/data", tag="work", writable=True)],
        ) as vm:
            assert vm.instance_id == 200
            console_chunks = [chunk async for chunk in vm.console]
            assert b"".join(console_chunks) == b"guest linux booted\n"
            await vm.write_console(b"poweroff\n")
            vm_res = await vm.wait()
            assert vm_res.exit_code == 0

        # Standalone SamplingSession RAII guard
        async with await session.start_instruction_sampling() as prof:
            raw_prof = await prof.samples()
            assert raw_prof.period_nanos == 1_000_000
            assert raw_prof.dropped == 1
            assert raw_prof.unique_pcs == 2
            assert raw_prof.total_samples == 17
        await asyncio.sleep(0.05)
        assert guest.sampling_starts == 1
        assert guest.sampling_drops >= 1

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


async def test_fleet_components_oci_and_labels(tmp_path: Path) -> None:
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

        # Fleet components fan-out
        comp_list = await fl.components.list()
        assert all(o.ok and len(o.unwrap()) == 2 for o in comp_list)
        comp_restart = await fl.components.restart("/core/http-client")
        assert all(o.ok and o.unwrap().restarts == 1 for o in comp_restart)
        comp_mounted = await fl.components.mount_dynamic("/core", guest_dir="/data/fleet-edge")
        assert all(o.ok and o.unwrap() == "/core/fleet-edge" for o in comp_mounted)
        comp_unmounted = await fl.components.unmount_dynamic("/core/fleet-edge")
        assert all(o.ok for o in comp_unmounted)

        # Fleet OCI fan-out
        oci_list = await fl.oci.list()
        assert all(o.ok and len(o.unwrap()) == 1 for o in oci_list)
        oci_rm = await fl.oci.remove("alpine:latest")
        assert all(o.ok and o.unwrap().reference.endswith("library/alpine:latest") for o in oci_rm)


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


async def test_cli_entry_main_module_repl_alias_and_teardown(tmp_path: Path) -> None:
    async with MockHeliosGuest() as guest:
        env = dict(os.environ)
        env["HELIOS_TARGET"] = guest.uri
        env["HELIOS_CONCURRENCY"] = "4"

        # 1. `python -m helios -c ...` using `s` REPL alias and InspectNode
        rc, out, err = await _run_subproc(
            [
                sys.executable,
                "-m",
                "helios",
                "-c",
                "assert s is session; procs = await s.ps(); comps = await s.components.list(); "
                "tree = (await s.inspect()).tree(); "
                "print(len(procs), len(comps), tree.core.http_client.status)",
            ],
            env=env,
        )
        assert rc == 0, err
        assert out.strip() == "2 2 healthy"

        # 2. Script file with positional arguments
        script = tmp_path / "check_node.py"
        script.write_text(
            "import sys\n"
            "snap = await inspect(['/core/http-client'])\n"
            "print(sys.argv[1], snap.to_dict()['/core/http-client/requests-total'])\n",
            encoding="utf-8",
        )
        rc, out, err = await _run_subproc(
            [sys.executable, "-m", "helios", str(script), "ok-arg"],
            env=env,
        )
        assert rc == 0, err
        assert out.strip() == "ok-arg 42"

        # 3. Interactive REPL over piped stdin using `s` alias & top-level await
        repl_input = (
            "async def count_comps():\n"
            "    return len(await s.components.list())\n"
            "\n"
            "n = await count_comps()\n"
            "print('repl-comps:', n)\n"
        )
        rc, out, err = await _run_subproc(
            [sys.executable, "-m", "helios"],
            env=env,
            stdin_text=repl_input,
        )
        assert rc == 0, err
        assert "repl-comps: 2" in out

        # 4. Attenuation via HELIOS_SCOPE + HELIOS_ONLY
        env_scoped = dict(env)
        env_scoped["HELIOS_SCOPE"] = "/core/http-client"
        env_scoped["HELIOS_ONLY"] = "inspect"
        rc, _out, err = await _run_subproc(
            [
                sys.executable,
                "-m",
                "helios",
                "-c",
                "await inspect(['/kernel/'])",
            ],
            env=env_scoped,
        )
        assert rc != 0
        assert "attenuation" in err.lower()

        # 5. Resolve default target from targets.toml when HELIOS_TARGET is unset
        store_path = tmp_path / "targets.toml"
        store = helios.TargetStore.load(str(store_path))
        store.upsert(helios.Target("local", guest.uri))
        store.set_default("local")
        store.save()

        env_default = dict(os.environ)
        env_default.pop("HELIOS_TARGET", None)
        env_default["HELIOS_TARGETS_PATH"] = str(store_path)
        rc, out, err = await _run_subproc(
            [
                sys.executable,
                "-m",
                "helios",
                "-c",
                "print(len(await ps()))",
            ],
            env=env_default,
        )
        assert rc == 0, err
        assert out.strip() == "2"


def test_cli_entry_ipython_autoawait_and_session_teardown(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class FakeInteractiveShellEmbed:
        def __init__(self, *, config: Any, user_ns: dict[str, Any], banner1: str) -> None:
            captured["config"] = config
            captured["user_ns"] = user_ns
            captured["banner1"] = banner1

        def __call__(self) -> None:
            captured["called"] = True

    class FakeConfig:
        def __init__(self) -> None:
            self.InteractiveShell = types.SimpleNamespace()
            self.TerminalInteractiveShell = types.SimpleNamespace()

    fake_embed_mod = types.ModuleType("IPython.terminal.embed")
    fake_embed_mod.InteractiveShellEmbed = FakeInteractiveShellEmbed  # type: ignore[attr-defined]
    fake_traitlets_mod = types.ModuleType("traitlets.config")
    fake_traitlets_mod.Config = FakeConfig  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "IPython.terminal.embed", fake_embed_mod)
    monkeypatch.setitem(sys.modules, "traitlets.config", fake_traitlets_mod)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)

    closed = False

    class FakeSession:
        async def __aexit__(self, *_args: Any) -> None:
            nonlocal closed
            closed = True

    fake_session = FakeSession()
    ns: dict[str, Any] = {"s": fake_session, "session": fake_session}
    assert _cli_entry._try_run_ipython(ns, "banner") == 0
    assert captured["config"].InteractiveShell.autoawait is True
    assert captured["config"].InteractiveShell.loop_runner == "asyncio"
    assert captured["config"].TerminalInteractiveShell.confirm_exit is False
    assert captured["user_ns"]["s"] is fake_session
    assert captured["called"] is True

    asyncio.run(_cli_entry._close_context(fake_session, None))  # type: ignore[arg-type]
    assert closed is True
