"""In-process TCP mock server speaking the real ``helios-wit-rpc`` wire framing."""

from __future__ import annotations

import asyncio
import hashlib
import json
import struct
from typing import Any

FRAME_MAGIC = b"\xff\x00HRPC\xaa\x55"

DIR_CALLER_TO_CALLEE = 0
DIR_CALLEE_TO_CALLER = 1

INSPECT_INSTANCE = "helios:system/inspect@0.1.0"
INSTANCES_INSTANCE = "helios:system/instances@0.1.0"
TRACING_INSTANCE = "helios:system/tracing@0.1.0"
PROFILING_INSTANCE = "helios:system/profiling@0.1.0"
PROGRAMS_INSTANCE = "helios:system/programs@0.1.0"
COMPONENT_CONTROL_INSTANCE = "helios:system/component-control@0.1.0"
MOUNTS_INSTANCE = "helios:system/mounts@0.1.0"
BTRFS_INSTANCE = "helios:system/btrfs@0.1.0"
WASI_PREOPENS_INSTANCE = "wasi:filesystem/preopens@0.3.0"
WASI_FS_TYPES_INSTANCE = "wasi:filesystem/types@0.3.0"

# `wasi:filesystem/types@0.3.0` descriptor-type discriminants
DESC_TYPE_DIRECTORY = 2
DESC_TYPE_REGULAR_FILE = 5

# `wasi:filesystem/types@0.3.0` open-flags bitmask (u32)
OPEN_CREATE = 1 << 0
OPEN_DIRECTORY = 1 << 1
OPEN_TRUNCATE = 1 << 3

# `wasi:filesystem/types@0.3.0` error-code discriminants
ERR_NO_ENTRY = 22
ERR_NOT_DIRECTORY = 24
ERR_IS_DIRECTORY = 14


def enc_u8(v: int) -> bytes:
    return struct.pack("<B", v)


def enc_u16(v: int) -> bytes:
    return struct.pack("<H", v)


def enc_u32(v: int) -> bytes:
    return struct.pack("<I", v)


def enc_u64(v: int) -> bytes:
    return struct.pack("<Q", v)


def enc_str(text: str) -> bytes:
    raw = text.encode("utf-8")
    return enc_u32(len(raw)) + raw


def enc_bytes(data: bytes) -> bytes:
    return enc_u32(len(data)) + data


def enc_opt_u64(val: int | None) -> bytes:
    if val is None:
        return b"\x00"
    return b"\x01" + enc_u64(val)


def enc_opt_str(val: str | None) -> bytes:
    if val is None:
        return b"\x00"
    return b"\x01" + enc_str(val)


def enc_opt_bytes(val: bytes | None) -> bytes:
    if val is None:
        return b"\x00"
    return b"\x01" + enc_bytes(val)


def dec_u8(buf: bytes, offset: int) -> tuple[int, int]:
    return buf[offset], offset + 1


def dec_u16(buf: bytes, offset: int) -> tuple[int, int]:
    (val,) = struct.unpack_from("<H", buf, offset)
    return val, offset + 2


def dec_u32(buf: bytes, offset: int) -> tuple[int, int]:
    (val,) = struct.unpack_from("<I", buf, offset)
    return val, offset + 4


def dec_u64(buf: bytes, offset: int) -> tuple[int, int]:
    (val,) = struct.unpack_from("<Q", buf, offset)
    return val, offset + 8


def dec_str(buf: bytes, offset: int) -> tuple[str, int]:
    length, pos = dec_u32(buf, offset)
    return buf[pos : pos + length].decode("utf-8"), pos + length


def dec_bytes(buf: bytes, offset: int) -> tuple[bytes, int]:
    length, pos = dec_u32(buf, offset)
    return buf[pos : pos + length], pos + length


def dec_opt_str(buf: bytes, offset: int) -> tuple[str | None, int]:
    tag, pos = dec_u8(buf, offset)
    if tag == 0:
        return None, pos
    return dec_str(buf, pos)


def dec_opt_u64(buf: bytes, offset: int) -> tuple[int | None, int]:
    tag, pos = dec_u8(buf, offset)
    if tag == 0:
        return None, pos
    return dec_u64(buf, pos)


def _encode_frame(payload: bytes) -> bytes:
    return FRAME_MAGIC + struct.pack("<I", len(payload)) + payload


def encode_accept(invocation: int) -> bytes:
    return _encode_frame(bytes([1]) + struct.pack("<I", invocation))


def encode_data(invocation: int, path: list[int], payload: bytes) -> bytes:
    body = bytearray([3])
    body += struct.pack("<II", invocation, len(path))
    for p in path:
        body += struct.pack("<I", p)
    body += struct.pack("<I", len(payload))
    body += payload
    return _encode_frame(bytes(body))


def encode_close(invocation: int, path: list[int]) -> bytes:
    body = bytearray([4])
    body += struct.pack("<II", invocation, len(path))
    for p in path:
        body += struct.pack("<I", p)
    return _encode_frame(bytes(body))


def encode_credit(invocation: int, path: list[int], credits: int) -> bytes:
    body = bytearray([5])
    body += struct.pack("<II", invocation, len(path))
    for p in path:
        body += struct.pack("<I", p)
    body += struct.pack("<I", credits)
    return _encode_frame(bytes(body))


async def read_frame(reader: asyncio.StreamReader) -> tuple[int, bytes] | None:
    try:
        header = await reader.readexactly(len(FRAME_MAGIC) + 4)
    except asyncio.IncompleteReadError:
        return None
    if header[: len(FRAME_MAGIC)] != FRAME_MAGIC:
        raise ValueError(f"bad frame magic: {header[:8]!r}")
    (length,) = struct.unpack("<I", header[len(FRAME_MAGIC) :])
    payload = await reader.readexactly(length)
    return payload[0], payload[1:]


def _decode_path(body: bytes, pos: int) -> tuple[list[int], int]:
    (path_len,) = struct.unpack_from("<I", body, pos)
    pos += 4
    path = list(struct.unpack_from(f"<{path_len}I", body, pos)) if path_len else []
    pos += 4 * path_len
    return path, pos


def _join_vfs_path(base: str, rel: str) -> str:
    combined = f"{base.rstrip('/')}/{rel.lstrip('/')}" if rel else base
    parts: list[str] = []
    for seg in combined.split("/"):
        if not seg or seg == ".":
            continue
        if seg == "..":
            if parts:
                parts.pop()
        else:
            parts.append(seg)
    return "/" + "/".join(parts)


def _seed_oci_image(reference_canonical: str, repo: str, tag: str, rootfs_path: str) -> tuple[str, bytes]:
    key = hashlib.sha256(reference_canonical.encode("utf-8")).hexdigest()
    manifest_digest = "sha256:" + ("a" * 64)
    layer_chain = "sha256:" + ("b" * 64)
    doc = {
        "reference": {
            "registry": "registry-1.docker.io",
            "repository": repo,
            "selector": {"Tag": tag},
            "insecure_http": False,
        },
        "manifest_digest": manifest_digest,
        "arch": "amd64",
        "config": {
            "architecture": "amd64",
            "os": "linux",
            "config": {
                "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
                "Cmd": ["/bin/sh"],
                "WorkingDir": "/app",
            },
            "rootfs": {
                "type": "layers",
                "diff_ids": [layer_chain],
            },
        },
        "layer_chain_ids": [layer_chain],
        "rootfs_path": rootfs_path,
        "btrfs_backed": True,
    }
    return key, json.dumps(doc).encode("utf-8")


class MockHeliosGuest:
    """Async TCP mock server implementing Helios ``wit-rpc`` inspector endpoints."""

    def __init__(self) -> None:
        alpine_key, alpine_json = _seed_oci_image(
            "registry-1.docker.io/library/alpine:latest",
            "library/alpine",
            "latest",
            "/var/lib/helios/oci/layers/" + ("b" * 64),
        )
        self.files: dict[str, bytes] = {
            "/etc/rc.nu": b"echo hello from mock guest\n",
            "/bin/ping": b"\x00asm",
            "/bin/vmm": b"\x00asm",
            "/boot/vmlinux": b"\x7fELF",
            f"/var/lib/helios/oci/images/{alpine_key}.json": alpine_json,
        }
        self.dirs: set[str] = {
            "/",
            "/bin",
            "/boot",
            "/etc",
            "/tmp",
            "/data",
            "/var",
            "/var/lib",
            "/var/lib/helios",
            "/var/lib/helios/oci",
            "/var/lib/helios/oci/images",
            "/var/lib/helios/oci/layers",
            "/var/lib/helios/oci/layers/" + ("b" * 64),
        }
        self.killed_ids: list[int] = []
        self.signals_sent: list[tuple[int, int]] = []
        self.exec_calls: list[tuple[str, list[str], str | None]] = []
        self.spawn_calls: list[tuple[str, list[str], str | None]] = []
        self.container_exec_calls: list[tuple[str, list[str], str | None]] = []
        self.container_spawn_calls: list[tuple[str, list[str], str | None]] = []
        self.child_stdin_received: dict[int, bytes] = {}
        self.default_image: tuple[str, list[tuple[str, str]], tuple[int, int, list[int]] | None] | None = (
            None
        )
        self.components: dict[str, dict[str, Any]] = {
            "/core/http-client": {
                "moniker": "/core/http-client",
                "program": "/bin/http-client",
                "state": "running",
                "instance_id": 7,
                "restarts": 0,
            },
            "/core/logger": {
                "moniker": "/core/logger",
                "program": "/bin/logger",
                "state": "stopped",
                "instance_id": None,
                "restarts": 1,
            },
        }
        self.mounts: dict[str, dict[str, Any]] = {
            "/data": {
                "path": "/data",
                "source": "btrfs:disk0",
                "read_only": False,
                "sharing": "shared",
            }
        }
        self.subvolumes: dict[str, dict[str, Any]] = {
            "/data/base": {
                "id": 256,
                "parent_id": 5,
                "path": "base",
                "uuid": bytes([0x11] * 16),
                "parent_uuid": None,
                "received_uuid": None,
                "generation": 10,
                "ctransid": 10,
                "otransid": 9,
                "stransid": 0,
                "rtransid": 0,
                "read_only": False,
            }
        }
        self._next_subvol_id = 257
        self.devices: list[dict[str, Any]] = [
            {
                "devid": 1,
                "uuid": bytes([0x22] * 16),
                "total_bytes": 16 * 1024 * 1024 * 1024,
                "bytes_used": 1024 * 1024 * 1024,
                "serial": "disk0",
            }
        ]
        self.quota_enabled = False
        self.qgroups: dict[tuple[int, int], dict[str, Any]] = {
            (0, 256): {
                "level": 0,
                "id": 256,
                "referenced_bytes": 4096,
                "referenced_compressed_bytes": 4096,
                "exclusive_bytes": 4096,
                "exclusive_compressed_bytes": 4096,
                "max_referenced": None,
                "max_exclusive": None,
                "parents": [],
            }
        }
        self.sampling_starts = 0
        self.sampling_drops = 0
        self._sampling_handles: set[int] = set()
        self._children: dict[int, list[Any]] = {}
        self._containers: dict[int, dict[str, Any]] = {}
        self._server: asyncio.AbstractServer | None = None
        self._writers: set[asyncio.StreamWriter] = set()
        self.port: int = 0

    @property
    def uri(self) -> str:
        return f"tcp://127.0.0.1:{self.port}"

    async def start(self) -> MockHeliosGuest:
        self._server = await asyncio.start_server(self._handle_client, "127.0.0.1", 0)
        sock = self._server.sockets[0]
        self.port = int(sock.getsockname()[1])
        return self

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            for writer in list(self._writers):
                writer.close()
            if hasattr(self._server, "close_clients"):
                self._server.close_clients()
            await self._server.wait_closed()
            self._server = None

    async def __aenter__(self) -> MockHeliosGuest:
        return await self.start()

    async def __aexit__(self, *_args: Any) -> None:
        await self.close()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self._writers.add(writer)
        handles: dict[int, tuple[str, bool]] = {1: ("/", True)}
        next_handle = 2
        active: dict[int, tuple[str, str, bytearray]] = {}
        pending_out: dict[tuple[int, int], list[bytes]] = {}
        pending_in: dict[tuple[int, int], tuple[str, Any, int | None, bytearray, int]] = {}
        early_credits: set[tuple[int, int]] = set()

        async def flush_subpath(inv: int, sub_id: int) -> None:
            chunks = pending_out.pop((inv, sub_id), None)
            if chunks is None:
                return
            for chunk in chunks:
                writer.write(encode_data(inv, [DIR_CALLEE_TO_CALLER, sub_id], chunk))
            writer.write(encode_close(inv, [DIR_CALLEE_TO_CALLER, sub_id]))
            await writer.drain()

        def alloc_handle(path: str, is_dir: bool) -> int:
            nonlocal next_handle
            h = next_handle
            next_handle += 1
            handles[h] = (path, is_dir)
            return h

        try:
            while True:
                frame = await read_frame(reader)
                if frame is None:
                    break
                tag, body = frame
                if tag == 0:  # Open
                    (invocation,) = struct.unpack_from("<I", body, 0)
                    pos = 4
                    instance, pos = dec_str(body, pos)
                    func, pos = dec_str(body, pos)
                    active[invocation] = (instance, func, bytearray())
                    writer.write(encode_accept(invocation))
                    await writer.drain()
                elif tag == 3:  # Data
                    (invocation,) = struct.unpack_from("<I", body, 0)
                    path, pos = _decode_path(body, 4)
                    (data_len,) = struct.unpack_from("<I", body, pos)
                    pos += 4
                    chunk = body[pos : pos + data_len]
                    if path == [DIR_CALLER_TO_CALLEE] and invocation in active:
                        active[invocation][2].extend(chunk)
                    elif len(path) == 2 and path[0] == DIR_CALLER_TO_CALLEE:
                        key = (invocation, path[1])
                        if key in pending_in:
                            batch_len, bpos = dec_u32(chunk, 0)
                            payload_bytes = chunk[bpos : bpos + batch_len]
                            pending_in[key][3].extend(payload_bytes)
                            if pending_in[key][0] == "stdin":
                                child_h = pending_in[key][1]
                                self.child_stdin_received[child_h] = (
                                    self.child_stdin_received.get(child_h, b"") + payload_bytes
                                )
                            writer.write(encode_credit(invocation, [DIR_CALLER_TO_CALLEE, path[1]], 8))
                            await writer.drain()
                elif tag == 4:  # Close
                    (invocation,) = struct.unpack_from("<I", body, 0)
                    path, _ = _decode_path(body, 4)
                    if path == [DIR_CALLER_TO_CALLEE] and invocation in active:
                        instance, func, payload = active.pop(invocation)
                        reply, out_subpaths, in_stream = self._dispatch(
                            instance, func, bytes(payload), handles, alloc_handle
                        )
                        writer.write(encode_data(invocation, [DIR_CALLEE_TO_CALLER], reply))
                        writer.write(encode_close(invocation, [DIR_CALLEE_TO_CALLER]))
                        for sub_id, chunks in out_subpaths.items():
                            pending_out[(invocation, sub_id)] = chunks
                            if (invocation, sub_id) in early_credits:
                                early_credits.discard((invocation, sub_id))
                                await flush_subpath(invocation, sub_id)
                        if in_stream is not None:
                            in_sub_id, sink_kind, target_key, offset, done_sub_id = in_stream
                            pending_in[(invocation, in_sub_id)] = (
                                sink_kind,
                                target_key,
                                offset,
                                bytearray(),
                                done_sub_id,
                            )
                            writer.write(encode_credit(invocation, [DIR_CALLER_TO_CALLEE, in_sub_id], 8))
                        await writer.drain()
                    elif len(path) == 2 and path[0] == DIR_CALLER_TO_CALLEE:
                        key = (invocation, path[1])
                        entry = pending_in.pop(key, None)
                        if entry is not None:
                            sink_kind, target_key, offset, data, done_sub_id = entry
                            if sink_kind == "stdin":
                                child_state = self._children.get(target_key)
                                if child_state is not None:
                                    child_state[2].extend(data)
                                self.child_stdin_received[target_key] = bytes(
                                    child_state[2] if child_state is not None else data
                                )
                            elif offset is None:
                                self.files[target_key] = self.files.get(target_key, b"") + bytes(data)
                            else:
                                existing = bytearray(self.files.get(target_key, b""))
                                end = offset + len(data)
                                if len(existing) < end:
                                    existing.extend(b"\x00" * (end - len(existing)))
                                existing[offset:end] = data
                                self.files[target_key] = bytes(existing)
                            pending_out[(invocation, done_sub_id)] = [b"\x00"]
                            if (invocation, done_sub_id) in early_credits:
                                early_credits.discard((invocation, done_sub_id))
                                await flush_subpath(invocation, done_sub_id)
                elif tag == 5:  # Credit
                    (invocation,) = struct.unpack_from("<I", body, 0)
                    path, _ = _decode_path(body, 4)
                    if len(path) == 2 and path[0] == DIR_CALLEE_TO_CALLER:
                        key = (invocation, path[1])
                        if key in pending_out:
                            await flush_subpath(invocation, path[1])
                        else:
                            early_credits.add(key)
                elif tag == 6:  # ResourceDrop
                    (handle,) = struct.unpack_from("<I", body, 0)
                    if handle in self._sampling_handles:
                        self._sampling_handles.discard(handle)
                        self.sampling_drops += 1
                    self._containers.pop(handle, None)
                    if handle != 1:
                        handles.pop(handle, None)
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        finally:
            self._writers.discard(writer)
            writer.close()

    def _dispatch(
        self,
        instance: str,
        func: str,
        payload: bytes,
        handles: dict[int, tuple[str, bool]],
        alloc_handle: Any,
    ) -> tuple[bytes, dict[int, list[bytes]], tuple[int, str, Any, int | None, int] | None]:
        if instance == INSPECT_INSTANCE and func == "snapshot":
            return self._encode_inspect_snapshot(), {}, None
        if instance == INSTANCES_INSTANCE and func == "snapshot":
            return self._encode_instances(), {}, None
        if instance == INSTANCES_INSTANCE and func == "kill":
            inst_id, _ = dec_u64(payload, 0)
            self.killed_ids.append(inst_id)
            return b"\x00", {}, None
        if instance == TRACING_INSTANCE and func == "recent":
            return self._encode_tracing_recent(), {}, None
        if instance == TRACING_INSTANCE and func == "set-target-enabled":
            return b"\x00", {}, None
        if instance == PROFILING_INSTANCE:
            return self._dispatch_profiling(func, alloc_handle)
        if instance == COMPONENT_CONTROL_INSTANCE:
            return self._dispatch_components(func, payload)
        if instance == MOUNTS_INSTANCE:
            return self._dispatch_mounts(func, payload)
        if instance == BTRFS_INSTANCE:
            return self._dispatch_btrfs(func, payload)
        if instance == PROGRAMS_INSTANCE:
            return self._dispatch_programs(func, payload, alloc_handle)
        if instance == WASI_PREOPENS_INSTANCE and func == "get-directories":
            return enc_u32(1) + enc_u32(1) + enc_str("/"), {}, None
        if instance == WASI_FS_TYPES_INSTANCE:
            return self._dispatch_wasi_fs(func, payload, handles, alloc_handle)
        return b"", {}, None

    def _dispatch_profiling(
        self, func: str, alloc_handle: Any
    ) -> tuple[bytes, dict[int, list[bytes]], tuple[int, str, Any, int | None, int] | None]:
        if func in ("metrics", "folded"):
            return b"\x00" + enc_u32(0), {}, None
        if func == "start-instruction-sampling":
            h = alloc_handle("/profiling/sampling", False)
            self._sampling_handles.add(h)
            self.sampling_starts += 1
            return b"\x00" + enc_u32(h), {}, None
        if func == "instruction-samples":
            buf = bytearray(b"\x00")
            buf += enc_u64(1_000_000)  # period_nanos
            buf += enc_u64(0xFFFF_8000_0000_0000)  # kernel_image_base
            buf += enc_u32(2)  # 2 samples
            # Sample 1: Wasm(WasmFunction)
            buf += enc_u8(0)
            buf += enc_str("/bin/http-client")
            buf += enc_u32(0)
            buf += enc_u32(3)
            buf += enc_opt_str("handle_request")
            buf += enc_u64(12)
            # Sample 2: Native(u64)
            buf += enc_u8(2)
            buf += enc_u64(0xFFFF_8000_0000_1234)
            buf += enc_u64(5)
            buf += enc_u64(1)  # dropped
            return bytes(buf), {}, None
        return b"", {}, None

    def _dispatch_components(
        self, func: str, payload: bytes
    ) -> tuple[bytes, dict[int, list[bytes]], tuple[int, str, Any, int | None, int] | None]:
        if func == "list-components":
            items = [self.components[k] for k in sorted(self.components)]
            buf = bytearray(b"\x00" + enc_u32(len(items)))
            for comp in items:
                buf += self._encode_component_status(comp)
            return bytes(buf), {}, None
        if func == "start":
            moniker, _ = dec_str(payload, 0)
            comp = self.components.get(moniker)
            if comp is None:
                return b"\x01" + enc_u8(1) + enc_str(f"unknown component {moniker}"), {}, None
            comp["state"] = "running"
            comp["instance_id"] = comp["instance_id"] or 55
            return b"\x00" + self._encode_component_status(comp), {}, None
        if func == "stop":
            moniker, _ = dec_str(payload, 0)
            comp = self.components.get(moniker)
            if comp is None:
                return b"\x01" + enc_u8(1) + enc_str(f"unknown component {moniker}"), {}, None
            comp["state"] = "stopped"
            comp["instance_id"] = None
            return b"\x00", {}, None
        if func == "restart":
            moniker, _ = dec_str(payload, 0)
            comp = self.components.get(moniker)
            if comp is None:
                return b"\x01" + enc_u8(1) + enc_str(f"unknown component {moniker}"), {}, None
            comp["state"] = "running"
            comp["restarts"] += 1
            comp["instance_id"] = (comp["instance_id"] or 50) + 1
            return b"\x00" + self._encode_component_status(comp), {}, None
        if func == "mount-dynamic":
            parent_moniker, pos = dec_str(payload, 0)
            src_tag, pos = dec_u8(payload, pos)
            if src_tag == 0:
                subtree_name, pos = dec_str(payload, pos)
                _guest_path, pos = dec_str(payload, pos)
            elif src_tag == 1:
                count, pos = dec_u32(payload, pos)
                first_rel = "dynamic"
                for idx in range(count):
                    rel, pos = dec_str(payload, pos)
                    _toml, pos = dec_str(payload, pos)
                    if idx == 0:
                        seg = rel.split("/", 1)[0]
                        if seg and seg != "component.toml":
                            first_rel = seg
                subtree_name = first_rel
            else:
                return b"\x01" + enc_u8(3) + enc_str("invalid dynamic source tag"), {}, None
            prefix = parent_moniker.rstrip("/")
            mounted = f"{prefix}/{subtree_name}"
            if mounted in self.components:
                return b"\x01" + enc_u8(2) + enc_str(f"already exists {mounted}"), {}, None
            self.components[mounted] = {
                "moniker": mounted,
                "program": "/bin/dynamic",
                "state": "running",
                "instance_id": 150,
                "restarts": 0,
            }
            return b"\x00" + enc_str(mounted), {}, None
        if func == "unmount-dynamic":
            moniker, _ = dec_str(payload, 0)
            if moniker not in self.components:
                return b"\x01" + enc_u8(1) + enc_str(f"unknown component {moniker}"), {}, None
            self.components.pop(moniker, None)
            return b"\x00", {}, None
        return b"\x01" + enc_u8(4) + enc_str(f"unsupported {func}"), {}, None

    def _dispatch_mounts(
        self, func: str, payload: bytes
    ) -> tuple[bytes, dict[int, list[bytes]], tuple[int, str, Any, int | None, int] | None]:
        if func == "mount":
            src_tag, pos = dec_u8(payload, 0)
            if src_tag == 0:
                source = "memory"
            elif src_tag == 1:
                source = "boot-image"
            elif src_tag == 2:
                source = "host-share"
            elif src_tag == 3:
                serial, pos = dec_str(payload, pos)
                source = f"disk:{serial}"
            elif src_tag == 4:
                serial, pos = dec_str(payload, pos)
                source = f"btrfs:{serial}"
            else:
                return b"\x01" + enc_u8(10) + enc_str("bad source"), {}, None
            path, pos = dec_str(payload, pos)
            ro_byte, pos = dec_u8(payload, pos)
            sharing_byte, pos = dec_u8(payload, pos)
            self.mounts[path] = {
                "path": path,
                "source": source,
                "read_only": ro_byte != 0,
                "sharing": "private" if sharing_byte == 0 else "shared",
            }
            self.dirs.add(path)
            return b"\x00", {}, None
        if func == "unmount":
            path, _ = dec_str(payload, 0)
            if path not in self.mounts:
                return b"\x01" + enc_u8(3) + enc_str(f"{path} is not mounted"), {}, None
            self.mounts.pop(path, None)
            return b"\x00", {}, None
        return b"\x01" + enc_u8(10) + enc_str(f"unsupported {func}"), {}, None

    def _dispatch_btrfs(
        self, func: str, payload: bytes
    ) -> tuple[bytes, dict[int, list[bytes]], tuple[int, str, Any, int | None, int] | None]:
        if func == "create-subvolume":
            path, _ = dec_str(payload, 0)
            info = self._new_subvol(path, read_only=False)
            self.subvolumes[path] = info
            self.dirs.add(path)
            return b"\x00" + self._encode_subvolume_info(info), {}, None
        if func == "delete-subvolume":
            path, _ = dec_str(payload, 0)
            if path not in self.subvolumes:
                return b"\x01" + enc_u8(2) + enc_str(f"missing {path}"), {}, None
            self.subvolumes.pop(path, None)
            return b"\x00", {}, None
        if func == "snapshot-subvolume":
            src, pos = dec_str(payload, 0)
            dst, pos = dec_str(payload, pos)
            ro_byte, _ = dec_u8(payload, pos)
            src_info = self.subvolumes.get(src)
            if src_info is None:
                return b"\x01" + enc_u8(2) + enc_str(f"missing source {src}"), {}, None
            info = self._new_subvol(dst, read_only=(ro_byte != 0), parent_uuid=src_info["uuid"])
            self.subvolumes[dst] = info
            self.dirs.add(dst)
            return b"\x00" + self._encode_subvolume_info(info), {}, None
        if func == "set-subvolume-read-only":
            path, pos = dec_str(payload, 0)
            ro_byte, _ = dec_u8(payload, pos)
            info = self.subvolumes.get(path)
            if info is None:
                return b"\x01" + enc_u8(2) + enc_str(f"missing {path}"), {}, None
            info["read_only"] = ro_byte != 0
            return b"\x00", {}, None
        if func == "get-subvolume-info":
            path, _ = dec_str(payload, 0)
            info = self.subvolumes.get(path)
            if info is None:
                return b"\x01" + enc_u8(2) + enc_str(f"missing {path}"), {}, None
            return b"\x00" + self._encode_subvolume_info(info), {}, None
        if func == "list-subvolumes":
            items = [self.subvolumes[k] for k in sorted(self.subvolumes)]
            buf = bytearray(b"\x00" + enc_u32(len(items)))
            for info in items:
                buf += self._encode_subvolume_info(info)
            return bytes(buf), {}, None
        if func == "send-subvolume":
            return b"\x00" + enc_bytes(b"btrfs-stream\x00\x01\x00\x00\x00"), {}, None
        if func == "receive-subvolume":
            dest, _ = dec_str(payload, 0)
            path = f"{dest.rstrip('/')}/received"
            info = self._new_subvol(path, read_only=True, received_uuid=bytes([0x33] * 16))
            self.subvolumes[path] = info
            return b"\x00" + self._encode_subvolume_info(info), {}, None
        if func == "reflink":
            return b"\x00", {}, None
        if func == "dedupe":
            _src, pos = dec_str(payload, 0)
            _src_off, pos = dec_u64(payload, pos)
            _dst, pos = dec_str(payload, pos)
            _dst_off, pos = dec_u64(payload, pos)
            length, _ = dec_u64(payload, pos)
            return b"\x00" + enc_u8(1) + enc_u64(length), {}, None
        if func == "list-devices":
            buf = bytearray(b"\x00" + enc_u32(len(self.devices)))
            for dev in self.devices:
                buf += self._encode_device_info(dev)
            return bytes(buf), {}, None
        if func == "add-device":
            _mp, pos = dec_str(payload, 0)
            serial, _ = dec_str(payload, pos)
            dev = {
                "devid": len(self.devices) + 1,
                "uuid": bytes([0x44] * 16),
                "total_bytes": 8 * 1024 * 1024 * 1024,
                "bytes_used": 0,
                "serial": serial,
            }
            self.devices.append(dev)
            return b"\x00" + self._encode_device_info(dev), {}, None
        if func == "remove-device":
            _mp, pos = dec_str(payload, 0)
            devid, _ = dec_u64(payload, pos)
            self.devices = [d for d in self.devices if d["devid"] != devid]
            return b"\x00", {}, None
        if func == "replace-device":
            _mp, pos = dec_str(payload, 0)
            src_devid, pos = dec_u64(payload, pos)
            serial, _ = dec_str(payload, pos)
            for dev in self.devices:
                if dev["devid"] == src_devid:
                    dev["serial"] = serial
                    return b"\x00" + self._encode_device_info(dev), {}, None
            return b"\x01" + enc_u8(24) + enc_str("device not found"), {}, None
        if func == "resize-device":
            _mp, pos = dec_str(payload, 0)
            devid, pos = dec_opt_u64(payload, pos)
            target_tag, pos = dec_u8(payload, pos)
            new_size = 32 * 1024 * 1024 * 1024
            if target_tag == 1:
                new_size, _ = dec_u64(payload, pos)
            target_dev = self.devices[0]
            if devid is not None:
                for dev in self.devices:
                    if dev["devid"] == devid:
                        target_dev = dev
                        break
            target_dev["total_bytes"] = new_size
            return b"\x00" + self._encode_device_info(target_dev), {}, None
        if func == "balance":
            return b"\x00" + enc_u64(4) + enc_u64(2), {}, None
        if func == "scrub":
            buf = bytearray(b"\x00")
            for val in (16, 4, 65536, 16384, 0, 0, 0, 0, 0):
                buf += enc_u64(val)
            return bytes(buf), {}, None
        if func == "quota-enable":
            self.quota_enabled = True
            return b"\x00", {}, None
        if func == "quota-disable":
            self.quota_enabled = False
            return b"\x00", {}, None
        if func == "quota-rescan":
            return b"\x00", {}, None
        if func == "get-quota-status":
            buf = bytearray(b"\x00")
            buf += enc_u8(1 if self.quota_enabled else 0)
            buf += enc_u8(0)
            buf += enc_u8(0)
            buf += enc_u64(12)
            return bytes(buf), {}, None
        if func == "qgroup-list":
            items = [self.qgroups[k] for k in sorted(self.qgroups)]
            buf = bytearray(b"\x00" + enc_u32(len(items)))
            for qg in items:
                buf += self._encode_qgroup_info(qg)
            return bytes(buf), {}, None
        if func == "qgroup-create":
            _mp, pos = dec_str(payload, 0)
            level, pos = dec_u16(payload, pos)
            qid, _ = dec_u64(payload, pos)
            self.qgroups[(level, qid)] = {
                "level": level,
                "id": qid,
                "referenced_bytes": 0,
                "referenced_compressed_bytes": 0,
                "exclusive_bytes": 0,
                "exclusive_compressed_bytes": 0,
                "max_referenced": None,
                "max_exclusive": None,
                "parents": [],
            }
            return b"\x00", {}, None
        if func == "qgroup-destroy":
            _mp, pos = dec_str(payload, 0)
            level, pos = dec_u16(payload, pos)
            qid, _ = dec_u64(payload, pos)
            self.qgroups.pop((level, qid), None)
            return b"\x00", {}, None
        if func in ("qgroup-assign", "qgroup-remove", "qgroup-limit"):
            return b"\x00", {}, None
        return b"\x01" + enc_u8(9) + enc_str(f"unsupported btrfs {func}"), {}, None

    def _dispatch_programs(
        self, func: str, payload: bytes, alloc_handle: Any
    ) -> tuple[bytes, dict[int, list[bytes]], tuple[int, str, Any, int | None, int] | None]:
        if func == "set-default-image":
            tag, pos = dec_u8(payload, 0)
            if tag == 0:
                self.default_image = None
                return b"\x00", {}, None
            root_path, pos = dec_str(payload, pos)
            env_len, pos = dec_u32(payload, pos)
            env_pairs: list[tuple[str, str]] = []
            for _ in range(env_len):
                k, pos = dec_str(payload, pos)
                v, pos = dec_str(payload, pos)
                env_pairs.append((k, v))
            cred_tag, pos = dec_u8(payload, pos)
            creds: tuple[int, int, list[int]] | None = None
            if cred_tag == 1:
                uid, pos = dec_u32(payload, pos)
                gid, pos = dec_u32(payload, pos)
                supp_len, pos = dec_u32(payload, pos)
                supp: list[int] = []
                for _ in range(supp_len):
                    g, pos = dec_u32(payload, pos)
                    supp.append(g)
                creds = (uid, gid, supp)
            self.default_image = (root_path, env_pairs, creds)
            return b"\x00", {}, None
        if func == "get-default-image":
            if self.default_image is None:
                return b"\x00", {}, None
            root_path, env_pairs, creds = self.default_image
            buf = bytearray(b"\x01")
            buf += enc_str(root_path)
            buf += enc_u32(len(env_pairs))
            for k, v in env_pairs:
                buf += enc_str(k) + enc_str(v)
            if creds is None:
                buf += b"\x00"
            else:
                uid, gid, supp = creds
                buf += b"\x01" + enc_u32(uid) + enc_u32(gid) + enc_u32(len(supp))
                for g in supp:
                    buf += enc_u32(g)
            return bytes(buf), {}, None
        if func == "create-container":
            h = alloc_handle("/containers/mock", False)
            self._containers[h] = {"id": h}
            return b"\x00" + enc_u32(h), {}, None
        if func == "[method]container.exec":
            _ch, pos = dec_u32(payload, 0)
            name, pos = dec_str(payload, pos)
            argc, pos = dec_u32(payload, pos)
            args: list[str] = []
            for _ in range(argc):
                arg, pos = dec_str(payload, pos)
                args.append(arg)
            envc, pos = dec_u32(payload, pos)
            for _ in range(envc):
                _, pos = dec_str(payload, pos)
                _, pos = dec_str(payload, pos)
            _path, pos = dec_str(payload, pos)
            cwd, _ = dec_opt_str(payload, pos)
            self.container_exec_calls.append((name, args, cwd))
            return self._encode_exec_result(120, 0, b"container exec ok\n", b""), {}, None
        if func == "[method]container.spawn":
            _ch, pos = dec_u32(payload, 0)
            name, pos = dec_str(payload, pos)
            argc, pos = dec_u32(payload, pos)
            args = []
            for _ in range(argc):
                arg, pos = dec_str(payload, pos)
                args.append(arg)
            envc, pos = dec_u32(payload, pos)
            for _ in range(envc):
                _, pos = dec_str(payload, pos)
                _, pos = dec_str(payload, pos)
            _path, pos = dec_str(payload, pos)
            cwd, _ = dec_opt_str(payload, pos)
            self.container_spawn_calls.append((name, args, cwd))
            child_h = alloc_handle("/proc/121", False)
            self._children[child_h] = [121, 0, bytearray(), b"container child out\n", b""]
            return b"\x00" + enc_u32(child_h), {}, None
        if func == "exec":
            name, pos = dec_str(payload, 0)
            argc, pos = dec_u32(payload, pos)
            args = []
            for _ in range(argc):
                arg, pos = dec_str(payload, pos)
                args.append(arg)
            envc, pos = dec_u32(payload, pos)
            for _ in range(envc):
                _, pos = dec_str(payload, pos)
                _, pos = dec_str(payload, pos)
            _path, pos = dec_str(payload, pos)
            cwd, _ = dec_opt_str(payload, pos)
            self.exec_calls.append((name, args, cwd))
            if "-c" in args and "2" in args:
                return self._encode_exec_result(99, 0, b"spawned ok\n", b"warn line\n"), {}, None
            return self._encode_exec_result(42, 0, b"exec ok\n", b""), {}, None
        if func == "spawn":
            name, pos = dec_str(payload, 0)
            argc, pos = dec_u32(payload, pos)
            args = []
            for _ in range(argc):
                arg, pos = dec_str(payload, pos)
                args.append(arg)
            envc, pos = dec_u32(payload, pos)
            for _ in range(envc):
                _, pos = dec_str(payload, pos)
                _, pos = dec_str(payload, pos)
            _path, pos = dec_str(payload, pos)
            cwd, _ = dec_opt_str(payload, pos)
            self.spawn_calls.append((name, args, cwd))
            if name == "/bin/vmm":
                inst_id, stdout, stderr = 200, b"guest linux booted\n", b""
            elif "-c" in args and "2" in args:
                inst_id, stdout, stderr = 99, b"spawned ok\n", b"warn line\n"
            else:
                inst_id, stdout, stderr = 42, b"exec ok\n", b""
            child_h = alloc_handle(f"/proc/{inst_id}", False)
            self._children[child_h] = [inst_id, 0, bytearray(), stdout, stderr]
            return b"\x00" + enc_u32(child_h), {}, None
        if func == "[method]child.instance-id":
            child_h, _ = dec_u32(payload, 0)
            inst_id = int(self._children[child_h][0])
            return enc_u64(inst_id), {}, None
        if func == "[method]child.stdout":
            child_h, _ = dec_u32(payload, 0)
            data = self._children[child_h][3]
            self._children[child_h][3] = b""
            subpaths = {
                1: [enc_bytes(data)] if data else [],
                2: [b"\x00"],
            }
            return enc_u32(1) + enc_u32(2), subpaths, None
        if func == "[method]child.stderr":
            child_h, _ = dec_u32(payload, 0)
            data = self._children[child_h][4]
            self._children[child_h][4] = b""
            subpaths = {
                1: [enc_bytes(data)] if data else [],
                2: [b"\x00"],
            }
            return enc_u32(1) + enc_u32(2), subpaths, None
        if func == "[method]child.stdin":
            child_h, pos = dec_u32(payload, 0)
            in_sub_id, _ = dec_u32(payload, pos)
            done_sub_id = 1
            return enc_u32(done_sub_id), {}, (in_sub_id, "stdin", child_h, None, done_sub_id)
        if func == "[method]child.signal":
            child_h, pos = dec_u32(payload, 0)
            sig = payload[pos]
            inst_id = int(self._children[child_h][0])
            self.signals_sent.append((inst_id, sig))
            return b"\x00", {}, None
        if func == "[method]child.wait":
            child_h, _ = dec_u32(payload, 0)
            inst_id = int(self._children[child_h][0])
            exit_code = int(self._children[child_h][1])
            return b"\x00" + enc_u64(inst_id) + b"\x00" + enc_u32(exit_code), {}, None
        return b"", {}, None

    def _new_subvol(
        self,
        path: str,
        *,
        read_only: bool,
        parent_uuid: bytes | None = None,
        received_uuid: bytes | None = None,
    ) -> dict[str, Any]:
        sid = self._next_subvol_id
        self._next_subvol_id += 1
        rel = path.lstrip("/").split("/", 1)[-1] if "/" in path.lstrip("/") else path.lstrip("/")
        return {
            "id": sid,
            "parent_id": 5,
            "path": rel,
            "uuid": bytes([sid & 0xFF] * 16),
            "parent_uuid": parent_uuid,
            "received_uuid": received_uuid,
            "generation": 20,
            "ctransid": 20,
            "otransid": 20,
            "stransid": 0,
            "rtransid": 0,
            "read_only": read_only,
        }

    def _encode_component_status(self, comp: dict[str, Any]) -> bytes:
        buf = bytearray()
        buf += enc_str(comp["moniker"])
        buf += enc_str(comp["program"])
        buf += enc_str(comp["state"])
        buf += enc_opt_u64(comp["instance_id"])
        buf += enc_u64(comp["restarts"])
        return bytes(buf)

    def _encode_subvolume_info(self, info: dict[str, Any]) -> bytes:
        buf = bytearray()
        buf += enc_u64(info["id"])
        buf += enc_opt_u64(info["parent_id"])
        buf += enc_str(info["path"])
        buf += enc_bytes(info["uuid"])
        buf += enc_opt_bytes(info["parent_uuid"])
        buf += enc_opt_bytes(info["received_uuid"])
        buf += enc_u64(info["generation"])
        buf += enc_u64(info["ctransid"])
        buf += enc_u64(info["otransid"])
        buf += enc_u64(info["stransid"])
        buf += enc_u64(info["rtransid"])
        buf += enc_u8(1 if info["read_only"] else 0)
        return bytes(buf)

    def _encode_device_info(self, dev: dict[str, Any]) -> bytes:
        buf = bytearray()
        buf += enc_u64(dev["devid"])
        buf += enc_bytes(dev["uuid"])
        buf += enc_u64(dev["total_bytes"])
        buf += enc_u64(dev["bytes_used"])
        buf += enc_opt_str(dev["serial"])
        return bytes(buf)

    def _encode_qgroup_info(self, qg: dict[str, Any]) -> bytes:
        buf = bytearray()
        buf += enc_u16(qg["level"])
        buf += enc_u64(qg["id"])
        buf += enc_u64(qg["referenced_bytes"])
        buf += enc_u64(qg["referenced_compressed_bytes"])
        buf += enc_u64(qg["exclusive_bytes"])
        buf += enc_u64(qg["exclusive_compressed_bytes"])
        buf += enc_opt_u64(qg["max_referenced"])
        buf += enc_opt_u64(qg["max_exclusive"])
        buf += enc_u32(len(qg["parents"]))
        for plevel, pid in qg["parents"]:
            buf += enc_u16(plevel) + enc_u64(pid)
        return bytes(buf)

    def _dispatch_wasi_fs(
        self,
        func: str,
        payload: bytes,
        handles: dict[int, tuple[str, bool]],
        alloc_handle: Any,
    ) -> tuple[bytes, dict[int, list[bytes]], tuple[int, str, Any, int | None, int] | None]:
        if func == "[method]descriptor.open-at":
            base_h, pos = dec_u32(payload, 0)
            _path_flags, pos = dec_u32(payload, pos)
            rel, pos = dec_str(payload, pos)
            open_flags, pos = dec_u32(payload, pos)
            _desc_flags, pos = dec_u32(payload, pos)
            base_path, _ = handles.get(base_h, ("/", True))
            full = _join_vfs_path(base_path, rel)
            if open_flags & OPEN_DIRECTORY:
                if full not in self.dirs:
                    return b"\x01" + enc_u8(ERR_NO_ENTRY), {}, None
                return b"\x00" + enc_u32(alloc_handle(full, True)), {}, None
            if full in self.dirs:
                return b"\x01" + enc_u8(ERR_IS_DIRECTORY), {}, None
            if full not in self.files:
                if open_flags & OPEN_CREATE:
                    self.files[full] = b""
                else:
                    return b"\x01" + enc_u8(ERR_NO_ENTRY), {}, None
            elif open_flags & OPEN_TRUNCATE:
                self.files[full] = b""
            return b"\x00" + enc_u32(alloc_handle(full, False)), {}, None

        if func == "[method]descriptor.stat":
            h, _ = dec_u32(payload, 0)
            path, is_dir = handles.get(h, ("/", True))
            return self._encode_stat(path, is_dir), {}, None

        if func == "[method]descriptor.stat-at":
            base_h, pos = dec_u32(payload, 0)
            _path_flags, pos = dec_u32(payload, pos)
            rel, _ = dec_str(payload, pos)
            base_path, _ = handles.get(base_h, ("/", True))
            full = _join_vfs_path(base_path, rel)
            if full in self.dirs:
                return self._encode_stat(full, True), {}, None
            if full in self.files:
                return self._encode_stat(full, False), {}, None
            return b"\x01" + enc_u8(ERR_NO_ENTRY), {}, None

        if func == "[method]descriptor.read-directory":
            h, _ = dec_u32(payload, 0)
            path, _ = handles.get(h, ("/", True))
            entries_batch = self._encode_dir_entries_batch(path)
            subpaths: dict[int, list[bytes]] = {
                1: [entries_batch] if entries_batch else [],
                2: [b"\x00"],
            }
            return enc_u32(1) + enc_u32(2), subpaths, None

        if func == "[method]descriptor.read-via-stream":
            h, pos = dec_u32(payload, 0)
            offset, _ = dec_u64(payload, pos)
            path, _ = handles.get(h, ("/", False))
            data = self.files.get(path, b"")[offset:]
            subpaths = {
                1: [enc_bytes(data)] if data else [],
                2: [b"\x00"],
            }
            return enc_u32(1) + enc_u32(2), subpaths, None

        if func == "[method]descriptor.write-via-stream":
            h, pos = dec_u32(payload, 0)
            in_sub_id, pos = dec_u32(payload, pos)
            offset, _ = dec_u64(payload, pos)
            path, _ = handles.get(h, ("/", False))
            done_sub_id = 1
            return enc_u32(done_sub_id), {}, (in_sub_id, "file", path, offset, done_sub_id)

        if func == "[method]descriptor.append-via-stream":
            h, pos = dec_u32(payload, 0)
            in_sub_id, _ = dec_u32(payload, pos)
            path, _ = handles.get(h, ("/", False))
            done_sub_id = 1
            return enc_u32(done_sub_id), {}, (in_sub_id, "file", path, None, done_sub_id)

        if func == "[method]descriptor.create-directory-at":
            base_h, pos = dec_u32(payload, 0)
            rel, _ = dec_str(payload, pos)
            base_path, _ = handles.get(base_h, ("/", True))
            self.dirs.add(_join_vfs_path(base_path, rel))
            return b"\x00", {}, None

        if func in ("[method]descriptor.unlink-file-at", "[method]descriptor.remove-directory-at"):
            base_h, pos = dec_u32(payload, 0)
            rel, _ = dec_str(payload, pos)
            base_path, _ = handles.get(base_h, ("/", True))
            full = _join_vfs_path(base_path, rel)
            self.files.pop(full, None)
            self.dirs.discard(full)
            return b"\x00", {}, None

        return b"\x01" + enc_u8(ERR_NOT_DIRECTORY), {}, None

    def _encode_stat(self, path: str, is_dir: bool) -> bytes:
        buf = bytearray(b"\x00")
        buf += enc_u8(DESC_TYPE_DIRECTORY if is_dir else DESC_TYPE_REGULAR_FILE)
        buf += enc_u64(1)
        buf += enc_u64(0 if is_dir else len(self.files.get(path, b"")))
        buf += b"\x00\x00\x00"
        return bytes(buf)

    def _encode_dir_entries_batch(self, path: str) -> bytes:
        norm = path.rstrip("/") or "/"
        entries: list[tuple[int, str]] = []
        prefix = "/" if norm == "/" else f"{norm}/"
        seen: set[str] = set()
        for d in sorted(self.dirs):
            if d == norm or not d.startswith(prefix):
                continue
            rest = d[len(prefix) :]
            if "/" not in rest and rest not in seen:
                seen.add(rest)
                entries.append((DESC_TYPE_DIRECTORY, rest))
        for f in sorted(self.files):
            if not f.startswith(prefix):
                continue
            rest = f[len(prefix) :]
            if "/" not in rest and rest not in seen:
                seen.add(rest)
                entries.append((DESC_TYPE_REGULAR_FILE, rest))
        if not entries:
            return b""
        buf = bytearray(enc_u32(len(entries)))
        for dtype, name in entries:
            buf += enc_u8(dtype)
            buf += enc_str(name)
        return bytes(buf)

    def _encode_inspect_snapshot(self) -> bytes:
        entries: list[tuple[str, int, Any]] = [
            ("/kernel/uptime-ns", 2, 5_000_000_000),
            ("/kernel/processors/configured", 2, 4),
            ("/kernel/processors/online", 2, 4),
            ("/kernel/memory/total-bytes", 2, 2 * 1024 * 1024 * 1024),
            ("/kernel/memory/available-bytes", 2, 1024 * 1024 * 1024),
            ("/kernel/hv/1/vmid", 2, 11),
            ("/kernel/hv/1/owner-instance-id", 2, 200),
            ("/kernel/hv/1/vcpus", 2, 2),
            ("/kernel/hv/1/memory-limit-bytes", 2, 256 * 1024 * 1024),
            ("/kernel/hv/1/allocated-bytes", 2, 64 * 1024 * 1024),
            ("/kernel/hv/1/vcpu-exits/total", 2, 4096),
            ("/kernel/containers/1/uts/hostname", 4, "web-1"),
            ("/kernel/containers/1/pids/live", 2, 3),
            ("/core/http-client/requests-total", 2, 42),
            ("/core/http-client/status", 4, "healthy"),
        ]
        for idx, m in enumerate(self.mounts.values()):
            entries.extend(
                [
                    (f"/kernel/mounts/{idx}/path", 4, m["path"]),
                    (f"/kernel/mounts/{idx}/source", 4, m["source"]),
                    (f"/kernel/mounts/{idx}/read-only", 0, bool(m["read_only"])),
                    (f"/kernel/mounts/{idx}/sharing", 4, m["sharing"]),
                ]
            )
        buf = bytearray(b"\x00")
        buf += enc_u64(123_456_789)
        buf += enc_u32(len(entries))
        for path, tag, val in entries:
            buf += enc_str(path)
            buf += enc_u8(tag)
            if tag == 0:
                buf += enc_u8(1 if val else 0)
            elif tag == 2:
                buf += enc_u64(int(val))
            elif tag == 4:
                buf += enc_str(str(val))
        buf += b"\x00"
        buf += enc_u32(1)
        buf += enc_u64(7)
        buf += enc_str("http-client")
        buf += enc_str("state")
        buf += enc_u64(2)
        buf += enc_u8(0)
        return bytes(buf)

    def _encode_instances(self) -> bytes:
        instances = [
            (1, "init", 100, 5_000_000_000, 4 * 1024 * 1024, 0, 12),
            (7, "/core/http-client", 200, 3_000_000_000, 8 * 1024 * 1024, 65_536, 45),
        ]
        buf = bytearray(enc_u32(len(instances)))
        for inst_id, name, started, uptime, mem, storage, cpu in instances:
            buf += enc_u64(inst_id)
            buf += enc_str(name)
            buf += enc_u64(started)
            buf += enc_u64(uptime)
            buf += enc_u64(mem)
            buf += enc_u64(storage)
            buf += enc_u16(cpu)
        return bytes(buf)

    def _encode_tracing_recent(self) -> bytes:
        buf = bytearray(b"\x00")
        buf += enc_u32(1)
        buf += enc_u64(9_000_000)
        buf += enc_u8(2)
        buf += enc_str("helios_kernel::net::tcp")
        buf += enc_u32(1)
        buf += enc_str("message")
        buf += enc_u8(4)
        buf += enc_str("link up")
        return bytes(buf)

    def _encode_exec_result(
        self, inst_id: int, exit_code: int, stdout: bytes, stderr: bytes
    ) -> bytes:
        buf = bytearray(b"\x00")
        buf += enc_u64(inst_id)
        buf += enc_u32(exit_code)
        buf += enc_bytes(stdout)
        buf += enc_bytes(stderr)
        buf += enc_u64(12_345)
        return bytes(buf)
