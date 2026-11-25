"""In-process TCP mock server speaking the real ``helios-wit-rpc`` wire framing."""

from __future__ import annotations

import asyncio
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


def dec_u8(buf: bytes, offset: int) -> tuple[int, int]:
    return buf[offset], offset + 1


def dec_u32(buf: bytes, offset: int) -> tuple[int, int]:
    (val,) = struct.unpack_from("<I", buf, offset)
    return val, offset + 4


def dec_u64(buf: bytes, offset: int) -> tuple[int, int]:
    (val,) = struct.unpack_from("<Q", buf, offset)
    return val, offset + 8


def dec_str(buf: bytes, offset: int) -> tuple[str, int]:
    length, pos = dec_u32(buf, offset)
    return buf[pos : pos + length].decode("utf-8"), pos + length


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


class MockHeliosGuest:
    """Async TCP mock server implementing Helios ``wit-rpc`` inspector endpoints."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {
            "/etc/rc.nu": b"echo hello from mock guest\n",
            "/bin/ping": b"\x00asm",
        }
        self.dirs: set[str] = {"/", "/bin", "/etc", "/tmp"}
        self.killed_ids: list[int] = []
        self.exec_calls: list[tuple[str, list[str]]] = []
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
        # Per-connection resource handle table: handle -> (path, is_dir)
        handles: dict[int, tuple[str, bool]] = {1: ("/", True)}
        next_handle = 2
        # Active invocations: inv -> (instance, func, root_request_bytes)
        active: dict[int, tuple[str, str, bytearray]] = {}
        # Pending server->client subpaths waiting for Credit: (inv, sub_id) -> list[bytes]
        pending_out: dict[tuple[int, int], list[bytes]] = {}
        # Active client->server write streams: (inv, sub_id) -> (path, offset_or_none, bytearray, done_sub_id)
        pending_in: dict[tuple[int, int], tuple[str, int | None, bytearray, int]] = {}
        # Credits received before a done future was ready: set[(inv, sub_id)]
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
                            # `stream<u8>` item batches are encoded as `u32(len) + raw bytes`.
                            batch_len, bpos = dec_u32(chunk, 0)
                            pending_in[key][2].extend(chunk[bpos : bpos + batch_len])
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
                            in_sub_id, fpath, offset, done_sub_id = in_stream
                            pending_in[(invocation, in_sub_id)] = (
                                fpath,
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
                            fpath, offset, data, done_sub_id = entry
                            if offset is None:
                                self.files[fpath] = self.files.get(fpath, b"") + bytes(data)
                            else:
                                existing = bytearray(self.files.get(fpath, b""))
                                end = offset + len(data)
                                if len(existing) < end:
                                    existing.extend(b"\x00" * (end - len(existing)))
                                existing[offset:end] = data
                                self.files[fpath] = bytes(existing)
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
    ) -> tuple[bytes, dict[int, list[bytes]], tuple[int, str, int | None, int] | None]:
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
        if instance == PROFILING_INSTANCE and func in ("metrics", "folded"):
            return b"\x00" + enc_u32(0), {}, None
        if instance == PROGRAMS_INSTANCE and func == "exec":
            name, pos = dec_str(payload, 0)
            argc, pos = dec_u32(payload, pos)
            args: list[str] = []
            for _ in range(argc):
                arg, pos = dec_str(payload, pos)
                args.append(arg)
            self.exec_calls.append((name, args))
            if "-c" in args and "2" in args:
                return self._encode_exec_result(99, 0, b"spawned ok\n", b"warn line\n"), {}, None
            return self._encode_exec_result(42, 0, b"exec ok\n", b""), {}, None
        if instance == WASI_PREOPENS_INSTANCE and func == "get-directories":
            # list<tuple<own<descriptor>, string>>
            return enc_u32(1) + enc_u32(1) + enc_str("/"), {}, None
        if instance == WASI_FS_TYPES_INSTANCE:
            return self._dispatch_wasi_fs(func, payload, handles, alloc_handle)
        return b"", {}, None

    def _dispatch_wasi_fs(
        self,
        func: str,
        payload: bytes,
        handles: dict[int, tuple[str, bool]],
        alloc_handle: Any,
    ) -> tuple[bytes, dict[int, list[bytes]], tuple[int, str, int | None, int] | None]:
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
            return enc_u32(done_sub_id), {}, (in_sub_id, path, offset, done_sub_id)

        if func == "[method]descriptor.append-via-stream":
            h, pos = dec_u32(payload, 0)
            in_sub_id, _ = dec_u32(payload, pos)
            path, _ = handles.get(h, ("/", False))
            done_sub_id = 1
            return enc_u32(done_sub_id), {}, (in_sub_id, path, None, done_sub_id)

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
        buf = bytearray(b"\x00")  # Result::Ok
        buf += enc_u8(DESC_TYPE_DIRECTORY if is_dir else DESC_TYPE_REGULAR_FILE)
        buf += enc_u64(1)  # link-count
        buf += enc_u64(0 if is_dir else len(self.files.get(path, b"")))  # size
        buf += b"\x00\x00\x00"  # 3 optional timestamps = None
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
        entries: list[tuple[str, int, int | str]] = [
            ("/kernel/uptime-ns", 2, 5_000_000_000),
            ("/kernel/processors/configured", 2, 4),
            ("/kernel/processors/online", 2, 4),
            ("/kernel/memory/total-bytes", 2, 2 * 1024 * 1024 * 1024),
            ("/kernel/memory/available-bytes", 2, 1024 * 1024 * 1024),
            ("/core/http-client/requests-total", 2, 42),
            ("/core/http-client/status", 4, "healthy"),
        ]
        buf = bytearray(b"\x00")  # Result::Ok
        buf += enc_u64(123_456_789)  # timestamp
        buf += enc_u32(len(entries))
        for path, tag, val in entries:
            buf += enc_str(path)
            buf += enc_u8(tag)
            if tag == 2:
                buf += enc_u64(int(val))
            elif tag == 4:
                buf += enc_str(str(val))
        buf += b"\x00"  # truncated = false
        buf += enc_u32(1)  # 1 publication
        buf += enc_u64(7)  # instance-id
        buf += enc_str("http-client")  # instance-name
        buf += enc_str("state")  # name
        buf += enc_u64(2)  # generation
        buf += enc_u8(0)  # PublicationStatus::Ok
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
        buf = bytearray(b"\x00")  # Result::Ok
        buf += enc_u32(1)  # 1 event
        buf += enc_u64(9_000_000)  # timestamp
        buf += enc_u8(2)  # Level::Info
        buf += enc_str("helios_kernel::net::tcp")
        buf += enc_u32(1)  # 1 field
        buf += enc_str("message")
        buf += enc_u8(4)  # Value::Text
        buf += enc_str("link up")
        return bytes(buf)

    def _encode_exec_result(
        self, inst_id: int, exit_code: int, stdout: bytes, stderr: bytes
    ) -> bytes:
        buf = bytearray(b"\x00")  # Result::Ok
        buf += enc_u64(inst_id)
        buf += enc_u32(exit_code)
        buf += enc_bytes(stdout)
        buf += enc_bytes(stderr)
        buf += enc_u64(12_345)  # launch-nanos
        return bytes(buf)
