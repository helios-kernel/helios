"""In-process TCP mock server speaking the real ``helios-inspector-protocol`` wire framing."""

from __future__ import annotations

import asyncio
import struct
from typing import Any

FRAME_MAGIC = b"\xff\x00HRPC\xaa\x55"

INSPECT_INSTANCE = "helios:system/inspect@0.1.0"
INSTANCES_INSTANCE = "helios:system/instances@0.1.0"
TRACING_INSTANCE = "helios:system/tracing@0.1.0"
PROFILING_INSTANCE = "helios:system/profiling@0.1.0"
PROGRAMS_INSTANCE = "helios:system/programs@0.1.0"
DBG_PROGRAMS_INSTANCE = "helios:debugger/programs@0.1.0"
DBG_FS_INSTANCE = "helios:debugger/filesystem@0.1.0"


def enc_varint(value: int) -> bytes:
    out = bytearray()
    n = value
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def dec_varint(buf: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    pos = offset
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7


def enc_str(text: str) -> bytes:
    raw = text.encode("utf-8")
    return enc_varint(len(raw)) + raw


def dec_str(buf: bytes, offset: int) -> tuple[str, int]:
    length, pos = dec_varint(buf, offset)
    return buf[pos : pos + length].decode("utf-8"), pos + length


def enc_bytes(data: bytes) -> bytes:
    return enc_varint(len(data)) + data


def dec_bytes(buf: bytes, offset: int) -> tuple[bytes, int]:
    length, pos = dec_varint(buf, offset)
    return buf[pos : pos + length], pos + length


def _encode_frame(payload: bytes) -> bytes:
    return FRAME_MAGIC + struct.pack("<I", len(payload)) + payload


def encode_accept(invocation: int) -> bytes:
    return _encode_frame(bytes([1]) + struct.pack("<I", invocation))


def encode_data(invocation: int, payload: bytes) -> bytes:
    body = bytes([3]) + struct.pack("<II", invocation, 0) + struct.pack("<I", len(payload)) + payload
    return _encode_frame(body)


def encode_close(invocation: int) -> bytes:
    return _encode_frame(bytes([4]) + struct.pack("<II", invocation, 0))


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


class MockHeliosGuest:
    """Async TCP mock server implementing core Helios inspector RPC endpoints."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {
            "/etc/rc.nu": b"echo hello from mock guest\n",
            "/bin/ping": b"\x00asm",
        }
        self.dirs: set[str] = {"/", "/bin", "/etc", "/tmp"}
        self.killed_ids: list[int] = []
        self.exec_calls: list[tuple[str, bytes]] = []
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
        active: dict[int, tuple[str, str, bytearray]] = {}
        try:
            while True:
                frame = await read_frame(reader)
                if frame is None:
                    break
                tag, body = frame
                if tag == 0:  # Open
                    (invocation,) = struct.unpack_from("<I", body, 0)
                    pos = 4
                    (inst_len,) = struct.unpack_from("<I", body, pos)
                    pos += 4
                    instance = body[pos : pos + inst_len].decode("utf-8")
                    pos += inst_len
                    (func_len,) = struct.unpack_from("<I", body, pos)
                    pos += 4
                    func = body[pos : pos + func_len].decode("utf-8")
                    active[invocation] = (instance, func, bytearray())
                    writer.write(encode_accept(invocation))
                    await writer.drain()
                elif tag == 3:  # Data
                    (invocation, path_len) = struct.unpack_from("<II", body, 0)
                    pos = 8 + 4 * path_len
                    (data_len,) = struct.unpack_from("<I", body, pos)
                    pos += 4
                    chunk = body[pos : pos + data_len]
                    if invocation in active:
                        active[invocation][2].extend(chunk)
                elif tag == 4:  # Close
                    (invocation, path_len) = struct.unpack_from("<II", body, 0)
                    if path_len != 0 or invocation not in active:
                        continue
                    instance, func, payload = active.pop(invocation)
                    reply = self._dispatch(instance, func, bytes(payload))
                    writer.write(encode_data(invocation, reply))
                    writer.write(encode_close(invocation))
                    await writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        finally:
            self._writers.discard(writer)
            writer.close()

    def _dispatch(self, instance: str, func: str, payload: bytes) -> bytes:
        if instance == INSPECT_INSTANCE and func == "snapshot":
            return self._encode_inspect_snapshot()
        if instance == INSTANCES_INSTANCE and func == "snapshot":
            return self._encode_instances()
        if instance == INSTANCES_INSTANCE and func == "kill":
            inst_id, _ = dec_varint(payload, 0)
            self.killed_ids.append(inst_id)
            return b"\x00"  # Ok(())
        if instance == TRACING_INSTANCE and func == "recent":
            return self._encode_tracing_recent()
        if instance == TRACING_INSTANCE and func == "set-target-enabled":
            return b"\x00"
        if instance == PROFILING_INSTANCE and func in ("metrics", "folded"):
            return b"\x00\x00"  # Ok(vec![])
        if instance == DBG_PROGRAMS_INSTANCE and func == "exec-path":
            self.exec_calls.append(("exec-path", payload))
            return self._encode_exec_result(42, 0, b"exec-path ok\n", b"")
        if instance == PROGRAMS_INSTANCE and func == "exec":
            self.exec_calls.append(("system.exec", payload))
            return self._encode_exec_result(99, 0, b"spawned ok\n", b"warn line\n")
        if instance == DBG_FS_INSTANCE and func == "list":
            path, _ = dec_str(payload, 0)
            return self._encode_list_dir(path)
        if instance == DBG_FS_INSTANCE and func == "read":
            path, _ = dec_str(payload, 0)
            return enc_bytes(self.files.get(path, b""))
        if instance == DBG_FS_INSTANCE and func == "write":
            path, pos = dec_str(payload, 0)
            data, pos = dec_bytes(payload, pos)
            append = bool(payload[pos])
            if append and path in self.files:
                self.files[path] += data
            else:
                self.files[path] = data
            return b""
        if instance == DBG_FS_INSTANCE and func == "create-directory":
            path, _ = dec_str(payload, 0)
            self.dirs.add(path)
            return b""
        if instance == DBG_FS_INSTANCE and func == "remove":
            path, _ = dec_str(payload, 0)
            self.files.pop(path, None)
            self.dirs.discard(path)
            return b""
        return b""

    def _encode_inspect_snapshot(self) -> bytes:
        entries = [
            ("/kernel/uptime-ns", 2, 5_000_000_000),
            ("/kernel/processors/configured", 2, 4),
            ("/kernel/processors/online", 2, 4),
            ("/kernel/memory/total-bytes", 2, 2 * 1024 * 1024 * 1024),
            ("/kernel/memory/available-bytes", 2, 1024 * 1024 * 1024),
            ("/core/http-client/requests-total", 2, 42),
            ("/core/http-client/status", 4, "healthy"),
        ]
        buf = bytearray(b"\x00")  # Result::Ok
        buf += enc_varint(123_456_789)  # timestamp
        buf += enc_varint(len(entries))
        for path, tag, val in entries:
            buf += enc_str(path)
            buf += enc_varint(tag)
            if tag == 2:
                buf += enc_varint(int(val))
            elif tag == 4:
                buf += enc_str(str(val))
        buf += b"\x00"  # truncated = false
        buf += enc_varint(1)  # 1 publication
        buf += enc_varint(7)
        buf += enc_str("http-client")
        buf += enc_str("state")
        buf += enc_varint(2)
        buf += enc_varint(0)  # PublicationStatus::Ok
        return bytes(buf)

    def _encode_instances(self) -> bytes:
        instances = [
            (1, "init", 100, 5_000_000_000, 4 * 1024 * 1024, 0, 12),
            (7, "/core/http-client", 200, 3_000_000_000, 8 * 1024 * 1024, 65_536, 45),
        ]
        buf = bytearray(enc_varint(len(instances)))
        for inst_id, name, started, uptime, mem, storage, cpu in instances:
            buf += enc_varint(inst_id)
            buf += enc_str(name)
            buf += enc_varint(started)
            buf += enc_varint(uptime)
            buf += enc_varint(mem)
            buf += enc_varint(storage)
            buf += enc_varint(cpu)
        return bytes(buf)

    def _encode_tracing_recent(self) -> bytes:
        buf = bytearray(b"\x00")  # Result::Ok
        buf += enc_varint(1)  # 1 event
        buf += enc_varint(9_000_000)  # timestamp
        buf += enc_varint(2)  # Level::Info
        buf += enc_str("helios_kernel::net::tcp")
        buf += enc_varint(1)  # 1 field
        buf += enc_str("message")
        buf += enc_varint(4)  # Value::Text
        buf += enc_str("link up")
        return bytes(buf)

    def _encode_exec_result(self, inst_id: int, exit_code: int, stdout: bytes, stderr: bytes) -> bytes:
        buf = bytearray(b"\x00")  # Result::Ok
        buf += enc_varint(inst_id)
        buf += enc_varint(exit_code)
        buf += enc_bytes(stdout)
        buf += enc_bytes(stderr)
        buf += enc_varint(12_345)  # launch_nanos
        return bytes(buf)

    def _encode_list_dir(self, path: str) -> bytes:
        norm = path.rstrip("/") or "/"
        entries: list[tuple[str, int]] = []
        prefix = "/" if norm == "/" else f"{norm}/"
        seen: set[str] = set()
        for d in sorted(self.dirs):
            if d == norm or not d.startswith(prefix):
                continue
            rest = d[len(prefix) :]
            if "/" not in rest and rest not in seen:
                seen.add(rest)
                entries.append((rest, 0))  # Directory
        for f in sorted(self.files):
            if not f.startswith(prefix):
                continue
            rest = f[len(prefix) :]
            if "/" not in rest and rest not in seen:
                seen.add(rest)
                entries.append((rest, 1))  # File
        buf = bytearray(enc_varint(len(entries)))
        for name, kind in entries:
            buf += enc_str(name)
            buf += enc_varint(kind)
        return bytes(buf)
