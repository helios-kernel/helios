#!/usr/bin/env python3
"""Pinned upstream reader tests and reproducible libFuzzer seed preparation."""

import argparse
import concurrent.futures
import errno
import hashlib
import json
import lzma
import os
import shutil
import struct
import subprocess
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / "target/btrfs-upstream"
SEEDS = ROOT / "target/btrfs-seeds"
REPORT = ROOT / "target/btrfs-results"
SECTOR = 4096


def run(args, *, timeout=120, **kwargs):
    subprocess.run([str(arg) for arg in args], check=True, timeout=timeout, **kwargs)


def fetch(entry):
    path = WORK / entry["path"]
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(entry["url"], timeout=60) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError(f"upstream checksum mismatch: {entry['path']}")
        path.write_bytes(data)
    if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
        raise ValueError(f"cached upstream checksum mismatch: {entry['path']}")


def prepare():
    entries = json.loads((ROOT / "tools/btrfs/upstream.json").read_text())
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
        list(pool.map(fetch, entries))
    REPORT.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "tools/btrfs/upstream.json", REPORT / "upstream.json")


def seed(data, target):
    directory = SEEDS / f"btrfs-{target}-fuzz"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / hashlib.sha256(data).hexdigest()).write_bytes(data)


def sectors(source):
    """Visit allocated ranges only; Linux SEEK_DATA avoids scanning sparse disks."""
    size = os.fstat(source.fileno()).st_size
    offset = 0
    while offset < size:
        try:
            start = os.lseek(source.fileno(), offset, os.SEEK_DATA)
        except OSError as error:
            if error.errno == errno.ENXIO:
                break
            raise
        end = min(os.lseek(source.fileno(), start, os.SEEK_HOLE), size)
        source.seek(start // SECTOR * SECTOR)
        while source.tell() < end:
            at = source.tell()
            data = source.read(SECTOR)
            if any(data):
                yield at, data.ljust(SECTOR, b"\0")
        offset = end


def records(blocks, sb):
    # btrfs disk format: a 101-byte header and 25-byte leaf item descriptors.
    nodesize = struct.unpack_from("<I", sb, 148)[0]
    if nodesize not in (4096, 8192, 16384, 32768, 65536):
        return
    for offset, first in blocks.items():
        if first[32:48] != sb[32:48] or first[100] != 0:
            continue
        node = b"".join(
            blocks.get(offset + i, bytes(SECTOR)) for i in range(0, nodesize, SECTOR)
        )
        count = struct.unpack_from("<I", node, 96)[0]
        if count > (nodesize - 101) // 25:
            continue
        for index in range(count):
            slot = 101 + index * 25
            start, length = struct.unpack_from("<II", node, slot + 17)
            start += 101
            if start + length <= nodesize:
                yield node[slot : slot + 17], node[start : start + length]


def compressed_seed(payload, encoded):
    size = struct.unpack_from("<Q", payload, 8)[0]
    # BTRFS_MAX_UNCOMPRESSED is 128 KiB; preserve that boundary exactly.
    if size <= 128 * 1024:
        seed(
            bytes([5, payload[16] - 1]) + size.to_bytes(3, "little") + b"\0" + encoded,
            "record",
        )


def capture(path):
    path = Path(path).resolve()
    marker = WORK / ("captured-" + hashlib.sha256(str(path).encode()).hexdigest())
    if marker.exists():
        return
    with path.open("rb") as source:
        blocks = dict(sectors(source))
    packed = bytearray(struct.pack("<Q", path.stat().st_size))
    for offset, data in blocks.items():
        packed.extend(struct.pack("<Q", offset))
        packed.extend(data)
    seed(packed, "image")
    sb = blocks.get(65536)
    if sb:
        seed(b"\x04" + sb, "record")
        items = list(records(blocks, sb))
        chunks = []
        for key, payload in items:
            # CHUNK_ITEM: length, logical key offset, first stripe's physical offset.
            if key[8] == 228 and len(payload) >= 80:
                chunks.append(
                    (
                        struct.unpack_from("<Q", key, 9)[0],
                        struct.unpack_from("<Q", payload, 0)[0],
                        struct.unpack_from("<Q", payload, 56)[0],
                    )
                )
        for key, payload in items:
            kind = key[8]
            selector = {1: 0, 132: 1, 84: 2, 96: 2, 24: 2, 108: 3}.get(kind)
            if selector is not None:
                seed(bytes([selector]) + payload, "record")
            if kind != 108 or len(payload) < 21 or payload[16] not in (1, 2, 3):
                continue
            if payload[20] == 0:
                compressed_seed(payload, payload[21:])
            elif payload[20] == 1 and len(payload) >= 53:
                logical, length = struct.unpack_from("<QQ", payload, 21)
                # The compressed extent format bounds stored bytes at 128 KiB.
                if length > 128 * 1024 or not logical:
                    continue
                for start, size, stripe in chunks:
                    if start <= logical and logical + length <= start + size:
                        physical = stripe + logical - start
                        if physical % SECTOR == 0:
                            encoded = b"".join(
                                blocks.get(physical + i, bytes(SECTOR))
                                for i in range(0, length, SECTOR)
                            )[:length]
                            compressed_seed(payload, encoded)
                        break
    marker.touch()


def corpus():
    prepare()
    replay = ROOT / "target/debug/examples/btrfs-corpus"
    results = []
    for compressed in sorted((WORK / "corpus").glob("*.raw.xz")):
        raw = compressed.with_suffix("")
        try:
            with lzma.open(compressed) as source, raw.open("wb") as dest:
                while chunk := source.read(1024 * 1024):
                    if any(chunk):
                        dest.write(chunk)
                    else:
                        dest.seek(len(chunk), os.SEEK_CUR)
                dest.truncate()
            capture(raw)
            result = subprocess.run(
                [str(replay), str(raw)],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            results.append(
                {
                    "image": compressed.name,
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }
            )
            (REPORT / "corpus.json").write_text(json.dumps(results, indent=2) + "\n")
            result.check_returncode()
        finally:
            raw.unlink(missing_ok=True)
    if not results:
        raise RuntimeError("empty upstream malformed-image corpus")


def grub(config):
    prepare()
    template = (WORK / "grub-fs-tester.in").read_text()
    script = WORK / "grub-fs-tester"
    script.write_text(
        template.replace("@BUILD_SHEBANG@", "/bin/bash").replace(
            "@builddir@", str(WORK)
        )
    )
    shutil.copyfile(ROOT / "tools/btrfs/grub-fstest", WORK / "grub-fstest")
    (WORK / "grub-fstest").chmod(0o755)
    run(["cc", WORK / "garbage-gen.c", "-o", WORK / "garbage-gen"])
    env = dict(os.environ, HELIOS_BTRFS_ROOT=str(ROOT), GRUB_TEST_DEFAULT_DEBUG="2")
    with (REPORT / f"{config}.log").open("w") as log:
        run(
            [
                "sudo",
                "--preserve-env=HELIOS_BTRFS_ROOT,GRUB_TEST_DEFAULT_DEBUG",
                "bash",
                script,
                config,
            ],
            timeout=600,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )


def host_target():
    info = subprocess.run(
        ["rustc", "-vV"], check=True, capture_output=True, text=True, timeout=30
    ).stdout
    for line in info.splitlines():
        if line.startswith("host: "):
            return line.removeprefix("host: ").strip()
    raise RuntimeError("rustc -vV did not report a host target")


def fuzz(target, seconds):
    directory = SEEDS / target
    sizes = [path.stat().st_size for path in directory.iterdir()]
    if not sizes:
        raise RuntimeError(f"empty seed corpus: {directory}")
    REPORT.mkdir(parents=True, exist_ok=True)
    crashes = ROOT / "target/btrfs-crashes" / target
    crashes.mkdir(parents=True, exist_ok=True)
    # Keep every seed intact. Records may grow to a complete compressed extent.
    max_len = max(*sizes, 128 * 1024 + 6)
    # cargo-binstall's prebuilt cargo-fuzz is musl-targeted and otherwise
    # defaults to x86_64-unknown-linux-musl, which fails with ASan.
    command = [
        "cargo",
        "fuzz",
        "run",
        "--fuzz-dir",
        "btrfs",
        "--target",
        host_target(),
        "--features",
        "fuzzing",
        "--dev",
        "--target-dir",
        "target/btrfs-fuzz",
        target,
        directory,
        "--",
        f"-max_total_time={seconds}",
        "-timeout=30",
        "-rss_limit_mb=4096",
        f"-max_len={max_len}",
        f"-artifact_prefix={crashes}/",
    ]
    (REPORT / f"{target}-command.json").write_text(
        json.dumps(list(map(str, command)), indent=2) + "\n"
    )
    with (REPORT / f"{target}.log").open("w") as log:
        # Compilation has its own allowance; the campaign duration is explicit.
        run(
            command,
            timeout=600 + seconds,
            cwd=ROOT,
            stdout=log,
            stderr=subprocess.STDOUT,
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("prepare")
    sub.add_parser("corpus")
    p = sub.add_parser("grub")
    p.add_argument(
        "config",
        choices=["btrfs", "btrfs_single", "btrfs_zlib", "btrfs_lzo", "btrfs_zstd"],
    )
    p = sub.add_parser("capture")
    p.add_argument("image", type=Path)
    p = sub.add_parser("fuzz")
    p.add_argument("target", choices=["btrfs-image-fuzz", "btrfs-record-fuzz"])
    p.add_argument("--seconds", type=int, default=180)
    args = parser.parse_args()
    if args.command == "grub":
        grub(args.config)
    elif args.command == "capture":
        capture(args.image)
    elif args.command == "fuzz":
        fuzz(args.target, args.seconds)
    elif args.command == "corpus":
        corpus()
    else:
        prepare()


if __name__ == "__main__":
    main()
