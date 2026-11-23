"""A write burst on the guest's btrfs mount, recorded for a crash check.

The guest writes and fsyncs files one after another. After each fsync
returns it appends one line to the ledger, which lives on the host share
so the host sees it the moment it is written. The host kills the VM
while this runs, so the ledger is what it knows completed: a file with a
ledger line was synced before the kill and must hold exactly the bytes
the line names. A file without one may be absent, short or whole.

    guest <directory> <share>   run inside the guest, as /etc/rc does
    verify <directory> <ledger> check every ledger line against its file
    kill-point <seed>           print how many ledger lines the host waits for
    total                       print how many files a whole burst writes
    count <ledger>              print how many syncs the ledger records

`guest` reads `<share>/phase`: `burst <seed>` writes the burst, `verify`
reads back what the ledger names. The same script runs on the host, so
Linux and Helios apply one definition of "intact".
"""

import hashlib
import os
from pathlib import Path
import random
import sys

TOTAL_FILES = 48
CHUNK = 64 * 1024
# ASCII, Chinese, Japanese and Korean names, interleaved so every kill
# point leaves files of all four kinds.
PREFIXES = ("ascii", "中文", "日本語", "한국어")
SECTOR = 4096
MAX_SECTORS = 192
TEXT_LINE = "compressible line of text, 中文 日本語 한국어\n"


def kill_point(seed):
    """Ledger lines the host waits for before killing: at most half the
    burst, so the program is always still writing when the kill lands."""
    return random.Random(f"kill:{seed}").randint(1, TOTAL_FILES // 2)


def plan(seed):
    """The burst's files: name, bytes. Contents alternate between random
    (stored raw) and repetitive text (stored compressed by `zstd:3`)."""
    rng = random.Random(f"data:{seed}")
    for index in range(TOTAL_FILES):
        name = f"{PREFIXES[index % len(PREFIXES)]}-{index:02d}.bin"
        size = SECTOR * rng.randint(1, MAX_SECTORS)
        if index % 2 == 0:
            data = rng.randbytes(size)
        else:
            text = TEXT_LINE.encode("utf-8")
            data = (text * (size // len(text) + 1))[:size]
        yield name, data


def burst(directory, ledger_path, seed):
    directory.mkdir()
    # Written sequentially through one descriptor, one write per line, so
    # the host never reads a line the guest has not finished.
    with ledger_path.open("wb", buffering=0) as ledger:
        for name, data in plan(seed):
            with (directory / name).open("wb") as stream:
                for start in range(0, len(data), CHUNK):
                    stream.write(data[start : start + CHUNK])
                stream.flush()
                os.fsync(stream.fileno())
            digest = hashlib.sha256(data).hexdigest()
            ledger.write(f"{name}\t{digest}\t{len(data)}\n".encode("utf-8"))
            print(f"btrfs-crash:synced {name} {digest}", flush=True)
    print("btrfs-crash:completed", flush=True)


def entries(ledger_path):
    """The complete lines of the ledger; a last line cut by the kill has
    no newline and was never a recorded sync."""
    text = ledger_path.read_bytes().decode("utf-8")
    complete = text[: text.rfind("\n") + 1]
    result = []
    for line in complete.splitlines():
        name, digest, size = line.split("\t")
        result.append((name, digest, int(size)))
    return result


def verify(directory, ledger_path):
    recorded = entries(ledger_path)
    assert recorded, f"{ledger_path} holds no completed sync"
    for name, digest, size in recorded:
        data = (directory / name).read_bytes()
        assert len(data) == size, f"{name}: {len(data)} bytes, synced {size}"
        assert hashlib.sha256(data).hexdigest() == digest, f"{name}: bytes differ"
    return len(recorded)


if __name__ == "__main__":
    action, *arguments = sys.argv[1:]
    if action == "kill-point":
        (seed,) = arguments
        print(kill_point(seed))
    elif action == "total":
        print(TOTAL_FILES)
    elif action == "count":
        (ledger,) = arguments
        print(len(entries(Path(ledger))))
    elif action == "verify":
        directory, ledger = arguments
        print(f"btrfs-crash:linux-verified {verify(Path(directory), Path(ledger))}")
    elif action == "guest":
        directory, share = arguments
        share = Path(share)
        phase = (share / "phase").read_text(encoding="utf-8").split()
        if phase[0] == "burst":
            burst(Path(directory), share / "ledger", phase[1])
        elif phase[0] == "verify":
            count = verify(Path(directory), share / "ledger")
            print(f"btrfs-crash:guest-verified {count}", flush=True)
        else:
            raise ValueError(f"unknown phase: {phase}")
    else:
        raise ValueError(f"unknown action: {action}")
