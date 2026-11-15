"""Write through the guest VFS, then verify the same tree from Linux."""

import os
from pathlib import Path
import sys


PAYLOAD = bytes(range(256)) * 257
LABELS = {
    "中文.txt": "你好，世界\n",
    "日本語.txt": "こんにちは世界\n",
    "한국어.txt": "안녕하세요 세계\n",
}


def synced_file(path, data):
    with path.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def write(root):
    directory = root / "written"
    directory.mkdir()
    original = directory / "original"
    synced_file(original, PAYLOAD)
    os.link(original, directory / "hard")
    original.rename(directory / "renamed")
    with (directory / "hard").open("r+b") as stream:
        stream.seek(4093)
        stream.write(b"cross-sector-overwrite")
        stream.truncate(len(PAYLOAD) + 8192)
        stream.flush()
        os.fsync(stream.fileno())
    with (directory / "renamed").open("ab") as stream:
        stream.write(b"append-after-hole")
        stream.flush()
        os.fsync(stream.fileno())
    os.symlink("renamed", directory / "symlink")
    for name, content in LABELS.items():
        synced_file(directory / name, content.encode("utf-8"))
    synced_file(directory / "deleted", b"must disappear")
    (directory / "deleted").unlink()
    (directory / "empty").mkdir()
    (directory / "empty").rmdir()
    synced_file(directory / "truncated", PAYLOAD)
    with (directory / "truncated").open("r+b") as stream:
        stream.truncate(17)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    verify(root)
    print("btrfs:guest-write-synced", flush=True)


def verify(root):
    directory = root / "written"
    expected = bytearray(PAYLOAD)
    patch = b"cross-sector-overwrite"
    expected[4093 : 4093 + len(patch)] = patch
    expected.extend(bytes(8192))
    expected.extend(b"append-after-hole")
    for name in ("renamed", "hard", "symlink"):
        assert (directory / name).read_bytes() == expected, name
    assert (directory / "renamed").stat().st_ino == (directory / "hard").stat().st_ino
    assert (directory / "renamed").stat().st_nlink == 2
    assert os.readlink(directory / "symlink") == "renamed"
    assert (directory / "truncated").read_bytes() == PAYLOAD[:17]
    assert not (directory / "original").exists()
    assert not (directory / "deleted").exists()
    assert not (directory / "empty").exists()
    for name, content in LABELS.items():
        assert (directory / name).read_text(encoding="utf-8") == content


if __name__ == "__main__":
    action, location = sys.argv[1:]
    root = Path(location)
    if action == "write":
        write(root)
    elif action == "verify":
        verify(root)
        print("btrfs:linux-readback-ok")
    else:
        raise ValueError(f"unknown action: {action}")
