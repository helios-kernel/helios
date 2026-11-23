"""Fetch verified Alpine ARM64 Linux assets and build the VMM test initramfs."""
import argparse
import gzip
import hashlib
import logging
from pathlib import Path
import shutil
import struct
import tarfile
import urllib.request

URL = "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-netboot-3.22.2-aarch64.tar.gz"
SHA256 = "be57d346c814a109d89b68aad981e4b7086b42bb189f664dd042f6cba0419849"


def cpio_entry(name, data, mode):
    # SVR4 newc: 13 eight-hex-digit fields, names and data aligned to 4.
    encoded = name.encode() + b"\0"
    fields = [1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
    header = b"070701" + b"".join(f"{field:08x}".encode() for field in fields)
    result = header + encoded
    result += b"\0" * (-len(result) % 4)
    result += data
    result += b"\0" * (-len(data) % 4)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("target/linux-vmm"))
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    archive = args.archive or args.output / "alpine-netboot.tar.gz"
    if not archive.exists():
        with urllib.request.urlopen(URL, timeout=120) as response, archive.open("wb") as target:
            shutil.copyfileobj(response, target)
    digest = hashlib.file_digest(archive.open("rb"), "sha256").hexdigest()
    if digest != SHA256:
        raise RuntimeError(f"{archive}: SHA-256 {digest}, expected {SHA256}")
    with tarfile.open(archive, "r:gz") as source:
        for member, output in [("boot/vmlinuz-virt", "Image"), ("boot/initramfs-virt", "initramfs-alpine.gz")]:
            with source.extractfile(member) as content, (args.output / output).open("wb") as target:
                shutil.copyfileobj(content, target)
    # Linux v6.12 drivers/firmware/efi/libstub/zboot-header.S defines
    # the zimg payload offset/length at bytes 8/12 and compression at 24.
    image_path = args.output / "Image"
    wrapper = image_path.read_bytes()
    if wrapper[4:8] != b"zimg" or wrapper[24:29] != b"gzip\0":
        raise RuntimeError("expected the pinned Alpine gzip EFI zboot image")
    offset, length = struct.unpack_from("<II", wrapper, 8)
    image = gzip.decompress(wrapper[offset:offset + length])
    if image[56:60] != b"ARM\x64":
        raise RuntimeError("zboot payload is not an ARM64 Linux Image")
    image_path.write_bytes(image)
    # Linux accepts concatenated cpio archives. The final /init replaces
    # Alpine's network installer without changing its real BusyBox or modules.
    init = Path(__file__).with_name("linux-vmm-init").read_bytes()
    original = gzip.decompress((args.output / "initramfs-alpine.gz").read_bytes())
    rules = Path(__file__).with_name("linux-vmm-mdev.conf").read_bytes()
    overlay = (cpio_entry("init", init, 0o100755)
               + cpio_entry("etc/mdev.conf", rules, 0o100644)
               + cpio_entry("TRAILER!!!", b"", 0))
    with (args.output / "initramfs.gz").open("wb") as target:
        with gzip.GzipFile(fileobj=target, mode="wb", mtime=0) as compressed:
            compressed.write(original)
            compressed.write(b"\0" * (-len(original) % 4))
            compressed.write(overlay)
    # A regular raw disk gives the integration test persistent read/write
    # evidence through virtio-blk; it is never checked into the repository.
    disk = args.output / "disk.raw"
    if not disk.exists():
        with disk.open("wb") as target:
            target.truncate(8 * 1024 * 1024)
    logging.info("Linux assets: %s", args.output)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    main()
