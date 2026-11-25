"""Boot real Linux in the Wasm VMM and check SMP, console and virtio block."""
import argparse
import json
import logging
import os
from pathlib import Path
import selectors
import subprocess
import time

from qemu_test import quit_vm


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inspector", default="target/debug/helios")
    parser.add_argument("--assets", type=Path, default=Path("target/linux-vmm"))
    parser.add_argument("--runtime-dir", type=Path, default=Path("target/linux-vmm-test"))
    parser.add_argument("--deadline-seconds", type=float, default=300)
    parser.add_argument("--cpus", type=int, default=2)
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--acpi", action="store_true")
    parser.add_argument("--gdb")
    args = parser.parse_args()
    if args.deadline_seconds <= 0 or args.cpus < 1:
        parser.error("deadline and cpus must be positive")
    args.runtime_dir.mkdir(parents=True, exist_ok=True)
    for name in ("Image", "initramfs.gz", "disk.raw"):
        if not (args.assets / name).is_file():
            parser.error(f"missing {args.assets / name}; run tools/prepare-linux-vmm.py")
    # A previous successful run must not satisfy the persistence check.
    with (args.assets / "disk.raw").open("r+b") as disk:
        disk.write(bytes(512))
    command = [args.inspector, "vm", "--arch", "aarch64", "--accel", "tcg",
               "--cpu", "max", "--smp", "3", "--qemu-arg=-machine",
               "--qemu-arg=virtualization=on", "--shared-dir", str(args.assets.resolve()),
               "--shared-dir-writable", "--runtime-dir", str(args.runtime_dir),
               "--keep-runtime-dir", "--no-compiler-plugin"]
    for program in ("init", "inspector-host", "inspector-tls", "inspector-worker", "nu", "vmm"):
        command.extend(["--boot-program", program])
    if args.no_build:
        command.append("--no-build")
    if args.acpi:
        command.append("--acpi")
    if args.gdb:
        command.extend(["--gdb", args.gdb])
    # Input is queued until Linux opens the virtio console; no sleep or
    # serial side channel is needed to guess when its shell becomes ready.
    script = Path(__file__).with_name("linux-vmm-commands").read_text()
    shell = (
        f'with-grants ["dir:/:rw"] {{ {json.dumps(script)} '
        f"| ^/bin/vmm --kernel /host/Image --initramfs /host/initramfs.gz "
        f"--disk /host/disk.raw --cpus {args.cpus} }}"
    )
    command.extend(["shell", "--shell", "/bin/nu", "-c", shell])
    deadline = time.monotonic() + args.deadline_seconds
    output = bytearray()
    with (args.runtime_dir / "linux.log").open("wb") as log:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while process.poll() is None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise TimeoutError(f"Linux boot exceeded {args.deadline_seconds}s; see {log.name}")
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    output.extend(chunk)
                    log.write(chunk)
                    log.flush()
            remaining = max(1, deadline - time.monotonic())
            code = process.wait(timeout=remaining)
            tail = process.stdout.read()
            output.extend(tail)
            log.write(tail)
            text = output.decode(errors="replace").replace("\r", "")
            expected = ["HELIOS_LINUX_READY", "\nHELIOS_ARCH_aarch64\n",
                        f"\nHELIOS_CPUS_{args.cpus}\n", "\nHELIOS_BLOCK_OK\n",
                        "vmm: guest requested shutdown"]
            if args.cpus > 1:
                expected.append("\nHELIOS_CPU_HOTPLUG_OK\n")
            missing = [marker.strip() for marker in expected if marker not in text]
            if code != 0 or missing:
                raise RuntimeError(f"Linux test exit={code}, missing={missing}; see {log.name}")
            with (args.assets / "disk.raw").open("rb") as disk:
                persisted = disk.read(512)
            if not persisted.startswith(b"helios-virtio-block\n"):
                raise RuntimeError("virtio block write did not persist to the host disk")
            logging.info("Linux shell, %s CPUs and virtio block passed; %s", args.cpus, log.name)
        finally:
            try:
                quit_vm(args.runtime_dir)
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                process.stdout.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    main()
