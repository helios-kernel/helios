#!/usr/bin/env python3
"""Build and run the ARM hardware-virtualization self-test under QEMU TCG."""

import argparse
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
    parser.add_argument("--runtime-dir", type=Path, default=Path("target/hv-aarch64-test"))
    parser.add_argument("--deadline-seconds", type=float, default=180)
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--acpi", action="store_true")
    parser.add_argument("--gdb")
    args = parser.parse_args()
    if args.deadline_seconds <= 0:
        parser.error("deadline-seconds must be positive")
    args.runtime_dir.mkdir(parents=True, exist_ok=True)
    command = [
        args.inspector, "vm", "--arch", "aarch64", "--accel", "tcg",
        "--cpu", "max", "--smp", "3", "--boot-program", "init",
        "--boot-program", "inspector-host", "--boot-program", "inspector-tls",
        "--boot-program", "inspector-worker", "--qemu-arg=-machine",
        "--qemu-arg=virtualization=on", "--runtime-dir", str(args.runtime_dir),
        "--keep-runtime-dir",
    ]
    if args.no_build:
        command.append("--no-build")
    if args.acpi:
        command.append("--acpi")
    if args.gdb:
        command.extend(["--gdb", args.gdb])
    command.extend(["tracing", "--target-prefix", "helios_aarch64::hv"])
    environment = dict(os.environ, HELIOS_HV_SELF_TEST="1")
    deadline = time.monotonic() + args.deadline_seconds
    with (args.runtime_dir / "self-test.log").open("wb") as log:
        process = subprocess.Popen(
            command, env=environment, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, start_new_session=True,
        )
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                pending = b""
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise TimeoutError(f"HV self-test exceeded {args.deadline_seconds}s; see {log.name}")
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        raise RuntimeError(f"inspector exited before HV self-test completed; see {log.name}")
                    log.write(chunk)
                    log.flush()
                    pending += chunk
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        if b"panicked" in line or b"PANIC" in line:
                            raise RuntimeError(f"kernel self-test panicked: {line.decode(errors='replace')}")
                        if b"HV self-test:" in line:
                            logging.info("%s", line.decode(errors="replace"))
                        if b"HV self-test: complete" in line:
                            return
        finally:
            # QEMU owns a separate process group. Stop it through its own
            # monitor before stopping the inspector and build subprocesses.
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
