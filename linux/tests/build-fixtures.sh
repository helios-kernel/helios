#!/usr/bin/env bash
# Builds a boot root holding the static Linux fixtures of one architecture
# under /linux beside init's own files, for `helios-inspector vm
# --bootfs-root`.
# Usage: build-fixtures.sh <output directory> [x86_64|aarch64]
set -euo pipefail
cd "$(dirname "$0")/../.."
out="${1:?bootfs output directory required}"
arch="${2:-x86_64}"
case "$arch" in
    x86_64) sources=linux/tests ;;
    aarch64) sources=linux/tests/aarch64 ;;
    *) echo "unknown fixture architecture: $arch" >&2; exit 1 ;;
esac
mkdir -p "$out/linux"
cp -R programs/init/bootfs/. "$out/"
for program in hello fault spin; do
    zig cc -target "$arch-linux-musl" -nostdlib -static -no-pie -Wl,--build-id=none \
        "$sources/$program.S" -o "$out/linux/$program"
done
for program in hello-libc args memory; do
    zig cc -target "$arch-linux-musl" -static -no-pie -s -O2 -Wl,--build-id=none \
        "linux/tests/$program.c" -o "$out/linux/$program"
done
cp linux/tests/check-memory.sh "$out/linux/check-memory.sh"
# The same executables first run under Linux, establishing their ABI assertions.
if [[ "$(uname -s)" == Linux && "$(uname -m)" == "$arch" ]]; then
    "$out/linux/hello"
    "$out/linux/hello-libc"
    HELIOS_PROCESS_ID=1 "$out/linux/args" 0 >/dev/null
    sh "$out/linux/check-memory.sh" "$out/linux/memory"
fi
