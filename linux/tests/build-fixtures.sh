#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
out="${1:?bootfs output directory required}"
mkdir -p "$out/linux-prototype"
for program in hello fault spin; do
    zig cc -target x86_64-linux-musl -nostdlib -static -no-pie -Wl,--build-id=none \
        "linux/tests/$program.S" -o "$out/linux-prototype/$program"
done
zig cc -target x86_64-linux-musl -static -no-pie -Wl,--build-id=none \
    linux/tests/hello-libc.c -o "$out/linux-prototype/hello-libc"
# The same executable first runs under Linux, establishing its ABI assertions.
if [[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]]; then
    "$out/linux-prototype/hello"
    "$out/linux-prototype/hello-libc"
fi
