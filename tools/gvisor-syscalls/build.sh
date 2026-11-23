#!/usr/bin/env bash
# Builds gVisor's syscall test binaries (test/syscalls/linux) from the
# revision pin.json names, statically linked for the host's architecture,
# into <output directory>. The Linux subsystem has no dynamic loader, so a
# binary that is not a static ET_EXEC image fails the build here rather
# than every case of it on Helios.
#
# Usage: build.sh <x86_64|aarch64> <output directory> [binaries file]
#
# With a binaries file (one `*_test` name per line) only those are built;
# without one, every binary test/syscalls/BUILD runs as a syscall test.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
arch="${1:?architecture required: x86_64 or aarch64}"
out="${2:?output directory required}"
binaries="${3:-}"
case "$arch" in
    x86_64 | aarch64) ;;
    *) echo "unknown architecture: $arch" >&2; exit 1 ;;
esac
# The suite's own build is native: gVisor builds its tests on the
# architecture they run on, and so does this.
if [[ "$(uname -s)" != Linux || "$(uname -m)" != "$arch" ]]; then
    echo "building $arch binaries needs a $arch Linux host, not $(uname -s) $(uname -m)" >&2
    exit 1
fi
mkdir -p "$out"
out="$(cd "$out" && pwd)"

work="$(mktemp -d)"
# The Bazel server the build starts is stopped with the tree it serves.
bazel_started=false
cleanup() {
    if [[ "$bazel_started" == true ]]; then
        (cd "$work/src" && "$bazel" shutdown)
    fi
    rm -rf "$work"
}
trap cleanup EXIT
pin() { jq -er "$1" "$here/pin.json"; }
fetch() {
    curl --fail --silent --show-error --location --output "$2" "$1"
    echo "$3  $2" | sha256sum --check -
}
revision="$(pin .revision)"
names=()
if [[ -n "$binaries" ]]; then
    mapfile -t names < <(grep -Ev '^[[:space:]]*(#|$)' "$binaries" | sort -u)
    if [[ ${#names[@]} -eq 0 ]]; then
        echo "gVisor $revision $arch: the binaries file names none" > "$out/BUILT"
        exit 0
    fi
fi
fetch "$(pin .url)" "$work/gvisor.tar.gz" "$(pin .sha256)"
mkdir "$work/src"
tar -xzf "$work/gvisor.tar.gz" -C "$work/src" --strip-components=1
src="$work/src"
# The Bazel release the revision asks for (.bazelversion), pinned beside
# it rather than resolved by a launcher at build time.
bazel_version="$(pin .bazel.version)"
if [[ "$(cat "$src/.bazelversion")" != "$bazel_version" ]]; then
    echo "gVisor $revision asks for Bazel $(cat "$src/.bazelversion"), pin.json pins $bazel_version" >&2
    exit 1
fi
bazel="$work/bazel"
fetch "$(pin ".bazel.$arch.url")" "$bazel" "$(pin ".bazel.$arch.sha256")"
chmod +x "$bazel"

if [[ -z "$binaries" ]]; then
    mapfile -t names < <(grep -o 'test = "//test/syscalls/linux:[a-z0-9_]*"' \
        "$src/test/syscalls/BUILD" | sed 's/.*://; s/"$//' | sort -u)
    if [[ ${#names[@]} -eq 0 ]]; then
        echo "test/syscalls/BUILD of gVisor $revision names no syscall test" >&2
        exit 1
    fi
fi
targets=()
for name in "${names[@]}"; do
    targets+=("//test/syscalls/linux:$name")
done

# The link options are the ones gVisor's own `cc_binary(static = True)`
# applies (tools/bazeldefs/cc.bzl): a static C++ program that uses
# threads. `-no-pie` because the Linux host loads ET_EXEC images only.
# `--stamp` is off because the stamp is the git revision, which an
# archive does not carry and pin.json already records.
bazel_started=true
(
    cd "$src"
    "$bazel" build \
        --nostamp \
        --strip=always \
        --skip_incompatible_explicit_targets \
        --linkopt=-static \
        --linkopt=-no-pie \
        --linkopt=-lstdc++ \
        --linkopt=-Wl,--whole-archive \
        --linkopt=-lpthread \
        --linkopt=-Wl,--no-whole-archive \
        "${targets[@]}"
)

# The convenience link the build just pointed at its own output tree.
bin="$src/bazel-bin/test/syscalls/linux"
for name in "${names[@]}"; do
    binary="$bin/$name"
    if [[ ! -f "$binary" ]]; then
        # `--skip_incompatible_explicit_targets` leaves out a target the
        # architecture does not build; it is not part of this suite.
        echo "$name: not built for $arch" >&2
        continue
    fi
    header="$(readelf --file-header "$binary")"
    segments="$(readelf --program-headers "$binary")"
    if ! grep -Eq 'Type:[[:space:]]+EXEC' <<< "$header" || grep -q INTERP <<< "$segments"; then
        echo "$name is not a static ET_EXEC image:" >&2
        echo "$header" >&2
        exit 1
    fi
    install -m 0755 "$binary" "$out/$name"
done
echo "gVisor $revision $arch" > "$out/BUILT"
