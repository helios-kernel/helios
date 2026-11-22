#!/usr/bin/env bash
# Builds a static musl `dash` binary from the pinned upstream 0.5.12 source
# tarball for `x86_64` or `aarch64` using `zig cc`, caching the verified
# tarball and per-architecture binary under `target/linux-dash-cache/`.
# Usage: build-dash.sh <output binary path> [x86_64|aarch64]
set -euo pipefail

cd "$(dirname "$0")/../.."
output="${1:?output binary path required}"
arch="${2:-x86_64}"
case "$arch" in
    x86_64|aarch64) ;;
    *) echo "unknown dash target architecture: $arch" >&2; exit 1 ;;
esac

DASH_VERSION="0.5.12"
DASH_URL="https://deb.debian.org/debian/pool/main/d/dash/dash_${DASH_VERSION}.orig.tar.gz"
DASH_SHA256="6a474ac46e8b0b32916c4c60df694c82058d3297d8b385b74508030ca4a8f28a"

cache_dir="target/linux-dash-cache"
tarball="${cache_dir}/dash-${DASH_VERSION}.tar.gz"
cached_bin="${cache_dir}/dash-${DASH_VERSION}-${arch}"

mkdir -p "$cache_dir" "$(dirname "$output")"

if [[ -x "$cached_bin" ]]; then
    cp "$cached_bin" "$output"
    chmod +x "$output"
    exit 0
fi

verify_sha256() {
    local file="$1"
    local expected="$2"
    local actual
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$file" | awk '{print $1}')"
    else
        actual="$(shasum -a 256 "$file" | awk '{print $1}')"
    fi
    if [[ "$actual" != "$expected" ]]; then
        echo "dash tarball SHA-256 mismatch: expected $expected, got $actual" >&2
        return 1
    fi
}

if [[ ! -f "$tarball" ]] || ! verify_sha256 "$tarball" "$DASH_SHA256"; then
    tmp_tar="${tarball}.tmp.$$"
    curl -fsSL -o "$tmp_tar" "$DASH_URL"
    verify_sha256 "$tmp_tar" "$DASH_SHA256"
    mv "$tmp_tar" "$tarball"
fi

work_dir="$(cd "$(mktemp -d "${cache_dir}/build-${arch}.XXXXXX")" && pwd)"
trap 'rm -rf "$work_dir"' EXIT

mkdir -p "$work_dir/src" "$work_dir/build"
tar -xzf "$tarball" -C "$work_dir/src" --strip-components=1

jobs="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
(
    cd "$work_dir/build"
    "$work_dir/src/configure" \
        --host="${arch}-linux-musl" \
        --enable-static \
        CC="zig cc -target ${arch}-linux-musl" \
        CC_FOR_BUILD="zig cc" \
        CFLAGS="-Os" \
        LDFLAGS="-static -no-pie -s -Wl,--build-id=none" \
        >/dev/null
    make -j"$jobs" >/dev/null
)

tmp_bin="${cached_bin}.tmp.$$"
cp "$work_dir/build/src/dash" "$tmp_bin"
chmod +x "$tmp_bin"
mv "$tmp_bin" "$cached_bin"
cp "$cached_bin" "$output"
chmod +x "$output"
