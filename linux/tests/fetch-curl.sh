#!/usr/bin/env bash
# Fetches a pinned, hash-verified static musl non-PIE (ET_EXEC) curl binary
# for x86_64 or aarch64 into <output path>, cached in <cache dir> when given.
# Usage: fetch-curl.sh <output path> <x86_64|aarch64> [cache dir]
set -euo pipefail

out="${1:?output path required}"
arch="${2:?architecture (x86_64|aarch64) required}"
cache_dir="${3:-}"

version="v8.11.0"
case "$arch" in
    x86_64)
        asset="curl-amd64"
        sha256="d18aa1f4e03b50b649491ca2c401cd8c5e89e72be91ff758952ad2ab5a83135d"
        ;;
    aarch64)
        asset="curl-aarch64"
        sha256="1b050abd1669f9a2ac29b34eb022cdeafb271dce5a4fb57d8ef8fadff6d7be1f"
        ;;
    *)
        echo "unknown architecture: $arch" >&2
        exit 1
        ;;
esac

verify_sha256() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s  %s\n' "$sha256" "$file" | sha256sum -c - >/dev/null
    else
        printf '%s  %s\n' "$sha256" "$file" | shasum -a 256 -c - >/dev/null
    fi
}

mkdir -p "$(dirname "$out")"
if [[ -n "$cache_dir" ]]; then
    mkdir -p "$cache_dir"
    cached="$cache_dir/${asset}-${version}"
    if [[ -f "$cached" ]] && verify_sha256 "$cached"; then
        cp "$cached" "$out"
        chmod +x "$out"
        exit 0
    fi
fi

url="https://github.com/moparisthebest/static-curl/releases/download/${version}/${asset}"
tmp="${out}.tmp.$$"
trap 'rm -f "$tmp"' EXIT
curl --fail --silent --show-error --location --retry 3 --retry-delay 2 "$url" -o "$tmp"
verify_sha256 "$tmp"
chmod +x "$tmp"
if [[ -n "$cache_dir" ]]; then
    cp "$tmp" "$cache_dir/${asset}-${version}"
fi
mv "$tmp" "$out"
