#!/usr/bin/env bash
# Builds a full static musl non-PIE (ET_EXEC) `busybox` binary from the pinned
# upstream 1.36.1 source tarball (`make defconfig` + `CONFIG_STATIC=y`) for
# `x86_64` or `aarch64` using `zig cc`, caching the verified tarball and
# per-architecture binary under `target/linux-busybox-cache/`.
# Usage: build-busybox.sh <output binary path> [x86_64|aarch64]
set -euo pipefail

cd "$(dirname "$0")/../.."
output="${1:?output binary path required}"
arch="${2:-x86_64}"
case "$arch" in
    x86_64|aarch64) ;;
    *) echo "unknown busybox target architecture: $arch" >&2; exit 1 ;;
esac

BUSYBOX_VERSION="1.36.1"
BUSYBOX_URL="https://busybox.net/downloads/busybox-${BUSYBOX_VERSION}.tar.bz2"
BUSYBOX_SHA256="b8cc24c9574d809e7279c3be349795c5d5ceb6fdf19ca709f80cde50e47de314"

cache_dir="target/linux-busybox-cache"
tarball="${cache_dir}/busybox-${BUSYBOX_VERSION}.tar.bz2"
cached_bin="${cache_dir}/busybox-${BUSYBOX_VERSION}-defconfig-${arch}"

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
        echo "busybox tarball SHA-256 mismatch: expected $expected, got $actual" >&2
        return 1
    fi
}

if [[ ! -f "$tarball" ]] || ! verify_sha256 "$tarball" "$BUSYBOX_SHA256"; then
    tmp_tar="${tarball}.tmp.$$"
    curl --fail --silent --show-error --location --retry 3 --retry-delay 2 \
        -o "$tmp_tar" "$BUSYBOX_URL"
    verify_sha256 "$tmp_tar" "$BUSYBOX_SHA256"
    mv "$tmp_tar" "$tarball"
fi

work_dir="$(cd "$(mktemp -d "${cache_dir}/build-${arch}.XXXXXX")" && pwd)"
trap 'rm -rf "$work_dir"' EXIT

mkdir -p "$work_dir/src"
tar -xjf "$tarball" -C "$work_dir/src" --strip-components=1

jobs="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
host_cc="${HOSTCC:-cc}"
cc_wrapper="$work_dir/zig-cc-wrapper.sh"
cat > "$cc_wrapper" <<EOF
#!/usr/bin/env bash
set -euo pipefail
# Zig 0.13's clang driver fails with FileNotFound on BusyBox's \`-Wp,-MD,<file>\`
# because it expects the depfile under its own tmp dir; standard \`-MD -MF <file>\`
# works across Zig 0.13 and newer releases.
args=()
for arg in "\$@"; do
    case "\$arg" in
        -Wp,-MD,*)
            args+=(-MD -MF "\${arg#-Wp,-MD,}")
            ;;
        *)
            args+=("\$arg")
            ;;
    esac
done
exec zig cc -target "${arch}-linux-musl" "\${args[@]}"
EOF
chmod +x "$cc_wrapper"
(
    cd "$work_dir/src"
    export ZIG_LOCAL_CACHE_DIR="$work_dir/zig-local-cache"
    mkdir -p "$ZIG_LOCAL_CACHE_DIR"
    # Strip GNU-ld-only flags that zig/lld rejects, and guard CBQ decoding in
    # `networking/tc.c` behind `#ifdef TCA_CBQ_MAX` so BusyBox 1.36.1 builds
    # with unmodified `defconfig` against Linux >= 6.8 UAPI headers (e.g. newer
    # Zig toolchains) as well as Zig 0.13.
    python3 - <<'PY'
from pathlib import Path
p = Path("scripts/trylink")
text = p.read_text()
for flag in ("-Wl,--warn-common", "-Wl,--verbose", "-Wl,-Map,$EXE.map"):
    text = text.replace(flag, "")
p.write_text(text)

tc = Path("networking/tc.c")
tc_text = tc.read_text()
needle = "static int cbq_print_opt(struct rtattr *opt)\n{\n"
end_needle = " done:\n\treturn 0;\n}\n"
start = tc_text.index(needle)
end = tc_text.index(end_needle, start) + len(end_needle)
body = tc_text[start + len(needle):end - 2]
replacement = (
    needle
    + "#ifdef TCA_CBQ_MAX\n"
    + body
    + "#else\n\t(void)opt;\n\treturn 0;\n#endif\n}\n"
)
tc.write_text(tc_text[:start] + replacement + tc_text[end:])
PY
    make defconfig HOSTCC="$host_cc" >/dev/null
    python3 - <<'PY'
from pathlib import Path
p = Path(".config")
text = p.read_text()
text = text.replace("# CONFIG_STATIC is not set", "CONFIG_STATIC=y")
p.write_text(text)
PY
    # `yes` exits with SIGPIPE once `make oldconfig` closes stdin.
    (set +o pipefail; yes "" | make oldconfig HOSTCC="$host_cc" >/dev/null)
    make -j"$jobs" \
        HOSTCC="$host_cc" \
        CC="$cc_wrapper" \
        AR="zig ar" \
        LD="$cc_wrapper" \
        SKIP_STRIP=y \
        EXTRA_CFLAGS="-Os -fno-PIE -DBB_GLOBAL_CONST= -Wno-ignored-optimization-argument" \
        EXTRA_LDFLAGS="-static -no-pie -s -Wl,--build-id=none" \
        busybox >/dev/null
)

tmp_bin="${cached_bin}.tmp.$$"
cp "$work_dir/src/busybox" "$tmp_bin"
chmod +x "$tmp_bin"
mv "$tmp_bin" "$cached_bin"
cp "$cached_bin" "$output"
chmod +x "$output"
