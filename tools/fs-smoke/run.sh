#!/usr/bin/env bash
# Exercise both disk filesystems through init and its children on a real
# guest. Each lane supplies its architecture and explicit accelerator.
set -euo pipefail
arch="${1:?architecture required}"
accel="${2:?accelerator required}"
runtime="${GITHUB_WORKSPACE:?}/smoke-runtime/filesystems"
mkdir -p "$runtime"
cp -R tools/fs-smoke/tree "$runtime/tree"
cp -R tools/fs-smoke/bootfs "$runtime/bootfs"
mkdir -p "$runtime/bootfs/image" "$runtime/bootfs/btrfs"
ln -s hello.txt "$runtime/tree/hello-link"
mkfs.erofs -zlz4 "$runtime/image.erofs" "$runtime/tree"
# mkfs.btrfs' default single-device geometry requires at least 114294784 bytes.
truncate -s 128M "$runtime/image.btrfs"
mkfs.btrfs -q -f --rootdir "$runtime/tree" "$runtime/image.btrfs"
init_args=()
if [[ -n "${HELIOS_PREBUILT_WASM:-}" ]]; then
  if [[ -f "${HELIOS_PREBUILT_WASM}/release/helios_fs_smoke_init.wasm" ]]; then
    init_args=(--init-wasm "${HELIOS_PREBUILT_WASM}/release/helios_fs_smoke_init.wasm")
  elif [[ -f "${HELIOS_PREBUILT_WASM}/helios_fs_smoke_init.wasm" ]]; then
    init_args=(--init-wasm "${HELIOS_PREBUILT_WASM}/helios_fs_smoke_init.wasm")
  else
    echo "fs-smoke: missing prebuilt helios_fs_smoke_init.wasm under HELIOS_PREBUILT_WASM=${HELIOS_PREBUILT_WASM}" >&2
    exit 1
  fi
else
  init_args=(--components tools/fs-smoke/components)
fi
shell_program="nu"
shell_path="/bin/nu"
if [[ "$arch" == "riscv64" ]]; then
  # `nu` requires Wasm SIMD128 (`bytecount 0.6.9`), unavailable on `riscv64gc`.
  shell_program="dash"
  shell_path="/bin/dash"
fi
./target/release/helios vm --arch "$arch" --release --memory 2G \
  --accel "$accel" \
  --runtime-dir "$runtime" --keep-runtime-dir \
  --bootfs-root "$runtime/bootfs" \
  "${init_args[@]}" \
  --disk "$runtime/image.erofs,serial=erofs-smoke,readonly" \
  --disk "$runtime/image.btrfs,serial=btrfs-smoke" \
  --boot-program "$shell_program" --boot-program inspector-host --boot-program inspector-tls --boot-program inspector-worker \
  --boot-program ls --boot-program cat --boot-program python3 \
  --no-compiler-plugin \
  shell --shell "$shell_path" -c 'true' 2>&1 > "$runtime/shell.out" | tee "$runtime/inspector.log"
sed '/^\[KDBG run:begin\]$/q' "$runtime/debug-serial.log" | tr -d '\r' > "$runtime/guest.out"
cat "$runtime/guest.out"
grep -Fqx 'helios init: online root=/' "$runtime/guest.out"
grep -Fqx 'helios init: mounted disk:erofs-smoke at /image' "$runtime/guest.out"
grep -Fqx 'helios init: mounted btrfs:btrfs-smoke at /btrfs' "$runtime/guest.out"
grep -Fqx 'helios init: listing /image' "$runtime/guest.out"
grep -Fqx 'helios init: listing /btrfs' "$runtime/guest.out"
# Both filesystems must supply their own listing and data, including the
# btrfs symlink followed by the VFS from declarative oneshot components under init's namespace.
for line in 'dir docs' 'file hello.txt' 'filesystem:ok' '中文.txt' '日本語.txt' '한국어.txt'; do
  test "$(grep -Fxc "$line" "$runtime/guest.out")" -eq 2
done
for line in '你好，世界' 'こんにちは世界' '안녕하세요 세계'; do
  grep -Fqx "$line" "$runtime/guest.out"
done

grep -Fqx 'btrfs:guest-write-synced' "$runtime/guest.out"
btrfs check --readonly "$runtime/image.btrfs" 2>&1 | tee "$runtime/btrfs-check.log"
# The guest mounted with compress=zstd:3, so the file it wrote must be stored
# in zstd extents (`extent compression 3 (zstd)` in btrfs-progs' tree dump),
# not merely read back correctly.
btrfs inspect-internal dump-tree -t 5 "$runtime/image.btrfs" > "$runtime/fs-tree.log"
grep -Eq 'extent compression 3 \(zstd\)' "$runtime/fs-tree.log"
echo 'btrfs:zstd-extents-present'
mkdir -p "$runtime/linux-mount"
sudo mount -t btrfs -o loop,ro "$runtime/image.btrfs" "$runtime/linux-mount"
trap 'sudo umount "$runtime/linux-mount"' EXIT
python3 tools/fs-smoke/bootfs/etc/btrfs-write.py verify "$runtime/linux-mount"   | tee "$runtime/linux-readback.log"
sudo umount "$runtime/linux-mount"
trap - EXIT
