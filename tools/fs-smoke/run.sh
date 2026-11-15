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
./target/release/helios-inspector vm --arch "$arch" --release --memory 2G \
  --accel "$accel" \
  --runtime-dir "$runtime" --keep-runtime-dir \
  --bootfs-root "$runtime/bootfs" \
  --disk "$runtime/image.erofs,serial=erofs-smoke,readonly" \
  --disk "$runtime/image.btrfs,serial=btrfs-smoke,readonly" \
  --boot-program dash --boot-program debugger \
  --boot-program ls --boot-program cat --boot-program init \
  --no-compiler-plugin \
  shell -c init 2>&1 > "$runtime/guest.out" | tee "$runtime/inspector.log"
cat "$runtime/guest.out"
grep -Fqx 'helios init: mounted disk:erofs-smoke at /image' "$runtime/guest.out"
grep -Fqx 'helios init: mounted btrfs:btrfs-smoke at /btrfs' "$runtime/guest.out"
grep -Fqx 'helios init: listing /image' "$runtime/guest.out"
grep -Fqx 'helios init: listing /btrfs' "$runtime/guest.out"
# Both filesystems must supply their own listing and data, including the
# btrfs symlink followed by the VFS from /etc/rc under init's namespace.
for line in 'dir docs' 'file hello.txt' 'filesystem:ok' '中文.txt' '日本語.txt' '한국어.txt'; do
  test "$(grep -Fxc "$line" "$runtime/guest.out")" -eq 2
done
for line in '你好，世界' 'こんにちは世界' '안녕하세요 세계'; do
  grep -Fqx "$line" "$runtime/guest.out"
done
