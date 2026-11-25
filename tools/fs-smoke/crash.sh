#!/usr/bin/env bash
# Kill a guest in the middle of a btrfs write burst and check what it left.
#
# The guest syncs files one by one and records each completed sync as a
# ledger line on the writable host share. The inspector SIGKILLs QEMU once
# the ledger holds a number of lines drawn from CRASH_SEED, so the kill lands
# at a different point of the burst from run to run. The image is then
# checked with `btrfs check`, mounted on Linux, and booted again by the
# guest. Only a file whose sync completed is promised: the file being
# written at the kill may be absent, short or whole, and nothing here asks
# for more.
#
# A failure is replayed with the seed this prints:
#   CRASH_SEED=<seed> bash tools/fs-smoke/crash.sh <arch> <accel>
set -euo pipefail
arch="${1:?architecture required}"
accel="${2:?accelerator required}"
seed="${CRASH_SEED:-$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')}"
script=tools/fs-smoke/crash/bootfs/etc/crash-burst.py
total="$(python3 -I "$script" total)"
kill_lines="$(python3 -I "$script" kill-point "$seed")"
echo "btrfs-crash: seed=$seed kill after $kill_lines of $total synced files (replay: CRASH_SEED=$seed)"

runtime="${GITHUB_WORKSPACE:?}/smoke-runtime/btrfs-crash"
rm -rf "$runtime"
mkdir -p "$runtime/share"
cp -R tools/fs-smoke/tree "$runtime/tree"
cp -R tools/fs-smoke/crash/bootfs "$runtime/bootfs"
mkdir -p "$runtime/bootfs/btrfs" "$runtime/bootfs/host"
# mkfs.btrfs' default single-device geometry requires at least 114294784 bytes.
truncate -s 128M "$runtime/image.btrfs"
mkfs.btrfs -q -f --rootdir "$runtime/tree" "$runtime/image.btrfs"
ledger="$runtime/share/ledger"

# One guest boot on the shared image. The inspector's own arguments follow
# the boot's name; the output lands in $runtime/<name>.out and .log.
boot() {
  local name="$1"
  shift
  mkdir -p "$runtime/$name"
  set +e
  ./target/release/helios vm --arch "$arch" --release --memory 2G \
    --accel "$accel" \
    --runtime-dir "$runtime/$name" --keep-runtime-dir \
    --bootfs-root "$runtime/bootfs" \
    --disk "$runtime/image.btrfs,serial=btrfs-smoke" \
    --shared-dir "$runtime/share" --shared-dir-writable \
    --boot-program nu --boot-program inspector-host --boot-program inspector-tls --boot-program inspector-worker \
    --boot-program ls --boot-program cat --boot-program python3 \
    --no-compiler-plugin \
    "$@" \
    shell --shell /bin/nu -c 'true' 2>&1 > "$runtime/$name.out" | tee "$runtime/$name.log"
  boot_status="${PIPESTATUS[0]}"
  sed '/^\[KDBG run:begin\]$/q' "$runtime/$name/debug-serial.log" | tr -d '\r' > "$runtime/$name-boot.out"
  set -e
}

# Boot 1: the burst, killed part way through.
printf 'burst %s\n' "$seed" > "$runtime/share/phase"
boot burst --kill-after-lines "$ledger:$kill_lines"
cat "$runtime/burst.out"
cat "$runtime/burst-boot.out"
grep -Fq 'kill-after-lines: SIGKILL sent to QEMU' "$runtime/burst.out"
test "$boot_status" -ne 0
# The kill is what ended the session: a burst that ran to its end was not
# interrupted at all.
if grep -Fq 'btrfs-crash:completed' "$runtime/burst-boot.out"; then
  echo 'btrfs-crash: the burst finished before the kill landed' >&2
  exit 1
fi
synced="$(grep -c '' "$ledger")"
echo "btrfs-crash: $synced ledger lines at the kill (the last may be cut)"
test "$synced" -ge "$kill_lines"
test "$synced" -lt "$total"

# The host's view of what the kill left.
btrfs check --readonly "$runtime/image.btrfs" 2>&1 | tee "$runtime/btrfs-check-killed.log"
mkdir -p "$runtime/linux-mount"
sudo mount -t btrfs -o loop,ro "$runtime/image.btrfs" "$runtime/linux-mount"
trap 'sudo umount "$runtime/linux-mount"' EXIT
python3 -I "$script" verify "$runtime/linux-mount/crash" "$ledger" | tee "$runtime/linux-verify.log"
sudo umount "$runtime/linux-mount"
trap - EXIT

# Boot 2: the same image, the same ledger, read back by the guest.
printf 'verify\n' > "$runtime/share/phase"
boot verify
cat "$runtime/verify-boot.out"
test "$boot_status" -eq 0
grep -Fqx 'helios init: online root=/' "$runtime/verify-boot.out"
verified="$(sed -n 's/^btrfs-crash:guest-verified //p' "$runtime/verify-boot.out")"
test "$verified" -eq "$(python3 -I "$script" count "$ledger")"
btrfs check --readonly "$runtime/image.btrfs" 2>&1 | tee "$runtime/btrfs-check-rebooted.log"
echo "btrfs-crash: seed=$seed ok, $verified synced files intact on Linux and Helios"
