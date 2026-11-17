#!/usr/bin/env bash
# Crash consistency of the writer, after fstests' tests/btrfs/192 and
# tests/generic/482: a dm-log-writes target records every write a workload
# makes to a fresh btrfs, and fstests' replay-log replays the log onto the
# device, running `btrfs check` at every FUA write. Each commit's superblock
# write is a FUA write, so each is a point a power cut could have left behind.
# The workload is fstests' fsstress rather than 192's, which needs the
# in-kernel btrfs's subvolume ioctls.
#
# Called by run.sh, which sets up the devices and the environment: the fstests
# tree HELIOS_FSTESTS_DIR, the device HELIOS_CRASH_DEV the target sits on, the
# device HELIOS_CRASH_LOG_DEV the log goes to, the mountpoint HELIOS_CRASH_MNT
# and the results directory HELIOS_FSTESTS_RESULTS.
# HELIOS_CRASH_SECONDS (default 30) bounds the workload.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
source "$here/lib.sh"

: "${HELIOS_FSTESTS_DIR:?}" "${HELIOS_CRASH_DEV:?}" "${HELIOS_CRASH_LOG_DEV:?}"
: "${HELIOS_CRASH_MNT:?}" "${HELIOS_FSTESTS_RESULTS:?}" "${HELIOS_FUSE_BTRFS_RUN_DIR:?}"

seconds=${HELIOS_CRASH_SECONDS:-30}
# fsstress's seed, fixed so a failure repeats.
seed=1
# As btrfs/192 caps its processes.
processes=$(nproc)
((processes <= 8)) || processes=8

target=logwrites-helios
target_device=/dev/mapper/$target
replay_log=$HELIOS_FSTESTS_DIR/src/log-writes/replay-log
fsstress=$HELIOS_FSTESTS_DIR/ltp/fsstress
out=$HELIOS_FSTESTS_RESULTS/crash

modprobe dm-log-writes || die "cannot load the dm-log-writes kernel module; the kernel needs it (linux-modules-extra-$(uname -r) on Ubuntu)"

mkdir -p "$out"

cleanup() {
    set +e
    mountpoint -q "$HELIOS_CRASH_MNT" && umount "$HELIOS_CRASH_MNT"
    [[ -e "$target_device" ]] && dmsetup remove --retry "$target"
}
trap cleanup EXIT

sectors=$(blockdev --getsz "$HELIOS_CRASH_DEV")
dmsetup create "$target" --table "0 $sectors log-writes $HELIOS_CRASH_DEV $HELIOS_CRASH_LOG_DEV"

# As btrfs/192: discard the whole device, so a tree pointer that is wrong
# cannot land on an older valid tree block and pass.
blkdiscard "$target_device"
dmsetup message "$target" 0 mark prepare

mkfs.btrfs --force --nodesize 4k --sectorsize 4k "$target_device" >"$out/mkfs.log"
dmsetup message "$target" 0 mark mkfs
mount -t fuse.helios-btrfs "$target_device" "$HELIOS_CRASH_MNT"

mkdir "$HELIOS_CRASH_MNT/fsstress"
# Its own session, so the whole workload is stopped through one pid. fsstress
# prints an error for every operation the filesystem does not support and
# goes on.
setsid "$fsstress" -w -d "$HELIOS_CRASH_MNT/fsstress" -n 99999 -p "$processes" -s "$seed" \
    >"$out/fsstress.log" 2>&1 &
workload=$!
sleep "$seconds"
kill -0 "$workload" 2>/dev/null || die "fsstress ended before the $seconds second workload did; see $out/fsstress.log"
kill -TERM -- "-$workload"
# The status of a workload that was just killed says nothing.
wait "$workload" || true
# fsstress's children outlive it for a moment; the unmount needs them gone.
deadline=$((SECONDS + 30))
while kill -0 -- "-$workload" 2>/dev/null; do
    ((SECONDS < deadline)) || die "the fsstress processes did not exit within 30 seconds of being stopped"
    sleep 0.1
done

unmount_device "$HELIOS_CRASH_MNT" "$target_device"
dmsetup remove --retry "$target"

# Without a FUA write there is no point to check and the replay below would
# pass having checked nothing.
first_fua=
if ! first_fua=$("$replay_log" --find --log "$HELIOS_CRASH_LOG_DEV" --next-fua --start-entry 0 2>/dev/null); then
    first_fua=
fi
[[ -n "$first_fua" ]] || die "the log holds no FUA write; the commit's superblock write did not reach the device as one"

"$replay_log" --log "$HELIOS_CRASH_LOG_DEV" --replay "$HELIOS_CRASH_DEV" \
    --check fua --fsck "btrfs check $HELIOS_CRASH_DEV" 2>&1 | tee "$out/replay.log"
