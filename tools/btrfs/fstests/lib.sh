#!/usr/bin/env bash
# Shared by run.sh and crash.sh. Sourced, never run.

die() {
    echo "fstests: $*" >&2
    exit 1
}

# Waits, with a deadline, for the fuse-btrfs daemon that served $1 to exit.
# `mount.fuse.helios-btrfs` records its pid under HELIOS_FUSE_BTRFS_RUN_DIR.
# The mount is plain `fuse`, so umount returns without waiting for the daemon,
# which commits what it still holds as its session ends; this waits for that
# commit and for the process to let go of the device before the caller checks
# or tears it down.
wait_daemon_exit() {
    local device=$1 pidfile pid deadline=$((SECONDS + 30))
    pidfile="$HELIOS_FUSE_BTRFS_RUN_DIR/$(basename "$device").pid"
    [[ -f "$pidfile" ]] || return 0
    pid=$(<"$pidfile")
    while kill -0 "$pid" 2>/dev/null; do
        ((SECONDS < deadline)) || die "fuse-btrfs (pid $pid) still holds $device 30 seconds after its unmount"
        sleep 0.1
    done
    rm -f "$pidfile"
}

# Unmounts $1, the mountpoint of $2, and waits for its daemon to exit.
unmount_device() {
    local mountpoint=$1 device=$2
    umount "$mountpoint"
    wait_daemon_exit "$device"
}
