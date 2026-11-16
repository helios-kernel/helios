#!/usr/bin/env bash
# Shared by run.sh and crash.sh. Sourced, never run.

die() {
    echo "fstests: $*" >&2
    exit 1
}

# Waits, with a deadline, for the fuse-btrfs daemon that served $1 to exit.
# `mount.fuse.helios-btrfs` records its pid under HELIOS_FUSE_BTRFS_RUN_DIR.
# The mount is `fuseblk`, so umount already waited for the daemon's answer to
# the kernel's destroy request; this waits for the process to finish exiting
# and let go of the device.
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
