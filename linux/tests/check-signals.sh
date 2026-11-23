#!/bin/sh
# Runs the musl signal handling, delivery, fault, and timer fixture (#1033)
# in each of its endings and compares output and exit status with Linux.
# Runs on Linux (in build-fixtures.sh) and under Helios's dash.
# Usage: check-signals.sh <signals fixture>
fixture="${1:?signals fixture required}"
failed=0

check() {
    mode="$1"
    status="$2"
    expected="$3"
    output="$("$fixture" "$mode")"
    actual=$?
    if [ "$output" = "$expected" ] && [ "$actual" -eq "$status" ]; then
        echo "signals $mode: ok"
    else
        echo "signals $mode: expected status $status, got $actual; output:"
        printf '%s\n' "$output"
        failed=1
    fi
}

check suite 0 'signals suite: ok'
check default-term 143 'end: default sigterm'
check default-kill 137 'end: default sigkill'
check default-alrm 142 'end: default sigalrm'
check masked-segv 139 'end: masked segv force default'
exit "$failed"
