#!/usr/bin/env bash
# Shared by run.sh and crash.sh. Sourced, never run.

die() {
    echo "fstests: $*" >&2
    exit 1
}
