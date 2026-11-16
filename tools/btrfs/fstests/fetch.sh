#!/usr/bin/env bash
# Fetches the pinned upstream fstests into $1 and builds it. Needs the build
# dependencies of fstests' README installed.
set -euo pipefail

readonly repository=https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git
readonly tag=v2026.11.10
# The commit the tag peels to. The tag object itself is e047468c9332a73b61a0272c98b0f093b60d8e5e.
readonly commit=71641219a506ac62bfa231592394265ca812670e

directory=${1:?usage: fetch.sh <directory>}

if [[ ! -d "$directory/.git" ]]; then
    git clone --quiet --depth 1 --branch "$tag" "$repository" "$directory"
fi
head=$(git -C "$directory" rev-parse HEAD)
if [[ "$head" != "$commit" ]]; then
    echo "fstests: $directory is at $head, not $tag ($commit)" >&2
    exit 1
fi
make -C "$directory" -j"$(nproc)"
