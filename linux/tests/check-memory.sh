#!/bin/sh
# Runs the memory fixture in each of its three endings and compares its
# output and exit status with what Linux gives. The same script runs under
# Linux and under Helios's dash.
# Usage: check-memory.sh <memory fixture>
#
# Where each expectation comes from (man-pages 6.x and the Linux kernel's
# mm/ directory):
# - brk(2): the system call returns the new break, or the current one when
#   it cannot move; mm/mmap.c `brk` keeps an unaligned break, ignores a
#   request below `start_brk`, and unmaps the pages a shrink gives up.
# - malloc: musl's allocator frees a block past its mmap threshold with
#   munmap, so mprotect(2) on it then fails with ENOMEM ("one or more pages
#   ... are not mapped"); realloc grows such a block with mremap(2).
# - munmap(2): EINVAL for an unaligned address and, since Linux 2.6.12, for
#   a zero length (`do_vmi_munmap`); a range with nothing mapped succeeds.
# - mprotect(2): EINVAL for an unaligned address, success for a zero
#   length, ENOMEM for unmapped pages; mm/mprotect.c `do_mprotect_pkey`
#   changes the mappings before the first hole and stops there.
# - read(2): EFAULT when the buffer is not writable.
# - madvise(2): MADV_DONTNEED leaves zero-fill-on-demand pages in a private
#   anonymous mapping; MADV_FREE succeeds and a later write keeps its
#   bytes; ENOMEM when part of the range is unmapped, after mm/madvise.c
#   `madvise_walk_vmas` has advised every mapped part; EINVAL unaligned.
# - mremap(2): growth in place when the following pages are free; ENOMEM
#   when they are not and MREMAP_MAYMOVE is absent; with it, the contents
#   move and the old range is unmapped; EINVAL for an unaligned address, a
#   zero new size, or MREMAP_FIXED without MREMAP_MAYMOVE; EFAULT for an
#   unmapped address or a range across two mappings ("mappings ... of
#   different types"); MREMAP_FIXED moves onto the given address.
# - mmap(2): MAP_FIXED_NOREPLACE fails with EEXIST over a mapping.
# - mmap(2) and mprotect(2) grant PROT_WRITE with PROT_EXEC on anonymous
#   private memory: mm/mmap.c `calc_vm_prot_bits` sets VM_WRITE|VM_EXEC,
#   anonymous mappings carry every VM_MAY* bit so mm/mprotect.c's EACCES
#   check passes, and only an LSM `execmem` policy or PR_SET_MDWE (neither
#   set for these runs) refuses the pair. Code written to such a page runs
#   once the instruction stream is synchronised (on arm64 the EL0
#   DC CVAU / IC IVAU sequence Linux's SCTLR_EL1.UCI permits), and the page
#   stays writable while it is executable.
# - A store to an unmapped or read-only page raises SIGSEGV (signal(7));
#   the shell reports a process a signal ended as 128 plus its number
#   (POSIX `wait` status, SIGSEGV is 11 on x86-64 and arm64).
fixture="${1:?memory fixture required}"
common='brk grow: moved
brk below start: unchanged
brk same page: moved
brk shrink: moved
mprotect above shrunk brk: ENOMEM
malloc small blocks: intact
realloc large: intact
mprotect freed large block: ENOMEM
munmap unaligned: EINVAL
munmap zero length: EINVAL
munmap second page: ok
munmap hole again: ok
mprotect unmapped page: ENOMEM
mprotect across hole: ENOMEM
read into first page: EFAULT
read into third page: ok
mprotect unaligned: EINVAL
mprotect zero length: ok
mprotect writable again: ok
read into first page: ok
mprotect none: ok
munmap rest: ok
madvise dontneed: ok
dontneed contents: zero
madvise free: ok
write after free: kept
madvise unaligned: EINVAL
madvise across hole: ENOMEM
contents around hole: zero
mprotect reservation: ok
mremap grow in place: same address
grown contents: kept
mremap shrink: same address
mprotect shrunk tail: ENOMEM
map fixed noreplace: placed
map fixed noreplace over mapping: EEXIST
mremap blocked: ENOMEM
mremap maymove: moved
moved contents: kept
mprotect old address: ENOMEM
mremap unaligned: EINVAL
mremap zero size: EINVAL
mremap fixed alone: EINVAL
mremap unmapped: EFAULT
mprotect half: ok
mremap across regions: EFAULT
mremap fixed: ok
fixed contents: kept
mmap write and execute: ok
rwx code returns: 42
mprotect rw to rwx: ok
rw to rwx code returns: 42
rewritten code returns: 7
mmap over totalram: ok
touch reserved ends: ok
mmap over freeram: ok
touch sparse ends: ok
mremap over freeram: ok
mremap touch tail: ok'
failed=0

check() {
    ending="$1"
    status="$2"
    tail="$3"
    output="$("$fixture" "$ending")"
    actual=$?
    expected="$common
$tail"
    if [ "$output" = "$expected" ] && [ "$actual" -eq "$status" ]; then
        echo "memory $ending: ok"
    else
        echo "memory $ending: expected status $status, got $actual; output:"
        printf '%s\n' "$output"
        failed=1
    fi
}

check exit 0 'end: exit'
check unmapped 139 'munmap before touch: ok
end: touch unmapped page'
check readonly 139 'mprotect read only: ok
end: write read-only page'
exit "$failed"
