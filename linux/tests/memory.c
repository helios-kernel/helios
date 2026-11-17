#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Allocates and frees through malloc, moves the break, unmaps, reprotects,
 * discards and remaps anonymous memory, and prints one line per result:
 * the value or errno a call returned, never an address. The argument picks
 * how it ends: "exit" returns 0, "unmapped" touches a page after munmap,
 * "readonly" writes a page after mprotect(PROT_READ). check-memory.sh
 * holds the output Linux gives. */

static size_t page;

static const char *name(long result) {
    if (result >= 0) return "ok";
    switch (errno) {
    case EPERM: return "EPERM";
    case ENOMEM: return "ENOMEM";
    case EFAULT: return "EFAULT";
    case EEXIST: return "EEXIST";
    case EINVAL: return "EINVAL";
    default: return "unexpected errno";
    }
}

static void report(const char *what, long result) {
    printf("%s: %s\n", what, name(result));
}

static long remap(void *address, size_t old_size, size_t new_size, int flags, void *target) {
    void *moved = mremap(address, old_size, new_size, flags, target);
    return moved == MAP_FAILED ? -1 : 0;
}

static char *map(size_t pages) {
    char *memory = mmap(0, pages * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) {
        printf("mmap %zu pages failed\n", pages);
        exit(90);
    }
    return memory;
}

/* Whether `count` bytes from `address` all hold `value`. */
static int holds(const char *address, size_t count, char value) {
    for (size_t index = 0; index < count; index++)
        if (address[index] != value) return 0;
    return 1;
}

/* A read into `address` through a pipe holding one byte: EFAULT when the
 * page is not writable, since read(2) never writes there. */
static long read_into(char *address) {
    int fds[2];
    if (pipe(fds) || write(fds[1], "x", 1) != 1) exit(91);
    long result = read(fds[0], address, 1);
    close(fds[0]);
    close(fds[1]);
    return result;
}

static void program_break(void) {
    uintptr_t start = syscall(SYS_brk, 0);
    uintptr_t grown = start + 3 * page + 5;
    printf("brk grow: %s\n", syscall(SYS_brk, grown) == grown ? "moved" : "refused");
    memset((void *)start, 0x2a, 3 * page + 5);
    printf("brk below start: %s\n", syscall(SYS_brk, start - 1) == grown ? "unchanged" : "moved");
    printf("brk same page: %s\n", syscall(SYS_brk, grown + 1) == grown + 1 ? "moved" : "refused");
    printf("brk shrink: %s\n", syscall(SYS_brk, start) == start ? "moved" : "refused");
    report("mprotect above shrunk brk", mprotect((void *)(start + page), page, PROT_READ));
}

static void allocator(void) {
    /* Small blocks across many size classes, every other one freed and the
     * rest grown, with their bytes checked throughout. */
    enum { blocks = 96 };
    char *small[blocks];
    for (int index = 0; index < blocks; index++) {
        size_t size = 1 + index * 97;
        small[index] = malloc(size);
        if (!small[index]) exit(92);
        memset(small[index], index, size);
    }
    for (int index = 0; index < blocks; index += 2) free(small[index]);
    int intact = 1;
    for (int index = 1; index < blocks; index += 2) {
        size_t size = 1 + index * 97;
        intact &= holds(small[index], size, index);
        small[index] = realloc(small[index], size * 3);
        if (!small[index]) exit(93);
        intact &= holds(small[index], size, index);
        free(small[index]);
    }
    printf("malloc small blocks: %s\n", intact ? "intact" : "corrupted");

    /* A block past the mmap threshold grows through mremap and goes back
     * to the system when freed. */
    size_t size = 1 << 20;
    char *large = malloc(size);
    if (!large) exit(94);
    memset(large, 0x61, size);
    large = realloc(large, 4 * size);
    if (!large) exit(95);
    printf("realloc large: %s\n", holds(large, size, 0x61) ? "intact" : "corrupted");
    memset(large + size, 0x62, 3 * size);
    char *base = (char *)((uintptr_t)large & -(uintptr_t)page);
    free(large);
    report("mprotect freed large block", mprotect(base, page, PROT_READ));
}

static void unmapping(void) {
    char *memory = map(4);
    memset(memory, 0x11, 4 * page);
    report("munmap unaligned", munmap(memory + 1, page));
    report("munmap zero length", munmap(memory, 0));
    report("munmap second page", munmap(memory + page, page));
    report("munmap hole again", munmap(memory + page, page));
    report("mprotect unmapped page", mprotect(memory + page, page, PROT_READ));
    report("mprotect across hole", mprotect(memory, 4 * page, PROT_READ));
    report("read into first page", read_into(memory));
    report("read into third page", read_into(memory + 2 * page));
    /* musl's mprotect rounds the address down to a page first. */
    report("mprotect unaligned", syscall(SYS_mprotect, memory + 1, page, PROT_READ));
    report("mprotect zero length", mprotect(memory + page, 0, PROT_READ));
    report("mprotect writable again", mprotect(memory, page, PROT_READ | PROT_WRITE));
    report("read into first page", read_into(memory));
    report("mprotect none", mprotect(memory + 2 * page, 2 * page, PROT_NONE));
    report("munmap rest", munmap(memory, 4 * page));
}

static void discarding(void) {
    char *memory = map(2);
    memset(memory, 0x5a, 2 * page);
    report("madvise dontneed", madvise(memory, 2 * page, MADV_DONTNEED));
    printf("dontneed contents: %s\n", holds(memory, 2 * page, 0) ? "zero" : "kept");
    memset(memory, 0x5b, 2 * page);
    report("madvise free", madvise(memory, 2 * page, MADV_FREE));
    memset(memory, 0x5c, page);
    printf("write after free: %s\n", holds(memory, page, 0x5c) ? "kept" : "lost");
    report("madvise unaligned", madvise(memory + 1, page, MADV_DONTNEED));
    munmap(memory, 2 * page);

    char *holed = map(3);
    memset(holed, 0x5d, 3 * page);
    munmap(holed + page, page);
    report("madvise across hole", madvise(holed, 3 * page, MADV_DONTNEED));
    printf("contents around hole: %s\n",
           holds(holed, page, 0) && holds(holed + 2 * page, page, 0) ? "zero" : "kept");
    munmap(holed, 3 * page);
}

static void remapping(void) {
    /* Eight reserved pages with the first two usable: the pages after them
     * are free once the reservation's tail goes. */
    char *memory = mmap(0, 8 * page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) exit(96);
    munmap(memory + 2 * page, 6 * page);
    report("mprotect reservation", mprotect(memory, 2 * page, PROT_READ | PROT_WRITE));
    memset(memory, 0x41, 2 * page);
    printf("mremap grow in place: %s\n",
           mremap(memory, 2 * page, 4 * page, 0) == memory ? "same address" : "failed");
    printf("grown contents: %s\n",
           holds(memory, 2 * page, 0x41) && holds(memory + 2 * page, 2 * page, 0) ? "kept" : "lost");
    printf("mremap shrink: %s\n",
           mremap(memory, 4 * page, 2 * page, 0) == memory ? "same address" : "failed");
    report("mprotect shrunk tail", mprotect(memory + 2 * page, page, PROT_READ));

    char *blocker = mmap(memory + 2 * page, page, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    printf("map fixed noreplace: %s\n", blocker == memory + 2 * page ? "placed" : "refused");
    report("map fixed noreplace over mapping",
           mmap(memory, page, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0) == MAP_FAILED ? -1 : 0);
    report("mremap blocked", remap(memory, 2 * page, 4 * page, 0, 0));
    char *moved = mremap(memory, 2 * page, 4 * page, MREMAP_MAYMOVE);
    printf("mremap maymove: %s\n", moved != MAP_FAILED && moved != memory ? "moved" : "failed");
    printf("moved contents: %s\n",
           holds(moved, 2 * page, 0x41) && holds(moved + 2 * page, 2 * page, 0) ? "kept" : "lost");
    report("mprotect old address", mprotect(memory, page, PROT_READ));

    report("mremap unaligned", remap(moved + 1, page, 2 * page, MREMAP_MAYMOVE, 0));
    report("mremap zero size", remap(moved, page, 0, MREMAP_MAYMOVE, 0));
    report("mremap fixed alone", remap(moved, page, page, MREMAP_FIXED, memory));
    report("mremap unmapped", remap(memory, page, 2 * page, MREMAP_MAYMOVE, 0));
    report("mprotect half", mprotect(moved + 2 * page, 2 * page, PROT_READ));
    report("mremap across regions", remap(moved, 4 * page, 5 * page, MREMAP_MAYMOVE, 0));
    report("mremap fixed", remap(moved, 2 * page, 2 * page, MREMAP_MAYMOVE | MREMAP_FIXED, memory));
    printf("fixed contents: %s\n", holds(memory, 2 * page, 0x41) ? "kept" : "lost");
    munmap(memory, 3 * page);
    munmap(moved, 4 * page);
}

int main(int argc, char **argv) {
    if (argc != 2) return 100;
    page = sysconf(_SC_PAGESIZE);
    program_break();
    allocator();
    unmapping();
    discarding();
    remapping();
    if (!strcmp(argv[1], "exit")) {
        printf("end: exit\n");
        return 0;
    }
    char *memory = map(1);
    memset(memory, 0x77, page);
    if (!strcmp(argv[1], "unmapped")) {
        report("munmap before touch", munmap(memory, page));
        printf("end: touch unmapped page\n");
        fflush(stdout);
        *(volatile char *)memory = 1;
    } else if (!strcmp(argv[1], "readonly")) {
        report("mprotect read only", mprotect(memory, page, PROT_READ));
        printf("end: write read-only page\n");
        fflush(stdout);
        *(volatile char *)memory = 1;
    }
    printf("end: survived\n");
    return 101;
}
