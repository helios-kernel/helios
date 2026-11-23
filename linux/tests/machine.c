/* uname and sysinfo.
 *
 * Expected values: Linux v6.12 kernel/sys.c (`newuname`, which both
 * architectures' `uname` is, copies a six-field `struct new_utsname`;
 * `do_sysinfo` reports uptime rounded up to a second, and scales the memory
 * fields to bytes with `mem_unit` 1 when they fit), include/linux/uts.h
 * (`UTS_SYSNAME` is "Linux"), arch/x86/Makefile and arch/arm64/Makefile
 * (`UTS_MACHINE`). */
#include "check.h"

#include <stdint.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <time.h>

#if defined(__x86_64__)
#define MACHINE "x86_64"
#elif defined(__aarch64__)
#define MACHINE "aarch64"
#else
#error "the fixtures cover x86-64 and aarch64"
#endif

/* The length of a NUL-terminated field, or -1 when it has no terminator
 * within `size` bytes. */
static int length(const char *field, size_t size) {
    for (size_t at = 0; at < size; at++)
        if (!field[at]) return (int)at;
    return -1;
}

int main(void) {
    struct utsname name;
    memset(&name, 0xaa, sizeof name);
    CHECK(SYS(SYS_uname, &name) == 0);
    CHECK(strcmp(name.sysname, "Linux") == 0);
    CHECK(strcmp(name.machine, MACHINE) == 0);
    /* A release starts with the version number, and every field ends
     * inside its 65 bytes. */
    CHECK(length(name.nodename, sizeof name.nodename) >= 0);
    CHECK(length(name.release, sizeof name.release) > 0);
    CHECK(name.release[0] >= '0' && name.release[0] <= '9');
    CHECK(length(name.version, sizeof name.version) >= 0);
    CHECK(length(name.domainname, sizeof name.domainname) >= 0);
    /* libc's `uname` is the same call. */
    struct utsname again;
    CHECK(uname(&again) == 0);
    CHECK(strcmp(again.release, name.release) == 0);
    CHECK(strcmp(again.version, name.version) == 0);
    CHECK(SYS(SYS_uname, UNMAPPED) == -EFAULT);
    CHECK(SYS(SYS_uname, KERNEL_ADDRESS) == -EFAULT);
    CHECK(SYS(SYS_uname, NULL) == -EFAULT);

    /* sysinfo: uptime agrees with the boot-time clock, the machine has
     * memory, and the process counts itself. */
    struct timespec before, after;
    struct sysinfo info;
    CHECK(SYS(SYS_clock_gettime, CLOCK_BOOTTIME, &before) == 0);
    memset(&info, 0, sizeof info);
    CHECK(SYS(SYS_sysinfo, &info) == 0);
    CHECK(SYS(SYS_clock_gettime, CLOCK_BOOTTIME, &after) == 0);
    /* Rounded up, so never below the earlier whole second. */
    CHECK(info.uptime >= before.tv_sec);
    CHECK(info.uptime <= after.tv_sec + 1);
    CHECK(info.totalram > 0);
    CHECK(info.freeram <= info.totalram);
    CHECK(info.mem_unit >= 1);
    CHECK(info.procs >= 1);
    CHECK(info.freeswap <= info.totalswap);
    CHECK(SYS(SYS_sysinfo, UNMAPPED) == -EFAULT);
    CHECK(SYS(SYS_sysinfo, KERNEL_ADDRESS) == -EFAULT);
    CHECK(sysinfo(&info) == 0);

    puts("machine: ok");
    return 0;
}
