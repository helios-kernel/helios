/* The checks the system-information fixtures share. Each fixture exits 0
 * after printing `<name>: ok`, and exits 1 naming the failed check
 * otherwise, so the same executable decides on Linux and on Helios whether
 * the kernel under it behaves as Linux does. */
#ifndef HELIOS_LINUX_FIXTURE_CHECK_H
#define HELIOS_LINUX_FIXTURE_CHECK_H

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* A raw system call's result as the kernel returns it: the value, or the
 * negated errno. The fixtures call the kernel directly wherever libc would
 * add behaviour of its own (a retry, a fallback, a different structure). */
#define SYS(...)                                                       \
    ({                                                                 \
        long result_ = syscall(__VA_ARGS__);                           \
        result_ == -1 ? -(long)errno : result_;                        \
    })

#define CHECK(condition)                                               \
    do {                                                               \
        if (!(condition)) {                                            \
            dprintf(2, "%s:%d: check failed: %s\n", __FILE__, __LINE__, \
                    #condition);                                       \
            _exit(1);                                                  \
        }                                                              \
    } while (0)

/* An address no process maps: page zero, below every executable's image. */
#define UNMAPPED ((void *)1)

/* An address in the kernel's half of the address space, which no user
 * system call may name. */
#define KERNEL_ADDRESS ((void *)~0UL)

#endif
