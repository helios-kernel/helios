/* getrlimit, setrlimit and prlimit64, with RLIMIT_NOFILE as the table of
 * descriptors' limit.
 *
 * Usage: limits [unprivileged]
 *
 * `unprivileged` asserts the process may not raise a hard limit (Linux's
 * EPERM without CAP_SYS_RESOURCE). Without it a raise is allowed to
 * succeed or to fail, and the fixture checks the answer either way.
 *
 * Expected values: Linux v6.12 kernel/sys.c (`do_prlimit`: the resource is
 * checked first, then soft against hard, then RLIMIT_NOFILE against
 * `fs.nr_open`, then a raised hard limit against the capability;
 * `prlimit64` reads its new limit before it finds the process and stores
 * the old limit after the new one took effect), fs/file.c (`dup2` to a
 * descriptor at or past the limit is EBADF, a full table EMFILE). */
#include "check.h"

#include <fcntl.h>
#include <stdlib.h>
#include <sys/resource.h>

#define LIMITS 16
/* A process id no system has: past `pid_max`'s largest value. */
#define NO_SUCH_PROCESS 0x7ffffff0

static long get(unsigned resource, struct rlimit *limit) {
    return SYS(SYS_prlimit64, 0, resource, NULL, limit);
}

static long set(unsigned resource, struct rlimit limit) {
    return SYS(SYS_prlimit64, 0, resource, &limit, NULL);
}

int main(int argc, char **argv) {
    int unprivileged = argc > 1 && strcmp(argv[1], "unprivileged") == 0;
    struct rlimit limit, other;

    /* Every resource reads, soft within hard, and the three ways to ask
     * agree. */
    for (unsigned resource = 0; resource < LIMITS; resource++) {
        CHECK(get(resource, &limit) == 0);
        CHECK(limit.rlim_cur <= limit.rlim_max);
        CHECK(SYS(SYS_getrlimit, resource, &other) == 0);
        CHECK(other.rlim_cur == limit.rlim_cur && other.rlim_max == limit.rlim_max);
        CHECK(SYS(SYS_prlimit64, getpid(), resource, NULL, &other) == 0);
        CHECK(other.rlim_cur == limit.rlim_cur && other.rlim_max == limit.rlim_max);
        CHECK(getrlimit((int)resource, &other) == 0);
        CHECK(other.rlim_cur == limit.rlim_cur && other.rlim_max == limit.rlim_max);
    }
    /* RLIM_NLIMITS and above are EINVAL, whoever asks. The resource is an
     * `unsigned int`. */
    for (unsigned resource = LIMITS; resource < LIMITS + 3; resource++) {
        CHECK(get(resource, &limit) == -EINVAL);
        CHECK(SYS(SYS_getrlimit, resource, &limit) == -EINVAL);
        CHECK(SYS(SYS_setrlimit, resource, &limit) == -EINVAL);
    }
    CHECK(get(0xffffffffu, &limit) == -EINVAL);
    CHECK(SYS(SYS_prlimit64, 0, 7, NULL, NULL) == 0);
    /* Another process, which does not exist: ESRCH, after the new limit
     * (here none) was read. */
    CHECK(SYS(SYS_prlimit64, NO_SUCH_PROCESS, 7, NULL, &limit) == -ESRCH);
    CHECK(SYS(SYS_prlimit64, NO_SUCH_PROCESS, 7, UNMAPPED, &limit) == -EFAULT);

    /* Pointers that are not the process's: EFAULT. */
    CHECK(SYS(SYS_getrlimit, 7, UNMAPPED) == -EFAULT);
    CHECK(SYS(SYS_setrlimit, 7, UNMAPPED) == -EFAULT);
    CHECK(SYS(SYS_prlimit64, 0, 7, UNMAPPED, NULL) == -EFAULT);
    CHECK(SYS(SYS_prlimit64, 0, 7, NULL, KERNEL_ADDRESS) == -EFAULT);

    /* Soft above hard is EINVAL; nothing changes. */
    CHECK(get(RLIMIT_CORE, &limit) == 0);
    struct rlimit crossed = {.rlim_cur = 10, .rlim_max = 5};
    CHECK(set(RLIMIT_CORE, crossed) == -EINVAL);
    CHECK(SYS(SYS_setrlimit, RLIMIT_CORE, &crossed) == -EINVAL);
    CHECK(get(RLIMIT_CORE, &other) == 0);
    CHECK(other.rlim_cur == limit.rlim_cur && other.rlim_max == limit.rlim_max);

    /* A limit set reads back, and the old one comes with it. */
    struct rlimit lowered = {.rlim_cur = 0, .rlim_max = limit.rlim_max};
    struct rlimit old;
    CHECK(SYS(SYS_prlimit64, 0, RLIMIT_CORE, &lowered, &old) == 0);
    CHECK(old.rlim_cur == limit.rlim_cur && old.rlim_max == limit.rlim_max);
    CHECK(get(RLIMIT_CORE, &other) == 0);
    CHECK(other.rlim_cur == 0 && other.rlim_max == limit.rlim_max);
    CHECK(SYS(SYS_setrlimit, RLIMIT_CORE, &limit) == 0);
    /* When the old limit cannot be stored the new one has already taken
     * effect. */
    CHECK(SYS(SYS_prlimit64, 0, RLIMIT_CORE, &lowered, UNMAPPED) == -EFAULT);
    CHECK(get(RLIMIT_CORE, &other) == 0);
    CHECK(other.rlim_cur == 0);
    CHECK(set(RLIMIT_CORE, limit) == 0);

    /* Raising a hard limit past its value is the capability's. The
     * first resource with a finite hard limit stands for them all. */
    for (unsigned resource = 0; resource < LIMITS; resource++) {
        CHECK(get(resource, &limit) == 0);
        if (limit.rlim_max == RLIM_INFINITY) continue;
        struct rlimit raised = {.rlim_cur = limit.rlim_cur, .rlim_max = limit.rlim_max + 1};
        long result = set(resource, raised);
        if (unprivileged) CHECK(result == -EPERM);
        CHECK(result == 0 || result == -EPERM);
        CHECK(get(resource, &other) == 0);
        if (result == 0) CHECK(other.rlim_max == limit.rlim_max + 1);
        else CHECK(other.rlim_max == limit.rlim_max);
        CHECK(set(resource, limit) == 0);
        break;
    }

    /* RLIMIT_NOFILE is the table of descriptors' limit. */
    CHECK(get(RLIMIT_NOFILE, &limit) == 0);
    CHECK(limit.rlim_cur >= 3);
    struct rlimit original = limit;
    struct rlimit sixty_four = {.rlim_cur = 64, .rlim_max = limit.rlim_max};
    if (sixty_four.rlim_max < 64) sixty_four.rlim_max = sixty_four.rlim_cur = limit.rlim_max;
    CHECK(set(RLIMIT_NOFILE, sixty_four) == 0);
    CHECK(get(RLIMIT_NOFILE, &other) == 0);
    CHECK(other.rlim_cur == sixty_four.rlim_cur);
    /* Duplicate until the table is full: EMFILE, and no descriptor at or
     * past the limit. */
    int held[64];
    int taken = 0;
    for (;;) {
        int fd = dup(0);
        if (fd < 0) {
            CHECK(errno == EMFILE);
            break;
        }
        CHECK((unsigned long)fd < sixty_four.rlim_cur);
        CHECK(taken < 64);
        held[taken++] = fd;
    }
    CHECK(taken > 0);
    int pipes[2];
    CHECK(pipe(pipes) == -1 && errno == EMFILE);
    /* A descriptor number at the limit is not one a process may name. */
    errno = 0;
    CHECK(dup2(0, (int)sixty_four.rlim_cur) == -1 && errno == EBADF);
    /* Closing one makes room for exactly one. */
    int released = held[--taken];
    CHECK(close(released) == 0);
    CHECK(dup(0) == released);
    CHECK(dup(0) == -1 && errno == EMFILE);
    /* Lowering the limit below descriptors in use keeps them open and
     * admits no new one. */
    struct rlimit tiny = {.rlim_cur = 3, .rlim_max = sixty_four.rlim_max};
    CHECK(set(RLIMIT_NOFILE, tiny) == 0);
    CHECK(close(held[0]) == 0);
    CHECK(dup(0) == -1 && errno == EMFILE);
    CHECK(fcntl(held[1], F_GETFD) >= 0);
    for (int index = 1; index < taken; index++) CHECK(close(held[index]) == 0);
    CHECK(close(released) == 0);
    /* The descriptor table's soft limit is the one set last. */
    CHECK(set(RLIMIT_NOFILE, original) == 0);
    CHECK(get(RLIMIT_NOFILE, &other) == 0);
    CHECK(other.rlim_cur == original.rlim_cur && other.rlim_max == original.rlim_max);
    int fd = dup(0);
    CHECK(fd >= 3);
    CHECK(close(fd) == 0);

    puts("limits: ok");
    return 0;
}
