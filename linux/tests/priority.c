/* umask, getpriority and setpriority.
 *
 * Usage: priority [unprivileged]
 *
 * `unprivileged` asserts the process may not lower its nice value (Linux's
 * EACCES without CAP_SYS_NICE and with RLIMIT_NICE at 0, which the fixture
 * sets). Without it the lowering may succeed or fail, and the fixture
 * checks the answer either way.
 *
 * Expected values: Linux v6.12 kernel/sys.c (`umask` swaps the mask and
 * keeps the permission bits; `setpriority` clamps the value to -20..19,
 * answers EINVAL for an unknown `which` and ESRCH for a process it finds
 * none of, and refuses a lowered nice value with EACCES unless
 * `can_nice`; `getpriority` returns 20 - nice), kernel/sched/syscalls.c
 * (`can_nice`), include/linux/sched/prio.h (`nice_to_rlimit`). */
#include "check.h"

#include <stdlib.h>
#include <sys/resource.h>
#include <sys/stat.h>

/* A process id no system has: past `pid_max`'s largest value. */
#define NO_SUCH_PROCESS 0x7ffffff0

/* The kernel's own getpriority: 20 - nice, so 1 to 40. */
static long raw_priority(int which, int who) {
    return SYS(SYS_getpriority, which, who);
}

static long raw_set(int which, int who, int nice) {
    return SYS(SYS_setpriority, which, who, nice);
}

int main(int argc, char **argv) {
    int unprivileged = argc > 1 && strcmp(argv[1], "unprivileged") == 0;

    /* umask swaps the mask in and returns the previous one; bits above the
     * permission bits are dropped. */
    mode_t original = umask(077);
    CHECK(original <= 0777);
    CHECK(umask(027) == 077);
    CHECK(umask(07777) == 027);
    CHECK(umask(0) == 0777);
    CHECK(umask(original) == 0);
    CHECK(SYS(SYS_umask, 022) == original);
    CHECK(SYS(SYS_umask, 0xfffff000 | 077) == 022);
    CHECK(SYS(SYS_umask, original) == 077);

    /* The default nice value, as `20 - nice`. */
    long raw = raw_priority(PRIO_PROCESS, 0);
    CHECK(raw >= 1 && raw <= 40);
    int nice = 20 - (int)raw;
    CHECK(getpriority(PRIO_PROCESS, 0) == nice);
    CHECK(raw_priority(PRIO_PROCESS, getpid()) == raw);
    /* The group and the user this process belongs to hold at least it. */
    CHECK(raw_priority(PRIO_PGRP, 0) >= 1);
    CHECK(raw_priority(PRIO_USER, 0) >= 1);

    /* Raising the nice value is always allowed, by value and by process
     * id, and clamps at 19. */
    struct rlimit no_raise = {.rlim_cur = 0, .rlim_max = 0};
    CHECK(SYS(SYS_prlimit64, 0, RLIMIT_NICE, &no_raise, NULL) == 0);
    int raised = nice + 3 > 19 ? 19 : nice + 3;
    CHECK(raw_set(PRIO_PROCESS, 0, raised) == 0);
    CHECK(raw_priority(PRIO_PROCESS, 0) == 20 - raised);
    CHECK(raw_set(PRIO_PROCESS, getpid(), 100) == 0);
    CHECK(raw_priority(PRIO_PROCESS, 0) == 1);
    CHECK(setpriority(PRIO_PROCESS, 0, 19) == 0);
    CHECK(getpriority(PRIO_PROCESS, 0) == 19);

    /* Lowering it needs RLIMIT_NICE, which is 0, or CAP_SYS_NICE. */
    long lowered = raw_set(PRIO_PROCESS, 0, 5);
    if (unprivileged) CHECK(lowered == -EACCES);
    CHECK(lowered == 0 || lowered == -EACCES);
    CHECK(raw_priority(PRIO_PROCESS, 0) == (lowered == 0 ? 15 : 1));
    long far_lowered = raw_set(PRIO_PROCESS, 0, -100);
    if (unprivileged) CHECK(far_lowered == -EACCES);
    CHECK(far_lowered == 0 || far_lowered == -EACCES);
    CHECK(raw_priority(PRIO_PROCESS, 0) == (far_lowered == 0 ? 40 : lowered == 0 ? 15 : 1));

    /* An unknown `which` is EINVAL, a process that does not exist ESRCH. */
    for (int which = 3; which < 6; which++) {
        CHECK(raw_priority(which, 0) == -EINVAL);
        CHECK(raw_set(which, 0, 0) == -EINVAL);
    }
    CHECK(raw_priority(-1, 0) == -EINVAL);
    CHECK(raw_set(-1, 0, 0) == -EINVAL);
    CHECK(raw_priority(PRIO_PROCESS, NO_SUCH_PROCESS) == -ESRCH);
    CHECK(raw_set(PRIO_PROCESS, NO_SUCH_PROCESS, 0) == -ESRCH);
    CHECK(raw_priority(PRIO_PGRP, NO_SUCH_PROCESS) == -ESRCH);
    CHECK(raw_set(PRIO_PGRP, NO_SUCH_PROCESS, 0) == -ESRCH);

    puts("priority: ok");
    return 0;
}
