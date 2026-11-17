/* clock_gettime, clock_getres, clock_settime, gettimeofday and time.
 *
 * Usage: clock [denied|allowed]
 *
 * Without an argument the fixture never sets the clock to a valid time.
 * `denied` asserts the process may not set it (Linux's EPERM without
 * CAP_SYS_TIME; on Helios, an authority without the right to set the wall
 * clock). `allowed` asserts it may, sets the clock forward and back, and
 * checks the readings follow.
 *
 * Expected values: Linux v6.12 kernel/time/posix-timers.c (clock_gettime,
 * clock_getres and clock_settime dispatch on the clock's `k_clock`),
 * kernel/time/posix-cpu-timers.c (CPU-time clocks have no setter and read
 * at 1 ns), kernel/time/time.c (gettimeofday, time, and
 * `do_sys_settimeofday64`, which validates the time before it asks for the
 * capability). */
#include "check.h"

#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

static long long nanos(struct timespec time) {
    return time.tv_sec * 1000000000LL + time.tv_nsec;
}

static long get(int clock, struct timespec *time) {
    return SYS(SYS_clock_gettime, clock, time);
}

static void normalized(struct timespec time) {
    CHECK(time.tv_sec >= 0);
    CHECK(time.tv_nsec >= 0 && time.tv_nsec < 1000000000);
}

/* Reads `clock` until it moves, so a coarse clock is not mistaken for a
 * stuck one. */
static struct timespec advanced(int clock, struct timespec from) {
    struct timespec now;
    for (long spin = 0; spin < (1L << 28); spin++) {
        CHECK(get(clock, &now) == 0);
        if (nanos(now) > nanos(from)) return now;
    }
    CHECK(!"the clock never advanced");
    return now;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    struct timespec first, second, resolution;

    /* uapi/linux/time.h: every clock a kernel keeps. */
    static const int readable[] = {
        CLOCK_REALTIME,           CLOCK_MONOTONIC,
        CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID,
        CLOCK_MONOTONIC_RAW,      CLOCK_REALTIME_COARSE,
        CLOCK_MONOTONIC_COARSE,   CLOCK_BOOTTIME,
        CLOCK_TAI,
    };
    for (size_t index = 0; index < sizeof readable / sizeof *readable; index++) {
        int clock = readable[index];
        CHECK(get(clock, &first) == 0);
        normalized(first);
        /* Resolution is below a second, at least a nanosecond, and at most
         * a 100 Hz tick (the coarsest `KTIME_LOW_RES` of a kernel). */
        CHECK(SYS(SYS_clock_getres, clock, &resolution) == 0);
        CHECK(resolution.tv_sec == 0);
        CHECK(resolution.tv_nsec >= 1 && resolution.tv_nsec <= 10000000);
        /* clock_getres(2): a null `res` only asks whether the clock exists. */
        CHECK(SYS(SYS_clock_getres, clock, NULL) == 0);
        CHECK(SYS(SYS_clock_gettime, clock, UNMAPPED) == -EFAULT);
        CHECK(SYS(SYS_clock_gettime, clock, KERNEL_ADDRESS) == -EFAULT);
        CHECK(SYS(SYS_clock_getres, clock, UNMAPPED) == -EFAULT);
    }

    /* No clock has these numbers (posix_clocks[] is NULL there or ends
     * before them), and -1 is a malformed CPU-clock ID. The alarm clocks
     * (8 and 9) are left out: a machine with a wake-capable RTC reads them.
     * So are the auxiliary clocks CLOCK_AUX..CLOCK_AUX_LAST (16..23, Linux
     * 6.17): a kernel built with CONFIG_POSIX_AUX_CLOCKS answers ENODEV for
     * one not enabled, and one built without it answers EINVAL; 24 is the
     * first number past them. */
    static const int unknown[] = {10, 12, 15, 24, 1000, -1};
    for (size_t index = 0; index < sizeof unknown / sizeof *unknown; index++) {
        int clock = unknown[index];
        CHECK(get(clock, &first) == -EINVAL);
        CHECK(SYS(SYS_clock_getres, clock, &resolution) == -EINVAL);
        CHECK(SYS(SYS_clock_getres, clock, NULL) == -EINVAL);
        CHECK(SYS(SYS_clock_settime, clock, &first) == -EINVAL);
    }

    /* The monotonic clocks never go backwards, and advance. */
    static const int monotonic[] = {CLOCK_MONOTONIC, CLOCK_MONOTONIC_RAW,
                                    CLOCK_BOOTTIME};
    for (size_t index = 0; index < sizeof monotonic / sizeof *monotonic; index++) {
        CHECK(get(monotonic[index], &first) == 0);
        second = advanced(monotonic[index], first);
        CHECK(nanos(second) > nanos(first));
    }

    /* The CPU-time clocks count time the thread ran: busy work moves them,
     * and the process, which holds the thread, has run at least as long. */
    CHECK(get(CLOCK_THREAD_CPUTIME_ID, &first) == 0);
    volatile unsigned long sink = 0;
    for (unsigned long step = 0; step < 20000000UL; step++) sink += step;
    CHECK(get(CLOCK_THREAD_CPUTIME_ID, &second) == 0);
    CHECK(nanos(second) > nanos(first));
    struct timespec process;
    CHECK(get(CLOCK_PROCESS_CPUTIME_ID, &process) == 0);
    CHECK(nanos(process) >= nanos(second));

    /* gettimeofday and time agree with the real-time clock. */
    struct timespec before, after;
    struct timeval day;
    struct timezone zone;
    CHECK(get(CLOCK_REALTIME, &before) == 0);
    CHECK(SYS(SYS_gettimeofday, &day, NULL) == 0);
    CHECK(day.tv_usec >= 0 && day.tv_usec < 1000000);
    CHECK(SYS(SYS_gettimeofday, &day, &zone) == 0);
    CHECK(SYS(SYS_gettimeofday, NULL, &zone) == 0);
    CHECK(SYS(SYS_gettimeofday, NULL, NULL) == 0);
    CHECK(get(CLOCK_REALTIME, &after) == 0);
    long long microseconds = day.tv_sec * 1000000LL + day.tv_usec;
    CHECK(microseconds >= nanos(before) / 1000 - 5000000);
    CHECK(microseconds <= nanos(after) / 1000 + 5000000);
    CHECK(SYS(SYS_gettimeofday, UNMAPPED, NULL) == -EFAULT);
    CHECK(SYS(SYS_gettimeofday, &day, UNMAPPED) == -EFAULT);
    CHECK(SYS(SYS_gettimeofday, KERNEL_ADDRESS, NULL) == -EFAULT);
    /* The libc entry points reach the same clock. */
    CHECK(llabs((long long)time(NULL) - after.tv_sec) <= 5);
#ifdef SYS_time
    /* Only x86-64 has a `time` system call (aarch64's asm-generic table
     * has none, and libc reads the clock there). */
    time_t seconds = 0;
    long result = SYS(SYS_time, &seconds);
    CHECK(result == seconds);
    CHECK(llabs(seconds - after.tv_sec) <= 5);
    CHECK(SYS(SYS_time, NULL) >= seconds);
    CHECK(SYS(SYS_time, UNMAPPED) == -EFAULT);
#endif

    /* clock_settime: only the real-time clock has a setter, and the time is
     * validated before the caller's right to set it is. */
    CHECK(get(CLOCK_REALTIME, &first) == 0);
    static const int fixed[] = {CLOCK_MONOTONIC,
                                CLOCK_PROCESS_CPUTIME_ID,
                                CLOCK_THREAD_CPUTIME_ID,
                                CLOCK_MONOTONIC_RAW,
                                CLOCK_REALTIME_COARSE,
                                CLOCK_MONOTONIC_COARSE,
                                CLOCK_BOOTTIME,
                                CLOCK_TAI};
    for (size_t index = 0; index < sizeof fixed / sizeof *fixed; index++)
        CHECK(SYS(SYS_clock_settime, fixed[index], &first) == -EINVAL);
    struct timespec before_epoch = {-1, 0};
    struct timespec whole_second = {0, 1000000000};
    struct timespec negative_nanoseconds = {0, -1};
    struct timespec past_the_end = {INT64_MAX, 0};
    CHECK(SYS(SYS_clock_settime, CLOCK_REALTIME, &before_epoch) == -EINVAL);
    CHECK(SYS(SYS_clock_settime, CLOCK_REALTIME, &whole_second) == -EINVAL);
    CHECK(SYS(SYS_clock_settime, CLOCK_REALTIME, &negative_nanoseconds) == -EINVAL);
    CHECK(SYS(SYS_clock_settime, CLOCK_REALTIME, &past_the_end) == -EINVAL);
    CHECK(SYS(SYS_clock_settime, CLOCK_REALTIME, UNMAPPED) == -EFAULT);

    if (strcmp(mode, "denied") == 0) {
        CHECK(SYS(SYS_clock_settime, CLOCK_REALTIME, &first) == -EPERM);
        CHECK(get(CLOCK_REALTIME, &second) == 0);
        CHECK(nanos(second) >= nanos(first));
        CHECK(nanos(second) - nanos(first) < 5000000000LL);
    } else if (strcmp(mode, "allowed") == 0) {
        struct timespec later = first;
        later.tv_sec += 100;
        CHECK(SYS(SYS_clock_settime, CLOCK_REALTIME, &later) == 0);
        CHECK(get(CLOCK_REALTIME, &second) == 0);
        CHECK(nanos(second) >= nanos(later));
        CHECK(nanos(second) - nanos(later) < 5000000000LL);
        /* The monotonic clock is not the wall clock's to move. */
        CHECK(get(CLOCK_MONOTONIC, &after) == 0);
        CHECK(nanos(after) < nanos(later));
        CHECK(SYS(SYS_clock_settime, CLOCK_REALTIME, &first) == 0);
        CHECK(get(CLOCK_REALTIME, &second) == 0);
        CHECK(nanos(second) - nanos(first) < 5000000000LL);
    }

    puts("clock: ok");
    return 0;
}
