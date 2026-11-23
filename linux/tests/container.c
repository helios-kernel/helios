/* Container identity, PID namespace, UTS isolation and authority narrowing.
 *
 * Usage: container [pid1]
 *
 * Without an argument the fixture verifies the syscall contracts safely on a
 * host Linux machine. With `pid1` (the mode Helios's smoke lanes run inside a
 * fresh container) it additionally asserts:
 * - the process starts at PID 1 / TID 1 with `sysinfo().procs == 1`;
 * - running as `uid 0` inside a container granted narrow authority still fails
 *   `clock_settime` with `-EPERM` (Linux's root never widens container
 *   authority);
 * - `sethostname` and `setdomainname` update this container's UTS names while
 *   `uid 0` holds `CAP_SYS_ADMIN`, validate bounds (`-EINVAL`) and pointers
 *   (`-EFAULT`), and fail with `-EPERM` once `setuid`/`setgid` drops root;
 * - dropping `uid`/`gid` is irreversible without `CAP_SETUID`/`CAP_SETGID`.
 *
 * Expected values: Linux v6.12 kernel/sys.c (`sethostname`, `setdomainname`,
 * `setuid`, `setgid`), kernel/time/posix-timers.c (`clock_settime`). */
#include "check.h"

#include <stdint.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    int pid1_mode = strcmp(mode, "pid1") == 0;

    long pid = SYS(SYS_getpid);
    long tid = SYS(SYS_gettid);
    CHECK(pid > 0);
    CHECK(tid == pid);
    CHECK((long)getpid() == pid);

    struct sysinfo info;
    memset(&info, 0, sizeof info);
    CHECK(SYS(SYS_sysinfo, &info) == 0);
    CHECK(info.procs >= 1);

    struct utsname name;
    memset(&name, 0, sizeof name);
    CHECK(SYS(SYS_uname, &name) == 0);

    if (pid1_mode) {
        CHECK(pid == 1);
        CHECK(tid == 1);
        CHECK(info.procs == 1);
        CHECK(SYS(SYS_getuid) == 0);
        CHECK(SYS(SYS_geteuid) == 0);
        CHECK(SYS(SYS_getgid) == 0);
        CHECK(SYS(SYS_getegid) == 0);

        /* Container authority ceiling: `uid 0` holds no wall-clock right when
         * the container was not granted one. */
        struct timespec now;
        CHECK(SYS(SYS_clock_gettime, CLOCK_REALTIME, &now) == 0);
        CHECK(SYS(SYS_clock_settime, CLOCK_REALTIME, &now) == -EPERM);

        /* Container-local UTS names while `uid 0` holds `CAP_SYS_ADMIN`. */
        static const char host[] = "helios-box";
        static const char domain[] = "box.local";
        CHECK(SYS(SYS_sethostname, host, (long)(sizeof host - 1)) == 0);
        CHECK(SYS(SYS_setdomainname, domain, (long)(sizeof domain - 1)) == 0);
        memset(&name, 0, sizeof name);
        CHECK(SYS(SYS_uname, &name) == 0);
        CHECK(strcmp(name.nodename, host) == 0);
        CHECK(strcmp(name.domainname, domain) == 0);

        /* Length and fault checks mirror Linux `sethostname` / `setdomainname`. */
        CHECK(SYS(SYS_sethostname, host, -1L) == -EINVAL);
        CHECK(SYS(SYS_sethostname, host, 65L) == -EINVAL);
        CHECK(SYS(SYS_sethostname, UNMAPPED, 4L) == -EFAULT);
        CHECK(SYS(SYS_setdomainname, domain, -1L) == -EINVAL);
        CHECK(SYS(SYS_setdomainname, domain, 65L) == -EINVAL);
        CHECK(SYS(SYS_setdomainname, KERNEL_ADDRESS, 4L) == -EFAULT);

        /* Dropping privilege narrows what this process may do inside the
         * container and cannot be undone once `CAP_SETUID`/`CAP_SETGID` leave. */
        CHECK(SYS(SYS_setgid, 1000) == 0);
        CHECK(SYS(SYS_setuid, 1000) == 0);
        CHECK(SYS(SYS_getuid) == 1000);
        CHECK(SYS(SYS_geteuid) == 1000);
        CHECK(SYS(SYS_getgid) == 1000);
        CHECK(SYS(SYS_getegid) == 1000);

        CHECK(SYS(SYS_sethostname, "nope", 4L) == -EPERM);
        CHECK(SYS(SYS_setdomainname, "nope", 4L) == -EPERM);
        CHECK(SYS(SYS_setuid, 0) == -EPERM);
        CHECK(SYS(SYS_setgid, 0) == -EPERM);

        memset(&name, 0, sizeof name);
        CHECK(SYS(SYS_uname, &name) == 0);
        CHECK(strcmp(name.nodename, host) == 0);
        CHECK(strcmp(name.domainname, domain) == 0);
    } else if (SYS(SYS_getuid) != 0) {
        CHECK(SYS(SYS_sethostname, "nope", 4L) == -EPERM);
        CHECK(SYS(SYS_setdomainname, "nope", 4L) == -EPERM);
        CHECK(SYS(SYS_setuid, 0) == -EPERM);
        CHECK(SYS(SYS_setgid, 0) == -EPERM);
    }

    puts("container: ok");
    return 0;
}
