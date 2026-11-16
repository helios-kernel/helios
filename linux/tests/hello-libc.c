#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>

_Thread_local int value = 41;
_Thread_local int zero;

static int unix_io(void) {
    int event = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    int epoll = epoll_create1(EPOLL_CLOEXEC);
    if (event < 0 || epoll < 0) return 10;
    struct epoll_event registration = { .events = EPOLLIN | EPOLLONESHOT, .data.u64 = 0x1122334455667788 };
    struct epoll_event ready;
    if (epoll_ctl(epoll, EPOLL_CTL_ADD, event, &registration)) return 11;
    if (epoll_wait(epoll, &ready, 1, 0) != 0) return 12;
    int duplicate = dup(event);
    uint64_t value = 7;
    if (duplicate < 0 || write(duplicate, &value, sizeof(value)) != sizeof(value)) return 13;
    if (epoll_wait(epoll, &ready, 1, 0) != 1 || ready.events != EPOLLIN || ready.data.u64 != registration.data.u64) return 14;
    if (epoll_wait(epoll, &ready, 1, 0) != 0) return 15;
    if (epoll_ctl(epoll, EPOLL_CTL_MOD, event, &registration) || epoll_wait(epoll, &ready, 1, 0) != 1) return 16;
    if (read(event, &value, sizeof(value)) != sizeof(value) || value != 7) return 17;
    errno = 0;
    if (read(duplicate, &value, sizeof(value)) != -1 || errno != EAGAIN) return 18;
    if (close(duplicate) || close(event) || close(epoll)) return 19;
    int fds[2];
    if (pipe2(fds, O_NONBLOCK | O_CLOEXEC)) return 20;
    if (write(fds[1], "abcdef", 6) != 6) return 21;
    char bytes[6];
    if (read(fds[0], bytes, 2) != 2) return 22;
    duplicate = dup(fds[0]);
    if (duplicate < 0 || read(duplicate, bytes + 2, 4) != 4 || memcmp(bytes, "abcdef", 6)) return 23;
    if (close(fds[1]) || read(fds[0], bytes, sizeof(bytes)) != 0) return 24;
    if (close(duplicate) || close(fds[0])) return 25;
    errno = 0;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 1 || !argv[0] || value++ != 41 || zero++ != 0) return 1;
    errno = 0;
    if (getpid() <= 0 || syscall(SYS_gettid) != getpid()) return 2;
#ifdef __x86_64__
    unsigned long fs_base = 0;
    /* Linux x86-64 ARCH_GET_FS; compare the syscall result to the real TLS register. */
    if (syscall(SYS_arch_prctl, 0x1003, &fs_base) != 0 ||
        fs_base != (unsigned long)__builtin_thread_pointer()) return 3;
    /* A user output pointer must not let the syscall overwrite executable text. */
    if (syscall(SYS_arch_prctl, 0x1003, (void *)main) != -1 || errno != EFAULT) return 5;
#else
    /* aarch64 user code owns TPIDR_EL0; the thread-local values above
     * already proved the kernel kept it across every call. */
    if (!__builtin_thread_pointer()) return 3;
#endif
    int io_result = unix_io();
    if (io_result) return io_result;
    errno = 0;
    if (printf("Hello, %s!\n", "World") < 0) return 4;
    return value != 42 || zero != 1 || errno != 0;
}
