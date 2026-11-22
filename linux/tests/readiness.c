/* Readiness multiplexing (`poll`, `ppoll`, `select`, `pselect6`, `epoll` on
 * pipes, eventfds, regular files and stdin), `O_NONBLOCK` stdin reads, and
 * thread-local blocking suspension.
 *
 * Usage:
 *   readiness               Run core readiness + multi-thread blocking checks.
 *   readiness stdin-quiet   Also verify `epoll_ctl` on inherited fd 0 and
 *                           `O_NONBLOCK` read on quiet fd 0 returning EAGAIN.
 */
#include "check.h"

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/select.h>
#include <time.h>

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

struct block_args {
    int read_fd;
    int woke;
};

static void *blocked_poller(void *arg) {
    struct block_args *ctx = (struct block_args *)arg;
    struct pollfd pfd = { .fd = ctx->read_fd, .events = POLLIN, .revents = 0 };
    long rc = SYS(SYS_ppoll, &pfd, 1, NULL, NULL, 8);
    CHECK(rc == 1);
    CHECK((pfd.revents & POLLIN) != 0);
    char ch = 0;
    CHECK(SYS(SYS_read, ctx->read_fd, &ch, 1) == 1);
    CHECK(ch == 'K');
    ctx->woke = 1;
    return NULL;
}

static void check_poll_and_ppoll(void) {
    int pfds[2];
    CHECK(SYS(SYS_pipe2, pfds, O_CLOEXEC) == 0);
    int evfd = (int)SYS(SYS_eventfd2, 0, O_CLOEXEC);
    CHECK(evfd >= 0);

    /* Pipe write end + eventfd writable; read end not yet readable; invalid fd -> POLLNVAL */
    struct pollfd fds[4] = {
        { .fd = pfds[0], .events = POLLIN, .revents = 0 },
        { .fd = pfds[1], .events = POLLOUT, .revents = 0 },
        { .fd = -1, .events = POLLIN, .revents = 0x55 },
        { .fd = 998, .events = POLLIN, .revents = 0 },
    };
    struct timespec zero = { .tv_sec = 0, .tv_nsec = 0 };
    CHECK(SYS(SYS_ppoll, fds, 4, &zero, NULL, 8) == 2);
    CHECK(fds[0].revents == 0);
    CHECK((fds[1].revents & POLLOUT) != 0);
    CHECK(fds[2].revents == 0);
    CHECK(fds[3].revents == POLLNVAL);

    /* Short timeout expiration */
    struct pollfd wait_read = { .fd = pfds[0], .events = POLLIN, .revents = 0 };
    struct timespec short_ts = { .tv_sec = 0, .tv_nsec = 2 * 1000 * 1000 };
    CHECK(SYS(SYS_ppoll, &wait_read, 1, &short_ts, NULL, 8) == 0);
    CHECK(wait_read.revents == 0);

    /* Invalid timespec -> EINVAL */
    struct timespec bad_ts = { .tv_sec = 0, .tv_nsec = 1000000000L };
    CHECK(SYS(SYS_ppoll, &wait_read, 1, &bad_ts, NULL, 8) == -EINVAL);

    /* Write pipe + eventfd -> both become POLLIN */
    CHECK(SYS(SYS_write, pfds[1], "x", 1) == 1);
    uint64_t inc = 1;
    CHECK(SYS(SYS_write, evfd, &inc, 8) == 8);
    struct pollfd both[2] = {
        { .fd = pfds[0], .events = POLLIN, .revents = 0 },
        { .fd = evfd, .events = POLLIN, .revents = 0 },
    };
    CHECK(SYS(SYS_ppoll, both, 2, &zero, NULL, 8) == 2);
    CHECK((both[0].revents & POLLIN) != 0);
    CHECK((both[1].revents & POLLIN) != 0);

#ifdef SYS_poll
    both[0].revents = 0;
    both[1].revents = 0;
    CHECK(SYS(SYS_poll, both, 2, 0) == 2);
    CHECK((both[0].revents & POLLIN) != 0);
    CHECK((both[1].revents & POLLIN) != 0);
#endif

    /* Drain pipe and close writer -> POLLHUP */
    char ch = 0;
    CHECK(SYS(SYS_read, pfds[0], &ch, 1) == 1);
    CHECK(SYS(SYS_close, pfds[1]) == 0);
    wait_read.revents = 0;
    CHECK(SYS(SYS_ppoll, &wait_read, 1, &zero, NULL, 8) == 1);
    CHECK((wait_read.revents & POLLHUP) != 0);

    CHECK(SYS(SYS_close, pfds[0]) == 0);
    CHECK(SYS(SYS_close, evfd) == 0);
}

static void check_select_and_pselect6(void) {
    int pfds[2];
    CHECK(SYS(SYS_pipe2, pfds, O_CLOEXEC) == 0);

    fd_set rfds, wfds;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_SET(pfds[0], &rfds);
    FD_SET(pfds[1], &wfds);
    struct timespec zero = { .tv_sec = 0, .tv_nsec = 0 };
    int nfds = (pfds[0] > pfds[1] ? pfds[0] : pfds[1]) + 1;
    CHECK(SYS(SYS_pselect6, nfds, &rfds, &wfds, NULL, &zero, NULL) == 1);
    CHECK(!FD_ISSET(pfds[0], &rfds));
    CHECK(FD_ISSET(pfds[1], &wfds));

    /* Write then check both readable & writable */
    CHECK(SYS(SYS_write, pfds[1], "y", 1) == 1);
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_SET(pfds[0], &rfds);
    FD_SET(pfds[1], &wfds);
#ifdef SYS_select
    struct timeval tv = { .tv_sec = 0, .tv_usec = 5000 };
    CHECK(SYS(SYS_select, nfds, &rfds, &wfds, NULL, &tv) == 2);
#else
    CHECK(SYS(SYS_pselect6, nfds, &rfds, &wfds, NULL, &zero, NULL) == 2);
#endif
    CHECK(FD_ISSET(pfds[0], &rfds));
    CHECK(FD_ISSET(pfds[1], &wfds));

    /* Closed fd in fd_set -> EBADF; negative nfds -> EINVAL */
    FD_ZERO(&rfds);
    FD_SET(997, &rfds);
    CHECK(SYS(SYS_pselect6, 998, &rfds, NULL, NULL, &zero, NULL) == -EBADF);
    CHECK(SYS(SYS_pselect6, -1L, NULL, NULL, NULL, &zero, NULL) == -EINVAL);

    /* Close write end -> EOF makes read end ready in readfds */
    char ch = 0;
    CHECK(SYS(SYS_read, pfds[0], &ch, 1) == 1);
    CHECK(SYS(SYS_close, pfds[1]) == 0);
    FD_ZERO(&rfds);
    FD_SET(pfds[0], &rfds);
    CHECK(SYS(SYS_pselect6, pfds[0] + 1, &rfds, NULL, NULL, &zero, NULL) == 1);
    CHECK(FD_ISSET(pfds[0], &rfds));
    CHECK(SYS(SYS_close, pfds[0]) == 0);
}

static void check_regular_file_readiness(void) {
    long mk = SYS(SYS_mkdirat, AT_FDCWD, "/tmp", 0755);
    CHECK(mk == 0 || mk == -EEXIST);
    char path[128];
    snprintf(path, sizeof path, "/tmp/helios-ready-%ld", SYS(SYS_getpid));
    int fd = (int)SYS(SYS_openat, AT_FDCWD, path, O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0644);
    CHECK(fd >= 0);

    /* Regular file is always ready in poll/pselect6, and refused by epoll_ctl with EPERM */
    struct pollfd pfd = { .fd = fd, .events = POLLIN | POLLOUT, .revents = 0 };
    struct timespec zero = { .tv_sec = 0, .tv_nsec = 0 };
    CHECK(SYS(SYS_ppoll, &pfd, 1, &zero, NULL, 8) == 1);
    CHECK((pfd.revents & (POLLIN | POLLOUT)) == (POLLIN | POLLOUT));

    int ep = (int)SYS(SYS_epoll_create1, EPOLL_CLOEXEC);
    CHECK(ep >= 0);
    struct epoll_event ev = { .events = EPOLLIN, .data.u64 = 1 };
    CHECK(SYS(SYS_epoll_ctl, ep, EPOLL_CTL_ADD, fd, &ev) == -EPERM);
    CHECK(SYS(SYS_close, ep) == 0);
    CHECK(SYS(SYS_close, fd) == 0);
    CHECK(SYS(SYS_unlinkat, AT_FDCWD, path, 0) == 0);
}

static void check_thread_blocking(void) {
    int pfds[2];
    CHECK(SYS(SYS_pipe2, pfds, O_CLOEXEC) == 0);
    struct block_args ctx = { .read_fd = pfds[0], .woke = 0 };
    pthread_t worker;
    CHECK(pthread_create(&worker, NULL, blocked_poller, &ctx) == 0);

    struct timespec pause = { .tv_sec = 0, .tv_nsec = 5 * 1000 * 1000 };
    CHECK(nanosleep(&pause, NULL) == 0);
    CHECK(ctx.woke == 0);
    CHECK(SYS(SYS_write, pfds[1], "K", 1) == 1);
    CHECK(pthread_join(worker, NULL) == 0);
    CHECK(ctx.woke == 1);

    CHECK(SYS(SYS_close, pfds[0]) == 0);
    CHECK(SYS(SYS_close, pfds[1]) == 0);
}

static void check_stdin_epoll_only(void) {
    int ep = (int)SYS(SYS_epoll_create1, EPOLL_CLOEXEC);
    CHECK(ep >= 0);
    struct epoll_event ev = { .events = EPOLLIN, .data.u64 = 0x57d10ULL };
    CHECK(SYS(SYS_epoll_ctl, ep, EPOLL_CTL_ADD, 0, &ev) == 0);
    CHECK(SYS(SYS_epoll_ctl, ep, EPOLL_CTL_DEL, 0, NULL) == 0);
    CHECK(SYS(SYS_close, ep) == 0);
}

static void check_stdin_epoll_and_nonblock(void) {
    int ep = (int)SYS(SYS_epoll_create1, EPOLL_CLOEXEC);
    CHECK(ep >= 0);
    struct epoll_event ev = { .events = EPOLLIN, .data.u64 = 0x57d10ULL };
    CHECK(SYS(SYS_epoll_ctl, ep, EPOLL_CTL_ADD, 0, &ev) == 0);

    struct epoll_event out;
    CHECK(SYS(SYS_epoll_pwait, ep, &out, 1, 0, NULL, 8) == 0);
    CHECK(SYS(SYS_epoll_ctl, ep, EPOLL_CTL_DEL, 0, NULL) == 0);
    CHECK(SYS(SYS_close, ep) == 0);

    long old_fl = SYS(SYS_fcntl, 0, F_GETFL);
    CHECK(old_fl >= 0);
    CHECK(SYS(SYS_fcntl, 0, F_SETFL, old_fl | O_NONBLOCK) == 0);
    CHECK((SYS(SYS_fcntl, 0, F_GETFL) & O_NONBLOCK) != 0);
    char b = 0;
    CHECK(SYS(SYS_read, 0, &b, 1) == -EAGAIN);
    CHECK(SYS(SYS_fcntl, 0, F_SETFL, old_fl) == 0);
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "hold-open") == 0) {
        struct timespec pause = { .tv_sec = 0, .tv_nsec = 200 * 1000 * 1000 };
        (void)nanosleep(&pause, NULL);
        return 0;
    }

    int stdin_quiet = argc >= 2 && strcmp(argv[1], "stdin-quiet") == 0;
    int stdin_epoll = argc >= 2 && strcmp(argv[1], "stdin-epoll") == 0;

    check_poll_and_ppoll();
    check_select_and_pselect6();
    check_regular_file_readiness();
    check_thread_blocking();
    if (stdin_quiet) {
        check_stdin_epoll_and_nonblock();
    } else if (stdin_epoll) {
        check_stdin_epoll_only();
    }

    puts("readiness: ok");
    return 0;
}
