/* Native Linux signal handling, delivery, fault signals, and interval timers
 * fixture (#1033). Driven by check-signals.sh on Linux (in build-fixtures.sh)
 * and under Helios's dash. */
#include "check.h"
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <time.h>

static volatile sig_atomic_t g_last_sig = 0;
static volatile sig_atomic_t g_last_code = 0;
static volatile sig_atomic_t g_last_pid = 0;
static volatile sig_atomic_t g_handler_count = 0;
static volatile sig_atomic_t g_nested_depth = 0;
static volatile sig_atomic_t g_max_depth = 0;
static volatile sig_atomic_t g_on_altstack = 0;
static volatile sig_atomic_t g_altstack_eperm = 0;
static volatile sig_atomic_t g_altstack_disarmed = 0;
static volatile uintptr_t g_handler_sp = 0;
static volatile uintptr_t g_fault_addr = 0;
static volatile sig_atomic_t g_fault_code = 0;
static void *g_ro_page = NULL;
static size_t g_page_size = 4096;
static sigjmp_buf g_jump_env;
static _Atomic int g_thread_sig_tid = 0;
static _Atomic int g_thread_sig_count = 0;
static _Atomic int g_pipe_sig_received = 0;
static _Atomic int g_alrm_count = 0;
static _Atomic int g_vtalrm_count = 0;
static _Atomic int g_prof_count = 0;

static void basic_siginfo_handler(int sig, siginfo_t *info, void *ucontext) {
    (void)ucontext;
    /* Clobber floating-point / vector registers inside the handler to verify
     * rt_sigreturn restores the interrupted context's FP/SIMD state intact. */
    volatile double a = 3.14159265358979;
    volatile double b = 2.71828182845904;
    volatile double c = a * b + a / b;
    (void)c;

    g_last_sig = sig;
    g_last_code = info ? info->si_code : -999;
    g_last_pid = info ? (sig_atomic_t)info->si_pid : -1;
    g_handler_count++;
}

static void nodefer_handler(int sig) {
    int depth = ++g_nested_depth;
    if (depth > g_max_depth) {
        g_max_depth = depth;
    }
    if (depth == 1) {
        raise(sig);
    }
    g_nested_depth--;
}

static void resethand_handler(int sig) {
    g_last_sig = sig;
    g_handler_count++;
}

static void altstack_handler(int sig) {
    volatile char local_var = (char)sig;
    g_handler_sp = (uintptr_t)&local_var;
    stack_t cur;
    if (sigaltstack(NULL, &cur) == 0) {
        if (cur.ss_flags & SS_ONSTACK) {
            g_on_altstack = 1;
        }
        if (cur.ss_flags & SS_DISABLE) {
            g_altstack_disarmed = 1;
        }
    }
    /* Attempting to change the alternate stack while executing on it must
     * fail with EPERM (unless SS_AUTODISARM disarmed it). */
    stack_t disable = {.ss_flags = SS_DISABLE};
    if (sigaltstack(&disable, NULL) == -1 && errno == EPERM) {
        g_altstack_eperm = 1;
    }
    g_handler_count++;
}

static void restart_handler(int sig) {
    (void)sig;
    g_handler_count++;
}

static void pipe_handler(int sig) {
    (void)sig;
    atomic_fetch_add(&g_pipe_sig_received, 1);
}

static void thread_sig_handler(int sig) {
    (void)sig;
    atomic_store(&g_thread_sig_tid, (int)syscall(SYS_gettid));
    atomic_fetch_add(&g_thread_sig_count, 1);
}

static void timer_handler(int sig) {
    if (sig == SIGALRM) {
        atomic_fetch_add(&g_alrm_count, 1);
    } else if (sig == SIGVTALRM) {
        atomic_fetch_add(&g_vtalrm_count, 1);
    } else if (sig == SIGPROF) {
        atomic_fetch_add(&g_prof_count, 1);
    }
}

static void segv_mprotect_handler(int sig, siginfo_t *info, void *ucontext) {
    (void)ucontext;
    if (sig == SIGSEGV && info && info->si_addr == g_ro_page) {
        g_fault_addr = (uintptr_t)info->si_addr;
        g_fault_code = info->si_code;
        if (mprotect(g_ro_page, g_page_size, PROT_READ | PROT_WRITE) == 0) {
            g_handler_count++;
            return;
        }
    }
    _exit(99);
}

static void fault_longjmp_handler(int sig, siginfo_t *info, void *ucontext) {
    (void)ucontext;
    g_last_sig = sig;
    g_fault_code = info ? info->si_code : 0;
    g_fault_addr = info ? (uintptr_t)info->si_addr : 0;
    siglongjmp(g_jump_env, sig);
}

static void test_handlers(void) {
    struct sigaction sa;
    struct sigaction old;

    /* SIGKILL and SIGSTOP cannot be caught or ignored, but read-only query succeeds. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = resethand_handler;
    CHECK(sigaction(SIGKILL, &sa, NULL) == -1 && errno == EINVAL);
    CHECK(sigaction(SIGSTOP, &sa, NULL) == -1 && errno == EINVAL);
    CHECK(sigaction(SIGKILL, NULL, &old) == 0 && old.sa_handler == SIG_DFL);
    CHECK(sigaction(SIGSTOP, NULL, &old) == 0 && old.sa_handler == SIG_DFL);

    /* Basic SA_SIGINFO handler + FP register preservation across rt_sigreturn. */
    g_last_sig = 0;
    g_last_code = -1;
    g_last_pid = 0;
    g_handler_count = 0;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = basic_siginfo_handler;
    sa.sa_flags = SA_SIGINFO;
    CHECK(sigaction(SIGUSR1, &sa, &old) == 0);
    CHECK(old.sa_handler == SIG_DFL);

    double d0 = 12345.6789;
    double d1 = -98765.4321;
    double d2 = d0 + d1;
    CHECK(kill(getpid(), SIGUSR1) == 0);
    CHECK(g_handler_count == 1);
    CHECK(g_last_sig == SIGUSR1);
    CHECK(g_last_code == SI_USER);
    CHECK(g_last_pid == (sig_atomic_t)getpid());
    CHECK(d0 == 12345.6789);
    CHECK(d1 == -98765.4321);
    CHECK(d2 == (12345.6789 + (-98765.4321)));

    /* SA_NODEFER allows recursive delivery while inside the handler. */
    g_nested_depth = 0;
    g_max_depth = 0;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = nodefer_handler;
    sa.sa_flags = SA_NODEFER;
    CHECK(sigaction(SIGUSR1, &sa, NULL) == 0);
    CHECK(raise(SIGUSR1) == 0);
    CHECK(g_max_depth == 2);
    CHECK(g_nested_depth == 0);

    /* SA_RESETHAND resets the disposition to SIG_DFL on first delivery. */
    g_last_sig = 0;
    g_handler_count = 0;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = resethand_handler;
    sa.sa_flags = SA_RESETHAND;
    CHECK(sigaction(SIGUSR2, &sa, NULL) == 0);
    CHECK(raise(SIGUSR2) == 0);
    CHECK(g_handler_count == 1);
    CHECK(g_last_sig == SIGUSR2);
    CHECK(sigaction(SIGUSR2, NULL, &old) == 0);
    CHECK(old.sa_handler == SIG_DFL);

    /* Setting SIG_IGN discards pending blocked signals. */
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR1);
    CHECK(sigprocmask(SIG_BLOCK, &block, NULL) == 0);
    CHECK(raise(SIGUSR1) == 0);
    sigset_t pending;
    sigemptyset(&pending);
    CHECK(sigpending(&pending) == 0);
    CHECK(sigismember(&pending, SIGUSR1) == 1);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    CHECK(sigaction(SIGUSR1, &sa, NULL) == 0);
    sigemptyset(&pending);
    CHECK(sigpending(&pending) == 0);
    CHECK(sigismember(&pending, SIGUSR1) == 0);

    sa.sa_handler = SIG_DFL;
    CHECK(sigaction(SIGUSR1, &sa, NULL) == 0);
    CHECK(sigprocmask(SIG_UNBLOCK, &block, NULL) == 0);
}

struct delayed_signal_arg {
    int sig;
    int target_tid;
    int delay_ms;
    int write_fd;
};

static void *delayed_signal_worker(void *raw) {
    struct delayed_signal_arg *arg = raw;
    struct timespec ts = {
        .tv_sec = arg->delay_ms / 1000,
        .tv_nsec = (long)(arg->delay_ms % 1000) * 1000000L,
    };
    nanosleep(&ts, NULL);
    if (arg->target_tid > 0) {
        CHECK(SYS(SYS_tgkill, getpid(), arg->target_tid, arg->sig) == 0);
    } else {
        CHECK(kill(getpid(), arg->sig) == 0);
    }
    if (arg->write_fd >= 0) {
        struct timespec after = {.tv_sec = 0, .tv_nsec = 25000000L};
        nanosleep(&after, NULL);
        char byte = 'K';
        ssize_t n = write(arg->write_fd, &byte, 1);
        CHECK(n == 1);
    }
    return NULL;
}

static void test_masks_suspend_and_timedwait(void) {
    /* SIGKILL and SIGSTOP can never be blocked in the signal mask. */
    sigset_t all, cur;
    sigemptyset(&all);
    sigaddset(&all, SIGKILL);
    sigaddset(&all, SIGSTOP);
    sigaddset(&all, SIGUSR1);
    CHECK(sigprocmask(SIG_BLOCK, &all, NULL) == 0);
    CHECK(sigprocmask(SIG_SETMASK, NULL, &cur) == 0);
    CHECK(sigismember(&cur, SIGKILL) == 0);
    CHECK(sigismember(&cur, SIGSTOP) == 0);
    CHECK(sigismember(&cur, SIGUSR1) == 1);

    /* rt_sigtimedwait consumes a pending blocked signal immediately and
     * populates siginfo_t; zero timeout when empty returns EAGAIN. */
    struct timespec zero = {0, 0};
    siginfo_t info;
    sigset_t want;
    sigemptyset(&want);
    sigaddset(&want, SIGUSR1);
    CHECK(sigtimedwait(&want, &info, &zero) == -1 && errno == EAGAIN);

    CHECK(kill(getpid(), SIGUSR1) == 0);
    memset(&info, 0, sizeof(info));
    CHECK(sigtimedwait(&want, &info, &zero) == SIGUSR1);
    CHECK(info.si_signo == SIGUSR1);
    CHECK(info.si_code == SI_USER);
    CHECK(info.si_pid == getpid());

    /* sigsuspend atomically unblocks SIGUSR1, runs handler, and restores mask. */
    g_handler_count = 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = restart_handler;
    CHECK(sigaction(SIGUSR1, &sa, NULL) == 0);

    pthread_t helper;
    struct delayed_signal_arg arg = {
        .sig = SIGUSR1,
        .target_tid = (int)syscall(SYS_gettid),
        .delay_ms = 25,
        .write_fd = -1,
    };
    CHECK(pthread_create(&helper, NULL, delayed_signal_worker, &arg) == 0);

    sigset_t empty;
    sigemptyset(&empty);
    CHECK(sigsuspend(&empty) == -1 && errno == EINTR);
    CHECK(g_handler_count == 1);
    CHECK(pthread_join(helper, NULL) == 0);

    /* Original mask (SIGUSR1 blocked) MUST be restored after sigsuspend! */
    CHECK(sigprocmask(SIG_SETMASK, NULL, &cur) == 0);
    CHECK(sigismember(&cur, SIGUSR1) == 1);

    /* Real-time signal queueing: two blocked SIGRTMIN signals both arrive. */
    int rt_sig = SIGRTMIN + 2;
    sigset_t rt_set;
    sigemptyset(&rt_set);
    sigaddset(&rt_set, rt_sig);
    CHECK(sigprocmask(SIG_BLOCK, &rt_set, NULL) == 0);
    CHECK(kill(getpid(), rt_sig) == 0);
    CHECK(kill(getpid(), rt_sig) == 0);
    CHECK(sigtimedwait(&rt_set, &info, &zero) == rt_sig);
    CHECK(sigtimedwait(&rt_set, &info, &zero) == rt_sig);
    CHECK(sigtimedwait(&rt_set, &info, &zero) == -1 && errno == EAGAIN);

    /* Clean up masks and dispositions. */
    sa.sa_handler = SIG_DFL;
    CHECK(sigaction(SIGUSR1, &sa, NULL) == 0);
    CHECK(sigprocmask(SIG_SETMASK, &empty, NULL) == 0);
}

static void test_altstack(void) {
    /* Too small fails with ENOMEM; unknown flag fails with EINVAL. */
    char tiny[64];
    stack_t ss = {.ss_sp = tiny, .ss_flags = 0, .ss_size = sizeof(tiny)};
    CHECK(sigaltstack(&ss, NULL) == -1 && errno == ENOMEM);

    size_t stack_sz = 32768;
    char *altbuf = malloc(stack_sz);
    CHECK(altbuf != NULL);
    ss.ss_sp = altbuf;
    ss.ss_size = stack_sz;
    ss.ss_flags = 0x100;
    CHECK(sigaltstack(&ss, NULL) == -1 && errno == EINVAL);

    /* Normal SA_ONSTACK delivery executes inside altbuf and reports SS_ONSTACK. */
    ss.ss_flags = 0;
    stack_t old;
    CHECK(sigaltstack(&ss, &old) == 0);
    CHECK(old.ss_flags == SS_DISABLE);

    g_handler_count = 0;
    g_on_altstack = 0;
    g_altstack_eperm = 0;
    g_altstack_disarmed = 0;
    g_handler_sp = 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = altstack_handler;
    sa.sa_flags = SA_ONSTACK;
    CHECK(sigaction(SIGUSR1, &sa, NULL) == 0);
    CHECK(raise(SIGUSR1) == 0);
    CHECK(g_handler_count == 1);
    CHECK(g_on_altstack == 1);
    CHECK(g_altstack_eperm == 1);
    CHECK(g_handler_sp >= (uintptr_t)altbuf && g_handler_sp < (uintptr_t)(altbuf + stack_sz));

    /* SS_AUTODISARM disarms inside the handler and re-arms on rt_sigreturn. */
    ss.ss_sp = altbuf;
    ss.ss_size = stack_sz;
    ss.ss_flags = (int)SS_AUTODISARM;
    CHECK(sigaltstack(&ss, NULL) == 0);

    g_handler_count = 0;
    g_altstack_disarmed = 0;
    g_handler_sp = 0;
    CHECK(raise(SIGUSR1) == 0);
    CHECK(g_handler_count == 1);
    CHECK(g_altstack_disarmed == 1);
    CHECK(g_handler_sp >= (uintptr_t)altbuf && g_handler_sp < (uintptr_t)(altbuf + stack_sz));

    CHECK(sigaltstack(NULL, &old) == 0);
    CHECK((old.ss_flags & SS_DISABLE) == 0);
    CHECK(((unsigned)old.ss_flags & SS_AUTODISARM) != 0);

    /* Disable altstack before freeing. */
    stack_t disable = {.ss_flags = SS_DISABLE};
    CHECK(sigaltstack(&disable, NULL) == 0);
    sa.sa_handler = SIG_DFL;
    CHECK(sigaction(SIGUSR1, &sa, NULL) == 0);
    free(altbuf);
}

static void test_restart_and_eintr(void) {
    int fds[2];
    CHECK(pipe(fds) == 0);

    /* 1. Without SA_RESTART: pipe read returns -1 / EINTR. */
    g_handler_count = 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = restart_handler;
    sa.sa_flags = 0;
    CHECK(sigaction(SIGUSR1, &sa, NULL) == 0);

    pthread_t helper;
    struct delayed_signal_arg arg = {
        .sig = SIGUSR1,
        .target_tid = (int)syscall(SYS_gettid),
        .delay_ms = 25,
        .write_fd = -1,
    };
    CHECK(pthread_create(&helper, NULL, delayed_signal_worker, &arg) == 0);
    char ch = 0;
    CHECK(read(fds[0], &ch, 1) == -1 && errno == EINTR);
    CHECK(g_handler_count == 1);
    CHECK(pthread_join(helper, NULL) == 0);

    /* 2. With SA_RESTART: pipe read restarts automatically and reads 'K'. */
    g_handler_count = 0;
    sa.sa_flags = SA_RESTART;
    CHECK(sigaction(SIGUSR1, &sa, NULL) == 0);
    arg.write_fd = fds[1];
    CHECK(pthread_create(&helper, NULL, delayed_signal_worker, &arg) == 0);
    CHECK(read(fds[0], &ch, 1) == 1);
    CHECK(ch == 'K');
    CHECK(g_handler_count == 1);
    CHECK(pthread_join(helper, NULL) == 0);

    /* 3. nanosleep is NEVER restarted by SA_RESTART and writes remaining time. */
    g_handler_count = 0;
    arg.write_fd = -1;
    CHECK(pthread_create(&helper, NULL, delayed_signal_worker, &arg) == 0);
    struct timespec req = {.tv_sec = 1, .tv_nsec = 0};
    struct timespec rem = {.tv_sec = 0, .tv_nsec = 0};
    CHECK(nanosleep(&req, &rem) == -1 && errno == EINTR);
    CHECK(g_handler_count == 1);
    CHECK(rem.tv_sec > 0 || rem.tv_nsec > 0);
    CHECK(pthread_join(helper, NULL) == 0);

    /* 4. pause() is NEVER restarted by SA_RESTART. */
    g_handler_count = 0;
    CHECK(pthread_create(&helper, NULL, delayed_signal_worker, &arg) == 0);
    CHECK(pause() == -1 && errno == EINTR);
    CHECK(g_handler_count == 1);
    CHECK(pthread_join(helper, NULL) == 0);

    /* 5. epoll_pwait atomically unblocks a masked signal and restores mask. */
    int ep = epoll_create1(0);
    CHECK(ep >= 0);
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = fds[0]};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fds[0], &ev) == 0);

    sigset_t block, empty, cur;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR1);
    sigemptyset(&empty);
    CHECK(sigprocmask(SIG_BLOCK, &block, NULL) == 0);

    g_handler_count = 0;
    CHECK(pthread_create(&helper, NULL, delayed_signal_worker, &arg) == 0);
    struct epoll_event out;
    CHECK(epoll_pwait(ep, &out, 1, 2000, &empty) == -1 && errno == EINTR);
    CHECK(g_handler_count == 1);
    CHECK(pthread_join(helper, NULL) == 0);
    CHECK(sigprocmask(SIG_SETMASK, NULL, &cur) == 0);
    CHECK(sigismember(&cur, SIGUSR1) == 1);
    CHECK(sigprocmask(SIG_UNBLOCK, &block, NULL) == 0);
    close(ep);

    /* 6. Broken pipe write raises SIGPIPE and returns -EPIPE. */
    close(fds[0]);
    atomic_store(&g_pipe_sig_received, 0);
    sa.sa_handler = pipe_handler;
    sa.sa_flags = 0;
    CHECK(sigaction(SIGPIPE, &sa, NULL) == 0);
    CHECK(write(fds[1], "x", 1) == -1 && errno == EPIPE);
    CHECK(atomic_load(&g_pipe_sig_received) == 1);
    close(fds[1]);

    sa.sa_handler = SIG_DFL;
    CHECK(sigaction(SIGUSR1, &sa, NULL) == 0);
    CHECK(sigaction(SIGPIPE, &sa, NULL) == 0);
}

struct thread_sig_ctx {
    _Atomic int tid;
    _Atomic int ready;
    _Atomic int done;
};

static void *thread_signal_target(void *raw) {
    struct thread_sig_ctx *ctx = raw;
    /* Unblock SIGUSR2 in this thread (main masks it). */
    sigset_t unblock;
    sigemptyset(&unblock);
    sigaddset(&unblock, SIGUSR2);
    CHECK(pthread_sigmask(SIG_UNBLOCK, &unblock, NULL) == 0);

    atomic_store(&ctx->tid, (int)syscall(SYS_gettid));
    atomic_store(&ctx->ready, 1);

    while (!atomic_load(&ctx->done)) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5000000L};
        nanosleep(&ts, NULL);
    }
    return NULL;
}

static void test_thread_directed_signals(void) {
    /* kill(pid, 0) probes existence without raising a signal. */
    CHECK(kill(getpid(), 0) == 0);
    CHECK(kill(999999, 0) == -1 && errno == ESRCH);
    CHECK(SYS(SYS_tkill, 0, SIGUSR1) == -EINVAL);
    CHECK(SYS(SYS_tgkill, 0, getpid(), SIGUSR1) == -EINVAL);
    CHECK(SYS(SYS_tgkill, getpid() + 1000, (int)syscall(SYS_gettid), 0) == -ESRCH);

    /* Block SIGUSR2 on main so process-directed kill(getpid(), SIGUSR2) must
     * route to the worker thread, and tgkill targets the worker directly. */
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR2);
    CHECK(pthread_sigmask(SIG_BLOCK, &block, NULL) == 0);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = thread_sig_handler;
    CHECK(sigaction(SIGUSR2, &sa, NULL) == 0);

    struct thread_sig_ctx ctx = {0};
    pthread_t worker;
    CHECK(pthread_create(&worker, NULL, thread_signal_target, &ctx) == 0);
    while (!atomic_load(&ctx.ready)) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 1000000L};
        nanosleep(&ts, NULL);
    }
    int worker_tid = atomic_load(&ctx.tid);
    CHECK(worker_tid > 0 && worker_tid != (int)syscall(SYS_gettid));

    /* 1. tgkill directly to worker_tid. */
    atomic_store(&g_thread_sig_count, 0);
    atomic_store(&g_thread_sig_tid, 0);
    CHECK(SYS(SYS_tgkill, getpid(), worker_tid, SIGUSR2) == 0);
    for (int i = 0; i < 200 && atomic_load(&g_thread_sig_count) < 1; i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5000000L};
        nanosleep(&ts, NULL);
    }
    CHECK(atomic_load(&g_thread_sig_count) == 1);
    CHECK(atomic_load(&g_thread_sig_tid) == worker_tid);

    /* 2. Process-directed kill(getpid(), SIGUSR2) routed to unmasked worker. */
    atomic_store(&g_thread_sig_tid, 0);
    CHECK(kill(getpid(), SIGUSR2) == 0);
    for (int i = 0; i < 200 && atomic_load(&g_thread_sig_count) < 2; i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5000000L};
        nanosleep(&ts, NULL);
    }
    CHECK(atomic_load(&g_thread_sig_count) == 2);
    CHECK(atomic_load(&g_thread_sig_tid) == worker_tid);

    atomic_store(&ctx.done, 1);
    CHECK(pthread_join(worker, NULL) == 0);

    sa.sa_handler = SIG_DFL;
    CHECK(sigaction(SIGUSR2, &sa, NULL) == 0);
    CHECK(pthread_sigmask(SIG_UNBLOCK, &block, NULL) == 0);
}

static void test_timers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = timer_handler;
    CHECK(sigaction(SIGALRM, &sa, NULL) == 0);
    CHECK(sigaction(SIGVTALRM, &sa, NULL) == 0);
    CHECK(sigaction(SIGPROF, &sa, NULL) == 0);

    /* Invalid timer type / invalid timeval rejected with EINVAL. */
    struct itimerval bad = {.it_value = {.tv_sec = 0, .tv_usec = 1000000}};
    CHECK(setitimer(ITIMER_REAL, &bad, NULL) == -1 && errno == EINVAL);
    CHECK(getitimer(99, &bad) == -1 && errno == EINVAL);

    /* Repeating ITIMER_REAL -> SIGALRM, then getitimer & cancel via alarm(0). */
    atomic_store(&g_alrm_count, 0);
    struct itimerval it = {
        .it_interval = {.tv_sec = 0, .tv_usec = 15000},
        .it_value = {.tv_sec = 0, .tv_usec = 15000},
    };
    struct itimerval cur;
    CHECK(setitimer(ITIMER_REAL, &it, NULL) == 0);
    CHECK(getitimer(ITIMER_REAL, &cur) == 0);
    CHECK(cur.it_interval.tv_usec == 15000);

    for (int i = 0; i < 400 && atomic_load(&g_alrm_count) < 2; i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5000000L};
        nanosleep(&ts, NULL);
    }
    CHECK(atomic_load(&g_alrm_count) >= 2);

    /* alarm(5) replaces ITIMER_REAL and alarm(0) returns remaining >= 1. */
    (void)alarm(5);
    unsigned rem = alarm(0);
    CHECK(rem >= 1 && rem <= 5);
    CHECK(getitimer(ITIMER_REAL, &cur) == 0);
    CHECK(cur.it_value.tv_sec == 0 && cur.it_value.tv_usec == 0);

    /* ITIMER_VIRTUAL -> SIGVTALRM while burning user CPU. */
    atomic_store(&g_vtalrm_count, 0);
    it.it_interval.tv_sec = 0;
    it.it_interval.tv_usec = 0;
    it.it_value.tv_sec = 0;
    it.it_value.tv_usec = 15000;
    CHECK(setitimer(ITIMER_VIRTUAL, &it, NULL) == 0);
    volatile uint64_t spin = 0;
    for (uint64_t i = 0; i < 400000000ULL && atomic_load(&g_vtalrm_count) == 0; i++) {
        spin += i ^ (i >> 3);
    }
    (void)spin;
    CHECK(atomic_load(&g_vtalrm_count) >= 1);

    /* ITIMER_PROF -> SIGPROF while burning CPU. */
    atomic_store(&g_prof_count, 0);
    it.it_value.tv_usec = 15000;
    CHECK(setitimer(ITIMER_PROF, &it, NULL) == 0);
    for (uint64_t i = 0; i < 400000000ULL && atomic_load(&g_prof_count) == 0; i++) {
        spin += i ^ (i >> 5);
    }
    (void)spin;
    CHECK(atomic_load(&g_prof_count) >= 1);

    sa.sa_handler = SIG_DFL;
    CHECK(sigaction(SIGALRM, &sa, NULL) == 0);
    CHECK(sigaction(SIGVTALRM, &sa, NULL) == 0);
    CHECK(sigaction(SIGPROF, &sa, NULL) == 0);
}

static void test_fault_signals(void) {
    g_page_size = (size_t)sysconf(_SC_PAGESIZE);
    g_ro_page = mmap(NULL, g_page_size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(g_ro_page != MAP_FAILED);

    /* 1. Catchable SIGSEGV (SEGV_ACCERR) repaired in-place via mprotect and
     * resumed directly at the faulting store instruction! */
    g_handler_count = 0;
    g_fault_addr = 0;
    g_fault_code = 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = segv_mprotect_handler;
    sa.sa_flags = SA_SIGINFO;
    CHECK(sigaction(SIGSEGV, &sa, NULL) == 0);

    volatile uint32_t *cell = (volatile uint32_t *)g_ro_page;
    *cell = 0x13572468U;
    CHECK(g_handler_count == 1);
    CHECK(g_fault_addr == (uintptr_t)g_ro_page);
    CHECK(g_fault_code == SEGV_ACCERR);
    CHECK(*cell == 0x13572468U);
    CHECK(munmap(g_ro_page, g_page_size) == 0);

    /* 2. Catchable SIGSEGV (SEGV_MAPERR) via sigsetjmp/siglongjmp. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fault_longjmp_handler;
    sa.sa_flags = SA_SIGINFO;
    CHECK(sigaction(SIGSEGV, &sa, NULL) == 0);
    int jumped = sigsetjmp(g_jump_env, 1);
    if (jumped == 0) {
        volatile char *bad = (volatile char *)0x1000;
        (void)*bad;
        CHECK(0);
    }
    CHECK(jumped == SIGSEGV);
    CHECK(g_fault_code == SEGV_MAPERR);
    CHECK(g_fault_addr == 0x1000);

    /* 3. Catchable SIGILL via sigsetjmp/siglongjmp. */
    CHECK(sigaction(SIGILL, &sa, NULL) == 0);
    jumped = sigsetjmp(g_jump_env, 1);
    if (jumped == 0) {
#if defined(__x86_64__)
        __asm__ volatile("ud2");
#elif defined(__aarch64__)
        __asm__ volatile(".inst 0x00000000");
#endif
        CHECK(0);
    }
    CHECK(jumped == SIGILL);

    /* 4. Catchable SIGTRAP via sigsetjmp/siglongjmp. */
    CHECK(sigaction(SIGTRAP, &sa, NULL) == 0);
    jumped = sigsetjmp(g_jump_env, 1);
    if (jumped == 0) {
#if defined(__x86_64__)
        __asm__ volatile("int3");
#elif defined(__aarch64__)
        __asm__ volatile("brk #0");
#endif
        CHECK(0);
    }
    CHECK(jumped == SIGTRAP);

#if defined(__x86_64__)
    /* 5. Catchable SIGFPE on x86-64 integer divide by zero. */
    CHECK(sigaction(SIGFPE, &sa, NULL) == 0);
    jumped = sigsetjmp(g_jump_env, 1);
    if (jumped == 0) {
        volatile int zero = 0;
        volatile int one = 1;
        volatile int q = one / zero;
        (void)q;
        CHECK(0);
    }
    CHECK(jumped == SIGFPE);
#endif

    sa.sa_handler = SIG_DFL;
    CHECK(sigaction(SIGSEGV, &sa, NULL) == 0);
    CHECK(sigaction(SIGILL, &sa, NULL) == 0);
    CHECK(sigaction(SIGTRAP, &sa, NULL) == 0);
    CHECK(sigaction(SIGFPE, &sa, NULL) == 0);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "suite";

    if (strcmp(mode, "suite") == 0) {
        test_handlers();
        test_masks_suspend_and_timedwait();
        test_altstack();
        test_restart_and_eintr();
        test_thread_directed_signals();
        test_timers();
        test_fault_signals();
        puts("signals suite: ok");
        return 0;
    }

    if (strcmp(mode, "default-term") == 0) {
        puts("end: default sigterm");
        fflush(stdout);
        raise(SIGTERM);
        return 0;
    }

    if (strcmp(mode, "default-kill") == 0) {
        puts("end: default sigkill");
        fflush(stdout);
        raise(SIGKILL);
        return 0;
    }

    if (strcmp(mode, "default-alrm") == 0) {
        puts("end: default sigalrm");
        fflush(stdout);
        struct itimerval it = {
            .it_interval = {0, 0},
            .it_value = {.tv_sec = 0, .tv_usec = 20000},
        };
        CHECK(setitimer(ITIMER_REAL, &it, NULL) == 0);
        pause();
        return 0;
    }

    if (strcmp(mode, "masked-segv") == 0) {
        puts("end: masked segv force default");
        fflush(stdout);
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = fault_longjmp_handler;
        sa.sa_flags = SA_SIGINFO;
        CHECK(sigaction(SIGSEGV, &sa, NULL) == 0);
        sigset_t block;
        sigemptyset(&block);
        sigaddset(&block, SIGSEGV);
        CHECK(sigprocmask(SIG_BLOCK, &block, NULL) == 0);
        volatile char *bad = (volatile char *)0x1000;
        (void)*bad;
        return 0;
    }

    dprintf(2, "unknown signals mode: %s\n", mode);
    return 2;
}
