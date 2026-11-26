/* Exercises private anonymous pages, fork CoW preservation, blocking pipe read
 * into a private user buffer (post-wakeup syscall buffer write), /proc/self/status
 * VmSwap reporting, MADV_DONTNEED, and munmap teardown. */
#include "check.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>

static const char CJK_HEADER[] = "中文 日本語 한국어 ";

static void fill_page(unsigned char *buf, size_t page_size, size_t page_idx) {
    char prefix[64];
    int n = snprintf(prefix, sizeof(prefix), "%spage=%zu:", CJK_HEADER, page_idx);
    CHECK(n > 0 && (size_t)n < page_size);
    memcpy(buf, prefix, (size_t)n);
    for (size_t i = (size_t)n; i < page_size; i++) {
        buf[i] = (unsigned char)((page_idx * 37 + i * 13 + 0x5a) & 0xff);
    }
}

static void verify_page(const unsigned char *buf, size_t page_size, size_t page_idx) {
    char prefix[64];
    int n = snprintf(prefix, sizeof(prefix), "%spage=%zu:", CJK_HEADER, page_idx);
    CHECK(n > 0 && (size_t)n < page_size);
    CHECK(memcmp(buf, prefix, (size_t)n) == 0);
    for (size_t i = (size_t)n; i < page_size; i++) {
        unsigned char expected = (unsigned char)((page_idx * 37 + i * 13 + 0x5a) & 0xff);
        CHECK(buf[i] == expected);
    }
}

static void check_proc_status_vmswap(void) {
    int fd = open("/proc/self/status", O_RDONLY);
    CHECK(fd >= 0);
    char buf[8192];
    size_t total = 0;
    while (total + 1 < sizeof(buf)) {
        ssize_t got = read(fd, buf + total, sizeof(buf) - 1 - total);
        CHECK(got >= 0);
        if (got == 0) break;
        total += (size_t)got;
    }
    close(fd);
    buf[total] = '\0';
    const char *line = strstr(buf, "VmSwap:");
    CHECK(line != NULL);
    unsigned long kb = 0;
    CHECK(sscanf(line, "VmSwap: %lu kB", &kb) == 1);
}

int main(void) {
    long raw_page = sysconf(_SC_PAGESIZE);
    CHECK(raw_page >= 4096);
    size_t page = (size_t)raw_page;

    const size_t pages = 16;
    unsigned char *region = mmap(NULL, pages * page, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(region != MAP_FAILED);
    for (size_t i = 0; i < pages; i++) {
        fill_page(region + i * page, page, i);
    }

    check_proc_status_vmswap();

    /* Separate private buffer populated by a blocking pipe read after wakeup. */
    unsigned char *recv_buf = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(recv_buf != MAP_FAILED);
    memset(recv_buf, 0xaa, 2 * page);

    const char msg[] = "中文 日本語 한국어 post-wakeup pipe payload";
    const size_t msg_len = sizeof(msg) - 1;

    int pfd[2];
    CHECK(pipe(pfd) == 0);

    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        close(pfd[0]);
        /* Verify all inherited private pages survived fork byte-exact. */
        for (size_t i = 0; i < pages; i++) {
            verify_page(region + i * page, page, i);
        }
        /* Mutate page 0 in child to verify CoW isolation from parent. */
        region[0] ^= 0xff;
        struct timespec delay = { .tv_sec = 0, .tv_nsec = 20 * 1000 * 1000 };
        nanosleep(&delay, NULL);
        size_t sent = 0;
        while (sent < msg_len) {
            ssize_t w = write(pfd[1], msg + sent, msg_len - sent);
            CHECK(w > 0);
            sent += (size_t)w;
        }
        close(pfd[1]);
        _exit(0);
    }

    close(pfd[1]);
    size_t got = 0;
    while (got < msg_len) {
        ssize_t r = read(pfd[0], recv_buf + got, msg_len - got);
        CHECK(r > 0);
        got += (size_t)r;
    }
    close(pfd[0]);
    CHECK(memcmp(recv_buf, msg, msg_len) == 0);

    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* Parent's private pages are intact and unaffected by child's CoW write. */
    for (size_t i = 0; i < pages; i++) {
        verify_page(region + i * page, page, i);
    }

    /* MADV_DONTNEED discards a private page cleanly to zero. */
    CHECK(madvise(region + 2 * page, page, MADV_DONTNEED) == 0);
    for (size_t i = 0; i < page; i++) {
        CHECK(region[2 * page + i] == 0);
    }

    CHECK(munmap(recv_buf, 2 * page) == 0);
    CHECK(munmap(region, pages * page) == 0);

    check_proc_status_vmswap();
    printf("native-swap: ok\n");
    return 0;
}
