/* File, path, directory, metadata, descriptor I/O, fcntl, close_range and
 * file-backed / shared mmap + msync conformance fixture.
 *
 * Usage:
 *   files [scratch_dir]        Run the full POSIX/Linux file & mmap suite.
 *   files cross <shared_file>  Cross-ABI mode: verify bytes written by WASIX,
 *                              append via O_APPEND, and write a sibling file
 *                              through MAP_SHARED + msync for WASIX to read.
 */
#include "check.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <time.h>

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif
#ifndef AT_REMOVEDIR
#define AT_REMOVEDIR 0x200
#endif
#ifndef AT_SYMLINK_FOLLOW
#define AT_SYMLINK_FOLLOW 0x400
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0)
#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1U << 1)
#endif
#ifndef RWF_DSYNC
#define RWF_DSYNC 0x02
#endif
#ifndef RWF_SYNC
#define RWF_SYNC 0x04
#endif
#ifndef RWF_APPEND
#define RWF_APPEND 0x10
#endif
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif
#ifndef STATX_BASIC_STATS
#define STATX_BASIC_STATS 0x07ffU
#endif
#ifndef UTIME_NOW
#define UTIME_NOW ((1L << 30) - 1L)
#endif
#ifndef UTIME_OMIT
#define UTIME_OMIT ((1L << 30) - 2L)
#endif

struct linux_dirent64_raw {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[];
};

struct statx_timestamp_raw {
    int64_t tv_sec;
    uint32_t tv_nsec;
    int32_t reserved;
};

struct statx_raw {
    uint32_t stx_mask;
    uint32_t stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink;
    uint32_t stx_uid;
    uint32_t stx_gid;
    uint16_t stx_mode;
    uint16_t pad0;
    uint64_t stx_ino;
    uint64_t stx_size;
    uint64_t stx_blocks;
    uint64_t stx_attributes_mask;
    struct statx_timestamp_raw stx_atime;
    struct statx_timestamp_raw stx_btime;
    struct statx_timestamp_raw stx_ctime;
    struct statx_timestamp_raw stx_mtime;
    uint32_t stx_rdev_major;
    uint32_t stx_rdev_minor;
    uint32_t stx_dev_major;
    uint32_t stx_dev_minor;
    uint64_t spare[14];
};

static int run_cross(const char *path) {
    static const char expected[] = "from-wasix: \xe4\xb8\xad\xe6\x96\x87 \xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e \xed\x95\x9c\xea\xb5\xad\xec\x96\xb4\n";
    static const char append_msg[] = "from-linux-write\n";
    static const char mmap_msg[] = "from-linux-mmap\n";

    int fd = (int)SYS(SYS_openat, AT_FDCWD, path, O_RDWR | O_APPEND, 0);
    CHECK(fd >= 0);

    char buf[128];
    memset(buf, 0, sizeof buf);
    long n = SYS(SYS_read, fd, buf, sizeof buf - 1);
    CHECK(n == (long)(sizeof expected - 1));
    CHECK(memcmp(buf, expected, (size_t)n) == 0);

    CHECK(SYS(SYS_write, fd, append_msg, sizeof append_msg - 1) == (long)(sizeof append_msg - 1));
    CHECK(SYS(SYS_fsync, fd) == 0);
    CHECK(SYS(SYS_close, fd) == 0);

    char mpath[256];
    snprintf(mpath, sizeof mpath, "%s.mmap", path);
    int mfd = (int)SYS(SYS_openat, AT_FDCWD, mpath, O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK(mfd >= 0);
    CHECK(SYS(SYS_ftruncate, mfd, (long)(sizeof mmap_msg - 1)) == 0);
    char *mapped = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
    CHECK(mapped != MAP_FAILED);
    memcpy(mapped, mmap_msg, sizeof mmap_msg - 1);
    CHECK(SYS(SYS_msync, mapped, 4096, MS_SYNC) == 0);
    CHECK(SYS(SYS_munmap, mapped, 4096) == 0);
    CHECK(SYS(SYS_close, mfd) == 0);

    puts("files-cross: ok");
    return 0;
}

static void check_open_rw_seek(int dirfd) {
    /* openat O_CREAT | O_EXCL, duplicate EEXIST, O_TRUNC, O_APPEND */
    int fd = (int)SYS(SYS_openat, dirfd, "alpha.txt", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0644);
    CHECK(fd >= 0);
    CHECK(SYS(SYS_fcntl, fd, F_GETFD) == FD_CLOEXEC);
    CHECK((SYS(SYS_fcntl, fd, F_GETFL) & O_ACCMODE) == O_RDWR);
    CHECK(SYS(SYS_openat, dirfd, "alpha.txt", O_CREAT | O_EXCL | O_RDWR, 0644) == -EEXIST);

    static const char hello[] = "hello-world";
    CHECK(SYS(SYS_write, fd, hello, sizeof hello - 1) == (long)(sizeof hello - 1));
    CHECK(SYS(SYS_lseek, fd, 0, SEEK_CUR) == (long)(sizeof hello - 1));
    CHECK(SYS(SYS_lseek, fd, 0, SEEK_SET) == 0);

    char buf[64];
    memset(buf, 0, sizeof buf);
    CHECK(SYS(SYS_read, fd, buf, 5) == 5);
    CHECK(memcmp(buf, "hello", 5) == 0);
    CHECK(SYS(SYS_lseek, fd, 0, SEEK_CUR) == 5);

    /* pread64 / pwrite64 do not alter file offset */
    CHECK(SYS(SYS_pwrite64, fd, "WORLD", 5, 6) == 5);
    CHECK(SYS(SYS_lseek, fd, 0, SEEK_CUR) == 5);
    memset(buf, 0, sizeof buf);
    CHECK(SYS(SYS_pread64, fd, buf, 11, 0) == 11);
    CHECK(memcmp(buf, "hello-WORLD", 11) == 0);
    CHECK(SYS(SYS_lseek, fd, 0, SEEK_CUR) == 5);
    CHECK(SYS(SYS_pread64, fd, buf, 4, -1L) == -EINVAL);
    CHECK(SYS(SYS_pwrite64, fd, "x", 1, -1L) == -EINVAL);

    /* readv / writev / preadv / pwritev / preadv2 / pwritev2 */
    struct iovec wiov[2] = {
        { .iov_base = (void *)"-123", .iov_len = 4 },
        { .iov_base = (void *)"456", .iov_len = 3 },
    };
    CHECK(SYS(SYS_pwritev, fd, wiov, 2, 11, 0) == 7);
    CHECK(SYS(SYS_lseek, fd, 0, SEEK_CUR) == 5);

    char r1[6], r2[12];
    memset(r1, 0, sizeof r1);
    memset(r2, 0, sizeof r2);
    struct iovec riov[2] = {
        { .iov_base = r1, .iov_len = 6 },
        { .iov_base = r2, .iov_len = 12 },
    };
    CHECK(SYS(SYS_preadv, fd, riov, 2, 0, 0) == 18);
    CHECK(memcmp(r1, "hello-", 6) == 0);
    CHECK(memcmp(r2, "WORLD-123456", 12) == 0);

    /* pwritev2 with RWF_APPEND + preadv2 with offset -1 (uses current pos) */
    struct iovec app = { .iov_base = (void *)"!", .iov_len = 1 };
    CHECK(SYS(SYS_pwritev2, fd, &app, 1, 0, 0, RWF_APPEND | RWF_DSYNC) == 1);
    CHECK(SYS(SYS_pwritev2, fd, &app, 1, 0, 0, 0x8000) == -EOPNOTSUPP);
    CHECK(SYS(SYS_lseek, fd, 18, SEEK_SET) == 18);
    char bang = 0;
    struct iovec one = { .iov_base = &bang, .iov_len = 1 };
    CHECK(SYS(SYS_preadv2, fd, &one, 1, -1L, -1L, 0) == 1);
    CHECK(bang == '!');
    CHECK(SYS(SYS_lseek, fd, 0, SEEK_END) == 19);
    CHECK(SYS(SYS_lseek, fd, -1L, SEEK_SET) == -EINVAL);
    CHECK(SYS(SYS_lseek, fd, 0, 99) == -EINVAL);

    /* fsync / fdatasync / ftruncate */
    CHECK(SYS(SYS_fsync, fd) == 0);
    CHECK(SYS(SYS_fdatasync, fd) == 0);
    CHECK(SYS(SYS_ftruncate, fd, 5) == 0);
    struct stat st;
    CHECK(SYS(SYS_fstat, fd, &st) == 0);
    CHECK(S_ISREG(st.st_mode));
    CHECK(st.st_size == 5);
    CHECK(SYS(SYS_ftruncate, fd, -1L) == -EINVAL);

    /* O_RDONLY rejects write & ftruncate; O_WRONLY rejects read */
    int ro = (int)SYS(SYS_openat, dirfd, "alpha.txt", O_RDONLY, 0);
    CHECK(ro >= 0);
    CHECK(SYS(SYS_write, ro, "x", 1) == -EBADF);
    CHECK(SYS(SYS_ftruncate, ro, 1) == -EINVAL);
    CHECK(SYS(SYS_close, ro) == 0);

    int wo = (int)SYS(SYS_openat, dirfd, "alpha.txt", O_WRONLY | O_APPEND, 0);
    CHECK(wo >= 0);
    CHECK(SYS(SYS_read, wo, buf, 1) == -EBADF);
    CHECK((SYS(SYS_fcntl, wo, F_GETFL) & (O_ACCMODE | O_APPEND)) == (O_WRONLY | O_APPEND));
    CHECK(SYS(SYS_write, wo, "Z", 1) == 1);
    CHECK(SYS(SYS_close, wo) == 0);

    /* O_PATH allows fstat/AT_EMPTY_PATH, refuses read/write/F_SETFL */
    int pfd = (int)SYS(SYS_openat, dirfd, "alpha.txt", O_PATH, 0);
    CHECK(pfd >= 0);
    CHECK(SYS(SYS_read, pfd, buf, 1) == -EBADF);
    CHECK(SYS(SYS_write, pfd, "x", 1) == -EBADF);
    CHECK(SYS(SYS_fcntl, pfd, F_SETFL, O_NONBLOCK) == -EBADF);
    CHECK(SYS(SYS_newfstatat, pfd, "", &st, AT_EMPTY_PATH) == 0);
    CHECK(st.st_size == 6);
    CHECK(SYS(SYS_close, pfd) == 0);

    /* O_DIRECTORY on file -> ENOTDIR; trailing slash on file -> ENOTDIR */
    CHECK(SYS(SYS_openat, dirfd, "alpha.txt", O_RDONLY | O_DIRECTORY, 0) == -ENOTDIR);
    CHECK(SYS(SYS_openat, dirfd, "alpha.txt/", O_RDONLY, 0) == -ENOTDIR);
    CHECK(SYS(SYS_openat, dirfd, "alpha.txt/child", O_RDONLY, 0) == -ENOTDIR);
    CHECK(SYS(SYS_openat, dirfd, "", O_RDONLY, 0) == -ENOENT);
    CHECK(SYS(SYS_openat, dirfd, "missing.txt", O_RDONLY, 0) == -ENOENT);

    /* pipe rejects pread/pwrite/lseek with ESPIPE and fsync with EINVAL */
    int pfds[2];
    CHECK(SYS(SYS_pipe2, pfds, O_CLOEXEC) == 0);
    CHECK(SYS(SYS_lseek, pfds[0], 0, SEEK_CUR) == -ESPIPE);
    CHECK(SYS(SYS_pread64, pfds[0], buf, 1, 0) == -ESPIPE);
    CHECK(SYS(SYS_pwrite64, pfds[1], "x", 1, 0) == -ESPIPE);
    CHECK(SYS(SYS_fsync, pfds[0]) == -EINVAL);
    CHECK(SYS(SYS_close, pfds[0]) == 0);
    CHECK(SYS(SYS_close, pfds[1]) == 0);

    CHECK(SYS(SYS_close, fd) == 0);
}

static void check_dirs_links_rename_meta(int dirfd) {
    CHECK(SYS(SYS_mkdirat, dirfd, "sub", 0755) == 0);
    CHECK(SYS(SYS_mkdirat, dirfd, "sub", 0755) == -EEXIST);
    CHECK(SYS(SYS_mkdirat, dirfd, "sub2/", 0755) == 0);
    CHECK(SYS(SYS_mkdirat, dirfd, "no_parent/child", 0755) == -ENOENT);

    /* Cannot open directory for writing; reading a dir gives EISDIR */
    CHECK(SYS(SYS_openat, dirfd, "sub", O_WRONLY, 0) == -EISDIR);
    int sfd = (int)SYS(SYS_openat, dirfd, "sub", O_RDONLY | O_DIRECTORY, 0);
    CHECK(sfd >= 0);
    char b;
    CHECK(SYS(SYS_read, sfd, &b, 1) == -EISDIR);

    /* Create file inside sub, then check getdents64 + rewind */
    int cfd = (int)SYS(SYS_openat, sfd, "item.txt", O_CREAT | O_RDWR, 0644);
    CHECK(cfd >= 0);
    CHECK(SYS(SYS_write, cfd, "abc", 3) == 3);
    CHECK(SYS(SYS_close, cfd) == 0);

    char dbuf[1024];
    CHECK(SYS(SYS_getdents64, sfd, dbuf, 8) == -EINVAL);
    int seen_dot = 0, seen_dotdot = 0, seen_item = 0;
    for (;;) {
        long n = SYS(SYS_getdents64, sfd, dbuf, sizeof dbuf);
        CHECK(n >= 0);
        if (n == 0) break;
        long pos = 0;
        while (pos < n) {
            struct linux_dirent64_raw *d = (struct linux_dirent64_raw *)(dbuf + pos);
            if (strcmp(d->d_name, ".") == 0) {
                CHECK(d->d_type == 4); /* DT_DIR */
                seen_dot = 1;
            } else if (strcmp(d->d_name, "..") == 0) {
                CHECK(d->d_type == 4);
                seen_dotdot = 1;
            } else if (strcmp(d->d_name, "item.txt") == 0) {
                CHECK(d->d_type == 8); /* DT_REG */
                seen_item = 1;
            }
            pos += d->d_reclen;
        }
    }
    CHECK(seen_dot && seen_dotdot && seen_item);
    CHECK(SYS(SYS_lseek, sfd, 0, SEEK_SET) == 0);
    CHECK(SYS(SYS_getdents64, sfd, dbuf, sizeof dbuf) > 0);
    CHECK(SYS(SYS_close, sfd) == 0);

    /* Non-empty rmdir -> ENOTEMPTY; unlink dir -> EISDIR; rmdir file -> ENOTDIR */
    CHECK(SYS(SYS_unlinkat, dirfd, "sub", AT_REMOVEDIR) == -ENOTEMPTY);
    CHECK(SYS(SYS_unlinkat, dirfd, "sub", 0) == -EISDIR);
    CHECK(SYS(SYS_unlinkat, dirfd, "alpha.txt", AT_REMOVEDIR) == -ENOTDIR);
    CHECK(SYS(SYS_unlinkat, dirfd, ".", AT_REMOVEDIR) == -EINVAL);

    /* Symlinks: CJK target, readlinkat truncation, O_NOFOLLOW, dangling O_CREAT|O_EXCL, ELOOP */
    static const char cjk_target[] = "sub/item.txt";
    CHECK(SYS(SYS_symlinkat, cjk_target, dirfd, "sym_item") == 0);
    char lbuf[64];
    memset(lbuf, 0, sizeof lbuf);
    CHECK(SYS(SYS_readlinkat, dirfd, "sym_item", lbuf, sizeof lbuf) == (long)(sizeof cjk_target - 1));
    CHECK(memcmp(lbuf, cjk_target, sizeof cjk_target - 1) == 0);
    CHECK(SYS(SYS_readlinkat, dirfd, "sym_item", lbuf, 3) == 3);
    CHECK(memcmp(lbuf, "sub", 3) == 0);
    CHECK(SYS(SYS_readlinkat, dirfd, "alpha.txt", lbuf, sizeof lbuf) == -EINVAL);

    struct stat st_link, st_follow;
    CHECK(SYS(SYS_newfstatat, dirfd, "sym_item", &st_link, AT_SYMLINK_NOFOLLOW) == 0);
    CHECK(S_ISLNK(st_link.st_mode));
    CHECK(SYS(SYS_newfstatat, dirfd, "sym_item", &st_follow, 0) == 0);
    CHECK(S_ISREG(st_follow.st_mode));
    CHECK(st_follow.st_size == 3);
    CHECK(SYS(SYS_openat, dirfd, "sym_item", O_RDONLY | O_NOFOLLOW, 0) == -ELOOP);

    /* Dangling symlink + O_CREAT | O_EXCL must return EEXIST */
    CHECK(SYS(SYS_symlinkat, "does-not-exist", dirfd, "dangling") == 0);
    CHECK(SYS(SYS_openat, dirfd, "dangling", O_CREAT | O_EXCL | O_RDWR, 0644) == -EEXIST);
    CHECK(SYS(SYS_unlinkat, dirfd, "dangling", 0) == 0);

    /* Symlink loop -> ELOOP */
    CHECK(SYS(SYS_symlinkat, "loop_b", dirfd, "loop_a") == 0);
    CHECK(SYS(SYS_symlinkat, "loop_a", dirfd, "loop_b") == 0);
    CHECK(SYS(SYS_newfstatat, dirfd, "loop_a", &st_follow, 0) == -ELOOP);
    CHECK(SYS(SYS_unlinkat, dirfd, "loop_a", 0) == 0);
    CHECK(SYS(SYS_unlinkat, dirfd, "loop_b", 0) == 0);

    /* Intermediate symlink + ".." resolves symlink before ".." */
    CHECK(SYS(SYS_symlinkat, "sub", dirfd, "sym_sub") == 0);
    CHECK(SYS(SYS_newfstatat, dirfd, "sym_sub/../alpha.txt", &st_follow, 0) == 0);
    CHECK(SYS(SYS_newfstatat, dirfd, "nonexistent/..", &st_follow, 0) == -ENOENT);
    CHECK(SYS(SYS_newfstatat, dirfd, "alpha.txt/..", &st_follow, 0) == -ENOTDIR);

    /* Hard links */
    CHECK(SYS(SYS_linkat, dirfd, "alpha.txt", dirfd, "alpha_hard", 0) == 0);
    struct stat st_a, st_h;
    CHECK(SYS(SYS_newfstatat, dirfd, "alpha.txt", &st_a, 0) == 0);
    CHECK(SYS(SYS_newfstatat, dirfd, "alpha_hard", &st_h, 0) == 0);
    CHECK(st_a.st_ino == st_h.st_ino);
    CHECK(st_a.st_nlink >= 2);
    CHECK(SYS(SYS_unlinkat, dirfd, "alpha_hard", 0) == 0);

    /* statx */
    struct statx_raw sx;
    memset(&sx, 0, sizeof sx);
    CHECK(SYS(SYS_statx, dirfd, "alpha.txt", 0, STATX_BASIC_STATS, &sx) == 0);
    CHECK((sx.stx_mask & STATX_BASIC_STATS) != 0);
    CHECK(sx.stx_ino == st_a.st_ino);
    CHECK(sx.stx_size == (uint64_t)st_a.st_size);
    CHECK(S_ISREG(sx.stx_mode));

    /* faccessat2 */
    CHECK(SYS(SYS_faccessat2, dirfd, "alpha.txt", F_OK | R_OK | W_OK, 0) == 0);
    CHECK(SYS(SYS_faccessat2, dirfd, "missing.txt", F_OK, 0) == -ENOENT);
    CHECK(SYS(SYS_faccessat2, dirfd, "alpha.txt", 0x10, 0) == -EINVAL);

    /* renameat2: Replace, RENAME_NOREPLACE, RENAME_EXCHANGE */
    int f1 = (int)SYS(SYS_openat, dirfd, "r1", O_CREAT | O_RDWR | O_TRUNC, 0644);
    int f2 = (int)SYS(SYS_openat, dirfd, "r2", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK(f1 >= 0 && f2 >= 0);
    CHECK(SYS(SYS_write, f1, "ONE", 3) == 3);
    CHECK(SYS(SYS_write, f2, "TWO", 3) == 3);
    CHECK(SYS(SYS_close, f1) == 0);
    CHECK(SYS(SYS_close, f2) == 0);

    CHECK(SYS(SYS_renameat2, dirfd, "r1", dirfd, "r2", RENAME_NOREPLACE) == -EEXIST);
    CHECK(SYS(SYS_renameat2, dirfd, "r1", dirfd, "r2", RENAME_NOREPLACE | RENAME_EXCHANGE) == -EINVAL);
    CHECK(SYS(SYS_renameat2, dirfd, "r1", dirfd, "r2", RENAME_EXCHANGE) == 0);

    char rbuf[4] = {0};
    f1 = (int)SYS(SYS_openat, dirfd, "r1", O_RDONLY, 0);
    CHECK(f1 >= 0);
    CHECK(SYS(SYS_read, f1, rbuf, 3) == 3);
    CHECK(memcmp(rbuf, "TWO", 3) == 0);
    CHECK(SYS(SYS_close, f1) == 0);

    CHECK(SYS(SYS_renameat2, dirfd, "r1", dirfd, "r3", RENAME_NOREPLACE) == 0);
    CHECK(SYS(SYS_newfstatat, dirfd, "r1", &st_a, 0) == -ENOENT);
    CHECK(SYS(SYS_renameat2, dirfd, "r3", dirfd, "r2", 0) == 0);
    CHECK(SYS(SYS_unlinkat, dirfd, "r2", 0) == 0);

    /* utimensat */
    struct timespec ts[2] = {
        { .tv_sec = 1700000000, .tv_nsec = 123000 },
        { .tv_sec = 1700000100, .tv_nsec = 456000 },
    };
    CHECK(SYS(SYS_utimensat, dirfd, "alpha.txt", ts, 0) == 0);
    CHECK(SYS(SYS_newfstatat, dirfd, "alpha.txt", &st_a, 0) == 0);
    CHECK(st_a.st_mtim.tv_sec == 1700000100);
    struct timespec bad_ts[2] = {
        { .tv_sec = 0, .tv_nsec = 1000000000L },
        { .tv_sec = 0, .tv_nsec = UTIME_OMIT },
    };
    CHECK(SYS(SYS_utimensat, dirfd, "alpha.txt", bad_ts, 0) == -EINVAL);

    /* Clean up sub entries */
    CHECK(SYS(SYS_unlinkat, dirfd, "sym_item", 0) == 0);
    CHECK(SYS(SYS_unlinkat, dirfd, "sym_sub", 0) == 0);
    CHECK(SYS(SYS_unlinkat, dirfd, "sub/item.txt", 0) == 0);
    CHECK(SYS(SYS_unlinkat, dirfd, "sub", AT_REMOVEDIR) == 0);
    CHECK(SYS(SYS_unlinkat, dirfd, "sub2", AT_REMOVEDIR) == 0);
}

static void check_cwd_fcntl_close_range(int dirfd, const char *root_path) {
    char orig[256];
    CHECK(SYS(SYS_getcwd, orig, sizeof orig) > 0);
    CHECK(SYS(SYS_getcwd, orig, 1) == -ERANGE);

    CHECK(SYS(SYS_mkdirat, dirfd, "cwd_dir", 0755) == 0);
    CHECK(SYS(SYS_fchdir, dirfd) == 0);
    char cur[256];
    CHECK(SYS(SYS_getcwd, cur, sizeof cur) > 0);
    CHECK(strcmp(cur, root_path) == 0);

    CHECK(SYS(SYS_chdir, "cwd_dir") == 0);
    CHECK(SYS(SYS_getcwd, cur, sizeof cur) > 0);
    char expected[300];
    snprintf(expected, sizeof expected, "%s/cwd_dir", root_path);
    CHECK(strcmp(cur, expected) == 0);
    CHECK(SYS(SYS_chdir, "../alpha.txt") == -ENOTDIR);

    /* fcntl F_DUPFD / F_DUPFD_CLOEXEC / F_GETFL / F_SETFL + close_range */
    int fd = (int)SYS(SYS_openat, dirfd, "alpha.txt", O_RDWR, 0);
    CHECK(fd >= 0);
    int d1 = (int)SYS(SYS_fcntl, fd, F_DUPFD, 20);
    CHECK(d1 >= 20);
    CHECK(SYS(SYS_fcntl, d1, F_GETFD) == 0);
    int d2 = (int)SYS(SYS_fcntl, fd, F_DUPFD_CLOEXEC, 21);
    CHECK(d2 >= 21);
    CHECK(SYS(SYS_fcntl, d2, F_GETFD) == FD_CLOEXEC);
    CHECK(SYS(SYS_fcntl, fd, F_DUPFD, -1L) == -EINVAL);

    /* Status flags are shared across duplicated descriptors */
    CHECK(SYS(SYS_fcntl, d1, F_SETFL, O_APPEND | O_NONBLOCK) == 0);
    long fl = SYS(SYS_fcntl, fd, F_GETFL);
    CHECK((fl & (O_APPEND | O_NONBLOCK)) == (O_APPEND | O_NONBLOCK));

    /* close_range CLOEXEC then close */
    CHECK(SYS(SYS_close_range, 21, 20, 0) == -EINVAL);
    CHECK(SYS(SYS_close_range, d1, d2, CLOSE_RANGE_CLOEXEC) == 0);
    CHECK(SYS(SYS_fcntl, d1, F_GETFD) == FD_CLOEXEC);
    CHECK(SYS(SYS_close_range, d1, d2, 0) == 0);
    CHECK(SYS(SYS_fcntl, d1, F_GETFD) == -EBADF);
    CHECK(SYS(SYS_fcntl, d2, F_GETFD) == -EBADF);
    CHECK(SYS(SYS_close, fd) == 0);

    CHECK(SYS(SYS_chdir, orig) == 0);
    CHECK(SYS(SYS_unlinkat, dirfd, "cwd_dir", AT_REMOVEDIR) == 0);
}

static void check_file_and_shared_mmap(int dirfd) {
    int fd = (int)SYS(SYS_openat, dirfd, "mapped.bin", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK(fd >= 0);
    static const char initial[] = "0123456789abcdef";
    CHECK(SYS(SYS_write, fd, initial, 16) == 16);

    /* MAP_PRIVATE: reads file, writes do not affect file */
    char *priv = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    CHECK(priv != MAP_FAILED);
    CHECK(memcmp(priv, initial, 16) == 0);
    memcpy(priv, "ZZZZ", 4);
    CHECK(SYS(SYS_munmap, priv, 4096) == 0);

    char check_buf[16];
    CHECK(SYS(SYS_pread64, fd, check_buf, 16, 0) == 16);
    CHECK(memcmp(check_buf, initial, 16) == 0);

    /* MAP_SHARED: writes persist on msync + visible to pread, and pwrite visible in mapping */
    char *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(shared != MAP_FAILED);
    CHECK(memcmp(shared, initial, 16) == 0);
    memcpy(shared, "ABCD", 4);
    CHECK(SYS(SYS_msync, shared, 4096, MS_SYNC) == 0);
    CHECK(SYS(SYS_pread64, fd, check_buf, 16, 0) == 16);
    CHECK(memcmp(check_buf, "ABCD456789abcdef", 16) == 0);

    CHECK(SYS(SYS_pwrite64, fd, "WXYZ", 4, 4) == 4);
    CHECK(memcmp(shared + 4, "WXYZ", 4) == 0);

    /* msync error checks */
    CHECK(SYS(SYS_msync, shared + 1, 4096, MS_SYNC) == -EINVAL);
    CHECK(SYS(SYS_msync, shared, 4096, MS_ASYNC | MS_SYNC) == -EINVAL);
    CHECK(SYS(SYS_munmap, shared, 4096) == 0);
    CHECK(SYS(SYS_msync, shared, 4096, MS_SYNC) == -ENOMEM);

    /* Anonymous MAP_SHARED */
    char *anon = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(anon != MAP_FAILED);
    CHECK(anon[0] == 0 && anon[4095] == 0);
    anon[0] = 42;
    CHECK(SYS(SYS_munmap, anon, 4096) == 0);

    /* Error cases: MAP_SHARED|PROT_WRITE on O_RDONLY -> EACCES; closed fd -> EBADF; pipe -> ENODEV */
    int ro = (int)SYS(SYS_openat, dirfd, "mapped.bin", O_RDONLY, 0);
    CHECK(ro >= 0);
    CHECK(SYS(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, ro, 0) == -EACCES);
    CHECK(SYS(SYS_close, ro) == 0);
    CHECK(SYS(SYS_mmap, 0, 4096, PROT_READ, MAP_PRIVATE, 999, 0) == -EBADF);

    int pfds[2];
    CHECK(SYS(SYS_pipe2, pfds, O_CLOEXEC) == 0);
    CHECK(SYS(SYS_mmap, 0, 4096, PROT_READ, MAP_PRIVATE, pfds[0], 0) == -ENODEV);
    CHECK(SYS(SYS_close, pfds[0]) == 0);
    CHECK(SYS(SYS_close, pfds[1]) == 0);

    CHECK(SYS(SYS_close, fd) == 0);
    CHECK(SYS(SYS_unlinkat, dirfd, "mapped.bin", 0) == 0);
}

#ifdef SYS_open
static void check_legacy_x86_syscalls(const char *root_path) {
    char p1[300], p2[300], pl[300];
    snprintf(p1, sizeof p1, "%s/legacy1", root_path);
    snprintf(p2, sizeof p2, "%s/legacy2", root_path);
    snprintf(pl, sizeof pl, "%s/legacylink", root_path);

    int fd = (int)SYS(SYS_creat, p1, 0644);
    CHECK(fd >= 0);
    CHECK(SYS(SYS_write, fd, "hi", 2) == 2);
    CHECK(SYS(SYS_close, fd) == 0);

    struct stat st;
    CHECK(SYS(SYS_stat, p1, &st) == 0 && st.st_size == 2);
    CHECK(SYS(SYS_access, p1, R_OK | W_OK) == 0);
    CHECK(SYS(SYS_truncate, p1, 1) == 0);
    CHECK(SYS(SYS_stat, p1, &st) == 0 && st.st_size == 1);
    CHECK(SYS(SYS_symlink, p1, pl) == 0);
    CHECK(SYS(SYS_lstat, pl, &st) == 0 && S_ISLNK(st.st_mode));
    char lb[300];
    long ln = SYS(SYS_readlink, pl, lb, sizeof lb);
    CHECK(ln == (long)strlen(p1) && memcmp(lb, p1, (size_t)ln) == 0);
    CHECK(SYS(SYS_unlink, pl) == 0);
    CHECK(SYS(SYS_rename, p1, p2) == 0);
    CHECK(SYS(SYS_unlink, p2) == 0);
}
#endif

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "cross") == 0) {
        return run_cross(argv[2]);
    }

    char scratch[256];
    int created_scratch = 0;
    if (argc >= 2) {
        snprintf(scratch, sizeof scratch, "%s", argv[1]);
    } else {
        long mk = SYS(SYS_mkdirat, AT_FDCWD, "/tmp", 0755);
        CHECK(mk == 0 || mk == -EEXIST);
        snprintf(scratch, sizeof scratch, "/tmp/helios-files-%ld", SYS(SYS_getpid));
        (void)SYS(SYS_unlinkat, AT_FDCWD, scratch, AT_REMOVEDIR);
        CHECK(SYS(SYS_mkdirat, AT_FDCWD, scratch, 0755) == 0);
        created_scratch = 1;
    }

    int dirfd = (int)SYS(SYS_openat, AT_FDCWD, scratch, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    CHECK(dirfd >= 0);

    check_open_rw_seek(dirfd);
    check_dirs_links_rename_meta(dirfd);
    check_cwd_fcntl_close_range(dirfd, scratch);
    check_file_and_shared_mmap(dirfd);
#ifdef SYS_open
    check_legacy_x86_syscalls(scratch);
#endif

    CHECK(SYS(SYS_unlinkat, dirfd, "alpha.txt", 0) == 0);
    CHECK(SYS(SYS_close, dirfd) == 0);
    if (created_scratch) {
        CHECK(SYS(SYS_unlinkat, AT_FDCWD, scratch, AT_REMOVEDIR) == 0);
    }

    puts("files: ok");
    return 0;
}
