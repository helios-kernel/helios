/* Permission, ownership, capability, mknod and extended-attribute syscall
 * conformance fixture.
 *
 * Runs cleanly both natively on Linux (unprivileged or root) and inside a
 * Helios Linux container (on a private btrfs mount or a shared mount).
 */
#include "check.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef XATTR_CREATE
#define XATTR_CREATE 1
#endif
#ifndef XATTR_REPLACE
#define XATTR_REPLACE 2
#endif
#ifndef SYS_fchmodat2
#define SYS_fchmodat2 452
#endif

struct cap_header {
    uint32_t version;
    int32_t pid;
};

struct cap_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

#define LINUX_CAPABILITY_VERSION_3 0x20080522U

int main(void) {
    /* 1. capget / capset */
    struct cap_header hdr = {0, 0};
    struct cap_data data[2];
    memset(data, 0, sizeof(data));

    CHECK(SYS(SYS_capget, &hdr, NULL) == 0);
    CHECK(hdr.version == LINUX_CAPABILITY_VERSION_3);

    hdr.version = 0x12345678U;
    CHECK(SYS(SYS_capget, &hdr, data) == -EINVAL);
    CHECK(hdr.version == LINUX_CAPABILITY_VERSION_3);

    CHECK(SYS(SYS_capget, &hdr, data) == 0);
    CHECK(SYS(SYS_capset, &hdr, data) == 0);

    if ((data[0].permitted & (1U << 21)) == 0) {
        struct cap_data bad[2];
        memcpy(bad, data, sizeof(bad));
        bad[0].effective |= (1U << 21);
        CHECK(SYS(SYS_capset, &hdr, bad) == -EPERM);
    }

    int has_cap_mknod = (data[0].effective & (1U << 27)) != 0;

    /* 2. Scratch directory for file/mode/owner/mknod/xattr checks. */
    char dir[128];
    snprintf(dir, sizeof(dir), "/tmp/helios-perm-%d", (int)getpid());
    (void)rmdir(dir);
    CHECK(mkdir(dir, 0755) == 0);

    int dfd = open(dir, O_RDONLY | O_DIRECTORY);
    CHECK(dfd >= 0);

    mode_t old_mask = umask(0027);
    int fd = openat(dfd, "file", O_CREAT | O_EXCL | O_RDWR, 0666);
    CHECK(fd >= 0);
    umask(old_mask);

    /* chmod / fchmod / fchmodat / fchmodat2 */
    CHECK(fchmod(fd, 0640) == 0);
    CHECK(fchmodat(dfd, "file", 0600, 0) == 0);
    CHECK(symlinkat("file", dfd, "link") == 0);
    CHECK(SYS(SYS_fchmodat2, dfd, "link", 0644, AT_SYMLINK_NOFOLLOW) == -EOPNOTSUPP);
    CHECK(SYS(SYS_fchmodat2, dfd, "file", 0644, 0x8000) == -EINVAL);

    /* chown / fchown / fchownat with (-1, -1) and current (euid, egid). */
    uid_t euid = geteuid();
    gid_t egid = getegid();
    CHECK(fchown(fd, (uid_t)-1, (gid_t)-1) == 0);
    CHECK(fchownat(dfd, "file", euid, egid, 0) == 0);
    CHECK(fchownat(dfd, "link", (uid_t)-1, (gid_t)-1, AT_SYMLINK_NOFOLLOW) == 0);

    /* mknodat: FIFO & regular file without CAP_MKNOD; invalid S_IFDIR -> EINVAL. */
    CHECK(mknodat(dfd, "reg", S_IFREG | 0644, 0) == 0);
    CHECK(mknodat(dfd, "pipe", S_IFIFO | 0644, 0) == 0);
    CHECK(SYS(SYS_mknodat, dfd, "bad-dir", S_IFDIR | 0755, 0) == -EINVAL);
    if (!has_cap_mknod) {
        CHECK(SYS(SYS_mknodat, dfd, "chr", S_IFCHR | 0600, 0x0103) == -EPERM);
    }

    /* Extended attributes (CJK payload); skip storage assertions if EOPNOTSUPP. */
    char fpath[192];
    snprintf(fpath, sizeof(fpath), "%s/file", dir);
    const char *val = "中文 日本語 한국어";
    size_t vlen = strlen(val);

    CHECK(SYS(SYS_fsetxattr, fd, "user.lang", val, vlen, XATTR_CREATE | XATTR_REPLACE) ==
          -EINVAL);

    long set_rc = SYS(SYS_fsetxattr, fd, "user.lang", val, vlen, XATTR_CREATE);
    if (set_rc == 0) {
        CHECK(SYS(SYS_fsetxattr, fd, "user.lang", val, vlen, XATTR_CREATE) == -EEXIST);
        CHECK(getxattr(fpath, "user.lang", NULL, 0) == (ssize_t)vlen);

        char tiny[2];
        CHECK(SYS(SYS_fgetxattr, fd, "user.lang", tiny, sizeof(tiny)) == -ERANGE);

        char out[64];
        CHECK(fgetxattr(fd, "user.lang", out, sizeof(out)) == (ssize_t)vlen);
        CHECK(memcmp(out, val, vlen) == 0);

        char list[128];
        CHECK(flistxattr(fd, list, sizeof(list)) > 0);

        CHECK(fremovexattr(fd, "user.lang") == 0);
        CHECK(SYS(SYS_fgetxattr, fd, "user.lang", out, sizeof(out)) == -ENODATA);
    } else {
        CHECK(set_rc == -EOPNOTSUPP);
    }

    close(fd);
    unlinkat(dfd, "pipe", 0);
    unlinkat(dfd, "reg", 0);
    unlinkat(dfd, "link", 0);
    unlinkat(dfd, "file", 0);
    close(dfd);
    rmdir(dir);

    puts("permissions: ok");
    return 0;
}
