/* getuid, geteuid, getgid, getegid, getresuid, getresgid and getgroups.
 *
 * The IDs are values the process reports, so the fixture checks that the
 * calls agree with each other and fail as Linux's do, not what the IDs are.
 *
 * Expected values: Linux v6.12 kernel/sys.c (`getuid`, `geteuid`, `getgid`,
 * `getegid`, `getresuid` and `getresgid`, whose `put_user`s stop at the
 * first fault) and kernel/groups.c (`getgroups`: a zero size only counts,
 * a short list is EINVAL, a fault EFAULT). */
#include "check.h"

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    uint32_t real, effective, saved;

    CHECK(SYS(SYS_getresuid, &real, &effective, &saved) == 0);
    CHECK((uint32_t)SYS(SYS_getuid) == real);
    CHECK((uint32_t)SYS(SYS_geteuid) == effective);
    CHECK(SYS(SYS_getresgid, &real, &effective, &saved) == 0);
    CHECK((uint32_t)SYS(SYS_getgid) == real);
    CHECK((uint32_t)SYS(SYS_getegid) == effective);
    /* libc reads the same values. */
    CHECK(getuid() == (uid_t)SYS(SYS_getuid));
    CHECK(getegid() == (gid_t)SYS(SYS_getegid));

    /* Each of the three IDs is stored in turn, up to the first that faults:
     * the first alone, then the first two, are written. */
    uint32_t ids[3];
    memset(ids, 0xaa, sizeof ids);
    CHECK(SYS(SYS_getresuid, &ids[0], UNMAPPED, &ids[2]) == -EFAULT);
    CHECK(ids[0] == (uint32_t)SYS(SYS_getuid));
    CHECK(ids[1] == 0xaaaaaaaau && ids[2] == 0xaaaaaaaau);
    memset(ids, 0xaa, sizeof ids);
    CHECK(SYS(SYS_getresgid, &ids[0], &ids[1], KERNEL_ADDRESS) == -EFAULT);
    CHECK(ids[0] == (uint32_t)SYS(SYS_getgid));
    CHECK(ids[1] == (uint32_t)SYS(SYS_getegid));
    CHECK(ids[2] == 0xaaaaaaaau);

    /* The supplementary groups: counted, then listed. */
    long count = SYS(SYS_getgroups, 0, NULL);
    CHECK(count >= 0 && count <= 65536);
    /* A zero size never touches the list, so any address will do. */
    CHECK(SYS(SYS_getgroups, 0, UNMAPPED) == count);
    gid_t *groups = calloc((size_t)count + 1, sizeof *groups);
    CHECK(groups);
    CHECK(SYS(SYS_getgroups, count, groups) == count);
    /* A larger list is served the same. */
    CHECK(SYS(SYS_getgroups, count + 1, groups) == count);
    CHECK(getgroups(0, NULL) == count);
    if (count > 0) {
        CHECK(SYS(SYS_getgroups, count - 1, groups) == -EINVAL);
        CHECK(SYS(SYS_getgroups, count, UNMAPPED) == -EFAULT);
    }
    /* A negative size is EINVAL whatever the list. */
    CHECK(SYS(SYS_getgroups, -1, groups) == -EINVAL);
    CHECK(SYS(SYS_getgroups, INT32_MIN, NULL) == -EINVAL);
    free(groups);

    puts("identity: ok");
    return 0;
}
