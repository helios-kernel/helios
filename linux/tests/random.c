/* getrandom.
 *
 * Expected values: Linux v6.12 drivers/char/random.c (the `getrandom`
 * system call: flag validation, the `import_ubuf` bound at MAX_RW_COUNT,
 * `get_random_bytes_user` returning the bytes copied before a fault, or
 * -EFAULT when none were) and include/uapi/linux/random.h (GRND_*). */
#include "check.h"

#include <stdlib.h>

#define GRND_NONBLOCK 0x1
#define GRND_RANDOM 0x2
#define GRND_INSECURE 0x4

static long draw(void *buffer, size_t length, unsigned flags) {
    return SYS(SYS_getrandom, buffer, length, flags);
}

int main(void) {
    static unsigned char first[256], second[256];

    /* A request up to 256 bytes is always served whole. */
    CHECK(draw(first, sizeof first, 0) == sizeof first);
    CHECK(draw(second, sizeof second, 0) == sizeof second);
    CHECK(memcmp(first, second, sizeof first) != 0);
    unsigned char zero[256] = {0};
    CHECK(memcmp(first, zero, sizeof first) != 0);

    /* Every length around the chunk and page sizes, the buffer's bytes
     * outside the request untouched. */
    static const size_t lengths[] = {0, 1, 31, 32, 33, 63, 64, 65, 255, 256,
                                     4095, 4096, 4097, 8192, 100000};
    size_t capacity = 100000 + 16;
    unsigned char *buffer = malloc(capacity);
    CHECK(buffer);
    for (size_t index = 0; index < sizeof lengths / sizeof *lengths; index++) {
        size_t length = lengths[index];
        memset(buffer, 0x5a, capacity);
        /* A longer draw may return short when a signal arrives, and none
         * does here. */
        CHECK(draw(buffer + 8, length, 0) == (long)length);
        for (size_t at = 0; at < 8; at++) CHECK(buffer[at] == 0x5a);
        for (size_t at = length + 8; at < length + 16; at++) CHECK(buffer[at] == 0x5a);
    }

    /* Each flag alone, and GRND_NONBLOCK beside the others, is valid; the
     * entropy pool is ready, so none changes the result. */
    static const unsigned valid[] = {GRND_NONBLOCK,
                                     GRND_RANDOM,
                                     GRND_INSECURE,
                                     GRND_NONBLOCK | GRND_RANDOM,
                                     GRND_NONBLOCK | GRND_INSECURE};
    for (size_t index = 0; index < sizeof valid / sizeof *valid; index++)
        CHECK(draw(first, 16, valid[index]) == 16);
    /* An unknown flag, and GRND_RANDOM with GRND_INSECURE, are EINVAL
     * before the buffer is looked at. */
    static const unsigned invalid[] = {0x8, 0x10, 0x100, 0x80000000u,
                                       GRND_RANDOM | GRND_INSECURE,
                                       GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE};
    for (size_t index = 0; index < sizeof invalid / sizeof *invalid; index++) {
        CHECK(draw(first, 16, invalid[index]) == -EINVAL);
        CHECK(draw(UNMAPPED, 16, invalid[index]) == -EINVAL);
    }

    /* A buffer that is not the process's to write: EFAULT, nothing drawn. */
    CHECK(draw(UNMAPPED, 16, 0) == -EFAULT);
    CHECK(draw(KERNEL_ADDRESS, 1, 0) == -EFAULT);
    CHECK(draw(KERNEL_ADDRESS, 4096, 0) == -EFAULT);
    CHECK(draw(NULL, 16, 0) == -EFAULT);
    /* A zero-length draw touches nothing, so any address will do. */
    CHECK(draw(UNMAPPED, 0, 0) == 0);

    /* The generator is not obviously biased: over 64 KiB each byte value
     * appears (expected 256 times, deviation 16) between 150 and 400
     * times. */
    unsigned counts[256] = {0};
    for (int round = 0; round < 16; round++) {
        CHECK(draw(buffer, 4096, 0) == 4096);
        for (size_t at = 0; at < 4096; at++) counts[buffer[at]]++;
    }
    for (int value = 0; value < 256; value++) {
        CHECK(counts[value] >= 150);
        CHECK(counts[value] <= 400);
    }

    free(buffer);
    puts("random: ok");
    return 0;
}
