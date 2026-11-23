/* Terminal and descriptor ioctl conformance fixture: `TCGETS`, `TCSETS`,
 * `TCSETSW`, `TCSETSF`, `TIOCGWINSZ`, `TIOCSWINSZ`, `FIONBIO`, `FIOCLEX`,
 * `FIONCLEX`, plus `ENOTTY` / `EBADF` / `EFAULT` checks.
 *
 * Usage:
 *   tty              Auto-detect whether stdout is a TTY.
 *   tty expect-tty   Require stdout/stdin to be a TTY and test termios/winsize
 *                    mutation round-trips.
 */
#include "check.h"

#include <fcntl.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <termios.h>

#ifndef TCGETS
#define TCGETS 0x5401
#endif
#ifndef TCSETS
#define TCSETS 0x5402
#endif
#ifndef TCSETSW
#define TCSETSW 0x5403
#endif
#ifndef TCSETSF
#define TCSETSF 0x5404
#endif
#ifndef TIOCGWINSZ
#define TIOCGWINSZ 0x5413
#endif
#ifndef TIOCSWINSZ
#define TIOCSWINSZ 0x5414
#endif
#ifndef FIONBIO
#define FIONBIO 0x5421
#endif
#ifndef FIONCLEX
#define FIONCLEX 0x5450
#endif
#ifndef FIOCLEX
#define FIOCLEX 0x5451
#endif

struct kernel_termios_raw {
    uint32_t c_iflag;
    uint32_t c_oflag;
    uint32_t c_cflag;
    uint32_t c_lflag;
    uint8_t c_line;
    uint8_t c_cc[19];
};

int main(int argc, char **argv) {
    int expect_tty = argc >= 2 && strcmp(argv[1], "expect-tty") == 0;

    /* Closed fd -> EBADF */
    struct kernel_termios_raw tio;
    struct winsize ws;
    CHECK(SYS(SYS_ioctl, 996, TCGETS, &tio) == -EBADF);

    /* Pipe is not a TTY -> ENOTTY; FIONBIO / FIOCLEX / FIONCLEX work on pipes */
    int pfds[2];
    CHECK(SYS(SYS_pipe2, pfds, 0) == 0);
    CHECK(SYS(SYS_ioctl, pfds[0], TCGETS, &tio) == -ENOTTY);
    CHECK(SYS(SYS_ioctl, pfds[0], TIOCGWINSZ, &ws) == -ENOTTY);

    int one = 1, zero = 0;
    CHECK(SYS(SYS_ioctl, pfds[0], FIONBIO, &one) == 0);
    CHECK((SYS(SYS_fcntl, pfds[0], F_GETFL) & O_NONBLOCK) != 0);
    CHECK(SYS(SYS_ioctl, pfds[0], FIONBIO, &zero) == 0);
    CHECK((SYS(SYS_fcntl, pfds[0], F_GETFL) & O_NONBLOCK) == 0);
    CHECK(SYS(SYS_ioctl, pfds[0], FIONBIO, UNMAPPED) == -EFAULT);

    CHECK(SYS(SYS_ioctl, pfds[0], FIOCLEX, 0) == 0);
    CHECK(SYS(SYS_fcntl, pfds[0], F_GETFD) == FD_CLOEXEC);
    CHECK(SYS(SYS_ioctl, pfds[0], FIONCLEX, 0) == 0);
    CHECK(SYS(SYS_fcntl, pfds[0], F_GETFD) == 0);

    CHECK(SYS(SYS_close, pfds[0]) == 0);
    CHECK(SYS(SYS_close, pfds[1]) == 0);

    /* Test TCGETS / TCSETS* / TIOCGWINSZ / TIOCSWINSZ on stdout when it is a TTY */
    long rc = SYS(SYS_ioctl, 1, TCGETS, &tio);
    if (expect_tty) {
        CHECK(rc == 0);
    }
    if (rc == 0) {
        struct kernel_termios_raw saved = tio;
        CHECK(SYS(SYS_ioctl, 1, TCGETS, UNMAPPED) == -EFAULT);

        struct kernel_termios_raw raw = saved;
        raw.c_lflag &= ~(uint32_t)(ICANON | ECHO);
        CHECK(SYS(SYS_ioctl, 1, TCSETS, &raw) == 0);

        struct kernel_termios_raw check_tio;
        memset(&check_tio, 0, sizeof check_tio);
        CHECK(SYS(SYS_ioctl, 1, TCGETS, &check_tio) == 0);
        CHECK((check_tio.c_lflag & (ICANON | ECHO)) == 0);

        CHECK(SYS(SYS_ioctl, 1, TCSETSW, &saved) == 0);
        CHECK(SYS(SYS_ioctl, 1, TCSETSF, &saved) == 0);
        CHECK(SYS(SYS_ioctl, 1, TCGETS, &check_tio) == 0);
        CHECK(check_tio.c_lflag == saved.c_lflag);

        struct winsize saved_ws;
        CHECK(SYS(SYS_ioctl, 1, TIOCGWINSZ, &saved_ws) == 0);
        CHECK(SYS(SYS_ioctl, 1, TIOCGWINSZ, UNMAPPED) == -EFAULT);

        struct winsize next_ws = { .ws_row = 40, .ws_col = 120, .ws_xpixel = 0, .ws_ypixel = 0 };
        CHECK(SYS(SYS_ioctl, 1, TIOCSWINSZ, &next_ws) == 0);
        memset(&ws, 0, sizeof ws);
        CHECK(SYS(SYS_ioctl, 1, TIOCGWINSZ, &ws) == 0);
        CHECK(ws.ws_row == 40 && ws.ws_col == 120);
        CHECK(SYS(SYS_ioctl, 1, TIOCSWINSZ, &saved_ws) == 0);
    } else {
        CHECK(rc == -ENOTTY);
        CHECK(SYS(SYS_ioctl, 1, TIOCGWINSZ, &ws) == -ENOTTY);
    }

    puts("tty: ok");
    return 0;
}
