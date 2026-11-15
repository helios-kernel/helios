#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

_Thread_local int value = 41;
_Thread_local int zero;

int main(int argc, char **argv) {
    if (argc != 1 || !argv[0] || value++ != 41 || zero++ != 0) return 1;
    errno = 0;
    if (getpid() <= 0 || syscall(SYS_gettid) != getpid()) return 2;
    unsigned long fs_base = 0;
    /* Linux x86-64 ARCH_GET_FS; compare the syscall result to the real TLS register. */
    if (syscall(SYS_arch_prctl, 0x1003, &fs_base) != 0 ||
        fs_base != (unsigned long)__builtin_thread_pointer()) return 3;
    /* A user output pointer must not let the syscall overwrite executable text. */
    if (syscall(SYS_arch_prctl, 0x1003, (void *)main) != -1 || errno != EFAULT) return 5;
    errno = 0;
    if (printf("Hello, %s!\n", "World") < 0) return 4;
    return value != 42 || zero != 1 || errno != 0;
}
