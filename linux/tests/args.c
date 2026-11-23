#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Prints its arguments and the environment variable the launcher set, one
 * per line, and exits with the status its first argument names. */
int main(int argc, char **argv) {
    if (argc < 2) return 100;
    for (int index = 1; index < argc; index++) {
        if (printf("arg%d=%s\n", index, argv[index]) < 0) return 101;
    }
    const char *pid = getenv("HELIOS_PROCESS_ID");
    if (!pid || !*pid) return 102;
    if (printf("environment:ok\n") < 0) return 103;
    return atoi(argv[1]);
}
