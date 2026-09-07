#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Close the helper's visible file-trace descriptor, reuse that number for an
 * unrelated application file, then perform a traceable open.  The close
 * interposer must preserve the trace on a hidden descriptor without writing
 * trace bytes to, closing, or otherwise corrupting the reused application
 * descriptor. */
int main(int argc, char **argv)
{
    char proc_path[64];
    char target[PATH_MAX];
    int trace_fd = -1;
    int replacement;
    int input;
    static const char marker[] = "application-fd-ok\n";

    if (argc != 4)
        return 2;

    for (int fd = 3; fd < 1024; fd++) {
        int length = snprintf(proc_path, sizeof(proc_path),
                              "/proc/self/fd/%d", fd);
        ssize_t target_length;

        if (length < 0 || (size_t)length >= sizeof(proc_path))
            return 3;
        target_length = readlink(proc_path, target, sizeof(target) - 1);
        if (target_length < 0)
            continue;
        if ((size_t)target_length >= sizeof(target) - 1)
            return 4;
        target[target_length] = '\0';
        if (strcmp(target, argv[1]) == 0) {
            trace_fd = fd;
            break;
        }
    }
    if (trace_fd < 0)
        return 5;
    if (close(trace_fd) != 0)
        return 6;

    replacement = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (replacement < 0)
        return 7;
    if (replacement != trace_fd) {
        if (dup2(replacement, trace_fd) != trace_fd)
            return 8;
        if (close(replacement) != 0)
            return 9;
        replacement = trace_fd;
    }

    if (write(replacement, marker, sizeof(marker) - 1) !=
            (ssize_t)(sizeof(marker) - 1) ||
        close(replacement) != 0)
        return 10;

    input = open(argv[3], O_RDONLY);
    if (input < 0)
        return 11;
    return close(input) == 0 ? 0 : 12;
}
