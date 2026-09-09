#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int parse_descriptor(const char *text, int *descriptor_out)
{
    char *end = NULL;
    long value;

    errno = 0;
    value = strtol(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || value < 0 || value > INT_MAX)
        return -1;
    *descriptor_out = (int)value;
    return 0;
}

static int launch_with_lock(const char *artifact, const char *lock_path,
                            const char *expectation)
{
    struct flock lock = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0,
    };
    char descriptor_text[32];
    int descriptor;

    descriptor = open(lock_path, O_RDWR | O_CREAT, 0600);
    if (descriptor < 0)
        return 70;
    if (fcntl(descriptor, F_SETLK, &lock) < 0) {
        if (errno == ENOLCK || errno == ENOSYS || errno == EOPNOTSUPP)
            return 77;
        return 71;
    }
    if (snprintf(descriptor_text, sizeof(descriptor_text), "%d",
                 descriptor) <= 0)
        return 72;

    execl(artifact, artifact, "--target", descriptor_text, expectation,
          (char *)NULL);
    return 73;
}

static int check_inherited_lock(const char *descriptor_text,
                                const char *expectation)
{
    struct flock probe = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0,
    };
    int descriptor;

    if (parse_descriptor(descriptor_text, &descriptor) < 0)
        return 80;
    if (fcntl(descriptor, F_GETLK, &probe) < 0)
        return 81;

    if (strcmp(expectation, "in-process") == 0) {
        /* A process never conflicts with its own POSIX record lock. */
        if (probe.l_type != F_UNLCK)
            return 82;
        probe.l_type = F_WRLCK;
        if (fcntl(descriptor, F_SETLK, &probe) < 0)
            return 83;
        puts("inherited-posix-lock-in-process-ok");
        return 0;
    }

    if (strcmp(expectation, "supervised") == 0) {
        /* fork() leaves ownership in the supervisor, not its child. */
        if (probe.l_type != F_WRLCK || probe.l_pid != getppid())
            return 84;
        probe.l_type = F_WRLCK;
        errno = 0;
        if (fcntl(descriptor, F_SETLK, &probe) != -1 ||
            (errno != EACCES && errno != EAGAIN))
            return 85;
        puts("inherited-posix-lock-supervised-ok");
        return 0;
    }

    return 86;
}

int main(int argc, char **argv)
{
    if (argc == 5 && strcmp(argv[1], "--launch") == 0)
        return launch_with_lock(argv[2], argv[3], argv[4]);
    if (argc == 4 && strcmp(argv[1], "--target") == 0)
        return check_inherited_lock(argv[2], argv[3]);
    return 64;
}
