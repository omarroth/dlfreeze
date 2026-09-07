#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int open_needs_mode(int flags)
{
    return (flags & O_CREAT) ||
#ifdef O_TMPFILE
           ((flags & O_TMPFILE) == O_TMPFILE);
#else
           0;
#endif
}

int openat(int dirfd, const char *path, int flags, ...)
{
    static int (*next_openat)(int, const char *, int, ...);
    static int replaced;
    const char *replacement = getenv("DLFREEZE_DIRFD_REPLACEMENT");
    mode_t mode = 0;
    int replacement_fd;

    if (open_needs_mode(flags)) {
        va_list arguments;

        va_start(arguments, flags);
        mode = va_arg(arguments, mode_t);
        va_end(arguments);
    }
    if (!next_openat)
        next_openat = (int (*)(int, const char *, int, ...))
            dlsym(RTLD_NEXT, "openat");
    if (!next_openat)
        return -1;

    if (!replaced && replacement && replacement[0] &&
        dirfd != AT_FDCWD && strcmp(path, "input.txt") == 0) {
        replacement_fd = next_openat(
            AT_FDCWD, replacement, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (replacement_fd < 0 || dup2(replacement_fd, dirfd) != dirfd) {
            if (replacement_fd >= 0)
                (void)close(replacement_fd);
            return -1;
        }
        if (replacement_fd != dirfd)
            (void)close(replacement_fd);
        replaced = 1;
    }
    if (open_needs_mode(flags))
        return next_openat(dirfd, path, flags, mode);
    return next_openat(dirfd, path, flags);
}
