#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int (*next_open)(const char *, int, ...);

static int needs_mode(int flags)
{
    return (flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE;
}

int open(const char *path, int flags, ...)
{
    const char *exit_path;
    mode_t mode = 0;
    int fd;

    if (needs_mode(flags)) {
        va_list arguments;

        va_start(arguments, flags);
        mode = va_arg(arguments, mode_t);
        va_end(arguments);
    }
    if (!next_open) {
        void *symbol = dlsym(RTLD_NEXT, "open");

        memcpy(&next_open, &symbol, sizeof(next_open));
    }
    if (!next_open)
        _exit(125);
    fd = needs_mode(flags)
        ? next_open(path, flags, mode) : next_open(path, flags);
    exit_path = getenv("DLFREEZE_EXIT_AFTER_OPEN");
    if (fd >= 0 && exit_path && strcmp(path, exit_path) == 0)
        _exit(0);
    return fd;
}
