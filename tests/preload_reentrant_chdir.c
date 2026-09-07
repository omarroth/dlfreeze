#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

static _Thread_local int reentrant_depth;

int chdir(const char *path)
{
    static int (*libc_chdir)(const char *);
    const char *nested;

    if (!libc_chdir)
        libc_chdir = (int (*)(const char *))dlsym(RTLD_NEXT, "chdir");
    if (!libc_chdir) {
        errno = ENOSYS;
        return -1;
    }
    nested = getenv("DLFREEZE_REENTRANT_CWD");
    if (reentrant_depth == 0 && nested && nested[0]) {
        int (*front_chdir)(const char *) =
            (int (*)(const char *))dlsym(RTLD_DEFAULT, "chdir");

        if (!front_chdir) {
            errno = ENOSYS;
            return -1;
        }
        reentrant_depth = 1;
        if (front_chdir(nested) != 0) {
            reentrant_depth = 0;
            return -1;
        }
        reentrant_depth = 0;
    }
    return libc_chdir(path);
}
