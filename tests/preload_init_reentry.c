#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <unistd.h>

extern void *__real_dlsym(void *handle, const char *name);

static _Atomic int reentry_failures;

/* Linked with --wrap=dlsym.  Re-enter open() on every resolver lookup: a
 * resolver without a same-thread guard recurses indefinitely, while the
 * guarded helper must use its raw openat fallback until real_open is known. */
void *__wrap_dlsym(void *handle, const char *name)
{
    int saved_errno = errno;
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);

    if (fd < 0)
        atomic_fetch_add_explicit(&reentry_failures, 1,
                                  memory_order_relaxed);
    else
        close(fd);
    errno = saved_errno;
    return __real_dlsym(handle, name);
}

int dlfreeze_test_reentry_failures(void)
{
    return atomic_load_explicit(&reentry_failures, memory_order_relaxed);
}
