#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#if defined(DLFREEZE_EARLY_DLOPEN_OBJECT)

int preload_early_dlopen_value(void)
{
    return 42;
}

#elif defined(DLFREEZE_EARLY_PRELOAD)

static int constructor_status = 1;

/* This DSO is linked as a dependency of the trace helper in the regression
 * test.  ELF dependency ordering therefore runs this constructor before the
 * helper's constructor, while the helper's interposers are already visible.
 * That deterministically models an earlier user LD_PRELOAD constructor. */
__attribute__((constructor))
static void preload_early_constructor(void)
{
    const char *dlopen_path = getenv("DLFREEZE_EARLY_DLOPEN");
    const char *open_path = getenv("DLFREEZE_EARLY_OPEN");
    int (*value)(void);
    void *handle;
    char byte;
    int fd;

    if (!dlopen_path || !open_path)
        return;
    handle = dlopen(dlopen_path, RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return;
    value = (int (*)(void))dlsym(handle, "preload_early_dlopen_value");
    if (!value || value() != 42)
        return;

    fd = open(open_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return;
    if (read(fd, &byte, 1) == 1)
        constructor_status = 0;
    close(fd);
}

/* The helper must also remain active until every other finalizer is done.
 * Its trace descriptors are process-lifetime resources and are closed by the
 * kernel, which avoids losing activity from a dependency's later destructor.
 */
__attribute__((destructor))
static void preload_late_destructor(void)
{
    const char *path = getenv("DLFREEZE_LATE_DESTRUCTOR_OPEN");
    char byte;
    int fd;

    if (!path)
        return;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t read_result = read(fd, &byte, 1);

        (void)read_result;
        close(fd);
    }
}

int preload_early_constructor_status(void)
{
    return constructor_status;
}

#else

#include <stdio.h>

int main(void)
{
    int (*status)(void) =
        (int (*)(void))dlsym(RTLD_DEFAULT,
                             "preload_early_constructor_status");

    if (!status || status() != 0)
        return 1;
    puts("preload-early-constructor-ok");
    return 0;
}

#endif
