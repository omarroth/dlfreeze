#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <unistd.h>

atomic_int dlfreeze_cwd_block_entered;
atomic_int dlfreeze_cwd_block_release;

static const char *new_cwd;
static int chdir_result = -1;

static void *change_cwd(void *unused)
{
    (void)unused;
    chdir_result = chdir(new_cwd);
    return NULL;
}

int main(int argc, char **argv)
{
    int (*value)(void) = NULL;
    pthread_t thread;
    void *handle = NULL;
    char byte;
    int fd = -1;
    int ok = 1;

    if (argc != 4)
        return 2;
    new_cwd = argv[1];
    alarm(10);
    if (pthread_create(&thread, NULL, change_cwd, NULL) != 0)
        return 3;
    while (!atomic_load_explicit(&dlfreeze_cwd_block_entered,
                                 memory_order_acquire))
        sched_yield();

    /* Both requests complete against the old cwd while the interposed chdir
     * is deliberately held between the helper's epoch begin/end markers.
     * The helper must reject attribution without deadlocking either call. */
    fd = open(argv[2], O_RDONLY | O_CLOEXEC);
    if (fd < 0 || read(fd, &byte, 1) != 1)
        ok = 0;
    if (fd >= 0 && close(fd) != 0)
        ok = 0;

    handle = dlopen(argv[3], RTLD_NOW | RTLD_LOCAL);
    if (handle) {
        value = (int (*)(void))dlsym(handle, "cwd_overlap_value");
        if (!value || value() != 43)
            ok = 0;
    } else {
        ok = 0;
    }

    atomic_store_explicit(&dlfreeze_cwd_block_release, 1,
                          memory_order_release);
    if (pthread_join(thread, NULL) != 0 || chdir_result != 0)
        ok = 0;
    if (handle)
        (void)dlclose(handle);
    if (!ok)
        return 4;
    puts("cwd-overlap-ok");
    return 0;
}
