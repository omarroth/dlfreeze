#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <sched.h>
#include <stdatomic.h>
#include <unistd.h>

extern atomic_int dlfreeze_cwd_block_entered;
extern atomic_int dlfreeze_cwd_block_release;

int chdir(const char *path)
{
    static int (*next_chdir)(const char *);

    if (!next_chdir)
        next_chdir = (int (*)(const char *))dlsym(RTLD_NEXT, "chdir");
    if (!next_chdir)
        return -1;

    atomic_store_explicit(&dlfreeze_cwd_block_entered, 1,
                          memory_order_release);
    while (!atomic_load_explicit(&dlfreeze_cwd_block_release,
                                 memory_order_acquire))
        sched_yield();
    return next_chdir(path);
}
