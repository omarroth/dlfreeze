#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static _Atomic int ready;
static _Atomic int finished;
static int (*plugin_entry)(void);
static int result;

/* The worker predates dlopen and must perform genuinely cold calls while
 * the constructor waits: one in the main PLT and two in the plugin PLT,
 * including an IFUNC. No dlsym or second dlopen is needed to release it. */
static void *worker(void *unused)
{
    (void)unused;
    while (!atomic_load_explicit(&ready, memory_order_acquire))
        sched_yield();
    result = getppid() > 0 && plugin_entry() == 42;
    atomic_store_explicit(&finished, 1, memory_order_release);
    return NULL;
}

void constructor_binding_hold(int (*entry)(void))
{
    struct timespec start, now;

    if (clock_gettime(CLOCK_MONOTONIC, &start))
        _Exit(10);
    plugin_entry = entry;
    atomic_store_explicit(&ready, 1, memory_order_release);
    while (!atomic_load_explicit(&finished, memory_order_acquire)) {
        if (clock_gettime(CLOCK_MONOTONIC, &now) ||
            now.tv_sec - start.tv_sec >= 10)
            _Exit(11);
        sched_yield();
    }
}

int main(int argc, char **argv)
{
    pthread_t thread;
    void *handle;

    if (argc != 2 || pthread_create(&thread, NULL, worker, NULL))
        return 1;
    handle = dlopen(argv[1], RTLD_LAZY | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        return 2;
    }
    if (pthread_join(thread, NULL) || !result || dlclose(handle))
        return 3;
    puts("constructor-binding-ok");
    return 0;
}
