#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>

#ifndef REQUESTER_PATH
#error REQUESTER_PATH is required
#endif

extern int *direct_external_ie_owner_addr(void);

static pthread_barrier_t existing_ready;
static pthread_barrier_t existing_go;
static int (*requester_read)(void);
static int (*requester_exchange)(int);

static void *existing_worker(void *unused)
{
    int *owner_value = direct_external_ie_owner_addr();
    int owner_was_initialized = owner_value && *owner_value == 37;

    (void)unused;
    pthread_barrier_wait(&existing_ready);
    pthread_barrier_wait(&existing_go);
    return (void *)(long)(
        owner_was_initialized && requester_read && requester_exchange &&
        requester_exchange(71) == 37 && requester_read() == 71
            ? 0 : 1);
}

static void *new_worker(void *unused)
{
    int *owner_value = direct_external_ie_owner_addr();

    (void)unused;
    return (void *)(long)(
        owner_value && *owner_value == 37 && requester_read &&
        requester_exchange && requester_exchange(72) == 37 &&
        requester_read() == 72
            ? 0 : 1);
}

int main(void)
{
    pthread_t existing;
    pthread_t fresh;
    void *thread_result = NULL;
    void *requester;
    int *owner_value = direct_external_ie_owner_addr();

    if (!owner_value || *owner_value != 37 ||
        pthread_barrier_init(&existing_ready, NULL, 2) != 0 ||
        pthread_barrier_init(&existing_go, NULL, 2) != 0 ||
        pthread_create(&existing, NULL, existing_worker, NULL) != 0)
        return 1;
    pthread_barrier_wait(&existing_ready);

    requester = dlopen(REQUESTER_PATH, RTLD_NOW | RTLD_GLOBAL);
    if (!requester) {
        fprintf(stderr, "startup-owned IE requester: %s\n", dlerror());
        return 2;
    }
    requester_read =
        (int (*)(void))dlsym(requester, "direct_external_ie_read");
    requester_exchange =
        (int (*)(int))dlsym(requester, "direct_external_ie_exchange");
    if (!requester_read || !requester_exchange || requester_read() != 37 ||
        requester_exchange(61) != 37 || requester_read() != 61 ||
        *owner_value != 61)
        return 3;

    pthread_barrier_wait(&existing_go);
    if (pthread_join(existing, &thread_result) != 0 || thread_result)
        return 4;
    if (pthread_create(&fresh, NULL, new_worker, NULL) != 0 ||
        pthread_join(fresh, &thread_result) != 0 || thread_result)
        return 5;

    pthread_barrier_destroy(&existing_go);
    pthread_barrier_destroy(&existing_ready);
    puts("startup-owned-initial-exec-ok");
    return 0;
}
