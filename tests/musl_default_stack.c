#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

struct worker_result {
    size_t stack_size;
    int status;
};

#ifdef DLFREEZE_STACK_STARTUP_DEP
extern int dlfreeze_stack_startup_dependency(void);
#endif

static int default_stack_size(size_t *size_out)
{
    pthread_attr_t attr;
    int status;
    int destroy_status;

    status = pthread_getattr_default_np(&attr);
    if (status != 0)
        return status;
    status = pthread_attr_getstacksize(&attr, size_out);
    destroy_status = pthread_attr_destroy(&attr);
    return status != 0 ? status : destroy_status;
}

static void *measure_worker_stack(void *argument)
{
    struct worker_result *result = argument;
    pthread_attr_t attr;
    void *stack_base = NULL;

    result->status = pthread_getattr_np(pthread_self(), &attr);
    if (result->status != 0)
        return NULL;
    result->status = pthread_attr_getstack(
        &attr, &stack_base, &result->stack_size);
    if (pthread_attr_destroy(&attr) != 0 && result->status == 0)
        result->status = 1;
    if (!stack_base && result->status == 0)
        result->status = 1;
    return NULL;
}

static int worker_stack_size(size_t *size_out)
{
    struct worker_result result = {0};
    pthread_t thread;
    int status;

    status = pthread_create(&thread, NULL, measure_worker_stack, &result);
    if (status != 0)
        return status;
    status = pthread_join(thread, NULL);
    if (status != 0)
        return status;
    if (result.status != 0)
        return result.status;
    *size_out = result.stack_size;
    return 0;
}

int main(int argc, char **argv)
{
    size_t default_before;
    size_t worker_before;

#ifdef DLFREEZE_STACK_STARTUP_DEP
    if (dlfreeze_stack_startup_dependency() != 73)
        return 8;
#endif
    if (default_stack_size(&default_before) != 0 ||
        worker_stack_size(&worker_before) != 0)
        return 2;
    if (argc == 1) {
        printf("default=%zu worker=%zu\n", default_before, worker_before);
        return 0;
    }
    if (argc == 2) {
        size_t default_after;
        size_t worker_after;
        void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
        int (*touch)(void);

        if (!handle)
            return 3;
        touch = (int (*)(void))dlsym(handle, "dlfreeze_stack_touch");
        if (!touch || touch() != 73)
            return 4;
        if (default_stack_size(&default_after) != 0 ||
            worker_stack_size(&worker_after) != 0)
            return 5;
        printf("before=%zu/%zu after=%zu/%zu\n",
               default_before, worker_before, default_after, worker_after);
        return default_before == default_after &&
               worker_before == worker_after ? 0 : 6;
    }
    return 7;
}
