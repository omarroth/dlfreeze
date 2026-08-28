#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct chain_request {
    const char *path;
    int expected;
    int result;
};

static void *load_chain(void *opaque)
{
    struct chain_request *request = opaque;
    int (*value)(void);
    void *handle;

    handle = dlopen(request->path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        request->result = 3;
        return NULL;
    }
    value = (int (*)(void))dlsym(handle, "dlfrz_chain_0");
    if (!value) {
        fprintf(stderr, "dlsym: %s\n", dlerror());
        request->result = 4;
        return NULL;
    }
    if (value() != request->expected) {
        request->result = 5;
        return NULL;
    }
    request->result = 0;
    return NULL;
}

int main(int argc, char **argv)
{
    static const size_t stack_sizes[] = {64U * 1024U, 128U * 1024U};
    struct chain_request request;
    pthread_attr_t attr;
    pthread_t thread;
    size_t selected = 0;
    int error;

    if (argc == 1) {
        puts("small-stack-ready");
        return 0;
    }
    if (argc != 3)
        return 2;
    request.path = argv[1];
    request.expected = atoi(argv[2]);
    request.result = 6;
    if (request.expected <= 0 || pthread_attr_init(&attr) != 0)
        return 2;
    for (size_t i = 0; i < sizeof(stack_sizes) / sizeof(stack_sizes[0]);
         i++) {
        if (pthread_attr_setstacksize(&attr, stack_sizes[i]) == 0) {
            selected = stack_sizes[i];
            break;
        }
    }
    if (selected == 0) {
        pthread_attr_destroy(&attr);
        return 7;
    }
    error = pthread_create(&thread, &attr, load_chain, &request);
    pthread_attr_destroy(&attr);
    if (error != 0)
        return 8;
    if (pthread_join(thread, NULL) != 0)
        return 9;
    if (request.result != 0)
        return request.result;
    printf("small-stack-chain=%d stack=%zu\n", request.expected,
           selected / 1024U);
    return 0;
}
