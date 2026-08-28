#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

static int (*touch_tls)(unsigned int);
static uintptr_t cached_thread_tps[2];

static uintptr_t current_tp(void)
{
    uintptr_t tp;

#if defined(__x86_64__)
    __asm__ volatile("movq %%fs:0, %0" : "=r"(tp));
#elif defined(__aarch64__)
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tp));
#else
#error unsupported architecture
#endif
    return tp;
}

static void *worker(void *argument)
{
    uintptr_t value = (uintptr_t)argument;

    if (value == 0x41)
        cached_thread_tps[0] = current_tp();
    else if (value == 0x42)
        cached_thread_tps[1] = current_tp();
    return (void *)(uintptr_t)!touch_tls((unsigned int)value);
}

static unsigned long virtual_pages(void)
{
    FILE *file = fopen("/proc/self/statm", "r");
    unsigned long pages = 0;

    if (!file)
        return 0;
    if (fscanf(file, "%lu", &pages) != 1)
        pages = 0;
    fclose(file);
    return pages;
}

static int run_thread(pthread_attr_t *attribute, unsigned int value)
{
    pthread_t thread;
    void *result = NULL;

    if (pthread_create(&thread, attribute, worker,
                       (void *)(uintptr_t)value) != 0 ||
        pthread_join(thread, &result) != 0 || result)
        return 0;
    return 1;
}

int main(int argc, char **argv)
{
    const size_t stack_size = 256 * 1024;
    const long page_size = sysconf(_SC_PAGESIZE);
    pthread_attr_t attribute;
    unsigned long before;
    unsigned long after;
    void *stack;
    void *handle;

    if (argc != 2 || page_size <= 0)
        return 2;
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return 3;
    touch_tls = (int (*)(unsigned int))dlsym(
        handle, "direct_tls_teardown_touch");
    if (!touch_tls)
        return 4;

    /* Default stacks normally enter glibc's cache.  On reuse glibc itself
     * frees and clears dynamic DTV entries before _dl_allocate_tls_init. */
    if (!run_thread(NULL, 0x41) || !run_thread(NULL, 0x42) ||
        cached_thread_tps[0] == 0 ||
        cached_thread_tps[0] != cached_thread_tps[1])
        return 9;
    stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack == MAP_FAILED || pthread_attr_init(&attribute) != 0 ||
        pthread_attr_setstack(&attribute, stack, stack_size) != 0)
        return 5;

    /* A caller-provided stack bypasses glibc's pthread stack cache, forcing
     * `_dl_deallocate_tls(tcb, false)` after every join. */
    if (!run_thread(&attribute, 1))
        return 6;
    before = virtual_pages();
    if (!before)
        return 77;
    for (unsigned int i = 2; i < 34; i++) {
        if (!run_thread(&attribute, i))
            return 7;
    }
    after = virtual_pages();
    pthread_attr_destroy(&attribute);
    munmap(stack, stack_size);
    dlclose(handle);
    if (!after || after > before + (unsigned long)(8 * 1024 * 1024 /
                                                    page_size))
        return 8;
    puts("tls-teardown-ok");
    return 0;
}
