#include <locale.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static _Thread_local int tls_value = 7;
static pthread_t initial_thread;
static int initial_result;

static void *worker(void *opaque)
{
    tls_value += *(const int *)opaque;
    return (void *)(intptr_t)tls_value;
}

static void *join_initial_thread(void *opaque)
{
    static const char success[] = "musl-initial-thread-joined\n";
    void *result = NULL;

    if (pthread_join(initial_thread, &result) != 0 || result != opaque)
        _Exit(3);
    if (write(STDOUT_FILENO, success, sizeof(success) - 1) !=
        (ssize_t)(sizeof(success) - 1))
        _Exit(4);
    _Exit(0);
}

int main(void)
{
    pthread_t thread;
    void *result = NULL;
    int increment = 5;
    locale_t locale = uselocale((locale_t)0);

    if (!locale || pthread_create(&thread, NULL, worker, &increment) != 0 ||
        pthread_join(thread, &result) != 0)
        return 2;
    printf("musl-contract:%ld:%d\n", (long)(intptr_t)result, tls_value);
    if (fflush(stdout) != 0)
        return 3;

    /* musl's join synchronization waits on its hidden thread-list lock,
     * which the kernel clears through the initial thread's registered
     * clear_child_tid address after pthread_exit issues SYS_exit. */
    initial_thread = pthread_self();
    if (pthread_create(
            &thread, NULL, join_initial_thread, &initial_result) != 0)
        return 4;
    pthread_exit(&initial_result);
}
