#include <locale.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

static _Thread_local int tls_value = 7;

static void *worker(void *opaque)
{
    tls_value += *(const int *)opaque;
    return (void *)(intptr_t)tls_value;
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
    return 0;
}
