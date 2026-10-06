#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

static pthread_barrier_t barrier;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static int turn;
struct probe { const char *path; int result; int index; };

static int missing(const char *path, int consume)
{
    int saved;
    char *error;
    (void)dlerror();
    errno = 123;
    if (dlopen(path, RTLD_NOW | RTLD_LOCAL)) return 1;
    saved = errno;
    if (!consume) return 0;
    error = dlerror();
    if (!error || !strstr(error, path)) return 2;
    /* Compare these observable values between native, traced and frozen
     * runs. Older GNU libcs and other families need not preserve the caller's
     * errno, and such failures are deliberately not replay witnesses. */
    printf("errno=%d dlerror-errno=%d\n", saved, errno);
    if (dlerror() != NULL) return 4;
    return 0;
}

static void *thread_probe(void *pointer)
{
    struct probe *probe = pointer;
    const char *error;
    pthread_mutex_lock(&mutex);
    while (turn != probe->index)
        pthread_cond_wait(&condition, &mutex);
    probe->result = missing(probe->path, 0);
    turn++;
    pthread_cond_broadcast(&condition);
    pthread_mutex_unlock(&mutex);
    pthread_barrier_wait(&barrier);
    error = dlerror();
    if (!error || !strstr(error, probe->path) || dlerror()) probe->result = 5;
    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t threads[2];
    struct probe probes[2];
    void *handle;
    int (*value)(void);
    if (argc != 4) return 2;
    if (missing(argv[1], 1) || missing(argv[2], 1)) return 10;
    /* A new successful operation replaces an unconsumed failure. */
    if (missing(argv[1], 0)) return 11;
    handle = dlopen(argv[3], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 12;
#if defined(__GLIBC__)
    if (dlerror()) return 12;
#else
    /* Some native libcs retain an unconsumed diagnostic after success.
     * They are not admitted by the GNU missing-root replay contract. */
    (void)dlerror();
#endif
    value = (int (*)(void))dlsym(handle, "test_value");
    if (!value || dlerror() || value() != 42) return 13;
    /* Error storage must remain independent across threads. */
    probes[0] = (struct probe){argv[1], 0, 0};
    probes[1] = (struct probe){argv[2], 0, 1};
    if (pthread_barrier_init(&barrier, NULL, 2)) return 14;
    for (int i = 0; i < 2; i++)
        if (pthread_create(&threads[i], NULL, thread_probe, &probes[i])) return 15;
    for (int i = 0; i < 2; i++)
        if (pthread_join(threads[i], NULL) || probes[i].result) return 16;
    if (dlerror() || dlclose(handle)) return 17;
    pthread_barrier_destroy(&barrier);
    puts("missing roots, fallback plugin, errno and thread-local errors passed");
    return 0;
}
