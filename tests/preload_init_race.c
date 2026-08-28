#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

enum { THREAD_COUNT = 32, ITERATIONS = 100 };

static _Atomic int ready_count;
static _Atomic int start_flag;
static _Atomic int failure_count;

extern int dlfreeze_test_reentry_failures(void) __attribute__((weak));

static void record_failure(void)
{
    atomic_fetch_add_explicit(&failure_count, 1, memory_order_relaxed);
}

static void *worker(void *unused)
{
    struct stat st;

    (void)unused;
    atomic_fetch_add_explicit(&ready_count, 1, memory_order_release);
    while (!atomic_load_explicit(&start_flag, memory_order_acquire))
        sched_yield();

    for (int i = 0; i < ITERATIONS; i++) {
        FILE *file;
        DIR *dir;
        int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);

        if (fd < 0) {
            record_failure();
        } else {
            if (fstat(fd, &st) != 0)
                record_failure();
            close(fd);
        }

        fd = openat(AT_FDCWD, "/dev/null", O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            record_failure();
        else
            close(fd);

        if (stat("/dev/null", &st) != 0 ||
            fstatat(AT_FDCWD, "/dev/null", &st, 0) != 0 ||
            access("/dev/null", R_OK) != 0)
            record_failure();

        file = fopen("/dev/null", "r");
        if (!file)
            record_failure();
        else
            fclose(file);

        dir = opendir("/dev");
        if (!dir)
            record_failure();
        else
            closedir(dir);
    }
    return NULL;
}

int main(void)
{
    pthread_t threads[THREAD_COUNT];
    int created = 0;

    for (; created < THREAD_COUNT; created++) {
        if (pthread_create(&threads[created], NULL, worker, NULL) != 0)
            break;
    }
    if (created != THREAD_COUNT) {
        atomic_store_explicit(&start_flag, 1, memory_order_release);
        for (int i = 0; i < created; i++)
            pthread_join(threads[i], NULL);
        return 2;
    }

    while (atomic_load_explicit(&ready_count, memory_order_acquire) !=
           THREAD_COUNT)
        sched_yield();
    atomic_store_explicit(&start_flag, 1, memory_order_release);

    for (int i = 0; i < THREAD_COUNT; i++) {
        if (pthread_join(threads[i], NULL) != 0)
            record_failure();
    }

    if (dlfreeze_test_reentry_failures &&
        dlfreeze_test_reentry_failures() != 0)
        record_failure();

    if (atomic_load_explicit(&failure_count, memory_order_relaxed) != 0)
        return 1;
    puts("preload-init-race-ok");
    return 0;
}
