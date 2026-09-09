#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PLUGIN_DIR
#error "PLUGIN_DIR must name the fixture directory"
#endif

#define PLUGIN_COUNT 12
#define LOADER_THREADS 4
#define READER_THREADS 4
#define MIN_READER_PASSES 64
#define MIN_FORKS 6

static pthread_barrier_t start_barrier;
static _Atomic int next_plugin;
static _Atomic int loaded_plugins;
static _Atomic int completed_readers;
static _Atomic unsigned int failures;
static _Atomic int publication_constructor_waiting;
static _Atomic int publication_constructor_release;
static _Atomic int first_publication_complete;
static _Atomic int quiescent_publications;
static _Atomic int all_publications_quiescent;
static _Atomic int first_fork_complete;
static _Atomic int publication_overlap_observed;
static int publication_overlap_enabled = 1;

static void note_failure(unsigned int bit)
{
    atomic_fetch_or_explicit(&failures, bit, memory_order_relaxed);
}

static int wait_for_flag(_Atomic int *flag)
{
    struct timespec start;
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
        return -1;
    while (!atomic_load_explicit(flag, memory_order_acquire)) {
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
            now.tv_sec - start.tv_sec >= 10)
            return -1;
        sched_yield();
    }
    return 0;
}

static int wait_for_value(_Atomic int *value, int expected)
{
    struct timespec start;
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
        return -1;
    while (atomic_load_explicit(value, memory_order_acquire) != expected) {
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
            now.tv_sec - start.tv_sec >= 10)
            return -1;
        sched_yield();
    }
    return 0;
}

static void note_quiescent_publication(void)
{
    int count = atomic_fetch_add_explicit(
                    &quiescent_publications, 1,
                    memory_order_acq_rel) + 1;

    if (count == PLUGIN_COUNT)
        atomic_store_explicit(
            &all_publications_quiescent, 1, memory_order_release);
    else if (count > PLUGIN_COUNT)
        note_failure(1U << 26);
}

/* Plugin zero calls this exported hook from its constructor while dlopen
 * owns the loader lock.  Holding that constructor until the first fork has
 * entered its application prepare callback proves that fork() overlaps a
 * real loader publication without relying on scheduler timing. */
void loader_stress_publication_hold(int plugin_id)
{
    if (plugin_id != 0 || !publication_overlap_enabled)
        return;
    atomic_store_explicit(
        &publication_constructor_waiting, 1, memory_order_release);
    if (wait_for_flag(&publication_constructor_release) != 0)
        note_failure(1U << 23);
}

/* The loader registers its private atfork handler before application code,
 * so application prepares run first.  This callback observes plugin zero's
 * lock-held constructor, releases it, and waits for every loader worker to
 * reach a quiescent point before returning to the loader-private prepare.
 * Thus the child must see either the coherent completed object or a test
 * failure, never an inferred timing window.  It does not claim that the
 * private prepare itself blocked: that handler begins only after this
 * callback returns. */
static void overlap_atfork_prepare(void)
{
    if (!publication_overlap_enabled)
        return;
    if (atomic_load_explicit(
            &publication_overlap_observed, memory_order_acquire))
        return;
    if (wait_for_flag(&publication_constructor_waiting) != 0) {
        note_failure(1U << 22);
        atomic_store_explicit(
            &publication_constructor_release, 1, memory_order_release);
        return;
    }
    atomic_store_explicit(
        &publication_overlap_observed, 1, memory_order_release);
    atomic_store_explicit(
        &publication_constructor_release, 1, memory_order_release);
    if (wait_for_flag(&first_publication_complete) != 0 ||
        wait_for_flag(&all_publications_quiescent) != 0) {
        note_failure(1U << 24);
        return;
    }
}

static int iterate_callback(struct dl_phdr_info *info, size_t size, void *data)
{
    int *count = data;

    if (!info || size < sizeof(*info) || !info->dlpi_phdr)
        note_failure(1U << 0);
    (*count)++;
    return 0;
}

static int exercise_readers(unsigned int discriminator)
{
    char missing[96];
    void *puts_address;
    const char *error;
    Dl_info info;
    int phdr_count = 0;

    puts_address = dlsym(RTLD_DEFAULT, "puts");
    if (!puts_address || !dladdr(puts_address, &info) || !info.dli_fname)
        return -1;
    if (dl_iterate_phdr(iterate_callback, &phdr_count) != 0 ||
        phdr_count == 0)
        return -2;

    snprintf(missing, sizeof(missing),
             "dlfreeze_missing_%u_%lu", discriminator,
             (unsigned long)pthread_self());
    (void)dlerror();
    if (dlsym(RTLD_DEFAULT, missing) != NULL)
        return -1;
    sched_yield();
    error = dlerror();
    if (!error || !strstr(error, missing) || dlerror() != NULL)
        return -4;
    return 0;
}

static void *loader_worker(void *unused)
{
    (void)unused;
    pthread_barrier_wait(&start_barrier);
    for (;;) {
        char path[1024];
        int index = atomic_fetch_add_explicit(
            &next_plugin, 1, memory_order_relaxed);
        int (*value)(void);
        void *handle;

        if (index >= PLUGIN_COUNT)
            break;
        snprintf(path, sizeof(path), "%s/libloader_stress_%02d.so",
                 PLUGIN_DIR, index);
        handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            note_failure(1U << 8);
            if (index == 0)
                atomic_store_explicit(
                    &first_publication_complete, 1,
                    memory_order_release);
            note_quiescent_publication();
            atomic_fetch_add_explicit(
                &loaded_plugins, 1, memory_order_release);
            continue;
        }
        value = (int (*)(void))dlsym(handle, "loader_stress_value");
        if (!value || value() != 1000 + index)
            note_failure(1U << 9);
        if (index == 0) {
            atomic_store_explicit(
                &first_publication_complete, 1, memory_order_release);
            note_quiescent_publication();
            if (wait_for_flag(&first_fork_complete) != 0)
                note_failure(1U << 25);
        }
        if (dlclose(handle) != 0)
            note_failure(1U << 10);
        if (index != 0)
            note_quiescent_publication();
        atomic_fetch_add_explicit(
            &loaded_plugins, 1, memory_order_release);
    }
    return NULL;
}

static void *reader_worker(void *argument)
{
    unsigned int discriminator = (unsigned int)(uintptr_t)argument;
    int pass = 0;

    pthread_barrier_wait(&start_barrier);
    do {
        int result = exercise_readers(discriminator);

        if (result < 0)
            note_failure(1U << (11 - result));
        pass++;
        sched_yield();
    } while (pass < MIN_READER_PASSES ||
             atomic_load_explicit(&loaded_plugins,
                                  memory_order_acquire) < PLUGIN_COUNT);
    atomic_fetch_add_explicit(
        &completed_readers, 1, memory_order_release);
    return NULL;
}

static void *fork_worker(void *unused)
{
    int pass = 0;

    (void)unused;
    pthread_barrier_wait(&start_barrier);
    do {
        int status = 0;
        pid_t child;

        /* Older native loaders can acquire internal locks before invoking
         * application atfork prepares. Their control run forks only after
         * publication is quiescent; direct replay still requires overlap. */
        if (pass == 0 && !publication_overlap_enabled &&
            wait_for_flag(&all_publications_quiescent) != 0) {
            note_failure(1U << 27);
            break;
        }
        if (pass == 1 &&
            (wait_for_value(&loaded_plugins, PLUGIN_COUNT) != 0 ||
             wait_for_value(&completed_readers, READER_THREADS) != 0)) {
            note_failure(1U << 27);
            break;
        }
        child = fork();

        if (child < 0) {
            note_failure(1U << 20);
            if (pass == 0)
                atomic_store_explicit(
                    &first_fork_complete, 1, memory_order_release);
            break;
        }
        if (child == 0) {
            char path[1024];
            void *handle;
            int (*value)(void) = NULL;
            int result = 0;

            alarm(10);
            if (pass == 0) {
                snprintf(path, sizeof(path),
                         "%s/libloader_stress_00.so", PLUGIN_DIR);
                handle = dlopen(
                    path, RTLD_NOW | RTLD_NOLOAD | RTLD_LOCAL);
                if (!handle)
                    result = 2;
                else {
                    value = (int (*)(void))dlsym(
                        handle, "loader_stress_value");
                    if (!value)
                        result = 3;
                    else if (value() != 1000)
                        result = 4;
                }
            } else {
                handle = dlopen(NULL, RTLD_NOW | RTLD_LOCAL);
                if (!handle)
                    result = 5;
            }
            if (exercise_readers(999) < 0 && result == 0)
                result = 6;

            if (handle && dlclose(handle) != 0)
                result = 7;
            _exit(result);
        }
        if (waitpid(child, &status, 0) != child ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "fork-pass=%d child-status=0x%x\n",
                    pass, status);
            note_failure(1U << 21);
        }
        if (pass == 0)
            atomic_store_explicit(
                &first_fork_complete, 1, memory_order_release);
        pass++;
    } while (pass < MIN_FORKS ||
             atomic_load_explicit(&loaded_plugins,
                                  memory_order_acquire) < PLUGIN_COUNT);
    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t loaders[LOADER_THREADS];
    pthread_t readers[READER_THREADS];
    pthread_t forker;

    if (argc == 2 && strcmp(argv[1], "native") == 0) {
        publication_overlap_enabled = 0;
        atomic_store_explicit(&publication_overlap_observed, 1,
                              memory_order_relaxed);
    } else if (argc != 1) {
        return 11;
    }
    alarm(30);
    if (pthread_barrier_init(
            &start_barrier, NULL,
            LOADER_THREADS + READER_THREADS + 1) != 0)
        return 2;
    if (pthread_atfork(overlap_atfork_prepare, NULL, NULL) != 0)
        return 10;
    for (int i = 0; i < LOADER_THREADS; i++)
        if (pthread_create(&loaders[i], NULL, loader_worker, NULL) != 0)
            return 3;
    for (int i = 0; i < READER_THREADS; i++)
        if (pthread_create(&readers[i], NULL, reader_worker,
                           (void *)(uintptr_t)(i + 1)) != 0)
            return 4;
    if (pthread_create(&forker, NULL, fork_worker, NULL) != 0)
        return 5;
    for (int i = 0; i < LOADER_THREADS; i++)
        if (pthread_join(loaders[i], NULL) != 0)
            return 6;
    for (int i = 0; i < READER_THREADS; i++)
        if (pthread_join(readers[i], NULL) != 0)
            return 7;
    if (pthread_join(forker, NULL) != 0)
        return 8;
    alarm(0);
    pthread_barrier_destroy(&start_barrier);

    if (atomic_load_explicit(&loaded_plugins, memory_order_acquire) !=
            PLUGIN_COUNT ||
        !atomic_load_explicit(
            &publication_overlap_observed, memory_order_acquire) ||
        atomic_load_explicit(&failures, memory_order_relaxed) != 0) {
        fprintf(stderr, "loaded=%d overlap=%d failures=0x%x\n",
                atomic_load_explicit(&loaded_plugins, memory_order_relaxed),
                atomic_load_explicit(
                    &publication_overlap_observed, memory_order_relaxed),
                atomic_load_explicit(&failures, memory_order_relaxed));
        return 9;
    }
    puts("loader-concurrency-ok");
    return 0;
}
