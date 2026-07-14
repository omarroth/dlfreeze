#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef ROOT_A_PATH
#error ROOT_A_PATH is required
#endif
#ifndef ROOT_B_PATH
#error ROOT_B_PATH is required
#endif
#ifndef DEP_PATH
#error DEP_PATH is required
#endif
#ifndef LATE_PATH
#error LATE_PATH is required
#endif
#ifndef EXTERNAL_IE_PATH
#error EXTERNAL_IE_PATH is required
#endif
#ifndef EXTERNAL_IE_OWNER_PATH
#error EXTERNAL_IE_OWNER_PATH is required
#endif
#ifndef LATE_EXTERNAL_IE_PATH
#error LATE_EXTERNAL_IE_PATH is required
#endif
#ifndef DIRECT_EARLY_HAVE_IFUNC
#define DIRECT_EARLY_HAVE_IFUNC 0
#endif

#if DIRECT_EARLY_HAVE_IFUNC
#define ROOT_A_EVENTS "IDA"
#define ROOT_B_EVENTS "IDAIB"
#else
#define ROOT_A_EVENTS "DA"
#define ROOT_B_EVENTS "DAB"
#endif

static char events[16];
static size_t event_count;
static const char *phdr_needle;
static pthread_barrier_t existing_ready;
static pthread_barrier_t existing_go;
static int (*thread_exchange)(int);
static int (*external_thread_exchange)(int);
int direct_early_ifunc_ready;

void record_event(char event)
{
    if (event_count + 1 < sizeof(events)) {
        events[event_count++] = event;
        events[event_count] = '\0';
    }
}

static int phdr_contains(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    (void)data;
    return info->dlpi_name && strstr(info->dlpi_name, phdr_needle) != NULL;
}

static int object_is_reported(const char *needle)
{
    phdr_needle = needle;
    return dl_iterate_phdr(phdr_contains, NULL) != 0;
}

static void *existing_worker(void *unused)
{
    (void)unused;
    pthread_barrier_wait(&existing_ready);
    pthread_barrier_wait(&existing_go);
    return (void *)(long)(
        thread_exchange && thread_exchange(91) == 41 &&
        external_thread_exchange && external_thread_exchange(93) == 37
            ? 0 : 1);
}

static void *new_worker(void *unused)
{
    (void)unused;
    return (void *)(long)(
        thread_exchange && thread_exchange(92) == 41 &&
        external_thread_exchange && external_thread_exchange(94) == 37
            ? 0 : 1);
}

static int run_late_rejection(void)
{
    void *handle;
    const char *error;

    handle = dlopen(LATE_PATH, RTLD_NOW | RTLD_GLOBAL);
    error = dlerror();
    if (handle || !error ||
        (strstr(error, "static-TLS") == NULL &&
         strstr(error, "STATIC_TLS") == NULL) ||
        event_count != 0)
        return 30;
    puts("untraced-static-tls-rejected");
    return 0;
}

static int run_external_ie_late_rejection(void)
{
    void *handle;
    const char *error;

    handle = dlopen(LATE_EXTERNAL_IE_PATH, RTLD_NOW | RTLD_GLOBAL);
    error = dlerror();
    if (handle || !error ||
        (strstr(error, "static-TLS") == NULL &&
         strstr(error, "STATIC_TLS") == NULL) ||
        event_count != 0)
        return 31;
    puts("untraced-external-ie-rejected");
    return 0;
}

static int run_preloaded_trace(void)
{
    void *root_a;
    void *root_b;
    void *external_ie;

    if (!getenv("DLFREEZE_DIRECT_EARLY_PRELOADED") ||
        strcmp(getenv("DLFREEZE_DIRECT_EARLY_PRELOADED"), "1") != 0) {
        fputs("preloaded trace stage lacks its recursion marker\n", stderr);
        return 32;
    }

    dlerror();
    root_a = dlopen(ROOT_A_PATH, RTLD_NOW | RTLD_GLOBAL);
    if (!root_a) {
        fprintf(stderr, "preloaded trace root A: %s\n", dlerror());
        return 33;
    }
    root_b = dlopen(ROOT_B_PATH, RTLD_NOW | RTLD_GLOBAL);
    if (!root_b) {
        fprintf(stderr, "preloaded trace root B: %s\n", dlerror());
        return 34;
    }
    external_ie = dlopen(EXTERNAL_IE_PATH, RTLD_NOW | RTLD_GLOBAL);
    if (!external_ie) {
        fprintf(stderr, "preloaded trace external IE: %s\n", dlerror());
        return 35;
    }
    return 0;
}

static int exec_preloaded_trace(void)
{
    const char *old_preload = getenv("LD_PRELOAD");
    const char *trace_file = getenv("DLFREEZE_TRACE_FILE");
    char *preload = NULL;
    char *const trace_argv[] = {
        (char *)"direct-early-tls-trace", (char *)"trace-preloaded", NULL
    };
    int length;

    if (getenv("DLFREEZE_DIRECT_EARLY_PRELOADED")) {
        fputs("preloaded trace recursion detected\n", stderr);
        return 36;
    }
    if (!old_preload || !old_preload[0] || !trace_file || !trace_file[0]) {
        fputs("preloaded trace requires the dlfreeze tracer\n", stderr);
        return 37;
    }

    length = asprintf(&preload, "%s:%s:%s", old_preload,
                      DEP_PATH, EXTERNAL_IE_OWNER_PATH);
    if (length < 0 || !preload) {
        fputs("could not allocate preloaded trace environment\n", stderr);
        free(preload);
        return 38;
    }
    if (setenv("DLFREEZE_DIRECT_EARLY_PRELOADED", "1", 1) != 0 ||
        setenv("LD_PRELOAD", preload, 1) != 0) {
        perror("could not configure preloaded trace environment");
        free(preload);
        return 39;
    }
    free(preload);

    execv("/proc/self/exe", trace_argv);
    perror("could not re-exec preloaded trace fixture");
    return 40;
}

int main(int argc, char **argv)
{
    pthread_t existing;
    pthread_t fresh;
    void *thread_result = NULL;
    void *root_a;
    void *root_b;
    void *dependency;
    void *external_ie;
    int (*root_read)(void);
    int (*root_ifunc)(void);
    int (*external_read)(void);

    if (argc == 2 && strcmp(argv[1], "late") == 0)
        return run_late_rejection();
    if (argc == 2 && strcmp(argv[1], "external-late") == 0)
        return run_external_ie_late_rejection();
    if (argc == 2 && strcmp(argv[1], "trace") == 0)
        return exec_preloaded_trace();
    if (argc == 2 && strcmp(argv[1], "trace-preloaded") == 0)
        return run_preloaded_trace();

    dlerror();
    if (events[0] != '\0' ||
        dlsym(RTLD_DEFAULT, "direct_early_tls_root_read") != NULL ||
        dlsym(RTLD_DEFAULT, "direct_early_tls_exchange") != NULL ||
        dlsym(RTLD_DEFAULT, "direct_external_ie_read") != NULL ||
        object_is_reported("libdlfrz_early_root_a.so") ||
        object_is_reported("libdlfrz_early_root_b.so") ||
        object_is_reported("libdlfrz_early_tls_dep.so") ||
        object_is_reported("libdlfrz_external_ie_requester.so") ||
        object_is_reported("libdlfrz_external_ie_owner.so"))
        return 1;

    if (pthread_barrier_init(&existing_ready, NULL, 2) != 0 ||
        pthread_barrier_init(&existing_go, NULL, 2) != 0 ||
        pthread_create(&existing, NULL, existing_worker, NULL) != 0)
        return 2;
    pthread_barrier_wait(&existing_ready);

    direct_early_ifunc_ready = 1;
    root_a = dlopen(ROOT_A_PATH, RTLD_NOW | RTLD_GLOBAL);
    if (!root_a || strcmp(events, ROOT_A_EVENTS) != 0) {
        fprintf(stderr, "root-a activation: handle=%p events=%s error=%s\n",
                root_a, events, dlerror());
        return 3;
    }
    root_read = (int (*)(void))dlsym(root_a, "direct_early_tls_root_read");
    root_ifunc =
        (int (*)(void))dlsym(root_a, "direct_early_tls_root_ifunc");
    thread_exchange =
        (int (*)(int))dlsym(root_a, "direct_early_tls_exchange");
    if (!root_read || !root_ifunc || root_ifunc() != 73 ||
        !thread_exchange || root_read() != 41 ||
        thread_exchange(77) != 41 || root_read() != 77)
        return 4;
    if (!dlsym(RTLD_DEFAULT, "direct_early_tls_root_read") ||
        !dlsym(RTLD_DEFAULT, "direct_early_tls_exchange") ||
        !object_is_reported("libdlfrz_early_root_a.so") ||
        !object_is_reported("libdlfrz_early_tls_dep.so") ||
        object_is_reported("libdlfrz_early_root_b.so"))
        return 5;

    if (dlopen(ROOT_A_PATH, RTLD_NOW | RTLD_GLOBAL) != root_a ||
        strcmp(events, ROOT_A_EVENTS) != 0)
        return 8;
    dependency = dlopen(DEP_PATH, RTLD_NOW | RTLD_GLOBAL);
    if (!dependency || strcmp(events, ROOT_A_EVENTS) != 0)
        return 9;

    root_b = dlopen(ROOT_B_PATH, RTLD_NOW | RTLD_GLOBAL);
    if (!root_b || strcmp(events, ROOT_B_EVENTS) != 0 ||
        !object_is_reported("libdlfrz_early_root_b.so")) {
        fprintf(stderr, "root-b activation: handle=%p events=%s error=%s\n",
                root_b, events, dlerror());
        return 10;
    }
    root_read = (int (*)(void))dlsym(root_b, "direct_early_tls_root_read");
    root_ifunc =
        (int (*)(void))dlsym(root_b, "direct_early_tls_root_ifunc");
    if (!root_read || !root_ifunc || root_ifunc() != 73 || root_read() != 77)
        return 11;

    external_ie = dlopen(EXTERNAL_IE_PATH, RTLD_NOW | RTLD_GLOBAL);
    if (!external_ie) {
        fprintf(stderr, "external-IE activation failed: %s\n", dlerror());
        return 12;
    }
    external_read =
        (int (*)(void))dlsym(external_ie, "direct_external_ie_read");
    external_thread_exchange =
        (int (*)(int))dlsym(external_ie, "direct_external_ie_exchange");
    if (!external_read || !external_thread_exchange ||
        external_read() != 37 || external_thread_exchange(61) != 37 ||
        external_read() != 61 ||
        !object_is_reported("libdlfrz_external_ie_requester.so") ||
        !object_is_reported("libdlfrz_external_ie_owner.so"))
        return 13;

    pthread_barrier_wait(&existing_go);
    if (pthread_join(existing, &thread_result) != 0 || thread_result)
        return 14;
    if (pthread_create(&fresh, NULL, new_worker, NULL) != 0 ||
        pthread_join(fresh, &thread_result) != 0 || thread_result)
        return 15;

    pthread_barrier_destroy(&existing_go);
    pthread_barrier_destroy(&existing_ready);
    puts("promoted-static-tls-ok");
    return 0;
}
