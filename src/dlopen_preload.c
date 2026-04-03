/*
 * dlfreeze dlopen tracer — LD_PRELOAD library.
 *
 * When loaded via LD_PRELOAD, intercepts dlopen() and logs the
 * resolved library paths to $DLFREEZE_TRACE_FILE (one per line).
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <link.h>
#include <pthread.h>

static FILE         *g_trace;
static void         *(*real_dlopen)(const char *, int);
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

__attribute__((constructor))
static void dlfreeze_trace_init(void)
{
    real_dlopen = dlsym(RTLD_NEXT, "dlopen");
    const char *path = getenv("DLFREEZE_TRACE_FILE");
    if (path) g_trace = fopen(path, "a");
}

__attribute__((destructor))
static void dlfreeze_trace_fini(void)
{
    if (g_trace) { fclose(g_trace); g_trace = NULL; }
}

void *dlopen(const char *filename, int flags)
{
    if (!real_dlopen)
        real_dlopen = dlsym(RTLD_NEXT, "dlopen");

    void *h = real_dlopen ? real_dlopen(filename, flags) : NULL;

    if (h && filename && g_trace) {
        struct link_map *lm = NULL;
        if (dlinfo(h, RTLD_DI_LINKMAP, &lm) == 0 && lm && lm->l_name && lm->l_name[0]) {
            pthread_mutex_lock(&g_lock);
            fprintf(g_trace, "%s\n", lm->l_name);
            fflush(g_trace);
            pthread_mutex_unlock(&g_lock);
        }
    }
    return h;
}
