#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>

#ifndef STARTUP_IFUNC_LATE_PATH
#error "STARTUP_IFUNC_LATE_PATH must name the late-load test DSO"
#endif

enum {
    STARTUP_SAW_PROCESS_HANDLE = 1U << 0,
    STARTUP_SAW_MAIN_SYMBOL = 1U << 1,
    STARTUP_LOADED_LATE_OBJECT = 1U << 2,
    STARTUP_REJECTED_LATE_OBJECT = 1U << 3,
    STARTUP_SAW_REJECTION_ERROR = 1U << 4,
    STARTUP_GRAPH_SURVIVED_REJECTION = 1U << 5
};

typedef int (*startup_value_fn)(void);
static unsigned int symbolic_startup_observation;

static int direct_startup_symbolic_ifunc_implementation(void)
{
    return 59;
}

static startup_value_fn direct_startup_symbolic_ifunc_resolver(void)
{
    void *process = dlopen(NULL, RTLD_NOW | RTLD_LOCAL);
    void *late;
    startup_value_fn value = NULL;

    if (process) {
        symbolic_startup_observation |= STARTUP_SAW_PROCESS_HANDLE;
        value = (startup_value_fn)dlsym(
            process, "direct_startup_ifunc_main_value");
        if (value && value() == 29)
            symbolic_startup_observation |= STARTUP_SAW_MAIN_SYMBOL;
    }

    late = dlopen(STARTUP_IFUNC_LATE_PATH, RTLD_NOW | RTLD_LOCAL);
    if (late) {
        symbolic_startup_observation |= STARTUP_LOADED_LATE_OBJECT;
    } else {
        const char *error = dlerror();

        symbolic_startup_observation |= STARTUP_REJECTED_LATE_OBJECT;
        if (error && error[0])
            symbolic_startup_observation |= STARTUP_SAW_REJECTION_ERROR;
        value = process ? (startup_value_fn)dlsym(
                              process,
                              "direct_startup_ifunc_main_value") : NULL;
        if (value && value() == 29)
            symbolic_startup_observation |=
                STARTUP_GRAPH_SURVIVED_REJECTION;
    }
    return direct_startup_symbolic_ifunc_implementation;
}

__attribute__((ifunc("direct_startup_symbolic_ifunc_resolver"),
               visibility("default")))
int direct_startup_symbolic_ifunc_probe(void);

unsigned int direct_startup_symbolic_ifunc_observation(void)
{
    return symbolic_startup_observation;
}
