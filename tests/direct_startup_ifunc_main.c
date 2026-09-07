#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

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

static unsigned int startup_observation;
typedef int (*startup_value_fn)(void);

extern int direct_startup_symbolic_ifunc_probe(void);
extern unsigned int direct_startup_symbolic_ifunc_observation(void);

__attribute__((visibility("default"), noinline))
int direct_startup_ifunc_main_value(void)
{
    return 29;
}

static int direct_startup_ifunc_implementation(void)
{
    return 41;
}

static startup_value_fn direct_startup_ifunc_resolver(void)
{
    void *process = dlopen(NULL, RTLD_NOW | RTLD_LOCAL);
    void *late = NULL;
    startup_value_fn value = NULL;

    if (process) {
        startup_observation |= STARTUP_SAW_PROCESS_HANDLE;
        value = (startup_value_fn)dlsym(
            process, "direct_startup_ifunc_main_value");
        if (value && value() == 29)
            startup_observation |= STARTUP_SAW_MAIN_SYMBOL;
    }

    late = dlopen(STARTUP_IFUNC_LATE_PATH, RTLD_NOW | RTLD_LOCAL);
    if (late) {
        startup_observation |= STARTUP_LOADED_LATE_OBJECT;
    } else {
        const char *error = dlerror();

        startup_observation |= STARTUP_REJECTED_LATE_OBJECT;
        if (error && error[0])
            startup_observation |= STARTUP_SAW_REJECTION_ERROR;
        value = process ? (startup_value_fn)dlsym(
                              process,
                              "direct_startup_ifunc_main_value") : NULL;
        if (value && value() == 29)
            startup_observation |= STARTUP_GRAPH_SURVIVED_REJECTION;
    }
    return direct_startup_ifunc_implementation;
}

__attribute__((ifunc("direct_startup_ifunc_resolver")))
int direct_startup_ifunc_probe(void);

int main(void)
{
    void *late;
    startup_value_fn value;
    unsigned int required = STARTUP_SAW_PROCESS_HANDLE |
                            STARTUP_SAW_MAIN_SYMBOL;
    unsigned int symbolic_observation;

    if (direct_startup_ifunc_probe() != 41 ||
        (startup_observation & required) != required)
        return 2;
    symbolic_observation = direct_startup_symbolic_ifunc_observation();
    if ((symbolic_observation & required) != required)
        return 7;
    if (direct_startup_symbolic_ifunc_probe() != 59)
        return 6;

    /* The same request must become a normal graph mutation once startup is
     * complete.  The standalone gate leaves this otherwise-unreferenced DSO
     * on disk so the post-startup transaction exercises the regular runtime
     * loader path. */
    late = dlopen(STARTUP_IFUNC_LATE_PATH, RTLD_NOW | RTLD_LOCAL);
    if (!late)
        return 3;
    value = (startup_value_fn)dlsym(
        late, "direct_startup_ifunc_late_value");
    if (!value || value() != 73)
        return 4;

    if ((startup_observation & STARTUP_LOADED_LATE_OBJECT) != 0 &&
        (symbolic_observation & STARTUP_LOADED_LATE_OBJECT) != 0) {
        puts("startup-ifunc-native-load-ok");
        return 0;
    }
    if ((startup_observation &
         (STARTUP_REJECTED_LATE_OBJECT | STARTUP_SAW_REJECTION_ERROR |
          STARTUP_GRAPH_SURVIVED_REJECTION)) ==
        (STARTUP_REJECTED_LATE_OBJECT | STARTUP_SAW_REJECTION_ERROR |
         STARTUP_GRAPH_SURVIVED_REJECTION) &&
        (symbolic_observation &
         (STARTUP_REJECTED_LATE_OBJECT | STARTUP_SAW_REJECTION_ERROR |
          STARTUP_GRAPH_SURVIVED_REJECTION)) ==
        (STARTUP_REJECTED_LATE_OBJECT | STARTUP_SAW_REJECTION_ERROR |
         STARTUP_GRAPH_SURVIVED_REJECTION)) {
        puts("startup-ifunc-readonly-ok");
        return 0;
    }
    return 5;
}
