#define _GNU_SOURCE
#include <dlfcn.h>

#ifndef PLUGIN_ID
#error "PLUGIN_ID must identify this fixture"
#endif
#ifndef NESTED_PATH
#error "NESTED_PATH must identify the nested fixture"
#endif

static int constructor_ok;

extern void loader_stress_publication_hold(int plugin_id);

__attribute__((constructor))
static void loader_stress_constructor(void)
{
    int (*nested_value)(void);
    void *handle;

    loader_stress_publication_hold(PLUGIN_ID);
    handle = dlopen(NESTED_PATH, RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return;
    nested_value = (int (*)(void))dlsym(
        handle, "loader_stress_nested_value");
    constructor_ok = nested_value && nested_value() == 73;
    dlclose(handle);
}

int loader_stress_value(void)
{
    return constructor_ok ? 1000 + PLUGIN_ID : -1;
}
