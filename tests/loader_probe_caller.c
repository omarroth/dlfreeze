#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>

int probe_load(const char *name, const char *provider)
{
    (void)dlerror();
    if (dlopen(name, RTLD_NOW)) return -2;
    const char *error = dlerror();
    if (!error || !strstr(error, name)) return -3;
    void *handle = dlopen(provider, RTLD_NOW);
    int (*value)(void) = handle ? (int (*)(void))dlsym(handle, "test_value") : 0;
    int result = value ? value() : -1;
    if (handle) dlclose(handle);
    return result;
}
