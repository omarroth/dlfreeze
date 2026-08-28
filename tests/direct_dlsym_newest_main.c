#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

typedef int (*value_fn)(void);

int main(int argc, char **argv)
{
    void *handle;
    value_fn old_value;
    value_fn new_value;
    void *unversioned;
    const char *error;

    if (argc != 2)
        return 1;
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return 2;
    old_value = (value_fn)dlvsym(handle, "ambiguous", "NEWEST_1");
    new_value = (value_fn)dlvsym(handle, "ambiguous", "NEWEST_2");
    if (!old_value || !new_value || old_value() != 11 || new_value() != 22)
        return 3;
    (void)dlerror();
    unversioned = dlsym(handle, "ambiguous");
    error = dlerror();
    if (unversioned != NULL || error == NULL)
        return 4;
    puts("return-newest-ok");
    return 0;
}
