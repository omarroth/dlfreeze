#include <dlfcn.h>
#include <stdio.h>

typedef int (*value_fn)(void);

int main(int argc, char **argv)
{
    void *handle;
    value_fn value;

    if (argc != 2)
        return 2;
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 3;
    }
    value = (value_fn)dlsym(handle, "dlfreeze_runtime_bounds_value");
    if (!value) {
        fprintf(stderr, "dlsym: %s\n", dlerror());
        return 4;
    }
    printf("runtime-bounds=%d\n", value());
    return 0;
}
