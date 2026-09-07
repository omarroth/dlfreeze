#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

typedef void *(*weak_tlsdesc_address_fn)(void);

int main(int argc, char **argv)
{
    weak_tlsdesc_address_fn address_fn;
    void *handle;

    if (argc != 2)
        return 2;
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        const char *error = dlerror();

        fprintf(stderr, "dlopen: %s\n", error ? error : "unknown error");
        return 3;
    }
    address_fn = (weak_tlsdesc_address_fn)dlsym(
        handle, "direct_weak_tlsdesc_address");
    if (!address_fn) {
        const char *error = dlerror();

        fprintf(stderr, "dlsym: %s\n", error ? error : "unknown error");
        return 4;
    }
    if (address_fn() != NULL) {
        fprintf(stderr, "undefined weak TLSDESC did not resolve to NULL\n");
        return 5;
    }
    puts("weak-tlsdesc-null-ok");
    return 0;
}
