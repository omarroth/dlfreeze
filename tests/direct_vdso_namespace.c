#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>

typedef int (*value_fn)(void);

static int is_kernel_virtual_identity(const char *name)
{
    return name &&
           (strcmp(name, "linux-vdso.so.1") == 0 ||
            strcmp(name, "linux-gate.so.1") == 0);
}

static int count_kernel_virtual_objects(struct dl_phdr_info *info,
                                        size_t size, void *opaque)
{
    int *count = opaque;

    (void)size;
    if (info && is_kernel_virtual_identity(info->dlpi_name))
        (*count)++;
    return 0;
}

static int load_ordinary_path(const char *path)
{
    void *handle;
    void *no_load;
    void *symbol;
    value_fn value;

    dlerror();
    handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle || dlerror())
        return 1;
    symbol = dlsym(handle, "ordinary_vdso_basename_value");
    if (!symbol || dlerror())
        return 2;
    memcpy(&value, &symbol, sizeof(value));
    if (value() != 83)
        return 3;

    dlerror();
    no_load = dlopen(path, RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
    if (no_load != handle || dlerror())
        return 4;
    if (dlclose(no_load) != 0 || dlclose(handle) != 0)
        return 5;
    return 0;
}

static int require_reserved_name_failure(const char *name, int flags)
{
    void *handle;
    const char *error;

    dlerror();
    handle = dlopen(name, flags);
    error = dlerror();
    if (handle) {
        dlclose(handle);
        return 1;
    }
    if (!error || !error[0])
        return 2;
    if (dlerror())
        return 3;
    return 0;
}

int main(int argc, char **argv)
{
    static const char *const reserved[] = {
        "linux-vdso.so.1",
        "linux-gate.so.1"
    };
    uintptr_t sysinfo_ehdr;
    Dl_info info;
    int virtual_objects = 0;
    int result;

    if (argc != 3)
        return 2;
    if (strcmp(argv[1], "trace") == 0) {
        result = load_ordinary_path(argv[2]);
        if (result)
            return 10 + result;
        puts("vdso-path-trace-ok");
        return 0;
    }
    if (strcmp(argv[1], "strict") != 0)
        return 3;

    if (dl_iterate_phdr(count_kernel_virtual_objects, &virtual_objects) != 0 ||
        virtual_objects != 0)
        return 20;
    sysinfo_ehdr = (uintptr_t)getauxval(AT_SYSINFO_EHDR);
    if (sysinfo_ehdr) {
        memset(&info, 0, sizeof(info));
        if (dladdr((void *)sysinfo_ehdr, &info) != 0)
            return 21;
    }

    for (size_t i = 0; i < sizeof(reserved) / sizeof(reserved[0]); i++) {
        result = require_reserved_name_failure(
            reserved[i], RTLD_NOW | RTLD_LOCAL);
        if (result)
            return 30 + (int)i * 4 + result;
        result = require_reserved_name_failure(
            reserved[i], RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
        if (result)
            return 40 + (int)i * 4 + result;
    }

    result = load_ordinary_path(argv[2]);
    if (result)
        return 50 + result;
    puts("vdso-namespace-ok");
    return 0;
}
