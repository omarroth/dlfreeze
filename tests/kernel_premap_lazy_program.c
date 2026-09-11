#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int kernel_premap_lazy_ctor_count;
static const unsigned char startup_image[3 * 1024 * 1024] = {0x5a};

int main(void)
{
    const char *name = "libkernel_premap_lazy.so";
    volatile const unsigned char *image = startup_image;
    void *handle;
    int (*value)(void);

    if (image[0] != 0x5a || image[sizeof(startup_image) - 1] != 0 ||
        kernel_premap_lazy_ctor_count != 0)
        return 1;
    if (getenv("DLFREEZE_TEST_PREMAP")) {
        handle = dlopen(name, RTLD_LAZY | RTLD_NOLOAD);
        if (handle != NULL) {
            dlclose(handle);
            return 2;
        }
    }
    handle = dlopen(name, RTLD_NOW | RTLD_LOCAL);
    if (!handle || kernel_premap_lazy_ctor_count != 1)
        return 3;
    value = (int (*)(void))dlsym(handle, "kernel_premap_lazy_value");
    if (!value || value() != 73)
        return 4;
    puts("kernel-premap-lazy-ok");
    return 0;
}
