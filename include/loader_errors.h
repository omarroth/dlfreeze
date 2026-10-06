#ifndef DLFREEZE_LOADER_ERRORS_H
#define DLFREEZE_LOADER_ERRORS_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* A frozen missing-object witness is deliberately narrower than an arbitrary
 * failed dlopen: its absolute root did not exist and the native loader's
 * unconsumed error named that root. Unknown error contracts remain native.
 * The public message is formatted only when dlerror is requested, using the
 * embedded target libc's current locale, not the bootstrap libc's strings. */
#define DLFRZ_LOADER_MISS_MAGIC UINT32_C(0x314d4c44)
#define DLFRZ_LOADER_MISS_GNU UINT32_C(1)
#define DLFRZ_LOADER_MISS_REASON "cannot open shared object file"

struct dlfrz_loader_miss {
    uint32_t magic;
    uint32_t family;
    uint32_t error_code;
    uint32_t reserved;
};

static inline int dlfrz_loader_miss_canonical(
    const struct dlfrz_loader_miss *miss, size_t size)
{
    return miss && size == sizeof(*miss) &&
        miss->magic == DLFRZ_LOADER_MISS_MAGIC &&
        miss->family == DLFRZ_LOADER_MISS_GNU &&
        miss->error_code == 2 && miss->reserved == 0;
}

#endif
