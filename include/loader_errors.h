#ifndef DLFREEZE_LOADER_ERRORS_H
#define DLFREEZE_LOADER_ERRORS_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "dynamic_semantics.h"

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

/* A probe is scoped to the caller's immutable ELF source and exact public
 * mode. It never creates a file/directory identity in the captured VFS.
 * A provider index, when present, retains inode aliases of an unloaded
 * object that a later traced operation loads through another spelling. */
#define DLFRZ_LOADER_PROBE_MAGIC UINT32_C(0x3142504c)
struct dlfrz_loader_probe {
    uint32_t magic;
    uint32_t family;
    uint32_t error_code; /* zero: NOLOAD returned NULL without a diagnostic */
    uint32_t mode;
    uint32_t caller_index;
    uint32_t provider_index; /* UINT32_MAX when no captured provider exists */
    uint32_t reserved[2];
};
_Static_assert(sizeof(struct dlfrz_loader_probe) == 32,
               "loader-probe witness ABI changed");

static inline int dlfrz_loader_probe_canonical(
    const struct dlfrz_loader_probe *probe, size_t size)
{
    return probe && size == sizeof(*probe) &&
        probe->magic == DLFRZ_LOADER_PROBE_MAGIC &&
        probe->family == DLFRZ_LOADER_MISS_GNU &&
        dlfrz_dlopen_mode_is_supported(probe->mode) &&
        (probe->error_code == 2 ||
         (probe->error_code == 0 && (probe->mode & DLFRZ_RTLD_NOLOAD))) &&
        (probe->error_code == 0 || probe->provider_index == UINT32_MAX) &&
        probe->reserved[0] == 0 && probe->reserved[1] == 0;
}

static inline int dlfrz_loader_miss_canonical(
    const struct dlfrz_loader_miss *miss, size_t size)
{
    return miss && size == sizeof(*miss) &&
        miss->magic == DLFRZ_LOADER_MISS_MAGIC &&
        miss->family == DLFRZ_LOADER_MISS_GNU &&
        miss->error_code == 2 && miss->reserved == 0;
}

#endif
