#define _GNU_SOURCE
#include <sys/mman.h>
#include <unistd.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "libc_semantics.h"

struct soname_case {
    const char *name;
    int reserved;
};

static int guarded_check(const char *name, int reserved)
{
    long page_size = sysconf(_SC_PAGESIZE);
    size_t length = strlen(name) + 1;
    char *mapping;
    char *guarded;
    int actual;

    if (page_size <= 0 || length > (size_t)page_size)
        return -1;
    mapping = mmap(NULL, (size_t)page_size * 2, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return -1;
    if (mprotect(mapping + page_size, (size_t)page_size, PROT_NONE) != 0) {
        munmap(mapping, (size_t)page_size * 2);
        return -1;
    }

    guarded = mapping + page_size - length;
    memcpy(guarded, name, length);
    actual = dlfrz_musl_reserved_soname(guarded);
    munmap(mapping, (size_t)page_size * 2);
    return actual == reserved ? 0 : 1;
}

static int glibc_static_tls_geometry_check(void)
{
    uint64_t size = 0;
    uint64_t align = 0;

    /* These exact expectations intentionally contain no native-rtld optional
     * surplus.  Direct mode assigns every admitted static block at startup. */
    if (!dlfrz_glibc_used_static_tls_geometry(
            1000, 16, 64, 2304, 1, &size, &align) ||
        size != 3328 || align != 64 ||
        !dlfrz_glibc_used_static_tls_geometry(
            1010, 256, 32, 0, 0, &size, &align) ||
        size != 1024 || align != 256 ||
        dlfrz_glibc_used_static_tls_geometry(
            UINT64_MAX, 64, 64, 2304, 1, &size, &align) ||
        dlfrz_glibc_used_static_tls_geometry(
            1000, 24, 64, 2304, 1, &size, &align) ||
        dlfrz_glibc_used_static_tls_geometry(
            1000, 64, 64, 1, 0, &size, &align))
        return 1;
    return 0;
}

int main(void)
{
    static const struct soname_case cases[] = {
        { "", 0 },          { "l", 0 },          { "li", 0 },
        { "lib", 0 },       { "libc", 0 },       { "libc.", 1 },
        { "libc.so", 1 },   { "libp", 0 },       { "libpt", 0 },
        { "libpth", 0 },    { "libpthr", 0 },    { "libpthre", 0 },
        { "libpthrea", 0 }, { "libpthread", 0 }, { "libpthread.", 1 },
        { "libr", 0 },      { "librt", 0 },      { "librt.", 1 },
        { "libm", 0 },      { "libm.", 1 },      { "libd", 0 },
        { "libdl", 0 },     { "libdl.", 1 },     { "libu", 0 },
        { "libut", 0 },     { "libuti", 0 },     { "libutil", 0 },
        { "libutil.", 1 },  { "libx", 0 },       { "libxn", 0 },
        { "libxne", 0 },    { "libxnet", 0 },    { "libxnet.", 1 },
        { "library.so", 0 }, { "libcrypt.so", 0 },
    };
    size_t i;

    if (dlfrz_musl_reserved_soname(NULL) != 0 ||
        glibc_static_tls_geometry_check() != 0)
        return 1;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int rc = guarded_check(cases[i].name, cases[i].reserved);

        if (rc != 0) {
            fprintf(stderr, "SONAME case failed: '%s' (rc=%d)\n",
                    cases[i].name, rc);
            return 1;
        }
    }
    return 0;
}
