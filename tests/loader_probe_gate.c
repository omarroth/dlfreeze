#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static int missing(const char *name, int flags, int consume)
{
    (void)dlerror();
    errno = 123;
    if (dlopen(name, flags)) return 1;
    int saved = errno;
    if (!consume) return 0;
    const char *error = dlerror();
    if (!error || !strstr(error, name)) return 2;
    printf("missing %s errno=%d error=%s\n", name, saved, error);
    return dlerror() != NULL;
}

static int silent(const char *name, int flags)
{
    errno = 123;
    if (dlopen(name, flags)) return 1;
    int saved = errno;
    if (dlerror() || dlerror()) return 2;
    printf("silent %s errno=%d\n", name, saved);
    return 0;
}

int main(int argc, char **argv)
{
    const char *available = "libprobe_available.so";
    const char *absent = "libprobe_absent.so";
    const char *scoped = "libprobe_context.so";
    if (argc != 6) return 2;
    FILE *data = fopen(argv[4], "r");
    if (!data || fgetc(data) != 'x' || fclose(data)) return 3;
    (void)dlerror();
    if (silent(available, RTLD_NOW | RTLD_NOLOAD) ||
        silent(argv[1], RTLD_NOW | RTLD_NOLOAD) ||
        missing(absent, RTLD_NOW | RTLD_NOLOAD, 1) ||
        missing(argv[3], RTLD_NOW | RTLD_NOLOAD, 1) ||
        missing(absent, RTLD_NOW, 1) ||
        missing(absent, RTLD_LAZY | RTLD_NOLOAD | RTLD_GLOBAL, 1) ||
        missing(scoped, RTLD_NOW, 1)) return 4;
    /* A silent NOLOAD must clear a previous unconsumed GNU diagnostic. */
    if (missing(absent, RTLD_NOW, 0) ||
        silent(available, RTLD_NOW | RTLD_NOLOAD)) return 5;
    /* The provider's SONAME and traced request differ from the earlier
     * bare-name probe. Match its frozen inode after the later load. */
    void *provider = dlopen(argv[1], RTLD_NOW);
    if (!provider || dlerror()) return 6;
    void *present = dlopen(available, RTLD_NOW | RTLD_NOLOAD);
    if (present != provider || dlerror()) return 7;
    /* Retain the same missing request independently for a second ELF caller,
     * followed by a positive exact-path load from that caller. */
    void *caller = dlopen(argv[2], RTLD_NOW);
    int (*load)(const char *, const char *) = caller
        ? (int (*)(const char *, const char *))dlsym(caller, "probe_load") : NULL;
    if (!load || dlerror() || load(scoped, argv[5]) != 42) return 8;
    if (dlclose(caller) || dlclose(present) || dlclose(provider)) return 9;
    puts("caller scopes, inode aliases and loader probes passed");
    return 0;
}
