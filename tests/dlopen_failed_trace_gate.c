#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <link.h>
#include <stdio.h>
#include <string.h>

#ifndef RTLD_DEEPBIND
#define RTLD_DEEPBIND 0x00008
#endif

int main(int argc, char **argv)
{
    static const char missing[] =
        "/dlfreeze-failed-loader-trace-object-does-not-exist.so";
    const char *error;
    void *handle = NULL;
    int saved_errno;

    if (argc != 2)
        return 2;
    (void)dlerror();
    errno = 123;
    if (strcmp(argv[1], "now") == 0)
        handle = dlopen(missing, RTLD_NOW | RTLD_LOCAL);
    else if (strcmp(argv[1], "deepbind") == 0)
        handle = dlopen(missing,
                        RTLD_NOW | RTLD_DEEPBIND | RTLD_LOCAL);
    else if (strcmp(argv[1], "null") == 0)
        handle = dlopen(NULL, 0);
#if defined(LM_ID_NEWLM)
    else if (strcmp(argv[1], "newlm") == 0)
        handle = dlmopen(LM_ID_NEWLM, missing,
                         RTLD_NOW | RTLD_LOCAL);
    else if (strcmp(argv[1], "newlm-null") == 0)
        handle = dlmopen(LM_ID_NEWLM, NULL,
                         RTLD_NOW | RTLD_LOCAL);
#else
    else if (strcmp(argv[1], "newlm") == 0 ||
             strcmp(argv[1], "newlm-null") == 0)
        return 77;
#endif
    else
        return 2;
    saved_errno = errno;
    error = dlerror();
    if (handle != NULL) {
        (void)dlclose(handle);
        return 78;
    }
    if (error == NULL)
        return 3;
    printf("errno=%d dlerror=%s\n", saved_errno, error);
    return 0;
}
