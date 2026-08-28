#include "dep_resolver.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    struct dep_list deps;
    int status = 1;

    if (argc != 4)
        return 2;
    if (dep_resolve(argv[1], &deps) < 0)
        return 1;
    if (dep_add_dlopen_libs(&deps, argv[2]) < 0)
        goto out;

    for (int i = 0; i < deps.count; i++) {
        if ((deps.libs[i].dlopen_request &&
             strcmp(deps.libs[i].dlopen_request, argv[3]) == 0) ||
            (deps.libs[i].logical_path &&
             strcmp(deps.libs[i].logical_path, argv[3]) == 0)) {
            fprintf(stderr,
                    "interpreter hardlink became a packaged DSO alias\n");
            goto out;
        }
    }
    status = 0;

out:
    dep_list_free(&deps);
    return status;
}
