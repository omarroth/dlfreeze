#include "dep_resolver.h"

#include <stdio.h>

int main(int argc, char **argv)
{
    struct dep_list deps;

    if (argc != 2 && argc != 3)
        return 2;
    if (dep_resolve(argv[1], &deps) < 0)
        return 1;
    if (argc == 3 &&
        (dep_add_dlopen_libs(&deps, argv[2]) < 0 ||
         dep_mark_dlopen_early_closures(&deps) < 0)) {
        dep_list_free(&deps);
        return 1;
    }
    if (deps.interp_path)
        printf("INTERP=%s\n", deps.interp_path);
    for (int i = 0; i < deps.count; i++)
        printf("NEEDED=%s\t%s\tLOGICAL=%s\tEARLY=%d\n",
               deps.libs[i].name, deps.libs[i].path,
               deps.libs[i].logical_path, deps.libs[i].dlopen_early);
    dep_list_free(&deps);
    return 0;
}
