#include "dep_resolver.h"
#include "packer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    struct dep_list deps;
    struct pack_options options = {0};
    char *target;
    int found = 0;
    int result;

    if (argc != 6)
        return 2;
    target = realpath(argv[3], NULL);
    if (!target || dep_resolve(argv[1], &deps) < 0) {
        free(target);
        return 3;
    }
    for (int i = 0; i < deps.count; i++)
        if (strcmp(deps.libs[i].path, target) == 0) {
            found = 1;
            break;
        }
    if (!found || rename(argv[4], argv[3]) < 0) {
        dep_list_free(&deps);
        free(target);
        return 4;
    }

    options.exe_path = argv[1];
    options.exe_name = argv[1];
    options.bootstrap_path = argv[2];
    options.output_path = argv[5];
    options.deps = &deps;
    result = pack_frozen(&options);
    dep_list_free(&deps);
    free(target);

    /* A pathname replacement after resolution must neither be packaged nor
     * leave a partially committed output artifact. */
    if (result >= 0 || access(argv[5], F_OK) == 0)
        return 5;
    return 0;
}
