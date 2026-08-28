#include "dep_resolver.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    struct dep_list deps;
    char *resolved = NULL;
    char *expected = NULL;
    int expected_status;
    int status;

    if (argc == 7 && strcmp(argv[1], "--expect-status") == 0) {
        if (dep_resolve(argv[2], &deps) < 0)
            return 3;
        if (strcmp(argv[5], "-") != 0) {
            char *cache_path = strdup(argv[5]);

            if (!cache_path) {
                dep_list_free(&deps);
                return 5;
            }
            free(deps.gnu_cache_path);
            deps.gnu_cache_path = cache_path;
            /* This explicit test override models a different target loader
             * configuration.  Drop dep_resolve's process-lifetime snapshot
             * so the requested unreadable/malformed path is the first lookup
             * for that synthetic configuration. */
            free(deps.gnu_cache_index);
            deps.gnu_cache_index = NULL;
            free(deps.gnu_cache_image);
            deps.gnu_cache_image = NULL;
            deps.gnu_cache_image_size = 0;
            deps.gnu_cache_snapshot_state = 0;
        }
        expected_status = atoi(argv[6]);
        status = dep_resolve_aux_dependency(
            &deps, argv[3], argv[4], &resolved);
        if (status != expected_status || resolved) {
            fprintf(stderr,
                    "aux status=%d path=%s expected_status=%d\n",
                    status, resolved ? resolved : "(null)",
                    expected_status);
            free(resolved);
            dep_list_free(&deps);
            return 4;
        }
        dep_list_free(&deps);
        puts("aux-status-ok");
        return 0;
    }
    if (argc != 6 || strcmp(argv[1], "--expect") != 0)
        return 2;
    if (dep_resolve(argv[2], &deps) < 0)
        return 3;
    status = dep_resolve_aux_dependency(
        &deps, argv[3], argv[4], &resolved);
    expected = realpath(argv[5], NULL);
    if (status != 1 || !resolved || !expected ||
        strcmp(resolved, expected) != 0) {
        fprintf(stderr, "aux resolution status=%d path=%s expected=%s\n",
                status, resolved ? resolved : "(null)",
                expected ? expected : "(null)");
        free(expected);
        free(resolved);
        dep_list_free(&deps);
        return 4;
    }
    free(expected);
    free(resolved);
    dep_list_free(&deps);
    puts("aux-main-rpath-ok");
    return 0;
}
