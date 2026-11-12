#include "dep_resolver.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
    struct dep_list deps;
    int expected_lazy_semantics = -1;
    int expected_native_loader_semantics = -1;
    int expected_missing_roots = -1;
    int expected_probes = -1;
    int status = 1;

    if (argc < 4 || argc > 9)
        return 2;
    if (argc >= 5) {
        if (strcmp(argv[4], "0") == 0)
            expected_lazy_semantics = 0;
        else if (strcmp(argv[4], "1") == 0)
            expected_lazy_semantics = 1;
        else
            return 2;
    }
    if (argc >= 6) {
        if (strcmp(argv[5], "0") == 0)
            expected_native_loader_semantics = 0;
        else if (strcmp(argv[5], "1") == 0)
            expected_native_loader_semantics = 1;
        else
            return 2;
    }
    if (argc >= 7) {
        if (strcmp(argv[6], "0") == 0) expected_missing_roots = 0;
        else if (strcmp(argv[6], "1") == 0) expected_missing_roots = 1;
        else if (strcmp(argv[6], "2") == 0) expected_missing_roots = 2;
        else return 2;
    }
    if (argc >= 8) {
        char *end;
        long count = strtol(argv[7], &end, 10);
        if (!argv[7][0] || *end || count < 0 || count > 32) return 2;
        expected_probes = (int)count;
    }
    if (dep_resolve(argv[1], &deps) < 0)
        return 1;
    if (deps.interp_soname) {
        char *provider = NULL;
        struct stat original, auxiliary;
        int resolved = dep_resolve_aux_dependency(
            &deps, argv[1], deps.interp_soname, &provider);
        int same = resolved == 1 && stat(deps.interp_path, &original) == 0 &&
            stat(provider, &auxiliary) == 0 &&
            original.st_dev == auxiliary.st_dev &&
            original.st_ino == auxiliary.st_ino;

        free(provider);
        if (!same) {
            fprintf(stderr, "auxiliary interpreter dependency changed identity\n");
            goto out;
        }
    }
    if (dep_add_dlopen_libs(&deps, argv[2]) < 0)
        goto out;
    if (expected_missing_roots >= 0 && deps.dlopen_missing_count != expected_missing_roots) {
        fprintf(stderr, "missing-loader root count differs\n");
        goto out;
    }
    if (expected_probes >= 0 && deps.loader_probe_count != expected_probes) {
        fprintf(stderr, "loader-probe count differs\n");
        goto out;
    }
    if (argc == 9) {
        struct stat expected;
        if (stat(argv[8], &expected) < 0) goto out;
        for (int i = 0; i < deps.loader_probe_count; i++) {
            if (deps.loader_probes[i].error_code) continue;
            char *provider = NULL;
            struct stat actual;
            int valid = dep_validate_loader_probe(&deps, &deps.loader_probes[i], &provider) == 0 &&
                provider && stat(provider, &actual) == 0 &&
                actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino;
            free(provider);
            if (!valid) {
                fprintf(stderr, "loader-probe provider identity differs\n");
                goto out;
            }
        }
    }
    if (expected_lazy_semantics >= 0 &&
        deps.traced_requires_native_lazy_semantics !=
            expected_lazy_semantics) {
        fprintf(stderr, "failed-lazy trace classification differs\n");
        goto out;
    }
    if (expected_native_loader_semantics >= 0 &&
        deps.traced_requires_native_loader_semantics !=
            expected_native_loader_semantics) {
        fprintf(stderr, "failed-load trace classification differs\n");
        goto out;
    }

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
