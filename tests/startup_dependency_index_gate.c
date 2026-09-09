/* Exercise startup dependency resolution in its real translation unit. */
#include <stdio.h>

#define DLFREEZE_MANIFEST_IDENTITY_GATE 1
#include "../src/loader.c"

#define HIGH_MANIFEST_COUNT UINT32_C(65535)
#define HIGH_OBJECT_COUNT MAX_TOTAL_OBJS
#define DEEP_PATH_SIZE 8192U

static uint32_t append_string(char *table, size_t capacity, size_t *cursor,
                              const char *value)
{
    size_t length = strlen(value) + 1;
    uint32_t offset;

    if (*cursor == 0 || *cursor > capacity || *cursor > UINT32_MAX ||
        length > capacity - *cursor)
        return 0;
    offset = (uint32_t)*cursor;
    memcpy(table + *cursor, value, length);
    *cursor += length;
    return offset;
}

static size_t build_deep_path(char *path, size_t capacity)
{
    static const char leaf[] = "leaf.so";
    size_t cursor = 0;

    if (!path || capacity < sizeof("/d/leaf.so"))
        return 0;
    path[cursor++] = '/';
    while (cursor + 2 + sizeof(leaf) <= capacity) {
        path[cursor++] = 'd';
        path[cursor++] = '/';
    }
    memcpy(path + cursor, leaf, sizeof(leaf));
    return cursor + sizeof(leaf) - 1;
}

static int lookup_is(const struct dl_startup_dependency_index *index,
                     const char *name, int expected_result,
                     uint16_t expected_owner)
{
    uint16_t owner = UINT16_MAX;
    int result = dl_startup_dependency_index_lookup(index, name, &owner);

    return result == expected_result &&
           (result != 1 || owner == expected_owner);
}

static int runtime_lookup_is(
    const char *name, enum dl_manifest_identity_kind kind,
    int expected_result, uint32_t expected_first,
    uint32_t expected_dlopen)
{
    const struct dl_manifest_identity_slot *slot = NULL;
    int result = dl_manifest_identity_index_lookup(
        &g_dl_manifest_identity_index, name, kind, &slot);

    if (result != expected_result)
        return 0;
    if (result != 1)
        return slot == NULL;
    return slot && slot->first_manifest_index_plus_one ==
                       expected_first + 1 &&
           slot->first_dlopen_index_plus_one ==
               (expected_dlopen == UINT32_MAX
                    ? 0 : expected_dlopen + 1);
}

int main(void)
{
    const uint32_t deep_index = HIGH_MANIFEST_COUNT - 7;
    const uint32_t request_alias_index = HIGH_MANIFEST_COUNT - 6;
    const uint32_t lazy_index = HIGH_MANIFEST_COUNT - 5;
    const uint32_t pathful_index = HIGH_MANIFEST_COUNT - 4;
    const uint32_t bare_index = HIGH_MANIFEST_COUNT - 3;
    const uint32_t excluded_index = HIGH_MANIFEST_COUNT - 2;
    const uint32_t unmapped_index = HIGH_MANIFEST_COUNT - 1;
    struct dlfrz_entry *entries = NULL;
    Elf64_Dyn *dynamic = NULL;
    char *strtab = NULL;
    char deep_path[DEEP_PATH_SIZE];
    size_t deep_path_length = build_deep_path(
        deep_path, sizeof(deep_path));
    size_t strtab_capacity =
        HIGH_OBJECT_COUNT * 32U + DEEP_PATH_SIZE + 256U;
    size_t cursor = 1;
    uint32_t first_name_offset = 0;
    uint32_t second_name_offset = 0;
    uint32_t excluded_name_offset = 0;
    uint32_t excluded_request_offset = 0;
    uint32_t scoped_excluded_offset = 0;
    uint32_t component_node_offset = 0;
    uint32_t component_child_offset = 0;
    uint32_t repeated_child_offset = 0;
    uint32_t lexical_neighbor_offset = 0;
    uint32_t root_offset = 0;
    unsigned char random_key[16];
    struct dl_startup_dependency_index index;
    int result = 1;

    entries = calloc(HIGH_MANIFEST_COUNT, sizeof(*entries));
    dynamic = calloc(HIGH_OBJECT_COUNT - 1U, sizeof(*dynamic));
    strtab = calloc(strtab_capacity, 1);
    if (!entries || !dynamic || !strtab)
        goto out;

    memset(g_all_objs, 0, sizeof(g_all_objs));
    entries[0].flags = LDR_FLAG_MAIN_EXE;
    entries[0].data_offset = UINT64_C(0x1000);
    entries[0].data_size = UINT64_C(0x1000);
    g_all_objs[0].name = "/fixture/main";
    g_all_objs[0].flags = LDR_FLAG_MAIN_EXE;
    g_all_objs[0].frozen_manifest_index_plus_one = 1;
    g_all_objs[0].visible = 1;

    for (uint32_t i = 1; i < HIGH_OBJECT_COUNT; i++) {
        char name[32];
        uint32_t name_offset;
        int length = snprintf(name, sizeof(name), "libhigh%03u.so", i);

        if (length <= 0 || (size_t)length >= sizeof(name))
            goto out;
        name_offset = append_string(
            strtab, strtab_capacity, &cursor, name);
        if (name_offset == 0)
            goto out;
        if (i == 1)
            first_name_offset = name_offset;
        if (i == 2)
            second_name_offset = name_offset;
        entries[i].flags = LDR_FLAG_SHLIB;
        entries[i].data_offset = UINT64_C(0x100000) +
                                 (uint64_t)i * UINT64_C(0x2000);
        entries[i].data_size = UINT64_C(0x1000);
        entries[i].name_offset = name_offset;
        dynamic[i - 1].d_tag = DT_NEEDED;
        dynamic[i - 1].d_un.d_val = name_offset;
        g_all_objs[i].name = strtab + name_offset;
        g_all_objs[i].flags = LDR_FLAG_SHLIB;
        g_all_objs[i].frozen_manifest_index_plus_one = i + 1;
        g_all_objs[i].visible = 1;
    }
    for (uint32_t i = HIGH_OBJECT_COUNT;
         i < HIGH_MANIFEST_COUNT; i++)
        entries[i].flags = LDR_FLAG_DATA;

    {
        uint32_t pathful_name = append_string(
            strtab, strtab_capacity, &cursor,
            "/opt/dlfreeze/libpath.so");
        uint32_t bare_name = append_string(
            strtab, strtab_capacity, &cursor, "libpath.so");
        uint32_t excluded_name = append_string(
            strtab, strtab_capacity, &cursor, "excluded.so");
        uint32_t excluded_request = append_string(
            strtab, strtab_capacity, &cursor, "./excluded.so");
        uint32_t scoped_excluded = append_string(
            strtab, strtab_capacity, &cursor, "/scope/excluded.so");
        uint32_t component_node = append_string(
            strtab, strtab_capacity, &cursor, "/captured/node");
        uint32_t component_child = append_string(
            strtab, strtab_capacity, &cursor,
            "/captured/node/child.so");
        uint32_t repeated_child = append_string(
            strtab, strtab_capacity, &cursor,
            "/captured/node//child.so");
        uint32_t lexical_neighbor = append_string(
            strtab, strtab_capacity, &cursor,
            "/captured/nodeish/child.so");
        uint32_t root = append_string(
            strtab, strtab_capacity, &cursor, "/");
        uint32_t deep_name = append_string(
            strtab, strtab_capacity, &cursor, deep_path);
        uint32_t lazy_name = append_string(
            strtab, strtab_capacity, &cursor, "liblazy-index.so");

        if (!pathful_name || !bare_name || !excluded_name ||
            !excluded_request || !scoped_excluded || !component_node ||
            !component_child || !repeated_child || !lexical_neighbor ||
            !root || !deep_path_length || !deep_name || !lazy_name)
            goto out;
        excluded_name_offset = excluded_name;
        excluded_request_offset = excluded_request;
        scoped_excluded_offset = scoped_excluded;
        component_node_offset = component_node;
        component_child_offset = component_child;
        repeated_child_offset = repeated_child;
        lexical_neighbor_offset = lexical_neighbor;
        root_offset = root;
        entries[deep_index].flags =
            DLFRZ_FLAG_DATA | DLFRZ_FLAG_DATA_DIRECTORY;
        entries[deep_index].name_offset = deep_name;
        entries[request_alias_index] = entries[3];
        /* A startup-owned object may also retain a later exact dlopen
         * spelling; both identities must survive runtime indexing. */
        entries[request_alias_index].flags = LDR_FLAG_SHLIB;
        entries[request_alias_index].dlopen_request_offset =
            excluded_request;
        entries[lazy_index] = entries[4];
        entries[lazy_index].flags =
            LDR_FLAG_SHLIB | LDR_FLAG_DLOPEN;
        entries[lazy_index].name_offset = lazy_name;
        entries[pathful_index] = entries[1];
        entries[pathful_index].flags =
            LDR_FLAG_SHLIB | DLFRZ_FLAG_NEEDED_PATHFUL;
        entries[pathful_index].name_offset = pathful_name;
        entries[bare_index] = entries[2];
        entries[bare_index].name_offset = bare_name;
        entries[excluded_index] = entries[3];
        entries[excluded_index].flags = LDR_FLAG_SHLIB | LDR_FLAG_DLOPEN;
        entries[excluded_index].name_offset = excluded_name;
        entries[excluded_index].dlopen_request_offset = excluded_request;
        entries[unmapped_index] = entries[1];
        entries[unmapped_index].data_offset = UINT64_C(0x7fff0000);
        entries[unmapped_index].name_offset = first_name_offset;
    }

    g_all_objs[0].dynamic = dynamic;
    g_all_objs[0].dynamic_count = HIGH_OBJECT_COUNT - 1U;
    g_all_objs[0].dynstr = strtab;
    g_all_objs[0].dynstr_size = cursor;
    g_frozen_entries = entries;
    g_frozen_strtab = strtab;
    g_frozen_num_entries = HIGH_MANIFEST_COUNT;
    g_nobj = HIGH_OBJECT_COUNT;
    g_is_musl_runtime = 1;
    for (size_t i = 0; i < sizeof(random_key); i++)
        random_key[i] = (unsigned char)(i * 17U + 3U);
    if (vfs_seed_hash_key(random_key) < 0)
        goto out;

    /* Runtime request and lazy-dependency lookup must size itself from the
     * handful of ELF identities, not from the 65k-record DATA manifest. */
    if (dl_manifest_identity_index_build(
            &g_dl_manifest_identity_index) < 0 ||
        !g_dl_manifest_identity_index.ready ||
        g_dl_manifest_identity_build_records != HIGH_MANIFEST_COUNT ||
        g_dl_manifest_identity_index.capacity > 4096 ||
        g_dl_manifest_path_hash_bytes < deep_path_length * 2U ||
        cursor > SIZE_MAX / 4U ||
        g_dl_manifest_path_hash_bytes > cursor * 4U)
        goto out;
    g_dl_manifest_identity_lookup_probes = 0;
    if (!runtime_lookup_is(
            "./excluded.so", DL_MANIFEST_IDENTITY_REQUEST, 1,
            request_alias_index, UINT32_MAX) ||
        !runtime_lookup_is(
            "liblazy-index.so", DL_MANIFEST_IDENTITY_DEPENDENCY_BARE, 1,
            lazy_index, lazy_index) ||
        !runtime_lookup_is(
            "/opt/dlfreeze/libpath.so",
            DL_MANIFEST_IDENTITY_DEPENDENCY_PATHFUL, 1,
            pathful_index, UINT32_MAX) ||
        !runtime_lookup_is(
            strtab + first_name_offset,
            DL_MANIFEST_IDENTITY_DEPENDENCY_BARE, 1,
            1, UINT32_MAX) ||
        !runtime_lookup_is(
            "not-in-manifest.so", DL_MANIFEST_IDENTITY_DEPENDENCY_BARE,
            0, 0, UINT32_MAX) ||
        g_dl_manifest_identity_lookup_probes > 64)
        goto out;
    {
        const struct dl_manifest_identity_slot *request_slot = NULL;

        if (dl_manifest_request_index_lookup(
                "./excluded.so", &request_slot) != 1 ||
            !dl_loaded_request_slot_matches(
                &g_all_objs[3], request_slot) ||
            dl_loaded_request_slot_matches(
                &g_all_objs[1], request_slot))
            goto out;
    }
    dl_manifest_identity_index_release(
        &g_dl_manifest_identity_index);

    /* A repeated exact request may describe aliases of one source, but it
     * must never make one spelling select two immutable byte ranges. */
    entries[request_alias_index].data_offset++;
    if (dl_manifest_identity_index_build(
            &g_dl_manifest_identity_index) == 0) {
        dl_manifest_identity_index_release(
            &g_dl_manifest_identity_index);
        goto out;
    }
    entries[request_alias_index].data_offset--;

    {
        struct dlfrz_entry saved_pathful = entries[pathful_index];
        struct dlfrz_entry saved_bare = entries[bare_index];

        /* A bare request and a non-pathful dependency normalize to the same
         * basename domain.  Distinct immutable sources must be rejected. */
        entries[request_alias_index].dlopen_request_offset =
            excluded_name_offset;
        entries[pathful_index] = entries[1];
        entries[pathful_index].flags =
            LDR_FLAG_SHLIB | LDR_FLAG_DLOPEN;
        entries[pathful_index].name_offset = scoped_excluded_offset;
        if (dl_manifest_identity_index_build(
                &g_dl_manifest_identity_index) == 0) {
            dl_manifest_identity_index_release(
                &g_dl_manifest_identity_index);
            goto out;
        }
        entries[pathful_index].data_offset =
            entries[request_alias_index].data_offset;
        entries[pathful_index].data_size =
            entries[request_alias_index].data_size;
        if (dl_manifest_identity_index_build(
                &g_dl_manifest_identity_index) < 0)
            goto out;
        dl_manifest_identity_index_release(
            &g_dl_manifest_identity_index);

        /* Canonical, logical, and exact-request path spellings share the
         * embedded-ELF namespace even when loader lookup roles do not. */
        entries[request_alias_index].dlopen_request_offset =
            excluded_request_offset;
        entries[pathful_index] = saved_pathful;
        entries[pathful_index].logical_name_offset =
            excluded_request_offset;
        if (dl_manifest_identity_index_build(
                &g_dl_manifest_identity_index) == 0) {
            dl_manifest_identity_index_release(
                &g_dl_manifest_identity_index);
            goto out;
        }
        entries[pathful_index].data_offset =
            entries[request_alias_index].data_offset;
        entries[pathful_index].data_size =
            entries[request_alias_index].data_size;
        if (dl_manifest_identity_index_build(
                &g_dl_manifest_identity_index) < 0)
            goto out;
        dl_manifest_identity_index_release(
            &g_dl_manifest_identity_index);

        memset(&entries[pathful_index], 0,
               sizeof(entries[pathful_index]));
        entries[pathful_index].flags =
            DLFRZ_FLAG_DATA | DLFRZ_FLAG_DATA_NEGATIVE;
        entries[pathful_index].name_offset =
            excluded_request_offset;
        if (dl_manifest_identity_index_build(
                &g_dl_manifest_identity_index) == 0) {
            dl_manifest_identity_index_release(
                &g_dl_manifest_identity_index);
            goto out;
        }

        /* Component ancestors participate in VFS type identity.  Exercise
         * both ELF->DATA and DATA->ELF orderings, root, repeated separators,
         * and the non-component lexical prefix control. */
        entries[request_alias_index].dlopen_request_offset =
            component_node_offset;
        memset(&entries[pathful_index], 0,
               sizeof(entries[pathful_index]));
        entries[pathful_index].flags = DLFRZ_FLAG_DATA;
        entries[pathful_index].name_offset = component_child_offset;
        entries[pathful_index].data_offset = UINT64_C(0x88000000);
        entries[pathful_index].data_size = UINT64_C(0x1000);
        if (dl_manifest_identity_index_build(
                &g_dl_manifest_identity_index) == 0) {
            dl_manifest_identity_index_release(
                &g_dl_manifest_identity_index);
            goto out;
        }
        entries[pathful_index].flags =
            DLFRZ_FLAG_DATA | DLFRZ_FLAG_DATA_NEGATIVE;
        entries[pathful_index].data_offset = 0;
        entries[pathful_index].data_size = 0;
        if (dl_manifest_identity_index_build(
                &g_dl_manifest_identity_index) < 0)
            goto out;
        dl_manifest_identity_index_release(
            &g_dl_manifest_identity_index);

        entries[request_alias_index].dlopen_request_offset =
            excluded_request_offset;
        memset(&entries[pathful_index], 0,
               sizeof(entries[pathful_index]));
        entries[pathful_index].flags =
            DLFRZ_FLAG_DATA | DLFRZ_FLAG_DATA_NEGATIVE;
        entries[pathful_index].name_offset = component_node_offset;
        entries[bare_index] = saved_bare;
        entries[bare_index].flags =
            LDR_FLAG_SHLIB | DLFRZ_FLAG_NEEDED_PATHFUL;
        entries[bare_index].name_offset = component_child_offset;
        if (dl_manifest_identity_index_build(
                &g_dl_manifest_identity_index) == 0) {
            dl_manifest_identity_index_release(
                &g_dl_manifest_identity_index);
            goto out;
        }
        memset(&entries[bare_index], 0, sizeof(entries[bare_index]));
        entries[bare_index].flags =
            DLFRZ_FLAG_DATA | DLFRZ_FLAG_DATA_NEGATIVE;
        entries[bare_index].name_offset = component_child_offset;
        if (dl_manifest_identity_index_build(
                &g_dl_manifest_identity_index) < 0)
            goto out;
        dl_manifest_identity_index_release(
            &g_dl_manifest_identity_index);
        entries[bare_index] = saved_bare;
        entries[bare_index].flags =
            LDR_FLAG_SHLIB | DLFRZ_FLAG_NEEDED_PATHFUL;
        entries[bare_index].name_offset = component_child_offset;
        entries[pathful_index].flags =
            DLFRZ_FLAG_DATA | DLFRZ_FLAG_DATA_DIRECTORY;
        if (dl_manifest_identity_index_build(
                &g_dl_manifest_identity_index) < 0)
            goto out;
        dl_manifest_identity_index_release(
            &g_dl_manifest_identity_index);

        entries[pathful_index].flags =
            DLFRZ_FLAG_DATA | DLFRZ_FLAG_DATA_NEGATIVE;
        entries[bare_index].name_offset = lexical_neighbor_offset;
        if (dl_manifest_identity_index_build(
                &g_dl_manifest_identity_index) < 0)
            goto out;
        dl_manifest_identity_index_release(
            &g_dl_manifest_identity_index);
        entries[bare_index].name_offset = repeated_child_offset;
        if (dl_manifest_identity_index_build(
                &g_dl_manifest_identity_index) == 0) {
            dl_manifest_identity_index_release(
                &g_dl_manifest_identity_index);
            goto out;
        }

        entries[pathful_index].name_offset = root_offset;
        entries[bare_index].name_offset = component_child_offset;
        if (dl_manifest_identity_index_build(
                &g_dl_manifest_identity_index) == 0) {
            dl_manifest_identity_index_release(
                &g_dl_manifest_identity_index);
            goto out;
        }
        entries[pathful_index].flags =
            DLFRZ_FLAG_DATA | DLFRZ_FLAG_DATA_DIRECTORY;
        if (dl_manifest_identity_index_build(
                &g_dl_manifest_identity_index) < 0)
            goto out;
        dl_manifest_identity_index_release(
            &g_dl_manifest_identity_index);
        entries[pathful_index] = saved_pathful;
        entries[bare_index] = saved_bare;
    }

    /* With the former per-object full-manifest alias scan, these 511 edges
     * and 65,535 records require billions of comparisons. */
    if (dl_initialize_startup_lookup_scopes(
            g_all_objs, HIGH_OBJECT_COUNT) < 0 ||
        g_all_objs[0].needed_count != HIGH_OBJECT_COUNT - 1U ||
        g_all_objs[0].lookup_scope_count != HIGH_OBJECT_COUNT ||
        g_global_scope_count != HIGH_OBJECT_COUNT)
        goto out;
    for (uint16_t i = 1; i < HIGH_OBJECT_COUNT; i++)
        if (g_all_objs[0].needed_indices[i - 1] != i)
            goto out;

    if (dl_startup_dependency_index_build(
            g_all_objs, HIGH_OBJECT_COUNT, &index) < 0)
        goto out;
    if (!lookup_is(&index, "/opt/dlfreeze/libpath.so", 1, 1) ||
        !lookup_is(&index, "libpath.so", 1, 2) ||
        !lookup_is(&index, "excluded.so", 0, 0) ||
        !lookup_is(&index, strtab + first_name_offset, 1, 1)) {
        dl_startup_dependency_index_release(&index);
        goto out;
    }
    dl_startup_dependency_index_release(&index);

    /* A native loaded-name match earlier in object order still wins over a
     * later object's manifest alias. */
    entries[1].flags = LDR_FLAG_SHLIB | LDR_FLAG_DLOPEN;
    entries[1].dlopen_request_offset = excluded_request_offset;
    entries[unmapped_index] = entries[3];
    entries[unmapped_index].flags = LDR_FLAG_SHLIB;
    entries[unmapped_index].name_offset = first_name_offset;
    if (dl_startup_dependency_index_build(
            g_all_objs, HIGH_OBJECT_COUNT, &index) < 0)
        goto out;
    if (!lookup_is(&index, strtab + first_name_offset, 1, 3)) {
        dl_startup_dependency_index_release(&index);
        goto out;
    }
    dl_startup_dependency_index_release(&index);
    g_all_objs[0].needed_count = 0;
    g_all_objs[0].dynamic_count = 1;
    if (dl_initialize_startup_dependency_edges(
            g_all_objs, HIGH_OBJECT_COUNT) < 0 ||
        g_all_objs[0].needed_count != 1 ||
        g_all_objs[0].needed_indices[0] != 1)
        goto out;
    g_all_objs[0].dynamic_count = HIGH_OBJECT_COUNT - 1U;

    /* Manifest order is independent of load order.  Insert owner 2's own
     * identity first and a later alias for owner 1, then require owner 1. */
    entries[1].flags = LDR_FLAG_SHLIB;
    entries[1].dlopen_request_offset = 0;
    entries[unmapped_index] = entries[1];
    entries[unmapped_index].name_offset = second_name_offset;
    if (dl_startup_dependency_index_build(
            g_all_objs, HIGH_OBJECT_COUNT, &index) < 0)
        goto out;
    if (!lookup_is(&index, strtab + second_name_offset, 1, 1)) {
        dl_startup_dependency_index_release(&index);
        goto out;
    }
    dl_startup_dependency_index_release(&index);

    /* Two loaded objects cannot own the same nonempty immutable source.
     * That is structural corruption, not dependency-name shadowing. */
    {
        uint64_t second_data_offset = entries[2].data_offset;
        uint64_t second_data_size = entries[2].data_size;

        entries[2].data_offset = entries[1].data_offset;
        entries[2].data_size = entries[1].data_size;
        if (dl_startup_dependency_index_build(
                g_all_objs, HIGH_OBJECT_COUNT, &index) == 0) {
            dl_startup_dependency_index_release(&index);
            goto out;
        }
        entries[2].data_offset = second_data_offset;
        entries[2].data_size = second_data_size;
    }
    result = 0;

out:
    dl_manifest_identity_index_release(
        &g_dl_manifest_identity_index);
    g_frozen_entries = NULL;
    g_frozen_strtab = NULL;
    g_frozen_num_entries = 0;
    g_nobj = 0;
    memset(g_all_objs, 0, sizeof(g_all_objs));
    free(strtab);
    free(dynamic);
    free(entries);
    if (result != 0)
        fputs("startup dependency identity index gate failed\n", stderr);
    return result;
}
