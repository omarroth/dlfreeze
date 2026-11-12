#include "../src/loader.c"

int main(void)
{
    struct dlfrz_entry entries[4] = {
        {.flags = DLFRZ_FLAG_MAIN_EXE, .data_offset = 128, .data_size = 16},
        {.flags = DLFRZ_FLAG_SHLIB, .data_offset = 160, .data_size = 16,
         .name_offset = sizeof("/caller-a")},
        {.flags = DLFRZ_FLAG_SHLIB, .data_offset = 128, .data_size = 16,
         .name_offset = sizeof("/caller-a") + sizeof("/caller-b")},
        {.flags = DLFRZ_FLAG_DATA | DLFRZ_FLAG_DATA_NEGATIVE | DLFRZ_FLAG_LOADER_PROBE,
         .data_offset = 0, .data_size = sizeof(struct dlfrz_loader_probe),
         .name_offset = sizeof("/caller-a") + sizeof("/caller-b") + sizeof("/caller-alias")}
    };
    const char strings[] = "/caller-a\0/caller-b\0/caller-alias\0/recorded/probe.so\0";
    const char *request = strings + entries[3].name_offset;
    struct dlfrz_loader_probe witness = {
        DLFRZ_LOADER_PROBE_MAGIC, DLFRZ_LOADER_MISS_GNU, 0,
        DLFRZ_RTLD_NOW | DLFRZ_RTLD_NOLOAD, 0, UINT32_MAX, {0, 0}
    };
    struct loaded_obj caller = {.frozen_manifest_index_plus_one = 1};
    struct loaded_obj other = {.frozen_manifest_index_plus_one = 2};
    struct loaded_obj alias = {.frozen_manifest_index_plus_one = 3};
    uint8_t key[16] = {0};
    g_frozen_entries = entries;
    g_frozen_num_entries = 4;
    g_frozen_strtab = strings;
    if (vfs_seed_hash_key(key) < 0 ||
        vfs_init((const uint8_t *)&witness, 0, entries, strings, 4) < 0 ||
        g_loader_probe_count != 1 || g_vfs_count ||
        vfs_lookup(request) || vfs_dir_exists("/recorded")) return 1;
    const struct frozen_loader_probe *probe = dl_find_loader_probe(&caller, request, 6);
    if (!probe || dl_find_loader_probe(&other, request, 6) ||
        dl_find_loader_probe(NULL, request, 6) ||
        dl_find_loader_probe(&caller, request, 2) ||
        dl_find_loader_probe(&caller, "unrecorded.so", 6) ||
        dl_find_loader_probe(&alias, request, 6) != probe) return 2;
    for (int mutation = 0; mutation < 8; mutation++) {
        struct dlfrz_loader_probe changed = witness;
        switch (mutation) {
        case 0: changed.magic++; break;
        case 1: changed.family++; break;
        case 2: changed.error_code = 99; break;
        case 3: changed.mode = DLFRZ_RTLD_NOLOAD; break;
        case 4: changed.caller_index = 4; break;
        case 5: changed.caller_index = 3; break;
        case 6: changed.provider_index = 4; break;
        case 7: changed.reserved[1] = 1; break;
        }
        if (vfs_init((const uint8_t *)&changed, 0, entries, strings, 4) == 0)
            return 10 + mutation;
    }
    puts("probe metadata bounds, caller isolation and VFS separation passed");
    return 0;
}
