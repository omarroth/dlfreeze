/* Focused embedded-VFS hashing and derived-directory complexity gate. */
#include "../src/loader.c"

#define COLLIDER_COUNT (1U << 14)
#define COLLIDER_PAIRS 14U
#define COLLIDER_STRIDE (2U * COLLIDER_PAIRS + 2U)
#define DEEP_COMPONENTS 12000U

static uint64_t legacy_djb_hash(const char *string)
{
    uint64_t hash = 5381;

    while (*string)
        hash = hash * 33 + (uint8_t)*string++;
    return hash;
}

static void reset_gate_vfs(void)
{
    free(g_vfs_table);
    g_vfs_table = NULL;
    g_vfs_table_size = 0;
    g_vfs_count = 0;
    vfs_reset_dirs();
    g_frozen_metas = NULL;
    g_frozen_entries = NULL;
    g_frozen_strtab = NULL;
    g_frozen_num_entries = 0;
}

static int keyed_hash_gate(void)
{
    uint8_t key[16];
    uint64_t first;

    for (size_t i = 0; i < sizeof(key); i++)
        key[i] = (uint8_t)i;
    if (vfs_seed_hash_key(key) < 0 ||
        vfs_hash_n("", 0) != UINT64_C(0x726fdb47dd0e0e31))
        return -1;
    first = vfs_hash_n("/adversarial/path", 17);
    key[0] ^= UINT8_C(0xa5);
    if (vfs_seed_hash_key(key) < 0 ||
        vfs_hash_n("/adversarial/path", 17) == first)
        return -1;
    return 0;
}

static int collider_manifest_gate(void)
{
    struct dlfrz_entry *entries = NULL;
    char *strings = NULL;
    uint8_t key[16];
    uint8_t data = 0;
    uint64_t legacy_hash = 0;
    int result = -1;

    entries = calloc(COLLIDER_COUNT, sizeof(*entries));
    strings = calloc(COLLIDER_COUNT, COLLIDER_STRIDE);
    if (!entries || !strings)
        goto out;
    for (uint32_t i = 0; i < COLLIDER_COUNT; i++) {
        char *path = strings + (size_t)i * COLLIDER_STRIDE;

        path[0] = '/';
        for (unsigned int bit = 0; bit < COLLIDER_PAIRS; bit++) {
            int alternate = (i & (UINT32_C(1) << bit)) != 0;

            path[1 + 2 * bit] = alternate ? 'B' : 'A';
            path[2 + 2 * bit] = alternate ? ']' : '~';
        }
        path[1 + 2 * COLLIDER_PAIRS] = '\0';
        entries[i].flags = DLFRZ_FLAG_DATA | DLFRZ_FLAG_DATA_NEGATIVE;
        entries[i].name_offset = i * COLLIDER_STRIDE;
        if (i == 0)
            legacy_hash = legacy_djb_hash(path);
        else if (legacy_djb_hash(path) != legacy_hash)
            goto out;
    }

    memset(g_vfs_hash_key, 0, sizeof(g_vfs_hash_key));
    g_vfs_hash_key_ready = 0;
    if (vfs_init(&data, 0, entries, strings, 1) == 0)
        goto out;
    for (size_t i = 0; i < sizeof(key); i++)
        key[i] = (uint8_t)(0x80U + i);
    if (vfs_seed_hash_key(key) < 0 ||
        vfs_init(&data, 0, entries, strings, COLLIDER_COUNT) < 0 ||
        g_vfs_count != COLLIDER_COUNT)
        goto out;
    for (uint32_t i = 0; i < COLLIDER_COUNT; i++) {
        const char *path = strings + (size_t)i * COLLIDER_STRIDE;
        const struct vfs_entry *entry = vfs_lookup(path);

        if (!entry || !vfs_is_negative_entry(entry))
            goto out;
    }
    result = 0;

out:
    reset_gate_vfs();
    free(entries);
    free(strings);
    return result;
}

static int deep_directory_gate(void)
{
    struct dlfrz_entry entry;
    char *path = NULL;
    uint8_t data = 0;
    size_t path_size = 2U * DEEP_COMPONENTS + sizeof("/file");
    size_t position = 0;
    int result = -1;

    path = malloc(path_size);
    if (!path)
        return -1;
    for (size_t i = 0; i < DEEP_COMPONENTS; i++) {
        path[position++] = '/';
        path[position++] = 'a';
    }
    memcpy(path + position, "/file", sizeof("/file"));
    memset(&entry, 0, sizeof(entry));
    entry.flags = DLFRZ_FLAG_DATA;
    if (vfs_init(&data, 0, &entry, path, 1) < 0 ||
        g_vfs_dir_count != DEEP_COMPONENTS ||
        !vfs_dir_exists_n(path, 2) ||
        !vfs_dir_exists_n(path, 2U * DEEP_COMPONENTS))
        goto out;
    for (size_t i = 0; i < g_vfs_dir_table_size; i++) {
        const struct vfs_dir_entry *directory = &g_vfs_dir_table[i];

        if (!directory->path)
            continue;
        if (directory->path != path || directory->length > position)
            goto out;
    }
    result = 0;

out:
    reset_gate_vfs();
    free(path);
    return result;
}

int main(void)
{
    if (keyed_hash_gate() < 0)
        return 1;
    if (collider_manifest_gate() < 0)
        return 2;
    if (deep_directory_gate() < 0)
        return 3;
    return 0;
}
