/* Focused embedded-VFS hashing and derived-directory complexity gate. */
#define DLFREEZE_VFS_COMPLEXITY_GATE 1
#include "../src/loader.c"

#define COLLIDER_COUNT (1U << 14)
#define COLLIDER_PAIRS 14U
#define COLLIDER_STRIDE (2U * COLLIDER_PAIRS + 2U)
#define DEEP_COMPONENTS 12000U
#define FROZEN_ELF_COUNT (1U << 14)
#define FROZEN_ELF_NAME_SIZE 48U
#define FROZEN_ELF_STRIDE (2U * FROZEN_ELF_NAME_SIZE)
#define SHARED_PREFIX_FILES (1U << 12)
#define SHARED_PREFIX_COMPONENTS 64U
#define SHARED_PREFIX_STRIDE 160U
#define SPARSE_CHILD_FILES (1U << 12)
#define SPARSE_CHILD_STRIDE 192U

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
    frozen_elf_index_reset();
    vfs_reset_dirs();
    g_frozen_metas = NULL;
    g_frozen_entries = NULL;
    g_frozen_strtab = NULL;
    g_frozen_num_entries = 0;
    g_frozen_mem = NULL;
    g_frozen_mem_foff = 0;
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

static int frozen_elf_index_gate(void)
{
    struct dlfrz_entry *entries = NULL;
    struct dlfrz_lib_meta *metas = NULL;
    char *strings = NULL;
    uint8_t data = 0;
    size_t lookup_count = 0;
    int result = -1;

    entries = calloc(FROZEN_ELF_COUNT, sizeof(*entries));
    metas = calloc(FROZEN_ELF_COUNT, sizeof(*metas));
    strings = calloc(FROZEN_ELF_COUNT, FROZEN_ELF_STRIDE);
    if (!entries || !metas || !strings)
        goto out;
    for (uint32_t i = 0; i < FROZEN_ELF_COUNT; i++) {
        size_t offset = (size_t)i * FROZEN_ELF_STRIDE;
        char *canonical = strings + offset;
        char *logical = canonical + FROZEN_ELF_NAME_SIZE;
        int canonical_length;
        int logical_length;

        if (offset > UINT32_MAX - FROZEN_ELF_NAME_SIZE)
            goto out;
        canonical_length = snprintf(
            canonical, FROZEN_ELF_NAME_SIZE,
            "/frozen/canonical/%08u.so", i);
        logical_length = snprintf(
            logical, FROZEN_ELF_NAME_SIZE,
            "/frozen/logical/%08u.so", i);
        if (canonical_length <= 0 ||
            (size_t)canonical_length >= FROZEN_ELF_NAME_SIZE ||
            logical_length <= 0 ||
            (size_t)logical_length >= FROZEN_ELF_NAME_SIZE)
            goto out;
        entries[i].flags = DLFRZ_FLAG_SHLIB;
        entries[i].name_offset = (uint32_t)offset;
        entries[i].logical_name_offset =
            (uint32_t)(offset + FROZEN_ELF_NAME_SIZE);
        metas[i].flags = LDR_FLAG_SHLIB;
    }

    /* The last entry's canonical spelling aliases entry zero's logical
     * spelling.  The index must retain the old lowest-manifest-index result. */
    entries[FROZEN_ELF_COUNT - 1].name_offset =
        entries[0].logical_name_offset;
    g_frozen_mem = &data;
    g_frozen_mem_foff = 0;
    g_frozen_metas = metas;
    g_frozen_entries = entries;
    g_frozen_strtab = strings;
    g_frozen_num_entries = FROZEN_ELF_COUNT;
    if (vfs_init(&data, 0, entries, strings, FROZEN_ELF_COUNT) < 0 ||
        g_frozen_elf_path_count != 2U * FROZEN_ELF_COUNT - 1U ||
        frozen_elf_find(strings + entries[0].logical_name_offset) != 0)
        goto out;

    g_frozen_elf_lookup_probes = 0;
    for (uint32_t i = 0; i < FROZEN_ELF_COUNT; i++) {
        const char *canonical = strings + (size_t)i * FROZEN_ELF_STRIDE;
        const char *logical = canonical + FROZEN_ELF_NAME_SIZE;
        char missing[FROZEN_ELF_NAME_SIZE];
        int missing_length;
        int canonical_expected =
            i == FROZEN_ELF_COUNT - 1 ? -1 : (int)i;

        if (canonical_expected >= 0 &&
            frozen_elf_find(canonical) != canonical_expected)
            goto out;
        if (frozen_elf_find(logical) != (int)i)
            goto out;
        missing_length = snprintf(
            missing, sizeof(missing), "/not-frozen/%08u.so", i);
        if (missing_length <= 0 ||
            (size_t)missing_length >= sizeof(missing) ||
            frozen_elf_find(missing) != -1)
            goto out;
        lookup_count += canonical_expected >= 0 ? 3U : 2U;
    }
    if (g_frozen_elf_lookup_probes > lookup_count * 16U)
        goto out;
    result = 0;

out:
    reset_gate_vfs();
    g_frozen_mem = NULL;
    g_frozen_mem_foff = 0;
    free(entries);
    free(metas);
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
        g_vfs_dir_count != DEEP_COMPONENTS + 1U ||
        !vfs_dir_exists_n(path, 1) ||
        !vfs_dir_exists_n(path, 2) ||
        !vfs_dir_exists_n(path, 2U * DEEP_COMPONENTS))
        goto out;
    for (size_t i = 0; i < g_vfs_dir_count; i++) {
        const struct vfs_dir_entry *directory = &g_vfs_dirs[i];

        if (directory->path != path || directory->length > position)
            goto out;
    }
    result = 0;

out:
    reset_gate_vfs();
    free(path);
    return result;
}

static int root_frozen_elf_directory_gate(void)
{
    static char path[] = "/dlfrz-frozen-root-probe.so";
    struct dlfrz_entry entry;
    struct dlfrz_lib_meta meta;
    struct vfs_dir_handle handle;
    struct dirent *dirent;
    uint8_t data = 0;
    int fd = -1;
    int matches = 0;
    int result = -1;

    reset_gate_vfs();
    memset(&entry, 0, sizeof(entry));
    memset(&meta, 0, sizeof(meta));
    entry.flags = DLFRZ_FLAG_SHLIB | DLFRZ_FLAG_DLOPEN;
    meta.flags = LDR_FLAG_SHLIB | LDR_FLAG_DLOPEN;
    g_frozen_mem = &data;
    g_frozen_mem_foff = 0;
    g_frozen_metas = &meta;
    g_frozen_entries = &entry;
    g_frozen_strtab = path;
    g_frozen_num_entries = 1;
    if (vfs_init(&data, 0, &entry, path, 1) < 0 ||
        !vfs_dir_exists("/"))
        goto out;

    fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        goto out;
    memset(&handle, 0, sizeof(handle));
    handle.fd_compat = fd;
    handle.vfs_path = "/";
    handle.vfs_path_len = 1;
    handle.phase = -1;
    handle.real_directory = 1;
    vfs_initialize_real_dir_position(&handle);
    while ((dirent = vfs_readdir_fake_locked(&handle)) != NULL) {
        if (strcmp(dirent->d_name, path + 1) == 0)
            matches++;
    }
    if (matches == 1 && handle.phase == 3)
        result = 0;

out:
    if (fd >= 0)
        close(fd);
    reset_gate_vfs();
    return result;
}

static int shared_prefix_capacity_gate(void)
{
    struct dlfrz_entry *entries = NULL;
    char *strings = NULL;
    uint8_t data = 0;
    size_t expected_directories = SHARED_PREFIX_COMPONENTS + 1U;
    size_t expected_children =
        SHARED_PREFIX_FILES + SHARED_PREFIX_COMPONENTS;
    int result = -1;

    entries = calloc(SHARED_PREFIX_FILES, sizeof(*entries));
    strings = calloc(SHARED_PREFIX_FILES, SHARED_PREFIX_STRIDE);
    if (!entries || !strings)
        goto out;
    for (uint32_t i = 0; i < SHARED_PREFIX_FILES; i++) {
        size_t offset = (size_t)i * SHARED_PREFIX_STRIDE;
        char *path = strings + offset;
        size_t position = 0;
        int length;

        if (offset > UINT32_MAX)
            goto out;
        for (size_t component = 0;
             component < SHARED_PREFIX_COMPONENTS; component++) {
            if (position + 2 >= SHARED_PREFIX_STRIDE)
                goto out;
            path[position++] = '/';
            path[position++] = 'a';
        }
        length = snprintf(path + position, SHARED_PREFIX_STRIDE - position,
                          "/file-%08u", i);
        if (length <= 0 ||
            (size_t)length >= SHARED_PREFIX_STRIDE - position)
            goto out;
        entries[i].flags = DLFRZ_FLAG_DATA;
        entries[i].name_offset = (uint32_t)offset;
    }

    if (vfs_init(&data, 0, entries, strings, SHARED_PREFIX_FILES) < 0 ||
        g_vfs_dir_count != expected_directories ||
        g_vfs_dir_child_count != expected_children ||
        g_vfs_dir_table_size > 4U * expected_directories ||
        g_vfs_dir_capacity >= 2U * expected_directories)
        goto out;
    result = 0;

out:
    reset_gate_vfs();
    free(entries);
    free(strings);
    return result;
}

static int sparse_directory_child_gate(void)
{
    enum {
        DATA_INDEX = SPARSE_CHILD_FILES,
        VIRTUAL_INDEX,
        NEGATIVE_INDEX,
        EXPLICIT_DIR_INDEX,
        NESTED_INDEX,
        ELF_INDEX,
        ENTRY_COUNT,
    };
    struct dlfrz_entry *entries = NULL;
    struct dlfrz_lib_meta *metas = NULL;
    char *strings = NULL;
    const struct vfs_dir_entry *focus;
    const struct vfs_entry *data_entry;
    const struct vfs_entry *virtual_entry;
    const struct vfs_dir_entry *explicit_directory;
    const struct vfs_dir_entry *nested_directory;
    struct vfs_dir_handle handle;
    struct dirent *dirent;
    uint8_t data = 0;
    ino_t elf_inode;
    unsigned int last_phase = 0;
    int data_count = 0;
    int virtual_count = 0;
    int explicit_count = 0;
    int nested_count = 0;
    int module_count = 0;
    int alias_count = 0;
    int result = -1;

    entries = calloc(ENTRY_COUNT, sizeof(*entries));
    metas = calloc(ENTRY_COUNT, sizeof(*metas));
    strings = calloc(ENTRY_COUNT, SPARSE_CHILD_STRIDE);
    if (!entries || !metas || !strings)
        goto out;
    for (uint32_t i = 0; i < SPARSE_CHILD_FILES; i++) {
        size_t offset = (size_t)i * SPARSE_CHILD_STRIDE;
        char *path = strings + offset;
        int length = snprintf(path, SPARSE_CHILD_STRIDE,
                              "/bulk/%08u/item", i);

        if (offset > UINT32_MAX || length <= 0 ||
            (size_t)length >= SPARSE_CHILD_STRIDE)
            goto out;
        entries[i].flags = DLFRZ_FLAG_DATA;
        entries[i].name_offset = (uint32_t)offset;
    }
    {
        static const char *const data_paths[] = {
            "/focus/data",
            "/focus/virtual",
            "/focus/missing",
            "/focus/explicit",
            "/focus/sub/leaf",
        };

        for (size_t i = 0; i < sizeof(data_paths) / sizeof(data_paths[0]);
             i++) {
            size_t index = DATA_INDEX + i;
            size_t offset = index * SPARSE_CHILD_STRIDE;
            size_t length = strlen(data_paths[i]);

            if (offset > UINT32_MAX || length >= SPARSE_CHILD_STRIDE)
                goto out;
            memcpy(strings + offset, data_paths[i], length + 1);
            entries[index].flags = DLFRZ_FLAG_DATA;
            entries[index].name_offset = (uint32_t)offset;
        }
    }
    entries[VIRTUAL_INDEX].flags |= DLFRZ_FLAG_DATA_VIRTUAL;
    entries[NEGATIVE_INDEX].flags |= DLFRZ_FLAG_DATA_NEGATIVE;
    entries[EXPLICIT_DIR_INDEX].flags |= DLFRZ_FLAG_DATA_DIRECTORY;
    {
        size_t offset = (size_t)ELF_INDEX * SPARSE_CHILD_STRIDE;
        char *canonical = strings + offset;
        char *logical = canonical + 64;
        char *request = canonical + 128;

        if (offset > UINT32_MAX - 128U)
            goto out;
        memcpy(canonical, "/focus/module.so", sizeof("/focus/module.so"));
        memcpy(logical, "/focus/module-alias.so",
               sizeof("/focus/module-alias.so"));
        memcpy(request, "/focus/data", sizeof("/focus/data"));
        entries[ELF_INDEX].flags = DLFRZ_FLAG_SHLIB | DLFRZ_FLAG_DLOPEN;
        entries[ELF_INDEX].name_offset = (uint32_t)offset;
        entries[ELF_INDEX].logical_name_offset = (uint32_t)(offset + 64);
        entries[ELF_INDEX].dlopen_request_offset = (uint32_t)(offset + 128);
        metas[ELF_INDEX].flags = LDR_FLAG_SHLIB | LDR_FLAG_DLOPEN;
    }

    g_frozen_mem = &data;
    g_frozen_mem_foff = 0;
    g_frozen_metas = metas;
    g_frozen_entries = entries;
    g_frozen_strtab = strings;
    g_frozen_num_entries = ENTRY_COUNT;
    if (vfs_init(&data, 0, entries, strings, ENTRY_COUNT) < 0)
        goto out;
    focus = vfs_dir_lookup("/focus");
    data_entry = vfs_lookup("/focus/data");
    virtual_entry = vfs_lookup("/focus/virtual");
    explicit_directory = vfs_dir_lookup("/focus/explicit");
    nested_directory = vfs_dir_lookup("/focus/sub");
    if (!focus || !data_entry || !virtual_entry || !explicit_directory ||
        !nested_directory || !g_frozen_elf_inodes)
        goto out;
    elf_inode = g_frozen_elf_inodes[ELF_INDEX];

    memset(&handle, 0, sizeof(handle));
    handle.fd_compat = -1;
    handle.vfs_path = "/focus";
    handle.vfs_path_len = sizeof("/focus") - 1;
    handle.vfs_directory = focus;
    handle.phase = VFS_DIR_CHILD_DATA;
    handle.next_position_cookie = 2;
    if (!vfs_real_dirent_is_shadowed(&handle, "missing") ||
        !vfs_real_dirent_is_shadowed(&handle, "data") ||
        !vfs_real_dirent_is_shadowed(&handle, "module.so") ||
        vfs_real_dirent_is_shadowed(&handle, "host-only"))
        goto out;

    g_vfs_readdir_child_probes = 0;
    while ((dirent = vfs_readdir_fake_locked(&handle)) != NULL) {
        uint64_t encoded_offset = (uint64_t)dirent->d_off;
        unsigned int phase = (unsigned int)(encoded_offset >> 32);

        if (phase < 1 || phase > 3 || phase < last_phase ||
            (uint32_t)encoded_offset == 0)
            goto out;
        last_phase = phase;
        if (strcmp(dirent->d_name, "data") == 0) {
            if (phase != 1 || dirent->d_type != DT_REG ||
                dirent->d_ino != data_entry->inode)
                goto out;
            data_count++;
        } else if (strcmp(dirent->d_name, "virtual") == 0) {
            if (phase != 1 || dirent->d_type != DT_REG ||
                dirent->d_ino != virtual_entry->inode)
                goto out;
            virtual_count++;
        } else if (strcmp(dirent->d_name, "explicit") == 0) {
            if (phase != 2 || dirent->d_type != DT_DIR ||
                dirent->d_ino != explicit_directory->inode)
                goto out;
            explicit_count++;
        } else if (strcmp(dirent->d_name, "sub") == 0) {
            if (phase != 2 || dirent->d_type != DT_DIR ||
                dirent->d_ino != nested_directory->inode)
                goto out;
            nested_count++;
        } else if (strcmp(dirent->d_name, "module.so") == 0) {
            if (phase != 3 || dirent->d_type != DT_REG ||
                dirent->d_ino != elf_inode)
                goto out;
            module_count++;
        } else if (strcmp(dirent->d_name, "module-alias.so") == 0) {
            if (phase != 3 || dirent->d_type != DT_REG ||
                dirent->d_ino != elf_inode)
                goto out;
            alias_count++;
        } else {
            goto out;
        }
    }
    if (data_count != 1 || virtual_count != 1 || explicit_count != 1 ||
        nested_count != 1 || module_count != 1 || alias_count != 1 ||
        handle.phase != VFS_DIR_CHILD_PHASES ||
        g_vfs_readdir_child_probes != 6)
        goto out;
    for (size_t i = 0; i < 64; i++) {
        if (vfs_readdir_fake_locked(&handle) != NULL)
            goto out;
    }
    if (g_vfs_readdir_child_probes != 6)
        goto out;
    vfs_rewinddir_fake_locked(&handle);
    while (vfs_readdir_fake_locked(&handle) != NULL)
        ;
    if (handle.phase != VFS_DIR_CHILD_PHASES ||
        g_vfs_readdir_child_probes != 12)
        goto out;
    result = 0;

out:
    reset_gate_vfs();
    free(entries);
    free(metas);
    free(strings);
    return result;
}

int main(void)
{
    if (keyed_hash_gate() < 0)
        return 1;
    if (collider_manifest_gate() < 0)
        return 2;
    if (frozen_elf_index_gate() < 0)
        return 3;
    if (deep_directory_gate() < 0)
        return 4;
    if (root_frozen_elf_directory_gate() < 0)
        return 5;
    if (shared_prefix_capacity_gate() < 0)
        return 6;
    if (sparse_directory_child_gate() < 0)
        return 7;
    return 0;
}
