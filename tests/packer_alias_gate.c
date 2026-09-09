#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../src/packer.c"

static int stable_file_truncation_gate(void)
{
    char path[PATH_MAX];
    unsigned char expected[8192];
    struct packer_stable_file_image image = {0};
    struct stat before;
    const char *temporary_directory = getenv("TMPDIR");
    size_t temporary_directory_length;
    size_t done = 0;
    int fd = -1;
    int result = 0;
    int path_length;

    if (!temporary_directory || temporary_directory[0] != '/')
        temporary_directory = "/tmp";
    temporary_directory_length = strlen(temporary_directory);
    path_length = snprintf(
        path, sizeof(path), "%s%sdlfreeze-packer-stable.XXXXXX",
        temporary_directory,
        temporary_directory_length != 0 &&
                temporary_directory[temporary_directory_length - 1] == '/'
            ? "" : "/");
    if (path_length < 0 || (size_t)path_length >= sizeof(path))
        goto out;

    for (size_t i = 0; i < sizeof(expected); i++)
        expected[i] = (unsigned char)(i * 131U + 17U);
    fd = mkstemp(path);
    if (fd < 0)
        goto out;
    while (done < sizeof(expected)) {
        ssize_t written = write(fd, expected + done,
                                sizeof(expected) - done);

        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            goto out;
        done += (size_t)written;
    }
    if (fstat(fd, &before) < 0 ||
        packer_read_stable_fd(fd, &before, &image) < 0 ||
        image.size != sizeof(expected) ||
        memcmp(image.bytes, expected, sizeof(expected)) != 0)
        goto out;
    packer_stable_file_image_free(&image);

    /* Deterministically model truncate winning immediately after the first
     * fstat.  A file-backed mmap would become SIGBUS-prone; the stable reader
     * must instead report stale input without exposing any bytes. */
    if (ftruncate(fd, 0) < 0)
        goto out;
    errno = 0;
    if (packer_read_stable_fd(fd, &before, &image) == 0 ||
        errno != ESTALE || image.bytes != NULL || image.size != 0)
        goto out;
    result = 1;

out:
    packer_stable_file_image_free(&image);
    if (fd >= 0)
        close(fd);
    unlink(path);
    return result;
}

static uint32_t alias_gate_append_string(
    char *table, size_t capacity, size_t *cursor, const char *value)
{
    size_t length = strlen(value) + 1;
    uint32_t offset;

    if (!table || !cursor || !value || *cursor == 0 ||
        *cursor > capacity || *cursor > UINT32_MAX ||
        length > capacity - *cursor)
        return 0;
    offset = (uint32_t)*cursor;
    memcpy(table + *cursor, value, length);
    *cursor += length;
    return offset;
}

static int manifest_alias_collision_gate(void)
{
    struct dlfrz_entry entries[2];
    char strings[512] = {0};
    size_t cursor = 1;
    const char *conflict = NULL;
    uint32_t request_source;
    uint32_t exact_identity;
    uint32_t bare_identity;
    uint32_t bare_source;
    uint32_t node;
    uint32_t child;
    uint32_t repeated_child;
    uint32_t lexical_neighbor;
    uint32_t root;

    request_source = alias_gate_append_string(
        strings, sizeof(strings), &cursor, "/captured/request.so");
    exact_identity = alias_gate_append_string(
        strings, sizeof(strings), &cursor, "/scope/libcollision.so");
    bare_identity = alias_gate_append_string(
        strings, sizeof(strings), &cursor, "libcollision.so");
    bare_source = alias_gate_append_string(
        strings, sizeof(strings), &cursor, "/captured/libcollision.so");
    node = alias_gate_append_string(
        strings, sizeof(strings), &cursor, "/captured/node");
    child = alias_gate_append_string(
        strings, sizeof(strings), &cursor, "/captured/node/child.so");
    repeated_child = alias_gate_append_string(
        strings, sizeof(strings), &cursor, "/captured/node//child.so");
    lexical_neighbor = alias_gate_append_string(
        strings, sizeof(strings), &cursor,
        "/captured/nodeish/child.so");
    root = alias_gate_append_string(
        strings, sizeof(strings), &cursor, "/");
    if (!request_source || !exact_identity || !bare_identity ||
        !bare_source || !node || !child || !repeated_child ||
        !lexical_neighbor || !root)
        return 0;

    memset(entries, 0, sizeof(entries));
    entries[0].flags = DLFRZ_FLAG_SHLIB | DLFRZ_FLAG_DLOPEN;
    entries[0].name_offset = request_source;
    entries[0].dlopen_request_offset = exact_identity;
    entries[0].data_offset = UINT64_C(0x1000);
    entries[0].data_size = UINT64_C(0x800);
    entries[1].flags = DLFRZ_FLAG_SHLIB | DLFRZ_FLAG_DLOPEN |
                       DLFRZ_FLAG_NEEDED_PATHFUL;
    entries[1].name_offset = exact_identity;
    entries[1].data_offset = UINT64_C(0x3000);
    entries[1].data_size = UINT64_C(0x800);
    errno = 0;
    if (packed_manifest_aliases_are_consistent(
            entries, 2, strings, &conflict) == 0 ||
        errno != EEXIST || !conflict ||
        strcmp(conflict, strings + exact_identity) != 0)
        return 0;
    entries[1].data_offset = entries[0].data_offset;
    if (packed_manifest_aliases_are_consistent(
            entries, 2, strings, &conflict) < 0)
        return 0;

    /* DATA shadows frozen ELFs in open/stat.  A negative, virtual, or
     * directory record therefore cannot reuse an ELF path identity. */
    memset(&entries[1], 0, sizeof(entries[1]));
    entries[1].flags = DLFRZ_FLAG_DATA | DLFRZ_FLAG_DATA_NEGATIVE;
    entries[1].name_offset = exact_identity;
    errno = 0;
    if (packed_manifest_aliases_are_consistent(
            entries, 2, strings, &conflict) == 0 ||
        errno != EEXIST || !conflict ||
        strcmp(conflict, strings + exact_identity) != 0)
        return 0;

    /* A derived child requires every captured component ancestor to be a
     * directory.  Cover both DATA->ELF and ELF->DATA directionality, while
     * retaining ordinary lexical prefixes as distinct names. */
    memset(entries, 0, sizeof(entries));
    entries[0].flags = DLFRZ_FLAG_DATA | DLFRZ_FLAG_DATA_NEGATIVE;
    entries[0].name_offset = node;
    entries[1].flags = DLFRZ_FLAG_SHLIB | DLFRZ_FLAG_NEEDED_PATHFUL;
    entries[1].name_offset = child;
    entries[1].data_offset = UINT64_C(0x9000);
    entries[1].data_size = UINT64_C(0x800);
    if (packed_manifest_aliases_are_consistent(
            entries, 2, strings, &conflict) == 0 ||
        !conflict || strcmp(conflict, strings + node) != 0)
        return 0;

    /* Progressive misses do not materialize the child or derive its parent
     * as a directory, so a negative ancestor and negative descendant are a
     * coherent lexical snapshot. */
    entries[1].flags = DLFRZ_FLAG_DATA | DLFRZ_FLAG_DATA_NEGATIVE;
    entries[1].data_offset = 0;
    entries[1].data_size = 0;
    if (packed_manifest_aliases_are_consistent(
            entries, 2, strings, &conflict) < 0)
        return 0;

    entries[1].flags = DLFRZ_FLAG_SHLIB | DLFRZ_FLAG_NEEDED_PATHFUL;
    entries[1].data_offset = UINT64_C(0x9000);
    entries[1].data_size = UINT64_C(0x800);
    entries[0].flags = DLFRZ_FLAG_DATA | DLFRZ_FLAG_DATA_DIRECTORY;
    if (packed_manifest_aliases_are_consistent(
            entries, 2, strings, &conflict) < 0)
        return 0;

    entries[0].flags = DLFRZ_FLAG_SHLIB | DLFRZ_FLAG_NEEDED_PATHFUL;
    entries[0].data_offset = UINT64_C(0xb000);
    entries[0].data_size = UINT64_C(0x800);
    entries[1].flags = DLFRZ_FLAG_DATA;
    entries[1].data_offset = UINT64_C(0xd000);
    entries[1].data_size = UINT64_C(0x800);
    if (packed_manifest_aliases_are_consistent(
            entries, 2, strings, &conflict) == 0)
        return 0;
    entries[1].name_offset = lexical_neighbor;
    if (packed_manifest_aliases_are_consistent(
            entries, 2, strings, &conflict) < 0)
        return 0;
    entries[1].name_offset = repeated_child;
    if (packed_manifest_aliases_are_consistent(
            entries, 2, strings, &conflict) == 0)
        return 0;

    entries[0].flags = DLFRZ_FLAG_DATA | DLFRZ_FLAG_DATA_NEGATIVE;
    entries[0].name_offset = root;
    entries[0].data_offset = 0;
    entries[0].data_size = 0;
    entries[1].flags = DLFRZ_FLAG_SHLIB | DLFRZ_FLAG_NEEDED_PATHFUL;
    entries[1].name_offset = child;
    if (packed_manifest_aliases_are_consistent(
            entries, 2, strings, &conflict) == 0)
        return 0;
    entries[0].flags = DLFRZ_FLAG_DATA | DLFRZ_FLAG_DATA_DIRECTORY;
    if (packed_manifest_aliases_are_consistent(
            entries, 2, strings, &conflict) < 0)
        return 0;

    /* Bare dependency identities compare by basename, exactly as the
     * runtime's DT_NEEDED lookup does. */
    memset(entries, 0, sizeof(entries));
    entries[0].flags = DLFRZ_FLAG_SHLIB | DLFRZ_FLAG_DLOPEN;
    entries[0].name_offset = request_source;
    entries[0].dlopen_request_offset = bare_identity;
    entries[0].data_offset = UINT64_C(0x5000);
    entries[0].data_size = UINT64_C(0x800);
    entries[1].flags = DLFRZ_FLAG_SHLIB | DLFRZ_FLAG_DLOPEN;
    entries[1].name_offset = bare_source;
    entries[1].data_offset = UINT64_C(0x7000);
    entries[1].data_size = UINT64_C(0x800);
    errno = 0;
    if (packed_manifest_aliases_are_consistent(
            entries, 2, strings, &conflict) == 0 ||
        errno != EEXIST || !conflict ||
        strcmp(conflict, strings + bare_identity) != 0)
        return 0;
    entries[1].data_offset = entries[0].data_offset;
    return packed_manifest_aliases_are_consistent(
               entries, 2, strings, &conflict) == 0;
}

int main(void)
{
    enum { ALIAS_COUNT = 65535 };
    struct resolved_lib *libs =
        calloc(ALIAS_COUNT, sizeof(*libs));
    struct dlfrz_entry *entries =
        calloc(ALIAS_COUNT, sizeof(*entries));
    struct dlfrz_lib_meta *metas =
        calloc(ALIAS_COUNT, sizeof(*metas));
    int *source_aliases = malloc(ALIAS_COUNT * sizeof(*source_aliases));
    int *startup_aliases = malloc(ALIAS_COUNT * sizeof(*startup_aliases));
    struct packed_dep_source_plan source_plan = {0};
    struct dep_list deps = {
        .libs = libs,
        .count = ALIAS_COUNT,
        .interp_path = (char *)"/generic-interpreter",
    };
    struct pack_options opts = {.deps = &deps};
    const int first_ordinary = ALIAS_COUNT / 2;
    int result = 1;

    /* This gate includes the packer translation unit directly and links it
     * with section GC.  Keep helpers exercised by other packer paths marked
     * as referenced so a -Werror build remains a faithful compile gate. */
    (void)&packer_phdr_write;

    if (!stable_file_truncation_gate() ||
        !manifest_alias_collision_gate() || !libs ||
        !entries || !metas || !source_aliases || !startup_aliases)
        goto out;

    deps.main_snapshot = (struct dep_file_snapshot) {
        .device = 1, .inode = 1, .size = 4096,
        .mtime_sec = 10, .mtime_nsec = 11,
        .ctime_sec = 12, .ctime_nsec = 13, .valid = 1,
    };
    deps.interp_snapshot = (struct dep_file_snapshot) {
        .device = 2, .inode = 2, .size = 8192,
        .mtime_sec = 20, .mtime_nsec = 21,
        .ctime_sec = 22, .ctime_nsec = 23, .valid = 1,
    };
    for (int i = 0; i < ALIAS_COUNT; i++)
        libs[i].snapshot = deps.interp_snapshot;

    /* An interpreter may also be a SHLIB (musl).  Even a very large set of
     * logical aliases must form one dependency source group promptly and
     * point at the earlier interpreter payload entry. */
    if (packed_build_dep_source_plan(&deps, &source_plan) < 0 ||
        source_plan.unique_group_count != 1 || source_plan.aliases_main)
        goto out;
    for (int i = 0; i < ALIAS_COUNT; i++) {
        if (source_plan.manifest_aliases[i] != 1 ||
            source_plan.group_leaders[i] != 0)
            goto out;
    }
    packed_dep_source_plan_free(&source_plan);

    /* MAIN cannot share a direct immutable-source group with SHLIB.  Detect
     * that producer-side instead of publishing metadata the bootstrap will
     * reject at startup. */
    deps.main_snapshot = deps.interp_snapshot;
    if (packed_build_dep_source_plan(&deps, &source_plan) < 0 ||
        !source_plan.aliases_main ||
        source_plan.unique_group_count != 1 ||
        direct_runtime_supported(&opts, &source_plan) != 0)
        goto out;
    packed_dep_source_plan_free(&source_plan);

    for (int i = 0; i < ALIAS_COUNT; i++) {
        uint32_t flags = i == 0 ? DLFRZ_FLAG_INTERP : DLFRZ_FLAG_SHLIB;

        if (i != 0 && i < first_ordinary)
            flags |= DLFRZ_FLAG_DLOPEN;
        entries[i].data_offset = UINT64_C(0x2000);
        entries[i].data_size = UINT64_C(0x3000);
        entries[i].flags = flags;
        metas[i].base_addr = UINT64_C(0x200000000);
        metas[i].vaddr_hi = UINT64_C(0x4000);
        metas[i].phdr_off = sizeof(Elf64_Ehdr);
        metas[i].phdr_num = 3;
        metas[i].phdr_entsz = sizeof(Elf64_Phdr);
        metas[i].flags = flags;
    }

    if (packed_build_alias_owners(entries, metas, ALIAS_COUNT,
                                  source_aliases, startup_aliases) < 0 ||
        source_aliases[0] != -1 ||
        startup_aliases[first_ordinary] != -1)
        goto out;
    metas[first_ordinary - 1].flags |= DLFRZ_FLAG_DLOPEN_EARLY;
    if (packed_canonicalize_alias_metadata(
            metas, ALIAS_COUNT, source_aliases) < 0 ||
        (metas[0].flags & DLFRZ_FLAG_DLOPEN_EARLY) ||
        !(metas[1].flags & DLFRZ_FLAG_DLOPEN_EARLY))
        goto out;
    for (int i = 1; i < ALIAS_COUNT; i++) {
        if (source_aliases[i] != 0)
            goto out;
        if (i < first_ordinary) {
            if (startup_aliases[i] != -1 ||
                !(metas[i].flags & DLFRZ_FLAG_DLOPEN_EARLY))
                goto out;
        } else if (i > first_ordinary &&
                   startup_aliases[i] != first_ordinary) {
            goto out;
        } else if (metas[i].flags & DLFRZ_FLAG_DLOPEN_EARLY) {
            goto out;
        }
        if (!packed_alias_geometry_matches(&metas[0], &metas[i]))
            goto out;
    }

    metas[ALIAS_COUNT - 1].base_addr += 4096;
    if (packed_canonicalize_alias_metadata(
            metas, ALIAS_COUNT, source_aliases) == 0)
        goto out;
    metas[ALIAS_COUNT - 1].base_addr = metas[0].base_addr;

    metas[first_ordinary].flags |= DLFRZ_FLAG_PRELINKED |
                                    DLFRZ_FLAG_RUNTIME_SCAN;
    metas[first_ordinary].runtime_fixup_count = 1;
    if (packed_canonicalize_alias_metadata(
            metas, ALIAS_COUNT, source_aliases) == 0)
        goto out;
    metas[first_ordinary].flags = DLFRZ_FLAG_SHLIB;
    metas[first_ordinary].runtime_fixup_count = 0;

    /* MAIN is never an immutable-source alias role.  Removing INTERP from
     * this group makes the first SHLIB its own geometry owner. */
    entries[0].flags = DLFRZ_FLAG_MAIN_EXE;
    metas[0].flags = DLFRZ_FLAG_MAIN_EXE;
    if (packed_build_alias_owners(entries, metas, ALIAS_COUNT,
                                  source_aliases, startup_aliases) < 0 ||
        source_aliases[0] != -1 || source_aliases[1] != -1 ||
        source_aliases[2] != 1)
        goto out;
    result = 0;

out:
    packed_dep_source_plan_free(&source_plan);
    free(startup_aliases);
    free(source_aliases);
    free(metas);
    free(entries);
    free(libs);
    return result;
}
