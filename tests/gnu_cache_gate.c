/* Exercise the direct loader's private GNU cache parser against a synthetic
 * version-1.1 cache.  Dead-section elimination discards the rest of the
 * loader when this helper is linked. */
#define DLFREEZE_GNU_CACHE_GATE 1
#include "../src/loader.c"

static int gate_cached_cache_lookup(const char *path, const char *needed,
                                    char candidate[PATH_MAX])
{
    return dl_gnu_cache_lookup_path(path, needed, candidate);
}

static int gate_fresh_cache_lookup(const char *path, const char *needed,
                                   char candidate[PATH_MAX])
{
    dl_gnu_cache_snapshot_reset();
    return gate_cached_cache_lookup(path, needed, candidate);
}

/* Most cases below intentionally construct independent cache images. */
#define dl_gnu_cache_lookup_path gate_fresh_cache_lookup

static uint32_t append_string(uint8_t *image, size_t *cursor,
                              const char *value)
{
    uint32_t offset = (uint32_t)*cursor;
    size_t length = strlen(value) + 1;

    memcpy(image + *cursor, value, length);
    *cursor += length;
    return offset;
}

static uint32_t append_old_string(uint8_t *image, size_t strings_start,
                                  size_t *cursor, const char *value)
{
    uint32_t absolute = append_string(image, cursor, value);

    return absolute - (uint32_t)strings_start;
}

static int write_exact(int fd, const void *buffer, size_t size)
{
    const uint8_t *cursor = buffer;

    while (size != 0) {
        ssize_t written = write(fd, cursor, size);

        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return -1;
        cursor += written;
        size -= (size_t)written;
    }
    return 0;
}

static int replace_path(const char *path, const void *buffer, size_t size)
{
    int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
    int result;

    if (fd < 0)
        return -1;
    result = write_exact(fd, buffer, size);
    if (close(fd) < 0)
        result = -1;
    return result;
}

static int cache_gate_temp_template(char path[PATH_MAX], const char *name)
{
    const char *tmpdir = getenv("TMPDIR");
    int length;

    if (!tmpdir || tmpdir[0] != '/')
        tmpdir = "/tmp";
    length = snprintf(path, PATH_MAX, "%s%s%s.XXXXXX", tmpdir,
                      tmpdir[strlen(tmpdir) - 1] == '/' ? "" : "/",
                      name);
    return length > 0 && length < PATH_MAX;
}

static size_t make_tunables_cache(
    uint8_t *image, size_t image_size, int compatibility,
    int with_extension, const uint32_t *tags, uint32_t count)
{
    struct dl_gnu_cache_old_header *old_header;
    struct dl_gnu_cache_header *header;
    struct dl_gnu_cache_extension *extension;
    struct dl_gnu_cache_extension_section *sections;
    size_t cache_base = compatibility
        ? sizeof(struct dl_gnu_cache_old_header) : 0;
    size_t extension_offset;
    size_t directory_end;
    size_t cursor;

    if (!image || cache_base > image_size ||
        sizeof(*header) > image_size - cache_base)
        return 0;
    memset(image, 0, image_size);
    if (compatibility) {
        old_header = (void *)image;
        memcpy(old_header->magic, DL_GNU_CACHE_OLD_MAGIC,
               sizeof(old_header->magic));
        old_header->nlibs = 0;
    }
    header = (void *)(image + cache_base);
    memcpy(header->magic, "glibc-ld.so.cache", sizeof(header->magic));
    memcpy(header->version, "1.1", sizeof(header->version));
    header->flags = 2;
    if (!with_extension)
        return cache_base + sizeof(*header);

    extension_offset = cache_base + sizeof(*header);
    if (extension_offset > UINT32_MAX ||
        sizeof(*extension) > image_size - extension_offset ||
        (size_t)count >
            (image_size - extension_offset - sizeof(*extension)) /
                sizeof(*sections))
        return 0;
    header->extension_offset = (uint32_t)extension_offset;
    extension = (void *)(image + extension_offset);
    extension->magic = DL_GNU_CACHE_EXTENSION_MAGIC;
    extension->count = count;
    sections = (void *)(extension + 1);
    directory_end = extension_offset + sizeof(*extension) +
        (size_t)count * sizeof(*sections);
    cursor = directory_end;

    for (uint32_t i = 0; i < count; i++) {
        uint32_t tag = tags ? tags[i] : 0;

        sections[i].tag = tag;
        if (tag == 2) {
            cursor = (cursor + 7u) & ~(size_t)7u;
            if (cursor > UINT32_MAX || sizeof(uint64_t) > image_size - cursor)
                return 0;
            sections[i].offset = (uint32_t)cursor;
            sections[i].size = sizeof(uint64_t);
            cursor += sizeof(uint64_t);
        } else if (tag == 1) {
            cursor = (cursor + 3u) & ~(size_t)3u;
            if (cursor > UINT32_MAX || sizeof(uint32_t) > image_size - cursor)
                return 0;
            sections[i].offset = (uint32_t)cursor;
            sections[i].size = sizeof(uint32_t);
            cursor += sizeof(uint32_t);
        }
    }
    return cursor;
}

static int tunables_state_without_snapshot(const char *path, int expected)
{
    size_t snapshot_attempts = g_dl_gnu_cache_full_snapshot_attempts;
    int result;

    dl_gnu_cache_snapshot_reset();
    result = dl_gnu_cache_target_tunables_state(path);
    return result == expected &&
           g_dl_gnu_cache_full_snapshot_attempts == snapshot_attempts &&
           g_glibc_cache_snapshot_state ==
               DL_GNU_CACHE_SNAPSHOT_UNINITIALIZED &&
           g_glibc_cache_image == NULL &&
           g_glibc_cache_image_size == 0;
}

static int tunables_inspection_gate(void)
{
    _Alignas(8) uint8_t image[8192];
    static const uint32_t unknown_tag[] = {0};
    static const uint32_t tunables_tag[] = {2};
    static const uint32_t duplicate_tunables[] = {2, 2};
    static const uint32_t duplicate_hwcaps[] = {1, 1};
    struct dl_gnu_cache_old_header *old_header = (void *)image;
    struct dl_gnu_cache_header *header = (void *)image;
    struct dl_gnu_cache_extension *extension;
    struct dl_gnu_cache_extension_section *sections;
    char path[PATH_MAX];
    char candidate[PATH_MAX];
    size_t size;
    int fd;

    if (!cache_gate_temp_template(path, "dlfreeze-gnu-tunables-gate"))
        return 101;
    fd = mkstemp(path);
    if (fd < 0)
        return 102;
    if (close(fd) < 0) {
        unlink(path);
        return 103;
    }

    /* A direct new-format cache with no extension must require only two
     * bounded header passes and leave the complete snapshot untouched. */
    size = make_tunables_cache(
        image, sizeof(image), 0, 0, NULL, 0);
    g_dl_gnu_cache_tunables_pread_calls = 0;
    g_dl_gnu_cache_tunables_pread_bytes = 0;
    g_dl_gnu_cache_tunables_inspections = 0;
    g_dl_gnu_cache_full_snapshot_attempts = 0;
    if (size == 0 || replace_path(path, image, size) < 0 ||
        !tunables_state_without_snapshot(path, 0) ||
        g_dl_gnu_cache_tunables_inspections != 1 ||
        g_dl_gnu_cache_tunables_pread_calls != 4 ||
        g_dl_gnu_cache_tunables_pread_bytes !=
            2 * ((sizeof("glibc-ld.so.cache") - 1) +
                 (sizeof("1.1") - 1) +
                 sizeof(struct dl_gnu_cache_header))) {
        unlink(path);
        return 104;
    }

    /* The first real lookup still takes exactly one immutable full snapshot;
     * tunables-only inspection must neither initialize nor poison it. */
    g_glibc_minor = 36;
    if (gate_cached_cache_lookup(path, "libmissing.so", candidate) != 0 ||
        g_dl_gnu_cache_full_snapshot_attempts != 1 ||
        g_glibc_cache_snapshot_state != DL_GNU_CACHE_SNAPSHOT_READY ||
        !g_glibc_cache_image || g_glibc_cache_image_size != size) {
        unlink(path);
        return 105;
    }
    dl_gnu_cache_snapshot_reset();

    size = make_tunables_cache(
        image, sizeof(image), 0, 1, unknown_tag, 1);
    g_dl_gnu_cache_tunables_pread_calls = 0;
    g_dl_gnu_cache_tunables_pread_bytes = 0;
    if (size == 0 || replace_path(path, image, size) < 0 ||
        !tunables_state_without_snapshot(path, 0) ||
        g_dl_gnu_cache_tunables_pread_calls != 8 ||
        g_dl_gnu_cache_tunables_pread_bytes !=
            2 * ((sizeof("glibc-ld.so.cache") - 1) +
                 (sizeof("1.1") - 1) +
                 sizeof(struct dl_gnu_cache_header) +
                 sizeof(struct dl_gnu_cache_extension) +
                 sizeof(struct dl_gnu_cache_extension_section))) {
        unlink(path);
        return 106;
    }

    size = make_tunables_cache(
        image, sizeof(image), 0, 1, tunables_tag, 1);
    if (size == 0 || replace_path(path, image, size) < 0 ||
        !tunables_state_without_snapshot(path, 1)) {
        unlink(path);
        return 107;
    }

    /* If the cache changes after startup inspection, the lazy immutable
     * snapshot must independently reject a newly introduced tunables tag. */
    size = make_tunables_cache(
        image, sizeof(image), 0, 0, NULL, 0);
    if (size == 0 || replace_path(path, image, size) < 0 ||
        !tunables_state_without_snapshot(path, 0)) {
        unlink(path);
        return 125;
    }
    size = make_tunables_cache(
        image, sizeof(image), 0, 1, tunables_tag, 1);
    if (size == 0 || replace_path(path, image, size) < 0 ||
        gate_cached_cache_lookup(path, "libmissing.so", candidate) != -1 ||
        g_glibc_cache_snapshot_state != DL_GNU_CACHE_SNAPSHOT_MALFORMED) {
        unlink(path);
        return 126;
    }
    dl_gnu_cache_snapshot_reset();

    size = make_tunables_cache(
        image, sizeof(image), 0, 1, duplicate_tunables, 2);
    if (size == 0 || replace_path(path, image, size) < 0 ||
        !tunables_state_without_snapshot(path, -1)) {
        unlink(path);
        return 108;
    }
    size = make_tunables_cache(
        image, sizeof(image), 0, 1, duplicate_hwcaps, 2);
    if (size == 0 || replace_path(path, image, size) < 0 ||
        !tunables_state_without_snapshot(path, -1)) {
        unlink(path);
        return 109;
    }

    size = make_tunables_cache(
        image, sizeof(image), 0, 1, unknown_tag, 1);
    header = (void *)image;
    extension = (void *)(image + header->extension_offset);
    sections = (void *)(extension + 1);
    sections[0].offset = (uint32_t)size + 1u;
    sections[0].size = 1;
    if (replace_path(path, image, size) < 0 ||
        !tunables_state_without_snapshot(path, -1)) {
        unlink(path);
        return 110;
    }

    size = make_tunables_cache(
        image, sizeof(image), 0, 1, unknown_tag, 1);
    header = (void *)image;
    extension = (void *)(image + header->extension_offset);
    if (replace_path(
            path, image,
            header->extension_offset + sizeof(*extension) +
                sizeof(*sections) - 1) < 0 ||
        !tunables_state_without_snapshot(path, -1)) {
        unlink(path);
        return 111;
    }

    size = make_tunables_cache(
        image, sizeof(image), 0, 1, NULL,
        DL_GNU_CACHE_TUNABLE_SECTION_LIMIT + 1u);
    if (size == 0 || replace_path(path, image, size) < 0 ||
        !tunables_state_without_snapshot(path, -1)) {
        unlink(path);
        return 112;
    }

    size = make_tunables_cache(
        image, sizeof(image), 0, 0, NULL, 0);
    header = (void *)image;
    header->nlibs = 1;
    if (replace_path(path, image, size) < 0 ||
        !tunables_state_without_snapshot(path, -1)) {
        unlink(path);
        return 113;
    }

    memset(image, 0, sizeof(image));
    memcpy(old_header->magic, DL_GNU_CACHE_OLD_MAGIC,
           sizeof(old_header->magic));
    old_header->nlibs = 0;
    if (replace_path(path, image, sizeof(*old_header)) < 0 ||
        !tunables_state_without_snapshot(path, 0)) {
        unlink(path);
        return 114;
    }
    old_header->nlibs = 1;
    if (replace_path(path, image, sizeof(*old_header)) < 0 ||
        !tunables_state_without_snapshot(path, -1)) {
        unlink(path);
        return 115;
    }

    size = make_tunables_cache(
        image, sizeof(image), 1, 0, NULL, 0);
    if (size == 0 || replace_path(path, image, size) < 0 ||
        !tunables_state_without_snapshot(path, 0)) {
        unlink(path);
        return 116;
    }
    if (replace_path(
            path, image,
            sizeof(struct dl_gnu_cache_old_header) +
                (sizeof("glibc-ld.so.cache") - 1) +
                (sizeof("1.1") - 1)) < 0 ||
        !tunables_state_without_snapshot(path, -1)) {
        unlink(path);
        return 117;
    }
    size = make_tunables_cache(
        image, sizeof(image), 1, 1, tunables_tag, 1);
    if (size == 0 || replace_path(path, image, size) < 0 ||
        !tunables_state_without_snapshot(path, 1)) {
        unlink(path);
        return 118;
    }

    g_dl_gnu_cache_tunables_forced_open_errno = ENOENT;
    if (!tunables_state_without_snapshot(path, 0)) {
        unlink(path);
        return 119;
    }
    g_dl_gnu_cache_tunables_forced_open_errno = ENOTDIR;
    if (!tunables_state_without_snapshot(path, 0)) {
        unlink(path);
        return 120;
    }
    g_dl_gnu_cache_tunables_forced_open_errno = EACCES;
    if (!tunables_state_without_snapshot(path, -1)) {
        unlink(path);
        return 121;
    }
    g_dl_gnu_cache_tunables_forced_open_errno = EIO;
    if (!tunables_state_without_snapshot(path, -1)) {
        unlink(path);
        return 122;
    }
    g_dl_gnu_cache_tunables_forced_open_errno = 0;
    if (!tunables_state_without_snapshot("/", -1)) {
        unlink(path);
        return 123;
    }
    if (unlink(path) < 0 ||
        !tunables_state_without_snapshot(path, 0))
        return 124;
    g_glibc_minor = 36;
    if (gate_cached_cache_lookup(
            path, "libmissing.so", candidate) != -1 ||
        g_glibc_cache_snapshot_state !=
            DL_GNU_CACHE_SNAPSHOT_UNREADABLE)
        return 127;
    dl_gnu_cache_snapshot_reset();
    return 0;
}

static size_t make_ordered_cache(uint8_t *image, size_t image_size,
                                 int old_format, int reversed)
{
    static const char newer[] = "libdlfreeze_order.so.10";
    static const char older[] = "libdlfreeze_order.so.9";
    const char *first = reversed ? older : newer;
    const char *second = reversed ? newer : older;
    size_t cursor;

    memset(image, 0, image_size);
    if (old_format) {
        struct dl_gnu_cache_old_header *header = (void *)image;
        struct dl_gnu_cache_old_entry *entries =
            (void *)(image + sizeof(*header));
        size_t strings_start = sizeof(*header) + 2 * sizeof(*entries);

        if (strings_start >= image_size)
            return 0;
        memcpy(header->magic, DL_GNU_CACHE_OLD_MAGIC,
               sizeof(header->magic));
        header->nlibs = 2;
        cursor = strings_start;
        entries[0].flags = (int32_t)DL_GNU_CACHE_DEFAULT_ID;
        entries[0].key = append_old_string(
            image, strings_start, &cursor, first);
        entries[0].value = append_old_string(
            image, strings_start, &cursor, "/ordered/first.so");
        entries[1].flags = (int32_t)DL_GNU_CACHE_DEFAULT_ID;
        entries[1].key = append_old_string(
            image, strings_start, &cursor, second);
        entries[1].value = append_old_string(
            image, strings_start, &cursor, "/ordered/second.so");
        return cursor <= image_size ? cursor : 0;
    }
    {
        struct dl_gnu_cache_header *header = (void *)image;
        struct dl_gnu_cache_entry *entries =
            (void *)(image + sizeof(*header));
        size_t strings_start = sizeof(*header) + 2 * sizeof(*entries);

        if (strings_start >= image_size)
            return 0;
        memcpy(header->magic, "glibc-ld.so.cache", sizeof(header->magic));
        memcpy(header->version, "1.1", sizeof(header->version));
        header->nlibs = 2;
        header->flags = 2;
        cursor = strings_start;
        entries[0].flags = (int32_t)DL_GNU_CACHE_DEFAULT_ID;
        entries[0].key = append_string(image, &cursor, first);
        entries[0].value = append_string(
            image, &cursor, "/ordered/first.so");
        entries[1].flags = (int32_t)DL_GNU_CACHE_DEFAULT_ID;
        entries[1].key = append_string(image, &cursor, second);
        entries[1].value = append_string(
            image, &cursor, "/ordered/second.so");
        if (cursor > image_size)
            return 0;
        header->len_strings = (uint32_t)(cursor - strings_start);
        return cursor;
    }
}

static int synthetic_cache_gate(void)
{
    static const char soname[] = "libdlfreeze_cache_gate.so.1";
    uint8_t image[1024] = {0};
    struct dl_gnu_cache_header *header = (void *)image;
    struct dl_gnu_cache_entry *entries =
        (void *)(image + sizeof(*header));
    struct dl_gnu_cache_extension *extension;
    struct dl_gnu_cache_extension_section *section;
    uint32_t *hwcap_indices;
    size_t strings_start = sizeof(*header) + 2 * sizeof(*entries);
    size_t cursor = strings_start;
    uint32_t key;
    uint32_t v3_path;
    uint32_t generic_path;
    uint32_t v3_name;
    uint32_t parsed_version;
    char path[PATH_MAX];
    char candidate[PATH_MAX];
    int fd;
    int rc;
    int comparison;

    g_glibc_minor = 35;
    if (dl_gnu_cache_key_compare("liborder.so.10", "liborder.so.9",
                                 &comparison) < 0 || comparison <= 0 ||
        dl_gnu_cache_key_compare("liborder.so.9", "liborder.so.10",
                                 &comparison) < 0 || comparison >= 0)
        return 31;

    if (dl_kernel_release_version("6.18.46-1-lts", &parsed_version) < 0 ||
        parsed_version != UINT32_C(0x06122e) ||
        dl_kernel_release_version("3.2.0", &parsed_version) < 0 ||
        parsed_version != UINT32_C(0x030200) ||
        dl_kernel_release_version("256.1.1", &parsed_version) == 0 ||
        dl_kernel_release_version("not-a-release", &parsed_version) == 0)
        return 19;

    memcpy(header->magic, "glibc-ld.so.cache", sizeof(header->magic));
    memcpy(header->version, "1.1", sizeof(header->version));
    header->nlibs = 2;
    header->flags = 2;
    key = append_string(image, &cursor, soname);
    v3_path = append_string(image, &cursor,
                            "/synthetic/glibc-hwcaps/x86-64-v3/"
                            "libdlfreeze_cache_gate.so.1");
    generic_path = append_string(image, &cursor,
                                 "/synthetic/libdlfreeze_cache_gate.so.1");
    v3_name = append_string(image, &cursor, "x86-64-v3");
    header->len_strings = (uint32_t)(cursor - strings_start);

    entries[0].flags = (int32_t)DL_GNU_CACHE_DEFAULT_ID;
    entries[0].key = key;
    entries[0].value = v3_path;
    /* A directory name and an ELF ISA note are independent admission
     * checks.  Keep the entry's ISA level at baseline so the gate proves a
     * baseline CPU still rejects the named v3 directory itself. */
    entries[0].hwcap = DL_GNU_CACHE_HWCAP_EXTENSION;
    entries[1].flags = (int32_t)DL_GNU_CACHE_DEFAULT_ID;
    entries[1].key = key;
    entries[1].value = generic_path;

    cursor = (cursor + 3u) & ~(size_t)3u;
    header->extension_offset = (uint32_t)cursor;
    extension = (void *)(image + cursor);
    extension->magic = DL_GNU_CACHE_EXTENSION_MAGIC;
    extension->count = 1;
    cursor += sizeof(*extension);
    section = (void *)(image + cursor);
    section->tag = 1;
    cursor += sizeof(*section);
    section->offset = (uint32_t)cursor;
    section->size = sizeof(*hwcap_indices);
    hwcap_indices = (void *)(image + cursor);
    hwcap_indices[0] = v3_name;
    cursor += sizeof(*hwcap_indices);

    if (!cache_gate_temp_template(path, "dlfreeze-gnu-cache-gate"))
        return 1;
    fd = mkstemp(path);
    if (fd < 0)
        return 1;
    if (write_exact(fd, image, cursor) < 0 || close(fd) < 0) {
        unlink(path);
        return 2;
    }

#if defined(__x86_64__)
    g_x86_isa_1 = UINT32_C(0x7);
    rc = dl_gnu_cache_lookup_path(path, soname, candidate);
    if (rc != 1 || strcmp(candidate,
                         "/synthetic/glibc-hwcaps/x86-64-v3/"
                         "libdlfreeze_cache_gate.so.1") != 0) {
        unlink(path);
        return 3;
    }
    g_x86_isa_1 = UINT32_C(0x1);
#endif
    rc = dl_gnu_cache_lookup_path(path, soname, candidate);
    if (rc != 1 || strcmp(candidate,
                         "/synthetic/libdlfreeze_cache_gate.so.1") != 0) {
        unlink(path);
        return 4;
    }

    /* glibc <= 2.39 still considers legacy HWCAP/platform records.  Until
     * their private target eligibility is reproduced exactly, a matching
     * nonzero legacy record must make lookup fail closed rather than select
     * the generic DSO.  glibc 2.40+ removed that selection path. */
    entries[0].hwcap = UINT64_C(1);
    if (replace_path(path, image, cursor) < 0) {
        unlink(path);
        return 36;
    }
    g_glibc_minor = 39;
    if (dl_gnu_cache_lookup_path(path, soname, candidate) != -1) {
        unlink(path);
        return 37;
    }
    g_glibc_minor = 40;
    if (dl_gnu_cache_lookup_path(path, soname, candidate) != 1 ||
        strcmp(candidate,
               "/synthetic/libdlfreeze_cache_gate.so.1") != 0) {
        unlink(path);
        return 38;
    }
    entries[0].hwcap = DL_GNU_CACHE_HWCAP_EXTENSION;
    g_glibc_minor = 35;
    if (replace_path(path, image, cursor) < 0) {
        unlink(path);
        return 39;
    }
    header->flags = UINT8_C(0x82);
    fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd < 0 || write_exact(fd, image, cursor) < 0) {
        if (fd >= 0)
            close(fd);
        unlink(path);
        return 15;
    }
    if (close(fd) < 0) {
        unlink(path);
        return 15;
    }
    fd = -1;
    if (dl_gnu_cache_lookup_path(path, soname, candidate) != 1) {
        unlink(path);
        return 16;
    }
    header->flags = UINT8_C(0x80);
    fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd < 0 || write_exact(fd, image, cursor) < 0) {
        if (fd >= 0)
            close(fd);
        unlink(path);
        return 17;
    }
    if (close(fd) < 0) {
        unlink(path);
        return 17;
    }
    fd = -1;
    if (gate_cached_cache_lookup(path, soname, candidate) != 1) {
        unlink(path);
        return 33;
    }
    if (dl_gnu_cache_lookup_path(path, soname, candidate) != -1) {
        unlink(path);
        return 18;
    }
    header->flags = 2;
    entries[0].osversion = 1;
    entries[1].osversion = 1;
    fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd < 0 || write_exact(fd, image, cursor) < 0) {
        if (fd >= 0)
            close(fd);
        unlink(path);
        return 13;
    }
    if (close(fd) < 0) {
        unlink(path);
        return 13;
    }
    fd = -1;
    if (gate_cached_cache_lookup(path, soname, candidate) != -1) {
        unlink(path);
        return 34;
    }
    if (dl_gnu_cache_lookup_path(path, soname, candidate) != 1 ||
        strcmp(candidate, "/synthetic/libdlfreeze_cache_gate.so.1") != 0) {
        unlink(path);
        return 14;
    }
    entries[0].osversion = UINT32_MAX;
    entries[1].osversion = UINT32_MAX;
    fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd < 0 || write_exact(fd, image, cursor) < 0) {
        if (fd >= 0)
            close(fd);
        unlink(path);
        return 20;
    }
    if (close(fd) < 0) {
        unlink(path);
        return 20;
    }
    fd = -1;
    if (dl_gnu_cache_lookup_path(path, soname, candidate) != 0) {
        unlink(path);
        return 21;
    }
    g_glibc_minor = 36;
    if (dl_gnu_cache_lookup_path(path, soname, candidate) != 1 ||
        strcmp(candidate, "/synthetic/libdlfreeze_cache_gate.so.1") != 0) {
        unlink(path);
        return 30;
    }
    g_glibc_minor = 35;
    entries[0].osversion = 0;
    entries[1].osversion = 0;

    /* Older glibc emits a validated old-format prefix followed by the 1.1
     * table at its exact eight-byte-aligned ABI offset.  String offsets stay
     * relative to the 1.1 header; extension offsets remain file-absolute. */
    {
        uint8_t compat[2048] = {0};
        struct dl_gnu_cache_old_header *old_header = (void *)compat;
        struct dl_gnu_cache_header *new_header;
        size_t old_end = sizeof(*old_header) +
            2 * sizeof(struct dl_gnu_cache_old_entry);
        size_t new_offset =
            (old_end + (DL_GNU_CACHE_NEW_ALIGNMENT - 1u)) &
            ~(size_t)(DL_GNU_CACHE_NEW_ALIGNMENT - 1u);

        memcpy(old_header->magic, DL_GNU_CACHE_OLD_MAGIC,
               sizeof(old_header->magic));
        old_header->nlibs = 2;
        memcpy(compat + new_offset, image, cursor);
        new_header = (void *)(compat + new_offset);
        if (new_header->extension_offset != 0) {
            struct dl_gnu_cache_extension *new_extension =
                (void *)(compat + new_offset +
                         new_header->extension_offset);
            struct dl_gnu_cache_extension_section *new_sections =
                (void *)(new_extension + 1);

            new_header->extension_offset += (uint32_t)new_offset;
            for (uint32_t i = 0; i < new_extension->count; i++)
                new_sections[i].offset += (uint32_t)new_offset;
        }
        fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
        if (fd < 0 || write_exact(fd, compat, new_offset + cursor) < 0) {
            if (fd >= 0)
                close(fd);
            unlink(path);
            return 7;
        }
        if (close(fd) < 0) {
            unlink(path);
            return 7;
        }
        fd = -1;
        rc = dl_gnu_cache_lookup_path(path, soname, candidate);
        if (rc != 1 || strcmp(candidate,
                             "/synthetic/libdlfreeze_cache_gate.so.1") != 0) {
            unlink(path);
            return 8;
        }

        new_header->extension_offset -= (uint32_t)new_offset;
        fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
        if (fd < 0 || write_exact(fd, compat, new_offset + cursor) < 0) {
            if (fd >= 0)
                close(fd);
            unlink(path);
            return 11;
        }
        if (close(fd) < 0) {
            unlink(path);
            return 11;
        }
        fd = -1;
        if (dl_gnu_cache_lookup_path(path, soname, candidate) != -1) {
            unlink(path);
            return 12;
        }
        new_header->extension_offset += (uint32_t)new_offset;

        fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
        if (fd < 0 || write_exact(fd, compat, new_offset) < 0) {
            if (fd >= 0)
                close(fd);
            unlink(path);
            return 9;
        }
        if (close(fd) < 0) {
            unlink(path);
            return 9;
        }
        fd = -1;
        if (dl_gnu_cache_lookup_path(path, soname, candidate) != -1) {
            unlink(path);
            return 10;
        }
    }

    /* Old-only caches use string offsets relative to the end of the old
     * entry array.  The first exact-ABI match wins deterministically. */
    {
        uint8_t old_image[1024] = {0};
        struct dl_gnu_cache_old_header *old_header = (void *)old_image;
        struct dl_gnu_cache_old_entry *old_entries =
            (void *)(old_image + sizeof(*old_header));
        size_t old_strings_start = sizeof(*old_header) +
            3 * sizeof(*old_entries);
        size_t old_cursor = old_strings_start;
        size_t old_size;
        uint32_t old_key;
        uint32_t saved_key;
        uint32_t wrong_id = DL_GNU_CACHE_DEFAULT_ID == UINT32_C(0x0303)
            ? UINT32_C(0x0a03) : UINT32_C(0x0303);

        memcpy(old_header->magic, DL_GNU_CACHE_OLD_MAGIC,
               sizeof(old_header->magic));
        old_header->nlibs = 3;
        old_key = append_old_string(old_image, old_strings_start,
                                    &old_cursor, soname);
        old_entries[0].flags = (int32_t)wrong_id;
        old_entries[0].key = old_key;
        old_entries[0].value = append_old_string(
            old_image, old_strings_start, &old_cursor,
            "/wrong-abi/libdlfreeze_cache_gate.so.1");
        old_entries[1].flags = (int32_t)DL_GNU_CACHE_DEFAULT_ID;
        old_entries[1].key = old_key;
        old_entries[1].value = append_old_string(
            old_image, old_strings_start, &old_cursor,
            "/legacy/libdlfreeze_cache_gate.so.1");
        old_entries[2].flags = (int32_t)DL_GNU_CACHE_DEFAULT_ID;
        old_entries[2].key = old_key;
        old_entries[2].value = append_old_string(
            old_image, old_strings_start, &old_cursor,
            "/later/libdlfreeze_cache_gate.so.1");
        old_size = old_cursor;

        fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
        if (fd < 0 || write_exact(fd, old_image, old_size) < 0) {
            if (fd >= 0)
                close(fd);
            unlink(path);
            return 22;
        }
        if (close(fd) < 0) {
            unlink(path);
            return 22;
        }
        fd = -1;
        rc = dl_gnu_cache_lookup_path(path, soname, candidate);
        if (rc != 1 ||
            strcmp(candidate,
                   "/legacy/libdlfreeze_cache_gate.so.1") != 0 ||
            dl_gnu_cache_lookup_path(path, "libmissing.so", candidate) != 0) {
            unlink(path);
            return 23;
        }

        /* An unrelated record cannot hide an out-of-range string offset. */
        saved_key = old_entries[0].key;
        old_entries[0].key = UINT32_MAX;
        fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
        if (fd < 0 || write_exact(fd, old_image, old_size) < 0) {
            if (fd >= 0)
                close(fd);
            unlink(path);
            return 24;
        }
        if (close(fd) < 0) {
            unlink(path);
            return 24;
        }
        fd = -1;
        if (dl_gnu_cache_lookup_path(path, soname, candidate) != -1) {
            unlink(path);
            return 25;
        }
        old_entries[0].key = saved_key;
        old_entries[1].value = (uint32_t)(old_size - old_strings_start);
        fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
        if (fd < 0 || write_exact(fd, old_image, old_size) < 0) {
            if (fd >= 0)
                close(fd);
            unlink(path);
            return 26;
        }
        if (close(fd) < 0) {
            unlink(path);
            return 26;
        }
        fd = -1;
        if (dl_gnu_cache_lookup_path(path, soname, candidate) != -1) {
            unlink(path);
            return 27;
        }

        /* A zero-entry old cache is a validated miss, not a truncated 1.1
         * image. */
        memset(old_image, 0, sizeof(old_image));
        memcpy(old_header->magic, DL_GNU_CACHE_OLD_MAGIC,
               sizeof(old_header->magic));
        fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
        if (fd < 0 || write_exact(fd, old_image, sizeof(*old_header)) < 0) {
            if (fd >= 0)
                close(fd);
            unlink(path);
            return 28;
        }
        if (close(fd) < 0) {
            unlink(path);
            return 28;
        }
        fd = -1;
        if (dl_gnu_cache_lookup_path(path, soname, candidate) != 0) {
            unlink(path);
            return 29;
        }
    }
    {
        size_t ordered_size;

        ordered_size = make_ordered_cache(image, sizeof(image), 0, 0);
        if (ordered_size == 0 ||
            replace_path(path, image, ordered_size) < 0 ||
            dl_gnu_cache_lookup_path(
                path, "libdlfreeze_order.so.9", candidate) != 1 ||
            strcmp(candidate, "/ordered/second.so") != 0) {
            unlink(path);
            return 32;
        }
        ordered_size = make_ordered_cache(image, sizeof(image), 0, 1);
        if (ordered_size == 0 ||
            replace_path(path, image, ordered_size) < 0 ||
            dl_gnu_cache_lookup_path(
                path, "libdlfreeze_order.so.9", candidate) != -1) {
            unlink(path);
            return 33;
        }
        ordered_size = make_ordered_cache(image, sizeof(image), 1, 0);
        if (ordered_size == 0 ||
            replace_path(path, image, ordered_size) < 0 ||
            dl_gnu_cache_lookup_path(
                path, "libdlfreeze_order.so.9", candidate) != 1 ||
            strcmp(candidate, "/ordered/second.so") != 0) {
            unlink(path);
            return 34;
        }
        ordered_size = make_ordered_cache(image, sizeof(image), 1, 1);
        if (ordered_size == 0 ||
            replace_path(path, image, ordered_size) < 0 ||
            dl_gnu_cache_lookup_path(
                path, "libdlfreeze_order.so.9", candidate) != -1) {
            unlink(path);
            return 35;
        }
    }
    if (unlink(path) < 0)
        return 5;
    return 0;
}

int main(int argc, char **argv)
{
    char candidate[PATH_MAX];
    int gate_result;
    int rc;

    gate_result = tunables_inspection_gate();
    if (gate_result != 0)
        return gate_result;
    if (synthetic_cache_gate() != 0)
        return 1;
    if (argc == 1)
        return 0;
    if (argc != 3)
        return 2;
#if defined(__x86_64__)
    /* The host gate runs after normal libc initialization.  Baseline-only is
     * enough to validate a generic entry; production initialization computes
     * the full OS-usable bitmap before target code can call dlopen. */
    g_x86_isa_1 = UINT32_C(0x1);
#endif
    g_glibc_minor = 36;
    rc = dl_gnu_cache_lookup_path(argv[1], argv[2], candidate);
    if (rc != 1)
        return 3;
    puts(candidate);
    return 0;
}
