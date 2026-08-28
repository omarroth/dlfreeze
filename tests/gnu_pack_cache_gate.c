/* Exercise the pack-time GNU cache parser against synthetic legacy,
 * compatibility, and version-1.1 images.  Including the resolver keeps its
 * production parser private while this gate covers malformed/miss states. */
#include "../src/dep_resolver.c"

static uint32_t append_string(uint8_t *image, size_t image_size,
                              size_t *cursor, const char *value)
{
    size_t length = strlen(value) + 1;
    uint32_t offset;

    if (*cursor > UINT32_MAX || length > image_size - *cursor)
        return 0;
    offset = (uint32_t)*cursor;
    memcpy(image + *cursor, value, length);
    *cursor += length;
    return offset;
}

static uint32_t append_old_string(uint8_t *image, size_t image_size,
                                  size_t strings_start, size_t *cursor,
                                  const char *value)
{
    uint32_t absolute = append_string(image, image_size, cursor, value);

    if (absolute < strings_start)
        return UINT32_MAX;
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

static int replace_file(int fd, const void *buffer, size_t size)
{
    if (ftruncate(fd, 0) < 0 || lseek(fd, 0, SEEK_SET) < 0 ||
        write_exact(fd, buffer, size) < 0 || fsync(fd) < 0)
        return -1;
    return 0;
}

static size_t make_valid_cache(uint8_t *image, size_t image_size,
                               uint32_t required_id)
{
    static const char soname[] = "libdlfreeze_pack_cache_gate.so.1";
    struct gnu_cache_header *header = (void *)image;
    struct gnu_cache_entry *entries =
        (void *)(image + sizeof(*header));
    size_t strings_start = sizeof(*header) + 3 * sizeof(*entries);
    size_t cursor = strings_start;
    uint32_t key;

    if (strings_start >= image_size)
        return 0;
    memset(image, 0, image_size);
    memcpy(header->magic, "glibc-ld.so.cache", sizeof(header->magic));
    memcpy(header->version, "1.1", sizeof(header->version));
    header->nlibs = 3;
    header->flags = 2;

    key = append_string(image, image_size, &cursor, soname);
    entries[0].key = key;
    entries[0].value = append_string(
        image, image_size, &cursor, "/wrong-abi/libdlfreeze.so");
    entries[0].flags = required_id == GNU_CACHE_ID_X86_64
        ? (int32_t)GNU_CACHE_ID_AARCH64
        : (int32_t)GNU_CACHE_ID_X86_64;

    entries[1].key = key;
    entries[1].value = append_string(
        image, image_size, &cursor,
        "/glibc-hwcaps/optimized/libdlfreeze.so");
    entries[1].flags = (int32_t)required_id;
    entries[1].hwcap = UINT64_C(1) << 62;

    entries[2].key = key;
    entries[2].value = append_string(
        image, image_size, &cursor, "/generic/libdlfreeze.so");
    entries[2].flags = (int32_t)required_id;
    header->len_strings = (uint32_t)(cursor - strings_start);

    cursor = (cursor + 3u) & ~(size_t)3u;
    if (cursor > UINT32_MAX ||
        sizeof(struct gnu_cache_extension) +
            sizeof(struct gnu_cache_extension_section) + 1 >
            image_size - cursor)
        return 0;
    header->extension_offset = (uint32_t)cursor;
    {
        struct gnu_cache_extension *extension = (void *)(image + cursor);
        struct gnu_cache_extension_section *section;

        extension->magic = GNU_CACHE_EXTENSION_MAGIC;
        extension->count = 1;
        cursor += sizeof(*extension);
        section = (void *)(image + cursor);
        section->tag = 0; /* cache_extension_tag_generator */
        cursor += sizeof(*section);
        section->offset = (uint32_t)cursor;
        section->size = 1;
        image[cursor++] = 'x';
    }
    return cursor;
}

static size_t make_compat_cache(uint8_t *image, size_t image_size,
                                uint32_t required_id)
{
    struct gnu_cache_old_header *old_header = (void *)image;
    size_t old_end = sizeof(*old_header) +
        2 * sizeof(struct gnu_cache_old_entry);
    size_t new_offset =
        (old_end + (GNU_CACHE_NEW_ALIGNMENT - 1u)) &
        ~(size_t)(GNU_CACHE_NEW_ALIGNMENT - 1u);
    size_t new_size;

    if (new_offset >= image_size)
        return 0;
    memset(image, 0, image_size);
    memcpy(old_header->magic, GNU_CACHE_OLD_MAGIC,
           sizeof(old_header->magic));
    old_header->nlibs = 2;
    new_size = make_valid_cache(image + new_offset,
                                image_size - new_offset, required_id);
    if (new_size == 0)
        return 0;
    {
        struct gnu_cache_header *new_header =
            (void *)(image + new_offset);
        struct gnu_cache_extension *extension =
            (void *)(image + new_offset + new_header->extension_offset);
        struct gnu_cache_extension_section *sections =
            (void *)(extension + 1);

        new_header->extension_offset += (uint32_t)new_offset;
        for (uint32_t i = 0; i < extension->count; i++)
            sections[i].offset += (uint32_t)new_offset;
    }
    return new_offset + new_size;
}

static size_t make_valid_old_cache(uint8_t *image, size_t image_size,
                                   uint32_t required_id)
{
    static const char soname[] = "libdlfreeze_pack_cache_gate.so.1";
    struct gnu_cache_old_header *header = (void *)image;
    struct gnu_cache_old_entry *entries =
        (void *)(image + sizeof(*header));
    size_t strings_start = sizeof(*header) + 3 * sizeof(*entries);
    size_t cursor = strings_start;
    uint32_t key;

    if (strings_start >= image_size || strings_start > UINT32_MAX)
        return 0;
    memset(image, 0, image_size);
    memcpy(header->magic, GNU_CACHE_OLD_MAGIC, sizeof(header->magic));
    header->nlibs = 3;
    key = append_old_string(image, image_size, strings_start, &cursor,
                            soname);
    if (key == UINT32_MAX)
        return 0;

    entries[0].flags = required_id == GNU_CACHE_ID_X86_64
        ? (int32_t)GNU_CACHE_ID_AARCH64
        : (int32_t)GNU_CACHE_ID_X86_64;
    entries[0].key = key;
    entries[0].value = append_old_string(
        image, image_size, strings_start, &cursor,
        "/wrong-abi/libdlfreeze.so");

    entries[1].flags = (int32_t)required_id;
    entries[1].key = key;
    entries[1].value = append_old_string(
        image, image_size, strings_start, &cursor,
        "/legacy/libdlfreeze.so");

    entries[2].flags = (int32_t)required_id;
    entries[2].key = key;
    entries[2].value = append_old_string(
        image, image_size, strings_start, &cursor,
        "/later/libdlfreeze.so");
    if (entries[0].value == UINT32_MAX ||
        entries[1].value == UINT32_MAX ||
        entries[2].value == UINT32_MAX)
        return 0;
    return cursor;
}

static size_t make_ordered_cache(uint8_t *image, size_t image_size,
                                 uint32_t required_id, int old_format,
                                 int reversed)
{
    static const char newer[] = "libdlfreeze_order.so.10";
    static const char older[] = "libdlfreeze_order.so.9";
    const char *first = reversed ? older : newer;
    const char *second = reversed ? newer : older;
    size_t cursor;

    memset(image, 0, image_size);
    if (old_format) {
        struct gnu_cache_old_header *header = (void *)image;
        struct gnu_cache_old_entry *entries =
            (void *)(image + sizeof(*header));
        size_t strings_start = sizeof(*header) + 2 * sizeof(*entries);

        if (strings_start >= image_size || strings_start > UINT32_MAX)
            return 0;
        memcpy(header->magic, GNU_CACHE_OLD_MAGIC, sizeof(header->magic));
        header->nlibs = 2;
        cursor = strings_start;
        entries[0].flags = (int32_t)required_id;
        entries[0].key = append_old_string(
            image, image_size, strings_start, &cursor, first);
        entries[0].value = append_old_string(
            image, image_size, strings_start, &cursor, "/ordered/first.so");
        entries[1].flags = (int32_t)required_id;
        entries[1].key = append_old_string(
            image, image_size, strings_start, &cursor, second);
        entries[1].value = append_old_string(
            image, image_size, strings_start, &cursor, "/ordered/second.so");
        if (entries[0].key == UINT32_MAX ||
            entries[0].value == UINT32_MAX ||
            entries[1].key == UINT32_MAX ||
            entries[1].value == UINT32_MAX)
            return 0;
        return cursor;
    }
    {
        struct gnu_cache_header *header = (void *)image;
        struct gnu_cache_entry *entries =
            (void *)(image + sizeof(*header));
        size_t strings_start = sizeof(*header) + 2 * sizeof(*entries);

        if (strings_start >= image_size)
            return 0;
        memcpy(header->magic, "glibc-ld.so.cache", sizeof(header->magic));
        memcpy(header->version, "1.1", sizeof(header->version));
        header->nlibs = 2;
        header->flags = 2;
        cursor = strings_start;
        entries[0].flags = (int32_t)required_id;
        entries[0].key = append_string(
            image, image_size, &cursor, first);
        entries[0].value = append_string(
            image, image_size, &cursor, "/ordered/first.so");
        entries[1].flags = (int32_t)required_id;
        entries[1].key = append_string(
            image, image_size, &cursor, second);
        entries[1].value = append_string(
            image, image_size, &cursor, "/ordered/second.so");
        header->len_strings = (uint32_t)(cursor - strings_start);
        return cursor;
    }
}

static size_t make_numeric_equivalent_cache(
    uint8_t *image, size_t image_size, uint32_t required_id)
{
    struct gnu_cache_header *header = (void *)image;
    struct gnu_cache_entry *entries =
        (void *)(image + sizeof(*header));
    size_t strings_start = sizeof(*header) + 2 * sizeof(*entries);
    size_t cursor = strings_start;

    if (strings_start >= image_size)
        return 0;
    memset(image, 0, image_size);
    memcpy(header->magic, "glibc-ld.so.cache", sizeof(header->magic));
    memcpy(header->version, "1.1", sizeof(header->version));
    header->nlibs = 2;
    header->flags = 2;
    entries[0].flags = (int32_t)required_id;
    entries[0].key = append_string(
        image, image_size, &cursor, "libnumeric.so.01");
    entries[0].value = append_string(
        image, image_size, &cursor, "/numeric/leading-zero.so");
    entries[1].flags = (int32_t)required_id;
    entries[1].key = append_string(
        image, image_size, &cursor, "libnumeric.so.1");
    entries[1].value = append_string(
        image, image_size, &cursor, "/numeric/plain.so");
    if (cursor > image_size)
        return 0;
    header->len_strings = (uint32_t)(cursor - strings_start);
    return cursor;
}

static int expect_lookup(const char *cache_path, const char *name,
                         uint32_t required_id, int expected_status,
                         const char *expected_path)
{
    struct dep_list deps = {
        .gnu_cache_path = (char *)cache_path,
    };
    char *path = NULL;
    extern int test_target_glibc_minor;
    int status;
    int matches;

    deps.gnu_release_minor = test_target_glibc_minor;
    status = gnu_cache_lookup_path(&deps, name, required_id, &path);
    matches = status == expected_status &&
        ((expected_path == NULL && path == NULL) ||
         (expected_path && path && strcmp(expected_path, path) == 0));

    gnu_cache_index_free(deps.gnu_cache_index);
    free(deps.gnu_cache_image);
    free(path);
    return matches ? 0 : -1;
}

static int expect_snapshot_lookup(struct dep_list *deps, const char *name,
                                  uint32_t required_id,
                                  int expected_status,
                                  const char *expected_path)
{
    char *path = NULL;
    int status = gnu_cache_lookup_path(deps, name, required_id, &path);
    int matches = status == expected_status &&
        ((expected_path == NULL && path == NULL) ||
         (expected_path && path && strcmp(expected_path, path) == 0));

    free(path);
    return matches ? 0 : -1;
}

int test_target_glibc_minor = 35;

static int repeated_string_cache_gate(uint32_t required_id)
{
    const uint32_t entry_count = UINT32_C(16384);
    const size_t key_size = 2U * 1024U * 1024U;
    size_t strings_start = sizeof(struct gnu_cache_header) +
        (size_t)entry_count * sizeof(struct gnu_cache_entry);
    size_t image_size = strings_start + key_size + 1U + sizeof("/x");
    uint8_t *image = calloc(1, image_size);
    struct dep_list deps = {
        .gnu_cache_path = (char *)"/unused",
        .gnu_cache_image = image,
        .gnu_cache_image_size = image_size,
        .gnu_cache_snapshot_state = GNU_CACHE_SNAPSHOT_READY,
        .gnu_release_minor = 36,
    };
    struct gnu_cache_header *header;
    struct gnu_cache_entry *entries;
    uint32_t key_offset;
    uint32_t value_offset;
    char *path = NULL;
    void *first_index;
    int result = -1;

    if (!image || strings_start > UINT32_MAX ||
        strings_start + key_size + 1U > UINT32_MAX)
        goto out;
    header = (void *)image;
    entries = (void *)(image + sizeof(*header));
    memcpy(header->magic, "glibc-ld.so.cache", sizeof(header->magic));
    memcpy(header->version, "1.1", sizeof(header->version));
    header->nlibs = entry_count;
    header->flags = 2;
    header->len_strings = (uint32_t)(image_size - strings_start);
    key_offset = (uint32_t)strings_start;
    value_offset = key_offset + (uint32_t)key_size + 1U;
    memset(image + key_offset, 'a', key_size);
    memcpy(image + value_offset, "/x", sizeof("/x"));
    for (uint32_t i = 0; i < entry_count; i++) {
        entries[i].flags = (int32_t)required_id;
        entries[i].key = key_offset +
            i * (uint32_t)(key_size / entry_count);
        entries[i].value = value_offset;
    }

    /* Every entry deliberately points at a different overlapping suffix of
     * one multi-megabyte key.  Validation must rank that storage
     * structurally, rather than rescanning successively shorter strings, and
     * later probes must reuse the immutable index. */
    alarm(10);
    if (gnu_cache_lookup_path(&deps, "libmissing.so", required_id, &path) !=
            GNU_CACHE_MISS || path || !deps.gnu_cache_index)
        goto out;
    first_index = deps.gnu_cache_index;
    if (gnu_cache_lookup_path(&deps, "another-miss.so", required_id,
                              &path) != GNU_CACHE_MISS ||
        path || deps.gnu_cache_index != first_index)
        goto out;
    alarm(0);
    result = 0;

out:
    alarm(0);
    free(path);
    gnu_cache_index_free(deps.gnu_cache_index);
    free(deps.gnu_cache_image);
    return result;
}

static int cache_string_proof_gate(void)
{
    static const uint8_t strings[] =
        "2147483647x\0"
        "2147483648x\0"
        "0000000000000000000000000001x\0"
        "unterminated";
    const size_t valid = 0;
    const size_t overflow = sizeof("2147483647x");
    const size_t leading_zero = overflow + sizeof("2147483648x");
    const size_t unterminated = leading_zero +
        sizeof("0000000000000000000000000001x");
    uint8_t *flags = gnu_cache_string_flags(strings, sizeof(strings) - 1U);
    int result = -1;

    if (flags &&
        (flags[valid] & GNU_CACHE_STRING_KEY_VALID) &&
        !(flags[overflow] & GNU_CACHE_STRING_KEY_VALID) &&
        (flags[leading_zero] & GNU_CACHE_STRING_KEY_VALID) &&
        !(flags[unterminated] & GNU_CACHE_STRING_TERMINATED))
        result = 0;
    free(flags);
    return result;
}

static int cache_collation_rank_gate(void)
{
    uint8_t strings[512] = {0};
    size_t cursor = 0;
    size_t offsets[12];
    size_t count = 0;
    size_t *ranks;

#define ADD_RANK_STRING(value) do {                                      \
        offsets[count++] = cursor;                                       \
        memcpy(strings + cursor, (value), sizeof(value));                 \
        cursor += sizeof(value);                                         \
    } while (0)
    ADD_RANK_STRING("liborder.so.10");
    ADD_RANK_STRING("liborder.so.9");
    ADD_RANK_STRING("liborder.so.01x");
    ADD_RANK_STRING("liborder.so.1x");
    ADD_RANK_STRING("/usr/lib/libsuffix.so.2");
    offsets[count] = offsets[count - 1] + sizeof("/usr/lib/") - 1U;
    count++;
    ADD_RANK_STRING("plain");
    ADD_RANK_STRING("plainer");
#undef ADD_RANK_STRING
    offsets[count++] = cursor;
    strings[cursor++] = UINT8_C(0x80);
    strings[cursor++] = 'x';
    strings[cursor++] = '\0';
    offsets[count++] = cursor;
    strings[cursor++] = UINT8_C(0xff);
    strings[cursor++] = 'x';
    strings[cursor++] = '\0';

    ranks = gnu_cache_collation_ranks(strings, cursor);
    if (!ranks)
        return -1;
    for (size_t left = 0; left < count; left++) {
        for (size_t right = 0; right < count; right++) {
            int comparison;
            int ranked;

            if (gnu_cache_key_compare(
                    (const char *)strings + offsets[left],
                    (const char *)strings + offsets[right],
                    &comparison) < 0) {
                free(ranks);
                return -1;
            }
            ranked = ranks[offsets[left]] > ranks[offsets[right]] ? 1 :
                     ranks[offsets[left]] < ranks[offsets[right]] ? -1 : 0;
            comparison = comparison > 0 ? 1 : comparison < 0 ? -1 : 0;
            if (ranked != comparison) {
                free(ranks);
                return -1;
            }
        }
    }
    free(ranks);
    return 0;
}

int main(void)
{
    static const char soname[] = "libdlfreeze_pack_cache_gate.so.1";
    uint8_t image[1024];
    struct gnu_cache_header *header = (void *)image;
    struct gnu_cache_entry *entries =
        (void *)(image + sizeof(*header));
    uint32_t required_id;
    uint32_t parsed_version;
    size_t size;
    char cache_path[] = "/tmp/dlfreeze-pack-cache-gate-XXXXXX";
    int fd;
    int result = 1;
    int comparison;

    {
        struct dep_list renamed = {
            .interp_path = "/tmp/renamed-interpreter",
            .interp_soname = "ld-linux-example.so.2"
        };

        if (!is_interpreter_dependency(
                "ld-linux-example.so.2", &renamed) ||
            !is_interpreter_dependency(
                "/tmp/renamed-interpreter", &renamed) ||
            is_interpreter_dependency(
                "renamed-interpreter", &renamed))
            return 1;
    }

#if defined(__x86_64__)
    required_id = GNU_CACHE_ID_X86_64;
#elif defined(__aarch64__)
    required_id = GNU_CACHE_ID_AARCH64;
#else
    return 77;
#endif

    if (cache_string_proof_gate() < 0 ||
        cache_collation_rank_gate() < 0 ||
        repeated_string_cache_gate(required_id) < 0)
        return 1;

    if (gnu_cache_key_compare("liborder.so.10", "liborder.so.9",
                              &comparison) < 0 || comparison <= 0 ||
        gnu_cache_key_compare("liborder.so.9", "liborder.so.10",
                              &comparison) < 0 || comparison >= 0)
        return 1;

    size = make_valid_cache(image, sizeof(image), required_id);
    fd = mkstemp(cache_path);
    if (size == 0 || fd < 0 || replace_file(fd, image, size) < 0)
        goto out;
    if (expect_lookup(cache_path, soname, required_id, GNU_CACHE_FOUND,
                      "/generic/libdlfreeze.so") < 0 ||
        expect_lookup(cache_path, "libmissing.so", required_id,
                      GNU_CACHE_MISS, NULL) < 0 ||
        expect_lookup("/definitely/missing/dlfreeze-ld.so.cache", soname,
                      required_id, GNU_CACHE_UNREADABLE, NULL) < 0)
        goto out;

    /* The target loader retains its first cache image.  Rewriting the path
     * between two lookups must not change either a hit or a miss, and an
     * initially malformed image remains a cached failure. */
    {
        struct dep_list snapshot = {
            .gnu_cache_path = cache_path,
            .gnu_release_minor = test_target_glibc_minor,
        };

        if (expect_snapshot_lookup(
                &snapshot, soname, required_id, GNU_CACHE_FOUND,
                "/generic/libdlfreeze.so") < 0)
            goto out;
        size = make_ordered_cache(
            image, sizeof(image), required_id, 0, 1);
        if (size == 0 || replace_file(fd, image, size) < 0 ||
            expect_snapshot_lookup(
                &snapshot, soname, required_id, GNU_CACHE_FOUND,
                "/generic/libdlfreeze.so") < 0 ||
            expect_snapshot_lookup(
                &snapshot, "libmissing.so", required_id,
                GNU_CACHE_MISS, NULL) < 0) {
            gnu_cache_index_free(snapshot.gnu_cache_index);
            free(snapshot.gnu_cache_image);
            goto out;
        }
        gnu_cache_index_free(snapshot.gnu_cache_index);
        free(snapshot.gnu_cache_image);
    }
    size = make_ordered_cache(image, sizeof(image), required_id, 0, 1);
    if (size == 0 || replace_file(fd, image, size) < 0)
        goto out;
    {
        struct dep_list malformed = {
            .gnu_cache_path = cache_path,
            .gnu_release_minor = test_target_glibc_minor,
        };

        if (expect_snapshot_lookup(
                &malformed, "libdlfreeze_order.so.9", required_id,
                GNU_CACHE_MALFORMED, NULL) < 0) {
            gnu_cache_index_free(malformed.gnu_cache_index);
            free(malformed.gnu_cache_image);
            goto out;
        }
        size = make_valid_cache(image, sizeof(image), required_id);
        if (size == 0 || replace_file(fd, image, size) < 0 ||
            expect_snapshot_lookup(
                &malformed, soname, required_id,
                GNU_CACHE_MALFORMED, NULL) < 0) {
            gnu_cache_index_free(malformed.gnu_cache_index);
            free(malformed.gnu_cache_image);
            goto out;
        }
        gnu_cache_index_free(malformed.gnu_cache_index);
        free(malformed.gnu_cache_image);
    }

    size = make_ordered_cache(
        image, sizeof(image), required_id, 0, 0);
    if (size == 0 || replace_file(fd, image, size) < 0 ||
        expect_lookup(cache_path, "libdlfreeze_order.so.9", required_id,
                      GNU_CACHE_FOUND, "/ordered/second.so") < 0)
        goto out;
    size = make_ordered_cache(
        image, sizeof(image), required_id, 0, 1);
    if (size == 0 || replace_file(fd, image, size) < 0 ||
        expect_lookup(cache_path, "libdlfreeze_order.so.9", required_id,
                      GNU_CACHE_MALFORMED, NULL) < 0)
        goto out;
    size = make_ordered_cache(
        image, sizeof(image), required_id, 1, 0);
    if (size == 0 || replace_file(fd, image, size) < 0 ||
        expect_lookup(cache_path, "libdlfreeze_order.so.9", required_id,
                      GNU_CACHE_FOUND, "/ordered/second.so") < 0)
        goto out;
    size = make_ordered_cache(
        image, sizeof(image), required_id, 1, 1);
    if (size == 0 || replace_file(fd, image, size) < 0 ||
        expect_lookup(cache_path, "libdlfreeze_order.so.9", required_id,
                      GNU_CACHE_MALFORMED, NULL) < 0)
        goto out;

    /* Numeric-equivalent cache keys share one _dl_cache_libcmp rank, while
     * lookup still requires the exact requested soname inside that group. */
    size = make_numeric_equivalent_cache(
        image, sizeof(image), required_id);
    if (size == 0 || replace_file(fd, image, size) < 0 ||
        expect_lookup(cache_path, "libnumeric.so.01", required_id,
                      GNU_CACHE_FOUND, "/numeric/leading-zero.so") < 0 ||
        expect_lookup(cache_path, "libnumeric.so.1", required_id,
                      GNU_CACHE_FOUND, "/numeric/plain.so") < 0)
        goto out;

    size = make_valid_cache(image, sizeof(image), required_id);
    header = (void *)image;
    entries = (void *)(image + sizeof(*header));

    header->flags = UINT8_C(0x82);
    if (replace_file(fd, image, size) < 0 ||
        expect_lookup(cache_path, soname, required_id, GNU_CACHE_FOUND,
                      "/generic/libdlfreeze.so") < 0)
        goto out;
    header->flags = UINT8_C(0x80);
    if (replace_file(fd, image, size) < 0 ||
        expect_lookup(cache_path, soname, required_id, GNU_CACHE_MALFORMED,
                      NULL) < 0)
        goto out;
    header->flags = 2;

    if (gnu_kernel_release_version("6.18.46-1-lts",
                                   &parsed_version) < 0 ||
        parsed_version != UINT32_C(0x06122e) ||
        gnu_kernel_release_version("3.2.0", &parsed_version) < 0 ||
        parsed_version != UINT32_C(0x030200) ||
        gnu_kernel_release_version("256.1.1", &parsed_version) == 0 ||
        gnu_kernel_release_version("not-a-release", &parsed_version) == 0)
        goto out;

    entries[2].osversion = 1;
    if (replace_file(fd, image, size) < 0 ||
        expect_lookup(cache_path, soname, required_id, GNU_CACHE_FOUND,
                      "/generic/libdlfreeze.so") < 0)
        goto out;
    entries[2].osversion = UINT32_MAX;
    if (replace_file(fd, image, size) < 0 ||
        expect_lookup(cache_path, soname, required_id,
                      GNU_CACHE_MISS, NULL) < 0)
        goto out;
    test_target_glibc_minor = 36;
    if (expect_lookup(cache_path, soname, required_id, GNU_CACHE_FOUND,
                      "/generic/libdlfreeze.so") < 0)
        goto out;
    test_target_glibc_minor = 35;
    size = make_valid_cache(image, sizeof(image), required_id);

    size = make_compat_cache(image, sizeof(image), required_id);
    if (size == 0 || replace_file(fd, image, size) < 0 ||
        expect_lookup(cache_path, soname, required_id, GNU_CACHE_FOUND,
                      "/generic/libdlfreeze.so") < 0)
        goto out;
    {
        const struct gnu_cache_old_header *old_header = (const void *)image;
        size_t old_end = sizeof(*old_header) +
            (size_t)old_header->nlibs * sizeof(struct gnu_cache_old_entry);
        size_t new_offset =
            (old_end + (GNU_CACHE_NEW_ALIGNMENT - 1u)) &
            ~(size_t)(GNU_CACHE_NEW_ALIGNMENT - 1u);
        struct gnu_cache_header *new_header =
            (void *)(image + new_offset);

        /* extension_offset is absolute from the file start, unlike cache
         * strings.  Treating it as relative to the embedded header must not
         * accidentally parse the compatibility image. */
        new_header->extension_offset -= (uint32_t)new_offset;
        if (replace_file(fd, image, size) < 0 ||
            expect_lookup(cache_path, soname, required_id,
                          GNU_CACHE_MALFORMED, NULL) < 0)
            goto out;
    }
    size = make_valid_old_cache(image, sizeof(image), required_id);
    if (size == 0 || replace_file(fd, image, size) < 0 ||
        expect_lookup(cache_path, soname, required_id, GNU_CACHE_FOUND,
                      "/legacy/libdlfreeze.so") < 0 ||
        expect_lookup(cache_path, "libmissing.so", required_id,
                      GNU_CACHE_MISS, NULL) < 0)
        goto out;

    /* Every old-format string is bounded, even in an unrelated ABI entry. */
    {
        struct gnu_cache_old_entry *old_entries =
            (void *)(image + sizeof(struct gnu_cache_old_header));
        uint32_t saved = old_entries[0].key;

        old_entries[0].key = UINT32_MAX;
        if (replace_file(fd, image, size) < 0 ||
            expect_lookup(cache_path, soname, required_id,
                          GNU_CACHE_MALFORMED, NULL) < 0)
            goto out;
        old_entries[0].key = saved;
        old_entries[1].value = (uint32_t)(size -
            (sizeof(struct gnu_cache_old_header) +
             3 * sizeof(struct gnu_cache_old_entry)));
        if (replace_file(fd, image, size) < 0 ||
            expect_lookup(cache_path, soname, required_id,
                          GNU_CACHE_MALFORMED, NULL) < 0)
            goto out;
    }

    /* A minimal zero-entry legacy cache is a valid miss, not a truncated
     * version-1.1 header. */
    memset(image, 0, sizeof(image));
    {
        struct gnu_cache_old_header *old_header = (void *)image;

        memcpy(old_header->magic, GNU_CACHE_OLD_MAGIC,
               sizeof(old_header->magic));
        if (replace_file(fd, image, sizeof(*old_header)) < 0 ||
            expect_lookup(cache_path, soname, required_id,
                          GNU_CACHE_MISS, NULL) < 0)
            goto out;
    }

    size = make_valid_cache(image, sizeof(image), required_id);

    /* An invalid string in an unrelated record invalidates the bounded
     * cache, instead of allowing scan order to hide corruption. */
    entries[0].key = 1;
    if (replace_file(fd, image, size) < 0 ||
        expect_lookup(cache_path, soname, required_id,
                      GNU_CACHE_MALFORMED, NULL) < 0)
        goto out;
    size = make_valid_cache(image, sizeof(image), required_id);

    /* Numeric cache collation is defined only through INT_MAX.  A shared
     * key cannot bypass that proof merely because adjacent entries reuse the
     * same offset. */
    memcpy(image + entries[0].key, "libx.so.2147483648",
           sizeof("libx.so.2147483648"));
    if (replace_file(fd, image, size) < 0 ||
        expect_lookup(cache_path, soname, required_id,
                      GNU_CACHE_MALFORMED, NULL) < 0)
        goto out;
    size = make_valid_cache(image, sizeof(image), required_id);

    memcpy(header->magic, "ld.so-1.7.0", sizeof("ld.so-1.7.0") - 1);
    if (replace_file(fd, image, size) < 0 ||
        expect_lookup(cache_path, soname, required_id,
                      GNU_CACHE_MALFORMED, NULL) < 0)
        goto out;
    size = make_valid_cache(image, sizeof(image), required_id);

    header->nlibs = UINT32_MAX;
    if (replace_file(fd, image, size) < 0 ||
        expect_lookup(cache_path, soname, required_id,
                      GNU_CACHE_MALFORMED, NULL) < 0)
        goto out;
    size = make_valid_cache(image, sizeof(image), required_id);

    header->flags = 1; /* explicitly wrong endian */
    if (replace_file(fd, image, size) < 0 ||
        expect_lookup(cache_path, soname, required_id,
                      GNU_CACHE_MALFORMED, NULL) < 0)
        goto out;
    size = make_valid_cache(image, sizeof(image), required_id);

    header->extension_offset = (uint32_t)((size + 3u) & ~(size_t)3u);
    if (replace_file(fd, image, size) < 0 ||
        expect_lookup(cache_path, soname, required_id,
                      GNU_CACHE_MALFORMED, NULL) < 0)
        goto out;
    size = make_valid_cache(image, sizeof(image), required_id);

    /* A selected relative pathname is not a GNU system-cache result. */
    memcpy(image + entries[2].value, "relative/libdlfreeze.so",
           sizeof("relative/libdlfreeze.so"));
    if (replace_file(fd, image, size) < 0 ||
        expect_lookup(cache_path, soname, required_id,
                      GNU_CACHE_MALFORMED, NULL) < 0)
        goto out;

    result = 0;

out:
    if (fd >= 0)
        close(fd);
    unlink(cache_path);
    return result;
}
