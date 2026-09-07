#include "dep_resolver.h"
#include "elf_parser.h"
#include "glibc_layout.h"
#include "libc_semantics.h"
#include "dynamic_semantics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/auxv.h>
#include <sys/utsname.h>
#include <libgen.h>

#ifndef DF_1_NODEFLIB
#define DF_1_NODEFLIB 0x00000800
#endif
#ifndef DF_1_PIE
#define DF_1_PIE 0x08000000
#endif

#define DEP_MUSL_SEARCH_BUFFER_SIZE (2U * NAME_MAX + 2U)

_Static_assert(DEP_MUSL_SEARCH_BUFFER_SIZE <= PATH_MAX,
               "musl search buffer exceeds pack resolver buffer");

/* Public callers expose found/miss/error, but retaining the reason internally
 * prevents malformed configuration and allocation failures from becoming an
 * ordinary provider miss. */
enum library_lookup_result {
    LIBRARY_LOOKUP_INCOMPATIBLE = -5,
    LIBRARY_LOOKUP_INTERNAL = -4,
    LIBRARY_LOOKUP_UNSUPPORTED = -3,
    LIBRARY_LOOKUP_MALFORMED = -2,
    LIBRARY_LOOKUP_UNREADABLE = -1,
    LIBRARY_LOOKUP_MISS = 0,
    LIBRARY_LOOKUP_FOUND = 1,
    /* A GNU open_path list stops on an unusual open failure, but the loader
     * continues with its next search mechanism (for example RUNPATH after
     * LD_LIBRARY_PATH). */
    LIBRARY_LOOKUP_NEXT_STAGE = 2,
};

/* Kernel-provided objects that are not ordinary filesystem dependencies. */
static int is_kernel_virtual_lib(const char *name)
{
    /* These are reserved bare DT_NEEDED identities, not forbidden
     * basenames.  A traced slash-containing DSO with the same basename is a
     * normal file-backed ELF object. */
    return name &&
           (strcmp(name, "linux-vdso.so.1") == 0 ||
            strcmp(name, "linux-gate.so.1") == 0);
}

/* Some libc DSOs carry an explicit DT_NEEDED edge back to PT_INTERP.  Compare
 * identities exactly against either its full PT_INTERP path or its parsed
 * DT_SONAME.  The pathname basename is not an ELF identity: an interpreter
 * may be renamed, and an unrelated DSO may legitimately use that basename.
 * Callers skip this edge for separate-loader runtimes.  For musl they retain
 * the edge and bind it to the exact PT_INTERP file, because that object is
 * also libc. */
static int is_interpreter_dependency(const char *name,
                                     const struct dep_list *deps)
{
    if (!name || !name[0] || !deps || !deps->interp_path ||
        !deps->interp_path[0])
        return 0;
    if (strcmp(name, deps->interp_path) == 0)
        return 1;
    return deps->interp_soname && deps->interp_soname[0] &&
           strcmp(name, deps->interp_soname) == 0;
}

static int snapshot_is_interpreter(
    const struct dep_file_snapshot *snapshot,
    const struct dep_list *deps)
{
    /* Native loaders deduplicate an already mapped interpreter by file
     * identity.  A hardlink spelling is therefore the interpreter too even
     * though its canonical pathname differs from PT_INTERP. */
    return snapshot && snapshot->valid && deps &&
           deps->interp_snapshot.valid &&
           snapshot->device == deps->interp_snapshot.device &&
           snapshot->inode == deps->interp_snapshot.inode;
}

static void dep_snapshot_from_stat(struct dep_file_snapshot *snapshot,
                                   const struct stat *st)
{
    if (!snapshot || !st)
        return;
    snapshot->device = st->st_dev;
    snapshot->inode = st->st_ino;
    snapshot->size = st->st_size;
    snapshot->mtime_sec = st->st_mtim.tv_sec;
    snapshot->mtime_nsec = st->st_mtim.tv_nsec;
    snapshot->ctime_sec = st->st_ctim.tv_sec;
    snapshot->ctime_nsec = st->st_ctim.tv_nsec;
    snapshot->valid = 1;
}

static int dep_snapshot_matches_stat(
    const struct dep_file_snapshot *snapshot, const struct stat *st)
{
    return snapshot && snapshot->valid && st &&
           snapshot->device == st->st_dev &&
           snapshot->inode == st->st_ino &&
           snapshot->size == st->st_size &&
           snapshot->mtime_sec == st->st_mtim.tv_sec &&
           snapshot->mtime_nsec == st->st_mtim.tv_nsec &&
           snapshot->ctime_sec == st->st_ctim.tv_sec &&
           snapshot->ctime_nsec == st->st_ctim.tv_nsec;
}

static int dep_stats_match(const struct stat *left,
                           const struct stat *right)
{
    struct dep_file_snapshot snapshot = {0};

    dep_snapshot_from_stat(&snapshot, left);
    return dep_snapshot_matches_stat(&snapshot, right);
}

static int elf_parse_path_snapshot(
    const char *path, const struct dep_file_snapshot *expected,
    struct elf_info *info, struct dep_file_snapshot *snapshot_out)
{
    struct stat before;
    struct stat after;
    int fd;
    int result = -1;

    if (!path || !info || (expected && !expected->valid)) {
        errno = EINVAL;
        return -1;
    }
    memset(info, 0, sizeof(*info));
    if (snapshot_out)
        memset(snapshot_out, 0, sizeof(*snapshot_out));
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (fstat(fd, &before) < 0)
        goto out;
    if (!S_ISREG(before.st_mode) || before.st_size < 0) {
        errno = EINVAL;
        goto out;
    }
    if (expected && !dep_snapshot_matches_stat(expected, &before)) {
        errno = ESTALE;
        goto out;
    }
    if (elf_parse_fd(fd, info) < 0)
        goto out;
    if (fstat(fd, &after) < 0) {
        elf_info_free(info);
        memset(info, 0, sizeof(*info));
        goto out;
    }
    if (!dep_stats_match(&before, &after)) {
        elf_info_free(info);
        memset(info, 0, sizeof(*info));
        errno = ESTALE;
        goto out;
    }
    if (snapshot_out)
        dep_snapshot_from_stat(snapshot_out, &after);
    result = 0;

out:
    {
        int saved_errno = errno;

        close(fd);
        errno = saved_errno;
    }
    return result;
}

static enum dep_runtime_family detect_interpreter_family(
    const char *path, const struct dep_file_snapshot *expected,
    char gnu_cache_path[PATH_MAX],
    int *gnu_release_minor_out)
{
    struct stat st;
    struct stat after;
    unsigned char *image = NULL;
    size_t image_size = 0;
    size_t offset = 0;
    enum dep_runtime_family family = DEP_RUNTIME_UNKNOWN;
    int fd = -1;

    if (gnu_cache_path)
        gnu_cache_path[0] = '\0';
    if (gnu_release_minor_out)
        *gnu_release_minor_out = -1;
    if (!path || !path[0] || !gnu_cache_path || !gnu_release_minor_out ||
        !expected || !expected->valid)
        return DEP_RUNTIME_UNKNOWN;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0 && fstat(fd, &st) == 0 &&
        dep_snapshot_matches_stat(expected, &st) && st.st_size > 0 &&
        (uintmax_t)st.st_size <= SIZE_MAX) {
        image_size = (size_t)st.st_size;
        image = malloc(image_size);
        while (image && offset < image_size) {
            size_t remaining = image_size - offset;
            size_t chunk = remaining > (size_t)SSIZE_MAX
                ? (size_t)SSIZE_MAX : remaining;
            ssize_t got = pread(fd, image + offset, chunk, (off_t)offset);

            if (got > 0) {
                offset += (size_t)got;
                continue;
            }
            if (got < 0 && errno == EINTR)
                continue;
            break;
        }
        /* Decoder inputs must be immutable.  A MAP_PRIVATE view can still
         * SIGBUS when another process truncates the interpreter after the
         * first fstat.  Copy the exact revision first, then admit it only
         * after the descriptor still has the same complete identity. */
        if (image && offset == image_size && fstat(fd, &after) == 0 &&
            dep_stats_match(&st, &after)) {
            int is_musl = dlfrz_musl_rtld_identity(
                image, image_size);
            int is_gnu = dlfrz_glibc_rtld_identity(
                image, image_size, NULL);

            if (is_musl && !is_gnu)
                family = DEP_RUNTIME_MUSL;
            else if (is_gnu && !is_musl &&
                     dlfrz_glibc_elf_config_paths(
                         image, image_size, gnu_cache_path, PATH_MAX,
                         NULL, 0)) {
                int development = 0;
                int minor = -1;

                /* Cache behavior changes by target release.  A development
                 * or unrecognized loader cannot safely inherit the packer's
                 * host policy. */
                if (dlfrz_glibc_elf_release_profile(
                        image, image_size, &minor, &development) &&
                    !development && minor >= 0) {
                    *gnu_release_minor_out = minor;
                    family = DEP_RUNTIME_GNU;
                }
            }
        }
    }

    free(image);
    if (fd >= 0)
        close(fd);
    return family;
}

static int musl_dependency_is_self(const char *name,
                                   const struct dep_list *deps)
{
    return deps->runtime_family == DEP_RUNTIME_MUSL &&
           (is_interpreter_dependency(name, deps) ||
            dlfrz_musl_reserved_soname(name));
}

static int elf_info_matches_target(const struct elf_info *info,
                                   const struct dep_list *deps)
{
    /* A dependency candidate must be ET_DYN and must not declare DF_1_PIE.
     * PT_INTERP is not an executable-only discriminator: glibc's libc.so.6
     * is both a loadable DSO and directly executable, and therefore carries
     * PT_INTERP without DF_1_PIE.  Rejecting that segment would make a valid
     * cache entry depend on how its libc was linked. */
    return info->is_dynamic && info->is_pie &&
           (info->flags_1 & DF_1_PIE) == 0 &&
           info->ei_class == deps->target_ei_class &&
           info->e_machine == deps->target_e_machine;
}

static int candidate_open_miss_errno(int error, int gnu_search)
{
    return error == ENOENT || error == ENOTDIR || error == EACCES ||
           (!gnu_search && error == ENAMETOOLONG);
}

enum candidate_search_context {
    CANDIDATE_NON_GNU = 0,
    CANDIDATE_GNU_DIRECTORY_NONEXISTING,
    CANDIDATE_GNU_DIRECTORY_EXISTING,
};

/* Class and machine mismatches are the one opened-file rejection for which
 * GNU search may continue.  elf_parse_fd intentionally admits only the
 * build architecture, so identify that narrow case before invoking it.
 * Other header damage remains malformed and must not be hidden by a later
 * directory entry. */
static enum library_lookup_result candidate_elf_identity(
    int fd, const struct dep_list *deps)
{
    unsigned char prefix[offsetof(Elf64_Ehdr, e_version)];
    size_t offset = 0;

    while (offset < sizeof(prefix)) {
        ssize_t got = pread(fd, prefix + offset, sizeof(prefix) - offset,
                            (off_t)offset);

        if (got > 0) {
            offset += (size_t)got;
            continue;
        }
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0 && errno == ENOMEM)
            return LIBRARY_LOOKUP_INTERNAL;
        return LIBRARY_LOOKUP_MALFORMED;
    }
    if (memcmp(prefix, ELFMAG, SELFMAG) != 0)
        return LIBRARY_LOOKUP_MALFORMED;
    if (prefix[EI_CLASS] != deps->target_ei_class)
        return LIBRARY_LOOKUP_INCOMPATIBLE;
    {
        uint16_t machine;

        memcpy(&machine, prefix + offsetof(Elf64_Ehdr, e_machine),
               sizeof(machine));
        if (machine != deps->target_e_machine)
            return LIBRARY_LOOKUP_INCOMPATIBLE;
    }
    return LIBRARY_LOOKUP_FOUND;
}

static char *validated_candidate(const char *path,
                                 const struct dep_list *deps,
                                 enum candidate_search_context context,
                                 enum library_lookup_result *lookup_result,
                                 char **logical_path_out,
                                 struct dep_file_snapshot *snapshot_out)
{
    struct elf_info info;
    struct stat st;
    struct stat after;
    struct stat canonical;
    char *logical;
    char *real;
    int fd = -1;
    enum library_lookup_result identity;

    if (lookup_result)
        *lookup_result = LIBRARY_LOOKUP_MISS;
    if (logical_path_out)
        *logical_path_out = NULL;
    if (snapshot_out)
        memset(snapshot_out, 0, sizeof(*snapshot_out));
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        int error = errno;
        int gnu_search = context != CANDIDATE_NON_GNU;

        if (lookup_result && error == ENOMEM)
            *lookup_result = LIBRARY_LOOKUP_INTERNAL;
        else if (lookup_result && gnu_search &&
                 !candidate_open_miss_errno(error, 1))
            *lookup_result = context == CANDIDATE_GNU_DIRECTORY_EXISTING
                ? LIBRARY_LOOKUP_NEXT_STAGE : LIBRARY_LOOKUP_MISS;
        else if (lookup_result &&
                 !candidate_open_miss_errno(error, gnu_search))
            *lookup_result = LIBRARY_LOOKUP_UNREADABLE;
        return NULL;
    }
    if (fstat(fd, &st) != 0) {
        int error = errno;

        /* GNU's list-local stop applies to open_path's open() failure.
         * Once a pathname has opened, failure to obtain its file identity
         * is fatal in _dl_map_object_from_fd; it must not advance either the
         * current directory list or a later search mechanism. */
        if (lookup_result)
            *lookup_result = error == ENOMEM
                ? LIBRARY_LOOKUP_INTERNAL : LIBRARY_LOOKUP_UNREADABLE;
        close(fd);
        return NULL;
    }
    if (!S_ISREG(st.st_mode)) {
        if (lookup_result)
            *lookup_result = LIBRARY_LOOKUP_MALFORMED;
        close(fd);
        return NULL;
    }
    identity = candidate_elf_identity(fd, deps);
    if (identity != LIBRARY_LOOKUP_FOUND) {
        if (lookup_result)
            *lookup_result = identity;
        close(fd);
        return NULL;
    }
    errno = 0;
    if (elf_parse_fd(fd, &info) < 0) {
        if (lookup_result)
            *lookup_result = errno == ENOMEM
                ? LIBRARY_LOOKUP_INTERNAL : LIBRARY_LOOKUP_MALFORMED;
        close(fd);
        return NULL;
    }
    if (!elf_info_matches_target(&info, deps)) {
        elf_info_free(&info);
        close(fd);
        if (lookup_result)
            *lookup_result = LIBRARY_LOOKUP_MALFORMED;
        return NULL;
    }
    elf_info_free(&info);

    real = realpath(path, NULL);
    if (!real) {
        int error = errno;
        if (lookup_result)
            *lookup_result = error == ENOMEM
                ? LIBRARY_LOOKUP_INTERNAL : LIBRARY_LOOKUP_UNREADABLE;
        close(fd);
        return NULL;
    }
    if (stat(real, &canonical) < 0) {
        int error = errno;

        if (lookup_result)
            *lookup_result = error == ENOMEM
                ? LIBRARY_LOOKUP_INTERNAL : LIBRARY_LOOKUP_UNREADABLE;
        free(real);
        close(fd);
        return NULL;
    }
    if (!dep_stats_match(&st, &canonical)) {
        if (lookup_result)
            *lookup_result = LIBRARY_LOOKUP_UNREADABLE;
        errno = ESTALE;
        free(real);
        close(fd);
        return NULL;
    }
    if (fstat(fd, &after) < 0) {
        int error = errno;

        if (lookup_result)
            *lookup_result = error == ENOMEM
                ? LIBRARY_LOOKUP_INTERNAL : LIBRARY_LOOKUP_UNREADABLE;
        free(real);
        close(fd);
        return NULL;
    }
    if (!dep_stats_match(&st, &after)) {
        if (lookup_result)
            *lookup_result = LIBRARY_LOOKUP_UNREADABLE;
        errno = ESTALE;
        free(real);
        close(fd);
        return NULL;
    }
    logical = strdup(path);
    if (!logical) {
        if (lookup_result)
            *lookup_result = LIBRARY_LOOKUP_INTERNAL;
        free(real);
        close(fd);
        return NULL;
    }
    /* Keep the verified descriptor alive until both identities have been
     * captured.  In particular, do not close and then reopen the candidate
     * merely to derive the canonical snapshot pathname. */
    if (snapshot_out)
        dep_snapshot_from_stat(snapshot_out, &after);
    close(fd);
    if (logical_path_out)
        *logical_path_out = logical;
    else
        free(logical);
    if (lookup_result)
        *lookup_result = LIBRARY_LOOKUP_FOUND;
    return real;
}

static int musl_arch_from_target(const struct dep_list *deps, char *arch,
                                 size_t arch_size)
{
    const char *value;

    if (!deps || deps->runtime_family != DEP_RUNTIME_MUSL || arch_size == 0)
        return -1;
    if (deps->target_e_machine == EM_X86_64)
        value = "x86_64";
    else if (deps->target_e_machine == EM_AARCH64)
        value = "aarch64";
    else
        return -1;
    if (strlen(value) >= arch_size)
        return -1;
    strcpy(arch, value);
    return 0;
}

static int initialize_gnu_platform(struct dep_list *deps)
{
    if (!deps || deps->runtime_family != DEP_RUNTIME_GNU)
        return 0;
    if (deps->target_e_machine != EM_AARCH64)
        return 0;
#if defined(__aarch64__)
    {
        const char *platform = (const char *)getauxval(AT_PLATFORM);

        /* A missing/empty AT_PLATFORM makes native substitution discard the
         * affected path element.  Keep NULL to represent that exact state. */
        if (!platform || !platform[0])
            return 0;
        deps->gnu_platform = strdup(platform);
        return deps->gnu_platform ? 0 : -1;
    }
#else
    /* A cross-architecture pack process does not share the target kernel
     * auxv.  No value is safer than importing the pack host's platform. */
    return 0;
#endif
}

/* ------------------------------------------------------------------ */
/*  GNU version-1.1 runtime cache                                     */
/* ------------------------------------------------------------------ */
#define GNU_CACHE_EXTENSION_MAGIC UINT32_C(0xeaa42174)

/* These are GNU cache ABI IDs: FLAG_ELF_LIBC6 plus the architecture's
 * 64-bit ABI selector.  They are independent of distribution directory
 * layouts. */
#define GNU_CACHE_ID_X86_64 UINT32_C(0x0303)
#define GNU_CACHE_ID_AARCH64 UINT32_C(0x0a03)
#define GNU_CACHE_OLD_MAGIC "ld.so-1.7.0"
#define GNU_CACHE_NEW_ALIGNMENT 8u

struct gnu_cache_old_header {
    char magic[sizeof(GNU_CACHE_OLD_MAGIC) - 1];
    uint32_t nlibs;
};

struct gnu_cache_old_entry {
    int32_t flags;
    uint32_t key;
    uint32_t value;
};

struct gnu_cache_entry {
    int32_t flags;
    uint32_t key;
    uint32_t value;
    uint32_t osversion;
    uint64_t hwcap;
};

struct gnu_cache_header {
    char magic[17];
    char version[3];
    uint32_t nlibs;
    uint32_t len_strings;
    uint8_t flags;
    uint8_t padding_unused[3];
    uint32_t extension_offset;
    uint32_t unused[3];
};

struct gnu_cache_extension_section {
    uint32_t tag;
    uint32_t flags;
    uint32_t offset;
    uint32_t size;
};

struct gnu_cache_extension {
    uint32_t magic;
    uint32_t count;
};

enum gnu_cache_lookup_result {
    GNU_CACHE_INTERNAL = -3,
    GNU_CACHE_MALFORMED = -2,
    GNU_CACHE_UNREADABLE = -1,
    GNU_CACHE_MISS = 0,
    GNU_CACHE_FOUND = 1,
};

enum {
    GNU_CACHE_SNAPSHOT_UNINITIALIZED = 0,
    GNU_CACHE_SNAPSHOT_READY = 2,
};

struct gnu_cache_lookup_entry {
    const char *key;
    const char *value;
    size_t collation_rank;
    uint32_t flags;
    uint32_t osversion;
    uint64_t hwcap;
};

struct gnu_cache_lookup_index {
    uint32_t count;
    struct gnu_cache_lookup_entry entries[];
};

enum {
    GNU_CACHE_STRING_TERMINATED = 1U << 0,
    GNU_CACHE_STRING_KEY_VALID = 1U << 1,
};

static void gnu_cache_index_free(void *opaque)
{
    free(opaque);
}

_Static_assert(sizeof(struct gnu_cache_entry) == 24,
               "GNU cache entry ABI changed");
_Static_assert(sizeof(struct gnu_cache_header) == 48,
               "GNU cache header ABI changed");
_Static_assert(sizeof(struct gnu_cache_old_header) == 16,
               "old GNU cache header ABI changed");
_Static_assert(sizeof(struct gnu_cache_old_entry) == 12,
               "old GNU cache entry ABI changed");

static int gnu_cache_required_id(const struct dep_list *deps,
                                 uint32_t *id_out)
{
    if (!deps || deps->target_ei_class != ELFCLASS64 || !id_out)
        return -1;
    if (deps->target_e_machine == EM_X86_64)
        *id_out = GNU_CACHE_ID_X86_64;
    else if (deps->target_e_machine == EM_AARCH64)
        *id_out = GNU_CACHE_ID_AARCH64;
    else
        return -1;
    return 0;
}

/* glibc sorts cache keys in descending _dl_cache_libcmp order.  Numeric
 * runs compare as numbers (so .10 sorts ahead of .9), not bytewise.  Reject
 * an unrepresentable run rather than invoking the signed-overflow behavior
 * of the historical implementation on a hostile cache key. */
static int gnu_cache_key_compare(const char *left, const char *right,
                                 int *comparison_out)
{
    const char *p1 = left;
    const char *p2 = right;

    if (!p1 || !p2 || !comparison_out)
        return -1;
    if (p1 == p2) {
        *comparison_out = 0;
        return 0;
    }
    while (*p1 != '\0') {
        if (*p1 >= '0' && *p1 <= '9') {
            if (*p2 >= '0' && *p2 <= '9') {
                int value1 = 0;
                int value2 = 0;

                do {
                    int digit = *p1++ - '0';

                    if (value1 > (INT_MAX - digit) / 10)
                        return -1;
                    value1 = value1 * 10 + digit;
                } while (*p1 >= '0' && *p1 <= '9');
                do {
                    int digit = *p2++ - '0';

                    if (value2 > (INT_MAX - digit) / 10)
                        return -1;
                    value2 = value2 * 10 + digit;
                } while (*p2 >= '0' && *p2 <= '9');
                if (value1 != value2) {
                    *comparison_out = value1 - value2;
                    return 0;
                }
            } else {
                *comparison_out = 1;
                return 0;
            }
        } else if (*p2 >= '0' && *p2 <= '9') {
            *comparison_out = -1;
            return 0;
        } else if (*p1 != *p2) {
            *comparison_out = *p1 - *p2;
            return 0;
        } else {
            p1++;
            p2++;
        }
    }
    *comparison_out = *p1 - *p2;
    return 0;
}

/* Build a byte-indexed proof that every possible referenced offset reaches a
 * NUL inside the declared string region.  Key offsets additionally prove
 * that every numeric comparison run is representable by glibc's cache
 * comparator.  This backward pass is linear in the cache image even when a
 * hostile table makes thousands of entries share one very long suffix; a
 * memchr from every entry would be quadratic. */
static uint8_t *gnu_cache_string_flags(const uint8_t *strings, size_t size)
{
    const uint64_t decimal_limit = (uint64_t)INT_MAX + 1U;
    uint8_t *flags;
    uint64_t suffix_value = 0;
    uint64_t decimal_place = 1;
    int suffix_numeric_valid = 0;
    int next_is_digit = 0;

    if (!strings || size == SIZE_MAX)
        return NULL;
    flags = calloc(size + 1, sizeof(*flags));
    if (!flags)
        return NULL;

    for (size_t cursor = size; cursor-- > 0;) {
        unsigned int value = strings[cursor];

        if (value == 0) {
            flags[cursor] = GNU_CACHE_STRING_TERMINATED |
                            GNU_CACHE_STRING_KEY_VALID;
            suffix_value = 0;
            decimal_place = 1;
            suffix_numeric_valid = 0;
            next_is_digit = 0;
            continue;
        }
        if (value >= '0' && value <= '9') {
            uint64_t digit = value - '0';
            int numeric_valid;

            if (!next_is_digit) {
                suffix_value = digit;
                decimal_place = 10;
                numeric_valid = 1;
            } else if (!suffix_numeric_valid) {
                numeric_valid = 0;
            } else if (digit == 0) {
                numeric_valid = 1;
            } else if (decimal_place > (uint64_t)INT_MAX ||
                       digit > ((uint64_t)INT_MAX - suffix_value) /
                                   decimal_place) {
                numeric_valid = 0;
            } else {
                suffix_value += digit * decimal_place;
                numeric_valid = 1;
            }
            flags[cursor] = flags[cursor + 1] &
                            GNU_CACHE_STRING_TERMINATED;
            if (numeric_valid &&
                (flags[cursor + 1] & GNU_CACHE_STRING_KEY_VALID))
                flags[cursor] |= GNU_CACHE_STRING_KEY_VALID;
            suffix_numeric_valid = numeric_valid;
            if (next_is_digit && decimal_place < decimal_limit) {
                if (decimal_place > decimal_limit / 10U)
                    decimal_place = decimal_limit;
                else {
                    decimal_place *= 10U;
                    if (decimal_place > decimal_limit)
                        decimal_place = decimal_limit;
                }
            }
            next_is_digit = 1;
            continue;
        }

        flags[cursor] = flags[cursor + 1];
        suffix_value = 0;
        decimal_place = 1;
        suffix_numeric_valid = 0;
        next_is_digit = 0;
    }
    return flags;
}

static void gnu_cache_rank_radix_pass(
    const size_t *input, size_t *output, size_t count, unsigned int shift,
    const size_t *rank, const size_t *jump, int successor)
{
    size_t buckets[256] = {0};
    size_t starts[256];

    for (size_t i = 0; i < count; i++) {
        size_t position = input[i];
        size_t value = successor ? rank[jump[position]] : rank[position];

        buckets[(value >> shift) & 0xffU]++;
    }
    starts[0] = 0;
    for (size_t i = 1; i < 256; i++)
        starts[i] = starts[i - 1] + buckets[i - 1];
    for (size_t i = 0; i < count; i++) {
        size_t position = input[i];
        size_t value = successor ? rank[jump[position]] : rank[position];
        size_t bucket = (value >> shift) & 0xffU;

        output[starts[bucket]++] = position;
    }
}

/* Assign the exact _dl_cache_libcmp ordering rank to every possible string
 * offset.  Numeric runs are one token, so different spellings of the same
 * value (for example .01 and .1) share a rank when their suffixes agree.
 * Prefix doubling over the token-successor graph plus stable radix passes is
 * O(string-bytes * log(longest-string)) and makes sortedness validation
 * independent of adversarial overlapping suffix lengths. */
static size_t *gnu_cache_collation_ranks(const uint8_t *strings, size_t size)
{
    const uint64_t decimal_limit = (uint64_t)INT_MAX + 1U;
    size_t node_count;
    size_t allocation_size;
    size_t *rank = NULL;
    size_t *jump = NULL;
    size_t *order = NULL;
    size_t *scratch = NULL;
    uint64_t suffix_value = 0;
    uint64_t decimal_place = 1;
    size_t run_end = size;
    int suffix_numeric_valid = 0;
    int next_is_digit = 0;

    if (!strings || size == SIZE_MAX)
        return NULL;
    node_count = size + 1U;
    if (node_count > SIZE_MAX / sizeof(*rank))
        return NULL;
    allocation_size = node_count * sizeof(*rank);
    rank = malloc(allocation_size);
    jump = malloc(allocation_size);
    order = malloc(allocation_size);
    scratch = malloc(allocation_size);
    if (!rank || !jump || !order || !scratch)
        goto fail;

    rank[size] = (size_t)(0 - CHAR_MIN);
    jump[size] = size;
    for (size_t cursor = size; cursor-- > 0;) {
        unsigned int byte = strings[cursor];

        if (byte == 0) {
            rank[cursor] = (size_t)(0 - CHAR_MIN);
            jump[cursor] = size;
            suffix_value = 0;
            decimal_place = 1;
            run_end = cursor;
            suffix_numeric_valid = 0;
            next_is_digit = 0;
            continue;
        }
        if (byte >= '0' && byte <= '9') {
            uint64_t digit = byte - '0';
            int numeric_valid;

            if (!next_is_digit) {
                suffix_value = digit;
                decimal_place = 10;
                run_end = cursor + 1U;
                numeric_valid = 1;
            } else if (!suffix_numeric_valid) {
                numeric_valid = 0;
            } else if (digit == 0) {
                numeric_valid = 1;
            } else if (decimal_place > (uint64_t)INT_MAX ||
                       digit > ((uint64_t)INT_MAX - suffix_value) /
                                   decimal_place) {
                numeric_valid = 0;
            } else {
                suffix_value += digit * decimal_place;
                numeric_valid = 1;
            }
            rank[cursor] = (size_t)UCHAR_MAX + 1U +
                (numeric_valid ? (size_t)suffix_value
                               : (size_t)INT_MAX + 1U);
            jump[cursor] = run_end;
            suffix_numeric_valid = numeric_valid;
            if (next_is_digit && decimal_place < decimal_limit) {
                if (decimal_place > decimal_limit / 10U)
                    decimal_place = decimal_limit;
                else {
                    decimal_place *= 10U;
                    if (decimal_place > decimal_limit)
                        decimal_place = decimal_limit;
                }
            }
            next_is_digit = 1;
            continue;
        }

        rank[cursor] = (size_t)((int)(char)byte - CHAR_MIN);
        jump[cursor] = cursor + 1U;
        suffix_value = 0;
        decimal_place = 1;
        run_end = cursor;
        suffix_numeric_valid = 0;
        next_is_digit = 0;
    }

    for (;;) {
        size_t max_rank = 0;
        size_t next_rank = 0;
        size_t *old_rank;
        size_t *old_jump;
        unsigned int pass_count = 0;
        int all_terminal = 1;

        for (size_t i = 0; i < node_count; i++) {
            order[i] = i;
            if (rank[i] > max_rank)
                max_rank = rank[i];
            if (jump[i] != size)
                all_terminal = 0;
        }
        if (all_terminal)
            break;
        do {
            pass_count++;
            max_rank >>= 8U;
        } while (max_rank != 0);

        /* Sort by successor rank and then first-token rank.  Each key uses
         * the same number of byte passes, so the final permutation is back
         * in order[] and scratch[] is available for the new rank vector. */
        for (unsigned int pass = 0; pass < pass_count; pass++) {
            gnu_cache_rank_radix_pass(
                order, scratch, node_count, pass * 8U,
                rank, jump, 1);
            {
                size_t *swap = order;
                order = scratch;
                scratch = swap;
            }
        }
        for (unsigned int pass = 0; pass < pass_count; pass++) {
            gnu_cache_rank_radix_pass(
                order, scratch, node_count, pass * 8U,
                rank, jump, 0);
            {
                size_t *swap = order;
                order = scratch;
                scratch = swap;
            }
        }
        for (size_t i = 0; i < node_count; i++) {
            size_t position = order[i];

            if (i != 0) {
                size_t previous = order[i - 1];

                if (rank[previous] != rank[position] ||
                    rank[jump[previous]] != rank[jump[position]])
                    next_rank++;
            }
            scratch[position] = next_rank;
        }
        for (size_t i = 0; i < node_count; i++)
            rank[i] = jump[jump[i]];

        old_rank = rank;
        old_jump = jump;
        rank = scratch;
        jump = old_rank;
        scratch = order;
        order = old_jump;
    }

    free(jump);
    free(order);
    free(scratch);
    return rank;

fail:
    free(rank);
    free(jump);
    free(order);
    free(scratch);
    return NULL;
}

static int gnu_cache_resolve_string(
    const uint8_t *file, size_t file_size, size_t offset_base,
    size_t strings_start, size_t strings_end, const uint8_t *string_flags,
    uint32_t encoded_offset, int key, const char **value_out)
{
    size_t offset;
    size_t relative;
    unsigned int required = key ? GNU_CACHE_STRING_KEY_VALID
                                : GNU_CACHE_STRING_TERMINATED;

    if (!file || !string_flags || !value_out ||
        offset_base > SIZE_MAX - (size_t)encoded_offset)
        return -1;
    offset = offset_base + (size_t)encoded_offset;
    if (offset < strings_start || offset >= strings_end ||
        offset >= file_size)
        return -1;
    relative = offset - strings_start;
    if ((string_flags[relative] & required) != required)
        return -1;
    *value_out = (const char *)file + offset;
    if ((key && (*value_out)[0] == '\0') ||
        (!key && (*value_out)[0] != '/'))
        return -1;
    return 0;
}

static struct gnu_cache_lookup_index *gnu_cache_index_allocate(
    uint32_t count)
{
    struct gnu_cache_lookup_index *index;
    size_t entries_size;

    entries_size = (size_t)count * sizeof(*index->entries);
    if ((count != 0 && entries_size / (size_t)count !=
                       sizeof(*index->entries)) ||
        entries_size > SIZE_MAX - sizeof(*index))
        return NULL;
    index = calloc(1, sizeof(*index) + entries_size);
    if (index)
        index->count = count;
    return index;
}

static int gnu_cache_index_order_is_valid(
    const struct gnu_cache_lookup_index *index)
{
    for (uint32_t i = 1; i < index->count; i++) {
        if (index->entries[i - 1].collation_rank <
            index->entries[i].collation_rank)
            return 0;
    }
    return 1;
}

/* Legacy cache offsets are relative to the byte immediately following the
 * old entry array, unlike version-1.1 offsets, which are relative to that
 * format's header.  Validate every entry before selecting one so an invalid
 * unrelated record cannot steer an indexed lookup around malformed storage. */
static int gnu_cache_build_old_index(
    const uint8_t *file, size_t file_size,
    struct gnu_cache_lookup_index **index_out)
{
    const struct gnu_cache_old_header *header;
    const struct gnu_cache_old_entry *entries;
    struct gnu_cache_lookup_index *index = NULL;
    uint8_t *string_flags = NULL;
    size_t *collation_ranks = NULL;
    size_t entries_size;
    size_t strings_start;
    size_t strings_size;
    int result = GNU_CACHE_MALFORMED;

    if (!index_out)
        return GNU_CACHE_MALFORMED;
    *index_out = NULL;
    if (!file || file_size < sizeof(*header))
        return GNU_CACHE_MALFORMED;
    header = (const void *)file;
    if (memcmp(header->magic, GNU_CACHE_OLD_MAGIC,
               sizeof(header->magic)) != 0 ||
        (size_t)header->nlibs >
            (file_size - sizeof(*header)) / sizeof(*entries))
        return GNU_CACHE_MALFORMED;
    entries_size = (size_t)header->nlibs * sizeof(*entries);
    strings_start = sizeof(*header) + entries_size;
    strings_size = file_size - strings_start;
    entries = (const void *)(file + sizeof(*header));
    index = gnu_cache_index_allocate(header->nlibs);
    if (!index)
        return GNU_CACHE_INTERNAL;
    string_flags = gnu_cache_string_flags(file + strings_start,
                                          strings_size);
    if (!string_flags) {
        result = GNU_CACHE_INTERNAL;
        goto out;
    }
    collation_ranks = gnu_cache_collation_ranks(file + strings_start,
                                                strings_size);
    if (!collation_ranks) {
        result = GNU_CACHE_INTERNAL;
        goto out;
    }

    for (uint32_t i = 0; i < header->nlibs; i++) {
        if (gnu_cache_resolve_string(
                file, file_size, strings_start, strings_start, file_size,
                string_flags, entries[i].key, 1,
                &index->entries[i].key) < 0 ||
            gnu_cache_resolve_string(
                file, file_size, strings_start, strings_start, file_size,
                string_flags, entries[i].value, 0,
                &index->entries[i].value) < 0)
            goto out;
        index->entries[i].flags = (uint32_t)entries[i].flags;
        index->entries[i].collation_rank =
            collation_ranks[entries[i].key];
    }
    if (!gnu_cache_index_order_is_valid(index))
        goto out;
    *index_out = index;
    index = NULL;
    result = GNU_CACHE_FOUND;

out:
    free(string_flags);
    free(collation_ranks);
    gnu_cache_index_free(index);
    return result;
}

/* Match glibc's Linux cache ABI encoding: up to three decimal release
 * components occupy one byte each (major.minor.patch), with suffixes ignored
 * after the third component.  Reject values which cannot be represented
 * instead of reproducing unsigned wraparound on a malformed uname result. */
static int gnu_kernel_release_version(const char *release,
                                      uint32_t *version_out)
{
    const char *cursor = release;
    uint32_t version = 0;
    unsigned int parts = 0;

    if (!release || !version_out)
        return -1;
    while (parts < 3 && *cursor >= '0' && *cursor <= '9') {
        unsigned int component = 0;

        do {
            unsigned int digit = (unsigned int)(*cursor++ - '0');

            if (component > (UINT8_MAX - digit) / 10U)
                return -1;
            component = component * 10U + digit;
        } while (*cursor >= '0' && *cursor <= '9');
        version = (version << 8) | component;
        parts++;
        if (parts == 3 || *cursor != '.')
            break;
        cursor++;
    }
    if (parts == 0)
        return -1;
    version <<= 8U * (3U - parts);
    *version_out = version;
    return 0;
}

static int gnu_kernel_osversion(uint32_t *version_out)
{
    struct utsname uts;

    if (!version_out || uname(&uts) < 0)
        return -1;
    return gnu_kernel_release_version(uts.release, version_out);
}

/* Validate the extension directory even though pack-time lookup deliberately
 * selects the generic cache entry.  glibc treats out-of-range extension data
 * as unusable; accepting the rest of such a cache would make our trust rule
 * weaker than the runtime's. */
static int gnu_cache_extensions_valid(const uint8_t *file, size_t file_size,
                                      size_t strings_end,
                                      uint32_t extension_offset)
{
    const struct gnu_cache_extension *extension;
    const struct gnu_cache_extension_section *sections;
    size_t sections_offset;
    size_t directory_end;
    size_t minimum_offset;

    if (extension_offset == 0)
        return 1;
    if (strings_end > SIZE_MAX - 3)
        return 0;
    minimum_offset = (strings_end + 3u) & ~(size_t)3u;
    if ((extension_offset & 3u) != 0 ||
        (size_t)extension_offset < minimum_offset ||
        (size_t)extension_offset > file_size ||
        sizeof(*extension) > file_size - (size_t)extension_offset)
        return 0;
    extension = (const void *)(file + extension_offset);
    if (extension->magic != GNU_CACHE_EXTENSION_MAGIC)
        return 0;
    sections_offset = (size_t)extension_offset + sizeof(*extension);
    if ((size_t)extension->count >
        (file_size - sections_offset) / sizeof(*sections))
        return 0;
    sections = (const void *)(file + sections_offset);
    directory_end = sections_offset +
        (size_t)extension->count * sizeof(*sections);
    for (uint32_t i = 0; i < extension->count; i++) {
        size_t offset = sections[i].offset;
        size_t size = sections[i].size;

        if (offset > file_size || size > file_size - offset ||
            (size != 0 && offset < directory_end))
            return 0;
    }
    return 1;
}

static int gnu_cache_snapshot_initialize(struct dep_list *deps)
{
    struct stat st;
    struct stat after;
    uint8_t *image;
    size_t size;
    size_t offset = 0;
    int fd;

    if (!deps)
        return GNU_CACHE_MALFORMED;
    if (deps->gnu_cache_snapshot_state !=
        GNU_CACHE_SNAPSHOT_UNINITIALIZED)
        return deps->gnu_cache_snapshot_state;
    if (!deps->gnu_cache_path || !deps->gnu_cache_path[0])
        return GNU_CACHE_MALFORMED;

    fd = open(deps->gnu_cache_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        deps->gnu_cache_snapshot_state = GNU_CACHE_UNREADABLE;
        return deps->gnu_cache_snapshot_state;
    }
    if (fstat(fd, &st) < 0) {
        close(fd);
        deps->gnu_cache_snapshot_state = GNU_CACHE_UNREADABLE;
        return deps->gnu_cache_snapshot_state;
    }
    if (!S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uintmax_t)st.st_size > SIZE_MAX ||
        (uintmax_t)st.st_size < sizeof(struct gnu_cache_old_header)) {
        close(fd);
        deps->gnu_cache_snapshot_state = GNU_CACHE_MALFORMED;
        return deps->gnu_cache_snapshot_state;
    }
    size = (size_t)st.st_size;
    image = malloc(size);
    if (!image) {
        close(fd);
        deps->gnu_cache_snapshot_state = GNU_CACHE_INTERNAL;
        return deps->gnu_cache_snapshot_state;
    }
    while (offset < size) {
        size_t remaining = size - offset;
        size_t chunk = remaining > (size_t)SSIZE_MAX
            ? (size_t)SSIZE_MAX : remaining;
        ssize_t got = read(fd, image + offset, chunk);

        if (got > 0) {
            offset += (size_t)got;
            continue;
        }
        if (got < 0 && errno == EINTR)
            continue;
        free(image);
        close(fd);
        deps->gnu_cache_snapshot_state = GNU_CACHE_UNREADABLE;
        return deps->gnu_cache_snapshot_state;
    }
    if (fstat(fd, &after) < 0 || !dep_stats_match(&st, &after)) {
        free(image);
        close(fd);
        deps->gnu_cache_snapshot_state = GNU_CACHE_UNREADABLE;
        return deps->gnu_cache_snapshot_state;
    }
    close(fd);
    deps->gnu_cache_image = image;
    deps->gnu_cache_image_size = size;
    deps->gnu_cache_snapshot_state = GNU_CACHE_SNAPSHOT_READY;
    return deps->gnu_cache_snapshot_state;
}

static int gnu_cache_build_new_index(
    const uint8_t *file, size_t file_size, size_t cache_base_offset,
    struct gnu_cache_lookup_index **index_out)
{
    static const char magic[] = "glibc-ld.so.cache";
    static const char version[] = "1.1";
    const struct gnu_cache_header *header;
    const struct gnu_cache_entry *entries;
    const uint8_t *cache_base;
    struct gnu_cache_lookup_index *index = NULL;
    uint8_t *string_flags = NULL;
    size_t *collation_ranks = NULL;
    size_t cache_size;
    size_t entry_bytes;
    size_t strings_start;
    size_t strings_end;
    size_t absolute_strings_start;
    size_t absolute_strings_end;
    int result = GNU_CACHE_MALFORMED;

    if (!file || !index_out || cache_base_offset > file_size)
        return GNU_CACHE_MALFORMED;
    *index_out = NULL;
    cache_base = file + cache_base_offset;
    cache_size = file_size - cache_base_offset;
    header = (const void *)cache_base;
    if (cache_size < sizeof(*header) ||
        memcmp(header->magic, magic, sizeof(header->magic)) != 0 ||
        memcmp(header->version, version, sizeof(header->version)) != 0 ||
        (header->flags != 0 && (header->flags & 3u) != 2u) ||
        (size_t)header->nlibs >
            (cache_size - sizeof(*header)) / sizeof(*entries))
        return GNU_CACHE_MALFORMED;
    entry_bytes = (size_t)header->nlibs * sizeof(*entries);
    strings_start = sizeof(*header) + entry_bytes;
    if ((size_t)header->len_strings > cache_size - strings_start)
        return GNU_CACHE_MALFORMED;
    strings_end = strings_start + (size_t)header->len_strings;
    if (cache_base_offset > SIZE_MAX - strings_start ||
        cache_base_offset > SIZE_MAX - strings_end)
        return GNU_CACHE_MALFORMED;
    absolute_strings_start = cache_base_offset + strings_start;
    absolute_strings_end = cache_base_offset + strings_end;
    if (!gnu_cache_extensions_valid(file, file_size,
                                    absolute_strings_end,
                                    header->extension_offset))
        return GNU_CACHE_MALFORMED;

    index = gnu_cache_index_allocate(header->nlibs);
    if (!index)
        return GNU_CACHE_INTERNAL;
    string_flags = gnu_cache_string_flags(
        file + absolute_strings_start,
        absolute_strings_end - absolute_strings_start);
    if (!string_flags) {
        result = GNU_CACHE_INTERNAL;
        goto out;
    }
    collation_ranks = gnu_cache_collation_ranks(
        file + absolute_strings_start,
        absolute_strings_end - absolute_strings_start);
    if (!collation_ranks) {
        result = GNU_CACHE_INTERNAL;
        goto out;
    }
    entries = (const void *)(cache_base + sizeof(*header));
    for (uint32_t i = 0; i < header->nlibs; i++) {
        if (gnu_cache_resolve_string(
                file, file_size, cache_base_offset,
                absolute_strings_start, absolute_strings_end,
                string_flags, entries[i].key, 1,
                &index->entries[i].key) < 0 ||
            gnu_cache_resolve_string(
                file, file_size, cache_base_offset,
                absolute_strings_start, absolute_strings_end,
                string_flags, entries[i].value, 0,
                &index->entries[i].value) < 0)
            goto out;
        index->entries[i].flags = (uint32_t)entries[i].flags;
        index->entries[i].collation_rank =
            collation_ranks[(size_t)entries[i].key - strings_start];
        index->entries[i].osversion = entries[i].osversion;
        index->entries[i].hwcap = entries[i].hwcap;
    }
    if (!gnu_cache_index_order_is_valid(index))
        goto out;
    *index_out = index;
    index = NULL;
    result = GNU_CACHE_FOUND;

out:
    free(string_flags);
    free(collation_ranks);
    gnu_cache_index_free(index);
    return result;
}

static int gnu_cache_index_initialize(struct dep_list *deps)
{
    static const char magic[] = "glibc-ld.so.cache";
    static const char version[] = "1.1";
    const uint8_t *file;
    struct gnu_cache_lookup_index *index = NULL;
    size_t file_size;
    size_t cache_base_offset = 0;
    int result;

    if (!deps)
        return GNU_CACHE_MALFORMED;
    if (deps->gnu_cache_index)
        return GNU_CACHE_FOUND;
    result = gnu_cache_snapshot_initialize(deps);
    if (result != GNU_CACHE_SNAPSHOT_READY)
        return result;
    file = deps->gnu_cache_image;
    file_size = deps->gnu_cache_image_size;

    if (file_size < sizeof(magic) - 1 ||
        memcmp(file, magic, sizeof(magic) - 1) != 0) {
        const struct gnu_cache_old_header *old_header;
        size_t old_entries_size;
        size_t old_end;
        size_t signature_size = sizeof(magic) - 1 + sizeof(version) - 1;

        if (file_size < sizeof(*old_header) ||
            memcmp(file, GNU_CACHE_OLD_MAGIC,
                   sizeof(GNU_CACHE_OLD_MAGIC) - 1) != 0)
            return GNU_CACHE_MALFORMED;
        old_header = (const void *)file;
        if ((size_t)old_header->nlibs >
            (file_size - sizeof(*old_header)) /
                sizeof(struct gnu_cache_old_entry))
            return GNU_CACHE_MALFORMED;
        old_entries_size = (size_t)old_header->nlibs *
            sizeof(struct gnu_cache_old_entry);
        old_end = sizeof(*old_header) + old_entries_size;
        if (old_end > SIZE_MAX - (GNU_CACHE_NEW_ALIGNMENT - 1u))
            return GNU_CACHE_MALFORMED;
        cache_base_offset =
            (old_end + (GNU_CACHE_NEW_ALIGNMENT - 1u)) &
            ~(size_t)(GNU_CACHE_NEW_ALIGNMENT - 1u);
        /* A compatibility cache places a complete 1.1 signature at this
         * exact aligned offset.  Otherwise glibc consumes the old table and
         * interprets its string offsets relative to old_end. */
        if (cache_base_offset > file_size ||
            signature_size > file_size - cache_base_offset ||
            memcmp(file + cache_base_offset, magic,
                   sizeof(magic) - 1) != 0 ||
            memcmp(file + cache_base_offset + sizeof(magic) - 1,
                   version, sizeof(version) - 1) != 0) {
            result = gnu_cache_build_old_index(file, file_size, &index);
            if (result == GNU_CACHE_FOUND)
                deps->gnu_cache_index = index;
            return result;
        }
        if (sizeof(struct gnu_cache_header) >
            file_size - cache_base_offset)
            return GNU_CACHE_MALFORMED;
    }
    result = gnu_cache_build_new_index(
        file, file_size, cache_base_offset, &index);
    if (result == GNU_CACHE_FOUND)
        deps->gnu_cache_index = index;
    return result;
}

static int gnu_cache_key_is_representable(const char *key)
{
    const unsigned char *cursor = (const unsigned char *)key;

    if (!cursor || !cursor[0])
        return 0;
    while (*cursor) {
        if (*cursor < '0' || *cursor > '9') {
            cursor++;
            continue;
        }
        {
            int value = 0;

            do {
                int digit = *cursor++ - '0';

                if (value > (INT_MAX - digit) / 10)
                    return 0;
                value = value * 10 + digit;
            } while (*cursor >= '0' && *cursor <= '9');
        }
    }
    return 1;
}

/* Return GNU_CACHE_FOUND and an owned absolute pathname for a generic
 * exact-ABI entry, GNU_CACHE_MISS for a validated miss,
 * GNU_CACHE_UNREADABLE for an I/O failure, GNU_CACHE_MALFORMED for an
 * invalid image, and GNU_CACHE_INTERNAL for an allocation failure.  Named
 * glibc-hwcaps selection depends on evolving loader-private CPU/tunable
 * state; selecting the cache's generic ABI-compatible entry is deterministic
 * and avoids freezing an object the target loader may not admit on replay. */
static int gnu_cache_lookup_path(struct dep_list *deps, const char *name,
                                 uint32_t required_id, char **path_out)
{
    const struct gnu_cache_lookup_index *index;
    const char *selected = NULL;
    uint32_t kernel_osversion = 0;
    int kernel_osversion_known;
    size_t low = 0;
    size_t high;
    size_t target_rank = 0;
    int result;

    if (path_out)
        *path_out = NULL;
    if (!deps || !name || !name[0] || !path_out ||
        deps->gnu_release_minor < 0 ||
        !gnu_cache_key_is_representable(name))
        return GNU_CACHE_MALFORMED;
    result = gnu_cache_index_initialize(deps);
    if (result != GNU_CACHE_FOUND)
        goto invalid_index;
    index = deps->gnu_cache_index;
    high = index->count;

    /* The validated cache is descending in _dl_cache_libcmp order.  Locate
     * the complete collation-equivalent group, then retain strcmp's exact
     * soname semantics inside that group.  Reusing this immutable index turns
     * a dependency closure's repeated cache probes from O(objects*cache) into
     * O(cache + objects*log(cache)). */
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        int comparison;

        if (gnu_cache_key_compare(index->entries[middle].key, name,
                                  &comparison) < 0) {
            result = GNU_CACHE_MALFORMED;
            goto out;
        }
        if (comparison > 0)
            low = middle + 1;
        else
            high = middle;
    }
    if (low < index->count) {
        int comparison;

        if (gnu_cache_key_compare(index->entries[low].key, name,
                                  &comparison) < 0) {
            result = GNU_CACHE_MALFORMED;
            goto out;
        }
        if (comparison == 0)
            target_rank = index->entries[low].collation_rank;
        else
            low = index->count;
    }
    kernel_osversion_known = deps->gnu_release_minor <= 35 &&
        gnu_kernel_osversion(&kernel_osversion) == 0;
    for (size_t i = low; i < index->count; i++) {
        const struct gnu_cache_lookup_entry *entry = &index->entries[i];

        if (entry->collation_rank != target_rank)
            break;
        if (strcmp(entry->key, name) != 0 || entry->flags != required_id)
            continue;
        /* glibc compares the cached GNU ABI-tag requirement with the running
         * Linux version.  uname is the same stable kernel input used by its
         * fallback discovery path; if it cannot be represented, retain only
         * entries which declare no OS minimum. */
        if (deps->gnu_release_minor <= 35 && entry->osversion != 0 &&
            (!kernel_osversion_known ||
             entry->osversion > kernel_osversion))
            continue;
        /* Both legacy and named hardware-capability entries require loader
         * CPU/tunable policy.  Pack-time resolution uses only the generic
         * cache contract. */
        if (entry->hwcap != 0)
            continue;
        selected = entry->value;
        break;
    }

    if (!selected) {
        result = GNU_CACHE_MISS;
        goto out;
    }
    *path_out = strdup(selected);
    if (!*path_out) {
        result = GNU_CACHE_INTERNAL;
        goto out;
    }
    result = GNU_CACHE_FOUND;
    goto out;

invalid_index:
    if (result == GNU_CACHE_MALFORMED) {
        deps->gnu_cache_snapshot_state = GNU_CACHE_MALFORMED;
        gnu_cache_index_free(deps->gnu_cache_index);
        deps->gnu_cache_index = NULL;
        free(deps->gnu_cache_image);
        deps->gnu_cache_image = NULL;
        deps->gnu_cache_image_size = 0;
    }

out:
    if (result != GNU_CACHE_FOUND) {
        free(*path_out);
        *path_out = NULL;
    }
    return result;
}

static char *resolve_from_gnu_cache(const char *name,
                                    struct dep_list *deps,
                                    int *lookup_status,
                                    char **logical_path_out,
                                    struct dep_file_snapshot *snapshot_out)
{
    char *cached_path = NULL;
    char *candidate = NULL;
    uint32_t required_id;
    int status;

    if (gnu_cache_required_id(deps, &required_id) < 0) {
        *lookup_status = GNU_CACHE_MALFORMED;
        return NULL;
    }
    if (!deps->gnu_cache_path || !deps->gnu_cache_path[0]) {
        *lookup_status = GNU_CACHE_MALFORMED;
        return NULL;
    }
    status = gnu_cache_lookup_path(deps, name, required_id, &cached_path);
    if (status == GNU_CACHE_FOUND) {
        enum library_lookup_result candidate_status;

        candidate = validated_candidate(cached_path, deps,
                                        CANDIDATE_NON_GNU,
                                        &candidate_status,
                                        logical_path_out, snapshot_out);
        if (!candidate)
            status = candidate_status == LIBRARY_LOOKUP_INTERNAL
                ? GNU_CACHE_INTERNAL : GNU_CACHE_MALFORMED;
    }
    free(cached_path);
    *lookup_status = status;
    return candidate;
}

/* ------------------------------------------------------------------ */
/*  dep_list helpers                                                  */
/* ------------------------------------------------------------------ */
static int dep_list_add(struct dep_list *deps, const char *name,
                        const char *path, const char *logical_path,
                        const struct dep_file_snapshot *snapshot,
                        int from_dlopen,
                        int dlopen_direct, int dlopen_pathful,
                        int needed_pathful,
                        const char *dlopen_request)
{
    if (!logical_path)
        logical_path = path;
    if (!snapshot || !snapshot->valid)
        return -1;
    if (dlopen_request) {
        for (int i = 0; i < deps->count; i++) {
            if (deps->libs[i].dlopen_request &&
                strcmp(deps->libs[i].dlopen_request, dlopen_request) == 0 &&
                (deps->libs[i].device != snapshot->device ||
                 deps->libs[i].inode != snapshot->inode ||
                 strcmp(deps->libs[i].logical_path, logical_path) != 0)) {
                fprintf(stderr,
                        "dlfreeze: one dlopen request has conflicting traced identity: %s\n",
                        dlopen_request);
                return -1;
            }
        }
    }
    /* Native loaders admit one map per file identity.  Preserve the logical
     * spelling which reached that identity first: it remains the owner of
     * $ORIGIN even when a later edge uses a symlink or hardlink alias. */
    for (int i = 0; i < deps->count; i++) {
        char *replacement_name = NULL;
        char *replacement_request = NULL;

        if (deps->libs[i].device != snapshot->device ||
            deps->libs[i].inode != snapshot->inode)
            continue;
        if (deps->libs[i].snapshot.size != snapshot->size ||
            deps->libs[i].snapshot.mtime_sec != snapshot->mtime_sec ||
            deps->libs[i].snapshot.mtime_nsec != snapshot->mtime_nsec ||
            deps->libs[i].snapshot.ctime_sec != snapshot->ctime_sec ||
            deps->libs[i].snapshot.ctime_nsec != snapshot->ctime_nsec) {
            fprintf(stderr,
                    "dlfreeze: dependency changed during resolution: %s\n",
                    path);
            return -1;
        }
        /* A direct trace request and a DT_NEEDED edge are different lookup
         * identities even when their visible ELF name happens to match.
         * Keep a request-less manifest alias for the dependency role: using
         * every traced root's basename as an implicit DT_NEEDED alias could
         * select the wrong same-SONAME object from another search scope. */
        if (!dlopen_request && deps->libs[i].from_dlopen &&
            deps->libs[i].dlopen_request)
            continue;
        /* Draining each completed traced closure before the next record can
         * expose the reverse order: a dependency identity is known before a
         * later direct request for it.  Preserve both manifest roles rather
         * than replacing the dependency identity with the request alias. */
        if (dlopen_request && deps->libs[i].from_dlopen &&
            !deps->libs[i].dlopen_request)
            continue;
        /* Distinct dlopen requests and distinct ordinary DT_NEEDED names are
         * lookup aliases for one native map.  Keep separate manifest records
         * so every spelling remains resolvable, while the BFS caller uses
         * filesystem identity to traverse the source closure only once. */
        if (dlopen_request && deps->libs[i].dlopen_request &&
            strcmp(deps->libs[i].dlopen_request, dlopen_request) != 0)
            continue;

        if (strcmp(deps->libs[i].name, name) != 0) {
            /* A traced root's ELF name is not the dlopen identity: the trace keeps
             * the exact request separately.  Preserve an already-known
             * dependency name when merging a trace, or replace the initial
             * traced name once when the startup graph later supplies the
             * real DT_NEEDED identity. */
            if (dlopen_request) {
                /* Keep the existing dependency identity. */
            } else if (!from_dlopen && deps->libs[i].from_dlopen &&
                       deps->libs[i].dlopen_request) {
                replacement_name = strdup(name);
                if (!replacement_name)
                    return -1;
            } else {
                /* A second dependency spelling needs its own alias record;
                 * do not merge it into whichever spelling opened first. */
                continue;
            }
        }

        if (dlopen_request && !deps->libs[i].dlopen_request) {
            replacement_request = strdup(dlopen_request);
            if (!replacement_request) {
                free(replacement_name);
                return -1;
            }
        }
        if (!from_dlopen)
            deps->libs[i].from_dlopen = 0;
        if (replacement_name) {
            free(deps->libs[i].name);
            deps->libs[i].name = replacement_name;
        }
        if (replacement_request)
            deps->libs[i].dlopen_request = replacement_request;
        if (dlopen_direct)
            deps->libs[i].dlopen_direct = 1;
        if (dlopen_pathful)
            deps->libs[i].dlopen_pathful = 1;
        if (needed_pathful)
            deps->libs[i].needed_pathful = 1;
        return 0;
    }

    if (deps->count >= deps->capacity) {
        int nc;

        if (deps->capacity > INT_MAX / 2)
            return -1;
        nc = deps->capacity ? deps->capacity * 2 : 64;
        if ((size_t)nc > SIZE_MAX / sizeof(*deps->libs))
            return -1;
        struct resolved_lib *nl = realloc(deps->libs, nc * sizeof(*nl));
        if (!nl) return -1;
        deps->libs = nl;
        deps->capacity = nc;
    }
    char *new_name = strdup(name);
    char *new_path = strdup(path);
    char *new_logical_path = strdup(logical_path);
    char *new_request = dlopen_request ? strdup(dlopen_request) : NULL;
    if (!new_name || !new_path || !new_logical_path ||
        (dlopen_request && !new_request)) {
        free(new_name);
        free(new_path);
        free(new_logical_path);
        free(new_request);
        return -1;
    }
    deps->libs[deps->count].name        = new_name;
    deps->libs[deps->count].path        = new_path;
    deps->libs[deps->count].logical_path = new_logical_path;
    deps->libs[deps->count].device      = snapshot->device;
    deps->libs[deps->count].inode       = snapshot->inode;
    deps->libs[deps->count].snapshot    = *snapshot;
    deps->libs[deps->count].from_dlopen = from_dlopen;
    deps->libs[deps->count].dlopen_direct = dlopen_direct;
    deps->libs[deps->count].dlopen_pathful = dlopen_pathful;
    deps->libs[deps->count].needed_pathful = needed_pathful;
    deps->libs[deps->count].dlopen_early = 0;
    deps->libs[deps->count].dlopen_request = new_request;
    deps->count++;
    return 1; /* added */
}

/* ------------------------------------------------------------------ */
/*  $ORIGIN expansion                                                 */
/* ------------------------------------------------------------------ */
enum origin_expansion_result {
    ORIGIN_EXPANSION_OK = 0,
    ORIGIN_EXPANSION_TOO_LONG,
    ORIGIN_EXPANSION_UNAVAILABLE,
    ORIGIN_EXPANSION_UNSUPPORTED,
    ORIGIN_EXPANSION_INTERNAL,
};

enum search_path_grammar {
    SEARCH_GNU_ELF,
    SEARCH_GNU_ENV,
    SEARCH_MUSL_RPATH,
    SEARCH_MUSL_RAW,
};

/* Recognize only the token spellings shared by every admitted GNU loader.
 * Official glibc 2.27 accepts an unbraced DST only before NUL or '/', while
 * 2.28 and later use the broader gABI identifier boundary.  Downstream
 * backports make a release-number guess unsafe, so punctuation/adjacent-DST
 * spellings outside this intersection fail closed.  Braces are unambiguous
 * in both implementations. */
static int gnu_dynamic_token_length(const char *input, const char *token,
                                    size_t *length_out)
{
    size_t token_length;

    if (!input || !token || !length_out || input[0] != '$')
        return 0;
    token_length = strlen(token);
    if (input[1] == '{') {
        if (strncmp(input + 2, token, token_length) != 0 ||
            input[token_length + 2] != '}')
            return 0;
        *length_out = token_length + 3;
        return 1;
    }
    if (strncmp(input + 1, token, token_length) != 0 ||
        (input[token_length + 1] != '\0' &&
         input[token_length + 1] != '/'))
        return 0;
    *length_out = token_length + 1;
    return 1;
}

static char *expand_origin(const char *tmpl, const char *origin,
                           enum search_path_grammar grammar,
                           const struct dep_list *deps,
                           size_t output_size,
                           enum origin_expansion_result *result)
{
    char *buf;

    if (result)
        *result = ORIGIN_EXPANSION_OK;
    if (!tmpl || !origin || output_size == 0) {
        if (result)
            *result = ORIGIN_EXPANSION_INTERNAL;
        return NULL;
    }
    buf = malloc(output_size);
    if (!buf) {
        if (result)
            *result = ORIGIN_EXPANSION_INTERNAL;
        return NULL;
    }
    char *d = buf, *end = buf + output_size - 1;
    const char *s = tmpl;
    while (*s) {
        const char *replacement = NULL;
        size_t consumed = 0;

        if (grammar == SEARCH_GNU_ELF || grammar == SEARCH_GNU_ENV) {
            if (gnu_dynamic_token_length(s, "ORIGIN", &consumed)) {
                replacement = origin;
            } else if (gnu_dynamic_token_length(s, "LIB", &consumed)) {
                /* DL_DST_LIB is generated from notdir(slibdir) at glibc
                 * build time.  It is neither an ELF identity nor derivable
                 * from the interpreter pathname (multiarch and custom builds
                 * routinely disagree), so guessing would leak host/distro
                 * policy into target resolution. */
                if (result)
                    *result = ORIGIN_EXPANSION_UNSUPPORTED;
                free(buf);
                return NULL;
            } else if (gnu_dynamic_token_length(
                           s, "PLATFORM", &consumed)) {
                /* AArch64 glibc 2.27--2.44 uses the kernel AT_PLATFORM value
                 * unchanged.  x86-64 may replace it using CPUID, OSXSAVE and
                 * release-specific tunable state, which is not a portable
                 * pack-time target identity. */
                if (deps && deps->target_e_machine == EM_AARCH64 &&
                    deps->gnu_platform && deps->gnu_platform[0]) {
                    replacement = deps->gnu_platform;
                } else if (deps &&
                           deps->target_e_machine == EM_AARCH64) {
                    if (result)
                        *result = ORIGIN_EXPANSION_UNAVAILABLE;
                    free(buf);
                    return NULL;
                } else {
                    if (result)
                        *result = ORIGIN_EXPANSION_UNSUPPORTED;
                    free(buf);
                    return NULL;
                }
            }
        } else if (strncmp(s, "${ORIGIN}", 9) == 0) {
            replacement = origin;
            consumed = 9;
        } else if (strncmp(s, "$ORIGIN", 7) == 0) {
            /* musl substitutes the literal prefix wherever it appears. */
            replacement = origin;
            consumed = 7;
        }

        if (replacement) {
            size_t l = strlen(replacement);
            if (l > (size_t)(end - d)) {
                if (result)
                    *result = ORIGIN_EXPANSION_TOO_LONG;
                free(buf);
                return NULL;
            }
            memcpy(d, replacement, l);
            d += l;
            s += consumed;
        } else if (*s == '$') {
            if (result)
                *result = ORIGIN_EXPANSION_UNSUPPORTED;
            free(buf);
            return NULL;
        } else if (d < end) {
            *d++ = *s++;
        } else {
            if (result)
                *result = ORIGIN_EXPANSION_TOO_LONG;
            free(buf);
            return NULL;
        }
    }
    *d = '\0';
    return buf;
}

/* Each old-style DT_RPATH scope retains the object origin used for token
 * expansion.  Scopes are ordered nearest requester first. */
struct rpath_scope {
    char *path;
    char *origin;
    struct rpath_scope *parent;
};

/* ------------------------------------------------------------------ */
/*  Library search (RPATH → LD_LIBRARY_PATH → RUNPATH → defaults)     */
/* ------------------------------------------------------------------ */
static const char *search_path_separator(const char *start,
                                         enum search_path_grammar grammar)
{
    for (const char *p = start; *p; p++) {
        if (*p == ':')
            return p;
        if (grammar == SEARCH_GNU_ENV && *p == ';')
            return p;
        if ((grammar == SEARCH_MUSL_RPATH ||
             grammar == SEARCH_MUSL_RAW) && *p == '\n')
            return p;
    }
    return NULL;
}

static int musl_rpath_has_unknown_token(const char *path)
{
    const char *cursor = path;

    while (cursor && *cursor) {
        const char *token = strchr(cursor, '$');

        if (!token)
            return 0;
        if (strncmp(token, "$ORIGIN", 7) == 0)
            cursor = token + 7;
        else if (strncmp(token, "${ORIGIN}", 9) == 0)
            cursor = token + 9;
        else
            return 1;
    }
    return 0;
}

/* glibc decomposes and expands a complete path list when it first publishes
 * that object's search metadata.  Apply the conservative admission boundary
 * to every component up front, so an earlier successful directory cannot
 * hide an unrepresentable token in a later component. */
static int gnu_path_tokens_admitted(const char *path,
                                    enum search_path_grammar grammar,
                                    const struct dep_list *deps)
{
    const char *start = path;

    while (start) {
        const char *separator = search_path_separator(start, grammar);
        size_t length = separator ? (size_t)(separator - start)
                                  : strlen(start);
        char *component = strndup(start, length);
        const char *cursor;

        if (!component)
            return -1;
        cursor = component;
        while ((cursor = strchr(cursor, '$')) != NULL) {
            size_t token_length;

            if (gnu_dynamic_token_length(
                    cursor, "ORIGIN", &token_length)) {
                cursor += token_length;
                continue;
            }
            if (gnu_dynamic_token_length(
                    cursor, "PLATFORM", &token_length) && deps &&
                deps->target_e_machine == EM_AARCH64) {
                cursor += token_length;
                continue;
            }
            /* $LIB is a target build constant, and unknown/ambiguous
             * spellings are an intentional fail-closed divergence from
             * native's literal handling. */
            free(component);
            return 0;
        }
        free(component);
        if (!separator)
            break;
        start = separator + 1;
    }
    return 1;
}

static char *search_dirs(const char *name, const char *dirs, const char *origin,
                         const struct dep_list *deps,
                         enum search_path_grammar grammar,
                         enum library_lookup_result *lookup_result,
                         char **logical_path_out,
                         struct dep_file_snapshot *snapshot_out)
{
    if (lookup_result)
        *lookup_result = LIBRARY_LOOKUP_MISS;
    if (logical_path_out)
        *logical_path_out = NULL;
    if (snapshot_out)
        memset(snapshot_out, 0, sizeof(*snapshot_out));
    if (!dirs || !dirs[0]) return NULL;
    if (grammar == SEARCH_GNU_ELF || grammar == SEARCH_GNU_ENV) {
        int token_status = gnu_path_tokens_admitted(dirs, grammar, deps);

        if (token_status <= 0) {
            if (lookup_result)
                *lookup_result = token_status < 0
                    ? LIBRARY_LOOKUP_INTERNAL : LIBRARY_LOOKUP_UNSUPPORTED;
            if (token_status == 0)
                fprintf(stderr,
                        "dlfreeze: unsupported dynamic string token in "
                        "library search path\n");
            return NULL;
        }
    }
    /* musl validates the complete string before publishing p->rpath.  One
     * unknown token discards this object's whole list, including otherwise
     * valid earlier components, then lookup continues with parent/system
     * mechanisms.  GNU's separate token policy remains fail-closed below. */
    if (grammar == SEARCH_MUSL_RPATH &&
        musl_rpath_has_unknown_token(dirs))
        return NULL;
    const char *start = dirs;
    char path[PATH_MAX];
    const int musl_grammar = grammar == SEARCH_MUSL_RPATH ||
                             grammar == SEARCH_MUSL_RAW;
    const size_t candidate_size = musl_grammar
        ? DEP_MUSL_SEARCH_BUFFER_SIZE : sizeof(path);

    for (;;) {
        const char *separator = search_path_separator(start, grammar);
        size_t length = separator ? (size_t)(separator - start) : strlen(start);
        char *tok;
        char *expanded;
        char *candidate;
        int component_would_be_absolute;
        enum candidate_search_context candidate_context =
            CANDIDATE_NON_GNU;
        enum origin_expansion_result expansion_result =
            ORIGIN_EXPANSION_OK;
        enum library_lookup_result candidate_result;

        /* glibc treats an empty path element as the current directory;
         * musl's path parser skips it. */
        if (length == 0 && (grammar == SEARCH_MUSL_RPATH ||
                            grammar == SEARCH_MUSL_RAW))
            goto next;
        tok = length ? strndup(start, length) : strdup(".");
        if (!tok) {
            if (lookup_result)
                *lookup_result = LIBRARY_LOOKUP_INTERNAL;
            return NULL;
        }
        component_would_be_absolute = tok[0] == '/' ||
            ((grammar == SEARCH_GNU_ELF || grammar == SEARCH_GNU_ENV) &&
             origin && origin[0] == '/' &&
             (strncmp(tok, "$ORIGIN", 7) == 0 ||
              strncmp(tok, "${ORIGIN}", 9) == 0));
        if (grammar == SEARCH_MUSL_RAW)
            expanded = strdup(tok);
        else
            expanded = expand_origin(
                tok, origin, grammar, deps, candidate_size,
                &expansion_result);
        free(tok);
        if (!expanded && expansion_result == ORIGIN_EXPANSION_UNSUPPORTED) {
            fprintf(stderr,
                    "dlfreeze: unsupported dynamic string token in "
                    "library search path\n");
            if (lookup_result)
                *lookup_result = LIBRARY_LOOKUP_UNSUPPORTED;
            return NULL;
        }
        if (!expanded && expansion_result == ORIGIN_EXPANSION_UNAVAILABLE)
            goto next;
        if (!expanded && (grammar == SEARCH_MUSL_RAW ||
                          expansion_result == ORIGIN_EXPANSION_INTERNAL)) {
            if (lookup_result)
                *lookup_result = LIBRARY_LOOKUP_INTERNAL;
            return NULL;
        }
        if (!expanded &&
            (grammar == SEARCH_GNU_ELF || grammar == SEARCH_GNU_ENV)) {
            /* Relative GNU directory elements are pre-classified existing.
             * An overlong absolute element cannot name an existing Linux
             * directory and is classified nonexisting, so native open_path
             * advances within this list instead of abandoning the list. */
            if (!component_would_be_absolute) {
                if (lookup_result)
                    *lookup_result = LIBRARY_LOOKUP_NEXT_STAGE;
                return NULL;
            }
            goto next;
        }
        if (!expanded)
            goto next;
        if (grammar == SEARCH_GNU_ELF || grammar == SEARCH_GNU_ENV) {
            struct stat directory_identity;

            /* glibc treats relative search directories as existing.  An
             * absolute directory starts unknown and an unusual candidate
             * failure stops this list only if the directory itself can be
             * classified as an existing directory. */
            candidate_context = (expanded[0] != '/' ||
                (stat(expanded, &directory_identity) == 0 &&
                 S_ISDIR(directory_identity.st_mode)))
                ? CANDIDATE_GNU_DIRECTORY_EXISTING
                : CANDIDATE_GNU_DIRECTORY_NONEXISTING;
        }
        if (snprintf(path, candidate_size, "%s/%s", expanded, name) >=
            (int)candidate_size) {
            free(expanded);
            if (grammar == SEARCH_GNU_ELF || grammar == SEARCH_GNU_ENV) {
                if (candidate_context ==
                    CANDIDATE_GNU_DIRECTORY_EXISTING) {
                    if (lookup_result)
                        *lookup_result = LIBRARY_LOOKUP_NEXT_STAGE;
                    return NULL;
                }
                goto next;
            }
            goto next;
        }
        free(expanded);
        candidate = validated_candidate(
            path, deps, candidate_context,
            &candidate_result,
            logical_path_out, snapshot_out);
        if (candidate) {
            if (lookup_result)
                *lookup_result = LIBRARY_LOOKUP_FOUND;
            return candidate;
        }
        /* GNU open_verify deliberately skips a well-formed ELF for another
         * class or architecture.  musl commits to its first successfully
         * opened pathname, so even an unsupported ABI must stop that search.
         * Every other opened-file rejection is fatal for both families. */
        if (candidate_result == LIBRARY_LOOKUP_INCOMPATIBLE &&
            (grammar == SEARCH_GNU_ELF || grammar == SEARCH_GNU_ENV))
            goto next;
        if (candidate_result == LIBRARY_LOOKUP_NEXT_STAGE) {
            if (lookup_result)
                *lookup_result = candidate_result;
            return NULL;
        }
        if (candidate_result != LIBRARY_LOOKUP_MISS) {
            if (lookup_result)
                *lookup_result = candidate_result;
            return NULL;
        }

next:
        if (!separator)
            break;
        start = separator + 1;
    }
    return NULL;
}

static int initialize_musl_system_path(struct dep_list *deps)
{
    static const char default_musl_path[] =
        "/lib:/usr/local/lib:/usr/lib";
    const char *interp;
    const char *last;
    const char *previous;
    struct stat st;
    size_t prefix_len = 0;
    size_t size;
    size_t offset = 0;
    char config_path[PATH_MAX];
    char arch[64];
    char *contents;
    int fd;

    if (!deps)
        return LIBRARY_LOOKUP_INTERNAL;
    if (deps->musl_system_path_initialized)
        return deps->musl_system_path_status;
    deps->musl_system_path_initialized = 1;
    deps->musl_system_path_status = LIBRARY_LOOKUP_FOUND;
    deps->musl_system_path_size = 0;
    interp = deps->interp_path;
    if (!interp || musl_arch_from_target(deps, arch, sizeof(arch)) < 0) {
        deps->musl_system_path_status = LIBRARY_LOOKUP_UNSUPPORTED;
        return deps->musl_system_path_status;
    }

    /* musl derives the installation prefix from the directory above the
     * interpreter's lib directory.  Thus /lib/ld-musl-*.so uses /etc while
     * /opt/musl/lib/ld-musl-*.so uses /opt/musl/etc. */
    last = interp;
    previous = interp;
    if (interp[0] == '/') {
        for (const char *cursor = interp; *cursor; cursor++) {
            if (*cursor == '/') {
                previous = last;
                last = cursor;
            }
        }
        prefix_len = (size_t)(previous - interp);
        if (prefix_len >= PATH_MAX)
            prefix_len = 0;
    }
    if (snprintf(config_path, sizeof(config_path),
                 "%.*s/etc/ld-musl-%s.path", (int)prefix_len, interp,
                 arch) >= (int)sizeof(config_path)) {
        deps->musl_system_path_status = LIBRARY_LOOKUP_UNSUPPORTED;
        return deps->musl_system_path_status;
    }

    fd = open(config_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            deps->musl_system_path = strdup(default_musl_path);
            if (!deps->musl_system_path)
                deps->musl_system_path_status = LIBRARY_LOOKUP_INTERNAL;
            else
                deps->musl_system_path_size =
                    sizeof(default_musl_path) - 1;
        }
        /* Every non-ENOENT open failure becomes one cached empty path in
         * native musl.  It is neither retried nor replaced by defaults. */
        return deps->musl_system_path_status;
    }

    /* Once musl opens the path file, all later failures likewise publish an
     * empty process-lifetime path.  Snapshot exactly the initial st_size. */
    if (fstat(fd, &st) != 0 || st.st_size < 0 ||
        (uintmax_t)st.st_size > SIZE_MAX - 1) {
        close(fd);
        return deps->musl_system_path_status;
    }
    size = (size_t)st.st_size;
    if (size == 0) {
        close(fd);
        return deps->musl_system_path_status;
    }
    contents = malloc(size + 1);
    if (!contents) {
        close(fd);
        return deps->musl_system_path_status;
    }
    while (offset < size) {
        size_t remaining = size - offset;
        size_t chunk = remaining > (size_t)SSIZE_MAX
            ? (size_t)SSIZE_MAX : remaining;
        ssize_t got = read(fd, contents + offset, chunk);

        if (got > 0) {
            offset += (size_t)got;
            continue;
        }
        if (got < 0 && errno == EINTR)
            continue;
        free(contents);
        close(fd);
        return deps->musl_system_path_status;
    }
    contents[size] = '\0';
    close(fd);
    deps->musl_system_path = contents;
    deps->musl_system_path_size = strnlen(contents, size);
    return deps->musl_system_path_status;
}

static char *resolve_from_musl_system_path(
    const char *name, struct dep_list *deps,
    enum library_lookup_result *result_out, char **logical_path_out,
    struct dep_file_snapshot *snapshot_out)
{
    int status;

    if (result_out)
        *result_out = LIBRARY_LOOKUP_MISS;
    status = initialize_musl_system_path(deps);
    if (status < 0) {
        if (result_out)
            *result_out = status;
        return NULL;
    }
    return search_dirs(name,
                       deps->musl_system_path
                           ? deps->musl_system_path : "",
                       deps->main_origin, deps, SEARCH_MUSL_RAW,
                       result_out, logical_path_out, snapshot_out);
}

static char *find_library(const char *name,
                          const char *rpath, const char *runpath,
                          const char *origin,
                          const struct rpath_scope *inherited_rpath,
                          uint64_t flags_1,
                          struct dep_list *deps,
                          int diagnostics,
                          enum library_lookup_result *lookup_result,
                          char **logical_path_out,
                          struct dep_file_snapshot *snapshot_out)
{
    const char *ldp = getenv("LD_LIBRARY_PATH");
    int musl_search = deps->runtime_family == DEP_RUNTIME_MUSL;
    enum library_lookup_result search_result;
    char *p;

    if (lookup_result)
        *lookup_result = LIBRARY_LOOKUP_MISS;
    if (logical_path_out)
        *logical_path_out = NULL;
    if (snapshot_out)
        memset(snapshot_out, 0, sizeof(*snapshot_out));
    /* A DT_NEEDED name containing a slash is a pathname, not a soname. */
    if (strchr(name, '/'))
        return validated_candidate(name, deps, CANDIDATE_NON_GNU,
                                   lookup_result,
                                   logical_path_out, snapshot_out);

    if (musl_search) {
        /* musl searches the environment first, then walks the requesting
         * object's unified RPATH/RUNPATH ancestry.  It does not expand
         * dynamic-string tokens in LD_LIBRARY_PATH. */
        if (ldp && ldp[0]) {
            p = search_dirs(name, ldp, deps->main_origin, deps,
                            SEARCH_MUSL_RAW, &search_result,
                            logical_path_out, snapshot_out);
            if (p || search_result < 0) {
                if (lookup_result) *lookup_result = search_result;
                return p;
            }
        }
        /* musl gives DT_RUNPATH precedence by tag presence, including an
         * empty string.  Do not resurrect DT_RPATH merely because the
         * selected DT_RUNPATH contributes no directories. */
        if (runpath) {
            if (runpath[0]) {
                p = search_dirs(name, runpath, origin, deps,
                                SEARCH_MUSL_RPATH, &search_result,
                                logical_path_out, snapshot_out);
                if (p || search_result < 0) {
                    if (lookup_result) *lookup_result = search_result;
                    return p;
                }
            }
        } else if (rpath && rpath[0]) {
            p = search_dirs(name, rpath, origin, deps,
                            SEARCH_MUSL_RPATH, &search_result,
                            logical_path_out, snapshot_out);
            if (p || search_result < 0) {
                if (lookup_result) *lookup_result = search_result;
                return p;
            }
        }
        for (const struct rpath_scope *scope = inherited_rpath;
             scope; scope = scope->parent) {
            p = search_dirs(name, scope->path, scope->origin, deps,
                            SEARCH_MUSL_RPATH, &search_result,
                            logical_path_out, snapshot_out);
            if (p || search_result < 0) {
                if (lookup_result) *lookup_result = search_result;
                return p;
            }
        }
    } else {
        /* GNU-style DT_RPATH is inherited, while DT_RUNPATH is limited to
         * the requester's direct DT_NEEDED entries. */
        if (!runpath) {
            if (rpath && rpath[0]) {
                p = search_dirs(name, rpath, origin, deps, SEARCH_GNU_ELF,
                                &search_result, logical_path_out,
                                snapshot_out);
                if (p || search_result < 0) {
                    if (lookup_result) *lookup_result = search_result;
                    return p;
                }
            }
            for (const struct rpath_scope *scope = inherited_rpath;
                 scope; scope = scope->parent) {
                p = search_dirs(name, scope->path, scope->origin, deps,
                                SEARCH_GNU_ELF, &search_result,
                                logical_path_out, snapshot_out);
                if (p || search_result < 0) {
                    if (lookup_result) *lookup_result = search_result;
                    return p;
                }
            }
        }
        if (ldp && ldp[0]) {
            p = search_dirs(name, ldp, deps->main_origin, deps,
                            SEARCH_GNU_ENV, &search_result,
                            logical_path_out, snapshot_out);
            if (p || search_result < 0) {
                if (lookup_result) *lookup_result = search_result;
                return p;
            }
        }
        if (runpath) {
            p = search_dirs(name, runpath, origin, deps, SEARCH_GNU_ELF,
                            &search_result, logical_path_out,
                            snapshot_out);
            if (p || search_result < 0) {
                if (lookup_result) *lookup_result = search_result;
                return p;
            }
        }
    }

    /* A musl path file replaces, rather than augments, the compiled-in
     * system path.  It is located relative to a non-system interpreter
     * prefix; there is no independent "interpreter directory" search. */
    if (musl_search)
        return resolve_from_musl_system_path(name, deps, lookup_result,
                                             logical_path_out, snapshot_out);

    /* The GNU cache is meaningful only for that loader family.  A cache miss
     * would fall through to glibc's private compiled directory table; no
     * stable ELF/cache field describes that table, so do not guess it. */
    if (deps->runtime_family == DEP_RUNTIME_GNU) {
        int cache_status;

        if (flags_1 & DF_1_NODEFLIB) {
            /* glibc may admit a non-default cache entry here only after
             * classifying it against its private system-directory table.
             * Without that private table, either choice could be wrong. */
            if (diagnostics)
                fprintf(stderr,
                        "dlfreeze: uncaptured GNU DF_1_NODEFLIB cache lookup "
                        "cannot be classified safely: %s\n",
                        name);
            if (lookup_result)
                *lookup_result = LIBRARY_LOOKUP_UNSUPPORTED;
            return NULL;
        }
        p = resolve_from_gnu_cache(name, deps, &cache_status,
                                   logical_path_out, snapshot_out);
        if (p) {
            if (lookup_result)
                *lookup_result = LIBRARY_LOOKUP_FOUND;
            return p;
        }
        if (lookup_result) {
            if (cache_status == GNU_CACHE_MISS)
                *lookup_result = LIBRARY_LOOKUP_MISS;
            else if (cache_status == GNU_CACHE_UNREADABLE)
                *lookup_result = LIBRARY_LOOKUP_UNREADABLE;
            else if (cache_status == GNU_CACHE_MALFORMED)
                *lookup_result = LIBRARY_LOOKUP_MALFORMED;
            else
                *lookup_result = LIBRARY_LOOKUP_INTERNAL;
        }
        if (!diagnostics)
            return NULL;
        if (cache_status == GNU_CACHE_UNREADABLE)
            fprintf(stderr,
                    "dlfreeze: GNU runtime cache cannot be read: %s\n",
                    deps->gnu_cache_path ? deps->gnu_cache_path : "(unknown)");
        else if (cache_status == GNU_CACHE_MALFORMED)
            fprintf(stderr,
                    "dlfreeze: GNU runtime cache is malformed or selected "
                    "an incompatible object: %s\n",
                    deps->gnu_cache_path ? deps->gnu_cache_path : "(unknown)");
        else if (cache_status == GNU_CACHE_INTERNAL)
            fprintf(stderr,
                    "dlfreeze: GNU runtime cache lookup failed internally: %s\n",
                    deps->gnu_cache_path ? deps->gnu_cache_path : "(unknown)");
        else if (cache_status == GNU_CACHE_MISS)
            fprintf(stderr,
                    "dlfreeze: %s is absent from the GNU runtime cache; "
                    "compiled default directories cannot be inferred "
                    "safely\n",
                    name);
        else
            fprintf(stderr,
                    "dlfreeze: invalid GNU runtime cache lookup state: %s\n",
                    name);
        return NULL;
    }
    if (lookup_result)
        *lookup_result = LIBRARY_LOOKUP_UNSUPPORTED;
    return NULL;
}

/* An old-style DT_RPATH applies to the requester's entire descendant
 * closure.  Keep each entry with the object and origin which supplied it so
 * $ORIGIN remains relative to that ancestor, not whichever child happens to
 * need a library. */
static void rpath_scope_free(struct rpath_scope *scope)
{
    while (scope) {
        struct rpath_scope *next = scope->parent;

        free(scope->path);
        free(scope->origin);
        free(scope);
        scope = next;
    }
}

static struct rpath_scope *rpath_scope_clone(
    const struct rpath_scope *scope)
{
    struct rpath_scope *copy = NULL;
    struct rpath_scope **tail = &copy;

    while (scope) {
        struct rpath_scope *node = calloc(1, sizeof(*node));

        if (!node)
            goto fail;
        node->path = strdup(scope->path);
        node->origin = strdup(scope->origin);
        if (!node->path || !node->origin) {
            free(node->path);
            free(node->origin);
            free(node);
            goto fail;
        }
        *tail = node;
        tail = &node->parent;
        scope = scope->parent;
    }
    return copy;

fail:
    rpath_scope_free(copy);
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  BFS queue                                                         */
/* ------------------------------------------------------------------ */
struct bfs_item {
    char *path;
    char *logical_path;
    struct dep_file_snapshot snapshot;
    struct rpath_scope *inherited_rpath;
};

struct trace_process_identity {
    uint64_t pid;
    dev_t device;
    ino_t inode;
};

struct trace_loader_operation {
    uint64_t pid;
    uint64_t attempt;
    uint64_t evidence_count;
    char kind;
};

struct trace_descriptor_operation {
    uint64_t pid;
    uint64_t attempt;
};

struct trace_initial_identity {
    struct dep_file_snapshot snapshot;
};

#define TRACE_PROCESS_IDENTITY_LIMIT 65536
#define TRACE_PENDING_EXEC_LIMIT 4096

struct bfs_queue {
    struct bfs_item *items;
    int    head, tail, cap;
    struct trace_process_identity *trace_identities;
    int trace_identity_count;
    int trace_identity_capacity;
    uint64_t *pending_exec_attempts;
    int pending_exec_count;
    int pending_exec_capacity;
    struct trace_loader_operation *loader_operations;
    int loader_operation_count;
    int loader_operation_capacity;
    struct trace_descriptor_operation *descriptor_operations;
    int descriptor_operation_count;
    int descriptor_operation_capacity;
    struct trace_initial_identity *initial_identities;
    int initial_identity_count;
    int initial_identity_capacity;
};

static int bfs_init(struct bfs_queue *q)
{
    q->cap   = 256;
    q->items = calloc((size_t)q->cap, sizeof(*q->items));
    q->head  = q->tail = 0;
    q->trace_identities = NULL;
    q->trace_identity_count = 0;
    q->trace_identity_capacity = 0;
    q->pending_exec_attempts = NULL;
    q->pending_exec_count = 0;
    q->pending_exec_capacity = 0;
    q->loader_operations = NULL;
    q->loader_operation_count = 0;
    q->loader_operation_capacity = 0;
    q->descriptor_operations = NULL;
    q->descriptor_operation_count = 0;
    q->descriptor_operation_capacity = 0;
    q->initial_identities = NULL;
    q->initial_identity_count = 0;
    q->initial_identity_capacity = 0;
    return q->items ? 0 : -1;
}

/* Return one only for the first observation of this mapped-file identity in
 * a traced process.  Fork records can interleave, so a global first-seen bit
 * or adjacency test cannot establish which $ORIGIN closure that process had
 * already inherited. */
static int bfs_trace_identity_first(
    struct bfs_queue *q, uint64_t pid,
    const struct dep_file_snapshot *snapshot)
{
    if (!q || pid == 0 || !snapshot || !snapshot->valid)
        return -1;
    for (int i = 0; i < q->trace_identity_count; i++) {
        if (q->trace_identities[i].pid == pid &&
            q->trace_identities[i].device == snapshot->device &&
            q->trace_identities[i].inode == snapshot->inode)
            return 0;
    }
    if (q->trace_identity_count >= TRACE_PROCESS_IDENTITY_LIMIT)
        return -1;
    if (q->trace_identity_count >= q->trace_identity_capacity) {
        int new_capacity;
        struct trace_process_identity *new_identities;

        if (q->trace_identity_capacity > INT_MAX / 2)
            return -1;
        new_capacity = q->trace_identity_capacity
            ? q->trace_identity_capacity * 2 : 64;
        if ((size_t)new_capacity > SIZE_MAX / sizeof(*new_identities))
            return -1;
        new_identities = realloc(
            q->trace_identities,
            (size_t)new_capacity * sizeof(*new_identities));
        if (!new_identities)
            return -1;
        q->trace_identities = new_identities;
        q->trace_identity_capacity = new_capacity;
    }
    q->trace_identities[q->trace_identity_count].pid = pid;
    q->trace_identities[q->trace_identity_count].device = snapshot->device;
    q->trace_identities[q->trace_identity_count].inode = snapshot->inode;
    q->trace_identity_count++;
    return 1;
}

static int bfs_exec_attempt_update(struct bfs_queue *q, uint64_t attempt,
                                   int begin)
{
    int index;

    if (!q || attempt == 0)
        return -1;
    for (index = 0; index < q->pending_exec_count; index++) {
        if (q->pending_exec_attempts[index] == attempt)
            break;
    }
    if (!begin) {
        if (index == q->pending_exec_count)
            return -1;
        q->pending_exec_count--;
        q->pending_exec_attempts[index] =
            q->pending_exec_attempts[q->pending_exec_count];
        return 0;
    }
    if (index != q->pending_exec_count ||
        q->pending_exec_count >= TRACE_PENDING_EXEC_LIMIT)
        return -1;
    if (q->pending_exec_count >= q->pending_exec_capacity) {
        int new_capacity = q->pending_exec_capacity
            ? q->pending_exec_capacity * 2 : 16;
        uint64_t *new_attempts;

        if (new_capacity > TRACE_PENDING_EXEC_LIMIT)
            new_capacity = TRACE_PENDING_EXEC_LIMIT;
        new_attempts = realloc(q->pending_exec_attempts,
                               (size_t)new_capacity *
                                   sizeof(*new_attempts));
        if (!new_attempts)
            return -1;
        q->pending_exec_attempts = new_attempts;
        q->pending_exec_capacity = new_capacity;
    }
    q->pending_exec_attempts[q->pending_exec_count++] = attempt;
    return 0;
}

static int bfs_descriptor_operation_update(
    struct bfs_queue *q, uint64_t pid, uint64_t attempt, int begin)
{
    int index;

    if (!q || pid == 0 || attempt == 0)
        return -1;
    for (index = 0; index < q->descriptor_operation_count; index++) {
        if (q->descriptor_operations[index].pid == pid &&
            q->descriptor_operations[index].attempt == attempt)
            break;
    }
    if (!begin) {
        if (index == q->descriptor_operation_count)
            return -1;
        q->descriptor_operation_count--;
        q->descriptor_operations[index] =
            q->descriptor_operations[q->descriptor_operation_count];
        return 0;
    }
    if (index != q->descriptor_operation_count ||
        q->descriptor_operation_count >= TRACE_PENDING_EXEC_LIMIT)
        return -1;
    if (q->descriptor_operation_count >=
        q->descriptor_operation_capacity) {
        int new_capacity = q->descriptor_operation_capacity
            ? q->descriptor_operation_capacity * 2 : 16;
        struct trace_descriptor_operation *operations;

        if (new_capacity > TRACE_PENDING_EXEC_LIMIT)
            new_capacity = TRACE_PENDING_EXEC_LIMIT;
        operations = realloc(q->descriptor_operations,
                             (size_t)new_capacity * sizeof(*operations));
        if (!operations)
            return -1;
        q->descriptor_operations = operations;
        q->descriptor_operation_capacity = new_capacity;
    }
    q->descriptor_operations[q->descriptor_operation_count].pid = pid;
    q->descriptor_operations[q->descriptor_operation_count].attempt =
        attempt;
    q->descriptor_operation_count++;
    return 0;
}

static struct trace_loader_operation *bfs_loader_operation_find(
    struct bfs_queue *q, uint64_t pid, uint64_t attempt)
{
    if (!q)
        return NULL;
    for (int index = 0; index < q->loader_operation_count; index++) {
        if (q->loader_operations[index].pid == pid &&
            q->loader_operations[index].attempt == attempt)
            return &q->loader_operations[index];
    }
    return NULL;
}

static int bfs_loader_operation_begin(
    struct bfs_queue *q, uint64_t pid, uint64_t attempt, char kind)
{
    struct trace_loader_operation *operations;
    int capacity;

    if (!q || pid == 0 || attempt == 0 || (kind != 'A' && kind != 'B') ||
        bfs_loader_operation_find(q, pid, attempt) ||
        q->loader_operation_count >= TRACE_PENDING_EXEC_LIMIT)
        return -1;
    if (q->loader_operation_count >= q->loader_operation_capacity) {
        capacity = q->loader_operation_capacity
            ? q->loader_operation_capacity * 2 : 16;
        if (capacity > TRACE_PENDING_EXEC_LIMIT)
            capacity = TRACE_PENDING_EXEC_LIMIT;
        operations = realloc(q->loader_operations,
                             (size_t)capacity * sizeof(*operations));
        if (!operations)
            return -1;
        q->loader_operations = operations;
        q->loader_operation_capacity = capacity;
    }
    q->loader_operations[q->loader_operation_count].pid = pid;
    q->loader_operations[q->loader_operation_count].attempt = attempt;
    q->loader_operations[q->loader_operation_count].evidence_count = 0;
    q->loader_operations[q->loader_operation_count].kind = kind;
    q->loader_operation_count++;
    return 0;
}

static int bfs_loader_operation_evidence(
    struct bfs_queue *q, uint64_t pid, uint64_t attempt, char kind)
{
    struct trace_loader_operation *operation =
        bfs_loader_operation_find(q, pid, attempt);

    if (!operation || operation->kind != kind ||
        operation->evidence_count == UINT64_MAX)
        return -1;
    operation->evidence_count++;
    return 0;
}

static int bfs_loader_operation_commit(
    struct bfs_queue *q, uint64_t pid, uint64_t attempt, char kind,
    uint64_t evidence_count)
{
    struct trace_loader_operation *operation =
        bfs_loader_operation_find(q, pid, attempt);
    int index;

    if (!operation || operation->kind != kind ||
        operation->evidence_count != evidence_count)
        return -1;
    index = (int)(operation - q->loader_operations);
    q->loader_operation_count--;
    q->loader_operations[index] =
        q->loader_operations[q->loader_operation_count];
    return 0;
}

static int trace_snapshots_equal(const struct dep_file_snapshot *left,
                                 const struct dep_file_snapshot *right)
{
    return left && right && left->valid && right->valid &&
           left->device == right->device && left->inode == right->inode &&
           left->size == right->size &&
           left->mtime_sec == right->mtime_sec &&
           left->mtime_nsec == right->mtime_nsec &&
           left->ctime_sec == right->ctime_sec &&
           left->ctime_nsec == right->ctime_nsec;
}

static int trace_initial_snapshot_expected(
    const struct dep_list *deps, const struct dep_file_snapshot *snapshot)
{
    if (!deps || !snapshot || !snapshot->valid)
        return 0;
    if (trace_snapshots_equal(&deps->main_snapshot, snapshot) ||
        trace_snapshots_equal(&deps->interp_snapshot, snapshot))
        return 1;
    for (int index = 0; index < deps->count; index++) {
        if (!deps->libs[index].from_dlopen &&
            trace_snapshots_equal(&deps->libs[index].snapshot, snapshot))
            return 1;
    }
    return 0;
}

static int bfs_initial_identity_add(
    struct bfs_queue *q, const struct dep_list *deps,
    const struct dep_file_snapshot *snapshot)
{
    struct trace_initial_identity *identities;
    int capacity;

    if (!q || !trace_initial_snapshot_expected(deps, snapshot))
        return -1;
    for (int index = 0; index < q->initial_identity_count; index++) {
        if (trace_snapshots_equal(
                &q->initial_identities[index].snapshot, snapshot))
            return -1;
    }
    if (q->initial_identity_count >= TRACE_PROCESS_IDENTITY_LIMIT)
        return -1;
    if (q->initial_identity_count >= q->initial_identity_capacity) {
        capacity = q->initial_identity_capacity
            ? q->initial_identity_capacity * 2 : 16;
        if (capacity > TRACE_PROCESS_IDENTITY_LIMIT)
            capacity = TRACE_PROCESS_IDENTITY_LIMIT;
        identities = realloc(q->initial_identities,
                             (size_t)capacity * sizeof(*identities));
        if (!identities)
            return -1;
        q->initial_identities = identities;
        q->initial_identity_capacity = capacity;
    }
    q->initial_identities[q->initial_identity_count++].snapshot = *snapshot;
    return 0;
}

static int bfs_initial_snapshot_seen(
    const struct bfs_queue *q, const struct dep_file_snapshot *snapshot)
{
    if (!q || !snapshot)
        return 0;
    for (int index = 0; index < q->initial_identity_count; index++) {
        if (trace_snapshots_equal(
                snapshot, &q->initial_identities[index].snapshot))
            return 1;
    }
    return 0;
}

static int bfs_initial_evidence_is_complete(
    const struct bfs_queue *q, const struct dep_list *deps)
{
    if (!q || !deps || q->initial_identity_count == 0)
        return 0;
    if (!bfs_initial_snapshot_seen(q, &deps->main_snapshot) ||
        !bfs_initial_snapshot_seen(q, &deps->interp_snapshot))
        return 0;
    for (int index = 0; index < deps->count; index++) {
        if (!deps->libs[index].from_dlopen &&
            !bfs_initial_snapshot_seen(q, &deps->libs[index].snapshot))
            return 0;
    }
    return 1;
}

static int bfs_push(struct bfs_queue *q, const char *path,
                    const char *logical_path,
                    const struct dep_file_snapshot *snapshot,
                    const struct rpath_scope *inherited_rpath)
{
    if (!snapshot || !snapshot->valid)
        return -1;
    if (q->tail >= q->cap) {
        int new_cap;

        if (q->cap > INT_MAX / 2)
            return -1;
        new_cap = q->cap * 2;
        if ((size_t)new_cap > SIZE_MAX / sizeof(*q->items))
            return -1;
        struct bfs_item *new_items = realloc(
            q->items, (size_t)new_cap * sizeof(*new_items));
        if (!new_items)
            return -1;
        memset(new_items + q->cap, 0,
               (size_t)(new_cap - q->cap) * sizeof(*new_items));
        q->items = new_items;
        q->cap = new_cap;
    }
    q->items[q->tail].path = strdup(path);
    if (!q->items[q->tail].path)
        return -1;
    q->items[q->tail].logical_path = strdup(
        logical_path ? logical_path : path);
    if (!q->items[q->tail].logical_path) {
        free(q->items[q->tail].path);
        q->items[q->tail].path = NULL;
        return -1;
    }
    q->items[q->tail].snapshot = *snapshot;
    if (inherited_rpath) {
        q->items[q->tail].inherited_rpath =
            rpath_scope_clone(inherited_rpath);
        if (!q->items[q->tail].inherited_rpath) {
            free(q->items[q->tail].path);
            free(q->items[q->tail].logical_path);
            q->items[q->tail].path = NULL;
            q->items[q->tail].logical_path = NULL;
            return -1;
        }
    }
    q->tail++;
    return 0;
}

static int bfs_pop(struct bfs_queue *q, struct bfs_item *item)
{
    if (q->head >= q->tail)
        return 0;
    *item = q->items[q->head];
    memset(&q->items[q->head], 0, sizeof(q->items[q->head]));
    q->head++;
    return 1;
}

static void bfs_item_free(struct bfs_item *item)
{
    free(item->path);
    free(item->logical_path);
    rpath_scope_free(item->inherited_rpath);
    memset(item, 0, sizeof(*item));
}

static void bfs_free(struct bfs_queue *q)
{
    for (int i = q->head; i < q->tail; i++) {
        free(q->items[i].path);
        free(q->items[i].logical_path);
        rpath_scope_free(q->items[i].inherited_rpath);
    }
    free(q->items);
    free(q->trace_identities);
    free(q->pending_exec_attempts);
    free(q->loader_operations);
    free(q->descriptor_operations);
    free(q->initial_identities);
    q->items = NULL;
    q->trace_identities = NULL;
    q->pending_exec_attempts = NULL;
    q->loader_operations = NULL;
    q->descriptor_operations = NULL;
    q->initial_identities = NULL;
    q->head = q->tail = q->cap = 0;
    q->trace_identity_count = q->trace_identity_capacity = 0;
    q->pending_exec_count = q->pending_exec_capacity = 0;
    q->loader_operation_count = q->loader_operation_capacity = 0;
    q->descriptor_operation_count =
        q->descriptor_operation_capacity = 0;
    q->initial_identity_count = q->initial_identity_capacity = 0;
}

static const struct rpath_scope *rpath_scope_for_children(
    struct elf_info *info, char *origin, const struct dep_list *deps,
    const struct rpath_scope *inherited_rpath,
    struct rpath_scope *own_scope)
{
    char *inherited_path = NULL;

    if (deps->runtime_family == DEP_RUNTIME_MUSL) {
        if (info->runpath) {
            if (info->runpath[0])
                inherited_path = info->runpath;
        } else if (info->rpath && info->rpath[0]) {
            inherited_path = info->rpath;
        }
    } else if (!info->runpath && info->rpath && info->rpath[0]) {
        inherited_path = info->rpath;
    }
    if (!inherited_path)
        return inherited_rpath;
    own_scope->path = inherited_path;
    own_scope->origin = origin;
    own_scope->parent = (struct rpath_scope *)inherited_rpath;
    return own_scope;
}

static int dependency_snapshot_index(
    const struct dep_list *deps,
    const struct dep_file_snapshot *snapshot);

/* ------------------------------------------------------------------ */
/*  Resolve all transitive deps of one ELF into deps                  */
/* ------------------------------------------------------------------ */
static int resolve_needed(struct elf_info *info, char *origin,
                          struct dep_list *deps, struct bfs_queue *q,
                          int dlopen_flag,
                          const struct rpath_scope *inherited_rpath)
{
    struct rpath_scope own_scope;
    const struct rpath_scope *child_inherited = rpath_scope_for_children(
        info, origin, deps, inherited_rpath, &own_scope);

    for (int i = 0; i < info->needed_count; i++) {
        const char *name = info->needed[i];
        int interpreter_dependency = is_interpreter_dependency(name, deps);
        int musl_self_dependency =
            musl_dependency_is_self(name, deps);

        if (is_kernel_virtual_lib(name) ||
            (interpreter_dependency &&
             deps->runtime_family != DEP_RUNTIME_MUSL))
            continue;
        if (strchr(name, '$')) {
            fprintf(stderr,
                    "dlfreeze: dynamic string tokens in DT_NEEDED names "
                    "are unsupported: %s\n",
                    name);
            return -1;
        }

        /* musl's interpreter is its libc provider.  Resolve this special
         * self-edge to PT_INTERP itself, never through environment/search
         * paths which could select a different same-named object. */
        char *logical_path = NULL;
        struct dep_file_snapshot snapshot = {0};
        char *path = musl_self_dependency
            ? validated_candidate(deps->interp_path, deps,
                                  CANDIDATE_NON_GNU, NULL,
                                  &logical_path, &snapshot)
            : find_library(name, info->rpath, info->runpath, origin,
                           inherited_rpath, info->flags_1, deps, 1, NULL,
                           &logical_path, &snapshot);
        if (!path) {
            free(logical_path);
            fprintf(stderr,
                    "dlfreeze: required library not found or incompatible: %s\n",
                    name);
            return -1;
        }
        int identity_was_known =
            dependency_snapshot_index(deps, &snapshot) >= 0;
        int added = dep_list_add(deps,
                                 musl_self_dependency ? "libc.so" : name,
                                 path, logical_path, &snapshot,
                                 dlopen_flag, 0, 0,
                                 !musl_self_dependency &&
                                     strchr(name, '/') != NULL,
                                 NULL);
        if (added > 0 && !identity_was_known &&
            bfs_push(q, path, logical_path, &snapshot,
                                  child_inherited) < 0) {
            free(logical_path);
            free(path);
            return -1;
        }
        free(logical_path);
        free(path);
        if (added < 0)
            return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Public: resolve all deps                                          */
/* ------------------------------------------------------------------ */
int dep_resolve(const char *exe_path, struct dep_list *deps)
{
    char gnu_cache_path[PATH_MAX];

    if (!exe_path || !exe_path[0] || !deps) {
        errno = EINVAL;
        return -1;
    }
    memset(deps, 0, sizeof(*deps));
    deps->gnu_release_minor = -1;
    gnu_cache_path[0] = '\0';

    char *real = realpath(exe_path, NULL);
    if (!real) { perror(exe_path); return -1; }

    char *dir_tmp = strdup(real);
    char *origin  = dir_tmp ? strdup(dirname(dir_tmp)) : NULL;
    free(dir_tmp);
    if (!origin) { free(real); return -1; }

    struct elf_info info;
    if (elf_parse_path_snapshot(
            real, NULL, &info, &deps->main_snapshot) < 0) {
        fprintf(stderr, "dlfreeze: failed to parse %s\n", real);
        free(origin); free(real);
        return -1;
    }

    if (!info.is_dynamic) {
        fprintf(stderr, "dlfreeze: %s is not dynamically linked\n", real);
        elf_info_free(&info);
        free(origin); free(real);
        return -1;
    }

    deps->target_ei_class = info.ei_class;
    deps->target_e_machine = info.e_machine;

    if (info.interp && info.interp[0]) {
        struct elf_info interp_info = {0};

        if (elf_parse_path_snapshot(
                info.interp, NULL, &interp_info,
                &deps->interp_snapshot) < 0 ||
            !elf_info_matches_target(&interp_info, deps)) {
            fprintf(stderr,
                    "dlfreeze: interpreter is missing, invalid, or incompatible: %s\n",
                    info.interp);
            elf_info_free(&interp_info);
            elf_info_free(&info);
            free(origin); free(real);
            return -1;
        }
        deps->interp_path = strdup(info.interp);
        if (!deps->interp_path) {
            elf_info_free(&interp_info);
            elf_info_free(&info);
            free(origin); free(real);
            return -1;
        }
        deps->runtime_family =
            detect_interpreter_family(deps->interp_path,
                                      &deps->interp_snapshot,
                                      gnu_cache_path,
                                      &deps->gnu_release_minor);
        if (deps->runtime_family == DEP_RUNTIME_UNKNOWN) {
            fprintf(stderr,
                    "dlfreeze: unsupported target dynamic-linker search ABI: %s\n",
                    deps->interp_path);
            elf_info_free(&interp_info);
            elf_info_free(&info);
            free(origin); free(real);
            dep_list_free(deps);
            return -1;
        }
        if (initialize_gnu_platform(deps) < 0) {
            elf_info_free(&interp_info);
            elf_info_free(&info);
            free(origin); free(real);
            dep_list_free(deps);
            return -1;
        }
        if (deps->runtime_family == DEP_RUNTIME_GNU &&
            (!interp_info.soname || !interp_info.soname[0])) {
            fprintf(stderr,
                    "dlfreeze: target interpreter has no exact "
                    "DT_SONAME identity: %s\n",
                    deps->interp_path);
            elf_info_free(&interp_info);
            elf_info_free(&info);
            free(origin); free(real);
            dep_list_free(deps);
            return -1;
        }
        deps->interp_soname = interp_info.soname
            ? strdup(interp_info.soname) : NULL;
        elf_info_free(&interp_info);
        if (deps->runtime_family == DEP_RUNTIME_GNU &&
            !deps->interp_soname) {
            elf_info_free(&info);
            free(origin); free(real);
            dep_list_free(deps);
            return -1;
        }
        if (deps->runtime_family == DEP_RUNTIME_GNU) {
            deps->gnu_cache_path = strdup(gnu_cache_path);
            if (!deps->gnu_cache_path) {
                elf_info_free(&info);
                free(origin); free(real);
                dep_list_free(deps);
                return -1;
            }
        }
    }

    deps->main_origin = strdup(origin);
    if (!deps->main_origin) {
        elf_info_free(&info);
        free(origin);
        free(real);
        dep_list_free(deps);
        return -1;
    }
    /* glibc maps an LD_PRELOAD object with the main executable as its
     * l_loader.  Consequently an old-dtags main-object DT_RPATH participates
     * in the preload's DT_NEEDED ancestry; DT_RUNPATH deliberately does not.
     * Retain the exact dynamic string and its own $ORIGIN for auxiliary
     * compatibility checks without adding anything to the packaged closure. */
    if (deps->runtime_family == DEP_RUNTIME_GNU && !info.runpath &&
        info.rpath && info.rpath[0]) {
        deps->main_rpath = strdup(info.rpath);
        if (!deps->main_rpath) {
            elf_info_free(&info);
            free(origin);
            free(real);
            dep_list_free(deps);
            return -1;
        }
    }

    struct bfs_queue q;
    if (bfs_init(&q) < 0) {
        elf_info_free(&info);
        free(origin); free(real);
        dep_list_free(deps);
        return -1;
    }

    if (resolve_needed(&info, origin, deps, &q, 0, NULL) < 0) {
        elf_info_free(&info);
        bfs_free(&q);
        free(origin); free(real);
        dep_list_free(deps);
        return -1;
    }
    elf_info_free(&info);

    /* BFS: process transitive deps */
    struct bfs_item item;
    while (bfs_pop(&q, &item)) {
        char *lib_path = item.path;
        struct elf_info li;
        if (elf_parse_path_snapshot(lib_path, &item.snapshot, &li, NULL) < 0 ||
            !li.is_dynamic ||
            li.ei_class != deps->target_ei_class ||
            li.e_machine != deps->target_e_machine) {
            fprintf(stderr,
                    "dlfreeze: resolved library became invalid or incompatible: %s\n",
                    lib_path);
            elf_info_free(&li);
            bfs_item_free(&item);
            bfs_free(&q);
            free(origin); free(real);
            dep_list_free(deps);
            return -1;
        }

        char *dt = strdup(item.logical_path);
        char *lo = dt ? strdup(dirname(dt)) : NULL;
        if (!dt || !lo ||
            resolve_needed(&li, lo, deps, &q, 0,
                           item.inherited_rpath) < 0) {
            free(lo); free(dt);
            elf_info_free(&li);
            bfs_item_free(&item);
            bfs_free(&q);
            free(origin); free(real);
            dep_list_free(deps);
            return -1;
        }
        free(lo); free(dt);
        elf_info_free(&li);
        bfs_item_free(&item);
    }
    bfs_free(&q);

    free(origin);
    free(real);
    return 0;
}

int dep_resolve_aux_dependency(struct dep_list *deps,
                               const char *requester_path,
                               const char *name, char **path_out)
{
    struct elf_info info = {0};
    char *real = NULL;
    char *dir_copy = NULL;
    char *origin = NULL;
    char *resolved = NULL;
    struct rpath_scope main_scope = {0};
    const struct rpath_scope *inherited_rpath = NULL;
    enum library_lookup_result lookup_result;
    struct dep_file_snapshot snapshot;
    int musl_self_dependency;
    int result = -1;

    if (path_out)
        *path_out = NULL;
    if (!deps || !requester_path || !requester_path[0] || !name ||
        !name[0] || !path_out || strchr(name, '$'))
        return -1;

    real = realpath(requester_path, NULL);
    if (!real || elf_parse_path_snapshot(real, NULL, &info, NULL) < 0 ||
        !info.is_dynamic ||
        info.ei_class != deps->target_ei_class ||
        info.e_machine != deps->target_e_machine)
        goto out;
    /* Parse/snapshot through the canonical source, but DT_ORIGIN belongs to
     * the loader-visible requester spelling (ordinary DSOs are not given the
     * main executable's /proc/self/exe canonicalization policy). */
    dir_copy = strdup(requester_path);
    origin = dir_copy ? strdup(dirname(dir_copy)) : NULL;
    if (!origin)
        goto out;

    if (deps->runtime_family == DEP_RUNTIME_GNU && deps->main_rpath &&
        deps->main_rpath[0] && deps->main_origin) {
        main_scope.path = deps->main_rpath;
        main_scope.origin = deps->main_origin;
        inherited_rpath = &main_scope;
    }
    /* The musl interpreter is also its libc provider.  Its reserved self
     * names bind to the already-loaded PT_INTERP object before filesystem
     * search, including when that exact runtime was copied or renamed.  Keep
     * auxiliary helper resolution consistent with the ordinary dependency
     * walk instead of consulting a path file relative to the copied name. */
    musl_self_dependency = musl_dependency_is_self(name, deps);
    resolved = musl_self_dependency
        ? validated_candidate(deps->interp_path, deps,
                              CANDIDATE_NON_GNU, &lookup_result,
                              NULL, &snapshot)
        : find_library(name, info.rpath, info.runpath, origin,
                       inherited_rpath, info.flags_1, deps, 0,
                       &lookup_result, NULL, &snapshot);
    if (!resolved) {
        result = lookup_result == LIBRARY_LOOKUP_MISS ? 0 : -1;
        goto out;
    }
    *path_out = resolved;
    resolved = NULL;
    result = 1;

out:
    free(resolved);
    free(origin);
    free(dir_copy);
    free(real);
    elf_info_free(&info);
    return result;
}

/* ------------------------------------------------------------------ */
/*  Merge dlopen-traced libraries                                     */
/* ------------------------------------------------------------------ */
#define DLOPEN_TRACE_READY "#DLFREEZE_DLOPEN_TRACE_V8"
#define DLOPEN_TRACE_OLD_READY "#DLFREEZE_DLOPEN_TRACE_V7"
#define DLOPEN_TRACE_LEGACY_READY "#DLFREEZE_DLOPEN_TRACE_V6"
#define DLOPEN_TRACE_LINE_SIZE (6U * PATH_MAX + 196U)

_Static_assert(PATH_MAX <= (SIZE_MAX - 196U) / 6U,
               "dlopen trace line size overflows size_t");

static int trace_hex_value(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

static int trace_hex_decode(const char *hex, size_t hex_len,
                            char *out, size_t out_size)
{
    if (hex_len == 0 || (hex_len & 1) != 0 ||
        hex_len / 2 >= out_size)
        return -1;
    for (size_t i = 0; i < hex_len; i += 2) {
        int hi = trace_hex_value(hex[i]);
        int lo = trace_hex_value(hex[i + 1]);

        if (hi < 0 || lo < 0 || (hi == 0 && lo == 0))
            return -1;
        out[i / 2] = (char)((hi << 4) | lo);
    }
    out[hex_len / 2] = '\0';
    return 0;
}

static int trace_u32_hex_decode(const char *hex, size_t hex_len,
                                uint32_t *value_out)
{
    uint32_t value = 0;

    if (!hex || !value_out || hex_len != 8)
        return -1;
    for (size_t i = 0; i < hex_len; i++) {
        int digit = trace_hex_value(hex[i]);

        if (digit < 0)
            return -1;
        value = (value << 4) | (uint32_t)digit;
    }
    *value_out = value;
    return 0;
}

static int trace_u64_hex_decode(const char *hex, size_t hex_len,
                                uint64_t *value_out)
{
    uint64_t value = 0;

    if (!hex || !value_out || hex_len != 16)
        return -1;
    for (size_t i = 0; i < hex_len; i++) {
        int digit = trace_hex_value(hex[i]);

        if (digit < 0)
            return -1;
        value = (value << 4) | (uint64_t)digit;
    }
    *value_out = value;
    return 0;
}

static int trace_split_fields(char *line, char **fields, size_t field_count)
{
    if (!line || !line[0] || !fields || field_count == 0)
        return -1;
    fields[0] = line;
    for (size_t i = 1; i < field_count; i++) {
        char *separator = strchr(fields[i - 1], ' ');

        if (!separator || separator == fields[i - 1])
            return -1;
        *separator = '\0';
        fields[i] = separator + 1;
    }
    if (!fields[field_count - 1][0] ||
        strchr(fields[field_count - 1], ' '))
        return -1;
    return 0;
}

/* Compare in the fixed-width wire domain.  This avoids accepting truncation
 * when a trace produced on a target with wider stat fields is consumed by a
 * narrower packer, and retains two's-complement negative timestamps exactly. */
static int trace_snapshot_matches_dep(
    const uint64_t fields[8], const struct dep_file_snapshot *snapshot)
{
    return fields && snapshot && snapshot->valid &&
           fields[0] == (uint64_t)snapshot->device &&
           fields[1] == (uint64_t)snapshot->inode &&
           fields[2] == (uint64_t)S_IFREG &&
           fields[3] == (uint64_t)snapshot->size &&
           fields[4] == (uint64_t)snapshot->mtime_sec &&
           fields[5] == (uint64_t)snapshot->mtime_nsec &&
           fields[6] == (uint64_t)snapshot->ctime_sec &&
           fields[7] == (uint64_t)snapshot->ctime_nsec;
}

static char *validate_traced_elf_object(
    struct dep_list *deps, const char *logical, const char *source,
    const uint64_t trace_snapshot[8], struct dep_file_snapshot *snapshot,
    struct elf_info *info)
{
    char *resolved;
    struct stat status;

    if (!deps || !logical || logical[0] != '/' || !source ||
        source[0] != '/' || !trace_snapshot || !snapshot || !info ||
        trace_snapshot[2] != (uint64_t)S_IFREG ||
        trace_snapshot[5] > 999999999 ||
        trace_snapshot[7] > 999999999)
        return NULL;
    resolved = realpath(source, NULL);
    if (!resolved || strcmp(resolved, source) != 0 ||
        stat(resolved, &status) < 0 || !S_ISREG(status.st_mode) ||
        status.st_size < 0) {
        free(resolved);
        errno = ESTALE;
        return NULL;
    }
    dep_snapshot_from_stat(snapshot, &status);
    if (!trace_snapshot_matches_dep(trace_snapshot, snapshot)) {
        free(resolved);
        errno = ESTALE;
        return NULL;
    }
    memset(info, 0, sizeof(*info));
    if (elf_parse_path_snapshot(resolved, snapshot, info, NULL) < 0 ||
        !info->is_dynamic || info->ei_class != deps->target_ei_class ||
        info->e_machine != deps->target_e_machine) {
        elf_info_free(info);
        free(resolved);
        return NULL;
    }
    return resolved;
}

/* Drain one traced root's closure before interpreting the next trace record.
 * The native dlopen which produced that record completed the same closure
 * before returning.  Mirroring that discovery order preserves first-owner
 * logical paths and lets a later direct request retain a distinct alias from
 * a dependency record already discovered through an earlier root. */
static int resolve_dlopen_dependency_queue(struct dep_list *deps,
                                           struct bfs_queue *q)
{
    struct bfs_item item;

    while (bfs_pop(q, &item)) {
        char *lib_path = item.path;
        struct elf_info info = {0};
        char *directory_copy;
        char *origin;

        if (elf_parse_path_snapshot(
                lib_path, &item.snapshot, &info, NULL) < 0 ||
            !info.is_dynamic ||
            info.ei_class != deps->target_ei_class ||
            info.e_machine != deps->target_e_machine) {
            elf_info_free(&info);
            bfs_item_free(&item);
            return -1;
        }

        directory_copy = strdup(item.logical_path);
        origin = directory_copy ? strdup(dirname(directory_copy)) : NULL;
        if (!directory_copy || !origin ||
            resolve_needed(&info, origin, deps, q, 1,
                           item.inherited_rpath) < 0) {
            free(origin);
            free(directory_copy);
            elf_info_free(&info);
            bfs_item_free(&item);
            return -1;
        }
        free(origin);
        free(directory_copy);
        elf_info_free(&info);
        bfs_item_free(&item);
    }
    q->head = 0;
    q->tail = 0;
    return 0;
}

static int dep_add_dlopen_libs_internal(
    struct dep_list *deps, const char *trace_file, int trace_fd)
{
    if (!deps || (trace_fd < 0 && (!trace_file || !trace_file[0]))) {
        errno = EINVAL;
        return -1;
    }
    FILE *f = trace_fd >= 0 ? fdopen(trace_fd, "r")
                            : fopen(trace_file, "r");
    if (!f) {
        if (trace_fd >= 0)
            close(trace_fd);
        return -1;
    }
    /* The trace helper holds this OFD lock across the owner and every fork
     * descendant.  Do not parse a prefix while a daemonized child can still
     * append or while the supervised root is incompletely torn down. */
    if (flock(fileno(f), LOCK_EX | LOCK_NB) < 0) {
        fprintf(stderr,
                "dlfreeze: dlopen trace is still owned by a live traced "
                "process\n");
        fclose(f);
        return -1;
    }

    struct bfs_queue q;
    if (bfs_init(&q) < 0) {
        fclose(f);
        return -1;
    }

    char line[DLOPEN_TRACE_LINE_SIZE];
    int saw_header = 0;
    int saw_owner = 0;
    int saw_initial_begin = 0;
    int saw_initial_commit = 0;
    int saw_call = 0;
    uint64_t owner_pid = 0;
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        char request[PATH_MAX];
        char logical[PATH_MAX];
        char source[PATH_MAX];
        char *fields[16];
        uint64_t trace_snapshot[8];
        uint64_t record_pid;
        uint64_t operation_attempt;
        uint64_t operation_evidence_count;
        uint32_t mode;
        int pathful;

        if (len == 0 || line[len - 1] != '\n') {
            fprintf(stderr, "dlfreeze: malformed or truncated dlopen trace\n");
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        line[--len] = '\0';
        if (strcmp(line, DLOPEN_TRACE_READY) == 0) {
            if (saw_header) {
                fprintf(stderr,
                        "dlfreeze: duplicate dlopen trace version header\n");
                fclose(f);
                bfs_free(&q);
                return -1;
            }
            saw_header = 1;
            continue;
        }
        if (strcmp(line, DLOPEN_TRACE_OLD_READY) == 0) {
            fprintf(stderr,
                    "dlfreeze: dlopen trace V7 has no descriptor-operation "
                    "transactions and is unsupported\n");
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        if (strcmp(line, DLOPEN_TRACE_LEGACY_READY) == 0) {
            fprintf(stderr,
                    "dlfreeze: dlopen trace V6 has no mapped-object or "
                    "owner-exec provenance and is unsupported\n");
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        if (saw_header && len == 18 && line[0] == 'O' && line[1] == ' ') {
            if (saw_owner || saw_call ||
                trace_u64_hex_decode(line + 2, 16, &owner_pid) < 0 ||
                owner_pid == 0) {
                fprintf(stderr,
                        "dlfreeze: malformed or duplicate dlopen trace "
                        "owner record\n");
                fclose(f);
                bfs_free(&q);
                return -1;
            }
            saw_owner = 1;
            continue;
        }
        if (saw_header && len > 0 && line[0] == 'O') {
            fprintf(stderr,
                    "dlfreeze: malformed or duplicate dlopen trace owner "
                    "record\n");
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        if (saw_header && saw_owner && saw_initial_commit && len == 35 &&
            (line[0] == 'V' || line[0] == 'W') && line[1] == ' ' &&
            line[18] == ' ') {
            uint64_t attempt;

            if (trace_u64_hex_decode(line + 2, 16, &record_pid) < 0 ||
                record_pid == 0 ||
                trace_u64_hex_decode(line + 19, 16, &attempt) < 0 ||
                bfs_descriptor_operation_update(
                    &q, record_pid, attempt, line[0] == 'V') < 0) {
                fprintf(stderr,
                        "dlfreeze: malformed descriptor-operation trace "
                        "record\n");
                fclose(f);
                bfs_free(&q);
                return -1;
            }
            saw_call = 1;
            continue;
        }
        if (saw_header && len > 0 &&
            (line[0] == 'V' || line[0] == 'W')) {
            fprintf(stderr,
                    "dlfreeze: malformed descriptor-operation trace "
                    "record\n");
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        if (saw_header && saw_owner && len == 35 &&
            (line[0] == 'A' || line[0] == 'B') && line[1] == ' ' &&
            line[18] == ' ') {
            uint64_t attempt;
            int initial = line[0] == 'A';

            if (trace_u64_hex_decode(line + 2, 16, &record_pid) < 0 ||
                record_pid == 0 ||
                trace_u64_hex_decode(line + 19, 16, &attempt) < 0 ||
                attempt == 0 ||
                (initial &&
                 (record_pid != owner_pid || saw_initial_begin ||
                  saw_initial_commit || saw_call)) ||
                (!initial && !saw_initial_commit) ||
                bfs_loader_operation_begin(
                    &q, record_pid, attempt, initial ? 'A' : 'B') < 0) {
                fprintf(stderr,
                        "dlfreeze: malformed dlopen trace operation begin\n");
                fclose(f);
                bfs_free(&q);
                return -1;
            }
            if (initial)
                saw_initial_begin = 1;
            else
                saw_call = 1;
            continue;
        }
        if (saw_header && saw_owner && len == 52 && line[0] == 'K' &&
            line[1] == ' ' && line[18] == ' ' && line[35] == ' ') {
            uint64_t attempt;
            uint64_t evidence_count;

            if (trace_u64_hex_decode(line + 2, 16, &record_pid) < 0 ||
                record_pid != owner_pid ||
                trace_u64_hex_decode(line + 19, 16, &attempt) < 0 ||
                trace_u64_hex_decode(line + 36, 16, &evidence_count) < 0 ||
                evidence_count == 0 ||
                !saw_initial_begin || saw_initial_commit ||
                !bfs_initial_evidence_is_complete(&q, deps) ||
                bfs_loader_operation_commit(
                    &q, record_pid, attempt, 'A', evidence_count) < 0) {
                fprintf(stderr,
                        "dlfreeze: malformed dlopen trace initialization "
                        "commit\n");
                fclose(f);
                bfs_free(&q);
                return -1;
            }
            saw_initial_commit = 1;
            continue;
        }
        if (saw_header && saw_owner && saw_initial_commit && len == 35 &&
            line[0] == 'Q' && line[1] == ' ' && line[18] == ' ') {
            uint64_t attempt;

            if (trace_u64_hex_decode(line + 2, 16, &record_pid) < 0 ||
                record_pid == 0 ||
                trace_u64_hex_decode(line + 19, 16, &attempt) < 0 ||
                attempt == 0 ||
                bfs_loader_operation_commit(
                    &q, record_pid, attempt, 'B', 0) < 0) {
                fprintf(stderr,
                        "dlfreeze: malformed no-object loader commit\n");
                fclose(f);
                bfs_free(&q);
                return -1;
            }
            saw_call = 1;
            continue;
        }
        if (saw_header && len > 0 &&
            (line[0] == 'A' || line[0] == 'B' || line[0] == 'K' ||
             line[0] == 'Q')) {
            fprintf(stderr,
                    "dlfreeze: malformed dlopen trace operation record\n");
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        if (saw_header && saw_owner && saw_initial_commit && len == 35 &&
            (line[0] == 'E' || line[0] == 'C') && line[1] == ' ' &&
            line[18] == ' ') {
            uint64_t attempt;

            if (trace_u64_hex_decode(line + 2, 16, &record_pid) < 0 ||
                record_pid != owner_pid ||
                trace_u64_hex_decode(line + 19, 16, &attempt) < 0 ||
                bfs_exec_attempt_update(&q, attempt, line[0] == 'E') < 0) {
                fprintf(stderr,
                        "dlfreeze: malformed dlopen trace exec record\n");
                fclose(f);
                bfs_free(&q);
                return -1;
            }
            saw_call = 1;
            continue;
        }
        if (saw_header && len > 0 &&
            (line[0] == 'E' || line[0] == 'C')) {
            fprintf(stderr,
                    "dlfreeze: malformed dlopen trace exec record\n");
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        if (saw_header && saw_owner && len >= 20 && line[0] == '!' &&
            line[1] == ' ' && line[18] == ' ' && line[19] != '\0') {
            int reason_valid = 1;

            for (size_t i = 19; i < len; i++) {
                if (!((line[i] >= 'a' && line[i] <= 'z') ||
                      (line[i] >= '0' && line[i] <= '9') ||
                      line[i] == '-')) {
                    reason_valid = 0;
                    break;
                }
            }
            if (!reason_valid ||
                trace_u64_hex_decode(line + 2, 16, &record_pid) < 0 ||
                record_pid == 0) {
                fprintf(stderr,
                        "dlfreeze: malformed dlopen trace terminal record\n");
                fclose(f);
                bfs_free(&q);
                return -1;
            }
            fprintf(stderr,
                    "dlfreeze: preload helper reported an incomplete "
                    "dlopen trace: %s\n",
                    line + 19);
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        if (saw_header && len > 0 && line[0] == '!') {
            fprintf(stderr,
                    "dlfreeze: malformed dlopen trace terminal record\n");
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        if (saw_header && saw_owner && len > 0 &&
            (line[0] == 'I' || line[0] == 'R')) {
            struct dep_file_snapshot snapshot = {0};
            struct elf_info info = {0};
            uint64_t attempt;
            char evidence_kind = line[0] == 'I' ? 'A' : 'B';
            char *resolved;

            if (trace_split_fields(line, fields, 13) < 0 ||
                strlen(fields[0]) != 1 ||
                trace_u64_hex_decode(fields[1], strlen(fields[1]),
                                     &record_pid) < 0 ||
                record_pid == 0 ||
                trace_u64_hex_decode(fields[2], strlen(fields[2]),
                                     &attempt) < 0 ||
                attempt == 0 ||
                (evidence_kind == 'A' && record_pid != owner_pid) ||
                (evidence_kind == 'B' && !saw_initial_commit) ||
                trace_hex_decode(fields[3], strlen(fields[3]),
                                 logical, sizeof(logical)) < 0 ||
                trace_hex_decode(fields[4], strlen(fields[4]),
                                 source, sizeof(source)) < 0) {
                fprintf(stderr,
                        "dlfreeze: malformed mapped-object trace evidence\n");
                fclose(f);
                bfs_free(&q);
                return -1;
            }
            for (size_t index = 0; index < 8; index++) {
                if (trace_u64_hex_decode(
                        fields[5 + index], strlen(fields[5 + index]),
                        &trace_snapshot[index]) < 0) {
                    fprintf(stderr,
                            "dlfreeze: malformed mapped-object trace "
                            "snapshot\n");
                    fclose(f);
                    bfs_free(&q);
                    return -1;
                }
            }
            resolved = validate_traced_elf_object(
                deps, logical, source, trace_snapshot, &snapshot, &info);
            if (!resolved ||
                bfs_loader_operation_evidence(
                    &q, record_pid, attempt, evidence_kind) < 0 ||
                (evidence_kind == 'A' &&
                 bfs_initial_identity_add(&q, deps, &snapshot) < 0)) {
                fprintf(stderr,
                        "dlfreeze: mapped object changed after tracing or "
                        "has no pending operation: %s\n", source);
                elf_info_free(&info);
                free(resolved);
                fclose(f);
                bfs_free(&q);
                return -1;
            }
            if (evidence_kind == 'B' &&
                !is_kernel_virtual_lib(resolved) &&
                !snapshot_is_interpreter(&snapshot, deps)) {
                const char *base = strrchr(logical, '/');
                const char *name;
                int identity_index = dependency_snapshot_index(
                    deps, &snapshot);
                int startup_owned = identity_index >= 0 &&
                    !deps->libs[identity_index].from_dlopen;
                int first_in_process = startup_owned
                    ? 0 : bfs_trace_identity_first(
                              &q, record_pid, &snapshot);
                int added;

                base = base ? base + 1 : logical;
                name = info.soname && info.soname[0] ? info.soname : base;
                if (first_in_process < 0) {
                    elf_info_free(&info);
                    free(resolved);
                    fclose(f);
                    bfs_free(&q);
                    return -1;
                }
                /* A nested constructor dlopen can commit while its caller's
                 * transaction is still pending.  The outer post-scan then
                 * sees the same mapping as R evidence.  Count and validate
                 * that evidence, but do not invent a requestless alias once
                 * this process has already established the identity. */
                if (first_in_process == 0) {
                    saw_call = 1;
                    elf_info_free(&info);
                    free(resolved);
                    continue;
                }
                added = dep_list_add(
                    deps, name, resolved, logical, &snapshot,
                    1, 0, 0, 0, NULL);
                if (added < 0) {
                    elf_info_free(&info);
                    free(resolved);
                    fclose(f);
                    bfs_free(&q);
                    return -1;
                }
                saw_call = 1;
            }
            elf_info_free(&info);
            free(resolved);
            continue;
        }
        /* Failed-load records intentionally carry no pathname: there is no
         * successful link_map identity to package, and direct replay cannot
         * reproduce the native loader's observable dlerror state.  Preserve
         * the API, NULL-vs-non-NULL filename, namespace, and exact mode in a
         * fixed-width grammar, together with the originating process.  Every
         * uint32_t mode and uint64_t namespace is meaningful here because
         * invalid arguments can themselves be the reason the native
         * operation failed. */
        if (saw_header && saw_owner && saw_initial_commit && len == 65 &&
            line[0] == 'F' && line[1] == ' ' && line[18] == ' ' &&
            line[35] == ' ' &&
            (line[36] == 'D' || line[36] == 'M') && line[37] == ' ' &&
            (line[38] == 'N' || line[38] == 'P') && line[39] == ' ' &&
            line[56] == ' ') {
            uint64_t namespace_id;
            uint64_t attempt;

            if (trace_u64_hex_decode(line + 2, 16, &record_pid) < 0 ||
                record_pid == 0 ||
                trace_u64_hex_decode(line + 19, 16, &attempt) < 0 ||
                attempt == 0 ||
                trace_u64_hex_decode(line + 40, 16, &namespace_id) < 0 ||
                trace_u32_hex_decode(line + 57, 8, &mode) < 0 ||
                (line[36] == 'D' && namespace_id != 0) ||
                bfs_loader_operation_commit(
                    &q, record_pid, attempt, 'B', 0) < 0) {
                fprintf(stderr,
                        "dlfreeze: unsupported or malformed failed-load "
                        "trace record\n");
                fclose(f);
                bfs_free(&q);
                return -1;
            }
            deps->traced_requires_native_loader_semantics = 1;
            saw_call = 1;
            continue;
        }
        if (saw_header && len > 0 && line[0] == 'F') {
            fprintf(stderr,
                    "dlfreeze: unsupported or malformed failed-load "
                    "trace record\n");
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        if (!saw_header || !saw_owner || !saw_initial_commit || len < 15 ||
            trace_split_fields(line, fields,
                               sizeof(fields) / sizeof(fields[0])) < 0 ||
            strlen(fields[0]) != 1 ||
            (fields[0][0] != 'P' && fields[0][0] != 'S')) {
            fprintf(stderr,
                    "dlfreeze: unsupported or malformed dlopen trace format\n");
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        if (trace_u64_hex_decode(fields[1], strlen(fields[1]),
                                 &record_pid) < 0 ||
            record_pid == 0) {
            fprintf(stderr,
                    "dlfreeze: malformed dlopen trace process identity\n");
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        if (trace_u64_hex_decode(fields[2], strlen(fields[2]),
                                 &operation_attempt) < 0 ||
            operation_attempt == 0 ||
            trace_u64_hex_decode(fields[3], strlen(fields[3]),
                                 &operation_evidence_count) < 0 ||
            trace_u32_hex_decode(fields[4], strlen(fields[4]), &mode) < 0 ||
            !dlfrz_dlopen_mode_is_supported((int)mode)) {
            fprintf(stderr,
                    "dlfreeze: unsupported or malformed dlopen trace mode\n");
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        {
            struct trace_loader_operation *operation =
                bfs_loader_operation_find(
                    &q, record_pid, operation_attempt);

            if (!operation || operation->kind != 'B' ||
                operation->evidence_count != operation_evidence_count) {
                fprintf(stderr,
                        "dlfreeze: dlopen trace root has no matching "
                        "operation evidence\n");
                fclose(f);
                bfs_free(&q);
                return -1;
            }
        }
        if (trace_hex_decode(fields[5], strlen(fields[5]),
                             request, sizeof(request)) < 0 ||
            trace_hex_decode(fields[6], strlen(fields[6]),
                             logical, sizeof(logical)) < 0 ||
            trace_hex_decode(fields[7], strlen(fields[7]),
                             source, sizeof(source)) < 0) {
            fprintf(stderr, "dlfreeze: malformed dlopen trace encoding\n");
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        for (size_t i = 0; i < 8; i++) {
            if (trace_u64_hex_decode(fields[8 + i],
                                     strlen(fields[8 + i]),
                                     &trace_snapshot[i]) < 0) {
                fprintf(stderr,
                        "dlfreeze: malformed dlopen trace source snapshot\n");
                fclose(f);
                bfs_free(&q);
                return -1;
            }
        }
        if (trace_snapshot[2] != (uint64_t)S_IFREG ||
            trace_snapshot[5] > 999999999 ||
            trace_snapshot[7] > 999999999) {
            fprintf(stderr,
                    "dlfreeze: malformed dlopen trace source snapshot\n");
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        pathful = strchr(request, '/') != NULL;
        if (pathful != (fields[0][0] == 'P') || logical[0] != '/' ||
            source[0] != '/') {
            fprintf(stderr, "dlfreeze: inconsistent dlopen trace record\n");
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        if (strchr(request, '$') != NULL) {
            fprintf(stderr,
                    "dlfreeze: dynamic string tokens in traced dlopen "
                    "requests are unsupported: %s\n",
                    request);
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        saw_call = 1;

        /* V8 stores the exact mode, first loader-visible spelling, canonical
         * source, and the source revision observed immediately after the
         * native load.  Refuse pathname replacement instead of silently
         * packing bytes which were never associated with this record. */
        struct dep_file_snapshot snapshot = {0};
        char *rp = validated_candidate(
            source, deps, CANDIDATE_NON_GNU, NULL, NULL, &snapshot);
        if (!rp || strcmp(rp, source) != 0) {
            fprintf(stderr,
                    "dlfreeze: traced dlopen object is no longer readable: %s\n",
                    source);
            free(rp);
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        if (!trace_snapshot_matches_dep(trace_snapshot, &snapshot)) {
            fprintf(stderr,
                    "dlfreeze: traced dlopen object changed after tracing: %s\n",
                    source);
            free(rp);
            fclose(f);
            bfs_free(&q);
            errno = ESTALE;
            return -1;
        }

        const char *base = strrchr(logical, '/');
        const char *name;
        struct elf_info info = {0};

        base = base ? base + 1 : logical;
        if (is_kernel_virtual_lib(rp) ||
            snapshot_is_interpreter(&snapshot, deps)) {
            if (bfs_loader_operation_commit(
                    &q, record_pid, operation_attempt, 'B',
                    operation_evidence_count) < 0) {
                free(rp);
                fclose(f);
                bfs_free(&q);
                return -1;
            }
            free(rp);
            continue;
        }

        if (elf_parse_path_snapshot(rp, &snapshot, &info, NULL) < 0 ||
            !info.is_dynamic ||
            info.ei_class != deps->target_ei_class ||
            info.e_machine != deps->target_e_machine) {
            fprintf(stderr,
                    "dlfreeze: traced dlopen object is invalid or incompatible: %s\n",
                    rp);
            elf_info_free(&info);
            free(rp);
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        name = info.soname && info.soname[0] ? info.soname : base;

        /* Native loaders traverse one dependency closure for the first map
         * of a filesystem identity in each process.  Later request aliases
         * need their own manifest identities, but must not re-run DT_NEEDED
         * resolution with a later alias's $ORIGIN in that process. */
        int identity_index = dependency_snapshot_index(deps, &snapshot);
        /* One pid-tagged append-only trace is intentionally inherited across
         * fork and can also contain multiple dlmopen namespaces or an
         * unload/reload sequence.  An earlier record therefore does not prove
         * that this identity was visible in the process/namespace which
         * issued the current pure-LAZY request.  The immutable startup graph
         * is the only safe visibility proof available in V8. */
        int identity_was_startup_owned =
            identity_index >= 0 && !deps->libs[identity_index].from_dlopen;
        int first_in_process = identity_was_startup_owned
            ? 0 : bfs_trace_identity_first(&q, record_pid, &snapshot);

        if (first_in_process < 0) {
            elf_info_free(&info);
            free(rp);
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        int added = dep_list_add(deps, name, rp, logical, &snapshot,
                                 1, 1, pathful, 0, request);
        if (added < 0) {
            elf_info_free(&info);
            free(rp);
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        if (!identity_was_startup_owned &&
            dlfrz_dlopen_mode_requires_lazy_binding((int)mode))
            deps->traced_requires_native_lazy_semantics = 1;
        if (added > 0 && first_in_process &&
            bfs_push(&q, rp, logical, &snapshot, NULL) < 0) {
            elf_info_free(&info);
            free(rp);
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        elf_info_free(&info);
        free(rp);
        if (added > 0 && first_in_process &&
            resolve_dlopen_dependency_queue(deps, &q) < 0) {
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        if (bfs_loader_operation_commit(
                &q, record_pid, operation_attempt, 'B',
                operation_evidence_count) < 0) {
            fprintf(stderr,
                    "dlfreeze: dlopen trace operation evidence count "
                    "does not match its root commit\n");
            fclose(f);
            bfs_free(&q);
            return -1;
        }
    }
    if (ferror(f) || !saw_header || !saw_owner || !saw_initial_begin ||
        !saw_initial_commit || q.pending_exec_count != 0 ||
        q.loader_operation_count != 0 ||
        q.descriptor_operation_count != 0) {
        if (!ferror(f)) {
            if (!saw_header)
                fprintf(stderr,
                        "dlfreeze: missing dlopen trace version header\n");
            else if (!saw_owner)
                fprintf(stderr,
                        "dlfreeze: missing dlopen trace owner record\n");
            else if (!saw_initial_begin || !saw_initial_commit)
                fprintf(stderr,
                        "dlfreeze: incomplete initial mapped-object "
                        "evidence\n");
            else if (q.pending_exec_count != 0)
                fprintf(stderr,
                        "dlfreeze: traced owner replaced its process image "
                        "during dlopen tracing\n");
            else if (q.descriptor_operation_count != 0)
                fprintf(stderr,
                        "dlfreeze: incomplete descriptor operation during "
                        "dlopen tracing\n");
            else
                fprintf(stderr,
                        "dlfreeze: incomplete dlopen operation evidence\n");
        }
        fclose(f);
        bfs_free(&q);
        return -1;
    }
    fclose(f);

    bfs_free(&q);
    return 0;
}

int dep_add_dlopen_libs(struct dep_list *deps, const char *trace_file)
{
    return dep_add_dlopen_libs_internal(deps, trace_file, -1);
}

int dep_add_dlopen_libs_fd(struct dep_list *deps, int trace_fd)
{
    if (trace_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    return dep_add_dlopen_libs_internal(deps, NULL, trace_fd);
}

static int dependency_snapshot_index(
    const struct dep_list *deps,
    const struct dep_file_snapshot *snapshot)
{
    if (!snapshot || !snapshot->valid)
        return -1;
    for (int i = 0; i < deps->count; i++) {
        if (deps->libs[i].device != snapshot->device ||
            deps->libs[i].inode != snapshot->inode)
            continue;
        return i;
    }
    return -1;
}

struct closure_queue_item {
    int index;
    struct rpath_scope *inherited_rpath;
};

static void closure_queue_free(struct closure_queue_item *queue,
                               int head, int tail)
{
    for (int i = head; i < tail; i++)
        rpath_scope_free(queue[i].inherited_rpath);
}

static int inspect_dlopen_closure(
    struct dep_list *deps, int root, unsigned char *closure,
    struct closure_queue_item *queue, int *needs_early_out)
{
    int head = 0;
    int tail = 0;
    int needs_early = 0;

    closure[root] = 1;
    queue[tail].index = root;
    queue[tail].inherited_rpath = NULL;
    tail++;

    while (head < tail) {
        struct closure_queue_item item = queue[head];
        struct rpath_scope own_scope;
        const struct rpath_scope *child_inherited;
        struct elf_info info;
        char *path_copy = NULL;
        char *origin = NULL;
        int failed = 0;

        queue[head].inherited_rpath = NULL;
        head++;
        if (elf_parse_path_snapshot(
                deps->libs[item.index].path,
                &deps->libs[item.index].snapshot, &info, NULL) < 0) {
            rpath_scope_free(item.inherited_rpath);
            closure_queue_free(queue, head, tail);
            return -1;
        }
        path_copy = strdup(deps->libs[item.index].logical_path);
        origin = path_copy ? strdup(dirname(path_copy)) : NULL;
        if (!path_copy || !origin) {
            free(origin);
            free(path_copy);
            elf_info_free(&info);
            rpath_scope_free(item.inherited_rpath);
            closure_queue_free(queue, head, tail);
            return -1;
        }
        child_inherited = rpath_scope_for_children(
            &info, origin, deps, item.inherited_rpath, &own_scope);
        if (deps->libs[item.index].from_dlopen && info.has_static_tls)
            needs_early = 1;

        for (int n = 0; n < info.needed_count; n++) {
            char *resolved;
            struct dep_file_snapshot snapshot = {0};
            int dependency;
            int interpreter_dependency =
                is_interpreter_dependency(info.needed[n], deps);
            int musl_self_dependency =
                musl_dependency_is_self(info.needed[n], deps);

            if (is_kernel_virtual_lib(info.needed[n]) ||
                (interpreter_dependency &&
                 deps->runtime_family != DEP_RUNTIME_MUSL))
                continue;
            if (strchr(info.needed[n], '$')) {
                failed = 1;
                break;
            }
            resolved = musl_self_dependency
                ? validated_candidate(deps->interp_path, deps,
                                      CANDIDATE_NON_GNU, NULL,
                                      NULL, &snapshot)
                : find_library(info.needed[n], info.rpath,
                               info.runpath, origin,
                               item.inherited_rpath, info.flags_1, deps, 1,
                               NULL, NULL, &snapshot);
            if (!resolved) {
                failed = 1;
                break;
            }
            dependency = dependency_snapshot_index(deps, &snapshot);
            free(resolved);
            if (dependency < 0) {
                failed = 1;
                break;
            }
            if (!deps->libs[dependency].from_dlopen ||
                closure[dependency])
                continue;
            if (tail >= deps->count) {
                failed = 1;
                break;
            }
            queue[tail].index = dependency;
            queue[tail].inherited_rpath = child_inherited
                ? rpath_scope_clone(child_inherited) : NULL;
            if (child_inherited && !queue[tail].inherited_rpath) {
                failed = 1;
                break;
            }
            closure[dependency] = 1;
            tail++;
        }

        free(origin);
        free(path_copy);
        elf_info_free(&info);
        rpath_scope_free(item.inherited_rpath);
        if (failed) {
            closure_queue_free(queue, head, tail);
            return -1;
        }
    }

    *needs_early_out = needs_early;
    return 0;
}

int dep_mark_dlopen_early_closures(struct dep_list *deps)
{
    unsigned char *closure;
    struct closure_queue_item *queue;

    if (!deps || deps->count < 0)
        return -1;
    if (deps->count == 0)
        return 0;
    closure = calloc((size_t)deps->count, sizeof(*closure));
    queue = calloc((size_t)deps->count, sizeof(*queue));
    if (!closure || !queue) {
        free(closure);
        free(queue);
        return -1;
    }

    for (int root = 0; root < deps->count; root++) {
        int needs_early = 0;

        if (!deps->libs[root].from_dlopen ||
            !deps->libs[root].dlopen_direct)
            continue;
        memset(closure, 0, (size_t)deps->count);
        memset(queue, 0, (size_t)deps->count * sizeof(*queue));
        if (inspect_dlopen_closure(deps, root, closure, queue,
                                   &needs_early) < 0) {
            free(closure);
            free(queue);
            return -1;
        }

        if (needs_early) {
            for (int i = 0; i < deps->count; i++)
                if (closure[i] && deps->libs[i].from_dlopen)
                    deps->libs[i].dlopen_early = 1;
        }
    }

    free(closure);
    free(queue);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Cleanup                                                           */
/* ------------------------------------------------------------------ */
void dep_list_free(struct dep_list *deps)
{
    if (!deps)
        return;
    for (int i = 0; i < deps->count; i++) {
        free(deps->libs[i].name);
        free(deps->libs[i].path);
        free(deps->libs[i].logical_path);
        free(deps->libs[i].dlopen_request);
    }
    free(deps->libs);
    free(deps->interp_path);
    free(deps->interp_soname);
    free(deps->gnu_platform);
    free(deps->gnu_cache_path);
    gnu_cache_index_free(deps->gnu_cache_index);
    free(deps->gnu_cache_image);
    free(deps->musl_system_path);
    free(deps->main_origin);
    free(deps->main_rpath);
    memset(deps, 0, sizeof(*deps));
}
