#include "dep_resolver.h"
#include "elf_parser.h"
#include "glibc_layout.h"
#include "libc_semantics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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
                     dlfrz_glibc_config_path(
                         image, image_size,
                         DLFRZ_GLIBC_CACHE_SUFFIX,
                         sizeof(DLFRZ_GLIBC_CACHE_SUFFIX) - 1,
                         gnu_cache_path, PATH_MAX)) {
                int minor = dlfrz_glibc_stable_release_minor(
                    image, image_size);

                /* Cache behavior changes by target release.  A development
                 * or unrecognized loader cannot safely inherit the packer's
                 * host policy. */
                if (minor >= 0) {
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

struct bfs_queue {
    struct bfs_item *items;
    int    head, tail, cap;
};

static int bfs_init(struct bfs_queue *q)
{
    q->cap   = 256;
    q->items = calloc((size_t)q->cap, sizeof(*q->items));
    q->head  = q->tail = 0;
    return q->items ? 0 : -1;
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
    resolved = find_library(name, info.rpath, info.runpath, origin,
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
#define DLOPEN_TRACE_READY "#DLFREEZE_DLOPEN_TRACE_V4"

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

int dep_add_dlopen_libs(struct dep_list *deps, const char *trace_file)
{
    if (!deps || !trace_file || !trace_file[0]) {
        errno = EINVAL;
        return -1;
    }
    FILE *f = fopen(trace_file, "r");
    if (!f) return -1;

    struct bfs_queue q;
    if (bfs_init(&q) < 0) {
        fclose(f);
        return -1;
    }

    char line[6 * PATH_MAX + 24];
    int saw_header = 0;
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        char request[PATH_MAX];
        char logical[PATH_MAX];
        char source[PATH_MAX];
        char *first_separator;
        char *second_separator;
        size_t request_hex_len, logical_hex_len, source_hex_len;
        int pathful;

        if (len == 0 || line[len - 1] != '\n') {
            fprintf(stderr, "dlfreeze: malformed or truncated dlopen trace\n");
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        line[--len] = '\0';
        if (strcmp(line, DLOPEN_TRACE_READY) == 0) {
            saw_header = 1;
            continue;
        }
        if (saw_header && len > 2 && line[0] == '!' && line[1] == ' ') {
            fprintf(stderr,
                    "dlfreeze: preload helper reported an incomplete "
                    "dlopen trace: %s\n",
                    line + 2);
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        if (!saw_header || len < 6 ||
            (line[0] != 'P' && line[0] != 'S') || line[1] != ' ') {
            fprintf(stderr,
                    "dlfreeze: unsupported or malformed dlopen trace format\n");
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        first_separator = strchr(line + 2, ' ');
        second_separator = first_separator
            ? strchr(first_separator + 1, ' ') : NULL;
        if (!first_separator || !second_separator ||
            strchr(second_separator + 1, ' ')) {
            fprintf(stderr, "dlfreeze: malformed dlopen trace record\n");
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        request_hex_len = (size_t)(first_separator - (line + 2));
        logical_hex_len =
            (size_t)(second_separator - (first_separator + 1));
        source_hex_len = strlen(second_separator + 1);
        if (trace_hex_decode(line + 2, request_hex_len,
                             request, sizeof(request)) < 0 ||
            trace_hex_decode(first_separator + 1, logical_hex_len,
                             logical, sizeof(logical)) < 0 ||
            trace_hex_decode(second_separator + 1, source_hex_len,
                             source, sizeof(source)) < 0) {
            fprintf(stderr, "dlfreeze: malformed dlopen trace encoding\n");
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        pathful = strchr(request, '/') != NULL;
        if (pathful != (line[0] == 'P') || logical[0] != '/' ||
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

        /* V4 stores the first loader-visible spelling and canonical source
         * separately.  Refuse a stale/non-canonical source instead of
         * silently replacing the recorded l_name and its $ORIGIN owner. */
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

        const char *base = strrchr(logical, '/');
        const char *name;
        struct elf_info info;

        base = base ? base + 1 : logical;
        if (is_kernel_virtual_lib(rp) ||
            snapshot_is_interpreter(&snapshot, deps)) {
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
         * of a filesystem identity.  Later request aliases need their own
         * manifest identities, but must not re-run DT_NEEDED resolution with
         * a later alias's $ORIGIN. */
        int identity_was_known =
            dependency_snapshot_index(deps, &snapshot) >= 0;
        int added = dep_list_add(deps, name, rp, logical, &snapshot,
                                 1, 1, pathful, 0, request);
        if (added > 0 && !identity_was_known &&
            bfs_push(&q, rp, logical, &snapshot, NULL) < 0) {
            elf_info_free(&info);
            free(rp);
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        elf_info_free(&info);
        free(rp);
        if (added < 0) {
            fclose(f);
            bfs_free(&q);
            return -1;
        }
    }
    if (ferror(f) || !saw_header) {
        if (!ferror(f))
            fprintf(stderr, "dlfreeze: missing dlopen trace version header\n");
        fclose(f);
        bfs_free(&q);
        return -1;
    }
    fclose(f);

    /* resolve transitive deps of dlopen'd libs */
    struct bfs_item item;
    while (bfs_pop(&q, &item)) {
        char *lib_path = item.path;
        struct elf_info li;
        if (elf_parse_path_snapshot(lib_path, &item.snapshot, &li, NULL) < 0 ||
            !li.is_dynamic ||
            li.ei_class != deps->target_ei_class ||
            li.e_machine != deps->target_e_machine) {
            elf_info_free(&li);
            bfs_item_free(&item);
            bfs_free(&q);
            return -1;
        }

        char *dt = strdup(item.logical_path);
        char *lo = dt ? strdup(dirname(dt)) : NULL;
        if (!dt || !lo ||
            resolve_needed(&li, lo, deps, &q, 1,
                           item.inherited_rpath) < 0) {
            free(lo); free(dt);
            elf_info_free(&li);
            bfs_item_free(&item);
            bfs_free(&q);
            return -1;
        }
        free(lo); free(dt);
        elf_info_free(&li);
        bfs_item_free(&item);
    }
    bfs_free(&q);
    return 0;
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
