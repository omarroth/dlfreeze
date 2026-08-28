#include "packer.h"
#include "common.h"
#include "dynamic_semantics.h"
#include "elf_parser.h"
#include "elf_sections.h"
#include "glibc_layout.h"
#include "musl_layout.h"
#include "load_segments.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>
#include <elf.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0)
#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1U << 1)
#endif

#ifndef DLFRZ_FLAG_DATA_VIRTUAL
#define DLFRZ_FLAG_DATA_VIRTUAL 0x100
#endif
#ifndef DLFRZ_FLAG_DATA_NEGATIVE
#define DLFRZ_FLAG_DATA_NEGATIVE 0x200
#endif
#ifndef DLFRZ_FLAG_DATA_DIRECTORY
#define DLFRZ_FLAG_DATA_DIRECTORY 0x4000
#endif

/* Fallback for musl libc which lacks Elf64_Relr */
#ifndef ELF_RELR_DEFINED
#ifdef __LP64__
typedef Elf64_Xword Elf64_Relr;
#endif
#endif

/* Fallback for pre-4.17 kernel headers */
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#ifndef DT_DEPAUDIT
#define DT_DEPAUDIT 0x6ffffefb
#endif
#ifndef DT_AUDIT
#define DT_AUDIT 0x6ffffefc
#endif
#ifndef DT_AUXILIARY
#define DT_AUXILIARY 0x7ffffffd
#endif
#ifndef DT_FILTER
#define DT_FILTER 0x7fffffff
#endif
#ifndef DF_1_NOW
#define DF_1_NOW 0x00000001
#endif
#ifndef DF_1_NODELETE
#define DF_1_NODELETE 0x00000008
#endif
#ifndef DF_1_ORIGIN
#define DF_1_ORIGIN 0x00000080
#endif
#ifndef DF_1_NODEFLIB
#define DF_1_NODEFLIB 0x00000800
#endif
#ifndef DF_1_NODUMP
#define DF_1_NODUMP 0x00001000
#endif
#ifndef DF_1_NODIRECT
#define DF_1_NODIRECT 0x00020000
#endif
#ifndef DF_1_PIE
#define DF_1_PIE 0x08000000
#endif
#ifndef DF_ORIGIN
#define DF_ORIGIN 0x00000001
#endif
#ifndef DF_SYMBOLIC
#define DF_SYMBOLIC 0x00000002
#endif
#ifndef DF_TEXTREL
#define DF_TEXTREL 0x00000004
#endif
#ifndef DF_BIND_NOW
#define DF_BIND_NOW 0x00000008
#endif
#ifndef DF_STATIC_TLS
#define DF_STATIC_TLS 0x00000010
#endif

/* Fallback defines for aarch64 relocation types missing from older elf.h */
#ifndef R_AARCH64_IRELATIVE
#define R_AARCH64_IRELATIVE  1032
#endif
#ifndef R_AARCH64_COPY
#define R_AARCH64_COPY       1024
#endif
#ifndef R_AARCH64_TLS_TPREL
#define R_AARCH64_TLS_TPREL  1030
#endif
#ifndef R_AARCH64_TLS_DTPMOD
#define R_AARCH64_TLS_DTPMOD 1028
#endif
#ifndef R_AARCH64_TLS_DTPREL
#define R_AARCH64_TLS_DTPREL 1029
#endif
#ifndef R_AARCH64_TLSDESC
#define R_AARCH64_TLSDESC 1031
#endif

/* ---- architecture-specific relocation types --------------------------- */
#if defined(__x86_64__)
  #ifndef R_X86_64_TLSDESC
  #define R_X86_64_TLSDESC      36
  #endif
  #define ARCH_RELOC_RELATIVE   R_X86_64_RELATIVE
  #define ARCH_RELOC_GLOB_DAT   R_X86_64_GLOB_DAT
  #define ARCH_RELOC_JUMP_SLOT  R_X86_64_JUMP_SLOT
  #define ARCH_RELOC_ABS        R_X86_64_64
  #define ARCH_RELOC_TPOFF      R_X86_64_TPOFF64
  #define ARCH_RELOC_DTPMOD     R_X86_64_DTPMOD64
  #define ARCH_RELOC_DTPOFF     R_X86_64_DTPOFF64
  #define ARCH_RELOC_TLSDESC    R_X86_64_TLSDESC
  #define ARCH_RELOC_IRELATIVE  R_X86_64_IRELATIVE
  #define ARCH_RELOC_COPY       R_X86_64_COPY
#elif defined(__aarch64__)
  #define ARCH_RELOC_RELATIVE   R_AARCH64_RELATIVE
  #define ARCH_RELOC_GLOB_DAT   R_AARCH64_GLOB_DAT
  #define ARCH_RELOC_JUMP_SLOT  R_AARCH64_JUMP_SLOT
  #define ARCH_RELOC_ABS        R_AARCH64_ABS64
  #define ARCH_RELOC_TPOFF      R_AARCH64_TLS_TPREL
  #define ARCH_RELOC_DTPMOD     R_AARCH64_TLS_DTPMOD
  #define ARCH_RELOC_DTPOFF     R_AARCH64_TLS_DTPREL
    #define ARCH_RELOC_TLSDESC    R_AARCH64_TLSDESC
  #define ARCH_RELOC_IRELATIVE  R_AARCH64_IRELATIVE
  #define ARCH_RELOC_COPY       R_AARCH64_COPY
    #define PRELINK_TLS_ABOVE_TP  1
    #define PRELINK_TLS_TCB_SIZE  0x10
#else
  #error "Unsupported architecture"
#endif

#ifndef PRELINK_TLS_ABOVE_TP
#define PRELINK_TLS_ABOVE_TP 0
#endif
#ifndef PRELINK_TLS_TCB_SIZE
#define PRELINK_TLS_TCB_SIZE 0
#endif

static int u64_add_checked(uint64_t left, uint64_t right, uint64_t *out)
{
    if (right > UINT64_MAX - left)
        return 0;
    *out = left + right;
    return 1;
}

static int u64_align_up_checked(uint64_t value, uint64_t align,
                                uint64_t *out)
{
    uint64_t mask;

    if (align == 0 || (align & (align - 1)) != 0)
        return 0;
    mask = align - 1;
    if (value > UINT64_MAX - mask)
        return 0;
    *out = (value + mask) & ~mask;
    return 1;
}

/* Program-header tables are file byte sequences.  e_phoff has no C object
 * alignment guarantee, and metadata-backed tables should not acquire one as
 * an undocumented precondition either.  Keep all table traversal byte-based;
 * callers work with aligned local copies and stores use memcpy. */
static int packer_phdr_read(const uint8_t *table, size_t table_size,
                            size_t index, size_t stride,
                            Elf64_Phdr *header_out)
{
    size_t offset;

    if (!table || !header_out || stride != sizeof(*header_out) ||
        index > SIZE_MAX / stride)
        return 0;
    offset = index * stride;
    if (offset > table_size || sizeof(*header_out) > table_size - offset)
        return 0;
    memcpy(header_out, table + offset, sizeof(*header_out));
    return 1;
}

static int packer_phdr_write(uint8_t *table, size_t table_size,
                             size_t index, size_t stride,
                             const Elf64_Phdr *header)
{
    size_t offset;

    if (!table || !header || stride != sizeof(*header) ||
        index > SIZE_MAX / stride)
        return 0;
    offset = index * stride;
    if (offset > table_size || sizeof(*header) > table_size - offset)
        return 0;
    memcpy(table + offset, header, sizeof(*header));
    return 1;
}

/* Starting base address for direct-loaded objects (above bootstrap VA) */
#define DIRECT_LOAD_BASE  0x200000000ULL

/* A frozen AArch64 payload must remain mmap-able on 4, 16, and 64 KiB
 * kernels.  Align embedded ELF starts to the largest supported page size. */
#if defined(__aarch64__)
#define PAYLOAD_ALIGN 65536ULL
#else
#define PAYLOAD_ALIGN 4096ULL
#endif

/* ------------------------------------------------------------------ */
/* Data file list helpers                                              */
/* ------------------------------------------------------------------ */
void data_file_list_init(struct data_file_list *dl)
{
    dl->paths      = NULL;
    dl->source_paths = NULL;
    dl->kinds      = NULL;
    dl->count      = 0;
    dl->capacity   = 0;
    dl->failed     = 0;
}

static void data_file_list_add_ex(struct data_file_list *dl, const char *path,
                                  const char *source_path,
                                  enum data_file_kind kind)
{
    char *path_copy;
    char *source_copy = NULL;

    if (!dl || !path ||
        (kind == DATA_FILE_KIND_REGULAR && !source_path) || dl->failed)
        return;
    /* An exact request identity may occur many times, but it must never
     * silently change kind or source during one trace.  Different request
     * aliases are deliberately allowed to name the same canonical source. */
    for (int i = 0; i < dl->count; i++) {
        if (strcmp(dl->paths[i], path) != 0)
            continue;
        if (dl->kinds[i] != kind ||
            (kind == DATA_FILE_KIND_REGULAR &&
             (!dl->source_paths[i] ||
              strcmp(dl->source_paths[i], source_path) != 0)))
            dl->failed = 1;
        return;
    }

    if (dl->count >= dl->capacity) {
        int newcap;
        char **new_paths;
        char **new_sources;
        enum data_file_kind *new_kinds;

        if (dl->capacity > INT_MAX / 2) {
            dl->failed = 1;
            return;
        }
        newcap = dl->capacity ? dl->capacity * 2 : 64;
        if ((size_t)newcap > SIZE_MAX / sizeof(*new_paths) ||
            (size_t)newcap > SIZE_MAX / sizeof(*new_sources) ||
            (size_t)newcap > SIZE_MAX / sizeof(*new_kinds)) {
            dl->failed = 1;
            return;
        }
        new_paths = malloc((size_t)newcap * sizeof(*new_paths));
        new_sources = calloc((size_t)newcap, sizeof(*new_sources));
        new_kinds = calloc((size_t)newcap, sizeof(*new_kinds));
        if (!new_paths || !new_sources || !new_kinds) {
            free(new_paths);
            free(new_sources);
            free(new_kinds);
            dl->failed = 1;
            return;
        }
        if (dl->count > 0) {
            memcpy(new_paths, dl->paths,
                   (size_t)dl->count * sizeof(*new_paths));
            memcpy(new_sources, dl->source_paths,
                   (size_t)dl->count * sizeof(*new_sources));
            memcpy(new_kinds, dl->kinds,
                   (size_t)dl->count * sizeof(*new_kinds));
        }
        free(dl->paths);
        free(dl->source_paths);
        free(dl->kinds);
        dl->paths = new_paths;
        dl->source_paths = new_sources;
        dl->kinds = new_kinds;
        dl->capacity = newcap;
    }

    path_copy = strdup(path);
    if (source_path)
        source_copy = strdup(source_path);
    if (!path_copy || (source_path && !source_copy)) {
        free(path_copy);
        free(source_copy);
        dl->failed = 1;
        return;
    }
    dl->paths[dl->count]      = path_copy;
    dl->source_paths[dl->count] = source_copy;
    dl->kinds[dl->count] = kind;
    dl->count++;
}

void data_file_list_add(struct data_file_list *dl, const char *path,
                        const char *source_path)
{
    data_file_list_add_ex(dl, path, source_path, DATA_FILE_KIND_REGULAR);
}

void data_file_list_add_virtual(struct data_file_list *dl, const char *path)
{
    data_file_list_add_ex(dl, path, NULL, DATA_FILE_KIND_VIRTUAL);
}

void data_file_list_add_negative(struct data_file_list *dl, const char *path)
{
    data_file_list_add_ex(dl, path, NULL, DATA_FILE_KIND_NEGATIVE);
}

void data_file_list_add_directory(struct data_file_list *dl, const char *path)
{
    data_file_list_add_ex(dl, path, NULL, DATA_FILE_KIND_DIRECTORY);
}

void data_file_list_free(struct data_file_list *dl)
{
    for (int i = 0; i < dl->count; i++) {
        free(dl->paths[i]);
        free(dl->source_paths[i]);
    }
    free(dl->paths);
    free(dl->source_paths);
    free(dl->kinds);
    dl->paths = NULL;
    dl->source_paths = NULL;
    dl->kinds = NULL;
    dl->count = dl->capacity = dl->failed = 0;
}

/* ------------------------------------------------------------------ */
struct packed_input_snapshot {
    struct stat st;
    int valid;
};

static int input_snapshot_matches(const struct packed_input_snapshot *snapshot,
                                  const struct stat *current)
{
    return snapshot && snapshot->valid && current &&
           snapshot->st.st_dev == current->st_dev &&
           snapshot->st.st_ino == current->st_ino &&
           snapshot->st.st_size == current->st_size &&
           snapshot->st.st_mtim.tv_sec == current->st_mtim.tv_sec &&
           snapshot->st.st_mtim.tv_nsec == current->st_mtim.tv_nsec &&
           snapshot->st.st_ctim.tv_sec == current->st_ctim.tv_sec &&
           snapshot->st.st_ctim.tv_nsec == current->st_ctim.tv_nsec;
}

static int resolved_snapshot_matches(
    const struct dep_file_snapshot *snapshot, const struct stat *current)
{
    return !snapshot ||
           (snapshot->valid && current &&
            snapshot->device == current->st_dev &&
            snapshot->inode == current->st_ino &&
            snapshot->size == current->st_size &&
            snapshot->mtime_sec == current->st_mtim.tv_sec &&
            snapshot->mtime_nsec == current->st_mtim.tv_nsec &&
            snapshot->ctime_sec == current->st_ctim.tv_sec &&
            snapshot->ctime_nsec == current->st_ctim.tv_nsec);
}

static int validate_input_snapshot(
    const char *path, const struct packed_input_snapshot *snapshot,
    const char *phase)
{
    struct stat current;
    int stat_status;
    int saved_errno;

    if (!path || !snapshot || !snapshot->valid) {
        errno = EINVAL;
        return -1;
    }
    stat_status = stat(path, &current);
    if (stat_status == 0 &&
        input_snapshot_matches(snapshot, &current))
        return 0;

    saved_errno = stat_status < 0 && errno ? errno : ESTALE;
    fprintf(stderr, "dlfreeze: input changed %s: %s\n", phase, path);
    errno = saved_errno;
    return -1;
}

/* Reuse bytes already copied into this transaction only when the prospective
 * source still has the exact snapshotted filesystem identity.  The alias
 * keeps its own path and snapshot so final revalidation remains per request,
 * while identical manifest ranges give extraction a cheap, unambiguous proof
 * that two runtime roles may share one materialized file. */
static int dep_file_snapshots_equal(
    const struct dep_file_snapshot *left,
    const struct dep_file_snapshot *right)
{
    return left && right && left->valid && right->valid &&
           left->device == right->device &&
           left->inode == right->inode &&
           left->size == right->size &&
           left->mtime_sec == right->mtime_sec &&
           left->mtime_nsec == right->mtime_nsec &&
           left->ctime_sec == right->ctime_sec &&
           left->ctime_nsec == right->ctime_nsec;
}

struct packed_dep_source_ref {
    const struct dep_file_snapshot *snapshot;
    int manifest_index;
    int dep_index;
};

struct packed_dep_source_plan {
    int *manifest_aliases;
    int *group_leaders;
    size_t unique_group_count;
    int aliases_main;
};

static int packed_dep_source_ref_cmp(const void *left_ptr,
                                     const void *right_ptr)
{
    const struct packed_dep_source_ref *left = left_ptr;
    const struct packed_dep_source_ref *right = right_ptr;
    const struct dep_file_snapshot *ls = left->snapshot;
    const struct dep_file_snapshot *rs = right->snapshot;
    int cmp;

#define PACKED_SNAPSHOT_CMP(field)                                         \
    do {                                                                    \
        cmp = ls->field < rs->field ? -1 : ls->field > rs->field;          \
        if (cmp != 0)                                                       \
            return cmp;                                                     \
    } while (0)

    PACKED_SNAPSHOT_CMP(device);
    PACKED_SNAPSHOT_CMP(inode);
    PACKED_SNAPSHOT_CMP(size);
    PACKED_SNAPSHOT_CMP(mtime_sec);
    PACKED_SNAPSHOT_CMP(mtime_nsec);
    PACKED_SNAPSHOT_CMP(ctime_sec);
    PACKED_SNAPSHOT_CMP(ctime_nsec);

#undef PACKED_SNAPSHOT_CMP

    return left->manifest_index < right->manifest_index ? -1 :
           left->manifest_index > right->manifest_index;
}

static void packed_dep_source_plan_free(struct packed_dep_source_plan *plan)
{
    if (!plan)
        return;
    free(plan->manifest_aliases);
    free(plan->group_leaders);
    memset(plan, 0, sizeof(*plan));
}

/* Build the exact immutable-source equivalence classes once.  Manifest
 * production, direct-mode admission, and bootstrap validation must agree on
 * which byte revisions alias; sorting also prevents a large hardlink/soname
 * alias set from amplifying admission and payload construction quadratically.
 */
static int packed_build_dep_source_plan(
    const struct dep_list *deps, struct packed_dep_source_plan *plan)
{
    struct packed_dep_source_ref *refs = NULL;
    size_t source_count;
    size_t ref_count = 0;
    int first_lib;

    if (!deps || !plan || deps->count < 0 ||
        (deps->count > 0 && !deps->libs)) {
        errno = EINVAL;
        return -1;
    }
    memset(plan, 0, sizeof(*plan));
    first_lib = 1 + (deps->interp_path ? 1 : 0);
    if (deps->count > INT_MAX - first_lib) {
        errno = EOVERFLOW;
        return -1;
    }
    source_count = (size_t)first_lib + (size_t)deps->count;
    if (source_count > SIZE_MAX / sizeof(*refs) ||
        (size_t)deps->count > SIZE_MAX / sizeof(*plan->manifest_aliases) ||
        (size_t)deps->count > SIZE_MAX / sizeof(*plan->group_leaders)) {
        errno = EOVERFLOW;
        return -1;
    }
    refs = malloc(source_count * sizeof(*refs));
    if (deps->count > 0) {
        plan->manifest_aliases =
            malloc((size_t)deps->count * sizeof(*plan->manifest_aliases));
        plan->group_leaders =
            malloc((size_t)deps->count * sizeof(*plan->group_leaders));
    }
    if (!refs || (deps->count > 0 &&
                  (!plan->manifest_aliases || !plan->group_leaders)))
        goto fail;
    if (!deps->main_snapshot.valid ||
        (deps->interp_path && !deps->interp_snapshot.valid)) {
        errno = EINVAL;
        goto fail;
    }

    refs[ref_count++] = (struct packed_dep_source_ref) {
        &deps->main_snapshot, 0, -1
    };
    if (deps->interp_path) {
        refs[ref_count++] = (struct packed_dep_source_ref) {
            &deps->interp_snapshot, 1, -1
        };
    }
    for (int i = 0; i < deps->count; i++) {
        if (!deps->libs[i].snapshot.valid) {
            errno = EINVAL;
            goto fail;
        }
        refs[ref_count++] = (struct packed_dep_source_ref) {
            &deps->libs[i].snapshot, first_lib + i, i
        };
        plan->manifest_aliases[i] = -1;
        plan->group_leaders[i] = -1;
    }
    if (ref_count != source_count) {
        errno = EINVAL;
        goto fail;
    }

    qsort(refs, ref_count, sizeof(*refs), packed_dep_source_ref_cmp);
    for (size_t begin = 0; begin < ref_count;) {
        size_t end = begin + 1;
        int owner = refs[begin].manifest_index;
        int leader = -1;
        int has_main = owner == 0;

        while (end < ref_count &&
               dep_file_snapshots_equal(refs[begin].snapshot,
                                        refs[end].snapshot))
            end++;
        for (size_t i = begin; i < end; i++) {
            if (refs[i].manifest_index == 0)
                has_main = 1;
            if (refs[i].dep_index >= 0 && leader < 0)
                leader = refs[i].dep_index;
        }
        if (leader >= 0) {
            plan->unique_group_count++;
            if (has_main)
                plan->aliases_main = 1;
            for (size_t i = begin; i < end; i++) {
                int dep_index = refs[i].dep_index;

                if (dep_index < 0)
                    continue;
                plan->group_leaders[dep_index] = leader;
                if (refs[i].manifest_index != owner)
                    plan->manifest_aliases[dep_index] = owner;
            }
        }
        begin = end;
    }

    free(refs);
    return 0;

fail:
    free(refs);
    packed_dep_source_plan_free(plan);
    return -1;
}

/* A musl interpreter is libc too, so one immutable file may legitimately
 * have both INTERP and SHLIB manifest identities.  No other role is allowed
 * to inherit ELF geometry merely because its payload range is identical. */
struct packed_source_ref {
    uint64_t data_offset;
    uint64_t data_size;
    int entry_index;
};

static int packed_source_alias_role(uint32_t flags)
{
    uint32_t role = flags & (DLFRZ_FLAG_MAIN_EXE |
                             DLFRZ_FLAG_INTERP |
                             DLFRZ_FLAG_SHLIB |
                             DLFRZ_FLAG_DATA);

    return role == DLFRZ_FLAG_INTERP || role == DLFRZ_FLAG_SHLIB;
}

static int packed_source_ref_cmp(const void *left_pointer,
                                 const void *right_pointer)
{
    const struct packed_source_ref *left = left_pointer;
    const struct packed_source_ref *right = right_pointer;

    if (left->data_offset < right->data_offset)
        return -1;
    if (left->data_offset > right->data_offset)
        return 1;
    if (left->data_size < right->data_size)
        return -1;
    if (left->data_size > right->data_size)
        return 1;
    if (left->entry_index < right->entry_index)
        return -1;
    if (left->entry_index > right->entry_index)
        return 1;
    return 0;
}

static int packed_collect_source_refs(
    const struct dlfrz_entry *entries, int count,
    struct packed_source_ref **refs_out, size_t *count_out)
{
    struct packed_source_ref *refs;
    size_t ref_count = 0;

    if (!entries || count <= 0 || !refs_out || !count_out ||
        (size_t)count > SIZE_MAX / sizeof(*refs)) {
        errno = EINVAL;
        return -1;
    }
    refs = malloc((size_t)count * sizeof(*refs));
    if (!refs)
        return -1;
    for (int i = 0; i < count; i++) {
        if (!packed_source_alias_role(entries[i].flags) ||
            entries[i].data_size == 0)
            continue;
        refs[ref_count++] = (struct packed_source_ref) {
            entries[i].data_offset, entries[i].data_size, i
        };
    }
    qsort(refs, ref_count, sizeof(*refs), packed_source_ref_cmp);
    *refs_out = refs;
    *count_out = ref_count;
    return 0;
}

/* Resolve immutable-source and ordinary-startup ownership once.  Both maps
 * contain -1 for their group owner and the owner's manifest index for every
 * later alias.  This retains manifest-order ownership without repeated
 * prefix scans when a source has many lookup identities. */
static int packed_build_alias_owners(
    const struct dlfrz_entry *entries,
    const struct dlfrz_lib_meta *metas, int count,
    int *source_aliases, int *startup_aliases)
{
    struct packed_source_ref *refs = NULL;
    size_t ref_count = 0;
    int result = -1;

    if (!source_aliases && !startup_aliases) {
        errno = EINVAL;
        return -1;
    }
    if (packed_collect_source_refs(
            entries, count, &refs, &ref_count) < 0)
        return -1;
    for (int i = 0; i < count; i++) {
        if (source_aliases)
            source_aliases[i] = -1;
        if (startup_aliases)
            startup_aliases[i] = -1;
    }

    for (size_t begin = 0; begin < ref_count;) {
        size_t end = begin + 1;
        int source_owner = refs[begin].entry_index;
        int startup_owner = -1;

        while (end < ref_count &&
               refs[end].data_offset == refs[begin].data_offset &&
               refs[end].data_size == refs[begin].data_size)
            end++;
        for (size_t i = begin; i < end; i++) {
            int index = refs[i].entry_index;

            if (source_aliases && index != source_owner)
                source_aliases[index] = source_owner;
            if (!startup_aliases)
                continue;
            if (!metas) {
                errno = EINVAL;
                goto out;
            }
            /* INTERP owns no runtime object and a lazy/promoted DLOPEN
             * identity owns no prelink work.  The first ordinary SHLIB is
             * the startup owner even when INTERP supplied the geometry. */
            if ((metas[index].flags & (DLFRZ_FLAG_INTERP |
                                       DLFRZ_FLAG_DLOPEN)) != 0 ||
                (metas[index].flags & DLFRZ_FLAG_SHLIB) == 0)
                continue;
            if (startup_owner < 0)
                startup_owner = index;
            else
                startup_aliases[index] = startup_owner;
        }
        begin = end;
    }
    result = 0;

out:
    free(refs);
    return result;
}

static int packed_alias_geometry_matches(
    const struct dlfrz_lib_meta *left,
    const struct dlfrz_lib_meta *right)
{
    return left->base_addr == right->base_addr &&
           left->vaddr_lo == right->vaddr_lo &&
           left->vaddr_hi == right->vaddr_hi &&
           left->entry == right->entry &&
           left->phdr_file_off == right->phdr_file_off &&
           left->phdr_off == right->phdr_off &&
           left->phdr_num == right->phdr_num &&
           left->phdr_entsz == right->phdr_entsz &&
           ((left->flags ^ right->flags) & DLFRZ_FLAG_NEEDS_RTLD) == 0;
}

static int packed_alias_runtime_state_matches(
    const struct dlfrz_lib_meta *left,
    const struct dlfrz_lib_meta *right)
{
    return ((left->flags ^ right->flags) &
            (DLFRZ_FLAG_PRELINKED | DLFRZ_FLAG_RUNTIME_SCAN)) == 0 &&
           left->runtime_fixup_off == right->runtime_fixup_off &&
           left->runtime_fixup_count == right->runtime_fixup_count;
}

static int packed_canonicalize_alias_metadata(
    struct dlfrz_lib_meta *metas, int count,
    const int *source_aliases)
{
    unsigned char *source_is_early;
    int *ordinary_owners;

    if (!metas || count <= 0 || !source_aliases) {
        errno = EINVAL;
        return -1;
    }
    source_is_early = calloc((size_t)count, sizeof(*source_is_early));
    ordinary_owners = malloc((size_t)count * sizeof(*ordinary_owners));
    if (!source_is_early || !ordinary_owners) {
        free(ordinary_owners);
        free(source_is_early);
        return -1;
    }
    for (int i = 0; i < count; i++)
        ordinary_owners[i] = -1;

    for (int i = 0; i < count; i++) {
        int owner = source_aliases[i] >= 0 ? source_aliases[i] : i;

        if (owner < 0 || owner > i || owner >= count ||
            (source_aliases[i] >= 0 &&
             !packed_alias_geometry_matches(&metas[owner], &metas[i]))) {
            free(ordinary_owners);
            free(source_is_early);
            errno = EINVAL;
            return -1;
        }
        if ((metas[i].flags & (DLFRZ_FLAG_DLOPEN |
                               DLFRZ_FLAG_DLOPEN_EARLY)) ==
            (DLFRZ_FLAG_DLOPEN | DLFRZ_FLAG_DLOPEN_EARLY))
            source_is_early[owner] = 1;
        if ((metas[i].flags & (DLFRZ_FLAG_INTERP |
                               DLFRZ_FLAG_DLOPEN)) == 0 &&
            (metas[i].flags & DLFRZ_FLAG_SHLIB) != 0) {
            if (ordinary_owners[owner] < 0) {
                ordinary_owners[owner] = i;
            } else if (!packed_alias_runtime_state_matches(
                           &metas[ordinary_owners[owner]], &metas[i])) {
                free(ordinary_owners);
                free(source_is_early);
                errno = EINVAL;
                return -1;
            }
        }
    }
    for (int i = 0; i < count; i++) {
        int owner = source_aliases[i] >= 0 ? source_aliases[i] : i;

        if ((metas[i].flags & DLFRZ_FLAG_DLOPEN) &&
            source_is_early[owner])
            metas[i].flags |= DLFRZ_FLAG_DLOPEN_EARLY;
    }
    free(ordinary_owners);
    free(source_is_early);
    return 0;
}

static int validate_copied_elf(FILE *output, const char *path,
                              uint64_t offset, size_t length,
                              int expected_class, uint16_t expected_machine,
                              uint32_t entry_flags)
{
    struct elf_info info;
    int fd;
    int valid;

    memset(&info, 0, sizeof(info));
    fd = fileno(output);
    if (fd < 0 || elf_parse_fd_range(fd, offset, length, &info) < 0) {
        fprintf(stderr, "dlfreeze: copied ELF input is malformed: %s\n",
                path ? path : "(null)");
        errno = EINVAL;
        return -1;
    }
    valid = info.ei_class == expected_class &&
            info.e_machine == expected_machine &&
            (!(entry_flags & (DLFRZ_FLAG_INTERP | DLFRZ_FLAG_SHLIB)) ||
             (info.is_dynamic && info.is_pie));
    elf_info_free(&info);
    if (valid)
        return 0;
    fprintf(stderr, "dlfreeze: copied ELF input is incompatible: %s\n",
            path ? path : "(null)");
    errno = ENOEXEC;
    return -1;
}

static int append_file(FILE *out, const char *path,
                       const struct dep_file_snapshot *expected,
                       size_t *written,
                       struct packed_input_snapshot *snapshot)
{
    struct stat before;
    struct stat after;
    char buf[65536];
    FILE *in;
    size_t total = 0;
    int saved_errno = 0;
    int rc = -1;

    if (!out || !path || !written) {
        errno = EINVAL;
        return -1;
    }
    *written = 0;
    if (snapshot)
        snapshot->valid = 0;
    in = fopen(path, "rb");
    if (!in) {
        perror(path);
        return -1;
    }
    if (fstat(fileno(in), &before) < 0) {
        saved_errno = errno ? errno : EIO;
        fprintf(stderr, "dlfreeze: cannot snapshot input %s: %s\n", path,
                strerror(saved_errno));
        goto out;
    }
    if (!resolved_snapshot_matches(expected, &before)) {
        saved_errno = ESTALE;
        fprintf(stderr,
                "dlfreeze: resolved input changed before packing: %s\n",
                path);
        goto out;
    }
    if (!S_ISREG(before.st_mode) || before.st_size < 0 ||
        (uintmax_t)before.st_size > SIZE_MAX) {
        saved_errno = EINVAL;
        fprintf(stderr, "dlfreeze: input is not a bounded regular file: %s\n",
                path);
        goto out;
    }

    for (;;) {
        size_t n = fread(buf, 1, sizeof(buf), in);

        if (n != 0) {
            if (n > SIZE_MAX - total) {
                saved_errno = EOVERFLOW;
                goto out;
            }
            if (fwrite(buf, 1, n, out) != n) {
                saved_errno = errno ? errno : EIO;
                fprintf(stderr, "dlfreeze: cannot append %s: %s\n", path,
                        strerror(saved_errno));
                goto out;
            }
            total += n;
        }
        if (n == sizeof(buf))
            continue;
        if (ferror(in)) {
            saved_errno = errno ? errno : EIO;
            fprintf(stderr, "dlfreeze: read error for %s: %s\n", path,
                    strerror(saved_errno));
            goto out;
        }
        if (!feof(in)) {
            saved_errno = EIO;
            fprintf(stderr, "dlfreeze: short read without EOF for %s\n",
                    path);
            goto out;
        }
        break;
    }

    if (fstat(fileno(in), &after) < 0) {
        saved_errno = errno ? errno : EIO;
        fprintf(stderr, "dlfreeze: cannot recheck input %s: %s\n", path,
                strerror(saved_errno));
        goto out;
    }
    if (total != (size_t)before.st_size ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) {
        saved_errno = ESTALE;
        fprintf(stderr, "dlfreeze: input changed while packing: %s\n", path);
        goto out;
    }

    rc = 0;
out:
    if (fclose(in) != 0) {
        int close_errno = errno ? errno : EIO;

        fprintf(stderr, "dlfreeze: close error for %s: %s\n", path,
                strerror(close_errno));
        if (rc == 0 || saved_errno == 0)
            saved_errno = close_errno;
        rc = -1;
    }
    if (rc == 0) {
        *written = total;
        if (snapshot) {
            snapshot->st = after;
            snapshot->valid = 1;
        }
        return 0;
    }
    errno = saved_errno ? saved_errno : EIO;
    return -1;
}

static int size_add_assign(size_t *value, size_t increment)
{
    if (!value || increment > SIZE_MAX - *value) {
        errno = EOVERFLOW;
        return -1;
    }
    *value += increment;
    return 0;
}

static int write_pad(FILE *out, size_t *cur, size_t align)
{
    size_t target;
    size_t pad;

    if (!out || !cur || align == 0 || (align & (align - 1)) != 0 ||
        *cur > SIZE_MAX - (align - 1)) {
        errno = EOVERFLOW;
        return -1;
    }
    target = (*cur + align - 1) & ~(align - 1);
    pad = target - *cur;
    while (pad > 0) {
        char zeros[4096] = {0};
        size_t chunk = pad > sizeof(zeros) ? sizeof(zeros) : pad;
        if (fwrite(zeros, 1, chunk, out) != chunk) {
            if (errno == 0)
                errno = EIO;
            return -1;
        }
        pad -= chunk;
    }
    *cur = target;
    return 0;
}

static int filesize(const char *path, size_t *size_out)
{
    struct stat st;

    if (!path || !size_out || stat(path, &st) < 0)
        return -1;
    if (!S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uintmax_t)st.st_size > SIZE_MAX) {
        errno = EFBIG;
        return -1;
    }
    *size_out = (size_t)st.st_size;
    return 0;
}

static int packer_stream_seek(FILE *stream, uint64_t offset)
{
    if (!stream || offset > (uint64_t)INT64_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    return fseeko(stream, (off_t)offset, SEEK_SET);
}

static int create_output_transaction(const char *output_path,
                                     char transaction_path[PATH_MAX],
                                     FILE **stream_out)
{
    static const char leaf[] = ".dlfreeze-pack.XXXXXX";
    const char *slash;
    size_t prefix_len = 0;
    size_t leaf_len = sizeof(leaf) - 1;
    int fd = -1;
    int fd_flags;
    FILE *stream = NULL;

    if (!output_path || output_path[0] == '\0' || !transaction_path ||
        !stream_out) {
        errno = EINVAL;
        return -1;
    }
    transaction_path[0] = '\0';
    *stream_out = NULL;
    slash = strrchr(output_path, '/');
    if (slash) {
        prefix_len = (size_t)(slash - output_path);
        if (prefix_len == 0) {
            transaction_path[0] = '/';
            prefix_len = 1;
        } else {
            memcpy(transaction_path, output_path, prefix_len);
        }
    }
    if (prefix_len > PATH_MAX - leaf_len - 2) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (prefix_len != 0 && transaction_path[prefix_len - 1] != '/')
        transaction_path[prefix_len++] = '/';
    memcpy(transaction_path + prefix_len, leaf, leaf_len + 1);

    fd = mkstemp(transaction_path);
    if (fd < 0)
        return -1;
    fd_flags = fcntl(fd, F_GETFD);
    if (fd_flags < 0 || fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC) < 0)
        goto fail;
    stream = fdopen(fd, "w+b");
    if (!stream)
        goto fail;
    fd = -1;
    *stream_out = stream;
    return 0;

fail:
    {
        int saved_errno = errno ? errno : EIO;

        if (fd >= 0)
            close(fd);
        unlink(transaction_path);
        transaction_path[0] = '\0';
        errno = saved_errno;
        return -1;
    }
}

static int finish_output_stream(FILE **stream_ptr)
{
    FILE *stream;
    int fd;
    int saved_errno = 0;

    if (!stream_ptr || !*stream_ptr) {
        errno = EINVAL;
        return -1;
    }
    stream = *stream_ptr;
    fd = fileno(stream);
    if (fd < 0)
        saved_errno = errno ? errno : EIO;
    if (fflush(stream) != 0 && saved_errno == 0)
        saved_errno = errno ? errno : EIO;
    if (fd >= 0 && fsync(fd) != 0 && saved_errno == 0)
        saved_errno = errno ? errno : EIO;
    if (fclose(stream) != 0 && saved_errno == 0)
        saved_errno = errno ? errno : EIO;
    *stream_ptr = NULL;
    if (saved_errno != 0) {
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static int sync_output_transaction(const char *path)
{
    int fd;
    int saved_errno = 0;

    fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (fchmod(fd, 0755) < 0)
        saved_errno = errno ? errno : EIO;
    if (fsync(fd) < 0 && saved_errno == 0)
        saved_errno = errno ? errno : EIO;
    if (close(fd) < 0 && saved_errno == 0)
        saved_errno = errno ? errno : EIO;
    if (saved_errno != 0) {
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static int open_output_parent_directory(const char *output_path)
{
    const char *slash;
    char directory[PATH_MAX];
    size_t length;

    slash = strrchr(output_path, '/');
    if (!slash)
        return open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    length = (size_t)(slash - output_path);
    if (length == 0) {
        directory[0] = '/';
        directory[1] = '\0';
    } else {
        if (length >= sizeof(directory)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(directory, output_path, length);
        directory[length] = '\0';
    }
    return open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

static int fsync_retry(int fd)
{
    int result;

    do {
        result = fsync(fd);
    } while (result < 0 && errno == EINTR);
    return result;
}

static int rename_with_flags(const char *old_path, const char *new_path,
                             unsigned int flags)
{
#if defined(SYS_renameat2)
    return (int)syscall(SYS_renameat2, AT_FDCWD, old_path, AT_FDCWD,
                        new_path, flags);
#elif defined(__NR_renameat2)
    return (int)syscall(__NR_renameat2, AT_FDCWD, old_path, AT_FDCWD,
                        new_path, flags);
#else
    (void)old_path;
    (void)new_path;
    (void)flags;
    errno = ENOTSUP;
    return -1;
#endif
}

/* Publish only after the file and its temporary directory entry are durable.
 * Linux renameat2 flags are used fail-closed: RENAME_EXCHANGE retains an
 * existing destination at transaction_path until the committed directory
 * state is synced, while RENAME_NOREPLACE prevents a concurrent destination
 * from being overwritten.  A kernel/filesystem without these semantics is
 * rejected before publication rather than weakening the transaction. */
static int commit_output_transaction(char transaction_path[PATH_MAX],
                                     const char *output_path)
{
    struct stat existing;
    int directory_fd;
    int destination_exists;
    int saved_errno;

    directory_fd = open_output_parent_directory(output_path);
    if (directory_fd < 0)
        return -1;
    if (fsync_retry(directory_fd) < 0) {
        saved_errno = errno ? errno : EIO;
        close(directory_fd);
        errno = saved_errno;
        return -1;
    }

    destination_exists = lstat(output_path, &existing) == 0;
    if (!destination_exists && errno != ENOENT) {
        saved_errno = errno ? errno : EIO;
        close(directory_fd);
        errno = saved_errno;
        return -1;
    }

    if (destination_exists) {
        if (rename_with_flags(transaction_path, output_path,
                              RENAME_EXCHANGE) < 0) {
            saved_errno = errno ? errno : EIO;
            close(directory_fd);
            errno = saved_errno;
            return -1;
        }
        if (fsync_retry(directory_fd) < 0) {
            saved_errno = errno ? errno : EIO;
            if (rename_with_flags(transaction_path, output_path,
                                  RENAME_EXCHANGE) < 0) {
                fprintf(stderr,
                        "dlfreeze: cannot roll back failed output commit: %s\n",
                        strerror(errno));
            } else if (fsync_retry(directory_fd) < 0) {
                fprintf(stderr,
                        "dlfreeze: cannot sync rolled-back output: %s\n",
                        strerror(errno));
            }
            close(directory_fd);
            errno = saved_errno;
            return -1;
        }

        /* transaction_path now names the old destination.  If it cannot be
         * removed, exchange it back before reporting failure. */
        if (unlink(transaction_path) < 0) {
            saved_errno = errno ? errno : EIO;
            if (rename_with_flags(transaction_path, output_path,
                                  RENAME_EXCHANGE) < 0) {
                fprintf(stderr,
                        "dlfreeze: cannot roll back output cleanup failure: "
                        "%s\n", strerror(errno));
            } else {
                if (unlink(transaction_path) < 0 && errno != ENOENT)
                    fprintf(stderr,
                            "dlfreeze: cannot remove rolled-back transaction: "
                            "%s\n", strerror(errno));
                if (fsync_retry(directory_fd) < 0)
                    fprintf(stderr,
                            "dlfreeze: cannot sync rolled-back output: %s\n",
                            strerror(errno));
            }
            close(directory_fd);
            errno = saved_errno;
            return -1;
        }

        /* The exchange itself is already durable.  This second sync makes
         * removal of the retained old destination durable as well. */
        if (fsync_retry(directory_fd) < 0)
            fprintf(stderr,
                    "dlfreeze: warning: old output cleanup is not durable: %s\n",
                    strerror(errno));
    } else {
        if (rename_with_flags(transaction_path, output_path,
                              RENAME_NOREPLACE) < 0) {
            saved_errno = errno ? errno : EIO;
            close(directory_fd);
            errno = saved_errno;
            return -1;
        }
        if (fsync_retry(directory_fd) < 0) {
            saved_errno = errno ? errno : EIO;
            if (rename_with_flags(output_path, transaction_path,
                                  RENAME_NOREPLACE) < 0) {
                fprintf(stderr,
                        "dlfreeze: cannot roll back failed output commit: %s\n",
                        strerror(errno));
            } else if (fsync_retry(directory_fd) < 0) {
                fprintf(stderr,
                        "dlfreeze: cannot sync rolled-back output: %s\n",
                        strerror(errno));
            }
            close(directory_fd);
            errno = saved_errno;
            return -1;
        }
    }

    if (close(directory_fd) < 0)
        fprintf(stderr, "dlfreeze: warning: output directory close failed: %s\n",
                strerror(errno));
    return 0;
}

static int reject_output_alias(const struct stat *output_st,
                               const char *output_path,
                               const char *input_path)
{
    struct stat input_st;

    if (!input_path)
        return 0;
    if (stat(input_path, &input_st) < 0) {
        fprintf(stderr, "dlfreeze: cannot inspect input %s: %s\n",
                input_path, strerror(errno));
        return -1;
    }
    if (output_st->st_dev != input_st.st_dev ||
        output_st->st_ino != input_st.st_ino)
        return 0;

    fprintf(stderr, "dlfreeze: output %s aliases input %s\n",
            output_path, input_path);
    errno = EINVAL;
    return -1;
}

static int validate_output_aliases(const struct pack_options *opts)
{
    struct stat output_st;

    if (stat(opts->output_path, &output_st) < 0) {
        if (errno == ENOENT)
            return 0;
        fprintf(stderr, "dlfreeze: cannot inspect output %s: %s\n",
                opts->output_path, strerror(errno));
        return -1;
    }
    if (reject_output_alias(&output_st, opts->output_path,
                            opts->bootstrap_path) < 0 ||
        reject_output_alias(&output_st, opts->output_path,
                            opts->exe_path) < 0 ||
        (opts->deps->interp_path &&
         reject_output_alias(&output_st, opts->output_path,
                             opts->deps->interp_path) < 0))
        return -1;
    for (int i = 0; i < opts->deps->count; i++) {
        if (reject_output_alias(&output_st, opts->output_path,
                                opts->deps->libs[i].path) < 0)
            return -1;
    }
    if (opts->data_files) {
        for (int i = 0; i < opts->data_files->count; i++) {
            if (opts->data_files->kinds[i] == DATA_FILE_KIND_REGULAR &&
                reject_output_alias(&output_st, opts->output_path,
                                    opts->data_files->source_paths[i]) < 0)
                return -1;
        }
    }
    return 0;
}

static int make_transaction_copy(const char *path, const char *suffix,
                                 char copy_path[PATH_MAX])
{
    struct stat st;
    char buffer[1 << 16];
    int src = -1;
    int dst = -1;
    int rc = -1;

    if (snprintf(copy_path, PATH_MAX, "%s.%s.XXXXXX", path, suffix) >=
        PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }
    src = open(path, O_RDONLY | O_CLOEXEC);
    if (src < 0 || fstat(src, &st) < 0)
        goto out;
    dst = mkstemp(copy_path);
    if (dst < 0)
        goto out;
    if (fchmod(dst, st.st_mode & 0777) < 0)
        goto out;

    for (;;) {
        ssize_t got = read(src, buffer, sizeof(buffer));

        if (got < 0) {
            if (errno == EINTR)
                continue;
            goto out;
        }
        if (got == 0)
            break;
        for (ssize_t written = 0; written < got;) {
            ssize_t n = write(dst, buffer + written, (size_t)(got - written));

            if (n < 0) {
                if (errno == EINTR)
                    continue;
                goto out;
            }
            if (n == 0) {
                errno = EIO;
                goto out;
            }
            written += n;
        }
    }
    if (fsync(dst) < 0)
        goto out;
    rc = 0;

out:
    if (src >= 0 && close(src) < 0 && rc == 0)
        rc = -1;
    if (dst >= 0 && close(dst) < 0)
        rc = -1;
    if (rc < 0 && dst >= 0)
        unlink(copy_path);
    return rc;
}

struct bounded_elf_sections {
    int fd;
    size_t file_size;
    size_t count;
    Elf64_Shdr *items;
};

static int packer_file_range_valid(uint64_t offset, uint64_t length,
                                   size_t file_size)
{
    return offset <= file_size && length <= file_size - offset;
}

static int packer_pread_exact(int fd, void *buffer, size_t size,
                              uint64_t offset)
{
    unsigned char *out = buffer;
    size_t done = 0;

    while (done < size) {
        size_t chunk = size - done;
        ssize_t got;

        if (chunk > (size_t)SSIZE_MAX)
            chunk = (size_t)SSIZE_MAX;
        got = pread(fd, out + done, chunk, (off_t)(offset + done));
        if (got < 0 && errno == EINTR)
            continue;
        if (got == 0) {
            errno = ESTALE;
            return -1;
        }
        if (got < 0)
            return -1;
        done += (size_t)got;
    }
    return 0;
}

struct packer_stable_file_image {
    uint8_t *bytes;
    size_t size;
    struct stat snapshot;
};

static void packer_stable_file_image_free(
    struct packer_stable_file_image *image)
{
    if (!image)
        return;
    free(image->bytes);
    memset(image, 0, sizeof(*image));
}

static int packer_stat_snapshot_matches(const struct stat *before,
                                        const struct stat *after)
{
    return before && after && before->st_dev == after->st_dev &&
           before->st_ino == after->st_ino &&
           before->st_mode == after->st_mode &&
           before->st_size == after->st_size &&
           before->st_mtim.tv_sec == after->st_mtim.tv_sec &&
           before->st_mtim.tv_nsec == after->st_mtim.tv_nsec &&
           before->st_ctim.tv_sec == after->st_ctim.tv_sec &&
           before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
}

/* Copy a regular file into process-owned memory, then prove that the open
 * description retained the same identity, size, and change timestamps for
 * the whole read.  Parsers never dereference a file-backed mapping, so a
 * concurrent truncate is an ordinary failed admission rather than SIGBUS.
 * The caller-supplied initial stat also makes the fstat->read race directly
 * testable. */
static int packer_read_stable_fd(
    int fd, const struct stat *before,
    struct packer_stable_file_image *image)
{
    struct stat after;
    uint8_t *bytes;
    size_t size;

    if (!image) {
        errno = EINVAL;
        return -1;
    }
    memset(image, 0, sizeof(*image));
    if (fd < 0 || !before ||
        !S_ISREG(before->st_mode) || before->st_size <= 0 ||
        (uintmax_t)before->st_size > SIZE_MAX) {
        errno = EINVAL;
        return -1;
    }
    size = (size_t)before->st_size;
    bytes = malloc(size);
    if (!bytes)
        return -1;
    if (packer_pread_exact(fd, bytes, size, 0) < 0) {
        int saved_errno = errno ? errno : EIO;

        free(bytes);
        errno = saved_errno;
        return -1;
    }
    if (fstat(fd, &after) < 0) {
        int saved_errno = errno ? errno : EIO;

        free(bytes);
        errno = saved_errno;
        return -1;
    }
    if (!packer_stat_snapshot_matches(before, &after)) {
        free(bytes);
        errno = ESTALE;
        return -1;
    }
    image->bytes = bytes;
    image->size = size;
    image->snapshot = after;
    return 0;
}

static int packer_read_stable_file(
    const char *path, struct packer_stable_file_image *image)
{
    struct stat before;
    int fd;
    int result;
    int saved_errno;

    if (!path || !image) {
        errno = EINVAL;
        return -1;
    }
    memset(image, 0, sizeof(*image));
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (fstat(fd, &before) < 0)
        result = -1;
    else
        result = packer_read_stable_fd(fd, &before, image);
    saved_errno = errno;
    if (close(fd) < 0 && result == 0) {
        result = -1;
        saved_errno = errno;
        packer_stable_file_image_free(image);
    }
    if (result < 0)
        errno = saved_errno ? saved_errno : EIO;
    return result;
}

static void bounded_elf_sections_close(struct bounded_elf_sections *table)
{
    free(table->items);
    memset(table, 0, sizeof(*table));
    table->fd = -1;
}

/* Load and validate the on-disk section table once.  A fully stripped ELF
 * (e_shoff == e_shnum == 0) is valid and produces an empty table.  Extended
 * section counts and string-table indices are accepted through section zero. */
static int bounded_elf_sections_open(FILE *file, const Elf64_Ehdr *ehdr,
                                     struct bounded_elf_sections *table)
{
    Elf64_Shdr section_zero;
    struct stat st;
    size_t count;
    size_t bytes;

    memset(table, 0, sizeof(*table));
    table->fd = fileno(file);
    if (table->fd < 0 || fstat(table->fd, &st) < 0 || st.st_size < 0 ||
        (uintmax_t)st.st_size > SIZE_MAX)
        return -1;
    table->file_size = (size_t)st.st_size;

    if (ehdr->e_shoff == 0)
        return ehdr->e_shnum == 0 && ehdr->e_shstrndx == SHN_UNDEF
            ? 0 : -1;
    if (ehdr->e_shentsize != sizeof(Elf64_Shdr) ||
        !packer_file_range_valid(ehdr->e_shoff, sizeof(section_zero),
                                 table->file_size) ||
        packer_pread_exact(table->fd, &section_zero, sizeof(section_zero),
                           ehdr->e_shoff) < 0)
        return -1;

    if (ehdr->e_shnum != 0) {
        if (ehdr->e_shnum >= SHN_LORESERVE)
            return -1;
        count = ehdr->e_shnum;
    } else {
        if (section_zero.sh_size == 0 || section_zero.sh_size > SIZE_MAX)
            return -1;
        count = (size_t)section_zero.sh_size;
    }
    if (count > SIZE_MAX / sizeof(Elf64_Shdr))
        return -1;
    bytes = count * sizeof(Elf64_Shdr);
    if (!packer_file_range_valid(ehdr->e_shoff, bytes, table->file_size))
        return -1;

    table->items = malloc(bytes);
    if (!table->items ||
        packer_pread_exact(table->fd, table->items, bytes,
                           ehdr->e_shoff) < 0)
        goto fail;
    table->count = count;
    if (table->items[0].sh_type != SHT_NULL)
        goto fail;

    if (ehdr->e_shstrndx != SHN_UNDEF) {
        size_t string_index;

        if (ehdr->e_shstrndx == SHN_XINDEX)
            string_index = table->items[0].sh_link;
        else if (ehdr->e_shstrndx >= SHN_LORESERVE)
            goto fail;
        else
            string_index = ehdr->e_shstrndx;

        if (string_index >= count ||
            table->items[string_index].sh_type != SHT_STRTAB)
            goto fail;
    }

    for (size_t i = 1; i < count; i++) {
        const Elf64_Shdr *section = &table->items[i];

        if (section->sh_type == SHT_NOBITS) {
            if (section->sh_offset > table->file_size)
                goto fail;
        } else if (!packer_file_range_valid(section->sh_offset,
                                            section->sh_size,
                                            table->file_size)) {
            goto fail;
        }

        if (section->sh_type == SHT_SYMTAB ||
            section->sh_type == SHT_DYNSYM) {
            if (section->sh_entsize != sizeof(Elf64_Sym) ||
                section->sh_size % sizeof(Elf64_Sym) != 0 ||
                section->sh_link >= count ||
                table->items[section->sh_link].sh_type != SHT_STRTAB)
                goto fail;
        } else if (section->sh_type == SHT_RELA) {
            if (section->sh_entsize != sizeof(Elf64_Rela) ||
                section->sh_size % sizeof(Elf64_Rela) != 0 ||
                section->sh_link >= count ||
                (table->items[section->sh_link].sh_type != SHT_SYMTAB &&
                 table->items[section->sh_link].sh_type != SHT_DYNSYM))
                goto fail;
        } else if (section->sh_type == SHT_REL) {
            if (section->sh_entsize != sizeof(Elf64_Rel) ||
                section->sh_size % sizeof(Elf64_Rel) != 0 ||
                section->sh_link >= count ||
                (table->items[section->sh_link].sh_type != SHT_SYMTAB &&
                 table->items[section->sh_link].sh_type != SHT_DYNSYM))
                goto fail;
        }
    }
    return 0;

fail:
    bounded_elf_sections_close(table);
    return -1;
}

static int bounded_elf_section_read(const struct bounded_elf_sections *table,
                                    size_t index, void **data_out,
                                    size_t *size_out)
{
    const Elf64_Shdr *section;
    void *data;
    size_t size;

    if (index >= table->count)
        return -1;
    section = &table->items[index];
    if (section->sh_type == SHT_NOBITS || section->sh_size > SIZE_MAX)
        return -1;
    size = (size_t)section->sh_size;
    data = malloc(size ? size : 1);
    if (!data)
        return -1;
    if (size != 0 &&
        packer_pread_exact(table->fd, data, size, section->sh_offset) < 0) {
        free(data);
        return -1;
    }
    *data_out = data;
    *size_out = size;
    return 0;
}

/* Returns 1 when found, 0 when absent, and -1 for malformed/I/O input. */
static int find_named_symbol(FILE *file, const Elf64_Ehdr *ehdr,
                             const char *target, uint64_t *value_out)
{
    struct bounded_elf_sections table;
    int result = -1;

    *value_out = 0;
    if (bounded_elf_sections_open(file, ehdr, &table) < 0)
        return -1;
    result = 0;
    for (size_t i = 0; i < table.count; i++) {
        const Elf64_Shdr *sym_section = &table.items[i];
        Elf64_Sym *symbols = NULL;
        char *strings = NULL;
        size_t symbols_size = 0;
        size_t strings_size = 0;

        if (sym_section->sh_type != SHT_SYMTAB &&
            sym_section->sh_type != SHT_DYNSYM)
            continue;
        if (bounded_elf_section_read(&table, sym_section->sh_link,
                                     (void **)&strings,
                                     &strings_size) < 0 ||
            bounded_elf_section_read(&table, i, (void **)&symbols,
                                     &symbols_size) < 0) {
            free(strings);
            free(symbols);
            goto out;
        }

        size_t symbol_count = symbols_size / sizeof(*symbols);
        for (size_t j = 0; j < symbol_count; j++) {
            const Elf64_Sym *symbol = &symbols[j];
            const char *name;

            if (symbol->st_name >= strings_size) {
                result = -1;
                break;
            }
            name = strings + symbol->st_name;
            if (!memchr(name, '\0', strings_size - symbol->st_name)) {
                result = -1;
                break;
            }
            if (symbol->st_shndx != SHN_UNDEF &&
                strcmp(name, target) == 0) {
                *value_out = symbol->st_value;
                result = 1;
                break;
            }
        }
        free(strings);
        free(symbols);
        if (result != 0)
            break;
    }

out:
    bounded_elf_sections_close(&table);
    return result;
}

/* Check if an ELF imports _rtld_global or _rtld_global_ro (undefined refs).
 * Returns -1 for malformed section/symbol metadata. */
static int has_rtld_import(FILE *file, const Elf64_Ehdr *ehdr)
{
    struct bounded_elf_sections table;
    int result = -1;

    if (bounded_elf_sections_open(file, ehdr, &table) < 0)
        return -1;
    result = 0;
    for (size_t i = 0; i < table.count && result == 0; i++) {
        const Elf64_Shdr *sym_section = &table.items[i];
        Elf64_Sym *symbols = NULL;
        char *strings = NULL;
        size_t symbols_size = 0;
        size_t strings_size = 0;

        if (sym_section->sh_type != SHT_DYNSYM)
            continue;
        if (bounded_elf_section_read(&table, sym_section->sh_link,
                                     (void **)&strings,
                                     &strings_size) < 0 ||
            bounded_elf_section_read(&table, i, (void **)&symbols,
                                     &symbols_size) < 0) {
            free(strings);
            free(symbols);
            goto out;
        }

        size_t symbol_count = symbols_size / sizeof(*symbols);
        for (size_t j = 0; j < symbol_count; j++) {
            const Elf64_Sym *symbol = &symbols[j];
            const char *name;

            if (symbol->st_name >= strings_size) {
                result = -1;
                break;
            }
            name = strings + symbol->st_name;
            if (!memchr(name, '\0', strings_size - symbol->st_name)) {
                result = -1;
                break;
            }
            if (symbol->st_shndx == SHN_UNDEF &&
                (strcmp(name, "_rtld_global") == 0 ||
                 strcmp(name, "_rtld_global_ro") == 0)) {
                result = 1;
                break;
            }
        }
        free(strings);
        free(symbols);
    }

out:
    bounded_elf_sections_close(&table);
    return result;
}

/* Determine whether a pre-linked object still needs runtime relocation work.
 * Do not infer loader-owned symbols from spelling conventions.  Any symbolic
 * GOT/PLT relocation can depend on runtime scope, symbol versions, interposed
 * loader services, or IFUNC selection, so retain the generic runtime pass. */
static int needs_runtime_reloc_scan(FILE *f, const Elf64_Ehdr *ehdr)
{
    struct bounded_elf_sections table;
    size_t dynsym_index = SIZE_MAX;
    Elf64_Sym *syms = NULL;
    char *strtab = NULL;
    size_t symtab_size = 0;
    size_t strtab_size = 0;
    int needs_scan = 0;

    if (bounded_elf_sections_open(f, ehdr, &table) < 0)
        return -1;
    if (table.count == 0) {
        bounded_elf_sections_close(&table);
        return 1;  /* stripped: retain conservative runtime scan */
    }
    for (size_t i = 0; i < table.count; i++) {
        if (table.items[i].sh_type == SHT_DYNSYM) {
            dynsym_index = i;
            break;
        }
    }
    if (dynsym_index == SIZE_MAX) {
        bounded_elf_sections_close(&table);
        return 1;
    }
    if (bounded_elf_section_read(&table,
                                 table.items[dynsym_index].sh_link,
                                 (void **)&strtab, &strtab_size) < 0 ||
        bounded_elf_section_read(&table, dynsym_index,
                                 (void **)&syms, &symtab_size) < 0) {
        free(strtab);
        free(syms);
        bounded_elf_sections_close(&table);
        return -1;
    }

    size_t nsyms = symtab_size / sizeof(*syms);
    for (size_t i = 0; i < table.count && !needs_scan; i++) {
        const Elf64_Shdr *sh = &table.items[i];
        Elf64_Rela *rels = NULL;
        size_t relasz = 0;

        /* Only dynamic relocations indexed through the selected DYNSYM can
         * name runtime imports.  Toolchains may also retain perfectly valid
         * SHT_RELA sections linked to the full SHT_SYMTAB (for example debug
         * or post-link metadata); interpreting their symbol indices through
         * DYNSYM would produce false matches or reject a valid ELF. */
        if (sh->sh_type != SHT_RELA || sh->sh_link != dynsym_index)
            continue;
        if (sh->sh_size == 0) continue;
        if (bounded_elf_section_read(&table, i, (void **)&rels,
                                     &relasz) < 0) {
            needs_scan = -1;
            break;
        }

        size_t nrels = relasz / sizeof(Elf64_Rela);
        for (size_t j = 0; j < nrels; j++) {
            uint32_t type = ELF64_R_TYPE(rels[j].r_info);
            if (type == ARCH_RELOC_IRELATIVE) {
                needs_scan = 1;
                break;
            }
            if (type != ARCH_RELOC_GLOB_DAT && type != ARCH_RELOC_JUMP_SLOT)
                continue;

            uint32_t sidx = ELF64_R_SYM(rels[j].r_info);
            if (sidx >= nsyms) {
                needs_scan = -1;
                break;
            }
            if (syms[sidx].st_name >= strtab_size) {
                needs_scan = -1;
                break;
            }
            const char *name = strtab + syms[sidx].st_name;
            if (!memchr(name, '\0', strtab_size - syms[sidx].st_name)) {
                needs_scan = -1;
                break;
            }
            (void)name;
            needs_scan = 1;
            break;
        }

        free(rels);
    }

    free(strtab);
    free(syms);
    bounded_elf_sections_close(&table);
    return needs_scan;
}

/* ---- compute per-library metadata for direct loading ------------- */
static int compute_lib_meta(const char *path,
                            const struct packed_input_snapshot *snapshot,
                            uint64_t base, uint32_t flags,
                            struct dlfrz_lib_meta *meta)
{
    FILE *f = fopen(path, "rb");
    struct stat st;
    if (!f) { perror(path); return -1; }

    if (fstat(fileno(f), &st) < 0) {
        fclose(f); return -1;
    }
    if (!input_snapshot_matches(snapshot, &st)) {
        errno = ESTALE;
        fclose(f); return -1;
    }
    if (st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
        errno = EINVAL;
        fclose(f); return -1;
    }

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, 1, sizeof(ehdr), f) != sizeof(ehdr)) {
        fclose(f); return -1;
    }
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr.e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr.e_ident[EI_VERSION] != EV_CURRENT ||
        (ehdr.e_ident[EI_OSABI] != ELFOSABI_NONE &&
         ehdr.e_ident[EI_OSABI] != ELFOSABI_LINUX) ||
        ehdr.e_ident[EI_ABIVERSION] != 0 ||
        ehdr.e_version != EV_CURRENT ||
        ehdr.e_flags != 0 ||
        (ehdr.e_type != ET_DYN && ehdr.e_type != ET_EXEC) ||
        (ehdr.e_type == ET_EXEC &&
         (flags & DLFRZ_FLAG_MAIN_EXE) == 0) ||
        ehdr.e_ehsize != sizeof(Elf64_Ehdr) ||
        ehdr.e_phentsize != sizeof(Elf64_Phdr)) {
        fprintf(stderr, "dlfreeze: %s: unsupported or malformed ELF\n", path);
        fclose(f); return -1;
    }
    for (size_t i = EI_PAD; i < EI_NIDENT; i++) {
        if (ehdr.e_ident[i] != 0) {
            fprintf(stderr,
                    "dlfreeze: %s: unsupported or malformed ELF\n", path);
            fclose(f);
            return -1;
        }
    }
#if defined(__x86_64__)
    if (ehdr.e_machine != EM_X86_64) {
#elif defined(__aarch64__)
    if (ehdr.e_machine != EM_AARCH64) {
#else
    if (1) {
#endif
        fprintf(stderr, "dlfreeze: %s: ELF machine does not match dlfreeze\n",
                path);
        fclose(f); return -1;
    }

    meta->base_addr  = base;
    meta->entry      = ehdr.e_entry;
    meta->phdr_file_off = 0;
    meta->phdr_off   = 0;  /* canonical mapped/external form below */
    meta->phdr_num   = ehdr.e_phnum;
    meta->phdr_entsz = ehdr.e_phentsize;
    meta->flags      = flags;
    meta->runtime_fixup_off = 0;
    meta->runtime_fixup_count = 0;
    meta->_reserved  = 0;

    /* Check if this library imports _rtld_global/_rtld_global_ro.  Direct
     * metadata must never be derived from a malformed optional section table.
     *
     * needs_runtime_reloc_scan() is a pre-link analysis, not serialized
     * runtime state.  The pre-link transaction constructs the exact compact
     * runtime-fixup table and sets DLFRZ_FLAG_RUNTIME_SCAN only when that
     * transaction commits.  If the transaction fails, the original ELF is
     * runtime-relocated and the canonical metadata representation has the
     * flag and fixup range clear. */
    int rtld_import = has_rtld_import(f, &ehdr);
    int runtime_scan = needs_runtime_reloc_scan(f, &ehdr);
    if (rtld_import < 0 || runtime_scan < 0) {
        fprintf(stderr, "dlfreeze: %s: malformed ELF section metadata\n",
                path);
        fclose(f);
        return -1;
    }
    if (rtld_import)
        meta->flags |= DLFRZ_FLAG_NEEDS_RTLD;

    /* Read program headers to get VA span */
    if (ehdr.e_phnum == 0 || ehdr.e_phnum == PN_XNUM ||
        ehdr.e_phoff > (uint64_t)st.st_size ||
        (uint64_t)ehdr.e_phnum >
            ((uint64_t)st.st_size - ehdr.e_phoff) / sizeof(Elf64_Phdr) ||
        ehdr.e_phoff > (uint64_t)LONG_MAX) {
        fclose(f); return -1;
    }
    size_t phsz = (size_t)ehdr.e_phnum * sizeof(Elf64_Phdr);
    uint8_t *phdrs = malloc(phsz);
    if (!phdrs) { fclose(f); return -1; }
    if (fseek(f, (long)ehdr.e_phoff, SEEK_SET) != 0 ||
        fread(phdrs, 1, phsz, f) != phsz) {
        free(phdrs); fclose(f); return -1;
    }

    uint64_t lo = UINT64_MAX, hi = 0, phdr_vaddr = UINT64_MAX;
    uint64_t phdr_file_end = ehdr.e_phoff + phsz;
    uint64_t max_load_align = 1;
    int phdr_translation_ambiguous = 0;
    int phdr_translation_readable = 0;
    int tls_count = 0;
    int dynamic_count = 0;
    int gnu_stack_count = 0;
    int phdr_count = 0;
    int saw_load_header = 0;
    int executable_stack = 0;
    Elf64_Phdr tls_phdr = {0};
    Elf64_Phdr dynamic_phdr = {0};
    Elf64_Phdr self_phdr = {0};
    int have_tls_phdr = 0;
    int have_dynamic_phdr = 0;
    int have_self_phdr = 0;
    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr ph;

        if (!packer_phdr_read(phdrs, phsz, (size_t)i,
                              ehdr.e_phentsize, &ph) ||
            ph.p_offset > (uint64_t)st.st_size ||
            ph.p_filesz > (uint64_t)st.st_size - ph.p_offset ||
            ph.p_memsz > UINT64_MAX - ph.p_vaddr ||
            ((ph.p_type == PT_LOAD || ph.p_type == PT_DYNAMIC ||
              ph.p_type == PT_TLS) && ph.p_filesz > ph.p_memsz)) {
            free(phdrs); fclose(f); return -1;
        }
        if (ph.p_type == PT_TLS) {
            if (++tls_count != 1 ||
                (ph.p_align > 1 &&
                 (ph.p_align & (ph.p_align - 1)) != 0)) {
                fprintf(stderr,
                        "dlfreeze: %s: malformed PT_TLS program header\n",
                        path);
                free(phdrs); fclose(f); return -1;
            }
            tls_phdr = ph;
            have_tls_phdr = 1;
        }
        if (ph.p_type == PT_DYNAMIC) {
            if (++dynamic_count != 1) {
                fprintf(stderr,
                        "dlfreeze: %s: duplicate PT_DYNAMIC headers\n",
                        path);
                free(phdrs); fclose(f); return -1;
            }
            dynamic_phdr = ph;
            have_dynamic_phdr = 1;
        }
        if (ph.p_type == PT_PHDR) {
            if (++phdr_count != 1 || saw_load_header) {
                fprintf(stderr,
                        "dlfreeze: %s: misplaced or duplicate PT_PHDR "
                        "headers\n", path);
                free(phdrs); fclose(f); return -1;
            }
            self_phdr = ph;
            have_self_phdr = 1;
        }
        if (ph.p_type == PT_GNU_STACK) {
            if (++gnu_stack_count != 1) {
                fprintf(stderr,
                        "dlfreeze: %s: duplicate PT_GNU_STACK headers\n",
                        path);
                free(phdrs); fclose(f); return -1;
            }
            executable_stack = (ph.p_flags & PF_X) != 0;
        }
        if (ph.p_type != PT_LOAD) continue;
        saw_load_header = 1;
        if (ph.p_align > 1 &&
            ((ph.p_align & (ph.p_align - 1)) != 0 ||
             (ph.p_vaddr & (ph.p_align - 1)) !=
                 (ph.p_offset & (ph.p_align - 1)))) {
            free(phdrs); fclose(f); return -1;
        }
        /* A zero-sized PT_LOAD maps no addresses and therefore cannot
         * constrain the object's load bias or contribute to its mapped
         * span.  Some linkers retain such placeholder program headers. */
        if (ph.p_memsz == 0)
            continue;
        if (ph.p_align > max_load_align)
            max_load_align = ph.p_align;
        if (ph.p_vaddr < lo) lo = ph.p_vaddr;
        uint64_t end = ph.p_vaddr + ph.p_memsz;
        if (end > hi) hi = end;
        if (ehdr.e_phoff >= ph.p_offset &&
            phdr_file_end >= ehdr.e_phoff &&
            phdr_file_end - ph.p_offset <= ph.p_filesz) {
            uint64_t candidate =
                ph.p_vaddr + (ehdr.e_phoff - ph.p_offset);

            if (phdr_vaddr != UINT64_MAX && phdr_vaddr != candidate)
                phdr_translation_ambiguous = 1;
            else
                phdr_vaddr = candidate;
            if (ph.p_flags & PF_R)
                phdr_translation_readable = 1;
        }
    }

    if (have_dynamic_phdr &&
        !dlfrz_segment_is_contained_by_load_bytes(
            phdrs, ehdr.e_phnum, ehdr.e_phentsize, &dynamic_phdr)) {
        fprintf(stderr,
                "dlfreeze: %s: PT_DYNAMIC is not contained in a "
                "file-backed PT_LOAD\n", path);
        free(phdrs);
        fclose(f);
        return -1;
    }

    if (!dlfrz_load_pages_do_not_overlap_bytes(
            phdrs, ehdr.e_phnum, ehdr.e_phentsize, PAYLOAD_ALIGN)) {
        fprintf(stderr,
                "dlfreeze: %s: overlapping PT_LOAD runtime pages are "
                "unsupported in direct mode\n", path);
        free(phdrs);
        fclose(f);
        return 1;
    }

    if (gnu_stack_count != 1 || executable_stack) {
        fprintf(stderr,
                "dlfreeze: warning: %s %s, which direct-load does not "
                "support\n", path,
                gnu_stack_count == 0
                    ? "has no PT_GNU_STACK and therefore requires legacy "
                      "executable-stack semantics"
                    : "requires an executable process stack");
        free(phdrs);
        if (fclose(f) != 0)
            return -1;
        return 1;
    }

    if (have_tls_phdr) {
        uint64_t tls_align = tls_phdr.p_align ? tls_phdr.p_align : 1;

        if ((tls_phdr.p_vaddr & (tls_align - 1)) !=
            (tls_phdr.p_offset & (tls_align - 1))) {
            free(phdrs); fclose(f); return -1;
        }
        if (tls_phdr.p_filesz != 0) {
            int template_contained = 0;

            for (int i = 0; i < ehdr.e_phnum; i++) {
                Elf64_Phdr load;
                uint64_t delta;

                if (!packer_phdr_read(phdrs, phsz, (size_t)i,
                                      ehdr.e_phentsize, &load) ||
                    load.p_type != PT_LOAD ||
                    tls_phdr.p_vaddr < load.p_vaddr ||
                    tls_phdr.p_offset < load.p_offset)
                    continue;
                delta = tls_phdr.p_vaddr - load.p_vaddr;
                if (tls_phdr.p_offset - load.p_offset != delta ||
                    delta > load.p_filesz ||
                    tls_phdr.p_filesz > load.p_filesz - delta ||
                    delta > load.p_memsz ||
                    tls_phdr.p_filesz > load.p_memsz - delta)
                    continue;
                template_contained = 1;
                break;
            }
            if (!template_contained) {
                fprintf(stderr,
                        "dlfreeze: %s: PT_TLS template is not contained "
                        "in file-backed PT_LOAD\n", path);
                free(phdrs); fclose(f); return -1;
            }
        }
    }

    if (ehdr.e_type == ET_EXEC)
        meta->base_addr = 0;
    else if (!u64_align_up_checked(base, max_load_align,
                                   &meta->base_addr)) {
        free(phdrs); fclose(f); return -1;
    }

    if (lo >= hi || phdr_translation_ambiguous) {
        fprintf(stderr, "dlfreeze: %s: ambiguous program-header mapping\n",
                path);
        free(phdrs);
        fclose(f);
        return -1;
    }
    int phdr_has_canonical_mapping =
        phdr_vaddr != UINT64_MAX && phdr_translation_readable &&
        phdr_vaddr < DLFRZ_PHDR_EXTERNAL &&
        phdr_vaddr % _Alignof(Elf64_Phdr) == 0;
    if (have_self_phdr &&
        (!phdr_has_canonical_mapping ||
         self_phdr.p_offset != ehdr.e_phoff ||
         self_phdr.p_vaddr != phdr_vaddr ||
         self_phdr.p_filesz != phsz || self_phdr.p_memsz != phsz ||
         !(self_phdr.p_flags & PF_R) ||
         (self_phdr.p_align > 1 &&
          ((self_phdr.p_align & (self_phdr.p_align - 1)) != 0 ||
           (self_phdr.p_vaddr & (self_phdr.p_align - 1)) !=
               (self_phdr.p_offset & (self_phdr.p_align - 1)))))) {
        fprintf(stderr, "dlfreeze: %s: incoherent PT_PHDR header\n", path);
        free(phdrs);
        fclose(f);
        return -1;
    }
    meta->vaddr_lo = lo;
    meta->vaddr_hi = hi;
    if (phdr_has_canonical_mapping) {
        meta->phdr_off = (uint32_t)phdr_vaddr;
        meta->phdr_file_off = 0;
    } else {
        meta->phdr_off = DLFRZ_PHDR_EXTERNAL;
        meta->phdr_file_off = ehdr.e_phoff;
    }
    free(phdrs);
    if (fclose(f) != 0)
        return -1;
    return 0;
}

/* ==== Pre-linker: resolve relocations at freeze time ================== */

/*
 * Pre-link all objects: apply relocations offline so the loader can skip
 * the relocation pass at runtime.  This is done in a child process that
 * mmaps libraries at their assigned base addresses, runs the relocation
 * engine (including IRELATIVE resolvers), and writes the patched writable
 * segments back to the frozen binary.
 */

struct prelink_obj {
    const char       *name;
    uint64_t          base;
    uint32_t          flags;
    const uint8_t    *phdr_base;
    uint16_t          phdr_num;
    uint16_t          phdr_entsz;
    const Elf64_Sym  *dynsym;
    const char       *dynstr;
    size_t            dynstr_size;
    uint32_t          dynsym_count;
    const uint32_t   *gnu_hash;
    const uint32_t   *sysv_hash;
    const uint16_t   *versym;

    const Elf64_Rela *rela;
    size_t            rela_count;
    const Elf64_Rela *jmprel;
    size_t            jmprel_count;
    const Elf64_Relr *relr;
    size_t            relr_count;

    int64_t           tls_tpoff;
    size_t            tls_modid;
    uint64_t          tls_memsz;
    uint64_t          tls_align;
};

/* ELF relocation offsets are byte addresses; a valid output field need not
 * have C's uint64_t alignment (packed data is a common example).  Keep every
 * prelink scalar access defined on strict-alignment hosts. */
static uint64_t pl_relocation_load_u64(const void *address)
{
    uint64_t value;

    memcpy(&value, address, sizeof(value));
    return value;
}

static void pl_relocation_store_u64(void *address, uint64_t value)
{
    memcpy(address, &value, sizeof(value));
}

static int pl_phdr_read(const struct prelink_obj *obj, uint16_t index,
                        Elf64_Phdr *header_out)
{
    size_t table_size;

    if (!obj || index >= obj->phdr_num ||
        obj->phdr_entsz != sizeof(*header_out))
        return 0;
    table_size = (size_t)obj->phdr_num * obj->phdr_entsz;
    return packer_phdr_read(obj->phdr_base, table_size, index,
                            obj->phdr_entsz, header_out);
}

static int pl_vaddr_pointer(const struct prelink_obj *obj, uint64_t vaddr,
                            size_t size, int file_backed,
                            uint32_t required_flags, void **pointer_out)
{
    uintptr_t pointer;

    if (!obj || !obj->phdr_base || obj->phdr_entsz != sizeof(Elf64_Phdr) ||
        vaddr > UINTPTR_MAX || obj->base > UINTPTR_MAX - vaddr)
        return 0;
    pointer = (uintptr_t)(obj->base + vaddr);
    if (size > UINTPTR_MAX - pointer)
        return 0;

    for (uint16_t i = 0; i < obj->phdr_num; i++) {
        Elf64_Phdr ph;
        uint64_t limit;
        uint64_t delta;

        if (!pl_phdr_read(obj, i, &ph) || ph.p_type != PT_LOAD ||
            (ph.p_flags & required_flags) != required_flags ||
            vaddr < ph.p_vaddr)
            continue;
        limit = file_backed ? ph.p_filesz : ph.p_memsz;
        delta = vaddr - ph.p_vaddr;
        if (delta > limit || size > limit - delta)
            continue;
        if (pointer_out)
            *pointer_out = (void *)pointer;
        return 1;
    }
    return 0;
}

static int pl_u64_add(uint64_t left, uint64_t right, uint64_t *result)
{
    if (left > UINT64_MAX - right)
        return 0;
    *result = left + right;
    return 1;
}

static int pl_u64_mul(uint64_t left, uint64_t right, uint64_t *result)
{
    if (left != 0 && right > UINT64_MAX / left)
        return 0;
    *result = left * right;
    return 1;
}

static const Elf64_Sym *pl_dynsym(const struct prelink_obj *obj,
                                  uint32_t index)
{
    if (!obj || !obj->dynsym || index >= obj->dynsym_count)
        return NULL;
    return &obj->dynsym[index];
}

static const char *pl_dynstr(const struct prelink_obj *obj, uint32_t offset)
{
    const char *value;

    if (!obj || !obj->dynstr || offset >= obj->dynstr_size)
        return NULL;
    value = obj->dynstr + offset;
    if (!memchr(value, '\0', obj->dynstr_size - offset))
        return NULL;
    return value;
}

static const char *pl_symbol_name(const struct prelink_obj *obj,
                                  const Elf64_Sym *symbol)
{
    return symbol ? pl_dynstr(obj, symbol->st_name) : NULL;
}

static int pl_file_bytes_available(const struct prelink_obj *obj,
                                   uint64_t vaddr, size_t *available_out)
{
    if (!obj || !available_out || !obj->phdr_base ||
        obj->phdr_entsz != sizeof(Elf64_Phdr))
        return 0;
    for (uint16_t i = 0; i < obj->phdr_num; i++) {
        Elf64_Phdr ph;
        uint64_t delta;
        uint64_t available;

        if (!pl_phdr_read(obj, i, &ph) || ph.p_type != PT_LOAD ||
            !(ph.p_flags & PF_R) || vaddr < ph.p_vaddr)
            continue;
        delta = vaddr - ph.p_vaddr;
        if (delta > ph.p_filesz)
            continue;
        available = ph.p_filesz - delta;
        if (available > SIZE_MAX)
            available = SIZE_MAX;
        if (!pl_vaddr_pointer(obj, vaddr, (size_t)available, 1, PF_R,
                              NULL))
            continue;
        *available_out = (size_t)available;
        return 1;
    }
    return 0;
}

static int pl_validate_sysv_hash(struct prelink_obj *obj, uint64_t address,
                                 const uint32_t **table_out,
                                 uint32_t *symbol_count_out)
{
    const uint32_t *header;
    const uint32_t *buckets;
    const uint32_t *chains;
    uint64_t words;
    uint64_t bytes;
    uint32_t nbuckets;
    uint32_t nchain;

    if ((address & (_Alignof(uint32_t) - 1)) != 0 ||
        !pl_vaddr_pointer(obj, address, 2 * sizeof(uint32_t), 1, PF_R,
                          (void **)&header))
        return 0;
    nbuckets = header[0];
    nchain = header[1];
    if (nbuckets == 0 || nchain == 0 ||
        !pl_u64_add(2, nbuckets, &words) ||
        !pl_u64_add(words, nchain, &words) ||
        !pl_u64_mul(words, sizeof(uint32_t), &bytes) || bytes > SIZE_MAX ||
        !pl_vaddr_pointer(obj, address, (size_t)bytes, 1, PF_R,
                          (void **)&header))
        return 0;
    buckets = &header[2];
    chains = &buckets[nbuckets];
    for (uint32_t i = 0; i < nbuckets; i++) {
        if (buckets[i] != STN_UNDEF && buckets[i] >= nchain)
            return 0;
    }
    for (uint32_t i = 0; i < nchain; i++) {
        if (chains[i] != STN_UNDEF && chains[i] >= nchain)
            return 0;
    }
    *table_out = header;
    *symbol_count_out = nchain;
    return 1;
}

static int pl_validate_gnu_hash(struct prelink_obj *obj, uint64_t address,
                                const uint32_t **table_out,
                                uint32_t *symbol_count_out)
{
    const uint32_t *header;
    const uint32_t *buckets;
    const uint32_t *chain;
    uint32_t nbuckets;
    uint32_t symoffset;
    uint32_t bloom_size;
    uint32_t bloom_shift;
    uint32_t max_symbol = 0;
    uint32_t count;
    uint64_t bloom_bytes;
    uint64_t bucket_bytes;
    uint64_t prefix_bytes;
    uint64_t chain_address;
    uint64_t chain_offset;
    uint64_t total_bytes;
    size_t chain_available;
    size_t chain_capacity;
    int have_symbol = 0;

    if ((address & (_Alignof(uint64_t) - 1)) != 0 ||
        !pl_vaddr_pointer(obj, address, 4 * sizeof(uint32_t), 1, PF_R,
                          (void **)&header))
        return 0;
    nbuckets = header[0];
    symoffset = header[1];
    bloom_size = header[2];
    bloom_shift = header[3];
    if (nbuckets == 0 || bloom_size == 0 || bloom_shift >= 32 ||
        !pl_u64_mul(bloom_size, sizeof(uint64_t), &bloom_bytes) ||
        !pl_u64_mul(nbuckets, sizeof(uint32_t), &bucket_bytes) ||
        !pl_u64_add(4 * sizeof(uint32_t), bloom_bytes, &prefix_bytes) ||
        !pl_u64_add(prefix_bytes, bucket_bytes, &prefix_bytes) ||
        prefix_bytes > SIZE_MAX ||
        !pl_vaddr_pointer(obj, address, (size_t)prefix_bytes, 1, PF_R,
                          (void **)&header) ||
        !pl_u64_add(address, prefix_bytes, &chain_address) ||
        !pl_file_bytes_available(obj, chain_address, &chain_available))
        return 0;

    buckets = (const uint32_t *)(
        (const uint8_t *)header + 4 * sizeof(uint32_t) + bloom_bytes);
    chain_capacity = chain_available / sizeof(uint32_t);
    for (uint32_t i = 0; i < nbuckets; i++) {
        uint32_t symbol = buckets[i];

        if (symbol == STN_UNDEF)
            continue;
        if (symbol < symoffset ||
            (uint64_t)(symbol - symoffset) >= chain_capacity)
            return 0;
        if (!have_symbol || symbol > max_symbol)
            max_symbol = symbol;
        have_symbol = 1;
    }
    if (!have_symbol) {
        count = symoffset;
    } else {
        size_t index = (size_t)(max_symbol - symoffset);

        chain = (const uint32_t *)(uintptr_t)(obj->base + chain_address);
        for (;;) {
            if (index >= chain_capacity || max_symbol == UINT32_MAX)
                return 0;
            if (chain[index] & 1) {
                count = max_symbol + 1;
                break;
            }
            index++;
            max_symbol++;
        }
    }
    if (count == 0 || count < symoffset ||
        !pl_u64_mul((uint64_t)(count - symoffset), sizeof(uint32_t),
                    &chain_offset) ||
        !pl_u64_add(prefix_bytes, chain_offset, &total_bytes) ||
        total_bytes > SIZE_MAX ||
        !pl_vaddr_pointer(obj, address, (size_t)total_bytes, 1, PF_R,
                          (void **)&header))
        return 0;
    for (uint32_t i = 0; i < nbuckets; i++) {
        if (buckets[i] != STN_UNDEF &&
            (buckets[i] < symoffset || buckets[i] >= count))
            return 0;
    }
    *table_out = header;
    *symbol_count_out = count;
    return 1;
}

static uint32_t pl_gnu_hash(const char *name)
{
    uint32_t h = 5381;
    for (const uint8_t *p = (const uint8_t *)name; *p; p++)
        h = h * 33 + *p;
    return h;
}

static uint32_t pl_sysv_hash(const char *name)
{
    uint32_t h = 0;

    for (const uint8_t *p = (const uint8_t *)name; *p; p++) {
        uint32_t high;

        h = (h << 4) + *p;
        high = h & 0xf0000000U;
        if (high)
            h ^= high >> 24;
        h &= ~high;
    }
    return h;
}

static const Elf64_Sym *pl_lookup_gnu(const struct prelink_obj *obj,
                                       const char *name, uint32_t gh)
{
    const uint32_t *ht = obj->gnu_hash;
    if (!ht) return NULL;
    uint32_t nbuckets = ht[0], symoffset = ht[1], bloom_size = ht[2], bloom_shift = ht[3];
    if (nbuckets == 0 || bloom_size == 0 || bloom_shift >= 32)
        return NULL;
    const uint64_t *bloom = (const uint64_t *)&ht[4];
    const uint32_t *buckets = (const uint32_t *)(bloom + bloom_size);
    const uint32_t *chain = &buckets[nbuckets];

    uint64_t word = bloom[(gh / 64) % bloom_size];
    uint64_t mask = (1ULL << (gh % 64)) | (1ULL << ((gh >> bloom_shift) % 64));
    if ((word & mask) != mask) return NULL;

    uint32_t idx = buckets[gh % nbuckets];
    if (idx < symoffset || idx >= obj->dynsym_count) return NULL;

    const Elf64_Sym *fallback = NULL;
    while (idx < obj->dynsym_count) {
        uint32_t hv = chain[idx - symoffset];
        if ((hv | 1) == (gh | 1)) {
            const Elf64_Sym *s = pl_dynsym(obj, idx);
            const char *symbol_name = pl_symbol_name(obj, s);

            if (!s || !symbol_name)
                return NULL;
            if (s->st_shndx != 0 && strcmp(symbol_name, name) == 0) {
                /* Prefer default version (versym without HIDDEN bit) */
                if (!obj->versym || !(obj->versym[idx] & 0x8000))
                    return s;
                if (!fallback)
                    fallback = s;
            }
        }
        if (hv & 1) break;
        idx++;
    }
    return fallback;
}

static const Elf64_Sym *pl_lookup_linear(const struct prelink_obj *obj,
                                          const char *name)
{
    const Elf64_Sym *fallback = NULL;
    for (uint32_t i = 1; i < obj->dynsym_count; i++) {
        const Elf64_Sym *s = pl_dynsym(obj, i);
        const char *symbol_name = pl_symbol_name(obj, s);

        if (!s || !symbol_name)
            return NULL;
        if (s->st_shndx == 0) continue;
        if (strcmp(symbol_name, name) == 0) {
            if (!obj->versym || !(obj->versym[i] & 0x8000))
                return s;
            if (!fallback)
                fallback = s;
        }
    }
    return fallback;
}

static const Elf64_Sym *pl_lookup_sysv(const struct prelink_obj *obj,
                                        const char *name)
{
    const uint32_t *ht = obj->sysv_hash;
    uint32_t nbuckets;
    uint32_t nchain;
    const uint32_t *buckets;
    const uint32_t *chains;
    uint32_t idx;
    const Elf64_Sym *fallback = NULL;

    if (!ht)
        return NULL;
    nbuckets = ht[0];
    nchain = ht[1];
    if (nbuckets == 0 || nchain == 0)
        return NULL;
    buckets = &ht[2];
    chains = &buckets[nbuckets];
    idx = buckets[pl_sysv_hash(name) % nbuckets];

    for (uint32_t steps = 0; idx != STN_UNDEF && steps < nchain; steps++) {
        const Elf64_Sym *sym;

        if (idx >= nchain || idx >= obj->dynsym_count)
            return NULL;
        sym = pl_dynsym(obj, idx);
        if (!sym || !pl_symbol_name(obj, sym))
            return NULL;
        if (sym->st_shndx != SHN_UNDEF &&
            ELF64_ST_BIND(sym->st_info) != STB_LOCAL &&
            strcmp(pl_symbol_name(obj, sym), name) == 0) {
            if (!obj->versym || !(obj->versym[idx] & 0x8000))
                return sym;
            if (!fallback)
                fallback = sym;
        }
        idx = chains[idx];
    }
    return fallback;
}

/* ---- Prelinker symbol resolution cache -------------------------------- */
#define PL_CACHE_SIZE 4096  /* must be power of 2 */
static struct {
    const char *name;
    uint32_t    hash;
    uint64_t    value;
    uint8_t     used;
} pl_sym_cache[PL_CACHE_SIZE];

static void pl_cache_init(void)
{
    memset(pl_sym_cache, 0, sizeof(pl_sym_cache));
}

static uint64_t pl_resolve_sym(struct prelink_obj *objs, int nobj,
                                const char *name)
{
    uint32_t gh = pl_gnu_hash(name);

    /* Check cache */
    uint32_t ci = gh & (PL_CACHE_SIZE - 1);
    for (uint32_t n = 0; n < PL_CACHE_SIZE; n++) {
        if (!pl_sym_cache[ci].used) break;
        if (pl_sym_cache[ci].hash == gh &&
            strcmp(pl_sym_cache[ci].name, name) == 0)
            return pl_sym_cache[ci].value;
        ci = (ci + 1) & (PL_CACHE_SIZE - 1);
    }

    /* Cache miss — do full lookup */
    uint64_t result = 0;
    for (int i = 0; i < nobj; i++) {
        const Elf64_Sym *sym = objs[i].gnu_hash
            ? pl_lookup_gnu(&objs[i], name, gh)
            : (objs[i].sysv_hash
                ? pl_lookup_sysv(&objs[i], name)
                : pl_lookup_linear(&objs[i], name));
        if (sym) {
            if (ELF64_ST_TYPE(sym->st_info) == STT_GNU_IFUNC) {
                result = 0;
            } else {
                result = objs[i].base + sym->st_value;
            }
            break;
        }
    }

    /* Store in cache */
    ci = gh & (PL_CACHE_SIZE - 1);
    for (uint32_t n = 0; n < PL_CACHE_SIZE; n++) {
        if (!pl_sym_cache[ci].used) {
            pl_sym_cache[ci].name  = name;
            pl_sym_cache[ci].hash  = gh;
            pl_sym_cache[ci].value = result;
            pl_sym_cache[ci].used  = 1;
            break;
        }
        ci = (ci + 1) & (PL_CACHE_SIZE - 1);
    }

    return result;
}

static int pl_parse_dynamic(struct prelink_obj *obj, uint64_t base,
                            const uint8_t *phdr_base,
                            uint16_t phdr_num, uint16_t phdr_entsz)
{
    Elf64_Phdr dyn_ph = {0};
    const Elf64_Dyn *dyn;
    size_t dyn_count;
    void *pointer;
    uint64_t symtab = 0, strtab = 0, strsz = 0, syment = 0;
    uint64_t v_rela = 0, rela_sz = 0, rela_ent = 0;
    uint64_t jmprel = 0, pltrelsz = 0, pltrel = 0;
    uint64_t v_relr = 0, relr_sz = 0, relr_ent = 0;
    uint64_t gnu_hash_addr = 0, sysv_hash_addr = 0;
    uint64_t versym_addr = 0;
    uint64_t dynamic_flags = 0, dynamic_flags_1 = 0;
    int have_symtab = 0, have_strtab = 0, have_strsz = 0, have_syment = 0;
    int have_rela = 0, have_relasz = 0, have_relaent = 0;
    int have_jmprel = 0, have_pltrelsz = 0, have_pltrel = 0;
    int have_relr = 0, have_relrsz = 0, have_relrent = 0;
    int have_gnu_hash = 0, have_sysv_hash = 0, have_versym = 0;
    int have_dynamic_flags = 0, have_dynamic_flags_1 = 0;
    int have_dyn_ph = 0;
    int saw_null = 0;

    obj->phdr_base = phdr_base;
    obj->phdr_num = phdr_num;
    obj->phdr_entsz = phdr_entsz;
    if (phdr_entsz != sizeof(Elf64_Phdr) || !phdr_base)
        return -1;
    for (int i = 0; i < phdr_num; i++) {
        Elf64_Phdr ph;

        if (!pl_phdr_read(obj, (uint16_t)i, &ph))
            return -1;
        if (ph.p_type == PT_DYNAMIC) {
            if (have_dyn_ph)
                return -1;
            dyn_ph = ph;
            have_dyn_ph = 1;
        }
    }
    if (!have_dyn_ph)
        return 0;
    if (dyn_ph.p_filesz == 0 || dyn_ph.p_filesz > dyn_ph.p_memsz ||
        dyn_ph.p_filesz > SIZE_MAX ||
        (dyn_ph.p_vaddr & (_Alignof(Elf64_Dyn) - 1)) != 0 ||
        dyn_ph.p_filesz % sizeof(Elf64_Dyn) != 0 ||
        !pl_vaddr_pointer(obj, dyn_ph.p_vaddr,
                          (size_t)dyn_ph.p_filesz, 1, PF_R, &pointer))
        return -1;
    dyn = (const Elf64_Dyn *)pointer;
    dyn_count = (size_t)dyn_ph.p_filesz / sizeof(Elf64_Dyn);

#define PL_SET_DYNAMIC(seen, storage, value) do { \
        uint64_t dynamic_value = (uint64_t)(value); \
        if ((seen) && (storage) != dynamic_value) return -1; \
        (seen) = 1; \
        (storage) = dynamic_value; \
    } while (0)

    for (size_t i = 0; i < dyn_count; i++) {
        if (dyn[i].d_tag == DT_NULL) {
            saw_null = 1;
            break;
        }
        if (dlfrz_dynamic_tag_requires_unsupported_semantics(
                dyn[i].d_tag, dyn[i].d_un.d_val))
            return -1;
        switch (dyn[i].d_tag) {
        case DT_SYMTAB:
            PL_SET_DYNAMIC(have_symtab, symtab, dyn[i].d_un.d_ptr);
            break;
        case DT_STRTAB:
            PL_SET_DYNAMIC(have_strtab, strtab, dyn[i].d_un.d_ptr);
            break;
        case DT_STRSZ:
            PL_SET_DYNAMIC(have_strsz, strsz, dyn[i].d_un.d_val);
            break;
        case DT_SYMENT:
            PL_SET_DYNAMIC(have_syment, syment, dyn[i].d_un.d_val);
            break;
        case DT_RELA:
            PL_SET_DYNAMIC(have_rela, v_rela, dyn[i].d_un.d_ptr);
            break;
        case DT_RELASZ:
            PL_SET_DYNAMIC(have_relasz, rela_sz, dyn[i].d_un.d_val);
            break;
        case DT_RELAENT:
            PL_SET_DYNAMIC(have_relaent, rela_ent, dyn[i].d_un.d_val);
            break;
        case DT_JMPREL:
            PL_SET_DYNAMIC(have_jmprel, jmprel, dyn[i].d_un.d_ptr);
            break;
        case DT_PLTRELSZ:
            PL_SET_DYNAMIC(have_pltrelsz, pltrelsz, dyn[i].d_un.d_val);
            break;
        case DT_PLTREL:
            PL_SET_DYNAMIC(have_pltrel, pltrel, dyn[i].d_un.d_val);
            break;
        case DT_GNU_HASH:
            PL_SET_DYNAMIC(have_gnu_hash, gnu_hash_addr,
                           dyn[i].d_un.d_ptr);
            break;
        case DT_HASH:
            PL_SET_DYNAMIC(have_sysv_hash, sysv_hash_addr,
                           dyn[i].d_un.d_ptr);
            break;
        case DT_VERSYM:
            PL_SET_DYNAMIC(have_versym, versym_addr, dyn[i].d_un.d_ptr);
            break;
        case DT_FLAGS:
            PL_SET_DYNAMIC(have_dynamic_flags, dynamic_flags,
                           dyn[i].d_un.d_val);
            break;
        case DT_FLAGS_1:
            PL_SET_DYNAMIC(have_dynamic_flags_1, dynamic_flags_1,
                           dyn[i].d_un.d_val);
            break;
        case DT_TEXTREL:
            return -1;
        case 36: /* DT_RELR */
            PL_SET_DYNAMIC(have_relr, v_relr, dyn[i].d_un.d_ptr);
            break;
        case 35: /* DT_RELRSZ */
            PL_SET_DYNAMIC(have_relrsz, relr_sz, dyn[i].d_un.d_val);
            break;
        case 37: /* DT_RELRENT */
            PL_SET_DYNAMIC(have_relrent, relr_ent, dyn[i].d_un.d_val);
            break;
        case DT_DEPAUDIT:
        case DT_AUDIT:
        case DT_AUXILIARY:
        case DT_FILTER:
            /* Audit and filter objects alter rtld callbacks and symbol
             * lookup.  Direct mode does not implement those contracts. */
            return -1;
        case DT_REL:
        case DT_RELSZ:
        case DT_RELENT:
            if (dyn[i].d_un.d_val != 0)
                return -1;
            break;
        }
    }
#undef PL_SET_DYNAMIC

    if (!saw_null ||
        have_strtab != have_symtab || have_strtab != have_strsz ||
        have_symtab != have_syment ||
        (have_symtab && (symtab == 0 || strtab == 0 || strsz == 0 ||
                         syment != sizeof(Elf64_Sym))) ||
        ((have_rela || have_relasz || have_relaent) &&
         (!have_rela || !have_relasz || !have_relaent || v_rela == 0 ||
          rela_ent != sizeof(Elf64_Rela) ||
          rela_sz % sizeof(Elf64_Rela) != 0)) ||
        ((have_jmprel || have_pltrelsz || have_pltrel) &&
         (!have_jmprel || !have_pltrelsz || !have_pltrel || jmprel == 0 ||
          pltrel != DT_RELA || pltrelsz % sizeof(Elf64_Rela) != 0)) ||
        ((have_relr || have_relrsz || have_relrent) &&
         (!have_relr || !have_relrsz || !have_relrent || v_relr == 0 ||
          relr_ent != sizeof(Elf64_Relr) ||
          relr_sz % sizeof(Elf64_Relr) != 0)) ||
        (have_gnu_hash && gnu_hash_addr == 0) ||
        (have_sysv_hash && sysv_hash_addr == 0) ||
        (have_versym && versym_addr == 0))
        return -1;

    {
        const uint64_t flags_allowed =
            DF_ORIGIN | DF_SYMBOLIC | DF_BIND_NOW | DF_STATIC_TLS;
        const uint64_t flags_1_allowed =
            DF_1_NOW | DF_1_NODELETE | DF_1_ORIGIN | DF_1_NODEFLIB |
            DF_1_NODUMP | DF_1_NODIRECT | DF_1_PIE;

        if ((dynamic_flags & ~flags_allowed) != 0 ||
            (dynamic_flags_1 & ~flags_1_allowed) != 0 ||
            ((dynamic_flags_1 & DF_1_PIE) != 0 &&
             (obj->flags & DLFRZ_FLAG_MAIN_EXE) == 0))
            return -1;
    }

    if (have_strtab) {
        if (strsz > SIZE_MAX ||
            !pl_vaddr_pointer(obj, strtab, (size_t)strsz, 1, PF_R,
                              &pointer))
            return -1;
        obj->dynstr = (const char *)pointer;
        obj->dynstr_size = (size_t)strsz;
    }

    if (have_rela) {
        if (rela_sz > SIZE_MAX ||
            (v_rela & (_Alignof(Elf64_Rela) - 1)) != 0 ||
            !pl_vaddr_pointer(obj, v_rela, (size_t)rela_sz, 1, PF_R,
                              &pointer))
            return -1;
        obj->rela = (const Elf64_Rela *)pointer;
        obj->rela_count = (size_t)rela_sz / sizeof(Elf64_Rela);
    }
    if (have_jmprel) {
        if (pltrelsz > SIZE_MAX ||
            (jmprel & (_Alignof(Elf64_Rela) - 1)) != 0 ||
            !pl_vaddr_pointer(obj, jmprel, (size_t)pltrelsz, 1, PF_R,
                              &pointer))
            return -1;
        obj->jmprel = (const Elf64_Rela *)pointer;
        obj->jmprel_count = (size_t)pltrelsz / sizeof(Elf64_Rela);
    }

    /* Relocation references provide a proven lower bound even when GNU hash
     * omits undefined imports.  The final table range check below turns this
     * lower bound into a safe dynsym view. */
    {
        const Elf64_Rela *tables[] = { obj->rela, obj->jmprel };
        size_t counts[] = { obj->rela_count, obj->jmprel_count };

        for (size_t table = 0; table < 2; table++) {
            for (size_t i = 0; i < counts[table]; i++) {
                uint32_t index = ELF64_R_SYM(tables[table][i].r_info);

                if (index == UINT32_MAX)
                    return -1;
                if (index + 1 > obj->dynsym_count)
                    obj->dynsym_count = index + 1;
            }
        }
    }

    {
        uint32_t sysv_count = 0;
        uint32_t gnu_count = 0;

        if (have_sysv_hash) {
            if (!pl_validate_sysv_hash(obj, sysv_hash_addr,
                                       &obj->sysv_hash, &sysv_count) ||
                sysv_count < obj->dynsym_count)
                return -1;
            obj->dynsym_count = sysv_count;
        }
        if (have_gnu_hash) {
            if (!pl_validate_gnu_hash(obj, gnu_hash_addr,
                                      &obj->gnu_hash, &gnu_count) ||
                (sysv_count != 0 && gnu_count > sysv_count))
                return -1;
            if (gnu_count > obj->dynsym_count)
                obj->dynsym_count = gnu_count;
        }
    }

    if (have_symtab) {
        uint64_t span = 0;
        size_t bytes;

        if ((symtab & (_Alignof(Elf64_Sym) - 1)) != 0)
            return -1;
        if (strtab > symtab &&
            (strtab - symtab) % sizeof(Elf64_Sym) == 0) {
            span = (strtab - symtab) / sizeof(Elf64_Sym);
            if (span == 0 || span > UINT32_MAX)
                return -1;
            if (!have_gnu_hash && !have_sysv_hash)
                obj->dynsym_count = (uint32_t)span;
            else if (obj->dynsym_count > span)
                return -1;
        } else if (!have_gnu_hash && !have_sysv_hash) {
            return -1;
        }
        if (obj->dynsym_count == 0)
            return -1;
        bytes = (size_t)obj->dynsym_count * sizeof(Elf64_Sym);
        if (!pl_vaddr_pointer(obj, symtab, bytes, 1, PF_R, &pointer))
            return -1;
        obj->dynsym = (const Elf64_Sym *)pointer;
        for (uint32_t i = 0; i < obj->dynsym_count; i++) {
            const Elf64_Sym *symbol = pl_dynsym(obj, i);

            if (!symbol || !pl_symbol_name(obj, symbol))
                return -1;
        }
    } else if (have_gnu_hash || have_sysv_hash || have_versym ||
               obj->dynsym_count != 0) {
        return -1;
    }

    if (have_versym) {
        size_t bytes;

        if (!obj->dynsym ||
            (versym_addr & (_Alignof(uint16_t) - 1)) != 0)
            return -1;
        bytes = (size_t)obj->dynsym_count * sizeof(uint16_t);
        if (!pl_vaddr_pointer(obj, versym_addr, bytes, 1, PF_R, &pointer))
            return -1;
        obj->versym = (const uint16_t *)pointer;
    }

    if (have_relr) {
        if (relr_sz > SIZE_MAX ||
            (v_relr & (_Alignof(Elf64_Relr) - 1)) != 0 ||
            !pl_vaddr_pointer(obj, v_relr, (size_t)relr_sz, 1, PF_R,
                              &pointer))
            return -1;
        obj->relr = (const Elf64_Relr *)pointer;
        obj->relr_count = (size_t)relr_sz / sizeof(Elf64_Relr);
    }

    for (int i = 0; i < phdr_num; i++) {
        Elf64_Phdr ph;

        if (!pl_phdr_read(obj, (uint16_t)i, &ph))
            return -1;
        if (ph.p_type == PT_TLS) {
            if ((ph.p_align > 1 &&
                 (ph.p_align & (ph.p_align - 1)) != 0) ||
                ph.p_filesz > ph.p_memsz)
                return -1;
            obj->tls_memsz  = ph.p_memsz;
            obj->tls_align  = ph.p_align ? ph.p_align : 1;
            break;
        }
    }
    (void)base;
    return 0;
}

static int pl_apply_relr(struct prelink_obj *obj)
{
    uint64_t base = obj->base;
    const Elf64_Relr *relr = obj->relr;
    size_t count = obj->relr_count;
    uint64_t where_offset = 0;
    int have_where = 0;

    if (count != 0 && !relr)
        return -1;

    for (size_t i = 0; i < count; i++) {
        Elf64_Relr entry = relr[i];
        if ((entry & 1) == 0) {
            void *where;

            if ((entry & (sizeof(uint64_t) - 1)) != 0 ||
                /* The transaction serializes only PT_LOAD p_filesz bytes.
                 * A RELR destination in the zero-fill suffix would be reset
                 * when the frozen object is mapped again.  RELR has no
                 * compact runtime-fixup encoding, so decline prelinking and
                 * let the ordinary runtime RELR pass handle this object. */
                !pl_vaddr_pointer(obj, entry, sizeof(uint64_t), 1, PF_W,
                                  &where) ||
                entry > UINT64_MAX - sizeof(uint64_t))
                return -1;
            pl_relocation_store_u64(
                where, pl_relocation_load_u64(where) + base);
            where_offset = entry + sizeof(uint64_t);
            have_where = 1;
        } else {
            uint64_t bitmap = entry >> 1;

            if (!have_where)
                return -1;
            for (unsigned int j = 0; bitmap; j++, bitmap >>= 1) {
                uint64_t offset;
                void *where;

                if (!(bitmap & 1))
                    continue;
                if (where_offset > UINT64_MAX -
                                   (uint64_t)j * sizeof(uint64_t))
                    return -1;
                offset = where_offset + (uint64_t)j * sizeof(uint64_t);
                if (!pl_vaddr_pointer(obj, offset, sizeof(uint64_t), 1, PF_W,
                                      &where))
                    return -1;
                pl_relocation_store_u64(
                    where, pl_relocation_load_u64(where) + base);
            }
            if (where_offset > UINT64_MAX - 63 * sizeof(uint64_t))
                return -1;
            where_offset += 63 * sizeof(uint64_t);
        }
    }
    return 0;
}

static int pl_signed_offset_pointer(const struct prelink_obj *obj,
                                    int64_t offset, size_t size,
                                    uint32_t required_flags,
                                    void **pointer_out)
{
    uintptr_t address;

    if (!obj || obj->base > UINTPTR_MAX)
        return 0;
    if (offset < 0) {
        uint64_t magnitude = (uint64_t)(-(offset + 1)) + 1;

        if (magnitude > obj->base)
            return 0;
        address = (uintptr_t)(obj->base - magnitude);
    } else {
        if ((uint64_t)offset > UINTPTR_MAX - obj->base)
            return 0;
        address = (uintptr_t)(obj->base + (uint64_t)offset);
    }
    if (size > UINTPTR_MAX - address)
        return 0;

    for (uint16_t i = 0; i < obj->phdr_num; i++) {
        Elf64_Phdr ph;
        uintptr_t start;
        size_t within;

        if (!pl_phdr_read(obj, i, &ph) || ph.p_type != PT_LOAD ||
            (ph.p_flags & required_flags) != required_flags ||
            ph.p_vaddr > UINTPTR_MAX - obj->base ||
            ph.p_memsz > SIZE_MAX)
            continue;
        start = (uintptr_t)(obj->base + ph.p_vaddr);
        if (address < start)
            continue;
        within = address - start;
        if (within <= ph.p_memsz && size <= ph.p_memsz - within) {
            if (pointer_out)
                *pointer_out = (void *)address;
            return 1;
        }
    }
    return 0;
}

static int pl_validate_rela_record(struct prelink_obj *obj,
                                   const Elf64_Rela *rel, void **slot_out)
{
    uint32_t type = ELF64_R_TYPE(rel->r_info);
    uint32_t symbol_index = ELF64_R_SYM(rel->r_info);
    const Elf64_Sym *symbol = NULL;
    size_t width = sizeof(uint64_t);
    void *slot = NULL;

    if (symbol_index != 0) {
        symbol = pl_dynsym(obj, symbol_index);
        if (!symbol || !pl_symbol_name(obj, symbol))
            return 0;
    }
    switch (type) {
    case 0: /* R_X86_64_NONE / R_AARCH64_NONE */
        width = 0;
        break;
    case ARCH_RELOC_RELATIVE:
    case ARCH_RELOC_IRELATIVE:
        if (symbol_index != 0)
            return 0;
        break;
    case ARCH_RELOC_COPY:
        if (!symbol || symbol->st_size > SIZE_MAX)
            return 0;
        width = (size_t)symbol->st_size;
        break;
    case ARCH_RELOC_TLSDESC:
        width = 2 * sizeof(uint64_t);
        break;
    case ARCH_RELOC_GLOB_DAT:
    case ARCH_RELOC_JUMP_SLOT:
    case ARCH_RELOC_ABS:
    case ARCH_RELOC_TPOFF:
    case ARCH_RELOC_DTPMOD:
    case ARCH_RELOC_DTPOFF:
        break;
    default:
        return 0;
    }

    if (width != 0 &&
        !pl_vaddr_pointer(obj, rel->r_offset, width, 0, PF_W, &slot))
        return 0;
    if (type == ARCH_RELOC_IRELATIVE &&
        !pl_signed_offset_pointer(obj, rel->r_addend, 1, PF_X, NULL))
        return 0;
    if (slot_out)
        *slot_out = slot;
    return 1;
}

static int pl_apply_rela(struct prelink_obj *obj,
                          const Elf64_Rela *rtab, size_t count,
                          struct prelink_obj *all, int nobj, int pass)
{
    uint64_t base = obj->base;
    for (size_t i = 0; i < count; i++) {
        const Elf64_Rela *r = &rtab[i];
        void *slot = NULL;
        uint32_t type  = ELF64_R_TYPE(r->r_info);
        uint32_t sidx  = ELF64_R_SYM(r->r_info);

        if (!pl_validate_rela_record(obj, r, &slot))
            return -1;

        if (type == ARCH_RELOC_IRELATIVE) {
            /* Skip IRELATIVE at pre-link time — resolver needs a seeded
             * _rtld_global_ro GOT entry.  Loader handles these at runtime. */
            continue;
        }
        if (type == ARCH_RELOC_COPY) {
            /* COPY targets live in .bss (memsz > filesz) which is not
             * written back to the frozen file.  Defer to the loader. */
            continue;
        }
        if (pass != 0) continue;

        switch (type) {
        case 0: /* R_X86_64_NONE / R_AARCH64_NONE */
            break;

        case ARCH_RELOC_RELATIVE:
            pl_relocation_store_u64(slot, base + r->r_addend);
            break;

        case ARCH_RELOC_GLOB_DAT:
        case ARCH_RELOC_JUMP_SLOT: {
            /* ELF ABI: S (no addend).  glibc ≥2.39 stores the PLT stub
             * address in r_addend for JUMP_SLOT; applying it would point
             * the GOT at the wrong function. */
            const Elf64_Sym *symbol;
            const char *name;

            uint64_t addr = 0;

            if (sidx != 0) {
                symbol = pl_dynsym(obj, sidx);
                name = pl_symbol_name(obj, symbol);
                if (!name)
                    return -1;
                addr = pl_resolve_sym(all, nobj, name);
            }
            pl_relocation_store_u64(slot, addr);
            break;
        }
        case ARCH_RELOC_ABS: {
            const Elf64_Sym *symbol;
            const char *name;

            uint64_t addr = 0;

            if (sidx != 0) {
                symbol = pl_dynsym(obj, sidx);
                name = pl_symbol_name(obj, symbol);
                if (!name)
                    return -1;
                addr = pl_resolve_sym(all, nobj, name);
            }
            pl_relocation_store_u64(slot, addr + r->r_addend);
            break;
        }

        case ARCH_RELOC_TPOFF:
        case ARCH_RELOC_DTPMOD:
        case ARCH_RELOC_DTPOFF:
            /* TLS relocations depend on the final runtime TLS layout.
             * Keep the on-disk value untouched and let the loader resolve
             * them after it has built the live TLS image. */
            break;

        case ARCH_RELOC_TLSDESC:
            /* TLSDESC descriptors embed resolver function pointers.
             * These must be synthesized by the runtime loader, where the
             * loader stub addresses are known, so keep the file contents
             * untouched and record a runtime fixup instead. */
            break;

        default:
            fprintf(stderr,
                    "dlfreeze: unsupported relocation type %u during pre-link\n",
                    type);
            return -1;
        }
    }
    return 0;
}

/* Per-object runtime fixup table entries encode the relocation table in the
 * top bit and the relocation index in the remaining bits. */
#define PRELINK_FIXUP_JMPREL 0x80000000u

static int prelink_obj_collect_runtime_fixups(const struct prelink_obj *obj,
                                              uint32_t **fixups,
                                              size_t *fixup_count,
                                              size_t *fixup_cap,
                                              uint32_t *out_off,
                                              uint32_t *out_count)
{
    const Elf64_Rela *tabs[] = { obj->rela, obj->jmprel };
    size_t counts[] = { obj->rela_count, obj->jmprel_count };

    if (*fixup_count > UINT32_MAX)
        return -1;

    *out_off = (uint32_t)*fixup_count;
    *out_count = 0;

    for (int t = 0; t < 2; t++) {
        for (size_t i = 0; i < counts[t]; i++) {
            const Elf64_Rela *rel = &tabs[t][i];
            uint32_t type = ELF64_R_TYPE(rel->r_info);
            int needs_fixup = 0;

            if (type == ARCH_RELOC_RELATIVE) {
                /* A zero-fill destination is not persisted by the prelink
                 * writeback.  RELA has an index in the compact table, so
                 * replay precisely this relocation at runtime. */
                needs_fixup = !pl_vaddr_pointer(
                    obj, rel->r_offset, sizeof(uint64_t), 1, PF_W, NULL);
            } else if (type == ARCH_RELOC_IRELATIVE ||
                type == ARCH_RELOC_COPY ||
                type == ARCH_RELOC_ABS ||
                type == ARCH_RELOC_TPOFF ||
                type == ARCH_RELOC_DTPMOD ||
                type == ARCH_RELOC_DTPOFF) {
                if (type == ARCH_RELOC_ABS) {
                    uint32_t sidx = ELF64_R_SYM(rel->r_info);

                    /* Runtime lookup is authoritative for every imported
                     * ABS relocation (weak references included).  STN_UNDEF
                     * is retained too so S+A is explicitly canonicalized. */
                    if (sidx == 0 || sidx < obj->dynsym_count)
                        needs_fixup = 1;
                } else {
                    needs_fixup = 1;
                }
            } else if (type == ARCH_RELOC_TLSDESC) {
                needs_fixup = 1;
            } else if (type == ARCH_RELOC_GLOB_DAT ||
                       type == ARCH_RELOC_JUMP_SLOT) {
                uint32_t sidx = ELF64_R_SYM(rel->r_info);

                /* Object-table discovery is depth-first, while ELF symbol
                 * lookup is breadth-first over DT_NEEDED.  Keep every
                 * symbolic GOT/PLT relocation as a compact runtime fixup so
                 * the audited loader scope, visibility, and version rules
                 * determine the final binding. */
                if (sidx == 0 || sidx < obj->dynsym_count)
                    needs_fixup = 1;
            }

            if (!needs_fixup)
                continue;

            if (*fixup_count >= UINT32_MAX)
                return -1;

            if (*fixup_count == *fixup_cap) {
                size_t newcap = *fixup_cap ? *fixup_cap * 2 : 256;
                uint32_t *grown = realloc(*fixups, newcap * sizeof(**fixups));
                if (!grown)
                    return -1;
                *fixups = grown;
                *fixup_cap = newcap;
            }

            (*fixups)[*fixup_count] = (t ? PRELINK_FIXUP_JMPREL : 0)
                                    | (uint32_t)i;
            (*fixup_count)++;
            (*out_count)++;
        }
    }

    return 0;
}

static int prelink_embedded_header_valid(
    const Elf64_Ehdr *ehdr, const struct dlfrz_entry *entry,
    const struct dlfrz_lib_meta *meta, size_t output_size,
    size_t *phdr_size_out)
{
    size_t phdr_size;

    if (!ehdr || !entry || !meta || !phdr_size_out ||
        entry->data_offset > output_size ||
        entry->data_size > output_size - entry->data_offset ||
        entry->data_size < sizeof(*ehdr) ||
        memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
        (ehdr->e_ident[EI_OSABI] != ELFOSABI_NONE &&
         ehdr->e_ident[EI_OSABI] != ELFOSABI_LINUX) ||
        ehdr->e_ident[EI_ABIVERSION] != 0 ||
        ehdr->e_version != EV_CURRENT || ehdr->e_flags != 0 ||
        (ehdr->e_type != ET_DYN && ehdr->e_type != ET_EXEC) ||
        ehdr->e_ehsize != sizeof(*ehdr) ||
        ehdr->e_phnum == 0 || ehdr->e_phnum == PN_XNUM ||
        ehdr->e_phnum != meta->phdr_num ||
        ehdr->e_phentsize != sizeof(Elf64_Phdr) ||
        ehdr->e_phentsize != meta->phdr_entsz)
        return 0;
#if defined(__x86_64__)
    if (ehdr->e_machine != EM_X86_64)
        return 0;
#elif defined(__aarch64__)
    if (ehdr->e_machine != EM_AARCH64)
        return 0;
#else
    return 0;
#endif
    for (size_t i = EI_PAD; i < EI_NIDENT; i++)
        if (ehdr->e_ident[i] != 0)
            return 0;
    phdr_size = (size_t)ehdr->e_phnum * sizeof(Elf64_Phdr);
    if (ehdr->e_phoff > entry->data_size ||
        phdr_size > entry->data_size - ehdr->e_phoff)
        return 0;
    *phdr_size_out = phdr_size;
    return 1;
}

static int prelink_mapping_span(const struct dlfrz_lib_meta *meta,
                                size_t *span_out, void **requested_out)
{
    const uint64_t guards = 4 * PAYLOAD_ALIGN;
    uint64_t lo;
    uint64_t hi;
    uint64_t span;
    uint64_t address;

    if (!meta || !span_out || !requested_out ||
        meta->vaddr_lo >= meta->vaddr_hi ||
        !u64_align_up_checked(meta->vaddr_hi, PAYLOAD_ALIGN, &hi))
        return 0;
    lo = meta->vaddr_lo & ~(uint64_t)(PAYLOAD_ALIGN - 1);
    if (hi < lo || hi - lo > UINT64_MAX - guards)
        return 0;
    span = hi - lo + guards;
    if (span == 0 || span > SIZE_MAX ||
        meta->base_addr > UINT64_MAX - lo)
        return 0;
    address = meta->base_addr + lo;
    if (address > UINTPTR_MAX || span > UINTPTR_MAX - address)
        return 0;
    *span_out = (size_t)span;
    *requested_out = (void *)(uintptr_t)address;
    return 1;
}

static int prelink_program_header_valid(const Elf64_Phdr *phdr,
                                        const struct dlfrz_entry *entry)
{
    if (!phdr || !entry ||
        phdr->p_offset > entry->data_size ||
        phdr->p_filesz > entry->data_size - phdr->p_offset ||
        phdr->p_vaddr > UINT64_MAX - phdr->p_memsz ||
        ((phdr->p_type == PT_LOAD || phdr->p_type == PT_DYNAMIC ||
          phdr->p_type == PT_TLS) && phdr->p_filesz > phdr->p_memsz))
        return 0;
    return 1;
}

static int prelink_load_header_valid(const Elf64_Phdr *phdr,
                                     const struct dlfrz_entry *entry,
                                     const struct dlfrz_lib_meta *meta)
{
    if (!prelink_program_header_valid(phdr, entry) || !meta ||
        phdr->p_type != PT_LOAD || phdr->p_filesz > SIZE_MAX ||
        phdr->p_memsz > SIZE_MAX ||
        meta->base_addr > UINTPTR_MAX ||
        phdr->p_vaddr > UINTPTR_MAX - meta->base_addr)
        return 0;
    if (phdr->p_memsz == 0)
        return phdr->p_filesz == 0;
    return phdr->p_vaddr >= meta->vaddr_lo &&
           phdr->p_vaddr <= meta->vaddr_hi &&
           phdr->p_memsz <= meta->vaddr_hi - phdr->p_vaddr;
}

static int prelink_objects(const char *output_path,
                           const struct dlfrz_entry *entries,
                           struct dlfrz_lib_meta *metas,
                           const int *startup_aliases,
                           uint64_t meta_off,
                           int nobj)
{
    char transaction_path[PATH_MAX];

    if (!entries || !metas || !startup_aliases || nobj <= 0) {
        errno = EINVAL;
        return -1;
    }

    /* Relocations and metadata form one commit.  Work on a same-directory
     * copy so a child crash, ENOSPC, or short write cannot leave a partially
     * relocated artifact that the runtime later treats as clean input. */
    if (make_transaction_copy(output_path, "prelink", transaction_path) < 0) {
        perror("pre-link transaction copy");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        unlink(transaction_path);
        return -1;
    }

    if (pid > 0) {
        int status;

        while (waitpid(pid, &status, 0) < 0) {
            if (errno != EINTR) {
                perror("waitpid");
                unlink(transaction_path);
                return -1;
            }
        }
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            if (rename(transaction_path, output_path) == 0)
                return 0;
            perror("pre-link transaction commit");
            unlink(transaction_path);
            return -1;
        }

        fprintf(stderr, "dlfreeze: pre-linker %s\n",
                WIFSIGNALED(status) ? "crashed" : "failed");
        unlink(transaction_path);
        return -1;
    }

    /* ==== Child process ==== */

    FILE *outf = fopen(transaction_path, "r+b");
    struct stat output_st;
    size_t output_size;

    if (!outf || fstat(fileno(outf), &output_st) < 0 ||
        !S_ISREG(output_st.st_mode) || output_st.st_size < 0 ||
        (uintmax_t)output_st.st_size > SIZE_MAX)
        _exit(1);
    output_size = (size_t)output_st.st_size;

    pl_cache_init();

    struct prelink_obj *objs = calloc(nobj, sizeof(*objs));
    uint32_t *runtime_fixups = NULL;
    size_t runtime_fixup_count = 0;
    size_t runtime_fixup_cap = 0;
    if (!objs) _exit(1);

    /* 1. Map all objects at assigned base addresses and load segments */
    for (int i = 0; i < nobj; i++) {
        const struct dlfrz_lib_meta *m = &metas[i];
        uint64_t base = m->base_addr;

            /* Skip ld.so — the loader never maps it at runtime */
            if (m->flags & DLFRZ_FLAG_INTERP) continue;
            /* Skip dlopen'd objects — loaded lazily at runtime */
            if (m->flags & DLFRZ_FLAG_DLOPEN) continue;
            /* Skip embedded data files — not ELFs */
            if (m->flags & DLFRZ_FLAG_DATA) continue;
            /* Exact startup aliases share the first startup map. */
            if (startup_aliases[i] >= 0)
                continue;

        size_t span;
        void *requested;
        void *mapped;

        if (!prelink_mapping_span(m, &span, &requested))
            _exit(1);
        mapped = mmap(requested, span,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                            -1, 0);
        if (mapped == MAP_FAILED) _exit(1);
        if (mapped != requested) {
            munmap(mapped, span);
            _exit(1);
        }

        /* Read program headers */
        size_t phsz = 0;
        uint8_t *phdr_buf;
        Elf64_Ehdr embedded_ehdr;
        uint64_t input_off;
        if (packer_stream_seek(outf, entries[i].data_offset) < 0 ||
            fread(&embedded_ehdr, 1, sizeof(embedded_ehdr), outf) !=
            sizeof(embedded_ehdr))
            _exit(1);
        if (!prelink_embedded_header_valid(
                &embedded_ehdr, &entries[i], m, output_size, &phsz))
            _exit(1);
        phdr_buf = malloc(phsz);
        if (!phdr_buf)
            _exit(1);
        if (!u64_add_checked(entries[i].data_offset, embedded_ehdr.e_phoff,
                             &input_off) ||
            packer_stream_seek(outf, input_off) < 0 ||
            fread(phdr_buf, 1, phsz, outf) != phsz)
            _exit(1);

        objs[i].base = base;
        objs[i].flags = m->flags;
        objs[i].name = "";
        objs[i].phdr_base = phdr_buf;
        objs[i].phdr_num = m->phdr_num;
        objs[i].phdr_entsz = m->phdr_entsz;

        /* Load each PT_LOAD segment */
        for (int p = 0; p < m->phdr_num; p++) {
            Elf64_Phdr ph;

            if (!packer_phdr_read(phdr_buf, phsz, (size_t)p,
                                  m->phdr_entsz, &ph) ||
                !prelink_program_header_valid(&ph, &entries[i]))
                _exit(1);
            if (ph.p_type != PT_LOAD)
                continue;
            if (!prelink_load_header_valid(&ph, &entries[i], m))
                _exit(1);
            if (ph.p_filesz == 0)
                continue;
            if (!u64_add_checked(entries[i].data_offset, ph.p_offset,
                                 &input_off) ||
                packer_stream_seek(outf, input_off) < 0 ||
                fread((void *)(uintptr_t)(base + ph.p_vaddr), 1,
                      (size_t)ph.p_filesz, outf) != (size_t)ph.p_filesz)
                _exit(1);
            if (ph.p_memsz > ph.p_filesz)
                memset((void *)(uintptr_t)(base + ph.p_vaddr + ph.p_filesz),
                       0, (size_t)(ph.p_memsz - ph.p_filesz));
        }

        /* 2. Parse PT_DYNAMIC */
        if (pl_parse_dynamic(&objs[i], base,
                             objs[i].phdr_base,
                             m->phdr_num, m->phdr_entsz) < 0)
            _exit(1);

        /* pl_vaddr_pointer() uses these headers throughout relocation and
         * hash validation.  The prelink worker exits after this transaction,
         * so retain the small buffer for the child's lifetime. */
    }

    /* 3. Compute TLS layout (same algorithm as loader).
     * modid must match the loader's scheme: modid = (non-INTERP index) + 1.
     * The loader iterates only non-INTERP, non-DLOPEN objects and assigns
     * oi+1, so we must count the same way. */
    uint64_t total_tls = PRELINK_TLS_ABOVE_TP ? PRELINK_TLS_TCB_SIZE : 0;
    int oi = 0;  /* non-INTERP, non-DLOPEN object counter; matches loader's oi */
    for (int i = 0; i < nobj; i++) {
        if (metas[i].flags & DLFRZ_FLAG_INTERP) continue;
        if (metas[i].flags & DLFRZ_FLAG_DLOPEN) continue;
        if (metas[i].flags & DLFRZ_FLAG_DATA) continue;
        if (startup_aliases[i] >= 0)
            continue;
        if (objs[i].tls_memsz > 0) {
            uint64_t align = objs[i].tls_align;
            uint64_t next_tls;

            if (PRELINK_TLS_ABOVE_TP) {
                if (!u64_align_up_checked(total_tls, align, &next_tls) ||
                    next_tls > INT64_MAX)
                    _exit(1);
                total_tls = next_tls;
                objs[i].tls_tpoff = (int64_t)total_tls;
                if (!u64_add_checked(total_tls, objs[i].tls_memsz,
                                     &total_tls) ||
                    total_tls > INT64_MAX)
                    _exit(1);
            } else {
                if (!u64_add_checked(total_tls, objs[i].tls_memsz,
                                     &next_tls) ||
                    !u64_align_up_checked(next_tls, align, &total_tls) ||
                    total_tls > INT64_MAX)
                    _exit(1);
                objs[i].tls_tpoff = -(int64_t)total_tls;
            }
            objs[i].tls_modid = (size_t)(oi + 1);  /* matches loader's oi+1 */
        }
        oi++;
    }

    /* 4. Apply relocations */
    /* Pass 0: all except IRELATIVE/COPY */
    for (int i = 0; i < nobj; i++) {
            if (metas[i].flags & DLFRZ_FLAG_INTERP) continue;
            if (metas[i].flags & DLFRZ_FLAG_DLOPEN) continue;
            if (metas[i].flags & DLFRZ_FLAG_DATA) continue;
            if (startup_aliases[i] >= 0)
                continue;
        if (pl_apply_relr(&objs[i]) < 0)
            _exit(1);
        if (objs[i].rela_count > 0 &&
            pl_apply_rela(&objs[i], objs[i].rela, objs[i].rela_count,
                          objs, nobj, 0) < 0)
            _exit(1);
        if (objs[i].jmprel_count > 0 &&
            pl_apply_rela(&objs[i], objs[i].jmprel, objs[i].jmprel_count,
                          objs, nobj, 0) < 0)
            _exit(1);
    }
    /* Pass 1: IRELATIVE (resolvers can read populated GOTs) */
    for (int i = 0; i < nobj; i++) {
            if (metas[i].flags & DLFRZ_FLAG_INTERP) continue;
            if (metas[i].flags & DLFRZ_FLAG_DLOPEN) continue;
            if (metas[i].flags & DLFRZ_FLAG_DATA) continue;
            if (startup_aliases[i] >= 0)
                continue;
        if (objs[i].rela_count > 0 &&
            pl_apply_rela(&objs[i], objs[i].rela, objs[i].rela_count,
                          objs, nobj, 1) < 0)
            _exit(1);
        if (objs[i].jmprel_count > 0 &&
            pl_apply_rela(&objs[i], objs[i].jmprel, objs[i].jmprel_count,
                          objs, nobj, 1) < 0)
            _exit(1);
    }
    /* Pass 2: COPY after source DSOs have already been fully relocated. */
    for (int i = 0; i < nobj; i++) {
            if (metas[i].flags & DLFRZ_FLAG_INTERP) continue;
            if (metas[i].flags & DLFRZ_FLAG_DLOPEN) continue;
            if (metas[i].flags & DLFRZ_FLAG_DATA) continue;
            if (startup_aliases[i] >= 0)
                continue;
        if (objs[i].rela_count > 0 &&
            pl_apply_rela(&objs[i], objs[i].rela, objs[i].rela_count,
                          objs, nobj, 2) < 0)
            _exit(1);
        if (objs[i].jmprel_count > 0 &&
            pl_apply_rela(&objs[i], objs[i].jmprel, objs[i].jmprel_count,
                          objs, nobj, 2) < 0)
            _exit(1);
    }

    for (int i = 0; i < nobj; i++) {
        uint32_t fixup_off = 0, fixup_count = 0;
        int source_alias = startup_aliases[i];

        metas[i].runtime_fixup_off = 0;
        metas[i].runtime_fixup_count = 0;
        metas[i]._reserved = 0;

        if (metas[i].flags & DLFRZ_FLAG_INTERP) {
            metas[i].flags &= ~DLFRZ_FLAG_PRELINKED;
            metas[i].flags &= ~DLFRZ_FLAG_RUNTIME_SCAN;
            continue;
        }
        if (metas[i].flags & DLFRZ_FLAG_DLOPEN) {
            metas[i].flags &= ~DLFRZ_FLAG_PRELINKED;
            metas[i].flags &= ~DLFRZ_FLAG_RUNTIME_SCAN;
            continue;
        }
        if (metas[i].flags & DLFRZ_FLAG_DATA) {
            metas[i].flags &= ~DLFRZ_FLAG_PRELINKED;
            metas[i].flags &= ~DLFRZ_FLAG_RUNTIME_SCAN;
            continue;
        }
        if (source_alias >= 0) {
            metas[i].runtime_fixup_off =
                metas[source_alias].runtime_fixup_off;
            metas[i].runtime_fixup_count =
                metas[source_alias].runtime_fixup_count;
            metas[i].flags |= metas[source_alias].flags &
                (DLFRZ_FLAG_PRELINKED | DLFRZ_FLAG_RUNTIME_SCAN);
            continue;
        }
        metas[i].flags |= DLFRZ_FLAG_PRELINKED;

        if (prelink_obj_collect_runtime_fixups(&objs[i],
                                              &runtime_fixups,
                                              &runtime_fixup_count,
                                              &runtime_fixup_cap,
                                              &fixup_off,
                                              &fixup_count) < 0)
            _exit(1);

        /* An empty per-object range has one canonical representation.  Its
         * offset is semantically inapplicable, so do not retain the running
         * table cursor as ignored state. */
        metas[i].runtime_fixup_off = fixup_count ? fixup_off : 0;
        metas[i].runtime_fixup_count = fixup_count;
        if (fixup_count != 0)
            metas[i].flags |= DLFRZ_FLAG_RUNTIME_SCAN;
        else
            metas[i].flags &= ~DLFRZ_FLAG_RUNTIME_SCAN;
    }

    /* 5. Write patched segments back to frozen binary */
    for (int i = 0; i < nobj; i++) {
        const struct dlfrz_lib_meta *m = &metas[i];
            if (m->flags & DLFRZ_FLAG_INTERP) continue;
            if (m->flags & DLFRZ_FLAG_DLOPEN) continue;
            if (m->flags & DLFRZ_FLAG_DATA) continue;
            if (startup_aliases[i] >= 0)
                continue;
        uint64_t base = objs[i].base;
        const uint8_t *phdr_mem = objs[i].phdr_base;
        size_t phdr_size = (size_t)m->phdr_num * m->phdr_entsz;

        for (int p = 0; p < m->phdr_num; p++) {
            Elf64_Phdr ph;
            uint64_t foff;

            if (!packer_phdr_read(phdr_mem, phdr_size, (size_t)p,
                                  m->phdr_entsz, &ph) ||
                !prelink_program_header_valid(&ph, &entries[i]))
                _exit(1);
            if (ph.p_type != PT_LOAD)
                continue;
            if (!prelink_load_header_valid(&ph, &entries[i], m))
                _exit(1);
            if (ph.p_filesz == 0)
                continue;
            if (!u64_add_checked(entries[i].data_offset, ph.p_offset,
                                 &foff) ||
                packer_stream_seek(outf, foff) < 0 ||
                fwrite((void *)(uintptr_t)(base + ph.p_vaddr), 1,
                       (size_t)ph.p_filesz, outf) != (size_t)ph.p_filesz)
                _exit(1);
        }
    }

    if (meta_off != 0) {
        if (packer_stream_seek(outf, meta_off) < 0 ||
            fwrite(metas, sizeof(*metas), (size_t)nobj, outf) != (size_t)nobj)
            _exit(1);
    }

    if (runtime_fixup_count > 0) {
        struct dlfrz_footer saved_ft;
        size_t file_end, footer_pos, pad_to;
        off_t file_end_off;
        uint64_t fixup_off = 0;
        uint64_t fixup_total = (uint64_t)runtime_fixup_count;

        if (fseeko(outf, 0, SEEK_END) != 0 ||
            (file_end_off = ftello(outf)) < 0 ||
            (uintmax_t)file_end_off > SIZE_MAX)
            _exit(1);
        file_end = (size_t)file_end_off;
        if (file_end < sizeof(saved_ft))
            _exit(1);
        footer_pos = file_end - sizeof(saved_ft);

        if (packer_stream_seek(outf, footer_pos) < 0 ||
            fread(&saved_ft, 1, sizeof(saved_ft), outf) != sizeof(saved_ft))
            _exit(1);

        if (packer_stream_seek(outf, footer_pos) < 0 ||
            footer_pos > SIZE_MAX - 7)
            _exit(1);
        pad_to = (footer_pos + 7) & ~(size_t)7;
        if (pad_to > footer_pos) {
            static const char zeros[8];
            if (fwrite(zeros, 1, pad_to - footer_pos, outf) != pad_to - footer_pos)
                _exit(1);
        }

        fixup_off = pad_to;
        if (fwrite(runtime_fixups, sizeof(*runtime_fixups), runtime_fixup_count, outf)
            != runtime_fixup_count)
            _exit(1);

        memcpy(saved_ft.pad + 8, &fixup_off, sizeof(fixup_off));
        memcpy(saved_ft.pad + 16, &fixup_total, sizeof(fixup_total));
        if (fwrite(&saved_ft, 1, sizeof(saved_ft), outf) != sizeof(saved_ft))
            _exit(1);
    }

    {
        int output_error = 0;

        if (fflush(outf) != 0)
            output_error = 1;
        if (fsync(fileno(outf)) < 0)
            output_error = 1;
        if (fclose(outf) != 0)
            output_error = 1;
        if (output_error)
            _exit(1);
    }
    free(runtime_fixups);
    free(objs);
    _exit(0);
}

/* ---- ELF patching for UPX compatibility -------------------------- */
static int phdr_has_payload_note(const uint8_t *image, size_t image_size,
                                 const Elf64_Phdr *ph)
{
    static const unsigned char owner[] = "DLFREEZE";
    static const unsigned char descriptor[] = "DLFRZPLD";
    const uint32_t payload_note_type = 0x44504c44; /* DPLD */

    if (ph->p_type != PT_NOTE ||
        ph->p_offset > image_size ||
        ph->p_filesz > image_size - (size_t)ph->p_offset)
        return 0;

    size_t pos = (size_t)ph->p_offset;
    size_t end = pos + (size_t)ph->p_filesz;
    while (pos <= end && end - pos >= sizeof(Elf64_Nhdr)) {
        Elf64_Nhdr note;
        size_t name_off, desc_off;

        memcpy(&note, image + pos, sizeof(note));
        pos += sizeof(note);
        name_off = pos;
        if (note.n_namesz > end - pos)
            return 0;
        pos += note.n_namesz;
        if (pos > SIZE_MAX - 3)
            return 0;
        pos = (pos + 3) & ~(size_t)3;
        if (pos > end)
            return 0;

        desc_off = pos;
        if (note.n_descsz > end - pos)
            return 0;
        pos += note.n_descsz;
        if (pos > SIZE_MAX - 3)
            return 0;
        pos = (pos + 3) & ~(size_t)3;
        if (pos > end)
            return 0;

        if (note.n_type == payload_note_type &&
            note.n_namesz == sizeof(owner) - 1 &&
            note.n_descsz == sizeof(descriptor) - 1 &&
            memcmp(image + name_off, owner, sizeof(owner) - 1) == 0 &&
            memcmp(image + desc_off, descriptor,
                   sizeof(descriptor) - 1) == 0)
            return 1;
    }
    return 0;
}

/*
 * PT_LOAD entries are required to appear in ascending p_vaddr order.  Most
 * GNU ld layouts put the dedicated payload note after all load segments, but
 * that is not an ELF guarantee: other conforming linkers may put their single
 * PT_NOTE before the first PT_LOAD.  Changing that entry's type in place would
 * then make the payload the first load even though it has the highest virtual
 * address.  Besides violating the ELF ordering contract, compressors commonly
 * require the first PT_LOAD to remain the offset-zero, header-bearing segment.
 *
 * Move only the converted entry behind the original PT_LOAD group.  Shifting
 * the intervening entries as one sequence preserves every pre-existing
 * ordering constraint, including the requirement that PT_PHDR and PT_INTERP
 * precede loadable segments when present.
 */
static int place_payload_phdr_after_loads(uint8_t *table, size_t table_size,
                                          size_t stride,
                                          uint16_t payload_index,
                                          uint16_t last_load_index)
{
    Elf64_Phdr payload;
    size_t destination;
    size_t source;
    size_t move_size;

    if (payload_index >= last_load_index)
        return 1;
    if (!packer_phdr_read(table, table_size, payload_index, stride,
                          &payload) ||
        (size_t)payload_index > SIZE_MAX / stride ||
        (size_t)(payload_index + 1) > SIZE_MAX / stride ||
        (size_t)(last_load_index - payload_index) > SIZE_MAX / stride)
        return 0;
    destination = (size_t)payload_index * stride;
    source = (size_t)(payload_index + 1) * stride;
    move_size = (size_t)(last_load_index - payload_index) * stride;
    if (destination > table_size || move_size > table_size - destination ||
        source > table_size || move_size > table_size - source)
        return 0;
    memmove(table + destination, table + source, move_size);
    return packer_phdr_write(table, table_size, last_load_index, stride,
                             &payload);
}

/*
 * After writing the frozen binary (bootstrap + payload), we patch the
 * ELF headers so that:
 *
 *  1. The "DLFRZLDR" sentinel in .data is filled with the payload VA
 *     and size.  This survives UPX decompression because it lives in a
 *     PT_LOAD segment.
 *
 *  2. The bootstrap's reserved .note.dlfreeze.payload PT_NOTE entry is
 *     converted into a PT_LOAD that maps the payload region.  This is an
 *     explicit part of the bootstrap/packer ABI; it does not depend on a
 *     linker happening to emit a build-id or GNU property note.  PT_GNU_STACK
 *     is deliberately preserved so the frozen executable retains the
 *     bootstrap's non-executable-stack policy.  UPX compresses all PT_LOAD
 *     segments and restores them at runtime.
 *
 *  3. Section-header metadata is zeroed out (UPX strips it anyway).
 */
static int patch_elf_for_upx_inplace(const char *path, size_t bootstrap_sz,
                                     size_t payload_off, size_t total_sz)
{
    FILE *f = fopen(path, "r+b");
    struct stat st;
    Elf64_Ehdr ehdr;
    uint8_t *phdr_table;
    size_t phdr_table_size;

    if (!f) { perror(path); return -1; }
    if (fstat(fileno(f), &st) < 0 || !S_ISREG(st.st_mode) ||
        st.st_size < 0 || (uintmax_t)st.st_size > SIZE_MAX ||
        (size_t)st.st_size != total_sz || bootstrap_sz > total_sz) {
        fclose(f);
        errno = EINVAL;
        return -1;
    }

    /* Read enough of the bootstrap to get ELF + phdr + scan for sentinel */
    /* We need to read the full bootstrap to find DLFRZLDR in .data */
    uint8_t *hdr = malloc(bootstrap_sz);
    if (!hdr) { fclose(f); return -1; }
    if (fread(hdr, 1, bootstrap_sz, f) != bootstrap_sz) {
        free(hdr); fclose(f); return -1;
    }

    if (bootstrap_sz < sizeof(ehdr)) {
        fprintf(stderr, "dlfreeze: invalid bootstrap ELF header\n");
        free(hdr); fclose(f); return -1;
    }
    memcpy(&ehdr, hdr, sizeof(ehdr));
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr.e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr.e_ident[EI_VERSION] != EV_CURRENT ||
        ehdr.e_version != EV_CURRENT || ehdr.e_type != ET_EXEC ||
        (ehdr.e_machine != EM_X86_64 && ehdr.e_machine != EM_AARCH64) ||
        ehdr.e_ehsize != sizeof(Elf64_Ehdr) ||
        ehdr.e_phentsize != sizeof(Elf64_Phdr) ||
        ehdr.e_phnum == 0 || ehdr.e_phnum == PN_XNUM ||
        ehdr.e_phoff > bootstrap_sz ||
        (size_t)ehdr.e_phnum >
            (bootstrap_sz - (size_t)ehdr.e_phoff) / sizeof(Elf64_Phdr)) {
        fprintf(stderr, "dlfreeze: invalid bootstrap ELF header\n");
        free(hdr); fclose(f); return -1;
    }
    phdr_table = hdr + (size_t)ehdr.e_phoff;
    phdr_table_size = (size_t)ehdr.e_phnum * ehdr.e_phentsize;

    /* --- Find the highest VA used by existing PT_LOAD segments --- */
    if (total_sz < payload_off || payload_off < bootstrap_sz ||
        (payload_off & (PAYLOAD_ALIGN - 1)) != 0) {
        fprintf(stderr, "dlfreeze: invalid bootstrap payload layout\n");
        free(hdr); fclose(f); return -1;
    }

    uint64_t max_va = 0;
    uint64_t previous_load_vaddr = 0;
    int found_load = 0;
    int last_load_index = -1;
    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr ph;

        if (!packer_phdr_read(phdr_table, phdr_table_size, (size_t)i,
                              ehdr.e_phentsize, &ph)) {
            fprintf(stderr, "dlfreeze: invalid bootstrap program header\n");
            free(hdr); fclose(f); return -1;
        }
        if (ph.p_type == PT_LOAD) {
            if (ph.p_filesz > ph.p_memsz ||
                ph.p_offset > bootstrap_sz ||
                ph.p_filesz > bootstrap_sz - (size_t)ph.p_offset ||
                ph.p_vaddr > UINT64_MAX - ph.p_memsz) {
                fprintf(stderr, "dlfreeze: invalid bootstrap PT_LOAD range\n");
                free(hdr); fclose(f); return -1;
            }
            if (found_load && ph.p_vaddr < previous_load_vaddr) {
                fprintf(stderr,
                        "dlfreeze: bootstrap PT_LOAD entries are unordered\n");
                free(hdr); fclose(f); return -1;
            }
            found_load = 1;
            previous_load_vaddr = ph.p_vaddr;
            last_load_index = i;
            uint64_t end = ph.p_vaddr + ph.p_memsz;
            if (end > max_va) max_va = end;
        }
    }

    /* Payload VA: next page-aligned address after the last PT_LOAD */
    if (!found_load || max_va > UINT64_MAX - (PAYLOAD_ALIGN - 1)) {
        fprintf(stderr, "dlfreeze: bootstrap address space is exhausted\n");
        free(hdr); fclose(f); return -1;
    }
    uint64_t payload_vaddr = ALIGN_UP(max_va, PAYLOAD_ALIGN);
    size_t payload_filesz = total_sz - payload_off;

    /* --- Find and repurpose our reserved PT_NOTE for the payload. --- */
    int found_payload_slot = 0;
    int payload_slot_index = -1;
    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr ph;

        if (!packer_phdr_read(phdr_table, phdr_table_size, (size_t)i,
                              ehdr.e_phentsize, &ph)) {
            free(hdr); fclose(f); return -1;
        }
        if (phdr_has_payload_note(hdr, bootstrap_sz, &ph)) {
            ph.p_type   = PT_LOAD;
            ph.p_flags  = PF_R;
            ph.p_offset = payload_off;
            ph.p_vaddr  = payload_vaddr;
            ph.p_paddr  = payload_vaddr;
            ph.p_filesz = payload_filesz;
            ph.p_memsz  = payload_filesz;
            ph.p_align  = PAYLOAD_ALIGN;
            if (!packer_phdr_write(phdr_table, phdr_table_size, (size_t)i,
                                   ehdr.e_phentsize, &ph)) {
                free(hdr); fclose(f); return -1;
            }
            found_payload_slot = 1;
            payload_slot_index = i;
            break;
        }
    }
    if (!found_payload_slot) {
        fprintf(stderr,
                "dlfreeze: reserved payload PT_NOTE is missing from the "
                "bootstrap\n");
        free(hdr); fclose(f); return -1;
    }

    if (!place_payload_phdr_after_loads(
            phdr_table, phdr_table_size, ehdr.e_phentsize,
            (uint16_t)payload_slot_index, (uint16_t)last_load_index)) {
        fprintf(stderr, "dlfreeze: invalid bootstrap program-header order\n");
        free(hdr); fclose(f); return -1;
    }

    /* --- Zero section-header table if not already set by symtab --- */
    if (ehdr.e_shoff == 0) {
        ehdr.e_shentsize = 0;
        ehdr.e_shnum     = 0;
        ehdr.e_shstrndx  = 0;
    }

    /* --- Patch the DLFRZLDR sentinel in a writable PT_LOAD. ---
     * The marker bytes may also occur in notes, debug data, or other
     * file-only metadata.  Patching the first raw match can leave the live
     * descriptor at zero: the ordinary EOF-footer path still works, while a
     * UPX image fails because it needs the in-memory descriptor. */
    const char sentinel[] = "DLFRZLDR";
    size_t loader_info_off = SIZE_MAX;
    for (size_t i = 0; i + sizeof(struct dlfrz_loader_info) <= bootstrap_sz; i++) {
        if (memcmp(hdr + i, sentinel, 8) == 0) {
            /* Verify this is our struct (followed by three zero uint64s) */
            uint64_t v1, v2, v3;
            int in_writable_load = 0;

            memcpy(&v1, hdr + i + 8, 8);
            memcpy(&v2, hdr + i + 16, 8);
            memcpy(&v3, hdr + i + 24, 8);
            if (v1 != 0 || v2 != 0 || v3 != 0)
                continue;
            for (int p = 0; p < ehdr.e_phnum; p++) {
                Elf64_Phdr ph;

                if (!packer_phdr_read(phdr_table, phdr_table_size,
                                      (size_t)p, ehdr.e_phentsize, &ph) ||
                    ph.p_type != PT_LOAD || !(ph.p_flags & PF_W) ||
                    ph.p_offset > i ||
                    i - (size_t)ph.p_offset > ph.p_filesz ||
                    sizeof(struct dlfrz_loader_info) >
                        ph.p_filesz - (i - (size_t)ph.p_offset))
                    continue;
                in_writable_load = 1;
                break;
            }
            if (!in_writable_load)
                continue;
            if (loader_info_off != SIZE_MAX) {
                fprintf(stderr,
                        "dlfreeze: multiple live DLFRZLDR sentinels found\n");
                free(hdr); fclose(f); return -1;
            }
            loader_info_off = i;
        }
    }
    if (loader_info_off == SIZE_MAX) {
        fprintf(stderr, "dlfreeze: live DLFRZLDR sentinel not found\n");
        free(hdr); fclose(f); return -1;
    }
    if (payload_filesz == 0 ||
        payload_vaddr > UINT64_MAX - (uint64_t)payload_filesz) {
        fprintf(stderr, "dlfreeze: payload mapping is unrepresentable\n");
        free(hdr); fclose(f); return -1;
    }
    {
        uint64_t foff = payload_off;
        uint64_t mapped_filesz = payload_filesz;

        memcpy(hdr + loader_info_off + 8, &payload_vaddr, 8);
        memcpy(hdr + loader_info_off + 16, &mapped_filesz, 8);
        memcpy(hdr + loader_info_off + 24, &foff, 8);
    }

    memcpy(hdr, &ehdr, sizeof(ehdr));

    /* --- Write modified header back --- */
    rewind(f);
    if (fwrite(hdr, 1, bootstrap_sz, f) != bootstrap_sz) {
        free(hdr); fclose(f); return -1;
    }

    {
        int saved_errno = 0;

        if (fflush(f) != 0)
            saved_errno = errno ? errno : EIO;
        if (!saved_errno && fsync(fileno(f)) < 0)
            saved_errno = errno ? errno : EIO;
        if (fclose(f) != 0 && !saved_errno)
            saved_errno = errno ? errno : EIO;
        free(hdr);
        if (saved_errno) {
            errno = saved_errno;
            return -1;
        }
    }
    return 0;
}

static int patch_elf_for_upx(const char *path, size_t bootstrap_sz,
                             size_t payload_off, size_t total_sz)
{
    char transaction_path[PATH_MAX];
    int saved_errno;

    /* Header fields and the live loader descriptor are one commit.  A short
     * write, ENOSPC, or process interruption must not leave a plausible ELF
     * with only half of that pair updated. */
    if (make_transaction_copy(path, "upx", transaction_path) < 0)
        return -1;
    if (patch_elf_for_upx_inplace(transaction_path, bootstrap_sz,
                                  payload_off, total_sz) < 0) {
        saved_errno = errno ? errno : EIO;
        unlink(transaction_path);
        errno = saved_errno;
        return -1;
    }
    if (rename(transaction_path, path) < 0) {
        saved_errno = errno ? errno : EIO;
        unlink(transaction_path);
        errno = saved_errno;
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
static int symtab_size_add(size_t left, size_t right, size_t *result)
{
    if (right > SIZE_MAX - left) {
        errno = EOVERFLOW;
        return -1;
    }
    *result = left + right;
    return 0;
}

static int symtab_size_mul(size_t left, size_t right, size_t *result)
{
    if (left != 0 && right > SIZE_MAX / left) {
        errno = EOVERFLOW;
        return -1;
    }
    *result = left * right;
    return 0;
}

static int symtab_size_align(size_t value, size_t alignment, size_t *result)
{
    size_t mask;

    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        errno = EINVAL;
        return -1;
    }
    mask = alignment - 1;
    if (value > SIZE_MAX - mask) {
        errno = EOVERFLOW;
        return -1;
    }
    *result = (value + mask) & ~mask;
    return 0;
}

static int symtab_stream_seek(FILE *file, size_t offset)
{
    return packer_stream_seek(file, offset);
}

static int symtab_stream_write(FILE *file, const void *data, size_t size)
{
    if (size != 0 && fwrite(data, 1, size, file) != size) {
        if (errno == 0)
            errno = EIO;
        return -1;
    }
    return 0;
}

static int symtab_stream_pad(FILE *file, size_t size)
{
    static const unsigned char zeros[8];

    while (size != 0) {
        size_t chunk = size < sizeof(zeros) ? size : sizeof(zeros);

        if (symtab_stream_write(file, zeros, chunk) < 0)
            return -1;
        size -= chunk;
    }
    return 0;
}

struct symtab_text_info {
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    int valid;
};

struct symtab_elf_view {
    const uint8_t *image;
    size_t image_size;
    const uint8_t *phdrs;
    uint16_t phnum;
    const uint8_t *dynamic;
    size_t dynamic_count;
    const uint8_t *dynsym;
    const char *dynstr;
    const uint8_t *versym;
    uint32_t dynsym_count;
    size_t dynstr_size;
    uint64_t verneed_address;
    uint64_t verneed_count;
    int have_versym;
    int have_verneed;
};

static int symtab_image_range(const uint8_t *image, size_t image_size,
                              uint64_t offset, uint64_t size,
                              const uint8_t **bytes_out)
{
    if (!image || offset > (uint64_t)image_size ||
        size > (uint64_t)image_size - offset || offset > SIZE_MAX)
        return 0;
    if (bytes_out)
        *bytes_out = image + (size_t)offset;
    return 1;
}

static int symtab_view_phdr(const struct symtab_elf_view *view,
                            uint16_t index, Elf64_Phdr *phdr_out)
{
    /* Keep a defined value even for compilers which do not propagate the
     * success-only output contract of symtab_size_mul() through the
     * short-circuit expression below.  The value is still consumed only
     * after the checked multiplication succeeds. */
    size_t offset = 0;

    if (!view || !phdr_out || index >= view->phnum ||
        symtab_size_mul(index, sizeof(*phdr_out), &offset) < 0)
        return 0;
    memcpy(phdr_out, view->phdrs + offset, sizeof(*phdr_out));
    return 1;
}

/* Resolve an ELF virtual address only through a readable, file-backed
 * PT_LOAD.  Overlapping segments are accepted only when they describe the
 * same file bytes; otherwise the mapping is ambiguous and is rejected. */
static int symtab_vaddr_file(const struct symtab_elf_view *view,
                             uint64_t address, size_t size,
                             const uint8_t **bytes_out,
                             size_t *available_out)
{
    const uint8_t *match = NULL;
    size_t match_available = 0;
    int found = 0;

    if (!view)
        return 0;
    for (uint16_t i = 0; i < view->phnum; i++) {
        Elf64_Phdr phdr;
        uint64_t delta;
        uint64_t file_offset;
        uint64_t available;
        const uint8_t *candidate;

        if (!symtab_view_phdr(view, i, &phdr) ||
            phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_R) ||
            address < phdr.p_vaddr)
            continue;
        delta = address - phdr.p_vaddr;
        if (delta > phdr.p_filesz ||
            (uint64_t)size > phdr.p_filesz - delta ||
            !u64_add_checked(phdr.p_offset, delta, &file_offset) ||
            !symtab_image_range(view->image, view->image_size, file_offset,
                                size, &candidate))
            continue;
        available = phdr.p_filesz - delta;
        if (available > SIZE_MAX)
            available = SIZE_MAX;
        if (found && candidate != match)
            return 0;
        if (!found || (size_t)available < match_available) {
            match = candidate;
            match_available = (size_t)available;
        }
        found = 1;
    }
    if (!found)
        return 0;
    if (bytes_out)
        *bytes_out = match;
    if (available_out)
        *available_out = match_available;
    return 1;
}

static uint32_t symtab_read_u32(const uint8_t *bytes)
{
    uint32_t value;

    memcpy(&value, bytes, sizeof(value));
    return value;
}

static int symtab_validate_sysv_hash(const struct symtab_elf_view *view,
                                     uint64_t address,
                                     uint32_t max_symbols,
                                     uint32_t *symbol_count_out)
{
    const uint8_t *table;
    /* GCC 7 cannot always see that every size helper initializes its output
     * on the only path which reaches the following helper.  Initial values
     * make that contract explicit without weakening any overflow check. */
    size_t bucket_bytes = 0;
    size_t chain_bytes = 0;
    size_t table_bytes = 0;
    uint32_t nbuckets;
    uint32_t nchain;

    if (!symbol_count_out ||
        (address & (_Alignof(uint32_t) - 1)) != 0 ||
        !symtab_vaddr_file(view, address, 2 * sizeof(uint32_t), &table,
                           NULL))
        return 0;
    nbuckets = symtab_read_u32(table);
    nchain = symtab_read_u32(table + sizeof(uint32_t));
    if (nbuckets == 0 || nchain == 0 || nchain > max_symbols ||
        symtab_size_mul(nbuckets, sizeof(uint32_t), &bucket_bytes) < 0 ||
        symtab_size_mul(nchain, sizeof(uint32_t), &chain_bytes) < 0 ||
        symtab_size_add(2 * sizeof(uint32_t), bucket_bytes,
                        &table_bytes) < 0 ||
        symtab_size_add(table_bytes, chain_bytes, &table_bytes) < 0 ||
        !symtab_vaddr_file(view, address, table_bytes, &table, NULL))
        return 0;

    for (uint32_t i = 0; i < nbuckets; i++) {
        uint32_t symbol = symtab_read_u32(
            table + 2 * sizeof(uint32_t) + (size_t)i * sizeof(uint32_t));

        if (symbol != STN_UNDEF && symbol >= nchain)
            return 0;
    }
    for (uint32_t i = 0; i < nchain; i++) {
        uint32_t symbol = symtab_read_u32(
            table + 2 * sizeof(uint32_t) + bucket_bytes +
            (size_t)i * sizeof(uint32_t));

        if (symbol != STN_UNDEF && symbol >= nchain)
            return 0;
    }
    *symbol_count_out = nchain;
    return 1;
}

static int symtab_validate_gnu_hash(const struct symtab_elf_view *view,
                                    uint64_t address,
                                    uint32_t max_symbols,
                                    uint32_t *symbol_count_out)
{
    const uint8_t *table;
    const uint8_t *chain;
    size_t bloom_bytes;
    size_t bucket_bytes;
    size_t prefix_bytes;
    size_t chain_available;
    size_t chain_capacity;
    size_t chain_bytes;
    size_t total_bytes;
    uint64_t chain_address;
    uint32_t nbuckets;
    uint32_t symoffset;
    uint32_t bloom_size;
    uint32_t bloom_shift;
    uint32_t max_symbol = 0;
    uint32_t count;
    int have_symbol = 0;

    if (!symbol_count_out ||
        (address & (_Alignof(uint64_t) - 1)) != 0 ||
        !symtab_vaddr_file(view, address, 4 * sizeof(uint32_t), &table,
                           NULL))
        return 0;
    nbuckets = symtab_read_u32(table);
    symoffset = symtab_read_u32(table + sizeof(uint32_t));
    bloom_size = symtab_read_u32(table + 2 * sizeof(uint32_t));
    bloom_shift = symtab_read_u32(table + 3 * sizeof(uint32_t));
    if (nbuckets == 0 || bloom_size == 0 || bloom_shift >= 32 ||
        symoffset > max_symbols ||
        symtab_size_mul(bloom_size, sizeof(uint64_t), &bloom_bytes) < 0 ||
        symtab_size_mul(nbuckets, sizeof(uint32_t), &bucket_bytes) < 0 ||
        symtab_size_add(4 * sizeof(uint32_t), bloom_bytes,
                        &prefix_bytes) < 0 ||
        symtab_size_add(prefix_bytes, bucket_bytes, &prefix_bytes) < 0 ||
        !symtab_vaddr_file(view, address, prefix_bytes, &table, NULL) ||
        !u64_add_checked(address, prefix_bytes, &chain_address) ||
        !symtab_vaddr_file(view, chain_address, 0, &chain,
                           &chain_available))
        return 0;

    chain_capacity = chain_available / sizeof(uint32_t);
    if (chain_capacity > (size_t)(max_symbols - symoffset))
        chain_capacity = (size_t)(max_symbols - symoffset);
    for (uint32_t i = 0; i < nbuckets; i++) {
        uint32_t symbol = symtab_read_u32(
            table + 4 * sizeof(uint32_t) + bloom_bytes +
            (size_t)i * sizeof(uint32_t));

        if (symbol == STN_UNDEF)
            continue;
        if (symbol < symoffset || symbol >= max_symbols ||
            (uint64_t)(symbol - symoffset) >= chain_capacity)
            return 0;
        if (!have_symbol || symbol > max_symbol)
            max_symbol = symbol;
        have_symbol = 1;
    }
    if (!have_symbol) {
        count = symoffset;
    } else {
        size_t index = (size_t)(max_symbol - symoffset);

        for (;;) {
            uint32_t hash;

            if (index >= chain_capacity || max_symbol == UINT32_MAX)
                return 0;
            hash = symtab_read_u32(chain + index * sizeof(uint32_t));
            if (hash & 1) {
                count = max_symbol + 1;
                break;
            }
            index++;
            max_symbol++;
        }
    }
    if (count == 0 || count < symoffset || count > max_symbols ||
        symtab_size_mul((size_t)(count - symoffset), sizeof(uint32_t),
                        &chain_bytes) < 0 ||
        symtab_size_add(prefix_bytes, chain_bytes, &total_bytes) < 0 ||
        !symtab_vaddr_file(view, address, total_bytes, &table, NULL))
        return 0;
    for (uint32_t i = 0; i < nbuckets; i++) {
        uint32_t symbol = symtab_read_u32(
            table + 4 * sizeof(uint32_t) + bloom_bytes +
            (size_t)i * sizeof(uint32_t));

        if (symbol != STN_UNDEF &&
            (symbol < symoffset || symbol >= count))
            return 0;
    }
    *symbol_count_out = count;
    return 1;
}

static int symtab_set_dynamic(int *seen, uint64_t *storage, uint64_t value)
{
    if (*seen && *storage != value)
        return 0;
    *seen = 1;
    *storage = value;
    return 1;
}

/* GNU hash chains enumerate exported definitions, not necessarily the
 * leading undefined symbols named by dynamic relocations.  Derive a second
 * bounded lower limit for DYNSYM from those relocation indices so a binary
 * with no hash-exported definitions (for example a minimal -pg executable)
 * does not lose its imports from the view. */
static int symtab_rela_symbol_count(const struct symtab_elf_view *view,
                                    uint64_t address, uint64_t byte_size,
                                    uint32_t max_symbols,
                                    uint32_t *count_inout)
{
    const uint8_t *table;
    size_t size;

    if (!view || !count_inout || byte_size > SIZE_MAX ||
        byte_size % sizeof(Elf64_Rela) != 0 ||
        (address & (_Alignof(Elf64_Rela) - 1)) != 0)
        return 0;
    size = (size_t)byte_size;
    if (size == 0)
        return 1;
    if (!symtab_vaddr_file(view, address, size, &table, NULL))
        return 0;
    for (size_t offset = 0; offset < size; offset += sizeof(Elf64_Rela)) {
        Elf64_Rela relocation;
        uint32_t index;

        memcpy(&relocation, table + offset, sizeof(relocation));
        index = ELF64_R_SYM(relocation.r_info);
        if (index >= max_symbols)
            return 0;
        if (index != UINT32_MAX && index + 1 > *count_inout)
            *count_inout = index + 1;
    }
    return 1;
}

static int symtab_elf_view_init(const uint8_t *file_image,
                                size_t file_size,
                                const struct dlfrz_entry *entry,
                                const struct dlfrz_lib_meta *meta,
                                struct symtab_elf_view *view,
                                struct symtab_text_info *text,
                                int include_relocation_symbols)
{
    const uint8_t *image;
    const uint8_t *dynamic;
    const uint8_t *mapped_dynamic;
    const uint8_t *dynstr;
    const uint8_t *dynsym;
    Elf64_Ehdr ehdr;
    Elf64_Phdr dynamic_phdr = {0};
    uint64_t symtab_address = 0;
    uint64_t strtab_address = 0;
    uint64_t strtab_size = 0;
    uint64_t syment = 0;
    uint64_t gnu_hash_address = 0;
    uint64_t sysv_hash_address = 0;
    uint64_t rela_address = 0;
    uint64_t rela_size = 0;
    uint64_t rela_entry_size = 0;
    uint64_t jmprel_address = 0;
    uint64_t pltrel_size = 0;
    uint64_t pltrel_type = 0;
    uint64_t versym_address = 0;
    uint64_t verneed_address = 0;
    uint64_t verneed_count = 0;
    uint32_t gnu_count = 0;
    uint32_t sysv_count = 0;
    uint32_t symbol_count = 0;
    uint32_t max_symbols;
    size_t dynamic_count;
    size_t phdr_bytes;
    size_t symtab_available;
    size_t symtab_bytes;
    int have_dynamic = 0;
    int have_load = 0;
    int saw_null = 0;
    int have_symtab = 0;
    int have_strtab = 0;
    int have_strsz = 0;
    int have_syment = 0;
    int have_gnu_hash = 0;
    int have_sysv_hash = 0;
    int have_rela = 0;
    int have_relasz = 0;
    int have_relaent = 0;
    int have_jmprel = 0;
    int have_pltrelsz = 0;
    int have_pltrel = 0;
    int have_versym = 0;
    int have_verneed = 0;
    int have_verneed_count = 0;

    if (!file_image || !entry || !meta || !view || !text ||
        entry->data_size > SIZE_MAX ||
        !symtab_image_range(file_image, file_size, entry->data_offset,
                            entry->data_size, &image) ||
        entry->data_size < sizeof(ehdr))
        goto malformed;
    memset(view, 0, sizeof(*view));
    memcpy(&ehdr, image, sizeof(ehdr));
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr.e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr.e_ident[EI_VERSION] != EV_CURRENT ||
        ehdr.e_version != EV_CURRENT ||
        (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) ||
        ehdr.e_ehsize != sizeof(ehdr) ||
        ehdr.e_phnum == 0 || ehdr.e_phnum == PN_XNUM ||
        ehdr.e_phentsize != sizeof(Elf64_Phdr) ||
#if defined(__x86_64__)
        ehdr.e_machine != EM_X86_64 ||
#elif defined(__aarch64__)
        ehdr.e_machine != EM_AARCH64 ||
#endif
        symtab_size_mul(ehdr.e_phnum, sizeof(Elf64_Phdr), &phdr_bytes) < 0 ||
        !symtab_image_range(image, (size_t)entry->data_size, ehdr.e_phoff,
                            phdr_bytes, &view->phdrs))
        goto malformed;

    view->image = image;
    view->image_size = (size_t)entry->data_size;
    view->phnum = ehdr.e_phnum;
    for (uint16_t i = 0; i < view->phnum; i++) {
        Elf64_Phdr phdr;

        if (!symtab_view_phdr(view, i, &phdr))
            goto malformed;
        if (phdr.p_type == PT_LOAD) {
            uint64_t ignored;

            if (phdr.p_filesz > phdr.p_memsz ||
                !symtab_image_range(image, view->image_size, phdr.p_offset,
                                    phdr.p_filesz, NULL) ||
                !u64_add_checked(phdr.p_vaddr, phdr.p_memsz, &ignored))
                goto malformed;
            have_load = 1;
            if ((phdr.p_flags & PF_X) && !text->valid) {
                if (!u64_add_checked(meta->base_addr, phdr.p_vaddr,
                                     &text->sh_addr) ||
                    !u64_add_checked(entry->data_offset, phdr.p_offset,
                                     &text->sh_offset))
                    goto malformed;
                text->sh_size = phdr.p_memsz;
                text->valid = 1;
            }
        }
        if (phdr.p_type == PT_DYNAMIC) {
            if (have_dynamic)
                goto malformed;
            dynamic_phdr = phdr;
            have_dynamic = 1;
        }
    }
    if (!have_load)
        goto malformed;
    if (!have_dynamic)
        return 0;
    if (dynamic_phdr.p_filesz == 0 ||
        dynamic_phdr.p_filesz > dynamic_phdr.p_memsz ||
        dynamic_phdr.p_filesz % sizeof(Elf64_Dyn) != 0 ||
        dynamic_phdr.p_filesz > SIZE_MAX ||
        !symtab_image_range(image, view->image_size, dynamic_phdr.p_offset,
                            dynamic_phdr.p_filesz, &dynamic) ||
        !symtab_vaddr_file(view, dynamic_phdr.p_vaddr,
                           (size_t)dynamic_phdr.p_filesz, &mapped_dynamic,
                           NULL) || mapped_dynamic != dynamic)
        goto malformed;
    dynamic_count = (size_t)dynamic_phdr.p_filesz / sizeof(Elf64_Dyn);
    for (size_t i = 0; i < dynamic_count; i++) {
        Elf64_Dyn item;

        memcpy(&item, dynamic + i * sizeof(item), sizeof(item));
        if (item.d_tag == DT_NULL) {
            saw_null = 1;
            break;
        }
        switch (item.d_tag) {
        case DT_SYMTAB:
            if (!symtab_set_dynamic(&have_symtab, &symtab_address,
                                    item.d_un.d_ptr))
                goto malformed;
            break;
        case DT_STRTAB:
            if (!symtab_set_dynamic(&have_strtab, &strtab_address,
                                    item.d_un.d_ptr))
                goto malformed;
            break;
        case DT_STRSZ:
            if (!symtab_set_dynamic(&have_strsz, &strtab_size,
                                    item.d_un.d_val))
                goto malformed;
            break;
        case DT_SYMENT:
            if (!symtab_set_dynamic(&have_syment, &syment,
                                    item.d_un.d_val))
                goto malformed;
            break;
        case DT_GNU_HASH:
            if (!symtab_set_dynamic(&have_gnu_hash, &gnu_hash_address,
                                    item.d_un.d_ptr))
                goto malformed;
            break;
        case DT_HASH:
            if (!symtab_set_dynamic(&have_sysv_hash, &sysv_hash_address,
                                    item.d_un.d_ptr))
                goto malformed;
            break;
        case DT_RELA:
            if (include_relocation_symbols &&
                !symtab_set_dynamic(&have_rela, &rela_address,
                                    item.d_un.d_ptr))
                goto malformed;
            break;
        case DT_RELASZ:
            if (include_relocation_symbols &&
                !symtab_set_dynamic(&have_relasz, &rela_size,
                                    item.d_un.d_val))
                goto malformed;
            break;
        case DT_RELAENT:
            if (include_relocation_symbols &&
                !symtab_set_dynamic(&have_relaent, &rela_entry_size,
                                    item.d_un.d_val))
                goto malformed;
            break;
        case DT_JMPREL:
            if (include_relocation_symbols &&
                !symtab_set_dynamic(&have_jmprel, &jmprel_address,
                                    item.d_un.d_ptr))
                goto malformed;
            break;
        case DT_PLTRELSZ:
            if (include_relocation_symbols &&
                !symtab_set_dynamic(&have_pltrelsz, &pltrel_size,
                                    item.d_un.d_val))
                goto malformed;
            break;
        case DT_PLTREL:
            if (include_relocation_symbols &&
                !symtab_set_dynamic(&have_pltrel, &pltrel_type,
                                    item.d_un.d_val))
                goto malformed;
            break;
        case DT_VERSYM:
            if (include_relocation_symbols &&
                !symtab_set_dynamic(&have_versym, &versym_address,
                                    item.d_un.d_ptr))
                goto malformed;
            break;
        case DT_VERNEED:
            if (include_relocation_symbols &&
                !symtab_set_dynamic(&have_verneed, &verneed_address,
                                    item.d_un.d_ptr))
                goto malformed;
            break;
        case DT_VERNEEDNUM:
            if (include_relocation_symbols &&
                !symtab_set_dynamic(&have_verneed_count, &verneed_count,
                                    item.d_un.d_val))
                goto malformed;
            break;
        }
    }
    if (!saw_null)
        goto malformed;
    if (!have_symtab && !have_strtab && !have_strsz && !have_syment &&
        !have_gnu_hash && !have_sysv_hash)
        return 0;
    if (!have_symtab || !have_strtab || !have_strsz || !have_syment ||
        symtab_address == 0 || strtab_address == 0 || strtab_size == 0 ||
        syment != sizeof(Elf64_Sym) ||
        (have_gnu_hash && gnu_hash_address == 0) ||
        (have_sysv_hash && sysv_hash_address == 0) ||
        strtab_size > SIZE_MAX ||
        !symtab_vaddr_file(view, strtab_address, (size_t)strtab_size,
                           &dynstr, NULL) || dynstr[0] != '\0' ||
        dynstr[(size_t)strtab_size - 1] != '\0' ||
        !symtab_vaddr_file(view, symtab_address, sizeof(Elf64_Sym),
                           &dynsym, &symtab_available))
        goto malformed;
    if (include_relocation_symbols &&
        (have_verneed != have_verneed_count ||
         (have_versym && versym_address == 0) ||
         (have_verneed &&
          (verneed_address == 0 || verneed_count == 0 ||
           verneed_count > view->image_size / sizeof(Elf64_Verneed)))))
        goto malformed;
    if ((symtab_address & (_Alignof(Elf64_Sym) - 1)) != 0)
        goto malformed;
    if (symtab_available / sizeof(Elf64_Sym) > UINT32_MAX)
        max_symbols = UINT32_MAX;
    else
        max_symbols = (uint32_t)(symtab_available / sizeof(Elf64_Sym));
    if (max_symbols == 0)
        goto malformed;

    if (have_sysv_hash &&
        !symtab_validate_sysv_hash(view, sysv_hash_address, max_symbols,
                                   &sysv_count))
        goto malformed;
    if (have_gnu_hash &&
        !symtab_validate_gnu_hash(view, gnu_hash_address, max_symbols,
                                  &gnu_count))
        goto malformed;
    if (have_sysv_hash) {
        if (have_gnu_hash && gnu_count > sysv_count)
            goto malformed;
        symbol_count = sysv_count;
    } else if (have_gnu_hash) {
        symbol_count = gnu_count;
    }

    if (include_relocation_symbols && (have_rela || have_relasz) &&
        (!have_rela || !have_relasz || !have_relaent ||
         rela_entry_size != sizeof(Elf64_Rela) || rela_address == 0 ||
         !symtab_rela_symbol_count(view, rela_address, rela_size,
                                   max_symbols, &symbol_count)))
        goto malformed;
    if (include_relocation_symbols &&
        (have_jmprel || have_pltrelsz || have_pltrel) &&
        (!have_jmprel || !have_pltrelsz || !have_pltrel ||
         pltrel_type != DT_RELA || jmprel_address == 0 ||
         !symtab_rela_symbol_count(view, jmprel_address, pltrel_size,
                                   max_symbols, &symbol_count)))
        goto malformed;

    if (strtab_address > symtab_address &&
        (strtab_address - symtab_address) % sizeof(Elf64_Sym) == 0) {
        uint64_t adjacent_count =
            (strtab_address - symtab_address) / sizeof(Elf64_Sym);

        if (adjacent_count == 0 || adjacent_count > UINT32_MAX)
            goto malformed;
        if (!have_gnu_hash && !have_sysv_hash)
            symbol_count = (uint32_t)adjacent_count;
        else if (symbol_count > adjacent_count)
            goto malformed;
    } else if (!have_gnu_hash && !have_sysv_hash) {
        goto malformed;
    }
    if (symbol_count == 0 || symbol_count > max_symbols ||
        symtab_size_mul(symbol_count, sizeof(Elf64_Sym), &symtab_bytes) < 0 ||
        !symtab_vaddr_file(view, symtab_address, symtab_bytes, &dynsym, NULL))
        goto malformed;

    if (include_relocation_symbols && have_versym) {
        size_t versym_bytes;

        if ((versym_address & (_Alignof(uint16_t) - 1)) != 0 ||
            symtab_size_mul(symbol_count, sizeof(uint16_t),
                            &versym_bytes) < 0 ||
            !symtab_vaddr_file(view, versym_address, versym_bytes,
                               &view->versym, NULL))
            goto malformed;
    }

    for (uint32_t i = 0; i < symbol_count; i++) {
        Elf64_Sym symbol;

        memcpy(&symbol, dynsym + (size_t)i * sizeof(symbol), sizeof(symbol));
        if (symbol.st_name >= strtab_size)
            goto malformed;
    }
    view->dynsym = dynsym;
    view->dynstr = (const char *)dynstr;
    view->dynamic = dynamic;
    view->dynamic_count = dynamic_count;
    view->dynsym_count = symbol_count;
    view->dynstr_size = (size_t)strtab_size;
    view->verneed_address = verneed_address;
    view->verneed_count = verneed_count;
    view->have_versym = have_versym;
    view->have_verneed = have_verneed;
    return 0;

malformed:
    errno = EINVAL;
    return -1;
}

static void symtab_view_symbol(const struct symtab_elf_view *view,
                               uint32_t index, Elf64_Sym *symbol_out)
{
    memcpy(symbol_out, view->dynsym + (size_t)index * sizeof(*symbol_out),
           sizeof(*symbol_out));
}

static const char *symtab_view_string(const struct symtab_elf_view *view,
                                      uint64_t offset)
{
    if (!view || !view->dynstr || offset >= view->dynstr_size)
        return NULL;
    /* symtab_elf_view_init admitted the ELF string-table sentinels once, so
     * every in-range suffix is terminated without a repeated tail scan. */
    return view->dynstr + (size_t)offset;
}

static uint32_t symtab_version_name_hash(const char *name)
{
    uint32_t hash = 0;

    while (name && *name) {
        uint32_t high;

        hash = (hash << 4) + (unsigned char)*name++;
        high = hash & 0xf0000000U;
        if (high != 0)
            hash ^= high >> 24;
        hash &= ~high;
    }
    return hash;
}

/* A VERNEED provider is meaningful only when the same bounded dynamic table
 * names it as a dependency.  Return -1 for a malformed string reference. */
static int symtab_provider_is_needed(const struct symtab_elf_view *view,
                                     const char *provider)
{
    if (!view || !view->dynamic || !provider)
        return -1;
    for (size_t i = 0; i < view->dynamic_count; i++) {
        Elf64_Dyn item;
        const char *needed;

        memcpy(&item, view->dynamic + i * sizeof(item), sizeof(item));
        if (item.d_tag == DT_NULL)
            return 0;
        if (item.d_tag != DT_NEEDED)
            continue;
        needed = symtab_view_string(view, item.d_un.d_val);
        if (!needed)
            return -1;
        if (strcmp(needed, provider) == 0)
            return 1;
    }
    return -1;
}

/* Resolve one undefined symbol's version index through an exact, bounded
 * VERNEED chain.  This associates the import with its named ABI provider;
 * the spelling alone is deliberately not a feature signal. */
static int symtab_symbol_requires_provider(
    const struct symtab_elf_view *view, uint32_t symbol_index,
    const char *required_provider)
{
    uint16_t raw_version;
    uint16_t version_index;
    uint64_t need_address;
    int matched = -1;

    if (!view || !required_provider || symbol_index >= view->dynsym_count)
        return -1;
    if (!view->have_versym || !view->versym)
        return 0;
    memcpy(&raw_version,
           view->versym + (size_t)symbol_index * sizeof(raw_version),
           sizeof(raw_version));
    version_index = raw_version & 0x7fffU;
    if (version_index <= VER_NDX_GLOBAL)
        return 0;
    if (!view->have_verneed || view->verneed_count == 0)
        return -1;

    need_address = view->verneed_address;
    for (uint64_t i = 0; i < view->verneed_count; i++) {
        const uint8_t *bytes;
        const char *provider;
        Elf64_Verneed need;
        uint64_t aux_address;
        int provider_needed;

        if (!symtab_vaddr_file(view, need_address, sizeof(need), &bytes,
                               NULL))
            return -1;
        memcpy(&need, bytes, sizeof(need));
        if (need.vn_version != VER_NEED_CURRENT || need.vn_cnt == 0 ||
            need.vn_aux < sizeof(need) || need.vn_aux % 4 != 0 ||
            ((i + 1 < view->verneed_count) != (need.vn_next != 0)) ||
            (need.vn_next != 0 &&
             (need.vn_next < sizeof(need) || need.vn_next % 4 != 0)) ||
            !u64_add_checked(need_address, need.vn_aux, &aux_address))
            return -1;
        provider = symtab_view_string(view, need.vn_file);
        if (!provider || !provider[0])
            return -1;
        provider_needed = symtab_provider_is_needed(view, provider);
        if (provider_needed <= 0)
            return -1;

        for (uint16_t j = 0; j < need.vn_cnt; j++) {
            const char *version;
            Elf64_Vernaux aux;

            if (!symtab_vaddr_file(view, aux_address, sizeof(aux), &bytes,
                                   NULL))
                return -1;
            memcpy(&aux, bytes, sizeof(aux));
            if ((aux.vna_flags & ~(VER_FLG_WEAK | 0x4U)) != 0 ||
                (aux.vna_other & 0x7fffU) <= VER_NDX_GLOBAL ||
                ((j + 1 < need.vn_cnt) != (aux.vna_next != 0)) ||
                (aux.vna_next != 0 &&
                 (aux.vna_next < sizeof(aux) || aux.vna_next % 4 != 0)))
                return -1;
            version = symtab_view_string(view, aux.vna_name);
            if (!version || !version[0] ||
                aux.vna_hash != symtab_version_name_hash(version))
                return -1;
            if ((aux.vna_other & 0x7fffU) == version_index) {
                if (matched >= 0)
                    return -1;
                matched = strcmp(provider, required_provider) == 0;
            }
            if (aux.vna_next != 0 &&
                !u64_add_checked(aux_address, aux.vna_next, &aux_address))
                return -1;
        }
        if (need.vn_next != 0 &&
            !u64_add_checked(need_address, need.vn_next, &need_address))
            return -1;
    }
    return matched;
}

/* glibc's gmon cleanup walks its hidden rtld link-map namespace directly.
 * A direct-loaded process has a dlfreeze-owned object graph instead, so an
 * object which imports either entry point of that profiling lifecycle must
 * run under the matching native interpreter.  Inspect PT_DYNAMIC-derived
 * DYNSYM data rather than section headers: valid stripped and sectionless
 * ELF inputs must reach the same feature gate.  Returns 1 when the native
 * gmon loader ABI is required, 0 when absent, and -1 for malformed input. */
static int elf_requires_native_glibc_gmon(const char *path)
{
    struct symtab_elf_view view;
    struct symtab_text_info text = {0};
    struct dlfrz_entry entry = {0};
    struct dlfrz_lib_meta meta = {0};
    struct packer_stable_file_image image = {0};
    int result = -1;

    if (!path || packer_read_stable_file(path, &image) < 0)
        return -1;
    entry.data_size = image.size;
    if (symtab_elf_view_init(image.bytes, image.size, &entry, &meta,
                             &view, &text, 1) < 0)
        goto out;

    result = 0;
    for (uint32_t i = 1; i < view.dynsym_count; i++) {
        Elf64_Sym symbol;
        const char *name;

        symtab_view_symbol(&view, i, &symbol);
        if (symbol.st_shndx != SHN_UNDEF)
            continue;
        name = view.dynstr + symbol.st_name;
        if (strcmp(name, "__monstartup") == 0 ||
            strcmp(name, "_mcleanup") == 0) {
            int provider = symtab_symbol_requires_provider(
                &view, i, "libc.so.6");

            if (provider < 0)
                goto out;
            if (provider > 0) {
                result = 1;
                break;
            }
        }
    }

out:
    packer_stable_file_image_free(&image);
    return result;
}

/*
 * append_combined_symtab - Append a combined .symtab to the frozen binary.
 *
 * After packing and pre-linking, the frozen binary's outer ELF has its
 * section headers zeroed (for UPX compat).  perf and other profiling tools
 * try to read symbols from the outer ELF and fail.  This function creates a
 * combined .symtab/.strtab from *all* embedded objects' .dynsym sections,
 * rebased to their pre-assigned load addresses, and appends it to the file
 * with proper section headers so that tools can resolve symbols.
 *
 * Layout appended to the file (all 8-byte aligned):
 *   .shstrtab  (section-name string table)
 *   .strtab    (combined symbol-name string table)
 *   .symtab    (combined Elf64_Sym array with absolute addresses)
 *   Elf64_Shdr[4]  (NULL, .shstrtab, .strtab, .symtab)
 */
static int append_combined_symtab_inplace(
    const char *path, const struct dlfrz_entry *entries,
    const struct dlfrz_lib_meta *metas, int nent,
    size_t *symbol_count_out, size_t *symbol_bytes_out)
{
    if (!path || !entries || !metas || !symbol_count_out ||
        !symbol_bytes_out || nent <= 0) {
        errno = EINVAL;
        return -1;
    }
    *symbol_count_out = 0;
    *symbol_bytes_out = 0;

    /* Keep all profiler metadata views inside the immutable transaction
     * mapping.  Both passes consume the same validated bytes, so an object
     * cannot change between sizing and emission. */
    struct symtab_text_info *text_info = NULL;
    struct symtab_elf_view *views = NULL;
    size_t *strtab_bases = NULL;
    Elf64_Sym *symtab = NULL;
    Elf32_Word *symtab_shndx = NULL;
    char *strtab = NULL;
    uint8_t *file_map = MAP_FAILED;
    size_t mapped_size = 0;
    size_t total_syms = 1;   /* slot 0 is the NULL symbol */
    size_t total_strsz = 1;  /* byte 0 is always '\0' */
    size_t sym_idx = 1;
    size_t str_off = 1;
    struct stat scan_stat;
    int scan_fd = -1;
    int scan_errno = 0;
    const int use_extended_symbol_indices =
        (size_t)nent >= (size_t)SHN_LORESERVE - 3;
    const size_t text_section_base =
        use_extended_symbol_indices ? 5 : 4;
    const size_t sh_count = text_section_base + (size_t)nent;

    text_info = calloc((size_t)nent, sizeof(*text_info));
    views = calloc((size_t)nent, sizeof(*views));
    strtab_bases = malloc((size_t)nent * sizeof(*strtab_bases));
    if (!text_info || !views || !strtab_bases)
        goto symtab_scan_fail;
    for (int e = 0; e < nent; e++)
        strtab_bases[e] = SIZE_MAX;
    scan_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (scan_fd < 0 || fstat(scan_fd, &scan_stat) < 0 ||
        !S_ISREG(scan_stat.st_mode) || scan_stat.st_size <= 0 ||
        (uintmax_t)scan_stat.st_size > SIZE_MAX) {
        if (errno == 0)
            errno = EINVAL;
        goto symtab_scan_fail;
    }
    mapped_size = (size_t)scan_stat.st_size;
    file_map = mmap(NULL, mapped_size, PROT_READ, MAP_PRIVATE, scan_fd, 0);
    if (file_map == MAP_FAILED)
        goto symtab_scan_fail;
    close(scan_fd);
    scan_fd = -1;

    /* ---- Pass 1: validate and size symbols and names. ---- */
    for (int e = 0; e < nent; e++) {
        const struct symtab_elf_view *view = &views[e];
        int has_output_symbols = 0;

        if (entries[e].flags & DLFRZ_FLAG_DATA)
            continue;
        if (symtab_elf_view_init(file_map, mapped_size, &entries[e],
                                 &metas[e], &views[e], &text_info[e], 0) < 0)
            goto symtab_scan_fail;
        for (uint32_t s = 1; s < view->dynsym_count; s++) {
            Elf64_Sym symbol;
            const char *name;

            symtab_view_symbol(view, s, &symbol);
            if (ELF64_ST_TYPE(symbol.st_info) != STT_FUNC &&
                ELF64_ST_TYPE(symbol.st_info) != STT_GNU_IFUNC &&
                ELF64_ST_TYPE(symbol.st_info) != STT_OBJECT)
                continue;
            if (symbol.st_value == 0 || symbol.st_shndx == SHN_UNDEF)
                continue;
            if (symbol.st_name >= view->dynstr_size)
                goto symtab_scan_malformed;
            name = view->dynstr + symbol.st_name;
            if (name[0] == '\0')
                continue;
            if (total_syms >= UINT32_MAX) {
                errno = EOVERFLOW;
                goto symtab_scan_fail;
            }
            total_syms++;
            has_output_symbols = 1;
        }
        if (has_output_symbols) {
            if (view->dynstr_size > (size_t)UINT32_MAX - total_strsz) {
                errno = EOVERFLOW;
                goto symtab_scan_fail;
            }
            strtab_bases[e] = total_strsz;
            total_strsz += view->dynstr_size;
        }
    }

    if (total_syms <= 1) {
        munmap(file_map, mapped_size);
        free(views);
        free(strtab_bases);
        free(text_info);
        return 0;
    }

    /* ---- Pass 2: emit from the already-validated immutable views. ---- */
    symtab = calloc(total_syms, sizeof(*symtab));
    strtab = calloc(1, total_strsz);
    if (use_extended_symbol_indices)
        symtab_shndx = calloc(total_syms, sizeof(*symtab_shndx));
    if (!symtab || !strtab ||
        (use_extended_symbol_indices && !symtab_shndx))
        goto symtab_scan_fail;

    for (int e = 0; e < nent; e++) {
        const struct symtab_elf_view *view = &views[e];
        uint64_t base = metas[e].base_addr;

        if (entries[e].flags & DLFRZ_FLAG_DATA)
            continue;
        if (strtab_bases[e] != SIZE_MAX) {
            if (str_off != strtab_bases[e] ||
                view->dynstr_size > total_strsz - str_off) {
                errno = ESTALE;
                goto symtab_scan_fail;
            }
            memcpy(strtab + str_off, view->dynstr, view->dynstr_size);
            str_off += view->dynstr_size;
        }
        for (uint32_t s = 1; s < view->dynsym_count; s++) {
            Elf64_Sym symbol;
            Elf64_Sym *out_sym;
            const char *name;
            size_t output_name;

            symtab_view_symbol(view, s, &symbol);
            if (ELF64_ST_TYPE(symbol.st_info) != STT_FUNC &&
                ELF64_ST_TYPE(symbol.st_info) != STT_GNU_IFUNC &&
                ELF64_ST_TYPE(symbol.st_info) != STT_OBJECT)
                continue;
            if (symbol.st_value == 0 || symbol.st_shndx == SHN_UNDEF)
                continue;
            if (symbol.st_name >= view->dynstr_size)
                goto symtab_scan_malformed;
            name = view->dynstr + symbol.st_name;
            if (name[0] == '\0')
                continue;
            if (strtab_bases[e] == SIZE_MAX ||
                symbol.st_name > SIZE_MAX - strtab_bases[e]) {
                errno = ESTALE;
                goto symtab_scan_fail;
            }
            output_name = strtab_bases[e] + symbol.st_name;
            if (sym_idx >= total_syms || output_name >= total_strsz ||
                output_name > UINT32_MAX) {
                errno = ESTALE;
                goto symtab_scan_fail;
            }

            out_sym = &symtab[sym_idx];
            out_sym->st_name = (uint32_t)output_name;
            out_sym->st_info = ELF64_ST_INFO(
                STB_GLOBAL, ELF64_ST_TYPE(symbol.st_info) == STT_GNU_IFUNC
                                ? STT_FUNC
                                : ELF64_ST_TYPE(symbol.st_info));
            out_sym->st_other = 0;
            if (!text_info[e].valid) {
                out_sym->st_shndx = SHN_ABS;
            } else {
                size_t section_index = text_section_base + (size_t)e;
                Elf32_Word *extended_index = symtab_shndx
                    ? &symtab_shndx[sym_idx] : NULL;

                if (!dlfrz_elf64_encode_symbol_section(
                        out_sym, extended_index, section_index)) {
                    errno = EOVERFLOW;
                    goto symtab_scan_fail;
                }
            }
            if (!u64_add_checked(base, symbol.st_value,
                                 &out_sym->st_value)) {
                errno = EOVERFLOW;
                goto symtab_scan_fail;
            }
            out_sym->st_size = symbol.st_size;

            sym_idx++;
        }
    }
    if (sym_idx != total_syms || str_off != total_strsz) {
        errno = ESTALE;
        goto symtab_scan_fail;
    }

    munmap(file_map, mapped_size);
    file_map = MAP_FAILED;
    free(views);
    views = NULL;
    free(strtab_bases);
    strtab_bases = NULL;
    goto symtab_scan_complete;

symtab_scan_malformed:
    errno = EINVAL;
symtab_scan_fail:
    scan_errno = errno ? errno : EIO;
    if (scan_fd >= 0)
        close(scan_fd);
    if (file_map != MAP_FAILED)
        munmap(file_map, mapped_size);
    free(views);
    free(strtab_bases);
    free(symtab);
    free(symtab_shndx);
    free(strtab);
    free(text_info);
    errno = scan_errno;
    return -1;

symtab_scan_complete:
    ;

    /* ---- Append to the frozen binary ---- */
    /*
     * The caller gives this function a same-directory transaction copy.
     * Every byte and metadata update is checked before that copy can be
     * committed over the output.  The footer must remain the final bytes
     * because bootstrap locates it relative to st_size.
     */
    FILE *f = NULL;
    Elf64_Shdr *shdrs = NULL;
    struct stat output_stat;
    struct dlfrz_footer saved_ft;
    Elf64_Ehdr outer_ehdr;
    const char shstrtab[] =
        "\0.shstrtab\0.strtab\0.symtab\0.symtab_shndx\0.text";
    const size_t shstrtab_sz = sizeof(shstrtab);
    size_t file_end;
    size_t write_pos;
    size_t shstrtab_off;
    size_t strtab_off_file;
    size_t symtab_off_file;
    size_t symtab_sz = 0;
    size_t symtab_shndx_off = 0;
    size_t symtab_shndx_sz = 0;
    size_t shdr_off;
    size_t shdr_sz;
    size_t footer_off = 0;
    size_t final_size = 0;
    size_t cur = 0;
    int saved_errno = 0;
    int result = -1;
    enum {
        SHNAME_SHSTRTAB = 1,
        SHNAME_STRTAB = 11,
        SHNAME_SYMTAB = 19,
        SHNAME_SYMTAB_SHNDX = 27,
        SHNAME_TEXT = 41
    };

    if (sym_idx > total_syms || str_off > total_strsz ||
        symtab_size_mul(sym_idx, sizeof(Elf64_Sym), &symtab_sz) < 0 ||
        (use_extended_symbol_indices &&
         symtab_size_mul(sym_idx, sizeof(*symtab_shndx),
                         &symtab_shndx_sz) < 0) ||
        symtab_size_mul(sh_count, sizeof(Elf64_Shdr), &shdr_sz) < 0)
        goto append_out;

    f = fopen(path, "r+b");
    if (!f)
        goto append_out;
    if (fstat(fileno(f), &output_stat) < 0 ||
        !S_ISREG(output_stat.st_mode) || output_stat.st_size < 0 ||
        (uintmax_t)output_stat.st_size > SIZE_MAX) {
        if (errno == 0)
            errno = EINVAL;
        goto append_out;
    }
    file_end = (size_t)output_stat.st_size;
    if (file_end < sizeof(saved_ft)) {
        errno = EINVAL;
        goto append_out;
    }
    write_pos = file_end - sizeof(saved_ft);
    if (symtab_stream_seek(f, write_pos) < 0 ||
        fread(&saved_ft, 1, sizeof(saved_ft), f) != sizeof(saved_ft)) {
        if (errno == 0)
            errno = EIO;
        goto append_out;
    }
    if (memcmp(saved_ft.magic, DLFRZ_MAGIC, sizeof(saved_ft.magic)) != 0 ||
        saved_ft.version != DLFRZ_VERSION) {
        errno = EINVAL;
        goto append_out;
    }
    if (symtab_stream_seek(f, 0) < 0 ||
        fread(&outer_ehdr, 1, sizeof(outer_ehdr), f) != sizeof(outer_ehdr)) {
        if (errno == 0)
            errno = EIO;
        goto append_out;
    }
    if (memcmp(outer_ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        outer_ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        outer_ehdr.e_ehsize != sizeof(outer_ehdr)) {
        errno = EINVAL;
        goto append_out;
    }

    if (symtab_size_align(write_pos, 8, &shstrtab_off) < 0 ||
        symtab_size_add(shstrtab_off, shstrtab_sz, &cur) < 0 ||
        symtab_size_align(cur, 8, &strtab_off_file) < 0 ||
        symtab_size_add(strtab_off_file, total_strsz, &cur) < 0 ||
        symtab_size_align(cur, 8, &symtab_off_file) < 0 ||
        symtab_size_add(symtab_off_file, symtab_sz, &cur) < 0 ||
        (use_extended_symbol_indices &&
         (symtab_size_align(cur, _Alignof(Elf32_Word),
                            &symtab_shndx_off) < 0 ||
          symtab_size_add(symtab_shndx_off, symtab_shndx_sz, &cur) < 0)) ||
        symtab_size_align(cur, 8, &shdr_off) < 0 ||
        symtab_size_add(shdr_off, shdr_sz, &footer_off) < 0 ||
        symtab_size_add(footer_off, sizeof(saved_ft), &final_size) < 0 ||
        (uintmax_t)final_size > (uintmax_t)INT64_MAX)
        goto append_out;

    shdrs = calloc(sh_count, sizeof(*shdrs));
    if (!shdrs ||
        !dlfrz_elf64_encode_section_count(&outer_ehdr, &shdrs[0],
                                          sh_count))
        goto append_out;

    /* [0] SHT_NULL */
    /* already zeroed */

    /* [1] .shstrtab */
    shdrs[1].sh_name   = SHNAME_SHSTRTAB;
    shdrs[1].sh_type   = SHT_STRTAB;
    shdrs[1].sh_offset = shstrtab_off;
    shdrs[1].sh_size   = shstrtab_sz;
    shdrs[1].sh_addralign = 1;

    /* [2] .strtab */
    shdrs[2].sh_name   = SHNAME_STRTAB;
    shdrs[2].sh_type   = SHT_STRTAB;
    shdrs[2].sh_offset = strtab_off_file;
    shdrs[2].sh_size   = total_strsz;
    shdrs[2].sh_addralign = 1;

    /* [3] .symtab */
    shdrs[3].sh_name    = SHNAME_SYMTAB;
    shdrs[3].sh_type    = SHT_SYMTAB;
    shdrs[3].sh_offset  = symtab_off_file;
    shdrs[3].sh_size    = symtab_sz;
    shdrs[3].sh_link    = 2;  /* .strtab */
    shdrs[3].sh_entsize = sizeof(Elf64_Sym);
    shdrs[3].sh_addralign = 8;
    /* sh_info = index of first non-local symbol (all ours are GLOBAL) */
    shdrs[3].sh_info = 1;

    if (use_extended_symbol_indices) {
        shdrs[4].sh_name = SHNAME_SYMTAB_SHNDX;
        shdrs[4].sh_type = SHT_SYMTAB_SHNDX;
        shdrs[4].sh_offset = symtab_shndx_off;
        shdrs[4].sh_size = symtab_shndx_sz;
        shdrs[4].sh_link = 3;
        shdrs[4].sh_entsize = sizeof(*symtab_shndx);
        shdrs[4].sh_addralign = _Alignof(Elf32_Word);
    }

    /* One .text section per embedded ELF follows the symbol metadata.
     * Each section's (sh_addr, sh_offset) establishes the mapping:
     *   file_offset = VA - sh_addr + sh_offset
     * which perf uses to convert symbol VAs to file offsets for lookup. */
    for (int i = 0; i < nent; i++) {
        Elf64_Shdr *sh = &shdrs[text_section_base + (size_t)i];
        sh->sh_name  = SHNAME_TEXT;
        sh->sh_type  = SHT_PROGBITS;
        sh->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        if (text_info[i].valid) {
            sh->sh_addr   = text_info[i].sh_addr;
            sh->sh_offset = text_info[i].sh_offset;
            sh->sh_size   = text_info[i].sh_size;
        }
        sh->sh_addralign = 16;
    }

    /* Write the complete append region before making the section table
     * reachable from the ELF header. */
    if (symtab_stream_seek(f, write_pos) < 0 ||
        symtab_stream_pad(f, shstrtab_off - write_pos) < 0 ||
        symtab_stream_write(f, shstrtab, shstrtab_sz) < 0 ||
        symtab_size_add(shstrtab_off, shstrtab_sz, &cur) < 0 ||
        symtab_stream_pad(f, strtab_off_file - cur) < 0 ||
        symtab_stream_write(f, strtab, total_strsz) < 0 ||
        symtab_size_add(strtab_off_file, total_strsz, &cur) < 0 ||
        symtab_stream_pad(f, symtab_off_file - cur) < 0 ||
        symtab_stream_write(f, symtab, symtab_sz) < 0 ||
        symtab_size_add(symtab_off_file, symtab_sz, &cur) < 0)
        goto append_out;
    if (use_extended_symbol_indices &&
        (symtab_stream_pad(f, symtab_shndx_off - cur) < 0 ||
         symtab_stream_write(f, symtab_shndx, symtab_shndx_sz) < 0 ||
         symtab_size_add(symtab_shndx_off, symtab_shndx_sz, &cur) < 0))
        goto append_out;
    if (
        symtab_stream_pad(f, shdr_off - cur) < 0 ||
        symtab_stream_write(f, shdrs, shdr_sz) < 0 ||
        symtab_stream_write(f, &saved_ft, sizeof(saved_ft)) < 0)
        goto append_out;

    outer_ehdr.e_shoff     = shdr_off;
    outer_ehdr.e_shentsize = sizeof(Elf64_Shdr);
    outer_ehdr.e_shstrndx  = 1;
    if (symtab_stream_seek(f, 0) < 0 ||
        symtab_stream_write(f, &outer_ehdr, sizeof(outer_ehdr)) < 0 ||
        fflush(f) != 0 ||
        ftruncate(fileno(f), (off_t)final_size) < 0 ||
        fsync(fileno(f)) < 0)
        goto append_out;

    /* NOTE: We intentionally do NOT extend the payload PT_LOAD segment.
     * The symbol/section data is only read by offline tools (readelf,
     * perf, objdump) from the file — it doesn't need to be mapped into
     * memory at runtime. */

    result = 0;

append_out:
    if (result < 0)
        saved_errno = errno ? errno : EIO;
    if (f && fclose(f) != 0 && result == 0) {
        saved_errno = errno ? errno : EIO;
        result = -1;
    }
    free(shdrs);
    free(symtab);
    free(symtab_shndx);
    free(strtab);
    free(strtab_bases);
    free(text_info);
    if (result < 0) {
        errno = saved_errno ? saved_errno : EIO;
        return -1;
    }
    *symbol_count_out = sym_idx - 1;
    if (symtab_size_add(symtab_sz, total_strsz, symbol_bytes_out) < 0 ||
        symtab_size_add(*symbol_bytes_out, symtab_shndx_sz,
                        symbol_bytes_out) < 0 ||
        symtab_size_add(*symbol_bytes_out, shstrtab_sz,
                        symbol_bytes_out) < 0)
        return -1;
    return 0;
}

static int append_combined_symtab(const char *path,
                                  const struct dlfrz_entry *entries,
                                  const struct dlfrz_lib_meta *metas,
                                  int nent)
{
    char transaction_path[PATH_MAX];
    size_t symbol_count = 0;
    size_t symbol_bytes = 0;
    int saved_errno;

    if (make_transaction_copy(path, "symtab", transaction_path) < 0) {
        saved_errno = errno ? errno : EIO;
        fprintf(stderr, "dlfreeze: cannot start symbol-table transaction: %s\n",
                strerror(saved_errno));
        errno = saved_errno;
        return -1;
    }
    if (append_combined_symtab_inplace(transaction_path, entries, metas,
                                       nent, &symbol_count,
                                       &symbol_bytes) < 0) {
        saved_errno = errno ? errno : EIO;
        unlink(transaction_path);
        errno = saved_errno;
        return -1;
    }
    if (rename(transaction_path, path) < 0) {
        saved_errno = errno ? errno : EIO;
        unlink(transaction_path);
        errno = saved_errno;
        return -1;
    }

    if (symbol_count != 0)
        printf("  symbols    : %zu entries (%zu bytes)\n",
               symbol_count, symbol_bytes);
    return 0;
}

/* ------------------------------------------------------------------ */
static int elf_defines_symbol(const char *path, const char *name)
{
    FILE *file = fopen(path, "rb");
    Elf64_Ehdr ehdr;
    uint64_t value = 0;
    int found = 0;

    if (!file)
        return 0;
    if (fread(&ehdr, 1, sizeof(ehdr), file) == sizeof(ehdr) &&
        memcmp(ehdr.e_ident, ELFMAG, SELFMAG) == 0 &&
        ehdr.e_ident[EI_CLASS] == ELFCLASS64)
        found = find_named_symbol(file, &ehdr, name, &value) > 0;
    fclose(file);
    return found;
}

/* Read the two exported private-rtld object sizes used as a validated glibc
 * layout key.  This intentionally requires a bounded on-disk DYNSYM: if the
 * interpreter does not expose enough metadata to identify a known layout,
 * the safe result is extraction mode. */
static enum dlfrz_glibc_layout_id elf_glibc_layout(const char *path,
                                                    int *minor_out)
{
    enum dlfrz_glibc_layout_id layout = DLFRZ_GLIBC_LAYOUT_UNKNOWN;
    struct dlfrz_glibc_rtld_identity identity;
    struct packer_stable_file_image image = {0};

    if (minor_out)
        *minor_out = -1;

    if (packer_read_stable_file(path, &image) < 0 ||
        image.size < sizeof(Elf64_Ehdr))
        goto out;
    if (dlfrz_glibc_is_development_release(image.bytes, image.size))
        goto out;
    if (!dlfrz_glibc_rtld_identity(image.bytes, image.size, &identity))
        goto out;
    layout = dlfrz_glibc_layout_lookup(
        identity.machine, identity.global_ro_size, identity.global_size);
    {
        int minor = dlfrz_glibc_stable_release_minor(
            image.bytes, image.size);

        if (minor < 0 ||
            !dlfrz_glibc_layout_release_is_supported(layout, minor) ||
            !dlfrz_glibc_glro_relocations_valid(
                image.bytes, image.size, layout,
                identity.global_ro_vaddr, identity.global_ro_size) ||
            (identity.machine == EM_X86_64 &&
             !dlfrz_glibc_x86_cpu_contract_valid(
                 image.bytes, image.size, layout, minor,
                 identity.global_ro_vaddr, identity.global_ro_size,
                 NULL, NULL))) {
            layout = DLFRZ_GLIBC_LAYOUT_UNKNOWN;
        } else if (minor_out) {
            *minor_out = minor;
        }
    }

out:
    packer_stable_file_image_free(&image);
    return layout;
}

static int file_glibc_release_minor(const char *path)
{
    struct packer_stable_file_image image = {0};
    int minor = -1;

    if (packer_read_stable_file(path, &image) < 0)
        goto out;
    if (!dlfrz_glibc_is_development_release(image.bytes, image.size))
        minor = dlfrz_glibc_stable_release_minor(image.bytes, image.size);

out:
    packer_stable_file_image_free(&image);
    return minor;
}

static int file_glibc_dlfcn_hook_consumer(const char *path,
                                          int hook_offset)
{
    struct packer_stable_file_image image = {0};
    int valid = 0;

    if (packer_read_stable_file(path, &image) < 0)
        goto out;
    valid = dlfrz_glibc_dlfcn_hook_consumer_valid(
        image.bytes, image.size, hook_offset, NULL);

out:
    packer_stable_file_image_free(&image);
    return valid;
}

static const struct dlfrz_musl_layout *file_musl_layout(const char *path)
{
    struct packer_stable_file_image image = {0};
    const struct dlfrz_musl_layout *layout = NULL;
    Elf64_Ehdr ehdr;

    if (packer_read_stable_file(path, &image) < 0 ||
        image.size < sizeof(Elf64_Ehdr))
        goto out;
    memcpy(&ehdr, image.bytes, sizeof(ehdr));
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) == 0 &&
        ehdr.e_ident[EI_CLASS] == ELFCLASS64 &&
        ehdr.e_ident[EI_DATA] == ELFDATA2LSB &&
        ehdr.e_ident[EI_VERSION] == EV_CURRENT &&
        ehdr.e_version == EV_CURRENT &&
        dlfrz_musl_rtld_identity(image.bytes, image.size))
        layout = dlfrz_musl_layout_lookup(ehdr.e_machine, image.bytes,
                                          image.size);

out:
    packer_stable_file_image_free(&image);
    return layout;
}

static int file_soname_matches(const char *path, const char *expected)
{
    struct elf_info info = {0};
    int matches = 0;

    if (path && expected && elf_parse(path, &info) == 0)
        matches = info.soname && strcmp(info.soname, expected) == 0;
    elf_info_free(&info);
    return matches;
}

static int direct_runtime_supported(
    const struct pack_options *opts,
    const struct packed_dep_source_plan *source_plan)
{
    const char *interp_path = opts->deps->interp_path;
    enum dlfrz_glibc_layout_id glibc_layout;
    int hook_offset;
    int interp_minor = -1;

    if (!source_plan || source_plan->aliases_main ||
        source_plan->unique_group_count >
            DLFRZ_DIRECT_MAX_OBJECTS - 1U)
        return 0;

    /* The in-process loader is bootstrap-libc-neutral after replacing the
     * thread pointer: syscall-like work uses its architecture raw layer and
     * exposed wrappers publish errno through the admitted target libc. */
    if (!interp_path)
        return 0;
    if (opts->deps->runtime_family == DEP_RUNTIME_MUSL)
        return file_musl_layout(interp_path) != NULL;
    if (opts->deps->runtime_family != DEP_RUNTIME_GNU)
        return 0;
    glibc_layout = elf_glibc_layout(interp_path, &interp_minor);
    if (glibc_layout == DLFRZ_GLIBC_LAYOUT_UNKNOWN ||
        !dlfrz_glibc_direct_thread_layout_is_supported(glibc_layout))
        return 0;
    hook_offset = dlfrz_glibc_dlfcn_hook_offset(
        glibc_layout, interp_minor);
    if (interp_minor >= 34 && hook_offset < 0)
        return 0;

    for (int i = 0; i < opts->deps->count; i++) {
        if (source_plan->group_leaders[i] != i)
            continue;
        /* Manifest lookup spelling is not provider identity: a valid
         * slash-containing DT_NEEDED retains its raw pathname.  Identify
         * glibc through the object's exact ELF DT_SONAME, consistent with
         * the runtime loader's structural libc admission. */
        if (file_soname_matches(opts->deps->libs[i].path, "libc.so.6") &&
            file_glibc_release_minor(opts->deps->libs[i].path) ==
                interp_minor &&
            (hook_offset < 0 ||
             file_glibc_dlfcn_hook_consumer(
                 opts->deps->libs[i].path, hook_offset)) &&
            elf_defines_symbol(opts->deps->libs[i].path,
                               "gnu_get_libc_version") &&
            elf_defines_symbol(opts->deps->libs[i].path,
                               "__libc_early_init"))
            return 1;
    }
    return 0;
}

static int string_table_size_add(size_t *total, const char *value,
                                 size_t extra)
{
    size_t len;

    if (!total || !value)
        return -1;
    len = strlen(value);
    if (len > SIZE_MAX - extra || *total > SIZE_MAX - (len + extra) ||
        *total + len + extra > UINT32_MAX)
        return -1;
    *total += len + extra;
    return 0;
}

static const char *packed_library_resolved_basename(
    const struct resolved_lib *lib)
{
    const char *slash = strrchr(lib->path, '/');

    return slash ? slash + 1 : lib->path;
}

/* This mirrors the manifest-name choice below.  Extraction places the
 * basename of that name in its LD_LIBRARY_PATH root, so it is also the only
 * bare request spelling extraction can reproduce without another alias. */
static int packed_library_uses_resolved_path(const struct resolved_lib *lib)
{
    return lib->from_dlopen && lib->dlopen_direct &&
           strcmp(packed_library_resolved_basename(lib), lib->name) != 0;
}

static const char *packed_library_extraction_basename(
    const struct resolved_lib *lib)
{
    return packed_library_uses_resolved_path(lib)
        ? packed_library_resolved_basename(lib) : lib->name;
}

static int packed_library_name_size_add(size_t *total,
                                        const struct resolved_lib *lib)
{
    const char *slash;
    size_t bytes;
    size_t name_len;

    if (!total || !lib || !lib->path || !lib->logical_path || !lib->name)
        return -1;
    if (lib->needed_pathful)
        return string_table_size_add(total, lib->name, 1);
    if (packed_library_uses_resolved_path(lib))
        return string_table_size_add(total, lib->path, 1);
    slash = strrchr(lib->logical_path, '/');
    if (!slash)
        return string_table_size_add(total, lib->name, 1);
    bytes = (size_t)(slash - lib->logical_path + 1);
    name_len = strlen(lib->name);
    if (bytes > SIZE_MAX - name_len - 1 ||
        *total > SIZE_MAX - (bytes + name_len + 1) ||
        *total + bytes + name_len + 1 > UINT32_MAX)
        return -1;
    *total += bytes + name_len + 1;
    return 0;
}

static int packed_library_name_matches_logical(
    const struct resolved_lib *lib)
{
    const char *slash;

    if (!lib || !lib->logical_path)
        return 0;
    if (lib->needed_pathful)
        return strcmp(lib->name, lib->logical_path) == 0;
    if (packed_library_uses_resolved_path(lib))
        return strcmp(lib->path, lib->logical_path) == 0;
    slash = strrchr(lib->logical_path, '/');
    return strcmp(slash ? slash + 1 : lib->logical_path, lib->name) == 0;
}

/* A single ELF may be both the process interpreter and a shared object.  In
 * that case its SHLIB logical identity is already represented by the INTERP
 * manifest name.  Reuse that string record rather than encoding an unrelated
 * direct-only distinction; the bootstrap can then recognize the exact
 * source/name alias without pathname heuristics or repeated string scans. */
static int packed_library_uses_interpreter_logical_name(
    const struct dep_list *deps, const struct resolved_lib *lib)
{
    return deps && lib && deps->interp_path && lib->logical_path &&
           strcmp(lib->logical_path, deps->interp_path) == 0 &&
           dep_file_snapshots_equal(&lib->snapshot,
                                    &deps->interp_snapshot);
}

int pack_frozen(const struct pack_options *opts)
{
    FILE *out = NULL;
    char transaction_path[PATH_MAX] = {0};
    struct dlfrz_entry *entries = NULL;
    struct dlfrz_entry *entries_copy = NULL;
    struct dlfrz_lib_meta *metas = NULL;
    struct packed_dep_source_plan dep_source_plan = {0};
    int *source_aliases = NULL;
    int *startup_aliases = NULL;
    const char **src_paths = NULL;
    struct packed_input_snapshot *src_snapshots = NULL;
    char *strtab = NULL;
    uint32_t interp_name_offset = 0;
    size_t off = 0;
    size_t written = 0;
    size_t bootstrap_sz = 0;
    size_t payload_off = 0;
    size_t total_sz = 0;
    int eidx_save = 0;
    int transaction_live = 0;
    int saved_errno = 0;
    int direct_supported;
    int has_pathful_needed = 0;
    int has_pathful_traced_dlopen = 0;
    int has_unreproducible_bare_dlopen = 0;

    if (!opts || !opts->deps || !opts->exe_path || !opts->output_path ||
        !opts->bootstrap_path ||
        (opts->data_files &&
         (opts->data_files->failed || opts->data_files->count < 0 ||
          (opts->data_files->count > 0 &&
           (!opts->data_files->paths || !opts->data_files->source_paths ||
            !opts->data_files->kinds))))) {
        fprintf(stderr, "dlfreeze: incomplete file manifest\n");
        return -1;
    }
    if (opts->data_files) {
        for (int i = 0; i < opts->data_files->count; i++) {
            enum data_file_kind kind = opts->data_files->kinds[i];

            if (!opts->data_files->paths[i] ||
                opts->data_files->paths[i][0] != '/' ||
                kind < DATA_FILE_KIND_REGULAR ||
                kind > DATA_FILE_KIND_DIRECTORY ||
                (kind == DATA_FILE_KIND_REGULAR &&
                 (!opts->data_files->source_paths[i] ||
                  opts->data_files->source_paths[i][0] != '/')) ||
                (kind != DATA_FILE_KIND_REGULAR &&
                 opts->data_files->source_paths[i])) {
                fprintf(stderr, "dlfreeze: incomplete captured-file entry\n");
                return -1;
            }
        }
    }
    if (packed_build_dep_source_plan(opts->deps, &dep_source_plan) < 0) {
        fprintf(stderr, "dlfreeze: incomplete dependency source manifest\n");
        return -1;
    }
    direct_supported = opts->direct_load &&
                       direct_runtime_supported(opts, &dep_source_plan);
    for (int i = 0; i < opts->deps->count; i++) {
        const struct resolved_lib *lib = &opts->deps->libs[i];

        /* A slash-containing DT_NEEDED string is an exact pathname, not a
         * soname.  Extraction flattens libraries into LD_LIBRARY_PATH and
         * cannot reproduce that identity. */
        if (lib->needed_pathful)
            has_pathful_needed = 1;
        /* The manifest retains the exact dlopen request separately from the
         * canonical source path.  Extraction cannot reproduce a request
         * containing '/', so those traced roots must remain direct-only. */
        if (lib->dlopen_direct && lib->dlopen_pathful)
            has_pathful_traced_dlopen = 1;
        if (lib->dlopen_request && !lib->dlopen_pathful &&
            strcmp(lib->dlopen_request,
                   packed_library_extraction_basename(lib)) != 0)
            has_unreproducible_bare_dlopen = 1;
    }
    if (has_pathful_needed && !direct_supported) {
        fprintf(stderr,
                "dlfreeze: pathful DT_NEEDED entries require a supported "
                "direct-load mode\n");
        packed_dep_source_plan_free(&dep_source_plan);
        return -1;
    }
    if (has_pathful_traced_dlopen && !direct_supported) {
        fprintf(stderr,
                "dlfreeze: pathful traced dlopen entries require a supported "
                "direct-load mode\n");
        packed_dep_source_plan_free(&dep_source_plan);
        return -1;
    }
    if (has_unreproducible_bare_dlopen && !direct_supported) {
        fprintf(stderr,
                "dlfreeze: bare traced dlopen aliases require a supported "
                "direct-load mode\n");
        packed_dep_source_plan_free(&dep_source_plan);
        return -1;
    }
    if (opts->data_files && opts->data_files->count > 0) {
        if (!opts->direct_load) {
            fprintf(stderr,
                    "dlfreeze: captured files require direct-load mode (-d)\n");
            packed_dep_source_plan_free(&dep_source_plan);
            return -1;
        }
        if (!direct_supported) {
            fprintf(stderr,
                    "dlfreeze: captured files require a supported direct-load "
                    "runtime\n");
            packed_dep_source_plan_free(&dep_source_plan);
            return -1;
        }
    }
    if (opts->direct_load &&
        dep_mark_dlopen_early_closures(opts->deps) < 0) {
        fprintf(stderr,
                "dlfreeze: cannot classify traced static-TLS closures\n");
        packed_dep_source_plan_free(&dep_source_plan);
        return -1;
    }

    if (validate_output_aliases(opts) < 0) {
        packed_dep_source_plan_free(&dep_source_plan);
        return -1;
    }
    if (create_output_transaction(opts->output_path, transaction_path,
                                  &out) < 0) {
        fprintf(stderr, "dlfreeze: cannot create output transaction for %s: "
                "%s\n", opts->output_path, strerror(errno));
        packed_dep_source_plan_free(&dep_source_plan);
        return -1;
    }
    transaction_live = 1;

    /* 1. bootstrap binary ------------------------------------------ */
    if (append_file(out, opts->bootstrap_path, NULL, &written, NULL) < 0)
        goto fail;
    bootstrap_sz = written;
    if (size_add_assign(&off, written) < 0)
        goto fail;

    /* total entries: main-exe + interpreter? + libs + data files */
    int ndata = opts->data_files ? opts->data_files->count : 0;
    size_t nent_size;

    if (opts->deps->count < 0 || ndata < 0 || ndata > INT_MAX - 2 ||
        opts->deps->count > INT_MAX - 2 - ndata) {
        fprintf(stderr, "dlfreeze: too many manifest entries\n");
        goto fail;
    }
    nent_size = 1U + (opts->deps->interp_path ? 1U : 0U) +
                (size_t)opts->deps->count + (size_t)ndata;
    if (nent_size > UINT32_MAX || nent_size > INT_MAX ||
        nent_size > SIZE_MAX / sizeof(struct dlfrz_entry) ||
        nent_size > SIZE_MAX / sizeof(struct dlfrz_lib_meta) ||
        nent_size > SIZE_MAX / sizeof(struct packed_input_snapshot) ||
        nent_size > SIZE_MAX / sizeof(const char *)) {
        fprintf(stderr, "dlfreeze: too many manifest entries\n");
        goto fail;
    }
    /* Parallel array of source paths for lib_meta computation */
    entries = calloc(nent_size, sizeof(*entries));
    src_paths = calloc(nent_size, sizeof(*src_paths));
    src_snapshots = calloc(nent_size, sizeof(*src_snapshots));
    if (!entries || !src_paths || !src_snapshots)
        goto fail2;

    /* build string table ------------------------------------------- */
    /* Store directory-qualified sonames (dirname(logical_path)/soname) so:
     *   - dl_basename() still matches DT_NEEDED sonames at runtime
     *   - $ORIGIN and dl_iterate_phdr retain the first loader-visible name
     * The canonical path remains the source of packaged bytes.  It must not
     * replace a symlink/hardlink spelling which owns runtime path semantics. */
    size_t strsz = 0;
    const char *main_name = opts->exe_name ? opts->exe_name : opts->exe_path;

    if (string_table_size_add(&strsz, main_name, 1) < 0 ||
        (opts->deps->interp_path &&
         string_table_size_add(&strsz, opts->deps->interp_path, 1) < 0)) {
        fprintf(stderr, "dlfreeze: manifest string table is too large\n");
        goto fail2;
    }
    for (int i = 0; i < opts->deps->count; i++) {
        if (packed_library_name_size_add(
                &strsz, &opts->deps->libs[i]) < 0 ||
            (!packed_library_name_matches_logical(&opts->deps->libs[i]) &&
             !packed_library_uses_interpreter_logical_name(
                 opts->deps, &opts->deps->libs[i]) &&
             string_table_size_add(&strsz,
                                   opts->deps->libs[i].logical_path, 1) < 0) ||
            (opts->deps->libs[i].dlopen_request &&
             string_table_size_add(&strsz,
                                   opts->deps->libs[i].dlopen_request, 1) < 0)) {
            fprintf(stderr, "dlfreeze: manifest string table is too large\n");
            goto fail2;
        }
    }
    for (int i = 0; i < ndata; i++) {
        if (!opts->data_files->paths[i] ||
            string_table_size_add(&strsz, opts->data_files->paths[i], 1) < 0) {
            fprintf(stderr, "dlfreeze: manifest string table is too large\n");
            goto fail2;
        }
    }

    strtab = calloc(1, strsz);
    if (!strtab)
        goto fail2;
    size_t stroff = 0;
    int eidx = 0;

    /* 2. main executable ------------------------------------------- */
    if (write_pad(out, &off, PAYLOAD_ALIGN) < 0)
        goto fail2;
    payload_off = off;   /* start of the payload region */
    entries[eidx].data_offset = off;
    entries[eidx].flags       = DLFRZ_FLAG_MAIN_EXE;
    entries[eidx].name_offset = stroff;
    strcpy(strtab + stroff, main_name); stroff += strlen(main_name) + 1;
    if (append_file(out, opts->exe_path, &opts->deps->main_snapshot, &written,
                    &src_snapshots[eidx]) < 0)
        goto fail2;
    entries[eidx].data_size = written;
    src_paths[eidx] = opts->exe_path;
    if (size_add_assign(&off, written) < 0)
        goto fail2;
    eidx++;

    /* 3. interpreter ----------------------------------------------- */
    if (opts->deps->interp_path) {
        if (write_pad(out, &off, PAYLOAD_ALIGN) < 0)
            goto fail2;
        entries[eidx].data_offset = off;
        entries[eidx].flags       = DLFRZ_FLAG_INTERP;
        entries[eidx].name_offset = stroff;
        interp_name_offset = (uint32_t)stroff;
        strcpy(strtab + stroff, opts->deps->interp_path); stroff += strlen(opts->deps->interp_path) + 1;
        if (append_file(out, opts->deps->interp_path,
                        &opts->deps->interp_snapshot, &written,
                        &src_snapshots[eidx]) < 0)
            goto fail2;
        entries[eidx].data_size = written;
        src_paths[eidx] = opts->deps->interp_path;
        if (size_add_assign(&off, written) < 0)
            goto fail2;
        eidx++;
    }

    /* 4. shared libraries ------------------------------------------ */
    for (int i = 0; i < opts->deps->count; i++) {
        int source_alias = dep_source_plan.manifest_aliases[i];

        entries[eidx].flags       = DLFRZ_FLAG_SHLIB;
        if (opts->deps->libs[i].from_dlopen)
            entries[eidx].flags |= DLFRZ_FLAG_DLOPEN;
        if (opts->deps->libs[i].dlopen_pathful)
            entries[eidx].flags |= DLFRZ_FLAG_DLOPEN_PATHFUL;
        if (opts->deps->libs[i].needed_pathful)
            entries[eidx].flags |= DLFRZ_FLAG_NEEDED_PATHFUL;
        entries[eidx].name_offset = stroff;
        /* Build dirname(path)/soname.  The resolved path may use a fully
         * versioned filename, but runtime DT_NEEDED matching needs the soname.
         *
         * Direct dlopen captures use the probed absolute path, not
         * DT_NEEDED-style soname lookup.  When the soname does not match
         * the file basename, the extraction fallback must preserve the
         * original full path so path-based loaders find the same file. */
        {
            const char *source_path = opts->deps->libs[i].path;
            const char *logical_path = opts->deps->libs[i].logical_path;
            const char *sname = opts->deps->libs[i].name;
            const char *last_slash = strrchr(logical_path, '/');
            if (entries[eidx].flags & DLFRZ_FLAG_NEEDED_PATHFUL) {
                /* The loader compares pathful dependencies byte-for-byte. */
                strcpy(strtab + stroff, sname);
                stroff += strlen(sname) + 1;
            } else if (packed_library_uses_resolved_path(
                           &opts->deps->libs[i])) {
                /* Use the full original path for path-based dlopen probes. */
                strcpy(strtab + stroff, source_path);
                stroff += strlen(source_path) + 1;
            } else if (last_slash) {
                size_t dirlen =
                    (size_t)(last_slash - logical_path + 1); /* include '/' */
                memcpy(strtab + stroff, logical_path, dirlen);
                strcpy(strtab + stroff + dirlen, sname);
                stroff += dirlen + strlen(sname) + 1;
            } else {
                strcpy(strtab + stroff, sname);
                stroff += strlen(sname) + 1;
            }
        }
        /* Keep dependency matching/extraction above independent from the
         * exact loader-visible name.  The latter is first-open state and may
         * legitimately have an alias basename which differs from DT_SONAME. */
        if (strcmp(strtab + entries[eidx].name_offset,
                   opts->deps->libs[i].logical_path) != 0) {
            if (packed_library_uses_interpreter_logical_name(
                    opts->deps, &opts->deps->libs[i])) {
                if (interp_name_offset == 0) {
                    fprintf(stderr,
                            "dlfreeze: missing interpreter manifest name\n");
                    goto fail2;
                }
                entries[eidx].logical_name_offset = interp_name_offset;
            } else {
                entries[eidx].logical_name_offset = (uint32_t)stroff;
                strcpy(strtab + stroff, opts->deps->libs[i].logical_path);
                stroff += strlen(opts->deps->libs[i].logical_path) + 1;
            }
        }
        if (opts->deps->libs[i].dlopen_request) {
            entries[eidx].dlopen_request_offset = (uint32_t)stroff;
            strcpy(strtab + stroff, opts->deps->libs[i].dlopen_request);
            stroff += strlen(opts->deps->libs[i].dlopen_request) + 1;
        }
        src_paths[eidx] = opts->deps->libs[i].path;
        if (source_alias >= 0) {
            if (source_alias >= eidx || !src_snapshots[source_alias].valid) {
                errno = EINVAL;
                goto fail2;
            }
            entries[eidx].data_offset = entries[source_alias].data_offset;
            entries[eidx].data_size = entries[source_alias].data_size;
            src_snapshots[eidx] = src_snapshots[source_alias];
        } else {
            if (write_pad(out, &off, PAYLOAD_ALIGN) < 0)
                goto fail2;
            entries[eidx].data_offset = off;
            if (append_file(out, src_paths[eidx],
                            &opts->deps->libs[i].snapshot, &written,
                            &src_snapshots[eidx]) < 0)
                goto fail2;
            entries[eidx].data_size = written;
            if (size_add_assign(&off, written) < 0)
                goto fail2;
        }
        eidx++;
    }

    /* 4b. data files ----------------------------------------------- */
    for (int i = 0; i < ndata; i++) {
        enum data_file_kind kind = opts->data_files->kinds
            ? opts->data_files->kinds[i] : DATA_FILE_KIND_REGULAR;

        entries[eidx].flags       = DLFRZ_FLAG_DATA;
        if (kind == DATA_FILE_KIND_VIRTUAL)
            entries[eidx].flags |= DLFRZ_FLAG_DATA_VIRTUAL;
        else if (kind == DATA_FILE_KIND_NEGATIVE)
            entries[eidx].flags |= DLFRZ_FLAG_DATA_NEGATIVE;
        else if (kind == DATA_FILE_KIND_DIRECTORY)
            entries[eidx].flags |= DLFRZ_FLAG_DATA_DIRECTORY;
        entries[eidx].name_offset = stroff;
        const char *request_path = opts->data_files->paths[i];
        const char *source_path = opts->data_files->source_paths[i];
        strcpy(strtab + stroff, request_path);
        stroff += strlen(request_path) + 1;
        if (kind != DATA_FILE_KIND_REGULAR) {
            /* Non-file entries have one canonical representation.  Keeping
             * both fields zero makes malformed aliases detectable before the
             * bootstrap or VFS derives a pointer from the manifest. */
            entries[eidx].data_offset = 0;
            written = 0;
        } else {
            if (write_pad(out, &off, 8) < 0)
                goto fail2;
            entries[eidx].data_offset = off;
            if (append_file(out, source_path, NULL, &written, NULL) < 0)
                goto fail2;
        }
        entries[eidx].data_size = written;
        src_paths[eidx] = source_path ? source_path : request_path;
        if (size_add_assign(&off, written) < 0)
            goto fail2;
        eidx++;
    }

    /* Resolution and ABI admission happened before packing.  Re-parse the
     * exact bytes just appended to the transaction so extraction artifacts
     * cannot publish a path-race replacement or a different ELF than the one
     * represented by the manifest. */
    if (fflush(out) != 0)
        goto fail2;
    for (int i = 0; i < eidx; i++) {
        if (entries[i].flags & DLFRZ_FLAG_DATA)
            continue;
        if (entries[i].data_size > SIZE_MAX) {
            errno = EOVERFLOW;
            goto fail2;
        }
        if (validate_copied_elf(
                out, src_paths[i], entries[i].data_offset,
                (size_t)entries[i].data_size,
                opts->deps->target_ei_class,
                opts->deps->target_e_machine, entries[i].flags) < 0)
            goto fail2;
    }

    /* Keep the producer on the same manifest flag contract enforced by the
     * bootstrap.  An exact dlopen request may annotate either a lazy traced
     * object or a startup-owned object which the trace opened again. */
    for (int i = 0; i < eidx; i++) {
        const char *request = NULL;
        const char *logical_name = NULL;

        if (entries[i].logical_name_offset != 0) {
            if (!(entries[i].flags & DLFRZ_FLAG_SHLIB) ||
                entries[i].logical_name_offset >= stroff) {
                fprintf(stderr,
                        "dlfreeze: inconsistent manifest logical-name offset\n");
                goto fail2;
            }
            logical_name = strtab + entries[i].logical_name_offset;
            if (!logical_name[0] ||
                !memchr(logical_name, '\0',
                        stroff - entries[i].logical_name_offset)) {
                fprintf(stderr,
                        "dlfreeze: inconsistent empty manifest logical name\n");
                goto fail2;
            }
        }

        if (entries[i].dlopen_request_offset != 0) {
            if (entries[i].dlopen_request_offset >= stroff) {
                fprintf(stderr,
                        "dlfreeze: inconsistent manifest request offset\n");
                goto fail2;
            }
            request = strtab + entries[i].dlopen_request_offset;
            if (!request[0] ||
                !memchr(request, '\0',
                        stroff - entries[i].dlopen_request_offset)) {
                fprintf(stderr,
                        "dlfreeze: inconsistent empty manifest request\n");
                goto fail2;
            }
        }
        if (!dlfrz_manifest_entry_flags_canonical(
                entries[i].flags, request != NULL,
                request && strchr(request, '/') != NULL)) {
            fprintf(stderr,
                    "dlfreeze: inconsistent manifest entry flags\n");
            goto fail2;
        }
    }

    /* 5. string table ---------------------------------------------- */
    if (write_pad(out, &off, 8) < 0)
        goto fail2;
    size_t strtab_off = off;
    if (fwrite(strtab, 1, strsz, out) != strsz) goto fail2;
    if (size_add_assign(&off, strsz) < 0)
        goto fail2;

    /* 6. manifest -------------------------------------------------- */
    if (write_pad(out, &off, 8) < 0)
        goto fail2;
    size_t manifest_off = off;
    size_t manifest_sz  = eidx * sizeof(struct dlfrz_entry);
    if (fwrite(entries, 1, manifest_sz, out) != manifest_sz) goto fail2;
    if (size_add_assign(&off, manifest_sz) < 0)
        goto fail2;

    /* 6b. loader metadata (direct-load mode) ----------------------- */
    size_t meta_off = 0;
    if (opts->direct_load && !direct_supported) {
        fprintf(stderr,
                "dlfreeze: warning: direct-load is unavailable for runtime %s; "
                "creating an extraction-mode binary\n",
                opts->deps->interp_path ? opts->deps->interp_path : "(none)");
    } else if (opts->direct_load) {
        metas = calloc(eidx, sizeof(*metas));
        source_aliases = malloc((size_t)eidx * sizeof(*source_aliases));
        startup_aliases = malloc((size_t)eidx * sizeof(*startup_aliases));
        if (!metas || !source_aliases || !startup_aliases)
            goto fail2;
        if (packed_build_alias_owners(
                entries, NULL, eidx, source_aliases, NULL) < 0)
            goto fail2;

        uint64_t base = DIRECT_LOAD_BASE;
        int first_lib = 1 + (opts->deps->interp_path ? 1 : 0);
        for (int i = 0; i < eidx; i++) {
            int gmon_status = 0;
            int meta_alias;

            if (entries[i].flags & DLFRZ_FLAG_DATA) {
                metas[i].flags = DLFRZ_FLAG_DATA; /* mark so loader can skip */
                continue;
            }
            if (validate_input_snapshot(src_paths[i], &src_snapshots[i],
                                        "before metadata parsing") < 0)
                goto fail2;
            meta_alias = source_aliases[i];
            if (meta_alias >= 0) {
                uint32_t shared_flags =
                    metas[meta_alias].flags & DLFRZ_FLAG_NEEDS_RTLD;

                /* Geometry is a property of the immutable source bytes.
                 * Lookup/lifecycle role flags remain entry-specific. */
                metas[i] = metas[meta_alias];
                metas[i].flags = entries[i].flags | shared_flags;
                metas[i].runtime_fixup_off = 0;
                metas[i].runtime_fixup_count = 0;
                metas[i]._reserved = 0;
            } else {
                if (opts->deps->runtime_family == DEP_RUNTIME_GNU &&
                    !(entries[i].flags & DLFRZ_FLAG_INTERP)) {
                    gmon_status =
                        elf_requires_native_glibc_gmon(src_paths[i]);
                    if (gmon_status < 0) {
                        /* This scan is an extraction-policy hint, not the
                         * authoritative ELF validator.  In particular, the
                         * pre-linker is allowed to decline malformed relocation
                         * metadata and publish an un-prelinked artifact whose
                         * runtime parser then rejects it transactionally.  Do
                         * not turn that existing fallback contract into a
                         * pack-time failure merely because the optional gmon
                         * feature scan cannot construct a bounded DYNSYM view. */
                        gmon_status = 0;
                    }
                }
                if (validate_input_snapshot(
                        src_paths[i], &src_snapshots[i],
                        "during profiling ABI inspection") < 0)
                    goto fail2;
                if (gmon_status > 0) {
                    fprintf(stderr,
                            "dlfreeze: warning: %s requires glibc's native gmon "
                            "loader ABI; creating an extraction-mode binary\n",
                            src_paths[i]);
                    free(metas);
                    metas = NULL;
                    break;
                }
                int meta_status = compute_lib_meta(
                    src_paths[i], &src_snapshots[i], base, entries[i].flags,
                    &metas[i]);
                int meta_errno =
                    meta_status < 0 ? (errno ? errno : EIO) : 0;
                if (validate_input_snapshot(src_paths[i], &src_snapshots[i],
                                            "during metadata parsing") < 0)
                    goto fail2;
                if (meta_status < 0) {
                    errno = meta_errno;
                    goto fail2;
                }
                if (meta_status > 0) {
                    fprintf(stderr,
                            "dlfreeze: warning: creating an extraction-mode "
                            "binary\n");
                    free(metas);
                    metas = NULL;
                    break;
                }
            }
            if (i >= first_lib && i < first_lib + opts->deps->count) {
                const struct resolved_lib *lib =
                    &opts->deps->libs[i - first_lib];

                if (lib->from_dlopen && lib->dlopen_early)
                    metas[i].flags |= DLFRZ_FLAG_DLOPEN_EARLY;
                if (lib->from_dlopen && lib->dlopen_direct)
                    metas[i].flags |= DLFRZ_FLAG_DLOPEN_ROOT;
            }
            if (metas[i].flags & DLFRZ_FLAG_DLOPEN)
                metas[i].flags &= ~DLFRZ_FLAG_RUNTIME_SCAN;
            /* Non-PIE executables (ET_EXEC) have absolute addresses
             * baked into code/data.  They must run at their original
             * link address, so set base_addr=0 (loader maps at vaddr
             * directly) and don't advance the DSO base cursor. */
            if (meta_alias >= 0) {
                /* Exact aliases share the canonical object's address. */
            } else if ((entries[i].flags & DLFRZ_FLAG_MAIN_EXE) &&
                       metas[i].base_addr == 0) {
                /* Verify the exe doesn't overlap with either the
                 * bootstrap (at 0x40000000) or its trailing guard pages. */
                if (metas[i].vaddr_hi > UINT64_MAX - 5 * PAYLOAD_ALIGN ||
                    ALIGN_UP(metas[i].vaddr_hi, PAYLOAD_ALIGN) +
                        4 * PAYLOAD_ALIGN > 0x40000000ULL) {
                    fprintf(stderr,
                            "dlfreeze: non-PIE executable VA range or guards "
                            "overlap the bootstrap; direct-load not supported\n");
                    free(metas); metas = NULL;
                    break;
                }
            } else {
                /* compute_lib_meta aligns each load bias to the largest
                 * PT_LOAD p_align required by that object. */
                base = metas[i].base_addr;
                /* Leave room for the loader's trailing guard pages even when
                 * an object's high VA is exactly on a 2 MiB boundary. */
                uint64_t step_input;
                uint64_t step;
                if (!u64_add_checked(metas[i].vaddr_hi,
                                     4 * PAYLOAD_ALIGN, &step_input) ||
                    !u64_align_up_checked(step_input, 0x200000, &step)) {
                    free(metas); metas = NULL;
                    break;
                }
                if (base > UINT64_MAX - step) {
                    free(metas); metas = NULL;
                    break;
                }
                base += step;
            }
        }

        if (metas) {
            /* Static-TLS promotion is immutable-source-wide.  First collect
             * the group state, then publish it to every dlopen identity in a
             * pair of linear passes rather than rescanning prior aliases. */
            if (packed_canonicalize_alias_metadata(
                    metas, eidx, source_aliases) < 0)
                goto fail2;
            if (packed_build_alias_owners(
                    entries, metas, eidx, NULL, startup_aliases) < 0)
                goto fail2;

            if (write_pad(out, &off, 8) < 0)
                goto fail2;
            meta_off = off;
            size_t metasz = eidx * sizeof(struct dlfrz_lib_meta);
            if (fwrite(metas, 1, metasz, out) != metasz) {
                goto fail2;
            }
            if (size_add_assign(&off, metasz) < 0)
                goto fail2;

            printf("  mode       : direct-load (in-process loader)\n");
        }
    }

    if (ndata > 0 && !metas) {
        fprintf(stderr,
                "dlfreeze: captured-file manifest has no usable direct-load "
                "metadata\n");
        goto fail2;
    }
    if (has_pathful_needed && !metas) {
        fprintf(stderr,
                "dlfreeze: pathful DT_NEEDED manifest has no usable "
                "direct-load metadata\n");
        goto fail2;
    }
    if (has_pathful_traced_dlopen && !metas) {
        fprintf(stderr,
                "dlfreeze: pathful traced dlopen manifest has no usable "
                "direct-load metadata\n");
        goto fail2;
    }
    if (has_unreproducible_bare_dlopen && !metas) {
        fprintf(stderr,
                "dlfreeze: bare traced dlopen alias has no usable "
                "direct-load metadata\n");
        goto fail2;
    }

    /* 7. footer ---------------------------------------------------- */
    struct dlfrz_footer ft;
    memset(&ft, 0, sizeof(ft));
    memcpy(ft.magic, DLFRZ_MAGIC, 8);
    ft.version         = DLFRZ_VERSION;
    ft.num_entries     = (uint32_t)eidx;
    ft.manifest_offset = manifest_off;
    ft.strtab_offset   = strtab_off;
    ft.strtab_size     = strsz;
    /* pad[0..7] = loader metadata offset (0 if not in direct-load mode) */
    if (meta_off)
        memcpy(ft.pad, &meta_off, sizeof(meta_off));
    if (fwrite(&ft, 1, sizeof(ft), out) != sizeof(ft)) goto fail2;

    /* Save entries/count for pre-linker (called after fclose) */
    eidx_save = eidx;
    if (metas) {
        entries_copy = malloc(eidx * sizeof(*entries));
        if (!entries_copy)
            goto fail2;
        memcpy(entries_copy, entries, eidx * sizeof(*entries));
    }

    if (finish_output_stream(&out) < 0) {
        fprintf(stderr, "dlfreeze: cannot finish output %s: %s\n",
                opts->output_path, strerror(errno));
        goto fail2;
    }

    /* 8. pre-link: apply relocations at freeze time ---------------- */
    if (metas) {
        printf("  pre-linking...\n");
        if (prelink_objects(transaction_path, entries_copy, metas,
                            startup_aliases, meta_off, eidx_save) == 0) {
            printf("  pre-linked : yes\n");
            for (int i = 0; i < eidx_save; i++)
                if (!(metas[i].flags & (DLFRZ_FLAG_INTERP |
                                        DLFRZ_FLAG_DLOPEN |
                                        DLFRZ_FLAG_DATA)) &&
                    startup_aliases[i] < 0)
                    metas[i].flags |= DLFRZ_FLAG_PRELINKED;
        } else {
            printf("  pre-linked : no (failed, will use runtime relocation)\n");
        }

        /* 9. append combined symbol table for profiler support ----- */
        if (append_combined_symtab(transaction_path, entries_copy, metas,
                                   eidx_save) < 0) {
            int symbol_errno = errno ? errno : EIO;

            fprintf(stderr,
                    "dlfreeze: cannot append profiler symbol table: %s\n",
                    strerror(symbol_errno));
            errno = symbol_errno;
            goto fail2;
        }
    }

    /* 10. patch ELF for UPX compatibility --------------------------
     * Must happen LAST so payload_filesz includes everything appended
     * after the footer (symtab, section headers, re-appended footer). */
    if (filesize(transaction_path, &total_sz) < 0) {
        fprintf(stderr, "dlfreeze: cannot inspect completed output: %s\n",
                strerror(errno));
        goto fail2;
    }
    if (patch_elf_for_upx(transaction_path, bootstrap_sz,
                           payload_off, total_sz) < 0) {
        int patch_errno = errno ? errno : EIO;

        fprintf(stderr, "dlfreeze: ELF patching failed: %s\n",
                strerror(patch_errno));
        errno = patch_errno;
        goto fail2;
    }
    if (sync_output_transaction(transaction_path) < 0) {
        fprintf(stderr, "dlfreeze: cannot sync completed output %s: %s\n",
                opts->output_path, strerror(errno));
        goto fail2;
    }
    if (commit_output_transaction(transaction_path, opts->output_path) < 0) {
        fprintf(stderr, "dlfreeze: cannot commit output %s: %s\n",
                opts->output_path, strerror(errno));
        goto fail2;
    }
    transaction_live = 0;

    printf("Frozen binary: %s\n", opts->output_path);
    printf("  bootstrap  : %zu bytes\n", bootstrap_sz);
    printf("  embedded   : %d files\n", eidx_save);
    printf("  total size : %zu bytes\n", total_sz);
    free(entries);
    free(entries_copy);
    free(strtab);
    free(src_paths);
    free(src_snapshots);
    free(metas);
    free(startup_aliases);
    free(source_aliases);
    packed_dep_source_plan_free(&dep_source_plan);
    return 0;

fail2:
    free(entries);
    free(entries_copy);
    free(strtab);
    free(src_paths);
    free(src_snapshots);
    free(metas);
    free(startup_aliases);
    free(source_aliases);
fail:
    packed_dep_source_plan_free(&dep_source_plan);
    saved_errno = errno ? errno : EIO;
    fprintf(stderr, "dlfreeze: packing failed\n");
    if (out && fclose(out) != 0)
        fprintf(stderr, "dlfreeze: cannot close failed transaction: %s\n",
                strerror(errno));
    if (transaction_live && unlink(transaction_path) < 0 && errno != ENOENT)
        fprintf(stderr, "dlfreeze: cannot remove failed transaction %s: %s\n",
                transaction_path, strerror(errno));
    errno = saved_errno;
    return -1;
}
