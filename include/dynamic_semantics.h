#ifndef DLFREEZE_DYNAMIC_SEMANTICS_H
#define DLFREEZE_DYNAMIC_SEMANTICS_H

#include <stdint.h>

/* Keep these spellings independent of the host libc's elf.h.  Several are
 * absent from older glibc and musl headers even though they are part of ELF
 * ABIs that can appear in an input object. */
#define DLFRZ_DT_SYMTAB_SHNDX   UINT64_C(34)
#define DLFRZ_DT_ANDROID_REL    UINT64_C(0x6000000f)
#define DLFRZ_DT_ANDROID_RELSZ  UINT64_C(0x60000010)
#define DLFRZ_DT_ANDROID_RELA   UINT64_C(0x60000011)
#define DLFRZ_DT_ANDROID_RELASZ UINT64_C(0x60000012)
#define DLFRZ_DT_ANDROID_RELR   UINT64_C(0x6fffe000)
#define DLFRZ_DT_ANDROID_RELRSZ UINT64_C(0x6fffe001)
#define DLFRZ_DT_ANDROID_RELRENT UINT64_C(0x6fffe003)
#define DLFRZ_DT_GNU_PRELINKED  UINT64_C(0x6ffffdf5)
#define DLFRZ_DT_GNU_CONFLICTSZ UINT64_C(0x6ffffdf6)
#define DLFRZ_DT_GNU_LIBLISTSZ  UINT64_C(0x6ffffdf7)
#define DLFRZ_DT_PLTPADSZ       UINT64_C(0x6ffffdf9)
#define DLFRZ_DT_MOVEENT        UINT64_C(0x6ffffdfa)
#define DLFRZ_DT_MOVESZ         UINT64_C(0x6ffffdfb)
#define DLFRZ_DT_FEATURE_1      UINT64_C(0x6ffffdfc)
#define DLFRZ_DT_POSFLAG_1      UINT64_C(0x6ffffdfd)
#define DLFRZ_DT_SYMINSZ        UINT64_C(0x6ffffdfe)
#define DLFRZ_DT_SYMINENT       UINT64_C(0x6ffffdff)
#define DLFRZ_DT_CONFIG         UINT64_C(0x6ffffefa)
#define DLFRZ_DT_GNU_CONFLICT   UINT64_C(0x6ffffef8)
#define DLFRZ_DT_GNU_LIBLIST    UINT64_C(0x6ffffef9)
#define DLFRZ_DT_PLTPAD         UINT64_C(0x6ffffefd)
#define DLFRZ_DT_MOVETAB        UINT64_C(0x6ffffefe)
#define DLFRZ_DT_SYMINFO        UINT64_C(0x6ffffeff)
#define DLFRZ_DT_RELCOUNT       UINT64_C(0x6ffffffa)

/* AArch64 processor-specific dynamic tags.  Keep these scoped to AArch64 in
 * the classifier below: DT_LOPROC + 1 and + 3 are valid x86-64 PLT metadata
 * with different meanings.  DT_AARCH64_PAC_PLT requires each JUMP_SLOT
 * result to be signed at load time with the process's APIA key and the GOT
 * slot address as modifier.  The authenticated-symbol/RELR tags likewise
 * request relocation semantics which direct replay does not implement.
 * MemtagABI tags require process, stack/heap, mapping, global-tagging, and
 * relocation transitions; notably MEMTAG_MODE value zero requests
 * synchronous MTE and is not an inert payload. */
#define DLFRZ_DT_AARCH64_BTI_PLT      UINT64_C(0x70000001)
#define DLFRZ_DT_AARCH64_PAC_PLT      UINT64_C(0x70000003)
#define DLFRZ_DT_AARCH64_VARIANT_PCS  UINT64_C(0x70000005)
#define DLFRZ_DT_AARCH64_AUTH_SYM     UINT64_C(0x70000008)
#define DLFRZ_DT_AARCH64_MEMTAG_MODE  UINT64_C(0x70000009)
#define DLFRZ_DT_AARCH64_MEMTAG_HEAP  UINT64_C(0x7000000b)
#define DLFRZ_DT_AARCH64_MEMTAG_STACK UINT64_C(0x7000000c)
#define DLFRZ_DT_AARCH64_MEMTAG_GLOBALS UINT64_C(0x7000000d)
#define DLFRZ_DT_AARCH64_MEMTAG_GLOBALSSZ UINT64_C(0x7000000f)
#define DLFRZ_DT_AARCH64_AUTH_RELRSZ  UINT64_C(0x70000011)
#define DLFRZ_DT_AARCH64_AUTH_RELR    UINT64_C(0x70000012)
#define DLFRZ_DT_AARCH64_AUTH_RELRENT UINT64_C(0x70000013)

/* DT_FLAGS/DT_FLAGS_1 values used by the direct-loader admission contract.
 * Keep private spellings here as well: the bootstrap, packer, and trace
 * interposer can be built against different libc header versions. */
#define DLFRZ_DF_ORIGIN       UINT64_C(0x00000001)
#define DLFRZ_DF_SYMBOLIC     UINT64_C(0x00000002)
#define DLFRZ_DF_BIND_NOW     UINT64_C(0x00000008)
#define DLFRZ_DF_STATIC_TLS   UINT64_C(0x00000010)

#define DLFRZ_DF_1_NOW        UINT64_C(0x00000001)
#define DLFRZ_DF_1_NODELETE   UINT64_C(0x00000008)
#define DLFRZ_DF_1_NOOPEN     UINT64_C(0x00000040)
#define DLFRZ_DF_1_ORIGIN     UINT64_C(0x00000080)
#define DLFRZ_DF_1_NODEFLIB   UINT64_C(0x00000800)
#define DLFRZ_DF_1_NODUMP     UINT64_C(0x00001000)
#define DLFRZ_DF_1_NODIRECT   UINT64_C(0x00020000)
#define DLFRZ_DF_1_PIE        UINT64_C(0x08000000)

/* Admit only policies implemented by direct replay.  DF_1_NOOPEN is an
 * object-use restriction, not a prohibition on loading the object as part of
 * the startup dependency graph, so it belongs in the supported set here.
 * The operation-specific helper below rejects it for a later dlopen. */
static inline int dlfrz_dynamic_flags_are_supported(
    uint64_t flags, uint64_t flags_1, int is_main_executable)
{
    const uint64_t flags_allowed =
        DLFRZ_DF_ORIGIN | DLFRZ_DF_SYMBOLIC | DLFRZ_DF_BIND_NOW |
        DLFRZ_DF_STATIC_TLS;
    const uint64_t flags_1_allowed =
        DLFRZ_DF_1_NOW | DLFRZ_DF_1_NODELETE | DLFRZ_DF_1_NOOPEN |
        DLFRZ_DF_1_ORIGIN | DLFRZ_DF_1_NODEFLIB |
        DLFRZ_DF_1_NODUMP | DLFRZ_DF_1_NODIRECT | DLFRZ_DF_1_PIE;

    return (flags & ~flags_allowed) == 0 &&
           (flags_1 & ~flags_1_allowed) == 0 &&
           ((flags_1 & DLFRZ_DF_1_PIE) == 0 || is_main_executable);
}

static inline int dlfrz_dynamic_flags_allow_dlopen(uint64_t flags_1)
{
    return (flags_1 & (DLFRZ_DF_1_NOOPEN | DLFRZ_DF_1_PIE)) == 0;
}

/* Linux dlopen mode values are part of the target ABI, even when the libc
 * used to build the static bootstrap omits a GNU spelling such as
 * RTLD_DEEPBIND.  Keep trace-time admission and direct replay on one exact
 * contract so tracing cannot publish an artifact whose successful native
 * dlopen is guaranteed to be rejected later.  RTLD_LOCAL is zero. */
#define DLFRZ_RTLD_LAZY       UINT32_C(0x00001)
#define DLFRZ_RTLD_NOW        UINT32_C(0x00002)
#define DLFRZ_RTLD_NOLOAD     UINT32_C(0x00004)
#define DLFRZ_RTLD_DEEPBIND   UINT32_C(0x00008)
#define DLFRZ_RTLD_GLOBAL     UINT32_C(0x00100)
#define DLFRZ_RTLD_NODELETE   UINT32_C(0x01000)

static inline int dlfrz_dlopen_mode_is_supported(int flags)
{
    const uint32_t value = (uint32_t)flags;
    const uint32_t binding = value &
        (DLFRZ_RTLD_LAZY | DLFRZ_RTLD_NOW);
    const uint32_t known = DLFRZ_RTLD_LAZY | DLFRZ_RTLD_NOW |
        DLFRZ_RTLD_NOLOAD | DLFRZ_RTLD_GLOBAL | DLFRZ_RTLD_NODELETE;

    return binding != 0 && (value & DLFRZ_RTLD_DEEPBIND) == 0 &&
           (value & ~known) == 0;
}

/* RTLD_NOW takes precedence when both binding bits are present.  A remaining
 * pure-LAZY request needs a PLT resolver if it introduces a new object on a
 * GNU runtime; musl deliberately implements both public modes eagerly. */
static inline int dlfrz_dlopen_mode_requires_lazy_binding(int flags)
{
    const uint32_t value = (uint32_t)flags;

    return (value & DLFRZ_RTLD_LAZY) != 0 &&
           (value & DLFRZ_RTLD_NOW) == 0;
}

/* These tags request relocation formats, symbol-index extensions, or
 * loader policies that direct mode does not implement.  A zero-valued entry
 * is inert and remains admissible; unknown tags are deliberately not rejected
 * here because OS/vendor namespaces also contain advisory metadata. */
static inline int dlfrz_dynamic_tag_requires_unsupported_semantics(
    int64_t tag, uint64_t value)
{
#if defined(__aarch64__)
    /* These are presence tags/tables.  In particular, GNU ld emits
     * DT_AARCH64_PAC_PLT with a zero d_val, and MEMTAG_MODE value zero means
     * synchronous MTE.  Both still require loader transitions. */
    switch ((uint64_t)tag) {
    case DLFRZ_DT_AARCH64_PAC_PLT:
    case DLFRZ_DT_AARCH64_AUTH_SYM:
    case DLFRZ_DT_AARCH64_MEMTAG_MODE:
    case DLFRZ_DT_AARCH64_MEMTAG_HEAP:
    case DLFRZ_DT_AARCH64_MEMTAG_STACK:
    case DLFRZ_DT_AARCH64_MEMTAG_GLOBALS:
    case DLFRZ_DT_AARCH64_MEMTAG_GLOBALSSZ:
    case DLFRZ_DT_AARCH64_AUTH_RELRSZ:
    case DLFRZ_DT_AARCH64_AUTH_RELR:
    case DLFRZ_DT_AARCH64_AUTH_RELRENT:
        return 1;
    default:
        break;
    }
#endif

    if (value == 0)
        return 0;

    switch ((uint64_t)tag) {
    case DLFRZ_DT_SYMTAB_SHNDX:
    case DLFRZ_DT_ANDROID_REL:
    case DLFRZ_DT_ANDROID_RELSZ:
    case DLFRZ_DT_ANDROID_RELA:
    case DLFRZ_DT_ANDROID_RELASZ:
    case DLFRZ_DT_ANDROID_RELR:
    case DLFRZ_DT_ANDROID_RELRSZ:
    case DLFRZ_DT_ANDROID_RELRENT:
    case DLFRZ_DT_GNU_PRELINKED:
    case DLFRZ_DT_GNU_CONFLICTSZ:
    case DLFRZ_DT_GNU_LIBLISTSZ:
    case DLFRZ_DT_PLTPADSZ:
    case DLFRZ_DT_MOVEENT:
    case DLFRZ_DT_MOVESZ:
    case DLFRZ_DT_FEATURE_1:
    case DLFRZ_DT_POSFLAG_1:
    case DLFRZ_DT_SYMINSZ:
    case DLFRZ_DT_SYMINENT:
    case DLFRZ_DT_CONFIG:
    case DLFRZ_DT_GNU_CONFLICT:
    case DLFRZ_DT_GNU_LIBLIST:
    case DLFRZ_DT_PLTPAD:
    case DLFRZ_DT_MOVETAB:
    case DLFRZ_DT_SYMINFO:
    case DLFRZ_DT_RELCOUNT:
        return 1;
    default:
        return 0;
    }
}

#endif /* DLFREEZE_DYNAMIC_SEMANTICS_H */
