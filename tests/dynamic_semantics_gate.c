#include "dynamic_semantics.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

int main(void)
{
    static const uint64_t unsupported[] = {
        DLFRZ_DT_SYMTAB_SHNDX,
        DLFRZ_DT_ANDROID_REL,
        DLFRZ_DT_ANDROID_RELSZ,
        DLFRZ_DT_ANDROID_RELA,
        DLFRZ_DT_ANDROID_RELASZ,
        DLFRZ_DT_ANDROID_RELR,
        DLFRZ_DT_ANDROID_RELRSZ,
        DLFRZ_DT_ANDROID_RELRENT,
        DLFRZ_DT_GNU_PRELINKED,
        DLFRZ_DT_GNU_CONFLICTSZ,
        DLFRZ_DT_GNU_LIBLISTSZ,
        DLFRZ_DT_PLTPADSZ,
        DLFRZ_DT_MOVEENT,
        DLFRZ_DT_MOVESZ,
        DLFRZ_DT_FEATURE_1,
        DLFRZ_DT_POSFLAG_1,
        DLFRZ_DT_SYMINSZ,
        DLFRZ_DT_SYMINENT,
        DLFRZ_DT_CONFIG,
        DLFRZ_DT_GNU_CONFLICT,
        DLFRZ_DT_GNU_LIBLIST,
        DLFRZ_DT_PLTPAD,
        DLFRZ_DT_MOVETAB,
        DLFRZ_DT_SYMINFO,
        DLFRZ_DT_RELCOUNT,
    };
    /* Standard eager-loader hints, standard RELR, and metadata that carries
     * no unimplemented runtime behavior remain admissible.  Unknown tags are
     * tested implicitly by the helper's default branch. */
    static const uint64_t harmless[] = {
        UINT64_C(0),          /* DT_NULL */
        UINT64_C(21),         /* DT_DEBUG */
        UINT64_C(24),         /* DT_BIND_NOW */
        UINT64_C(35),         /* DT_RELRSZ */
        UINT64_C(36),         /* DT_RELR */
        UINT64_C(37),         /* DT_RELRENT */
        UINT64_C(0x6ffffdf8), /* DT_CHECKSUM */
        UINT64_C(0x6ffffef6), /* DT_TLSDESC_PLT */
        UINT64_C(0x6ffffef7), /* DT_TLSDESC_GOT */
        UINT64_C(0x6abc1234), /* Unassigned OS/vendor tag */
    };

    for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++) {
        if (!dlfrz_dynamic_tag_requires_unsupported_semantics(
                (int64_t)unsupported[i], 1) ||
            dlfrz_dynamic_tag_requires_unsupported_semantics(
                (int64_t)unsupported[i], 0)) {
            fprintf(stderr, "bad unsupported-tag classification: 0x%llx\n",
                    (unsigned long long)unsupported[i]);
            return 1;
        }
    }
    for (size_t i = 0; i < sizeof(harmless) / sizeof(harmless[0]); i++) {
        if (dlfrz_dynamic_tag_requires_unsupported_semantics(
                (int64_t)harmless[i], UINT64_MAX)) {
            fprintf(stderr, "bad harmless-tag classification: 0x%llx\n",
                    (unsigned long long)harmless[i]);
            return 1;
        }
    }
    return 0;
}
