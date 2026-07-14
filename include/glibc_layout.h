#ifndef DLFREEZE_GLIBC_LAYOUT_H
#define DLFREEZE_GLIBC_LAYOUT_H

#include <elf.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define DLFRZ_GLIBC_DEVELOPMENT_MARKER "development release version"

/*
 * glibc's _rtld_global and _rtld_global_ro are private implementation
 * details.  Their total sizes are only admission keys for layouts whose
 * individual field offsets have been validated; they are not sufficient
 * data from which to derive a new layout.
 *
 * Keep this as the single list shared by the packer and direct loader.  The
 * packer uses it to decide whether direct metadata may be emitted, while the
 * loader maps each id to its validated offset profile.
 */
#define DLFRZ_GLIBC_LAYOUT_KEYS(X)                                            \
    X(DLFRZ_GLIBC_X86_2_17,          EM_X86_64,   440, 3960)                 \
    X(DLFRZ_GLIBC_AARCH64_2_27,      EM_AARCH64,  520, 4088)                 \
    X(DLFRZ_GLIBC_X86_2_29,          EM_X86_64,   536, 3992)                 \
    X(DLFRZ_GLIBC_X86_2_31_DEBIAN,   EM_X86_64,   544, 4000)                 \
    X(DLFRZ_GLIBC_AARCH64_2_31,      EM_AARCH64,  624, 4152)                 \
    X(DLFRZ_GLIBC_AARCH64_2_35_LARGE, EM_AARCH64, 704, 4488)                 \
    X(DLFRZ_GLIBC_AARCH64_2_36_DEBIAN, EM_AARCH64, 672, 4520)                \
    X(DLFRZ_GLIBC_AARCH64_2_35,      EM_AARCH64,  688, 4504)                 \
    X(DLFRZ_GLIBC_AARCH64_2_43,      EM_AARCH64,  400, 2272)                 \
    X(DLFRZ_GLIBC_AARCH64_2_40_LEGACY, EM_AARCH64, 704, 4504)                \
    X(DLFRZ_GLIBC_AARCH64_2_41,      EM_AARCH64,  704, 3040)                 \
    X(DLFRZ_GLIBC_X86_2_36_DEBIAN,   EM_X86_64,   896, 4336)                 \
    X(DLFRZ_GLIBC_X86_2_34,          EM_X86_64,   928, 4304)                 \
    X(DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY, EM_X86_64, 952, 4352)            \
    X(DLFRZ_GLIBC_X86_2_40,          EM_X86_64,   928, 2120)                 \
    X(DLFRZ_GLIBC_X86_2_41_DEBIAN,   EM_X86_64,   952, 2888)

enum dlfrz_glibc_layout_id {
    DLFRZ_GLIBC_LAYOUT_UNKNOWN = 0,
#define DLFRZ_GLIBC_LAYOUT_ENUM(id, machine, glro_size, gl_size) id,
    DLFRZ_GLIBC_LAYOUT_KEYS(DLFRZ_GLIBC_LAYOUT_ENUM)
#undef DLFRZ_GLIBC_LAYOUT_ENUM
};

struct dlfrz_glibc_layout_key {
    enum dlfrz_glibc_layout_id id;
    uint16_t machine;
    uint64_t glro_size;
    uint64_t gl_size;
};

static inline enum dlfrz_glibc_layout_id
dlfrz_glibc_layout_lookup(uint16_t machine, uint64_t glro_size,
                          uint64_t gl_size)
{
    static const struct dlfrz_glibc_layout_key keys[] = {
#define DLFRZ_GLIBC_LAYOUT_ROW(id, arch, ro, global) \
        { id, arch, ro, global },
        DLFRZ_GLIBC_LAYOUT_KEYS(DLFRZ_GLIBC_LAYOUT_ROW)
#undef DLFRZ_GLIBC_LAYOUT_ROW
    };

    for (unsigned int i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        if (keys[i].machine == machine &&
            keys[i].glro_size == glro_size &&
            keys[i].gl_size == gl_size)
            return keys[i].id;
    }
    return DLFRZ_GLIBC_LAYOUT_UNKNOWN;
}

/* glibc development snapshots can retain a stable release's size tuple while
 * changing code that consumes private rtld fields.  Reject both the explicit
 * development marker and the snapshot release form (for example 2.43.9000).
 * The latter keeps the check fail-closed if a downstream build edits the
 * prose but preserves the release number. */
static inline int
dlfrz_glibc_is_development_release(const void *data, size_t size)
{
    static const char marker[] = DLFRZ_GLIBC_DEVELOPMENT_MARKER;
    static const char release[] = "release version ";
    const unsigned char *bytes = (const unsigned char *)data;

    if (!data)
        return 0;
    if (size >= sizeof(marker) - 1) {
        for (size_t i = 0; i <= size - (sizeof(marker) - 1); i++) {
            if (memcmp(bytes + i, marker, sizeof(marker) - 1) == 0)
                return 1;
        }
    }
    if (size <= sizeof(release) - 1)
        return 0;
    for (size_t i = 0; i < size - (sizeof(release) - 1); i++) {
        size_t p;

        if (memcmp(bytes + i, release, sizeof(release) - 1) != 0)
            continue;
        p = i + sizeof(release) - 1;
        while (p < size && bytes[p] >= '0' && bytes[p] <= '9')
            p++;
        if (p >= size || bytes[p++] != '.')
            continue;
        while (p < size && bytes[p] >= '0' && bytes[p] <= '9')
            p++;
        if (p + 1 < size && bytes[p] == '.' &&
            bytes[p + 1] >= '0' && bytes[p + 1] <= '9')
            return 1;
    }
    return 0;
}

/* Return the minor from glibc's canonical stable-release banner.  Private
 * rtld layouts must not be selected from the largest GLIBC_2.* symbol
 * version: that is an ABI floor, not a positive runtime identity. */
static inline int
dlfrz_glibc_stable_release_minor(const void *data, size_t size)
{
    static const char prefix[] = "stable release version 2.";
    const unsigned char *bytes = (const unsigned char *)data;
    int found = -1;

    if (!data || size < sizeof(prefix))
        return -1;
    for (size_t i = 0; i <= size - (sizeof(prefix) - 1); i++) {
        size_t p;
        int minor = 0;
        int digits = 0;

        if (memcmp(bytes + i, prefix, sizeof(prefix) - 1) != 0)
            continue;
        p = i + sizeof(prefix) - 1;
        while (p < size && bytes[p] >= '0' && bytes[p] <= '9') {
            if (minor > 1000)
                return -1;
            minor = minor * 10 + (int)(bytes[p] - '0');
            digits++;
            p++;
        }
        if (!digits)
            return -1;
        if (found >= 0 && found != minor)
            return -1;
        found = minor;
    }
    return found;
}

/* Size tuples can be retained or reused after private fields move.  Admit
 * only releases for which the corresponding field profile was validated;
 * the explicitly ambiguous x86-64 tuple is split by its stable release. */
static inline int
dlfrz_glibc_layout_release_is_supported(enum dlfrz_glibc_layout_id layout,
                                         int minor)
{
    switch (layout) {
    case DLFRZ_GLIBC_X86_2_17:
        return minor >= 17 && minor <= 28;
    case DLFRZ_GLIBC_AARCH64_2_27:
        return minor == 27;
    case DLFRZ_GLIBC_X86_2_29:
        return minor >= 29 && minor <= 33;
    case DLFRZ_GLIBC_X86_2_31_DEBIAN:
    case DLFRZ_GLIBC_AARCH64_2_31:
        return minor == 31;
    case DLFRZ_GLIBC_AARCH64_2_35_LARGE:
        return minor == 35;
    case DLFRZ_GLIBC_AARCH64_2_36_DEBIAN:
        return minor == 36;
    case DLFRZ_GLIBC_AARCH64_2_35:
        return minor >= 36 && minor <= 39;
    case DLFRZ_GLIBC_AARCH64_2_43:
        return minor == 43;
    case DLFRZ_GLIBC_AARCH64_2_40_LEGACY:
        return minor == 40;
    case DLFRZ_GLIBC_AARCH64_2_41:
        return minor == 41;
    case DLFRZ_GLIBC_X86_2_36_DEBIAN:
        return minor == 36;
    case DLFRZ_GLIBC_X86_2_34:
        return minor >= 34 && minor <= 36;
    case DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY:
        return (minor >= 37 && minor <= 39) || minor == 40;
    case DLFRZ_GLIBC_X86_2_40:
        return minor >= 40 && minor <= 43;
    case DLFRZ_GLIBC_X86_2_41_DEBIAN:
        return minor == 41;
    case DLFRZ_GLIBC_LAYOUT_UNKNOWN:
        return 0;
    }
    return 0;
}

#endif /* DLFREEZE_GLIBC_LAYOUT_H */
