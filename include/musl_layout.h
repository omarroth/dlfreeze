#ifndef DLFREEZE_MUSL_LAYOUT_H
#define DLFREEZE_MUSL_LAYOUT_H

#include <elf.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * Direct musl startup has to construct the initial struct pthread and the
 * small public prefix of struct __libc which the dynamic linker normally
 * owns.  Those structures are private musl ABI.  Keep an explicit allowlist
 * of layouts derived from the corresponding upstream release sources; never
 * infer one layout from another or from the bootstrap libc.
 *
 * A profile is only a release-identity candidate.  It is never authority for
 * a private write: the loader derives and cross-checks every field it uses
 * from the mapped target's exported implementations before installing the
 * target thread pointer.  In particular, a matching release string alone is
 * insufficient to admit a downstream libc with a changed private layout.
 */
struct dlfrz_musl_layout {
    uint16_t machine;
    uint8_t major;
    uint8_t minor;
    uint8_t patch;

    uint16_t pthread_size;
    uint16_t tp_self_delta;
    uint16_t thread_dtv;
    uint16_t thread_prev;
    uint16_t thread_next;
    uint16_t thread_sysinfo;
    uint16_t thread_canary;
    uint16_t thread_tid;
    uint16_t thread_errno;
    uint16_t thread_detach;
    uint16_t thread_robust;
    uint16_t thread_locale;
    int8_t detach_initial;

    uint16_t libc_size;
    uint16_t libc_can_do_threads;
    uint16_t libc_threaded;
    uint16_t libc_tls_head;
    uint16_t libc_tls_size;
    uint16_t libc_tls_align;
    uint16_t libc_tls_cnt;
    uint16_t libc_global_locale;
    uint8_t libc_flag_width;
};

#define DLFRZ_MUSL_X86_12X(patch_)                                          \
    { EM_X86_64, 1, 2, patch_, 200, 0, 8, 16, 24, 32, 40, 48, 52, 56, 136,  \
      168, 2, 104, 0, 1, 16, 24, 32, 40, 56, 1 }

#define DLFRZ_MUSL_AARCH64_12X(patch_)                                      \
    { EM_AARCH64, 1, 2, patch_, 200, 200, 192, 8, 16, 24, 184, 32, 36, 40,   \
      120, 152, 2, 104, 0, 1, 16, 24, 32, 40, 56, 1 }

static const struct dlfrz_musl_layout dlfrz_musl_layouts[] = {
    DLFRZ_MUSL_X86_12X(2),
    DLFRZ_MUSL_X86_12X(3),
    DLFRZ_MUSL_X86_12X(4),
    DLFRZ_MUSL_X86_12X(5),
    DLFRZ_MUSL_X86_12X(6),
    DLFRZ_MUSL_AARCH64_12X(2),
    DLFRZ_MUSL_AARCH64_12X(3),
    DLFRZ_MUSL_AARCH64_12X(4),
    DLFRZ_MUSL_AARCH64_12X(5),
    DLFRZ_MUSL_AARCH64_12X(6),
};

static inline int dlfrz_musl_scan_word_has_byte(uintptr_t word,
                                                unsigned char byte)
{
    const uintptr_t ones = UINTPTR_MAX / UINT8_MAX;
    const uintptr_t high_bits = ones << 7;
    uintptr_t candidate = word ^ (ones * byte);

    return ((candidate - ones) & ~candidate & high_bits) != 0;
}

static inline const struct dlfrz_musl_layout *
dlfrz_musl_layout_lookup(uint16_t machine, const uint8_t *data, size_t size)
{
    struct dlfrz_musl_version_candidate {
        const struct dlfrz_musl_layout *layout;
        char version[8];
        size_t length;
        int present;
    } candidates[sizeof(dlfrz_musl_layouts) /
                 sizeof(dlfrz_musl_layouts[0])];
    static const char version_marker[] = "Version %s";
    static const char loader_marker[] = "Dynamic Program Loader";
    const char *arch_marker;
    size_t arch_marker_length;
    size_t candidate_count = 0;
    int have_arch_marker = 0;
    int have_version_marker = 0;
    int have_loader_marker = 0;
    const struct dlfrz_musl_layout *matched = NULL;

    if (!data)
        return NULL;
    if (machine == EM_X86_64)
        arch_marker = "musl libc (x86_64)";
    else if (machine == EM_AARCH64)
        arch_marker = "musl libc (aarch64)";
    else
        return NULL;
    arch_marker_length = strlen(arch_marker);

    /* Prepare the architecture's admitted release strings once.  The scan
     * below visits the image once regardless of how many release profiles
     * are admitted; adding a profile must not add another full-image pass. */
    for (size_t i = 0;
         i < sizeof(dlfrz_musl_layouts) / sizeof(dlfrz_musl_layouts[0]); i++) {
        const struct dlfrz_musl_layout *layout = &dlfrz_musl_layouts[i];
        struct dlfrz_musl_version_candidate *candidate;

        if (layout->machine != machine)
            continue;
        candidate = &candidates[candidate_count++];
        candidate->layout = layout;
        candidate->version[0] = (char)('0' + layout->major);
        candidate->version[1] = '.';
        candidate->version[2] = (char)('0' + layout->minor);
        candidate->version[3] = '.';
        if (layout->patch >= 10) {
            candidate->version[4] =
                (char)('0' + layout->patch / 10);
            candidate->version[5] =
                (char)('0' + layout->patch % 10);
            candidate->length = 6;
        } else {
            candidate->version[4] = (char)('0' + layout->patch);
            candidate->length = 5;
        }
        candidate->version[candidate->length] = '\0';
        candidate->present = 0;
    }

    for (size_t offset = 0; offset < size;) {
        size_t chunk = 1;
        size_t remaining = size - offset;

        /* Most bytes cannot begin any identity token.  Inspect a native word
         * at a time, but only when memcpy can read the whole word inside the
         * caller's range.  The byte loop still examines every position in a
         * candidate word, preserving tokens which straddle word boundaries. */
        if (remaining >= sizeof(uintptr_t)) {
            uintptr_t word;
            int candidate_word;

            memcpy(&word, data + offset, sizeof(word));
            candidate_word =
                (!have_arch_marker && dlfrz_musl_scan_word_has_byte(
                    word, (unsigned char)arch_marker[0])) ||
                (!have_version_marker && dlfrz_musl_scan_word_has_byte(
                    word, (unsigned char)version_marker[0])) ||
                (!have_loader_marker && dlfrz_musl_scan_word_has_byte(
                    word, (unsigned char)loader_marker[0]));
            for (size_t i = 0; !candidate_word && i < candidate_count; i++)
                candidate_word = !candidates[i].present &&
                    dlfrz_musl_scan_word_has_byte(
                        word, (unsigned char)candidates[i].version[0]);
            if (!candidate_word) {
                offset += sizeof(word);
                continue;
            }
            chunk = sizeof(word);
        }

        for (size_t within = 0; within < chunk; within++) {
            size_t position = offset + within;
            size_t position_remaining = size - position;
            uint8_t first = data[position];

            if (!have_arch_marker &&
                first == (uint8_t)arch_marker[0] &&
                arch_marker_length <= position_remaining &&
                memcmp(data + position, arch_marker,
                       arch_marker_length) == 0)
                have_arch_marker = 1;
            if (!have_version_marker &&
                first == (uint8_t)version_marker[0] &&
                sizeof(version_marker) - 1 <= position_remaining &&
                memcmp(data + position, version_marker,
                       sizeof(version_marker) - 1) == 0)
                have_version_marker = 1;
            if (!have_loader_marker &&
                first == (uint8_t)loader_marker[0] &&
                sizeof(loader_marker) - 1 <= position_remaining &&
                memcmp(data + position, loader_marker,
                       sizeof(loader_marker) - 1) == 0)
                have_loader_marker = 1;

            /* The release identifier is a standalone NUL-terminated object.
             * More than one admitted release identity is ambiguous and must
             * not select whichever profile happens to appear first.  Test
             * release candidates only at possible C-string starts; repeated
             * copies of the same release remain one identity, matching the
             * old presence predicate. */
            if (position != 0 && data[position - 1] != '\0')
                continue;
            for (size_t i = 0; i < candidate_count; i++) {
                struct dlfrz_musl_version_candidate *candidate =
                    &candidates[i];

                if (candidate->present ||
                    first != (uint8_t)candidate->version[0] ||
                    candidate->length >= position_remaining ||
                    data[position + candidate->length] != '\0' ||
                    memcmp(data + position, candidate->version,
                           candidate->length) != 0)
                    continue;
                candidate->present = 1;
            }
        }
        offset += chunk;
    }

    if (!have_arch_marker || !have_version_marker || !have_loader_marker)
        return NULL;
    for (size_t i = 0; i < candidate_count; i++) {
        if (!candidates[i].present)
            continue;
        if (matched)
            return NULL;
        matched = candidates[i].layout;
    }
    return matched;
}

#undef DLFRZ_MUSL_X86_12X
#undef DLFRZ_MUSL_AARCH64_12X

#endif
