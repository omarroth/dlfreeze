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
 * A profile is only an admission candidate.  The loader additionally decodes
 * independent target implementations (__errno_location, __tls_get_addr,
 * pthread_self, pthread_kill, pthread_detach and pthread_create) and requires
 * every decoded offset/address to agree with the selected profile.
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
    uint8_t canary_zero_second_byte;

    uint16_t libc_size;
    uint16_t libc_can_do_threads;
    uint16_t libc_threaded;
    uint16_t libc_secure;
    uint16_t libc_threads_minus_1;
    uint16_t libc_auxv;
    uint16_t libc_tls_head;
    uint16_t libc_tls_size;
    uint16_t libc_tls_align;
    uint16_t libc_tls_cnt;
    uint16_t libc_page_size;
    uint16_t libc_global_locale;
    uint8_t libc_flag_width;
};

#define DLFRZ_MUSL_X86_119                                                   \
    { EM_X86_64, 1, 1, 19, 280, 0, 8, 16, 24, 32, 40, 56, 68, 84, 168, 200, \
      0, 0, 112, 0, 4, 8, 12, 16, 24, 32, 40, 48, 56, 64, 4 }

#define DLFRZ_MUSL_X86_124                                                   \
    { EM_X86_64, 1, 1, 24, 224, 0, 8, 16, 24, 32, 40, 56, 60, 64, 144, 176, \
      2, 0, 112, 0, 4, 8, 12, 16, 24, 32, 40, 48, 56, 64, 4 }

#define DLFRZ_MUSL_X86_12X(patch_)                                          \
    { EM_X86_64, 1, 2, patch_, 200, 0, 8, 16, 24, 32, 40, 48, 52, 56, 136,  \
      168, 2, 1, 104, 0, 1, 2, 4, 8, 16, 24, 32, 40, 48, 56, 1 }

#define DLFRZ_MUSL_AARCH64_12X(patch_)                                      \
    { EM_AARCH64, 1, 2, patch_, 200, 200, 192, 8, 16, 24, 184, 32, 36, 40,   \
      120, 152, 2, 1, 104, 0, 1, 2, 4, 8, 16, 24, 32, 40, 48, 56, 1 }

static const struct dlfrz_musl_layout dlfrz_musl_layouts[] = {
    DLFRZ_MUSL_X86_119,
    DLFRZ_MUSL_X86_124,
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

static inline int dlfrz_musl_has_bytes(const uint8_t *data, size_t size,
                                       const char *needle, size_t len)
{
    if (!data || !needle || len == 0 || len > size)
        return 0;
    for (size_t i = 0; i <= size - len; i++)
        if (memcmp(data + i, needle, len) == 0)
            return 1;
    return 0;
}

static inline int dlfrz_musl_has_cstring(const uint8_t *data, size_t size,
                                         const char *value, size_t len)
{
    if (!data || !value || len == 0 || len >= size)
        return 0;
    for (size_t i = 0; i <= size - (len + 1); i++) {
        if (i != 0 && data[i - 1] != '\0')
            continue;
        if (memcmp(data + i, value, len) == 0 && data[i + len] == '\0')
            return 1;
    }
    return 0;
}

static inline const struct dlfrz_musl_layout *
dlfrz_musl_layout_lookup(uint16_t machine, const uint8_t *data, size_t size)
{
    const char *arch_marker;
    const struct dlfrz_musl_layout *matched = NULL;

    if (machine == EM_X86_64)
        arch_marker = "musl libc (x86_64)";
    else if (machine == EM_AARCH64)
        arch_marker = "musl libc (aarch64)";
    else
        return NULL;

    if (!dlfrz_musl_has_bytes(data, size, arch_marker, strlen(arch_marker)) ||
        !dlfrz_musl_has_bytes(data, size, "Version %s", 10) ||
        !dlfrz_musl_has_bytes(data, size, "Dynamic Program Loader", 22))
        return NULL;

    for (size_t i = 0;
         i < sizeof(dlfrz_musl_layouts) / sizeof(dlfrz_musl_layouts[0]); i++) {
        const struct dlfrz_musl_layout *layout = &dlfrz_musl_layouts[i];
        char version[8];
        int len;

        if (layout->machine != machine)
            continue;
        version[0] = (char)('0' + layout->major);
        version[1] = '.';
        version[2] = (char)('0' + layout->minor);
        version[3] = '.';
        if (layout->patch >= 10) {
            version[4] = (char)('0' + layout->patch / 10);
            version[5] = (char)('0' + layout->patch % 10);
            len = 6;
        } else {
            version[4] = (char)('0' + layout->patch);
            len = 5;
        }
        version[len] = '\0';
        /* The release identifier is a standalone NUL-terminated object.
         * More than one admitted release identity is ambiguous and must not
         * select whichever profile happens to appear first. */
        if (dlfrz_musl_has_cstring(data, size, version, (size_t)len)) {
            if (matched)
                return NULL;
            matched = layout;
        }
    }
    return matched;
}

#undef DLFRZ_MUSL_X86_119
#undef DLFRZ_MUSL_X86_124
#undef DLFRZ_MUSL_X86_12X
#undef DLFRZ_MUSL_AARCH64_12X

#endif
