#ifndef DLFREEZE_GNU_PROPERTIES_H
#define DLFREEZE_GNU_PROPERTIES_H

#include <elf.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Use private spellings so a bootstrap built against an older glibc or musl
 * header applies exactly the same target-ELF policy as the packer. */
#define DLFRZ_NT_GNU_PROPERTY_TYPE_0 UINT32_C(5)
#define DLFRZ_GNU_PROPERTY_STACK_SIZE UINT32_C(1)
#define DLFRZ_GNU_PROPERTY_NO_COPY_ON_PROTECTED UINT32_C(2)
#define DLFRZ_GNU_PROPERTY_1_NEEDED UINT32_C(0xb0008000)

#define DLFRZ_GNU_PROPERTY_X86_FEATURE_2_NEEDED UINT32_C(0xc0008001)
#define DLFRZ_GNU_PROPERTY_X86_ISA_1_NEEDED UINT32_C(0xc0008002)
#define DLFRZ_GNU_PROPERTY_X86_FEATURE_2_USED UINT32_C(0xc0010001)
#define DLFRZ_GNU_PROPERTY_X86_ISA_1_USED UINT32_C(0xc0010002)
#define DLFRZ_GNU_PROPERTY_X86_FEATURE_1_AND UINT32_C(0xc0000002)
#define DLFRZ_GNU_PROPERTY_X86_ISA_1_BASELINE UINT32_C(1)
#define DLFRZ_GNU_PROPERTY_X86_FEATURE_1_IBT UINT32_C(1)
#define DLFRZ_GNU_PROPERTY_X86_FEATURE_1_SHSTK UINT32_C(2)

#define DLFRZ_GNU_PROPERTY_AARCH64_FEATURE_1_AND UINT32_C(0xc0000000)
#define DLFRZ_GNU_PROPERTY_AARCH64_FEATURE_1_BTI UINT32_C(1)
#define DLFRZ_GNU_PROPERTY_AARCH64_FEATURE_1_PAC UINT32_C(2)
#define DLFRZ_GNU_PROPERTY_AARCH64_FEATURE_1_GCS UINT32_C(4)

/* Linux AArch64 UAPI values.  Keep private spellings so old glibc/musl
 * headers make the same mapping decision as current headers.  GCS is in
 * AT_HWCAP (not AT_HWCAP2); it is recorded here to keep future policy code
 * from repeating that easy-to-miss distinction. */
#define DLFRZ_AARCH64_HWCAP_GCS  (UINT64_C(1) << 32)
#define DLFRZ_AARCH64_HWCAP2_BTI (UINT64_C(1) << 17)
#define DLFRZ_AARCH64_PROT_BTI   UINT32_C(0x10)

struct dlfrz_gnu_property_profile {
    uint32_t feature_1;
    uint8_t feature_1_seen;
    uint64_t stack_size;
    uint8_t stack_size_seen;
};

static inline int dlfrz_aarch64_bti_mapping_required(
    const struct dlfrz_gnu_property_profile *profile, uint64_t hwcap2)
{
    return profile && profile->feature_1_seen &&
           (profile->feature_1 &
            DLFRZ_GNU_PROPERTY_AARCH64_FEATURE_1_BTI) != 0 &&
           (hwcap2 & DLFRZ_AARCH64_HWCAP2_BTI) != 0;
}

static inline int dlfrz_gnu_property_align_up(size_t value,
                                               size_t alignment,
                                               size_t *result)
{
    size_t mask;

    if (!result || alignment == 0 ||
        (alignment & (alignment - 1)) != 0)
        return 0;
    mask = alignment - 1;
    if (value > SIZE_MAX - mask)
        return 0;
    *result = (value + mask) & ~mask;
    return 1;
}

static inline int dlfrz_gnu_property_u32(const uint8_t *data,
                                          size_t size,
                                          uint32_t *value)
{
    if (!data || !value || size != sizeof(*value))
        return 0;
    memcpy(value, data, sizeof(*value));
    return 1;
}

static inline int dlfrz_gnu_property_u64(const uint8_t *data,
                                          size_t size,
                                          uint64_t *value)
{
    if (!data || !value || size != sizeof(*value))
        return 0;
    memcpy(value, data, sizeof(*value));
    return 1;
}

/* A final ELF object carries its effective stack contract in PT_GNU_STACK.
 * GNU_PROPERTY_STACK_SIZE is the link-time minimum which led to that header,
 * not an independent runtime authority.  Require one non-executable stack
 * header and prove that it represents every parsed property requirement.
 * Keep the table byte-based because e_phoff has no C alignment guarantee. */
static inline int dlfrz_gnu_property_profile_matches_phdrs(
    const uint8_t *phdr, size_t phdr_size, size_t phnum, size_t phentsize,
    const struct dlfrz_gnu_property_profile *profile)
{
    Elf64_Phdr stack = {0};
    int stack_count = 0;

    if (!phdr || !profile || phentsize != sizeof(Elf64_Phdr) ||
        phnum == 0 || phnum > SIZE_MAX / phentsize ||
        phnum * phentsize > phdr_size)
        return 0;
    for (size_t i = 0; i < phnum; i++) {
        Elf64_Phdr current;

        memcpy(&current, phdr + i * phentsize, sizeof(current));
        if (current.p_type != PT_GNU_STACK)
            continue;
        if (++stack_count != 1 || (current.p_flags & PF_X) != 0)
            return 0;
        stack = current;
    }
    return stack_count == 1 &&
           (!profile->stack_size_seen ||
            stack.p_memsz >= profile->stack_size);
}

/* Parse the complete contents of one PT_GNU_PROPERTY segment.  Direct mode
 * implements one canonical ELF64 GNU note with strictly increasing property
 * types.  Loader-affecting requirements which direct replay cannot enforce
 * are rejected rather than treated as advisory metadata. */
static inline int dlfrz_gnu_property_segment_parse(
    const void *segment, size_t segment_size,
    struct dlfrz_gnu_property_profile *profile_out)
{
    const uint8_t *bytes = (const uint8_t *)segment;
    struct dlfrz_gnu_property_profile profile = {0};
    Elf64_Nhdr header;
    size_t cursor = 0;
    size_t name_bytes;
    size_t desc_bytes;
    size_t desc_end;
    uint32_t previous_type = 0;
    int have_previous = 0;

    if (profile_out)
        *profile_out = profile;
    if (!bytes || segment_size < sizeof(header))
        return 0;
    memcpy(&header, bytes, sizeof(header));
    cursor = sizeof(header);
    if (!dlfrz_gnu_property_align_up(
            (size_t)header.n_namesz, 4, &name_bytes) ||
        name_bytes > segment_size - cursor || header.n_namesz != 4 ||
        memcmp(bytes + cursor, "GNU\0", 4) != 0)
        return 0;
    cursor += name_bytes;
    if (!dlfrz_gnu_property_align_up(
            (size_t)header.n_descsz, 4, &desc_bytes) ||
        desc_bytes > segment_size - cursor ||
        header.n_type != DLFRZ_NT_GNU_PROPERTY_TYPE_0)
        return 0;
    desc_end = cursor + (size_t)header.n_descsz;

    while (cursor < desc_end) {
        uint32_t type;
        uint32_t data_size;
        uint32_t value;
        size_t padded_size;
        const uint8_t *data;

        if (desc_end - cursor < 2 * sizeof(uint32_t))
            return 0;
        memcpy(&type, bytes + cursor, sizeof(type));
        memcpy(&data_size, bytes + cursor + sizeof(type),
               sizeof(data_size));
        cursor += 2 * sizeof(uint32_t);
        if (!dlfrz_gnu_property_align_up(
                (size_t)data_size, 8, &padded_size) ||
            padded_size > desc_end - cursor ||
            (have_previous && type <= previous_type))
            return 0;
        data = bytes + cursor;
        previous_type = type;
        have_previous = 1;

        if (type == DLFRZ_GNU_PROPERTY_STACK_SIZE) {
            if (!dlfrz_gnu_property_u64(
                    data, data_size, &profile.stack_size) ||
                profile.stack_size_seen)
                return 0;
            profile.stack_size_seen = 1;
        } else if (type == DLFRZ_GNU_PROPERTY_NO_COPY_ON_PROTECTED) {
            return 0;
        } else if (type == DLFRZ_GNU_PROPERTY_1_NEEDED) {
            if (!dlfrz_gnu_property_u32(data, data_size, &value) ||
                value != 0)
                return 0;
#if defined(__x86_64__)
        } else if (type == DLFRZ_GNU_PROPERTY_X86_FEATURE_1_AND) {
            if (!dlfrz_gnu_property_u32(data, data_size, &value) ||
                (value & ~(DLFRZ_GNU_PROPERTY_X86_FEATURE_1_IBT |
                           DLFRZ_GNU_PROPERTY_X86_FEATURE_1_SHSTK)) != 0 ||
                profile.feature_1_seen)
                return 0;
            profile.feature_1 = value;
            profile.feature_1_seen = 1;
        } else if (type == DLFRZ_GNU_PROPERTY_X86_ISA_1_NEEDED) {
            if (!dlfrz_gnu_property_u32(data, data_size, &value) ||
                (value & ~DLFRZ_GNU_PROPERTY_X86_ISA_1_BASELINE) != 0)
                return 0;
        } else if (type == DLFRZ_GNU_PROPERTY_X86_ISA_1_USED ||
                   type == DLFRZ_GNU_PROPERTY_X86_FEATURE_2_USED) {
            if (!dlfrz_gnu_property_u32(data, data_size, &value))
                return 0;
        } else if (type == DLFRZ_GNU_PROPERTY_X86_FEATURE_2_NEEDED) {
            if (!dlfrz_gnu_property_u32(data, data_size, &value) ||
                value != 0)
                return 0;
#elif defined(__aarch64__)
        } else if (type == DLFRZ_GNU_PROPERTY_AARCH64_FEATURE_1_AND) {
            if (!dlfrz_gnu_property_u32(data, data_size, &value) ||
                (value & ~(DLFRZ_GNU_PROPERTY_AARCH64_FEATURE_1_BTI |
                           DLFRZ_GNU_PROPERTY_AARCH64_FEATURE_1_PAC |
                           DLFRZ_GNU_PROPERTY_AARCH64_FEATURE_1_GCS)) != 0 ||
                profile.feature_1_seen)
                return 0;
            profile.feature_1 = value;
            profile.feature_1_seen = 1;
#endif
        } else {
            return 0;
        }
        cursor += padded_size;
    }

    if (cursor != desc_end || cursor + (desc_bytes - header.n_descsz) !=
            segment_size)
        return 0;
    if (profile_out)
        *profile_out = profile;
    return 1;
}

#endif /* DLFREEZE_GNU_PROPERTIES_H */
