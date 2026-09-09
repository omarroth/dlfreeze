#include "gnu_properties.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct property_fixture {
    uint8_t bytes[256];
    size_t desc_start;
    size_t cursor;
};

static int fixture_init(struct property_fixture *fixture)
{
    Elf64_Nhdr header = {
        4, 0, DLFRZ_NT_GNU_PROPERTY_TYPE_0
    };

    if (!fixture)
        return 0;
    memset(fixture, 0, sizeof(*fixture));
    memcpy(fixture->bytes, &header, sizeof(header));
    memcpy(fixture->bytes + sizeof(header), "GNU\0", 4);
    fixture->desc_start = sizeof(header) + 4;
    fixture->cursor = fixture->desc_start;
    return 1;
}

static int fixture_add(struct property_fixture *fixture, uint32_t type,
                       const void *data, uint32_t data_size)
{
    size_t padded;

    if (!fixture ||
        !dlfrz_gnu_property_align_up((size_t)data_size, 8, &padded) ||
        fixture->cursor > sizeof(fixture->bytes) ||
        2 * sizeof(uint32_t) > sizeof(fixture->bytes) - fixture->cursor)
        return 0;
    memcpy(fixture->bytes + fixture->cursor, &type, sizeof(type));
    memcpy(fixture->bytes + fixture->cursor + sizeof(type),
           &data_size, sizeof(data_size));
    fixture->cursor += 2 * sizeof(uint32_t);
    if (padded > sizeof(fixture->bytes) - fixture->cursor ||
        (data_size != 0 && !data))
        return 0;
    if (data_size != 0)
        memcpy(fixture->bytes + fixture->cursor, data, data_size);
    fixture->cursor += padded;
    return 1;
}

static size_t fixture_finish(struct property_fixture *fixture)
{
    Elf64_Nhdr header;

    if (!fixture || fixture->cursor < fixture->desc_start ||
        fixture->cursor - fixture->desc_start > UINT32_MAX)
        return 0;
    memcpy(&header, fixture->bytes, sizeof(header));
    header.n_descsz = (uint32_t)(fixture->cursor - fixture->desc_start);
    memcpy(fixture->bytes, &header, sizeof(header));
    return fixture->cursor;
}

static int parse_fixture(struct property_fixture *fixture,
                         struct dlfrz_gnu_property_profile *profile)
{
    size_t size = fixture_finish(fixture);

    return size != 0 &&
           dlfrz_gnu_property_segment_parse(fixture->bytes, size, profile);
}

static int reject_fixture(struct property_fixture *fixture)
{
    struct dlfrz_gnu_property_profile profile = {0};

    profile.feature_1 = UINT32_MAX;
    profile.feature_1_seen = UINT8_MAX;
    profile.stack_size = UINT64_MAX;
    profile.stack_size_seen = UINT8_MAX;

    if (parse_fixture(fixture, &profile))
        return 0;
    return profile.feature_1 == 0 && !profile.feature_1_seen &&
           profile.stack_size == 0 && !profile.stack_size_seen;
}

static int valid_profile_gate(void)
{
    struct dlfrz_gnu_property_profile profile = {0};
    struct property_fixture fixture;
    uint32_t zero = 0;
    uint32_t feature;

    profile.feature_1 = UINT32_MAX;
    profile.feature_1_seen = UINT8_MAX;
    profile.stack_size = UINT64_MAX;
    profile.stack_size_seen = UINT8_MAX;
    if (!fixture_init(&fixture) || !parse_fixture(&fixture, &profile) ||
        profile.feature_1_seen || profile.feature_1 != 0 ||
        profile.stack_size_seen || profile.stack_size != 0 ||
        !parse_fixture(&fixture, NULL))
        return 0;

#if defined(__x86_64__)
    feature = DLFRZ_GNU_PROPERTY_X86_FEATURE_1_IBT |
              DLFRZ_GNU_PROPERTY_X86_FEATURE_1_SHSTK;
#elif defined(__aarch64__)
    feature = DLFRZ_GNU_PROPERTY_AARCH64_FEATURE_1_BTI |
              DLFRZ_GNU_PROPERTY_AARCH64_FEATURE_1_PAC |
              DLFRZ_GNU_PROPERTY_AARCH64_FEATURE_1_GCS;
#else
    return 0;
#endif
    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_1_NEEDED,
                     &zero, sizeof(zero)) ||
#if defined(__x86_64__)
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_X86_FEATURE_1_AND,
                     &feature, sizeof(feature)) ||
#elif defined(__aarch64__)
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_AARCH64_FEATURE_1_AND,
                     &feature, sizeof(feature)) ||
#endif
        !parse_fixture(&fixture, &profile) ||
        !profile.feature_1_seen || profile.feature_1 != feature ||
        profile.stack_size_seen || profile.stack_size != 0)
        return 0;
    return 1;
}

static int stack_size_property_gate(void)
{
    static const uint64_t valid_values[] = {
        UINT64_C(0), UINT64_C(2) * 1024 * 1024, UINT64_MAX
    };
    static const uint32_t invalid_sizes[] = {0, 1, 4, 7, 16};
    struct dlfrz_gnu_property_profile profile = {0};
    struct property_fixture fixture;
    uint8_t data[16] = {0};
    uint32_t zero = 0;
    size_t size;

    for (size_t i = 0;
         i < sizeof(valid_values) / sizeof(valid_values[0]); i++) {
        if (!fixture_init(&fixture) ||
            !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_STACK_SIZE,
                         &valid_values[i], sizeof(valid_values[i])) ||
            !parse_fixture(&fixture, &profile) ||
            !profile.stack_size_seen ||
            profile.stack_size != valid_values[i] ||
            profile.feature_1_seen || profile.feature_1 != 0)
            return 0;
    }

    for (size_t i = 0;
         i < sizeof(invalid_sizes) / sizeof(invalid_sizes[0]); i++) {
        const void *value = invalid_sizes[i] == 0 ? NULL : data;

        if (!fixture_init(&fixture) ||
            !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_STACK_SIZE,
                         value, invalid_sizes[i]) ||
            !reject_fixture(&fixture))
            return 0;
    }

    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_STACK_SIZE,
                     &valid_values[1], sizeof(valid_values[1])) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_STACK_SIZE,
                     &valid_values[1], sizeof(valid_values[1])) ||
        !reject_fixture(&fixture))
        return 0;

    /* STACK_SIZE is the lowest generic type, so placing it after another
     * property also exercises strict type ordering. */
    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_1_NEEDED,
                     &zero, sizeof(zero)) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_STACK_SIZE,
                     &valid_values[1], sizeof(valid_values[1])) ||
        !reject_fixture(&fixture))
        return 0;

    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_STACK_SIZE,
                     &valid_values[1], sizeof(valid_values[1])) ||
        (size = fixture_finish(&fixture)) == 0 ||
        dlfrz_gnu_property_segment_parse(
            fixture.bytes, size - 1, &profile))
        return 0;
    return profile.feature_1 == 0 && !profile.feature_1_seen &&
           profile.stack_size == 0 && !profile.stack_size_seen;
}

static int generic_rejection_gate(void)
{
    struct property_fixture fixture;
    uint64_t wide = 0;
    uint32_t value;

    value = 0;
    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_NO_COPY_ON_PROTECTED,
                     &value, sizeof(value)) ||
        !reject_fixture(&fixture))
        return 0;
    value = 1;
    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_1_NEEDED,
                     &value, sizeof(value)) ||
        !reject_fixture(&fixture))
        return 0;
    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_1_NEEDED,
                     &wide, sizeof(wide)) ||
        !reject_fixture(&fixture))
        return 0;
    return 1;
}

static int stack_size_correlation_gate(void)
{
    uint8_t storage[1 + 3 * sizeof(Elf64_Phdr)] = {0};
    uint8_t *table = storage + 1;
    struct dlfrz_gnu_property_profile profile = {0};
    Elf64_Phdr load = {0};
    Elf64_Phdr stack = {0};
    size_t two_headers = 2 * sizeof(Elf64_Phdr);

    load.p_type = PT_LOAD;
    load.p_flags = PF_R;
    stack.p_type = PT_GNU_STACK;
    stack.p_flags = PF_R | PF_W;
    memcpy(table, &load, sizeof(load));
    memcpy(table + sizeof(load), &stack, sizeof(stack));

    if (!dlfrz_gnu_property_profile_matches_phdrs(
            table, two_headers, 2, sizeof(Elf64_Phdr), &profile) ||
        dlfrz_gnu_property_profile_matches_phdrs(
            NULL, two_headers, 2, sizeof(Elf64_Phdr), &profile) ||
        dlfrz_gnu_property_profile_matches_phdrs(
            table, two_headers, 2, sizeof(Elf64_Phdr), NULL) ||
        dlfrz_gnu_property_profile_matches_phdrs(
            table, two_headers, 0, sizeof(Elf64_Phdr), &profile) ||
        dlfrz_gnu_property_profile_matches_phdrs(
            table, two_headers - 1, 2, sizeof(Elf64_Phdr), &profile) ||
        dlfrz_gnu_property_profile_matches_phdrs(
            table, two_headers, 2, sizeof(Elf64_Phdr) - 1, &profile) ||
        dlfrz_gnu_property_profile_matches_phdrs(
            table, SIZE_MAX, SIZE_MAX / sizeof(Elf64_Phdr) + 1,
            sizeof(Elf64_Phdr), &profile))
        return 0;

    profile.stack_size_seen = 1;
    profile.stack_size = 0;
    if (!dlfrz_gnu_property_profile_matches_phdrs(
            table, two_headers, 2, sizeof(Elf64_Phdr), &profile))
        return 0;

    profile.stack_size = UINT64_C(2) * 1024 * 1024;
    stack.p_memsz = profile.stack_size;
    memcpy(table + sizeof(load), &stack, sizeof(stack));
    if (!dlfrz_gnu_property_profile_matches_phdrs(
            table, two_headers, 2, sizeof(Elf64_Phdr), &profile))
        return 0;
    stack.p_memsz++;
    memcpy(table + sizeof(load), &stack, sizeof(stack));
    if (!dlfrz_gnu_property_profile_matches_phdrs(
            table, two_headers, 2, sizeof(Elf64_Phdr), &profile))
        return 0;
    stack.p_memsz = profile.stack_size - 1;
    memcpy(table + sizeof(load), &stack, sizeof(stack));
    if (dlfrz_gnu_property_profile_matches_phdrs(
            table, two_headers, 2, sizeof(Elf64_Phdr), &profile))
        return 0;

    profile.stack_size = UINT64_MAX;
    stack.p_memsz = UINT64_MAX;
    memcpy(table + sizeof(load), &stack, sizeof(stack));
    if (!dlfrz_gnu_property_profile_matches_phdrs(
            table, two_headers, 2, sizeof(Elf64_Phdr), &profile))
        return 0;
    stack.p_memsz--;
    memcpy(table + sizeof(load), &stack, sizeof(stack));
    if (dlfrz_gnu_property_profile_matches_phdrs(
            table, two_headers, 2, sizeof(Elf64_Phdr), &profile))
        return 0;

    memcpy(table + sizeof(load), &load, sizeof(load));
    if (dlfrz_gnu_property_profile_matches_phdrs(
            table, two_headers, 2, sizeof(Elf64_Phdr), &profile))
        return 0;

    stack.p_memsz = UINT64_MAX;
    stack.p_flags |= PF_X;
    memcpy(table + sizeof(load), &stack, sizeof(stack));
    if (dlfrz_gnu_property_profile_matches_phdrs(
            table, two_headers, 2, sizeof(Elf64_Phdr), &profile))
        return 0;

    stack.p_flags &= ~PF_X;
    memcpy(table, &stack, sizeof(stack));
    memcpy(table + sizeof(stack), &stack, sizeof(stack));
    return !dlfrz_gnu_property_profile_matches_phdrs(
        table, two_headers, 2, sizeof(Elf64_Phdr), &profile);
}

static int architecture_gate(void)
{
    struct dlfrz_gnu_property_profile profile = {0};
    struct property_fixture fixture;
    uint32_t value;

#if defined(__x86_64__)
    uint64_t wide = 0;

    value = DLFRZ_GNU_PROPERTY_X86_ISA_1_BASELINE;
    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_X86_ISA_1_NEEDED,
                     &value, sizeof(value)) ||
        !parse_fixture(&fixture, &profile))
        return 0;
    value = UINT32_C(2);
    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_X86_ISA_1_NEEDED,
                     &value, sizeof(value)) ||
        parse_fixture(&fixture, &profile))
        return 0;
    value = UINT32_MAX;
    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_X86_ISA_1_USED,
                     &value, sizeof(value)) ||
        !parse_fixture(&fixture, &profile))
        return 0;
    value = UINT32_MAX;
    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_X86_FEATURE_2_USED,
                     &value, sizeof(value)) ||
        !parse_fixture(&fixture, &profile))
        return 0;
    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_X86_FEATURE_2_USED,
                     &wide, sizeof(wide)) ||
        !reject_fixture(&fixture))
        return 0;
    value = 0;
    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_X86_FEATURE_2_NEEDED,
                     &value, sizeof(value)) ||
        !parse_fixture(&fixture, &profile))
        return 0;
    value = 1;
    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_X86_FEATURE_2_NEEDED,
                     &value, sizeof(value)) ||
        !reject_fixture(&fixture))
        return 0;
    value = UINT32_C(4);
    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_X86_FEATURE_1_AND,
                     &value, sizeof(value)) ||
        parse_fixture(&fixture, &profile))
        return 0;
#elif defined(__aarch64__)
    value = UINT32_C(8);
    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_AARCH64_FEATURE_1_AND,
                     &value, sizeof(value)) ||
        parse_fixture(&fixture, &profile))
        return 0;
#else
    return 0;
#endif
    return 1;
}

static int aarch64_bti_mapping_policy_gate(void)
{
#if defined(__aarch64__)
    struct dlfrz_gnu_property_profile profile = {0};
    const uint32_t non_bti_features =
        DLFRZ_GNU_PROPERTY_AARCH64_FEATURE_1_PAC |
        DLFRZ_GNU_PROPERTY_AARCH64_FEATURE_1_GCS;

    /* GCS is an AT_HWCAP bit.  HWCAP2 bit 32 names EBF16, and must never
     * accidentally trigger a BTI mapping decision. */
    if (DLFRZ_AARCH64_HWCAP_GCS == DLFRZ_AARCH64_HWCAP2_BTI ||
        DLFRZ_AARCH64_HWCAP2_BTI != (UINT64_C(1) << 17) ||
        DLFRZ_AARCH64_PROT_BTI != UINT32_C(0x10) ||
        dlfrz_aarch64_bti_mapping_required(
            &profile, DLFRZ_AARCH64_HWCAP2_BTI))
        return 0;

    profile.feature_1_seen = 1;
    profile.feature_1 = non_bti_features;
    if (dlfrz_aarch64_bti_mapping_required(
            &profile, DLFRZ_AARCH64_HWCAP2_BTI))
        return 0;

    profile.feature_1 |= DLFRZ_GNU_PROPERTY_AARCH64_FEATURE_1_BTI;
    if (dlfrz_aarch64_bti_mapping_required(&profile, 0) ||
        !dlfrz_aarch64_bti_mapping_required(
            &profile, DLFRZ_AARCH64_HWCAP2_BTI) ||
        dlfrz_aarch64_bti_mapping_required(
            NULL, DLFRZ_AARCH64_HWCAP2_BTI))
        return 0;
#endif
    return 1;
}

static int ordering_and_unknown_gate(void)
{
    struct dlfrz_gnu_property_profile profile = {0};
    struct property_fixture fixture;
    uint32_t zero = 0;
    uint32_t first;
    uint32_t second;
    uint32_t feature;

#if defined(__x86_64__)
    first = DLFRZ_GNU_PROPERTY_X86_ISA_1_NEEDED;
    second = DLFRZ_GNU_PROPERTY_X86_ISA_1_USED;
    feature = DLFRZ_GNU_PROPERTY_X86_FEATURE_1_IBT;
#elif defined(__aarch64__)
    first = DLFRZ_GNU_PROPERTY_1_NEEDED;
    second = DLFRZ_GNU_PROPERTY_AARCH64_FEATURE_1_AND;
    feature = DLFRZ_GNU_PROPERTY_AARCH64_FEATURE_1_BTI;
#else
    return 0;
#endif
    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, second, &zero, sizeof(zero)) ||
        !fixture_add(&fixture, first, &zero, sizeof(zero)) ||
        parse_fixture(&fixture, &profile))
        return 0;
    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, first, &zero, sizeof(zero)) ||
        !fixture_add(&fixture, first, &zero, sizeof(zero)) ||
        parse_fixture(&fixture, &profile))
        return 0;
    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, UINT32_C(0xdeadbeef),
                     &zero, sizeof(zero)) ||
        parse_fixture(&fixture, &profile))
        return 0;
#if defined(__x86_64__)
    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_X86_FEATURE_1_AND,
                     &feature, sizeof(feature)) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_X86_FEATURE_2_NEEDED,
                     &feature, sizeof(feature)) ||
        !reject_fixture(&fixture))
        return 0;
#elif defined(__aarch64__)
    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_AARCH64_FEATURE_1_AND,
                     &feature, sizeof(feature)) ||
        !fixture_add(&fixture, UINT32_C(0xdeadbeef),
                     &zero, sizeof(zero)) ||
        !reject_fixture(&fixture))
        return 0;
#endif
    return 1;
}

static int malformed_note_gate(void)
{
    struct dlfrz_gnu_property_profile profile = {0};
    struct property_fixture fixture;
    Elf64_Nhdr header;
    size_t size;
    uint32_t value = 0;

    profile.feature_1 = UINT32_MAX;
    profile.feature_1_seen = UINT8_MAX;
    profile.stack_size = UINT64_MAX;
    profile.stack_size_seen = UINT8_MAX;
    if (dlfrz_gnu_property_align_up(0, 0, &size) ||
        dlfrz_gnu_property_align_up(0, 3, &size) ||
        dlfrz_gnu_property_align_up(0, 4, NULL) ||
        dlfrz_gnu_property_align_up(SIZE_MAX, 8, &size) ||
        !dlfrz_gnu_property_align_up(SIZE_MAX - 7, 8, &size) ||
        size != SIZE_MAX - 7)
        return 0;

    if (dlfrz_gnu_property_segment_parse(NULL, SIZE_MAX, &profile) ||
        profile.feature_1_seen || profile.feature_1 != 0 ||
        profile.stack_size_seen || profile.stack_size != 0)
        return 0;

    if (!fixture_init(&fixture))
        return 0;
    for (size_t i = 0; i < sizeof(Elf64_Nhdr); i++) {
        if (dlfrz_gnu_property_segment_parse(fixture.bytes, i, &profile))
            return 0;
    }

    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_1_NEEDED,
                     &value, sizeof(value)) ||
        (size = fixture_finish(&fixture)) == 0)
        return 0;
    if (dlfrz_gnu_property_segment_parse(
            fixture.bytes, size - 1, &profile) ||
        dlfrz_gnu_property_segment_parse(
            fixture.bytes, size + 1, &profile))
        return 0;
    for (size_t i = 0; i < size; i++) {
        if (dlfrz_gnu_property_segment_parse(fixture.bytes, i, &profile))
            return 0;
    }

    memcpy(&header, fixture.bytes, sizeof(header));
    header.n_namesz = 3;
    memcpy(fixture.bytes, &header, sizeof(header));
    if (dlfrz_gnu_property_segment_parse(fixture.bytes, size, &profile))
        return 0;

    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_1_NEEDED,
                     &value, sizeof(value)) ||
        (size = fixture_finish(&fixture)) == 0)
        return 0;
    memcpy(&header, fixture.bytes, sizeof(header));
    header.n_namesz = UINT32_MAX;
    memcpy(fixture.bytes, &header, sizeof(header));
    if (dlfrz_gnu_property_segment_parse(fixture.bytes, size, &profile))
        return 0;

    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_1_NEEDED,
                     &value, sizeof(value)) ||
        (size = fixture_finish(&fixture)) == 0)
        return 0;
    fixture.bytes[sizeof(Elf64_Nhdr)] = 'X';
    if (dlfrz_gnu_property_segment_parse(fixture.bytes, size, &profile))
        return 0;

    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_1_NEEDED,
                     &value, sizeof(value)) ||
        (size = fixture_finish(&fixture)) == 0)
        return 0;
    memcpy(&header, fixture.bytes, sizeof(header));
    header.n_descsz = UINT32_MAX;
    memcpy(fixture.bytes, &header, sizeof(header));
    if (dlfrz_gnu_property_segment_parse(fixture.bytes, size, &profile))
        return 0;

    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_1_NEEDED,
                     &value, sizeof(value)) ||
        (size = fixture_finish(&fixture)) == 0)
        return 0;
    memcpy(&header, fixture.bytes, sizeof(header));
    header.n_type++;
    memcpy(fixture.bytes, &header, sizeof(header));
    if (dlfrz_gnu_property_segment_parse(fixture.bytes, size, &profile))
        return 0;

    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_1_NEEDED,
                     &value, sizeof(value)) ||
        (size = fixture_finish(&fixture)) == 0)
        return 0;
    memcpy(&header, fixture.bytes, sizeof(header));
    header.n_descsz--;
    memcpy(fixture.bytes, &header, sizeof(header));
    if (dlfrz_gnu_property_segment_parse(fixture.bytes, size, &profile))
        return 0;

    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_1_NEEDED,
                     &value, sizeof(value)) ||
        (size = fixture_finish(&fixture)) == 0)
        return 0;
    value = UINT32_MAX;
    memcpy(fixture.bytes + fixture.desc_start + sizeof(uint32_t),
           &value, sizeof(value));
    if (dlfrz_gnu_property_segment_parse(fixture.bytes, size, &profile))
        return 0;

    value = 0;
    if (!fixture_init(&fixture) ||
        !fixture_add(&fixture, DLFRZ_GNU_PROPERTY_1_NEEDED,
                     &value, sizeof(value)) ||
        (size = fixture_finish(&fixture)) == 0 ||
        size > sizeof(fixture.bytes) - size)
        return 0;
    memcpy(fixture.bytes + size, fixture.bytes, size);
    if (dlfrz_gnu_property_segment_parse(fixture.bytes, 2 * size, &profile))
        return 0;
    return 1;
}

int main(void)
{
    if (!valid_profile_gate()) return 1;
    if (!stack_size_property_gate()) return 2;
    if (!generic_rejection_gate()) return 3;
    if (!stack_size_correlation_gate()) return 4;
    if (!architecture_gate()) return 5;
    if (!aarch64_bti_mapping_policy_gate()) return 6;
    if (!ordering_and_unknown_gate()) return 7;
    if (!malformed_note_gate()) return 8;
    return 0;
}
