#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define DLFREEZE_PRELINK_RELOCATION_GATE 1
#include "../src/packer.c"

enum {
    TEST_IMAGE_SIZE = 2048,
    TEST_RELA_OFFSET = 128,
    TEST_RELR_OFFSET = 128,
    TEST_JMPREL_OFFSET = 256,
    TEST_DATA_OFFSET = 512
};

static void initialize_object(struct prelink_obj *obj,
                              unsigned char image[TEST_IMAGE_SIZE],
                              Elf64_Phdr *phdrs, uint16_t phdr_num)
{
    memset(obj, 0, sizeof(*obj));
    memset(phdrs, 0, (size_t)phdr_num * sizeof(*phdrs));
    obj->base = (uintptr_t)image;
    obj->file_size = TEST_IMAGE_SIZE;
    obj->phdr_base = (const uint8_t *)phdrs;
    obj->phdr_num = phdr_num;
    obj->phdr_entsz = sizeof(*phdrs);
}

static void initialize_load(Elf64_Phdr *phdr, uint32_t flags,
                            uint64_t file_offset, uint64_t vaddr,
                            uint64_t size)
{
    memset(phdr, 0, sizeof(*phdr));
    phdr->p_type = PT_LOAD;
    phdr->p_flags = flags;
    phdr->p_offset = file_offset;
    phdr->p_vaddr = vaddr;
    phdr->p_filesz = size;
    phdr->p_memsz = size;
}

static int overlap_component_alias_gate(void)
{
    _Alignas(Elf64_Rela) unsigned char image[TEST_IMAGE_SIZE];
    struct prelink_obj obj;
    Elf64_Phdr phdrs[2];
    const Elf64_Rela *live_rela;
    const Elf64_Rela *live_jmprel;
    const Elf64_Relr *live_relr;
    unsigned char admitted_byte;

    memset(image, 0x5a, sizeof(image));
    initialize_object(&obj, image, phdrs, 2);
    initialize_load(&phdrs[0], PF_R, 0, 0, sizeof(image));
    /* Even a partial writable overlap makes the complete connected source
     * component mutable. */
    initialize_load(&phdrs[1], PF_R | PF_W,
                    TEST_RELA_OFFSET + 17,
                    TEST_RELA_OFFSET + 17, 1);
    live_rela = (const Elf64_Rela *)(image + TEST_RELA_OFFSET);
    live_jmprel = (const Elf64_Rela *)(image + TEST_RELA_OFFSET + 8);
    live_relr = (const Elf64_Relr *)(image + TEST_RELA_OFFSET + 24);
    obj.rela = live_rela;
    obj.rela_count = 2;
    obj.jmprel = live_jmprel;
    obj.jmprel_count = 1;
    obj.relr = live_relr;
    obj.relr_count = 1;

    if (pl_relocation_sources_admit(
            &obj, TEST_RELA_OFFSET, 2 * sizeof(Elf64_Rela),
            TEST_RELA_OFFSET + 8, sizeof(Elf64_Rela),
            TEST_RELA_OFFSET + 24, sizeof(Elf64_Relr)) < 0 ||
        !obj.relocation_source_storage ||
        obj.relocation_source_count != 3 ||
        obj.relocation_component_count != 1 ||
        (const uint8_t *)obj.jmprel - (const uint8_t *)obj.rela != 8 ||
        (const uint8_t *)obj.relr - (const uint8_t *)obj.rela != 24 ||
        g_pl_relocation_snapshot_live_allocations != 1)
        return 0;
    admitted_byte = ((const uint8_t *)obj.rela)[10];
    image[TEST_RELA_OFFSET + 10] ^= 0xff;
    if (((const uint8_t *)obj.rela)[10] != admitted_byte ||
        pl_relocation_sources_unchanged(&obj))
        return 0;

    pl_relocation_sources_release(&obj);
    if (obj.rela != live_rela || obj.jmprel != live_jmprel ||
        obj.relr != live_relr || obj.relocation_source_storage ||
        g_pl_relocation_snapshot_live_allocations != 0)
        return 0;
    pl_relocation_sources_release(&obj);
    return g_pl_relocation_snapshot_live_allocations == 0;
}

static int immutable_and_failure_gate(void)
{
    _Alignas(Elf64_Rela) unsigned char image[TEST_IMAGE_SIZE];
    struct prelink_obj obj;
    Elf64_Phdr phdr;
    const Elf64_Rela *live_rela =
        (const Elf64_Rela *)(image + TEST_RELA_OFFSET);

    memset(image, 0, sizeof(image));
    initialize_object(&obj, image, &phdr, 1);
    initialize_load(&phdr, PF_R, 0, 0, sizeof(image));
    obj.rela = live_rela;
    obj.rela_count = 1;
    if (pl_relocation_sources_admit(
            &obj, TEST_RELA_OFFSET, sizeof(Elf64_Rela),
            0, 0, 0, 0) < 0 ||
        obj.rela != live_rela || obj.relocation_source_storage ||
        !pl_relocation_sources_unchanged(&obj))
        return 0;
    pl_relocation_sources_release(&obj);

    initialize_object(&obj, image, &phdr, 1);
    initialize_load(&phdr, PF_R | PF_W, 0, 0, sizeof(image));
    obj.rela = live_rela;
    obj.rela_count = 1;
    g_pl_relocation_snapshot_fail_allocation = 1;
    if (pl_relocation_sources_admit(
            &obj, TEST_RELA_OFFSET, sizeof(Elf64_Rela),
            0, 0, 0, 0) == 0 ||
        obj.rela != live_rela || obj.relocation_source_storage ||
        obj.relocation_source_count != 0 ||
        obj.relocation_component_count != 0 ||
        g_pl_relocation_snapshot_live_allocations != 0) {
        g_pl_relocation_snapshot_fail_allocation = 0;
        return 0;
    }
    g_pl_relocation_snapshot_fail_allocation = 0;
    pl_relocation_sources_release(&obj);
    return g_pl_relocation_snapshot_live_allocations == 0;
}

static int same_table_store_gate(void)
{
    _Alignas(Elf64_Rela) unsigned char image[TEST_IMAGE_SIZE];
    struct prelink_obj obj;
    Elf64_Phdr phdr;
    Elf64_Rela *live;
    uint32_t original_info;
    uint32_t *fixups = NULL;
    size_t fixup_count = 0;
    size_t fixup_capacity = 0;
    uint32_t object_fixup_offset = 0;
    uint32_t object_fixup_count = 0;
    uint64_t data_before = UINT64_C(0x1122334455667788);
    int valid = 0;

    memset(image, 0, sizeof(image));
    memcpy(image + TEST_DATA_OFFSET, &data_before, sizeof(data_before));
    initialize_object(&obj, image, &phdr, 1);
    initialize_load(&phdr, PF_R | PF_W, 0, 0, sizeof(image));
    live = (Elf64_Rela *)(image + TEST_RELA_OFFSET);
    live[0].r_offset = TEST_RELA_OFFSET + sizeof(Elf64_Rela) +
        offsetof(Elf64_Rela, r_info);
    live[0].r_info = ELF64_R_INFO(0, ARCH_RELOC_RELATIVE);
    live[0].r_addend = 0;
    live[1].r_offset = TEST_DATA_OFFSET;
    live[1].r_info = ELF64_R_INFO(0, ARCH_RELOC_TPOFF);
    live[1].r_addend = 0;
    original_info = (uint32_t)live[1].r_info;
    obj.rela = live;
    obj.rela_count = 2;

    if (pl_relocation_sources_admit(
            &obj, TEST_RELA_OFFSET, 2 * sizeof(Elf64_Rela),
            0, 0, 0, 0) < 0 || obj.rela == live)
        goto out;
    if (pl_apply_rela(&obj, obj.rela, obj.rela_count) == 0 ||
        live[1].r_info != original_info ||
        memcmp(image + TEST_DATA_OFFSET, &data_before,
               sizeof(data_before)) != 0)
        goto out;

    /* Fixup classification uses the admitted authority even if a later bug
     * or external test mutates the mapped table bytes. */
    live[1].r_info = ELF64_R_INFO(0, ARCH_RELOC_RELATIVE);
    if (prelink_obj_collect_runtime_fixups(
            &obj, &fixups, &fixup_count, &fixup_capacity,
            &object_fixup_offset, &object_fixup_count) < 0 ||
        object_fixup_offset != 0 || object_fixup_count != 1 ||
        fixup_count != 1 || fixups[0] != 1 ||
        pl_relocation_sources_unchanged(&obj))
        goto out;
    valid = 1;

out:
    free(fixups);
    pl_relocation_sources_release(&obj);
    return valid && g_pl_relocation_snapshot_live_allocations == 0;
}

static int relr_cross_table_store_gate(void)
{
    _Alignas(Elf64_Rela) unsigned char image[TEST_IMAGE_SIZE];
    struct prelink_obj obj;
    Elf64_Phdr phdr;
    Elf64_Relr *live_relr;
    Elf64_Rela *live_jmprel;
    Elf64_Xword original_info;
    uint32_t *fixups = NULL;
    size_t fixup_count = 0;
    size_t fixup_capacity = 0;
    uint32_t object_fixup_offset = 0;
    uint32_t object_fixup_count = 0;
    int valid = 0;

    memset(image, 0, sizeof(image));
    initialize_object(&obj, image, &phdr, 1);
    initialize_load(&phdr, PF_R | PF_W, 0, 0, sizeof(image));
    live_relr = (Elf64_Relr *)(image + TEST_RELR_OFFSET);
    live_jmprel = (Elf64_Rela *)(image + TEST_JMPREL_OFFSET);
    live_relr[0] = TEST_JMPREL_OFFSET + offsetof(Elf64_Rela, r_info);
    live_jmprel[0].r_offset = TEST_DATA_OFFSET;
    live_jmprel[0].r_info = ELF64_R_INFO(0, ARCH_RELOC_TPOFF);
    original_info = live_jmprel[0].r_info;
    obj.relr = live_relr;
    obj.relr_count = 1;
    obj.jmprel = live_jmprel;
    obj.jmprel_count = 1;

    if (pl_relocation_sources_admit(
            &obj, 0, 0,
            TEST_JMPREL_OFFSET, sizeof(Elf64_Rela),
            TEST_RELR_OFFSET, sizeof(Elf64_Relr)) < 0 ||
        obj.relr == live_relr || obj.jmprel == live_jmprel)
        goto out;
    if (pl_apply_relr(&obj) == 0 ||
        live_jmprel[0].r_info != original_info)
        goto out;
    if (prelink_obj_collect_runtime_fixups(
            &obj, &fixups, &fixup_count, &fixup_capacity,
            &object_fixup_offset, &object_fixup_count) < 0 ||
        object_fixup_offset != 0 || object_fixup_count != 1 ||
        fixup_count != 1 ||
        fixups[0] != (PRELINK_FIXUP_JMPREL | 0U))
        goto out;
    valid = 1;

out:
    free(fixups);
    pl_relocation_sources_release(&obj);
    return valid && g_pl_relocation_snapshot_live_allocations == 0;
}

static int relr_persisted_rela_overlap_gate(void)
{
    _Alignas(Elf64_Rela) unsigned char image[TEST_IMAGE_SIZE];
    struct prelink_obj obj;
    Elf64_Phdr phdr;
    Elf64_Rela *rela;
    Elf64_Relr *relr;

    memset(image, 0, sizeof(image));
    initialize_object(&obj, image, &phdr, 1);
    initialize_load(&phdr, PF_R | PF_W, 0, 0, sizeof(image));
    rela = (Elf64_Rela *)(image + TEST_RELA_OFFSET);
    relr = (Elf64_Relr *)(image + TEST_JMPREL_OFFSET);
    rela[0].r_offset = TEST_DATA_OFFSET + 1;
    rela[0].r_info = ELF64_R_INFO(0, ARCH_RELOC_RELATIVE);
    rela[0].r_addend = 17;
    relr[0] = TEST_DATA_OFFSET;
    obj.rela = rela;
    obj.rela_count = 1;
    obj.relr = relr;
    obj.relr_count = 1;

    /* RELA destinations are permitted to be unaligned.  An equality-only
     * cross-table check would miss this seven-byte overlap and runtime RELR
     * replay would add the base to bytes already serialized by prelink. */
    if (pl_apply_relr(&obj) == 0)
        return 0;

    rela[0].r_offset = TEST_DATA_OFFSET + sizeof(uint64_t);
    return pl_apply_relr(&obj) == 0;
}

static int control_metadata_store_gate(void)
{
    static const enum pl_control_metadata_kind kinds[] = {
        PL_CONTROL_ELF_HEADER,
        PL_CONTROL_PROGRAM_HEADERS,
        PL_CONTROL_SECTION_HEADERS,
        PL_CONTROL_SECTION_SYMBOLS,
        PL_CONTROL_SECTION_STRINGS,
        PL_CONTROL_DYNAMIC,
        PL_CONTROL_RELA,
        PL_CONTROL_JMPREL,
        PL_CONTROL_RELR,
        PL_CONTROL_DYNSTR,
        PL_CONTROL_DYNSYM,
        PL_CONTROL_VERSYM,
        PL_CONTROL_GNU_HASH,
        PL_CONTROL_SYSV_HASH,
        PL_CONTROL_VERDEF,
        PL_CONTROL_VERDAUX,
        PL_CONTROL_VERNEED,
        PL_CONTROL_VERNAUX,
        PL_CONTROL_GNU_PROPERTY
    };
    _Alignas(Elf64_Rela) unsigned char image[TEST_IMAGE_SIZE];
    Elf64_Phdr phdr;

    for (size_t target = 0;
         target < sizeof(kinds) / sizeof(kinds[0]); target++) {
        struct prelink_obj obj;
        struct pl_control_range_builder builder = {0};
        Elf64_Rela *live;
        uint64_t target_offset = 640 + target * 16;
        uint64_t before;
        int accepted = 0;

        memset(image, 0x3c, sizeof(image));
        initialize_object(&obj, image, &phdr, 1);
        initialize_load(&phdr, PF_R | PF_W, 0, 0, sizeof(image));
        live = (Elf64_Rela *)(image + TEST_RELA_OFFSET);
        live[0].r_offset = target_offset;
        live[0].r_info = ELF64_R_INFO(0, ARCH_RELOC_RELATIVE);
        live[0].r_addend = 0;
        obj.rela = live;
        obj.rela_count = 1;
        memcpy(&before, image + target_offset, sizeof(before));

        for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
            if (!pl_control_range_builder_add_file(
                    &obj, &builder, 640 + i * 16, sizeof(uint64_t),
                    kinds[i]))
                goto iteration_out;
        }
        if (!pl_control_range_builder_add_file(
                &obj, &builder, TEST_RELA_OFFSET, sizeof(Elf64_Rela),
                PL_CONTROL_RELA))
            goto iteration_out;

        if (pl_relocation_sources_admit(
                &obj, TEST_RELA_OFFSET, sizeof(Elf64_Rela),
                0, 0, 0, 0) < 0 ||
            pl_control_authority_admit(&obj, &builder) < 0 ||
            pl_apply_rela(&obj, obj.rela, obj.rela_count) == 0 ||
            memcmp(image + target_offset,
                   &before, sizeof(before)) != 0) {
            goto iteration_out;
        }
        accepted = 1;

iteration_out:
        pl_control_range_builder_release(&builder);
        pl_control_authority_release(&obj);
        pl_relocation_sources_release(&obj);
        if (!accepted || g_pl_relocation_snapshot_live_allocations != 0)
            return 0;
    }
    return 1;
}

static int control_snapshot_and_alias_gate(void)
{
    _Alignas(Elf64_Rela) unsigned char image[TEST_IMAGE_SIZE];
    struct prelink_obj obj;
    struct pl_control_range_builder builder = {0};
    Elf64_Phdr phdrs[3];
    Elf64_Rela *live;
    uint64_t before;
    int valid = 0;

    memset(image, 0, sizeof(image));
    initialize_object(&obj, image, phdrs, 2);
    initialize_load(&phdrs[0], PF_R, 0, 0, 512);
    initialize_load(&phdrs[1], PF_R | PF_W, 0, 768, 512);
    memcpy(image + 768, image, 512);
    live = (Elf64_Rela *)(image + TEST_RELA_OFFSET);
    live[0].r_offset = 768 + 96;
    live[0].r_info = ELF64_R_INFO(0, ARCH_RELOC_RELATIVE);
    obj.rela = live;
    obj.rela_count = 1;
    memcpy(&before, image + 768 + 96, sizeof(before));

    /* The relocation table is read through the immutable alias, while the
     * target reaches the same serialized metadata through a disjoint PF_W
     * alias. */
    if (!pl_control_range_builder_add_file(
            &obj, &builder, TEST_RELA_OFFSET, sizeof(Elf64_Rela),
            PL_CONTROL_RELA) ||
        !pl_control_range_builder_add_file(
            &obj, &builder, 96, sizeof(uint64_t), PL_CONTROL_DYNSYM) ||
        pl_relocation_sources_admit(
            &obj, TEST_RELA_OFFSET, sizeof(Elf64_Rela),
            0, 0, 0, 0) < 0 ||
        pl_control_authority_admit(&obj, &builder) < 0 ||
        obj.control_writable_view_count == 0 ||
        pl_apply_rela(&obj, obj.rela, obj.rela_count) == 0 ||
        memcmp(image + 768 + 96, &before, sizeof(before)) != 0)
        goto out;

    image[768 + 96] ^= 1;
    if (pl_control_authority_unchanged(&obj))
        goto out;
    image[768 + 96] ^= 1;
    if (!pl_control_authority_unchanged(&obj))
        goto out;
    valid = 1;

out:
    pl_control_range_builder_release(&builder);
    pl_control_authority_release(&obj);
    pl_relocation_sources_release(&obj);
    if (!valid || g_pl_relocation_snapshot_live_allocations != 0)
        return 0;

    /* A PF_W target can share its live virtual address with a read-only
     * PT_LOAD that serializes the same store over protected bytes at a
     * different file offset.  Writeback aliases, not just writable aliases,
     * participate in the store refusal. */
    valid = 0;
    initialize_object(&obj, image, phdrs, 3);
    initialize_load(&phdrs[0], PF_R | PF_W, 0, 0, 256);
    initialize_load(&phdrs[1], PF_R, 512, 0, 256);
    initialize_load(&phdrs[2], PF_R, 1024, 1024, 256);
    live = (Elf64_Rela *)(image + 1152);
    live[0].r_offset = 100;
    live[0].r_info = ELF64_R_INFO(0, ARCH_RELOC_RELATIVE);
    obj.rela = live;
    obj.rela_count = 1;
    memcpy(&before, image + 100, sizeof(before));
    if (!pl_control_range_builder_add_file(
            &obj, &builder, 612, sizeof(uint64_t),
            PL_CONTROL_ELF_HEADER) ||
        !pl_control_range_builder_add_file(
            &obj, &builder, 1152, sizeof(Elf64_Rela),
            PL_CONTROL_RELA) ||
        pl_relocation_sources_admit(
            &obj, 1152, sizeof(Elf64_Rela), 0, 0, 0, 0) < 0 ||
        pl_control_authority_admit(&obj, &builder) < 0 ||
        pl_apply_rela(&obj, obj.rela, obj.rela_count) == 0 ||
        memcmp(image + 100, &before, sizeof(before)) != 0)
        goto readonly_alias_out;
    valid = 1;

readonly_alias_out:
    pl_control_range_builder_release(&builder);
    pl_control_authority_release(&obj);
    pl_relocation_sources_release(&obj);
    if (!valid || g_pl_relocation_snapshot_live_allocations != 0)
        return 0;

    initialize_object(&obj, image, phdrs, 1);
    initialize_load(&phdrs[0], PF_R | PF_W, 0, 0, sizeof(image));
    if (!pl_control_range_builder_add_file(
            &obj, &builder, 96, sizeof(uint64_t), PL_CONTROL_DYNSYM))
        return 0;
    g_pl_relocation_snapshot_fail_allocation = 1;
    if (pl_control_authority_admit(&obj, &builder) == 0 ||
        obj.control_ranges || obj.control_writable_views ||
        obj.control_snapshot_storage ||
        g_pl_relocation_snapshot_live_allocations != 0) {
        g_pl_relocation_snapshot_fail_allocation = 0;
        pl_control_range_builder_release(&builder);
        pl_control_authority_release(&obj);
        return 0;
    }
    g_pl_relocation_snapshot_fail_allocation = 0;
    pl_control_range_builder_release(&builder);
    pl_control_authority_release(&obj);
    return g_pl_relocation_snapshot_live_allocations == 0;
}

static int symbolic_relocations_deferred_gate(void)
{
    enum { RELOCATION_COUNT = 10 };
    _Alignas(Elf64_Rela) unsigned char image[TEST_IMAGE_SIZE];
    struct prelink_obj obj;
    Elf64_Phdr phdr;
    Elf64_Rela *rela;
    Elf64_Sym *symbols;
    uint64_t before[RELOCATION_COUNT];
    uint32_t *fixups = NULL;
    size_t fixup_count = 0;
    size_t fixup_capacity = 0;
    uint32_t object_fixup_offset = 0;
    uint32_t object_fixup_count = 0;
    static const uint32_t types[RELOCATION_COUNT] = {
        ARCH_RELOC_RELATIVE,
        ARCH_RELOC_GLOB_DAT,
        ARCH_RELOC_JUMP_SLOT,
        ARCH_RELOC_ABS,
        ARCH_RELOC_TPOFF,
        ARCH_RELOC_DTPMOD,
        ARCH_RELOC_DTPOFF,
        ARCH_RELOC_TLSDESC,
        ARCH_RELOC_IRELATIVE,
        ARCH_RELOC_COPY
    };
    int valid = 0;

    memset(image, 0, sizeof(image));
    initialize_object(&obj, image, &phdr, 1);
    initialize_load(&phdr, PF_R | PF_W | PF_X, 0, 0, sizeof(image));
    rela = (Elf64_Rela *)(image + TEST_RELA_OFFSET);
    symbols = (Elf64_Sym *)(image + 400);
    obj.rela = rela;
    obj.rela_count = RELOCATION_COUNT;
    obj.dynsym = symbols;
    obj.dynsym_count = 2;
    obj.dynstr = (const char *)(image + 464);
    obj.dynstr_size = 16;
    obj.dynstr_suffixes_bounded = 1;
    memcpy(image + 464, "\0symbol\0", 8);
    symbols[1].st_name = 1;
    symbols[1].st_size = sizeof(uint64_t);

    for (size_t i = 0; i < RELOCATION_COUNT; i++) {
        uint64_t *slot = (uint64_t *)(image + TEST_DATA_OFFSET + i * 16);
        uint32_t symbol =
            (types[i] == ARCH_RELOC_RELATIVE ||
             types[i] == ARCH_RELOC_IRELATIVE) ? 0 : 1;

        before[i] = UINT64_C(0x1234000000000000) + i;
        memcpy(slot, &before[i], sizeof(before[i]));
        rela[i].r_offset = TEST_DATA_OFFSET + i * 16;
        rela[i].r_info = ELF64_R_INFO(symbol, types[i]);
        rela[i].r_addend =
            types[i] == ARCH_RELOC_IRELATIVE ? 1200 : 7;
    }

    if (pl_relocation_sources_admit(
            &obj, TEST_RELA_OFFSET,
            RELOCATION_COUNT * sizeof(Elf64_Rela),
            0, 0, 0, 0) < 0 ||
        pl_apply_rela(&obj, obj.rela, obj.rela_count) < 0)
        goto out;
    {
        uint64_t relative_value;

        memcpy(&relative_value, image + TEST_DATA_OFFSET,
               sizeof(relative_value));
        if (relative_value != obj.base + 7)
            goto out;
    }
    for (size_t i = 1; i < RELOCATION_COUNT; i++) {
        uint64_t current;

        memcpy(&current, image + TEST_DATA_OFFSET + i * 16,
               sizeof(current));
        if (current != before[i])
            goto out;
    }
    if (prelink_obj_collect_runtime_fixups(
            &obj, &fixups, &fixup_count, &fixup_capacity,
            &object_fixup_offset, &object_fixup_count) < 0 ||
        object_fixup_offset != 0 ||
        object_fixup_count != RELOCATION_COUNT - 1 ||
        fixup_count != RELOCATION_COUNT - 1)
        goto out;
    for (size_t i = 0; i < fixup_count; i++)
        if (fixups[i] != i + 1)
            goto out;
    valid = 1;

out:
    free(fixups);
    pl_relocation_sources_release(&obj);
    return valid && g_pl_relocation_snapshot_live_allocations == 0;
}

static int exact_version_record_gate(void)
{
    _Alignas(Elf64_Rela) unsigned char image[TEST_IMAGE_SIZE];
    struct prelink_obj obj;
    struct pl_control_range_builder builder = {0};
    Elf64_Phdr phdr;
    Elf64_Rela *rela;
    Elf64_Verdef *definition;
    Elf64_Verdaux *definition_aux;
    Elf64_Verneed *need;
    Elf64_Vernaux *need_aux;
    size_t record_bytes;
    size_t auxiliary_budget;
    uint64_t value;
    int valid = 0;

    memset(image, 0, sizeof(image));
    initialize_object(&obj, image, &phdr, 1);
    initialize_load(&phdr, PF_R | PF_W, 0, 0, sizeof(image));
    obj.dynstr = (const char *)(image + 1000);
    obj.dynstr_size = 64;
    memcpy(image + 1000, "\0VER_DEF\0", 9);
    memcpy(image + 1016, "libprovider.so\0", 15);
    memcpy(image + 1032, "VER_NEED\0", 9);

    definition = (Elf64_Verdef *)(image + 640);
    definition->vd_version = VER_DEF_CURRENT;
    definition->vd_ndx = 2;
    definition->vd_cnt = 1;
    definition->vd_hash = pl_sysv_hash_n("VER_DEF", 7);
    definition->vd_aux = 32;
    definition_aux = (Elf64_Verdaux *)(image + 672);
    definition_aux->vda_name = 1;

    need = (Elf64_Verneed *)(image + 720);
    need->vn_version = VER_NEED_CURRENT;
    need->vn_cnt = 1;
    need->vn_file = 16;
    need->vn_aux = 24;
    need_aux = (Elf64_Vernaux *)(image + 744);
    need_aux->vna_hash = pl_sysv_hash_n("VER_NEED", 8);
    need_aux->vna_other = 2;
    need_aux->vna_name = 32;

    rela = (Elf64_Rela *)(image + TEST_RELA_OFFSET);
    rela[0].r_offset = 664; /* Gap between Verdef and Verdaux. */
    rela[0].r_info = ELF64_R_INFO(0, ARCH_RELOC_RELATIVE);
    rela[0].r_addend = 11;
    obj.rela = rela;
    obj.rela_count = 1;

    if (!pl_version_file_budgets(
            &obj, &record_bytes, &auxiliary_budget) ||
        !pl_add_verdef_control_ranges(
            &obj, &builder, 640, 1, record_bytes,
            &auxiliary_budget) ||
        !pl_add_verneed_control_ranges(
            &obj, &builder, 720, 1, record_bytes,
            &auxiliary_budget) ||
        pl_relocation_sources_admit(
            &obj, TEST_RELA_OFFSET, sizeof(Elf64_Rela),
            0, 0, 0, 0) < 0 ||
        pl_control_authority_admit(&obj, &builder) < 0 ||
        pl_apply_rela(&obj, obj.rela, obj.rela_count) < 0)
        goto out;
    memcpy(&value, image + 664, sizeof(value));
    if (value != obj.base + 11 ||
        !pl_control_authority_unchanged(&obj))
        goto out;
    image[640] ^= 1;
    if (pl_control_authority_unchanged(&obj))
        goto out;
    image[640] ^= 1;
    valid = pl_control_authority_unchanged(&obj);

out:
    pl_control_range_builder_release(&builder);
    pl_control_authority_release(&obj);
    pl_relocation_sources_release(&obj);
    return valid && g_pl_relocation_snapshot_live_allocations == 0;
}

static int serialized_load_overlap_gate(void)
{
    _Alignas(Elf64_Rela) unsigned char image[TEST_IMAGE_SIZE];
    struct prelink_obj obj;
    Elf64_Phdr phdrs[2];

    for (size_t i = 0; i < 192; i++)
        image[i] = (unsigned char)(i * 3 + 1);
    memset(image + 256, 0xa5, 128);
    memcpy(image + 256, image + 64, 64);
    initialize_object(&obj, image, phdrs, 2);
    initialize_load(&phdrs[0], PF_R | PF_W, 0, 0, 128);
    initialize_load(&phdrs[1], PF_R | PF_W, 64, 256, 128);
    if (!pl_serialized_loads_coherent(&obj) ||
        g_pl_relocation_snapshot_live_allocations != 0)
        return 0;
    image[256 + 7] ^= 1;
    if (pl_serialized_loads_coherent(&obj))
        return 0;
    image[256 + 7] ^= 1;

    g_pl_relocation_snapshot_fail_allocation = 1;
    if (pl_serialized_loads_coherent(&obj) ||
        g_pl_relocation_snapshot_live_allocations != 0) {
        g_pl_relocation_snapshot_fail_allocation = 0;
        return 0;
    }
    g_pl_relocation_snapshot_fail_allocation = 0;

    /* Adjacent serialized ranges have no byte that needs reconciliation. */
    phdrs[1].p_offset = 128;
    image[256] ^= 0xff;
    return pl_serialized_loads_coherent(&obj) &&
           g_pl_relocation_snapshot_live_allocations == 0;
}

static int builder_contains(const struct pl_control_range_builder *builder,
                            uint64_t file_offset, size_t size,
                            enum pl_control_metadata_kind kind)
{
    for (size_t i = 0; i < builder->count; i++)
        if (builder->ranges[i].file_offset == file_offset &&
            builder->ranges[i].size == size &&
            builder->ranges[i].kind == kind)
            return 1;
    return 0;
}

static int section_and_property_control_gate(void)
{
    _Alignas(Elf64_Rela) unsigned char image[TEST_IMAGE_SIZE];
    struct prelink_obj obj;
    struct pl_control_range_builder builder = {0};
    struct dlfrz_entry entry = {0};
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)image;
    Elf64_Phdr phdrs[2];
    Elf64_Shdr *sections = (Elf64_Shdr *)(image + 256);
    FILE *file = NULL;
    int valid = 0;

    memset(image, 0, sizeof(image));
    initialize_object(&obj, image, phdrs, 2);
    initialize_load(&phdrs[0], PF_R | PF_W, 0, 0, sizeof(image));
    memset(&phdrs[1], 0, sizeof(phdrs[1]));
    phdrs[1].p_type = PT_GNU_PROPERTY;
    phdrs[1].p_offset = 900;
    phdrs[1].p_vaddr = 900;
    phdrs[1].p_filesz = 16;
    phdrs[1].p_memsz = 16;
    memcpy(image + sizeof(Elf64_Ehdr), phdrs, sizeof(phdrs));

    memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
    ehdr->e_phoff = sizeof(Elf64_Ehdr);
    ehdr->e_phnum = 2;
    ehdr->e_phentsize = sizeof(Elf64_Phdr);
    ehdr->e_shoff = 256;
    ehdr->e_shnum = 3;
    ehdr->e_shentsize = sizeof(Elf64_Shdr);
    sections[1].sh_type = SHT_SYMTAB;
    sections[1].sh_offset = 512;
    sections[1].sh_size = 2 * sizeof(Elf64_Sym);
    sections[1].sh_entsize = sizeof(Elf64_Sym);
    sections[1].sh_link = 2;
    sections[2].sh_type = SHT_STRTAB;
    sections[2].sh_offset = 600;
    sections[2].sh_size = 32;
    entry.data_size = sizeof(image);

    file = tmpfile();
    if (!file || fwrite(image, 1, sizeof(image), file) != sizeof(image) ||
        fflush(file) != 0 ||
        !pl_collect_object_control_ranges(
            file, &entry, ehdr, &obj, &builder) ||
        !builder_contains(&builder, 0, sizeof(*ehdr),
                          PL_CONTROL_ELF_HEADER) ||
        !builder_contains(&builder, sizeof(Elf64_Ehdr), sizeof(phdrs),
                          PL_CONTROL_PROGRAM_HEADERS) ||
        !builder_contains(&builder, 256, 3 * sizeof(Elf64_Shdr),
                          PL_CONTROL_SECTION_HEADERS) ||
        !builder_contains(&builder, 512, 2 * sizeof(Elf64_Sym),
                          PL_CONTROL_SECTION_SYMBOLS) ||
        !builder_contains(&builder, 600, 32,
                          PL_CONTROL_SECTION_STRINGS) ||
        !builder_contains(&builder, 900, 16,
                          PL_CONTROL_GNU_PROPERTY) ||
        pl_control_authority_admit(&obj, &builder) < 0)
        goto out;
    image[512] ^= 1;
    if (pl_control_authority_unchanged(&obj))
        goto out;
    valid = 1;

out:
    if (file)
        fclose(file);
    pl_control_range_builder_release(&builder);
    pl_control_authority_release(&obj);
    return valid && g_pl_relocation_snapshot_live_allocations == 0;
}

static int dynamic_mapped_and_serialized_gate(void)
{
    _Alignas(Elf64_Dyn) unsigned char image[TEST_IMAGE_SIZE];
    struct prelink_obj obj;
    struct pl_control_range_builder builder = {0};
    Elf64_Phdr phdrs[3];
    Elf64_Dyn *dynamic;
    int valid = 0;

    memset(image, 0x6d, sizeof(image));
    initialize_object(&obj, image, phdrs, 3);
    initialize_load(&phdrs[0], PF_R, 0, 1024, 512);
    initialize_load(&phdrs[1], PF_R | PF_W, 256, 1536, 64);
    memset(&phdrs[2], 0, sizeof(phdrs[2]));
    phdrs[2].p_type = PT_DYNAMIC;
    phdrs[2].p_offset = 256;
    phdrs[2].p_vaddr = 1152;
    phdrs[2].p_filesz = 4 * sizeof(Elf64_Dyn);
    phdrs[2].p_memsz = phdrs[2].p_filesz;
    dynamic = (Elf64_Dyn *)(image + 1152);
    memset(dynamic, 0, 4 * sizeof(*dynamic));
    dynamic[0].d_tag = DT_NULL;

    if (pl_parse_dynamic(&obj, obj.base, obj.phdr_base,
                         obj.phdr_num, obj.phdr_entsz,
                         &builder) < 0 ||
        obj.control_range_count != 2 ||
        obj.control_writable_view_count != 1 ||
        !pl_control_authority_unchanged(&obj))
        goto out;
    /* Bytes after DT_NULL remain public serialized PT_DYNAMIC state and are
     * part of the same authority, even though semantic parsing stopped. */
    image[1536 + 3 * sizeof(Elf64_Dyn) + 1] ^= 1;
    if (pl_control_authority_unchanged(&obj))
        goto out;
    valid = 1;

out:
    pl_control_range_builder_release(&builder);
    pl_control_authority_release(&obj);
    pl_relocation_sources_release(&obj);
    return valid && g_pl_relocation_snapshot_live_allocations == 0;
}

static void initialize_dynamic_string_fixture(
    struct prelink_obj *obj,
    unsigned char image[TEST_IMAGE_SIZE], Elf64_Phdr phdrs[2],
    uint32_t name_offset, int malformed_final)
{
    enum {
        DYNAMIC_OFFSET = 256,
        DYNSYM_OFFSET = 512,
        DYNSTR_OFFSET = 560,
        DYNSTR_SIZE = 32,
        HASH_OFFSET = 640
    };
    Elf64_Dyn *dynamic;
    Elf64_Sym *symbols;
    uint32_t *hash;

    memset(image, 0, TEST_IMAGE_SIZE);
    initialize_object(obj, image, phdrs, 2);
    initialize_load(&phdrs[0], PF_R | PF_W, 0, 0, TEST_IMAGE_SIZE);
    phdrs[1].p_type = PT_DYNAMIC;
    phdrs[1].p_flags = PF_R | PF_W;
    phdrs[1].p_offset = DYNAMIC_OFFSET;
    phdrs[1].p_vaddr = DYNAMIC_OFFSET;
    phdrs[1].p_filesz = 6 * sizeof(Elf64_Dyn);
    phdrs[1].p_memsz = phdrs[1].p_filesz;
    phdrs[1].p_align = _Alignof(Elf64_Dyn);

    dynamic = (Elf64_Dyn *)(void *)(image + DYNAMIC_OFFSET);
    dynamic[0].d_tag = DT_SYMTAB;
    dynamic[0].d_un.d_ptr = DYNSYM_OFFSET;
    dynamic[1].d_tag = DT_STRTAB;
    dynamic[1].d_un.d_ptr = DYNSTR_OFFSET;
    dynamic[2].d_tag = DT_STRSZ;
    dynamic[2].d_un.d_val = DYNSTR_SIZE;
    dynamic[3].d_tag = DT_SYMENT;
    dynamic[3].d_un.d_val = sizeof(Elf64_Sym);
    dynamic[4].d_tag = DT_HASH;
    dynamic[4].d_un.d_ptr = HASH_OFFSET;
    dynamic[5].d_tag = DT_NULL;

    symbols = (Elf64_Sym *)(void *)(image + DYNSYM_OFFSET);
    symbols[1].st_name = name_offset;
    memcpy(image + DYNSTR_OFFSET + 1, "overlap", sizeof("overlap"));
    memcpy(image + DYNSTR_OFFSET + 16, "unused", sizeof("unused"));
    if (malformed_final)
        image[DYNSTR_OFFSET + DYNSTR_SIZE - 1] = 'X';

    hash = (uint32_t *)(void *)(image + HASH_OFFSET);
    hash[0] = 1; /* nbuckets */
    hash[1] = 2; /* nchain */
    hash[2] = 1; /* bucket */
    hash[3] = 0;
    hash[4] = 0;
}

static int dynamic_string_table_gate(void)
{
    _Alignas(Elf64_Dyn) unsigned char image[TEST_IMAGE_SIZE];
    struct prelink_obj obj;
    struct pl_control_range_builder builder = {0};
    Elf64_Phdr phdrs[2];
    const char *name;

    /* Byte two is an overlapping suffix of the string beginning at byte
     * one.  Complete-table admission must accept both string starts and
     * arbitrary in-range suffixes. */
    initialize_dynamic_string_fixture(&obj, image, phdrs, 2, 0);
    if (pl_parse_dynamic(&obj, obj.base, obj.phdr_base,
                         obj.phdr_num, obj.phdr_entsz, &builder) < 0 ||
        !obj.dynstr_suffixes_bounded || obj.dynsym_count != 2 ||
        !(name = pl_symbol_name(&obj, &obj.dynsym[1])) ||
        strcmp(name, "verlap") != 0) {
        pl_control_range_builder_release(&builder);
        pl_control_authority_release(&obj);
        pl_relocation_sources_release(&obj);
        return 0;
    }
    pl_control_range_builder_release(&builder);
    pl_control_authority_release(&obj);
    pl_relocation_sources_release(&obj);

    /* The referenced suffix terminates well before DT_STRSZ.  Corrupt only
     * the unused declared final byte so rejection proves the table-level
     * sentinel, rather than a per-symbol tail scan, is authoritative. */
    memset(&builder, 0, sizeof(builder));
    initialize_dynamic_string_fixture(&obj, image, phdrs, 2, 1);
    if (pl_parse_dynamic(&obj, obj.base, obj.phdr_base,
                         obj.phdr_num, obj.phdr_entsz, &builder) == 0) {
        pl_control_range_builder_release(&builder);
        pl_control_authority_release(&obj);
        pl_relocation_sources_release(&obj);
        return 0;
    }
    pl_control_range_builder_release(&builder);
    pl_control_authority_release(&obj);
    pl_relocation_sources_release(&obj);

    /* Sentinel admission does not relax the independent st_name bound. */
    memset(&builder, 0, sizeof(builder));
    initialize_dynamic_string_fixture(&obj, image, phdrs, 32, 0);
    if (pl_parse_dynamic(&obj, obj.base, obj.phdr_base,
                         obj.phdr_num, obj.phdr_entsz, &builder) == 0) {
        pl_control_range_builder_release(&builder);
        pl_control_authority_release(&obj);
        pl_relocation_sources_release(&obj);
        return 0;
    }
    pl_control_range_builder_release(&builder);
    pl_control_authority_release(&obj);
    pl_relocation_sources_release(&obj);
    return g_pl_relocation_snapshot_live_allocations == 0;
}

static int section_string_table_gate(void)
{
    char strings[32] = {0};
    Elf64_Shdr section = {0};
    struct bounded_elf_sections table = {0};
    char *copy = NULL;
    size_t copy_size = 0;
    FILE *file;
    int valid = 0;

    memcpy(strings + 1, "overlap", sizeof("overlap"));
    memcpy(strings + 16, "unused", sizeof("unused"));
    file = tmpfile();
    if (!file || fwrite(strings, 1, sizeof(strings), file) !=
                     sizeof(strings) || fflush(file) != 0)
        goto out;
    section.sh_type = SHT_STRTAB;
    section.sh_offset = 0;
    section.sh_size = sizeof(strings);
    table.fd = fileno(file);
    table.file_size = sizeof(strings);
    table.items = &section;
    table.count = 1;

    if (bounded_elf_section_read(
            &table, 0, (void **)&copy, &copy_size) < 0 ||
        copy_size != sizeof(strings) || strcmp(copy + 2, "verlap") != 0)
        goto out;
    free(copy);
    copy = NULL;

    /* The referenced overlapping suffix still has an internal terminator;
     * only the complete section's required final sentinel is malformed. */
    if (pwrite(table.fd, "X", 1, (off_t)sizeof(strings) - 1) != 1 ||
        bounded_elf_section_read(
            &table, 0, (void **)&copy, &copy_size) == 0)
        goto out;

    /* ELF explicitly permits an empty string-table section.  It contains no
     * suffix to validate; every actual symbol-name offset is rejected later
     * by the ordinary offset-versus-size check. */
    section.sh_offset = sizeof(strings);
    section.sh_size = 0;
    if (bounded_elf_section_read(
            &table, 0, (void **)&copy, &copy_size) < 0 || copy_size != 0)
        goto out;
    free(copy);
    copy = NULL;
    valid = 1;

out:
    free(copy);
    if (file)
        fclose(file);
    return valid;
}

int main(void)
{
    if (!overlap_component_alias_gate()) return 1;
    if (!immutable_and_failure_gate()) return 2;
    if (!same_table_store_gate()) return 3;
    if (!relr_cross_table_store_gate()) return 4;
    if (!relr_persisted_rela_overlap_gate()) return 5;
    if (!control_metadata_store_gate()) return 6;
    if (!control_snapshot_and_alias_gate()) return 7;
    if (!symbolic_relocations_deferred_gate()) return 8;
    if (!exact_version_record_gate()) return 9;
    if (!serialized_load_overlap_gate()) return 10;
    if (!section_and_property_control_gate()) return 11;
    if (!dynamic_mapped_and_serialized_gate()) return 12;
    if (!dynamic_string_table_gate()) return 13;
    if (!section_string_table_gate()) return 14;
    return 0;
}
