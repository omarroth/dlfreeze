#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define GNU_UNIQUE_REGISTRY_INITIAL 32U
#define GNU_UNIQUE_REGISTRY_MAX 4096U
#define GNU_UNIQUE_BUCKET_COUNT 1024U
#define DLFREEZE_RELR_REPLAY_GATE 1

#include "../src/loader.c"

static void gate_object_init(struct loaded_obj *obj, uint8_t *image,
                             size_t image_size, Elf64_Phdr *phdr,
                             uint16_t phdr_count)
{
    memset(obj, 0, sizeof(*obj));
    memset(phdr, 0, (size_t)phdr_count * sizeof(*phdr));
    obj->base = (uintptr_t)image;
    obj->phdr = phdr;
    obj->phdr_num = phdr_count;
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R | PF_W;
    phdr[0].p_filesz = image_size;
    phdr[0].p_memsz = image_size;
}

static int gate_replay_requires_complete_admission(void)
{
    _Alignas(8) uint8_t image[512] = {0};
    Elf64_Phdr phdr[1];
    Elf64_Relr *relr = (Elf64_Relr *)(void *)(image + 64);
    Elf64_Rela bad_rela = {0};
    struct loaded_obj obj;

    gate_object_init(&obj, image, sizeof(image), phdr, 1);
    *relr = 256;
    relocation_store_u64(image + 256, 7);
    obj.relr = relr;
    obj.relr_count = 1;
    if (walk_relr(&obj, 1) == 0 || relocation_load_u64(image + 256) != 7)
        return 0;

    memset(&obj, 0, sizeof(obj));
    gate_object_init(&obj, image, sizeof(image), phdr, 1);
    bad_rela.r_offset = 264;
    bad_rela.r_info = ELF64_R_INFO(1, ARCH_RELOC_RELATIVE);
    if (publish_loaded_relocation_authority(
            &obj, &bad_rela, 1, NULL, 0, relr, 1) < 0)
        return 0;
    if (validate_object_relocations(&obj) == 0 ||
        obj.relr_replay_state != LOADED_RELR_UNADMITTED ||
        walk_relr(&obj, 1) == 0 ||
        relocation_load_u64(image + 256) != 7) {
        dl_release_runtime_mapping(&obj);
        return 0;
    }
    dl_release_runtime_mapping(&obj);
    return 1;
}

static int gate_prelinked_relr_is_replayed_once(void)
{
    _Alignas(8) uint8_t image[512] = {0};
    Elf64_Phdr phdr[1];
    Elf64_Relr entry = 256;
    struct loaded_obj obj;
    uint64_t serialized = UINT64_C(0x1020304050607080);

    gate_object_init(&obj, image, sizeof(image), phdr, 1);
    obj.flags = LDR_FLAG_PRELINKED;
    relocation_store_u64(image + 256, serialized);
    if (publish_loaded_relocation_authority(
            &obj, NULL, 0, NULL, 0, &entry, 1) < 0)
        return 0;
    if (validate_object_relocations(&obj) < 0 ||
        obj.relr_replay_state != LOADED_RELR_ADMITTED ||
        relocation_load_u64(image + 256) != serialized ||
        walk_relr(&obj, 1) < 0 ||
        obj.relr_replay_state != LOADED_RELR_REPLAYED ||
        relocation_load_u64(image + 256) !=
            serialized + (uint64_t)(uintptr_t)image ||
        walk_relr(&obj, 1) == 0 ||
        relocation_load_u64(image + 256) !=
            serialized + (uint64_t)(uintptr_t)image) {
        dl_release_runtime_mapping(&obj);
        return 0;
    }
    dl_release_runtime_mapping(&obj);
    return 1;
}

static int gate_empty_and_inconsistent_tables(void)
{
    _Alignas(8) uint8_t image[512] = {0};
    Elf64_Phdr phdr[1];
    Elf64_Relr entry = 256;
    struct loaded_obj obj;
    uint64_t sentinel = UINT64_C(0xa5a5a5a55a5a5a5a);

    gate_object_init(&obj, image, sizeof(image), phdr, 1);
    relocation_store_u64(image + 256, sentinel);
    if (validate_object_relocations(&obj) < 0 ||
        obj.relr_replay_state != LOADED_RELR_UNADMITTED ||
        walk_relr(&obj, 1) < 0 ||
        obj.relr_replay_state != LOADED_RELR_UNADMITTED ||
        relocation_load_u64(image + 256) != sentinel)
        return 0;

    gate_object_init(&obj, image, sizeof(image), phdr, 1);
    obj.flags = LDR_FLAG_PRELINKED;
    if (validate_object_relocations(&obj) < 0 ||
        obj.relr_replay_state != LOADED_RELR_UNADMITTED ||
        walk_relr(&obj, 1) < 0 ||
        obj.relr_replay_state != LOADED_RELR_UNADMITTED ||
        relocation_load_u64(image + 256) != sentinel)
        return 0;

    gate_object_init(&obj, image, sizeof(image), phdr, 1);
    obj.relr = &entry;
    if (validate_object_relocations(&obj) == 0 ||
        obj.relr_replay_state != LOADED_RELR_UNADMITTED ||
        walk_relr(&obj, 1) == 0 ||
        relocation_load_u64(image + 256) != sentinel)
        return 0;

    gate_object_init(&obj, image, sizeof(image), phdr, 1);
    obj.relr_count = 1;
    if (validate_object_relocations(&obj) == 0 ||
        obj.relr_replay_state != LOADED_RELR_UNADMITTED ||
        walk_relr(&obj, 1) == 0 ||
        relocation_load_u64(image + 256) != sentinel)
        return 0;
    return 1;
}

static int gate_chained_bitmaps_and_address_reset(void)
{
    _Alignas(8) uint8_t image[2048] = {0};
    Elf64_Phdr phdr[1];
    Elf64_Relr entries[5];
    struct loaded_obj obj;
    uint64_t base = (uint64_t)(uintptr_t)image;

    gate_object_init(&obj, image, sizeof(image), phdr, 1);
    entries[0] = 258;
    entries[1] = 1;          /* Empty bitmap still advances the cursor. */
    entries[2] = UINT64_MAX; /* Every one of the 63 bitmap slots. */
    entries[3] = 1538;       /* A direct entry resets the bitmap cursor. */
    entries[4] = 3;
    relocation_store_u64(image + 258, 1);
    for (unsigned int i = 0; i < 63; i++)
        relocation_store_u64(image + 770 + (size_t)i * 8, 2 + i);
    relocation_store_u64(image + 1538, 65);
    relocation_store_u64(image + 1546, 66);

    if (publish_loaded_relocation_authority(
            &obj, NULL, 0, NULL, 0, entries, 5) < 0 ||
        validate_object_relocations(&obj) < 0 || walk_relr(&obj, 1) < 0 ||
        relocation_load_u64(image + 258) != base + 1 ||
        relocation_load_u64(image + 1538) != base + 65 ||
        relocation_load_u64(image + 1546) != base + 66) {
        dl_release_runtime_mapping(&obj);
        return 0;
    }
    for (unsigned int i = 0; i < 63; i++) {
        if (relocation_load_u64(image + 770 + (size_t)i * 8) !=
            base + 2 + i) {
            dl_release_runtime_mapping(&obj);
            return 0;
        }
    }
    dl_release_runtime_mapping(&obj);
    return 1;
}

static int gate_bss_end_boundary(void)
{
    _Alignas(8) uint8_t image[520] = {0};
    Elf64_Phdr phdr[1];
    Elf64_Relr entry;
    struct loaded_obj obj;
    uint64_t base = (uint64_t)(uintptr_t)image;
    uint64_t sentinel = UINT64_C(0x1122334455667788);

    gate_object_init(&obj, image, sizeof(image), phdr, 1);
    phdr[0].p_filesz = 256;
    phdr[0].p_memsz = 512;
    entry = 504;
    relocation_store_u64(image + 504, 7);
    if (publish_loaded_relocation_authority(
            &obj, NULL, 0, NULL, 0, &entry, 1) < 0 ||
        validate_object_relocations(&obj) < 0 || walk_relr(&obj, 1) < 0 ||
        relocation_load_u64(image + 504) != base + 7) {
        dl_release_runtime_mapping(&obj);
        return 0;
    }
    dl_release_runtime_mapping(&obj);

    /* An even, intentionally unaligned encoding is valid, but the complete
     * destination still has to fit: this one crosses the same p_memsz end. */
    gate_object_init(&obj, image, sizeof(image), phdr, 1);
    phdr[0].p_filesz = 256;
    phdr[0].p_memsz = 512;
    entry = 506;
    relocation_store_u64(image + 506, sentinel);
    if (publish_loaded_relocation_authority(
            &obj, NULL, 0, NULL, 0, &entry, 1) < 0)
        return 0;
    if (validate_object_relocations(&obj) == 0 ||
        obj.relr_replay_state != LOADED_RELR_UNADMITTED ||
        walk_relr(&obj, 1) == 0 ||
        relocation_load_u64(image + 506) != sentinel) {
        dl_release_runtime_mapping(&obj);
        return 0;
    }
    dl_release_runtime_mapping(&obj);
    return 1;
}

static int gate_malformed_relr_rejected(void)
{
    _Alignas(8) uint8_t image[512] = {0};
    Elf64_Phdr phdr[1];
    Elf64_Relr entries[2];
    struct loaded_obj obj;

    gate_object_init(&obj, image, sizeof(image), phdr, 1);
    entries[0] = 3; /* A bitmap cannot precede its address entry. */
    if (publish_loaded_relocation_authority(
            &obj, NULL, 0, NULL, 0, entries, 1) < 0)
        return 0;
    if (validate_object_relocations(&obj) == 0 ||
        obj.relr_replay_state != LOADED_RELR_UNADMITTED) {
        dl_release_runtime_mapping(&obj);
        return 0;
    }
    dl_release_runtime_mapping(&obj);

    gate_object_init(&obj, image, sizeof(image), phdr, 1);
    entries[0] = 258; /* Every even address is representable, including
                       * destinations which are not pointer-aligned. */
    entries[1] = 3;
    relocation_store_u64(image + 258, 6);
    relocation_store_u64(image + 266, 7);
    if (publish_loaded_relocation_authority(
            &obj, NULL, 0, NULL, 0, entries, 2) < 0)
        return 0;
    if (validate_object_relocations(&obj) < 0 || walk_relr(&obj, 1) < 0 ||
        relocation_load_u64(image + 258) !=
            (uint64_t)(uintptr_t)image + 6 ||
        relocation_load_u64(image + 266) !=
            (uint64_t)(uintptr_t)image + 7) {
        dl_release_runtime_mapping(&obj);
        return 0;
    }
    dl_release_runtime_mapping(&obj);

    gate_object_init(&obj, image, sizeof(image), phdr, 1);
    phdr[0].p_flags = PF_R;
    entries[0] = 256;
    if (publish_loaded_relocation_authority(
            &obj, NULL, 0, NULL, 0, entries, 1) < 0)
        return 0;
    if (validate_object_relocations(&obj) == 0) {
        dl_release_runtime_mapping(&obj);
        return 0;
    }
    dl_release_runtime_mapping(&obj);

    /* Exercise the bitmap-cursor overflow independently of a real mapping.
     * Validation never dereferences a relocation destination. */
    memset(&obj, 0, sizeof(obj));
    memset(phdr, 0, sizeof(phdr));
    obj.phdr = phdr;
    obj.phdr_num = 1;
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R | PF_W;
    phdr[0].p_vaddr = UINT64_MAX - 503;
    phdr[0].p_memsz = 504;
    entries[0] = UINT64_MAX - 503;
    entries[1] = 3;
    if (publish_loaded_relocation_authority(
            &obj, NULL, 0, NULL, 0, entries, 2) < 0)
        return 0;
    if (validate_object_relocations(&obj) == 0) {
        dl_release_runtime_mapping(&obj);
        return 0;
    }
    dl_release_runtime_mapping(&obj);
    return 1;
}

static int gate_frontier_matches_linear_scan(void)
{
    _Alignas(8) uint8_t image[2048] = {0};
    Elf64_Phdr phdr[6];
    struct loaded_obj obj;
    struct relr_writable_load_index index;
    static const size_t sizes[] = {1, sizeof(uint64_t), 31};

    gate_object_init(&obj, image, sizeof(image), phdr, 6);
    phdr[0].p_flags = PF_W; /* Write-only is a valid writable owner. */
    phdr[0].p_vaddr = 64;
    phdr[0].p_memsz = 448;  /* [64, 512) */
    phdr[1].p_type = PT_LOAD;
    phdr[1].p_flags = PF_R | PF_W;
    phdr[1].p_vaddr = 128;
    phdr[1].p_memsz = 72;   /* Nested and dominated by header 0. */
    phdr[2].p_type = PT_LOAD;
    phdr[2].p_flags = PF_R;
    phdr[2].p_vaddr = 160;
    phdr[2].p_memsz = 540;  /* A read-only overlap does not veto PF_W. */
    phdr[3].p_type = PT_LOAD;
    phdr[3].p_flags = PF_R | PF_W;
    phdr[3].p_vaddr = 400;
    phdr[3].p_memsz = 400;  /* Extends the writable maximum to 800. */
    phdr[4].p_type = PT_LOAD;
    phdr[4].p_flags = PF_W;
    phdr[4].p_vaddr = 800;
    phdr[4].p_memsz = 100;  /* Adjacent, not merged with header 3. */
    phdr[5].p_type = PT_LOAD;
    phdr[5].p_flags = PF_W;
    phdr[5].p_vaddr = 900;
    phdr[5].p_memsz = 0;

    if (relr_writable_load_index_init(&obj, &index) < 0)
        return 0;
    for (uint64_t vaddr = 0; vaddr < 1000; vaddr += 2) {
        for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
            int linear = loaded_obj_vaddr_pointer(
                &obj, vaddr, sizes[i], PF_W, NULL);
            int indexed = relr_writable_load_index_contains(
                &index, vaddr, sizes[i]);

            if (linear != indexed) {
                relr_writable_load_index_release(&index);
                return 0;
            }
        }
    }
    relr_writable_load_index_release(&index);

    /* Equal PT_LOAD starts are valid in the containment predicate.  Whichever
     * order their headers use, the frontier must retain/select the interval
     * with the greatest end. */
    for (unsigned int longer_first = 0; longer_first < 2; longer_first++) {
        gate_object_init(&obj, image, sizeof(image), phdr, 2);
        phdr[0].p_flags = PF_W;
        phdr[0].p_vaddr = 64;
        phdr[0].p_memsz = longer_first ? 256 : 64;
        phdr[1].p_type = PT_LOAD;
        phdr[1].p_flags = PF_W;
        phdr[1].p_vaddr = 64;
        phdr[1].p_memsz = longer_first ? 64 : 256;
        if (relr_writable_load_index_init(&obj, &index) < 0)
            return 0;
        for (uint64_t vaddr = 0; vaddr < 340; vaddr += 2) {
            int linear = loaded_obj_vaddr_pointer(
                &obj, vaddr, sizeof(uint64_t), PF_W, NULL);
            int indexed = relr_writable_load_index_contains(
                &index, vaddr, sizeof(uint64_t));

            if (linear != indexed) {
                relr_writable_load_index_release(&index);
                return 0;
            }
        }
        relr_writable_load_index_release(&index);
    }
    return 1;
}

static int gate_arbitrary_direct_order_and_duplicates(void)
{
    _Alignas(8) uint8_t image[1024] = {0};
    Elf64_Phdr phdr[1];
    Elf64_Relr entries[3] = {640, 256, 256};
    struct loaded_obj obj;
    uint64_t base = (uint64_t)(uintptr_t)image;
    uint64_t duplicate_expected = 7;

    gate_object_init(&obj, image, sizeof(image), phdr, 1);
    relocation_store_u64(image + 640, 5);
    relocation_store_u64(image + 256, 7);
    if (publish_loaded_relocation_authority(
            &obj, NULL, 0, NULL, 0, entries, 3) < 0 ||
        validate_object_relocations(&obj) < 0 ||
        walk_relr(&obj, 1) < 0) {
        dl_release_runtime_mapping(&obj);
        return 0;
    }
    duplicate_expected += base;
    duplicate_expected += base;
    if (relocation_load_u64(image + 640) != base + 5 ||
        relocation_load_u64(image + 256) != duplicate_expected) {
        dl_release_runtime_mapping(&obj);
        return 0;
    }
    dl_release_runtime_mapping(&obj);
    return 1;
}

static int gate_adjacent_writable_straddle_rejected(void)
{
    _Alignas(8) uint8_t image[512] = {0};
    Elf64_Phdr phdr[2];
    Elf64_Relr entry = 186;
    struct loaded_obj obj;
    uint64_t sentinel = UINT64_C(0x1020304050607080);

    gate_object_init(&obj, image, sizeof(image), phdr, 2);
    phdr[0].p_vaddr = 64;
    phdr[0].p_memsz = 128; /* [64, 192) */
    phdr[1].p_type = PT_LOAD;
    phdr[1].p_flags = PF_W;
    phdr[1].p_vaddr = 192;
    phdr[1].p_memsz = 128; /* [192, 320) */
    relocation_store_u64(image + 186, sentinel);
    if (publish_loaded_relocation_authority(
            &obj, NULL, 0, NULL, 0, &entry, 1) < 0)
        return 0;
    if (validate_object_relocations(&obj) == 0 ||
        obj.relr_replay_state != LOADED_RELR_UNADMITTED ||
        relocation_load_u64(image + 186) != sentinel) {
        dl_release_runtime_mapping(&obj);
        return 0;
    }
    dl_release_runtime_mapping(&obj);
    return 1;
}

static void gate_many_writable_loads_init(
    struct loaded_obj *obj, uint8_t *image, size_t image_size,
    Elf64_Phdr *phdr, size_t count)
{
    gate_object_init(obj, image, image_size, phdr, (uint16_t)count);
    for (size_t i = 0; i < count; i++) {
        phdr[i].p_type = PT_LOAD;
        phdr[i].p_flags = PF_W;
        phdr[i].p_vaddr = 128 + i * 128;
        phdr[i].p_memsz = 64;
    }
}

static int gate_frontier_mapping_and_allocation_failure(void)
{
    enum { LOAD_COUNT = RELR_WRITABLE_FRONTIER_INLINE + 2 };
    _Alignas(8) uint8_t image[2048] = {0};
    Elf64_Phdr phdr[LOAD_COUNT];
    Elf64_Relr entries[LOAD_COUNT];
    struct loaded_obj obj;
    uint64_t base = (uint64_t)(uintptr_t)image;

    gate_many_writable_loads_init(
        &obj, image, sizeof(image), phdr, LOAD_COUNT);
    for (size_t i = 0; i < LOAD_COUNT; i++) {
        size_t reverse = LOAD_COUNT - 1 - i;
        uint64_t offset = phdr[reverse].p_vaddr + 2;

        entries[i] = offset;
        relocation_store_u64(image + offset, i + 1);
    }
    if (publish_loaded_relocation_authority(
            &obj, NULL, 0, NULL, 0, entries, LOAD_COUNT) < 0)
        return 0;
    g_relr_writable_index_phdr_visits = 0;
    g_relr_writable_index_queries = 0;
    g_relr_writable_index_mmaps = 0;
    if (validate_object_relocations(&obj) < 0 ||
        g_relr_writable_index_phdr_visits != 2 * LOAD_COUNT ||
        g_relr_writable_index_queries != LOAD_COUNT ||
        g_relr_writable_index_mmaps != 1 || walk_relr(&obj, 1) < 0) {
        dl_release_runtime_mapping(&obj);
        return 0;
    }
    for (size_t i = 0; i < LOAD_COUNT; i++) {
        size_t reverse = LOAD_COUNT - 1 - i;
        uint64_t offset = phdr[reverse].p_vaddr + 2;

        if (relocation_load_u64(image + offset) != base + i + 1) {
            dl_release_runtime_mapping(&obj);
            return 0;
        }
    }
    dl_release_runtime_mapping(&obj);

    memset(image, 0, sizeof(image));
    gate_many_writable_loads_init(
        &obj, image, sizeof(image), phdr, LOAD_COUNT);
    for (size_t i = 0; i < LOAD_COUNT; i++) {
        entries[i] = phdr[i].p_vaddr + 2;
        relocation_store_u64(image + entries[i], UINT64_C(0x55aa));
    }
    if (publish_loaded_relocation_authority(
            &obj, NULL, 0, NULL, 0, entries, LOAD_COUNT) < 0)
        return 0;
    g_relr_writable_index_phdr_visits = 0;
    g_relr_writable_index_queries = 0;
    g_relr_writable_index_mmaps = 0;
    g_loaded_obj_vaddr_pointer_calls = 0;
    g_relr_writable_index_force_allocation_failure = 1;
    if (validate_object_relocations(&obj) < 0 ||
        obj.relr_replay_state != LOADED_RELR_ADMITTED ||
        g_relr_writable_index_phdr_visits != LOAD_COUNT ||
        g_relr_writable_index_queries != LOAD_COUNT ||
        g_relr_writable_index_mmaps != 0 ||
        g_loaded_obj_vaddr_pointer_calls != LOAD_COUNT) {
        g_relr_writable_index_force_allocation_failure = 0;
        dl_release_runtime_mapping(&obj);
        return 0;
    }
    g_relr_writable_index_force_allocation_failure = 0;
    for (size_t i = 0; i < LOAD_COUNT; i++) {
        if (relocation_load_u64(image + entries[i]) != UINT64_C(0x55aa)) {
            dl_release_runtime_mapping(&obj);
            return 0;
        }
    }
    if (walk_relr(&obj, 1) < 0) {
        dl_release_runtime_mapping(&obj);
        return 0;
    }
    for (size_t i = 0; i < LOAD_COUNT; i++) {
        if (relocation_load_u64(image + entries[i]) !=
            base + UINT64_C(0x55aa)) {
            dl_release_runtime_mapping(&obj);
            return 0;
        }
    }
    dl_release_runtime_mapping(&obj);
    return 1;
}

static int gate_runtime_destination_overflow_rejected(void)
{
    Elf64_Phdr phdr[1] = {{0}};
    Elf64_Relr entry = 256;
    struct loaded_obj obj = {0};

    obj.base = UINTPTR_MAX - 260;
    obj.phdr = phdr;
    obj.phdr_num = 1;
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_W;
    phdr[0].p_vaddr = 256;
    phdr[0].p_memsz = 16;
    if (publish_loaded_relocation_authority(
            &obj, NULL, 0, NULL, 0, &entry, 1) < 0)
        return 0;
    if (validate_object_relocations(&obj) == 0 ||
        obj.relr_replay_state != LOADED_RELR_UNADMITTED) {
        dl_release_runtime_mapping(&obj);
        return 0;
    }
    dl_release_runtime_mapping(&obj);
    return 1;
}

static int gate_high_cardinality_phdr_complexity(void)
{
    enum { DESTINATION_COUNT = 257 };
    const size_t phdr_count = (size_t)PN_XNUM - 1;
    const size_t phdr_size = phdr_count * sizeof(Elf64_Phdr);
    _Alignas(8) uint8_t image[512] = {0};
    Elf64_Relr entries[DESTINATION_COUNT];
    Elf64_Phdr *phdr;
    struct loaded_obj obj = {0};
    int result = 0;

    phdr = mmap(NULL, phdr_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (phdr == MAP_FAILED)
        return 0;
    memset(phdr, 0, phdr_size);
    phdr[phdr_count - 1].p_type = PT_LOAD;
    phdr[phdr_count - 1].p_flags = PF_W;
    phdr[phdr_count - 1].p_filesz = sizeof(image);
    phdr[phdr_count - 1].p_memsz = sizeof(image);
    obj.base = (uintptr_t)image;
    obj.phdr = phdr;
    obj.phdr_num = (uint16_t)phdr_count;
    for (size_t i = 0; i < DESTINATION_COUNT; i++)
        entries[i] = 256;

    if (publish_loaded_relocation_authority(
            &obj, NULL, 0, NULL, 0, entries,
            DESTINATION_COUNT) < 0)
        goto out;
    g_loaded_obj_vaddr_pointer_calls = 0;
    g_relr_writable_index_phdr_visits = 0;
    g_relr_writable_index_queries = 0;
    g_relr_writable_index_mmaps = 0;
    if (validate_object_relocations(&obj) < 0 ||
        obj.relr_replay_state != LOADED_RELR_ADMITTED ||
        g_relr_writable_index_phdr_visits != phdr_count ||
        g_relr_writable_index_queries != DESTINATION_COUNT ||
        g_relr_writable_index_mmaps != 0 ||
        g_loaded_obj_vaddr_pointer_calls != 0)
        goto out;
    result = 1;

out:
    dl_release_runtime_mapping(&obj);
    (void)munmap(phdr, phdr_size);
    return result;
}

static int gate_writable_authority_and_fast_replay(void)
{
    _Alignas(8) uint8_t image[512] = {0};
    Elf64_Phdr phdr[2];
    Elf64_Relr *relr = (Elf64_Relr *)(void *)(image + 64);
    struct loaded_obj obj;
    size_t admitted_queries;
    uint64_t expected0;
    uint64_t expected1;
    uint64_t expected2;

    gate_object_init(&obj, image, sizeof(image), phdr, 2);
    phdr[1].p_type = PT_GNU_RELRO;
    phdr[1].p_vaddr = 256;
    phdr[1].p_memsz = 64;
    /* The first relocation overlaps the live writable RELR table itself.
     * Later entries must still come from the copied admission authority. */
    relr[0] = 64;
    relr[1] = 256;
    relr[2] = ((UINT64_C(1) << 0 | UINT64_C(1) << 2) << 1) | 1;
    relocation_store_u64(image + 256, 1);
    relocation_store_u64(image + 264, 2);
    relocation_store_u64(image + 280, 3);
    relocation_store_u64(image + 400, 9);

    if (publish_loaded_relocation_authority(
            &obj, NULL, 0, NULL, 0, relr, 3) < 0 ||
        !obj.runtime_relocation_mapping)
        return 0;
    /* A target write to its writable DT_RELR table cannot redirect replay. */
    relr[0] = 400;
    g_loaded_obj_vaddr_pointer_calls = 0;
    g_relr_writable_index_queries = 0;
    if (validate_object_relocations(&obj) < 0 ||
        obj.relr_replay_state != LOADED_RELR_ADMITTED ||
        g_relr_writable_index_queries != 4 ||
        g_loaded_obj_vaddr_pointer_calls != 0) {
        dl_release_runtime_mapping(&obj);
        return 0;
    }
    admitted_queries = g_relr_writable_index_queries;
    expected0 = (uint64_t)(uintptr_t)image + 1;
    expected1 = (uint64_t)(uintptr_t)image + 2;
    expected2 = (uint64_t)(uintptr_t)image + 3;
    if (walk_relr(&obj, 1) < 0 ||
        obj.relr_replay_state != LOADED_RELR_REPLAYED ||
        g_relr_writable_index_queries != admitted_queries ||
        g_loaded_obj_vaddr_pointer_calls != 0 ||
        relocation_load_u64(image + 64) !=
            (uint64_t)(uintptr_t)image + 400 ||
        relocation_load_u64(image + 256) != expected0 ||
        relocation_load_u64(image + 264) != expected1 ||
        relocation_load_u64(image + 280) != expected2 ||
        relocation_load_u64(image + 400) != 9) {
        dl_release_runtime_mapping(&obj);
        return 0;
    }
    if (walk_relr(&obj, 1) == 0 ||
        relocation_load_u64(image + 256) != expected0) {
        dl_release_runtime_mapping(&obj);
        return 0;
    }
    dl_release_runtime_mapping(&obj);
    return obj.relr_replay_state == LOADED_RELR_UNADMITTED &&
        !obj.relr && !obj.runtime_relocation_mapping;
}

static int gate_readonly_authority_fast_replay(void)
{
    _Alignas(8) uint8_t image[512] = {0};
    Elf64_Phdr phdr[3];
    Elf64_Relr *relr = (Elf64_Relr *)(void *)(image + 64);
    struct loaded_obj obj;
    size_t admitted_queries;

    gate_object_init(&obj, image, sizeof(image), phdr, 3);
    phdr[0].p_flags = PF_R;
    phdr[0].p_filesz = 128;
    phdr[0].p_memsz = 128;
    phdr[1].p_type = PT_LOAD;
    phdr[1].p_flags = PF_R | PF_W;
    phdr[1].p_vaddr = 256;
    phdr[1].p_filesz = 128;
    phdr[1].p_memsz = 128;
    phdr[2].p_type = PT_GNU_RELRO;
    phdr[2].p_vaddr = 256;
    phdr[2].p_memsz = 64;
    relr[0] = 256;
    relr[1] = 3;
    relocation_store_u64(image + 256, 4);
    relocation_store_u64(image + 264, 5);

    if (publish_loaded_relocation_authority(
            &obj, NULL, 0, NULL, 0, relr, 2) < 0 ||
        obj.relr != relr || obj.runtime_relocation_mapping)
        return 0;
    g_loaded_obj_vaddr_pointer_calls = 0;
    g_relr_writable_index_queries = 0;
    if (validate_object_relocations(&obj) < 0)
        return 0;
    admitted_queries = g_relr_writable_index_queries;
    if (admitted_queries != 2 || g_loaded_obj_vaddr_pointer_calls != 0 ||
        walk_relr(&obj, 1) < 0 ||
        g_relr_writable_index_queries != admitted_queries ||
        g_loaded_obj_vaddr_pointer_calls != 0 ||
        relocation_load_u64(image + 256) !=
            (uint64_t)(uintptr_t)image + 4 ||
        relocation_load_u64(image + 264) !=
            (uint64_t)(uintptr_t)image + 5)
        return 0;
    dl_release_runtime_mapping(&obj);
    return 1;
}

int main(void)
{
    if (!gate_replay_requires_complete_admission())
        return 1;
    if (!gate_prelinked_relr_is_replayed_once())
        return 2;
    if (!gate_empty_and_inconsistent_tables())
        return 3;
    if (!gate_chained_bitmaps_and_address_reset())
        return 4;
    if (!gate_bss_end_boundary())
        return 5;
    if (!gate_malformed_relr_rejected())
        return 6;
    if (!gate_frontier_matches_linear_scan())
        return 7;
    if (!gate_arbitrary_direct_order_and_duplicates())
        return 8;
    if (!gate_adjacent_writable_straddle_rejected())
        return 9;
    if (!gate_frontier_mapping_and_allocation_failure())
        return 10;
    if (!gate_runtime_destination_overflow_rejected())
        return 11;
    if (!gate_high_cardinality_phdr_complexity())
        return 12;
    if (!gate_writable_authority_and_fast_replay())
        return 13;
    if (!gate_readonly_authority_fast_replay())
        return 14;
    return 0;
}
