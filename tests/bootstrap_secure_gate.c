#define main dlfreeze_embedded_bootstrap_main
#include "../src/bootstrap.c"
#undef main

struct fake_initial_stack {
    char *environment[2];
    Elf64_auxv_t auxiliary[257];
};

static void initialize_stack(struct fake_initial_stack *stack,
                             unsigned long secure)
{
    memset(stack, 0, sizeof(*stack));
    stack->environment[0] = (char *)"DLFREEZE_DEBUG=1";
    stack->auxiliary[0].a_type = AT_PAGESZ;
    stack->auxiliary[0].a_un.a_val = 4096;
    stack->auxiliary[1].a_type = AT_SECURE;
    stack->auxiliary[1].a_un.a_val = secure;
    stack->auxiliary[2].a_type = AT_NULL;
}

static int expect_range_result(const char *label, int actual, int expected)
{
    if (!!actual == !!expected)
        return 1;
    fprintf(stderr, "%s: valid=%d expected=%d\n",
            label, !!actual, !!expected);
    return 0;
}

static int payload_range_gate(void)
{
    enum {
        PAYLOAD_OFFSET = 0x1000,
        PAYLOAD_SIZE = 0x2000,
        STRTAB_OFFSET = 0x2000,
        MANIFEST_OFFSET = 0x2100,
        METADATA_OFFSET = 0x2200,
        FIXUP_OFFSET = 0x2400
    };
    static const char strings[] =
        "main\0libone.so\0libalias.so\0/empty\0/logical/libone.so\0";
    struct dlfrz_footer footer = {0};
    struct dlfrz_footer bad_footer;
    struct dlfrz_entry entries[4] = {{0}};
    struct dlfrz_entry bad_entries[4];
    const uint64_t manifest_size = sizeof(entries);
    const uint64_t footer_offset =
        PAYLOAD_OFFSET + PAYLOAD_SIZE - sizeof(footer);
    const uint64_t metadata_size =
        sizeof(entries) / sizeof(entries[0]) * sizeof(struct dlfrz_lib_meta);
    int ok = 1;

    footer.num_entries = sizeof(entries) / sizeof(entries[0]);
    footer.strtab_offset = STRTAB_OFFSET;
    footer.strtab_size = sizeof(strings);
    footer.manifest_offset = MANIFEST_OFFSET;

    entries[0].data_offset = 0x1000;
    entries[0].data_size = 0x200;
    entries[0].flags = DLFRZ_FLAG_MAIN_EXE;
    entries[0].name_offset = 0;
    entries[1].data_offset = 0x1400;
    entries[1].data_size = 0x100;
    entries[1].flags = DLFRZ_FLAG_SHLIB;
    entries[1].name_offset = 5;
    entries[2] = entries[1];
    entries[2].name_offset = 15;
    /* Empty regular files have no occupied payload range.  In particular,
     * an empty entry offset may coincide with a control-table byte. */
    entries[3].data_offset = STRTAB_OFFSET;
    entries[3].data_size = 0;
    entries[3].flags = DLFRZ_FLAG_DATA;
    entries[3].name_offset = 27;

    ok &= expect_range_result(
        "disjoint entries with an exact ELF alias and empty data",
        manifest_is_valid(&footer, entries, strings,
                          PAYLOAD_OFFSET, PAYLOAD_SIZE), 1);

    memcpy(bad_entries, entries, sizeof(bad_entries));
    bad_entries[1].logical_name_offset = 34;
    ok &= expect_range_result(
        "shared object with separate logical load name",
        manifest_is_valid(&footer, bad_entries, strings,
                          PAYLOAD_OFFSET, PAYLOAD_SIZE), 1);

    memcpy(bad_entries, entries, sizeof(bad_entries));
    bad_entries[0].logical_name_offset = 34;
    ok &= expect_range_result(
        "non-library logical load name",
        manifest_is_valid(&footer, bad_entries, strings,
                          PAYLOAD_OFFSET, PAYLOAD_SIZE), 0);

    memcpy(bad_entries, entries, sizeof(bad_entries));
    bad_entries[1].logical_name_offset = sizeof(strings);
    ok &= expect_range_result(
        "out-of-range logical load name",
        manifest_is_valid(&footer, bad_entries, strings,
                          PAYLOAD_OFFSET, PAYLOAD_SIZE), 0);

    memcpy(bad_entries, entries, sizeof(bad_entries));
    bad_entries[1].logical_name_offset = 4;
    ok &= expect_range_result(
        "empty logical load name",
        manifest_is_valid(&footer, bad_entries, strings,
                          PAYLOAD_OFFSET, PAYLOAD_SIZE), 0);

    memcpy(bad_entries, entries, sizeof(bad_entries));
    bad_entries[1].name_offset = 6;
    ok &= expect_range_result(
        "manifest name offset into a string suffix",
        manifest_is_valid(&footer, bad_entries, strings,
                          PAYLOAD_OFFSET, PAYLOAD_SIZE), 0);

    memcpy(bad_entries, entries, sizeof(bad_entries));
    bad_entries[1].dlopen_request_offset = 15;
    ok &= expect_range_result(
        "startup-owned bare dlopen request",
        manifest_is_valid(&footer, bad_entries, strings,
                          PAYLOAD_OFFSET, PAYLOAD_SIZE), 1);

    memcpy(bad_entries, entries, sizeof(bad_entries));
    bad_entries[1].flags |= DLFRZ_FLAG_DLOPEN_PATHFUL;
    bad_entries[1].dlopen_request_offset = 27;
    ok &= expect_range_result(
        "startup-owned pathful dlopen request",
        manifest_is_valid(&footer, bad_entries, strings,
                          PAYLOAD_OFFSET, PAYLOAD_SIZE), 1);

    memcpy(bad_entries, entries, sizeof(bad_entries));
    bad_entries[1].flags |= DLFRZ_FLAG_DLOPEN;
    bad_entries[1].dlopen_request_offset = 15;
    ok &= expect_range_result(
        "canonical bare dlopen request",
        manifest_is_valid(&footer, bad_entries, strings,
                          PAYLOAD_OFFSET, PAYLOAD_SIZE), 1);

    memcpy(bad_entries, entries, sizeof(bad_entries));
    bad_entries[1].flags |= DLFRZ_FLAG_DLOPEN_PATHFUL;
    bad_entries[1].dlopen_request_offset = 15;
    ok &= expect_range_result(
        "pathful flag on a bare request",
        manifest_is_valid(&footer, bad_entries, strings,
                          PAYLOAD_OFFSET, PAYLOAD_SIZE), 0);

    memcpy(bad_entries, entries, sizeof(bad_entries));
    bad_entries[1].dlopen_request_offset = 27;
    ok &= expect_range_result(
        "pathful request without its canonical flag",
        manifest_is_valid(&footer, bad_entries, strings,
                          PAYLOAD_OFFSET, PAYLOAD_SIZE), 0);

    memcpy(bad_entries, entries, sizeof(bad_entries));
    bad_entries[1].flags |= DLFRZ_FLAG_DLOPEN_PATHFUL;
    ok &= expect_range_result(
        "pathful flag without a request",
        manifest_is_valid(&footer, bad_entries, strings,
                          PAYLOAD_OFFSET, PAYLOAD_SIZE), 0);

    memcpy(bad_entries, entries, sizeof(bad_entries));
    bad_entries[0].dlopen_request_offset = 15;
    ok &= expect_range_result(
        "non-library dlopen request",
        manifest_is_valid(&footer, bad_entries, strings,
                          PAYLOAD_OFFSET, PAYLOAD_SIZE), 0);

    memcpy(bad_entries, entries, sizeof(bad_entries));
    bad_entries[2].data_offset += 0x80;
    ok &= expect_range_result(
        "partially overlapping entries",
        manifest_is_valid(&footer, bad_entries, strings,
                          PAYLOAD_OFFSET, PAYLOAD_SIZE), 0);

    memcpy(bad_entries, entries, sizeof(bad_entries));
    bad_entries[2].data_offset = STRTAB_OFFSET;
    bad_entries[2].data_size = 1;
    ok &= expect_range_result(
        "entry overlaps string table",
        manifest_is_valid(&footer, bad_entries, strings,
                          PAYLOAD_OFFSET, PAYLOAD_SIZE), 0);

    memcpy(bad_entries, entries, sizeof(bad_entries));
    bad_entries[2].data_offset = MANIFEST_OFFSET;
    bad_entries[2].data_size = 1;
    ok &= expect_range_result(
        "entry overlaps manifest",
        manifest_is_valid(&footer, bad_entries, strings,
                          PAYLOAD_OFFSET, PAYLOAD_SIZE), 0);

    memcpy(bad_entries, entries, sizeof(bad_entries));
    bad_entries[2].data_offset = footer_offset;
    bad_entries[2].data_size = 1;
    ok &= expect_range_result(
        "entry overlaps footer",
        manifest_is_valid(&footer, bad_entries, strings,
                          PAYLOAD_OFFSET, PAYLOAD_SIZE), 0);

    bad_footer = footer;
    bad_footer.manifest_offset = STRTAB_OFFSET + 1;
    ok &= expect_range_result(
        "string table overlaps manifest",
        manifest_is_valid(&bad_footer, entries, strings,
                          PAYLOAD_OFFSET, PAYLOAD_SIZE), 0);

    bad_footer = footer;
    bad_footer.strtab_offset = MANIFEST_OFFSET;
    bad_footer.strtab_size = manifest_size;
    ok &= expect_range_result(
        "string table exactly aliases manifest",
        manifest_is_valid(&bad_footer, entries, strings,
                          PAYLOAD_OFFSET, PAYLOAD_SIZE), 0);

    bad_footer = footer;
    bad_footer.strtab_offset = footer_offset;
    ok &= expect_range_result(
        "string table overlaps footer",
        manifest_is_valid(&bad_footer, entries, strings,
                          PAYLOAD_OFFSET, PAYLOAD_SIZE), 0);

    bad_footer = footer;
    bad_footer.manifest_offset = footer_offset - manifest_size + 1;
    ok &= expect_range_result(
        "manifest overlaps footer",
        manifest_is_valid(&bad_footer, entries, strings,
                          PAYLOAD_OFFSET, PAYLOAD_SIZE), 0);

    ok &= expect_range_result(
        "disjoint direct metadata and fixups",
        direct_payload_ranges_valid(
            &footer, entries, PAYLOAD_OFFSET, PAYLOAD_SIZE,
            METADATA_OFFSET, metadata_size, FIXUP_OFFSET, 16), 1);
    ok &= expect_range_result(
        "metadata overlaps entry",
        direct_payload_ranges_valid(
            &footer, entries, PAYLOAD_OFFSET, PAYLOAD_SIZE,
            entries[0].data_offset, metadata_size, FIXUP_OFFSET, 16), 0);
    ok &= expect_range_result(
        "metadata exactly aliases string table",
        direct_payload_ranges_valid(
            &footer, entries, PAYLOAD_OFFSET, PAYLOAD_SIZE,
            STRTAB_OFFSET, sizeof(strings), FIXUP_OFFSET, 16), 0);
    ok &= expect_range_result(
        "metadata overlaps manifest",
        direct_payload_ranges_valid(
            &footer, entries, PAYLOAD_OFFSET, PAYLOAD_SIZE,
            MANIFEST_OFFSET, metadata_size, FIXUP_OFFSET, 16), 0);
    ok &= expect_range_result(
        "metadata overlaps footer",
        direct_payload_ranges_valid(
            &footer, entries, PAYLOAD_OFFSET, PAYLOAD_SIZE,
            footer_offset, metadata_size, FIXUP_OFFSET, 16), 0);
    ok &= expect_range_result(
        "fixups overlap entry",
        direct_payload_ranges_valid(
            &footer, entries, PAYLOAD_OFFSET, PAYLOAD_SIZE,
            METADATA_OFFSET, metadata_size,
            entries[1].data_offset, entries[1].data_size), 0);
    ok &= expect_range_result(
        "fixups exactly alias footer",
        direct_payload_ranges_valid(
            &footer, entries, PAYLOAD_OFFSET, PAYLOAD_SIZE,
            METADATA_OFFSET, metadata_size,
            footer_offset, sizeof(footer)), 0);
    ok &= expect_range_result(
        "metadata and fixups exactly alias",
        direct_payload_ranges_valid(
            &footer, entries, PAYLOAD_OFFSET, PAYLOAD_SIZE,
            METADATA_OFFSET, metadata_size,
            METADATA_OFFSET, metadata_size), 0);
    return ok;
}

static int manifest_string_complexity_gate(void)
{
    enum {
        ENTRY_COUNT = 8192,
        STRING_SIZE = 1024 * 1024,
    };
    const uint64_t payload_offset = UINT64_C(0x1000);
    const uint64_t payload_size = UINT64_C(0x1000000);
    struct dlfrz_entry *entries = calloc(ENTRY_COUNT, sizeof(*entries));
    char *strings = malloc(STRING_SIZE);
    struct dlfrz_footer footer = {0};
    int valid = 0;

    if (!entries || !strings)
        goto out;
    strings[0] = '/';
    memset(strings + 1, 'a', STRING_SIZE - 2);
    strings[STRING_SIZE - 1] = '\0';

    footer.num_entries = ENTRY_COUNT;
    footer.strtab_offset = UINT64_C(0x200000);
    footer.strtab_size = STRING_SIZE;
    footer.manifest_offset = UINT64_C(0x400000);
    entries[0].data_offset = payload_offset;
    entries[0].data_size = 1;
    entries[0].flags = DLFRZ_FLAG_MAIN_EXE;
    for (size_t i = 1; i < ENTRY_COUNT; i++)
        entries[i].flags = DLFRZ_FLAG_DATA | DLFRZ_FLAG_DATA_NEGATIVE;

    /* All 8,192 references intentionally share the one long string.  The
     * canonical validator must scan those bytes once, not once per entry. */
    valid = manifest_is_valid(&footer, entries, strings,
                              payload_offset, payload_size);

out:
    free(strings);
    free(entries);
    return valid;
}

struct direct_test_elf {
    Elf64_Ehdr ehdr;
    Elf64_Phdr phdrs[3];
};

static void initialize_direct_test_elf(struct direct_test_elf *image,
                                       uint64_t tls_memsz)
{
    memset(image, 0, sizeof(*image));
    memcpy(image->ehdr.e_ident, ELFMAG, SELFMAG);
    image->ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    image->ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    image->ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    image->ehdr.e_ident[EI_OSABI] = ELFOSABI_NONE;
    image->ehdr.e_type = ET_DYN;
#if defined(__x86_64__)
    image->ehdr.e_machine = EM_X86_64;
#elif defined(__aarch64__)
    image->ehdr.e_machine = EM_AARCH64;
#else
#error "Unsupported architecture"
#endif
    image->ehdr.e_version = EV_CURRENT;
    image->ehdr.e_ehsize = sizeof(Elf64_Ehdr);
    image->ehdr.e_phoff = offsetof(struct direct_test_elf, phdrs);
    image->ehdr.e_phentsize = sizeof(Elf64_Phdr);
    image->ehdr.e_phnum = sizeof(image->phdrs) / sizeof(image->phdrs[0]);

    image->phdrs[0].p_type = PT_LOAD;
    image->phdrs[0].p_flags = PF_R;
    image->phdrs[0].p_filesz = sizeof(*image);
    image->phdrs[0].p_memsz = sizeof(*image);
    image->phdrs[0].p_align = _Alignof(Elf64_Ehdr);

    image->phdrs[1].p_type = PT_TLS;
    image->phdrs[1].p_memsz = tls_memsz;
    image->phdrs[1].p_align = 1;

    image->phdrs[2].p_type = PT_GNU_STACK;
    image->phdrs[2].p_flags = PF_R | PF_W;
    image->phdrs[2].p_align = 1;
}

static void initialize_direct_test_record(
    struct dlfrz_entry *entry, struct dlfrz_lib_meta *meta,
    uint64_t data_offset, uint64_t base_addr, uint32_t flags)
{
    memset(entry, 0, sizeof(*entry));
    memset(meta, 0, sizeof(*meta));
    entry->data_offset = data_offset;
    entry->data_size = sizeof(struct direct_test_elf);
    entry->flags = flags;
    meta->base_addr = base_addr;
    meta->vaddr_hi = sizeof(struct direct_test_elf);
    meta->phdr_off = offsetof(struct direct_test_elf, phdrs);
    meta->phdr_num = 3;
    meta->phdr_entsz = sizeof(Elf64_Phdr);
    meta->flags = flags;
}

static int direct_alias_complexity_gate(void)
{
    enum {
        ALIAS_COUNT = 65535,
        DATA_COUNT = 8192,
        ENTRY_COUNT = ALIAS_COUNT + DATA_COUNT,
    };
    struct direct_test_elf *image = malloc(sizeof(*image));
    struct dlfrz_entry *entries =
        calloc(ENTRY_COUNT, sizeof(*entries));
    struct dlfrz_lib_meta *metas =
        calloc(ENTRY_COUNT, sizeof(*metas));
    struct direct_source_ref owner_refs[3] = {
        {0, sizeof(*image), 0},
        {0, sizeof(*image), 1},
        {0, sizeof(*image), 2},
    };
    uint64_t tls_memsz;
    int ok = 0;

    if (!image || !entries || !metas)
        goto out;
#if defined(__aarch64__)
    tls_memsz = (uint64_t)INT64_MAX - 16;
#else
    tls_memsz = (uint64_t)INT64_MAX;
#endif
    initialize_direct_test_elf(image, tls_memsz);
    for (size_t i = 0; i < ALIAS_COUNT; i++) {
        uint32_t flags = DLFRZ_FLAG_SHLIB;

        if (i < 2)
            flags |= DLFRZ_FLAG_DLOPEN;
        initialize_direct_test_record(
            &entries[i], &metas[i], 0, UINT64_C(0x200000000), flags);
        if (i < 2)
            metas[i].flags |= DLFRZ_FLAG_DLOPEN_EARLY;
    }
    for (size_t i = ALIAS_COUNT; i < ENTRY_COUNT; i++) {
        entries[i].flags = DLFRZ_FLAG_DATA | DLFRZ_FLAG_DATA_NEGATIVE;
        metas[i].flags = DLFRZ_FLAG_DATA;
    }

    if (direct_source_group_startup_owner(
            owner_refs, 0, 3, entries, metas) != 2)
        goto out;
    if (!direct_metadata_is_valid((const uint8_t *)image, 0, metas,
                                  entries, ENTRY_COUNT, 0))
        goto out;

    /* Static-TLS promotion is source-wide for dlopen aliases. */
    metas[1].flags &= ~DLFRZ_FLAG_DLOPEN_EARLY;
    if (direct_metadata_is_valid((const uint8_t *)image, 0, metas,
                                 entries, ENTRY_COUNT, 0))
        goto out;
    metas[1].flags |= DLFRZ_FLAG_DLOPEN_EARLY;

    /* Geometry is immutable-source state, regardless of lookup role. */
    metas[ALIAS_COUNT - 1].base_addr += 4096;
    if (direct_metadata_is_valid((const uint8_t *)image, 0, metas,
                                 entries, ENTRY_COUNT, 0))
        goto out;
    ok = 1;

out:
    free(metas);
    free(entries);
    free(image);
    return ok;
}

static int direct_interp_shlib_alias_gate(void)
{
    struct direct_test_elf image;
    struct dlfrz_entry entries[3];
    struct dlfrz_lib_meta metas[3];
    struct direct_source_ref refs[3] = {
        {0, sizeof(image), 0},
        {0, sizeof(image), 1},
        {0, sizeof(image), 2},
    };
    struct dlfrz_lib_meta saved_interp_meta;
    int ok = 0;

    initialize_direct_test_elf(&image, 0);
    initialize_direct_test_record(
        &entries[0], &metas[0], 0, UINT64_C(0x280000000),
        DLFRZ_FLAG_INTERP);
    for (size_t i = 1; i < 3; i++) {
        initialize_direct_test_record(
            &entries[i], &metas[i], 0, metas[0].base_addr,
            DLFRZ_FLAG_SHLIB);
        metas[i].flags |= DLFRZ_FLAG_PRELINKED |
                          DLFRZ_FLAG_RUNTIME_SCAN;
        metas[i].runtime_fixup_count = 1;
    }

    /* INTERP supplies identical bytes/geometry but never owns startup work. */
    if (direct_source_group_startup_owner(
            refs, 0, 3, entries, metas) != 1 ||
        !direct_metadata_is_valid((const uint8_t *)&image, 0, metas,
                                  entries, 3, 2))
        return 0;

    metas[2].base_addr += 4096;
    if (direct_metadata_is_valid((const uint8_t *)&image, 0, metas,
                                 entries, 3, 2))
        return 0;
    metas[2].base_addr = metas[1].base_addr;

    /* INTERP has no prelink lifecycle.  The two ordinary SHLIB identities
     * must nevertheless agree with each other. */
    metas[2].runtime_fixup_off = 1;
    if (direct_metadata_is_valid((const uint8_t *)&image, 0, metas,
                                 entries, 3, 2))
        return 0;
    metas[2].runtime_fixup_off = 0;

    entries[0].flags = DLFRZ_FLAG_MAIN_EXE;
    metas[0].flags = DLFRZ_FLAG_MAIN_EXE;
    if (direct_metadata_is_valid((const uint8_t *)&image, 0, metas,
                                 entries, 3, 2))
        return 0;
    entries[0].flags = DLFRZ_FLAG_INTERP;
    metas[0].flags = DLFRZ_FLAG_INTERP;

    saved_interp_meta = metas[0];
    entries[0].flags = DLFRZ_FLAG_DATA;
    memset(&metas[0], 0, sizeof(metas[0]));
    metas[0].flags = DLFRZ_FLAG_DATA;
    if (direct_metadata_is_valid((const uint8_t *)&image, 0, metas,
                                 entries, 3, 2))
        return 0;
    entries[0].flags = DLFRZ_FLAG_INTERP;
    metas[0] = saved_interp_meta;

    entries[0].flags = DLFRZ_FLAG_INTERP | DLFRZ_FLAG_SHLIB;
    metas[0].flags = entries[0].flags;
    if (direct_metadata_is_valid((const uint8_t *)&image, 0, metas,
                                 entries, 3, 2))
        return 0;
    ok = 1;
    return ok;
}

static int direct_interval_and_object_count_gate(void)
{
    enum {
        UNIQUE_COUNT = DLFRZ_DIRECT_MAX_OBJECTS + 1,
        IMAGE_STRIDE = 4096,
        ADDRESS_STRIDE = 65536,
    };
    struct direct_test_elf images[2];
    struct dlfrz_entry entries[2];
    struct dlfrz_lib_meta metas[2];
    uint8_t *many_images = NULL;
    struct dlfrz_entry *many_entries = NULL;
    struct dlfrz_lib_meta *many_metas = NULL;
    long page_size = sysconf(_SC_PAGESIZE);
    int ok = 0;

    if (page_size <= 0 || (uint64_t)page_size > UINT64_MAX / 5)
        return 0;
    initialize_direct_test_elf(&images[0], 0);
    images[1] = images[0];
    initialize_direct_test_record(
        &entries[0], &metas[0], 0, UINT64_C(0x300000000),
        DLFRZ_FLAG_SHLIB);
    initialize_direct_test_record(
        &entries[1], &metas[1], sizeof(images[0]),
        metas[0].base_addr + 5 * (uint64_t)page_size,
        DLFRZ_FLAG_SHLIB);
    if (!direct_metadata_is_valid((const uint8_t *)images, 0, metas,
                                  entries, 2, 0))
        goto out;
    metas[1].base_addr -= (uint64_t)page_size;
    if (direct_metadata_is_valid((const uint8_t *)images, 0, metas,
                                 entries, 2, 0))
        goto out;

    many_images = calloc(UNIQUE_COUNT, IMAGE_STRIDE);
    many_entries = calloc(UNIQUE_COUNT, sizeof(*many_entries));
    many_metas = calloc(UNIQUE_COUNT, sizeof(*many_metas));
    if (!many_images || !many_entries || !many_metas)
        goto out;
    for (size_t i = 0; i < UNIQUE_COUNT; i++) {
        memcpy(many_images + i * IMAGE_STRIDE,
               &images[0], sizeof(images[0]));
        initialize_direct_test_record(
            &many_entries[i], &many_metas[i], i * IMAGE_STRIDE,
            UINT64_C(0x400000000) + i * ADDRESS_STRIDE,
            DLFRZ_FLAG_SHLIB);
    }
    if (direct_metadata_is_valid(many_images, 0, many_metas, many_entries,
                                 UNIQUE_COUNT, 0))
        goto out;
    ok = 1;

out:
    free(many_metas);
    free(many_entries);
    free(many_images);
    return ok;
}

static int alias_metadata_gate(void)
{
    struct dlfrz_entry entries[2] = {{0}};
    struct dlfrz_lib_meta metas[2] = {{0}};
    int ok = 1;

    entries[0].flags = entries[1].flags = DLFRZ_FLAG_SHLIB;
    entries[0].data_offset = entries[1].data_offset = 0x1000;
    entries[0].data_size = entries[1].data_size = 0x2000;
    metas[0].flags = metas[1].flags =
        DLFRZ_FLAG_SHLIB | DLFRZ_FLAG_PRELINKED |
        DLFRZ_FLAG_RUNTIME_SCAN;
    metas[0].base_addr = metas[1].base_addr = 0x200000;
    metas[0].vaddr_lo = metas[1].vaddr_lo = 0;
    metas[0].vaddr_hi = metas[1].vaddr_hi = 0x3000;
    metas[0].entry = metas[1].entry = 0x100;
    metas[0].phdr_off = metas[1].phdr_off = 0x40;
    metas[0].phdr_num = metas[1].phdr_num = 4;
    metas[0].phdr_entsz = metas[1].phdr_entsz = sizeof(Elf64_Phdr);
    metas[0].runtime_fixup_off = metas[1].runtime_fixup_off = 7;
    metas[0].runtime_fixup_count = metas[1].runtime_fixup_count = 3;

    ok &= expect_range_result(
        "exact source alias geometry",
        direct_alias_geometry_matches(&metas[0], &metas[1]), 1);
    ok &= expect_range_result(
        "exact source alias prelink state",
        direct_alias_runtime_state_matches(&metas[0], &metas[1]), 1);

    metas[1].base_addr += 0x1000;
    ok &= expect_range_result(
        "exact source alias with divergent load base",
        direct_alias_geometry_matches(&metas[0], &metas[1]), 0);
    metas[1].base_addr = metas[0].base_addr;

    metas[1].runtime_fixup_off++;
    ok &= expect_range_result(
        "equal-priority alias with divergent fixup slice",
        direct_alias_runtime_state_matches(&metas[0], &metas[1]), 0);
    metas[1].runtime_fixup_off = metas[0].runtime_fixup_off;
    metas[1].flags &= ~DLFRZ_FLAG_RUNTIME_SCAN;
    ok &= expect_range_result(
        "equal-priority alias with divergent prelink flags",
        direct_alias_runtime_state_matches(&metas[0], &metas[1]), 0);
    metas[1].flags = DLFRZ_FLAG_SHLIB | DLFRZ_FLAG_DLOPEN |
                     DLFRZ_FLAG_DLOPEN_EARLY;
    metas[1].runtime_fixup_off = 0;
    metas[1].runtime_fixup_count = 0;
    ok &= expect_range_result(
        "startup object with early dlopen request alias",
        direct_alias_runtime_state_matches(&metas[0], &metas[1]), 1);
    return ok;
}

int main(void)
{
    struct fake_initial_stack stack;

    initialize_stack(&stack, 0);
    if (bs_detect_secure_mode(stack.environment) != 0)
        return 1;
    initialize_stack(&stack, 1);
    if (bs_detect_secure_mode(stack.environment) != 1)
        return 2;
    if (bs_detect_secure_mode(NULL) != 1)
        return 3;

    memset(&stack, 0, sizeof(stack));
    stack.environment[0] = (char *)"X=1";
    for (size_t i = 0; i < 256; i++) {
        stack.auxiliary[i].a_type = AT_PAGESZ;
        stack.auxiliary[i].a_un.a_val = 4096;
    }
    if (bs_detect_secure_mode(stack.environment) != 1)
        return 4;

    if (setenv("DLFREEZE_DEBUG", "1", 1) != 0)
        return 5;
    g_bootstrap_secure_mode = 1;
    if (bs_env_enabled("DLFREEZE_DEBUG") != 0)
        return 6;
    if (bs_execution_context_supported() != 0)
        return 7;
    g_bootstrap_secure_mode = 0;
    if (bs_env_enabled("DLFREEZE_DEBUG") != 1)
        return 8;
    if (bs_execution_context_supported() != 1)
        return 9;
    if (!payload_range_gate())
        return 10;
    if (!alias_metadata_gate())
        return 13;
    if (!manifest_string_complexity_gate())
        return 14;
    if (!direct_alias_complexity_gate())
        return 15;
    if (!direct_interp_shlib_alias_gate())
        return 17;
    if (!direct_interval_and_object_count_gate())
        return 16;
    if (classify_extraction_fallback(0, 0, 0, 0) !=
        EXTRACTION_FALLBACK_ALLOWED)
        return 11;
    if (classify_extraction_fallback(0, 0, 0, 1) !=
        EXTRACTION_REFUSE_LOGICAL_NAME)
        return 12;
    {
        struct dlfrz_entry alias_entries[2] = {{0}};

        alias_entries[0].flags = DLFRZ_FLAG_INTERP;
        alias_entries[0].name_offset = 7;
        alias_entries[0].data_offset = 0x1000;
        alias_entries[0].data_size = 0x2000;
        alias_entries[1].flags = DLFRZ_FLAG_SHLIB;
        alias_entries[1].logical_name_offset = 7;
        alias_entries[1].data_offset = 0x1000;
        alias_entries[1].data_size = 0x2000;
        if (manifest_has_unextractable_logical_names(alias_entries, 2))
            return 18;
        alias_entries[1].logical_name_offset = 8;
        if (!manifest_has_unextractable_logical_names(alias_entries, 2))
            return 19;
        alias_entries[1].logical_name_offset = 7;
        alias_entries[1].data_offset++;
        if (!manifest_has_unextractable_logical_names(alias_entries, 2))
            return 20;
    }
    return 0;
}
