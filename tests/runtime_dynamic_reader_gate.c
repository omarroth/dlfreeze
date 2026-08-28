/* Exercise the runtime PT_DYNAMIC reader in its real translation unit. */
#define DLFREEZE_SYMBOL_LOOKUP_COMPLEXITY_GATE 1
#include "../src/loader.c"

static int temporary_file(char path[64], size_t size)
{
    int fd;

    memcpy(path, "/tmp/dlfreeze-dynamic-reader-XXXXXX",
           sizeof("/tmp/dlfreeze-dynamic-reader-XXXXXX"));
    fd = mkstemp(path);
    if (fd < 0)
        return -1;
    unlink(path);
    if (size > (size_t)INT64_MAX || ftruncate(fd, (off_t)size) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void initialize_headers(Elf64_Phdr phdrs[2], uint64_t size)
{
    memset(phdrs, 0, 2 * sizeof(*phdrs));
    phdrs[0].p_type = PT_DYNAMIC;
    phdrs[0].p_offset = 0;
    phdrs[0].p_filesz = size;
    phdrs[1].p_type = PT_TLS;
    phdrs[1].p_memsz = 1;
}

static int large_table_gate(void)
{
    const size_t entry_count = 65536;
    const size_t size = entry_count * sizeof(Elf64_Dyn);
    const size_t expected_reads =
        (size + DL_DYNAMIC_READ_CHUNK_BYTES - 1) /
        DL_DYNAMIC_READ_CHUNK_BYTES;
    char path[64];
    Elf64_Phdr phdrs[2];
    Elf64_Dyn *entries;
    size_t reads = 0;
    int fd;
    int result = 0;

    fd = temporary_file(path, size);
    if (fd < 0)
        return 0;
    entries = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_SHARED, fd, 0);
    if (entries == MAP_FAILED)
        goto out;
    initialize_headers(phdrs, size);
    for (size_t i = 0; i < entry_count; i++)
        entries[i].d_tag = DT_DEBUG;
    entries[entry_count - 1].d_tag = DT_NULL;
    if (msync(entries, size, MS_SYNC) < 0 ||
        dynamic_has_static_tls_counted(fd, phdrs, 2, &reads) != 0 ||
        reads != expected_reads)
        goto unmap;

    entries[entry_count - 2].d_tag = DT_FLAGS;
    entries[entry_count - 2].d_un.d_val = DF_STATIC_TLS;
    if (msync(entries, size, MS_SYNC) < 0 ||
        dynamic_has_static_tls_counted(fd, phdrs, 2, &reads) != 1 ||
        reads != expected_reads)
        goto unmap;

    /* The first terminator wins; flags after it are not interpreted. */
    entries[0].d_tag = DT_NULL;
    entries[1].d_tag = DT_FLAGS;
    entries[1].d_un.d_val = DF_STATIC_TLS;
    if (msync(entries, size, MS_SYNC) < 0 ||
        dynamic_has_static_tls_counted(fd, phdrs, 2, &reads) != 0 ||
        reads != 1)
        goto unmap;

    /* A full declared table without DT_NULL remains malformed. */
    entries[0].d_tag = DT_DEBUG;
    entries[1].d_tag = DT_DEBUG;
    entries[entry_count - 1].d_tag = DT_DEBUG;
    if (msync(entries, size, MS_SYNC) < 0 ||
        dynamic_has_static_tls_counted(fd, phdrs, 2, &reads) != -1 ||
        reads != expected_reads)
        goto unmap;
    result = 1;

unmap:
    munmap(entries, size);
out:
    close(fd);
    return result;
}

static int truncation_gate(void)
{
    const size_t actual_size = 2 * sizeof(Elf64_Dyn) + 7;
    char path[64];
    unsigned char file_bytes[2 * sizeof(Elf64_Dyn) + 7];
    Elf64_Dyn entries[2];
    Elf64_Phdr phdrs[2];
    size_t reads = 0;
    int fd;
    int result = 0;

    memset(entries, 0, sizeof(entries));
    entries[0].d_tag = DT_FLAGS;
    entries[0].d_un.d_val = DF_STATIC_TLS;
    entries[1].d_tag = DT_NULL;
    memset(file_bytes, 0xa5, sizeof(file_bytes));
    memcpy(file_bytes, entries, sizeof(entries));
    fd = temporary_file(path, actual_size);
    if (fd < 0)
        return 0;
    if (pwrite(fd, file_bytes, sizeof(file_bytes), 0) !=
        (ssize_t)sizeof(file_bytes))
        goto out;
    initialize_headers(phdrs, 8 * sizeof(Elf64_Dyn));

    /* Do not require bytes following the first complete DT_NULL. */
    if (dynamic_has_static_tls_counted(fd, phdrs, 2, &reads) != 1 ||
        reads != 1)
        goto out;

    entries[1].d_tag = DT_DEBUG;
    if (pwrite(fd, &entries[1], sizeof(entries[1]),
               sizeof(entries[0])) != (ssize_t)sizeof(entries[1]) ||
        dynamic_has_static_tls_counted(fd, phdrs, 2, &reads) != -1 ||
        reads != 2)
        goto out;

    phdrs[0].p_filesz = sizeof(Elf64_Dyn) + 1;
    if (dynamic_has_static_tls_counted(fd, phdrs, 2, &reads) != -1 ||
        reads != 0)
        goto out;
    phdrs[0].p_filesz = 2 * sizeof(Elf64_Dyn);
    phdrs[0].p_offset = (uint64_t)INT64_MAX;
    if (dynamic_has_static_tls_counted(fd, phdrs, 2, &reads) != -1 ||
        reads != 0)
        goto out;
    result = 1;

out:
    close(fd);
    return result;
}

static int runtime_file_revision_gate(void)
{
    char path[64];
    struct stat before;
    struct stat unchanged;
    struct stat truncated;
    Elf64_Phdr ph = {0};
    uint64_t saved_page_size = g_page_size;
    long page_size = sysconf(_SC_PAGESIZE);
    int fd;
    int result = 0;

    if (page_size <= 0 ||
        ((uint64_t)page_size & ((uint64_t)page_size - 1)) != 0)
        return 0;
    fd = temporary_file(path, (size_t)page_size);
    if (fd < 0)
        return 0;
    g_page_size = (uint64_t)page_size;
    ph.p_type = PT_LOAD;
    ph.p_filesz = 1;
    ph.p_memsz = 1;
    ph.p_flags = PF_R;
    if (fstat(fd, &before) < 0 || fstat(fd, &unchanged) < 0 ||
        !runtime_file_revision_matches(&before, &unchanged) ||
        runtime_probe_file_mapping_policy(fd, &ph) < 0)
        goto out;

    /* The policy probe must reject an unrepresentable file offset without
     * constructing or touching a source-file mapping. */
    ph.p_offset = UINT64_MAX;
    if (runtime_probe_file_mapping_policy(fd, &ph) == 0)
        goto out;
    ph.p_offset = 0;

    if (ftruncate(fd, 0) < 0 || fstat(fd, &truncated) < 0 ||
        runtime_file_revision_matches(&before, &truncated))
        goto out;
    result = 1;

out:
    g_page_size = saved_page_size;
    close(fd);
    return result;
}

struct version_record {
    Elf64_Verdef definition;
    Elf64_Verdaux auxiliary;
};

static size_t align_size(size_t value, size_t alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

static int symbol_lookup_complexity_gate(void)
{
    const uint32_t symbols_count = 8193;
    const size_t payload_length = symbols_count;
    const size_t strings_size = payload_length + 2;
    const size_t symbols_offset = align_size(
        strings_size, _Alignof(Elf64_Sym));
    const size_t symbols_size =
        (size_t)symbols_count * sizeof(Elf64_Sym);
    const size_t versions_offset = align_size(
        symbols_offset + symbols_size, _Alignof(uint16_t));
    const size_t versions_size =
        (size_t)symbols_count * sizeof(uint16_t);
    const size_t sysv_offset = align_size(
        versions_offset + versions_size, _Alignof(uint32_t));
    const size_t sysv_words = 3 + (size_t)symbols_count;
    const size_t gnu_offset = align_size(
        sysv_offset + sysv_words * sizeof(uint32_t),
        _Alignof(uint64_t));
    const size_t gnu_words = 7 + (size_t)symbols_count - 1;
    const size_t image_size =
        gnu_offset + gnu_words * sizeof(uint32_t);
    const size_t version_page_count =
        ((size_t)symbols_count >> DL_VERSION_PAGE_BITS) + 1;
    const size_t version_index_size =
        sizeof(struct loaded_version_index) + version_page_count *
            DL_VERSION_PAGE_ENTRIES * sizeof(struct loaded_version_entry);
    unsigned char key[16] = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01
    };
    struct loaded_obj object;
    struct symbol_lookup_query miss_query;
    struct symbol_lookup_query exact_query;
    Elf64_Phdr load;
    Elf64_Sym *symbols;
    uint16_t *versions;
    struct loaded_version_index *version_index = MAP_FAILED;
    uint32_t *sysv;
    uint32_t *gnu;
    uint64_t *bloom;
    uint32_t *bucket;
    uint32_t *chains;
    char *strings;
    char *miss = MAP_FAILED;
    char *exact = MAP_FAILED;
    uint8_t *image = MAP_FAILED;
    uint64_t cached = 0;
    int result = 0;

    image = mmap(NULL, image_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    version_index = mmap(NULL, version_index_size,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    miss = mmap(NULL, payload_length + 1, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    exact = mmap(NULL, payload_length + 1, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (image == MAP_FAILED || version_index == MAP_FAILED ||
        miss == MAP_FAILED || exact == MAP_FAILED)
        goto out;
    memset(image, 0, image_size);
    memset(version_index, 0, version_index_size);
    for (size_t page = 0; page < version_page_count; page++)
        version_index->page_slots[page] = (uint16_t)(page + 1);
    memset(&object, 0, sizeof(object));
    memset(&load, 0, sizeof(load));
    strings = (char *)image;
    symbols = (Elf64_Sym *)(image + symbols_offset);
    versions = (uint16_t *)(image + versions_offset);
    sysv = (uint32_t *)(image + sysv_offset);
    gnu = (uint32_t *)(image + gnu_offset);
    strings[0] = '\0';
    memset(strings + 1, 'a', payload_length);
    strings[payload_length] = 'b';
    strings[payload_length + 1] = '\0';
    memset(miss, 'a', payload_length);
    miss[payload_length - 1] = 'c';
    miss[payload_length] = '\0';
    memcpy(exact, strings + 1, payload_length);
    exact[payload_length] = '\0';

    for (uint32_t i = 1; i < symbols_count; i++) {
        struct loaded_version_entry *entry;
        uint16_t version = (uint16_t)(i + 1);

        symbols[i].st_name = i;
        symbols[i].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
        symbols[i].st_shndx = 1;
        versions[i] = version;
        entry = loaded_version_index_entry_mutable(version_index, version);
        if (!entry)
            goto out;
        entry->definition_name = i;
        entry->flags = DL_VERSION_ENTRY_DEFINED;
    }
    load.p_type = PT_LOAD;
    load.p_flags = PF_R | PF_W;
    load.p_filesz = image_size;
    load.p_memsz = image_size;
    object.base = (uintptr_t)image;
    object.phdr = &load;
    object.phdr_num = 1;
    object.dynstr = strings;
    object.dynstr_size = strings_size;
    object.dynsym = symbols;
    object.dynsym_count = symbols_count;
    object.versym = versions;
    object.version_index = version_index;
    if (vfs_seed_hash_key(key) < 0 ||
        build_loaded_symbol_name_keys(&object) < 0 ||
        !symbol_lookup_query_init(miss, &miss_query) ||
        !symbol_lookup_query_init(exact, &exact_query))
        goto out;

    /* A one-bucket SysV table is a valid worst-case chain. */
    sysv[0] = 1;
    sysv[1] = symbols_count;
    sysv[2] = 1;
    for (uint32_t i = 1; i < symbols_count; i++)
        sysv[3 + i] = i + 1 < symbols_count ? i + 1 : STN_UNDEF;
    object.sysv_hash = sysv;
    g_symbol_name_candidate_checks = 0;
    g_symbol_name_full_compare_bytes = 0;
    for (unsigned int pass = 0; pass < 8; pass++)
        if (lookup_sysv_hash_query(&object, &miss_query) != NULL)
            goto out;
    if (g_symbol_name_candidate_checks !=
            (size_t)(symbols_count - 1) * 8 ||
        g_symbol_name_full_compare_bytes != 0 ||
        lookup_sysv_hash_query(&object, &exact_query) != &symbols[1])
        goto out;

    /* Version names share the same string table and may independently point
     * at every overlapping suffix.  Their object-owned keys must reject a
     * long miss without one strcmp per version while retaining exact GNU
     * version selection. */
    g_symbol_name_full_compare_bytes = 0;
    for (uint32_t i = 1; i < symbols_count; i++)
        if (classify_versioned_candidate(
                &object, i, &miss_query, 0, 1, NULL) !=
            VERSIONED_CANDIDATE_NONE)
            goto out;
    if (g_symbol_name_full_compare_bytes != 0 ||
        classify_versioned_candidate(
            &object, 1, &exact_query, 0, 1, NULL) !=
            VERSIONED_CANDIDATE_EXACT)
        goto out;

    /* GNU chains ordinarily compare only equal 32-bit hashes.  The table is
     * untrusted, so make every chain word claim the query hash and verify
     * the independent keyed name filter still bounds string work. */
    gnu[0] = 1;
    gnu[1] = 1;
    gnu[2] = 1;
    gnu[3] = 0;
    bloom = (uint64_t *)(gnu + 4);
    bloom[0] = UINT64_MAX;
    bucket = (uint32_t *)(bloom + 1);
    bucket[0] = 1;
    chains = bucket + 1;
    for (uint32_t i = 1; i < symbols_count; i++)
        chains[i - 1] = miss_query.gnu_hash & ~UINT32_C(1);
    chains[symbols_count - 2] |= UINT32_C(1);
    object.gnu_hash = gnu;
    object.sysv_hash = NULL;
    g_symbol_name_candidate_checks = 0;
    g_symbol_name_full_compare_bytes = 0;
    for (unsigned int pass = 0; pass < 8; pass++)
        if (lookup_gnu_hash_query(&object, &miss_query) != NULL)
            goto out;
    if (g_symbol_name_candidate_checks !=
            (size_t)(symbols_count - 1) * 8 ||
        g_symbol_name_full_compare_bytes != 0)
        goto out;

    /* Cache identity is now keyed independently of the attacker-controlled
     * ELF GNU hash, while the retained canonical pointer still receives an
     * exact final comparison. */
    clear_resolution_caches();
    sym_cache_store_canonical(strings + 1, &exact_query,
                              CACHE_FOUND, UINT64_C(0x12345678));
    if (sym_cache_lookup(&exact_query, &cached) != 1 ||
        cached != UINT64_C(0x12345678) ||
        sym_cache_lookup(&miss_query, &cached) != 0)
        goto out;
    sym_cache_store_canonical(strings + 1, &exact_query,
                              CACHE_MISS, 0);
    if (sym_cache_lookup(&exact_query, &cached) != -1)
        goto out;
    result = 1;

out:
    if (object.runtime_symbol_name_mapping)
        dl_release_runtime_mapping(&object);
    if (exact != MAP_FAILED)
        munmap(exact, payload_length + 1);
    if (miss != MAP_FAILED)
        munmap(miss, payload_length + 1);
    if (image != MAP_FAILED)
        munmap(image, image_size);
    if (version_index != MAP_FAILED)
        munmap(version_index, version_index_size);
    return result;
}

static void initialize_version_object(
    struct loaded_obj *object, Elf64_Phdr *load,
    void *image, size_t image_size, struct version_record *records,
    uint32_t count, uint16_t *versions, char *strings)
{
    memset(object, 0, sizeof(*object));
    memset(load, 0, sizeof(*load));
    load->p_type = PT_LOAD;
    load->p_flags = PF_R | PF_W;
    load->p_filesz = image_size;
    load->p_memsz = image_size;
    object->base = (uintptr_t)image;
    object->phdr = load;
    object->phdr_num = 1;
    object->dynstr = strings;
    object->dynstr_size = 3;
    object->dynsym_count = count;
    object->versym = versions;
    object->verdef = &records[0].definition;
    object->verdef_count = count;
}

static int version_index_rejects(struct loaded_obj *object)
{
    if (build_loaded_version_index(object) < 0)
        return 1;
    if (object->runtime_version_mapping)
        dl_release_runtime_mapping(object);
    return 0;
}

static int version_index_gate(void)
{
    const uint32_t count = 20000;
    const size_t records_size =
        (size_t)count * sizeof(struct version_record);
    const size_t versions_offset = align_size(
        records_size, _Alignof(uint16_t));
    const size_t strings_offset = versions_offset +
        (size_t)count * sizeof(uint16_t);
    const size_t image_size = strings_offset + 3;
    struct loaded_obj object;
    Elf64_Phdr load;
    struct version_record *records;
    uint16_t *versions;
    char *strings;
    uint8_t *image;
    uint32_t hash;
    int result = 0;

    image = mmap(NULL, image_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (image == MAP_FAILED)
        return 0;
    memset(image, 0, image_size);
    records = (struct version_record *)image;
    versions = (uint16_t *)(image + versions_offset);
    strings = (char *)(image + strings_offset);
    strings[0] = '\0';
    strings[1] = 'V';
    strings[2] = '\0';
    hash = sysv_hash_calc(strings + 1);
    for (uint32_t i = 0; i < count; i++) {
        records[i].definition.vd_version = VER_DEF_CURRENT;
        records[i].definition.vd_ndx = (uint16_t)(i + 2);
        records[i].definition.vd_cnt = 1;
        records[i].definition.vd_hash = hash;
        records[i].definition.vd_aux =
            offsetof(struct version_record, auxiliary);
        records[i].definition.vd_next =
            i + 1 < count ? sizeof(struct version_record) : 0;
        records[i].auxiliary.vda_name = 1;
        versions[i] = (uint16_t)(i + 2);
    }
    initialize_version_object(&object, &load, image, image_size,
                              records, count, versions, strings);
    if (build_loaded_version_index(&object) < 0 ||
        !object.version_index)
        goto out;
    for (uint32_t i = 0; i < count; i++) {
        const char *version = defined_symbol_version(&object, i);

        if (!version || version[0] != 'V' || version[1] != '\0')
            goto release;
    }

    /* The GNU hidden bit belongs to VERSYM, independently of the indexed
     * definition name.  Both public/default and hidden references retain
     * the same O(1) name lookup. */
    versions[0] = UINT16_C(0x8000) | 2;
    {
        const char *version = NULL;
        int hidden = 0;

        if (relocation_symbol_version(
                &object, 0, &version, &hidden, NULL) != 1 ||
            !version || strcmp(version, "V") != 0 || !hidden)
            goto release;
    }
    versions[0] = 30001;
    {
        const char *version = NULL;

        if (symbol_version_name(&object, 0, &version) != -1)
            goto release;
    }
    result = 1;

release:
    dl_release_runtime_mapping(&object);
    if (!result)
        goto out;

    /* A prematurely terminated Verdef chain and a mismatched name hash are
     * rejected during the one structural pass, before any index is exposed. */
    records[count / 2].definition.vd_next = 0;
    initialize_version_object(&object, &load, image, image_size,
                              records, count, versions, strings);
    if (build_loaded_version_index(&object) == 0) {
        if (object.runtime_version_mapping)
            dl_release_runtime_mapping(&object);
        result = 0;
        goto out;
    }
    records[count / 2].definition.vd_next =
        sizeof(struct version_record);
    records[0].definition.vd_hash ^= 1;
    initialize_version_object(&object, &load, image, image_size,
                              records, count, versions, strings);
    if (!version_index_rejects(&object)) {
        result = 0;
        goto out;
    }
    records[0].definition.vd_hash ^= 1;

    /* A version index is an identity, not a first-record-wins key.  Reject
     * duplicate definitions even when their payloads happen to agree. */
    records[1].definition.vd_ndx = records[0].definition.vd_ndx;
    initialize_version_object(&object, &load, image, image_size,
                              records, count, versions, strings);
    if (!version_index_rejects(&object)) {
        result = 0;
        goto out;
    }
    records[1].definition.vd_ndx = 3;

    records[0].definition.vd_flags = UINT16_C(0x8000);
    initialize_version_object(&object, &load, image, image_size,
                              records, count, versions, strings);
    if (!version_index_rejects(&object)) {
        result = 0;
        goto out;
    }
    records[0].definition.vd_flags = 0;

    records[0].definition.vd_ndx = VER_NDX_LOCAL;
    initialize_version_object(&object, &load, image, image_size,
                              records, count, versions, strings);
    if (!version_index_rejects(&object)) {
        result = 0;
        goto out;
    }
    records[0].definition.vd_ndx = 2;

    records[0].definition.vd_next = sizeof(struct version_record) + 2;
    initialize_version_object(&object, &load, image, image_size,
                              records, count, versions, strings);
    if (!version_index_rejects(&object)) {
        result = 0;
        goto out;
    }
    records[0].definition.vd_next = sizeof(struct version_record);

    records[0].auxiliary.vda_next = sizeof(Elf64_Verdaux);
    initialize_version_object(&object, &load, image, image_size,
                              records, count, versions, strings);
    if (!version_index_rejects(&object))
        result = 0;

out:
    munmap(image, image_size);
    return result;
}

struct version_need_record {
    Elf64_Verneed need;
    Elf64_Vernaux auxiliary;
};

static int version_need_index_gate(void)
{
    const uint32_t count = 20000;
    const char string_bytes[] = "\0libprovider.so\0VERSION\0";
    const uint32_t provider_offset = 1;
    const uint32_t version_offset = sizeof("\0libprovider.so");
    const size_t records_size =
        (size_t)count * sizeof(struct version_need_record);
    const size_t dynamic_offset = align_size(
        records_size, _Alignof(Elf64_Dyn));
    const size_t strings_offset =
        dynamic_offset + 2 * sizeof(Elf64_Dyn);
    const size_t image_size = strings_offset + sizeof(string_bytes);
    struct loaded_obj object;
    struct version_need_record *records;
    Elf64_Dyn *dynamic;
    Elf64_Phdr load;
    char *strings;
    uint8_t *image;
    uint32_t hash;
    int result = 0;

    image = mmap(NULL, image_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (image == MAP_FAILED)
        return 0;
    memset(image, 0, image_size);
    records = (struct version_need_record *)image;
    dynamic = (Elf64_Dyn *)(image + dynamic_offset);
    strings = (char *)(image + strings_offset);
    memcpy(strings, string_bytes, sizeof(string_bytes));
    hash = sysv_hash_calc(strings + version_offset);
    dynamic[0].d_tag = DT_NEEDED;
    dynamic[0].d_un.d_val = provider_offset;
    dynamic[1].d_tag = DT_NULL;
    for (uint32_t i = 0; i < count; i++) {
        records[i].need.vn_version = VER_NEED_CURRENT;
        records[i].need.vn_cnt = 1;
        records[i].need.vn_file = provider_offset;
        records[i].need.vn_aux =
            offsetof(struct version_need_record, auxiliary);
        records[i].need.vn_next =
            i + 1 < count ? sizeof(struct version_need_record) : 0;
        records[i].auxiliary.vna_hash = hash;
        records[i].auxiliary.vna_other = (uint16_t)(i + 2);
        records[i].auxiliary.vna_name = version_offset;
    }
    memset(&object, 0, sizeof(object));
    memset(&load, 0, sizeof(load));
    load.p_type = PT_LOAD;
    load.p_flags = PF_R | PF_W;
    load.p_filesz = image_size;
    load.p_memsz = image_size;
    object.base = (uintptr_t)image;
    object.phdr = &load;
    object.phdr_num = 1;
    object.dynstr = strings;
    object.dynstr_size = sizeof(string_bytes);
    object.dynamic = dynamic;
    object.dynamic_count = 2;
    object.verneed = &records[0].need;
    object.verneed_count = count;

    if (build_loaded_version_index(&object) < 0 || !object.version_index)
        goto out;
    for (uint32_t i = 0; i < count; i++) {
        const char *version = NULL;
        const char *provider = NULL;

        if (needed_symbol_version(&object, (uint16_t)(i + 2),
                                  &version, &provider) != 1 ||
            !version || strcmp(version, "VERSION") != 0 ||
            !provider || strcmp(provider, "libprovider.so") != 0)
            goto release;
    }
    result = 1;

release:
    dl_release_runtime_mapping(&object);
    if (!result)
        goto out;
    object.phdr = &load;
    object.phdr_num = 1;

    /* Conflicting (and even byte-identical) repeated 15-bit requirement
     * indices are ambiguous and must never use first-record-wins behavior. */
    records[1].auxiliary.vna_other = records[0].auxiliary.vna_other;
    if (!version_index_rejects(&object)) {
        result = 0;
        goto out;
    }
    records[1].auxiliary.vna_other = 3;

    records[0].auxiliary.vna_flags = UINT16_C(0x8000);
    if (!version_index_rejects(&object)) {
        result = 0;
        goto out;
    }
    records[0].auxiliary.vna_flags = 0;

    records[0].auxiliary.vna_other = VER_NDX_GLOBAL;
    if (!version_index_rejects(&object)) {
        result = 0;
        goto out;
    }
    records[0].auxiliary.vna_other = 2;

    records[0].need.vn_next = sizeof(struct version_need_record) + 2;
    if (!version_index_rejects(&object)) {
        result = 0;
        goto out;
    }
    records[0].need.vn_next = sizeof(struct version_need_record);

    records[0].auxiliary.vna_next = sizeof(Elf64_Vernaux);
    if (!version_index_rejects(&object)) {
        result = 0;
        goto out;
    }
    records[0].auxiliary.vna_next = 0;

    records[0].need.vn_file = version_offset;
    if (!version_index_rejects(&object))
        result = 0;

out:
    munmap(image, image_size);
    return result;
}

static int manifest_startup_owner_gate(void)
{
    const uint32_t count = UINT16_MAX;
    const uint32_t ordinary = 60000;
    const uint32_t main_owner = 65000;
    const size_t entry_bytes = (size_t)count * sizeof(struct dlfrz_entry);
    const size_t meta_bytes =
        (size_t)count * sizeof(struct dlfrz_lib_meta);
    struct dl_manifest_startup_owners owners;
    struct dlfrz_entry *entries = MAP_FAILED;
    struct dlfrz_lib_meta *metas = MAP_FAILED;
    int result = 0;

    entries = mmap(NULL, entry_bytes, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    metas = mmap(NULL, meta_bytes, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (entries == MAP_FAILED || metas == MAP_FAILED)
        goto out;
    memset(entries, 0, entry_bytes);
    memset(metas, 0, meta_bytes);
    for (uint32_t i = 0; i < count; i++) {
        entries[i].flags = DLFRZ_FLAG_SHLIB;
        entries[i].data_offset = UINT64_C(0x1000);
        entries[i].data_size = UINT64_C(0x2000);
        metas[i].flags = LDR_FLAG_DLOPEN | LDR_FLAG_DLOPEN_EARLY;
    }
    metas[ordinary].flags = LDR_FLAG_SHLIB;
    metas[main_owner].flags = LDR_FLAG_MAIN_EXE;

    /* All 65,535 request aliases share one payload object.  The same
     * main -> ordinary -> early priority as startup population must select
     * one owner without a count-squared scan. */
    if (dl_manifest_startup_owners_build(
            entries, metas, count, &owners) < 0)
        goto out;
    if (owners.owner_count != 1 || !owners.is_owner[main_owner]) {
        dl_manifest_startup_owners_release(&owners);
        goto out;
    }
    for (uint32_t i = 0; i < count; i++)
        if (i != main_owner && owners.is_owner[i]) {
            dl_manifest_startup_owners_release(&owners);
            goto out;
        }
    dl_manifest_startup_owners_release(&owners);

    /* Exact source geometry is the alias key; a distinct byte range remains
     * a second startup owner. */
    entries[0].data_size++;
    if (dl_manifest_startup_owners_build(
            entries, metas, count, &owners) < 0)
        goto out;
    if (owners.owner_count != 2 || !owners.is_owner[0] ||
        !owners.is_owner[main_owner]) {
        dl_manifest_startup_owners_release(&owners);
        goto out;
    }
    dl_manifest_startup_owners_release(&owners);
    entries[0].data_size--;

    /* Total manifest cardinality is independent of the 512 mapped-object
     * limit: high-cardinality DATA entries do not consume startup slots. */
    for (uint32_t i = 0; i + 1 < count; i++) {
        entries[i].flags = DLFRZ_FLAG_DATA;
        metas[i].flags = LDR_FLAG_DATA;
    }
    metas[count - 1].flags = LDR_FLAG_MAIN_EXE;
    if (dl_manifest_startup_owners_build(
            entries, metas, count, &owners) < 0)
        goto out;
    if (owners.owner_count != 1 || !owners.is_owner[count - 1]) {
        dl_manifest_startup_owners_release(&owners);
        goto out;
    }
    dl_manifest_startup_owners_release(&owners);
    result = 1;

out:
    if (metas != MAP_FAILED)
        munmap(metas, meta_bytes);
    if (entries != MAP_FAILED)
        munmap(entries, entry_bytes);
    return result;
}

int main(void)
{
    if (!large_table_gate()) return 1;
    if (!truncation_gate()) return 2;
    if (!runtime_file_revision_gate()) return 3;
    if (!version_index_gate()) return 4;
    if (!version_need_index_gate()) return 5;
    if (!manifest_startup_owner_gate()) return 6;
    if (!symbol_lookup_complexity_gate()) return 7;
    return 0;
}
