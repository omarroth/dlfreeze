/* Exercise the runtime PT_DYNAMIC reader in its real translation unit. */
#include <sched.h>
#include <time.h>
#include <sys/wait.h>

#ifndef MADV_WIPEONFORK
#define MADV_WIPEONFORK 18
#endif

#define DLFREEZE_SYMBOL_LOOKUP_COMPLEXITY_GATE 1
#define DLFREEZE_MEMCHR_COMPLEXITY_GATE 1
#define DLFREEZE_RUNTIME_LOCK_SIGNAL_GATE 1
#include "../src/loader.c"

static const void *reference_memchr_exact(const void *memory, int value,
                                          size_t length)
{
    const unsigned char *cursor = memory;
    unsigned char byte = (unsigned char)value;

    for (size_t i = 0; i < length; i++)
        if (cursor[i] == byte)
            return cursor + i;
    return NULL;
}

static int loader_memcmp_gate(void)
{
    long page_long = sysconf(_SC_PAGESIZE);
    unsigned char *mapping;
    unsigned char *left;
    unsigned char *right;
    size_t page;
    int valid = 1;

    if (page_long < 1024 || (uintmax_t)page_long > SIZE_MAX / 5U)
        return 0;
    page = (size_t)page_long;
    mapping = mmap(NULL, 5U * page, PROT_NONE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return 0;
    left = mapping + page;
    right = mapping + 3U * page;
    if (mprotect(left, page, PROT_READ | PROT_WRITE) < 0 ||
        mprotect(right, page, PROT_READ | PROT_WRITE) < 0) {
        munmap(mapping, 5U * page);
        return 0;
    }
    if (ldr_memcmp(mapping, NULL, 0) != 0 ||
        ldr_memcmp(NULL, mapping, 0) != 0)
        valid = 0;
    for (size_t length = 1; length <= 260; length++) {
        for (size_t alignment = 0; alignment < 16; alignment++) {
            unsigned char *a = left + page - length;
            unsigned char *b = right + alignment;
            size_t positions[] = {0, 15, 16, 31, 32, 63, 64,
                                  length / 2, length - 1};

            ldr_memset(a, 0x80, length);
            ldr_memset(b, 0x80, length);
            if (ldr_memcmp(a, b, length) != 0 ||
                ldr_memcmp(b, a, length) != 0 ||
                ldr_memcmp(a, a, length) != 0)
                valid = 0;
            for (size_t i = 0; i < sizeof(positions) / sizeof(positions[0]); i++) {
                size_t position = positions[i];

                if (position >= length)
                    continue;
                b[position] = 0xff;
                /* A later opposite mismatch must not change ordering. */
                if (position + 1 < length)
                    b[position + 1] = 0;
                if (ldr_memcmp(a, b, length) >= 0 ||
                    ldr_memcmp(b, a, length) <= 0)
                    valid = 0;
                b[position] = 0x7f;
                if (ldr_memcmp(a, b, length) <= 0 ||
                    ldr_memcmp(b, a, length) >= 0)
                    valid = 0;
                b[position] = 0x80;
                if (position + 1 < length)
                    b[position + 1] = 0x80;
            }
        }
    }
    ldr_memset(left, 0x55, page);
    ldr_memset(right, 0x55, page);
    if (ldr_memcmp(left, right, page) != 0)
        valid = 0;
    right[page - 1] = 0x54;
    if (ldr_memcmp(left, right, page) <= 0 ||
        ldr_memcmp(right, left, page) >= 0)
        valid = 0;
    munmap(mapping, 5U * page);
    return valid;
}

static int loader_memchr_gate(void)
{
    static const int edge_values[] = {
        -257, -1, 0, 1, 0x55, 0x8b, 0xff, 0x100, 0x18b
    };
    long page_size_long = sysconf(_SC_PAGESIZE);
    size_t word_size = sizeof(uintptr_t);
    size_t page_size;
    size_t complexity_length;
    unsigned char *mapping = MAP_FAILED;
    unsigned char *page;
    unsigned char *guard;
    int valid = 0;

    if (page_size_long <= 0 ||
        (uintmax_t)page_size_long > SIZE_MAX / 3U)
        return 0;
    page_size = (size_t)page_size_long;
    if (page_size < 8U * word_size)
        return 0;
    complexity_length = page_size -
        page_size % (LDR_MEMCHR_VECTOR_BATCH *
                     LDR_MEMCHR_VECTOR_BYTES);
    mapping = mmap(NULL, 3U * page_size, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return 0;
    page = mapping + page_size;
    guard = page + page_size;
    if (mprotect(page, page_size, PROT_READ | PROT_WRITE) != 0)
        goto out;

    /* A zero-length search must not inspect even a PROT_NONE address. */
    if (ldr_memchr(mapping, 0, 0) != NULL ||
        ldr_memchr(guard, 0, 0) != NULL)
        goto out;

    /* This is a deterministic complexity gate, not a timing assertion.  A
     * long aligned miss must use exactly one bounded load per vector while
     * amortizing loop control across four vectors. */
    ldr_memset(page, 0x55, complexity_length);
    g_ldr_memchr_word_loads = 0;
    g_ldr_memchr_byte_loads = 0;
    g_ldr_memchr_vector_loads = 0;
    g_ldr_memchr_vector_batch_iterations = 0;
    g_ldr_memchr_vector_batch_reductions = 0;
    g_ldr_memchr_batch_iterations = 0;
    g_ldr_memchr_single_word_iterations = 0;
    if (ldr_memchr(page, 0xaa, complexity_length) != NULL ||
        g_ldr_memchr_vector_loads !=
            complexity_length / LDR_MEMCHR_VECTOR_BYTES ||
        g_ldr_memchr_vector_batch_iterations !=
            complexity_length /
                (LDR_MEMCHR_VECTOR_BATCH * LDR_MEMCHR_VECTOR_BYTES) ||
        g_ldr_memchr_vector_batch_reductions !=
            complexity_length /
                (LDR_MEMCHR_VECTOR_BATCH * LDR_MEMCHR_VECTOR_BYTES) ||
        g_ldr_memchr_word_loads != 0 ||
        g_ldr_memchr_byte_loads != 0 ||
        g_ldr_memchr_batch_iterations != 0 ||
        g_ldr_memchr_single_word_iterations != 0)
        goto out;

    /* Every possible first-match position in one aggregate vector batch must
     * retain exact address order.  Multiple matches also prove that a later
     * equality vector cannot be selected ahead of an earlier one. */
    for (size_t position = 0;
         position < LDR_MEMCHR_VECTOR_BATCH * LDR_MEMCHR_VECTOR_BYTES;
         position++) {
        ldr_memset(page, 0x55,
                   LDR_MEMCHR_VECTOR_BATCH * LDR_MEMCHR_VECTOR_BYTES);
        page[position] = 0xaa;
        if (ldr_memchr(
                page, 0xaa,
                LDR_MEMCHR_VECTOR_BATCH * LDR_MEMCHR_VECTOR_BYTES) !=
            page + position)
            goto out;
    }
    ldr_memset(page, 0x55,
               2U * LDR_MEMCHR_VECTOR_BATCH * LDR_MEMCHR_VECTOR_BYTES);
    page[4] = 0xaa;
    page[16] = 0xaa;
    page[31] = 0xaa;
    page[63] = 0xaa;
    page[70] = 0xaa;
    if (ldr_memchr(
            page, 0xaa,
            2U * LDR_MEMCHR_VECTOR_BATCH * LDR_MEMCHR_VECTOR_BYTES) !=
        page + 4)
        goto out;

    for (size_t alignment = 0;
         alignment < LDR_MEMCHR_VECTOR_BYTES; alignment++) {
        unsigned char *start = page + alignment;
        size_t length = page_size - alignment;
        size_t positions[] = {
            0, 1, word_size - 1, word_size, word_size + 1,
            2U * word_size - 1U, 2U * word_size,
            3U * word_size - 1U, 3U * word_size,
            4U * word_size - 1U, 4U * word_size, length - 1
        };

        /* Every starting alignment reaches the upper guard exactly.  A
         * no-match scan catches any word load past the declared range. */
        ldr_memset(start, 0x55, length);
        if (ldr_memchr(start, 0xaa, length) != NULL)
            goto out;
        for (unsigned int value_index = 0; value_index < 3; value_index++) {
            static const unsigned char targets[] = {0, 0x8b, 0xff};
            unsigned char target = targets[value_index];

            for (size_t position_index = 0;
                 position_index < sizeof(positions) / sizeof(positions[0]);
                 position_index++) {
                size_t position = positions[position_index];

                if (position >= length)
                    continue;
                ldr_memset(start, 0x55, length);
                start[position] = target;
                if (ldr_memchr(start, target, length) != start + position)
                    goto out;
            }
        }

        for (size_t i = 0; i < length; i++)
            start[i] = (unsigned char)(i * 37U + alignment * 19U);
        for (int value = 0; value <= UINT8_MAX; value++) {
            if (ldr_memchr(start, value, length) !=
                reference_memchr_exact(start, value, length))
                goto out;
        }
    }

    /* Short spans ending immediately before the guard exercise every tail
     * length and, consequently, every starting alignment near a page edge. */
    for (size_t length = 0; length <= 4U * word_size + 3U; length++) {
        unsigned char *start = guard - length;

        for (size_t i = 0; i < length; i++)
            start[i] = (unsigned char)(i * 73U + length * 11U);
        for (size_t i = 0;
             i < sizeof(edge_values) / sizeof(edge_values[0]); i++) {
            int value = edge_values[i];

            if (ldr_memchr(start, value, length) !=
                reference_memchr_exact(start, value, length))
                goto out;
        }
    }
    valid = 1;

out:
    if (mapping != MAP_FAILED)
        munmap(mapping, 3U * page_size);
    return valid;
}

static int temporary_file(size_t size)
{
    const char *tmpdir = getenv("TMPDIR");
    char path[PATH_MAX];
    int fd;
    int length;

    if (!tmpdir || !tmpdir[0])
        tmpdir = "/tmp";
    length = snprintf(path, sizeof(path), "%s%sdlfreeze-dynamic-reader-XXXXXX",
                      tmpdir, tmpdir[strlen(tmpdir) - 1] == '/' ? "" : "/");
    if (length < 0 || (size_t)length >= sizeof(path))
        return -1;
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

static int resolver_tls_template_overlap_gate(void)
{
    struct loaded_obj object = {0};
    Elf64_Phdr tls = {0};

    tls.p_type = PT_TLS;
    tls.p_vaddr = UINT64_C(0x1000);
    tls.p_filesz = UINT64_C(0x20);
    tls.p_memsz = UINT64_C(0x8000);
    object.phdr = &tls;
    object.phdr_num = 1;

    if (!relocation_destination_overlaps_tls_template(
            &object, UINT64_C(0x1000), 1) ||
        !relocation_destination_overlaps_tls_template(
            &object, UINT64_C(0x101f), 2) ||
        relocation_destination_overlaps_tls_template(
            &object, UINT64_C(0x1020), 1) ||
        relocation_destination_overlaps_tls_template(
            &object, UINT64_C(0x1800), sizeof(uint64_t)))
        return 0;

    /* A pure .tbss template has no object-image bytes to mutate.  Its
     * conceptual address extent may overlap a real writable section. */
    tls.p_filesz = 0;
    if (relocation_destination_overlaps_tls_template(
            &object, UINT64_C(0x1000), sizeof(uint64_t)) ||
        relocation_destination_overlaps_tls_template(
            &object, UINT64_C(0x1800), sizeof(uint64_t)))
        return 0;

    /* Exercise the post-setup path, which uses the admitted TLS record. */
    object.phdr = NULL;
    object.phdr_num = 0;
    object.tls.vaddr = UINT64_C(0x1000);
    object.tls.filesz = UINT64_C(0x20);
    object.tls.memsz = UINT64_C(0x8000);
    if (!relocation_destination_overlaps_tls_template(
            &object, UINT64_C(0x1018), sizeof(uint64_t)) ||
        relocation_destination_overlaps_tls_template(
            &object, UINT64_C(0x1800), sizeof(uint64_t)) ||
        !relocation_destination_overlaps_tls_template(
            &object, UINT64_MAX, sizeof(uint64_t)) ||
        relocation_destination_overlaps_tls_template(
            &object, UINT64_MAX, 0))
        return 0;

    object.tls.filesz = 0;
    return !relocation_destination_overlaps_tls_template(
        &object, UINT64_C(0x1800), sizeof(uint64_t));
}

static int large_table_gate(void)
{
    const size_t entry_count = 65536;
    const size_t size = entry_count * sizeof(Elf64_Dyn);
    const size_t expected_reads =
        (size + DL_DYNAMIC_READ_CHUNK_BYTES - 1) /
        DL_DYNAMIC_READ_CHUNK_BYTES;
    Elf64_Phdr phdrs[2];
    Elf64_Dyn *entries;
    size_t reads = 0;
    int fd;
    int result = 0;

    fd = temporary_file(size);
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

static int relocation_admission_single_pass_gate(void)
{
    enum { COUNT = 4096, DYNAMIC = 16, SYMTAB = 512, STRTAB = 608,
           RELA = 1024, PLT = RELA + COUNT * sizeof(Elf64_Rela),
           SIZE = PLT + 2 * sizeof(Elf64_Rela) };
    struct dlfrz_lib_meta meta = { .flags = LDR_FLAG_SHLIB };
    Elf64_Phdr phdrs[2] = {
        { .p_type = PT_LOAD, .p_flags = PF_R,
          .p_filesz = SIZE, .p_memsz = SIZE },
        { .p_type = PT_DYNAMIC, .p_vaddr = DYNAMIC,
          .p_filesz = 12 * sizeof(Elf64_Dyn),
          .p_memsz = 12 * sizeof(Elf64_Dyn) }
    };
    struct loaded_obj object = {0};
    uint8_t key[16] = {0};
    unsigned char *image = calloc(1, SIZE);
    int result = 0;

    if (!image)
        return 0;
    if (vfs_seed_hash_key(key) < 0)
        goto out;
    Elf64_Dyn dynamic[] = {
        { .d_tag = DT_SYMTAB, .d_un.d_ptr = SYMTAB },
        { .d_tag = DT_STRTAB, .d_un.d_ptr = STRTAB },
        { .d_tag = DT_STRSZ, .d_un.d_val = 1 },
        { .d_tag = DT_SYMENT, .d_un.d_val = sizeof(Elf64_Sym) },
        { .d_tag = DT_RELA, .d_un.d_ptr = RELA },
        { .d_tag = DT_RELASZ, .d_un.d_val = COUNT * sizeof(Elf64_Rela) },
        { .d_tag = DT_RELAENT, .d_un.d_val = sizeof(Elf64_Rela) },
        { .d_tag = DT_RELACOUNT, .d_un.d_val = COUNT - 1 },
        { .d_tag = DT_JMPREL, .d_un.d_ptr = PLT },
        { .d_tag = DT_PLTRELSZ, .d_un.d_val = 2 * sizeof(Elf64_Rela) },
        { .d_tag = DT_PLTREL, .d_un.d_val = DT_RELA },
        { .d_tag = DT_NULL }
    };
    memcpy(image + DYNAMIC, dynamic, sizeof(dynamic));
    Elf64_Rela *relocations = (Elf64_Rela *)(image + RELA);
    Elf64_Rela *plt = (Elf64_Rela *)(image + PLT);
    for (size_t i = 0; i < COUNT - 1; i++)
        relocations[i].r_info = ELF64_R_INFO(0, ARCH_RELOC_RELATIVE);
    relocations[COUNT - 1].r_info = ELF64_R_INFO(1, ARCH_RELOC_ABS);
    plt[0].r_info = plt[1].r_info = ELF64_R_INFO(3, ARCH_RELOC_JUMP_SLOT);

    for (int variant = 0; variant < 6; variant++) {
        memset(&object, 0, sizeof(object));
        object.base = (uintptr_t)image;
        object.phdr = phdrs;
        object.phdr_num = 2;
        ((Elf64_Dyn *)(image + DYNAMIC))[7].d_un.d_val = COUNT - 1;
        relocations[0].r_info = ELF64_R_INFO(0, ARCH_RELOC_RELATIVE);
        plt[1].r_info = ELF64_R_INFO(3, ARCH_RELOC_JUMP_SLOT);
        if (variant == 1)
            relocations[0].r_info = ELF64_R_INFO(0, ARCH_RELOC_ABS);
        if (variant == 2)
            relocations[0].r_info = ELF64_R_INFO(1, ARCH_RELOC_RELATIVE);
        if (variant == 3)
            ((Elf64_Dyn *)(image + DYNAMIC))[7].d_un.d_val = COUNT + 1;
        if (variant == 4)
            plt[1].r_info = ELF64_R_INFO(UINT32_MAX, ARCH_RELOC_JUMP_SLOT);
        if (variant == 5)
            plt[1].r_info = ELF64_R_INFO(4, ARCH_RELOC_JUMP_SLOT);
        g_loaded_rela_reads = 0;
        int rc = parse_dynamic(&object, &meta);
        int ok = variant == 0
            ? rc == 0 && object.dynsym_count == 4 &&
              g_loaded_rela_reads == COUNT + 2
            : rc < 0;
        if (!ok)
            fprintf(stderr, "relocation admission variant=%d rc=%d "
                    "symbols=%u reads=%zu\n", variant, rc,
                    object.dynsym_count, g_loaded_rela_reads);
        dl_release_runtime_mapping(&object);
        if (!ok)
            goto out;
    }
    result = 1;
out:
    free(image);
    return result;
}

static int truncation_gate(void)
{
    const size_t actual_size = 2 * sizeof(Elf64_Dyn) + 7;
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
    fd = temporary_file(actual_size);
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
    struct stat before;
    struct stat unchanged;
    struct stat truncated;
    Elf64_Phdr ph = {0};
    const struct dlfrz_gnu_property_profile property_profile = {0};
    uint64_t saved_page_size = g_page_size;
    long page_size = sysconf(_SC_PAGESIZE);
    int fd;
    int result = 0;

    if (page_size <= 0 ||
        ((uint64_t)page_size & ((uint64_t)page_size - 1)) != 0)
        return 0;
    fd = temporary_file((size_t)page_size);
    if (fd < 0)
        return 0;
    g_page_size = (uint64_t)page_size;
    ph.p_type = PT_LOAD;
    ph.p_filesz = 1;
    ph.p_memsz = 1;
    ph.p_flags = PF_R;
    if (fstat(fd, &before) < 0 || fstat(fd, &unchanged) < 0 ||
        !runtime_file_revision_matches(&before, &unchanged) ||
        runtime_probe_file_mapping_policy(fd, &ph, &property_profile) < 0)
        goto out;

    /* The policy probe must reject an unrepresentable file offset without
     * constructing or touching a source-file mapping. */
    ph.p_offset = UINT64_MAX;
    if (runtime_probe_file_mapping_policy(fd, &ph, &property_profile) == 0)
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

static int symbol_queries_equal(struct symbol_lookup_query *left,
                                struct symbol_lookup_query *right)
{
    uint64_t left_keyed_hash;
    uint64_t right_keyed_hash;
    uint32_t left_sysv_hash;
    uint32_t right_sysv_hash;

    return left->name == right->name &&
           left->key.length == right->key.length &&
           left->key.fingerprint == right->key.fingerprint &&
           left->gnu_hash == right->gnu_hash &&
           symbol_lookup_query_sysv_hash(left, &left_sysv_hash) &&
           symbol_lookup_query_sysv_hash(right, &right_sysv_hash) &&
           left_sysv_hash == right_sysv_hash &&
           symbol_lookup_query_keyed_hash(left, &left_keyed_hash) &&
           symbol_lookup_query_keyed_hash(right, &right_keyed_hash) &&
           left_keyed_hash == right_keyed_hash;
}

static int symbol_query_equivalence_gate(void)
{
    static const char high_bytes[] = {
        'x', (char)0x80, (char)0xff, 'y', '\0'
    };
    static const char *const cases[] = {
        "", "a", "ordinary_symbol_name", high_bytes,
        "gkyeawephq", "vikjksoybz", "aq", "ba"
    };
    static const unsigned char key_bytes[16] = {
        0x9f, 0x12, 0x47, 0x88, 0x05, 0xab, 0xde, 0x31,
        0x73, 0x26, 0xc4, 0x59, 0xe0, 0x1d, 0x6a, 0xb5
    };
    const size_t long_length = 1024U * 1024U;
    struct symbol_lookup_query gnu_left;
    struct symbol_lookup_query gnu_right;
    struct symbol_lookup_query sysv_left;
    struct symbol_lookup_query sysv_right;
    char malformed[] = { 'a', 'b', 'c', '\0', 'x', '\0' };
    char *long_name = MAP_FAILED;
    int result = 0;

    if (vfs_seed_hash_key(key_bytes) < 0)
        return 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const char *name = cases[i];
        size_t length = strlen(name);
        struct symbol_lookup_query fused;
        struct symbol_lookup_query known;

        if (!symbol_lookup_query_init(name, &fused) ||
            !fused.keyed_hash_valid || fused.keyed_hash_deferred ||
            fused.key.length != length ||
            fused.key.fingerprint !=
                symbol_name_fingerprint_n(name, length) ||
            fused.keyed_hash != vfs_hash_n(name, length) ||
            fused.gnu_hash != gnu_hash_calc(name) ||
            fused.sysv_hash != sysv_hash_calc(name) ||
            !symbol_lookup_query_init_known_key(
                name, &fused.key, &known) ||
            known.keyed_hash_valid || !known.keyed_hash_deferred ||
            !symbol_queries_equal(&fused, &known))
            return 0;
    }

    /* Hash value zero is data, not the lazy-state sentinel.  Keep this
     * explicit so a future compact representation cannot silently disable
     * either cache or GNU_UNIQUE consumers for a valid zero result. */
    {
        struct symbol_lookup_query zero_hash;
        uint64_t resolved = UINT64_MAX;

        if (!symbol_lookup_query_init("zero_hash", &zero_hash))
            return 0;
        zero_hash.keyed_hash = 0;
        zero_hash.keyed_hash_valid = 1;
        zero_hash.keyed_hash_deferred = 0;
        if (!symbol_lookup_query_keyed_hash(&zero_hash, &resolved) ||
            resolved != 0)
            return 0;
    }

    long_name = mmap(NULL, long_length + 1, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (long_name == MAP_FAILED)
        return 0;
    for (size_t i = 0; i < long_length; i++)
        long_name[i] = (char)(i % 255U + 1U);
    long_name[long_length] = '\0';
    {
        struct symbol_lookup_query fused;
        struct symbol_lookup_query known;

        if (!symbol_lookup_query_init(long_name, &fused) ||
            !fused.keyed_hash_valid || fused.keyed_hash_deferred ||
            fused.key.length != long_length ||
            fused.keyed_hash != vfs_hash_n(long_name, long_length) ||
            fused.gnu_hash != gnu_hash_calc(long_name) ||
            fused.sysv_hash != sysv_hash_calc(long_name) ||
            !symbol_lookup_query_init_known_key(
                long_name, &fused.key, &known) ||
            known.keyed_hash_valid || !known.keyed_hash_deferred ||
            !symbol_queries_equal(&fused, &known))
            goto out;
    }

    /* A trusted key still cannot relax termination: too-short, too-long,
     * and unrepresentable bounds all fail without falling back to strlen. */
    {
        struct symbol_lookup_query query;
        struct loaded_symbol_name_key malformed_key = {
            .fingerprint = UINT64_C(0x1234),
            .length = 2
        };

        if (symbol_lookup_query_init_known_key(
                malformed, &malformed_key, &query))
            goto out;
        malformed_key.length = 4;
        if (symbol_lookup_query_init_known_key(
                malformed, &malformed_key, &query))
            goto out;
        malformed_key.length = SIZE_MAX;
        if (symbol_lookup_query_init_known_key(
                malformed, &malformed_key, &query))
            goto out;
    }

    /* Exercise real 32-bit GNU and SysV collisions, then force the keyed
     * work filter to collide too.  The final exact byte comparison remains
     * authoritative in both cases. */
    if (!symbol_lookup_query_init("gkyeawephq", &gnu_left) ||
        !symbol_lookup_query_init("vikjksoybz", &gnu_right) ||
        gnu_left.gnu_hash != gnu_right.gnu_hash ||
        loaded_name_key_eq("vikjksoybz", &gnu_left.key, &gnu_left) ||
        !symbol_lookup_query_init("aq", &sysv_left) ||
        !symbol_lookup_query_init("ba", &sysv_right) ||
        sysv_left.sysv_hash != sysv_right.sysv_hash ||
        loaded_name_key_eq("ba", &sysv_left.key, &sysv_left))
        goto out;
    result = 1;

out:
    munmap(long_name, long_length + 1);
    return result;
}

static int symbol_name_span_gate(void)
{
    const size_t strings_size = 16384;
    const size_t count = 7;
    const size_t size = strings_size + count * sizeof(Elf64_Sym);
    static const uint32_t offsets[] = {0, 8, 8, 64, 1023, 4095, 16383};
    struct loaded_obj prototype = {0};
    Elf64_Phdr phdr = {0};
    unsigned char key[16] = {7, 6, 5, 4};
    uint8_t *image = mmap(NULL, size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    Elf64_Sym *symbols;
    int valid = 1;

    if (image == MAP_FAILED)
        return 0;
    if (vfs_seed_hash_key(key) < 0) {
        munmap(image, size);
        return 0;
    }
    memset(image, 'a', strings_size);
    image[0] = image[63] = image[strings_size - 1] = 0;
    symbols = (void *)(image + strings_size);
    for (size_t i = 0; i < count; i++)
        symbols[i].st_name = offsets[i];
    phdr.p_type = PT_LOAD;
    phdr.p_flags = PF_R;
    phdr.p_filesz = phdr.p_memsz = size;
    prototype.base = (uintptr_t)image;
    prototype.phdr = &phdr;
    prototype.phdr_num = 1;
    prototype.dynstr = (const char *)image;
    prototype.dynstr_size = strings_size;
    prototype.dynsym = symbols;
    prototype.dynsym_count = prototype.dynsym_admitted_count = count;

    for (unsigned int minimum = 0; minimum <= 3; minimum += 3) {
        struct loaded_obj object = prototype;

        symbols[0].st_name = minimum;
        g_symbol_name_admission_bytes = g_symbol_name_ref_boundaries = 0;
        if (build_loaded_symbol_name_keys(&object) < 0) {
            valid = 0;
            break;
        }
        /* Long spans, duplicate references, suffix sharing, empty strings,
         * and an unused prefix all retain exactly the ordinary query keys. */
        if (g_symbol_name_ref_boundaries != 6 ||
            g_symbol_name_admission_bytes != strings_size - minimum)
            valid = 0;
        for (size_t i = 0; i < count; i++) {
            struct symbol_lookup_query expected;
            const struct loaded_symbol_name_key *actual =
                &object.symbol_name_keys[i];

            if (!symbol_lookup_query_init(
                    (const char *)image + symbols[i].st_name, &expected) ||
                actual->length != expected.key.length ||
                actual->fingerprint != expected.key.fingerprint ||
                actual->gnu_hash != expected.gnu_hash ||
                actual->dynstr_offset != symbols[i].st_name)
                valid = 0;
        }
        munmap(object.runtime_symbol_name_mapping,
               object.runtime_symbol_name_mapping_size);
    }
    {
        struct loaded_obj object = prototype;

        symbols[count - 1].st_name = strings_size;
        if (build_loaded_symbol_name_keys(&object) >= 0) {
            munmap(object.runtime_symbol_name_mapping,
                   object.runtime_symbol_name_mapping_size);
            valid = 0;
        }
    }
    munmap(image, size);
    return valid;
}

static int symbol_name_radix_sort_gate(void)
{
    const size_t count = 300;
    const size_t refs_bytes =
        count * sizeof(struct loaded_symbol_name_ref);
    const size_t scratch_size = refs_bytes +
        LOADED_SYMBOL_NAME_RADIX_BUCKETS * sizeof(size_t);
    struct loaded_symbol_name_ref refs[300];
    void *scratch = MAP_FAILED;
    int result = 0;

    scratch = mmap(NULL, scratch_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (scratch == MAP_FAILED)
        return 0;
    for (size_t i = 0; i < count; i++) {
        if (i % 17U == 0)
            refs[i].offset = 0;
        else if (i % 19U == 0)
            refs[i].offset = UINT32_MAX;
        else
            refs[i].offset =
                (uint32_t)(i * UINT32_C(2654435761));
        refs[i].destination =
            (struct loaded_symbol_name_key *)(uintptr_t)(i + 1U);
    }
    /* Refuse undersized scratch before touching either array. */
    if (loaded_symbol_name_refs_radix_sort(
            refs, count, scratch, scratch_size - 1U))
        goto out;
    if (!loaded_symbol_name_refs_radix_sort(
            refs, count, scratch, scratch_size))
        goto out;
    for (size_t i = 1; i < count; i++) {
        if (refs[i - 1].offset > refs[i].offset)
            goto out;
        if (refs[i - 1].offset == refs[i].offset &&
            (uintptr_t)refs[i - 1].destination >=
                (uintptr_t)refs[i].destination)
            goto out;
    }
    result = 1;

out:
    munmap(scratch, scratch_size);
    return result;
}

static int hash_view_cache_gate(void)
{
    const size_t image_size = 128;
    struct loaded_obj readonly_object;
    struct loaded_obj writable_object;
    struct loaded_obj bss_object;
    struct gnu_hash_view gnu_view;
    struct sysv_hash_view sysv_view;
    Elf64_Phdr loads[2];
    uint8_t *image = MAP_FAILED;
    uint32_t *gnu;
    uint64_t *bloom;
    uint32_t *gnu_bucket;
    uint32_t *gnu_chain;
    uint32_t *sysv;
    uint32_t chain_value;
    int result = 0;

    image = mmap(NULL, image_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (image == MAP_FAILED)
        return 0;
    memset(image, 0, image_size);
    memset(loads, 0, sizeof(loads));
    loads[0].p_type = PT_LOAD;
    loads[0].p_flags = PF_R;
    loads[0].p_filesz = image_size;
    loads[0].p_memsz = image_size;
    loads[1] = loads[0];
    loads[1].p_flags = PF_R | PF_W;

    gnu = (uint32_t *)image;
    bloom = (uint64_t *)(gnu + 4);
    gnu_bucket = (uint32_t *)(bloom + 1);
    gnu_chain = gnu_bucket + 1;
    gnu[0] = 1;
    gnu[1] = 1;
    gnu[2] = 1;
    gnu[3] = 5;

    /* Live PF_W geometry may change, but it must never promote zero-filled
     * PT_LOAD tail bytes into a GNU hash table.  The baseline fixed arrays
     * end immediately before the first chain word; expanding either
     * variable-length array crosses p_filesz while remaining inside p_memsz. */
    memset(&bss_object, 0, sizeof(bss_object));
    loads[1].p_filesz = (size_t)((uint8_t *)gnu_chain - image);
    bss_object.base = (uintptr_t)image;
    bss_object.phdr = &loads[1];
    bss_object.phdr_num = 1;
    bss_object.gnu_hash = gnu;
    if (!get_gnu_hash_view(&bss_object, &gnu_view))
        goto out;
    gnu[2] = 2;
    if (get_gnu_hash_view(&bss_object, &gnu_view))
        goto out;
    gnu[2] = 1;
    gnu[0] = 2;
    if (get_gnu_hash_view(&bss_object, &gnu_view))
        goto out;
    gnu[0] = 1;
    loads[1].p_filesz = image_size;
    bloom[0] = UINT64_MAX;
    gnu_bucket[0] = 1;
    gnu_chain[0] = UINT32_C(0x12345679);
    /* Mapped padding is not part of the admitted chain. */
    gnu_chain[1] = UINT32_C(0xabcdef01);

    memset(&readonly_object, 0, sizeof(readonly_object));
    readonly_object.base = (uintptr_t)image;
    readonly_object.phdr = loads;
    readonly_object.phdr_num = 1;
    readonly_object.gnu_hash = gnu;

    /* Invalid header geometry continues to fail before any cache can be
     * published, even though the surrounding mapping is large enough for
     * the fixed header itself. */
    gnu[3] = 32;
    if (get_gnu_hash_view(&readonly_object, &gnu_view))
        goto out;
    gnu[3] = 5;
    gnu[2] = UINT32_MAX;
    if (get_gnu_hash_view(&readonly_object, &gnu_view))
        goto out;
    gnu[2] = 1;

    if (!get_gnu_hash_view(&readonly_object, &gnu_view) ||
        gnu_hash_symbol_count_loaded(&readonly_object) != 2)
        goto out;
    cache_validated_gnu_hash_view(&readonly_object, &gnu_view, 2);
    if (!readonly_object.gnu_hash_view_cached ||
        !get_gnu_hash_view(&readonly_object, &gnu_view) ||
        !gnu_view.chain_count_valid || gnu_view.chain_count != 1 ||
        !gnu_hash_chain_value(
            &readonly_object, &gnu_view, 1, &chain_value) ||
        chain_value != UINT32_C(0x12345679) ||
        gnu_hash_chain_value(
            &readonly_object, &gnu_view, 2, &chain_value))
        goto out;
    dl_release_runtime_mapping(&readonly_object);
    if (readonly_object.gnu_hash_view_cached ||
        readonly_object.gnu_hash_cached_bloom ||
        readonly_object.gnu_hash_cached_buckets ||
        readonly_object.gnu_hash_cached_chain_addr ||
        readonly_object.gnu_hash_cached_chain_count)
        goto out;

    /* A writable overlap must keep the live validation path.  Mutations to
     * both header geometry and chain contents are consequently visible on
     * the next read instead of being served from stale admission state. */
    memset(&writable_object, 0, sizeof(writable_object));
    writable_object.base = (uintptr_t)image;
    writable_object.phdr = loads;
    writable_object.phdr_num = 2;
    writable_object.gnu_hash = gnu;
    if (!get_gnu_hash_view(&writable_object, &gnu_view))
        goto out;
    cache_validated_gnu_hash_view(&writable_object, &gnu_view, 2);
    if (writable_object.gnu_hash_view_cached)
        goto out;
    gnu[3] = 6;
    gnu_chain[0] = UINT32_C(0x76543211);
    if (!get_gnu_hash_view(&writable_object, &gnu_view) ||
        gnu_view.bloom_shift != 6 || gnu_view.chain_count_valid ||
        !gnu_hash_chain_value(
            &writable_object, &gnu_view, 1, &chain_value) ||
        chain_value != UINT32_C(0x76543211))
        goto out;
    gnu[3] = 5;

    sysv = (uint32_t *)(image + 64);
    sysv[0] = 1;
    sysv[1] = 2;
    sysv[2] = 1;
    sysv[3] = STN_UNDEF;
    sysv[4] = STN_UNDEF;
    sysv[5] = UINT32_C(0xfefefefe);
    memset(&readonly_object, 0, sizeof(readonly_object));
    readonly_object.base = (uintptr_t)image;
    readonly_object.phdr = loads;
    readonly_object.phdr_num = 1;
    readonly_object.sysv_hash = sysv;

    sysv[1] = UINT32_MAX;
    if (get_sysv_hash_view(&readonly_object, &sysv_view))
        goto out;
    sysv[1] = 2;
    if (!get_sysv_hash_view(&readonly_object, &sysv_view))
        goto out;
    cache_validated_sysv_hash_view(&readonly_object, &sysv_view);
    if (!readonly_object.sysv_hash_view_cached ||
        !get_sysv_hash_view(&readonly_object, &sysv_view) ||
        sysv_view.nbuckets != 1 || sysv_view.nchain != 2 ||
        sysv_view.buckets != sysv + 2 || sysv_view.chains != sysv + 3)
        goto out;

    memset(&writable_object, 0, sizeof(writable_object));
    writable_object.base = (uintptr_t)image;
    writable_object.phdr = &loads[1];
    writable_object.phdr_num = 1;
    writable_object.sysv_hash = sysv;
    if (!get_sysv_hash_view(&writable_object, &sysv_view))
        goto out;
    cache_validated_sysv_hash_view(&writable_object, &sysv_view);
    if (writable_object.sysv_hash_view_cached)
        goto out;
    sysv[0] = 2;
    if (!get_sysv_hash_view(&writable_object, &sysv_view) ||
        sysv_view.nbuckets != 2 || sysv_view.buckets != sysv + 2 ||
        sysv_view.chains != sysv + 4)
        goto out;
    sysv[0] = 1;

    /* The same current-byte rule applies to SysV hash geometry.  A PF_W
     * header cannot grow buckets/chains from the file image into BSS. */
    memset(&bss_object, 0, sizeof(bss_object));
    loads[1].p_filesz = (size_t)((uint8_t *)(sysv + 5) - image);
    bss_object.base = (uintptr_t)image;
    bss_object.phdr = &loads[1];
    bss_object.phdr_num = 1;
    bss_object.sysv_hash = sysv;
    if (!get_sysv_hash_view(&bss_object, &sysv_view))
        goto out;
    sysv[0] = 2;
    if (get_sysv_hash_view(&bss_object, &sysv_view))
        goto out;
    sysv[0] = 1;
    loads[1].p_filesz = image_size;
    dl_release_runtime_mapping(&readonly_object);
    if (readonly_object.sysv_hash_view_cached ||
        readonly_object.sysv_hash_cached_buckets ||
        readonly_object.sysv_hash_cached_chains ||
        readonly_object.sysv_hash_cached_nbuckets ||
        readonly_object.sysv_hash_cached_nchain)
        goto out;
    result = 1;

out:
    munmap(image, image_size);
    return result;
}

static int mutable_dynsym_name_gate(void)
{
    static const char string_bytes[] = "\0alpha\0bravo\0";
    static const unsigned char key_bytes[16] = {
        0x29, 0x71, 0xc8, 0x03, 0xd4, 0x6b, 0x15, 0xae,
        0x5c, 0xe2, 0x90, 0x37, 0xfa, 0x44, 0x81, 0xbd
    };
    const size_t dynsym_offset = 64;
    const size_t image_size = 128;
    struct loaded_obj object = {0};
    struct symbol_lookup_query alpha;
    struct symbol_lookup_query cached_alpha;
    struct symbol_lookup_query bravo;
    struct symbol_lookup_query expected;
    Elf64_Phdr loads[2];
    Elf64_Sym *symbols;
    uint8_t *image = MAP_FAILED;
    int global_object_installed = 0;
    int released = 0;
    int result = 0;

    image = mmap(NULL, image_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (image == MAP_FAILED)
        return 0;
    memset(image, 0, image_size);
    memcpy(image, string_bytes, sizeof(string_bytes));
    symbols = (Elf64_Sym *)(image + dynsym_offset);
    symbols[1].st_name = 1;
    symbols[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    symbols[1].st_shndx = 1;

    memset(loads, 0, sizeof(loads));
    loads[0].p_type = PT_LOAD;
    loads[0].p_flags = PF_R;
    loads[0].p_filesz = sizeof(string_bytes);
    loads[0].p_memsz = sizeof(string_bytes);
    loads[1].p_type = PT_LOAD;
    loads[1].p_flags = PF_R;
    loads[1].p_vaddr = dynsym_offset;
    loads[1].p_filesz = 2 * sizeof(Elf64_Sym);
    loads[1].p_memsz = 2 * sizeof(Elf64_Sym);

    memset(&object, 0, sizeof(object));
    object.base = (uintptr_t)image;
    object.phdr = loads;
    object.phdr_num = 2;
    object.dynstr = (const char *)image;
    object.dynstr_size = sizeof(string_bytes);
    object.dynsym = symbols;
    object.dynsym_count = 2;
    if (vfs_seed_hash_key(key_bytes) < 0 ||
        build_loaded_symbol_name_keys(&object) < 0 ||
        !object.dynstr_readonly || !object.dynsym_readonly ||
        g_nobj != 0)
        goto out;

    memset(&g_all_objs[0], 0, sizeof(g_all_objs[0]));
    g_all_objs[0] = object;
    g_all_objs[0].relocation_scope_root = 0;
    g_all_objs[0].relocation_scope_root_valid = 1;
    global_object_installed = 1;
    clear_resolution_caches();
    g_symbol_query_forward_bytes = 0;
    g_symbol_query_sysv_bytes = 0;
    if (!symbol_lookup_query_init_dynsym(
            &g_all_objs[0], 1, g_all_objs, 1, &alpha) ||
        !symbol_lookup_query_init_dynsym(
            &g_all_objs[0], 1, g_all_objs, 1, &cached_alpha) ||
        strcmp(alpha.name, "alpha") != 0 ||
        alpha.keyed_hash_valid || !alpha.keyed_hash_deferred ||
        alpha.sysv_hash_valid || !alpha.sysv_hash_deferred ||
        alpha.gnu_hash != gnu_hash_calc("alpha") ||
        alpha.key.dynstr_offset != 1 ||
        g_all_objs[0].symbol_name_keys[1].gnu_hash != alpha.gnu_hash ||
        g_symbol_query_forward_bytes != 0 ||
        g_symbol_query_sysv_bytes != 0)
        goto out;
    if (!symbol_queries_equal(&alpha, &cached_alpha) ||
        !alpha.sysv_hash_valid || alpha.sysv_hash_deferred ||
        g_symbol_query_sysv_bytes != 2 * strlen("alpha"))
        goto out;

    /* Keep DT_STRTAB immutable while allowing only DT_SYMTAB to change.
     * A same-length st_name redirect must bypass the admission key and build
     * every query field from the redirected current bytes. */
    loads[1].p_flags = PF_R | PF_W;
    g_all_objs[0].dynsym_readonly = 0;
    symbols[1].st_name = 7;
    if (!symbol_lookup_query_init_dynsym(
            &g_all_objs[0], 1, g_all_objs, 1, &bravo) ||
        !symbol_lookup_query_init("bravo", &expected) ||
        strcmp(bravo.name, "bravo") != 0 ||
        bravo.key.length != alpha.key.length ||
        bravo.key.fingerprint == alpha.key.fingerprint ||
        bravo.key.fingerprint != expected.key.fingerprint ||
        !bravo.keyed_hash_valid || bravo.keyed_hash_deferred ||
        !expected.keyed_hash_valid || expected.keyed_hash_deferred ||
        bravo.keyed_hash != expected.keyed_hash ||
        bravo.gnu_hash != expected.gnu_hash ||
        bravo.sysv_hash != expected.sysv_hash ||
        !loaded_symbol_name_eq_query(
            &g_all_objs[0], &symbols[1], &bravo) ||
        loaded_symbol_name_eq_query(
            &g_all_objs[0], &symbols[1], &alpha))
        goto out;

    symbols[1].st_name = 1;
    if (!loaded_symbol_name_eq_query(
            &g_all_objs[0], &symbols[1], &alpha) ||
        loaded_symbol_name_eq_query(
            &g_all_objs[0], &symbols[1], &bravo))
        goto out;

    clear_resolution_caches();
    memset(&g_all_objs[0], 0, sizeof(g_all_objs[0]));
    global_object_installed = 0;
    dl_release_runtime_mapping(&object);
    released = 1;
    if (object.symbol_name_keys || object.symbol_name_index ||
        object.dynstr_readonly ||
        object.dynsym_readonly || object.runtime_symbol_name_mapping)
        goto out;
    result = 1;

out:
    if (global_object_installed) {
        clear_resolution_caches();
        memset(&g_all_objs[0], 0, sizeof(g_all_objs[0]));
    }
    if (!released && object.runtime_symbol_name_mapping)
        dl_release_runtime_mapping(&object);
    munmap(image, image_size);
    return result;
}

static int mutable_versym_key_gate(void)
{
    static const char string_bytes[] = "\0VER_A\0VER_B\0symbol\0";
    const size_t dynsym_offset = 64;
    const size_t versym_offset = 112;
    const size_t image_size = 128;
    const size_t version_index_size =
        sizeof(struct loaded_version_index) +
        2 * DL_VERSION_PAGE_ENTRIES * sizeof(struct loaded_version_entry);
    struct loaded_obj object = {0};
    struct symbol_lookup_query version_a;
    struct symbol_lookup_query version_b;
    struct loaded_version_index *version_index = MAP_FAILED;
    struct loaded_version_entry *entry;
    Elf64_Phdr loads[3];
    Elf64_Sym *symbols;
    uint16_t *versions;
    uint8_t *image = MAP_FAILED;
    int hidden = 0;
    int result = 0;

    image = mmap(NULL, image_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    version_index = mmap(NULL, version_index_size,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (image == MAP_FAILED || version_index == MAP_FAILED)
        goto out;
    memset(image, 0, image_size);
    memset(version_index, 0, version_index_size);
    memcpy(image, string_bytes, sizeof(string_bytes));
    symbols = (Elf64_Sym *)(image + dynsym_offset);
    versions = (uint16_t *)(image + versym_offset);
    symbols[1].st_name = 13;
    symbols[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    symbols[1].st_shndx = 1;
    versions[1] = 2;

    version_index->page_slots[0] = 1;
    version_index->page_slots[DL_VERSION_PAGE_COUNT - 1] = 2;
    entry = loaded_version_index_entry_mutable(version_index, 2);
    if (!entry)
        goto out;
    entry->definition_name = 1;
    entry->flags = DL_VERSION_ENTRY_DEFINED;
    entry = loaded_version_index_entry_mutable(
        version_index, DL_VERSION_INDEX_MASK);
    if (!entry)
        goto out;
    entry->definition_name = 7;
    entry->flags = DL_VERSION_ENTRY_DEFINED;

    memset(loads, 0, sizeof(loads));
    loads[0].p_type = PT_LOAD;
    loads[0].p_flags = PF_R;
    loads[0].p_filesz = sizeof(string_bytes);
    loads[0].p_memsz = sizeof(string_bytes);
    loads[1].p_type = PT_LOAD;
    loads[1].p_flags = PF_R;
    loads[1].p_vaddr = dynsym_offset;
    loads[1].p_filesz = 2 * sizeof(Elf64_Sym);
    loads[1].p_memsz = 2 * sizeof(Elf64_Sym);
    loads[2].p_type = PT_LOAD;
    loads[2].p_flags = PF_R | PF_W;
    loads[2].p_vaddr = versym_offset;
    loads[2].p_filesz = 2 * sizeof(uint16_t);
    loads[2].p_memsz = 2 * sizeof(uint16_t);

    memset(&object, 0, sizeof(object));
    object.base = (uintptr_t)image;
    object.phdr = loads;
    object.phdr_num = 3;
    object.dynstr = (const char *)image;
    object.dynstr_size = sizeof(string_bytes);
    object.dynsym = symbols;
    object.dynsym_count = 2;
    object.versym = versions;
    object.version_index = version_index;
    g_version_key_admission_visits = 0;
    if (build_loaded_symbol_name_keys(&object) < 0 ||
        !object.dynstr_readonly || !object.dynsym_readonly ||
        object.versym_readonly ||
        g_version_key_admission_visits !=
            2 * (2 * DL_VERSION_PAGE_ENTRIES - 2) ||
        !symbol_lookup_query_init("VER_A", &version_a) ||
        !symbol_lookup_query_init("VER_B", &version_b))
        goto out;

    /* A writable VERSYM selects the normalized entry from one current-value
     * snapshot.  Once selected, its key depends only on the immutable
     * DT_STRTAB bytes and remains safe to use. */
    {
        const char *version = NULL;
        const struct loaded_symbol_name_key *version_key = NULL;

        g_versym_value_reads = 0;
        if (relocation_symbol_version(
                &object, 1, &version, &version_key, &hidden,
                NULL, NULL) != 1 ||
            !version || !version_key || hidden ||
            !loaded_name_key_eq(version, version_key, &version_a) ||
            g_versym_value_reads != 1)
            goto out;
    }
    g_symbol_query_forward_bytes = 0;
    g_versym_value_reads = 0;
    if (classify_versioned_candidate(
            &object, 1, &version_a, 0, 1, NULL) !=
                VERSIONED_CANDIDATE_EXACT ||
        g_symbol_query_forward_bytes != 0 || g_versym_value_reads != 1)
        goto out;
    versions[1] = DL_VERSION_INDEX_MASK;
    {
        const char *version = NULL;
        const struct loaded_symbol_name_key *version_key = NULL;

        g_versym_value_reads = 0;
        if (relocation_symbol_version(
                &object, 1, &version, &version_key, &hidden,
                NULL, NULL) != 1 ||
            !version || !version_key || hidden ||
            !loaded_name_key_eq(version, version_key, &version_b) ||
            g_versym_value_reads != 1)
            goto out;
    }
    g_symbol_query_forward_bytes = 0;
    g_versym_value_reads = 0;
    if (classify_versioned_candidate(
            &object, 1, &version_b, 0, 1, NULL) !=
                VERSIONED_CANDIDATE_EXACT ||
        g_symbol_query_forward_bytes != 0 || g_versym_value_reads != 1)
        goto out;
    g_versym_value_reads = 0;
    if (classify_versioned_candidate(
            &object, 1, &version_a, 0, 1, NULL) !=
                VERSIONED_CANDIDATE_NONE ||
        g_versym_value_reads != 1)
        goto out;
    versions[1] = UINT16_C(0x8000) | DL_VERSION_INDEX_MASK;
    if (!symbol_hidden(&object, 1, &hidden) || !hidden)
        goto out;
    versions[1] = 3;
    if (classify_versioned_candidate(
            &object, 1, &version_b, 0, 1, NULL) !=
        VERSIONED_CANDIDATE_INVALID)
        goto out;
    result = 1;

out:
    if (object.runtime_symbol_name_mapping)
        dl_release_runtime_mapping(&object);
    if (result && (object.versym_readonly || object.symbol_name_keys ||
                   object.symbol_name_index ||
                   object.version_name_index))
        result = 0;
    if (version_index != MAP_FAILED)
        munmap(version_index, version_index_size);
    if (image != MAP_FAILED)
        munmap(image, image_size);
    return result;
}

#define EXACT_NAME_SYMBOL_COUNT 1025U
#define EXACT_NAME_WRITABLE_DYNSTR 0x01U
#define EXACT_NAME_WRITABLE_DYNSYM 0x02U
#define EXACT_NAME_WRITABLE_VERSYM 0x04U

enum exact_name_string_offset {
    EXACT_NAME_GNU_COLLISION_A = 1,
    EXACT_NAME_GNU_COLLISION_B = 12,
    EXACT_NAME_NOISE = 23,
    EXACT_NAME_DUPLICATE = 29,
    EXACT_NAME_REPLACEMENT = 39
};

struct exact_name_fixture {
    struct loaded_obj object;
    Elf64_Phdr loads[4];
    struct {
        uint16_t page_slots[DL_VERSION_PAGE_COUNT];
        struct loaded_version_entry entries[DL_VERSION_PAGE_ENTRIES];
    } version_index;
    uint8_t *image;
    size_t image_size;
    char *strings;
    Elf64_Sym *symbols;
    uint16_t *versions;
};

static void exact_name_fixture_release(struct exact_name_fixture *fixture)
{
    if (!fixture)
        return;
    if (fixture->object.runtime_symbol_name_mapping)
        dl_release_runtime_mapping(&fixture->object);
    if (fixture->image != MAP_FAILED)
        munmap(fixture->image, fixture->image_size);
    fixture->image = MAP_FAILED;
}

static int exact_name_fixture_init(struct exact_name_fixture *fixture,
                                   unsigned int writable)
{
    static const char string_bytes[] =
        "\0gkyeawephq\0vikjksoybz\0noise\0duplicate\0abcdefghij";
    static const unsigned char key_bytes[16] = {
        0x3d, 0xa7, 0x11, 0xc9, 0x58, 0x24, 0xef, 0x62,
        0x95, 0x0b, 0x76, 0xd3, 0x41, 0xba, 0x8e, 0x17
    };
    const size_t strings_size = sizeof(string_bytes);
    const size_t symbols_offset = align_size(
        strings_size, _Alignof(Elf64_Sym));
    const size_t symbols_size =
        EXACT_NAME_SYMBOL_COUNT * sizeof(Elf64_Sym);
    const size_t versions_offset = align_size(
        symbols_offset + symbols_size, _Alignof(uint16_t));
    const size_t versions_size =
        EXACT_NAME_SYMBOL_COUNT * sizeof(uint16_t);
    const size_t gnu_offset = align_size(
        versions_offset + versions_size, _Alignof(uint64_t));
    const size_t gnu_size = 4 * sizeof(uint32_t) + sizeof(uint64_t) +
        sizeof(uint32_t) +
        (EXACT_NAME_SYMBOL_COUNT - 1U) * sizeof(uint32_t);
    uint32_t *gnu;
    uint64_t *bloom;
    uint32_t *bucket;
    uint32_t *chains;

    if (!fixture)
        return 0;
    memset(fixture, 0, sizeof(*fixture));
    fixture->image = MAP_FAILED;
    fixture->image_size = gnu_offset + gnu_size;
    fixture->image = mmap(NULL, fixture->image_size,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (fixture->image == MAP_FAILED)
        return 0;
    memset(fixture->image, 0, fixture->image_size);
    fixture->strings = (char *)fixture->image;
    fixture->symbols = (Elf64_Sym *)(fixture->image + symbols_offset);
    fixture->versions = (uint16_t *)(fixture->image + versions_offset);
    gnu = (uint32_t *)(fixture->image + gnu_offset);
    bloom = (uint64_t *)(gnu + 4);
    bucket = (uint32_t *)(bloom + 1);
    chains = bucket + 1;
    memcpy(fixture->strings, string_bytes, strings_size);

    for (uint32_t i = 1; i < EXACT_NAME_SYMBOL_COUNT; i++) {
        fixture->symbols[i].st_name = EXACT_NAME_NOISE;
        fixture->symbols[i].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
        fixture->symbols[i].st_shndx = 1;
        fixture->versions[i] = VER_NDX_GLOBAL;
    }
    fixture->symbols[1].st_name = EXACT_NAME_GNU_COLLISION_A;
    fixture->symbols[2].st_name = EXACT_NAME_GNU_COLLISION_B;
    fixture->symbols[3].st_name = EXACT_NAME_GNU_COLLISION_A;
    fixture->symbols[EXACT_NAME_SYMBOL_COUNT - 2U].st_name =
        EXACT_NAME_DUPLICATE;
    fixture->symbols[EXACT_NAME_SYMBOL_COUNT - 1U].st_name =
        EXACT_NAME_DUPLICATE;
    fixture->versions[1] = UINT16_C(0x8002);
    fixture->versions[2] = 2;
    fixture->versions[3] = 2;
    fixture->versions[EXACT_NAME_SYMBOL_COUNT - 2U] = 2;
    fixture->versions[EXACT_NAME_SYMBOL_COUNT - 1U] = 2;

    /* One deliberately long GNU chain contains a real 32-bit hash
     * collision.  Exact-name indexing may reduce the complete-table scan,
     * but the independent hash-table consistency check must still select
     * the same exact symbol rather than accepting the collision alone. */
    gnu[0] = 1;
    gnu[1] = 1;
    gnu[2] = 1;
    gnu[3] = 0;
    bloom[0] = UINT64_MAX;
    bucket[0] = 1;
    for (uint32_t i = 1; i < EXACT_NAME_SYMBOL_COUNT; i++) {
        const char *name = fixture->strings + fixture->symbols[i].st_name;

        chains[i - 1U] = gnu_hash_calc(name) & ~UINT32_C(1);
    }
    chains[EXACT_NAME_SYMBOL_COUNT - 2U] |= UINT32_C(1);

    memset(fixture->loads, 0, sizeof(fixture->loads));
    for (size_t i = 0; i < sizeof(fixture->loads) /
             sizeof(fixture->loads[0]); i++) {
        fixture->loads[i].p_type = PT_LOAD;
        fixture->loads[i].p_flags = PF_R;
    }
    fixture->loads[0].p_vaddr = 0;
    fixture->loads[0].p_filesz = strings_size;
    fixture->loads[0].p_memsz = strings_size;
    fixture->loads[1].p_vaddr = symbols_offset;
    fixture->loads[1].p_filesz = symbols_size;
    fixture->loads[1].p_memsz = symbols_size;
    fixture->loads[2].p_vaddr = versions_offset;
    fixture->loads[2].p_filesz = versions_size;
    fixture->loads[2].p_memsz = versions_size;
    fixture->loads[3].p_vaddr = gnu_offset;
    fixture->loads[3].p_filesz = gnu_size;
    fixture->loads[3].p_memsz = gnu_size;
    if (writable & EXACT_NAME_WRITABLE_DYNSTR)
        fixture->loads[0].p_flags |= PF_W;
    if (writable & EXACT_NAME_WRITABLE_DYNSYM)
        fixture->loads[1].p_flags |= PF_W;
    if (writable & EXACT_NAME_WRITABLE_VERSYM)
        fixture->loads[2].p_flags |= PF_W;

    fixture->object.base = (uintptr_t)fixture->image;
    fixture->object.phdr = fixture->loads;
    fixture->object.phdr_num =
        sizeof(fixture->loads) / sizeof(fixture->loads[0]);
    fixture->object.dynstr = fixture->strings;
    fixture->object.dynstr_size = strings_size;
    fixture->object.dynsym = fixture->symbols;
    fixture->object.dynsym_count = EXACT_NAME_SYMBOL_COUNT;
    fixture->object.dynsym_admitted_count = EXACT_NAME_SYMBOL_COUNT;
    fixture->object.versym = fixture->versions;
    fixture->object.versym_admitted_count = EXACT_NAME_SYMBOL_COUNT;
    fixture->version_index.page_slots[0] = 1;
    fixture->version_index.entries[2].definition_name = EXACT_NAME_NOISE;
    fixture->version_index.entries[2].flags = DL_VERSION_ENTRY_DEFINED;
    fixture->object.version_index =
        (struct loaded_version_index *)&fixture->version_index;
    fixture->object.gnu_hash = gnu;
    if (vfs_seed_hash_key(key_bytes) < 0 ||
        build_loaded_symbol_name_keys(&fixture->object) < 0 ||
        fixture->object.dynstr_readonly !=
            ((writable & EXACT_NAME_WRITABLE_DYNSTR) == 0) ||
        fixture->object.dynsym_readonly !=
            ((writable & EXACT_NAME_WRITABLE_DYNSYM) == 0) ||
        fixture->object.versym_readonly !=
            ((writable & EXACT_NAME_WRITABLE_VERSYM) == 0) ||
        (fixture->object.symbol_name_index != NULL) !=
            ((writable & (EXACT_NAME_WRITABLE_DYNSTR |
                          EXACT_NAME_WRITABLE_DYNSYM)) == 0 &&
             !g_symbol_name_index_force_allocation_fallback)) {
        exact_name_fixture_release(fixture);
        return 0;
    }
    return 1;
}

static int immutable_exact_name_index_gate(void)
{
    static const char collision_a[] = "gkyeawephq";
    static const char collision_b[] = "vikjksoybz";
    static const char replacement[] = "abcdefghij";
    struct exact_name_fixture fixture;
    const Elf64_Sym *selected = NULL;
    int result = 0;

    fixture.image = MAP_FAILED;
    if (gnu_hash_calc(collision_a) != gnu_hash_calc(collision_b) ||
        !exact_name_fixture_init(&fixture, 0))
        goto out;

    /* The immutable index must retain every same-name record.  A hidden
     * compatibility definition coexists with its public default, while two
     * public defaults remain malformed even when they occur at the end of a
     * large table.  The colliding other name is never an exact candidate. */
    g_symbol_name_candidate_checks = 0;
    if (unique_default_exported_symbol(
            &fixture.object, collision_a, &selected) !=
                UNIQUE_DEFAULT_SYMBOL_FOUND ||
        selected != &fixture.symbols[3] ||
        unique_default_exported_symbol(
            &fixture.object, collision_b, &selected) !=
                UNIQUE_DEFAULT_SYMBOL_FOUND ||
        selected != &fixture.symbols[2] ||
        unique_default_exported_symbol(
            &fixture.object, "duplicate", &selected) !=
                UNIQUE_DEFAULT_SYMBOL_MALFORMED ||
        selected != NULL ||
        unique_default_exported_symbol(
            &fixture.object, "not_present", &selected) !=
                UNIQUE_DEFAULT_SYMBOL_ABSENT ||
        selected != NULL ||
        g_symbol_name_candidate_checks > 16)
        goto out;

    exact_name_fixture_release(&fixture);

    /* A failed optional extended mapping retries the mandatory key mapping
     * and retains the immutable-key full scan. */
    g_symbol_name_index_force_allocation_fallback = 1;
    {
        int initialized = exact_name_fixture_init(&fixture, 0);

        g_symbol_name_index_force_allocation_fallback = 0;
        if (!initialized)
            goto out;
    }
    fixture.object.gnu_hash = NULL;
    g_symbol_name_candidate_checks = 0;
    if (fixture.object.symbol_name_index ||
        unique_default_exported_symbol(
            &fixture.object, collision_a, &selected) !=
                UNIQUE_DEFAULT_SYMBOL_FOUND ||
        selected != &fixture.symbols[3] ||
        g_symbol_name_candidate_checks != EXACT_NAME_SYMBOL_COUNT - 1U)
        goto out;
    exact_name_fixture_release(&fixture);

    /* A PF_W DT_STRTAB cannot publish an admission-time name index.  Keep
     * the complete live scan, and observe a same-length byte mutation rather
     * than consulting stale fingerprints or buckets. */
    if (!exact_name_fixture_init(
            &fixture, EXACT_NAME_WRITABLE_DYNSTR))
        goto out;
    fixture.object.gnu_hash = NULL;
    g_symbol_name_candidate_checks = 0;
    if (unique_default_exported_symbol(
            &fixture.object, collision_a, &selected) !=
                UNIQUE_DEFAULT_SYMBOL_FOUND ||
        selected != &fixture.symbols[3] ||
        g_symbol_name_candidate_checks != EXACT_NAME_SYMBOL_COUNT - 1U)
        goto out;
    memcpy(fixture.strings + EXACT_NAME_GNU_COLLISION_A,
           replacement, sizeof(replacement));
    if (unique_default_exported_symbol(
            &fixture.object, collision_a, &selected) !=
                UNIQUE_DEFAULT_SYMBOL_ABSENT ||
        unique_default_exported_symbol(
            &fixture.object, replacement, &selected) !=
                UNIQUE_DEFAULT_SYMBOL_FOUND ||
        selected != &fixture.symbols[3])
        goto out;
    exact_name_fixture_release(&fixture);

    /* PF_W DT_SYMTAB can redirect st_name without changing either string.
     * It must likewise bypass an immutable exact-name index. */
    if (!exact_name_fixture_init(
            &fixture, EXACT_NAME_WRITABLE_DYNSYM))
        goto out;
    fixture.object.gnu_hash = NULL;
    g_symbol_name_candidate_checks = 0;
    if (unique_default_exported_symbol(
            &fixture.object, collision_a, &selected) !=
                UNIQUE_DEFAULT_SYMBOL_FOUND ||
        selected != &fixture.symbols[3] ||
        g_symbol_name_candidate_checks != EXACT_NAME_SYMBOL_COUNT - 1U)
        goto out;
    fixture.symbols[3].st_name = EXACT_NAME_GNU_COLLISION_B;
    if (unique_default_exported_symbol(
            &fixture.object, collision_a, &selected) !=
                UNIQUE_DEFAULT_SYMBOL_ABSENT ||
        unique_default_exported_symbol(
            &fixture.object, collision_b, &selected) !=
                UNIQUE_DEFAULT_SYMBOL_MALFORMED ||
        selected != NULL)
        goto out;
    exact_name_fixture_release(&fixture);

    /* A name-only index can remain valid when only VERSYM is writable, but
     * default/compatibility classification itself must remain live. */
    if (!exact_name_fixture_init(
            &fixture, EXACT_NAME_WRITABLE_VERSYM))
        goto out;
    fixture.object.gnu_hash = NULL;
    if (unique_default_exported_symbol(
            &fixture.object, collision_a, &selected) !=
                UNIQUE_DEFAULT_SYMBOL_FOUND ||
        selected != &fixture.symbols[3])
        goto out;
    fixture.versions[1] = 2;
    if (unique_default_exported_symbol(
            &fixture.object, collision_a, &selected) !=
                UNIQUE_DEFAULT_SYMBOL_MALFORMED ||
        selected != NULL)
        goto out;
    fixture.versions[3] = UINT16_C(0x8002);
    if (unique_default_exported_symbol(
            &fixture.object, collision_a, &selected) !=
                UNIQUE_DEFAULT_SYMBOL_FOUND ||
        selected != &fixture.symbols[1])
        goto out;
    result = 1;

out:
    exact_name_fixture_release(&fixture);
    return result;
}

static void initialize_admitted_span_image(
    uint8_t *image, size_t image_size, Elf64_Phdr phdrs[4])
{
    enum {
        DYNAMIC_OFFSET = 64,
        DYNSYM_OFFSET = 256,
        DYNSTR_OFFSET = 304,
        VERSYM_OFFSET = 336,
        DYNAMIC_COUNT = 6
    };
    static const char strings[] = "\0symbol\0";
    Elf64_Dyn *dynamic = (Elf64_Dyn *)(image + DYNAMIC_OFFSET);
    Elf64_Sym *symbols = (Elf64_Sym *)(image + DYNSYM_OFFSET);
    uint16_t *versions = (uint16_t *)(image + VERSYM_OFFSET);

    memset(image, 0, image_size);
    memset(phdrs, 0, 4 * sizeof(*phdrs));
    memcpy(image + DYNSTR_OFFSET, strings, sizeof(strings));
    symbols[1].st_name = 1;
    symbols[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    symbols[1].st_shndx = 1;
    symbols[1].st_value = 128;
    symbols[1].st_size = 1;
    versions[1] = VER_NDX_GLOBAL;

    dynamic[0].d_tag = DT_SYMTAB;
    dynamic[0].d_un.d_ptr = DYNSYM_OFFSET;
    dynamic[1].d_tag = DT_STRTAB;
    dynamic[1].d_un.d_ptr = DYNSTR_OFFSET;
    dynamic[2].d_tag = DT_STRSZ;
    dynamic[2].d_un.d_val = sizeof(strings);
    dynamic[3].d_tag = DT_SYMENT;
    dynamic[3].d_un.d_val = sizeof(Elf64_Sym);
    dynamic[4].d_tag = DT_VERSYM;
    dynamic[4].d_un.d_ptr = VERSYM_OFFSET;
    dynamic[5].d_tag = DT_NULL;

    phdrs[0].p_type = PT_LOAD;
    phdrs[0].p_flags = PF_R | PF_W;
    phdrs[0].p_filesz = DYNSTR_OFFSET;
    phdrs[0].p_memsz = DYNSTR_OFFSET;
    phdrs[1].p_type = PT_LOAD;
    phdrs[1].p_flags = PF_R;
    phdrs[1].p_vaddr = DYNSTR_OFFSET;
    phdrs[1].p_filesz = sizeof(strings);
    phdrs[1].p_memsz = sizeof(strings);
    phdrs[2].p_type = PT_LOAD;
    phdrs[2].p_flags = PF_R | PF_W;
    phdrs[2].p_vaddr = VERSYM_OFFSET;
    phdrs[2].p_filesz = 2 * sizeof(uint16_t);
    phdrs[2].p_memsz = 2 * sizeof(uint16_t);
    phdrs[3].p_type = PT_DYNAMIC;
    phdrs[3].p_vaddr = DYNAMIC_OFFSET;
    phdrs[3].p_filesz = DYNAMIC_COUNT * sizeof(Elf64_Dyn);
    phdrs[3].p_memsz = phdrs[3].p_filesz;
}

static int admitted_symbol_span_gate(void)
{
    enum {
        IMAGE_SIZE = 384,
        DYNSYM_OFFSET = 256,
        DYNSTR_OFFSET = 304,
        VERSYM_OFFSET = 336
    };
    struct dlfrz_lib_meta meta = {0};
    struct loaded_obj object;
    Elf64_Phdr phdrs[4];
    Elf64_Sym *symbols;
    uint16_t *versions;
    uint8_t *image = MAP_FAILED;
    uint16_t version = 0;
    int result = 0;

    image = mmap(NULL, IMAGE_SIZE, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (image == MAP_FAILED)
        return 0;
    initialize_admitted_span_image(image, IMAGE_SIZE, phdrs);
    symbols = (Elf64_Sym *)(image + DYNSYM_OFFSET);
    versions = (uint16_t *)(image + VERSYM_OFFSET);
    memset(&object, 0, sizeof(object));
    object.base = (uintptr_t)image;
    object.phdr = phdrs;
    object.phdr_num = 4;
    if (parse_dynamic(&object, &meta) < 0 ||
        object.dynsym_admitted_count != 2 ||
        object.versym_admitted_count != 2 ||
        object.dynsym_readonly || object.versym_readonly)
        goto out;

    /* Admission cached only geometry.  PF_W entry mutations remain visible,
     * and the proof avoids later program-header rescans without widening the
     * admitted span. */
    phdrs[0].p_filesz = 0;
    phdrs[2].p_filesz = 0;
    object.phdr_num = 0;
    symbols[1].st_value = 192;
    symbols[1].st_info = ELF64_ST_INFO(STB_WEAK, STT_OBJECT);
    symbols[1].st_shndx = 2;
    versions[1] = UINT16_C(0x8000) | VER_NDX_GLOBAL;
    if (loaded_dynsym(&object, 1) != &symbols[1] ||
        loaded_dynsym(&object, 1)->st_value != 192 ||
        loaded_dynsym(&object, 1)->st_info !=
            ELF64_ST_INFO(STB_WEAK, STT_OBJECT) ||
        loaded_dynsym(&object, 1)->st_shndx != 2 ||
        !loaded_versym_value(&object, 1, &version) ||
        version != (UINT16_C(0x8000) | VER_NDX_GLOBAL))
        goto release;
    object.dynsym_admitted_count = 1;
    object.versym_admitted_count = 1;
    if (loaded_dynsym(&object, 1) ||
        loaded_versym_value(&object, 1, &version))
        goto release;
    object.dynsym_admitted_count = 2;
    object.versym_admitted_count = 2;
    if (loaded_dynsym(&object, 2) ||
        loaded_versym_value(&object, 2, &version))
        goto release;

    result = 1;
release:
    dl_release_runtime_mapping(&object);
    if (object.dynsym_admitted_count || object.versym_admitted_count)
        result = 0;
    if (!result)
        goto out;

    /* A one-byte file truncation cannot publish a whole-table proof even
     * when p_memsz still maps the missing tail. */
    initialize_admitted_span_image(image, IMAGE_SIZE, phdrs);
    phdrs[0].p_filesz = DYNSTR_OFFSET - 1;
    memset(&object, 0, sizeof(object));
    object.base = (uintptr_t)image;
    object.phdr = phdrs;
    object.phdr_num = 4;
    if (parse_dynamic(&object, &meta) == 0 ||
        object.dynsym_admitted_count != 0) {
        result = 0;
        if (object.runtime_symbol_name_mapping)
            dl_release_runtime_mapping(&object);
        goto out;
    }

    /* The same rule applies to VERSYM.  Dynsym may already carry a local
     * proof during a failing parse, but failure cleanup must revoke it before
     * the object can be reused or its mapping released. */
    initialize_admitted_span_image(image, IMAGE_SIZE, phdrs);
    phdrs[2].p_filesz--;
    memset(&object, 0, sizeof(object));
    object.base = (uintptr_t)image;
    object.phdr = phdrs;
    object.phdr_num = 4;
    if (parse_dynamic(&object, &meta) == 0 ||
        object.versym_admitted_count != 0) {
        result = 0;
        if (object.runtime_symbol_name_mapping)
            dl_release_runtime_mapping(&object);
        goto out;
    }
    dl_release_runtime_mapping(&object);
    if (object.dynsym_admitted_count || object.versym_admitted_count)
        result = 0;

out:
    munmap(image, IMAGE_SIZE);
    return result;
}

enum {
    DYNAMIC_SEMANTIC_IMAGE_SIZE = 768,
    DYNAMIC_SEMANTIC_DYNAMIC_OFFSET = 64,
    DYNAMIC_SEMANTIC_DYNSYM_OFFSET = 512,
    DYNAMIC_SEMANTIC_DYNSTR_OFFSET = 560,
    DYNAMIC_SEMANTIC_DYNAMIC_COUNT = 10
};

static const char dynamic_semantic_strings[] =
    "\0libsemantic.so\0/old/rpath\0/old/runpath\0";

static void initialize_dynamic_semantic_image(
    uint8_t *image, Elf64_Phdr phdrs[3], int writable_dynstr)
{
    const uint32_t soname_offset = 1;
    const uint32_t rpath_offset = sizeof("\0libsemantic.so");
    const uint32_t runpath_offset =
        sizeof("\0libsemantic.so") + sizeof("/old/rpath");
    Elf64_Dyn *dynamic = (Elf64_Dyn *)(
        image + DYNAMIC_SEMANTIC_DYNAMIC_OFFSET);

    memset(image, 0, DYNAMIC_SEMANTIC_IMAGE_SIZE);
    memset(phdrs, 0, 3 * sizeof(*phdrs));
    memcpy(image + DYNAMIC_SEMANTIC_DYNSTR_OFFSET,
           dynamic_semantic_strings, sizeof(dynamic_semantic_strings));

    dynamic[0].d_tag = DT_SYMTAB;
    dynamic[0].d_un.d_ptr = DYNAMIC_SEMANTIC_DYNSYM_OFFSET;
    dynamic[1].d_tag = DT_STRTAB;
    dynamic[1].d_un.d_ptr = DYNAMIC_SEMANTIC_DYNSTR_OFFSET;
    dynamic[2].d_tag = DT_STRSZ;
    dynamic[2].d_un.d_val = sizeof(dynamic_semantic_strings);
    dynamic[3].d_tag = DT_SYMENT;
    dynamic[3].d_un.d_val = sizeof(Elf64_Sym);
    dynamic[4].d_tag = DT_SONAME;
    dynamic[4].d_un.d_val = soname_offset;
    dynamic[5].d_tag = DT_RPATH;
    dynamic[5].d_un.d_val = rpath_offset;
    dynamic[6].d_tag = DT_RUNPATH;
    dynamic[6].d_un.d_val = runpath_offset;
    dynamic[7].d_tag = DT_FLAGS;
    dynamic[7].d_un.d_val = DF_STATIC_TLS;
    dynamic[8].d_tag = DT_FLAGS_1;
    dynamic[8].d_un.d_val = DF_1_NODELETE | DF_1_NODEFLIB;
    dynamic[9].d_tag = DT_NULL;

    phdrs[0].p_type = PT_LOAD;
    phdrs[0].p_flags = PF_R | PF_W;
    phdrs[0].p_filesz = writable_dynstr
        ? DYNAMIC_SEMANTIC_IMAGE_SIZE : DYNAMIC_SEMANTIC_DYNSTR_OFFSET;
    phdrs[0].p_memsz = phdrs[0].p_filesz;
    if (!writable_dynstr) {
        phdrs[1].p_type = PT_LOAD;
        phdrs[1].p_flags = PF_R;
        phdrs[1].p_vaddr = DYNAMIC_SEMANTIC_DYNSTR_OFFSET;
        phdrs[1].p_filesz = sizeof(dynamic_semantic_strings);
        phdrs[1].p_memsz = phdrs[1].p_filesz;
    }
    phdrs[2].p_type = PT_DYNAMIC;
    phdrs[2].p_vaddr = DYNAMIC_SEMANTIC_DYNAMIC_OFFSET;
    phdrs[2].p_filesz =
        DYNAMIC_SEMANTIC_DYNAMIC_COUNT * sizeof(Elf64_Dyn);
    phdrs[2].p_memsz = phdrs[2].p_filesz;
}

static int dynamic_semantic_snapshot_gate(void)
{
    static const uint8_t hash_key[16] = {
        0x2b, 0x77, 0x40, 0x1f, 0x9a, 0x63, 0xd8, 0x05,
        0xc1, 0x34, 0xee, 0x58, 0x7d, 0x96, 0x12, 0xab
    };
    const uint32_t soname_offset = 1;
    const uint32_t rpath_offset = sizeof("\0libsemantic.so");
    const uint32_t runpath_offset =
        sizeof("\0libsemantic.so") + sizeof("/old/rpath");
    struct dlfrz_lib_meta meta = {0};
    struct loaded_obj object;
    Elf64_Phdr phdrs[3];
    Elf64_Dyn *dynamic;
    char *strings;
    uint8_t *image = MAP_FAILED;
    int result = 0;

    image = mmap(NULL, DYNAMIC_SEMANTIC_IMAGE_SIZE,
                 PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (image == MAP_FAILED || vfs_seed_hash_key(hash_key) < 0)
        goto out;
    dynamic = (Elf64_Dyn *)(
        image + DYNAMIC_SEMANTIC_DYNAMIC_OFFSET);
    strings = (char *)image + DYNAMIC_SEMANTIC_DYNSTR_OFFSET;

    /* A writable DT_STRTAB is snapshotted into one loader-owned read-only
     * mapping.  Neither raw tag changes nor removing every source terminator
     * after admission can alter the published semantics or cause an overread. */
    initialize_dynamic_semantic_image(image, phdrs, 1);
    memset(&object, 0, sizeof(object));
    object.base = (uintptr_t)image;
    object.phdr = phdrs;
    object.phdr_num = 3;
    if (parse_dynamic(&object, &meta) < 0 ||
        !object.runtime_dynamic_semantic_mapping ||
        object.runtime_dynamic_semantic_mapping_size == 0 ||
        object.admitted_soname == strings + soname_offset ||
        object.admitted_rpath == strings + rpath_offset ||
        object.admitted_runpath == strings + runpath_offset ||
        strcmp(object.admitted_soname, "libsemantic.so") != 0 ||
        strcmp(object.admitted_rpath, "/old/rpath") != 0 ||
        strcmp(object.admitted_runpath, "/old/runpath") != 0)
        goto mutable_release;
    for (size_t i = 0; i < DYNAMIC_SEMANTIC_DYNAMIC_COUNT; i++) {
        dynamic[i].d_tag = DT_DEBUG;
        dynamic[i].d_un.d_val = UINT64_MAX;
    }
    memset(strings + 1, 'X', sizeof(dynamic_semantic_strings) - 1);
    {
        struct symbol_lookup_query soname_query;
        const char *rpath = NULL;
        const char *runpath = NULL;
        uint64_t flags_1 = 0;

        object.tls.memsz = 1;
        if (!dl_object_soname_query(&object, &soname_query) ||
            !symbol_lookup_query_eq_cstr(
                &soname_query, "libsemantic.so") ||
            dl_object_search_paths(&object, &rpath, &runpath) < 0 ||
            !rpath || strcmp(rpath, "/old/rpath") != 0 ||
            !runpath || strcmp(runpath, "/old/runpath") != 0 ||
            dl_object_flags_1(&object, &flags_1) < 0 ||
            flags_1 != (DF_1_NODELETE | DF_1_NODEFLIB) ||
            dl_lazy_static_tls_admitted(&object, "semantic") != -1)
            goto mutable_release;
    }
    result = 1;

mutable_release:
    dl_release_runtime_mapping(&object);
    if (object.runtime_dynamic_semantic_mapping ||
        object.admitted_soname || object.admitted_rpath ||
        object.admitted_runpath || object.admitted_dynamic_flags ||
        object.admitted_dynamic_flags_1)
        result = 0;
    if (!result)
        goto out;

    /* A DT_STRTAB covered only by non-writable PT_LOAD declarations keeps
     * the normal zero-allocation path.  PT_DYNAMIC is still writable here;
     * changing it cannot redirect any already-admitted semantic consumer. */
    result = 0;
    initialize_dynamic_semantic_image(image, phdrs, 0);
    memset(&object, 0, sizeof(object));
    object.base = (uintptr_t)image;
    object.phdr = phdrs;
    object.phdr_num = 3;
    if (parse_dynamic(&object, &meta) < 0 ||
        object.runtime_dynamic_semantic_mapping ||
        object.admitted_soname != strings + soname_offset ||
        object.admitted_rpath != strings + rpath_offset ||
        object.admitted_runpath != strings + runpath_offset)
        goto immutable_release;
    for (size_t i = 0; i < DYNAMIC_SEMANTIC_DYNAMIC_COUNT; i++) {
        dynamic[i].d_tag = DT_DEBUG;
        dynamic[i].d_un.d_val = 0;
    }
    {
        const char *rpath = NULL;
        const char *runpath = NULL;
        uint64_t flags_1 = 0;

        object.tls.memsz = 1;
        if (!dl_object_soname(&object) ||
            strcmp(dl_object_soname(&object), "libsemantic.so") != 0 ||
            dl_object_search_paths(&object, &rpath, &runpath) < 0 ||
            !rpath || strcmp(rpath, "/old/rpath") != 0 ||
            !runpath || strcmp(runpath, "/old/runpath") != 0 ||
            dl_object_flags_1(&object, &flags_1) < 0 ||
            flags_1 != (DF_1_NODELETE | DF_1_NODEFLIB) ||
            dl_lazy_static_tls_admitted(&object, "semantic") != -1)
            goto immutable_release;
    }
    result = 1;

immutable_release:
    dl_release_runtime_mapping(&object);

out:
    if (image != MAP_FAILED)
        munmap(image, DYNAMIC_SEMANTIC_IMAGE_SIZE);
    return result;
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
    int global_object_installed = 0;
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
    load.p_flags = PF_R;
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
    g_version_key_admission_visits = 0;
    g_symbol_name_radix_sorts = 0;
    g_versym_value_reads = 0;
    if (vfs_seed_hash_key(key) < 0 ||
        build_loaded_symbol_name_keys(&object) < 0 ||
        g_symbol_name_radix_sorts != 1 ||
        g_versym_value_reads != symbols_count ||
        g_version_key_admission_visits !=
            2 * (version_page_count * DL_VERSION_PAGE_ENTRIES - 2) ||
        !symbol_lookup_query_init(miss, &miss_query) ||
        !symbol_lookup_query_init(exact, &exact_query))
        goto out;
    {
        static const uint32_t indices[] = {
            0, 1, symbols_count / 2, symbols_count - 1
        };
        struct symbol_lookup_query mismatched;

        for (size_t i = 0;
             i < sizeof(indices) / sizeof(indices[0]); i++) {
            uint32_t index = indices[i];
            const struct loaded_symbol_name_key *name_key =
                &object.symbol_name_keys[index];

            if (name_key->dynstr_offset != symbols[index].st_name ||
                name_key->gnu_hash !=
                    gnu_hash_calc(strings + symbols[index].st_name))
                goto out;
        }
        if (loaded_object_name_query_init(
                &object, strings + 2, &object.symbol_name_keys[1],
                &mismatched))
            goto out;
    }

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

    /* Model initial relocation, where the complete table is already known
     * to lookup_relocation_definition but g_nobj is deliberately not yet
     * published.  An admitted key makes construction independent of graph
     * scope and epoch, with no global work cache or target-string reread. */
    if (g_nobj != 0)
        goto out;
    g_all_objs[0] = object;
    g_all_objs[0].relocation_scope_root = 0;
    g_all_objs[0].relocation_scope_root_valid = 1;
    load.p_flags = PF_R;
    g_all_objs[0].dynstr_readonly = loaded_obj_range_declared_readonly(
        &g_all_objs[0], g_all_objs[0].dynstr,
        g_all_objs[0].dynstr_size) ? 1 : 0;
    if (!g_all_objs[0].dynstr_readonly)
        goto out;
    global_object_installed = 1;
    clear_resolution_caches();
    g_symbol_query_forward_bytes = 0;
    g_symbol_query_reverse_bytes = 0;
    g_symbol_query_sysv_bytes = 0;
    {
        struct symbol_lookup_query first;
        struct symbol_lookup_query second;
        struct symbol_lookup_query adjacent;
        struct symbol_lookup_query changed_scope;
        struct symbol_lookup_query changed_epoch;
        struct symbol_lookup_query distinct;
        struct loaded_symbol_name_key excessive =
            g_all_objs[0].symbol_name_keys[1];
        uint64_t first_keyed_hash;
        uint32_t first_sysv_hash;

        if (!symbol_lookup_query_init_dynsym(
                &g_all_objs[0], 1, g_all_objs, 1, &first) ||
            !symbol_lookup_query_init_dynsym(
                &g_all_objs[0], 1, g_all_objs, 1, &second) ||
            first.name != strings + 1 ||
            first.key.length != exact_query.key.length ||
            first.key.fingerprint != exact_query.key.fingerprint ||
            first.key.gnu_hash != exact_query.gnu_hash ||
            first.key.dynstr_offset != 1 ||
            first.keyed_hash_valid || !first.keyed_hash_deferred ||
            first.sysv_hash_valid || !first.sysv_hash_deferred ||
            second.sysv_hash_valid || !second.sysv_hash_deferred ||
            g_symbol_query_forward_bytes != 0 ||
            g_symbol_query_reverse_bytes != 0 ||
            g_symbol_query_sysv_bytes != 0 ||
            !symbol_lookup_query_keyed_hash(
                &first, &first_keyed_hash) ||
            first_keyed_hash != exact_query.keyed_hash ||
            first.gnu_hash != exact_query.gnu_hash ||
            !symbol_lookup_query_init_dynsym(
                &g_all_objs[0], 2, g_all_objs, 1, &adjacent) ||
            adjacent.name != strings + 2 ||
            adjacent.key.length != payload_length - 1)
            goto out;
        if (!symbol_lookup_query_sysv_hash(&first, &first_sysv_hash) ||
            first_sysv_hash != exact_query.sysv_hash ||
            !symbol_lookup_query_sysv_hash(&first, &first_sysv_hash) ||
            g_symbol_query_sysv_bytes != payload_length ||
            !symbol_queries_equal(&first, &second) ||
            g_symbol_query_sysv_bytes != 2 * payload_length)
            goto out;
        sym_cache_store_canonical(
            strings + 1, &first, CACHE_FOUND,
            UINT64_C(0x1020304050607080));
        if (sym_cache_lookup(&first, &cached) != 1 ||
            cached != UINT64_C(0x1020304050607080))
            goto out;
        g_all_objs[0].relocation_scope_root = 1;
        if (!symbol_lookup_query_init_dynsym(
                &g_all_objs[0], 1, g_all_objs, 1, &changed_scope))
            goto out;
        clear_resolution_caches();
        if (!symbol_lookup_query_init_dynsym(
                &g_all_objs[0], 1, g_all_objs, 1, &changed_epoch) ||
            first.name != changed_scope.name ||
            first.name != changed_epoch.name ||
            first.key.length != changed_scope.key.length ||
            first.key.length != changed_epoch.key.length ||
            first.key.fingerprint != changed_scope.key.fingerprint ||
            first.key.fingerprint != changed_epoch.key.fingerprint ||
            first.gnu_hash != changed_scope.gnu_hash ||
            first.gnu_hash != changed_epoch.gnu_hash ||
            changed_scope.sysv_hash_valid ||
            !changed_scope.sysv_hash_deferred ||
            changed_epoch.sysv_hash_valid ||
            !changed_epoch.sysv_hash_deferred ||
            g_symbol_query_forward_bytes != 0 ||
            g_symbol_query_reverse_bytes != 0)
            goto out;

        excessive.length = g_all_objs[0].dynstr_size;
        if (loaded_object_name_query_init(
                &g_all_objs[0], strings + 1, &excessive, &first))
            goto out;

        /* A writable DT_STRTAB retains correct semantics without retaining
         * stale bytes or pre-relocation fingerprints.  Same-length mutation
         * between calls must produce the same query as a full current-byte
         * scan rather than reuse either cached query or object-owned key. */
        load.p_flags = PF_R | PF_W;
        g_all_objs[0].dynstr_readonly = 0;
        strings[1] = 'z';
        if (!symbol_lookup_query_init_dynsym(
                &g_all_objs[0], 1, g_all_objs, 1, &first))
            goto out;
        strings[1] = 'y';
        if (!symbol_lookup_query_init_dynsym(
                &g_all_objs[0], 1, g_all_objs, 1, &second) ||
            first.gnu_hash == second.gnu_hash ||
            g_symbol_query_forward_bytes !=
                2 * payload_length ||
            g_symbol_query_reverse_bytes != 2 * payload_length)
            goto out;
        if (!symbol_lookup_query_init(strings + 1, &changed_epoch) ||
            !symbol_queries_equal(&second, &changed_epoch))
            goto out;

        /* Writable candidate bytes are re-read at comparison time.  Cover
         * both an independent query buffer and the harder aliasing case in
         * which query.name itself points into the mutated DT_STRTAB. */
        exact[0] = 'y';
        if (!symbol_lookup_query_init(exact, &distinct) ||
            !loaded_symbol_name_eq_query(
                &g_all_objs[0], &symbols[1], &distinct))
            goto out;
        strings[1] = 'x';
        if (loaded_symbol_name_eq_query(
                &g_all_objs[0], &symbols[1], &distinct) ||
            loaded_symbol_name_eq_query(
                &g_all_objs[0], &symbols[1], &second))
            goto out;
        strings[1] = 'y';

        if (!loaded_symbol_name_eq_query(
                &g_all_objs[0], &symbols[1], &second) ||
            loaded_symbol_name_eq_query(
                &g_all_objs[0], &symbols[1], &exact_query) ||
            classify_versioned_candidate(
                &g_all_objs[0], 1, &second, 0, 1, NULL) !=
                    VERSIONED_CANDIDATE_EXACT ||
            classify_versioned_candidate(
                &g_all_objs[0], 1, &exact_query, 0, 1, NULL) !=
                    VERSIONED_CANDIDATE_NONE)
            goto out;
        strings[payload_length + 1] = 'x';
        if (symbol_lookup_query_init_dynsym(
                &g_all_objs[0], 1, g_all_objs, 1, &second) ||
            loaded_symbol_name_eq_query(
                &g_all_objs[0], &symbols[1], &changed_epoch) ||
            classify_versioned_candidate(
                &g_all_objs[0], 1, &changed_epoch, 0, 1, NULL) !=
                    VERSIONED_CANDIDATE_NONE)
            goto out;
        strings[payload_length + 1] = '\0';
    }
    clear_resolution_caches();
    memset(&g_all_objs[0], 0, sizeof(g_all_objs[0]));
    global_object_installed = 0;
    result = 1;

out:
    if (global_object_installed) {
        clear_resolution_caches();
        memset(&g_all_objs[0], 0, sizeof(g_all_objs[0]));
    }
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

    /* Raw VERDEF is writable in this gate.  The loader-owned index
     * intentionally snapshots its validated identity/name mapping, so later
     * record mutations cannot redirect lookups through unvalidated chains. */
    records[0].definition.vd_ndx = 3;
    records[0].auxiliary.vda_name = 0;
    {
        const char *version = defined_symbol_version(&object, 0);

        if (!version || strcmp(version, "V") != 0)
            goto release;
    }
    records[0].definition.vd_ndx = 2;
    records[0].auxiliary.vda_name = 1;

    /* The GNU hidden bit belongs to VERSYM, independently of the indexed
     * definition name.  Both public/default and hidden references retain
     * the same O(1) name lookup. */
    versions[0] = UINT16_C(0x8000) | 2;
    {
        const char *version = NULL;
        int hidden = 0;

        if (relocation_symbol_version(
                &object, 0, &version, NULL, &hidden, NULL, NULL) != 1 ||
            !version || strcmp(version, "V") != 0 || !hidden)
            goto release;
    }
    versions[0] = 30001;
    if (loaded_symbol_version_is_admitted(&object, 0))
        goto release;
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
    {
        uint16_t selector[1] = {2};
        const char *version = NULL;
        const char *provider = NULL;
        const struct loaded_symbol_name_key *version_key = NULL;
        const struct loaded_symbol_name_key *provider_key = NULL;
        struct symbol_lookup_query version_query;
        struct symbol_lookup_query provider_query;

        object.dynsym_count = 1;
        object.versym = selector;
        object.versym_admitted_count = 1;
        if (relocation_symbol_version(
                &object, 0, &version, &version_key, NULL,
                &provider, &provider_key) != 1 ||
            version_key || provider_key || !version || !provider ||
            !symbol_lookup_query_init_object_name(
                &object, version, version_key, &version_query) ||
            !symbol_lookup_query_init_object_name(
                &object, provider, provider_key, &provider_query) ||
            !symbol_lookup_query_eq_cstr(&version_query, "VERSION") ||
            !symbol_lookup_query_eq_cstr(
                &provider_query, "libprovider.so"))
            goto release;

        /* PF_W provider bytes are compared through the captured bounded
         * query, and removing every remaining DT_STRTAB terminator makes a
         * version query fail instead of escaping the table. */
        strings[provider_offset + strlen("libprovider.so")] = 'X';
        if (!symbol_lookup_query_init_object_name(
                &object, provider, provider_key, &provider_query) ||
            symbol_lookup_query_eq_cstr(
                &provider_query, "libprovider.so"))
            goto release;
        strings[provider_offset + strlen("libprovider.so")] = '\0';
        strings[sizeof(string_bytes) - 2] = 'X';
        strings[sizeof(string_bytes) - 1] = 'X';
        if (symbol_lookup_query_init_object_name(
                &object, version, version_key, &version_query))
            goto release;
        strings[sizeof(string_bytes) - 2] = '\0';
        strings[sizeof(string_bytes) - 1] = '\0';
        object.versym = NULL;
        object.versym_admitted_count = 0;
        object.dynsym_count = 0;
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

struct global_cache_gate_image {
    char strings[64];
    Elf64_Sym symbols[2];
    uint16_t versions[2];
    uint32_t sysv_hash[5];
    unsigned char payload[64];
};

static int global_address_cache_mutation_gate(void)
{
    static const unsigned char key[16] = {
        0x91, 0x42, 0x73, 0x24, 0x55, 0x86, 0xb7, 0xe8,
        0x19, 0x4a, 0x7b, 0xac, 0xdd, 0x0e, 0x3f, 0x60
    };
    static const char name[] = "dlfreeze_cache_scope_gate";
    struct global_cache_gate_image *images = MAP_FAILED;
    Elf64_Phdr loads[2] = {{0}};
    struct symbol_lookup_query query;
    struct sysv_hash_view sysv_view;
    uint64_t address;
    uint64_t cached;
    int saved_musl = g_is_musl_runtime;
    int result = 0;

    images = mmap(NULL, 2 * sizeof(*images), PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (images == MAP_FAILED || sizeof(name) >= sizeof(images[0].strings) ||
        vfs_seed_hash_key(key) < 0 ||
        !symbol_lookup_query_init(name, &query))
        goto out;
    memset(images, 0, 2 * sizeof(*images));
    memset(g_all_objs, 0, 2 * sizeof(g_all_objs[0]));
    for (unsigned int i = 0; i < 2; i++) {
        memcpy(images[i].strings + 1, name, sizeof(name));
        images[i].symbols[1].st_name = 1;
        images[i].symbols[1].st_info =
            ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);
        images[i].symbols[1].st_shndx = 1;
        images[i].symbols[1].st_value =
            offsetof(struct global_cache_gate_image, payload);
        images[i].symbols[1].st_size = 1;
        loads[i].p_type = PT_LOAD;
        loads[i].p_flags = i == 0 ? PF_R | PF_W : PF_R;
        loads[i].p_filesz = sizeof(images[i]);
        loads[i].p_memsz = sizeof(images[i]);
        g_all_objs[i].base = (uintptr_t)&images[i];
        g_all_objs[i].phdr = &loads[i];
        g_all_objs[i].phdr_num = 1;
        g_all_objs[i].dynstr = images[i].strings;
        g_all_objs[i].dynstr_size = sizeof(images[i].strings);
        g_all_objs[i].dynsym = images[i].symbols;
        g_all_objs[i].dynsym_count = 2;
        g_all_objs[i].dynsym_admitted_count = 2;
        g_all_objs[i].dynstr_readonly = i != 0;
        g_all_objs[i].dynsym_readonly = i != 0;
        g_all_objs[i].visible = 1;
    }
    g_nobj = 2;
    g_is_musl_runtime = 1;
    g_global_scope_count = 2;
    g_global_scope_indices[0] = 0;
    g_global_scope_indices[1] = 1;

    /* An earlier PF_W DYNSYM may become the selected definition between
     * calls.  The later immutable owner's address must not survive in the
     * process-global cache. */
    images[0].symbols[1].st_shndx = SHN_UNDEF;
    clear_resolution_caches();
    if (resolve_sym_address(g_all_objs, g_nobj, name, &address) != 1 ||
        address != (uint64_t)(uintptr_t)images[1].payload ||
        sym_cache_lookup(&query, &cached) != 0)
        goto out;
    images[0].symbols[1].st_shndx = 1;
    if (resolve_sym_address(g_all_objs, g_nobj, name, &address) != 1 ||
        address != (uint64_t)(uintptr_t)images[0].payload)
        goto out;

    /* VERSYM visibility and a hash bucket are independent earlier-scope
     * selection inputs and receive the same no-stale-result guarantee. */
    images[0].versions[1] = UINT16_C(0x8002);
    g_all_objs[0].versym = images[0].versions;
    g_all_objs[0].versym_admitted_count = 2;
    clear_resolution_caches();
    if (resolve_sym_address(g_all_objs, g_nobj, name, &address) != 1 ||
        address != (uint64_t)(uintptr_t)images[1].payload)
        goto out;
    images[0].versions[1] = VER_NDX_GLOBAL;
    if (resolve_sym_address(g_all_objs, g_nobj, name, &address) != 1 ||
        address != (uint64_t)(uintptr_t)images[0].payload)
        goto out;

    g_all_objs[0].versym = NULL;
    images[0].sysv_hash[0] = 1;
    images[0].sysv_hash[1] = 2;
    images[0].sysv_hash[2] = STN_UNDEF;
    images[0].sysv_hash[3] = STN_UNDEF;
    images[0].sysv_hash[4] = STN_UNDEF;
    g_all_objs[0].sysv_hash = images[0].sysv_hash;
    clear_resolution_caches();
    if (resolve_sym_address(g_all_objs, g_nobj, name, &address) != 1 ||
        address != (uint64_t)(uintptr_t)images[1].payload)
        goto out;
    images[0].sysv_hash[2] = 1;
    if (resolve_sym_address(g_all_objs, g_nobj, name, &address) != 1 ||
        address != (uint64_t)(uintptr_t)images[0].payload)
        goto out;

    /* Once the complete lookup metadata is PF_R and the admitted hash view
     * is cached, the ordinary positive-address fast path remains enabled. */
    loads[0].p_flags = PF_R;
    g_all_objs[0].dynstr_readonly = 1;
    g_all_objs[0].dynsym_readonly = 1;
    if (!get_sysv_hash_view(&g_all_objs[0], &sysv_view))
        goto out;
    cache_validated_sysv_hash_view(&g_all_objs[0], &sysv_view);
    clear_resolution_caches();
    if (!g_all_objs[0].sysv_hash_view_cached ||
        resolve_sym_address(g_all_objs, g_nobj, name, &address) != 1 ||
        address != (uint64_t)(uintptr_t)images[0].payload ||
        sym_cache_lookup(&query, &cached) != 1 || cached != address)
        goto out;
    result = 1;

out:
    clear_resolution_caches();
    g_global_scope_count = 0;
    g_nobj = 0;
    g_is_musl_runtime = saved_musl;
    memset(g_all_objs, 0, 2 * sizeof(g_all_objs[0]));
    if (images != MAP_FAILED)
        munmap(images, 2 * sizeof(*images));
    return result;
}

static int runtime_gnu_unique_call(
    struct loaded_obj *candidate_owner, const Elf64_Sym *candidate,
    struct loaded_obj *copy_owner, const Elf64_Sym *copy_definition,
    struct loaded_obj **selected_owner, const Elf64_Sym **selected_symbol)
{
    struct symbol_lookup_query query;
    uint32_t symbol_index;

    if (!loaded_symbol_table_index(
            candidate_owner, candidate, &symbol_index) ||
        !symbol_lookup_query_init_dynsym(
            candidate_owner, symbol_index, g_all_objs, g_nobj, &query))
        return -1;
    return gnu_unique_canonicalize(
        g_all_objs, g_nobj, &query, candidate_owner, candidate,
        copy_owner, copy_definition, selected_owner, selected_symbol);
}

/* Registry records intentionally retain ELF name identity, but never a
 * lifetime exemption for writable metadata.  Keep the final byte of DT_STRSZ
 * immediately before a guard page so loss of its terminator proves every
 * registered/candidate revalidation is bounded. */
static int mutable_gnu_unique_registry_gate(void)
{
    static const unsigned char hash_key[16] = {
        0x91, 0x02, 0xb3, 0x24, 0xd5, 0x46, 0xf7, 0x68,
        0x79, 0xea, 0x5b, 0xcc, 0x3d, 0xae, 0x1f, 0x80
    };
    const size_t page_size = 4096;
    const size_t string_offset = 4 * sizeof(Elf64_Sym);
    uint8_t *image = MAP_FAILED;
    Elf64_Sym *symbols;
    char *strings;
    Elf64_Phdr load = {0};
    struct loaded_obj object = {0};
    int saved_musl = g_is_musl_runtime;
    int result = 0;

    image = mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (image == MAP_FAILED ||
        mprotect(image + page_size, page_size, PROT_NONE) < 0)
        goto out;
    memset(image, 0, page_size);
    symbols = (Elf64_Sym *)image;
    strings = (char *)image + string_offset;
    memcpy(strings, "\0runtime_unique\0", sizeof("\0runtime_unique\0"));

    load.p_type = PT_LOAD;
    load.p_flags = PF_R | PF_W;
    load.p_filesz = page_size;
    load.p_memsz = page_size;
    object.base = (uintptr_t)image;
    object.phdr = &load;
    object.phdr_num = 1;
    object.dynsym = symbols;
    object.dynsym_count = 3;
    object.dynstr = strings;
    object.dynstr_size = page_size - string_offset;
    object.visible = 1;
    for (uint32_t i = 1; i < 3; i++) {
        symbols[i].st_name = 1;
        symbols[i].st_info = ELF64_ST_INFO(STB_GNU_UNIQUE, STT_OBJECT);
        symbols[i].st_other = STV_DEFAULT;
        symbols[i].st_shndx = 1;
        symbols[i].st_value = 1;
        symbols[i].st_size = 1;
    }

    if (vfs_seed_hash_key(hash_key) < 0)
        goto out;
    memset(g_all_objs, 0, 2 * sizeof(g_all_objs[0]));
    g_all_objs[0] = object;
    g_all_objs[1] = object;
    g_nobj = 2;
    g_is_musl_runtime = 0;
    memset(&g_dl_transaction, 0, sizeof(g_dl_transaction));
    gnu_unique_registry_reset();

    /* PF_W names are never deferred: a resolver or hostile writer may
     * change them after query construction. */
    {
        struct symbol_lookup_query query;

        if (!symbol_lookup_query_init_dynsym(
                &g_all_objs[0], 1, g_all_objs, g_nobj, &query) ||
            !query.keyed_hash_valid || query.keyed_hash_deferred)
            goto out;
    }

    /* A second valid same-name definition observes the first sticky owner. */
    {
        struct loaded_obj *owner = &g_all_objs[0];
        const Elf64_Sym *symbol = &symbols[1];

        if (runtime_gnu_unique_call(
                &g_all_objs[0], &symbols[1], NULL, NULL,
                &owner, &symbol) != 1)
            goto out;
        owner = &g_all_objs[1];
        symbol = &symbols[2];
        if (runtime_gnu_unique_call(
                &g_all_objs[1], &symbols[2], NULL, NULL,
                &owner, &symbol) != 1 ||
            owner != &g_all_objs[0] || symbol != &symbols[1])
            goto out;
    }

    for (unsigned int mutation = 0; mutation < 5; mutation++) {
        struct loaded_obj *owner = &g_all_objs[0];
        const Elf64_Sym *symbol = &symbols[1];

        symbols[1].st_name = 1;
        symbols[1].st_info = ELF64_ST_INFO(STB_GNU_UNIQUE, STT_OBJECT);
        symbols[1].st_other = STV_DEFAULT;
        symbols[1].st_shndx = 1;
        strings[object.dynstr_size - 1] = '\0';
        if (!gnu_unique_registry_rewind(0) ||
            runtime_gnu_unique_call(
                &g_all_objs[0], &symbols[1], NULL, NULL,
                &owner, &symbol) != 1)
            goto out;
        switch (mutation) {
        case 0:
            symbols[1].st_name = (uint32_t)(object.dynstr_size - 1);
            strings[object.dynstr_size - 1] = 'X';
            break;
        case 1:
            symbols[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);
            break;
        case 2:
            symbols[1].st_info = ELF64_ST_INFO(STB_GNU_UNIQUE, STT_FUNC);
            break;
        case 3:
            symbols[1].st_other = STV_HIDDEN;
            break;
        default:
            symbols[1].st_shndx = SHN_UNDEF;
            break;
        }
        owner = &g_all_objs[1];
        symbol = &symbols[2];
        if (runtime_gnu_unique_call(
                &g_all_objs[1], &symbols[2], NULL, NULL,
                &owner, &symbol) >= 0)
            goto out;
    }

    /* Candidate name validation is bounded by the same DT_STRSZ contract. */
    symbols[1].st_name = 1;
    symbols[1].st_info = ELF64_ST_INFO(STB_GNU_UNIQUE, STT_OBJECT);
    symbols[1].st_other = STV_DEFAULT;
    symbols[1].st_shndx = 1;
    symbols[2].st_name = (uint32_t)(object.dynstr_size - 1);
    strings[object.dynstr_size - 1] = 'X';
    {
        struct loaded_obj *owner = &g_all_objs[1];
        const Elf64_Sym *symbol = &symbols[2];

        if (runtime_gnu_unique_call(
                &g_all_objs[1], &symbols[2], NULL, NULL,
                &owner, &symbol) >= 0)
            goto out;
    }

    /* COPY registration stores the executable's ordinary GLOBAL definition
     * while returning the selected DSO definition for the COPY itself. */
    symbols[2].st_name = 1;
    strings[object.dynstr_size - 1] = '\0';
    symbols[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);
    symbols[1].st_other = STV_DEFAULT;
    symbols[1].st_shndx = 1;
    symbols[2].st_info = ELF64_ST_INFO(STB_GNU_UNIQUE, STT_OBJECT);
    symbols[2].st_other = STV_DEFAULT;
    symbols[2].st_shndx = 1;
    g_all_objs[0].flags |= LDR_FLAG_MAIN_EXE;
    if (!gnu_unique_registry_rewind(0))
        goto out;
    {
        struct loaded_obj *owner = &g_all_objs[1];
        const Elf64_Sym *symbol = &symbols[2];

        if (runtime_gnu_unique_call(
                &g_all_objs[1], &symbols[2],
                &g_all_objs[0], &symbols[1], &owner, &symbol) != 1 ||
            owner != &g_all_objs[1] || symbol != &symbols[2])
            goto out;
        owner = &g_all_objs[1];
        symbol = &symbols[2];
        if (runtime_gnu_unique_call(
                &g_all_objs[1], &symbols[2], NULL, NULL,
                &owner, &symbol) != 1 ||
            owner != &g_all_objs[0] || symbol != &symbols[1])
            goto out;
        symbols[1].st_info = ELF64_ST_INFO(STB_WEAK, STT_OBJECT);
        owner = &g_all_objs[1];
        symbol = &symbols[2];
        if (runtime_gnu_unique_call(
                &g_all_objs[1], &symbols[2], NULL, NULL,
                &owner, &symbol) >= 0)
            goto out;
    }

    /* The same mandatory consumer must materialize a deferred hash when
     * DT_STRTAB/DYNSYM are proven immutable. */
    gnu_unique_registry_reset();
    load.p_flags = PF_R;
    symbols[1].st_name = 1;
    symbols[1].st_info = ELF64_ST_INFO(STB_GNU_UNIQUE, STT_OBJECT);
    symbols[1].st_other = STV_DEFAULT;
    symbols[1].st_shndx = 1;
    strings[object.dynstr_size - 1] = '\0';
    memset(g_all_objs, 0, 2 * sizeof(g_all_objs[0]));
    g_all_objs[0] = object;
    g_nobj = 1;
    if (build_loaded_symbol_name_keys(&g_all_objs[0]) < 0)
        goto out;
    {
        struct symbol_lookup_query query;
        struct loaded_obj *owner = &g_all_objs[0];
        const Elf64_Sym *symbol = &symbols[1];
        uint64_t keyed_hash;

        if (!symbol_lookup_query_init_dynsym(
                &g_all_objs[0], 1, g_all_objs, g_nobj, &query) ||
            query.keyed_hash_valid || !query.keyed_hash_deferred ||
            !symbol_lookup_query_keyed_hash(&query, &keyed_hash) ||
            keyed_hash != vfs_hash_n(query.name, query.key.length) ||
            runtime_gnu_unique_call(
                &g_all_objs[0], &symbols[1], NULL, NULL,
                &owner, &symbol) != 1 ||
            g_gnu_unique_count != 1 ||
            g_gnu_unique_registry[0].keyed_hash != keyed_hash)
            goto out;
    }
    result = 1;

out:
    gnu_unique_registry_reset();
    if (g_all_objs[0].runtime_symbol_name_mapping &&
        g_all_objs[0].runtime_symbol_name_mapping_size)
        munmap(g_all_objs[0].runtime_symbol_name_mapping,
               g_all_objs[0].runtime_symbol_name_mapping_size);
    g_nobj = 0;
    g_is_musl_runtime = saved_musl;
    memset(g_all_objs, 0, 2 * sizeof(g_all_objs[0]));
    if (image != MAP_FAILED)
        munmap(image, 2 * page_size);
    return result;
}

static int mutable_dladdr_symbol_gate(void)
{
    const size_t page_size = 4096;
    const size_t hash_offset = 256;
    const size_t string_offset = 512;
    uint8_t *image = MAP_FAILED;
    Elf64_Sym *symbols;
    uint32_t *gnu_hash;
    char *strings;
    Elf64_Phdr load = {0};
    struct loaded_obj object = {0};
    const char *best_name = NULL;
    const Elf64_Sym *best_symbol = NULL;
    uintptr_t best_address = 0;
    int result = 0;

    image = mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (image == MAP_FAILED ||
        mprotect(image + page_size, page_size, PROT_NONE) < 0)
        goto out;
    memset(image, 0, page_size);
    symbols = (Elf64_Sym *)image;
    gnu_hash = (uint32_t *)(image + hash_offset);
    strings = (char *)image + string_offset;
    memcpy(strings, "\0dladdr_name\0", sizeof("\0dladdr_name\0"));

    load.p_type = PT_LOAD;
    load.p_flags = PF_R | PF_W;
    load.p_filesz = page_size;
    load.p_memsz = page_size;
    object.base = (uintptr_t)image;
    object.phdr = &load;
    object.phdr_num = 1;
    object.dynsym = symbols;
    object.dynsym_count = 3;
    object.dynstr = strings;
    object.dynstr_size = page_size - string_offset;
    object.gnu_hash = gnu_hash;

    for (uint32_t i = 1; i < 3; i++) {
        symbols[i].st_name = 1;
        symbols[i].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
        symbols[i].st_other = STV_DEFAULT;
        symbols[i].st_shndx = 1;
        symbols[i].st_value = 128;
        symbols[i].st_size = 16;
    }
    gnu_hash[0] = 4;
    gnu_hash[1] = 1;
    gnu_hash[2] = 1;
    gnu_hash[3] = 5;
    ((uint64_t *)(gnu_hash + 4))[0] = UINT64_MAX;
    gnu_hash[6] = 2;
    gnu_hash[7] = STN_UNDEF;
    gnu_hash[8] = STN_UNDEF;
    gnu_hash[9] = STN_UNDEF;
    gnu_hash[10] = 0;
    gnu_hash[11] = 1;

    /* A PF_W bucket may redirect the scan, but never confer exported binding
     * or visibility on a local/hidden symbol. */
    symbols[2].st_info = ELF64_ST_INFO(STB_LOCAL, STT_FUNC);
    dladdr_scan_symbols(
        &object, object.base + 128,
        &best_name, &best_symbol, &best_address);
    if (best_name || best_symbol)
        goto out;
    symbols[2].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    symbols[2].st_other = STV_HIDDEN;
    dladdr_scan_symbols(
        &object, object.base + 128,
        &best_name, &best_symbol, &best_address);
    if (best_name || best_symbol)
        goto out;

    /* The final DT_STRSZ byte borders PROT_NONE.  Removing its NUL must fail
     * without either returning an unterminated dli_sname or touching guard. */
    symbols[2].st_other = STV_DEFAULT;
    symbols[2].st_name = (uint32_t)(object.dynstr_size - 1);
    strings[object.dynstr_size - 1] = 'X';
    dladdr_scan_symbols(
        &object, object.base + 128,
        &best_name, &best_symbol, &best_address);
    if (best_name || best_symbol)
        goto out;

    strings[object.dynstr_size - 1] = '\0';
    symbols[2].st_name = 1;
    dladdr_scan_symbols(
        &object, object.base + 128,
        &best_name, &best_symbol, &best_address);
    if (!best_name || best_symbol != &symbols[2] ||
        best_address != object.base + 128 ||
        strcmp(best_name, "dladdr_name") != 0)
        goto out;

    /* Duplicate writable buckets cannot multiply dladdr work.  A valid table
     * partitions its symbol chains, so dynsym_count is a conservative global
     * visit budget even when every live bucket is redirected to one chain. */
    best_name = NULL;
    best_symbol = NULL;
    best_address = 0;
    for (uint32_t bucket = 0; bucket < 4; bucket++)
        gnu_hash[6 + bucket] = 1;
    g_dladdr_gnu_chain_visits = 0;
    dladdr_scan_symbols(
        &object, object.base + 128,
        &best_name, &best_symbol, &best_address);
    if (!best_name || !best_symbol ||
        g_dladdr_gnu_chain_visits != object.dynsym_count)
        goto out;
    result = 1;

out:
    if (image != MAP_FAILED)
        munmap(image, 2 * page_size);
    return result;
}

static volatile uint32_t runtime_lock_gate_acquired;
static volatile uint32_t runtime_lock_gate_signal_boundary;
static volatile uint32_t runtime_lock_gate_signal_count;
static volatile uint32_t runtime_lock_gate_signal_failed;
static volatile uint32_t runtime_lock_gate_waiter_mask_failed;
static volatile long runtime_lock_gate_fork_result;
static volatile long runtime_lock_gate_nested_fork_result;

static void runtime_lock_gate_signal_handler(int signal_number)
{
    runtime_loader_lock_token token;
    uint32_t boundary = runtime_atomic_load32(
        &runtime_lock_gate_signal_boundary);
    uintptr_t owner_before = runtime_atomic_load_pointer(
        &g_runtime_loader_lock.owner);
    uintptr_t identity = runtime_atomic_load32(
        &g_runtime_loader_lock.identity_mode) ==
            RUNTIME_LOCK_IDENTITY_TARGET_TP
        ? arch_get_tp()
        : (uintptr_t)runtime_loader_kernel_id(SYS_gettid);

    (void)signal_number;
    token = runtime_loader_lock_acquire();
    if (token != identity ||
        runtime_atomic_load_pointer(&g_runtime_loader_lock.owner) !=
            identity ||
        (boundary == RUNTIME_UNLOCK_GATE_AFTER_OWNER_RELEASE
             ? (owner_before != 0 ||
                runtime_atomic_load32(
                    &g_runtime_loader_lock.nested) != 0)
             : (owner_before != identity ||
                runtime_atomic_load32(
                    &g_runtime_loader_lock.nested) != 1)))
        runtime_atomic_store32(&runtime_lock_gate_signal_failed, 1);
    runtime_loader_lock_release(token);
    (void)runtime_atomic_fetch_add32(
        &runtime_lock_gate_signal_count, 1);
}

static void runtime_lock_gate_unlock_boundary(unsigned int boundary)
{
    void (*hook)(unsigned int) = g_runtime_loader_unlock_gate_hook;

    /* The signal's own final release may cross the same instrumented point
     * when it acquired a fresh root.  Disable only the gate hook while the
     * synchronous handler runs, then restore it for the interrupted release. */
    g_runtime_loader_unlock_gate_hook = NULL;
    runtime_atomic_store32(&runtime_lock_gate_signal_boundary, boundary);
    if (raise(SIGUSR1) != 0)
        runtime_atomic_store32(&runtime_lock_gate_signal_failed, 1);
    g_runtime_loader_unlock_gate_hook = hook;
}

static int runtime_lock_gate_signal_boundaries(void)
{
    struct sigaction signal_action;
    struct sigaction old_signal_action;
    runtime_loader_lock_token outer_token;

    memset(&signal_action, 0, sizeof(signal_action));
    signal_action.sa_handler = runtime_lock_gate_signal_handler;
    sigemptyset(&signal_action.sa_mask);
    if (sigaction(SIGUSR1, &signal_action, &old_signal_action) != 0)
        return 0;
    runtime_atomic_store32(&runtime_lock_gate_signal_count, 0);
    runtime_atomic_store32(&runtime_lock_gate_signal_failed, 0);
    g_runtime_loader_unlock_gate_hook =
        runtime_lock_gate_unlock_boundary;
    outer_token = runtime_loader_lock_acquire();
    runtime_loader_lock_release(outer_token);
    g_runtime_loader_unlock_gate_hook = NULL;
    return sigaction(SIGUSR1, &old_signal_action, NULL) == 0 &&
        runtime_atomic_load32(&runtime_lock_gate_signal_count) == 3 &&
        runtime_atomic_load32(&runtime_lock_gate_signal_failed) == 0 &&
        runtime_atomic_load_pointer(&g_runtime_loader_lock.owner) == 0 &&
        runtime_atomic_load32(&g_runtime_loader_lock.nested) == 0;
}

static void runtime_lock_gate_release_registered_waiter(void)
{
    uint64_t current_signals = 0;

    g_runtime_loader_waiter_registered_gate_hook = NULL;
    if (arch_raw_syscall4(
            SYS_rt_sigprocmask, SIG_SETMASK, 0,
            (long)&current_signals, sizeof(current_signals)) < 0 ||
        (current_signals &
         (UINT64_C(1) << (unsigned int)(SIGUSR1 - 1))) == 0)
        runtime_atomic_store32(
            &runtime_lock_gate_waiter_mask_failed, 1);
    runtime_atomic_store_pointer(&g_runtime_loader_lock.owner, 0);
}

static void runtime_lock_gate_fork_before_owner_cas(void)
{
    long child;

    g_runtime_loader_before_owner_cas_gate_hook = NULL;
    child = arch_raw_syscall5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
    runtime_lock_gate_fork_result = raw_syscall_failed(child) ? -1 : child;
}

static void runtime_lock_gate_registered_fork_before_owner_cas(void)
{
    pid_t child;

    g_runtime_loader_before_owner_cas_gate_hook = NULL;
    child = fork();
    runtime_lock_gate_fork_result = child;
}

static void runtime_lock_gate_fork_after_published_identity(void)
{
    pid_t child;

    g_runtime_loader_published_identity_gate_hook = NULL;
    child = fork();
    runtime_lock_gate_nested_fork_result = child;
}

static void runtime_lock_gate_fork_after_owner_cas(void)
{
    pid_t child;

    g_runtime_loader_after_owner_cas_gate_hook = NULL;
    child = fork();
    runtime_lock_gate_fork_result = child;
    if (child == 0)
        g_runtime_loader_published_identity_gate_hook =
            runtime_lock_gate_fork_after_published_identity;
}

static int runtime_lock_gate_interrupted_acquire(void)
{
    runtime_loader_lock_token token;
    uint32_t tid = runtime_loader_kernel_id(SYS_gettid);
    uintptr_t forged_owner = tid == UINT32_MAX
        ? (uintptr_t)tid - 1 : (uintptr_t)tid + 1;
    int status;

    /* The contended registration/owner-check/unregister region must block a
     * same-thread fork signal.  Release the modeled competing owner from the
     * exact post-registration hook and verify that mask directly. */
    runtime_loader_lock_initialize();
    runtime_atomic_store_pointer(
        &g_runtime_loader_lock.owner, forged_owner);
    runtime_atomic_store32(&runtime_lock_gate_waiter_mask_failed, 0);
    g_runtime_loader_waiter_registered_gate_hook =
        runtime_lock_gate_release_registered_waiter;
    token = runtime_loader_lock_acquire();
    g_runtime_loader_waiter_registered_gate_hook = NULL;
    if (token != tid ||
        runtime_atomic_load32(&g_runtime_loader_lock.waiters) != 0 ||
        runtime_atomic_load32(
            &runtime_lock_gate_waiter_mask_failed) != 0)
        return 0;
    runtime_loader_lock_release(token);

    /* Fork exactly after the final mode recheck and before owner CAS.  The
     * child must roll back the stale parent-TID publication, repair its PID
     * cache, and return a token naming its actual kernel TID. */
    runtime_loader_lock_initialize();
    runtime_lock_gate_fork_result = -1;
    g_runtime_loader_before_owner_cas_gate_hook =
        runtime_lock_gate_fork_before_owner_cas;
    token = runtime_loader_lock_acquire();
    g_runtime_loader_before_owner_cas_gate_hook = NULL;
    if (runtime_lock_gate_fork_result == 0) {
        uint32_t child_tid = runtime_loader_kernel_id(SYS_gettid);

        if (token != child_tid ||
            runtime_atomic_load_pointer(
                &g_runtime_loader_lock.owner) != child_tid ||
            runtime_atomic_load32(
                &g_runtime_loader_lock.process_id) !=
                (uint32_t)arch_raw_syscall0(SYS_getpid))
            loader_exit(1);
        runtime_loader_lock_release(token);
        loader_exit(0);
    }
    if (runtime_lock_gate_fork_result <= 0) {
        runtime_loader_lock_release(token);
        return 0;
    }
    runtime_loader_lock_release(token);
    return waitpid((pid_t)runtime_lock_gate_fork_result, &status, 0) ==
            (pid_t)runtime_lock_gate_fork_result &&
        WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static void *runtime_lock_gate_waiter(void *unused)
{
    runtime_loader_lock_token lock_token;

    (void)unused;
    lock_token = runtime_loader_lock_acquire();
    runtime_atomic_store32(&runtime_lock_gate_acquired, 1);
    runtime_loader_lock_release(lock_token);
    return NULL;
}

static int runtime_loader_lock_gate(void)
{
    struct timespec contention_start;
    struct timespec contention_now;
    pthread_t waiter;
    uint64_t wakes_before;
    uint32_t process_id;
    uint32_t tid;
    runtime_loader_lock_token outer_token;
    runtime_loader_lock_token inner_token;
    pid_t child;
    int status;
    int saw_contention = 0;

    runtime_loader_lock_initialize();
    runtime_atomic_store64(&g_runtime_loader_futex_waits, 0);
    runtime_atomic_store64(&g_runtime_loader_futex_wakes, 0);
    runtime_atomic_store64(&g_runtime_loader_futex_woken, 0);
    runtime_atomic_store64(&g_runtime_loader_tid_revalidations, 0);
    runtime_atomic_store64(&g_runtime_loader_identity_syscalls, 0);
    runtime_atomic_store64(
        &g_runtime_loader_tp_identity_initializations, 0);

    /* Deterministically deliver a same-thread signal at every final-release
     * boundary.  A handler before the owner CAS is one recursive level and
     * must fully unwind before release resumes; a handler after the CAS owns
     * a new root.  Both leave the lock free after the interrupted release. */
    if (!runtime_lock_gate_signal_boundaries())
        return 0;
    if (!runtime_lock_gate_interrupted_acquire())
        return 0;
    runtime_loader_lock_initialize();

    /* Recursive acquisition must preserve ownership and still perform no
     * futex operation when no other thread has attempted the lock. */
    tid = (uint32_t)arch_raw_syscall0(SYS_gettid);
    for (unsigned int i = 0; i < 256; i++) {
        outer_token = runtime_loader_lock_acquire();
        inner_token = runtime_loader_lock_acquire();
        if (outer_token != tid || inner_token != tid ||
            runtime_atomic_load_pointer(
                &g_runtime_loader_lock.owner) != tid ||
            runtime_atomic_load32(&g_runtime_loader_lock.nested) != 1 ||
            runtime_atomic_load32(&g_runtime_loader_lock.waiters) != 0)
            return 0;
        runtime_loader_lock_release(inner_token);
        runtime_loader_lock_release(outer_token);
    }
    if (runtime_atomic_load_pointer(&g_runtime_loader_lock.owner) != 0 ||
        runtime_atomic_load32(&g_runtime_loader_lock.nested) != 0 ||
        runtime_atomic_load64(&g_runtime_loader_futex_waits) != 0 ||
        runtime_atomic_load64(&g_runtime_loader_futex_wakes) != 0 ||
        runtime_atomic_load64(&g_runtime_loader_tid_revalidations) != 0)
        return 0;

    /* Hold the lock until a second thread atomically publishes its waiter
     * count.  Unlock may then win before either the ownership recheck or
     * FUTEX_WAIT: both a queued wake and a completely avoided syscall are
     * correct, provided the waiter makes progress and cleans its record. */
    runtime_atomic_store32(&runtime_lock_gate_acquired, 0);
    outer_token = runtime_loader_lock_acquire();
    if (pthread_create(&waiter, NULL, runtime_lock_gate_waiter, NULL) != 0) {
        runtime_loader_lock_release(outer_token);
        return 0;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &contention_start) != 0) {
        runtime_loader_lock_release(outer_token);
        (void)pthread_join(waiter, NULL);
        return 0;
    }
    for (;;) {
        if (runtime_atomic_load32(&g_runtime_loader_lock.waiters) != 0) {
            saw_contention = 1;
            break;
        }
        if (clock_gettime(CLOCK_MONOTONIC, &contention_now) != 0 ||
            contention_now.tv_sec - contention_start.tv_sec >= 5)
            break;
        sched_yield();
    }
    runtime_loader_lock_release(outer_token);
    if (pthread_join(waiter, NULL) != 0 || !saw_contention ||
        runtime_atomic_load32(&runtime_lock_gate_acquired) != 1)
        return 0;
    if (runtime_atomic_load_pointer(&g_runtime_loader_lock.owner) != 0 ||
        runtime_atomic_load32(&g_runtime_loader_lock.nested) != 0 ||
        runtime_atomic_load32(&g_runtime_loader_lock.waiters) != 0)
        return 0;

    /* The child callback drops only the prepare recursion level, assigns
     * ownership to the child/current TID, and clears inherited contention:
     * no waiter can survive fork.  Calling the paired callbacks directly
     * also preserves and restores the test thread's actual signal mask. */
    outer_token = runtime_loader_lock_acquire();
    runtime_loader_atfork_prepare();
    wakes_before = runtime_atomic_load64(&g_runtime_loader_futex_wakes);
    runtime_loader_atfork_child();
    process_id = (uint32_t)arch_raw_syscall0(SYS_getpid);
    tid = (uint32_t)arch_raw_syscall0(SYS_gettid);
    if (runtime_atomic_load_pointer(&g_runtime_loader_lock.owner) != tid ||
        runtime_atomic_load32(&g_runtime_loader_lock.nested) != 0 ||
        runtime_atomic_load32(&g_runtime_loader_lock.waiters) != 0 ||
        runtime_atomic_load32(&g_runtime_loader_lock.process_id) !=
            process_id) {
        runtime_loader_lock_initialize();
        return 0;
    }
    runtime_loader_lock_release(outer_token);
    if (runtime_atomic_load_pointer(&g_runtime_loader_lock.owner) != 0 ||
        runtime_atomic_load64(&g_runtime_loader_futex_wakes) !=
            wakes_before)
        return 0;

    /* Raw-fork recovery uses the PID mismatch as an independent reset and
     * must discard waiter metadata inherited from the old process. */
    runtime_atomic_store32(&g_runtime_loader_lock.waiters, 1);
    runtime_atomic_store32(
        &g_runtime_loader_lock.process_id, process_id + 1);
    outer_token = runtime_loader_lock_acquire();
    if (runtime_atomic_load_pointer(&g_runtime_loader_lock.owner) != tid ||
        runtime_atomic_load32(&g_runtime_loader_lock.nested) != 0 ||
        runtime_atomic_load32(&g_runtime_loader_lock.waiters) != 0) {
        runtime_loader_lock_initialize();
        return 0;
    }
    runtime_loader_lock_release(outer_token);
    if (runtime_atomic_load_pointer(&g_runtime_loader_lock.owner) != 0 ||
        runtime_atomic_load64(&g_runtime_loader_futex_wakes) !=
            wakes_before)
        return 0;

    /* A real child without the loader's atfork repair may safely discard an
     * unlocked waiter record: no owner or waiter survives in the copied VM. */
    runtime_atomic_store32(&g_runtime_loader_lock.waiters, 1);
    runtime_atomic_store32(
        &g_runtime_loader_lock.process_id, process_id);
    child = fork();
    if (child == 0) {
        runtime_loader_lock_token child_token =
            runtime_loader_lock_acquire();
        uint32_t child_tid = runtime_loader_kernel_id(SYS_gettid);
        uint32_t child_process_id = runtime_loader_kernel_id(SYS_getpid);

        if (child_token != child_tid ||
            runtime_atomic_load_pointer(
                &g_runtime_loader_lock.owner) != child_tid ||
            runtime_atomic_load32(&g_runtime_loader_lock.nested) != 0 ||
            runtime_atomic_load32(&g_runtime_loader_lock.waiters) != 0 ||
            runtime_atomic_load32(&g_runtime_loader_lock.process_id) !=
                child_process_id)
            loader_exit(1);
        runtime_loader_lock_release(child_token);
        loader_exit(runtime_atomic_load_pointer(
                        &g_runtime_loader_lock.owner) == 0 ? 0 : 1);
    }
    if (child < 0 || waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        runtime_loader_lock_initialize();
        return 0;
    }
    runtime_loader_lock_initialize();

    /* Live inherited ownership is not safe to erase.  A raw-fork child
     * which re-enters the loader before unwinding the outer operation must
     * fail closed, before the nested operation can publish any effects. */
    outer_token = runtime_loader_lock_acquire();
    child = fork();
    if (child == 0) {
        (void)runtime_loader_lock_acquire();
        loader_exit(1);
    }
    if (child < 0) {
        runtime_loader_lock_release(outer_token);
        return 0;
    }
    runtime_loader_lock_release(outer_token);
    if (waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 127)
        return 0;

    /* The owner itself may instead unwind the inherited outer operation
     * using its carried token.  Once state is free, the next child acquire
     * repairs the PID cache and proceeds normally. */
    outer_token = runtime_loader_lock_acquire();
    child = fork();
    if (child == 0) {
        runtime_loader_lock_token child_token;
        uint32_t child_tid;

        runtime_loader_lock_release(outer_token);
        child_token = runtime_loader_lock_acquire();
        child_tid = runtime_loader_kernel_id(SYS_gettid);
        if (child_token != child_tid ||
            runtime_atomic_load_pointer(
                &g_runtime_loader_lock.owner) != child_tid ||
            runtime_atomic_load32(&g_runtime_loader_lock.nested) != 0)
            loader_exit(1);
        runtime_loader_lock_release(child_token);
        loader_exit(0);
    }
    if (child < 0) {
        runtime_loader_lock_release(outer_token);
        return 0;
    }
    runtime_loader_lock_release(outer_token);
    if (waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 0;

    /* Conversely, a real pthread_atfork child keeps an outer recursion
     * level but rewrites it to the child's TID.  The parent's acquisition
     * token is then revalidated exactly once in the child before release. */
    if (pthread_atfork(runtime_loader_atfork_prepare,
                       runtime_loader_atfork_parent,
                       runtime_loader_atfork_child) != 0)
        return 0;

    /* A registered fork can complete just before the interrupted owner CAS.
     * Its child callback has advanced the generation while leaving owner
     * free; the stale parent-TID publication must still be rolled back. */
    runtime_lock_gate_fork_result = -1;
    g_runtime_loader_before_owner_cas_gate_hook =
        runtime_lock_gate_registered_fork_before_owner_cas;
    outer_token = runtime_loader_lock_acquire();
    g_runtime_loader_before_owner_cas_gate_hook = NULL;
    if (runtime_lock_gate_fork_result == 0) {
        uint32_t child_tid = runtime_loader_kernel_id(SYS_gettid);

        if (outer_token != child_tid ||
            runtime_atomic_load_pointer(
                &g_runtime_loader_lock.owner) != child_tid)
            loader_exit(1);
        runtime_loader_lock_release(outer_token);
        loader_exit(0);
    }
    if (runtime_lock_gate_fork_result < 0) {
        runtime_loader_lock_release(outer_token);
        return 0;
    }
    runtime_loader_lock_release(outer_token);
    if (waitpid((pid_t)runtime_lock_gate_fork_result, &status, 0) !=
            (pid_t)runtime_lock_gate_fork_result ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 0;

    outer_token = runtime_loader_lock_acquire();
    child = fork();
    if (child == 0) {
        uint32_t child_tid = runtime_loader_kernel_id(SYS_gettid);

        if (runtime_atomic_load_pointer(
                &g_runtime_loader_lock.owner) != child_tid ||
            runtime_atomic_load32(&g_runtime_loader_lock.nested) != 0 ||
            runtime_atomic_load32(&g_runtime_loader_lock.waiters) != 0)
            loader_exit(1);
        runtime_loader_lock_release(outer_token);
        loader_exit(
            runtime_atomic_load64(
                &g_runtime_loader_tid_revalidations) == 1 &&
            runtime_atomic_load_pointer(
                &g_runtime_loader_lock.owner) == 0 ? 0 : 1);
    }
    if (child < 0) {
        runtime_loader_lock_release(outer_token);
        return 0;
    }
    runtime_loader_lock_release(outer_token);
    if (waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
        runtime_atomic_load_pointer(&g_runtime_loader_lock.owner) != 0 ||
        runtime_atomic_load64(&g_runtime_loader_tid_revalidations) != 0)
        return 0;

    /* Fork exactly after root ownership is published, then fork its child
     * between the validation identity and owner reads.  Each registered
     * child callback carries the root under its new TID.  A stable retry must
     * neither combine the two child identities nor reject the rewritten
     * acquisition. */
    runtime_lock_gate_fork_result = -1;
    runtime_lock_gate_nested_fork_result = -1;
    g_runtime_loader_after_owner_cas_gate_hook =
        runtime_lock_gate_fork_after_owner_cas;
    outer_token = runtime_loader_lock_acquire();
    g_runtime_loader_after_owner_cas_gate_hook = NULL;
    if (runtime_lock_gate_fork_result == 0) {
        uint32_t child_tid = runtime_loader_kernel_id(SYS_gettid);
        long nested_child = runtime_lock_gate_nested_fork_result;
        int nested_status;

        if (outer_token != child_tid ||
            runtime_atomic_load_pointer(
                &g_runtime_loader_lock.owner) != child_tid ||
            nested_child < 0)
            loader_exit(1);
        runtime_loader_lock_release(outer_token);
        if (nested_child == 0)
            loader_exit(0);
        if (waitpid((pid_t)nested_child, &nested_status, 0) !=
                (pid_t)nested_child ||
            !WIFEXITED(nested_status) || WEXITSTATUS(nested_status) != 0)
            loader_exit(1);
        loader_exit(0);
    }
    if (runtime_lock_gate_fork_result < 0) {
        runtime_loader_lock_release(outer_token);
        return 0;
    }
    runtime_loader_lock_release(outer_token);
    if (waitpid((pid_t)runtime_lock_gate_fork_result, &status, 0) !=
            (pid_t)runtime_lock_gate_fork_result ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 0;

    /* A token acquired before a pthread_atfork child repair carries the
     * parent's TID.  Model that one exceptional mismatch: release must
     * revalidate the current kernel TID, while ordinary paired releases
     * above must never pay that syscall. */
    outer_token = runtime_loader_lock_acquire();
    runtime_loader_lock_release(outer_token == UINTPTR_MAX
                                    ? outer_token - 1
                                    : outer_token + 1);
    return runtime_atomic_load_pointer(&g_runtime_loader_lock.owner) == 0 &&
           runtime_atomic_load32(&g_runtime_loader_lock.nested) == 0 &&
           runtime_atomic_load64(&g_runtime_loader_futex_wakes) ==
               wakes_before &&
           runtime_atomic_load64(&g_runtime_loader_tid_revalidations) == 1;
}

static pid_t runtime_lock_gate_raw_fork(void)
{
    long child = arch_raw_syscall5(SYS_clone, SIGCHLD, 0, 0, 0, 0);

    if (raw_syscall_failed(child) || child > INT_MAX)
        return -1;
    return (pid_t)child;
}

static int runtime_loader_tp_lock_gate(void)
{
    long page_size_long = sysconf(_SC_PAGESIZE);
    volatile uint32_t *cookie;
    runtime_loader_lock_token outer_token;
    uint64_t identity_syscalls;
    uintptr_t tp;
    pthread_t waiter;
    pid_t child;
    int status;

    if (page_size_long <= 0)
        return 0;
    cookie = mmap(NULL, (size_t)page_size_long,
                  PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (cookie == MAP_FAILED)
        return 0;
    if (madvise((void *)cookie, (size_t)page_size_long,
                MADV_WIPEONFORK) != 0) {
        (void)munmap((void *)cookie, (size_t)page_size_long);
        return 0;
    }
    *cookie = DLFRZ_RUNTIME_FORK_COOKIE;
    g_runtime_loader_fork_cookie = cookie;
    g_target_tls_active = 1;
    runtime_atomic_store64(&g_runtime_loader_identity_syscalls, 0);
    runtime_atomic_store64(
        &g_runtime_loader_tp_identity_initializations, 0);
    runtime_loader_lock_initialize();
    tp = arch_get_tp();
    if (tp == 0 ||
        runtime_atomic_load32(&g_runtime_loader_lock.identity_mode) !=
            RUNTIME_LOCK_IDENTITY_TARGET_TP ||
        runtime_atomic_load64(
            &g_runtime_loader_tp_identity_initializations) != 1)
        goto fail;
    if (!runtime_lock_gate_signal_boundaries())
        goto fail;

    /* The steady-state lock may call neither gettid nor a target-libc
     * identity helper.  Exercise both outer and recursive acquisitions. */
    identity_syscalls = runtime_atomic_load64(
        &g_runtime_loader_identity_syscalls);
    for (unsigned int i = 0; i < 4096; i++) {
        runtime_loader_lock_token inner_token;

        outer_token = runtime_loader_lock_acquire();
        inner_token = runtime_loader_lock_acquire();
        if (outer_token != tp || inner_token != tp ||
            runtime_atomic_load_pointer(
                &g_runtime_loader_lock.owner) != tp ||
            runtime_atomic_load32(&g_runtime_loader_lock.nested) != 1)
            goto fail_locked;
        runtime_loader_lock_release(inner_token);
        runtime_loader_lock_release(outer_token);
    }
    if (runtime_atomic_load64(&g_runtime_loader_identity_syscalls) !=
            identity_syscalls ||
        runtime_atomic_load_pointer(&g_runtime_loader_lock.owner) != 0)
        goto fail;

    /* A target thread has a distinct architectural TP, so contention must
     * take the futex path rather than being mistaken for recursion. */
    runtime_atomic_store32(&runtime_lock_gate_acquired, 0);
    outer_token = runtime_loader_lock_acquire();
    if (pthread_create(&waiter, NULL, runtime_lock_gate_waiter, NULL) != 0) {
        runtime_loader_lock_release(outer_token);
        goto fail;
    }
    for (unsigned int spin = 0;
         spin < 1000000 &&
         runtime_atomic_load32(&g_runtime_loader_lock.waiters) == 0;
         spin++)
        sched_yield();
    if (runtime_atomic_load32(&g_runtime_loader_lock.waiters) == 0) {
        runtime_loader_lock_release(outer_token);
        (void)pthread_join(waiter, NULL);
        goto fail;
    }
    runtime_loader_lock_release(outer_token);
    if (pthread_join(waiter, NULL) != 0 ||
        runtime_atomic_load32(&runtime_lock_gate_acquired) != 1 ||
        runtime_atomic_load64(&g_runtime_loader_identity_syscalls) !=
            identity_syscalls)
        goto fail;

    /* A raw child with an unlocked snapshot repairs the wiped cookie and
     * process metadata once, then continues in TP mode. */
    child = runtime_lock_gate_raw_fork();
    if (child == 0) {
        runtime_loader_lock_token child_token =
            runtime_loader_lock_acquire();

        if (child_token != arch_get_tp() ||
            runtime_atomic_load32(cookie) !=
                DLFRZ_RUNTIME_FORK_COOKIE ||
            runtime_atomic_load32(
                &g_runtime_loader_lock.process_id) !=
                (uint32_t)arch_raw_syscall0(SYS_getpid))
            loader_exit(1);
        runtime_loader_lock_release(child_token);
        loader_exit(0);
    }
    if (child < 0 || waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        goto fail;

    /* TP survives fork for the calling thread.  That exact equality proves
     * a live owner belongs to the surviving thread, so a nested child call
     * may continue and unwind the carried outer operation safely. */
    outer_token = runtime_loader_lock_acquire();
    child = runtime_lock_gate_raw_fork();
    if (child == 0) {
        runtime_loader_lock_token inner_token =
            runtime_loader_lock_acquire();
        runtime_loader_lock_token fresh_token;

        if (inner_token != arch_get_tp() ||
            runtime_atomic_load32(&g_runtime_loader_lock.nested) != 1 ||
            runtime_atomic_load32(cookie) !=
                DLFRZ_RUNTIME_FORK_COOKIE)
            loader_exit(1);
        runtime_loader_lock_release(inner_token);
        runtime_loader_lock_release(outer_token);
        fresh_token = runtime_loader_lock_acquire();
        if (fresh_token != arch_get_tp())
            loader_exit(1);
        runtime_loader_lock_release(fresh_token);
        loader_exit(0);
    }
    if (child < 0) {
        runtime_loader_lock_release(outer_token);
        goto fail;
    }
    runtime_loader_lock_release(outer_token);
    if (waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        goto fail;

    /* Conversely, a live owner which differs from the surviving TP belongs
     * to a vanished thread and must not be repaired. */
    child = runtime_lock_gate_raw_fork();
    if (child == 0) {
        uintptr_t forged_owner = arch_get_tp() ^ (uintptr_t)0x1000U;

        if (forged_owner == 0 || forged_owner == arch_get_tp())
            loader_exit(1);
        runtime_atomic_store_pointer(
            &g_runtime_loader_lock.owner, forged_owner);
        (void)runtime_loader_lock_acquire();
        loader_exit(1);
    }
    if (child < 0 || waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 127)
        goto fail;

    /* The already-registered atfork callbacks rearm the wiped page and keep
     * an outer recursion level owned by the child's TP. */
    outer_token = runtime_loader_lock_acquire();
    child = fork();
    if (child == 0) {
        if (runtime_atomic_load_pointer(
                &g_runtime_loader_lock.owner) != arch_get_tp() ||
            runtime_atomic_load32(&g_runtime_loader_lock.nested) != 0 ||
            runtime_atomic_load32(cookie) !=
                DLFRZ_RUNTIME_FORK_COOKIE)
            loader_exit(1);
        runtime_loader_lock_release(outer_token);
        loader_exit(0);
    }
    if (child < 0) {
        runtime_loader_lock_release(outer_token);
        goto fail;
    }
    runtime_loader_lock_release(outer_token);
    if (waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        goto fail;

    /* Missing bootstrap proof must leave the old TID mode intact even when
     * target TLS itself is already active. */
    g_runtime_loader_fork_cookie = NULL;
    runtime_loader_lock_initialize();
    if (runtime_atomic_load32(&g_runtime_loader_lock.identity_mode) !=
        RUNTIME_LOCK_IDENTITY_TID)
        goto fail_unmapped;
    outer_token = runtime_loader_lock_acquire();
    if (outer_token != (uintptr_t)runtime_loader_kernel_id(SYS_gettid)) {
        runtime_loader_lock_release(outer_token);
        goto fail_unmapped;
    }
    runtime_loader_lock_release(outer_token);
    g_target_tls_active = 0;
    (void)munmap((void *)cookie, (size_t)page_size_long);
    return 1;

fail_locked:
    runtime_loader_lock_release(outer_token);
fail:
    g_runtime_loader_fork_cookie = NULL;
fail_unmapped:
    g_target_tls_active = 0;
    (void)munmap((void *)cookie, (size_t)page_size_long);
    runtime_loader_lock_initialize();
    return 0;
}

static int published_tls_fast_path_gate(void)
{
    const size_t iterations = 4096;
    uintptr_t fake_tp_words[8] = {0};
    unsigned char static_tls[192] = {0};
    uintptr_t raw_glibc_dtv[10] = {0};
    uintptr_t musl_dtv[4] = {0};
    unsigned char tls_block[64] = {0};
    uintptr_t tp = (uintptr_t)(static_tls + 96);
    uintptr_t *glibc_dtv = raw_glibc_dtv + 2;
    size_t acquisitions = g_runtime_loader_lock_acquisitions;
    void *address;

    memset(g_runtime_tls_fast, 0, sizeof(g_runtime_tls_fast));
    runtime_atomic_store64(
        &g_runtime_tls_fast[3].static_tpoff_bits, (uint64_t)(int64_t)-64);
    runtime_atomic_store64(
        &g_runtime_tls_fast[3].extent_plus_one,
        sizeof(tls_block) + 1U);
    g_is_musl_runtime = 0;
    g_glibc_tcb_dtv_off = sizeof(uintptr_t);
    raw_glibc_dtv[0] = 0;
    *(uintptr_t **)(tp + TCB_OFF_DTV) = glibc_dtv;
    if (runtime_tls_get_addr_fast(tp, 3, 0, &address))
        return 0;
    raw_glibc_dtv[0] = 3;
    glibc_dtv[3 * 2] = (uintptr_t)(static_tls + 32);
    for (size_t i = 0; i < iterations; i++) {
        size_t offset = i % (sizeof(tls_block) + 1U);

        address = runtime_tls_get_addr(tp, 3, offset);
        if (address != (void *)(static_tls + 32 + offset))
            return 0;
    }
    if (g_runtime_loader_lock_acquisitions != acquisitions)
        return 0;

    memset(g_runtime_tls_fast, 0, sizeof(g_runtime_tls_fast));
    runtime_atomic_store64(
        &g_runtime_tls_fast[3].static_tpoff_bits, 16);
    runtime_atomic_store64(
        &g_runtime_tls_fast[3].extent_plus_one,
        sizeof(tls_block) + 1U);
    glibc_dtv[3 * 2] = (uintptr_t)(static_tls + 112);
    for (size_t i = 0; i < iterations; i++) {
        size_t offset = i % (sizeof(tls_block) + 1U);

        address = runtime_tls_get_addr(tp, 3, offset);
        if (address != (void *)(static_tls + 112 + offset))
            return 0;
    }
    if (g_runtime_loader_lock_acquisitions != acquisitions)
        return 0;

    memset(g_runtime_tls_fast, 0, sizeof(g_runtime_tls_fast));
    tp = (uintptr_t)fake_tp_words;
    runtime_atomic_store64(
        &g_runtime_tls_fast[3].extent_plus_one,
        sizeof(tls_block) + 1U);

    g_is_musl_runtime = 0;
    g_glibc_tcb_dtv_off = sizeof(uintptr_t);
    raw_glibc_dtv[0] = 3;
    glibc_dtv[3 * 2] = (uintptr_t)tls_block;
    *(uintptr_t **)(tp + TCB_OFF_DTV) = glibc_dtv;
    for (size_t i = 0; i < iterations; i++) {
        size_t offset = i % (sizeof(tls_block) + 1U);

        address = runtime_tls_get_addr(tp, 3, offset);
        if (address != tls_block + offset)
            return 0;
    }
    if (g_runtime_loader_lock_acquisitions != acquisitions)
        return 0;

    memset(fake_tp_words, 0, sizeof(fake_tp_words));
    g_is_musl_runtime = 1;
    g_musl_tp_self_delta = 0;
    g_musl_thread.dtv = sizeof(uintptr_t);
    musl_dtv[0] = 3;
    musl_dtv[3] = (uintptr_t)tls_block;
    *(uintptr_t **)musl_thread_dtv_slot(tp) = musl_dtv;
    for (size_t i = 0; i < iterations; i++) {
        size_t offset = i % (sizeof(tls_block) + 1U);

        address = runtime_tls_get_addr(tp, 3, offset);
        if (address != tls_block + offset)
            return 0;
    }
    if (g_runtime_loader_lock_acquisitions != acquisitions)
        return 0;

    memset(g_runtime_tls_fast, 0, sizeof(g_runtime_tls_fast));
    return 1;
}

struct tls_publication_gate_context {
    unsigned char static_tls[192];
    uintptr_t raw_glibc_dtv[10];
    volatile uint64_t saw_absent;
    volatile uint64_t offset_ready;
    volatile uint64_t checked_unpublished;
    volatile uint64_t observed;
    volatile uint64_t failed;
};

static void *tls_publication_gate_reader(void *opaque)
{
    struct tls_publication_gate_context *context = opaque;
    uintptr_t tp = (uintptr_t)(context->static_tls + 96);
    void *address = NULL;

    if (runtime_tls_get_addr_fast(tp, 3, 7, &address)) {
        runtime_atomic_store64(&context->failed, 1);
        return NULL;
    }
    runtime_atomic_store64(&context->saw_absent, 1);

    while (runtime_atomic_load64(&context->offset_ready) == 0)
        sched_yield();
    if (runtime_tls_get_addr_fast(tp, 3, 7, &address)) {
        runtime_atomic_store64(&context->failed, 1);
        return NULL;
    }
    runtime_atomic_store64(&context->checked_unpublished, 1);

    while (runtime_atomic_load64(
               &g_runtime_tls_fast[3].extent_plus_one) == 0)
        sched_yield();
    if (!runtime_tls_get_addr_fast(tp, 3, 7, &address) ||
        address != context->static_tls + 39) {
        runtime_atomic_store64(&context->failed, 1);
        return NULL;
    }
    runtime_atomic_store64(&context->observed, 1);
    return NULL;
}

static int concurrent_tls_publication_gate(void)
{
    struct tls_publication_gate_context context = {0};
    uintptr_t tp = (uintptr_t)(context.static_tls + 96);
    uintptr_t *dtv = context.raw_glibc_dtv + 2;
    pthread_t reader;

    memset(g_runtime_tls_fast, 0, sizeof(g_runtime_tls_fast));
    g_is_musl_runtime = 0;
    g_glibc_tcb_dtv_off = sizeof(uintptr_t);
    context.raw_glibc_dtv[0] = 3;
    dtv[3 * 2] = (uintptr_t)(context.static_tls + 32);
    *(uintptr_t **)(tp + TCB_OFF_DTV) = dtv;
    if (pthread_create(&reader, NULL, tls_publication_gate_reader,
                       &context) != 0)
        return 0;
    while (runtime_atomic_load64(&context.saw_absent) == 0 &&
           runtime_atomic_load64(&context.failed) == 0)
        sched_yield();
    if (runtime_atomic_load64(&context.failed) != 0) {
        (void)pthread_join(reader, NULL);
        memset(g_runtime_tls_fast, 0, sizeof(g_runtime_tls_fast));
        return 0;
    }
    runtime_atomic_store64(
        &g_runtime_tls_fast[3].static_tpoff_bits,
        (uint64_t)(int64_t)-64);
    runtime_atomic_store64(&context.offset_ready, 1);
    while (runtime_atomic_load64(&context.checked_unpublished) == 0 &&
           runtime_atomic_load64(&context.failed) == 0)
        sched_yield();
    if (runtime_atomic_load64(&context.failed) == 0)
        runtime_atomic_store64(
            &g_runtime_tls_fast[3].extent_plus_one, 65);
    if (pthread_join(reader, NULL) != 0)
        return 0;
    memset(g_runtime_tls_fast, 0, sizeof(g_runtime_tls_fast));
    return runtime_atomic_load64(&context.failed) == 0 &&
           runtime_atomic_load64(&context.observed) != 0;
}

static int runtime_loader_kernel_id_gate(void)
{
    uint32_t id = 0;

    if (runtime_loader_kernel_id_value(-EPERM, &id) ||
        runtime_loader_kernel_id_value(-1, &id) ||
        runtime_loader_kernel_id_value(0, &id) ||
        runtime_loader_kernel_id_value(1, NULL) ||
        id != 0)
        return 0;
    if (!runtime_loader_kernel_id_value(1, &id) || id != 1)
        return 0;
#if ULONG_MAX > UINT32_MAX
    if (runtime_loader_kernel_id_value(
            (long)UINT32_MAX + 1L, &id))
        return 0;
#endif
    return runtime_loader_kernel_id_value(UINT32_MAX, &id) &&
           id == UINT32_MAX;
}

struct completed_plt_gate_context {
    volatile uint32_t returned;
    uintptr_t target;
};

static void *completed_plt_gate_worker(void *argument)
{
    struct completed_plt_gate_context *context = argument;

    context->target = lazy_plt_fixup(
        &g_all_objs[0].public_link_map, 0, 0);
    runtime_atomic_store32(&context->returned, 1);
    return NULL;
}

static int completed_plt_gate_wait(volatile uint32_t *word)
{
    struct timespec start, now;

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
        return 0;
    while (runtime_atomic_load32(word) == 0) {
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
            now.tv_sec - start.tv_sec >= 3)
            return 0;
        sched_yield();
    }
    return 1;
}

static int completed_startup_plt_gate(void)
{
    struct lazy_plt_resolution resolution = {.initial = 1};
    struct completed_plt_gate_context context = {0};
    struct startup_lazy_plt_dispatch *dispatch =
        &g_startup_lazy_plt_dispatch[0];
    runtime_loader_lock_token token;
    pthread_t worker;
    size_t index;
    uint64_t slot = 0;
    void *saved_mapping = g_startup_lazy_plt_resolution_mapping;
    size_t saved_mapping_size = g_startup_lazy_plt_resolution_mapping_size;
    int ok;

    g_target_tls_active = 0;
    g_runtime_loader_fork_cookie = NULL;
    runtime_loader_lock_initialize();
    runtime_atomic_store32(&g_runtime_loader_phase,
                           RUNTIME_LOADER_PHASE_RUNNING);
    dispatch->resolutions = &resolution;
    dispatch->count = 1;
    dispatch->first_slot = 0x1000;
    runtime_atomic_store32(&g_startup_lazy_plt_dispatch_count, 1);
    index = 0;
    if (startup_lazy_plt_resolution(
            (void *)((uintptr_t)&g_all_objs[0].public_link_map + 1),
            &index, 0) ||
        startup_lazy_plt_resolution(
            &g_all_objs[1].public_link_map, &index, 0))
        return 0;
    index = 1;
    if (startup_lazy_plt_resolution(
            &g_all_objs[0].public_link_map, &index, 0))
        return 0;
    index = 0;
    resolution.initial = 0;
    if (startup_lazy_plt_resolution(
            &g_all_objs[0].public_link_map, &index, 0))
        return 0;
    resolution.initial = 1;
#if defined(__aarch64__)
    index = SIZE_MAX;
    if (startup_lazy_plt_resolution(
            &g_all_objs[0].public_link_map, &index, 0x1001))
        return 0;
    index = SIZE_MAX;
    if (startup_lazy_plt_resolution(
            &g_all_objs[0].public_link_map, &index, 0x1000) != &resolution ||
        index != 0)
        return 0;
#endif

    token = runtime_loader_lock_acquire();
    g_startup_lazy_plt_resolution_mapping = &resolution;
    g_startup_lazy_plt_resolution_mapping_size = sizeof(resolution);
    if (pthread_create(&worker, NULL, completed_plt_gate_worker, &context))
        return 0;
    ok = completed_plt_gate_wait(&g_runtime_loader_lock.waiters);
    /* Publish the same irreversible result as a real lazy resolver, while
     * intentionally retaining the namespace lock. The waiting caller must
     * make progress before this owner can release its constructor hold. */
    (void)lazy_plt_resolution_publish(&resolution, &slot, 0x12345);
    ok = completed_plt_gate_wait(&context.returned) && ok;
    ok = ok && context.target == 0x12345 &&
        runtime_atomic_load_pointer(&g_runtime_loader_lock.owner) == token &&
        runtime_atomic_load32(&g_runtime_loader_lock.waiters) == 0 &&
        runtime_atomic_load32(&g_runtime_loader_lock.nested) == 0;
    runtime_loader_lock_release(token);
    if (pthread_join(worker, NULL) != 0)
        ok = 0;
    /* A completed weak binding may legitimately be zero; DONE, not target,
     * must distinguish the result from an unresolved slot. */
    runtime_atomic_store64(&resolution.state, 0);
    runtime_atomic_store64(&resolution.target, 0);
    runtime_atomic_store64(&resolution.state, LAZY_PLT_RESOLUTION_DONE);
    if (lazy_plt_fixup(&g_all_objs[0].public_link_map, 0, 0) != 0)
        ok = 0;
    runtime_atomic_store32(&g_startup_lazy_plt_dispatch_count, 0);
    dispatch->resolutions = NULL;
    g_startup_lazy_plt_resolution_mapping = saved_mapping;
    g_startup_lazy_plt_resolution_mapping_size = saved_mapping_size;
    runtime_atomic_store32(&g_runtime_loader_phase,
                           RUNTIME_LOADER_PHASE_RESET);
    return ok;
}

static void *callback_lookup_gate_worker(void *argument)
{
    volatile uint32_t *returned = argument;
    runtime_loader_lock_token token =
        runtime_loader_lock_acquire_or_complete(NULL, 1);

    runtime_loader_lock_release(token);
    runtime_atomic_store32(returned, 1);
    return NULL;
}

static int callback_reservation_gate(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    volatile uint32_t *cookie;

    if (page_size <= 0)
        return 0;
    cookie = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (cookie == MAP_FAILED ||
        madvise((void *)cookie, (size_t)page_size, MADV_WIPEONFORK))
        return 0;
    *cookie = DLFRZ_RUNTIME_FORK_COOKIE;
    for (int fast = 0; fast < 2; fast++) {
        struct runtime_loader_callback_scope outer, inner;
        volatile uint32_t lookup_returned = 0;
        pthread_t ordinary, lookup;
        pid_t child;
        int status;

        g_target_tls_active = 1;
        g_runtime_loader_fork_cookie = fast ? cookie : NULL;
        runtime_loader_lock_initialize();
        (void)runtime_loader_lock_acquire();
        (void)runtime_loader_lock_acquire();
        outer = runtime_loader_callback_begin();
        (void)runtime_loader_lock_acquire();
        inner = runtime_loader_callback_begin();
        runtime_atomic_store32(&runtime_lock_gate_acquired, 0);
        if (pthread_create(&ordinary, NULL, runtime_lock_gate_waiter, NULL) ||
            !completed_plt_gate_wait(&g_runtime_loader_lock.waiters) ||
            pthread_create(&lookup, NULL, callback_lookup_gate_worker,
                           (void *)&lookup_returned) ||
            !completed_plt_gate_wait(&lookup_returned) ||
            pthread_join(lookup, NULL) ||
            runtime_atomic_load32(&runtime_lock_gate_acquired) != 0)
            return 0;

        /* Both raw and registered fork must retain the surviving nested
         * callback frames, including when the optional TP optimization is
         * unavailable. A blocked ordinary waiter does not survive either. */
        for (int registered = 0; registered < 2; registered++) {
            if (registered)
                runtime_loader_atfork_prepare();
            child = runtime_lock_gate_raw_fork();
            if (child == 0) {
                if (registered)
                    runtime_loader_atfork_child();
                runtime_loader_callback_end(inner);
                runtime_loader_lock_release_current();
                runtime_loader_callback_end(outer);
                if (runtime_atomic_load32(&g_runtime_loader_lock.nested) != 1)
                    loader_exit(1);
                runtime_loader_lock_release_current();
                runtime_loader_lock_release_current();
                loader_exit(runtime_atomic_load_pointer(
                    &g_runtime_loader_lock.callback_owner) != 0);
            }
            if (registered)
                runtime_loader_atfork_parent();
            if (child < 0 || waitpid(child, &status, 0) != child ||
                !WIFEXITED(status) || WEXITSTATUS(status) != 0)
                return 0;
        }

        runtime_loader_callback_end(inner);
        runtime_loader_lock_release_current();
        if (runtime_atomic_load_pointer(&g_runtime_loader_lock.callback_owner) !=
                arch_get_tp() ||
            runtime_atomic_load32(&runtime_lock_gate_acquired) != 0)
            return 0;
        runtime_loader_callback_end(outer);
        if (runtime_atomic_load32(&g_runtime_loader_lock.nested) != 1)
            return 0;
        runtime_loader_lock_release_current();
        runtime_loader_lock_release_current();
        if (pthread_join(ordinary, NULL) ||
            runtime_atomic_load32(&runtime_lock_gate_acquired) != 1 ||
            runtime_atomic_load_pointer(&g_runtime_loader_lock.callback_owner) != 0 ||
            runtime_atomic_load_pointer(&g_runtime_loader_lock.owner) != 0 ||
            runtime_atomic_load32(&g_runtime_loader_lock.waiters) != 0)
            return 0;
    }
    g_target_tls_active = 0;
    g_runtime_loader_fork_cookie = NULL;
    runtime_loader_lock_initialize();
    return munmap((void *)cookie, (size_t)page_size) == 0;
}

int main(void)
{
    if (!loader_memcmp_gate()) return 31;
    if (!loader_memchr_gate()) return 15;
    if (!resolver_tls_template_overlap_gate()) return 25;
    if (!large_table_gate()) return 1;
    if (!relocation_admission_single_pass_gate()) return 29;
    if (!truncation_gate()) return 2;
    if (!runtime_file_revision_gate()) return 3;
    if (!version_index_gate()) return 4;
    if (!version_need_index_gate()) return 5;
    if (!manifest_startup_owner_gate()) return 6;
    if (!symbol_query_equivalence_gate()) return 7;
    if (!symbol_name_radix_sort_gate()) return 19;
    if (!symbol_name_span_gate()) return 30;
    if (!hash_view_cache_gate()) return 8;
    if (!mutable_dynsym_name_gate()) return 9;
    if (!mutable_versym_key_gate()) return 10;
    if (!immutable_exact_name_index_gate()) return 21;
    if (!admitted_symbol_span_gate()) return 11;
    if (!symbol_lookup_complexity_gate()) return 12;
    if (!global_address_cache_mutation_gate()) return 13;
    if (!mutable_gnu_unique_registry_gate()) return 16;
    if (!mutable_dladdr_symbol_gate()) return 17;
    if (!dynamic_semantic_snapshot_gate()) return 18;
    if (!published_tls_fast_path_gate()) return 14;
    if (!concurrent_tls_publication_gate()) return 24;
    if (!runtime_loader_lock_gate()) return 20;
    if (!runtime_loader_tp_lock_gate()) return 26;
    if (!runtime_loader_kernel_id_gate()) return 23;
    if (!completed_startup_plt_gate()) return 27;
    if (!callback_reservation_gate()) return 28;
    return 0;
}
