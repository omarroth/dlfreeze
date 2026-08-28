/* Keep the exhaustion path cheap under native and emulated CI while testing
 * the same mmap growth/rewind implementation as the much larger production
 * ceiling. */
#define GNU_UNIQUE_REGISTRY_INITIAL 32U
#define GNU_UNIQUE_REGISTRY_MAX 4096U
#define GNU_UNIQUE_BUCKET_COUNT 1024U

/* Exercise the loader's private section-table fallback in its real source. */
#include "../src/loader.c"

static unsigned int gate_pthread_atfork_calls;
static unsigned int gate_register_atfork_calls;
static void *gate_register_atfork_token;

static int gate_pthread_atfork(void (*prepare)(void), void (*parent)(void),
                               void (*child)(void))
{
    (void)prepare;
    (void)parent;
    (void)child;
    gate_pthread_atfork_calls++;
    return 0;
}

static int gate_register_atfork(void (*prepare)(void), void (*parent)(void),
                                void (*child)(void), void *token)
{
    (void)prepare;
    (void)parent;
    (void)child;
    gate_register_atfork_calls++;
    gate_register_atfork_token = token;
    return 0;
}

static int gate_map_embedded_elf_eof(void)
{
    const size_t entry_size = 256;
    const size_t container_size = 2 * 4096;
    FILE *container = NULL;
    uint8_t *source = MAP_FAILED;
    uint8_t *target = MAP_FAILED;
    struct dlfrz_entry entry = {0};
    struct dlfrz_lib_meta meta = {0};
    struct loaded_obj object = {0};
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    int result = 0;

    if (g_page_size != 4096)
        return 0;
    container = tmpfile();
    if (!container || ftruncate(fileno(container), container_size) < 0)
        goto out;
    source = mmap(NULL, container_size, PROT_READ | PROT_WRITE,
                  MAP_SHARED, fileno(container), 0);
    if (source == MAP_FAILED)
        goto out;
    memset(source, 0, container_size);
    memset(source + 4096, 0x3c, entry_size);
    memset(source + 4096 + entry_size, 0xa5, 4096 - entry_size);

    ehdr = (Elf64_Ehdr *)(source + 4096);
    phdr = (Elf64_Phdr *)(source + 4096 + sizeof(*ehdr));
    memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
    ehdr->e_phoff = sizeof(*ehdr);
    ehdr->e_phnum = 1;
    ehdr->e_phentsize = sizeof(*phdr);
    phdr->p_type = PT_LOAD;
    phdr->p_flags = PF_R | PF_W;
    phdr->p_offset = 0;
    phdr->p_vaddr = 0;
    phdr->p_filesz = entry_size;
    phdr->p_memsz = entry_size;
    phdr->p_align = 4096;

    target = mmap(NULL, 4096, PROT_NONE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (target == MAP_FAILED)
        goto out;
    entry.data_offset = 4096;
    entry.data_size = entry_size;
    meta.base_addr = (uintptr_t)target;
    meta.vaddr_lo = 0;
    meta.vaddr_hi = entry_size;
    meta.phdr_off = sizeof(*ehdr);
    meta.phdr_num = 1;
    meta.phdr_entsz = sizeof(*phdr);
    meta.flags = DLFRZ_FLAG_SHLIB;

    if (map_object(source, 0, fileno(container), &meta, &entry,
                   &object, 1) < 0 ||
        memcmp(target, source + 4096, entry_size) != 0)
        goto out;
    for (size_t i = entry_size; i < 4096; i++)
        if (target[i] != 0)
            goto out;
    result = 1;

out:
    if (target != MAP_FAILED)
        munmap(target, 4096);
    if (source != MAP_FAILED)
        munmap(source, container_size);
    if (container)
        fclose(container);
    return result;
}

static int gate_partial_relro_page(void)
{
    const size_t page = 4096;
    uint8_t *mapping = MAP_FAILED;
    Elf64_Phdr *phdr;
    struct loaded_obj object = {0};
    struct dlfrz_lib_meta meta = {0};
    void *pointer = NULL;
    int result = 0;

    if (g_page_size != page)
        return 0;
    mapping = mmap(NULL, 3 * page, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return 0;
    phdr = (Elf64_Phdr *)(mapping + 2 * page + 128);
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R | PF_W;
    phdr[0].p_filesz = 3 * page;
    phdr[0].p_memsz = 3 * page;
    phdr[1].p_type = PT_GNU_RELRO;
    phdr[1].p_vaddr = 128;
    phdr[1].p_memsz = 128;

    object.base = (uintptr_t)mapping;
    object.phdr = phdr;
    object.phdr_num = 2;
    meta.base_addr = (uintptr_t)mapping;
    meta.vaddr_lo = 0;
    meta.vaddr_hi = 3 * page;
    meta.phdr_off = 2 * page + 128;
    meta.phdr_num = 2;
    meta.phdr_entsz = sizeof(*phdr);

    /* A RELRO interval containing no complete final page protects nothing. */
    if (!loaded_obj_writable_pointer(
            &object, 128, 1, &pointer) || pointer != mapping + 128 ||
        protect_object(&object, &meta) < 0)
        goto out;
    mapping[128] = 0x31;

    /* With one complete page and a partial suffix, the protected range is
     * [floor(start), floor(end)).  The prefix shares the protected page,
     * while the raw RELRO tail shares a writable .data page. */
    phdr[1].p_memsz = page;
    if (loaded_obj_writable_pointer(&object, 64, 1, NULL) ||
        !loaded_obj_writable_pointer(
            &object, page + 64, 1, &pointer) ||
        pointer != mapping + page + 64 ||
        protect_object(&object, &meta) < 0)
        goto out;
    mapping[page + 64] = 0x52;
    if (mapping[page + 64] != 0x52)
        goto out;
    result = 1;

out:
    if (mapping != MAP_FAILED)
        munmap(mapping, 3 * page);
    return result;
}

static int gate_prelinked_unresolved_symbol_values(void)
{
    uint8_t image[512] = {0};
    Elf64_Sym *symbols = (Elf64_Sym *)(image + 64);
    char *strings = (char *)(image + 128);
    uint64_t *slot = (uint64_t *)(image + 256);
    Elf64_Phdr load = {0};
    struct loaded_obj object = {0};
    Elf64_Rela relocation = {0};

    load.p_type = PT_LOAD;
    load.p_flags = PF_R | PF_W;
    load.p_filesz = sizeof(image);
    load.p_memsz = sizeof(image);
    object.base = (uintptr_t)image;
    object.dynsym = symbols;
    object.dynsym_count = 2;
    object.dynstr = strings;
    object.dynstr_size = 64;
    object.phdr = &load;
    object.phdr_num = 1;
    memcpy(strings, "\0dlfreeze_gate_unresolved_weak\0", 32);
    symbols[1].st_name = 1;
    symbols[1].st_info = ELF64_ST_INFO(STB_WEAK, STT_FUNC);
    symbols[1].st_shndx = SHN_UNDEF;
    relocation.r_offset = 256;

    /* Final version/scope resolution can invalidate the prelinker's
     * provisional name-only binding.  Unresolved weak GOT/PLT and ABS
     * relocations must overwrite that value with native S=0 semantics. */
    *slot = UINT64_C(0xfeedface);
    relocation.r_info = ELF64_R_INFO(1, ARCH_RELOC_GLOB_DAT);
    if (apply_prelinked_runtime_reloc(
            &object, &object, 1, &relocation,
            RELOC_PASS_ORDINARY) < 0 || *slot != 0)
        return 0;
    *slot = UINT64_C(0xfeedface);
    relocation.r_info = ELF64_R_INFO(1, ARCH_RELOC_JUMP_SLOT);
    if (apply_prelinked_runtime_reloc(
            &object, &object, 1, &relocation,
            RELOC_PASS_ORDINARY) < 0 || *slot != 0)
        return 0;
    *slot = UINT64_C(0xfeedface);
    relocation.r_info = ELF64_R_INFO(1, ARCH_RELOC_ABS);
    relocation.r_addend = 0x123;
    if (apply_prelinked_runtime_reloc(
            &object, &object, 1, &relocation,
            RELOC_PASS_ORDINARY) < 0 || *slot != 0x123)
        return 0;

    /* STN_UNDEF is still a real relocation operand: GLOB_DAT/JUMP_SLOT
     * write zero and ABS writes its addend.  Never retain input slot bytes. */
    *slot = UINT64_C(0xfeedface);
    relocation.r_info = ELF64_R_INFO(0, ARCH_RELOC_GLOB_DAT);
    relocation.r_addend = 0;
    if (apply_prelinked_runtime_reloc(
            &object, &object, 1, &relocation,
            RELOC_PASS_ORDINARY) < 0 || *slot != 0)
        return 0;
    *slot = UINT64_C(0xfeedface);
    relocation.r_info = ELF64_R_INFO(0, ARCH_RELOC_JUMP_SLOT);
    if (apply_prelinked_runtime_reloc(
            &object, &object, 1, &relocation,
            RELOC_PASS_ORDINARY) < 0 || *slot != 0)
        return 0;
    *slot = UINT64_C(0xfeedface);
    relocation.r_info = ELF64_R_INFO(0, ARCH_RELOC_ABS);
    relocation.r_addend = 0x345;
    if (apply_prelinked_runtime_reloc(
            &object, &object, 1, &relocation,
            RELOC_PASS_ORDINARY) < 0 || *slot != 0x345)
        return 0;
    return 1;
}

static int gate_prelinked_zero_fill_relative(void)
{
    uint8_t image[512] = {0};
    Elf64_Phdr load = {0};
    struct loaded_obj object = {0};
    Elf64_Rela relocation = {0};
    uint64_t *file_slot = (uint64_t *)(image + 192);
    uint64_t *zero_fill_slot = (uint64_t *)(image + 320);

    load.p_type = PT_LOAD;
    load.p_flags = PF_R | PF_W;
    load.p_filesz = 256;
    load.p_memsz = sizeof(image);
    object.base = (uintptr_t)image;
    object.phdr = &load;
    object.phdr_num = 1;
    relocation.r_info = ELF64_R_INFO(0, ARCH_RELOC_RELATIVE);

    relocation.r_offset = 192;
    if (prelinked_relocation_requires_runtime_fixup(
            &object, &relocation) != 0)
        return 0;

    relocation.r_offset = 320;
    if (prelinked_relocation_requires_runtime_fixup(
            &object, &relocation) != 1)
        return 0;
    *zero_fill_slot = UINT64_C(0xfeedface);
    relocation.r_addend = 0x123;
    if (apply_prelinked_runtime_reloc(
            &object, &object, 1, &relocation,
            RELOC_PASS_ORDINARY) < 0 ||
        *zero_fill_slot != (uint64_t)(uintptr_t)image + 0x123)
        return 0;

    return *file_slot == 0;
}

static int gate_unaligned_scalar_relocations(void)
{
    uint8_t image[512] = {0};
    Elf64_Phdr load = {0};
    struct loaded_obj object = {0};
    Elf64_Rela relocation = {0};
    uint64_t first;
    uint64_t second;
    const uint64_t expected = (uint64_t)(uintptr_t)image + 0x123;

    load.p_type = PT_LOAD;
    load.p_flags = PF_R | PF_W;
    load.p_filesz = sizeof(image);
    load.p_memsz = sizeof(image);
    object.base = (uintptr_t)image;
    object.phdr = &load;
    object.phdr_num = 1;
    relocation.r_offset = 257;
    relocation.r_info = ELF64_R_INFO(0, ARCH_RELOC_RELATIVE);
    relocation.r_addend = 0x123;

    if (apply_relocs_rela(&object, &relocation, 1, &object, 1,
                          RELOC_PASS_ORDINARY) < 0)
        return 0;
    memcpy(&first, image + 257, sizeof(first));
    if (first != expected)
        return 0;

    memset(image + 257, 0, sizeof(uint64_t));
    if (apply_prelinked_runtime_reloc(
            &object, &object, 1, &relocation,
            RELOC_PASS_ORDINARY) < 0)
        return 0;
    memcpy(&first, image + 257, sizeof(first));
    if (first != expected)
        return 0;

    relocation_store_u64_pair(
        image + 257, UINT64_C(0x1122334455667788),
        UINT64_C(0x99aabbccddeeff00));
    memcpy(&first, image + 257, sizeof(first));
    memcpy(&second, image + 257 + sizeof(first), sizeof(second));
    return first == UINT64_C(0x1122334455667788) &&
           second == UINT64_C(0x99aabbccddeeff00);
}

static int gate_control_table_alignment(void)
{
    _Alignas(16) uint8_t image[512] = {0};
    Elf64_Phdr phdr[2] = {{0}};
    struct dlfrz_lib_meta meta = {0};
    struct loaded_obj object = {0};
    struct sysv_hash_view sysv_view;
    struct gnu_hash_view gnu_view;
    Elf64_Dyn *dynamic = (Elf64_Dyn *)(image + 128);
    Elf64_Rela rela = {0};
    Elf64_Relr relr = 0;
    uint32_t sysv_hash[] = {1, 1, STN_UNDEF, STN_UNDEF};
    uint32_t gnu_hash[] = {1, 1, 1, 5};
    uint16_t versym;

    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R | PF_W;
    phdr[0].p_filesz = sizeof(image);
    phdr[0].p_memsz = sizeof(image);
    object.base = (uintptr_t)image;
    object.phdr = phdr;
    object.phdr_num = 1;

    memcpy(image + 1, sysv_hash, sizeof(sysv_hash));
    object.sysv_hash = (const uint32_t *)(const void *)(image + 1);
    if (get_sysv_hash_view(&object, &sysv_view))
        return 0;

    memcpy(image + 4, gnu_hash, sizeof(gnu_hash));
    object.gnu_hash = (const uint32_t *)(const void *)(image + 4);
    if (get_gnu_hash_view(&object, &gnu_view))
        return 0;

    object.dynsym = (const Elf64_Sym *)(const void *)(image + 1);
    object.dynsym_count = 1;
    if (loaded_dynsym(&object, 0))
        return 0;
    object.versym = (const uint16_t *)(const void *)(image + 1);
    if (loaded_versym_value(&object, 0, &versym))
        return 0;

    object.verdef = (const Elf64_Verdef *)(const void *)(image + 1);
    object.verdef_count = 1;
    if (build_loaded_version_index(&object) == 0)
        return 0;
    object.verdef = NULL;
    object.verdef_count = 0;
    object.verneed = (const Elf64_Verneed *)(const void *)(image + 1);
    object.verneed_count = 1;
    if (build_loaded_version_index(&object) == 0)
        return 0;

    memset(&object, 0, sizeof(object));
    object.base = (uintptr_t)image;
    object.phdr = (const Elf64_Phdr *)(const void *)(image + 1);
    object.phdr_num = 1;
    if (parse_dynamic(&object, &meta) == 0)
        return 0;

    /* PT_DYNAMIC and each typed table it names are ABI control records.
     * Unlike relocation destinations, their natural alignment is required
     * by the ELF64 ABI and malformed late-loaded objects must be refused
     * before a typed dereference. */
    memset(&object, 0, sizeof(object));
    phdr[1].p_type = PT_DYNAMIC;
    phdr[1].p_vaddr = 1;
    phdr[1].p_filesz = sizeof(Elf64_Dyn);
    phdr[1].p_memsz = sizeof(Elf64_Dyn);
    object.base = (uintptr_t)image;
    object.phdr = phdr;
    object.phdr_num = 2;
    if (parse_dynamic(&object, &meta) == 0)
        return 0;

    phdr[1].p_vaddr = 128;
    phdr[1].p_filesz = 4 * sizeof(Elf64_Dyn);
    phdr[1].p_memsz = phdr[1].p_filesz;
    memset(dynamic, 0, 4 * sizeof(*dynamic));
    dynamic[0].d_tag = DT_RELA;
    dynamic[0].d_un.d_ptr = 257;
    dynamic[1].d_tag = DT_RELASZ;
    dynamic[1].d_un.d_val = sizeof(rela);
    dynamic[2].d_tag = DT_RELAENT;
    dynamic[2].d_un.d_val = sizeof(rela);
    rela.r_info = ELF64_R_INFO(0, ARCH_RELOC_RELATIVE);
    memcpy(image + 257, &rela, sizeof(rela));
    memset(&object, 0, sizeof(object));
    object.base = (uintptr_t)image;
    object.phdr = phdr;
    object.phdr_num = 2;
    if (parse_dynamic(&object, &meta) == 0)
        return 0;

    memset(dynamic, 0, 4 * sizeof(*dynamic));
    dynamic[0].d_tag = 36; /* DT_RELR */
    dynamic[0].d_un.d_ptr = 257;
    dynamic[1].d_tag = 35; /* DT_RELRSZ */
    dynamic[1].d_un.d_val = sizeof(relr);
    dynamic[2].d_tag = 37; /* DT_RELRENT */
    dynamic[2].d_un.d_val = sizeof(relr);
    memcpy(image + 257, &relr, sizeof(relr));
    memset(&object, 0, sizeof(object));
    object.base = (uintptr_t)image;
    object.phdr = phdr;
    object.phdr_num = 2;
    if (parse_dynamic(&object, &meta) == 0)
        return 0;

    memset(dynamic, 0, 4 * sizeof(*dynamic));
    dynamic[0].d_tag = DT_INIT_ARRAY;
    dynamic[0].d_un.d_ptr = 257;
    dynamic[1].d_tag = DT_INIT_ARRAYSZ;
    dynamic[1].d_un.d_val = sizeof(void *);
    memset(&object, 0, sizeof(object));
    object.base = (uintptr_t)image;
    object.phdr = phdr;
    object.phdr_num = 2;
    return parse_dynamic(&object, &meta) < 0;
}

static int gate_gnu_hash_chain_stays_file_backed(void)
{
    _Alignas(8) uint8_t image[64] = {0};
    Elf64_Phdr load = {0};
    struct loaded_obj object = {0};
    uint32_t *header = (uint32_t *)(void *)image;
    uint64_t *bloom = (uint64_t *)(void *)(image + 16);
    uint32_t *bucket = (uint32_t *)(void *)(image + 24);
    uint32_t *chain = (uint32_t *)(void *)(image + 28);

    header[0] = 1;
    header[1] = 1;
    header[2] = 1;
    header[3] = 5;
    bloom[0] = UINT64_MAX;
    bucket[0] = 1;
    chain[0] = UINT32_C(0x12345678); /* file-backed, nonterminating */
    chain[1] = UINT32_C(1);          /* mapped zero-fill, terminator */

    load.p_type = PT_LOAD;
    load.p_flags = PF_R | PF_W;
    load.p_vaddr = 0;
    load.p_filesz = 32; /* ends immediately after chain[0] */
    load.p_memsz = sizeof(image);
    object.base = (uintptr_t)image;
    object.phdr = &load;
    object.phdr_num = 1;
    object.gnu_hash = header;

    if (!loaded_obj_contains(&object, (uintptr_t)&chain[1],
                             sizeof(chain[1])) ||
        loaded_obj_file_contains(&object, (uintptr_t)&chain[1],
                                 sizeof(chain[1])))
        return 0;
    return gnu_hash_symbol_count_loaded(&object) == 0;
}

static int gate_origin_token_grammars(void)
{
    struct loaded_obj object = {0};
    char expanded[PATH_MAX];
    int absolute;
    static const char musl_prefix[] = "$ORIGINsuffix";
    static const char repeated[] = "$ORIGIN$ORIGIN";
    static const char gnu_slash[] = "$ORIGIN/subdir";

    object.name = "/tmp/dlfreeze-origin/main";
    if (dl_expand_search_component(
            musl_prefix, sizeof(musl_prefix) - 1,
            DL_SEARCH_MUSL_RPATH, &object,
            expanded, sizeof(expanded), &absolute) != 0 ||
        strcmp(expanded, "/tmp/dlfreeze-originsuffix") != 0)
        return 0;
    if (dl_expand_search_component(
            repeated, sizeof(repeated) - 1,
            DL_SEARCH_MUSL_RPATH, &object,
            expanded, sizeof(expanded), &absolute) != 0 ||
        strcmp(expanded,
               "/tmp/dlfreeze-origin/tmp/dlfreeze-origin") != 0)
        return 0;
    if (dl_expand_search_component(
            musl_prefix, sizeof(musl_prefix) - 1,
            DL_SEARCH_GNU_ELF, &object,
            expanded, sizeof(expanded), &absolute) >= 0)
        return 0;
    if (dl_expand_search_component(
            gnu_slash, sizeof(gnu_slash) - 1,
            DL_SEARCH_GNU_ELF, &object,
            expanded, sizeof(expanded), &absolute) != 0)
        return 0;
    return strcmp(expanded, "/tmp/dlfreeze-origin/subdir") == 0;
}

static int gate_system_preload_policy(void)
{
    char path[] = "/tmp/dlfreeze-system-preload-gate.XXXXXX";
    static const char whitespace[] = " \t\r\n\v\f";
    static const char entry[] = "/tmp/libdlfreeze-preload-gate.so\n";
    int fd = mkstemp(path);
    int result = 0;

    if (fd < 0)
        return 0;
    if (write(fd, whitespace, sizeof(whitespace) - 1) !=
            (ssize_t)(sizeof(whitespace) - 1) ||
        close(fd) != 0 || glibc_system_preload_state(path) != 0)
        goto out;
    fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0 || write(fd, entry, sizeof(entry) - 1) !=
            (ssize_t)(sizeof(entry) - 1) ||
        close(fd) != 0 || glibc_system_preload_state(path) != 1)
        goto out;
    fd = -1;
    if (unlink(path) != 0 || glibc_system_preload_state(path) != 0)
        return 0;
    return 1;

out:
    if (fd >= 0)
        close(fd);
    unlink(path);
    return result;
}

static int gate_gnu_unique_registry(void)
{
    const unsigned char hash_key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    const size_t symbol_count = GNU_UNIQUE_REGISTRY_MAX + 3;
    const size_t symbol_bytes = symbol_count * sizeof(Elf64_Sym);
    const size_t string_bytes = symbol_count * 32;
    const size_t image_size = symbol_bytes + string_bytes;
    uint8_t *image = MAP_FAILED;
    Elf64_Sym *symbols;
    char *strings;
    size_t string_used = 1;
    Elf64_Phdr load = {0};
    struct loaded_obj *owner = &g_all_objs[0];
    const Elf64_Sym *symbol;
    int result = 0;

    if (vfs_seed_hash_key(hash_key) < 0)
        return 0;
    image = mmap(NULL, image_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (image == MAP_FAILED)
        return 0;
    symbols = (Elf64_Sym *)image;
    strings = (char *)(image + symbol_bytes);
    strings[0] = '\0';
    memset(g_all_objs, 0, 2 * sizeof(g_all_objs[0]));
    load.p_type = PT_LOAD;
    load.p_flags = PF_R | PF_W;
    load.p_filesz = image_size;
    load.p_memsz = image_size;
    owner->base = (uintptr_t)image;
    owner->dynsym = symbols;
    owner->dynsym_count = (uint32_t)symbol_count;
    owner->dynstr = strings;
    owner->dynstr_size = string_bytes;
    owner->phdr = &load;
    owner->phdr_num = 1;
    owner->visible = 1;
    for (size_t i = 1; i < symbol_count; i++) {
        int written = snprintf(strings + string_used,
                               string_bytes - string_used,
                               "dlfreeze_unique_gate_%zu", i);

        if (written <= 0 ||
            (size_t)written >= string_bytes - string_used)
            goto out;
        symbols[i].st_name = (uint32_t)string_used;
        symbols[i].st_info = ELF64_ST_INFO(STB_GNU_UNIQUE, STT_OBJECT);
        symbols[i].st_shndx = 1;
        symbols[i].st_value = 1;
        symbols[i].st_size = 1;
        string_used += (size_t)written + 1;
    }

    g_nobj = 1;
    g_is_musl_runtime = 0;
    memset(&g_dl_transaction, 0, sizeof(g_dl_transaction));
    gnu_unique_registry_reset();
    for (size_t i = 1; i <= GNU_UNIQUE_REGISTRY_MAX; i++) {
        struct loaded_obj *selected_owner = owner;

        symbol = &symbols[i];
        if (gnu_unique_canonicalize(
                g_all_objs, g_nobj, strings + symbol->st_name,
                owner, symbol, NULL, NULL, &selected_owner, &symbol) < 0 ||
            selected_owner != owner || symbol != &symbols[i])
            goto out;
    }
    {
        struct loaded_obj *selected_owner = owner;

        symbol = &symbols[GNU_UNIQUE_REGISTRY_MAX + 1];
        if (gnu_unique_canonicalize(
                g_all_objs, g_nobj, strings + symbol->st_name,
                owner, symbol, NULL, NULL, &selected_owner, &symbol) >= 0)
            goto out;
    }

    /* A rollback removes the exhausted transaction tail and leaves no
     * dangling canonical owner. */
    if (!gnu_unique_registry_rewind(0) || g_gnu_unique_count != 0)
        goto out;
    {
        struct loaded_obj *selected_owner = owner;

        symbol = &symbols[GNU_UNIQUE_REGISTRY_MAX + 1];
        if (gnu_unique_canonicalize(
                g_all_objs, g_nobj, strings + symbol->st_name,
                owner, symbol, NULL, NULL, &selected_owner, &symbol) < 0 ||
            selected_owner != owner ||
            symbol != &symbols[GNU_UNIQUE_REGISTRY_MAX + 1])
            goto out;
    }

    /* musl does not publish binding-10 definitions outside normal lookup
     * scope, and therefore must not consume registry capacity. */
    gnu_unique_registry_reset();
    g_is_musl_runtime = 1;
    {
        struct loaded_obj *selected_owner = owner;

        symbol = &symbols[1];
        if (gnu_unique_canonicalize(
                g_all_objs, g_nobj, strings + symbol->st_name,
                owner, symbol, NULL, NULL, &selected_owner, &symbol) != 0 ||
            selected_owner != owner || symbol != &symbols[1] ||
            g_gnu_unique_count != 0)
            goto out;
    }
    result = 1;

out:
    gnu_unique_registry_reset();
    g_nobj = 0;
    munmap(image, image_size);
    return result;
}

int main(void)
{
    enum { IMAGE_SIZE = 512, SECTION_STRIDE = sizeof(Elf64_Shdr) + 8 };
    uint8_t image[IMAGE_SIZE] = {0};
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)image;
    const size_t section_offset = sizeof(*ehdr);
    const size_t string_offset = section_offset + 4 * SECTION_STRIDE;
    const size_t symbol_offset = string_offset + 32;
    Elf64_Shdr strtab = {0};
    Elf64_Shdr symtab = {0};
    Elf64_Shdr data_section = {0};
    Elf64_Sym symbols[2] = {{0}};
    Elf64_Phdr load = {0};
    struct loaded_obj object = {0};
    const char strings[] = "\0stride_symbol\0";
    const uint64_t base = UINT64_C(0x100000);
    uint8_t fake_rtld_global;
    uint8_t fake_rtld_global_ro;
    struct {
        char *environment[1];
        Elf64_auxv_t auxiliary[2];
    } initial_stack = {0};
    uint64_t page_size = 0;
    Elf64_Phdr property_phdr[2] = {{0}};
    uint8_t property_note[32] = {0};
    Elf64_Nhdr property_header = {4, 16, NT_GNU_PROPERTY_TYPE_0};
    uint32_t property_type;
    uint32_t property_size = 4;
    uint32_t property_value = 1;
    uint8_t service_image[1024] = {0};
    Elf64_Sym *service_symbols = (Elf64_Sym *)(service_image + 64);
    char *service_strings = (char *)(service_image + 192);
    uint16_t *service_versions = (uint16_t *)(service_image + 256);
    uint32_t *service_sysv_hash = (uint32_t *)(service_image + 320);
    uint32_t *service_gnu_hash = (uint32_t *)(service_image + 384);
    Elf64_Phdr service_load = {0};
    struct loaded_obj service_object = {0};
    enum libc_function_resolution service_resolution;
    void *service_address;
    const uint8_t *service_code = NULL;
    size_t service_code_length = 0;

    memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
    ehdr->e_ident[EI_CLASS] = ELFCLASS64;
    ehdr->e_shoff = section_offset;
    ehdr->e_shentsize = SECTION_STRIDE;
    ehdr->e_shnum = 4;

    strtab.sh_type = SHT_STRTAB;
    strtab.sh_offset = string_offset;
    strtab.sh_size = sizeof(strings);
    memcpy(image + section_offset + SECTION_STRIDE, &strtab, sizeof(strtab));

    symtab.sh_type = SHT_SYMTAB;
    symtab.sh_offset = symbol_offset;
    symtab.sh_size = sizeof(symbols);
    symtab.sh_link = 1;
    symtab.sh_entsize = sizeof(Elf64_Sym);
    memcpy(image + section_offset + 2 * SECTION_STRIDE,
           &symtab, sizeof(symtab));

    data_section.sh_flags = SHF_ALLOC;
    data_section.sh_addr = 0;
    data_section.sh_size = UINT64_C(0x10000);
    memcpy(image + section_offset + 3 * SECTION_STRIDE,
           &data_section, sizeof(data_section));

    symbols[1].st_name = 1;
    symbols[1].st_info = ELF64_ST_INFO(STB_LOCAL, STT_OBJECT);
    symbols[1].st_shndx = 3;
    symbols[1].st_value = UINT64_C(0x2345);
    symbols[1].st_size = sizeof(uint64_t);
    memcpy(image + string_offset, strings, sizeof(strings));
    memcpy(image + symbol_offset, symbols, sizeof(symbols));

    object.base = base;
    object.elf = image;
    object.elf_size = sizeof(image);
    load.p_type = PT_LOAD;
    load.p_flags = PF_R;
    load.p_memsz = UINT64_C(0x10000);
    load.p_filesz = load.p_memsz;
    object.phdr = &load;
    object.phdr_num = 1;
    {
        uintptr_t address = 0;

        if (lookup_exact_elf_object_addr(
                &object, "stride_symbol", sizeof(uint64_t), &address) != 1 ||
            address != base + symbols[1].st_value)
            return 1;
    }

    /* A full table must report failure instead of probing forever. */
    for (size_t i = 0; i < SPECIAL_TAB_SIZE; i++)
        g_special_tab[i].used = 1;
    if (special_table_insert("overflow", &object) != -1)
        return 2;

    /* Exercise the maximum compile-time population, including VFS entries. */
    memset(g_special_tab, 0, sizeof(g_special_tab));
    g_vfs_count = 1;
    g_fake_rtld_global = &fake_rtld_global;
    g_fake_rtld_global_ro = &fake_rtld_global_ro;
    if (build_special_table() < 0)
        return 3;
    for (const struct stub_sym *entry = g_overrides; entry->name; entry++) {
        if (!lookup_special(entry->name, gnu_hash_calc(entry->name)))
            return 4;
    }
    for (const struct stub_sym *entry = g_vfs_overrides; entry->name; entry++) {
        if (!lookup_special(entry->name, gnu_hash_calc(entry->name)))
            return 5;
    }
    for (const struct stub_sym *entry = g_stubs; entry->name; entry++) {
        if (!lookup_special(entry->name, gnu_hash_calc(entry->name)))
            return 6;
    }
    initial_stack.auxiliary[0].a_type = AT_PAGESZ;
    initial_stack.auxiliary[0].a_un.a_val = 4096;
    initial_stack.auxiliary[1].a_type = AT_NULL;
    if (!direct_page_size_from_auxv(initial_stack.environment, &page_size) ||
        page_size != 4096)
        return 7;
    initial_stack.auxiliary[0].a_un.a_val = 65536;
    if (!direct_page_size_from_auxv(initial_stack.environment, &page_size) ||
        page_size != 65536)
        return 8;
    initial_stack.auxiliary[0].a_un.a_val = 12288;
    if (direct_page_size_from_auxv(initial_stack.environment, &page_size))
        return 9;
    initial_stack.auxiliary[0].a_type = AT_NULL;
    if (direct_page_size_from_auxv(initial_stack.environment, &page_size))
        return 10;

    memcpy(property_note, &property_header, sizeof(property_header));
    memcpy(property_note + sizeof(property_header), "GNU\0", 4);
#if defined(__x86_64__)
    property_type = GNU_PROPERTY_X86_FEATURE_1_AND;
#else
    property_type = GNU_PROPERTY_AARCH64_FEATURE_1_AND;
#endif
    memcpy(property_note + 16, &property_type, sizeof(property_type));
    memcpy(property_note + 20, &property_size, sizeof(property_size));
    memcpy(property_note + 24, &property_value, sizeof(property_value));
    memcpy(image + 256, property_note, sizeof(property_note));
    property_phdr[0].p_type = PT_LOAD;
    property_phdr[0].p_flags = PF_R;
    property_phdr[0].p_filesz = sizeof(image);
    property_phdr[0].p_memsz = sizeof(image);
    property_phdr[1].p_type = PT_GNU_PROPERTY;
    property_phdr[1].p_vaddr = 256;
    property_phdr[1].p_filesz = sizeof(property_note);
    property_phdr[1].p_memsz = sizeof(property_note);
    object.base = (uintptr_t)image;
    object.elf = image;
    object.elf_size = sizeof(image);
    object.phdr = property_phdr;
    object.phdr_num = 2;
    if (parse_loaded_gnu_properties(&object) != 0 ||
        !object.gnu_property_feature_1_seen ||
        object.gnu_property_feature_1 != property_value)
        return 11;
    property_value = UINT32_C(0x80000000);
    memcpy(image + 256 + 24, &property_value, sizeof(property_value));
    if (parse_loaded_gnu_properties(&object) == 0)
        return 12;
    property_value = 0;
    property_type = UINT32_C(0xc1234567);
    memcpy(image + 256 + 16, &property_type, sizeof(property_type));
    memcpy(image + 256 + 24, &property_value, sizeof(property_value));
    if (parse_loaded_gnu_properties(&object) == 0)
        return 13;

    /* Loader-private libc calls must come from the selected provider, name a
     * default ordinary function, and fit wholly in one executable PT_LOAD. */
    service_load.p_type = PT_LOAD;
    service_load.p_flags = PF_R | PF_X;
    service_load.p_filesz = sizeof(service_image);
    service_load.p_memsz = sizeof(service_image);
    service_object.base = (uintptr_t)service_image;
    service_object.dynsym = service_symbols;
    service_object.dynsym_count = 2;
    service_object.dynstr = service_strings;
    service_object.dynstr_size = 32;
    service_object.phdr = &service_load;
    service_object.phdr_num = 1;
    memcpy(service_strings, "\0required_service\0other\0", 25);
    service_symbols[1].st_name = 1;
    service_symbols[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    service_symbols[1].st_shndx = 1;
    service_symbols[1].st_value = 512;
    service_symbols[1].st_size = 16;

    service_address = vfs_libc_function_resolve(
        NULL, "required_service", NULL, &service_resolution);
    if (service_address ||
        service_resolution != LIBC_FUNCTION_PROVIDER_ABSENT)
        return 14;
    service_address = vfs_libc_function_resolve(
        &service_object, "required_service", NULL, &service_resolution);
    if (service_address != service_image + 512 ||
        service_resolution != LIBC_FUNCTION_RESOLVED)
        return 15;
    if (musl_defined_function_addr(
            &service_object, "required_service") !=
            (uintptr_t)(service_image + 512) ||
        !musl_defined_function_view(
            &service_object, "required_service", 1, 64,
            &service_code, &service_code_length) ||
        service_code != service_image + 512 || service_code_length != 16 ||
        !glibc_target_function_view(
            &service_object, "required_service", 1, 64,
            &service_code, &service_code_length) ||
        service_code != service_image + 512 || service_code_length != 16)
        return 16;
    service_symbols[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);
    if (vfs_libc_function_resolve(
            &service_object, "required_service", NULL,
            &service_resolution) ||
        service_resolution != LIBC_FUNCTION_WRONG_TYPE_OR_VERSION)
        return 17;
    service_symbols[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    service_versions[1] = UINT16_C(0x8002);
    service_object.versym = service_versions;
    if (vfs_libc_function_resolve(
            &service_object, "required_service", NULL,
            &service_resolution) ||
        service_resolution != LIBC_FUNCTION_SYMBOL_ABSENT)
        return 18;
    service_object.versym = NULL;
    service_load.p_flags = PF_R;
    if (vfs_libc_function_resolve(
            &service_object, "required_service", NULL,
            &service_resolution) ||
        service_resolution != LIBC_FUNCTION_OUTSIDE_EXECUTABLE_LOAD)
        return 19;
    service_load.p_flags = PF_R | PF_X;
    service_load.p_filesz = 512;
    if (vfs_libc_function_resolve(
            &service_object, "required_service", NULL,
            &service_resolution) ||
        service_resolution != LIBC_FUNCTION_OUTSIDE_EXECUTABLE_LOAD)
        return 20;
    service_load.p_filesz = sizeof(service_image);
    if (vfs_libc_function_resolve(
            &service_object, "missing_service", NULL,
            &service_resolution) ||
        service_resolution != LIBC_FUNCTION_SYMBOL_ABSENT)
        return 21;

    /* Private service pointers and layout witnesses must never depend on
     * hash-table order when an object publishes multiple default definitions
     * for the same name.  Equal values do not make duplicate symbol records
     * unambiguous: their metadata and versions may still differ. */
    service_symbols[2] = service_symbols[1];
    service_symbols[2].st_value = 544;
    service_object.dynsym_count = 3;
    if (vfs_libc_function_resolve(
            &service_object, "required_service", NULL,
            &service_resolution) ||
        service_resolution != LIBC_FUNCTION_WRONG_TYPE_OR_VERSION ||
        musl_defined_function_addr(
            &service_object, "required_service") != 0 ||
        musl_defined_function_view(
            &service_object, "required_service", 1, 64,
            &service_code, &service_code_length) ||
        glibc_target_function_view(
            &service_object, "required_service", 1, 64,
            &service_code, &service_code_length))
        return 22;
    service_symbols[2].st_value = service_symbols[1].st_value;
    if (vfs_libc_function_resolve(
            &service_object, "required_service", NULL,
            &service_resolution) ||
        service_resolution != LIBC_FUNCTION_WRONG_TYPE_OR_VERSION ||
        musl_defined_function_addr(
            &service_object, "required_service") != 0 ||
        musl_defined_function_view(
            &service_object, "required_service", 1, 64,
            &service_code, &service_code_length) ||
        glibc_target_function_view(
            &service_object, "required_service", 1, 64,
            &service_code, &service_code_length))
        return 23;

    /* An alias is a fallback only when the primary name is absent.  It must
     * never turn malformed/ambiguous primary metadata into an accepted
     * loader-private call target. */
    service_symbols[3] = service_symbols[1];
    service_symbols[3].st_name = 18;
    service_symbols[3].st_value = 576;
    service_object.dynsym_count = 4;
    if (vfs_libc_function_resolve(
            &service_object, "required_service", "other",
            &service_resolution) ||
        service_resolution != LIBC_FUNCTION_WRONG_TYPE_OR_VERSION)
        return 24;
    service_object.dynsym_count = 3;

    /* A hidden compatibility definition may coexist with one public default
     * definition.  Both GNU and SysV hashes must agree with the full-table
     * selection whenever the object publishes both tables. */
    service_symbols[2].st_value = 544;
    service_versions[1] = UINT16_C(0x8002);
    service_versions[2] = 2;
    service_object.versym = service_versions;
    service_address = vfs_libc_function_resolve(
        &service_object, "required_service", NULL, &service_resolution);
    if (service_address != service_image + 544 ||
        service_resolution != LIBC_FUNCTION_RESOLVED ||
        musl_defined_function_addr(
            &service_object, "required_service") !=
            (uintptr_t)(service_image + 544))
        return 25;
    {
        uint32_t gnu_hash = gnu_hash_calc("required_service");
        uint64_t *bloom = (uint64_t *)(service_gnu_hash + 4);
        uint32_t *buckets = (uint32_t *)(bloom + 1);
        uint32_t *chains = buckets + 1;

        service_gnu_hash[0] = 1;
        service_gnu_hash[1] = 1;
        service_gnu_hash[2] = 1;
        service_gnu_hash[3] = 5;
        bloom[0] = (UINT64_C(1) << (gnu_hash % 64)) |
                   (UINT64_C(1) << ((gnu_hash >> 5) % 64));
        buckets[0] = 1;
        chains[0] = gnu_hash & ~UINT32_C(1);
        chains[1] = gnu_hash | UINT32_C(1);

        service_sysv_hash[0] = 1;
        service_sysv_hash[1] = 3;
        service_sysv_hash[2] = 1;
        service_sysv_hash[3] = 0;
        service_sysv_hash[4] = 2;
        service_sysv_hash[5] = 0;
        service_object.gnu_hash = service_gnu_hash;
        service_object.sysv_hash = service_sysv_hash;
    }
    service_address = vfs_libc_function_resolve(
        &service_object, "required_service", NULL, &service_resolution);
    if (service_address != service_image + 544 ||
        service_resolution != LIBC_FUNCTION_RESOLVED)
        return 26;
    service_sysv_hash[4] = 0;
    if (vfs_libc_function_resolve(
            &service_object, "required_service", NULL,
            &service_resolution) ||
        service_resolution != LIBC_FUNCTION_WRONG_TYPE_OR_VERSION ||
        musl_defined_function_addr(
            &service_object, "required_service") != 0)
        return 27;
    service_object.gnu_hash = NULL;
    service_object.sysv_hash = NULL;
    service_object.versym = NULL;
    service_object.dynsym_count = 2;

    /* A PT_LOAD ending inside its embedded ELF's final page must not mmap
     * through the container into the following payload entry. */
    if (!gate_map_embedded_elf_eof())
        return 28;
    if (!gate_partial_relro_page())
        return 29;
    if (!gate_prelinked_unresolved_symbol_values())
        return 30;
    if (!gate_prelinked_zero_fill_relative())
        return 31;
    if (!gate_unaligned_scalar_relocations())
        return 32;
    if (!gate_control_table_alignment())
        return 33;
    if (!gate_gnu_hash_chain_stays_file_backed())
        return 38;
    if (!gate_origin_token_grammars())
        return 39;
    if (!gate_system_preload_policy())
        return 34;

    /* glibc's four-argument backend receives a unique process-lifetime
     * loader token.  musl retains its public three-argument ABI. */
    g_target_pthread_atfork = gate_pthread_atfork;
    g_target_register_atfork = gate_register_atfork;
    g_is_musl_runtime = 0;
    if (runtime_target_atfork_register(NULL, NULL, NULL) != 0 ||
        gate_register_atfork_calls != 1 || gate_pthread_atfork_calls != 0 ||
        gate_register_atfork_token != &g_runtime_atfork_token)
        return 35;
    g_is_musl_runtime = 1;
    if (runtime_target_atfork_register(NULL, NULL, NULL) != 0 ||
        gate_register_atfork_calls != 1 || gate_pthread_atfork_calls != 1)
        return 36;
    if (!gate_gnu_unique_registry())
        return 37;
    return 0;
}
