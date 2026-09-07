/* Exercise relocation binding reuse and phase filtering in the real loader
 * translation unit. */
#include <stdint.h>

#define DLFREEZE_SYMBOL_LOOKUP_COMPLEXITY_GATE 1
#include "../src/loader.c"

static char requester_strings[] = "\0hot\0";
static char provider_strings[] = "\0hot\0";
static Elf64_Sym requester_symbols[2];
static Elf64_Sym provider_symbols[2];
static uint16_t requester_versions[2];

enum { MANY_SCOPE_SYMBOLS = 33, MANY_SCOPE_STRINGS = 512 };
static char many_scope_strings[MANY_SCOPE_STRINGS];
static Elf64_Sym many_requester_symbols[MANY_SCOPE_SYMBOLS];
static Elf64_Sym many_provider_symbols[MANY_SCOPE_SYMBOLS];

struct gnu_hash_fixture {
    uint32_t header[4];
    uint64_t bloom;
    uint32_t bucket;
    uint32_t chain;
};

struct sysv_hash_fixture {
    uint32_t header[2];
    uint32_t bucket;
    uint32_t chains[2];
};

static void initialize_symbol_scope(void)
{
    memset(g_all_objs, 0, 2 * sizeof(g_all_objs[0]));
    memset(requester_symbols, 0, sizeof(requester_symbols));
    memset(provider_symbols, 0, sizeof(provider_symbols));
    memset(&g_dl_transaction, 0, sizeof(g_dl_transaction));

    requester_symbols[1].st_name = 1;
    requester_symbols[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    requester_symbols[1].st_other = STV_DEFAULT;
    requester_symbols[1].st_shndx = SHN_UNDEF;

    provider_symbols[1].st_name = 1;
    provider_symbols[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    provider_symbols[1].st_other = STV_DEFAULT;
    provider_symbols[1].st_shndx = 1;

    g_all_objs[0].name = "requester";
    g_all_objs[0].dynstr = requester_strings;
    g_all_objs[0].dynstr_size = sizeof(requester_strings);
    g_all_objs[0].dynsym = requester_symbols;
    g_all_objs[0].dynsym_count = 2;
    g_all_objs[0].dynsym_admitted_count = 2;
    g_all_objs[0].dynstr_readonly = 1;
    g_all_objs[0].dynsym_readonly = 1;
    g_all_objs[0].visible = 1;
    g_all_objs[0].lookup_scope_valid = 1;
    g_all_objs[0].lookup_scope_count = 2;
    g_all_objs[0].lookup_scope_indices[0] = 0;
    g_all_objs[0].lookup_scope_indices[1] = 1;
    g_all_objs[0].relocation_scope_root = 0;
    g_all_objs[0].relocation_scope_root_valid = 1;

    g_all_objs[1].name = "provider";
    g_all_objs[1].dynstr = provider_strings;
    g_all_objs[1].dynstr_size = sizeof(provider_strings);
    g_all_objs[1].dynsym = provider_symbols;
    g_all_objs[1].dynsym_count = 2;
    g_all_objs[1].dynsym_admitted_count = 2;
    g_all_objs[1].dynstr_readonly = 1;
    g_all_objs[1].dynsym_readonly = 1;
    g_all_objs[1].visible = 1;
    g_all_objs[1].lookup_scope_valid = 1;
    g_all_objs[1].lookup_scope_count = 1;
    g_all_objs[1].lookup_scope_indices[0] = 1;
    g_all_objs[1].relocation_scope_root = 1;
    g_all_objs[1].relocation_scope_root_valid = 1;

    g_global_scope_count = 2;
    g_global_scope_indices[0] = 0;
    g_global_scope_indices[1] = 1;
    g_nobj = 2;
    g_is_musl_runtime = 0;
    g_vfs_hash_key_ready = 1;
    g_special_tab_ready = 0;
    clear_resolution_caches();
}

static void reset_cache_counters(void)
{
    g_relocation_definition_cache_hits = 0;
    g_relocation_definition_cache_stores = 0;
    g_relocation_definition_scope_scans = 0;
    g_relocation_ifunc_cache_hits = 0;
}

static int immutable_binding_cache_gate(void)
{
    struct loaded_obj *owner = NULL;
    const Elf64_Sym *definition;

    initialize_symbol_scope();
    reset_cache_counters();
    definition = lookup_relocation_definition(
        &g_all_objs[0], 1, g_all_objs, 2, 0, &owner);
    if (definition != &provider_symbols[1] || owner != &g_all_objs[1] ||
        g_relocation_definition_cache_stores != 1 ||
        g_relocation_definition_cache_hits != 0 ||
        g_relocation_definition_scope_scans != 1)
        return 0;
    for (unsigned int i = 0; i < 32; i++) {
        owner = NULL;
        definition = lookup_relocation_definition(
            &g_all_objs[0], 1, g_all_objs, 2, 0, &owner);
        if (definition != &provider_symbols[1] || owner != &g_all_objs[1])
            return 0;
    }
    if (g_relocation_definition_cache_stores != 1 ||
        g_relocation_definition_cache_hits != 32 ||
        g_relocation_definition_scope_scans != 1)
        return 0;

    if (relocation_symbol_is_ifunc(
            &g_all_objs[0], 1, g_all_objs, 2) ||
        relocation_symbol_is_ifunc(
            &g_all_objs[0], 1, g_all_objs, 2) ||
        g_relocation_ifunc_cache_hits != 1)
        return 0;
    return 1;
}

static int many_binding_scope_proof_gate(void)
{
    struct loaded_obj *owner;
    size_t string_end = 1;

    initialize_symbol_scope();
    memset(many_scope_strings, 0, sizeof(many_scope_strings));
    memset(many_requester_symbols, 0, sizeof(many_requester_symbols));
    memset(many_provider_symbols, 0, sizeof(many_provider_symbols));
    for (uint32_t i = 1; i < MANY_SCOPE_SYMBOLS; i++) {
        int length = snprintf(
            many_scope_strings + string_end,
            sizeof(many_scope_strings) - string_end, "scope_%u", i);

        if (length <= 0 ||
            (size_t)length >= sizeof(many_scope_strings) - string_end)
            return 0;
        many_requester_symbols[i].st_name = (uint32_t)string_end;
        many_requester_symbols[i].st_info =
            ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
        many_requester_symbols[i].st_other = STV_DEFAULT;
        many_requester_symbols[i].st_shndx = SHN_UNDEF;
        many_provider_symbols[i].st_name = (uint32_t)string_end;
        many_provider_symbols[i].st_info =
            ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
        many_provider_symbols[i].st_other = STV_DEFAULT;
        many_provider_symbols[i].st_shndx = 1;
        string_end += (size_t)length + 1;
    }
    g_all_objs[0].dynstr = many_scope_strings;
    g_all_objs[0].dynstr_size = string_end;
    g_all_objs[0].dynsym = many_requester_symbols;
    g_all_objs[0].dynsym_count = MANY_SCOPE_SYMBOLS;
    g_all_objs[0].dynsym_admitted_count = MANY_SCOPE_SYMBOLS;
    g_all_objs[1].dynstr = many_scope_strings;
    g_all_objs[1].dynstr_size = string_end;
    g_all_objs[1].dynsym = many_provider_symbols;
    g_all_objs[1].dynsym_count = MANY_SCOPE_SYMBOLS;
    g_all_objs[1].dynsym_admitted_count = MANY_SCOPE_SYMBOLS;
    reset_cache_counters();

    for (uint32_t i = 1; i < MANY_SCOPE_SYMBOLS; i++) {
        const Elf64_Sym *definition;

        owner = NULL;
        definition = lookup_relocation_definition(
            &g_all_objs[0], i, g_all_objs, 2, 0, &owner);
        if (definition != &many_provider_symbols[i] ||
            owner != &g_all_objs[1])
            return 0;
    }
    return g_relocation_definition_cache_stores ==
            MANY_SCOPE_SYMBOLS - 1 &&
        g_relocation_definition_cache_hits == 0 &&
        g_relocation_definition_scope_scans == 1;
}

static int cache_mode_and_epoch_gate(void)
{
    struct loaded_obj *owner = NULL;
    const Elf64_Sym *definition;

    initialize_symbol_scope();
    requester_symbols[1].st_shndx = 1;
    reset_cache_counters();

    definition = lookup_relocation_definition(
        &g_all_objs[0], 1, g_all_objs, 2, 0, &owner);
    if (definition != &requester_symbols[1] || owner != &g_all_objs[0])
        return 0;
    definition = lookup_relocation_definition(
        &g_all_objs[0], 1, g_all_objs, 2, 1, &owner);
    if (definition != &provider_symbols[1] || owner != &g_all_objs[1] ||
        g_relocation_definition_cache_stores != 2 ||
        g_relocation_definition_scope_scans != 1)
        return 0;

    /* A scope epoch change must discard both lookup modes. */
    clear_resolution_caches();
    g_global_scope_indices[0] = 1;
    g_global_scope_indices[1] = 0;
    owner = NULL;
    definition = lookup_relocation_definition(
        &g_all_objs[0], 1, g_all_objs, 2, 0, &owner);
    return definition == &provider_symbols[1] && owner == &g_all_objs[1] &&
        g_relocation_definition_scope_scans == 2;
}

static int mutable_and_unique_bypass_gate(void)
{
    struct loaded_obj *owner = NULL;
    const Elf64_Sym *definition;

    initialize_symbol_scope();
    g_all_objs[1].dynstr_readonly = 0;
    reset_cache_counters();
    definition = lookup_relocation_definition(
        &g_all_objs[0], 1, g_all_objs, 2, 0, &owner);
    if (definition != &provider_symbols[1] || owner != &g_all_objs[1])
        return 0;
    definition = lookup_relocation_definition(
        &g_all_objs[0], 1, g_all_objs, 2, 0, &owner);
    if (definition != &provider_symbols[1] ||
        g_relocation_definition_cache_stores != 0 ||
        g_relocation_definition_cache_hits != 0 ||
        g_relocation_definition_scope_scans != 1)
        return 0;
    if (relocation_symbol_is_ifunc(
            &g_all_objs[0], 1, g_all_objs, 2))
        return 0;
    provider_symbols[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_GNU_IFUNC);
    if (!relocation_symbol_is_ifunc(
            &g_all_objs[0], 1, g_all_objs, 2) ||
        g_relocation_definition_scope_scans != 1)
        return 0;

    initialize_symbol_scope();
    reset_cache_counters();
    provider_symbols[1].st_info = ELF64_ST_INFO(STB_GNU_UNIQUE, STT_OBJECT);
    relocation_definition_cache_store(
        &g_all_objs[0], 1, g_all_objs, 2, 0,
        &g_all_objs[1], &provider_symbols[1]);
    return g_relocation_definition_cache_stores == 0;
}

static int scope_immutability_key_gate(void)
{
    initialize_symbol_scope();
    reset_cache_counters();
    if (!relocation_definition_cache_scope_immutable(
            &g_all_objs[0], g_all_objs, 2) ||
        !relocation_definition_cache_scope_immutable(
            &g_all_objs[0], g_all_objs, 2) ||
        g_relocation_definition_scope_scans != 1)
        return 0;

    /* A root change without an epoch bump is not expected in production,
     * but it must still miss the defensive key. */
    g_all_objs[0].relocation_scope_root = 1;
    if (!relocation_definition_cache_scope_immutable(
            &g_all_objs[0], g_all_objs, 2) ||
        g_relocation_definition_scope_scans != 2)
        return 0;

    /* Likewise, a transaction-time object count cannot inherit a proof for
     * the previous table extent. */
    g_global_scope_count = 1;
    g_global_scope_indices[0] = 0;
    g_all_objs[0].relocation_scope_root = 0;
    g_all_objs[0].lookup_scope_count = 1;
    if (!relocation_definition_cache_scope_immutable(
            &g_all_objs[0], g_all_objs, 1) ||
        g_relocation_definition_scope_scans != 3)
        return 0;

    /* Exercise the generation-wrap clearing path: epoch 1 must not be able
     * to observe a stale epoch-1 scope proof after uint32_t rollover. */
    g_relocation_scope_immutability[0].epoch = 1;
    g_relocation_scope_immutability[0].state =
        RELOCATION_SCOPE_MUTABLE;
    g_cache_epoch = UINT32_MAX;
    clear_resolution_caches();
    if (g_cache_epoch != 1 ||
        g_relocation_scope_immutability[0].state !=
            RELOCATION_SCOPE_IMMUTABILITY_UNKNOWN ||
        !relocation_definition_cache_scope_immutable(
            &g_all_objs[0], g_all_objs, 1) ||
        g_relocation_definition_scope_scans != 4)
        return 0;
    return 1;
}

static int mutable_lookup_metadata_bypass_gate(void)
{
    struct loaded_obj *owner = NULL;
    const Elf64_Sym *definition;
    Elf64_Phdr hash_phdr;
    struct gnu_hash_fixture gnu;
    struct sysv_hash_fixture sysv;
    uint32_t hash;

    /* The requester symbol itself is part of the cache key's authority. */
    initialize_symbol_scope();
    g_all_objs[0].dynsym_readonly = 0;
    reset_cache_counters();
    definition = lookup_relocation_definition(
        &g_all_objs[0], 1, g_all_objs, 2, 0, &owner);
    if (definition != &provider_symbols[1] || owner != &g_all_objs[1])
        return 0;
    requester_symbols[1].st_name = 0;
    owner = NULL;
    if (lookup_relocation_definition(
            &g_all_objs[0], 1, g_all_objs, 2, 0, &owner) != NULL || owner ||
        g_relocation_definition_cache_stores != 0 ||
        g_relocation_definition_cache_hits != 0)
        return 0;

    /* A writable provider DYNSYM must likewise remain live. */
    initialize_symbol_scope();
    g_all_objs[1].dynsym_readonly = 0;
    reset_cache_counters();
    definition = lookup_relocation_definition(
        &g_all_objs[0], 1, g_all_objs, 2, 0, &owner);
    if (definition != &provider_symbols[1] || owner != &g_all_objs[1])
        return 0;
    provider_symbols[1].st_shndx = SHN_UNDEF;
    owner = NULL;
    if (lookup_relocation_definition(
            &g_all_objs[0], 1, g_all_objs, 2, 0, &owner) != NULL || owner ||
        g_relocation_definition_cache_stores != 0 ||
        g_relocation_definition_cache_hits != 0)
        return 0;

    /* Mutable VERSYM can turn a valid unversioned request into malformed
     * version metadata between two lookups. */
    initialize_symbol_scope();
    memset(requester_versions, 0, sizeof(requester_versions));
    requester_versions[1] = VER_NDX_GLOBAL;
    g_all_objs[0].versym = requester_versions;
    g_all_objs[0].versym_admitted_count = 2;
    g_all_objs[0].versym_readonly = 0;
    reset_cache_counters();
    definition = lookup_relocation_definition(
        &g_all_objs[0], 1, g_all_objs, 2, 0, &owner);
    if (definition != &provider_symbols[1] || owner != &g_all_objs[1])
        return 0;
    requester_versions[1] = 2;
    owner = NULL;
    if (lookup_relocation_definition(
            &g_all_objs[0], 1, g_all_objs, 2, 0, &owner) != NULL || owner ||
        g_relocation_definition_cache_stores != 0 ||
        g_relocation_definition_cache_hits != 0)
        return 0;

    /* Exercise current-byte GNU hash lookup through a PF_W table. */
    initialize_symbol_scope();
    memset(&gnu, 0, sizeof(gnu));
    memset(&hash_phdr, 0, sizeof(hash_phdr));
    hash = gnu_hash_calc("hot");
    gnu.header[0] = 1;
    gnu.header[1] = 1;
    gnu.header[2] = 1;
    gnu.header[3] = 5;
    gnu.bloom = (UINT64_C(1) << (hash % 64)) |
                (UINT64_C(1) << ((hash >> gnu.header[3]) % 64));
    gnu.bucket = 1;
    gnu.chain = hash | 1;
    hash_phdr.p_type = PT_LOAD;
    hash_phdr.p_flags = PF_R | PF_W;
    hash_phdr.p_filesz = sizeof(gnu);
    hash_phdr.p_memsz = sizeof(gnu);
    g_all_objs[1].base = (uint64_t)(uintptr_t)&gnu;
    g_all_objs[1].phdr = &hash_phdr;
    g_all_objs[1].phdr_num = 1;
    g_all_objs[1].gnu_hash = (const uint32_t *)(const void *)&gnu;
    reset_cache_counters();
    definition = lookup_relocation_definition(
        &g_all_objs[0], 1, g_all_objs, 2, 0, &owner);
    if (definition != &provider_symbols[1] || owner != &g_all_objs[1])
        return 0;
    gnu.bucket = STN_UNDEF;
    owner = NULL;
    if (lookup_relocation_definition(
            &g_all_objs[0], 1, g_all_objs, 2, 0, &owner) != NULL || owner ||
        g_relocation_definition_cache_stores != 0 ||
        g_relocation_definition_cache_hits != 0)
        return 0;

    /* SysV hash selection has the same live-table contract. */
    initialize_symbol_scope();
    memset(&sysv, 0, sizeof(sysv));
    memset(&hash_phdr, 0, sizeof(hash_phdr));
    sysv.header[0] = 1;
    sysv.header[1] = 2;
    sysv.bucket = 1;
    hash_phdr.p_type = PT_LOAD;
    hash_phdr.p_flags = PF_R | PF_W;
    hash_phdr.p_filesz = sizeof(sysv);
    hash_phdr.p_memsz = sizeof(sysv);
    g_all_objs[1].base = (uint64_t)(uintptr_t)&sysv;
    g_all_objs[1].phdr = &hash_phdr;
    g_all_objs[1].phdr_num = 1;
    g_all_objs[1].sysv_hash = (const uint32_t *)(const void *)&sysv;
    reset_cache_counters();
    definition = lookup_relocation_definition(
        &g_all_objs[0], 1, g_all_objs, 2, 0, &owner);
    if (definition != &provider_symbols[1] || owner != &g_all_objs[1])
        return 0;
    sysv.bucket = STN_UNDEF;
    owner = NULL;
    return lookup_relocation_definition(
               &g_all_objs[0], 1, g_all_objs, 2, 0, &owner) == NULL &&
        owner == NULL && g_relocation_definition_cache_stores == 0 &&
        g_relocation_definition_cache_hits == 0;
}

static int cache_load_bound_gate(void)
{
    struct relocation_definition_cache_ent *entry;

    initialize_symbol_scope();
    for (uint32_t symbol_index = 0;
         symbol_index < RELOCATION_DEFINITION_CACHE_MAX_ENTRIES;
         symbol_index++) {
        entry = relocation_definition_cache_entry(
            0, symbol_index, 2, 0, 1);
        if (!entry)
            return 0;
    }
    if (g_relocation_definition_cache_entries !=
            RELOCATION_DEFINITION_CACHE_MAX_ENTRIES ||
        relocation_definition_cache_entry(
            0, RELOCATION_DEFINITION_CACHE_MAX_ENTRIES, 2, 0, 1) != NULL ||
        relocation_definition_cache_entry(0, 0, 2, 0, 0) == NULL)
        return 0;

    clear_resolution_caches();
    return g_relocation_definition_cache_entries == 0 &&
        relocation_definition_cache_entry(0, 0, 2, 0, 1) != NULL &&
        g_relocation_definition_cache_entries == 1;
}

static int cache_collision_gate(void)
{
    enum { COLLISION_COUNT = 64, SEARCH_LIMIT = 4 * 1024 * 1024 };
    uint32_t symbols[COLLISION_COUNT];
    uint32_t target_bucket;
    size_t found = 0;

    initialize_symbol_scope();
    target_bucket = relocation_definition_cache_hash(0, 0, 2, 0) &
        (RELOCATION_DEFINITION_CACHE_SIZE - 1);
    for (uint32_t symbol = 0;
         symbol < SEARCH_LIMIT && found < COLLISION_COUNT; symbol++) {
        if ((relocation_definition_cache_hash(0, symbol, 2, 0) &
             (RELOCATION_DEFINITION_CACHE_SIZE - 1)) == target_bucket)
            symbols[found++] = symbol;
    }
    if (found != COLLISION_COUNT)
        return 0;
    for (size_t i = 0; i < found; i++) {
        struct relocation_definition_cache_ent *entry =
            relocation_definition_cache_entry(0, symbols[i], 2, 0, 1);

        if (!entry || entry->reference_symbol_index != symbols[i])
            return 0;
    }
    if (g_relocation_definition_cache_entries != COLLISION_COUNT)
        return 0;
    for (size_t i = found; i != 0; i--) {
        const struct relocation_definition_cache_ent *entry =
            relocation_definition_cache_entry(
                0, symbols[i - 1], 2, 0, 0);

        if (!entry || entry->reference_symbol_index != symbols[i - 1])
            return 0;
    }
    return relocation_definition_cache_entry(
               0, SEARCH_LIMIT, 2, 0, 0) == NULL;
}

static size_t phase_ifunc_calls;

static uint64_t phase_ifunc_resolver(void)
{
    phase_ifunc_calls++;
    return UINT64_C(0x1020304050607080);
}

static int run_all_relocation_phases(struct loaded_obj *obj,
                                     struct loaded_obj *all, int nobj,
                                     Elf64_Rela *relocation, int prelinked)
{
    int result = 1;

    g_relocation_validation_calls = 0;
    if (!prelinked) {
        obj->rela = relocation;
        obj->rela_count = 1;
    }
    for (int phase = RELOC_PASS_ORDINARY;
         phase <= RELOC_PASS_IRELATIVE; phase++) {
        int status = prelinked
            ? apply_prelinked_runtime_reloc(
                  obj, all, nobj, relocation,
                  (enum relocation_pass)phase)
            : apply_relocs_rela(
                  obj, LOADED_RELA_DYNAMIC, all, nobj,
                  (enum relocation_pass)phase);

        if (status < 0)
            result = 0;
    }
    if (!prelinked) {
        obj->rela = NULL;
        obj->rela_count = 0;
    }
    return result && g_relocation_validation_calls == 1;
}

static int symbolic_relocation_phase_gate(void)
{
    long page_size_long = sysconf(_SC_PAGESIZE);
    uint8_t *mapping;
    Elf64_Phdr requester_phdr = {0};
    Elf64_Phdr provider_phdr = {0};
    Elf64_Rela relocation = {0};
    uint64_t source = UINT64_C(0xa1b2c3d4e5f60718);
    uintptr_t resolver = (uintptr_t)(void *)&phase_ifunc_resolver;
    uintptr_t resolver_page;
    int valid = 0;

    if (page_size_long <= 0 || (uintmax_t)page_size_long > SIZE_MAX)
        return 0;
    mapping = mmap(NULL, (size_t)page_size_long,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return 0;

    initialize_symbol_scope();
    requester_phdr.p_type = PT_LOAD;
    requester_phdr.p_flags = PF_R | PF_W;
    requester_phdr.p_filesz = (uint64_t)page_size_long;
    requester_phdr.p_memsz = (uint64_t)page_size_long;
    g_all_objs[0].base = (uint64_t)(uintptr_t)mapping;
    g_all_objs[0].phdr = &requester_phdr;
    g_all_objs[0].phdr_num = 1;

    /* A normal symbolic relocation belongs only to the ordinary pass. */
    provider_phdr.p_type = PT_LOAD;
    provider_phdr.p_flags = PF_R;
    provider_phdr.p_filesz = sizeof(source);
    provider_phdr.p_memsz = sizeof(source);
    g_all_objs[1].base = (uint64_t)(uintptr_t)&source;
    g_all_objs[1].phdr = &provider_phdr;
    g_all_objs[1].phdr_num = 1;
    provider_symbols[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);
    provider_symbols[1].st_value = 0;
    provider_symbols[1].st_size = sizeof(source);
    relocation.r_offset = 128;
    relocation.r_info = ELF64_R_INFO(1, ARCH_RELOC_GLOB_DAT);
    if (!run_all_relocation_phases(
            &g_all_objs[0], g_all_objs, 2, &relocation, 1) ||
        relocation_load_u64(mapping + relocation.r_offset) !=
            (uint64_t)(uintptr_t)&source)
        goto out;

    relocation_store_u64(mapping + relocation.r_offset, 0);
    if (!run_all_relocation_phases(
            &g_all_objs[0], g_all_objs, 2, &relocation, 0) ||
        relocation_load_u64(mapping + relocation.r_offset) !=
            (uint64_t)(uintptr_t)&source)
        goto out;

    /* COPY uses its requester-skipping definition and only the COPY pass. */
    clear_resolution_caches();
    requester_symbols[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);
    requester_symbols[1].st_shndx = 1;
    requester_symbols[1].st_size = sizeof(source);
    relocation_store_u64(mapping + relocation.r_offset, 0);
    relocation.r_info = ELF64_R_INFO(1, ARCH_RELOC_COPY);
    if (!run_all_relocation_phases(
            &g_all_objs[0], g_all_objs, 2, &relocation, 1) ||
        relocation_load_u64(mapping + relocation.r_offset) != source)
        goto out;

    /* An ELF IFUNC is skipped by ordinary/COPY and consumed only by IFUNC. */
    clear_resolution_caches();
    requester_symbols[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    requester_symbols[1].st_shndx = SHN_UNDEF;
    requester_symbols[1].st_size = 0;
    resolver_page = resolver - resolver % (uintptr_t)page_size_long;
    provider_phdr.p_flags = PF_R | PF_X;
    provider_phdr.p_filesz = (uint64_t)page_size_long;
    provider_phdr.p_memsz = (uint64_t)page_size_long;
    g_all_objs[1].base = resolver_page;
    provider_symbols[1].st_info =
        ELF64_ST_INFO(STB_GLOBAL, STT_GNU_IFUNC);
    provider_symbols[1].st_value = resolver - resolver_page;
    provider_symbols[1].st_size = 1;
    relocation_store_u64(mapping + relocation.r_offset, 0);
    relocation.r_info = ELF64_R_INFO(1, ARCH_RELOC_GLOB_DAT);
    phase_ifunc_calls = 0;
    if (!run_all_relocation_phases(
            &g_all_objs[0], g_all_objs, 2, &relocation, 1) ||
        phase_ifunc_calls != 1 ||
        relocation_load_u64(mapping + relocation.r_offset) !=
            UINT64_C(0x1020304050607080))
        goto out;
    relocation_store_u64(mapping + relocation.r_offset, 0);
    if (!run_all_relocation_phases(
            &g_all_objs[0], g_all_objs, 2, &relocation, 0) ||
        phase_ifunc_calls != 2 ||
        relocation_load_u64(mapping + relocation.r_offset) !=
            UINT64_C(0x1020304050607080))
        goto out;
    valid = 1;

out:
    munmap(mapping, (size_t)page_size_long);
    return valid;
}

/* An immutable definition-cache entry proves that IFUNC phase membership
 * cannot change between graph-wide passes.  Writable requester metadata has
 * no such proof: retain live validation before a phase skip so an earlier
 * relocation cannot make a deferred record silently disappear. */
static int mutable_phase_filter_fail_closed_gate(void)
{
    long page_size_long = sysconf(_SC_PAGESIZE);
    uint8_t *mapping;
    Elf64_Phdr requester_phdr = {0};
    Elf64_Phdr provider_phdr = {0};
    Elf64_Rela relocation = {0};
    uintptr_t resolver = (uintptr_t)(void *)&phase_ifunc_resolver;
    uintptr_t resolver_page;
    int valid = 0;

    if (page_size_long <= 0 || (uintmax_t)page_size_long > SIZE_MAX)
        return 0;
    mapping = mmap(NULL, (size_t)page_size_long,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return 0;
    resolver_page = resolver - resolver % (uintptr_t)page_size_long;

    requester_phdr.p_type = PT_LOAD;
    requester_phdr.p_flags = PF_R | PF_W;
    requester_phdr.p_filesz = (uint64_t)page_size_long;
    requester_phdr.p_memsz = (uint64_t)page_size_long;
    provider_phdr.p_type = PT_LOAD;
    provider_phdr.p_flags = PF_R | PF_X;
    provider_phdr.p_filesz = (uint64_t)page_size_long;
    provider_phdr.p_memsz = (uint64_t)page_size_long;
    relocation.r_offset = 128;
    relocation.r_info = ELF64_R_INFO(1, ARCH_RELOC_GLOB_DAT);

    for (int prelinked = 0; prelinked <= 1; prelinked++) {
        int status;

        initialize_symbol_scope();
        g_all_objs[0].base = (uint64_t)(uintptr_t)mapping;
        g_all_objs[0].phdr = &requester_phdr;
        g_all_objs[0].phdr_num = 1;
        /* This is the production signal which suppresses definition-cache
         * publication for writable requester metadata. */
        g_all_objs[0].dynsym_readonly = 0;
        g_all_objs[1].base = resolver_page;
        g_all_objs[1].phdr = &provider_phdr;
        g_all_objs[1].phdr_num = 1;
        provider_symbols[1].st_info =
            ELF64_ST_INFO(STB_GLOBAL, STT_GNU_IFUNC);
        provider_symbols[1].st_value = resolver - resolver_page;
        provider_symbols[1].st_size = 1;
        relocation_store_u64(mapping + relocation.r_offset, 0);
        phase_ifunc_calls = 0;
        g_relocation_validation_calls = 0;

        if (!prelinked) {
            g_all_objs[0].rela = &relocation;
            g_all_objs[0].rela_count = 1;
            status = apply_relocs_rela(
                &g_all_objs[0], LOADED_RELA_DYNAMIC, g_all_objs, 2,
                RELOC_PASS_ORDINARY);
        } else {
            status = apply_prelinked_runtime_reloc(
                &g_all_objs[0], g_all_objs, 2, &relocation,
                RELOC_PASS_ORDINARY);
        }
        if (status < 0 || g_relocation_validation_calls != 1 ||
            phase_ifunc_calls != 0)
            goto out;

        /* Model an admitted ordinary relocation into the requester's
         * PF_W-backed DYNSYM.  IFUNC classification now fails, but the
         * deferred record still has to fail its live structural proof. */
        requester_symbols[1].st_name = sizeof(requester_strings);
        if (!prelinked) {
            status = apply_relocs_rela(
                &g_all_objs[0], LOADED_RELA_DYNAMIC, g_all_objs, 2,
                RELOC_PASS_IFUNC);
            g_all_objs[0].rela = NULL;
            g_all_objs[0].rela_count = 0;
        } else {
            status = apply_prelinked_runtime_reloc(
                &g_all_objs[0], g_all_objs, 2, &relocation,
                RELOC_PASS_IFUNC);
        }
        if (status >= 0 || g_relocation_validation_calls != 2 ||
            phase_ifunc_calls != 0 ||
            relocation_load_u64(mapping + relocation.r_offset) != 0)
            goto out;
    }
    valid = 1;

out:
    munmap(mapping, (size_t)page_size_long);
    return valid;
}

/* GNU-unique replay has the same fail-closed requirement, but no immutable
 * classification cache.  In particular, a promoted dormant relocation may
 * be admitted and deferred during the ordinary pass before writable version
 * metadata is changed by an earlier relocation. */
static int mutable_gnu_unique_phase_filter_fail_closed_gate(void)
{
    long page_size_long = sysconf(_SC_PAGESIZE);
    uint8_t *mapping;
    Elf64_Phdr requester_phdr = {0};
    Elf64_Phdr provider_phdr = {0};
    Elf64_Rela relocation = {0};
    uint64_t source = UINT64_C(0x1122334455667788);
    int status;
    int valid = 0;

    if (page_size_long <= 0 || (uintmax_t)page_size_long > SIZE_MAX)
        return 0;
    mapping = mmap(NULL, (size_t)page_size_long,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return 0;

    initialize_symbol_scope();
    gnu_unique_registry_reset();
    requester_phdr.p_type = PT_LOAD;
    requester_phdr.p_flags = PF_R | PF_W;
    requester_phdr.p_filesz = (uint64_t)page_size_long;
    requester_phdr.p_memsz = (uint64_t)page_size_long;
    g_all_objs[0].base = (uint64_t)(uintptr_t)mapping;
    g_all_objs[0].phdr = &requester_phdr;
    g_all_objs[0].phdr_num = 1;
    g_all_objs[0].visible = 0;
    g_all_objs[0].flags |= LDR_FLAG_DLOPEN_EARLY;
    memset(requester_versions, 0, sizeof(requester_versions));
    requester_versions[1] = VER_NDX_GLOBAL;
    g_all_objs[0].versym = requester_versions;
    g_all_objs[0].versym_admitted_count = 2;
    g_all_objs[0].versym_readonly = 0;

    provider_phdr.p_type = PT_LOAD;
    provider_phdr.p_flags = PF_R;
    provider_phdr.p_filesz = sizeof(source);
    provider_phdr.p_memsz = sizeof(source);
    g_all_objs[1].base = (uint64_t)(uintptr_t)&source;
    g_all_objs[1].phdr = &provider_phdr;
    g_all_objs[1].phdr_num = 1;
    provider_symbols[1].st_info =
        ELF64_ST_INFO(STB_GNU_UNIQUE, STT_OBJECT);
    provider_symbols[1].st_value = 0;
    provider_symbols[1].st_size = sizeof(source);

    relocation.r_offset = 128;
    relocation.r_info = ELF64_R_INFO(1, ARCH_RELOC_GLOB_DAT);
    relocation_store_u64(mapping + relocation.r_offset, 0);
    g_all_objs[0].rela = &relocation;
    g_all_objs[0].rela_count = 1;
    g_relocation_validation_calls = 0;

    status = apply_relocs_rela(
        &g_all_objs[0], LOADED_RELA_DYNAMIC, g_all_objs, 2,
        RELOC_PASS_ORDINARY);
    if (status < 0 || g_relocation_validation_calls != 1 ||
        !g_all_objs[0].deferred_gnu_unique_relocations ||
        relocation_load_u64(mapping + relocation.r_offset) != 0)
        goto out;

    /* A writable VERSYM can invalidate the live name/version query after
     * deferral.  The GNU-unique filter must validate before skipping it. */
    requester_versions[1] = 2;
    status = apply_relocs_rela(
        &g_all_objs[0], LOADED_RELA_DYNAMIC, g_all_objs, 2,
        RELOC_PASS_GNU_UNIQUE);
    if (status >= 0 || g_relocation_validation_calls != 2 ||
        relocation_load_u64(mapping + relocation.r_offset) != 0)
        goto out;
    valid = 1;

out:
    g_all_objs[0].rela = NULL;
    g_all_objs[0].rela_count = 0;
    gnu_unique_registry_reset();
    munmap(mapping, (size_t)page_size_long);
    return valid;
}

static int relocation_phase_validation_gate(void)
{
    long page_size_long = sysconf(_SC_PAGESIZE);
    uint8_t *mapping;
    Elf64_Phdr phdr = {0};
    Elf64_Rela relocation = {0};
    struct loaded_obj obj = {0};
    uint64_t expected;
    int valid = 0;

    if (page_size_long <= 0 || (uintmax_t)page_size_long > SIZE_MAX)
        return 0;
    mapping = mmap(NULL, (size_t)page_size_long,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return 0;
    phdr.p_type = PT_LOAD;
    phdr.p_flags = PF_R | PF_W;
    phdr.p_vaddr = 0;
    phdr.p_filesz = (uint64_t)page_size_long;
    phdr.p_memsz = (uint64_t)page_size_long;
    obj.name = "phase-gate";
    obj.base = (uint64_t)(uintptr_t)mapping;
    obj.phdr = &phdr;
    obj.phdr_num = 1;
    relocation.r_offset = 128;
    relocation.r_info = ELF64_R_INFO(0, ARCH_RELOC_RELATIVE);
    relocation.r_addend = 17;
    expected = obj.base + (uint64_t)relocation.r_addend;

    g_relocation_validation_calls = 0;
    for (int phase = RELOC_PASS_ORDINARY;
         phase <= RELOC_PASS_IRELATIVE; phase++) {
        if (apply_prelinked_runtime_reloc(
                &obj, &obj, 1, &relocation,
                (enum relocation_pass)phase) < 0)
            goto out;
    }
    if (g_relocation_validation_calls != 1 ||
        relocation_load_u64(mapping + relocation.r_offset) != expected)
        goto out;

    relocation_store_u64(mapping + relocation.r_offset, 0);
    obj.rela = &relocation;
    obj.rela_count = 1;
    g_relocation_validation_calls = 0;
    for (int phase = RELOC_PASS_ORDINARY;
         phase <= RELOC_PASS_IRELATIVE; phase++) {
        if (apply_relocs_rela(
                &obj, LOADED_RELA_DYNAMIC, &obj, 1,
                (enum relocation_pass)phase) < 0)
            goto out;
    }
    if (g_relocation_validation_calls != 1 ||
        relocation_load_u64(mapping + relocation.r_offset) != expected)
        goto out;
    valid = 1;

out:
    munmap(mapping, (size_t)page_size_long);
    return valid;
}

int main(void)
{
    /* These complexity-gate helpers are exercised by the broader dynamic
     * reader gate; keep their definitions live in this focused translation
     * unit so -Werror does not mistake the shared instrumentation for dead
     * production code. */
    (void)symbol_lookup_query_init_known_key;
    (void)defined_symbol_version;
    (void)needed_symbol_version;
    if (!immutable_binding_cache_gate())
        return 1;
    if (!many_binding_scope_proof_gate())
        return 2;
    if (!cache_mode_and_epoch_gate())
        return 3;
    if (!mutable_and_unique_bypass_gate())
        return 4;
    if (!mutable_lookup_metadata_bypass_gate())
        return 5;
    if (!cache_load_bound_gate())
        return 6;
    if (!cache_collision_gate())
        return 7;
    if (!scope_immutability_key_gate())
        return 8;
    if (!relocation_phase_validation_gate())
        return 9;
    if (!symbolic_relocation_phase_gate())
        return 10;
    if (!mutable_phase_filter_fail_closed_gate())
        return 11;
    if (!mutable_gnu_unique_phase_filter_fail_closed_gate())
        return 12;
    return 0;
}
