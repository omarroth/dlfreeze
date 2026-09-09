#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef PT_GNU_SFRAME
#define PT_GNU_SFRAME 0x6474e554
#endif

#define TEST_DLFO_FLAG_SFRAME (1ULL << 0)

#ifdef DLFO_FLAG_SFRAME
#define TEST_NATIVE_DLFO_HAS_SFRAME 1
#else
#define TEST_NATIVE_DLFO_HAS_SFRAME 0
#endif

enum {
    TEST_RTLD_DL_SYMENT = 1,
    TEST_RTLD_DL_LINKMAP = 2,
    TEST_RTLD_DI_LMID = 1,
    TEST_RTLD_DI_LINKMAP = 2,
    TEST_RTLD_DI_TLS_MODID = 9,
    TEST_RTLD_DI_TLS_DATA = 10,
    TEST_RTLD_DI_PHDR = 11
};

struct test_dl_find_object {
    unsigned long long flags;
    void *map_start;
    void *map_end;
    struct link_map *link_map;
    void *eh_frame;
    void *sframe;
    unsigned long long reserved[6];
};

_Static_assert(sizeof(struct test_dl_find_object) == 96,
               "LP64 dl_find_object ABI size changed");

typedef int (*value_fn)(void);
typedef int *(*tls_address_fn)(void);
typedef int (*find_object_fn)(void *, struct test_dl_find_object *);
typedef int (*dladdr1_fn)(const void *, Dl_info *, void **, int);

struct iterate_tls_state {
    const char *name;
    size_t modid;
    void *data;
    int strict;
    int matches;
    int invalid;
    ElfW(Addr) base;
    const ElfW(Phdr) *phdr;
    ElfW(Half) phnum;
};

static int inspect_module_tls(struct dl_phdr_info *info, size_t size,
                              void *opaque)
{
    struct iterate_tls_state *state = opaque;
    size_t required = offsetof(struct dl_phdr_info, dlpi_tls_data) +
                      sizeof(info->dlpi_tls_data);

    if (!info || !state || !info->dlpi_name ||
        !strstr(info->dlpi_name, state->name))
        return 0;
    state->matches++;
    state->base = info->dlpi_addr;
    state->phdr = info->dlpi_phdr;
    state->phnum = info->dlpi_phnum;
    if (state->strict &&
        (size < required || info->dlpi_tls_modid != state->modid ||
         info->dlpi_tls_data != state->data))
        state->invalid = 1;
    return 0;
}

struct iterate_main_state {
    ElfW(Addr) base;
    const char *name;
    int matches;
};

static int inspect_main_name(struct dl_phdr_info *info, size_t size,
                             void *opaque)
{
    struct iterate_main_state *state = opaque;

    (void)size;
    if (!info || !state || info->dlpi_addr != state->base)
        return 0;
    state->matches++;
    state->name = info->dlpi_name;
    return 0;
}

struct iterate_address_state {
    uintptr_t address;
    void *sframe;
    int matches;
    int invalid;
};

struct iterate_reentrant_state {
    const char *late_path;
    void *late_handle;
    size_t nested_count;
    size_t outer_count;
    int triggered;
    int invalid;
    int saw_late;
};

static int count_nested_object(struct dl_phdr_info *info, size_t size,
                               void *opaque)
{
    struct iterate_reentrant_state *state = opaque;

    if (!state || !info ||
        size < offsetof(struct dl_phdr_info, dlpi_phnum) +
                   sizeof(info->dlpi_phnum) ||
        !info->dlpi_name || !info->dlpi_phdr || info->dlpi_phnum == 0) {
        if (state)
            state->invalid = 1;
        return 0;
    }
    state->nested_count++;
    return 0;
}

static int inspect_reentrant_object(struct dl_phdr_info *info, size_t size,
                                    void *opaque)
{
    struct iterate_reentrant_state *state = opaque;

    if (!state || !info || !info->dlpi_name) {
        if (state)
            state->invalid = 1;
        return 0;
    }
    state->outer_count++;
    if (strstr(info->dlpi_name, "libloader_introspection_late.so"))
        state->saw_late++;
    if (!state->triggered) {
        state->triggered = 1;
        if (!dlsym(RTLD_DEFAULT, "puts") ||
            dl_iterate_phdr(count_nested_object, state) != 0)
            state->invalid = 1;
        state->late_handle = dlopen(state->late_path, RTLD_NOW | RTLD_LOCAL);
        if (!state->late_handle)
            state->invalid = 1;
    }
    (void)size;
    return 0;
}

static int inspect_address_object(struct dl_phdr_info *info, size_t size,
                                  void *opaque)
{
    struct iterate_address_state *state = opaque;
    int contains = 0;
    int sframe_count = 0;

    (void)size;
    if (!info || !state || !info->dlpi_phdr)
        return 0;
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        uintptr_t start;

        if (ph->p_type != PT_LOAD || ph->p_memsz == 0 ||
            ph->p_vaddr > UINTPTR_MAX - info->dlpi_addr)
            continue;
        start = (uintptr_t)info->dlpi_addr + (uintptr_t)ph->p_vaddr;
        if (state->address >= start &&
            state->address - start < ph->p_memsz)
            contains = 1;
    }
    if (!contains)
        return 0;

    state->matches++;
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];

        if (ph->p_type != PT_GNU_SFRAME ||
            (ph->p_filesz == 0 && ph->p_memsz == 0))
            continue;
        if (++sframe_count > 1 || ph->p_filesz == 0 ||
            ph->p_filesz > ph->p_memsz ||
            ph->p_vaddr > UINTPTR_MAX - info->dlpi_addr) {
            state->invalid = 1;
            continue;
        }
        state->sframe = (void *)((uintptr_t)info->dlpi_addr +
                                 (uintptr_t)ph->p_vaddr);
    }
    return 0;
}

static int load_bounds(ElfW(Addr) base, const ElfW(Phdr) *phdr,
                       ElfW(Half) phnum, uintptr_t page_size,
                       uintptr_t *start_out, uintptr_t *end_out)
{
    uint64_t low = UINT64_MAX;
    uint64_t high = 0;

    if (!phdr || phnum == 0 || page_size == 0)
        return 0;
    for (ElfW(Half) i = 0; i < phnum; i++) {
        uint64_t end;

        if (phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0 ||
            phdr[i].p_vaddr > UINT64_MAX - phdr[i].p_memsz)
            continue;
        end = phdr[i].p_vaddr + phdr[i].p_memsz;
        if (phdr[i].p_vaddr < low)
            low = phdr[i].p_vaddr;
        if (end > high)
            high = end;
    }
    if (low >= high || base > UINTPTR_MAX - high)
        return 0;
    low -= low % page_size;
    *start_out = (uintptr_t)base + (uintptr_t)low;
    *end_out = (uintptr_t)base + (uintptr_t)high;
    return 1;
}

static int load_padding_address(ElfW(Addr) base, const ElfW(Phdr) *phdr,
                                ElfW(Half) phnum, uintptr_t *address_out)
{
    uint64_t high = 0;

    if (!phdr || !address_out)
        return 0;
    for (ElfW(Half) i = 0; i < phnum; i++) {
        uint64_t end;

        if (phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0 ||
            phdr[i].p_vaddr > UINT64_MAX - phdr[i].p_memsz)
            continue;
        end = phdr[i].p_vaddr + phdr[i].p_memsz;
        if (end > high)
            high = end;
    }
    for (ElfW(Half) i = 0; i < phnum; i++) {
        uint64_t candidate;
        int covered = 0;

        if (phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0 ||
            phdr[i].p_vaddr > UINT64_MAX - phdr[i].p_memsz)
            continue;
        candidate = phdr[i].p_vaddr + phdr[i].p_memsz;
        if (candidate >= high)
            continue;
        for (ElfW(Half) j = 0; j < phnum; j++) {
            if (phdr[j].p_type != PT_LOAD || phdr[j].p_memsz == 0 ||
                candidate < phdr[j].p_vaddr)
                continue;
            if (candidate - phdr[j].p_vaddr < phdr[j].p_memsz) {
                covered = 1;
                break;
            }
        }
        if (!covered && candidate <= UINTPTR_MAX - base) {
            *address_out = (uintptr_t)base + (uintptr_t)candidate;
            return 1;
        }
    }
    return 0;
}

static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t state_changed = PTHREAD_COND_INITIALIZER;
static void *shared_handle;
static int handle_ready;
static int strict_mode;

static void *worker_main(void *unused)
{
    void *handle;
    void *before = (void *)(uintptr_t)1;
    void *after = NULL;
    void *symbol;
    tls_address_fn tls_address;
    int *tls_pointer;
    int before_status;
    int after_status;

    (void)unused;
    if (pthread_mutex_lock(&state_lock) != 0)
        return (void *)(uintptr_t)10;
    while (!handle_ready)
        if (pthread_cond_wait(&state_changed, &state_lock) != 0) {
            pthread_mutex_unlock(&state_lock);
            return (void *)(uintptr_t)11;
        }
    handle = shared_handle;
    pthread_mutex_unlock(&state_lock);
    if (!handle)
        return (void *)(uintptr_t)12;

    /* This thread existed before dlopen and has not touched the new module.
     * RTLD_DI_TLS_DATA must observe the empty DTV slot, not allocate it. */
    before_status = dlinfo(handle, TEST_RTLD_DI_TLS_DATA, &before);
    if (strict_mode && (before_status != 0 || before))
        return (void *)(uintptr_t)13;
    symbol = dlsym(handle, "loader_introspection_tls_address");
    if (!symbol)
        return (void *)(uintptr_t)14;
    memcpy(&tls_address, &symbol, sizeof(tls_address));
    tls_pointer = tls_address();
    if (!tls_pointer)
        return (void *)(uintptr_t)15;
    if (*tls_pointer != 73) {
        fprintf(stderr, "loader-introspection TLS value %d (expected 73)\n",
                *tls_pointer);
        return (void *)(uintptr_t)17;
    }
    /* Native AArch64 glibc can satisfy a TLSDESC access without publishing
     * the block through the DTV slot observed by RTLD_DI_TLS_DATA.  The
     * frozen strict run specifically verifies dlfreeze's documented DTV
     * publication and no-allocation behavior. */
    after_status = dlinfo(handle, TEST_RTLD_DI_TLS_DATA, &after);
    if (strict_mode &&
        (after_status != 0 || !after || after != (void *)tls_pointer))
        return (void *)(uintptr_t)16;
    *tls_pointer = 97;
    return NULL;
}

static int fail(int code)
{
    fprintf(stderr, "loader-introspection failure %d\n", code);
    return code;
}

int main(int argc, char **argv)
{
    pthread_t worker;
    void *handle;
    void *main_handle;
    void *symbol;
    void *thread_result = NULL;
    struct link_map *map = NULL;
    struct link_map *main_map = NULL;
    struct link_map *previous = NULL;
    const ElfW(Phdr) *phdr = NULL;
    size_t tls_modid = 0;
    tls_address_fn tls_address;
    int *main_tls_pointer;
    void *main_tls_data = NULL;
    struct iterate_tls_state iterate_tls;
    struct iterate_main_state iterate_main;
    long lmid = -1;
    int phnum;
    int saw_dynamic = 0;
    int saw_tls = 0;
    int saw_map = 0;
    int map_count = 0;
    int query_status;
    value_fn value;
    dladdr1_fn dladdr1_call = NULL;
    int target_has_glibc_api = 0;
    uintptr_t expected_map_start = 0;
    uintptr_t expected_map_end = 0;
    uintptr_t padding_address = 0;
    long page_size;
    Dl_info info;
    void *extra;
    void *sized_symbol;
    void *zero_sized_symbol;
    void *wide_symbol;
    void *short_symbol;
    void *loader_api_symbol;
    Dl_info loader_api_info;
    struct link_map *loader_interior_map = NULL;
    struct iterate_reentrant_state iterate_reentrant;

    if (argc != 4 && argc != 5)
        return fail(2);
    strict_mode = strcmp(argv[2], "strict") == 0;
    target_has_glibc_api =
        dlsym(RTLD_DEFAULT, "gnu_get_libc_version") != NULL;
    if (pthread_create(&worker, NULL, worker_main, NULL) != 0)
        return fail(3);

    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (pthread_mutex_lock(&state_lock) != 0)
        return fail(4);
    shared_handle = handle;
    handle_ready = 1;
    pthread_cond_broadcast(&state_changed);
    pthread_mutex_unlock(&state_lock);
    if (!handle) {
        pthread_join(worker, NULL);
        return fail(5);
    }
    if (pthread_join(worker, &thread_result) != 0 || thread_result)
        return fail(20 + (int)(uintptr_t)thread_result);

    query_status = dlinfo(handle, TEST_RTLD_DI_LMID, &lmid);
    if ((strict_mode && (query_status != 0 || lmid != 0)) ||
        (!strict_mode && query_status == 0 && lmid != 0))
        return fail(40);
    if (dlinfo(handle, TEST_RTLD_DI_LINKMAP, &map) != 0 || !map ||
        !map->l_name || !strstr(map->l_name,
                                "libloader_introspection_plugin.so") ||
        !map->l_ld)
        return fail(41);
    query_status = dlinfo(handle, TEST_RTLD_DI_TLS_MODID, &tls_modid);
    if (strict_mode && (query_status != 0 || tls_modid == 0))
        return fail(42);
    symbol = dlsym(handle, "loader_introspection_tls_address");
    if (!symbol)
        return fail(61);
    memcpy(&tls_address, &symbol, sizeof(tls_address));
    main_tls_pointer = tls_address();
    query_status = dlinfo(handle, TEST_RTLD_DI_TLS_DATA, &main_tls_data);
    if (!main_tls_pointer || *main_tls_pointer != 73 ||
        (strict_mode &&
         (query_status != 0 ||
          main_tls_data != (void *)main_tls_pointer)))
        return fail(62);
    memset(&iterate_tls, 0, sizeof(iterate_tls));
    iterate_tls.name = "libloader_introspection_plugin.so";
    iterate_tls.modid = tls_modid;
    iterate_tls.data = main_tls_pointer;
    iterate_tls.strict = strict_mode;
    if (dl_iterate_phdr(inspect_module_tls, &iterate_tls) != 0 ||
        iterate_tls.matches != 1 || iterate_tls.invalid)
        return fail(63);
    page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 ||
        !load_bounds(iterate_tls.base, iterate_tls.phdr,
                     iterate_tls.phnum, (uintptr_t)page_size,
                     &expected_map_start, &expected_map_end))
        return fail(64);
    if (load_padding_address(iterate_tls.base, iterate_tls.phdr,
                             iterate_tls.phnum, &padding_address)) {
        memset(&info, 0xa5, sizeof(info));
        query_status = dladdr((void *)padding_address, &info);
        if ((target_has_glibc_api &&
             (query_status != 1 || info.dli_fbase !=
                                       (void *)expected_map_start)) ||
            (!target_has_glibc_api && query_status != 0))
            return fail(65);
    }
    phnum = dlinfo(handle, TEST_RTLD_DI_PHDR, &phdr);
    /* RTLD_DI_PHDR was added in glibc 2.34.  It is mandatory for the
     * dlfreeze strict run, while an older native control may lack it. */
    if (strict_mode &&
        (phnum <= 0 || !phdr || phdr != iterate_tls.phdr ||
         (ElfW(Half))phnum != iterate_tls.phnum))
        return fail(43);
    if (phnum > 0 && phdr) {
        for (int i = 0; i < phnum; i++) {
            if (phdr[i].p_type == PT_DYNAMIC) {
                saw_dynamic = 1;
                if ((uintptr_t)map->l_addr + phdr[i].p_vaddr !=
                    (uintptr_t)map->l_ld)
                    return fail(44);
            } else if (phdr[i].p_type == PT_TLS) {
                saw_tls = 1;
            }
        }
        if (!saw_dynamic || !saw_tls)
            return fail(45);
    }

    main_handle = dlopen(NULL, RTLD_NOW);
    if (!main_handle ||
        dlinfo(main_handle, TEST_RTLD_DI_LINKMAP, &main_map) != 0 ||
        !main_map || main_map->l_prev)
        return fail(46);
    if (!main_map->l_name ||
        (target_has_glibc_api ? main_map->l_name[0] != '\0'
                              : main_map->l_name[0] == '\0'))
        return fail(66);
    memset(&iterate_main, 0, sizeof(iterate_main));
    iterate_main.base = main_map->l_addr;
    if (dl_iterate_phdr(inspect_main_name, &iterate_main) != 0 ||
        iterate_main.matches != 1 || !iterate_main.name ||
        (target_has_glibc_api ? iterate_main.name[0] != '\0'
                              : iterate_main.name[0] == '\0'))
        return fail(67);
    memset(&info, 0, sizeof(info));
    if (dladdr((void *)(uintptr_t)&main, &info) != 1 ||
        !info.dli_fname || !info.dli_fname[0] ||
        info.dli_fbase == NULL)
        return fail(68);
    loader_api_symbol = dlsym(RTLD_DEFAULT, "dlopen");
    memset(&loader_api_info, 0, sizeof(loader_api_info));
    if (!loader_api_symbol ||
        dladdr(loader_api_symbol, &loader_api_info) != 1 ||
        !loader_api_info.dli_fname || !loader_api_info.dli_fname[0] ||
        !loader_api_info.dli_fbase || !loader_api_info.dli_sname ||
        strcmp(loader_api_info.dli_sname, "dlopen") != 0 ||
        loader_api_info.dli_saddr != loader_api_symbol)
        return fail(82);
    memset(&info, 0, sizeof(info));
    if (dladdr((void *)((uintptr_t)loader_api_symbol + 1), &info) != 1 ||
        !info.dli_fname || !info.dli_fname[0] || !info.dli_fbase ||
        (strict_mode &&
         (strcmp(info.dli_fname, loader_api_info.dli_fname) == 0 ||
          info.dli_sname != NULL || info.dli_saddr != NULL)))
        return fail(87);
    for (struct link_map *cursor = main_map; cursor; cursor = cursor->l_next) {
        if (++map_count > 1024)
            return fail(47);
        if (cursor->l_prev != previous)
            return fail(48);
        if (cursor == map)
            saw_map = 1;
        previous = cursor;
        if (!cursor->l_next)
            break;
        if (previous->l_next->l_prev != previous)
            return fail(49);
    }
    if (!saw_map)
        return fail(50);
    if (strict_mode) {
        struct r_debug *debug = NULL;
        int terminated = 0;

        for (size_t i = 0; i < 4096; i++) {
            const ElfW(Dyn) *entry = &main_map->l_ld[i];

            if (entry->d_tag == DT_DEBUG) {
                if (debug)
                    return fail(59);
                debug = (struct r_debug *)(uintptr_t)entry->d_un.d_ptr;
            }
            if (entry->d_tag == DT_NULL) {
                terminated = 1;
                break;
            }
        }
        if (!terminated || !debug || debug->r_version != 1 ||
            debug->r_state != RT_CONSISTENT || !debug->r_brk ||
            debug->r_map != main_map)
            return fail(60);
    }

    memset(&iterate_reentrant, 0, sizeof(iterate_reentrant));
    iterate_reentrant.late_path = argv[3];
    if (dl_iterate_phdr(inspect_reentrant_object, &iterate_reentrant) != 0 ||
        !iterate_reentrant.triggered || iterate_reentrant.invalid ||
        !iterate_reentrant.late_handle || iterate_reentrant.saw_late != 1 ||
        iterate_reentrant.nested_count == 0 ||
        iterate_reentrant.outer_count != iterate_reentrant.nested_count + 1)
        return fail(77);
    symbol = dlsym(iterate_reentrant.late_handle,
                   "loader_introspection_value");
    if (!symbol)
        return fail(78);
    memcpy(&value, &symbol, sizeof(value));
    if (value() != 41)
        return fail(79);

    symbol = dlsym(handle, "loader_introspection_value");
    if (!symbol)
        return fail(51);
    memcpy(&value, &symbol, sizeof(value));
    if (value() != 41)
        return fail(52);
    sized_symbol = dlsym(handle, "loader_introspection_sized_symbol");
    if (!sized_symbol)
        return fail(73);
    memset(&info, 0, sizeof(info));
    if (dladdr((unsigned char *)sized_symbol + 16, &info) != 1 ||
        !info.dli_fname || info.dli_sname != NULL ||
        info.dli_saddr != NULL)
        return fail(74);
    zero_sized_symbol =
        dlsym(handle, "loader_introspection_zero_sized_symbol");
    if (!zero_sized_symbol)
        return fail(75);
    memset(&info, 0, sizeof(info));
    if (dladdr((unsigned char *)zero_sized_symbol + 1, &info) != 1 ||
        !info.dli_fname ||
        (target_has_glibc_api
             ? (info.dli_sname != NULL || info.dli_saddr != NULL)
             : (!info.dli_sname ||
                strcmp(info.dli_sname,
                       "loader_introspection_zero_sized_symbol") != 0 ||
                info.dli_saddr != zero_sized_symbol)))
        return fail(76);
    wide_symbol = dlsym(handle, "loader_introspection_wide_symbol");
    short_symbol = dlsym(handle, "loader_introspection_short_symbol");
    if (!wide_symbol || !short_symbol ||
        (uintptr_t)short_symbol - (uintptr_t)wide_symbol != 16)
        return fail(80);
    memset(&info, 0, sizeof(info));
    if (dladdr((unsigned char *)short_symbol + 2, &info) != 1 ||
        !info.dli_fname ||
        (target_has_glibc_api
             ? (!info.dli_sname ||
                strcmp(info.dli_sname,
                       "loader_introspection_wide_symbol") != 0 ||
                info.dli_saddr != wide_symbol)
             : (info.dli_sname != NULL || info.dli_saddr != NULL)))
        return fail(81);

    {
        void *dladdr1_symbol = dlsym(RTLD_DEFAULT, "dladdr1");

        if (dladdr1_symbol)
            memcpy(&dladdr1_call, &dladdr1_symbol, sizeof(dladdr1_call));
    }
    /* dladdr1 is a GNU extension and is not exported by every target libc.
     * Require it when the target itself exposes the glibc API family; the
     * direct loader must neither lose that contract nor invent it for an
     * alternate libc. */
    if (strict_mode && target_has_glibc_api && !dladdr1_call)
        return fail(53);
    if (dladdr1_call) {
        struct link_map *loader_api_map;

        memset(&info, 0, sizeof(info));
        extra = NULL;
        if (dladdr1_call(symbol, &info, &extra,
                         TEST_RTLD_DL_LINKMAP) != 1 ||
            extra != map || !info.dli_fname || !info.dli_sname ||
            strcmp(info.dli_sname, "loader_introspection_value") != 0)
            return fail(53);
        memset(&info, 0, sizeof(info));
        extra = NULL;
        if (dladdr1_call(symbol, &info, &extra, TEST_RTLD_DL_SYMENT) != 1 ||
            !extra ||
            ELF64_ST_TYPE(((const Elf64_Sym *)extra)->st_info) != STT_FUNC)
            return fail(54);
        memset(&info, 0, sizeof(info));
        extra = NULL;
        if (dladdr1_call(loader_api_symbol, &info, &extra,
                         TEST_RTLD_DL_LINKMAP) != 1 ||
            !extra || !info.dli_fname || !info.dli_sname ||
            strcmp(info.dli_sname, "dlopen") != 0 ||
            info.dli_saddr != loader_api_symbol)
            return fail(83);
        loader_api_map = (struct link_map *)extra;
        if (!loader_api_map->l_name ||
            strcmp(loader_api_map->l_name, info.dli_fname) != 0)
            return fail(83);
        memset(&info, 0, sizeof(info));
        extra = NULL;
        if (dladdr1_call(
                (void *)((uintptr_t)loader_api_symbol + 1),
                &info, &extra, TEST_RTLD_DL_LINKMAP) != 1 ||
            !extra || !info.dli_fname || !info.dli_fname[0])
            return fail(88);
        loader_interior_map = (struct link_map *)extra;
        if (!loader_interior_map->l_name ||
            strcmp(loader_interior_map->l_name, info.dli_fname) != 0 ||
            (strict_mode && loader_interior_map == loader_api_map))
            return fail(88);
        memset(&info, 0, sizeof(info));
        extra = NULL;
        if (dladdr1_call(loader_api_symbol, &info, &extra,
                         TEST_RTLD_DL_SYMENT) != 1 ||
            !extra ||
            (ELF64_ST_TYPE(((const Elf64_Sym *)extra)->st_info) != STT_FUNC &&
             ELF64_ST_TYPE(((const Elf64_Sym *)extra)->st_info) !=
                 STT_GNU_IFUNC) ||
            (strict_mode &&
             (((const Elf64_Sym *)extra)->st_shndx != SHN_ABS ||
              ((const Elf64_Sym *)extra)->st_value !=
                  (Elf64_Addr)(uintptr_t)loader_api_symbol ||
              ((const Elf64_Sym *)extra)->st_size != 0)))
            return fail(84);
    }
    {
        find_object_fn find_object = NULL;
        struct test_dl_find_object found;

        symbol = dlsym(RTLD_DEFAULT, "_dl_find_object");
        if (strict_mode && ((target_has_glibc_api && !symbol) ||
                            (!target_has_glibc_api && symbol)))
            return fail(69);
        if (symbol) {
            struct iterate_address_state puts_object;
            struct iterate_address_state loader_object;
            void *puts_address = dlsym(RTLD_DEFAULT, "puts");

            memcpy(&find_object, &symbol, sizeof(find_object));
            memset(&found, 0xa5, sizeof(found));
            if (find_object((void *)(uintptr_t)value, &found) != 0 ||
                found.link_map != map ||
                found.map_start != (void *)expected_map_start ||
                found.map_end != (void *)expected_map_end ||
                (uintptr_t)value < expected_map_start ||
                (uintptr_t)value >= expected_map_end)
                return fail(56);
            memset(&found, 0xa5, sizeof(found));
            if (find_object(
                    (void *)((uintptr_t)loader_api_symbol + 1),
                    &found) != 0 || !loader_interior_map ||
                found.link_map != loader_interior_map ||
                !found.eh_frame ||
                (uintptr_t)loader_api_symbol + 1 <
                    (uintptr_t)found.map_start ||
                (uintptr_t)loader_api_symbol + 1 >=
                    (uintptr_t)found.map_end)
                return fail(89);
            memset(&loader_object, 0, sizeof(loader_object));
            loader_object.address = (uintptr_t)loader_api_symbol + 1;
            if (dl_iterate_phdr(inspect_address_object, &loader_object) != 0 ||
                loader_object.matches != 1 || loader_object.invalid)
                return fail(90);
            if (!puts_address)
                return fail(70);
            memset(&puts_object, 0, sizeof(puts_object));
            puts_object.address = (uintptr_t)puts_address;
            if (dl_iterate_phdr(inspect_address_object, &puts_object) != 0 ||
                puts_object.matches != 1 || puts_object.invalid)
                return fail(71);
            memset(&found, 0xa5, sizeof(found));
            /* glibc added the SFrame member by consuming the first reserved
             * ABI slot.  Older native loaders leave that slot zero even when
             * their libc ELF already carries PT_GNU_SFRAME.  Require the
             * extension from a native control only when its target headers
             * expose it; dlfreeze's strict shim deliberately implements the
             * forward-compatible fixed-size ABI on every admitted glibc. */
            if (find_object(puts_address, &found) != 0 ||
                ((strict_mode || TEST_NATIVE_DLFO_HAS_SFRAME) &&
                 ((puts_object.sframe &&
                   (!(found.flags & TEST_DLFO_FLAG_SFRAME) ||
                    found.sframe != puts_object.sframe)) ||
                  (!puts_object.sframe &&
                   ((found.flags & TEST_DLFO_FLAG_SFRAME) ||
                    found.sframe)))))
                return fail(72);
        }
    }

    if (strict_mode && dladdr1_call) {
        extra = (void *)(uintptr_t)0x1234;
        memset(&info, 0xa5, sizeof(info));
        if (dladdr1_call((void *)(uintptr_t)value, &info, &extra, 0) != 0 ||
            extra != NULL || info.dli_fname != NULL ||
            info.dli_fbase != NULL || info.dli_sname != NULL ||
            info.dli_saddr != NULL)
            return fail(55);
        extra = (void *)(uintptr_t)0x5678;
        memset(&info, 0xa5, sizeof(info));
        if (dladdr1_call((void *)(uintptr_t)value, &info, &extra, 99) != 0 ||
            extra != NULL || info.dli_fname != NULL || info.dli_fbase != NULL ||
            info.dli_sname != NULL || info.dli_saddr != NULL)
            return fail(57);
    }
    if (strict_mode) {
        (void)dlerror();
        if (dlinfo(handle, 0, &extra) != -1 || dlerror() == NULL)
            return fail(58);
    }

    if (argc == 5) {
        unsigned char byte;
        Dl_info open_info;
        void *open_symbol = dlsym(RTLD_DEFAULT, "open");
        int fd = open(argv[4], O_RDONLY | O_CLOEXEC);

        if (fd < 0 || read(fd, &byte, sizeof(byte)) != 1 ||
            close(fd) != 0)
            return fail(85);
        memset(&open_info, 0, sizeof(open_info));
        if (!open_symbol || dladdr(open_symbol, &open_info) != 1 ||
            !open_info.dli_fname || !open_info.dli_fname[0] ||
            !open_info.dli_fbase || !open_info.dli_sname ||
            !open_info.dli_sname[0] || open_info.dli_saddr != open_symbol)
            return fail(86);
        printf("loader-vfs-alias:%s\n", open_info.dli_sname);
    }

    puts("loader-introspection-ok");
    return 0;
}
