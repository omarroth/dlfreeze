#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

enum { TEST_RTLD_DI_LINKMAP = 2 };

struct test_dl_find_object {
    unsigned long long flags;
    void *map_start;
    void *map_end;
    struct link_map *link_map;
    void *eh_frame;
    void *sframe;
    unsigned long long reserved[6];
};

typedef int (*value_fn)(void);
typedef int (*find_object_fn)(void *, struct test_dl_find_object *);

struct object_view {
    uintptr_t address;
    ElfW(Addr) base;
    const ElfW(Phdr) *phdr;
    ElfW(Half) phnum;
    int matches;
};

static int find_view(struct dl_phdr_info *info, size_t size, void *opaque)
{
    struct object_view *view = opaque;

    (void)size;
    if (!info || !view || !info->dlpi_phdr)
        return 0;
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        uintptr_t start;

        if (ph->p_type != PT_LOAD || ph->p_memsz == 0 ||
            ph->p_vaddr > UINTPTR_MAX - info->dlpi_addr)
            continue;
        start = (uintptr_t)info->dlpi_addr + (uintptr_t)ph->p_vaddr;
        if (view->address < start || view->address - start >= ph->p_memsz)
            continue;
        view->matches++;
        view->base = info->dlpi_addr;
        view->phdr = info->dlpi_phdr;
        view->phnum = info->dlpi_phnum;
        break;
    }
    return 0;
}

static int fail(int code)
{
    fprintf(stderr, "dladdr-layout failure %d\n", code);
    return code;
}

int main(int argc, char **argv)
{
    struct object_view view = {0};
    struct link_map *map = NULL;
    struct test_dl_find_object found;
    find_object_fn find_object = NULL;
    value_fn value;
    void *handle;
    void *symbol;
    void *find_symbol;
    uint64_t low = UINT64_MAX;
    uint64_t high = 0;
    uint64_t containing_low = UINT64_MAX;
    uint64_t containing_high = 0;
    uint64_t padding = UINT64_MAX;
    uint64_t hole = UINT64_MAX;
    uintptr_t expected_start;
    uintptr_t expected_end;
    uintptr_t page_size;
    int target_has_glibc_api;
    int expect_dladdr_aggregate;
    Dl_info info;

    if (argc != 1 && argc != 2)
        return fail(2);
    target_has_glibc_api =
        dlsym(RTLD_DEFAULT, "gnu_get_libc_version") != NULL;
    expect_dladdr_aggregate = target_has_glibc_api && argc == 2;
    handle = dlopen(argc == 1 ? NULL : argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return fail(3);
    if (argc == 1) {
        symbol = (void *)(uintptr_t)&main;
    } else {
        symbol = dlsym(handle, "loader_introspection_value");
        if (!symbol)
            return fail(4);
        memcpy(&value, &symbol, sizeof(value));
        if (value() != 41)
            return fail(5);
    }
    if (dlinfo(handle, TEST_RTLD_DI_LINKMAP, &map) != 0 || !map)
        return fail(6);

    view.address = (uintptr_t)symbol;
    if (dl_iterate_phdr(find_view, &view) != 0 || view.matches != 1 ||
        !view.phdr || view.phnum == 0)
        return fail(7);
    page_size = (uintptr_t)sysconf(_SC_PAGESIZE);
    if (page_size == 0 || (page_size & (page_size - 1)) != 0)
        return fail(8);
    for (ElfW(Half) i = 0; i < view.phnum; i++) {
        uint64_t end;

        if (view.phdr[i].p_type != PT_LOAD || view.phdr[i].p_memsz == 0 ||
            view.phdr[i].p_vaddr > UINT64_MAX - view.phdr[i].p_memsz)
            continue;
        end = view.phdr[i].p_vaddr + view.phdr[i].p_memsz;
        if (view.phdr[i].p_vaddr < low)
            low = view.phdr[i].p_vaddr;
        if (end > high)
            high = end;
        if ((uintptr_t)symbol >=
                (uintptr_t)view.base + (uintptr_t)view.phdr[i].p_vaddr &&
            (uintptr_t)symbol -
                ((uintptr_t)view.base + (uintptr_t)view.phdr[i].p_vaddr) <
                view.phdr[i].p_memsz) {
            containing_low = view.phdr[i].p_vaddr;
            containing_high = end;
        }
    }
    if (low == UINT64_MAX || containing_low == UINT64_MAX || low == 0 ||
        low >= high || containing_low >= containing_high ||
        view.base > UINTPTR_MAX - high)
        return fail(9);
    expected_start = (uintptr_t)view.base +
                     (uintptr_t)(low & ~(uint64_t)(page_size - 1));
    expected_end = (uintptr_t)view.base + (uintptr_t)high;

    for (ElfW(Half) i = 0; i < view.phnum; i++) {
        uint64_t raw_end;
        uint64_t page_end;
        uint64_t next_page = UINT64_MAX;

        if (view.phdr[i].p_type != PT_LOAD || view.phdr[i].p_memsz == 0)
            continue;
        raw_end = view.phdr[i].p_vaddr + view.phdr[i].p_memsz;
        page_end = (raw_end + page_size - 1) & ~(uint64_t)(page_size - 1);
        for (ElfW(Half) j = 0; j < view.phnum; j++) {
            uint64_t start_page;

            if (view.phdr[j].p_type != PT_LOAD ||
                view.phdr[j].p_memsz == 0 ||
                view.phdr[j].p_vaddr <= raw_end)
                continue;
            start_page = view.phdr[j].p_vaddr &
                         ~(uint64_t)(page_size - 1);
            if (start_page < next_page)
                next_page = start_page;
        }
        if (padding == UINT64_MAX && raw_end < page_end)
            padding = raw_end;
        if (next_page != UINT64_MAX && page_end < next_page)
            hole = page_end;
    }
    if (padding == UINT64_MAX || hole == UINT64_MAX)
        return fail(10);

    memset(&info, 0, sizeof(info));
    if (dladdr(symbol, &info) != 1 ||
        info.dli_fbase != (void *)expected_start)
        return fail(11);
    memset(&info, 0xa5, sizeof(info));
    if (dladdr((void *)((uintptr_t)view.base + padding), &info) !=
            expect_dladdr_aggregate ||
        (expect_dladdr_aggregate &&
         info.dli_fbase != (void *)expected_start))
        return fail(12);
    memset(&info, 0xa5, sizeof(info));
    if (dladdr((void *)((uintptr_t)view.base + hole), &info) !=
            expect_dladdr_aggregate ||
        (expect_dladdr_aggregate &&
         info.dli_fbase != (void *)expected_start))
        return fail(13);

    find_symbol = dlsym(RTLD_DEFAULT, "_dl_find_object");
    if (find_symbol) {
        memcpy(&find_object, &find_symbol, sizeof(find_object));
        memset(&found, 0, sizeof(found));
        if (find_object(symbol, &found) != 0)
            return fail(14);
        if (found.link_map != map)
            return fail(17);
        if (found.map_start !=
            (void *)(expect_dladdr_aggregate
                         ? expected_start
                         : (uintptr_t)view.base + containing_low))
            return fail(18);
        if (found.map_end !=
            (void *)(expect_dladdr_aggregate
                         ? expected_end
                         : (uintptr_t)view.base + containing_high))
            return fail(19);
        if ((find_object((void *)((uintptr_t)view.base + padding), &found) ==
             0) != expect_dladdr_aggregate)
            return fail(15);
        if ((find_object((void *)((uintptr_t)view.base + hole), &found) == 0) !=
            expect_dladdr_aggregate)
            return fail(16);
    }

    puts("dladdr-layout-ok");
    return 0;
}
