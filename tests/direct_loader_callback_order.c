#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum { TEST_RTLD_DI_LINKMAP = 2 };

typedef int (*late_value_fn)(void);

struct iterate_state {
    const char *late_path;
    const char *late_basename;
    const char *loader_name;
    void *iterate_address;
    void *late_handle;
    size_t record_count;
    size_t loader_position;
    size_t late_position;
    int loader_count;
    int late_count;
    int invalid;
};

static const char *path_basename(const char *path)
{
    const char *slash;

    if (!path)
        return "";
    slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static int record_contains(const struct dl_phdr_info *info,
                           uintptr_t address)
{
    if (!info || !info->dlpi_phdr)
        return 0;
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
        uintptr_t start;

        if (phdr->p_type != PT_LOAD || phdr->p_memsz == 0 ||
            phdr->p_vaddr > UINTPTR_MAX - info->dlpi_addr)
            continue;
        start = (uintptr_t)info->dlpi_addr + (uintptr_t)phdr->p_vaddr;
        if (address >= start && address - start < phdr->p_memsz)
            return 1;
    }
    return 0;
}

static int inspect_and_load(struct dl_phdr_info *info, size_t size,
                            void *opaque)
{
    struct iterate_state *state = opaque;
    size_t position;

    (void)size;
    if (!state || !info || !info->dlpi_name || !info->dlpi_phdr ||
        info->dlpi_phnum == 0) {
        if (state)
            state->invalid = 1;
        return 0;
    }
    position = state->record_count++;
    if (record_contains(info, (uintptr_t)state->iterate_address)) {
        state->loader_count++;
        state->loader_position = position;
        state->loader_name = info->dlpi_name;
        if (!state->late_handle)
            state->late_handle = dlopen(state->late_path,
                                        RTLD_NOW | RTLD_LOCAL);
        if (!state->late_handle)
            state->invalid = 1;
    }
    if (strcmp(path_basename(info->dlpi_name), state->late_basename) == 0) {
        state->late_count++;
        state->late_position = position;
    }
    return 0;
}

static int traced_load(const char *path)
{
    late_value_fn value = NULL;
    void *symbol;
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);

    if (!handle)
        return 0;
    symbol = dlsym(handle, "loader_callback_order_value");
    if (!symbol)
        return 0;
    memcpy(&value, &symbol, sizeof(value));
    return value && value() == 19;
}

int main(int argc, char **argv)
{
    struct iterate_state state;
    struct link_map *map = NULL;
    struct link_map *previous = NULL;
    size_t map_position = 0;
    size_t loader_map_position = 0;
    size_t late_map_position = 0;
    int loader_map_count = 0;
    int late_map_count = 0;
    void *main_handle;

    if (argc != 3)
        return 2;
    if (strcmp(argv[2], "trace") == 0) {
        if (!traced_load(argv[1]))
            return 3;
        puts("loader-callback-order-trace");
        return 0;
    }
    if (strcmp(argv[2], "strict") != 0)
        return 4;

    memset(&state, 0, sizeof(state));
    state.late_path = argv[1];
    state.late_basename = path_basename(argv[1]);
    state.iterate_address = dlsym(RTLD_DEFAULT, "dl_iterate_phdr");
    if (!state.iterate_address ||
        dl_iterate_phdr(inspect_and_load, &state) != 0 || state.invalid ||
        state.loader_count != 1 || state.late_count != 1 ||
        !state.loader_name || !state.late_handle ||
        state.loader_position >= state.late_position)
        return 5;
    if (!traced_load(argv[1]))
        return 6;

    main_handle = dlopen(NULL, RTLD_NOW);
    if (!main_handle ||
        dlinfo(main_handle, TEST_RTLD_DI_LINKMAP, &map) != 0 || !map)
        return 7;
    for (; map; map = map->l_next, map_position++) {
        if (map_position >= 512 || map->l_prev != previous || !map->l_name)
            return 8;
        if (strcmp(map->l_name, state.loader_name) == 0) {
            loader_map_count++;
            loader_map_position = map_position;
        }
        if (strcmp(path_basename(map->l_name), state.late_basename) == 0) {
            late_map_count++;
            late_map_position = map_position;
        }
        previous = map;
    }
    if (loader_map_count != 1 || late_map_count != 1 ||
        loader_map_position >= late_map_position)
        return 9;

    puts("loader-callback-order-ok");
    return 0;
}
