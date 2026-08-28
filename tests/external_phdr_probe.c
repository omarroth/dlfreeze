#define _GNU_SOURCE

#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

struct phdr_query {
    uintptr_t address;
    const Elf64_Phdr *phdr;
    Elf64_Half phnum;
    int matches;
    int has_dynamic;
};

static int find_owner(struct dl_phdr_info *info, size_t size, void *opaque)
{
    struct phdr_query *query = opaque;
    int owns = 0;
    int has_dynamic = 0;

    (void)size;
    for (Elf64_Half i = 0; i < info->dlpi_phnum; i++) {
        const Elf64_Phdr *ph = &info->dlpi_phdr[i];
        uintptr_t start;

        if (ph->p_type == PT_DYNAMIC)
            has_dynamic = 1;
        if (ph->p_type != PT_LOAD || ph->p_memsz == 0 ||
            ph->p_vaddr > UINTPTR_MAX - info->dlpi_addr)
            continue;
        start = info->dlpi_addr + ph->p_vaddr;
        if (query->address >= start &&
            query->address - start < ph->p_memsz)
            owns = 1;
    }
    if (!owns)
        return 0;
    query->matches++;
    query->phdr = info->dlpi_phdr;
    query->phnum = info->dlpi_phnum;
    query->has_dynamic = has_dynamic;
    return 0;
}

static int header_view_is_read_only(const Elf64_Phdr *phdr)
{
    pid_t child = fork();
    int status;

    if (child < 0)
        return 0;
    if (child == 0) {
        volatile unsigned char *byte =
            (volatile unsigned char *)(uintptr_t)phdr;

        *byte = *byte;
        _exit(0);
    }
    if (waitpid(child, &status, 0) != child)
        return 0;
    return WIFSIGNALED(status) &&
           (WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS);
}

int main(int argc, char **argv)
{
    struct phdr_query query = {0};
    struct link_map *map = NULL;
    Dl_info info;
    void *handle;
    int (*value)(void);
    const char *path;
    int require_owned = 0;
    int load_only = 0;

    if (argc == 3 && strcmp(argv[1], "--expect-fail") == 0) {
        handle = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
        if (handle) {
            dlclose(handle);
            return 1;
        }
        return dlerror() ? 0 : 2;
    }
    if (argc == 3 && strcmp(argv[1], "--require-owned") == 0) {
        require_owned = 1;
        path = argv[2];
    } else if (argc == 3 && strcmp(argv[1], "--load-only") == 0) {
        load_only = 1;
        path = argv[2];
    } else if (argc == 2) {
        path = argv[1];
    } else {
        return 2;
    }
    handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return 3;
    value = (int (*)(void))dlsym(handle, "external_phdr_value");
    if (!value || value() != 73)
        return 4;
    if (load_only) {
        puts("external-phdr-ok");
        return 0;
    }
    query.address = (uintptr_t)value;
    if (dl_iterate_phdr(find_owner, &query) != 0 || query.matches != 1 ||
        !query.phdr || query.phnum == 0 || !query.has_dynamic ||
        (require_owned &&
         (uintptr_t)query.phdr % _Alignof(Elf64_Phdr) != 0))
        return 5;
    if (dlinfo(handle, RTLD_DI_LINKMAP, &map) != 0 || !map ||
        !map->l_name || !map->l_name[0])
        return 6;
    memset(&info, 0, sizeof(info));
    if (!dladdr((void *)(uintptr_t)value, &info) || !info.dli_fname ||
        !info.dli_fname[0] || !info.dli_fbase)
        return 7;
    if (require_owned && !header_view_is_read_only(query.phdr))
        return 8;
    puts("external-phdr-ok");
    return 0;
}
