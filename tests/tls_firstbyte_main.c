#define _GNU_SOURCE
#include <link.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

uintptr_t dlfreeze_tls_first_address(void);
uintptr_t dlfreeze_tls_aligned_address(void);
int dlfreeze_tls_values_valid(void);

struct tls_phdr_geometry {
    uintptr_t residue;
    uintptr_t align;
    int found;
};

static int find_module_tls(struct dl_phdr_info *info, size_t size,
                           void *opaque)
{
    struct tls_phdr_geometry *geometry = opaque;
    uintptr_t function = (uintptr_t)dlfreeze_tls_first_address;
    int owns_function = 0;

    (void)size;
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
        uintptr_t start;
        uintptr_t end;

        if (phdr->p_type != PT_LOAD || phdr->p_memsz == 0)
            continue;
        start = (uintptr_t)info->dlpi_addr + phdr->p_vaddr;
        end = start + phdr->p_memsz;
        if (end >= start && function >= start && function < end) {
            owns_function = 1;
            break;
        }
    }
    if (!owns_function)
        return 0;
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];

        if (phdr->p_type != PT_TLS)
            continue;
        geometry->align = phdr->p_align ? phdr->p_align : 1;
        geometry->residue = phdr->p_vaddr & (geometry->align - 1);
        geometry->found = 1;
        return 1;
    }
    return 0;
}

static int module_is_valid(const struct tls_phdr_geometry *geometry)
{
    return geometry->found && geometry->align == 4096 &&
           geometry->residue != 0 &&
           (dlfreeze_tls_first_address() & (geometry->align - 1)) ==
               geometry->residue &&
           (dlfreeze_tls_aligned_address() & (geometry->align - 1)) == 0 &&
           dlfreeze_tls_values_valid();
}

static void *worker(void *opaque)
{
    return (void *)(uintptr_t)!module_is_valid(opaque);
}

int main(void)
{
    struct tls_phdr_geometry geometry = {0};
    pthread_t thread;
    void *result = NULL;

    dl_iterate_phdr(find_module_tls, &geometry);
    if (!module_is_valid(&geometry) ||
        pthread_create(&thread, NULL, worker, &geometry) != 0 ||
        pthread_join(thread, &result) != 0 || result)
        return 1;
    puts("static-tls-firstbyte-ok");
    return 0;
}
