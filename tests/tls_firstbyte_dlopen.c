#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

typedef uintptr_t (*address_fn)(void);
typedef int (*values_fn)(void);

struct tls_module {
    uintptr_t residue;
    uintptr_t align;
    address_fn first_address;
    address_fn aligned_address;
    values_fn values_valid;
};

static int find_module_tls(struct dl_phdr_info *info, size_t size,
                           void *opaque)
{
    struct tls_module *module = opaque;
    uintptr_t function = (uintptr_t)module->first_address;
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
        module->align = phdr->p_align ? phdr->p_align : 1;
        module->residue = phdr->p_vaddr & (module->align - 1);
        return 1;
    }
    return 0;
}

static int module_is_valid(struct tls_module *module)
{
    uintptr_t first = module->first_address();
    uintptr_t aligned = module->aligned_address();

    /* glibc's allocate_dtv_entry aligns a dynamically allocated TLS block
     * itself.  PT_TLS first-byte congruence is a static-layout rule. */
    return module->align == 4096 && module->residue != 0 &&
           (first & (module->align - 1)) == 0 &&
           (aligned & (module->align - 1)) ==
               ((module->align - module->residue) &
                (module->align - 1)) &&
           module->values_valid();
}

static void *worker(void *opaque)
{
    return (void *)(uintptr_t)!module_is_valid(opaque);
}

int main(int argc, char **argv)
{
    struct tls_module module = {0};
    pthread_t thread;
    void *handle;
    void *result = NULL;

    if (argc != 2)
        return 2;
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return 3;
    module.first_address = (address_fn)dlsym(
        handle, "dlfreeze_tls_first_address");
    module.aligned_address = (address_fn)dlsym(
        handle, "dlfreeze_tls_aligned_address");
    module.values_valid = (values_fn)dlsym(
        handle, "dlfreeze_tls_values_valid");
    if (!module.first_address || !module.aligned_address ||
        !module.values_valid ||
        !dl_iterate_phdr(find_module_tls, &module) ||
        !module_is_valid(&module) ||
        pthread_create(&thread, NULL, worker, &module) != 0 ||
        pthread_join(thread, &result) != 0 || result)
        return 4;
    puts("dynamic-tls-firstbyte-ok");
    return 0;
}
