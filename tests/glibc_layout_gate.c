#include "common.h"
#include "glibc_layout.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static int range_fits(size_t offset, size_t length, size_t size)
{
    return offset <= size && length <= size - offset;
}

static int patch_rtld_global_size(uint8_t *elf, size_t elf_size)
{
    Elf64_Ehdr *ehdr;
    Elf64_Shdr *shdrs;

    if (elf_size < sizeof(Elf64_Ehdr))
        return -1;
    ehdr = (Elf64_Ehdr *)elf;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr->e_shentsize != sizeof(Elf64_Shdr) ||
        ehdr->e_shnum == 0 ||
        !range_fits((size_t)ehdr->e_shoff,
                    (size_t)ehdr->e_shnum * sizeof(Elf64_Shdr), elf_size))
        return -1;

    shdrs = (Elf64_Shdr *)(elf + ehdr->e_shoff);
    for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *sym_sh = &shdrs[i];
        Elf64_Shdr *str_sh;
        Elf64_Sym *syms;
        const char *strings;
        size_t nsyms;

        if (sym_sh->sh_type != SHT_DYNSYM ||
            sym_sh->sh_entsize != sizeof(Elf64_Sym) ||
            sym_sh->sh_link >= ehdr->e_shnum ||
            sym_sh->sh_size % sizeof(Elf64_Sym) != 0 ||
            !range_fits((size_t)sym_sh->sh_offset,
                        (size_t)sym_sh->sh_size, elf_size))
            continue;
        str_sh = &shdrs[sym_sh->sh_link];
        if (str_sh->sh_type != SHT_STRTAB ||
            !range_fits((size_t)str_sh->sh_offset,
                        (size_t)str_sh->sh_size, elf_size))
            continue;

        syms = (Elf64_Sym *)(elf + sym_sh->sh_offset);
        strings = (const char *)(elf + str_sh->sh_offset);
        nsyms = (size_t)sym_sh->sh_size / sizeof(Elf64_Sym);
        for (size_t j = 0; j < nsyms; j++) {
            const char *name;
            size_t remain;

            if (ELF64_ST_TYPE(syms[j].st_info) != STT_OBJECT ||
                syms[j].st_shndx == SHN_UNDEF ||
                syms[j].st_name >= str_sh->sh_size)
                continue;
            name = strings + syms[j].st_name;
            remain = (size_t)str_sh->sh_size - syms[j].st_name;
            if (remain > sizeof("_rtld_global") - 1 &&
                memcmp(name, "_rtld_global", sizeof("_rtld_global") - 1) == 0 &&
                name[sizeof("_rtld_global") - 1] == '\0') {
                syms[j].st_size += 16;
                return 0;
            }
        }
    }
    return -1;
}

static int patch_stable_release_minor(uint8_t *elf, size_t elf_size)
{
    static const char prefix[] = "stable release version 2.";

    if (dlfrz_glibc_is_development_release(elf, elf_size))
        return -1;
    if (elf_size < sizeof(prefix) - 1)
        return -1;
    for (size_t i = 0; i <= elf_size - (sizeof(prefix) - 1); i++) {
        size_t p;

        if (memcmp(elf + i, prefix, sizeof(prefix) - 1) != 0)
            continue;
        p = i + sizeof(prefix) - 1;
        if (p >= elf_size || elf[p] < '0' || elf[p] > '9')
            return -1;
        while (p + 1 < elf_size && elf[p + 1] >= '0' && elf[p + 1] <= '9')
            p++;
        elf[p] = elf[p] == '0' ? '1' : (unsigned char)(elf[p] - 1);
        return 0;
    }
    return -1;
}

static int remove_stable_release_identity(uint8_t *elf, size_t elf_size)
{
    static const char prefix[] = "stable release version 2.";

    if (elf_size < sizeof(prefix) - 1)
        return -1;
    for (size_t i = 0; i <= elf_size - (sizeof(prefix) - 1); i++) {
        if (memcmp(elf + i, prefix, sizeof(prefix) - 1) != 0)
            continue;
        elf[i] = 'x';
        return 0;
    }
    return -1;
}

static int patch_frozen_interp(uint8_t *map, size_t size, int operation)
{
    struct dlfrz_footer *footer;
    struct dlfrz_entry *entries;
    size_t entries_size;

    if (size < sizeof(struct dlfrz_footer))
        return -1;
    footer = (struct dlfrz_footer *)(map + size - sizeof(*footer));
    if (memcmp(footer->magic, DLFRZ_MAGIC, sizeof(footer->magic)) != 0 ||
        footer->version != DLFRZ_VERSION)
        return -1;
    entries_size = (size_t)footer->num_entries * sizeof(struct dlfrz_entry);
    if (!range_fits((size_t)footer->manifest_offset, entries_size, size))
        return -1;
    entries = (struct dlfrz_entry *)(map + footer->manifest_offset);

    for (uint32_t i = 0; i < footer->num_entries; i++) {
        if (!(entries[i].flags & DLFRZ_FLAG_INTERP))
            continue;
        if (!range_fits((size_t)entries[i].data_offset,
                        (size_t)entries[i].data_size, size))
            return -1;
        if (operation == 3)
            return remove_stable_release_identity(
                map + entries[i].data_offset,
                (size_t)entries[i].data_size);
        return patch_rtld_global_size(
            map + entries[i].data_offset,
            (size_t)entries[i].data_size);
    }
    return -1;
}

static int patch_file(const char *path, int operation)
{
    struct stat st;
    uint8_t *map;
    int fd;
    int rc;

    fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        perror(path);
        return 1;
    }
    if (fstat(fd, &st) < 0 || st.st_size <= 0) {
        perror("fstat");
        close(fd);
        return 1;
    }
    map = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE,
               MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }
    if (operation == 3)
        rc = patch_frozen_interp(map, (size_t)st.st_size, operation);
    else if (operation == 2)
        rc = patch_stable_release_minor(map, (size_t)st.st_size);
    else if (operation == 1)
        rc = patch_frozen_interp(map, (size_t)st.st_size, operation);
    else
        rc = patch_rtld_global_size(map, (size_t)st.st_size);
    if (rc == 0 && msync(map, (size_t)st.st_size, MS_SYNC) < 0) {
        perror("msync");
        rc = -1;
    }
    munmap(map, (size_t)st.st_size);
    close(fd);
    if (rc != 0)
        fprintf(stderr, "%s: could not patch requested identity\n", path);
    return rc != 0;
}

static int selftest(void)
{
    static const char stable[] =
        "ld.so (GNU libc) stable release version 2.43.";
    static const char development[] =
        "ld.so (GNU libc) development release version 2.43.9000";
    static const char downstream_snapshot[] =
        "ld.so (GNU libc) downstream release version 2.43.9000";

    if (dlfrz_glibc_layout_lookup(EM_X86_64, 928, 2120) !=
            DLFRZ_GLIBC_X86_2_40 ||
        dlfrz_glibc_layout_lookup(EM_X86_64, 928, 2136) !=
            DLFRZ_GLIBC_LAYOUT_UNKNOWN ||
        dlfrz_glibc_layout_lookup(EM_AARCH64, 400, 2272) !=
            DLFRZ_GLIBC_AARCH64_2_43 ||
        dlfrz_glibc_layout_lookup(EM_AARCH64, 400, 2288) !=
            DLFRZ_GLIBC_LAYOUT_UNKNOWN ||
        dlfrz_glibc_stable_release_minor(stable, sizeof(stable) - 1) != 43 ||
        dlfrz_glibc_stable_release_minor(development,
                                          sizeof(development) - 1) != -1 ||
        !dlfrz_glibc_layout_release_is_supported(
            DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY, 39) ||
        !dlfrz_glibc_layout_release_is_supported(
            DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY, 40) ||
        dlfrz_glibc_layout_release_is_supported(
            DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY, 36) ||
        dlfrz_glibc_layout_release_is_supported(
            DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY, 41) ||
        !dlfrz_glibc_layout_release_is_supported(
            DLFRZ_GLIBC_X86_2_40, 43) ||
        dlfrz_glibc_layout_release_is_supported(
            DLFRZ_GLIBC_X86_2_40, 44) ||
        dlfrz_glibc_layout_release_is_supported(
            DLFRZ_GLIBC_LAYOUT_UNKNOWN, 43) ||
        dlfrz_glibc_is_development_release(stable, sizeof(stable) - 1) ||
        !dlfrz_glibc_is_development_release(development,
                                             sizeof(development) - 1) ||
        !dlfrz_glibc_is_development_release(downstream_snapshot,
                                             sizeof(downstream_snapshot) - 1))
        return 1;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0)
        return selftest();
    if (argc == 3 && strcmp(argv[1], "--elf") == 0)
        return patch_file(argv[2], 0);
    if (argc == 3 && strcmp(argv[1], "--frozen") == 0)
        return patch_file(argv[2], 1);
    if (argc == 3 && strcmp(argv[1], "--release-mismatch") == 0)
        return patch_file(argv[2], 2);
    if (argc == 3 && strcmp(argv[1], "--frozen-release-missing") == 0)
        return patch_file(argv[2], 3);
    fprintf(stderr,
            "usage: %s --selftest | --elf FILE | --frozen FILE | "
            "--release-mismatch FILE | --frozen-release-missing FILE\n",
            argv[0]);
    return 2;
}
