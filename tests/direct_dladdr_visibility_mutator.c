#define _GNU_SOURCE
#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static int range_ok(size_t file_size, uint64_t offset, uint64_t size)
{
    return offset <= file_size && size <= file_size - offset;
}

static uint32_t elf_hash(const unsigned char *name)
{
    uint32_t value = 0;

    while (*name) {
        uint32_t high;

        value = (value << 4) + *name++;
        high = value & UINT32_C(0xf0000000);
        if (high)
            value ^= high >> 24;
        value &= ~high;
    }
    return value;
}

static int symbol_name(const Elf64_Sym *symbol, const char *strings,
                       size_t strings_size, const char **name_out)
{
    const char *name;

    if (symbol->st_name >= strings_size)
        return 0;
    name = strings + symbol->st_name;
    if (!memchr(name, '\0', strings_size - symbol->st_name))
        return 0;
    *name_out = name;
    return 1;
}

int main(int argc, char **argv)
{
    static const char local_name[] = "loader_dladdr_candidate_a";
    static const char hidden_name[] = "loader_dladdr_candidate_b";
    struct stat status;
    unsigned char *file = MAP_FAILED;
    Elf64_Ehdr *ehdr;
    Elf64_Shdr *sections;
    Elf64_Shdr *dynsym_section = NULL;
    Elf64_Shdr *hash_section = NULL;
    Elf64_Sym *symbols;
    Elf64_Sym *copy = NULL;
    const char *strings;
    size_t symbol_count;
    size_t local_index = SIZE_MAX;
    size_t hidden_index = SIZE_MAX;
    int fd = -1;
    int result = 1;

    if (argc != 2)
        return 2;
    fd = open(argv[1], O_RDWR | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &status) != 0 || status.st_size < 0)
        goto out;
    file = mmap(NULL, (size_t)status.st_size, PROT_READ | PROT_WRITE,
                MAP_SHARED, fd, 0);
    if (file == MAP_FAILED)
        goto out;
    if (!range_ok((size_t)status.st_size, 0, sizeof(Elf64_Ehdr)))
        goto out;
    ehdr = (Elf64_Ehdr *)file;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr->e_shentsize != sizeof(Elf64_Shdr) || ehdr->e_shnum == 0 ||
        !range_ok((size_t)status.st_size, ehdr->e_shoff,
                  (uint64_t)ehdr->e_shnum * sizeof(Elf64_Shdr)))
        goto out;
    sections = (Elf64_Shdr *)(file + ehdr->e_shoff);
    for (size_t i = 0; i < ehdr->e_shnum; i++) {
        if (!range_ok((size_t)status.st_size, sections[i].sh_offset,
                      sections[i].sh_size))
            goto out;
        if (sections[i].sh_type == SHT_DYNSYM) {
            if (dynsym_section)
                goto out;
            dynsym_section = &sections[i];
        } else if (sections[i].sh_type == SHT_HASH) {
            if (hash_section)
                goto out;
            hash_section = &sections[i];
        }
    }
    if (!dynsym_section || !hash_section ||
        dynsym_section->sh_entsize != sizeof(Elf64_Sym) ||
        dynsym_section->sh_size % sizeof(Elf64_Sym) != 0 ||
        dynsym_section->sh_link >= ehdr->e_shnum ||
        sections[dynsym_section->sh_link].sh_type != SHT_STRTAB)
        goto out;
    for (size_t i = 0; i < ehdr->e_shnum; i++)
        if ((sections[i].sh_type == SHT_REL ||
             sections[i].sh_type == SHT_RELA) &&
            sections[i].sh_link == (size_t)(dynsym_section - sections) &&
            sections[i].sh_size != 0)
            goto out;

    symbol_count = dynsym_section->sh_size / sizeof(Elf64_Sym);
    if (symbol_count < 3 || symbol_count > UINT32_MAX)
        goto out;
    symbols = (Elf64_Sym *)(file + dynsym_section->sh_offset);
    strings = (const char *)file +
              sections[dynsym_section->sh_link].sh_offset;
    for (size_t i = 1; i < symbol_count; i++) {
        const char *name;

        if (!symbol_name(&symbols[i], strings,
                         sections[dynsym_section->sh_link].sh_size, &name))
            goto out;
        if (strcmp(name, local_name) == 0)
            local_index = i;
        else if (strcmp(name, hidden_name) == 0)
            hidden_index = i;
    }
    if (local_index == SIZE_MAX || hidden_index == SIZE_MAX ||
        local_index == hidden_index)
        goto out;

    copy = malloc(dynsym_section->sh_size);
    if (!copy)
        goto out;
    memcpy(copy, symbols, dynsym_section->sh_size);
    symbols[0] = copy[0];
    symbols[1] = copy[local_index];
    symbols[1].st_info = ELF64_ST_INFO(
        STB_LOCAL, ELF64_ST_TYPE(symbols[1].st_info));
    {
        size_t output = 2;

        for (size_t input = 1; input < symbol_count; input++) {
            if (input == local_index)
                continue;
            symbols[output] = copy[input];
            if (input == hidden_index)
                symbols[output].st_other =
                    (symbols[output].st_other & ~UINT8_C(3)) | STV_HIDDEN;
            output++;
        }
        if (output != symbol_count)
            goto out;
    }
    dynsym_section->sh_info = 2;

    {
        uint32_t *hash = (uint32_t *)(file + hash_section->sh_offset);
        uint32_t buckets;
        uint32_t chains;
        uint32_t *bucket_table;
        uint32_t *chain_table;

        if (hash_section->sh_size < 2 * sizeof(uint32_t))
            goto out;
        buckets = hash[0];
        chains = hash[1];
        if (buckets == 0 || chains != symbol_count ||
            hash_section->sh_size <
                (uint64_t)(2 + buckets + chains) * sizeof(uint32_t))
            goto out;
        bucket_table = hash + 2;
        chain_table = bucket_table + buckets;
        memset(bucket_table, 0,
               (size_t)(buckets + chains) * sizeof(uint32_t));
        for (uint32_t i = 2; i < chains; i++) {
            const char *name;
            uint32_t *slot;

            if (!symbol_name(&symbols[i], strings,
                             sections[dynsym_section->sh_link].sh_size,
                             &name))
                goto out;
            slot = &bucket_table[elf_hash((const unsigned char *)name) %
                                         buckets];
            while (*slot != STN_UNDEF) {
                if (*slot >= chains)
                    goto out;
                slot = &chain_table[*slot];
            }
            *slot = i;
        }
    }

    if (msync(file, (size_t)status.st_size, MS_SYNC) != 0)
        goto out;
    result = 0;
out:
    free(copy);
    if (file != MAP_FAILED)
        munmap(file, (size_t)status.st_size);
    if (fd >= 0)
        close(fd);
    if (result)
        fprintf(stderr, "could not construct dladdr visibility fixture\n");
    return result;
}
