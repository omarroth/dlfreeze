#include "elf_sections.h"

#include <elf.h>
#include <stdint.h>
#include <string.h>

static int check_count(size_t count, Elf64_Half encoded_count,
                       Elf64_Xword extended_count)
{
    Elf64_Ehdr ehdr;
    Elf64_Shdr section_zero;

    memset(&ehdr, 0xa5, sizeof(ehdr));
    memset(&section_zero, 0, sizeof(section_zero));
    if (!dlfrz_elf64_encode_section_count(&ehdr, &section_zero, count))
        return -1;
    if (ehdr.e_shnum != encoded_count ||
        section_zero.sh_size != extended_count)
        return -1;
    return 0;
}

int main(void)
{
    Elf64_Ehdr ehdr;
    Elf64_Shdr section_zero;
    Elf64_Sym symbol;
    Elf32_Word extended_index;

    if (check_count((size_t)SHN_LORESERVE - 1,
                    (Elf64_Half)(SHN_LORESERVE - 1), 0) < 0)
        return 1;
    if (check_count(SHN_LORESERVE, 0, SHN_LORESERVE) < 0)
        return 2;
    if (check_count((size_t)SHN_LORESERVE + 123, 0,
                    (Elf64_Xword)SHN_LORESERVE + 123) < 0)
        return 3;
    memset(&ehdr, 0, sizeof(ehdr));
    memset(&section_zero, 0, sizeof(section_zero));
    if (dlfrz_elf64_encode_section_count(&ehdr, &section_zero, 0) ||
        dlfrz_elf64_encode_section_count(NULL, &section_zero, 1) ||
        dlfrz_elf64_encode_section_count(&ehdr, NULL, 1))
        return 4;
    memset(&symbol, 0, sizeof(symbol));
    extended_index = UINT32_MAX;
    if (!dlfrz_elf64_encode_symbol_section(
            &symbol, NULL, (size_t)SHN_LORESERVE - 1) ||
        symbol.st_shndx != SHN_LORESERVE - 1)
        return 5;
    if (!dlfrz_elf64_encode_symbol_section(
            &symbol, &extended_index, SHN_LORESERVE) ||
        symbol.st_shndx != SHN_XINDEX ||
        extended_index != SHN_LORESERVE)
        return 6;
    if (dlfrz_elf64_encode_symbol_section(
            &symbol, NULL, SHN_LORESERVE))
        return 7;
    return 0;
}
