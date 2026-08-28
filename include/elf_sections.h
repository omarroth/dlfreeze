#ifndef DLFREEZE_ELF_SECTIONS_H
#define DLFREEZE_ELF_SECTIONS_H

#include <elf.h>
#include <stddef.h>
#include <stdint.h>

/* ELF reserves the upper direct e_shnum values.  Large section tables encode
 * their true count in section header zero instead.  Keep writers and tests on
 * the same ABI rule rather than imposing an implementation-specific cap. */
static inline int dlfrz_elf64_encode_section_count(
    Elf64_Ehdr *ehdr, Elf64_Shdr *section_zero, size_t count)
{
    Elf64_Xword encoded = (Elf64_Xword)count;

    if (!ehdr || !section_zero || count == 0 ||
        (size_t)encoded != count)
        return 0;

    section_zero->sh_size = 0;
    if (count >= SHN_LORESERVE) {
        ehdr->e_shnum = 0;
        section_zero->sh_size = encoded;
    } else {
        ehdr->e_shnum = (Elf64_Half)count;
    }
    return 1;
}

/* A symbol whose section index is in the reserved direct range uses
 * SHN_XINDEX and stores the actual index in its parallel SHT_SYMTAB_SHNDX
 * word.  Callers need not allocate that table while all indices are direct. */
static inline int dlfrz_elf64_encode_symbol_section(
    Elf64_Sym *symbol, Elf32_Word *extended_index, size_t section_index)
{
    Elf32_Word encoded = (Elf32_Word)section_index;

    if (!symbol || (size_t)encoded != section_index ||
        (section_index >= SHN_LORESERVE && !extended_index))
        return 0;
    if (extended_index)
        *extended_index = 0;
    if (section_index >= SHN_LORESERVE) {
        symbol->st_shndx = SHN_XINDEX;
        *extended_index = encoded;
    } else {
        symbol->st_shndx = (Elf64_Section)section_index;
    }
    return 1;
}

#endif
