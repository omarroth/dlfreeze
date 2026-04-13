#ifndef DLFREEZE_ELF_PARSER_H
#define DLFREEZE_ELF_PARSER_H

#include <elf.h>
#include <stddef.h>

struct elf_info {
    int       ei_class;         /* ELFCLASS32 or ELFCLASS64 */
    uint16_t  e_machine;
    char      interp[256];      /* PT_INTERP path */
    char      rpath[1024];      /* DT_RPATH */
    char      runpath[1024];    /* DT_RUNPATH */
    char    **needed;           /* DT_NEEDED entries (null-terminated array) */
    int       needed_count;
    char      soname[256];      /* DT_SONAME */
    int       is_dynamic;       /* has PT_DYNAMIC */
    int       is_pie;           /* ET_DYN (position-independent) */
};

/* Parse an ELF file and extract dynamic linking info */
int elf_parse(const char *path, struct elf_info *info);

/* Free resources allocated by elf_parse */
void elf_info_free(struct elf_info *info);

/* Quick check: is this file an ELF binary? */
int elf_check(const char *path);

#endif /* DLFREEZE_ELF_PARSER_H */
