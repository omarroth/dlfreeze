#ifndef DLFREEZE_ELF_PARSER_H
#define DLFREEZE_ELF_PARSER_H

#include <elf.h>
#include <stddef.h>

struct elf_version_requirement {
    char    *file;              /* pointer into elf_info's string snapshot */
    char    *name;              /* pointer into elf_info's string snapshot */
    uint32_t hash;              /* validated ELF version-name hash */
    uint16_t flags;             /* exact Elf64_Vernaux vna_flags */
    uint16_t index;             /* validated 15-bit version index */
};

struct elf_version_definition {
    char    *name;              /* pointer into elf_info's string snapshot */
    uint32_t hash;              /* validated ELF version-name hash */
    uint16_t flags;             /* exact Elf64_Verdef vd_flags */
    uint16_t index;             /* validated 15-bit version index */
};

struct elf_info {
    int       ei_class;         /* ELFCLASS32 or ELFCLASS64 */
    uint16_t  e_machine;
    char     *interp;           /* owned PT_INTERP path, or NULL */
    char     *rpath;            /* DT_RPATH in dynamic_strings, or NULL */
    char     *runpath;          /* DT_RUNPATH in dynamic_strings, or NULL */
    char    **needed;           /* pointers into dynamic_strings; NULL-ended */
    int       needed_count;
    char     *soname;           /* DT_SONAME in dynamic_strings, or NULL */
    int       is_dynamic;       /* has PT_DYNAMIC */
    int       is_pie;           /* ET_DYN (position-independent) */
    uint64_t  tls_memsz;        /* PT_TLS p_memsz (zero is valid) */
    uint64_t  flags_1;          /* exact DT_FLAGS_1 value, or zero */
    int       has_static_tls;    /* closure needs static placement (DF/TPOFF) */
    struct elf_version_requirement *version_requirements;
    size_t    version_requirement_count;
    struct elf_version_definition *version_definitions;
    size_t    version_definition_count;
    /* One immutable copy of DT_STRTAB backs all dynamic-string fields.  This
     * preserves native ELF aliasing without multiplying memory for repeated
     * references; callers continue to release everything via elf_info_free. */
    char     *dynamic_strings;
    size_t    dynamic_strings_size;
};

/* Parse an ELF file and extract dynamic linking info */
int elf_parse(const char *path, struct elf_info *info);

/* Parse an already-open ELF descriptor without reopening its pathname. */
int elf_parse_fd(int fd, struct elf_info *info);

/* Parse one bounded ELF image embedded inside an already-open file. */
int elf_parse_fd_range(int fd, uint64_t offset, size_t length,
                       struct elf_info *info);

/* Return nonzero when every runtime-checked DT_VERNEED requirement associated
 * with provider_name has an exact DT_VERDEF name/hash match in provider.
 * Only weak requirements may be absent, matching GNU ld.so semantics. */
int elf_version_requirements_match(const struct elf_info *consumer,
                                   const char *provider_name,
                                   const struct elf_info *provider);

/* Free resources allocated by elf_parse */
void elf_info_free(struct elf_info *info);

/* Strict admission check for a supported executable/shared-object ELF. */
int elf_check(const char *path);

#endif /* DLFREEZE_ELF_PARSER_H */
