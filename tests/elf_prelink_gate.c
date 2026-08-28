#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "dynamic_semantics.h"

#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef DT_DEPAUDIT
#define DT_DEPAUDIT 0x6ffffefb
#endif
#ifndef DT_AUDIT
#define DT_AUDIT 0x6ffffefc
#endif
#ifndef DT_AUXILIARY
#define DT_AUXILIARY 0x7ffffffd
#endif
#ifndef DT_FILTER
#define DT_FILTER 0x7fffffff
#endif
#ifndef DF_TEXTREL
#define DF_TEXTREL 0x00000004
#endif
#ifndef DF_1_GLOBAL
#define DF_1_GLOBAL 0x00000002
#endif
#ifndef DF_1_GROUP
#define DF_1_GROUP 0x00000004
#endif
#ifndef DF_1_INITFIRST
#define DF_1_INITFIRST 0x00000020
#endif
#ifndef DF_1_GLOBAUDIT
#define DF_1_GLOBAUDIT 0x01000000
#endif

struct elf_image {
    uint8_t *data;
    size_t size;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Dyn *dynamic;
    size_t dynamic_count;
};

static int range_fits(uint64_t offset, uint64_t length, size_t size)
{
    return offset <= size && length <= (uint64_t)size - offset;
}

static void *vaddr_file(struct elf_image *image, uint64_t address,
                        uint64_t length)
{
    for (uint16_t i = 0; i < image->ehdr->e_phnum; i++) {
        const Elf64_Phdr *ph = &image->phdr[i];
        uint64_t delta;
        uint64_t offset;

        if (ph->p_type != PT_LOAD || address < ph->p_vaddr)
            continue;
        delta = address - ph->p_vaddr;
        if (delta > ph->p_filesz || length > ph->p_filesz - delta ||
            ph->p_offset > UINT64_MAX - delta)
            continue;
        offset = ph->p_offset + delta;
        if (range_fits(offset, length, image->size))
            return image->data + offset;
    }
    return NULL;
}

static Elf64_Dyn *dynamic_tag(struct elf_image *image, Elf64_Sxword tag)
{
    for (size_t i = 0; i < image->dynamic_count; i++) {
        if (image->dynamic[i].d_tag == DT_NULL)
            break;
        if (image->dynamic[i].d_tag == tag)
            return &image->dynamic[i];
    }
    return NULL;
}

static Elf64_Rela *first_relocation(struct elf_image *image,
                                    int require_symbol)
{
    const Elf64_Sxword address_tags[] = { DT_RELA, DT_JMPREL };
    const Elf64_Sxword size_tags[] = { DT_RELASZ, DT_PLTRELSZ };

    for (size_t table = 0; table < 2; table++) {
        Elf64_Dyn *address = dynamic_tag(image, address_tags[table]);
        Elf64_Dyn *bytes = dynamic_tag(image, size_tags[table]);
        Elf64_Rela *relocations;
        size_t count;

        if (!address || !bytes || bytes->d_un.d_val < sizeof(Elf64_Rela) ||
            bytes->d_un.d_val % sizeof(Elf64_Rela) != 0)
            continue;
        relocations = vaddr_file(image, address->d_un.d_ptr,
                                 bytes->d_un.d_val);
        if (!relocations)
            continue;
        count = (size_t)bytes->d_un.d_val / sizeof(Elf64_Rela);
        for (size_t i = 0; i < count; i++) {
            if (!require_symbol || ELF64_R_SYM(relocations[i].r_info) != 0)
                return &relocations[i];
        }
    }
    return NULL;
}

static int mutate(struct elf_image *image, const char *mode)
{
    static const uint64_t bad_address = UINT64_MAX - 7;
    Elf64_Dyn *entry;

    if (strncmp(mode, "dynamic-", sizeof("dynamic-") - 1) == 0) {
        struct unsupported_dynamic_mode {
            const char *name;
            uint64_t tag;
        };
        static const struct unsupported_dynamic_mode modes[] = {
            { "dynamic-relcount", DLFRZ_DT_RELCOUNT },
            { "dynamic-shndx", DLFRZ_DT_SYMTAB_SHNDX },
            { "dynamic-posflag", DLFRZ_DT_POSFLAG_1 },
            { "dynamic-feature", DLFRZ_DT_FEATURE_1 },
            { "dynamic-move", DLFRZ_DT_MOVETAB },
            { "dynamic-syminfo", DLFRZ_DT_SYMINFO },
            { "dynamic-config", DLFRZ_DT_CONFIG },
            { "dynamic-android-rela", DLFRZ_DT_ANDROID_RELA },
            { "dynamic-android-relr", DLFRZ_DT_ANDROID_RELR },
            { "dynamic-gnu-prelinked", DLFRZ_DT_GNU_PRELINKED },
            { "dynamic-gnu-conflictsz", DLFRZ_DT_GNU_CONFLICTSZ },
            { "dynamic-gnu-liblistsz", DLFRZ_DT_GNU_LIBLISTSZ },
            { "dynamic-pltpadsz", DLFRZ_DT_PLTPADSZ },
            { "dynamic-gnu-conflict", DLFRZ_DT_GNU_CONFLICT },
            { "dynamic-gnu-liblist", DLFRZ_DT_GNU_LIBLIST },
            { "dynamic-pltpad", DLFRZ_DT_PLTPAD },
        };
        uint64_t tag = 0;

        for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
            if (strcmp(mode, modes[i].name) == 0) {
                tag = modes[i].tag;
                break;
            }
        }
        if (tag == 0)
            return 64;
        entry = dynamic_tag(image, DT_DEBUG);
        if (!entry)
            return 77;
        entry->d_tag = (Elf64_Sxword)tag;
        entry->d_un.d_val = 1;
        return 0;
    }

    if (strcmp(mode, "audit") == 0 ||
        strcmp(mode, "depaudit") == 0 ||
        strcmp(mode, "auxiliary") == 0 ||
        strcmp(mode, "filter") == 0) {
        entry = dynamic_tag(image, DT_DEBUG);
        if (!entry)
            return 77;
        if (strcmp(mode, "audit") == 0)
            entry->d_tag = DT_AUDIT;
        else if (strcmp(mode, "depaudit") == 0)
            entry->d_tag = DT_DEPAUDIT;
        else if (strcmp(mode, "auxiliary") == 0)
            entry->d_tag = DT_AUXILIARY;
        else
            entry->d_tag = DT_FILTER;
        entry->d_un.d_val = 0;
        return 0;
    }
    if (strcmp(mode, "textrel-tag") == 0) {
        entry = dynamic_tag(image, DT_DEBUG);
        if (!entry)
            return 77;
        entry->d_tag = DT_TEXTREL;
        entry->d_un.d_val = 0;
        return 0;
    }
    if (strcmp(mode, "flags-textrel") == 0) {
        entry = dynamic_tag(image, DT_FLAGS);
        if (!entry)
            entry = dynamic_tag(image, DT_DEBUG);
        if (!entry)
            return 77;
        entry->d_tag = DT_FLAGS;
        entry->d_un.d_val |= DF_TEXTREL;
        return 0;
    }
    if (strncmp(mode, "flags1-", sizeof("flags1-") - 1) == 0) {
        uint64_t flag;

        if (strcmp(mode, "flags1-global") == 0)
            flag = DF_1_GLOBAL;
        else if (strcmp(mode, "flags1-group") == 0)
            flag = DF_1_GROUP;
        else if (strcmp(mode, "flags1-initfirst") == 0)
            flag = DF_1_INITFIRST;
        else if (strcmp(mode, "flags1-globaudit") == 0)
            flag = DF_1_GLOBAUDIT;
        else
            return 64;
        entry = dynamic_tag(image, DT_FLAGS_1);
        if (!entry)
            entry = dynamic_tag(image, DT_DEBUG);
        if (!entry)
            return 77;
        entry->d_tag = DT_FLAGS_1;
        entry->d_un.d_val |= flag;
        return 0;
    }

    if (strcmp(mode, "syment") == 0) {
        entry = dynamic_tag(image, DT_SYMENT);
        if (!entry)
            return 77;
        entry->d_un.d_val = sizeof(Elf64_Sym) - 1;
        return 0;
    }
    if (strcmp(mode, "sysv-hash") == 0) {
        entry = dynamic_tag(image, DT_HASH);
        if (!entry)
            return 77;
        entry->d_un.d_ptr = bad_address;
        return 0;
    }
    if (strcmp(mode, "gnu-hash") == 0) {
        entry = dynamic_tag(image, DT_GNU_HASH);
        if (!entry)
            return 77;
        entry->d_un.d_ptr = bad_address;
        return 0;
    }
    if (strcmp(mode, "gnu-count") == 0) {
        uint32_t *header;

        entry = dynamic_tag(image, DT_GNU_HASH);
        if (!entry)
            return 77;
        header = vaddr_file(image, entry->d_un.d_ptr,
                            4 * sizeof(uint32_t));
        if (!header)
            return 77;
        header[0] = UINT32_MAX;
        return 0;
    }
    if (strcmp(mode, "versym") == 0) {
        entry = dynamic_tag(image, DT_VERSYM);
        if (!entry)
            entry = dynamic_tag(image, DT_DEBUG);
        if (!entry)
            return 77;
        entry->d_tag = DT_VERSYM;
        entry->d_un.d_ptr = bad_address;
        return 0;
    }
    if (strcmp(mode, "symtab") == 0) {
        entry = dynamic_tag(image, DT_SYMTAB);
        if (!entry)
            return 77;
        entry->d_un.d_ptr = bad_address;
        return 0;
    }
    if (strcmp(mode, "relocation-offset") == 0) {
        Elf64_Rela *relocation = first_relocation(image, 0);

        if (!relocation)
            return 77;
        relocation->r_offset = bad_address;
        return 0;
    }
    if (strcmp(mode, "symbol-index") == 0) {
        Elf64_Rela *relocation = first_relocation(image, 0);
        uint32_t type;

        if (!relocation)
            return 77;
        type = ELF64_R_TYPE(relocation->r_info);
        relocation->r_info = ELF64_R_INFO(UINT32_MAX, type);
        return 0;
    }
    if (strcmp(mode, "symbol-name") == 0) {
        Elf64_Rela *relocation = first_relocation(image, 1);
        Elf64_Dyn *symtab = dynamic_tag(image, DT_SYMTAB);
        Elf64_Dyn *strsz = dynamic_tag(image, DT_STRSZ);
        uint32_t symbol_index;
        uint64_t symbol_delta;
        Elf64_Sym *symbol;

        if (!relocation || !symtab || !strsz)
            return 77;
        symbol_index = ELF64_R_SYM(relocation->r_info);
        symbol_delta = (uint64_t)symbol_index * sizeof(Elf64_Sym);
        if (symtab->d_un.d_ptr > UINT64_MAX - symbol_delta)
            return 77;
        symbol = vaddr_file(image, symtab->d_un.d_ptr + symbol_delta,
                            sizeof(*symbol));
        if (!symbol || strsz->d_un.d_val > UINT32_MAX)
            return 77;
        symbol->st_name = (uint32_t)strsz->d_un.d_val;
        /* Keep the malformed symbol metadata on the prelink/runtime path.
         * With section headers present, the independent section gate rejects
         * it before the prelink transaction is started. */
        image->ehdr->e_shoff = 0;
        image->ehdr->e_shnum = 0;
        image->ehdr->e_shstrndx = SHN_UNDEF;
        return 0;
    }
    return 64;
}

int main(int argc, char **argv)
{
    struct elf_image image = {0};
    struct stat st;
    int fd = -1;
    int result = 1;

    if (argc != 3)
        return 64;
    fd = open(argv[2], O_RDWR | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) < 0 || st.st_size < 0 ||
        (uintmax_t)st.st_size > SIZE_MAX)
        goto out;
    image.size = (size_t)st.st_size;
    image.data = mmap(NULL, image.size, PROT_READ | PROT_WRITE,
                      MAP_SHARED, fd, 0);
    if (image.data == MAP_FAILED) {
        image.data = NULL;
        goto out;
    }
    if (image.size < sizeof(Elf64_Ehdr))
        goto out;
    image.ehdr = (Elf64_Ehdr *)image.data;
    if (memcmp(image.ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        image.ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        image.ehdr->e_phentsize != sizeof(Elf64_Phdr) ||
        !range_fits(image.ehdr->e_phoff,
                    (uint64_t)image.ehdr->e_phnum * sizeof(Elf64_Phdr),
                    image.size))
        goto out;
    image.phdr = (Elf64_Phdr *)(image.data + image.ehdr->e_phoff);
    for (uint16_t i = 0; i < image.ehdr->e_phnum; i++) {
        Elf64_Phdr *ph = &image.phdr[i];

        if (ph->p_type != PT_DYNAMIC)
            continue;
        if (image.dynamic || ph->p_filesz == 0 ||
            ph->p_filesz % sizeof(Elf64_Dyn) != 0 ||
            !range_fits(ph->p_offset, ph->p_filesz, image.size))
            goto out;
        image.dynamic = (Elf64_Dyn *)(image.data + ph->p_offset);
        image.dynamic_count = (size_t)ph->p_filesz / sizeof(Elf64_Dyn);
    }
    if (!image.dynamic)
        goto out;
    result = mutate(&image, argv[1]);
    if (result == 0 && msync(image.data, image.size, MS_SYNC) < 0)
        result = 1;

out:
    if (image.data)
        munmap(image.data, image.size);
    if (fd >= 0)
        close(fd);
    return result;
}
