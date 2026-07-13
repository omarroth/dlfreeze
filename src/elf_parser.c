#include "elf_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

static int range_in_file(uint64_t offset, uint64_t length, size_t size)
{
    return offset <= size && length <= size - offset;
}

static const char *dynamic_string(const char *strtab, size_t strtab_size,
                                  uint64_t offset)
{
    const char *value;

    if (offset >= strtab_size)
        return NULL;
    value = strtab + offset;
    if (!memchr(value, '\0', strtab_size - offset))
        return NULL;
    return value;
}

int elf_check(const char *path)
{
    unsigned char hdr[4];
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    int ok = (fread(hdr, 1, 4, f) == 4 &&
              hdr[0] == 0x7f && hdr[1] == 'E' &&
              hdr[2] == 'L'  && hdr[3] == 'F');
    fclose(f);
    return ok;
}

/* ---- 64-bit parser ---------------------------------------------------- */

static int parse_elf64(const uint8_t *data, size_t size, struct elf_info *info)
{
    if (size < sizeof(Elf64_Ehdr)) return -1;
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)data;

    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
        ehdr->e_version != EV_CURRENT ||
        ehdr->e_ehsize != sizeof(*ehdr) ||
        ehdr->e_phentsize != sizeof(Elf64_Phdr))
        return -1;

    info->ei_class  = ELFCLASS64;
    info->e_machine = ehdr->e_machine;
    info->is_pie    = (ehdr->e_type == ET_DYN);

    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) return -1;
    if (!range_in_file(ehdr->e_phoff,
                       (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr), size))
        return -1;

    const Elf64_Phdr *phdr = (const Elf64_Phdr *)(data + ehdr->e_phoff);

    const Elf64_Dyn *dyn_section = NULL;
    size_t dyn_count = 0;

    /* First pass: PT_INTERP + PT_DYNAMIC */
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_INTERP) {
            const uint8_t *value;
            size_t len;

            if (phdr[i].p_filesz == 0 ||
                !range_in_file(phdr[i].p_offset, phdr[i].p_filesz, size))
                return -1;
            value = data + phdr[i].p_offset;
            if (!memchr(value, '\0', phdr[i].p_filesz))
                return -1;
            len = strnlen((const char *)value, phdr[i].p_filesz);
            if (len >= sizeof(info->interp))
                return -1;
            memcpy(info->interp, value, len + 1);
        }
        if (phdr[i].p_type == PT_DYNAMIC) {
            info->is_dynamic = 1;
            if (phdr[i].p_filesz % sizeof(Elf64_Dyn) != 0 ||
                !range_in_file(phdr[i].p_offset, phdr[i].p_filesz, size))
                return -1;
            dyn_section = (const Elf64_Dyn *)(data + phdr[i].p_offset);
            dyn_count   = phdr[i].p_filesz / sizeof(Elf64_Dyn);
        }
    }

    if (!dyn_section) return 0;  /* static binary */

    /* Find the dynamic string table */
    uint64_t strtab_addr = 0;
    uint64_t declared_strtab_size = 0;
    for (size_t i = 0; i < dyn_count; i++) {
        if (dyn_section[i].d_tag == DT_STRTAB)
            strtab_addr = dyn_section[i].d_un.d_ptr;
        else if (dyn_section[i].d_tag == DT_STRSZ)
            declared_strtab_size = dyn_section[i].d_un.d_val;
        if (dyn_section[i].d_tag == DT_NULL) break;
    }
    if (strtab_addr == 0) return 0;

    /* Convert VA → file offset */
    const char *dyn_strtab = NULL;
    size_t dyn_strtab_size = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD &&
            strtab_addr >= phdr[i].p_vaddr &&
            strtab_addr - phdr[i].p_vaddr < phdr[i].p_filesz)
        {
            uint64_t off = phdr[i].p_offset + (strtab_addr - phdr[i].p_vaddr);
            uint64_t available = phdr[i].p_filesz -
                                 (strtab_addr - phdr[i].p_vaddr);

            if (!range_in_file(off, available, size))
                return -1;
            if (declared_strtab_size > available)
                return -1;
            dyn_strtab = (const char *)(data + off);
            dyn_strtab_size = declared_strtab_size
                ? (size_t)declared_strtab_size : (size_t)available;
            break;
        }
    }
    if (!dyn_strtab) return 0;

    /* Count DT_NEEDED */
    int needed_count = 0;
    for (size_t i = 0; i < dyn_count; i++) {
        if (dyn_section[i].d_tag == DT_NEEDED) needed_count++;
        if (dyn_section[i].d_tag == DT_NULL)   break;
    }

    info->needed = calloc(needed_count + 1, sizeof(char *));
    if (!info->needed) return -1;
    info->needed_count = needed_count;

    int idx = 0;
    for (size_t i = 0; i < dyn_count; i++) {
        if (dyn_section[i].d_tag == DT_NULL) break;
        const char *s;
        switch (dyn_section[i].d_tag) {
        case DT_NEEDED:
            s = dynamic_string(dyn_strtab, dyn_strtab_size,
                               dyn_section[i].d_un.d_val);
            if (!s || !(info->needed[idx] = strdup(s)))
                return -1;
            idx++;
            break;
        case DT_RPATH:
            s = dynamic_string(dyn_strtab, dyn_strtab_size,
                               dyn_section[i].d_un.d_val);
            if (!s || strlen(s) >= sizeof(info->rpath))
                return -1;
            strcpy(info->rpath, s);
            break;
        case DT_RUNPATH:
            s = dynamic_string(dyn_strtab, dyn_strtab_size,
                               dyn_section[i].d_un.d_val);
            if (!s || strlen(s) >= sizeof(info->runpath))
                return -1;
            strcpy(info->runpath, s);
            break;
        case DT_SONAME:
            s = dynamic_string(dyn_strtab, dyn_strtab_size,
                               dyn_section[i].d_un.d_val);
            if (!s || strlen(s) >= sizeof(info->soname))
                return -1;
            strcpy(info->soname, s);
            break;
        }
    }
    return 0;
}

/* ---- public API ------------------------------------------------------- */

int elf_parse(const char *path, struct elf_info *info)
{
    memset(info, 0, sizeof(*info));

    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); return -1; }

    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return -1; }
    if (st.st_size < (off_t)EI_NIDENT) { close(fd); return -1; }

    uint8_t *data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (data == MAP_FAILED) { perror("mmap"); return -1; }

    int ret = -1;
    if (memcmp(data, ELFMAG, SELFMAG) != 0) goto out;

    if (data[EI_CLASS] == ELFCLASS64)
        ret = parse_elf64(data, st.st_size, info);
    else
        fprintf(stderr, "dlfreeze: 32-bit ELF not yet supported\n");

out:
    munmap(data, st.st_size);
    if (ret < 0)
        elf_info_free(info);
    return ret;
}

void elf_info_free(struct elf_info *info)
{
    if (info->needed) {
        for (int i = 0; i < info->needed_count; i++)
            free(info->needed[i]);
        free(info->needed);
        info->needed = NULL;
    }
}
