#include "elf_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

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

    info->ei_class  = ELFCLASS64;
    info->e_machine = ehdr->e_machine;
    info->is_pie    = (ehdr->e_type == ET_DYN);

    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) return -1;
    if (ehdr->e_phoff + (uint64_t)ehdr->e_phnum * ehdr->e_phentsize > size) return -1;

    const Elf64_Phdr *phdr = (const Elf64_Phdr *)(data + ehdr->e_phoff);

    const Elf64_Dyn *dyn_section = NULL;
    size_t dyn_count = 0;

    /* First pass: PT_INTERP + PT_DYNAMIC */
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_INTERP) {
            if (phdr[i].p_offset + phdr[i].p_filesz <= size) {
                size_t len = phdr[i].p_filesz;
                if (len >= sizeof(info->interp)) len = sizeof(info->interp) - 1;
                memcpy(info->interp, data + phdr[i].p_offset, len);
                info->interp[len] = '\0';
                /* strip trailing NUL already embedded in the segment */
                size_t slen = strlen(info->interp);
                if (slen > 0 && info->interp[slen-1] == '\n') info->interp[--slen] = '\0';
            }
        }
        if (phdr[i].p_type == PT_DYNAMIC) {
            info->is_dynamic = 1;
            if (phdr[i].p_offset + phdr[i].p_filesz <= size) {
                dyn_section = (const Elf64_Dyn *)(data + phdr[i].p_offset);
                dyn_count   = phdr[i].p_filesz / sizeof(Elf64_Dyn);
            }
        }
    }

    if (!dyn_section) return 0;  /* static binary */

    /* Find the dynamic string table */
    uint64_t strtab_addr = 0;
    for (size_t i = 0; i < dyn_count; i++) {
        if (dyn_section[i].d_tag == DT_STRTAB) {
            strtab_addr = dyn_section[i].d_un.d_ptr;
            break;
        }
        if (dyn_section[i].d_tag == DT_NULL) break;
    }
    if (strtab_addr == 0) return 0;

    /* Convert VA → file offset */
    const char *dyn_strtab = NULL;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD &&
            strtab_addr >= phdr[i].p_vaddr &&
            strtab_addr <  phdr[i].p_vaddr + phdr[i].p_filesz)
        {
            uint64_t off = phdr[i].p_offset + (strtab_addr - phdr[i].p_vaddr);
            if (off < size) dyn_strtab = (const char *)(data + off);
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
            s = dyn_strtab + dyn_section[i].d_un.d_val;
            info->needed[idx++] = strdup(s);
            break;
        case DT_RPATH:
            s = dyn_strtab + dyn_section[i].d_un.d_val;
            strncpy(info->rpath, s, sizeof(info->rpath) - 1);
            break;
        case DT_RUNPATH:
            s = dyn_strtab + dyn_section[i].d_un.d_val;
            strncpy(info->runpath, s, sizeof(info->runpath) - 1);
            break;
        case DT_SONAME:
            s = dyn_strtab + dyn_section[i].d_un.d_val;
            strncpy(info->soname, s, sizeof(info->soname) - 1);
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
