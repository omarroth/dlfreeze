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

static const void *elf64_vaddr_file(const uint8_t *data, size_t size,
                                    const Elf64_Phdr *phdr, uint16_t phnum,
                                    uint64_t vaddr, uint64_t length)
{
    for (uint16_t i = 0; i < phnum; i++) {
        uint64_t delta;
        uint64_t offset;

        if (phdr[i].p_type != PT_LOAD || vaddr < phdr[i].p_vaddr)
            continue;
        delta = vaddr - phdr[i].p_vaddr;
        if (delta > phdr[i].p_filesz ||
            length > phdr[i].p_filesz - delta ||
            phdr[i].p_offset > UINT64_MAX - delta)
            continue;
        offset = phdr[i].p_offset + delta;
        if (!range_in_file(offset, length, size))
            return NULL;
        return data + offset;
    }
    return NULL;
}

static int elf64_tpoff_relocation(uint16_t machine, uint32_t type)
{
#ifdef R_X86_64_TPOFF64
    if (machine == EM_X86_64 && type == R_X86_64_TPOFF64)
        return 1;
#endif
#ifdef R_AARCH64_TLS_TPREL
    if (machine == EM_AARCH64 && type == R_AARCH64_TLS_TPREL)
        return 1;
#endif
    return 0;
}

static int elf64_rela_has_tpoff(const uint8_t *data, size_t size,
                                const Elf64_Ehdr *ehdr,
                                const Elf64_Phdr *phdr,
                                uint64_t address, uint64_t bytes,
                                uint64_t entsz, int *found_out)
{
    const uint8_t *rela;
    size_t count;

    if (bytes == 0)
        return 0;
    if (address == 0 || entsz != sizeof(Elf64_Rela) ||
        bytes % sizeof(Elf64_Rela) != 0 || bytes > SIZE_MAX)
        return -1;
    rela = elf64_vaddr_file(data, size, phdr, ehdr->e_phnum,
                           address, bytes);
    if (!rela)
        return -1;
    count = (size_t)(bytes / sizeof(Elf64_Rela));
    for (size_t i = 0; i < count; i++) {
        Elf64_Xword r_info;

        memcpy(&r_info,
               rela + i * sizeof(Elf64_Rela) + offsetof(Elf64_Rela, r_info),
               sizeof(r_info));
        if (elf64_tpoff_relocation(ehdr->e_machine,
                                   ELF64_R_TYPE(r_info))) {
            *found_out = 1;
            break;
        }
    }
    return 0;
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
    unsigned int tls_count = 0;

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
        if (phdr[i].p_type == PT_TLS) {
            if (++tls_count != 1 || phdr[i].p_filesz > phdr[i].p_memsz)
                return -1;
            info->tls_memsz = phdr[i].p_memsz;
        }
    }

    if (!dyn_section) return 0;  /* static binary */

    /* Find the dynamic string table */
    uint64_t strtab_addr = 0;
    uint64_t declared_strtab_size = 0;
    uint64_t rela_addr = 0;
    uint64_t rela_size = 0;
    uint64_t rela_ent = sizeof(Elf64_Rela);
    uint64_t jmprel_addr = 0;
    uint64_t pltrel_size = 0;
    uint64_t pltrel_kind = DT_RELA;
    int has_df_static_tls = 0;
    int has_tpoff = 0;
    for (size_t i = 0; i < dyn_count; i++) {
        if (dyn_section[i].d_tag == DT_STRTAB)
            strtab_addr = dyn_section[i].d_un.d_ptr;
        else if (dyn_section[i].d_tag == DT_STRSZ)
            declared_strtab_size = dyn_section[i].d_un.d_val;
        else if (dyn_section[i].d_tag == DT_RELA)
            rela_addr = dyn_section[i].d_un.d_ptr;
        else if (dyn_section[i].d_tag == DT_RELASZ)
            rela_size = dyn_section[i].d_un.d_val;
        else if (dyn_section[i].d_tag == DT_RELAENT)
            rela_ent = dyn_section[i].d_un.d_val;
        else if (dyn_section[i].d_tag == DT_JMPREL)
            jmprel_addr = dyn_section[i].d_un.d_ptr;
        else if (dyn_section[i].d_tag == DT_PLTRELSZ)
            pltrel_size = dyn_section[i].d_un.d_val;
        else if (dyn_section[i].d_tag == DT_PLTREL)
            pltrel_kind = dyn_section[i].d_un.d_val;
        else if (dyn_section[i].d_tag == DT_FLAGS &&
                 (dyn_section[i].d_un.d_val & DF_STATIC_TLS) != 0)
            has_df_static_tls = 1;
        if (dyn_section[i].d_tag == DT_NULL) break;
    }
    if (elf64_rela_has_tpoff(data, size, ehdr, phdr, rela_addr, rela_size,
                             rela_ent, &has_tpoff) < 0)
        return -1;
    if (pltrel_size != 0 &&
        (pltrel_kind != DT_RELA ||
         elf64_rela_has_tpoff(data, size, ehdr, phdr, jmprel_addr,
                              pltrel_size, sizeof(Elf64_Rela),
                              &has_tpoff) < 0))
        return -1;
    /* A TPOFF relocation constrains the defining TLS module, not
     * necessarily the object that contains the relocation.  A requester
     * with no PT_TLS of its own can therefore force a dependency's TLS into
     * the static layout.  DF_STATIC_TLS by itself only describes a useful
     * constraint when this object has a non-empty TLS template. */
    info->has_static_tls = has_tpoff ||
                           (info->tls_memsz != 0 && has_df_static_tls);
    if (strtab_addr == 0) return 0;

    /* Convert VA → file offset */
    const char *dyn_strtab = NULL;
    size_t dyn_strtab_size = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        uint64_t available;

        if (phdr[i].p_type != PT_LOAD ||
            strtab_addr < phdr[i].p_vaddr ||
            strtab_addr - phdr[i].p_vaddr >= phdr[i].p_filesz)
            continue;
        available = phdr[i].p_filesz -
                    (strtab_addr - phdr[i].p_vaddr);
        if (declared_strtab_size > available)
            return -1;
        dyn_strtab = elf64_vaddr_file(
            data, size, phdr, ehdr->e_phnum, strtab_addr,
            declared_strtab_size ? declared_strtab_size : available);
        if (!dyn_strtab)
            return -1;
        dyn_strtab_size = declared_strtab_size
            ? (size_t)declared_strtab_size : (size_t)available;
        break;
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
