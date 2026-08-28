#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "common.h"

#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static int range_fits(uint64_t offset, uint64_t length, uint64_t size)
{
    return offset <= size && length <= size - offset;
}

static void *elf_vaddr_file(uint8_t *data, size_t size,
                            const Elf64_Ehdr *ehdr, uint64_t address,
                            uint64_t length)
{
    const Elf64_Phdr *phdr;

    if (!range_fits(ehdr->e_phoff,
                    (uint64_t)ehdr->e_phnum * sizeof(*phdr), size))
        return NULL;
    phdr = (const Elf64_Phdr *)(data + ehdr->e_phoff);
    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        uint64_t delta;
        uint64_t offset;

        if (phdr[i].p_type != PT_LOAD || address < phdr[i].p_vaddr)
            continue;
        delta = address - phdr[i].p_vaddr;
        if (delta > phdr[i].p_filesz ||
            length > phdr[i].p_filesz - delta ||
            phdr[i].p_offset > UINT64_MAX - delta)
            continue;
        offset = phdr[i].p_offset + delta;
        if (range_fits(offset, length, size))
            return data + offset;
    }
    return NULL;
}

static int mutate_unknown_relocation(uint8_t *data, size_t size,
                                     const uint32_t *fixups,
                                     uint32_t fixup_off,
                                     uint32_t fixup_count,
                                     uint32_t *removed_out)
{
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Dyn *dynamic = NULL;
    size_t dynamic_count = 0;
    uint64_t rela_address[2] = {0, 0};
    uint64_t rela_bytes[2] = {0, 0};

#if defined(__x86_64__)
    const uint32_t absolute_type = R_X86_64_64;
    const uint32_t glob_dat_type = R_X86_64_GLOB_DAT;
    const uint32_t jump_slot_type = R_X86_64_JUMP_SLOT;
#elif defined(__aarch64__)
    const uint32_t absolute_type = R_AARCH64_ABS64;
    const uint32_t glob_dat_type = R_AARCH64_GLOB_DAT;
    const uint32_t jump_slot_type = R_AARCH64_JUMP_SLOT;
#else
    (void)data;
    (void)size;
    (void)fixups;
    (void)fixup_off;
    (void)fixup_count;
    (void)removed_out;
    return 77;
#endif

    if (!fixups || !removed_out || fixup_count == 0 ||
        size < sizeof(*ehdr))
        return 77;
    ehdr = (Elf64_Ehdr *)data;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr->e_phentsize != sizeof(*phdr) ||
        !range_fits(ehdr->e_phoff,
                    (uint64_t)ehdr->e_phnum * sizeof(*phdr), size))
        return 77;
    phdr = (Elf64_Phdr *)(data + ehdr->e_phoff);
    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_DYNAMIC)
            continue;
        if (dynamic || phdr[i].p_filesz == 0 ||
            phdr[i].p_filesz % sizeof(*dynamic) != 0 ||
            !range_fits(phdr[i].p_offset, phdr[i].p_filesz, size))
            return 77;
        dynamic = (Elf64_Dyn *)(data + phdr[i].p_offset);
        dynamic_count = (size_t)phdr[i].p_filesz / sizeof(*dynamic);
    }
    if (!dynamic)
        return 77;
    for (size_t i = 0; i < dynamic_count; i++) {
        if (dynamic[i].d_tag == DT_NULL)
            break;
        switch (dynamic[i].d_tag) {
        case DT_RELA:
            rela_address[0] = dynamic[i].d_un.d_ptr;
            break;
        case DT_RELASZ:
            rela_bytes[0] = dynamic[i].d_un.d_val;
            break;
        case DT_JMPREL:
            rela_address[1] = dynamic[i].d_un.d_ptr;
            break;
        case DT_PLTRELSZ:
            rela_bytes[1] = dynamic[i].d_un.d_val;
            break;
        default:
            break;
        }
    }
    for (size_t table = 0; table < 2; table++) {
        Elf64_Rela *relocations;
        size_t count;

        if (!rela_address[table] || rela_bytes[table] == 0 ||
            rela_bytes[table] % sizeof(*relocations) != 0)
            continue;
        relocations = elf_vaddr_file(data, size, ehdr,
                                     rela_address[table],
                                     rela_bytes[table]);
        if (!relocations)
            continue;
        count = (size_t)rela_bytes[table] / sizeof(*relocations);
        for (size_t i = 0; i < count; i++) {
            uint32_t type = ELF64_R_TYPE(relocations[i].r_info);
            uint32_t encoded;

            if (ELF64_R_SYM(relocations[i].r_info) == 0 ||
                (type != absolute_type && type != glob_dat_type &&
                 type != jump_slot_type) ||
                i > UINT32_MAX / 2)
                continue;
            encoded = (table ? UINT32_C(0x80000000) : 0) |
                      (uint32_t)i;
            for (uint32_t j = 0; j < fixup_count; j++) {
                if (fixups[fixup_off + j] != encoded)
                    continue;
                relocations[i].r_info = ELF64_R_INFO(
                    ELF64_R_SYM(relocations[i].r_info), UINT32_MAX);
                *removed_out = fixup_off + j;
                return 0;
            }
        }
    }
    return 77;
}

static int mutate_fixups(const char *mode, const char *path)
{
    struct stat st;
    struct dlfrz_footer *footer;
    struct dlfrz_entry *entries;
    struct dlfrz_lib_meta *metas;
    uint32_t *fixups;
    uint8_t *map = MAP_FAILED;
    uint64_t metadata_offset;
    uint64_t fixup_offset;
    uint64_t fixup_count;
    uint64_t size = 0;
    int fd = -1;
    int result = 1;

    fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) < 0 || st.st_size <= 0 ||
        (uintmax_t)st.st_size > SIZE_MAX)
        goto out;
    size = (uint64_t)st.st_size;
    map = mmap(NULL, (size_t)size, PROT_READ | PROT_WRITE,
               MAP_SHARED, fd, 0);
    if (map == MAP_FAILED || size < sizeof(*footer))
        goto out;

    footer = (struct dlfrz_footer *)(map + size - sizeof(*footer));
    if (memcmp(footer->magic, DLFRZ_MAGIC, sizeof(footer->magic)) != 0 ||
        footer->version != DLFRZ_VERSION || footer->num_entries == 0)
        goto out;
    memcpy(&metadata_offset, footer->pad, sizeof(metadata_offset));
    memcpy(&fixup_offset, footer->pad + 8, sizeof(fixup_offset));
    memcpy(&fixup_count, footer->pad + 16, sizeof(fixup_count));
    if (metadata_offset == 0 ||
        !range_fits(footer->manifest_offset,
                    (uint64_t)footer->num_entries * sizeof(*entries), size) ||
        !range_fits(metadata_offset,
                    (uint64_t)footer->num_entries * sizeof(*metas), size))
        goto out;
    entries = (struct dlfrz_entry *)(map + footer->manifest_offset);
    metas = (struct dlfrz_lib_meta *)(map + metadata_offset);

    if (fixup_offset == 0 || fixup_count == 0 ||
        fixup_count > UINT32_MAX ||
        fixup_count > UINT64_MAX / sizeof(*fixups) ||
        !range_fits(fixup_offset, fixup_count * sizeof(*fixups), size))
        goto out;
    fixups = (uint32_t *)(map + fixup_offset);

    if (strcmp(mode, "unknown-relocation") == 0) {
        for (uint32_t i = 0; i < footer->num_entries; i++) {
            int mutation;
            uint32_t removed;

            if ((metas[i].flags & DLFRZ_FLAG_PRELINKED) == 0 ||
                (metas[i].flags & (DLFRZ_FLAG_DATA | DLFRZ_FLAG_INTERP)) != 0 ||
                metas[i].runtime_fixup_count == 0 ||
                metas[i].runtime_fixup_off > fixup_count ||
                metas[i].runtime_fixup_count >
                    fixup_count - metas[i].runtime_fixup_off ||
                entries[i].data_size > SIZE_MAX ||
                !range_fits(entries[i].data_offset,
                            entries[i].data_size, size))
                continue;
            mutation = mutate_unknown_relocation(
                map + entries[i].data_offset, (size_t)entries[i].data_size,
                fixups, metas[i].runtime_fixup_off,
                metas[i].runtime_fixup_count, &removed);
            if (mutation == 77)
                continue;
            if (mutation != 0)
                goto out;
            memmove(&fixups[removed], &fixups[removed + 1],
                    ((size_t)fixup_count - removed - 1) * sizeof(*fixups));
            fixup_count--;
            memcpy(footer->pad + 16, &fixup_count, sizeof(fixup_count));
            metas[i].runtime_fixup_count--;
            if (metas[i].runtime_fixup_count == 0) {
                metas[i].runtime_fixup_off = 0;
                metas[i].flags &= ~DLFRZ_FLAG_RUNTIME_SCAN;
            }
            for (uint32_t j = 0; j < footer->num_entries; j++) {
                if (metas[j].runtime_fixup_count != 0 &&
                    metas[j].runtime_fixup_off > removed)
                    metas[j].runtime_fixup_off--;
            }
            if (msync(map, (size_t)size, MS_SYNC) < 0)
                goto out;
            result = 0;
            goto out;
        }
        result = 77;
        goto out;
    }

    if (fixup_count < 2)
        goto out;
    for (uint32_t i = 0; i < footer->num_entries; i++) {
        struct dlfrz_lib_meta *meta = &metas[i];
        uint32_t off = meta->runtime_fixup_off;
        uint32_t count = meta->runtime_fixup_count;
        uint32_t temporary;

        if ((meta->flags & DLFRZ_FLAG_PRELINKED) == 0 || count < 2 ||
            off > fixup_count || count > fixup_count - off)
            continue;
        if (strcmp(mode, "omit") == 0) {
            meta->runtime_fixup_count--;
        } else if (strcmp(mode, "duplicate") == 0) {
            fixups[off + 1] = fixups[off];
        } else if (strcmp(mode, "reorder") == 0) {
            temporary = fixups[off];
            fixups[off] = fixups[off + 1];
            fixups[off + 1] = temporary;
        } else {
            result = 64;
            goto out;
        }
        if (msync(map, (size_t)size, MS_SYNC) < 0)
            goto out;
        result = 0;
        goto out;
    }
    result = 77;

out:
    if (map != MAP_FAILED)
        munmap(map, (size_t)size);
    if (fd >= 0)
        close(fd);
    return result;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr,
                "usage: %s omit|duplicate|reorder|unknown-relocation FILE\n",
                argv[0]);
        return 64;
    }
    return mutate_fixups(argv[1], argv[2]);
}
