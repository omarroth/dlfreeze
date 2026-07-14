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

static int mutate_program_header(const char *path, uint32_t target_type)
{
    struct stat st;
    struct dlfrz_footer *footer;
    struct dlfrz_entry *entries;
    uint8_t *map = MAP_FAILED;
    uint64_t size;
    int fd = -1;
    int rc = 1;

    fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) < 0 || st.st_size <= 0)
        goto out;
    size = (uint64_t)st.st_size;
    map = mmap(NULL, (size_t)size, PROT_READ | PROT_WRITE,
               MAP_SHARED, fd, 0);
    if (map == MAP_FAILED || size < sizeof(*footer))
        goto out;

    footer = (struct dlfrz_footer *)(map + size - sizeof(*footer));
    if (memcmp(footer->magic, DLFRZ_MAGIC, sizeof(footer->magic)) != 0 ||
        footer->version != DLFRZ_VERSION || footer->num_entries == 0 ||
        !range_fits(footer->manifest_offset,
                    (uint64_t)footer->num_entries * sizeof(*entries), size))
        goto out;
    entries = (struct dlfrz_entry *)(map + footer->manifest_offset);

    for (uint32_t i = 0; i < footer->num_entries; i++) {
        Elf64_Ehdr *eh;
        Elf64_Phdr *ph;
        Elf64_Phdr *target = NULL;
        uint64_t max_load_end = 0;
        uint64_t outside;

        if (!(entries[i].flags & DLFRZ_FLAG_MAIN_EXE) ||
            !range_fits(entries[i].data_offset, entries[i].data_size, size) ||
            entries[i].data_size < sizeof(*eh))
            continue;
        eh = (Elf64_Ehdr *)(map + entries[i].data_offset);
        if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
            eh->e_phentsize != sizeof(*ph) || eh->e_phnum == 0 ||
            !range_fits(eh->e_phoff,
                        (uint64_t)eh->e_phnum * sizeof(*ph),
                        entries[i].data_size))
            goto out;
        ph = (Elf64_Phdr *)((uint8_t *)eh + eh->e_phoff);
        for (uint16_t p = 0; p < eh->e_phnum; p++) {
            uint64_t end;

            if (ph[p].p_type == target_type) {
                if (target)
                    goto out;
                target = &ph[p];
            }
            if (ph[p].p_type != PT_LOAD ||
                ph[p].p_memsz > UINT64_MAX - ph[p].p_vaddr)
                continue;
            end = ph[p].p_vaddr + ph[p].p_memsz;
            if (end > max_load_end)
                max_load_end = end;
        }
        if (!target || target->p_memsz == 0 ||
            max_load_end > UINT64_MAX - 0x1fff)
            goto out;
        outside = (max_load_end + 0xfff) & ~(uint64_t)0xfff;
        outside += 0x1000;
        if (target->p_memsz > UINT64_MAX - outside)
            goto out;
        target->p_vaddr = outside;
        target->p_paddr = outside;
        if (msync(map, (size_t)size, MS_SYNC) < 0)
            goto out;
        rc = 0;
        goto out;
    }

out:
    if (map != MAP_FAILED)
        munmap(map, (size_t)size);
    if (fd >= 0)
        close(fd);
    return rc;
}

int main(int argc, char **argv)
{
    uint32_t type;

    if (argc != 3) {
        fprintf(stderr, "usage: %s --relro-outside|--eh-outside FILE\n",
                argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "--relro-outside") == 0)
        type = PT_GNU_RELRO;
    else if (strcmp(argv[1], "--eh-outside") == 0)
        type = PT_GNU_EH_FRAME;
    else
        return 2;
    return mutate_program_header(argv[2], type);
}
