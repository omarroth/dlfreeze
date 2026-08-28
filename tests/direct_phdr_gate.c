#include "common.h"

#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PT_GNU_SFRAME
#define PT_GNU_SFRAME 0x6474e554
#endif

static int range_fits(uint64_t offset, uint64_t length, uint64_t size)
{
    return offset <= size && length <= size - offset;
}

/*
 * The direct-metadata fixture deliberately reserves one PT_NOTE for tests
 * which need to add a synthetic PT_LOAD.  Select that private reservation by
 * its complete note identity instead of borrowing a toolchain-provided GNU
 * property, ABI-tag, or build-id note.  Some valid musl links provide none of
 * those notes, and their presence/order is not part of the fixture contract.
 */
static int phdr_has_fixture_spare_note(const uint8_t *elf, uint64_t elf_size,
                                       const Elf64_Phdr *phdr)
{
    static const unsigned char owner[] = "DLFREEZE";
    static const unsigned char descriptor[] = "PHDRTEST";
    const uint32_t fixture_note_type = 0x44504844;
    size_t position;
    size_t end;

    if (phdr->p_type != PT_NOTE || phdr->p_offset > elf_size ||
        phdr->p_filesz > elf_size - phdr->p_offset ||
        phdr->p_offset > SIZE_MAX || phdr->p_filesz > SIZE_MAX)
        return 0;
    position = (size_t)phdr->p_offset;
    end = position + (size_t)phdr->p_filesz;
    while (position <= end && end - position >= sizeof(Elf64_Nhdr)) {
        Elf64_Nhdr note;
        size_t name_offset;
        size_t descriptor_offset;

        memcpy(&note, elf + position, sizeof(note));
        position += sizeof(note);
        name_offset = position;
        if (note.n_namesz > end - position)
            return 0;
        position += note.n_namesz;
        if (position > SIZE_MAX - 3)
            return 0;
        position = (position + 3) & ~(size_t)3;
        if (position > end)
            return 0;
        descriptor_offset = position;
        if (note.n_descsz > end - position)
            return 0;
        position += note.n_descsz;
        if (position > SIZE_MAX - 3)
            return 0;
        position = (position + 3) & ~(size_t)3;
        if (position > end)
            return 0;
        if (note.n_type == fixture_note_type &&
            note.n_namesz == sizeof(owner) - 1 &&
            note.n_descsz == sizeof(descriptor) - 1 &&
            memcmp(elf + name_offset, owner, sizeof(owner) - 1) == 0 &&
            memcmp(elf + descriptor_offset, descriptor,
                   sizeof(descriptor) - 1) == 0)
            return 1;
    }
    return 0;
}

static Elf64_Phdr *find_fixture_spare_note(uint8_t *elf, uint64_t elf_size,
                                           Elf64_Phdr *phdr,
                                           uint16_t phnum)
{
    Elf64_Phdr *spare = NULL;

    for (uint16_t i = 0; i < phnum; i++) {
        if (!phdr_has_fixture_spare_note(elf, elf_size, &phdr[i]))
            continue;
        if (spare)
            return NULL;
        spare = &phdr[i];
    }
    return spare;
}

static int mutate_program_header(const char *path, uint32_t target_type,
                                 int mutation)
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
        if (!target && (target_type == PT_GNU_EH_FRAME ||
                        target_type == PT_GNU_SFRAME)) {
            target = find_fixture_spare_note(
                (uint8_t *)eh, entries[i].data_size, ph, eh->e_phnum);
            if (target) {
                target->p_type = target_type;
                target->p_flags = PF_R;
            }
        }
        if (!target)
            goto out;
        if (mutation < 0) {
            memset(target, 0, sizeof(*target));
            if (msync(map, (size_t)size, MS_SYNC) < 0)
                goto out;
            rc = 0;
            goto out;
        }
        if (mutation > 0) {
            target->p_flags |= PF_X;
            if (msync(map, (size_t)size, MS_SYNC) < 0)
                goto out;
            rc = 0;
            goto out;
        }
        if (target->p_memsz == 0 ||
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

enum raw_program_header_mutation {
    RAW_PROGRAM_HEADER_REMOVE,
    RAW_PROGRAM_HEADER_MOVE_OUTSIDE,
};

static int mutate_raw_program_header(
    const char *path, uint32_t target_type,
    enum raw_program_header_mutation mutation)
{
    struct stat st;
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
    if (map == MAP_FAILED || size < sizeof(Elf64_Ehdr))
        goto out;

    Elf64_Ehdr *eh = (Elf64_Ehdr *)map;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        eh->e_phentsize != sizeof(Elf64_Phdr) || eh->e_phnum == 0 ||
        !range_fits(eh->e_phoff,
                    (uint64_t)eh->e_phnum * sizeof(Elf64_Phdr), size))
        goto out;

    Elf64_Phdr *ph = (Elf64_Phdr *)(map + eh->e_phoff);
    Elf64_Phdr *target = NULL;
    uint64_t max_load_end = 0;
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        uint64_t end;

        if (ph[i].p_type == target_type) {
            if (target)
                goto out;
            target = &ph[i];
        }
        if (ph[i].p_type == PT_LOAD) {
            if (ph[i].p_vaddr > UINT64_MAX - ph[i].p_memsz)
                goto out;
            end = ph[i].p_vaddr + ph[i].p_memsz;
            if (end > max_load_end)
                max_load_end = end;
        }
    }
    if (!target)
        goto out;
    if (mutation == RAW_PROGRAM_HEADER_REMOVE) {
        memset(target, 0, sizeof(*target));
    } else {
        uint64_t outside;

        if (target->p_memsz == 0 ||
            max_load_end > UINT64_MAX - 0x1fff)
            goto out;
        outside = (max_load_end + 0xfff) & ~(uint64_t)0xfff;
        outside += 0x1000;
        if (target->p_memsz > UINT64_MAX - outside)
            goto out;
        target->p_vaddr = outside;
        target->p_paddr = outside;
    }
    if (msync(map, (size_t)size, MS_SYNC) < 0)
        goto out;
    rc = 0;

out:
    if (map != MAP_FAILED)
        munmap(map, (size_t)size);
    if (fd >= 0)
        close(fd);
    return rc;
}

static int mutate_entry_to_nonexec(const char *path)
{
    struct stat st;
    struct dlfrz_footer *footer;
    struct dlfrz_entry *entries;
    struct dlfrz_lib_meta *metas;
    uint8_t *map = MAP_FAILED;
    uint64_t metadata_offset;
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
    memcpy(&metadata_offset, footer->pad, sizeof(metadata_offset));
    if (metadata_offset == 0 ||
        !range_fits(metadata_offset,
                    (uint64_t)footer->num_entries * sizeof(*metas), size))
        goto out;
    entries = (struct dlfrz_entry *)(map + footer->manifest_offset);
    metas = (struct dlfrz_lib_meta *)(map + metadata_offset);

    for (uint32_t i = 0; i < footer->num_entries; i++) {
        Elf64_Ehdr *eh;
        Elf64_Phdr *ph;

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
            if (ph[p].p_type != PT_LOAD || (ph[p].p_flags & PF_W) == 0 ||
                (ph[p].p_flags & PF_X) != 0 || ph[p].p_filesz == 0)
                continue;
            eh->e_entry = ph[p].p_vaddr;
            metas[i].entry = ph[p].p_vaddr;
            if (msync(map, (size_t)size, MS_SYNC) < 0)
                goto out;
            rc = 0;
            goto out;
        }
        goto out;
    }

out:
    if (map != MAP_FAILED)
        munmap(map, (size_t)size);
    if (fd >= 0)
        close(fd);
    return rc;
}

static int mutate_main_elf_header(const char *path, const char *field)
{
    struct stat st;
    struct dlfrz_footer *footer;
    struct dlfrz_entry *entries;
    uint8_t *map = MAP_FAILED;
    uint64_t size = 0;
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

        if (!(entries[i].flags & DLFRZ_FLAG_MAIN_EXE) ||
            !range_fits(entries[i].data_offset, entries[i].data_size, size) ||
            entries[i].data_size < sizeof(*eh))
            continue;
        eh = (Elf64_Ehdr *)(map + entries[i].data_offset);
        if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0)
            goto out;
        if (strcmp(field, "osabi") == 0)
            eh->e_ident[EI_OSABI] = ELFOSABI_FREEBSD;
        else if (strcmp(field, "abiversion") == 0)
            eh->e_ident[EI_ABIVERSION] = 1;
        else if (strcmp(field, "ident-pad") == 0)
            eh->e_ident[EI_PAD] = 1;
        else if (strcmp(field, "flags") == 0)
            eh->e_flags = 1;
        else if (strcmp(field, "type") == 0)
            eh->e_type = eh->e_type == ET_EXEC ? ET_DYN : ET_EXEC;
        else
            goto out;
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

static int mutate_ambiguous_phdr_mapping(const char *path)
{
    struct stat st;
    struct dlfrz_footer *footer;
    struct dlfrz_entry *entries;
    struct dlfrz_lib_meta *metas;
    uint8_t *map = MAP_FAILED;
    uint64_t metadata_offset;
    uint64_t size = 0;
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
    memcpy(&metadata_offset, footer->pad, sizeof(metadata_offset));
    if (metadata_offset == 0 ||
        !range_fits(metadata_offset,
                    (uint64_t)footer->num_entries * sizeof(*metas), size))
        goto out;
    entries = (struct dlfrz_entry *)(map + footer->manifest_offset);
    metas = (struct dlfrz_lib_meta *)(map + metadata_offset);

    for (uint32_t i = 0; i < footer->num_entries; i++) {
        Elf64_Ehdr *eh;
        Elf64_Phdr *ph;
        Elf64_Phdr *owner = NULL;
        Elf64_Phdr *spare = NULL;
        uint64_t phdr_bytes;
        uint64_t phdr_file_end;
        uint64_t shifted_vaddr;
        uint64_t needed;
        uint64_t last_candidate = UINT64_MAX;
        uint64_t first_candidate = UINT64_MAX;
        int ambiguous = 0;

        if (!(entries[i].flags & DLFRZ_FLAG_MAIN_EXE) ||
            !range_fits(entries[i].data_offset, entries[i].data_size, size) ||
            entries[i].data_size < sizeof(*eh))
            continue;
        eh = (Elf64_Ehdr *)(map + entries[i].data_offset);
        if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
            eh->e_phentsize != sizeof(*ph) || eh->e_phnum == 0)
            goto out;
        phdr_bytes = (uint64_t)eh->e_phnum * sizeof(*ph);
        if (!range_fits(eh->e_phoff, phdr_bytes, entries[i].data_size) ||
            eh->e_phoff > UINT64_MAX - phdr_bytes)
            goto out;
        phdr_file_end = eh->e_phoff + phdr_bytes;
        ph = (Elf64_Phdr *)((uint8_t *)eh + eh->e_phoff);

        spare = find_fixture_spare_note((uint8_t *)eh,
                                        entries[i].data_size,
                                        ph, eh->e_phnum);
        for (uint16_t p = 0; p < eh->e_phnum; p++) {
            if (!owner && ph[p].p_type == PT_LOAD &&
                eh->e_phoff >= ph[p].p_offset &&
                phdr_file_end - ph[p].p_offset <= ph[p].p_filesz)
                owner = &ph[p];
        }
        if (!owner || !spare || owner == spare ||
            owner->p_vaddr > UINT64_MAX - _Alignof(Elf64_Phdr))
            goto out;
        shifted_vaddr = owner->p_vaddr + _Alignof(Elf64_Phdr);
        needed = phdr_file_end - owner->p_offset;
        if (needed > UINT64_MAX - shifted_vaddr ||
            owner->p_vaddr > UINT64_MAX - owner->p_memsz ||
            shifted_vaddr + needed > owner->p_vaddr + owner->p_memsz)
            goto out;

        memset(spare, 0, sizeof(*spare));
        spare->p_type = PT_LOAD;
        spare->p_flags = PF_R;
        spare->p_offset = owner->p_offset;
        spare->p_vaddr = shifted_vaddr;
        spare->p_paddr = shifted_vaddr;
        spare->p_filesz = needed;
        spare->p_memsz = needed;
        spare->p_align = 1;

        /* Keep the metadata otherwise canonical under the old first/last
         * match behavior.  The hardened validator must reject the fact that
         * two loads produce different virtual addresses for the same bytes. */
        for (uint16_t p = 0; p < eh->e_phnum; p++) {
            uint64_t candidate;

            if (ph[p].p_type != PT_LOAD ||
                eh->e_phoff < ph[p].p_offset ||
                phdr_file_end - ph[p].p_offset > ph[p].p_filesz ||
                ph[p].p_vaddr >
                    UINT64_MAX - (eh->e_phoff - ph[p].p_offset))
                continue;
            candidate = ph[p].p_vaddr +
                        (eh->e_phoff - ph[p].p_offset);
            if (first_candidate == UINT64_MAX)
                first_candidate = candidate;
            else if (candidate != first_candidate)
                ambiguous = 1;
            last_candidate = candidate;
        }
        if (!ambiguous || last_candidate == UINT64_MAX ||
            last_candidate > UINT32_MAX)
            goto out;
        metas[i].phdr_off = (uint32_t)last_candidate;
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

static int mutate_zero_sized_load_placeholder(const char *path)
{
    struct stat st;
    struct dlfrz_footer *footer;
    struct dlfrz_entry *entries;
    uint8_t *map = MAP_FAILED;
    uint64_t size = 0;
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
        Elf64_Phdr *spare;
        uint64_t placeholder_vaddr = 0;
        int have_placeholder_vaddr = 0;

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
        spare = find_fixture_spare_note((uint8_t *)eh,
                                        entries[i].data_size,
                                        ph, eh->e_phnum);
        if (!spare)
            goto out;

        /* PT_LOAD entries must remain in ascending p_vaddr order even when
         * one entry maps no bytes.  Give the placeholder the address of the
         * nearest load on its left, or the nearest load on its right when the
         * reserved slot precedes every load.  Reusing an adjacent address is
         * harmless because p_memsz is zero and makes the fixture valid across
         * linkers that place the private PT_NOTE at different positions. */
        for (uint16_t p = 0; p < eh->e_phnum; p++) {
            if (&ph[p] == spare)
                break;
            if (ph[p].p_type == PT_LOAD) {
                placeholder_vaddr = ph[p].p_vaddr;
                have_placeholder_vaddr = 1;
            }
        }
        if (!have_placeholder_vaddr) {
            for (uint16_t p = (uint16_t)(spare - ph + 1);
                 p < eh->e_phnum; p++) {
                if (ph[p].p_type != PT_LOAD)
                    continue;
                placeholder_vaddr = ph[p].p_vaddr;
                have_placeholder_vaddr = 1;
                break;
            }
        }
        if (!have_placeholder_vaddr)
            goto out;
        memset(spare, 0, sizeof(*spare));
        spare->p_type = PT_LOAD;
        spare->p_vaddr = placeholder_vaddr;
        spare->p_paddr = placeholder_vaddr;
        spare->p_align = 1;
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

static int mutate_overlapping_load(const char *path)
{
    struct stat st;
    struct dlfrz_footer *footer;
    struct dlfrz_entry *entries;
    uint8_t *map = MAP_FAILED;
    uint64_t size = 0;
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
        Elf64_Phdr *owner = NULL;
        Elf64_Phdr *spare = NULL;

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
        spare = find_fixture_spare_note((uint8_t *)eh,
                                        entries[i].data_size,
                                        ph, eh->e_phnum);
        for (uint16_t p = 0; p < eh->e_phnum; p++) {
            if (!owner && ph[p].p_type == PT_LOAD && ph[p].p_memsz != 0)
                owner = &ph[p];
        }
        if (!owner || !spare || owner == spare)
            goto out;
        *spare = *owner;
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

enum metadata_mutation {
    METADATA_DATA_PRELINKED,
    METADATA_DATA_PHDR,
    METADATA_DATA_EMPTY_FIXUP_OFFSET,
    METADATA_RUNTIME_RELOCATED_FIXUPS,
    METADATA_EXTERNAL_PHDR_PROVENANCE,
};

static int mutate_noncanonical_metadata(const char *path,
                                        enum metadata_mutation mutation)
{
    struct stat st;
    struct dlfrz_footer *footer;
    struct dlfrz_entry *entries;
    struct dlfrz_lib_meta *metas;
    uint8_t *map = MAP_FAILED;
    uint64_t metadata_offset;
    uint64_t fixup_count;
    uint64_t size = 0;
    int changed = 0;
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
    memcpy(&metadata_offset, footer->pad, sizeof(metadata_offset));
    memcpy(&fixup_count, footer->pad + 16, sizeof(fixup_count));
    if (metadata_offset == 0 ||
        !range_fits(metadata_offset,
                    (uint64_t)footer->num_entries * sizeof(*metas), size))
        goto out;
    entries = (struct dlfrz_entry *)(map + footer->manifest_offset);
    metas = (struct dlfrz_lib_meta *)(map + metadata_offset);

    if (mutation == METADATA_RUNTIME_RELOCATED_FIXUPS) {
        for (uint32_t i = 0; i < footer->num_entries; i++) {
            if ((metas[i].flags & DLFRZ_FLAG_PRELINKED) == 0)
                continue;
            if (metas[i].runtime_fixup_count != 0)
                changed = 1;
            metas[i].flags &= ~(DLFRZ_FLAG_PRELINKED |
                                DLFRZ_FLAG_RUNTIME_SCAN);
        }
    } else if (mutation == METADATA_EXTERNAL_PHDR_PROVENANCE) {
        for (uint32_t i = 0; i < footer->num_entries; i++) {
            if (metas[i].phdr_off != DLFRZ_PHDR_EXTERNAL ||
                metas[i].phdr_file_off == UINT64_MAX)
                continue;
            metas[i].phdr_file_off++;
            changed = 1;
            break;
        }
    } else {
        for (uint32_t i = 0; i < footer->num_entries; i++) {
            if ((entries[i].flags & DLFRZ_FLAG_DATA) == 0)
                continue;
            if (mutation == METADATA_DATA_PRELINKED) {
                metas[i].flags |= DLFRZ_FLAG_PRELINKED;
            } else if (mutation == METADATA_DATA_PHDR) {
                metas[i].phdr_off = 8;
            } else {
                if (fixup_count == 0 || fixup_count > UINT32_MAX)
                    goto out;
                metas[i].runtime_fixup_off = (uint32_t)fixup_count;
            }
            changed = 1;
            break;
        }
    }
    if (!changed || msync(map, (size_t)size, MS_SYNC) < 0)
        goto out;
    rc = 0;

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
        fprintf(stderr,
                "usage: %s --relro-outside|--eh-outside|--sframe-outside|"
                "--entry-nonexec|"
                "--phdr-ambiguous|--zero-load|--overlap-load|"
                "--stack-exec|--stack-missing|--raw-stack-missing|"
                "--dynamic-outside|--raw-dynamic-outside|"
                "--data-prelinked|--data-phdr|"
                "--data-empty-fixup-offset|--runtime-relocated-fixups|"
                "--external-phdr-provenance|"
                "--elf-osabi|--elf-abiversion|--elf-ident-pad|"
                "--elf-flags|--elf-type FILE\n",
                argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "--entry-nonexec") == 0)
        return mutate_entry_to_nonexec(argv[2]);
    if (strcmp(argv[1], "--phdr-ambiguous") == 0)
        return mutate_ambiguous_phdr_mapping(argv[2]);
    if (strcmp(argv[1], "--zero-load") == 0)
        return mutate_zero_sized_load_placeholder(argv[2]);
    if (strcmp(argv[1], "--overlap-load") == 0)
        return mutate_overlapping_load(argv[2]);
    if (strcmp(argv[1], "--stack-exec") == 0)
        return mutate_program_header(argv[2], PT_GNU_STACK, 1);
    if (strcmp(argv[1], "--stack-missing") == 0)
        return mutate_program_header(argv[2], PT_GNU_STACK, -1);
    if (strcmp(argv[1], "--raw-stack-missing") == 0)
        return mutate_raw_program_header(
            argv[2], PT_GNU_STACK, RAW_PROGRAM_HEADER_REMOVE);
    if (strcmp(argv[1], "--dynamic-outside") == 0)
        return mutate_program_header(argv[2], PT_DYNAMIC, 0);
    if (strcmp(argv[1], "--raw-dynamic-outside") == 0)
        return mutate_raw_program_header(
            argv[2], PT_DYNAMIC, RAW_PROGRAM_HEADER_MOVE_OUTSIDE);
    if (strcmp(argv[1], "--data-prelinked") == 0)
        return mutate_noncanonical_metadata(argv[2],
                                             METADATA_DATA_PRELINKED);
    if (strcmp(argv[1], "--data-phdr") == 0)
        return mutate_noncanonical_metadata(argv[2], METADATA_DATA_PHDR);
    if (strcmp(argv[1], "--data-empty-fixup-offset") == 0)
        return mutate_noncanonical_metadata(
            argv[2], METADATA_DATA_EMPTY_FIXUP_OFFSET);
    if (strcmp(argv[1], "--runtime-relocated-fixups") == 0)
        return mutate_noncanonical_metadata(
            argv[2], METADATA_RUNTIME_RELOCATED_FIXUPS);
    if (strcmp(argv[1], "--external-phdr-provenance") == 0)
        return mutate_noncanonical_metadata(
            argv[2], METADATA_EXTERNAL_PHDR_PROVENANCE);
    if (strncmp(argv[1], "--elf-", sizeof("--elf-") - 1) == 0)
        return mutate_main_elf_header(
            argv[2], argv[1] + sizeof("--elf-") - 1);
    if (strcmp(argv[1], "--relro-outside") == 0)
        type = PT_GNU_RELRO;
    else if (strcmp(argv[1], "--eh-outside") == 0)
        type = PT_GNU_EH_FRAME;
    else if (strcmp(argv[1], "--sframe-outside") == 0)
        type = PT_GNU_SFRAME;
    else
        return 2;
    return mutate_program_header(argv[2], type, 0);
}
