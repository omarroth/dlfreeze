#ifndef DLFREEZE_LOAD_SEGMENTS_H
#define DLFREEZE_LOAD_SEGMENTS_H

#include <elf.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* A mapped control segment such as PT_DYNAMIC must describe the same bytes
 * through both of its ELF coordinates and be wholly owned by one PT_LOAD:
 *
 *   subject.p_offset - load.p_offset ==
 *       subject.p_vaddr - load.p_vaddr
 *
 * Check the complete file-backed and memory ranges with subtraction-based
 * bounds so hostile end values cannot wrap.  The byte-table form also keeps
 * callers with an unaligned on-disk e_phoff free of typed-load UB. */
static inline int dlfrz_segment_is_contained_by_load_bytes(
    const uint8_t *phdr, size_t phnum, size_t phentsize,
    const Elf64_Phdr *subject_pointer)
{
    Elf64_Phdr subject;

    if (!phdr || !subject_pointer ||
        phentsize != sizeof(Elf64_Phdr) ||
        phnum > SIZE_MAX / phentsize)
        return 0;
    memcpy(&subject, subject_pointer, sizeof(subject));
    if (subject.p_filesz > subject.p_memsz ||
        subject.p_offset > UINT64_MAX - subject.p_filesz ||
        subject.p_vaddr > UINT64_MAX - subject.p_memsz)
        return 0;

    for (size_t i = 0; i < phnum; i++) {
        Elf64_Phdr load;
        uint64_t file_delta;
        uint64_t memory_delta;

        memcpy(&load, phdr + i * phentsize, sizeof(load));
        if (load.p_type != PT_LOAD)
            continue;
        if (load.p_filesz > load.p_memsz ||
            load.p_offset > UINT64_MAX - load.p_filesz ||
            load.p_vaddr > UINT64_MAX - load.p_memsz ||
            subject.p_offset < load.p_offset ||
            subject.p_vaddr < load.p_vaddr)
            continue;
        file_delta = subject.p_offset - load.p_offset;
        memory_delta = subject.p_vaddr - load.p_vaddr;
        if (file_delta != memory_delta ||
            file_delta > load.p_filesz ||
            subject.p_filesz > load.p_filesz - file_delta ||
            memory_delta > load.p_memsz ||
            subject.p_memsz > load.p_memsz - memory_delta)
            continue;
        return 1;
    }
    return 0;
}

static inline int dlfrz_segment_is_contained_by_load(
    const Elf64_Phdr *phdr, size_t phnum,
    const Elf64_Phdr *subject)
{
    return dlfrz_segment_is_contained_by_load_bytes(
        (const uint8_t *)phdr, phnum, sizeof(*phdr), subject);
}

/* The gABI requires PT_LOAD entries to appear in ascending p_vaddr order.
 * Sequential MAP_FIXED mappings are also order-dependent when distinct
 * entries cover the same runtime page: their file translations, BSS tails,
 * and final permissions can disagree even though each header is valid in
 * isolation.  Direct mode therefore admits only a single owner per page and
 * validates both properties in one pass; unusual native-loader layouts fall
 * back instead of depending on header order. */
static inline int dlfrz_load_pages_do_not_overlap_bytes(
    const uint8_t *phdr, size_t phnum, size_t phentsize,
    uint64_t page_size)
{
    uint64_t previous_load_vaddr = 0;
    uint64_t previous_page_end = 0;
    int saw_load = 0;
    int saw_nonempty_load = 0;

    if (!phdr || phentsize != sizeof(Elf64_Phdr) ||
        page_size < 4096 || page_size > 65536 ||
        (page_size & (page_size - 1)) != 0 ||
        phnum > SIZE_MAX / phentsize)
        return 0;

    for (size_t i = 0; i < phnum; i++) {
        Elf64_Phdr load;
        uint64_t page_start;
        uint64_t end_value;
        uint64_t page_end;

        memcpy(&load, phdr + i * phentsize, sizeof(load));
        if (load.p_type != PT_LOAD)
            continue;

        if (saw_load && load.p_vaddr < previous_load_vaddr)
            return 0;
        previous_load_vaddr = load.p_vaddr;
        saw_load = 1;

        if (load.p_memsz == 0)
            continue;
        if (load.p_vaddr > UINT64_MAX - load.p_memsz)
            return 0;
        page_start = load.p_vaddr & ~(page_size - 1);
        end_value = load.p_vaddr + load.p_memsz;
        if (end_value > UINT64_MAX - (page_size - 1))
            return 0;
        page_end = (end_value + page_size - 1) & ~(page_size - 1);

        if (saw_nonempty_load && page_start < previous_page_end)
            return 0;
        previous_page_end = page_end;
        saw_nonempty_load = 1;
    }
    return 1;
}

static inline int dlfrz_load_pages_do_not_overlap(const Elf64_Phdr *phdr,
                                                   size_t phnum,
                                                   uint64_t page_size)
{
    return dlfrz_load_pages_do_not_overlap_bytes(
        (const uint8_t *)phdr, phnum, sizeof(*phdr), page_size);
}

#endif
