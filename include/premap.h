#ifndef DLFREEZE_PREMAP_H
#define DLFREEZE_PREMAP_H

#include <elf.h>
#include <stddef.h>
#include <stdint.h>

/* Independent, opt-in outer-ELF ABI. The ordinary payload ABI is unchanged.
 * Staging PT_LOADs are R-only; p_paddr (unused by Linux userspace) records
 * the corresponding target address, never permission to overwrite it.
 * Only the ordinary, independently validated loader plan grants that right.
 * Keep the table below the old Linux 4 KiB ELF_MIN_ALIGN ceiling. */
#define DLFRZ_PREMAP_MAGIC "DLFRZPM1"
#define DLFRZ_PREMAP_MAX_PHDRS 73U
#define DLFRZ_PREMAP_LO UINT64_C(0x10000000)
#define DLFRZ_PREMAP_HI UINT64_C(0x3f000000)

struct dlfrz_premap_info {
    char magic[8];
    uint64_t phdr_vaddr;
    uint64_t phdr_count;
};

struct dlfrz_premap_range {
    uint64_t source, target, length, file_offset;
};

/* Pure producer/consumer admission, before any optional fixed mapping or
 * unmapping. Exactly one complete table owner, disjoint LOAD page ranges,
 * and max-page congruence are mandatory even on permissive kernels. */
static inline int dlfrz_premap_headers_valid(
    const Elf64_Phdr *ph, size_t count, uint64_t table_address,
    uint64_t file_size, uint64_t page)
{
    uint64_t previous_end = 0;
    size_t owners = 0, stages = 0;
    if (!ph || count < 5 || count > DLFRZ_PREMAP_MAX_PHDRS ||
        (page != 4096 && page != 65536) ||
        table_address < DLFRZ_PREMAP_LO ||
        table_address - DLFRZ_PREMAP_LO != ph[0].p_offset ||
        ph[1].p_type != PT_LOAD || ph[1].p_flags != PF_R ||
        ph[1].p_offset != 0 || ph[1].p_vaddr != DLFRZ_PREMAP_LO ||
        ph[1].p_paddr != DLFRZ_PREMAP_LO ||
        ph[1].p_filesz != page || ph[1].p_memsz != page ||
        ph[0].p_type != PT_PHDR || ph[0].p_flags != PF_R ||
        ph[0].p_vaddr != table_address ||
        ph[0].p_paddr != table_address ||
        ph[0].p_filesz != count * sizeof(*ph) ||
        ph[0].p_memsz != ph[0].p_filesz || ph[0].p_align != 8 ||
        ph[0].p_offset > file_size ||
        ph[0].p_filesz > file_size - ph[0].p_offset)
        return 0;
    for (size_t i = 1; i < count; i++) {
        const Elf64_Phdr *p = &ph[i];
        uint64_t start, end;
        if (p->p_type == PT_PHDR)
            return 0;
        if (p->p_type != PT_LOAD)
            continue;
        if (!p->p_memsz || p->p_filesz > p->p_memsz ||
            p->p_offset > file_size ||
            p->p_filesz > file_size - p->p_offset ||
            p->p_vaddr >= UINT64_C(0x800000000000) ||
            p->p_memsz > UINT64_C(0x800000000000) - p->p_vaddr ||
            p->p_align < page || (p->p_align & (p->p_align - 1)) ||
            ((p->p_offset ^ p->p_vaddr) & (p->p_align - 1)))
            return 0;
        start = p->p_vaddr & ~(page - 1);
        end = (p->p_vaddr + p->p_memsz + page - 1) & ~(page - 1);
        if (start < previous_end)
            return 0;
        previous_end = end;
        if (ph[0].p_offset >= p->p_offset &&
            ph[0].p_offset - p->p_offset < p->p_filesz) {
            uint64_t delta = ph[0].p_offset - p->p_offset;
            if (p->p_flags != PF_R ||
                ph[0].p_filesz > p->p_filesz - delta ||
                p->p_vaddr + delta != table_address)
                return 0;
            owners++;
        }
        if (p->p_paddr != p->p_vaddr) {
            if (p->p_flags != PF_R || p->p_memsz != p->p_filesz ||
                ((p->p_vaddr | p->p_paddr | p->p_offset |
                  p->p_filesz) & (page - 1)) ||
                start < DLFRZ_PREMAP_LO || end > DLFRZ_PREMAP_HI ||
                p->p_paddr >= UINT64_C(0x800000000000) ||
                p->p_memsz > UINT64_C(0x800000000000) - p->p_paddr)
                return 0;
            stages++;
        }
    }
    return owners == 1 && stages != 0;
}

#endif
