#include "premap.h"
#include <assert.h>
#include <string.h>

static Elf64_Phdr headers[DLFRZ_PREMAP_MAX_PHDRS + 1];

static void fixture(size_t count, uint64_t page)
{
    memset(headers, 0, sizeof(headers));
    headers[0] = (Elf64_Phdr){PT_PHDR, PF_R, 0x80000, 0x10080000,
        0x10080000, count * sizeof(Elf64_Phdr), count * sizeof(Elf64_Phdr), 8};
    headers[1] = (Elf64_Phdr){PT_LOAD, PF_R, 0, 0x10000000,
        0x10000000, page, page, page};
    headers[2] = (Elf64_Phdr){PT_LOAD, PF_R, 0x10000, 0x10010000,
        0x200000000, 0x20000, 0x20000, page};
    headers[3] = (Elf64_Phdr){PT_LOAD, PF_R, 0x80000, 0x10080000,
        0x10080000, count * sizeof(Elf64_Phdr), count * sizeof(Elf64_Phdr), page};
    headers[4] = (Elf64_Phdr){PT_LOAD, PF_R, 0, 0x40000000,
        0x40000000, 0x10000, 0x10000, page};
}

static int valid(size_t count, uint64_t page)
{
    return dlfrz_premap_headers_valid(headers, count, 0x10080000,
                                      0x90000, page);
}

int main(void)
{
    for (uint64_t page = 4096; page <= 65536; page *= 16) {
        fixture(5, page); assert(valid(5, page));
        fixture(73, page); assert(valid(73, page));
        fixture(74, page); assert(!valid(74, page));
        fixture(5, page); headers[1].p_type = PT_NULL; assert(!valid(5, page));
        fixture(5, page); headers[2].p_flags |= PF_W; assert(!valid(5, page));
        fixture(5, page); headers[2].p_flags |= PF_X; assert(!valid(5, page));
        fixture(5, page); headers[2].p_offset++; assert(!valid(5, page));
        fixture(5, page); headers[2].p_paddr++; assert(!valid(5, page));
        fixture(5, page); headers[2].p_align = 3; assert(!valid(5, page));
        fixture(5, page); headers[2].p_memsz++; assert(!valid(5, page));
        fixture(5, page); headers[2].p_offset = 0x80000; assert(!valid(5, page));
        fixture(5, page); headers[3].p_filesz--; assert(!valid(5, page));
        fixture(5, page); headers[3].p_vaddr--; assert(!valid(5, page));
        fixture(5, page); headers[3].p_type = PT_NULL; assert(!valid(5, page));
        fixture(5, page); headers[4].p_type = PT_PHDR; assert(!valid(5, page));
        fixture(5, page); headers[4].p_vaddr = UINT64_MAX; assert(!valid(5, page));
        fixture(5, page); headers[4].p_memsz = UINT64_MAX; assert(!valid(5, page));
        fixture(5, page); headers[4].p_vaddr = 0x10010000; assert(!valid(5, page));
        fixture(5, page); headers[0].p_offset = UINT64_MAX; assert(!valid(5, page));
        fixture(5, page); headers[0].p_memsz++; assert(!valid(5, page));
    }
    return 0;
}
