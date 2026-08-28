#include "load_segments.h"

#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int check_small_tables(void)
{
    Elf64_Phdr phdr[3] = {0};
    Elf64_Phdr subject = {0};

    phdr[0].p_type = PT_LOAD;
    phdr[0].p_vaddr = 0x1000;
    phdr[0].p_memsz = 1;
    phdr[1].p_type = PT_LOAD;
    phdr[1].p_vaddr = 0x2000;
    phdr[1].p_memsz = 1;
    if (!dlfrz_load_pages_do_not_overlap(phdr, 2, 4096))
        return 1;

    phdr[1].p_vaddr = 0x1fff;
    if (dlfrz_load_pages_do_not_overlap(phdr, 2, 4096))
        return 1;
    phdr[1].p_vaddr = 0x2000;

    phdr[2] = phdr[0];
    phdr[2].p_memsz = 0;
    phdr[2].p_vaddr = 0;
    if (dlfrz_load_pages_do_not_overlap(phdr, 3, 4096))
        return 1;

    phdr[2].p_vaddr = UINT64_MAX - 1;
    phdr[2].p_memsz = 2;
    if (dlfrz_load_pages_do_not_overlap(phdr, 3, 4096))
        return 1;

    memset(phdr, 0, sizeof(phdr));
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_offset = 0x2000;
    phdr[0].p_vaddr = 0x4000;
    phdr[0].p_filesz = 0x1000;
    phdr[0].p_memsz = 0x2000;
    subject.p_type = PT_DYNAMIC;
    subject.p_offset = 0x2800;
    subject.p_vaddr = 0x4800;
    subject.p_filesz = 0x100;
    subject.p_memsz = 0x180;
    if (!dlfrz_segment_is_contained_by_load(phdr, 3, &subject))
        return 1;
    subject.p_vaddr++;
    if (dlfrz_segment_is_contained_by_load(phdr, 3, &subject))
        return 1;
    subject.p_vaddr--;
    subject.p_memsz = 0x1801;
    if (dlfrz_segment_is_contained_by_load(phdr, 3, &subject))
        return 1;
    return 0;
}

static int check_maximum_table(void)
{
    const size_t count = PN_XNUM;
    Elf64_Phdr *phdr = calloc(count, sizeof(*phdr));
    int result;

    if (!phdr)
        return 1;
    for (size_t i = 0; i < count; i++) {
        phdr[i].p_type = PT_LOAD;
        phdr[i].p_flags = PF_R;
        phdr[i].p_vaddr = (uint64_t)i * 4096;
        phdr[i].p_paddr = phdr[i].p_vaddr;
        phdr[i].p_memsz = 1;
        phdr[i].p_align = 4096;
    }
    result = dlfrz_load_pages_do_not_overlap(phdr, count, 4096);
    free(phdr);
    return result ? 0 : 1;
}

static int write_pn_xnum_dso(const char *path)
{
    const size_t load_count = PN_XNUM - 2;
    const size_t phdr_bytes = (size_t)PN_XNUM * sizeof(Elf64_Phdr);
    const size_t phdr_end = sizeof(Elf64_Ehdr) + phdr_bytes;
    const size_t dynamic_offset = (phdr_end + 4095) & ~(size_t)4095;
    const size_t file_size = dynamic_offset + sizeof(Elf64_Dyn);
    uint8_t *map = MAP_FAILED;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Dyn *dynamic;
    int fd = -1;
    int rc = 1;

    fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 || ftruncate(fd, (off_t)file_size) < 0)
        goto out;
    map = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED)
        goto out;

    ehdr = (Elf64_Ehdr *)map;
    memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
    ehdr->e_ident[EI_CLASS] = ELFCLASS64;
    ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr->e_ident[EI_VERSION] = EV_CURRENT;
    ehdr->e_ident[EI_OSABI] = ELFOSABI_NONE;
    ehdr->e_type = ET_DYN;
#if defined(__x86_64__)
    ehdr->e_machine = EM_X86_64;
#elif defined(__aarch64__)
    ehdr->e_machine = EM_AARCH64;
#else
#error "unsupported test architecture"
#endif
    ehdr->e_version = EV_CURRENT;
    ehdr->e_ehsize = sizeof(*ehdr);
    ehdr->e_phoff = sizeof(*ehdr);
    ehdr->e_phentsize = sizeof(Elf64_Phdr);
    ehdr->e_phnum = PN_XNUM;

    phdr = (Elf64_Phdr *)(map + ehdr->e_phoff);
    for (size_t i = 0; i < load_count; i++) {
        phdr[i].p_type = PT_LOAD;
        phdr[i].p_flags = PF_R;
        phdr[i].p_vaddr = (uint64_t)i * 4096;
        phdr[i].p_paddr = phdr[i].p_vaddr;
        phdr[i].p_memsz = 1;
        phdr[i].p_align = 4096;
    }

    /* Make one load own the single DT_NULL entry.  The remaining nonempty,
     * page-disjoint loads force a quadratic overlap validator to perform
     * roughly 2.1 billion comparisons before accepting the table. */
    phdr[0].p_offset = dynamic_offset;
    phdr[0].p_filesz = sizeof(Elf64_Dyn);
    phdr[0].p_memsz = sizeof(Elf64_Dyn);

    phdr[load_count].p_type = PT_DYNAMIC;
    phdr[load_count].p_flags = PF_R | PF_W;
    phdr[load_count].p_offset = dynamic_offset;
    phdr[load_count].p_filesz = sizeof(Elf64_Dyn);
    phdr[load_count].p_memsz = sizeof(Elf64_Dyn);
    phdr[load_count].p_align = sizeof(uint64_t);

    phdr[load_count + 1].p_type = PT_GNU_STACK;
    phdr[load_count + 1].p_flags = PF_R | PF_W;
    phdr[load_count + 1].p_align = 16;

    dynamic = (Elf64_Dyn *)(map + dynamic_offset);
    dynamic->d_tag = DT_NULL;
    if (msync(map, file_size, MS_SYNC) < 0)
        goto out;
    rc = 0;

out:
    if (map != MAP_FAILED)
        munmap(map, file_size);
    if (fd >= 0)
        close(fd);
    if (rc != 0)
        unlink(path);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc == 1)
        return check_small_tables() || check_maximum_table();
    if (argc == 3 && strcmp(argv[1], "--write-pn-xnum") == 0)
        return write_pn_xnum_dso(argv[2]);
    fprintf(stderr, "usage: %s [--write-pn-xnum FILE]\n", argv[0]);
    return 2;
}
