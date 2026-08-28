#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static int range_fits(uint64_t offset, uint64_t length, size_t size)
{
    return offset <= size && length <= (uint64_t)size - offset;
}

int main(int argc, char **argv)
{
    struct stat st;
    uint8_t *image;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdrs;
    Elf64_Dyn *dynamic = NULL;
    size_t dynamic_count = 0;
    uint64_t relr_vaddr = 0;
    uint64_t relr_size = 0;
    uint64_t relr_ent = 0;
    uint64_t relr_offset = UINT64_MAX;
    int fd;
    int rc = 1;

    if (argc != 2)
        return 64;
    fd = open(argv[1], O_RDWR | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) < 0 || st.st_size < 0 ||
        (uintmax_t)st.st_size > SIZE_MAX)
        return 1;
    image = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE,
                 MAP_SHARED, fd, 0);
    if (image == MAP_FAILED)
        goto out;
    ehdr = (Elf64_Ehdr *)image;
    if ((size_t)st.st_size < sizeof(*ehdr) ||
        memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr->e_phentsize != sizeof(Elf64_Phdr) ||
        !range_fits(ehdr->e_phoff,
                    (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr),
                    (size_t)st.st_size))
        goto unmap;
    phdrs = (Elf64_Phdr *)(image + ehdr->e_phoff);
    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type != PT_DYNAMIC)
            continue;
        if (dynamic || phdrs[i].p_filesz == 0 ||
            phdrs[i].p_filesz % sizeof(Elf64_Dyn) != 0 ||
            !range_fits(phdrs[i].p_offset, phdrs[i].p_filesz,
                        (size_t)st.st_size))
            goto unmap;
        dynamic = (Elf64_Dyn *)(image + phdrs[i].p_offset);
        dynamic_count = (size_t)phdrs[i].p_filesz / sizeof(Elf64_Dyn);
    }
    if (!dynamic)
        goto unmap;
    for (size_t i = 0; i < dynamic_count; i++) {
        if (dynamic[i].d_tag == DT_NULL)
            break;
        if (dynamic[i].d_tag == DT_RELR)
            relr_vaddr = dynamic[i].d_un.d_ptr;
        else if (dynamic[i].d_tag == DT_RELRSZ)
            relr_size = dynamic[i].d_un.d_val;
        else if (dynamic[i].d_tag == DT_RELRENT)
            relr_ent = dynamic[i].d_un.d_val;
    }
    if (relr_vaddr == 0 || relr_size < sizeof(Elf64_Relr) ||
        relr_ent != sizeof(Elf64_Relr))
        goto unmap;
    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        uint64_t delta;

        if (phdrs[i].p_type != PT_LOAD ||
            relr_vaddr < phdrs[i].p_vaddr)
            continue;
        delta = relr_vaddr - phdrs[i].p_vaddr;
        if (delta <= phdrs[i].p_filesz &&
            sizeof(Elf64_Relr) <= phdrs[i].p_filesz - delta) {
            relr_offset = phdrs[i].p_offset + delta;
            break;
        }
    }
    if (relr_offset == UINT64_MAX ||
        !range_fits(relr_offset, sizeof(Elf64_Relr), (size_t)st.st_size))
        goto unmap;

    /* A bitmap has no base address until a preceding even entry establishes
     * the current relocation word. */
    *(Elf64_Relr *)(image + relr_offset) = 3;
    if (msync(image, (size_t)st.st_size, MS_SYNC) < 0)
        goto unmap;
    rc = 0;

unmap:
    munmap(image, (size_t)st.st_size);
out:
    close(fd);
    return rc;
}
