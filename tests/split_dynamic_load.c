#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* Test-only ELF post-link mutation: split the readable PT_LOAD containing
 * DT_STRTAB on a page inside that table.  No file bytes are moved. */
int main(int argc, char **argv)
{
    uint8_t *image = MAP_FAILED;
    Elf64_Ehdr ehdr;
    Elf64_Phdr *headers = NULL;
    Elf64_Phdr second;
    struct stat status;
    uint64_t strtab = 0;
    uint64_t strsz = 0;
    uint64_t split;
    uint64_t split_alignment;
    size_t size = 0;
    long host_page_size;
    int input = -1;
    int output = -1;
    int source_index = -1;
    int spare_index = -1;
    int dynamic_index = -1;
    int output_created = 0;
    int result = 1;

    if (argc != 3)
        return 64;
    input = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (input < 0 || fstat(input, &status) < 0 ||
        !S_ISREG(status.st_mode) || status.st_size <= 0 ||
        (uintmax_t)status.st_size > SIZE_MAX)
        goto out;
    size = (size_t)status.st_size;
    output = open(argv[2], O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
    if (output < 0)
        goto out;
    output_created = 1;
    if (ftruncate(output, status.st_size) < 0)
        goto out;
    image = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, output, 0);
    if (image == MAP_FAILED)
        goto out;
    for (size_t offset = 0; offset < size;) {
        ssize_t count = pread(input, image + offset, size - offset,
                              (off_t)offset);

        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            goto out;
        offset += (size_t)count;
    }
    if (size < sizeof(ehdr))
        goto out;
    memcpy(&ehdr, image, sizeof(ehdr));
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr.e_phentsize != sizeof(Elf64_Phdr) ||
        ehdr.e_phnum < 3 ||
        ehdr.e_phoff > size ||
        ehdr.e_phnum > (size - (size_t)ehdr.e_phoff) / sizeof(Elf64_Phdr))
        goto out;
    headers = malloc((size_t)ehdr.e_phnum * sizeof(*headers));
    if (!headers)
        goto out;
    memcpy(headers, image + ehdr.e_phoff,
           (size_t)ehdr.e_phnum * sizeof(*headers));
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        if (headers[i].p_type == PT_DYNAMIC)
            dynamic_index = i;
        if (headers[i].p_type == PT_GNU_EH_FRAME)
            spare_index = i;
    }
    if (dynamic_index < 0 || spare_index < 0)
        goto out;
    {
        Elf64_Phdr *dynamic = &headers[dynamic_index];
        size_t count;

        if (dynamic->p_offset > size ||
            dynamic->p_filesz > size - (size_t)dynamic->p_offset ||
            dynamic->p_filesz % sizeof(Elf64_Dyn) != 0)
            goto out;
        count = (size_t)dynamic->p_filesz / sizeof(Elf64_Dyn);
        for (size_t i = 0; i < count; i++) {
            Elf64_Dyn item;

            memcpy(&item, image + dynamic->p_offset + i * sizeof(item),
                   sizeof(item));
            if (item.d_tag == DT_NULL)
                break;
            if (item.d_tag == DT_STRTAB)
                strtab = item.d_un.d_ptr;
            if (item.d_tag == DT_STRSZ)
                strsz = item.d_un.d_val;
        }
    }
    if (strtab == 0 || strsz < 8192 ||
        strtab > UINT64_MAX - strsz)
        goto out;
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        const Elf64_Phdr *load = &headers[i];

        if (load->p_type != PT_LOAD || !(load->p_flags & PF_R) ||
            load->p_vaddr > strtab ||
            load->p_filesz > UINT64_MAX - load->p_vaddr ||
            strtab + strsz > load->p_vaddr + load->p_filesz)
            continue;
        source_index = i;
        break;
    }
    if (source_index < 0 || source_index == spare_index)
        goto out;
    host_page_size = sysconf(_SC_PAGESIZE);
    if (host_page_size <= 0 ||
        ((uint64_t)host_page_size & ((uint64_t)host_page_size - 1)) != 0)
        goto out;
    split_alignment = headers[source_index].p_align;
    if (split_alignment == 0)
        split_alignment = 1;
    if ((split_alignment & (split_alignment - 1)) != 0)
        goto out;
    if (split_alignment < (uint64_t)host_page_size)
        split_alignment = (uint64_t)host_page_size;
    if (strtab > UINT64_MAX - (split_alignment - 1))
        goto out;
    split = (strtab + split_alignment - 1) & ~(split_alignment - 1);
    if (split <= strtab || split >= strtab + strsz)
        goto out;
    {
        Elf64_Phdr *first = &headers[source_index];
        uint64_t delta = split - first->p_vaddr;

        if (delta == 0 || delta >= first->p_filesz ||
            delta >= first->p_memsz ||
            first->p_offset > UINT64_MAX - delta)
            goto out;
        second = *first;
        second.p_vaddr += delta;
        second.p_paddr += delta;
        second.p_offset += delta;
        second.p_filesz -= delta;
        second.p_memsz -= delta;
        first->p_filesz = delta;
        first->p_memsz = delta;
    }
    memmove(&headers[spare_index], &headers[spare_index + 1],
            (size_t)(ehdr.e_phnum - spare_index - 1) * sizeof(*headers));
    if (spare_index < source_index)
        source_index--;
    memmove(&headers[source_index + 2], &headers[source_index + 1],
            (size_t)(ehdr.e_phnum - source_index - 2) * sizeof(*headers));
    headers[source_index + 1] = second;
    memcpy(image + ehdr.e_phoff, headers,
           (size_t)ehdr.e_phnum * sizeof(*headers));
    if (msync(image, size, MS_SYNC) < 0)
        goto out;
    result = 0;

out:
    free(headers);
    if (image != MAP_FAILED)
        munmap(image, size);
    if (input >= 0)
        close(input);
    if (output >= 0)
        close(output);
    if (result != 0 && output_created)
        unlink(argv[2]);
    return result;
}
