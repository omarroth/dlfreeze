#define _GNU_SOURCE 1
#include <elf.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PT_GNU_PROPERTY
#define PT_GNU_PROPERTY 0x6474e553
#endif

static int read_exact(int fd, void *buffer, size_t size, off_t offset)
{
    size_t done = 0;

    while (done < size) {
        ssize_t result = pread(fd, (char *)buffer + done, size - done,
                               offset + (off_t)done);
        if (result <= 0)
            return 0;
        done += (size_t)result;
    }
    return 1;
}

int main(int argc, char **argv)
{
    Elf64_Ehdr ehdr;
    struct stat st;
    off_t property_offset = 0;
    uint32_t replacement = PT_NOTE;
    unsigned int property_count = 0;
    int fd;

    if (argc != 2)
        return 2;
    fd = open(argv[1], O_RDWR | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) < 0 || st.st_size < (off_t)sizeof(ehdr) ||
        !read_exact(fd, &ehdr, sizeof(ehdr), 0))
        return 3;
    if (ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr.e_ident[EI_MAG3] != ELFMAG3 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr.e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr.e_phentsize != sizeof(Elf64_Phdr) || ehdr.e_phnum == 0 ||
        ehdr.e_phoff > (uint64_t)st.st_size ||
        (uint64_t)ehdr.e_phnum >
            ((uint64_t)st.st_size - ehdr.e_phoff) / sizeof(Elf64_Phdr))
        return 4;
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        uint64_t offset = ehdr.e_phoff +
            (uint64_t)i * sizeof(Elf64_Phdr);

        if (offset > (uint64_t)INT64_MAX ||
            !read_exact(fd, &phdr, sizeof(phdr), (off_t)offset))
            return 5;
        if (phdr.p_type != PT_GNU_PROPERTY)
            continue;
        property_count++;
        if (offset > (uint64_t)INT64_MAX - offsetof(Elf64_Phdr, p_type))
            return 6;
        property_offset = (off_t)(offset + offsetof(Elf64_Phdr, p_type));
    }
    if (property_count != 1 ||
        pwrite(fd, &replacement, sizeof(replacement), property_offset) !=
            (ssize_t)sizeof(replacement) ||
        close(fd) != 0)
        return 7;
    return 0;
}
