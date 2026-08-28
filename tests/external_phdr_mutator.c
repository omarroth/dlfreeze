#define _GNU_SOURCE

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int read_exact(int fd, void *buffer, size_t size, uint64_t offset)
{
    size_t done = 0;

    while (done < size) {
        ssize_t got = pread(fd, (uint8_t *)buffer + done, size - done,
                            (off_t)(offset + done));

        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            return -1;
        done += (size_t)got;
    }
    return 0;
}

static int write_exact(int fd, const void *buffer, size_t size,
                       uint64_t offset)
{
    size_t done = 0;

    while (done < size) {
        ssize_t put = pwrite(fd, (const uint8_t *)buffer + done, size - done,
                             (off_t)(offset + done));

        if (put < 0 && errno == EINTR)
            continue;
        if (put <= 0)
            return -1;
        done += (size_t)put;
    }
    return 0;
}

static int valid_header(const Elf64_Ehdr *ehdr, uint64_t file_size,
                        size_t *phdr_bytes_out)
{
    uint64_t bytes;

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr->e_phnum == 0 || ehdr->e_phnum == PN_XNUM ||
        ehdr->e_phentsize != sizeof(Elf64_Phdr))
        return 0;
    bytes = (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr);
    if (bytes > SIZE_MAX || ehdr->e_phoff > file_size ||
        bytes > file_size - ehdr->e_phoff)
        return 0;
    *phdr_bytes_out = (size_t)bytes;
    return 1;
}

static int move_table(const char *path, const char *offset_text,
                      int add_incoherent_phdr)
{
    struct stat st;
    Elf64_Ehdr ehdr;
    Elf64_Phdr *phdr = NULL;
    size_t phdr_bytes;
    uint64_t offset;
    uint64_t end;
    int fd = -1;
    int result = 1;

    fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) < 0 || st.st_size < 0 ||
        read_exact(fd, &ehdr, sizeof(ehdr), 0) < 0 ||
        !valid_header(&ehdr, (uint64_t)st.st_size, &phdr_bytes))
        goto out;
    if (offset_text) {
        char *endptr = NULL;

        errno = 0;
        offset = strtoull(offset_text, &endptr, 0);
        if (errno || !endptr || *endptr != '\0')
            goto out;
    } else {
        if ((uint64_t)st.st_size == UINT64_MAX)
            goto out;
        offset = (uint64_t)st.st_size + 1;
    }
    if (offset > (uint64_t)INT64_MAX ||
        (uint64_t)phdr_bytes > UINT64_MAX - offset)
        goto out;
    end = offset + (uint64_t)phdr_bytes;
    if (end > (uint64_t)INT64_MAX)
        goto out;

    phdr = malloc(phdr_bytes);
    if (!phdr || read_exact(fd, phdr, phdr_bytes, ehdr.e_phoff) < 0)
        goto out;
    /* PT_PHDR describes a table in the memory image.  Once e_phoff names a
     * file-only table, retaining the old self-pointer would describe stale
     * bytes rather than the table being consumed. */
    for (uint16_t i = 0; i < ehdr.e_phnum; i++)
        if (phdr[i].p_type == PT_PHDR)
            memset(&phdr[i], 0, sizeof(phdr[i]));
    if (add_incoherent_phdr) {
        Elf64_Phdr *slot = NULL;

        for (uint16_t i = 0; i < ehdr.e_phnum; i++)
            if (phdr[i].p_type == PT_NOTE || phdr[i].p_type == PT_NULL) {
                slot = &phdr[i];
                break;
            }
        if (!slot)
            goto out;
        memset(slot, 0, sizeof(*slot));
        slot->p_type = PT_PHDR;
        slot->p_flags = PF_R;
        slot->p_offset = offset;
        slot->p_filesz = phdr_bytes;
        slot->p_memsz = phdr_bytes;
        slot->p_align = _Alignof(Elf64_Phdr);
    }

    if (ftruncate(fd, (off_t)end) < 0 ||
        write_exact(fd, phdr, phdr_bytes, offset) < 0)
        goto out;
    ehdr.e_phoff = offset;
    if (write_exact(fd, &ehdr, sizeof(ehdr), 0) < 0 || fsync(fd) < 0)
        goto out;
    result = 0;

out:
    free(phdr);
    if (fd >= 0)
        close(fd);
    return result;
}

static int truncate_table(const char *path)
{
    struct stat st;
    Elf64_Ehdr ehdr;
    size_t phdr_bytes;
    uint64_t offset;
    int fd = -1;
    int result = 1;

    fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) < 0 || st.st_size < 0 ||
        read_exact(fd, &ehdr, sizeof(ehdr), 0) < 0 ||
        !valid_header(&ehdr, (uint64_t)st.st_size, &phdr_bytes) ||
        phdr_bytes < 2 || (uint64_t)st.st_size < phdr_bytes / 2)
        goto out;
    offset = (uint64_t)st.st_size - phdr_bytes / 2;
    ehdr.e_phoff = offset;
    if (write_exact(fd, &ehdr, sizeof(ehdr), 0) < 0 || fsync(fd) < 0)
        goto out;
    result = 0;

out:
    if (fd >= 0)
        close(fd);
    return result;
}

static int mutate_self_header(const char *path, int duplicate)
{
    struct stat st;
    Elf64_Ehdr ehdr;
    Elf64_Phdr *phdr = NULL;
    Elf64_Phdr *self = NULL;
    Elf64_Phdr *spare = NULL;
    Elf64_Phdr *second_spare = NULL;
    size_t phdr_bytes;
    uint64_t table_end;
    uint64_t vaddr = UINT64_MAX;
    int fd = -1;
    int result = 1;

    fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) < 0 || st.st_size < 0 ||
        read_exact(fd, &ehdr, sizeof(ehdr), 0) < 0 ||
        !valid_header(&ehdr, (uint64_t)st.st_size, &phdr_bytes) ||
        (uint64_t)phdr_bytes > UINT64_MAX - ehdr.e_phoff)
        goto out;
    table_end = ehdr.e_phoff + (uint64_t)phdr_bytes;
    phdr = malloc(phdr_bytes);
    if (!phdr || read_exact(fd, phdr, phdr_bytes, ehdr.e_phoff) < 0)
        goto out;
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_R) &&
            ehdr.e_phoff >= phdr[i].p_offset &&
            table_end - phdr[i].p_offset <= phdr[i].p_filesz) {
            uint64_t candidate = phdr[i].p_vaddr +
                (ehdr.e_phoff - phdr[i].p_offset);

            if (vaddr != UINT64_MAX && vaddr != candidate)
                goto out;
            vaddr = candidate;
        }
        if (phdr[i].p_type == PT_PHDR) {
            if (self)
                goto out;
            self = &phdr[i];
        } else if (phdr[i].p_type == PT_NOTE ||
                   phdr[i].p_type == PT_NULL) {
            if (!spare)
                spare = &phdr[i];
            else if (!second_spare)
                second_spare = &phdr[i];
        }
    }
    if (vaddr == UINT64_MAX || (!self && !spare) ||
        (duplicate && !(self ? spare : second_spare)))
        goto out;
    if (!self) {
        self = spare;
        spare = second_spare;
    }
    memset(self, 0, sizeof(*self));
    self->p_type = PT_PHDR;
    self->p_flags = PF_R;
    self->p_offset = ehdr.e_phoff;
    self->p_vaddr = vaddr;
    self->p_paddr = vaddr;
    self->p_filesz = duplicate ? phdr_bytes : phdr_bytes - 1;
    self->p_memsz = phdr_bytes;
    self->p_align = _Alignof(Elf64_Phdr);
    if (duplicate)
        *spare = *self;
    if (write_exact(fd, phdr, phdr_bytes, ehdr.e_phoff) < 0 || fsync(fd) < 0)
        goto out;
    result = 0;

out:
    free(phdr);
    if (fd >= 0)
        close(fd);
    return result;
}

int main(int argc, char **argv)
{
    if ((argc == 3 || argc == 4) && strcmp(argv[1], "--move") == 0)
        return move_table(argv[2], argc == 4 ? argv[3] : NULL, 0);
    if (argc == 3 && strcmp(argv[1], "--move-bad-phdr") == 0)
        return move_table(argv[2], NULL, 1);
    if (argc == 3 && strcmp(argv[1], "--truncate") == 0)
        return truncate_table(argv[2]);
    if (argc == 3 && strcmp(argv[1], "--duplicate-phdr") == 0)
        return mutate_self_header(argv[2], 1);
    if (argc == 3 && strcmp(argv[1], "--partial-phdr") == 0)
        return mutate_self_header(argv[2], 0);
    fprintf(stderr, "usage: %s --move FILE [OFFSET] | "
                    "--move-bad-phdr FILE | --truncate FILE | "
                    "--duplicate-phdr FILE | --partial-phdr FILE\n",
            argv[0]);
    return 2;
}
