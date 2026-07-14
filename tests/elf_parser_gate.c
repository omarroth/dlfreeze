#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "elf_parser.h"

#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef DF_STATIC_TLS
#define DF_STATIC_TLS 0x10
#endif

struct mapped_elf {
    int fd;
    size_t size;
    uint8_t *data;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Dyn *dynamic;
    size_t dynamic_count;
};

static int copy_fixture(const char *source, char path[64])
{
    char buffer[16384];
    int input = -1;
    int output = -1;
    int rc = -1;
    ssize_t count;

    strcpy(path, "/tmp/dlfreeze-elf-parser.XXXXXX");
    output = mkstemp(path);
    input = open(source, O_RDONLY | O_CLOEXEC);
    if (input < 0 || output < 0)
        goto out;
    while ((count = read(input, buffer, sizeof(buffer))) > 0) {
        ssize_t done = 0;

        while (done < count) {
            ssize_t written = write(output, buffer + done,
                                    (size_t)(count - done));
            if (written <= 0)
                goto out;
            done += written;
        }
    }
    if (count == 0)
        rc = 0;
out:
    if (input >= 0)
        close(input);
    if (output >= 0)
        close(output);
    if (rc < 0 && path[0])
        unlink(path);
    return rc;
}

static int map_fixture(const char *path, struct mapped_elf *mapped)
{
    struct stat st;

    memset(mapped, 0, sizeof(*mapped));
    mapped->fd = open(path, O_RDWR | O_CLOEXEC);
    if (mapped->fd < 0 || fstat(mapped->fd, &st) < 0 ||
        st.st_size < (off_t)sizeof(Elf64_Ehdr))
        return -1;
    mapped->size = (size_t)st.st_size;
    mapped->data = mmap(NULL, mapped->size, PROT_READ | PROT_WRITE,
                        MAP_SHARED, mapped->fd, 0);
    if (mapped->data == MAP_FAILED)
        return -1;
    mapped->ehdr = (Elf64_Ehdr *)mapped->data;
    if (memcmp(mapped->ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        mapped->ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        mapped->ehdr->e_phentsize != sizeof(Elf64_Phdr) ||
        mapped->ehdr->e_phoff > mapped->size ||
        mapped->ehdr->e_phnum >
            (mapped->size - mapped->ehdr->e_phoff) / sizeof(Elf64_Phdr))
        return -1;
    mapped->phdr = (Elf64_Phdr *)(mapped->data + mapped->ehdr->e_phoff);
    for (uint16_t i = 0; i < mapped->ehdr->e_phnum; i++) {
        Elf64_Phdr *ph = &mapped->phdr[i];

        if (ph->p_type != PT_DYNAMIC)
            continue;
        if (ph->p_offset > mapped->size ||
            ph->p_filesz > mapped->size - ph->p_offset ||
            ph->p_filesz % sizeof(Elf64_Dyn) != 0)
            return -1;
        mapped->dynamic = (Elf64_Dyn *)(mapped->data + ph->p_offset);
        mapped->dynamic_count = ph->p_filesz / sizeof(Elf64_Dyn);
        break;
    }
    return mapped->dynamic ? 0 : -1;
}

static void unmap_fixture(struct mapped_elf *mapped)
{
    if (mapped->data && mapped->data != MAP_FAILED)
        munmap(mapped->data, mapped->size);
    if (mapped->fd >= 0)
        close(mapped->fd);
    memset(mapped, 0, sizeof(*mapped));
    mapped->fd = -1;
}

static int clear_static_tls_flag(struct mapped_elf *mapped)
{
    for (size_t i = 0; i < mapped->dynamic_count; i++) {
        if (mapped->dynamic[i].d_tag == DT_NULL)
            break;
        if (mapped->dynamic[i].d_tag == DT_FLAGS)
            mapped->dynamic[i].d_un.d_val &= ~((uint64_t)DF_STATIC_TLS);
    }
    /* AArch64 linkers commonly emit TLS_TPREL without a DT_FLAGS entry.
     * Clearing an already-absent advisory flag is still a valid mutation:
     * the relocation itself must remain sufficient for classification. */
    return 0;
}

static int parse_requires_static_tls(const char *path)
{
    struct elf_info info;
    int result;

    if (elf_parse(path, &info) < 0)
        return -1;
    result = info.has_static_tls;
    elf_info_free(&info);
    return result ? 0 : -1;
}

static int parse_external_ie_requires_static_tls(const char *path)
{
    struct elf_info info;
    int result;

    if (elf_parse(path, &info) < 0)
        return -1;
    result = info.tls_memsz == 0 && info.has_static_tls;
    elf_info_free(&info);
    return result ? 0 : -1;
}

static int tpoff_without_flag(const char *source)
{
    char path[64] = "";
    struct mapped_elf mapped;
    int rc = -1;

    if (copy_fixture(source, path) < 0 || map_fixture(path, &mapped) < 0)
        goto out;
    if (clear_static_tls_flag(&mapped) < 0 || msync(mapped.data, mapped.size,
                                                    MS_SYNC) < 0) {
        unmap_fixture(&mapped);
        goto out;
    }
    unmap_fixture(&mapped);
    rc = parse_requires_static_tls(path);
out:
    if (path[0])
        unlink(path);
    return rc;
}

static int duplicate_zero_tls_rejected(const char *source)
{
    char path[64] = "";
    struct mapped_elf mapped;
    int have_tls = 0;
    int candidate = -1;
    int rc = -1;

    if (copy_fixture(source, path) < 0 || map_fixture(path, &mapped) < 0)
        goto out;
    for (uint16_t i = 0; i < mapped.ehdr->e_phnum; i++) {
        uint32_t type = mapped.phdr[i].p_type;

        if (type == PT_TLS)
            have_tls = 1;
        else if (candidate < 0 && type != PT_LOAD && type != PT_DYNAMIC &&
                 type != PT_INTERP && type != PT_PHDR)
            candidate = i;
    }
    if (!have_tls || candidate < 0) {
        unmap_fixture(&mapped);
        goto out;
    }
    memset(&mapped.phdr[candidate], 0, sizeof(mapped.phdr[candidate]));
    mapped.phdr[candidate].p_type = PT_TLS;
    mapped.phdr[candidate].p_align = 1;
    if (msync(mapped.data, mapped.size, MS_SYNC) < 0) {
        unmap_fixture(&mapped);
        goto out;
    }
    unmap_fixture(&mapped);
    {
        struct elf_info info;

        if (elf_parse(path, &info) < 0)
            rc = 0;
        else
            elf_info_free(&info);
    }
out:
    if (path[0])
        unlink(path);
    return rc;
}

static int malformed_rela_rejected(const char *source)
{
    char path[64] = "";
    struct mapped_elf mapped;
    int found_rela = 0;
    int rc = -1;

    if (copy_fixture(source, path) < 0 || map_fixture(path, &mapped) < 0)
        goto out;
    if (clear_static_tls_flag(&mapped) < 0) {
        unmap_fixture(&mapped);
        goto out;
    }
    for (size_t i = 0; i < mapped.dynamic_count; i++) {
        if (mapped.dynamic[i].d_tag == DT_NULL)
            break;
        if (mapped.dynamic[i].d_tag == DT_RELASZ) {
            mapped.dynamic[i].d_un.d_val = UINT64_MAX;
            found_rela = 1;
            break;
        }
    }
    if (!found_rela || msync(mapped.data, mapped.size, MS_SYNC) < 0) {
        unmap_fixture(&mapped);
        goto out;
    }
    unmap_fixture(&mapped);
    {
        struct elf_info info;

        if (elf_parse(path, &info) < 0)
            rc = 0;
        else
            elf_info_free(&info);
    }
out:
    if (path[0])
        unlink(path);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc != 2 && argc != 3)
        return 64;
    if (parse_requires_static_tls(argv[1]) < 0)
        return 1;
    if (tpoff_without_flag(argv[1]) < 0)
        return 2;
    if (duplicate_zero_tls_rejected(argv[1]) < 0)
        return 3;
    if (malformed_rela_rejected(argv[1]) < 0)
        return 4;
    if (argc == 3) {
        if (parse_external_ie_requires_static_tls(argv[2]) < 0)
            return 5;
        if (tpoff_without_flag(argv[2]) < 0)
            return 6;
    }
    return 0;
}
