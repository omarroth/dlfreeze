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
#include <sys/wait.h>
#include <unistd.h>

#if defined(__x86_64__)
#define TEST_ELF_MACHINE EM_X86_64
#elif defined(__aarch64__)
#define TEST_ELF_MACHINE EM_AARCH64
#else
#error "unsupported ELF test architecture"
#endif

static size_t align_up(size_t value, size_t alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

static uint32_t elf_name_hash(const char *name)
{
    uint32_t hash = 0;

    while (*name) {
        uint32_t high;

        hash = (hash << 4) + (unsigned char)*name++;
        high = hash & 0xf0000000U;
        if (high != 0)
            hash ^= high >> 24;
        hash &= ~high;
    }
    return hash;
}

static int write_all(int fd, const void *data, size_t size)
{
    const uint8_t *bytes = data;

    while (size != 0) {
        ssize_t written = write(fd, bytes, size);

        if (written <= 0)
            return -1;
        bytes += (size_t)written;
        size -= (size_t)written;
    }
    return 0;
}

static int pwrite_all(int fd, const void *data, size_t size)
{
    const uint8_t *bytes = data;
    size_t offset = 0;

    while (offset != size) {
        ssize_t written = pwrite(fd, bytes + offset, size - offset,
                                 (off_t)offset);

        if (written <= 0)
            return -1;
        offset += (size_t)written;
    }
    return 0;
}

static int pread_all(int fd, void *data, size_t size)
{
    uint8_t *bytes = data;
    size_t offset = 0;

    while (offset != size) {
        ssize_t count = pread(fd, bytes + offset, size - offset,
                              (off_t)offset);

        if (count <= 0)
            return -1;
        offset += (size_t)count;
    }
    return 0;
}

static int make_version_fixture(int stress, char path[64])
{
    const size_t phnum = (size_t)PN_XNUM - 1;
    const size_t definition_count = stress ? 16 : 1;
    const size_t auxiliary_count = stress ? UINT16_MAX : 1;
    const size_t name_length = stress ? (size_t)1 << 20 : 1;
    const size_t phdr_offset = sizeof(Elf64_Ehdr);
    const size_t phdr_bytes = phnum * sizeof(Elf64_Phdr);
    const size_t dynamic_offset =
        align_up(phdr_offset + phdr_bytes, _Alignof(Elf64_Dyn));
    /* Keep a second DT_NULL slot so malformed tests can replace the first
     * terminator without making the table unterminated. */
    const size_t dynamic_count = 6;
    const size_t definition_offset = align_up(
        dynamic_offset + dynamic_count * sizeof(Elf64_Dyn), 4);
    const size_t auxiliary_offset = align_up(
        definition_offset + definition_count * sizeof(Elf64_Verdef), 4);
    const size_t string_offset =
        auxiliary_offset + auxiliary_count * sizeof(Elf64_Verdaux);
    const size_t string_size = name_length + 2;
    const size_t file_size = string_offset + string_size;
    uint8_t *image = NULL;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Dyn *dynamic;
    Elf64_Verdef *definition;
    Elf64_Verdaux *auxiliary;
    int fd = -1;
    int result = -1;

    image = calloc(1, file_size);
    if (!image)
        return -1;
    ehdr = (Elf64_Ehdr *)image;
    phdr = (Elf64_Phdr *)(image + phdr_offset);
    dynamic = (Elf64_Dyn *)(image + dynamic_offset);
    definition = (Elf64_Verdef *)(image + definition_offset);
    auxiliary = (Elf64_Verdaux *)(image + auxiliary_offset);

    memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
    ehdr->e_ident[EI_CLASS] = ELFCLASS64;
    ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr->e_ident[EI_VERSION] = EV_CURRENT;
    ehdr->e_type = ET_DYN;
    ehdr->e_machine = TEST_ELF_MACHINE;
    ehdr->e_version = EV_CURRENT;
    ehdr->e_ehsize = sizeof(*ehdr);
    ehdr->e_phoff = phdr_offset;
    ehdr->e_phentsize = sizeof(*phdr);
    ehdr->e_phnum = (Elf64_Half)phnum;
    ehdr->e_shentsize = sizeof(Elf64_Shdr);

    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R;
    phdr[0].p_filesz = file_size;
    phdr[0].p_memsz = file_size;
    phdr[0].p_align = 1;

    phdr[1].p_type = PT_DYNAMIC;
    phdr[1].p_flags = PF_R;
    phdr[1].p_offset = dynamic_offset;
    phdr[1].p_vaddr = dynamic_offset;
    phdr[1].p_filesz = dynamic_count * sizeof(Elf64_Dyn);
    phdr[1].p_memsz = phdr[1].p_filesz;
    phdr[1].p_align = _Alignof(Elf64_Dyn);

    for (size_t i = 2; i < phnum; i++) {
        phdr[i].p_type = PT_LOAD;
        phdr[i].p_vaddr = file_size + i;
        phdr[i].p_align = 1;
    }

    dynamic[0].d_tag = DT_STRTAB;
    dynamic[0].d_un.d_ptr = string_offset;
    dynamic[1].d_tag = DT_STRSZ;
    dynamic[1].d_un.d_val = string_size;
    dynamic[2].d_tag = DT_VERDEF;
    dynamic[2].d_un.d_ptr = definition_offset;
    dynamic[3].d_tag = DT_VERDEFNUM;
    dynamic[3].d_un.d_val = definition_count;
    dynamic[4].d_tag = DT_NULL;
    dynamic[5].d_tag = DT_NULL;

    image[string_offset] = '\0';
    memset(image + string_offset + 1, 'V', name_length);
    image[string_offset + 1 + name_length] = '\0';

    for (size_t i = 0; i < definition_count; i++) {
        size_t record_offset =
            definition_offset + i * sizeof(Elf64_Verdef);

        definition[i].vd_version = VER_DEF_CURRENT;
        definition[i].vd_ndx = (Elf64_Half)(VER_NDX_GLOBAL + 1 + i);
        definition[i].vd_cnt = (Elf64_Half)auxiliary_count;
        definition[i].vd_hash = elf_name_hash(
            (const char *)image + string_offset + 1);
        definition[i].vd_aux = (Elf64_Word)(auxiliary_offset - record_offset);
        if (i + 1 < definition_count)
            definition[i].vd_next = sizeof(Elf64_Verdef);
    }
    for (size_t i = 0; i < auxiliary_count; i++) {
        auxiliary[i].vda_name = 1;
        if (i + 1 < auxiliary_count)
            auxiliary[i].vda_next = sizeof(Elf64_Verdaux);
    }
    strcpy(path, "/tmp/dlfreeze-version-stress.XXXXXX");
    fd = mkstemp(path);
    if (fd < 0 || write_all(fd, image, file_size) < 0)
        goto out;
    result = fd;
    fd = -1;

out:
    if (fd >= 0)
        close(fd);
    if (result < 0 && path[0] != '\0')
        unlink(path);
    free(image);
    return result;
}

static int valid_large_program_header_control(void)
{
    struct elf_info info;
    char path[64] = "";
    int fd = -1;
    int result = -1;

    fd = make_version_fixture(0, path);
    if (fd < 0)
        goto out;
    if (elf_parse_fd(fd, &info) < 0)
        goto out;
    if (info.version_definition_count == 1)
        result = 0;
    elf_info_free(&info);

out:
    if (fd >= 0)
        close(fd);
    if (path[0] != '\0')
        unlink(path);
    return result;
}

static int reused_auxiliary_chain_rejected(void)
{
    struct elf_info info;
    char path[64] = "";
    int fd = -1;
    int result = -1;

    fd = make_version_fixture(1, path);
    if (fd < 0)
        goto out;
    if (elf_parse_fd(fd, &info) < 0) {
        result = 0;
    } else {
        elf_info_free(&info);
    }

out:
    if (fd >= 0)
        close(fd);
    if (path[0] != '\0')
        unlink(path);
    return result;
}

/* Repeating one long provider/version string is valid ELF metadata and must
 * not cause one strlen/hash/copy per auxiliary record. */
static int repeated_long_requirement_is_linear(int duplicate_index)
{
    const size_t auxiliary_count = UINT16_C(0x7fff) - VER_NDX_GLOBAL;
    const size_t name_length = (size_t)1 << 20;
    const size_t phdr_offset = sizeof(Elf64_Ehdr);
    const size_t dynamic_offset = align_up(
        phdr_offset + 2 * sizeof(Elf64_Phdr), _Alignof(Elf64_Dyn));
    const size_t dynamic_count = 7;
    const size_t need_offset = align_up(
        dynamic_offset + dynamic_count * sizeof(Elf64_Dyn), 4);
    const size_t auxiliary_offset = need_offset + sizeof(Elf64_Verneed);
    const size_t string_offset =
        auxiliary_offset + auxiliary_count * sizeof(Elf64_Vernaux);
    const size_t string_size = name_length + 2;
    const size_t file_size = string_offset + string_size;
    struct elf_info info;
    uint8_t *image = NULL;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Dyn *dynamic;
    Elf64_Verneed *need;
    Elf64_Vernaux *auxiliary;
    uint32_t name_hash;
    char path[] = "/tmp/dlfreeze-version-requirements.XXXXXX";
    int fd = -1;
    int result = -1;

    image = calloc(1, file_size);
    if (!image)
        goto out;
    ehdr = (Elf64_Ehdr *)image;
    phdr = (Elf64_Phdr *)(image + phdr_offset);
    dynamic = (Elf64_Dyn *)(image + dynamic_offset);
    need = (Elf64_Verneed *)(image + need_offset);
    auxiliary = (Elf64_Vernaux *)(image + auxiliary_offset);

    memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
    ehdr->e_ident[EI_CLASS] = ELFCLASS64;
    ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr->e_ident[EI_VERSION] = EV_CURRENT;
    ehdr->e_type = ET_DYN;
    ehdr->e_machine = TEST_ELF_MACHINE;
    ehdr->e_version = EV_CURRENT;
    ehdr->e_ehsize = sizeof(*ehdr);
    ehdr->e_phoff = phdr_offset;
    ehdr->e_phentsize = sizeof(*phdr);
    ehdr->e_phnum = 2;
    ehdr->e_shentsize = sizeof(Elf64_Shdr);

    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R;
    phdr[0].p_filesz = file_size;
    phdr[0].p_memsz = file_size;
    phdr[0].p_align = 1;
    phdr[1].p_type = PT_DYNAMIC;
    phdr[1].p_flags = PF_R;
    phdr[1].p_offset = dynamic_offset;
    phdr[1].p_vaddr = dynamic_offset;
    phdr[1].p_filesz = dynamic_count * sizeof(Elf64_Dyn);
    phdr[1].p_memsz = phdr[1].p_filesz;
    phdr[1].p_align = _Alignof(Elf64_Dyn);

    dynamic[0].d_tag = DT_STRTAB;
    dynamic[0].d_un.d_ptr = string_offset;
    dynamic[1].d_tag = DT_STRSZ;
    dynamic[1].d_un.d_val = string_size;
    dynamic[2].d_tag = DT_NEEDED;
    dynamic[2].d_un.d_val = 1;
    dynamic[3].d_tag = DT_VERNEED;
    dynamic[3].d_un.d_ptr = need_offset;
    dynamic[4].d_tag = DT_VERNEEDNUM;
    dynamic[4].d_un.d_val = 1;
    dynamic[5].d_tag = DT_NULL;
    dynamic[6].d_tag = DT_NULL;

    image[string_offset] = '\0';
    memset(image + string_offset + 1, 'R', name_length);
    image[string_offset + name_length + 1] = '\0';
    name_hash = elf_name_hash((const char *)image + string_offset + 1);
    need->vn_version = VER_NEED_CURRENT;
    need->vn_cnt = (Elf64_Half)auxiliary_count;
    need->vn_file = 1;
    need->vn_aux = sizeof(*need);
    for (size_t i = 0; i < auxiliary_count; i++) {
        auxiliary[i].vna_hash = name_hash;
        auxiliary[i].vna_other =
            (Elf64_Half)(VER_NDX_GLOBAL + 1 + i);
        if (duplicate_index && i == 1)
            auxiliary[i].vna_other = auxiliary[0].vna_other;
        auxiliary[i].vna_name = 1;
        if (i + 1 < auxiliary_count)
            auxiliary[i].vna_next = sizeof(Elf64_Vernaux);
    }

    fd = mkstemp(path);
    if (fd < 0 || write_all(fd, image, file_size) < 0)
        goto out;
    if (elf_parse_fd(fd, &info) < 0) {
        if (duplicate_index)
            result = 0;
        goto out;
    }
    if (duplicate_index) {
        elf_info_free(&info);
        goto out;
    }
    if (info.version_requirement_count == auxiliary_count &&
        info.needed_count == 1 &&
        info.version_requirements[0].file == info.needed[0] &&
        info.version_requirements[0].name == info.needed[0] &&
        info.version_requirements[auxiliary_count - 1].name ==
            info.needed[0])
        result = 0;
    elf_info_free(&info);

out:
    if (fd >= 0)
        close(fd);
    unlink(path);
    free(image);
    return result;
}

static int concurrent_truncation_is_safe(void)
{
    struct elf_info info;
    struct stat st;
    char path[64] = "";
    uint8_t *image = NULL;
    volatile int *stop = MAP_FAILED;
    pid_t child = -1;
    int fd = -1;
    int result = -1;

    fd = make_version_fixture(0, path);
    if (fd < 0 || fstat(fd, &st) < 0 || st.st_size <= 64 ||
        (uintmax_t)st.st_size > SIZE_MAX)
        goto out;
    image = malloc((size_t)st.st_size);
    stop = mmap(NULL, sizeof(*stop), PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!image || stop == MAP_FAILED ||
        pread_all(fd, image, (size_t)st.st_size) < 0)
        goto out;
    *stop = 0;
    child = fork();
    if (child < 0)
        goto out;
    if (child == 0) {
        while (!*stop) {
            if (ftruncate(fd, 64) < 0 ||
                ftruncate(fd, st.st_size) < 0 ||
                pwrite_all(fd, image, (size_t)st.st_size) < 0)
                _exit(1);
        }
        _exit(0);
    }

    /* Each parse may accept a complete snapshot or reject a changing one;
     * it must never retain a truncatable file mapping and receive SIGBUS. */
    for (size_t i = 0; i < 64; i++)
        (void)elf_check(path);
    *stop = 1;
    if (waitpid(child, NULL, 0) != child)
        goto out;
    child = -1;
    if (ftruncate(fd, st.st_size) < 0 ||
        pwrite_all(fd, image, (size_t)st.st_size) < 0 || fsync(fd) < 0 ||
        elf_parse_fd(fd, &info) < 0)
        goto out;
    if (info.version_definition_count == 1)
        result = 0;
    elf_info_free(&info);

out:
    if (child > 0) {
        *stop = 1;
        waitpid(child, NULL, 0);
    }
    if (stop != MAP_FAILED)
        munmap((void *)stop, sizeof(*stop));
    free(image);
    if (fd >= 0)
        close(fd);
    if (path[0] != '\0')
        unlink(path);
    return result;
}

static int conflicting_dynamic_value_rejected(void)
{
    struct elf_info info;
    Elf64_Ehdr ehdr;
    Elf64_Phdr dynamic_phdr;
    Elf64_Dyn conflicting;
    char path[64] = "";
    int fd = -1;
    int result = -1;

    fd = make_version_fixture(0, path);
    if (fd < 0 || pread(fd, &ehdr, sizeof(ehdr), 0) != sizeof(ehdr) ||
        pread(fd, &dynamic_phdr, sizeof(dynamic_phdr),
              (off_t)(ehdr.e_phoff + sizeof(Elf64_Phdr))) !=
            sizeof(dynamic_phdr))
        goto out;
    memset(&conflicting, 0, sizeof(conflicting));
    conflicting.d_tag = DT_STRSZ;
    conflicting.d_un.d_val = 4;
    if (pwrite(fd, &conflicting, sizeof(conflicting),
               (off_t)(dynamic_phdr.p_offset +
                       4 * sizeof(Elf64_Dyn))) != sizeof(conflicting))
        goto out;
    if (elf_parse_fd(fd, &info) < 0) {
        result = 0;
    } else {
        elf_info_free(&info);
    }

out:
    if (fd >= 0)
        close(fd);
    if (path[0] != '\0')
        unlink(path);
    return result;
}

static int orphan_relocation_tag_rejected(Elf64_Sxword tag, uint64_t value)
{
    struct elf_info info;
    Elf64_Ehdr ehdr;
    Elf64_Phdr dynamic_phdr;
    Elf64_Dyn orphan;
    char path[64] = "";
    int fd = -1;
    int result = -1;

    fd = make_version_fixture(0, path);
    if (fd < 0 || pread(fd, &ehdr, sizeof(ehdr), 0) != sizeof(ehdr) ||
        pread(fd, &dynamic_phdr, sizeof(dynamic_phdr),
              (off_t)(ehdr.e_phoff + sizeof(Elf64_Phdr))) !=
            sizeof(dynamic_phdr))
        goto out;
    memset(&orphan, 0, sizeof(orphan));
    orphan.d_tag = tag;
    orphan.d_un.d_val = value;
    if (pwrite(fd, &orphan, sizeof(orphan),
               (off_t)(dynamic_phdr.p_offset +
                       4 * sizeof(Elf64_Dyn))) != sizeof(orphan))
        goto out;
    if (elf_parse_fd(fd, &info) < 0) {
        result = 0;
    } else {
        elf_info_free(&info);
    }

out:
    if (fd >= 0)
        close(fd);
    if (path[0] != '\0')
        unlink(path);
    return result;
}

static int invalid_string_sentinel_rejected(void)
{
    struct elf_info info;
    struct stat st;
    char path[64] = "";
    const char nonzero = 'X';
    int fd = -1;
    int result = -1;

    fd = make_version_fixture(0, path);
    /* The control fixture's dynamic string table is its final three bytes:
     * NUL, "V", NUL.  Corrupt only reserved index zero while keeping every
     * referenced string independently terminated. */
    if (fd < 0 || fstat(fd, &st) < 0 || st.st_size < 3 ||
        pwrite(fd, &nonzero, 1, st.st_size - 3) != 1)
        goto out;
    if (elf_parse_fd(fd, &info) < 0) {
        result = 0;
    } else {
        elf_info_free(&info);
    }

out:
    if (fd >= 0)
        close(fd);
    if (path[0] != '\0')
        unlink(path);
    return result;
}

int main(void)
{
    if (valid_large_program_header_control() < 0)
        return 1;
    if (reused_auxiliary_chain_rejected() < 0)
        return 2;
    if (concurrent_truncation_is_safe() < 0)
        return 3;
    if (conflicting_dynamic_value_rejected() < 0)
        return 4;
    if (invalid_string_sentinel_rejected() < 0)
        return 5;
    if (repeated_long_requirement_is_linear(0) < 0)
        return 6;
    if (orphan_relocation_tag_rejected(DT_RELA, 1) < 0)
        return 7;
    if (orphan_relocation_tag_rejected(DT_JMPREL, 1) < 0)
        return 8;
    if (repeated_long_requirement_is_linear(1) < 0)
        return 9;
    return 0;
}
