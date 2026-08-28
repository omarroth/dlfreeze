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

static int spare_program_header(const struct mapped_elf *mapped);

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

static int ambiguous_vaddr_translation_rejected(const char *source)
{
    char path[64] = "";
    struct mapped_elf mapped;
    uint64_t strtab_vaddr = 0;
    int source_index = -1;
    int candidate;
    int rc = -1;

    if (copy_fixture(source, path) < 0 || map_fixture(path, &mapped) < 0)
        goto out;
    for (size_t i = 0; i < mapped.dynamic_count; i++) {
        if (mapped.dynamic[i].d_tag == DT_NULL)
            break;
        if (mapped.dynamic[i].d_tag == DT_STRTAB) {
            strtab_vaddr = mapped.dynamic[i].d_un.d_ptr;
            break;
        }
    }
    candidate = spare_program_header(&mapped);
    for (uint16_t i = 0; i < mapped.ehdr->e_phnum; i++) {
        uint64_t delta;

        if (mapped.phdr[i].p_type != PT_LOAD ||
            strtab_vaddr < mapped.phdr[i].p_vaddr)
            continue;
        delta = strtab_vaddr - mapped.phdr[i].p_vaddr;
        if (delta < mapped.phdr[i].p_filesz) {
            source_index = i;
            break;
        }
    }
    if (!strtab_vaddr || candidate < 0 || source_index < 0)
        goto unmap;
    mapped.phdr[candidate] = mapped.phdr[source_index];
    mapped.phdr[candidate].p_align = 1;
    if (mapped.phdr[candidate].p_offset < mapped.size &&
        mapped.phdr[candidate].p_filesz <
            mapped.size - mapped.phdr[candidate].p_offset) {
        mapped.phdr[candidate].p_offset++;
    } else if (mapped.phdr[candidate].p_offset != 0) {
        mapped.phdr[candidate].p_offset--;
    } else {
        goto unmap;
    }
    if (msync(mapped.data, mapped.size, MS_SYNC) < 0)
        goto unmap;
    unmap_fixture(&mapped);
    {
        struct elf_info info;

        if (elf_parse(path, &info) < 0)
            rc = 0;
        else
            elf_info_free(&info);
    }
    goto out;

unmap:
    unmap_fixture(&mapped);
out:
    if (path[0])
        unlink(path);
    return rc;
}

enum admission_mutation {
    MUTATE_TYPE,
    MUTATE_CLASS,
    MUTATE_DATA,
    MUTATE_IDENT_VERSION,
    MUTATE_OSABI,
    MUTATE_ABI_VERSION,
    MUTATE_IDENT_PADDING,
    MUTATE_MACHINE,
    MUTATE_HEADER_SIZE,
    MUTATE_PHENT_SIZE,
    MUTATE_PHNUM_XNUM,
    MUTATE_PH_BOUNDS,
    MUTATE_UNALIGNED_PHOFF,
    MUTATE_SH_BOUNDS,
    MUTATE_DUP_DYNAMIC,
    MUTATE_DUP_INTERP,
    MUTATE_DYNAMIC_OUTSIDE_LOAD,
    MUTATE_DYNAMIC_INCONGRUENT,
    MUTATE_TLS_INCONGRUENT,
    MUTATE_EMPTY_LOADS,
    MUTATE_LOAD_ORDER,
    MUTATE_UNTERMINATED_DYNAMIC,
};

static int parser_rejects(const char *path)
{
    struct elf_info info;

    if (elf_check(path))
        return -1;
    if (elf_parse(path, &info) == 0) {
        elf_info_free(&info);
        return -1;
    }
    return 0;
}

static int spare_program_header(const struct mapped_elf *mapped)
{
    for (uint16_t i = 0; i < mapped->ehdr->e_phnum; i++) {
        uint32_t type = mapped->phdr[i].p_type;

        if (type != PT_LOAD && type != PT_DYNAMIC && type != PT_INTERP &&
            type != PT_PHDR && type != PT_TLS)
            return i;
    }
    return -1;
}

static int mutate_admission(const char *source,
                            enum admission_mutation mutation)
{
    char path[64] = "";
    struct mapped_elf mapped;
    int candidate;
    int source_index;
    int rc = -1;

    if (copy_fixture(source, path) < 0 || map_fixture(path, &mapped) < 0)
        goto out;
    switch (mutation) {
    case MUTATE_TYPE:
        mapped.ehdr->e_type = ET_REL;
        break;
    case MUTATE_CLASS:
        mapped.ehdr->e_ident[EI_CLASS] = ELFCLASS32;
        break;
    case MUTATE_DATA:
        mapped.ehdr->e_ident[EI_DATA] = ELFDATA2MSB;
        break;
    case MUTATE_IDENT_VERSION:
        mapped.ehdr->e_ident[EI_VERSION] = EV_NONE;
        break;
    case MUTATE_OSABI:
        mapped.ehdr->e_ident[EI_OSABI] = ELFOSABI_FREEBSD;
        break;
    case MUTATE_ABI_VERSION:
        mapped.ehdr->e_ident[EI_ABIVERSION] = 1;
        break;
    case MUTATE_IDENT_PADDING:
        mapped.ehdr->e_ident[EI_PAD] = 1;
        break;
    case MUTATE_MACHINE:
        mapped.ehdr->e_machine = EM_NONE;
        break;
    case MUTATE_HEADER_SIZE:
        mapped.ehdr->e_ehsize--;
        break;
    case MUTATE_PHENT_SIZE:
        mapped.ehdr->e_phentsize--;
        break;
    case MUTATE_PHNUM_XNUM:
        mapped.ehdr->e_phnum = PN_XNUM;
        break;
    case MUTATE_PH_BOUNDS:
        mapped.ehdr->e_phoff = mapped.size - sizeof(Elf64_Phdr) + 1;
        break;
    case MUTATE_UNALIGNED_PHOFF:
        mapped.ehdr->e_phoff++;
        break;
    case MUTATE_SH_BOUNDS:
        if (mapped.ehdr->e_shoff == 0)
            goto unmap;
        mapped.ehdr->e_shoff = mapped.size - sizeof(Elf64_Shdr) + 1;
        break;
    case MUTATE_DUP_DYNAMIC:
        candidate = spare_program_header(&mapped);
        source_index = -1;
        for (uint16_t i = 0; i < mapped.ehdr->e_phnum; i++)
            if (mapped.phdr[i].p_type == PT_DYNAMIC)
                source_index = i;
        if (candidate < 0 || source_index < 0)
            goto unmap;
        mapped.phdr[candidate] = mapped.phdr[source_index];
        break;
    case MUTATE_DUP_INTERP:
        candidate = spare_program_header(&mapped);
        source_index = -1;
        for (uint16_t i = 0; i < mapped.ehdr->e_phnum; i++)
            if (mapped.phdr[i].p_type == PT_INTERP)
                source_index = i;
        if (candidate < 0 || source_index < 0)
            goto unmap;
        mapped.phdr[candidate] = mapped.phdr[source_index];
        break;
    case MUTATE_DYNAMIC_OUTSIDE_LOAD: {
        uint64_t max_load_end = 0;
        uint64_t outside;

        source_index = -1;
        for (uint16_t i = 0; i < mapped.ehdr->e_phnum; i++) {
            uint64_t end;

            if (mapped.phdr[i].p_type == PT_DYNAMIC)
                source_index = i;
            if (mapped.phdr[i].p_type != PT_LOAD ||
                mapped.phdr[i].p_vaddr >
                    UINT64_MAX - mapped.phdr[i].p_memsz)
                continue;
            end = mapped.phdr[i].p_vaddr + mapped.phdr[i].p_memsz;
            if (end > max_load_end)
                max_load_end = end;
        }
        if (source_index < 0 || max_load_end > UINT64_MAX - 0x1fff)
            goto unmap;
        outside = (max_load_end + 0xfff) & ~(uint64_t)0xfff;
        outside += 0x1000;
        if (mapped.phdr[source_index].p_memsz > UINT64_MAX - outside)
            goto unmap;
        mapped.phdr[source_index].p_vaddr = outside;
        mapped.phdr[source_index].p_paddr = outside;
        break;
    }
    case MUTATE_DYNAMIC_INCONGRUENT:
        source_index = -1;
        for (uint16_t i = 0; i < mapped.ehdr->e_phnum; i++)
            if (mapped.phdr[i].p_type == PT_DYNAMIC)
                source_index = i;
        if (source_index < 0)
            goto unmap;
        mapped.phdr[source_index].p_align = 2;
        mapped.phdr[source_index].p_vaddr ^= 1;
        mapped.phdr[source_index].p_paddr =
            mapped.phdr[source_index].p_vaddr;
        break;
    case MUTATE_TLS_INCONGRUENT:
        source_index = -1;
        for (uint16_t i = 0; i < mapped.ehdr->e_phnum; i++)
            if (mapped.phdr[i].p_type == PT_TLS)
                source_index = i;
        if (source_index < 0)
            goto unmap;
        mapped.phdr[source_index].p_align = 2;
        mapped.phdr[source_index].p_vaddr ^= 1;
        mapped.phdr[source_index].p_paddr =
            mapped.phdr[source_index].p_vaddr;
        break;
    case MUTATE_EMPTY_LOADS:
        for (uint16_t i = 0; i < mapped.ehdr->e_phnum; i++) {
            if (mapped.phdr[i].p_type == PT_LOAD) {
                mapped.phdr[i].p_filesz = 0;
                mapped.phdr[i].p_memsz = 0;
            } else if (mapped.phdr[i].p_type == PT_DYNAMIC) {
                mapped.phdr[i].p_type = PT_NULL;
            }
        }
        break;
    case MUTATE_LOAD_ORDER: {
        int first = -1;
        int last = -1;
        Elf64_Phdr temporary;

        for (uint16_t i = 0; i < mapped.ehdr->e_phnum; i++) {
            if (mapped.phdr[i].p_type != PT_LOAD)
                continue;
            if (first < 0)
                first = i;
            last = i;
        }
        if (first < 0 || last <= first ||
            mapped.phdr[first].p_vaddr >= mapped.phdr[last].p_vaddr)
            goto unmap;
        temporary = mapped.phdr[first];
        mapped.phdr[first] = mapped.phdr[last];
        mapped.phdr[last] = temporary;
        break;
    }
    case MUTATE_UNTERMINATED_DYNAMIC:
        for (size_t i = 0; i < mapped.dynamic_count; i++)
            if (mapped.dynamic[i].d_tag == DT_NULL)
                mapped.dynamic[i].d_tag = DT_DEBUG;
        break;
    }
    if (msync(mapped.data, mapped.size, MS_SYNC) < 0)
        goto unmap;
    unmap_fixture(&mapped);
    rc = parser_rejects(path);
    goto out;

unmap:
    unmap_fixture(&mapped);
out:
    if (path[0])
        unlink(path);
    return rc;
}

static int malformed_admission_rejected(const char *shared_object,
                                        const char *executable)
{
    static const enum admission_mutation shared_mutations[] = {
        MUTATE_TYPE,
        MUTATE_CLASS,
        MUTATE_DATA,
        MUTATE_IDENT_VERSION,
        MUTATE_OSABI,
        MUTATE_ABI_VERSION,
        MUTATE_IDENT_PADDING,
        MUTATE_MACHINE,
        MUTATE_HEADER_SIZE,
        MUTATE_PHENT_SIZE,
        MUTATE_PHNUM_XNUM,
        MUTATE_PH_BOUNDS,
        MUTATE_UNALIGNED_PHOFF,
        MUTATE_SH_BOUNDS,
        MUTATE_DUP_DYNAMIC,
        MUTATE_DYNAMIC_OUTSIDE_LOAD,
        MUTATE_DYNAMIC_INCONGRUENT,
        MUTATE_TLS_INCONGRUENT,
        MUTATE_EMPTY_LOADS,
        MUTATE_LOAD_ORDER,
        MUTATE_UNTERMINATED_DYNAMIC,
    };

    for (size_t i = 0;
         i < sizeof(shared_mutations) / sizeof(shared_mutations[0]); i++)
        if (mutate_admission(shared_object, shared_mutations[i]) < 0)
            return -1;
    return mutate_admission(executable, MUTATE_DUP_INTERP);
}

static int descriptor_parse_is_path_race_safe(const char *source)
{
    static const char replacement[] = "not an ELF";
    struct elf_info info;
    struct stat source_stat;
    char path[64] = "";
    int source_fd = -1;
    int replacement_fd = -1;
    int rc = -1;

    if (copy_fixture(source, path) < 0)
        goto out;
    source_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (source_fd < 0 || fstat(source_fd, &source_stat) < 0 ||
        source_stat.st_size < 0 || unlink(path) < 0)
        goto out;
    replacement_fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                          0600);
    if (replacement_fd < 0 ||
        write(replacement_fd, replacement, sizeof(replacement)) !=
            (ssize_t)sizeof(replacement))
        goto out;
    if (close(replacement_fd) < 0) {
        replacement_fd = -1;
        goto out;
    }
    replacement_fd = -1;

    if (elf_parse_fd(source_fd, &info) < 0)
        goto out;
    elf_info_free(&info);
    if (elf_parse_fd_range(source_fd, 0, (size_t)source_stat.st_size,
                           &info) < 0)
        goto out;
    elf_info_free(&info);
    if (elf_parse(path, &info) == 0) {
        elf_info_free(&info);
        goto out;
    }
    rc = 0;

out:
    if (replacement_fd >= 0)
        close(replacement_fd);
    if (source_fd >= 0)
        close(source_fd);
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
    if (ambiguous_vaddr_translation_rejected(argv[1]) < 0)
        return 9;
    if (malformed_admission_rejected(argv[1], argv[0]) < 0)
        return 7;
    if (descriptor_parse_is_path_race_safe(argv[1]) < 0)
        return 8;
    if (argc == 3) {
        if (parse_external_ie_requires_static_tls(argv[2]) < 0)
            return 5;
        if (tpoff_without_flag(argv[2]) < 0)
            return 6;
    }
    return 0;
}
