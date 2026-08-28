#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "elf_parser.h"

#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define DLFREEZE_VER_FLG_INFO 0x4U

struct mapped_elf {
    int fd;
    size_t size;
    uint8_t *data;
    Elf64_Ehdr ehdr;
    Elf64_Phdr *phdr;
    size_t phnum;
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

    strcpy(path, "/tmp/dlfreeze-elf-version.XXXXXX");
    output = mkstemp(path);
    input = open(source, O_RDONLY | O_CLOEXEC);
    if (input < 0 || output < 0)
        goto out;
    while ((count = read(input, buffer, sizeof(buffer))) > 0) {
        ssize_t offset = 0;

        while (offset < count) {
            ssize_t written = write(output, buffer + offset,
                                    (size_t)(count - offset));

            if (written <= 0)
                goto out;
            offset += written;
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

static int copy_named_fixture(const char *source, const char *path)
{
    char buffer[16384];
    int input = -1;
    int output = -1;
    int rc = -1;
    ssize_t count;

    input = open(source, O_RDONLY | O_CLOEXEC);
    output = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0700);
    if (input < 0 || output < 0)
        goto out;
    while ((count = read(input, buffer, sizeof(buffer))) > 0) {
        ssize_t offset = 0;

        while (offset < count) {
            ssize_t written = write(output, buffer + offset,
                                    (size_t)(count - offset));

            if (written <= 0)
                goto out;
            offset += written;
        }
    }
    if (count == 0)
        rc = 0;
out:
    if (input >= 0)
        close(input);
    if (output >= 0 && close(output) < 0)
        rc = -1;
    if (rc < 0)
        unlink(path);
    return rc;
}

static int map_fixture(const char *path, struct mapped_elf *mapped)
{
    struct stat st;
    const uint8_t *raw;

    memset(mapped, 0, sizeof(*mapped));
    mapped->fd = -1;
    mapped->fd = open(path, O_RDWR | O_CLOEXEC);
    if (mapped->fd < 0 || fstat(mapped->fd, &st) < 0 ||
        st.st_size < (off_t)sizeof(mapped->ehdr))
        goto fail;
    mapped->size = (size_t)st.st_size;
    mapped->data = mmap(NULL, mapped->size, PROT_READ | PROT_WRITE,
                        MAP_SHARED, mapped->fd, 0);
    if (mapped->data == MAP_FAILED)
        goto fail;
    memcpy(&mapped->ehdr, mapped->data, sizeof(mapped->ehdr));
    if (memcmp(mapped->ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        mapped->ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        mapped->ehdr.e_phentsize != sizeof(Elf64_Phdr) ||
        mapped->ehdr.e_phnum == 0 ||
        mapped->ehdr.e_phoff > mapped->size ||
        mapped->ehdr.e_phnum >
            (mapped->size - mapped->ehdr.e_phoff) / sizeof(Elf64_Phdr))
        goto fail;
    mapped->phnum = mapped->ehdr.e_phnum;
    mapped->phdr = malloc(mapped->phnum * sizeof(*mapped->phdr));
    if (!mapped->phdr)
        goto fail;
    memcpy(mapped->phdr, mapped->data + mapped->ehdr.e_phoff,
           mapped->phnum * sizeof(*mapped->phdr));

    for (size_t i = 0; i < mapped->phnum; i++) {
        if (mapped->phdr[i].p_type != PT_DYNAMIC)
            continue;
        if (mapped->phdr[i].p_offset > mapped->size ||
            mapped->phdr[i].p_filesz >
                mapped->size - mapped->phdr[i].p_offset ||
            mapped->phdr[i].p_filesz % sizeof(Elf64_Dyn) != 0)
            goto fail;
        raw = mapped->data + mapped->phdr[i].p_offset;
        mapped->dynamic = (Elf64_Dyn *)(uintptr_t)raw;
        mapped->dynamic_count =
            (size_t)(mapped->phdr[i].p_filesz / sizeof(Elf64_Dyn));
        return 0;
    }
fail:
    free(mapped->phdr);
    if (mapped->data && mapped->data != MAP_FAILED)
        munmap(mapped->data, mapped->size);
    if (mapped->fd >= 0)
        close(mapped->fd);
    memset(mapped, 0, sizeof(*mapped));
    mapped->fd = -1;
    return -1;
}

static void unmap_fixture(struct mapped_elf *mapped)
{
    free(mapped->phdr);
    if (mapped->data && mapped->data != MAP_FAILED)
        munmap(mapped->data, mapped->size);
    if (mapped->fd >= 0)
        close(mapped->fd);
    memset(mapped, 0, sizeof(*mapped));
    mapped->fd = -1;
}

static uint8_t *vaddr_file(struct mapped_elf *mapped, uint64_t address,
                           size_t length)
{
    uint8_t *result = NULL;

    for (size_t i = 0; i < mapped->phnum; i++) {
        uint64_t delta;
        uint64_t offset;
        uint8_t *candidate;

        if (mapped->phdr[i].p_type != PT_LOAD ||
            address < mapped->phdr[i].p_vaddr)
            continue;
        delta = address - mapped->phdr[i].p_vaddr;
        if (delta > mapped->phdr[i].p_filesz ||
            length > mapped->phdr[i].p_filesz - delta ||
            mapped->phdr[i].p_offset > UINT64_MAX - delta)
            continue;
        offset = mapped->phdr[i].p_offset + delta;
        if (offset > mapped->size || length > mapped->size - offset)
            continue;
        candidate = mapped->data + offset;
        if (result && result != candidate)
            return NULL;
        result = candidate;
    }
    return result;
}

static uint32_t version_name_hash(const char *name)
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

static const char *mapped_string(const uint8_t *strtab, size_t size,
                                 uint32_t offset)
{
    if (offset >= size || !memchr(strtab + offset, '\0', size - offset))
        return NULL;
    return (const char *)strtab + offset;
}

static int rehash_version_requirement(const char *path,
                                      const char *provider_name,
                                      const char *version_name)
{
    struct mapped_elf mapped;
    struct elf_info check;
    uint64_t strtab_address = 0;
    uint64_t strtab_size = 0;
    uint64_t need_address = 0;
    uint64_t need_count = 0;
    uint8_t *strtab;
    int found = 0;
    int rc = -1;

    if (map_fixture(path, &mapped) < 0)
        return -1;
    for (size_t i = 0; i < mapped.dynamic_count; i++) {
        if (mapped.dynamic[i].d_tag == DT_NULL)
            break;
        if (mapped.dynamic[i].d_tag == DT_STRTAB)
            strtab_address = mapped.dynamic[i].d_un.d_ptr;
        else if (mapped.dynamic[i].d_tag == DT_STRSZ)
            strtab_size = mapped.dynamic[i].d_un.d_val;
        else if (mapped.dynamic[i].d_tag == DT_VERNEED)
            need_address = mapped.dynamic[i].d_un.d_ptr;
        else if (mapped.dynamic[i].d_tag == DT_VERNEEDNUM)
            need_count = mapped.dynamic[i].d_un.d_val;
    }
    if (strtab_size == 0 || strtab_size > SIZE_MAX ||
        need_count > mapped.size / sizeof(Elf64_Verneed) ||
        !(strtab = vaddr_file(&mapped, strtab_address,
                              (size_t)strtab_size)))
        goto out;

    for (uint64_t i = 0; need_address != 0 && i < need_count; i++) {
        uint8_t *raw = vaddr_file(&mapped, need_address,
                                  sizeof(Elf64_Verneed));
        Elf64_Verneed need;
        uint64_t aux_address;
        const char *file;

        if (!raw)
            goto out;
        memcpy(&need, raw, sizeof(need));
        file = mapped_string(strtab, (size_t)strtab_size, need.vn_file);
        if (!file || need_address > UINT64_MAX - need.vn_aux)
            goto out;
        aux_address = need_address + need.vn_aux;
        for (uint16_t j = 0; j < need.vn_cnt; j++) {
            Elf64_Vernaux aux;
            const char *name;

            raw = vaddr_file(&mapped, aux_address, sizeof(aux));
            if (!raw)
                goto out;
            memcpy(&aux, raw, sizeof(aux));
            name = mapped_string(strtab, (size_t)strtab_size, aux.vna_name);
            if (!name)
                goto out;
            if (strcmp(file, provider_name) == 0 &&
                strcmp(name, version_name) == 0) {
                aux.vna_hash = version_name_hash(name);
                memcpy(raw, &aux, sizeof(aux));
                found++;
            }
            if (j + 1 < need.vn_cnt) {
                if (aux.vna_next == 0 ||
                    aux_address > UINT64_MAX - aux.vna_next)
                    goto out;
                aux_address += aux.vna_next;
            }
        }
        if (i + 1 < need_count) {
            if (need.vn_next == 0 ||
                need_address > UINT64_MAX - need.vn_next)
                goto out;
            need_address += need.vn_next;
        }
    }
    if (found != 1 || msync(mapped.data, mapped.size, MS_SYNC) < 0)
        goto out;
    rc = 0;
out:
    unmap_fixture(&mapped);
    if (rc == 0) {
        if (elf_parse(path, &check) < 0)
            return -1;
        elf_info_free(&check);
    }
    return rc;
}

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

static uint8_t *version_requirement_aux(struct mapped_elf *mapped,
                                        size_t ordinal);

static int malformed_count_rejected(const char *source)
{
    char path[64] = "";
    struct mapped_elf mapped;
    int found = 0;
    int rc = -1;

    if (copy_fixture(source, path) < 0 || map_fixture(path, &mapped) < 0)
        goto out;
    for (size_t i = 0; i < mapped.dynamic_count; i++) {
        if (mapped.dynamic[i].d_tag == DT_NULL)
            break;
        if (mapped.dynamic[i].d_tag == DT_VERNEEDNUM) {
            mapped.dynamic[i].d_un.d_val = UINT64_MAX;
            found = 1;
            break;
        }
    }
    if (!found || msync(mapped.data, mapped.size, MS_SYNC) < 0) {
        unmap_fixture(&mapped);
        goto out;
    }
    unmap_fixture(&mapped);
    rc = parser_rejects(path);
out:
    if (path[0])
        unlink(path);
    return rc;
}

static int forged_hash_rejected(const char *source, size_t ordinal)
{
    char path[64] = "";
    struct mapped_elf mapped;
    uint8_t *raw;
    Elf64_Vernaux aux;
    int rc = -1;

    if (copy_fixture(source, path) < 0 || map_fixture(path, &mapped) < 0)
        goto out;
    raw = version_requirement_aux(&mapped, ordinal);
    if (!raw) {
        unmap_fixture(&mapped);
        goto out;
    }
    memcpy(&aux, raw, sizeof(aux));
    aux.vna_hash ^= 1U;
    memcpy(raw, &aux, sizeof(aux));
    if (msync(mapped.data, mapped.size, MS_SYNC) < 0) {
        unmap_fixture(&mapped);
        goto out;
    }
    unmap_fixture(&mapped);
    rc = parser_rejects(path);
out:
    if (path[0])
        unlink(path);
    return rc;
}

static uint8_t *version_requirement_aux(struct mapped_elf *mapped,
                                        size_t ordinal)
{
    uint64_t address = 0;
    uint64_t count = 0;

    for (size_t i = 0; i < mapped->dynamic_count; i++) {
        if (mapped->dynamic[i].d_tag == DT_NULL)
            break;
        if (mapped->dynamic[i].d_tag == DT_VERNEED)
            address = mapped->dynamic[i].d_un.d_ptr;
        else if (mapped->dynamic[i].d_tag == DT_VERNEEDNUM)
            count = mapped->dynamic[i].d_un.d_val;
    }
    for (uint64_t i = 0; i < count; i++) {
        uint8_t *raw = vaddr_file(mapped, address, sizeof(Elf64_Verneed));
        Elf64_Verneed need;
        uint64_t aux_address;

        if (!raw)
            return NULL;
        memcpy(&need, raw, sizeof(need));
        if (address > UINT64_MAX - need.vn_aux)
            return NULL;
        aux_address = address + need.vn_aux;
        for (uint16_t j = 0; j < need.vn_cnt; j++) {
            Elf64_Vernaux aux;

            raw = vaddr_file(mapped, aux_address, sizeof(aux));
            if (!raw)
                return NULL;
            if (ordinal == 0)
                return raw;
            ordinal--;
            memcpy(&aux, raw, sizeof(aux));
            if (j + 1 < need.vn_cnt) {
                if (aux.vna_next == 0 ||
                    aux_address > UINT64_MAX - aux.vna_next)
                    return NULL;
                aux_address += aux.vna_next;
            }
        }
        if (i + 1 < count) {
            if (need.vn_next == 0 || address > UINT64_MAX - need.vn_next)
                return NULL;
            address += need.vn_next;
        }
    }
    return NULL;
}

static uint8_t *version_definition_record(struct mapped_elf *mapped,
                                          size_t ordinal)
{
    uint64_t address = 0;
    uint64_t count = 0;

    for (size_t i = 0; i < mapped->dynamic_count; i++) {
        if (mapped->dynamic[i].d_tag == DT_NULL)
            break;
        if (mapped->dynamic[i].d_tag == DT_VERDEF)
            address = mapped->dynamic[i].d_un.d_ptr;
        else if (mapped->dynamic[i].d_tag == DT_VERDEFNUM)
            count = mapped->dynamic[i].d_un.d_val;
    }
    if (ordinal >= count)
        return NULL;
    for (size_t i = 0; i <= ordinal; i++) {
        uint8_t *raw = vaddr_file(mapped, address, sizeof(Elf64_Verdef));
        Elf64_Verdef definition;

        if (!raw)
            return NULL;
        if (i == ordinal)
            return raw;
        memcpy(&definition, raw, sizeof(definition));
        if (definition.vd_next == 0 ||
            address > UINT64_MAX - definition.vd_next)
            return NULL;
        address += definition.vd_next;
    }
    return NULL;
}

static int forged_definition_hash_rejected(const char *source,
                                           size_t ordinal)
{
    char path[64] = "";
    struct mapped_elf mapped;
    uint8_t *raw;
    Elf64_Verdef definition;
    int rc = -1;

    if (copy_fixture(source, path) < 0 || map_fixture(path, &mapped) < 0)
        goto out;
    raw = version_definition_record(&mapped, ordinal);
    if (!raw) {
        unmap_fixture(&mapped);
        goto out;
    }
    memcpy(&definition, raw, sizeof(definition));
    definition.vd_hash ^= 1U;
    memcpy(raw, &definition, sizeof(definition));
    if (msync(mapped.data, mapped.size, MS_SYNC) < 0) {
        unmap_fixture(&mapped);
        goto out;
    }
    unmap_fixture(&mapped);
    rc = parser_rejects(path);
out:
    if (path[0])
        unlink(path);
    return rc;
}

static int has_split_verneed_layout(const char *path)
{
    struct mapped_elf mapped;
    uint64_t address = 0;
    uint64_t count = 0;
    int result = -1;

    if (map_fixture(path, &mapped) < 0)
        return -1;
    for (size_t i = 0; i < mapped.dynamic_count; i++) {
        if (mapped.dynamic[i].d_tag == DT_NULL)
            break;
        if (mapped.dynamic[i].d_tag == DT_VERNEED)
            address = mapped.dynamic[i].d_un.d_ptr;
        else if (mapped.dynamic[i].d_tag == DT_VERNEEDNUM)
            count = mapped.dynamic[i].d_un.d_val;
    }
    for (uint64_t i = 0; address != 0 && i < count; i++) {
        uint8_t *raw = vaddr_file(&mapped, address, sizeof(Elf64_Verneed));
        Elf64_Verneed need;

        if (!raw)
            goto out;
        memcpy(&need, raw, sizeof(need));
        if (need.vn_next != 0 && need.vn_aux >= need.vn_next) {
            result = 0;
            goto out;
        }
        if (i + 1 < count) {
            if (need.vn_next == 0 || address > UINT64_MAX - need.vn_next)
                goto out;
            address += need.vn_next;
        }
    }
out:
    unmap_fixture(&mapped);
    return result;
}

static int write_informational_requirement(const char *source,
                                           const char *output,
                                           const char *provider_name)
{
    struct elf_info info;
    struct elf_info check;
    struct mapped_elf mapped;
    uint8_t *raw;
    Elf64_Vernaux aux;
    size_t ordinal = SIZE_MAX;
    int rc = -1;

    if (elf_parse(source, &info) < 0)
        return -1;
    for (size_t i = 0; i < info.version_requirement_count; i++) {
        if (strcmp(info.version_requirements[i].file, provider_name) == 0) {
            ordinal = i;
            break;
        }
    }
    elf_info_free(&info);
    if (ordinal == SIZE_MAX || copy_named_fixture(source, output) < 0 ||
        map_fixture(output, &mapped) < 0)
        goto out;
    raw = version_requirement_aux(&mapped, ordinal);
    if (!raw) {
        unmap_fixture(&mapped);
        goto out;
    }
    memcpy(&aux, raw, sizeof(aux));
    aux.vna_flags |= DLFREEZE_VER_FLG_INFO;
    memcpy(raw, &aux, sizeof(aux));
    if (msync(mapped.data, mapped.size, MS_SYNC) < 0) {
        unmap_fixture(&mapped);
        goto out;
    }
    unmap_fixture(&mapped);
    if (elf_parse(output, &check) < 0)
        goto out;
    for (size_t i = 0; i < check.version_requirement_count; i++) {
        if (strcmp(check.version_requirements[i].file, provider_name) == 0 &&
            (check.version_requirements[i].flags &
             DLFREEZE_VER_FLG_INFO) != 0) {
            rc = 0;
            break;
        }
    }
    elf_info_free(&check);
out:
    if (rc < 0)
        unlink(output);
    return rc;
}

static int informational_requirement_is_required(
    const char *source, size_t ordinal, const char *provider_name,
    const struct elf_info *older)
{
    char path[64] = "";
    struct mapped_elf mapped;
    struct elf_info modified;
    uint8_t *raw;
    Elf64_Vernaux aux;
    int rc = -1;

    if (copy_fixture(source, path) < 0 || map_fixture(path, &mapped) < 0)
        goto out;
    raw = version_requirement_aux(&mapped, ordinal);
    if (!raw) {
        unmap_fixture(&mapped);
        goto out;
    }
    memcpy(&aux, raw, sizeof(aux));
    aux.vna_flags |= DLFREEZE_VER_FLG_INFO;
    memcpy(raw, &aux, sizeof(aux));
    if (msync(mapped.data, mapped.size, MS_SYNC) < 0) {
        unmap_fixture(&mapped);
        goto out;
    }
    unmap_fixture(&mapped);
    if (elf_parse(path, &modified) < 0)
        goto out;
    rc = elf_version_requirements_match(&modified, provider_name, older)
             ? -1 : 0;
    elf_info_free(&modified);
out:
    if (path[0])
        unlink(path);
    return rc;
}

static int informational_definition_is_accepted(
    const char *source, size_t ordinal, const struct elf_info *consumer,
    const char *provider_name)
{
    char path[64] = "";
    struct mapped_elf mapped;
    struct elf_info modified;
    uint8_t *raw;
    Elf64_Verdef definition;
    int rc = -1;

    if (copy_fixture(source, path) < 0 || map_fixture(path, &mapped) < 0)
        goto out;
    raw = version_definition_record(&mapped, ordinal);
    if (!raw) {
        unmap_fixture(&mapped);
        goto out;
    }
    memcpy(&definition, raw, sizeof(definition));
    definition.vd_flags |= DLFREEZE_VER_FLG_INFO;
    memcpy(raw, &definition, sizeof(definition));
    if (msync(mapped.data, mapped.size, MS_SYNC) < 0) {
        unmap_fixture(&mapped);
        goto out;
    }
    unmap_fixture(&mapped);
    if (elf_parse(path, &modified) < 0)
        goto out;
    rc = elf_version_requirements_match(consumer, provider_name, &modified)
             ? 0 : -1;
    elf_info_free(&modified);
out:
    if (path[0])
        unlink(path);
    return rc;
}

int main(int argc, char **argv)
{
    struct elf_info consumer;
    struct elf_info current;
    struct elf_info older;
    int saw_requirement = 0;
    int saw_definition = 0;
    size_t requirement_ordinal = 0;
    size_t definition_ordinal = 0;
    int rc = 1;

    if (argc == 5 && strcmp(argv[1], "--rehash-requirement") == 0)
        return rehash_version_requirement(argv[2], argv[3], argv[4]) < 0
                   ? 12 : 0;
    if (argc == 3 && strcmp(argv[1], "--require-split-verneed") == 0)
        return has_split_verneed_layout(argv[2]) < 0 ? 11 : 0;
    if (argc == 5 && strcmp(argv[1], "--mark-info") == 0)
        return write_informational_requirement(argv[2], argv[3], argv[4]) < 0
                   ? 10 : 0;
    if (argc != 5)
        return 64;
    if (elf_parse(argv[1], &consumer) < 0)
        return 2;
    if (elf_parse(argv[2], &current) < 0) {
        rc = 3;
        goto consumer_out;
    }
    if (elf_parse(argv[3], &older) < 0) {
        rc = 4;
        goto current_out;
    }
    for (size_t i = 0; i < consumer.version_requirement_count; i++) {
        if (strcmp(consumer.version_requirements[i].file, argv[4]) == 0) {
            saw_requirement = 1;
            requirement_ordinal = i;
            for (size_t j = 0; j < current.version_definition_count; j++)
                if (strcmp(current.version_definitions[j].name,
                           consumer.version_requirements[i].name) == 0) {
                    definition_ordinal = j;
                    saw_definition = 1;
                }
            break;
        }
    }
    if (!saw_requirement || !saw_definition ||
        !elf_version_requirements_match(&consumer, argv[4], &current) ||
        elf_version_requirements_match(&consumer, argv[4], &older)) {
        rc = 5;
        goto older_out;
    }
    if (malformed_count_rejected(argv[1]) < 0) {
        rc = 6;
        goto older_out;
    }
    if (forged_hash_rejected(argv[1], requirement_ordinal) < 0) {
        rc = 7;
        goto older_out;
    }
    if (forged_definition_hash_rejected(argv[2], definition_ordinal) < 0) {
        rc = 8;
        goto older_out;
    }
    if (informational_requirement_is_required(
            argv[1], requirement_ordinal, argv[4], &older) < 0) {
        rc = 9;
        goto older_out;
    }
    if (informational_definition_is_accepted(
            argv[2], definition_ordinal, &consumer, argv[4]) < 0) {
        rc = 10;
        goto older_out;
    }
    rc = 0;

older_out:
    elf_info_free(&older);
current_out:
    elf_info_free(&current);
consumer_out:
    elf_info_free(&consumer);
    return rc;
}
