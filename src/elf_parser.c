#include "elf_parser.h"
#include "load_segments.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__x86_64__)
#define DLFREEZE_ELF_MACHINE EM_X86_64
#elif defined(__aarch64__)
#define DLFREEZE_ELF_MACHINE EM_AARCH64
#else
#error "dlfreeze supports only x86-64 and AArch64 ELF"
#endif

#ifndef ELFOSABI_LINUX
#define ELFOSABI_LINUX 3
#endif

/* Solaris originated ELF symbol versioning and defines this Vernaux flag,
 * while glibc and musl's public elf.h omit it.  Binutils and LLVM retain the
 * value.  Parsing it is portable, but GNU ld.so does not implement Solaris's
 * optional-at-runtime semantics, so matching below treats it as required. */
#define DLFRZ_VER_FLG_INFO 0x4U

struct elf64_load_translation {
    uint64_t vaddr;
    uint64_t offset;
    uint64_t filesz;
    size_t widest_index;
};

struct elf64_image {
    Elf64_Ehdr ehdr;
    Elf64_Phdr *phdr;
    size_t phnum;
    struct elf64_load_translation *load_index;
    size_t load_index_count;
};

struct dynamic_string_table {
    const char *data;
    size_t size;
    size_t hash_work;
    size_t hash_work_limit;
    struct dynamic_string_cache_entry *cache;
};

#define DYNAMIC_STRING_CACHE_COUNT 256U

struct dynamic_string_cache_entry {
    size_t offset;
    size_t length;
    uint64_t needed_hash;
    uint32_t version_hash;
    int valid;
};

struct needed_name_index {
    const char *name;
    size_t length;
    uint64_t hash;
};

static int range_in_file(uint64_t offset, uint64_t length, size_t size)
{
    return offset <= size && length <= size - offset;
}

static int power_of_two_or_zero(uint64_t value)
{
    return value == 0 || (value & (value - 1)) == 0;
}

static int segment_coordinates_are_congruent(const Elf64_Phdr *phdr)
{
    return phdr->p_align <= 1 ||
           phdr->p_offset % phdr->p_align ==
               phdr->p_vaddr % phdr->p_align;
}

static int elf64_section_headers_valid(const uint8_t *data, size_t size,
                                       const Elf64_Ehdr *ehdr)
{
    Elf64_Shdr section_zero;
    size_t count;
    size_t stride;
    size_t string_index = SIZE_MAX;

    if (ehdr->e_shoff == 0) {
        return ehdr->e_shnum == 0 && ehdr->e_shstrndx == SHN_UNDEF &&
               (ehdr->e_shentsize == 0 ||
                ehdr->e_shentsize == sizeof(Elf64_Shdr));
    }
    if (ehdr->e_shoff < sizeof(*ehdr) ||
        ehdr->e_shentsize < sizeof(Elf64_Shdr) ||
        !range_in_file(ehdr->e_shoff, sizeof(section_zero), size))
        return 0;
    stride = ehdr->e_shentsize;

    memcpy(&section_zero, data + ehdr->e_shoff, sizeof(section_zero));
    if (section_zero.sh_type != SHT_NULL)
        return 0;
    if (ehdr->e_shnum == 0) {
        if (section_zero.sh_size == 0 || section_zero.sh_size > SIZE_MAX)
            return 0;
        count = (size_t)section_zero.sh_size;
    } else {
        if (ehdr->e_shnum >= SHN_LORESERVE)
            return 0;
        count = ehdr->e_shnum;
    }
    if (count > SIZE_MAX / stride)
        return 0;
    if (!range_in_file(ehdr->e_shoff, count * stride, size))
        return 0;

    if (ehdr->e_shstrndx == SHN_XINDEX) {
        string_index = section_zero.sh_link;
    } else if (ehdr->e_shstrndx != SHN_UNDEF) {
        if (ehdr->e_shstrndx >= SHN_LORESERVE)
            return 0;
        string_index = ehdr->e_shstrndx;
    }
    if (string_index != SIZE_MAX && string_index >= count)
        return 0;

    for (size_t i = 0; i < count; i++) {
        Elf64_Shdr section;

        memcpy(&section,
               data + ehdr->e_shoff + i * stride,
               sizeof(section));
        if (!power_of_two_or_zero(section.sh_addralign))
            return 0;
        if (section.sh_type != SHT_NOBITS &&
            !range_in_file(section.sh_offset, section.sh_size, size))
            return 0;
        if (section.sh_entsize != 0 &&
            section.sh_size % section.sh_entsize != 0)
            return 0;
        if (i == string_index && section.sh_type != SHT_STRTAB)
            return 0;
    }
    return 1;
}

static int elf64_dynamic_terminated(const uint8_t *data, size_t size,
                                    const Elf64_Phdr *dynamic)
{
    size_t count;

    if (dynamic->p_filesz < sizeof(Elf64_Dyn) ||
        dynamic->p_filesz % sizeof(Elf64_Dyn) != 0 ||
        !range_in_file(dynamic->p_offset, dynamic->p_filesz, size))
        return 0;
    count = (size_t)(dynamic->p_filesz / sizeof(Elf64_Dyn));
    for (size_t i = 0; i < count; i++) {
        Elf64_Dyn item;

        memcpy(&item,
               data + dynamic->p_offset + i * sizeof(Elf64_Dyn),
               sizeof(item));
        if (item.d_tag == DT_NULL)
            return 1;
    }
    return 0;
}

static int elf64_interp_valid(const uint8_t *data, size_t size,
                              const Elf64_Phdr *interp)
{
    const uint8_t *value;
    size_t length;

    if (interp->p_filesz < 2 || interp->p_filesz > SIZE_MAX ||
        !range_in_file(interp->p_offset, interp->p_filesz, size))
        return 0;
    value = data + interp->p_offset;
    length = (size_t)interp->p_filesz;
    return value[length - 1] == '\0' && value[0] != '\0' &&
           memchr(value, '\0', length - 1) == NULL;
}

/* Validate everything shared by the quick admission gate and the full
 * dynamic parser.  File-backed headers are copied into aligned storage before
 * typed access, so a malicious e_phoff/e_shoff cannot create undefined
 * unaligned loads. */
static int elf64_image_open(const uint8_t *data, size_t size,
                            struct elf64_image *image)
{
    Elf64_Ehdr ehdr;
    size_t phdr_bytes;
    unsigned int interp_count = 0;
    unsigned int dynamic_count = 0;
    unsigned int tls_count = 0;
    unsigned int load_count = 0;
    unsigned int nonempty_load_count = 0;
    uint64_t previous_load_vaddr = 0;
    int saw_load = 0;
    const Elf64_Phdr *dynamic_phdr = NULL;

    memset(image, 0, sizeof(*image));
    if (!data || size < sizeof(ehdr))
        return -1;
    memcpy(&ehdr, data, sizeof(ehdr));

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr.e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr.e_ident[EI_VERSION] != EV_CURRENT ||
        (ehdr.e_ident[EI_OSABI] != ELFOSABI_NONE &&
         ehdr.e_ident[EI_OSABI] != ELFOSABI_LINUX) ||
        ehdr.e_ident[EI_ABIVERSION] != 0 ||
        (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) ||
        ehdr.e_machine != DLFREEZE_ELF_MACHINE ||
        ehdr.e_version != EV_CURRENT || ehdr.e_flags != 0 ||
        ehdr.e_ehsize != sizeof(ehdr) ||
        ehdr.e_phentsize != sizeof(Elf64_Phdr) ||
        ehdr.e_phoff < sizeof(ehdr) || ehdr.e_phnum == 0 ||
        ehdr.e_phnum == PN_XNUM)
        return -1;
    for (size_t i = EI_PAD; i < EI_NIDENT; i++)
        if (ehdr.e_ident[i] != 0)
            return -1;

    phdr_bytes = (size_t)ehdr.e_phnum * sizeof(Elf64_Phdr);
    if (!range_in_file(ehdr.e_phoff, phdr_bytes, size) ||
        !elf64_section_headers_valid(data, size, &ehdr))
        return -1;

    image->phdr = malloc(phdr_bytes);
    if (!image->phdr)
        return -1;
    memcpy(image->phdr, data + ehdr.e_phoff, phdr_bytes);
    image->ehdr = ehdr;
    image->phnum = ehdr.e_phnum;
    image->load_index = calloc(image->phnum, sizeof(*image->load_index));
    if (!image->load_index)
        goto fail;

    for (size_t i = 0; i < image->phnum; i++) {
        const Elf64_Phdr *ph = &image->phdr[i];

        if (!power_of_two_or_zero(ph->p_align) ||
            (ph->p_filesz != 0 &&
             !range_in_file(ph->p_offset, ph->p_filesz, size)) ||
            ph->p_vaddr > UINT64_MAX - ph->p_memsz ||
            ((ph->p_type == PT_LOAD || ph->p_type == PT_DYNAMIC ||
              ph->p_type == PT_TLS) &&
             !segment_coordinates_are_congruent(ph)))
            goto fail;
        if (ph->p_type == PT_LOAD) {
            struct elf64_load_translation *translation;
            size_t index;

            load_count++;
            if ((saw_load && ph->p_vaddr < previous_load_vaddr) ||
                ph->p_filesz > ph->p_memsz)
                goto fail;
            previous_load_vaddr = ph->p_vaddr;
            saw_load = 1;
            if (ph->p_memsz != 0)
                nonempty_load_count++;
            if (ph->p_filesz == 0)
                continue;

            index = image->load_index_count++;
            translation = &image->load_index[index];
            translation->vaddr = ph->p_vaddr;
            translation->offset = ph->p_offset;
            translation->filesz = ph->p_filesz;
            translation->widest_index = index;
            if (index != 0) {
                const struct elf64_load_translation *previous =
                    &image->load_index[index - 1];
                size_t widest_index = previous->widest_index;
                const struct elf64_load_translation *widest =
                    &image->load_index[widest_index];
                uint64_t widest_end = widest->vaddr + widest->filesz;
                uint64_t translation_end =
                    translation->vaddr + translation->filesz;

                if (translation->vaddr < widest_end) {
                    uint64_t delta = translation->vaddr - widest->vaddr;

                    if (widest->offset > UINT64_MAX - delta ||
                        widest->offset + delta != translation->offset)
                        goto fail;
                }
                if (translation_end <= widest_end)
                    translation->widest_index = widest_index;
            }
        } else if (ph->p_type == PT_INTERP) {
            if (++interp_count != 1 || ph->p_filesz > ph->p_memsz ||
                !elf64_interp_valid(data, size, ph))
                goto fail;
        } else if (ph->p_type == PT_DYNAMIC) {
            if (++dynamic_count != 1 || ph->p_filesz > ph->p_memsz ||
                !elf64_dynamic_terminated(data, size, ph))
                goto fail;
            dynamic_phdr = ph;
        } else if (ph->p_type == PT_TLS) {
            if (++tls_count != 1 || ph->p_filesz > ph->p_memsz)
                goto fail;
        }
    }
    if (load_count == 0 || nonempty_load_count == 0 ||
        (dynamic_phdr &&
         !dlfrz_segment_is_contained_by_load(
             image->phdr, image->phnum, dynamic_phdr)))
        goto fail;
    return 0;

fail:
    free(image->load_index);
    free(image->phdr);
    memset(image, 0, sizeof(*image));
    return -1;
}

static void elf64_image_close(struct elf64_image *image)
{
    free(image->load_index);
    free(image->phdr);
    memset(image, 0, sizeof(*image));
}

static int dynamic_string_table_init(struct dynamic_string_table *table,
                                     const char *data, size_t size)
{
    memset(table, 0, sizeof(*table));
    /* ELF string tables reserve both index zero and the final byte.  With
     * those sentinels admitted once, every in-range suffix is terminated. */
    if (!data || size == 0 || data[0] != '\0' || data[size - 1] != '\0')
        return -1;
    table->data = data;
    table->size = size;
    table->hash_work_limit =
        size > SIZE_MAX / 8 ? SIZE_MAX : size * 8;
    table->cache = calloc(DYNAMIC_STRING_CACHE_COUNT,
                          sizeof(*table->cache));
    if (!table->cache) {
        memset(table, 0, sizeof(*table));
        return -1;
    }
    return 0;
}

static void dynamic_string_table_destroy(struct dynamic_string_table *table)
{
    free(table->cache);
    memset(table, 0, sizeof(*table));
}

static const char *dynamic_string(const struct dynamic_string_table *table,
                                  uint64_t offset)
{
    if (offset >= table->size)
        return NULL;
    return table->data + (size_t)offset;
}

/* The same offset may occur in thousands of version records.  Compute its
 * length and both hashes together, retain a small direct-mapped hot cache,
 * and cap cache-miss byte work to a constant multiple of DT_STRSZ.  Thus
 * repeated strings stay O(1), while deliberately colliding overlapping
 * suffixes fail closed instead of amplifying a small ELF into unbounded CPU. */
static int dynamic_string_metadata(struct dynamic_string_table *table,
                                   uint64_t raw_offset, size_t *length_out,
                                   uint64_t *needed_hash_out,
                                   uint32_t *version_hash_out)
{
    struct dynamic_string_cache_entry *entry;
    uint64_t needed_hash = UINT64_C(14695981039346656037);
    uint32_t version_hash = 0;
    size_t offset;
    size_t cursor;
    size_t slot;

    if (raw_offset >= table->size)
        return -1;
    offset = (size_t)raw_offset;
    slot = (size_t)((uint64_t)offset *
                    UINT64_C(11400714819323198485)) &
           (DYNAMIC_STRING_CACHE_COUNT - 1U);
    entry = &table->cache[slot];
    if (entry->valid && entry->offset == offset)
        goto found;

    cursor = offset;
    while (table->data[cursor] != '\0') {
        unsigned char value = (unsigned char)table->data[cursor];
        uint32_t high;

        if (table->hash_work == table->hash_work_limit)
            return -1;
        table->hash_work++;
        needed_hash ^= value;
        needed_hash *= UINT64_C(1099511628211);
        version_hash = (version_hash << 4) + value;
        high = version_hash & UINT32_C(0xf0000000);
        if (high != 0)
            version_hash ^= high >> 24;
        version_hash &= ~high;
        cursor++;
    }
    /* Keep empty and all-zero state distinguishable in diagnostics and make
     * the low bits less dependent on short common prefixes. */
    needed_hash ^= needed_hash >> 32;
    needed_hash *= UINT64_C(0xd6e8feb86659fd93);
    needed_hash ^= needed_hash >> 32;
    entry->offset = offset;
    entry->length = cursor - offset;
    entry->needed_hash = needed_hash;
    entry->version_hash = version_hash;
    entry->valid = 1;

found:
    if (length_out)
        *length_out = entry->length;
    if (needed_hash_out)
        *needed_hash_out = entry->needed_hash;
    if (version_hash_out)
        *version_hash_out = entry->version_hash;
    return 0;
}

static int needed_name_index_compare(const void *left, const void *right)
{
    const struct needed_name_index *a = left;
    const struct needed_name_index *b = right;

    if (a->hash < b->hash)
        return -1;
    if (a->hash > b->hash)
        return 1;
    if (a->length < b->length)
        return -1;
    if (a->length > b->length)
        return 1;
    return 0;
}

static int needed_name_index_contains(
    const struct needed_name_index *index, size_t count,
    struct dynamic_string_table *table, uint64_t offset)
{
    struct needed_name_index key;
    const char *name;
    size_t low = 0;
    size_t high = count;

    name = dynamic_string(table, offset);
    if (!name || dynamic_string_metadata(table, offset, &key.length,
                                         &key.hash, NULL) < 0)
        return -1;
    key.name = name;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        int order = needed_name_index_compare(&index[middle], &key);

        if (order < 0)
            low = middle + 1;
        else
            high = middle;
    }
    while (low < count && index[low].hash == key.hash &&
           index[low].length == key.length) {
        if (memcmp(index[low].name, name, key.length + 1) == 0)
            return 1;
        low++;
    }
    return 0;
}

static const void *elf64_vaddr_file(const uint8_t *data, size_t size,
                                    const struct elf64_image *image,
                                    uint64_t vaddr, uint64_t length);
static const struct elf64_load_translation *elf64_vaddr_translation(
    const struct elf64_image *image, uint64_t vaddr, uint64_t *delta_out);

static int version_requirement_append(struct elf_info *info,
                                      const char *file, const char *name,
                                      uint32_t hash, uint16_t flags,
                                      uint16_t index,
                                      size_t maximum, size_t *capacity)
{
    struct elf_version_requirement *items;
    size_t count = info->version_requirement_count;
    size_t new_capacity;

    if (count >= maximum)
        return -1;
    if (count == *capacity) {
        new_capacity = *capacity ? *capacity : 8;
        if (new_capacity > maximum / 2)
            new_capacity = maximum;
        else
            new_capacity *= 2;
        if (new_capacity <= count ||
            new_capacity > SIZE_MAX / sizeof(*items))
            return -1;
        items = realloc(info->version_requirements,
                        new_capacity * sizeof(*items));
        if (!items)
            return -1;
        info->version_requirements = items;
        *capacity = new_capacity;
    }
    items = info->version_requirements;
    memset(&items[count], 0, sizeof(items[count]));
    items[count].file = (char *)file;
    items[count].name = (char *)name;
    items[count].hash = hash;
    items[count].flags = flags;
    items[count].index = index;
    info->version_requirement_count = count + 1;
    return 0;
}

static int version_definition_append(struct elf_info *info,
                                     const char *name, uint32_t hash,
                                     uint16_t flags, uint16_t index,
                                     size_t maximum,
                                     size_t *capacity)
{
    struct elf_version_definition *items;
    size_t count = info->version_definition_count;
    size_t new_capacity;

    if (count >= maximum)
        return -1;
    if (count == *capacity) {
        new_capacity = *capacity ? *capacity : 8;
        if (new_capacity > maximum / 2)
            new_capacity = maximum;
        else
            new_capacity *= 2;
        if (new_capacity <= count ||
            new_capacity > SIZE_MAX / sizeof(*items))
            return -1;
        items = realloc(info->version_definitions,
                        new_capacity * sizeof(*items));
        if (!items)
            return -1;
        info->version_definitions = items;
        *capacity = new_capacity;
    }
    items = info->version_definitions;
    memset(&items[count], 0, sizeof(items[count]));
    items[count].name = (char *)name;
    items[count].hash = hash;
    items[count].flags = flags;
    items[count].index = index;
    info->version_definition_count = count + 1;
    return 0;
}

#define ELF_VERSION_INDEX_COUNT UINT32_C(0x8000)
#define ELF_VERSION_INDEX_WORDS (ELF_VERSION_INDEX_COUNT / 64U)

static int claim_version_index(
    uint64_t indices[ELF_VERSION_INDEX_WORDS], uint16_t raw_index)
{
    uint16_t index = raw_index & UINT16_C(0x7fff);
    uint64_t mask = UINT64_C(1) << (index & 63U);
    uint64_t *word = &indices[index >> 6];

    if ((*word & mask) != 0)
        return 0;
    *word |= mask;
    return 1;
}

static int elf64_parse_verneed(const uint8_t *data, size_t size,
                               const struct elf64_image *image,
                               struct dynamic_string_table *strtab,
                               uint64_t address, uint64_t record_count,
                               struct elf_info *info,
                               const struct needed_name_index *needed_index,
                               size_t needed_count,
                               size_t *auxiliary_budget,
                               uint64_t version_indices[
                                   ELF_VERSION_INDEX_WORDS])
{
    const size_t maximum = size / sizeof(Elf64_Vernaux);
    size_t capacity = 0;
    uint64_t record_address = address;

    if ((address == 0) != (record_count == 0) ||
        record_count > size / sizeof(Elf64_Verneed))
        return -1;
    for (uint64_t i = 0; i < record_count; i++) {
        const uint8_t *raw;
        Elf64_Verneed need;
        const char *file;
        uint64_t aux_address;
        int provider_present;

        raw = elf64_vaddr_file(data, size, image, record_address,
                              sizeof(need));
        if (!raw)
            return -1;
        memcpy(&need, raw, sizeof(need));
        if (need.vn_version != VER_NEED_CURRENT || need.vn_cnt == 0 ||
            need.vn_aux < sizeof(need) || need.vn_aux % 4 != 0 ||
            ((i + 1 < record_count) != (need.vn_next != 0)) ||
            (need.vn_next != 0 &&
             (need.vn_next < sizeof(need) || need.vn_next % 4 != 0)) ||
            record_address > UINT64_MAX - need.vn_aux)
            return -1;
        file = dynamic_string(strtab, need.vn_file);
        provider_present = needed_name_index_contains(
            needed_index, needed_count, strtab, need.vn_file);
        if (!file || !file[0] || provider_present != 1)
            return -1;
        aux_address = record_address + need.vn_aux;

        for (uint16_t j = 0; j < need.vn_cnt; j++) {
            Elf64_Vernaux aux;
            const char *name;
            uint32_t calculated_hash;
            uint16_t version_index;

            if (*auxiliary_budget == 0)
                return -1;
            (*auxiliary_budget)--;
            raw = elf64_vaddr_file(data, size, image, aux_address,
                                  sizeof(aux));
            if (!raw)
                return -1;
            memcpy(&aux, raw, sizeof(aux));
            version_index = aux.vna_other & UINT16_C(0x7fff);
            if ((aux.vna_flags &
                 ~(VER_FLG_WEAK | DLFRZ_VER_FLG_INFO)) != 0 ||
                version_index <= VER_NDX_GLOBAL ||
                !claim_version_index(version_indices, aux.vna_other) ||
                ((j + 1 < need.vn_cnt) != (aux.vna_next != 0)) ||
                (aux.vna_next != 0 &&
                 (aux.vna_next < sizeof(aux) || aux.vna_next % 4 != 0)))
                return -1;
            name = dynamic_string(strtab, aux.vna_name);
            if (!name || !name[0] ||
                dynamic_string_metadata(strtab, aux.vna_name, NULL, NULL,
                                        &calculated_hash) < 0 ||
                aux.vna_hash != calculated_hash ||
                version_requirement_append(info, file, name, aux.vna_hash,
                                           aux.vna_flags, version_index,
                                           maximum,
                                           &capacity) < 0)
                return -1;
            if (aux.vna_next != 0) {
                if (aux_address > UINT64_MAX - aux.vna_next)
                    return -1;
                aux_address += aux.vna_next;
            }
        }
        if (need.vn_next != 0) {
            /* The version records and their auxiliary lists are independent
             * offset chains.  LLVM/lld validly emits every Verneed header
             * first and places all Vernaux records after them. */
            if (record_address > UINT64_MAX - need.vn_next)
                return -1;
            record_address += need.vn_next;
        }
    }
    return 0;
}

static int elf64_parse_verdef(const uint8_t *data, size_t size,
                              const struct elf64_image *image,
                              struct dynamic_string_table *strtab,
                              uint64_t address, uint64_t record_count,
                              struct elf_info *info,
                              size_t *auxiliary_budget,
                              uint64_t version_indices[
                                  ELF_VERSION_INDEX_WORDS])
{
    const size_t maximum = size / sizeof(Elf64_Verdef);
    size_t capacity = 0;
    uint64_t record_address = address;

    if ((address == 0) != (record_count == 0) ||
        record_count > size / sizeof(Elf64_Verdef))
        return -1;
    for (uint64_t i = 0; i < record_count; i++) {
        const uint8_t *raw;
        Elf64_Verdef definition;
        uint64_t aux_address;
        const char *name = NULL;
        uint32_t calculated_hash;
        uint16_t version_index;

        raw = elf64_vaddr_file(data, size, image, record_address,
                              sizeof(definition));
        if (!raw)
            return -1;
        memcpy(&definition, raw, sizeof(definition));
        version_index = definition.vd_ndx & UINT16_C(0x7fff);
        if (definition.vd_version != VER_DEF_CURRENT ||
            definition.vd_cnt == 0 ||
            (definition.vd_flags &
             ~(VER_FLG_BASE | VER_FLG_WEAK | DLFRZ_VER_FLG_INFO)) != 0 ||
            version_index == VER_NDX_LOCAL ||
            ((version_index == VER_NDX_GLOBAL) !=
             ((definition.vd_flags & VER_FLG_BASE) != 0)) ||
            !claim_version_index(version_indices, definition.vd_ndx) ||
            definition.vd_aux < sizeof(definition) ||
            definition.vd_aux % 4 != 0 ||
            ((i + 1 < record_count) != (definition.vd_next != 0)) ||
            (definition.vd_next != 0 &&
             (definition.vd_next < sizeof(definition) ||
              definition.vd_next % 4 != 0)) ||
            record_address > UINT64_MAX - definition.vd_aux)
            return -1;
        aux_address = record_address + definition.vd_aux;
        for (uint16_t j = 0; j < definition.vd_cnt; j++) {
            Elf64_Verdaux aux;

            if (*auxiliary_budget == 0)
                return -1;
            (*auxiliary_budget)--;
            raw = elf64_vaddr_file(data, size, image, aux_address,
                                  sizeof(aux));
            if (!raw)
                return -1;
            memcpy(&aux, raw, sizeof(aux));
            if (((j + 1 < definition.vd_cnt) != (aux.vda_next != 0)) ||
                (aux.vda_next != 0 &&
                 (aux.vda_next < sizeof(aux) || aux.vda_next % 4 != 0)))
                return -1;
            if (j == 0) {
                name = dynamic_string(strtab, aux.vda_name);
                if (!name || !name[0] ||
                    dynamic_string_metadata(strtab, aux.vda_name, NULL,
                                            NULL, &calculated_hash) < 0 ||
                    definition.vd_hash != calculated_hash)
                    return -1;
            } else if (!dynamic_string(strtab, aux.vda_name)) {
                return -1;
            }
            if (aux.vda_next != 0) {
                if (aux_address > UINT64_MAX - aux.vda_next)
                    return -1;
                aux_address += aux.vda_next;
            }
        }
        if (!name || version_definition_append(
                         info, name, definition.vd_hash,
                         definition.vd_flags, version_index, maximum,
                         &capacity) < 0)
            return -1;
        if (definition.vd_next != 0) {
            /* Verdef/Verdaux use independent offset chains too; do not
             * impose an ordering which the ELF ABI does not require. */
            if (record_address > UINT64_MAX - definition.vd_next)
                return -1;
            record_address += definition.vd_next;
        }
    }
    return 0;
}

static const struct elf64_load_translation *elf64_vaddr_translation(
    const struct elf64_image *image, uint64_t vaddr, uint64_t *delta_out)
{
    const struct elf64_load_translation *translation;
    size_t low = 0;
    size_t high = image->load_index_count;
    size_t index;

    while (low < high) {
        size_t middle = low + (high - low) / 2;

        if (image->load_index[middle].vaddr <= vaddr)
            low = middle + 1;
        else
            high = middle;
    }
    if (low == 0)
        return NULL;
    index = image->load_index[low - 1].widest_index;
    translation = &image->load_index[index];
    if (vaddr < translation->vaddr)
        return NULL;
    *delta_out = vaddr - translation->vaddr;
    if (*delta_out >= translation->filesz)
        return NULL;
    return translation;
}

static const void *elf64_vaddr_file(const uint8_t *data, size_t size,
                                    const struct elf64_image *image,
                                    uint64_t vaddr, uint64_t length)
{
    const struct elf64_load_translation *translation;
    uint64_t delta;
    uint64_t offset;

    if (length == 0)
        return NULL;
    translation = elf64_vaddr_translation(image, vaddr, &delta);
    if (!translation || length > translation->filesz - delta ||
        translation->offset > UINT64_MAX - delta)
        return NULL;
    offset = translation->offset + delta;
    if (!range_in_file(offset, length, size))
        return NULL;
    return data + offset;
}

static int elf64_tpoff_relocation(uint16_t machine, uint32_t type)
{
#ifdef R_X86_64_TPOFF64
    if (machine == EM_X86_64 && type == R_X86_64_TPOFF64)
        return 1;
#endif
#ifdef R_AARCH64_TLS_TPREL
    if (machine == EM_AARCH64 && type == R_AARCH64_TLS_TPREL)
        return 1;
#endif
    return 0;
}

static int elf64_rela_has_tpoff(const uint8_t *data, size_t size,
                                const struct elf64_image *image,
                                uint64_t address, uint64_t bytes,
                                uint64_t entsz, int *found_out)
{
    const uint8_t *rela;
    size_t count;

    if (bytes == 0)
        return 0;
    if (address == 0 || entsz != sizeof(Elf64_Rela) ||
        bytes % sizeof(Elf64_Rela) != 0 || bytes > SIZE_MAX)
        return -1;
    rela = elf64_vaddr_file(data, size, image, address, bytes);
    if (!rela)
        return -1;
    count = (size_t)(bytes / sizeof(Elf64_Rela));
    for (size_t i = 0; i < count; i++) {
        Elf64_Xword r_info;

        memcpy(&r_info,
               rela + i * sizeof(Elf64_Rela) + offsetof(Elf64_Rela, r_info),
               sizeof(r_info));
        if (elf64_tpoff_relocation(image->ehdr.e_machine,
                                   ELF64_R_TYPE(r_info))) {
            *found_out = 1;
            break;
        }
    }
    return 0;
}

static int parse_elf64(const uint8_t *data, size_t size, struct elf_info *info)
{
    struct elf64_image image;
    struct dynamic_string_table dyn_strtab;
    const Elf64_Phdr *dynamic_phdr = NULL;
    Elf64_Dyn *dynamic = NULL;
    struct needed_name_index *needed_names = NULL;
    uint64_t version_indices[ELF_VERSION_INDEX_WORDS] = {0};
    size_t dynamic_count = 0;
    int ret = -1;

    memset(&dyn_strtab, 0, sizeof(dyn_strtab));

    if (elf64_image_open(data, size, &image) < 0)
        return -1;

    info->ei_class = ELFCLASS64;
    info->e_machine = image.ehdr.e_machine;
    info->is_pie = image.ehdr.e_type == ET_DYN;

    for (size_t i = 0; i < image.phnum; i++) {
        const Elf64_Phdr *ph = &image.phdr[i];

        if (ph->p_type == PT_INTERP) {
            info->interp = strdup((const char *)data + ph->p_offset);
            if (!info->interp)
                goto out;
        } else if (ph->p_type == PT_DYNAMIC) {
            info->is_dynamic = 1;
            dynamic_phdr = ph;
        } else if (ph->p_type == PT_TLS) {
            info->tls_memsz = ph->p_memsz;
        }
    }

    if (!dynamic_phdr) {
        ret = 0;
        goto out;
    }

    dynamic_count = (size_t)(dynamic_phdr->p_filesz / sizeof(Elf64_Dyn));
    dynamic = malloc((size_t)dynamic_phdr->p_filesz);
    if (!dynamic)
        goto out;
    memcpy(dynamic, data + dynamic_phdr->p_offset,
           (size_t)dynamic_phdr->p_filesz);

    /* Find dynamic tables and static-TLS constraints. */
    uint64_t strtab_addr = 0;
    uint64_t declared_strtab_size = 0;
    uint64_t rela_addr = 0;
    uint64_t rela_size = 0;
    uint64_t rela_ent = sizeof(Elf64_Rela);
    uint64_t jmprel_addr = 0;
    uint64_t pltrel_size = 0;
    uint64_t pltrel_kind = DT_RELA;
    uint64_t verneed_addr = 0;
    uint64_t verneed_count = 0;
    uint64_t verdef_addr = 0;
    uint64_t verdef_count = 0;
    uint64_t dynamic_flags = 0;
    uint64_t rpath_offset = 0;
    uint64_t runpath_offset = 0;
    uint64_t soname_offset = 0;
    size_t version_auxiliary_budget = size / sizeof(Elf64_Verdaux);
    int has_df_static_tls = 0;
    int has_tpoff = 0;
    int strtab_seen = 0;
    int strsz_seen = 0;
    int rela_seen = 0;
    int rela_size_seen = 0;
    int rela_ent_seen = 0;
    int jmprel_seen = 0;
    int pltrel_size_seen = 0;
    int pltrel_kind_seen = 0;
    int flags_seen = 0;
    int flags_1_seen = 0;
    int verneed_seen = 0;
    int verneed_count_seen = 0;
    int verdef_seen = 0;
    int verdef_count_seen = 0;
    int rpath_seen = 0;
    int runpath_seen = 0;
    int soname_seen = 0;
    size_t terminated_count = dynamic_count;

    for (size_t i = 0; i < dynamic_count; i++) {
        if (dynamic[i].d_tag == DT_NULL) {
            terminated_count = i;
            break;
        }
#define RECORD_DYNAMIC_VALUE(seen, storage, value) do {                  \
            uint64_t recorded_value = (uint64_t)(value);                  \
            if ((seen) && (storage) != recorded_value)                    \
                goto out;                                                  \
            (seen) = 1;                                                    \
            (storage) = recorded_value;                                    \
        } while (0)
        switch (dynamic[i].d_tag) {
        case DT_STRTAB:
            RECORD_DYNAMIC_VALUE(strtab_seen, strtab_addr,
                                 dynamic[i].d_un.d_ptr);
            break;
        case DT_STRSZ:
            RECORD_DYNAMIC_VALUE(strsz_seen, declared_strtab_size,
                                 dynamic[i].d_un.d_val);
            break;
        case DT_RELA:
            RECORD_DYNAMIC_VALUE(rela_seen, rela_addr,
                                 dynamic[i].d_un.d_ptr);
            break;
        case DT_RELASZ:
            RECORD_DYNAMIC_VALUE(rela_size_seen, rela_size,
                                 dynamic[i].d_un.d_val);
            break;
        case DT_RELAENT:
            RECORD_DYNAMIC_VALUE(rela_ent_seen, rela_ent,
                                 dynamic[i].d_un.d_val);
            break;
        case DT_JMPREL:
            RECORD_DYNAMIC_VALUE(jmprel_seen, jmprel_addr,
                                 dynamic[i].d_un.d_ptr);
            break;
        case DT_PLTRELSZ:
            RECORD_DYNAMIC_VALUE(pltrel_size_seen, pltrel_size,
                                 dynamic[i].d_un.d_val);
            break;
        case DT_PLTREL:
            RECORD_DYNAMIC_VALUE(pltrel_kind_seen, pltrel_kind,
                                 dynamic[i].d_un.d_val);
            break;
        case DT_FLAGS:
            RECORD_DYNAMIC_VALUE(flags_seen, dynamic_flags,
                                 dynamic[i].d_un.d_val);
            break;
        case DT_FLAGS_1:
            RECORD_DYNAMIC_VALUE(flags_1_seen, info->flags_1,
                                 dynamic[i].d_un.d_val);
            break;
        case DT_VERNEED:
            RECORD_DYNAMIC_VALUE(verneed_seen, verneed_addr,
                                 dynamic[i].d_un.d_ptr);
            break;
        case DT_VERNEEDNUM:
            RECORD_DYNAMIC_VALUE(verneed_count_seen, verneed_count,
                                 dynamic[i].d_un.d_val);
            break;
        case DT_VERDEF:
            RECORD_DYNAMIC_VALUE(verdef_seen, verdef_addr,
                                 dynamic[i].d_un.d_ptr);
            break;
        case DT_VERDEFNUM:
            RECORD_DYNAMIC_VALUE(verdef_count_seen, verdef_count,
                                 dynamic[i].d_un.d_val);
            break;
        case DT_RPATH:
            RECORD_DYNAMIC_VALUE(rpath_seen, rpath_offset,
                                 dynamic[i].d_un.d_val);
            break;
        case DT_RUNPATH:
            RECORD_DYNAMIC_VALUE(runpath_seen, runpath_offset,
                                 dynamic[i].d_un.d_val);
            break;
        case DT_SONAME:
            RECORD_DYNAMIC_VALUE(soname_seen, soname_offset,
                                 dynamic[i].d_un.d_val);
            break;
        default:
            break;
        }
#undef RECORD_DYNAMIC_VALUE
    }
    has_df_static_tls = flags_seen &&
                        (dynamic_flags & DF_STATIC_TLS) != 0;
    /* Static-TLS classification must not silently treat a partial relocation
     * description as an empty table.  Direct loading consumes the same tag
     * groups, so admit only complete RELA/JMPREL tuples here. */
    if ((rela_seen || rela_size_seen || rela_ent_seen) &&
        (!rela_seen || !rela_size_seen || !rela_ent_seen || rela_addr == 0 ||
         rela_ent != sizeof(Elf64_Rela) ||
         rela_size % sizeof(Elf64_Rela) != 0))
        goto out;
    if ((jmprel_seen || pltrel_size_seen || pltrel_kind_seen) &&
        (!jmprel_seen || !pltrel_size_seen || !pltrel_kind_seen ||
         jmprel_addr == 0 || pltrel_kind != DT_RELA ||
         pltrel_size % sizeof(Elf64_Rela) != 0))
        goto out;
    if (elf64_rela_has_tpoff(data, size, &image, rela_addr, rela_size,
                             rela_ent, &has_tpoff) < 0)
        goto out;
    if (pltrel_size != 0 &&
        (pltrel_kind != DT_RELA ||
         elf64_rela_has_tpoff(data, size, &image, jmprel_addr,
                              pltrel_size, sizeof(Elf64_Rela),
                              &has_tpoff) < 0))
        goto out;
    /* A TPOFF relocation constrains the defining TLS module, not
     * necessarily the object that contains the relocation. */
    info->has_static_tls = has_tpoff ||
                           (info->tls_memsz != 0 && has_df_static_tls);

    if (verneed_seen != verneed_count_seen ||
        verdef_seen != verdef_count_seen ||
        (verneed_seen && (verneed_addr == 0 || verneed_count == 0)) ||
        (verdef_seen && (verdef_addr == 0 || verdef_count == 0)))
        goto out;

    {
        size_t string_users = 0;

        for (size_t i = 0; i < terminated_count; i++) {
            if (dynamic[i].d_tag == DT_NEEDED ||
                dynamic[i].d_tag == DT_RPATH ||
                dynamic[i].d_tag == DT_RUNPATH ||
                dynamic[i].d_tag == DT_SONAME)
                string_users++;
        }
        if (verneed_seen || verdef_seen)
            string_users++;
        if (strtab_seen != strsz_seen)
            goto out;
        if (!strtab_seen) {
            if (string_users != 0)
                goto out;
            ret = 0;
            goto out;
        }
        if (strtab_addr == 0 || declared_strtab_size == 0)
            goto out;
    }

    /* Convert the dynamic string table VA to a bounded file view. */
    {
        const struct elf64_load_translation *translation;
        const char *string_data;
        uint64_t delta;
        uint64_t available;
        uint64_t string_bytes;

        translation = elf64_vaddr_translation(&image, strtab_addr, &delta);
        if (!translation)
            goto out;
        available = translation->filesz - delta;
        if (declared_strtab_size > available)
            goto out;
        string_bytes = declared_strtab_size;
        string_data = elf64_vaddr_file(data, size, &image, strtab_addr,
                                      string_bytes);
        if (!string_data || string_bytes > SIZE_MAX)
            goto out;
        if (string_data[0] != '\0' ||
            string_data[(size_t)string_bytes - 1] != '\0')
            goto out;
        info->dynamic_strings = malloc((size_t)string_bytes);
        if (!info->dynamic_strings)
            goto out;
        memcpy(info->dynamic_strings, string_data, (size_t)string_bytes);
        info->dynamic_strings_size = (size_t)string_bytes;
        if (dynamic_string_table_init(&dyn_strtab, info->dynamic_strings,
                                      info->dynamic_strings_size) < 0)
            goto out;
    }

    size_t needed_count = 0;
    for (size_t i = 0; i < terminated_count; i++)
        if (dynamic[i].d_tag == DT_NEEDED)
            needed_count++;
    if (needed_count > INT_MAX || needed_count == SIZE_MAX)
        goto out;
    info->needed = calloc(needed_count + 1, sizeof(char *));
    if (!info->needed)
        goto out;
    info->needed_count = (int)needed_count;

    size_t needed_cursor = 0;
    for (size_t i = 0; i < terminated_count; i++) {
        const char *value;

        if (dynamic[i].d_tag != DT_NEEDED)
            continue;
        value = dynamic_string(&dyn_strtab, dynamic[i].d_un.d_val);
        if (!value)
            goto out;
        info->needed[needed_cursor] = (char *)value;
        needed_cursor++;
    }
#define COPY_DYNAMIC_STRING(seen, offset, field) do {                    \
        if (seen) {                                                        \
            const char *value = dynamic_string(&dyn_strtab, (offset));     \
            if (!value)                                                    \
                goto out;                                                  \
            info->field = (char *)value;                                   \
        }                                                                  \
    } while (0)
    COPY_DYNAMIC_STRING(rpath_seen, rpath_offset, rpath);
    COPY_DYNAMIC_STRING(runpath_seen, runpath_offset, runpath);
    COPY_DYNAMIC_STRING(soname_seen, soname_offset, soname);
#undef COPY_DYNAMIC_STRING
    if (needed_count != 0) {
        if (needed_count > SIZE_MAX / sizeof(*needed_names))
            goto out;
        needed_names = malloc(needed_count * sizeof(*needed_names));
        if (!needed_names)
            goto out;
        needed_cursor = 0;
        for (size_t i = 0; i < terminated_count; i++) {
            if (dynamic[i].d_tag != DT_NEEDED)
                continue;
            needed_names[needed_cursor].name = info->needed[needed_cursor];
            if (dynamic_string_metadata(
                    &dyn_strtab, dynamic[i].d_un.d_val,
                    &needed_names[needed_cursor].length,
                    &needed_names[needed_cursor].hash, NULL) < 0)
                goto out;
            needed_cursor++;
        }
        qsort(needed_names, needed_count, sizeof(*needed_names),
              needed_name_index_compare);
    }
    if (elf64_parse_verneed(data, size, &image, &dyn_strtab,
                            verneed_addr, verneed_count, info,
                            needed_names, needed_count,
                            &version_auxiliary_budget,
                            version_indices) < 0 ||
        elf64_parse_verdef(data, size, &image, &dyn_strtab, verdef_addr,
                           verdef_count, info,
                           &version_auxiliary_budget,
                           version_indices) < 0)
        goto out;
    ret = 0;

out:
    dynamic_string_table_destroy(&dyn_strtab);
    free(needed_names);
    free(dynamic);
    elf64_image_close(&image);
    return ret;
}

static int file_identity_unchanged(const struct stat *before,
                                   const struct stat *after)
{
    return before->st_dev == after->st_dev &&
           before->st_ino == after->st_ino &&
           before->st_mode == after->st_mode &&
           before->st_size == after->st_size &&
           before->st_mtim.tv_sec == after->st_mtim.tv_sec &&
           before->st_mtim.tv_nsec == after->st_mtim.tv_nsec &&
           before->st_ctim.tv_sec == after->st_ctim.tv_sec &&
           before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
}

/* A MAP_PRIVATE file mapping can still raise SIGBUS when another process
 * truncates its backing file.  Parsing is an admission boundary, so first
 * copy the requested range into an anonymous snapshot, then make it
 * read-only.  Metadata is checked after the copy to reject ordinary
 * concurrent replacement/modification instead of parsing a mixed image. */
static int snapshot_fd_range(int fd, uint64_t offset, size_t length,
                             const struct stat *before, uint8_t **data_out,
                             int report_error)
{
    struct stat after;
    uint8_t *data;
    size_t done = 0;

    if (length == 0 || offset > (uint64_t)INT64_MAX ||
        length > (uint64_t)INT64_MAX - offset) {
        errno = EOVERFLOW;
        return -1;
    }
    data = mmap(NULL, length, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (data == MAP_FAILED) {
        if (report_error)
            perror("mmap");
        return -1;
    }
    while (done < length) {
        size_t chunk = length - done;
        ssize_t count;

        if (chunk > (size_t)SSIZE_MAX)
            chunk = (size_t)SSIZE_MAX;
        count = pread(fd, data + done, chunk, (off_t)(offset + done));
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            if (count == 0)
                errno = ESTALE;
            if (report_error)
                perror("pread");
            munmap(data, length);
            return -1;
        }
        done += (size_t)count;
    }
    if (fstat(fd, &after) < 0) {
        if (report_error)
            perror("fstat");
        munmap(data, length);
        return -1;
    }
    if (!file_identity_unchanged(before, &after)) {
        errno = ESTALE;
        if (report_error)
            perror("fstat");
        munmap(data, length);
        return -1;
    }
    if (mprotect(data, length, PROT_READ) < 0) {
        if (report_error)
            perror("mprotect");
        munmap(data, length);
        return -1;
    }
    *data_out = data;
    return 0;
}

static int map_fd(int fd, uint8_t **data_out, size_t *size_out,
                  int report_error)
{
    struct stat st;

    if (fd < 0) {
        errno = EBADF;
        return -1;
    }
    if (fstat(fd, &st) < 0) {
        if (report_error)
            perror("fstat");
        return -1;
    }
    if (st.st_size < (off_t)sizeof(Elf64_Ehdr) ||
        (uintmax_t)st.st_size > SIZE_MAX) {
        errno = ENOEXEC;
        if (report_error)
            fprintf(stderr, "dlfreeze: invalid ELF file size\n");
        return -1;
    }
    if (snapshot_fd_range(fd, 0, (size_t)st.st_size, &st, data_out,
                          report_error) < 0)
        return -1;
    *size_out = (size_t)st.st_size;
    return 0;
}

static int map_file(const char *path, uint8_t **data_out, size_t *size_out,
                    int report_error)
{
    int fd;
    int result;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (report_error)
            perror(path);
        return -1;
    }
    result = map_fd(fd, data_out, size_out, report_error);
    if (close(fd) < 0) {
        if (report_error)
            perror("close");
        if (result == 0)
            munmap(*data_out, *size_out);
        return -1;
    }
    return result;
}

int elf_check(const char *path)
{
    struct elf_info info;
    uint8_t *data;
    size_t size;
    int valid;

    if (!path || map_file(path, &data, &size, 0) < 0)
        return 0;
    memset(&info, 0, sizeof(info));
    valid = parse_elf64(data, size, &info) == 0;
    elf_info_free(&info);
    munmap(data, size);
    return valid;
}

int elf_parse(const char *path, struct elf_info *info)
{
    uint8_t *data;
    size_t size;
    int ret;

    if (!path || !info)
        return -1;
    memset(info, 0, sizeof(*info));
    if (map_file(path, &data, &size, 1) < 0)
        return -1;
    ret = parse_elf64(data, size, info);
    munmap(data, size);
    if (ret < 0)
        elf_info_free(info);
    return ret;
}

int elf_parse_fd(int fd, struct elf_info *info)
{
    uint8_t *data;
    size_t size;
    int ret;

    if (fd < 0 || !info)
        return -1;
    memset(info, 0, sizeof(*info));
    if (map_fd(fd, &data, &size, 1) < 0)
        return -1;
    ret = parse_elf64(data, size, info);
    munmap(data, size);
    if (ret < 0)
        elf_info_free(info);
    return ret;
}

int elf_parse_fd_range(int fd, uint64_t offset, size_t length,
                       struct elf_info *info)
{
    struct stat st;
    uint8_t *mapping;
    int ret;

    if (fd < 0 || !info || length < sizeof(Elf64_Ehdr))
        return -1;
    memset(info, 0, sizeof(*info));
    if (fstat(fd, &st) < 0 || st.st_size < 0 ||
        offset > (uint64_t)st.st_size ||
        length > (uint64_t)st.st_size - offset)
        return -1;
    if (snapshot_fd_range(fd, offset, length, &st, &mapping, 0) < 0)
        return -1;
    ret = parse_elf64(mapping, length, info);
    munmap(mapping, length);
    if (ret < 0)
        elf_info_free(info);
    return ret;
}

void elf_info_free(struct elf_info *info)
{
    if (!info)
        return;
    free(info->needed);
    info->needed = NULL;
    info->needed_count = 0;
    free(info->interp);
    free(info->version_requirements);
    free(info->version_definitions);
    free(info->dynamic_strings);
    info->interp = NULL;
    info->rpath = NULL;
    info->runpath = NULL;
    info->soname = NULL;
    info->version_requirements = NULL;
    info->version_requirement_count = 0;
    info->version_definitions = NULL;
    info->version_definition_count = 0;
    info->dynamic_strings = NULL;
    info->dynamic_strings_size = 0;
}

static int version_definition_pointer_compare(const void *left,
                                              const void *right)
{
    const struct elf_version_definition *a =
        *(const struct elf_version_definition *const *)left;
    const struct elf_version_definition *b =
        *(const struct elf_version_definition *const *)right;

    if (a->hash < b->hash)
        return -1;
    if (a->hash > b->hash)
        return 1;
    return strcmp(a->name, b->name);
}

int elf_version_requirements_match(const struct elf_info *consumer,
                                   const char *provider_name,
                                   const struct elf_info *provider)
{
    const struct elf_version_definition **sorted = NULL;
    size_t definition_count;
    int result = 1;

    if (!consumer || !provider_name || !provider)
        return 0;
    definition_count = provider->version_definition_count;
    if (definition_count != 0) {
        if (definition_count > SIZE_MAX / sizeof(*sorted))
            return 0;
        sorted = malloc(definition_count * sizeof(*sorted));
        if (!sorted)
            return 0;
        for (size_t i = 0; i < definition_count; i++)
            sorted[i] = &provider->version_definitions[i];
        qsort(sorted, definition_count, sizeof(*sorted),
              version_definition_pointer_compare);
    }
    for (size_t i = 0; i < consumer->version_requirement_count; i++) {
        const struct elf_version_requirement *requirement =
            &consumer->version_requirements[i];
        size_t low = 0;
        size_t high = definition_count;
        int found = 0;

        if (strcmp(requirement->file, provider_name) != 0)
            continue;
        while (low < high) {
            size_t middle = low + (high - low) / 2;
            const struct elf_version_definition *definition =
                sorted[middle];
            int order;

            if (requirement->hash < definition->hash) {
                order = -1;
            } else if (requirement->hash > definition->hash) {
                order = 1;
            } else {
                order = strcmp(requirement->name, definition->name);
            }
            if (order == 0) {
                found = 1;
                break;
            }
            if (order < 0)
                high = middle;
            else
                low = middle + 1;
        }
        if (!found && (requirement->flags & VER_FLG_WEAK) == 0) {
            result = 0;
            break;
        }
    }
    free(sorted);
    return result;
}
