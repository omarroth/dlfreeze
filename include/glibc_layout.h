#ifndef DLFREEZE_GLIBC_LAYOUT_H
#define DLFREEZE_GLIBC_LAYOUT_H

#include <elf.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef DT_RELRSZ
#define DT_RELRSZ 35
#endif
#ifndef DT_RELR
#define DT_RELR 36
#endif
#ifndef DT_RELRENT
#define DT_RELRENT 37
#endif

#define DLFRZ_GLIBC_DEVELOPMENT_MARKER "development release version"

#define DLFRZ_GLIBC_CACHE_SUFFIX "/ld.so.cache"
#define DLFRZ_GLIBC_PRELOAD_SUFFIX "/ld.so.preload"

/*
 * glibc's _rtld_global and _rtld_global_ro are private implementation
 * details.  Their total sizes are only admission keys for layouts whose
 * individual field offsets have been validated; they are not sufficient
 * data from which to derive a new layout.
 *
 * Keep this as the single list shared by the packer and direct loader.  The
 * packer uses it to decide whether direct metadata may be emitted, while the
 * loader maps each id to its validated offset profile.
 */
#define DLFRZ_GLIBC_LAYOUT_KEYS(X)                                            \
    X(DLFRZ_GLIBC_X86_2_17,          EM_X86_64,   440, 3960)                 \
    X(DLFRZ_GLIBC_AARCH64_2_27,      EM_AARCH64,  520, 4088)                 \
    X(DLFRZ_GLIBC_X86_2_29,          EM_X86_64,   536, 3992)                 \
    X(DLFRZ_GLIBC_X86_RTLD_544_4000, EM_X86_64,   544, 4000)                 \
    X(DLFRZ_GLIBC_AARCH64_2_31,      EM_AARCH64,  624, 4152)                 \
    X(DLFRZ_GLIBC_AARCH64_2_35_LARGE, EM_AARCH64, 704, 4488)                 \
    X(DLFRZ_GLIBC_AARCH64_RTLD_672_4520, EM_AARCH64, 672, 4520)              \
    X(DLFRZ_GLIBC_AARCH64_2_35,      EM_AARCH64,  688, 4504)                 \
    X(DLFRZ_GLIBC_AARCH64_2_43,      EM_AARCH64,  400, 2272)                 \
    X(DLFRZ_GLIBC_AARCH64_2_44,      EM_AARCH64,  400, 2288)                 \
    X(DLFRZ_GLIBC_AARCH64_2_40_LEGACY, EM_AARCH64, 704, 4504)                \
    X(DLFRZ_GLIBC_AARCH64_2_41,      EM_AARCH64,  704, 3040)                 \
    X(DLFRZ_GLIBC_X86_RTLD_896_4336, EM_X86_64,   896, 4336)                 \
    X(DLFRZ_GLIBC_X86_2_34,          EM_X86_64,   928, 4304)                 \
    X(DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY, EM_X86_64, 952, 4352)            \
    X(DLFRZ_GLIBC_X86_2_40,          EM_X86_64,   928, 2120)                 \
    X(DLFRZ_GLIBC_X86_2_44,          EM_X86_64,   928, 2136)                 \
    X(DLFRZ_GLIBC_X86_RTLD_952_2888, EM_X86_64,   952, 2888)

/* Some x86-64 glibc builds publish a dynamic-symbol extent for
 * _rtld_global which is 16 bytes larger than the corresponding validated
 * private layout.  These are observed, exact aliases, not a general size
 * adjustment: an unlisted size must remain unknown.  Keep aliases separate
 * from DLFRZ_GLIBC_LAYOUT_KEYS so enum ids and private offset profiles
 * continue to have one definition. */
#define DLFRZ_GLIBC_LAYOUT_PUBLIC_SIZE_ALIASES(X)                             \
    X(DLFRZ_GLIBC_X86_RTLD_896_4336, EM_X86_64, 896, 4352)                   \
    X(DLFRZ_GLIBC_X86_2_34,          EM_X86_64, 928, 4320)                   \
    X(DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY,                                  \
                                            EM_X86_64, 952, 4368)            \
    X(DLFRZ_GLIBC_X86_RTLD_952_2888, EM_X86_64, 952, 2904)

enum dlfrz_glibc_layout_id {
    DLFRZ_GLIBC_LAYOUT_UNKNOWN = 0,
#define DLFRZ_GLIBC_LAYOUT_ENUM(id, machine, glro_size, gl_size) id,
    DLFRZ_GLIBC_LAYOUT_KEYS(DLFRZ_GLIBC_LAYOUT_ENUM)
#undef DLFRZ_GLIBC_LAYOUT_ENUM
};

struct dlfrz_glibc_layout_key {
    enum dlfrz_glibc_layout_id id;
    uint16_t machine;
    uint64_t glro_size;
    uint64_t gl_size;
};

/* Content identity for glibc's dynamic linker.  These are public dynamic
 * symbol facts, not an inference from the interpreter pathname or a vendor
 * release banner. */
struct dlfrz_glibc_rtld_identity {
    uint16_t machine;
    uint64_t global_vaddr;
    uint64_t global_size;
    uint64_t global_ro_vaddr;
    uint64_t global_ro_size;
};

/* Function pointers in _rtld_global_ro are initialized by the interpreter's
 * relative relocations.  Requiring those relocation targets gives positive
 * structural evidence for the private offsets instead of trusting only an
 * exported size tuple.  _dl_find_object is deliberately not included: the
 * supported interpreters leave that optional slot unrelocated even though
 * the direct loader installs a conservative fallback there. */
struct dlfrz_glibc_glro_reloc_profile {
    uint16_t machine;
    int debug_printf;
    int mcount;
    int open;
    int close;
    int catch_error;
    int error_free;
};

static inline int
dlfrz_glibc_glro_reloc_profile(
    enum dlfrz_glibc_layout_id layout,
    struct dlfrz_glibc_glro_reloc_profile *profile)
{
    struct dlfrz_glibc_glro_reloc_profile value;

    switch (layout) {
    case DLFRZ_GLIBC_X86_2_17:
        value = (struct dlfrz_glibc_glro_reloc_profile){
            EM_X86_64, 360, 368, 392, 400, -1, -1 };
        break;
    case DLFRZ_GLIBC_AARCH64_2_27:
    case DLFRZ_GLIBC_AARCH64_2_31:
        value = (struct dlfrz_glibc_glro_reloc_profile){
            EM_AARCH64, -1, -1, -1, -1, -1, -1 };
        break;
    case DLFRZ_GLIBC_X86_2_29:
        value = (struct dlfrz_glibc_glro_reloc_profile){
            EM_X86_64, 464, 472, 488, 496, -1, -1 };
        break;
    case DLFRZ_GLIBC_X86_RTLD_544_4000:
        value = (struct dlfrz_glibc_glro_reloc_profile){
            EM_X86_64, 472, 480, 496, 504, -1, -1 };
        break;
    case DLFRZ_GLIBC_AARCH64_2_35_LARGE:
        value = (struct dlfrz_glibc_glro_reloc_profile){
            EM_AARCH64, 592, 600, 616, 624, 632, 640 };
        break;
    case DLFRZ_GLIBC_AARCH64_RTLD_672_4520:
        value = (struct dlfrz_glibc_glro_reloc_profile){
            EM_AARCH64, 568, 576, 592, 600, 608, 616 };
        break;
    case DLFRZ_GLIBC_AARCH64_2_35:
        value = (struct dlfrz_glibc_glro_reloc_profile){
            EM_AARCH64, 584, 592, 608, 616, 624, 632 };
        break;
    case DLFRZ_GLIBC_AARCH64_2_43:
    case DLFRZ_GLIBC_AARCH64_2_44:
        value = (struct dlfrz_glibc_glro_reloc_profile){
            EM_AARCH64, 288, 296, 312, 320, 328, 336 };
        break;
    case DLFRZ_GLIBC_AARCH64_2_40_LEGACY:
    case DLFRZ_GLIBC_AARCH64_2_41:
        value = (struct dlfrz_glibc_glro_reloc_profile){
            EM_AARCH64, 600, 608, 624, 632, 640, 648 };
        break;
    case DLFRZ_GLIBC_X86_RTLD_896_4336:
        value = (struct dlfrz_glibc_glro_reloc_profile){
            EM_X86_64, 792, 800, 816, 824, 832, 840 };
        break;
    case DLFRZ_GLIBC_X86_2_34:
    case DLFRZ_GLIBC_X86_2_40:
    case DLFRZ_GLIBC_X86_2_44:
        value = (struct dlfrz_glibc_glro_reloc_profile){
            EM_X86_64, 816, 824, 840, 848, 856, 864 };
        break;
    case DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY:
    case DLFRZ_GLIBC_X86_RTLD_952_2888:
        value = (struct dlfrz_glibc_glro_reloc_profile){
            EM_X86_64, 848, 856, 872, 880, 888, 896 };
        break;
    case DLFRZ_GLIBC_LAYOUT_UNKNOWN:
    default:
        return 0;
    }
    if (profile)
        *profile = value;
    return 1;
}

static inline int
dlfrz_glibc_glro_reloc_profile_matches(
    enum dlfrz_glibc_layout_id layout, int debug_printf, int mcount,
    int open_offset, int close_offset, int catch_error, int error_free)
{
    struct dlfrz_glibc_glro_reloc_profile profile;

    return dlfrz_glibc_glro_reloc_profile(layout, &profile) &&
           profile.debug_printf == debug_printf &&
           profile.mcount == mcount && profile.open == open_offset &&
           profile.close == close_offset &&
           profile.catch_error == catch_error &&
           profile.error_free == error_free;
}

static inline enum dlfrz_glibc_layout_id
dlfrz_glibc_layout_lookup(uint16_t machine, uint64_t glro_size,
                          uint64_t gl_size)
{
    static const struct dlfrz_glibc_layout_key keys[] = {
#define DLFRZ_GLIBC_LAYOUT_ROW(id, arch, ro, global) \
        { id, arch, ro, global },
        DLFRZ_GLIBC_LAYOUT_KEYS(DLFRZ_GLIBC_LAYOUT_ROW)
#undef DLFRZ_GLIBC_LAYOUT_ROW
    };
    static const struct dlfrz_glibc_layout_key public_size_aliases[] = {
#define DLFRZ_GLIBC_LAYOUT_ALIAS_ROW(id, arch, ro, global) \
        { id, arch, ro, global },
        DLFRZ_GLIBC_LAYOUT_PUBLIC_SIZE_ALIASES(
            DLFRZ_GLIBC_LAYOUT_ALIAS_ROW)
#undef DLFRZ_GLIBC_LAYOUT_ALIAS_ROW
    };

    for (unsigned int i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        if (keys[i].machine == machine &&
            keys[i].glro_size == glro_size &&
            keys[i].gl_size == gl_size)
            return keys[i].id;
    }
    for (unsigned int i = 0;
         i < sizeof(public_size_aliases) /
                 sizeof(public_size_aliases[0]);
         i++) {
        if (public_size_aliases[i].machine == machine &&
            public_size_aliases[i].glro_size == glro_size &&
            public_size_aliases[i].gl_size == gl_size)
            return public_size_aliases[i].id;
    }
    return DLFRZ_GLIBC_LAYOUT_UNKNOWN;
}

static inline int
dlfrz_glibc_read_phdr(const unsigned char *elf, size_t elf_size,
                      const Elf64_Ehdr *ehdr, uint16_t index,
                      Elf64_Phdr *phdr)
{
    size_t offset;

    if (index >= ehdr->e_phnum || ehdr->e_phentsize != sizeof(*phdr) ||
        ehdr->e_phoff > elf_size ||
        (size_t)index >=
            (elf_size - (size_t)ehdr->e_phoff) / sizeof(*phdr))
        return 0;
    offset = (size_t)ehdr->e_phoff + (size_t)index * sizeof(*phdr);
    if (offset > elf_size || sizeof(*phdr) > elf_size - offset)
        return 0;
    memcpy(phdr, elf + offset, sizeof(*phdr));
    return 1;
}

static inline int
dlfrz_glibc_vaddr_file_range(const unsigned char *elf, size_t elf_size,
                             const Elf64_Ehdr *ehdr, uint64_t vaddr,
                             uint64_t range_size, size_t *offset_out)
{
    int found = 0;
    size_t result = 0;

    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr phdr;
        uint64_t delta;
        uint64_t file_offset;

        if (!dlfrz_glibc_read_phdr(elf, elf_size, ehdr, i, &phdr))
            return 0;
        if (phdr.p_type != PT_LOAD)
            continue;
        if (phdr.p_filesz > phdr.p_memsz || phdr.p_offset > elf_size ||
            phdr.p_filesz > (uint64_t)elf_size - phdr.p_offset ||
            phdr.p_vaddr > UINT64_MAX - phdr.p_memsz)
            return 0;
        if (vaddr < phdr.p_vaddr)
            continue;
        delta = vaddr - phdr.p_vaddr;
        if (delta > phdr.p_filesz || range_size > phdr.p_filesz - delta ||
            phdr.p_offset > UINT64_MAX - delta)
            continue;
        file_offset = phdr.p_offset + delta;
        if (file_offset > elf_size ||
            range_size > (uint64_t)elf_size - file_offset ||
            file_offset > SIZE_MAX)
            return 0;
        if (found && result != (size_t)file_offset)
            return 0;
        found = 1;
        result = (size_t)file_offset;
    }
    if (!found)
        return 0;
    *offset_out = result;
    return 1;
}

static inline int
dlfrz_glibc_vaddr_file_available(const unsigned char *elf, size_t elf_size,
                                 const Elf64_Ehdr *ehdr, uint64_t vaddr,
                                 size_t *offset_out, size_t *available_out)
{
    int found = 0;
    size_t result_offset = 0;
    size_t result_available = 0;

    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr phdr;
        uint64_t delta;
        uint64_t file_offset;
        uint64_t available;

        if (!dlfrz_glibc_read_phdr(elf, elf_size, ehdr, i, &phdr))
            return 0;
        if (phdr.p_type != PT_LOAD)
            continue;
        if (phdr.p_filesz > phdr.p_memsz || phdr.p_offset > elf_size ||
            phdr.p_filesz > (uint64_t)elf_size - phdr.p_offset ||
            phdr.p_vaddr > UINT64_MAX - phdr.p_memsz)
            return 0;
        if (vaddr < phdr.p_vaddr)
            continue;
        delta = vaddr - phdr.p_vaddr;
        if (delta >= phdr.p_filesz || phdr.p_offset > UINT64_MAX - delta)
            continue;
        file_offset = phdr.p_offset + delta;
        available = phdr.p_filesz - delta;
        if (file_offset > elf_size || available > elf_size - file_offset ||
            file_offset > SIZE_MAX || available > SIZE_MAX)
            return 0;
        if (found && result_offset != (size_t)file_offset)
            return 0;
        found = 1;
        result_offset = (size_t)file_offset;
        if ((size_t)available > result_available)
            result_available = (size_t)available;
    }
    if (!found)
        return 0;
    *offset_out = result_offset;
    *available_out = result_available;
    return 1;
}

static inline int
dlfrz_glibc_vaddr_writable_mem_range(const unsigned char *elf,
                                     size_t elf_size,
                                     const Elf64_Ehdr *ehdr,
                                     uint64_t vaddr, uint64_t range_size)
{
    int found = 0;

    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr phdr;
        uint64_t delta;

        if (!dlfrz_glibc_read_phdr(elf, elf_size, ehdr, i, &phdr))
            return 0;
        if (phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_W) ||
            vaddr < phdr.p_vaddr)
            continue;
        delta = vaddr - phdr.p_vaddr;
        if (delta <= phdr.p_memsz && range_size <= phdr.p_memsz - delta)
            found = 1;
    }
    return found;
}

static inline int
dlfrz_glibc_vaddr_executable_file_range(const unsigned char *elf,
                                        size_t elf_size,
                                        const Elf64_Ehdr *ehdr,
                                        uint64_t vaddr,
                                        uint64_t range_size)
{
    int found = 0;

    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr phdr;
        uint64_t delta;

        if (!dlfrz_glibc_read_phdr(elf, elf_size, ehdr, i, &phdr))
            return 0;
        if (phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_X) ||
            vaddr < phdr.p_vaddr)
            continue;
        delta = vaddr - phdr.p_vaddr;
        if (delta <= phdr.p_filesz &&
            range_size <= phdr.p_filesz - delta &&
            phdr.p_offset <= UINT64_MAX - delta) {
            uint64_t file_offset = phdr.p_offset + delta;

            if (file_offset <= elf_size &&
                range_size <= (uint64_t)elf_size - file_offset)
                found = 1;
        }
    }
    return found;
}

static inline uint32_t
dlfrz_glibc_read_u32(const unsigned char *bytes)
{
    uint32_t value;

    memcpy(&value, bytes, sizeof(value));
    return value;
}

static inline int
dlfrz_glibc_size_add(size_t left, size_t right, size_t *result)
{
    if (left > SIZE_MAX - right)
        return 0;
    *result = left + right;
    return 1;
}

static inline int
dlfrz_glibc_size_mul(size_t left, size_t right, size_t *result)
{
    if (left != 0 && right > SIZE_MAX / left)
        return 0;
    *result = left * right;
    return 1;
}

static inline int
dlfrz_glibc_dynamic_value(int *seen, uint64_t *storage, uint64_t value)
{
    if (*seen && *storage != value)
        return 0;
    *seen = 1;
    *storage = value;
    return 1;
}

static inline int
dlfrz_glibc_sysv_symbol_count(const unsigned char *elf, size_t elf_size,
                              const Elf64_Ehdr *ehdr, uint64_t address,
                              uint32_t max_symbols, uint32_t *count_out)
{
    size_t offset;
    size_t bucket_bytes;
    size_t chain_bytes;
    size_t table_bytes;
    uint32_t nbuckets;
    uint32_t nchain;

    if (!dlfrz_glibc_vaddr_file_range(elf, elf_size, ehdr, address,
                                      2 * sizeof(uint32_t), &offset))
        return 0;
    nbuckets = dlfrz_glibc_read_u32(elf + offset);
    nchain = dlfrz_glibc_read_u32(elf + offset + sizeof(uint32_t));
    if (nbuckets == 0 || nchain == 0 || nchain > max_symbols ||
        !dlfrz_glibc_size_mul(nbuckets, sizeof(uint32_t), &bucket_bytes) ||
        !dlfrz_glibc_size_mul(nchain, sizeof(uint32_t), &chain_bytes) ||
        !dlfrz_glibc_size_add(2 * sizeof(uint32_t), bucket_bytes,
                              &table_bytes) ||
        !dlfrz_glibc_size_add(table_bytes, chain_bytes, &table_bytes) ||
        !dlfrz_glibc_vaddr_file_range(elf, elf_size, ehdr, address,
                                      table_bytes, &offset))
        return 0;

    for (uint32_t i = 0; i < nbuckets; i++) {
        uint32_t symbol = dlfrz_glibc_read_u32(
            elf + offset + 2 * sizeof(uint32_t) +
            (size_t)i * sizeof(uint32_t));

        if (symbol != STN_UNDEF && symbol >= nchain)
            return 0;
    }
    for (uint32_t i = 0; i < nchain; i++) {
        uint32_t symbol = dlfrz_glibc_read_u32(
            elf + offset + 2 * sizeof(uint32_t) + bucket_bytes +
            (size_t)i * sizeof(uint32_t));

        if (symbol != STN_UNDEF && symbol >= nchain)
            return 0;
    }
    *count_out = nchain;
    return 1;
}

static inline int
dlfrz_glibc_gnu_symbol_count(const unsigned char *elf, size_t elf_size,
                             const Elf64_Ehdr *ehdr, uint64_t address,
                             uint32_t max_symbols, uint32_t *count_out)
{
    size_t offset;
    size_t available;
    size_t bloom_bytes;
    size_t bucket_bytes;
    size_t prefix_bytes;
    uint32_t nbuckets;
    uint32_t symoffset;
    uint32_t bloom_size;
    uint32_t bloom_shift;
    uint32_t max_symbol = 0;
    uint32_t count;
    int have_symbol = 0;

    if (!dlfrz_glibc_vaddr_file_range(elf, elf_size, ehdr, address,
                                      4 * sizeof(uint32_t), &offset))
        return 0;
    nbuckets = dlfrz_glibc_read_u32(elf + offset);
    symoffset = dlfrz_glibc_read_u32(elf + offset + sizeof(uint32_t));
    bloom_size = dlfrz_glibc_read_u32(elf + offset + 2 * sizeof(uint32_t));
    bloom_shift = dlfrz_glibc_read_u32(
        elf + offset + 3 * sizeof(uint32_t));
    if (nbuckets == 0 || bloom_size == 0 || bloom_shift >= 32 ||
        nbuckets > max_symbols || bloom_size > max_symbols ||
        symoffset > max_symbols ||
        !dlfrz_glibc_size_mul(bloom_size, sizeof(uint64_t), &bloom_bytes) ||
        !dlfrz_glibc_size_mul(nbuckets, sizeof(uint32_t), &bucket_bytes) ||
        !dlfrz_glibc_size_add(4 * sizeof(uint32_t), bloom_bytes,
                              &prefix_bytes) ||
        !dlfrz_glibc_size_add(prefix_bytes, bucket_bytes, &prefix_bytes) ||
        !dlfrz_glibc_vaddr_file_range(elf, elf_size, ehdr, address,
                                      prefix_bytes, &offset) ||
        address > UINT64_MAX - prefix_bytes ||
        !dlfrz_glibc_vaddr_file_available(
            elf, elf_size, ehdr, address + prefix_bytes, &available,
            &bucket_bytes))
        return 0;

    /* Reuse available for the chain file offset and bucket_bytes for its
     * byte capacity; both are local scratch values from here onward. */
    for (uint32_t i = 0; i < nbuckets; i++) {
        uint32_t symbol = dlfrz_glibc_read_u32(
            elf + offset + 4 * sizeof(uint32_t) + bloom_bytes +
            (size_t)i * sizeof(uint32_t));

        if (symbol == STN_UNDEF)
            continue;
        if (symbol < symoffset || symbol >= max_symbols)
            return 0;
        if (!have_symbol || symbol > max_symbol)
            max_symbol = symbol;
        have_symbol = 1;
    }
    if (!have_symbol) {
        count = symoffset;
    } else {
        size_t chain_index = (size_t)(max_symbol - symoffset);
        size_t chain_capacity = bucket_bytes / sizeof(uint32_t);

        if (chain_capacity > (size_t)(max_symbols - symoffset))
            chain_capacity = (size_t)(max_symbols - symoffset);
        for (;;) {
            uint32_t hash;

            if (chain_index >= chain_capacity || max_symbol == UINT32_MAX)
                return 0;
            hash = dlfrz_glibc_read_u32(
                elf + available + chain_index * sizeof(uint32_t));
            if (hash & 1U) {
                count = max_symbol + 1;
                break;
            }
            chain_index++;
            max_symbol++;
        }
    }
    if (count == 0 || count < symoffset || count > max_symbols)
        return 0;
    for (uint32_t i = 0; i < nbuckets; i++) {
        uint32_t symbol = dlfrz_glibc_read_u32(
            elf + offset + 4 * sizeof(uint32_t) + bloom_bytes +
            (size_t)i * sizeof(uint32_t));

        if (symbol != STN_UNDEF &&
            (symbol < symoffset || symbol >= count))
            return 0;
    }
    *count_out = count;
    return 1;
}

static inline int
dlfrz_glibc_dynstr_name(const unsigned char *strtab, size_t strtab_size,
                        uint32_t offset, const char *expected)
{
    size_t length = strlen(expected);

    return offset < strtab_size && length < strtab_size - offset &&
           memcmp(strtab + offset, expected, length) == 0 &&
           strtab[offset + length] == '\0';
}

static inline int
dlfrz_glibc_version_is_private(const unsigned char *elf, size_t elf_size,
                               const Elf64_Ehdr *ehdr,
                               const unsigned char *strtab,
                               size_t strtab_size, uint64_t verdef_address,
                               uint64_t verdef_count,
                               uint16_t version_index)
{
    uint64_t address = verdef_address;
    int found = 0;

    if (version_index <= VER_NDX_GLOBAL || verdef_count == 0 ||
        verdef_count > UINT16_MAX)
        return 0;
    for (uint64_t i = 0; i < verdef_count; i++) {
        Elf64_Verdef verdef;
        size_t offset;

        if (!dlfrz_glibc_vaddr_file_range(elf, elf_size, ehdr, address,
                                          sizeof(verdef), &offset))
            return 0;
        memcpy(&verdef, elf + offset, sizeof(verdef));
        if (verdef.vd_version != VER_DEF_CURRENT || verdef.vd_cnt == 0 ||
            verdef.vd_aux == 0)
            return 0;
        if ((verdef.vd_ndx & UINT16_C(0x7fff)) == version_index) {
            Elf64_Verdaux aux;
            uint64_t aux_address;

            if (found || address > UINT64_MAX - verdef.vd_aux)
                return 0;
            aux_address = address + verdef.vd_aux;
            if (!dlfrz_glibc_vaddr_file_range(
                    elf, elf_size, ehdr, aux_address, sizeof(aux), &offset))
                return 0;
            memcpy(&aux, elf + offset, sizeof(aux));
            if (!dlfrz_glibc_dynstr_name(
                    strtab, strtab_size, aux.vda_name, "GLIBC_PRIVATE"))
                return 0;
            found = 1;
        }
        if (i + 1 == verdef_count) {
            if (verdef.vd_next != 0)
                return 0;
        } else {
            if (verdef.vd_next == 0 ||
                address > UINT64_MAX - verdef.vd_next)
                return 0;
            address += verdef.vd_next;
        }
    }
    return found;
}

/* Shared bounded view of an ELF64 dynamic symbol ABI.  Runtime-family
 * detectors build on this view so GNU and musl classification cannot drift
 * into separate ad-hoc parsers. */
struct dlfrz_elf64_dyn_view {
    const unsigned char *elf;
    size_t elf_size;
    Elf64_Ehdr ehdr;
    size_t dynsym_offset;
    uint32_t dynsym_count;
    size_t dynstr_offset;
    size_t dynstr_size;
    size_t versym_offset;
    uint64_t verdef_address;
    uint64_t verdef_count;
    uint64_t sysv_hash_address;
    uint64_t gnu_hash_address;
    uint64_t soname_offset;
    int have_versym;
    int have_verdef;
    int have_verneed;
    int have_sysv_hash;
    int have_gnu_hash;
    int have_soname;
    int has_interp;
    uint32_t needed_count;
};

static inline int
dlfrz_elf64_dyn_view_init(const void *data, size_t elf_size,
                          struct dlfrz_elf64_dyn_view *view)
{
    const unsigned char *elf = (const unsigned char *)data;
    Elf64_Ehdr ehdr;
    Elf64_Phdr dynamic_phdr = {0};
    uint64_t symtab_address = 0, strtab_address = 0, strtab_size = 0;
    uint64_t syment = 0, sysv_hash_address = 0, gnu_hash_address = 0;
    uint64_t versym_address = 0, verdef_address = 0, verdef_count = 0;
    uint64_t verneed_address = 0, verneed_count = 0, soname_offset = 0;
    int have_symtab = 0, have_strtab = 0, have_strsz = 0, have_syment = 0;
    int have_sysv_hash = 0, have_gnu_hash = 0, have_versym = 0;
    int have_verdef = 0, have_verdef_count = 0;
    int have_verneed = 0, have_verneed_count = 0, have_soname = 0;
    int dynamic_found = 0, load_found = 0, interp_found = 0;
    int terminated = 0;
    size_t dynamic_offset;
    size_t symtab_offset;
    size_t symtab_available;
    size_t strtab_offset;
    size_t symbol_bytes;
    size_t versym_offset = 0;
    uint32_t max_symbols;
    uint32_t sysv_count = 0, gnu_count = 0, symbol_count = 0;
    uint32_t needed_count = 0;

    if (!view)
        return 0;
    memset(view, 0, sizeof(*view));
    if (!elf || elf_size < sizeof(ehdr))
        return 0;
    memcpy(&ehdr, elf, sizeof(ehdr));
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr.e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr.e_ident[EI_VERSION] != EV_CURRENT ||
        ehdr.e_version != EV_CURRENT || ehdr.e_type != ET_DYN ||
        (ehdr.e_machine != EM_X86_64 && ehdr.e_machine != EM_AARCH64) ||
        ehdr.e_ehsize != sizeof(ehdr) ||
        ehdr.e_phentsize != sizeof(Elf64_Phdr) || ehdr.e_phnum == 0 ||
        ehdr.e_phnum == PN_XNUM || ehdr.e_phoff > elf_size ||
        (size_t)ehdr.e_phnum >
            (elf_size - (size_t)ehdr.e_phoff) / sizeof(Elf64_Phdr))
        return 0;

    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;

        if (!dlfrz_glibc_read_phdr(elf, elf_size, &ehdr, i, &phdr) ||
            phdr.p_filesz > phdr.p_memsz || phdr.p_offset > elf_size ||
            phdr.p_filesz > (uint64_t)elf_size - phdr.p_offset ||
            phdr.p_vaddr > UINT64_MAX - phdr.p_memsz)
            return 0;
        if (phdr.p_type == PT_LOAD)
            load_found = 1;
        if (phdr.p_type == PT_INTERP && ++interp_found != 1)
            return 0;
        if (phdr.p_type != PT_DYNAMIC)
            continue;
        if (dynamic_found || phdr.p_filesz == 0 ||
            phdr.p_filesz % sizeof(Elf64_Dyn) != 0)
            return 0;
        dynamic_phdr = phdr;
        dynamic_found = 1;
    }
    if (!load_found || !dynamic_found ||
        !dlfrz_glibc_vaddr_file_range(
            elf, elf_size, &ehdr, dynamic_phdr.p_vaddr,
            dynamic_phdr.p_filesz, &dynamic_offset) ||
        dynamic_offset != (size_t)dynamic_phdr.p_offset)
        return 0;

    for (uint64_t pos = 0; pos < dynamic_phdr.p_filesz;
         pos += sizeof(Elf64_Dyn)) {
        Elf64_Dyn dynamic;
        size_t offset = (size_t)dynamic_phdr.p_offset + (size_t)pos;

        memcpy(&dynamic, elf + offset, sizeof(dynamic));
        if (dynamic.d_tag == DT_NULL) {
            terminated = 1;
            break;
        }
#define DLFRZ_ELF_IDENTITY_DYNAMIC(tag, seen, slot)                        \
        case tag:                                                          \
            if (!dlfrz_glibc_dynamic_value(                                \
                    &(seen), &(slot), dynamic.d_un.d_val))                 \
                return 0;                                                   \
            break
        switch (dynamic.d_tag) {
        DLFRZ_ELF_IDENTITY_DYNAMIC(DT_SYMTAB, have_symtab,
                                   symtab_address);
        DLFRZ_ELF_IDENTITY_DYNAMIC(DT_STRTAB, have_strtab,
                                   strtab_address);
        DLFRZ_ELF_IDENTITY_DYNAMIC(DT_STRSZ, have_strsz, strtab_size);
        DLFRZ_ELF_IDENTITY_DYNAMIC(DT_SYMENT, have_syment, syment);
        DLFRZ_ELF_IDENTITY_DYNAMIC(DT_HASH, have_sysv_hash,
                                   sysv_hash_address);
        DLFRZ_ELF_IDENTITY_DYNAMIC(DT_GNU_HASH, have_gnu_hash,
                                   gnu_hash_address);
        DLFRZ_ELF_IDENTITY_DYNAMIC(DT_VERSYM, have_versym,
                                   versym_address);
        DLFRZ_ELF_IDENTITY_DYNAMIC(DT_VERDEF, have_verdef,
                                   verdef_address);
        DLFRZ_ELF_IDENTITY_DYNAMIC(DT_VERDEFNUM, have_verdef_count,
                                   verdef_count);
        DLFRZ_ELF_IDENTITY_DYNAMIC(DT_VERNEED, have_verneed,
                                   verneed_address);
        DLFRZ_ELF_IDENTITY_DYNAMIC(DT_VERNEEDNUM, have_verneed_count,
                                   verneed_count);
        DLFRZ_ELF_IDENTITY_DYNAMIC(DT_SONAME, have_soname,
                                   soname_offset);
        case DT_NEEDED:
            if (needed_count == UINT32_MAX)
                return 0;
            needed_count++;
            break;
        default:
            break;
        }
#undef DLFRZ_ELF_IDENTITY_DYNAMIC
    }
    (void)verneed_address;
    if (!terminated || !have_symtab || !have_strtab || !have_strsz ||
        !have_syment || (!have_sysv_hash && !have_gnu_hash) ||
        symtab_address == 0 || strtab_address == 0 || strtab_size == 0 ||
        strtab_size > SIZE_MAX || syment != sizeof(Elf64_Sym) ||
        have_verdef != have_verdef_count ||
        have_verneed != have_verneed_count ||
        (have_verdef && verdef_count == 0) ||
        (have_verneed && verneed_count == 0) ||
        !dlfrz_glibc_vaddr_file_range(
            elf, elf_size, &ehdr, strtab_address, strtab_size,
            &strtab_offset) || elf[strtab_offset] != '\0' ||
        elf[strtab_offset + (size_t)strtab_size - 1] != '\0' ||
        !dlfrz_glibc_vaddr_file_available(
            elf, elf_size, &ehdr, symtab_address, &symtab_offset,
            &symtab_available))
        return 0;
    /* A complete ELF string table reserves its first and final bytes for
     * NUL.  Once both sentinels and the complete DT_STRSZ range are proved,
     * every in-range offset denotes a bounded, terminated suffix. */
    if (have_soname && soname_offset >= strtab_size)
        return 0;
    if (symtab_available / sizeof(Elf64_Sym) > UINT32_MAX)
        max_symbols = UINT32_MAX;
    else
        max_symbols =
            (uint32_t)(symtab_available / sizeof(Elf64_Sym));
    if (max_symbols == 0)
        return 0;

    if (have_sysv_hash &&
        !dlfrz_glibc_sysv_symbol_count(
            elf, elf_size, &ehdr, sysv_hash_address, max_symbols,
            &sysv_count))
        return 0;
    if (have_gnu_hash &&
        !dlfrz_glibc_gnu_symbol_count(
            elf, elf_size, &ehdr, gnu_hash_address, max_symbols,
            &gnu_count))
        return 0;
    if (have_sysv_hash) {
        if (have_gnu_hash && gnu_count != sysv_count)
            return 0;
        symbol_count = sysv_count;
    } else {
        symbol_count = gnu_count;
    }
    if (symbol_count == 0 || symbol_count > max_symbols ||
        !dlfrz_glibc_size_mul(symbol_count, sizeof(Elf64_Sym),
                              &symbol_bytes) ||
        !dlfrz_glibc_vaddr_file_range(
            elf, elf_size, &ehdr, symtab_address, symbol_bytes,
            &symtab_offset))
        return 0;
    if (have_versym) {
        if (!dlfrz_glibc_size_mul(symbol_count, sizeof(uint16_t),
                                  &symbol_bytes) ||
            !dlfrz_glibc_vaddr_file_range(
                elf, elf_size, &ehdr, versym_address, symbol_bytes,
                &versym_offset))
            return 0;
    }

    for (uint32_t i = 0; i < symbol_count; i++) {
        Elf64_Sym symbol;

        memcpy(&symbol,
               elf + symtab_offset + (size_t)i * sizeof(symbol),
               sizeof(symbol));
        if (symbol.st_name >= strtab_size)
            return 0;
    }

    view->elf = elf;
    view->elf_size = elf_size;
    view->ehdr = ehdr;
    view->dynsym_offset = symtab_offset;
    view->dynsym_count = symbol_count;
    view->dynstr_offset = strtab_offset;
    view->dynstr_size = (size_t)strtab_size;
    view->versym_offset = versym_offset;
    view->verdef_address = verdef_address;
    view->verdef_count = verdef_count;
    view->sysv_hash_address = sysv_hash_address;
    view->gnu_hash_address = gnu_hash_address;
    view->soname_offset = soname_offset;
    view->have_versym = have_versym;
    view->have_verdef = have_verdef;
    view->have_verneed = have_verneed;
    view->have_sysv_hash = have_sysv_hash;
    view->have_gnu_hash = have_gnu_hash;
    view->have_soname = have_soname;
    view->has_interp = interp_found;
    view->needed_count = needed_count;
    return 1;
}

static inline void
dlfrz_elf64_dyn_view_symbol(const struct dlfrz_elf64_dyn_view *view,
                            uint32_t index, Elf64_Sym *symbol)
{
    memcpy(symbol,
           view->elf + view->dynsym_offset +
               (size_t)index * sizeof(*symbol),
           sizeof(*symbol));
}

static inline uint32_t
dlfrz_elf64_sysv_name_hash(const char *name)
{
    uint32_t hash = 0;

    while (*name) {
        uint32_t high;

        hash = (hash << 4) + (unsigned char)*name++;
        high = hash & UINT32_C(0xf0000000);
        if (high)
            hash ^= high >> 24;
        hash &= ~high;
    }
    return hash;
}

static inline uint32_t
dlfrz_elf64_gnu_name_hash(const char *name)
{
    uint32_t hash = 5381;

    while (*name)
        hash = hash * 33U + (unsigned char)*name++;
    return hash;
}

static inline int
dlfrz_elf64_sysv_hash_exports(const struct dlfrz_elf64_dyn_view *view,
                              const char *name, uint32_t target_index)
{
    size_t offset;
    size_t bucket_bytes;
    size_t table_bytes;
    uint32_t nbuckets;
    uint32_t nchain;
    uint32_t symbol;

    if (!dlfrz_glibc_vaddr_file_range(
            view->elf, view->elf_size, &view->ehdr,
            view->sysv_hash_address, 2 * sizeof(uint32_t), &offset))
        return 0;
    nbuckets = dlfrz_glibc_read_u32(view->elf + offset);
    nchain = dlfrz_glibc_read_u32(
        view->elf + offset + sizeof(uint32_t));
    if (nbuckets == 0 || nchain != view->dynsym_count ||
        !dlfrz_glibc_size_mul(nbuckets, sizeof(uint32_t), &bucket_bytes) ||
        !dlfrz_glibc_size_add(2 * sizeof(uint32_t), bucket_bytes,
                              &table_bytes) ||
        !dlfrz_glibc_size_add(
            table_bytes, (size_t)nchain * sizeof(uint32_t), &table_bytes) ||
        !dlfrz_glibc_vaddr_file_range(
            view->elf, view->elf_size, &view->ehdr,
            view->sysv_hash_address, table_bytes, &offset))
        return 0;
    symbol = dlfrz_glibc_read_u32(
        view->elf + offset + 2 * sizeof(uint32_t) +
        (size_t)(dlfrz_elf64_sysv_name_hash(name) % nbuckets) *
            sizeof(uint32_t));
    for (uint32_t step = 0; symbol != STN_UNDEF && step < nchain; step++) {
        if (symbol >= nchain)
            return 0;
        if (symbol == target_index)
            return 1;
        symbol = dlfrz_glibc_read_u32(
            view->elf + offset + 2 * sizeof(uint32_t) + bucket_bytes +
            (size_t)symbol * sizeof(uint32_t));
    }
    return 0;
}

static inline int
dlfrz_elf64_gnu_hash_exports(const struct dlfrz_elf64_dyn_view *view,
                             const char *name, uint32_t target_index)
{
    size_t offset;
    size_t bloom_bytes;
    size_t bucket_bytes;
    size_t prefix_bytes;
    size_t chain_bytes;
    uint32_t nbuckets;
    uint32_t symoffset;
    uint32_t bloom_size;
    uint32_t bloom_shift;
    uint32_t name_hash;
    uint32_t symbol;
    uint64_t bloom_word;

    if (!dlfrz_glibc_vaddr_file_range(
            view->elf, view->elf_size, &view->ehdr,
            view->gnu_hash_address, 4 * sizeof(uint32_t), &offset))
        return 0;
    nbuckets = dlfrz_glibc_read_u32(view->elf + offset);
    symoffset = dlfrz_glibc_read_u32(
        view->elf + offset + sizeof(uint32_t));
    bloom_size = dlfrz_glibc_read_u32(
        view->elf + offset + 2 * sizeof(uint32_t));
    bloom_shift = dlfrz_glibc_read_u32(
        view->elf + offset + 3 * sizeof(uint32_t));
    if (nbuckets == 0 || bloom_size == 0 ||
        bloom_shift >= 32 || symoffset > view->dynsym_count ||
        target_index < symoffset ||
        !dlfrz_glibc_size_mul(bloom_size, sizeof(uint64_t), &bloom_bytes) ||
        !dlfrz_glibc_size_mul(nbuckets, sizeof(uint32_t), &bucket_bytes) ||
        !dlfrz_glibc_size_add(4 * sizeof(uint32_t), bloom_bytes,
                              &prefix_bytes) ||
        !dlfrz_glibc_size_add(prefix_bytes, bucket_bytes, &prefix_bytes) ||
        !dlfrz_glibc_size_mul(view->dynsym_count - symoffset,
                              sizeof(uint32_t), &chain_bytes) ||
        !dlfrz_glibc_size_add(prefix_bytes, chain_bytes, &chain_bytes) ||
        !dlfrz_glibc_vaddr_file_range(
            view->elf, view->elf_size, &view->ehdr,
            view->gnu_hash_address, chain_bytes, &offset))
        return 0;
    name_hash = dlfrz_elf64_gnu_name_hash(name);
    memcpy(&bloom_word,
           view->elf + offset + 4 * sizeof(uint32_t) +
               (size_t)((name_hash / 64U) % bloom_size) * sizeof(uint64_t),
           sizeof(bloom_word));
    if ((bloom_word & (UINT64_C(1) << (name_hash % 64U))) == 0 ||
        (bloom_word &
         (UINT64_C(1) << ((name_hash >> bloom_shift) % 64U))) == 0)
        return 0;
    symbol = dlfrz_glibc_read_u32(
        view->elf + offset + 4 * sizeof(uint32_t) + bloom_bytes +
        (size_t)(name_hash % nbuckets) *
            sizeof(uint32_t));
    for (uint32_t step = 0; symbol != STN_UNDEF &&
                            step < view->dynsym_count; step++, symbol++) {
        uint32_t chain;

        if (symbol < symoffset || symbol >= view->dynsym_count)
            return 0;
        chain = dlfrz_glibc_read_u32(
            view->elf + offset + prefix_bytes +
            (size_t)(symbol - symoffset) * sizeof(uint32_t));
        if (symbol == target_index)
            return (chain | 1U) == (name_hash | 1U);
        if (chain & 1U)
            break;
    }
    return 0;
}

/* Return 1 for one exact hash-exported name, 0 when absent, and -1 for
 * duplicates or hash metadata which does not export the matching entry. */
static inline int
dlfrz_elf64_dyn_view_find(const struct dlfrz_elf64_dyn_view *view,
                          const char *name, Elf64_Sym *symbol_out,
                          uint32_t *index_out)
{
    Elf64_Sym matched = {0};
    uint32_t matched_index = 0;
    int found = 0;

    for (uint32_t i = 0; i < view->dynsym_count; i++) {
        Elf64_Sym symbol;

        dlfrz_elf64_dyn_view_symbol(view, i, &symbol);
        if (!dlfrz_glibc_dynstr_name(
                view->elf + view->dynstr_offset, view->dynstr_size,
                symbol.st_name, name))
            continue;
        if (found)
            return -1;
        found = 1;
        matched = symbol;
        matched_index = i;
    }
    if (!found)
        return 0;
    if ((view->have_sysv_hash &&
         !dlfrz_elf64_sysv_hash_exports(view, name, matched_index)) ||
        (view->have_gnu_hash &&
         !dlfrz_elf64_gnu_hash_exports(view, name, matched_index)))
        return -1;
    if (symbol_out)
        *symbol_out = matched;
    if (index_out)
        *index_out = matched_index;
    return 1;
}

#define DLFRZ_GLIBC_DLFCN_HOOK_SLOTS 13U

/* Target-code evidence for glibc's private _dl_dlfcn_hook contract.  The
 * three scalar offsets retain the original, especially strict dlclose
 * field/slot-one witness.  The arrays cover every public and internal
 * member of struct dlfcn_hook, in target order.  Public witnesses are tied
 * to their exact exported libc entry points; the four hidden __libc_dl*
 * entry points are stripped from installed libc objects, so their entries
 * are instead the unique executable-image dispatches rooted at libc's
 * _rtld_global_ro relocation. */
struct dlfrz_glibc_dlfcn_consumer_evidence {
    size_t glro_load_file_offset;
    size_t hook_load_file_offset;
    size_t slot_load_file_offset;
    size_t hook_load_file_offsets[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS];
    size_t slot_load_file_offsets[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS];
};

static inline int
dlfrz_glibc_add_signed_u64(uint64_t base, int64_t displacement,
                           uint64_t *result)
{
    if (displacement >= 0) {
        uint64_t addend = (uint64_t)displacement;

        if (base > UINT64_MAX - addend)
            return 0;
        *result = base + addend;
    } else {
        uint64_t magnitude = (uint64_t)(-(displacement + 1)) + 1;

        if (base < magnitude)
            return 0;
        *result = base - magnitude;
    }
    return 1;
}

struct dlfrz_glibc_x86_mov_load {
    unsigned int destination;
    unsigned int base;
    int rip_relative;
    int64_t displacement;
    size_t length;
};

/* Decode only the x86-64 `mov r64, r/m64` form used by this evidence chain.
 * Every read is bounded by AVAILABLE; unsupported prefixes/addressing modes
 * simply do not constitute evidence. */
static inline int
dlfrz_glibc_x86_mov_load(const unsigned char *bytes, size_t available,
                         struct dlfrz_glibc_x86_mov_load *load)
{
    unsigned int rex;
    unsigned int modrm;
    unsigned int mod;
    unsigned int rm;
    unsigned int base;
    size_t cursor = 3;
    int64_t displacement = 0;
    int rip_relative = 0;

    if (!bytes || !load || available < 3 ||
        bytes[0] < UINT8_C(0x48) || bytes[0] > UINT8_C(0x4f) ||
        bytes[1] != UINT8_C(0x8b))
        return 0;
    rex = bytes[0];
    modrm = bytes[2];
    mod = modrm >> 6;
    rm = modrm & 7U;
    if (mod == 3)
        return 0;

    if (rm == 4) {
        unsigned int sib;
        unsigned int index;

        if (available < cursor + 1)
            return 0;
        sib = bytes[cursor++];
        index = ((sib >> 3) & 7U) | ((rex & 2U) ? 8U : 0U);
        /* Only the no-index SIB form is needed for a plain base load. */
        if (index != 4U)
            return 0;
        base = (sib & 7U) | ((rex & 1U) ? 8U : 0U);
        if (mod == 0 && (sib & 7U) == 5U)
            return 0;
    } else if (mod == 0 && rm == 5) {
        if (rex & 1U)
            return 0;
        base = 0;
        rip_relative = 1;
    } else {
        base = rm | ((rex & 1U) ? 8U : 0U);
    }

    if (rip_relative || mod == 2) {
        int32_t value;

        if (available < cursor + sizeof(value))
            return 0;
        memcpy(&value, bytes + cursor, sizeof(value));
        displacement = value;
        cursor += sizeof(value);
    } else if (mod == 1) {
        int8_t value;

        if (available < cursor + sizeof(value))
            return 0;
        memcpy(&value, bytes + cursor, sizeof(value));
        displacement = value;
        cursor += sizeof(value);
    }

    load->destination = ((modrm >> 3) & 7U) |
                        ((rex & 4U) ? 8U : 0U);
    load->base = base;
    load->rip_relative = rip_relative;
    load->displacement = displacement;
    load->length = cursor;
    return 1;
}

/* Enumerate exactly the byte positions at which the decoder above can
 * succeed.  A valid load always starts with REX.W followed by opcode 0x8b
 * and has at least one ModR/M byte.  Searching for the uncommon opcode first
 * avoids invoking the full decoder at every byte of a multi-MiB executable
 * segment without weakening its checks or its duplicate-witness scan.
 *
 * POSITION_LIMIT bounds candidate starts, not instruction ends.  This
 * distinction preserves callers whose bounded chain window permits an
 * instruction beginning at its last byte positions to consume bytes from
 * the enclosing CODE_SIZE range. */
static inline int
dlfrz_glibc_x86_next_mov_load_candidate(
    const unsigned char *code, size_t code_size, size_t position_limit,
    size_t start, size_t *position_out)
{
    size_t position_end;
    size_t opcode_position;

    if (!code || !position_out || position_limit > code_size ||
        code_size < 3)
        return 0;
    /* Positions [0, code_size - 2) have the decoder's three required
     * bytes.  POSITION_END is exclusive for starts and inclusive for their
     * second-byte opcode positions. */
    position_end = code_size - 2;
    if (position_end > position_limit)
        position_end = position_limit;
    if (start >= position_end)
        return 0;
    opcode_position = start + 1;

    while (opcode_position <= position_end) {
        const unsigned char *opcode =
            (const unsigned char *)memchr(
                code + opcode_position, UINT8_C(0x8b),
                position_end - opcode_position + 1);
        size_t candidate;

        if (!opcode)
            return 0;
        candidate = (size_t)(opcode - code) - 1;
        if (code[candidate] >= UINT8_C(0x48) &&
            code[candidate] <= UINT8_C(0x4f)) {
            *position_out = candidate;
            return 1;
        }
        opcode_position = (size_t)(opcode - code) + 1;
    }
    return 0;
}

static inline int
dlfrz_glibc_x86_register_move(const unsigned char *bytes, size_t available,
                              unsigned int *destination, size_t *length)
{
    unsigned int rex;
    unsigned int modrm;

    if (available < 3 || bytes[0] < UINT8_C(0x48) ||
        bytes[0] > UINT8_C(0x4f) || bytes[1] != UINT8_C(0x89) ||
        (bytes[2] >> 6) != 3)
        return 0;
    rex = bytes[0];
    modrm = bytes[2];
    *destination = (modrm & 7U) | ((rex & 1U) ? 8U : 0U);
    *length = 3;
    return 1;
}

static inline int
dlfrz_glibc_x86_cmp_memory_zero(const unsigned char *bytes,
                                size_t available, unsigned int expected_base,
                                size_t *length)
{
    unsigned int rex;
    unsigned int modrm;
    unsigned int mod;
    unsigned int rm;
    unsigned int base;
    size_t cursor = 3;

    if (available < 4 || bytes[0] < UINT8_C(0x48) ||
        bytes[0] > UINT8_C(0x4f) || bytes[1] != UINT8_C(0x83))
        return 0;
    rex = bytes[0];
    modrm = bytes[2];
    mod = modrm >> 6;
    rm = modrm & 7U;
    if (((modrm >> 3) & 7U) != 7U || mod == 0 || mod == 3 || rm == 4)
        return 0;
    base = rm | ((rex & 1U) ? 8U : 0U);
    if (base != expected_base)
        return 0;
    if (mod == 1)
        cursor += 1;
    else
        cursor += sizeof(int32_t);
    if (available < cursor + 1 || bytes[cursor] != 0)
        return 0;
    *length = cursor + 1;
    return 1;
}

static inline int
dlfrz_glibc_x86_je_target(const unsigned char *bytes, size_t available,
                          uint64_t instruction_vaddr,
                          uint64_t *target_vaddr, size_t *length)
{
    int64_t displacement;

    if (available >= 2 && bytes[0] == UINT8_C(0x74)) {
        int8_t value;

        memcpy(&value, bytes + 1, sizeof(value));
        displacement = value;
        *length = 2;
    } else if (available >= 6 && bytes[0] == UINT8_C(0x0f) &&
               bytes[1] == UINT8_C(0x84)) {
        int32_t value;

        memcpy(&value, bytes + 2, sizeof(value));
        displacement = value;
        *length = 6;
    } else {
        return 0;
    }
    if (instruction_vaddr > UINT64_MAX - *length)
        return 0;
    return dlfrz_glibc_add_signed_u64(
        instruction_vaddr + *length, displacement, target_vaddr);
}

static inline int
dlfrz_glibc_x86_test_same_register(const unsigned char *bytes,
                                   size_t available, unsigned int reg,
                                   size_t *length)
{
    unsigned int rex;
    unsigned int modrm;
    unsigned int left;
    unsigned int right;

    if (available < 3 || bytes[0] < UINT8_C(0x48) ||
        bytes[0] > UINT8_C(0x4f) || bytes[1] != UINT8_C(0x85) ||
        (bytes[2] >> 6) != 3)
        return 0;
    rex = bytes[0];
    modrm = bytes[2];
    left = (modrm & 7U) | ((rex & 1U) ? 8U : 0U);
    right = ((modrm >> 3) & 7U) | ((rex & 4U) ? 8U : 0U);
    if (left != reg || right != reg)
        return 0;
    *length = 3;
    return 1;
}

static inline int
dlfrz_glibc_x86_jump_slot_one(const unsigned char *bytes, size_t available,
                              unsigned int hook_register, size_t *length)
{
    size_t cursor = 0;
    unsigned int rex = 0x40;
    unsigned int modrm;
    unsigned int base;

    if (available && bytes[0] >= UINT8_C(0x40) &&
        bytes[0] <= UINT8_C(0x4f))
        rex = bytes[cursor++];
    if (available < cursor + 3 || bytes[cursor++] != UINT8_C(0xff))
        return 0;
    modrm = bytes[cursor++];
    if (((modrm >> 3) & 7U) != 4U || (modrm >> 6) != 1 ||
        (modrm & 7U) == 4U)
        return 0;
    base = (modrm & 7U) | ((rex & 1U) ? 8U : 0U);
    if (base != hook_register || bytes[cursor] != sizeof(void *))
        return 0;
    *length = cursor + 1;
    return 1;
}

/* Prove one tightly constrained control-flow chain in libc's dlclose body.
 * This intentionally does not carry register taint across arbitrary code:
 * the modern loads are adjacent, while the legacy audit branch admits only
 * register moves which do not overwrite GLRO, one memory comparison, and a
 * JE whose target is the exact hook load. */
static inline int
dlfrz_glibc_x86_dlfcn_chain(
    const unsigned char *code, size_t code_size, uint64_t function_vaddr,
    size_t function_file_offset, uint64_t glro_got_vaddr, int hook_offset,
    struct dlfrz_glibc_dlfcn_consumer_evidence *evidence)
{
    size_t completed = 0;
    struct dlfrz_glibc_dlfcn_consumer_evidence result;

    memset(&result, 0, sizeof(result));

    for (size_t got_position = 0; got_position < code_size; got_position++) {
        struct dlfrz_glibc_x86_mov_load got_load;
        uint64_t next_vaddr;
        uint64_t target_vaddr;

        if (!dlfrz_glibc_x86_mov_load(
                code + got_position, code_size - got_position, &got_load) ||
            !got_load.rip_relative ||
            function_vaddr > UINT64_MAX - got_position ||
            function_vaddr + got_position > UINT64_MAX - got_load.length)
            continue;
        next_vaddr = function_vaddr + got_position + got_load.length;
        if (!dlfrz_glibc_add_signed_u64(
                next_vaddr, got_load.displacement, &target_vaddr) ||
            target_vaddr != glro_got_vaddr)
            continue;

        for (size_t hook_position = got_position + got_load.length;
             hook_position < code_size; hook_position++) {
            struct dlfrz_glibc_x86_mov_load hook_load;
            size_t cursor;
            int linked = 0;

            if (!dlfrz_glibc_x86_mov_load(
                    code + hook_position, code_size - hook_position,
                    &hook_load) || hook_load.rip_relative ||
                hook_load.base != got_load.destination ||
                hook_load.displacement != hook_offset)
                continue;
            if (hook_position == got_position + got_load.length) {
                linked = 1;
            } else {
                uint64_t branch_target;
                size_t branch_length;
                size_t compare_length;

                cursor = got_position + got_load.length;
                for (unsigned int moves = 0; moves < 2; moves++) {
                    unsigned int destination;
                    size_t move_length;

                    if (!dlfrz_glibc_x86_register_move(
                            code + cursor, code_size - cursor,
                            &destination, &move_length))
                        break;
                    if (destination == got_load.destination)
                        break;
                    cursor += move_length;
                }
                if (dlfrz_glibc_x86_cmp_memory_zero(
                        code + cursor, code_size - cursor,
                        got_load.destination, &compare_length)) {
                    cursor += compare_length;
                    if (function_vaddr <= UINT64_MAX - cursor &&
                        dlfrz_glibc_x86_je_target(
                            code + cursor, code_size - cursor,
                            function_vaddr + cursor, &branch_target,
                            &branch_length) &&
                        branch_target == function_vaddr + hook_position)
                        linked = 1;
                }
            }
            if (!linked)
                continue;

            cursor = hook_position + hook_load.length;
            {
                struct dlfrz_glibc_x86_mov_load slot_load;

                if (dlfrz_glibc_x86_mov_load(
                        code + cursor, code_size - cursor, &slot_load) &&
                    !slot_load.rip_relative &&
                    slot_load.base == hook_load.destination &&
                    slot_load.displacement == (int64_t)sizeof(void *)) {
                    completed++;
                    result.slot_load_file_offset =
                        function_file_offset + cursor;
                } else {
                    size_t test_length;
                    size_t branch_length;
                    uint64_t ignored_target;
                    size_t jump_length;

                    if (!dlfrz_glibc_x86_test_same_register(
                            code + cursor, code_size - cursor,
                            hook_load.destination, &test_length))
                        continue;
                    cursor += test_length;
                    if (function_vaddr > UINT64_MAX - cursor ||
                        !dlfrz_glibc_x86_je_target(
                            code + cursor, code_size - cursor,
                            function_vaddr + cursor, &ignored_target,
                            &branch_length))
                        continue;
                    cursor += branch_length;
                    if (!dlfrz_glibc_x86_jump_slot_one(
                            code + cursor, code_size - cursor,
                            hook_load.destination, &jump_length))
                        continue;
                    completed++;
                    result.slot_load_file_offset =
                        function_file_offset + cursor;
                }
            }
            result.glro_load_file_offset =
                function_file_offset + got_position;
            result.hook_load_file_offset =
                function_file_offset + hook_position;
        }
    }
    if (completed != 1)
        return 0;
    if (evidence)
        memcpy(evidence, &result, sizeof(result));
    return 1;
}

static inline int
dlfrz_glibc_x86_dlfcn_consumer(
    const struct dlfrz_elf64_dyn_view *view, const Elf64_Sym *symbol,
    uint64_t glro_got_vaddr, int hook_offset,
    struct dlfrz_glibc_dlfcn_consumer_evidence *evidence)
{
    size_t function_offset;

    if (symbol->st_size < 7 || symbol->st_size > 1024 ||
        !dlfrz_glibc_vaddr_file_range(
            view->elf, view->elf_size, &view->ehdr,
            symbol->st_value, symbol->st_size, &function_offset))
        return 0;
    return dlfrz_glibc_x86_dlfcn_chain(
        view->elf + function_offset, (size_t)symbol->st_size,
        symbol->st_value, function_offset, glro_got_vaddr, hook_offset,
        evidence);
}

static inline int64_t
dlfrz_glibc_sign_extend_21(uint32_t value)
{
    value &= UINT32_C(0x1fffff);
    if (value & UINT32_C(0x100000))
        return (int64_t)value - INT64_C(0x200000);
    return (int64_t)value;
}

static inline int
dlfrz_glibc_aarch64_dlfcn_consumer(
    const struct dlfrz_elf64_dyn_view *view, const Elf64_Sym *symbol,
    uint64_t glro_got_vaddr, int hook_offset,
    struct dlfrz_glibc_dlfcn_consumer_evidence *evidence)
{
    size_t function_offset;
    size_t completed = 0;
    struct dlfrz_glibc_dlfcn_consumer_evidence result;

    memset(&result, 0, sizeof(result));

    if (hook_offset < 0 || (hook_offset & 7) != 0 ||
        symbol->st_value % sizeof(uint32_t) != 0 ||
        symbol->st_size < 5 * sizeof(uint32_t) ||
        symbol->st_size > 1024 ||
        symbol->st_size % sizeof(uint32_t) != 0 ||
        !dlfrz_glibc_vaddr_file_range(
            view->elf, view->elf_size, &view->ehdr,
            symbol->st_value, symbol->st_size,
            &function_offset))
        return 0;

    for (size_t got_position = 0;
         got_position + 2 * sizeof(uint32_t) <= (size_t)symbol->st_size;
         got_position += sizeof(uint32_t)) {
        const unsigned char *code = view->elf + function_offset;
        uint32_t adrp = dlfrz_glibc_read_u32(code + got_position);
        uint32_t got_load = dlfrz_glibc_read_u32(
            code + got_position + sizeof(uint32_t));
        unsigned int page_register;
        unsigned int glro_register;
        uint32_t immediate;
        int64_t page_displacement;
        uint64_t pc_page;
        uint64_t target_page;
        uint64_t got_displacement;

        if ((adrp & UINT32_C(0x9f000000)) != UINT32_C(0x90000000) ||
            (got_load & UINT32_C(0xffc00000)) !=
                UINT32_C(0xf9400000))
            continue;
        page_register = adrp & 31U;
        if (((got_load >> 5) & 31U) != page_register)
            continue;
        glro_register = got_load & 31U;
        immediate = ((adrp >> 29) & 3U) |
                    (((adrp >> 5) & UINT32_C(0x7ffff)) << 2);
        page_displacement =
            dlfrz_glibc_sign_extend_21(immediate) * INT64_C(4096);
        if (symbol->st_value > UINT64_MAX - got_position)
            return 0;
        pc_page = (symbol->st_value + got_position) & ~UINT64_C(0xfff);
        got_displacement =
            ((got_load >> 10) & UINT32_C(0xfff)) * UINT64_C(8);
        if (!dlfrz_glibc_add_signed_u64(
                pc_page, page_displacement, &target_page) ||
            target_page > UINT64_MAX - got_displacement ||
            target_page + got_displacement != glro_got_vaddr)
            continue;

        for (size_t hook_position = got_position + 2 * sizeof(uint32_t);
             hook_position + 2 * sizeof(uint32_t) <=
                 (size_t)symbol->st_size;
             hook_position += sizeof(uint32_t)) {
            uint32_t hook_load = dlfrz_glibc_read_u32(
                code + hook_position);
            unsigned int hook_register;
            int linked = 0;

            if ((hook_load & UINT32_C(0xffc00000)) !=
                    UINT32_C(0xf9400000) ||
                ((hook_load >> 5) & 31U) != glro_register ||
                (((hook_load >> 10) & UINT32_C(0xfff)) * UINT64_C(8)) !=
                    (uint64_t)hook_offset)
                continue;
            hook_register = hook_load & 31U;
            if (hook_position == got_position + 2 * sizeof(uint32_t)) {
                linked = 1;
            } else {
                uint32_t audit_load = dlfrz_glibc_read_u32(
                    code + got_position + 2 * sizeof(uint32_t));
                uint32_t branch = dlfrz_glibc_read_u32(
                    code + got_position + 3 * sizeof(uint32_t));
                unsigned int audit_register = audit_load & 31U;
                uint32_t branch_imm;
                int64_t branch_displacement;
                uint64_t branch_target;
                uint64_t branch_vaddr;

                branch_imm = (branch >> 5) & UINT32_C(0x7ffff);
                branch_displacement = (branch_imm & UINT32_C(0x40000))
                    ? ((int64_t)branch_imm - INT64_C(0x80000)) * 4
                    : (int64_t)branch_imm * 4;
                if ((audit_load & UINT32_C(0xffc00000)) ==
                        UINT32_C(0xf9400000) &&
                    ((audit_load >> 5) & 31U) == glro_register &&
                    audit_register != glro_register &&
                    (branch & UINT32_C(0xff000000)) ==
                        UINT32_C(0xb4000000) &&
                    (branch & 31U) == audit_register &&
                    symbol->st_value <= UINT64_MAX - got_position -
                        3 * sizeof(uint32_t)) {
                    branch_vaddr = symbol->st_value + got_position +
                                   3 * sizeof(uint32_t);
                    if (dlfrz_glibc_add_signed_u64(
                            branch_vaddr, branch_displacement,
                            &branch_target) &&
                        branch_target == symbol->st_value + hook_position)
                        linked = 1;
                }
            }
            if (!linked)
                continue;
            {
                size_t slot_position = hook_position + sizeof(uint32_t);
                uint32_t slot_load = dlfrz_glibc_read_u32(
                    code + slot_position);

                if ((slot_load & UINT32_C(0xffc00000)) ==
                        UINT32_C(0xf9400000) &&
                    ((slot_load >> 5) & 31U) == hook_register &&
                    (((slot_load >> 10) & UINT32_C(0xfff)) * UINT64_C(8)) ==
                        sizeof(void *)) {
                    completed++;
                    result.glro_load_file_offset =
                        function_offset + got_position + sizeof(uint32_t);
                    result.hook_load_file_offset =
                        function_offset + hook_position;
                    result.slot_load_file_offset =
                        function_offset + slot_position;
                    continue;
                }
                /* Modern glibc checks a nullable hook with CBZ before the
                 * slot-one load on the fall-through edge. */
                if ((slot_load & UINT32_C(0xff000000)) ==
                        UINT32_C(0xb4000000) &&
                    (slot_load & 31U) == hook_register &&
                    slot_position + 2 * sizeof(uint32_t) <=
                        (size_t)symbol->st_size) {
                    slot_position += sizeof(uint32_t);
                    slot_load = dlfrz_glibc_read_u32(code + slot_position);
                    if ((slot_load & UINT32_C(0xffc00000)) ==
                            UINT32_C(0xf9400000) &&
                        ((slot_load >> 5) & 31U) == hook_register &&
                        (((slot_load >> 10) & UINT32_C(0xfff)) *
                         UINT64_C(8)) == sizeof(void *)) {
                        completed++;
                        result.glro_load_file_offset = function_offset +
                            got_position + sizeof(uint32_t);
                        result.hook_load_file_offset =
                            function_offset + hook_position;
                        result.slot_load_file_offset =
                            function_offset + slot_position;
                    }
                }
            }
        }
    }
    if (completed != 1)
        return 0;
    if (evidence)
        memcpy(evidence, &result, sizeof(result));
    return 1;
}

/* Decode an x86-64 indirect call/jump through memory.  Only a plain base
 * plus displacement is admitted; indexed, RIP-relative, and register-only
 * forms are handled separately. */
static inline int
dlfrz_glibc_x86_indirect_memory(const unsigned char *bytes,
                                size_t available,
                                unsigned int *base_out,
                                int64_t *displacement_out,
                                size_t *length_out)
{
    size_t cursor = 0;
    unsigned int rex = UINT8_C(0x40);
    unsigned int modrm;
    unsigned int mod;
    unsigned int rm;
    unsigned int base;
    int64_t displacement = 0;

    if (available && bytes[0] >= UINT8_C(0x40) &&
        bytes[0] <= UINT8_C(0x4f))
        rex = bytes[cursor++];
    if (available < cursor + 2 || bytes[cursor++] != UINT8_C(0xff))
        return 0;
    modrm = bytes[cursor++];
    mod = modrm >> 6;
    rm = modrm & 7U;
    if ((rex & 4U) ||
        (((modrm >> 3) & 7U) != 2U &&
         ((modrm >> 3) & 7U) != 4U) ||
        mod == 3)
        return 0;
    if (rm == 4U) {
        unsigned int sib;
        unsigned int index;

        if (available < cursor + 1)
            return 0;
        sib = bytes[cursor++];
        index = ((sib >> 3) & 7U) | ((rex & 2U) ? 8U : 0U);
        if (index != 4U || (mod == 0 && (sib & 7U) == 5U))
            return 0;
        base = (sib & 7U) | ((rex & 1U) ? 8U : 0U);
    } else {
        if (mod == 0 && rm == 5U)
            return 0;
        base = rm | ((rex & 1U) ? 8U : 0U);
    }
    if (mod == 1) {
        int8_t value;

        if (available < cursor + sizeof(value))
            return 0;
        memcpy(&value, bytes + cursor, sizeof(value));
        displacement = value;
        cursor += sizeof(value);
    } else if (mod == 2) {
        int32_t value;

        if (available < cursor + sizeof(value))
            return 0;
        memcpy(&value, bytes + cursor, sizeof(value));
        displacement = value;
        cursor += sizeof(value);
    }
    *base_out = base;
    *displacement_out = displacement;
    *length_out = cursor;
    return 1;
}

static inline int
dlfrz_glibc_x86_indirect_register(const unsigned char *bytes,
                                  size_t available,
                                  unsigned int expected_register,
                                  size_t *length_out)
{
    size_t cursor = 0;
    unsigned int rex = UINT8_C(0x40);
    unsigned int modrm;
    unsigned int target;

    if (available && bytes[0] >= UINT8_C(0x40) &&
        bytes[0] <= UINT8_C(0x4f))
        rex = bytes[cursor++];
    if (available < cursor + 2 || bytes[cursor++] != UINT8_C(0xff))
        return 0;
    modrm = bytes[cursor++];
    if ((rex & 4U) || (modrm >> 6) != 3U ||
        (((modrm >> 3) & 7U) != 2U &&
         ((modrm >> 3) & 7U) != 4U))
        return 0;
    target = (modrm & 7U) | ((rex & 1U) ? 8U : 0U);
    if (target != expected_register)
        return 0;
    *length_out = cursor;
    return 1;
}

/* Find one dispatch of EXPECTED_SLOT from a register already proven to hold
 * the target hook.  The function pointer may be called/jumped through the
 * hook directly, or loaded into a register and dispatched after bounded
 * epilogue/canary work. */
static inline size_t
dlfrz_glibc_x86_dlfcn_slot_dispatches(
    const unsigned char *code, size_t code_size, size_t start,
    unsigned int hook_register, unsigned int expected_slot,
    size_t *slot_position_out)
{
    size_t completed = 0;
    size_t end = code_size;
    int64_t expected_displacement =
        (int64_t)expected_slot * (int64_t)sizeof(void *);

    if (start > end)
        return 0;
    if (end - start > 96U)
        end = start + 96U;
    for (size_t position = start; position < end; position++) {
        unsigned int base;
        int64_t displacement;
        size_t length;
        struct dlfrz_glibc_x86_mov_load load;

        if (dlfrz_glibc_x86_indirect_memory(
                code + position, end - position, &base, &displacement,
                &length) && base == hook_register &&
            displacement == expected_displacement) {
            completed++;
            if (slot_position_out)
                *slot_position_out = position;
        }
        if (!dlfrz_glibc_x86_mov_load(
                code + position, end - position, &load) ||
            load.rip_relative || load.base != hook_register ||
            load.displacement != expected_displacement)
            continue;
        {
            size_t dispatch_end = end;

            if (dispatch_end - position > 96U)
                dispatch_end = position + 96U;
            for (size_t dispatch = position + load.length;
                 dispatch < dispatch_end; dispatch++) {
                if (!dlfrz_glibc_x86_indirect_register(
                        code + dispatch, dispatch_end - dispatch,
                        load.destination, &length))
                    continue;
                completed++;
                if (slot_position_out)
                    *slot_position_out = position;
                break;
            }
        }
    }
    return completed;
}

/* Collect the four stripped internal-member dispatches in one pass through
 * the bounded hook-consumer window.  Keep this separate from the public
 * single-slot helper above so its behavior remains unchanged. */
static inline void
dlfrz_glibc_x86_dlfcn_internal_slot_dispatches(
    const unsigned char *code, size_t code_size, size_t start,
    unsigned int hook_register,
    size_t completed[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U],
    size_t slot_positions[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U])
{
    const size_t internal_count = DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U;
    const int64_t first_displacement =
        INT64_C(9) * (int64_t)sizeof(void *);
    const int64_t end_displacement =
        (int64_t)DLFRZ_GLIBC_DLFCN_HOOK_SLOTS *
        (int64_t)sizeof(void *);
    size_t end = code_size;

    for (size_t internal = 0; internal < internal_count; internal++) {
        completed[internal] = 0;
        slot_positions[internal] = 0;
    }
    if (start > end)
        return;
    if (end - start > 96U)
        end = start + 96U;
    for (size_t position = start; position < end; position++) {
        unsigned int base;
        int64_t displacement;
        size_t length;
        struct dlfrz_glibc_x86_mov_load load;

        if (dlfrz_glibc_x86_indirect_memory(
                code + position, end - position, &base, &displacement,
                &length) && base == hook_register &&
            displacement >= first_displacement &&
            displacement < end_displacement &&
            displacement % (int64_t)sizeof(void *) == 0) {
            size_t internal =
                (size_t)(displacement / (int64_t)sizeof(void *)) - 9U;

            completed[internal]++;
            slot_positions[internal] = position;
        }
        if (!dlfrz_glibc_x86_mov_load(
                code + position, end - position, &load) ||
            load.rip_relative || load.base != hook_register ||
            load.displacement < first_displacement ||
            load.displacement >= end_displacement ||
            load.displacement % (int64_t)sizeof(void *) != 0)
            continue;
        {
            size_t internal =
                (size_t)(load.displacement /
                         (int64_t)sizeof(void *)) - 9U;
            size_t dispatch_end = end;

            if (dispatch_end - position > 96U)
                dispatch_end = position + 96U;
            for (size_t dispatch = position + load.length;
                 dispatch < dispatch_end; dispatch++) {
                if (!dlfrz_glibc_x86_indirect_register(
                        code + dispatch, dispatch_end - dispatch,
                        load.destination, &length))
                    continue;
                completed[internal]++;
                slot_positions[internal] = position;
                break;
            }
        }
    }
}

static inline int
dlfrz_glibc_x86_dlfcn_branch_targets(
    const unsigned char *code, size_t code_size, uint64_t code_vaddr,
    size_t search_start, size_t target_position)
{
    size_t search_end = target_position;

    if (search_start > search_end || search_end > code_size)
        return 0;
    if (search_end - search_start > 64U)
        search_end = search_start + 64U;
    for (size_t position = search_start; position < search_end;
         position++) {
        uint64_t target_vaddr;
        size_t length;

        if (code_vaddr > UINT64_MAX - position ||
            !dlfrz_glibc_x86_je_target(
                code + position, code_size - position,
                code_vaddr + position, &target_vaddr, &length))
            continue;
        if (code_vaddr <= UINT64_MAX - target_position) {
            uint64_t hook_vaddr = code_vaddr + target_position;

            if (target_vaddr <= hook_vaddr &&
                hook_vaddr - target_vaddr <= UINT64_C(32))
                return 1;
        }
    }
    return 0;
}

/* Count bounded, relocation-rooted witnesses for one hook member in an
 * x86-64 code region.  Requiring one unique root/hook/dispatch chain avoids
 * treating an unrelated table access with the same small displacement as
 * ABI evidence. */
static inline size_t
dlfrz_glibc_x86_dlfcn_member_matches(
    const unsigned char *code, size_t code_size, uint64_t code_vaddr,
    uint64_t glro_got_vaddr, int hook_offset, unsigned int expected_slot,
    size_t chain_limit,
    size_t *hook_position_out, size_t *slot_position_out)
{
    size_t completed = 0;

    for (size_t got_position = 0; got_position < code_size;
         got_position++) {
        struct dlfrz_glibc_x86_mov_load got_load;
        uint64_t next_vaddr;
        uint64_t target_vaddr;
        size_t hook_end;

        if (!dlfrz_glibc_x86_mov_load(
                code + got_position, code_size - got_position, &got_load) ||
            !got_load.rip_relative ||
            code_vaddr > UINT64_MAX - got_position ||
            code_vaddr + got_position > UINT64_MAX - got_load.length)
            continue;
        next_vaddr = code_vaddr + got_position + got_load.length;
        if (!dlfrz_glibc_add_signed_u64(
                next_vaddr, got_load.displacement, &target_vaddr) ||
            target_vaddr != glro_got_vaddr)
            continue;
        hook_end = code_size;
        if (chain_limit == 0)
            continue;
        if (hook_end - got_position > chain_limit)
            hook_end = got_position + chain_limit;
        for (size_t hook_position = got_position + got_load.length;
             hook_position < hook_end; hook_position++) {
            struct dlfrz_glibc_x86_mov_load hook_load;
            size_t slot_position = 0;
            size_t dispatches;

            if (!dlfrz_glibc_x86_mov_load(
                    code + hook_position, code_size - hook_position,
                    &hook_load) || hook_load.rip_relative ||
                hook_load.base != got_load.destination ||
                hook_load.displacement != hook_offset)
                continue;
            if (hook_position > got_position + 48U &&
                !dlfrz_glibc_x86_dlfcn_branch_targets(
                    code, code_size, code_vaddr,
                    got_position + got_load.length, hook_position))
                continue;
            dispatches = dlfrz_glibc_x86_dlfcn_slot_dispatches(
                code, code_size, hook_position + hook_load.length,
                hook_load.destination, expected_slot, &slot_position);
            if (dispatches != 1)
                continue;
            completed++;
            if (hook_position_out)
                *hook_position_out = hook_position;
            if (slot_position_out)
                *slot_position_out = slot_position;
        }
    }
    return completed;
}

/* Scan one x86-64 code region once for all four hidden dlfcn-hook
 * consumers.  Every currently admitted hook offset is a positive value
 * above INT8_MAX and therefore uses a disp32; its low byte is a much rarer
 * immutable anchor than the tens of thousands of ordinary REX.W/MOV
 * instructions in a libc text segment.  Enumerate exact hook-load candidates
 * from that byte, then search only the preceding 1024-byte chain window for
 * the relocation-rooted GOT load.  Checking the decoded displacement
 * position prevents one byte from reporting the same instruction twice
 * through the SIB and non-SIB shapes.  The generic helper retains the
 * original forward validator for a possible future disp8 profile.
 *
 * Reversing the traversal does not change the evidence relation: every
 * accepted GOT/hook pair still passes the same decoders, address proof,
 * branch proof and bounded dispatch scan.  Keep a separate match count per
 * slot so this has exactly the same fail-closed uniqueness contract as four
 * calls to dlfrz_glibc_x86_dlfcn_member_matches(). */
static inline int
dlfrz_glibc_x86_dlfcn_internal_matches(
    const unsigned char *code, size_t code_size, uint64_t code_vaddr,
    uint64_t glro_got_vaddr, int hook_offset,
    size_t matches[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U],
    size_t hook_positions[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U],
    size_t slot_positions[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U])
{
    const size_t internal_count = DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U;
    size_t displacement_search = 0;
    unsigned char encoded_hook_offset[sizeof(int32_t)];
    unsigned char displacement_low;

    if (!matches || !hook_positions || !slot_positions)
        return 0;
    for (size_t i = 0; i < internal_count; i++) {
        matches[i] = 0;
        hook_positions[i] = 0;
        slot_positions[i] = 0;
    }
    if (!code)
        return 1;
    if (hook_offset >= INT8_MIN && hook_offset <= INT8_MAX) {
        for (size_t internal = 0; internal < internal_count; internal++)
            matches[internal] = dlfrz_glibc_x86_dlfcn_member_matches(
                code, code_size, code_vaddr, glro_got_vaddr,
                hook_offset, (unsigned int)(9U + internal), 1024U,
                &hook_positions[internal], &slot_positions[internal]);
        return 1;
    }
    if (hook_offset < INT32_MIN || hook_offset > INT32_MAX)
        return 1;
    for (size_t byte = 0; byte < sizeof(encoded_hook_offset); byte++)
        encoded_hook_offset[byte] =
            (unsigned char)((uint32_t)hook_offset >> (byte * 8U));
    displacement_low = encoded_hook_offset[0];

    while (displacement_search < code_size) {
        const unsigned char *displacement =
            (const unsigned char *)memchr(
                code + displacement_search, displacement_low,
                code_size - displacement_search);
        size_t displacement_position;
        size_t candidate_positions[2];
        size_t candidate_count = 0;

        if (!displacement)
            break;
        displacement_position = (size_t)(displacement - code);
        displacement_search = displacement_position + 1U;
        if (sizeof(encoded_hook_offset) >
                code_size - displacement_position ||
            memcmp(displacement, encoded_hook_offset,
                   sizeof(encoded_hook_offset)) != 0)
            continue;
        /* A plain base load places its disp32 three bytes after the REX;
         * the admitted no-index SIB form places it four bytes after. */
        if (displacement_position >= 4U)
            candidate_positions[candidate_count++] =
                displacement_position - 4U;
        if (displacement_position >= 3U)
            candidate_positions[candidate_count++] =
                displacement_position - 3U;

        for (size_t candidate = 0; candidate < candidate_count;
             candidate++) {
            size_t hook_position = candidate_positions[candidate];
            struct dlfrz_glibc_x86_mov_load hook_load;
            size_t dispatches[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U];
            size_t dispatch_positions[
                DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U];
            size_t got_search;

            if (!dlfrz_glibc_x86_mov_load(
                    code + hook_position, code_size - hook_position,
                    &hook_load) || hook_load.rip_relative ||
                hook_load.displacement != hook_offset ||
                hook_load.length < sizeof(int32_t) ||
                hook_position + hook_load.length - sizeof(int32_t) !=
                    displacement_position)
                continue;
            dlfrz_glibc_x86_dlfcn_internal_slot_dispatches(
                code, code_size, hook_position + hook_load.length,
                hook_load.destination, dispatches, dispatch_positions);

            /* GOT_POSITION must satisfy HOOK_POSITION < GOT_POSITION +
             * 1024, exactly matching the forward scanner's half-open chain
             * window. */
            got_search = hook_position >= 1024U
                ? hook_position - 1023U : 0;
            for (;;) {
                struct dlfrz_glibc_x86_mov_load got_load;
                uint64_t next_vaddr;
                uint64_t target_vaddr;
                size_t got_position;

                if (!dlfrz_glibc_x86_next_mov_load_candidate(
                        code, code_size, hook_position, got_search,
                        &got_position))
                    break;
                got_search = got_position + 1U;
                if (!dlfrz_glibc_x86_mov_load(
                        code + got_position, code_size - got_position,
                        &got_load) || !got_load.rip_relative ||
                    got_load.destination != hook_load.base ||
                    got_position + got_load.length > hook_position ||
                    code_vaddr > UINT64_MAX - got_position ||
                    code_vaddr + got_position >
                        UINT64_MAX - got_load.length)
                    continue;
                next_vaddr = code_vaddr + got_position + got_load.length;
                if (!dlfrz_glibc_add_signed_u64(
                        next_vaddr, got_load.displacement, &target_vaddr) ||
                    target_vaddr != glro_got_vaddr ||
                    (hook_position - got_position > 48U &&
                     !dlfrz_glibc_x86_dlfcn_branch_targets(
                         code, code_size, code_vaddr,
                         got_position + got_load.length, hook_position)))
                    continue;
                for (size_t internal = 0; internal < internal_count;
                     internal++) {
                    if (dispatches[internal] != 1)
                        continue;
                    if (matches[internal] == SIZE_MAX)
                        return 0;
                    matches[internal]++;
                    hook_positions[internal] = hook_position;
                    slot_positions[internal] =
                        dispatch_positions[internal];
                }
            }
        }
    }
    return 1;
}

static inline int
dlfrz_glibc_aarch64_indirect_branch(uint32_t instruction,
                                    unsigned int expected_register)
{
    uint32_t opcode = instruction & UINT32_C(0xfffffc1f);

    return (opcode == UINT32_C(0xd61f0000) ||
            opcode == UINT32_C(0xd63f0000)) &&
           ((instruction >> 5) & 31U) == expected_register;
}

static inline int
dlfrz_glibc_aarch64_register_move(uint32_t instruction,
                                 unsigned int source_register,
                                 unsigned int *destination_out)
{
    if ((instruction & UINT32_C(0xffe0ffe0)) !=
            UINT32_C(0xaa0003e0) ||
        ((instruction >> 16) & 31U) != source_register)
        return 0;
    *destination_out = instruction & 31U;
    return 1;
}

static inline size_t
dlfrz_glibc_aarch64_dlfcn_slot_dispatches(
    const unsigned char *code, size_t code_size, size_t start,
    unsigned int hook_register, unsigned int expected_slot,
    size_t *slot_position_out)
{
    size_t completed = 0;
    size_t end = code_size;
    uint64_t expected_displacement =
        (uint64_t)expected_slot * UINT64_C(8);

    if (start > end || (start & 3U) != 0)
        return 0;
    if (end - start > 96U)
        end = start + 96U;
    for (size_t position = start;
         position + sizeof(uint32_t) <= end;
         position += sizeof(uint32_t)) {
        uint32_t load = dlfrz_glibc_read_u32(code + position);
        unsigned int target_register;
        unsigned int dispatch_register;
        size_t dispatch_end;

        if ((load & UINT32_C(0xffc00000)) != UINT32_C(0xf9400000) ||
            ((load >> 5) & 31U) != hook_register ||
            ((uint64_t)((load >> 10) & UINT32_C(0xfff)) * UINT64_C(8)) !=
                expected_displacement)
            continue;
        target_register = load & 31U;
        dispatch_register = target_register;
        dispatch_end = end;
        if (dispatch_end - position > 96U)
            dispatch_end = position + 96U;
        for (size_t dispatch = position + sizeof(uint32_t);
             dispatch + sizeof(uint32_t) <= dispatch_end;
             dispatch += sizeof(uint32_t)) {
            uint32_t instruction =
                dlfrz_glibc_read_u32(code + dispatch);
            unsigned int destination;

            if (dlfrz_glibc_aarch64_indirect_branch(
                    instruction, dispatch_register)) {
                completed++;
                if (slot_position_out)
                    *slot_position_out = position;
                break;
            }
            if (dlfrz_glibc_aarch64_register_move(
                    instruction, dispatch_register, &destination))
                dispatch_register = destination;
        }
    }
    return completed;
}

/* Collect all hidden internal-member loads while decoding the bounded
 * AArch64 hook-consumer window once. */
static inline void
dlfrz_glibc_aarch64_dlfcn_internal_slot_dispatches(
    const unsigned char *code, size_t code_size, size_t start,
    unsigned int hook_register,
    size_t completed[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U],
    size_t slot_positions[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U])
{
    const size_t internal_count = DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U;
    const uint64_t first_displacement = UINT64_C(9) * UINT64_C(8);
    const uint64_t end_displacement =
        (uint64_t)DLFRZ_GLIBC_DLFCN_HOOK_SLOTS * UINT64_C(8);
    size_t end = code_size;

    for (size_t internal = 0; internal < internal_count; internal++) {
        completed[internal] = 0;
        slot_positions[internal] = 0;
    }
    if (start > end || (start & 3U) != 0)
        return;
    if (end - start > 96U)
        end = start + 96U;
    for (size_t position = start;
         position + sizeof(uint32_t) <= end;
         position += sizeof(uint32_t)) {
        uint32_t load = dlfrz_glibc_read_u32(code + position);
        uint64_t displacement;
        unsigned int target_register;
        unsigned int dispatch_register;
        size_t dispatch_end;
        size_t internal;

        if ((load & UINT32_C(0xffc00000)) != UINT32_C(0xf9400000) ||
            ((load >> 5) & 31U) != hook_register)
            continue;
        displacement =
            (uint64_t)((load >> 10) & UINT32_C(0xfff)) * UINT64_C(8);
        if (displacement < first_displacement ||
            displacement >= end_displacement)
            continue;
        internal = (size_t)(displacement / UINT64_C(8)) - 9U;
        target_register = load & 31U;
        dispatch_register = target_register;
        dispatch_end = end;
        if (dispatch_end - position > 96U)
            dispatch_end = position + 96U;
        for (size_t dispatch = position + sizeof(uint32_t);
             dispatch + sizeof(uint32_t) <= dispatch_end;
             dispatch += sizeof(uint32_t)) {
            uint32_t instruction =
                dlfrz_glibc_read_u32(code + dispatch);
            unsigned int destination;

            if (dlfrz_glibc_aarch64_indirect_branch(
                    instruction, dispatch_register)) {
                completed[internal]++;
                slot_positions[internal] = position;
                break;
            }
            if (dlfrz_glibc_aarch64_register_move(
                    instruction, dispatch_register, &destination))
                dispatch_register = destination;
        }
    }
}

/* AArch64 compilers need not keep the GOT load adjacent to its ADRP.  Find
 * one exact, bounded ADRP/LDR pair for the _rtld_global_ro relocation. */
static inline int
dlfrz_glibc_aarch64_dlfcn_glro_load(
    const unsigned char *code, size_t code_size, uint64_t code_vaddr,
    size_t adrp_position, uint64_t glro_got_vaddr,
    size_t *load_position_out, unsigned int *glro_register_out)
{
    uint32_t adrp;
    unsigned int page_register;
    uint32_t immediate;
    int64_t page_displacement;
    uint64_t pc_page;
    uint64_t target_page;
    size_t scan_end;
    size_t matches = 0;

    if ((adrp_position & 3U) != 0 ||
        adrp_position + sizeof(uint32_t) > code_size ||
        code_vaddr > UINT64_MAX - adrp_position)
        return 0;
    adrp = dlfrz_glibc_read_u32(code + adrp_position);
    if ((adrp & UINT32_C(0x9f000000)) != UINT32_C(0x90000000))
        return 0;
    page_register = adrp & 31U;
    immediate = ((adrp >> 29) & 3U) |
                (((adrp >> 5) & UINT32_C(0x7ffff)) << 2);
    page_displacement =
        dlfrz_glibc_sign_extend_21(immediate) * INT64_C(4096);
    pc_page = (code_vaddr + adrp_position) & ~UINT64_C(0xfff);
    if (!dlfrz_glibc_add_signed_u64(
            pc_page, page_displacement, &target_page))
        return 0;

    scan_end = code_size;
    if (scan_end - adrp_position > 32U)
        scan_end = adrp_position + 32U;
    for (size_t position = adrp_position + sizeof(uint32_t);
         position + sizeof(uint32_t) <= scan_end;
         position += sizeof(uint32_t)) {
        uint32_t load = dlfrz_glibc_read_u32(code + position);
        uint64_t displacement;

        if ((load & UINT32_C(0xffc00000)) != UINT32_C(0xf9400000) ||
            ((load >> 5) & 31U) != page_register)
            continue;
        displacement =
            (uint64_t)((load >> 10) & UINT32_C(0xfff)) * UINT64_C(8);
        if (target_page > UINT64_MAX - displacement ||
            target_page + displacement != glro_got_vaddr)
            continue;
        matches++;
        *load_position_out = position;
        *glro_register_out = load & 31U;
    }
    return matches == 1;
}

/* Legacy glibc consumers test an audit-interface field before entering a
 * distant hook block.  Accept a distant block only when an early conditional
 * branch targets that block, rather than joining unrelated code in the same
 * executable segment. */
static inline int
dlfrz_glibc_aarch64_dlfcn_branch_targets(
    const unsigned char *code, size_t code_size, uint64_t code_vaddr,
    size_t search_start, size_t target_position)
{
    size_t search_end = target_position;

    if ((search_start & 3U) != 0 || (target_position & 3U) != 0 ||
        search_start > search_end || search_end > code_size)
        return 0;
    if (search_end - search_start > 64U)
        search_end = search_start + 64U;
    for (size_t position = search_start;
         position + sizeof(uint32_t) <= search_end;
         position += sizeof(uint32_t)) {
        uint32_t instruction = dlfrz_glibc_read_u32(code + position);
        uint32_t immediate;
        int64_t displacement;
        uint64_t instruction_vaddr;
        uint64_t branch_vaddr;
        uint64_t hook_vaddr;

        if ((instruction & UINT32_C(0x7e000000)) ==
                UINT32_C(0x34000000)) {
            immediate = (instruction >> 5) & UINT32_C(0x7ffff);
        } else if ((instruction & UINT32_C(0xff000010)) ==
                       UINT32_C(0x54000000)) {
            immediate = (instruction >> 5) & UINT32_C(0x7ffff);
        } else {
            continue;
        }
        displacement = (int64_t)immediate;
        if (immediate & UINT32_C(0x40000))
            displacement -= INT64_C(0x80000);
        displacement *= INT64_C(4);
        if (code_vaddr > UINT64_MAX - position ||
            code_vaddr > UINT64_MAX - target_position)
            return 0;
        instruction_vaddr = code_vaddr + position;
        hook_vaddr = code_vaddr + target_position;
        if (!dlfrz_glibc_add_signed_u64(
                instruction_vaddr, displacement, &branch_vaddr))
            continue;
        if (branch_vaddr <= hook_vaddr &&
            hook_vaddr - branch_vaddr <= UINT64_C(32))
            return 1;
    }
    return 0;
}

static inline size_t
dlfrz_glibc_aarch64_dlfcn_member_matches(
    const unsigned char *code, size_t code_size, uint64_t code_vaddr,
    uint64_t glro_got_vaddr, int hook_offset, unsigned int expected_slot,
    size_t chain_limit,
    size_t *hook_position_out, size_t *slot_position_out)
{
    size_t completed = 0;

    /* An executable PT_LOAD may end in non-instruction data/padding. */
    if ((code_vaddr & 3U) != 0)
        return 0;
    for (size_t got_position = 0;
         got_position + sizeof(uint32_t) <= code_size;
         got_position += sizeof(uint32_t)) {
        size_t got_load_position = 0;
        unsigned int glro_register = 0;
        size_t hook_end;

        if (!dlfrz_glibc_aarch64_dlfcn_glro_load(
                code, code_size, code_vaddr, got_position,
                glro_got_vaddr, &got_load_position, &glro_register))
            continue;
        hook_end = code_size;
        if (chain_limit == 0)
            continue;
        if (hook_end - got_load_position > chain_limit)
            hook_end = got_load_position + chain_limit;
        for (size_t hook_position =
                 got_load_position + sizeof(uint32_t);
             hook_position + sizeof(uint32_t) <= hook_end;
             hook_position += sizeof(uint32_t)) {
            uint32_t hook_load =
                dlfrz_glibc_read_u32(code + hook_position);
            unsigned int hook_register;
            size_t slot_position = 0;
            size_t dispatches;

            if ((hook_load & UINT32_C(0xffc00000)) !=
                    UINT32_C(0xf9400000) ||
                ((hook_load >> 5) & 31U) != glro_register ||
                ((uint64_t)((hook_load >> 10) & UINT32_C(0xfff)) *
                 UINT64_C(8)) != (uint64_t)hook_offset)
                continue;
            if (hook_position > got_load_position + 48U &&
                !dlfrz_glibc_aarch64_dlfcn_branch_targets(
                    code, code_size, code_vaddr,
                    got_load_position + sizeof(uint32_t), hook_position))
                continue;
            hook_register = hook_load & 31U;
            dispatches = dlfrz_glibc_aarch64_dlfcn_slot_dispatches(
                code, code_size, hook_position + sizeof(uint32_t),
                hook_register, expected_slot, &slot_position);
            if (dispatches != 1)
                continue;
            completed++;
            if (hook_position_out)
                *hook_position_out = hook_position;
            if (slot_position_out)
                *slot_position_out = slot_position;
        }
    }
    return completed;
}

/* AArch64 counterpart of the hidden-member scan above.  The hook offset is
 * an exact immediate in one LDR, so enumerate those rare loads first and
 * prove each possible ADRP/LDR root only inside its preceding bounded chain
 * window. */
static inline int
dlfrz_glibc_aarch64_dlfcn_internal_matches(
    const unsigned char *code, size_t code_size, uint64_t code_vaddr,
    uint64_t glro_got_vaddr, int hook_offset,
    size_t matches[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U],
    size_t hook_positions[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U],
    size_t slot_positions[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U])
{
    const size_t internal_count = DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U;

    if (!matches || !hook_positions || !slot_positions)
        return 0;
    for (size_t i = 0; i < internal_count; i++) {
        matches[i] = 0;
        hook_positions[i] = 0;
        slot_positions[i] = 0;
    }
    /* Match the single-slot scanner: an unaligned executable region cannot
     * contain an AArch64 witness, but another well-formed PT_LOAD may. */
    if ((code_vaddr & 3U) != 0)
        return 1;
    if (!code || hook_offset < 0 ||
        (hook_offset & 7) != 0 || hook_offset > 4095 * 8)
        return 1;

    for (size_t hook_position = 0;
         hook_position + sizeof(uint32_t) <= code_size;
         hook_position += sizeof(uint32_t)) {
        uint32_t hook_load =
            dlfrz_glibc_read_u32(code + hook_position);
        unsigned int hook_register;
        size_t dispatches[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U];
        size_t dispatch_positions[
            DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U];
        size_t root_start;

        if ((hook_load & UINT32_C(0xffc00000)) !=
                UINT32_C(0xf9400000) ||
            ((uint64_t)((hook_load >> 10) & UINT32_C(0xfff)) *
             UINT64_C(8)) != (uint64_t)hook_offset)
            continue;
        hook_register = hook_load & 31U;
        dlfrz_glibc_aarch64_dlfcn_internal_slot_dispatches(
            code, code_size, hook_position + sizeof(uint32_t),
            hook_register, dispatches, dispatch_positions);

        /* The GOT LDR may be at most 28 bytes after its ADRP, and the hook
         * LDR's end must fit in the GOT load's 1024-byte chain window.  A
         * 1056-byte reverse envelope is therefore conservative; the exact
         * forward inequalities below decide admission. */
        root_start = hook_position > 1056U
            ? (hook_position - 1056U) & ~(size_t)3U : 0;
        for (size_t got_position = root_start;
             got_position + sizeof(uint32_t) <= hook_position;
             got_position += sizeof(uint32_t)) {
            size_t got_load_position = 0;
            unsigned int glro_register = 0;
            size_t hook_end;

            if (!dlfrz_glibc_aarch64_dlfcn_glro_load(
                    code, code_size, code_vaddr, got_position,
                    glro_got_vaddr, &got_load_position, &glro_register) ||
                ((hook_load >> 5) & 31U) != glro_register ||
                got_load_position + sizeof(uint32_t) > hook_position)
                continue;
            hook_end = code_size;
            if (hook_end - got_load_position > 1024U)
                hook_end = got_load_position + 1024U;
            if (hook_position + sizeof(uint32_t) > hook_end ||
                (hook_position - got_load_position > 48U &&
                 !dlfrz_glibc_aarch64_dlfcn_branch_targets(
                     code, code_size, code_vaddr,
                     got_load_position + sizeof(uint32_t),
                     hook_position)))
                continue;
            {
                for (size_t internal = 0; internal < internal_count;
                     internal++) {
                    if (dispatches[internal] != 1)
                        continue;
                    if (matches[internal] == SIZE_MAX)
                        return 0;
                    matches[internal]++;
                    hook_positions[internal] = hook_position;
                    slot_positions[internal] =
                        dispatch_positions[internal];
                }
            }
        }
    }
    return 1;
}

/* Return one unique exported libc implementation even though glibc exports
 * multiple symbol-version aliases for the same function body. */
static inline int
dlfrz_glibc_function_definition(const struct dlfrz_elf64_dyn_view *view,
                                const char *name,
                                Elf64_Sym *definition)
{
    Elf64_Sym matched = {0};
    int found = 0;

    for (uint32_t i = 0; i < view->dynsym_count; i++) {
        Elf64_Sym symbol;

        dlfrz_elf64_dyn_view_symbol(view, i, &symbol);
        if (!dlfrz_glibc_dynstr_name(
                view->elf + view->dynstr_offset, view->dynstr_size,
                symbol.st_name, name))
            continue;
        if (ELF64_ST_BIND(symbol.st_info) != STB_GLOBAL ||
            ELF64_ST_TYPE(symbol.st_info) != STT_FUNC ||
            ELF64_ST_VISIBILITY(symbol.st_other) != STV_DEFAULT ||
            symbol.st_shndx == SHN_UNDEF ||
            symbol.st_shndx >= SHN_LORESERVE || symbol.st_value == 0 ||
            symbol.st_size == 0 || symbol.st_size > 2048 ||
            (view->have_sysv_hash &&
             !dlfrz_elf64_sysv_hash_exports(view, name, i)) ||
            (view->have_gnu_hash &&
             !dlfrz_elf64_gnu_hash_exports(view, name, i)))
            return 0;
        if (found && (matched.st_value != symbol.st_value ||
                      matched.st_size != symbol.st_size))
            return 0;
        matched = symbol;
        found = 1;
    }
    if (!found ||
        !dlfrz_glibc_vaddr_executable_file_range(
            view->elf, view->elf_size, &view->ehdr,
            matched.st_value, matched.st_size))
        return 0;
    *definition = matched;
    return 1;
}

static inline const char *
dlfrz_glibc_dlfcn_public_name(unsigned int slot)
{
    static const char *const names[9] = {
        "dlopen", "dlclose", "dlsym", "dlvsym", "dlerror",
        "dladdr", "dladdr1", "dlinfo", "dlmopen"
    };

    return slot < sizeof(names) / sizeof(names[0]) ? names[slot] : NULL;
}

/* All public dlfcn witnesses have a distinct third byte except dladdr and
 * dladdr1.  Classify that bounded prefix before doing one exact string-table
 * comparison, so collecting the complete hook contract does not turn into
 * nine full dynsym scans. */
static inline int
dlfrz_glibc_dlfcn_public_name_slot(
    const struct dlfrz_elf64_dyn_view *view, uint32_t name_offset)
{
    const unsigned char *name;
    size_t remaining;
    int slot;

    if (!view || name_offset >= view->dynstr_size)
        return -1;
    name = view->elf + view->dynstr_offset + (size_t)name_offset;
    remaining = view->dynstr_size - (size_t)name_offset;
    if (remaining < 3 || name[0] != 'd' || name[1] != 'l')
        return -1;
    switch (name[2]) {
    case 'o': slot = 0; break;
    case 'c': slot = 1; break;
    case 's': slot = 2; break;
    case 'v': slot = 3; break;
    case 'e': slot = 4; break;
    case 'a':
        if (dlfrz_glibc_dynstr_name(
                view->elf + view->dynstr_offset, view->dynstr_size,
                name_offset, dlfrz_glibc_dlfcn_public_name(5)))
            return 5;
        slot = 6;
        break;
    case 'i': slot = 7; break;
    case 'm': slot = 8; break;
    default: return -1;
    }
    return dlfrz_glibc_dynstr_name(
               view->elf + view->dynstr_offset, view->dynstr_size,
               name_offset, dlfrz_glibc_dlfcn_public_name((unsigned)slot))
        ? slot : -1;
}

/* Collect the nine exported implementations in one bounded dynsym pass.
 * Per-name validity and version-alias uniqueness are identical to
 * dlfrz_glibc_function_definition(); only the repeated table traversal is
 * removed. */
static inline int
dlfrz_glibc_dlfcn_public_definitions(
    const struct dlfrz_elf64_dyn_view *view, Elf64_Sym definitions[9])
{
    unsigned int found = 0;

    if (!view || !definitions)
        return 0;
    memset(definitions, 0, 9U * sizeof(definitions[0]));
    for (uint32_t i = 0; i < view->dynsym_count; i++) {
        Elf64_Sym symbol;
        const char *name;
        int slot;

        dlfrz_elf64_dyn_view_symbol(view, i, &symbol);
        slot = dlfrz_glibc_dlfcn_public_name_slot(view, symbol.st_name);
        if (slot < 0)
            continue;
        name = dlfrz_glibc_dlfcn_public_name((unsigned int)slot);
        if (ELF64_ST_BIND(symbol.st_info) != STB_GLOBAL ||
            ELF64_ST_TYPE(symbol.st_info) != STT_FUNC ||
            ELF64_ST_VISIBILITY(symbol.st_other) != STV_DEFAULT ||
            symbol.st_shndx == SHN_UNDEF ||
            symbol.st_shndx >= SHN_LORESERVE || symbol.st_value == 0 ||
            symbol.st_size == 0 || symbol.st_size > 2048 ||
            (view->have_sysv_hash &&
             !dlfrz_elf64_sysv_hash_exports(view, name, i)) ||
            (view->have_gnu_hash &&
             !dlfrz_elf64_gnu_hash_exports(view, name, i)))
            return 0;
        if ((found & (1U << slot)) != 0 &&
            (definitions[slot].st_value != symbol.st_value ||
             definitions[slot].st_size != symbol.st_size))
            return 0;
        definitions[slot] = symbol;
        found |= 1U << slot;
    }
    if (found != (1U << 9) - 1U)
        return 0;
    for (unsigned int slot = 0; slot < 9U; slot++)
        if (!dlfrz_glibc_vaddr_executable_file_range(
                view->elf, view->elf_size, &view->ehdr,
                definitions[slot].st_value, definitions[slot].st_size))
            return 0;
    return 1;
}

static inline int
dlfrz_glibc_dlclose_definition(const struct dlfrz_elf64_dyn_view *view,
                               Elf64_Sym *definition)
{
    return dlfrz_glibc_function_definition(view, "dlclose", definition);
}

static inline int
dlfrz_glibc_glro_got_relocation(const struct dlfrz_elf64_dyn_view *view,
                                uint64_t *got_vaddr)
{
    Elf64_Phdr dynamic_phdr = {0};
    uint64_t rela_address = 0;
    uint64_t rela_size = 0;
    uint64_t rela_entry_size = 0;
    uint32_t glro_symbol_index = 0;
    unsigned int dynamic_count = 0;
    unsigned int rela_seen = 0, relasz_seen = 0, relaent_seen = 0;
    unsigned int glro_symbol_seen = 0, glro_relocation_seen = 0;
    int terminated = 0;
    size_t rela_offset;

    for (uint32_t i = 0; i < view->dynsym_count; i++) {
        Elf64_Sym symbol;

        dlfrz_elf64_dyn_view_symbol(view, i, &symbol);
        if (!dlfrz_glibc_dynstr_name(
                view->elf + view->dynstr_offset, view->dynstr_size,
                symbol.st_name, "_rtld_global_ro"))
            continue;
        if (++glro_symbol_seen != 1 || i == STN_UNDEF ||
            ELF64_ST_BIND(symbol.st_info) != STB_GLOBAL ||
            ELF64_ST_TYPE(symbol.st_info) != STT_OBJECT ||
            ELF64_ST_VISIBILITY(symbol.st_other) != STV_DEFAULT ||
            symbol.st_shndx != SHN_UNDEF || symbol.st_value != 0)
            return 0;
        glro_symbol_index = i;
    }
    if (glro_symbol_seen != 1)
        return 0;

    for (uint16_t i = 0; i < view->ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;

        if (!dlfrz_glibc_read_phdr(
                view->elf, view->elf_size, &view->ehdr, i, &phdr))
            return 0;
        if (phdr.p_type == PT_DYNAMIC) {
            if (++dynamic_count != 1)
                return 0;
            dynamic_phdr = phdr;
        }
    }
    if (dynamic_count != 1 || dynamic_phdr.p_filesz == 0 ||
        dynamic_phdr.p_filesz % sizeof(Elf64_Dyn) != 0 ||
        dynamic_phdr.p_offset > view->elf_size ||
        dynamic_phdr.p_filesz > view->elf_size - dynamic_phdr.p_offset)
        return 0;
    for (uint64_t position = 0; position < dynamic_phdr.p_filesz;
         position += sizeof(Elf64_Dyn)) {
        Elf64_Dyn dynamic;

        memcpy(&dynamic,
               view->elf + (size_t)dynamic_phdr.p_offset + (size_t)position,
               sizeof(dynamic));
        if (dynamic.d_tag == DT_NULL) {
            terminated = 1;
            break;
        }
        if (dynamic.d_tag == DT_RELA) {
            if (++rela_seen != 1)
                return 0;
            rela_address = dynamic.d_un.d_ptr;
        } else if (dynamic.d_tag == DT_RELASZ) {
            if (++relasz_seen != 1)
                return 0;
            rela_size = dynamic.d_un.d_val;
        } else if (dynamic.d_tag == DT_RELAENT) {
            if (++relaent_seen != 1)
                return 0;
            rela_entry_size = dynamic.d_un.d_val;
        }
    }
    if (!terminated || rela_seen != 1 || relasz_seen != 1 ||
        relaent_seen != 1 || rela_address == 0 || rela_size == 0 ||
        rela_entry_size != sizeof(Elf64_Rela) ||
        rela_size % sizeof(Elf64_Rela) != 0 || rela_size > SIZE_MAX ||
        !dlfrz_glibc_vaddr_file_range(
            view->elf, view->elf_size, &view->ehdr,
            rela_address, rela_size, &rela_offset))
        return 0;

    for (size_t position = 0; position < (size_t)rela_size;
         position += sizeof(Elf64_Rela)) {
        Elf64_Rela relocation;
        uint32_t symbol_index;
        uint32_t relocation_type;
        uint32_t expected_type = view->ehdr.e_machine == EM_X86_64
            ? R_X86_64_GLOB_DAT : R_AARCH64_GLOB_DAT;

        memcpy(&relocation, view->elf + rela_offset + position,
               sizeof(relocation));
        symbol_index = (uint32_t)ELF64_R_SYM(relocation.r_info);
        relocation_type = (uint32_t)ELF64_R_TYPE(relocation.r_info);
        if (symbol_index >= view->dynsym_count)
            return 0;
        if (symbol_index != glro_symbol_index)
            continue;
        if (++glro_relocation_seen != 1 ||
            relocation_type != expected_type || relocation.r_addend != 0 ||
            relocation.r_offset % sizeof(uint64_t) != 0 ||
            !dlfrz_glibc_vaddr_writable_mem_range(
                view->elf, view->elf_size, &view->ehdr,
                relocation.r_offset, sizeof(uint64_t)))
            return 0;
        *got_vaddr = relocation.r_offset;
    }
    return glro_relocation_seen == 1;
}

static inline int
dlfrz_glibc_dlfcn_public_definition_valid(
    const struct dlfrz_elf64_dyn_view *view, const Elf64_Sym *symbol,
    unsigned int slot, uint64_t glro_got_vaddr, int hook_offset,
    size_t *hook_file_offset_out, size_t *slot_file_offset_out)
{
    size_t function_offset;
    size_t hook_position = 0;
    size_t slot_position = 0;
    size_t matches;

    if (!symbol || slot >= DLFRZ_GLIBC_DLFCN_HOOK_SLOTS ||
        !dlfrz_glibc_vaddr_file_range(
            view->elf, view->elf_size, &view->ehdr,
            symbol->st_value, symbol->st_size, &function_offset))
        return 0;
    if (view->ehdr.e_machine == EM_X86_64) {
        matches = dlfrz_glibc_x86_dlfcn_member_matches(
            view->elf + function_offset, (size_t)symbol->st_size,
            symbol->st_value, glro_got_vaddr, hook_offset, slot,
            (size_t)symbol->st_size,
            &hook_position, &slot_position);
    } else if (view->ehdr.e_machine == EM_AARCH64) {
        matches = dlfrz_glibc_aarch64_dlfcn_member_matches(
            view->elf + function_offset, (size_t)symbol->st_size,
            symbol->st_value, glro_got_vaddr, hook_offset, slot,
            (size_t)symbol->st_size,
            &hook_position, &slot_position);
    } else {
        return 0;
    }
    if (matches != 1 || hook_position >= (size_t)symbol->st_size ||
        slot_position >= (size_t)symbol->st_size)
        return 0;
    *hook_file_offset_out = function_offset + hook_position;
    *slot_file_offset_out = function_offset + slot_position;
    return 1;
}

static inline int
dlfrz_glibc_dlfcn_public_member_valid(
    const struct dlfrz_elf64_dyn_view *view, const char *name,
    unsigned int slot, uint64_t glro_got_vaddr, int hook_offset,
    size_t *hook_file_offset_out, size_t *slot_file_offset_out)
{
    Elf64_Sym symbol;

    return dlfrz_glibc_function_definition(view, name, &symbol) &&
           dlfrz_glibc_dlfcn_public_definition_valid(
               view, &symbol, slot, glro_got_vaddr, hook_offset,
               hook_file_offset_out, slot_file_offset_out);
}

/* Installed libc strips the hidden __libc_dlopen_mode/__libc_dlsym/
 * __libc_dlvsym/__libc_dlclose symbol names.  Their target code remains a
 * verifiable contract: require exactly one executable-image dispatch for
 * each of slots 9--12, rooted through the unique _rtld_global_ro GOT
 * relocation and the already-proven hook field. */
static inline int
dlfrz_glibc_dlfcn_internal_member_valid(
    const struct dlfrz_elf64_dyn_view *view, unsigned int slot,
    uint64_t glro_got_vaddr, int hook_offset,
    size_t *hook_file_offset_out, size_t *slot_file_offset_out)
{
    size_t completed = 0;
    size_t selected_hook = 0;
    size_t selected_slot = 0;

    if (slot < 9U || slot >= DLFRZ_GLIBC_DLFCN_HOOK_SLOTS)
        return 0;
    for (uint16_t i = 0; i < view->ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        size_t hook_position = 0;
        size_t slot_position = 0;
        size_t matches;

        if (!dlfrz_glibc_read_phdr(
                view->elf, view->elf_size, &view->ehdr, i, &phdr))
            return 0;
        if (phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_X) ||
            phdr.p_filesz == 0)
            continue;
        if (phdr.p_filesz > SIZE_MAX || phdr.p_offset > view->elf_size ||
            (size_t)phdr.p_filesz > view->elf_size - (size_t)phdr.p_offset)
            return 0;
        if (view->ehdr.e_machine == EM_X86_64) {
            matches = dlfrz_glibc_x86_dlfcn_member_matches(
                view->elf + (size_t)phdr.p_offset,
                (size_t)phdr.p_filesz, phdr.p_vaddr,
                glro_got_vaddr, hook_offset, slot, 1024U,
                &hook_position, &slot_position);
        } else if (view->ehdr.e_machine == EM_AARCH64) {
            matches = dlfrz_glibc_aarch64_dlfcn_member_matches(
                view->elf + (size_t)phdr.p_offset,
                (size_t)phdr.p_filesz, phdr.p_vaddr,
                glro_got_vaddr, hook_offset, slot, 1024U,
                &hook_position, &slot_position);
        } else {
            return 0;
        }
        if (matches > 1 || completed > SIZE_MAX - matches)
            return 0;
        if (matches == 1) {
            selected_hook = (size_t)phdr.p_offset + hook_position;
            selected_slot = (size_t)phdr.p_offset + slot_position;
        }
        completed += matches;
    }
    if (completed != 1)
        return 0;
    *hook_file_offset_out = selected_hook;
    *slot_file_offset_out = selected_slot;
    return 1;
}

/* Validate all four stripped __libc_dl* consumers while traversing each
 * executable PT_LOAD only once.  Match counts remain independent: a missing
 * or duplicate witness for any one slot rejects the complete hook exactly as
 * the former four-pass validation did. */
static inline int
dlfrz_glibc_dlfcn_internal_members_valid(
    const struct dlfrz_elf64_dyn_view *view,
    uint64_t glro_got_vaddr, int hook_offset,
    size_t hook_file_offsets[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS],
    size_t slot_file_offsets[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS])
{
    const size_t internal_count = DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U;
    size_t completed[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U] = {0};
    size_t selected_hooks[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U] = {0};
    size_t selected_slots[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U] = {0};

    if (!view || !hook_file_offsets || !slot_file_offsets)
        return 0;
    for (uint16_t i = 0; i < view->ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        size_t matches[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U];
        size_t hook_positions[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U];
        size_t slot_positions[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U];
        int scanned;

        if (!dlfrz_glibc_read_phdr(
                view->elf, view->elf_size, &view->ehdr, i, &phdr))
            return 0;
        if (phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_X) ||
            phdr.p_filesz == 0)
            continue;
        if (phdr.p_filesz > SIZE_MAX || phdr.p_offset > view->elf_size ||
            (size_t)phdr.p_filesz >
                view->elf_size - (size_t)phdr.p_offset)
            return 0;
        if (view->ehdr.e_machine == EM_X86_64) {
            scanned = dlfrz_glibc_x86_dlfcn_internal_matches(
                view->elf + (size_t)phdr.p_offset,
                (size_t)phdr.p_filesz, phdr.p_vaddr,
                glro_got_vaddr, hook_offset, matches,
                hook_positions, slot_positions);
        } else if (view->ehdr.e_machine == EM_AARCH64) {
            scanned = dlfrz_glibc_aarch64_dlfcn_internal_matches(
                view->elf + (size_t)phdr.p_offset,
                (size_t)phdr.p_filesz, phdr.p_vaddr,
                glro_got_vaddr, hook_offset, matches,
                hook_positions, slot_positions);
        } else {
            return 0;
        }
        if (!scanned)
            return 0;
        for (size_t internal = 0; internal < internal_count; internal++) {
            if (matches[internal] > 1 ||
                completed[internal] > SIZE_MAX - matches[internal])
                return 0;
            if (matches[internal] == 1) {
                selected_hooks[internal] =
                    (size_t)phdr.p_offset + hook_positions[internal];
                selected_slots[internal] =
                    (size_t)phdr.p_offset + slot_positions[internal];
            }
            completed[internal] += matches[internal];
        }
    }
    for (size_t internal = 0; internal < internal_count; internal++) {
        size_t slot = 9U + internal;

        if (completed[internal] != 1)
            return 0;
        hook_file_offsets[slot] = selected_hooks[internal];
        slot_file_offsets[slot] = selected_slots[internal];
    }
    return 1;
}

/* Validate the complete 13-member private hook against the target libc.
 * A release/profile supplies only the candidate field displacement.  The
 * field is first independently proved by the tightly constrained dlclose
 * chain above, and every member position is then proved by its own target
 * consumer.  Any missing, duplicate, reordered, or independently patched
 * dispatch fails closed. */
static inline int
dlfrz_glibc_dlfcn_hook_consumer_valid(
    const void *data, size_t elf_size, int hook_offset,
    struct dlfrz_glibc_dlfcn_consumer_evidence *evidence)
{
    struct dlfrz_elf64_dyn_view view;
    struct dlfrz_glibc_dlfcn_consumer_evidence result;
    Elf64_Sym public_definitions[9];
    uint64_t glro_got_vaddr = 0;
    const char *soname;
    int strict_field_valid;

    memset(&result, 0, sizeof(result));
    if (hook_offset < 0 || (hook_offset & 7) != 0 ||
        !dlfrz_elf64_dyn_view_init(data, elf_size, &view) ||
        !view.have_soname)
        return 0;
    soname = (const char *)view.elf + view.dynstr_offset +
             (size_t)view.soname_offset;
    if (strcmp(soname, "libc.so.6") != 0 ||
        !dlfrz_glibc_dlfcn_public_definitions(
            &view, public_definitions) ||
        !dlfrz_glibc_glro_got_relocation(&view, &glro_got_vaddr))
        return 0;
    if (view.ehdr.e_machine == EM_X86_64) {
        strict_field_valid = dlfrz_glibc_x86_dlfcn_consumer(
            &view, &public_definitions[1], glro_got_vaddr,
            hook_offset, &result);
    } else if (view.ehdr.e_machine == EM_AARCH64) {
        strict_field_valid = dlfrz_glibc_aarch64_dlfcn_consumer(
            &view, &public_definitions[1], glro_got_vaddr,
            hook_offset, &result);
    } else {
        return 0;
    }
    if (!strict_field_valid)
        return 0;
    for (unsigned int slot = 0; slot < 9U; slot++) {
        if (!dlfrz_glibc_dlfcn_public_definition_valid(
                &view, &public_definitions[slot], slot,
                glro_got_vaddr, hook_offset,
                &result.hook_load_file_offsets[slot],
                &result.slot_load_file_offsets[slot]))
            return 0;
    }
    if (result.hook_load_file_offsets[1] !=
            result.hook_load_file_offset ||
        result.slot_load_file_offsets[1] != result.slot_load_file_offset)
        return 0;
    if (!dlfrz_glibc_dlfcn_internal_members_valid(
            &view, glro_got_vaddr, hook_offset,
            result.hook_load_file_offsets,
            result.slot_load_file_offsets))
        return 0;
    if (evidence)
        memcpy(evidence, &result, sizeof(result));
    return 1;
}

/* Identify glibc from bounded ABI structures only.  Both private rtld
 * objects must be defined, writable GLOBAL/DEFAULT dynamic symbols and both
 * must be versioned GLIBC_PRIVATE.  This deliberately does not inspect the
 * interpreter basename or release prose, so downstream-renamed and
 * byte-identical vendor loaders retain their runtime family. */
static inline int
dlfrz_glibc_rtld_identity(const void *data, size_t elf_size,
                          struct dlfrz_glibc_rtld_identity *identity_out)
{
    const unsigned char *elf = (const unsigned char *)data;
    struct dlfrz_glibc_rtld_identity identity = {0};
    Elf64_Ehdr ehdr;
    Elf64_Phdr dynamic_phdr = {0};
    uint64_t symtab_address = 0, strtab_address = 0, strtab_size = 0;
    uint64_t syment = 0, sysv_hash_address = 0, gnu_hash_address = 0;
    uint64_t versym_address = 0, verdef_address = 0, verdef_count = 0;
    int have_symtab = 0, have_strtab = 0, have_strsz = 0, have_syment = 0;
    int have_sysv_hash = 0, have_gnu_hash = 0, have_versym = 0;
    int have_verdef = 0, have_verdef_count = 0;
    int dynamic_found = 0, load_found = 0, terminated = 0;
    size_t symtab_offset;
    size_t symtab_available;
    size_t strtab_offset;
    size_t symbol_bytes;
    size_t versym_offset;
    uint32_t max_symbols;
    uint32_t sysv_count = 0, gnu_count = 0, symbol_count = 0;
    uint32_t global_index = 0, global_ro_index = 0;
    int global_found = 0, global_ro_found = 0;

    /* The shared view proves that these are actual hash-exported dynamic
     * definitions before the glibc-specific layout facts below are read. */
    {
        struct dlfrz_elf64_dyn_view view;
        Elf64_Sym global_symbol;
        Elf64_Sym global_ro_symbol;
        uint32_t view_global_index;
        uint32_t view_global_ro_index;
        uint16_t global_version;
        uint16_t global_ro_version;

        if (!dlfrz_elf64_dyn_view_init(data, elf_size, &view) ||
            dlfrz_elf64_dyn_view_find(
                &view, "_rtld_global", &global_symbol,
                &view_global_index) != 1 ||
            dlfrz_elf64_dyn_view_find(
                &view, "_rtld_global_ro", &global_ro_symbol,
                &view_global_ro_index) != 1 ||
            ELF64_ST_BIND(global_symbol.st_info) != STB_GLOBAL ||
            ELF64_ST_BIND(global_ro_symbol.st_info) != STB_GLOBAL ||
            ELF64_ST_TYPE(global_symbol.st_info) != STT_OBJECT ||
            ELF64_ST_TYPE(global_ro_symbol.st_info) != STT_OBJECT ||
            ELF64_ST_VISIBILITY(global_symbol.st_other) != STV_DEFAULT ||
            ELF64_ST_VISIBILITY(global_ro_symbol.st_other) != STV_DEFAULT ||
            global_symbol.st_shndx == SHN_UNDEF ||
            global_ro_symbol.st_shndx == SHN_UNDEF ||
            global_symbol.st_shndx >= SHN_LORESERVE ||
            global_ro_symbol.st_shndx >= SHN_LORESERVE ||
            global_symbol.st_value == 0 || global_symbol.st_size == 0 ||
            global_ro_symbol.st_value == 0 ||
            global_ro_symbol.st_size == 0 || view.has_interp ||
            !view.have_versym ||
            !view.have_verdef ||
            !dlfrz_glibc_vaddr_writable_mem_range(
                view.elf, view.elf_size, &view.ehdr,
                global_symbol.st_value, global_symbol.st_size) ||
            !dlfrz_glibc_vaddr_writable_mem_range(
                view.elf, view.elf_size, &view.ehdr,
                global_ro_symbol.st_value, global_ro_symbol.st_size))
            return 0;
        memcpy(&global_version,
               view.elf + view.versym_offset +
                   (size_t)view_global_index * sizeof(global_version),
               sizeof(global_version));
        memcpy(&global_ro_version,
               view.elf + view.versym_offset +
                   (size_t)view_global_ro_index * sizeof(global_ro_version),
               sizeof(global_ro_version));
        if ((global_version & UINT16_C(0x8000)) != 0 ||
            (global_ro_version & UINT16_C(0x8000)) != 0)
            return 0;
        global_version &= UINT16_C(0x7fff);
        global_ro_version &= UINT16_C(0x7fff);
        if (global_version != global_ro_version ||
            !dlfrz_glibc_version_is_private(
                view.elf, view.elf_size, &view.ehdr,
                view.elf + view.dynstr_offset, view.dynstr_size,
                view.verdef_address, view.verdef_count, global_version))
            return 0;
    }

    if (!elf || elf_size < sizeof(ehdr))
        return 0;
    memcpy(&ehdr, elf, sizeof(ehdr));
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr.e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr.e_ident[EI_VERSION] != EV_CURRENT ||
        ehdr.e_version != EV_CURRENT || ehdr.e_type != ET_DYN ||
        (ehdr.e_machine != EM_X86_64 && ehdr.e_machine != EM_AARCH64) ||
        ehdr.e_ehsize != sizeof(ehdr) ||
        ehdr.e_phentsize != sizeof(Elf64_Phdr) || ehdr.e_phnum == 0 ||
        ehdr.e_phnum == PN_XNUM || ehdr.e_phoff > elf_size ||
        (size_t)ehdr.e_phnum >
            (elf_size - (size_t)ehdr.e_phoff) / sizeof(Elf64_Phdr))
        return 0;

    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;

        if (!dlfrz_glibc_read_phdr(elf, elf_size, &ehdr, i, &phdr) ||
            phdr.p_filesz > phdr.p_memsz || phdr.p_offset > elf_size ||
            phdr.p_filesz > (uint64_t)elf_size - phdr.p_offset ||
            phdr.p_vaddr > UINT64_MAX - phdr.p_memsz)
            return 0;
        if (phdr.p_type == PT_LOAD)
            load_found = 1;
        if (phdr.p_type != PT_DYNAMIC)
            continue;
        if (dynamic_found || phdr.p_filesz == 0 ||
            phdr.p_filesz % sizeof(Elf64_Dyn) != 0)
            return 0;
        dynamic_phdr = phdr;
        dynamic_found = 1;
    }
    if (!load_found || !dynamic_found ||
        !dlfrz_glibc_vaddr_file_range(
            elf, elf_size, &ehdr, dynamic_phdr.p_vaddr,
            dynamic_phdr.p_filesz, &symtab_offset) ||
        symtab_offset != (size_t)dynamic_phdr.p_offset)
        return 0;

    for (uint64_t pos = 0; pos < dynamic_phdr.p_filesz;
         pos += sizeof(Elf64_Dyn)) {
        Elf64_Dyn dynamic;
        size_t offset = (size_t)dynamic_phdr.p_offset + (size_t)pos;

        memcpy(&dynamic, elf + offset, sizeof(dynamic));
        if (dynamic.d_tag == DT_NULL) {
            terminated = 1;
            break;
        }
#define DLFRZ_GLIBC_IDENTITY_DYNAMIC(tag, seen, slot)                      \
        case tag:                                                          \
            if (!dlfrz_glibc_dynamic_value(                                \
                    &(seen), &(slot), dynamic.d_un.d_val))                 \
                return 0;                                                   \
            break
        switch (dynamic.d_tag) {
        DLFRZ_GLIBC_IDENTITY_DYNAMIC(DT_SYMTAB, have_symtab,
                                     symtab_address);
        DLFRZ_GLIBC_IDENTITY_DYNAMIC(DT_STRTAB, have_strtab,
                                     strtab_address);
        DLFRZ_GLIBC_IDENTITY_DYNAMIC(DT_STRSZ, have_strsz, strtab_size);
        DLFRZ_GLIBC_IDENTITY_DYNAMIC(DT_SYMENT, have_syment, syment);
        DLFRZ_GLIBC_IDENTITY_DYNAMIC(DT_HASH, have_sysv_hash,
                                     sysv_hash_address);
        DLFRZ_GLIBC_IDENTITY_DYNAMIC(DT_GNU_HASH, have_gnu_hash,
                                     gnu_hash_address);
        DLFRZ_GLIBC_IDENTITY_DYNAMIC(DT_VERSYM, have_versym,
                                     versym_address);
        DLFRZ_GLIBC_IDENTITY_DYNAMIC(DT_VERDEF, have_verdef,
                                     verdef_address);
        DLFRZ_GLIBC_IDENTITY_DYNAMIC(DT_VERDEFNUM, have_verdef_count,
                                     verdef_count);
        default:
            break;
        }
#undef DLFRZ_GLIBC_IDENTITY_DYNAMIC
    }
    if (!terminated || !have_symtab || !have_strtab || !have_strsz ||
        !have_syment || !have_versym || !have_verdef ||
        !have_verdef_count || (!have_sysv_hash && !have_gnu_hash) ||
        symtab_address == 0 || strtab_address == 0 ||
        strtab_size == 0 || strtab_size > SIZE_MAX ||
        syment != sizeof(Elf64_Sym) || verdef_count == 0 ||
        !dlfrz_glibc_vaddr_file_range(
            elf, elf_size, &ehdr, strtab_address, strtab_size,
            &strtab_offset) || elf[strtab_offset] != '\0' ||
        elf[strtab_offset + (size_t)strtab_size - 1] != '\0' ||
        !dlfrz_glibc_vaddr_file_available(
            elf, elf_size, &ehdr, symtab_address, &symtab_offset,
            &symtab_available))
        return 0;
    if (symtab_available / sizeof(Elf64_Sym) > UINT32_MAX)
        max_symbols = UINT32_MAX;
    else
        max_symbols =
            (uint32_t)(symtab_available / sizeof(Elf64_Sym));
    if (max_symbols == 0)
        return 0;

    if (have_sysv_hash &&
        !dlfrz_glibc_sysv_symbol_count(
            elf, elf_size, &ehdr, sysv_hash_address, max_symbols,
            &sysv_count))
        return 0;
    if (have_gnu_hash &&
        !dlfrz_glibc_gnu_symbol_count(
            elf, elf_size, &ehdr, gnu_hash_address, max_symbols,
            &gnu_count))
        return 0;
    if (have_sysv_hash) {
        if (have_gnu_hash && gnu_count != sysv_count)
            return 0;
        symbol_count = sysv_count;
    } else if (have_gnu_hash) {
        symbol_count = gnu_count;
    }
    if (symbol_count == 0 || symbol_count > max_symbols ||
        !dlfrz_glibc_size_mul(symbol_count, sizeof(Elf64_Sym),
                              &symbol_bytes) ||
        !dlfrz_glibc_vaddr_file_range(
            elf, elf_size, &ehdr, symtab_address, symbol_bytes,
            &symtab_offset) ||
        !dlfrz_glibc_size_mul(symbol_count, sizeof(uint16_t),
                              &symbol_bytes) ||
        !dlfrz_glibc_vaddr_file_range(
            elf, elf_size, &ehdr, versym_address, symbol_bytes,
            &versym_offset))
        return 0;

    for (uint32_t i = 0; i < symbol_count; i++) {
        Elf64_Sym symbol;
        int is_global;
        int is_global_ro;

        memcpy(&symbol,
               elf + symtab_offset + (size_t)i * sizeof(symbol),
               sizeof(symbol));
        if (symbol.st_name >= strtab_size)
            return 0;
        is_global = dlfrz_glibc_dynstr_name(
            elf + strtab_offset, (size_t)strtab_size, symbol.st_name,
            "_rtld_global");
        is_global_ro = dlfrz_glibc_dynstr_name(
            elf + strtab_offset, (size_t)strtab_size, symbol.st_name,
            "_rtld_global_ro");
        if (!is_global && !is_global_ro)
            continue;
        if (ELF64_ST_BIND(symbol.st_info) != STB_GLOBAL ||
            ELF64_ST_TYPE(symbol.st_info) != STT_OBJECT ||
            ELF64_ST_VISIBILITY(symbol.st_other) != STV_DEFAULT ||
            symbol.st_shndx == SHN_UNDEF ||
            symbol.st_shndx >= SHN_LORESERVE || symbol.st_value == 0 ||
            symbol.st_size == 0 ||
            !dlfrz_glibc_vaddr_writable_mem_range(
                elf, elf_size, &ehdr, symbol.st_value, symbol.st_size))
            return 0;
        if (is_global) {
            if (global_found)
                return 0;
            global_found = 1;
            global_index = i;
            identity.global_vaddr = symbol.st_value;
            identity.global_size = symbol.st_size;
        } else {
            if (global_ro_found)
                return 0;
            global_ro_found = 1;
            global_ro_index = i;
            identity.global_ro_vaddr = symbol.st_value;
            identity.global_ro_size = symbol.st_size;
        }
    }
    if (!global_found || !global_ro_found)
        return 0;
    {
        uint16_t global_version;
        uint16_t global_ro_version;

        memcpy(&global_version,
               elf + versym_offset +
                   (size_t)global_index * sizeof(global_version),
               sizeof(global_version));
        memcpy(&global_ro_version,
               elf + versym_offset +
                   (size_t)global_ro_index * sizeof(global_ro_version),
               sizeof(global_ro_version));
        if ((global_version & UINT16_C(0x8000)) != 0 ||
            (global_ro_version & UINT16_C(0x8000)) != 0)
            return 0;
        global_version &= UINT16_C(0x7fff);
        global_ro_version &= UINT16_C(0x7fff);
        if (!dlfrz_glibc_version_is_private(
                elf, elf_size, &ehdr, elf + strtab_offset,
                (size_t)strtab_size, verdef_address, verdef_count,
                global_version) ||
            (global_ro_version != global_version &&
             !dlfrz_glibc_version_is_private(
                 elf, elf_size, &ehdr, elf + strtab_offset,
                 (size_t)strtab_size, verdef_address, verdef_count,
                 global_ro_version)))
            return 0;
    }
    identity.machine = ehdr.e_machine;
    if (identity_out)
        *identity_out = identity;
    return 1;
}

/* x86-64 libc IFUNC resolvers consume a private struct cpu_features inside
 * _rtld_global_ro.  A release number and the total GLRO size do not prove
 * that structure's position or member layout.  Keep the candidate layouts
 * here, but admit one only when the embedded interpreter's exported accessor,
 * adjacent hidden initialization wrapper, and actual initializer writes all
 * agree with it. */
struct dlfrz_glibc_x86_cpu_layout {
    unsigned int feature_count;
    uint64_t object_size;
    int preferred;
    int isa_1;
    int xsave_state_size;
    int xsave_state_full_size;
    int data_cache_size;
    int shared_cache_size;
    int non_temporal_threshold;
    int memset_non_temporal_threshold;
    int rep_movsb_threshold;
    int rep_movsb_stop_threshold;
    int rep_stosb_threshold;
    int level1_icache_size;
    int level1_icache_linesize;
    int level1_dcache_size;
    int level1_dcache_assoc;
    int level1_dcache_linesize;
    int level2_cache_size;
    int level2_cache_assoc;
    int level2_cache_linesize;
    int level3_cache_size;
    int level3_cache_assoc;
    int level3_cache_linesize;
    int level4_cache_size;
    int cachesize_non_temporal_divisor;
};

/* Some releases genuinely omit a member rather than placing it at a
 * different offset.  Keep that state distinct from every valid byte offset
 * so callers cannot accidentally reinterpret the next member as the absent
 * one. */
#define DLFRZ_GLIBC_X86_CPU_FIELD_ABSENT (-1)
#define DLFRZ_GLIBC_X86_CPU_CACHE_INFO_WORDS 12U
#define DLFRZ_GLIBC_X86_CPU_END_WRITERS_MAX 16U

struct dlfrz_glibc_x86_cpu_contract {
    struct dlfrz_glibc_x86_cpu_layout layout;
    uint64_t cpu_features_offset;
    uint64_t wrapper_vaddr;
    uint64_t initializer_vaddr;
    uint64_t published_prefix_size;
    uint64_t cache_info_offset;
    uint32_t cache_info_word_count;
    uint32_t generic_kind;
};

struct dlfrz_glibc_getauxval_contract {
    uint64_t hwcap_offset;
    uint64_t hwcap2_offset;
};

struct dlfrz_glibc_x86_cpu_evidence {
    size_t accessor_displacement_file_offset;
    size_t wrapper_displacement_file_offset;
    size_t layout_write_displacement_file_offset;
    size_t generic_kind_immediate_file_offset;
    size_t tail_boundary_displacement_file_offset;
    size_t cache_info_displacement_file_offsets[
        DLFRZ_GLIBC_X86_CPU_CACHE_INFO_WORDS];
    size_t object_end_displacement_file_offsets[
        DLFRZ_GLIBC_X86_CPU_END_WRITERS_MAX];
    size_t object_end_displacement_count;
};

struct dlfrz_glibc_x86_getauxval_evidence {
    size_t glro_displacement_file_offset;
    size_t hwcap2_displacement_file_offset;
};

struct dlfrz_glibc_aarch64_getauxval_evidence {
    size_t dispatcher_file_offset;
    size_t branch_file_offsets[2];
    size_t adrp_file_offsets[2];
    size_t got_load_file_offsets[2];
    size_t field_load_file_offsets[2];
    size_t restore_file_offsets[2];
};

struct dlfrz_glibc_x86_rip_write {
    uint64_t target_vaddr;
    size_t width;
    size_t length;
    size_t displacement_offset;
};

static inline int
dlfrz_glibc_x86_cpu_layout_profile(
    enum dlfrz_glibc_layout_id layout, int minor,
    struct dlfrz_glibc_x86_cpu_layout *profile_out)
{
    struct dlfrz_glibc_x86_cpu_layout profile;

    switch (layout) {
    case DLFRZ_GLIBC_X86_2_34:
    case DLFRZ_GLIBC_X86_RTLD_896_4336:
    case DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY:
    case DLFRZ_GLIBC_X86_2_40:
    case DLFRZ_GLIBC_X86_2_44:
    case DLFRZ_GLIBC_X86_RTLD_952_2888:
        break;
    case DLFRZ_GLIBC_X86_2_17:
    case DLFRZ_GLIBC_X86_2_29:
    case DLFRZ_GLIBC_X86_RTLD_544_4000:
    case DLFRZ_GLIBC_AARCH64_2_27:
    case DLFRZ_GLIBC_AARCH64_2_31:
    case DLFRZ_GLIBC_AARCH64_2_35_LARGE:
    case DLFRZ_GLIBC_AARCH64_RTLD_672_4520:
    case DLFRZ_GLIBC_AARCH64_2_35:
    case DLFRZ_GLIBC_AARCH64_2_43:
    case DLFRZ_GLIBC_AARCH64_2_44:
    case DLFRZ_GLIBC_AARCH64_2_40_LEGACY:
    case DLFRZ_GLIBC_AARCH64_2_41:
    case DLFRZ_GLIBC_LAYOUT_UNKNOWN:
        return 0;
    }

    if (minor >= 34 && minor <= 38) {
        profile = (struct dlfrz_glibc_x86_cpu_layout){
            .feature_count = 9,
            .object_size = minor == 38 ? 488 : 480,
            .preferred = 308,
            .isa_1 = 312,
            .xsave_state_size = 320,
            .xsave_state_full_size = 328,
            .data_cache_size = 336,
            .shared_cache_size = 344,
            .non_temporal_threshold = 352,
            .memset_non_temporal_threshold =
                DLFRZ_GLIBC_X86_CPU_FIELD_ABSENT,
            .rep_movsb_threshold = 360,
            .rep_movsb_stop_threshold = 368,
            .rep_stosb_threshold = 376,
            .level1_icache_size = 384,
            .level1_icache_linesize = 392,
            .level1_dcache_size = 400,
            .level1_dcache_assoc = 408,
            .level1_dcache_linesize = 416,
            .level2_cache_size = 424,
            .level2_cache_assoc = 432,
            .level2_cache_linesize = 440,
            .level3_cache_size = 448,
            .level3_cache_assoc = 456,
            .level3_cache_linesize = 464,
            .level4_cache_size = 472,
            .cachesize_non_temporal_divisor =
                minor == 38 ? 480 : DLFRZ_GLIBC_X86_CPU_FIELD_ABSENT,
        };
    } else if (minor == 39) {
        profile = (struct dlfrz_glibc_x86_cpu_layout){
            .feature_count = 10,
            .object_size = 520,
            .preferred = 340,
            .isa_1 = 344,
            .xsave_state_size = 352,
            .xsave_state_full_size = 360,
            .data_cache_size = 368,
            .shared_cache_size = 376,
            .non_temporal_threshold = 384,
            .memset_non_temporal_threshold =
                DLFRZ_GLIBC_X86_CPU_FIELD_ABSENT,
            .rep_movsb_threshold = 392,
            .rep_movsb_stop_threshold = 400,
            .rep_stosb_threshold = 408,
            .level1_icache_size = 416,
            .level1_icache_linesize = 424,
            .level1_dcache_size = 432,
            .level1_dcache_assoc = 440,
            .level1_dcache_linesize = 448,
            .level2_cache_size = 456,
            .level2_cache_assoc = 464,
            .level2_cache_linesize = 472,
            .level3_cache_size = 480,
            .level3_cache_assoc = 488,
            .level3_cache_linesize = 496,
            .level4_cache_size = 504,
            .cachesize_non_temporal_divisor = 512,
        };
    } else if (minor >= 40 && minor <= 44) {
        profile = (struct dlfrz_glibc_x86_cpu_layout){
            .feature_count = 10,
            .object_size = 528,
            .preferred = 340,
            .isa_1 = 344,
            .xsave_state_size = 352,
            .xsave_state_full_size = 360,
            .data_cache_size = 368,
            .shared_cache_size = 376,
            .non_temporal_threshold = 384,
            .memset_non_temporal_threshold = 392,
            .rep_movsb_threshold = 400,
            .rep_movsb_stop_threshold = 408,
            .rep_stosb_threshold = 416,
            .level1_icache_size = 424,
            .level1_icache_linesize = 432,
            .level1_dcache_size = 440,
            .level1_dcache_assoc = 448,
            .level1_dcache_linesize = 456,
            .level2_cache_size = 464,
            .level2_cache_assoc = 472,
            .level2_cache_linesize = 480,
            .level3_cache_size = 488,
            .level3_cache_assoc = 496,
            .level3_cache_linesize = 504,
            .level4_cache_size = 512,
            .cachesize_non_temporal_divisor = 520,
        };
    } else {
        return 0;
    }
    if (profile_out)
        *profile_out = profile;
    return 1;
}

/* The cache-information tail is not otherwise consumed by dlfreeze, but it
 * is part of glibc's private cpu_features object and is read by public
 * sysconf queries.  Bound the complete release-profiled object, rather than
 * stopping at the last threshold that dlfreeze writes. */
static inline int
dlfrz_glibc_x86_cpu_object_fits(
    const struct dlfrz_glibc_x86_cpu_layout *layout,
    uint64_t cpu_features_offset, uint64_t glro_size)
{
    return layout && layout->object_size != 0 &&
           cpu_features_offset <= glro_size &&
           layout->object_size <= glro_size - cpu_features_offset;
}

/* Prove that the release profile describes the complete pointer-free scalar
 * object, not merely the fields currently used by IFUNC selection.  The
 * fixed prefix is cpu_features_basic (five uint32_t words), followed by
 * feature_count entries containing two four-uint32_t arrays, one preferred
 * uint32_t, isa_1, the two XSAVE scalars, the threshold scalars, and the
 * cache-information tail.  Known alignment holes are zero because the
 * isolated child initializes the complete object from zero. */
static inline int
dlfrz_glibc_x86_cpu_object_profile_complete(
    const struct dlfrz_glibc_x86_cpu_layout *layout)
{
    uint64_t threshold;
    uint64_t cache_start;

    if (!layout || layout->feature_count < 9 ||
        layout->feature_count > 10 ||
        layout->preferred !=
            20 + (int)layout->feature_count * 32 ||
        layout->isa_1 != layout->preferred + 4 ||
        layout->xsave_state_size != layout->isa_1 + 8 ||
        layout->xsave_state_full_size !=
            layout->xsave_state_size + 8 ||
        layout->data_cache_size !=
            layout->xsave_state_full_size + 8 ||
        layout->shared_cache_size != layout->data_cache_size + 8 ||
        layout->non_temporal_threshold !=
            layout->shared_cache_size + 8)
        return 0;
    threshold = (uint64_t)layout->non_temporal_threshold + 8;
    if (layout->memset_non_temporal_threshold !=
            DLFRZ_GLIBC_X86_CPU_FIELD_ABSENT) {
        if (layout->memset_non_temporal_threshold < 0 ||
            (uint64_t)layout->memset_non_temporal_threshold != threshold)
            return 0;
        threshold += 8;
    }
    if (layout->rep_movsb_threshold < 0 ||
        (uint64_t)layout->rep_movsb_threshold != threshold ||
        layout->rep_movsb_stop_threshold !=
            layout->rep_movsb_threshold + 8 ||
        layout->rep_stosb_threshold !=
            layout->rep_movsb_stop_threshold + 8)
        return 0;
    cache_start = (uint64_t)layout->rep_stosb_threshold + 8;
    if (layout->level1_icache_size < 0 ||
        (uint64_t)layout->level1_icache_size != cache_start ||
        layout->level1_icache_linesize !=
            layout->level1_icache_size + 8 ||
        layout->level1_dcache_size !=
            layout->level1_icache_linesize + 8 ||
        layout->level1_dcache_assoc !=
            layout->level1_dcache_size + 8 ||
        layout->level1_dcache_linesize !=
            layout->level1_dcache_assoc + 8 ||
        layout->level2_cache_size !=
            layout->level1_dcache_linesize + 8 ||
        layout->level2_cache_assoc != layout->level2_cache_size + 8 ||
        layout->level2_cache_linesize !=
            layout->level2_cache_assoc + 8 ||
        layout->level3_cache_size !=
            layout->level2_cache_linesize + 8 ||
        layout->level3_cache_assoc != layout->level3_cache_size + 8 ||
        layout->level3_cache_linesize !=
            layout->level3_cache_assoc + 8 ||
        layout->level4_cache_size !=
            layout->level3_cache_linesize + 8)
        return 0;
    cache_start +=
        DLFRZ_GLIBC_X86_CPU_CACHE_INFO_WORDS * UINT64_C(8);
    if (layout->cachesize_non_temporal_divisor ==
            DLFRZ_GLIBC_X86_CPU_FIELD_ABSENT)
        return cache_start == layout->object_size;
    return layout->cachesize_non_temporal_divisor >= 0 &&
           (uint64_t)layout->cachesize_non_temporal_divisor == cache_start &&
           cache_start <= UINT64_MAX - 8 &&
           cache_start + 8 == layout->object_size;
}

/* Decode the bounded RIP-relative memory-destination forms emitted by the
 * supported glibc CPU initializers.  This is deliberately not a general x86
 * decoder: an unrecognized compiler form is absence of ABI evidence. */
static inline int
dlfrz_glibc_x86_rip_write(const unsigned char *bytes, size_t available,
                          uint64_t instruction_vaddr,
                          struct dlfrz_glibc_x86_rip_write *write)
{
    size_t cursor = 0;
    unsigned int legacy = 0;
    unsigned int rex = 0;
    unsigned int opcode;
    unsigned int modrm;
    size_t displacement_offset;
    size_t immediate_size = 0;
    size_t width = 0;
    int32_t displacement;
    uint64_t next_vaddr;
    uint64_t target_vaddr;

    if (!bytes || !write)
        return 0;
    if (cursor < available &&
        (bytes[cursor] == UINT8_C(0x66) ||
         bytes[cursor] == UINT8_C(0xf2) ||
         bytes[cursor] == UINT8_C(0xf3)))
        legacy = bytes[cursor++];
    if (cursor < available && bytes[cursor] >= UINT8_C(0x40) &&
        bytes[cursor] <= UINT8_C(0x4f))
        rex = bytes[cursor++];
    if (cursor >= available)
        return 0;
    opcode = bytes[cursor++];

    if (!legacy &&
        (opcode == UINT8_C(0x89) || opcode == UINT8_C(0xc7) ||
         opcode == UINT8_C(0x81) || opcode == UINT8_C(0x83))) {
        if (cursor >= available)
            return 0;
        modrm = bytes[cursor++];
        if ((modrm & UINT8_C(0xc7)) != UINT8_C(0x05))
            return 0;
        if (opcode == UINT8_C(0xc7) &&
            ((modrm >> 3) & 7U) != 0U)
            return 0;
        if ((opcode == UINT8_C(0x81) || opcode == UINT8_C(0x83)) &&
            ((modrm >> 3) & 7U) == 7U)
            return 0; /* cmp does not write its memory operand */
        width = (rex & UINT8_C(0x08)) ? 8U : 4U;
        if (opcode == UINT8_C(0xc7) || opcode == UINT8_C(0x81))
            immediate_size = 4;
        else if (opcode == UINT8_C(0x83))
            immediate_size = 1;
    } else if (opcode == UINT8_C(0x0f)) {
        unsigned int second;

        if (cursor >= available)
            return 0;
        second = bytes[cursor++];
        if (cursor >= available)
            return 0;
        modrm = bytes[cursor++];
        if ((modrm & UINT8_C(0xc7)) != UINT8_C(0x05))
            return 0;
        if (second == UINT8_C(0x11)) {
            if (legacy == UINT8_C(0xf2))
                width = 8;  /* movsd */
            else if (legacy == UINT8_C(0xf3))
                width = 4;  /* movss */
            else if (!legacy || legacy == UINT8_C(0x66))
                width = 16; /* movups/movupd */
            else
                return 0;
        } else if (second == UINT8_C(0x29)) {
            if (!legacy || legacy == UINT8_C(0x66))
                width = 16; /* movaps/movapd */
            else
                return 0;
        } else if (second == UINT8_C(0x7f) &&
                   (legacy == UINT8_C(0x66) ||
                    legacy == UINT8_C(0xf3))) {
            width = 16;
        } else if (second == UINT8_C(0xd6) &&
                   legacy == UINT8_C(0x66)) {
            width = 8;
        } else if (second == UINT8_C(0x7e) &&
                   legacy == UINT8_C(0x66)) {
            width = (rex & UINT8_C(0x08)) ? 8U : 4U;
        } else {
            return 0;
        }
    } else {
        return 0;
    }

    displacement_offset = cursor;
    if (available < cursor + sizeof(displacement) + immediate_size)
        return 0;
    memcpy(&displacement, bytes + cursor, sizeof(displacement));
    cursor += sizeof(displacement) + immediate_size;
    if (instruction_vaddr > UINT64_MAX - cursor)
        return 0;
    next_vaddr = instruction_vaddr + cursor;
    if (!dlfrz_glibc_add_signed_u64(
            next_vaddr, displacement, &target_vaddr))
        return 0;
    write->target_vaddr = target_vaddr;
    write->width = width;
    write->length = cursor;
    write->displacement_offset = displacement_offset;
    return 1;
}

struct dlfrz_glibc_x86_instruction {
    size_t length;
    int direct_branch;
    int conditional_branch;
    int direct_call;
    int terminal;
    int64_t branch_displacement;
    int immediate_register;
    unsigned int register_number;
    uint32_t immediate;
    size_t immediate_offset;
    int rip_store_register;
    int32_t rip_displacement;
};

enum dlfrz_glibc_x86_instruction_state {
    DLFRZ_X86_INSN_START = 1,
    DLFRZ_X86_INSN_INTERIOR = 2,
    DLFRZ_X86_INSN_QUEUED = 4,
    DLFRZ_X86_INSN_DECODED = 8
};

static inline int
dlfrz_glibc_x86_legacy_prefix(unsigned char byte)
{
    return byte == UINT8_C(0xf0) || byte == UINT8_C(0xf2) ||
           byte == UINT8_C(0xf3) || byte == UINT8_C(0x2e) ||
           byte == UINT8_C(0x36) || byte == UINT8_C(0x3e) ||
           byte == UINT8_C(0x26) || byte == UINT8_C(0x64) ||
           byte == UINT8_C(0x65) || byte == UINT8_C(0x66) ||
           byte == UINT8_C(0x67);
}

static inline int
dlfrz_glibc_x86_modrm_end(const unsigned char *bytes, size_t available,
                          size_t modrm_position, size_t *end_out)
{
    unsigned int modrm;
    unsigned int mod;
    unsigned int rm;
    size_t end;

    if (!bytes || !end_out || modrm_position >= available)
        return 0;
    modrm = bytes[modrm_position];
    mod = modrm >> 6;
    rm = modrm & 7U;
    end = modrm_position + 1;
    if (mod != 3U && rm == 4U) {
        unsigned int sib;

        if (end >= available)
            return 0;
        sib = bytes[end++];
        if (mod == 0U && (sib & 7U) == 5U) {
            if (available - end < sizeof(int32_t))
                return 0;
            end += sizeof(int32_t);
        }
    } else if (mod == 0U && rm == 5U) {
        if (available - end < sizeof(int32_t))
            return 0;
        end += sizeof(int32_t);
    }
    if (mod == 1U) {
        if (available - end < sizeof(int8_t))
            return 0;
        end += sizeof(int8_t);
    } else if (mod == 2U) {
        if (available - end < sizeof(int32_t))
            return 0;
        end += sizeof(int32_t);
    }
    *end_out = end;
    return 1;
}

/* Conservative legacy x86-64 length decoder for the scalar/SSE instruction
 * forms emitted by every admitted CPU initializer.  It is intentionally not
 * a permissive disassembler: VEX/EVEX, address-size overrides, three-byte
 * opcode maps, and unknown forms reject the target contract. */
static inline int
dlfrz_glibc_x86_instruction(const unsigned char *bytes, size_t available,
                            struct dlfrz_glibc_x86_instruction *instruction)
{
    size_t cursor = 0;
    size_t prefix_count = 0;
    size_t immediate_size = 0;
    size_t modrm_position = 0;
    unsigned int opcode;
    unsigned int rex = 0;
    int operand16 = 0;
    int have_modrm = 0;

    if (!bytes || !instruction || available == 0)
        return 0;
    memset(instruction, 0, sizeof(*instruction));
    while (cursor < available &&
           dlfrz_glibc_x86_legacy_prefix(bytes[cursor])) {
        if (bytes[cursor] == UINT8_C(0x66))
            operand16 = 1;
        if (bytes[cursor] == UINT8_C(0x67))
            return 0;
        if (++prefix_count > 8)
            return 0;
        cursor++;
    }
    if (cursor < available && bytes[cursor] >= UINT8_C(0x40) &&
        bytes[cursor] <= UINT8_C(0x4f))
        rex = bytes[cursor++];
    if (cursor >= available)
        return 0;
    opcode = bytes[cursor++];

    if ((opcode <= UINT8_C(0x3b) && (opcode & 7U) <= 3U) ||
        opcode == UINT8_C(0x63) || opcode == UINT8_C(0x69) ||
        opcode == UINT8_C(0x6b) ||
        (opcode >= UINT8_C(0x80) && opcode <= UINT8_C(0x8f)) ||
        opcode == UINT8_C(0xc0) || opcode == UINT8_C(0xc1) ||
        opcode == UINT8_C(0xc6) || opcode == UINT8_C(0xc7) ||
        (opcode >= UINT8_C(0xd0) && opcode <= UINT8_C(0xd3)) ||
        opcode == UINT8_C(0xf6) || opcode == UINT8_C(0xf7) ||
        opcode == UINT8_C(0xfe) || opcode == UINT8_C(0xff)) {
        have_modrm = 1;
        modrm_position = cursor;
        if (opcode == UINT8_C(0x69) || opcode == UINT8_C(0x81) ||
            opcode == UINT8_C(0xc7))
            immediate_size = operand16 ? 2U : 4U;
        else if (opcode == UINT8_C(0x6b) ||
                 opcode == UINT8_C(0x80) ||
                 opcode == UINT8_C(0x82) ||
                 opcode == UINT8_C(0x83) ||
                 opcode == UINT8_C(0xc0) ||
                 opcode == UINT8_C(0xc1) ||
                 opcode == UINT8_C(0xc6))
            immediate_size = 1;
    } else if ((opcode & UINT8_C(0xf8)) == UINT8_C(0x50) ||
               (opcode & UINT8_C(0xf8)) == UINT8_C(0x58) ||
               (opcode >= UINT8_C(0x90) && opcode <= UINT8_C(0x99)) ||
               opcode == UINT8_C(0xc3) || opcode == UINT8_C(0xc9) ||
               opcode == UINT8_C(0xf4) || opcode == UINT8_C(0xf5) ||
               (opcode >= UINT8_C(0xf8) && opcode <= UINT8_C(0xfd))) {
        /* fixed one-byte form */
        if (opcode == UINT8_C(0xc3) || opcode == UINT8_C(0xf4))
            instruction->terminal = 1;
    } else if (opcode == UINT8_C(0x04) || opcode == UINT8_C(0x0c) ||
               opcode == UINT8_C(0x14) || opcode == UINT8_C(0x1c) ||
               opcode == UINT8_C(0x24) || opcode == UINT8_C(0x2c) ||
               opcode == UINT8_C(0x34) || opcode == UINT8_C(0x3c) ||
               opcode == UINT8_C(0x6a) || opcode == UINT8_C(0xa8) ||
               (opcode >= UINT8_C(0xb0) && opcode <= UINT8_C(0xb7))) {
        immediate_size = 1;
    } else if (opcode == UINT8_C(0x05) || opcode == UINT8_C(0x0d) ||
               opcode == UINT8_C(0x15) || opcode == UINT8_C(0x1d) ||
               opcode == UINT8_C(0x25) || opcode == UINT8_C(0x2d) ||
               opcode == UINT8_C(0x35) || opcode == UINT8_C(0x3d) ||
               opcode == UINT8_C(0x68) || opcode == UINT8_C(0xa9)) {
        immediate_size = operand16 ? 2U : 4U;
    } else if ((opcode >= UINT8_C(0x70) && opcode <= UINT8_C(0x7f)) ||
               (opcode >= UINT8_C(0xe0) && opcode <= UINT8_C(0xe3)) ||
               opcode == UINT8_C(0xeb)) {
        immediate_size = 1;
        if (opcode == UINT8_C(0xeb)) {
            int8_t displacement;

            if (available - cursor < sizeof(displacement))
                return 0;
            memcpy(&displacement, bytes + cursor, sizeof(displacement));
            instruction->direct_branch = 1;
            instruction->branch_displacement = displacement;
        } else {
            int8_t displacement;

            if (available - cursor < sizeof(displacement))
                return 0;
            memcpy(&displacement, bytes + cursor, sizeof(displacement));
            instruction->conditional_branch = 1;
            instruction->branch_displacement = displacement;
        }
    } else if (opcode == UINT8_C(0xe8) || opcode == UINT8_C(0xe9)) {
        immediate_size = 4;
        {
            int32_t displacement;

            if (available - cursor < sizeof(displacement))
                return 0;
            memcpy(&displacement, bytes + cursor, sizeof(displacement));
            if (opcode == UINT8_C(0xe9))
                instruction->direct_branch = 1;
            else
                instruction->direct_call = 1;
            instruction->branch_displacement = displacement;
        }
    } else if (opcode >= UINT8_C(0xb8) && opcode <= UINT8_C(0xbf)) {
        immediate_size = (rex & UINT8_C(0x08)) ? 8U :
                         (operand16 ? 2U : 4U);
        if (!(rex & UINT8_C(0x08)) && !operand16) {
            uint32_t immediate;

            if (available - cursor < sizeof(immediate))
                return 0;
            memcpy(&immediate, bytes + cursor, sizeof(immediate));
            instruction->immediate_register = 1;
            instruction->register_number =
                opcode - UINT8_C(0xb8) +
                ((rex & UINT8_C(0x01)) ? 8U : 0U);
            instruction->immediate = immediate;
            instruction->immediate_offset = cursor;
        }
    } else if (opcode == UINT8_C(0xc2)) {
        immediate_size = 2;
        instruction->terminal = 1;
    } else if (opcode == UINT8_C(0x0f)) {
        unsigned int secondary;

        if (cursor >= available)
            return 0;
        secondary = bytes[cursor++];
        if (secondary == UINT8_C(0x01) && cursor < available &&
            bytes[cursor] == UINT8_C(0xd0)) {
            /* xgetbv, used by update_active before its HWCAP2 test. */
            cursor++;
        } else if (secondary == UINT8_C(0x05) ||
            secondary == UINT8_C(0x31) ||
            secondary == UINT8_C(0xa2)) {
            /* syscall, rdtsc, cpuid */
        } else if (secondary >= UINT8_C(0x80) &&
                   secondary <= UINT8_C(0x8f)) {
            int32_t displacement;

            immediate_size = 4;
            if (available - cursor < sizeof(displacement))
                return 0;
            memcpy(&displacement, bytes + cursor, sizeof(displacement));
            instruction->conditional_branch = 1;
            instruction->branch_displacement = displacement;
        } else if ((secondary >= UINT8_C(0x10) &&
                    secondary <= UINT8_C(0x1f)) ||
                   (secondary >= UINT8_C(0x28) &&
                    secondary <= UINT8_C(0x2f)) ||
                   (secondary >= UINT8_C(0x40) &&
                    secondary <= UINT8_C(0x4f)) ||
                   (secondary >= UINT8_C(0x54) &&
                    secondary <= UINT8_C(0x76)) ||
                   (secondary >= UINT8_C(0x7e) &&
                    secondary <= UINT8_C(0x7f)) ||
                   (secondary >= UINT8_C(0x90) &&
                    secondary <= UINT8_C(0x9f)) ||
                   secondary == UINT8_C(0xa3) ||
                   secondary == UINT8_C(0xa4) ||
                   secondary == UINT8_C(0xa5) ||
                   secondary == UINT8_C(0xab) ||
                   secondary == UINT8_C(0xac) ||
                   secondary == UINT8_C(0xad) ||
                   secondary == UINT8_C(0xae) ||
                   secondary == UINT8_C(0xaf) ||
                   (secondary >= UINT8_C(0xb0) &&
                    secondary <= UINT8_C(0xbf)) ||
                   (secondary >= UINT8_C(0xc0) &&
                    secondary <= UINT8_C(0xc7)) ||
                   secondary >= UINT8_C(0xd0)) {
            have_modrm = 1;
            modrm_position = cursor;
            if (secondary == UINT8_C(0x70) ||
                (secondary >= UINT8_C(0x71) &&
                 secondary <= UINT8_C(0x73)) ||
                secondary == UINT8_C(0xa4) ||
                secondary == UINT8_C(0xac) ||
                secondary == UINT8_C(0xba) ||
                secondary == UINT8_C(0xc2) ||
                secondary == UINT8_C(0xc4) ||
                secondary == UINT8_C(0xc5) ||
                secondary == UINT8_C(0xc6))
                immediate_size = 1;
        } else {
            return 0;
        }
    } else {
        return 0;
    }

    if (have_modrm) {
        unsigned int modrm;
        size_t end;

        if (!dlfrz_glibc_x86_modrm_end(
                bytes, available, modrm_position, &end))
            return 0;
        modrm = bytes[modrm_position];
        if (opcode == UINT8_C(0xff)) {
            unsigned int extension = (modrm >> 3) & 7U;

            if (extension == 4U)
                instruction->terminal = 1;
            else if (extension == 3U || extension == 5U ||
                     extension == 7U)
                return 0;
        }
        if ((opcode == UINT8_C(0xf6) || opcode == UINT8_C(0xf7)) &&
            (((modrm >> 3) & 7U) == 0U ||
             ((modrm >> 3) & 7U) == 1U))
            immediate_size = opcode == UINT8_C(0xf6) ? 1U :
                             (operand16 ? 2U : 4U);
        cursor = end;
        if (opcode == UINT8_C(0x89) && !operand16 &&
            !(rex & UINT8_C(0x08)) &&
            (modrm & UINT8_C(0xc7)) == UINT8_C(0x05)) {
            int32_t displacement;

            memcpy(&displacement, bytes + modrm_position + 1,
                   sizeof(displacement));
            instruction->rip_store_register = 1;
            instruction->register_number =
                ((modrm >> 3) & 7U) |
                ((rex & UINT8_C(0x04)) ? 8U : 0U);
            instruction->rip_displacement = displacement;
        }
    }
    if (immediate_size > available - cursor)
        return 0;
    instruction->length = cursor + immediate_size;
    return instruction->length != 0 && instruction->length <= 15;
}

static inline int
dlfrz_glibc_x86_straight_line(const unsigned char *code, size_t code_size,
                              const unsigned char *instruction_state,
                              unsigned int preserved_register,
                              size_t first, size_t limit)
{
    size_t position = first;

    if (!code || !instruction_state || first > limit || limit > code_size)
        return 0;
    while (position < limit) {
        struct dlfrz_glibc_x86_instruction instruction;

        if (!(instruction_state[position] & DLFRZ_X86_INSN_DECODED) ||
            !dlfrz_glibc_x86_instruction(
                code + position, code_size - position, &instruction) ||
            instruction.length > limit - position ||
            instruction.direct_branch || instruction.conditional_branch ||
            instruction.terminal ||
            (instruction.direct_call && preserved_register != 3U &&
             preserved_register != 5U && preserved_register < 12U))
            return 0;
        position += instruction.length;
    }
    return position == limit;
}

/* Recover the initializer's generic CPU kind without importing the private
 * enum.  Each supported initializer assigns its kind through one register,
 * then joins one common predecessor of the accessor-proven kind store.  Root
 * every enum immediate in control flow to that predecessor: all but one use
 * a direct branch and the remaining assignment falls through.  Constants in
 * later cache/tuning code therefore cannot manufacture or invalidate kind
 * evidence merely because the compiler happened to reuse the same register. */
static inline int
dlfrz_glibc_x86_cpu_generic_kind(
    const unsigned char *code, size_t code_size, uint64_t code_vaddr,
    size_t code_file_offset, uint64_t cpu_vaddr, uint32_t *kind_out,
    size_t *immediate_file_offset_out)
{
    enum {
        DLFRZ_X86_KIND_MAX_ASSIGNMENTS = 96,
        DLFRZ_X86_KIND_MAX_EDGES = 192,
        DLFRZ_X86_KIND_MAX_JUMPS = 512,
        DLFRZ_X86_KIND_MAX_BLOCKS = 4096,
        DLFRZ_X86_KIND_PATH_LIMIT = 128,
        DLFRZ_X86_KIND_MAX_VALUE = 5
    };
    struct dlfrz_x86_kind_assignment {
        unsigned int value;
        size_t position;
        size_t end;
        size_t immediate_file_offset;
    } assignments[DLFRZ_X86_KIND_MAX_ASSIGNMENTS];
    struct dlfrz_x86_kind_jump {
        size_t position;
        size_t target;
    } jumps[DLFRZ_X86_KIND_MAX_JUMPS];
    struct dlfrz_x86_kind_edge {
        size_t assignment;
        size_t target;
    } edges[DLFRZ_X86_KIND_MAX_EDGES];
    unsigned char instruction_state[32769];
    uint16_t block_worklist[DLFRZ_X86_KIND_MAX_BLOCKS];
    size_t block_head = 0;
    size_t block_tail = 0;
    size_t assignment_count = 0;
    size_t jump_count = 0;
    size_t edge_count = 0;
    unsigned int source_register = ~0U;
    size_t kind_store_position = 0;
    size_t kind_store_count = 0;
    unsigned int selected_kind = 0;
    size_t selected_immediate_file_offset = 0;
    size_t selected_contracts = 0;

    /* This header is also compiled into the bootstrap-neutral direct loader.
     * A large aggregate initializer is lowered to the build libc's memset by
     * GCC, leaving a forbidden host-libc import that could be reached after
     * target-TP handoff.  Volatile byte stores keep this admission scratch
     * initialization loader-owned without changing the decoder contract. */
    {
        volatile unsigned char *state = instruction_state;

        for (size_t i = 0; i < sizeof(instruction_state); i++)
            state[i] = 0;
    }
    if (!code || code_size < 256 || code_size > 32768)
        return 0;
    instruction_state[0] = DLFRZ_X86_INSN_START |
                           DLFRZ_X86_INSN_QUEUED;
    block_worklist[block_tail++] = 0;
    while (block_head < block_tail) {
        size_t position = block_worklist[block_head++];

        instruction_state[position] &=
            (unsigned char)~DLFRZ_X86_INSN_QUEUED;
        if (instruction_state[position] & DLFRZ_X86_INSN_DECODED)
            continue;
        while (position < code_size) {
            struct dlfrz_glibc_x86_instruction instruction;
            size_t next;

            if (instruction_state[position] & DLFRZ_X86_INSN_INTERIOR)
                return 0;
            if (instruction_state[position] & DLFRZ_X86_INSN_DECODED)
                break;
            if (!dlfrz_glibc_x86_instruction(
                    code + position, code_size - position, &instruction) ||
                instruction.length > code_size - position)
                return 0;
            next = position + instruction.length;
            instruction_state[position] |= DLFRZ_X86_INSN_START |
                                           DLFRZ_X86_INSN_DECODED;
            for (size_t byte = position + 1; byte < next; byte++) {
                if (instruction_state[byte] & DLFRZ_X86_INSN_START)
                    return 0;
                instruction_state[byte] |= DLFRZ_X86_INSN_INTERIOR;
            }

            if (instruction.direct_branch ||
                instruction.conditional_branch ||
                instruction.direct_call) {
                uint64_t next_vaddr;
                uint64_t target_vaddr;

                if (code_vaddr > UINT64_MAX - next)
                    return 0;
                next_vaddr = code_vaddr + next;
                if (!dlfrz_glibc_add_signed_u64(
                        next_vaddr, instruction.branch_displacement,
                        &target_vaddr))
                    return 0;
                if (target_vaddr >= code_vaddr &&
                    target_vaddr - code_vaddr < code_size) {
                    size_t target = (size_t)(target_vaddr - code_vaddr);

                    if (instruction_state[target] &
                            DLFRZ_X86_INSN_INTERIOR)
                        return 0;
                    instruction_state[target] |= DLFRZ_X86_INSN_START;
                    if (!(instruction_state[target] &
                          (DLFRZ_X86_INSN_QUEUED |
                           DLFRZ_X86_INSN_DECODED))) {
                        if (block_tail >= DLFRZ_X86_KIND_MAX_BLOCKS)
                            return 0;
                        instruction_state[target] |=
                            DLFRZ_X86_INSN_QUEUED;
                        block_worklist[block_tail++] = (uint16_t)target;
                    }
                }
            }
            if (instruction.direct_branch || instruction.terminal)
                break;
            position = next;
        }
    }
    instruction_state[code_size] = DLFRZ_X86_INSN_START |
                                   DLFRZ_X86_INSN_DECODED;

    for (size_t position = 0; position < code_size;) {
        struct dlfrz_glibc_x86_instruction instruction;
        size_t next;

        if (!(instruction_state[position] & DLFRZ_X86_INSN_DECODED)) {
            position++;
            continue;
        }
        if (!dlfrz_glibc_x86_instruction(
                code + position, code_size - position, &instruction) ||
            instruction.length > code_size - position)
            return 0;
        next = position + instruction.length;
        if (instruction.direct_branch) {
            uint64_t next_vaddr;
            uint64_t target_vaddr;

            if (code_vaddr > UINT64_MAX - next)
                return 0;
            next_vaddr = code_vaddr + next;
            if (!dlfrz_glibc_add_signed_u64(
                    next_vaddr, instruction.branch_displacement,
                    &target_vaddr))
                return 0;
            if (target_vaddr >= code_vaddr &&
                target_vaddr - code_vaddr < code_size) {
                size_t target = (size_t)(target_vaddr - code_vaddr);

                if (!(instruction_state[target] &
                      DLFRZ_X86_INSN_DECODED) ||
                    jump_count >= DLFRZ_X86_KIND_MAX_JUMPS)
                    return 0;
                jumps[jump_count].position = position;
                jumps[jump_count].target = target;
                jump_count++;
            }
        }
        if (instruction.rip_store_register) {
            uint64_t next_vaddr;
            uint64_t target_vaddr;

            if (code_vaddr > UINT64_MAX - next)
                return 0;
            next_vaddr = code_vaddr + next;
            if (dlfrz_glibc_add_signed_u64(
                    next_vaddr, instruction.rip_displacement,
                    &target_vaddr) && target_vaddr == cpu_vaddr) {
                source_register = instruction.register_number;
                kind_store_position = position;
                kind_store_count++;
            }
        }
        position = next;
    }
    if (kind_store_count != 1 || source_register == ~0U)
        return 0;

    for (size_t position = 0; position < code_size;) {
        struct dlfrz_glibc_x86_instruction instruction;
        size_t next;

        if (!(instruction_state[position] & DLFRZ_X86_INSN_DECODED)) {
            position++;
            continue;
        }
        if (!dlfrz_glibc_x86_instruction(
                code + position, code_size - position, &instruction) ||
            instruction.length > code_size - position)
            return 0;
        next = position + instruction.length;
        if (instruction.immediate_register &&
            instruction.register_number == source_register &&
            instruction.immediate != 0 &&
            instruction.immediate <= DLFRZ_X86_KIND_MAX_VALUE) {
            if (assignment_count >= DLFRZ_X86_KIND_MAX_ASSIGNMENTS)
                return 0;
            assignments[assignment_count].value = instruction.immediate;
            assignments[assignment_count].position = position;
            assignments[assignment_count].end = next;
            assignments[assignment_count].immediate_file_offset =
                code_file_offset + position +
                instruction.immediate_offset;
            assignment_count++;
        }
        position = next;
    }
    if (assignment_count < 4)
        return 0;

    for (size_t assignment = 0; assignment < assignment_count;
         assignment++) {
        size_t limit = assignments[assignment].end +
                       DLFRZ_X86_KIND_PATH_LIMIT;

        if (limit < assignments[assignment].end || limit > code_size)
            limit = code_size;
        for (size_t next = 0; next < assignment_count; next++) {
            if (assignments[next].position >= assignments[assignment].end &&
                assignments[next].position < limit)
                limit = assignments[next].position;
        }
        for (size_t jump = 0; jump < jump_count; jump++) {
            size_t target = jumps[jump].target;
            int duplicate = 0;

            if (jumps[jump].position < assignments[assignment].end ||
                jumps[jump].position >= limit ||
                !dlfrz_glibc_x86_straight_line(
                    code, code_size, instruction_state,
                    source_register,
                    assignments[assignment].end,
                    jumps[jump].position) ||
                target >= kind_store_position ||
                kind_store_position - target >
                    DLFRZ_X86_KIND_PATH_LIMIT ||
                !(instruction_state[target] & DLFRZ_X86_INSN_DECODED))
                continue;
            for (size_t edge = 0; edge < edge_count; edge++) {
                if (edges[edge].assignment == assignment &&
                    edges[edge].target == target) {
                    duplicate = 1;
                    break;
                }
            }
            if (duplicate)
                continue;
            if (edge_count >= DLFRZ_X86_KIND_MAX_EDGES)
                return 0;
            edges[edge_count].assignment = assignment;
            edges[edge_count].target = target;
            edge_count++;
        }
    }

    for (size_t candidate_edge = 0; candidate_edge < edge_count;
         candidate_edge++) {
        size_t join = edges[candidate_edge].target;
        unsigned int direct_count[DLFRZ_X86_KIND_MAX_VALUE + 1] = {0};
        unsigned int fallthrough_count[DLFRZ_X86_KIND_MAX_VALUE + 1] = {0};
        size_t root_assignment[DLFRZ_X86_KIND_MAX_VALUE + 1] = {0};
        unsigned int direct_total = 0;
        unsigned int fallthrough_total = 0;

        /* Evaluate each distinct branch target only once. */
        for (size_t prior = 0; prior < candidate_edge; prior++) {
            if (edges[prior].target == join) {
                join = SIZE_MAX;
                break;
            }
        }
        if (join == SIZE_MAX)
            continue;
        for (size_t edge = 0; edge < edge_count; edge++) {
            unsigned int value;

            if (edges[edge].target != join)
                continue;
            value = assignments[edges[edge].assignment].value;
            direct_count[value]++;
            root_assignment[value] = edges[edge].assignment;
            direct_total++;
        }
        for (size_t assignment = 0; assignment < assignment_count;
             assignment++) {
            unsigned int value = assignments[assignment].value;
            int branches_to_join = 0;
            int intervening_assignment = 0;

            for (size_t edge = 0; edge < edge_count; edge++) {
                if (edges[edge].assignment == assignment &&
                    edges[edge].target == join) {
                    branches_to_join = 1;
                    break;
                }
            }
            if (branches_to_join || assignments[assignment].end > join ||
                join - assignments[assignment].end >
                    DLFRZ_X86_KIND_PATH_LIMIT ||
                !dlfrz_glibc_x86_straight_line(
                    code, code_size, instruction_state,
                    source_register,
                    assignments[assignment].end, join))
                continue;
            for (size_t next = 0; next < assignment_count; next++) {
                if (assignments[next].position >=
                        assignments[assignment].end &&
                    assignments[next].position < join) {
                    intervening_assignment = 1;
                    break;
                }
            }
            if (intervening_assignment)
                continue;
            fallthrough_count[value]++;
            root_assignment[value] = assignment;
            fallthrough_total++;
        }

        for (unsigned int cardinality = 4; cardinality <= 5;
             cardinality++) {
            int valid = direct_total == cardinality - 1U &&
                        fallthrough_total == 1U;

            for (unsigned int value = 1;
                 valid && value <= DLFRZ_X86_KIND_MAX_VALUE; value++) {
                unsigned int roots = direct_count[value] +
                                     fallthrough_count[value];

                if ((value <= cardinality && roots != 1U) ||
                    (value > cardinality && roots != 0U))
                    valid = 0;
            }
            if (!valid)
                continue;
            selected_kind = cardinality;
            selected_immediate_file_offset =
                assignments[root_assignment[cardinality]].
                    immediate_file_offset;
            selected_contracts++;
        }
    }
    if (selected_contracts != 1)
        return 0;
    if (kind_out)
        *kind_out = selected_kind;
    if (immediate_file_offset_out)
        *immediate_file_offset_out = selected_immediate_file_offset;
    return 1;
}

static inline int
dlfrz_glibc_x86_reachable_instructions(
    const unsigned char *code, size_t code_size, uint64_t code_vaddr,
    unsigned char *instruction_state, size_t state_size);

static inline int
dlfrz_glibc_x86_cpu_initializer_matches(
    const unsigned char *code, size_t code_size, uint64_t code_vaddr,
    size_t code_file_offset, uint64_t cpu_vaddr,
    const struct dlfrz_glibc_x86_cpu_layout *layout,
    size_t *layout_write_file_offset,
    size_t *tail_boundary_file_offset,
    size_t cache_info_file_offsets[
        DLFRZ_GLIBC_X86_CPU_CACHE_INFO_WORDS],
    size_t object_end_file_offsets[
        DLFRZ_GLIBC_X86_CPU_END_WRITERS_MAX],
    size_t *object_end_file_offset_count)
{
    const int required_offsets[] = {
        layout->xsave_state_size,
        layout->data_cache_size,
        layout->shared_cache_size,
        layout->non_temporal_threshold,
        layout->memset_non_temporal_threshold,
        layout->rep_movsb_threshold,
        layout->rep_movsb_stop_threshold,
        layout->rep_stosb_threshold,
    };
    const int cache_info_offsets[DLFRZ_GLIBC_X86_CPU_CACHE_INFO_WORDS] = {
        layout->level1_icache_size,
        layout->level1_icache_linesize,
        layout->level1_dcache_size,
        layout->level1_dcache_assoc,
        layout->level1_dcache_linesize,
        layout->level2_cache_size,
        layout->level2_cache_assoc,
        layout->level2_cache_linesize,
        layout->level3_cache_size,
        layout->level3_cache_assoc,
        layout->level3_cache_linesize,
        layout->level4_cache_size,
    };
    unsigned char covered[sizeof(required_offsets) /
                          sizeof(required_offsets[0])] = {0};
    unsigned char cache_info_writes[
        DLFRZ_GLIBC_X86_CPU_CACHE_INFO_WORDS] = {0};
    size_t cache_info_displacements[
        DLFRZ_GLIBC_X86_CPU_CACHE_INFO_WORDS] = {0};
    size_t cache_info_positions[
        DLFRZ_GLIBC_X86_CPU_CACHE_INFO_WORDS] = {0};
    size_t cache_info_lengths[
        DLFRZ_GLIBC_X86_CPU_CACHE_INFO_WORDS] = {0};
    size_t object_end_displacements[
        DLFRZ_GLIBC_X86_CPU_END_WRITERS_MAX] = {0};
    size_t object_end_writes = 0;
    unsigned char instruction_state[32769];
    size_t kind_writes = 0;
    size_t preferred_writes = 0;
    size_t data_cache_writes = 0;
    size_t data_cache_displacement = 0;
    size_t prefix_end_writes = 0;
    size_t tail_start_writes = 0;
    size_t tail_start_displacement = 0;
    uint64_t prefix_end;
    uint64_t cache_info_end;
    uint64_t object_end;
    uint64_t object_end_field;

    if (!code || !layout || code_size < 256 || code_size > 32768 ||
        !dlfrz_glibc_x86_cpu_object_profile_complete(layout) ||
        layout->preferred < 0 || layout->data_cache_size < 0 ||
        layout->rep_stosb_threshold < 0 ||
        (uint64_t)layout->rep_stosb_threshold > UINT64_MAX - 8 ||
        (uint64_t)layout->rep_stosb_threshold + 8 >
            layout->object_size ||
        cpu_vaddr > UINT64_MAX -
            ((uint64_t)layout->rep_stosb_threshold + 8))
        return 0;
    prefix_end = cpu_vaddr +
                 (uint64_t)layout->rep_stosb_threshold + 8;
    cache_info_end = (uint64_t)layout->rep_stosb_threshold + 8;
    for (size_t field = 0;
         field < DLFRZ_GLIBC_X86_CPU_CACHE_INFO_WORDS; field++) {
        uint64_t expected;

        if (cache_info_end > UINT64_MAX - field * UINT64_C(8))
            return 0;
        expected = cache_info_end + field * UINT64_C(8);
        if (cache_info_offsets[field] < 0 ||
            (uint64_t)cache_info_offsets[field] != expected)
            return 0;
    }
    if (cache_info_end > UINT64_MAX -
            DLFRZ_GLIBC_X86_CPU_CACHE_INFO_WORDS * UINT64_C(8))
        return 0;
    cache_info_end +=
        DLFRZ_GLIBC_X86_CPU_CACHE_INFO_WORDS * UINT64_C(8);
    if ((layout->cachesize_non_temporal_divisor ==
             DLFRZ_GLIBC_X86_CPU_FIELD_ABSENT &&
         cache_info_end != layout->object_size) ||
        (layout->cachesize_non_temporal_divisor !=
             DLFRZ_GLIBC_X86_CPU_FIELD_ABSENT &&
         (layout->cachesize_non_temporal_divisor < 0 ||
          (uint64_t)layout->cachesize_non_temporal_divisor !=
              cache_info_end ||
          cache_info_end > UINT64_MAX - 8 ||
          cache_info_end + 8 != layout->object_size)) ||
        cpu_vaddr > UINT64_MAX - cache_info_end ||
        layout->object_size < 8 ||
        cpu_vaddr > UINT64_MAX - layout->object_size)
        return 0;
    object_end = cpu_vaddr + layout->object_size;
    object_end_field = object_end - UINT64_C(8);
    if (!dlfrz_glibc_x86_reachable_instructions(
            code, code_size, code_vaddr, instruction_state,
            sizeof(instruction_state)))
        return 0;
    for (size_t position = 0; position < code_size; position++) {
        struct dlfrz_glibc_x86_rip_write write;
        uint64_t write_end;

        if (!(instruction_state[position] & DLFRZ_X86_INSN_DECODED) ||
            code_vaddr > UINT64_MAX - position ||
            !dlfrz_glibc_x86_rip_write(
                code + position, code_size - position,
                code_vaddr + position, &write) ||
            write.target_vaddr > UINT64_MAX - write.width)
            continue;
        write_end = write.target_vaddr + write.width;
        if (write.target_vaddr < object_end && write_end > object_end)
            return 0;
        if (write.target_vaddr < object_end &&
            write_end > object_end_field) {
            size_t current_displacement = code_file_offset + position +
                                          write.displacement_offset;
            size_t existing;

            for (existing = 0; existing < object_end_writes; existing++) {
                if (object_end_displacements[existing] ==
                        current_displacement)
                    break;
            }
            if (existing == object_end_writes) {
                if (!((write.width == 8 &&
                       write.target_vaddr == object_end_field) ||
                      (write.width == 16 && object_end >= UINT64_C(16) &&
                       write.target_vaddr ==
                           object_end - UINT64_C(16))) ||
                    object_end_writes ==
                        DLFRZ_GLIBC_X86_CPU_END_WRITERS_MAX)
                    return 0;
                object_end_displacements[object_end_writes++] =
                    current_displacement;
            }
        }
        if (write.target_vaddr < prefix_end && write_end > prefix_end)
            return 0;
        if (write.target_vaddr < prefix_end && write_end == prefix_end)
            prefix_end_writes++;
        if (write.target_vaddr == prefix_end) {
            size_t current_displacement = code_file_offset + position +
                                          write.displacement_offset;

            if (!tail_start_writes ||
                current_displacement != tail_start_displacement) {
                tail_start_writes++;
                tail_start_displacement = current_displacement;
            }
        }
        for (size_t field = 0;
             field < DLFRZ_GLIBC_X86_CPU_CACHE_INFO_WORDS; field++) {
            uint64_t target = cpu_vaddr +
                (uint64_t)cache_info_offsets[field];
            uint64_t target_end = target + UINT64_C(8);
            size_t current_displacement;

            if (write.target_vaddr >= target_end || write_end <= target)
                continue;
            current_displacement = code_file_offset + position +
                                   write.displacement_offset;
            /* Starting at the opcode of a REX-prefixed store decodes the
             * same displacement as a narrower apparent instruction.  It is
             * one witness, not a second partial writer. */
            if (cache_info_writes[field] &&
                current_displacement ==
                    cache_info_displacements[field])
                continue;
            if (!((write.width == 8 &&
                   write.target_vaddr == target) ||
                  (write.width == 16 &&
                   ((field % 2U == 0 &&
                     write.target_vaddr == target) ||
                    (field % 2U == 1 && target >= UINT64_C(8) &&
                     write.target_vaddr == target - UINT64_C(8))))))
                return 0;
            if (cache_info_writes[field])
                return 0;
            cache_info_writes[field] = 1;
            cache_info_displacements[field] = current_displacement;
            cache_info_positions[field] = position;
            cache_info_lengths[field] = write.length;
        }
        if (write.target_vaddr == cpu_vaddr && write.width == 4)
            kind_writes++;
        if (cpu_vaddr <= UINT64_MAX - (uint64_t)layout->preferred &&
            write.target_vaddr ==
                cpu_vaddr + (uint64_t)layout->preferred &&
            write.width == 4)
            preferred_writes++;
        if (cpu_vaddr <= UINT64_MAX - (uint64_t)layout->data_cache_size &&
            write.target_vaddr ==
                cpu_vaddr + (uint64_t)layout->data_cache_size) {
            size_t current_displacement = code_file_offset + position +
                                          write.displacement_offset;

            /* A REX-prefixed store is also syntactically decodable when a
             * byte-by-byte evidence scan begins at its opcode.  Both views
             * name the same displacement word, so count that instruction
             * once rather than mistaking its width variant for a second
             * witness. */
            if (!data_cache_writes ||
                current_displacement != data_cache_displacement) {
                data_cache_writes++;
                data_cache_displacement = current_displacement;
            }
        }
        for (size_t required = 0;
             required < sizeof(required_offsets) /
                            sizeof(required_offsets[0]);
             required++) {
            uint64_t target;

            if (required_offsets[required] < 0) {
                covered[required] = 1;
                continue;
            }
            if (cpu_vaddr > UINT64_MAX -
                    (uint64_t)required_offsets[required])
                return 0;
            target = cpu_vaddr + (uint64_t)required_offsets[required];
            if (write.target_vaddr <= target && target < write_end)
                covered[required] = 1;
        }
    }
    if (!kind_writes || !preferred_writes || data_cache_writes != 1 ||
        !prefix_end_writes || tail_start_writes != 1 ||
        object_end_writes == 0)
        return 0;
    for (size_t required = 0;
         required < sizeof(required_offsets) / sizeof(required_offsets[0]);
         required++) {
        if (!covered[required])
            return 0;
    }
    {
        size_t block_start = SIZE_MAX;
        size_t block_end = 0;
        size_t position;

        for (size_t field = 0;
             field < DLFRZ_GLIBC_X86_CPU_CACHE_INFO_WORDS; field++) {
            size_t end;

            if (cache_info_writes[field] != 1 ||
                cache_info_positions[field] >
                    SIZE_MAX - cache_info_lengths[field])
                return 0;
            end = cache_info_positions[field] +
                  cache_info_lengths[field];
            if (cache_info_positions[field] < block_start)
                block_start = cache_info_positions[field];
            if (end > block_end)
                block_end = end;
        }
        /* All published cache words must have witnesses in one reachable,
         * branch-free block.  Conditional or call-separated byte patterns
         * are not strong enough to establish one coherent field layout. */
        position = block_start;
        while (position < block_end) {
            struct dlfrz_glibc_x86_instruction instruction;

            if (!dlfrz_glibc_x86_instruction(
                    code + position, code_size - position,
                    &instruction) ||
                instruction.length > block_end - position ||
                instruction.direct_branch ||
                instruction.conditional_branch ||
                instruction.direct_call || instruction.terminal)
                return 0;
            position += instruction.length;
        }
        if (position != block_end)
            return 0;
    }
    if (layout_write_file_offset)
        *layout_write_file_offset = data_cache_displacement;
    if (tail_boundary_file_offset)
        *tail_boundary_file_offset = tail_start_displacement;
    if (cache_info_file_offsets)
        memcpy(cache_info_file_offsets, cache_info_displacements,
               sizeof(cache_info_displacements));
    if (object_end_file_offsets)
        memcpy(object_end_file_offsets, object_end_displacements,
               object_end_writes * sizeof(object_end_displacements[0]));
    if (object_end_file_offset_count)
        *object_end_file_offset_count = object_end_writes;
    return 1;
}

static inline int
dlfrz_glibc_x86_cpu_contract_valid(
    const void *data, size_t elf_size, enum dlfrz_glibc_layout_id layout,
    int minor, uint64_t glro_vaddr, uint64_t glro_size,
    struct dlfrz_glibc_x86_cpu_contract *contract_out,
    struct dlfrz_glibc_x86_cpu_evidence *evidence_out)
{
    static const unsigned char endbr64[] = { 0xf3, 0x0f, 0x1e, 0xfa };
    static const unsigned char wrapper_padding[] = {
        0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    struct dlfrz_elf64_dyn_view view;
    struct dlfrz_glibc_x86_cpu_layout profile;
    struct dlfrz_glibc_x86_cpu_layout alternative;
    struct dlfrz_glibc_x86_cpu_contract contract;
    struct dlfrz_glibc_x86_cpu_evidence evidence;
    Elf64_Sym accessor;
    const unsigned char *accessor_code;
    const unsigned char *wrapper_code;
    const unsigned char *initializer_code;
    size_t accessor_offset;
    size_t wrapper_offset;
    size_t initializer_offset;
    size_t accessor_cursor = 0;
    size_t wrapper_cursor = 0;
    uint64_t cpu_vaddr;
    uint64_t wrapper_vaddr;
    uint64_t wrapper_load_vaddr;
    uint64_t initializer_vaddr;
    uint64_t initializer_size;
    uint32_t generic_kind;
    int32_t displacement;

    /* Keep this an explicit call so loader.c's private memset redirection is
     * honored.  GCC may otherwise lower a large aggregate initializer to a
     * bootstrap-libc import after the target thread pointer is installed. */
    memset(&evidence, 0, sizeof(evidence));
    if (!dlfrz_glibc_x86_cpu_layout_profile(
            layout, minor, &profile) ||
        !dlfrz_elf64_dyn_view_init(data, elf_size, &view) ||
        view.ehdr.e_machine != EM_X86_64 ||
        dlfrz_elf64_dyn_view_find(
            &view, "_dl_x86_get_cpu_features", &accessor, NULL) != 1 ||
        ELF64_ST_BIND(accessor.st_info) != STB_GLOBAL ||
        ELF64_ST_TYPE(accessor.st_info) != STT_FUNC ||
        ELF64_ST_VISIBILITY(accessor.st_other) != STV_DEFAULT ||
        accessor.st_shndx == SHN_UNDEF ||
        accessor.st_shndx >= SHN_LORESERVE ||
        (accessor.st_size != 8 && accessor.st_size != 12) ||
        !dlfrz_glibc_vaddr_file_range(
            view.elf, view.elf_size, &view.ehdr,
            accessor.st_value, accessor.st_size, &accessor_offset) ||
        !dlfrz_glibc_vaddr_executable_file_range(
            view.elf, view.elf_size, &view.ehdr,
            accessor.st_value, accessor.st_size))
        return 0;
    accessor_code = view.elf + accessor_offset;
    if (accessor.st_size == sizeof(endbr64) + 8 &&
        memcmp(accessor_code, endbr64, sizeof(endbr64)) == 0)
        accessor_cursor = sizeof(endbr64);
    if (accessor_cursor + 8 != accessor.st_size ||
        accessor_code[accessor_cursor] != UINT8_C(0x48) ||
        accessor_code[accessor_cursor + 1] != UINT8_C(0x8d) ||
        accessor_code[accessor_cursor + 2] != UINT8_C(0x05) ||
        accessor_code[accessor_cursor + 7] != UINT8_C(0xc3))
        return 0;
    memcpy(&displacement, accessor_code + accessor_cursor + 3,
           sizeof(displacement));
    if (accessor.st_value > UINT64_MAX - accessor_cursor - 7 ||
        !dlfrz_glibc_add_signed_u64(
            accessor.st_value + accessor_cursor + 7,
            displacement, &cpu_vaddr) ||
        cpu_vaddr < glro_vaddr ||
        !dlfrz_glibc_x86_cpu_object_fits(
            &profile, cpu_vaddr - glro_vaddr, glro_size) ||
        accessor.st_value < 32)
        return 0;
    evidence.accessor_displacement_file_offset = accessor_offset +
                                                  accessor_cursor + 3;

    wrapper_vaddr = accessor.st_value - 32;
    if (!dlfrz_glibc_vaddr_file_range(
            view.elf, view.elf_size, &view.ehdr,
            wrapper_vaddr, 32, &wrapper_offset) ||
        !dlfrz_glibc_vaddr_executable_file_range(
            view.elf, view.elf_size, &view.ehdr, wrapper_vaddr, 32))
        return 0;
    wrapper_code = view.elf + wrapper_offset;
    if (memcmp(wrapper_code, endbr64, sizeof(endbr64)) == 0)
        wrapper_cursor = sizeof(endbr64);
    if (wrapper_cursor + 11 > 16 ||
        wrapper_code[wrapper_cursor] != UINT8_C(0x8b) ||
        wrapper_code[wrapper_cursor + 1] != UINT8_C(0x05) ||
        wrapper_code[wrapper_cursor + 6] != UINT8_C(0x85) ||
        wrapper_code[wrapper_cursor + 7] != UINT8_C(0xc0) ||
        wrapper_code[wrapper_cursor + 8] != UINT8_C(0x74) ||
        wrapper_code[wrapper_cursor + 9] !=
            (unsigned char)(6U - wrapper_cursor) ||
        wrapper_code[wrapper_cursor + 10] != UINT8_C(0xc3) ||
        wrapper_code[16] != UINT8_C(0xe9) ||
        memcmp(wrapper_code + 21, wrapper_padding,
               sizeof(wrapper_padding)) != 0)
        return 0;
    if (wrapper_cursor == sizeof(endbr64)) {
        if (wrapper_code[15] != UINT8_C(0x90))
            return 0;
    } else {
        static const unsigned char nop5[] = {
            0x0f, 0x1f, 0x44, 0x00, 0x00
        };
        if (memcmp(wrapper_code + 11, nop5, sizeof(nop5)) != 0)
            return 0;
    }
    memcpy(&displacement, wrapper_code + wrapper_cursor + 2,
           sizeof(displacement));
    if (wrapper_vaddr > UINT64_MAX - wrapper_cursor - 6 ||
        !dlfrz_glibc_add_signed_u64(
            wrapper_vaddr + wrapper_cursor + 6,
            displacement, &wrapper_load_vaddr) ||
        wrapper_load_vaddr != cpu_vaddr)
        return 0;
    evidence.wrapper_displacement_file_offset = wrapper_offset +
                                                wrapper_cursor + 2;
    memcpy(&displacement, wrapper_code + 17, sizeof(displacement));
    if (wrapper_vaddr > UINT64_MAX - 21 ||
        !dlfrz_glibc_add_signed_u64(
            wrapper_vaddr + 21, displacement, &initializer_vaddr) ||
        initializer_vaddr >= wrapper_vaddr)
        return 0;
    initializer_size = wrapper_vaddr - initializer_vaddr;
    if (initializer_size > SIZE_MAX || initializer_size < 256 ||
        initializer_size > 32768 ||
        !dlfrz_glibc_vaddr_file_range(
            view.elf, view.elf_size, &view.ehdr,
            initializer_vaddr, initializer_size, &initializer_offset) ||
        !dlfrz_glibc_vaddr_executable_file_range(
            view.elf, view.elf_size, &view.ehdr,
            initializer_vaddr, initializer_size))
        return 0;
    initializer_code = view.elf + initializer_offset;
    if (!dlfrz_glibc_x86_cpu_generic_kind(
            initializer_code, (size_t)initializer_size,
            initializer_vaddr, initializer_offset, cpu_vaddr,
            &generic_kind,
            &evidence.generic_kind_immediate_file_offset) ||
        !dlfrz_glibc_x86_cpu_initializer_matches(
            initializer_code, (size_t)initializer_size,
            initializer_vaddr, initializer_offset, cpu_vaddr, &profile,
            &evidence.layout_write_displacement_file_offset,
            &evidence.tail_boundary_displacement_file_offset,
            evidence.cache_info_displacement_file_offsets,
            evidence.object_end_displacement_file_offsets,
            &evidence.object_end_displacement_count))
        return 0;

    /* The structurally distinct feature-array family must disagree with the
     * same target initializer.  The 2.39 and 2.40 layouts share write
     * positions from offset 392 onward (with different member meanings), so
     * their distinction comes from the exact stable-release profile above,
     * not from a misleading absence-of-write test. */
    alternative = profile;
    if (profile.feature_count == 9) {
        alternative = (struct dlfrz_glibc_x86_cpu_layout){
            .feature_count = 10,
            .object_size = 528,
            .preferred = 340,
            .isa_1 = 344,
            .xsave_state_size = 352,
            .xsave_state_full_size = 360,
            .data_cache_size = 368,
            .shared_cache_size = 376,
            .non_temporal_threshold = 384,
            .memset_non_temporal_threshold = 392,
            .rep_movsb_threshold = 400,
            .rep_movsb_stop_threshold = 408,
            .rep_stosb_threshold = 416,
            .level1_icache_size = 424,
            .level1_icache_linesize = 432,
            .level1_dcache_size = 440,
            .level1_dcache_assoc = 448,
            .level1_dcache_linesize = 456,
            .level2_cache_size = 464,
            .level2_cache_assoc = 472,
            .level2_cache_linesize = 480,
            .level3_cache_size = 488,
            .level3_cache_assoc = 496,
            .level3_cache_linesize = 504,
            .level4_cache_size = 512,
            .cachesize_non_temporal_divisor = 520,
        };
    } else {
        alternative = (struct dlfrz_glibc_x86_cpu_layout){
            .feature_count = 9,
            .object_size = 488,
            .preferred = 308,
            .isa_1 = 312,
            .xsave_state_size = 320,
            .xsave_state_full_size = 328,
            .data_cache_size = 336,
            .shared_cache_size = 344,
            .non_temporal_threshold = 352,
            .memset_non_temporal_threshold =
                DLFRZ_GLIBC_X86_CPU_FIELD_ABSENT,
            .rep_movsb_threshold = 360,
            .rep_movsb_stop_threshold = 368,
            .rep_stosb_threshold = 376,
            .level1_icache_size = 384,
            .level1_icache_linesize = 392,
            .level1_dcache_size = 400,
            .level1_dcache_assoc = 408,
            .level1_dcache_linesize = 416,
            .level2_cache_size = 424,
            .level2_cache_assoc = 432,
            .level2_cache_linesize = 440,
            .level3_cache_size = 448,
            .level3_cache_assoc = 456,
            .level3_cache_linesize = 464,
            .level4_cache_size = 472,
            .cachesize_non_temporal_divisor = 480,
        };
    }
    if (dlfrz_glibc_x86_cpu_initializer_matches(
            initializer_code, (size_t)initializer_size,
            initializer_vaddr, initializer_offset, cpu_vaddr, &alternative,
            NULL, NULL, NULL, NULL, NULL))
        return 0;

    contract.layout = profile;
    contract.cpu_features_offset = cpu_vaddr - glro_vaddr;
    contract.wrapper_vaddr = wrapper_vaddr;
    contract.initializer_vaddr = initializer_vaddr;
    contract.published_prefix_size =
        (uint64_t)profile.rep_stosb_threshold + 8;
    contract.cache_info_offset =
        (uint64_t)profile.level1_icache_size;
    contract.cache_info_word_count =
        DLFRZ_GLIBC_X86_CPU_CACHE_INFO_WORDS;
    contract.generic_kind = generic_kind;
    if (contract_out)
        *contract_out = contract;
    if (evidence_out)
        *evidence_out = evidence;
    return 1;
}

/* Recover the two GLRO fields which target libc exposes for AT_HWCAP and
 * AT_HWCAP2.  These offsets are distribution-build properties, not release
 * constants: supported 2.34--2.44 libcs place HWCAP2 at several different
 * locations.  Root both branches in the unique _rtld_global_ro GLOB_DAT
 * relocation and require the exact leaf loads reached by the public
 * __getauxval comparisons. */
static inline int
dlfrz_glibc_x86_getauxval_contract_valid(
    const void *data, size_t elf_size, uint64_t glro_size,
    struct dlfrz_glibc_getauxval_contract *contract_out,
    struct dlfrz_glibc_x86_getauxval_evidence *evidence_out)
{
    static const unsigned char endbr64[] = { 0xf3, 0x0f, 0x1e, 0xfa };
    struct dlfrz_glibc_getauxval_contract contract;
    struct dlfrz_glibc_x86_getauxval_evidence evidence = {0};
    struct dlfrz_elf64_dyn_view view;
    Elf64_Sym function;
    const unsigned char *code;
    uint64_t glro_got_vaddr = 0;
    uint64_t load_next;
    uint64_t load_target;
    size_t function_offset;
    size_t cursor = 0;
    size_t hwcap_position;
    size_t hwcap2_position;
    int32_t displacement;
    int8_t branch;

    if (!dlfrz_elf64_dyn_view_init(data, elf_size, &view) ||
        view.ehdr.e_machine != EM_X86_64 ||
        !dlfrz_glibc_function_definition(
            &view, "__getauxval", &function) ||
        (function.st_size != 104 && function.st_size != 120) ||
        !dlfrz_glibc_glro_got_relocation(&view, &glro_got_vaddr) ||
        !dlfrz_glibc_vaddr_file_range(
            view.elf, view.elf_size, &view.ehdr,
            function.st_value, function.st_size, &function_offset))
        return 0;
    code = view.elf + function_offset;
    if (function.st_size >= sizeof(endbr64) &&
        memcmp(code, endbr64, sizeof(endbr64)) == 0)
        cursor = sizeof(endbr64);

    /* mov _rtld_global_ro@GOTPCREL(%rip),%rax; cmp $AT_HWCAP,%rdi;
     * je leaf; cmp $AT_HWCAP2,%rdi; je leaf; mov dl_auxv(%rax),%rax */
    if (cursor + 23 > function.st_size ||
        code[cursor] != UINT8_C(0x48) ||
        code[cursor + 1] != UINT8_C(0x8b) ||
        code[cursor + 2] != UINT8_C(0x05) ||
        code[cursor + 7] != UINT8_C(0x48) ||
        code[cursor + 8] != UINT8_C(0x83) ||
        code[cursor + 9] != UINT8_C(0xff) ||
        code[cursor + 10] != UINT8_C(0x10) ||
        code[cursor + 11] != UINT8_C(0x74) ||
        code[cursor + 13] != UINT8_C(0x48) ||
        code[cursor + 14] != UINT8_C(0x83) ||
        code[cursor + 15] != UINT8_C(0xff) ||
        code[cursor + 16] != UINT8_C(0x1a) ||
        code[cursor + 17] != UINT8_C(0x74) ||
        code[cursor + 19] != UINT8_C(0x48) ||
        code[cursor + 20] != UINT8_C(0x8b) ||
        code[cursor + 21] != UINT8_C(0x40) ||
        code[cursor + 22] != UINT8_C(0x68))
        return 0;
    memcpy(&displacement, code + cursor + 3, sizeof(displacement));
    if (function.st_value > UINT64_MAX - cursor - 7)
        return 0;
    load_next = function.st_value + cursor + 7;
    if (!dlfrz_glibc_add_signed_u64(
            load_next, displacement, &load_target) ||
        load_target != glro_got_vaddr)
        return 0;
    evidence.glro_displacement_file_offset = function_offset + cursor + 3;

    memcpy(&branch, code + cursor + 12, sizeof(branch));
    if (branch < 0 ||
        (size_t)branch > (size_t)function.st_size - (cursor + 13))
        return 0;
    hwcap_position = cursor + 13 + (size_t)branch;
    memcpy(&branch, code + cursor + 18, sizeof(branch));
    if (branch < 0 ||
        (size_t)branch > (size_t)function.st_size - (cursor + 19))
        return 0;
    hwcap2_position = cursor + 19 + (size_t)branch;
    if (hwcap_position > (size_t)function.st_size - 5 ||
        code[hwcap_position] != UINT8_C(0x48) ||
        code[hwcap_position + 1] != UINT8_C(0x8b) ||
        code[hwcap_position + 2] != UINT8_C(0x40) ||
        code[hwcap_position + 3] != UINT8_C(0x60) ||
        code[hwcap_position + 4] != UINT8_C(0xc3) ||
        hwcap2_position > (size_t)function.st_size - 8 ||
        code[hwcap2_position] != UINT8_C(0x48) ||
        code[hwcap2_position + 1] != UINT8_C(0x8b) ||
        code[hwcap2_position + 2] != UINT8_C(0x80) ||
        code[hwcap2_position + 7] != UINT8_C(0xc3))
        return 0;
    memcpy(&displacement, code + hwcap2_position + 3,
           sizeof(displacement));
    if (displacement < 0 || ((uint32_t)displacement & 7U) != 0 ||
        (uint64_t)(uint32_t)displacement > glro_size ||
        sizeof(uint64_t) >
            glro_size - (uint64_t)(uint32_t)displacement ||
        (uint32_t)displacement == UINT32_C(0x60))
        return 0;
    contract.hwcap_offset = UINT64_C(0x60);
    contract.hwcap2_offset = (uint32_t)displacement;
    evidence.hwcap2_displacement_file_offset =
        function_offset + hwcap2_position + 3;
    if (contract_out)
        *contract_out = contract;
    if (evidence_out)
        *evidence_out = evidence;
    return 1;
}

struct dlfrz_glibc_aarch64_getauxval_leaf {
    uint64_t field_offset;
    size_t start;
    size_t end;
    size_t adrp_position;
    size_t got_load_position;
    size_t field_load_position;
    size_t restore_position;
    int restore_before_field;
};

static inline int
dlfrz_glibc_aarch64_getauxval_branch_target(
    uint32_t instruction, uint64_t instruction_vaddr,
    uint64_t *target_vaddr)
{
    uint32_t immediate;
    int64_t displacement;

    /* B.EQ with the architecturally reserved bit four clear. */
    if (!target_vaddr ||
        (instruction & UINT32_C(0xff00001f)) != UINT32_C(0x54000000))
        return 0;
    immediate = (instruction >> 5) & UINT32_C(0x7ffff);
    displacement = (int64_t)immediate;
    if (immediate & UINT32_C(0x40000))
        displacement -= INT64_C(0x80000);
    displacement *= INT64_C(4);
    return dlfrz_glibc_add_signed_u64(
        instruction_vaddr, displacement, target_vaddr);
}

static inline int
dlfrz_glibc_aarch64_getauxval_leaf_valid(
    const unsigned char *code, size_t code_size, uint64_t code_vaddr,
    uint64_t target_vaddr, uint64_t glro_got_vaddr, uint64_t glro_size,
    int framed, struct dlfrz_glibc_aarch64_getauxval_leaf *leaf_out)
{
    static const uint32_t restore = UINT32_C(0xa8c17bfd);
    static const uint32_t ret = UINT32_C(0xd65f03c0);
    struct dlfrz_glibc_aarch64_getauxval_leaf leaf = {0};
    uint32_t adrp;
    uint32_t got_load;
    uint32_t field_load;
    uint32_t immediate;
    unsigned int page_register;
    unsigned int glro_register;
    int64_t page_displacement;
    uint64_t target_page;
    uint64_t got_vaddr;
    size_t field_index;
    size_t ret_index;
    size_t required;

    if (target_vaddr < code_vaddr ||
        target_vaddr - code_vaddr > code_size ||
        (target_vaddr - code_vaddr) % 4U != 0)
        return 0;
    leaf.start = (size_t)(target_vaddr - code_vaddr);
    required = framed ? 5U * sizeof(uint32_t) : 4U * sizeof(uint32_t);
    if (leaf.start > code_size || required > code_size - leaf.start)
        return 0;

    adrp = dlfrz_glibc_read_u32(code + leaf.start);
    got_load = dlfrz_glibc_read_u32(
        code + leaf.start + sizeof(uint32_t));
    if ((adrp & UINT32_C(0x9f000000)) != UINT32_C(0x90000000) ||
        (got_load & UINT32_C(0xffc00000)) != UINT32_C(0xf9400000))
        return 0;
    page_register = adrp & 31U;
    glro_register = got_load & 31U;
    if (page_register == 31U || glro_register == 31U ||
        ((got_load >> 5) & 31U) != page_register)
        return 0;
    immediate = ((adrp >> 29) & 3U) |
                (((adrp >> 5) & UINT32_C(0x7ffff)) << 2);
    page_displacement =
        dlfrz_glibc_sign_extend_21(immediate) * INT64_C(4096);
    if (!dlfrz_glibc_add_signed_u64(
            target_vaddr & ~UINT64_C(0xfff), page_displacement,
            &target_page))
        return 0;
    immediate = (got_load >> 10) & UINT32_C(0xfff);
    if (target_page > UINT64_MAX - (uint64_t)immediate * UINT64_C(8))
        return 0;
    got_vaddr = target_page + (uint64_t)immediate * UINT64_C(8);
    if (got_vaddr != glro_got_vaddr)
        return 0;

    leaf.restore_position = SIZE_MAX;
    if (!framed) {
        field_index = 2U;
        ret_index = 3U;
        leaf.restore_before_field = 0;
    } else if (dlfrz_glibc_read_u32(
                   code + leaf.start + 2U * sizeof(uint32_t)) == restore) {
        field_index = 3U;
        ret_index = 4U;
        leaf.restore_position = leaf.start + 2U * sizeof(uint32_t);
        leaf.restore_before_field = 1;
    } else if (dlfrz_glibc_read_u32(
                   code + leaf.start + 3U * sizeof(uint32_t)) == restore) {
        field_index = 2U;
        ret_index = 4U;
        leaf.restore_position = leaf.start + 3U * sizeof(uint32_t);
        leaf.restore_before_field = 0;
    } else {
        return 0;
    }
    if (leaf.restore_before_field &&
        (glro_register == 29U || glro_register == 30U))
        return 0;

    field_load = dlfrz_glibc_read_u32(
        code + leaf.start + field_index * sizeof(uint32_t));
    if ((field_load & UINT32_C(0xffc00000)) != UINT32_C(0xf9400000) ||
        (field_load & 31U) != 0U ||
        ((field_load >> 5) & 31U) != glro_register ||
        dlfrz_glibc_read_u32(
            code + leaf.start + ret_index * sizeof(uint32_t)) != ret)
        return 0;
    leaf.field_offset =
        (uint64_t)((field_load >> 10) & UINT32_C(0xfff)) * UINT64_C(8);
    if (leaf.field_offset > glro_size ||
        sizeof(uint64_t) > glro_size - leaf.field_offset)
        return 0;
    leaf.end = leaf.start + required;
    leaf.adrp_position = leaf.start;
    leaf.got_load_position = leaf.start + sizeof(uint32_t);
    leaf.field_load_position =
        leaf.start + field_index * sizeof(uint32_t);
    if (leaf_out)
        *leaf_out = leaf;
    return 1;
}

/* Recover AArch64 GLRO HWCAP fields from the public __getauxval control
 * flow.  This deliberately admits only the instruction families observed
 * in supported release fixtures.  In particular PAC prologues, alternate
 * dispatcher orderings, non-adjacent GOT loads, and unbalanced framed
 * epilogues fail closed until separately evidenced. */
static inline int
dlfrz_glibc_aarch64_getauxval_contract_valid(
    const void *data, size_t elf_size, uint64_t glro_size,
    struct dlfrz_glibc_getauxval_contract *contract_out,
    struct dlfrz_glibc_aarch64_getauxval_evidence *evidence_out)
{
    static const uint32_t bti_c = UINT32_C(0xd503245f);
    static const uint32_t frame_push = UINT32_C(0xa9bf7bfd);
    static const uint32_t frame_pointer = UINT32_C(0x910003fd);
    static const uint32_t cmp_hwcap = UINT32_C(0xf100401f);
    static const uint32_t cmp_hwcap2 = UINT32_C(0xf100681f);
    struct dlfrz_glibc_getauxval_contract contract;
    struct dlfrz_glibc_aarch64_getauxval_evidence evidence;
    struct dlfrz_glibc_aarch64_getauxval_leaf leaves[2];
    struct dlfrz_elf64_dyn_view view;
    Elf64_Sym function;
    const unsigned char *code;
    uint64_t glro_got_vaddr;
    uint64_t targets[2];
    size_t function_offset;
    size_t cursor = 0;
    size_t scan_size;
    unsigned int quartet_count = 0;
    int framed = 0;

    memset(&evidence, 0, sizeof(evidence));
    evidence.restore_file_offsets[0] = SIZE_MAX;
    evidence.restore_file_offsets[1] = SIZE_MAX;
    if (!dlfrz_elf64_dyn_view_init(data, elf_size, &view) ||
        view.ehdr.e_machine != EM_AARCH64 ||
        dlfrz_elf64_dyn_view_find(
            &view, "__getauxval", &function, NULL) != 1 ||
        ELF64_ST_BIND(function.st_info) != STB_GLOBAL ||
        ELF64_ST_TYPE(function.st_info) != STT_FUNC ||
        ELF64_ST_VISIBILITY(function.st_other) != STV_DEFAULT ||
        function.st_shndx == SHN_UNDEF ||
        function.st_shndx >= SHN_LORESERVE || function.st_value == 0 ||
        function.st_size < 8U * sizeof(uint32_t) ||
        function.st_size > 2048U || (function.st_value & 3U) != 0 ||
        (function.st_size & 3U) != 0 ||
        !dlfrz_glibc_vaddr_executable_file_range(
            view.elf, view.elf_size, &view.ehdr,
            function.st_value, function.st_size) ||
        !dlfrz_glibc_glro_got_relocation(&view, &glro_got_vaddr) ||
        !dlfrz_glibc_vaddr_file_range(
            view.elf, view.elf_size, &view.ehdr,
            function.st_value, function.st_size, &function_offset))
        return 0;
    code = view.elf + function_offset;
    if (dlfrz_glibc_read_u32(code) == bti_c)
        cursor += sizeof(uint32_t);
    if (cursor + 2U * sizeof(uint32_t) <= function.st_size &&
        dlfrz_glibc_read_u32(code + cursor) == frame_push &&
        dlfrz_glibc_read_u32(code + cursor + sizeof(uint32_t)) ==
            frame_pointer) {
        framed = 1;
        cursor += 2U * sizeof(uint32_t);
    }
    if (cursor + 4U * sizeof(uint32_t) > function.st_size ||
        dlfrz_glibc_read_u32(code + cursor) != cmp_hwcap ||
        !dlfrz_glibc_aarch64_getauxval_branch_target(
            dlfrz_glibc_read_u32(code + cursor + sizeof(uint32_t)),
            function.st_value + cursor + sizeof(uint32_t), &targets[0]) ||
        dlfrz_glibc_read_u32(
            code + cursor + 2U * sizeof(uint32_t)) != cmp_hwcap2 ||
        !dlfrz_glibc_aarch64_getauxval_branch_target(
            dlfrz_glibc_read_u32(
                code + cursor + 3U * sizeof(uint32_t)),
            function.st_value + cursor + 3U * sizeof(uint32_t),
            &targets[1]))
        return 0;

    scan_size = (size_t)function.st_size;
    if (scan_size > 64U)
        scan_size = 64U;
    for (size_t position = 0;
         position + 4U * sizeof(uint32_t) <= scan_size;
         position += sizeof(uint32_t)) {
        uint64_t ignored;

        if (dlfrz_glibc_read_u32(code + position) == cmp_hwcap &&
            dlfrz_glibc_aarch64_getauxval_branch_target(
                dlfrz_glibc_read_u32(
                    code + position + sizeof(uint32_t)),
                function.st_value + position + sizeof(uint32_t),
                &ignored) &&
            dlfrz_glibc_read_u32(
                code + position + 2U * sizeof(uint32_t)) == cmp_hwcap2 &&
            dlfrz_glibc_aarch64_getauxval_branch_target(
                dlfrz_glibc_read_u32(
                    code + position + 3U * sizeof(uint32_t)),
                function.st_value + position + 3U * sizeof(uint32_t),
                &ignored))
            quartet_count++;
    }
    if (quartet_count != 1 ||
        !dlfrz_glibc_aarch64_getauxval_leaf_valid(
            code, (size_t)function.st_size, function.st_value,
            targets[0], glro_got_vaddr, glro_size, framed, &leaves[0]) ||
        !dlfrz_glibc_aarch64_getauxval_leaf_valid(
            code, (size_t)function.st_size, function.st_value,
            targets[1], glro_got_vaddr, glro_size, framed, &leaves[1]))
        return 0;

    if ((leaves[0].start < leaves[1].end &&
         leaves[1].start < leaves[0].end) ||
        leaves[0].field_offset == leaves[1].field_offset ||
        (framed && leaves[0].restore_before_field !=
                       leaves[1].restore_before_field))
        return 0;
    contract.hwcap_offset = leaves[0].field_offset;
    contract.hwcap2_offset = leaves[1].field_offset;
    evidence.dispatcher_file_offset = function_offset + cursor;
    for (size_t i = 0; i < 2; i++) {
        evidence.branch_file_offsets[i] =
            function_offset + cursor +
            (i == 0 ? 1U : 3U) * sizeof(uint32_t);
        evidence.adrp_file_offsets[i] =
            function_offset + leaves[i].adrp_position;
        evidence.got_load_file_offsets[i] =
            function_offset + leaves[i].got_load_position;
        evidence.field_load_file_offsets[i] =
            function_offset + leaves[i].field_load_position;
        if (leaves[i].restore_position != SIZE_MAX)
            evidence.restore_file_offsets[i] =
                function_offset + leaves[i].restore_position;
    }
    if (contract_out)
        *contract_out = contract;
    if (evidence_out)
        *evidence_out = evidence;
    return 1;
}

/* Mark every instruction reachable through the bounded direct-control-flow
 * subset admitted by the CPU initializer decoder.  Direct calls inside the
 * supplied range are part of the closure; indirect transfers and unknown
 * instruction forms fail closed. */
static inline int
dlfrz_glibc_x86_reachable_instructions(
    const unsigned char *code, size_t code_size, uint64_t code_vaddr,
    unsigned char *instruction_state, size_t state_size)
{
    enum { DLFRZ_X86_REACHABLE_MAX_BLOCKS = 4096 };
    uint16_t worklist[DLFRZ_X86_REACHABLE_MAX_BLOCKS];
    size_t head = 0;
    size_t tail = 0;

    if (!code || !instruction_state || code_size == 0 ||
        code_size > 32768 || state_size <= code_size)
        return 0;
    memset(instruction_state, 0, state_size);
    instruction_state[0] = DLFRZ_X86_INSN_START |
                           DLFRZ_X86_INSN_QUEUED;
    worklist[tail++] = 0;
    while (head < tail) {
        size_t position = worklist[head++];

        instruction_state[position] &=
            (unsigned char)~DLFRZ_X86_INSN_QUEUED;
        if (instruction_state[position] & DLFRZ_X86_INSN_DECODED)
            continue;
        while (position < code_size) {
            struct dlfrz_glibc_x86_instruction instruction;
            size_t next;

            if (instruction_state[position] & DLFRZ_X86_INSN_INTERIOR)
                return 0;
            if (instruction_state[position] & DLFRZ_X86_INSN_DECODED)
                break;
            if (!dlfrz_glibc_x86_instruction(
                    code + position, code_size - position, &instruction) ||
                instruction.length > code_size - position)
                return 0;
            next = position + instruction.length;
            instruction_state[position] |= DLFRZ_X86_INSN_START |
                                           DLFRZ_X86_INSN_DECODED;
            for (size_t byte = position + 1; byte < next; byte++) {
                if (instruction_state[byte] & DLFRZ_X86_INSN_START)
                    return 0;
                instruction_state[byte] |= DLFRZ_X86_INSN_INTERIOR;
            }
            if (instruction.direct_branch ||
                instruction.conditional_branch ||
                instruction.direct_call) {
                uint64_t target_vaddr;

                if (code_vaddr > UINT64_MAX - next ||
                    !dlfrz_glibc_add_signed_u64(
                        code_vaddr + next,
                        instruction.branch_displacement, &target_vaddr))
                    return 0;
                if (target_vaddr >= code_vaddr &&
                    target_vaddr - code_vaddr < code_size) {
                    size_t target_position =
                        (size_t)(target_vaddr - code_vaddr);

                    if (instruction_state[target_position] &
                            DLFRZ_X86_INSN_INTERIOR)
                        return 0;
                    instruction_state[target_position] |=
                        DLFRZ_X86_INSN_START;
                    if (!(instruction_state[target_position] &
                          (DLFRZ_X86_INSN_QUEUED |
                           DLFRZ_X86_INSN_DECODED))) {
                        if (tail >= DLFRZ_X86_REACHABLE_MAX_BLOCKS)
                            return 0;
                        instruction_state[target_position] |=
                            DLFRZ_X86_INSN_QUEUED;
                        worklist[tail++] = (uint16_t)target_position;
                    }
                }
            }
            if (instruction.direct_branch || instruction.terminal)
                break;
            position = next;
        }
    }
    instruction_state[code_size] = DLFRZ_X86_INSN_START |
                                   DLFRZ_X86_INSN_DECODED;
    return 1;
}

/* Starting with glibc 2.38, update_active consumes GLRO(dl_hwcap2) while
 * constructing the active feature bitmap.  Prove that the initializer's
 * reachable direct-call closure contains exactly one helper rooted at the
 * same HWCAP2 offset recovered from target libc. */
static inline int
dlfrz_glibc_x86_cpu_hwcap2_association_valid(
    const void *data, size_t elf_size, uint64_t glro_vaddr,
    const struct dlfrz_glibc_x86_cpu_contract *cpu_contract,
    const struct dlfrz_glibc_getauxval_contract *aux_contract,
    size_t *hwcap2_displacement_file_offset_out)
{
    enum {
        DLFRZ_X86_HWCAP2_CLOSURE_LIMIT = 8192,
        DLFRZ_X86_HWCAP2_HELPER_LIMIT = 1024
    };
    struct dlfrz_elf64_dyn_view view;
    const unsigned char *initializer_code;
    unsigned char initializer_state[32769];
    size_t initializer_offset;
    size_t initializer_size;
    uint64_t selected_helper = 0;
    size_t selected_displacement = 0;
    unsigned int selected_helpers = 0;

    if (!cpu_contract || !aux_contract ||
        cpu_contract->wrapper_vaddr <= cpu_contract->initializer_vaddr ||
        cpu_contract->wrapper_vaddr - cpu_contract->initializer_vaddr >
            32768 ||
        glro_vaddr > UINT64_MAX - aux_contract->hwcap2_offset ||
        !dlfrz_elf64_dyn_view_init(data, elf_size, &view) ||
        view.ehdr.e_machine != EM_X86_64)
        return 0;
    initializer_size = (size_t)(cpu_contract->wrapper_vaddr -
                                cpu_contract->initializer_vaddr);
    if (!dlfrz_glibc_vaddr_file_range(
            view.elf, view.elf_size, &view.ehdr,
            cpu_contract->initializer_vaddr, initializer_size,
            &initializer_offset) ||
        !dlfrz_glibc_vaddr_executable_file_range(
            view.elf, view.elf_size, &view.ehdr,
            cpu_contract->initializer_vaddr, initializer_size))
        return 0;
    initializer_code = view.elf + initializer_offset;
    if (!dlfrz_glibc_x86_reachable_instructions(
            initializer_code, initializer_size,
            cpu_contract->initializer_vaddr, initializer_state,
            sizeof(initializer_state)))
        return 0;

    for (size_t position = 0; position < initializer_size;) {
        struct dlfrz_glibc_x86_instruction instruction;
        uint64_t next_vaddr;
        uint64_t helper_vaddr;
        size_t helper_size;
        size_t helper_offset;
        const unsigned char *helper_code;
        size_t helper_matches = 0;
        size_t helper_displacement = 0;
        int helper_complete = 0;

        if (!(initializer_state[position] & DLFRZ_X86_INSN_DECODED)) {
            position++;
            continue;
        }
        if (!dlfrz_glibc_x86_instruction(
                initializer_code + position,
                initializer_size - position, &instruction) ||
            instruction.length > initializer_size - position)
            return 0;
        if (!instruction.direct_call) {
            position += instruction.length;
            continue;
        }
        if (cpu_contract->initializer_vaddr > UINT64_MAX - position -
                instruction.length)
            return 0;
        next_vaddr = cpu_contract->initializer_vaddr + position +
                     instruction.length;
        if (!dlfrz_glibc_add_signed_u64(
                next_vaddr, instruction.branch_displacement,
                &helper_vaddr))
            return 0;
        if (helper_vaddr >= cpu_contract->initializer_vaddr ||
            cpu_contract->initializer_vaddr - helper_vaddr >
                DLFRZ_X86_HWCAP2_CLOSURE_LIMIT) {
            position += instruction.length;
            continue;
        }
        helper_size = (size_t)(cpu_contract->initializer_vaddr -
                               helper_vaddr);
        /* This is a direct-call target, but stripped ld.so has no reliable
         * function-size metadata for it.  Do not let one candidate claim a
         * witness in a later helper merely because both precede the CPU
         * initializer in the same text range.  update_active's admitted
         * 2.38--2.44 bodies carry the HWCAP2 test within their first KiB. */
        if (helper_size > DLFRZ_X86_HWCAP2_HELPER_LIMIT)
            helper_size = DLFRZ_X86_HWCAP2_HELPER_LIMIT;
        if (!dlfrz_glibc_vaddr_file_range(
                view.elf, view.elf_size, &view.ehdr,
                helper_vaddr, helper_size, &helper_offset) ||
            !dlfrz_glibc_vaddr_executable_file_range(
                view.elf, view.elf_size, &view.ehdr,
                helper_vaddr, helper_size))
            return 0;
        helper_code = view.elf + helper_offset;
        for (size_t helper_position = 0; helper_position < helper_size;) {
            struct dlfrz_glibc_x86_instruction helper_instruction;
            int32_t displacement;
            uint64_t target;

            /* Establish a conservative entry-owned body boundary.  The
             * target helper must decode linearly from its direct-call entry
             * through a return/tail branch, and the exact HWCAP2 test must
             * begin at an instruction boundary before that terminator.
             * This prevents an earlier adjacent helper from borrowing the
             * same byte sequence out of update_active. */
            if (!dlfrz_glibc_x86_instruction(
                    helper_code + helper_position,
                    helper_size - helper_position,
                    &helper_instruction) ||
                helper_instruction.length >
                    helper_size - helper_position) {
                helper_matches = 0;
                break;
            }
            if (helper_position + 9 <= helper_size &&
                helper_instruction.length == 7 &&
                helper_code[helper_position] == UINT8_C(0xf6) &&
                helper_code[helper_position + 1] == UINT8_C(0x05) &&
                helper_code[helper_position + 6] == UINT8_C(0x02) &&
                helper_code[helper_position + 7] == UINT8_C(0x74) &&
                (helper_code[helper_position + 8] == UINT8_C(0x09) ||
                 helper_code[helper_position + 8] == UINT8_C(0x0b))) {
                memcpy(&displacement,
                       helper_code + helper_position + 2,
                       sizeof(displacement));
                if (helper_vaddr > UINT64_MAX - helper_position - 7 ||
                    !dlfrz_glibc_add_signed_u64(
                        helper_vaddr + helper_position + 7,
                        displacement, &target))
                    return 0;
                if (target ==
                        glro_vaddr + aux_contract->hwcap2_offset) {
                    helper_matches++;
                    helper_displacement = helper_offset +
                                          helper_position + 2;
                }
            }
            if (helper_instruction.direct_branch ||
                helper_instruction.terminal) {
                helper_complete = 1;
                break;
            }
            helper_position += helper_instruction.length;
        }
        if (!helper_complete) {
            position += instruction.length;
            continue;
        }
        if (helper_matches > 1)
            return 0;
        if (helper_matches == 1 && helper_vaddr != selected_helper) {
            selected_helper = helper_vaddr;
            selected_displacement = helper_displacement;
            selected_helpers++;
        }
        position += instruction.length;
    }
    if (selected_helpers != 1)
        return 0;
    if (hwcap2_displacement_file_offset_out)
        *hwcap2_displacement_file_offset_out = selected_displacement;
    return 1;
}

/* Identify musl's combined dynamic-linker/libc object from stable dynamic
 * ABI structure.  Some distributions omit DT_SONAME; when present it must
 * be musl's canonical architecture SONAME.  Renaming the file itself never
 * changes this result. */
static inline int
dlfrz_musl_rtld_identity(const void *data, size_t elf_size)
{
    static const struct {
        const char *name;
        unsigned char binding;
    } libc_functions[] = {
        { "__libc_start_main", STB_GLOBAL },
        { "__errno_location", STB_GLOBAL },
        { "__tls_get_addr", STB_GLOBAL },
        { "pthread_kill", STB_GLOBAL },
        { "pthread_create", STB_WEAK },
        { "pthread_detach", STB_WEAK },
        { "pthread_self", STB_WEAK },
    };
    struct dlfrz_elf64_dyn_view view;
    Elf64_Sym dlstart;
    Elf64_Sym dls3;
    Elf64_Sym debug_addr;
    const char *soname;
    const char *expected_soname;
    const char *interpreter_soname;
    uint64_t dlstart_size;
    uint64_t dls3_size;

    if (!dlfrz_elf64_dyn_view_init(data, elf_size, &view) ||
        view.has_interp || view.have_versym || view.have_verdef ||
        view.have_verneed ||
        view.needed_count != 0 ||
        dlfrz_elf64_dyn_view_find(
            &view, "_dlstart", &dlstart, NULL) != 1 ||
        dlfrz_elf64_dyn_view_find(&view, "__dls3", &dls3, NULL) != 1 ||
        dlfrz_elf64_dyn_view_find(
            &view, "_dl_debug_addr", &debug_addr, NULL) != 1)
        return 0;

    if (view.ehdr.e_machine == EM_X86_64) {
        expected_soname = "libc.musl-x86_64.so.1";
        interpreter_soname = "ld-musl-x86_64.so.1";
    } else if (view.ehdr.e_machine == EM_AARCH64) {
        expected_soname = "libc.musl-aarch64.so.1";
        interpreter_soname = "ld-musl-aarch64.so.1";
    } else {
        return 0;
    }
    if (view.have_soname) {
        soname = (const char *)view.elf + view.dynstr_offset +
                 (size_t)view.soname_offset;
        /* The combined object can name either its libc or its interpreter
         * ABI.  Neither spelling replaces the structural checks below. */
        if (strcmp(soname, expected_soname) != 0 &&
            strcmp(soname, interpreter_soname) != 0)
            return 0;
    }

    dlstart_size = dlstart.st_size ? dlstart.st_size : 1;
    dls3_size = dls3.st_size ? dls3.st_size : 1;
    if (ELF64_ST_BIND(dlstart.st_info) != STB_GLOBAL ||
        (ELF64_ST_TYPE(dlstart.st_info) != STT_FUNC &&
         ELF64_ST_TYPE(dlstart.st_info) != STT_NOTYPE) ||
        ELF64_ST_VISIBILITY(dlstart.st_other) != STV_DEFAULT ||
        dlstart.st_shndx == SHN_UNDEF ||
        dlstart.st_shndx >= SHN_LORESERVE || dlstart.st_value == 0 ||
        dlstart.st_value != view.ehdr.e_entry ||
        !dlfrz_glibc_vaddr_executable_file_range(
            view.elf, view.elf_size, &view.ehdr, dlstart.st_value,
            dlstart_size) ||
        ELF64_ST_BIND(dls3.st_info) != STB_GLOBAL ||
        ELF64_ST_TYPE(dls3.st_info) != STT_FUNC ||
        ELF64_ST_VISIBILITY(dls3.st_other) != STV_DEFAULT ||
        dls3.st_shndx == SHN_UNDEF || dls3.st_shndx >= SHN_LORESERVE ||
        dls3.st_value == 0 ||
        !dlfrz_glibc_vaddr_executable_file_range(
            view.elf, view.elf_size, &view.ehdr, dls3.st_value,
            dls3_size) ||
        ELF64_ST_BIND(debug_addr.st_info) != STB_GLOBAL ||
        ELF64_ST_TYPE(debug_addr.st_info) != STT_OBJECT ||
        ELF64_ST_VISIBILITY(debug_addr.st_other) != STV_DEFAULT ||
        debug_addr.st_shndx == SHN_UNDEF ||
        debug_addr.st_shndx >= SHN_LORESERVE ||
        debug_addr.st_value == 0 || debug_addr.st_size != sizeof(uint64_t) ||
        !dlfrz_glibc_vaddr_writable_mem_range(
            view.elf, view.elf_size, &view.ehdr, debug_addr.st_value,
            debug_addr.st_size))
        return 0;

    /* These are the stable callable ABI surface consumed by musl startup,
     * TLS, errno, and threading—not release- or application-specific names.
     * Requiring both loader internals and this libc surface distinguishes the
     * combined musl object from a small marker-bearing loader-shaped DSO. */
    for (size_t i = 0;
         i < sizeof(libc_functions) / sizeof(libc_functions[0]); i++) {
        Elf64_Sym symbol;

        if (dlfrz_elf64_dyn_view_find(
                &view, libc_functions[i].name, &symbol, NULL) != 1 ||
            ELF64_ST_BIND(symbol.st_info) != libc_functions[i].binding ||
            ELF64_ST_TYPE(symbol.st_info) != STT_FUNC ||
            ELF64_ST_VISIBILITY(symbol.st_other) != STV_DEFAULT ||
            symbol.st_shndx == SHN_UNDEF ||
            symbol.st_shndx >= SHN_LORESERVE || symbol.st_value == 0 ||
            symbol.st_size == 0 ||
            !dlfrz_glibc_vaddr_executable_file_range(
                view.elf, view.elf_size, &view.ehdr, symbol.st_value,
                symbol.st_size))
            return 0;
    }
    return 1;
}

static inline void
dlfrz_glibc_mark_glro_reloc_target(const uint64_t *targets,
                                    size_t target_count, uint64_t target,
                                    unsigned int *found_mask)
{
    for (size_t i = 0; i < target_count; i++) {
        if (targets[i] == target)
            *found_mask |= 1U << i;
    }
}

/* Validate the exact function-pointer relocation targets used as positive
 * evidence for a selected glibc private layout.  Only bounded ELF64
 * little-endian PT_DYNAMIC metadata is accepted.  RELA entries must be the
 * architecture's RELATIVE relocation; RELR targets are relative by design. */
static inline int
dlfrz_glibc_glro_relocations_valid(
    const void *data, size_t elf_size, enum dlfrz_glibc_layout_id layout,
    uint64_t glro_vaddr, uint64_t glro_size)
{
    const unsigned char *elf = (const unsigned char *)data;
    struct dlfrz_glibc_glro_reloc_profile profile;
    Elf64_Ehdr ehdr;
    Elf64_Phdr dynamic_phdr = {0};
    uint64_t targets[6];
    int offsets[6];
    size_t target_count = 0;
    unsigned int found_mask = 0;
    unsigned int required_mask;
    int dynamic_found = 0;
    int dynamic_terminated = 0;
    uint64_t rela_vaddr = 0, rela_size = 0, rela_ent = 0;
    uint64_t relr_vaddr = 0, relr_size = 0, relr_ent = 0;
    int have_rela_vaddr = 0, have_rela_size = 0, have_rela_ent = 0;
    int have_relr_vaddr = 0, have_relr_size = 0, have_relr_ent = 0;

    if (!elf || elf_size < sizeof(ehdr) ||
        !dlfrz_glibc_glro_reloc_profile(layout, &profile))
        return 0;
    memcpy(&ehdr, elf, sizeof(ehdr));
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr.e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr.e_ident[EI_VERSION] != EV_CURRENT ||
        ehdr.e_version != EV_CURRENT || ehdr.e_type != ET_DYN ||
        ehdr.e_machine != profile.machine ||
        ehdr.e_phentsize != sizeof(Elf64_Phdr) || ehdr.e_phnum == 0 ||
        ehdr.e_phnum == PN_XNUM || ehdr.e_phoff > elf_size ||
        (size_t)ehdr.e_phnum >
            (elf_size - (size_t)ehdr.e_phoff) / sizeof(Elf64_Phdr))
        return 0;

    offsets[0] = profile.debug_printf;
    offsets[1] = profile.mcount;
    offsets[2] = profile.open;
    offsets[3] = profile.close;
    offsets[4] = profile.catch_error;
    offsets[5] = profile.error_free;
    for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        uint64_t offset;

        if (offsets[i] < 0)
            continue;
        offset = (uint64_t)offsets[i];
        if ((offset & (sizeof(uint64_t) - 1)) != 0 ||
            offset > glro_size || sizeof(uint64_t) > glro_size - offset ||
            glro_vaddr > UINT64_MAX - offset)
            return 0;
        targets[target_count++] = glro_vaddr + offset;
    }
    if (target_count == 0)
        return 1;
    required_mask = (1U << target_count) - 1U;

    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;

        if (!dlfrz_glibc_read_phdr(elf, elf_size, &ehdr, i, &phdr))
            return 0;
        if (phdr.p_type != PT_DYNAMIC)
            continue;
        if (dynamic_found || phdr.p_offset > elf_size ||
            phdr.p_filesz > (uint64_t)elf_size - phdr.p_offset ||
            phdr.p_filesz == 0 ||
            phdr.p_filesz % sizeof(Elf64_Dyn) != 0)
            return 0;
        dynamic_phdr = phdr;
        dynamic_found = 1;
    }
    if (!dynamic_found)
        return 0;

    for (uint64_t pos = 0; pos < dynamic_phdr.p_filesz;
         pos += sizeof(Elf64_Dyn)) {
        Elf64_Dyn dyn;
        size_t offset = (size_t)dynamic_phdr.p_offset + (size_t)pos;
        uint64_t value;

        memcpy(&dyn, elf + offset, sizeof(dyn));
        if (dyn.d_tag == DT_NULL) {
            dynamic_terminated = 1;
            break;
        }
        value = dyn.d_un.d_val;
#define DLFRZ_GLIBC_DYNAMIC_VALUE(tag, have, slot)                         \
        case tag:                                                          \
            if (have && slot != value)                                     \
                return 0;                                                   \
            have = 1;                                                       \
            slot = value;                                                   \
            break
        switch (dyn.d_tag) {
        DLFRZ_GLIBC_DYNAMIC_VALUE(DT_RELA, have_rela_vaddr, rela_vaddr);
        DLFRZ_GLIBC_DYNAMIC_VALUE(DT_RELASZ, have_rela_size, rela_size);
        DLFRZ_GLIBC_DYNAMIC_VALUE(DT_RELAENT, have_rela_ent, rela_ent);
        DLFRZ_GLIBC_DYNAMIC_VALUE(DT_RELR, have_relr_vaddr, relr_vaddr);
        DLFRZ_GLIBC_DYNAMIC_VALUE(DT_RELRSZ, have_relr_size, relr_size);
        DLFRZ_GLIBC_DYNAMIC_VALUE(DT_RELRENT, have_relr_ent, relr_ent);
        default:
            break;
        }
#undef DLFRZ_GLIBC_DYNAMIC_VALUE
    }
    if (!dynamic_terminated)
        return 0;

    if (have_rela_vaddr || have_rela_size || have_rela_ent) {
        size_t rela_offset;
        uint32_t relative_type = profile.machine == EM_X86_64 ? 8U : 1027U;

        if (!have_rela_vaddr || !have_rela_size || !have_rela_ent ||
            rela_ent != sizeof(Elf64_Rela) ||
            rela_size % sizeof(Elf64_Rela) != 0 ||
            !dlfrz_glibc_vaddr_file_range(elf, elf_size, &ehdr, rela_vaddr,
                                          rela_size, &rela_offset))
            return 0;
        for (uint64_t pos = 0; pos < rela_size; pos += sizeof(Elf64_Rela)) {
            Elf64_Rela rela;

            memcpy(&rela, elf + rela_offset + (size_t)pos, sizeof(rela));
            if (ELF64_R_TYPE(rela.r_info) == relative_type)
                dlfrz_glibc_mark_glro_reloc_target(
                    targets, target_count, rela.r_offset, &found_mask);
        }
    }

    if (have_relr_vaddr || have_relr_size || have_relr_ent) {
        size_t relr_offset;
        uint64_t where = 0;
        int have_where = 0;

        if (!have_relr_vaddr || !have_relr_size || !have_relr_ent ||
            relr_ent != sizeof(uint64_t) ||
            relr_size % sizeof(uint64_t) != 0 ||
            !dlfrz_glibc_vaddr_file_range(elf, elf_size, &ehdr, relr_vaddr,
                                          relr_size, &relr_offset))
            return 0;
        for (uint64_t pos = 0; pos < relr_size; pos += sizeof(uint64_t)) {
            uint64_t entry;

            memcpy(&entry, elf + relr_offset + (size_t)pos, sizeof(entry));
            if ((entry & 1U) == 0) {
                if ((entry & (sizeof(uint64_t) - 1)) != 0 ||
                    entry > UINT64_MAX - sizeof(uint64_t))
                    return 0;
                dlfrz_glibc_mark_glro_reloc_target(
                    targets, target_count, entry, &found_mask);
                where = entry + sizeof(uint64_t);
                have_where = 1;
            } else {
                if (!have_where ||
                    where > UINT64_MAX - 63U * sizeof(uint64_t))
                    return 0;
                for (unsigned int bit = 0; bit < 63; bit++) {
                    if (entry & (UINT64_C(2) << bit))
                        dlfrz_glibc_mark_glro_reloc_target(
                            targets, target_count,
                            where + (uint64_t)bit * sizeof(uint64_t),
                            &found_mask);
                }
                where += 63U * sizeof(uint64_t);
            }
        }
    }

    return found_mask == required_mask;
}

/* Find an exact byte literal without examining every non-candidate position
 * in scalar code.  libc's memchr is substantially cheaper for the multi-MiB
 * interpreter/libc images inspected during bootstrap, while the final
 * memcmp remains authoritative. */
static inline const unsigned char *
dlfrz_glibc_find_literal_from_byte(const unsigned char *bytes, size_t size,
                                   size_t start, const char *literal,
                                   size_t literal_size,
                                   size_t search_byte)
{
    size_t candidate_limit;
    size_t search;

    if (!bytes || !literal || literal_size == 0 || start > size ||
        literal_size > size - start || search_byte >= literal_size)
        return NULL;
    candidate_limit = size - literal_size;
    search = start + search_byte;
    while (search <= candidate_limit + search_byte) {
        const unsigned char *matched =
            (const unsigned char *)memchr(
                bytes + search, (unsigned char)literal[search_byte],
                candidate_limit + search_byte - search + 1U);
        size_t matched_offset;
        size_t candidate;

        if (!matched)
            return NULL;
        matched_offset = (size_t)(matched - bytes);
        candidate = matched_offset - search_byte;
        if (memcmp(bytes + candidate, literal, literal_size) == 0)
            return bytes + candidate;
        search = matched_offset + 1U;
    }
    return NULL;
}

static inline const unsigned char *
dlfrz_glibc_find_literal(const unsigned char *bytes, size_t size,
                         size_t start, const char *literal,
                         size_t literal_size)
{
    return dlfrz_glibc_find_literal_from_byte(
        bytes, size, start, literal, literal_size, 0);
}

struct dlfrz_glibc_release_profile_state {
    int stable_minor;
    int stable_invalid;
    int development;
};

static inline void
dlfrz_glibc_release_profile_state_init(
    struct dlfrz_glibc_release_profile_state *state)
{
    state->stable_minor = -1;
    state->stable_invalid = 0;
    state->development = 0;
}

/* Accumulate one independent byte range.  Callers which inspect multiple
 * ELF segments retain STATE between calls, but deliberately reset literal
 * matching at each segment boundary so disjoint file ranges cannot
 * synthesize a witness. */
static inline void
dlfrz_glibc_release_profile_accumulate(
    const unsigned char *bytes, size_t size,
    struct dlfrz_glibc_release_profile_state *state,
    int want_stable, int want_development)
{
    static const char anchor[] = "release version";
    static const char development_prefix[] = "development ";
    static const char stable_prefix[] = "stable ";
    static const char stable_suffix[] = " 2.";
    size_t search = 0;

    if (!bytes || !state ||
        ((!want_development || state->development) &&
         (!want_stable || state->stable_invalid)))
        return;
    while (want_stable || want_development) {
        const unsigned char *match = dlfrz_glibc_find_literal_from_byte(
            bytes, size, search, anchor, sizeof(anchor) - 1, 8U);
        size_t i;
        size_t after;

        if (!match)
            break;
        i = (size_t)(match - bytes);
        after = i + sizeof(anchor) - 1;
        search = i + 1;

        if (want_development && !state->development) {
            size_t p;

            /* The explicit marker has no required trailing byte, so this
             * also recognizes a marker ending exactly at EOF. */
            if (i >= sizeof(development_prefix) - 1 &&
                memcmp(bytes + i - (sizeof(development_prefix) - 1),
                       development_prefix,
                       sizeof(development_prefix) - 1) == 0) {
                state->development = 1;
            } else if (after < size && bytes[after] == ' ') {
                p = after + 1;
                while (p < size && bytes[p] >= '0' && bytes[p] <= '9')
                    p++;
                if (p < size && bytes[p++] == '.') {
                    while (p < size && bytes[p] >= '0' && bytes[p] <= '9')
                        p++;
                    if (p + 1 < size && bytes[p] == '.' &&
                        bytes[p + 1] >= '0' && bytes[p + 1] <= '9')
                        state->development = 1;
                }
            }
        }

        if (want_stable && !state->stable_invalid &&
            i >= sizeof(stable_prefix) - 1 &&
            memcmp(bytes + i - (sizeof(stable_prefix) - 1), stable_prefix,
                   sizeof(stable_prefix) - 1) == 0 &&
            sizeof(stable_suffix) - 1 <= size - after &&
            memcmp(bytes + after, stable_suffix,
                   sizeof(stable_suffix) - 1) == 0) {
            size_t p = after + sizeof(stable_suffix) - 1;
            int minor = 0;
            int have_digit = 0;

            while (p < size && bytes[p] >= '0' && bytes[p] <= '9') {
                if (minor > 1000) {
                    state->stable_invalid = 1;
                    break;
                }
                minor = minor * 10 + (int)(bytes[p] - '0');
                have_digit = 1;
                p++;
            }
            if (!have_digit ||
                (state->stable_minor >= 0 &&
                 state->stable_minor != minor))
                state->stable_invalid = 1;
            else
                state->stable_minor = minor;
        }

        if ((!want_development || state->development) &&
            (!want_stable || state->stable_invalid))
            break;
    }
}

static inline void
dlfrz_glibc_release_profile_state_finish(
    const struct dlfrz_glibc_release_profile_state *state,
    int *stable_minor_out, int *development_out)
{
    if (stable_minor_out)
        *stable_minor_out = state->stable_invalid
            ? -1 : state->stable_minor;
    if (development_out)
        *development_out = state->development;
}

/* Collect the stable minor and development-snapshot verdict in one bounded,
 * monotonic search.  All three accepted witnesses contain the exact
 * "release version" anchor: the explicit development marker has the
 * "development " prefix, the stable banner has the "stable " prefix and
 * " 2." suffix, and the generic snapshot form has a space followed by its
 * numeric components.  Matching the common anchor once avoids rescanning a
 * multi-MiB interpreter or libc while retaining exact byte-literal checks.
 * Malformed/conflicting stable banners remain fail-closed. */
static inline void
dlfrz_glibc_release_profile(const void *data, size_t size,
                            int *stable_minor_out,
                            int *development_out)
{
    struct dlfrz_glibc_release_profile_state state;

    dlfrz_glibc_release_profile_state_init(&state);
    if (data)
        dlfrz_glibc_release_profile_accumulate(
            (const unsigned char *)data, size, &state,
            stable_minor_out != NULL, development_out != NULL);
    dlfrz_glibc_release_profile_state_finish(
        &state, stable_minor_out, development_out);
}

/* Establish one canonical PT_LOAD envelope before immutable ELF bytes are
 * used as runtime identity.  File-backed and virtual ranges must both be
 * monotonic and non-overlapping.  The virtual proof includes p_memsz, so a
 * writable BSS mapping cannot alias a supposedly immutable file witness.
 * Keeping this geometry gate shared makes release banners and compiled
 * configuration paths use exactly the same admission contract. */
static inline int
dlfrz_glibc_immutable_elf_loads(const unsigned char *elf, size_t elf_size,
                                Elf64_Ehdr *ehdr_out)
{
    Elf64_Ehdr ehdr;
    uint64_t previous_load_vaddr = 0;
    uint64_t previous_file_end = 0;
    uint64_t previous_memory_end = 0;
    int have_nonempty_file = 0;
    int have_nonempty_memory = 0;
    int load_found = 0;

    if (!elf || elf_size < sizeof(ehdr))
        return 0;
    memcpy(&ehdr, elf, sizeof(ehdr));
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr.e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr.e_ident[EI_VERSION] != EV_CURRENT ||
        ehdr.e_version != EV_CURRENT || ehdr.e_type != ET_DYN ||
        (ehdr.e_machine != EM_X86_64 &&
         ehdr.e_machine != EM_AARCH64) ||
        ehdr.e_ehsize != sizeof(ehdr) ||
        ehdr.e_phentsize != sizeof(Elf64_Phdr) || ehdr.e_phnum == 0 ||
        ehdr.e_phnum == PN_XNUM || ehdr.e_phoff > elf_size ||
        (size_t)ehdr.e_phnum >
            (elf_size - (size_t)ehdr.e_phoff) / sizeof(Elf64_Phdr))
        return 0;

    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;

        if (!dlfrz_glibc_read_phdr(elf, elf_size, &ehdr, i, &phdr))
            return 0;
        if (phdr.p_type != PT_LOAD)
            continue;
        if (phdr.p_filesz > phdr.p_memsz || phdr.p_offset > elf_size ||
            phdr.p_filesz > (uint64_t)elf_size - phdr.p_offset ||
            phdr.p_vaddr > UINT64_MAX - phdr.p_memsz)
            return 0;
        if (load_found && phdr.p_vaddr < previous_load_vaddr)
            return 0;
        previous_load_vaddr = phdr.p_vaddr;
        load_found = 1;
        if (phdr.p_memsz != 0) {
            uint64_t memory_end = phdr.p_vaddr + phdr.p_memsz;

            if (have_nonempty_memory &&
                phdr.p_vaddr < previous_memory_end)
                return 0;
            previous_memory_end = memory_end;
            have_nonempty_memory = 1;
        }
        if (phdr.p_filesz != 0) {
            uint64_t file_end = phdr.p_offset + phdr.p_filesz;

            if (have_nonempty_file && phdr.p_offset < previous_file_end)
                return 0;
            previous_file_end = file_end;
            have_nonempty_file = 1;
        }
    }
    if (!load_found || !have_nonempty_file || !have_nonempty_memory)
        return 0;
    if (ehdr_out)
        *ehdr_out = ehdr;
    return 1;
}

struct dlfrz_glibc_config_path_match {
    const unsigned char *bytes;
    size_t size;
    int ambiguous;
};

static inline void
dlfrz_glibc_config_path_match_accumulate(
    struct dlfrz_glibc_config_path_match *match,
    const unsigned char *candidate, size_t candidate_size,
    const char *suffix, size_t suffix_size)
{
    if (!match || match->ambiguous || candidate_size < suffix_size ||
        memcmp(candidate + candidate_size - suffix_size,
               suffix, suffix_size) != 0)
        return;
    if (!match->bytes) {
        match->bytes = candidate;
        match->size = candidate_size;
    } else if (match->size != candidate_size ||
               memcmp(match->bytes, candidate, candidate_size) != 0) {
        match->ambiguous = 1;
    }
}

/* Walk one immutable file range once, recognizing both configured glibc
 * paths from complete absolute C strings.  Both identities contain the
 * exact "/ld.so." suffix anchor.  Searching that uncommon literal avoids a
 * memchr restart at every NUL byte in code, relocation data and segment
 * padding.  Only after the complete suffix and its terminating NUL match do
 * we walk backward to the preceding string boundary; those accepted walks
 * are disjoint unless the input contains another suffix anchor in the same
 * string, so total work remains bounded by the input plus its candidates.
 * Literal matching is deliberately reset at each PT_LOAD boundary, so
 * disjoint ranges cannot synthesize a pathname. */
static inline void
dlfrz_glibc_config_paths_accumulate(
    const unsigned char *bytes, size_t size,
    struct dlfrz_glibc_config_path_match *cache,
    struct dlfrz_glibc_config_path_match *preload)
{
    static const char anchor[] = "/ld.so.";
    const size_t anchor_size = sizeof(anchor) - 1U;
    const size_t cache_suffix_size =
        sizeof(DLFRZ_GLIBC_CACHE_SUFFIX) - 1U;
    const size_t preload_suffix_size =
        sizeof(DLFRZ_GLIBC_PRELOAD_SUFFIX) - 1U;
    size_t search = 0;

    if (!bytes)
        return;
    while (search < size) {
        const unsigned char *suffix = dlfrz_glibc_find_literal(
            bytes, size, search, anchor, anchor_size);
        const unsigned char *candidate;
        size_t suffix_position;
        size_t candidate_size;
        size_t matched_suffix_size = 0;

        if (!suffix)
            break;
        suffix_position = (size_t)(suffix - bytes);
        search = suffix_position + 1U;
        if (cache && cache_suffix_size < size - suffix_position &&
            memcmp(suffix, DLFRZ_GLIBC_CACHE_SUFFIX,
                   cache_suffix_size) == 0 &&
            suffix[cache_suffix_size] == '\0') {
            matched_suffix_size = cache_suffix_size;
        } else if (preload &&
                   preload_suffix_size < size - suffix_position &&
                   memcmp(suffix, DLFRZ_GLIBC_PRELOAD_SUFFIX,
                          preload_suffix_size) == 0 &&
                   suffix[preload_suffix_size] == '\0') {
            matched_suffix_size = preload_suffix_size;
        }
        if (matched_suffix_size == 0)
            continue;

        candidate = suffix;
        while (candidate != bytes && candidate[-1] != '\0')
            candidate--;
        if (*candidate != '/')
            continue;
        candidate_size = (size_t)(suffix - candidate) +
                         matched_suffix_size;
        if (matched_suffix_size == cache_suffix_size)
            dlfrz_glibc_config_path_match_accumulate(
                cache, candidate, candidate_size,
                DLFRZ_GLIBC_CACHE_SUFFIX, cache_suffix_size);
        else
            dlfrz_glibc_config_path_match_accumulate(
                preload, candidate, candidate_size,
                DLFRZ_GLIBC_PRELOAD_SUFFIX, preload_suffix_size);
    }
}

static inline int
dlfrz_glibc_address_ranges_overlap(const void *left, size_t left_size,
                                   const void *right, size_t right_size)
{
    uintptr_t left_begin = (uintptr_t)left;
    uintptr_t right_begin = (uintptr_t)right;
    uintptr_t left_end;
    uintptr_t right_end;

    if (left_size == 0 || right_size == 0)
        return 0;
    if (left_begin > UINTPTR_MAX - left_size ||
        right_begin > UINTPTR_MAX - right_size)
        return 1;
    left_end = left_begin + left_size;
    right_end = right_begin + right_size;
    return left_begin < right_end && right_begin < left_end;
}

/* glibc compiles SYSCONFDIR into its interpreter and may therefore consult
 * paths other than /etc/ld.so.cache and /etc/ld.so.preload.  Recover both
 * identities in a single bounded pass over readable, non-writable PT_LOAD
 * file bytes.  Duplicate copies of one exact path are harmless; distinct
 * candidates, truncated strings, mutable aliases, malformed load geometry,
 * and undersized or overlapping output buffers fail closed.
 *
 * A NULL output paired with size zero means that identity is not requested.
 * Return one only when every requested identity has one unique complete
 * witness.  Outputs never alias the ELF input in production; rejecting that
 * unsupported shape also keeps final copies independent of scan storage. */
static inline int
dlfrz_glibc_elf_config_paths(const void *data, size_t elf_size,
                             char *cache_path, size_t cache_path_size,
                             char *preload_path, size_t preload_path_size)
{
    const unsigned char *elf = (const unsigned char *)data;
    struct dlfrz_glibc_config_path_match cache = {0};
    struct dlfrz_glibc_config_path_match preload = {0};
    Elf64_Ehdr ehdr;
    size_t cache_copy_size = 0;
    size_t preload_copy_size = 0;

    if (cache_path && cache_path_size)
        cache_path[0] = '\0';
    if (preload_path && preload_path_size)
        preload_path[0] = '\0';
    if ((!cache_path && cache_path_size != 0) ||
        (cache_path && cache_path_size == 0) ||
        (!preload_path && preload_path_size != 0) ||
        (preload_path && preload_path_size == 0) ||
        (!cache_path && !preload_path) ||
        !dlfrz_glibc_immutable_elf_loads(elf, elf_size, &ehdr))
        return 0;

    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;

        if (!dlfrz_glibc_read_phdr(elf, elf_size, &ehdr, i, &phdr))
            return 0;
        if (phdr.p_type != PT_LOAD || phdr.p_filesz == 0 ||
            !(phdr.p_flags & PF_R) || (phdr.p_flags & PF_W))
            continue;
        dlfrz_glibc_config_paths_accumulate(
            elf + (size_t)phdr.p_offset, (size_t)phdr.p_filesz,
            cache_path ? &cache : NULL,
            preload_path ? &preload : NULL);
    }

    if ((cache_path &&
         (!cache.bytes || cache.ambiguous ||
          cache.size >= cache_path_size)) ||
        (preload_path &&
         (!preload.bytes || preload.ambiguous ||
          preload.size >= preload_path_size)))
        return 0;
    if (cache_path)
        cache_copy_size = cache.size + 1;
    if (preload_path)
        preload_copy_size = preload.size + 1;
    if ((cache_path && dlfrz_glibc_address_ranges_overlap(
             elf, elf_size, cache_path, cache_copy_size)) ||
        (preload_path && dlfrz_glibc_address_ranges_overlap(
             elf, elf_size, preload_path, preload_copy_size)) ||
        (cache_path && preload_path &&
         dlfrz_glibc_address_ranges_overlap(
             cache_path, cache_copy_size,
             preload_path, preload_copy_size)))
        return 0;
    if (cache_path)
        memcpy(cache_path, cache.bytes, cache_copy_size);
    if (preload_path)
        memcpy(preload_path, preload.bytes, preload_copy_size);
    return 1;
}

/* Compatibility for single-identity callers.  This keeps the old call shape
 * safe while routing it through immutable ELF admission; callers needing
 * both paths should use dlfrz_glibc_elf_config_paths() to scan only once. */
static inline int
dlfrz_glibc_config_path(const void *data, size_t data_size,
                        const char *suffix, size_t suffix_size,
                        char *path_out, size_t path_size)
{
    if (suffix && suffix_size == sizeof(DLFRZ_GLIBC_CACHE_SUFFIX) - 1 &&
        memcmp(suffix, DLFRZ_GLIBC_CACHE_SUFFIX, suffix_size) == 0)
        return dlfrz_glibc_elf_config_paths(
            data, data_size, path_out, path_size, NULL, 0);
    if (suffix && suffix_size == sizeof(DLFRZ_GLIBC_PRELOAD_SUFFIX) - 1 &&
        memcmp(suffix, DLFRZ_GLIBC_PRELOAD_SUFFIX, suffix_size) == 0)
        return dlfrz_glibc_elf_config_paths(
            data, data_size, NULL, 0, path_out, path_size);
    if (path_out && path_size)
        path_out[0] = '\0';
    return 0;
}

/* Inspect only immutable runtime bytes when using a release banner as ELF
 * identity.  Requiring PT_LOAD entries and their nonempty file and memory
 * ranges to be monotonically ordered and non-overlapping makes this a linear
 * proof that a byte admitted from a readable, non-writable segment has no
 * exact PF_W file or virtual-address alias.  Memory ranges use p_memsz, so a
 * writable segment's BSS cannot alias admitted file-backed identity bytes.
 * Separate ranges share the conflict/development state but never
 * literal-matching state.
 *
 * Final ELF permissions are page-granular.  Direct-loading callers must also
 * retain their runtime-page overlap gate using the target kernel's AT_PAGESZ;
 * this helper deliberately has no host- or architecture-guessed page size.
 *
 * Return one when the supported ELF envelope and every PT_LOAD range are
 * structurally valid.  A valid ELF can still report no stable witness (-1),
 * or a development witness which callers must reject for direct loading. */
static inline int
dlfrz_glibc_elf_release_profile(const void *data, size_t elf_size,
                                int *stable_minor_out,
                                int *development_out)
{
    const unsigned char *elf = (const unsigned char *)data;
    struct dlfrz_glibc_release_profile_state state;
    Elf64_Ehdr ehdr;

    dlfrz_glibc_release_profile_state_init(&state);
    if (!dlfrz_glibc_immutable_elf_loads(elf, elf_size, &ehdr))
        goto invalid;

    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;

        if (!dlfrz_glibc_read_phdr(elf, elf_size, &ehdr, i, &phdr))
            goto invalid;
        if (phdr.p_type != PT_LOAD || phdr.p_filesz == 0 ||
            !(phdr.p_flags & PF_R) || (phdr.p_flags & PF_W))
            continue;
        dlfrz_glibc_release_profile_accumulate(
            elf + (size_t)phdr.p_offset, (size_t)phdr.p_filesz,
            &state, stable_minor_out != NULL, development_out != NULL);
    }
    dlfrz_glibc_release_profile_state_finish(
        &state, stable_minor_out, development_out);
    return 1;

invalid:
    dlfrz_glibc_release_profile_state_init(&state);
    dlfrz_glibc_release_profile_state_finish(
        &state, stable_minor_out, development_out);
    return 0;
}

/* glibc development snapshots can retain a stable release's size tuple while
 * changing code that consumes private rtld fields.  Reject both the explicit
 * development marker and the snapshot release form (for example 2.43.9000).
 * The latter keeps the check fail-closed if a downstream build edits the
 * prose but preserves the release number. */
static inline int
dlfrz_glibc_is_development_release(const void *data, size_t size)
{
    int development;

    dlfrz_glibc_release_profile(data, size, NULL, &development);
    return development;
}

/* Return the minor from glibc's canonical stable-release banner.  Private
 * rtld layouts must not be selected from the largest GLIBC_2.* symbol
 * version: that is an ABI floor, not a positive runtime identity. */
static inline int
dlfrz_glibc_stable_release_minor(const void *data, size_t size)
{
    int stable_minor;

    dlfrz_glibc_release_profile(data, size, &stable_minor, NULL);
    return stable_minor;
}

/* Size tuples can be retained or reused after private fields move.  Admit
 * only releases for which the corresponding field profile was validated;
 * the explicitly ambiguous x86-64 tuple is split by its stable release. */
static inline int
dlfrz_glibc_layout_release_is_supported(enum dlfrz_glibc_layout_id layout,
                                         int minor)
{
    switch (layout) {
    case DLFRZ_GLIBC_X86_2_17:
        return minor >= 17 && minor <= 28;
    case DLFRZ_GLIBC_AARCH64_2_27:
        return minor == 27;
    case DLFRZ_GLIBC_X86_2_29:
        return minor >= 29 && minor <= 33;
    case DLFRZ_GLIBC_X86_RTLD_544_4000:
    case DLFRZ_GLIBC_AARCH64_2_31:
        return minor == 31;
    case DLFRZ_GLIBC_AARCH64_2_35_LARGE:
        return minor == 35;
    case DLFRZ_GLIBC_AARCH64_RTLD_672_4520:
        return minor == 36;
    case DLFRZ_GLIBC_AARCH64_2_35:
        return minor >= 36 && minor <= 39;
    case DLFRZ_GLIBC_AARCH64_2_43:
        return minor == 43;
    case DLFRZ_GLIBC_AARCH64_2_44:
        return minor == 44;
    case DLFRZ_GLIBC_AARCH64_2_40_LEGACY:
        return minor == 40;
    case DLFRZ_GLIBC_AARCH64_2_41:
        return minor == 41;
    case DLFRZ_GLIBC_X86_RTLD_896_4336:
        return minor == 36;
    case DLFRZ_GLIBC_X86_2_34:
        return minor >= 34 && minor <= 36;
    case DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY:
        return (minor >= 37 && minor <= 39) || minor == 40;
    case DLFRZ_GLIBC_X86_2_40:
        return minor >= 40 && minor <= 43;
    case DLFRZ_GLIBC_X86_2_44:
        return minor == 44;
    case DLFRZ_GLIBC_X86_RTLD_952_2888:
        return minor == 41;
    case DLFRZ_GLIBC_LAYOUT_UNKNOWN:
        return 0;
    }
    return 0;
}

/* glibc 2.34 and 2.35 decide whether the dynamic loader is active by
 * testing _rtld_global_ro._dl_init_all_dirs.  A direct-loaded libc has no
 * real ld.so search-path list, but leaving this field NULL makes those
 * releases take their static-dlopen hook path and dereference the likewise
 * absent _dl_dlfcn_hook.  Return the exact validated field offset only for
 * the affected private layout/release combinations.  A complete validated
 * dlfcn hook takes precedence over this fail-closed discriminator. */
static inline int
dlfrz_glibc_legacy_rtld_active_offset(
    enum dlfrz_glibc_layout_id layout, int minor)
{
    if (layout == DLFRZ_GLIBC_X86_2_34 &&
        (minor == 34 || minor == 35))
        return 736; /* offsetof(struct rtld_global_ro, _dl_init_all_dirs) */
    if (layout == DLFRZ_GLIBC_AARCH64_2_35_LARGE && minor == 35)
        return 528; /* offsetof(struct rtld_global_ro, _dl_init_all_dirs) */
    return -1;
}

/* glibc 2.34 introduced struct dlfcn_hook as the complete, opaque-handle
 * interface used after a dynamic loader has been brought into a static
 * process.  It is the only private module-loading interface which does not
 * require its client to fabricate a target-private link_map.  The pointer's
 * position is still private ABI: releases with an otherwise-identical size
 * tuple moved it as adjacent optional fields were added or removed.  Return
 * an offset only for layout/release pairs whose exact position was
 * validated. */
static inline int
dlfrz_glibc_dlfcn_hook_offset(enum dlfrz_glibc_layout_id layout, int minor)
{
    switch (layout) {
    case DLFRZ_GLIBC_X86_2_34:
        if (minor == 34)
            return 888;
        if (minor == 35)
            return 904;
        if (minor == 36)
            return 896;
        return -1;
    case DLFRZ_GLIBC_X86_RTLD_896_4336:
        return minor == 36 ? 872 : -1;
    case DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY:
        return ((minor >= 37 && minor <= 39) || minor == 40) ? 928 : -1;
    case DLFRZ_GLIBC_X86_2_40:
        return minor >= 40 && minor <= 43 ? 896 : -1;
    case DLFRZ_GLIBC_X86_2_44:
        return minor == 44 ? 904 : -1;
    case DLFRZ_GLIBC_X86_RTLD_952_2888:
        return minor == 41 ? 928 : -1;
    case DLFRZ_GLIBC_AARCH64_2_35:
        return minor >= 36 && minor <= 39 ? 664 : -1;
    case DLFRZ_GLIBC_AARCH64_2_35_LARGE:
        return minor == 35 ? 680 : -1;
    case DLFRZ_GLIBC_AARCH64_2_41:
        return minor == 41 ? 680 : -1;
    case DLFRZ_GLIBC_AARCH64_2_44:
        return minor == 44 ? 376 : -1;
    case DLFRZ_GLIBC_X86_2_17:
    case DLFRZ_GLIBC_X86_2_29:
    case DLFRZ_GLIBC_X86_RTLD_544_4000:
    case DLFRZ_GLIBC_AARCH64_2_27:
    case DLFRZ_GLIBC_AARCH64_2_31:
    case DLFRZ_GLIBC_AARCH64_RTLD_672_4520:
    case DLFRZ_GLIBC_AARCH64_2_40_LEGACY:
    case DLFRZ_GLIBC_AARCH64_2_43:
    case DLFRZ_GLIBC_LAYOUT_UNKNOWN:
        return -1;
    }
    return -1;
}

/* _dl_find_object was added next to the hook after glibc 2.34.  Keep its
 * release-aware offset separate: the shared x86-64 2.34--2.36 size profile
 * otherwise mistakes the 2.34 dlfcn-hook slot for _dl_find_object. */
static inline int
dlfrz_glibc_find_object_offset(enum dlfrz_glibc_layout_id layout, int minor)
{
    switch (layout) {
    case DLFRZ_GLIBC_X86_2_34:
        return minor == 34 ? -1 : (minor == 35 || minor == 36 ? 888 : -1);
    case DLFRZ_GLIBC_X86_RTLD_896_4336:
        return minor == 36 ? 864 : -1;
    case DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY:
        return ((minor >= 37 && minor <= 39) || minor == 40) ? 920 : -1;
    case DLFRZ_GLIBC_X86_2_40:
    case DLFRZ_GLIBC_X86_2_44:
        return dlfrz_glibc_layout_release_is_supported(layout, minor)
            ? 888 : -1;
    case DLFRZ_GLIBC_X86_RTLD_952_2888:
        return minor == 41 ? 920 : -1;
    case DLFRZ_GLIBC_AARCH64_2_35:
        return minor >= 36 && minor <= 39 ? 656 : -1;
    case DLFRZ_GLIBC_AARCH64_2_35_LARGE:
        return minor == 35 ? 664 : -1;
    case DLFRZ_GLIBC_AARCH64_2_41:
        return minor == 41 ? 672 : -1;
    case DLFRZ_GLIBC_AARCH64_2_44:
        return minor == 44 ? 360 : -1;
    case DLFRZ_GLIBC_X86_2_17:
    case DLFRZ_GLIBC_X86_2_29:
    case DLFRZ_GLIBC_X86_RTLD_544_4000:
    case DLFRZ_GLIBC_AARCH64_2_27:
    case DLFRZ_GLIBC_AARCH64_2_31:
    case DLFRZ_GLIBC_AARCH64_RTLD_672_4520:
    case DLFRZ_GLIBC_AARCH64_2_40_LEGACY:
    case DLFRZ_GLIBC_AARCH64_2_43:
    case DLFRZ_GLIBC_LAYOUT_UNKNOWN:
        return -1;
    }
    return -1;
}

/* Direct loading writes private rtld/GLRO state, x86 CPU-feature state, and
 * initial-thread descriptor fields.  Keep pack-time and bootstrap admission
 * identical.  Pre-2.34 glibc layouts remain detectable for extraction
 * compatibility, but their older private-state ABIs are not direct-loaded. */
static inline int
dlfrz_glibc_direct_thread_layout_is_supported(
    enum dlfrz_glibc_layout_id layout)
{
    switch (layout) {
    case DLFRZ_GLIBC_AARCH64_2_35:
    case DLFRZ_GLIBC_AARCH64_2_41:
    case DLFRZ_GLIBC_AARCH64_2_44:
    case DLFRZ_GLIBC_X86_RTLD_896_4336:
    case DLFRZ_GLIBC_X86_2_34:
    case DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY:
    case DLFRZ_GLIBC_X86_2_40:
    case DLFRZ_GLIBC_X86_2_44:
    case DLFRZ_GLIBC_X86_RTLD_952_2888:
        return 1;
    case DLFRZ_GLIBC_AARCH64_2_27:
    case DLFRZ_GLIBC_AARCH64_2_31:
    case DLFRZ_GLIBC_AARCH64_2_35_LARGE:
    case DLFRZ_GLIBC_AARCH64_RTLD_672_4520:
    case DLFRZ_GLIBC_AARCH64_2_43:
    case DLFRZ_GLIBC_AARCH64_2_40_LEGACY:
    case DLFRZ_GLIBC_X86_2_17:
    case DLFRZ_GLIBC_X86_2_29:
    case DLFRZ_GLIBC_X86_RTLD_544_4000:
    case DLFRZ_GLIBC_LAYOUT_UNKNOWN:
        return 0;
    }
    return 0;
}

#endif /* DLFREEZE_GLIBC_LAYOUT_H */
