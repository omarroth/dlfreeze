#include "common.h"
#include "glibc_layout.h"

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

static int range_fits(size_t offset, size_t length, size_t size)
{
    return offset <= size && length <= size - offset;
}

static int locate_glibc_layout(const uint8_t *elf, size_t elf_size,
                               enum dlfrz_glibc_layout_id *layout_out,
                               uint64_t *glro_vaddr_out,
                               uint64_t *glro_size_out)
{
    struct dlfrz_glibc_rtld_identity identity;

    if (!dlfrz_glibc_rtld_identity(elf, elf_size, &identity))
        return -1;
    *layout_out = dlfrz_glibc_layout_lookup(
        identity.machine, identity.global_ro_size, identity.global_size);
    if (*layout_out == DLFRZ_GLIBC_LAYOUT_UNKNOWN)
        return -1;
    *glro_vaddr_out = identity.global_ro_vaddr;
    *glro_size_out = identity.global_ro_size;
    return 0;
}

struct glibc_reloc_tables {
    size_t rela_offset;
    uint64_t rela_size;
    size_t relr_offset;
    uint64_t relr_size;
};

static int locate_glibc_reloc_tables(const uint8_t *elf, size_t elf_size,
                                     struct glibc_reloc_tables *tables)
{
    Elf64_Ehdr ehdr;
    Elf64_Phdr dynamic_phdr = {0};
    uint64_t rela_vaddr = 0, rela_size = 0, rela_ent = 0;
    uint64_t relr_vaddr = 0, relr_size = 0, relr_ent = 0;
    int dynamic_found = 0;
    int terminated = 0;
    int have_rela_vaddr = 0, have_rela_size = 0, have_rela_ent = 0;
    int have_relr_vaddr = 0, have_relr_size = 0, have_relr_ent = 0;

    memset(tables, 0, sizeof(*tables));
    if (elf_size < sizeof(ehdr))
        return -1;
    memcpy(&ehdr, elf, sizeof(ehdr));
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;

        if (!dlfrz_glibc_read_phdr(elf, elf_size, &ehdr, i, &phdr))
            return -1;
        if (phdr.p_type != PT_DYNAMIC)
            continue;
        if (dynamic_found || phdr.p_offset > elf_size ||
            phdr.p_filesz > (uint64_t)elf_size - phdr.p_offset ||
            phdr.p_filesz % sizeof(Elf64_Dyn) != 0)
            return -1;
        dynamic_phdr = phdr;
        dynamic_found = 1;
    }
    if (!dynamic_found)
        return -1;

    for (uint64_t pos = 0; pos < dynamic_phdr.p_filesz;
         pos += sizeof(Elf64_Dyn)) {
        Elf64_Dyn dyn;
        uint64_t value;

        memcpy(&dyn, elf + (size_t)dynamic_phdr.p_offset + (size_t)pos,
               sizeof(dyn));
        if (dyn.d_tag == DT_NULL) {
            terminated = 1;
            break;
        }
        value = dyn.d_un.d_val;
#define GLIBC_GATE_DYNAMIC_VALUE(tag, have, slot)                          \
        case tag:                                                          \
            if (have && slot != value)                                     \
                return -1;                                                  \
            have = 1;                                                       \
            slot = value;                                                   \
            break
        switch (dyn.d_tag) {
        GLIBC_GATE_DYNAMIC_VALUE(DT_RELA, have_rela_vaddr, rela_vaddr);
        GLIBC_GATE_DYNAMIC_VALUE(DT_RELASZ, have_rela_size, rela_size);
        GLIBC_GATE_DYNAMIC_VALUE(DT_RELAENT, have_rela_ent, rela_ent);
        GLIBC_GATE_DYNAMIC_VALUE(DT_RELR, have_relr_vaddr, relr_vaddr);
        GLIBC_GATE_DYNAMIC_VALUE(DT_RELRSZ, have_relr_size, relr_size);
        GLIBC_GATE_DYNAMIC_VALUE(DT_RELRENT, have_relr_ent, relr_ent);
        default:
            break;
        }
#undef GLIBC_GATE_DYNAMIC_VALUE
    }
    if (!terminated)
        return -1;
    if (have_rela_vaddr || have_rela_size || have_rela_ent) {
        if (!have_rela_vaddr || !have_rela_size || !have_rela_ent ||
            rela_ent != sizeof(Elf64_Rela) ||
            rela_size % sizeof(Elf64_Rela) != 0 ||
            !dlfrz_glibc_vaddr_file_range(
                elf, elf_size, &ehdr, rela_vaddr, rela_size,
                &tables->rela_offset))
            return -1;
        tables->rela_size = rela_size;
    }
    if (have_relr_vaddr || have_relr_size || have_relr_ent) {
        if (!have_relr_vaddr || !have_relr_size || !have_relr_ent ||
            relr_ent != sizeof(uint64_t) ||
            relr_size % sizeof(uint64_t) != 0 ||
            !dlfrz_glibc_vaddr_file_range(
                elf, elf_size, &ehdr, relr_vaddr, relr_size,
                &tables->relr_offset))
            return -1;
        tables->relr_size = relr_size;
    }
    return 0;
}

static int is_required_glro_target(
    const struct dlfrz_glibc_glro_reloc_profile *profile,
    uint64_t glro_vaddr, uint64_t target)
{
    const int offsets[] = {
        profile->debug_printf, profile->mcount, profile->open,
        profile->close, profile->catch_error, profile->error_free
    };

    for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        if (offsets[i] >= 0 &&
            glro_vaddr <= UINT64_MAX - (uint64_t)offsets[i] &&
            glro_vaddr + (uint64_t)offsets[i] == target)
            return 1;
    }
    return 0;
}

static int remove_required_glro_relocation(uint8_t *elf, size_t elf_size)
{
    enum dlfrz_glibc_layout_id layout;
    struct dlfrz_glibc_glro_reloc_profile profile;
    struct glibc_reloc_tables tables;
    uint64_t glro_vaddr;
    uint64_t glro_size;

    if (locate_glibc_layout(elf, elf_size, &layout, &glro_vaddr,
                            &glro_size) < 0 ||
        !dlfrz_glibc_glro_reloc_profile(layout, &profile) ||
        !dlfrz_glibc_glro_relocations_valid(
            elf, elf_size, layout, glro_vaddr, glro_size) ||
        locate_glibc_reloc_tables(elf, elf_size, &tables) < 0)
        return -1;

    /* Prefer a RELR bitmap bit: clearing it preserves a bounded, canonical
     * table while removing exactly one relocation target. */
    if (tables.relr_size != 0) {
        uint64_t where = 0;
        int have_where = 0;

        for (uint64_t pos = 0; pos < tables.relr_size;
             pos += sizeof(uint64_t)) {
            uint64_t *entry = (uint64_t *)(elf + tables.relr_offset +
                                            (size_t)pos);
            uint64_t value;

            memcpy(&value, entry, sizeof(value));
            if ((value & 1U) == 0) {
                if (value > UINT64_MAX - sizeof(uint64_t))
                    return -1;
                where = value + sizeof(uint64_t);
                have_where = 1;
                continue;
            }
            if (!have_where ||
                where > UINT64_MAX - 63U * sizeof(uint64_t))
                return -1;
            for (unsigned int bit = 0; bit < 63; bit++) {
                uint64_t mask = UINT64_C(2) << bit;
                uint64_t target = where +
                    (uint64_t)bit * sizeof(uint64_t);
                uint64_t mutated;

                if (!(value & mask) ||
                    !is_required_glro_target(&profile, glro_vaddr, target))
                    continue;
                mutated = value & ~mask;
                memcpy(entry, &mutated, sizeof(mutated));
                if (!dlfrz_glibc_glro_relocations_valid(
                        elf, elf_size, layout, glro_vaddr, glro_size))
                    return 0;
                memcpy(entry, &value, sizeof(value));
            }
            where += 63U * sizeof(uint64_t);
        }
    }

    if (tables.rela_size != 0) {
        uint32_t relative_type = profile.machine == EM_X86_64 ? 8U : 1027U;

        for (uint64_t pos = 0; pos < tables.rela_size;
             pos += sizeof(Elf64_Rela)) {
            Elf64_Rela *rela = (Elf64_Rela *)(elf + tables.rela_offset +
                                               (size_t)pos);
            Elf64_Rela value;
            Elf64_Rela mutated;

            memcpy(&value, rela, sizeof(value));
            if (ELF64_R_TYPE(value.r_info) != relative_type ||
                !is_required_glro_target(
                    &profile, glro_vaddr, value.r_offset))
                continue;
            mutated = value;
            mutated.r_offset = 0;
            memcpy(rela, &mutated, sizeof(mutated));
            if (!dlfrz_glibc_glro_relocations_valid(
                    elf, elf_size, layout, glro_vaddr, glro_size))
                return 0;
            memcpy(rela, &value, sizeof(value));
        }
    }
    return -1;
}

static int patch_tunable_service_relocation(uint8_t *elf, size_t elf_size,
                                            int malformed_symbol)
{
    enum dlfrz_glibc_layout_id layout;
    struct dlfrz_glibc_glro_reloc_profile profile;
    struct glibc_reloc_tables tables;
    uint64_t glro_vaddr;
    uint64_t glro_size;

    if (locate_glibc_layout(elf, elf_size, &layout, &glro_vaddr,
                            &glro_size) < 0 ||
        !dlfrz_glibc_glro_reloc_profile(layout, &profile) ||
        !dlfrz_glibc_glro_relocations_valid(
            elf, elf_size, layout, glro_vaddr, glro_size) ||
        locate_glibc_reloc_tables(elf, elf_size, &tables) < 0)
        return -1;

    for (uint64_t pos = 0; pos < tables.rela_size;
         pos += sizeof(Elf64_Rela)) {
        Elf64_Rela *record = (Elf64_Rela *)(elf + tables.rela_offset +
                                             (size_t)pos);
        Elf64_Rela relocation;
        uint32_t type;

        memcpy(&relocation, record, sizeof(relocation));
        type = ELF64_R_TYPE(relocation.r_info);
        if (type == 0 ||
            is_required_glro_target(&profile, glro_vaddr,
                                    relocation.r_offset))
            continue;
        if (malformed_symbol) {
            relocation.r_info = ELF64_R_INFO(UINT32_MAX, type);
        } else {
            /* Deliberately outside both admitted architecture relocation
             * sets.  The isolated tunable service must reject it rather
             * than silently leaving a potentially reachable slot stale. */
            relocation.r_info = ELF64_R_INFO(
                ELF64_R_SYM(relocation.r_info), UINT32_C(0x7fffffff));
        }
        memcpy(record, &relocation, sizeof(relocation));
        return 0;
    }
    return -1;
}

static int patch_tunable_accessor(uint8_t *elf, size_t elf_size, int mode)
{
    struct dlfrz_elf64_dyn_view view;
    Elf64_Sym symbol;
    size_t code_offset;
    uint8_t *code;
    size_t code_size;
    int changed = 0;

    if (!dlfrz_elf64_dyn_view_init(elf, elf_size, &view) ||
        dlfrz_elf64_dyn_view_find(
            &view, "__tunable_get_val", &symbol, NULL) != 1 ||
        ELF64_ST_TYPE(symbol.st_info) != STT_FUNC ||
        symbol.st_shndx == SHN_UNDEF || symbol.st_size == 0 ||
        symbol.st_size > SIZE_MAX ||
        !dlfrz_glibc_vaddr_file_range(
            elf, elf_size, &view.ehdr, symbol.st_value, symbol.st_size,
            &code_offset))
        return -1;
    code = elf + code_offset;
    code_size = (size_t)symbol.st_size;

    if (view.ehdr.e_machine == EM_X86_64) {
        if (mode == 9) { /* overwrite the callback argument register */
            static const uint8_t test_rdx[] = { 0x48, 0x85, 0xd2 };
            static const uint8_t mov_rdx_rax[] = { 0x48, 0x89, 0xc2 };

            for (size_t i = 0; i + sizeof(test_rdx) <= code_size; i++) {
                if (memcmp(code + i, test_rdx, sizeof(test_rdx)) != 0)
                    continue;
                memcpy(code + i, mov_rdx_rax, sizeof(mov_rdx_rax));
                return 0;
            }
        } else if (mode == 10) { /* make an existing branch self-loop */
            for (size_t i = code_size; i >= 2; i--) {
                size_t position = i - 2;
                int8_t displacement;
                int64_t target;

                if (code[position] != 0xeb)
                    continue;
                memcpy(&displacement, code + position + 1,
                       sizeof(displacement));
                target = (int64_t)position + 2 + displacement;
                if (target < 0 || (uint64_t)target >= code_size)
                    continue;
                code[position + 1] = 0xfe;
                return 0;
            }
        } else if (mode == 11) { /* remove every reachable terminator */
            for (size_t i = 0; i < code_size; i++) {
                if (code[i] == 0xc3) {
                    code[i] = 0x90;
                    changed = 1;
                }
                if (i + 1 < code_size && code[i] == 0xff &&
                    code[i + 1] == 0xe2) {
                    code[i] = 0x90;
                    code[i + 1] = 0x90;
                    changed = 1;
                    i++;
                }
            }
            return changed ? 0 : -1;
        }
    } else if (view.ehdr.e_machine == EM_AARCH64 &&
               code_size % sizeof(uint32_t) == 0) {
        if (mode == 9) {
            for (size_t i = 0; i < code_size; i += sizeof(uint32_t)) {
                uint32_t instruction;

                memcpy(&instruction, code + i, sizeof(instruction));
                if (instruction != UINT32_C(0xf100005f))
                    continue; /* cmp x2, #0 */
                instruction = UINT32_C(0xaa0003e2); /* mov x2, x0 */
                memcpy(code + i, &instruction, sizeof(instruction));
                return 0;
            }
        } else if (mode == 10) {
            for (size_t i = code_size; i >= sizeof(uint32_t);
                 i -= sizeof(uint32_t)) {
                size_t position = i - sizeof(uint32_t);
                uint32_t instruction;

                memcpy(&instruction, code + position,
                       sizeof(instruction));
                if ((instruction & UINT32_C(0xfc000000)) !=
                    UINT32_C(0x14000000))
                    continue;
                instruction = UINT32_C(0x14000000); /* b . */
                memcpy(code + position, &instruction,
                       sizeof(instruction));
                return 0;
            }
        } else if (mode == 11) {
            for (size_t i = 0; i < code_size; i += sizeof(uint32_t)) {
                uint32_t instruction;

                memcpy(&instruction, code + i, sizeof(instruction));
                if (instruction == UINT32_C(0xd65f03c0) ||
                    (instruction & UINT32_C(0xfffffc1f)) ==
                        UINT32_C(0xd61f0000)) {
                    instruction = UINT32_C(0xd503201f); /* nop */
                    memcpy(code + i, &instruction, sizeof(instruction));
                    changed = 1;
                }
            }
            return changed ? 0 : -1;
        } else if (mode == 13) {
            size_t callback = SIZE_MAX;

            for (size_t i = sizeof(uint32_t); i < code_size;
                 i += sizeof(uint32_t)) {
                uint32_t previous;
                uint32_t instruction;

                memcpy(&previous, code + i - sizeof(previous),
                       sizeof(previous));
                memcpy(&instruction, code + i, sizeof(instruction));
                if (previous == UINT32_C(0xaa0203f0) &&
                    instruction == UINT32_C(0xd61f0200)) {
                    callback = i;
                    break;
                }
            }
            if (callback == SIZE_MAX)
                return -1;
            for (size_t i = 0; i < code_size; i += sizeof(uint32_t)) {
                uint32_t instruction;
                int64_t words = ((int64_t)callback - (int64_t)i) / 4;

                memcpy(&instruction, code + i, sizeof(instruction));
                if ((instruction & UINT32_C(0x7c000000)) ==
                    UINT32_C(0x14000000)) { /* B */
                    instruction = (instruction & UINT32_C(0xfc000000)) |
                        ((uint32_t)words & UINT32_C(0x03ffffff));
                } else if ((instruction & UINT32_C(0xff000010)) ==
                           UINT32_C(0x54000000)) { /* B.cond */
                    instruction = (instruction & ~UINT32_C(0x00ffffe0)) |
                        (((uint32_t)words & UINT32_C(0x7ffff)) << 5);
                } else if ((instruction & UINT32_C(0x7e000000)) ==
                           UINT32_C(0x34000000)) { /* CBZ/CBNZ */
                    instruction = (instruction & ~UINT32_C(0x00ffffe0)) |
                        (((uint32_t)words & UINT32_C(0x7ffff)) << 5);
                } else if ((instruction & UINT32_C(0x7e000000)) ==
                           UINT32_C(0x36000000)) { /* TBZ/TBNZ */
                    instruction = (instruction & ~UINT32_C(0x0007ffe0)) |
                        (((uint32_t)words & UINT32_C(0x3fff)) << 5);
                } else {
                    continue;
                }
                memcpy(code + i, &instruction, sizeof(instruction));
                return 0;
            }
        }
    }
    return -1;
}

static int patch_rtld_global_size(uint8_t *elf, size_t elf_size)
{
    Elf64_Ehdr *ehdr;
    Elf64_Shdr *shdrs;

    if (elf_size < sizeof(Elf64_Ehdr))
        return -1;
    ehdr = (Elf64_Ehdr *)elf;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr->e_shentsize != sizeof(Elf64_Shdr) ||
        ehdr->e_shnum == 0 ||
        !range_fits((size_t)ehdr->e_shoff,
                    (size_t)ehdr->e_shnum * sizeof(Elf64_Shdr), elf_size))
        return -1;

    shdrs = (Elf64_Shdr *)(elf + ehdr->e_shoff);
    for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *sym_sh = &shdrs[i];
        Elf64_Shdr *str_sh;
        Elf64_Sym *syms;
        const char *strings;
        size_t nsyms;

        if (sym_sh->sh_type != SHT_DYNSYM ||
            sym_sh->sh_entsize != sizeof(Elf64_Sym) ||
            sym_sh->sh_link >= ehdr->e_shnum ||
            sym_sh->sh_size % sizeof(Elf64_Sym) != 0 ||
            !range_fits((size_t)sym_sh->sh_offset,
                        (size_t)sym_sh->sh_size, elf_size))
            continue;
        str_sh = &shdrs[sym_sh->sh_link];
        if (str_sh->sh_type != SHT_STRTAB ||
            !range_fits((size_t)str_sh->sh_offset,
                        (size_t)str_sh->sh_size, elf_size))
            continue;

        syms = (Elf64_Sym *)(elf + sym_sh->sh_offset);
        strings = (const char *)(elf + str_sh->sh_offset);
        nsyms = (size_t)sym_sh->sh_size / sizeof(Elf64_Sym);
        for (size_t j = 0; j < nsyms; j++) {
            const char *name;
            size_t remain;

            if (ELF64_ST_TYPE(syms[j].st_info) != STT_OBJECT ||
                syms[j].st_shndx == SHN_UNDEF ||
                syms[j].st_name >= str_sh->sh_size)
                continue;
            name = strings + syms[j].st_name;
            remain = (size_t)str_sh->sh_size - syms[j].st_name;
            if (remain > sizeof("_rtld_global") - 1 &&
                memcmp(name, "_rtld_global", sizeof("_rtld_global") - 1) == 0 &&
                name[sizeof("_rtld_global") - 1] == '\0') {
                syms[j].st_size += 16;
                return 0;
            }
        }
    }
    return -1;
}

static int patch_stable_release_minor(uint8_t *elf, size_t elf_size)
{
    static const char prefix[] = "stable release version 2.";

    if (dlfrz_glibc_is_development_release(elf, elf_size))
        return -1;
    if (elf_size < sizeof(prefix) - 1)
        return -1;
    for (size_t i = 0; i <= elf_size - (sizeof(prefix) - 1); i++) {
        size_t p;

        if (memcmp(elf + i, prefix, sizeof(prefix) - 1) != 0)
            continue;
        p = i + sizeof(prefix) - 1;
        if (p >= elf_size || elf[p] < '0' || elf[p] > '9')
            return -1;
        while (p + 1 < elf_size && elf[p + 1] >= '0' && elf[p + 1] <= '9')
            p++;
        elf[p] = elf[p] == '0' ? '1' : (unsigned char)(elf[p] - 1);
        return 0;
    }
    return -1;
}

static int remove_stable_release_identity(uint8_t *elf, size_t elf_size)
{
    static const char prefix[] = "stable release version 2.";

    if (elf_size < sizeof(prefix) - 1)
        return -1;
    for (size_t i = 0; i <= elf_size - (sizeof(prefix) - 1); i++) {
        if (memcmp(elf + i, prefix, sizeof(prefix) - 1) != 0)
            continue;
        elf[i] = 'x';
        return 0;
    }
    return -1;
}

static int patch_x86_cpu_contract(uint8_t *elf, size_t elf_size,
                                  int operation)
{
    struct dlfrz_glibc_rtld_identity identity;
    struct dlfrz_glibc_x86_cpu_evidence evidence;
    enum dlfrz_glibc_layout_id layout;
    size_t displacement_offset;
    int32_t displacement;
    int minor;

    if (!dlfrz_glibc_rtld_identity(elf, elf_size, &identity) ||
        identity.machine != EM_X86_64)
        return -1;
    layout = dlfrz_glibc_layout_lookup(
        identity.machine, identity.global_ro_size, identity.global_size);
    minor = dlfrz_glibc_stable_release_minor(elf, elf_size);
    if (minor < 0 || !dlfrz_glibc_x86_cpu_contract_valid(
            elf, elf_size, layout, minor, identity.global_ro_vaddr,
            identity.global_ro_size, NULL, &evidence))
        return -1;
    if (operation == 21) {
        uint32_t original;
        uint32_t unrelated_only = 6;
        size_t immediate_offset =
            evidence.generic_kind_immediate_file_offset;

        if (!range_fits(immediate_offset, sizeof(original), elf_size))
            return -1;
        memcpy(&original, elf + immediate_offset, sizeof(original));
        memcpy(elf + immediate_offset, &unrelated_only,
               sizeof(unrelated_only));
        if (dlfrz_glibc_x86_cpu_contract_valid(
                elf, elf_size, layout, minor, identity.global_ro_vaddr,
                identity.global_ro_size, NULL, NULL)) {
            memcpy(elf + immediate_offset, &original, sizeof(original));
            return -1;
        }
        return 0;
    }
    displacement_offset = operation == 18 ?
        evidence.accessor_displacement_file_offset :
        evidence.layout_write_displacement_file_offset;
    if (!range_fits(displacement_offset, sizeof(displacement), elf_size))
        return -1;
    memcpy(&displacement, elf + displacement_offset, sizeof(displacement));
    if (displacement > INT32_MAX - 4)
        return -1;
    displacement += 4;
    memcpy(elf + displacement_offset, &displacement, sizeof(displacement));

    /* The mutation is useful only if the exact target-code gate rejects it. */
    if (dlfrz_glibc_x86_cpu_contract_valid(
            elf, elf_size, layout, minor, identity.global_ro_vaddr,
            identity.global_ro_size, NULL, NULL)) {
        displacement -= 4;
        memcpy(elf + displacement_offset, &displacement,
               sizeof(displacement));
        return -1;
    }
    return 0;
}

static int patch_frozen_interp(uint8_t *map, size_t size, int operation)
{
    struct dlfrz_footer *footer;
    struct dlfrz_entry *entries;
    size_t entries_size;

    if (size < sizeof(struct dlfrz_footer))
        return -1;
    footer = (struct dlfrz_footer *)(map + size - sizeof(*footer));
    if (memcmp(footer->magic, DLFRZ_MAGIC, sizeof(footer->magic)) != 0 ||
        footer->version != DLFRZ_VERSION)
        return -1;
    entries_size = (size_t)footer->num_entries * sizeof(struct dlfrz_entry);
    if (!range_fits((size_t)footer->manifest_offset, entries_size, size))
        return -1;
    entries = (struct dlfrz_entry *)(map + footer->manifest_offset);

    for (uint32_t i = 0; i < footer->num_entries; i++) {
        if (!(entries[i].flags & DLFRZ_FLAG_INTERP))
            continue;
        if (!range_fits((size_t)entries[i].data_offset,
                        (size_t)entries[i].data_size, size))
            return -1;
        if (operation == 4)
            return remove_required_glro_relocation(
                map + entries[i].data_offset,
                (size_t)entries[i].data_size);
        if (operation == 18 || operation == 19 || operation == 22)
            return patch_x86_cpu_contract(
                map + entries[i].data_offset,
                (size_t)entries[i].data_size,
                operation == 22 ? 21 : operation);
        if ((operation >= 9 && operation <= 11) || operation == 13)
            return patch_tunable_accessor(
                map + entries[i].data_offset,
                (size_t)entries[i].data_size, operation);
        if (operation == 7 || operation == 8)
            return patch_tunable_service_relocation(
                map + entries[i].data_offset,
                (size_t)entries[i].data_size, operation == 8);
        if (operation == 3)
            return remove_stable_release_identity(
                map + entries[i].data_offset,
                (size_t)entries[i].data_size);
        return patch_rtld_global_size(
            map + entries[i].data_offset,
            (size_t)entries[i].data_size);
    }
    return -1;
}

static int patch_frozen_libc_release(uint8_t *map, size_t size)
{
    struct dlfrz_footer *footer;
    struct dlfrz_entry *entries;
    size_t entries_size;

    if (size < sizeof(struct dlfrz_footer))
        return -1;
    footer = (struct dlfrz_footer *)(map + size - sizeof(*footer));
    if (memcmp(footer->magic, DLFRZ_MAGIC, sizeof(footer->magic)) != 0 ||
        footer->version != DLFRZ_VERSION)
        return -1;
    entries_size = (size_t)footer->num_entries * sizeof(*entries);
    if (!range_fits((size_t)footer->manifest_offset, entries_size, size))
        return -1;
    entries = (struct dlfrz_entry *)(map + footer->manifest_offset);

    for (uint32_t i = 0; i < footer->num_entries; i++) {
        struct dlfrz_elf64_dyn_view view;
        uint8_t *elf;
        const char *soname;

        if (entries[i].flags & (DLFRZ_FLAG_INTERP | DLFRZ_FLAG_DATA))
            continue;
        if (entries[i].data_size > SIZE_MAX ||
            !range_fits((size_t)entries[i].data_offset,
                        (size_t)entries[i].data_size, size))
            return -1;
        elf = map + (size_t)entries[i].data_offset;
        if (!dlfrz_elf64_dyn_view_init(
                elf, (size_t)entries[i].data_size, &view) ||
            !view.have_soname)
            continue;
        soname = (const char *)view.elf + view.dynstr_offset +
                 (size_t)view.soname_offset;
        if (strcmp(soname, "libc.so.6") == 0)
            return patch_stable_release_minor(
                elf, (size_t)entries[i].data_size);
    }
    return -1;
}

static int patch_frozen_libc_hook_consumer(uint8_t *map, size_t size)
{
    struct dlfrz_footer *footer;
    struct dlfrz_entry *entries;
    size_t entries_size;
    int hook_offset = -1;

    if (size < sizeof(struct dlfrz_footer))
        return -1;
    footer = (struct dlfrz_footer *)(map + size - sizeof(*footer));
    if (memcmp(footer->magic, DLFRZ_MAGIC, sizeof(footer->magic)) != 0 ||
        footer->version != DLFRZ_VERSION)
        return -1;
    entries_size = (size_t)footer->num_entries * sizeof(*entries);
    if (!range_fits((size_t)footer->manifest_offset, entries_size, size))
        return -1;
    entries = (struct dlfrz_entry *)(map + footer->manifest_offset);

    for (uint32_t i = 0; i < footer->num_entries; i++) {
        struct dlfrz_glibc_rtld_identity identity;
        enum dlfrz_glibc_layout_id layout;
        uint8_t *elf;
        int minor;

        if (!(entries[i].flags & DLFRZ_FLAG_INTERP))
            continue;
        if (entries[i].data_size > SIZE_MAX ||
            !range_fits((size_t)entries[i].data_offset,
                        (size_t)entries[i].data_size, size))
            return -1;
        elf = map + (size_t)entries[i].data_offset;
        if (!dlfrz_glibc_rtld_identity(
                elf, (size_t)entries[i].data_size, &identity))
            return -1;
        layout = dlfrz_glibc_layout_lookup(
            identity.machine, identity.global_ro_size, identity.global_size);
        minor = dlfrz_glibc_stable_release_minor(
            elf, (size_t)entries[i].data_size);
        hook_offset = dlfrz_glibc_dlfcn_hook_offset(layout, minor);
        break;
    }
    if (hook_offset < 0)
        return -1;

    for (uint32_t i = 0; i < footer->num_entries; i++) {
        struct dlfrz_elf64_dyn_view view;
        struct dlfrz_glibc_dlfcn_consumer_evidence evidence;
        uint8_t *elf;
        const char *soname;

        if (entries[i].flags & (DLFRZ_FLAG_INTERP | DLFRZ_FLAG_DATA))
            continue;
        if (entries[i].data_size > SIZE_MAX ||
            !range_fits((size_t)entries[i].data_offset,
                        (size_t)entries[i].data_size, size))
            return -1;
        elf = map + (size_t)entries[i].data_offset;
        if (!dlfrz_elf64_dyn_view_init(
                elf, (size_t)entries[i].data_size, &view) ||
            !view.have_soname)
            continue;
        soname = (const char *)view.elf + view.dynstr_offset +
                 (size_t)view.soname_offset;
        if (strcmp(soname, "libc.so.6") != 0)
            continue;
        if (!dlfrz_glibc_dlfcn_hook_consumer_valid(
                elf, (size_t)entries[i].data_size, hook_offset, &evidence) ||
            evidence.hook_load_file_offset >= entries[i].data_size)
            return -1;
        if (view.ehdr.e_machine == EM_X86_64) {
            struct dlfrz_glibc_x86_mov_load load;
            int32_t moved_offset;

            if (!dlfrz_glibc_x86_mov_load(
                    elf + evidence.hook_load_file_offset,
                    (size_t)entries[i].data_size -
                        evidence.hook_load_file_offset,
                    &load) || load.displacement != hook_offset ||
                load.length < sizeof(moved_offset) ||
                evidence.hook_load_file_offset + load.length >
                    entries[i].data_size)
                return -1;
            moved_offset = hook_offset + (int)sizeof(void *);
            memcpy(elf + evidence.hook_load_file_offset + load.length -
                       sizeof(moved_offset),
                   &moved_offset, sizeof(moved_offset));
        } else if (view.ehdr.e_machine == EM_AARCH64) {
            uint32_t instruction;
            uint32_t immediate;

            if (!range_fits(evidence.hook_load_file_offset,
                            sizeof(instruction),
                            (size_t)entries[i].data_size))
                return -1;
            memcpy(&instruction, elf + evidence.hook_load_file_offset,
                   sizeof(instruction));
            immediate = (instruction >> 10) & UINT32_C(0xfff);
            if (immediate * UINT64_C(8) != (uint64_t)hook_offset ||
                immediate == UINT32_C(0xfff))
                return -1;
            instruction &= ~(UINT32_C(0xfff) << 10);
            instruction |= (immediate + 1) << 10;
            memcpy(elf + evidence.hook_load_file_offset, &instruction,
                   sizeof(instruction));
        } else {
            return -1;
        }
        return dlfrz_glibc_dlfcn_hook_consumer_valid(
            elf, (size_t)entries[i].data_size, hook_offset, NULL) ? -1 : 0;
    }
    return -1;
}

/* Independently corrupt only __call_tls_dtors' encoded counter field.  The
 * target release, thread_db descriptors, and registration-side increment are
 * unchanged, so runtime refusal proves that the loader cross-checks target
 * code rather than assuming adjacency to l_tls_modid. */
static int patch_frozen_tls_dtor_counter(uint8_t *map, size_t size)
{
    struct dlfrz_footer *footer;
    struct dlfrz_entry *entries;
    size_t entries_size;

    if (size < sizeof(struct dlfrz_footer))
        return -1;
    footer = (struct dlfrz_footer *)(map + size - sizeof(*footer));
    if (memcmp(footer->magic, DLFRZ_MAGIC, sizeof(footer->magic)) != 0 ||
        footer->version != DLFRZ_VERSION)
        return -1;
    entries_size = (size_t)footer->num_entries * sizeof(*entries);
    if (!range_fits((size_t)footer->manifest_offset, entries_size, size))
        return -1;
    entries = (struct dlfrz_entry *)(map + footer->manifest_offset);

    for (uint32_t i = 0; i < footer->num_entries; i++) {
        struct dlfrz_elf64_dyn_view view;
        Elf64_Sym symbol;
        uint8_t *elf;
        uint8_t *code;
        const char *soname;
        size_t code_offset;
        size_t code_size;
        size_t selected = SIZE_MAX;
        unsigned int candidates = 0;

        if (entries[i].flags & (DLFRZ_FLAG_INTERP | DLFRZ_FLAG_DATA) ||
            entries[i].data_size > SIZE_MAX ||
            !range_fits((size_t)entries[i].data_offset,
                        (size_t)entries[i].data_size, size))
            continue;
        elf = map + (size_t)entries[i].data_offset;
        if (!dlfrz_elf64_dyn_view_init(
                elf, (size_t)entries[i].data_size, &view) ||
            !view.have_soname)
            continue;
        soname = (const char *)view.elf + view.dynstr_offset +
                 (size_t)view.soname_offset;
        if (strcmp(soname, "libc.so.6") != 0)
            continue;
        if (dlfrz_elf64_dyn_view_find(
                &view, "__call_tls_dtors", &symbol, NULL) != 1 ||
            ELF64_ST_TYPE(symbol.st_info) != STT_FUNC ||
            symbol.st_shndx == SHN_UNDEF || symbol.st_size == 0 ||
            symbol.st_size > 512 || symbol.st_size > SIZE_MAX ||
            !dlfrz_glibc_vaddr_file_range(
                elf, (size_t)entries[i].data_size, &view.ehdr,
                symbol.st_value, symbol.st_size, &code_offset))
            return -1;
        code = elf + code_offset;
        code_size = (size_t)symbol.st_size;

        if (view.ehdr.e_machine == EM_X86_64) {
            for (size_t p = 0; p + 9 <= code_size; p++) {
                if (memcmp(code + p, "\xf0\x48\x83\xa8", 4) != 0 ||
                    code[p + 8] != 1)
                    continue;
                selected = p + 4;
                candidates++;
            }
            if (candidates == 1) {
                uint32_t displacement;

                memcpy(&displacement, code + selected,
                       sizeof(displacement));
                if (displacement > UINT32_MAX - sizeof(uintptr_t))
                    return -1;
                displacement += sizeof(uintptr_t);
                memcpy(code + selected, &displacement,
                       sizeof(displacement));
                return 0;
            }
        } else if (view.ehdr.e_machine == EM_AARCH64 &&
                   code_size % sizeof(uint32_t) == 0) {
            for (size_t p = 0; p + 3 * sizeof(uint32_t) <= code_size;
                 p += sizeof(uint32_t)) {
                uint32_t constant;
                uint32_t add;
                uint32_t call;

                memcpy(&constant, code + p, sizeof(constant));
                memcpy(&add, code + p + sizeof(uint32_t), sizeof(add));
                memcpy(&call, code + p + 2 * sizeof(uint32_t),
                       sizeof(call));
                if (constant != UINT32_C(0x92800000) ||
                    (add & UINT32_C(0xffc003ff)) !=
                        UINT32_C(0x91000021) ||
                    (call & UINT32_C(0xfc000000)) !=
                        UINT32_C(0x94000000))
                    continue;
                selected = p + sizeof(uint32_t);
                candidates++;
            }
            if (candidates == 1) {
                uint32_t add;
                uint32_t immediate;

                memcpy(&add, code + selected, sizeof(add));
                immediate = (add >> 10) & UINT32_C(0xfff);
                if (immediate > UINT32_C(0xfff) - sizeof(uintptr_t))
                    return -1;
                add &= ~(UINT32_C(0xfff) << 10);
                add |= (immediate + sizeof(uintptr_t)) << 10;
                memcpy(code + selected, &add, sizeof(add));
                return 0;
            }
        }
        return -1;
    }
    return -1;
}

static int frozen_target_libc(
    uint8_t *map, size_t size, uint8_t **elf_out, size_t *elf_size_out,
    struct dlfrz_elf64_dyn_view *view_out)
{
    struct dlfrz_footer *footer;
    struct dlfrz_entry *entries;
    size_t entries_size;
    unsigned int matches = 0;

    if (size < sizeof(struct dlfrz_footer))
        return -1;
    footer = (struct dlfrz_footer *)(map + size - sizeof(*footer));
    if (memcmp(footer->magic, DLFRZ_MAGIC, sizeof(footer->magic)) != 0 ||
        footer->version != DLFRZ_VERSION)
        return -1;
    entries_size = (size_t)footer->num_entries * sizeof(*entries);
    if (!range_fits((size_t)footer->manifest_offset, entries_size, size))
        return -1;
    entries = (struct dlfrz_entry *)(map + footer->manifest_offset);

    for (uint32_t i = 0; i < footer->num_entries; i++) {
        struct dlfrz_elf64_dyn_view view;
        uint8_t *elf;
        const char *soname;

        if (entries[i].flags & (DLFRZ_FLAG_INTERP | DLFRZ_FLAG_DATA) ||
            entries[i].data_size > SIZE_MAX ||
            !range_fits((size_t)entries[i].data_offset,
                        (size_t)entries[i].data_size, size))
            continue;
        elf = map + (size_t)entries[i].data_offset;
        if (!dlfrz_elf64_dyn_view_init(
                elf, (size_t)entries[i].data_size, &view) ||
            !view.have_soname)
            continue;
        soname = (const char *)view.elf + view.dynstr_offset +
                 (size_t)view.soname_offset;
        if (strcmp(soname, "libc.so.6") != 0)
            continue;
        matches++;
        *elf_out = elf;
        *elf_size_out = (size_t)entries[i].data_size;
        *view_out = view;
    }
    return matches == 1 ? 0 : -1;
}

/* Corrupt only the target-published pthread DTV-slot descriptor.  Release,
 * rtld profiles, pthread size, and the two-word DTV descriptors remain
 * unchanged, so strict refusal proves the runtime does not silently fall
 * back to an architecture constant when target evidence disagrees. */
static int patch_frozen_glibc_dtv_descriptor(uint8_t *map, size_t size)
{
    struct dlfrz_elf64_dyn_view view;
    Elf64_Sym symbol;
    uint8_t *elf = NULL;
    size_t elf_size = 0;
    size_t descriptor_offset;
    struct {
        uint32_t element_bits;
        uint32_t element_count;
        uint32_t offset;
    } descriptor;

    if (frozen_target_libc(
            map, size, &elf, &elf_size, &view) < 0 ||
        dlfrz_elf64_dyn_view_find(
            &view, "_thread_db_pthread_dtvp", &symbol, NULL) != 1 ||
        ELF64_ST_TYPE(symbol.st_info) != STT_OBJECT ||
        symbol.st_shndx == SHN_UNDEF ||
        symbol.st_size != sizeof(descriptor) ||
        !dlfrz_glibc_vaddr_file_range(
            elf, elf_size, &view.ehdr, symbol.st_value,
            sizeof(descriptor), &descriptor_offset))
        return -1;
    memcpy(&descriptor, elf + descriptor_offset, sizeof(descriptor));
    if (descriptor.element_bits != sizeof(uintptr_t) * 8 ||
        descriptor.element_count != 1 ||
        descriptor.offset > UINT32_MAX - sizeof(uintptr_t))
        return -1;
    descriptor.offset += sizeof(uintptr_t);
    memcpy(elf + descriptor_offset, &descriptor, sizeof(descriptor));
    return 0;
}

/* Versioned glibc exports commonly contain two dynamic symbols with the
 * same unversioned name and identical code range.  Accept that aliasing in
 * this mutation helper, but reject distinct definitions. */
static int frozen_identical_function_definition(
    const struct dlfrz_elf64_dyn_view *view, const char *name,
    Elf64_Sym *symbol_out)
{
    Elf64_Sym selected = {0};
    int found = 0;

    for (uint32_t i = 0; i < view->dynsym_count; i++) {
        Elf64_Sym symbol;

        dlfrz_elf64_dyn_view_symbol(view, i, &symbol);
        if (!dlfrz_glibc_dynstr_name(
                view->elf + view->dynstr_offset, view->dynstr_size,
                symbol.st_name, name))
            continue;
        if (ELF64_ST_TYPE(symbol.st_info) != STT_FUNC ||
            symbol.st_shndx == SHN_UNDEF)
            return -1;
        if (found &&
            (selected.st_value != symbol.st_value ||
             selected.st_size != symbol.st_size ||
             selected.st_shndx != symbol.st_shndx))
            return -1;
        selected = symbol;
        found = 1;
    }
    if (!found)
        return -1;
    *symbol_out = selected;
    return 0;
}

static int frozen_aarch64_function(
    uint8_t *elf, size_t elf_size, const struct dlfrz_elf64_dyn_view *view,
    const char *name, size_t minimum, size_t maximum,
    uint8_t **code_out, size_t *code_size_out, Elf64_Sym *symbol_out)
{
    Elf64_Sym symbol;
    size_t code_offset;

    if (view->ehdr.e_machine != EM_AARCH64 ||
        frozen_identical_function_definition(view, name, &symbol) < 0 ||
        ELF64_ST_TYPE(symbol.st_info) != STT_FUNC ||
        symbol.st_shndx == SHN_UNDEF || symbol.st_size < minimum ||
        symbol.st_size > maximum || symbol.st_size > SIZE_MAX ||
        symbol.st_size % sizeof(uint32_t) != 0 ||
        !dlfrz_glibc_vaddr_file_range(
            elf, elf_size, &view->ehdr, symbol.st_value, symbol.st_size,
            &code_offset))
        return -1;
    *code_out = elf + code_offset;
    *code_size_out = (size_t)symbol.st_size;
    if (symbol_out)
        *symbol_out = symbol;
    return 0;
}

/* Mutate each target witness independently.  Modes 15 and 16 alter one of
 * the two stackblock_size consumers while leaving the other untouched;
 * mode 17 alters only the rseq syscall witness.  A direct loader which
 * trusts release profiles or a single instruction shape would admit one of
 * these stale artifacts. */
static int patch_frozen_aarch64_pthread_contract(
    uint8_t *map, size_t size, int mode)
{
    struct dlfrz_elf64_dyn_view view;
    Elf64_Sym pthread_create;
    uint8_t *elf = NULL;
    uint8_t *alloca_code = NULL;
    uint8_t *getattr_code = NULL;
    size_t elf_size = 0;
    size_t alloca_size = 0;
    size_t getattr_size = 0;
    size_t alloca_load = SIZE_MAX;
    unsigned int alloca_matches = 0;

    if (frozen_target_libc(
            map, size, &elf, &elf_size, &view) < 0 ||
        frozen_aarch64_function(
            elf, elf_size, &view, "__libc_alloca_cutoff", 20, 128,
            &alloca_code, &alloca_size, NULL) < 0)
        return -1;

    for (size_t p = 0; p + sizeof(uint32_t) <= alloca_size;
         p += sizeof(uint32_t)) {
        uint32_t load;
        unsigned int value_reg;
        int has_divide = 0;

        memcpy(&load, alloca_code + p, sizeof(load));
        if ((load & UINT32_C(0xffc00000)) != UINT32_C(0xf9400000))
            continue;
        value_reg = load & 31U;
        for (size_t q = p + sizeof(uint32_t);
             q + sizeof(uint32_t) <= alloca_size && q <= p + 24;
             q += sizeof(uint32_t)) {
            uint32_t shift;

            memcpy(&shift, alloca_code + q, sizeof(shift));
            if ((shift & UINT32_C(0xfffffc00)) ==
                    UINT32_C(0xd342fc00) &&
                ((shift >> 5) & 31U) == value_reg) {
                has_divide = 1;
                break;
            }
        }
        if (!has_divide)
            continue;
        alloca_load = p;
        alloca_matches++;
    }
    if (alloca_matches != 1)
        return -1;

    if (mode == 15) {
        uint32_t load;
        uint32_t immediate;

        memcpy(&load, alloca_code + alloca_load, sizeof(load));
        immediate = (load >> 10) & UINT32_C(0xfff);
        if (immediate == UINT32_C(0xfff))
            return -1;
        load &= ~(UINT32_C(0xfff) << 10);
        load |= (immediate + 1) << 10;
        memcpy(alloca_code + alloca_load, &load, sizeof(load));
        return 0;
    }

    if (mode == 16) {
        uint32_t alloca_instruction;
        uint32_t stack_size_immediate;
        size_t selected = SIZE_MAX;
        unsigned int candidates = 0;

        if (frozen_aarch64_function(
                elf, elf_size, &view, "pthread_getattr_np", 64, 2048,
                &getattr_code, &getattr_size, NULL) < 0)
            return -1;
        memcpy(&alloca_instruction, alloca_code + alloca_load,
               sizeof(alloca_instruction));
        stack_size_immediate =
            (alloca_instruction >> 10) & UINT32_C(0xfff);
        if (stack_size_immediate == 0 ||
            stack_size_immediate == UINT32_C(0xfff))
            return -1;

        for (size_t p = 0; p + sizeof(uint32_t) <= getattr_size;
             p += sizeof(uint32_t)) {
            uint32_t load;
            unsigned int base;
            int have_stack = 0;
            int have_guard = 0;

            memcpy(&load, getattr_code + p, sizeof(load));
            if ((load & UINT32_C(0xffc00000)) !=
                    UINT32_C(0xf9400000) ||
                ((load >> 10) & UINT32_C(0xfff)) !=
                    stack_size_immediate)
                continue;
            base = (load >> 5) & 31U;
            for (size_t q = p > 96 ? p - 96 : 0;
                 q + sizeof(uint32_t) <= getattr_size && q <= p + 48;
                 q += sizeof(uint32_t)) {
                uint32_t adjacent;
                uint32_t immediate;

                memcpy(&adjacent, getattr_code + q, sizeof(adjacent));
                if ((adjacent & UINT32_C(0xffc00000)) !=
                        UINT32_C(0xf9400000) ||
                    ((adjacent >> 5) & 31U) != base)
                    continue;
                immediate = (adjacent >> 10) & UINT32_C(0xfff);
                if (immediate + 1 == stack_size_immediate)
                    have_stack = 1;
                if (immediate == stack_size_immediate + 1)
                    have_guard = 1;
            }
            if (!have_stack || !have_guard)
                continue;
            selected = p;
            candidates++;
        }
        if (candidates != 1)
            return -1;
        {
            uint32_t load;

            memcpy(&load, getattr_code + selected, sizeof(load));
            load &= ~(UINT32_C(0xfff) << 10);
            load |= (stack_size_immediate + 2) << 10;
            memcpy(getattr_code + selected, &load, sizeof(load));
        }
        return 0;
    }

    if (mode == 17) {
        size_t code_offset;
        size_t window_size;
        uint8_t *window;
        size_t selected = SIZE_MAX;
        unsigned int candidates = 0;
        uint64_t window_vaddr = 0;

        if (frozen_aarch64_function(
                elf, elf_size, &view, "pthread_create", 64, 8192,
                &getattr_code, &getattr_size, &pthread_create) < 0)
            return -1;
        (void)getattr_code;
        (void)getattr_size;
        for (uint16_t i = 0; i < view.ehdr.e_phnum; i++) {
            Elf64_Phdr phdr;
            uint64_t end;

            if (!dlfrz_glibc_read_phdr(
                    elf, elf_size, &view.ehdr, i, &phdr) ||
                phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_X) ||
                phdr.p_filesz > phdr.p_memsz ||
                phdr.p_vaddr > UINT64_MAX - phdr.p_filesz)
                continue;
            end = phdr.p_vaddr + phdr.p_filesz;
            if (pthread_create.st_value < phdr.p_vaddr ||
                pthread_create.st_value > end)
                continue;
            window_vaddr = pthread_create.st_value - phdr.p_vaddr > 4096
                ? pthread_create.st_value - 4096 : phdr.p_vaddr;
            break;
        }
        if (window_vaddr == 0 || window_vaddr >= pthread_create.st_value ||
            pthread_create.st_value - window_vaddr > SIZE_MAX)
            return -1;
        window_size = (size_t)(pthread_create.st_value - window_vaddr);
        if (!dlfrz_glibc_vaddr_file_range(
                elf, elf_size, &view.ehdr, window_vaddr, window_size,
                &code_offset))
            return -1;
        window = elf + code_offset;
        for (size_t p = 0; p + 2 * sizeof(uint32_t) <= window_size;
             p += sizeof(uint32_t)) {
            uint32_t instruction;
            int has_svc = 0;

            memcpy(&instruction, window + p, sizeof(instruction));
            if (instruction != UINT32_C(0xd28024a8))
                continue;
            for (size_t q = p + sizeof(uint32_t);
                 q + sizeof(uint32_t) <= window_size && q <= p + 12;
                 q += sizeof(uint32_t)) {
                memcpy(&instruction, window + q, sizeof(instruction));
                if (instruction == UINT32_C(0xd4000001)) {
                    has_svc = 1;
                    break;
                }
            }
            if (!has_svc)
                continue;
            selected = p;
            candidates++;
        }
        if (candidates != 1)
            return -1;
        {
            uint32_t wrong_syscall = UINT32_C(0xd2802488);

            memcpy(window + selected, &wrong_syscall,
                   sizeof(wrong_syscall));
        }
        return 0;
    }

    return -1;
}

static int patch_file(const char *path, int operation)
{
    struct stat st;
    uint8_t *map;
    int fd;
    int rc;

    fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        perror(path);
        return 1;
    }
    if (fstat(fd, &st) < 0 || st.st_size <= 0) {
        perror("fstat");
        close(fd);
        return 1;
    }
    map = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE,
               MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }
    if (operation == 21)
        rc = patch_x86_cpu_contract(map, (size_t)st.st_size, operation);
    else if (operation == 22)
        rc = patch_frozen_interp(map, (size_t)st.st_size, operation);
    else if (operation == 20)
        rc = patch_frozen_glibc_dtv_descriptor(
            map, (size_t)st.st_size);
    else if (operation >= 18 && operation <= 19)
        rc = patch_frozen_interp(map, (size_t)st.st_size, operation);
    else if (operation >= 15 && operation <= 17)
        rc = patch_frozen_aarch64_pthread_contract(
            map, (size_t)st.st_size, operation);
    else if (operation == 14)
        rc = patch_frozen_tls_dtor_counter(map, (size_t)st.st_size);
    else if (operation == 12)
        rc = patch_frozen_libc_hook_consumer(map, (size_t)st.st_size);
    else if ((operation >= 7 && operation <= 11) || operation == 13)
        rc = patch_frozen_interp(map, (size_t)st.st_size, operation);
    else if (operation == 6)
        rc = patch_frozen_libc_release(map, (size_t)st.st_size);
    else if (operation == 5)
        rc = remove_required_glro_relocation(map, (size_t)st.st_size);
    else if (operation == 4)
        rc = patch_frozen_interp(map, (size_t)st.st_size, operation);
    else if (operation == 3)
        rc = patch_frozen_interp(map, (size_t)st.st_size, operation);
    else if (operation == 2)
        rc = patch_stable_release_minor(map, (size_t)st.st_size);
    else if (operation == 1)
        rc = patch_frozen_interp(map, (size_t)st.st_size, operation);
    else
        rc = patch_rtld_global_size(map, (size_t)st.st_size);
    if (rc == 0 && msync(map, (size_t)st.st_size, MS_SYNC) < 0) {
        perror("msync");
        rc = -1;
    }
    munmap(map, (size_t)st.st_size);
    close(fd);
    if (rc != 0)
        fprintf(stderr, "%s: could not patch requested identity\n", path);
    return rc != 0;
}

static int validate_relocation_file(const char *path)
{
    enum dlfrz_glibc_layout_id layout;
    struct stat st;
    uint8_t *map;
    uint64_t glro_vaddr;
    uint64_t glro_size;
    int fd;
    int valid = 0;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 1;
    if (fstat(fd, &st) < 0 || st.st_size <= 0) {
        close(fd);
        return 1;
    }
    map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map != MAP_FAILED &&
        locate_glibc_layout(map, (size_t)st.st_size, &layout,
                            &glro_vaddr, &glro_size) == 0 &&
        dlfrz_glibc_glro_relocations_valid(
            map, (size_t)st.st_size, layout, glro_vaddr, glro_size))
        valid = 1;
    if (map != MAP_FAILED)
        munmap(map, (size_t)st.st_size);
    close(fd);
    return valid ? 0 : 1;
}

static int validate_identity_file(const char *path, int musl)
{
    struct stat st;
    uint8_t *map;
    int fd;
    int valid = 0;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 1;
    if (fstat(fd, &st) < 0 || st.st_size <= 0 ||
        (uintmax_t)st.st_size > SIZE_MAX) {
        close(fd);
        return 1;
    }
    map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map != MAP_FAILED &&
        (musl ? dlfrz_musl_rtld_identity(map, (size_t)st.st_size)
              : dlfrz_glibc_rtld_identity(
                    map, (size_t)st.st_size, NULL)))
        valid = 1;
    if (map != MAP_FAILED)
        munmap(map, (size_t)st.st_size);
    close(fd);
    return valid ? 0 : 1;
}

static int validate_x86_cpu_contract_file(const char *path)
{
    struct dlfrz_glibc_rtld_identity identity;
    struct dlfrz_glibc_x86_cpu_contract contract;
    enum dlfrz_glibc_layout_id layout;
    struct stat st;
    uint8_t *map = MAP_FAILED;
    int fd;
    int minor;
    int valid = 0;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 1;
    if (fstat(fd, &st) < 0 || st.st_size <= 0 ||
        (uintmax_t)st.st_size > SIZE_MAX)
        goto out;
    map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED ||
        !dlfrz_glibc_rtld_identity(map, (size_t)st.st_size, &identity))
        goto out;
    layout = dlfrz_glibc_layout_lookup(
        identity.machine, identity.global_ro_size, identity.global_size);
    minor = dlfrz_glibc_stable_release_minor(map, (size_t)st.st_size);
    valid = minor >= 0 && dlfrz_glibc_x86_cpu_contract_valid(
        map, (size_t)st.st_size, layout, minor,
        identity.global_ro_vaddr, identity.global_ro_size, &contract, NULL);
    if (valid)
        printf("%u\n", contract.generic_kind);

out:
    if (map != MAP_FAILED)
        munmap(map, (size_t)st.st_size);
    close(fd);
    return valid ? 0 : 1;
}

static int validate_dlfcn_hook_file(const char *path, const char *offset_text)
{
    struct stat st;
    uint8_t *map;
    char *end = NULL;
    long parsed;
    int fd;
    int valid;

    errno = 0;
    parsed = strtol(offset_text, &end, 0);
    if (errno != 0 || !end || *end != '\0' || parsed < 0 ||
        parsed > INT32_MAX)
        return 1;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 1;
    if (fstat(fd, &st) < 0 || st.st_size <= 0 ||
        (uintmax_t)st.st_size > SIZE_MAX) {
        close(fd);
        return 1;
    }
    map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        return 1;
    }
    valid = dlfrz_glibc_dlfcn_hook_consumer_valid(
        map, (size_t)st.st_size, (int)parsed, NULL);
    if (!valid) {
        static const char *const names[9] = {
            "dlopen", "dlclose", "dlsym", "dlvsym", "dlerror",
            "dladdr", "dladdr1", "dlinfo", "dlmopen"
        };
        struct dlfrz_elf64_dyn_view view;
        uint64_t got = 0;

        if (dlfrz_elf64_dyn_view_init(map, (size_t)st.st_size, &view) &&
            dlfrz_glibc_glro_got_relocation(&view, &got)) {
            for (unsigned int slot = 0; slot < 9U; slot++) {
                size_t hook_at;
                size_t slot_at;
                int member_valid = dlfrz_glibc_dlfcn_public_member_valid(
                    &view, names[slot], slot, got, (int)parsed,
                    &hook_at, &slot_at);
                fprintf(stderr, "public slot %u (%s): %s", slot,
                        names[slot], member_valid ? "valid" : "invalid");
                if (!member_valid) {
                    Elf64_Sym symbol;
                    size_t function_offset;
                    size_t matches = 0;

                    if (dlfrz_glibc_function_definition(
                            &view, names[slot], &symbol) &&
                        dlfrz_glibc_vaddr_file_range(
                            view.elf, view.elf_size, &view.ehdr,
                            symbol.st_value, symbol.st_size,
                            &function_offset)) {
                        if (view.ehdr.e_machine == EM_X86_64)
                            matches = dlfrz_glibc_x86_dlfcn_member_matches(
                                view.elf + function_offset,
                                (size_t)symbol.st_size, symbol.st_value,
                                got, (int)parsed, slot,
                                (size_t)symbol.st_size, NULL, NULL);
                        else if (view.ehdr.e_machine == EM_AARCH64)
                            matches =
                                dlfrz_glibc_aarch64_dlfcn_member_matches(
                                    view.elf + function_offset,
                                    (size_t)symbol.st_size,
                                    symbol.st_value, got, (int)parsed,
                                    slot, (size_t)symbol.st_size,
                                    NULL, NULL);
                    }
                    fprintf(stderr, " (matches=%zu)", matches);
                }
                fputc('\n', stderr);
            }
            for (unsigned int slot = 9U;
                 slot < DLFRZ_GLIBC_DLFCN_HOOK_SLOTS; slot++) {
                size_t hook_at;
                size_t slot_at;
                int member_valid = dlfrz_glibc_dlfcn_internal_member_valid(
                    &view, slot, got, (int)parsed, &hook_at, &slot_at);
                fprintf(stderr, "internal slot %u: %s", slot,
                        member_valid ? "valid" : "invalid");
                if (!member_valid) {
                    size_t matches = 0;

                    for (uint16_t i = 0; i < view.ehdr.e_phnum; i++) {
                        Elf64_Phdr phdr;

                        if (!dlfrz_glibc_read_phdr(
                                view.elf, view.elf_size, &view.ehdr,
                                i, &phdr) || phdr.p_type != PT_LOAD ||
                            !(phdr.p_flags & PF_X) || phdr.p_filesz == 0 ||
                            phdr.p_offset > view.elf_size ||
                            phdr.p_filesz >
                                view.elf_size - (size_t)phdr.p_offset)
                            continue;
                        if (view.ehdr.e_machine == EM_X86_64)
                            matches +=
                                dlfrz_glibc_x86_dlfcn_member_matches(
                                    view.elf + (size_t)phdr.p_offset,
                                    (size_t)phdr.p_filesz, phdr.p_vaddr,
                                    got, (int)parsed, slot, 1024U,
                                    NULL, NULL);
                        else if (view.ehdr.e_machine == EM_AARCH64)
                            matches +=
                                dlfrz_glibc_aarch64_dlfcn_member_matches(
                                    view.elf + (size_t)phdr.p_offset,
                                    (size_t)phdr.p_filesz, phdr.p_vaddr,
                                    got, (int)parsed, slot, 1024U,
                                    NULL, NULL);
                    }
                    fprintf(stderr, " (matches=%zu)", matches);
                }
                fputc('\n', stderr);
            }
        }
    }
    munmap(map, (size_t)st.st_size);
    close(fd);
    return valid ? 0 : 1;
}

static int vaddr_file_range_selftest(void)
{
    unsigned char image[512] = {0};
    Elf64_Ehdr ehdr = {0};
    Elf64_Phdr phdrs[2] = {0};
    size_t offset = 0;
    size_t available = 0;

    /* Deliberately make the table unaligned.  The helper must copy each
     * header into aligned storage rather than dereferencing image + 1. */
    ehdr.e_phoff = 1;
    ehdr.e_phentsize = sizeof(Elf64_Phdr);
    ehdr.e_phnum = 2;
    phdrs[0].p_type = PT_LOAD;
    phdrs[0].p_flags = PF_R;
    phdrs[0].p_offset = 256;
    phdrs[0].p_vaddr = 0x1000;
    phdrs[0].p_filesz = 64;
    phdrs[0].p_memsz = 64;
    memcpy(image + ehdr.e_phoff, phdrs, sizeof(phdrs));

    if (!dlfrz_glibc_vaddr_file_range(
            image, sizeof(image), &ehdr, 0x1010, 16, &offset) ||
        offset != 272 ||
        !dlfrz_glibc_vaddr_file_available(
            image, sizeof(image), &ehdr, 0x1010, &offset, &available) ||
        offset != 272 || available != 48 ||
        dlfrz_glibc_vaddr_file_range(
            image, sizeof(image), &ehdr, 0x1010, 49, &offset) ||
        !dlfrz_glibc_vaddr_file_range(
            image, sizeof(image), &ehdr, 0x1040, 0, &offset) ||
        offset != 320)
        return 0;

    /* Two PT_LOADs may cover the same virtual bytes only when they map the
     * same file bytes.  A different answer is ambiguous and must fail. */
    phdrs[1] = phdrs[0];
    phdrs[1].p_offset = 320;
    memcpy(image + ehdr.e_phoff, phdrs, sizeof(phdrs));
    if (dlfrz_glibc_vaddr_file_range(
            image, sizeof(image), &ehdr, 0x1010, 16, &offset) ||
        dlfrz_glibc_vaddr_file_available(
            image, sizeof(image), &ehdr, 0x1010, &offset, &available))
        return 0;
    phdrs[1].p_offset = phdrs[0].p_offset;
    memcpy(image + ehdr.e_phoff, phdrs, sizeof(phdrs));
    if (!dlfrz_glibc_vaddr_file_range(
            image, sizeof(image), &ehdr, 0x1010, 16, &offset) ||
        offset != 272)
        return 0;

    /* Reject malformed segment geometry before translating even a small
     * prefix which happens to remain inside the physical file. */
    phdrs[1].p_type = PT_NULL;
    phdrs[0].p_offset = 500;
    phdrs[0].p_filesz = 64;
    phdrs[0].p_memsz = 64;
    memcpy(image + ehdr.e_phoff, phdrs, sizeof(phdrs));
    if (dlfrz_glibc_vaddr_file_range(
            image, sizeof(image), &ehdr, 0x1000, 4, &offset))
        return 0;

    phdrs[0].p_offset = 0;
    phdrs[0].p_vaddr = UINT64_MAX - 7;
    phdrs[0].p_filesz = 8;
    phdrs[0].p_memsz = 16;
    memcpy(image + ehdr.e_phoff, phdrs, sizeof(phdrs));
    if (dlfrz_glibc_vaddr_file_range(
            image, sizeof(image), &ehdr, UINT64_MAX - 7, 1, &offset))
        return 0;

    ehdr.e_phoff = sizeof(image) - 1;
    ehdr.e_phnum = 1;
    if (dlfrz_glibc_vaddr_file_range(
            image, sizeof(image), &ehdr, 0x1000, 1, &offset))
        return 0;
    return 1;
}

static int config_path_selftest(void)
{
    static const char image[] =
        "\0/etc/ld.so.cache\0/etc/ld.so.preload\0"
        "  --inhibit-cache: do not use /wrong/ld.so.cache\0"
        "/etc/ld.so.cache\0";
    static const char custom[] =
        "\0/opt/runtime/etc/ld.so.cache\0"
        "/opt/runtime/etc/ld.so.preload\0";
    static const char ambiguous[] =
        "\0/etc/ld.so.cache\0/opt/etc/ld.so.cache\0";
    static const char diagnostic_only[] =
        "\0Do not use /etc/ld.so.cache\0";
    char path[128];

    if (!dlfrz_glibc_config_path(
            image, sizeof(image), DLFRZ_GLIBC_CACHE_SUFFIX,
            sizeof(DLFRZ_GLIBC_CACHE_SUFFIX) - 1,
            path, sizeof(path)) ||
        strcmp(path, "/etc/ld.so.cache") != 0 ||
        !dlfrz_glibc_config_path(
            image, sizeof(image), DLFRZ_GLIBC_PRELOAD_SUFFIX,
            sizeof(DLFRZ_GLIBC_PRELOAD_SUFFIX) - 1,
            path, sizeof(path)) ||
        strcmp(path, "/etc/ld.so.preload") != 0 ||
        !dlfrz_glibc_config_path(
            custom, sizeof(custom), DLFRZ_GLIBC_CACHE_SUFFIX,
            sizeof(DLFRZ_GLIBC_CACHE_SUFFIX) - 1,
            path, sizeof(path)) ||
        strcmp(path, "/opt/runtime/etc/ld.so.cache") != 0 ||
        dlfrz_glibc_config_path(
            ambiguous, sizeof(ambiguous), DLFRZ_GLIBC_CACHE_SUFFIX,
            sizeof(DLFRZ_GLIBC_CACHE_SUFFIX) - 1,
            path, sizeof(path)) ||
        dlfrz_glibc_config_path(
            diagnostic_only, sizeof(diagnostic_only),
            DLFRZ_GLIBC_CACHE_SUFFIX,
            sizeof(DLFRZ_GLIBC_CACHE_SUFFIX) - 1,
            path, sizeof(path)) ||
        dlfrz_glibc_config_path(
            custom, sizeof(custom), DLFRZ_GLIBC_CACHE_SUFFIX,
            sizeof(DLFRZ_GLIBC_CACHE_SUFFIX) - 1,
            path, 8))
        return 0;
    return 1;
}

static int dlfcn_consumer_sequence_selftest(void)
{
    unsigned char direct[] = {
        0x48, 0x8b, 0x05, 0xf9, 0x0f, 0x00, 0x00,
        0x48, 0x8b, 0x80, 0x88, 0x03, 0x00, 0x00,
        0x48, 0x8b, 0x40, 0x08
    };
    unsigned char overwritten[] = {
        0x48, 0x8b, 0x05, 0xf9, 0x0f, 0x00, 0x00,
        0x48, 0x31, 0xc0, /* xor %rax,%rax destroys the GLRO value */
        0x48, 0x8b, 0x80, 0x88, 0x03, 0x00, 0x00,
        0x48, 0x8b, 0x40, 0x08
    };
    struct dlfrz_glibc_dlfcn_consumer_evidence evidence;

    if (!dlfrz_glibc_x86_dlfcn_chain(
            direct, sizeof(direct), UINT64_C(0x1000), 0,
            UINT64_C(0x2000), 904, &evidence) ||
        evidence.glro_load_file_offset != 0 ||
        evidence.hook_load_file_offset != 7 ||
        evidence.slot_load_file_offset != 14 ||
        dlfrz_glibc_x86_dlfcn_chain(
            overwritten, sizeof(overwritten), UINT64_C(0x1000), 0,
            UINT64_C(0x2000), 904, NULL))
        return 0;

    /* Move the encoded hook displacement by one pointer-width while leaving
     * the release and object-size fingerprints untouched. */
    direct[10] = 0x90;
    return !dlfrz_glibc_x86_dlfcn_chain(
        direct, sizeof(direct), UINT64_C(0x1000), 0,
        UINT64_C(0x2000), 904, NULL);
}

/* Every private hook-table member needs an independent instruction witness.
 * Mutating only that member's displacement must invalidate the witness on
 * both admitted architectures. */
static int dlfcn_member_slot_selftest(void)
{
    unsigned char x86[] = {
        0x48, 0x8b, 0x05, 0xf9, 0x0f, 0x00, 0x00,
        0x48, 0x8b, 0x80, 0x88, 0x03, 0x00, 0x00,
        0x48, 0x8b, 0x40, 0x00,
        0xff, 0xd0
    };
    uint32_t aarch64[] = {
        UINT32_C(0xb0000000), /* adrp x0, 0x2000 */
        UINT32_C(0xf9400002), /* ldr x2, [x0] */
        UINT32_C(0xf941c443), /* ldr x3, [x2, #904] */
        UINT32_C(0xf9400061), /* ldr x1, [x3, #slot * 8] */
        UINT32_C(0xd63f0020)  /* blr x1 */
    };

    for (unsigned int slot = 0;
         slot < DLFRZ_GLIBC_DLFCN_HOOK_SLOTS; slot++) {
        size_t hook_position = SIZE_MAX;
        size_t slot_position = SIZE_MAX;
        unsigned int mutated =
            (slot + 1U) % DLFRZ_GLIBC_DLFCN_HOOK_SLOTS;

        x86[17] = (unsigned char)(slot * sizeof(uint64_t));
        if (dlfrz_glibc_x86_dlfcn_member_matches(
                x86, sizeof(x86), UINT64_C(0x1000), UINT64_C(0x2000),
                904, slot, sizeof(x86), &hook_position, &slot_position) !=
                1 || hook_position != 7U || slot_position != 14U)
            return 0;
        x86[17] = (unsigned char)(mutated * sizeof(uint64_t));
        if (dlfrz_glibc_x86_dlfcn_member_matches(
                x86, sizeof(x86), UINT64_C(0x1000), UINT64_C(0x2000),
                904, slot, sizeof(x86), NULL, NULL) != 0)
            return 0;

        aarch64[3] = UINT32_C(0xf9400061) | (slot << 10);
        hook_position = SIZE_MAX;
        slot_position = SIZE_MAX;
        if (dlfrz_glibc_aarch64_dlfcn_member_matches(
                (const unsigned char *)aarch64, sizeof(aarch64),
                UINT64_C(0x1000), UINT64_C(0x2000), 904, slot,
                sizeof(aarch64), &hook_position, &slot_position) != 1 ||
            hook_position != 8U || slot_position != 12U)
            return 0;
        aarch64[3] = UINT32_C(0xf9400061) | (mutated << 10);
        if (dlfrz_glibc_aarch64_dlfcn_member_matches(
                (const unsigned char *)aarch64, sizeof(aarch64),
                UINT64_C(0x1000), UINT64_C(0x2000), 904, slot,
                sizeof(aarch64), NULL, NULL) != 0)
            return 0;
    }
    return 1;
}

/* Only real, reachable instructions whose paths reach the common predecessor
 * may form the private enum witness.  The post-store value and opcode bytes
 * embedded in movabs immediates must neither invalidate the valid contract nor
 * replace its mutated reaching value. */
static int x86_cpu_kind_control_flow_selftest(void)
{
    unsigned char code[256];
    const uint64_t code_vaddr = UINT64_C(0x1000);
    const uint64_t cpu_vaddr = UINT64_C(0x4000);
    const size_t join = 100;
    const size_t store = 120;
    uint32_t value;
    uint32_t kind = 0;
    size_t immediate_offset = SIZE_MAX;
    int32_t displacement;

    memset(code, 0x90, sizeof(code));

    /* Make every kind root CFG-reachable from the initializer entry. */
    code[0] = 0x74;
    code[1] = 18; /* root 4 at 20 */
    code[2] = 0x74;
    code[3] = 36; /* root 1 at 40 */
    code[4] = 0x74;
    code[5] = 54; /* root 3 at 60 */
    code[6] = 0xe9;
    displacement = (int32_t)(90 - 11); /* fallthrough root 2 */
    memcpy(code + 7, &displacement, sizeof(displacement));

    code[20] = 0xb8;
    value = 4;
    memcpy(code + 21, &value, sizeof(value));
    code[25] = 0xe9;
    displacement = (int32_t)(join - 30);
    memcpy(code + 26, &displacement, sizeof(displacement));

    code[40] = 0xb8;
    value = 1;
    memcpy(code + 41, &value, sizeof(value));
    code[45] = 0xe9;
    displacement = (int32_t)(join - 50);
    memcpy(code + 46, &displacement, sizeof(displacement));

    code[60] = 0xb8;
    value = 3;
    memcpy(code + 61, &value, sizeof(value));
    code[65] = 0xe9;
    displacement = (int32_t)(join - 70);
    memcpy(code + 66, &displacement, sizeof(displacement));

    code[90] = 0xb8;
    value = 2;
    memcpy(code + 91, &value, sizeof(value));

    code[store] = 0x89;
    code[store + 1] = 0x05;
    displacement = (int32_t)(cpu_vaddr -
                              (code_vaddr + store + 6));
    memcpy(code + store + 2, &displacement, sizeof(displacement));

    code[130] = 0xb8;
    value = 4; /* unrelated post-store constant */
    memcpy(code + 131, &value, sizeof(value));

    /* These apparent mov/jmp opcodes are data inside two movabs immediates. */
    code[190] = 0x48;
    code[191] = 0xb8;
    code[192] = 0xb8;
    value = 4;
    memcpy(code + 193, &value, sizeof(value));
    code[210] = 0x48;
    code[211] = 0xb8;
    code[212] = 0xe9;
    displacement = (int32_t)(join - 217);
    memcpy(code + 213, &displacement, sizeof(displacement));
    code[230] = 0xc3;

    if (!dlfrz_glibc_x86_cpu_generic_kind(
            code, sizeof(code), code_vaddr, 0, cpu_vaddr, &kind,
            &immediate_offset) ||
        kind != 4 || immediate_offset != 21)
        return 0;

    /* The fallthrough assignment must reach the join without a return. */
    code[96] = 0xc3;
    if (dlfrz_glibc_x86_cpu_generic_kind(
            code, sizeof(code), code_vaddr, 0, cpu_vaddr, NULL, NULL))
        return 0;
    code[96] = 0x90;

    /* Nor may an intervening unconditional transfer masquerade as flow. */
    code[96] = 0xeb;
    code[97] = 12; /* target 110, bypassing the join at 100 */
    if (dlfrz_glibc_x86_cpu_generic_kind(
            code, sizeof(code), code_vaddr, 0, cpu_vaddr, NULL, NULL))
        return 0;
    code[96] = 0x90;
    code[97] = 0x90;

    value = 6;
    memcpy(code + 21, &value, sizeof(value));
    memcpy(code + 193, &value, sizeof(value));
    return !dlfrz_glibc_x86_cpu_generic_kind(
        code, sizeof(code), code_vaddr, 0, cpu_vaddr, NULL, NULL);
}

static int selftest(void)
{
    static const char stable[] =
        "ld.so (GNU libc) stable release version 2.43.";
    static const char development[] =
        "ld.so (GNU libc) development release version 2.43.9000";
    static const char downstream_snapshot[] =
        "ld.so (GNU libc) downstream release version 2.43.9000";

    if (!vaddr_file_range_selftest() ||
        !config_path_selftest() ||
        !dlfcn_consumer_sequence_selftest() ||
        !dlfcn_member_slot_selftest() ||
        !x86_cpu_kind_control_flow_selftest() ||
        dlfrz_glibc_layout_lookup(EM_X86_64, 928, 2120) !=
            DLFRZ_GLIBC_X86_2_40 ||
        dlfrz_glibc_layout_lookup(EM_X86_64, 928, 2136) !=
            DLFRZ_GLIBC_X86_2_44 ||
        dlfrz_glibc_layout_lookup(EM_AARCH64, 400, 2272) !=
            DLFRZ_GLIBC_AARCH64_2_43 ||
        dlfrz_glibc_layout_lookup(EM_AARCH64, 400, 2288) !=
            DLFRZ_GLIBC_LAYOUT_UNKNOWN ||
        dlfrz_glibc_stable_release_minor(stable, sizeof(stable) - 1) != 43 ||
        dlfrz_glibc_stable_release_minor(development,
                                          sizeof(development) - 1) != -1 ||
        !dlfrz_glibc_layout_release_is_supported(
            DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY, 39) ||
        !dlfrz_glibc_layout_release_is_supported(
            DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY, 40) ||
        dlfrz_glibc_layout_release_is_supported(
            DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY, 36) ||
        dlfrz_glibc_layout_release_is_supported(
            DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY, 41) ||
        !dlfrz_glibc_layout_release_is_supported(
            DLFRZ_GLIBC_X86_2_40, 43) ||
        dlfrz_glibc_layout_release_is_supported(
            DLFRZ_GLIBC_X86_2_40, 44) ||
        !dlfrz_glibc_layout_release_is_supported(
            DLFRZ_GLIBC_X86_2_44, 44) ||
        dlfrz_glibc_layout_release_is_supported(
            DLFRZ_GLIBC_X86_2_44, 43) ||
        dlfrz_glibc_layout_release_is_supported(
            DLFRZ_GLIBC_X86_2_44, 45) ||
        dlfrz_glibc_legacy_rtld_active_offset(
            DLFRZ_GLIBC_X86_2_34, 34) != 736 ||
        dlfrz_glibc_legacy_rtld_active_offset(
            DLFRZ_GLIBC_X86_2_34, 35) != 736 ||
        dlfrz_glibc_legacy_rtld_active_offset(
            DLFRZ_GLIBC_X86_2_34, 36) != -1 ||
        dlfrz_glibc_legacy_rtld_active_offset(
            DLFRZ_GLIBC_X86_2_40, 40) != -1 ||
        dlfrz_glibc_legacy_rtld_active_offset(
            DLFRZ_GLIBC_AARCH64_2_35_LARGE, 35) != 528 ||
        dlfrz_glibc_dlfcn_hook_offset(
            DLFRZ_GLIBC_X86_2_34, 34) != 888 ||
        dlfrz_glibc_dlfcn_hook_offset(
            DLFRZ_GLIBC_X86_2_34, 35) != 904 ||
        dlfrz_glibc_dlfcn_hook_offset(
            DLFRZ_GLIBC_X86_2_34, 36) != 896 ||
        dlfrz_glibc_dlfcn_hook_offset(
            DLFRZ_GLIBC_X86_RTLD_896_4336, 36) != 872 ||
        dlfrz_glibc_dlfcn_hook_offset(
            DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY, 40) != 928 ||
        dlfrz_glibc_dlfcn_hook_offset(
            DLFRZ_GLIBC_X86_2_40, 43) != 896 ||
        dlfrz_glibc_dlfcn_hook_offset(
            DLFRZ_GLIBC_X86_2_44, 44) != 904 ||
        dlfrz_glibc_dlfcn_hook_offset(
            DLFRZ_GLIBC_AARCH64_2_35, 39) != 664 ||
        dlfrz_glibc_dlfcn_hook_offset(
            DLFRZ_GLIBC_AARCH64_2_35_LARGE, 35) != 680 ||
        dlfrz_glibc_dlfcn_hook_offset(
            DLFRZ_GLIBC_AARCH64_2_41, 41) != 680 ||
        dlfrz_glibc_dlfcn_hook_offset(
            DLFRZ_GLIBC_X86_2_29, 33) != -1 ||
        dlfrz_glibc_dlfcn_hook_offset(
            DLFRZ_GLIBC_X86_2_40, 44) != -1 ||
        dlfrz_glibc_find_object_offset(
            DLFRZ_GLIBC_X86_2_34, 34) != -1 ||
        dlfrz_glibc_find_object_offset(
            DLFRZ_GLIBC_X86_2_34, 35) != 888 ||
        dlfrz_glibc_find_object_offset(
            DLFRZ_GLIBC_X86_RTLD_896_4336, 36) != 864 ||
        dlfrz_glibc_find_object_offset(
            DLFRZ_GLIBC_X86_2_44, 44) != 888 ||
        dlfrz_glibc_find_object_offset(
            DLFRZ_GLIBC_AARCH64_2_35, 36) != 656 ||
        dlfrz_glibc_find_object_offset(
            DLFRZ_GLIBC_AARCH64_2_35_LARGE, 35) != 664 ||
        dlfrz_glibc_direct_thread_layout_is_supported(
            DLFRZ_GLIBC_AARCH64_2_31) ||
        !dlfrz_glibc_direct_thread_layout_is_supported(
            DLFRZ_GLIBC_AARCH64_2_35) ||
        !dlfrz_glibc_direct_thread_layout_is_supported(
            DLFRZ_GLIBC_AARCH64_2_41) ||
        dlfrz_glibc_direct_thread_layout_is_supported(
            DLFRZ_GLIBC_AARCH64_2_27) ||
        dlfrz_glibc_direct_thread_layout_is_supported(
            DLFRZ_GLIBC_AARCH64_2_35_LARGE) ||
        dlfrz_glibc_direct_thread_layout_is_supported(
            DLFRZ_GLIBC_AARCH64_RTLD_672_4520) ||
        dlfrz_glibc_direct_thread_layout_is_supported(
            DLFRZ_GLIBC_AARCH64_2_40_LEGACY) ||
        dlfrz_glibc_direct_thread_layout_is_supported(
            DLFRZ_GLIBC_AARCH64_2_43) ||
        dlfrz_glibc_direct_thread_layout_is_supported(
            DLFRZ_GLIBC_X86_2_17) ||
        dlfrz_glibc_direct_thread_layout_is_supported(
            DLFRZ_GLIBC_X86_2_29) ||
        dlfrz_glibc_direct_thread_layout_is_supported(
            DLFRZ_GLIBC_X86_RTLD_544_4000) ||
        !dlfrz_glibc_direct_thread_layout_is_supported(
            DLFRZ_GLIBC_X86_2_34) ||
        !dlfrz_glibc_direct_thread_layout_is_supported(
            DLFRZ_GLIBC_X86_2_40) ||
        !dlfrz_glibc_direct_thread_layout_is_supported(
            DLFRZ_GLIBC_X86_2_44) ||
        !dlfrz_glibc_glro_reloc_profile_matches(
            DLFRZ_GLIBC_X86_2_34, 816, 824, 840, 848, 856, 864) ||
        !dlfrz_glibc_glro_reloc_profile_matches(
            DLFRZ_GLIBC_AARCH64_2_41,
            600, 608, 624, 632, 640, 648) ||
        !dlfrz_glibc_glro_reloc_profile_matches(
            DLFRZ_GLIBC_X86_2_44,
            816, 824, 840, 848, 856, 864) ||
        dlfrz_glibc_glro_reloc_profile_matches(
            DLFRZ_GLIBC_X86_2_34, 816, 824, 840, 848, 856, 872) ||
        dlfrz_glibc_layout_release_is_supported(
            DLFRZ_GLIBC_LAYOUT_UNKNOWN, 43) ||
        dlfrz_glibc_direct_thread_layout_is_supported(
            DLFRZ_GLIBC_LAYOUT_UNKNOWN) ||
        dlfrz_glibc_is_development_release(stable, sizeof(stable) - 1) ||
        !dlfrz_glibc_is_development_release(development,
                                             sizeof(development) - 1) ||
        !dlfrz_glibc_is_development_release(downstream_snapshot,
                                             sizeof(downstream_snapshot) - 1))
        return 1;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0)
        return selftest();
    if (argc == 3 && strcmp(argv[1], "--elf") == 0)
        return patch_file(argv[2], 0);
    if (argc == 3 && strcmp(argv[1], "--frozen") == 0)
        return patch_file(argv[2], 1);
    if (argc == 3 && strcmp(argv[1], "--release-mismatch") == 0)
        return patch_file(argv[2], 2);
    if (argc == 3 && strcmp(argv[1], "--frozen-release-missing") == 0)
        return patch_file(argv[2], 3);
    if (argc == 3 && strcmp(argv[1], "--frozen-reloc-missing") == 0)
        return patch_file(argv[2], 4);
    if (argc == 3 && strcmp(argv[1], "--elf-reloc-missing") == 0)
        return patch_file(argv[2], 5);
    if (argc == 3 &&
        strcmp(argv[1], "--frozen-libc-release-mismatch") == 0)
        return patch_file(argv[2], 6);
    if (argc == 3 &&
        strcmp(argv[1], "--frozen-tunable-reloc-unsupported") == 0)
        return patch_file(argv[2], 7);
    if (argc == 3 &&
        strcmp(argv[1], "--frozen-tunable-reloc-symbol") == 0)
        return patch_file(argv[2], 8);
    if (argc == 3 &&
        strcmp(argv[1], "--frozen-tunable-callback-clobber") == 0)
        return patch_file(argv[2], 9);
    if (argc == 3 &&
        strcmp(argv[1], "--frozen-tunable-self-loop") == 0)
        return patch_file(argv[2], 10);
    if (argc == 3 &&
        strcmp(argv[1], "--frozen-tunable-fallthrough") == 0)
        return patch_file(argv[2], 11);
    if (argc == 3 &&
        strcmp(argv[1], "--frozen-hook-consumer-mismatch") == 0)
        return patch_file(argv[2], 12);
    if (argc == 3 &&
        strcmp(argv[1], "--frozen-tunable-callback-bypass") == 0)
        return patch_file(argv[2], 13);
    if (argc == 3 &&
        strcmp(argv[1], "--frozen-tls-dtor-counter-mismatch") == 0)
        return patch_file(argv[2], 14);
    if (argc == 3 &&
        strcmp(argv[1], "--frozen-aarch64-alloca-stack-mismatch") == 0)
        return patch_file(argv[2], 15);
    if (argc == 3 &&
        strcmp(argv[1], "--frozen-aarch64-getattr-stack-mismatch") == 0)
        return patch_file(argv[2], 16);
    if (argc == 3 &&
        strcmp(argv[1], "--frozen-aarch64-rseq-mismatch") == 0)
        return patch_file(argv[2], 17);
    if (argc == 3 &&
        strcmp(argv[1], "--frozen-x86-cpu-accessor-mismatch") == 0)
        return patch_file(argv[2], 18);
    if (argc == 3 &&
        strcmp(argv[1], "--frozen-x86-cpu-layout-mismatch") == 0)
        return patch_file(argv[2], 19);
    if (argc == 3 &&
        strcmp(argv[1], "--frozen-glibc-dtv-descriptor-mismatch") == 0)
        return patch_file(argv[2], 20);
    if (argc == 3 &&
        strcmp(argv[1], "--elf-x86-cpu-kind-root-mismatch") == 0)
        return patch_file(argv[2], 21);
    if (argc == 3 &&
        strcmp(argv[1], "--frozen-x86-cpu-kind-root-mismatch") == 0)
        return patch_file(argv[2], 22);
    if (argc == 3 && strcmp(argv[1], "--validate-relocations") == 0)
        return validate_relocation_file(argv[2]);
    if (argc == 3 && strcmp(argv[1], "--validate-family") == 0)
        return validate_identity_file(argv[2], 0);
    if (argc == 3 && strcmp(argv[1], "--validate-musl-family") == 0)
        return validate_identity_file(argv[2], 1);
    if (argc == 3 && strcmp(argv[1], "--validate-x86-cpu") == 0)
        return validate_x86_cpu_contract_file(argv[2]);
    if (argc == 4 && strcmp(argv[1], "--validate-dlfcn-hook") == 0)
        return validate_dlfcn_hook_file(argv[3], argv[2]);
    fprintf(stderr,
            "usage: %s --selftest | --elf FILE | --frozen FILE | "
            "--release-mismatch FILE | --frozen-release-missing FILE | "
            "--frozen-reloc-missing FILE | --elf-reloc-missing FILE | "
            "--frozen-libc-release-mismatch FILE | "
            "--frozen-tunable-reloc-unsupported FILE | "
            "--frozen-tunable-reloc-symbol FILE | "
            "--frozen-tunable-callback-clobber FILE | "
            "--frozen-tunable-self-loop FILE | "
            "--frozen-tunable-fallthrough FILE | "
            "--frozen-tunable-callback-bypass FILE | "
            "--frozen-hook-consumer-mismatch FILE | "
            "--frozen-tls-dtor-counter-mismatch FILE | "
            "--frozen-aarch64-alloca-stack-mismatch FILE | "
            "--frozen-aarch64-getattr-stack-mismatch FILE | "
            "--frozen-aarch64-rseq-mismatch FILE | "
            "--frozen-glibc-dtv-descriptor-mismatch FILE | "
            "--frozen-x86-cpu-accessor-mismatch FILE | "
            "--frozen-x86-cpu-layout-mismatch FILE | "
            "--frozen-x86-cpu-kind-root-mismatch FILE | "
            "--elf-x86-cpu-kind-root-mismatch FILE | "
            "--validate-dlfcn-hook OFFSET FILE | "
            "--validate-relocations FILE | --validate-family FILE | "
            "--validate-musl-family FILE | --validate-x86-cpu FILE\n",
            argv[0]);
    return 2;
}
