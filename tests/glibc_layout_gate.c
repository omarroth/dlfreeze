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
    if (operation == 23) {
        int32_t originals[DLFRZ_GLIBC_X86_CPU_END_WRITERS_MAX];

        if (evidence.object_end_displacement_count == 0 ||
            evidence.object_end_displacement_count >
                DLFRZ_GLIBC_X86_CPU_END_WRITERS_MAX)
            return -1;
        for (size_t writer = 0;
             writer < evidence.object_end_displacement_count; writer++) {
            size_t offset =
                evidence.object_end_displacement_file_offsets[writer];
            int32_t moved;

            if (!range_fits(offset, sizeof(moved), elf_size))
                return -1;
            memcpy(&originals[writer], elf + offset, sizeof(moved));
            if (originals[writer] > INT32_MAX - 4)
                return -1;
            moved = originals[writer] + 4;
            memcpy(elf + offset, &moved, sizeof(moved));
        }
        if (dlfrz_glibc_x86_cpu_contract_valid(
                elf, elf_size, layout, minor, identity.global_ro_vaddr,
                identity.global_ro_size, NULL, NULL)) {
            for (size_t writer = 0;
                 writer < evidence.object_end_displacement_count; writer++)
                memcpy(elf +
                           evidence.object_end_displacement_file_offsets[
                               writer],
                       &originals[writer], sizeof(originals[writer]));
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
        if (operation == 18 || operation == 19 || operation == 22 ||
            operation == 23)
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

static int patch_frozen_glibc_cache_path(uint8_t *map, size_t size,
                                         const char *replacement)
{
    static const char original[] = "/etc/ld.so.cache";
    struct dlfrz_footer *footer;
    struct dlfrz_entry *entries;
    size_t replacement_size;
    size_t entries_size;
    size_t matches = 0;

    if (!replacement || replacement[0] != '/')
        return -1;
    replacement_size = strlen(replacement);
    if (replacement_size == 0 ||
        replacement_size > sizeof(original) - 1 ||
        size < sizeof(struct dlfrz_footer))
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
        uint8_t *elf;
        size_t elf_size;

        if (!(entries[i].flags & DLFRZ_FLAG_INTERP) ||
            entries[i].data_size > SIZE_MAX ||
            !range_fits((size_t)entries[i].data_offset,
                        (size_t)entries[i].data_size, size))
            continue;
        elf = map + (size_t)entries[i].data_offset;
        elf_size = (size_t)entries[i].data_size;
        for (size_t offset = 0;
             offset + sizeof(original) <= elf_size; offset++) {
            if (memcmp(elf + offset, original, sizeof(original)) != 0)
                continue;
            memset(elf + offset, 0, sizeof(original));
            memcpy(elf + offset, replacement, replacement_size);
            matches++;
        }
    }
    return matches != 0 ? 0 : -1;
}

struct gate_cache_header {
    char magic[17];
    char version[3];
    uint32_t nlibs;
    uint32_t len_strings;
    uint8_t flags;
    uint8_t padding[3];
    uint32_t extension_offset;
    uint32_t unused[3];
};

struct gate_cache_extension {
    uint32_t magic;
    uint32_t count;
};

struct gate_cache_extension_section {
    uint32_t tag;
    uint32_t flags;
    uint32_t offset;
    uint32_t size;
};

static int patch_cache_tag2_map(uint8_t *map, size_t size)
{
    static const char magic[] = "glibc-ld.so.cache";
    static const char version[] = "1.1";
    struct gate_cache_header *header;
    struct gate_cache_extension *extension;
    struct gate_cache_extension_section *sections;
    size_t directory_end;
    size_t data_offset;

    if (size < sizeof(*header))
        return -1;
    header = (void *)map;
    if (memcmp(header->magic, magic, sizeof(header->magic)) != 0 ||
        memcmp(header->version, version, sizeof(header->version)) != 0 ||
        header->extension_offset > size ||
        sizeof(*extension) > size - header->extension_offset)
        return -1;
    extension = (void *)(map + header->extension_offset);
    if (extension->magic != UINT32_C(0xeaa42174) ||
        extension->count == 0 ||
        (size_t)extension->count >
            (size - header->extension_offset - sizeof(*extension)) /
                sizeof(*sections))
        return -1;
    sections = (void *)(extension + 1);
    directory_end = header->extension_offset + sizeof(*extension) +
        (size_t)extension->count * sizeof(*sections);
    if (directory_end > SIZE_MAX - 7)
        return -1;
    data_offset = (directory_end + 7) & ~(size_t)7;
    if (data_offset > UINT32_MAX || size - data_offset < 8)
        return -1;
    sections[0].tag = 2;
    sections[0].flags = 0;
    sections[0].offset = (uint32_t)data_offset;
    sections[0].size = 8;
    return 0;
}

static int patch_mapped_file(const char *path,
                             int (*patch)(uint8_t *, size_t))
{
    struct stat st;
    uint8_t *map;
    int fd;
    int result;

    fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return 1;
    if (fstat(fd, &st) < 0 || st.st_size <= 0 ||
        (uintmax_t)st.st_size > SIZE_MAX) {
        close(fd);
        return 1;
    }
    map = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE,
               MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        return 1;
    }
    result = patch(map, (size_t)st.st_size);
    if (result == 0 && msync(map, (size_t)st.st_size, MS_SYNC) < 0)
        result = -1;
    munmap(map, (size_t)st.st_size);
    close(fd);
    return result == 0 ? 0 : 1;
}

static int patch_frozen_cache_path_file(const char *path,
                                        const char *replacement)
{
    struct stat st;
    uint8_t *map;
    int fd;
    int result;

    fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return 1;
    if (fstat(fd, &st) < 0 || st.st_size <= 0 ||
        (uintmax_t)st.st_size > SIZE_MAX) {
        close(fd);
        return 1;
    }
    map = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE,
               MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        return 1;
    }
    result = patch_frozen_glibc_cache_path(
        map, (size_t)st.st_size, replacement);
    if (result == 0 && msync(map, (size_t)st.st_size, MS_SYNC) < 0)
        result = -1;
    munmap(map, (size_t)st.st_size);
    close(fd);
    return result == 0 ? 0 : 1;
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
    else if (operation == 22 || operation == 23)
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

/* CPU-feature layout fixtures intentionally cover distribution builds whose
 * unrelated _rtld_global total size is not in direct mode's full private-ABI
 * allowlist.  Select only the release's CPU profile here; production still
 * requires dlfrz_glibc_layout_lookup() to accept the complete interpreter
 * tuple before it can reach the same structural CPU validator. */
static enum dlfrz_glibc_layout_id
x86_cpu_fixture_profile(const struct dlfrz_glibc_rtld_identity *identity,
                        int minor)
{
    enum dlfrz_glibc_layout_id layout;

    if (!identity || identity->machine != EM_X86_64)
        return DLFRZ_GLIBC_LAYOUT_UNKNOWN;
    layout = dlfrz_glibc_layout_lookup(
        identity->machine, identity->global_ro_size,
        identity->global_size);
    if (layout != DLFRZ_GLIBC_LAYOUT_UNKNOWN)
        return layout;
    if (minor >= 34 && minor <= 39)
        return DLFRZ_GLIBC_X86_2_34;
    if (minor >= 40 && minor <= 43)
        return DLFRZ_GLIBC_X86_2_40;
    if (minor == 44)
        return DLFRZ_GLIBC_X86_2_44;
    return DLFRZ_GLIBC_LAYOUT_UNKNOWN;
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
    minor = dlfrz_glibc_stable_release_minor(map, (size_t)st.st_size);
    layout = x86_cpu_fixture_profile(&identity, minor);
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

static int validate_x86_cpu_probe_files(const char *interp_path,
                                        const char *libc_path)
{
    struct dlfrz_glibc_rtld_identity identity;
    struct dlfrz_glibc_x86_cpu_contract cpu;
    struct dlfrz_glibc_getauxval_contract aux;
    enum dlfrz_glibc_layout_id layout;
    struct stat interp_stat;
    struct stat libc_stat;
    uint8_t *interp = MAP_FAILED;
    uint8_t *libc = MAP_FAILED;
    int interp_fd = -1;
    int libc_fd = -1;
    int minor;
    int valid = 0;

    interp_fd = open(interp_path, O_RDONLY | O_CLOEXEC);
    libc_fd = open(libc_path, O_RDONLY | O_CLOEXEC);
    if (interp_fd < 0 || libc_fd < 0 ||
        fstat(interp_fd, &interp_stat) < 0 ||
        fstat(libc_fd, &libc_stat) < 0 ||
        interp_stat.st_size <= 0 || libc_stat.st_size <= 0 ||
        (uintmax_t)interp_stat.st_size > SIZE_MAX ||
        (uintmax_t)libc_stat.st_size > SIZE_MAX)
        goto out;
    interp = mmap(NULL, (size_t)interp_stat.st_size, PROT_READ,
                  MAP_PRIVATE, interp_fd, 0);
    libc = mmap(NULL, (size_t)libc_stat.st_size, PROT_READ,
                MAP_PRIVATE, libc_fd, 0);
    if (interp == MAP_FAILED || libc == MAP_FAILED ||
        !dlfrz_glibc_rtld_identity(
            interp, (size_t)interp_stat.st_size, &identity))
        goto out;
    minor = dlfrz_glibc_stable_release_minor(
        interp, (size_t)interp_stat.st_size);
    layout = x86_cpu_fixture_profile(&identity, minor);
    valid = minor >= 0 &&
        dlfrz_glibc_x86_cpu_contract_valid(
            interp, (size_t)interp_stat.st_size, layout, minor,
            identity.global_ro_vaddr, identity.global_ro_size,
            &cpu, NULL) &&
        dlfrz_glibc_x86_getauxval_contract_valid(
            libc, (size_t)libc_stat.st_size, identity.global_ro_size,
            &aux, NULL) &&
        (minor < 38 ||
         dlfrz_glibc_x86_cpu_hwcap2_association_valid(
             interp, (size_t)interp_stat.st_size,
             identity.global_ro_vaddr, &cpu, &aux, NULL));
    if (valid)
        printf("%d %llu %llu %llu\n", minor,
               (unsigned long long)cpu.published_prefix_size,
               (unsigned long long)aux.hwcap_offset,
               (unsigned long long)aux.hwcap2_offset);

out:
    if (interp != MAP_FAILED)
        munmap(interp, (size_t)interp_stat.st_size);
    if (libc != MAP_FAILED)
        munmap(libc, (size_t)libc_stat.st_size);
    if (interp_fd >= 0)
        close(interp_fd);
    if (libc_fd >= 0)
        close(libc_fd);
    return valid ? 0 : 1;
}

static int validate_aarch64_getauxval_file(const char *path,
                                           const char *glro_size_text)
{
    struct dlfrz_glibc_getauxval_contract contract;
    struct stat st;
    uint8_t *map = MAP_FAILED;
    char *end = NULL;
    unsigned long long parsed;
    int fd = -1;
    int valid = 0;

    errno = 0;
    parsed = strtoull(glro_size_text, &end, 0);
    if (errno != 0 || !end || *end != '\0' || parsed == 0 ||
        parsed > UINT64_MAX)
        return 1;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) < 0 || st.st_size <= 0 ||
        (uintmax_t)st.st_size > SIZE_MAX)
        goto out;
    map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED)
        goto out;
    valid = dlfrz_glibc_aarch64_getauxval_contract_valid(
        map, (size_t)st.st_size, (uint64_t)parsed, &contract, NULL);
    if (valid)
        printf("%llu %llu\n",
               (unsigned long long)contract.hwcap_offset,
               (unsigned long long)contract.hwcap2_offset);

out:
    if (map != MAP_FAILED)
        munmap(map, (size_t)st.st_size);
    if (fd >= 0)
        close(fd);
    return valid ? 0 : 1;
}

static int aarch64_aux_ranges_overlap(size_t left, size_t left_size,
                                      size_t right, size_t right_size)
{
    if (left_size > SIZE_MAX - left || right_size > SIZE_MAX - right)
        return 1;
    return left < right + right_size && right < left + left_size;
}

static int aarch64_getauxval_mutation_gate(const uint8_t *image,
                                           size_t image_size,
                                           uint64_t glro_size)
{
    struct dlfrz_glibc_aarch64_getauxval_evidence evidence;
    struct dlfrz_glibc_getauxval_contract contract;
    struct dlfrz_elf64_dyn_view view;
    Elf64_Sym function;
    uint8_t *mutant = NULL;
    size_t function_offset;
    size_t duplicate_offset = SIZE_MAX;
    size_t scan_size;
    uint32_t instruction;
    int valid = 0;

    if (!dlfrz_glibc_aarch64_getauxval_contract_valid(
            image, image_size, glro_size, &contract, &evidence) ||
        !dlfrz_elf64_dyn_view_init(image, image_size, &view) ||
        dlfrz_elf64_dyn_view_find(
            &view, "__getauxval", &function, NULL) != 1 ||
        !dlfrz_glibc_vaddr_file_range(
            image, image_size, &view.ehdr,
            function.st_value, function.st_size, &function_offset) ||
        evidence.branch_file_offsets[1] !=
            evidence.branch_file_offsets[0] + 2U * sizeof(uint32_t) ||
        evidence.dispatcher_file_offset > image_size ||
        4U * sizeof(uint32_t) >
            image_size - evidence.dispatcher_file_offset)
        return 0;
    mutant = malloc(image_size);
    if (!mutant)
        return 0;

    /* A retargeted HWCAP branch must not be allowed to escape the public
     * function's exact leaf grammar. */
    memcpy(mutant, image, image_size);
    instruction = dlfrz_glibc_read_u32(
        mutant + evidence.branch_file_offsets[0]);
    instruction &= ~(UINT32_C(0x7ffff) << 5);
    instruction |= UINT32_C(0x40000) << 5;
    memcpy(mutant + evidence.branch_file_offsets[0], &instruction,
           sizeof(instruction));
    if (dlfrz_glibc_aarch64_getauxval_contract_valid(
            mutant, image_size, glro_size, NULL, NULL))
        goto out;

    /* The admitted quartet must be the live entry dispatcher. */
    memcpy(mutant, image, image_size);
    instruction = dlfrz_glibc_read_u32(
        mutant + evidence.dispatcher_file_offset);
    instruction ^= UINT32_C(1) << 5;
    memcpy(mutant + evidence.dispatcher_file_offset, &instruction,
           sizeof(instruction));
    if (dlfrz_glibc_aarch64_getauxval_contract_valid(
            mutant, image_size, glro_size, NULL, NULL))
        goto out;

    /* A second plausible quartet in the bounded entry window is ambiguous,
     * even when the original one remains intact. */
    scan_size = (size_t)function.st_size;
    if (scan_size > 64U)
        scan_size = 64U;
    for (size_t position =
             evidence.dispatcher_file_offset + 4U * sizeof(uint32_t);
         position + 4U * sizeof(uint32_t) <=
             function_offset + scan_size;
         position += sizeof(uint32_t)) {
        size_t leaf0_size = evidence.restore_file_offsets[0] == SIZE_MAX
            ? 4U * sizeof(uint32_t) : 5U * sizeof(uint32_t);
        size_t leaf1_size = evidence.restore_file_offsets[1] == SIZE_MAX
            ? 4U * sizeof(uint32_t) : 5U * sizeof(uint32_t);

        if (!aarch64_aux_ranges_overlap(
                position, 4U * sizeof(uint32_t),
                evidence.adrp_file_offsets[0], leaf0_size) &&
            !aarch64_aux_ranges_overlap(
                position, 4U * sizeof(uint32_t),
                evidence.adrp_file_offsets[1], leaf1_size)) {
            duplicate_offset = position;
            break;
        }
    }
    if (duplicate_offset == SIZE_MAX)
        goto out;
    memcpy(mutant, image, image_size);
    memcpy(mutant + duplicate_offset,
           image + evidence.dispatcher_file_offset,
           4U * sizeof(uint32_t));
    if (dlfrz_glibc_aarch64_getauxval_contract_valid(
            mutant, image_size, glro_size, NULL, NULL))
        goto out;

    /* Both ADRP and its immediately data-dependent GOT load are part of the
     * relocation-rooted proof. */
    memcpy(mutant, image, image_size);
    instruction = dlfrz_glibc_read_u32(
        mutant + evidence.adrp_file_offsets[0]);
    instruction ^= UINT32_C(1) << 5;
    memcpy(mutant + evidence.adrp_file_offsets[0], &instruction,
           sizeof(instruction));
    if (dlfrz_glibc_aarch64_getauxval_contract_valid(
            mutant, image_size, glro_size, NULL, NULL))
        goto out;

    memcpy(mutant, image, image_size);
    instruction = dlfrz_glibc_read_u32(
        mutant + evidence.got_load_file_offsets[1]);
    instruction ^= UINT32_C(1) << 10;
    memcpy(mutant + evidence.got_load_file_offsets[1], &instruction,
           sizeof(instruction));
    if (dlfrz_glibc_aarch64_getauxval_contract_valid(
            mutant, image_size, glro_size, NULL, NULL))
        goto out;

    /* A field ending exactly at the advertised GLRO boundary is outside the
     * object; unsigned-immediate LDRs make every admitted field aligned. */
    if ((glro_size & 7U) != 0 || glro_size / 8U > UINT32_C(0xfff))
        goto out;
    memcpy(mutant, image, image_size);
    instruction = dlfrz_glibc_read_u32(
        mutant + evidence.field_load_file_offsets[0]);
    instruction &= ~(UINT32_C(0xfff) << 10);
    instruction |= (uint32_t)(glro_size / 8U) << 10;
    memcpy(mutant + evidence.field_load_file_offsets[0], &instruction,
           sizeof(instruction));
    if (dlfrz_glibc_aarch64_getauxval_contract_valid(
            mutant, image_size, glro_size, NULL, NULL))
        goto out;

    /* The field load must consume the register produced by the GOT load. */
    memcpy(mutant, image, image_size);
    instruction = dlfrz_glibc_read_u32(
        mutant + evidence.field_load_file_offsets[1]);
    {
        unsigned int base = (instruction >> 5) & 31U;
        unsigned int replacement = base == 28U ? 27U : base + 1U;

        instruction &= ~(UINT32_C(31) << 5);
        instruction |= replacement << 5;
    }
    memcpy(mutant + evidence.field_load_file_offsets[1], &instruction,
           sizeof(instruction));
    if (dlfrz_glibc_aarch64_getauxval_contract_valid(
            mutant, image_size, glro_size, NULL, NULL))
        goto out;

    /* Sending both comparisons to the same otherwise-valid leaf must fail
     * both the leaf-range and field-range disjointness checks. */
    memcpy(mutant, image, image_size);
    instruction = dlfrz_glibc_read_u32(
        mutant + evidence.branch_file_offsets[0]);
    {
        int32_t immediate = (int32_t)((instruction >> 5) &
                                      UINT32_C(0x7ffff));
        uint32_t second = dlfrz_glibc_read_u32(
            mutant + evidence.branch_file_offsets[1]);

        if (immediate & INT32_C(0x40000))
            immediate -= INT32_C(0x80000);
        immediate -= 2;
        if (immediate < -INT32_C(0x40000) ||
            immediate >= INT32_C(0x40000))
            goto out;
        second &= ~(UINT32_C(0x7ffff) << 5);
        second |= ((uint32_t)immediate & UINT32_C(0x7ffff)) << 5;
        memcpy(mutant + evidence.branch_file_offsets[1], &second,
               sizeof(second));
    }
    if (dlfrz_glibc_aarch64_getauxval_contract_valid(
            mutant, image_size, glro_size, NULL, NULL))
        goto out;

    /* A framed implementation must restore at the same point in both
     * leaves.  Swap one exact LDP with its field load to create a balanced
     * but inconsistent alternate epilogue. */
    if (evidence.restore_file_offsets[0] != SIZE_MAX) {
        uint32_t field;
        uint32_t restore;

        memcpy(mutant, image, image_size);
        field = dlfrz_glibc_read_u32(
            mutant + evidence.field_load_file_offsets[0]);
        restore = dlfrz_glibc_read_u32(
            mutant + evidence.restore_file_offsets[0]);
        memcpy(mutant + evidence.field_load_file_offsets[0], &restore,
               sizeof(restore));
        memcpy(mutant + evidence.restore_file_offsets[0], &field,
               sizeof(field));
        if (dlfrz_glibc_aarch64_getauxval_contract_valid(
                mutant, image_size, glro_size, NULL, NULL))
            goto out;
    }

    /* PAC is intentionally outside the evidenced entry grammar. */
    memcpy(mutant, image, image_size);
    instruction = UINT32_C(0xd503233f); /* PACIASP */
    memcpy(mutant + function_offset, &instruction, sizeof(instruction));
    if (dlfrz_glibc_aarch64_getauxval_contract_valid(
            mutant, image_size, glro_size, NULL, NULL))
        goto out;
    valid = 1;

out:
    free(mutant);
    return valid;
}

static int test_aarch64_getauxval_file(const char *path,
                                       const char *glro_size_text)
{
    struct stat st;
    uint8_t *map = MAP_FAILED;
    char *end = NULL;
    unsigned long long parsed;
    int fd = -1;
    int valid = 0;

    errno = 0;
    parsed = strtoull(glro_size_text, &end, 0);
    if (errno != 0 || !end || *end != '\0' || parsed == 0 ||
        parsed > UINT64_MAX)
        return 1;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) < 0 || st.st_size <= 0 ||
        (uintmax_t)st.st_size > SIZE_MAX)
        goto out;
    map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED)
        goto out;
    valid = aarch64_getauxval_mutation_gate(
        map, (size_t)st.st_size, (uint64_t)parsed);

out:
    if (map != MAP_FAILED)
        munmap(map, (size_t)st.st_size);
    if (fd >= 0)
        close(fd);
    return valid ? 0 : 1;
}

enum {
    AARCH64_AUX_FIXTURE_SIZE = 8192,
    AARCH64_AUX_RX_SIZE = 4096,
    AARCH64_AUX_RW_OFFSET = 4096,
    AARCH64_AUX_DYNAMIC_OFFSET = 0x1100,
    AARCH64_AUX_RELA_OFFSET = 0x1200,
    AARCH64_AUX_STRTAB_OFFSET = 0x280,
    AARCH64_AUX_SYMTAB_OFFSET = 0x300,
    AARCH64_AUX_HASH_OFFSET = 0x380,
    AARCH64_AUX_CODE_OFFSET = 0x600,
};

#define AARCH64_AUX_RX_VADDR UINT64_C(0x400000)
#define AARCH64_AUX_RW_VADDR UINT64_C(0x500000)
#define AARCH64_AUX_GOT_VADDR (AARCH64_AUX_RW_VADDR + UINT64_C(0x800))

struct aarch64_aux_fixture {
    uint8_t image[AARCH64_AUX_FIXTURE_SIZE];
};

static uint32_t aarch64_aux_adrp(uint64_t pc, uint64_t target,
                                 unsigned int destination)
{
    int64_t pages = (int64_t)((target & ~UINT64_C(0xfff)) -
                              (pc & ~UINT64_C(0xfff))) /
                    INT64_C(4096);
    uint32_t immediate = (uint32_t)pages & UINT32_C(0x1fffff);

    return UINT32_C(0x90000000) |
           ((immediate & 3U) << 29) |
           (((immediate >> 2) & UINT32_C(0x7ffff)) << 5) |
           (destination & 31U);
}

static uint32_t aarch64_aux_ldr(unsigned int destination,
                                unsigned int base, uint64_t byte_offset)
{
    return UINT32_C(0xf9400000) |
           ((uint32_t)(byte_offset / UINT64_C(8)) &
            UINT32_C(0xfff)) << 10 |
           (base & 31U) << 5 | (destination & 31U);
}

static uint32_t aarch64_aux_beq(size_t from, size_t to)
{
    int32_t words = (int32_t)((int64_t)to - (int64_t)from) / 4;

    return UINT32_C(0x54000000) |
           ((uint32_t)words & UINT32_C(0x7ffff)) << 5;
}

static void aarch64_aux_put_word(struct aarch64_aux_fixture *fixture,
                                 size_t code_position, uint32_t value)
{
    memcpy(fixture->image + AARCH64_AUX_CODE_OFFSET + code_position,
           &value, sizeof(value));
}

/* MODE zero is the observed optional-BTI frameless family.  MODE one is
 * the observed framed, restore-before-field family.  MODE two exercises the
 * equally balanced restore-after-field grammar and deliberately keeps the
 * GLRO pointer in x29 until that restore. */
static int aarch64_aux_fixture_init(struct aarch64_aux_fixture *fixture,
                                    int mode)
{
    static const char dynstr[] =
        "\0__getauxval\0_rtld_global_ro\0";
    Elf64_Ehdr ehdr = {0};
    Elf64_Phdr phdr[3] = {{0}};
    Elf64_Dyn dynamic[9] = {{0}};
    Elf64_Sym symbols[3] = {{0}};
    Elf64_Rela relocation = {0};
    uint32_t hash[6] = {1, 3, 1, 0, 2, 0};
    size_t cursor;
    size_t leaf[2];
    size_t function_size;
    unsigned int glro_register = mode == 2 ? 29U : 0U;

    if (!fixture || mode < 0 || mode > 2)
        return 0;
    memset(fixture, 0, sizeof(*fixture));
    memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
    ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_type = ET_DYN;
    ehdr.e_machine = EM_AARCH64;
    ehdr.e_version = EV_CURRENT;
    ehdr.e_ehsize = sizeof(ehdr);
    ehdr.e_phoff = sizeof(ehdr);
    ehdr.e_phentsize = sizeof(Elf64_Phdr);
    ehdr.e_phnum = 3;

    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R | PF_X;
    phdr[0].p_offset = 0;
    phdr[0].p_vaddr = AARCH64_AUX_RX_VADDR;
    phdr[0].p_paddr = phdr[0].p_vaddr;
    phdr[0].p_filesz = AARCH64_AUX_RX_SIZE;
    phdr[0].p_memsz = AARCH64_AUX_RX_SIZE;
    phdr[0].p_align = 4096;
    phdr[1].p_type = PT_LOAD;
    phdr[1].p_flags = PF_R | PF_W;
    phdr[1].p_offset = AARCH64_AUX_RW_OFFSET;
    phdr[1].p_vaddr = AARCH64_AUX_RW_VADDR;
    phdr[1].p_paddr = phdr[1].p_vaddr;
    phdr[1].p_filesz = AARCH64_AUX_RX_SIZE;
    phdr[1].p_memsz = AARCH64_AUX_RX_SIZE;
    phdr[1].p_align = 4096;
    phdr[2].p_type = PT_DYNAMIC;
    phdr[2].p_flags = PF_R | PF_W;
    phdr[2].p_offset = AARCH64_AUX_DYNAMIC_OFFSET;
    phdr[2].p_vaddr = AARCH64_AUX_RW_VADDR +
                      (AARCH64_AUX_DYNAMIC_OFFSET -
                       AARCH64_AUX_RW_OFFSET);
    phdr[2].p_paddr = phdr[2].p_vaddr;
    phdr[2].p_filesz = sizeof(dynamic);
    phdr[2].p_memsz = sizeof(dynamic);
    phdr[2].p_align = sizeof(uint64_t);

    dynamic[0].d_tag = DT_STRTAB;
    dynamic[0].d_un.d_ptr =
        AARCH64_AUX_RX_VADDR + AARCH64_AUX_STRTAB_OFFSET;
    dynamic[1].d_tag = DT_STRSZ;
    dynamic[1].d_un.d_val = sizeof(dynstr);
    dynamic[2].d_tag = DT_SYMTAB;
    dynamic[2].d_un.d_ptr =
        AARCH64_AUX_RX_VADDR + AARCH64_AUX_SYMTAB_OFFSET;
    dynamic[3].d_tag = DT_SYMENT;
    dynamic[3].d_un.d_val = sizeof(Elf64_Sym);
    dynamic[4].d_tag = DT_HASH;
    dynamic[4].d_un.d_ptr =
        AARCH64_AUX_RX_VADDR + AARCH64_AUX_HASH_OFFSET;
    dynamic[5].d_tag = DT_RELA;
    dynamic[5].d_un.d_ptr = AARCH64_AUX_RW_VADDR +
                            (AARCH64_AUX_RELA_OFFSET -
                             AARCH64_AUX_RW_OFFSET);
    dynamic[6].d_tag = DT_RELASZ;
    dynamic[6].d_un.d_val = sizeof(relocation);
    dynamic[7].d_tag = DT_RELAENT;
    dynamic[7].d_un.d_val = sizeof(relocation);
    dynamic[8].d_tag = DT_NULL;

    function_size = mode == 0 ? 128U : 148U;
    symbols[1].st_name = 1;
    symbols[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    symbols[1].st_other = STV_DEFAULT;
    symbols[1].st_shndx = 1;
    symbols[1].st_value =
        AARCH64_AUX_RX_VADDR + AARCH64_AUX_CODE_OFFSET;
    symbols[1].st_size = function_size;
    /* The first name starts at byte one.  sizeof includes its terminating
     * NUL, which is also the separator before the second name. */
    symbols[2].st_name = 1U + (uint32_t)sizeof("__getauxval");
    symbols[2].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);
    symbols[2].st_other = STV_DEFAULT;
    symbols[2].st_shndx = SHN_UNDEF;
    relocation.r_offset = AARCH64_AUX_GOT_VADDR;
    relocation.r_info = ELF64_R_INFO(2, R_AARCH64_GLOB_DAT);

    memcpy(fixture->image, &ehdr, sizeof(ehdr));
    memcpy(fixture->image + sizeof(ehdr), phdr, sizeof(phdr));
    memcpy(fixture->image + AARCH64_AUX_DYNAMIC_OFFSET,
           dynamic, sizeof(dynamic));
    memcpy(fixture->image + AARCH64_AUX_RELA_OFFSET,
           &relocation, sizeof(relocation));
    memcpy(fixture->image + AARCH64_AUX_STRTAB_OFFSET,
           dynstr, sizeof(dynstr));
    memcpy(fixture->image + AARCH64_AUX_SYMTAB_OFFSET,
           symbols, sizeof(symbols));
    memcpy(fixture->image + AARCH64_AUX_HASH_OFFSET,
           hash, sizeof(hash));

    cursor = 0;
    if (mode == 0) {
        aarch64_aux_put_word(fixture, cursor, UINT32_C(0xd503245f));
        cursor += sizeof(uint32_t);
        leaf[0] = 96U;
        leaf[1] = 112U;
    } else {
        aarch64_aux_put_word(fixture, cursor, UINT32_C(0xa9bf7bfd));
        cursor += sizeof(uint32_t);
        aarch64_aux_put_word(fixture, cursor, UINT32_C(0x910003fd));
        cursor += sizeof(uint32_t);
        leaf[0] = 108U;
        leaf[1] = 128U;
    }
    aarch64_aux_put_word(fixture, cursor, UINT32_C(0xf100401f));
    aarch64_aux_put_word(
        fixture, cursor + sizeof(uint32_t),
        aarch64_aux_beq(cursor + sizeof(uint32_t), leaf[0]));
    aarch64_aux_put_word(
        fixture, cursor + 2U * sizeof(uint32_t), UINT32_C(0xf100681f));
    aarch64_aux_put_word(
        fixture, cursor + 3U * sizeof(uint32_t),
        aarch64_aux_beq(cursor + 3U * sizeof(uint32_t), leaf[1]));

    for (size_t i = 0; i < 2; i++) {
        uint64_t pc = symbols[1].st_value + leaf[i];
        size_t position = leaf[i];

        aarch64_aux_put_word(
            fixture, position,
            aarch64_aux_adrp(pc, AARCH64_AUX_GOT_VADDR, 0));
        position += sizeof(uint32_t);
        aarch64_aux_put_word(
            fixture, position,
            aarch64_aux_ldr(glro_register, 0,
                            AARCH64_AUX_GOT_VADDR & UINT64_C(0xfff)));
        position += sizeof(uint32_t);
        if (mode == 1) {
            aarch64_aux_put_word(
                fixture, position, UINT32_C(0xa8c17bfd));
            position += sizeof(uint32_t);
        }
        aarch64_aux_put_word(
            fixture, position,
            aarch64_aux_ldr(0, glro_register,
                            i == 0 ? UINT64_C(96) : UINT64_C(256)));
        position += sizeof(uint32_t);
        if (mode == 2) {
            aarch64_aux_put_word(
                fixture, position, UINT32_C(0xa8c17bfd));
            position += sizeof(uint32_t);
        }
        aarch64_aux_put_word(
            fixture, position, UINT32_C(0xd65f03c0));
    }
    return 1;
}

static int aarch64_getauxval_contract_selftest(void)
{
    struct aarch64_aux_fixture fixture;
    struct dlfrz_glibc_getauxval_contract contract;

    for (int mode = 0; mode < 3; mode++) {
        if (!aarch64_aux_fixture_init(&fixture, mode) ||
            !dlfrz_glibc_aarch64_getauxval_contract_valid(
                fixture.image, sizeof(fixture.image), 400,
                &contract, NULL) ||
            contract.hwcap_offset != 96 ||
            contract.hwcap2_offset != 256 ||
            !aarch64_getauxval_mutation_gate(
                fixture.image, sizeof(fixture.image), 400))
            return 0;
    }

    /* Duplicate public definitions, even byte-identical ones, are not a
     * unique ABI witness. */
    if (!aarch64_aux_fixture_init(&fixture, 0))
        return 0;
    {
        Elf64_Sym duplicate;
        uint32_t *hash = (uint32_t *)(fixture.image +
                                     AARCH64_AUX_HASH_OFFSET);

        memcpy(&duplicate,
               fixture.image + AARCH64_AUX_SYMTAB_OFFSET +
                   sizeof(Elf64_Sym),
               sizeof(duplicate));
        memcpy(fixture.image + AARCH64_AUX_SYMTAB_OFFSET +
                   3U * sizeof(Elf64_Sym),
               &duplicate, sizeof(duplicate));
        hash[1] = 4;
        hash[4] = 2;
        hash[5] = 3;
        hash[6] = 0;
    }
    if (dlfrz_glibc_aarch64_getauxval_contract_valid(
            fixture.image, sizeof(fixture.image), 400, NULL, NULL))
        return 0;

    /* The relocation root must itself be unique. */
    if (!aarch64_aux_fixture_init(&fixture, 0))
        return 0;
    {
        Elf64_Dyn *dynamic = (Elf64_Dyn *)(fixture.image +
                                           AARCH64_AUX_DYNAMIC_OFFSET);
        Elf64_Rela duplicate;

        memcpy(&duplicate, fixture.image + AARCH64_AUX_RELA_OFFSET,
               sizeof(duplicate));
        duplicate.r_offset += sizeof(uint64_t);
        memcpy(fixture.image + AARCH64_AUX_RELA_OFFSET +
                   sizeof(duplicate),
               &duplicate, sizeof(duplicate));
        dynamic[6].d_un.d_val = 2U * sizeof(duplicate);
    }
    return !dlfrz_glibc_aarch64_getauxval_contract_valid(
        fixture.image, sizeof(fixture.image), 400, NULL, NULL);
}

#undef AARCH64_AUX_RX_VADDR
#undef AARCH64_AUX_RW_VADDR
#undef AARCH64_AUX_GOT_VADDR

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

#define CONFIG_ELF_FIXTURE_SIZE 4096U
#define CONFIG_ELF_FIXTURE_PHDRS 4U

struct config_elf_fixture {
    unsigned char image[CONFIG_ELF_FIXTURE_SIZE];
    Elf64_Ehdr ehdr;
    Elf64_Phdr phdrs[CONFIG_ELF_FIXTURE_PHDRS];
};

static int config_elf_fixture_publish(struct config_elf_fixture *fixture)
{
    size_t phdr_bytes;

    if (!fixture || fixture->ehdr.e_phnum > CONFIG_ELF_FIXTURE_PHDRS ||
        fixture->ehdr.e_phoff > sizeof(fixture->image) ||
        (size_t)fixture->ehdr.e_phnum >
            (sizeof(fixture->image) - (size_t)fixture->ehdr.e_phoff) /
                sizeof(Elf64_Phdr))
        return 0;
    phdr_bytes = (size_t)fixture->ehdr.e_phnum * sizeof(Elf64_Phdr);
    memcpy(fixture->image, &fixture->ehdr, sizeof(fixture->ehdr));
    memcpy(fixture->image + (size_t)fixture->ehdr.e_phoff,
           fixture->phdrs, phdr_bytes);
    return 1;
}

static int config_elf_fixture_init(struct config_elf_fixture *fixture,
                                   uint16_t machine, uint16_t phnum)
{
    if (!fixture || phnum > CONFIG_ELF_FIXTURE_PHDRS)
        return 0;
    memset(fixture, 0, sizeof(*fixture));
    memcpy(fixture->ehdr.e_ident, ELFMAG, SELFMAG);
    fixture->ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    fixture->ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    fixture->ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    fixture->ehdr.e_type = ET_DYN;
    fixture->ehdr.e_machine = machine;
    fixture->ehdr.e_version = EV_CURRENT;
    fixture->ehdr.e_ehsize = sizeof(Elf64_Ehdr);
    fixture->ehdr.e_phoff = sizeof(Elf64_Ehdr);
    fixture->ehdr.e_phentsize = sizeof(Elf64_Phdr);
    fixture->ehdr.e_phnum = phnum;
    return config_elf_fixture_publish(fixture);
}

static int config_elf_fixture_load(struct config_elf_fixture *fixture,
                                   uint16_t index, uint64_t offset,
                                   uint64_t file_size, uint64_t memory_size,
                                   uint32_t flags)
{
    Elf64_Phdr *phdr;

    if (!fixture || index >= fixture->ehdr.e_phnum)
        return 0;
    phdr = &fixture->phdrs[index];
    memset(phdr, 0, sizeof(*phdr));
    phdr->p_type = PT_LOAD;
    phdr->p_flags = flags;
    phdr->p_offset = offset;
    phdr->p_vaddr = UINT64_C(0x400000) +
                    (uint64_t)index * UINT64_C(0x20000);
    phdr->p_paddr = phdr->p_vaddr;
    phdr->p_filesz = file_size;
    phdr->p_memsz = memory_size;
    phdr->p_align = 1;
    return config_elf_fixture_publish(fixture);
}

static int config_elf_fixture_string(struct config_elf_fixture *fixture,
                                     size_t offset, const char *value)
{
    size_t size;

    if (!fixture || !value)
        return 0;
    size = strlen(value) + 1;
    if (!range_fits(offset, size, sizeof(fixture->image)))
        return 0;
    memcpy(fixture->image + offset, value, size);
    return 1;
}

static int config_path_high_cardinality_selftest(void)
{
    const size_t image_size = 4U * 1024U * 1024U;
    unsigned char *image = calloc(1, image_size);
    const char *cache = "/opt/runtime/etc/ld.so.cache";
    const char *preload = "/opt/runtime/etc/ld.so.preload";
    Elf64_Ehdr ehdr = {0};
    Elf64_Phdr phdr = {0};
    char cache_out[128];
    char preload_out[128];
    size_t offset = 4096U;
    int valid = 0;

    if (!image)
        return 0;
    memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
    ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_type = ET_DYN;
    ehdr.e_machine = EM_X86_64;
    ehdr.e_version = EV_CURRENT;
    ehdr.e_ehsize = sizeof(ehdr);
    ehdr.e_phoff = sizeof(ehdr);
    ehdr.e_phentsize = sizeof(phdr);
    ehdr.e_phnum = 1;
    phdr.p_type = PT_LOAD;
    phdr.p_flags = PF_R;
    phdr.p_offset = 0;
    phdr.p_vaddr = UINT64_C(0x400000);
    phdr.p_filesz = image_size;
    phdr.p_memsz = image_size;
    phdr.p_align = 1;
    memcpy(image, &ehdr, sizeof(ehdr));
    memcpy(image + sizeof(ehdr), &phdr, sizeof(phdr));

    for (size_t i = 0; i < 100000U; i++) {
        int written = snprintf((char *)image + offset,
                               image_size - offset,
                               "/noise/%08zu/object.so", i);

        if (written < 0 || (size_t)written >= image_size - offset)
            goto out;
        offset += (size_t)written + 1;
    }
    if (!range_fits(offset, strlen(cache) + 1, image_size))
        goto out;
    memcpy(image + offset, cache, strlen(cache) + 1);
    offset += strlen(cache) + 1;
    if (!range_fits(offset, strlen(preload) + 1, image_size))
        goto out;
    memcpy(image + offset, preload, strlen(preload) + 1);

    if (!dlfrz_glibc_elf_config_paths(
            image, image_size, cache_out, sizeof(cache_out),
            preload_out, sizeof(preload_out)) ||
        strcmp(cache_out, cache) != 0 ||
        strcmp(preload_out, preload) != 0)
        goto out;

    offset += strlen(preload) + 1;
    if (!range_fits(offset, sizeof("/different/ld.so.cache"), image_size))
        goto out;
    memcpy(image + offset, "/different/ld.so.cache",
           sizeof("/different/ld.so.cache"));
    if (dlfrz_glibc_elf_config_paths(
            image, image_size, cache_out, sizeof(cache_out),
            preload_out, sizeof(preload_out)) ||
        cache_out[0] != '\0' || preload_out[0] != '\0')
        goto out;
    valid = 1;

out:
    free(image);
    return valid;
}

static int config_path_selftest(void)
{
    static const char cache[] = "/opt/runtime/etc/ld.so.cache";
    static const char preload[] = "/opt/runtime/etc/ld.so.preload";
    struct config_elf_fixture fixture;
    char cache_out[128];
    char preload_out[128];
    const size_t first = 512U;
    const size_t second = 1280U;

    /* Independent immutable ranges contribute to one combined scan.  Exact
     * duplicate witnesses are stable, and an embedded diagnostic substring
     * cannot become a path because it lacks a C-string boundary. */
    if (!config_elf_fixture_init(&fixture, EM_X86_64, 2) ||
        !config_elf_fixture_load(
            &fixture, 0, first, 512, 512, PF_R | PF_X) ||
        !config_elf_fixture_load(
            &fixture, 1, second, 512, 512, PF_R) ||
        !config_elf_fixture_string(&fixture, first + 17U, cache) ||
        !config_elf_fixture_string(&fixture, first + 80U, cache) ||
        !config_elf_fixture_string(
            &fixture, first + 160U,
            "Do not use /different/ld.so.cache") ||
        !config_elf_fixture_string(&fixture, second + 23U, preload) ||
        !dlfrz_glibc_elf_config_paths(
            fixture.image, sizeof(fixture.image),
            cache_out, sizeof(cache_out),
            preload_out, sizeof(preload_out)) ||
        strcmp(cache_out, cache) != 0 ||
        strcmp(preload_out, preload) != 0 ||
        !dlfrz_glibc_config_path(
            fixture.image, sizeof(fixture.image),
            DLFRZ_GLIBC_CACHE_SUFFIX,
            sizeof(DLFRZ_GLIBC_CACHE_SUFFIX) - 1,
            cache_out, sizeof(cache_out)) ||
        strcmp(cache_out, cache) != 0)
        return 0;

    /* Distinct candidates are ambiguous even when each one independently
     * has the requested suffix. */
    if (!config_elf_fixture_string(
            &fixture, second + 96U, "/different/ld.so.cache") ||
        dlfrz_glibc_elf_config_paths(
            fixture.image, sizeof(fixture.image),
            cache_out, sizeof(cache_out),
            preload_out, sizeof(preload_out)) ||
        cache_out[0] != '\0' || preload_out[0] != '\0')
        return 0;

    /* Non-loaded, execute-only, and writable strings never establish an
     * identity. */
    if (!config_elf_fixture_init(&fixture, EM_AARCH64, 3) ||
        !config_elf_fixture_load(
            &fixture, 0, first, 256, 256, PF_X) ||
        !config_elf_fixture_load(
            &fixture, 1, second, 256, 256, PF_R | PF_W) ||
        !config_elf_fixture_load(
            &fixture, 2, 2048U, 64, 64, PF_R) ||
        !config_elf_fixture_string(&fixture, first + 8U, cache) ||
        !config_elf_fixture_string(&fixture, second + 8U, preload) ||
        !config_elf_fixture_string(&fixture, 3000U, cache) ||
        dlfrz_glibc_elf_config_paths(
            fixture.image, sizeof(fixture.image),
            cache_out, sizeof(cache_out), NULL, 0) ||
        cache_out[0] != '\0')
        return 0;

    /* A string may not cross ranges, and a candidate ending exactly at its
     * range boundary is incomplete without a NUL terminator. */
    if (!config_elf_fixture_init(&fixture, EM_X86_64, 2) ||
        !config_elf_fixture_load(
            &fixture, 0, first, 64, 64, PF_R) ||
        !config_elf_fixture_load(
            &fixture, 1, first + 64U, 64, 64, PF_R))
        return 0;
    memcpy(fixture.image + first + 64U - 8U, cache, 8U);
    memcpy(fixture.image + first + 64U, cache + 8U, strlen(cache) - 8U);
    if (dlfrz_glibc_elf_config_paths(
            fixture.image, sizeof(fixture.image),
            cache_out, sizeof(cache_out), NULL, 0))
        return 0;
    memset(fixture.image + first, 'x', 64U);
    memcpy(fixture.image + first + 64U - strlen(cache),
           cache, strlen(cache));
    if (dlfrz_glibc_elf_config_paths(
            fixture.image, sizeof(fixture.image),
            cache_out, sizeof(cache_out), NULL, 0))
        return 0;

    /* File and virtual aliases, including a writable BSS alias, invalidate
     * the shared immutable-load envelope before string matching. */
    if (!config_elf_fixture_init(&fixture, EM_X86_64, 2) ||
        !config_elf_fixture_load(
            &fixture, 0, first, 256, 256, PF_R) ||
        !config_elf_fixture_load(
            &fixture, 1, first + 128U, 256, 256, PF_R | PF_W) ||
        dlfrz_glibc_elf_config_paths(
            fixture.image, sizeof(fixture.image),
            cache_out, sizeof(cache_out), NULL, 0))
        return 0;
    if (!config_elf_fixture_init(&fixture, EM_AARCH64, 2) ||
        !config_elf_fixture_load(
            &fixture, 0, first, 256, 256, PF_R) ||
        !config_elf_fixture_load(
            &fixture, 1, second, 0, 256, PF_R | PF_W))
        return 0;
    fixture.phdrs[1].p_vaddr = fixture.phdrs[0].p_vaddr;
    if (!config_elf_fixture_publish(&fixture) ||
        dlfrz_glibc_elf_config_paths(
            fixture.image, sizeof(fixture.image),
            cache_out, sizeof(cache_out), NULL, 0))
        return 0;

    /* Valid witnesses still fail safely when the destination cannot hold
     * the complete identity or when API/output alias contracts are broken. */
    if (!config_elf_fixture_init(&fixture, EM_X86_64, 1) ||
        !config_elf_fixture_load(
            &fixture, 0, first, 512, 512, PF_R) ||
        !config_elf_fixture_string(&fixture, first + 17U, cache) ||
        !config_elf_fixture_string(&fixture, first + 96U, preload) ||
        dlfrz_glibc_elf_config_paths(
            fixture.image, sizeof(fixture.image), cache_out, 8,
            preload_out, sizeof(preload_out)) ||
        cache_out[0] != '\0' || preload_out[0] != '\0' ||
        dlfrz_glibc_elf_config_paths(
            fixture.image, sizeof(fixture.image), NULL, 1,
            preload_out, sizeof(preload_out)) ||
        dlfrz_glibc_elf_config_paths(
            fixture.image, sizeof(fixture.image), NULL, 0, NULL, 0) ||
        dlfrz_glibc_elf_config_paths(
            fixture.image, sizeof(fixture.image), cache_out,
            sizeof(cache_out), cache_out, sizeof(cache_out)) ||
        dlfrz_glibc_elf_config_paths(
            fixture.image, sizeof(fixture.image),
            (char *)fixture.image + first + 300U, 64, NULL, 0) ||
        dlfrz_glibc_config_path(
            fixture.image, sizeof(fixture.image), "/unknown", 8,
            cache_out, sizeof(cache_out)))
        return 0;

    /* Truncated and malformed envelopes remain bounded. */
    fixture.ehdr.e_phoff = sizeof(fixture.image) - 1U;
    memcpy(fixture.image, &fixture.ehdr, sizeof(fixture.ehdr));
    if (dlfrz_glibc_elf_config_paths(
            fixture.image, sizeof(fixture.image),
            cache_out, sizeof(cache_out), NULL, 0) ||
        dlfrz_glibc_elf_config_paths(
            NULL, SIZE_MAX, cache_out, sizeof(cache_out), NULL, 0))
        return 0;
    return config_path_high_cardinality_selftest();
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

/* The hidden-member fast path must retain the exact independent match counts
 * of the single-slot validators while traversing a root/hook chain once. */
static int dlfcn_internal_members_selftest(void)
{
    unsigned char x86[] = {
        0x48, 0x8b, 0x05, 0xf9, 0x0f, 0x00, 0x00,
        0x48, 0x8b, 0x80, 0x88, 0x03, 0x00, 0x00,
        0xff, 0x90, 0x48, 0x00, 0x00, 0x00, /* call *hook[9] */
        0xff, 0x90, 0x50, 0x00, 0x00, 0x00, /* call *hook[10] */
        0xff, 0x90, 0x58, 0x00, 0x00, 0x00, /* call *hook[11] */
        0xff, 0x90, 0x60, 0x00, 0x00, 0x00, /* call *hook[12] */
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90
    };
    uint32_t aarch64[] = {
        UINT32_C(0xb0000000), /* adrp x0, 0x2000 */
        UINT32_C(0xf9400002), /* ldr x2, [x0] */
        UINT32_C(0xf941c443), /* ldr x3, [x2, #904] */
        UINT32_C(0xf9400061) | (UINT32_C(9) << 10),
        UINT32_C(0xd63f0020), /* blr x1 */
        UINT32_C(0xf9400061) | (UINT32_C(10) << 10),
        UINT32_C(0xd63f0020),
        UINT32_C(0xf9400061) | (UINT32_C(11) << 10),
        UINT32_C(0xd63f0020),
        UINT32_C(0xf9400061) | (UINT32_C(12) << 10),
        UINT32_C(0xd63f0020),
        UINT32_C(0xd503201f), /* nop; duplicate-witness space */
        UINT32_C(0xd503201f)
    };
    size_t matches[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U];
    size_t hooks[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U];
    size_t slots[DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U];

    for (unsigned int duplicate = 0; duplicate < 2U; duplicate++) {
        if (!dlfrz_glibc_x86_dlfcn_internal_matches(
                x86, sizeof(x86), UINT64_C(0x1000), UINT64_C(0x2000),
                904, matches, hooks, slots))
            return 0;
        for (unsigned int internal = 0;
             internal < DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U;
             internal++) {
            size_t hook = SIZE_MAX;
            size_t slot = SIZE_MAX;
            size_t expected = dlfrz_glibc_x86_dlfcn_member_matches(
                x86, sizeof(x86), UINT64_C(0x1000), UINT64_C(0x2000),
                904, 9U + internal, 1024U, &hook, &slot);
            size_t wanted = duplicate && internal == 0U ? 0U : 1U;

            if (expected != wanted || matches[internal] != expected ||
                (expected == 1 &&
                 (hooks[internal] != hook || slots[internal] != slot ||
                  hook != 7U || slot != 14U + internal * 6U)))
                return 0;
        }

        if (!dlfrz_glibc_aarch64_dlfcn_internal_matches(
                (const unsigned char *)aarch64, sizeof(aarch64),
                UINT64_C(0x1000), UINT64_C(0x2000), 904,
                matches, hooks, slots))
            return 0;
        for (unsigned int internal = 0;
             internal < DLFRZ_GLIBC_DLFCN_HOOK_SLOTS - 9U;
             internal++) {
            size_t hook = SIZE_MAX;
            size_t slot = SIZE_MAX;
            size_t expected = dlfrz_glibc_aarch64_dlfcn_member_matches(
                (const unsigned char *)aarch64, sizeof(aarch64),
                UINT64_C(0x1000), UINT64_C(0x2000), 904,
                9U + internal, 1024U, &hook, &slot);
            size_t wanted = duplicate && internal == 0U ? 0U : 1U;

            if (expected != wanted || matches[internal] != expected ||
                (expected == 1 &&
                 (hooks[internal] != hook || slots[internal] != slot ||
                  hook != 8U || slot != 12U + internal * 8U)))
                return 0;
        }

        /* A duplicate for only slot 9 must invalidate that chain for slot 9
         * without changing the independent slot 10--12 witnesses. */
        x86[38] = 0xff;
        x86[39] = 0x90;
        x86[40] = 0x48;
        x86[41] = 0x00;
        x86[42] = 0x00;
        x86[43] = 0x00;
        aarch64[11] =
            UINT32_C(0xf9400061) | (UINT32_C(9) << 10);
        aarch64[12] = UINT32_C(0xd63f0020);
    }
    return 1;
}

static int dlfcn_public_name_inventory_selftest(void)
{
    static const unsigned char strings[] =
        "\0dlopen\0dlclose\0dlsym\0dlvsym\0dlerror\0"
        "dladdr\0dladdr1\0dlinfo\0dlmopen\0"
        "dladdrx\0d\0dl\0dlunknown\0";
    struct dlfrz_elf64_dyn_view view;
    const char *cursor = (const char *)strings + 1;

    memset(&view, 0, sizeof(view));
    view.elf = strings;
    view.dynstr_size = sizeof(strings);
    for (unsigned int slot = 0; slot < 9U; slot++) {
        const char *expected = dlfrz_glibc_dlfcn_public_name(slot);

        if (!expected || strcmp(cursor, expected) != 0 ||
            dlfrz_glibc_dlfcn_public_name_slot(
                &view, (uint32_t)(cursor - (const char *)strings)) !=
                    (int)slot)
            return 0;
        cursor += strlen(cursor) + 1;
    }
    while ((size_t)(cursor - (const char *)strings) < sizeof(strings) - 1) {
        if (dlfrz_glibc_dlfcn_public_name_slot(
                &view, (uint32_t)(cursor - (const char *)strings)) != -1)
            return 0;
        cursor += strlen(cursor) + 1;
    }
    return dlfrz_glibc_dlfcn_public_name(9) == NULL &&
           dlfrz_glibc_dlfcn_public_name_slot(&view, 0) == -1 &&
           dlfrz_glibc_dlfcn_public_name_slot(
               &view, (uint32_t)sizeof(strings)) == -1;
}

struct x86_cpu_layout_expectation {
    int first_minor;
    int last_minor;
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
    int cache_info_offset;
    int cachesize_non_temporal_divisor;
};

static enum dlfrz_glibc_layout_id
x86_cpu_profile_test_layout(int minor)
{
    if (minor >= 34 && minor <= 36)
        return DLFRZ_GLIBC_X86_2_34;
    if (minor >= 37 && minor <= 39)
        return DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY;
    if (minor >= 40 && minor <= 43)
        return DLFRZ_GLIBC_X86_2_40;
    if (minor == 44)
        return DLFRZ_GLIBC_X86_2_44;
    return DLFRZ_GLIBC_LAYOUT_UNKNOWN;
}

static int x86_cpu_layout_matches(
    const struct dlfrz_glibc_x86_cpu_layout *layout,
    const struct x86_cpu_layout_expectation *expected)
{
    return layout->feature_count == expected->feature_count &&
           layout->object_size == expected->object_size &&
           layout->preferred == expected->preferred &&
           layout->isa_1 == expected->isa_1 &&
           layout->xsave_state_size == expected->xsave_state_size &&
           layout->xsave_state_full_size ==
               expected->xsave_state_full_size &&
           layout->data_cache_size == expected->data_cache_size &&
           layout->shared_cache_size == expected->shared_cache_size &&
           layout->non_temporal_threshold ==
               expected->non_temporal_threshold &&
           layout->memset_non_temporal_threshold ==
               expected->memset_non_temporal_threshold &&
           layout->rep_movsb_threshold == expected->rep_movsb_threshold &&
           layout->rep_movsb_stop_threshold ==
               expected->rep_movsb_stop_threshold &&
           layout->rep_stosb_threshold == expected->rep_stosb_threshold &&
           layout->level1_icache_size == expected->cache_info_offset &&
           layout->level1_icache_linesize ==
               expected->cache_info_offset + 8 &&
           layout->level1_dcache_size ==
               expected->cache_info_offset + 16 &&
           layout->level1_dcache_assoc ==
               expected->cache_info_offset + 24 &&
           layout->level1_dcache_linesize ==
               expected->cache_info_offset + 32 &&
           layout->level2_cache_size ==
               expected->cache_info_offset + 40 &&
           layout->level2_cache_assoc ==
               expected->cache_info_offset + 48 &&
           layout->level2_cache_linesize ==
               expected->cache_info_offset + 56 &&
           layout->level3_cache_size ==
               expected->cache_info_offset + 64 &&
           layout->level3_cache_assoc ==
               expected->cache_info_offset + 72 &&
           layout->level3_cache_linesize ==
               expected->cache_info_offset + 80 &&
           layout->level4_cache_size ==
               expected->cache_info_offset + 88 &&
           layout->cachesize_non_temporal_divisor ==
               expected->cachesize_non_temporal_divisor;
}

/* This is a host-independent transcription of the official x86-64
 * cpu_features definitions for every admitted modern release.  In
 * particular, 2.39 has ten feature leaves but predates the memset threshold
 * added in 2.40. */
static int x86_cpu_layout_profile_selftest(void)
{
    static const struct x86_cpu_layout_expectation expected[] = {
        { 34, 37, 9, 480, 308, 312, 320, 328, 336, 344, 352,
          DLFRZ_GLIBC_X86_CPU_FIELD_ABSENT, 360, 368, 376, 384,
          DLFRZ_GLIBC_X86_CPU_FIELD_ABSENT },
        { 38, 38, 9, 488, 308, 312, 320, 328, 336, 344, 352,
          DLFRZ_GLIBC_X86_CPU_FIELD_ABSENT, 360, 368, 376, 384, 480 },
        { 39, 39, 10, 520, 340, 344, 352, 360, 368, 376, 384,
          DLFRZ_GLIBC_X86_CPU_FIELD_ABSENT, 392, 400, 408, 416, 512 },
        { 40, 44, 10, 528, 340, 344, 352, 360, 368, 376, 384,
          392, 400, 408, 416, 424, 520 },
    };
    struct dlfrz_glibc_x86_cpu_layout layout;

    for (size_t profile = 0;
         profile < sizeof(expected) / sizeof(expected[0]); profile++) {
        for (int minor = expected[profile].first_minor;
             minor <= expected[profile].last_minor; minor++) {
            uint64_t prefix = UINT64_C(37);

            if (!dlfrz_glibc_x86_cpu_layout_profile(
                    x86_cpu_profile_test_layout(minor), minor, &layout) ||
                !x86_cpu_layout_matches(&layout, &expected[profile]) ||
                !dlfrz_glibc_x86_cpu_object_profile_complete(&layout) ||
                !dlfrz_glibc_x86_cpu_object_fits(
                    &layout, prefix, prefix + layout.object_size) ||
                dlfrz_glibc_x86_cpu_object_fits(
                    &layout, prefix,
                    prefix + layout.object_size - UINT64_C(1)) ||
                dlfrz_glibc_x86_cpu_object_fits(
                    &layout, UINT64_MAX, UINT64_MAX))
                return 0;
        }
    }

    /* The previous 2.39-as-2.40 profile stopped at offset 416 and would
     * admit too-small storage while shifting all three string thresholds.
     * Both the member positions and the complete 520-byte bound must reject
     * that model. */
    if (!dlfrz_glibc_x86_cpu_layout_profile(
            DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY, 39, &layout) ||
        layout.memset_non_temporal_threshold !=
            DLFRZ_GLIBC_X86_CPU_FIELD_ABSENT ||
        layout.rep_movsb_threshold != 392 ||
        layout.rep_movsb_stop_threshold != 400 ||
        layout.rep_stosb_threshold != 408 ||
        layout.object_size != 520 ||
        dlfrz_glibc_x86_cpu_object_fits(&layout, 0, 416))
        return 0;
    layout.object_size--;
    if (dlfrz_glibc_x86_cpu_object_profile_complete(&layout))
        return 0;

    memset(&layout, 0xa5, sizeof(layout));
    return !dlfrz_glibc_x86_cpu_layout_profile(
               DLFRZ_GLIBC_X86_2_34, 33, &layout) &&
           !dlfrz_glibc_x86_cpu_layout_profile(
               DLFRZ_GLIBC_X86_2_44, 45, &layout) &&
           !dlfrz_glibc_x86_cpu_layout_profile(
               DLFRZ_GLIBC_AARCH64_2_41, 41, &layout) &&
           !dlfrz_glibc_x86_cpu_object_fits(NULL, 0, UINT64_MAX);
}

static int x86_rip_write_width_selftest(void)
{
    static const unsigned char movups[] = {
        0x0f, 0x11, 0x05, 0, 0, 0, 0
    };
    static const unsigned char movupd[] = {
        0x66, 0x0f, 0x11, 0x05, 0, 0, 0, 0
    };
    static const unsigned char movsd[] = {
        0xf2, 0x0f, 0x11, 0x05, 0, 0, 0, 0
    };
    static const unsigned char movss[] = {
        0xf3, 0x0f, 0x11, 0x05, 0, 0, 0, 0
    };
    static const unsigned char invalid_movap[] = {
        0xf2, 0x0f, 0x29, 0x05, 0, 0, 0, 0
    };
    struct dlfrz_glibc_x86_rip_write write;

    return dlfrz_glibc_x86_rip_write(
               movups, sizeof(movups), UINT64_C(0x1000), &write) &&
           write.width == 16 && write.length == sizeof(movups) &&
           dlfrz_glibc_x86_rip_write(
               movupd, sizeof(movupd), UINT64_C(0x1000), &write) &&
           write.width == 16 && write.length == sizeof(movupd) &&
           dlfrz_glibc_x86_rip_write(
               movsd, sizeof(movsd), UINT64_C(0x1000), &write) &&
           write.width == 8 && write.length == sizeof(movsd) &&
           dlfrz_glibc_x86_rip_write(
               movss, sizeof(movss), UINT64_C(0x1000), &write) &&
           write.width == 4 && write.length == sizeof(movss) &&
           !dlfrz_glibc_x86_rip_write(
               invalid_movap, sizeof(invalid_movap),
               UINT64_C(0x1000), &write);
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

/* Frozen copy of the previous independent-search implementation.  Keep this
 * scalar and separate from dlfrz_glibc_find_literal(): it is the differential
 * oracle for the common-anchor implementation, including intentionally odd
 * generic snapshot forms and the historical stable-minor overflow bound. */
static void release_profile_reference(const void *data, size_t size,
                                      int *stable_minor_out,
                                      int *development_out)
{
    static const char marker[] = DLFRZ_GLIBC_DEVELOPMENT_MARKER;
    static const char release[] = "release version ";
    static const char stable[] = "stable release version 2.";
    const unsigned char *bytes = (const unsigned char *)data;
    int development = 0;
    int stable_minor = -1;
    int stable_invalid = 0;

    if (!data)
        size = 0;
    if (development_out && bytes) {
        if (size >= sizeof(marker) - 1) {
            for (size_t i = 0; i <= size - (sizeof(marker) - 1); i++) {
                if (memcmp(bytes + i, marker, sizeof(marker) - 1) == 0) {
                    development = 1;
                    break;
                }
            }
        }
        if (!development && size >= sizeof(release) - 1) {
            for (size_t i = 0;
                 i <= size - (sizeof(release) - 1) && !development; i++) {
                size_t p;

                if (memcmp(bytes + i, release,
                           sizeof(release) - 1) != 0)
                    continue;
                p = i + sizeof(release) - 1;
                while (p < size && bytes[p] >= '0' && bytes[p] <= '9')
                    p++;
                if (p < size && bytes[p++] == '.') {
                    while (p < size && bytes[p] >= '0' && bytes[p] <= '9')
                        p++;
                    if (p + 1 < size && bytes[p] == '.' &&
                        bytes[p + 1] >= '0' && bytes[p + 1] <= '9')
                        development = 1;
                }
            }
        }
    }
    if (stable_minor_out && bytes && size >= sizeof(stable) - 1) {
        for (size_t i = 0; i <= size - (sizeof(stable) - 1); i++) {
            size_t p;
            int minor = 0;
            int have_digit = 0;

            if (memcmp(bytes + i, stable, sizeof(stable) - 1) != 0)
                continue;
            p = i + sizeof(stable) - 1;
            while (p < size && bytes[p] >= '0' && bytes[p] <= '9') {
                if (minor > 1000) {
                    stable_invalid = 1;
                    break;
                }
                minor = minor * 10 + (int)(bytes[p] - '0');
                have_digit = 1;
                p++;
            }
            if (!have_digit ||
                (stable_minor >= 0 && stable_minor != minor))
                stable_invalid = 1;
            else if (!stable_invalid)
                stable_minor = minor;
            if (stable_invalid)
                break;
        }
    }
    if (stable_minor_out)
        *stable_minor_out = stable_invalid ? -1 : stable_minor;
    if (development_out)
        *development_out = development;
}

static int release_profile_matches_reference(const void *data, size_t size)
{
    int actual_minor = -991;
    int actual_development = -992;
    int expected_minor = -993;
    int expected_development = -994;
    int actual_alias = -995;
    int expected_alias = -996;

    dlfrz_glibc_release_profile(
        data, size, &actual_minor, &actual_development);
    release_profile_reference(
        data, size, &expected_minor, &expected_development);
    if (actual_minor != expected_minor ||
        actual_development != expected_development) {
        fprintf(stderr,
                "release profile mismatch (joint): "
                "actual=%d/%d expected=%d/%d size=%zu\n",
                actual_minor, actual_development, expected_minor,
                expected_development, size);
        return 0;
    }

    actual_minor = -991;
    expected_minor = -993;
    dlfrz_glibc_release_profile(data, size, &actual_minor, NULL);
    release_profile_reference(data, size, &expected_minor, NULL);
    if (actual_minor != expected_minor ||
        dlfrz_glibc_stable_release_minor(data, size) != expected_minor) {
        fprintf(stderr,
                "release profile mismatch (stable): "
                "actual=%d expected=%d size=%zu\n",
                actual_minor, expected_minor, size);
        return 0;
    }

    actual_development = -992;
    expected_development = -994;
    dlfrz_glibc_release_profile(data, size, NULL, &actual_development);
    release_profile_reference(data, size, NULL, &expected_development);
    if (actual_development != expected_development ||
        dlfrz_glibc_is_development_release(data, size) !=
            expected_development) {
        fprintf(stderr,
                "release profile mismatch (development): "
                "actual=%d expected=%d size=%zu\n",
                actual_development, expected_development, size);
        return 0;
    }

    /* The public helper historically permits aliased output pointers and
     * writes the development verdict last. */
    dlfrz_glibc_release_profile(
        data, size, &actual_alias, &actual_alias);
    release_profile_reference(
        data, size, &expected_alias, &expected_alias);
    dlfrz_glibc_release_profile(data, size, NULL, NULL);
    if (actual_alias != expected_alias) {
        fprintf(stderr,
                "release profile mismatch (aliased outputs): "
                "actual=%d expected=%d size=%zu\n",
                actual_alias, expected_alias, size);
        return 0;
    }
    return 1;
}

static int release_profile_expect(const void *data, size_t size,
                                  int expected_minor,
                                  int expected_development)
{
    int minor;
    int development;

    dlfrz_glibc_release_profile(data, size, &minor, &development);
    return minor == expected_minor &&
           development == expected_development &&
           release_profile_matches_reference(data, size);
}

static int release_profile_edge_selftest(void)
{
    static const unsigned char stable_at_end[] = {
        's', 's', 's', 'x', '\0',
        's', 't', 'a', 'b', 'l', 'e', ' ', 'r', 'e', 'l', 'e', 'a', 's',
        'e', ' ', 'v', 'e', 'r', 's', 'i', 'o', 'n', ' ', '2', '.', '4', '4'
    };
    static const struct {
        const char *bytes;
        int minor;
        int development;
    } cases[] = {
        { "", -1, 0 },
        { "release version", -1, 0 },
        { "development release version", -1, 1 },
        { "xdevelopment release versionx", -1, 1 },
        { "development release versio", -1, 0 },
        { "release version 2.44", -1, 0 },
        { "release version 2.44.", -1, 0 },
        { "release version 2.44.9", -1, 1 },
        { "release version ..9", -1, 1 },
        { "release version .44.9", -1, 1 },
        { "release version 2..9", -1, 1 },
        { "stable release version 2.44", 44, 0 },
        { "stable release version 2.44.9000", 44, 1 },
        { "stable release version 2.", -1, 0 },
        { "stable release version 2.9999", 9999, 0 },
        { "stable release version 2.10000", 10000, 0 },
        { "stable release version 2.10001", 10001, 0 },
        { "stable release version 2.99999", -1, 0 },
        { "stable release version 2.100000", -1, 0 },
        { "stable release version 2.00000000000044", 44, 0 },
        { "stable release version 2.44; stable release version 2.44",
          44, 0 },
        { "stable release version 2.43; stable release version 2.44",
          -1, 0 },
        { "stable release version 2.44; stable release version 2.",
          -1, 0 },
        { "stable release version 2.; stable release version 2.44",
          -1, 0 },
        { "stable release version 2.; development release version",
          -1, 1 },
        { "development release version; stable release version 2.44",
          44, 1 },
        { "development release versionstable release version 2.44",
          44, 1 },
        { "stable release version 2.44development release version",
          44, 1 },
        { "downstream release version 2.44.9000", -1, 1 }
    };

    if (!release_profile_expect(NULL, SIZE_MAX, -1, 0) ||
        !release_profile_expect(
            stable_at_end, sizeof(stable_at_end), 44, 0))
        return 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (!release_profile_expect(
                cases[i].bytes, strlen(cases[i].bytes), cases[i].minor,
                cases[i].development))
            return 0;
    }
    return 1;
}

static int release_profile_truncation_selftest(void)
{
    static const char *const witnesses[] = {
        "development release version",
        "stable release version 2.44",
        "stable release version 2.44.9000",
        "release version 2.44.9000",
        "release version ..9",
        "stable release version 2.",
        "stable release version 2.43; stable release version 2.44"
    };
    unsigned char padded[192];

    for (size_t witness = 0;
         witness < sizeof(witnesses) / sizeof(witnesses[0]); witness++) {
        size_t length = strlen(witnesses[witness]);

        /* Every contiguous truncation places both resulting boundaries at
         * the edge of the supplied span. */
        for (size_t begin = 0; begin <= length; begin++) {
            for (size_t end = begin; end <= length; end++) {
                if (!release_profile_matches_reference(
                        witnesses[witness] + begin, end - begin))
                    return 0;
            }
        }

        /* Exercise the same prefix truncations at every alignment around the
         * anchor length, with non-text bytes on both sides. */
        for (size_t offset = 0; offset <= 2 * sizeof("release version");
             offset++) {
            for (size_t prefix = 0; prefix <= length; prefix++) {
                size_t used = offset + prefix + 1;

                memset(padded, 0xa5, sizeof(padded));
                memcpy(padded + offset, witnesses[witness], prefix);
                if (!release_profile_matches_reference(padded, used))
                    return 0;
            }
        }
    }
    return 1;
}

static int release_profile_overlap_selftest(void)
{
    static const char *const witnesses[] = {
        "development release version",
        "stable release version 2.44",
        "stable release version 2.44.9000",
        "release version 2.44.9000",
        "release version ..9",
        "stable release version 2."
    };
    unsigned char bytes[192];

    /* Overlay every ordered pair at every intersecting displacement.  The
     * second witness intentionally wins conflicting bytes; reversing the
     * ordered pair covers the opposite overwrite. */
    for (size_t left = 0;
         left < sizeof(witnesses) / sizeof(witnesses[0]); left++) {
        size_t left_size = strlen(witnesses[left]);

        for (size_t right = 0;
             right < sizeof(witnesses) / sizeof(witnesses[0]); right++) {
            size_t right_size = strlen(witnesses[right]);
            int first_shift = -(int)right_size;
            int last_shift = (int)left_size;

            for (int shift = first_shift; shift <= last_shift; shift++) {
                size_t left_at = shift < 0 ? (size_t)-shift : 0;
                size_t right_at = shift < 0 ? 0 : (size_t)shift;
                size_t used = left_at + left_size;

                if (used < right_at + right_size)
                    used = right_at + right_size;
                if (used + 2 > sizeof(bytes))
                    return 0;
                memset(bytes, 0x5a, sizeof(bytes));
                memcpy(bytes + 1 + left_at, witnesses[left], left_size);
                memcpy(bytes + 1 + right_at, witnesses[right], right_size);
                if (!release_profile_matches_reference(bytes, used + 2))
                    return 0;
            }
        }
    }
    return 1;
}

static uint64_t release_profile_fuzz_next(uint64_t *state)
{
    uint64_t value = *state;

    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    *state = value;
    return value;
}

static int release_profile_differential_fuzz_selftest(void)
{
    static const char *const witnesses[] = {
        "development release version",
        "stable release version 2.44",
        "stable release version 2.44.9000",
        "release version 2.44.9000",
        "release version ..9",
        "stable release version 2.",
        "stable release version 2.99999",
        "stable release version 2.43; stable release version 2.44"
    };
    static const unsigned char mutations[] = {
        0, ' ', '.', '0', '2', '4', '9', 'd', 'e', 'l', 'r', 's', 'v',
        0x7f, 0x80, 0xff
    };
    unsigned char bytes[512];
    uint64_t random = UINT64_C(0x4d595df4d0f33173);

    /* Exhaust every one-byte replacement of every witness before the
     * pseudo-random corpus. */
    for (size_t witness = 0;
         witness < sizeof(witnesses) / sizeof(witnesses[0]); witness++) {
        size_t length = strlen(witnesses[witness]);

        for (size_t position = 0; position < length; position++) {
            for (size_t mutation = 0;
                 mutation < sizeof(mutations) / sizeof(mutations[0]);
                 mutation++) {
                memset(bytes, 0xcc, sizeof(bytes));
                memcpy(bytes + 3, witnesses[witness], length);
                bytes[3 + position] = mutations[mutation];
                if (!release_profile_matches_reference(
                        bytes, length + 6))
                    return 0;
            }
        }
    }

    for (size_t iteration = 0; iteration < 50000; iteration++) {
        size_t size =
            (size_t)(release_profile_fuzz_next(&random) % sizeof(bytes));
        size_t insertions =
            (size_t)(release_profile_fuzz_next(&random) % 6U);

        for (size_t i = 0; i < size; i++)
            bytes[i] = (unsigned char)release_profile_fuzz_next(&random);
        for (size_t insertion = 0; insertion < insertions; insertion++) {
            size_t witness = (size_t)(release_profile_fuzz_next(&random) %
                (sizeof(witnesses) / sizeof(witnesses[0])));
            size_t witness_size = strlen(witnesses[witness]);
            size_t offset;

            if (witness_size > size)
                continue;
            offset = (size_t)(release_profile_fuzz_next(&random) %
                              (size - witness_size + 1));
            memcpy(bytes + offset, witnesses[witness], witness_size);
            if ((release_profile_fuzz_next(&random) & 3U) == 0) {
                size_t mutation = (size_t)(
                    release_profile_fuzz_next(&random) % witness_size);

                bytes[offset + mutation] = (unsigned char)
                    release_profile_fuzz_next(&random);
            }
        }
        if (!release_profile_matches_reference(bytes, size))
            return 0;
        if (size != 0) {
            size_t begin = (size_t)(
                release_profile_fuzz_next(&random) % (size + 1));
            size_t end = begin + (size_t)(
                release_profile_fuzz_next(&random) % (size - begin + 1));

            if (!release_profile_matches_reference(
                    bytes + begin, end - begin))
                return 0;
        }
    }
    return 1;
}

#define RELEASE_ELF_FIXTURE_SIZE 2048U
#define RELEASE_ELF_FIXTURE_PHDRS 4U

struct release_elf_fixture {
    unsigned char image[RELEASE_ELF_FIXTURE_SIZE];
    Elf64_Ehdr ehdr;
    Elf64_Phdr phdrs[RELEASE_ELF_FIXTURE_PHDRS];
};

static int release_elf_fixture_publish(struct release_elf_fixture *fixture)
{
    size_t phdr_bytes;

    if (!fixture ||
        fixture->ehdr.e_phnum > RELEASE_ELF_FIXTURE_PHDRS ||
        fixture->ehdr.e_phoff > sizeof(fixture->image) ||
        (size_t)fixture->ehdr.e_phnum >
            (sizeof(fixture->image) - (size_t)fixture->ehdr.e_phoff) /
                sizeof(Elf64_Phdr))
        return 0;
    phdr_bytes =
        (size_t)fixture->ehdr.e_phnum * sizeof(Elf64_Phdr);
    memcpy(fixture->image, &fixture->ehdr, sizeof(fixture->ehdr));
    memcpy(fixture->image + (size_t)fixture->ehdr.e_phoff,
           fixture->phdrs, phdr_bytes);
    return 1;
}

static int release_elf_fixture_init(struct release_elf_fixture *fixture,
                                    uint16_t machine, uint16_t phnum)
{
    if (!fixture || phnum > RELEASE_ELF_FIXTURE_PHDRS)
        return 0;
    memset(fixture, 0, sizeof(*fixture));
    memcpy(fixture->ehdr.e_ident, ELFMAG, SELFMAG);
    fixture->ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    fixture->ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    fixture->ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    fixture->ehdr.e_type = ET_DYN;
    fixture->ehdr.e_machine = machine;
    fixture->ehdr.e_version = EV_CURRENT;
    fixture->ehdr.e_ehsize = sizeof(Elf64_Ehdr);
    fixture->ehdr.e_phoff = sizeof(Elf64_Ehdr);
    fixture->ehdr.e_phentsize = sizeof(Elf64_Phdr);
    fixture->ehdr.e_phnum = phnum;
    return release_elf_fixture_publish(fixture);
}

static int release_elf_fixture_load(struct release_elf_fixture *fixture,
                                    uint16_t index, uint64_t offset,
                                    uint64_t file_size, uint32_t flags)
{
    Elf64_Phdr *phdr;

    if (!fixture || index >= fixture->ehdr.e_phnum)
        return 0;
    phdr = &fixture->phdrs[index];
    memset(phdr, 0, sizeof(*phdr));
    phdr->p_type = PT_LOAD;
    phdr->p_flags = flags;
    phdr->p_offset = offset;
    phdr->p_vaddr = UINT64_C(0x400000) +
                    (uint64_t)index * UINT64_C(0x20000);
    phdr->p_paddr = phdr->p_vaddr;
    phdr->p_filesz = file_size;
    phdr->p_memsz = file_size;
    phdr->p_align = 1;
    return release_elf_fixture_publish(fixture);
}

static int release_elf_fixture_put(struct release_elf_fixture *fixture,
                                   size_t offset, const char *text)
{
    size_t length;

    if (!fixture || !text)
        return 0;
    length = strlen(text);
    if (offset > sizeof(fixture->image) ||
        length > sizeof(fixture->image) - offset)
        return 0;
    memcpy(fixture->image + offset, text, length);
    return 1;
}

static int immutable_release_profile_expect(
    const struct release_elf_fixture *fixture, int expected_valid,
    int expected_minor, int expected_development)
{
    int actual_alias = -994;
    int actual_development = -992;
    int actual_minor = -991;
    int valid;

    valid = dlfrz_glibc_elf_release_profile(
        fixture ? fixture->image : NULL,
        fixture ? sizeof(fixture->image) : SIZE_MAX,
        &actual_minor, &actual_development);
    if (valid != expected_valid || actual_minor != expected_minor ||
        actual_development != expected_development) {
        fprintf(stderr,
                "immutable release profile mismatch: "
                "valid=%d minor=%d development=%d "
                "expected=%d/%d/%d\n",
                valid, actual_minor, actual_development,
                expected_valid, expected_minor, expected_development);
        return 0;
    }
    if (!expected_valid)
        return 1;

    actual_minor = -991;
    if (!dlfrz_glibc_elf_release_profile(
            fixture->image, sizeof(fixture->image),
            &actual_minor, NULL) || actual_minor != expected_minor)
        return 0;
    actual_development = -992;
    if (!dlfrz_glibc_elf_release_profile(
            fixture->image, sizeof(fixture->image),
            NULL, &actual_development) ||
        actual_development != expected_development)
        return 0;
    if (!dlfrz_glibc_elf_release_profile(
            fixture->image, sizeof(fixture->image),
            &actual_alias, &actual_alias) ||
        actual_alias != expected_development ||
        !dlfrz_glibc_elf_release_profile(
            fixture->image, sizeof(fixture->image), NULL, NULL))
        return 0;
    return 1;
}

static int immutable_release_profile_machine_selftest(uint16_t machine)
{
    static const char stable_43[] = "stable release version 2.43.";
    static const char stable_44[] = "stable release version 2.44.";
    static const char malformed[] = "stable release version 2.";
    static const char development[] =
        "development release version 2.44.9000";
    static const char snapshot[] = "stable release version 2.44.9000";
    struct release_elf_fixture fixture;
    const size_t first = 512U;
    const size_t second = 768U;
    const size_t third = 1024U;

    /* Writable content cannot provide, invalidate, or turn a stable witness
     * into a development snapshot. */
    if (!release_elf_fixture_init(&fixture, machine, 3) ||
        !release_elf_fixture_load(
            &fixture, 0, first, 192, PF_R | PF_X) ||
        !release_elf_fixture_load(
            &fixture, 1, second, 192, PF_R | PF_W) ||
        !release_elf_fixture_load(&fixture, 2, third, 192, PF_R) ||
        !release_elf_fixture_put(&fixture, first + 17U, stable_44) ||
        !release_elf_fixture_put(&fixture, second + 11U, stable_43) ||
        !release_elf_fixture_put(&fixture, second + 80U, development) ||
        !immutable_release_profile_expect(&fixture, 1, 44, 0))
        return 0;

    if (!release_elf_fixture_init(&fixture, machine, 1) ||
        !release_elf_fixture_load(&fixture, 0, first, 192, PF_R) ||
        !release_elf_fixture_put(&fixture, first + 17U, snapshot) ||
        !immutable_release_profile_expect(&fixture, 1, 44, 1))
        return 0;

    /* Persistent state keeps both development and conflicting/malformed
     * stable evidence across independent immutable segments. */
    if (!release_elf_fixture_init(&fixture, machine, 2) ||
        !release_elf_fixture_load(&fixture, 0, first, 192, PF_R) ||
        !release_elf_fixture_load(&fixture, 1, second, 192, PF_R) ||
        !release_elf_fixture_put(&fixture, first + 9U, stable_44) ||
        !release_elf_fixture_put(&fixture, second + 7U, development) ||
        !immutable_release_profile_expect(&fixture, 1, 44, 1))
        return 0;
    if (!release_elf_fixture_put(&fixture, second + 80U, stable_43) ||
        !immutable_release_profile_expect(&fixture, 1, -1, 1))
        return 0;

    if (!release_elf_fixture_init(&fixture, machine, 2) ||
        !release_elf_fixture_load(&fixture, 0, first, 192, PF_R) ||
        !release_elf_fixture_load(&fixture, 1, second, 192, PF_R) ||
        !release_elf_fixture_put(&fixture, first + 9U, stable_44) ||
        !release_elf_fixture_put(&fixture, second + 9U, stable_44) ||
        !immutable_release_profile_expect(&fixture, 1, 44, 0))
        return 0;
    if (!release_elf_fixture_init(&fixture, machine, 2) ||
        !release_elf_fixture_load(&fixture, 0, first, 192, PF_R) ||
        !release_elf_fixture_load(&fixture, 1, second, 192, PF_R) ||
        !release_elf_fixture_put(&fixture, first + 9U, malformed) ||
        !release_elf_fixture_put(&fixture, second + 9U, stable_44) ||
        !immutable_release_profile_expect(&fixture, 1, -1, 0))
        return 0;

    /* Literal matching restarts at adjacent segment boundaries. */
    if (!release_elf_fixture_init(&fixture, machine, 2) ||
        !release_elf_fixture_load(&fixture, 0, first, 64, PF_R) ||
        !release_elf_fixture_load(&fixture, 1, first + 64U, 64, PF_R))
        return 0;
    {
        size_t split = 10U;
        size_t length = strlen(stable_44);

        if (split >= length || split > 64U || length - split > 64U)
            return 0;
        memcpy(fixture.image + first + 64U - split,
               stable_44, split);
        memcpy(fixture.image + first + 64U,
               stable_44 + split, length - split);
    }
    if (!immutable_release_profile_expect(&fixture, 1, -1, 0))
        return 0;

    /* Non-loaded, execute-only, and writable-only witnesses are not
     * immutable readable runtime identity. */
    if (!release_elf_fixture_init(&fixture, machine, 3) ||
        !release_elf_fixture_load(&fixture, 0, first, 128, PF_X) ||
        !release_elf_fixture_load(
            &fixture, 1, second, 128, PF_R | PF_W) ||
        !release_elf_fixture_load(&fixture, 2, third, 128, PF_R) ||
        !release_elf_fixture_put(&fixture, first + 5U, stable_44) ||
        !release_elf_fixture_put(&fixture, second + 5U, stable_44) ||
        !release_elf_fixture_put(&fixture, 1500U, stable_44) ||
        !immutable_release_profile_expect(&fixture, 1, -1, 0))
        return 0;
    return 1;
}

static int immutable_release_profile_geometry_selftest(void)
{
    static const char stable_44[] = "stable release version 2.44.";
    struct release_elf_fixture fixture;
    const size_t first = 512U;
    const size_t second = 768U;

    /* Both complete and partial PF_W file aliases fail the linear admission
     * contract before any witness is inspected. */
    if (!release_elf_fixture_init(&fixture, EM_X86_64, 2) ||
        !release_elf_fixture_load(&fixture, 0, first, 192, PF_R) ||
        !release_elf_fixture_load(
            &fixture, 1, first, 192, PF_R | PF_W) ||
        !immutable_release_profile_expect(&fixture, 0, -1, 0))
        return 0;
    if (!release_elf_fixture_init(&fixture, EM_AARCH64, 2) ||
        !release_elf_fixture_load(&fixture, 0, first, 192, PF_R) ||
        !release_elf_fixture_load(
            &fixture, 1, first + 96U, 192, PF_R | PF_W) ||
        !immutable_release_profile_expect(&fixture, 0, -1, 0))
        return 0;

    /* Disjoint file offsets do not prevent the corresponding mappings from
     * aliasing.  Reject full and partial virtual aliases before a PF_W load
     * can overwrite identity bytes admitted from the first load. */
    if (!release_elf_fixture_init(&fixture, EM_X86_64, 2) ||
        !release_elf_fixture_load(&fixture, 0, first, 192, PF_R) ||
        !release_elf_fixture_load(
            &fixture, 1, second, 192, PF_R | PF_W) ||
        !release_elf_fixture_put(&fixture, first + 17U, stable_44))
        return 0;
    fixture.phdrs[1].p_vaddr = fixture.phdrs[0].p_vaddr;
    if (!release_elf_fixture_publish(&fixture) ||
        !immutable_release_profile_expect(&fixture, 0, -1, 0))
        return 0;

    if (!release_elf_fixture_init(&fixture, EM_AARCH64, 2) ||
        !release_elf_fixture_load(&fixture, 0, first, 192, PF_R) ||
        !release_elf_fixture_load(
            &fixture, 1, second, 192, PF_R | PF_W) ||
        !release_elf_fixture_put(&fixture, first + 17U, stable_44))
        return 0;
    fixture.phdrs[1].p_vaddr = fixture.phdrs[0].p_vaddr + 96U;
    if (!release_elf_fixture_publish(&fixture) ||
        !immutable_release_profile_expect(&fixture, 0, -1, 0))
        return 0;

    /* A writable load with no file bytes still maps and zeros p_memsz.  Its
     * BSS is therefore a virtual alias when it covers the read-only load's
     * file-backed release witness. */
    if (!release_elf_fixture_init(&fixture, EM_X86_64, 2) ||
        !release_elf_fixture_load(&fixture, 0, first, 192, PF_R) ||
        !release_elf_fixture_load(
            &fixture, 1, second, 0, PF_R | PF_W) ||
        !release_elf_fixture_put(&fixture, first + 17U, stable_44))
        return 0;
    fixture.phdrs[1].p_vaddr = fixture.phdrs[0].p_vaddr;
    fixture.phdrs[1].p_memsz = 192U;
    if (!release_elf_fixture_publish(&fixture) ||
        !immutable_release_profile_expect(&fixture, 0, -1, 0))
        return 0;

    /* Even disjoint PT_LOADs must retain canonical file order, keeping the
     * proof linear on hostile program-header tables.  Virtual order is
     * independently canonical, including zero-sized placeholder loads. */
    if (!release_elf_fixture_init(&fixture, EM_X86_64, 2) ||
        !release_elf_fixture_load(&fixture, 0, second, 128, PF_R) ||
        !release_elf_fixture_load(&fixture, 1, first, 128, PF_R) ||
        !immutable_release_profile_expect(&fixture, 0, -1, 0))
        return 0;
    if (!release_elf_fixture_init(&fixture, EM_AARCH64, 2) ||
        !release_elf_fixture_load(&fixture, 0, first, 128, PF_R) ||
        !release_elf_fixture_load(&fixture, 1, second, 0, PF_R))
        return 0;
    fixture.phdrs[1].p_vaddr = fixture.phdrs[0].p_vaddr - 1U;
    if (!release_elf_fixture_publish(&fixture) ||
        !immutable_release_profile_expect(&fixture, 0, -1, 0))
        return 0;

    if (!release_elf_fixture_init(&fixture, EM_X86_64, 1) ||
        !release_elf_fixture_load(
            &fixture, 0, sizeof(fixture.image) - 8U, 16, PF_R) ||
        !immutable_release_profile_expect(&fixture, 0, -1, 0))
        return 0;
    if (!release_elf_fixture_init(&fixture, EM_AARCH64, 1) ||
        !release_elf_fixture_load(&fixture, 0, first, 64, PF_R))
        return 0;
    fixture.phdrs[0].p_memsz = fixture.phdrs[0].p_filesz - 1U;
    if (!release_elf_fixture_publish(&fixture) ||
        !immutable_release_profile_expect(&fixture, 0, -1, 0))
        return 0;
    fixture.phdrs[0].p_memsz = fixture.phdrs[0].p_filesz;
    fixture.phdrs[0].p_vaddr = UINT64_MAX - 7U;
    if (!release_elf_fixture_publish(&fixture) ||
        !immutable_release_profile_expect(&fixture, 0, -1, 0))
        return 0;

    if (!release_elf_fixture_init(&fixture, EM_386, 1) ||
        !release_elf_fixture_load(&fixture, 0, first, 64, PF_R) ||
        !immutable_release_profile_expect(&fixture, 0, -1, 0))
        return 0;
    if (!release_elf_fixture_init(&fixture, EM_X86_64, 1) ||
        !immutable_release_profile_expect(&fixture, 0, -1, 0) ||
        !release_elf_fixture_load(&fixture, 0, first, 0, PF_R) ||
        !immutable_release_profile_expect(&fixture, 0, -1, 0))
        return 0;
    if (!release_elf_fixture_init(&fixture, EM_X86_64, 1) ||
        !release_elf_fixture_load(&fixture, 0, first, 64, PF_R))
        return 0;
    fixture.ehdr.e_type = ET_EXEC;
    if (!release_elf_fixture_publish(&fixture) ||
        !immutable_release_profile_expect(&fixture, 0, -1, 0))
        return 0;
    fixture.ehdr.e_type = ET_DYN;
    fixture.ehdr.e_phoff = sizeof(fixture.image) - 1U;
    /* Copy only the header so the classifier sees the intentionally
     * truncated program-header table. */
    memcpy(fixture.image, &fixture.ehdr, sizeof(fixture.ehdr));
    if (!immutable_release_profile_expect(&fixture, 0, -1, 0) ||
        !immutable_release_profile_expect(NULL, 0, -1, 0))
        return 0;
    return 1;
}

static int release_search_selftest(void)
{
    return release_profile_edge_selftest() &&
           release_profile_truncation_selftest() &&
           release_profile_overlap_selftest() &&
           release_profile_differential_fuzz_selftest() &&
           immutable_release_profile_machine_selftest(EM_X86_64) &&
           immutable_release_profile_machine_selftest(EM_AARCH64) &&
           immutable_release_profile_geometry_selftest();
}

/* Exercise both the raw differential oracle and immutable-load classifier
 * against an unmodified, real interpreter or libc image.  This option is
 * architecture-neutral, so native and cross gate binaries can both inspect
 * x86-64 and AArch64 glibc files. */
static int validate_release_profile_file(const char *path)
{
    struct stat st;
    unsigned char *map = MAP_FAILED;
    int development;
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
        !release_profile_matches_reference(map, (size_t)st.st_size) ||
        !dlfrz_glibc_elf_release_profile(
            map, (size_t)st.st_size, &minor, &development))
        goto out;
    printf("%d %d\n", minor, development);
    valid = 1;

out:
    if (map != MAP_FAILED)
        munmap(map, (size_t)st.st_size);
    close(fd);
    return valid ? 0 : 1;
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
        !dlfcn_internal_members_selftest() ||
        !dlfcn_public_name_inventory_selftest() ||
        !x86_cpu_layout_profile_selftest() ||
        !x86_rip_write_width_selftest() ||
        !x86_cpu_kind_control_flow_selftest() ||
        !aarch64_getauxval_contract_selftest() ||
        !release_search_selftest() ||
        dlfrz_glibc_layout_lookup(EM_X86_64, 928, 2120) !=
            DLFRZ_GLIBC_X86_2_40 ||
        dlfrz_glibc_layout_lookup(EM_X86_64, 928, 2136) !=
            DLFRZ_GLIBC_X86_2_44 ||
        dlfrz_glibc_layout_lookup(EM_X86_64, 896, 4352) !=
            DLFRZ_GLIBC_X86_RTLD_896_4336 ||
        dlfrz_glibc_layout_lookup(EM_X86_64, 928, 4320) !=
            DLFRZ_GLIBC_X86_2_34 ||
        dlfrz_glibc_layout_lookup(EM_X86_64, 952, 4368) !=
            DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY ||
        dlfrz_glibc_layout_lookup(EM_X86_64, 952, 2904) !=
            DLFRZ_GLIBC_X86_RTLD_952_2888 ||
        dlfrz_glibc_layout_lookup(EM_X86_64, 896, 4351) !=
            DLFRZ_GLIBC_LAYOUT_UNKNOWN ||
        dlfrz_glibc_layout_lookup(EM_X86_64, 896, 4353) !=
            DLFRZ_GLIBC_LAYOUT_UNKNOWN ||
        dlfrz_glibc_layout_lookup(EM_X86_64, 928, 4319) !=
            DLFRZ_GLIBC_LAYOUT_UNKNOWN ||
        dlfrz_glibc_layout_lookup(EM_X86_64, 928, 4321) !=
            DLFRZ_GLIBC_LAYOUT_UNKNOWN ||
        dlfrz_glibc_layout_lookup(EM_X86_64, 952, 4367) !=
            DLFRZ_GLIBC_LAYOUT_UNKNOWN ||
        dlfrz_glibc_layout_lookup(EM_X86_64, 952, 4369) !=
            DLFRZ_GLIBC_LAYOUT_UNKNOWN ||
        dlfrz_glibc_layout_lookup(EM_X86_64, 952, 2903) !=
            DLFRZ_GLIBC_LAYOUT_UNKNOWN ||
        dlfrz_glibc_layout_lookup(EM_X86_64, 952, 2905) !=
            DLFRZ_GLIBC_LAYOUT_UNKNOWN ||
        dlfrz_glibc_layout_lookup(EM_X86_64, 895, 4352) !=
            DLFRZ_GLIBC_LAYOUT_UNKNOWN ||
        dlfrz_glibc_layout_lookup(EM_X86_64, 897, 4352) !=
            DLFRZ_GLIBC_LAYOUT_UNKNOWN ||
        dlfrz_glibc_layout_lookup(EM_AARCH64, 896, 4352) !=
            DLFRZ_GLIBC_LAYOUT_UNKNOWN ||
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
            dlfrz_glibc_layout_lookup(EM_X86_64, 952, 4368), 39) ||
        !dlfrz_glibc_layout_release_is_supported(
            dlfrz_glibc_layout_lookup(EM_X86_64, 952, 4368), 40) ||
        !dlfrz_glibc_layout_release_is_supported(
            dlfrz_glibc_layout_lookup(EM_X86_64, 952, 4368), 38) ||
        dlfrz_glibc_layout_release_is_supported(
            dlfrz_glibc_layout_lookup(EM_X86_64, 952, 4368), 36) ||
        dlfrz_glibc_layout_release_is_supported(
            dlfrz_glibc_layout_lookup(EM_X86_64, 952, 4368), 41) ||
        !dlfrz_glibc_layout_release_is_supported(
            dlfrz_glibc_layout_lookup(EM_X86_64, 896, 4352), 36) ||
        dlfrz_glibc_layout_release_is_supported(
            dlfrz_glibc_layout_lookup(EM_X86_64, 896, 4352), 35) ||
        dlfrz_glibc_layout_release_is_supported(
            dlfrz_glibc_layout_lookup(EM_X86_64, 896, 4352), 37) ||
        !dlfrz_glibc_layout_release_is_supported(
            dlfrz_glibc_layout_lookup(EM_X86_64, 928, 4320), 34) ||
        !dlfrz_glibc_layout_release_is_supported(
            dlfrz_glibc_layout_lookup(EM_X86_64, 928, 4320), 36) ||
        dlfrz_glibc_layout_release_is_supported(
            dlfrz_glibc_layout_lookup(EM_X86_64, 928, 4320), 33) ||
        dlfrz_glibc_layout_release_is_supported(
            dlfrz_glibc_layout_lookup(EM_X86_64, 928, 4320), 37) ||
        !dlfrz_glibc_layout_release_is_supported(
            dlfrz_glibc_layout_lookup(EM_X86_64, 952, 2904), 41) ||
        dlfrz_glibc_layout_release_is_supported(
            dlfrz_glibc_layout_lookup(EM_X86_64, 952, 2904), 40) ||
        dlfrz_glibc_layout_release_is_supported(
            dlfrz_glibc_layout_lookup(EM_X86_64, 952, 2904), 42) ||
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
    if (argc == 3 && strcmp(argv[1], "--cache-add-tag2") == 0)
        return patch_mapped_file(argv[2], patch_cache_tag2_map);
    if (argc == 4 && strcmp(argv[1], "--frozen-cache-path") == 0)
        return patch_frozen_cache_path_file(argv[3], argv[2]);
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
    if (argc == 3 &&
        strcmp(argv[1], "--frozen-x86-cpu-end-mismatch") == 0)
        return patch_file(argv[2], 23);
    if (argc == 3 && strcmp(argv[1], "--validate-relocations") == 0)
        return validate_relocation_file(argv[2]);
    if (argc == 3 && strcmp(argv[1], "--validate-family") == 0)
        return validate_identity_file(argv[2], 0);
    if (argc == 3 && strcmp(argv[1], "--validate-musl-family") == 0)
        return validate_identity_file(argv[2], 1);
    if (argc == 3 && strcmp(argv[1], "--validate-x86-cpu") == 0)
        return validate_x86_cpu_contract_file(argv[2]);
    if (argc == 4 && strcmp(argv[1], "--validate-x86-cpu-probe") == 0)
        return validate_x86_cpu_probe_files(argv[2], argv[3]);
    if (argc == 4 &&
        strcmp(argv[1], "--validate-aarch64-getauxval") == 0)
        return validate_aarch64_getauxval_file(argv[2], argv[3]);
    if (argc == 4 &&
        strcmp(argv[1], "--test-aarch64-getauxval") == 0)
        return test_aarch64_getauxval_file(argv[2], argv[3]);
    if (argc == 3 && strcmp(argv[1], "--validate-release-profile") == 0)
        return validate_release_profile_file(argv[2]);
    if (argc == 4 && strcmp(argv[1], "--validate-dlfcn-hook") == 0)
        return validate_dlfcn_hook_file(argv[3], argv[2]);
    fprintf(stderr,
            "usage: %s --selftest | --elf FILE | --frozen FILE | "
            "--cache-add-tag2 FILE | --frozen-cache-path PATH FILE | "
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
            "--frozen-x86-cpu-end-mismatch FILE | "
            "--elf-x86-cpu-kind-root-mismatch FILE | "
            "--validate-dlfcn-hook OFFSET FILE | "
            "--validate-relocations FILE | --validate-family FILE | "
            "--validate-musl-family FILE | --validate-x86-cpu FILE | "
            "--validate-aarch64-getauxval FILE GLRO_SIZE | "
            "--test-aarch64-getauxval FILE GLRO_SIZE | "
            "--validate-release-profile FILE\n",
            argv[0]);
    return 2;
}
