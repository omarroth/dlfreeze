#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !defined(__aarch64__)
#error "this decoder fixture is AArch64-specific"
#endif

/* Keep the production decoder private while testing the exact instruction
 * streams emitted by supported musl toolchains. */
#include "../src/loader.c"

enum {
    CONTRACT_IMAGE_SIZE = 0x2000,
    CONTRACT_LOCALE_OFF = 0x100,
    CONTRACT_START_OFF = 0x200,
    CONTRACT_INIT_OFF = 0x300,
    CONTRACT_INIT_TLS_OFF = 0x700,
    CONTRACT_INIT_SSP_OFF = 0x740,
    CONTRACT_COPY_TLS_OFF = 0x800,
    CONTRACT_LIBC_OFF = 0x1800,
    CONTRACT_GUARD_GOT_OFF = 0x1900,
    CONTRACT_GUARD_OFF = 0x1910,
    CONTRACT_DYNSYM_OFF = 0x1a00,
    CONTRACT_DYNSTR_OFF = 0x1b00,
    CONTRACT_RELA_OFF = 0x1c00,
};

static uint8_t contract_image[CONTRACT_IMAGE_SIZE];
static Elf64_Phdr contract_phdr;
static struct loaded_obj contract_obj;

static uint32_t encode_bl(uintptr_t pc, uintptr_t target)
{
    int64_t displacement = (int64_t)target - (int64_t)pc;

    return 0x94000000u |
           (uint32_t)(((uint64_t)(displacement >> 2)) & 0x03ffffffu);
}

static const struct dlfrz_musl_layout *modern_aarch64_layout(void)
{
    for (size_t i = 0;
         i < sizeof(dlfrz_musl_layouts) / sizeof(dlfrz_musl_layouts[0]);
         i++)
        if (dlfrz_musl_layouts[i].machine == EM_AARCH64 &&
            dlfrz_musl_layouts[i].minor == 2 &&
            dlfrz_musl_layouts[i].patch == 6)
            return &dlfrz_musl_layouts[i];
    return NULL;
}

static uint32_t encode_adrp(uintptr_t pc, uintptr_t target,
                            unsigned int rd)
{
    int64_t pages = ((int64_t)(target & ~(uintptr_t)0xfff) -
                     (int64_t)(pc & ~(uintptr_t)0xfff)) >> 12;
    uint64_t immediate = (uint64_t)pages & 0x1fffff;

    return 0x90000000u | (uint32_t)((immediate & 3) << 29) |
           (uint32_t)(((immediate >> 2) & 0x7ffff) << 5) | rd;
}

static uint32_t encode_add_imm(unsigned int rd, unsigned int rn,
                               size_t immediate)
{
    return 0x91000000u | (uint32_t)(immediate << 10) |
           (uint32_t)(rn << 5) | rd;
}

static uint32_t encode_ldrstr64(int load, unsigned int rt,
                                unsigned int rn, size_t offset)
{
    return (load ? 0xf9400000u : 0xf9000000u) |
           (uint32_t)((offset / 8) << 10) | (uint32_t)(rn << 5) | rt;
}

static uint32_t encode_ldp64(unsigned int rt, unsigned int rt2,
                             unsigned int rn, size_t offset)
{
    return 0xa9400000u | (uint32_t)((offset / 8) << 15) |
           (uint32_t)(rt2 << 10) | (uint32_t)(rn << 5) | rt;
}

static int test_init_contract_decoder(void)
{
    Elf64_Sym *symbols;
    char *strings;
    Elf64_Rela *guard_relocation;
    uint32_t *start;
    uint32_t *init;
    uint32_t *ssp;
    uintptr_t decoded = 0;
    size_t canary = 0;
    uint32_t saved;

    memset(contract_image, 0, sizeof(contract_image));
    memset(&contract_phdr, 0, sizeof(contract_phdr));
    contract_phdr.p_type = PT_LOAD;
    contract_phdr.p_flags = PF_R | PF_W | PF_X;
    contract_phdr.p_vaddr = 0;
    contract_phdr.p_filesz = sizeof(contract_image);
    contract_phdr.p_memsz = sizeof(contract_image);
    memset(&contract_obj, 0, sizeof(contract_obj));
    contract_obj.base = (uintptr_t)contract_image;
    contract_obj.phdr = &contract_phdr;
    contract_obj.phdr_num = 1;

    symbols = (Elf64_Sym *)(contract_image + CONTRACT_DYNSYM_OFF);
    strings = (char *)(contract_image + CONTRACT_DYNSTR_OFF);
    guard_relocation =
        (Elf64_Rela *)(contract_image + CONTRACT_RELA_OFF);
    memset(symbols, 0, 3 * sizeof(*symbols));
    strings[0] = '\0';
    strcpy(strings + 1, "__libc_start_main");
    strcpy(strings + 19, "__stack_chk_guard");
    symbols[1].st_name = 1;
    symbols[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    symbols[1].st_shndx = 1;
    symbols[1].st_value = CONTRACT_START_OFF;
    symbols[1].st_size = 16;
    symbols[2].st_name = 19;
    symbols[2].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);
    symbols[2].st_shndx = 1;
    symbols[2].st_value = CONTRACT_GUARD_OFF;
    symbols[2].st_size = sizeof(uintptr_t);
    contract_obj.dynsym = symbols;
    contract_obj.dynsym_count = 3;
    contract_obj.dynstr = strings;
    contract_obj.dynstr_size = 19 + strlen(strings + 19) + 1;
    memset(guard_relocation, 0, sizeof(*guard_relocation));
    guard_relocation->r_offset = CONTRACT_GUARD_GOT_OFF;
    guard_relocation->r_info = ELF64_R_INFO(2, ARCH_RELOC_GLOB_DAT);
    contract_obj.rela = guard_relocation;
    contract_obj.rela_count = 1;

    start = (uint32_t *)(contract_image + CONTRACT_START_OFF);
    init = (uint32_t *)(contract_image + CONTRACT_INIT_OFF);
    ssp = (uint32_t *)(contract_image + CONTRACT_INIT_SSP_OFF);
    start[0] = encode_bl((uintptr_t)&start[0],
                         (uintptr_t)(contract_image + CONTRACT_INIT_OFF));
    start[1] = 0xd65f03c0u;
    init[4] = encode_bl((uintptr_t)&init[4],
                        (uintptr_t)(contract_image + CONTRACT_INIT_TLS_OFF));
    init[6] = encode_bl((uintptr_t)&init[6],
                        (uintptr_t)(contract_image + CONTRACT_INIT_SSP_OFF));
    *(uint32_t *)(contract_image + CONTRACT_INIT_TLS_OFF) = 0xd65f03c0u;
    ssp[0] = encode_adrp((uintptr_t)&ssp[0],
                         (uintptr_t)(contract_image +
                                     CONTRACT_GUARD_GOT_OFF), 0);
    ssp[1] = encode_ldrstr64(
        1, 0, 0,
        ((uintptr_t)(contract_image + CONTRACT_GUARD_GOT_OFF)) & 0xfff);
    ssp[2] = 0xd53bd041u; /* mrs x1,tpidr_el0 */
    ssp[3] = 0x3900041fu; /* strb wzr,[x0,#1] */
    ssp[4] = encode_ldrstr64(1, 0, 0, 0);
    ssp[5] = 0xf81f0020u; /* stur x0,[x1,#-16] */
    ssp[6] = 0xd65f03c0u;

    if (!decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary) ||
        decoded != (uintptr_t)(contract_image + CONTRACT_INIT_OFF) ||
        canary != 184) {
        fprintf(stderr,
                "init positive fixture: decoded=%#lx canary=%zu\n",
                (unsigned long)decoded, canary);
        return 0;
    }

    saved = ssp[3];
    ssp[3] = 0x3900081fu; /* wrong guard byte */
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;
    ssp[3] = saved;

    saved = ssp[5];
    ssp[5] = 0xf81f0022u; /* store a value not loaded from the guard */
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;
    ssp[5] = saved;

    guard_relocation->r_info = ELF64_R_INFO(1, ARCH_RELOC_GLOB_DAT);
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;
    guard_relocation->r_info = ELF64_R_INFO(2, ARCH_RELOC_GLOB_DAT);

    saved = *(uint32_t *)(contract_image + CONTRACT_INIT_TLS_OFF);
    *(uint32_t *)(contract_image + CONTRACT_INIT_TLS_OFF) = 0xd503201fu;
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;
    *(uint32_t *)(contract_image + CONTRACT_INIT_TLS_OFF) = saved;

    start[2] = encode_bl((uintptr_t)&start[2],
                         (uintptr_t)(contract_image + CONTRACT_INIT_TLS_OFF));
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;
    start[2] = 0;

    contract_phdr.p_filesz = CONTRACT_START_OFF;
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;
    contract_phdr.p_filesz = sizeof(contract_image);
    return 1;
}

static int test_target_contract_decoders(void)
{
    uint32_t *locale;
    uint32_t *copy;
    uintptr_t global;
    uintptr_t expected_global;
    size_t locale_offset;
    size_t pthread_size;
    size_t dtv;
    uintptr_t tls_head;
    uintptr_t tls_size;
    uintptr_t tls_align;
    uintptr_t tls_cnt;
    uint32_t saved;

    g_musl_layout = modern_aarch64_layout();
    if (!g_musl_layout)
        return 0;
    memset(contract_image, 0, sizeof(contract_image));
    memset(&contract_phdr, 0, sizeof(contract_phdr));
    contract_phdr.p_type = PT_LOAD;
    contract_phdr.p_flags = PF_R | PF_W | PF_X;
    contract_phdr.p_vaddr = 0;
    contract_phdr.p_filesz = sizeof(contract_image);
    contract_phdr.p_memsz = sizeof(contract_image);
    memset(&contract_obj, 0, sizeof(contract_obj));
    contract_obj.base = (uintptr_t)contract_image;
    contract_obj.phdr = &contract_phdr;
    contract_obj.phdr_num = 1;

    expected_global = (uintptr_t)(contract_image + CONTRACT_LIBC_OFF + 56);
    locale = (uint32_t *)(contract_image + CONTRACT_LOCALE_OFF);
    locale[0] = 0xd53bd042u; /* mrs x2,tpidr_el0 */
    locale[1] = 0xf85d0043u; /* ldur x3,[x2,#-48] */
    locale[2] = encode_adrp((uintptr_t)&locale[2], expected_global, 1);
    locale[3] = 0xd1032042u; /* sub x2,x2,#200 */
    locale[4] = encode_add_imm(4, 1, expected_global & 0xfff);
    locale[5] = encode_ldrstr64(0, 0, 2, 152);
    locale[6] = encode_add_imm(1, 1, expected_global & 0xfff);
    locale[7] = 0xd65f03c0u;
    if (!decode_aarch64_musl_uselocale(
            &contract_obj, (const uint8_t *)locale, 8 * sizeof(*locale),
            200, &locale_offset, &global) || locale_offset != 152 ||
        global != expected_global)
        return 0;
    saved = locale[5];
    locale[5] = encode_ldrstr64(0, 0, 2, 144);
    if (decode_aarch64_musl_uselocale(
            &contract_obj, (const uint8_t *)locale, 8 * sizeof(*locale),
            200, &locale_offset, &global))
        return 0;
    locale[5] = saved;

    copy = (uint32_t *)(contract_image + CONTRACT_COPY_TLS_OFF);
    copy[0] = 0x928018e2u; /* mov x2,#-200 */
    copy[1] = encode_adrp(
        (uintptr_t)&copy[1],
        (uintptr_t)(contract_image + CONTRACT_LIBC_OFF), 25);
    copy[2] = encode_add_imm(
        1, 25, ((uintptr_t)(contract_image + CONTRACT_LIBC_OFF)) & 0xfff);
    copy[3] = encode_ldp64(22, 24, 1, 32); /* align,cnt */
    copy[4] = encode_ldp64(19, 0, 1, 16);  /* head,size */
    copy[5] = encode_add_imm(21, 22, 200);
    copy[6] = encode_ldrstr64(1, 1, 19, 40);
    copy[7] = encode_ldp64(1, 2, 19, 8);
    copy[8] = encode_ldrstr64(1, 0, 19, 40);
    copy[9] = encode_ldrstr64(1, 19, 19, 0);
    copy[10] = encode_ldrstr64(1, 1, 1, 40);
    copy[11] = encode_ldrstr64(0, 26, 22, 192);
    copy[12] = 0xd65f03c0u;
    if (!decode_aarch64_musl_copy_tls_contract(
            &contract_obj,
            (uintptr_t)(contract_image + CONTRACT_COPY_TLS_OFF),
            (uintptr_t)(contract_image + CONTRACT_LIBC_OFF),
            &pthread_size, &dtv, &tls_head, &tls_size, &tls_align,
            &tls_cnt) || pthread_size != 200 || dtv != 192 ||
        tls_head != (uintptr_t)(contract_image + CONTRACT_LIBC_OFF + 16) ||
        tls_size != (uintptr_t)(contract_image + CONTRACT_LIBC_OFF + 24) ||
        tls_align != (uintptr_t)(contract_image + CONTRACT_LIBC_OFF + 32) ||
        tls_cnt != (uintptr_t)(contract_image + CONTRACT_LIBC_OFF + 40))
        return 0;
    saved = copy[9];
    copy[9] = encode_ldrstr64(1, 19, 19, 8);
    if (decode_aarch64_musl_copy_tls_contract(
            &contract_obj,
            (uintptr_t)(contract_image + CONTRACT_COPY_TLS_OFF),
            (uintptr_t)(contract_image + CONTRACT_LIBC_OFF),
            &pthread_size, &dtv, &tls_head, &tls_size, &tls_align,
            &tls_cnt))
        return 0;
    copy[9] = saved;
    return 1;
}

static int expect_detach_layout(const char *label, const uint32_t *code,
                                size_t count, int expected,
                                int expected_initial)
{
    size_t offset = 0;
    int initial = -1;
    int decoded = decode_aarch64_musl_detach_offset(
        (const uint8_t *)code, count * sizeof(*code), &offset, &initial);

    if (decoded != expected ||
        (decoded && (offset != 40 || initial != expected_initial))) {
        fprintf(stderr, "%s: decoded=%d offset=%zu initial=%d\n",
                label, decoded, offset, initial);
        return 0;
    }
    return 1;
}

static int expect_prefixes_rejected(const char *label, const uint32_t *code,
                                    size_t count)
{
    for (size_t prefix = 0; prefix < count; prefix++) {
        size_t offset = 0;
        int initial = -1;

        if (decode_aarch64_musl_detach_offset(
                (const uint8_t *)code, prefix * sizeof(*code),
                &offset, &initial)) {
            fprintf(stderr,
                    "%s prefix %zu: decoded offset=%zu initial=%d\n",
                    label, prefix, offset, initial);
            return 0;
        }
    }
    return 1;
}

static int expect_gpr_writes(const char *label, uint32_t instruction,
                             uint32_t expected)
{
    uint32_t writes = 0;

    if (!aarch64_musl_gpr_writes(instruction, &writes) ||
        writes != expected) {
        fprintf(stderr, "%s: writes=%#x expected=%#x\n",
                label, writes, expected);
        return 0;
    }
    return 1;
}

int main(void)
{
    static const uint32_t direct_store[] = {
        0x52800042, /* mov   w2, #2 */
        0xb9002802, /* str   w2, [x0, #40] */
    };
    /* Alpine 3.20: compact, unprotected pthread_detach prologue. */
    static const uint32_t compact[] = {
        0x9100a001, /* add   x1, x0, #0x28 */
        0x52800063, /* mov   w3, #3 */
        0x910003fd, /* mov   x29, sp */
        0xf9000bf3, /* str   x19, [sp, #16] */
        0xaa0003f3, /* mov   x19, x0 */
        0x885ffc22, /* ldaxr w2, [x1] */
        0x7100085f, /* cmp   w2, #2 */
        0x54000081, /* b.ne  ... */
        0x8802fc23, /* stlxr w2, w3, [x1] */
    };

    /* Debian 13: stack protector and PAC/BTI hardening put the exclusive
     * load 56 bytes after the address calculation. */
    static const uint32_t hardened[] = {
        0x9100a001, /* add   x1, x0, #0x28 */
        0x900002e2, /* adrp  x2, ... */
        0xf947bc42, /* ldr   x2, [x2, ...] */
        0x52800063, /* mov   w3, #3 */
        0xa9017bfd, /* stp   x29, x30, [sp, #16] */
        0x910043fd, /* add   x29, sp, #0x10 */
        0xf90013f3, /* str   x19, [sp, #32] */
        0xaa0003f3, /* mov   x19, x0 */
        0xf9400040, /* ldr   x0, [x2] */
        0xf90007e0, /* str   x0, [sp, #8] */
        0xd2800000, /* mov   x0, #0 */
        0x14000003, /* b     ... */
        0x8802fc23, /* stlxr w2, w3, [x1] */
        0x340001c2, /* cbz   w2, ... */
        0x885ffc22, /* ldaxr w2, [x1] */
        0x7100085f, /* cmp   w2, #2 */
        0x54ffff80, /* b.eq  ... */
    };
    /* Ubuntu 24.04 arm64 musl 1.2.4-2: stack protector plus pointer
     * authentication precede the argument-derived detach-state address. */
    static const uint32_t ubuntu_pac[] = {
        0xd503233f, /* paciasp */
        0xd100c3ff, /* sub   sp, sp, #0x30 */
        0xb0000302, /* adrp  x2, ... */
        0xf947c042, /* ldr   x2, [x2, ...] */
        0x9100a001, /* add   x1, x0, #0x28 */
        0xa9017bfd, /* stp   x29, x30, [sp, #16] */
        0x910043fd, /* add   x29, sp, #0x10 */
        0x52800063, /* mov   w3, #3 */
        0xf90013f3, /* str   x19, [sp, #32] */
        0xaa0003f3, /* mov   x19, x0 */
        0xf9400040, /* ldr   x0, [x2] */
        0xf90007e0, /* str   x0, [sp, #8] */
        0xd2800000, /* mov   x0, #0 */
        0x14000003, /* b     ... */
        0x8802fc23, /* stlxr w2, w3, [x1] */
        0x340001c2, /* cbz   w2, ... */
        0x885ffc22, /* ldaxr w2, [x1] */
        0x7100085f, /* cmp   w2, #2 */
        0x54ffff80, /* b.eq  ... */
    };
    /* A BTI-enabled build may place its landing pad before the same PAC
     * prologue.  The landing pad carries no argument provenance itself. */
    static const uint32_t ubuntu_pac_bti[] = {
        0xd503245f, /* bti   c */
        0xd503233f, /* paciasp */
        0xd100c3ff, /* sub   sp, sp, #0x30 */
        0xb0000302, /* adrp  x2, ... */
        0xf947c042, /* ldr   x2, [x2, ...] */
        0x9100a001, /* add   x1, x0, #0x28 */
        0xa9017bfd, /* stp   x29, x30, [sp, #16] */
        0x910043fd, /* add   x29, sp, #0x10 */
        0x52800063, /* mov   w3, #3 */
        0xf90013f3, /* str   x19, [sp, #32] */
        0xaa0003f3, /* mov   x19, x0 */
        0xf9400040, /* ldr   x0, [x2] */
        0xf90007e0, /* str   x0, [sp, #8] */
        0xd2800000, /* mov   x0, #0 */
        0x14000003, /* b     ... */
        0x8802fc23, /* stlxr w2, w3, [x1] */
        0x340001c2, /* cbz   w2, ... */
        0x885ffc22, /* ldaxr w2, [x1] */
        0x7100085f, /* cmp   w2, #2 */
        0x54ffff80, /* b.eq  ... */
    };
    /* Arch Linux ARM (GCC 16): the argument and detached value are both
     * preserved before the stack-canary prologue finishes. */
    static const uint32_t preserved_arg[] = {
        0xd10083ff, /* sub   sp, sp, #0x20 */
        0x52800062, /* mov   w2, #3 */
        0xa9014ffe, /* stp   x30, x19, [sp, #16] */
        0xaa0003f3, /* mov   x19, x0 */
        0x900002c0, /* adrp  x0, ... */
        0xf9479c00, /* ldr   x0, [x0, ...] */
        0xf9400001, /* ldr   x1, [x0] */
        0xf90007e1, /* str   x1, [sp, #8] */
        0xd2800001, /* mov   x1, #0 */
        0x9100a260, /* add   x0, x19, #0x28 */
        0x885ffc01, /* ldaxr w1, [x0] */
        0x7100083f, /* cmp   w1, #2 */
        0x54000081, /* b.ne  ... */
        0x8801fc02, /* stlxr w1, w2, [x0] */
    };
    uint32_t mutated[sizeof(hardened) / sizeof(hardened[0])];
    uint32_t preserved_mutated[
        sizeof(preserved_arg) / sizeof(preserved_arg[0])];
    uint32_t hardened_prefix_mutated[
        sizeof(ubuntu_pac_bti) / sizeof(ubuntu_pac_bti[0])];
    uint32_t direct_mutated[3];

    if (!expect_detach_layout(
            "direct store", direct_store,
            sizeof(direct_store) / sizeof(direct_store[0]), 1, 0) ||
        !expect_detach_layout("compact", compact,
                              sizeof(compact) / sizeof(compact[0]), 1, 2) ||
        !expect_detach_layout("hardened", hardened,
                              sizeof(hardened) / sizeof(hardened[0]), 1, 2) ||
        !expect_detach_layout("Ubuntu PAC", ubuntu_pac,
                              sizeof(ubuntu_pac) / sizeof(ubuntu_pac[0]),
                              1, 2) ||
        !expect_detach_layout(
            "Ubuntu PAC+BTI", ubuntu_pac_bti,
            sizeof(ubuntu_pac_bti) / sizeof(ubuntu_pac_bti[0]), 1, 2) ||
        !expect_detach_layout(
            "preserved argument", preserved_arg,
            sizeof(preserved_arg) / sizeof(preserved_arg[0]), 1, 2))
        return 1;

    if (!expect_prefixes_rejected(
            "direct store", direct_store,
            sizeof(direct_store) / sizeof(direct_store[0])) ||
        !expect_prefixes_rejected(
            "compact", compact, sizeof(compact) / sizeof(compact[0])) ||
        !expect_prefixes_rejected(
            "hardened", hardened,
            sizeof(hardened) / sizeof(hardened[0])) ||
        !expect_prefixes_rejected(
            "Ubuntu PAC", ubuntu_pac,
            sizeof(ubuntu_pac) / sizeof(ubuntu_pac[0])) ||
        !expect_prefixes_rejected(
            "Ubuntu PAC+BTI", ubuntu_pac_bti,
            sizeof(ubuntu_pac_bti) / sizeof(ubuntu_pac_bti[0])) ||
        !expect_prefixes_rejected(
            "preserved argument", preserved_arg,
            sizeof(preserved_arg) / sizeof(preserved_arg[0])))
        return 1;

    if (!expect_gpr_writes("PACIASP", 0xd503233f, 1u << 30) ||
        !expect_gpr_writes("PACIBSP", 0xd503237f, 1u << 30) ||
        !expect_gpr_writes("AUTIASP", 0xd50323bf, 1u << 30) ||
        !expect_gpr_writes("AUTIBSP", 0xd50323ff, 1u << 30) ||
        !expect_gpr_writes("BTI", 0xd503241f, 0) ||
        !expect_gpr_writes("BTI c", 0xd503245f, 0) ||
        !expect_gpr_writes("BTI j", 0xd503249f, 0) ||
        !expect_gpr_writes("BTI jc", 0xd50324df, 0))
        return 1;

    memcpy(hardened_prefix_mutated, ubuntu_pac_bti,
           sizeof(hardened_prefix_mutated));
    hardened_prefix_mutated[0] = 0xaa0103e0; /* mov x0, x1 */
    if (!expect_detach_layout(
            "BTI replaced by argument clobber", hardened_prefix_mutated,
            sizeof(hardened_prefix_mutated) /
                sizeof(hardened_prefix_mutated[0]),
            0, -1))
        return 1;

    memcpy(hardened_prefix_mutated, ubuntu_pac_bti,
           sizeof(hardened_prefix_mutated));
    hardened_prefix_mutated[1] = 0xffffffff; /* unknown prefix instruction */
    if (!expect_detach_layout(
            "unknown PAC replacement", hardened_prefix_mutated,
            sizeof(hardened_prefix_mutated) /
                sizeof(hardened_prefix_mutated[0]),
            0, -1))
        return 1;

    memcpy(mutated, hardened, sizeof(mutated));
    mutated[15] = 0x7100045f; /* cmp w2, #1 */
    if (!expect_detach_layout("wrong initial state", mutated,
                              sizeof(mutated) / sizeof(mutated[0]), 0, -1))
        return 1;

    memcpy(mutated, hardened, sizeof(mutated));
    mutated[12] = 0x8802fc43; /* stlxr w2, w3, [x2] */
    if (!expect_detach_layout("wrong store address", mutated,
                              sizeof(mutated) / sizeof(mutated[0]), 0, -1))
        return 1;

    memcpy(preserved_mutated, preserved_arg, sizeof(preserved_mutated));
    preserved_mutated[3] = 0xaa0103f3; /* mov x19, x1 */
    if (!expect_detach_layout(
            "unproven preserved argument", preserved_mutated,
            sizeof(preserved_mutated) / sizeof(preserved_mutated[0]), 0,
            -1))
        return 1;

    memcpy(preserved_mutated, preserved_arg, sizeof(preserved_mutated));
    preserved_mutated[3] = 0xaa0003e9; /* mov x9, x0 */
    preserved_mutated[9] = 0x9100a120; /* add x0, x9, #0x28 */
    if (!expect_detach_layout(
            "volatile preserved argument", preserved_mutated,
            sizeof(preserved_mutated) / sizeof(preserved_mutated[0]), 0,
            -1))
        return 1;

    memcpy(preserved_mutated, preserved_arg, sizeof(preserved_mutated));
    preserved_mutated[3] = preserved_arg[4]; /* adrp x0, ... */
    preserved_mutated[4] = preserved_arg[3]; /* late mov x19, x0 */
    if (!expect_detach_layout(
            "copy after argument clobber", preserved_mutated,
            sizeof(preserved_mutated) / sizeof(preserved_mutated[0]), 0,
            -1))
        return 1;

    memcpy(preserved_mutated, preserved_arg, sizeof(preserved_mutated));
    preserved_mutated[0] = 0x14000004; /* branch over mov x19, x0 */
    if (!expect_detach_layout(
            "branch skips preserved argument", preserved_mutated,
            sizeof(preserved_mutated) / sizeof(preserved_mutated[0]), 0,
            -1))
        return 1;

    memcpy(preserved_mutated, preserved_arg, sizeof(preserved_mutated));
    preserved_mutated[1] = 0x52800082; /* mov w2, #4 */
    if (!expect_detach_layout(
            "wrong preserved detached value", preserved_mutated,
            sizeof(preserved_mutated) / sizeof(preserved_mutated[0]), 0,
            -1))
        return 1;

    memcpy(preserved_mutated, preserved_arg, sizeof(preserved_mutated));
    preserved_mutated[8] = 0xaa0103f3; /* mov x19, x1 after valid copy */
    if (!expect_detach_layout(
            "clobbered preserved argument", preserved_mutated,
            sizeof(preserved_mutated) / sizeof(preserved_mutated[0]), 0,
            -1))
        return 1;

    memcpy(mutated, hardened, sizeof(mutated));
    mutated[1] = 0xaa0203e1; /* mov x1, x2 after address ADD */
    if (!expect_detach_layout("clobbered address register", mutated,
                              sizeof(mutated) / sizeof(mutated[0]), 0, -1))
        return 1;

    memcpy(mutated, hardened, sizeof(mutated));
    mutated[1] = 0x14000003; /* branch over MOVZ w3, #3 */
    if (!expect_detach_layout("branch skips detached value", mutated,
                              sizeof(mutated) / sizeof(mutated[0]), 0, -1))
        return 1;

    memcpy(mutated, compact, sizeof(compact));
    mutated[2] = 0x14000004; /* branch over LDAXR to CMP */
    if (!expect_detach_layout("branch skips exclusive load", mutated,
                              sizeof(compact) / sizeof(compact[0]), 0, -1))
        return 1;

    memcpy(preserved_mutated, preserved_arg, sizeof(preserved_mutated));
    preserved_mutated[8] = 0x52800082; /* mov w2, #4 before STLXR */
    if (!expect_detach_layout(
            "clobbered detached value", preserved_mutated,
            sizeof(preserved_mutated) / sizeof(preserved_mutated[0]), 0,
            -1))
        return 1;

    memcpy(preserved_mutated, preserved_arg, sizeof(preserved_mutated));
    preserved_mutated[12] = 0xd503201f; /* nop instead of B.NE */
    if (!expect_detach_layout(
            "missing state branch", preserved_mutated,
            sizeof(preserved_mutated) / sizeof(preserved_mutated[0]), 0,
            -1))
        return 1;

    memcpy(mutated, hardened, sizeof(mutated));
    mutated[14] = 0x885ffc21; /* ldaxr w1, [x1] */
    mutated[15] = 0x7100083f; /* cmp w1, #2 */
    if (!expect_detach_layout("loaded register aliases address", mutated,
                              sizeof(mutated) / sizeof(mutated[0]), 0, -1))
        return 1;

    memcpy(mutated, hardened, sizeof(mutated));
    mutated[14] = 0x885ffc23; /* ldaxr w3, [x1] */
    mutated[15] = 0x7100087f; /* cmp w3, #2 */
    if (!expect_detach_layout("loaded register aliases value", mutated,
                              sizeof(mutated) / sizeof(mutated[0]), 0, -1))
        return 1;

    memcpy(mutated, hardened, sizeof(mutated));
    mutated[12] = 0x8803fc23; /* stlxr w3, w3, [x1] */
    if (!expect_detach_layout("status register aliases value", mutated,
                              sizeof(mutated) / sizeof(mutated[0]), 0, -1))
        return 1;

    direct_mutated[0] = 0x52a00042; /* mov w2, #2, lsl #16 */
    direct_mutated[1] = direct_store[1];
    if (!expect_detach_layout("shifted direct marker", direct_mutated, 2,
                              0, -1))
        return 1;

    direct_mutated[0] = 0x5280005f; /* mov wzr, #2 */
    direct_mutated[1] = 0xb900281f; /* str wzr, [x0, #40] */
    if (!expect_detach_layout("zero-register direct marker", direct_mutated,
                              2, 0, -1))
        return 1;

    direct_mutated[0] = direct_store[0];
    direct_mutated[1] = 0x52800082; /* clobber w2 with 4 */
    direct_mutated[2] = direct_store[1];
    if (!expect_detach_layout("clobbered direct marker", direct_mutated, 3,
                              0, -1))
        return 1;

    direct_mutated[0] = direct_store[0];
    direct_mutated[1] = 0xaa0103e0; /* mov x0, x1 */
    direct_mutated[2] = direct_store[1];
    if (!expect_detach_layout("clobbered direct base", direct_mutated, 3,
                              0, -1))
        return 1;

    if (!test_init_contract_decoder()) {
        fprintf(stderr, "AArch64 musl init contract decoder failed\n");
        return 1;
    }

    if (!test_target_contract_decoders()) {
        fprintf(stderr, "AArch64 musl target contract decoder failed\n");
        return 1;
    }

    return 0;
}
