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
    CONTRACT_INIT_SSP_SEED_OFF = 0x7f0,
    CONTRACT_COPY_TLS_OFF = 0x800,
    CONTRACT_CREATE_OFF = 0x1000,
    CONTRACT_CLONE_OFF = 0x1400,
    CONTRACT_LIBC_OFF = 0x1800,
    CONTRACT_THREAD_LIST_LOCK_OFF = 0x1880,
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

static uint32_t encode_b(uintptr_t pc, uintptr_t target)
{
    int64_t displacement = (int64_t)target - (int64_t)pc;

    return 0x14000000u |
           (uint32_t)(((uint64_t)(displacement >> 2)) & 0x03ffffffu);
}

static uint32_t encode_cbz64(unsigned int reg, uintptr_t pc,
                             uintptr_t target)
{
    int64_t displacement = (int64_t)target - (int64_t)pc;

    return 0xb4000000u |
           (uint32_t)((((uint64_t)(displacement >> 2)) & 0x7ffffu) << 5) |
           reg;
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

/* GCC 10's musl init_ssp has one GOT-page base shared by its seeded and
 * fallback arms.  The fallback is placed after RET and jumps backward to
 * the common guard-to-TCB copy.  Keep this fixture byte-for-byte shaped like
 * that CFG so each accepted edge and value can be mutated independently. */
static void build_branched_init_ssp(uint32_t *ssp)
{
    size_t got_offset =
        ((uintptr_t)(contract_image + CONTRACT_GUARD_GOT_OFF)) & 0xfff;

    memset(ssp, 0, 160);
    ssp[0] = 0xa9be7bfdu; /* stp x29,x30,[sp,#-32]! */
    ssp[1] = 0x910003fdu; /* mov x29,sp */
    ssp[2] = 0xf9000bf3u; /* str x19,[sp,#16] */
    ssp[3] = encode_adrp(
        (uintptr_t)&ssp[3],
        (uintptr_t)(contract_image + CONTRACT_GUARD_GOT_OFF), 19);
    ssp[4] = encode_cbz64(
        0, (uintptr_t)&ssp[4], (uintptr_t)&ssp[16]);
    ssp[5] = 0xaa0003e1u; /* mov x1,x0 */
    ssp[6] = 0xd2800102u; /* mov x2,#8 */
    ssp[7] = encode_ldrstr64(1, 0, 19, got_offset);
    ssp[8] = encode_bl(
        (uintptr_t)&ssp[8],
        (uintptr_t)(contract_image + CONTRACT_INIT_SSP_SEED_OFF));
    ssp[9] = encode_ldrstr64(1, 19, 19, got_offset);
    ssp[10] = 0xd53bd040u; /* mrs x0,tpidr_el0 */
    ssp[11] = encode_ldrstr64(1, 1, 19, 0);
    ssp[12] = 0xf9400bf3u; /* ldr x19,[sp,#16] */
    ssp[13] = 0xf81f0001u; /* stur x1,[x0,#-16] */
    ssp[14] = 0xa8c27bfdu; /* ldp x29,x30,[sp],#32 */
    ssp[15] = 0xd65f03c0u;
    ssp[16] = encode_ldrstr64(1, 0, 19, got_offset);
    ssp[17] = 0xd289cda1u; /* movz x1,#0x4e6d */
    ssp[18] = 0xf2a838c1u; /* movk x1,#0x41c6,lsl #16 */
    ssp[19] = 0x9b017c01u; /* mul x1,x0,x1 */
    ssp[20] = encode_ldrstr64(0, 1, 0, 0);
    ssp[21] = encode_b((uintptr_t)&ssp[21], (uintptr_t)&ssp[9]);
    *(uint32_t *)(contract_image + CONTRACT_INIT_SSP_SEED_OFF) =
        0xd65f03c0u;
}

static void build_derived_self_uselocale(uint32_t *locale,
                                         uintptr_t global)
{
    memset(locale, 0, 128);
    locale[0] = 0xd53bd042u; /* mrs x2,tpidr_el0 */
    locale[1] = encode_adrp((uintptr_t)&locale[1], global, 1);
    locale[2] = 0xd1032042u; /* sub x2,x2,#200: struct pthread */
    locale[3] = encode_ldrstr64(1, 3, 2, 152);
    locale[4] = 0xb40000a0u; /* cbz x0,join */
    locale[5] = 0xb100041fu; /* cmn x0,#1 */
    locale[6] = 0x54000041u; /* b.ne store */
    locale[7] = encode_add_imm(0, 1, global & 0xfff);
    locale[8] = encode_ldrstr64(0, 0, 2, 152);
    locale[9] = encode_add_imm(1, 1, global & 0xfff);
    locale[10] = 0xeb01007fu; /* cmp x3,x1 */
    locale[11] = 0xda9f1060u; /* csinv x0,x3,xzr,ne */
    locale[12] = 0xd65f03c0u;
}

static void build_split_load_copy_tls(uint32_t *copy)
{
    uintptr_t libc_base =
        (uintptr_t)(contract_image + CONTRACT_LIBC_OFF);

    memset(copy, 0, 192);
    copy[0] = 0x928018e2u; /* mov x2,#-200 */
    copy[1] = encode_adrp((uintptr_t)&copy[1], libc_base, 25);
    copy[2] = encode_add_imm(1, 25, libc_base & 0xfff);
    copy[3] = encode_ldp64(19, 0, 1, 16); /* TLS head,size */
    copy[4] = encode_ldrstr64(1, 22, 1, 32); /* TLS align */
    copy[5] = encode_ldrstr64(1, 24, 1, 40); /* TLS count */
    copy[6] = 0xd503201fu;
    copy[7] = encode_add_imm(21, 22, 200);
    copy[8] = encode_ldrstr64(1, 1, 19, 40); /* module offset */
    copy[9] = encode_ldrstr64(1, 1, 19, 8);  /* module image */
    copy[10] = encode_ldrstr64(1, 2, 19, 16); /* module length */
    copy[11] = encode_ldrstr64(1, 19, 19, 0); /* module next */
    copy[12] = encode_ldrstr64(0, 26, 22, 192);
    copy[13] = 0xd65f03c0u;
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

    /* The relocation-proven guard, byte clear, value load, and TCB store
     * must occur in that order on one register-preserving basic-block path. */
    ssp[3] = 0xd503201fu;
    ssp[6] = 0x3900041fu;
    ssp[7] = 0xd65f03c0u;
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;
    ssp[3] = 0x3900041fu;
    ssp[6] = 0xd65f03c0u;
    ssp[7] = 0;

    memmove(&ssp[3], &ssp[2], 5 * sizeof(*ssp));
    ssp[2] = 0xaa1f03e0u; /* mov x0,xzr: clobber guard provenance */
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;
    ssp[2] = 0xd53bd041u;
    ssp[3] = 0x3900041fu;
    ssp[4] = encode_ldrstr64(1, 0, 0, 0);
    ssp[5] = 0xf81f0020u;
    ssp[6] = 0xd65f03c0u;
    ssp[7] = 0;

    memmove(&ssp[5], &ssp[4], 3 * sizeof(*ssp));
    ssp[4] = 0x14000001u; /* branch to next instruction */
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;
    ssp[4] = encode_ldrstr64(1, 0, 0, 0);
    ssp[5] = 0xf81f0020u;
    ssp[6] = 0xd65f03c0u;
    ssp[7] = 0;

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

    {
        uint32_t *stub = (uint32_t *)(contract_image + CONTRACT_INIT_TLS_OFF);
        static const uint32_t framed[] = {
            0xd503233f, 0xa9bf7bfd, 0x910003fd,
            0xa8c17bfd, 0xd50323bf, 0xd65f03c0,
        };
        memcpy(stub, framed, sizeof(framed));
        if (!decode_aarch64_musl_init_libc(
                &contract_obj, 200, &decoded, &canary) || canary != 184)
            return 0;
        stub[4] = 0xd50323ff; /* authentication key must match */
        if (decode_aarch64_musl_init_libc(
                &contract_obj, 200, &decoded, &canary))
            return 0;
        stub[4] = framed[4];
        stub[3] = 0xa8c27bfd; /* stack restore must balance the save */
        if (decode_aarch64_musl_init_libc(
                &contract_obj, 200, &decoded, &canary))
            return 0;
        memset(stub, 0, sizeof(framed));
        stub[0] = saved;
    }

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

    /* musl 1.2.2 predates the guard-byte clear used as the modern decoder's
     * anchor.  Model its exact fallback assignment and guard-to-TCB copy. */
    memset(ssp, 0, 160);
    ssp[0] = encode_adrp((uintptr_t)&ssp[0],
                         (uintptr_t)(contract_image +
                                     CONTRACT_GUARD_GOT_OFF), 19);
    ssp[1] = encode_ldrstr64(
        1, 0, 19,
        ((uintptr_t)(contract_image + CONTRACT_GUARD_GOT_OFF)) & 0xfff);
    ssp[2] = 0xd289cda1u; /* movz x1,#0x4e6d */
    ssp[3] = 0xf2a838c1u; /* movk x1,#0x41c6,lsl #16 */
    ssp[4] = 0x9b017c01u; /* mul x1,x0,x1 */
    ssp[5] = encode_ldrstr64(0, 1, 0, 0);
    ssp[6] = encode_ldrstr64(
        1, 19, 19,
        ((uintptr_t)(contract_image + CONTRACT_GUARD_GOT_OFF)) & 0xfff);
    ssp[7] = 0xd53bd040u; /* mrs x0,tpidr_el0 */
    ssp[8] = encode_ldrstr64(1, 1, 19, 0);
    ssp[9] = 0xf81f0001u; /* stur x1,[x0,#-16] */
    ssp[10] = 0xd65f03c0u;
    if (!decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary) ||
        decoded != (uintptr_t)(contract_image + CONTRACT_INIT_OFF) ||
        canary != 184)
        return 0;

    saved = ssp[2];
    ssp[2] ^= 1u << 5; /* wrong fallback multiplier */
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;
    ssp[2] = saved;

    saved = ssp[5];
    ssp[5] = encode_ldrstr64(0, 2, 0, 0); /* wrong fallback value */
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;
    ssp[5] = saved;

    saved = ssp[9];
    ssp[9] = 0xf81f0002u; /* TCB store has wrong source */
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;
    ssp[9] = saved;

    ssp[10] = 0xf81f8001u; /* stur x1,[x0,#-8] */
    ssp[11] = 0xd65f03c0u;
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0; /* conflicting canary offsets are ambiguous */
    ssp[10] = 0xd65f03c0u;
    ssp[11] = 0;

    /* GCC 11 schedules the multiplier before the GOT load and reuses the
     * multiplication result directly for the TCB store. */
    memset(ssp, 0, 160);
    ssp[0] = encode_adrp((uintptr_t)&ssp[0],
                         (uintptr_t)(contract_image + CONTRACT_GUARD_GOT_OFF), 1);
    ssp[1] = 0xd289cda0;
    ssp[2] = 0xf2a838c0;
    ssp[3] = encode_ldrstr64(1, 1, 1,
        (uintptr_t)(contract_image + CONTRACT_GUARD_GOT_OFF) & 0xfff);
    ssp[4] = 0x9b007c20; /* mul x0, x1, x0 */
    ssp[5] = encode_ldrstr64(0, 0, 1, 0);
    ssp[6] = 0xd53bd041;
    ssp[7] = 0xf81f0020;
    ssp[8] = 0xd65f03c0;
    if (!decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary) || canary != 184)
        return 0;
    ssp[7] = 0xf81f0022;
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;
    ssp[7] = 0xf81f0020;
    ssp[1] ^= 1u << 5;
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;

    /* GCC 10 places the guard-page ADRP before a CBZ and shares it across
     * the seeded arm, the post-call join, and the out-of-line fallback. */
    build_branched_init_ssp(ssp);
    if (!decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary) ||
        decoded != (uintptr_t)(contract_image + CONTRACT_INIT_OFF) ||
        canary != 184) {
        fprintf(stderr,
                "branched init positive: decoded=%#lx canary=%zu\n",
                (unsigned long)decoded, canary);
        return 0;
    }

    build_branched_init_ssp(ssp);
    ssp[4] ^= UINT32_C(1) << 24; /* CBNZ reverses the seeded/fallback arms */
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;

    build_branched_init_ssp(ssp);
    ssp[4] = encode_cbz64(
        0, (uintptr_t)&ssp[4], (uintptr_t)&ssp[17]);
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0; /* the conditional edge must start at the guard load */

    build_branched_init_ssp(ssp);
    ssp[4] = encode_cbz64(
        0, (uintptr_t)&ssp[4], (uintptr_t)&ssp[3]);
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0; /* no backward conditional fallback edge */

    build_branched_init_ssp(ssp);
    ssp[1] = 0xaa1f03e0u; /* mov x0,xzr: no longer the entry entropy */
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;

    build_branched_init_ssp(ssp);
    ssp[21] = encode_b((uintptr_t)&ssp[21], (uintptr_t)&ssp[10]);
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0; /* both arms must converge at the guard reload */

    build_branched_init_ssp(ssp);
    ssp[15] = 0xd503201fu; /* seeded arm would fall into the fallback */
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;

    build_branched_init_ssp(ssp);
    ssp[3] = encode_adrp(
        (uintptr_t)&ssp[3],
        (uintptr_t)(contract_image + CONTRACT_GUARD_GOT_OFF), 9);
    ssp[7] = encode_ldrstr64(
        1, 0, 9,
        ((uintptr_t)(contract_image + CONTRACT_GUARD_GOT_OFF)) & 0xfff);
    ssp[9] = encode_ldrstr64(
        1, 9, 9,
        ((uintptr_t)(contract_image + CONTRACT_GUARD_GOT_OFF)) & 0xfff);
    ssp[16] = encode_ldrstr64(
        1, 0, 9,
        ((uintptr_t)(contract_image + CONTRACT_GUARD_GOT_OFF)) & 0xfff);
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0; /* a volatile GOT-page base cannot survive BL */

    build_branched_init_ssp(ssp);
    ssp[5] = 0xaa1f03f3u; /* mov x19,xzr: destroy the GOT-page base */
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;

    build_branched_init_ssp(ssp);
    ssp[8] = 0xd503201fu; /* missing seeded-arm call */
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;

    build_branched_init_ssp(ssp);
    ssp[8] = 0xd63f0200u; /* blr x16: indirect target has no proof */
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;

    build_branched_init_ssp(ssp);
    ssp[8] = encode_bl(
        (uintptr_t)&ssp[8],
        (uintptr_t)contract_image + CONTRACT_IMAGE_SIZE + 0x100);
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0; /* direct but outside the target's executable image */

    build_branched_init_ssp(ssp);
    ssp[5] = encode_bl(
        (uintptr_t)&ssp[5],
        (uintptr_t)(contract_image + CONTRACT_INIT_SSP_SEED_OFF));
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0; /* the seeded arm must contain exactly one call */

    build_branched_init_ssp(ssp);
    ssp[7] = encode_ldrstr64(
        1, 0, 19,
        (((uintptr_t)(contract_image + CONTRACT_GUARD_GOT_OFF)) & 0xfff) +
            8);
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0; /* seeded load must use the relocated guard slot */

    build_branched_init_ssp(ssp);
    ssp[9] = encode_ldrstr64(
        1, 19, 19,
        (((uintptr_t)(contract_image + CONTRACT_GUARD_GOT_OFF)) & 0xfff) +
            8);
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0; /* join must reload from the same relocated slot */

    build_branched_init_ssp(ssp);
    ssp[16] = encode_ldrstr64(
        1, 0, 19,
        (((uintptr_t)(contract_image + CONTRACT_GUARD_GOT_OFF)) & 0xfff) +
            8);
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0; /* fallback load must use that same slot */

    build_branched_init_ssp(ssp);
    ssp[17] ^= UINT32_C(1) << 5; /* wrong fallback multiplier */
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;

    build_branched_init_ssp(ssp);
    ssp[19] = 0x9b027c01u; /* multiply by x2, not the proven constant */
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;

    build_branched_init_ssp(ssp);
    ssp[20] = encode_ldrstr64(0, 2, 0, 0); /* store wrong result */
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;

    build_branched_init_ssp(ssp);
    ssp[14] = 0xf81f8001u; /* second TCB field makes layout ambiguous */
    if (decode_aarch64_musl_init_libc(
            &contract_obj, 200, &decoded, &canary))
        return 0;

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

    /* The equivalent direct-TP signed store does not materialize self. */
    locale[3] = 0x910003fd; /* unrelated frame setup */
    locale[5] = 0xf81d0040; /* stur x0, [x2, #-48] */
    if (!decode_aarch64_musl_uselocale(
            &contract_obj, (const uint8_t *)locale, 8 * sizeof(*locale),
            200, &locale_offset, &global) || locale_offset != 152 ||
        global != expected_global)
        return 0;
    locale[5] = 0xf81d8040; /* mismatched store offset */
    if (decode_aarch64_musl_uselocale(
            &contract_obj, (const uint8_t *)locale, 8 * sizeof(*locale),
            200, &locale_offset, &global))
        return 0;
    locale[5] = 0xf81d0040;
    locale[3] = 0xaa1f03e2; /* lost TP provenance */
    if (decode_aarch64_musl_uselocale(
            &contract_obj, (const uint8_t *)locale, 8 * sizeof(*locale),
            200, &locale_offset, &global))
        return 0;

    build_derived_self_uselocale(locale, expected_global);
    if (!decode_aarch64_musl_uselocale(
            &contract_obj, (const uint8_t *)locale, 13 * sizeof(*locale),
            200, &locale_offset, &global) || locale_offset != 152 ||
        global != expected_global)
        return 0;

    build_derived_self_uselocale(locale, expected_global);
    locale[3] = encode_ldrstr64(1, 3, 4, 152);
    if (decode_aarch64_musl_uselocale(
            &contract_obj, (const uint8_t *)locale, 13 * sizeof(*locale),
            200, &locale_offset, &global))
        return 0; /* old locale load must use the proven self register */

    build_derived_self_uselocale(locale, expected_global);
    locale[3] = encode_ldrstr64(1, 3, 2, 144);
    if (decode_aarch64_musl_uselocale(
            &contract_obj, (const uint8_t *)locale, 13 * sizeof(*locale),
            200, &locale_offset, &global))
        return 0; /* load and conditional store offsets must agree */

    build_derived_self_uselocale(locale, expected_global);
    memmove(&locale[4], &locale[3], 10 * sizeof(*locale));
    locale[3] = 0xaa1f03e2u; /* mov x2,xzr: clobber derived self */
    if (decode_aarch64_musl_uselocale(
            &contract_obj, (const uint8_t *)locale, 14 * sizeof(*locale),
            200, &locale_offset, &global))
        return 0;

    build_derived_self_uselocale(locale, expected_global);
    memmove(&locale[4], &locale[3], 10 * sizeof(*locale));
    locale[3] = 0x14000001u; /* branch across the load provenance path */
    if (decode_aarch64_musl_uselocale(
            &contract_obj, (const uint8_t *)locale, 14 * sizeof(*locale),
            200, &locale_offset, &global))
        return 0;

    build_derived_self_uselocale(locale, expected_global);
    locale[8] = encode_ldrstr64(0, 0, 2, 144);
    if (decode_aarch64_musl_uselocale(
            &contract_obj, (const uint8_t *)locale, 13 * sizeof(*locale),
            200, &locale_offset, &global))
        return 0;

    build_derived_self_uselocale(locale, expected_global);
    memmove(&locale[4], &locale[3], 10 * sizeof(*locale));
    locale[3] = encode_ldrstr64(1, 4, 2, 144);
    if (decode_aarch64_musl_uselocale(
            &contract_obj, (const uint8_t *)locale, 14 * sizeof(*locale),
            200, &locale_offset, &global))
        return 0; /* two distinct loaded offsets are ambiguous */

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

    build_split_load_copy_tls(copy);
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

    build_split_load_copy_tls(copy);
    copy[4] = encode_ldrstr64(1, 22, 2, 32);
    if (decode_aarch64_musl_copy_tls_contract(
            &contract_obj,
            (uintptr_t)(contract_image + CONTRACT_COPY_TLS_OFF),
            (uintptr_t)(contract_image + CONTRACT_LIBC_OFF),
            &pthread_size, &dtv, &tls_head, &tls_size, &tls_align,
            &tls_cnt))
        return 0; /* standalone align load has the wrong libc base */

    build_split_load_copy_tls(copy);
    copy[5] = encode_ldrstr64(1, 24, 1, 48);
    if (decode_aarch64_musl_copy_tls_contract(
            &contract_obj,
            (uintptr_t)(contract_image + CONTRACT_COPY_TLS_OFF),
            (uintptr_t)(contract_image + CONTRACT_LIBC_OFF),
            &pthread_size, &dtv, &tls_head, &tls_size, &tls_align,
            &tls_cnt))
        return 0; /* standalone count load has the wrong field offset */

    build_split_load_copy_tls(copy);
    copy[9] = encode_ldrstr64(1, 1, 20, 8);
    if (decode_aarch64_musl_copy_tls_contract(
            &contract_obj,
            (uintptr_t)(contract_image + CONTRACT_COPY_TLS_OFF),
            (uintptr_t)(contract_image + CONTRACT_LIBC_OFF),
            &pthread_size, &dtv, &tls_head, &tls_size, &tls_align,
            &tls_cnt))
        return 0; /* module image load has the wrong module base */

    build_split_load_copy_tls(copy);
    copy[10] = encode_ldrstr64(1, 2, 19, 24);
    if (decode_aarch64_musl_copy_tls_contract(
            &contract_obj,
            (uintptr_t)(contract_image + CONTRACT_COPY_TLS_OFF),
            (uintptr_t)(contract_image + CONTRACT_LIBC_OFF),
            &pthread_size, &dtv, &tls_head, &tls_size, &tls_align,
            &tls_cnt))
        return 0; /* module length load has the wrong field offset */

    build_split_load_copy_tls(copy);
    copy[10] = 0xd503201fu;
    if (decode_aarch64_musl_copy_tls_contract(
            &contract_obj,
            (uintptr_t)(contract_image + CONTRACT_COPY_TLS_OFF),
            (uintptr_t)(contract_image + CONTRACT_LIBC_OFF),
            &pthread_size, &dtv, &tls_head, &tls_size, &tls_align,
            &tls_cnt))
        return 0; /* all four module fields remain required */
    return 1;
}

static int test_clone_ctid_decoder(void)
{
    uint32_t *create =
        (uint32_t *)(contract_image + CONTRACT_CREATE_OFF);
    uint32_t *clone =
        (uint32_t *)(contract_image + CONTRACT_CLONE_OFF);
    uintptr_t expected =
        (uintptr_t)(contract_image + CONTRACT_THREAD_LIST_LOCK_OFF);
    uintptr_t decoded = 0;
    uint32_t saved;

    memset(create, 0, 16 * sizeof(*create));
    memset(clone, 0, 12 * sizeof(*clone));
    create[0] = 0x5281e002u; /* mov w2,#0xf00 */
    create[1] = encode_adrp((uintptr_t)&create[1], expected, 6);
    create[2] = encode_add_imm(5, 27, 200); /* TLS: new pthread */
    create[3] = encode_add_imm(6, 6, expected & 0xfff);
    create[4] = encode_add_imm(4, 27, 32); /* ptid: new->tid */
    create[5] = 0xaa1c03e3u; /* mov x3,x28 */
    create[6] = 0x9a8010e0u; /* csel x0,x7,x0,ne */
    create[7] = 0xaa1c03e1u; /* mov x1,x28 */
    create[8] = 0x72a00fa2u; /* movk w2,#0x7d,lsl #16 */
    create[9] = encode_bl(
        (uintptr_t)&create[9],
        (uintptr_t)(contract_image + CONTRACT_CLONE_OFF));

    clone[0] = 0x927cec21u; /* and x1,x1,#-16 */
    clone[1] = 0xa9bf0c20u; /* stp x0,x3,[x1,#-16]! */
    clone[2] = 0x2a0203e0u; /* mov w0,w2 */
    clone[3] = 0xaa0403e2u; /* mov x2,x4 */
    clone[4] = 0xaa0503e3u; /* mov x3,x5 */
    clone[5] = 0xaa0603e4u; /* mov x4,x6: ctid */
    clone[6] = 0xd2801b88u; /* mov x8,#SYS_clone */
    clone[7] = 0xd4000001u; /* svc #0 */

    if (!decode_aarch64_musl_clone_ctid(
            &contract_obj, (const uint8_t *)create,
            10 * sizeof(*create), 27, 200, 32, &decoded) ||
        decoded != expected)
        return 0;

    saved = create[4];
    create[4] = encode_add_imm(4, 27, 36);
    if (decode_aarch64_musl_clone_ctid(
            &contract_obj, (const uint8_t *)create,
            10 * sizeof(*create), 27, 200, 32, &decoded))
        return 0;
    create[4] = saved;

    saved = clone[5];
    clone[5] = 0xaa0703e4u; /* wrapper no longer maps X6 to kernel ctid */
    if (decode_aarch64_musl_clone_ctid(
            &contract_obj, (const uint8_t *)create,
            10 * sizeof(*create), 27, 200, 32, &decoded))
        return 0;
    clone[5] = saved;

    saved = create[3];
    create[3] = encode_add_imm(6, 6, (expected & 0xfff) + 1);
    if (decode_aarch64_musl_clone_ctid(
            &contract_obj, (const uint8_t *)create,
            10 * sizeof(*create), 27, 200, 32, &decoded))
        return 0;
    create[3] = saved;

    contract_phdr.p_flags &= ~PF_W;
    if (decode_aarch64_musl_clone_ctid(
            &contract_obj, (const uint8_t *)create,
            10 * sizeof(*create), 27, 200, 32, &decoded))
        return 0;
    contract_phdr.p_flags |= PF_W;
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

static int test_scheduled_tp_access(void)
{
    uint32_t code[] = {
        0xd503233f, /* paciasp */
        0xa9bf7bfd, /* stp x29, x30, [sp, #-16]! */
        0xd53bd040, /* mrs x0, tpidr_el0 */
        0x910003fd, /* mov x29, sp (scheduled between TP operations) */
        0xd1032000, /* sub x0, x0, #200 */
        0xa8c17bfd, /* ldp x29, x30, [sp], #16 */
        0xd50323bf, /* autiasp */
        0xd65f03c0, /* ret */
    };
    size_t delta = 0;
    int64_t relative = 0;

    if (!decode_aarch64_musl_self_delta((const uint8_t *)code,
                                        sizeof(code), &delta) || delta != 200)
        return 0;
    code[4] = 0xd1029000; /* errno is TP - 164 */
    if (!decode_aarch64_musl_tp_relative((const uint8_t *)code,
                                         sizeof(code), &relative) || relative != -164)
        return 0;
    code[3] = 0xaa0103e0; /* clobber the TP register */
    if (decode_aarch64_musl_self_delta((const uint8_t *)code, sizeof(code), &delta) ||
        decode_aarch64_musl_tp_relative((const uint8_t *)code, sizeof(code), &relative))
        return 0;
    code[3] = 0x14000002; /* branch around the address calculation */
    if (decode_aarch64_musl_self_delta((const uint8_t *)code, sizeof(code), &delta) ||
        decode_aarch64_musl_tp_relative((const uint8_t *)code, sizeof(code), &relative))
        return 0;
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

    /* Alpine 3.14/3.16 (musl 1.2.2/1.2.3): GCC lays the retrying
     * exclusive store after the non-joinable tail-call path.  The B.EQ
     * reaches the store only for JOINABLE (2), and CBNZ retries at LDAXR
     * until DETACHED (3) is committed. */
    static const uint32_t old_forward_store[] = {
        0x9100a002, /* add   x2, x0, #0x28 */
        0x52800061, /* mov   w1, #3 */
        0x885ffc43, /* ldaxr w3, [x2] */
        0x7100087f, /* cmp   w3, #2 */
        0x54000080, /* b.eq  forward store */
        0xd5033bbf, /* dmb   ish */
        0xd2800001, /* mov   x1, #0 */
        0x14000020, /* b     outside this pthread_detach body */
        0x8803fc41, /* stlxr w3, w1, [x2] */
        0x35ffff23, /* cbnz  w3, back to ldaxr */
        0x52800000, /* mov   w0, #0 */
        0xd65f03c0, /* ret */
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
    uint32_t old_forward_mutated[
        sizeof(old_forward_store) / sizeof(old_forward_store[0])];
    uint32_t direct_mutated[3];

    if (!expect_detach_layout(
            "direct store", direct_store,
            sizeof(direct_store) / sizeof(direct_store[0]), 1, 0) ||
        !expect_detach_layout("compact", compact,
                              sizeof(compact) / sizeof(compact[0]), 1, 2) ||
        !expect_detach_layout(
            "old forward store", old_forward_store,
            sizeof(old_forward_store) / sizeof(old_forward_store[0]), 1,
            2) ||
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
            "old forward store", old_forward_store,
            sizeof(old_forward_store) / sizeof(old_forward_store[0])) ||
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

    memcpy(old_forward_mutated, old_forward_store,
           sizeof(old_forward_mutated));
    old_forward_mutated[3] = 0x7100047f; /* cmp w3, #1 */
    if (!expect_detach_layout(
            "old forward store wrong initial state", old_forward_mutated,
            sizeof(old_forward_mutated) / sizeof(old_forward_mutated[0]),
            0, -1))
        return 1;

    memcpy(old_forward_mutated, old_forward_store,
           sizeof(old_forward_mutated));
    old_forward_mutated[4] = 0x540000a0; /* b.eq after the store */
    if (!expect_detach_layout(
            "old forward store wrong branch target", old_forward_mutated,
            sizeof(old_forward_mutated) / sizeof(old_forward_mutated[0]),
            0, -1))
        return 1;

    memcpy(old_forward_mutated, old_forward_store,
           sizeof(old_forward_mutated));
    old_forward_mutated[7] = 0xd503201f; /* non-joinable path falls through */
    if (!expect_detach_layout(
            "old forward store missing tail exit", old_forward_mutated,
            sizeof(old_forward_mutated) / sizeof(old_forward_mutated[0]),
            0, -1))
        return 1;

    memcpy(old_forward_mutated, old_forward_store,
           sizeof(old_forward_mutated));
    old_forward_mutated[7] = 0x14000001; /* non-joinable path reaches store */
    if (!expect_detach_layout(
            "old forward store tail reaches store", old_forward_mutated,
            sizeof(old_forward_mutated) / sizeof(old_forward_mutated[0]),
            0, -1))
        return 1;

    memcpy(old_forward_mutated, old_forward_store,
           sizeof(old_forward_mutated));
    old_forward_mutated[9] = 0x34ffff23; /* cbz instead of retry-on-failure */
    if (!expect_detach_layout(
            "old forward store wrong retry sense", old_forward_mutated,
            sizeof(old_forward_mutated) / sizeof(old_forward_mutated[0]),
            0, -1))
        return 1;

    memcpy(old_forward_mutated, old_forward_store,
           sizeof(old_forward_mutated));
    old_forward_mutated[9] = 0x35ffff43; /* retry at cmp, not ldaxr */
    if (!expect_detach_layout(
            "old forward store wrong retry target", old_forward_mutated,
            sizeof(old_forward_mutated) / sizeof(old_forward_mutated[0]),
            0, -1))
        return 1;

    memcpy(old_forward_mutated, old_forward_store,
           sizeof(old_forward_mutated));
    old_forward_mutated[1] = 0x52800081; /* mov w1, #4 */
    if (!expect_detach_layout(
            "old forward store wrong detached value", old_forward_mutated,
            sizeof(old_forward_mutated) / sizeof(old_forward_mutated[0]),
            0, -1))
        return 1;

    memcpy(old_forward_mutated, old_forward_store,
           sizeof(old_forward_mutated));
    old_forward_mutated[8] = 0x8803fc61; /* store through x3, not x2 */
    if (!expect_detach_layout(
            "old forward store wrong address", old_forward_mutated,
            sizeof(old_forward_mutated) / sizeof(old_forward_mutated[0]),
            0, -1))
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

    if (!test_scheduled_tp_access()) {
        fprintf(stderr, "AArch64 scheduled TP access decoder failed\n");
        return 1;
    }

    if (!test_init_contract_decoder()) {
        fprintf(stderr, "AArch64 musl init contract decoder failed\n");
        return 1;
    }

    if (!test_target_contract_decoders()) {
        fprintf(stderr, "AArch64 musl target contract decoder failed\n");
        return 1;
    }

    if (!test_clone_ctid_decoder()) {
        fprintf(stderr, "AArch64 musl clone ctid decoder failed\n");
        return 1;
    }

    return 0;
}
