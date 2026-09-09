#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !defined(__x86_64__)
#error "this decoder fixture is x86-64-specific"
#endif

/* Keep the production decoders private while mutation-testing their exact
 * fail-closed instruction contracts. */
#include "../src/loader.c"

enum {
    IMAGE_SIZE = 0x4000,
    START_OFF = 0x100,
    INIT_OFF = 0x400,
    INIT_TLS_OFF = 0x1000,
    INIT_SSP_OFF = 0x1200,
    INIT_SSP_CALL_OFF = 0x1400,
    COPY_TLS_OFF = 0x1800,
    CLONE_OFF = 0x1c00,
    CREATE_OFF = 0x2000,
    EXIT_OFF = 0x2800,
    LIBC_OFF = 0x3000,
    THREAD_LIST_LOCK_OFF = 0x3200,
    GUARD_GOT_OFF = 0x3080,
    DYNSYM_OFF = 0x3800,
    DYNSTR_OFF = 0x3900,
};

static uint8_t image[IMAGE_SIZE];
static Elf64_Phdr phdr;
static Elf64_Rela guard_relocation;
static struct loaded_obj obj;

static const struct dlfrz_musl_layout *modern_layout(void)
{
    for (size_t i = 0;
         i < sizeof(dlfrz_musl_layouts) / sizeof(dlfrz_musl_layouts[0]);
         i++)
        if (dlfrz_musl_layouts[i].machine == EM_X86_64 &&
            dlfrz_musl_layouts[i].minor == 2 &&
            dlfrz_musl_layouts[i].patch == 6)
            return &dlfrz_musl_layouts[i];
    return NULL;
}

static void set_rel32(uint8_t *instruction, uintptr_t target)
{
    int64_t delta = (int64_t)target -
                    (int64_t)(uintptr_t)(instruction + 5);
    int32_t displacement = (int32_t)delta;

    instruction[0] = 0xe8;
    memcpy(instruction + 1, &displacement, sizeof(displacement));
}

static void set_rip_disp32(uint8_t *instruction, size_t length,
                           uintptr_t target)
{
    int64_t delta = (int64_t)target -
                    (int64_t)(uintptr_t)(instruction + length);
    int32_t displacement = (int32_t)delta;

    memcpy(instruction + length - sizeof(displacement), &displacement,
           sizeof(displacement));
}

static void initialize_object(void)
{
    Elf64_Sym *symbols;
    char *strings;

    memset(image, 0x90, sizeof(image));
    memset(&phdr, 0, sizeof(phdr));
    phdr.p_type = PT_LOAD;
    phdr.p_flags = PF_R | PF_W | PF_X;
    phdr.p_vaddr = 0;
    phdr.p_filesz = sizeof(image);
    phdr.p_memsz = sizeof(image);

    memset(&obj, 0, sizeof(obj));
    obj.base = (uintptr_t)image;
    obj.phdr = &phdr;
    obj.phdr_num = 1;
    obj.map_start = (uintptr_t)image;
    obj.map_end = (uintptr_t)image + sizeof(image);

    symbols = (Elf64_Sym *)(image + DYNSYM_OFF);
    strings = (char *)(image + DYNSTR_OFF);
    memset(symbols, 0, 3 * sizeof(*symbols));
    strings[0] = '\0';
    strcpy(strings + 1, "__libc_start_main");
    symbols[1].st_name = 1;
    symbols[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    symbols[1].st_shndx = 1;
    symbols[1].st_value = START_OFF;
    symbols[1].st_size = 16;
    strcpy(strings + 19, "__stack_chk_guard");
    symbols[2].st_name = 19;
    symbols[2].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);
    symbols[2].st_shndx = 1;
    symbols[2].st_value = LIBC_OFF + 0x100;
    symbols[2].st_size = sizeof(uintptr_t);
    obj.dynsym = symbols;
    obj.dynsym_count = 3;
    obj.dynstr = strings;
    obj.dynstr_size = 19 + strlen(strings + 19) + 1;
    memset(&guard_relocation, 0, sizeof(guard_relocation));
    guard_relocation.r_offset = GUARD_GOT_OFF;
    guard_relocation.r_info = ELF64_R_INFO(2, ARCH_RELOC_GLOB_DAT);
    obj.rela = &guard_relocation;
    obj.rela_count = 1;
}

static void build_init_contract(void)
{
    uint8_t *start = image + START_OFF;
    uint8_t *init = image + INIT_OFF;
    uint8_t *ssp = image + INIT_SSP_OFF;

    memset(ssp, 0x90, 160);
    set_rel32(start, (uintptr_t)(image + INIT_OFF));
    start[5] = 0xc3;
    set_rel32(init + 16, (uintptr_t)(image + INIT_TLS_OFF));
    set_rel32(init + 24, (uintptr_t)(image + INIT_SSP_OFF));
    image[INIT_TLS_OFF] = 0xc3;
    memcpy(ssp, "\x48\x8b\x0d\0\0\0\0", 7); /* guard GOT -> rcx */
    set_rip_disp32(ssp, 7, (uintptr_t)(image + GUARD_GOT_OFF));
    memcpy(ssp + 7, "\xc6\x41\x01\0", 4);       /* guard[1] = 0 */
    memcpy(ssp + 11, "\x48\x8b\x11", 3);        /* value = *guard */
    memcpy(ssp + 14, "\x64\x48\x8b\x04\x25\0\0\0\0", 9);
    memcpy(ssp + 23, "\x48\x89\x50\x28", 4);
    ssp[27] = 0xc3;
}

static void build_old_init_contract(void)
{
    uint8_t *ssp = image + INIT_SSP_OFF;
    uint32_t multiplier = UINT32_C(1103515245);

    build_init_contract();
    memset(ssp, 0x90, 160);
    memcpy(ssp, "\x48\x8b\x1d\0\0\0\0", 7); /* guard GOT -> rbx */
    set_rip_disp32(ssp, 7, (uintptr_t)(image + GUARD_GOT_OFF));
    memcpy(ssp + 7, "\x48\x69\xc3", 3);       /* guard * fallback */
    memcpy(ssp + 10, &multiplier, sizeof(multiplier));
    memcpy(ssp + 14, "\x48\x89\x03", 3);     /* fallback -> guard */
    memcpy(ssp + 17, "\x48\x8b\x13", 3);     /* value = *guard */
    memcpy(ssp + 20, "\x64\x48\x8b\x04\x25\0\0\0\0", 9);
    memcpy(ssp + 29, "\x48\x89\x50\x28", 4);
    ssp[33] = 0xc3;
}

/* Alpine's GCC-built musl 1.2.5 keeps the relocation-proven guard address
 * in callee-saved RBX across memcpy instead of spilling it to the stack. */
static void build_live_call_init_contract(void)
{
    uint8_t *ssp = image + INIT_SSP_OFF;

    build_init_contract();
    memset(ssp, 0x90, 160);
    memcpy(ssp, "\x48\x8b\x1d\0\0\0\0", 7); /* guard GOT -> rbx */
    set_rip_disp32(ssp, 7, (uintptr_t)(image + GUARD_GOT_OFF));
    memcpy(ssp + 7, "\x48\x89\xfe", 3);       /* rdi -> rsi */
    memcpy(ssp + 10, "\xba\x08\0\0\0", 5);  /* copy eight bytes */
    memcpy(ssp + 15, "\x48\x89\xdf", 3);     /* guard -> rdi */
    set_rel32(ssp + 18, (uintptr_t)(image + INIT_SSP_CALL_OFF));
    memcpy(ssp + 23, "\xc6\x43\x01\0", 4);  /* guard[1] = 0 */
    memcpy(ssp + 27, "\x48\x8b\x13", 3);     /* value = *guard */
    memcpy(ssp + 30, "\x64\x48\x8b\x04\x25\0\0\0\0", 9);
    memcpy(ssp + 39, "\x48\x89\x50\x28", 4);
    ssp[43] = 0xc3;
    image[INIT_SSP_CALL_OFF] = 0xc3;
}

static void build_branched_old_init_contract(void)
{
    uint8_t *ssp = image + INIT_SSP_OFF;
    uint32_t multiplier = UINT32_C(1103515245);

    build_init_contract();
    memset(ssp, 0x90, 160);
    memcpy(ssp, "\x48\x85\xff\x53", 4);      /* test entropy; push rbx */
    memcpy(ssp + 4, "\x48\x8b\x1d\0\0\0\0", 7);
    set_rip_disp32(ssp + 4, 7,
                   (uintptr_t)(image + GUARD_GOT_OFF));
    memcpy(ssp + 11, "\x74\x12", 2);         /* fallback at +31 */
    memcpy(ssp + 13, "\x48\x89\xfe", 3);    /* entropy -> source */
    memcpy(ssp + 16, "\xba\x08\0\0\0", 5);
    memcpy(ssp + 21, "\x48\x89\xdf", 3);    /* guard -> destination */
    set_rel32(ssp + 24, (uintptr_t)(image + INIT_SSP_CALL_OFF));
    memcpy(ssp + 29, "\xeb\x0a", 2);         /* common copy at +41 */
    memcpy(ssp + 31, "\x48\x69\xc3", 3);
    memcpy(ssp + 34, &multiplier, sizeof(multiplier));
    memcpy(ssp + 38, "\x48\x89\x03", 3);
    memcpy(ssp + 41, "\x48\x8b\x13", 3);
    memcpy(ssp + 44, "\x64\x48\x8b\x04\x25\0\0\0\0", 9);
    memcpy(ssp + 53, "\x48\x89\x50\x28", 4);
    memcpy(ssp + 57, "\x5b\xc3", 2);
    image[INIT_SSP_CALL_OFF] = 0xc3;
}

static void build_backward_old_init_contract(void)
{
    uint8_t *ssp = image + INIT_SSP_OFF;
    uint32_t multiplier = UINT32_C(1103515245);

    build_init_contract();
    memset(ssp, 0x90, 160);
    memcpy(ssp, "\xf3\x0f\x1e\xfa\x53\x48\x85\xff\x74\x2e", 10);
    memcpy(ssp + 10, "\x48\x8b\x1d\0\0\0\0", 7);
    set_rip_disp32(ssp + 10, 7, (uintptr_t)(image + GUARD_GOT_OFF));
    memcpy(ssp + 17, "\x48\x89\xfe\xba\x08\0\0\0\x48\x89\xdf", 11);
    set_rel32(ssp + 28, (uintptr_t)(image + INIT_SSP_CALL_OFF));
    memcpy(ssp + 33, "\x48\x8b\x03", 3);
    memcpy(ssp + 36, "\x64\x48\x8b\x14\x25\0\0\0\0", 9);
    memcpy(ssp + 45, "\x48\x89\x42\x28\x5b\xc3", 6);
    memcpy(ssp + 56, "\x48\x8b\x15\0\0\0\0", 7);
    set_rip_disp32(ssp + 56, 7, (uintptr_t)(image + GUARD_GOT_OFF));
    memcpy(ssp + 63, "\x48\x69\xc2", 3);
    memcpy(ssp + 66, &multiplier, sizeof(multiplier));
    memcpy(ssp + 70, "\x48\x89\x02\xeb\xd9", 5);
    image[INIT_SSP_CALL_OFF] = 0xc3;
}

static void build_frame_spill_init_contract(void)
{
    uint8_t *ssp = image + INIT_SSP_OFF;

    build_init_contract();
    memset(ssp, 0x90, 160);
    memcpy(ssp, "\x55\x48\x89\xe5\x48\x83\xec\x10", 8);
    memcpy(ssp + 8, "\x48\x85\xff\x74\x3b", 5);
    memcpy(ssp + 13, "\x48\x8b\x0d\0\0\0\0", 7);
    set_rip_disp32(ssp + 13, 7,
                   (uintptr_t)(image + GUARD_GOT_OFF));
    memcpy(ssp + 20, "\x48\x89\xfe\xba\x08\0\0\0", 8);
    memcpy(ssp + 28, "\x48\x89\x4d\xf8\x48\x89\xcf\x67", 8);
    set_rel32(ssp + 36, (uintptr_t)(image + INIT_SSP_CALL_OFF));
    memcpy(ssp + 41, "\x48\x8b\x4d\xf8\xc6\x41\x01\0", 8);
    memcpy(ssp + 49, "\x48\x8b\x11", 3);
    memcpy(ssp + 52, "\x64\x48\x8b\x04\x25\0\0\0\0", 9);
    memcpy(ssp + 61, "\x48\x89\x50\x28\xc9\xc3", 6);
    ssp[72] = 0xc3;
    image[INIT_SSP_CALL_OFF] = 0xc3;
}

static int test_init_contract(void)
{
    uintptr_t decoded = 0;
    size_t canary = 0;
    uint8_t saved;

    build_init_contract();
    if (!decode_x86_64_musl_init_libc(&obj, &decoded, &canary) ||
        decoded != (uintptr_t)(image + INIT_OFF) || canary != 40)
        return 0;

    saved = image[INIT_TLS_OFF];
    image[INIT_TLS_OFF] = 0x90;
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;
    image[INIT_TLS_OFF] = saved;

    saved = image[INIT_SSP_OFF + 26];
    image[INIT_SSP_OFF + 26] = 0x30;
    if (!decode_x86_64_musl_init_libc(&obj, &decoded, &canary) ||
        canary != 48)
        return 0;
    image[INIT_SSP_OFF + 26] = saved;

    saved = image[INIT_SSP_OFF + 9];
    image[INIT_SSP_OFF + 9] = 2;
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;
    image[INIT_SSP_OFF + 9] = saved;

    /* The clear must execute before the guard value is loaded.  A decoder
     * that merely collects both instructions from the function would admit
     * this reordered stream and install the uncleared value in the TCB. */
    build_init_contract();
    memset(image + INIT_SSP_OFF + 7, 0x90, 4);
    memcpy(image + INIT_SSP_OFF + 28, "\xc6\x41\x01\0", 4);
    image[INIT_SSP_OFF + 32] = 0xc3;
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;

    /* Register provenance and basic-block reachability are part of the
     * contract as well: neither a clobber nor a branch may separate the
     * clear from the value load. */
    build_init_contract();
    memmove(image + INIT_SSP_OFF + 14,
            image + INIT_SSP_OFF + 11, 17);
    memcpy(image + INIT_SSP_OFF + 11, "\x48\x31\xc9", 3);
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;
    build_init_contract();
    memmove(image + INIT_SSP_OFF + 13,
            image + INIT_SSP_OFF + 11, 17);
    memcpy(image + INIT_SSP_OFF + 11, "\xeb\0", 2);
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;
    build_init_contract();

    guard_relocation.r_info = ELF64_R_INFO(1, ARCH_RELOC_GLOB_DAT);
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;
    guard_relocation.r_info = ELF64_R_INFO(2, ARCH_RELOC_GLOB_DAT);

    set_rel32(image + START_OFF + 8,
              (uintptr_t)(image + INIT_TLS_OFF));
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;
    memset(image + START_OFF + 8, 0x90, 5);

    phdr.p_filesz = START_OFF;
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;
    phdr.p_filesz = sizeof(image);

    build_old_init_contract();
    if (!decode_x86_64_musl_init_libc(&obj, &decoded, &canary) ||
        decoded != (uintptr_t)(image + INIT_OFF) || canary != 40)
        return 0;

    saved = image[INIT_SSP_OFF + 10];
    image[INIT_SSP_OFF + 10] ^= 1; /* wrong fallback multiplier */
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;
    image[INIT_SSP_OFF + 10] = saved;

    saved = image[INIT_SSP_OFF + 16];
    image[INIT_SSP_OFF + 16] = 0x0b; /* fallback stored elsewhere */
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;
    image[INIT_SSP_OFF + 16] = saved;

    saved = image[INIT_SSP_OFF + 31];
    image[INIT_SSP_OFF + 31] = 0x48; /* TCB store has wrong source */
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;
    image[INIT_SSP_OFF + 31] = saved;

    /* Two reachable stores with incompatible offsets remain ambiguous. */
    memcpy(image + INIT_SSP_OFF + 33, "\x48\x89\x50\x30", 4);
    image[INIT_SSP_OFF + 37] = 0xc3;
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0; /* conflicting canary offsets are ambiguous */
    image[INIT_SSP_OFF + 33] = 0xc3;
    memset(image + INIT_SSP_OFF + 34, 0x90, 4);

    build_live_call_init_contract();
    if (!decode_x86_64_musl_init_libc(&obj, &decoded, &canary) ||
        decoded != (uintptr_t)(image + INIT_OFF) || canary != 40)
        return 0;

    /* A call cannot preserve a guard address held in a volatile register. */
    image[INIT_SSP_OFF + 2] = 0x0d;  /* guard GOT -> rcx */
    image[INIT_SSP_OFF + 17] = 0xcf; /* rcx -> rdi */
    image[INIT_SSP_OFF + 24] = 0x41; /* guard[1] via rcx */
    image[INIT_SSP_OFF + 29] = 0x11; /* value via rcx */
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;

    /* An explicit write to the otherwise callee-saved guard is fatal. */
    build_live_call_init_contract();
    memcpy(image + INIT_SSP_OFF + 7, "\x48\x89\xfb", 3);
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;

    /* Indirect calls provide no target provenance. */
    build_live_call_init_contract();
    memcpy(image + INIT_SSP_OFF + 18, "\xff\xd0\x90\x90\x90", 5);
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;

    /* Nor may the direct target escape the validated libc mapping. */
    build_live_call_init_contract();
    set_rel32(image + INIT_SSP_OFF + 18,
              (uintptr_t)image + IMAGE_SIZE + 0x100);
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;

    /* Exactly one call is admitted on the proven path. */
    build_live_call_init_contract();
    memmove(image + INIT_SSP_OFF + 28,
            image + INIT_SSP_OFF + 23, 21);
    set_rel32(image + INIT_SSP_OFF + 23,
              (uintptr_t)(image + INIT_SSP_CALL_OFF));
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;

    build_branched_old_init_contract();
    if (!decode_x86_64_musl_init_libc(&obj, &decoded, &canary) ||
        decoded != (uintptr_t)(image + INIT_OFF) || canary != 40)
        return 0;

    /* The conditional edge must land exactly on the fallback multiply. */
    image[INIT_SSP_OFF + 12]--;
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;

    build_branched_old_init_contract();
    image[INIT_SSP_OFF + 12] = 0xfe; /* backward conditional edge */
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;

    /* The entropy and fallback arms must converge at one exact join. */
    build_branched_old_init_contract();
    image[INIT_SSP_OFF + 30]--;
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;

    /* A call does not preserve a guard address held in volatile RCX. */
    build_branched_old_init_contract();
    image[INIT_SSP_OFF + 6] = 0x0d;
    image[INIT_SSP_OFF + 23] = 0xcf;
    image[INIT_SSP_OFF + 33] = 0xc1;
    image[INIT_SSP_OFF + 40] = 0x01;
    image[INIT_SSP_OFF + 43] = 0x11;
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;

    build_branched_old_init_contract();
    memcpy(image + INIT_SSP_OFF + 13, "\x48\x89\xfb", 3);
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0; /* guard clobber before the call */

    build_branched_old_init_contract();
    memset(image + INIT_SSP_OFF + 24, 0x90, 5);
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0; /* missing entropy-copy call */

    build_branched_old_init_contract();
    memcpy(image + INIT_SSP_OFF + 24, "\xff\xd0\x90\x90\x90", 5);
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0; /* indirect call has no target proof */

    build_branched_old_init_contract();
    set_rel32(image + INIT_SSP_OFF + 24,
              (uintptr_t)image + IMAGE_SIZE + 0x100);
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0; /* direct call escapes the libc mapping */

    build_branched_old_init_contract();
    set_rel32(image + INIT_SSP_OFF + 13,
              (uintptr_t)(image + INIT_SSP_CALL_OFF));
    memset(image + INIT_SSP_OFF + 18, 0x90, 3);
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0; /* two calls make the entropy arm ambiguous */

    build_branched_old_init_contract();
    image[INIT_SSP_OFF + 34] ^= 1;
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0; /* wrong fallback multiplier */

    build_branched_old_init_contract();
    image[INIT_SSP_OFF + 40] = 0x0b;
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0; /* fallback result stored through another base */

    build_branched_old_init_contract();
    memcpy(image + INIT_SSP_OFF + 57, "\x48\x89\x50\x30", 4);
    image[INIT_SSP_OFF + 61] = 0xc3;
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0; /* common copy has two incompatible TCB fields */

    build_backward_old_init_contract();
    if (!decode_x86_64_musl_init_libc(&obj, &decoded, &canary) || canary != 40)
        return 0;
    /* Neither an interior jump nor disagreement between arm values proves
     * the shared TCB store. */
    image[INIT_SSP_OFF + 74]++;
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;
    build_backward_old_init_contract();
    image[INIT_SSP_OFF + 35] = 0x0b;
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;
    build_backward_old_init_contract();
    image[INIT_SSP_OFF + 66] ^= 1;
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;
    build_backward_old_init_contract();
    image[INIT_SSP_OFF + 9]--;
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0;
    build_backward_old_init_contract();
    memset(image + INIT_SSP_OFF + 28, 0x90, 5);
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0; /* the entropy arm must actually initialize the guard */

    build_frame_spill_init_contract();
    if (!decode_x86_64_musl_init_libc(&obj, &decoded, &canary) ||
        canary != 40)
        return 0;
    image[INIT_SSP_OFF + 64] = 48;
    if (!decode_x86_64_musl_init_libc(&obj, &decoded, &canary) ||
        canary != 48)
        return 0;

    build_frame_spill_init_contract();
    image[INIT_SSP_OFF + 7] = 4;
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0; /* spill lies beyond the allocated caller frame */
    build_frame_spill_init_contract();
    image[INIT_SSP_OFF + 7] = 8;
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0; /* slot fits, but the call-site stack is misaligned */
    build_frame_spill_init_contract();
    memcpy(image + INIT_SSP_OFF + 20, "\x48\x89\xfd", 3);
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0; /* RBP no longer identifies the allocated spill frame */
    build_frame_spill_init_contract();
    memcpy(image + INIT_SSP_OFF + 20, "\x48\x89\xfc", 3);
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0; /* RSP no longer leaves the saved pointer above the call */
    build_frame_spill_init_contract();
    image[INIT_SSP_OFF + 44] = 0xf0;
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0; /* reload does not identify the saved pointer */
    build_frame_spill_init_contract();
    image[INIT_SSP_OFF + 34] = 0xef;
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0; /* call destination is the frame pointer */
    build_frame_spill_init_contract();
    image[INIT_SSP_OFF + 12] = 1;
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0; /* conditional edge splits the proven guard load */
    build_frame_spill_init_contract();
    set_rel32(image + INIT_SSP_OFF + 36,
              (uintptr_t)image + IMAGE_SIZE + 0x100);
    if (decode_x86_64_musl_init_libc(&obj, &decoded, &canary))
        return 0; /* direct call escapes the admitted target object */
    return 1;
}

static size_t append_rip_load(uint8_t *code, size_t cursor,
                              uintptr_t target)
{
    memcpy(code + cursor, "\x48\x8b\x05\0\0\0\0", 7);
    set_rip_disp32(code + cursor, 7, target);
    return cursor + 7;
}

static void build_copy_tls_contract(void)
{
    uint8_t *code = image + COPY_TLS_OFF;
    size_t cursor = 0;

    memset(code, 0x90, 192);
    memcpy(code + cursor, "\x48\x8d\x84\x07\x38\xff\xff\xff", 8);
    cursor += 8;
    cursor = append_rip_load(
        code, cursor, (uintptr_t)(image + LIBC_OFF +
                                  g_musl_layout->libc_tls_head));
    cursor = append_rip_load(
        code, cursor, (uintptr_t)(image + LIBC_OFF +
                                  g_musl_layout->libc_tls_size));
    cursor = append_rip_load(
        code, cursor, (uintptr_t)(image + LIBC_OFF +
                                  g_musl_layout->libc_tls_align));
    cursor = append_rip_load(
        code, cursor, (uintptr_t)(image + LIBC_OFF +
                                  g_musl_layout->libc_tls_cnt));
    memcpy(code + cursor, "\x48\x8b\x1b", 3); cursor += 3;
    memcpy(code + cursor, "\x48\x8b\x73\x08", 4); cursor += 4;
    memcpy(code + cursor, "\x48\x8b\x53\x10", 4); cursor += 4;
    memcpy(code + cursor, "\x48\x8b\x7b\x28", 4); cursor += 4;
    code[cursor] = 0xc3;
}

static int test_copy_tls_contract(void)
{
    size_t pthread_size = 0;
    uintptr_t tls_head = 0;
    uintptr_t tls_size = 0;
    uintptr_t tls_align = 0;
    uintptr_t tls_cnt = 0;
    uint8_t saved;

    build_copy_tls_contract();
    if (!decode_x86_64_musl_copy_tls_contract(
            &obj, (uintptr_t)(image + COPY_TLS_OFF),
            (uintptr_t)(image + LIBC_OFF), &pthread_size,
            &tls_head, &tls_size, &tls_align, &tls_cnt) ||
        pthread_size != 200 ||
        tls_head != (uintptr_t)(image + LIBC_OFF + 16) ||
        tls_size != (uintptr_t)(image + LIBC_OFF + 24) ||
        tls_align != (uintptr_t)(image + LIBC_OFF + 32) ||
        tls_cnt != (uintptr_t)(image + LIBC_OFF + 40)) {
        fprintf(stderr, "copy-TLS positive fixture size=%zu\n", pthread_size);
        return 0;
    }

    saved = image[COPY_TLS_OFF + 36];
    image[COPY_TLS_OFF + 36] = 0x90; /* remove the next-field load */
    if (decode_x86_64_musl_copy_tls_contract(
            &obj, (uintptr_t)(image + COPY_TLS_OFF),
            (uintptr_t)(image + LIBC_OFF), &pthread_size,
            &tls_head, &tls_size, &tls_align, &tls_cnt))
        return 0;
    image[COPY_TLS_OFF + 36] = saved;

    saved = image[COPY_TLS_OFF + 7];
    image[COPY_TLS_OFF + 7] = 0xfe; /* sizeof pthread becomes 456 */
    if (decode_x86_64_musl_copy_tls_contract(
            &obj, (uintptr_t)(image + COPY_TLS_OFF),
            (uintptr_t)(image + LIBC_OFF), &pthread_size,
            &tls_head, &tls_size, &tls_align, &tls_cnt))
        return 0;
    image[COPY_TLS_OFF + 7] = saved;
    return 1;
}

static int test_accessors(void)
{
    uint8_t self[] = { 0x64, 0x48, 0x8b, 0x04, 0x25,
                       0, 0, 0, 0, 0xc3 };
    uint8_t *locale = image + 0x3400;
    size_t delta = SIZE_MAX;
    size_t offset = 0;
    uintptr_t global = 0;

    if (!decode_x86_64_musl_self_delta(self, sizeof(self), &delta) ||
        delta != 0)
        return 0;
    self[5] = 1;
    if (decode_x86_64_musl_self_delta(self, sizeof(self), &delta))
        return 0;

    memset(locale, 0x90, 48);
    memcpy(locale, "\x48\x8d\x15\0\0\0\0", 7);
    set_rip_disp32(locale, 7, (uintptr_t)(image + LIBC_OFF + 56));
    memcpy(locale + 8, "\x48\x8b\x81\xa8\0\0\0", 7);
    memcpy(locale + 16, "\x48\x89\xb9\xa8\0\0\0", 7);
    if (!decode_x86_64_musl_uselocale(
            locale, 48, &offset, &global) || offset != 168 ||
        global != (uintptr_t)(image + LIBC_OFF + 56))
        return 0;
    locale[19] = 0xa0;
    if (decode_x86_64_musl_uselocale(
            locale, 48, &offset, &global))
        return 0;
    return 1;
}

static int test_pthread_geometry(void)
{
    uint8_t *create = image + CREATE_OFF;
    uint8_t *exit_code = image + EXIT_OFF;
    uintptr_t copy_tls = 0;
    size_t pthread_size = 0;
    size_t prev = 0;
    size_t next = 0;
    size_t sysinfo = 0;
    size_t robust = 0;
    uintptr_t tls_head = 0;
    uintptr_t tls_size = 0;
    uintptr_t tls_align = 0;
    uintptr_t tls_cnt = 0;
    uintptr_t thread_list_lock = 0;
    uint8_t saved;
    size_t cursor = 0;

    memset(create, 0x90, 512);
    memset(exit_code, 0x90, 256);
    set_rel32(create + cursor, (uintptr_t)(image + COPY_TLS_OFF));
    memcpy(create + 5, "\x48\x89\xc3", 3); /* copy_tls result -> rbx */
    cursor = 8;
    memcpy(create + cursor, "\x48\x89\x1b", 3); cursor += 4;
    memcpy(create + cursor,
           "\x64\x4c\x8b\x34\x25\0\0\0\0", 9); cursor += 10;
    memcpy(create + cursor, "\x48\x8d\x83\x88\0\0\0", 7); cursor += 7;
    memcpy(create + cursor, "\x48\x89\x83\x88\0\0\0", 7); cursor += 8;
    memcpy(create + cursor, "\x49\x8b\x46\x28", 4); cursor += 4;
    memcpy(create + cursor, "\x48\x89\x43\x28", 4); cursor += 4;
    memcpy(create + cursor, "\x49\x8b\x46\x20", 4); cursor += 4;
    memcpy(create + cursor, "\x48\x89\x43\x20", 4); cursor += 4;
    memcpy(create + cursor, "\x0f\x11\x43\x10", 4); cursor += 4;
    memcpy(create + cursor, "\x48\x89\x58\x10", 4); cursor += 4;
    memcpy(create + cursor, "\x48\x89\x58\x18", 4);
    /* Old GCC spells list initialization as a separately loaded peer field;
     * it must not become a third inherited scalar-field candidate. */
    memcpy(create + 80, "\x49\x8b\x46\x18", 4);
    memcpy(create + 84, "\x48\x89\x43\x18", 4);

    /* pthread_create passes the new TCB as TLS, new->tid as ptid, and the
     * hidden thread-list lock as __clone's seventh (stack) ctid argument. */
    memcpy(create + 112, "\x49\x89\xd9", 3); /* rbx -> r9 */
    memcpy(create + 115, "\xba\0\x0f\x7d\0", 5);
    memcpy(create + 120, "\x48\x83\xec\x08", 4);
    memcpy(create + 124, "\x4c\x8d\x43\x30", 4);
    memcpy(create + 128, "\x48\x8d\x05\0\0\0\0", 7);
    set_rip_disp32(create + 128, 7,
                   (uintptr_t)(image + THREAD_LIST_LOCK_OFF));
    create[135] = 0x50;
    memcpy(create + 136, "\x31\xc0", 2);
    set_rel32(create + 138, (uintptr_t)(image + CLONE_OFF));

    memcpy(image + CLONE_OFF,
           "\x31\xc0\xb0\x38\x49\x89\xfb\x48\x89\xd7"
           "\x4c\x89\xc2\x4d\x89\xc8\x4c\x8b\x54\x24\x08"
           "\x4d\x89\xd9\x48\x83\xe6\xf0\x48\x83\xee\x08"
           "\x48\x89\x0e\x0f\x05",
           37);

    memcpy(exit_code,
           "\x64\x48\x8b\x1c\x25\0\0\0\0", 9);
    memcpy(exit_code + 9, "\x48\x8b\x53\x18", 4);
    memcpy(exit_code + 13, "\x48\x8b\x43\x10", 4);
    memcpy(exit_code + 17, "\x48\x89\x42\x10", 4);
    memcpy(exit_code + 21, "\x48\x8b\x53\x18", 4);
    memcpy(exit_code + 25, "\x48\x89\x50\x18", 4);
    memcpy(exit_code + 32, "\x48\x8b\x83\x88\0\0\0", 7);

    if (!decode_x86_64_musl_pthread_geometry(
            &obj, create, 512, exit_code, 256,
            (uintptr_t)(image + LIBC_OFF), 40, 48,
            &copy_tls, &pthread_size, &prev, &next, &sysinfo, &robust,
            &thread_list_lock, &tls_head, &tls_size,
            &tls_align, &tls_cnt) ||
        copy_tls != (uintptr_t)(image + COPY_TLS_OFF) ||
        pthread_size != 200 || prev != 16 || next != 24 ||
        sysinfo != 32 || robust != 136 ||
        thread_list_lock != (uintptr_t)(image + THREAD_LIST_LOCK_OFF))
        return 0;

    saved = create[135];
    create[135] = 0x53; /* push rbx, not the RIP-derived ctid address */
    if (decode_x86_64_musl_pthread_geometry(
            &obj, create, 512, exit_code, 256,
            (uintptr_t)(image + LIBC_OFF), 40, 48,
            &copy_tls, &pthread_size, &prev, &next, &sysinfo, &robust,
            &thread_list_lock, &tls_head, &tls_size,
            &tls_align, &tls_cnt))
        return 0;
    create[135] = saved;

    if (decode_x86_64_musl_pthread_geometry(
            &obj, create, 512, exit_code, 256,
            (uintptr_t)(image + LIBC_OFF), 40, 52,
            &copy_tls, &pthread_size, &prev, &next, &sysinfo, &robust,
            &thread_list_lock, &tls_head, &tls_size,
            &tls_align, &tls_cnt))
        return 0; /* clone ptid must use the independently decoded tid */

    saved = image[CLONE_OFF + 35];
    image[CLONE_OFF + 35] = 0x90; /* no syscall: not musl's clone wrapper */
    if (decode_x86_64_musl_pthread_geometry(
            &obj, create, 512, exit_code, 256,
            (uintptr_t)(image + LIBC_OFF), 40, 48,
            &copy_tls, &pthread_size, &prev, &next, &sysinfo, &robust,
            &thread_list_lock, &tls_head, &tls_size,
            &tls_align, &tls_cnt))
        return 0;
    image[CLONE_OFF + 35] = saved;

    phdr.p_flags &= ~PF_W;
    if (decode_x86_64_musl_pthread_geometry(
            &obj, create, 512, exit_code, 256,
            (uintptr_t)(image + LIBC_OFF), 40, 48,
            &copy_tls, &pthread_size, &prev, &next, &sysinfo, &robust,
            &thread_list_lock, &tls_head, &tls_size,
            &tls_align, &tls_cnt))
        return 0;
    phdr.p_flags |= PF_W;

    saved = create[7];
    create[7] = 0xc1; /* copy_tls result no longer feeds the used new pointer */
    if (decode_x86_64_musl_pthread_geometry(
            &obj, create, 512, exit_code, 256,
            (uintptr_t)(image + LIBC_OFF), 40, 48,
            &copy_tls, &pthread_size, &prev, &next, &sysinfo, &robust,
            &thread_list_lock, &tls_head, &tls_size,
            &tls_align, &tls_cnt))
        return 0;
    create[7] = saved;

    saved = exit_code[20];
    exit_code[20] = 0x18; /* unlink writes the wrong peer field */
    if (decode_x86_64_musl_pthread_geometry(
            &obj, create, 512, exit_code, 256,
            (uintptr_t)(image + LIBC_OFF), 40, 48,
            &copy_tls, &pthread_size, &prev, &next, &sysinfo, &robust,
            &thread_list_lock, &tls_head, &tls_size,
            &tls_align, &tls_cnt))
        return 0;
    exit_code[20] = saved;

    saved = create[83];
    create[83] = 0x30; /* an unrelated third inherited scalar field */
    create[87] = 0x30;
    if (decode_x86_64_musl_pthread_geometry(
            &obj, create, 512, exit_code, 256,
            (uintptr_t)(image + LIBC_OFF), 40, 48,
            &copy_tls, &pthread_size, &prev, &next, &sysinfo, &robust,
            &thread_list_lock, &tls_head, &tls_size,
            &tls_align, &tls_cnt))
        return 0;
    create[83] = saved;
    create[87] = saved;

    /* Older GCC orders the two reciprocal unlink stores in the opposite
     * direction and reloads the first peer between them. */
    memcpy(exit_code + 9, "\x48\x8b\x53\x10", 4);
    memcpy(exit_code + 13, "\x48\x8b\x43\x18", 4);
    memcpy(exit_code + 17, "\x48\x89\x50\x10", 4);
    memcpy(exit_code + 21, "\x48\x8b\x53\x10", 4);
    memcpy(exit_code + 25, "\x48\x89\x42\x18", 4);
    if (!decode_x86_64_musl_pthread_geometry(
            &obj, create, 512, exit_code, 256,
            (uintptr_t)(image + LIBC_OFF), 40, 48,
            &copy_tls, &pthread_size, &prev, &next, &sysinfo, &robust,
            &thread_list_lock, &tls_head, &tls_size,
            &tls_align, &tls_cnt) || prev != 16 || next != 24)
        return 0;
    saved = exit_code[20];
    exit_code[20] = 0x18;
    if (decode_x86_64_musl_pthread_geometry(
            &obj, create, 512, exit_code, 256,
            (uintptr_t)(image + LIBC_OFF), 40, 48,
            &copy_tls, &pthread_size, &prev, &next, &sysinfo, &robust,
            &thread_list_lock, &tls_head, &tls_size,
            &tls_align, &tls_cnt))
        return 0;
    exit_code[20] = saved;

    /* Reciprocal stores may be emitted in either order, but they must share
     * one branch-free data-flow chain. */
    memcpy(exit_code + 9, "\x48\x8b\x53\x10", 4);
    memcpy(exit_code + 13, "\x48\x8b\x43\x18", 4);
    memcpy(exit_code + 17, "\x48\x89\x50\x10", 4);
    memmove(exit_code + 23, exit_code + 21, 8);
    memcpy(exit_code + 21, "\xeb\0", 2);
    if (decode_x86_64_musl_pthread_geometry(
            &obj, create, 512, exit_code, 256,
            (uintptr_t)(image + LIBC_OFF), 40, 48,
            &copy_tls, &pthread_size, &prev, &next, &sysinfo, &robust,
            &thread_list_lock, &tls_head, &tls_size,
            &tls_align, &tls_cnt))
        return 0;

    memset(exit_code + 9, 0x90, 32);
    memcpy(exit_code + 9, "\x48\x8b\x53\x10", 4);
    memcpy(exit_code + 13, "\x48\x8b\x43\x18", 4);
    memcpy(exit_code + 17, "\x48\x89\x50\x10", 4);
    memcpy(exit_code + 21, "\x48\x8b\x53\x10", 4);
    memcpy(exit_code + 25, "\x48\x89\x42\x18", 4);
    memmove(exit_code + 20, exit_code + 17, 12);
    memcpy(exit_code + 17, "\x48\x31\xc0", 3);
    if (decode_x86_64_musl_pthread_geometry(
            &obj, create, 512, exit_code, 256,
            (uintptr_t)(image + LIBC_OFF), 40, 48,
            &copy_tls, &pthread_size, &prev, &next, &sysinfo, &robust,
            &thread_list_lock, &tls_head, &tls_size,
            &tls_align, &tls_cnt))
        return 0;

    /* Alpine's GCC-built musl 1.2.5 prepares a vector self-link between the
     * two scalar peer loads and reciprocal unlink stores.  The vector-only
     * operations must leave the scalar pointer provenance intact. */
    memset(exit_code + 9, 0x90, 48);
    memcpy(exit_code + 9, "\x48\x8b\x53\x18", 4);
    memcpy(exit_code + 13, "\x48\x8b\x43\x10", 4);
    memcpy(exit_code + 17, "\x66\x48\x0f\x6e\xc3", 5);
    memcpy(exit_code + 22, "\x66\x48\x0f\x6e\xe0", 5);
    memcpy(exit_code + 27, "\x66\x0f\x6c\xc4", 4);
    memcpy(exit_code + 31, "\x48\x89\x42\x10", 4);
    memcpy(exit_code + 35, "\x48\x8b\x53\x18", 4);
    memcpy(exit_code + 39, "\x48\x89\x50\x18", 4);
    memcpy(exit_code + 43, "\x0f\x11\x43\x10", 4);
    memcpy(exit_code + 48, "\x48\x8b\x83\x88\0\0\0", 7);
    if (!decode_x86_64_musl_pthread_geometry(
            &obj, create, 512, exit_code, 256,
            (uintptr_t)(image + LIBC_OFF), 40, 48,
            &copy_tls, &pthread_size, &prev, &next, &sysinfo, &robust,
            &thread_list_lock, &tls_head, &tls_size,
            &tls_align, &tls_cnt) || prev != 16 || next != 24)
        return 0;

    /* Register-only SIMD is intentional: memory data flow is not part of
     * the proven list update. */
    exit_code[30] = 0x00; /* PUNPCKLQDQ (%rax),xmm0 */
    if (decode_x86_64_musl_pthread_geometry(
            &obj, create, 512, exit_code, 256,
            (uintptr_t)(image + LIBC_OFF), 40, 48,
            &copy_tls, &pthread_size, &prev, &next, &sysinfo, &robust,
            &thread_list_lock, &tls_head, &tls_size,
            &tls_align, &tls_cnt))
        return 0;
    exit_code[30] = 0xc4;

    memcpy(exit_code + 27, "\xeb\x02\x90\x90", 4);
    if (decode_x86_64_musl_pthread_geometry(
            &obj, create, 512, exit_code, 256,
            (uintptr_t)(image + LIBC_OFF), 40, 48,
            &copy_tls, &pthread_size, &prev, &next, &sysinfo, &robust,
            &thread_list_lock, &tls_head, &tls_size,
            &tls_align, &tls_cnt))
        return 0;
    memcpy(exit_code + 27, "\x66\x0f\x6c\xc4", 4);

    memcpy(exit_code + 22, "\x48\x31\xc0\x90\x90", 5);
    if (decode_x86_64_musl_pthread_geometry(
            &obj, create, 512, exit_code, 256,
            (uintptr_t)(image + LIBC_OFF), 40, 48,
            &copy_tls, &pthread_size, &prev, &next, &sysinfo, &robust,
            &thread_list_lock, &tls_head, &tls_size,
            &tls_align, &tls_cnt))
        return 0;
    return 1;
}

/* A volatile TLS pointer is authoritative only across proven spill/reload
 * paths. These mutations exercise both branch successors and stack aliases. */
static int test_spilled_tls_argument(void)
{
    uint8_t *code = image + CREATE_OFF;
    uint8_t saved[128];
    struct x86_64_musl_clone_instruction instruction;

    memset(code, 0x90, 128);
    memcpy(code, "\x55\x48\x89\xe5\x48\x81\xec\x00\x01\0\0", 11);
    set_rel32(code + 16, (uintptr_t)(image + COPY_TLS_OFF));
    memcpy(code + 21, "\x49\x89\xc1", 3); /* copy result -> r9 */
    memcpy(code + 24, "\x75\x06", 2); /* both paths converge at spill */
    memcpy(code + 32, "\x4c\x89\x4d\xe0", 4);
    set_rel32(code + 40, (uintptr_t)(image + INIT_OFF));
    memcpy(code + 48, "\x4c\x8b\x4d\xe0", 4);
    memcpy(code + 64, "\x41\x52", 2); /* outgoing CTID stack argument */
    memcpy(code + 66, "\x4c\x89\x4d\xd0", 4);
    set_rel32(code + 80, (uintptr_t)(image + CLONE_OFF));
    memcpy(saved, code, sizeof(saved));
    if (!x86_64_musl_spilled_tls_argument(&obj, code, 128, 16, 80) ||
        !x86_64_musl_pushed_ctid_gap(code, 128, 66, 80, 1) ||
        x86_64_musl_pushed_ctid_gap(code, 128, 66, 80, 0))
        return 0;

#define REJECT_POINTER_MUTATION(offset, bytes) do { \
    memcpy(code, saved, sizeof(saved)); \
    memcpy(code + (offset), (bytes), sizeof(bytes) - 1); \
    if (x86_64_musl_spilled_tls_argument(&obj, code, 128, 16, 80)) \
        return 0; \
} while (0)
    REJECT_POINTER_MUTATION(26, "\x45\x31\xc9"); /* fallthrough clobber */
    REJECT_POINTER_MUTATION(26, "\xeb\xfe"); /* branch arm loops */
    REJECT_POINTER_MUTATION(24, "\xeb\x7f"); /* escaping branch */
    REJECT_POINTER_MUTATION(36, "\x48\x89\x45\xe4"); /* overlapping slot */
    REJECT_POINTER_MUTATION(48, "\x4c\x8b\x4d\xd8"); /* wrong reload */
    REJECT_POINTER_MUTATION(52, "\x45\x31\xc9"); /* volatile clobber */
    REJECT_POINTER_MUTATION(52, "\xe8\0\0\0\0"); /* call after reload */
    REJECT_POINTER_MUTATION(7, "\x08\0\0\0"); /* unallocated spill */
#undef REJECT_POINTER_MUTATION
    memcpy(code, saved, sizeof(saved));
    memcpy(code + 70, "\x48\x89\xc4", 3); /* MOV RAX,RSP */
    if (x86_64_musl_pushed_ctid_gap(code, 128, 66, 80, 1))
        return 0;
    memcpy(code, saved, sizeof(saved));
    memcpy(code + 70, "\x48\x89\x04\x24", 4); /* overwrite CTID */
    if (x86_64_musl_pushed_ctid_gap(code, 128, 66, 80, 1))
        return 0;
    if (!x86_64_musl_clone_instruction((const uint8_t *)"\x0f\x95\xc4", 3,
            0, &instruction) || instruction.writes != 1u ||
        !x86_64_musl_clone_instruction((const uint8_t *)"\xc6\xc7\0", 3,
            0, &instruction) || instruction.writes != (1u << 3))
        return 0;
    return 1;
}

int main(void)
{
    g_musl_layout = modern_layout();
    if (!g_musl_layout) {
        fprintf(stderr, "modern musl layout is missing\n");
        return 1;
    }
    initialize_object();
    if (!test_init_contract()) {
        fprintf(stderr, "x86-64 musl init decoder gate failed\n");
        return 1;
    }
    if (!test_accessors()) {
        fprintf(stderr, "x86-64 musl accessor decoder gate failed\n");
        return 1;
    }
    if (!test_copy_tls_contract()) {
        fprintf(stderr, "x86-64 musl copy-TLS decoder gate failed\n");
        return 1;
    }
    if (!test_pthread_geometry()) {
        fprintf(stderr, "x86-64 musl pthread decoder gate failed\n");
        return 1;
    }
    if (!test_spilled_tls_argument()) {
        fprintf(stderr, "x86-64 musl spilled TLS argument decoder gate failed\n");
        return 1;
    }
    return 0;
}
