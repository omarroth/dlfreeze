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
    COPY_TLS_OFF = 0x1800,
    CREATE_OFF = 0x2000,
    EXIT_OFF = 0x2800,
    LIBC_OFF = 0x3000,
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
            (uintptr_t)(image + LIBC_OFF), 40, &copy_tls, &pthread_size,
            &prev, &next, &sysinfo, &robust, &tls_head, &tls_size,
            &tls_align, &tls_cnt) ||
        copy_tls != (uintptr_t)(image + COPY_TLS_OFF) ||
        pthread_size != 200 || prev != 16 || next != 24 ||
        sysinfo != 32 || robust != 136)
        return 0;

    saved = create[7];
    create[7] = 0xc1; /* copy_tls result no longer feeds the used new pointer */
    if (decode_x86_64_musl_pthread_geometry(
            &obj, create, 512, exit_code, 256,
            (uintptr_t)(image + LIBC_OFF), 40, &copy_tls, &pthread_size,
            &prev, &next, &sysinfo, &robust, &tls_head, &tls_size,
            &tls_align, &tls_cnt))
        return 0;
    create[7] = saved;

    saved = exit_code[20];
    exit_code[20] = 0x18; /* unlink writes the wrong peer field */
    if (decode_x86_64_musl_pthread_geometry(
            &obj, create, 512, exit_code, 256,
            (uintptr_t)(image + LIBC_OFF), 40, &copy_tls, &pthread_size,
            &prev, &next, &sysinfo, &robust, &tls_head, &tls_size,
            &tls_align, &tls_cnt))
        return 0;
    exit_code[20] = saved;
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
    return 0;
}
