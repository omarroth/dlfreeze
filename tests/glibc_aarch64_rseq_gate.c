#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !defined(__aarch64__)
#error "this decoder fixture is AArch64-specific"
#endif

/* Keep the target-code contract private while exercising its exact control
 * flow and register-provenance requirements. */
#include "../src/loader.c"

enum {
    IMAGE_SIZE = 0x10000,
    ADJACENT_DECOY_OFF = 0x0e00,
    PTHREAD_CREATE_OFF = 0x1000,
    CREATE_A_OFF = 0x2000,
    CREATE_B_OFF = 0x2400,
    START_A_OFF = 0x3000,
    START_B_OFF = 0x3800,
    CLONE_HELPER_OFF = 0x5000,
    CLONE_OFF = 0x6000,
    ALLOCA_OFF = 0x7000,
    GETATTR_OFF = 0x7200,
    DYNSYM_OFF = 0xf000,
    DYNSTR_OFF = 0xf400,
    VERSYM_OFF = 0xf800,
    PTHREAD_SIZE = 0x740,
    RSEQ_OFF = 0x720,
};

static _Alignas(4096) uint8_t image[IMAGE_SIZE];
static Elf64_Phdr phdr;
static struct loaded_obj obj;

static uint32_t encode_branch(uintptr_t pc, uintptr_t target, int link)
{
    int64_t displacement = (int64_t)target - (int64_t)pc;

    return (link ? UINT32_C(0x94000000) : UINT32_C(0x14000000)) |
           (uint32_t)(((uint64_t)(displacement >> 2)) &
                      UINT32_C(0x03ffffff));
}

static uint32_t encode_adrp(uintptr_t pc, uintptr_t target,
                            unsigned int rd)
{
    int64_t pages = ((int64_t)(target & ~(uintptr_t)0xfff) -
                     (int64_t)(pc & ~(uintptr_t)0xfff)) >> 12;
    uint64_t immediate = (uint64_t)pages & UINT64_C(0x1fffff);

    return UINT32_C(0x90000000) |
           (uint32_t)((immediate & 3) << 29) |
           (uint32_t)(((immediate >> 2) & UINT64_C(0x7ffff)) << 5) |
           rd;
}

static uint32_t encode_add_imm(unsigned int rd, unsigned int rn,
                               size_t immediate)
{
    return UINT32_C(0x91000000) |
           (uint32_t)(immediate << 10) | (uint32_t)(rn << 5) | rd;
}

static uint32_t encode_mov(unsigned int rd, unsigned int rn)
{
    return UINT32_C(0xaa0003e0) | (uint32_t)(rn << 16) | rd;
}

static uint32_t encode_ldr64(unsigned int rt, unsigned int rn,
                             size_t offset)
{
    return UINT32_C(0xf9400000) |
           (uint32_t)((offset / sizeof(uint64_t)) << 10) |
           (uint32_t)(rn << 5) | rt;
}

static void emit_private_rseq(uint32_t *code)
{
    code[0] = encode_add_imm(0, 19, RSEQ_OFF);
    code[1] = UINT32_C(0x52800404); /* mov w4,#32 */
    code[2] = UINT32_C(0xd2978003); /* mov x3,#0xbc00 */
    code[3] = UINT32_C(0xd28024a8); /* mov x8,#SYS_rseq */
    code[4] = UINT32_C(0xd4000001); /* svc #0 */
    code[5] = UINT32_C(0x54000069); /* b.ls +12 */
    code[6] = UINT32_C(0x12800020); /* mov w0,#-2 */
    code[7] = UINT32_C(0xb9000000) |
              (uint32_t)((RSEQ_OFF + sizeof(int32_t)) /
                         sizeof(uint32_t) << 10) |
              (19U << 5);           /* str w0,[x19,#RSEQ_OFF+4] */
}

static void emit_create(uint32_t *code, uintptr_t start)
{
    uintptr_t helper = (uintptr_t)(image + CLONE_HELPER_OFF);

    code[0] = encode_mov(19, 0); /* preserve pd */
    code[1] = UINT32_C(0xd503201f);
    code[2] = encode_adrp((uintptr_t)&code[2], start, 1);
    code[3] = encode_add_imm(1, 1, start & 0xfff);
    code[4] = encode_mov(2, 19);
    code[5] = encode_branch((uintptr_t)&code[5], helper, 1);
    code[6] = UINT32_C(0xd65f03c0);
}

static void reset_fixture(void)
{
    Elf64_Sym *symbols;
    uint16_t *versions;
    char *strings;
    uint32_t *pthread_code;
    uint32_t *create_a;
    uint32_t *create_b;
    uint32_t *start_a;
    uint32_t *helper;
    uint32_t *clone;
    uint32_t *alloca_code;
    uint32_t *getattr_code;
    size_t name = 1;

    memset(image, 0, sizeof(image));
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
    obj.map_end = (uintptr_t)(image + sizeof(image));

    symbols = (Elf64_Sym *)(image + DYNSYM_OFF);
    strings = (char *)(image + DYNSTR_OFF);
    versions = (uint16_t *)(image + VERSYM_OFF);
    memset(symbols, 0, 5 * sizeof(*symbols));
    memset(versions, 0, 5 * sizeof(*versions));
    strings[0] = '\0';

#define ADD_FUNCTION(index_, text_, value_, size_)                          \
    do {                                                                    \
        size_t text_length = strlen(text_) + 1;                             \
        memcpy(strings + name, text_, text_length);                         \
        symbols[index_].st_name = (uint32_t)name;                           \
        symbols[index_].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);      \
        symbols[index_].st_shndx = 1;                                      \
        symbols[index_].st_value = value_;                                 \
        symbols[index_].st_size = size_;                                   \
        versions[index_] = 2;                                              \
        name += text_length;                                                \
    } while (0)

    ADD_FUNCTION(1, "pthread_create", PTHREAD_CREATE_OFF, 64);
    ADD_FUNCTION(2, "__clone", CLONE_OFF, 32);
    ADD_FUNCTION(3, "__libc_alloca_cutoff", ALLOCA_OFF, 20);
    ADD_FUNCTION(4, "pthread_getattr_np", GETATTR_OFF, 64);
#undef ADD_FUNCTION

    obj.dynsym = symbols;
    obj.dynsym_count = 5;
    obj.dynstr = strings;
    obj.dynstr_size = name;
    obj.versym = versions;

    pthread_code = (uint32_t *)(image + PTHREAD_CREATE_OFF);
    create_a = (uint32_t *)(image + CREATE_A_OFF);
    create_b = (uint32_t *)(image + CREATE_B_OFF);
    start_a = (uint32_t *)(image + START_A_OFF);
    helper = (uint32_t *)(image + CLONE_HELPER_OFF);
    clone = (uint32_t *)(image + CLONE_OFF);

    pthread_code[0] = encode_branch(
        (uintptr_t)&pthread_code[0], (uintptr_t)create_a, 1);
    pthread_code[1] = encode_branch(
        (uintptr_t)&pthread_code[1], (uintptr_t)create_a, 1);
    pthread_code[2] = UINT32_C(0xd65f03c0);
    emit_create(create_a, (uintptr_t)start_a);
    emit_create(create_b, (uintptr_t)start_a);
    start_a[0] = UINT32_C(0xd503201f);
    emit_private_rseq(start_a + 1);
    start_a[9] = UINT32_C(0xd65f03c0);
    helper[0] = encode_branch(
        (uintptr_t)&helper[0], (uintptr_t)clone, 0);
    clone[0] = UINT32_C(0xd65f03c0);

    /* __libc_alloca_cutoff: TP - pthread_size, load size, divide by 4. */
    alloca_code = (uint32_t *)(image + ALLOCA_OFF);
    alloca_code[0] = UINT32_C(0xd53bd041); /* mrs x1,tpidr_el0 */
    alloca_code[1] = UINT32_C(0xd1000000) |
                     ((uint32_t)PTHREAD_SIZE << 10) | (1U << 5) | 1U;
    alloca_code[2] = encode_ldr64(2, 1, 0x6e0);
    alloca_code[3] = UINT32_C(0xd342fc42); /* lsr x2,x2,#2 */
    alloca_code[4] = UINT32_C(0xd65f03c0);

    /* pthread_getattr_np: the exact three adjacent private-field loads and
     * both public-result arithmetic consumers. */
    getattr_code = (uint32_t *)(image + GETATTR_OFF);
    getattr_code[0] = encode_mov(19, 0);
    getattr_code[1] = encode_ldr64(1, 19, 0x6d8);
    getattr_code[2] = UINT32_C(0xb4000041); /* cbz x1,+8 */
    getattr_code[3] = encode_ldr64(2, 19, 0x6e0);
    getattr_code[4] = encode_ldr64(3, 19, 0x6e8);
    getattr_code[5] = UINT32_C(0x8b020024); /* add x4,x1,x2 */
    getattr_code[6] = UINT32_C(0xcb030045); /* sub x5,x2,x3 */
    for (size_t i = 7; i < 15; i++)
        getattr_code[i] = UINT32_C(0xd503201f);
    getattr_code[15] = UINT32_C(0xd65f03c0);
}

static int rseq_decodes(void)
{
    enum glibc_aarch64_rseq_storage storage = GLIBC_AARCH64_RSEQ_NONE;
    size_t offset = 0;

    return glibc_aarch64_rseq_contract(
               &obj, PTHREAD_SIZE, &storage, &offset) &&
           storage == GLIBC_AARCH64_RSEQ_PRIVATE_PTHREAD &&
           offset == RSEQ_OFF;
}

static int test_rseq_control_flow(void)
{
    uint32_t *pthread_code;
    uint32_t *create_a;
    uint32_t *start_a;
    uint32_t *start_b;
    uint32_t *decoy;

    reset_fixture();
    if (!rseq_decodes()) {
        fprintf(stderr, "Ubuntu 24-shaped rseq fixture was rejected\n");
        return 0;
    }

    /* A valid byte sequence adjacent to pthread_create is not an identity. */
    reset_fixture();
    start_a = (uint32_t *)(image + START_A_OFF);
    memset(start_a, 0, 10 * sizeof(*start_a));
    start_a[0] = UINT32_C(0xd65f03c0);
    decoy = (uint32_t *)(image + ADJACENT_DECOY_OFF);
    emit_private_rseq(decoy);
    decoy[8] = UINT32_C(0xd65f03c0);
    if (rseq_decodes()) {
        fprintf(stderr, "adjacency-only rseq sequence was accepted\n");
        return 0;
    }

    /* The semantic sequence exists but an entry branch skips it. */
    reset_fixture();
    start_a = (uint32_t *)(image + START_A_OFF);
    start_a[0] = encode_branch(
        (uintptr_t)&start_a[0], (uintptr_t)&start_a[9], 0);
    if (rseq_decodes()) {
        fprintf(stderr, "branch-skipped rseq sequence was accepted\n");
        return 0;
    }

    /* Both pthread_create creation paths must call the same exact helper. */
    reset_fixture();
    pthread_code = (uint32_t *)(image + PTHREAD_CREATE_OFF);
    pthread_code[1] = encode_branch(
        (uintptr_t)&pthread_code[1],
        (uintptr_t)(image + CREATE_B_OFF), 1);
    if (rseq_decodes()) {
        fprintf(stderr, "differing create_thread targets were accepted\n");
        return 0;
    }

    /* X1 must be the exact ADRP+ADD start_thread address at clone time. */
    reset_fixture();
    create_a = (uint32_t *)(image + CREATE_A_OFF);
    create_a[3] = encode_add_imm(
        3, 1, ((uintptr_t)(image + START_A_OFF)) & 0xfff);
    if (rseq_decodes()) {
        fprintf(stderr, "bad start_thread X1 provenance was accepted\n");
        return 0;
    }

    /* X2 must still derive from create_thread's incoming pthread pointer. */
    reset_fixture();
    create_a = (uint32_t *)(image + CREATE_A_OFF);
    create_a[4] = encode_mov(2, 20);
    if (rseq_decodes()) {
        fprintf(stderr, "bad pthread X2 provenance was accepted\n");
        return 0;
    }

    /* Two independently reachable witnesses are ambiguous and fail closed. */
    reset_fixture();
    start_a = (uint32_t *)(image + START_A_OFF);
    start_a[9] = UINT32_C(0xd503201f);
    emit_private_rseq(start_a + 10);
    start_a[18] = UINT32_C(0xd65f03c0);
    if (rseq_decodes()) {
        fprintf(stderr, "ambiguous reachable rseq witnesses were accepted\n");
        return 0;
    }

    /* A second valid start identity is also insufficient if create targets
     * disagree; keep this region populated to ensure the failure above did
     * not merely depend on missing code at CREATE_B. */
    reset_fixture();
    start_b = (uint32_t *)(image + START_B_OFF);
    start_b[0] = UINT32_C(0xd503201f);
    emit_private_rseq(start_b + 1);
    start_b[9] = UINT32_C(0xd65f03c0);
    emit_create((uint32_t *)(image + CREATE_B_OFF), (uintptr_t)start_b);
    pthread_code = (uint32_t *)(image + PTHREAD_CREATE_OFF);
    pthread_code[1] = encode_branch(
        (uintptr_t)&pthread_code[1],
        (uintptr_t)(image + CREATE_B_OFF), 1);
    if (rseq_decodes()) {
        fprintf(stderr, "two complete creation identities were accepted\n");
        return 0;
    }
    return 1;
}

static int test_file_backed_consumers(void)
{
    size_t pthread_size = 0;
    size_t stack_offset = 0;

    reset_fixture();
    if (!glibc_aarch64_alloca_contract(
            &obj, &pthread_size, &stack_offset) ||
        pthread_size != PTHREAD_SIZE || stack_offset != 0x6e0) {
        fprintf(stderr, "alloca positive fixture was rejected\n");
        return 0;
    }
    if (!glibc_aarch64_getattr_stack_size_contract(
            &obj, PTHREAD_SIZE, &stack_offset) ||
        stack_offset != 0x6e0) {
        fprintf(stderr, "getattr positive fixture was rejected\n");
        return 0;
    }

    phdr.p_filesz = ALLOCA_OFF + 19;
    if (glibc_aarch64_alloca_contract(
            &obj, &pthread_size, &stack_offset)) {
        fprintf(stderr, "zero-fill alloca code was accepted\n");
        return 0;
    }
    phdr.p_filesz = GETATTR_OFF + 63;
    if (glibc_aarch64_getattr_stack_size_contract(
            &obj, PTHREAD_SIZE, &stack_offset)) {
        fprintf(stderr, "zero-fill getattr code was accepted\n");
        return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--rseq") == 0)
        return test_rseq_control_flow() ? 0 : 1;
    if (argc == 2 && strcmp(argv[1], "--file-backed") == 0)
        return test_file_backed_consumers() ? 0 : 1;
    if (argc != 1) {
        fprintf(stderr, "usage: %s [--rseq|--file-backed]\n", argv[0]);
        return 2;
    }
    if (!test_rseq_control_flow() || !test_file_backed_consumers())
        return 1;
    puts("glibc-aarch64-rseq-contract-ok");
    return 0;
}
