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
    /* Fedora 46 performs unrelated flag normalization with logical-immediate
     * and conditional-select forms before consuming the stack fields. */
    getattr_code[1] = UINT32_C(0x32000020); /* orr w0,w1,#1 */
    getattr_code[2] = UINT32_C(0x1a810000); /* csel w0,w0,w1,eq */
    getattr_code[3] = encode_ldr64(1, 19, 0x6d8);
    getattr_code[4] = UINT32_C(0xb4000041); /* cbz x1,+8 */
    getattr_code[5] = encode_ldr64(2, 19, 0x6e0);
    getattr_code[6] = encode_ldr64(3, 19, 0x6e8);
    getattr_code[7] = UINT32_C(0x8b020024); /* add x4,x1,x2 */
    getattr_code[8] = UINT32_C(0xcb030045); /* sub x5,x2,x3 */
    for (size_t i = 9; i < 15; i++)
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
    uint32_t *getattr_code;
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

    getattr_code = (uint32_t *)(image + GETATTR_OFF);
    getattr_code[2] = UINT32_C(0x9a810013); /* csel x19,x0,x1,eq */
    if (glibc_aarch64_getattr_stack_size_contract(
            &obj, PTHREAD_SIZE, &stack_offset)) {
        fprintf(stderr, "getattr base-register clobber was accepted\n");
        return 0;
    }
    reset_fixture();

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

static void emit_initial_thread_completion(uint32_t *code, size_t offset)
{
    memset(code, 0, 8 * sizeof(*code));
    code[0] = UINT32_C(0xd503233f); /* paciasp */
    code[1] = UINT32_C(0xa9bf7bfd); /* stp x29,x30,[sp,#-16]! */
    code[2] = encode_add_imm(2, 0, offset);
    /* A function prologue may establish its frame after computing the
     * private pthread address.  This exact Fedora 46 shape is safe because
     * it does not overwrite X2 or cross a control-flow edge. */
    code[3] = UINT32_C(0x910003fd); /* mov x29,sp */
    code[4] = UINT32_C(0x88dffc42); /* ldar w2,[x2] */
    code[5] = UINT32_C(0x34000042); /* cbz w2,+8 */
    code[6] = UINT32_C(0xd503201f); /* nop */
    code[7] = UINT32_C(0xd65f03c0); /* ret */
}

static int test_initial_thread_completion_word(void)
{
    uint32_t code[8];
    size_t offset = 0;

    emit_initial_thread_completion(code, 0x428);
    if (!glibc_aarch64_completion_word(
            (const uint8_t *)code, sizeof(code), &offset) ||
        offset != 0x428) {
        fprintf(stderr, "frame-setup completion witness was rejected\n");
        return 0;
    }

    /* The permitted prologue gap is a provenance proof, not an arbitrary
     * wildcard: overwriting the derived address must invalidate it. */
    emit_initial_thread_completion(code, 0x428);
    code[3] = encode_add_imm(2, 3, 0); /* mov x2,x3 */
    if (glibc_aarch64_completion_word(
            (const uint8_t *)code, sizeof(code), &offset)) {
        fprintf(stderr, "address-clobbering completion gap was accepted\n");
        return 0;
    }

    /* Nor may a match be assembled across a basic-block edge. */
    emit_initial_thread_completion(code, 0x428);
    code[3] = UINT32_C(0x14000001); /* b +4 */
    if (glibc_aarch64_completion_word(
            (const uint8_t *)code, sizeof(code), &offset)) {
        fprintf(stderr, "branching completion gap was accepted\n");
        return 0;
    }
    return 1;
}

static int tunable_scalar_stream_decodes(uint32_t *code, size_t count)
{
    return target_tunable_accessor_control_flow_safe(
        &obj, (const unsigned char *)code,
        count * sizeof(*code));
}

static int test_tunable_scalar_control_flow(void)
{
    uint32_t code[] = {
        UINT32_C(0xd503245f), /* bti c */
        UINT32_C(0x2a0003e5), /* mov w5,w0 */
        UINT32_C(0xd37c7c03), /* ubfiz x3,x0,#4,#32 */
        UINT32_C(0xd503233f), /* paciasp */
        UINT32_C(0xcb204021), /* sub x1,x1,w0,uxtw */
        UINT32_C(0x52800f03), /* mov w3,#120 */
        UINT32_C(0x9ba11000), /* umaddl x0,w0,w1,x4 */
        UINT32_C(0xd50323bf), /* autiasp */
        UINT32_C(0xd65f03c0), /* ret */
    };
    uint32_t saved;

    reset_fixture();
    if (!tunable_scalar_stream_decodes(
            code, sizeof(code) / sizeof(code[0]))) {
        fprintf(stderr, "Fedora 46 tunable scalar stream was rejected\n");
        return 0;
    }

    /* Each newly admitted arithmetic class still reports Rd precisely;
     * overwriting callback argument X2 must fail closed. */
    saved = code[4];
    code[4] = (code[4] & ~UINT32_C(31)) | UINT32_C(2);
    if (tunable_scalar_stream_decodes(
            code, sizeof(code) / sizeof(code[0]))) {
        fprintf(stderr, "extended arithmetic callback clobber accepted\n");
        return 0;
    }
    code[4] = saved;

    saved = code[5];
    code[5] = (code[5] & ~UINT32_C(31)) | UINT32_C(2);
    if (tunable_scalar_stream_decodes(
            code, sizeof(code) / sizeof(code[0]))) {
        fprintf(stderr, "wide-move callback clobber accepted\n");
        return 0;
    }
    code[5] = saved;

    saved = code[6];
    code[6] = (code[6] & ~UINT32_C(31)) | UINT32_C(2);
    if (tunable_scalar_stream_decodes(
            code, sizeof(code) / sizeof(code[0]))) {
        fprintf(stderr, "multiply-add callback clobber accepted\n");
        return 0;
    }
    code[6] = saved;
    if (!tunable_scalar_stream_decodes(
            code, sizeof(code) / sizeof(code[0])))
        return 0;

    {
        uint32_t callback_code[] = {
            UINT32_C(0xd503245f), /* bti c */
            UINT32_C(0xaa0203f0), /* mov x16,x2 */
            UINT32_C(0x9ba11000), /* umaddl x0,w0,w1,x4 */
            UINT32_C(0x91012000), /* add x0,x0,#0x48 */
            UINT32_C(0xd61f0200), /* br x16 */
        };

        if (!tunable_scalar_stream_decodes(
                callback_code,
                sizeof(callback_code) / sizeof(callback_code[0]))) {
            fprintf(stderr, "live callback gap was rejected\n");
            return 0;
        }

        callback_code[2] = UINT32_C(0xd2800010); /* mov x16,#0 */
        if (tunable_scalar_stream_decodes(
                callback_code,
                sizeof(callback_code) / sizeof(callback_code[0]))) {
            fprintf(stderr, "callback-register clobber was accepted\n");
            return 0;
        }

        callback_code[2] = UINT32_C(0x9ba11000);
        callback_code[0] = UINT32_C(0x14000002); /* b to after MOV */
        if (tunable_scalar_stream_decodes(
                callback_code,
                sizeof(callback_code) / sizeof(callback_code[0]))) {
            fprintf(stderr, "callback-producer bypass was accepted\n");
            return 0;
        }
    }
    return 1;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--rseq") == 0)
        return test_rseq_control_flow() ? 0 : 1;
    if (argc == 2 && strcmp(argv[1], "--file-backed") == 0)
        return test_file_backed_consumers() ? 0 : 1;
    if (argc == 2 && strcmp(argv[1], "--initial-thread") == 0)
        return test_initial_thread_completion_word() ? 0 : 1;
    if (argc == 2 && strcmp(argv[1], "--tunable") == 0)
        return test_tunable_scalar_control_flow() ? 0 : 1;
    if (argc != 1) {
        fprintf(stderr,
                "usage: %s [--rseq|--file-backed|--initial-thread|--tunable]\n",
                argv[0]);
        return 2;
    }
    if (!test_rseq_control_flow() || !test_file_backed_consumers() ||
        !test_initial_thread_completion_word() ||
        !test_tunable_scalar_control_flow())
        return 1;
    puts("glibc-aarch64-rseq-contract-ok");
    return 0;
}
