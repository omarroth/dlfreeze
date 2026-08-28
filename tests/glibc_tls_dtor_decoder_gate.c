#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !defined(__x86_64__) && !defined(__aarch64__)
#error "glibc TLS-dtor decoder fixture needs x86-64 or AArch64"
#endif

/* Exercise the production-private decoders with independent instruction
 * fixtures.  Each negative mutates one proof witness while retaining the
 * others, so a byte-pattern scan or l_tls_modid adjacency guess cannot pass. */
#include "../src/loader.c"

static unsigned char image[4096] __attribute__((aligned(4096)));
static Elf64_Phdr load_segment;
static struct loaded_obj libc_object;

static void initialize_object(void)
{
    memset(image, 0x90, sizeof(image));
    memset(&load_segment, 0, sizeof(load_segment));
    memset(&libc_object, 0, sizeof(libc_object));
    load_segment.p_type = PT_LOAD;
    load_segment.p_flags = PF_R | PF_W | PF_X;
    load_segment.p_filesz = sizeof(image);
    load_segment.p_memsz = sizeof(image);
    libc_object.base = (uintptr_t)image;
    libc_object.phdr = &load_segment;
    libc_object.phdr_num = 1;
}

static int expect_result(const char *label, int actual, int expected)
{
    if (!!actual == !!expected)
        return 1;
    fprintf(stderr, "%s: decoded=%d expected=%d\n",
            label, !!actual, !!expected);
    return 0;
}

#if defined(__x86_64__)
static void store_i32(unsigned char *where, int64_t value)
{
    int32_t narrowed = (int32_t)value;

    memcpy(where, &narrowed, sizeof(narrowed));
}

static int run_rtld_word_pair_gate(void)
{
    unsigned char split[64];
    unsigned char vector[64];
    unsigned char bad[64];
    const uint64_t function_vaddr = UINT64_C(0x100000);
    const uint64_t got_vaddr = UINT64_C(0x120000);
    const size_t first_offset = 0x2c8;
    int ok = 1;

    memset(split, 0x90, sizeof(split));
    /* Ubuntu 24.04's __libc_early_init: exact GOT load followed by
     * independent alignment and size words, in that order. */
    memcpy(split,
           "\x48\x8b\x05\x00\x00\x00\x00"
           "\x31\xd2"
           "\x4c\x8b\x80\xd0\x02\x00\x00"
           "\x48\x8b\x88\xc8\x02\x00\x00",
           23);
    store_i32(split + 3, (int64_t)got_vaddr -
                            (int64_t)(function_vaddr + 7));
    ok &= expect_result(
        "split private-rtld word pair",
        glibc_x86_rtld_word_pair_access(
            split, sizeof(split), function_vaddr, got_vaddr,
            first_offset),
        1);

    memset(vector, 0x90, sizeof(vector));
    memcpy(vector,
           "\x48\x8b\x05\x00\x00\x00\x00"
           "\xf3\x0f\x6f\x80\xc8\x02\x00\x00",
           15);
    store_i32(vector + 3, (int64_t)got_vaddr -
                             (int64_t)(function_vaddr + 7));
    ok &= expect_result(
        "vector private-rtld word pair",
        glibc_x86_rtld_word_pair_access(
            vector, sizeof(vector), function_vaddr, got_vaddr,
            first_offset),
        1);

    memcpy(bad, vector, sizeof(bad));
    memmove(bad + 7, bad + 8, sizeof(bad) - 8);
    bad[sizeof(bad) - 1] = 0x90; /* Unprefixed 0F 6F is 8-byte MMX MOVQ. */
    ok &= expect_result(
        "MMX load is not a 16-byte private-rtld pair",
        glibc_x86_rtld_word_pair_access(
            bad, sizeof(bad), function_vaddr, got_vaddr, first_offset),
        0);

    memcpy(bad, split, sizeof(bad));
    bad[19] = 0xc0; /* size now comes from 0x2c0 */
    ok &= expect_result(
        "split pair requires the first word",
        glibc_x86_rtld_word_pair_access(
            bad, sizeof(bad), function_vaddr, got_vaddr, first_offset),
        0);

    memcpy(bad, split, sizeof(bad));
    bad[12] = 0xd8; /* alignment now comes from 0x2d8 */
    ok &= expect_result(
        "split pair requires the adjacent word",
        glibc_x86_rtld_word_pair_access(
            bad, sizeof(bad), function_vaddr, got_vaddr, first_offset),
        0);

    memcpy(bad, split, sizeof(bad));
    bad[8] = 0xc0; /* xor EAX,EAX clobbers the private-object base. */
    ok &= expect_result(
        "split pair base must remain live",
        glibc_x86_rtld_word_pair_access(
            bad, sizeof(bad), function_vaddr, got_vaddr, first_offset),
        0);

    ok &= expect_result(
        "split pair requires the exact GOT provenance",
        glibc_x86_rtld_word_pair_access(
            split, sizeof(split), function_vaddr, got_vaddr + 8,
            first_offset),
        0);
    return ok;
}

static int run_pthread_direct_field_gate(void)
{
    unsigned char code[96];
    unsigned char bad[96];
    const uint64_t function_vaddr = UINT64_C(0x100000);
    const uint64_t got_vaddr = UINT64_C(0x120000);
    int ok = 1;

    memset(code, 0x90, sizeof(code));
    /* Exact target shape: GOT -> R15, unrelated operations which preserve
     * R15, then a 32-bit stack-flags load from the private object. */
    memcpy(code,
           "\x4c\x8b\x3d\x00\x00\x00\x00"
           "\x49\xf7\xde"
           "\x4c\x21\xf2"
           "\x48\x89\x95\xe8\xfe\xff\xff"
           "\x41\x8b\xb7\x70\x10\x00\x00",
           27);
    store_i32(code + 3, (int64_t)got_vaddr -
                           (int64_t)(function_vaddr + 7));
    ok &= expect_result(
        "direct pthread private-rtld field",
        glibc_x86_direct_rtld_field(
            code, sizeof(code), function_vaddr, got_vaddr, 0x1070, 4),
        1);

    memcpy(bad, code, sizeof(bad));
    bad[9] = 0xdf; /* neg R15 instead of R14 */
    ok &= expect_result(
        "direct field base must remain live",
        glibc_x86_direct_rtld_field(
            bad, sizeof(bad), function_vaddr, got_vaddr, 0x1070, 4),
        0);

    memcpy(bad, code, sizeof(bad));
    bad[9] = 0xe6; /* MUL R14 leaves the private base in R15 intact. */
    ok &= expect_result(
        "direct field models unrelated implicit-output arithmetic",
        glibc_x86_direct_rtld_field(
            bad, sizeof(bad), function_vaddr, got_vaddr, 0x1070, 4),
        1);

    memset(bad, 0x90, sizeof(bad));
    memcpy(bad,
           "\x48\x8b\x05\x00\x00\x00\x00"
           "\x49\xf7\xe6" /* MUL R14 overwrites the private base in RAX. */
           "\x48\x8b\x80\x70\x10\x00\x00",
           17);
    store_i32(bad + 3, (int64_t)got_vaddr -
                           (int64_t)(function_vaddr + 7));
    ok &= expect_result(
        "implicit-output arithmetic clobbers a matching base",
        glibc_x86_direct_rtld_field(
            bad, sizeof(bad), function_vaddr, got_vaddr, 0x1070, 8),
        0);

    memset(bad, 0x90, sizeof(bad));
    memcpy(bad,
           "\x48\x8b\x0d\x00\x00\x00\x00"
           "\xe2\x00" /* LOOP writes RCX even when both edges rejoin. */
           "\x48\x8b\x81\x70\x10\x00\x00",
           16);
    store_i32(bad + 3, (int64_t)got_vaddr -
                           (int64_t)(function_vaddr + 7));
    ok &= expect_result(
        "LOOP clobbers an RCX private base",
        glibc_x86_direct_rtld_field(
            bad, sizeof(bad), function_vaddr, got_vaddr, 0x1070, 8),
        0);

    memset(bad, 0x90, sizeof(bad));
    memcpy(bad,
           "\x48\x8b\x0d\x00\x00\x00\x00"
           "\x48\x87\xc8" /* XCHG writes both RAX and RCX. */
           "\x48\x8b\x81\x70\x10\x00\x00",
           17);
    store_i32(bad + 3, (int64_t)got_vaddr -
                           (int64_t)(function_vaddr + 7));
    ok &= expect_result(
        "XCHG register operand clobbers the private base",
        glibc_x86_direct_rtld_field(
            bad, sizeof(bad), function_vaddr, got_vaddr, 0x1070, 8),
        0);

    memset(bad, 0x90, sizeof(bad));
    memcpy(bad,
           "\x4c\x8b\x3d\x00\x00\x00\x00"
           "\x66\x49\x0f\x7e\xff" /* MOVQ XMM7,R15. */
           "\x49\x8b\x87\x70\x10\x00\x00",
           19);
    store_i32(bad + 3, (int64_t)got_vaddr -
                           (int64_t)(function_vaddr + 7));
    ok &= expect_result(
        "MOVQ r/m GPR clobbers the private base",
        glibc_x86_direct_rtld_field(
            bad, sizeof(bad), function_vaddr, got_vaddr, 0x1070, 8),
        0);

    memset(bad, 0x90, sizeof(bad));
    memcpy(bad,
           "\x4c\x8b\x3d\x00\x00\x00\x00"
           "\x49\x0f\xc7\xf6" /* Unsupported group-9 subform. */
           "\x49\x8b\x87\x70\x10\x00\x00",
           18);
    store_i32(bad + 3, (int64_t)got_vaddr -
                           (int64_t)(function_vaddr + 7));
    ok &= expect_result(
        "operation-dependent group 9 fails closed",
        glibc_x86_direct_rtld_field(
            bad, sizeof(bad), function_vaddr, got_vaddr, 0x1070, 8),
        0);

    memset(bad, 0x90, sizeof(bad));
    memcpy(bad,
           "\x48\x8b\x05\x00\x00\x00\x00"
           "\xb4\x00" /* MOV AH,0 partially overwrites RAX. */
           "\x48\x8b\x80\x70\x10\x00\x00",
           16);
    store_i32(bad + 3, (int64_t)got_vaddr -
                           (int64_t)(function_vaddr + 7));
    ok &= expect_result(
        "legacy high-byte write clobbers its full private base",
        glibc_x86_direct_rtld_field(
            bad, sizeof(bad), function_vaddr, got_vaddr, 0x1070, 8),
        0);

    memcpy(bad, code, sizeof(bad));
    bad[23] = 0x78; /* private offset 0x1078 */
    ok &= expect_result(
        "direct field requires the exact offset",
        glibc_x86_direct_rtld_field(
            bad, sizeof(bad), function_vaddr, got_vaddr, 0x1070, 4),
        0);

    ok &= expect_result(
        "direct field requires the exact GOT provenance",
        glibc_x86_direct_rtld_field(
            code, sizeof(code), function_vaddr, got_vaddr + 8, 0x1070, 4),
        0);

    memset(bad, 0x90, sizeof(bad));
    /* The seven apparent GOT-load bytes begin inside MOVABS's immediate.
     * The later access is a real instruction, but RAX contains the immediate,
     * not the private object. */
    bad[0] = 0x48;
    bad[1] = 0xb8;
    memcpy(bad + 2, "\x48\x8b\x05\x00\x00\x00\x00\x90", 8);
    store_i32(bad + 5, (int64_t)got_vaddr -
                           (int64_t)(function_vaddr + 9));
    memcpy(bad + 10, "\x48\x8b\x80\x70\x10\x00\x00\xc3", 8);
    ok &= expect_result(
        "embedded GOT bytes are not provenance",
        glibc_x86_direct_rtld_field(
            bad, sizeof(bad), function_vaddr, got_vaddr, 0x1070, 8),
        0);

    memset(bad, 0x90, sizeof(bad));
    memcpy(bad,
           "\x48\x8b\x05\x00\x00\x00\x00"
           "\xeb\x07"
           "\x48\x8b\x80\x70\x10\x00\x00"
           "\xc3",
           17);
    store_i32(bad + 3, (int64_t)got_vaddr -
                           (int64_t)(function_vaddr + 7));
    ok &= expect_result(
        "branch-skipped field is not provenance",
        glibc_x86_direct_rtld_field(
            bad, sizeof(bad), function_vaddr, got_vaddr, 0x1070, 8),
        0);
    return ok;
}

static int run_pthread_spill_field_gate(void)
{
    unsigned char code[96];
    unsigned char bad[96];
    const uint64_t function_vaddr = UINT64_C(0x100000);
    const uint64_t got_vaddr = UINT64_C(0x120000);
    int ok = 1;

    memset(code, 0x90, sizeof(code));
    memcpy(code,
           "\x48\x8b\x35\x00\x00\x00\x00" /* GOT -> RSI */
           "\x48\x89\x75\xe0"             /* spill -0x20(RBP) */
           "\x75\x02\x90\x90"           /* two paths rejoin */
           "\x48\x8b\x4d\xe0"           /* reload -> RCX */
           "\x48\x8b\x81\xd8\x10\x00\x00"
           "\xc3",
           27);
    store_i32(code + 3, (int64_t)got_vaddr -
                           (int64_t)(function_vaddr + 7));
    ok &= expect_result(
        "reachable private base spill and reload",
        glibc_x86_pthread_rtld_field(
            code, sizeof(code), function_vaddr, got_vaddr, 0x10d8, 8),
        1);

    memset(bad, 0x90, sizeof(bad));
    memcpy(bad,
           "\x48\x8b\x35\x00\x00\x00\x00"
           "\x48\x89\x75\xe0"
           "\x48\xc7\x45\xe0\x00\x00\x00\x00"
           "\x48\x8b\x4d\xe0"
           "\x48\x8b\x81\xd8\x10\x00\x00"
           "\xc3",
           31);
    store_i32(bad + 3, (int64_t)got_vaddr -
                           (int64_t)(function_vaddr + 7));
    ok &= expect_result(
        "overwritten private base spill is rejected",
        glibc_x86_pthread_rtld_field(
            bad, sizeof(bad), function_vaddr, got_vaddr, 0x10d8, 8),
        0);

    memcpy(bad, code, sizeof(bad));
    bad[19] = 0x31;
    bad[20] = 0xc9; /* XOR ECX,ECX replaces the field-load prefix/opcode. */
    memcpy(bad + 21, "\x48\x8b\x81\xd8\x10\x00\x00\xc3", 8);
    ok &= expect_result(
        "reloaded private base must remain live",
        glibc_x86_pthread_rtld_field(
            bad, sizeof(bad), function_vaddr, got_vaddr, 0x10d8, 8),
        0);

    memset(bad, 0x90, sizeof(bad));
    memcpy(bad,
           "\x48\x8b\x35\x00\x00\x00\x00"
           "\x48\x89\x75\xe0"
           "\xeb\x0b"
           "\x48\x8b\x4d\xe0"
           "\x48\x8b\x81\xd8\x10\x00\x00"
           "\xc3",
           24);
    store_i32(bad + 3, (int64_t)got_vaddr -
                           (int64_t)(function_vaddr + 7));
    ok &= expect_result(
        "branch-skipped spill reload is rejected",
        glibc_x86_pthread_rtld_field(
            bad, sizeof(bad), function_vaddr, got_vaddr, 0x10d8, 8),
        0);
    return ok;
}

static int run_decoder_gate(void)
{
    unsigned char *registration = image + 0x100;
    unsigned char *destruction = image + 0x200;
    unsigned char registration_bad[128];
    unsigned char destruction_bad[64];
    const size_t registration_length = 96;
    const size_t destruction_length = 32;
    const size_t registration_atomic = 5;
    const size_t destruction_atomic = 4;
    const size_t counter_offset = 0x498;
    size_t decoded = 0;
    int ok = 1;

    /* fs:[thread-local map cache] -> rax; lock addq $1, counter(rax). */
    memcpy(registration,
           "\x64\x49\x8b\x04\x24"
           "\xf0\x48\x83\x80\x00\x00\x00\x00\x01",
           14);
    memcpy(registration + registration_atomic + 4,
           &counter_offset, sizeof(uint32_t));

    /* The later _dl_find_dso_for_object-shaped fallback tests RAX and both
     * selection paths rejoin at the atomic increment. */
    registration[32] = 0xe8;
    store_i32(registration + 33,
              (image + 0x380) - (registration + 37));
    memcpy(registration + 37, "\x48\x85\xc0\x74\x02\x90\x90\xe9", 8);
    store_i32(registration + 45,
              (registration + registration_atomic) -
                  (registration + 49));
    image[0x380] = 0xc3;

    /* mov 16(node), rax; lock subq $1, counter(rax); loop. */
    memcpy(destruction,
           "\x48\x8b\x43\x10"
           "\xf0\x48\x83\xa8\x00\x00\x00\x00\x01",
           13);
    memcpy(destruction + destruction_atomic + 4,
           &counter_offset, sizeof(uint32_t));
    destruction[13] = 0x75;
    destruction[14] = (unsigned char)(0 - 15);

    ok &= expect_result(
        "valid paired x86-64 counter",
        glibc_tls_dtor_counter_from_code(
            &libc_object, registration, registration_length,
            destruction, destruction_length, &decoded) &&
            decoded == counter_offset,
        1);

    memcpy(registration_bad, registration, registration_length);
    registration_bad[registration_atomic + 8] = 2;
    ok &= expect_result(
        "increment must be exactly +1",
        glibc_tls_dtor_counter_from_code(
            &libc_object, registration_bad, registration_length,
            destruction, destruction_length, &decoded),
        0);

    memcpy(registration_bad, registration, registration_length);
    registration_bad[0] = 0x90;
    ok &= expect_result(
        "increment map must come from the thread-local cache",
        glibc_tls_dtor_counter_from_code(
            &libc_object, registration_bad, registration_length,
            destruction, destruction_length, &decoded),
        0);

    memcpy(registration_bad, registration, registration_length);
    registration_bad[44] = 0x90;
    ok &= expect_result(
        "DSO fallback must rejoin the increment",
        glibc_tls_dtor_counter_from_code(
            &libc_object, registration_bad, registration_length,
            destruction, destruction_length, &decoded),
        0);

    memcpy(destruction_bad, destruction, destruction_length);
    destruction_bad[3] = 0x18;
    ok &= expect_result(
        "decrement map must come from node offset 16",
        glibc_tls_dtor_counter_from_code(
            &libc_object, registration, registration_length,
            destruction_bad, destruction_length, &decoded),
        0);

    memcpy(destruction_bad, destruction, destruction_length);
    destruction_bad[destruction_atomic + 8] = 2;
    ok &= expect_result(
        "decrement must be exactly -1",
        glibc_tls_dtor_counter_from_code(
            &libc_object, registration, registration_length,
            destruction_bad, destruction_length, &decoded),
        0);

    memcpy(destruction_bad, destruction, destruction_length);
    destruction_bad[13] = 0x90;
    ok &= expect_result(
        "destructor traversal must retain its loop",
        glibc_tls_dtor_counter_from_code(
            &libc_object, registration, registration_length,
            destruction_bad, destruction_length, &decoded),
        0);

    memcpy(destruction_bad, destruction, destruction_length);
    {
        uint32_t mismatched = (uint32_t)counter_offset + 8;

        memcpy(destruction_bad + destruction_atomic + 4,
               &mismatched, sizeof(mismatched));
    }
    ok &= expect_result(
        "increment and decrement offsets must agree",
        glibc_tls_dtor_counter_from_code(
            &libc_object, registration, registration_length,
            destruction_bad, destruction_length, &decoded),
        0);
    return ok;
}
#elif defined(__aarch64__)
static uint32_t direct_branch(uint32_t opcode, uintptr_t from,
                              uintptr_t to)
{
    int64_t words = ((int64_t)to - (int64_t)from) / 4;

    return opcode | ((uint32_t)words & UINT32_C(0x03ffffff));
}

static uint32_t compare_branch(uint32_t opcode, size_t from, size_t to,
                               unsigned int reg)
{
    int64_t words = ((int64_t)to - (int64_t)from) / 4;

    return opcode | (((uint32_t)words & UINT32_C(0x7ffff)) << 5) | reg;
}

static uint32_t add_x1(size_t offset)
{
    return UINT32_C(0x91000021) | ((uint32_t)offset << 10);
}

static uint32_t private_adrp(uint64_t pc, uint64_t target,
                             unsigned int destination)
{
    int64_t pages =
        ((int64_t)(target & ~UINT64_C(0xfff)) -
         (int64_t)(pc & ~UINT64_C(0xfff))) /
        INT64_C(4096);
    uint32_t immediate = (uint32_t)pages & UINT32_C(0x1fffff);

    return UINT32_C(0x90000000) |
           ((immediate & 3U) << 29) |
           (((immediate >> 2) & UINT32_C(0x7ffff)) << 5) |
           destination;
}

static uint32_t private_got_load(unsigned int destination,
                                 unsigned int page_register,
                                 uint64_t got_vaddr)
{
    return UINT32_C(0xf9400000) |
           (((uint32_t)(got_vaddr & UINT64_C(0xfff)) / 8U) << 10) |
           (page_register << 5) | destination;
}

static uint32_t private_field_load(unsigned int destination,
                                   unsigned int base, size_t offset,
                                   size_t width)
{
    uint32_t opcode = width == 8 ? UINT32_C(0xf9400000)
                                 : UINT32_C(0xb9400000);

    return opcode | ((uint32_t)(offset / width) << 10) |
           (base << 5) | destination;
}

static int run_rtld_field_provenance_gate(void)
{
    uint32_t code[24];
    uint32_t bad[24];
    const uint64_t function_vaddr = UINT64_C(0x100000);
    const uint64_t got_vaddr = UINT64_C(0x120040);
    int ok = 1;

    for (size_t i = 0; i < 24; i++)
        code[i] = UINT32_C(0xd503201f);
    code[0] = private_adrp(function_vaddr, got_vaddr, 21);
    code[1] = private_got_load(21, 21, got_vaddr);
    code[2] = UINT32_C(0x94000000); /* BL preserves callee-saved X21. */
    code[3] = private_field_load(0, 21, 0x1070, 4);
    code[4] = UINT32_C(0xd65f03c0);
    ok &= expect_result(
        "AArch64 reachable callee-saved private field",
        glibc_aarch64_pthread_rtld_field(
            (const uint8_t *)code, sizeof(code), function_vaddr,
            got_vaddr, 0x1070, 4),
        1);

    memcpy(bad, code, sizeof(bad));
    bad[0] = private_adrp(function_vaddr, got_vaddr, 9);
    bad[1] = private_got_load(9, 9, got_vaddr);
    bad[3] = private_field_load(0, 9, 0x1070, 4);
    ok &= expect_result(
        "AArch64 call clobbers caller-saved private base",
        glibc_aarch64_pthread_rtld_field(
            (const uint8_t *)bad, sizeof(bad), function_vaddr,
            got_vaddr, 0x1070, 4),
        0);

    memcpy(bad, code, sizeof(bad));
    bad[2] = UINT32_C(0xaa1f03f5); /* MOV X21,XZR. */
    ok &= expect_result(
        "AArch64 private base must remain live",
        glibc_aarch64_pthread_rtld_field(
            (const uint8_t *)bad, sizeof(bad), function_vaddr,
            got_vaddr, 0x1070, 4),
        0);

    memcpy(bad, code, sizeof(bad));
    bad[2] = UINT32_C(0x14000002); /* B from word 2 to word 4. */
    ok &= expect_result(
        "AArch64 branch-skipped field is rejected",
        glibc_aarch64_pthread_rtld_field(
            (const uint8_t *)bad, sizeof(bad), function_vaddr,
            got_vaddr, 0x1070, 4),
        0);

    for (size_t i = 0; i < 24; i++)
        bad[i] = UINT32_C(0xd503201f);
    bad[0] = UINT32_C(0x14000004); /* Skip the entire apparent witness. */
    bad[1] = private_adrp(function_vaddr + 4, got_vaddr, 21);
    bad[2] = private_got_load(21, 21, got_vaddr);
    bad[3] = private_field_load(0, 21, 0x1070, 4);
    bad[4] = UINT32_C(0xd65f03c0);
    ok &= expect_result(
        "AArch64 unreachable GOT pair is rejected",
        glibc_aarch64_pthread_rtld_field(
            (const uint8_t *)bad, sizeof(bad), function_vaddr,
            got_vaddr, 0x1070, 4),
        0);

    for (size_t i = 0; i < 24; i++)
        bad[i] = UINT32_C(0xd503201f);
    bad[0] = private_adrp(function_vaddr, got_vaddr, 21);
    bad[1] = private_got_load(21, 21, got_vaddr);
    bad[2] = UINT32_C(0xf98012a0); /* PRFM PLDL1KEEP,[X21,#0x20]. */
    bad[3] = UINT32_C(0xd65f03c0);
    ok &= expect_result(
        "AArch64 prefetch has no pointer-field width",
        glibc_aarch64_pthread_rtld_field(
            (const uint8_t *)bad, sizeof(bad), function_vaddr,
            got_vaddr, 0x20, 8),
        0);
    return ok;
}

static int run_rtld_word_pair_gate(void)
{
    uint32_t code[16];
    uint32_t bad[16];
    const uint64_t function_vaddr = UINT64_C(0x100000);
    const uint64_t got_vaddr = UINT64_C(0x120040);
    const size_t first_offset = 0x2c8;
    int ok = 1;

    for (size_t i = 0; i < 16; i++)
        code[i] = UINT32_C(0xd503201f);
    code[0] = private_adrp(function_vaddr, got_vaddr, 21);
    code[1] = private_got_load(21, 21, got_vaddr);
    code[2] = private_field_load(0, 21, first_offset, 8);
    code[3] = UINT32_C(0xb4000040); /* CBZ X0 from word 3 to word 5. */
    code[4] = UINT32_C(0xd503201f);
    code[5] = private_field_load(1, 21, first_offset + 8, 8);
    code[6] = UINT32_C(0xd65f03c0);
    ok &= expect_result(
        "AArch64 scalar private-rtld word pair",
        glibc_aarch64_rtld_word_pair_access(
            (const uint8_t *)code, sizeof(code), function_vaddr,
            got_vaddr, first_offset),
        1);

    for (size_t i = 0; i < 16; i++)
        bad[i] = UINT32_C(0xd503201f);
    bad[0] = private_adrp(function_vaddr, got_vaddr, 21);
    bad[1] = private_got_load(21, 21, got_vaddr);
    bad[2] = UINT32_C(0xb4000060); /* Choose one mutually exclusive arm. */
    bad[3] = private_field_load(0, 21, first_offset, 8);
    bad[4] = UINT32_C(0x14000003);
    bad[5] = private_field_load(1, 21, first_offset + 8, 8);
    bad[6] = UINT32_C(0x14000001);
    bad[7] = UINT32_C(0xd65f03c0);
    ok &= expect_result(
        "AArch64 pair words must share one path",
        glibc_aarch64_rtld_word_pair_access(
            (const uint8_t *)bad, sizeof(bad), function_vaddr,
            got_vaddr, first_offset),
        0);

    memcpy(bad, code, sizeof(bad));
    bad[3] = UINT32_C(0xaa1f03f5); /* Clobber X21 between words. */
    ok &= expect_result(
        "AArch64 pair base must remain live",
        glibc_aarch64_rtld_word_pair_access(
            (const uint8_t *)bad, sizeof(bad), function_vaddr,
            got_vaddr, first_offset),
        0);

    for (size_t i = 0; i < 16; i++)
        bad[i] = UINT32_C(0xd503201f);
    bad[0] = private_adrp(function_vaddr, got_vaddr, 21);
    bad[1] = private_got_load(21, 21, got_vaddr);
    /* LDP Q0,Q1,[X21,#0x40].  Interpreting SIMD scale as integer scale
     * would incorrectly report a 16-byte pair at 0x20. */
    bad[2] = UINT32_C(0xad4206a0);
    bad[3] = UINT32_C(0xd65f03c0);
    ok &= expect_result(
        "AArch64 SIMD pair is not integer field evidence",
        glibc_aarch64_rtld_word_pair_access(
            (const uint8_t *)bad, sizeof(bad), function_vaddr,
            got_vaddr, 0x20),
        0);

    for (size_t i = 0; i < 16; i++)
        bad[i] = UINT32_C(0xd503201f);
    bad[0] = private_adrp(function_vaddr, got_vaddr, 21);
    bad[1] = private_got_load(21, 21, got_vaddr);
    /* LDP X0,X1,[X21],#0x20 accesses offset zero; the immediate is only
     * post-index writeback and cannot witness a field at 0x20. */
    bad[2] = UINT32_C(0xa8c206a0);
    bad[3] = UINT32_C(0xd65f03c0);
    ok &= expect_result(
        "AArch64 post-index immediate is not a field offset",
        glibc_aarch64_rtld_word_pair_access(
            (const uint8_t *)bad, sizeof(bad), function_vaddr,
            got_vaddr, 0x20),
        0);
    return ok;
}

static void initialize_atomic_helper(uint32_t *helper, int release)
{
    uintptr_t page = (uintptr_t)image & ~(uintptr_t)0xfff;
    size_t feature_offset = (uintptr_t)(image + 0x3f0) - page;

    helper[0] = UINT32_C(0xd503245f);
    helper[1] = UINT32_C(0x90000010);
    helper[2] = UINT32_C(0x39400210) |
                ((uint32_t)feature_offset << 10);
    helper[3] = UINT32_C(0x34000070);
    helper[4] = release ? UINT32_C(0xf8600020)
                        : UINT32_C(0xf8200020);
    helper[5] = UINT32_C(0xd65f03c0);
    helper[6] = UINT32_C(0xaa0003f0);
    helper[7] = UINT32_C(0xc85f7c20);
    helper[8] = UINT32_C(0x8b100011);
    helper[9] = release ? UINT32_C(0xc80ffc31)
                        : UINT32_C(0xc80f7c31);
    helper[10] = UINT32_C(0x35ffffaf);
    helper[11] = UINT32_C(0xd65f03c0);
}

static int run_decoder_gate(void)
{
    uint32_t *registration = (uint32_t *)(void *)(image + 0x100);
    uint32_t *destruction = (uint32_t *)(void *)(image + 0x200);
    uint32_t *relaxed_helper = (uint32_t *)(void *)(image + 0x300);
    uint32_t *release_helper = (uint32_t *)(void *)(image + 0x340);
    uint32_t registration_bad[16];
    uint32_t destruction_bad[8];
    uint32_t relaxed_bad[12];
    uint32_t release_bad[12];
    const size_t registration_count = 9;
    const size_t destruction_count = 6;
    const size_t counter_offset = 0x498;
    size_t decoded = 0;
    int ok = 1;

    initialize_atomic_helper(relaxed_helper, 0);
    initialize_atomic_helper(release_helper, 1);
    *(uint32_t *)(void *)(image + 0x380) = UINT32_C(0xd65f03c0);

    registration[0] = UINT32_C(0xf9400681); /* ldr x1, [x20, #8] */
    registration[1] = add_x1(counter_offset);
    registration[2] = UINT32_C(0xd2800020); /* mov x0, #1 */
    registration[3] = direct_branch(
        UINT32_C(0x94000000), (uintptr_t)&registration[3],
        (uintptr_t)relaxed_helper);
    registration[4] = UINT32_C(0xd503201f);
    registration[5] = direct_branch(
        UINT32_C(0x94000000), (uintptr_t)&registration[5],
        (uintptr_t)(image + 0x380));
    registration[6] = UINT32_C(0xaa0003e1); /* mov x1, x0 */
    registration[7] = UINT32_C(0xb4000040); /* cbz x0, +8 */
    registration[8] = direct_branch(
        UINT32_C(0x14000000), (uintptr_t)&registration[8],
        (uintptr_t)&registration[1]);

    destruction[0] = UINT32_C(0xf9400a61); /* ldr x1, [x19, #16] */
    destruction[1] = UINT32_C(0x92800000); /* mov x0, #-1 */
    destruction[2] = add_x1(counter_offset);
    destruction[3] = direct_branch(
        UINT32_C(0x94000000), (uintptr_t)&destruction[3],
        (uintptr_t)release_helper);
    destruction[4] = UINT32_C(0xd503201f);
    destruction[5] = compare_branch(
        UINT32_C(0xb5000000), 5 * sizeof(uint32_t), 0, 19);

    ok &= expect_result(
        "valid paired AArch64 counter",
        glibc_tls_dtor_counter_from_code(
            &libc_object, (const uint8_t *)registration,
            registration_count * sizeof(*registration),
            (const uint8_t *)destruction,
            destruction_count * sizeof(*destruction), &decoded) &&
            decoded == counter_offset,
        1);

    memcpy(registration_bad, registration,
           registration_count * sizeof(*registration));
    registration_bad[2] = UINT32_C(0xd2800040); /* mov x0, #2 */
    ok &= expect_result(
        "increment must be exactly +1",
        glibc_tls_dtor_counter_from_code(
            &libc_object, (const uint8_t *)registration_bad,
            registration_count * sizeof(*registration_bad),
            (const uint8_t *)destruction,
            destruction_count * sizeof(*destruction), &decoded),
        0);

    memcpy(registration_bad, registration,
           registration_count * sizeof(*registration));
    registration_bad[8] = UINT32_C(0xd503201f);
    ok &= expect_result(
        "DSO fallback must rejoin the increment",
        glibc_tls_dtor_counter_from_code(
            &libc_object, (const uint8_t *)registration_bad,
            registration_count * sizeof(*registration_bad),
            (const uint8_t *)destruction,
            destruction_count * sizeof(*destruction), &decoded),
        0);

    memcpy(registration_bad, registration,
           registration_count * sizeof(*registration));
    registration_bad[6] = UINT32_C(0xaa0003e2); /* mov x2, x0 */
    ok &= expect_result(
        "fallback result must select x1",
        glibc_tls_dtor_counter_from_code(
            &libc_object, (const uint8_t *)registration_bad,
            registration_count * sizeof(*registration_bad),
            (const uint8_t *)destruction,
            destruction_count * sizeof(*destruction), &decoded),
        0);

    memcpy(relaxed_bad, relaxed_helper, sizeof(relaxed_bad));
    relaxed_helper[4] = UINT32_C(0xd503201f);
    ok &= expect_result(
        "increment helper must perform atomic add",
        glibc_tls_dtor_counter_from_code(
            &libc_object, (const uint8_t *)registration,
            registration_count * sizeof(*registration),
            (const uint8_t *)destruction,
            destruction_count * sizeof(*destruction), &decoded),
        0);
    memcpy(relaxed_helper, relaxed_bad, sizeof(relaxed_bad));

    memcpy(destruction_bad, destruction,
           destruction_count * sizeof(*destruction));
    destruction_bad[0] = UINT32_C(0xf9400e61); /* offset 24 */
    ok &= expect_result(
        "decrement map must come from node offset 16",
        glibc_tls_dtor_counter_from_code(
            &libc_object, (const uint8_t *)registration,
            registration_count * sizeof(*registration),
            (const uint8_t *)destruction_bad,
            destruction_count * sizeof(*destruction_bad), &decoded),
        0);

    memcpy(release_bad, release_helper, sizeof(release_bad));
    release_helper[4] = UINT32_C(0xf8200020);
    ok &= expect_result(
        "decrement helper must retain release ordering",
        glibc_tls_dtor_counter_from_code(
            &libc_object, (const uint8_t *)registration,
            registration_count * sizeof(*registration),
            (const uint8_t *)destruction,
            destruction_count * sizeof(*destruction), &decoded),
        0);
    memcpy(release_helper, release_bad, sizeof(release_bad));

    memcpy(destruction_bad, destruction,
           destruction_count * sizeof(*destruction));
    destruction_bad[5] = UINT32_C(0xd503201f);
    ok &= expect_result(
        "destructor traversal must retain its loop",
        glibc_tls_dtor_counter_from_code(
            &libc_object, (const uint8_t *)registration,
            registration_count * sizeof(*registration),
            (const uint8_t *)destruction_bad,
            destruction_count * sizeof(*destruction_bad), &decoded),
        0);

    memcpy(destruction_bad, destruction,
           destruction_count * sizeof(*destruction));
    destruction_bad[2] = add_x1(counter_offset + 8);
    ok &= expect_result(
        "increment and decrement offsets must agree",
        glibc_tls_dtor_counter_from_code(
            &libc_object, (const uint8_t *)registration,
            registration_count * sizeof(*registration),
            (const uint8_t *)destruction_bad,
            destruction_count * sizeof(*destruction_bad), &decoded),
        0);
    return ok;
}
#endif

int main(void)
{
    initialize_object();
#if defined(__x86_64__)
    return run_decoder_gate() && run_rtld_word_pair_gate() &&
           run_pthread_direct_field_gate() &&
           run_pthread_spill_field_gate() ? 0 : 1;
#else
    return run_decoder_gate() && run_rtld_field_provenance_gate() &&
           run_rtld_word_pair_gate() ? 0 : 1;
#endif
}
