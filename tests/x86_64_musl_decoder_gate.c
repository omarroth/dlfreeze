#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !defined(__x86_64__)
#error "this decoder fixture is x86-64-specific"
#endif

/* Keep the production decoder private while testing the exact instruction
 * forms emitted by supported musl toolchains. */
#include "../src/loader.c"

static const struct dlfrz_musl_layout *find_layout(unsigned int minor,
                                                   unsigned int patch)
{
    for (size_t i = 0;
         i < sizeof(dlfrz_musl_layouts) / sizeof(dlfrz_musl_layouts[0]); i++) {
        const struct dlfrz_musl_layout *layout = &dlfrz_musl_layouts[i];

        if (layout->machine == EM_X86_64 && layout->minor == minor &&
            layout->patch == patch)
            return layout;
    }
    return NULL;
}

static void set_disp32(uint8_t *code, size_t pos, size_t next,
                       uintptr_t target)
{
    int64_t delta = (int64_t)target - (int64_t)(uintptr_t)(code + next);
    int32_t disp = (int32_t)delta;

    memcpy(code + pos, &disp, sizeof(disp));
}

static void patch_119_targets(uint8_t *code, uintptr_t candidate,
                              const struct dlfrz_musl_layout *layout)
{
    set_disp32(code, 2, 6, candidate + layout->libc_can_do_threads);
    set_disp32(code, 77, 81, candidate + layout->libc_threaded);
}

static void patch_124_targets(uint8_t *code, uintptr_t candidate,
                              const struct dlfrz_musl_layout *layout)
{
    set_disp32(code, 3, 7, candidate + layout->libc_can_do_threads);
    set_disp32(code, 76, 80, candidate + layout->libc_threaded);
}

static int expect_decode(const char *label, struct loaded_obj *obj,
                         const uint8_t *code, size_t len,
                         uintptr_t expected)
{
    uintptr_t decoded = 0;
    int ok = decode_x86_64_musl_libc_addr(obj, code, len, &decoded);

    if (ok != (expected != 0) || (ok && decoded != expected)) {
        fprintf(stderr, "%s: decoded=%d address=%p expected=%p\n", label,
                ok, (void *)decoded, (void *)expected);
        return 0;
    }
    return 1;
}

int main(void)
{
    static uint8_t image[2048];
    /* Ubuntu 18.04 musl 1.1.19 pthread_create, from the first private flag
     * load through the second zero branch.  RIP displacements are patched
     * below to point into the synthetic loaded object. */
    static const uint8_t old119_template[] = {
        0x8b, 0x3d, 0, 0, 0, 0,
        0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0,
        0x48, 0x89, 0x44, 0x24, 0x78,
        0x31, 0xc0,
        0x48, 0x89, 0x14, 0x24,
        0x48, 0x89, 0x4c, 0x24, 0x08,
        0x85, 0xff,
        0x48, 0xc7, 0x44, 0x24, 0x70, 0, 0, 0, 0,
        0x0f, 0x29, 0x44, 0x24, 0x40,
        0x0f, 0x29, 0x44, 0x24, 0x50,
        0x0f, 0x29, 0x44, 0x24, 0x60,
        0x0f, 0x84, 0, 0, 0, 0,
        0x48, 0x89, 0xf5,
        0x64, 0x4c, 0x8b, 0x2c, 0x25, 0, 0, 0, 0,
        0x8b, 0x35, 0, 0, 0, 0,
        0x85, 0xf6,
        0x0f, 0x84, 0, 0, 0, 0,
    };
    /* Ubuntu 20.04 musl 1.1.24 emits the same data flow with high registers
     * and performs a thread-pointer load before testing the second flag. */
    static const uint8_t old124_template[] = {
        0x44, 0x8b, 0x0d, 0, 0, 0, 0,
        0x48, 0x89, 0x7c, 0x24, 0x10,
        0x48, 0x89, 0x14, 0x24,
        0x48, 0x89, 0x4c, 0x24, 0x08,
        0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0,
        0x48, 0x89, 0x84, 0x24, 0xf8, 0, 0, 0,
        0x31, 0xc0,
        0x0f, 0x29, 0x44, 0x24, 0x30,
        0x48, 0xc7, 0x44, 0x24, 0x60, 0, 0, 0, 0,
        0x0f, 0x29, 0x44, 0x24, 0x40,
        0x0f, 0x29, 0x44, 0x24, 0x50,
        0x45, 0x85, 0xc9,
        0x0f, 0x84, 0, 0, 0, 0,
        0x44, 0x8b, 0x05, 0, 0, 0, 0,
        0x48, 0x89, 0xf3,
        0x64, 0x4c, 0x8b, 0x34, 0x25, 0, 0, 0, 0,
        0x45, 0x85, 0xc0,
        0x0f, 0x84, 0, 0, 0, 0,
    };
    static uint8_t old119[sizeof(old119_template)];
    static uint8_t old124[sizeof(old124_template)];
    static uint8_t mutated[128];
    Elf64_Phdr phdr = {
        .p_type = PT_LOAD,
        .p_flags = PF_R | PF_W,
        .p_vaddr = 0,
        .p_filesz = sizeof(image),
        .p_memsz = sizeof(image),
    };
    struct loaded_obj obj = {
        .base = (uintptr_t)image,
        .phdr = &phdr,
        .phdr_num = 1,
    };
    const struct dlfrz_musl_layout *layout119 = find_layout(1, 19);
    const struct dlfrz_musl_layout *layout124 = find_layout(1, 24);
    uintptr_t candidate = (uintptr_t)image + 1024;

    if (!layout119 || !layout124) {
        fprintf(stderr, "supported old-musl layouts are missing\n");
        return 1;
    }

    memcpy(old119, old119_template, sizeof(old119));
    patch_119_targets(old119, candidate, layout119);
    g_musl_layout = layout119;
    if (!expect_decode("musl 1.1.19 register flags", &obj, old119,
                       sizeof(old119), candidate))
        return 1;

    memcpy(old124, old124_template, sizeof(old124));
    patch_124_targets(old124, candidate, layout124);
    g_musl_layout = layout124;
    if (!expect_decode("musl 1.1.24 register flags", &obj, old124,
                       sizeof(old124), candidate))
        return 1;

    memset(mutated, 0x90, sizeof(mutated));
    memcpy(mutated, old124, sizeof(old124));
    patch_124_targets(mutated, candidate, layout124);
    mutated[66] = 0xc0; /* test r8d instead of the loaded r9d */
    if (!expect_decode("wrong first test register", &obj, mutated,
                       sizeof(old124), 0))
        return 1;

    memcpy(mutated, old124, sizeof(old124));
    patch_124_targets(mutated, candidate, layout124);
    mutated[68] = 0x85; /* jne instead of the required zero branch */
    if (!expect_decode("wrong first branch", &obj, mutated,
                       sizeof(old124), 0))
        return 1;

    memcpy(mutated, old124, sizeof(old124));
    patch_124_targets(mutated, candidate, layout124);
    mutated[45] = 0x41; /* mov $0, %r9d between load and test */
    mutated[46] = 0xb9;
    memset(mutated + 47, 0, 4);
    memset(mutated + 51, 0x90, 3);
    if (!expect_decode("clobbered flag register", &obj, mutated,
                       sizeof(old124), 0))
        return 1;

    memcpy(mutated, old124, sizeof(old124));
    patch_124_targets(mutated, candidate, layout124);
    mutated[45] = 0xe8; /* call between load and test */
    memset(mutated + 46, 0, 4);
    memset(mutated + 50, 0x90, 4);
    if (!expect_decode("call between flag load and test", &obj, mutated,
                       sizeof(old124), 0))
        return 1;

    memcpy(mutated, old119, sizeof(old119));
    patch_119_targets(mutated, candidate, layout119);
    mutated[33] = 0x31; /* xor clobbers EFLAGS between test and JE */
    mutated[34] = 0xc0;
    memset(mutated + 35, 0x90, 7);
    if (!expect_decode("flags clobbered before zero branch", &obj, mutated,
                       sizeof(old119), 0))
        return 1;

    memcpy(mutated, old124, sizeof(old124));
    patch_124_targets(mutated, candidate, layout124);
    set_disp32(mutated, 76, 80,
               candidate + layout124->libc_threaded + sizeof(uint32_t));
    if (!expect_decode("wrong second field", &obj, mutated,
                       sizeof(old124), 0))
        return 1;

    memcpy(mutated, old124, sizeof(old124));
    patch_124_targets(mutated, candidate, layout124);
    mutated[94] = 0xc9; /* test r9d instead of the second loaded r8d */
    if (!expect_decode("wrong second test register", &obj, mutated,
                       sizeof(old124), 0))
        return 1;

    memcpy(mutated, old124, sizeof(old124));
    patch_124_targets(mutated, candidate, layout124);
    mutated[96] = 0x85; /* JNE instead of the second JE */
    if (!expect_decode("wrong second branch", &obj, mutated,
                       sizeof(old124), 0))
        return 1;

    memcpy(mutated, old124, sizeof(old124));
    patch_124_targets(mutated, candidate, layout124);
    set_disp32(mutated, 3, 7,
               candidate + layout124->libc_can_do_threads + 8);
    if (!expect_decode("wrong first field", &obj, mutated,
                       sizeof(old124), 0))
        return 1;

    memcpy(mutated, old124, sizeof(old124));
    patch_124_targets(mutated, candidate, layout124);
    set_disp32(mutated, 3, 7,
               (uintptr_t)image + sizeof(image) +
                   layout124->libc_can_do_threads);
    set_disp32(mutated, 76, 80,
               (uintptr_t)image + sizeof(image) +
                   layout124->libc_threaded);
    if (!expect_decode("first field outside mapping", &obj, mutated,
                       sizeof(old124), 0))
        return 1;

    if (!expect_decode("truncated REX load", &obj, old124, 1, 0) ||
        !expect_decode("truncated load opcode", &obj, old124, 2, 0) ||
        !expect_decode("truncated load displacement", &obj, old124, 6, 0) ||
        !expect_decode("truncated near branch", &obj, old124,
                       sizeof(old124) - 1, 0))
        return 1;

    memcpy(mutated, old124, sizeof(old124));
    patch_124_targets(mutated, candidate, layout124);
    mutated[95] = 0x74;
    mutated[96] = 0;
    if (!expect_decode("truncated short branch", &obj, mutated, 96, 0))
        return 1;

    memcpy(mutated, old124, sizeof(old124));
    patch_124_targets(mutated, candidate, layout124);
    mutated[67] = 0x74; /* accept an equivalent short JE */
    mutated[68] = 0;
    memset(mutated + 69, 0x90, 4);
    if (!expect_decode("short zero branch", &obj, mutated,
                       sizeof(old124), candidate))
        return 1;

    struct dlfrz_musl_layout byte_flags = *layout124;
    byte_flags.libc_flag_width = 1;
    g_musl_layout = &byte_flags;
    if (!expect_decode("wrong flag width", &obj, old124, sizeof(old124), 0))
        return 1;

    g_musl_layout = layout124;
    phdr.p_flags = PF_R;
    if (!expect_decode("non-writable libc state", &obj, old124,
                       sizeof(old124), 0))
        return 1;

    return 0;
}
