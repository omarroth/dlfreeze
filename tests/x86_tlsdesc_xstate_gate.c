#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !defined(__x86_64__)

int main(void)
{
    puts("SKIP: x86 TLSDESC XSAVE gate (not x86-64)");
    return 77;
}

#else

#define DLFREEZE_TLSDESC_XSTATE_GATE 1
#include "../src/loader.c"

struct gate_tlsdesc {
    uintptr_t resolver;
    uintptr_t argument;
};

extern uint64_t gate_call_tlsdesc(const struct gate_tlsdesc *,
                                  const unsigned char *, unsigned char *);

/* Enter the resolver through the real x86-64 TLSDESC convention.  The push
 * makes RSP 16-byte aligned at the nested call site, exactly as generated
 * compiler call sequences require. */
__asm__(
    ".text\n"
    ".global gate_call_tlsdesc\n"
    ".type gate_call_tlsdesc, @function\n"
    "gate_call_tlsdesc:\n"
    "\tpushq %rbp\n"
    "\tvmovdqu (%rsi), %ymm0\n"
    "\tmovq %rdi, %rax\n"
    "\tcall *(%rax)\n"
    "\tvmovdqu %ymm0, (%rdx)\n"
    "\tpopq %rbp\n"
    "\tret\n"
    ".size gate_call_tlsdesc, .-gate_call_tlsdesc\n");

int main(void)
{
    static const unsigned char pattern[32]
        __attribute__((aligned(32))) = {
            0x13, 0x57, 0x9b, 0xdf, 0x24, 0x68, 0xac, 0xe0,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
            0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
        };
    unsigned char observed[sizeof(pattern)] __attribute__((aligned(32)));
    struct x86_64_tlsdesc_arg argument = {
        .modid = 0,
        .offset = UINT64_C(0x13579bdf2468ace0),
    };
    struct gate_tlsdesc descriptor = {
        .resolver = (uintptr_t)dlfreeze_x86_64_tlsdesc_dynamic,
        .argument = (uintptr_t)&argument,
    };
    uint32_t cpuid_eax;
    uint32_t cpuid_ebx;
    uint32_t cpuid_ecx;
    uint32_t cpuid_edx;
    uint64_t result;

    if (!initialize_x86_tlsdesc_xstate()) {
        fputs("FAIL: x86 TLSDESC XSAVE admission\n", stderr);
        return 1;
    }
    x86_cpuid_count(1, 0, &cpuid_eax, &cpuid_ebx,
                    &cpuid_ecx, &cpuid_edx);
    if ((cpuid_ecx & (1U << 28)) == 0 ||
        g_x86_64_tlsdesc_xsave_size == 0 ||
        (g_x86_64_tlsdesc_xsave_mask_low & (1U << 2)) == 0) {
        puts("SKIP: x86 TLSDESC XSAVE gate (AVX state unavailable)");
        return 77;
    }

    memset(observed, 0, sizeof(observed));
    g_x86_64_tlsdesc_xstate_gate_clobber = 1;
    result = gate_call_tlsdesc(&descriptor, pattern, observed);
    g_x86_64_tlsdesc_xstate_gate_clobber = 0;

    if (result != argument.offset) {
        fputs("FAIL: x86 TLSDESC resolver result changed\n", stderr);
        return 1;
    }
    if (memcmp(pattern, observed, sizeof(pattern)) != 0) {
        fputs("FAIL: x86 TLSDESC resolver clobbered AVX state\n", stderr);
        return 1;
    }

    puts("PASS: x86 TLSDESC resolver preserves admitted AVX state");
    return 0;
}

#endif
