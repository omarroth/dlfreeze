#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !defined(__aarch64__)
#error "this decoder fixture is AArch64-specific"
#endif

/* Keep the production decoder private while testing the exact instruction
 * streams emitted by supported musl toolchains. */
#include "../src/loader.c"

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
    uint32_t direct_mutated[3];

    if (!expect_detach_layout(
            "direct store", direct_store,
            sizeof(direct_store) / sizeof(direct_store[0]), 1, 0) ||
        !expect_detach_layout("compact", compact,
                              sizeof(compact) / sizeof(compact[0]), 1, 2) ||
        !expect_detach_layout("hardened", hardened,
                              sizeof(hardened) / sizeof(hardened[0]), 1, 2) ||
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
            "preserved argument", preserved_arg,
            sizeof(preserved_arg) / sizeof(preserved_arg[0])))
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

    return 0;
}
