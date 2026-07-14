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
                                size_t count, int expected)
{
    size_t offset = 0;
    int initial = -1;
    int decoded = decode_aarch64_musl_detach_offset(
        (const uint8_t *)code, count * sizeof(*code), &offset, &initial);

    if (decoded != expected ||
        (decoded && (offset != 40 || initial != 2))) {
        fprintf(stderr, "%s: decoded=%d offset=%zu initial=%d\n",
                label, decoded, offset, initial);
        return 0;
    }
    return 1;
}

int main(void)
{
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
    uint32_t mutated[sizeof(hardened) / sizeof(hardened[0])];

    if (!expect_detach_layout("compact", compact,
                              sizeof(compact) / sizeof(compact[0]), 1) ||
        !expect_detach_layout("hardened", hardened,
                              sizeof(hardened) / sizeof(hardened[0]), 1))
        return 1;

    memcpy(mutated, hardened, sizeof(mutated));
    mutated[15] = 0x7100045f; /* cmp w2, #1 */
    if (!expect_detach_layout("wrong initial state", mutated,
                              sizeof(mutated) / sizeof(mutated[0]), 0))
        return 1;

    memcpy(mutated, hardened, sizeof(mutated));
    mutated[12] = 0x8802fc43; /* stlxr w2, w3, [x2] */
    if (!expect_detach_layout("wrong store address", mutated,
                              sizeof(mutated) / sizeof(mutated[0]), 0))
        return 1;

    return 0;
}
