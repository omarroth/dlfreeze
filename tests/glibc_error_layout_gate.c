#include "glibc_error_layout.h"
#include <stdio.h>

struct reader { uintptr_t address; intptr_t offset; int denied; };
static int read_got(void *context, uintptr_t address, void *out, size_t size)
{
    struct reader *reader = context;
    if (reader->denied || address != reader->address || size != sizeof(reader->offset))
        return 0;
    memcpy(out, &reader->offset, size);
    return 1;
}

int main(void)
{
    unsigned char code[] = {
        0x48,0x8b,0x15,0,0,0,0,       /* GOT -> RDX */
        0x48,0x89,0x5d,0xf8,          /* preserve RBX; non-adjacent TLS load */
        0x64,0x48,0x8b,0x1a,          /* FS:(RDX) -> RBX */
        0x48,0x8b,0x43,0x10,          /* reason */
        0x48,0x8b,0x4b,0x08,          /* root */
        0x8b,0x13,                    /* errno */
        0x80,0x7b,0x05,0,             /* returned */
        0x0f,0xb6,0x43,0x04,          /* storage source */
        0xc3
    };
    unsigned char changed[sizeof(code) + 5];
    struct reader reader = {0x100007, -48, 0};
#define ACCEPT(bytes, size) dlfrz_glibc_x86_error_layout( \
    bytes, size, 0x100000, -48, read_got, &reader)
    if (!ACCEPT(code, sizeof(code))) return 1;
    reader.offset++;
    if (ACCEPT(code, sizeof(code))) return 2;
    reader.offset--;
    reader.denied = 1;
    if (ACCEPT(code, sizeof(code))) return 3;
    reader.denied = 0;
    if (ACCEPT(code, 0) || ACCEPT(code, 2049) || ACCEPT(code, 14)) return 4;
    /* A field read through a replaced pointer proves nothing. */
    memcpy(changed, code, 15);
    memcpy(changed + 15, "\x48\x83\xc3\x01", 4);
    memcpy(changed + 19, code + 15, sizeof(code) - 15);
    if (ACCEPT(changed, sizeof(code) + 4)) return 5;
    memcpy(changed + 15, "\x48\x8b\x5d\xf8", 4);
    if (ACCEPT(changed, sizeof(code) + 4)) return 6;
    memcpy(changed + 15, "\xc6\xc7\0", 3); /* MOV imm8, BH invalidates RBX. */
    memcpy(changed + 18, code + 15, sizeof(code) - 15);
    if (ACCEPT(changed, sizeof(code) + 3)) return 11;
    /* A call preserves this callee-saved pointer. */
    memcpy(changed + 15, "\xe8\0\0\0\0", 5);
    memcpy(changed + 20, code + 15, sizeof(code) - 15);
    if (!ACCEPT(changed, sizeof(changed))) return 7;
    /* The same call must kill a caller-saved RAX result pointer. */
    changed[14] = 0x02;
    changed[22] = 0x48; changed[26] = 0x70; changed[29] = 0x10;
    changed[31] = 0x78; changed[36] = 0x50;
    if (ACCEPT(changed, sizeof(changed))) return 8;
    memmove(changed + 15, changed + 20, sizeof(code) - 15);
    if (!ACCEPT(changed, sizeof(code))) return 10;
    /* Jumping into an immediate cannot manufacture field witnesses. */
    memcpy(changed, code, sizeof(code));
    changed[0] = 0xeb; changed[1] = 2;
    if (ACCEPT(changed, sizeof(code))) return 9;
    puts("bounded GNU error-layout provenance passed");
    return 0;
}
