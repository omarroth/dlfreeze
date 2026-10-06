#ifndef DLFREEZE_GLIBC_ERROR_LAYOUT_H
#define DLFREEZE_GLIBC_ERROR_LAYOUT_H

#include "glibc_layout.h"

/* Read-only observation of __libc_dlerror_result must not infer a private
 * structure from a release banner. Require the exported dlerror body to
 * select the exact TLS slot, and to read every field used by the observer
 * through that selected result register. All reads of live memory are made
 * through a bounded callback; unsupported instructions/layouts decline. */
typedef int (*dlfrz_error_read_fn)(void *, uintptr_t, void *, size_t);

/* Unknown register effects kill provenance. Merely finding instruction-like
 * bytes or a field read after an unrelated register assignment is not proof.
 * SysV calls preserve only RBX,RBP,R12..R15 (and the stack pointer). */
static inline unsigned int dlfrz_error_x86_writes(
    const unsigned char *bytes, size_t size)
{
    size_t cursor = 0;
    unsigned int rex = 0, opcode, modrm, reg, rm;
    while (cursor < size && dlfrz_glibc_x86_legacy_prefix(bytes[cursor]))
        cursor++;
    if (cursor < size && bytes[cursor] >= 0x40 && bytes[cursor] <= 0x4f)
        rex = bytes[cursor++];
    if (cursor >= size) return 0xffffU;
    opcode = bytes[cursor++];
    if (opcode == 0xe8) return 0x0fc7U;
    if (opcode == 0xc3 || opcode == 0xe9 || opcode == 0xeb ||
        (opcode >= 0x70 && opcode <= 0x7f) || opcode == 0x90) return 0;
    if (opcode >= 0x50 && opcode <= 0x57) return 1U << 4;
    if (opcode >= 0x58 && opcode <= 0x5f)
        return (1U << 4) | (1U << ((opcode & 7U) | ((rex & 1U) ? 8U : 0U)));
    if (opcode >= 0xb8 && opcode <= 0xbf)
        return 1U << ((opcode & 7U) | ((rex & 1U) ? 8U : 0U));
    if (opcode == 0xc9) return (1U << 4) | (1U << 5);
    if (opcode == 0x0f) {
        if (cursor >= size) return 0xffffU;
        opcode = bytes[cursor++];
        if ((opcode >= 0x80 && opcode <= 0x8f) || opcode == 0x1e || opcode == 0x1f)
            return 0;
        if ((opcode >= 0x40 && opcode <= 0x4f) ||
            opcode == 0xb6 || opcode == 0xb7 || opcode == 0xbe || opcode == 0xbf) {
            if (cursor >= size) return 0xffffU;
            return 1U << (((bytes[cursor] >> 3) & 7U) | ((rex & 4U) ? 8U : 0U));
        }
        return 0xffffU;
    }
    if (cursor >= size) return 0xffffU;
    modrm = bytes[cursor];
    reg = ((modrm >> 3) & 7U) | ((rex & 4U) ? 8U : 0U);
    rm = (modrm & 7U) | ((rex & 1U) ? 8U : 0U);
    if (opcode == 0x8b || opcode == 0x8d || opcode == 0x63 ||
        opcode == 0x03 || opcode == 0x0b || opcode == 0x23 ||
        opcode == 0x2b || opcode == 0x33) return 1U << reg;
    if (opcode == 0x39 || opcode == 0x3b || opcode == 0x84 || opcode == 0x85)
        return 0;
    if (opcode == 0xff && ((modrm >> 3) & 7U) == 2) return 0x0fc7U;
    if ((opcode == 0x80 || opcode == 0x81 || opcode == 0x83) &&
        ((modrm >> 3) & 7U) == 7) return 0;
    if ((opcode == 0x88 || opcode == 0xc6 || opcode == 0x80) &&
        !rex && (modrm >> 6) == 3 && rm >= 4)
        return 1U << (rm - 4); /* AH,CH,DH,BH modify their parent GPR. */
    if (opcode == 0x89 || opcode == 0x88 || opcode == 0xc6 || opcode == 0xc7 ||
        opcode == 0x01 || opcode == 0x09 || opcode == 0x21 ||
        opcode == 0x29 || opcode == 0x31 ||
        opcode == 0x80 || opcode == 0x81 || opcode == 0x83)
        return (modrm >> 6) == 3 ? (1U << rm) : 0;
    return 0xffffU;
}

static inline int dlfrz_error_read_tls_offset(
    dlfrz_error_read_fn read, void *context, uintptr_t address,
    intptr_t expected)
{
    intptr_t value;
    return read && read(context, address, &value, sizeof(value)) &&
           value == expected;
}

static inline int dlfrz_glibc_x86_error_layout(
    const unsigned char *code, size_t size, uintptr_t address,
    intptr_t tls_offset, dlfrz_error_read_fn read, void *context)
{
    unsigned char state[2048] = {0};
    size_t queue[2048];
    uint32_t inputs[2048] = {0};
    size_t head = 0, tail = 1, pending = 1;
    unsigned int fields = 0;

    if (!code || !read || size == 0 || size > sizeof(state) ||
        size > UINTPTR_MAX - address)
        return 0;
    queue[0] = 0;
    state[0] = DLFRZ_X86_INSN_QUEUED;
    while (pending) {
        size_t position = queue[head++ % 2048];
        struct dlfrz_glibc_x86_instruction instruction;
        const unsigned char *bytes = code + position;
        size_t remaining = size - position;
        size_t next;
        unsigned int offsets = inputs[position] & 0xffffU;
        unsigned int tls_registers = inputs[position] >> 16;
        unsigned int new_offsets = 0, new_pointers = 0;
        size_t successors[2], successor_count = 0;

        pending--;
        state[position] &= ~DLFRZ_X86_INSN_QUEUED;
        if (state[position] & DLFRZ_X86_INSN_INTERIOR)
            return 0;
        state[position] |= DLFRZ_X86_INSN_START;
        if (!dlfrz_glibc_x86_instruction(bytes, remaining, &instruction) ||
            instruction.length > remaining)
            continue;
        next = position + instruction.length;
        state[position] |= DLFRZ_X86_INSN_DECODED;
        for (size_t interior = position + 1; interior < next; interior++) {
            if (state[interior] & (DLFRZ_X86_INSN_QUEUED | DLFRZ_X86_INSN_START))
                return 0;
            state[interior] |= DLFRZ_X86_INSN_INTERIOR;
        }
        /* Initial-exec TLS: MOV offset@GOTTPOFF(%rip), r; MOV %fs:(r), p.
         * The matching GOT-derived offset ties field-read provenance to the
         * same TLS slot in this actual loaded function. */
        if (remaining >= 7 && bytes[0] >= 0x48 && bytes[0] <= 0x4f &&
            bytes[1] == 0x8b && (bytes[2] & 0xc7) == 0x05) {
            unsigned int offset_reg = ((bytes[2] >> 3) & 7U) |
                                      ((bytes[0] & 4U) ? 8U : 0U);
            int32_t displacement;
            uint64_t got;

            memcpy(&displacement, bytes + 3, sizeof(displacement));
            if (dlfrz_glibc_add_signed_u64(address + position + 7,
                                           displacement, &got) &&
                dlfrz_error_read_tls_offset(read, context, got, tls_offset))
                new_offsets = 1U << offset_reg;
        }
        if (instruction.length == 4 && bytes[0] == 0x64 &&
            bytes[1] >= 0x48 && bytes[1] <= 0x4f && bytes[2] == 0x8b &&
            (bytes[3] >> 6) == 0 && (bytes[3] & 7U) != 4 && (bytes[3] & 7U) != 5 &&
            (offsets & (1U << ((bytes[3] & 7U) | ((bytes[1] & 1U) ? 8U : 0U)))))
            new_pointers = 1U << (((bytes[3] >> 3) & 7U) | ((bytes[1] & 4U) ? 8U : 0U));
        {
            size_t cursor = 0;
            unsigned int rex = 0;
            unsigned int opcode;
            unsigned int modrm;
            unsigned int base;
            int64_t offset = 0;

            if (bytes[cursor] >= 0x40 && bytes[cursor] <= 0x4f)
                rex = bytes[cursor++];
            opcode = bytes[cursor++];
            if ((opcode == 0x8b || opcode == 0x80) &&
                cursor < instruction.length) {
                modrm = bytes[cursor++];
                base = (modrm & 7U) | ((rex & 1U) ? 8U : 0U);
                if ((modrm >> 6) == 1 && cursor < instruction.length)
                    offset = (int8_t)bytes[cursor++];
                else if ((modrm >> 6) == 2 &&
                         instruction.length - cursor >= sizeof(int32_t)) {
                    int32_t value;
                    memcpy(&value, bytes + cursor, sizeof(value));
                    offset = value;
                    cursor += sizeof(value);
                }
                if ((modrm >> 6) != 3 && (modrm & 7U) != 4U &&
                    !((modrm >> 6) == 0 && (modrm & 7U) == 5U) &&
                    (tls_registers & (1U << base))) {
                    if (opcode == 0x8b && (rex & 8U) && offset == 16)
                        fields |= 1;
                    if (opcode == 0x8b && (rex & 8U) && offset == 8)
                        fields |= 2;
                    if (opcode == 0x8b && !(rex & 8U) && offset == 0)
                        fields |= 4;
                    if (opcode == 0x80 && ((modrm >> 3) & 7U) == 7 &&
                        offset == 5 && cursor < instruction.length &&
                        bytes[cursor] == 0)
                        fields |= 8;
                }
            }
            if (opcode == 0x0f && cursor + 3 <= instruction.length &&
                bytes[cursor] == 0xb6) {
                modrm = bytes[cursor + 1];
                base = (modrm & 7U) | ((rex & 1U) ? 8U : 0U);
                if ((modrm >> 6) == 1 && (modrm & 7U) != 4 &&
                    bytes[cursor + 2] == 4 && (tls_registers & (1U << base)))
                    fields |= 16;
            }
        }
        {
            unsigned int writes = dlfrz_error_x86_writes(bytes, instruction.length);
            offsets = (offsets & ~writes) | new_offsets;
            tls_registers = (tls_registers & ~writes) | new_pointers;
        }
        if (instruction.direct_branch || instruction.conditional_branch) {
            uint64_t target;
            if (!dlfrz_glibc_add_signed_u64(next,
                    instruction.branch_displacement, &target) || target >= size)
                return 0;
            successors[successor_count++] = (size_t)target;
        }
        if (!instruction.terminal && !instruction.direct_branch) {
            if (next < size)
                successors[successor_count++] = next;
        }
        for (size_t i = 0; i < successor_count; i++) {
            size_t successor = successors[i];
            uint32_t combined = inputs[successor] | offsets | (tls_registers << 16);
            if (!(state[successor] & DLFRZ_X86_INSN_START) || combined != inputs[successor]) {
                inputs[successor] = combined;
                if (!(state[successor] & DLFRZ_X86_INSN_QUEUED)) {
                    if (pending >= 2048) return 0;
                    state[successor] |= DLFRZ_X86_INSN_QUEUED;
                    queue[tail++ % 2048] = successor;
                    pending++;
                }
            }
        }
    }
    return fields == 31;
}

#endif
