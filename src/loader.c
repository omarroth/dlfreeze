/*
 * dlfreeze in-process ELF loader.
 *
 * Maps embedded shared objects from the frozen binary's virtual memory,
 * resolves symbols, applies relocations, sets up TLS, and transfers
 * control to the main executable — all without ld.so.
 *
 * Targets: ELF64 x86-64 and AArch64 on supported Linux libc runtimes.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <dirent.h>
#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <locale.h>
#include <dlfcn.h>

#include "common.h"
#include "glibc_layout.h"
#include "musl_layout.h"
#include "loader.h"

/* ---- flag constants (must match common.h) ----------------------------- */
#define LDR_FLAG_MAIN_EXE    0x01
#define LDR_FLAG_INTERP      0x02
#define LDR_FLAG_SHLIB       0x04
#define LDR_FLAG_DLOPEN      0x08
#define LDR_FLAG_PRELINKED   0x10
#define LDR_FLAG_NEEDS_RTLD  0x20
#define LDR_FLAG_DATA        0x40
#define LDR_FLAG_RUNTIME_SCAN 0x80

#define LDR_PRELINK_FIXUP_JMPREL 0x80000000u

/* Fallback for musl libc which lacks Elf64_Relr */
#ifndef ELF_RELR_DEFINED
#ifdef __LP64__
typedef Elf64_Xword Elf64_Relr;
#endif
#endif

/* Fallback for pre-4.17 kernel headers */
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#ifndef DF_1_NOOPEN
#define DF_1_NOOPEN 0x00000040
#endif
#ifndef DF_1_NODEFLIB
#define DF_1_NODEFLIB 0x00000800
#endif
#ifndef DF_1_PIE
#define DF_1_PIE 0x08000000
#endif

/* ---- architecture abstraction ----------------------------------------- */
/* Fallback defines for aarch64 relocation types missing from older elf.h */
#ifndef R_AARCH64_IRELATIVE
#define R_AARCH64_IRELATIVE  1032
#endif
#ifndef R_AARCH64_COPY
#define R_AARCH64_COPY       1024
#endif
#ifndef R_AARCH64_TLS_TPREL
#define R_AARCH64_TLS_TPREL  1030
#endif
#ifndef R_AARCH64_TLS_DTPMOD
#define R_AARCH64_TLS_DTPMOD 1028
#endif
#ifndef R_AARCH64_TLS_DTPREL
#define R_AARCH64_TLS_DTPREL 1029
#endif
#ifndef R_AARCH64_TLSDESC
#define R_AARCH64_TLSDESC   1031
#endif

#if defined(__x86_64__)
#ifndef R_X86_64_TLSDESC
#define R_X86_64_TLSDESC      36
#endif
#define ARCH_ELF_MACHINE      EM_X86_64
#define ARCH_RELOC_RELATIVE   R_X86_64_RELATIVE
#define ARCH_RELOC_GLOB_DAT   R_X86_64_GLOB_DAT
#define ARCH_RELOC_JUMP_SLOT  R_X86_64_JUMP_SLOT
#define ARCH_RELOC_ABS        R_X86_64_64
#define ARCH_RELOC_TPOFF      R_X86_64_TPOFF64
#define ARCH_RELOC_DTPMOD     R_X86_64_DTPMOD64
#define ARCH_RELOC_DTPOFF     R_X86_64_DTPOFF64
#define ARCH_RELOC_TLSDESC    R_X86_64_TLSDESC
#define ARCH_RELOC_IRELATIVE  R_X86_64_IRELATIVE
#define ARCH_RELOC_COPY       R_X86_64_COPY

  static inline uintptr_t arch_get_tp(void) {
      uintptr_t tp;
      __asm__ volatile("mov %%fs:0, %0" : "=r"(tp));
      return tp;
  }
  static inline void arch_set_tp(uintptr_t tp) {
      syscall(SYS_arch_prctl, 0x1002 /*ARCH_SET_FS*/, tp);
  }
  static inline uintptr_t arch_get_tp_syscall(void) {
      uintptr_t tp = 0;
      syscall(SYS_arch_prctl, 0x1003 /*ARCH_GET_FS*/, &tp);
      return tp;
  }
  /* Read a value at an offset from the thread pointer (FS segment) */
  static inline uintptr_t arch_read_tp_offset(unsigned off) {
      uintptr_t val;
      switch (off) {
      case 0x00: __asm__ volatile("mov %%fs:0x00, %0" : "=r"(val)); break;
      case 0x10: __asm__ volatile("mov %%fs:0x10, %0" : "=r"(val)); break;
      case 0x28: __asm__ volatile("mov %%fs:0x28, %0" : "=r"(val)); break;
      default:   val = *(uintptr_t *)(arch_get_tp() + off); break;
      }
      return val;
  }
  static inline long arch_raw_write(int fd, const void *buf, size_t len) {
      register long nr __asm__("rax") = SYS_write;
      register long arg0 __asm__("rdi") = fd;
      register long arg1 __asm__("rsi") = (long)buf;
      register long arg2 __asm__("rdx") = (long)len;
      __asm__ volatile("syscall" : "+a"(nr)
                       : "D"(arg0), "S"(arg1), "d"(arg2)
                       : "rcx", "r11", "memory");
      return nr;
  }
  static inline long arch_raw_close(int fd) {
      register long nr __asm__("rax") = SYS_close;
      register long arg0 __asm__("rdi") = fd;
      __asm__ volatile("syscall" : "+a"(nr)
                       : "D"(arg0) : "rcx", "r11", "memory");
      return nr;
  }
#elif defined(__aarch64__)
#define ARCH_ELF_MACHINE      EM_AARCH64
#define ARCH_RELOC_RELATIVE   R_AARCH64_RELATIVE
#define ARCH_RELOC_GLOB_DAT   R_AARCH64_GLOB_DAT
#define ARCH_RELOC_JUMP_SLOT  R_AARCH64_JUMP_SLOT
#define ARCH_RELOC_ABS        R_AARCH64_ABS64
#define ARCH_RELOC_TPOFF      R_AARCH64_TLS_TPREL
#define ARCH_RELOC_DTPMOD     R_AARCH64_TLS_DTPMOD
#define ARCH_RELOC_DTPOFF     R_AARCH64_TLS_DTPREL
#define ARCH_RELOC_TLSDESC    R_AARCH64_TLSDESC
#define ARCH_RELOC_IRELATIVE  R_AARCH64_IRELATIVE
#define ARCH_RELOC_COPY       R_AARCH64_COPY

  static inline uintptr_t arch_get_tp(void) {
      uintptr_t tp;
      __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tp));
      return tp;
  }
  static inline void arch_set_tp(uintptr_t tp) {
      __asm__ volatile("msr tpidr_el0, %0" :: "r"(tp));
  }
  static inline uintptr_t arch_get_tp_syscall(void) {
      return arch_get_tp();
  }
  static inline uintptr_t arch_read_tp_offset(unsigned off) {
      return *(uintptr_t *)(arch_get_tp() + off);
  }
  static inline long arch_raw_write(int fd, const void *buf, size_t len) {
      register long arg0 __asm__("x0") = fd;
      register long arg1 __asm__("x1") = (long)buf;
      register long arg2 __asm__("x2") = (long)len;
      register long nr __asm__("x8") = SYS_write;
      __asm__ volatile("svc 0" : "+r"(arg0)
                       : "r"(arg1), "r"(arg2), "r"(nr) : "memory");
      return arg0;
  }
  static inline long arch_raw_close(int fd) {
      register long arg0 __asm__("x0") = fd;
      register long nr __asm__("x8") = SYS_close;
      __asm__ volatile("svc 0" : "+r"(arg0) : "r"(nr) : "memory");
      return arg0;
  }
#else
  #error "Unsupported architecture"
#endif

/* Debug verbosity — enabled by DLFREEZE_DEBUG=1 env var.
 * Set before TLS swap (getenv is safe in bootstrap's libc). */
static int g_debug;
static int g_glibc_early_init_done;

/* Perf-friendly mode — enabled by DLFREEZE_PERF=1 env var.
 * Uses anonymous memory (memcpy) instead of file-backed mmap so that
 * perf falls back to /tmp/perf-<PID>.map for symbol resolution.
 * Without this, all loaded code is file-backed from the frozen binary
 * which has stripped section headers, so perf finds no symbols. */
static int g_perf_mode;
static int g_is_musl_runtime;
static uintptr_t g_musl_tp_self_delta;
static uintptr_t g_musl_libc_addr;
static uintptr_t g_musl_stack_guard;
static const struct dlfrz_musl_layout *g_musl_layout;
static uint64_t g_page_size = 4096;

/* Present in static musl startup, absent from glibc and other bootstrap
 * libcs.  This is an identity check only; the loader never calls it. */
extern void *__copy_tls(unsigned char *) __attribute__((weak));
extern uintptr_t __stack_chk_guard __attribute__((weak));

static uint64_t page_floor(uint64_t value)
{
    return value & ~(g_page_size - 1);
}

static int u64_add_checked(uint64_t left, uint64_t right, uint64_t *out)
{
    if (right > UINT64_MAX - left)
        return 0;
    *out = left + right;
    return 1;
}

static int u64_mul_checked(uint64_t left, uint64_t right, uint64_t *out)
{
    if (left != 0 && right > UINT64_MAX / left)
        return 0;
    *out = left * right;
    return 1;
}

static int u64_align_up_checked(uint64_t value, uint64_t align,
                                uint64_t *out)
{
    uint64_t mask;

    if (align == 0 || (align & (align - 1)) != 0)
        return 0;
    mask = align - 1;
    if (value > UINT64_MAX - mask)
        return 0;
    *out = (value + mask) & ~mask;
    return 1;
}

static int u64_add_i64_checked(uint64_t base, int64_t delta, uint64_t *out)
{
    if (delta >= 0)
        return u64_add_checked(base, (uint64_t)delta, out);

    uint64_t magnitude = (uint64_t)(-(delta + 1)) + 1;
    if (magnitude > base)
        return 0;
    *out = base - magnitude;
    return 1;
}

static int i64_add_u64_checked(int64_t base, uint64_t addend, int64_t *out)
{
    if (base >= 0) {
        if (addend > (uint64_t)(INT64_MAX - base))
            return 0;
        *out = base + (int64_t)addend;
        return 1;
    }

    uint64_t magnitude = (uint64_t)(-(base + 1)) + 1;
    if (addend >= magnitude) {
        uint64_t positive = addend - magnitude;

        if (positive > INT64_MAX)
            return 0;
        *out = (int64_t)positive;
        return 1;
    }

    magnitude -= addend;
    if (magnitude == (uint64_t)INT64_MAX + 1) {
        *out = INT64_MIN;
        return 1;
    }
    *out = -(int64_t)magnitude;
    return 1;
}

static int i64_add_checked(int64_t left, int64_t right, int64_t *out)
{
    if ((right > 0 && left > INT64_MAX - right) ||
        (right < 0 && left < INT64_MIN - right))
        return 0;
    *out = left + right;
    return 1;
}

#if defined(__aarch64__)
static inline int64_t sign_extend64(uint64_t value, unsigned bits)
{
    uint64_t sign = 1ULL << (bits - 1);
    return (int64_t)((value ^ sign) - sign);
}

static inline int aarch64_is_b_imm(uint32_t insn)
{
    return (insn & 0xfc000000u) == 0x14000000u;
}

static inline uintptr_t aarch64_decode_b_imm(uintptr_t pc, uint32_t insn)
{
    int64_t imm = sign_extend64((uint64_t)(insn & 0x03ffffffu), 26) << 2;
    return pc + imm;
}

static inline int aarch64_is_adrp(uint32_t insn)
{
    return (insn & 0x9f000000u) == 0x90000000u;
}

static inline int aarch64_is_adr(uint32_t insn)
{
    return (insn & 0x9f000000u) == 0x10000000u;
}

static inline uintptr_t aarch64_decode_adrp(uintptr_t pc, uint32_t insn)
{
    uint64_t immhi = (insn >> 5) & 0x7ffffu;
    uint64_t immlo = (insn >> 29) & 0x3u;
    int64_t imm = sign_extend64((immhi << 2) | immlo, 21) << 12;
    return (pc & ~0xfffULL) + imm;
}

static inline uintptr_t aarch64_decode_adr(uintptr_t pc, uint32_t insn)
{
    uint64_t immhi = (insn >> 5) & 0x7ffffu;
    uint64_t immlo = (insn >> 29) & 0x3u;
    int64_t imm = sign_extend64((immhi << 2) | immlo, 21);
    return pc + imm;
}

static inline int aarch64_is_add_imm64(uint32_t insn)
{
    return (insn & 0xff000000u) == 0x91000000u;
}

static inline uint32_t aarch64_add_imm64(uint32_t insn)
{
    uint32_t imm12 = (insn >> 10) & 0xfffu;
    uint32_t shift = (insn >> 22) & 0x3u;
    return imm12 << (shift ? 12 : 0);
}

static inline int aarch64_is_ldr_uimm64(uint32_t insn)
{
    return (insn & 0xffc00000u) == 0xf9400000u;
}

static uint64_t aarch64_try_extract_main_from_block(uintptr_t map_start,
                                                    uintptr_t map_end,
                                                    uintptr_t block_addr,
                                                    int depth)
{
    if (depth <= 0)
        return 0;
    if (block_addr < map_start || block_addr + 16 * sizeof(uint32_t) > map_end)
        return 0;

    const uint32_t *insns = (const uint32_t *)block_addr;

    for (int i = 0; i < 16; i++) {
        uint32_t insn = insns[i];
        uintptr_t pc = block_addr + (uintptr_t)i * sizeof(uint32_t);
        uint32_t rd = insn & 31u;

        if (aarch64_is_b_imm(insn)) {
            uintptr_t target = aarch64_decode_b_imm(pc, insn);
            if (target != pc)
                return aarch64_try_extract_main_from_block(map_start, map_end,
                                                           target, depth - 1);
            continue;
        }

        if (rd != 0)
            continue;

        if (aarch64_is_adr(insn))
            return aarch64_decode_adr(pc, insn);

        if (!aarch64_is_adrp(insn))
            continue;

        uintptr_t base = aarch64_decode_adrp(pc, insn);
        if (i + 1 >= 16)
            continue;

        uint32_t next = insns[i + 1];
        uint32_t next_rd = next & 31u;
        uint32_t next_rn = (next >> 5) & 31u;

        if (aarch64_is_add_imm64(next) && next_rd == 0 && next_rn == 0)
            return base + aarch64_add_imm64(next);

        if (aarch64_is_ldr_uimm64(next) && next_rd == 0 && next_rn == 0) {
            uintptr_t slot = base + (((next >> 10) & 0xfffu) << 3);

            if (slot < map_start || slot + sizeof(uint64_t) > map_end)
                return 0;

            return *(const uint64_t *)(uintptr_t)slot;
        }
    }

    return 0;
}

static uint64_t aarch64_extract_main_from_entry(uintptr_t map_start,
                                                uintptr_t map_end,
                                                uintptr_t entry)
{
    return aarch64_try_extract_main_from_block(map_start, map_end, entry, 3);
}
#endif

#if defined(__aarch64__)
struct aarch64_tlsdesc_arg {
    uint64_t modid;
    uint64_t offset;
};

#define AARCH64_TLSDESC_ARGS_PER_PAGE 127

extern uintptr_t dlfreeze_aarch64_tlsdesc_static(void *);
extern uintptr_t dlfreeze_aarch64_tlsdesc_dynamic(void *);
static int64_t dlfreeze_aarch64_tlsdesc_resolve_c(void *arg_in);
static void *runtime_tls_get_addr(uintptr_t tp, unsigned long modid,
                                  unsigned long ti_offset);

struct aarch64_tlsdesc_page {
    struct aarch64_tlsdesc_page *next;
    size_t used;
    struct aarch64_tlsdesc_arg args[AARCH64_TLSDESC_ARGS_PER_PAGE];
};

static struct aarch64_tlsdesc_page *g_aarch64_tlsdesc_pages;

__asm__(
    ".text\n"
    ".align 2\n"
    ".global dlfreeze_aarch64_tlsdesc_static\n"
    ".hidden dlfreeze_aarch64_tlsdesc_static\n"
    ".type dlfreeze_aarch64_tlsdesc_static, %function\n"
    "dlfreeze_aarch64_tlsdesc_static:\n"
    "\tldr x0, [x0, #8]\n"
    "\tret\n"
    ".size dlfreeze_aarch64_tlsdesc_static, .-dlfreeze_aarch64_tlsdesc_static\n"
    /* Dynamic TLSDESC resolver.  AArch64 TLSDESC ABI: only x0 (and the
     * flags) may be clobbered; all other GPRs and FP registers must be
     * preserved.  Route every lookup through the checked C resolver: an
     * inline DTV lookup cannot safely read a module slot without first
     * validating that thread's DTV capacity. */
    ".global dlfreeze_aarch64_tlsdesc_dynamic\n"
    ".hidden dlfreeze_aarch64_tlsdesc_dynamic\n"
    ".type dlfreeze_aarch64_tlsdesc_dynamic, %function\n"
    "dlfreeze_aarch64_tlsdesc_dynamic:\n"
    "\tstp x1, x2, [sp, #-16]!\n"
    "\tstp x3, x4, [sp, #-16]!\n"
    "\tldr x0, [x0, #8]\n"            /* x0 = arg pointer (kept until end) */
    "1:\n"
    /* Slow path: x0 still holds the arg pointer.  Save remaining
     * caller-clobbered GPRs and call into C. */
    "\tstp x29, x30, [sp, #-16]!\n"
    "\tmov x29, sp\n"
    "\tstp x5, x6,   [sp, #-16]!\n"
    "\tstp x7, x8,   [sp, #-16]!\n"
    "\tstp x9, x10,  [sp, #-16]!\n"
    "\tstp x11, x12, [sp, #-16]!\n"
    "\tstp x13, x14, [sp, #-16]!\n"
    "\tstp x15, x16, [sp, #-16]!\n"
    "\tstp x17, x18, [sp, #-16]!\n"
    "\tsub sp, sp, #528\n"
    "\tstp q0, q1, [sp, #0]\n"
    "\tstp q2, q3, [sp, #32]\n"
    "\tstp q4, q5, [sp, #64]\n"
    "\tstp q6, q7, [sp, #96]\n"
    "\tstp q8, q9, [sp, #128]\n"
    "\tstp q10, q11, [sp, #160]\n"
    "\tstp q12, q13, [sp, #192]\n"
    "\tstp q14, q15, [sp, #224]\n"
    "\tstp q16, q17, [sp, #256]\n"
    "\tstp q18, q19, [sp, #288]\n"
    "\tstp q20, q21, [sp, #320]\n"
    "\tstp q22, q23, [sp, #352]\n"
    "\tstp q24, q25, [sp, #384]\n"
    "\tstp q26, q27, [sp, #416]\n"
    "\tstp q28, q29, [sp, #448]\n"
    "\tstp q30, q31, [sp, #480]\n"
    "\tmrs x17, fpcr\n"
    "\tmrs x18, fpsr\n"
    "\tstr x17, [sp, #512]\n"
    "\tstr x18, [sp, #520]\n"
    "\tbl dlfreeze_aarch64_tlsdesc_resolve_c\n"
    "\tldr x17, [sp, #512]\n"
    "\tldr x18, [sp, #520]\n"
    "\tmsr fpcr, x17\n"
    "\tmsr fpsr, x18\n"
    "\tldp q0, q1, [sp, #0]\n"
    "\tldp q2, q3, [sp, #32]\n"
    "\tldp q4, q5, [sp, #64]\n"
    "\tldp q6, q7, [sp, #96]\n"
    "\tldp q8, q9, [sp, #128]\n"
    "\tldp q10, q11, [sp, #160]\n"
    "\tldp q12, q13, [sp, #192]\n"
    "\tldp q14, q15, [sp, #224]\n"
    "\tldp q16, q17, [sp, #256]\n"
    "\tldp q18, q19, [sp, #288]\n"
    "\tldp q20, q21, [sp, #320]\n"
    "\tldp q22, q23, [sp, #352]\n"
    "\tldp q24, q25, [sp, #384]\n"
    "\tldp q26, q27, [sp, #416]\n"
    "\tldp q28, q29, [sp, #448]\n"
    "\tldp q30, q31, [sp, #480]\n"
    "\tadd sp, sp, #528\n"
    "\tldp x17, x18, [sp], #16\n"
    "\tldp x15, x16, [sp], #16\n"
    "\tldp x13, x14, [sp], #16\n"
    "\tldp x11, x12, [sp], #16\n"
    "\tldp x9, x10,  [sp], #16\n"
    "\tldp x7, x8,   [sp], #16\n"
    "\tldp x5, x6,   [sp], #16\n"
    "\tldp x29, x30, [sp], #16\n"
    "\tldp x3, x4, [sp], #16\n"
    "\tldp x1, x2, [sp], #16\n"
    "\tret\n"
    ".size dlfreeze_aarch64_tlsdesc_dynamic, .-dlfreeze_aarch64_tlsdesc_dynamic\n");

static struct aarch64_tlsdesc_arg *alloc_aarch64_tlsdesc_arg(void)
{
    struct aarch64_tlsdesc_page *page = g_aarch64_tlsdesc_pages;

    if (!page || page->used == AARCH64_TLSDESC_ARGS_PER_PAGE) {
        page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED)
            return NULL;
        memset(page, 0, 4096);
        page->next = g_aarch64_tlsdesc_pages;
        g_aarch64_tlsdesc_pages = page;
    }

    return &page->args[page->used++];
}

/* Slow-path C helper for the dynamic AArch64 TLSDESC resolver.  Called
 * by the asm trampoline above when the calling thread's DTV is missing
 * a slot for the requested module.  Returns the address of the TLS
 * variable relative to tpidr_el0 (so the caller can use the value as
 * a tpoff). */
static int64_t dlfreeze_aarch64_tlsdesc_resolve_c(void *arg_in) __attribute__((used));
static int64_t dlfreeze_aarch64_tlsdesc_resolve_c(void *arg_in)
{
    struct aarch64_tlsdesc_arg *arg = (struct aarch64_tlsdesc_arg *)arg_in;
    uintptr_t tp = arch_get_tp();
    uintptr_t tls_addr = (uintptr_t)runtime_tls_get_addr(
        tp, (unsigned long)arg->modid, (unsigned long)arg->offset);
    return (int64_t)(tls_addr - tp);
}
#endif

#if defined(__x86_64__)
struct x86_64_tlsdesc_arg {
    uint64_t modid;
    uint64_t offset;
};

#define X86_64_TLSDESC_ARGS_PER_PAGE 255

/* x86_64 TLSDESC ABI: caller does `lea desc(%rip), %rax; call *(%rax)`.
 * Resolver may clobber %rax and the flags only; all other registers
 * (including arg registers) must be preserved.  Returns the TP offset
 * (i.e. value to be combined as `%fs:(%rax)`) in %rax. */
extern uintptr_t dlfreeze_x86_64_tlsdesc_static(void *);
extern uintptr_t dlfreeze_x86_64_tlsdesc_dynamic(void *);
static int64_t dlfreeze_x86_64_tlsdesc_resolve_c(void *arg_in);

struct x86_64_tlsdesc_page {
    struct x86_64_tlsdesc_page *next;
    size_t used;
    struct x86_64_tlsdesc_arg args[X86_64_TLSDESC_ARGS_PER_PAGE];
};

static struct x86_64_tlsdesc_page *g_x86_64_tlsdesc_pages;

__asm__(
    ".text\n"
    ".global dlfreeze_x86_64_tlsdesc_static\n"
    ".hidden dlfreeze_x86_64_tlsdesc_static\n"
    ".type dlfreeze_x86_64_tlsdesc_static, @function\n"
    "dlfreeze_x86_64_tlsdesc_static:\n"
    "\tmovq 8(%rax), %rax\n"
    "\tret\n"
    ".size dlfreeze_x86_64_tlsdesc_static, .-dlfreeze_x86_64_tlsdesc_static\n"
    ".global dlfreeze_x86_64_tlsdesc_dynamic\n"
    ".hidden dlfreeze_x86_64_tlsdesc_dynamic\n"
    ".type dlfreeze_x86_64_tlsdesc_dynamic, @function\n"
    "dlfreeze_x86_64_tlsdesc_dynamic:\n"
    "\tpushq %rdi\n"
    "\tpushq %rsi\n"
    "\tpushq %rdx\n"
    "\tpushq %rcx\n"
    "\tpushq %r8\n"
    "\tpushq %r9\n"
    "\tpushq %r10\n"
    "\tpushq %r11\n"
    "\tpushq %rbx\n"
    "\tmovq 8(%rax), %rdi\n"
    /* The bootstrap is built for baseline x86-64/SSE2.  FXSAVE preserves
     * every FP/SIMD state component that such nested C code may modify,
     * including x87, MXCSR, and XMM0-XMM15.  Legacy SSE instructions leave
     * wider AVX register lanes untouched. */
    "\tsubq $512, %rsp\n"
    "\tfxsave64 (%rsp)\n"
    "\tcall dlfreeze_x86_64_tlsdesc_resolve_c\n"
    "\tfxrstor64 (%rsp)\n"
    "\taddq $512, %rsp\n"
    "\tpopq %rbx\n"
    "\tpopq %r11\n"
    "\tpopq %r10\n"
    "\tpopq %r9\n"
    "\tpopq %r8\n"
    "\tpopq %rcx\n"
    "\tpopq %rdx\n"
    "\tpopq %rsi\n"
    "\tpopq %rdi\n"
    "\tret\n"
    ".size dlfreeze_x86_64_tlsdesc_dynamic, .-dlfreeze_x86_64_tlsdesc_dynamic\n");

static struct x86_64_tlsdesc_arg *alloc_x86_64_tlsdesc_arg(void)
{
    struct x86_64_tlsdesc_page *page = g_x86_64_tlsdesc_pages;

    if (!page || page->used == X86_64_TLSDESC_ARGS_PER_PAGE) {
        page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED)
            return NULL;
        memset(page, 0, 4096);
        page->next = g_x86_64_tlsdesc_pages;
        g_x86_64_tlsdesc_pages = page;
    }

    return &page->args[page->used++];
}
#endif

static const char *path_basename(const char *path)
{
    const char *base = strrchr(path, '/');
    return base ? base + 1 : path;
}

static int is_musl_libc_path(const char *path)
{
    const char *base = path_basename(path);

    return strcmp(base, "libc.so") == 0 ||
           strncmp(base, "libc.musl-", 10) == 0;
}

enum frozen_runtime {
    FROZEN_RUNTIME_UNKNOWN,
    FROZEN_RUNTIME_GLIBC,
    FROZEN_RUNTIME_MUSL,
};

static enum frozen_runtime
detect_frozen_runtime(const struct dlfrz_lib_meta *metas,
                      const struct dlfrz_entry *entries,
                      const char *strtab,
                      uint32_t num_entries)
{
    for (uint32_t i = 0; i < num_entries; i++) {
        const char *base;

        if (!(metas[i].flags & LDR_FLAG_INTERP))
            continue;
        base = path_basename(strtab + entries[i].name_offset);
        if (strncmp(base, "ld-musl", 7) == 0)
            return FROZEN_RUNTIME_MUSL;
        if (strncmp(base, "ld-linux", 8) == 0)
            return FROZEN_RUNTIME_GLIBC;
        return FROZEN_RUNTIME_UNKNOWN;
    }
    return FROZEN_RUNTIME_UNKNOWN;
}

/* ---- error output (no stdio — bootstrap may break after TLS swap) ----- */
static void ldr_msg(const char *s)
{
    if (s) write(STDERR_FILENO, s, strlen(s));
}

/* Debug-only output — silent unless DLFREEZE_DEBUG is set. */
static void ldr_dbg(const char *s)
{
    if (g_debug) ldr_msg(s);
}

static void ldr_hex(const char *prefix, uint64_t val)
{
    char buf[80];
    int n = 0;
    while (*prefix) buf[n++] = *prefix++;
    char hx[17]; int hn = 0;
    if (val == 0) buf[n++] = '0';
    else { do { hx[hn++] = "0123456789abcdef"[val & 0xf]; val >>= 4; } while (val); while (hn > 0) buf[n++] = hx[--hn]; }
    buf[n++] = '\n'; buf[n] = 0;
    ldr_msg(buf);
}

static void ldr_dbg_hex(const char *prefix, uint64_t val)
{
    if (g_debug) ldr_hex(prefix, val);
}

static void ldr_err(const char *ctx, const char *detail)
{
    ldr_msg("dlfreeze-loader: ");
    ldr_msg(ctx);
    if (detail) { ldr_msg(": "); ldr_msg(detail); }
    ldr_msg("\n");
}

/* SIGSEGV handler for debugging */
#include <signal.h>
/* Pointer to mapped libc's main_arena, set during init for crash diagnostics */
static uintptr_t g_arena_addr;
/* Saved stack/pointer guard values and a main-thread address for diagnostics. */
static uintptr_t g_saved_stack_guard;
static uintptr_t g_saved_ptr_guard;
static uintptr_t g_ptr_guard_addr;

static inline void sync_glibc_errno_value(int err);
static inline void set_loader_errno(int err);

#if defined(__x86_64__)
static const uintptr_t g_ptr_guard_off = 48;
#elif defined(__aarch64__)
static const uintptr_t g_ptr_guard_off = 0;
#endif

/*
 * restore_ptr_guard — fix corruption from bootstrap libc's errno writes.
 *
 * The bootstrap binary is statically linked with musl, which stores
 * errno at FS:0x34.  After setup_tls switches FS to a glibc-compatible
 * TCB, musl's __syscall_ret still writes errno at FS:0x34, which
 * overlaps with glibc's pointer_guard at FS:0x30 (bytes 4-7 of the
 * 8-byte field on little-endian x86-64).  Any failing syscall through
 * the bootstrap's libc corrupts the pointer guard.
 *
 * Call this after any section that may invoke failing syscalls through
 * bootstrap (musl) wrappers (e.g. open, stat, mmap returning error).
 */
static inline void restore_ptr_guard(void)
{
#if defined(__aarch64__)
    return;
#endif
    if (g_saved_ptr_guard) {
        uintptr_t tp = arch_get_tp();

        if (tp > 0x1000)
            *(uintptr_t *)(tp + g_ptr_guard_off) = g_saved_ptr_guard;
    }
}

/* Fatal signals that the loader temporarily owns while running init code. */
static const int g_crash_signals[] = {
    SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL
};

#define CRASH_SIGNAL_COUNT ((int)(sizeof(g_crash_signals) / sizeof(g_crash_signals[0])))

typedef void (*signal_handler_t)(int);

static int guarded_sigaction(int signum, const struct sigaction *act,
                             struct sigaction *oldact)
{
    int rc = sigaction(signum, act, oldact);
    int saved_errno = errno;
    restore_ptr_guard();
    if (rc < 0)
        sync_glibc_errno_value(saved_errno);
    return rc;
}

static signal_handler_t guarded_signal(int signum, signal_handler_t handler)
{
    signal_handler_t old = signal(signum, handler);
    int saved_errno = errno;
    restore_ptr_guard();
    if (old == SIG_ERR)
        sync_glibc_errno_value(saved_errno);
    return old;
}

static void crash_handler(int sig, siginfo_t *info, void *ucontext);

static void crash_handler(int sig, siginfo_t *info, void *ucontext)
{
    if (!g_debug)
        _exit(127);

    (void)ucontext;
    const char *name = "UNKNOWN";
    if (sig == SIGSEGV) name = "SIGSEGV";
    else if (sig == SIGABRT) name = "SIGABRT";
    else if (sig == SIGBUS)  name = "SIGBUS";
    else if (sig == SIGFPE)  name = "SIGFPE";
    else if (sig == SIGILL)  name = "SIGILL";
    ldr_msg("[loader] ");
    ldr_msg(name);
    ldr_msg(" at addr=");
    ldr_hex("", (uint64_t)(uintptr_t)info->si_addr);
    ucontext_t *uc = (ucontext_t *)ucontext;
#if defined(__x86_64__)
    ldr_hex("[loader] RIP=0x", (uint64_t)uc->uc_mcontext.gregs[REG_RIP]);
    /* Print RSP and the return address (caller) from the stack */
    uint64_t rsp = (uint64_t)uc->uc_mcontext.gregs[REG_RSP];
    ldr_hex("[loader] RSP=0x", rsp);
    if (rsp > 0x1000) {
        /* Walk up the stack using RBP chain */
        uint64_t rbp = (uint64_t)uc->uc_mcontext.gregs[REG_RBP];
        ldr_msg("[loader] backtrace:\n");
        ldr_hex("[loader]  frame0 ret=", *(uint64_t *)(rsp));
        for (int f = 0; f < 15 && rbp > 0x1000; f++) {
            ldr_hex("[loader]  frame ret=", *(uint64_t *)(rbp + 8));
            rbp = *(uint64_t *)(rbp);
        }
    }
    ldr_hex("[loader] RBP=0x", (uint64_t)uc->uc_mcontext.gregs[REG_RBP]);
    ldr_hex("[loader] RAX=0x", (uint64_t)uc->uc_mcontext.gregs[REG_RAX]);
    ldr_hex("[loader] RDI=0x", (uint64_t)uc->uc_mcontext.gregs[REG_RDI]);
    ldr_hex("[loader] RSI=0x", (uint64_t)uc->uc_mcontext.gregs[REG_RSI]);
    ldr_hex("[loader] RDX=0x", (uint64_t)uc->uc_mcontext.gregs[REG_RDX]);
    ldr_hex("[loader] RCX=0x", (uint64_t)uc->uc_mcontext.gregs[REG_RCX]);
    ldr_hex("[loader] R8=0x",  (uint64_t)uc->uc_mcontext.gregs[REG_R8]);
    ldr_hex("[loader] R9=0x",  (uint64_t)uc->uc_mcontext.gregs[REG_R9]);
    ldr_hex("[loader] R13=0x", (uint64_t)uc->uc_mcontext.gregs[REG_R13]);
    if ((uint64_t)uc->uc_mcontext.gregs[REG_R9] > 0x1000) {
        uint64_t r9 = (uint64_t)uc->uc_mcontext.gregs[REG_R9];
        ldr_hex("[loader] *R9=0x", *(uint64_t *)r9);
        ldr_hex("[loader] *(R9+8)=0x", *(uint64_t *)(r9 + 8));
        ldr_hex("[loader] *(R9+16)=0x", *(uint64_t *)(r9 + 16));
    }
    if ((uint64_t)uc->uc_mcontext.gregs[REG_R13] > 0x1000) {
        uint64_t r13 = (uint64_t)uc->uc_mcontext.gregs[REG_R13];
        ldr_hex("[loader] *R13=0x", *(uint64_t *)r13);
        ldr_hex("[loader] *(R13+8)=0x", *(uint64_t *)(r13 + 8));
        ldr_hex("[loader] *(R13+16)=0x", *(uint64_t *)(r13 + 16));
        ldr_hex("[loader] *(R13+24)=0x", *(uint64_t *)(r13 + 24));
    }
#elif defined(__aarch64__)
    ldr_hex("[loader] PC=0x", (uint64_t)uc->uc_mcontext.pc);
    uint64_t rsp = (uint64_t)uc->uc_mcontext.sp;
    ldr_hex("[loader] SP=0x", rsp);
    if (rsp > 0x1000) {
        uint64_t fp = (uint64_t)uc->uc_mcontext.regs[29];
        ldr_msg("[loader] backtrace:\n");
        for (int f = 0; f < 15 && fp > 0x1000; f++) {
            ldr_hex("[loader]  frame ret=", *(uint64_t *)(fp + 8));
            fp = *(uint64_t *)(fp);
        }
    }
    ldr_hex("[loader] FP=0x",  (uint64_t)uc->uc_mcontext.regs[29]);
    ldr_hex("[loader] LR=0x",  (uint64_t)uc->uc_mcontext.regs[30]);
    ldr_hex("[loader] X0=0x",  (uint64_t)uc->uc_mcontext.regs[0]);
#endif
    /* Show thread pointer for TLS diagnosis */
    {
        uintptr_t fs_base = arch_get_tp_syscall();
        ldr_hex("[loader] TP=0x", fs_base);
        ldr_hex("[loader] gettid=", (uint64_t)syscall(SYS_gettid));
        /* Dump first 72 bytes of TCB (9 qwords: tcb,dtv,self,...,stack_guard,ptr_guard) */
        if (fs_base > 0x1000) {
            ldr_hex("[loader] tcb[0x00]=", *(uint64_t *)(fs_base + 0));
            ldr_hex("[loader] tcb[0x08]=", *(uint64_t *)(fs_base + 8));
            ldr_hex("[loader] tcb[0x10]=", *(uint64_t *)(fs_base + 16));
            ldr_hex("[loader] tcb[0x18]=", *(uint64_t *)(fs_base + 24));
            ldr_hex("[loader] tcb[0x20]=", *(uint64_t *)(fs_base + 32));
            ldr_hex("[loader] tcb[0x28]=", *(uint64_t *)(fs_base + 40));
            ldr_hex("[loader] tcb[0x30]=", *(uint64_t *)(fs_base + 48));
        }
    }
    /* Check if pointer_guard was corrupted */
    if (g_saved_ptr_guard) {
        ldr_hex("[loader] SAVED ptr_guard=", g_saved_ptr_guard);
        ldr_hex("[loader] ptr_guard_addr=", g_ptr_guard_addr);
        if (g_ptr_guard_addr > 0x1000) {
            ldr_hex("[loader] CURRENT *ptr_guard_addr=",
                    *(uint64_t *)g_ptr_guard_addr);
        }
    }
    if (sig == SIGABRT && g_arena_addr) {
        uintptr_t a = g_arena_addr;
        uintptr_t top = *(uint64_t *)(a + 0x08);
        ldr_hex("[loader] arena_top=0x", top);
        if (top > 0x1000) {
            ldr_hex("[loader] top_size=0x", *(uint64_t *)(top + 8));
        }
    }
    _exit(127);
}

static void install_crash_handlers(void)
{
    struct sigaction sa = {0};
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    for (int i = 0; i < CRASH_SIGNAL_COUNT; i++)
    guarded_sigaction(g_crash_signals[i], &sa, NULL);
}

static void capture_crash_handlers(struct sigaction *dst)
{
    for (int i = 0; i < CRASH_SIGNAL_COUNT; i++)
    guarded_sigaction(g_crash_signals[i], NULL, &dst[i]);
}

static void restore_crash_handlers(const struct sigaction *saved)
{
    for (int i = 0; i < CRASH_SIGNAL_COUNT; i++)
        guarded_sigaction(g_crash_signals[i], &saved[i], NULL);
}

static int vfs_sigaction(int signum, const struct sigaction *act,
                         struct sigaction *oldact)
{
    return guarded_sigaction(signum, act, oldact);
}

static signal_handler_t vfs_signal(int signum, signal_handler_t handler)
{
    return guarded_signal(signum, handler);
}

/* ---- fake _rtld_global / _rtld_global_ro for libc -------------------- */

/*
 * glibc's libc.so references _rtld_global and _rtld_global_ro (OBJECT
 * symbols normally provided by ld-linux.so).  We provide writable fake
 * copies with critical fields initialised so that malloc, stdio, etc.
 * work without the real dynamic linker.
 *
 * Field offsets are glibc-version-specific.  The struct layouts changed
 * significantly in glibc 2.40 (cpu_features restructured, hwcap_flags
 * and platforms arrays removed, tlsdesc fields added).
 *
 * We detect the layout at runtime by parsing the embedded ld-linux.so's
 * .dynsym for the _rtld_global_ro and _rtld_global OBJECT symbols.  Exact
 * known size pairs use validated profiles.  Unknown pairs are rejected:
 * total structure size does not reveal where glibc inserted new fields.
 *
 * To add a new glibc layout profile, use:
 *   gdb -batch -ex 'start' -ex 'ptype /o struct rtld_global_ro' /bin/true
 *   gdb -batch -ex 'start' -ex 'ptype /o struct rtld_global' /bin/true
 *   readelf --dyn-syms -W /lib64/ld-linux-x86-64.so.2 | grep _rtld_global
 */

/* Sizes for mmap allocation (generous, covers any glibc version) */
#define GLRO_SIZE        8192
#define GL_SIZE          8192

/* Version-independent offsets in _rtld_global_ro (stable across 2.35–2.43) */
#define GLRO_DL_PAGESIZE_OFF    24           /* offset 0x18             */
#define GLRO_DL_MINSIGSTKSZ_OFF 32           /* _dl_minsigstacksize     */
#define GLRO_DL_CLKTCK_OFF      64           /* offset 0x40             */
#define GLRO_DL_FPU_CONTROL_OFF 0x58         /* _dl_fpu_control         */
#define GLRO_DL_AUXV_OFF        104          /* _dl_auxv                */

/* Version-dependent offset profile for glibc _rtld_global{,_ro}.
 * Fields set to -1 are absent in that glibc version and skipped. */
struct glibc_ver_offsets {
    /* _rtld_global_ro (glro) */
    int glro_tls_static_size;   /* -1 if TLS fields are in _rtld_global */
    int glro_tls_static_align;
    int glro_debug_printf;
    int glro_mcount;
    int glro_open;
    int glro_close;
    int glro_catch_error;
    int glro_error_free;
    int glro_find_object;
    /* _rtld_global (gl) */
    int gl_tls_static_size;     /* -1 if TLS fields are in _rtld_global_ro */
    int gl_tls_static_align;
    int gl_nns;
    int gl_stack_flags;
    int gl_tls_generation;
    int gl_stack_used;
    int gl_stack_user;
    int gl_stack_cache;
    int gl_rtld_lock_recursive;   /* -1 if removed (glibc ≥ 2.34) */
    int gl_rtld_unlock_recursive;
    int gl_make_stack_executable; /* -1 if absent or unused */
    /* AArch64 struct pthread layout (per-glibc-version).  -1 keeps the
     * compiled-in default macro value.  Ignored on x86-64 (struct
     * pthread sits AT the TP there, not below it). */
    int pthread_size;             /* sizeof(struct pthread) */
    int pthread_tid_off;          /* offsetof(struct pthread, tid) */
    int pthread_rseq_off;         /* offsetof(struct pthread, rseq_area)
                                   * — set to -1 when no rseq area exists
                                   * (pre-glibc-2.34). */
    int pthread_rseq_cpu_id_off;  /* offsetof rseq_area.cpu_id */
};

/* glibc 2.17–2.28 (x86-64): _rtld_global_ro=440B, _rtld_global=3960B
 * TLS fields are in _rtld_global, not _rtld_global_ro.
 * No _dl_catch_error/_dl_error_free/_dl_find_object.
 * No _dl_stack_used/_dl_stack_user/_dl_stack_cache. */
static const struct glibc_ver_offsets glibc_2_17 = {
    /* x86-64: pthread struct layout fields are unused (TP points to
     * the head of struct pthread).  Leave all -1. */
    .pthread_size               = -1,
    .pthread_tid_off            = -1,
    .pthread_rseq_off           = -1,
    .pthread_rseq_cpu_id_off    = -1,
    .glro_tls_static_size  = -1,    /* TLS fields in _rtld_global */
    .glro_tls_static_align = -1,
    .glro_debug_printf     = 360,
    .glro_mcount           = 368,
    .glro_open             = 392,
    .glro_close            = 400,
    .glro_catch_error      = -1,
    .glro_error_free       = -1,
    .glro_find_object      = -1,
    .gl_tls_static_size    = 3896,
    .gl_tls_static_align   = 3912,
    .gl_nns                = 2304,
    .gl_stack_flags        = 3864,
    .gl_tls_generation     = 3928,
    .gl_stack_used         = -1,
    .gl_stack_user         = -1,
    .gl_stack_cache        = -1,
    .gl_rtld_lock_recursive   = 3840,  /* 0xf00 */
    .gl_rtld_unlock_recursive = 3848,  /* 0xf08 */
    .gl_make_stack_executable = -1,
};

/* glibc 2.29–2.33 (x86-64): _rtld_global_ro=536B, _rtld_global=3992B
 * Same structural pattern as 2.17: TLS fields in _rtld_global,
 * no catch_error/error_free/find_object, no stack lists. */
static const struct glibc_ver_offsets glibc_2_29 = {
    .pthread_size               = -1,
    .pthread_tid_off            = -1,
    .pthread_rseq_off           = -1,
    .pthread_rseq_cpu_id_off    = -1,
    .glro_tls_static_size  = -1,
    .glro_tls_static_align = -1,
    .glro_debug_printf     = 464,
    .glro_mcount           = 472,
    .glro_open             = 488,
    .glro_close            = 496,
    .glro_catch_error      = -1,
    .glro_error_free       = -1,
    .glro_find_object      = -1,
    .gl_tls_static_size    = 3928,
    .gl_tls_static_align   = 3944,
    .gl_nns                = 2304,
    .gl_stack_flags        = 3896,
    .gl_tls_generation     = 3960,
    .gl_stack_used         = -1,
    .gl_stack_user         = -1,
    .gl_stack_cache        = -1,
    .gl_rtld_lock_recursive   = 3848,  /* 0xf08 */
    .gl_rtld_unlock_recursive = 3856,  /* 0xf10 */
    .gl_make_stack_executable = -1,
};

/* glibc 2.31 Debian variant (x86-64): _rtld_global_ro=544B, _rtld_global=4000B
 * Debian 11 ships glibc 2.31 with a downstream patch that grows
 * _rtld_global_ro by 8 bytes (one extra word inserted before the
 * function-pointer block) and _rtld_global by 8 bytes.  The _rtld_global
 * field offsets we touch are unchanged versus 2.29, but every glro_*
 * function pointer is shifted by +8.  Confirmed by reading the live
 * struct on debian:11 amd64 (see /memories/repo). */
static const struct glibc_ver_offsets glibc_2_31_debian = {
    .pthread_size               = -1,
    .pthread_tid_off            = -1,
    .pthread_rseq_off           = -1,
    .pthread_rseq_cpu_id_off    = -1,
    .glro_tls_static_size  = -1,
    .glro_tls_static_align = -1,
    .glro_debug_printf     = 472,  /* 0x1d8 (was 0x1d0) */
    .glro_mcount           = 480,  /* 0x1e0 */
    .glro_open             = 496,  /* 0x1f0 */
    .glro_close            = 504,  /* 0x1f8 */
    .glro_catch_error      = -1,
    .glro_error_free       = -1,
    .glro_find_object      = -1,
    .gl_tls_static_size    = 3928,
    .gl_tls_static_align   = 3944,
    .gl_nns                = 2304,
    .gl_stack_flags        = 3896,
    .gl_tls_generation     = 3960,
    .gl_stack_used         = -1,
    .gl_stack_user         = -1,
    .gl_stack_cache        = -1,
    .gl_rtld_lock_recursive   = 3848,  /* 0xf08 */
    .gl_rtld_unlock_recursive = 3856,  /* 0xf10 */
    .gl_make_stack_executable = -1,
};

/* glibc 2.27 (AArch64): _rtld_global_ro=520B, _rtld_global=4088B
 * Older AArch64 glibc still routes _dl_addr through recursive lock
 * callbacks stored in _rtld_global, but their offsets differ from the
 * x86-64 layout.  The callbacks are tiny lock/unlock helpers in ld.so.
 * We stub them out because the frozen loader is single-threaded here.
 * _dl_make_stack_executable is also routed via _rtld_global. */
static const struct glibc_ver_offsets glibc_aarch64_2_27 = {
    /* AArch64 glibc 2.27: struct pthread is 0x710 bytes, no rseq area. */
    .pthread_size               = 0x710,
    .pthread_tid_off            = 0xd0,
    .pthread_rseq_off           = -1,
    .pthread_rseq_cpu_id_off    = -1,
    .glro_tls_static_size  = -1,
    .glro_tls_static_align = -1,
    .glro_debug_printf     = -1,
    .glro_mcount           = -1,
    .glro_open             = -1,
    .glro_close            = -1,
    .glro_catch_error      = -1,
    .glro_error_free       = -1,
    .glro_find_object      = -1,
    .gl_tls_static_size    = -1,
    .gl_tls_static_align   = -1,
    .gl_nns                = -1,
    .gl_stack_flags        = 0xa08,
    .gl_tls_generation     = -1,
    .gl_stack_used         = -1,
    .gl_stack_user         = -1,
    .gl_stack_cache        = -1,
    .gl_rtld_lock_recursive   = 0xf80,
    .gl_rtld_unlock_recursive = 0xf88,
    .gl_make_stack_executable = 0xf90,
};

/* glibc 2.31 (AArch64): _rtld_global_ro=624B, _rtld_global=4152B
 * Ubuntu 20.04 arm64 still uses the old _start path and expects the
 * recursive rtld lock callbacks plus _dl_make_stack_executable to be
 * present in _rtld_global.  The layout differs again from both x86-64
 * and glibc 2.27 AArch64, so detect it explicitly by ld.so symbol size. */
static const struct glibc_ver_offsets glibc_aarch64_2_31 = {
    /* AArch64 glibc 2.31 (Ubuntu 20.04): struct pthread is 0x720 bytes,
     * no rseq area yet.  TID at offset 0xd0. */
    .pthread_size               = 0x720,
    .pthread_tid_off            = 0xd0,
    .pthread_rseq_off           = -1,
    .pthread_rseq_cpu_id_off    = -1,
    .glro_tls_static_size  = -1,
    .glro_tls_static_align = -1,
    .glro_debug_printf     = -1,
    .glro_mcount           = -1,
    .glro_open             = -1,
    .glro_close            = -1,
    .glro_catch_error      = -1,
    .glro_error_free       = -1,
    .glro_find_object      = -1,
    .gl_tls_static_size    = -1,
    .gl_tls_static_align   = -1,
    .gl_nns                = -1,
    .gl_stack_flags        = -1,
    .gl_tls_generation     = -1,
    .gl_stack_used         = -1,
    .gl_stack_user         = -1,
    .gl_stack_cache        = -1,
    .gl_rtld_lock_recursive   = 0xfc0,
    .gl_rtld_unlock_recursive = 0xfc8,
    .gl_make_stack_executable = 0xfd0,
};

/* glibc 2.35 (AArch64): _rtld_global_ro=704B, _rtld_global=4488B
 * Ubuntu 22.04 arm64.  Its struct pthread is larger than later 2.36–2.40
 * layouts; pthread_self() subtracts 0x7c0, and rseq_area remains 0x20
 * bytes before TP. */
static const struct glibc_ver_offsets glibc_aarch64_2_35_large_pthread = {
    .pthread_size               = 0x7c0,
    .pthread_tid_off            = 0xd0,
    .pthread_rseq_off           = 0x7a0,
    .pthread_rseq_cpu_id_off    = 0x7a4,
    .glro_tls_static_size  = 472,   /* 0x1D8 */
    .glro_tls_static_align = 480,   /* 0x1E0 */
    .glro_debug_printf     = 592,   /* 0x250 */
    .glro_mcount           = 600,   /* 0x258 */
    .glro_open             = 616,   /* 0x268 */
    .glro_close            = 624,   /* 0x270 */
    .glro_catch_error      = 632,   /* 0x278 */
    .glro_error_free       = 640,   /* 0x280 */
    .glro_find_object      = 664,   /* 0x298 */
    .gl_tls_static_size    = -1,
    .gl_tls_static_align   = -1,
    .gl_nns                = 2688,  /* 0x0A80 */
    .gl_stack_flags        = 4344,  /* 0x10F8 */
    .gl_tls_generation     = 4400,  /* 0x1130 */
    .gl_stack_used         = 4416,  /* 0x1140 */
    .gl_stack_user         = 4432,  /* 0x1150 */
    .gl_stack_cache        = 4448,  /* 0x1160 */
    .gl_rtld_lock_recursive   = -1,
    .gl_rtld_unlock_recursive = -1,
    .gl_make_stack_executable = -1,
};

/* glibc 2.36–2.39 (AArch64): _rtld_global_ro=688B, _rtld_global=4504B
 * Ubuntu 24.04 arm64 (glibc 2.39) and similarly sized modern profiles.
 * Lock callbacks removed (same as x86-64 2.34+).
 * TLS static size/align fields now in _rtld_global_ro.
 * Offsets verified from Ubuntu 24.04 arm64 glibc 2.39 debug layout. */
static const struct glibc_ver_offsets glibc_aarch64_2_35 = {
    /* AArch64 glibc 2.35–2.39: struct pthread is 0x740, rseq area at
     * 0x720, cpu_id at 0x724. */
    .pthread_size               = 0x740,
    .pthread_tid_off            = 0xd0,
    .pthread_rseq_off           = 0x720,
    .pthread_rseq_cpu_id_off    = 0x724,
     .glro_tls_static_size  = 464,   /* 0x1D0 */
     .glro_tls_static_align = 472,   /* 0x1D8 */
    .glro_debug_printf     = 584,   /* 0x248 */
    .glro_mcount           = 592,   /* 0x250 */
    .glro_open             = 608,   /* 0x260 */
    .glro_close            = 616,   /* 0x268 */
    .glro_catch_error      = 624,   /* 0x270 */
    .glro_error_free       = 632,   /* 0x278 */
    .glro_find_object      = 656,   /* 0x290 */
    .gl_tls_static_size    = -1,
    .gl_tls_static_align   = -1,
    .gl_nns                = 2688,  /* 0x0A80 */
    .gl_stack_flags        = 4360,  /* 0x1108 */
    .gl_tls_generation     = 4416,  /* 0x1140 */
    .gl_stack_used         = 4432,  /* 0x1150 */
    .gl_stack_user         = 4448,  /* 0x1160 */
    .gl_stack_cache        = 4464,  /* 0x1170 */
    .gl_rtld_lock_recursive   = -1,
    .gl_rtld_unlock_recursive = -1,
    .gl_make_stack_executable = -1,
};

/* glibc 2.36 (AArch64): _rtld_global_ro=672B, _rtld_global=4520B
 * Debian 12 arm64 keeps the 0x740 pthread/rseq layout, but its rtld
 * structs differ from the 688/4504 AArch64 profile: glro function hooks
 * and gl stack/TLS fields sit 16 bytes earlier/later respectively. */
static const struct glibc_ver_offsets glibc_aarch64_2_36_debian = {
    .pthread_size               = 0x740,
    .pthread_tid_off            = 0xd0,
    .pthread_rseq_off           = 0x720,
    .pthread_rseq_cpu_id_off    = 0x724,
    .glro_tls_static_size  = 464,   /* 0x1D0 */
    .glro_tls_static_align = 472,   /* 0x1D8 */
    .glro_debug_printf     = 568,   /* 0x238 */
    .glro_mcount           = 576,   /* 0x240 */
    .glro_open             = 592,   /* 0x250 */
    .glro_close            = 600,   /* 0x258 */
    .glro_catch_error      = 608,   /* 0x260 */
    .glro_error_free       = 616,   /* 0x268 */
    .glro_find_object      = 640,   /* 0x280 */
    .gl_tls_static_size    = -1,
    .gl_tls_static_align   = -1,
    .gl_nns                = 2688,  /* 0x0A80 */
    .gl_stack_flags        = 4376,  /* 0x1118 */
    .gl_tls_generation     = 4432,  /* 0x1150 */
    .gl_stack_used         = 4448,  /* 0x1160 */
    .gl_stack_user         = 4464,  /* 0x1170 */
    .gl_stack_cache        = 4480,  /* 0x1180 */
    .gl_rtld_lock_recursive   = -1,
    .gl_rtld_unlock_recursive = -1,
    .gl_make_stack_executable = -1,
};

/* glibc 2.41 (AArch64): _rtld_global_ro=704B, _rtld_global=3040B
 * Debian trixie (glibc 2.41-12+deb13u2).  Compared to 2.35–2.39 (688/4504):
 *  - _dl_hwcap3, _dl_hwcap4 added in glro (+16 bytes)
 *  - TLS fields shifted +8 (after _dl_aarch64_cap_flags)
 *  - PTHREAD_IN_LIBC removed several gl fields, gl shrank from 4504→3040
 *  - struct pthread shrank to 0x720 and no longer has an rseq_area;
 *    using the old 0x740/rseq offsets aliases pthread exit_lock.
 * Verified via gdb -ex 'ptype /o struct rtld_global{,_ro}' and
 * 'ptype /o struct pthread' on debian:trixie arm64. */
static const struct glibc_ver_offsets glibc_aarch64_2_41 = {
    .pthread_size               = 0x720,
    .pthread_tid_off            = 0xd0,
    .pthread_rseq_off           = -1,
    .pthread_rseq_cpu_id_off    = -1,
    .glro_tls_static_size  = 472,   /* 0x1D8 */
    .glro_tls_static_align = 480,   /* 0x1E0 */
    .glro_debug_printf     = 600,   /* 0x258 */
    .glro_mcount           = 608,   /* 0x260 */
    .glro_open             = 624,   /* 0x270 */
    .glro_close            = 632,   /* 0x278 */
    .glro_catch_error      = 640,   /* 0x280 */
    .glro_error_free       = 648,   /* 0x288 */
    .glro_find_object      = 672,   /* 0x2A0 */
    .gl_tls_static_size    = -1,
    .gl_tls_static_align   = -1,
    .gl_nns                = 2688,  /* 0x0A80 */
    .gl_stack_flags        = 2896,  /* 0x0B50 */
    .gl_tls_generation     = 2952,  /* 0x0B88 */
    .gl_stack_used         = 2968,  /* 0x0B98 */
    .gl_stack_user         = 2984,  /* 0x0BA8 */
    .gl_stack_cache        = 3000,  /* 0x0BB8 */
    .gl_rtld_lock_recursive   = -1,
    .gl_rtld_unlock_recursive = -1,
    .gl_make_stack_executable = -1,
};

/* glibc 2.40 (AArch64): _rtld_global_ro=704B, _rtld_global=4504B
 * This is a hybrid between the 2.35-2.39 and 2.41 AArch64 layouts:
 * _rtld_global_ro has the new 704-byte shape, but _rtld_global still has
 * the older 4504-byte stack/TLS fields. */
static const struct glibc_ver_offsets glibc_aarch64_2_40_legacy_sized_rtld = {
    .pthread_size               = 0x740,
    .pthread_tid_off            = 0xd0,
    .pthread_rseq_off           = 0x720,
    .pthread_rseq_cpu_id_off    = 0x724,
    .glro_tls_static_size  = 472,   /* 0x1D8 */
    .glro_tls_static_align = 480,   /* 0x1E0 */
    .glro_debug_printf     = 600,   /* 0x258 */
    .glro_mcount           = 608,   /* 0x260 */
    .glro_open             = 624,   /* 0x270 */
    .glro_close            = 632,   /* 0x278 */
    .glro_catch_error      = 640,   /* 0x280 */
    .glro_error_free       = 648,   /* 0x288 */
    .glro_find_object      = 672,   /* 0x2A0 */
    .gl_tls_static_size    = -1,
    .gl_tls_static_align   = -1,
    .gl_nns                = 2688,  /* 0x0A80 */
    .gl_stack_flags        = 4360,  /* 0x1108 */
    .gl_tls_generation     = 4416,  /* 0x1140 */
    .gl_stack_used         = 4432,  /* 0x1150 */
    .gl_stack_user         = 4448,  /* 0x1160 */
    .gl_stack_cache        = 4464,  /* 0x1170 */
    .gl_rtld_lock_recursive   = -1,
    .gl_rtld_unlock_recursive = -1,
    .gl_make_stack_executable = -1,
};

/* glibc 2.43+ development (AArch64): _rtld_global_ro=400B,
 * _rtld_global=2272B.  The AArch64 hwcap name table moved out of glro,
 * making this much more compact than the 2.40/2.41 layouts. */
static const struct glibc_ver_offsets glibc_aarch64_2_43 = {
    .pthread_size               = 0x720,
    .pthread_tid_off            = 0xd0,
    .pthread_rseq_off           = -1,
    .pthread_rseq_cpu_id_off    = -1,
    .glro_tls_static_size  = 160,   /* 0x0A0 */
    .glro_tls_static_align = 168,   /* 0x0A8 */
    .glro_debug_printf     = 288,   /* 0x120 */
    .glro_mcount           = 296,   /* 0x128 */
    .glro_open             = 312,   /* 0x138 */
    .glro_close            = 320,   /* 0x140 */
    .glro_catch_error      = 328,   /* 0x148 */
    .glro_error_free       = 336,   /* 0x150 */
    .glro_find_object      = 360,   /* 0x168 */
    .gl_tls_static_size    = -1,
    .gl_tls_static_align   = -1,
    .gl_nns                = 1920,  /* 0x0780 */
    .gl_stack_flags        = 2128,  /* 0x0850 */
    .gl_tls_generation     = 2184,  /* 0x0888 */
    .gl_stack_used         = 2200,  /* 0x0898 */
    .gl_stack_user         = 2216,  /* 0x08A8 */
    .gl_stack_cache        = 2232,  /* 0x08B8 */
    .gl_rtld_lock_recursive   = -1,
    .gl_rtld_unlock_recursive = -1,
    .gl_make_stack_executable = -1,
};

/* glibc 2.34–2.36 (x86-64): _rtld_global_ro=928B, _rtld_global=4304B
 * TLS fields moved to _rtld_global_ro.  Has catch_error/error_free/
 * find_object.  Has stack lists.  Same glro layout as 2.40+ but
 * different (larger) _rtld_global. */
static const struct glibc_ver_offsets glibc_2_34 = {
    .pthread_size               = -1,
    .pthread_tid_off            = -1,
    .pthread_rseq_off           = -1,
    .pthread_rseq_cpu_id_off    = -1,
    .glro_tls_static_size  = 680,
    .glro_tls_static_align = 688,
    .glro_debug_printf     = 816,
    .glro_mcount           = 824,
    .glro_open             = 840,
    .glro_close            = 848,
    .glro_catch_error      = 856,
    .glro_error_free       = 864,
    .glro_find_object      = 888,
    .gl_tls_static_size    = -1,
    .gl_tls_static_align   = -1,
    .gl_nns                = 2560,
    .gl_stack_flags        = 4160,
    .gl_tls_generation     = 4216,
    .gl_stack_used         = 4232,
    .gl_stack_user         = 4248,
    .gl_stack_cache        = 4264,
    .gl_rtld_lock_recursive   = -1,
    .gl_rtld_unlock_recursive = -1,
    .gl_make_stack_executable = -1,
};

/* glibc 2.36 Debian 12 variant (x86-64): _rtld_global_ro=896B,
 * _rtld_global=4336B.  Similar generation to glibc_2_34, but the fields
 * used by pthread stack/TLS allocation are shifted by Debian's layout. */
static const struct glibc_ver_offsets glibc_2_36_debian = {
    .pthread_size               = -1,
    .pthread_tid_off            = -1,
    .pthread_rseq_off           = -1,
    .pthread_rseq_cpu_id_off    = -1,
    .glro_tls_static_size  = 672,   /* 0x2A0 */
    .glro_tls_static_align = 680,   /* 0x2A8 */
    .glro_debug_printf     = 792,   /* 0x318 */
    .glro_mcount           = 800,   /* 0x320 */
    .glro_open             = 816,   /* 0x330 */
    .glro_close            = 824,   /* 0x338 */
    .glro_catch_error      = 832,   /* 0x340 */
    .glro_error_free       = 840,   /* 0x348 */
    .glro_find_object      = 864,   /* 0x360 */
    .gl_tls_static_size    = -1,
    .gl_tls_static_align   = -1,
    .gl_nns                = 2560,  /* 0x0A00 */
    .gl_stack_flags        = 4192,  /* 0x1060 */
    .gl_tls_generation     = 4248,  /* 0x1098 */
    .gl_stack_used         = 4264,  /* 0x10A8 */
    .gl_stack_user         = 4280,  /* 0x10B8 */
    .gl_stack_cache        = 4296,  /* 0x10C8 */
    .gl_rtld_lock_recursive   = -1,
    .gl_rtld_unlock_recursive = -1,
    .gl_make_stack_executable = -1,
};

/* glibc 2.37–2.39 (x86-64): _rtld_global_ro=952B, _rtld_global=4352B */
static const struct glibc_ver_offsets glibc_2_37 = {
    .pthread_size               = -1,
    .pthread_tid_off            = -1,
    .pthread_rseq_off           = -1,
    .pthread_rseq_cpu_id_off    = -1,
    .glro_tls_static_size  = 712,   /* 0x2C8 */
    .glro_tls_static_align = 720,   /* 0x2D0 */
    .glro_debug_printf     = 848,
    .glro_mcount           = 856,
    .glro_open             = 872,
    .glro_close            = 880,
    .glro_catch_error      = 888,
    .glro_error_free       = 896,
    .glro_find_object      = 920,
    .gl_tls_static_size    = -1,
    .gl_tls_static_align   = -1,
    .gl_nns                = 2560,  /* 0xA00 */
    .gl_stack_flags        = 4208,  /* 0x1070 */
    .gl_tls_generation     = 4264,  /* 0x10A8 */
    .gl_stack_used         = 4280,  /* 0x10B8 */
    .gl_stack_user         = 4296,  /* 0x10C8 */
    .gl_stack_cache        = 4312,  /* 0x10D8 */
    .gl_rtld_lock_recursive   = -1,
    .gl_rtld_unlock_recursive = -1,
    .gl_make_stack_executable = -1,
};

/* glibc 2.40 with the legacy-sized x86-64 rtld structs:
 * _rtld_global_ro=952B, _rtld_global=4352B.  The public symbol sizes match
 * glibc 2.37-2.39, but pthread_create reads the TLS static fields one word
 * earlier in _rtld_global_ro.  Select this profile by the embedded
 * interpreter's GLIBC_2.40+ symbol-version strings, not by distro name. */
static const struct glibc_ver_offsets glibc_2_40_legacy_sized_rtld = {
    .pthread_size               = -1,
    .pthread_tid_off            = -1,
    .pthread_rseq_off           = -1,
    .pthread_rseq_cpu_id_off    = -1,
    .glro_tls_static_size  = 704,   /* 0x2C0 */
    .glro_tls_static_align = 712,   /* 0x2C8 */
    .glro_debug_printf     = 848,
    .glro_mcount           = 856,
    .glro_open             = 872,
    .glro_close            = 880,
    .glro_catch_error      = 888,
    .glro_error_free       = 896,
    .glro_find_object      = 920,
    .gl_tls_static_size    = -1,
    .gl_tls_static_align   = -1,
    .gl_nns                = 2560,  /* 0xA00 */
    .gl_stack_flags        = 4208,  /* 0x1070 */
    .gl_tls_generation     = 4264,  /* 0x10A8 */
    .gl_stack_used         = 4280,  /* 0x10B8 */
    .gl_stack_user         = 4296,  /* 0x10C8 */
    .gl_stack_cache        = 4312,  /* 0x10D8 */
    .gl_rtld_lock_recursive   = -1,
    .gl_rtld_unlock_recursive = -1,
    .gl_make_stack_executable = -1,
};

/* glibc 2.40+ (x86-64): _rtld_global_ro=928B, _rtld_global=2120B */
static const struct glibc_ver_offsets glibc_2_40 = {
    .pthread_size               = -1,
    .pthread_tid_off            = -1,
    .pthread_rseq_off           = -1,
    .pthread_rseq_cpu_id_off    = -1,
    .glro_tls_static_size  = 672,   /* 0x2A0 */
    .glro_tls_static_align = 680,   /* 0x2A8 */
    .glro_debug_printf     = 816,
    .glro_mcount           = 824,
    .glro_open             = 840,
    .glro_close            = 848,
    .glro_catch_error      = 856,
    .glro_error_free       = 864,
    .glro_find_object      = 888,
    .gl_tls_static_size    = -1,
    .gl_tls_static_align   = -1,
    .gl_nns                = 1792,  /* 0x700 */
    .gl_stack_flags        = 1976,  /* 0x7B8 */
    .gl_tls_generation     = 2032,  /* 0x7F0 */
    .gl_stack_used         = 2048,  /* 0x800 */
    .gl_stack_user         = 2064,  /* 0x810 */
    .gl_stack_cache        = 2080,  /* 0x820 */
    .gl_rtld_lock_recursive   = -1,
    .gl_rtld_unlock_recursive = -1,
    .gl_make_stack_executable = -1,
};

/* glibc 2.41 Debian/trixie (x86-64): _rtld_global_ro=952B, _rtld_global=2888B
 *
 * This is a hybrid layout: glro is the larger "pre-2.40" size (952) because
 * the cpu_features struct retains its older size, but gl is the smaller
 * "post-2.40" layout (2888) because the trailing pthread/dl_load_lock
 * compatibility fields were trimmed in 2.40.  Field offsets verified with
 *   gdb -batch -ex 'ptype /o struct rtld_global_ro' \
 *               -ex 'ptype /o struct rtld_global' /lib64/ld-linux-x86-64.so.2
 * on debian:trixie (glibc 2.41-12+deb13u2).
 */
static const struct glibc_ver_offsets glibc_2_41_debian = {
    .pthread_size               = -1,
    .pthread_tid_off            = -1,
    .pthread_rseq_off           = -1,
    .pthread_rseq_cpu_id_off    = -1,
    .glro_tls_static_size  = 704,   /* 0x2C0 */
    .glro_tls_static_align = 712,   /* 0x2C8 */
    .glro_debug_printf     = 848,
    .glro_mcount           = 856,
    .glro_open             = 872,
    .glro_close            = 880,
    .glro_catch_error      = 888,
    .glro_error_free       = 896,
    .glro_find_object      = 920,
    .gl_tls_static_size    = -1,
    .gl_tls_static_align   = -1,
    .gl_nns                = 2560,  /* 0xA00 */
    .gl_stack_flags        = 2744,  /* 0xAB8 */
    .gl_tls_generation     = 2800,  /* 0xAF0 */
    .gl_stack_used         = 2816,  /* 0xB00 */
    .gl_stack_user         = 2832,  /* 0xB10 */
    .gl_stack_cache        = 2848,  /* 0xB20 */
    .gl_rtld_lock_recursive   = -1,
    .gl_rtld_unlock_recursive = -1,
    .gl_make_stack_executable = -1,
};

static uint8_t *g_fake_rtld_global;
static uint8_t *g_fake_rtld_global_ro;
static const struct glibc_ver_offsets *g_glibc_off;
static int g_glibc_rtld_fixed;
static int g_glibc_minor = -1;
static size_t g_tls_static_size = 0x1080;
static size_t g_tls_static_align = 0x40;

/* Some glibc startup and thread paths read __libc_stack_end from ld-linux.
 * Direct-load mode does not map the real
 * interpreter, so provide loader-owned storage for that symbol. */
static void *g_fake_libc_stack_end;
static int g_fake_libc_enable_secure;
static char **g_fake_dl_argv;
static uintptr_t g_fake_stack_chk_guard;
static uintptr_t g_fake_pointer_chk_guard;

/* Fake link_map used by __cxa_thread_atexit_impl and other glibc internals
 * that dereference _rtld_global._dl_ns[0]._ns_loaded (offset 0).
 * Only the reference counter at link_map + 0x498 needs to be writable. */
static uint8_t g_fake_link_map[0x500] __attribute__((aligned(64)));

/* ---- rseq stub variables (replace ld-linux's __rseq_*) --------------- */
/*
 * glibc 2.35+ uses __rseq_offset / __rseq_size / __rseq_flags (defined
 * in ld-linux) to register restartable sequences per thread.  Since
 * ld-linux is not mapped in frozen binaries, libc's GOT slots for these
 * point to zero-filled anonymous memory, causing rseq to register at
 * offset 0 (= the TCB itself).  On thread cleanup glibc memsets the
 * rseq area, destroying the TCB and causing SIGSEGV.
 *
 * We provide our own copies.  For layouts with a real pthread rseq area,
 * __rseq_offset is set at runtime once the static TLS layout is known and
 * __rseq_size remains 32, the minimum kernel rseq struct size.  For known
 * no-rseq pthread layouts, setup_tls() sets __rseq_size to 0, uses safe
 * pthread padding as synthetic cpu-id storage, and clears glibc's per-thread
 * rseq-registered bit before the thread startup path reaches the syscall.
 */
static int64_t  g_rseq_offset = -160;
static uint32_t g_rseq_size   = 32;
static uint32_t g_rseq_flags  = 0;

/* ---- _rtld_global_ro function-pointer stubs (dl* wrappers) ----------- */
/*
 * glibc's libc.so calls dlopen / dlsym / dlclose / dlerror through
 * function pointers stored in _rtld_global_ro (the real pointers are
 * set by ld-linux.so at process startup).  Without the real dynamic
 * linker these slots are NULL.  A call through libc's dlopen →
 * _dlerror_run → GLRO(dl_catch_error)(…) dereferences offset
 * 856 → calls address 0 → SIGSEGV at RIP=0x0.
 *
 * Providing minimal stubs that return "error" makes dlopen() return
 * NULL and dlerror() return an explanatory message.
 */

/* _dl_catch_error — called by _dlerror_run for every dl* function.
 * Return non-zero immediately (error) without invoking operate(). */
static int glro_dl_catch_error(const char **objname, const char **errstring,
                               _Bool *malloced,
                               void (*operate)(void *), void *args)
{
    (void)operate; (void)args;
    static const char msg[] = "dlopen/dlsym not available (frozen binary)";
    if (objname)   *objname   = "";
    if (errstring) *errstring = msg;
    if (malloced)  *malloced  = 0;
    return 1; /* non-zero = error */
}

/* _dl_open — should never be reached (caught by _dl_catch_error above)
 * but provide a stub just in case. */
static void *glro_dl_open(const char *name, int mode, const void *caller,
                           long ns, int argc, char **argv, char **env)
{
    (void)name; (void)mode; (void)caller; (void)ns;
    (void)argc; (void)argv; (void)env;
    return NULL;
}

/* _dl_close — no-op */
static void glro_dl_close(void *map) { (void)map; }

/* _dl_error_free — no-op (our error strings are static) */
static void glro_dl_error_free(void *ptr) { (void)ptr; }

/* _dl_debug_printf — no-op (suppress ld.so debug spew) */
static void glro_dl_debug_printf(const char *fmt, ...) { (void)fmt; }

/* _dl_find_object — forward declaration (impl after struct loaded_obj) */
static int glro_dl_find_object(void *pc, void *result);

/* _dl_mcount — no-op profiling hook */
static void glro_dl_mcount(uintptr_t from, uintptr_t to)
{
    (void)from; (void)to;
}

/* _dl_rtld_lock_recursive / _dl_rtld_unlock_recursive — no-op lock stubs.
 * In glibc < 2.34, _rtld_global contains function pointers for recursive
 * locking of _dl_load_lock used by _dl_addr, dlopen, etc.  In a frozen
 * single-threaded binary, locking is unnecessary. */
static void glro_dl_lock_noop(void *lock)
{
    (void)lock;
}

static int glro_dl_make_stack_executable(const void *stack_endp)
{
    (void)stack_endp;
    return 0;
}

static int glibc_direct_main_without_early_init_ok(void)
{
    return 1;
}

/* make a list_t {next, prev} point to itself (empty circular list) */
static void init_empty_list(uint8_t *base, size_t off)
{
    uintptr_t addr = (uintptr_t)(base + off);
    *(uintptr_t *)(base + off)     = addr;  /* next */
    *(uintptr_t *)(base + off + 8) = addr;  /* prev */
}

#if defined(__x86_64__)
#define X86_CPUF_BASE              0x70
#define X86_CPUF_BASIC_KIND        0
#define X86_CPUF_BASIC_MAX_CPUID   4
#define X86_CPUF_BASIC_FAMILY      8
#define X86_CPUF_BASIC_MODEL       12
#define X86_CPUF_BASIC_STEPPING    16
#define X86_CPUF_FEATURES          20
#define X86_CPUF_FEATURE_SIZE      32
#define X86_CPUF_MAX_FEATURES      10

#define X86_CPUID_INDEX_1          0
#define X86_CPUID_INDEX_7          1
#define X86_CPUID_INDEX_80000001   2
#define X86_CPUID_INDEX_D_ECX_1    3
#define X86_CPUID_INDEX_80000007   4
#define X86_CPUID_INDEX_80000008   5
#define X86_CPUID_INDEX_7_ECX_1    6
#define X86_CPUID_INDEX_19         7
#define X86_CPUID_INDEX_14_ECX_0   8
#define X86_CPUID_INDEX_24_ECX_0   9

struct x86_cpu_features_layout {
    int feature_count;
    int preferred;
    int isa_1;
    int xsave_state_size;
    int xsave_state_full_size;
    int data_cache_size;
    int shared_cache_size;
    int non_temporal_threshold;
    int memset_non_temporal_threshold;
    int rep_movsb_threshold;
    int rep_movsb_stop_threshold;
    int rep_stosb_threshold;
};

struct x86_cpuid_feature_regs {
    uint32_t cpuid_eax;
    uint32_t cpuid_ebx;
    uint32_t cpuid_ecx;
    uint32_t cpuid_edx;
    uint32_t active_eax;
    uint32_t active_ebx;
    uint32_t active_ecx;
    uint32_t active_edx;
};

static const struct x86_cpu_features_layout x86_cpuf_initial_layout = {
    .feature_count = 2,
    .preferred = -1,
    .isa_1 = -1,
    .xsave_state_size = -1,
    .xsave_state_full_size = -1,
    .data_cache_size = -1,
    .shared_cache_size = -1,
    .non_temporal_threshold = -1,
    .memset_non_temporal_threshold = -1,
    .rep_movsb_threshold = -1,
    .rep_movsb_stop_threshold = -1,
    .rep_stosb_threshold = -1,
};

static const struct x86_cpu_features_layout x86_cpuf_layout_2_34_2_38 = {
    .feature_count = 9,
    .preferred = 308,
    .isa_1 = 312,
    .xsave_state_size = 320,
    .xsave_state_full_size = 328,
    .data_cache_size = 336,
    .shared_cache_size = 344,
    .non_temporal_threshold = 352,
    .memset_non_temporal_threshold = -1,
    .rep_movsb_threshold = 360,
    .rep_movsb_stop_threshold = 368,
    .rep_stosb_threshold = 376,
};

static const struct x86_cpu_features_layout x86_cpuf_layout_2_39_plus = {
    .feature_count = 10,
    .preferred = 340,
    .isa_1 = 344,
    .xsave_state_size = 352,
    .xsave_state_full_size = 360,
    .data_cache_size = 368,
    .shared_cache_size = 376,
    .non_temporal_threshold = 384,
    .memset_non_temporal_threshold = 392,
    .rep_movsb_threshold = 400,
    .rep_movsb_stop_threshold = 408,
    .rep_stosb_threshold = 416,
};

static void x86_cpuid_count(uint32_t leaf, uint32_t subleaf,
                            uint32_t *cpuid_eax, uint32_t *cpuid_ebx,
                            uint32_t *cpuid_ecx, uint32_t *cpuid_edx)
{
    __asm__ volatile("cpuid"
                     : "=a"(*cpuid_eax), "=b"(*cpuid_ebx),
                       "=c"(*cpuid_ecx), "=d"(*cpuid_edx)
                     : "a"(leaf), "c"(subleaf));
}

static uint64_t x86_xgetbv0(void)
{
    uint32_t xcr0_low;
    uint32_t xcr0_high;

    __asm__ volatile(".byte 0x0f, 0x01, 0xd0"
                     : "=a"(xcr0_low), "=d"(xcr0_high)
                     : "c"(0));
    return ((uint64_t)xcr0_high << 32) | xcr0_low;
}

static int x86_cpuf_offset_ok(int offset, size_t width)
{
    return offset >= 0 && (size_t)offset + width <= GLRO_SIZE - X86_CPUF_BASE;
}

static void x86_cpuf_store_u32(int offset, uint32_t value)
{
    if (x86_cpuf_offset_ok(offset, sizeof(uint32_t)))
        *(uint32_t *)(g_fake_rtld_global_ro + X86_CPUF_BASE + offset) = value;
}

static void x86_cpuf_store_size(int offset, size_t value)
{
    if (x86_cpuf_offset_ok(offset, sizeof(size_t)))
        *(size_t *)(g_fake_rtld_global_ro + X86_CPUF_BASE + offset) = value;
}

static void x86_cpuf_store_feature(
    const struct x86_cpu_features_layout *layout,
    int feature_index,
    const struct x86_cpuid_feature_regs *feature)
{
    uint8_t *slot;

    if (feature_index < 0 || feature_index >= layout->feature_count)
        return;
    if (!x86_cpuf_offset_ok(X86_CPUF_FEATURES +
                            feature_index * X86_CPUF_FEATURE_SIZE,
                            X86_CPUF_FEATURE_SIZE))
        return;

    slot = g_fake_rtld_global_ro + X86_CPUF_BASE + X86_CPUF_FEATURES +
           feature_index * X86_CPUF_FEATURE_SIZE;
    *(uint32_t *)(slot + 0)  = feature->cpuid_eax;
    *(uint32_t *)(slot + 4)  = feature->cpuid_ebx;
    *(uint32_t *)(slot + 8)  = feature->cpuid_ecx;
    *(uint32_t *)(slot + 12) = feature->cpuid_edx;
    *(uint32_t *)(slot + 16) = feature->active_eax;
    *(uint32_t *)(slot + 20) = feature->active_ebx;
    *(uint32_t *)(slot + 24) = feature->active_ecx;
    *(uint32_t *)(slot + 28) = feature->active_edx;
}

static const struct x86_cpu_features_layout *
x86_cpu_features_layout_for_glibc(const struct glibc_ver_offsets *glibc_offsets)
{
    if (g_glibc_minor >= 39 ||
        glibc_offsets == &glibc_2_40 ||
        glibc_offsets == &glibc_2_40_legacy_sized_rtld ||
        glibc_offsets == &glibc_2_41_debian)
        return &x86_cpuf_layout_2_39_plus;
    return &x86_cpuf_layout_2_34_2_38;
}

static uint32_t x86_cpu_kind_from_vendor(uint32_t vendor_ebx,
                                         uint32_t vendor_edx,
                                         uint32_t vendor_ecx)
{
    if (vendor_ebx == 0x756e6547u && vendor_edx == 0x49656e69u &&
        vendor_ecx == 0x6c65746eu)
        return 1;  /* arch_kind_intel */
    if (vendor_ebx == 0x68747541u && vendor_edx == 0x69746e65u &&
        vendor_ecx == 0x444d4163u)
        return 2;  /* arch_kind_amd */
    if (vendor_ebx == 0x746e6543u && vendor_edx == 0x48727561u &&
        vendor_ecx == 0x736c7561u)
        return 3;  /* arch_kind_zhaoxin */
    if (vendor_ebx == 0x6f677948u && vendor_edx == 0x6e65476eu &&
        vendor_ecx == 0x656e6975u)
        return 4;  /* arch_kind_hygon */
    return 5;      /* arch_kind_other */
}

static void x86_cpuf_record_leaf(struct x86_cpuid_feature_regs *feature,
                                 uint32_t cpuid_eax, uint32_t cpuid_ebx,
                                 uint32_t cpuid_ecx, uint32_t cpuid_edx)
{
    feature->cpuid_eax = cpuid_eax;
    feature->cpuid_ebx = cpuid_ebx;
    feature->cpuid_ecx = cpuid_ecx;
    feature->cpuid_edx = cpuid_edx;
    feature->active_eax = cpuid_eax;
    feature->active_ebx = cpuid_ebx;
    feature->active_ecx = cpuid_ecx;
    feature->active_edx = cpuid_edx;
}

static void x86_detect_cache_sizes(uint32_t max_leaf, uint32_t max_ext_leaf,
                                   size_t *data_cache_size,
                                   size_t *shared_cache_size)
{
    uint64_t detected_l1_data = 32u * 1024u;
    uint64_t detected_shared = 2u * 1024u * 1024u;

    if (max_leaf >= 4) {
        for (uint32_t cache_index = 0; cache_index < 32; cache_index++) {
            uint32_t cpuid_eax;
            uint32_t cpuid_ebx;
            uint32_t cpuid_ecx;
            uint32_t cpuid_edx;
            uint32_t cache_type;
            uint32_t cache_level;
            uint64_t line_size;
            uint64_t partitions;
            uint64_t ways;
            uint64_t sets;
            uint64_t cache_size;

            x86_cpuid_count(4, cache_index, &cpuid_eax, &cpuid_ebx,
                            &cpuid_ecx, &cpuid_edx);
            (void)cpuid_edx;
            cache_type = cpuid_eax & 0x1fu;
            if (cache_type == 0)
                break;
            cache_level = (cpuid_eax >> 5) & 0x7u;
            line_size = (cpuid_ebx & 0xfffu) + 1u;
            partitions = ((cpuid_ebx >> 12) & 0x3ffu) + 1u;
            ways = ((cpuid_ebx >> 22) & 0x3ffu) + 1u;
            sets = (uint64_t)cpuid_ecx + 1u;
            cache_size = line_size * partitions * ways * sets;

            if (cache_type == 1 && cache_level == 1 && cache_size > 0)
                detected_l1_data = cache_size;
            if (cache_level >= 2 && cache_size > detected_shared)
                detected_shared = cache_size;
        }
    }

    if (max_ext_leaf >= 0x8000001du) {
        for (uint32_t cache_index = 0; cache_index < 32; cache_index++) {
            uint32_t cpuid_eax;
            uint32_t cpuid_ebx;
            uint32_t cpuid_ecx;
            uint32_t cpuid_edx;
            uint32_t cache_type;
            uint32_t cache_level;
            uint64_t line_size;
            uint64_t partitions;
            uint64_t ways;
            uint64_t sets;
            uint64_t cache_size;

            x86_cpuid_count(0x8000001du, cache_index, &cpuid_eax,
                            &cpuid_ebx, &cpuid_ecx, &cpuid_edx);
            (void)cpuid_edx;
            cache_type = cpuid_eax & 0x1fu;
            if (cache_type == 0)
                break;
            cache_level = (cpuid_eax >> 5) & 0x7u;
            line_size = (cpuid_ebx & 0xfffu) + 1u;
            partitions = ((cpuid_ebx >> 12) & 0x3ffu) + 1u;
            ways = ((cpuid_ebx >> 22) & 0x3ffu) + 1u;
            sets = (uint64_t)cpuid_ecx + 1u;
            cache_size = line_size * partitions * ways * sets;

            if (cache_type == 1 && cache_level == 1 && cache_size > 0)
                detected_l1_data = cache_size;
            if (cache_level >= 2 && cache_size > detected_shared)
                detected_shared = cache_size;
        }
    } else if (max_ext_leaf >= 0x80000006u) {
        uint32_t cpuid_eax;
        uint32_t cpuid_ebx;
        uint32_t cpuid_ecx;
        uint32_t cpuid_edx;
        uint64_t l2_size;
        uint64_t l3_size;

        x86_cpuid_count(0x80000006u, 0, &cpuid_eax, &cpuid_ebx,
                        &cpuid_ecx, &cpuid_edx);
        (void)cpuid_eax;
        (void)cpuid_ebx;
        l2_size = ((uint64_t)(cpuid_ecx >> 16) & 0xffffu) * 1024u;
        l3_size = ((uint64_t)(cpuid_edx >> 18) & 0x3fffu) * 512u * 1024u;
        if (l2_size > detected_shared)
            detected_shared = l2_size;
        if (l3_size > detected_shared)
            detected_shared = l3_size;
    }

    *data_cache_size = (size_t)detected_l1_data;
    *shared_cache_size = (size_t)detected_shared;
}

static uint32_t x86_compute_isa_1(
    const struct x86_cpuid_feature_regs features[X86_CPUF_MAX_FEATURES])
{
    const uint32_t leaf1_ecx = features[X86_CPUID_INDEX_1].active_ecx;
    const uint32_t leaf1_edx = features[X86_CPUID_INDEX_1].active_edx;
    const uint32_t leaf7_ebx = features[X86_CPUID_INDEX_7].active_ebx;
    const uint32_t ext1_ecx = features[X86_CPUID_INDEX_80000001].active_ecx;
    uint32_t isa_1 = 0;
    const uint32_t baseline_edx = (1u << 0) | (1u << 8) | (1u << 15) |
                                  (1u << 23) | (1u << 24) | (1u << 25) |
                                  (1u << 26);
    const uint32_t v2_ecx = (1u << 0) | (1u << 9) | (1u << 13) |
                            (1u << 19) | (1u << 20) | (1u << 23);
    const uint32_t v3_ecx = (1u << 12) | (1u << 22) | (1u << 28) |
                            (1u << 29);
    const uint32_t v3_ebx = (1u << 3) | (1u << 5) | (1u << 8);
    const uint32_t v4_ebx = (1u << 16) | (1u << 17) | (1u << 28) |
                            (1u << 30) | (1u << 31);

    if ((leaf1_edx & baseline_edx) == baseline_edx)
        isa_1 |= 1u << 0;
    if ((isa_1 & (1u << 0)) && (leaf1_ecx & v2_ecx) == v2_ecx &&
        (ext1_ecx & (1u << 0)))
        isa_1 |= 1u << 1;
    if ((isa_1 & (1u << 1)) && (leaf1_ecx & v3_ecx) == v3_ecx &&
        (leaf7_ebx & v3_ebx) == v3_ebx && (ext1_ecx & (1u << 5)))
        isa_1 |= 1u << 2;
    if ((isa_1 & (1u << 2)) && (leaf7_ebx & v4_ebx) == v4_ebx)
        isa_1 |= 1u << 3;
    return isa_1;
}

static void init_x86_cpu_features(const struct glibc_ver_offsets *glibc_offsets,
                                  int layout_known)
{
    const struct x86_cpu_features_layout *layout = layout_known
        ? x86_cpu_features_layout_for_glibc(glibc_offsets)
        : &x86_cpuf_initial_layout;
    struct x86_cpuid_feature_regs features[X86_CPUF_MAX_FEATURES];
    uint32_t cpuid_eax;
    uint32_t cpuid_ebx;
    uint32_t cpuid_ecx;
    uint32_t cpuid_edx;
    uint32_t max_leaf;
    uint32_t max_ext_leaf = 0;
    uint32_t leaf7_max_subleaf = 0;
    uint64_t xcr0 = 0;
    int has_osxsave = 0;
    int has_avx_state = 0;
    int has_avx512_state = 0;
    int has_amx_state = 0;
    size_t data_cache_size = 32u * 1024u;
    size_t shared_cache_size = 2u * 1024u * 1024u;
    size_t non_temporal_threshold;
    size_t rep_movsb_stop_threshold;
    uint32_t xsave_state_size = 512;
    uint32_t xsave_state_full_size = 512;

    memset(features, 0, sizeof(features));
    memset(g_fake_rtld_global_ro + X86_CPUF_BASE, 0, 640);

    x86_cpuid_count(0, 0, &cpuid_eax, &cpuid_ebx, &cpuid_ecx, &cpuid_edx);
    max_leaf = cpuid_eax;
    x86_cpuf_store_u32(X86_CPUF_BASIC_KIND,
                       x86_cpu_kind_from_vendor(cpuid_ebx, cpuid_edx,
                                                cpuid_ecx));
    x86_cpuf_store_u32(X86_CPUF_BASIC_MAX_CPUID, max_leaf);

    x86_cpuid_count(0x80000000u, 0, &cpuid_eax, &cpuid_ebx,
                    &cpuid_ecx, &cpuid_edx);
    if (cpuid_eax >= 0x80000000u)
        max_ext_leaf = cpuid_eax;

    if (max_leaf >= 1) {
        uint32_t family;
        uint32_t model;

        x86_cpuid_count(1, 0, &cpuid_eax, &cpuid_ebx, &cpuid_ecx,
                        &cpuid_edx);
        x86_cpuf_record_leaf(&features[X86_CPUID_INDEX_1], cpuid_eax,
                             cpuid_ebx, cpuid_ecx, cpuid_edx);
        family = (cpuid_eax >> 8) & 0xfu;
        model = (cpuid_eax >> 4) & 0xfu;
        if (family == 6 || family == 15)
            model += ((cpuid_eax >> 16) & 0xfu) << 4;
        if (family == 15)
            family += (cpuid_eax >> 20) & 0xffu;
        x86_cpuf_store_u32(X86_CPUF_BASIC_FAMILY, family);
        x86_cpuf_store_u32(X86_CPUF_BASIC_MODEL, model);
        x86_cpuf_store_u32(X86_CPUF_BASIC_STEPPING, cpuid_eax & 0xfu);

        has_osxsave = (cpuid_ecx & ((1u << 26) | (1u << 27))) ==
                      ((1u << 26) | (1u << 27));
        if (has_osxsave)
            xcr0 = x86_xgetbv0();
        has_avx_state = layout_known && has_osxsave && ((xcr0 & 0x7u) == 0x7u);
        has_avx512_state = has_avx_state && ((xcr0 & 0xe0u) == 0xe0u);
        has_amx_state = layout_known && has_osxsave &&
                        ((xcr0 & ((1ull << 17) | (1ull << 18))) ==
                         ((1ull << 17) | (1ull << 18)));

        if (!has_osxsave)
            features[X86_CPUID_INDEX_1].active_ecx &=
                ~((1u << 26) | (1u << 27));
        if (!has_avx_state)
            features[X86_CPUID_INDEX_1].active_ecx &=
                ~((1u << 12) | (1u << 28) | (1u << 29));
    }

    if (max_leaf >= 7) {
        const uint32_t leaf7_ebx_avx512 = (1u << 16) | (1u << 17) |
                                          (1u << 21) | (1u << 26) |
                                          (1u << 27) | (1u << 28) |
                                          (1u << 30) | (1u << 31);
        const uint32_t leaf7_ecx_avx512 = (1u << 1) | (1u << 6) |
                                          (1u << 11) | (1u << 12) |
                                          (1u << 14);
        const uint32_t leaf7_edx_avx512 = (1u << 2) | (1u << 3) |
                                          (1u << 8) | (1u << 23);

        x86_cpuid_count(7, 0, &cpuid_eax, &cpuid_ebx, &cpuid_ecx,
                        &cpuid_edx);
        leaf7_max_subleaf = cpuid_eax;
        x86_cpuf_record_leaf(&features[X86_CPUID_INDEX_7], cpuid_eax,
                             cpuid_ebx, cpuid_ecx, cpuid_edx);
        if (!has_avx_state) {
            features[X86_CPUID_INDEX_7].active_ebx &= ~(1u << 5);
            features[X86_CPUID_INDEX_7].active_ecx &= ~((1u << 9) |
                                                        (1u << 10));
        }
        if (!has_avx512_state) {
            features[X86_CPUID_INDEX_7].active_ebx &= ~leaf7_ebx_avx512;
            features[X86_CPUID_INDEX_7].active_ecx &= ~leaf7_ecx_avx512;
            features[X86_CPUID_INDEX_7].active_edx &= ~leaf7_edx_avx512;
        }
        if (!has_amx_state)
            features[X86_CPUID_INDEX_7].active_edx &=
                ~((1u << 22) | (1u << 24) | (1u << 25));
    }

    if (max_ext_leaf >= 0x80000001u) {
        x86_cpuid_count(0x80000001u, 0, &cpuid_eax, &cpuid_ebx,
                        &cpuid_ecx, &cpuid_edx);
        x86_cpuf_record_leaf(&features[X86_CPUID_INDEX_80000001], cpuid_eax,
                             cpuid_ebx, cpuid_ecx, cpuid_edx);
        if (!has_avx_state)
            features[X86_CPUID_INDEX_80000001].active_ecx &=
                ~((1u << 11) | (1u << 16));
    }

    if (max_leaf >= 0xdu &&
        (features[X86_CPUID_INDEX_1].cpuid_ecx & (1u << 26))) {
        x86_cpuid_count(0xdu, 0, &cpuid_eax, &cpuid_ebx,
                        &cpuid_ecx, &cpuid_edx);
        if (has_osxsave) {
            xsave_state_size = cpuid_ebx ? cpuid_ebx : 512;
            xsave_state_full_size = cpuid_ecx ? cpuid_ecx : xsave_state_size;
        }
        x86_cpuid_count(0xdu, 1, &cpuid_eax, &cpuid_ebx,
                        &cpuid_ecx, &cpuid_edx);
        x86_cpuf_record_leaf(&features[X86_CPUID_INDEX_D_ECX_1], cpuid_eax,
                             cpuid_ebx, cpuid_ecx, cpuid_edx);
        if (!has_osxsave) {
            features[X86_CPUID_INDEX_D_ECX_1].active_eax = 0;
            features[X86_CPUID_INDEX_D_ECX_1].active_ebx = 0;
            features[X86_CPUID_INDEX_D_ECX_1].active_ecx = 0;
            features[X86_CPUID_INDEX_D_ECX_1].active_edx = 0;
        }
    }

    if (max_ext_leaf >= 0x80000007u) {
        x86_cpuid_count(0x80000007u, 0, &cpuid_eax, &cpuid_ebx,
                        &cpuid_ecx, &cpuid_edx);
        x86_cpuf_record_leaf(&features[X86_CPUID_INDEX_80000007], cpuid_eax,
                             cpuid_ebx, cpuid_ecx, cpuid_edx);
    }

    if (max_ext_leaf >= 0x80000008u) {
        x86_cpuid_count(0x80000008u, 0, &cpuid_eax, &cpuid_ebx,
                        &cpuid_ecx, &cpuid_edx);
        x86_cpuf_record_leaf(&features[X86_CPUID_INDEX_80000008], cpuid_eax,
                             cpuid_ebx, cpuid_ecx, cpuid_edx);
    }

    if (max_leaf >= 7 && leaf7_max_subleaf >= 1) {
        x86_cpuid_count(7, 1, &cpuid_eax, &cpuid_ebx, &cpuid_ecx,
                        &cpuid_edx);
        x86_cpuf_record_leaf(&features[X86_CPUID_INDEX_7_ECX_1], cpuid_eax,
                             cpuid_ebx, cpuid_ecx, cpuid_edx);
        if (!has_avx_state) {
            features[X86_CPUID_INDEX_7_ECX_1].active_eax &=
                ~((1u << 4) | (1u << 23));
            features[X86_CPUID_INDEX_7_ECX_1].active_edx &=
                ~((1u << 4) | (1u << 5) | (1u << 19));
        }
        if (!has_avx512_state)
            features[X86_CPUID_INDEX_7_ECX_1].active_eax &= ~(1u << 5);
        if (!has_amx_state) {
            features[X86_CPUID_INDEX_7_ECX_1].active_eax &= ~(1u << 21);
            features[X86_CPUID_INDEX_7_ECX_1].active_edx &= ~(1u << 8);
        }
    }

    if (max_leaf >= 0x19u) {
        x86_cpuid_count(0x19u, 0, &cpuid_eax, &cpuid_ebx,
                        &cpuid_ecx, &cpuid_edx);
        x86_cpuf_record_leaf(&features[X86_CPUID_INDEX_19], cpuid_eax,
                             cpuid_ebx, cpuid_ecx, cpuid_edx);
    }

    if (max_leaf >= 0x14u) {
        x86_cpuid_count(0x14u, 0, &cpuid_eax, &cpuid_ebx,
                        &cpuid_ecx, &cpuid_edx);
        x86_cpuf_record_leaf(&features[X86_CPUID_INDEX_14_ECX_0], cpuid_eax,
                             cpuid_ebx, cpuid_ecx, cpuid_edx);
    }

    if (layout->feature_count > X86_CPUID_INDEX_24_ECX_0 &&
        max_leaf >= 0x24u) {
        x86_cpuid_count(0x24u, 0, &cpuid_eax, &cpuid_ebx,
                        &cpuid_ecx, &cpuid_edx);
        x86_cpuf_record_leaf(&features[X86_CPUID_INDEX_24_ECX_0], cpuid_eax,
                             cpuid_ebx, cpuid_ecx, cpuid_edx);
        if (!has_avx_state)
            features[X86_CPUID_INDEX_24_ECX_0].active_ebx &=
                ~((1u << 16) | (1u << 17) | (1u << 18));
        else if (!has_avx512_state)
            features[X86_CPUID_INDEX_24_ECX_0].active_ebx &= ~(1u << 18);
    }

    for (int feature_index = 0; feature_index < layout->feature_count &&
         feature_index < X86_CPUF_MAX_FEATURES; feature_index++)
        x86_cpuf_store_feature(layout, feature_index,
                               &features[feature_index]);

    if (!layout_known)
        return;

    x86_detect_cache_sizes(max_leaf, max_ext_leaf, &data_cache_size,
                           &shared_cache_size);
    if (shared_cache_size < data_cache_size)
        shared_cache_size = data_cache_size;
    non_temporal_threshold = shared_cache_size * 3u / 4u;
    if (non_temporal_threshold < 1024u * 1024u)
        non_temporal_threshold = 1024u * 1024u;
    rep_movsb_stop_threshold = shared_cache_size * 4u;
    if (rep_movsb_stop_threshold < 4u * 1024u * 1024u)
        rep_movsb_stop_threshold = 4u * 1024u * 1024u;

    x86_cpuf_store_u32(layout->preferred, 0);
    x86_cpuf_store_u32(layout->isa_1, x86_compute_isa_1(features));
    x86_cpuf_store_size(layout->xsave_state_size, xsave_state_size);
    x86_cpuf_store_u32(layout->xsave_state_full_size,
                       xsave_state_full_size);
    x86_cpuf_store_size(layout->data_cache_size, data_cache_size);
    x86_cpuf_store_size(layout->shared_cache_size, shared_cache_size);
    x86_cpuf_store_size(layout->non_temporal_threshold,
                        non_temporal_threshold);
    x86_cpuf_store_size(layout->memset_non_temporal_threshold,
                        non_temporal_threshold);
    x86_cpuf_store_size(layout->rep_movsb_threshold, 2048);
    x86_cpuf_store_size(layout->rep_movsb_stop_threshold,
                        rep_movsb_stop_threshold);
    x86_cpuf_store_size(layout->rep_stosb_threshold, 2048);
}
#endif /* __x86_64__ */

static int init_fake_rtld(void)
{
    g_fake_rtld_global_ro = (uint8_t *)mmap(NULL, GLRO_SIZE,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    g_fake_rtld_global = (uint8_t *)mmap(NULL, GL_SIZE,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_fake_rtld_global_ro == MAP_FAILED ||
        g_fake_rtld_global    == MAP_FAILED) {
        ldr_err("mmap fake rtld", NULL);
        return -1;
    }

    /* _rtld_global_ro critical fields */
    *(size_t *)(g_fake_rtld_global_ro + GLRO_DL_PAGESIZE_OFF) = g_page_size;
    /* _dl_minsigstacksize: minimum signal stack size needed by the kernel
     * plus space for XSAVE.  glibc asserts this is non-zero in sysconf().
     * MINSIGSTKSZ (2048) + typical XSAVE area (2688) ≈ 4736.  Use the
     * kernel AT_MINSIGSTKSZ if available, otherwise a conservative default. */
    *(size_t *)(g_fake_rtld_global_ro + GLRO_DL_MINSIGSTKSZ_OFF) = 6144;
    *(int    *)(g_fake_rtld_global_ro + GLRO_DL_CLKTCK_OFF)   = 100;
    /* FPU control word — default x87 CW (0x037f).  Must match the
     * actual CW or _init_first will call __setfpucw. */
#if defined(__x86_64__)
    *(int    *)(g_fake_rtld_global_ro + GLRO_DL_FPU_CONTROL_OFF) = 0x037f;
#endif

#if defined(__x86_64__)
    init_x86_cpu_features(NULL, 0);
#endif /* __x86_64__ */

    /* _dl_ns[0]._ns_loaded — pointer to the head link_map.  Used by
     * __cxa_thread_atexit_impl when _dl_find_dso_for_object returns NULL:
     * it falls back to *(_rtld_global+0) to get a link_map and increments
     * a reference counter at link_map+0x498.
     * Offset 0 is version-independent (always start of struct). */
    *(uintptr_t *)(g_fake_rtld_global + 0) = (uintptr_t)g_fake_link_map;

    /* Version-dependent fields (_rtld_global_ro TLS offsets, function
     * pointer stubs, _rtld_global nns/stack/tls) are set later by
     * fixup_rtld_for_glibc() once the glibc version is known. */

    return 0;
}

/*
 * Set version-dependent fields in fake _rtld_global / _rtld_global_ro.
 * Called after libraries are loaded and relocated, but BEFORE
 * __libc_early_init which reads the TLS fields.
 */
static void fixup_rtld_for_glibc(const struct glibc_ver_offsets *o)
{
#if defined(__x86_64__)
    init_x86_cpu_features(o, 1);
#endif

    /* _rtld_global_ro: TLS static fields needed by __libc_early_init →
     * thread stack guard computation.  Without these, __libc_early_init
     * divides by zero (SIGFPE).
     * In glibc < 2.34, these fields are in _rtld_global instead. */
    if (o->glro_tls_static_size >= 0) {
        *(size_t *)(g_fake_rtld_global_ro + o->glro_tls_static_size)  = 0x1080;
        *(size_t *)(g_fake_rtld_global_ro + o->glro_tls_static_align) = 0x40;
    }
    if (o->gl_tls_static_size >= 0) {
        *(size_t *)(g_fake_rtld_global + o->gl_tls_static_size)  = 0x1080;
        *(size_t *)(g_fake_rtld_global + o->gl_tls_static_align) = 0x40;
    }

    /* _rtld_global_ro: dl* function pointer stubs — makes dlopen/dlsym/
     * dlclose return error/NULL instead of SIGSEGV through a NULL ptr. */
    if (o->glro_debug_printf >= 0)
        *(void **)(g_fake_rtld_global_ro + o->glro_debug_printf) = (void *)glro_dl_debug_printf;
    if (o->glro_mcount >= 0)
        *(void **)(g_fake_rtld_global_ro + o->glro_mcount)       = (void *)glro_dl_mcount;
    if (o->glro_open >= 0)
        *(void **)(g_fake_rtld_global_ro + o->glro_open)         = (void *)glro_dl_open;
    if (o->glro_close >= 0)
        *(void **)(g_fake_rtld_global_ro + o->glro_close)        = (void *)glro_dl_close;
    if (o->glro_catch_error >= 0)
        *(void **)(g_fake_rtld_global_ro + o->glro_catch_error)  = (void *)glro_dl_catch_error;
    if (o->glro_error_free >= 0)
        *(void **)(g_fake_rtld_global_ro + o->glro_error_free)   = (void *)glro_dl_error_free;
    if (o->glro_find_object >= 0)
        *(void **)(g_fake_rtld_global_ro + o->glro_find_object)  = (void *)glro_dl_find_object;

    /* _rtld_global: critical fields */
    if (o->gl_nns >= 0)
        *(size_t *)(g_fake_rtld_global + o->gl_nns)            = 1;
    if (o->gl_stack_flags >= 0)
        *(int    *)(g_fake_rtld_global + o->gl_stack_flags)    = 3; /* PROT_READ|PROT_WRITE */
    if (o->gl_tls_generation >= 0)
        *(size_t *)(g_fake_rtld_global + o->gl_tls_generation) = 1;

    /* Empty circular lists for stack tracking (glibc ≥ 2.34) */
    if (o->gl_stack_used >= 0)
        init_empty_list(g_fake_rtld_global, o->gl_stack_used);
    if (o->gl_stack_user >= 0)
        init_empty_list(g_fake_rtld_global, o->gl_stack_user);
    if (o->gl_stack_cache >= 0)
        init_empty_list(g_fake_rtld_global, o->gl_stack_cache);

    /* No-op lock stubs for _dl_load_lock (glibc < 2.34) */
    if (o->gl_rtld_lock_recursive >= 0)
        *(void **)(g_fake_rtld_global + o->gl_rtld_lock_recursive)   = (void *)glro_dl_lock_noop;
    if (o->gl_rtld_unlock_recursive >= 0)
        *(void **)(g_fake_rtld_global + o->gl_rtld_unlock_recursive) = (void *)glro_dl_lock_noop;
    if (o->gl_make_stack_executable >= 0)
        *(void **)(g_fake_rtld_global + o->gl_make_stack_executable) = (void *)glro_dl_make_stack_executable;
}

/*
 * Detect glibc struct layout by parsing the embedded ld-linux.so (INTERP)
 * ELF to extract st_size of _rtld_global_ro and _rtld_global symbols.
 * The ELF machine plus both sizes identify a validated layout admission key.
 * A glibc development marker is rejected even when its sizes match a stable
 * release, because private-field consumers can change without changing size.
 *
 * This reads the actual struct sizes from the frozen interpreter, rather
 * than relying on the build host's glibc version.
 */

static const struct glibc_ver_offsets *
glibc_offsets_for_layout(enum dlfrz_glibc_layout_id layout, int glibc_minor)
{
    switch (layout) {
    case DLFRZ_GLIBC_X86_2_17:
        return &glibc_2_17;
    case DLFRZ_GLIBC_AARCH64_2_27:
        return &glibc_aarch64_2_27;
    case DLFRZ_GLIBC_X86_2_29:
        return &glibc_2_29;
    case DLFRZ_GLIBC_X86_2_31_DEBIAN:
        return &glibc_2_31_debian;
    case DLFRZ_GLIBC_AARCH64_2_31:
        return &glibc_aarch64_2_31;
    case DLFRZ_GLIBC_AARCH64_2_35_LARGE:
        return &glibc_aarch64_2_35_large_pthread;
    case DLFRZ_GLIBC_AARCH64_2_36_DEBIAN:
        return &glibc_aarch64_2_36_debian;
    case DLFRZ_GLIBC_AARCH64_2_35:
        return &glibc_aarch64_2_35;
    case DLFRZ_GLIBC_AARCH64_2_43:
        return &glibc_aarch64_2_43;
    case DLFRZ_GLIBC_AARCH64_2_40_LEGACY:
        return &glibc_aarch64_2_40_legacy_sized_rtld;
    case DLFRZ_GLIBC_AARCH64_2_41:
        return &glibc_aarch64_2_41;
    case DLFRZ_GLIBC_X86_2_36_DEBIAN:
        return &glibc_2_36_debian;
    case DLFRZ_GLIBC_X86_2_34:
        return &glibc_2_34;
    case DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY:
        if (glibc_minor >= 37 && glibc_minor <= 39)
            return &glibc_2_37;
        if (glibc_minor == 40)
            return &glibc_2_40_legacy_sized_rtld;
        return NULL;
    case DLFRZ_GLIBC_X86_2_40:
        return &glibc_2_40;
    case DLFRZ_GLIBC_X86_2_41_DEBIAN:
        return &glibc_2_41_debian;
    case DLFRZ_GLIBC_LAYOUT_UNKNOWN:
        break;
    }
    return NULL;
}

/* Convert a virtual address to a file offset using PT_LOAD segments. */
static uint64_t elf_vaddr_to_foff(const uint8_t *elf, const Elf64_Ehdr *ehdr,
                                   uint64_t vaddr)
{
    const Elf64_Phdr *ph = (const Elf64_Phdr *)(elf + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD &&
            vaddr >= ph[i].p_vaddr &&
            vaddr < ph[i].p_vaddr + ph[i].p_filesz)
            return ph[i].p_offset + (vaddr - ph[i].p_vaddr);
    }
    return (uint64_t)-1;
}

static void ldr_dbg_offset(const char *prefix, int off)
{
    if (!g_debug)
        return;
    if (off >= 0) {
        ldr_hex(prefix, (uint64_t)(unsigned)off);
    } else {
        ldr_msg(prefix);
        ldr_msg("absent\n");
    }
}

static void debug_dump_glibc_offsets(const char *source,
                                     uint16_t machine,
                                     int minor,
                                     size_t glro_size,
                                     size_t gl_size,
                                     const struct glibc_ver_offsets *o)
{
    if (!g_debug || !o)
        return;

    ldr_msg("[loader] glibc rtld layout source: ");
    ldr_msg(source ? source : "unknown");
    ldr_msg("\n");
    ldr_dbg_hex("[loader]   machine=0x", machine);
    ldr_dbg_hex("[loader]   glibc minor=0x", minor >= 0 ? (uint64_t)minor : 0);
    ldr_dbg_hex("[loader]   _rtld_global_ro size=0x", glro_size);
    ldr_dbg_hex("[loader]   _rtld_global size=0x", gl_size);
    ldr_dbg_offset("[loader]   glro_tls_static_size=0x", o->glro_tls_static_size);
    ldr_dbg_offset("[loader]   glro_tls_static_align=0x", o->glro_tls_static_align);
    ldr_dbg_offset("[loader]   glro_open=0x", o->glro_open);
    ldr_dbg_offset("[loader]   glro_find_object=0x", o->glro_find_object);
    ldr_dbg_offset("[loader]   gl_nns=0x", o->gl_nns);
    ldr_dbg_offset("[loader]   gl_stack_flags=0x", o->gl_stack_flags);
    ldr_dbg_offset("[loader]   gl_tls_generation=0x", o->gl_tls_generation);
    ldr_dbg_offset("[loader]   gl_stack_used=0x", o->gl_stack_used);
#if defined(__aarch64__)
    ldr_dbg_offset("[loader]   pthread_size=0x", o->pthread_size);
    ldr_dbg_offset("[loader]   pthread_rseq_off=0x", o->pthread_rseq_off);
#endif
}

static int scan_glibc_2_minor(const char *buf, size_t len)
{
    static const char tag[] = "GLIBC_2.";
    const size_t tag_len = sizeof(tag) - 1;
    int max_minor = -1;

    for (size_t i = 0; i + tag_len < len; i++) {
        int minor = 0;
        int digits = 0;
        size_t j;

        if (memcmp(buf + i, tag, tag_len) != 0)
            continue;

        for (j = i + tag_len; j < len; j++) {
            unsigned char c = (unsigned char)buf[j];
            if (c < '0' || c > '9')
                break;
            if (minor < 1000)
                minor = minor * 10 + (int)(c - '0');
            digits++;
        }
        if (digits > 0 && minor > max_minor)
            max_minor = minor;
    }

    return max_minor;
}

static uint32_t elf_gnu_hash_symbol_count(const uint8_t *elf,
                                          const Elf64_Ehdr *ehdr,
                                          size_t elf_size,
                                          uint64_t gnu_hash_vaddr)
{
    uint64_t hash_foff = elf_vaddr_to_foff(elf, ehdr, gnu_hash_vaddr);
    const uint32_t *header;
    const uint32_t *buckets;
    const uint32_t *chains;
    size_t buckets_off;
    size_t chains_off;
    uint32_t nbuckets;
    uint32_t symoffset;
    uint32_t bloom_size;
    uint32_t max_sym = 0;

    if (hash_foff == (uint64_t)-1 || hash_foff + 16 > elf_size)
        return 0;
    header = (const uint32_t *)(elf + hash_foff);
    nbuckets = header[0];
    symoffset = header[1];
    bloom_size = header[2];
    if (nbuckets == 0)
        return 0;

    buckets_off = (size_t)hash_foff + 16 +
                  (size_t)bloom_size * sizeof(Elf64_Addr);
    if (buckets_off > elf_size ||
        (size_t)nbuckets > (elf_size - buckets_off) / sizeof(uint32_t))
        return 0;
    chains_off = buckets_off + (size_t)nbuckets * sizeof(uint32_t);
    if (chains_off > elf_size)
        return 0;

    buckets = (const uint32_t *)(elf + buckets_off);
    chains = (const uint32_t *)(elf + chains_off);
    for (uint32_t bucket_index = 0; bucket_index < nbuckets; bucket_index++) {
        uint32_t sym = buckets[bucket_index];
        size_t chain_index;
        size_t max_chain_words;

        if (sym < symoffset)
            continue;
        chain_index = (size_t)(sym - symoffset);
        max_chain_words = (elf_size - chains_off) / sizeof(uint32_t);
        if (chain_index >= max_chain_words)
            continue;

        for (size_t i = chain_index; i < max_chain_words; i++, sym++) {
            uint32_t hash = chains[i];

            if (sym > max_sym)
                max_sym = sym;
            if (hash & 1u)
                break;
        }
    }

    return max_sym ? max_sym + 1 : 0;
}

static uint32_t elf_fallback_symbol_count(size_t symtab_foff,
                                          size_t dynstr_foff,
                                          size_t elf_size)
{
    size_t max_syms;

    if (symtab_foff >= elf_size)
        return 0;
    if (dynstr_foff > symtab_foff)
        max_syms = (dynstr_foff - symtab_foff) / sizeof(Elf64_Sym);
    else
        max_syms = (elf_size - symtab_foff) / sizeof(Elf64_Sym);
    if (max_syms > 16384)
        max_syms = 16384;
    return (uint32_t)max_syms;
}

static int dynstr_name_matches(const char *str, size_t dynstr_size,
                               uint32_t name_offset, const char *expect)
{
    size_t i = 0;

    if ((size_t)name_offset >= dynstr_size)
        return 0;
    while (expect[i]) {
        if ((size_t)name_offset + i >= dynstr_size ||
            str[name_offset + i] != expect[i])
            return 0;
        i++;
    }
    if ((size_t)name_offset + i >= dynstr_size)
        return 0;
    return str[name_offset + i] == '\0' || str[name_offset + i] == '@';
}

static void scan_rtld_global_symbols(const Elf64_Sym *syms,
                                     size_t symbol_count,
                                     const char *strtab,
                                     size_t strtab_size,
                                     size_t *glro_size,
                                     size_t *gl_size,
                                     int *found)
{
    for (size_t i = 0; i < symbol_count && *found < 2; i++) {
        uint32_t name_offset;

        if (ELF64_ST_TYPE(syms[i].st_info) != STT_OBJECT)
            continue;
        if (syms[i].st_size == 0)
            continue;
        name_offset = syms[i].st_name;
        if (!*glro_size && dynstr_name_matches(strtab, strtab_size,
                                               name_offset,
                                               "_rtld_global_ro")) {
            *glro_size = syms[i].st_size;
            (*found)++;
        } else if (!*gl_size && dynstr_name_matches(strtab, strtab_size,
                                                    name_offset,
                                                    "_rtld_global")) {
            *gl_size = syms[i].st_size;
            (*found)++;
        }
    }
}

static void scan_section_rtld_global_symbols(const uint8_t *elf,
                                             const Elf64_Ehdr *ehdr,
                                             size_t elf_size,
                                             size_t *glro_size,
                                             size_t *gl_size,
                                             int *found)
{
    const uint8_t *shbase;
    size_t shdr_bytes;

    if (*found >= 2 || ehdr->e_shoff == 0 || ehdr->e_shnum == 0 ||
        ehdr->e_shentsize < sizeof(Elf64_Shdr))
        return;
    if (ehdr->e_shoff > elf_size)
        return;
    shdr_bytes = (size_t)ehdr->e_shnum * (size_t)ehdr->e_shentsize;
    if ((size_t)ehdr->e_shnum != 0 &&
        shdr_bytes / (size_t)ehdr->e_shnum != (size_t)ehdr->e_shentsize)
        return;
    if (shdr_bytes > elf_size - (size_t)ehdr->e_shoff)
        return;
    shbase = elf + ehdr->e_shoff;

    for (uint16_t i = 0; i < ehdr->e_shnum && *found < 2; i++) {
        const Elf64_Shdr *sh = (const Elf64_Shdr *)(shbase +
            (size_t)i * ehdr->e_shentsize);
        const Elf64_Shdr *strsh;
        const Elf64_Sym *syms;
        const char *strtab;
        size_t symbol_count;
        size_t entsize;

        if (sh->sh_type != SHT_SYMTAB && sh->sh_type != SHT_DYNSYM)
            continue;
        if (sh->sh_link >= ehdr->e_shnum)
            continue;
        entsize = sh->sh_entsize ? sh->sh_entsize : sizeof(Elf64_Sym);
        if (entsize != sizeof(Elf64_Sym) || sh->sh_offset > elf_size ||
            sh->sh_size > elf_size - sh->sh_offset)
            continue;

        strsh = (const Elf64_Shdr *)(shbase +
            (size_t)sh->sh_link * ehdr->e_shentsize);
        if (strsh->sh_offset > elf_size ||
            strsh->sh_size > elf_size - strsh->sh_offset)
            continue;

        syms = (const Elf64_Sym *)(elf + sh->sh_offset);
        strtab = (const char *)(elf + strsh->sh_offset);
        symbol_count = sh->sh_size / sizeof(Elf64_Sym);
        scan_rtld_global_symbols(syms, symbol_count, strtab,
                                 strsh->sh_size, glro_size, gl_size,
                                 found);
    }
}

/*
 * Detect glibc offsets from the embedded ld-linux.so's .dynsym.
 * Returns a pointer to the matching offset profile, or NULL on failure.
 */
static const struct glibc_ver_offsets *
detect_glibc_offsets_from_interp(const uint8_t *mem, uint64_t mem_foff,
                                  const struct dlfrz_entry *entries,
                                  const struct dlfrz_lib_meta *metas,
                                  uint32_t num_entries)
{
    /* Find the INTERP entry (ld-linux.so) */
    int idx = -1;
    for (uint32_t i = 0; i < num_entries; i++) {
        if (metas[i].flags & LDR_FLAG_INTERP) { idx = (int)i; break; }
    }
    if (idx < 0) return NULL;  /* no interp — likely musl-based */

    const uint8_t *elf = mem + (entries[idx].data_offset - mem_foff);
    size_t elf_size = entries[idx].data_size;
    if (elf_size < sizeof(Elf64_Ehdr)) return NULL;

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf;
    if (ehdr->e_ident[EI_MAG0] != 0x7f || ehdr->e_ident[EI_MAG1] != 'E' ||
        ehdr->e_ident[EI_MAG2] != 'L'  || ehdr->e_ident[EI_MAG3] != 'F')
        return NULL;
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
        ehdr->e_version != EV_CURRENT ||
        ehdr->e_phentsize != sizeof(Elf64_Phdr))
        return NULL;
    if (dlfrz_glibc_is_development_release(elf, elf_size)) {
        ldr_dbg("[loader] refusing glibc development snapshot\n");
        return NULL;
    }

    int glibc_minor = -1;
    size_t glro_size = 0, gl_size = 0;
    int found = 0;
    const char *str = NULL;
    size_t dynstr_size = 0;

    if (ehdr->e_phoff <= elf_size &&
        ehdr->e_phnum <= (elf_size - (size_t)ehdr->e_phoff) / ehdr->e_phentsize) {
        const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(elf + ehdr->e_phoff);
        uint64_t dyn_foff = 0;
        size_t dyn_size = 0;

        for (int i = 0; i < ehdr->e_phnum; i++) {
            const Elf64_Phdr *ph = (const Elf64_Phdr *)((const uint8_t *)phdrs +
                (size_t)i * ehdr->e_phentsize);

            if (ph->p_type == PT_DYNAMIC) {
                dyn_foff = ph->p_offset;
                dyn_size = ph->p_filesz;
                break;
            }
        }

        if (dyn_foff && dyn_foff <= elf_size && dyn_size <= elf_size - dyn_foff) {
            const Elf64_Dyn *dyn = (const Elf64_Dyn *)(elf + dyn_foff);
            size_t ndyn = dyn_size / sizeof(Elf64_Dyn);
            uint64_t symtab_vaddr = 0, dynstr_vaddr = 0, hash_vaddr = 0;
            uint64_t gnu_hash_vaddr = 0;
            uint64_t symtab_foff = (uint64_t)-1;
            uint64_t dynstr_foff = (uint64_t)-1;

            for (size_t i = 0; i < ndyn && dyn[i].d_tag != DT_NULL; i++) {
                switch (dyn[i].d_tag) {
                    case DT_SYMTAB: symtab_vaddr = dyn[i].d_un.d_ptr; break;
                    case DT_STRTAB: dynstr_vaddr = dyn[i].d_un.d_ptr; break;
                    case DT_STRSZ:  dynstr_size  = dyn[i].d_un.d_val; break;
                    case DT_HASH:   hash_vaddr   = dyn[i].d_un.d_ptr; break;
                    case DT_GNU_HASH: gnu_hash_vaddr = dyn[i].d_un.d_ptr; break;
                }
            }

            if (dynstr_vaddr) {
                dynstr_foff = elf_vaddr_to_foff(elf, ehdr, dynstr_vaddr);
                if (dynstr_foff != (uint64_t)-1 && dynstr_foff < elf_size) {
                    size_t avail = elf_size - (size_t)dynstr_foff;
                    if (dynstr_size == 0 || dynstr_size > avail)
                        dynstr_size = avail;
                    str = (const char *)(elf + dynstr_foff);
                    glibc_minor = scan_glibc_2_minor(str, dynstr_size);
                }
            }

            if (symtab_vaddr && str && dynstr_size > 0) {
                uint32_t nsyms = 0;

                symtab_foff = elf_vaddr_to_foff(elf, ehdr, symtab_vaddr);
                if (symtab_foff != (uint64_t)-1 && symtab_foff < elf_size) {
                    if (hash_vaddr) {
                        uint64_t hash_foff = elf_vaddr_to_foff(elf, ehdr, hash_vaddr);
                        if (hash_foff != (uint64_t)-1 && hash_foff + 8 <= elf_size) {
                            const uint32_t *hashtab = (const uint32_t *)(elf + hash_foff);
                            nsyms = hashtab[1];
                        }
                    }
                    if (nsyms == 0 && gnu_hash_vaddr)
                        nsyms = elf_gnu_hash_symbol_count(elf, ehdr, elf_size,
                                                          gnu_hash_vaddr);
                    if (nsyms == 0)
                        nsyms = elf_fallback_symbol_count((size_t)symtab_foff,
                                                          (size_t)(str - (const char *)elf),
                                                          elf_size);
                    if ((size_t)nsyms > (elf_size - (size_t)symtab_foff) /
                            sizeof(Elf64_Sym))
                        nsyms = (uint32_t)((elf_size - (size_t)symtab_foff) /
                                           sizeof(Elf64_Sym));
                    if (nsyms > 0) {
                        const Elf64_Sym *syms = (const Elf64_Sym *)(elf + symtab_foff);
                        scan_rtld_global_symbols(syms, nsyms, str, dynstr_size,
                                                 &glro_size, &gl_size, &found);
                    }
                }
            }
        }
    }

    if (glibc_minor < 0)
        glibc_minor = scan_glibc_2_minor((const char *)elf, elf_size);
    {
        int release_minor =
            dlfrz_glibc_stable_release_minor((const char *)elf, elf_size);

        /* A highest GLIBC_2.* symbol version is only an ABI floor.  It must
         * never substitute for a positive runtime release identity, even in
         * a stale or post-packaging-mutated direct artifact. */
        if (release_minor < 0) {
            ldr_dbg("[loader] missing stable glibc release identity\n");
            return NULL;
        }
        if (glibc_minor > release_minor) {
            ldr_dbg("[loader] inconsistent glibc release identity\n");
            return NULL;
        }
        glibc_minor = release_minor;
    }

    scan_section_rtld_global_symbols(elf, ehdr, elf_size, &glro_size,
                                     &gl_size, &found);

    enum dlfrz_glibc_layout_id layout =
        dlfrz_glibc_layout_lookup(ehdr->e_machine, glro_size, gl_size);
    if (!dlfrz_glibc_layout_release_is_supported(layout, glibc_minor)) {
        ldr_dbg("[loader] ambiguous glibc private rtld layout identity\n");
        return NULL;
    }
    const struct glibc_ver_offsets *offsets =
        glibc_offsets_for_layout(layout, glibc_minor);

    if (!offsets) {
        ldr_dbg("[loader] unsupported glibc private rtld layout\n");
        ldr_dbg_hex("[loader]   _rtld_global_ro size=0x", glro_size);
        ldr_dbg_hex("[loader]   _rtld_global size=0x", gl_size);
        return NULL;
    }

    if (glibc_minor >= 0)
        g_glibc_minor = glibc_minor;
    if (layout == DLFRZ_GLIBC_X86_2_37_OR_2_40_LEGACY &&
        glibc_minor >= 40)
        ldr_dbg("[loader] detected x86-64 glibc 2.40+ legacy-sized rtld layout\n");
    else
        ldr_dbg("[loader] matched validated glibc private rtld layout\n");
    debug_dump_glibc_offsets("validated-symbol-sizes", ehdr->e_machine,
                             glibc_minor, glro_size, gl_size, offsets);
    return offsets;
}

static const struct dlfrz_musl_layout *
detect_musl_layout_from_interp(const uint8_t *mem, uint64_t mem_foff,
                               const struct dlfrz_entry *entries,
                               const struct dlfrz_lib_meta *metas,
                               uint32_t num_entries)
{
    for (uint32_t i = 0; i < num_entries; i++) {
        const uint8_t *elf;
        const Elf64_Ehdr *ehdr;

        if (!(metas[i].flags & LDR_FLAG_INTERP))
            continue;
        if (entries[i].data_offset < mem_foff ||
            entries[i].data_size < sizeof(Elf64_Ehdr))
            return NULL;
        elf = mem + (entries[i].data_offset - mem_foff);
        ehdr = (const Elf64_Ehdr *)elf;
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
            ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
            ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
            ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
            ehdr->e_version != EV_CURRENT)
            return NULL;
        return dlfrz_musl_layout_lookup(ehdr->e_machine, elf,
                                         (size_t)entries[i].data_size);
    }
    return NULL;
}

/* ---- ld.so function stubs -------------------------------------------- */

/*
 * libc.so imports several functions from ld-linux.so.  Without the real
 * dynamic linker we provide no-op / minimal stubs so the GOT entries
 * are not NULL, preventing SIGSEGV on first call.
 */

/* __tunable_get_val — called by malloc tunables init.
 * Must zero the output parameter to prevent garbage tunable values. */
static void stub_tunable_get_val(long id, void *valp, void *cb)
{
    (void)id; (void)valp; (void)cb;
    /* Do nothing — leave the caller's value unmodified.
     * ptmalloc_init passes a stack-local of varying size (int32_t,
     * size_t).  Writing a fixed-size memset would overflow it.
     * Not modifying *valp and not calling cb leaves malloc tunables
     * at their compiled-in defaults. */
}

/* __tunable_is_initialized — return 0 (not initialised) */
static int stub_tunable_is_initialized(void) { return 0; }

/* _dl_find_dso_for_object — return NULL (not found) */
static void *stub_dl_find_dso_for_object(void) { return NULL; }

/* Keep the private rtld exception ABI independent of glibc headers.  This is
 * the three-pointer layout used by every supported glibc release.  Direct
 * loaded objects are never unloaded, so retaining the mapped input strings is
 * safer than allocating through the bootstrap libc after the TLS handoff. */
struct dlfreeze_dl_exception {
    const char *objname;
    const char *errstring;
    char *message_buffer;
};

static void stub_dl_exception_create(struct dlfreeze_dl_exception *exception,
                                     const char *objname,
                                     const char *errstring)
{
    if (!exception)
        return;
    exception->objname = objname ? objname : "";
    exception->errstring = errstring ? errstring : "";
    exception->message_buffer = NULL;
}

static void stub_dl_exception_create_format(
    struct dlfreeze_dl_exception *exception, const char *objname,
    const char *format, ...)
{
    /* This is an error-only fallback.  Retain the stable format string rather
     * than invoking a foreign-libc formatter from the loader's TLS context. */
    stub_dl_exception_create(exception, objname, format ? format : "");
}

static void stub_dl_exception_free(struct dlfreeze_dl_exception *exception)
{
    if (!exception)
        return;
    exception->objname = NULL;
    exception->errstring = NULL;
    exception->message_buffer = NULL;
}

/* _dl_fatal_printf is a noreturn private rtld printf.  A literal diagnostic
 * is deliberately used here: termination must remain reliable even if the
 * target libc called this because its own runtime state is inconsistent. */
static void stub_dl_fatal_printf(const char *format, ...)
    __attribute__((noreturn, format(printf, 1, 2)));
static void stub_dl_fatal_printf(const char *format, ...)
{
    ldr_msg("dlfreeze-loader: fatal glibc loader error: ");
    ldr_msg(format ? format : "_dl_fatal_printf called");
    ldr_msg("\n");
    _exit(127);
}

/* _dl_signal_error — fatal: print and abort */
static void stub_dl_signal_error(int errcode, const char *object,
                                 const char *occasion,
                                 const char *errstring)
{
    (void)errcode;
    ldr_msg("dlfreeze-loader: glibc loader error");
    if (occasion) { ldr_msg(" during "); ldr_msg(occasion); }
    if (object) { ldr_msg(" for "); ldr_msg(object); }
    if (errstring) { ldr_msg(": "); ldr_msg(errstring); }
    ldr_msg("\n");
    _exit(127);
}

/* _dl_signal_exception — fatal */
static void stub_dl_signal_exception(
    int errcode, struct dlfreeze_dl_exception *exception,
    const char *occasion)
{
    stub_dl_signal_error(errcode,
                         exception ? exception->objname : NULL,
                         occasion,
                         exception ? exception->errstring : NULL);
}

/* _dl_catch_exception — call operatep directly (no exception handling) */
static int stub_dl_catch_exception(struct dlfreeze_dl_exception *exc,
                                   void (*operate)(void *), void *args)
{
    operate(args);
    /* glibc's success contract clears the caller-owned result.  Several
     * callers deliberately leave it uninitialized before entering the
     * catcher and inspect errstring after a zero return. */
    if (exc)
        *exc = (struct dlfreeze_dl_exception){ 0 };
    return 0;
}

/* _dl_audit_symbind_alt / _dl_audit_preinit — no-ops */
static void stub_dl_audit_noop(void) { /* no-op */ }

/* _dl_allocate_tls / _dl_allocate_tls_init / _dl_deallocate_tls
 * Called by glibc's pthread_create to initialise TLS for new threads.
 * Implementations are below g_all_objs/g_nobj declarations. */
static void stub_dl_get_tls_static_info(size_t *sizep, size_t *alignp)
{
    if (sizep)
        *sizep = g_tls_static_size;
    if (alignp)
        *alignp = g_tls_static_align;
}

static void *stub_dl_allocate_tls(void *mem);       /* impl below */
static void *stub_dl_allocate_tls_init(void *mem);   /* impl below */
static void  stub_dl_deallocate_tls(void *mem) { (void)mem; }

/* _dl_rtld_di_serinfo — no-op */
static int stub_dl_rtld_di_serinfo(void) { return -1; }

/* The direct loader never enables executable pthread stacks.  Resolve the
 * private rtld hook so normal startup is well-defined, but fail closed if a
 * target actually requests the unsupported policy change. */
static int stub_nptl_change_stack_perm(void *thread)
{
    (void)thread;
    ldr_msg("dlfreeze-loader: executable pthread stacks are unsupported\n");
    _exit(127);
}

/* ---- TLS / arch constants --------------------------------------------- */
#define TCB_ALLOC     4096     /* generous TCB allocation */

#if defined(__x86_64__)
/* tcbhead_t offsets on x86-64 glibc */
#define TCB_OFF_SELF         0    /* void *tcb              */
#define TCB_OFF_DTV          8    /* dtv_t *dtv             */
#define TCB_OFF_SELF2       16    /* void *self             */
#define TCB_OFF_SELF3       24    /* musl thread self       */
#define TCB_OFF_STACK_GUARD 40    /* uintptr_t stack_guard  (0x28) */
#define TCB_OFF_PTR_GUARD   48    /* uintptr_t pointer_guard (0x30) */
#define TCB_OFF_TID        720    /* pid_t tid (0x2D0) — thread ID */
#elif defined(__aarch64__)
/* tcbhead_t offsets on aarch64 glibc (TP points to start of TCB) */
#define TCB_OFF_DTV          0    /* dtv_t *dtv             */
#define TCB_OFF_SELF         8    /* void *private (unused) */
#define TCB_OFF_SELF2        8
#define TCB_OFF_SELF3       16    /* musl thread self       */
/* AArch64 glibc keeps struct pthread immediately below TP and places
 * static TLS at positive TP offsets after the two-word TCB header. */
#define GLIBC_AARCH64_PTHREAD_SIZE_DEFAULT       0x740
#define GLIBC_AARCH64_TCB_SIZE                   0x10
#define GLIBC_AARCH64_PTHREAD_TID_OFF_DEFAULT    0x0d0
#define GLIBC_AARCH64_PTHREAD_RSEQ_OFF_DEFAULT   0x720
#define GLIBC_AARCH64_PTHREAD_RSEQ_CPU_ID_OFF_DEFAULT 0x724
#define GLIBC_AARCH64_PTHREAD_CANCELHANDLING_OFF_DEFAULT 0x108
#define GLIBC_AARCH64_PTHREAD_STACKBLOCK_OFF     0x490
#define GLIBC_AARCH64_PTHREAD_STACKBLOCK_SIZE_OFF 0x498
#define GLIBC_AARCH64_PTHREAD_GUARDSIZE_OFF      0x4a0
#define GLIBC_AARCH64_PTHREAD_REPORTED_GUARDSIZE_OFF 0x4a8
#define GLIBC_RSEQ_REGISTERED_BIT 0x80
#define GLIBC_RSEQ_CPU_ID_REGISTRATION_FAILED (-2)

/* Runtime accessors consult the profile validated before any target mapping.
 * The compiled-in return values only defend against an internal sequencing
 * error; they do not admit an unrecognized glibc layout.  A negative rseq
 * field in a validated profile means that the field is intentionally absent. */
static inline size_t glibc_aarch64_pthread_size(void)
{
    if (g_glibc_off && g_glibc_off->pthread_size > 0)
        return (size_t)g_glibc_off->pthread_size;
    return GLIBC_AARCH64_PTHREAD_SIZE_DEFAULT;
}
static inline size_t glibc_aarch64_pthread_tid_off(void)
{
    if (g_glibc_off && g_glibc_off->pthread_tid_off > 0)
        return (size_t)g_glibc_off->pthread_tid_off;
    return GLIBC_AARCH64_PTHREAD_TID_OFF_DEFAULT;
}
static inline int glibc_aarch64_has_rseq_area(void)
{
    if (g_glibc_off)
        return g_glibc_off->pthread_rseq_off > 0;
    /* Defensive only: glibc setup cannot reach this without a profile. */
    return 1;
}
static inline size_t glibc_aarch64_pthread_rseq_off(void)
{
    if (g_glibc_off && g_glibc_off->pthread_rseq_off > 0)
        return (size_t)g_glibc_off->pthread_rseq_off;
    return GLIBC_AARCH64_PTHREAD_RSEQ_OFF_DEFAULT;
}
static inline size_t glibc_aarch64_pthread_rseq_cpu_id_off(void)
{
    if (g_glibc_off && g_glibc_off->pthread_rseq_cpu_id_off > 0)
        return (size_t)g_glibc_off->pthread_rseq_cpu_id_off;
    return GLIBC_AARCH64_PTHREAD_RSEQ_CPU_ID_OFF_DEFAULT;
}
/* On aarch64 glibc the stack guard and pointer guard live in struct
 * pthread, which sits at a negative offset from the thread pointer.
 * These offsets are from the TP (positive, into the TCB header area).
 * glibc aarch64 stores the stack canary at TP - 0x10 equivalently,
 * but for our TCB we place them at fixed offsets within TCB_ALLOC. */
#define TCB_OFF_STACK_GUARD 16    /* uintptr_t stack_guard  */
#define TCB_OFF_PTR_GUARD   24    /* uintptr_t pointer_guard */
#define TCB_OFF_TID        720    /* pid_t tid              */
#endif
#if defined(__x86_64__)
#define MUSL_TLS_GAP_ABOVE_TP              0
#elif defined(__aarch64__)
#define MUSL_TLS_GAP_ABOVE_TP              16
#endif

#define MUSL_THREAD_PROBE_LIMIT 0x180

struct musl_thread_layout {
    size_t dtv;
    size_t prev;
    size_t next;
    size_t sysinfo;
    size_t tid;
    size_t errno_off;
    size_t detach_state;
    size_t robust_head;
    size_t locale;
};

static struct musl_thread_layout g_musl_thread;

/* errno and DTV have small exported accessors whose offsets can be decoded
 * directly.  tid and detach_state are not adjacent to errno on older musl
 * releases, so only seed them after independently deriving their offsets
 * from the target pthread implementation. */
static int g_musl_target_tid_known;
static int g_musl_target_errno_known;
static int g_musl_target_detach_known;
static int g_musl_target_detach_value = 2;

static void select_musl_thread_layout(
    const struct dlfrz_musl_layout *layout)
{
    g_musl_thread.dtv = layout->thread_dtv;
    g_musl_thread.prev = layout->thread_prev;
    g_musl_thread.next = layout->thread_next;
    g_musl_thread.sysinfo = layout->thread_sysinfo;
    g_musl_thread.tid = layout->thread_tid;
    g_musl_thread.errno_off = layout->thread_errno;
    g_musl_thread.detach_state = layout->thread_detach;
    g_musl_thread.robust_head = layout->thread_robust;
    g_musl_thread.locale = layout->thread_locale;
    g_musl_target_tid_known = 0;
    g_musl_target_errno_known = 0;
    g_musl_target_detach_known = 0;
    g_musl_target_detach_value = layout->detach_initial;
}

#define MUSL_THREAD_DTV_OFF          (g_musl_thread.dtv)
#define MUSL_THREAD_PREV_OFF         (g_musl_thread.prev)
#define MUSL_THREAD_NEXT_OFF         (g_musl_thread.next)
#define MUSL_THREAD_SYSINFO_OFF      (g_musl_thread.sysinfo)
#define MUSL_THREAD_TID_OFF          (g_musl_thread.tid)
#define MUSL_THREAD_ERRNO_OFF        (g_musl_thread.errno_off)
#define MUSL_THREAD_DETACH_STATE_OFF (g_musl_thread.detach_state)
#define MUSL_THREAD_ROBUST_HEAD_OFF  (g_musl_thread.robust_head)
#define MUSL_THREAD_LOCALE_OFF       (g_musl_thread.locale)

static inline int musl_tls_above_tp(void)
{
#if defined(__aarch64__)
    return 1;
#else
    return 0;
#endif
}

static inline int glibc_tls_above_tp(void)
{
#if defined(__aarch64__)
    return !g_is_musl_runtime;
#else
    return 0;
#endif
}

static inline int static_tls_above_tp(void)
{
    return (g_is_musl_runtime && musl_tls_above_tp()) ||
           glibc_tls_above_tp();
}

static inline uint64_t static_tls_first_tpoff(void)
{
#if defined(__aarch64__)
    if (glibc_tls_above_tp())
        return GLIBC_AARCH64_TCB_SIZE;
#endif
    if (g_is_musl_runtime && musl_tls_above_tp())
        return MUSL_TLS_GAP_ABOVE_TP;
    return 0;
}

#if defined(__aarch64__)
static inline uintptr_t glibc_aarch64_pthread_self_from_tp(uintptr_t tp)
{
    return tp - glibc_aarch64_pthread_size();
}

static void glibc_aarch64_disable_rseq_for_thread(uintptr_t tp)
{
    if (g_is_musl_runtime || g_rseq_size != 0)
        return;

    uintptr_t self = glibc_aarch64_pthread_self_from_tp(tp);
    int32_t *cancelhandling = (int32_t *)(self +
        GLIBC_AARCH64_PTHREAD_CANCELHANDLING_OFF_DEFAULT);
    uintptr_t rseq_base = (uintptr_t)((int64_t)tp + g_rseq_offset);

    *cancelhandling &= ~GLIBC_RSEQ_REGISTERED_BIT;
    *(int32_t *)(rseq_base + 4) = GLIBC_RSEQ_CPU_ID_REGISTRATION_FAILED;
}

static void glibc_aarch64_set_main_stack(uintptr_t stack_base,
                                          size_t stack_size)
{
    if (g_is_musl_runtime || !stack_base || !stack_size)
        return;

    uintptr_t self = glibc_aarch64_pthread_self_from_tp(arch_get_tp());
    *(uintptr_t *)(self + GLIBC_AARCH64_PTHREAD_STACKBLOCK_OFF) = stack_base;
    *(size_t *)(self + GLIBC_AARCH64_PTHREAD_STACKBLOCK_SIZE_OFF) = stack_size;
    *(size_t *)(self + GLIBC_AARCH64_PTHREAD_GUARDSIZE_OFF) = 0;
    *(size_t *)(self + GLIBC_AARCH64_PTHREAD_REPORTED_GUARDSIZE_OFF) = 0;
}
#endif

/* The NPTL descriptor keeps its stack-list node immediately before tid on
 * every glibc layout supported here (see struct pthread in nptl/descr.h).
 * The real rtld links the initial descriptor into dl_stack_user.  Direct
 * loading does not run that code, but fork's child-side reclaim_stacks still
 * unconditionally removes THREAD_SELF->list.  Give the synthetic main thread
 * a valid, self-contained list node so that operation is well-defined.  The
 * child then links itself into the appropriate fake rtld stack list.
 *
 * Derive the node from the detected per-architecture tid layout instead of
 * baking in the offset observed on one glibc release. */
static int init_glibc_main_thread_list(uintptr_t tp)
{
    uintptr_t self;
    size_t descriptor_size;
    size_t tid_off;
    size_t list_off;

#if defined(__aarch64__)
    descriptor_size = glibc_aarch64_pthread_size();
    tid_off = glibc_aarch64_pthread_tid_off();
    self = glibc_aarch64_pthread_self_from_tp(tp);
#else
    descriptor_size = TCB_ALLOC;
    tid_off = TCB_OFF_TID;
    self = tp;
#endif

    if (tid_off < 2 * sizeof(uintptr_t) ||
        tid_off + sizeof(int32_t) > descriptor_size)
        return -1;

    list_off = tid_off - 2 * sizeof(uintptr_t);
    *(uintptr_t *)(self + list_off) = self + list_off;
    *(uintptr_t *)(self + list_off + sizeof(uintptr_t)) = self + list_off;
    return 0;
}

static inline uintptr_t musl_thread_self_ptr(uintptr_t tp)
{
    return tp - g_musl_tp_self_delta;
}

static inline uintptr_t *musl_thread_dtv_slot(uintptr_t tp)
{
    return (uintptr_t *)(musl_thread_self_ptr(tp) + MUSL_THREAD_DTV_OFF);
}

/* Lazy per-thread musl TLS install — defined later (after `struct
 * loaded_obj`).  Forward declaration so __tls_get_addr can call it. */
static void *musl_lazy_install_tls(uintptr_t tp, unsigned long modid,
                                   unsigned long ti_offset);
static void *runtime_tls_get_addr(uintptr_t tp, unsigned long modid,
                                  unsigned long ti_offset);
static void tls_runtime_fatal(const char *reason)
    __attribute__((noreturn));

/* __tls_get_addr — GD/LD TLS model accessor.
 * Looks up the DTV entry for the module and adds the offset. */
struct tls_index { unsigned long ti_module; unsigned long ti_offset; };
static void *stub_tls_get_addr(struct tls_index *ti)
{
    if (!ti)
        return NULL;
    return runtime_tls_get_addr(arch_get_tp(), ti->ti_module,
                                ti->ti_offset);
}

/* Table of stub symbols — searched during resolution */
struct stub_sym {
    const char *name;
    void       *addr;
};

static const struct stub_sym g_stubs[] = {
    { "__tunable_get_val",       (void *)stub_tunable_get_val       },
    { "__tunable_is_initialized",(void *)stub_tunable_is_initialized},
    { "_dl_find_dso_for_object", (void *)stub_dl_find_dso_for_object},
    { "_dl_exception_create",    (void *)stub_dl_exception_create   },
    { "_dl_exception_create_format",
                                  (void *)stub_dl_exception_create_format},
    { "_dl_exception_free",      (void *)stub_dl_exception_free     },
    { "_dl_fatal_printf",        (void *)stub_dl_fatal_printf       },
    { "_dl_signal_error",        (void *)stub_dl_signal_error       },
    { "_dl_signal_exception",    (void *)stub_dl_signal_exception   },
    { "_dl_catch_exception",     (void *)stub_dl_catch_exception    },
    { "_dl_audit_symbind_alt",   (void *)stub_dl_audit_noop         },
    { "_dl_audit_preinit",       (void *)stub_dl_audit_noop         },
    { "_dl_get_tls_static_info", (void *)stub_dl_get_tls_static_info},
    { "_dl_allocate_tls",        (void *)stub_dl_allocate_tls       },
    { "_dl_allocate_tls_init",   (void *)stub_dl_allocate_tls_init  },
    { "_dl_deallocate_tls",      (void *)stub_dl_deallocate_tls     },
    { "_dl_rtld_di_serinfo",     (void *)stub_dl_rtld_di_serinfo    },
    { "__nptl_change_stack_perm",(void *)stub_nptl_change_stack_perm},
    { "__tls_get_addr",          (void *)stub_tls_get_addr          },
    { NULL, NULL }
};

static uint64_t lookup_stub(const char *name)
{
    for (const struct stub_sym *s = g_stubs; s->name; s++)
        if (strcmp(name, s->name) == 0)
            return (uint64_t)(uintptr_t)s->addr;
    return 0;
}

/* Resolve one of the loader-owned OBJECT shims together with the exact amount
 * of backing storage that is safe to read.  Ordinary relocations need only the
 * address; COPY relocations must also bound their source read because the
 * requester's symbol size is not authoritative for our synthetic object. */
static int lookup_fake_object_region(const char *name, const void **address_out,
                                     size_t *size_out)
{
    const void *address = NULL;
    size_t size = 0;

    if (strcmp(name, "_rtld_global") == 0) {
        address = g_fake_rtld_global;
        size = GL_SIZE;
    } else if (strcmp(name, "_rtld_global_ro") == 0) {
        address = g_fake_rtld_global_ro;
        size = GLRO_SIZE;
    } else if (strcmp(name, "__libc_stack_end") == 0) {
        address = &g_fake_libc_stack_end;
        size = sizeof(g_fake_libc_stack_end);
    } else if (strcmp(name, "__libc_enable_secure") == 0) {
        address = &g_fake_libc_enable_secure;
        size = sizeof(g_fake_libc_enable_secure);
    } else if (strcmp(name, "_dl_argv") == 0) {
        address = &g_fake_dl_argv;
        size = sizeof(g_fake_dl_argv);
    } else if (strcmp(name, "__stack_chk_guard") == 0) {
        address = &g_fake_stack_chk_guard;
        size = sizeof(g_fake_stack_chk_guard);
    } else if (strcmp(name, "__pointer_chk_guard") == 0) {
        address = &g_fake_pointer_chk_guard;
        size = sizeof(g_fake_pointer_chk_guard);
    } else if (strcmp(name, "__rseq_offset") == 0) {
        address = &g_rseq_offset;
        size = sizeof(g_rseq_offset);
    } else if (strcmp(name, "__rseq_size") == 0) {
        address = &g_rseq_size;
        size = sizeof(g_rseq_size);
    } else if (strcmp(name, "__rseq_flags") == 0) {
        address = &g_rseq_flags;
        size = sizeof(g_rseq_flags);
    }

    if (!address || size == 0)
        return 0;
    if (address_out)
        *address_out = address;
    if (size_out)
        *size_out = size;
    return 1;
}

/* Check if a symbol name should resolve to one of our fake OBJECT regions. */
static uint64_t lookup_fake_object(const char *name)
{
    const void *address;

    if (!lookup_fake_object_region(name, &address, NULL))
        return 0;
    return (uint64_t)(uintptr_t)address;
}

/* ---- Unified special-symbol hash table --------------------------------
 * Declared here, populated later after g_overrides is defined. */
#define SPECIAL_TAB_SIZE 128  /* must be power of 2, > total special syms */
static struct { uint32_t hash; const char *name; uint64_t addr; uint8_t used; }
    g_special_tab[SPECIAL_TAB_SIZE];
static int g_special_tab_ready;

/* Forward declarations — defined after g_overrides and gnu_hash_calc */
static void build_special_table(void);
static uint64_t lookup_special(const char *name, uint32_t gh);

/* ---- per-object runtime state ----------------------------------------- */
#define MAX_TOTAL_OBJS 512

struct obj_tls {
    int64_t  tpoff;       /* signed offset from TP to TLS block    */
    uint64_t filesz;      /* .tdata initialization size             */
    uint64_t memsz;       /* total TLS block (tdata + tbss)         */
    uint64_t vaddr;       /* p_vaddr of PT_TLS (in loaded image)    */
    uint64_t align;       /* PT_TLS alignment                       */
    size_t   modid;       /* DTV module ID (1-indexed)              */
};

static int tls_tpoff_value(const struct obj_tls *tls, uint64_t symbol_offset,
                           int64_t addend, int64_t *out)
{
    int64_t value;

    if (!tls || tls->memsz == 0 || symbol_offset > tls->memsz ||
        !i64_add_u64_checked(tls->tpoff, symbol_offset, &value) ||
        !i64_add_checked(value, addend, out))
        return 0;
    return 1;
}

static int tls_dtpoff_value(const struct obj_tls *tls,
                            uint64_t symbol_offset, int64_t addend,
                            uint64_t *out)
{
    if (!tls || !u64_add_i64_checked(symbol_offset, addend, out) ||
        tls->memsz == 0 || *out > tls->memsz)
        return 0;
    return 1;
}

struct loaded_obj {
    const char       *name;
    uint64_t          base;
    uint32_t          flags;
    const uint8_t    *elf;
    size_t            elf_size;

    /* Dynamic symbol table */
    const Elf64_Sym  *dynsym;
    const char       *dynstr;
    size_t            dynstr_size;
    uint32_t          dynsym_count;
    const uint32_t   *gnu_hash;
    const uint32_t   *sysv_hash;
    const uint16_t   *versym;
    const Elf64_Verdef *verdef;
    uint32_t          verdef_count;
    const Elf64_Verneed *verneed;
    uint32_t          verneed_count;

    /* Bounded PT_DYNAMIC view, including its terminating DT_NULL entry. */
    const Elf64_Dyn  *dynamic;
    size_t            dynamic_count;

    /* Relocations */
    const Elf64_Rela *rela;
    size_t            rela_count;
    size_t            rela_relative_count; /* DT_RELACOUNT: # of leading RELATIVE entries */
    const Elf64_Rela *jmprel;
    size_t            jmprel_count;
    const Elf64_Relr *relr;
    size_t            relr_count;

    /* Init / Fini */
    void           (**preinit_array)(void);
    size_t            preinit_array_sz;
    void            (*init_func)(void);
    void           (**init_array)(void);
    size_t            init_array_sz;
    void            (*fini_func)(void);
    void           (**fini_array)(void);
    size_t            fini_array_sz;
    int               init_started;

    /* Entry point (exe only) */
    uint64_t          entry;

    /* Program headers (for dl_iterate_phdr / _dl_find_object) */
    const Elf64_Phdr *phdr;
    uint16_t          phdr_num;
    uintptr_t         map_start;   /* base + vaddr_lo (first mapped byte) */
    uintptr_t         map_end;     /* base + vaddr_hi (past-the-end) */
    const void       *eh_frame_hdr; /* mapped PT_GNU_EH_FRAME, or NULL */

    /* Whole lazy-load reservation, used to discard an unsuccessful dlopen
     * transaction without leaving partially mapped dependency objects. */
    void             *runtime_reservation;
    size_t            runtime_reservation_size;
    uint64_t          runtime_dev;
    uint64_t          runtime_ino;
    int               runtime_identity_valid;

    /* Direct DT_NEEDED edges and the cached breadth-first dependency
     * closure rooted at this object.  Indices refer to g_all_objs. */
    uint16_t          needed_indices[MAX_TOTAL_OBJS];
    uint16_t          lookup_scope_indices[MAX_TOTAL_OBJS];
    uint16_t          needed_count;
    uint16_t          lookup_scope_count;
    uint16_t          relocation_scope_root;
    uint8_t           lookup_scope_valid;
    uint8_t           relocation_scope_root_valid;

    /* TLS */
    struct obj_tls    tls;
};

static const Elf64_Sym *lookup_linear(const struct loaded_obj *obj,
                                      const char *name);
static uint64_t lookup_elf_symbol_addr(const struct loaded_obj *obj,
                                       const char *name);

static int loaded_obj_contains(const struct loaded_obj *obj,
                               uintptr_t addr, size_t size)
{
    if (!obj || !obj->phdr)
        return 0;

    for (uint16_t i = 0; i < obj->phdr_num; i++) {
        const Elf64_Phdr *ph = &obj->phdr[i];
        uintptr_t start;
        size_t offset;

        if (ph->p_type != PT_LOAD || ph->p_memsz > SIZE_MAX ||
            ph->p_vaddr > UINTPTR_MAX - obj->base)
            continue;
        start = (uintptr_t)obj->base + (uintptr_t)ph->p_vaddr;
        if (addr < start)
            continue;
        offset = addr - start;
        if (offset <= ph->p_memsz && size <= ph->p_memsz - offset)
            return 1;
    }
    return 0;
}

static int loaded_obj_file_contains(const struct loaded_obj *obj,
                                    uintptr_t addr, size_t size)
{
    if (!obj || !obj->phdr)
        return 0;

    for (uint16_t i = 0; i < obj->phdr_num; i++) {
        const Elf64_Phdr *ph = &obj->phdr[i];
        uintptr_t start;
        size_t offset;

        if (ph->p_type != PT_LOAD || ph->p_filesz > ph->p_memsz ||
            ph->p_filesz > SIZE_MAX ||
            ph->p_vaddr > UINTPTR_MAX - obj->base)
            continue;
        start = (uintptr_t)obj->base + (uintptr_t)ph->p_vaddr;
        if (addr < start)
            continue;
        offset = addr - start;
        if (offset <= ph->p_filesz && size <= ph->p_filesz - offset)
            return 1;
    }
    return 0;
}

static int loaded_obj_vaddr_pointer(const struct loaded_obj *obj,
                                    uint64_t vaddr, size_t size,
                                    uint32_t required_flags,
                                    void **pointer_out)
{
    uintptr_t addr;

    if (!obj || vaddr > UINTPTR_MAX - obj->base)
        return 0;
    addr = (uintptr_t)obj->base + (uintptr_t)vaddr;

    for (uint16_t i = 0; i < obj->phdr_num; i++) {
        const Elf64_Phdr *ph = &obj->phdr[i];
        uintptr_t start;
        size_t offset;

        if (ph->p_type != PT_LOAD ||
            (ph->p_flags & required_flags) != required_flags ||
            ph->p_memsz > SIZE_MAX ||
            ph->p_vaddr > UINTPTR_MAX - obj->base)
            continue;
        start = (uintptr_t)obj->base + (uintptr_t)ph->p_vaddr;
        if (addr < start)
            continue;
        offset = addr - start;
        if (offset <= ph->p_memsz && size <= ph->p_memsz - offset) {
            if (pointer_out)
                *pointer_out = (void *)addr;
            return 1;
        }
    }
    return 0;
}

static int loaded_obj_file_vaddr_pointer(const struct loaded_obj *obj,
                                         uint64_t vaddr, size_t size,
                                         void **pointer_out)
{
    void *pointer;

    if (!loaded_obj_vaddr_pointer(obj, vaddr, size, 0, &pointer) ||
        !loaded_obj_file_contains(obj, (uintptr_t)pointer, size))
        return 0;
    if (pointer_out)
        *pointer_out = pointer;
    return 1;
}

static int discover_eh_frame_header(struct loaded_obj *obj)
{
    int found = 0;

    obj->eh_frame_hdr = NULL;
    for (uint16_t i = 0; i < obj->phdr_num; i++) {
        const Elf64_Phdr *ph = &obj->phdr[i];
        void *pointer;

        if (ph->p_type != PT_GNU_EH_FRAME)
            continue;
        if (ph->p_filesz == 0 && ph->p_memsz == 0)
            continue;
        if (found || ph->p_filesz == 0 || ph->p_filesz > ph->p_memsz ||
            ph->p_filesz > SIZE_MAX || ph->p_memsz > SIZE_MAX ||
            !loaded_obj_file_vaddr_pointer(obj, ph->p_vaddr,
                                            (size_t)ph->p_filesz,
                                            &pointer) ||
            !loaded_obj_vaddr_pointer(obj, ph->p_vaddr,
                                      (size_t)ph->p_memsz, PF_R, NULL))
            return -1;
        obj->eh_frame_hdr = pointer;
        found = 1;
    }
    return 0;
}

static int loaded_obj_signed_offset_pointer(const struct loaded_obj *obj,
                                            int64_t offset, size_t size,
                                            uint32_t required_flags,
                                            void **pointer_out)
{
    uintptr_t addr;

    if (offset < 0) {
        uint64_t magnitude = (uint64_t)(-(offset + 1)) + 1;

        if (magnitude > obj->base)
            return 0;
        addr = (uintptr_t)(obj->base - magnitude);
    } else {
        if ((uint64_t)offset > UINTPTR_MAX - obj->base)
            return 0;
        addr = (uintptr_t)obj->base + (uintptr_t)offset;
    }
    if (!loaded_obj_contains(obj, addr, size))
        return 0;

    if (required_flags != 0) {
        for (uint16_t i = 0; i < obj->phdr_num; i++) {
            const Elf64_Phdr *ph = &obj->phdr[i];
            uintptr_t start;
            size_t within;

            if (ph->p_type != PT_LOAD ||
                (ph->p_flags & required_flags) != required_flags ||
                ph->p_memsz > SIZE_MAX ||
                ph->p_vaddr > UINTPTR_MAX - obj->base)
                continue;
            start = (uintptr_t)obj->base + (uintptr_t)ph->p_vaddr;
            if (addr < start)
                continue;
            within = addr - start;
            if (within <= ph->p_memsz && size <= ph->p_memsz - within)
                goto found;
        }
        return 0;
    }

found:
    if (pointer_out)
        *pointer_out = (void *)addr;
    return 1;
}

/* Objects are finalized in the exact reverse of the order in which their
 * initialization began.  Recording the object before DT_INIT is important:
 * exit() from inside a constructor must still run that object's finalizers,
 * matching the dynamic linker's l_init_called behaviour. */
static struct loaded_obj *g_init_order[MAX_TOTAL_OBJS];
static size_t g_init_order_count;
static int g_fini_running;

static void record_object_init(struct loaded_obj *obj)
{
    if (!obj || obj->init_started)
        return;

    obj->init_started = 1;
    if (g_init_order_count < MAX_TOTAL_OBJS)
        g_init_order[g_init_order_count++] = obj;
}

static void run_loader_finalizers(void)
{
    if (g_fini_running)
        return;
    g_fini_running = 1;

    while (g_init_order_count > 0) {
        struct loaded_obj *obj = g_init_order[--g_init_order_count];

        for (size_t j = obj->fini_array_sz; j > 0; j--)
            obj->fini_array[j - 1]();
        if (obj->fini_func)
            obj->fini_func();
    }
}

static void run_loader_finalizers_cxa(void *unused)
{
    (void)unused;
    run_loader_finalizers();
}

static const struct loaded_obj *find_musl_libc(struct loaded_obj *objs, int nobj)
{
    for (int i = 0; i < nobj; i++) {
        const char *name = objs[i].name;

        if (!name)
            continue;
        if (is_musl_libc_path(name))
            return &objs[i];
    }
    return NULL;
}

static uint64_t musl_defined_symbol_addr(const struct loaded_obj *obj,
                                         const char *name)
{
    const Elf64_Sym *sym = lookup_linear(obj, name);

    if (!sym || sym->st_shndx == SHN_UNDEF || sym->st_size == 0)
        return lookup_elf_symbol_addr(obj, name);
    return obj->base + sym->st_value;
}

static uint32_t read_u32_le(const uint8_t *p)
{
    uint32_t v;

    memcpy(&v, p, sizeof(v));
    return v;
}

#if defined(__x86_64__)
static int read_i32_le(const uint8_t *p)
{
    return (int32_t)read_u32_le(p);
}

static int decode_x86_64_musl_errno_offset(const uint8_t *code, size_t len,
                                           size_t *off_out)
{
    for (size_t i = 0; i + 4 <= len; i++) {
        if (code[i] == 0x48 && code[i + 1] == 0x83 && code[i + 2] == 0xc0) {
            *off_out = code[i + 3];
            return *off_out < MUSL_THREAD_PROBE_LIMIT;
        }
        if (i + 6 <= len && code[i] == 0x48 && code[i + 1] == 0x05) {
            int off = read_i32_le(code + i + 2);

            if (off >= 0 && off < MUSL_THREAD_PROBE_LIMIT) {
                *off_out = (size_t)off;
                return 1;
            }
        }
    }
    return 0;
}

static int decode_x86_64_musl_dtv_offset(const uint8_t *code, size_t len,
                                         size_t *off_out)
{
    for (size_t i = 0; i + 4 <= len; i++) {
        if (code[i] != 0x48 || code[i + 1] != 0x8b)
            continue;

        if ((code[i + 2] & 0xc7) == 0x40) {
            *off_out = code[i + 3];
            return *off_out < MUSL_THREAD_PROBE_LIMIT;
        }
        if (i + 7 <= len && (code[i + 2] & 0xc7) == 0x80) {
            int off = read_i32_le(code + i + 3);

            if (off >= 0 && off < MUSL_THREAD_PROBE_LIMIT) {
                *off_out = (size_t)off;
                return 1;
            }
        }
    }
    return 0;
}

static int decode_x86_64_mem_disp(const uint8_t *code, size_t len,
                                  size_t i, size_t opcode_len,
                                  size_t *off_out, unsigned int *base_out)
{
    uint8_t modrm;
    uint8_t rex = 0;
    unsigned int mod;
    unsigned int base;
    size_t displacement;
    int off;

    if (i + opcode_len >= len)
        return 0;
    if (opcode_len > 1 && (code[i] & 0xf0) == 0x40)
        rex = code[i];
    modrm = code[i + opcode_len];
    mod = modrm >> 6;
    if (mod != 1 && mod != 2)
        return 0;
    displacement = i + opcode_len + 1;
    if ((modrm & 7) == 4) {
        uint8_t sib;

        if (displacement >= len)
            return 0;
        sib = code[displacement++];
        /* Accept the RSP/R12 encoding only when the SIB has no index.  An
         * indexed address is not a direct struct pthread field access. */
        if (((sib >> 3) & 7) != 4)
            return 0;
        base = (sib & 7) | ((rex & 1) ? 8 : 0);
    } else {
        base = (modrm & 7) | ((rex & 1) ? 8 : 0);
    }
    if (mod == 1) {
        if (displacement + 1 > len)
            return 0;
        off = (int8_t)code[displacement];
    } else {
        if (displacement + 4 > len)
            return 0;
        off = read_i32_le(code + displacement);
    }
    if (off < 0 || off >= MUSL_THREAD_PROBE_LIMIT)
        return 0;
    *off_out = (size_t)off;
    *base_out = base;
    return 1;
}

static uint32_t x86_64_musl_self_registers(const uint8_t *code, size_t len)
{
    uint32_t registers = 1u << 7; /* first argument: RDI */
    size_t limit = len < 32 ? len : 32;

    /* GCC and Clang preserve pthread_kill's first argument in a callee-saved
     * register in the prologue.  Recognize only direct 64-bit register moves
     * from RDI; do not infer provenance from arbitrary later loads. */
    for (size_t i = 0; i + 3 <= limit; i++) {
        uint8_t rex = code[i];
        uint8_t opcode = code[i + 1];
        uint8_t modrm = code[i + 2];
        unsigned int source;
        unsigned int destination;

        if ((rex & 0xf8) != 0x48 ||
            (opcode != 0x89 && opcode != 0x8b) ||
            (modrm >> 6) != 3)
            continue;
        if (opcode == 0x89) {
            source = ((modrm >> 3) & 7) | ((rex & 4) ? 8 : 0);
            destination = (modrm & 7) | ((rex & 1) ? 8 : 0);
        } else {
            source = (modrm & 7) | ((rex & 1) ? 8 : 0);
            destination = ((modrm >> 3) & 7) | ((rex & 4) ? 8 : 0);
        }
        if (source == 7)
            registers |= 1u << destination;
    }
    return registers;
}

/* pthread_kill loads the target thread's tid immediately before its tkill
 * syscall.  Decode the closest displaced 32-bit load rather than assuming
 * that tid precedes errno in struct pthread (it did not in musl 1.1.x). */
static int decode_x86_64_musl_tid_offset(const uint8_t *code, size_t len,
                                         size_t *off_out)
{
    uint32_t self_registers = x86_64_musl_self_registers(code, len);

    for (size_t i = 0; i + 7 <= len; i++) {
        uint32_t nr;
        size_t begin;
        size_t candidate = 0;
        int found = 0;

        if (code[i] != 0xb8 || code[i + 5] != 0x0f || code[i + 6] != 0x05)
            continue;
        nr = read_u32_le(code + i + 1);
        if (nr != SYS_tkill && nr != SYS_tgkill)
            continue;

        begin = i > 48 ? i - 48 : 0;
        for (size_t j = begin; j < i; j++) {
            size_t off;
            unsigned int base;

            if (code[j] == 0x8b &&
                decode_x86_64_mem_disp(code, i, j, 1, &off, &base) &&
                (self_registers & (1u << base))) {
                candidate = off;
                found = 1;
            } else if (j + 1 < i && (code[j] & 0xf0) == 0x40 &&
                       (code[j + 1] == 0x8b || code[j + 1] == 0x63) &&
                       decode_x86_64_mem_disp(code, i, j, 2, &off, &base) &&
                       (self_registers & (1u << base))) {
                candidate = off;
                found = 1;
            }
        }
        if (found) {
            *off_out = candidate;
            return 1;
        }
    }

    return 0;
}

/* Old musl pthread_detach stores its detached marker directly; newer musl
 * transitions a state machine with cmpxchg.  Both expose the field offset. */
static int decode_x86_64_musl_detach_offset(const uint8_t *code, size_t len,
                                            size_t *off_out,
                                            int *initial_out)
{
    for (size_t i = 0; i + 3 <= len; i++) {
        size_t off;
        unsigned int base;
        size_t disp_len;
        size_t imm_pos;

        if (code[i] != 0xc7 || (code[i + 1] & 7) != 7 ||
            (code[i + 1] >> 6) < 1 || (code[i + 1] >> 6) > 2 ||
            !decode_x86_64_mem_disp(code, len, i, 1, &off, &base) ||
            base != 7)
            continue;
        disp_len = (code[i + 1] >> 6) == 1 ? 1 : 4;
        imm_pos = i + 2 + disp_len;
        if (imm_pos + sizeof(uint32_t) <= len &&
            read_u32_le(code + imm_pos) == 2) {
            *off_out = off;
            /* The old boolean field starts clear; detach writes 2. */
            *initial_out = 0;
            return 1;
        }
    }

    for (size_t i = 0; i + 4 <= len; i++) {
        size_t off;
        unsigned int base;

        if (code[i] == 0xf0 && code[i + 1] == 0x0f &&
            code[i + 2] == 0xb1 &&
            (code[i + 3] & 7) == 7 &&
            (code[i + 3] >> 6) >= 1 && (code[i + 3] >> 6) <= 2 &&
            decode_x86_64_mem_disp(code, len, i, 3, &off, &base) &&
            base == 7 && off == g_musl_layout->thread_detach) {
            *off_out = off;
            /* State-machine musl transitions JOINABLE (2) to DETACHED. */
            *initial_out = 2;
            return 1;
        }
    }

    /* musl 1.1.19 first advances the pthread argument to exitlock and
     * subsequently stores the detached marker through a negative disp8.
     * Decode that complete, register-preserving sequence; neither operand
     * alone is evidence for the detached field. */
    for (size_t i = 0; i + 7 <= len; i++) {
        uint32_t addend;

        if (code[i] != 0x48 || code[i + 1] != 0x81 ||
            code[i + 2] != 0xc7)
            continue;
        addend = read_u32_le(code + i + 3);
        for (size_t j = i + 7; j + 7 <= len && j <= i + 32; j++) {
            int64_t off;

            if (code[j] != 0xc7 || code[j + 1] != 0x47 ||
                read_u32_le(code + j + 3) != 2)
                continue;
            off = (int64_t)addend + (int8_t)code[j + 2];
            if (off >= 0 && off < MUSL_THREAD_PROBE_LIMIT) {
                *off_out = (size_t)off;
                *initial_out = 0;
                return 1;
            }
        }
    }
    return 0;
}
#endif

#if defined(__aarch64__)
static int aarch64_is_mrs_tpidr_el0(uint32_t insn, int *rt)
{
    if ((insn & 0xffffffe0u) != 0xd53bd040u)
        return 0;
    *rt = (int)(insn & 0x1f);
    return 1;
}

static int aarch64_decode_addsub_imm(uint32_t insn, int rn, int rd,
                                     int64_t *imm_out)
{
    uint64_t imm;

    if ((insn & 0x80000000u) == 0 || (insn & 0x20000000u) != 0 ||
        (insn & 0x1f000000u) != 0x11000000u)
        return 0;
    if ((int)((insn >> 5) & 0x1f) != rn || (int)(insn & 0x1f) != rd)
        return 0;

    imm = (insn >> 10) & 0xfff;
    if ((insn >> 22) & 1)
        imm <<= 12;
    if (imm >= MUSL_THREAD_PROBE_LIMIT * 8)
        return 0;

    *imm_out = (insn & 0x40000000u) ? -(int64_t)imm : (int64_t)imm;
    return 1;
}

static int aarch64_decode_ldr64_unsigned(uint32_t insn, int rn,
                                         size_t *off_out)
{
    size_t off;

    if ((insn & 0xffc00000u) != 0xf9400000u)
        return 0;
    if ((int)((insn >> 5) & 0x1f) != rn)
        return 0;

    off = ((insn >> 10) & 0xfff) * sizeof(uint64_t);
    if (off >= MUSL_THREAD_PROBE_LIMIT)
        return 0;
    *off_out = off;
    return 1;
}

static int aarch64_decode_ldur64_signed(uint32_t insn, int rn,
                                        int64_t *off_out)
{
    int64_t off;

    if ((insn & 0xffe00c00u) != 0xf8400000u)
        return 0;
    if ((int)((insn >> 5) & 0x1f) != rn)
        return 0;

    off = (insn >> 12) & 0x1ff;
    if (off & 0x100)
        off -= 0x200;
    if (off <= -(int64_t)MUSL_THREAD_PROBE_LIMIT ||
        off >= (int64_t)MUSL_THREAD_PROBE_LIMIT)
        return 0;
    *off_out = off;
    return 1;
}

static int decode_aarch64_musl_self_delta(const uint8_t *code, size_t len,
                                          size_t *delta_out)
{
    for (size_t i = 0; i + 4 <= len; i += 4) {
        uint32_t insn = read_u32_le(code + i);
        int rt;

        if (!aarch64_is_mrs_tpidr_el0(insn, &rt))
            continue;
        if (i + 8 <= len && read_u32_le(code + i + 4) == 0xd65f03c0u &&
            rt == 0) {
            *delta_out = 0;
            return 1;
        }
        if (i + 8 <= len) {
            int64_t imm;

            if (aarch64_decode_addsub_imm(read_u32_le(code + i + 4), rt, 0, &imm) &&
                imm <= 0) {
                *delta_out = (size_t)-imm;
                return *delta_out < MUSL_THREAD_PROBE_LIMIT;
            }
        }
    }
    return 0;
}

static int decode_aarch64_musl_tp_relative(const uint8_t *code, size_t len,
                                           int64_t *tp_rel_out)
{
    for (size_t i = 0; i + 8 <= len; i += 4) {
        uint32_t insn = read_u32_le(code + i);
        int rt;

        if (!aarch64_is_mrs_tpidr_el0(insn, &rt))
            continue;
        if (aarch64_decode_addsub_imm(read_u32_le(code + i + 4), rt, 0,
                                      tp_rel_out))
            return 1;
    }
    return 0;
}

static int decode_aarch64_musl_dtv_offset(const uint8_t *code, size_t len,
                                          size_t self_delta,
                                          size_t *off_out)
{
    for (size_t i = 0; i + 8 <= len; i += 4) {
        uint32_t insn = read_u32_le(code + i);
        int rt;

        if (!aarch64_is_mrs_tpidr_el0(insn, &rt))
            continue;
        for (size_t j = i + 4; j + 4 <= len && j <= i + 24; j += 4) {
            size_t tp_off;
            int64_t tp_rel;

            if (aarch64_decode_ldr64_unsigned(read_u32_le(code + j), rt, &tp_off) &&
                self_delta + tp_off < MUSL_THREAD_PROBE_LIMIT) {
                *off_out = self_delta + tp_off;
                return 1;
            }
            if (aarch64_decode_ldur64_signed(read_u32_le(code + j), rt, &tp_rel) &&
                (int64_t)self_delta + tp_rel >= 0 &&
                (int64_t)self_delta + tp_rel < MUSL_THREAD_PROBE_LIMIT) {
                *off_out = (size_t)((int64_t)self_delta + tp_rel);
                return 1;
            }
        }
    }
    return 0;
}

static uint32_t aarch64_musl_self_registers(const uint8_t *code, size_t len)
{
    uint32_t registers = 1u; /* first argument: X0 */
    size_t limit = len < 32 ? len : 32;

    for (size_t i = 0; i + 4 <= limit; i += 4) {
        uint32_t insn = read_u32_le(code + i);
        unsigned int source;
        unsigned int destination;

        /* MOV Xd, Xm is the ORR Xd, XZR, Xm alias. */
        if ((insn & 0xffe0ffe0u) == 0xaa0003e0u) {
            source = (insn >> 16) & 0x1f;
            destination = insn & 0x1f;
            if (source == 0)
                registers |= 1u << destination;
            continue;
        }

        /* Some compilers spell the same prologue copy as ADD Xd, X0, #0. */
        if ((insn & 0xffffffe0u) == 0x91000000u) {
            destination = insn & 0x1f;
            registers |= 1u << destination;
        }
    }
    return registers;
}

/* pthread_kill's inline tkill consumes a tid loaded through the pthread
 * argument (X0 or its prologue copy).  Requiring both that provenance and
 * the syscall number prevents a stack/local load from becoming an offset. */
static int decode_aarch64_musl_tid_offset(const uint8_t *code, size_t len,
                                          size_t *off_out)
{
    uint32_t self_registers = aarch64_musl_self_registers(code, len);

    for (size_t i = 0; i + 4 <= len; i += 4) {
        size_t candidate = 0;
        int found = 0;
        int has_tkill_number = 0;
        size_t begin;

        if (read_u32_le(code + i) != 0xd4000001u) /* svc #0 */
            continue;
        begin = i > 64 ? i - 64 : 0;
        for (size_t j = begin; j < i; j += 4) {
            uint32_t insn = read_u32_le(code + j);
            size_t off;
            unsigned int base;

            if ((insn & 0x7f800000u) == 0x52800000u &&
                (insn & 0x1f) == 8 &&
                (((insn >> 5) & 0xffff) == SYS_tkill ||
                 ((insn >> 5) & 0xffff) == SYS_tgkill))
                has_tkill_number = 1;

            if ((insn & 0xffc00000u) != 0xb9400000u &&
                (insn & 0xffc00000u) != 0xb9800000u)
                continue;
            base = (insn >> 5) & 0x1f;
            if (!(self_registers & (1u << base)))
                continue;
            off = ((insn >> 10) & 0xfff) * sizeof(uint32_t);
            if (off >= MUSL_THREAD_PROBE_LIMIT)
                continue;
            candidate = off;
            found = 1;
        }
        if (found && has_tkill_number) {
            *off_out = candidate;
            return 1;
        }
    }
    return 0;
}

/* As on x86-64, old pthread_detach directly stores a detached marker while
 * modern implementations use an exclusive state transition. */
static int decode_aarch64_musl_detach_offset(const uint8_t *code, size_t len,
                                             size_t *off_out,
                                             int *initial_out)
{
    for (size_t i = 0; i + 4 <= len; i += 4) {
        uint32_t mov = read_u32_le(code + i);
        unsigned int value_reg;

        if ((mov & 0x7f800000u) != 0x52800000u ||
            ((mov >> 5) & 0xffff) != 2)
            continue;
        value_reg = mov & 0x1f;
        for (size_t j = i + 4; j + 4 <= len && j <= i + 16; j += 4) {
            uint32_t store = read_u32_le(code + j);
            size_t off;

            if ((store & 0xffc00000u) != 0xb9000000u ||
                ((store >> 5) & 0x1f) != 0 ||
                (store & 0x1f) != value_reg)
                continue;
            off = ((store >> 10) & 0xfff) * sizeof(uint32_t);
            if (off < MUSL_THREAD_PROBE_LIMIT) {
                *off_out = off;
                *initial_out = 0;
                return 1;
            }
        }
    }

    for (size_t i = 0; i + 8 <= len; i += 4) {
        uint32_t add = read_u32_le(code + i);
        unsigned int address_reg;
        uint64_t off;

        if ((add & 0xff000000u) != 0x91000000u ||
            ((add >> 5) & 0x1f) != 0)
            continue;
        address_reg = add & 0x1f;
        off = (add >> 10) & 0xfff;
        if ((add >> 22) & 1)
            off <<= 12;
        if (off >= MUSL_THREAD_PROBE_LIMIT)
            continue;
        /* Stack-protected builds may interleave their canary prologue with
         * the detach transition (Debian 13 places LDAXR 56 bytes after the
         * address calculation).  Keep admission fail-closed by requiring
         * the complete JOINABLE (2) -> DETACHED (3) exclusive sequence. */
        for (size_t j = i + 4; j + 4 <= len && j <= i + 80; j += 4) {
            uint32_t load = read_u32_le(code + j);
            unsigned int loaded_reg;
            int has_joinable_compare = 0;
            int has_detached_store = 0;

            if ((load & 0xfffffc00u) != 0x885ffc00u ||
                ((load >> 5) & 0x1f) != address_reg)
                continue;
            loaded_reg = load & 0x1f;

            for (size_t k = j + 4; k + 4 <= len && k <= j + 16; k += 4) {
                uint32_t compare = read_u32_le(code + k);

                if ((compare & 0xff00001fu) == 0x7100001fu &&
                    ((compare >> 5) & 0x1f) == loaded_reg &&
                    ((compare >> 10) & 0xfff) == 2 &&
                    ((compare >> 22) & 1) == 0) {
                    has_joinable_compare = 1;
                    break;
                }
            }
            if (!has_joinable_compare)
                continue;

            size_t store_begin = j > i + 16 ? j - 16 : i + 4;
            for (size_t k = store_begin;
                 k + 4 <= len && k <= j + 24; k += 4) {
                uint32_t store = read_u32_le(code + k);
                unsigned int value_reg;

                if ((store & 0xffe0fc00u) != 0x8800fc00u ||
                    ((store >> 5) & 0x1f) != address_reg)
                    continue;
                value_reg = store & 0x1f;
                for (size_t m = i + 4; m <= k; m += 4) {
                    uint32_t mov = read_u32_le(code + m);

                    if ((mov & 0x7f800000u) == 0x52800000u &&
                        ((mov >> 5) & 0xffff) == 3 &&
                        ((mov >> 21) & 3) == 0 &&
                        (mov & 0x1f) == value_reg) {
                        has_detached_store = 1;
                        break;
                    }
                }
                if (has_detached_store)
                    break;
            }
            if (has_detached_store) {
                *off_out = (size_t)off;
                *initial_out = 2;
                return 1;
            }
        }
    }
    return 0;
}
#endif

#if defined(__x86_64__)
static int decode_x86_64_musl_libc_addr(const struct loaded_obj *libc_obj,
                                        const uint8_t *code, size_t len,
                                        uintptr_t *addr_out)
{
    uint8_t cmp_opcode = g_musl_layout->libc_flag_width == 1 ? 0x80 : 0x83;

    for (size_t i = 0; i + 7 <= len; i++) {
        uintptr_t first;

        if (code[i] != cmp_opcode || code[i + 1] != 0x3d ||
            code[i + 6] != 0)
            continue;
        first = (uintptr_t)(code + i + 7) +
                (intptr_t)read_i32_le(code + i + 2);
        if (first < libc_obj->base + g_musl_layout->libc_can_do_threads)
            continue;
        uintptr_t candidate = first - g_musl_layout->libc_can_do_threads;

        for (size_t j = i + 7; j + 7 <= len && j <= i + 160; j++) {
            uintptr_t second;
            void *checked;

            if (code[j] != cmp_opcode || code[j + 1] != 0x3d ||
                code[j + 6] != 0)
                continue;
            second = (uintptr_t)(code + j + 7) +
                     (intptr_t)read_i32_le(code + j + 2);
            if (second != candidate + g_musl_layout->libc_threaded ||
                candidate < libc_obj->base ||
                candidate - libc_obj->base > INT64_MAX ||
                !loaded_obj_signed_offset_pointer(
                    libc_obj, (int64_t)(candidate - libc_obj->base),
                    g_musl_layout->libc_size, PF_W, &checked))
                continue;
            *addr_out = (uintptr_t)checked;
            return 1;
        }
    }
    return 0;
}
#elif defined(__aarch64__)
static int aarch64_decode_musl_adrp(uintptr_t pc, uint32_t insn,
                                    unsigned int *rd_out,
                                    uintptr_t *page_out)
{
    int64_t imm;

    if ((insn & 0x9f000000u) != 0x90000000u)
        return 0;
    imm = (int64_t)((((uint64_t)insn >> 5) & 0x7ffffu) << 2 |
                    (((uint64_t)insn >> 29) & 3));
    if (imm & (1 << 20))
        imm -= (1 << 21);
    imm <<= 12;
    *rd_out = insn & 0x1f;
    *page_out = (uintptr_t)((int64_t)(pc & ~(uintptr_t)0xfff) + imm);
    return 1;
}

static int decode_aarch64_musl_libc_addr(const struct loaded_obj *libc_obj,
                                         const uint8_t *code, size_t len,
                                         uintptr_t *addr_out)
{
    for (size_t i = 0; i + 4 <= len; i += 4) {
        unsigned int page_reg;
        uintptr_t page;

        if (!aarch64_decode_musl_adrp((uintptr_t)(code + i),
                                      read_u32_le(code + i),
                                      &page_reg, &page))
            continue;
        for (size_t j = i + 4; j + 4 <= len && j <= i + 64; j += 4) {
            uint32_t load = read_u32_le(code + j);
            uintptr_t first;

            if ((load & 0xffc00000u) != 0x39400000u ||
                ((load >> 5) & 0x1f) != page_reg)
                continue;
            first = page + ((load >> 10) & 0xfff);
            if (first < libc_obj->base +
                        g_musl_layout->libc_can_do_threads)
                continue;
            uintptr_t candidate =
                first - g_musl_layout->libc_can_do_threads;

            for (size_t k = j + 4; k + 8 <= len && k <= j + 96; k += 4) {
                uint32_t add = read_u32_le(code + k);
                unsigned int base_reg;
                uint64_t addend;

                if ((add & 0xff000000u) != 0x91000000u ||
                    ((add >> 5) & 0x1f) != page_reg)
                    continue;
                base_reg = add & 0x1f;
                addend = (add >> 10) & 0xfff;
                if ((add >> 22) & 1)
                    addend <<= 12;
                if (page + addend != candidate)
                    continue;
                /* pthread_create may finish its argument setup between the
                 * address calculation and the threaded flag load (musl
                 * 1.2.5 AArch64 places the load 32 bytes later). */
                for (size_t m = k + 4; m + 4 <= len && m <= k + 48;
                     m += 4) {
                    uint32_t second = read_u32_le(code + m);
                    void *checked;

                    if ((second & 0xffc00000u) != 0x39400000u ||
                        ((second >> 5) & 0x1f) != base_reg ||
                        ((second >> 10) & 0xfff) !=
                            g_musl_layout->libc_threaded ||
                        candidate < libc_obj->base ||
                        candidate - libc_obj->base > INT64_MAX ||
                        !loaded_obj_signed_offset_pointer(
                            libc_obj,
                            (int64_t)(candidate - libc_obj->base),
                            g_musl_layout->libc_size, PF_W, &checked))
                        continue;
                    *addr_out = (uintptr_t)checked;
                    return 1;
                }
            }
        }
    }
    return 0;
}
#endif

static int validate_musl_layout_from_target(const struct loaded_obj *libc_obj)
{
    g_musl_target_tid_known = 0;
    g_musl_target_errno_known = 0;
    g_musl_target_detach_known = 0;
    g_musl_target_detach_value = g_musl_layout->detach_initial;
#if defined(__x86_64__)
    uint64_t addr;
    size_t off;

    if (!libc_obj)
        return 0;

    addr = musl_defined_symbol_addr(libc_obj, "__errno_location");
    if (addr && loaded_obj_contains(libc_obj, (uintptr_t)addr, 32) &&
        decode_x86_64_musl_errno_offset((const uint8_t *)(uintptr_t)addr, 32,
                                        &off) &&
        off == g_musl_layout->thread_errno) {
        g_musl_target_errno_known = 1;
    } else {
        ldr_dbg("[loader] musl profile mismatch: errno\n");
        return 0;
    }

    addr = musl_defined_symbol_addr(libc_obj, "__tls_get_addr");
    if (addr && loaded_obj_contains(libc_obj, (uintptr_t)addr, 48) &&
        decode_x86_64_musl_dtv_offset((const uint8_t *)(uintptr_t)addr, 48,
                                      &off) &&
        off == g_musl_layout->thread_dtv) {
        /* validated */
    } else {
        ldr_dbg("[loader] musl profile mismatch: DTV\n");
        return 0;
    }

    addr = musl_defined_symbol_addr(libc_obj, "pthread_kill");
    if (addr && loaded_obj_contains(libc_obj, (uintptr_t)addr, 128) &&
        decode_x86_64_musl_tid_offset((const uint8_t *)(uintptr_t)addr,
                                      128, &off) &&
        off == g_musl_layout->thread_tid) {
        g_musl_target_tid_known = 1;
    } else {
        ldr_dbg("[loader] musl profile mismatch: tid\n");
        return 0;
    }

    addr = musl_defined_symbol_addr(libc_obj, "pthread_detach");
    if (addr && loaded_obj_contains(libc_obj, (uintptr_t)addr, 128) &&
        decode_x86_64_musl_detach_offset((const uint8_t *)(uintptr_t)addr,
                                         128, &off,
                                         &g_musl_target_detach_value) &&
        off == g_musl_layout->thread_detach &&
        g_musl_target_detach_value == g_musl_layout->detach_initial) {
        g_musl_target_detach_known = 1;
    } else {
        ldr_dbg("[loader] musl profile mismatch: detach state\n");
        return 0;
    }

    addr = musl_defined_symbol_addr(libc_obj, "pthread_create");
    if (!addr || !loaded_obj_contains(libc_obj, (uintptr_t)addr, 768) ||
        !decode_x86_64_musl_libc_addr(
            libc_obj, (const uint8_t *)(uintptr_t)addr, 768,
            &g_musl_libc_addr))
    {
        ldr_dbg("[loader] musl profile mismatch: libc state base\n");
        return 0;
    }
#elif defined(__aarch64__)
    uint64_t addr;
    size_t off;

    if (!libc_obj)
        return 0;

    addr = musl_defined_symbol_addr(libc_obj, "pthread_self");
    if (addr && loaded_obj_contains(libc_obj, (uintptr_t)addr, 32) &&
        decode_aarch64_musl_self_delta((const uint8_t *)(uintptr_t)addr, 32,
                                       &off) &&
        off == g_musl_layout->tp_self_delta) {
        /* validated */
    } else {
        ldr_dbg("[loader] musl profile mismatch: pthread self\n");
        return 0;
    }

    addr = musl_defined_symbol_addr(libc_obj, "__errno_location");
    if (addr && loaded_obj_contains(libc_obj, (uintptr_t)addr, 32)) {
        int64_t tp_rel;

        if (decode_aarch64_musl_tp_relative((const uint8_t *)(uintptr_t)addr, 32, &tp_rel) &&
            tp_rel + (int64_t)g_musl_tp_self_delta >= 0 &&
            tp_rel + (int64_t)g_musl_tp_self_delta < MUSL_THREAD_PROBE_LIMIT) {
            off = (size_t)(tp_rel + (int64_t)g_musl_tp_self_delta);
            if (off == g_musl_layout->thread_errno)
                g_musl_target_errno_known = 1;
        }
    }
    if (!g_musl_target_errno_known) {
        ldr_dbg("[loader] musl profile mismatch: errno\n");
        return 0;
    }

    addr = musl_defined_symbol_addr(libc_obj, "__tls_get_addr");
    if (addr && loaded_obj_contains(libc_obj, (uintptr_t)addr, 64) &&
        decode_aarch64_musl_dtv_offset((const uint8_t *)(uintptr_t)addr, 64,
                                       g_musl_tp_self_delta, &off) &&
        off == g_musl_layout->thread_dtv) {
        /* validated */
    } else {
        ldr_dbg("[loader] musl profile mismatch: DTV\n");
        return 0;
    }

    addr = musl_defined_symbol_addr(libc_obj, "pthread_kill");
    if (addr && loaded_obj_contains(libc_obj, (uintptr_t)addr, 128) &&
        decode_aarch64_musl_tid_offset((const uint8_t *)(uintptr_t)addr,
                                       128, &off) &&
        off == g_musl_layout->thread_tid) {
        g_musl_target_tid_known = 1;
    } else {
        ldr_dbg("[loader] musl profile mismatch: tid\n");
        return 0;
    }

    addr = musl_defined_symbol_addr(libc_obj, "pthread_detach");
    if (addr && loaded_obj_contains(libc_obj, (uintptr_t)addr, 128) &&
        decode_aarch64_musl_detach_offset((const uint8_t *)(uintptr_t)addr,
                                          128, &off,
                                          &g_musl_target_detach_value) &&
        off == g_musl_layout->thread_detach &&
        g_musl_target_detach_value == g_musl_layout->detach_initial) {
        g_musl_target_detach_known = 1;
    } else {
        ldr_dbg("[loader] musl profile mismatch: detach state\n");
        return 0;
    }

    addr = musl_defined_symbol_addr(libc_obj, "pthread_create");
    if (!addr || !loaded_obj_contains(libc_obj, (uintptr_t)addr, 768) ||
        !decode_aarch64_musl_libc_addr(
            libc_obj, (const uint8_t *)(uintptr_t)addr, 768,
            &g_musl_libc_addr))
    {
        ldr_dbg("[loader] musl profile mismatch: libc state base\n");
        return 0;
    }
#else
    (void)libc_obj;
    return 0;
#endif
    return 1;
}

/* ---- dlopen support globals ------------------------------------------ */

/* Global object table — populated by loader_run, extended by my_dlopen. */
static struct loaded_obj g_all_objs[MAX_TOTAL_OBJS];
static int g_nobj;
static int g_global_scope_root = -1;
static uint16_t g_global_scope_indices[MAX_TOTAL_OBJS];
static uint16_t g_global_scope_count;

/* Per-object metadata for dlopen'd objects (used by protect_object) */
static struct dlfrz_lib_meta g_dl_metas[MAX_TOTAL_OBJS];

static int dl_object_table_index(const struct loaded_obj *obj, int nobj,
                                 int *index_out)
{
    uintptr_t address = (uintptr_t)obj;
    uintptr_t start = (uintptr_t)&g_all_objs[0];
    uintptr_t end;
    uintptr_t delta;

    if (!obj || nobj < 0 || nobj > MAX_TOTAL_OBJS)
        return 0;
    end = (uintptr_t)&g_all_objs[nobj];
    if (address < start || address >= end)
        return 0;
    delta = address - start;
    if (delta % sizeof(g_all_objs[0]) != 0)
        return 0;
    *index_out = (int)(delta / sizeof(g_all_objs[0]));
    return 1;
}

static int dl_add_dependency_edge(struct loaded_obj *requester,
                                  struct loaded_obj *dependency, int nobj)
{
    int requester_index;
    int dependency_index;

    if (!dl_object_table_index(requester, nobj, &requester_index) ||
        !dl_object_table_index(dependency, nobj, &dependency_index))
        return -1;
    (void)requester_index;
    for (uint16_t i = 0; i < requester->needed_count; i++)
        if (requester->needed_indices[i] == (uint16_t)dependency_index)
            return 0;
    if (requester->needed_count >= MAX_TOTAL_OBJS)
        return -1;
    requester->needed_indices[requester->needed_count++] =
        (uint16_t)dependency_index;
    requester->lookup_scope_valid = 0;
    return 0;
}

static int dl_build_lookup_scope(struct loaded_obj *root, int nobj)
{
    uint8_t seen[MAX_TOTAL_OBJS];
    int root_index;
    uint16_t cursor = 0;

    if (!dl_object_table_index(root, nobj, &root_index))
        return -1;
    memset(seen, 0, sizeof(seen));
    root->lookup_scope_count = 1;
    root->lookup_scope_indices[0] = (uint16_t)root_index;
    seen[root_index] = 1;

    while (cursor < root->lookup_scope_count) {
        uint16_t current_index = root->lookup_scope_indices[cursor++];
        struct loaded_obj *current;

        if (current_index >= nobj)
            goto malformed;
        current = &g_all_objs[current_index];
        if (current->needed_count > MAX_TOTAL_OBJS)
            goto malformed;
        for (uint16_t i = 0; i < current->needed_count; i++) {
            uint16_t dependency_index = current->needed_indices[i];

            if (dependency_index >= nobj)
                goto malformed;
            if (seen[dependency_index])
                continue;
            if (root->lookup_scope_count >= MAX_TOTAL_OBJS)
                goto malformed;
            seen[dependency_index] = 1;
            root->lookup_scope_indices[root->lookup_scope_count++] =
                dependency_index;
        }
    }
    root->lookup_scope_valid = 1;
    return 0;

malformed:
    root->lookup_scope_count = 0;
    root->lookup_scope_valid = 0;
    return -1;
}

static int dl_set_relocation_scope_root(struct loaded_obj *obj,
                                        int root_index, int nobj)
{
    int index;

    if (!dl_object_table_index(obj, nobj, &index) || root_index < 0 ||
        root_index >= nobj)
        return -1;
    (void)index;
    obj->relocation_scope_root = (uint16_t)root_index;
    obj->relocation_scope_root_valid = 1;
    return 0;
}

static int dl_global_scope_contains(uint16_t index)
{
    for (uint16_t i = 0; i < g_global_scope_count; i++)
        if (g_global_scope_indices[i] == index)
            return 1;
    return 0;
}

static int dl_append_lookup_scope_to_global(struct loaded_obj *root,
                                            int nobj)
{
    if (!root->lookup_scope_valid && dl_build_lookup_scope(root, nobj) < 0)
        return -1;
    for (uint16_t i = 0; i < root->lookup_scope_count; i++) {
        uint16_t index = root->lookup_scope_indices[i];

        if (index >= nobj)
            return -1;
        if (dl_global_scope_contains(index))
            continue;
        if (g_global_scope_count >= MAX_TOTAL_OBJS)
            return -1;
        g_global_scope_indices[g_global_scope_count++] = index;
    }
    return 0;
}

static int dl_append_index_to_global(uint16_t index, int nobj)
{
    if (index >= nobj)
        return -1;
    if (dl_global_scope_contains(index))
        return 0;
    if (g_global_scope_count >= MAX_TOTAL_OBJS)
        return -1;
    g_global_scope_indices[g_global_scope_count++] = index;
    return 0;
}

static uint64_t resolve_main_address(struct loaded_obj *objs, int nobj,
                                     const int *idx_map,
                                     const struct dlfrz_lib_meta *metas,
                                     uintptr_t entry,
                                     int allow_aarch64_start_extract)
{
    uint64_t main_addr = 0;

#if !defined(__aarch64__)
    (void)entry;
    (void)allow_aarch64_start_extract;
#endif

    for (int i = 0; i < nobj; i++) {
        if (!(objs[i].flags & LDR_FLAG_MAIN_EXE))
            continue;
        int mi = idx_map[i];
        if (metas[mi].main_sym != 0) {
            main_addr = objs[i].base + metas[mi].main_sym;
            break;
        }
    }

    if (!main_addr) {
        for (int i = 0; i < nobj; i++) {
            if (!(objs[i].flags & LDR_FLAG_MAIN_EXE))
                continue;
            if (!objs[i].dynsym || !objs[i].dynstr)
                break;
            for (uint32_t s = 1; s < objs[i].dynsym_count; s++) {
                const Elf64_Sym *sym = &objs[i].dynsym[s];
                if (sym->st_shndx == SHN_UNDEF || sym->st_value == 0)
                    continue;
                if (strcmp(objs[i].dynstr + sym->st_name, "main") == 0) {
                    main_addr = objs[i].base + sym->st_value;
                    break;
                }
            }
            break;
        }
    }

#if defined(__aarch64__)
    if (!main_addr && allow_aarch64_start_extract) {
        for (int i = 0; i < nobj; i++) {
            if (!(objs[i].flags & LDR_FLAG_MAIN_EXE))
                continue;
            main_addr = aarch64_extract_main_from_entry(objs[i].map_start,
                                                        objs[i].map_end,
                                                        entry);
            if (main_addr && g_debug)
                ldr_hex("[loader] main from aarch64 _start=", main_addr);
            break;
        }
    }
#endif

    return main_addr;
}

#define RUNTIME_TLS_MAX_ALIGN (1ULL << 30)

static int runtime_tls_template_valid(const struct loaded_obj *obj)
{
    uint64_t align;

    if (!obj || obj->tls.memsz == 0)
        return 0;
    align = obj->tls.align ? obj->tls.align : 1;
    if (obj->tls.filesz > obj->tls.memsz || obj->tls.memsz > SIZE_MAX ||
        obj->tls.vaddr > UINT64_MAX - obj->tls.memsz ||
        align > RUNTIME_TLS_MAX_ALIGN || (align & (align - 1)) != 0 ||
        (obj->tls.filesz != 0 &&
         !loaded_obj_file_vaddr_pointer(obj, obj->tls.vaddr,
                                        (size_t)obj->tls.filesz, NULL)))
        return 0;
    return 1;
}

static int runtime_tls_mapping_size(const struct loaded_obj *obj,
                                    size_t *mapping_len_out)
{
    uint64_t align;
    uint64_t allocation_size;
    uint64_t map_len_u64;

    if (!runtime_tls_template_valid(obj))
        return 0;
    align = obj->tls.align ? obj->tls.align : 1;
    if (!u64_add_checked(obj->tls.memsz, align - 1, &allocation_size) ||
        !u64_align_up_checked(allocation_size, g_page_size, &map_len_u64) ||
        map_len_u64 == 0 || map_len_u64 > SIZE_MAX)
        return 0;
    *mapping_len_out = (size_t)map_len_u64;
    return 1;
}

static int allocate_runtime_tls_block(const struct loaded_obj *obj,
                                      void **mapping_out,
                                      size_t *mapping_len_out,
                                      uintptr_t *tls_base_out)
{
    uint64_t align;
    uint64_t tls_base_u64;
    uint64_t tls_end;
    uint64_t map_end;
    size_t map_len;
    void *mapping;

    *mapping_out = NULL;
    *mapping_len_out = 0;
    *tls_base_out = 0;
    if (!runtime_tls_mapping_size(obj, &map_len))
        return -1;

    align = obj->tls.align ? obj->tls.align : 1;
    mapping = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return -1;
    if (!u64_align_up_checked((uintptr_t)mapping, align, &tls_base_u64) ||
        !u64_add_checked(tls_base_u64, obj->tls.memsz, &tls_end) ||
        !u64_add_checked((uintptr_t)mapping, map_len, &map_end) ||
        tls_end > map_end) {
        munmap(mapping, map_len);
        return -1;
    }

    if (obj->tls.filesz != 0) {
        memcpy((void *)(uintptr_t)tls_base_u64,
               (const void *)(uintptr_t)(obj->base + obj->tls.vaddr),
               (size_t)obj->tls.filesz);
    }
    if (obj->tls.memsz > obj->tls.filesz) {
        memset((void *)(uintptr_t)(tls_base_u64 + obj->tls.filesz), 0,
               (size_t)(obj->tls.memsz - obj->tls.filesz));
    }

    *mapping_out = mapping;
    *mapping_len_out = map_len;
    *tls_base_out = (uintptr_t)tls_base_u64;
    return 0;
}

static int runtime_tls_address(const struct loaded_obj *obj,
                               uintptr_t tls_base, unsigned long offset,
                               void **address_out)
{
    uint64_t address;

    if (!runtime_tls_template_valid(obj) ||
        (uint64_t)offset > obj->tls.memsz ||
        !u64_add_checked(tls_base, (uint64_t)offset, &address) ||
        address > UINTPTR_MAX)
        return 0;
    *address_out = (void *)(uintptr_t)address;
    return 1;
}

static int static_tls_block_address(uintptr_t tp,
                                    const struct loaded_obj *obj,
                                    uint8_t **address_out)
{
    uint64_t magnitude;
    uintptr_t address;

    if (!runtime_tls_template_valid(obj) || obj->tls.tpoff == 0)
        return 0;
    if (obj->tls.tpoff < 0) {
        magnitude = (uint64_t)(-(obj->tls.tpoff + 1)) + 1;
        if (magnitude > tp || magnitude > g_tls_static_size ||
            obj->tls.memsz > magnitude)
            return 0;
        address = tp - (uintptr_t)magnitude;
    } else {
        uint64_t offset = (uint64_t)obj->tls.tpoff;

        if (offset > g_tls_static_size ||
            obj->tls.memsz > g_tls_static_size - offset ||
            offset > UINTPTR_MAX - tp)
            return 0;
        address = tp + (uintptr_t)offset;
    }
    *address_out = (uint8_t *)address;
    return 1;
}

static int discover_tls_template(struct loaded_obj *obj,
                                 const Elf64_Phdr *phdrs,
                                 int phnum)
{
    int found = 0;

    for (int i = 0; i < phnum; i++) {
        uint64_t align;

        if (phdrs[i].p_type != PT_TLS)
            continue;
        if (found)
            return -1;
        found = 1;
        align = phdrs[i].p_align ? phdrs[i].p_align : 1;
        if (phdrs[i].p_filesz > phdrs[i].p_memsz ||
            phdrs[i].p_memsz > SIZE_MAX ||
            phdrs[i].p_vaddr > UINT64_MAX - phdrs[i].p_memsz ||
            align > RUNTIME_TLS_MAX_ALIGN ||
            (align & (align - 1)) != 0 ||
            (phdrs[i].p_vaddr & (align - 1)) !=
                (phdrs[i].p_offset & (align - 1)) ||
            (phdrs[i].p_filesz != 0 &&
             !loaded_obj_file_vaddr_pointer(obj, phdrs[i].p_vaddr,
                                            (size_t)phdrs[i].p_filesz,
                                            NULL)))
            return -1;
        obj->tls.filesz = phdrs[i].p_filesz;
        obj->tls.memsz = phdrs[i].p_memsz;
        obj->tls.vaddr = phdrs[i].p_vaddr;
        obj->tls.align = align;
    }
    return 0;
}

static int next_tls_modid(size_t *modid_out)
{
    size_t max_modid = 0;

    for (int i = 0; i < g_nobj; i++) {
        if (g_all_objs[i].tls.modid > max_modid)
            max_modid = g_all_objs[i].tls.modid;
    }
    if (max_modid == SIZE_MAX || max_modid >= MAX_TOTAL_OBJS)
        return -1;
    *modid_out = max_modid + 1;
    return 0;
}

static int install_musl_dlopen_tls(struct loaded_obj *obj)
{
    uintptr_t tp;
    uintptr_t *old_dtv;
    uintptr_t *dtv;
    uintptr_t *new_dtv = NULL;
    size_t old_slots = 0;
    size_t new_slots;
    size_t dtv_bytes = 0;
    size_t tls_map_len = 0;
    void *tls_map = NULL;
    uintptr_t tls_base;
    uint64_t dtv_words;
    uint64_t dtv_bytes_u64;

    if (!g_is_musl_runtime || obj->tls.memsz == 0 || obj->tls.modid == 0)
        return 0;
    if (!runtime_tls_template_valid(obj) ||
        obj->tls.modid > MAX_TOTAL_OBJS)
        return -1;

    tp = arch_get_tp();
    old_dtv = *(uintptr_t **)musl_thread_dtv_slot(tp);
    if (old_dtv) {
        old_slots = old_dtv[0];
        if (old_slots > MAX_TOTAL_OBJS)
            return -1;
    }

    new_slots = obj->tls.modid;
    dtv = old_dtv;
    if (dtv && old_slots >= new_slots && dtv[obj->tls.modid])
        return 0;

    if (!dtv || old_slots < new_slots) {
        if (!u64_add_checked(new_slots, 1, &dtv_words) ||
            !u64_mul_checked(dtv_words, sizeof(uintptr_t), &dtv_words) ||
            !u64_align_up_checked(dtv_words, g_page_size, &dtv_bytes_u64) ||
            dtv_bytes_u64 == 0 || dtv_bytes_u64 > SIZE_MAX)
            return -1;
        dtv_bytes = (size_t)dtv_bytes_u64;
        new_dtv = mmap(NULL, dtv_bytes, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (new_dtv == MAP_FAILED)
            return -1;
        if (old_dtv)
            memcpy(new_dtv, old_dtv,
                   (old_slots + 1) * sizeof(uintptr_t));
        new_dtv[0] = new_slots;
        dtv = new_dtv;
    }

    if (allocate_runtime_tls_block(obj, &tls_map, &tls_map_len,
                                   &tls_base) < 0) {
        if (new_dtv)
            munmap(new_dtv, dtv_bytes);
        return -1;
    }
    dtv[obj->tls.modid] = tls_base;
    if (new_dtv)
        *(uintptr_t **)musl_thread_dtv_slot(tp) = new_dtv;

    if (g_debug) {
        ldr_msg("[loader] musl dlopen tls: ");
        ldr_msg(obj->name ? obj->name : "?");
        ldr_dbg_hex(" mod=0x", obj->tls.modid);
        ldr_dbg_hex(" block=0x", tls_base);
    }
    (void)tls_map;
    (void)tls_map_len;
    return 0;
}

/* Lazily install a per-thread DTV slot for a musl-runtime module that
 * was dlopen'd after the calling thread was created.  musl's pthread
 * allocates the static TLS area + DTV at thread creation time and does
 * not know about modules loaded later, so __tls_get_addr finds an empty
 * (or missing) slot.  We grow the DTV as needed and allocate a fresh
 * TLS block initialized from the module's .tdata image.  Forward-
 * declared near stub_tls_get_addr above. */
static void *musl_lazy_install_tls(uintptr_t tp, unsigned long modid,
                                   unsigned long ti_offset)
{
    struct loaded_obj *obj = NULL;
    uintptr_t *new_dtv = NULL;
    size_t new_dtv_bytes = 0;
    void *tls_map = NULL;
    size_t tls_map_len = 0;
    uintptr_t tls_base;
    void *address;

    for (int i = 0; i < g_nobj; i++) {
        if (g_all_objs[i].tls.modid == modid &&
            g_all_objs[i].tls.memsz != 0) {
            obj = &g_all_objs[i];
            break;
        }
    }
    if (!obj)
        tls_runtime_fatal("unknown musl TLS module");
    if (!runtime_tls_template_valid(obj) || modid > MAX_TOTAL_OBJS ||
        (uint64_t)ti_offset > obj->tls.memsz)
        tls_runtime_fatal("invalid musl TLS module or offset");

    uintptr_t *dtv = *(uintptr_t **)musl_thread_dtv_slot(tp);
    size_t cur_slots = dtv ? dtv[0] : 0;
    if (cur_slots > MAX_TOTAL_OBJS)
        tls_runtime_fatal("invalid musl DTV capacity");
    if (!dtv || cur_slots < modid) {
        size_t new_slots = modid;
        uint64_t words;
        uint64_t bytes_u64;

        if (!u64_add_checked(new_slots, 1, &words) ||
            !u64_mul_checked(words, sizeof(uintptr_t), &words) ||
            !u64_align_up_checked(words, g_page_size, &bytes_u64) ||
            bytes_u64 == 0 || bytes_u64 > SIZE_MAX)
            tls_runtime_fatal("musl DTV size overflow");
        new_dtv_bytes = (size_t)bytes_u64;
        new_dtv = mmap(NULL, new_dtv_bytes, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (new_dtv == MAP_FAILED)
            tls_runtime_fatal("cannot grow musl DTV");
        if (dtv)
            memcpy(new_dtv, dtv, (cur_slots + 1) * sizeof(uintptr_t));
        new_dtv[0] = new_slots;
        dtv = new_dtv;
    }

    if (!dtv[modid]) {
        if (allocate_runtime_tls_block(obj, &tls_map, &tls_map_len,
                                       &tls_base) < 0) {
            if (new_dtv)
                munmap(new_dtv, new_dtv_bytes);
            tls_runtime_fatal("cannot allocate musl TLS block");
        }
        dtv[modid] = tls_base;
        if (g_debug) {
            ldr_msg("[tls] musl lazy install ");
            ldr_msg(obj->name ? obj->name : "?");
            ldr_dbg_hex(" mod=", modid);
            ldr_dbg_hex(" blk=", tls_base);
        }
    }
    if (new_dtv)
        *(uintptr_t **)musl_thread_dtv_slot(tp) = new_dtv;

    if (!runtime_tls_address(obj, dtv[modid], ti_offset, &address))
        tls_runtime_fatal("musl TLS address overflow");
    (void)tls_map;
    (void)tls_map_len;
    return address;
}

/* install_glibc_dlopen_tls — allocate a TLS block for a dlopen'd module
 * and install it in the calling thread's DTV.  glibc convention:
 *   tcb->dtv = &raw_dtv[1]   (in dtv_t units, each 2×uintptr_t)
 *   dtv[modid*2]   = pointer to TLS block
 *   dtv[modid*2+1] = to_free marker
 * Only called for glibc runtime; musl uses install_musl_dlopen_tls. */
static int glibc_dtv_map_size(size_t capacity, size_t *map_size_out)
{
    uint64_t entries;
    uint64_t words;
    uint64_t bytes;

    if (capacity > MAX_TOTAL_OBJS ||
        !u64_add_checked(capacity, 1, &entries) ||
        !u64_mul_checked(entries, 2, &words) ||
        !u64_add_checked(words, 2, &words) ||
        !u64_mul_checked(words, sizeof(uintptr_t), &bytes) ||
        !u64_align_up_checked(bytes, g_page_size, &bytes) ||
        bytes == 0 || bytes > SIZE_MAX)
        return 0;
    *map_size_out = (size_t)bytes;
    return 1;
}

static int glibc_dtv_capacity(uintptr_t *dtv, size_t *capacity_out)
{
    size_t capacity;

    if (!dtv) {
        *capacity_out = 0;
        return 1;
    }
    capacity = dtv[-2];
    if (capacity > MAX_TOTAL_OBJS)
        return 0;
    *capacity_out = capacity;
    return 1;
}

static int glibc_static_tls_capacity(size_t *capacity_out)
{
    size_t capacity = 0;

    for (int i = 0; i < g_nobj; i++) {
        const struct loaded_obj *obj = &g_all_objs[i];

        if (obj->tls.memsz == 0 || obj->tls.tpoff == 0)
            continue;
        if (!runtime_tls_template_valid(obj) || obj->tls.modid == 0 ||
            obj->tls.modid > MAX_TOTAL_OBJS)
            return 0;
        if (obj->tls.modid > capacity)
            capacity = obj->tls.modid;
    }
    *capacity_out = capacity;
    return 1;
}

/* Reconstruct static slots from the thread pointer instead of reading them
 * beyond an old DTV's advertised capacity.  Some supported pthread paths can
 * hand us a conservative DTV header; that header remains the only safe bound
 * for copying the old allocation. */
static int glibc_seed_static_tls_slots(uintptr_t tp, uintptr_t *dtv,
                                       size_t capacity)
{
    if (!tp || !dtv)
        return 0;
    for (int i = 0; i < g_nobj; i++) {
        const struct loaded_obj *obj = &g_all_objs[i];
        uint8_t *static_block;

        if (obj->tls.memsz == 0 || obj->tls.tpoff == 0)
            continue;
        if (obj->tls.modid == 0 || obj->tls.modid > capacity ||
            !static_tls_block_address(tp, obj, &static_block))
            return 0;
        dtv[obj->tls.modid * 2] = (uintptr_t)static_block;
        dtv[obj->tls.modid * 2 + 1] = 0;
    }
    return 1;
}

static int glibc_tls_slot_allocated(uintptr_t value)
{
    /* glibc uses TLS_DTV_UNALLOCATED ((void *) -1l) as well as NULL for
     * an empty dynamic slot, depending on which update/teardown path ran. */
    return value != 0 && value != UINTPTR_MAX;
}

static int install_glibc_tls_for_thread(uintptr_t tp,
                                        struct loaded_obj *obj)
{
    uintptr_t *old_dtv;
    uintptr_t *dtv;
    uintptr_t *new_raw = NULL;
    size_t old_capacity = 0;
    size_t static_capacity = 0;
    size_t new_map_size = 0;
    void *tls_map = NULL;
    size_t tls_map_len = 0;
    uintptr_t tls_base;

    if (!tp || !runtime_tls_template_valid(obj) || obj->tls.modid == 0 ||
        obj->tls.modid > MAX_TOTAL_OBJS)
        return -1;

    old_dtv = *(uintptr_t **)(tp + TCB_OFF_DTV);
    if (!glibc_dtv_capacity(old_dtv, &old_capacity) ||
        !glibc_static_tls_capacity(&static_capacity))
        return -1;
    if (old_dtv && old_capacity >= obj->tls.modid &&
        glibc_tls_slot_allocated(old_dtv[obj->tls.modid * 2]))
        return 0;

    dtv = old_dtv;
    if (!old_dtv || old_capacity < obj->tls.modid) {
        size_t new_capacity = obj->tls.modid;

        if (static_capacity > new_capacity)
            new_capacity = static_capacity;

        if (!glibc_dtv_map_size(new_capacity, &new_map_size))
            return -1;
        new_raw = mmap(NULL, new_map_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (new_raw == MAP_FAILED)
            return -1;
        dtv = new_raw + 2;
        if (old_dtv) {
            size_t old_map_size;
            uint64_t old_words;
            uint64_t old_bytes;

            if (!glibc_dtv_map_size(old_capacity, &old_map_size) ||
                !u64_add_checked(old_capacity, 1, &old_words) ||
                !u64_mul_checked(old_words, 2, &old_words) ||
                !u64_add_checked(old_words, 2, &old_words) ||
                !u64_mul_checked(old_words, sizeof(uintptr_t), &old_bytes) ||
                old_bytes > old_map_size) {
                munmap(new_raw, new_map_size);
                return -1;
            }
            memcpy(new_raw, old_dtv - 2, (size_t)old_bytes);
        }
        new_raw[0] = new_capacity;
        new_raw[1] = 0;
        dtv[0] = 1;
        dtv[1] = 0;
        if (!glibc_seed_static_tls_slots(tp, dtv, new_capacity)) {
            munmap(new_raw, new_map_size);
            return -1;
        }
    }

    if (obj->tls.tpoff != 0) {
        uint8_t *static_block;

        if (!static_tls_block_address(tp, obj, &static_block)) {
            if (new_raw)
                munmap(new_raw, new_map_size);
            return -1;
        }
        tls_base = (uintptr_t)static_block;
    } else if (allocate_runtime_tls_block(obj, &tls_map, &tls_map_len,
                                          &tls_base) < 0) {
        if (new_raw)
            munmap(new_raw, new_map_size);
        return -1;
    }

    dtv[obj->tls.modid * 2] = tls_base;
    /* The target libc treats a non-NULL to_free marker as malloc storage.
     * Our block came from mmap, so publishing that mapping pointer here
     * would make thread teardown read allocator metadata before the map. */
    dtv[obj->tls.modid * 2 + 1] = 0;
    if (new_raw)
        *(uintptr_t **)(tp + TCB_OFF_DTV) = dtv;

    if (g_debug) {
        ldr_msg("[loader] glibc dlopen tls: ");
        ldr_msg(obj->name ? obj->name : "?");
        ldr_dbg_hex(" mod=0x", obj->tls.modid);
        ldr_dbg_hex(" block=0x", tls_base);
    }
    (void)tls_map_len;
    return 0;
}

static int install_glibc_dlopen_tls(struct loaded_obj *obj)
{
    if (g_is_musl_runtime || obj->tls.memsz == 0 || obj->tls.modid == 0)
        return 0;

    return install_glibc_tls_for_thread(arch_get_tp(), obj);
}

static void tls_runtime_fatal(const char *reason)
{
    ldr_msg("dlfreeze-loader: fatal TLS runtime failure: ");
    ldr_msg(reason);
    ldr_msg("\n");
    _exit(127);
}

static int dl_transaction_tls_address(uintptr_t tp, unsigned long modid,
                                      unsigned long ti_offset,
                                      void **address_out);

static void *runtime_tls_get_addr(uintptr_t tp, unsigned long modid,
                                  unsigned long ti_offset)
{
    struct loaded_obj *obj = NULL;
    void *address;
    int transaction_result = dl_transaction_tls_address(
        tp, modid, ti_offset, &address);

    if (transaction_result > 0)
        return address;
    if (transaction_result < 0)
        tls_runtime_fatal("cannot stage transaction TLS block");

    for (int i = 0; i < g_nobj; i++) {
        if (g_all_objs[i].tls.modid == modid &&
            g_all_objs[i].tls.memsz != 0) {
            obj = &g_all_objs[i];
            break;
        }
    }
    if (!obj || !runtime_tls_template_valid(obj) ||
        (uint64_t)ti_offset > obj->tls.memsz)
        tls_runtime_fatal("invalid TLS module or offset");

    if (g_is_musl_runtime)
        return musl_lazy_install_tls(tp, modid, ti_offset);

    {
        uintptr_t *dtv = *(uintptr_t **)(tp + TCB_OFF_DTV);
        uintptr_t tls_block = 0;
        size_t capacity = 0;

        if (!glibc_dtv_capacity(dtv, &capacity))
            tls_runtime_fatal("invalid glibc DTV capacity");
        if (dtv && modid <= capacity)
            tls_block = dtv[(size_t)modid * 2];
        if (!glibc_tls_slot_allocated(tls_block)) {
            if (install_glibc_tls_for_thread(tp, obj) < 0)
                tls_runtime_fatal("cannot install glibc TLS block");
            dtv = *(uintptr_t **)(tp + TCB_OFF_DTV);
            if (!glibc_dtv_capacity(dtv, &capacity))
                tls_runtime_fatal("invalid grown glibc DTV capacity");
            if (dtv && modid <= capacity)
                tls_block = dtv[(size_t)modid * 2];
        }
        if (!glibc_tls_slot_allocated(tls_block) ||
            !runtime_tls_address(obj, tls_block, ti_offset, &address))
            tls_runtime_fatal("missing glibc TLS DTV slot");
    }
    return address;
}

#if defined(__x86_64__)
static int64_t dlfreeze_x86_64_tlsdesc_resolve_c(void *arg_in) __attribute__((used));
static int64_t dlfreeze_x86_64_tlsdesc_resolve_c(void *arg_in)
{
    struct x86_64_tlsdesc_arg *arg = (struct x86_64_tlsdesc_arg *)arg_in;
    uintptr_t tp = arch_get_tp();
    uintptr_t tls_addr = (uintptr_t)runtime_tls_get_addr(
        tp, (unsigned long)arg->modid, (unsigned long)arg->offset);
    return (int64_t)(tls_addr - tp);
}
#endif

/* _dl_allocate_tls_init — copy .tdata for every TLS module into a
 * new thread's TLS block.  Called by glibc's pthread_create. */
static int g_tls_alloc_count;
static int g_tls_init_count;
static void *stub_dl_allocate_tls_init(void *mem)
{
    uintptr_t tp = (uintptr_t)mem;

    if (!mem)
        return NULL;
    g_tls_init_count++;
    ldr_dbg("[loader] _dl_allocate_tls_init #");
    ldr_dbg_hex("", (uint64_t)g_tls_init_count);
    ldr_dbg_hex("[loader]   tp=", tp);
    ldr_dbg_hex("[loader]   tid=", (uint64_t)syscall(SYS_gettid));
    /* Log caller thread's fs:0x10 for diagnostics */
    if (g_debug) {
        uintptr_t fs_self = arch_read_tp_offset(0x10);
        ldr_dbg_hex("[loader]   caller fs:0x10=", fs_self);
        ldr_dbg_hex("[loader]   tp+0x10 before=", *(uintptr_t *)(tp + 16));
    }
    for (int i = 0; i < g_nobj; i++) {
        struct loaded_obj *obj = &g_all_objs[i];
        uint8_t *dst;
        const uint8_t *src;

        if (obj->tls.memsz == 0)
            continue;
        if (!runtime_tls_template_valid(obj))
            return NULL;
        src = obj->tls.filesz != 0
            ? (const uint8_t *)(uintptr_t)(obj->base + obj->tls.vaddr)
            : NULL;
        /* dlopen'd modules (tpoff==0) live in separate per-thread TLS
         * blocks pointed to by the DTV.  When glibc recycles a cached
         * stack, _dl_allocate_tls_init is called without _dl_allocate_tls,
         * so the existing DTV block is reused and must be reset back to
         * the module's .tdata/.tbss image.  Otherwise __thread variables
         * defined in dlopened libraries would leak across threads. */
        if (obj->tls.tpoff == 0) {
            uintptr_t *dtv = *(uintptr_t **)(tp + TCB_OFF_DTV);
            size_t capacity = 0;
            uintptr_t blk;

            if (!glibc_dtv_capacity(dtv, &capacity))
                return NULL;
            if (!dtv || obj->tls.modid > capacity ||
                !glibc_tls_slot_allocated(dtv[obj->tls.modid * 2])) {
                if (install_glibc_tls_for_thread(tp, obj) < 0)
                    return NULL;
                dtv = *(uintptr_t **)(tp + TCB_OFF_DTV);
                if (!glibc_dtv_capacity(dtv, &capacity) || !dtv ||
                    obj->tls.modid > capacity)
                    return NULL;
            }
            blk = dtv[obj->tls.modid * 2];
            if (!glibc_tls_slot_allocated(blk))
                return NULL;
            dst = (uint8_t *)blk;
            if (obj->tls.filesz != 0)
                memcpy(dst, src, (size_t)obj->tls.filesz);
            size_t bss = (size_t)(obj->tls.memsz - obj->tls.filesz);
            if (bss > 0)
                memset(dst + obj->tls.filesz, 0, bss);
            ldr_dbg("[loader] tls_init dlopen: ");
            ldr_dbg(obj->name ? obj->name : "?");
            ldr_dbg_hex(" mod=", obj->tls.modid);
            ldr_dbg_hex(" blk=", blk);
            continue;
        }
        if (!static_tls_block_address(tp, obj, &dst))
            return NULL;
        ldr_dbg("[loader] tls_init: ");
        ldr_dbg(obj->name ? obj->name : "?");
        ldr_dbg_hex(" tpoff=", (uintptr_t)obj->tls.tpoff);
        if (obj->tls.filesz != 0)
            memcpy(dst, src, (size_t)obj->tls.filesz);
        /* Zero the .tbss portion */
        size_t bss = (size_t)(obj->tls.memsz - obj->tls.filesz);
        if (bss > 0)
            memset(dst + obj->tls.filesz, 0, bss);
    }

    /* Ensure TCB self-pointers survive the TLS re-init (cached stack
     * reuse path calls _dl_allocate_tls_init without _dl_allocate_tls,
     * and the stored self-pointer might have been cleared). */
    *(uintptr_t *)(tp + TCB_OFF_SELF)  = tp;
    *(uintptr_t *)(tp + TCB_OFF_SELF2) = tp;

#if defined(__aarch64__)
    glibc_aarch64_disable_rseq_for_thread(tp);
#endif

    return mem;
}

/* _dl_allocate_tls — allocate DTV and copy .tdata for a new thread. */
static uintptr_t g_last_tls_tp;
static void *stub_dl_allocate_tls(void *mem)
{
    uintptr_t *raw_dtv;
    uintptr_t *dtv;
    void *tls_maps[MAX_TOTAL_OBJS];
    size_t tls_map_lengths[MAX_TOTAL_OBJS];
    size_t tls_map_count = 0;
    size_t capacity = 0;
    size_t raw_dtv_map_size;

    g_tls_alloc_count++;
    ldr_dbg("[loader] _dl_allocate_tls #");
    ldr_dbg_hex("", (uint64_t)g_tls_alloc_count);
    ldr_dbg_hex("[loader]   tid=", (uint64_t)syscall(SYS_gettid));
    if (!mem)
        return NULL;
    uintptr_t tp = (uintptr_t)mem;

    for (int i = 0; i < g_nobj; i++) {
        if (g_all_objs[i].tls.memsz == 0)
            continue;
        if (!runtime_tls_template_valid(&g_all_objs[i]) ||
            g_all_objs[i].tls.modid == 0 ||
            g_all_objs[i].tls.modid > MAX_TOTAL_OBJS)
            return NULL;
        if (g_all_objs[i].tls.modid > capacity)
            capacity = g_all_objs[i].tls.modid;
    }
    if (!glibc_dtv_map_size(capacity, &raw_dtv_map_size))
        return NULL;
    raw_dtv = mmap(NULL, raw_dtv_map_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw_dtv == MAP_FAILED)
        return NULL;

    raw_dtv[0] = capacity;
    raw_dtv[1] = 0;
    dtv = raw_dtv + 2;
    dtv[0] = 1;
    dtv[1] = 0;
    for (int i = 0; i < g_nobj; i++) {
        struct loaded_obj *obj = &g_all_objs[i];
        size_t slot;

        if (obj->tls.memsz == 0)
            continue;
        slot = obj->tls.modid;
        if (obj->tls.tpoff != 0) {
            uint8_t *static_block;

            if (!static_tls_block_address(tp, obj, &static_block))
                goto fail_dtv;
            dtv[slot * 2] = (uintptr_t)static_block;
            dtv[slot * 2 + 1] = 0;
        } else {
            void *tls_map;
            size_t tls_map_len;
            uintptr_t tls_base;

            if (allocate_runtime_tls_block(obj, &tls_map, &tls_map_len,
                                           &tls_base) < 0)
                goto fail_dtv;
            dtv[slot * 2] = tls_base;
            dtv[slot * 2 + 1] = 0;
            tls_maps[tls_map_count] = tls_map;
            tls_map_lengths[tls_map_count] = tls_map_len;
            tls_map_count++;
        }
    }
    *(uintptr_t *)(tp + TCB_OFF_DTV) = (uintptr_t)dtv;

    /* Initialize TCB self-pointers so that %fs:0 and %fs:0x10 are valid
     * as soon as the new thread starts.  glibc's allocate_stack is
     * expected to set pd->header.self = pd after we return, but on some
     * builds the store is absent or overwritten, so we ensure it here. */
#if !defined(__aarch64__)
    *(uintptr_t *)(tp + TCB_OFF_SELF)  = tp;   /* tcbhead.tcb  (offset 0)  */
    *(uintptr_t *)(tp + TCB_OFF_SELF2) = tp;   /* tcbhead.self (offset 16) */
#endif

    /* New glibc threads inherit the process-wide canary/pointer guard. */
#if !defined(__aarch64__)
    if (g_saved_stack_guard)
        *(uintptr_t *)(tp + TCB_OFF_STACK_GUARD) = g_saved_stack_guard;
    if (g_saved_ptr_guard)
        *(uintptr_t *)(tp + TCB_OFF_PTR_GUARD) = g_saved_ptr_guard;
#endif

    /* Copy .tdata for all TLS modules */
    void *ret = stub_dl_allocate_tls_init(mem);

    if (!ret) {
        *(uintptr_t *)(tp + TCB_OFF_DTV) = 0;
        goto fail_dtv;
    }

    restore_ptr_guard();

    /* Verify our writes survived — debug diagnostics */
    g_last_tls_tp = tp;
    if (g_debug) {
        ldr_dbg_hex("[loader] alloc_tls done tp+0x00=", *(uintptr_t *)(tp + 0));
        ldr_dbg_hex("[loader] alloc_tls done dtv=", *(uintptr_t *)(tp + TCB_OFF_DTV));
        ldr_dbg_hex("[loader] alloc_tls done tp+0x10=", *(uintptr_t *)(tp + 16));
        ldr_dbg_hex("[loader] alloc_tls done tp+0x18=", *(uintptr_t *)(tp + 24));
    }
    return ret;

fail_dtv:
    for (size_t i = 0; i < tls_map_count; i++)
        munmap(tls_maps[i], tls_map_lengths[i]);
    munmap(raw_dtv, raw_dtv_map_size);
    return NULL;
}

/* ---- _dl_find_object implementation ---------------------------------- */

/* _dl_find_object — used by libgcc_s DWARF unwinder to find FDE info.
 * Searches g_all_objs[] for the object containing `pc` and returns
 * the .eh_frame_hdr pointer so the unwinder can locate FDE entries. */
static int glro_dl_find_object(void *pc, void *result)
{
    uintptr_t addr = (uintptr_t)pc;
    for (int i = 0; i < g_nobj; i++) {
        if (loaded_obj_contains(&g_all_objs[i], addr, 1)) {
            /* struct dl_find_object layout on x86-64 (glibc 2.35+):
             *   0: dlfo_flags           (unsigned long long)
             *   8: dlfo_map_start       (void *)
             *  16: dlfo_map_end         (void *)
             *  24: dlfo_link_map        (struct link_map *)
             *  32: dlfo_eh_frame        (void *) — .eh_frame_hdr
             *  40: dlfo_sframe          (void *)
             *  48: __dlfo_reserved[6]
             */
            uint8_t *r = (uint8_t *)result;
            memset(r, 0, 96);  /* zero the whole struct */
            *(unsigned long long *)(r + 0)  = 0;  /* flags */
            *(void **)(r + 8)  = (void *)g_all_objs[i].map_start;
            *(void **)(r + 16) = (void *)g_all_objs[i].map_end;
            *(void **)(r + 24) = NULL;  /* no link_map */
            *(void **)(r + 32) = (void *)g_all_objs[i].eh_frame_hdr;
            return 0;
        }
    }
    return -1;
}

/* argc/argv/envp saved for init functions of dlopen'd objects */
static int g_argc;
static char **g_argv;
static char **g_envp;

/* Frozen image context — saved by loader_run for lazy dlopen loading */
static const uint8_t *g_frozen_mem;
static uint64_t g_frozen_mem_foff;
static int g_frozen_srcfd;
static const struct dlfrz_lib_meta *g_frozen_metas;
static const struct dlfrz_entry *g_frozen_entries;
static const char *g_frozen_strtab;
static uint32_t g_frozen_num_entries;

/* dlerror support */
static char g_dlerror_msg[512];
static int g_dlerror_valid;

/* String pool for dlopen'd object names */
static char g_dl_strbuf[8192];
static size_t g_dl_strbuf_used;

/* A recursive dlopen is one transaction.  Constructors and dynamic TLS
 * publication are deferred until every DT_NEEDED edge and relocation has
 * succeeded, so a late missing dependency cannot run an earlier object's
 * constructor. */
struct dl_load_transaction {
    int active;
    int start_nobj;
    int high_water;
    int scope_root;
    int scope_root_valid;
    size_t start_strbuf_used;
    size_t start_init_order_count;
    uint16_t start_global_scope_count;
    struct loaded_obj *pending_init[MAX_TOTAL_OBJS];
    size_t pending_init_count;
    uintptr_t tls_bases[MAX_TOTAL_OBJS + 1];
    void *tls_maps[MAX_TOTAL_OBJS];
    size_t tls_map_lengths[MAX_TOTAL_OBJS];
    size_t tls_map_count;
#if defined(__aarch64__)
    struct aarch64_tlsdesc_page *start_tlsdesc_page;
    size_t start_tlsdesc_used;
#elif defined(__x86_64__)
    struct x86_64_tlsdesc_page *start_tlsdesc_page;
    size_t start_tlsdesc_used;
#endif
};

static struct dl_load_transaction g_dl_transaction;

/* ==== Embedded data-file VFS ========================================== */
/*
 * When -f patterns are used, non-ELF data files are packed into the frozen
 * binary with DLFRZ_FLAG_DATA.  At runtime we intercept openat() so that
 * any access to a path that matches an embedded file returns a memfd
 * containing the embedded data instead of going to the real filesystem.
 */

#define VFS_HASH_SIZE 4096U  /* must be power-of-two */

struct vfs_entry {
    const char     *path;      /* absolute path string (in strtab) */
    const uint8_t  *data;      /* pointer into mmap'd frozen binary */
    uint64_t        size;
    uint32_t        flags;
};

static struct vfs_entry g_vfs_table[VFS_HASH_SIZE];
static int g_vfs_count;
static uint32_t vfs_hash(const char *s);

static const struct vfs_entry *vfs_lookup_slow(const char *path)
{
    for (int i = 0; i < (int)VFS_HASH_SIZE; i++) {
        if (!g_vfs_table[i].path)
            continue;
        if (strcmp(g_vfs_table[i].path, path) == 0)
            return &g_vfs_table[i];
    }
    return NULL;
}

static const struct vfs_entry *vfs_lookup_manifest(const char *path)
{
    if (!g_frozen_entries || !g_frozen_strtab || !g_frozen_mem)
        return NULL;

    for (uint32_t i = 0; i < g_frozen_num_entries; i++) {
        const struct dlfrz_entry *ent = &g_frozen_entries[i];
        const char *name;
        uint32_t idx;

        if (!(ent->flags & DLFRZ_FLAG_DATA))
            continue;

        name = g_frozen_strtab + ent->name_offset;
        if (strcmp(name, path) != 0)
            continue;

        idx = vfs_hash(path) & (VFS_HASH_SIZE - 1);
        while (g_vfs_table[idx].path && strcmp(g_vfs_table[idx].path, path) != 0)
            idx = (idx + 1) & (VFS_HASH_SIZE - 1);

        if (!g_vfs_table[idx].path) {
            g_vfs_table[idx].path = name;
            g_vfs_table[idx].data = g_frozen_mem + (ent->data_offset - g_frozen_mem_foff);
            g_vfs_table[idx].size = ent->data_size;
            g_vfs_table[idx].flags = ent->flags;
            if (g_debug) {
                ldr_msg("vfs lookup repaired from manifest: ");
                ldr_msg(path);
                ldr_msg("\n");
            }
        }
        return &g_vfs_table[idx];
    }
    return NULL;
}

static int vfs_is_virtual_entry(const struct vfs_entry *ve)
{
    return ve && (ve->flags & DLFRZ_FLAG_DATA_VIRTUAL) != 0;
}

static int vfs_is_negative_entry(const struct vfs_entry *ve)
{
    return ve && (ve->flags & DLFRZ_FLAG_DATA_NEGATIVE) != 0;
}

static int vfs_is_dir_marker_path(const char *path)
{
    size_t len = strlen(path);

    return len >= 5 && strcmp(path + len - 5, "/.dir") == 0;
}

typedef int *(*errno_location_fn)(void);
static errno_location_fn g_real_errno_location;

static inline void sync_glibc_errno_value(int err)
{
    if (err > 0 && g_real_errno_location)
        *g_real_errno_location() = err;
}

static inline void set_loader_errno(int err)
{
    errno = err;
    /* musl errno write touches FS:0x34; once FS points at glibc TLS this can
     * overlap pointer_guard bytes. Restore guard before returning to user code. */
    restore_ptr_guard();
    sync_glibc_errno_value(err);
}

/*
 * VFS_SYSCALL — wrapper for syscall() in VFS functions.
 * musl's __syscall_ret writes errno at FS:0x34 on failure, corrupting
 * glibc's pointer_guard at FS:0x30.  This macro restores it after
 * every syscall so that atexit handlers can still PTR_DEMANGLE.
 */
#define VFS_SYSCALL(...) ({                           \
    long _r = syscall(__VA_ARGS__);                  \
    int _e = errno;                                  \
    restore_ptr_guard();                             \
    if (_r < 0)                                      \
        sync_glibc_errno_value(_e);                  \
    _r;                                              \
})

/* Saved real libc fopen/fdopen for vfs_fopen fallthrough */
typedef void *(*fopen_fn)(const char *, const char *);
typedef void *(*fdopen_fn)(int, const char *);
typedef void *(*opendir_fn)(const char *);
typedef void *(*fdopendir_fn)(int);
typedef void *(*readdir_fn)(void *);
typedef void *(*malloc_fn)(size_t);
typedef char *(*realpath_fn)(const char *, char *);
typedef int (*closedir_fn)(void *);
typedef int (*dirfd_fn)(void *);
typedef void (*rewinddir_fn)(void *);
typedef long (*telldir_fn)(void *);
typedef void (*seekdir_fn)(void *, long);
static fopen_fn  g_real_fopen;
static fdopen_fn g_real_fdopen;
static opendir_fn g_real_opendir;
static fdopendir_fn g_real_fdopendir;
static readdir_fn g_real_readdir;
static malloc_fn g_real_malloc;
static realpath_fn g_real_realpath;
static closedir_fn g_real_closedir;
static dirfd_fn g_real_dirfd;
static rewinddir_fn g_real_rewinddir;
static telldir_fn g_real_telldir;
static seekdir_fn g_real_seekdir;

static uint32_t vfs_hash(const char *s)
{
    uint32_t h = 5381;
    for (; *s; s++)
        h = h * 33 + (uint8_t)*s;
    return h;
}

static void vfs_init_dirs(void);
static int vfs_dir_exists(const char *path);
static const struct vfs_entry *vfs_lookup(const char *path);
static int frozen_dlopen_find(const char *path);

/* ---- VFS sealing ----------------------------------------------------- */
/*
 * The seal scope is derived from the captured file set: any directory
 * that contains at least one captured file is treated as a sealed
 * mount.  Lookups for non-captured paths inside such a directory
 * return ENOENT instead of falling through to the host filesystem,
 * so the frozen image behaves like an immutable bind mount of the
 * directories the program actually used at freeze time.
 *
 * Files outside any captured directory pass through to the host
 * unchanged.
 */

/* True when `path`'s parent directory is in the VFS dir table but the
 * path itself has no VFS entry / dir mapping / frozen-DLOPEN ELF. */
static int vfs_path_is_sealed_miss(const char *path)
{
    if (!path || path[0] != '/' || g_vfs_count == 0)
        return 0;
    if (vfs_lookup(path)) return 0;
    if (vfs_dir_exists(path)) return 0;
    if (frozen_dlopen_find(path) >= 0) return 0;
    /* Compute parent directory length (offset of last '/'). */
    const char *slash = NULL;
    for (const char *p = path; *p; p++)
        if (*p == '/') slash = p;
    if (!slash) return 0;
    /* Stack-allocate a small buffer for the parent path; bail if too
     * long.  Most kernel paths fit easily in PATH_MAX. */
    size_t plen = (size_t)(slash - path);
    if (plen == 0) return 0;            /* "/foo" — root not sealed */
    if (plen >= 4096) return 0;
    char parent[4096];
    memcpy(parent, path, plen);
    parent[plen] = '\0';
    return vfs_dir_exists(parent);
}

static void vfs_seal_log(const char *op, const char *path)
{
    if (!g_debug) return;
    ldr_msg("vfs sealed ");
    ldr_msg(op);
    ldr_msg(": ");
    ldr_msg(path);
    ldr_msg(" (parent dir captured, file not in image) -> ENOENT\n");
}

static void vfs_init(const uint8_t *mem, uint64_t mem_foff,
                     const struct dlfrz_entry *entries,
                     const char *strtab, uint32_t num_entries)
{
    g_vfs_count = 0;
    for (uint32_t i = 0; i < num_entries; i++) {
        if (!(entries[i].flags & DLFRZ_FLAG_DATA)) continue;
        const char *path = strtab + entries[i].name_offset;
        uint32_t idx = vfs_hash(path) & (VFS_HASH_SIZE - 1);
        while (g_vfs_table[idx].path)
            idx = (idx + 1) & (VFS_HASH_SIZE - 1);
        g_vfs_table[idx].path = path;
        g_vfs_table[idx].data = mem + (entries[i].data_offset - mem_foff);
        g_vfs_table[idx].size = entries[i].data_size;
        g_vfs_table[idx].flags = entries[i].flags;
        g_vfs_count++;
    }
    if (g_debug && g_vfs_count > 0) {
        ldr_dbg_hex("[loader] vfs: 0x", g_vfs_count);
        ldr_msg(" data files registered\n");
    }
    if (g_vfs_count > 0) {
        vfs_init_dirs();
    }
}

static const struct vfs_entry *vfs_lookup(const char *path)
{
    if (g_vfs_count == 0) return NULL;
    uint32_t idx = vfs_hash(path) & (VFS_HASH_SIZE - 1);
    for (int probes = 0; probes < (int)VFS_HASH_SIZE; probes++) {
        if (!g_vfs_table[idx].path) {
            const struct vfs_entry *slow = vfs_lookup_slow(path);
            return slow ? slow : vfs_lookup_manifest(path);
        }
        if (strcmp(g_vfs_table[idx].path, path) == 0)
            return &g_vfs_table[idx];
        idx = (idx + 1) & (VFS_HASH_SIZE - 1);
    }
    {
        const struct vfs_entry *slow = vfs_lookup_slow(path);
        return slow ? slow : vfs_lookup_manifest(path);
    }
}

static void vfs_dbg_op(const char *op, const char *path, const char *detail)
{
    if (!g_debug || !path || path[0] != '/')
        return;
    if (!vfs_lookup(path) && !vfs_dir_exists(path))
        return;

    ldr_msg("vfs ");
    ldr_msg(op);
    ldr_msg(": ");
    ldr_msg(path);
    if (detail) {
        ldr_msg(" ");
        ldr_msg(detail);
    }
    ldr_msg("\n");
}

/* The VFS overrides are only populated in the special-table when
 * g_vfs_count > 0, so they are a no-op for non-VFS binaries. */

/* ---- VFS directory table --------------------------------------------- */
/*
 * Derived from embedded file paths at init time.  For each file like
 * /usr/lib/app/data/config.json we record all parent directories:
 *   /usr/lib/app/data
 *   /usr/lib/app
 *   /usr/lib
 *   /usr
 * This lets stat() report them as directories and opendir() list them.
 */

#define VFS_DIR_HASH_SIZE 2048U  /* power-of-two */

static const char *g_vfs_dir_table[VFS_DIR_HASH_SIZE];
static int g_vfs_dir_count;
static char g_vfs_dir_strbuf[65536];
static int g_vfs_dir_strpos;
static char g_vfs_overlay_root[PATH_MAX];
static char g_vfs_library_path[16384];
static char **g_vfs_child_envp;
static int g_vfs_overlay_attempted;
static int g_vfs_overlay_ready;

static uint32_t vfs_hash_n(const char *s, int n)
{
    uint32_t h = 5381;
    for (int i = 0; i < n; i++)
        h = h * 33 + (uint8_t)s[i];
    return h;
}

static int vfs_dir_exists_n_slow(const char *path, int len)
{
    for (int i = 0; i < (int)VFS_DIR_HASH_SIZE; i++) {
        if (!g_vfs_dir_table[i])
            continue;
        if (strncmp(g_vfs_dir_table[i], path, len) == 0 &&
            g_vfs_dir_table[i][len] == '\0')
            return 1;
    }
    return 0;
}

/* Check if a directory path of exactly `len` bytes is already in the table */
static int vfs_dir_exists_n(const char *path, int len)
{
    uint32_t idx = vfs_hash_n(path, len) & (VFS_DIR_HASH_SIZE - 1);
    for (int p = 0; p < (int)VFS_DIR_HASH_SIZE; p++) {
        if (!g_vfs_dir_table[idx])
            return vfs_dir_exists_n_slow(path, len);
        if (strncmp(g_vfs_dir_table[idx], path, len) == 0 &&
            g_vfs_dir_table[idx][len] == '\0')
            return 1;
        idx = (idx + 1) & (VFS_DIR_HASH_SIZE - 1);
    }
    return vfs_dir_exists_n_slow(path, len);
}

static int vfs_dir_exists(const char *path)
{
    if (g_vfs_dir_count == 0) return 0;
    return vfs_dir_exists_n(path, strlen(path));
}

/* Check if VFS has at least one direct child file in this directory.
 * Used to distinguish dirs with captured contents from mere ancestor
 * dirs derived from file paths. */

/* Check if a VFS directory has at least one direct child file
 * (not counting .dir markers, which are just structural hints). */
static void vfs_dir_insert(const char *path, int len)
{
    if (g_vfs_dir_strpos + len + 1 > (int)sizeof(g_vfs_dir_strbuf)) return;
    char *stored = g_vfs_dir_strbuf + g_vfs_dir_strpos;
    memcpy(stored, path, len);
    stored[len] = '\0';
    g_vfs_dir_strpos += len + 1;

    uint32_t idx = vfs_hash_n(path, len) & (VFS_DIR_HASH_SIZE - 1);
    while (g_vfs_dir_table[idx])
        idx = (idx + 1) & (VFS_DIR_HASH_SIZE - 1);
    g_vfs_dir_table[idx] = stored;
    g_vfs_dir_count++;
}

/* Build the directory table from all VFS file paths */
static void vfs_init_dirs(void)
{
    g_vfs_dir_count = 0;
    g_vfs_dir_strpos = 0;
    for (int i = 0; i < (int)VFS_HASH_SIZE; i++) {
        if (!g_vfs_table[i].path) continue;
        /* Negative entries represent files that do not exist; their parent
         * directories should not be derived as VFS-visible directories. */
        if (g_vfs_table[i].flags & DLFRZ_FLAG_DATA_NEGATIVE) continue;
        const char *path = g_vfs_table[i].path;
        int len = strlen(path);
        /* Walk backwards, extracting each parent directory */
        for (int j = len - 1; j > 0; j--) {
            if (path[j] != '/') continue;
            /* path[0..j-1] is a parent directory */
            if (vfs_dir_exists_n(path, j))
                break;  /* this dir (and all its parents) already known */
            vfs_dir_insert(path, j);
        }
    }
    /* Also derive parent directories from frozen DLOPEN entries so that
    * directories whose only contents are dlopen-served .so files
    * report as existing.  Otherwise vfs_path_is_sealed_miss can make
    * extension/plugin directories look missing before the loader gets a
    * chance to serve their captured shared objects. */
    if (g_frozen_metas && g_frozen_entries && g_frozen_strtab) {
        for (uint32_t i = 0; i < g_frozen_num_entries; i++) {
            if (!(g_frozen_metas[i].flags & LDR_FLAG_DLOPEN)) continue;
            if (g_frozen_metas[i].flags & LDR_FLAG_INTERP) continue;
            const char *path = g_frozen_strtab +
                g_frozen_entries[i].name_offset;
            if (!path || path[0] != '/') continue;
            int len = strlen(path);
            for (int j = len - 1; j > 0; j--) {
                if (path[j] != '/') continue;
                if (vfs_dir_exists_n(path, j))
                    break;
                vfs_dir_insert(path, j);
            }
        }
    }
    if (g_debug && g_vfs_dir_count > 0) {
        ldr_dbg_hex("[loader] vfs: 0x", g_vfs_dir_count);
        ldr_msg(" directories derived\n");
    }
}

static int vfs_path_has_suffix(const char *path, const char *suffix)
{
    size_t plen = strlen(path);
    size_t slen = strlen(suffix);

    return plen >= slen && strcmp(path + plen - slen, suffix) == 0;
}

static int vfs_affects_library_path(const char *path)
{
    const char *base = path_basename(path);

    if (strcmp(base, ".dir") == 0)
        return 0;
    /* Materialize linker input files consumed by child processes, which
     * cannot see this process's in-memory VFS.  Runtime shared objects are
     * served by the loader and do not need a second on-disk copy. */
    return vfs_path_has_suffix(base, ".a") ||
           vfs_path_has_suffix(base, ".o");
}

static int vfs_append_decimal(char *buf, size_t buf_size,
                              size_t *pos, unsigned long val)
{
    char tmp[32];
    size_t n = 0;

    if (val == 0) {
        if (*pos + 2 > buf_size)
            return -1;
        buf[(*pos)++] = '0';
        buf[*pos] = '\0';
        return 0;
    }

    while (val && n < sizeof(tmp)) {
        tmp[n++] = (char)('0' + (val % 10));
        val /= 10;
    }
    if (*pos + n + 1 > buf_size)
        return -1;
    while (n > 0)
        buf[(*pos)++] = tmp[--n];
    buf[*pos] = '\0';
    return 0;
}

static int vfs_init_overlay_root(void)
{
    const char prefix[] = "/tmp/dlfreeze-vfs-";
    size_t pos = 0;

    if (g_vfs_overlay_root[0])
        return 0;

    if (sizeof(prefix) > sizeof(g_vfs_overlay_root))
        return -1;
    memcpy(g_vfs_overlay_root, prefix, sizeof(prefix) - 1);
    pos = sizeof(prefix) - 1;
    if (vfs_append_decimal(g_vfs_overlay_root, sizeof(g_vfs_overlay_root),
                           &pos, (unsigned long)syscall(SYS_getpid)) < 0)
        return -1;
    if (VFS_SYSCALL(SYS_mkdirat, AT_FDCWD, g_vfs_overlay_root, 0700) < 0 &&
        errno != EEXIST)
        return -1;
    return 0;
}

static int vfs_make_overlay_path(const char *path, char *out, size_t out_size)
{
    size_t root_len = strlen(g_vfs_overlay_root);
    size_t path_len = strlen(path);

    if (root_len + path_len + 1 > out_size)
        return -1;
    memcpy(out, g_vfs_overlay_root, root_len);
    memcpy(out + root_len, path, path_len + 1);
    return 0;
}

static int vfs_mkdir_parents(char *path)
{
    size_t root_len = strlen(g_vfs_overlay_root);

    for (char *p = path + root_len + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (VFS_SYSCALL(SYS_mkdirat, AT_FDCWD, path, 0700) < 0 && errno != EEXIST) {
            *p = '/';
            return -1;
        }
        *p = '/';
    }
    return 0;
}

static int vfs_library_path_contains(const char *dir)
{
    size_t dlen = strlen(dir);
    const char *p = g_vfs_library_path;

    while (*p) {
        const char *end = strchr(p, ':');
        size_t len = end ? (size_t)(end - p) : strlen(p);

        if (len == dlen && strncmp(p, dir, dlen) == 0)
            return 1;
        if (!end)
            break;
        p = end + 1;
    }
    return 0;
}

static void vfs_library_path_add(const char *dir)
{
    size_t cur;
    size_t len;

    if (!dir || !dir[0] || vfs_library_path_contains(dir))
        return;

    cur = strlen(g_vfs_library_path);
    len = strlen(dir);
    if (cur + (cur ? 1 : 0) + len + 1 > sizeof(g_vfs_library_path))
        return;
    if (cur)
        g_vfs_library_path[cur++] = ':';
    memcpy(g_vfs_library_path + cur, dir, len + 1);
}

static int vfs_prepare_library_overlay(void)
{
    if (g_vfs_overlay_attempted)
        return g_vfs_overlay_ready ? 0 : -1;

    g_vfs_overlay_attempted = 1;
    g_vfs_library_path[0] = '\0';

    if (g_vfs_count == 0)
        return -1;

    /* First pass: avoid creating an overlay for workloads that do not have
     * files consumed by external child processes. */
    {
        int have_any = 0;

        for (int i = 0; i < (int)VFS_HASH_SIZE; i++) {
            if (!g_vfs_table[i].path || g_vfs_table[i].size == 0)
                continue;
            if (vfs_affects_library_path(g_vfs_table[i].path)) {
                have_any = 1;
                break;
            }
        }
        if (!have_any)
            return -1;
    }

    if (vfs_init_overlay_root() < 0)
        return -1;

    for (int i = 0; i < (int)VFS_HASH_SIZE; i++) {
        char overlay_path[PATH_MAX];
        char *slash;
        int fd;
        uint64_t rem;
        const uint8_t *p;

        if (!g_vfs_table[i].path || g_vfs_table[i].size == 0)
            continue;
        if (!vfs_affects_library_path(g_vfs_table[i].path))
            continue;
        if (vfs_make_overlay_path(g_vfs_table[i].path, overlay_path,
                                  sizeof(overlay_path)) < 0)
            continue;
        if (vfs_mkdir_parents(overlay_path) < 0)
            continue;

        fd = (int)VFS_SYSCALL(SYS_openat, AT_FDCWD, overlay_path,
                              O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                              0644);
        if (fd < 0)
            continue;

        p = g_vfs_table[i].data;
        rem = g_vfs_table[i].size;
        while (rem > 0) {
            long w = VFS_SYSCALL(SYS_write, fd, p, rem);

            if (w <= 0) {
                VFS_SYSCALL(SYS_close, fd);
                fd = -1;
                break;
            }
            p += w;
            rem -= (uint64_t)w;
        }
        if (fd < 0)
            continue;
        VFS_SYSCALL(SYS_close, fd);

        slash = strrchr(overlay_path, '/');
        if (!slash)
            continue;
        *slash = '\0';
        vfs_library_path_add(overlay_path);
    }

    if (!g_vfs_library_path[0])
        return -1;

    g_vfs_overlay_ready = 1;
    if (g_debug) {
        ldr_msg("[loader] vfs library path: ");
        ldr_msg(g_vfs_library_path);
        ldr_msg("\n");
    }
    return 0;
}

static const char *vfs_find_env_value(char **envp, const char *name)
{
    size_t nlen = strlen(name);

    if (!envp)
        return NULL;
    for (size_t i = 0; envp[i]; i++) {
        if (strncmp(envp[i], name, nlen) == 0 && envp[i][nlen] == '=')
            return envp[i] + nlen + 1;
    }
    return NULL;
}

static char **vfs_prepare_child_env(char **envp)
{
    static char *g_vfs_child_envstr;
    size_t envc = 0;
    size_t keepc = 0;
    size_t str_bytes;
    size_t array_bytes;
    char **new_envp;
    char *envstr;
    char *dst;
    const char *existing;

    if (g_vfs_child_envp)
        return g_vfs_child_envp;
    if (vfs_prepare_library_overlay() < 0)
        return envp;

    existing = vfs_find_env_value(envp, "LIBRARY_PATH");
    while (envp && envp[envc]) {
        if (strncmp(envp[envc], "LIBRARY_PATH=", 13) != 0)
            keepc++;
        envc++;
    }

    str_bytes = strlen("LIBRARY_PATH=") + strlen(g_vfs_library_path) + 1;
    if (existing && existing[0] != '\0')
        str_bytes += strlen(existing) + 1;
    array_bytes = (keepc + 2) * sizeof(char *);

    envstr = mmap(NULL, ALIGN_UP(str_bytes, g_page_size), PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    new_envp = mmap(NULL, ALIGN_UP(array_bytes, g_page_size),
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (envstr == MAP_FAILED || new_envp == MAP_FAILED)
        return envp;

    g_vfs_child_envstr = envstr;
    dst = g_vfs_child_envstr;
    memcpy(dst, "LIBRARY_PATH=", 13);
    dst += 13;
    memcpy(dst, g_vfs_library_path, strlen(g_vfs_library_path));
    dst += strlen(g_vfs_library_path);
    if (existing && existing[0] != '\0') {
        *dst++ = ':';
        memcpy(dst, existing, strlen(existing));
        dst += strlen(existing);
    }
    *dst = '\0';

    keepc = 0;
    for (size_t i = 0; i < envc; i++) {
        if (strncmp(envp[i], "LIBRARY_PATH=", 13) == 0)
            continue;
        new_envp[keepc++] = envp[i];
    }
    new_envp[keepc++] = g_vfs_child_envstr;
    new_envp[keepc] = NULL;
    g_vfs_child_envp = new_envp;
    return g_vfs_child_envp;
}

/* ---- VFS opendir/readdir/closedir ------------------------------------ */
/*
 * We replace libc's opendir/readdir/closedir so directory enumeration sees
 * embedded files even when the real directories don't exist.
 *
 * For our fake DIR handles we use a magic sentinel at the start.
 * glibc's real DIR struct starts with an int fd (small positive number),
 * so our 8-byte magic is safe to distinguish.
 *
 * For real (non-VFS) directories, we implement opendir/readdir on top of
 * raw syscalls (SYS_openat + SYS_getdents64) since we can't call through
 * to glibc's implementations after patching the GOT.
 */

#define VFS_FAKE_DIR_MAGIC 0x564653444952ULL
#define VFS_MAX_DIR_HANDLES 32
#define VFS_DIRFD_MAP_MAX 64

struct vfs_dir_handle {
    int            fd_compat;   /* offset-0: for dirfd() ABI compat  */
    int            _pad;
    uint64_t       magic;       /* VFS_FAKE_DIR_MAGIC                */
    const char    *vfs_path;    /* NUL-terminated dir path (VFS)     */
    int            vfs_path_len;
    int            scan_pos;    /* iteration position                */
    int            phase;       /* 0=files, 1=subdirs, 2=done        */
    /* getdents64 buffer for real (non-VFS) dirs: */
    char           gd_buf[4096];
    int            gd_pos;
    int            gd_len;
    /* Return value for readdir: */
    struct dirent  result;
};

static struct vfs_dir_handle g_dir_handles[VFS_MAX_DIR_HANDLES];

struct vfs_dirfd_map {
    int  fd;
    char path[PATH_MAX];
};

static struct vfs_dirfd_map g_vfs_dirfd_maps[VFS_DIRFD_MAP_MAX];

static void remember_vfs_dirfd(int fd, const char *path)
{
    int slot = -1;

    if (fd < 0 || !path || path[0] != '/')
        return;

    for (int i = 0; i < VFS_DIRFD_MAP_MAX; i++) {
        if (g_vfs_dirfd_maps[i].path[0] == '\0') {
            if (slot < 0)
                slot = i;
            continue;
        }
        if (g_vfs_dirfd_maps[i].fd == fd) {
            slot = i;
            break;
        }
    }
    if (slot < 0)
        slot = fd % VFS_DIRFD_MAP_MAX;

    g_vfs_dirfd_maps[slot].fd = fd;
    snprintf(g_vfs_dirfd_maps[slot].path, sizeof(g_vfs_dirfd_maps[slot].path),
             "%s", path);
}

static const char *lookup_vfs_dirfd(int fd)
{
    for (int i = 0; i < VFS_DIRFD_MAP_MAX; i++) {
        if (g_vfs_dirfd_maps[i].path[0] != '\0' &&
            g_vfs_dirfd_maps[i].fd == fd)
            return g_vfs_dirfd_maps[i].path;
    }
    return NULL;
}

static void forget_vfs_dirfd(int fd)
{
    if (fd < 0)
        return;

    for (int i = 0; i < VFS_DIRFD_MAP_MAX; i++) {
        if (g_vfs_dirfd_maps[i].path[0] == '\0')
            continue;
        if (g_vfs_dirfd_maps[i].fd != fd)
            continue;
        g_vfs_dirfd_maps[i].fd = -1;
        g_vfs_dirfd_maps[i].path[0] = '\0';
    }
}

static int resolve_vfs_path_at(int dirfd, const char *path,
                               char *resolved, size_t resolved_sz)
{
    char proc_path[64];
    char base[PATH_MAX];
    ssize_t len;

    if (!path || !resolved || resolved_sz == 0)
        return 0;
    if (path[0] == '/') {
        snprintf(resolved, resolved_sz, "%s", path);
        return 1;
    }
    if (dirfd == AT_FDCWD)
        return 0;

    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", dirfd);
    len = (ssize_t)VFS_SYSCALL(SYS_readlinkat, AT_FDCWD, proc_path,
                               base, sizeof(base) - 1);
    if (len < 0)
        return 0;
    base[len] = '\0';

    if (base[0] == '/' && base[1] == '\0') {
        const char *mapped = lookup_vfs_dirfd(dirfd);
        if (mapped)
            return snprintf(resolved, resolved_sz, "%s/%s", mapped, path) <
                   (int)resolved_sz;
    }

    return snprintf(resolved, resolved_sz, "%s/%s", base, path) <
           (int)resolved_sz;
}

static void *vfs_opendir(const char *path)
{
    int has_vfs = (path && path[0] == '/' && vfs_dir_exists(path));
    int fd = -1;

    if (!has_vfs && g_real_opendir)
        return g_real_opendir(path);

    vfs_dbg_op("opendir", path, "enter");

    /* Serve captured dirs purely from VFS; do not touch the real FS.
     * Leave fd_compat = -1 so readdir treats this as virtual-only and
     * does not skip entries that happen to exist on disk.  vfs_dirfd()
     * lazily opens a placeholder fd on demand. */

    /* Find a free handle */
    for (int i = 0; i < VFS_MAX_DIR_HANDLES; i++) {
        if (g_dir_handles[i].magic == VFS_FAKE_DIR_MAGIC) continue;
        struct vfs_dir_handle *h = &g_dir_handles[i];
        memset(h, 0, sizeof(*h));
        h->magic = VFS_FAKE_DIR_MAGIC;
        h->fd_compat = fd;
        if (has_vfs) {
            h->vfs_path = path;
            h->vfs_path_len = strlen(path);
            h->scan_pos = 0;
            h->phase = 0;  /* virtual-only */
            vfs_dbg_op("opendir", path, "virtual");
        } else {
            /* Pure real dir, no VFS */
            h->vfs_path = NULL;
        }
        h->gd_pos = 0;
        h->gd_len = 0;
        return (void *)h;
    }
    /* No free handles */
    if (fd >= 0) VFS_SYSCALL(SYS_close, fd);
    return NULL;
}

static void *vfs_fdopendir(int fd)
{
    const char *mapped = lookup_vfs_dirfd(fd);

    if (fd < 0) {
        set_loader_errno(EBADF);
        return NULL;
    }
    if (!mapped && g_real_fdopendir)
        return g_real_fdopendir(fd);

    for (int i = 0; i < VFS_MAX_DIR_HANDLES; i++) {
        struct vfs_dir_handle *h;

        if (g_dir_handles[i].magic == VFS_FAKE_DIR_MAGIC)
            continue;
        h = &g_dir_handles[i];
        memset(h, 0, sizeof(*h));
        h->magic = VFS_FAKE_DIR_MAGIC;
        h->fd_compat = fd;
        h->vfs_path = mapped;
        h->gd_pos = 0;
        h->gd_len = 0;
        if (mapped) {
            h->vfs_path_len = strlen(mapped);
            h->scan_pos = 0;
            /* Virtual-only: the fd is a synthetic placeholder (opened
             * against "/"), so draining it via getdents would surface
             * the root directory contents, not the captured dir. */
            h->phase = 0;
            vfs_dbg_op("fdopendir", mapped, "virtual");
        }
        return (void *)h;
    }

    set_loader_errno(EMFILE);
    return NULL;
}

/* linux_dirent64 as returned by SYS_getdents64 */
struct ldr_linux_dirent64 {
    uint64_t       d_ino;
    int64_t        d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

static struct dirent *vfs_readdir(void *dirp)
{
    struct vfs_dir_handle *h = (struct vfs_dir_handle *)dirp;
    if (!h)
        return NULL;
    if (h->magic != VFS_FAKE_DIR_MAGIC) {
        if (g_real_readdir)
            return (struct dirent *)g_real_readdir(dirp);
        set_loader_errno(EBADF);
        return NULL;
    }

    /* ---- Phase -1: drain real directory via getdents64 ---- */
    if (h->phase == -1) {
        if (h->fd_compat >= 0) {
            for (;;) {
                if (h->gd_pos >= h->gd_len) {
                    long ret = VFS_SYSCALL(SYS_getdents64, h->fd_compat,
                                       h->gd_buf, sizeof(h->gd_buf));
                    if (ret <= 0) break;  /* done with real dir */
                    h->gd_len = (int)ret;
                    h->gd_pos = 0;
                }
                struct ldr_linux_dirent64 *d =
                    (struct ldr_linux_dirent64 *)(h->gd_buf + h->gd_pos);
                h->gd_pos += d->d_reclen;

                h->result.d_ino = (ino_t)d->d_ino;
                h->result.d_off = (off_t)d->d_off;
                h->result.d_reclen = sizeof(struct dirent);
                h->result.d_type = d->d_type;
                int nlen = strlen(d->d_name);
                if (nlen > 255) nlen = 255;
                memcpy(h->result.d_name, d->d_name, nlen);
                h->result.d_name[nlen] = '\0';
                return &h->result;
            }
        }
        /* Real dir exhausted — move to VFS file phase */
        h->phase = 0;
        h->scan_pos = 0;
    }

    if (h->vfs_path) {
        /* ---- Phase 0: yield VFS-only child files ----
         * ---- Phase 1: yield VFS-only child subdirs ----
         * ---- Phase 2: yield frozen DLOPEN child .so files ----
         * Captured dirs are virtual-only even when fdopendir carries a
         * placeholder fd for dirfd() compatibility. */
        while (h->phase < 3) {
            if (h->phase == 0) {
                while (h->scan_pos < (int)VFS_HASH_SIZE) {
                    int si = h->scan_pos++;
                    if (!g_vfs_table[si].path) continue;
                    const char *fp = g_vfs_table[si].path;
                    if (strncmp(fp, h->vfs_path, h->vfs_path_len) != 0) continue;
                    if (fp[h->vfs_path_len] != '/') continue;
                    const char *rest = fp + h->vfs_path_len + 1;
                    if (strchr(rest, '/')) continue; /* not direct child */
                    /* Skip .dir markers — invisible to applications */
                    if (rest[0] == '.' && rest[1] == 'd' && rest[2] == 'i'
                        && rest[3] == 'r' && rest[4] == '\0') continue;
                    /* Skip negative entries — they represent non-existent files */
                    if (g_vfs_table[si].flags & DLFRZ_FLAG_DATA_NEGATIVE) continue;
                    h->result.d_ino = (ino_t)(si + 1);
                    h->result.d_off = ((off_t)1 << 32) |
                                      (uint32_t)h->scan_pos;
                    h->result.d_reclen = sizeof(struct dirent);
                    h->result.d_type = DT_REG;
                    int nlen = strlen(rest);
                    if (nlen > 255) nlen = 255;
                    memcpy(h->result.d_name, rest, nlen);
                    h->result.d_name[nlen] = '\0';
                    return &h->result;
                }
                h->phase = 1;
                h->scan_pos = 0;
            }
            if (h->phase == 1) {
                while (h->scan_pos < (int)VFS_DIR_HASH_SIZE) {
                    int si = h->scan_pos++;
                    if (!g_vfs_dir_table[si]) continue;
                    const char *dp = g_vfs_dir_table[si];
                    int dplen = strlen(dp);
                    if (dplen <= h->vfs_path_len) continue;
                    if (strncmp(dp, h->vfs_path, h->vfs_path_len) != 0) continue;
                    if (dp[h->vfs_path_len] != '/') continue;
                    const char *rest = dp + h->vfs_path_len + 1;
                    if (strchr(rest, '/')) continue; /* not direct child */
                    h->result.d_ino = (ino_t)(VFS_HASH_SIZE + si + 1);
                    h->result.d_off = ((off_t)2 << 32) |
                                      (uint32_t)h->scan_pos;
                    h->result.d_reclen = sizeof(struct dirent);
                    h->result.d_type = DT_DIR;
                    int nlen = strlen(rest);
                    if (nlen > 255) nlen = 255;
                    memcpy(h->result.d_name, rest, nlen);
                    h->result.d_name[nlen] = '\0';
                    return &h->result;
                }
                h->phase = 2;
                h->scan_pos = 0;
            }
            if (h->phase == 2) {
                /* Frozen DLOPEN entries served via memfd are not in
                 * g_vfs_table; enumerate them here so directory scanners
                 * can discover them. */
                if (g_frozen_metas && g_frozen_entries && g_frozen_strtab) {
                    while (h->scan_pos < (int)g_frozen_num_entries) {
                        uint32_t si = (uint32_t)h->scan_pos++;
                        if (!(g_frozen_metas[si].flags & LDR_FLAG_DLOPEN))
                            continue;
                        if (g_frozen_metas[si].flags & LDR_FLAG_INTERP)
                            continue;
                        const char *fp = g_frozen_strtab +
                            g_frozen_entries[si].name_offset;
                        if (!fp || fp[0] != '/') continue;
                        if (strncmp(fp, h->vfs_path, h->vfs_path_len) != 0)
                            continue;
                        if (fp[h->vfs_path_len] != '/') continue;
                        const char *rest = fp + h->vfs_path_len + 1;
                        if (strchr(rest, '/')) continue; /* not direct child */
                        h->result.d_ino = (ino_t)(2 * VFS_HASH_SIZE + si + 1);
                        h->result.d_off = ((off_t)3 << 32) |
                                          (uint32_t)h->scan_pos;
                        h->result.d_reclen = sizeof(struct dirent);
                        h->result.d_type = DT_REG;
                        int nlen = strlen(rest);
                        if (nlen > 255) nlen = 255;
                        memcpy(h->result.d_name, rest, nlen);
                        h->result.d_name[nlen] = '\0';
                        return &h->result;
                    }
                }
                h->phase = 3;
            }
        }
        return NULL; /* end of merged listing */
    }

    /* ---- Non-VFS: pure real directory (phase was never -1) ---- */
    for (;;) {
        if (h->gd_pos >= h->gd_len) {
            long ret = VFS_SYSCALL(SYS_getdents64, h->fd_compat,
                               h->gd_buf, sizeof(h->gd_buf));
            if (ret <= 0) return NULL;
            h->gd_len = (int)ret;
            h->gd_pos = 0;
        }
        struct ldr_linux_dirent64 *d =
            (struct ldr_linux_dirent64 *)(h->gd_buf + h->gd_pos);
        h->gd_pos += d->d_reclen;

        h->result.d_ino = (ino_t)d->d_ino;
        h->result.d_off = (off_t)d->d_off;
        h->result.d_reclen = sizeof(struct dirent);
        h->result.d_type = d->d_type;
        int nlen = strlen(d->d_name);
        if (nlen > 255) nlen = 255;
        memcpy(h->result.d_name, d->d_name, nlen);
        h->result.d_name[nlen] = '\0';
        return &h->result;
    }
}

static int vfs_closedir(void *dirp)
{
    struct vfs_dir_handle *h = (struct vfs_dir_handle *)dirp;
    if (!h)
        return -1;
    if (h->magic != VFS_FAKE_DIR_MAGIC) {
        if (g_real_closedir)
            return g_real_closedir(dirp);
        set_loader_errno(EBADF);
        return -1;
    }
    if (h->fd_compat >= 0) {
        forget_vfs_dirfd(h->fd_compat);
        VFS_SYSCALL(SYS_close, h->fd_compat);
    }
    h->magic = 0;
    return 0;
}

static void vfs_rewinddir(void *dirp)
{
    struct vfs_dir_handle *h = (struct vfs_dir_handle *)dirp;

    if (!h)
        return;
    if (h->magic != VFS_FAKE_DIR_MAGIC) {
        if (g_real_rewinddir) {
            g_real_rewinddir(dirp);
            return;
        }
        set_loader_errno(EBADF);
        return;
    }
    if (h->fd_compat >= 0) {
        VFS_SYSCALL(SYS_lseek, h->fd_compat, (off_t)0, SEEK_SET);
        h->gd_pos = 0;
        h->gd_len = 0;
    }
    h->scan_pos = 0;
    if (h->vfs_path) {
        /* Virtual-only: never re-enter the real-FS drain phase. */
        h->phase = 0;
    }
}

static long vfs_telldir(void *dirp)
{
    struct vfs_dir_handle *h = (struct vfs_dir_handle *)dirp;

    if (!h)
        return -1;
    if (h->magic != VFS_FAKE_DIR_MAGIC) {
        if (g_real_telldir)
            return g_real_telldir(dirp);
        set_loader_errno(EBADF);
        return -1;
    }
    if (h->phase >= 0 && h->vfs_path)
        return (long)h->result.d_off;
    return (long)h->result.d_off;
}

static void vfs_seekdir(void *dirp, long loc)
{
    struct vfs_dir_handle *h = (struct vfs_dir_handle *)dirp;
    uint32_t tag;

    if (!h)
        return;
    if (h->magic != VFS_FAKE_DIR_MAGIC) {
        if (g_real_seekdir) {
            g_real_seekdir(dirp, loc);
            return;
        }
        set_loader_errno(EBADF);
        return;
    }
    if (loc == 0) {
        vfs_rewinddir(dirp);
        return;
    }

    tag = (uint32_t)((unsigned long)loc >> 32);
    if (tag != 0 && h->vfs_path) {
        h->phase = (int)tag - 1;
        h->scan_pos = (int)((uint32_t)loc);
        h->gd_pos = 0;
        h->gd_len = 0;
        return;
    }

    if (h->fd_compat >= 0) {
        VFS_SYSCALL(SYS_lseek, h->fd_compat, (off_t)loc, SEEK_SET);
        h->gd_pos = 0;
        h->gd_len = 0;
        if (h->vfs_path)
            h->phase = -1;
    }
}

static int vfs_dirfd(void *dirp)
{
    struct vfs_dir_handle *h = (struct vfs_dir_handle *)dirp;

    if (!h)
        return -1;
    if (h->magic != VFS_FAKE_DIR_MAGIC) {
        if (g_real_dirfd)
            return g_real_dirfd(dirp);
        set_loader_errno(EBADF);
        return -1;
    }
    if (h->fd_compat < 0 && h->vfs_path) {
        int fd = (int)VFS_SYSCALL(SYS_openat, AT_FDCWD, "/",
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);

        if (fd >= 0) {
            h->fd_compat = fd;
            remember_vfs_dirfd(fd, h->vfs_path);
        }
    }
    if (h->fd_compat < 0) {
        set_loader_errno(EBADF);
        return -1;
    }
    return h->fd_compat;
}

/* Helper: create a memfd serving embedded VFS data for a file entry */
static int vfs_serve_memfd(const struct vfs_entry *ve, const char *path);
static int frozen_dlopen_serve_memfd(const char *path);

static int vfs_serve_memfd(const struct vfs_entry *ve, const char *path)
{
    int fd = (int)VFS_SYSCALL(SYS_memfd_create, "dlfrz-vfs", 0);
    if (fd < 0) return -1;
    const uint8_t *p = ve->data;
    uint64_t rem = ve->size;
    while (rem > 0) {
        long w = VFS_SYSCALL(SYS_write, fd, p, rem);
        if (w <= 0) { VFS_SYSCALL(SYS_close, fd); return -1; }
        p   += w;
        rem -= w;
    }
    VFS_SYSCALL(SYS_lseek, fd, (off_t)0, 0 /* SEEK_SET */);
    if (g_debug) {
        ldr_msg("vfs: serving ");
        ldr_msg(path);
        ldr_msg("\n");
    }
    return fd;
}

static int vfs_open(const char *path, int flags, int mode)
{
    /* For absolute paths inside the captured tree, intercept all
     * accesses (read or write) so we never touch the host filesystem.
     * Writes to captured paths are refused (EROFS) since the frozen
    * image is read-only; this prevents caches, locks, and generated files
    * from silently writing to the original /usr/lib/... locations on the
    * host. */
    if (path && path[0] == '/') {
        int is_write = (flags & 3) != 0 /* O_WRONLY or O_RDWR */;
        /* Directory path captured in VFS: serve virtually (no FS touch). */
        if (!is_write && vfs_dir_exists(path)) {
            const struct vfs_entry *ve = vfs_lookup(path);
            if (!ve || (vfs_is_virtual_entry(ve) &&
                        vfs_is_dir_marker_path(path))) {
                int fd = (int)VFS_SYSCALL(SYS_openat, AT_FDCWD, "/",
                                         O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
                if (fd >= 0)
                    remember_vfs_dirfd(fd, path);
                vfs_dbg_op("open", path, "dir-virtual");
                return fd;
            }
        }
        const struct vfs_entry *ve = vfs_lookup(path);
        if (ve && vfs_is_negative_entry(ve)) {
            vfs_dbg_op("open", path, "negative");
            set_loader_errno(ENOENT);
            return -1;
        }
        if (ve && !vfs_is_virtual_entry(ve)) {
            if (is_write) {
                vfs_dbg_op("open", path, "write-refused");
                set_loader_errno(EROFS);
                return -1;
            }
            vfs_dbg_op("open", path, "file");
            int fd = vfs_serve_memfd(ve, path);
            if (fd >= 0) return fd;
        }
        /* Sealed mount: refuse host fall-through for paths that match a
         * frozen-mount glob but were not captured.  Applies to writes too,
         * otherwise cache and lock files could silently land in the host's
         * /usr tree. */
        if (vfs_path_is_sealed_miss(path)) {
            vfs_seal_log("open", path);
            set_loader_errno(is_write ? EROFS : ENOENT);
            return -1;
        }
        if (!is_write) {
            int ret = (int)VFS_SYSCALL(SYS_openat, AT_FDCWD, path, flags, mode);
            if (ret >= 0) return ret;
            /* Probe-open for a DLOPEN ELF before dlopen is reached. */
            int fd = frozen_dlopen_serve_memfd(path);
            if (fd >= 0) {
                vfs_dbg_op("open", path, "dlopen-elf");
                return fd;
            }
            return ret;
        }
    }
    return (int)VFS_SYSCALL(SYS_openat, AT_FDCWD, path, flags, mode);
}

static int vfs_openat(int dirfd, const char *path, int flags, int mode)
{
    char resolved[PATH_MAX];
    const char *lookup_path = path;
    int real_fd;
    (void)real_fd;

    if (path && path[0] != '/' &&
        resolve_vfs_path_at(dirfd, path, resolved, sizeof(resolved)))
        lookup_path = resolved;

    if (lookup_path && lookup_path[0] == '/') {
        int is_write = (flags & 3) != 0 /* O_WRONLY or O_RDWR */;
        /* Serve captured directories purely from VFS: avoid touching the
         * host filesystem whenever the VFS already knows the directory.
         * This applies to both explicit O_DIRECTORY opens and plain
         * O_RDONLY opens that happen to target a directory path. */
        if (!is_write && vfs_dir_exists(lookup_path)) {
            const struct vfs_entry *ve = vfs_lookup(lookup_path);
            if (!ve || (vfs_is_virtual_entry(ve) &&
                        vfs_is_dir_marker_path(lookup_path))) {
                int fd = (int)VFS_SYSCALL(SYS_openat, AT_FDCWD, "/",
                                         O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
                if (fd >= 0)
                    remember_vfs_dirfd(fd, lookup_path);
                vfs_dbg_op("openat", lookup_path, "dir-virtual");
                return fd;
            }
        }
        const struct vfs_entry *ve = vfs_lookup(lookup_path);
        if (ve && vfs_is_negative_entry(ve)) {
            vfs_dbg_op("openat", lookup_path, "negative");
            set_loader_errno(ENOENT);
            return -1;
        }
        if (ve && !vfs_is_virtual_entry(ve)) {
            if (is_write) {
                vfs_dbg_op("openat", lookup_path, "write-refused");
                set_loader_errno(EROFS);
                return -1;
            }
            vfs_dbg_op("openat", lookup_path, "file");
            int fd = vfs_serve_memfd(ve, lookup_path);
            if (fd >= 0) return fd;
        }
        /* Sealed mount: refuse host fall-through for matching misses.
         * Applies to writes too so .pyc cache writes etc. don't leak. */
        if (vfs_path_is_sealed_miss(lookup_path)) {
            vfs_seal_log("openat", lookup_path);
            set_loader_errno(is_write ? EROFS : ENOENT);
            return -1;
        }
        if (!is_write) {
            /* Fallback: probe-open for a DLOPEN ELF path not in VFS data */
            int ret = (int)VFS_SYSCALL(SYS_openat, dirfd, path, flags, mode);
            if (ret >= 0) return ret;
            int fd = frozen_dlopen_serve_memfd(lookup_path);
            if (fd >= 0) {
                vfs_dbg_op("openat", lookup_path, "dlopen-elf");
                return fd;
            }
            return ret;
        }
        vfs_dbg_op("openat", lookup_path, "syscall");
    }
    return (int)VFS_SYSCALL(SYS_openat, dirfd, path, flags, mode);
}

/* vfs_fopen — intercept fopen/fopen64 so that libc's internal openat
 * (which bypasses our GOT-patched openat) also serves from VFS.
 * Falls through to real glibc fopen for non-VFS files. */
static void *vfs_fopen(const char *path, const char *mode)
{
    if (path && path[0] == '/' && mode && mode[0] == 'r') {
        const struct vfs_entry *ve = vfs_lookup(path);
        if (ve && vfs_is_negative_entry(ve)) {
            vfs_dbg_op("fopen", path, "negative");
            set_loader_errno(ENOENT);
            return (void *)0;
        }
        if (ve && !vfs_is_virtual_entry(ve)) {
            vfs_dbg_op("fopen", path, "file");
            int fd = vfs_serve_memfd(ve, path);
            if (fd >= 0 && g_real_fdopen)
                return g_real_fdopen(fd, mode);
            if (fd >= 0) VFS_SYSCALL(SYS_close, fd);
        }
        if (vfs_path_is_sealed_miss(path)) {
            vfs_seal_log("fopen", path);
            set_loader_errno(ENOENT);
            return (void *)0;
        }
        vfs_dbg_op("fopen", path, "syscall");
    }
    if (g_real_fopen) {
        if (g_debug && path) {
            ldr_msg("vfs_fopen fallthrough: ");
            ldr_msg(path);
            ldr_msg("\n");
        }
        return g_real_fopen(path, mode);
    }
    return (void *)0;
}

/*
 * Helpers to make VFS stat/open/access wrappers aware of DLOPEN-captured ELFs.
 * When a frozen binary is run on a different distro, the original absolute
 * paths for extension modules/plugins may not exist on the host.  Without
 * these helpers, openat/stat probes return ENOENT before dlopen is reached.
 */

/* Return the frozen ELF index for path, or -1 if not found. */
static int frozen_dlopen_find(const char *path)
{
    if (!g_frozen_metas || !g_frozen_entries || !g_frozen_strtab)
        return -1;
    for (uint32_t i = 0; i < g_frozen_num_entries; i++) {
        if (!(g_frozen_metas[i].flags & LDR_FLAG_DLOPEN)) continue;
        if (g_frozen_metas[i].flags & LDR_FLAG_INTERP)   continue;
        const char *ename = g_frozen_strtab + g_frozen_entries[i].name_offset;
        if (strcmp(ename, path) == 0)
            return (int)i;
    }
    return -1;
}

/* Returns file size >= 0 if path is a frozen DLOPEN ELF, else -1. */
static int64_t frozen_dlopen_elf_size(const char *path)
{
    int idx = frozen_dlopen_find(path);
    if (idx < 0) return -1;
    return (int64_t)g_frozen_entries[idx].data_size;
}

/* Open a frozen DLOPEN ELF as a memfd so probe-opens succeed even when the
 * original path doesn't exist on the host filesystem. */
static int frozen_dlopen_serve_memfd(const char *path)
{
    int idx = frozen_dlopen_find(path);
    if (idx < 0) return -1;
    const uint8_t *data = g_frozen_mem +
        (g_frozen_entries[idx].data_offset - g_frozen_mem_foff);
    uint64_t size = g_frozen_entries[idx].data_size;
    int fd = (int)VFS_SYSCALL(SYS_memfd_create, "dlfrz-elf", 0);
    if (fd < 0) return -1;
    const uint8_t *p = data;
    uint64_t rem = size;
    while (rem > 0) {
        long w = VFS_SYSCALL(SYS_write, fd, p, rem);
        if (w <= 0) { VFS_SYSCALL(SYS_close, fd); return -1; }
        p   += w;
        rem -= (uint64_t)w;
    }
    VFS_SYSCALL(SYS_lseek, fd, (off_t)0, 0 /* SEEK_SET */);
    if (g_debug) {
        ldr_msg("vfs: serving dlopen-elf ");
        ldr_msg(path);
        ldr_msg("\n");
    }
    return fd;
}

/*
 * vfs_stat / vfs_fstatat — intercept stat calls for embedded files and
 * fabricate a regular-file stat result for embedded VFS entries.
 */
static int vfs_stat(const char *path, struct stat *buf)
{
    if (path && path[0] == '/') {
        /* Report real files and non-directory virtual placeholders so
         * directory/plugin scanners can discover embedded ELF names.
         * Directory markers stay synthetic-only. */
        const struct vfs_entry *ve = vfs_lookup(path);
        if (ve && vfs_is_negative_entry(ve)) {
            vfs_dbg_op("stat", path, "negative");
            set_loader_errno(ENOENT);
            return -1;
        }
        if (ve && !(vfs_is_virtual_entry(ve) && vfs_is_dir_marker_path(path))) {
            vfs_dbg_op("stat", path, "file");
            /* Virtual entries have no embedded data (size=0); fall through
             * so the real FS or frozen_dlopen_elf_size provides the correct size. */
            if (vfs_is_virtual_entry(ve))
                goto vfs_stat_fallthrough;
            __builtin_memset(buf, 0, sizeof(*buf));
            buf->st_mode  = 0100644;  /* regular file, rw-r--r-- */
            buf->st_nlink = 1;
            buf->st_size  = ve->size;
            buf->st_blksize = (blksize_t)g_page_size;
            buf->st_blocks  = (ve->size + 511) / 512;
            return 0;
        }
    }
vfs_stat_fallthrough:;
    /* Sealed mount: don't touch the host FS for misses inside a frozen mount. */
    if (vfs_path_is_sealed_miss(path)) {
        vfs_seal_log("stat", path);
        set_loader_errno(ENOENT);
        return -1;
    }
    /* Captured directories: synthesise the result so we never reach the
     * host filesystem for paths that are part of the frozen image. */
    if (path && path[0] == '/' && vfs_dir_exists(path)) {
        vfs_dbg_op("stat", path, "dir");
        __builtin_memset(buf, 0, sizeof(*buf));
        buf->st_mode  = 040755;  /* directory, rwxr-xr-x */
        buf->st_nlink = 2;
        buf->st_blksize = (blksize_t)g_page_size;
        return 0;
    }
    /* Frozen DLOPEN ELFs: synthesise so we never touch the host FS
     * even when a same-named .so happens to exist there. */
    if (path && path[0] == '/') {
        int64_t elf_sz = frozen_dlopen_elf_size(path);
        if (elf_sz >= 0) {
            vfs_dbg_op("stat", path, "dlopen-elf");
            __builtin_memset(buf, 0, sizeof(*buf));
            buf->st_mode  = 0100644;
            buf->st_nlink = 1;
            buf->st_size  = (off_t)elf_sz;
            buf->st_blksize = (blksize_t)g_page_size;
            buf->st_blocks  = (elf_sz + 511) / 512;
            return 0;
        }
    }
    /* Everything else: real FS */
    return (int)VFS_SYSCALL(SYS_newfstatat, AT_FDCWD, path, buf, 0);
}

static int vfs_fstatat(int dirfd, const char *path, struct stat *buf, int flag)
{
    char resolved[PATH_MAX];
    const char *lookup_path = path;

    if (path && path[0] != '/' &&
        resolve_vfs_path_at(dirfd, path, resolved, sizeof(resolved)))
        lookup_path = resolved;

    if (lookup_path && lookup_path[0] == '/') {
        const struct vfs_entry *ve = vfs_lookup(lookup_path);
        if (ve && vfs_is_negative_entry(ve)) {
            vfs_dbg_op("fstatat", lookup_path, "negative");
            set_loader_errno(ENOENT);
            return -1;
        }
        if (ve && !(vfs_is_virtual_entry(ve) && vfs_is_dir_marker_path(lookup_path))) {
            vfs_dbg_op("fstatat", lookup_path, "file");
            if (vfs_is_virtual_entry(ve))
                goto vfs_fstatat_fallthrough;
            __builtin_memset(buf, 0, sizeof(*buf));
            buf->st_mode  = 0100644;
            buf->st_nlink = 1;
            buf->st_size  = ve->size;
            buf->st_blksize = (blksize_t)g_page_size;
            buf->st_blocks  = (ve->size + 511) / 512;
            return 0;
        }
    }
vfs_fstatat_fallthrough:;
    if (vfs_path_is_sealed_miss(lookup_path)) {
        vfs_seal_log("fstatat", lookup_path);
        set_loader_errno(ENOENT);
        return -1;
    }
    if (lookup_path && lookup_path[0] == '/' && vfs_dir_exists(lookup_path)) {
        vfs_dbg_op("fstatat", lookup_path, "dir");
        __builtin_memset(buf, 0, sizeof(*buf));
        buf->st_mode  = 040755;
        buf->st_nlink = 2;
        buf->st_blksize = (blksize_t)g_page_size;
        return 0;
    }
    /* Frozen DLOPEN ELFs: synthesise so we never touch the host FS
     * even when a same-named .so happens to exist there. */
    if (lookup_path && lookup_path[0] == '/') {
        int64_t elf_sz = frozen_dlopen_elf_size(lookup_path);
        if (elf_sz >= 0) {
            vfs_dbg_op("fstatat", lookup_path, "dlopen-elf");
            __builtin_memset(buf, 0, sizeof(*buf));
            buf->st_mode  = 0100644;
            buf->st_nlink = 1;
            buf->st_size  = (off_t)elf_sz;
            buf->st_blksize = (blksize_t)g_page_size;
            buf->st_blocks  = (elf_sz + 511) / 512;
            return 0;
        }
    }
    return (int)VFS_SYSCALL(SYS_newfstatat, dirfd, path, buf, flag);
}

/* vfs_access / vfs_faccessat — keep existence probes inside the frozen image. */
static int vfs_access(const char *path, int amode)
{
    if (path && path[0] == '/') {
        const struct vfs_entry *ve = vfs_lookup(path);
        if (ve && vfs_is_negative_entry(ve)) {
            vfs_dbg_op("access", path, "negative");
            set_loader_errno(ENOENT);
            return -1;
        }
        if (ve && !(vfs_is_virtual_entry(ve) && vfs_is_dir_marker_path(path))) {
            vfs_dbg_op("access", path, "file");
            return 0;
        }
    }
    if (vfs_path_is_sealed_miss(path)) {
        vfs_seal_log("access", path);
        set_loader_errno(ENOENT);
        return -1;
    }
    if (path && path[0] == '/' && vfs_dir_exists(path)) {
        vfs_dbg_op("access", path, "dir");
        return 0;
    }
    if (path && path[0] == '/' &&
        frozen_dlopen_elf_size(path) >= 0) {
        vfs_dbg_op("access", path, "dlopen-elf");
        return 0;
    }
    return (int)VFS_SYSCALL(SYS_faccessat, AT_FDCWD, path, amode, 0);
}

static int vfs_faccessat(int dirfd, const char *path, int amode, int flag)
{
    char resolved[PATH_MAX];
    const char *lookup_path = path;

    if (path && path[0] != '/' &&
        resolve_vfs_path_at(dirfd, path, resolved, sizeof(resolved)))
        lookup_path = resolved;

    if (lookup_path && lookup_path[0] == '/') {
        const struct vfs_entry *ve = vfs_lookup(lookup_path);
        if (ve && vfs_is_negative_entry(ve)) {
            vfs_dbg_op("faccessat", lookup_path, "negative");
            set_loader_errno(ENOENT);
            return -1;
        }
        if (ve && !(vfs_is_virtual_entry(ve) && vfs_is_dir_marker_path(lookup_path))) {
            vfs_dbg_op("faccessat", lookup_path, "file");
            return 0;
        }
    }
    if (vfs_path_is_sealed_miss(lookup_path)) {
        vfs_seal_log("faccessat", lookup_path);
        set_loader_errno(ENOENT);
        return -1;
    }
    if (lookup_path && lookup_path[0] == '/' && vfs_dir_exists(lookup_path)) {
        vfs_dbg_op("faccessat", lookup_path, "dir");
        return 0;
    }
    if (lookup_path && lookup_path[0] == '/' &&
        frozen_dlopen_elf_size(lookup_path) >= 0) {
        vfs_dbg_op("faccessat", lookup_path, "dlopen-elf");
        return 0;
    }
    return (int)VFS_SYSCALL(SYS_faccessat, dirfd, path, amode, flag);
}

static int vfs_xstat(int ver, const char *path, struct stat *buf)
{
    (void)ver;
    return vfs_stat(path, buf);
}

/* Modern glibc (>= 2.33) exposes lstat / lstat64 as direct symbols rather
 * than the legacy __lxstat / __lxstat64 inline wrappers.  Recent callers
 * resolve these symbols, so we must intercept them too — otherwise lstat()
 * falls through to the host filesystem and leaks host metadata. */
static int vfs_lstat(const char *path, struct stat *buf)
{
    return vfs_fstatat(AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW);
}

static char *vfs_realpath(const char *path, char *resolved)
{
    if (path && path[0] == '/') {
        const struct vfs_entry *ve = vfs_lookup(path);
        int path_exists = 0;

        if (ve && vfs_is_negative_entry(ve)) {
            set_loader_errno(ENOENT);
            return NULL;
        }

        if (g_real_realpath) {
            char *result = g_real_realpath(path, resolved);

            if (result)
                return result;
        }

        if (VFS_SYSCALL(SYS_newfstatat, AT_FDCWD, path,
                        &(struct stat){0}, 0) == 0)
            path_exists = 1;

        if ((ve && !vfs_is_negative_entry(ve)) ||
            vfs_dir_exists(path) ||
            frozen_dlopen_elf_size(path) >= 0 ||
            path_exists) {
            size_t len = strlen(path) + 1;

            if (resolved) {
                memcpy(resolved, path, len);
                return resolved;
            }
            if (g_real_malloc) {
                char *copy = g_real_malloc(len);

                if (!copy) {
                    set_loader_errno(ENOMEM);
                    return NULL;
                }
                memcpy(copy, path, len);
                return copy;
            }
        }
    }

    if (g_real_realpath)
        return g_real_realpath(path, resolved);
    set_loader_errno(ENOENT);
    return NULL;
}

static int vfs_lxstat(int ver, const char *path, struct stat *buf)
{
    (void)ver;
    return vfs_fstatat(AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW);
}

static int vfs_fxstatat(int ver, int dirfd, const char *path,
                        struct stat *buf, int flag)
{
    (void)ver;
    return vfs_fstatat(dirfd, path, buf, flag);
}

/* Return the main executable path captured at freeze time, or NULL if
 * unavailable.  The /proc/self/exe hook preserves executable-relative
 * resource discovery inside the captured VFS tree. */
static const char *vfs_main_exe_path(void)
{
    if (!g_frozen_metas || !g_frozen_entries || !g_frozen_strtab)
        return NULL;
    for (uint32_t i = 0; i < g_frozen_num_entries; i++) {
        if (!(g_frozen_metas[i].flags & LDR_FLAG_MAIN_EXE))
            continue;
        const char *p = g_frozen_strtab + g_frozen_entries[i].name_offset;
        if (p && p[0] == '/')
            return p;
        return NULL;
    }
    return NULL;
}

/* Match "/proc/self/exe" or "/proc/<our-pid>/exe". */
static int vfs_path_is_self_exe(const char *path)
{
    if (!path) return 0;
    if (strcmp(path, "/proc/self/exe") == 0)
        return 1;
    if (strncmp(path, "/proc/", 6) != 0)
        return 0;
    const char *p = path + 6;
    long pid = 0;
    while (*p >= '0' && *p <= '9') {
        pid = pid * 10 + (*p - '0');
        p++;
    }
    if (p == path + 6) return 0;
    if (strcmp(p, "/exe") != 0) return 0;
    return pid == (long)VFS_SYSCALL(SYS_getpid);
}

static ssize_t vfs_readlinkat(int dirfd, const char *path,
                              char *buf, size_t bufsiz)
{
    if (path && vfs_path_is_self_exe(path)) {
        const char *exe = vfs_main_exe_path();
        if (exe) {
            size_t n = strlen(exe);
            if (n > bufsiz) n = bufsiz;
            memcpy(buf, exe, n);
            return (ssize_t)n;
        }
    }
    long ret = VFS_SYSCALL(SYS_readlinkat, dirfd, path, buf, bufsiz);
    if (ret < 0)
        return -1;
    return (ssize_t)ret;
}

static ssize_t vfs_readlink(const char *path, char *buf, size_t bufsiz)
{
    return vfs_readlinkat(AT_FDCWD, path, buf, bufsiz);
}

/* ==== Resolution cache ================================================ */

#define RESOLVE_CACHE_SIZE 65536U  /* must be power-of-two */

enum cache_state {
    CACHE_EMPTY = 0,
    CACHE_FOUND = 1,
    CACHE_MISS  = 2,
};

struct sym_cache_ent {
    const char *name;
    uint32_t    gh;
    uint32_t    epoch;
    uint8_t     state;
    uint64_t    value;
};

static struct sym_cache_ent g_sym_cache[RESOLVE_CACHE_SIZE];
static uint32_t g_cache_epoch = 1;

static void clear_resolution_caches(void)
{
    g_cache_epoch++;
    if (g_cache_epoch == 0) {
        memset(g_sym_cache, 0, sizeof(g_sym_cache));
        g_cache_epoch = 1;
    }
}

/* Return: 1 found, -1 cached miss, 0 not present in cache */
static int sym_cache_lookup(const char *name, uint32_t gh, uint64_t *out)
{
    uint32_t idx = gh & (RESOLVE_CACHE_SIZE - 1);
    for (uint32_t n = 0; n < RESOLVE_CACHE_SIZE; n++) {
        struct sym_cache_ent *e = &g_sym_cache[idx];
        if (e->epoch != g_cache_epoch || e->state == CACHE_EMPTY) return 0;
        if (e->gh == gh && e->name && strcmp(e->name, name) == 0) {
            if (e->state == CACHE_FOUND) { *out = e->value; return 1; }
            return -1;
        }
        idx = (idx + 1) & (RESOLVE_CACHE_SIZE - 1);
    }
    return 0;
}

/* Cache keys must outlive every API call that can query this table.  In
 * practice callers pass a name from a loaded object's bounded DT_STRTAB;
 * never retain a dlsym caller's stack/heap buffer here. */
static void sym_cache_store_canonical(const char *name, uint32_t gh,
                                      uint8_t state, uint64_t value)
{
    uint32_t idx = gh & (RESOLVE_CACHE_SIZE - 1);
    for (uint32_t n = 0; n < RESOLVE_CACHE_SIZE; n++) {
        struct sym_cache_ent *e = &g_sym_cache[idx];
        if (e->epoch != g_cache_epoch || e->state == CACHE_EMPTY ||
            (e->gh == gh && e->name && strcmp(e->name, name) == 0)) {
            e->name = name;
            e->gh = gh;
            e->epoch = g_cache_epoch;
            e->state = state;
            e->value = value;
            return;
        }
        idx = (idx + 1) & (RESOLVE_CACHE_SIZE - 1);
    }
}

/* ==== Symbol lookup ==================================================== */

static uint32_t gnu_hash_calc(const char *name)
{
    uint32_t h = 5381;
    for (; *name; name++)
        h = (h << 5) + h + (uint8_t)*name;
    return h;
}

static uint32_t sysv_hash_calc(const char *name)
{
    uint32_t h = 0;

    for (; *name; name++) {
        uint32_t high;

        h = (h << 4) + (uint8_t)*name;
        high = h & 0xf0000000U;
        if (high)
            h ^= high >> 24;
        h &= ~high;
    }
    return h;
}

static int elf_strtab_name_eq(const char *strtab, size_t strtab_size,
                              uint32_t off, const char *name);

static int mapped_array_contains(const struct loaded_obj *obj,
                                 uintptr_t addr, size_t count,
                                 size_t element_size)
{
    size_t bytes;

    if (count != 0 && element_size > SIZE_MAX / count)
        return 0;
    bytes = count * element_size;
    return loaded_obj_contains(obj, addr, bytes);
}

static int mapped_advance(const struct loaded_obj *obj, uintptr_t *addr,
                          size_t count, size_t element_size)
{
    size_t bytes;

    if (!mapped_array_contains(obj, *addr, count, element_size))
        return 0;
    bytes = count * element_size;
    if (*addr > UINTPTR_MAX - bytes)
        return 0;
    *addr += bytes;
    return 1;
}

static int mapped_pointer_add(const struct loaded_obj *obj, uintptr_t base,
                              size_t offset, size_t size,
                              uintptr_t *result)
{
    if (base > UINTPTR_MAX - offset)
        return 0;
    *result = base + offset;
    return loaded_obj_contains(obj, *result, size);
}

struct gnu_hash_view {
    uint32_t nbuckets;
    uint32_t symoffset;
    uint32_t bloom_size;
    uint32_t bloom_shift;
    const uint64_t *bloom;
    const uint32_t *buckets;
    uintptr_t chain_addr;
};

static int get_gnu_hash_view(const struct loaded_obj *obj,
                             struct gnu_hash_view *view)
{
    const uint32_t *header = obj->gnu_hash;
    uintptr_t cursor;

    if (!header ||
        !mapped_array_contains(obj, (uintptr_t)header, 4, sizeof(uint32_t)))
        return 0;

    view->nbuckets = header[0];
    view->symoffset = header[1];
    view->bloom_size = header[2];
    view->bloom_shift = header[3];
    if (view->nbuckets == 0 || view->bloom_size == 0 ||
        view->bloom_shift >= 32)
        return 0;

    cursor = (uintptr_t)(header + 4);
    view->bloom = (const uint64_t *)cursor;
    if (!mapped_advance(obj, &cursor, view->bloom_size, sizeof(uint64_t)))
        return 0;
    view->buckets = (const uint32_t *)cursor;
    if (!mapped_advance(obj, &cursor, view->nbuckets, sizeof(uint32_t)))
        return 0;
    view->chain_addr = cursor;
    return 1;
}

static int gnu_hash_chain_value(const struct loaded_obj *obj,
                                const struct gnu_hash_view *view,
                                uint32_t sym_index, uint32_t *value)
{
    size_t chain_index;
    uintptr_t addr;

    if (sym_index < view->symoffset)
        return 0;
    chain_index = (size_t)(sym_index - view->symoffset);
    if (chain_index > (UINTPTR_MAX - view->chain_addr) / sizeof(uint32_t))
        return 0;
    addr = view->chain_addr + chain_index * sizeof(uint32_t);
    if (!mapped_array_contains(obj, addr, 1, sizeof(uint32_t)))
        return 0;
    *value = *(const uint32_t *)addr;
    return 1;
}

static uint32_t gnu_hash_symbol_count_loaded(const struct loaded_obj *obj)
{
    struct gnu_hash_view view;
    uint32_t max_sym = 0;
    int have_symbol = 0;

    if (!get_gnu_hash_view(obj, &view))
        return 0;
    for (uint32_t i = 0; i < view.nbuckets; i++) {
        uint32_t sym = view.buckets[i];

        if (sym == STN_UNDEF)
            continue;
        if (sym < view.symoffset)
            return 0;
        if (!have_symbol || sym > max_sym)
            max_sym = sym;
        have_symbol = 1;
    }
    if (!have_symbol)
        return view.symoffset;

    for (;;) {
        uint32_t value;

        if (!gnu_hash_chain_value(obj, &view, max_sym, &value))
            return 0;
        if (value & 1)
            return max_sym == UINT32_MAX ? 0 : max_sym + 1;
        if (max_sym == UINT32_MAX)
            return 0;
        max_sym++;
    }
}

struct sysv_hash_view {
    uint32_t nbuckets;
    uint32_t nchain;
    const uint32_t *buckets;
    const uint32_t *chains;
};

static int get_sysv_hash_view(const struct loaded_obj *obj,
                              struct sysv_hash_view *view)
{
    const uint32_t *header = obj->sysv_hash;
    uintptr_t cursor;

    if (!header ||
        !mapped_array_contains(obj, (uintptr_t)header, 2, sizeof(uint32_t)))
        return 0;
    view->nbuckets = header[0];
    view->nchain = header[1];
    if (view->nbuckets == 0 || view->nchain == 0)
        return 0;

    cursor = (uintptr_t)(header + 2);
    view->buckets = (const uint32_t *)cursor;
    if (!mapped_advance(obj, &cursor, view->nbuckets, sizeof(uint32_t)))
        return 0;
    view->chains = (const uint32_t *)cursor;
    if (!mapped_array_contains(obj, cursor, view->nchain, sizeof(uint32_t)))
        return 0;
    return 1;
}

static const Elf64_Sym *loaded_dynsym(const struct loaded_obj *obj,
                                      uint32_t index)
{
    uintptr_t addr;

    if (!obj->dynsym || index >= obj->dynsym_count ||
        index > (UINTPTR_MAX - (uintptr_t)obj->dynsym) / sizeof(Elf64_Sym))
        return NULL;
    addr = (uintptr_t)obj->dynsym + (size_t)index * sizeof(Elf64_Sym);
    if (!mapped_array_contains(obj, addr, 1, sizeof(Elf64_Sym)))
        return NULL;
    return (const Elf64_Sym *)addr;
}

static int loaded_versym_value(const struct loaded_obj *obj, uint32_t index,
                               uint16_t *value)
{
    uintptr_t addr;

    if (!obj->versym)
        return 0;
    if (index > (UINTPTR_MAX - (uintptr_t)obj->versym) / sizeof(uint16_t))
        return 0;
    addr = (uintptr_t)obj->versym + (size_t)index * sizeof(uint16_t);
    if (!mapped_array_contains(obj, addr, 1, sizeof(uint16_t)))
        return 0;
    *value = *(const uint16_t *)addr;
    return 1;
}

static int symbol_hidden(const struct loaded_obj *obj, uint32_t index,
                         int *hidden)
{
    uint16_t value;

    *hidden = 0;
    if (!obj->versym)
        return 1;
    if (!loaded_versym_value(obj, index, &value))
        return 0;
    *hidden = (value & 0x8000) != 0;
    return 1;
}

static const char *loaded_dynstr_value(const struct loaded_obj *obj,
                                       uint32_t offset)
{
    const char *value;

    if (!obj->dynstr || obj->dynstr_size == 0 ||
        !mapped_array_contains(obj, (uintptr_t)obj->dynstr,
                               obj->dynstr_size, 1))
        return NULL;
    if (offset >= obj->dynstr_size)
        return NULL;
    value = obj->dynstr + offset;
    if (!memchr(value, '\0', obj->dynstr_size - offset))
        return NULL;
    return value;
}

static const char *loaded_symbol_name(const struct loaded_obj *obj,
                                      const Elf64_Sym *sym)
{
    return loaded_dynstr_value(obj, sym->st_name);
}

static int loaded_symbol_name_eq(const struct loaded_obj *obj,
                                 const Elf64_Sym *sym, const char *name)
{
    const char *value = loaded_symbol_name(obj, sym);

    return value && strcmp(value, name) == 0;
}

static int symbol_visible_outside_object(const Elf64_Sym *sym)
{
    unsigned int visibility;

    if (!sym)
        return 0;
    visibility = ELF64_ST_VISIBILITY(sym->st_other);
    return visibility != STV_HIDDEN && visibility != STV_INTERNAL;
}

static int symbol_must_bind_locally(const Elf64_Sym *sym)
{
    unsigned int visibility;

    if (!sym || sym->st_shndx == SHN_UNDEF)
        return 0;
    visibility = ELF64_ST_VISIBILITY(sym->st_other);
    return ELF64_ST_BIND(sym->st_info) == STB_LOCAL ||
           visibility == STV_HIDDEN || visibility == STV_INTERNAL ||
           visibility == STV_PROTECTED;
}

static const Elf64_Sym *lookup_gnu_hash(const struct loaded_obj *obj,
                                         const char *name, uint32_t gh)
{
    struct gnu_hash_view view;
    uint64_t word;
    uint64_t mask;
    uint32_t idx;
    const Elf64_Sym *fallback = NULL;

    if (!obj->dynsym || !obj->dynstr ||
        !get_gnu_hash_view(obj, &view))
        return NULL;

    word = view.bloom[(gh / 64) % view.bloom_size];
    mask = (1ULL << (gh % 64)) |
           (1ULL << ((gh >> view.bloom_shift) % 64));
    if ((word & mask) != mask)
        return NULL;

    idx = view.buckets[gh % view.nbuckets];
    if (idx < view.symoffset || idx >= obj->dynsym_count)
        return NULL;

    while (idx < obj->dynsym_count) {
        uint32_t ch;

        if (!gnu_hash_chain_value(obj, &view, idx, &ch))
            return NULL;
        if ((ch | 1) == (gh | 1)) {
            const Elf64_Sym *sym = loaded_dynsym(obj, idx);
            int hidden;

            if (sym && sym->st_shndx != SHN_UNDEF &&
                ELF64_ST_BIND(sym->st_info) != STB_LOCAL &&
                symbol_visible_outside_object(sym) &&
                loaded_symbol_name_eq(obj, sym, name) &&
                symbol_hidden(obj, idx, &hidden)) {
                /* Prefer default version (versym without HIDDEN bit) */
                if (!hidden)
                    return sym;
                if (!fallback)
                    fallback = sym;
            }
        }
        if (ch & 1)
            break;
        idx++;
    }
    return fallback;
}

static const Elf64_Sym *lookup_sysv_hash(const struct loaded_obj *obj,
                                          const char *name, uint32_t hash)
{
    struct sysv_hash_view view;
    uint32_t idx;
    const Elf64_Sym *fallback = NULL;

    if (!obj->dynsym || !obj->dynstr ||
        !get_sysv_hash_view(obj, &view))
        return NULL;

    idx = view.buckets[hash % view.nbuckets];
    for (uint32_t steps = 0; idx != STN_UNDEF && steps < view.nchain;
         steps++) {
        const Elf64_Sym *sym;
        int hidden;

        if (idx >= view.nchain || idx >= obj->dynsym_count)
            return NULL;
        sym = loaded_dynsym(obj, idx);
        if (!sym)
            return NULL;
        if (sym->st_shndx != SHN_UNDEF &&
            ELF64_ST_BIND(sym->st_info) != STB_LOCAL &&
            symbol_visible_outside_object(sym) &&
            loaded_symbol_name_eq(obj, sym, name) &&
            symbol_hidden(obj, idx, &hidden)) {
            if (!hidden)
                return sym;
            if (!fallback)
                fallback = sym;
        }
        idx = view.chains[idx];
    }
    return fallback;
}

static const Elf64_Sym *lookup_linear(const struct loaded_obj *obj,
                                       const char *name)
{
    if (!obj->dynsym || !obj->dynstr)
        return NULL;
    for (uint32_t i = 1; i < obj->dynsym_count; i++) {
        const Elf64_Sym *sym = loaded_dynsym(obj, i);

        if (!sym)
            return NULL;
        if (sym->st_shndx != SHN_UNDEF &&
            ELF64_ST_BIND(sym->st_info) != STB_LOCAL &&
            loaded_symbol_name_eq(obj, sym, name))
            return sym;
    }
    return NULL;
}

static const Elf64_Sym *lookup_linear_external(const struct loaded_obj *obj,
                                                const char *name)
{
    if (!obj->dynsym || !obj->dynstr)
        return NULL;
    for (uint32_t i = 1; i < obj->dynsym_count; i++) {
        const Elf64_Sym *sym = loaded_dynsym(obj, i);

        if (!sym)
            return NULL;
        if (sym->st_shndx != SHN_UNDEF &&
            ELF64_ST_BIND(sym->st_info) != STB_LOCAL &&
            symbol_visible_outside_object(sym) &&
            loaded_symbol_name_eq(obj, sym, name))
            return sym;
    }
    return NULL;
}

static const Elf64_Sym *lookup_object_symbol(const struct loaded_obj *obj,
                                              const char *name,
                                              uint32_t gnu_hash)
{
    if (obj->gnu_hash)
        return lookup_gnu_hash(obj, name, gnu_hash);
    if (obj->sysv_hash)
        return lookup_sysv_hash(obj, name, sysv_hash_calc(name));
    return lookup_linear_external(obj, name);
}

/* Convert a definition to its runtime address without trusting st_value.
 * TLS definitions are offsets in their module, SHN_ABS values are already
 * absolute, and every other definition must remain inside one PT_LOAD.
 * IFUNC resolvers additionally have to reside in executable memory. */
static int resolve_defined_symbol_address(struct loaded_obj *obj,
                                          const Elf64_Sym *sym,
                                          uint64_t *address_out,
                                          int *cacheable_out)
{
    unsigned int type;
    void *pointer;
    size_t size;

    if (!obj || !sym || !address_out || sym->st_shndx == SHN_UNDEF)
        return 0;
    if (cacheable_out)
        *cacheable_out = 1;
    type = ELF64_ST_TYPE(sym->st_info);

    if (type == STT_TLS) {
        if (sym->st_shndx >= SHN_LORESERVE ||
            !runtime_tls_template_valid(obj) || obj->tls.modid == 0 ||
            sym->st_value > obj->tls.memsz ||
            sym->st_size > obj->tls.memsz - sym->st_value)
            return 0;
        pointer = runtime_tls_get_addr(arch_get_tp(), obj->tls.modid,
                                       (unsigned long)sym->st_value);
        if (!pointer)
            return 0;
        *address_out = (uint64_t)(uintptr_t)pointer;
        if (cacheable_out)
            *cacheable_out = 0;
        return 1;
    }

    if (sym->st_shndx == SHN_ABS) {
        /* An absolute IFUNC would escape the owning object's executable
         * mappings, so it cannot be validated safely. */
        if (type == STT_GNU_IFUNC)
            return 0;
        *address_out = sym->st_value;
        return 1;
    }
    if (sym->st_shndx >= SHN_LORESERVE || sym->st_size > SIZE_MAX)
        return 0;

    size = type == STT_GNU_IFUNC ? 1 : (size_t)sym->st_size;
    if (!loaded_obj_vaddr_pointer(obj, sym->st_value, size,
                                  type == STT_GNU_IFUNC ? PF_X : 0,
                                  &pointer))
        return 0;
    if (type == STT_GNU_IFUNC) {
        typedef uint64_t (*ifunc_t)(void);

        *address_out = ((ifunc_t)pointer)();
    } else {
        *address_out = (uint64_t)(uintptr_t)pointer;
    }
    return 1;
}

static int elf_strtab_name_eq(const char *strtab, size_t strtab_size,
                              uint32_t off, const char *name)
{
    size_t i = 0;

    if (off >= strtab_size)
        return 0;
    while (name[i]) {
        if (off + i >= strtab_size || strtab[off + i] != name[i])
            return 0;
        i++;
    }
    return off + i < strtab_size && strtab[off + i] == '\0';
}

static const char *defined_symbol_version(const struct loaded_obj *obj,
                                          uint32_t sym_index)
{
    uint16_t raw_version;
    uint16_t version_index;
    uintptr_t cursor;

    if (!obj->versym || !obj->verdef || obj->verdef_count == 0 ||
        sym_index >= obj->dynsym_count)
        return NULL;

    if (!loaded_versym_value(obj, sym_index, &raw_version))
        return NULL;
    version_index = raw_version & 0x7fff;
    if (version_index <= 1)
        return NULL;

    cursor = (uintptr_t)obj->verdef;
    for (uint32_t i = 0; i < obj->verdef_count; i++) {
        const Elf64_Verdef *def = (const Elf64_Verdef *)(uintptr_t)cursor;

        if (!loaded_obj_contains(obj, cursor, sizeof(*def)))
            return NULL;
        if ((def->vd_ndx & 0x7fff) == version_index) {
            const Elf64_Verdaux *aux;
            const char *version;
            uintptr_t aux_addr;

            if (def->vd_aux < sizeof(*def))
                return NULL;
            if (!mapped_pointer_add(obj, cursor, def->vd_aux, sizeof(*aux),
                                    &aux_addr))
                return NULL;
            aux = (const Elf64_Verdaux *)(uintptr_t)aux_addr;
            version = loaded_dynstr_value(obj, aux->vda_name);
            return version;
        }
        if (def->vd_next == 0)
            break;
        if (!mapped_pointer_add(obj, cursor, def->vd_next,
                                sizeof(Elf64_Verdef), &cursor))
            return NULL;
    }
    return NULL;
}

/* Resolve a version index through VERNEED.  A COPY-relocated import is
 * defined in the executable's dynsym, but its version still belongs to
 * VERNEED, so st_shndx cannot be used to choose between VERNEED and VERDEF.
 * Return 1 when found, 0 when this table does not own the index, and -1 for
 * malformed metadata. */
static int needed_symbol_version(const struct loaded_obj *obj,
                                 uint16_t version_index,
                                 const char **version_out)
{
    uintptr_t cursor;

    *version_out = NULL;
    if (!obj->verneed || obj->verneed_count == 0)
        return 0;

    cursor = (uintptr_t)obj->verneed;
    for (uint32_t i = 0; i < obj->verneed_count; i++) {
        const Elf64_Verneed *need = (const Elf64_Verneed *)(uintptr_t)cursor;
        uintptr_t aux_cursor;

        if (!loaded_obj_contains(obj, cursor, sizeof(*need)) ||
            need->vn_aux < sizeof(*need))
            return -1;
        if (!mapped_pointer_add(obj, cursor, need->vn_aux,
                                sizeof(Elf64_Vernaux), &aux_cursor))
            return -1;
        for (uint16_t a = 0; a < need->vn_cnt; a++) {
            const Elf64_Vernaux *aux =
                (const Elf64_Vernaux *)(uintptr_t)aux_cursor;

            if (!loaded_obj_contains(obj, aux_cursor, sizeof(*aux)))
                return -1;
            if ((aux->vna_other & 0x7fff) == version_index) {
                *version_out = loaded_dynstr_value(obj, aux->vna_name);
                return *version_out ? 1 : -1;
            }
            if (aux->vna_next == 0)
                break;
            if (!mapped_pointer_add(obj, aux_cursor, aux->vna_next,
                                    sizeof(Elf64_Vernaux), &aux_cursor))
                return -1;
        }
        if (need->vn_next == 0)
            break;
        if (!mapped_pointer_add(obj, cursor, need->vn_next,
                                sizeof(Elf64_Verneed), &cursor))
            return -1;
    }
    return 0;
}

/* Resolve the version attached to any dynsym entry by version-index table
 * membership.  VERNEED is intentionally checked first for executable COPY
 * symbols; normal definitions then fall through to VERDEF. */
static int symbol_version_name(const struct loaded_obj *obj,
                               uint32_t sym_index,
                               const char **version_out)
{
    uint16_t raw_version;
    uint16_t version_index;
    const char *defined_version;
    int needed;

    *version_out = NULL;
    if (!obj->versym)
        return 0;
    if (sym_index >= obj->dynsym_count ||
        !loaded_versym_value(obj, sym_index, &raw_version))
        return -1;
    version_index = raw_version & 0x7fff;
    if (version_index <= 1)
        return 0;

    needed = needed_symbol_version(obj, version_index, version_out);
    if (needed != 0)
        return needed;

    defined_version = defined_symbol_version(obj, sym_index);
    if (!defined_version)
        return -1;
    *version_out = defined_version;
    return 1;
}

/* Return 1 and the requested/defined version name for a versioned
 * relocation, 0 for an unversioned symbol, or -1 for malformed metadata. */
static int relocation_symbol_version(const struct loaded_obj *obj,
                                     uint32_t sym_index,
                                     const char **version_out)
{
    return symbol_version_name(obj, sym_index, version_out);
}

static const Elf64_Sym *lookup_versioned_symbol(const struct loaded_obj *obj,
                                                 const char *name,
                                                 const char *version)
{
    if (!obj->dynsym || !obj->dynstr || !name || !version)
        return NULL;

    /* Versioned lookup cannot use the default-preferring helpers above, but
     * it must still follow the object's native hash chain.  A full dynsym
     * scan here made startup quadratic for C++ programs with large symbol
     * tables (LLVM/Clang can have tens of thousands of versioned fixups). */
    if (obj->gnu_hash) {
        struct gnu_hash_view view;
        uint32_t gh = gnu_hash_calc(name);
        uint64_t word;
        uint64_t mask;
        uint32_t idx;

        if (!get_gnu_hash_view(obj, &view))
            return NULL;

        word = view.bloom[(gh / 64) % view.bloom_size];
        mask = (1ULL << (gh % 64)) |
               (1ULL << ((gh >> view.bloom_shift) % 64));
        if ((word & mask) != mask)
            return NULL;

        idx = view.buckets[gh % view.nbuckets];
        if (idx < view.symoffset || idx >= obj->dynsym_count)
            return NULL;

        while (idx < obj->dynsym_count) {
            uint32_t ch;

            if (!gnu_hash_chain_value(obj, &view, idx, &ch))
                return NULL;
            if ((ch | 1) == (gh | 1)) {
                const Elf64_Sym *sym = loaded_dynsym(obj, idx);

                if (sym && sym->st_shndx != SHN_UNDEF &&
                    ELF64_ST_BIND(sym->st_info) != STB_LOCAL &&
                    symbol_visible_outside_object(sym) &&
                    loaded_symbol_name_eq(obj, sym, name)) {
                    const char *candidate_version = NULL;

                    if (symbol_version_name(obj, idx,
                                            &candidate_version) == 1 &&
                        strcmp(candidate_version, version) == 0)
                        return sym;
                }
            }
            if (ch & 1)
                break;
            idx++;
        }
        return NULL;
    }

    if (obj->sysv_hash) {
        struct sysv_hash_view view;
        uint32_t hash = sysv_hash_calc(name);
        uint32_t idx;

        if (!get_sysv_hash_view(obj, &view))
            return NULL;
        idx = view.buckets[hash % view.nbuckets];
        for (uint32_t steps = 0; idx != STN_UNDEF && steps < view.nchain;
             steps++) {
            const Elf64_Sym *sym;

            if (idx >= view.nchain || idx >= obj->dynsym_count)
                return NULL;
            sym = loaded_dynsym(obj, idx);
            if (!sym)
                return NULL;
            if (sym->st_shndx != SHN_UNDEF &&
                ELF64_ST_BIND(sym->st_info) != STB_LOCAL &&
                symbol_visible_outside_object(sym) &&
                loaded_symbol_name_eq(obj, sym, name)) {
                const char *candidate_version = NULL;

                if (symbol_version_name(obj, idx,
                                        &candidate_version) == 1 &&
                    strcmp(candidate_version, version) == 0)
                    return sym;
            }
            idx = view.chains[idx];
        }
        return NULL;
    }

    for (uint32_t i = 1; i < obj->dynsym_count; i++) {
        const Elf64_Sym *sym = loaded_dynsym(obj, i);
        const char *candidate_version = NULL;

        if (!sym)
            return NULL;
        if (sym->st_shndx == SHN_UNDEF ||
            ELF64_ST_BIND(sym->st_info) == STB_LOCAL ||
            !symbol_visible_outside_object(sym) ||
            !loaded_symbol_name_eq(obj, sym, name))
            continue;
        if (symbol_version_name(obj, i, &candidate_version) == 1 &&
            strcmp(candidate_version, version) == 0)
            return sym;
    }
    return NULL;
}

static const Elf64_Sym *lookup_relocation_definition(
        struct loaded_obj *requester, uint32_t sym_index,
        struct loaded_obj *objs, int nobj, int skip_requester,
        struct loaded_obj **owner_out)
{
    const Elf64_Sym *reference;
    const char *name;
    const char *version;
    uint32_t gh;
    int versioned;

    if (!requester->dynsym || !requester->dynstr ||
        sym_index == 0 || sym_index >= requester->dynsym_count)
        return NULL;
    reference = loaded_dynsym(requester, sym_index);
    if (!reference)
        return NULL;

    name = loaded_symbol_name(requester, reference);
    if (!name)
        return NULL;
    gh = gnu_hash_calc(name);
    versioned = relocation_symbol_version(requester, sym_index, &version);
    if (versioned < 0)
        return NULL;

    /* Hidden/internal definitions never leave their object, and protected
     * definitions are visible to others but cannot be preempted inside the
     * defining object.  COPY relocations deliberately skip requester
     * storage and must still locate the source definition. */
    if (!skip_requester && symbol_must_bind_locally(reference)) {
        if (owner_out)
            *owner_out = requester;
        return reference;
    }

    if (objs == g_all_objs && g_global_scope_count != 0) {
        uint8_t searched[MAX_TOTAL_OBJS];
        int requester_index;
        struct loaded_obj *root;

        if (!dl_object_table_index(requester, nobj, &requester_index) ||
            !requester->relocation_scope_root_valid ||
            requester->relocation_scope_root >= nobj)
            return NULL;
        (void)requester_index;
        memset(searched, 0, sizeof(searched));

        /* Preserve the loader's historical flattened global visibility:
         * startup objects and previously committed dlopen groups precede
         * the current transaction's breadth-first dependency scope. */
        for (uint16_t s = 0; s < g_global_scope_count; s++) {
            uint16_t index = g_global_scope_indices[s];
            const Elf64_Sym *candidate;

            if (index >= nobj)
                return NULL;
            searched[index] = 1;
            if (skip_requester && &objs[index] == requester)
                continue;
            candidate = versioned
                ? lookup_versioned_symbol(&objs[index], name, version)
                : lookup_object_symbol(&objs[index], name, gh);
            if (candidate) {
                if (owner_out)
                    *owner_out = &objs[index];
                return candidate;
            }
        }

        root = &g_all_objs[requester->relocation_scope_root];
        if (!root->lookup_scope_valid &&
            dl_build_lookup_scope(root, nobj) < 0)
            return NULL;
        for (uint16_t s = 0; s < root->lookup_scope_count; s++) {
            uint16_t index = root->lookup_scope_indices[s];
            const Elf64_Sym *candidate;

            if (index >= nobj)
                return NULL;
            if (searched[index])
                continue;
            searched[index] = 1;
            if (skip_requester && &objs[index] == requester)
                continue;
            candidate = versioned
                ? lookup_versioned_symbol(&objs[index], name, version)
                : lookup_object_symbol(&objs[index], name, gh);
            if (candidate) {
                if (owner_out)
                    *owner_out = &objs[index];
                return candidate;
            }
        }
        return NULL;
    }

    /* Bootstrap/unit-test fallback before the global graph is initialized. */
    for (int i = 0; i < nobj; i++) {
        const Elf64_Sym *candidate;

        if (skip_requester && &objs[i] == requester)
            continue;
        candidate = versioned
            ? lookup_versioned_symbol(&objs[i], name, version)
            : lookup_object_symbol(&objs[i], name, gh);
        if (candidate) {
            if (owner_out)
                *owner_out = &objs[i];
            return candidate;
        }
    }
    return NULL;
}

static uint64_t lookup_elf_symbol_addr(const struct loaded_obj *obj,
                                       const char *name)
{
    const Elf64_Ehdr *ehdr;
    const Elf64_Shdr *shdrs;

    if (!obj->elf || obj->elf_size < sizeof(*ehdr))
        return 0;

    ehdr = (const Elf64_Ehdr *)obj->elf;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr->e_shoff == 0 || ehdr->e_shnum == 0 ||
        ehdr->e_shentsize < sizeof(Elf64_Shdr))
        return 0;
    if (ehdr->e_shoff > obj->elf_size ||
        (uint64_t)ehdr->e_shnum * ehdr->e_shentsize >
            obj->elf_size - ehdr->e_shoff)
        return 0;

    shdrs = (const Elf64_Shdr *)(obj->elf + ehdr->e_shoff);
    for (uint16_t si = 0; si < ehdr->e_shnum; si++) {
        const Elf64_Shdr *sym_sh = &shdrs[si];
        const Elf64_Shdr *str_sh;
        const Elf64_Sym *syms;
        const char *strtab;
        size_t sym_count;

        if (sym_sh->sh_type != SHT_SYMTAB && sym_sh->sh_type != SHT_DYNSYM)
            continue;
        if (sym_sh->sh_entsize < sizeof(Elf64_Sym) ||
            sym_sh->sh_link >= ehdr->e_shnum)
            continue;
        str_sh = &shdrs[sym_sh->sh_link];
        if (sym_sh->sh_offset > obj->elf_size ||
            sym_sh->sh_size > obj->elf_size - sym_sh->sh_offset ||
            str_sh->sh_offset > obj->elf_size ||
            str_sh->sh_size > obj->elf_size - str_sh->sh_offset)
            continue;

        syms = (const Elf64_Sym *)(obj->elf + sym_sh->sh_offset);
        strtab = (const char *)(obj->elf + str_sh->sh_offset);
        sym_count = sym_sh->sh_size / sym_sh->sh_entsize;
        for (size_t i = 1; i < sym_count; i++) {
            const Elf64_Sym *sym = (const Elf64_Sym *)((const uint8_t *)syms +
                                  i * sym_sh->sh_entsize);
            unsigned type = ELF64_ST_TYPE(sym->st_info);

            if (sym->st_shndx == SHN_UNDEF || sym->st_name == 0)
                continue;
            if (type == STT_SECTION || type == STT_FILE)
                continue;
            if (!elf_strtab_name_eq(strtab, str_sh->sh_size, sym->st_name, name))
                continue;
            return obj->base + sym->st_value;
        }
    }
    return 0;
}

/* ---- dlopen override ------------------------------------------------- */

/* Forward declarations for dlopen replacements */
static void *my_dlopen(const char *path, int flags);
static void *my_dlmopen(long lmid, const char *path, int flags);
static void *my_dlsym(void *handle, const char *symbol);
static void *my_dlvsym(void *handle, const char *symbol, const char *version);
static int   my_dlclose(void *handle);
static char *my_dlerror(void);
static int   my_dladdr(const void *address, Dl_info *info);
static int   my_dl_iterate_phdr(
                 int (*callback)(struct dl_phdr_info *, size_t, void *),
                 void *data);

static void *bootstrap_memcpy(void *dst, const void *src, size_t len)
{
    return memcpy(dst, src, len);
}

static void *bootstrap_memmove(void *dst, const void *src, size_t len)
{
    return memmove(dst, src, len);
}

static void *bootstrap_memset(void *dst, int value, size_t len)
{
    return memset(dst, value, len);
}

static int bootstrap_memcmp(const void *lhs, const void *rhs, size_t len)
{
    return memcmp(lhs, rhs, len);
}

static int bootstrap_strcmp(const char *lhs, const char *rhs)
{
    return strcmp(lhs, rhs);
}

/* Override table — these symbols take priority over libc's exports
 * so that dlopen/dlsym/dlclose/dlerror go through our implementation
 * which can load .so files from the filesystem at runtime. */
static const struct stub_sym g_overrides[] = {
    { "dlopen",          (void *)my_dlopen          },
    { "dlmopen",         (void *)my_dlmopen         },
    { "dlsym",           (void *)my_dlsym           },
    { "dlvsym",          (void *)my_dlvsym          },
    { "dlclose",         (void *)my_dlclose         },
    { "dlerror",         (void *)my_dlerror         },
    { "dladdr",          (void *)my_dladdr          },
    { "dl_iterate_phdr", (void *)my_dl_iterate_phdr },
    { "__tls_get_addr",  (void *)stub_tls_get_addr  },
    { "memcpy",          (void *)bootstrap_memcpy   },
    { "memmove",         (void *)bootstrap_memmove  },
    { "memset",          (void *)bootstrap_memset   },
    { "memcmp",          (void *)bootstrap_memcmp   },
    { "strcmp",          (void *)bootstrap_strcmp   },
    { NULL, NULL }
};

/* VFS overrides — only activated when -f embeds data files into the binary.
 * Intercept file open/stat operations to serve embedded data files. */
static const struct stub_sym g_vfs_overrides[] = {
    { "open",            (void *)vfs_open           },
    { "open64",          (void *)vfs_open           },
    { "openat",          (void *)vfs_openat         },
    { "openat64",        (void *)vfs_openat         },
    { "__open64_2",      (void *)vfs_open           },
    { "realpath",        (void *)vfs_realpath       },
    { "stat",            (void *)vfs_stat           },
    { "stat64",          (void *)vfs_stat           },
    { "lstat",           (void *)vfs_lstat          },
    { "lstat64",         (void *)vfs_lstat          },
    { "__xstat",         (void *)vfs_xstat          },
    { "__xstat64",       (void *)vfs_xstat          },
    { "__lxstat",        (void *)vfs_lxstat         },
    { "__lxstat64",      (void *)vfs_lxstat         },
    { "fstatat",         (void *)vfs_fstatat        },
    { "fstatat64",       (void *)vfs_fstatat        },
    { "newfstatat",      (void *)vfs_fstatat        },
    { "__fxstatat",      (void *)vfs_fxstatat       },
    { "__fxstatat64",    (void *)vfs_fxstatat       },
    { "access",          (void *)vfs_access         },
    { "faccessat",       (void *)vfs_faccessat      },
    { "opendir",         (void *)vfs_opendir        },
    { "fdopendir",       (void *)vfs_fdopendir      },
    { "dirfd",           (void *)vfs_dirfd          },
    { "readdir",         (void *)vfs_readdir        },
    { "readdir64",       (void *)vfs_readdir        },
    { "rewinddir",       (void *)vfs_rewinddir      },
    { "telldir",         (void *)vfs_telldir        },
    { "seekdir",         (void *)vfs_seekdir        },
    { "closedir",        (void *)vfs_closedir       },
    { "fopen",           (void *)vfs_fopen          },
    { "fopen64",         (void *)vfs_fopen          },
    { "readlink",        (void *)vfs_readlink       },
    { "readlinkat",      (void *)vfs_readlinkat     },
    { NULL, NULL }
};

static uint64_t lookup_override(const char *name)
{
    for (const struct stub_sym *o = g_overrides; o->name; o++)
        if (strcmp(name, o->name) == 0)
            return (uint64_t)(uintptr_t)o->addr;
    if (g_vfs_count > 0) {
        for (const struct stub_sym *o = g_vfs_overrides; o->name; o++)
            if (strcmp(name, o->name) == 0)
                return (uint64_t)(uintptr_t)o->addr;
    }
    return 0;
}

/* ---- build_special_table / lookup_special implementations ------------- */

static void build_special_table(void)
{
    if (g_special_tab_ready) return;
    memset(g_special_tab, 0, sizeof(g_special_tab));

    #define SPEC_INSERT(n, a) do { \
        uint32_t _h = gnu_hash_calc(n); \
        uint32_t _i = _h & (SPECIAL_TAB_SIZE - 1); \
        while (g_special_tab[_i].used) _i = (_i + 1) & (SPECIAL_TAB_SIZE - 1); \
        g_special_tab[_i].hash = _h; \
        g_special_tab[_i].name = (n); \
        g_special_tab[_i].addr = (uint64_t)(uintptr_t)(a); \
        g_special_tab[_i].used = 1; \
    } while (0)

    for (const struct stub_sym *o = g_overrides; o->name; o++)
        SPEC_INSERT(o->name, o->addr);
    if (g_vfs_count > 0) {
        for (const struct stub_sym *o = g_vfs_overrides; o->name; o++)
            SPEC_INSERT(o->name, o->addr);
    }
    for (const struct stub_sym *s = g_stubs; s->name; s++)
        SPEC_INSERT(s->name, s->addr);
    if (g_fake_rtld_global)
        SPEC_INSERT("_rtld_global", g_fake_rtld_global);
    if (g_fake_rtld_global_ro)
        SPEC_INSERT("_rtld_global_ro", g_fake_rtld_global_ro);
    SPEC_INSERT("__libc_stack_end", &g_fake_libc_stack_end);
    SPEC_INSERT("__libc_enable_secure", &g_fake_libc_enable_secure);
    SPEC_INSERT("_dl_argv", &g_fake_dl_argv);
    SPEC_INSERT("__stack_chk_guard", &g_fake_stack_chk_guard);
    SPEC_INSERT("__pointer_chk_guard", &g_fake_pointer_chk_guard);
    SPEC_INSERT("__rseq_offset", &g_rseq_offset);
    SPEC_INSERT("__rseq_size",   &g_rseq_size);
    SPEC_INSERT("__rseq_flags",  &g_rseq_flags);
    SPEC_INSERT("signal",        vfs_signal);
    SPEC_INSERT("sigaction",     vfs_sigaction);
    SPEC_INSERT("__sigaction",   vfs_sigaction);
    #undef SPEC_INSERT

    g_special_tab_ready = 1;
}

static uint64_t lookup_special(const char *name, uint32_t gh)
{
    uint32_t idx = gh & (SPECIAL_TAB_SIZE - 1);
    for (uint32_t n = 0; n < SPECIAL_TAB_SIZE; n++) {
        if (!g_special_tab[idx].used) return 0;
        if (g_special_tab[idx].hash == gh &&
            strcmp(g_special_tab[idx].name, name) == 0)
            return g_special_tab[idx].addr;
        idx = (idx + 1) & (SPECIAL_TAB_SIZE - 1);
    }
    return 0;
}

enum relocation_special_provider {
    SPECIAL_PROVIDER_SCOPE,
    SPECIAL_PROVIDER_INTERP,
    SPECIAL_PROVIDER_GLIBC_PRIVATE
};

/* Loader-owned implementations must not turn a forged symbol version into a
 * successful binding.  Keep the provider-less interpreter ABI explicit;
 * every other public shim has to be backed by a real object in the normal
 * relocation scope. */
static enum relocation_special_provider
relocation_special_provider(const char *name)
{
    if (strcmp(name, "__tls_get_addr") == 0 ||
        strcmp(name, "__libc_stack_end") == 0 ||
        strcmp(name, "__stack_chk_guard") == 0 ||
        strcmp(name, "__pointer_chk_guard") == 0 ||
        strcmp(name, "__rseq_offset") == 0 ||
        strcmp(name, "__rseq_size") == 0 ||
        strcmp(name, "__rseq_flags") == 0)
        return SPECIAL_PROVIDER_INTERP;

    if (strcmp(name, "__tunable_get_val") == 0 ||
        strcmp(name, "__tunable_is_initialized") == 0 ||
        strcmp(name, "_dl_find_dso_for_object") == 0 ||
        strcmp(name, "_dl_exception_create") == 0 ||
        strcmp(name, "_dl_exception_create_format") == 0 ||
        strcmp(name, "_dl_exception_free") == 0 ||
        strcmp(name, "_dl_fatal_printf") == 0 ||
        strcmp(name, "_dl_signal_error") == 0 ||
        strcmp(name, "_dl_signal_exception") == 0 ||
        strcmp(name, "_dl_catch_exception") == 0 ||
        strcmp(name, "_dl_audit_symbind_alt") == 0 ||
        strcmp(name, "_dl_audit_preinit") == 0 ||
        strcmp(name, "_dl_get_tls_static_info") == 0 ||
        strcmp(name, "_dl_allocate_tls") == 0 ||
        strcmp(name, "_dl_allocate_tls_init") == 0 ||
        strcmp(name, "_dl_deallocate_tls") == 0 ||
        strcmp(name, "_dl_rtld_di_serinfo") == 0 ||
        strcmp(name, "__nptl_change_stack_perm") == 0 ||
        strcmp(name, "_rtld_global") == 0 ||
        strcmp(name, "_rtld_global_ro") == 0 ||
        strcmp(name, "__libc_enable_secure") == 0 ||
        strcmp(name, "_dl_argv") == 0)
        return SPECIAL_PROVIDER_GLIBC_PRIVATE;

    return SPECIAL_PROVIDER_SCOPE;
}

static int frozen_dynstr_equal(const char *dynstr, size_t dynstr_size,
                               uint32_t offset, const char *expected)
{
    size_t length;

    if (!expected || (size_t)offset >= dynstr_size)
        return 0;
    length = strlen(expected);
    return length < dynstr_size - (size_t)offset &&
           memcmp(dynstr + offset, expected, length) == 0 &&
           dynstr[offset + length] == '\0';
}

/* Prove an interpreter-owned version against the actual frozen interpreter.
 * The interpreter is intentionally not mapped into the normal lookup scope,
 * so its bounded on-disk dynamic metadata is the provider catalog. */
static int frozen_interp_exports_version(const char *name,
                                         const char *version)
{
    const uint8_t *elf;
    const Elf64_Ehdr *ehdr;
    const Elf64_Phdr *phdrs;
    const Elf64_Dyn *dynamic = NULL;
    size_t elf_size;
    size_t dynamic_count = 0;
    uint64_t symtab_vaddr = 0, strtab_vaddr = 0, versym_vaddr = 0;
    uint64_t verdef_vaddr = 0, hash_vaddr = 0, gnu_hash_vaddr = 0;
    uint64_t symtab_foff, strtab_foff, versym_foff, verdef_foff;
    size_t strtab_size = 0;
    uint32_t verdef_count = 0, symbol_count = 0;
    const Elf64_Sym *symbols;
    const uint16_t *versym;
    const char *dynstr;
    int interp_index = -1;

    if (!name || !version || !g_frozen_mem || !g_frozen_entries ||
        !g_frozen_metas)
        return 0;
    for (uint32_t i = 0; i < g_frozen_num_entries; i++) {
        if (g_frozen_metas[i].flags & LDR_FLAG_INTERP) {
            interp_index = (int)i;
            break;
        }
    }
    if (interp_index < 0 ||
        g_frozen_entries[interp_index].data_offset < g_frozen_mem_foff ||
        g_frozen_entries[interp_index].data_size > SIZE_MAX)
        return 0;
    elf = g_frozen_mem +
        (g_frozen_entries[interp_index].data_offset - g_frozen_mem_foff);
    elf_size = (size_t)g_frozen_entries[interp_index].data_size;
    if (elf_size < sizeof(Elf64_Ehdr))
        return 0;
    ehdr = (const Elf64_Ehdr *)elf;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
        ehdr->e_version != EV_CURRENT ||
        ehdr->e_phentsize != sizeof(Elf64_Phdr) ||
        ehdr->e_phoff > elf_size ||
        ehdr->e_phnum > (elf_size - (size_t)ehdr->e_phoff) /
                         sizeof(Elf64_Phdr))
        return 0;
    phdrs = (const Elf64_Phdr *)(elf + ehdr->e_phoff);
    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type != PT_DYNAMIC)
            continue;
        if (phdrs[i].p_offset > elf_size ||
            phdrs[i].p_filesz > elf_size - (size_t)phdrs[i].p_offset)
            return 0;
        dynamic = (const Elf64_Dyn *)(elf + phdrs[i].p_offset);
        dynamic_count = (size_t)phdrs[i].p_filesz / sizeof(Elf64_Dyn);
        break;
    }
    if (!dynamic)
        return 0;
    for (size_t i = 0; i < dynamic_count; i++) {
        if (dynamic[i].d_tag == DT_NULL)
            break;
        switch (dynamic[i].d_tag) {
        case DT_SYMTAB: symtab_vaddr = dynamic[i].d_un.d_ptr; break;
        case DT_SYMENT:
            if (dynamic[i].d_un.d_val != sizeof(Elf64_Sym)) return 0;
            break;
        case DT_STRTAB: strtab_vaddr = dynamic[i].d_un.d_ptr; break;
        case DT_STRSZ:
            if (dynamic[i].d_un.d_val > SIZE_MAX) return 0;
            strtab_size = (size_t)dynamic[i].d_un.d_val;
            break;
        case DT_VERSYM: versym_vaddr = dynamic[i].d_un.d_ptr; break;
        case DT_VERDEF: verdef_vaddr = dynamic[i].d_un.d_ptr; break;
        case DT_VERDEFNUM:
            if (dynamic[i].d_un.d_val > UINT32_MAX) return 0;
            verdef_count = (uint32_t)dynamic[i].d_un.d_val;
            break;
        case DT_HASH: hash_vaddr = dynamic[i].d_un.d_ptr; break;
        case DT_GNU_HASH: gnu_hash_vaddr = dynamic[i].d_un.d_ptr; break;
        }
    }
    if (!symtab_vaddr || !strtab_vaddr || !strtab_size || !versym_vaddr ||
        !verdef_vaddr || !verdef_count)
        return 0;
    symtab_foff = elf_vaddr_to_foff(elf, ehdr, symtab_vaddr);
    strtab_foff = elf_vaddr_to_foff(elf, ehdr, strtab_vaddr);
    versym_foff = elf_vaddr_to_foff(elf, ehdr, versym_vaddr);
    verdef_foff = elf_vaddr_to_foff(elf, ehdr, verdef_vaddr);
    if (symtab_foff == (uint64_t)-1 || strtab_foff == (uint64_t)-1 ||
        versym_foff == (uint64_t)-1 || verdef_foff == (uint64_t)-1 ||
        strtab_foff > elf_size || strtab_size > elf_size - strtab_foff ||
        symtab_foff > elf_size || versym_foff > elf_size ||
        verdef_foff > elf_size)
        return 0;
    if (hash_vaddr) {
        uint64_t hash_foff = elf_vaddr_to_foff(elf, ehdr, hash_vaddr);
        if (hash_foff == (uint64_t)-1 || hash_foff > elf_size ||
            elf_size - hash_foff < 2 * sizeof(uint32_t))
            return 0;
        symbol_count = ((const uint32_t *)(elf + hash_foff))[1];
    } else if (gnu_hash_vaddr) {
        symbol_count = elf_gnu_hash_symbol_count(elf, ehdr, elf_size,
                                                  gnu_hash_vaddr);
    }
    if (!symbol_count ||
        symbol_count > (elf_size - symtab_foff) / sizeof(Elf64_Sym) ||
        symbol_count > (elf_size - versym_foff) / sizeof(uint16_t))
        return 0;
    symbols = (const Elf64_Sym *)(elf + symtab_foff);
    versym = (const uint16_t *)(elf + versym_foff);
    dynstr = (const char *)(elf + strtab_foff);

    for (uint32_t i = 1; i < symbol_count; i++) {
        uint16_t version_index;
        uint64_t cursor = verdef_foff;

        if (symbols[i].st_shndx == SHN_UNDEF ||
            ELF64_ST_BIND(symbols[i].st_info) == STB_LOCAL ||
            !symbol_visible_outside_object(&symbols[i]) ||
            !frozen_dynstr_equal(dynstr, strtab_size,
                                 symbols[i].st_name, name))
            continue;
        version_index = versym[i] & 0x7fff;
        if (version_index <= 1)
            continue;
        for (uint32_t n = 0; n < verdef_count; n++) {
            const Elf64_Verdef *definition;
            uint64_t aux_offset;
            const Elf64_Verdaux *aux;

            if (cursor > elf_size ||
                elf_size - cursor < sizeof(Elf64_Verdef))
                return 0;
            definition = (const Elf64_Verdef *)(elf + cursor);
            if (definition->vd_version != VER_DEF_CURRENT ||
                !u64_add_checked(cursor, definition->vd_aux, &aux_offset) ||
                aux_offset > elf_size ||
                elf_size - aux_offset < sizeof(Elf64_Verdaux))
                return 0;
            aux = (const Elf64_Verdaux *)(elf + aux_offset);
            if ((definition->vd_ndx & 0x7fff) == version_index) {
                if (frozen_dynstr_equal(dynstr, strtab_size,
                                        aux->vda_name, version))
                    return 1;
                break;
            }
            if (definition->vd_next == 0)
                break;
            if (!u64_add_checked(cursor, definition->vd_next, &cursor))
                return 0;
        }
    }
    return 0;
}

static uint64_t raw_relocation_special(const char *name, uint32_t gh)
{
    uint64_t address;

    if (g_special_tab_ready)
        return lookup_special(name, gh);
    address = lookup_override(name);
    if (!address)
        address = lookup_stub(name);
    if (!address)
        address = lookup_fake_object(name);
    return address;
}

static uint64_t lookup_relocation_special(struct loaded_obj *requester,
                                          uint32_t sym_index,
                                          struct loaded_obj *objs, int nobj)
{
    const Elf64_Sym *reference;
    const char *name;
    const char *version = NULL;
    enum relocation_special_provider provider;
    uint64_t address;
    int versioned;

    if (!requester || !requester->dynsym || sym_index == 0 ||
        sym_index >= requester->dynsym_count)
        return 0;
    reference = loaded_dynsym(requester, sym_index);
    if (!reference || !(name = loaded_symbol_name(requester, reference)))
        return 0;
    address = raw_relocation_special(name, gnu_hash_calc(name));
    if (!address)
        return 0;
    versioned = relocation_symbol_version(requester, sym_index, &version);
    if (versioned < 0)
        return 0;
    provider = relocation_special_provider(name);

    /* Unversioned public/interpreter contracts are required by musl and by
     * older runtimes.  Private glibc contracts are never unversioned. */
    if (!versioned)
        return provider == SPECIAL_PROVIDER_GLIBC_PRIVATE ? 0 : address;
    if (!version)
        return 0;
    if (provider == SPECIAL_PROVIDER_SCOPE)
        return lookup_relocation_definition(requester, sym_index, objs, nobj,
                                             0, NULL) ? address : 0;
    if (provider == SPECIAL_PROVIDER_GLIBC_PRIVATE &&
        strcmp(version, "GLIBC_PRIVATE") != 0)
        return 0;
    if (lookup_relocation_definition(requester, sym_index, objs, nobj,
                                     0, NULL))
        return address;
    return frozen_interp_exports_version(name, version) ? address : 0;
}

/* Apply the same provider/version admission policy to dlsym and dlvsym.
 * `scope_provider_visible` means the API's selected lookup scope already
 * produced a real definition with the requested name/version.  Interpreter
 * contracts are proved against the frozen interpreter because it is not in
 * g_all_objs. */
static uint64_t lookup_api_special(const char *name, const char *version,
                                   int scope_provider_visible)
{
    enum relocation_special_provider provider;
    uint64_t address;

    if (!name)
        return 0;
    address = raw_relocation_special(name, gnu_hash_calc(name));
    if (!address)
        return 0;
    provider = relocation_special_provider(name);

    if (!version) {
        if (provider == SPECIAL_PROVIDER_GLIBC_PRIVATE)
            return 0;
        if (provider == SPECIAL_PROVIDER_SCOPE && !scope_provider_visible)
            return 0;
        return address;
    }
    if (provider == SPECIAL_PROVIDER_SCOPE)
        return scope_provider_visible ? address : 0;
    if (provider == SPECIAL_PROVIDER_GLIBC_PRIVATE &&
        strcmp(version, "GLIBC_PRIVATE") != 0)
        return 0;
    return (scope_provider_visible ||
            frozen_interp_exports_version(name, version)) ? address : 0;
}

/*
 * Global symbol search — exe first, then libs in load order.
 * Returns resolved virtual address or 0.
 */
static int dl_build_global_lookup_order(int nobj,
                                        uint16_t *order,
                                        uint16_t *count_out)
{
    uint8_t seen[MAX_TOTAL_OBJS];
    uint16_t count = 0;

    *count_out = 0;
    if (nobj < 0 || nobj > MAX_TOTAL_OBJS)
        return -1;
    if (g_global_scope_count == 0)
        return 0;
    memset(seen, 0, sizeof(seen));
    for (uint16_t i = 0; i < g_global_scope_count; i++) {
        uint16_t index = g_global_scope_indices[i];

        if (index >= nobj)
            return -1;
        if (!seen[index]) {
            seen[index] = 1;
            order[count++] = index;
        }
    }
    if (g_dl_transaction.active &&
        g_dl_transaction.scope_root_valid) {
        struct loaded_obj *root;

        if (g_dl_transaction.scope_root < 0 ||
            g_dl_transaction.scope_root >= nobj)
            return -1;
        root = &g_all_objs[g_dl_transaction.scope_root];
        if (!root->lookup_scope_valid &&
            dl_build_lookup_scope(root, nobj) < 0)
            return -1;
        for (uint16_t i = 0; i < root->lookup_scope_count; i++) {
            uint16_t index = root->lookup_scope_indices[i];

            if (index >= nobj)
                return -1;
            if (!seen[index]) {
                seen[index] = 1;
                order[count++] = index;
            }
        }
    }
    *count_out = count;
    return 1;
}

static int resolve_sym_address(struct loaded_obj *objs, int nobj,
                               const char *name, uint64_t *address_out)
{
    uint32_t gh = gnu_hash_calc(name);
    uint16_t order[MAX_TOTAL_OBJS];
    uint16_t order_count = 0;
    int scoped_order;

    uint64_t cached = 0;
    int c = sym_cache_lookup(name, gh, &cached);
    if (c == 1) {
        *address_out = cached;
        return 1;
    }
    if (c == -1)
        return 0;

    /* The interpreter is not represented in the ordinary object scope, so
     * admit only its provider-less contracts before searching real objects.
     * Public loader shims are admitted below only after their provider has
     * actually been found in the selected scope. */
    {
        uint64_t ovr = lookup_api_special(name, NULL, 0);

        if (ovr) {
            *address_out = ovr;
            return 1;
        }
    }

    scoped_order = objs == g_all_objs
        ? dl_build_global_lookup_order(nobj, order, &order_count) : 0;
    if (scoped_order < 0)
        return 0;
    for (int position = 0;
         position < (scoped_order ? (int)order_count : nobj);
         position++) {
        int i = scoped_order ? order[position] : position;
        const Elf64_Sym *sym = lookup_object_symbol(&objs[i], name, gh);
        if (sym) {
            const char *canonical_name;
            uint64_t special;
            uint64_t addr;
            int cacheable;

            special = lookup_api_special(name, NULL, 1);
            if (special) {
                *address_out = special;
                return 1;
            }
            if (!resolve_defined_symbol_address(&objs[i], sym, &addr,
                                                &cacheable))
                continue;
            canonical_name = loaded_symbol_name(&objs[i], sym);
            if (cacheable && canonical_name)
                sym_cache_store_canonical(canonical_name, gh,
                                          CACHE_FOUND, addr);
            *address_out = addr;
            return 1;
        }
    }
    return 0;
}

static uint64_t resolve_sym(struct loaded_obj *objs, int nobj,
                            const char *name)
{
    uint64_t address = 0;

    (void)resolve_sym_address(objs, nobj, name, &address);
    return address;
}

static int resolve_relocation_symbol(struct loaded_obj *requester,
                                     uint32_t sym_index,
                                     struct loaded_obj *objs, int nobj,
                                     uint64_t *address_out)
{
    const char *name;
    const Elf64_Sym *reference;
    const Elf64_Sym *sym;
    struct loaded_obj *owner = NULL;
    uint64_t addr;

    if (!requester->dynsym || !requester->dynstr ||
        sym_index == 0 || sym_index >= requester->dynsym_count)
        return 0;
    reference = loaded_dynsym(requester, sym_index);
    if (!reference)
        return 0;
    name = loaded_symbol_name(requester, reference);
    if (!name)
        return 0;
    /* A requester-local hidden/internal/protected definition wins even when
     * its name is also implemented by a loader override. */
    if (symbol_must_bind_locally(reference))
        return resolve_defined_symbol_address(requester, reference,
                                              address_out, NULL);

    addr = lookup_relocation_special(requester, sym_index, objs, nobj);
    if (addr) {
        *address_out = addr;
        return 1;
    }

    sym = lookup_relocation_definition(requester, sym_index, objs, nobj, 0,
                                       &owner);
    if (!sym || !owner ||
        !resolve_defined_symbol_address(owner, sym, &addr, NULL))
        return 0;
    *address_out = addr;
    return 1;
}

enum relocation_pass {
    RELOC_PASS_ORDINARY = 0,
    RELOC_PASS_COPY,
    RELOC_PASS_IFUNC,
    RELOC_PASS_IRELATIVE
};

/* Classify a symbolic relocation without invoking its resolver.  This must
 * mirror resolve_relocation_symbol's override precedence: a loader-provided
 * ABI shim suppresses an underlying ELF IFUNC definition. */
static int relocation_symbol_is_ifunc(struct loaded_obj *requester,
                                      uint32_t sym_index,
                                      struct loaded_obj *objs, int nobj)
{
    const Elf64_Sym *reference;
    const Elf64_Sym *definition;
    struct loaded_obj *owner = NULL;
    const char *name;
    uint64_t special;

    if (!requester->dynsym || !requester->dynstr || sym_index == 0 ||
        sym_index >= requester->dynsym_count)
        return 0;
    reference = loaded_dynsym(requester, sym_index);
    if (!reference)
        return 0;
    name = loaded_symbol_name(requester, reference);
    if (!name)
        return 0;
    if (symbol_must_bind_locally(reference))
        return ELF64_ST_TYPE(reference->st_info) == STT_GNU_IFUNC;

    special = lookup_relocation_special(requester, sym_index, objs, nobj);
    if (special)
        return 0;

    definition = lookup_relocation_definition(
        requester, sym_index, objs, nobj, 0, &owner);
    return definition && owner &&
           ELF64_ST_TYPE(definition->st_info) == STT_GNU_IFUNC;
}

#if defined(__aarch64__) || defined(__x86_64__)
static int resolve_tlsdesc_target(struct loaded_obj *obj,
                                  struct loaded_obj *all, int nobj,
                                  uint32_t sidx, int64_t addend,
                                  size_t *modid_out,
                                  uint64_t *offset_out,
                                  int64_t *tprel_out,
                                  int *have_tprel_out)
{
    struct loaded_obj *owner = obj;
    const Elf64_Sym *sym = NULL;
    const Elf64_Sym *reference = NULL;

    if (sidx != 0 && sidx < obj->dynsym_count)
        reference = &obj->dynsym[sidx];

    /* sidx == 0 means STN_UNDEF / local-DSO reference: the TLSDESC addend is
     * a direct offset into the object's own TLS block.  Use a synthetic
     * zero-offset symbol so the owner remains `obj`. */
    if (sidx == 0) {
        uint64_t offset;

        if (obj->tls.memsz == 0 || obj->tls.modid == 0)
            return -1;
        if (!u64_add_i64_checked(0, addend, &offset) ||
            offset > obj->tls.memsz)
            return -1;
        *modid_out = obj->tls.modid;
        *offset_out = offset;
        if (obj->tls.tpoff != 0) {
            if (!i64_add_u64_checked(obj->tls.tpoff, offset, tprel_out))
                return -1;
            *have_tprel_out = 1;
        } else {
            *tprel_out = 0;
            *have_tprel_out = 0;
        }
        return 0;
    }

    sym = lookup_relocation_definition(obj, sidx, all, nobj, 0, &owner);

    if (!sym || sym->st_shndx == SHN_UNDEF) {
        if (reference && ELF64_ST_BIND(reference->st_info) == STB_WEAK) {
            *modid_out = 0;
            *offset_out = 0;
            *tprel_out = 0;
            *have_tprel_out = 1;
            return 0;
        }
        return -1;
    }

    if (owner->tls.memsz == 0 || owner->tls.modid == 0)
        return -1;

    *modid_out = owner->tls.modid;
    if (!u64_add_i64_checked(sym->st_value, addend, offset_out) ||
        *offset_out > owner->tls.memsz)
        return -1;
    if (owner->tls.tpoff != 0) {
        if (!i64_add_u64_checked(owner->tls.tpoff, *offset_out,
                                 tprel_out))
            return -1;
        *have_tprel_out = 1;
    } else {
        *tprel_out = 0;
        *have_tprel_out = 0;
    }

    return 0;
}

#if defined(__aarch64__)
static int apply_aarch64_tlsdesc_reloc(struct loaded_obj *obj,
                                       struct loaded_obj *all, int nobj,
                                       const Elf64_Rela *rel)
{
    size_t modid;
    uint64_t offset;
    int64_t tprel;
    int have_tprel;
    uint64_t *slot = (uint64_t *)(obj->base + rel->r_offset);

    if (resolve_tlsdesc_target(obj, all, nobj,
                               ELF64_R_SYM(rel->r_info),
                               rel->r_addend,
                               &modid, &offset,
                               &tprel, &have_tprel) < 0) {
        ldr_err("unresolved TLSDESC symbol", obj->name);
        return -1;
    }

    if (have_tprel) {
        slot[0] = (uint64_t)(uintptr_t)dlfreeze_aarch64_tlsdesc_static;
        slot[1] = (uint64_t)tprel;
        return 0;
    }

    {
        struct aarch64_tlsdesc_arg *arg = alloc_aarch64_tlsdesc_arg();

        if (!arg)
            return -1;

        arg->modid = modid;
        arg->offset = offset;

        slot[0] = (uint64_t)(uintptr_t)dlfreeze_aarch64_tlsdesc_dynamic;
        slot[1] = (uint64_t)(uintptr_t)arg;
    }

    return 0;
}
#endif

#if defined(__x86_64__)
static int apply_x86_64_tlsdesc_reloc(struct loaded_obj *obj,
                                      struct loaded_obj *all, int nobj,
                                      const Elf64_Rela *rel)
{
    size_t modid;
    uint64_t offset;
    int64_t tprel;
    int have_tprel;
    uint64_t *slot = (uint64_t *)(obj->base + rel->r_offset);

    if (resolve_tlsdesc_target(obj, all, nobj,
                               ELF64_R_SYM(rel->r_info),
                               rel->r_addend,
                               &modid, &offset,
                               &tprel, &have_tprel) < 0) {
        ldr_err("unresolved TLSDESC symbol", obj->name);
        return -1;
    }

    if (have_tprel) {
        slot[0] = (uint64_t)(uintptr_t)dlfreeze_x86_64_tlsdesc_static;
        slot[1] = (uint64_t)tprel;
        return 0;
    }

    {
        struct x86_64_tlsdesc_arg *arg = alloc_x86_64_tlsdesc_arg();
        if (!arg)
            return -1;
        arg->modid = modid;
        arg->offset = offset;
        slot[0] = (uint64_t)(uintptr_t)dlfreeze_x86_64_tlsdesc_dynamic;
        slot[1] = (uint64_t)(uintptr_t)arg;
    }

    return 0;
}
#endif
#endif /* __aarch64__ || __x86_64__ */

static int validate_relocation_record(struct loaded_obj *obj,
                                      const Elf64_Rela *rel,
                                      const Elf64_Sym **reference_out,
                                      const char **name_out,
                                      void **slot_out)
{
    uint32_t type = ELF64_R_TYPE(rel->r_info);
    uint32_t sidx = ELF64_R_SYM(rel->r_info);
    const Elf64_Sym *reference = NULL;
    const char *name = NULL;
    size_t width = sizeof(uint64_t);
    void *slot = NULL;

    if (sidx != 0) {
        reference = loaded_dynsym(obj, sidx);
        if (!reference)
            return -1;
        name = loaded_symbol_name(obj, reference);
        if (!name)
            return -1;
    }

    if ((type == ARCH_RELOC_RELATIVE || type == ARCH_RELOC_IRELATIVE) &&
        sidx != 0)
        return -1;

    if (type == 0) {
        width = 0;
    } else if (type == ARCH_RELOC_COPY) {
        if (!reference || reference->st_size > SIZE_MAX)
            return -1;
        width = (size_t)reference->st_size;
    } else if (type == ARCH_RELOC_TLSDESC) {
        width = 2 * sizeof(uint64_t);
    }

    if (width != 0 &&
        !loaded_obj_vaddr_pointer(obj, rel->r_offset, width, PF_W, &slot))
        return -1;

    if (type == ARCH_RELOC_IRELATIVE) {
        void *resolver;

        if (!loaded_obj_signed_offset_pointer(obj, rel->r_addend, 1, PF_X,
                                              &resolver))
            return -1;
    }

    if (reference_out)
        *reference_out = reference;
    if (name_out)
        *name_out = name;
    if (slot_out)
        *slot_out = slot;
    return 0;
}

static int relocation_destination_overlaps_tls(
    const struct loaded_obj *obj, uint64_t offset, size_t size)
{
    uint64_t relocation_end;

    if (!obj || size == 0)
        return 0;
    if (!u64_add_checked(offset, size, &relocation_end))
        return 1;
    if (obj->tls.memsz != 0) {
        uint64_t tls_end;

        if (!u64_add_checked(obj->tls.vaddr, obj->tls.memsz, &tls_end))
            return 1;
        return offset < tls_end && obj->tls.vaddr < relocation_end;
    }
    /* Initial-load preflight runs before setup_tls() populates obj->tls, but
     * the mapped program headers are already available. */
    for (uint16_t i = 0; obj->phdr && i < obj->phdr_num; i++) {
        const Elf64_Phdr *ph = &obj->phdr[i];
        uint64_t tls_end;

        if (ph->p_type != PT_TLS || ph->p_memsz == 0)
            continue;
        if (!u64_add_checked(ph->p_vaddr, ph->p_memsz, &tls_end))
            return 1;
        if (offset < tls_end && ph->p_vaddr < relocation_end)
            return 1;
    }
    return 0;
}

/* Reject structurally unsupported resolver destinations before any target
 * resolver in the graph can run.  In particular, reporting this only from
 * the IFUNC/IRELATIVE pass is too late for dlopen: an earlier resolver may
 * already have made externally visible changes that transaction rollback
 * cannot undo. */
static int preflight_resolver_relocation_destinations(
    struct loaded_obj *targets, int ntargets,
    struct loaded_obj *scope, int nscope)
{
    for (int oi = 0; oi < ntargets; oi++) {
        struct loaded_obj *obj = &targets[oi];
        const Elf64_Rela *tables[] = { obj->rela, obj->jmprel };
        size_t counts[] = { obj->rela_count, obj->jmprel_count };

        for (size_t t = 0; t < sizeof(tables) / sizeof(tables[0]); t++) {
            for (size_t i = 0; i < counts[t]; i++) {
                const Elf64_Rela *rel = &tables[t][i];
                uint32_t type = ELF64_R_TYPE(rel->r_info);
                uint32_t sidx = ELF64_R_SYM(rel->r_info);
                int invokes_resolver = type == ARCH_RELOC_IRELATIVE;

                if (!invokes_resolver &&
                    (type == ARCH_RELOC_ABS ||
                     type == ARCH_RELOC_GLOB_DAT ||
                     type == ARCH_RELOC_JUMP_SLOT)) {
                    invokes_resolver = relocation_symbol_is_ifunc(
                        obj, sidx, scope, nscope);
                }
                if (!invokes_resolver)
                    continue;
                if (validate_relocation_record(obj, rel, NULL, NULL, NULL) < 0)
                    return -1;
                if (relocation_destination_overlaps_tls(
                        obj, rel->r_offset, sizeof(uint64_t))) {
                    ldr_err("IFUNC relocation into PT_TLS is unsupported in",
                            obj->name);
                    return -1;
                }
            }
        }
    }
    return 0;
}

static int apply_copy_relocation(struct loaded_obj *obj,
                                 struct loaded_obj *objs, int nobj,
                                 const Elf64_Rela *rel,
                                 const Elf64_Sym *reference,
                                 const char *name)
{
    struct loaded_obj *owner = NULL;
    const Elf64_Sym *definition;
    void *destination;
    void *source;
    size_t destination_size;
    size_t source_size;
    size_t copy_size;

    if (!reference || reference->st_size > SIZE_MAX)
        return -1;
    destination_size = (size_t)reference->st_size;
    if (destination_size != 0 &&
        !loaded_obj_vaddr_pointer(obj, rel->r_offset, destination_size, PF_W,
                                  &destination)) {
        ldr_err("COPY relocation destination is outside PT_LOAD in",
                obj->name);
        return -1;
    }

    definition = lookup_relocation_definition(obj,
        ELF64_R_SYM(rel->r_info), objs, nobj, 1, &owner);
    if (!definition || !owner) {
        const void *fake_source;

        if (name && lookup_relocation_special(
                        obj, ELF64_R_SYM(rel->r_info), objs, nobj) &&
            lookup_fake_object_region(name, &fake_source, &source_size)) {
            copy_size = destination_size < source_size
                ? destination_size : source_size;
            if (copy_size != 0)
                memcpy(destination, fake_source, copy_size);
            return 0;
        }
        if (ELF64_ST_BIND(reference->st_info) != STB_WEAK) {
            ldr_err("unresolved COPY symbol", name ? name : obj->name);
            return -1;
        }
        return 0;
    }

    copy_size = destination_size;
    if (definition->st_size < copy_size)
        copy_size = (size_t)definition->st_size;
    if (copy_size == 0)
        return 0;
    if (!loaded_obj_vaddr_pointer(owner, definition->st_value, copy_size, 0,
                                  &source)) {
        ldr_err("COPY relocation source is outside PT_LOAD in", owner->name);
        return -1;
    }
    memcpy(destination, source, copy_size);
    return 0;
}

static int apply_prelinked_runtime_reloc(struct loaded_obj *obj,
                                         struct loaded_obj *objs, int nobj,
                                         const Elf64_Rela *rel,
                                         enum relocation_pass pass)
{
    uint64_t base = obj->base;
    uint32_t type = ELF64_R_TYPE(rel->r_info);
    uint32_t sidx = ELF64_R_SYM(rel->r_info);
    const Elf64_Sym *reference;
    const char *symbol_name;
    void *relocation_slot;
    int symbolic_ifunc;

    if (validate_relocation_record(obj, rel, &reference, &symbol_name,
                                   &relocation_slot) < 0) {
        ldr_err("malformed relocation in", obj->name);
        return -1;
    }

    if (type == ARCH_RELOC_IRELATIVE) {
        typedef uint64_t (*ifunc_t)(void);
        ifunc_t resolver;

        if (pass != RELOC_PASS_IRELATIVE)
            return 0;
        if (relocation_destination_overlaps_tls(
                obj, rel->r_offset, sizeof(uint64_t))) {
            ldr_err("IFUNC relocation into PT_TLS is unsupported in",
                    obj->name);
            return -1;
        }
        resolver = (ifunc_t)(base + rel->r_addend);
        *(uint64_t *)relocation_slot = resolver();
        return 0;
    }

    if (type == ARCH_RELOC_COPY) {
        if (pass != RELOC_PASS_COPY)
            return 0;
        if (g_debug) {
            ldr_msg("COPY reloc: ");
            ldr_msg(symbol_name);
            ldr_msg("\n");
        }
        return apply_copy_relocation(obj, objs, nobj, rel, reference,
                                     symbol_name);
    }

    if (pass != RELOC_PASS_ORDINARY && pass != RELOC_PASS_IFUNC)
        return 0;
    symbolic_ifunc =
        (type == ARCH_RELOC_ABS || type == ARCH_RELOC_GLOB_DAT ||
         type == ARCH_RELOC_JUMP_SLOT) &&
        relocation_symbol_is_ifunc(obj, sidx, objs, nobj);
    if ((pass == RELOC_PASS_IFUNC) != symbolic_ifunc)
        return 0;
    if (symbolic_ifunc && relocation_destination_overlaps_tls(
            obj, rel->r_offset, sizeof(uint64_t))) {
        ldr_err("IFUNC relocation into PT_TLS is unsupported in",
                obj->name);
        return -1;
    }

#if defined(__aarch64__)
    if (type == ARCH_RELOC_TLSDESC) {
        return apply_aarch64_tlsdesc_reloc(obj, objs, nobj, rel);
    }
#endif
#if defined(__x86_64__)
    if (type == ARCH_RELOC_TLSDESC) {
        return apply_x86_64_tlsdesc_reloc(obj, objs, nobj, rel);
    }
#endif

    if (type == ARCH_RELOC_ABS) {
        if (sidx == 0)
            return 0;

        {
            uint64_t addr = 0;
            int resolved = resolve_relocation_symbol(
                obj, sidx, objs, nobj, &addr);

            if (!resolved && ELF64_ST_BIND(reference->st_info) != STB_WEAK) {
                ldr_err("unresolved relocation symbol", symbol_name);
                return -1;
            }

            *(uint64_t *)relocation_slot = addr + rel->r_addend;
        }
        return 0;
    }

    if (type == ARCH_RELOC_TPOFF) {
        uint64_t *slot = (uint64_t *)relocation_slot;
        int64_t value = 0;

        if (g_debug) {
            ldr_msg("[loader] runtime TLS TPOFF: ");
            ldr_msg(obj->name);
            ldr_dbg_hex(" off=0x", rel->r_offset);
        }

        if (sidx != 0) {
            const char *name = symbol_name;
            struct loaded_obj *owner = NULL;
            const Elf64_Sym *definition = lookup_relocation_definition(
                obj, sidx, objs, nobj, 0, &owner);

            if (definition && owner) {
                if (!tls_tpoff_value(&owner->tls, definition->st_value,
                                     rel->r_addend, &value)) {
                    ldr_err("TLS TPOFF relocation overflows in", obj->name);
                    return -1;
                }
            } else if (ELF64_ST_BIND(reference->st_info) != STB_WEAK) {
                ldr_err("unresolved TLS symbol", name);
                return -1;
            } else
                value = rel->r_addend;
        } else {
            if (!tls_tpoff_value(&obj->tls, 0, rel->r_addend, &value)) {
                ldr_err("TLS TPOFF relocation overflows in", obj->name);
                return -1;
            }
        }

        *(int64_t *)slot = value;
        if (g_debug) {
            ldr_dbg_hex("  addend=0x", (uint64_t)rel->r_addend);
            ldr_dbg_hex("  value=0x", (uint64_t)value);
        }
        return 0;
    }

    if (type == ARCH_RELOC_DTPMOD) {
        uint64_t *slot = (uint64_t *)relocation_slot;

        if (g_debug) {
            ldr_msg("[loader] runtime TLS DTPMOD: ");
            ldr_msg(obj->name);
            ldr_dbg_hex(" off=0x", rel->r_offset);
        }

        if (sidx != 0) {
            struct loaded_obj *owner = NULL;
            const Elf64_Sym *definition = lookup_relocation_definition(
                obj, sidx, objs, nobj, 0, &owner);

            if (definition && owner && owner->tls.modid) {
                *slot = owner->tls.modid;
            } else if (ELF64_ST_BIND(reference->st_info) != STB_WEAK) {
                ldr_err("unresolved TLS module symbol", symbol_name);
                return -1;
            } else {
                *slot = 0;
            }
        } else {
            *slot = obj->tls.modid ? obj->tls.modid : 1;
        }
        return 0;
    }

    if (type == ARCH_RELOC_DTPOFF) {
        uint64_t *slot = (uint64_t *)relocation_slot;

        if (g_debug) {
            ldr_msg("[loader] runtime TLS DTPOFF: ");
            ldr_msg(obj->name);
            ldr_dbg_hex(" off=0x", rel->r_offset);
        }

        if (sidx != 0) {
            uint64_t off = reference->st_value;
            struct loaded_obj *owner = obj;

            if (reference->st_shndx == 0) {
                const Elf64_Sym *definition = lookup_relocation_definition(
                    obj, sidx, objs, nobj, 0, &owner);

                if (definition)
                    off = definition->st_value;
                else if (ELF64_ST_BIND(reference->st_info) != STB_WEAK) {
                    ldr_err("unresolved TLS offset symbol", symbol_name);
                    return -1;
                } else {
                    *slot = 0;
                    return 0;
                }
            }
            if (!tls_dtpoff_value(&owner->tls, off, rel->r_addend, slot)) {
                ldr_err("TLS DTPOFF relocation overflows in", obj->name);
                return -1;
            }
        } else {
            if (!tls_dtpoff_value(&obj->tls, 0, rel->r_addend, slot)) {
                ldr_err("TLS DTPOFF relocation overflows in", obj->name);
                return -1;
            }
        }
        return 0;
    }

    if (type == 0) /* R_X86_64_NONE / R_AARCH64_NONE */
        return 0;

    if (type != ARCH_RELOC_GLOB_DAT &&
        type != ARCH_RELOC_JUMP_SLOT) {
        ldr_err("unsupported pre-linked relocation in", obj->name);
        ldr_hex("dlfreeze-loader: relocation type ", type);
        return -1;
    }

    if (sidx == 0)
        return 0;

    uint64_t *slot = (uint64_t *)relocation_slot;
    const char *required_version = NULL;
    int versioned = relocation_symbol_version(obj, sidx, &required_version);

    if (versioned < 0) {
        if (g_debug) {
            const Elf64_Sym *reference = loaded_dynsym(obj, sidx);
            uint16_t raw_version = 0;

            ldr_dbg_hex("[loader] malformed version symbol index=0x", sidx);
            if (reference) {
                const char *name = loaded_symbol_name(obj, reference);

                if (name) {
                    ldr_msg("[loader] malformed version symbol name=");
                    ldr_msg(name);
                    ldr_msg("\n");
                }
                ldr_dbg_hex("[loader] malformed version shndx=0x",
                            reference->st_shndx);
            }
            if (loaded_versym_value(obj, sidx, &raw_version))
                ldr_dbg_hex("[loader] malformed version index=0x",
                            raw_version);
            ldr_dbg_hex("[loader] verdef count=0x", obj->verdef_count);
            ldr_dbg_hex("[loader] verneed count=0x", obj->verneed_count);
        }
        ldr_err("malformed symbol version metadata in", obj->name);
        return -1;
    }
    {
        const char *name = symbol_name;
        uint64_t addr = 0;
        int resolved = resolve_relocation_symbol(
            obj, sidx, objs, nobj, &addr);

        if (resolved) {
            *slot = addr;
        } else if (ELF64_ST_BIND(reference->st_info) != STB_WEAK) {
            ldr_err("unresolved relocation symbol", name);
            return -1;
        }
    }
    return 0;
}

/* Fallback pass for pre-linked objects: ensure runtime override symbols
 * like dlopen/dlsym/__tls_get_addr are patched even if the packer's
 * runtime-fixup table omitted a relocation. Keep this narrowly focused
 * on override names so the hot prelinked path still avoids a full
 * generic relocation re-scan. */
static int apply_prelinked_override_fallbacks(struct loaded_obj *obj,
                                               struct loaded_obj *objs,
                                               int nobj)
{
    const Elf64_Rela *tabs[] = { obj->rela, obj->jmprel };
    size_t counts[] = { obj->rela_count, obj->jmprel_count };

    for (int t = 0; t < 2; t++) {
        for (size_t i = 0; i < counts[t]; i++) {
            const Elf64_Rela *rel = &tabs[t][i];
            uint32_t type = ELF64_R_TYPE(rel->r_info);
            uint32_t sidx;
            const char *name;
            uint64_t ovr;
            uint64_t *slot;
            const Elf64_Sym *reference;
            void *relocation_slot;

            if (type != ARCH_RELOC_GLOB_DAT &&
                type != ARCH_RELOC_JUMP_SLOT)
                continue;

            sidx = ELF64_R_SYM(rel->r_info);
            if (sidx == 0)
                continue;

            if (validate_relocation_record(obj, rel, &reference, &name,
                                           &relocation_slot) < 0)
                return -1;
            if (symbol_must_bind_locally(reference))
                continue;
            ovr = lookup_relocation_special(obj, sidx, objs, nobj);
            if (!ovr)
                continue;

            slot = (uint64_t *)relocation_slot;
            if (*slot != ovr) {
                if (g_debug) {
                    ldr_msg("GOT fallback patch: ");
                    ldr_msg(name);
                    ldr_msg(" in ");
                    ldr_msg(obj->name);
                    ldr_msg("\n");
                }
                *slot = ovr;
            }
        }
    }
    return 0;
}

/* ==== Map one object's PT_LOAD segments ================================ */

/*
 * Reserve virtual address ranges for all objects.  When all objects share
 * a high base address (PIE/DSOs only), a single contiguous reservation
 * suffices.  When a non-PIE executable is present (base_addr=0, mapped at
 * its original link address), the range is split into two reservations so
 * the bootstrap binary in between is not disturbed.
 */
static int reserve_address_range(const struct dlfrz_lib_meta *metas,
                                  const int *idx_map, int nobj,
                                  _Bool memcpy_mode)
{
    /* Partition objects into native-address (base_addr=0, non-PIE exe)
     * and relocated (base_addr>0, DSOs + PIE executables). */
    uint64_t nat_lo = UINT64_MAX, nat_hi = 0;
    uint64_t rel_lo = UINT64_MAX, rel_hi = 0;
    for (int i = 0; i < nobj; i++) {
        int mi = idx_map[i];
        uint64_t lo = metas[mi].base_addr + page_floor(metas[mi].vaddr_lo);
        uint64_t hi = metas[mi].base_addr +
                      ALIGN_UP(metas[mi].vaddr_hi, g_page_size);
        if (metas[mi].base_addr == 0) {
            if (lo < nat_lo) nat_lo = lo;
            if (hi > nat_hi) nat_hi = hi;
        } else {
            if (lo < rel_lo) rel_lo = lo;
            if (hi > rel_hi) rel_hi = hi;
        }
    }

    /* Reserve collisions without making holes or trailing guard pages
     * accessible.  Individual PT_LOAD pages are enabled by map_object(). */
    int res_prot = PROT_NONE;
    (void)memcpy_mode;

    if (nat_lo < nat_hi) {
        nat_hi += 4 * g_page_size;
        void *m = mmap((void *)nat_lo, nat_hi - nat_lo, res_prot,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                       -1, 0);
        if (m == MAP_FAILED) return -1;
    }
    if (rel_lo < rel_hi) {
        rel_hi += 4 * g_page_size;
        void *m = mmap((void *)rel_lo, rel_hi - rel_lo, res_prot,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                       -1, 0);
        if (m == MAP_FAILED) return -1;
    }
    if (nat_lo >= nat_hi && rel_lo >= rel_hi) return -1;
    return 0;
}

static int phdr_prot(const Elf64_Phdr *ph)
{
    int prot = 0;

    if (ph->p_flags & PF_R) prot |= PROT_READ;
    if (ph->p_flags & PF_W) prot |= PROT_WRITE;
    if (ph->p_flags & PF_X) prot |= PROT_EXEC;
    return prot;
}

static int loaded_obj_pages_covered(const struct loaded_obj *obj,
                                    uint64_t range_start,
                                    uint64_t range_end,
                                    uint32_t required_flags)
{
    uint64_t cursor = range_start;

    if (range_start >= range_end ||
        (range_start & (g_page_size - 1)) != 0 ||
        (range_end & (g_page_size - 1)) != 0)
        return 0;

    while (cursor < range_end) {
        uint64_t covered_end = cursor;

        for (uint16_t i = 0; i < obj->phdr_num; i++) {
            const Elf64_Phdr *ph = &obj->phdr[i];
            uint64_t raw_start, raw_end, load_start, load_end;

            if (ph->p_type != PT_LOAD || ph->p_memsz == 0 ||
                (ph->p_flags & required_flags) != required_flags ||
                !u64_add_checked(obj->base, ph->p_vaddr, &raw_start) ||
                !u64_add_checked(raw_start, ph->p_memsz, &raw_end) ||
                !u64_align_up_checked(raw_end, g_page_size, &load_end))
                continue;
            load_start = page_floor(raw_start);
            if (load_start <= cursor && load_end > covered_end)
                covered_end = load_end;
        }
        if (covered_end == cursor)
            return 0;
        cursor = covered_end < range_end ? covered_end : range_end;
    }
    return 1;
}

static int set_segment_protection(uint64_t base, const Elf64_Phdr *ph,
                                  int prot)
{
    uint64_t start = page_floor(base + ph->p_vaddr);
    uint64_t end = ALIGN_UP(base + ph->p_vaddr + ph->p_memsz, g_page_size);

    if (end <= start)
        return 0;
    return mprotect((void *)(uintptr_t)start, end - start, prot);
}

static int make_file_range_writable(uint64_t base, const Elf64_Phdr *ph)
{
    uint64_t start = page_floor(base + ph->p_vaddr);
    uint64_t end = ALIGN_UP(base + ph->p_vaddr + ph->p_filesz, g_page_size);

    if (end <= start)
        return 0;
    return mprotect((void *)(uintptr_t)start, end - start,
                    PROT_READ | PROT_WRITE);
}

static int zero_segment_bss_tail(uint64_t base, const Elf64_Phdr *ph)
{
    if (ph->p_memsz <= ph->p_filesz || ph->p_filesz == 0)
        return 0;

    uint64_t zero_off = ph->p_vaddr + ph->p_filesz;
    uint64_t zero_end = ALIGN_UP(zero_off, g_page_size);
    uint64_t seg_end = ph->p_vaddr + ph->p_memsz;

    if (zero_end > seg_end)
        zero_end = seg_end;
    if (zero_end > zero_off) {
        uint64_t page = page_floor(base + zero_off);
        uint64_t page_end = ALIGN_UP(base + zero_end, g_page_size);

        if (mprotect((void *)(uintptr_t)page, page_end - page,
                     PROT_READ | PROT_WRITE) < 0)
            return -1;
        memset((void *)(uintptr_t)(base + zero_off), 0, zero_end - zero_off);
    }
    return 0;
}

static int map_object(const uint8_t *mem, uint64_t mem_foff, int srcfd,
                      const struct dlfrz_lib_meta *meta,
                      const struct dlfrz_entry *ent,
                      struct loaded_obj *obj,
                      _Bool pre_reserved)
{
    uint64_t base = meta->base_addr;
    uint64_t lo   = page_floor(meta->vaddr_lo);
    uint64_t hi   = ALIGN_UP(meta->vaddr_hi, g_page_size);

    if (!pre_reserved) {
        /* Lazy dlopen path — reserve the object's address range now */
        uint64_t span = hi - lo + 4 * g_page_size;
        void *m = mmap((void *)(base + lo), span,
                       PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                       -1, 0);
        if (m == MAP_FAILED)
            return -1;  /* address collision — do not use MAP_FIXED */
        obj->runtime_reservation = m;
        obj->runtime_reservation_size = (size_t)span;
    }

    /* Copy/map each PT_LOAD segment from the payload. */
    const uint8_t *elf_base = mem + (ent->data_offset - mem_foff);
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf_base;
    const uint8_t *phdr_base = elf_base + ehdr->e_phoff;
    for (int i = 0; i < meta->phdr_num; i++) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(phdr_base + i * meta->phdr_entsz);
        if (ph->p_type != PT_LOAD) continue;

        if (ph->p_filesz > 0 && srcfd >= 0 && mem_foff == 0 &&
            (ph->p_vaddr - page_floor(ph->p_vaddr)) ==
                (ph->p_offset - page_floor(ph->p_offset)) &&
            !(g_perf_mode && (meta->flags & LDR_FLAG_MAIN_EXE))) {
            uint64_t seg_page_vaddr = page_floor(ph->p_vaddr);
            uint64_t seg_page_off   = page_floor(ph->p_offset);
            uint64_t page_delta     = ph->p_vaddr - seg_page_vaddr;
            uint64_t map_len        = ALIGN_UP(page_delta + ph->p_filesz,
                                               g_page_size);
            uint64_t file_off       = ent->data_offset + seg_page_off;

            /* Map with correct ELF permissions + PROT_WRITE for
             * writable segments (relocation targets live here).
             * Text/rodata get their final perms immediately. */
            int prot = phdr_prot(ph);

            void *m = mmap((void *)(base + seg_page_vaddr), map_len,
                           prot,
                           MAP_PRIVATE | MAP_FIXED,
                           srcfd, file_off);
            if (m == MAP_FAILED) {
                /* Fallback to memcpy for this segment if file mapping fails. */
                if (make_file_range_writable(base, ph) < 0)
                    return -1;
                memcpy((void *)(base + ph->p_vaddr), elf_base + ph->p_offset,
                       ph->p_filesz);
            }
        } else if (ph->p_filesz > 0) {
            if (make_file_range_writable(base, ph) < 0)
                return -1;
            memcpy((void *)(base + ph->p_vaddr), elf_base + ph->p_offset,
                   ph->p_filesz);
        }
        /* Only clear the partial tail of the last file-backed page. Full
         * .bss pages are already zero from the anonymous reservation. */
        if (zero_segment_bss_tail(base, ph) < 0)
            return -1;
    }

    /* Copied segments were writable while populated.  Restore the ELF
     * segment permissions now so code is executable for IFUNC resolvers,
     * while reserved holes and guard pages remain PROT_NONE. */
    for (int i = 0; i < meta->phdr_num; i++) {
        const Elf64_Phdr *ph =
            (const Elf64_Phdr *)(phdr_base + i * meta->phdr_entsz);

        if (ph->p_type == PT_LOAD &&
            set_segment_protection(base, ph, phdr_prot(ph)) < 0)
            return -1;
    }

    obj->base = base;
    obj->elf = elf_base;
    obj->elf_size = ent->data_size;
    return 0;
}

/* ==== Parse PT_DYNAMIC ================================================= */

static int validate_loaded_verdef(struct loaded_obj *obj)
{
    uintptr_t cursor = (uintptr_t)obj->verdef;

    for (uint32_t i = 0; i < obj->verdef_count; i++) {
        const Elf64_Verdef *def;
        uintptr_t aux_cursor;

        if (!loaded_obj_file_contains(obj, cursor, sizeof(*def)))
            return -1;
        def = (const Elf64_Verdef *)cursor;
        if (def->vd_version != VER_DEF_CURRENT || def->vd_cnt == 0 ||
            def->vd_aux < sizeof(*def) ||
            !mapped_pointer_add(obj, cursor, def->vd_aux,
                                sizeof(Elf64_Verdaux), &aux_cursor) ||
            !loaded_obj_file_contains(obj, aux_cursor,
                                      sizeof(Elf64_Verdaux)))
            return -1;

        for (uint16_t a = 0; a < def->vd_cnt; a++) {
            const Elf64_Verdaux *aux;

            if (!loaded_obj_file_contains(obj, aux_cursor, sizeof(*aux)))
                return -1;
            aux = (const Elf64_Verdaux *)aux_cursor;
            if (!loaded_dynstr_value(obj, aux->vda_name))
                return -1;
            if (a + 1 < def->vd_cnt) {
                if (aux->vda_next < sizeof(*aux) ||
                    !mapped_pointer_add(obj, aux_cursor, aux->vda_next,
                                        sizeof(*aux), &aux_cursor))
                    return -1;
            } else if (aux->vda_next != 0) {
                return -1;
            }
        }

        if (i + 1 < obj->verdef_count) {
            if (def->vd_next < sizeof(*def) ||
                !mapped_pointer_add(obj, cursor, def->vd_next,
                                    sizeof(*def), &cursor))
                return -1;
        } else if (def->vd_next != 0) {
            return -1;
        }
    }
    return 0;
}

static int validate_loaded_verneed(struct loaded_obj *obj)
{
    uintptr_t cursor = (uintptr_t)obj->verneed;

    for (uint32_t i = 0; i < obj->verneed_count; i++) {
        const Elf64_Verneed *need;
        uintptr_t aux_cursor;

        if (!loaded_obj_file_contains(obj, cursor, sizeof(*need)))
            return -1;
        need = (const Elf64_Verneed *)cursor;
        if (need->vn_version != VER_NEED_CURRENT || need->vn_cnt == 0 ||
            !loaded_dynstr_value(obj, need->vn_file) ||
            need->vn_aux < sizeof(*need) ||
            !mapped_pointer_add(obj, cursor, need->vn_aux,
                                sizeof(Elf64_Vernaux), &aux_cursor) ||
            !loaded_obj_file_contains(obj, aux_cursor,
                                      sizeof(Elf64_Vernaux)))
            return -1;

        for (uint16_t a = 0; a < need->vn_cnt; a++) {
            const Elf64_Vernaux *aux;

            if (!loaded_obj_file_contains(obj, aux_cursor, sizeof(*aux)))
                return -1;
            aux = (const Elf64_Vernaux *)aux_cursor;
            if (!loaded_dynstr_value(obj, aux->vna_name))
                return -1;
            if (a + 1 < need->vn_cnt) {
                if (aux->vna_next < sizeof(*aux) ||
                    !mapped_pointer_add(obj, aux_cursor, aux->vna_next,
                                        sizeof(*aux), &aux_cursor))
                    return -1;
            } else if (aux->vna_next != 0) {
                return -1;
            }
        }

        if (i + 1 < obj->verneed_count) {
            if (need->vn_next < sizeof(*need) ||
                !mapped_pointer_add(obj, cursor, need->vn_next,
                                    sizeof(*need), &cursor))
                return -1;
        } else if (need->vn_next != 0) {
            return -1;
        }
    }
    return 0;
}

static int parse_dynamic(struct loaded_obj *obj,
                         const struct dlfrz_lib_meta *meta)
{
    const Elf64_Phdr *dyn_ph = NULL;
    const Elf64_Dyn *dyn;
    size_t dyn_slots;
    void *pointer;
    uint64_t symtab = 0, strtab = 0, strsz = 0, syment = 0;
    uint64_t rela = 0, rela_sz = 0, rela_ent = 0, relacount = 0;
    uint64_t jmprel = 0, pltrelsz = 0, pltrel = 0;
    uint64_t relr = 0, relr_sz = 0, relr_ent = 0;
    uint64_t gnu_hash_addr = 0, sysv_hash_addr = 0;
    uint64_t preinit_array = 0, preinit_array_sz = 0;
    uint64_t init = 0, init_array = 0, init_array_sz = 0;
    uint64_t fini = 0, fini_array = 0, fini_array_sz = 0;
    uint64_t versym_addr = 0;
    uint64_t verdef_addr = 0, verdef_num = 0;
    uint64_t verneed_addr = 0, verneed_num = 0;
    int have_symtab = 0, have_strtab = 0, have_strsz = 0, have_syment = 0;
    int have_rela = 0, have_relasz = 0, have_relaent = 0;
    int have_jmprel = 0, have_pltrelsz = 0, have_pltrel = 0;
    int have_relr = 0, have_relrsz = 0, have_relrent = 0;
    int have_gnu_hash = 0, have_sysv_hash = 0;
    int have_preinit_array = 0, have_preinit_array_sz = 0;
    int have_init_array = 0, have_init_array_sz = 0;
    int have_fini_array = 0, have_fini_array_sz = 0;
    int have_init = 0, have_fini = 0, have_versym = 0;
    int have_verdef = 0, have_verdefnum = 0;
    int have_verneed = 0, have_verneednum = 0;
    int have_relacount = 0;
    int saw_null = 0;

    obj->entry = (meta->flags & LDR_FLAG_MAIN_EXE)
                 ? obj->base + meta->entry : 0;

    for (uint16_t i = 0; i < obj->phdr_num; i++) {
        if (obj->phdr[i].p_type != PT_DYNAMIC)
            continue;
        if (dyn_ph)
            return -1;
        dyn_ph = &obj->phdr[i];
    }
    if (!dyn_ph)
        return 0;
    if (dyn_ph->p_filesz == 0 || dyn_ph->p_filesz > dyn_ph->p_memsz ||
        dyn_ph->p_filesz > SIZE_MAX ||
        dyn_ph->p_filesz % sizeof(Elf64_Dyn) != 0 ||
        !loaded_obj_file_vaddr_pointer(obj, dyn_ph->p_vaddr,
                                       (size_t)dyn_ph->p_filesz, &pointer))
        return -1;

    dyn = (const Elf64_Dyn *)pointer;
    dyn_slots = (size_t)dyn_ph->p_filesz / sizeof(Elf64_Dyn);

#define SET_DYNAMIC_VALUE(seen, storage, value) do { \
        uint64_t _value = (uint64_t)(value); \
        if ((seen) && (storage) != _value) return -1; \
        (seen) = 1; \
        (storage) = _value; \
    } while (0)

    for (size_t i = 0; i < dyn_slots; i++) {
        if (dyn[i].d_tag == DT_NULL) {
            obj->dynamic = dyn;
            obj->dynamic_count = i + 1;
            saw_null = 1;
            break;
        }
        switch (dyn[i].d_tag) {
        case DT_SYMTAB: SET_DYNAMIC_VALUE(have_symtab, symtab, dyn[i].d_un.d_ptr); break;
        case DT_STRTAB: SET_DYNAMIC_VALUE(have_strtab, strtab, dyn[i].d_un.d_ptr); break;
        case DT_STRSZ: SET_DYNAMIC_VALUE(have_strsz, strsz, dyn[i].d_un.d_val); break;
        case DT_SYMENT: SET_DYNAMIC_VALUE(have_syment, syment, dyn[i].d_un.d_val); break;
        case DT_RELA: SET_DYNAMIC_VALUE(have_rela, rela, dyn[i].d_un.d_ptr); break;
        case DT_RELASZ: SET_DYNAMIC_VALUE(have_relasz, rela_sz, dyn[i].d_un.d_val); break;
        case DT_RELAENT: SET_DYNAMIC_VALUE(have_relaent, rela_ent, dyn[i].d_un.d_val); break;
        case DT_JMPREL: SET_DYNAMIC_VALUE(have_jmprel, jmprel, dyn[i].d_un.d_ptr); break;
        case DT_PLTRELSZ: SET_DYNAMIC_VALUE(have_pltrelsz, pltrelsz, dyn[i].d_un.d_val); break;
        case DT_PLTREL: SET_DYNAMIC_VALUE(have_pltrel, pltrel, dyn[i].d_un.d_val); break;
        case DT_GNU_HASH: SET_DYNAMIC_VALUE(have_gnu_hash, gnu_hash_addr, dyn[i].d_un.d_ptr); break;
        case DT_HASH: SET_DYNAMIC_VALUE(have_sysv_hash, sysv_hash_addr, dyn[i].d_un.d_ptr); break;
        case DT_INIT: SET_DYNAMIC_VALUE(have_init, init, dyn[i].d_un.d_ptr); break;
        case DT_INIT_ARRAY: SET_DYNAMIC_VALUE(have_init_array, init_array, dyn[i].d_un.d_ptr); break;
        case DT_INIT_ARRAYSZ: SET_DYNAMIC_VALUE(have_init_array_sz, init_array_sz, dyn[i].d_un.d_val); break;
        case DT_PREINIT_ARRAY: SET_DYNAMIC_VALUE(have_preinit_array, preinit_array, dyn[i].d_un.d_ptr); break;
        case DT_PREINIT_ARRAYSZ: SET_DYNAMIC_VALUE(have_preinit_array_sz, preinit_array_sz, dyn[i].d_un.d_val); break;
        case DT_FINI: SET_DYNAMIC_VALUE(have_fini, fini, dyn[i].d_un.d_ptr); break;
        case DT_FINI_ARRAY: SET_DYNAMIC_VALUE(have_fini_array, fini_array, dyn[i].d_un.d_ptr); break;
        case DT_FINI_ARRAYSZ: SET_DYNAMIC_VALUE(have_fini_array_sz, fini_array_sz, dyn[i].d_un.d_val); break;
        case 36: /* DT_RELR */ SET_DYNAMIC_VALUE(have_relr, relr, dyn[i].d_un.d_ptr); break;
        case 35: /* DT_RELRSZ */ SET_DYNAMIC_VALUE(have_relrsz, relr_sz, dyn[i].d_un.d_val); break;
        case 37: /* DT_RELRENT */ SET_DYNAMIC_VALUE(have_relrent, relr_ent, dyn[i].d_un.d_val); break;
        case DT_VERSYM: SET_DYNAMIC_VALUE(have_versym, versym_addr, dyn[i].d_un.d_ptr); break;
        case DT_VERDEF: SET_DYNAMIC_VALUE(have_verdef, verdef_addr, dyn[i].d_un.d_ptr); break;
        case DT_VERDEFNUM: SET_DYNAMIC_VALUE(have_verdefnum, verdef_num, dyn[i].d_un.d_val); break;
        case DT_VERNEED: SET_DYNAMIC_VALUE(have_verneed, verneed_addr, dyn[i].d_un.d_ptr); break;
        case DT_VERNEEDNUM: SET_DYNAMIC_VALUE(have_verneednum, verneed_num, dyn[i].d_un.d_val); break;
        case DT_RELACOUNT: SET_DYNAMIC_VALUE(have_relacount, relacount, dyn[i].d_un.d_val); break;
        case DT_REL:
        case DT_RELSZ:
        case DT_RELENT:
            /* ELF64 x86-64 and AArch64 use RELA.  Silently treating REL as
             * RELA would reinterpret the table and write arbitrary memory. */
            if (dyn[i].d_un.d_val != 0)
                return -1;
            break;
        }
    }
#undef SET_DYNAMIC_VALUE

    if (!saw_null)
        return -1;

    if (have_strtab != have_symtab || have_strtab != have_strsz ||
        have_symtab != have_syment ||
        (have_symtab && (symtab == 0 || strtab == 0 || strsz == 0 ||
                         syment != sizeof(Elf64_Sym))))
        return -1;
    if ((have_rela || have_relasz) &&
        (!have_rela || !have_relasz || !have_relaent || rela == 0 ||
         rela_ent != sizeof(Elf64_Rela) ||
         rela_sz % sizeof(Elf64_Rela) != 0))
        return -1;
    if (have_relaent && rela_ent != sizeof(Elf64_Rela))
        return -1;
    if ((have_jmprel || have_pltrelsz) &&
        (!have_jmprel || !have_pltrelsz || !have_pltrel || jmprel == 0 ||
         pltrel != DT_RELA || pltrelsz % sizeof(Elf64_Rela) != 0))
        return -1;
    if ((have_relr || have_relrsz) &&
        (!have_relr || !have_relrsz || !have_relrent || relr == 0 ||
         relr_ent != sizeof(Elf64_Relr) ||
         relr_sz % sizeof(Elf64_Relr) != 0))
        return -1;
    if (have_relrent && relr_ent != sizeof(Elf64_Relr))
        return -1;
    if ((have_verdef != have_verdefnum) ||
        (have_verneed != have_verneednum) ||
        verdef_num > UINT32_MAX || verneed_num > UINT32_MAX ||
        (have_gnu_hash && gnu_hash_addr == 0) ||
        (have_sysv_hash && sysv_hash_addr == 0) ||
        (have_versym && versym_addr == 0) ||
        (have_init && init == 0) || (have_fini && fini == 0) ||
        (have_verdef && (verdef_addr == 0 || verdef_num == 0)) ||
        (have_verneed && (verneed_addr == 0 || verneed_num == 0)))
        return -1;

    if (have_strtab) {
        if (strsz > SIZE_MAX ||
            !loaded_obj_file_vaddr_pointer(obj, strtab, (size_t)strsz,
                                           &pointer))
            return -1;
        obj->dynstr = (const char *)pointer;
        obj->dynstr_size = (size_t)strsz;
    }

    /* Relocation symbol indices are a second exact lower bound for dynsym.
     * GNU hash deliberately omits undefined imports on some linkers (notably
     * AArch64 GNU ld), so hash chains alone can under-count the table. */
    if (have_rela) {
        if (rela_sz > SIZE_MAX ||
            !loaded_obj_file_vaddr_pointer(obj, rela, (size_t)rela_sz,
                                           &pointer))
            return -1;
        obj->rela = (const Elf64_Rela *)pointer;
        obj->rela_count = (size_t)rela_sz / sizeof(Elf64_Rela);
    }
    if (relacount > obj->rela_count)
        return -1;
    obj->rela_relative_count = (size_t)relacount;
    for (size_t i = 0; i < obj->rela_relative_count; i++) {
        if (ELF64_R_TYPE(obj->rela[i].r_info) != ARCH_RELOC_RELATIVE ||
            ELF64_R_SYM(obj->rela[i].r_info) != 0)
            return -1;
    }

    if (have_jmprel) {
        if (pltrelsz > SIZE_MAX ||
            !loaded_obj_file_vaddr_pointer(obj, jmprel, (size_t)pltrelsz,
                                           &pointer))
            return -1;
        obj->jmprel = (const Elf64_Rela *)pointer;
        obj->jmprel_count = (size_t)pltrelsz / sizeof(Elf64_Rela);
    }
    {
        const Elf64_Rela *tables[] = { obj->rela, obj->jmprel };
        size_t counts[] = { obj->rela_count, obj->jmprel_count };

        for (size_t t = 0; t < sizeof(tables) / sizeof(tables[0]); t++) {
            for (size_t i = 0; i < counts[t]; i++) {
                uint32_t sidx = ELF64_R_SYM(tables[t][i].r_info);

                if (sidx == UINT32_MAX)
                    return -1;
                if (sidx + 1 > obj->dynsym_count)
                    obj->dynsym_count = sidx + 1;
            }
        }
    }

    if (sysv_hash_addr) {
        struct sysv_hash_view view;
        size_t words;

        if (!loaded_obj_file_vaddr_pointer(obj, sysv_hash_addr,
                                           2 * sizeof(uint32_t), &pointer))
            return -1;
        obj->sysv_hash = (const uint32_t *)pointer;
        if (!get_sysv_hash_view(obj, &view))
            return -1;
        words = 2 + (size_t)view.nbuckets + (size_t)view.nchain;
        if (words > SIZE_MAX / sizeof(uint32_t) ||
            !loaded_obj_file_contains(obj, (uintptr_t)obj->sysv_hash,
                                      words * sizeof(uint32_t)))
            return -1;
        for (uint32_t i = 0; i < view.nbuckets; i++)
            if (view.buckets[i] >= view.nchain &&
                view.buckets[i] != STN_UNDEF)
                return -1;
        for (uint32_t i = 0; i < view.nchain; i++)
            if (view.chains[i] >= view.nchain &&
                view.chains[i] != STN_UNDEF)
                return -1;
        if (view.nchain < obj->dynsym_count)
            return -1;
        obj->dynsym_count = view.nchain;
    }

    if (gnu_hash_addr) {
        struct gnu_hash_view view;
        uint32_t count;
        size_t words64, words32, bytes;

        if (!loaded_obj_file_vaddr_pointer(obj, gnu_hash_addr,
                                           4 * sizeof(uint32_t), &pointer))
            return -1;
        obj->gnu_hash = (const uint32_t *)pointer;
        if (!get_gnu_hash_view(obj, &view))
            return -1;
        count = gnu_hash_symbol_count_loaded(obj);
        if (count == 0 || count < view.symoffset)
            return -1;
        words64 = view.bloom_size;
        words32 = 4 + (size_t)view.nbuckets +
                  (size_t)(count - view.symoffset);
        if (words64 > (SIZE_MAX - words32 * sizeof(uint32_t)) /
                      sizeof(uint64_t))
            return -1;
        bytes = words32 * sizeof(uint32_t) + words64 * sizeof(uint64_t);
        if (!loaded_obj_file_contains(obj, (uintptr_t)obj->gnu_hash, bytes))
            return -1;
        for (uint32_t i = 0; i < view.nbuckets; i++)
            if (view.buckets[i] != STN_UNDEF &&
                (view.buckets[i] < view.symoffset ||
                 view.buckets[i] >= count))
                return -1;
        if (count > obj->dynsym_count)
            obj->dynsym_count = count;
    }

    if (have_symtab) {
        uint64_t span;
        size_t bytes;

        /* When present, an adjacent DT_STRTAB is a useful upper bound.  It
         * can include linker padding, so do not mistake it for the exact
         * symbol count when hashes/relocations already prove what is used. */
        if (strtab > symtab &&
            (strtab - symtab) % sizeof(Elf64_Sym) == 0) {
            span = (strtab - symtab) / sizeof(Elf64_Sym);
            if (span == 0 || span > UINT32_MAX)
                return -1;
            if (!gnu_hash_addr && !sysv_hash_addr)
                obj->dynsym_count = (uint32_t)span;
            else if (obj->dynsym_count > span)
                return -1;
        }
        if (obj->dynsym_count == 0)
            return -1;
        bytes = (size_t)obj->dynsym_count * sizeof(Elf64_Sym);
        if (!loaded_obj_file_vaddr_pointer(obj, symtab, bytes, &pointer))
            return -1;
        obj->dynsym = (const Elf64_Sym *)pointer;
        for (uint32_t i = 0; i < obj->dynsym_count; i++) {
            const Elf64_Sym *sym = loaded_dynsym(obj, i);

            if (!sym || !loaded_symbol_name(obj, sym))
                return -1;
        }
    } else if (gnu_hash_addr || sysv_hash_addr || versym_addr ||
               have_verdef || have_verneed) {
        return -1;
    }

    if (versym_addr) {
        size_t bytes;

        if (!obj->dynsym)
            return -1;
        bytes = (size_t)obj->dynsym_count * sizeof(uint16_t);
        if (!loaded_obj_file_vaddr_pointer(obj, versym_addr, bytes, &pointer))
            return -1;
        obj->versym = (const uint16_t *)pointer;
    }
    if (have_verdef) {
        if (!loaded_obj_file_vaddr_pointer(obj, verdef_addr,
                                           sizeof(Elf64_Verdef), &pointer))
            return -1;
        obj->verdef = (const Elf64_Verdef *)pointer;
        obj->verdef_count = (uint32_t)verdef_num;
        if (validate_loaded_verdef(obj) < 0)
            return -1;
    }
    if (have_verneed) {
        if (!loaded_obj_file_vaddr_pointer(obj, verneed_addr,
                                           sizeof(Elf64_Verneed), &pointer))
            return -1;
        obj->verneed = (const Elf64_Verneed *)pointer;
        obj->verneed_count = (uint32_t)verneed_num;
        if (validate_loaded_verneed(obj) < 0)
            return -1;
    }
    if (obj->versym) {
        for (uint32_t i = 0; i < obj->dynsym_count; i++) {
            const char *version;

            if (symbol_version_name(obj, i, &version) < 0)
                return -1;
        }
    }

    if (have_relr) {
        if (relr_sz > SIZE_MAX ||
            !loaded_obj_file_vaddr_pointer(obj, relr, (size_t)relr_sz,
                                           &pointer))
            return -1;
        obj->relr = (const Elf64_Relr *)pointer;
        obj->relr_count = (size_t)relr_sz / sizeof(Elf64_Relr);
    }

#define SET_DYNAMIC_ARRAY(have_ptr, address, have_size, byte_size, field, count_field) do { \
        if ((have_ptr) != (have_size) || (byte_size) % sizeof(void *) != 0 || \
            ((have_ptr) && ((address) == 0 || (byte_size) > SIZE_MAX || \
             !loaded_obj_vaddr_pointer(obj, (address), (size_t)(byte_size), \
                                       0, &pointer)))) \
            return -1; \
        if (have_ptr) { \
            obj->field = (void (**)(void))pointer; \
            obj->count_field = (size_t)(byte_size) / sizeof(void *); \
        } \
    } while (0)
    SET_DYNAMIC_ARRAY(have_preinit_array, preinit_array,
                      have_preinit_array_sz, preinit_array_sz,
                      preinit_array, preinit_array_sz);
    SET_DYNAMIC_ARRAY(have_init_array, init_array,
                      have_init_array_sz, init_array_sz,
                      init_array, init_array_sz);
    SET_DYNAMIC_ARRAY(have_fini_array, fini_array,
                      have_fini_array_sz, fini_array_sz,
                      fini_array, fini_array_sz);
#undef SET_DYNAMIC_ARRAY

    if (init) {
        if (!loaded_obj_vaddr_pointer(obj, init, 1, PF_X, &pointer))
            return -1;
        obj->init_func = (void (*)(void))pointer;
    }
    if (fini) {
        if (!loaded_obj_vaddr_pointer(obj, fini, 1, PF_X, &pointer))
            return -1;
        obj->fini_func = (void (*)(void))pointer;
    }

    /* Every dynamic string reference that later drives dependency loading
     * must be a complete string inside DT_STRTAB. */
    for (size_t i = 0; i < obj->dynamic_count; i++) {
        switch (obj->dynamic[i].d_tag) {
        case DT_NEEDED:
        case DT_SONAME:
        case DT_RPATH:
        case DT_RUNPATH:
            if (obj->dynamic[i].d_un.d_val > UINT32_MAX ||
                !loaded_dynstr_value(obj,
                    (uint32_t)obj->dynamic[i].d_un.d_val))
                return -1;
            break;
        }
    }
    return 0;
}

/* ==== Apply relocations ================================================ */

/* Ordinary symbol relocations and those resolving IFUNC are deliberately
 * separate graph-wide phases.  This keeps every resolver behind relocation
 * of all TLS templates and other ordinary data. */
static int apply_relocs_rela(struct loaded_obj *obj,
                              const Elf64_Rela *rtab, size_t count,
                              struct loaded_obj *all, int nobj,
                              enum relocation_pass pass)
{
    uint64_t base = obj->base;
    for (size_t i = 0; i < count; i++) {
        const Elf64_Rela *r = &rtab[i];
        uint32_t type  = ELF64_R_TYPE(r->r_info);
        uint32_t sidx  = ELF64_R_SYM(r->r_info);
        const Elf64_Sym *reference;
        const char *symbol_name;
        void *relocation_slot;
        uint64_t *slot;
        int symbolic_ifunc;

        if (validate_relocation_record(obj, r, &reference, &symbol_name,
                                       &relocation_slot) < 0) {
            ldr_err("malformed relocation in", obj->name);
            return -1;
        }
        slot = (uint64_t *)relocation_slot;

        if (type == ARCH_RELOC_IRELATIVE) {
            if (pass != RELOC_PASS_IRELATIVE)
                continue;
            typedef uint64_t (*ifunc_t)(void);
            ifunc_t resolver = (ifunc_t)(base + r->r_addend);
            if (relocation_destination_overlaps_tls(
                    obj, r->r_offset, sizeof(uint64_t))) {
                ldr_err("IFUNC relocation into PT_TLS is unsupported in",
                        obj->name);
                return -1;
            }
            *slot = resolver();
            continue;
        }
        if (type == ARCH_RELOC_COPY) {
            if (pass != RELOC_PASS_COPY)
                continue;

            /* Copy relocations must wait until source DSOs have already
             * applied their own RELATIVE/RELR relocations. */
            if (apply_copy_relocation(obj, all, nobj, r, reference,
                                      symbol_name) < 0)
                return -1;
            continue;
        }
        if (pass != RELOC_PASS_ORDINARY && pass != RELOC_PASS_IFUNC)
            continue;
        symbolic_ifunc =
            (type == ARCH_RELOC_ABS || type == ARCH_RELOC_GLOB_DAT ||
             type == ARCH_RELOC_JUMP_SLOT) &&
            relocation_symbol_is_ifunc(obj, sidx, all, nobj);
        if ((pass == RELOC_PASS_IFUNC) != symbolic_ifunc)
            continue;
        if (symbolic_ifunc && relocation_destination_overlaps_tls(
                obj, r->r_offset, sizeof(uint64_t))) {
            ldr_err("IFUNC relocation into PT_TLS is unsupported in",
                    obj->name);
            return -1;
        }

        switch (type) {
        case 0: /* R_X86_64_NONE / R_AARCH64_NONE */
            break;

        case ARCH_RELOC_RELATIVE:
            *slot = base + r->r_addend;
            break;

        case ARCH_RELOC_GLOB_DAT:
        case ARCH_RELOC_JUMP_SLOT:
        case ARCH_RELOC_ABS: {
            const char *name = symbol_name ? symbol_name : "";
            uint64_t addr = 0;
            int resolved = resolve_relocation_symbol(
                obj, sidx, all, nobj, &addr);
            if (reference && !resolved &&
                ELF64_ST_BIND(reference->st_info) != STB_WEAK) {
                ldr_err("unresolved relocation symbol", name);
                return -1;
            }
            /* GLOB_DAT and JUMP_SLOT: result = S (no addend per ELF ABI).
             * ABS (R_X86_64_64): result = S + A.
             * glibc ≥ 2.39 emits non-zero addends on JUMP_SLOT (lazy PLT
             * stub addresses); adding them corrupts the resolved pointer. */
            if (type == ARCH_RELOC_ABS)
                *slot = addr + r->r_addend;
            else
                *slot = addr;
            break;
        }

        case ARCH_RELOC_TPOFF: {
            if (sidx != 0) {
                const char *name = symbol_name;
                struct loaded_obj *owner = NULL;
                const Elf64_Sym *definition = lookup_relocation_definition(
                    obj, sidx, all, nobj, 0, &owner);

                if (definition && owner) {
                    int64_t value;

                    if (!tls_tpoff_value(&owner->tls,
                                         definition->st_value,
                                         r->r_addend, &value)) {
                        ldr_err("TLS TPOFF relocation overflows in",
                                obj->name);
                        return -1;
                    }
                    *(int64_t *)slot = value;
                } else if (ELF64_ST_BIND(reference->st_info) != STB_WEAK) {
                    ldr_err("unresolved TLS symbol", name);
                    return -1;
                } else {
                    *(int64_t *)slot = r->r_addend;
                }
            } else {
                int64_t value;

                if (!tls_tpoff_value(&obj->tls, 0, r->r_addend, &value)) {
                    ldr_err("TLS TPOFF relocation overflows in", obj->name);
                    return -1;
                }
                *(int64_t *)slot = value;
            }
            break;
        }

        case ARCH_RELOC_DTPMOD:
            /* Module ID — for GD/LD TLS model.  Use the correct module ID
             * so __tls_get_addr indexes the right DTV slot. */
            if (sidx != 0) {
                /* Find the defining object's module ID */
                struct loaded_obj *owner = NULL;
                const Elf64_Sym *definition = lookup_relocation_definition(
                    obj, sidx, all, nobj, 0, &owner);

                if (definition && owner && owner->tls.modid) {
                    *slot = owner->tls.modid;
                } else if (ELF64_ST_BIND(reference->st_info) != STB_WEAK) {
                    ldr_err("unresolved TLS module symbol", symbol_name);
                    return -1;
                } else {
                    *slot = 0;
                }
            } else {
                *slot = obj->tls.modid ? obj->tls.modid : 1;
            }
            break;

        case ARCH_RELOC_DTPOFF:
            if (sidx != 0) {
                /* If the symbol is undefined locally (imported), look it
                 * up in the defining library to get the correct TLS offset. */
                uint64_t off = reference->st_value;
                struct loaded_obj *owner = obj;
                if (reference->st_shndx == 0) {
                    const Elf64_Sym *definition = lookup_relocation_definition(
                        obj, sidx, all, nobj, 0, &owner);

                    if (definition)
                        off = definition->st_value;
                    else if (ELF64_ST_BIND(reference->st_info) != STB_WEAK) {
                        ldr_err("unresolved TLS offset symbol", symbol_name);
                        return -1;
                    } else {
                        *slot = 0;
                        break;
                    }
                }
                if (!tls_dtpoff_value(&owner->tls, off, r->r_addend,
                                      slot)) {
                    ldr_err("TLS DTPOFF relocation overflows in", obj->name);
                    return -1;
                }
            } else if (!tls_dtpoff_value(&obj->tls, 0, r->r_addend,
                                         slot)) {
                ldr_err("TLS DTPOFF relocation overflows in", obj->name);
                return -1;
            }
            break;

#if defined(__aarch64__)
        case ARCH_RELOC_TLSDESC:
            if (apply_aarch64_tlsdesc_reloc(obj, all, nobj, r) < 0)
                return -1;
            break;
#endif
#if defined(__x86_64__)
        case ARCH_RELOC_TLSDESC:
            if (apply_x86_64_tlsdesc_reloc(obj, all, nobj, r) < 0)
                return -1;
            break;
#endif

        default:
            ldr_err("unsupported relocation in", obj->name);
            ldr_hex("dlfreeze-loader: relocation type ", type);
            return -1;
        }
    }
    return 0;
}

static int walk_relr(struct loaded_obj *obj, int apply)
{
    uint64_t where_offset = 0;
    int have_where = 0;

    if (!obj->relr || obj->relr_count == 0)
        return 0;
    uint64_t base = obj->base;

    for (size_t i = 0; i < obj->relr_count; i++) {
        Elf64_Relr entry = obj->relr[i];
        if ((entry & 1) == 0) {
            uint64_t *where;

            if (!loaded_obj_vaddr_pointer(obj, entry, sizeof(*where), PF_W,
                                          (void **)&where))
                return -1;
            if (apply)
                *where += base;
            if (entry > UINT64_MAX - sizeof(*where))
                return -1;
            where_offset = entry + sizeof(*where);
            have_where = 1;
        } else {
            uint64_t bitmap = entry >> 1;

            if (!have_where)
                return -1;
            for (unsigned int j = 0; bitmap; j++, bitmap >>= 1) {
                uint64_t offset;
                uint64_t *where;

                if (!(bitmap & 1))
                    continue;
                if (where_offset > UINT64_MAX -
                                   (uint64_t)j * sizeof(*where))
                    return -1;
                offset = where_offset + (uint64_t)j * sizeof(*where);
                if (!loaded_obj_vaddr_pointer(obj, offset, sizeof(*where),
                                              PF_W,
                                              (void **)&where))
                    return -1;
                if (apply)
                    *where += base;
            }
            if (where_offset > UINT64_MAX - 63 * sizeof(uint64_t))
                return -1;
            where_offset += 63 * sizeof(uint64_t);
        }
    }
    return 0;
}

static int validate_object_relocations(struct loaded_obj *obj)
{
    const Elf64_Rela *tables[] = { obj->rela, obj->jmprel };
    size_t counts[] = { obj->rela_count, obj->jmprel_count };

    if (walk_relr(obj, 0) < 0)
        return -1;
    for (size_t t = 0; t < sizeof(tables) / sizeof(tables[0]); t++) {
        for (size_t i = 0; i < counts[t]; i++) {
            if (validate_relocation_record(obj, &tables[t][i], NULL, NULL,
                                           NULL) < 0)
                return -1;
        }
    }
    return 0;
}

/*
 * Pre-seed _rtld_global / _rtld_global_ro and __rseq_* GOT entries before any
 * relocations run.  IFUNC resolvers in glibc (memcpy, mempcpy, etc.)
 * read _rtld_global_ro through the GOT.  If a GLOB_DAT for an IFUNC
 * symbol is processed before _rtld_global_ro's own GLOB_DAT in the
 * same rela table, resolve_sym calls the IFUNC resolver → crash.
 * glibc's thread start path can also read __rseq_* before the generic
 * runtime-fixup pass reaches the symbol.  This pre-pass ensures those
 * startup-critical GOT slots are already populated.
 */
static int preseed_rtld_got(struct loaded_obj *obj,
                            struct loaded_obj *objs, int nobj)
{
    const Elf64_Rela *tabs[] = { obj->rela, obj->jmprel };
    size_t counts[] = { obj->rela_count, obj->jmprel_count };
    for (int t = 0; t < 2; t++) {
        for (size_t i = 0; i < counts[t]; i++) {
            const Elf64_Rela *r = &tabs[t][i];
            uint32_t type = ELF64_R_TYPE(r->r_info);
            uint32_t sidx;
            const char *name;
            uint64_t addr = 0;
            const Elf64_Sym *reference;
            void *relocation_slot;

            if (type != ARCH_RELOC_GLOB_DAT && type != ARCH_RELOC_JUMP_SLOT)
                continue;
            sidx = ELF64_R_SYM(r->r_info);
            if (sidx == 0)
                continue;
            if (validate_relocation_record(obj, r, &reference, &name,
                                           &relocation_slot) < 0)
                return -1;
            (void)reference;
            if (name[0] != '_')
                continue;

            if (lookup_fake_object(name))
                addr = lookup_relocation_special(obj, sidx, objs, nobj);

            if (addr) {
                /* GLOB_DAT/JUMP_SLOT compute S, never S+A.  Some glibc PLT
                 * entries carry a nonzero stub addend that must be ignored. */
                *(uint64_t *)relocation_slot = addr;
                if (g_debug) {
                    ldr_msg("GOT preseed: ");
                    ldr_msg(name);
                    ldr_msg(" in ");
                    ldr_msg(obj->name);
                    ldr_msg("\n");
                }
            }
        }
    }
    return 0;
}

static int apply_all_relocs(struct loaded_obj *obj,
                             struct loaded_obj *all, int nobj,
                             enum relocation_pass pass)
{
    if (pass == RELOC_PASS_ORDINARY) {
        /* RELR first (all relative, no symbols) */
        if (walk_relr(obj, 1) < 0) {
            ldr_err("malformed RELR relocation in", obj->name);
            return -1;
        }
    }

    /* RELA (.rela.dyn) */
    if (obj->rela_count > 0) {
        if (apply_relocs_rela(obj, obj->rela, obj->rela_count, all, nobj, pass) < 0)
            return -1;
    }

    /* JMPREL (.rela.plt) */
    if (obj->jmprel_count > 0) {
        if (apply_relocs_rela(obj, obj->jmprel, obj->jmprel_count, all, nobj, pass) < 0)
            return -1;
    }

    return 0;
}

/* ==== Minimal libc process initialization ============================= */

struct musl_tls_module_state {
    struct musl_tls_module_state *next;
    void *image;
    size_t len;
    size_t size;
    size_t align;
    size_t offset;
};

static uintptr_t get_auxval(char **envp, unsigned long type);
static Elf64_auxv_t *get_auxv_ptr(char **envp);
static const Elf64_Sym *lookup_linear(const struct loaded_obj *obj,
                                      const char *name);
static struct musl_tls_module_state g_musl_tls_modules[MAX_TOTAL_OBJS];

static void init_musl_process_state(struct loaded_obj *objs, int nobj,
                                    char **envp)
{
    const struct loaded_obj *libc_obj;
    Elf64_auxv_t *auxv;
    uintptr_t hwcap = 0;
    uintptr_t sysinfo = 0;
    uintptr_t pagesz = 4096;
    uint64_t sysinfo_addr;
    uint64_t hwcap_addr;
    uintptr_t tp = 0;
    int secure = 0;
    size_t max_modid = 0;
    size_t tls_span = 0;
    size_t max_align = sizeof(uintptr_t);
    uint64_t tls_size_sum;
    uint64_t tls_size;

    if (!g_is_musl_runtime)
        return;

    libc_obj = find_musl_libc(objs, nobj);
    if (!libc_obj || !g_musl_layout || !g_musl_libc_addr)
        _exit(127);

    auxv = get_auxv_ptr(envp);
    for (Elf64_auxv_t *entry = auxv; entry->a_type != AT_NULL; entry++) {
        switch (entry->a_type) {
        case AT_HWCAP:
            hwcap = entry->a_un.a_val;
            break;
        case AT_SYSINFO:
            sysinfo = entry->a_un.a_val;
            break;
        case AT_PAGESZ:
            pagesz = entry->a_un.a_val;
            break;
        case AT_SECURE:
            secure = entry->a_un.a_val != 0;
            break;
        default:
            break;
        }
    }

    if (!secure) {
        uintptr_t uid = get_auxval(envp, AT_UID);
        uintptr_t euid = get_auxval(envp, AT_EUID);
        uintptr_t gid = get_auxval(envp, AT_GID);
        uintptr_t egid = get_auxval(envp, AT_EGID);

        secure = (uid != euid) || (gid != egid);
    }

    memset(g_musl_tls_modules, 0, sizeof(g_musl_tls_modules));
    for (int i = 0; i < nobj; i++) {
        if (objs[i].tls.memsz == 0)
            continue;
        if (objs[i].tls.modid > max_modid)
            max_modid = objs[i].tls.modid;
    }
    for (size_t modid = 1; modid <= max_modid; modid++) {
        struct musl_tls_module_state *mod = &g_musl_tls_modules[modid - 1];

        mod->image = mod;
        mod->align = sizeof(uintptr_t);
        if (modid < max_modid)
            mod->next = &g_musl_tls_modules[modid];

        for (int i = 0; i < nobj; i++) {
            size_t offset;

            if (objs[i].tls.memsz == 0 || objs[i].tls.modid != modid)
                continue;
            offset = musl_tls_above_tp()
                ? (size_t)objs[i].tls.tpoff
                : (size_t)(-(objs[i].tls.tpoff));

            if (objs[i].tls.filesz != 0) {
                mod->image = (void *)(uintptr_t)(objs[i].base +
                                                  objs[i].tls.vaddr);
            }
            mod->len = objs[i].tls.filesz;
            mod->size = objs[i].tls.memsz;
            mod->align = objs[i].tls.align ? (size_t)objs[i].tls.align : 1;
            mod->offset = offset;
            if (musl_tls_above_tp()) {
                if (mod->size > SIZE_MAX - offset)
                    _exit(127);
                if (offset + mod->size > tls_span)
                    tls_span = offset + mod->size;
            } else if (offset > tls_span) {
                tls_span = offset;
            }
            break;
        }
        if (mod->align > max_align)
            max_align = mod->align;
    }

    if (!u64_add_checked((uint64_t)(max_modid + 1) * sizeof(uintptr_t),
                         tls_span, &tls_size_sum) ||
        !u64_add_checked(tls_size_sum, g_musl_layout->pthread_size,
                         &tls_size_sum) ||
        max_align > UINT64_MAX / 2 ||
        !u64_add_checked(tls_size_sum, (uint64_t)max_align * 2,
                         &tls_size_sum) ||
        !u64_align_up_checked(tls_size_sum, max_align, &tls_size) ||
        tls_size > SIZE_MAX)
        _exit(127);

    if (g_musl_layout->libc_flag_width == 1) {
        *(uint8_t *)(g_musl_libc_addr +
                     g_musl_layout->libc_can_do_threads) = 1;
        *(uint8_t *)(g_musl_libc_addr + g_musl_layout->libc_secure) =
            secure != 0;
    } else {
        *(int *)(g_musl_libc_addr +
                 g_musl_layout->libc_can_do_threads) = 1;
        *(int *)(g_musl_libc_addr + g_musl_layout->libc_secure) = secure;
    }
    *(size_t **)(g_musl_libc_addr + g_musl_layout->libc_auxv) =
        (size_t *)auxv;
    *(void **)(g_musl_libc_addr + g_musl_layout->libc_tls_head) =
        max_modid ? &g_musl_tls_modules[0] : NULL;
    *(size_t *)(g_musl_libc_addr + g_musl_layout->libc_tls_size) =
        (size_t)tls_size;
    *(size_t *)(g_musl_libc_addr + g_musl_layout->libc_tls_align) =
        max_align;
    *(size_t *)(g_musl_libc_addr + g_musl_layout->libc_tls_cnt) =
        max_modid;
    *(size_t *)(g_musl_libc_addr + g_musl_layout->libc_page_size) = pagesz;

    tp = arch_get_tp();
    if (tp) {
        uintptr_t self = musl_thread_self_ptr(tp);

        *(uintptr_t *)(self + MUSL_THREAD_PREV_OFF) = self;
        *(uintptr_t *)(self + MUSL_THREAD_NEXT_OFF) = self;
        *(uintptr_t *)(self + MUSL_THREAD_SYSINFO_OFF) = sysinfo;
        if (g_musl_target_tid_known)
            *(int *)(self + MUSL_THREAD_TID_OFF) = (int)syscall(SYS_gettid);
        if (g_musl_target_errno_known)
            *(int *)(self + MUSL_THREAD_ERRNO_OFF) = 0;
        if (g_musl_target_detach_known)
            *(int *)(self + MUSL_THREAD_DETACH_STATE_OFF) =
                g_musl_target_detach_value;
        *(uintptr_t *)(self + MUSL_THREAD_ROBUST_HEAD_OFF) =
            self + MUSL_THREAD_ROBUST_HEAD_OFF;
        *(uintptr_t *)(self + MUSL_THREAD_LOCALE_OFF) =
            g_musl_libc_addr + g_musl_layout->libc_global_locale;
    }

    sysinfo_addr = musl_defined_symbol_addr(libc_obj, "__sysinfo");
    if (sysinfo_addr &&
        loaded_obj_contains(libc_obj, (uintptr_t)sysinfo_addr, sizeof(uintptr_t)))
        *(uintptr_t *)(uintptr_t)sysinfo_addr = sysinfo;

    hwcap_addr = musl_defined_symbol_addr(libc_obj, "__hwcap");
    if (hwcap_addr &&
        loaded_obj_contains(libc_obj, (uintptr_t)hwcap_addr, sizeof(uintptr_t)))
        *(uintptr_t *)(uintptr_t)hwcap_addr = hwcap;

    {
        uint64_t guard_addr = musl_defined_symbol_addr(
            libc_obj, "__stack_chk_guard");

        if (guard_addr &&
            loaded_obj_contains(libc_obj, (uintptr_t)guard_addr,
                                sizeof(uintptr_t))) {
            *(uintptr_t *)(uintptr_t)guard_addr = g_musl_stack_guard;
        }
    }
}

static void init_libc_process_state(struct loaded_obj *objs, int nobj,
                                    int argc, char **argv, char **envp,
                                    char **auxv_envp)
{
    uint64_t addr;

    addr = resolve_sym(objs, nobj, "__environ");
    if (addr) {
        if (g_debug) {
            ldr_hex("__environ resolved to ", addr);
        }
        *(char ***)(uintptr_t)addr = envp;
    }
    /* Also set __environ in each DSO's own data (for COPY reloc scenarios
     * where libc may have internal references to its own copy). */
    for (int i = 0; i < nobj; i++) {
        if (objs[i].flags & LDR_FLAG_MAIN_EXE) continue;
        const Elf64_Sym *sym = lookup_object_symbol(
            &objs[i], "__environ", gnu_hash_calc("__environ"));
        if (sym && sym->st_shndx != 0 && sym->st_size > 0) {
            uint64_t dso_addr = objs[i].base + sym->st_value;
            if (dso_addr != addr) {
                if (g_debug) {
                    ldr_hex("__environ DSO copy at ", dso_addr);
                }
                *(char ***)(uintptr_t)dso_addr = envp;
            }
        }
    }
    addr = resolve_sym(objs, nobj, "environ");
    if (addr) *(char ***)(uintptr_t)addr = envp;

    addr = resolve_sym(objs, nobj, "program_invocation_name");
    if (addr) *(char **)(uintptr_t)addr = argv[0];

    addr = resolve_sym(objs, nobj, "program_invocation_short_name");
    if (addr) {
        const char *s = argv[0];
        const char *p = s;
        while (*p) { if (*p == '/') s = p + 1; p++; }
        *(const char **)(uintptr_t)addr = s;
    }

    addr = resolve_sym(objs, nobj, "__libc_argv");
    if (addr) *(char ***)(uintptr_t)addr = argv;
    addr = resolve_sym(objs, nobj, "__libc_argc");
    if (addr) *(int *)(uintptr_t)addr = argc;

    addr = resolve_sym(objs, nobj, "__libc_stack_end");
    if (addr) *(void **)(uintptr_t)addr = (void *)&argv[-1];

    init_musl_process_state(objs, nobj, auxv_envp);
    if (g_is_musl_runtime)
        return;

    /* glibc stdio exposes both FILE objects and pointer aliases. */
    uint64_t io_stdin  = resolve_sym(objs, nobj, "_IO_2_1_stdin_");
    uint64_t io_stdout = resolve_sym(objs, nobj, "_IO_2_1_stdout_");
    uint64_t io_stderr = resolve_sym(objs, nobj, "_IO_2_1_stderr_");

    addr = resolve_sym(objs, nobj, "stdin");
    if (addr && io_stdin) *(void **)(uintptr_t)addr = (void *)(uintptr_t)io_stdin;
    addr = resolve_sym(objs, nobj, "stdout");
    if (addr && io_stdout) *(void **)(uintptr_t)addr = (void *)(uintptr_t)io_stdout;
    addr = resolve_sym(objs, nobj, "stderr");
    if (addr && io_stderr) *(void **)(uintptr_t)addr = (void *)(uintptr_t)io_stderr;

    /* Record arena address for crash diagnostics */
    if (io_stdin)
        g_arena_addr = io_stdin + 0x1e0;

    /* Set _dl_auxv in _rtld_global_ro so that getauxval() works.
     * The real auxiliary vector lives on the stack just after envp's
     * NULL terminator. */
    {
        char **p = auxv_envp;
        while (*p) p++;
        p++;  /* skip NULL terminator of envp */
        *(Elf64_auxv_t **)(g_fake_rtld_global_ro + GLRO_DL_AUXV_OFF) =
            (Elf64_auxv_t *)p;
    }

    /* Call __libc_early_init(1) which performs all critical libc setup:
     *   - __ctype_init (ctype table pointers in TLS)
     *   - __libc_single_threaded = 1 (skip mutex locking)
     *   - __libc_initial = 1 (allow sbrk-based allocation)
     *   - Thread stack size computation (reads _rtld_global_ro TLS fields)
     *   - __pthread_tunables_init
     *   - __getrandom_early_init
     *   - Tail-calls __ptmalloc_init which:
     *     - Initializes tcache_key via getrandom syscall
     *     - Sets thread_arena TLS = &main_arena
     *     - Initializes all arena bins (self-referential fd/bk)
     *     - Sets top = initial_top
     *     - Processes malloc tunables (via our __tunable_get_val stub)
     *
     * Requires fake _rtld_global_ro to have:
     *   +0x18  _dl_pagesize = runtime AT_PAGESZ
     *   _dl_tls_static_size (non-zero, version-dependent offset)
     *   _dl_tls_static_align (non-zero, version-dependent offset)
     *
     * tcache TLS is already initialized from .tdata to &__tcache_dummy.
     * On first free(), glibc detects tcache == __tcache_dummy and calls
     * tcache_init() which allocates a real tcache via malloc. This is the
     * normal glibc initialization path — no manual tcache setup needed.
     */

    /* The private layout was validated before object mapping.  Never revive
     * the former numeric-version fallback here: a minor version does not
     * identify glibc's private rtld structs. */
    if (!g_glibc_rtld_fixed) {
        ldr_err("glibc private rtld layout was not validated", NULL);
        _exit(127);
    }

    /* Pre-initialize __curbrk in the mapped libc so that sbrk() has
     * the correct kernel brk value from the start.  Must be done
     * BEFORE __libc_early_init in case any init code uses malloc. */
    addr = resolve_sym(objs, nobj, "__curbrk");
    if (addr) {
        void *cur = (void *)syscall(SYS_brk, 0);
        *(void **)(uintptr_t)addr = cur;
    }

    addr = resolve_sym(objs, nobj, "__libc_early_init");
    if (addr) {
        ldr_dbg("[loader] calling __libc_early_init...\n");
        ((void(*)(int))(uintptr_t)addr)(1);
        g_glibc_early_init_done = 1;
        ldr_dbg("[loader] __libc_early_init done\n");
    }
}

/* ==== Set final memory protections ===================================== */

static int protect_object(struct loaded_obj *obj,
                          const struct dlfrz_lib_meta *meta)
{
    const uint8_t *phdr_start = (const uint8_t *)(obj->base + meta->phdr_off);

    for (int i = 0; i < meta->phdr_num; i++) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(phdr_start + i * meta->phdr_entsz);
        if (ph->p_type != PT_LOAD) continue;

        if (set_segment_protection(obj->base, ph, phdr_prot(ph)) < 0)
            return -1;
    }

    /* GNU_RELRO is writable while relocations are applied, then becomes
     * read-only before any constructor or application code runs. */
    for (int i = 0; i < meta->phdr_num; i++) {
        const Elf64_Phdr *relro =
            (const Elf64_Phdr *)(phdr_start + i * meta->phdr_entsz);
        uint64_t raw_start, raw_end, relro_start, relro_end;

        if (relro->p_type != PT_GNU_RELRO || relro->p_memsz == 0)
            continue;

        if (relro->p_memsz > SIZE_MAX ||
            !loaded_obj_vaddr_pointer(obj, relro->p_vaddr,
                                      (size_t)relro->p_memsz, PF_R, NULL) ||
            !u64_add_checked(obj->base, relro->p_vaddr, &raw_start) ||
            !u64_add_checked(raw_start, relro->p_memsz, &raw_end) ||
            !u64_align_up_checked(raw_end, g_page_size, &relro_end))
            return -1;
        relro_start = page_floor(raw_start);
        if (relro_end - relro_start > SIZE_MAX ||
            !loaded_obj_pages_covered(obj, relro_start, relro_end, PF_R))
            return -1;

        /* RELRO contains data, never executable code.  Using a union of
         * overlapping segment flags here can accidentally restore PF_X. */
        if (mprotect((void *)(uintptr_t)relro_start,
                     (size_t)(relro_end - relro_start), PROT_READ) < 0)
            return -1;
    }
    return 0;
}

/* ==== dlopen implementation ============================================ */

static const char *dl_basename(const char *path)
{
    const char *base = path;
    while (*path) { if (*path == '/') base = path + 1; path++; }
    return base;
}

static int dl_name_matches(const char *path, const char *name)
{
    const char *base;
    size_t n;

    if (!path || !name)
        return 0;

    base = dl_basename(path);
    if (strcmp(base, name) == 0)
        return 1;

    n = strlen(name);
    return n > 0 && strncmp(base, name, n) == 0 && base[n] == '.';
}

static int dl_is_virtual_runtime_object(const char *name)
{
    const char *base;

    if (!name || !name[0])
        return 0;
    base = dl_basename(name);
    if (strcmp(base, "linux-vdso.so.1") == 0 ||
        strcmp(base, "linux-gate.so.1") == 0)
        return 1;
#if defined(__x86_64__)
    return strcmp(base, "ld-linux-x86-64.so.2") == 0 ||
           strcmp(base, "ld-musl-x86_64.so.1") == 0;
#elif defined(__aarch64__)
    return strcmp(base, "ld-linux-aarch64.so.1") == 0 ||
           strcmp(base, "ld-musl-aarch64.so.1") == 0;
#endif
}

static const char *dl_store_name(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    n++;  /* include NUL */
    if (n > sizeof(g_dl_strbuf) - g_dl_strbuf_used)
        return NULL;
    char *d = g_dl_strbuf + g_dl_strbuf_used;
    memcpy(d, s, n);
    g_dl_strbuf_used += n;
    return d;
}

static void dl_set_error(const char *a, const char *b)
{
    char *d = g_dlerror_msg;
    char *end = g_dlerror_msg + sizeof(g_dlerror_msg) - 1;
    if (a) while (*a && d < end) *d++ = *a++;
    if (b) while (*b && d < end) *d++ = *b++;
    *d = '\0';
    g_dlerror_valid = 1;
}

struct dl_rpath_scope {
    const char *path;
    const struct loaded_obj *owner;
    const struct dl_rpath_scope *parent;
};

/* Forward declarations — recursive loading between these functions */
static struct loaded_obj *load_elf_from_file(
    const char *path, const struct dl_rpath_scope *inherited_rpath);
static struct loaded_obj *load_elf_from_file_fd(
    const char *path, int fd,
    const struct dl_rpath_scope *inherited_rpath);
static struct loaded_obj *load_embedded_object(
    uint32_t mi, const struct dl_rpath_scope *inherited_rpath);

static int read_runtime_dso_headers(int fd, Elf64_Ehdr *eh,
                                    Elf64_Phdr *ph, size_t ph_capacity,
                                    uint64_t *file_size_out)
{
    struct stat st;
    uint64_t phdr_bytes;
    const Elf64_Phdr *dynamic = NULL;
    unsigned int dynamic_count = 0;
    unsigned int load_count = 0;

    if (fstat(fd, &st) < 0 || st.st_size < (off_t)sizeof(*eh) ||
        pread(fd, eh, sizeof(*eh), 0) != (ssize_t)sizeof(*eh))
        return -1;
    *file_size_out = (uint64_t)st.st_size;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        eh->e_ident[EI_DATA] != ELFDATA2LSB ||
        eh->e_ident[EI_VERSION] != EV_CURRENT ||
        eh->e_version != EV_CURRENT || eh->e_ehsize != sizeof(*eh) ||
        eh->e_type != ET_DYN || eh->e_machine != ARCH_ELF_MACHINE ||
        eh->e_phnum == 0 || eh->e_phnum > ph_capacity ||
        eh->e_phentsize != sizeof(Elf64_Phdr) ||
        !u64_mul_checked(eh->e_phnum, sizeof(Elf64_Phdr), &phdr_bytes) ||
        eh->e_phoff > *file_size_out ||
        phdr_bytes > *file_size_out - eh->e_phoff ||
        eh->e_phoff > (uint64_t)INT64_MAX || phdr_bytes > SSIZE_MAX ||
        pread(fd, ph, (size_t)phdr_bytes, (off_t)eh->e_phoff) !=
            (ssize_t)phdr_bytes)
        return -1;

    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *header = &ph[i];

        if (header->p_offset > *file_size_out ||
            header->p_filesz > *file_size_out - header->p_offset ||
            header->p_vaddr > UINT64_MAX - header->p_memsz ||
            header->p_offset > (uint64_t)INT64_MAX ||
            header->p_filesz > SSIZE_MAX)
            return -1;
        if (header->p_type == PT_LOAD || header->p_type == PT_DYNAMIC ||
            header->p_type == PT_TLS) {
            if (header->p_filesz > header->p_memsz ||
                (header->p_align > 1 &&
                 ((header->p_align & (header->p_align - 1)) != 0 ||
                  (header->p_vaddr & (header->p_align - 1)) !=
                    (header->p_offset & (header->p_align - 1)))))
                return -1;
        }
        if (header->p_type == PT_LOAD && header->p_memsz != 0)
            load_count++;
        if (header->p_type == PT_DYNAMIC) {
            dynamic = header;
            dynamic_count++;
        }
    }
    if (load_count == 0 || dynamic_count != 1 || !dynamic ||
        dynamic->p_filesz == 0 ||
        dynamic->p_filesz % sizeof(Elf64_Dyn) != 0)
        return -1;

    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *load = &ph[i];
        uint64_t delta;

        if (load->p_type != PT_LOAD ||
            dynamic->p_vaddr < load->p_vaddr ||
            dynamic->p_offset < load->p_offset)
            continue;
        delta = dynamic->p_vaddr - load->p_vaddr;
        if (dynamic->p_offset - load->p_offset == delta &&
            delta <= load->p_memsz &&
            dynamic->p_memsz <= load->p_memsz - delta &&
            delta <= load->p_filesz &&
            dynamic->p_filesz <= load->p_filesz - delta)
            return 0;
    }
    return -1;
}

/* Search paths may contain a DSO for another ABI before the usable one.
 * Distinguish that normal mismatch from malformed metadata: searched ABI
 * mismatches are skipped, while an explicit path and malformed files fail. */
static int runtime_dso_fd_compatible(int fd)
{
    Elf64_Ehdr eh;

    if (pread(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh))
        return -1;
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0)
        return -1;
    if (eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_ident[EI_DATA] != ELFDATA2LSB ||
        eh.e_ident[EI_VERSION] != EV_CURRENT ||
        eh.e_version != EV_CURRENT || eh.e_type != ET_DYN ||
        eh.e_machine != ARCH_ELF_MACHINE)
        return 0;
    return 1;
}

/* dynamic_has_static_tls — inspect an already validated ELF file and report
 * its dynamic section sets DF_STATIC_TLS.  Such objects expect their
 * TLS block to live at a fixed negative TPOFF inside the main thread's
 * static TLS area.  glibc's real rtld refuses to dlopen them after
 * startup unless static-TLS surplus exists, because the dynamic TLS
 * model would relocate __thread accesses to the wrong addresses.
 *
 * Our in-process loader has no such surplus and would happily allocate
 * a regular DTV slot, so subsequent IE-model TPOFF relocs and ifunc
 * resolvers in the freshly mapped library scribble over the calling
 * thread's TLS.  The result is "*** stack smashing detected ***" or
 * a SIGSEGV inside whichever __thread variable was clobbered.
 *
 * Returning 1 here lets my_dlopen turn the request into a graceful
 * NULL+dlerror, mirroring glibc's "cannot allocate memory in static
 * TLS block" failure mode that callers already handle. */
static int dynamic_has_static_tls(int fd, const Elf64_Phdr *ph,
                                  uint16_t phnum)
{
    /* Locate PT_DYNAMIC and PT_TLS.  DF_STATIC_TLS is only meaningful
     * if the object actually has a non-empty TLS template — many glibc
     * libs (e.g. libm.so.6) carry the flag for legacy reasons but
     * declare zero TLS, so loading them is harmless. */
    const Elf64_Phdr *dyn_ph = NULL;
    uint64_t tls_memsz = 0;
    for (uint16_t i = 0; i < phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC) dyn_ph = &ph[i];
        else if (ph[i].p_type == PT_TLS) tls_memsz = ph[i].p_memsz;
    }
    if (!dyn_ph || tls_memsz == 0) {
        return 0;
    }

    Elf64_Dyn dyn[4096];
    if (dyn_ph->p_filesz > sizeof(dyn)) {
        return -1;
    }
    if (pread(fd, dyn, dyn_ph->p_filesz, dyn_ph->p_offset) !=
        (ssize_t)dyn_ph->p_filesz) {
        return -1;
    }

    int found = 0;
    size_t n = dyn_ph->p_filesz / sizeof(Elf64_Dyn);
    int saw_null = 0;
    for (size_t i = 0; i < n; i++) {
        if (dyn[i].d_tag == DT_NULL) {
            saw_null = 1;
            break;
        }
        if (dyn[i].d_tag == DT_FLAGS &&
            (dyn[i].d_un.d_val & 0x10 /* DF_STATIC_TLS */)) {
            found = 1;
        }
    }
    return saw_null ? found : -1;
}

/* Apply the same static-TLS admission rule after an object has been parsed.
 * The relocation scan is intentional: malformed or non-GNU-produced DSOs
 * are not allowed to evade DF_STATIC_TLS simply by omitting the flag. */
static int dl_lazy_static_tls_admitted(const struct loaded_obj *obj,
                                       const char *name)
{
    int requires_static_tls = 0;

    if (!obj || obj->tls.memsz == 0)
        return 0;
    for (size_t i = 0; i < obj->dynamic_count; i++) {
        if (obj->dynamic[i].d_tag == DT_FLAGS &&
            (obj->dynamic[i].d_un.d_val & 0x10 /* DF_STATIC_TLS */)) {
            requires_static_tls = 1;
            break;
        }
    }
    if (!requires_static_tls) {
        const Elf64_Rela *tables[] = { obj->rela, obj->jmprel };
        size_t counts[] = { obj->rela_count, obj->jmprel_count };

        for (size_t t = 0; t < sizeof(tables) / sizeof(tables[0]) &&
                           !requires_static_tls; t++) {
            for (size_t i = 0; i < counts[t]; i++) {
                if (ELF64_R_TYPE(tables[t][i].r_info) == ARCH_RELOC_TPOFF) {
                    requires_static_tls = 1;
                    break;
                }
            }
        }
    }
    if (!requires_static_tls)
        return 0;

    dl_set_error(name,
        ": cannot dlopen static-TLS library after startup "
        "(would clobber main thread TLS)");
    if (g_debug) {
        ldr_msg("[loader] refusing dlopen of static-TLS lib: ");
        ldr_msg(name);
        ldr_msg("\n");
    }
    return -1;
}

#define DL_SEARCH_PATH_BYTES_MAX 16384U
#define DL_SEARCH_COMPONENTS_MAX 128U

#if defined(__x86_64__)
static const char *g_runtime_search_dirs[] = {
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
    "/lib64",
    "/usr/lib64",
    "/usr/local/lib",
    "/lib",
    "/usr/lib",
    NULL
};
#elif defined(__aarch64__)
static const char *g_runtime_search_dirs[] = {
    "/lib/aarch64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
    "/lib64",
    "/usr/lib64",
    "/usr/local/lib",
    "/lib",
    "/usr/lib",
    NULL
};
#endif

static int dl_path_has_slash(const char *path)
{
    return path && strchr(path, '/') != NULL;
}

static int dl_dependency_name_matches(const char *loaded,
                                      const char *needed)
{
    if (dl_path_has_slash(needed))
        return loaded && strcmp(loaded, needed) == 0;
    return loaded && strcmp(dl_basename(loaded), needed) == 0;
}

static const char *dl_object_soname(const struct loaded_obj *obj)
{
    if (!obj || !obj->dynamic)
        return NULL;
    for (size_t i = 0; i < obj->dynamic_count; i++) {
        if (obj->dynamic[i].d_tag != DT_SONAME)
            continue;
        if (obj->dynamic[i].d_un.d_val > UINT32_MAX)
            return NULL;
        return loaded_dynstr_value(
            obj, (uint32_t)obj->dynamic[i].d_un.d_val);
    }
    return NULL;
}

static int dl_loaded_dependency_matches(const struct loaded_obj *obj,
                                        const char *needed)
{
    const char *soname;

    if (!obj || !obj->name || !needed)
        return 0;
    if (dl_path_has_slash(needed))
        return strcmp(obj->name, needed) == 0;
    soname = dl_object_soname(obj);
    return (soname && strcmp(soname, needed) == 0) ||
           strcmp(dl_basename(obj->name), needed) == 0;
}

static int dl_initialize_startup_lookup_scopes(struct loaded_obj *objs,
                                               int nobj)
{
    int main_index = -1;

    if (objs != g_all_objs || nobj <= 0 || nobj > MAX_TOTAL_OBJS)
        return -1;
    g_global_scope_root = -1;
    g_global_scope_count = 0;
    for (int i = 0; i < nobj; i++) {
        struct loaded_obj *obj = &objs[i];

        obj->needed_count = 0;
        obj->lookup_scope_count = 0;
        obj->lookup_scope_valid = 0;
        if (obj->flags & LDR_FLAG_MAIN_EXE) {
            if (main_index >= 0)
                return -1;
            main_index = i;
        }
    }
    if (main_index < 0)
        return -1;

    for (int i = 0; i < nobj; i++) {
        struct loaded_obj *obj = &objs[i];

        if (!obj->dynamic || !obj->dynstr)
            continue;
        for (size_t d = 0; d < obj->dynamic_count; d++) {
            const char *needed;
            struct loaded_obj *dependency = NULL;

            if (obj->dynamic[d].d_tag != DT_NEEDED)
                continue;
            if (obj->dynamic[d].d_un.d_val > UINT32_MAX)
                return -1;
            needed = loaded_dynstr_value(
                obj, (uint32_t)obj->dynamic[d].d_un.d_val);
            if (!needed || !needed[0])
                return -1;
            if (dl_is_virtual_runtime_object(needed))
                continue;
            for (int j = 0; j < nobj; j++) {
                if (dl_loaded_dependency_matches(&objs[j], needed)) {
                    dependency = &objs[j];
                    break;
                }
            }
            if (!dependency ||
                dl_add_dependency_edge(obj, dependency, nobj) < 0)
                return -1;
        }
    }

    g_global_scope_root = main_index;
    for (int i = 0; i < nobj; i++)
        if (dl_set_relocation_scope_root(&objs[i], main_index, nobj) < 0)
            return -1;
    if (dl_append_lookup_scope_to_global(&objs[main_index], nobj) < 0)
        return -1;

    /* Keep any packed startup object not reachable from the main object's
     * DT_NEEDED graph globally visible in its prior table order. */
    for (int i = 0; i < nobj; i++)
        if (dl_append_index_to_global((uint16_t)i, nobj) < 0)
            return -1;
    return 0;
}

static const struct loaded_obj *dl_main_object(void)
{
    for (int i = 0; i < g_nobj; i++)
        if (g_all_objs[i].flags & LDR_FLAG_MAIN_EXE)
            return &g_all_objs[i];
    return NULL;
}

static int dl_object_origin(const struct loaded_obj *obj,
                            char *origin, size_t origin_size)
{
    const char *name;
    const char *slash;
    size_t length;

    if (!obj)
        obj = dl_main_object();
    if (!obj || !obj->name || !obj->name[0] || origin_size < 2)
        return -1;
    name = obj->name;
    slash = strrchr(name, '/');
    if (!slash) {
        origin[0] = '.';
        origin[1] = '\0';
        return 0;
    }
    length = slash == name ? 1 : (size_t)(slash - name);
    if (length >= origin_size)
        return -1;
    memcpy(origin, name, length);
    origin[length] = '\0';
    return 0;
}

static int dl_expand_search_component(const char *component, size_t length,
                                      const struct loaded_obj *owner,
                                      char *expanded, size_t expanded_size)
{
    char origin[PATH_MAX];
    size_t input = 0;
    size_t output = 0;
    int have_origin = 0;

    if (length == 0) {
        if (expanded_size < 2)
            return -1;
        expanded[0] = '.';
        expanded[1] = '\0';
        return 0;
    }

    while (input < length) {
        size_t token_length = 0;

        if (component[input] == '$') {
            if (length - input >= sizeof("${ORIGIN}") - 1 &&
                memcmp(component + input, "${ORIGIN}",
                       sizeof("${ORIGIN}") - 1) == 0) {
                token_length = sizeof("${ORIGIN}") - 1;
            } else if (length - input >= sizeof("$ORIGIN") - 1 &&
                       memcmp(component + input, "$ORIGIN",
                              sizeof("$ORIGIN") - 1) == 0 &&
                       (length - input == sizeof("$ORIGIN") - 1 ||
                        component[input + sizeof("$ORIGIN") - 1] == '/')) {
                token_length = sizeof("$ORIGIN") - 1;
            } else {
                return -1;
            }
        }

        if (token_length) {
            size_t origin_length;

            if (!have_origin) {
                if (dl_object_origin(owner, origin, sizeof(origin)) < 0)
                    return -1;
                have_origin = 1;
            }
            origin_length = strlen(origin);
            if (origin_length > expanded_size - 1 - output)
                return -1;
            memcpy(expanded + output, origin, origin_length);
            output += origin_length;
            input += token_length;
            continue;
        }

        if (output + 1 >= expanded_size)
            return -1;
        expanded[output++] = component[input++];
    }
    expanded[output] = '\0';
    return 0;
}

static int dl_try_runtime_candidate(
    const char *path, const struct dl_rpath_scope *child_inherited,
    struct loaded_obj **result)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    int compatible;

    if (fd < 0) {
        if (errno == ENOENT || errno == ENOTDIR)
            return 0;
        dl_set_error(path, ": cannot open");
        return -1;
    }
    compatible = runtime_dso_fd_compatible(fd);
    if (compatible == 0) {
        close(fd);
        return 0;
    }
    if (compatible < 0) {
        close(fd);
        dl_set_error(path, ": malformed shared object candidate");
        return -1;
    }
    *result = load_elf_from_file_fd(path, fd, child_inherited);
    return *result ? 1 : -1;
}

static int dl_search_path_list(
    const char *list, const struct loaded_obj *owner, const char *needed,
    int allow_semicolon,
    const struct dl_rpath_scope *child_inherited,
    struct loaded_obj **result)
{
    size_t list_length;
    size_t start = 0;
    unsigned int components = 0;

    if (!list)
        return 0;
    list_length = strnlen(list, DL_SEARCH_PATH_BYTES_MAX + 1);
    if (list_length > DL_SEARCH_PATH_BYTES_MAX) {
        dl_set_error("library search path is too long", NULL);
        return -1;
    }

    for (;;) {
        const char *colon;
        const char *semicolon;
        const char *separator;
        size_t length;
        char directory[PATH_MAX];
        char candidate[PATH_MAX];
        int rc;

        if (++components > DL_SEARCH_COMPONENTS_MAX) {
            dl_set_error("too many library search path components", NULL);
            return -1;
        }
        colon = memchr(list + start, ':', list_length - start);
        semicolon = allow_semicolon
            ? memchr(list + start, ';', list_length - start) : NULL;
        separator = !colon ? semicolon
                           : (!semicolon || colon < semicolon
                                  ? colon : semicolon);
        length = separator ? (size_t)(separator - (list + start))
                           : list_length - start;
        if (dl_expand_search_component(list + start, length, owner,
                                       directory, sizeof(directory)) < 0) {
            dl_set_error("invalid dynamic library search path", NULL);
            return -1;
        }
        rc = snprintf(candidate, sizeof(candidate), "%s/%s",
                      directory, needed);
        if (rc < 0 || (size_t)rc >= sizeof(candidate)) {
            dl_set_error("dynamic library candidate path is too long", NULL);
            return -1;
        }
        rc = dl_try_runtime_candidate(candidate, child_inherited, result);
        if (rc != 0)
            return rc;
        if (!separator)
            return 0;
        start = (size_t)(separator - list) + 1;
    }
}

static int dl_object_search_paths(const struct loaded_obj *obj,
                                  const char **rpath_out,
                                  const char **runpath_out)
{
    const char *rpath = NULL;
    const char *runpath = NULL;

    if (obj && obj->dynamic) {
        for (size_t i = 0; i < obj->dynamic_count; i++) {
            const char **slot;
            const char *value;

            if (obj->dynamic[i].d_tag == DT_RPATH)
                slot = &rpath;
            else if (obj->dynamic[i].d_tag == DT_RUNPATH)
                slot = &runpath;
            else
                continue;
            if (obj->dynamic[i].d_un.d_val > UINT32_MAX)
                return -1;
            value = loaded_dynstr_value(
                obj, (uint32_t)obj->dynamic[i].d_un.d_val);
            if (!value || (*slot && strcmp(*slot, value) != 0))
                return -1;
            *slot = value;
        }
    }
    *rpath_out = rpath;
    *runpath_out = runpath;
    return 0;
}

static int dl_object_flags_1(const struct loaded_obj *obj,
                             uint64_t *flags_out)
{
    uint64_t flags = 0;
    int seen = 0;

    if (obj && obj->dynamic) {
        for (size_t i = 0; i < obj->dynamic_count; i++) {
            if (obj->dynamic[i].d_tag != DT_FLAGS_1)
                continue;
            if (seen && flags != obj->dynamic[i].d_un.d_val)
                return -1;
            flags = obj->dynamic[i].d_un.d_val;
            seen = 1;
        }
    }
    *flags_out = flags;
    return 0;
}

static int dl_lazy_dynamic_flags_admitted(const struct loaded_obj *obj,
                                          const char *name)
{
    uint64_t flags;

    if (dl_object_flags_1(obj, &flags) < 0) {
        dl_set_error(name, ": malformed DT_FLAGS_1 metadata");
        return -1;
    }
    if (flags & DF_1_PIE) {
        dl_set_error(name, ": PIE executable cannot be loaded with dlopen");
        return -1;
    }
    if (flags & DF_1_NOOPEN) {
        dl_set_error(name, ": DF_1_NOOPEN object cannot be loaded");
        return -1;
    }
    return 0;
}

static int load_needed_from_filesystem(
    const struct loaded_obj *requester,
    const struct dl_rpath_scope *inherited_rpath,
    const struct dl_rpath_scope *child_inherited,
    const char *needed, struct loaded_obj **result)
{
    const char *rpath = NULL;
    const char *runpath = NULL;
    uint64_t flags_1 = 0;
    int rc;

    *result = NULL;
    if (!needed || !needed[0]) {
        dl_set_error("empty DT_NEEDED name", NULL);
        return -1;
    }
    if (strchr(needed, '$')) {
        dl_set_error("dynamic string tokens in library filenames are "
                     "unsupported", NULL);
        return -1;
    }
    if (dl_path_has_slash(needed)) {
        *result = load_elf_from_file(needed, child_inherited);
        return *result ? 1 : -1;
    }
    if (dl_object_search_paths(requester, &rpath, &runpath) < 0 ||
        dl_object_flags_1(requester, &flags_1) < 0) {
        dl_set_error("malformed dynamic library search metadata", NULL);
        return -1;
    }

    /* DT_RPATH is used only in the absence of DT_RUNPATH and is inherited
     * down the dependency chain. */
    if (!runpath && rpath) {
        rc = dl_search_path_list(rpath, requester, needed, 0,
                                 child_inherited, result);
        if (rc != 0)
            return rc;
    }
    /* A requester's RUNPATH suppresses only that object's RPATH.  RPATH
     * scopes inherited from loader ancestors remain applicable. */
    for (const struct dl_rpath_scope *scope = inherited_rpath;
         scope; scope = scope->parent) {
        rc = dl_search_path_list(scope->path, scope->owner, needed, 0,
                                 child_inherited, result);
        if (rc != 0)
            return rc;
    }

    if (!g_fake_libc_enable_secure) {
        const char *library_path =
            vfs_find_env_value(g_envp, "LD_LIBRARY_PATH");

        if (library_path) {
            /* glibc accepts both ':' and ';' here, while musl treats ';'
             * as an ordinary filename byte.  Preserve the selected target
             * runtime's grammar instead of imposing the bootstrap libc's. */
            rc = dl_search_path_list(library_path, NULL, needed,
                                     !g_is_musl_runtime,
                                     child_inherited, result);
            if (rc != 0)
                return rc;
        }
    }

    if (runpath) {
        rc = dl_search_path_list(runpath, requester, needed, 0,
                                 child_inherited, result);
        if (rc != 0)
            return rc;
    }

    if (flags_1 & DF_1_NODEFLIB)
        return 0;

    for (const char **dir = g_runtime_search_dirs; *dir; dir++) {
        char candidate[PATH_MAX];

        rc = snprintf(candidate, sizeof(candidate), "%s/%s", *dir, needed);
        if (rc < 0 || (size_t)rc >= sizeof(candidate))
            continue;
        rc = dl_try_runtime_candidate(candidate, child_inherited, result);
        if (rc != 0)
            return rc;
    }
    return 0;
}

static int dl_load_needed(struct loaded_obj *obj,
                          const struct dlfrz_lib_meta *meta,
                          const struct dl_rpath_scope *inherited_rpath)
{
    const char *rpath = NULL;
    const char *runpath = NULL;
    struct dl_rpath_scope own_rpath;
    const struct dl_rpath_scope *child_inherited = inherited_rpath;

    (void)meta;
    if (!obj->dynamic || !obj->dynstr)
        return 0;
    if (dl_object_search_paths(obj, &rpath, &runpath) < 0) {
        dl_set_error(obj->name, ": malformed library search metadata");
        return -1;
    }
    if (!runpath && rpath) {
        own_rpath.path = rpath;
        own_rpath.owner = obj;
        own_rpath.parent = inherited_rpath;
        child_inherited = &own_rpath;
    }

    for (size_t i = 0; i < obj->dynamic_count; i++) {
        const char *needed;
        struct loaded_obj *dependency = NULL;
        int found = 0;

        if (obj->dynamic[i].d_tag != DT_NEEDED)
            continue;
        if (obj->dynamic[i].d_un.d_val > UINT32_MAX) {
            dl_set_error(obj->name, ": malformed DT_NEEDED offset");
            return -1;
        }
        needed = loaded_dynstr_value(
            obj, (uint32_t)obj->dynamic[i].d_un.d_val);
        if (!needed || !needed[0]) {
            dl_set_error(obj->name, ": malformed DT_NEEDED name");
            return -1;
        }
        if (dl_is_virtual_runtime_object(needed))
            continue;

        for (int j = 0; j < g_nobj; j++) {
            if (dl_loaded_dependency_matches(&g_all_objs[j], needed)) {
                dependency = &g_all_objs[j];
                found = 1;
                break;
            }
        }
        if (found) {
            if (dl_add_dependency_edge(obj, dependency, g_nobj) < 0) {
                dl_set_error(obj->name,
                             ": invalid or excessive DT_NEEDED graph");
                return -1;
            }
            continue;
        }

        if (g_frozen_metas) {
            for (uint32_t fi = 0; fi < g_frozen_num_entries; fi++) {
                const char *frozen_name;

                if (g_frozen_metas[fi].flags &
                    (LDR_FLAG_INTERP | LDR_FLAG_DATA))
                    continue;
                if (!(g_frozen_metas[fi].flags & LDR_FLAG_SHLIB))
                    continue;
                frozen_name = g_frozen_strtab +
                    g_frozen_entries[fi].name_offset;
                if (!dl_dependency_name_matches(frozen_name, needed))
                    continue;
                dependency = load_embedded_object(fi, child_inherited);
                if (!dependency)
                    return -1;
                found = 1;
                break;
            }
        }
        if (found) {
            if (dl_add_dependency_edge(obj, dependency, g_nobj) < 0) {
                dl_set_error(obj->name,
                             ": invalid or excessive DT_NEEDED graph");
                return -1;
            }
            continue;
        }

        int rc = load_needed_from_filesystem(
            obj, inherited_rpath, child_inherited, needed, &dependency);
        if (rc < 0)
            return -1;
        if (rc == 0 || !dependency) {
            dl_set_error(needed, ": required shared object was not found");
            return -1;
        }
        if (dl_add_dependency_edge(obj, dependency, g_nobj) < 0) {
            dl_set_error(obj->name,
                         ": invalid or excessive DT_NEEDED graph");
            return -1;
        }
    }
    return 0;
}

static void dl_transaction_begin(void)
{
    memset(&g_dl_transaction, 0, sizeof(g_dl_transaction));
    g_dl_transaction.active = 1;
    g_dl_transaction.start_nobj = g_nobj;
    g_dl_transaction.high_water = g_nobj;
    g_dl_transaction.start_strbuf_used = g_dl_strbuf_used;
    g_dl_transaction.start_init_order_count = g_init_order_count;
    g_dl_transaction.start_global_scope_count = g_global_scope_count;
#if defined(__aarch64__)
    g_dl_transaction.start_tlsdesc_page = g_aarch64_tlsdesc_pages;
    if (g_aarch64_tlsdesc_pages)
        g_dl_transaction.start_tlsdesc_used =
            g_aarch64_tlsdesc_pages->used;
#elif defined(__x86_64__)
    g_dl_transaction.start_tlsdesc_page = g_x86_64_tlsdesc_pages;
    if (g_x86_64_tlsdesc_pages)
        g_dl_transaction.start_tlsdesc_used =
            g_x86_64_tlsdesc_pages->used;
#endif
}

static int dl_assign_new_object_scope(struct loaded_obj *obj)
{
    int index;
    int root;

    if (!dl_object_table_index(obj, g_nobj, &index))
        return -1;
    if (g_dl_transaction.active) {
        if (!g_dl_transaction.scope_root_valid) {
            g_dl_transaction.scope_root = index;
            g_dl_transaction.scope_root_valid = 1;
        }
        root = g_dl_transaction.scope_root;
    } else {
        root = index;
    }
    return dl_set_relocation_scope_root(obj, root, g_nobj);
}

static int dl_transaction_finalize_lookup_scope(void)
{
    struct loaded_obj *root;
    uint8_t reachable[MAX_TOTAL_OBJS];

    if (!g_dl_transaction.active ||
        !g_dl_transaction.scope_root_valid ||
        g_dl_transaction.scope_root < g_dl_transaction.start_nobj ||
        g_dl_transaction.scope_root >= g_nobj)
        return -1;
    root = &g_all_objs[g_dl_transaction.scope_root];
    if (dl_build_lookup_scope(root, g_nobj) < 0)
        return -1;
    memset(reachable, 0, sizeof(reachable));
    for (uint16_t i = 0; i < root->lookup_scope_count; i++) {
        uint16_t index = root->lookup_scope_indices[i];

        if (index >= g_nobj)
            return -1;
        reachable[index] = 1;
    }
    for (int i = g_dl_transaction.start_nobj; i < g_nobj; i++) {
        if (!reachable[i] ||
            dl_set_relocation_scope_root(
                &g_all_objs[i], g_dl_transaction.scope_root, g_nobj) < 0)
            return -1;
    }
    return 0;
}

static void dl_transaction_note_mapping(int index)
{
    if (g_dl_transaction.active &&
        index + 1 > g_dl_transaction.high_water)
        g_dl_transaction.high_water = index + 1;
}

static int dl_transaction_stage_tls_block(struct loaded_obj *obj,
                                          uintptr_t *tls_base_out)
{
    ptrdiff_t index;
    size_t slot;
    uintptr_t tls_base;

    if (!g_dl_transaction.active || !obj)
        return 0;
    index = obj - g_all_objs;
    if (index < g_dl_transaction.start_nobj || index < 0 ||
        index >= MAX_TOTAL_OBJS)
        return 0;
    if (!runtime_tls_template_valid(obj) || obj->tls.memsz == 0 ||
        obj->tls.modid == 0 || obj->tls.modid > MAX_TOTAL_OBJS)
        return -1;
    if (g_dl_transaction.tls_bases[obj->tls.modid]) {
        *tls_base_out = g_dl_transaction.tls_bases[obj->tls.modid];
        return 1;
    }
    slot = g_dl_transaction.tls_map_count;
    if (slot >= MAX_TOTAL_OBJS ||
        allocate_runtime_tls_block(
            obj, &g_dl_transaction.tls_maps[slot],
            &g_dl_transaction.tls_map_lengths[slot], &tls_base) < 0)
        return -1;
    g_dl_transaction.tls_bases[obj->tls.modid] = tls_base;
    g_dl_transaction.tls_map_count++;
    *tls_base_out = tls_base;
    return 1;
}

static int dl_transaction_tls_address(uintptr_t tp, unsigned long modid,
                                      unsigned long ti_offset,
                                      void **address_out)
{
    struct loaded_obj *obj = NULL;
    uintptr_t tls_base;
    int staged;

    if (!g_dl_transaction.active)
        return 0;
    if (tp != arch_get_tp())
        return -1;
    for (int i = g_dl_transaction.start_nobj; i < g_nobj; i++) {
        if (g_all_objs[i].tls.modid == modid &&
            g_all_objs[i].tls.memsz != 0) {
            obj = &g_all_objs[i];
            break;
        }
    }
    if (!obj)
        return 0;
    staged = dl_transaction_stage_tls_block(obj, &tls_base);
    if (staged <= 0 ||
        !runtime_tls_address(obj, tls_base, ti_offset, address_out))
        return -1;
    return 1;
}

static int dl_transaction_queue_init(struct loaded_obj *obj)
{
    if (!g_dl_transaction.active)
        return -1;
    if (g_dl_transaction.pending_init_count >= MAX_TOTAL_OBJS) {
        dl_set_error("too many pending dlopen constructors", NULL);
        return -1;
    }
    g_dl_transaction.pending_init[
        g_dl_transaction.pending_init_count++] = obj;
    return 0;
}

static void dl_transaction_unmap_tls_blocks(void **maps,
                                            const size_t *map_lengths,
                                            size_t count);

static void dl_release_runtime_mapping(struct loaded_obj *obj)
{
    if (obj && obj->runtime_reservation && obj->runtime_reservation_size)
        munmap(obj->runtime_reservation, obj->runtime_reservation_size);
    if (obj) {
        obj->runtime_reservation = NULL;
        obj->runtime_reservation_size = 0;
    }
}

static void dl_transaction_rollback(void)
{
    int high_water = g_dl_transaction.high_water;
    int start = g_dl_transaction.start_nobj;

    if (!g_dl_transaction.active)
        return;
    dl_transaction_unmap_tls_blocks(
        g_dl_transaction.tls_maps,
        g_dl_transaction.tls_map_lengths,
        g_dl_transaction.tls_map_count);
#if defined(__aarch64__)
    while (g_aarch64_tlsdesc_pages && g_aarch64_tlsdesc_pages !=
           g_dl_transaction.start_tlsdesc_page) {
        struct aarch64_tlsdesc_page *page = g_aarch64_tlsdesc_pages;

        g_aarch64_tlsdesc_pages = page->next;
        munmap(page, 4096);
    }
    if (g_aarch64_tlsdesc_pages)
        g_aarch64_tlsdesc_pages->used =
            g_dl_transaction.start_tlsdesc_used;
#elif defined(__x86_64__)
    while (g_x86_64_tlsdesc_pages && g_x86_64_tlsdesc_pages !=
           g_dl_transaction.start_tlsdesc_page) {
        struct x86_64_tlsdesc_page *page = g_x86_64_tlsdesc_pages;

        g_x86_64_tlsdesc_pages = page->next;
        munmap(page, 4096);
    }
    if (g_x86_64_tlsdesc_pages)
        g_x86_64_tlsdesc_pages->used =
            g_dl_transaction.start_tlsdesc_used;
#endif
    if (high_water > MAX_TOTAL_OBJS)
        high_water = MAX_TOTAL_OBJS;
    for (int i = high_water - 1; i >= start; i--) {
        struct loaded_obj *obj = &g_all_objs[i];

        dl_release_runtime_mapping(obj);
        memset(obj, 0, sizeof(*obj));
        memset(&g_dl_metas[i], 0, sizeof(g_dl_metas[i]));
    }
    g_nobj = start;
    g_dl_strbuf_used = g_dl_transaction.start_strbuf_used;
    g_init_order_count = g_dl_transaction.start_init_order_count;
    g_global_scope_count = g_dl_transaction.start_global_scope_count;
    memset(&g_dl_transaction, 0, sizeof(g_dl_transaction));
    clear_resolution_caches();
}

static void dl_transaction_unmap_tls_blocks(void **maps,
                                            const size_t *map_lengths,
                                            size_t count)
{
    while (count > 0) {
        count--;
        if (maps[count] && map_lengths[count])
            munmap(maps[count], map_lengths[count]);
    }
}

static int dl_transaction_publish_musl_tls(struct loaded_obj **objects,
                                           size_t count)
{
    uintptr_t *old_dtv;
    uintptr_t *new_dtv;
    uintptr_t tp;
    size_t old_slots = 0;
    size_t new_slots = 0;
    uint64_t words;
    uint64_t bytes_u64;
    size_t bytes;

    for (size_t i = 0; i < count; i++) {
        struct loaded_obj *obj = objects[i];

        if (obj->tls.memsz == 0)
            continue;
        if (!runtime_tls_template_valid(obj) || obj->tls.modid == 0 ||
            obj->tls.modid > MAX_TOTAL_OBJS)
            return -1;
        if (obj->tls.modid > new_slots)
            new_slots = obj->tls.modid;
    }
    if (new_slots == 0)
        return 0;

    tp = arch_get_tp();
    if (!tp)
        return -1;
    old_dtv = *(uintptr_t **)musl_thread_dtv_slot(tp);
    if (old_dtv) {
        old_slots = old_dtv[0];
        if (old_slots > MAX_TOTAL_OBJS)
            return -1;
        if (old_slots > new_slots)
            new_slots = old_slots;
    }
    if (!u64_add_checked(new_slots, 1, &words) ||
        !u64_mul_checked(words, sizeof(uintptr_t), &words) ||
        !u64_align_up_checked(words, g_page_size, &bytes_u64) ||
        bytes_u64 == 0 || bytes_u64 > SIZE_MAX)
        return -1;
    bytes = (size_t)bytes_u64;
    new_dtv = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (new_dtv == MAP_FAILED)
        return -1;
    if (old_dtv)
        memcpy(new_dtv, old_dtv,
               (old_slots + 1) * sizeof(uintptr_t));
    new_dtv[0] = new_slots;

    for (size_t i = 0; i < count; i++) {
        struct loaded_obj *obj = objects[i];
        uintptr_t tls_base;

        if (obj->tls.memsz == 0)
            continue;
        if (old_dtv && obj->tls.modid <= old_slots &&
            old_dtv[obj->tls.modid]) {
            if (g_dl_transaction.tls_bases[obj->tls.modid]) {
                munmap(new_dtv, bytes);
                return -1;
            }
            continue;
        }
        if (dl_transaction_stage_tls_block(obj, &tls_base) <= 0) {
            munmap(new_dtv, bytes);
            return -1;
        }
        new_dtv[obj->tls.modid] = tls_base;
    }

    /* This is the transaction's sole publication point.  No target-visible
     * DTV slot changes until every allocation above has succeeded. */
    *(uintptr_t **)musl_thread_dtv_slot(tp) = new_dtv;
    return 0;
}

static int dl_transaction_publish_glibc_tls(struct loaded_obj **objects,
                                            size_t count)
{
    uintptr_t *old_dtv;
    uintptr_t *new_raw;
    uintptr_t *new_dtv;
    uintptr_t tp;
    size_t old_capacity = 0;
    size_t new_capacity = 0;
    size_t static_capacity = 0;
    size_t map_size;

    for (size_t i = 0; i < count; i++) {
        struct loaded_obj *obj = objects[i];

        if (obj->tls.memsz == 0)
            continue;
        if (!runtime_tls_template_valid(obj) || obj->tls.modid == 0 ||
            obj->tls.modid > MAX_TOTAL_OBJS)
            return -1;
        if (obj->tls.modid > new_capacity)
            new_capacity = obj->tls.modid;
    }
    if (new_capacity == 0)
        return 0;

    tp = arch_get_tp();
    if (!tp)
        return -1;
    old_dtv = *(uintptr_t **)(tp + TCB_OFF_DTV);
    if (!glibc_dtv_capacity(old_dtv, &old_capacity) ||
        !glibc_static_tls_capacity(&static_capacity))
        return -1;
    if (old_capacity > new_capacity)
        new_capacity = old_capacity;
    if (static_capacity > new_capacity)
        new_capacity = static_capacity;
    if (!glibc_dtv_map_size(new_capacity, &map_size))
        return -1;
    new_raw = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (new_raw == MAP_FAILED)
        return -1;
    new_dtv = new_raw + 2;
    if (old_dtv) {
        uint64_t entries;
        uint64_t words;
        uint64_t copy_bytes;

        if (!u64_add_checked(old_capacity, 1, &entries) ||
            !u64_mul_checked(entries, 2, &words) ||
            !u64_add_checked(words, 2, &words) ||
            !u64_mul_checked(words, sizeof(uintptr_t), &copy_bytes) ||
            copy_bytes > map_size) {
            munmap(new_raw, map_size);
            return -1;
        }
        memcpy(new_raw, old_dtv - 2, (size_t)copy_bytes);
    }
    new_raw[0] = new_capacity;
    if (!old_dtv)
        new_raw[1] = 0;
    new_dtv[0] = 1;
    if (!old_dtv)
        new_dtv[1] = 0;
    if (!glibc_seed_static_tls_slots(tp, new_dtv, new_capacity)) {
        munmap(new_raw, map_size);
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        struct loaded_obj *obj = objects[i];
        uintptr_t tls_base;

        if (obj->tls.memsz == 0)
            continue;
        if (old_dtv && obj->tls.modid <= old_capacity &&
            glibc_tls_slot_allocated(old_dtv[obj->tls.modid * 2])) {
            if (g_dl_transaction.tls_bases[obj->tls.modid]) {
                munmap(new_raw, map_size);
                return -1;
            }
            continue;
        }
        if (dl_transaction_stage_tls_block(obj, &tls_base) <= 0) {
            munmap(new_raw, map_size);
            return -1;
        }
        new_dtv[obj->tls.modid * 2] = tls_base;
        new_dtv[obj->tls.modid * 2 + 1] = 0;
    }

    /* Publish the completely populated replacement DTV atomically. */
    *(uintptr_t **)(tp + TCB_OFF_DTV) = new_dtv;
    return 0;
}

static int dl_transaction_commit(void)
{
    struct loaded_obj *pending[MAX_TOTAL_OBJS];
    size_t count;

    if (!g_dl_transaction.active)
        return -1;
    if (dl_transaction_finalize_lookup_scope() < 0) {
        dl_set_error("dlopen dependency graph",
                     ": cannot establish lookup scope");
        return -1;
    }
    count = g_dl_transaction.pending_init_count;
    memcpy(pending, g_dl_transaction.pending_init,
           count * sizeof(pending[0]));

    /* Dependency discovery deliberately maps the complete graph before any
     * relocation.  A dependency may resolve an undefined symbol from a
     * later sibling in the requester's DT_NEEDED list. */
    clear_resolution_caches();
    if (preflight_resolver_relocation_destinations(
            g_all_objs + g_dl_transaction.start_nobj,
            g_nobj - g_dl_transaction.start_nobj,
            g_all_objs, g_nobj) < 0) {
        dl_set_error("dlopen dependency graph",
                     ": resolver relocation targets PT_TLS");
        return -1;
    }
    for (size_t i = 0; i < count; i++) {
        struct loaded_obj *obj = pending[i];

        if (preseed_rtld_got(obj, g_all_objs, g_nobj) < 0) {
            dl_set_error(obj->name ? obj->name : "dlopen object",
                         ": malformed relocation metadata");
            return -1;
        }
    }
    /* Filesystem probing above uses bootstrap-libc errno state.  Restore the
     * target libc guard before any phase can invoke target code. */
    restore_ptr_guard();
    for (size_t i = 0; i < count; i++) {
        struct loaded_obj *obj = pending[i];

        if (apply_all_relocs(obj, g_all_objs, g_nobj,
                             RELOC_PASS_ORDINARY) < 0) {
            dl_set_error(obj->name ? obj->name : "dlopen object",
                         ": relocation failed");
            return -1;
        }
    }
    for (size_t i = 0; i < count; i++) {
        struct loaded_obj *obj = pending[i];

        if (apply_all_relocs(obj, g_all_objs, g_nobj,
                             RELOC_PASS_COPY) < 0) {
            dl_set_error(obj->name ? obj->name : "dlopen object",
                         ": COPY relocation failed");
            return -1;
        }
    }
    for (size_t i = 0; i < count; i++) {
        struct loaded_obj *obj = pending[i];

        if (apply_all_relocs(obj, g_all_objs, g_nobj,
                             RELOC_PASS_IFUNC) < 0) {
            dl_set_error(obj->name ? obj->name : "dlopen object",
                         ": IFUNC relocation failed");
            return -1;
        }
    }
    for (size_t i = 0; i < count; i++) {
        struct loaded_obj *obj = pending[i];

        if (apply_all_relocs(obj, g_all_objs, g_nobj,
                             RELOC_PASS_IRELATIVE) < 0) {
            dl_set_error(obj->name ? obj->name : "dlopen object",
                         ": IRELATIVE failed");
            return -1;
        }
    }
    for (size_t i = 0; i < count; i++) {
        struct loaded_obj *obj = pending[i];
        ptrdiff_t index = obj - g_all_objs;

        if (index < g_dl_transaction.start_nobj || index < 0 ||
            index >= g_nobj || protect_object(obj, &g_dl_metas[index]) < 0) {
            dl_set_error(obj->name ? obj->name : "dlopen object",
                         ": cannot set final memory protections");
            return -1;
        }
    }

    if (dl_append_lookup_scope_to_global(
            &g_all_objs[g_dl_transaction.scope_root], g_nobj) < 0) {
        dl_set_error("dlopen dependency graph",
                     ": cannot publish lookup scope");
        return -1;
    }

    /* Build a replacement DTV and all dynamic TLS blocks privately, then
     * publish one pointer only after every allocation succeeds. */
    if ((g_is_musl_runtime
             ? dl_transaction_publish_musl_tls(pending, count)
             : dl_transaction_publish_glibc_tls(pending, count)) < 0) {
        dl_set_error("dlopen dependency graph", ": TLS setup failed");
        return -1;
    }

    /* Mark the transaction committed before invoking user constructors so a
     * constructor may itself start an independent recursive dlopen. */
    memset(&g_dl_transaction, 0, sizeof(g_dl_transaction));
    restore_ptr_guard();
    for (size_t i = 0; i < count; i++) {
        struct loaded_obj *obj = pending[i];
        typedef void (*init_fn_t)(int, char **, char **);

        record_object_init(obj);
        if (obj->init_func)
            ((init_fn_t)obj->init_func)(g_argc, g_argv, g_envp);
        for (size_t j = 0; j < obj->init_array_sz; j++)
            ((init_fn_t)obj->init_array[j])(g_argc, g_argv, g_envp);
    }
    return 0;
}

/*
 * Load an ELF shared object from the filesystem.
 * Maps PT_LOAD segments, resolves symbols, applies relocations,
 * calls init functions.  Returns pointer to loaded_obj or NULL.
 */
static struct loaded_obj *load_elf_from_file(
    const char *path, const struct dl_rpath_scope *inherited_rpath)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd < 0) {
        dl_set_error(path, ": cannot open");
        return NULL;
    }
    return load_elf_from_file_fd(path, fd, inherited_rpath);
}

static struct loaded_obj *load_elf_from_file_fd(
    const char *path, int fd,
    const struct dl_rpath_scope *inherited_rpath)
{
    struct stat identity;
    int idx = g_nobj;

    if (fstat(fd, &identity) < 0) {
        close(fd);
        dl_set_error(path, ": cannot identify shared object");
        return NULL;
    }
    for (int i = 0; i < g_nobj; i++) {
        struct loaded_obj *existing = &g_all_objs[i];

        if (existing->runtime_identity_valid &&
            existing->runtime_dev == (uint64_t)identity.st_dev &&
            existing->runtime_ino == (uint64_t)identity.st_ino) {
            close(fd);
            return existing;
        }
    }
    if (idx >= MAX_TOTAL_OBJS) {
        close(fd);
        dl_set_error("too many loaded objects", NULL);
        return NULL;
    }

    Elf64_Ehdr ehdr;
    Elf64_Phdr phdr_buf[64];
    uint64_t file_size;

    if (read_runtime_dso_headers(fd, &ehdr, phdr_buf,
                                 sizeof(phdr_buf) / sizeof(phdr_buf[0]),
                                 &file_size) < 0) {
        close(fd);
        dl_set_error(path, ": malformed ELF program headers");
        return NULL;
    }
    (void)file_size;
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        if (phdr_buf[i].p_type == PT_INTERP) {
            close(fd);
            dl_set_error(path,
                         ": PT_INTERP executable cannot be loaded with "
                         "dlopen");
            return NULL;
        }
    }

    /* Refuse libraries built with DF_STATIC_TLS — they cannot be loaded
     * after startup without overwriting the calling thread's static TLS
     * area.  Surface this as a normal dlopen failure so callers can fall
     * back to alternative plugins instead of corrupting process TLS. */
    int static_tls = dynamic_has_static_tls(fd, phdr_buf, ehdr.e_phnum);
    if (static_tls < 0) {
        close(fd);
        dl_set_error(path, ": malformed dynamic section");
        return NULL;
    }
    if (static_tls) {
        close(fd);
        dl_set_error(path,
            ": cannot dlopen DF_STATIC_TLS library after startup "
            "(would clobber main thread TLS)");
        if (g_debug) {
            ldr_msg("[loader] refusing dlopen of DF_STATIC_TLS lib: ");
            ldr_msg(path);
            ldr_msg("\n");
        }
        return NULL;
    }
    size_t phdr_size = (size_t)ehdr.e_phnum * sizeof(Elf64_Phdr);

    /* Determine vaddr range from PT_LOAD segments */
    uint64_t lo = UINT64_MAX, hi = 0, phdr_vaddr = UINT64_MAX;
    uint64_t max_load_align = g_page_size;
    uint64_t phdr_file_end = ehdr.e_phoff + phdr_size;
    for (int i = 0; i < ehdr.e_phnum; i++) {
        if (phdr_buf[i].p_type != PT_LOAD) continue;
        if (phdr_buf[i].p_align > max_load_align)
            max_load_align = phdr_buf[i].p_align;
        if (phdr_buf[i].p_vaddr < lo) lo = phdr_buf[i].p_vaddr;
        uint64_t end = phdr_buf[i].p_vaddr + phdr_buf[i].p_memsz;
        if (end > hi) hi = end;
        if (ehdr.e_phoff >= phdr_buf[i].p_offset &&
            phdr_file_end >= ehdr.e_phoff &&
            phdr_file_end - phdr_buf[i].p_offset <=
                phdr_buf[i].p_filesz)
            phdr_vaddr = phdr_buf[i].p_vaddr +
                         (ehdr.e_phoff - phdr_buf[i].p_offset);
    }
    if (lo >= hi || phdr_vaddr == UINT64_MAX || phdr_vaddr > UINT32_MAX) {
        close(fd);
        dl_set_error(path, ": no PT_LOAD segments");
        return NULL;
    }

    lo = page_floor(lo);
    if (!u64_align_up_checked(hi, g_page_size, &hi) || hi <= lo ||
        g_page_size > UINT64_MAX / 4 ||
        hi - lo > UINT64_MAX - 4 * g_page_size) {
        close(fd);
        dl_set_error(path, ": invalid PT_LOAD address range");
        return NULL;
    }
    uint64_t span = hi - lo + 4 * g_page_size;  /* + guard pages */
    uint64_t reservation_len;
    if (span > SIZE_MAX || max_load_align > UINT64_MAX - span) {
        close(fd);
        dl_set_error(path, ": PT_LOAD address range is too large");
        return NULL;
    }
    reservation_len = span + max_load_align;
    if (reservation_len > SIZE_MAX) {
        close(fd);
        dl_set_error(path, ": PT_LOAD alignment range is too large");
        return NULL;
    }

    /* Reserve the whole range, but leave holes and guard pages inaccessible. */
    void *reservation = mmap(NULL, (size_t)reservation_len, PROT_NONE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reservation == MAP_FAILED) {
        close(fd);
        dl_set_error(path, ": mmap failed");
        return NULL;
    }

    uint64_t reservation_addr = (uint64_t)(uintptr_t)reservation;
    uint64_t base;
    if (reservation_addr < lo ||
        !u64_align_up_checked(reservation_addr - lo, max_load_align, &base) ||
        base > UINT64_MAX - lo || base + lo < reservation_addr ||
        base + lo - reservation_addr > reservation_len - span) {
        munmap(reservation, (size_t)reservation_len);
        close(fd);
        dl_set_error(path, ": cannot align PT_LOAD base address");
        return NULL;
    }

    /* Map/copy each PT_LOAD segment from the file */
    for (int i = 0; i < ehdr.e_phnum; i++) {
        if (phdr_buf[i].p_type != PT_LOAD) continue;
        if (phdr_buf[i].p_filesz > 0 &&
            (phdr_buf[i].p_vaddr - page_floor(phdr_buf[i].p_vaddr)) ==
                (phdr_buf[i].p_offset - page_floor(phdr_buf[i].p_offset))) {
            uint64_t seg_lo  = page_floor(phdr_buf[i].p_vaddr);
            uint64_t seg_off = page_floor(phdr_buf[i].p_offset);
            uint64_t delta   = phdr_buf[i].p_vaddr - seg_lo;
            uint64_t map_input;
            uint64_t map_len;

            if (!u64_add_checked(delta, phdr_buf[i].p_filesz,
                                 &map_input) ||
                !u64_align_up_checked(map_input, g_page_size, &map_len) ||
                map_len > SIZE_MAX || seg_lo < lo || seg_lo > hi ||
                map_len > hi - seg_lo) {
                munmap(reservation, (size_t)reservation_len);
                close(fd);
                dl_set_error(path, ": invalid PT_LOAD mapping range");
                return NULL;
            }

            void *m = mmap((void *)(base + seg_lo), (size_t)map_len,
                           phdr_prot(&phdr_buf[i]),
                           MAP_PRIVATE | MAP_FIXED, fd, seg_off);
            if (m == MAP_FAILED) {
                if (make_file_range_writable(base, &phdr_buf[i]) < 0 ||
                    pread(fd, (void *)(base + phdr_buf[i].p_vaddr),
                          phdr_buf[i].p_filesz, phdr_buf[i].p_offset) !=
                        (ssize_t)phdr_buf[i].p_filesz) {
                    munmap(reservation, (size_t)reservation_len);
                    close(fd);
                    dl_set_error(path, ": cannot map segment");
                    return NULL;
                }
            }
        } else if (phdr_buf[i].p_filesz > 0) {
            if (make_file_range_writable(base, &phdr_buf[i]) < 0 ||
                pread(fd, (void *)(base + phdr_buf[i].p_vaddr),
                      phdr_buf[i].p_filesz, phdr_buf[i].p_offset) !=
                    (ssize_t)phdr_buf[i].p_filesz) {
                munmap(reservation, (size_t)reservation_len);
                close(fd);
                dl_set_error(path, ": cannot read segment");
                return NULL;
            }
        }
        if (zero_segment_bss_tail(base, &phdr_buf[i]) < 0) {
            munmap(reservation, (size_t)reservation_len);
            close(fd);
            dl_set_error(path, ": cannot zero segment tail");
            return NULL;
        }
    }

    for (int i = 0; i < ehdr.e_phnum; i++) {
        if (phdr_buf[i].p_type == PT_LOAD &&
            set_segment_protection(base, &phdr_buf[i],
                                   phdr_prot(&phdr_buf[i])) < 0) {
            munmap(reservation, (size_t)reservation_len);
            close(fd);
            dl_set_error(path, ": cannot protect segment");
            return NULL;
        }
    }

    close(fd);

    /* Set up loaded_obj entry */
    struct loaded_obj *obj = &g_all_objs[idx];
    memset(obj, 0, sizeof(*obj));
    obj->base  = base;
    obj->name  = dl_store_name(path);
    if (!obj->name) {
        dl_set_error(path, ": dlopen name storage exhausted");
        munmap(reservation, (size_t)reservation_len);
        memset(obj, 0, sizeof(*obj));
        return NULL;
    }
    obj->flags = LDR_FLAG_SHLIB;
    obj->phdr  = (const Elf64_Phdr *)(base + phdr_vaddr);
    obj->phdr_num  = ehdr.e_phnum;
    obj->map_start = base + lo;
    obj->map_end   = base + hi;
    obj->runtime_reservation = reservation;
    obj->runtime_reservation_size = (size_t)reservation_len;
    obj->runtime_dev = (uint64_t)identity.st_dev;
    obj->runtime_ino = (uint64_t)identity.st_ino;
    obj->runtime_identity_valid = 1;
    dl_transaction_note_mapping(idx);
    if (discover_eh_frame_header(obj) < 0) {
        dl_release_runtime_mapping(obj);
        dl_set_error(path, ": malformed PT_GNU_EH_FRAME");
        return NULL;
    }

    /* Build metadata for parse_dynamic / protect_object */
    struct dlfrz_lib_meta *meta = &g_dl_metas[idx];
    memset(meta, 0, sizeof(*meta));
    meta->base_addr  = base;
    meta->vaddr_lo   = lo;
    meta->vaddr_hi   = hi;
    meta->phdr_off   = phdr_vaddr;
    meta->phdr_num   = ehdr.e_phnum;
    meta->phdr_entsz = ehdr.e_phentsize;
    meta->flags      = LDR_FLAG_SHLIB;

    if (parse_dynamic(obj, meta) < 0) {
        dl_set_error(path, ": malformed dynamic metadata");
        dl_release_runtime_mapping(obj);
        return NULL;
    }
    if (dl_lazy_dynamic_flags_admitted(obj, path) < 0) {
        dl_release_runtime_mapping(obj);
        return NULL;
    }
    if (validate_object_relocations(obj) < 0) {
        dl_set_error(path, ": malformed relocation metadata");
        dl_release_runtime_mapping(obj);
        return NULL;
    }
    if (discover_tls_template(obj, phdr_buf, ehdr.e_phnum) < 0) {
        dl_set_error(path, ": malformed TLS program header");
        dl_release_runtime_mapping(obj);
        return NULL;
    }
    if (dl_lazy_static_tls_admitted(obj, path) < 0) {
        dl_release_runtime_mapping(obj);
        return NULL;
    }
    if (obj->tls.memsz != 0 && next_tls_modid(&obj->tls.modid) < 0) {
        dl_set_error(path, ": too many TLS modules");
        dl_release_runtime_mapping(obj);
        return NULL;
    }

    /* Bump count so symbol resolution includes this object */
    g_nobj = idx + 1;
    if (dl_assign_new_object_scope(obj) < 0) {
        dl_set_error(path, ": cannot establish dependency lookup scope");
        g_nobj = idx;
        return NULL;
    }

    /* Load DT_NEEDED dependencies before applying relocations.
     * This may recursively call load_elf_from_file and increase g_nobj. */
    if (dl_load_needed(obj, meta, inherited_rpath) < 0) {
        g_nobj = idx;
        return NULL;
    }

    /* A dlopen transaction first discovers and maps the entire dependency
     * graph.  Relocation, final protections, TLS publication, and
     * constructors are committed only after every edge has succeeded. */
    if (g_dl_transaction.active) {
        if (dl_transaction_queue_init(obj) < 0) {
            g_nobj = idx;
            return NULL;
        }
        return obj;
    }

    /* Clear cached misses — new objects may provide symbols
     * that were previously unresolvable. */
    clear_resolution_caches();

    /* Apply relocations */
    if (preseed_rtld_got(obj, g_all_objs, g_nobj) < 0) {
        dl_set_error(path, ": malformed relocation metadata");
        g_nobj = idx;
        return NULL;
    }
    if (apply_all_relocs(obj, g_all_objs, g_nobj,
                         RELOC_PASS_ORDINARY) < 0) {
        dl_set_error(path, ": relocation failed");
        g_nobj = idx;  /* roll back */
        return NULL;
    }
    if (apply_all_relocs(obj, g_all_objs, g_nobj,
                         RELOC_PASS_COPY) < 0) {
        dl_set_error(path, ": COPY relocation failed");
        g_nobj = idx;
        return NULL;
    }
    if (apply_all_relocs(obj, g_all_objs, g_nobj,
                         RELOC_PASS_IFUNC) < 0) {
        dl_set_error(path, ": IFUNC relocation failed");
        g_nobj = idx;
        return NULL;
    }
    if (apply_all_relocs(obj, g_all_objs, g_nobj,
                         RELOC_PASS_IRELATIVE) < 0) {
        dl_set_error(path, ": IRELATIVE failed");
        g_nobj = idx;
        return NULL;
    }
    if (!g_dl_transaction.active) {
        if (install_musl_dlopen_tls(obj) < 0) {
            dl_set_error(path, ": musl TLS setup failed");
            g_nobj = idx;
            return NULL;
        }
        if (install_glibc_dlopen_tls(obj) < 0) {
            dl_set_error(path, ": glibc TLS setup failed");
            g_nobj = idx;
            return NULL;
        }
    }

    /* Set final memory protections */
    if (protect_object(obj, meta) < 0) {
        dl_set_error(path, ": cannot set final memory protections");
        g_nobj = idx;
        return NULL;
    }

    if (g_dl_transaction.active) {
        if (dl_transaction_queue_init(obj) < 0) {
            g_nobj = idx;
            return NULL;
        }
    } else {
        /* Restore pointer_guard before calling init functions — the
         * bootstrap libc may have corrupted it via errno writes. */
        typedef void (*init_fn_t)(int, char **, char **);

        restore_ptr_guard();
        record_object_init(obj);
        if (obj->init_func)
            ((init_fn_t)obj->init_func)(g_argc, g_argv, g_envp);
        for (size_t j = 0; j < obj->init_array_sz; j++)
            ((init_fn_t)obj->init_array[j])(g_argc, g_argv, g_envp);
    }

    ldr_dbg("[loader] dlopen: ");
    ldr_dbg(dl_basename(path));
    ldr_dbg_hex(" base=0x", base);

    return obj;
}

/* Pseudo-handle for dlopen(NULL) — search all loaded objects */
#define DL_GLOBAL_HANDLE ((void *)(uintptr_t)1)

/*
 * Load an object from the frozen image (for DLFRZ_FLAG_DLOPEN entries).
 * Uses the same map/parse/relocate/init flow as load_elf_from_file but
 * reads data from the frozen payload instead of the filesystem.
 */
static struct loaded_obj *load_embedded_object(
    uint32_t mi, const struct dl_rpath_scope *inherited_rpath)
{
    int idx = g_nobj;
    if (idx >= MAX_TOTAL_OBJS) {
        dl_set_error("too many loaded objects", NULL);
        return NULL;
    }

    const struct dlfrz_lib_meta *emeta = &g_frozen_metas[mi];
    const struct dlfrz_entry *eent = &g_frozen_entries[mi];
    const char *ename = g_frozen_strtab + eent->name_offset;

    struct loaded_obj *obj = &g_all_objs[idx];
    memset(obj, 0, sizeof(*obj));

    /* Map segments from the frozen image at the pre-assigned base */
    if (map_object(g_frozen_mem, g_frozen_mem_foff, g_frozen_srcfd,
                   emeta, eent, obj, 0) < 0) {
        dl_set_error(ename, ": mmap failed");
        if (obj->runtime_reservation && obj->runtime_reservation_size)
            munmap(obj->runtime_reservation,
                   obj->runtime_reservation_size);
        memset(obj, 0, sizeof(*obj));
        return NULL;
    }
    dl_transaction_note_mapping(idx);

    obj->name     = ename;
    obj->flags    = emeta->flags;
    obj->phdr     = (const Elf64_Phdr *)(obj->base + emeta->phdr_off);
    obj->phdr_num = emeta->phdr_num;
    obj->map_start = obj->base + emeta->vaddr_lo;
    obj->map_end   = obj->base + emeta->vaddr_hi;

    for (uint16_t i = 0; i < obj->phdr_num; i++) {
        if (obj->phdr[i].p_type == PT_INTERP) {
            dl_set_error(ename,
                         ": PT_INTERP executable cannot be loaded with "
                         "dlopen");
            return NULL;
        }
    }

    if (discover_eh_frame_header(obj) < 0) {
        dl_set_error(ename, ": malformed PT_GNU_EH_FRAME");
        return NULL;
    }

    /* Store metadata for protect_object */
    struct dlfrz_lib_meta *meta = &g_dl_metas[idx];
    *meta = *emeta;

    if (parse_dynamic(obj, meta) < 0) {
        dl_set_error(ename, ": malformed dynamic metadata");
        return NULL;
    }
    if (dl_lazy_dynamic_flags_admitted(obj, ename) < 0)
        return NULL;
    if (validate_object_relocations(obj) < 0) {
        dl_set_error(ename, ": malformed relocation metadata");
        return NULL;
    }
    if (discover_tls_template(obj, obj->phdr, obj->phdr_num) < 0) {
        dl_set_error(ename, ": malformed TLS program header");
        return NULL;
    }
    if (dl_lazy_static_tls_admitted(obj, ename) < 0)
        return NULL;
    if (obj->tls.memsz != 0 && next_tls_modid(&obj->tls.modid) < 0) {
        dl_set_error(ename, ": too many TLS modules");
        return NULL;
    }

    /* Bump count so symbol resolution includes this object */
    g_nobj = idx + 1;
    if (dl_assign_new_object_scope(obj) < 0) {
        dl_set_error(ename, ": cannot establish dependency lookup scope");
        g_nobj = idx;
        return NULL;
    }

    /* A matching embedded dependency counts only after its recursive load
     * succeeds.  Any missing edge aborts the entire dlopen transaction. */
    if (dl_load_needed(obj, meta, inherited_rpath) < 0) {
        g_nobj = idx;
        return NULL;
    }

    if (g_dl_transaction.active) {
        if (dl_transaction_queue_init(obj) < 0) {
            g_nobj = idx;
            return NULL;
        }
        return obj;
    }

    /* Clear cached misses — new objects may provide previously-missing symbols */
    clear_resolution_caches();

    /* Apply relocations */
    if (preseed_rtld_got(obj, g_all_objs, g_nobj) < 0) {
        dl_set_error(ename, ": malformed relocation metadata");
        g_nobj = idx;
        return NULL;
    }
    if (apply_all_relocs(obj, g_all_objs, g_nobj,
                         RELOC_PASS_ORDINARY) < 0) {
        dl_set_error(ename, ": relocation failed");
        g_nobj = idx;
        return NULL;
    }
    if (apply_all_relocs(obj, g_all_objs, g_nobj,
                         RELOC_PASS_COPY) < 0) {
        dl_set_error(ename, ": COPY relocation failed");
        g_nobj = idx;
        return NULL;
    }
    if (apply_all_relocs(obj, g_all_objs, g_nobj,
                         RELOC_PASS_IFUNC) < 0) {
        dl_set_error(ename, ": IFUNC relocation failed");
        g_nobj = idx;
        return NULL;
    }
    if (apply_all_relocs(obj, g_all_objs, g_nobj,
                         RELOC_PASS_IRELATIVE) < 0) {
        dl_set_error(ename, ": IRELATIVE failed");
        g_nobj = idx;
        return NULL;
    }
    if (!g_dl_transaction.active) {
        if (install_musl_dlopen_tls(obj) < 0) {
            dl_set_error(ename, ": musl TLS setup failed");
            g_nobj = idx;
            return NULL;
        }
        if (install_glibc_dlopen_tls(obj) < 0) {
            dl_set_error(ename, ": glibc TLS setup failed");
            g_nobj = idx;
            return NULL;
        }
    }

    /* Set final memory protections */
    if (protect_object(obj, meta) < 0) {
        dl_set_error(ename, ": cannot set final memory protections");
        g_nobj = idx;
        return NULL;
    }

    if (g_dl_transaction.active) {
        if (dl_transaction_queue_init(obj) < 0) {
            g_nobj = idx;
            return NULL;
        }
    } else {
        typedef void (*init_fn_t)(int, char **, char **);

        restore_ptr_guard();
        record_object_init(obj);
        if (obj->init_func)
            ((init_fn_t)obj->init_func)(g_argc, g_argv, g_envp);
        for (size_t j = 0; j < obj->init_array_sz; j++)
            ((init_fn_t)obj->init_array[j])(g_argc, g_argv, g_envp);
    }

    ldr_dbg("[loader] dlopen (embedded): ");
    ldr_dbg(dl_basename(ename));
    ldr_dbg_hex(" base=0x", obj->base);

    return obj;
}

static struct loaded_obj *dl_object_for_address(void *return_address)
{
    uintptr_t address = (uintptr_t)return_address;

    for (int i = 0; i < g_nobj; i++)
        if (loaded_obj_contains(&g_all_objs[i], address, 1))
            return &g_all_objs[i];
    return NULL;
}

static void *my_dlopen(const char *path, int flags)
{
    struct loaded_obj *caller;
    struct loaded_obj *ret = NULL;
    struct dl_rpath_scope caller_rpath;
    const struct dl_rpath_scope *top_inherited = NULL;
    const char *rpath = NULL;
    const char *runpath = NULL;
    void *return_address;

    (void)flags;
    g_dlerror_valid = 0;

    if (!path)
        return DL_GLOBAL_HANDLE;
    if (g_dl_transaction.active) {
        dl_set_error("recursive dlopen during dependency relocation is "
                     "unsupported", NULL);
        return NULL;
    }
    if (strchr(path, '$')) {
        dl_set_error("dynamic string tokens in dlopen filenames are "
                     "unsupported", NULL);
        return NULL;
    }

    const char *bn = dl_basename(path);

    if (dl_is_virtual_runtime_object(bn))
        return DL_GLOBAL_HANDLE;

    for (int i = 0; i < g_nobj; i++) {
        if (dl_loaded_dependency_matches(&g_all_objs[i], path))
            return &g_all_objs[i];
    }

    return_address =
        __builtin_extract_return_addr(__builtin_return_address(0));
    caller = dl_object_for_address(return_address);
    if (dl_object_search_paths(caller, &rpath, &runpath) < 0) {
        dl_set_error("dlopen caller has malformed library search metadata",
                     NULL);
        return NULL;
    }
    if (!runpath && rpath) {
        caller_rpath.path = rpath;
        caller_rpath.owner = caller;
        caller_rpath.parent = NULL;
        top_inherited = &caller_rpath;
    }

    /* Check embedded DLOPEN objects in the frozen image */
    if (g_frozen_metas) {
        for (uint32_t i = 0; i < g_frozen_num_entries; i++) {
            if (!(g_frozen_metas[i].flags & LDR_FLAG_DLOPEN)) continue;
            if (g_frozen_metas[i].flags & LDR_FLAG_INTERP) continue;
            if (g_frozen_metas[i].flags & LDR_FLAG_DATA) continue;
            const char *ename = g_frozen_strtab + g_frozen_entries[i].name_offset;
            if (dl_dependency_name_matches(ename, path)) {
                dl_transaction_begin();
                ret = load_embedded_object(i, top_inherited);
                if (ret && dl_transaction_commit() == 0) {
                    restore_ptr_guard();
                    return ret;
                }
                dl_transaction_rollback();
                if (!g_dlerror_valid)
                    dl_set_error(path, ": embedded object load failed");
                restore_ptr_guard();
                return NULL;
            }
        }
    }

    /* Fall back to the filesystem.  Per dlopen(3) semantics:
     *   - if `path` contains a slash it is used as a path directly
     *     (absolute or relative to the current working directory);
     *   - otherwise it is treated as a bare soname and resolved against
     *     the standard runtime library directories. */
    dl_transaction_begin();
    if (dl_path_has_slash(path)) {
        ret = load_elf_from_file(path, top_inherited);
    } else {
        int rc = load_needed_from_filesystem(
            caller, NULL, top_inherited, path, &ret);

        if (rc == 0 && !ret)
            dl_set_error(path, ": cannot open shared object file");
    }
    if (ret && dl_transaction_commit() == 0) {
        /* Loaded from disk — this library should have been captured */
        ldr_msg("dlfreeze: warning: dlopen loading '");
        ldr_msg(bn);
        ldr_msg("' from disk (not in frozen image)\n");
    } else {
        ret = NULL;
        dl_transaction_rollback();
        if (!g_dlerror_valid)
            dl_set_error(path, ": cannot open shared object file");
    }
    restore_ptr_guard();
    return ret;
}

static struct loaded_obj *dl_object_from_handle(void *handle)
{
    uintptr_t value = (uintptr_t)handle;
    uintptr_t start = (uintptr_t)&g_all_objs[0];
    uintptr_t end = (uintptr_t)&g_all_objs[g_nobj];
    uintptr_t delta;

    if (value < start || value >= end)
        return NULL;
    delta = value - start;
    if (delta % sizeof(g_all_objs[0]) != 0)
        return NULL;
    return &g_all_objs[delta / sizeof(g_all_objs[0])];
}

static int dl_next_lookup_scope(void *return_address,
                                uint16_t *order,
                                uint16_t *count_out,
                                uint16_t *first_out)
{
    uintptr_t address = (uintptr_t)return_address;
    int caller_index = -1;
    int scoped;

    for (int i = 0; i < g_nobj; i++)
        if (loaded_obj_contains(&g_all_objs[i], address, 1)) {
            caller_index = i;
            break;
        }
    if (caller_index < 0)
        return -1;

    scoped = dl_build_global_lookup_order(g_nobj, order, count_out);
    if (scoped < 0)
        return -1;
    if (scoped == 0) {
        *count_out = (uint16_t)g_nobj;
        for (int i = 0; i < g_nobj; i++)
            order[i] = (uint16_t)i;
    }
    for (uint16_t i = 0; i < *count_out; i++)
        if (order[i] == (uint16_t)caller_index) {
            *first_out = i + 1;
            return 0;
        }
    return -1;
}

/* dlmopen(LM_ID_BASE, ...) is equivalent to dlopen().  A new namespace
 * requires a distinct scope, link_map chain, TLS module set, and destructor
 * ownership; pretending to provide those semantics is unsafe. */
static void *my_dlmopen(long /*Lmid_t*/ lmid, const char *path, int flags)
{
    if (lmid == 0) /* LM_ID_BASE */
        return my_dlopen(path, flags);

    g_dlerror_valid = 0;
    dl_set_error("dlmopen: link-map namespaces are not supported", NULL);
    return NULL;
}

static int dl_lookup_handle_symbol(struct loaded_obj *root,
                                   const char *symbol,
                                   const char *version,
                                   uint64_t *address_out)
{
    uint32_t gh = gnu_hash_calc(symbol);

    if (!root->lookup_scope_valid &&
        dl_build_lookup_scope(root, g_nobj) < 0)
        return -1;
    for (uint16_t i = 0; i < root->lookup_scope_count; i++) {
        uint16_t index = root->lookup_scope_indices[i];
        const Elf64_Sym *sym;

        if (index >= g_nobj)
            return -1;
        sym = version
            ? lookup_versioned_symbol(&g_all_objs[index], symbol, version)
            : lookup_object_symbol(&g_all_objs[index], symbol, gh);
        if (sym) {
            uint64_t special = lookup_api_special(
                symbol, version, 1);

            if (special) {
                *address_out = special;
                return 1;
            }
            if (resolve_defined_symbol_address(
                    &g_all_objs[index], sym, address_out, NULL))
                return 1;
        }
    }
    {
        uint64_t special = lookup_api_special(symbol, version, 0);

        /* The interpreter is an implicit member of every handle's loader
         * scope even though it is not represented in g_all_objs. */
        if (special) {
            *address_out = special;
            return 1;
        }
    }
    return 0;
}

static void *my_dlsym(void *handle, const char *symbol)
{
    g_dlerror_valid = 0;

    if (!symbol) {
        dl_set_error("dlsym: NULL symbol name", NULL);
        return NULL;
    }

    if (handle == (void *)(uintptr_t)-1L /* RTLD_NEXT */) {
        uint16_t order[MAX_TOTAL_OBJS];
        uint16_t count;
        uint16_t first;

        if (dl_next_lookup_scope(
                __builtin_extract_return_addr(__builtin_return_address(0)),
                order, &count, &first) < 0) {
            dl_set_error("dlsym: RTLD_NEXT caller is not a loaded object",
                         NULL);
            return NULL;
        }
        for (uint16_t position = first; position < count; position++) {
            uint16_t i = order[position];
            uint32_t gh = gnu_hash_calc(symbol);
            const Elf64_Sym *sym = lookup_object_symbol(
                &g_all_objs[i], symbol, gh);
            uint64_t addr;

            if (sym) {
                uint64_t special = lookup_api_special(symbol, NULL, 1);

                /* RTLD_NEXT still selects the first provider after the
                 * caller; only the returned implementation is interposed. */
                if (special)
                    return (void *)(uintptr_t)special;
                if (resolve_defined_symbol_address(
                        &g_all_objs[i], sym, &addr, NULL))
                    return (void *)(uintptr_t)addr;
            }
        }
        dl_set_error("undefined symbol after caller: ", symbol);
        return NULL;
    }
    if (handle == (void *)(uintptr_t)-2L) {
        dl_set_error("dlsym: invalid handle", NULL);
        return NULL;
    }

    /* A real handle searches only that object's breadth-first dependency
     * closure.  It must not fall through to unrelated loaded objects. */
    if (handle && handle != DL_GLOBAL_HANDLE &&
        handle != (void *)(uintptr_t)-1L /* RTLD_NEXT */) {
        struct loaded_obj *obj = dl_object_from_handle(handle);
        uint64_t addr;
        int found;

        if (!obj) {
            dl_set_error("dlsym: invalid handle", NULL);
            return NULL;
        }
        found = dl_lookup_handle_symbol(obj, symbol, NULL, &addr);
        if (found > 0)
            return (void *)(uintptr_t)addr;
        if (found < 0)
            dl_set_error("dlsym: malformed handle dependency scope", NULL);
        else
            dl_set_error("undefined symbol: ", symbol);
        return NULL;
    }

    /* Fallback: search all loaded objects.  Keep success separate from the
     * address because a valid SHN_ABS definition may have value zero. */
    uint64_t addr = 0;
    if (resolve_sym_address(g_all_objs, g_nobj, symbol, &addr))
        return (void *)(uintptr_t)addr;

    dl_set_error("undefined symbol: ", symbol);
    return NULL;
}

/* dlvsym(handle, name, version) — exact GNU symbol-version lookup. */
static void *my_dlvsym(void *handle, const char *symbol, const char *version)
{
    g_dlerror_valid = 0;
    if (!symbol || !version) {
        dl_set_error("dlvsym: invalid symbol or version", NULL);
        return NULL;
    }

    if (handle == (void *)(uintptr_t)-1L /* RTLD_NEXT */) {
        uint16_t order[MAX_TOTAL_OBJS];
        uint16_t count;
        uint16_t first;

        if (dl_next_lookup_scope(
                __builtin_extract_return_addr(__builtin_return_address(0)),
                order, &count, &first) < 0) {
            dl_set_error("dlvsym: RTLD_NEXT caller is not a loaded object",
                         NULL);
            return NULL;
        }
        for (uint16_t position = first; position < count; position++) {
            uint16_t index = order[position];
            const Elf64_Sym *sym = lookup_versioned_symbol(
                &g_all_objs[index], symbol, version);
            uint64_t addr;

            if (sym) {
                uint64_t special = lookup_api_special(
                    symbol, version, 1);

                if (special)
                    return (void *)(uintptr_t)special;
                if (resolve_defined_symbol_address(
                        &g_all_objs[index], sym, &addr, NULL))
                    return (void *)(uintptr_t)addr;
            }
        }
        dl_set_error("undefined versioned symbol after caller: ", symbol);
        return NULL;
    } else if (handle == (void *)(uintptr_t)-2L) {
        dl_set_error("dlvsym: invalid handle", NULL);
        return NULL;
    }

    if (handle && handle != DL_GLOBAL_HANDLE &&
        handle != (void *)(uintptr_t)-1L /* RTLD_NEXT */) {
        struct loaded_obj *obj = dl_object_from_handle(handle);
        uint64_t addr;
        int found;

        if (!obj) {
            dl_set_error("dlvsym: invalid handle", NULL);
            return NULL;
        }
        found = dl_lookup_handle_symbol(obj, symbol, version, &addr);
        if (found > 0)
            return (void *)(uintptr_t)addr;
        if (found < 0)
            dl_set_error("dlvsym: malformed handle dependency scope", NULL);
        else
            dl_set_error("undefined versioned symbol: ", symbol);
        return NULL;
    }

    if (handle != (void *)(uintptr_t)-1L /* RTLD_NEXT */) {
        uint16_t order[MAX_TOTAL_OBJS];
        uint16_t count = 0;
        int scoped = dl_build_global_lookup_order(
            g_nobj, order, &count);
        uint64_t special = lookup_api_special(symbol, version, 0);

        /* The interpreter is globally resident conceptually, but is not
         * represented in g_all_objs. */
        if (special)
            return (void *)(uintptr_t)special;

        if (scoped < 0) {
            dl_set_error("dlvsym: malformed global lookup scope", NULL);
            return NULL;
        }
        if (scoped > 0) {
            for (uint16_t position = 0; position < count; position++) {
                uint16_t index = order[position];
                const Elf64_Sym *sym = lookup_versioned_symbol(
                    &g_all_objs[index], symbol, version);
                uint64_t addr;

                if (sym) {
                    special = lookup_api_special(symbol, version, 1);
                    if (special)
                        return (void *)(uintptr_t)special;
                    if (resolve_defined_symbol_address(
                            &g_all_objs[index], sym, &addr, NULL))
                        return (void *)(uintptr_t)addr;
                }
            }
            dl_set_error("undefined versioned symbol: ", symbol);
            return NULL;
        }
    }

    for (int i = 0; i < g_nobj; i++) {
        const Elf64_Sym *sym =
            lookup_versioned_symbol(&g_all_objs[i], symbol, version);
        uint64_t addr;

        if (sym) {
            uint64_t special = lookup_api_special(symbol, version, 1);

            if (special)
                return (void *)(uintptr_t)special;
            if (resolve_defined_symbol_address(
                    &g_all_objs[i], sym, &addr, NULL))
                return (void *)(uintptr_t)addr;
        }
    }

    dl_set_error("undefined versioned symbol: ", symbol);
    return NULL;
}

/* Bounded dladdr over the loader's mapped-object table.  The dynamic symbol
 * table is sufficient for the public contract; dladdr1's link_map and
 * section-index extensions are intentionally not synthesized. */
static int my_dladdr(const void *address_ptr, Dl_info *info)
{
    uintptr_t address = (uintptr_t)address_ptr;
    struct loaded_obj *obj = NULL;
    const char *best_name = NULL;
    uintptr_t best_address = 0;

    if (!info)
        return 0;
    memset(info, 0, sizeof(*info));
    for (int i = 0; i < g_nobj; i++) {
        if (loaded_obj_contains(&g_all_objs[i], address, 1)) {
            obj = &g_all_objs[i];
            break;
        }
    }
    if (!obj)
        return 0;

    for (uint32_t i = 1; i < obj->dynsym_count; i++) {
        const Elf64_Sym *sym = loaded_dynsym(obj, i);
        const char *name;
        unsigned int type;
        uintptr_t candidate;
        void *pointer;

        if (!sym || sym->st_shndx == SHN_UNDEF)
            continue;
        type = ELF64_ST_TYPE(sym->st_info);
        if (type == STT_TLS || type == STT_SECTION || type == STT_FILE)
            continue;
        name = loaded_symbol_name(obj, sym);
        if (!name || !name[0])
            continue;
        if (sym->st_shndx == SHN_ABS) {
            if (sym->st_value != address)
                continue;
            candidate = (uintptr_t)sym->st_value;
        } else {
            if (sym->st_shndx >= SHN_LORESERVE ||
                !loaded_obj_vaddr_pointer(obj, sym->st_value, 1, 0,
                                          &pointer))
                continue;
            candidate = (uintptr_t)pointer;
        }
        if (candidate > address || (best_name && candidate <= best_address))
            continue;
        best_address = candidate;
        best_name = name;
    }

    info->dli_fname = obj->name ? obj->name : "";
    info->dli_fbase = (void *)(uintptr_t)obj->base;
    info->dli_sname = best_name;
    info->dli_saddr = best_name ? (void *)best_address : NULL;
    return 1;
}

static int my_dlclose(void *handle)
{
    g_dlerror_valid = 0;
    if (handle != DL_GLOBAL_HANDLE && !dl_object_from_handle(handle)) {
        dl_set_error("dlclose: invalid handle", NULL);
        return -1;
    }
    return 0;  /* no-op — never unload */
}

static char *my_dlerror(void)
{
    if (g_dlerror_valid) {
        g_dlerror_valid = 0;
        return g_dlerror_msg;
    }
    return NULL;
}

/* ---- perf map file for profilers (UNUSED — kept for reference) -------- */
#if 0  /* Embedded .symtab/.text sections make this unnecessary */
static void write_perf_map(void)
{
    long ret;

    /* getpid() */
    __asm__ volatile("syscall" : "=a"(ret) : "a"((long)SYS_getpid)
                     : "rcx", "r11", "memory");
    long pid = ret;

    /* Build "/tmp/perf-<PID>.map" */
    char path[64];
    int pi = 0;
    const char *pfx = "/tmp/perf-";
    while (*pfx) path[pi++] = *pfx++;
    char dbuf[20];
    int dn = 0;
    long t = pid;
    do { dbuf[dn++] = '0' + (t % 10); t /= 10; } while (t);
    while (dn > 0) path[pi++] = dbuf[--dn];
    const char *sfx = ".map";
    while (*sfx) path[pi++] = *sfx++;
    path[pi] = '\0';

    /* openat(AT_FDCWD, path, O_WRONLY|O_CREAT|O_TRUNC, 0644) */
    {
        register long r10 __asm__("r10") = 0644;
        __asm__ volatile("syscall" : "=a"(ret)
            : "a"((long)SYS_openat), "D"((long)AT_FDCWD),
              "S"((long)(uintptr_t)path),
              "d"((long)(O_WRONLY | O_CREAT | O_TRUNC)),
              "r"(r10)
            : "rcx", "r11", "memory");
    }
    if (ret < 0) return;
    int fd = (int)ret;

    char buf[16384];
    int bpos = 0;

    #define PM_FLUSH() do { \
        if (bpos > 0) { \
            long _r; \
            __asm__ volatile("syscall" : "=a"(_r) \
                : "a"((long)SYS_write), "D"((long)fd), \
                  "S"((long)(uintptr_t)buf), "d"((long)bpos) \
                : "rcx", "r11", "memory"); \
            bpos = 0; \
        } \
    } while(0)

    for (int i = 0; i < g_nobj; i++) {
        const struct loaded_obj *obj = &g_all_objs[i];
        if (!obj->dynsym || !obj->dynstr) continue;

        for (uint32_t s = 0; s < obj->dynsym_count; s++) {
            const Elf64_Sym *sym = &obj->dynsym[s];
            unsigned char stype = ELF64_ST_TYPE(sym->st_info);
            if (stype != STT_FUNC && stype != STT_GNU_IFUNC) continue;
            if (sym->st_value == 0 || sym->st_shndx == SHN_UNDEF) continue;

            const char *name = obj->dynstr + sym->st_name;
            if (!name[0]) continue;

            uint64_t addr = obj->base + sym->st_value;
            uint64_t size = sym->st_size;

            if (bpos > (int)sizeof(buf) - 512) PM_FLUSH();

            /* hex addr (no 0x prefix, lowercase) */
            char hx[17];
            int hn = 0;
            uint64_t v = addr;
            do { hx[hn++] = "0123456789abcdef"[v & 0xf]; v >>= 4; } while (v);
            while (hn > 0) buf[bpos++] = hx[--hn];
            buf[bpos++] = ' ';

            /* hex size */
            hn = 0; v = size;
            if (v == 0) { buf[bpos++] = '0'; }
            else {
                do { hx[hn++] = "0123456789abcdef"[v & 0xf]; v >>= 4; } while (v);
                while (hn > 0) buf[bpos++] = hx[--hn];
            }
            buf[bpos++] = ' ';

            /* symbol name */
            while (*name && bpos < (int)sizeof(buf) - 2)
                buf[bpos++] = *name++;
            buf[bpos++] = '\n';
        }
    }

    PM_FLUSH();
    #undef PM_FLUSH

    /* close(fd) */
    __asm__ volatile("syscall" : "=a"(ret)
                     : "a"((long)SYS_close), "D"((long)fd)
                     : "rcx", "r11", "memory");

    ldr_dbg("[loader] wrote ");
    ldr_dbg(path);
    ldr_dbg("\n");
}
#endif

/* ---------- dl_iterate_phdr override ---------------------------------- */

static int my_dl_iterate_phdr(
        int (*callback)(struct dl_phdr_info *, size_t, void *),
        void *data)
{
    int ret = 0;
    for (int i = 0; i < g_nobj; i++) {
        if (!g_all_objs[i].phdr) continue;
        struct dl_phdr_info info;
        memset(&info, 0, sizeof(info));
        info.dlpi_addr    = (ElfW(Addr))g_all_objs[i].base;
        info.dlpi_name    = g_all_objs[i].name ? g_all_objs[i].name : "";
        info.dlpi_phdr    = g_all_objs[i].phdr;
        info.dlpi_phnum   = g_all_objs[i].phdr_num;
        info.dlpi_adds    = (unsigned long long)g_nobj;
        info.dlpi_subs    = 0;
        ret = callback(&info, sizeof(info), data);
        if (ret != 0) return ret;
    }
    return ret;
}

/* ==== TLS setup ======================================================== */

static uintptr_t get_auxval(char **envp, unsigned long type)
{
    char **p = envp;
    while (*p) p++;
    p++;  /* skip NULL terminator of envp */
    Elf64_auxv_t *a = (Elf64_auxv_t *)p;
    while (a->a_type != AT_NULL) {
        if (a->a_type == type) return a->a_un.a_val;
        a++;
    }
    return 0;
}

static Elf64_auxv_t *get_auxv_ptr(char **envp)
{
    char **p = envp;
    while (*p) p++;
    p++;
    return (Elf64_auxv_t *)p;
}

static size_t get_auxv_count(char **envp)
{
    Elf64_auxv_t *a = get_auxv_ptr(envp);
    size_t count = 1;

    while (a[count - 1].a_type != AT_NULL)
        count++;
    return count;
}

static void set_auxv_entry(Elf64_auxv_t *auxv, size_t *count,
                           unsigned long type, uintptr_t value)
{
    for (size_t i = 0; i < *count; i++) {
        if (auxv[i].a_type == type) {
            auxv[i].a_un.a_val = value;
            return;
        }
        if (auxv[i].a_type == AT_NULL)
            break;
    }

    auxv[*count - 1].a_type = type;
    auxv[*count - 1].a_un.a_val = value;
    auxv[*count].a_type = AT_NULL;
    auxv[*count].a_un.a_val = 0;
    (*count)++;
}

/*
 * Set up static TLS for all loaded objects.
 * Returns the thread pointer (TP) on success, 0 on failure.
 */
static uintptr_t setup_tls(struct loaded_obj *objs, int nobj,
                            const uint8_t *mem, uint64_t mem_foff,
                            const struct dlfrz_lib_meta *metas,
                            const struct dlfrz_entry *entries,
                            int *idx_map, int num_entries __attribute__((unused)),
                            uintptr_t at_random)
{
    uint64_t max_tls_align = 1;
    int64_t min_static_tpoff = 0;
    /* Discover PT_TLS for each object and compute total static TLS size.
     * x86-64 uses Variant II: TLS blocks at negative TP offsets.
     * Layout: [TLS block N ... TLS block 1] [TCB]
     *                                        ^ TP (= FS register)
     */
    int tls_above_tp = static_tls_above_tp();
    uint64_t total_tls = tls_above_tp ? static_tls_first_tpoff() : 0;
    for (int oi = 0; oi < nobj; oi++) {
        /* Find the matching manifest index */
        int mi = idx_map[oi];
        const uint8_t *elf = mem + (entries[mi].data_offset - mem_foff);
        const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf;
        const Elf64_Phdr *phdrs =
            (const Elf64_Phdr *)(elf + ehdr->e_phoff);

        for (int j = 0; j < metas[mi].phdr_num; j++) {
            if (phdrs[j].p_type != PT_TLS) continue;
            uint64_t align = phdrs[j].p_align ? phdrs[j].p_align : 1;
            uint64_t next_tls;

            if ((align & (align - 1)) != 0 ||
                phdrs[j].p_filesz > phdrs[j].p_memsz ||
                phdrs[j].p_memsz > SIZE_MAX ||
                phdrs[j].p_vaddr > UINT64_MAX - phdrs[j].p_memsz ||
                (phdrs[j].p_vaddr & (align - 1)) !=
                    (phdrs[j].p_offset & (align - 1)) ||
                (phdrs[j].p_filesz != 0 &&
                 !loaded_obj_file_vaddr_pointer(&objs[oi],
                                                phdrs[j].p_vaddr,
                                                (size_t)phdrs[j].p_filesz,
                                                NULL))) {
                ldr_err("invalid PT_TLS program header in", objs[oi].name);
                return 0;
            }
            if (align > max_tls_align)
                max_tls_align = align;
            if (tls_above_tp) {
                if (!u64_align_up_checked(total_tls, align, &next_tls) ||
                    next_tls > INT64_MAX) {
                    ldr_err("static TLS layout overflows for", objs[oi].name);
                    return 0;
                }
                total_tls = next_tls;
                objs[oi].tls.tpoff = (int64_t)total_tls;
                if (!u64_add_checked(total_tls, phdrs[j].p_memsz,
                                     &total_tls) ||
                    total_tls > INT64_MAX) {
                    ldr_err("static TLS layout overflows for", objs[oi].name);
                    return 0;
                }
            } else {
                if (!u64_add_checked(total_tls, phdrs[j].p_memsz,
                                     &next_tls) ||
                    !u64_align_up_checked(next_tls, align, &total_tls) ||
                    total_tls > INT64_MAX) {
                    ldr_err("static TLS layout overflows for", objs[oi].name);
                    return 0;
                }
                objs[oi].tls.tpoff  = -(int64_t)total_tls;
                if (objs[oi].tls.tpoff < min_static_tpoff)
                    min_static_tpoff = objs[oi].tls.tpoff;
            }
            objs[oi].tls.filesz = phdrs[j].p_filesz;
            objs[oi].tls.memsz  = phdrs[j].p_memsz;
            objs[oi].tls.vaddr  = phdrs[j].p_vaddr;
            objs[oi].tls.align  = align;
            objs[oi].tls.modid  = (size_t)(oi + 1);
            break;
        }
    }

    /* Update fake rtld TLS size/alignment so glibc's nptl and old
     * libpthread private hooks reserve enough static TLS for new threads.
     * glibc formula: roundup(total_tls + surplus + sizeof(struct pthread), 64)
     * sizeof(struct pthread) ≈ 2304 (0x900) on glibc 2.43 x86-64.
     * TLS_STATIC_SURPLUS ≈ 1664.  We use 0x1800 as a safe combined margin. */
    {
        uint64_t tls_static_u64;
        uint64_t tls_static_sum;
        uint64_t tls_align_u64 = max_tls_align < 0x40
                               ? 0x40 : max_tls_align;

        if (!u64_add_checked(total_tls, 0x1800, &tls_static_sum) ||
            !u64_align_up_checked(tls_static_sum, 64, &tls_static_u64) ||
            tls_static_u64 > SIZE_MAX || tls_align_u64 > SIZE_MAX) {
            ldr_err("static TLS allocation size overflows", NULL);
            return 0;
        }
        size_t tls_static = (size_t)tls_static_u64;
        size_t tls_align = (size_t)tls_align_u64;

        g_tls_static_size = tls_static;
        g_tls_static_align = tls_align;

        if (!g_is_musl_runtime) {
            /* In glibc ≥ 2.34, the TLS static size field is in
             * _rtld_global_ro.  In glibc < 2.34, it is in _rtld_global
             * (sentinel: glro_tls… = -1).  Musl has neither structure. */
            if (g_glibc_off->glro_tls_static_size >= 0)
                *(size_t *)(g_fake_rtld_global_ro +
                            g_glibc_off->glro_tls_static_size) = tls_static;
            else if (g_glibc_off->gl_tls_static_size >= 0)
                *(size_t *)(g_fake_rtld_global +
                            g_glibc_off->gl_tls_static_size) = tls_static;

            if (g_glibc_off->glro_tls_static_align >= 0)
                *(size_t *)(g_fake_rtld_global_ro +
                            g_glibc_off->glro_tls_static_align) = tls_align;
            else if (g_glibc_off->gl_tls_static_align >= 0)
                *(size_t *)(g_fake_rtld_global +
                            g_glibc_off->gl_tls_static_align) = tls_align;
        }
    }

#if defined(__aarch64__)
    if (!g_is_musl_runtime) {
        if (glibc_aarch64_has_rseq_area()) {
            g_rseq_offset = (int64_t)glibc_aarch64_pthread_rseq_off() -
                            (int64_t)glibc_aarch64_pthread_size();
        } else {
            /* No struct pthread rseq area.  Use the padding after tid as
             * synthetic cpu_id storage for glibc's failure marker. */
            g_rseq_offset = (int64_t)glibc_aarch64_pthread_tid_off() -
                            (int64_t)glibc_aarch64_pthread_size();
        }
        g_rseq_size = 0;
        if (g_debug) {
            ldr_dbg_hex("[loader] glibc rseq offset=", (uint64_t)g_rseq_offset);
            ldr_dbg_hex("[loader] glibc rseq size=", (uint64_t)g_rseq_size);
        }
    }
#else
    if (!g_is_musl_runtime && min_static_tpoff < 0) {
        int64_t rseq_off = min_static_tpoff - (int64_t)32;

        g_rseq_offset = rseq_off & ~((int64_t)31);
    }
#endif

    /* Allocate TLS block + TCB */
    size_t alloc;
    uintptr_t tp;
    void *block;
    uint64_t alloc_u64;
    uint64_t tp_input;
    uint64_t tp_u64;

    if (g_is_musl_runtime && musl_tls_above_tp()) {
        if (!u64_add_checked(g_musl_tp_self_delta, total_tls, &alloc_u64) ||
            !u64_add_checked(alloc_u64, max_tls_align - 1, &alloc_u64) ||
            alloc_u64 == 0 || alloc_u64 > SIZE_MAX) {
            ldr_err("TLS allocation size overflows", NULL);
            return 0;
        }
        alloc = (size_t)alloc_u64;
        block = mmap(NULL, alloc, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (block == MAP_FAILED) {
            ldr_err("TLS mmap failed", NULL);
            return 0;
        }
        if (!u64_add_checked((uintptr_t)block, g_musl_tp_self_delta,
                             &tp_input) ||
            !u64_align_up_checked(tp_input, max_tls_align, &tp_u64)) {
            munmap(block, alloc);
            ldr_err("TLS thread-pointer alignment overflows", NULL);
            return 0;
        }
        tp = (uintptr_t)tp_u64;
    }
#if defined(__aarch64__)
    else if (glibc_tls_above_tp()) {
        uint64_t tls_aligned;
        uint64_t pthread_size = glibc_aarch64_pthread_size();

        if (!u64_align_up_checked(total_tls, 64, &tls_aligned) ||
            !u64_add_checked(pthread_size, tls_aligned, &alloc_u64) ||
            !u64_add_checked(alloc_u64, max_tls_align - 1, &alloc_u64) ||
            alloc_u64 == 0 || alloc_u64 > SIZE_MAX) {
            ldr_err("TLS allocation size overflows", NULL);
            return 0;
        }
        alloc = (size_t)alloc_u64;
        block = mmap(NULL, alloc, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (block == MAP_FAILED) {
            ldr_err("TLS mmap failed", NULL);
            return 0;
        }
        if (!u64_add_checked((uintptr_t)block, pthread_size, &tp_input) ||
            !u64_align_up_checked(tp_input, max_tls_align, &tp_u64)) {
            munmap(block, alloc);
            ldr_err("TLS thread-pointer alignment overflows", NULL);
            return 0;
        }
        tp = (uintptr_t)tp_u64;
    }
#endif
    else {
        uint64_t tp_align = max_tls_align < 64 ? 64 : max_tls_align;

        if (!u64_add_checked(total_tls, TCB_ALLOC, &alloc_u64) ||
            !u64_add_checked(alloc_u64, tp_align - 1, &alloc_u64) ||
            alloc_u64 == 0 || alloc_u64 > SIZE_MAX) {
            ldr_err("TLS allocation size overflows", NULL);
            return 0;
        }
        alloc = (size_t)alloc_u64;
        block = mmap(NULL, alloc, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (block == MAP_FAILED) {
            ldr_err("TLS mmap failed", NULL);
            return 0;
        }
        if (!u64_add_checked((uintptr_t)block, total_tls, &tp_input) ||
            !u64_align_up_checked(tp_input, tp_align, &tp_u64)) {
            munmap(block, alloc);
            ldr_err("TLS thread-pointer alignment overflows", NULL);
            return 0;
        }
        tp = (uintptr_t)tp_u64;
    }

    if (!g_is_musl_runtime) {
        /* Initialize glibc TCB header */
        *(uintptr_t *)(tp + TCB_OFF_SELF)  = tp;
        *(uintptr_t *)(tp + TCB_OFF_SELF2) = tp;
    }

    if (g_is_musl_runtime) {
        uintptr_t self = musl_thread_self_ptr(tp);
        size_t dtv_slots = 1;
        for (int oi = 0; oi < nobj; oi++) {
            if (objs[oi].tls.memsz == 0)
                continue;
            if (objs[oi].tls.modid + 1 > dtv_slots)
                dtv_slots = objs[oi].tls.modid + 1;
        }

        uint64_t musl_dtv_raw;
        uint64_t musl_dtv_bytes_u64;

        if (!u64_mul_checked(dtv_slots, sizeof(uintptr_t), &musl_dtv_raw)) {
            munmap(block, alloc);
            ldr_err("musl DTV allocation size overflows", NULL);
            return 0;
        }
        if (!u64_align_up_checked(musl_dtv_raw, g_page_size,
                                  &musl_dtv_bytes_u64) ||
            musl_dtv_bytes_u64 == 0 || musl_dtv_bytes_u64 > SIZE_MAX) {
            munmap(block, alloc);
            ldr_err("musl DTV allocation size overflows", NULL);
            return 0;
        }
        size_t musl_dtv_bytes = (size_t)musl_dtv_bytes_u64;
        uintptr_t *musl_dtv = mmap(NULL, musl_dtv_bytes,
                                   PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (musl_dtv == MAP_FAILED) {
            munmap(block, alloc);
            ldr_err("musl DTV mmap failed", NULL);
            return 0;
        }
        *(uintptr_t *)(self + 0) = self;
        *(uintptr_t *)(self + MUSL_THREAD_PREV_OFF) = self;
        *(uintptr_t *)(self + MUSL_THREAD_NEXT_OFF) = self;
        *(uintptr_t *)(self + MUSL_THREAD_ROBUST_HEAD_OFF) =
            self + MUSL_THREAD_ROBUST_HEAD_OFF;
        if (g_musl_target_tid_known)
            *(int *)(self + MUSL_THREAD_TID_OFF) = (int)syscall(SYS_gettid);
        if (g_musl_target_errno_known)
            *(int *)(self + MUSL_THREAD_ERRNO_OFF) = 0;
        if (g_musl_target_detach_known)
            *(int *)(self + MUSL_THREAD_DETACH_STATE_OFF) =
                g_musl_target_detach_value;
        *(uintptr_t *)(self + MUSL_THREAD_LOCALE_OFF) =
            g_musl_libc_addr + g_musl_layout->libc_global_locale;
        (void)at_random;
        *(uintptr_t *)(self + g_musl_layout->thread_canary) =
            g_musl_stack_guard;

        musl_dtv[0] = dtv_slots - 1;
        for (int oi = 0; oi < nobj; oi++) {
            if (objs[oi].tls.memsz == 0)
                continue;
            musl_dtv[objs[oi].tls.modid] =
                tp + (uintptr_t)objs[oi].tls.tpoff;
        }
        *(uintptr_t *)musl_thread_dtv_slot(tp) = (uintptr_t)musl_dtv;
    }

    /* glibc stores the current TID in the TCB header; musl keeps it in
     * struct pthread and seeds it later in init_musl_process_state(). */
    if (!g_is_musl_runtime) {
#if defined(__aarch64__)
        uintptr_t self = glibc_aarch64_pthread_self_from_tp(tp);
        *(int32_t *)(self + glibc_aarch64_pthread_tid_off()) =
            (int32_t)syscall(SYS_gettid);
        if (glibc_aarch64_has_rseq_area()) {
            *(int32_t *)(self + glibc_aarch64_pthread_rseq_cpu_id_off()) =
                GLIBC_RSEQ_CPU_ID_REGISTRATION_FAILED;
        }
        glibc_aarch64_disable_rseq_for_thread(tp);
#else
        *(int32_t *)(tp + TCB_OFF_TID) = (int32_t)syscall(SYS_gettid);
#endif
        if (init_glibc_main_thread_list(tp) < 0) {
            ldr_err("unsupported glibc pthread list layout", NULL);
            return 0;
        }
    }

    /* Minimal DTV (Dynamic Thread Vector).
     * glibc convention: tcbhead.dtv points to raw_dtv[1] (offset by one
     * dtv_t entry = 16 bytes), so that dtv[-1].counter is the capacity.
     *   raw_dtv[0].counter = capacity
     *   dtv = raw_dtv + 1 (in dtv_t units)
     *   dtv[0].counter = generation
     *   dtv[modid] = {val, to_free} for TLS module modid (1-indexed)
     */
    if (!g_is_musl_runtime) {
        size_t max_modid = 0;
        for (int oi = 0; oi < nobj; oi++) {
            if (objs[oi].tls.memsz == 0 || objs[oi].tls.modid == 0)
                continue;
            if (objs[oi].tls.modid > max_modid)
                max_modid = objs[oi].tls.modid;
        }

        uint64_t dtv_slots;
        uint64_t raw_dtv_words;
        uint64_t raw_dtv_bytes;
        uint64_t raw_dtv_map_bytes;

        if (!u64_add_checked(1, max_modid, &dtv_slots) ||
            !u64_add_checked(1, dtv_slots, &raw_dtv_words) ||
            !u64_mul_checked(raw_dtv_words, 2, &raw_dtv_words) ||
            !u64_mul_checked(raw_dtv_words, sizeof(uintptr_t),
                             &raw_dtv_bytes) ||
            !u64_align_up_checked(raw_dtv_bytes, g_page_size,
                                  &raw_dtv_map_bytes) ||
            raw_dtv_map_bytes == 0 || raw_dtv_map_bytes > SIZE_MAX) {
            munmap(block, alloc);
            ldr_err("glibc DTV allocation size overflows", NULL);
            return 0;
        }
        uintptr_t *raw_dtv = (uintptr_t *)mmap(NULL,
                                               (size_t)raw_dtv_map_bytes,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (raw_dtv == MAP_FAILED) {
            munmap(block, alloc);
            ldr_err("glibc DTV mmap failed", NULL);
            return 0;
        }
        /* dtv[-1].counter is allocation capacity; dtv[0].counter is the
         * generation compared against the fake rtld TLS generation. */
        raw_dtv[0] = max_modid;
        raw_dtv[1] = 0;
        /* dtv = raw_dtv + one dtv_t entry (2 uintptr_t's) */
        uintptr_t *dtv = raw_dtv + 2;
        dtv[0] = 1;
        dtv[1] = 0;
        /* dtv[modid] for each TLS module: .val = tp + tpoff, to_free = NULL.
         * glibc uses 1-indexed modules, dtv[1] = module 1, etc. */
        for (int oi = 0; oi < nobj; oi++) {
            if (objs[oi].tls.memsz == 0) continue;
            size_t slot = objs[oi].tls.modid;
            if (slot < dtv_slots) {
                dtv[slot * 2]     = tp + (uintptr_t)objs[oi].tls.tpoff;
                dtv[slot * 2 + 1] = 0;  /* to_free = NULL */
            }
        }
        *(uintptr_t *)(tp + TCB_OFF_DTV) = (uintptr_t)dtv;
    }

    if (!g_is_musl_runtime) {
#if !defined(__aarch64__)
        /* Stack canary from AT_RANDOM */
        if (at_random) {
            uintptr_t canary;
            uintptr_t ptr_guard;

            memcpy(&canary, (void *)at_random, sizeof(canary));
            canary &= ~(uintptr_t)0xFF;   /* glibc zeroes low byte */
            *(uintptr_t *)(tp + TCB_OFF_STACK_GUARD) = canary;

            memcpy(&ptr_guard, (void *)(at_random + sizeof(uintptr_t)),
                   sizeof(ptr_guard));
            *(uintptr_t *)(tp + TCB_OFF_PTR_GUARD) = ptr_guard;
        }

        /* Preserve the bootstrap libc's stack canary so that SSP checks in
         * the static libc continue to work after we change FS. */
        {
            uintptr_t old_canary = arch_read_tp_offset(0x28);
            *(uintptr_t *)(tp + TCB_OFF_STACK_GUARD) = old_canary;
        }
#endif
    }

    /* NOTE: .tdata is NOT copied here — it must be copied AFTER
     * relocations are applied so that RELATIVE/RELR-relocated
     * pointers in the TLS template have their final values. */

    /* Set thread pointer register */
    arch_set_tp(tp);

    /* Save pointer_guard value and address for crash diagnostics.
     * musl does not keep a glibc-style pointer guard in the TCB header. */
    if (!g_is_musl_runtime) {
#if !defined(__aarch64__)
        g_saved_stack_guard = *(uintptr_t *)(tp + TCB_OFF_STACK_GUARD);
        g_ptr_guard_addr = tp + TCB_OFF_PTR_GUARD;
        g_saved_ptr_guard = *(uintptr_t *)(tp + TCB_OFF_PTR_GUARD);
#else
        g_saved_stack_guard = 0;
        g_ptr_guard_addr = 0;
        g_saved_ptr_guard = 0;
#endif
    } else {
        g_saved_stack_guard = 0;
        g_ptr_guard_addr = 0;
        g_saved_ptr_guard = 0;
    }

    return tp;
}

/* Copy .tdata from each module's loaded image into the TLS block.
 * Must be called AFTER relocations — the TLS template contains
 * pointers that are adjusted by RELATIVE / RELR relocations. */
static void copy_tdata(struct loaded_obj *objs, int nobj, uintptr_t tp)
{
    for (int oi = 0; oi < nobj; oi++) {
        if (objs[oi].tls.memsz == 0) continue;
        uint8_t *dst = (uint8_t *)(tp + objs[oi].tls.tpoff);
        if (objs[oi].tls.filesz != 0) {
            const uint8_t *src = (const uint8_t *)(objs[oi].base +
                                                   objs[oi].tls.vaddr);
            memcpy(dst, src, objs[oi].tls.filesz);
        }
        if (objs[oi].tls.memsz > objs[oi].tls.filesz) {
            memset(dst + objs[oi].tls.filesz, 0,
                   objs[oi].tls.memsz - objs[oi].tls.filesz);
        }
    }
}

/* ==== Stack construction and entry transfer ============================ */

__attribute__((noreturn))
static void transfer_to_entry(uintptr_t entry, int argc, char **argv,
                               char **envp, uintptr_t phdr, int phnum,
                               uintptr_t at_base, uintptr_t at_entry,
                               uintptr_t at_random,
                               int is_musl_runtime)
{
#if !defined(__aarch64__)
    (void)is_musl_runtime;
#endif

    /* Count envp */
    int envc = 0;
    while (envp[envc]) envc++;

    /* Preserve the kernel-provided auxv and override only the entries
     * that must describe the direct-loaded image.  musl startup uses
     * more of auxv than the glibc direct-main shortcut does. */
    size_t orig_auxvc = get_auxv_count(envp);
    Elf64_auxv_t *orig_auxv = get_auxv_ptr(envp);
    Elf64_auxv_t auxv[orig_auxvc + 8];
    size_t auxvc = orig_auxvc;

    memcpy(auxv, orig_auxv, orig_auxvc * sizeof(*auxv));
    set_auxv_entry(auxv, &auxvc, AT_PHDR, phdr);
    set_auxv_entry(auxv, &auxvc, AT_PHNUM, (uintptr_t)phnum);
    set_auxv_entry(auxv, &auxvc, AT_PHENT, sizeof(Elf64_Phdr));
    set_auxv_entry(auxv, &auxvc, AT_BASE, at_base);
    set_auxv_entry(auxv, &auxvc, AT_ENTRY, at_entry);
    set_auxv_entry(auxv, &auxvc, AT_RANDOM, at_random);

    /* Total words on stack:
     *   1 (argc) + argc+1 (argv+NULL) + envc+1 (envp+NULL) + auxvc*2 (auxv pairs)
     */
    int nwords = 1 + (argc + 1) + (envc + 1) + (int)auxvc * 2;

    /* Allocate a proper stack (8 MB) */
    size_t stack_size = 8 * 1024 * 1024;
    void *stack_mem = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack_mem == MAP_FAILED) {
        ldr_msg("dlfreeze-loader: stack mmap failed\n");
        _exit(127);
    }

    uintptr_t *top = (uintptr_t *)((char *)stack_mem + stack_size);
    uintptr_t *sp  = top - nwords;

    /* Ensure 16-byte alignment */
    sp = (uintptr_t *)((uintptr_t)sp & ~15ULL);
    /* After _start pops argc, RSP must be 16-byte aligned.
     * So we need sp to be 16-byte aligned with an odd number of 8-byte words
     * before argv starts... actually: at entry, RSP is 16-byte aligned.
     * Let's recompute to ensure. */
    if (((uintptr_t)sp & 0xF) != 0)
        sp--;

#if defined(__aarch64__)
    if (!is_musl_runtime)
        glibc_aarch64_set_main_stack((uintptr_t)stack_mem, stack_size);
#endif

    int p = 0;
    sp[p++] = (uintptr_t)argc;
    for (int i = 0; i < argc; i++) sp[p++] = (uintptr_t)argv[i];
    sp[p++] = 0;  /* argv NULL */
    for (int i = 0; i < envc; i++) sp[p++] = (uintptr_t)envp[i];
    sp[p++] = 0;  /* envp NULL */
    for (size_t i = 0; i < auxvc; i++) {
        sp[p++] = auxv[i].a_type;
        sp[p++] = auxv[i].a_un.a_val;
    }

#if defined(__x86_64__)
    __asm__ volatile(
        "mov %0, %%rsp\n\t"
        "xor %%edx, %%edx\n\t"    /* rdx = 0 (rtld_fini = NULL) */
        "xor %%ebp, %%ebp\n\t"    /* clear frame pointer        */
        "jmp *%1\n\t"
        : : "r"(sp), "r"(entry) : "memory"
    );
#elif defined(__aarch64__)
    {
        uintptr_t start_x0 = is_musl_runtime ? (uintptr_t)sp : 0;
        if (g_debug) {
            ldr_hex("[loader] transfer entry=", entry);
            ldr_hex("[loader] transfer sp=", (uintptr_t)sp);
            ldr_hex("[loader] transfer start_x0=", start_x0);
            ldr_hex("[loader] transfer is_musl=", (uint64_t)is_musl_runtime);
        }
        __asm__ volatile(
            "mov sp, %0\n\t"
            "mov x0, %1\n\t"
            "mov x29, #0\n\t"         /* clear frame pointer */
            "br %2\n\t"
            : : "r"(sp), "r"(start_x0), "r"(entry) : "memory", "x0"
        );
    }
#endif
    __builtin_unreachable();
}

/* DFS topological sort: visit dependencies of obj before obj itself.
 * state[]: 0 = unvisited, 1 = on stack (cycle marker), 2 = appended to order.
 * Walks PT_DYNAMIC for DT_NEEDED, finds matching loaded obj by basename. */
static void topo_visit_init(int idx, struct loaded_obj *objs, int nobj,
                            char *state, int *order, int *order_count)
{
    if (state[idx] != 0) return;
    state[idx] = 1;
    struct loaded_obj *obj = &objs[idx];
    if (obj->dynamic && obj->dynstr) {
        for (size_t d = 0; d < obj->dynamic_count; d++) {
                const char *needed;

                if (obj->dynamic[d].d_tag != DT_NEEDED)
                    continue;
                if (obj->dynamic[d].d_un.d_val > UINT32_MAX)
                    continue;
                needed = loaded_dynstr_value(
                    obj, (uint32_t)obj->dynamic[d].d_un.d_val);
                if (!needed)
                    continue;
                for (int j = 0; j < nobj; j++) {
                    if (j == idx) continue;
                    if (state[j] != 0) continue; /* done or cycle */
                    if (dl_name_matches(objs[j].name, needed)) {
                        topo_visit_init(j, objs, nobj, state, order,
                                        order_count);
                        break;
                    }
                }
        }
    }
    state[idx] = 2;
    order[(*order_count)++] = idx;
}

/* ==== Main entry point ================================================= */

static void notify_terminal_refusal(int handoff_fd)
{
    const char marker = DLFRZ_HANDOFF_TERMINAL_REFUSAL;
    ssize_t written;

    if (handoff_fd < 0)
        return;
    do {
        written = write(handoff_fd, &marker, sizeof(marker));
    } while (written < 0 && errno == EINTR);
}

int loader_run(const uint8_t *mem, uint64_t mem_foff, int srcfd,
               const struct dlfrz_lib_meta *metas,
               const struct dlfrz_entry *entries,
               const char *strtab,
               uint32_t num_entries,
               const uint32_t *runtime_fixups,
               uint32_t runtime_fixup_count,
               int handoff_fd,
               int argc, char **argv, char **envp)
{
    /* Check env flags before TLS swap (getenv uses bootstrap's libc) */
    {
        const char *dbg = getenv("DLFREEZE_DEBUG");
        g_debug = (dbg && dbg[0] != '0' && dbg[0] != '\0');
        const char *perf = getenv("DLFREEZE_PERF");
        g_perf_mode = (perf && perf[0] != '0' && perf[0] != '\0');
    }

    {
        uintptr_t page_size = get_auxval(envp, AT_PAGESZ);

        if (page_size >= 4096 && page_size <= 65536 &&
            (page_size & (page_size - 1)) == 0)
            g_page_size = page_size;
    }
    g_fake_dl_argv = argv;
    g_fake_libc_enable_secure = get_auxval(envp, AT_SECURE) != 0;
    {
        uintptr_t random = get_auxval(envp, AT_RANDOM);

        g_fake_stack_chk_guard = 0;
        g_fake_pointer_chk_guard = 0;
        if (random) {
            memcpy(&g_fake_stack_chk_guard, (const void *)random,
                   sizeof(g_fake_stack_chk_guard));
            g_fake_stack_chk_guard &= ~(uintptr_t)0xff;
            memcpy(&g_fake_pointer_chk_guard,
                   (const void *)(random + sizeof(uintptr_t)),
                   sizeof(g_fake_pointer_chk_guard));
        }
    }

    clear_resolution_caches();
    g_global_scope_root = -1;
    g_global_scope_count = 0;
    g_init_order_count = 0;
    g_fini_running = 0;
    g_glibc_off = NULL;
    g_glibc_rtld_fixed = 0;
    g_musl_layout = NULL;
    g_musl_libc_addr = 0;

    int prelinked = -1;
    for (uint32_t i = 0; i < num_entries; i++) {
        int object_prelinked;

        if (metas[i].flags & (LDR_FLAG_INTERP | LDR_FLAG_DLOPEN |
                              LDR_FLAG_DATA))
            continue;
        object_prelinked =
            (metas[i].flags & LDR_FLAG_PRELINKED) != 0;
        if (prelinked < 0)
            prelinked = object_prelinked;
        else if (prelinked != object_prelinked) {
            notify_terminal_refusal(handoff_fd);
            ldr_err("mixed pre-linked object metadata", NULL);
            return -1;
        }
    }
    if (prelinked < 0) {
        ldr_err("no startup objects in direct metadata", NULL);
        return -1;
    }

    enum frozen_runtime runtime =
        detect_frozen_runtime(metas, entries, strtab, num_entries);
    if (runtime == FROZEN_RUNTIME_UNKNOWN) {
        ldr_msg("dlfreeze: warning: direct-load does not support this "
                "runtime; using extraction mode\n");
        return -1;
    }
    int is_musl_runtime = runtime == FROZEN_RUNTIME_MUSL;
    g_is_musl_runtime = is_musl_runtime;
    const struct glibc_ver_offsets *glibc_off = NULL;

    /* Private glibc layouts must be positively identified before mapping any
     * target object.  A stale prelinked artifact is terminally refused here;
     * clean runtime-relocation payloads may still use extraction fallback. */
    if (runtime == FROZEN_RUNTIME_GLIBC) {
        glibc_off = detect_glibc_offsets_from_interp(mem, mem_foff, entries,
                                                     metas, num_entries);
        if (!glibc_off) {
            if (prelinked)
                notify_terminal_refusal(handoff_fd);
            ldr_msg("dlfreeze: direct-load artifact is incompatible with "
                    "this glibc private rtld layout\n");
            return -1;
        }
    } else {
        g_musl_layout = detect_musl_layout_from_interp(
            mem, mem_foff, entries, metas, num_entries);
        if (!g_musl_layout || !__copy_tls) {
            if (prelinked)
                notify_terminal_refusal(handoff_fd);
            ldr_msg("dlfreeze: direct-load artifact is incompatible with "
                    "this musl private runtime layout\n");
            return -1;
        }
        g_musl_tp_self_delta = g_musl_layout->tp_self_delta;
        if (&__stack_chk_guard) {
            g_musl_stack_guard = __stack_chk_guard;
        } else {
            uintptr_t random = get_auxval(envp, AT_RANDOM);

            if (!random) {
                ldr_msg("dlfreeze: musl bootstrap has no stack-guard "
                        "entropy\n");
                return -1;
            }
            memcpy(&g_musl_stack_guard, (const void *)random,
                   sizeof(g_musl_stack_guard));
            if (g_musl_layout->canary_zero_second_byte)
                ((unsigned char *)&g_musl_stack_guard)[1] = 0;
        }
        select_musl_thread_layout(g_musl_layout);
    }

    struct sigaction startup_crash_handlers[CRASH_SIGNAL_COUNT];
    capture_crash_handlers(startup_crash_handlers);

    /* Kick off asynchronous readahead of the frozen binary so that
     * page faults during segment mapping hit warm page cache. */
    if (srcfd >= 0) {
        off_t end = lseek(srcfd, 0, SEEK_END);
        if (end > 0)
            syscall(SYS_readahead, srcfd, (off_t)0, (size_t)end);
    }

    /* Install crash handlers for debugging */
    install_crash_handlers();

    /* Allocate fake _rtld_global / _rtld_global_ro for libc */
    if (init_fake_rtld() < 0) return -1;

    if (glibc_off) {
        g_glibc_off = glibc_off;
        fixup_rtld_for_glibc(glibc_off);
        g_glibc_rtld_fixed = 1;
    }

    /* Save frozen image context early so VFS lookup repair can fall back
     * to the original manifest before lazy dlopen initialization happens. */
    g_frozen_mem         = mem;
    g_frozen_mem_foff    = mem_foff;
    g_frozen_srcfd       = srcfd;
    g_frozen_metas       = metas;
    g_frozen_entries     = entries;
    g_frozen_strtab      = strtab;
    g_frozen_num_entries = num_entries;

    /* Initialize embedded data-file VFS (before any opens) */
    vfs_init(mem, mem_foff, entries, strtab, num_entries);

    char **runtime_envp = vfs_prepare_child_env(envp);

    int nobj = 0;
    for (uint32_t i = 0; i < num_entries; i++)
        if (!(metas[i].flags & LDR_FLAG_INTERP) &&
            !(metas[i].flags & LDR_FLAG_DLOPEN) &&
            !(metas[i].flags & LDR_FLAG_DATA)) nobj++;

    if (nobj == 0) { ldr_err("no objects to load", NULL); return -1; }
    if (nobj > MAX_TOTAL_OBJS) { ldr_err("too many objects", NULL); return -1; }

    /* Use global object table so dlopen'd objects can extend it */
    struct loaded_obj *objs = g_all_objs;
    int idx_map[nobj];    /* idx_map[oi] = manifest index */
    memset(objs, 0, nobj * sizeof(struct loaded_obj));

    /* Build in order: exe first, then shared libs (skip DLOPEN, DATA) */
    int oi = 0;
    for (uint32_t i = 0; i < num_entries; i++) {
        if (metas[i].flags & LDR_FLAG_INTERP) continue;
        if (metas[i].flags & LDR_FLAG_DLOPEN) continue;
        if (metas[i].flags & LDR_FLAG_DATA) continue;
        if (!(metas[i].flags & LDR_FLAG_MAIN_EXE)) continue;
        objs[oi].name  = strtab + entries[i].name_offset;
        objs[oi].flags = metas[i].flags;
        idx_map[oi] = (int)i;
        oi++;
    }
    for (uint32_t i = 0; i < num_entries; i++) {
        if (metas[i].flags & LDR_FLAG_INTERP) continue;
        if (metas[i].flags & LDR_FLAG_DLOPEN) continue;
        if (metas[i].flags & LDR_FLAG_DATA) continue;
        if (metas[i].flags & LDR_FLAG_MAIN_EXE) continue;
        objs[oi].name  = strtab + entries[i].name_offset;
        objs[oi].flags = metas[i].flags;
        idx_map[oi] = (int)i;
        oi++;
    }

    if (argc > 0 && argv && objs[0].name && objs[0].name[0])
        argv[0] = (char *)objs[0].name;

    /* 2. Map all objects into memory at pre-assigned addresses.
     *    Reserve the entire VA range in one mmap call first, then
     *    map individual segments on top.  This reduces mmap syscalls
     *    from N*M (objects*segments) to 1 + N*M_file-backed. */
    ldr_dbg("[loader] mapping objects...\n");
    if (reserve_address_range(metas, idx_map, nobj, srcfd < 0) < 0) {
        ldr_err("failed to reserve address range", NULL);
        return -1;
    }
    for (int i = 0; i < nobj; i++) {
        int mi = idx_map[i];
        if (map_object(mem, mem_foff, srcfd, &metas[mi], &entries[mi], &objs[i], 1) < 0)
            return -1;
        objs[i].phdr      = (const Elf64_Phdr *)(objs[i].base + metas[mi].phdr_off);
        objs[i].phdr_num  = metas[mi].phdr_num;
        objs[i].map_start = objs[i].base + metas[mi].vaddr_lo;
        objs[i].map_end   = objs[i].base + metas[mi].vaddr_hi;
        if (discover_eh_frame_header(&objs[i]) < 0) {
            ldr_err("malformed PT_GNU_EH_FRAME in", objs[i].name);
            return -1;
        }
        ldr_dbg("  ");
        ldr_dbg(objs[i].name);
        ldr_dbg_hex("  base=0x", objs[i].base);
    }

    /* 3. Parse PT_DYNAMIC for each object */
    ldr_dbg("[loader] parsing dynamic sections...\n");
    for (int i = 0; i < nobj; i++) {
        if (parse_dynamic(&objs[i], &metas[idx_map[i]]) < 0) {
            ldr_err("malformed dynamic metadata in", objs[i].name);
            return -1;
        }
        if (validate_object_relocations(&objs[i]) < 0) {
            ldr_err("malformed relocation metadata in", objs[i].name);
            return -1;
        }
    }
    if (dl_initialize_startup_lookup_scopes(objs, nobj) < 0) {
        ldr_err("malformed startup dependency graph", NULL);
        return -1;
    }

    if (is_musl_runtime &&
        !validate_musl_layout_from_target(find_musl_libc(objs, nobj))) {
        if (prelinked)
            notify_terminal_refusal(handoff_fd);
        ldr_msg("dlfreeze: direct-load artifact failed target musl "
                "private-layout validation\n");
        return -1;
    }
    if (prelinked) {
        for (int i = 0; i < nobj; i++) {
            uint32_t off = metas[idx_map[i]].runtime_fixup_off;
            uint32_t count = metas[idx_map[i]].runtime_fixup_count;

            if (count == 0)
                continue;
            if (!runtime_fixups || off > runtime_fixup_count ||
                count > runtime_fixup_count - off)
                return -1;
            for (uint32_t f = 0; f < count; f++) {
                uint32_t encoded = runtime_fixups[off + f];
                uint32_t index = encoded & ~LDR_PRELINK_FIXUP_JMPREL;
                size_t table_count =
                    (encoded & LDR_PRELINK_FIXUP_JMPREL)
                    ? objs[i].jmprel_count : objs[i].rela_count;

                if (index >= table_count) {
                    ldr_err("invalid pre-linked runtime fixup in",
                            objs[i].name);
                    return -1;
                }
            }
        }
    }
    if (preflight_resolver_relocation_destinations(
            objs, nobj, objs, nobj) < 0) {
        ldr_err("resolver relocation preflight failed", NULL);
        return -1;
    }

    /* 4. Set up TLS (must happen before relocations that reference TLS,
     *    and definitely before calling any IRELATIVE resolvers that might
     *    touch TLS / stack guard) */
    ldr_dbg("[loader] setting up TLS...\n");
    uintptr_t at_random = get_auxval(envp, 25 /* AT_RANDOM */);
    uintptr_t tp = setup_tls(objs, nobj, mem, mem_foff, metas, entries,
                              idx_map, num_entries, at_random);
    if (!tp) {
        ldr_err("TLS setup failed", NULL);
        return -1;
    }
    /* NOTE: After setup_tls, FS register is changed.  The bootstrap's
     * static glibc functions (printf, malloc etc.) are no longer safe
     * to call.  Use only write() and _exit() from here on. */

    /* Mapping and TLS setup are the last phases that do not execute target
     * code.  Relocations may invoke application IFUNC/IRELATIVE resolvers, so
     * fallback becomes unsafe here rather than only at constructor entry.
     * Restore the process's original fatal-signal dispositions before the
     * handoff: loader crash diagnostics must never own application signals. */
    restore_crash_handlers(startup_crash_handlers);
    if (handoff_fd >= 0) {
        char marker = DLFRZ_HANDOFF_APPLICATION_STARTED;
        long written;

        do {
            written = arch_raw_write(handoff_fd, &marker, sizeof(marker));
        } while (written == -EINTR);
        arch_raw_close(handoff_fd);
        handoff_fd = -1;
        if (written != sizeof(marker)) {
            ldr_err("cannot notify bootstrap before application handoff", NULL);
            _exit(127);
        }
    }

    /* 5. Apply relocations for all objects.
     *    Two-pass: first apply all non-IRELATIVE relocations across all
     *    objects so that GOT entries (e.g. _rtld_global_ro) are populated,
     *    then apply IRELATIVE whose resolvers depend on those GOT entries.
     *
     *    If the frozen binary was pre-linked, segments already contain
     *    resolved relocations.  We only need to patch GOT entries for
     *    runtime-only symbols (overrides like dlopen, __tls_get_addr,
     *    and the fake _rtld_global/_rtld_global_ro). */
    if (prelinked) {
        ldr_dbg("[loader] pre-linked: patching overrides...\n");

        /* Resolve real libc file/dir helpers BEFORE overrides are applied,
         * so VFS wrappers can fall through to the real implementation for
         * non-VFS paths and directory streams. Must bypass resolve_sym
         * (which checks g_vfs_overrides and would return our wrappers). */
        if (g_vfs_count > 0) {
            for (int i = 0; i < nobj &&
                    (!g_real_fopen || !g_real_fdopen || !g_real_opendir ||
                     !g_real_fdopendir || !g_real_readdir ||
                     !g_real_malloc || !g_real_realpath ||
                     !g_real_closedir || !g_real_dirfd ||
                     !g_real_rewinddir || !g_real_telldir ||
                     !g_real_errno_location ||
                     !g_real_seekdir); i++) {
                if (!objs[i].dynsym || !objs[i].dynstr) continue;
                for (uint32_t s = 0; s < objs[i].dynsym_count; s++) {
                    const Elf64_Sym *sym = &objs[i].dynsym[s];
                    if (sym->st_shndx == 0 || sym->st_value == 0) continue;
                    if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC) continue;
                    const char *n = objs[i].dynstr + sym->st_name;
                    if (!g_real_fopen && n[0] == 'f' && n[1] == 'o'
                        && (strcmp(n, "fopen64") == 0 ||
                            strcmp(n, "fopen") == 0))
                        g_real_fopen = (fopen_fn)(uintptr_t)(objs[i].base + sym->st_value);
                    else if (!g_real_fdopen && n[0] == 'f' && n[1] == 'd'
                             && strcmp(n, "fdopen") == 0)
                        g_real_fdopen = (fdopen_fn)(uintptr_t)(objs[i].base + sym->st_value);
                    else if (!g_real_opendir && strcmp(n, "opendir") == 0)
                        g_real_opendir = (opendir_fn)(uintptr_t)(objs[i].base + sym->st_value);
                    else if (!g_real_fdopendir && strcmp(n, "fdopendir") == 0)
                        g_real_fdopendir = (fdopendir_fn)(uintptr_t)(objs[i].base + sym->st_value);
                    else if (!g_real_readdir && strcmp(n, "readdir") == 0)
                        g_real_readdir = (readdir_fn)(uintptr_t)(objs[i].base + sym->st_value);
                    else if (!g_real_malloc && strcmp(n, "malloc") == 0)
                        g_real_malloc = (malloc_fn)(uintptr_t)(objs[i].base + sym->st_value);
                    else if (!g_real_closedir && strcmp(n, "closedir") == 0)
                        g_real_closedir = (closedir_fn)(uintptr_t)(objs[i].base + sym->st_value);
                    else if (!g_real_dirfd && strcmp(n, "dirfd") == 0)
                        g_real_dirfd = (dirfd_fn)(uintptr_t)(objs[i].base + sym->st_value);
                    else if (!g_real_rewinddir && strcmp(n, "rewinddir") == 0)
                        g_real_rewinddir = (rewinddir_fn)(uintptr_t)(objs[i].base + sym->st_value);
                    else if (!g_real_realpath && strcmp(n, "realpath") == 0)
                        g_real_realpath = (realpath_fn)(uintptr_t)(objs[i].base + sym->st_value);
                    else if (!g_real_telldir && strcmp(n, "telldir") == 0)
                        g_real_telldir = (telldir_fn)(uintptr_t)(objs[i].base + sym->st_value);
                    else if (!g_real_errno_location &&
                             strcmp(n, "__errno_location") == 0)
                        g_real_errno_location = (errno_location_fn)(uintptr_t)(objs[i].base + sym->st_value);
                    else if (!g_real_seekdir && strcmp(n, "seekdir") == 0)
                        g_real_seekdir = (seekdir_fn)(uintptr_t)(objs[i].base + sym->st_value);
                }
            }
            ldr_dbg("[loader] g_real_fopen=");
            ldr_dbg_hex("0x", (uint64_t)(uintptr_t)g_real_fopen);
            ldr_dbg(" g_real_fdopen=");
            ldr_dbg_hex("0x", (uint64_t)(uintptr_t)g_real_fdopen);
            ldr_dbg(" g_real_opendir=");
            ldr_dbg_hex("0x", (uint64_t)(uintptr_t)g_real_opendir);
            ldr_dbg(" g_real_fdopendir=");
            ldr_dbg_hex("0x", (uint64_t)(uintptr_t)g_real_fdopendir);
            ldr_dbg(" g_real_readdir=");
            ldr_dbg_hex("0x", (uint64_t)(uintptr_t)g_real_readdir);
            ldr_dbg(" g_real_closedir=");
            ldr_dbg_hex("0x", (uint64_t)(uintptr_t)g_real_closedir);
            ldr_dbg(" g_real_dirfd=");
            ldr_dbg_hex("0x", (uint64_t)(uintptr_t)g_real_dirfd);
            ldr_dbg(" g_real_rewinddir=");
            ldr_dbg_hex("0x", (uint64_t)(uintptr_t)g_real_rewinddir);
            ldr_dbg(" g_real_telldir=");
            ldr_dbg_hex("0x", (uint64_t)(uintptr_t)g_real_telldir);
            ldr_dbg(" g_real_errno_location=");
            ldr_dbg_hex("0x", (uint64_t)(uintptr_t)g_real_errno_location);
            ldr_dbg(" g_real_seekdir=");
            ldr_dbg_hex("0x", (uint64_t)(uintptr_t)g_real_seekdir);
        }

        /* Build the unified special-symbol hash table (overrides, stubs,
         * fake rtld objects) for fast O(1) lookup per relocation. */
        build_special_table();

        /* Pre-seed _rtld_global/_rtld_global_ro in every object's GOT
         * before the merged pass.  IRELATIVE resolvers may call code in
         * OTHER objects (e.g. libc) that reads _rtld_global_ro through
         * that object's GOT, so we must patch all GOTs up front.
         * Only scan objects flagged as importing these symbols. */
        for (int i = 0; i < nobj; i++) {
            if ((objs[i].flags & LDR_FLAG_NEEDS_RTLD) &&
                preseed_rtld_got(&objs[i], objs, nobj) < 0)
                _exit(127);
        }

        /* Runtime fixups use the same graph-wide ordering as a normal load.
         * The packer never invokes IFUNC, so every target resolver remains
         * deferred until all ordinary fixups and relocated TLS templates are
         * visible. */
        for (int phase = RELOC_PASS_ORDINARY;
             phase <= RELOC_PASS_IRELATIVE; phase++) {
            enum relocation_pass pass = (enum relocation_pass)phase;

            for (int i = 0; i < nobj; i++) {
                const uint32_t *obj_fixups = NULL;
                uint32_t obj_fixup_count = 0;

                if (runtime_fixups != NULL &&
                    metas[idx_map[i]].runtime_fixup_count != 0) {
                    uint32_t off = metas[idx_map[i]].runtime_fixup_off;
                    uint32_t count = metas[idx_map[i]].runtime_fixup_count;
                    if (off <= runtime_fixup_count &&
                        count <= runtime_fixup_count - off) {
                        obj_fixups = runtime_fixups + off;
                        obj_fixup_count = count;
                    }
                }

                if (pass == RELOC_PASS_ORDINARY && g_debug &&
                    obj_fixup_count != 0) {
                    ldr_msg("[loader] runtime fixups: ");
                    ldr_msg(objs[i].name);
                    ldr_dbg_hex(" count=0x", obj_fixup_count);
                }

                if (obj_fixups != NULL) {
                    for (uint32_t f = 0; f < obj_fixup_count; f++) {
                        uint32_t encoded = obj_fixups[f];
                        const Elf64_Rela *tab;
                        size_t count;
                        uint32_t idx =
                            encoded & ~LDR_PRELINK_FIXUP_JMPREL;

                        if (encoded & LDR_PRELINK_FIXUP_JMPREL) {
                            tab = objs[i].jmprel;
                            count = objs[i].jmprel_count;
                        } else {
                            tab = objs[i].rela;
                            count = objs[i].rela_count;
                        }
                        if (!tab || idx >= count) {
                            ldr_err("invalid pre-linked runtime fixup in",
                                    objs[i].name);
                            _exit(127);
                        }

                        if (apply_prelinked_runtime_reloc(
                                &objs[i], objs, nobj, &tab[idx], pass) < 0)
                            _exit(127);
                    }

                } else if (objs[i].flags & LDR_FLAG_RUNTIME_SCAN) {
                    const Elf64_Rela *tabs[] = {
                        objs[i].rela, objs[i].jmprel
                    };
                    size_t counts[] = {
                        objs[i].rela_count, objs[i].jmprel_count
                    };
                    size_t starts[] = { objs[i].rela_relative_count, 0 };

                    for (int t = 0; t < 2; t++) {
                        for (size_t r = starts[t]; r < counts[t]; r++) {
                            if (apply_prelinked_runtime_reloc(
                                    &objs[i], objs, nobj, &tabs[t][r],
                                    pass) < 0)
                                _exit(127);
                        }
                    }
                }

                /* This narrow exact-name scan is deliberately unconditional.
                 * The packer's compact fixup table must not duplicate or
                 * approximate the loader's evolving special-symbol set. */
                if (pass == RELOC_PASS_ORDINARY &&
                    apply_prelinked_override_fallbacks(&objs[i], objs,
                                                       nobj) < 0)
                    _exit(127);
            }

            if (pass == RELOC_PASS_COPY && tp)
                copy_tdata(objs, nobj, tp);
        }
    } else {
        ldr_dbg("[loader] applying relocations...\n");

        build_special_table();

        /* Pre-seed _rtld_global/_rtld_global_ro GOT entries so IFUNC
         * resolvers called during GLOB_DAT processing work correctly. */
        for (int i = 0; i < nobj; i++) {
            if ((objs[i].flags & LDR_FLAG_NEEDS_RTLD) &&
                preseed_rtld_got(&objs[i], objs, nobj) < 0)
                _exit(127);
        }

        for (int i = 0; i < nobj; i++) {
            if (apply_all_relocs(&objs[i], objs, nobj,
                                 RELOC_PASS_ORDINARY) < 0) {
                ldr_msg("dlfreeze-loader: relocation failed for ");
                ldr_msg(objs[i].name);
                ldr_msg("\n");
                _exit(127);
            }
        }
        for (int i = 0; i < nobj; i++) {
            if (apply_all_relocs(&objs[i], objs, nobj,
                                 RELOC_PASS_COPY) < 0) {
                ldr_msg("dlfreeze-loader: copy relocation failed for ");
                ldr_msg(objs[i].name);
                ldr_msg("\n");
                _exit(127);
            }
        }
        /* Initial TLS becomes visible only after every ordinary and COPY
         * relocation is complete, and before any target resolver runs. */
        if (tp)
            copy_tdata(objs, nobj, tp);
        for (int i = 0; i < nobj; i++) {
            if (apply_all_relocs(&objs[i], objs, nobj,
                                 RELOC_PASS_IFUNC) < 0) {
                ldr_msg("dlfreeze-loader: IFUNC relocation failed for ");
                ldr_msg(objs[i].name);
                ldr_msg("\n");
                _exit(127);
            }
        }
        for (int i = 0; i < nobj; i++) {
            if (apply_all_relocs(&objs[i], objs, nobj,
                                 RELOC_PASS_IRELATIVE) < 0) {
                ldr_msg("dlfreeze-loader: IRELATIVE failed for ");
                ldr_msg(objs[i].name);
                ldr_msg("\n");
                _exit(127);
            }
        }
    }

    /* 6. Set final memory protections.
     *    For pre-linked objects, segments were already mapped with their
     *    correct ELF permissions from map_object, so no mprotect needed
     *    — UNLESS memcpy was used (perf mode or UPX path with srcfd<0),
     *    where the anonymous reservation leaves pages as RWX and we need
     *    to set proper per-segment permissions. */
    ldr_dbg("[loader] setting protections...\n");
    /* Always call protect_object for every loaded object so that text
     * pages are correctly marked PROT_EXEC.  For prelinked non-UPX
     * binaries the file-backed mmap already sets the right permissions,
     * but if mmap falls back to memcpy the pages would be PROT_RW only
     * and executing them would raise SIGILL.  The extra mprotect calls
     * are a no-op when the permissions already match. */
    for (int i = 0; i < nobj; i++) {
        if (protect_object(&objs[i], &metas[idx_map[i]]) < 0) {
            ldr_err("cannot set final memory protections for", objs[i].name);
            _exit(127);
        }
    }

    /* Set dlopen support globals before init functions or main() can
     * call dlopen.  g_nobj is the count of objects in g_all_objs. */
    g_nobj = nobj;
    g_argc = argc;
    g_argv = argv;
    g_envp = runtime_envp;

    /* Resolve entry/program-header info before libc startup decisions. */
    uintptr_t entry = 0;
    uintptr_t exe_phdr = 0;
    uintptr_t at_base = 0;
    int exe_phnum = 0;
    for (int i = 0; i < nobj; i++) {
        if (!(objs[i].flags & LDR_FLAG_MAIN_EXE))
            continue;
        int mi = idx_map[i];
        entry = objs[i].base + metas[mi].entry;
        exe_phdr = objs[i].base + metas[mi].phdr_off;
        exe_phnum = metas[mi].phdr_num;
        break;
    }
    if (!entry) {
        ldr_err("no entry point found", NULL);
        _exit(127);
    }

    if (is_musl_runtime) {
        for (int i = 0; i < nobj; i++) {
            if (objs[i].flags & LDR_FLAG_MAIN_EXE)
                continue;
            if (is_musl_libc_path(objs[i].name)) {
                at_base = objs[i].base;
                break;
            }
        }
    }

#if defined(__aarch64__)
    /* Note: an early _start transfer was tried here historically but it
     * caused vfprintf format-parsing crashes (SIGSEGV at TP+0x198) on
     * glibc 2.35+ aarch64 because it skipped init_libc_process_state and
     * the init_array fan-out.  Direct main / __libc_start_main bridge
     * paths below handle every case correctly. */
#endif

    /* 7. Initialise libc process state (environ, arena, tcache) BEFORE
     *    calling any init functions — library init_array entries may call
     *    malloc, so the arena must be ready. */
    init_libc_process_state(objs, nobj, argc, argv, runtime_envp, envp);

    /* Decide startup ownership before constructors run.  When we call main
     * directly, target libc never gets the __libc_start_main opportunity to
     * register rtld finalization.  Register our equivalent first so that
     * constructor/main atexit callbacks run before ELF fini arrays.  Entry
     * and __libc_start_main bridge paths retain their existing ownership. */
    typedef int (*main_fn_t)(int, char **, char **);
    uint64_t main_addr = resolve_main_address(objs, nobj, idx_map, metas,
                                              entry,
                                              is_musl_runtime);
    uint64_t start_main_bridge_addr = 0;
#if defined(__aarch64__)
    if (main_addr && !is_musl_runtime && !g_glibc_early_init_done)
        start_main_bridge_addr = resolve_sym(objs, nobj, "__libc_start_main");
#endif
    int direct_main_owner = main_addr && !start_main_bridge_addr &&
        (is_musl_runtime || g_glibc_early_init_done ||
         glibc_direct_main_without_early_init_ok());
    uint64_t target_exit_addr = 0;

    if (direct_main_owner) {
        uint64_t cxa_atexit_addr = resolve_sym(objs, nobj, "__cxa_atexit");

        target_exit_addr = resolve_sym(objs, nobj, "exit");
        if (!cxa_atexit_addr || !target_exit_addr) {
            ldr_err("target libc does not provide __cxa_atexit/exit", NULL);
            _exit(127);
        }
        restore_ptr_guard();
        if (((int (*)(void (*)(void *), void *, void *))
             (uintptr_t)cxa_atexit_addr)(run_loader_finalizers_cxa,
                                         NULL, NULL) != 0) {
            ldr_err("cannot register target finalizer", NULL);
            _exit(127);
        }
    }

    /* 7b. Call shared library init functions (libc first, then others).
     *    Skip the exe — its constructors are called later.
     *    Now safe because _rtld_global/_rtld_global_ro stubs are in place
     *    and __tunable_get_val etc. resolve to our no-op stubs. */
    ldr_dbg("[loader] calling init functions...\n");
    typedef void (*init_fn_t)(int, char **, char **);

    /* Ensure pointer_guard is correct before init functions — init code
     * may call PTR_MANGLE-using functions like __cxa_atexit. */
    restore_ptr_guard();

    /* Glibc executes the main object's preinit array before dependency
     * constructors.  Musl's dynamic linker deliberately does not process
     * DT_PREINIT_ARRAY, so preserve that runtime's native behaviour. */
    if (!is_musl_runtime) {
        for (int i = 0; i < nobj; i++) {
            if (!(objs[i].flags & LDR_FLAG_MAIN_EXE))
                continue;
            for (size_t j = 0; j < objs[i].preinit_array_sz; j++)
                ((init_fn_t)objs[i].preinit_array[j])(
                    argc, argv, runtime_envp);
        }
    }

    /* Topologically sort objects so dependencies init before dependents.
     * The packer's discovery order is not necessarily dependency order; a
     * constructor may call into a dependency discovered later. */
    {
        int order[nobj > 0 ? nobj : 1];
        char state[nobj > 0 ? nobj : 1];
        int order_count = 0;
        for (int i = 0; i < nobj; i++) state[i] = 0;
        for (int i = 0; i < nobj; i++)
            topo_visit_init(i, objs, nobj, state, order, &order_count);

        for (int oi = 0; oi < order_count; oi++) {
            int i = order[oi];
            if (objs[i].flags & LDR_FLAG_MAIN_EXE) continue;
            ldr_dbg("[loader] init: ");
            ldr_dbg(objs[i].name);
            ldr_dbg("\n");
            record_object_init(&objs[i]);
            if (objs[i].init_func)
                ((init_fn_t)objs[i].init_func)(argc, argv, runtime_envp);
            for (size_t j = 0; j < objs[i].init_array_sz; j++)
                ((init_fn_t)objs[i].init_array[j])(argc, argv, runtime_envp);
        }
    }

    for (int i = 0; i < nobj; i++) {
        if (!(objs[i].flags & LDR_FLAG_MAIN_EXE)) continue;
        ldr_dbg("[loader] init: ");
        ldr_dbg(objs[i].name);
        ldr_dbg("\n");
        record_object_init(&objs[i]);
        if (objs[i].init_func)
            ((init_fn_t)objs[i].init_func)(argc, argv, runtime_envp);
        for (size_t j = 0; j < objs[i].init_array_sz; j++)
            ((init_fn_t)objs[i].init_array[j])(argc, argv, runtime_envp);
    }

    ldr_dbg("[loader] init functions done\n");

    /* 8. Try to call main() directly, bypassing __libc_start_main.
     *    __libc_start_main accesses _rtld_global which requires ld.so.
     *    For musl and newer glibc builds with __libc_early_init, calling
     *    main() directly works because:
     *    - stdio FILE structs are statically initialized in libc's .data
     *    - __libc_single_threaded is 1 (from .data, no locking needed)
     *    - __environ gets set by us below
     *    Older glibc builds still need __libc_start_main-era setup, so
     *    they must fall back through _start. */
    ldr_dbg("[loader] resolving main...\n");

#if defined(__aarch64__)
     /* Prefer direct main after __libc_early_init; the bridge can crash on large VFS payloads. */
    if (main_addr && !is_musl_runtime && !g_glibc_early_init_done) {
        if (start_main_bridge_addr) {
            typedef int (*libc_start_main_fn_t)(
                int (*)(int, char **, char **),
                int, char **,
                void (*)(void),
                void (*)(void),
                void (*)(void),
                void *);
            ldr_dbg("[loader] using __libc_start_main bridge...\n");
            restore_ptr_guard();
            int rc = ((libc_start_main_fn_t)(uintptr_t)start_main_bridge_addr)(
                (main_fn_t)(uintptr_t)main_addr,
                argc,
                argv,
                NULL,
                NULL,
                NULL,
                (void *)&argv[-1]);
            _exit(rc);
        }
    }
#endif

    if (direct_main_owner) {
        /* Warm up glibc's allocator so main_arena's top chunk lands in the
         * process brk before we enter user code. musl does not need this
         * ptmalloc-specific bootstrap path.  Older glibc builds without
         * __libc_early_init are not ready for a bootstrap malloc here and
         * can fault before we even enter main(). */
        if (!is_musl_runtime && g_glibc_early_init_done) {
            uint64_t libc_malloc_addr = resolve_sym(objs, nobj, "malloc");
            uint64_t libc_free_addr = resolve_sym(objs, nobj, "free");
            if (libc_malloc_addr && libc_free_addr) {
                void *p = ((void *(*)(size_t))(uintptr_t)libc_malloc_addr)(64);
                if (p)
                    ((void (*)(void *))(uintptr_t)libc_free_addr)(p);
            }
        } else if (!is_musl_runtime && g_debug) {
            ldr_dbg("[loader] skipping allocator warmup (no __libc_early_init)\n");
        }
        ldr_dbg("[loader] calling main() directly...\n");
        restore_ptr_guard();
        int rc = ((main_fn_t)(uintptr_t)main_addr)(argc, argv, runtime_envp);
        ldr_dbg("[loader] main() returned\n");
        /* Returning from main is defined as exit(rc), not _exit(rc).  Target
         * libc now owns atexit/TLS teardown and invokes our ELF finalizer as
         * the earliest-registered (therefore last-run) exit callback. */
        restore_ptr_guard();
        ((void (*)(int))(uintptr_t)target_exit_addr)(rc);
        _exit(rc);
    }

    if (main_addr && !is_musl_runtime && g_debug && !g_glibc_early_init_done)
        ldr_dbg("[loader] using _start path (glibc needs __libc_start_main init)\n");

    /* Fallback: transfer control via _start → __libc_start_main. */
    ldr_dbg("[loader] transferring to _start...\n");
    restore_ptr_guard();
    transfer_to_entry(entry, argc, argv, envp,
                      exe_phdr, exe_phnum, at_base, entry, at_random,
                      is_musl_runtime);
    /* NOTREACHED */
}
