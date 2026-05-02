/*
 * dlfreeze in-process ELF loader.
 *
 * Maps embedded shared objects from the frozen binary's virtual memory,
 * resolves symbols, applies relocations, sets up TLS, and transfers
 * control to the main executable — all without ld.so.
 *
 * Target: x86-64 glibc/Linux
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

#include "common.h"
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
#define ARCH_ELF_MACHINE      EM_X86_64
#define ARCH_RELOC_RELATIVE   R_X86_64_RELATIVE
#define ARCH_RELOC_GLOB_DAT   R_X86_64_GLOB_DAT
#define ARCH_RELOC_JUMP_SLOT  R_X86_64_JUMP_SLOT
#define ARCH_RELOC_ABS        R_X86_64_64
#define ARCH_RELOC_TPOFF      R_X86_64_TPOFF64
#define ARCH_RELOC_DTPMOD     R_X86_64_DTPMOD64
#define ARCH_RELOC_DTPOFF     R_X86_64_DTPOFF64
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
#else
  #error "Unsupported architecture"
#endif

/* Zeroed page used as target for unresolved OBJECT symbols.
 * Prevents NULL dereference crashes in IFUNC resolvers. */
static void *g_null_page;

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
    int64_t  dtv_offset;
    uint64_t entry_shift;
};

#define AARCH64_TLSDESC_ARGS_PER_PAGE 127

extern uintptr_t dlfreeze_aarch64_tlsdesc_static(void *);
extern uintptr_t dlfreeze_aarch64_tlsdesc_dynamic(void *);
static int64_t dlfreeze_aarch64_tlsdesc_resolve_c(void *arg_in);
static void *musl_lazy_install_tls(uintptr_t tp, unsigned long modid,
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
     * preserved.  Fast path inline; slow path (empty DTV slot) calls
     * dlfreeze_aarch64_tlsdesc_resolve_c which lazily allocates a per-
     * thread TLS block. */
    ".global dlfreeze_aarch64_tlsdesc_dynamic\n"
    ".hidden dlfreeze_aarch64_tlsdesc_dynamic\n"
    ".type dlfreeze_aarch64_tlsdesc_dynamic, %function\n"
    "dlfreeze_aarch64_tlsdesc_dynamic:\n"
    "\tstp x1, x2, [sp, #-16]!\n"
    "\tstp x3, x4, [sp, #-16]!\n"
    "\tmrs x1, tpidr_el0\n"
    "\tldr x0, [x0, #8]\n"            /* x0 = arg pointer (kept until end) */
    "\tldp x2, x3, [x0]\n"            /* x2=modid, x3=offset */
    "\tldr x4, [x0, #16]\n"           /* x4=dtv_offset */
    "\tldr x4, [x1, x4]\n"            /* x4 = DTV pointer */
    "\tcbz x4, 1f\n"                  /* no DTV — slow path */
    "\tldr x2, [x0, #24]\n"           /* x2 = entry_shift (overwrite modid) */
    "\tldr x4, [x0]\n"                /* x4 = modid */
    "\tlsl x2, x4, x2\n"              /* x2 = modid << shift */
    "\tldr x4, [x0, #16]\n"           /* reload dtv_offset */
    "\tldr x4, [x1, x4]\n"            /* DTV again */
    "\tldr x4, [x4, x2]\n"            /* x4 = DTV[byte_idx] */
    "\tcbz x4, 1f\n"                  /* empty slot — slow path */
    "\tadd x0, x4, x3\n"              /* tls_block + offset */
    "\tsub x0, x0, x1\n"              /* return relative to tp */
    "\tldp x3, x4, [sp], #16\n"
    "\tldp x1, x2, [sp], #16\n"
    "\tret\n"
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
    "\tbl dlfreeze_aarch64_tlsdesc_resolve_c\n"
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
    uintptr_t tls_addr = (uintptr_t)musl_lazy_install_tls(
        tp, (unsigned long)arg->modid, (unsigned long)arg->offset);
    return (int64_t)(tls_addr - tp);
}
#endif

#define MUSL_PROGNAME_NEAR_ENVIRON_MAX              0x100
#define MUSL_ENVIRON_TO_INIT_FINI_LIST_PTR_OLD      0x1a8
#define MUSL_ENVIRON_TO_INIT_FINI_LIST_SENTINEL_OLD 0x560
#define MUSL_ENVIRON_TO_INIT_FINI_LIST_PTR_NEW      0xa70
#define MUSL_ENVIRON_TO_INIT_FINI_LIST_SENTINEL_NEW 0x78

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

static int frozen_uses_musl(const struct dlfrz_lib_meta *metas,
                            const struct dlfrz_entry *entries,
                            const char *strtab,
                            uint32_t num_entries)
{
    for (uint32_t i = 0; i < num_entries; i++) {
        const char *name;

        if (!(metas[i].flags & LDR_FLAG_INTERP))
            continue;
        name = strtab + entries[i].name_offset;
        if (strncmp(path_basename(name), "ld-musl", 7) == 0)
            return 1;
    }
    return 0;
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

enum deferred_crash_handler_kind {
    DEFERRED_CRASH_NONE = 0,
    DEFERRED_CRASH_SIGACTION,
    DEFERRED_CRASH_SIGNAL,
};

struct deferred_crash_handler {
    int kind;
    struct sigaction act;
    signal_handler_t handler;
};

static int g_crash_handlers_locked;
static unsigned int g_crash_guard_depth;
static struct sigaction g_saved_crash_handlers[CRASH_SIGNAL_COUNT];
static struct deferred_crash_handler
    g_deferred_crash_handlers[CRASH_SIGNAL_COUNT];

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

static int crash_signal_slot(int signum)
{
    for (int i = 0; i < CRASH_SIGNAL_COUNT; i++)
        if (g_crash_signals[i] == signum)
            return i;
    return -1;
}

static int is_loader_crash_action(const struct sigaction *act)
{
    return (act->sa_flags & SA_SIGINFO) &&
           act->sa_sigaction == crash_handler;
}

static void capture_crash_handlers(struct sigaction *dst)
{
    for (int i = 0; i < CRASH_SIGNAL_COUNT; i++)
    guarded_sigaction(g_crash_signals[i], NULL, &dst[i]);
}

static void fill_visible_crash_oldact(int slot, struct sigaction *oldact)
{
    if (!oldact) return;

    if (g_deferred_crash_handlers[slot].kind == DEFERRED_CRASH_SIGACTION) {
        *oldact = g_deferred_crash_handlers[slot].act;
        return;
    }

    if (g_deferred_crash_handlers[slot].kind == DEFERRED_CRASH_SIGNAL) {
        memset(oldact, 0, sizeof(*oldact));
        oldact->sa_handler = g_deferred_crash_handlers[slot].handler;
        sigemptyset(&oldact->sa_mask);
        return;
    }

    *oldact = g_saved_crash_handlers[slot];
}

static void restore_crash_handlers_if_still_loader(const struct sigaction *saved)
{
    for (int i = 0; i < CRASH_SIGNAL_COUNT; i++) {
        struct sigaction cur;

        if (guarded_sigaction(g_crash_signals[i], NULL, &cur) < 0)
            continue;
        if (is_loader_crash_action(&cur))
            guarded_sigaction(g_crash_signals[i], &saved[i], NULL);
    }
}

static void begin_crash_handler_guard_from_saved(const struct sigaction *saved)
{
    if (g_crash_guard_depth++ > 0)
        return;

    memcpy(g_saved_crash_handlers, saved, sizeof(g_saved_crash_handlers));
    memset(g_deferred_crash_handlers, 0, sizeof(g_deferred_crash_handlers));
    g_crash_handlers_locked = 1;
    install_crash_handlers();
}

static void begin_crash_handler_guard(void)
{
    struct sigaction saved[CRASH_SIGNAL_COUNT];

    capture_crash_handlers(saved);
    begin_crash_handler_guard_from_saved(saved);
}

static void end_crash_handler_guard(void)
{
    if (g_crash_guard_depth == 0)
        return;
    if (--g_crash_guard_depth != 0)
        return;

    g_crash_handlers_locked = 0;

    for (int i = 0; i < CRASH_SIGNAL_COUNT; i++) {
        switch (g_deferred_crash_handlers[i].kind) {
        case DEFERRED_CRASH_SIGACTION:
            guarded_sigaction(g_crash_signals[i],
                              &g_deferred_crash_handlers[i].act, NULL);
            break;
        case DEFERRED_CRASH_SIGNAL:
            guarded_signal(g_crash_signals[i],
                           g_deferred_crash_handlers[i].handler);
            break;
        default:
            guarded_sigaction(g_crash_signals[i], &g_saved_crash_handlers[i],
                              NULL);
            break;
        }
    }

    memset(g_deferred_crash_handlers, 0, sizeof(g_deferred_crash_handlers));
}

/*
 * Wrapper for sigaction() — libraries in our GOT will call this instead
 * of the real sigaction.  While the loader's crash guard is active, defer
 * fatal-signal handler changes until control returns to the frozen program.
 */

static int vfs_sigaction(int signum, const struct sigaction *act,
                         struct sigaction *oldact)
{
    int slot = crash_signal_slot(signum);

    if (g_crash_handlers_locked && slot >= 0) {
        fill_visible_crash_oldact(slot, oldact);
        if (act) {
            g_deferred_crash_handlers[slot].kind = DEFERRED_CRASH_SIGACTION;
            g_deferred_crash_handlers[slot].act = *act;
            g_deferred_crash_handlers[slot].handler = NULL;
        }
        return 0;
    }
    return guarded_sigaction(signum, act, oldact);
}

static signal_handler_t vfs_signal(int signum, signal_handler_t handler)
{
    int slot = crash_signal_slot(signum);

    if (g_crash_handlers_locked && slot >= 0) {
        struct sigaction oldact;

        fill_visible_crash_oldact(slot, &oldact);
        g_deferred_crash_handlers[slot].kind = DEFERRED_CRASH_SIGNAL;
        g_deferred_crash_handlers[slot].handler = handler;
        memset(&g_deferred_crash_handlers[slot].act, 0,
               sizeof(g_deferred_crash_handlers[slot].act));
        return oldact.sa_handler;
    }

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
 * We detect the correct layout at runtime by parsing the embedded
 * ld-linux.so's .dynsym for the _rtld_global_ro and _rtld_global
 * OBJECT symbols — their st_size uniquely identifies the struct layout.
 * This avoids hardcoding against any particular glibc version and keeps
 * dlfreeze portable as a static musl binary.
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

/* glibc 2.35–2.39 (AArch64): _rtld_global_ro=688B, _rtld_global=4504B
 * Ubuntu 22.04 arm64 (glibc 2.35) through Ubuntu 24.04 arm64 (glibc 2.39).
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

static uint8_t *g_fake_rtld_global;
static uint8_t *g_fake_rtld_global_ro;
static const struct glibc_ver_offsets *g_glibc_off = &glibc_2_40;
static size_t g_tls_static_size = 0x1080;
static size_t g_tls_static_align = 0x40;

/* glibc consumers such as Ruby's main-thread stack setup may read
 * __libc_stack_end from ld-linux. Direct-load mode does not map the real
 * interpreter, so provide loader-owned storage for that symbol. */
static void *g_fake_libc_stack_end;

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
 * We provide our own copies.  __rseq_offset is set at runtime once the
 * static TLS layout is known so the 32-byte rseq area sits below every
 * TLS block copied into the thread image.
 * __rseq_size = 32 is the minimum kernel rseq struct size.
 */
static int64_t  g_rseq_offset = -160;
static uint32_t g_rseq_size   = 32;
static uint32_t g_rseq_flags  = 0;

/* ---- _rtld_global_ro function-pointer stubs (dl* wrappers) ----------- */
/*
 * glibc's libc.so calls dlopen / dlsym / dlclose / dlerror through
 * function pointers stored in _rtld_global_ro (the real pointers are
 * set by ld-linux.so at process startup).  Without the real dynamic
 * linker these slots are NULL.  When Python does "import _json", libc's
 * dlopen → _dlerror_run → GLRO(dl_catch_error)(…) dereferences offset
 * 856 → calls address 0 → SIGSEGV at RIP=0x0.
 *
 * Providing minimal stubs that return "error" makes dlopen() return
 * NULL and dlerror() return an explanatory message, so Python (and
 * other programs) fall back to pure-Python code gracefully.
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
    *(size_t *)(g_fake_rtld_global_ro + GLRO_DL_PAGESIZE_OFF) = 4096;
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
    /*
     * Populate _dl_x86_cpu_features from CPUID so that IFUNC resolvers
     * (memcpy, memset, strcmp, etc.) pick CPU-appropriate implementations.
     * Without this, resolvers see all-zero features and fall back to
     * a generic SSE2 variant that prefetches 12 KiB ahead, causing
     * SIGSEGV on buffer boundaries.
     *
     * struct cpu_features layout (stable across glibc 2.35–2.43):
     *   +0x70  _dl_x86_cpu_features
     *     +0   cpu_features_basic (20 bytes: kind, max_cpuid, family, model, stepping)
     *     +20  cpuid_feature_internal features[10] (32 bytes each: cpuid + usable)
     *     +340 preferred[1]
     *     +344 isa_1
     *     ...
     */
#define CPUF_BASE       0x70   /* _dl_x86_cpu_features in _rtld_global_ro */
#define CPUF_BASIC      (CPUF_BASE + 0)
#define CPUF_FEATURES(i) (CPUF_BASE + 20 + 32*(i))
#define CPUF_PREFERRED  (CPUF_BASE + 340)
    {
        uint32_t eax, ebx, ecx, edx;

        /* CPUID(0) — max leaf & vendor */
        __asm__ volatile("cpuid" : "=a"(eax),"=b"(ebx),"=c"(ecx),"=d"(edx)
                         : "a"(0), "c"(0));
        uint32_t max_leaf = eax;
        /* basic.kind = 1 (x86-64 arch), basic.max_cpuid = max_leaf */
        *(uint32_t *)(g_fake_rtld_global_ro + CPUF_BASIC + 0)  = 1;
        *(uint32_t *)(g_fake_rtld_global_ro + CPUF_BASIC + 4)  = max_leaf;

        /* CPUID(1) — family/model/stepping + feature flags */
        if (max_leaf >= 1) {
            __asm__ volatile("cpuid" : "=a"(eax),"=b"(ebx),"=c"(ecx),"=d"(edx)
                             : "a"(1), "c"(0));
            /* Decode family/model/stepping */
            uint32_t family = (eax >> 8) & 0xf;
            uint32_t model  = (eax >> 4) & 0xf;
            if (family == 6 || family == 15)
                model += ((eax >> 16) & 0xf) << 4;
            if (family == 15)
                family += (eax >> 20) & 0xff;
            *(uint32_t *)(g_fake_rtld_global_ro + CPUF_BASIC + 8)  = family;
            *(uint32_t *)(g_fake_rtld_global_ro + CPUF_BASIC + 12) = model;
            *(uint32_t *)(g_fake_rtld_global_ro + CPUF_BASIC + 16) = eax & 0xf;

            /* features[0].cpuid = raw CPUID(1) output */
            uint8_t *f0 = g_fake_rtld_global_ro + CPUF_FEATURES(0);
            *(uint32_t *)(f0 + 0)  = eax;
            *(uint32_t *)(f0 + 4)  = ebx;
            *(uint32_t *)(f0 + 8)  = ecx;
            *(uint32_t *)(f0 + 12) = edx;
            /* features[0].usable — copy cpuid results.
             * For AVX: only mark usable if OS supports XSAVE (ECX bit 27). */
            uint32_t usable_ecx = ecx;
            uint32_t usable_edx = edx;
            if (!(ecx & (1u << 27)))   /* OSXSAVE not set by OS */
                usable_ecx &= ~(1u << 28);  /* clear AVX */
            *(uint32_t *)(f0 + 16) = eax;
            *(uint32_t *)(f0 + 20) = ebx;
            *(uint32_t *)(f0 + 24) = usable_ecx;
            *(uint32_t *)(f0 + 28) = usable_edx;
        }

        /* CPUID(7,0) — extended features (ERMS, AVX2, AVX512, etc.) */
        if (max_leaf >= 7) {
            __asm__ volatile("cpuid" : "=a"(eax),"=b"(ebx),"=c"(ecx),"=d"(edx)
                             : "a"(7), "c"(0));
            uint8_t *f1 = g_fake_rtld_global_ro + CPUF_FEATURES(1);
            *(uint32_t *)(f1 + 0)  = eax;
            *(uint32_t *)(f1 + 4)  = ebx;
            *(uint32_t *)(f1 + 8)  = ecx;
            *(uint32_t *)(f1 + 12) = edx;
            /* usable = same as cpuid for leaf 7 features */
            *(uint32_t *)(f1 + 16) = eax;
            *(uint32_t *)(f1 + 20) = ebx;
            *(uint32_t *)(f1 + 24) = ecx;
            *(uint32_t *)(f1 + 28) = edx;
        }

        /* preferred[0] = 0 — let resolvers use raw feature checks
         * rather than model-specific tuning preferences. */

        /*
         * Non-temporal thresholds: glibc's optimised memcpy/memset use
         * non-temporal (streaming) stores for copies larger than
         * non_temporal_threshold.  Non-temporal stores bypass the cache
         * and write in large aligned chunks (e.g. 96 bytes per iteration
         * with MOVNTPS).  When the threshold is 0 (our default from the
         * zero-filled mmap), the condition "size >= 0" is always true,
         * so EVERY copy — even 67 bytes — takes the non-temporal path.
         * Those large-chunk writes overrun the destination buffer and
         * corrupt adjacent allocations (pymalloc pool headers, etc.).
         *
         * Set thresholds to SIZE_MAX to disable non-temporal stores
         * entirely.  This matches normal behaviour for most workloads
         * (non-temporal copies are only beneficial for multi-MB buffers).
         *
         * cpu_features layout (stable offset for non_temporal_threshold):
         *   +384  non_temporal_threshold         (8 bytes)
         * Following offsets shifted by +8 in glibc 2.40+ (added
         * memset_non_temporal_threshold), but all are set to SIZE_MAX
         * so the shift is harmless — the extra write lands on an adjacent
         * threshold or cache-size field which tolerates SIZE_MAX.
         */
#define CPUF_NON_TEMPORAL_THRESHOLD  (CPUF_BASE + 384)
#define CPUF_MEMSET_NT_THRESHOLD     (CPUF_BASE + 392)
#define CPUF_REP_MOVSB_THRESHOLD     (CPUF_BASE + 400)
#define CPUF_REP_MOVSB_STOP          (CPUF_BASE + 408)
#define CPUF_REP_STOSB_THRESHOLD     (CPUF_BASE + 416)
        *(size_t *)(g_fake_rtld_global_ro + CPUF_NON_TEMPORAL_THRESHOLD) = (size_t)-1;
        *(size_t *)(g_fake_rtld_global_ro + CPUF_MEMSET_NT_THRESHOLD)    = (size_t)-1;
        *(size_t *)(g_fake_rtld_global_ro + CPUF_REP_MOVSB_THRESHOLD)    = (size_t)-1;
        *(size_t *)(g_fake_rtld_global_ro + CPUF_REP_MOVSB_STOP)         = (size_t)-1;
        *(size_t *)(g_fake_rtld_global_ro + CPUF_REP_STOSB_THRESHOLD)    = (size_t)-1;
    }
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
 * The sizes uniquely identify the layout version (e.g., 952 bytes for
 * glibc 2.35–2.39 vs 928 bytes for glibc 2.40+).
 *
 * This approach is fully portable: it reads the actual struct sizes from
 * the binary that was frozen, regardless of which glibc version the build
 * host used.
 */

/* Known layout profiles, keyed by _rtld_global_ro AND _rtld_global st_size.
 * Both sizes are needed to disambiguate versions that share a glro_size
 * (e.g. glibc 2.34 and 2.40+ both have glro=928 but different gl sizes). */
static const struct {
    size_t glro_size;   /* expected st_size of _rtld_global_ro */
    size_t gl_size;     /* expected st_size of _rtld_global    */
    const struct glibc_ver_offsets *offsets;
} glibc_layout_table[] = {
    { 440,  3960, &glibc_2_17 },    /* glibc 2.17–2.28 x86-64 */
    { 520,  4088, &glibc_aarch64_2_27 }, /* glibc 2.27     AArch64 */
    { 536,  3992, &glibc_2_29 },    /* glibc 2.29–2.33 x86-64 (Ubuntu) */
    { 544,  4000, &glibc_2_31_debian }, /* glibc 2.31     x86-64 (Debian 11) */
    { 624,  4152, &glibc_aarch64_2_31 }, /* glibc 2.31     AArch64 */
    { 688,  4504, &glibc_aarch64_2_35 }, /* glibc 2.35–2.39 AArch64 */
    { 928,  4304, &glibc_2_34 },    /* glibc 2.34–2.36 x86-64 */
    { 952,  4352, &glibc_2_37 },    /* glibc 2.37–2.39 x86-64 */
    { 928,  2120, &glibc_2_40 },    /* glibc 2.40+     x86-64 */
};

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

    /* Find PT_DYNAMIC to locate .dynsym and .dynstr */
    const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(elf + ehdr->e_phoff);
    uint64_t dyn_foff = 0;
    size_t dyn_size = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            dyn_foff = phdrs[i].p_offset;
            dyn_size = phdrs[i].p_filesz;
            break;
        }
    }
    if (!dyn_foff || dyn_foff + dyn_size > elf_size) return NULL;

    /* Extract DT_SYMTAB, DT_STRTAB, DT_HASH from dynamic section */
    const Elf64_Dyn *dyn = (const Elf64_Dyn *)(elf + dyn_foff);
    size_t ndyn = dyn_size / sizeof(Elf64_Dyn);
    uint64_t symtab_vaddr = 0, dynstr_vaddr = 0, hash_vaddr = 0;
    for (size_t i = 0; i < ndyn && dyn[i].d_tag != DT_NULL; i++) {
        switch (dyn[i].d_tag) {
            case DT_SYMTAB: symtab_vaddr = dyn[i].d_un.d_ptr; break;
            case DT_STRTAB: dynstr_vaddr = dyn[i].d_un.d_ptr; break;
            case DT_HASH:   hash_vaddr   = dyn[i].d_un.d_ptr; break;
        }
    }
    if (!symtab_vaddr || !dynstr_vaddr) return NULL;

    /* Convert virtual addresses to file offsets */
    uint64_t symtab_foff = elf_vaddr_to_foff(elf, ehdr, symtab_vaddr);
    uint64_t dynstr_foff = elf_vaddr_to_foff(elf, ehdr, dynstr_vaddr);
    if (symtab_foff == (uint64_t)-1 || dynstr_foff == (uint64_t)-1) return NULL;

    /* Get symbol count from DT_HASH (nchain field) */
    uint32_t nsyms = 0;
    if (hash_vaddr) {
        uint64_t hash_foff = elf_vaddr_to_foff(elf, ehdr, hash_vaddr);
        if (hash_foff != (uint64_t)-1 && hash_foff + 8 <= elf_size) {
            const uint32_t *hashtab = (const uint32_t *)(elf + hash_foff);
            nsyms = hashtab[1];  /* nchain = number of symbols */
        }
    }
    if (nsyms == 0) nsyms = 4096;  /* fallback upper bound */

    /* Scan .dynsym for _rtld_global_ro and _rtld_global */
    const Elf64_Sym *syms = (const Elf64_Sym *)(elf + symtab_foff);
    const char *str = (const char *)(elf + dynstr_foff);
    size_t glro_size = 0, gl_size = 0;
    int found = 0;

    for (uint32_t i = 0; i < nsyms && found < 2; i++) {
        if (ELF64_ST_TYPE(syms[i].st_info) != STT_OBJECT) continue;
        if (syms[i].st_size == 0) continue;
        uint32_t noff = syms[i].st_name;
        const char *name = str + noff;
        /* Compare names — _rtld_global_ro first (longer) to avoid false match */
        if (name[0] == '_' && name[1] == 'r') {
            int j = 0;
            const char *expect_ro = "_rtld_global_ro";
            const char *expect_gl = "_rtld_global";
            while (expect_ro[j] && name[j] == expect_ro[j]) j++;
            if (expect_ro[j] == '\0' && (name[j] == '\0' || name[j] == '@')) {
                glro_size = syms[i].st_size;
                found++;
            } else {
                j = 0;
                while (expect_gl[j] && name[j] == expect_gl[j]) j++;
                if (expect_gl[j] == '\0' && (name[j] == '\0' || name[j] == '@')) {
                    gl_size = syms[i].st_size;
                    found++;
                }
            }
        }
    }

    if (!glro_size) return NULL;  /* symbol not found */

    /* Match against known layouts (both sizes needed for disambiguation) */
    for (size_t i = 0; i < sizeof(glibc_layout_table)/sizeof(glibc_layout_table[0]); i++) {
        if (glibc_layout_table[i].glro_size == glro_size &&
            glibc_layout_table[i].gl_size == gl_size) {
            ldr_dbg("[loader] detected _rtld_global_ro size from ld-linux.so, matched layout\n");
            return glibc_layout_table[i].offsets;
        }
    }

    /* Unknown struct size — log and return NULL for fallback */
    ldr_dbg("[loader] unknown _rtld_global_ro size, falling back\n");
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

/* _dl_signal_error — fatal: print and abort */
static void stub_dl_signal_error(void)
{
    ldr_msg("dlfreeze-loader: _dl_signal_error called\n");
    _exit(127);
}

/* _dl_signal_exception — fatal */
static void stub_dl_signal_exception(void)
{
    ldr_msg("dlfreeze-loader: _dl_signal_exception called\n");
    _exit(127);
}

/* _dl_catch_exception — call operatep directly (no exception handling) */
static int stub_dl_catch_exception(void *exc, void (*operate)(void *), void *args)
{
    (void)exc;
    operate(args);
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
#define GLIBC_RSEQ_CPU_ID_REGISTRATION_FAILED (-2)

/* Runtime accessors that consult the detected glibc version profile.
 * If the profile leaves the field at -1 we fall back to the default
 * compiled-in macro value (so untested glibc versions still get a
 * reasonable layout — matching modern glibc 2.34+ aarch64). */
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
    if (g_glibc_off && g_glibc_off->pthread_rseq_off >= 0)
        return g_glibc_off->pthread_rseq_off > 0;
    /* Default profile assumes modern glibc with rseq area. */
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
#define MUSL_TCB_PRESERVE_OFF 0x20
#define MUSL_TCB_PRESERVE_LEN 0xb0

#if defined(__x86_64__)
#define MUSL_TLS_GAP_ABOVE_TP              0
#define MUSL_THREAD_DTV_OFF_DEFAULT                0x08
#define MUSL_THREAD_PREV_OFF_DEFAULT               0x10
#define MUSL_THREAD_NEXT_OFF_DEFAULT               0x18
#define MUSL_THREAD_SYSINFO_OFF_DEFAULT            0x20
#define MUSL_THREAD_TID_OFF_DEFAULT                0x30
#define MUSL_THREAD_ERRNO_OFF_DEFAULT              0x34
#define MUSL_THREAD_DETACH_STATE_OFF_DEFAULT       0x38
#define MUSL_THREAD_ROBUST_HEAD_OFF_DEFAULT        0x88
#define MUSL_THREAD_LOCALE_OFF_DEFAULT             0xa8
#elif defined(__aarch64__)
#define MUSL_TLS_GAP_ABOVE_TP              16
#define MUSL_THREAD_DTV_OFF_DEFAULT                0xc0
#define MUSL_THREAD_PREV_OFF_DEFAULT               0x08
#define MUSL_THREAD_NEXT_OFF_DEFAULT               0x10
#define MUSL_THREAD_SYSINFO_OFF_DEFAULT            0x18
#define MUSL_THREAD_TID_OFF_DEFAULT                0x20
#define MUSL_THREAD_ERRNO_OFF_DEFAULT              0x24
#define MUSL_THREAD_DETACH_STATE_OFF_DEFAULT       0x28
#define MUSL_THREAD_ROBUST_HEAD_OFF_DEFAULT        0x78
#define MUSL_THREAD_LOCALE_OFF_DEFAULT             0x98
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

static struct musl_thread_layout g_musl_thread = {
    .dtv          = MUSL_THREAD_DTV_OFF_DEFAULT,
    .prev         = MUSL_THREAD_PREV_OFF_DEFAULT,
    .next         = MUSL_THREAD_NEXT_OFF_DEFAULT,
    .sysinfo      = MUSL_THREAD_SYSINFO_OFF_DEFAULT,
    .tid          = MUSL_THREAD_TID_OFF_DEFAULT,
    .errno_off    = MUSL_THREAD_ERRNO_OFF_DEFAULT,
    .detach_state = MUSL_THREAD_DETACH_STATE_OFF_DEFAULT,
    .robust_head  = MUSL_THREAD_ROBUST_HEAD_OFF_DEFAULT,
    .locale       = MUSL_THREAD_LOCALE_OFF_DEFAULT,
};

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

static inline uintptr_t glibc_aarch64_pthread_self_from_tp(uintptr_t tp)
{
#if defined(__aarch64__)
    return tp - glibc_aarch64_pthread_size();
#else
    return tp;
#endif
}

static inline uintptr_t musl_thread_self_ptr(uintptr_t tp)
{
    return tp - g_musl_tp_self_delta;
}

static inline uintptr_t *musl_thread_dtv_slot(uintptr_t tp)
{
    return (uintptr_t *)(musl_thread_self_ptr(tp) + MUSL_THREAD_DTV_OFF);
}

static int musl_thread_ptr_external(uintptr_t self, uintptr_t val)
{
    return val != 0 && val != self &&
           !(val >= self && val < self + MUSL_THREAD_PROBE_LIMIT);
}

static void probe_musl_thread_layout(uintptr_t old_self, uintptr_t old_tp)
{
    size_t word = sizeof(uintptr_t);
    long tid;
    uintptr_t locale;
    int dtv_probed = 0;

    if (!old_self)
        return;

    for (size_t off = word; off + word < MUSL_THREAD_PROBE_LIMIT; off += word) {
        uintptr_t first = *(uintptr_t *)(old_self + off);
        uintptr_t second = *(uintptr_t *)(old_self + off + word);

        if (first == old_self && second == old_self) {
            g_musl_thread.prev = off;
            g_musl_thread.next = off + word;
            break;
        }
    }

    if (old_tp >= old_self + word && old_tp - old_self < MUSL_THREAD_PROBE_LIMIT) {
        size_t off = (size_t)(old_tp - old_self - word);
        uintptr_t val = *(uintptr_t *)(old_self + off);

        if (musl_thread_ptr_external(old_self, val))
            g_musl_thread.dtv = off;
        dtv_probed = musl_thread_ptr_external(old_self, val);
    }
    if (!dtv_probed && old_tp >= old_self && old_tp - old_self < MUSL_THREAD_PROBE_LIMIT) {
        size_t off = (size_t)(old_tp - old_self);
        uintptr_t val = *(uintptr_t *)(old_self + off);

        if (musl_thread_ptr_external(old_self, val))
            g_musl_thread.dtv = off;
        dtv_probed = musl_thread_ptr_external(old_self, val);
    }
    if (!dtv_probed) {
        for (size_t off = word; off < MUSL_THREAD_PROBE_LIMIT; off += word) {
            uintptr_t val = *(uintptr_t *)(old_self + off);

            if (musl_thread_ptr_external(old_self, val)) {
                g_musl_thread.dtv = off;
                dtv_probed = 1;
                break;
            }
        }
    }

    tid = syscall(SYS_gettid);
    for (size_t off = 0; off + sizeof(int) <= MUSL_THREAD_PROBE_LIMIT; off += sizeof(int)) {
        if (*(int *)(old_self + off) == (int)tid) {
            g_musl_thread.tid = off;
            if (off + 2 * sizeof(int) < MUSL_THREAD_PROBE_LIMIT) {
                g_musl_thread.errno_off = off + sizeof(int);
                g_musl_thread.detach_state = off + 2 * sizeof(int);
            }
            break;
        }
    }

    for (size_t off = word; off < MUSL_THREAD_PROBE_LIMIT; off += word) {
        if (*(uintptr_t *)(old_self + off) == old_self + off) {
            g_musl_thread.robust_head = off;
            break;
        }
    }

    locale = (uintptr_t)uselocale((locale_t)0);
    if (locale && locale != (uintptr_t)-1) {
        for (size_t off = word; off < MUSL_THREAD_PROBE_LIMIT; off += word) {
            if (*(uintptr_t *)(old_self + off) == locale) {
                g_musl_thread.locale = off;
                break;
            }
        }
    }
}

#if defined(__aarch64__)
static void current_aarch64_tlsdesc_layout(int64_t *dtv_offset,
                                           uint64_t *entry_shift)
{
    if (g_is_musl_runtime) {
        *dtv_offset = -8;
        *entry_shift = 3;
        return;
    }

    *dtv_offset = TCB_OFF_DTV;
    *entry_shift = 4;
}
#endif

/* Lazy per-thread musl TLS install — defined later (after `struct
 * loaded_obj`).  Forward declaration so __tls_get_addr can call it. */
static void *musl_lazy_install_tls(uintptr_t tp, unsigned long modid,
                                   unsigned long ti_offset);

/* __tls_get_addr — GD/LD TLS model accessor.
 * Looks up the DTV entry for the module and adds the offset. */
struct tls_index { unsigned long ti_module; unsigned long ti_offset; };
static void *stub_tls_get_addr(struct tls_index *ti)
{
    uintptr_t tp = arch_get_tp();
    uintptr_t *dtv = g_is_musl_runtime
        ? *(uintptr_t **)musl_thread_dtv_slot(tp)
        : *(uintptr_t **)(tp + TCB_OFF_DTV);
    if (g_is_musl_runtime) {
        size_t cur_slots = dtv ? dtv[0] : 0;
        if (dtv && ti->ti_module <= cur_slots && dtv[ti->ti_module]) {
            return (void *)(dtv[ti->ti_module] + ti->ti_offset);
        }
        /* Slot missing — lazily allocate per-thread block. */
        return musl_lazy_install_tls(tp, ti->ti_module, ti->ti_offset);
    }
    if (dtv) {
        /* glibc convention: tcb->dtv points to dtv[1] in the raw array.
         * dtv[modid] = {val, to_free} — each slot is 2 uintptr_t's.
         * So dtv[modid * 2] = pointer to start of that module's TLS block */
        uintptr_t tls_block = dtv[ti->ti_module * 2];
        if (tls_block)
            return (void *)(tls_block + ti->ti_offset);
        if (g_debug) {
            ldr_msg("[tls] DTV slot empty mod=");
            ldr_hex("", ti->ti_module);
        }
    }
    /* Fallback: single-module approximation */
    if (g_debug)
        ldr_hex("[tls] FALLBACK off=", ti->ti_offset);
    return (void *)(tp + ti->ti_offset);
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

/* Check if a symbol name should resolve to one of our fake OBJECT regions */
static uint64_t lookup_fake_object(const char *name)
{
    if (strcmp(name, "_rtld_global") == 0)
        return (uint64_t)(uintptr_t)g_fake_rtld_global;
    if (strcmp(name, "_rtld_global_ro") == 0)
        return (uint64_t)(uintptr_t)g_fake_rtld_global_ro;
    if (strcmp(name, "__libc_stack_end") == 0)
        return (uint64_t)(uintptr_t)&g_fake_libc_stack_end;
    return 0;
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
struct obj_tls {
    int64_t  tpoff;       /* signed offset from TP to TLS block    */
    uint64_t filesz;      /* .tdata initialization size             */
    uint64_t memsz;       /* total TLS block (tdata + tbss)         */
    uint64_t vaddr;       /* p_vaddr of PT_TLS (in loaded image)    */
    uint64_t align;       /* PT_TLS alignment                       */
    size_t   modid;       /* DTV module ID (1-indexed)              */
};

struct loaded_obj {
    const char       *name;
    uint64_t          base;
    uint32_t          flags;
    const uint8_t    *elf;
    size_t            elf_size;

    /* Dynamic symbol table */
    const Elf64_Sym  *dynsym;
    const char       *dynstr;
    uint32_t          dynsym_count;
    const uint32_t   *gnu_hash;
    const uint16_t   *versym;

    /* Relocations */
    const Elf64_Rela *rela;
    size_t            rela_count;
    size_t            rela_relative_count; /* DT_RELACOUNT: # of leading RELATIVE entries */
    const Elf64_Rela *jmprel;
    size_t            jmprel_count;
    const Elf64_Relr *relr;
    size_t            relr_count;

    /* Init / Fini */
    void            (*init_func)(void);
    void           (**init_array)(void);
    size_t            init_array_sz;

    /* Entry point (exe only) */
    uint64_t          entry;

    /* Program headers (for dl_iterate_phdr / _dl_find_object) */
    const Elf64_Phdr *phdr;
    uint16_t          phdr_num;
    uintptr_t         map_start;   /* base + vaddr_lo (first mapped byte) */
    uintptr_t         map_end;     /* base + vaddr_hi (past-the-end) */
    const void       *eh_frame_hdr; /* mapped PT_GNU_EH_FRAME, or NULL */

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
    return addr >= obj->map_start &&
           addr <= obj->map_end &&
           size <= obj->map_end - addr;
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
#endif

static void probe_musl_thread_layout_from_target(const struct loaded_obj *libc_obj)
{
#if defined(__x86_64__)
    uint64_t addr;
    size_t off;

    if (!libc_obj)
        return;

    addr = musl_defined_symbol_addr(libc_obj, "__errno_location");
    if (addr && loaded_obj_contains(libc_obj, (uintptr_t)addr, 32) &&
        decode_x86_64_musl_errno_offset((const uint8_t *)(uintptr_t)addr, 32, &off)) {
        g_musl_thread.errno_off = off;
        if (off >= sizeof(int))
            g_musl_thread.tid = off - sizeof(int);
        if (off + sizeof(int) < MUSL_THREAD_PROBE_LIMIT)
            g_musl_thread.detach_state = off + sizeof(int);
    }

    addr = musl_defined_symbol_addr(libc_obj, "__tls_get_addr");
    if (addr && loaded_obj_contains(libc_obj, (uintptr_t)addr, 48) &&
        decode_x86_64_musl_dtv_offset((const uint8_t *)(uintptr_t)addr, 48, &off))
        g_musl_thread.dtv = off;
#elif defined(__aarch64__)
    uint64_t addr;
    size_t off;

    if (!libc_obj)
        return;

    addr = musl_defined_symbol_addr(libc_obj, "pthread_self");
    if (addr && loaded_obj_contains(libc_obj, (uintptr_t)addr, 32) &&
        decode_aarch64_musl_self_delta((const uint8_t *)(uintptr_t)addr, 32, &off))
        g_musl_tp_self_delta = off;

    addr = musl_defined_symbol_addr(libc_obj, "__errno_location");
    if (addr && loaded_obj_contains(libc_obj, (uintptr_t)addr, 32)) {
        int64_t tp_rel;

        if (decode_aarch64_musl_tp_relative((const uint8_t *)(uintptr_t)addr, 32, &tp_rel) &&
            tp_rel + (int64_t)g_musl_tp_self_delta >= 0 &&
            tp_rel + (int64_t)g_musl_tp_self_delta < MUSL_THREAD_PROBE_LIMIT) {
            off = (size_t)(tp_rel + (int64_t)g_musl_tp_self_delta);
            g_musl_thread.errno_off = off;
            if (off >= sizeof(int))
                g_musl_thread.tid = off - sizeof(int);
            if (off + sizeof(int) < MUSL_THREAD_PROBE_LIMIT)
                g_musl_thread.detach_state = off + sizeof(int);
        }
    }

    addr = musl_defined_symbol_addr(libc_obj, "__tls_get_addr");
    if (addr && loaded_obj_contains(libc_obj, (uintptr_t)addr, 64) &&
        decode_aarch64_musl_dtv_offset((const uint8_t *)(uintptr_t)addr, 64,
                                       g_musl_tp_self_delta, &off))
        g_musl_thread.dtv = off;
#else
    (void)libc_obj;
#endif
}

static void seed_musl_startup_globals(struct loaded_obj *objs, int nobj)
{
    const struct loaded_obj *libc_obj;
    uint64_t env_addr;
    uint64_t prog_addr;
    uint64_t prog_full_addr;
    uint64_t first_prog_addr = 0;
    uintptr_t ptr_delta = MUSL_ENVIRON_TO_INIT_FINI_LIST_PTR_OLD;
    uintptr_t sentinel_delta = MUSL_ENVIRON_TO_INIT_FINI_LIST_SENTINEL_OLD;
    uintptr_t ptr_addr;
    uintptr_t sentinel_addr;

    libc_obj = find_musl_libc(objs, nobj);
    if (!libc_obj)
        return;

    env_addr = musl_defined_symbol_addr(libc_obj, "__environ");
    if (!env_addr)
        return;

    prog_addr = musl_defined_symbol_addr(libc_obj, "__progname");
    prog_full_addr = musl_defined_symbol_addr(libc_obj, "__progname_full");
    if (prog_addr && prog_addr > env_addr)
        first_prog_addr = prog_addr;
    if (prog_full_addr && prog_full_addr > env_addr &&
        (!first_prog_addr || prog_full_addr < first_prog_addr))
        first_prog_addr = prog_full_addr;

    if (first_prog_addr &&
        first_prog_addr - env_addr >= MUSL_PROGNAME_NEAR_ENVIRON_MAX) {
        ptr_delta = MUSL_ENVIRON_TO_INIT_FINI_LIST_PTR_NEW;
        sentinel_delta = MUSL_ENVIRON_TO_INIT_FINI_LIST_SENTINEL_NEW;
    }

    if (env_addr < sentinel_delta)
        return;
    ptr_addr = (uintptr_t)(env_addr + ptr_delta);
    sentinel_addr = (uintptr_t)(env_addr - sentinel_delta);
    if (!loaded_obj_contains(libc_obj, ptr_addr, sizeof(uintptr_t)) ||
        !loaded_obj_contains(libc_obj, sentinel_addr, 1)) {
        if (g_debug)
            ldr_dbg("[loader] musl startup list seed skipped: offset outside map\n");
        return;
    }

    *(uintptr_t *)ptr_addr = sentinel_addr;
}

/* ---- dlopen support globals ------------------------------------------ */

#define MAX_TOTAL_OBJS 512

/* Global object table — populated by loader_run, extended by my_dlopen. */
static struct loaded_obj g_all_objs[MAX_TOTAL_OBJS];
static int g_nobj;

/* Per-object metadata for dlopen'd objects (used by protect_object) */
static struct dlfrz_lib_meta g_dl_metas[MAX_TOTAL_OBJS];

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

static void discover_tls_template(struct loaded_obj *obj,
                                  const Elf64_Phdr *phdrs,
                                  int phnum)
{
    for (int i = 0; i < phnum; i++) {
        uint64_t align;

        if (phdrs[i].p_type != PT_TLS)
            continue;
        align = phdrs[i].p_align ? phdrs[i].p_align : 1;
        obj->tls.filesz = phdrs[i].p_filesz;
        obj->tls.memsz = phdrs[i].p_memsz;
        obj->tls.vaddr = phdrs[i].p_vaddr;
        obj->tls.align = align;
        return;
    }
}

static size_t next_tls_modid(void)
{
    size_t max_modid = 0;

    for (int i = 0; i < g_nobj; i++) {
        if (g_all_objs[i].tls.modid > max_modid)
            max_modid = g_all_objs[i].tls.modid;
    }
    return max_modid + 1;
}

static int install_musl_dlopen_tls(struct loaded_obj *obj)
{
    uintptr_t tp;
    uintptr_t *old_dtv;
    uintptr_t *dtv;
    size_t old_slots = 0;
    size_t new_slots;
    size_t dtv_bytes;
    size_t align;
    size_t map_len;
    void *map;
    uintptr_t tls_base;

    if (!g_is_musl_runtime || obj->tls.memsz == 0 || obj->tls.modid == 0)
        return 0;

    tp = arch_get_tp();
    old_dtv = *(uintptr_t **)musl_thread_dtv_slot(tp);
    if (old_dtv)
        old_slots = old_dtv[0];

    new_slots = obj->tls.modid;
    dtv = old_dtv;
    if (!dtv || old_slots < new_slots) {
        dtv_bytes = ALIGN_UP((new_slots + 1) * sizeof(uintptr_t), 4096);
        dtv = mmap(NULL, dtv_bytes, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (dtv == MAP_FAILED)
            return -1;
        memset(dtv, 0, dtv_bytes);
        if (old_dtv && old_slots + 1 > 0) {
            memcpy(dtv, old_dtv, (old_slots + 1) * sizeof(uintptr_t));
        }
        dtv[0] = new_slots;
        *(uintptr_t **)musl_thread_dtv_slot(tp) = dtv;
    }

    if (dtv[obj->tls.modid])
        return 0;

    align = obj->tls.align ? (size_t)obj->tls.align : sizeof(uintptr_t);
    map_len = ALIGN_UP(obj->tls.memsz + align, 4096);
    map = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED)
        return -1;

    tls_base = ALIGN_UP((uintptr_t)map, align);
    memcpy((void *)tls_base, (const void *)(obj->base + obj->tls.vaddr),
           obj->tls.filesz);
    if (obj->tls.memsz > obj->tls.filesz) {
        memset((void *)(tls_base + obj->tls.filesz), 0,
               obj->tls.memsz - obj->tls.filesz);
    }
    dtv[obj->tls.modid] = tls_base;

    if (g_debug) {
        ldr_msg("[loader] musl dlopen tls: ");
        ldr_msg(obj->name ? obj->name : "?");
        ldr_dbg_hex(" mod=0x", obj->tls.modid);
        ldr_dbg_hex(" block=0x", tls_base);
    }
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
    for (int i = 0; i < g_nobj; i++) {
        if (g_all_objs[i].tls.modid == modid &&
            g_all_objs[i].tls.memsz != 0) {
            obj = &g_all_objs[i];
            break;
        }
    }
    if (!obj)
        return (void *)(tp + ti_offset);

    uintptr_t *dtv = *(uintptr_t **)musl_thread_dtv_slot(tp);
    size_t cur_slots = dtv ? dtv[0] : 0;
    if (!dtv || cur_slots < modid) {
        size_t new_slots = modid;
        size_t bytes = (new_slots + 1) * sizeof(uintptr_t);
        bytes = (bytes + 4095) & ~4095UL;
        uintptr_t *new_dtv = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (new_dtv == MAP_FAILED)
            return (void *)(tp + ti_offset);
        memset(new_dtv, 0, bytes);
        if (dtv && cur_slots > 0)
            memcpy(new_dtv, dtv, (cur_slots + 1) * sizeof(uintptr_t));
        new_dtv[0] = new_slots;
        *(uintptr_t **)musl_thread_dtv_slot(tp) = new_dtv;
        dtv = new_dtv;
    }

    if (!dtv[modid]) {
        size_t align = obj->tls.align ? (size_t)obj->tls.align
                                       : sizeof(uintptr_t);
        size_t map_len = ALIGN_UP(obj->tls.memsz + align, 4096);
        void *map = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (map == MAP_FAILED)
            return (void *)(tp + ti_offset);
        uintptr_t base = ALIGN_UP((uintptr_t)map, align);
        memcpy((void *)base, (const void *)(obj->base + obj->tls.vaddr),
               obj->tls.filesz);
        if (obj->tls.memsz > obj->tls.filesz)
            memset((void *)(base + obj->tls.filesz), 0,
                   obj->tls.memsz - obj->tls.filesz);
        dtv[modid] = base;
        if (g_debug) {
            ldr_msg("[tls] musl lazy install ");
            ldr_msg(obj->name ? obj->name : "?");
            ldr_dbg_hex(" mod=", modid);
            ldr_dbg_hex(" blk=", base);
        }
    }

    return (void *)(dtv[modid] + ti_offset);
}

/* install_glibc_dlopen_tls — allocate a TLS block for a dlopen'd module
 * and install it in the calling thread's DTV.  glibc convention:
 *   tcb->dtv = &raw_dtv[1]   (in dtv_t units, each 2×uintptr_t)
 *   dtv[modid*2]   = pointer to TLS block
 *   dtv[modid*2+1] = to_free marker
 * Only called for glibc runtime; musl uses install_musl_dlopen_tls. */
static int install_glibc_dlopen_tls(struct loaded_obj *obj)
{
    if (g_is_musl_runtime || obj->tls.memsz == 0 || obj->tls.modid == 0)
        return 0;

    uintptr_t tp = arch_get_tp();
    uintptr_t *dtv = *(uintptr_t **)(tp + TCB_OFF_DTV);

    /* Compute required raw DTV capacity.  The raw array is:
     *   raw_dtv[0]=generation, raw_dtv[1]=unused, raw_dtv[2..] = dtv[0..]
     * dtv (stored in tcb) points to raw_dtv+2.
     * Slot numbering: dtv[modid*2] = val, dtv[modid*2+1] = free_marker.
     * We need (modid+1) dtv_t entries, each 2 words → (modid+1)*2 words. */
    size_t need_words = (obj->tls.modid + 1) * 2;

    if (!dtv) {
        /* No DTV at all yet — allocate fresh */
        size_t raw_bytes = (need_words + 2) * sizeof(uintptr_t);
        raw_bytes = ALIGN_UP(raw_bytes, 4096);
        uintptr_t *raw = mmap(NULL, raw_bytes, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (raw == MAP_FAILED) return -1;
        raw[0] = 1;  /* generation */
        raw[1] = 0;
        dtv = raw + 2;
        *(uintptr_t **)(tp + TCB_OFF_DTV) = dtv;
    } else {
        /* Check if current DTV is large enough.  The generation counter
         * lives at dtv[-2] (raw_dtv[0]).  We scan existing slots to
         * determine the old capacity. */
        size_t old_cap = 0;
        /* Walk backwards from dtv pointer: raw_dtv = dtv - 2 */
        uintptr_t *raw_dtv = dtv - 2;
        /* Estimate old capacity from the allocation: look for the largest
         * populated modid.  Fall back to g_nobj as a safe upper bound. */
        for (int i = 0; i < g_nobj; i++) {
            if (g_all_objs[i].tls.memsz == 0) continue;
            size_t s = (g_all_objs[i].tls.modid + 1) * 2;
            if (s > old_cap) old_cap = s;
        }

        if (need_words > old_cap) {
            /* Grow: allocate new, copy old, install */
            size_t raw_bytes = (need_words + 2) * sizeof(uintptr_t);
            raw_bytes = ALIGN_UP(raw_bytes, 4096);
            uintptr_t *new_raw = mmap(NULL, raw_bytes, PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (new_raw == MAP_FAILED) return -1;
            /* Copy old raw array: generation + unused + old_cap words */
            memcpy(new_raw, raw_dtv, (old_cap + 2) * sizeof(uintptr_t));
            dtv = new_raw + 2;
            *(uintptr_t **)(tp + TCB_OFF_DTV) = dtv;
        }
    }

    /* Allocate the TLS block for this module */
    size_t align = obj->tls.align ? (size_t)obj->tls.align : sizeof(uintptr_t);
    size_t map_len = ALIGN_UP(obj->tls.memsz + align, 4096);
    void *map = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED) return -1;

    uintptr_t tls_base = ALIGN_UP((uintptr_t)map, align);
    memcpy((void *)tls_base, (const void *)(obj->base + obj->tls.vaddr),
           obj->tls.filesz);
    if (obj->tls.memsz > obj->tls.filesz)
        memset((void *)(tls_base + obj->tls.filesz), 0,
               obj->tls.memsz - obj->tls.filesz);

    dtv[obj->tls.modid * 2]     = tls_base;
    dtv[obj->tls.modid * 2 + 1] = 0;

    if (g_debug) {
        ldr_msg("[loader] glibc dlopen tls: ");
        ldr_msg(obj->name ? obj->name : "?");
        ldr_dbg_hex(" mod=0x", obj->tls.modid);
        ldr_dbg_hex(" block=0x", tls_base);
    }
    return 0;
}

/* _dl_allocate_tls_init — copy .tdata for every TLS module into a
 * new thread's TLS block.  Called by glibc's pthread_create. */
static int g_tls_alloc_count;
static int g_tls_init_count;
static void *stub_dl_allocate_tls_init(void *mem)
{
    uintptr_t tp = (uintptr_t)mem;
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
        if (g_all_objs[i].tls.memsz == 0) continue;
        /* dlopen'd modules (tpoff==0) live in separate per-thread TLS
         * blocks pointed to by the DTV.  When glibc recycles a cached
         * stack, _dl_allocate_tls_init is called without _dl_allocate_tls,
         * so the existing DTV block is reused and must be reset back to
         * the module's .tdata/.tbss image.  Otherwise __thread variables
         * defined in dlopened libraries would leak across threads. */
        if (g_all_objs[i].tls.tpoff == 0) {
            uintptr_t *dtv = *(uintptr_t **)(tp + TCB_OFF_DTV);
            if (!dtv) continue;
            uintptr_t blk = dtv[g_all_objs[i].tls.modid * 2];
            if (!blk) continue;
            uint8_t *dst = (uint8_t *)blk;
            const uint8_t *src = (const uint8_t *)(
                g_all_objs[i].base + g_all_objs[i].tls.vaddr);
            memcpy(dst, src, g_all_objs[i].tls.filesz);
            size_t bss = g_all_objs[i].tls.memsz - g_all_objs[i].tls.filesz;
            if (bss > 0)
                memset(dst + g_all_objs[i].tls.filesz, 0, bss);
            ldr_dbg("[loader] tls_init dlopen: ");
            ldr_dbg(g_all_objs[i].name ? g_all_objs[i].name : "?");
            ldr_dbg_hex(" mod=", g_all_objs[i].tls.modid);
            ldr_dbg_hex(" blk=", blk);
            continue;
        }
        uint8_t *dst = (uint8_t *)(tp + g_all_objs[i].tls.tpoff);
        const uint8_t *src = (const uint8_t *)(
            g_all_objs[i].base + g_all_objs[i].tls.vaddr);
        ldr_dbg("[loader] tls_init: ");
        ldr_dbg(g_all_objs[i].name ? g_all_objs[i].name : "?");
        ldr_dbg_hex(" tpoff=", (uintptr_t)g_all_objs[i].tls.tpoff);
        memcpy(dst, src, g_all_objs[i].tls.filesz);
        /* Zero the .tbss portion */
        size_t bss = g_all_objs[i].tls.memsz - g_all_objs[i].tls.filesz;
        if (bss > 0)
            memset(dst + g_all_objs[i].tls.filesz, 0, bss);
    }

    /* Ensure TCB self-pointers survive the TLS re-init (cached stack
     * reuse path calls _dl_allocate_tls_init without _dl_allocate_tls,
     * and the stored self-pointer might have been cleared). */
    *(uintptr_t *)(tp + TCB_OFF_SELF)  = tp;
    *(uintptr_t *)(tp + TCB_OFF_SELF2) = tp;

    return mem;
}

/* _dl_allocate_tls — allocate DTV and copy .tdata for a new thread. */
static uintptr_t g_last_tls_tp;
static void *stub_dl_allocate_tls(void *mem)
{
    g_tls_alloc_count++;
    ldr_dbg("[loader] _dl_allocate_tls #");
    ldr_dbg_hex("", (uint64_t)g_tls_alloc_count);
    ldr_dbg_hex("[loader]   tid=", (uint64_t)syscall(SYS_gettid));
    if (!mem) return NULL;
    uintptr_t tp = (uintptr_t)mem;

    /* Set up a minimal DTV for the new thread so __tls_get_addr works.
     * glibc convention: tcbhead.dtv = &raw_dtv[1] (in dtv_t units, each
     * dtv_t is 2 * sizeof(uintptr_t) = 16 bytes on x86-64).
     *   raw_dtv[0].counter = generation
     *   raw_dtv[1]         = unused / nptl bookkeeping
     *   raw_dtv[modid]     = {val, to_free} for TLS module modid (1-indexed)
     * So tcbhead.dtv[-1].counter = generation, tcbhead.dtv[modid] = module.
     */
    size_t dtv_slots = 2 + (size_t)g_nobj;
    size_t raw_dtv_bytes = (1 + dtv_slots) * 2 * sizeof(uintptr_t); /* +1 for dtv[-1] */
    uintptr_t *raw_dtv = mmap(NULL, (raw_dtv_bytes + 4095) & ~4095UL,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw_dtv != MAP_FAILED) {
        raw_dtv[0] = 1;  /* generation counter at raw_dtv[0] = tcb->dtv[-1] */
        raw_dtv[1] = 0;
        /* The pointer stored in tcb->dtv is offset by one dtv_t entry */
        uintptr_t *dtv = raw_dtv + 2; /* skip dtv_t[0] = 2 uintptr_t's */
        for (int i = 0; i < g_nobj; i++) {
            if (g_all_objs[i].tls.memsz == 0) continue;
            size_t slot = g_all_objs[i].tls.modid;
            if (slot >= dtv_slots) continue;
            if (g_all_objs[i].tls.tpoff != 0) {
                /* Static TLS — block is in the pre-allocated area */
                dtv[slot * 2]     = tp + (uintptr_t)g_all_objs[i].tls.tpoff;
            } else {
                /* dlopen'd module — allocate separate TLS block */
                size_t al = g_all_objs[i].tls.align;
                if (!al) al = sizeof(uintptr_t);
                size_t ml = ALIGN_UP(g_all_objs[i].tls.memsz + al, 4096);
                void *blk = mmap(NULL, ml, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (blk == MAP_FAILED) continue;
                uintptr_t ba = ALIGN_UP((uintptr_t)blk, al);
                memcpy((void *)ba,
                       (const void *)(g_all_objs[i].base + g_all_objs[i].tls.vaddr),
                       g_all_objs[i].tls.filesz);
                if (g_all_objs[i].tls.memsz > g_all_objs[i].tls.filesz)
                    memset((void *)(ba + g_all_objs[i].tls.filesz), 0,
                           g_all_objs[i].tls.memsz - g_all_objs[i].tls.filesz);
                dtv[slot * 2] = ba;
            }
            dtv[slot * 2 + 1] = 0;
        }
        *(uintptr_t *)(tp + TCB_OFF_DTV) = (uintptr_t)dtv;
    }

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

    restore_ptr_guard();

    /* Verify our writes survived — debug diagnostics */
    g_last_tls_tp = tp;
    if (g_debug) {
        ldr_dbg_hex("[loader] alloc_tls done tp+0x00=", *(uintptr_t *)(tp + 0));
        ldr_dbg_hex("[loader] alloc_tls done dtv=", *(uintptr_t *)(tp + TCB_OFF_DTV));
        ldr_dbg_hex("[loader] alloc_tls done tp+0x10=", *(uintptr_t *)(tp + 16));
        ldr_dbg_hex("[loader] alloc_tls done tp+0x18=", *(uintptr_t *)(tp + 24));
        /* Dump libc TPOFF64 GOT entries to verify relocation correctness */
        for (int i = 0; i < g_nobj; i++) {
            if (g_all_objs[i].name && strcmp(g_all_objs[i].name, "libc.so.6") == 0) {
                uintptr_t lb = g_all_objs[i].base;
                ldr_dbg_hex("[loader] libc GOT[0x1e6ef0] (tpoff+0x00) =", *(int64_t *)(lb + 0x1e6ef0));
                ldr_dbg_hex("[loader] libc GOT[0x1e6fe0] (tpoff+0x10) =", *(int64_t *)(lb + 0x1e6fe0));
                ldr_dbg_hex("[loader] libc GOT[0x1e6fc8] (tpoff+0x28) =", *(int64_t *)(lb + 0x1e6fc8));
                break;
            }
        }
    }
    return ret;
}

/* ---- _dl_find_object implementation ---------------------------------- */

/* _dl_find_object — used by libgcc_s DWARF unwinder to find FDE info.
 * Searches g_all_objs[] for the object containing `pc` and returns
 * the .eh_frame_hdr pointer so the unwinder can locate FDE entries. */
static int glro_dl_find_object(void *pc, void *result)
{
    uintptr_t addr = (uintptr_t)pc;
    for (int i = 0; i < g_nobj; i++) {
        if (addr >= g_all_objs[i].map_start && addr < g_all_objs[i].map_end) {
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
static void vfs_init_pyc_aliases(void);
static int vfs_dir_exists(const char *path);

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
        vfs_init_pyc_aliases();
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
 * /usr/lib/python3.14/json/__init__.py we record all parent directories:
 *   /usr/lib/python3.14/json
 *   /usr/lib/python3.14
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
    if (g_debug && g_vfs_dir_count > 0) {
        ldr_dbg_hex("[loader] vfs: 0x", g_vfs_dir_count);
        ldr_msg(" directories derived\n");
    }
}

/*
 * vfs_init_pyc_aliases — create synthetic <name>.pyc entries for every
 * __pycache__/<name>.cpython-XY.pyc file where the corresponding
 * <name>.py is missing from VFS.
 *
 * Python's SourceFileLoader needs <name>.py to exist on disk to find a
 * module.  When only the .pyc from __pycache__/ was captured (Python
 * loaded it without opening the .py source), SourceFileLoader fails.
 * SourcelessFileLoader looks for <name>.pyc (without version tag) in
 * the parent directory.  By creating these aliases we enable it to
 * find and load the bytecode.
 */
static void vfs_init_pyc_aliases(void)
{
    static char pyc_strbuf[65536];
    int strpos = 0;
    int alias_count = 0;

    for (int i = 0; i < (int)VFS_HASH_SIZE; i++) {
        if (!g_vfs_table[i].path) continue;
        const char *path = g_vfs_table[i].path;

        /* Match __pycache__/<name>.cpython-<digits>.pyc */
        const char *pc = strstr(path, "/__pycache__/");
        if (!pc) continue;

        const char *fname = pc + 13; /* past "/__pycache__/" */
        const char *cp = strstr(fname, ".cpython-");
        if (!cp) continue;
        const char *ext = cp + 9; /* past ".cpython-" */
        while (*ext >= '0' && *ext <= '9') ext++;
        if (ext[0] != '.' || ext[1] != 'p' || ext[2] != 'y' ||
            ext[3] != 'c' || ext[4] != '\0')
            continue;

        int parent_len = (int)(pc - path);
        int name_len   = (int)(cp - fname);

        /* Build <parent>/<name>.py and <parent>/<name>.pyc in a check buf */
        char buf[512];
        int base = parent_len + 1 + name_len;
        if (base + 5 > (int)sizeof(buf)) continue; /* .pyc\0 */
        memcpy(buf, path, parent_len);
        buf[parent_len] = '/';
        memcpy(buf + parent_len + 1, fname, name_len);

                /* Skip if .py already exists as a real embedded file.
                 * Virtual placeholders should not suppress the sourceless alias. */
        memcpy(buf + base, ".py", 4);
        { const struct vfs_entry *py_ve = vfs_lookup(buf);
                    if (py_ve && !vfs_is_virtual_entry(py_ve)) continue; }

        /* Skip if .pyc already exists */
        memcpy(buf + base, ".pyc", 5);
        if (vfs_lookup(buf)) continue;

        /* Store the new path string */
        int need = base + 4 + 1; /* .pyc\0 */
        if (strpos + need > (int)sizeof(pyc_strbuf)) break;
        char *dest = pyc_strbuf + strpos;
        memcpy(dest, buf, need);
        strpos += need;

        /* Insert into the hash table */
        uint32_t idx = vfs_hash(dest) & (VFS_HASH_SIZE - 1);
        while (g_vfs_table[idx].path)
            idx = (idx + 1) & (VFS_HASH_SIZE - 1);
        g_vfs_table[idx].path = dest;
        g_vfs_table[idx].data = g_vfs_table[i].data;
        g_vfs_table[idx].size = g_vfs_table[i].size;
        g_vfs_count++;
        alias_count++;
    }

    if (g_debug && alias_count > 0) {
        ldr_dbg_hex("[loader] vfs: 0x", alias_count);
        ldr_msg(" pyc aliases created\n");
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
    /* Only materialize archive/object files to the /tmp overlay.  These are
     * consumed by child linker processes (e.g. Alpine clang spawning ld)
     * that cannot see the in-process VFS.  Shared libraries (.so) are loaded
     * in-process via our dlopen/open interceptors, so writing them to /tmp
     * only wastes I/O when freezing Python programs captured with -f
     * that embed many extension modules. */
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

    /* First pass: check whether any captured entry would land in the
     * overlay.  Avoids creating /tmp/dlfreeze-vfs-<pid> for workloads that
     * don't need a child-linker overlay (e.g. Python programs captured
     * with -f that embed many extension modulesed many extension modules). */
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

    envstr = mmap(NULL, ALIGN_UP(str_bytes, 4096), PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    new_envp = mmap(NULL, ALIGN_UP(array_bytes, 4096),
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
 * We replace libc's opendir/readdir/closedir so Python's os.listdir()
 * sees embedded files even when the real directories don't exist.
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
         * Skip entries that already exist on disk (real dir covered them). */
        while (h->phase < 2) {
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
                    /* Skip if real FS already has this file */
                    if (h->fd_compat >= 0) {
                        int r = (int)VFS_SYSCALL(SYS_faccessat, AT_FDCWD, fp, 0 /*F_OK*/, 0);
                        if (r == 0) continue;
                    }
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
                    /* Skip if real FS already has this dir */
                    if (h->fd_compat >= 0) {
                        int r = (int)VFS_SYSCALL(SYS_faccessat, AT_FDCWD, dp, 0, 0);
                        if (r == 0) continue;
                    }
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
    /* Only intercept absolute paths for read-only opens */
    if (path && path[0] == '/' && (flags & 3) == 0 /* O_RDONLY */) {
        /* Directory path captured in VFS: serve virtually (no FS touch). */
        if (vfs_dir_exists(path)) {
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
            vfs_dbg_op("open", path, "file");
            int fd = vfs_serve_memfd(ve, path);
            if (fd >= 0) return fd;
        }
        int ret = (int)VFS_SYSCALL(SYS_openat, AT_FDCWD, path, flags, mode);
        if (ret >= 0) return ret;
        /* Probe-open for a DLOPEN ELF (e.g. Ruby's require checking .so exists) */
        {
            int fd = frozen_dlopen_serve_memfd(path);
            if (fd >= 0) {
                vfs_dbg_op("open", path, "dlopen-elf");
                return fd;
            }
        }
        return ret;
    }
    return (int)VFS_SYSCALL(SYS_openat, AT_FDCWD, path, flags, mode);
}

static int vfs_openat(int dirfd, const char *path, int flags, int mode)
{
    char resolved[PATH_MAX];
    const char *lookup_path = path;
    int real_fd;

    if (path && path[0] != '/' &&
        resolve_vfs_path_at(dirfd, path, resolved, sizeof(resolved)))
        lookup_path = resolved;

    if (lookup_path && lookup_path[0] == '/') {
        /* Serve captured directories purely from VFS: avoid touching the
         * host filesystem whenever the VFS already knows the directory.
         * This applies to both explicit O_DIRECTORY opens and plain
         * O_RDONLY opens that happen to target a directory path. */
        if (vfs_dir_exists(lookup_path)) {
            const struct vfs_entry *ve = vfs_lookup(lookup_path);
            if (!ve || (vfs_is_virtual_entry(ve) &&
                        vfs_is_dir_marker_path(lookup_path))) {
                (void)real_fd;
                int fd = (int)VFS_SYSCALL(SYS_openat, AT_FDCWD, "/",
                                         O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
                if (fd >= 0)
                    remember_vfs_dirfd(fd, lookup_path);
                vfs_dbg_op("openat", lookup_path, "dir-virtual");
                return fd;
            }
        }
        if ((flags & 3) == 0 /* O_RDONLY */) {
            const struct vfs_entry *ve = vfs_lookup(lookup_path);
            if (ve && vfs_is_negative_entry(ve)) {
                vfs_dbg_op("openat", lookup_path, "negative");
                set_loader_errno(ENOENT);
                return -1;
            }
            if (ve && !vfs_is_virtual_entry(ve)) {
                vfs_dbg_op("openat", lookup_path, "file");
                int fd = vfs_serve_memfd(ve, lookup_path);
                if (fd >= 0) return fd;
            }
            /* Fallback: probe-open for a DLOPEN ELF path not in VFS data */
            {
                int ret = (int)VFS_SYSCALL(SYS_openat, dirfd, path, flags, mode);
                if (ret >= 0) return ret;
                int fd = frozen_dlopen_serve_memfd(lookup_path);
                if (fd >= 0) {
                    vfs_dbg_op("openat", lookup_path, "dlopen-elf");
                    return fd;
                }
                return ret;
            }
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
 * When a frozen binary (e.g. Ubuntu 20.04 Ruby) is run on a different distro,
 * the original file paths (e.g. /usr/lib/x86_64-linux-gnu/ruby/2.7.0/monitor.so)
 * don't exist on the host.  Without these helpers, Ruby's openat/stat probes
 * return ENOENT → LoadError before dlopen is ever reached.
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

/* Open a frozen DLOPEN ELF as a memfd so probe-opens (e.g. Ruby's require)
 * succeed even when the original path doesn't exist on the host filesystem. */
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
 * vfs_stat / vfs_fstatat — intercept stat calls for embedded files.
 * Python's import system checks if files exist via stat() before opening.
 * We fabricate a regular-file stat result for embedded VFS entries.
 */
static int vfs_stat(const char *path, struct stat *buf)
{
    if (path && path[0] == '/') {
        /* Report real files and non-directory virtual placeholders so
         * importlib/plugin scanners can discover embedded ELF names.
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
            buf->st_blksize = 4096;
            buf->st_blocks  = (ve->size + 511) / 512;
            return 0;
        }
    }
vfs_stat_fallthrough:;
    /* Directories & everything else: real FS first, VFS fallback */
    int ret = (int)VFS_SYSCALL(SYS_newfstatat, AT_FDCWD, path, buf, 0);
    if (ret == 0) return 0;
    if (path && path[0] == '/') {
        if (vfs_dir_exists(path)) {
            vfs_dbg_op("stat", path, "dir");
            __builtin_memset(buf, 0, sizeof(*buf));
            buf->st_mode  = 040755;  /* directory, rwxr-xr-x */
            buf->st_nlink = 2;
            buf->st_blksize = 4096;
            return 0;
        }
        int64_t elf_sz = frozen_dlopen_elf_size(path);
        if (elf_sz >= 0) {
            vfs_dbg_op("stat", path, "dlopen-elf");
            __builtin_memset(buf, 0, sizeof(*buf));
            buf->st_mode  = 0100644;
            buf->st_nlink = 1;
            buf->st_size  = (off_t)elf_sz;
            buf->st_blksize = 4096;
            buf->st_blocks  = (elf_sz + 511) / 512;
            return 0;
        }
    }
    return ret;
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
            buf->st_blksize = 4096;
            buf->st_blocks  = (ve->size + 511) / 512;
            return 0;
        }
    }
vfs_fstatat_fallthrough:;
    int ret = (int)VFS_SYSCALL(SYS_newfstatat, dirfd, path, buf, flag);
    if (ret == 0) return 0;
    if (lookup_path && lookup_path[0] == '/') {
        if (vfs_dir_exists(lookup_path)) {
            vfs_dbg_op("fstatat", lookup_path, "dir");
            __builtin_memset(buf, 0, sizeof(*buf));
            buf->st_mode  = 040755;
            buf->st_nlink = 2;
            buf->st_blksize = 4096;
            return 0;
        }
        int64_t elf_sz = frozen_dlopen_elf_size(lookup_path);
        if (elf_sz >= 0) {
            vfs_dbg_op("fstatat", lookup_path, "dlopen-elf");
            __builtin_memset(buf, 0, sizeof(*buf));
            buf->st_mode  = 0100644;
            buf->st_nlink = 1;
            buf->st_size  = (off_t)elf_sz;
            buf->st_blksize = 4096;
            buf->st_blocks  = (elf_sz + 511) / 512;
            return 0;
        }
    }
    return ret;
}

/* vfs_access / vfs_faccessat — Python calls os.access() / os.path.exists() */
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
    int ret = (int)VFS_SYSCALL(SYS_faccessat, AT_FDCWD, path, amode, 0);
    if (ret == 0) return 0;
    if (path && path[0] == '/') {
        if (vfs_dir_exists(path)) {
            vfs_dbg_op("access", path, "dir");
            return 0;
        }
        if (frozen_dlopen_elf_size(path) >= 0) {
            vfs_dbg_op("access", path, "dlopen-elf");
            return 0;
        }
    }
    return ret;
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
    int ret = (int)VFS_SYSCALL(SYS_faccessat, dirfd, path, amode, flag);
    if (ret == 0) return 0;
    if (lookup_path && lookup_path[0] == '/') {
        if (vfs_dir_exists(lookup_path)) {
            vfs_dbg_op("faccessat", lookup_path, "dir");
            return 0;
        }
        if (frozen_dlopen_elf_size(lookup_path) >= 0) {
            vfs_dbg_op("faccessat", lookup_path, "dlopen-elf");
            return 0;
        }
    }
    return ret;
}

static int vfs_xstat(int ver, const char *path, struct stat *buf)
{
    (void)ver;
    return vfs_stat(path, buf);
}

static char *vfs_realpath(const char *path, char *resolved)
{
    if (path && path[0] == '/') {
        const struct vfs_entry *ve = vfs_lookup(path);

        if (ve && vfs_is_negative_entry(ve)) {
            set_loader_errno(ENOENT);
            return NULL;
        }

        if (g_real_realpath) {
            char *result = g_real_realpath(path, resolved);

            if (result)
                return result;
        }

        if ((ve && !vfs_is_negative_entry(ve)) ||
            vfs_dir_exists(path) ||
            frozen_dlopen_elf_size(path) >= 0) {
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

struct tls_cache_ent {
    const char *name;
    uint32_t    gh;
    uint32_t    epoch;
    uint8_t     state;
    int64_t     value;
};

static struct sym_cache_ent g_sym_cache[RESOLVE_CACHE_SIZE];
static struct tls_cache_ent g_tls_cache[RESOLVE_CACHE_SIZE];
static uint32_t g_cache_epoch = 1;

static void clear_resolution_caches(void)
{
    g_cache_epoch++;
    if (g_cache_epoch == 0) {
        memset(g_sym_cache, 0, sizeof(g_sym_cache));
        memset(g_tls_cache, 0, sizeof(g_tls_cache));
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

static void sym_cache_store(const char *name, uint32_t gh,
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

/* Return: 1 found, -1 cached miss, 0 not present in cache */
static int tls_cache_lookup(const char *name, uint32_t gh, int64_t *out)
{
    uint32_t idx = gh & (RESOLVE_CACHE_SIZE - 1);
    for (uint32_t n = 0; n < RESOLVE_CACHE_SIZE; n++) {
        struct tls_cache_ent *e = &g_tls_cache[idx];
        if (e->epoch != g_cache_epoch || e->state == CACHE_EMPTY) return 0;
        if (e->gh == gh && e->name && strcmp(e->name, name) == 0) {
            if (e->state == CACHE_FOUND) { *out = e->value; return 1; }
            return -1;
        }
        idx = (idx + 1) & (RESOLVE_CACHE_SIZE - 1);
    }
    return 0;
}

static void tls_cache_store(const char *name, uint32_t gh,
                            uint8_t state, int64_t value)
{
    uint32_t idx = gh & (RESOLVE_CACHE_SIZE - 1);
    for (uint32_t n = 0; n < RESOLVE_CACHE_SIZE; n++) {
        struct tls_cache_ent *e = &g_tls_cache[idx];
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

static const Elf64_Sym *lookup_gnu_hash(const struct loaded_obj *obj,
                                         const char *name, uint32_t gh)
{
    if (!obj->gnu_hash || !obj->dynsym || !obj->dynstr)
        return NULL;

    const uint32_t *ht  = obj->gnu_hash;
    uint32_t nbuckets   = ht[0];
    uint32_t symoffset  = ht[1];
    uint32_t bloom_size = ht[2];
    uint32_t bloom_shift = ht[3];

    const uint64_t *bloom   = (const uint64_t *)&ht[4];
    const uint32_t *buckets = (const uint32_t *)&bloom[bloom_size];
    const uint32_t *chain   = &buckets[nbuckets];

    /* Bloom filter */
    uint64_t word = bloom[(gh / 64) % bloom_size];
    uint64_t mask = (1ULL << (gh % 64)) | (1ULL << ((gh >> bloom_shift) % 64));
    if ((word & mask) != mask) return NULL;

    uint32_t idx = buckets[gh % nbuckets];
    if (idx < symoffset) return NULL;

    const Elf64_Sym *fallback = NULL;
    for (;;) {
        uint32_t ch = chain[idx - symoffset];
        if ((ch | 1) == (gh | 1)) {
            const Elf64_Sym *sym = &obj->dynsym[idx];
            if (sym->st_shndx != SHN_UNDEF &&
                strcmp(obj->dynstr + sym->st_name, name) == 0) {
                /* Prefer default version (versym without HIDDEN bit) */
                if (!obj->versym || !(obj->versym[idx] & 0x8000))
                    return sym;
                if (!fallback)
                    fallback = sym;
            }
        }
        if (ch & 1) break;
        idx++;
    }
    return fallback;
}

static const Elf64_Sym *lookup_linear(const struct loaded_obj *obj,
                                       const char *name)
{
    if (!obj->dynsym || !obj->dynstr) return NULL;
    for (uint32_t i = 1; i < obj->dynsym_count; i++) {
        const Elf64_Sym *sym = &obj->dynsym[i];
        if (sym->st_shndx != SHN_UNDEF &&
            ELF64_ST_BIND(sym->st_info) != STB_LOCAL &&
            strcmp(obj->dynstr + sym->st_name, name) == 0)
            return sym;
    }
    return NULL;
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
    { "__xstat",         (void *)vfs_xstat          },
    { "__xstat64",       (void *)vfs_xstat          },
    { "__lxstat",        (void *)vfs_lxstat         },
    { "__lxstat64",      (void *)vfs_lxstat         },
    { "fstatat",         (void *)vfs_fstatat        },
    { "fstatat64",       (void *)vfs_fstatat        },
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

static int maybe_runtime_override_name(const char *name)
{
    for (const struct stub_sym *o = g_overrides; o->name; o++)
        if (strcmp(name, o->name) == 0)
            return 1;

    if (g_vfs_count > 0) {
        for (const struct stub_sym *o = g_vfs_overrides; o->name; o++)
            if (strcmp(name, o->name) == 0)
                return 1;
    }

    return strcmp(name, "_rtld_global") == 0
        || strcmp(name, "_rtld_global_ro") == 0
        || strcmp(name, "__libc_stack_end") == 0
        || strcmp(name, "__rseq_offset") == 0
        || strcmp(name, "__rseq_size") == 0
        || strcmp(name, "__rseq_flags") == 0
        || strcmp(name, "signal") == 0
        || strcmp(name, "sigaction") == 0
        || strcmp(name, "__sigaction") == 0;
}

/*
 * Global symbol search — exe first, then libs in load order.
 * Returns resolved virtual address or 0.
 */
static uint64_t resolve_sym(struct loaded_obj *objs, int nobj,
                             const char *name)
{
    uint32_t gh = gnu_hash_calc(name);

    uint64_t cached = 0;
    int c = sym_cache_lookup(name, gh, &cached);
    if (c == 1) return cached;
    if (c == -1) return 0;

    /* Check unified special-symbol table (overrides, stubs, fake rtld) */
    if (g_special_tab_ready) {
        uint64_t ovr = lookup_special(name, gh);
        if (ovr) {
            sym_cache_store(name, gh, CACHE_FOUND, ovr);
            return ovr;
        }
    } else {
        /* Fallback to linear lookup before table is built */
        uint64_t ovr = lookup_override(name);
        if (ovr) {
            sym_cache_store(name, gh, CACHE_FOUND, ovr);
            return ovr;
        }
    }

    for (int i = 0; i < nobj; i++) {
        const Elf64_Sym *sym = objs[i].gnu_hash
            ? lookup_gnu_hash(&objs[i], name, gh)
            : lookup_linear(&objs[i], name);
        if (sym) {
            uint64_t addr = objs[i].base + sym->st_value;
            /* IFUNC symbols: the value is a resolver function, call it */
            if (ELF64_ST_TYPE(sym->st_info) == STT_GNU_IFUNC) {
                typedef uint64_t (*ifunc_t)(void);
                addr = ((ifunc_t)addr)();
            }
            sym_cache_store(name, gh, CACHE_FOUND, addr);
            return addr;
        }
    }

    /* Check stubs and fake objects before giving up */
    if (g_special_tab_ready) {
        /* Already checked in unified table above */
    } else {
        uint64_t stub = lookup_stub(name);
        if (!stub) stub = lookup_fake_object(name);
        if (stub) {
            sym_cache_store(name, gh, CACHE_FOUND, stub);
            return stub;
        }
    }

    sym_cache_store(name, gh, CACHE_MISS, 0);
    return 0;
}

/*
 * Resolve a TLS symbol — returns (st_value + owning module's tpoff).
 */
static int resolve_tpoff(struct loaded_obj *objs, int nobj,
                          const char *name, int64_t *out)
{
    uint32_t gh = gnu_hash_calc(name);

    int64_t cached = 0;
    int c = tls_cache_lookup(name, gh, &cached);
    if (c == 1) { *out = cached; return 0; }
    if (c == -1) return -1;

    for (int i = 0; i < nobj; i++) {
        const Elf64_Sym *sym = objs[i].gnu_hash
            ? lookup_gnu_hash(&objs[i], name, gh)
            : lookup_linear(&objs[i], name);
        if (sym) {
            int64_t v = (int64_t)sym->st_value + objs[i].tls.tpoff;
            tls_cache_store(name, gh, CACHE_FOUND, v);
            *out = v;
            return 0;
        }
    }

    tls_cache_store(name, gh, CACHE_MISS, 0);
    return -1;
}

#if defined(__aarch64__)
static int resolve_tlsdesc_target(struct loaded_obj *obj,
                                  struct loaded_obj *all, int nobj,
                                  uint32_t sidx, uint64_t addend,
                                  size_t *modid_out,
                                  uint64_t *offset_out,
                                  int64_t *tprel_out,
                                  int *have_tprel_out)
{
    const struct loaded_obj *owner = obj;
    const Elf64_Sym *sym = NULL;
    const char *name = NULL;

    if (sidx != 0 && sidx < obj->dynsym_count)
        sym = &obj->dynsym[sidx];

    /* sidx == 0 means STN_UNDEF / local-DSO reference: the TLSDESC addend is
     * a direct offset into the object's own TLS block.  Use a synthetic
     * zero-offset symbol so the owner remains `obj`. */
    if (sidx == 0) {
        if (obj->tls.memsz == 0 || obj->tls.modid == 0)
            return -1;
        *modid_out = obj->tls.modid;
        *offset_out = addend;
        if (obj->tls.tpoff != 0) {
            *tprel_out = obj->tls.tpoff + (int64_t)addend;
            *have_tprel_out = 1;
        } else {
            *tprel_out = 0;
            *have_tprel_out = 0;
        }
        return 0;
    }

    if (sym && sym->st_shndx == SHN_UNDEF) {
        name = obj->dynstr + sym->st_name;
        uint32_t gh = gnu_hash_calc(name);

        for (int i = 0; i < nobj; i++) {
            const Elf64_Sym *cand = all[i].gnu_hash
                ? lookup_gnu_hash(&all[i], name, gh)
                : lookup_linear(&all[i], name);

            if (!cand || cand->st_shndx == SHN_UNDEF)
                continue;
            owner = &all[i];
            sym = cand;
            break;
        }
    }

    if (!sym || sym->st_shndx == SHN_UNDEF) {
        if (sym && ELF64_ST_BIND(sym->st_info) == STB_WEAK) {
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
    *offset_out = sym->st_value + addend;
    if (owner->tls.tpoff != 0) {
        *tprel_out = owner->tls.tpoff + (int64_t)*offset_out;
        *have_tprel_out = 1;
    } else {
        *tprel_out = 0;
        *have_tprel_out = 0;
    }

    return 0;
}

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
        int64_t dtv_offset;
        uint64_t entry_shift;
        struct aarch64_tlsdesc_arg *arg = alloc_aarch64_tlsdesc_arg();

        if (!arg)
            return -1;

        current_aarch64_tlsdesc_layout(&dtv_offset, &entry_shift);
        arg->modid = modid;
        arg->offset = offset;
        arg->dtv_offset = dtv_offset;
        arg->entry_shift = entry_shift;

        slot[0] = (uint64_t)(uintptr_t)dlfreeze_aarch64_tlsdesc_dynamic;
        slot[1] = (uint64_t)(uintptr_t)arg;
    }

    return 0;
}
#endif

static void apply_prelinked_runtime_reloc(struct loaded_obj *obj,
                                          struct loaded_obj *objs, int nobj,
                                          const Elf64_Rela *rel)
{
    uint64_t base = obj->base;
    uint32_t type = ELF64_R_TYPE(rel->r_info);
    uint32_t sidx = ELF64_R_SYM(rel->r_info);

#if defined(__aarch64__)
    if (type == ARCH_RELOC_TLSDESC) {
        apply_aarch64_tlsdesc_reloc(obj, objs, nobj, rel);
        return;
    }
#endif

    if (type == ARCH_RELOC_IRELATIVE) {
        typedef uint64_t (*ifunc_t)(void);
        ifunc_t resolver = (ifunc_t)(base + rel->r_addend);
        *(uint64_t *)(base + rel->r_offset) = resolver();
        return;
    }

    if (type == ARCH_RELOC_COPY) {
        uint32_t sidx = ELF64_R_SYM(rel->r_info);
        if (sidx == 0) return;
        const char *name = obj->dynstr + obj->dynsym[sidx].st_name;
        uint64_t src_size = obj->dynsym[sidx].st_size;
        if (g_debug) {
            ldr_msg("COPY reloc: ");
            ldr_msg(name);
            ldr_msg("\n");
        }
        for (int j = 0; j < nobj; j++) {
            if (&objs[j] == obj) continue;
            for (uint32_t k = 0; k < objs[j].dynsym_count; k++) {
                if (objs[j].dynsym[k].st_shndx == 0) continue;
                const char *sn = objs[j].dynstr + objs[j].dynsym[k].st_name;
                if (strcmp(sn, name) != 0) continue;
                uint64_t src = objs[j].base + objs[j].dynsym[k].st_value;
                uint64_t sz = src_size ? src_size : objs[j].dynsym[k].st_size;
                memcpy((void *)(base + rel->r_offset), (void *)src, sz);
                return;
            }
        }
        return;
    }

    if (type == ARCH_RELOC_ABS) {
        if (sidx == 0)
            return;

        {
            const char *name = obj->dynstr + obj->dynsym[sidx].st_name;
            uint64_t addr = resolve_sym(objs, nobj, name);

            if (!addr && ELF64_ST_BIND(obj->dynsym[sidx].st_info) != STB_WEAK
                && ELF64_ST_TYPE(obj->dynsym[sidx].st_info) == STT_OBJECT
                && g_null_page) {
                addr = (uint64_t)(uintptr_t)g_null_page;
            }

            *(uint64_t *)(base + rel->r_offset) = addr + rel->r_addend;
        }
        return;
    }

    if (type == ARCH_RELOC_TPOFF) {
        uint64_t *slot = (uint64_t *)(base + rel->r_offset);
        int64_t value = 0;

        if (g_debug) {
            ldr_msg("[loader] runtime TLS TPOFF: ");
            ldr_msg(obj->name);
            ldr_dbg_hex(" off=0x", rel->r_offset);
        }

        if (sidx != 0) {
            const char *name = obj->dynstr + obj->dynsym[sidx].st_name;
            int64_t tp;

            if (resolve_tpoff(objs, nobj, name, &tp) == 0)
                value = tp + rel->r_addend;
        } else {
            value = obj->tls.tpoff + rel->r_addend;
        }

        *(int64_t *)slot = value;
        if (g_debug) {
            ldr_dbg_hex("  addend=0x", (uint64_t)rel->r_addend);
            ldr_dbg_hex("  value=0x", (uint64_t)value);
        }
        return;
    }

    if (type == ARCH_RELOC_DTPMOD) {
        uint64_t *slot = (uint64_t *)(base + rel->r_offset);

        if (g_debug) {
            ldr_msg("[loader] runtime TLS DTPMOD: ");
            ldr_msg(obj->name);
            ldr_dbg_hex(" off=0x", rel->r_offset);
        }

        if (sidx != 0) {
            const char *name = obj->dynstr + obj->dynsym[sidx].st_name;
            size_t mid = obj->tls.modid ? obj->tls.modid : 1;

            for (int j = 0; j < nobj; j++) {
                const Elf64_Sym *ds = objs[j].gnu_hash
                    ? lookup_gnu_hash(&objs[j], name, gnu_hash_calc(name))
                    : lookup_linear(&objs[j], name);

                if (ds && ds->st_shndx != 0) {
                    mid = objs[j].tls.modid ? objs[j].tls.modid : (size_t)(j + 1);
                    break;
                }
            }
            *slot = mid;
        } else {
            *slot = obj->tls.modid ? obj->tls.modid : 1;
        }
        return;
    }

    if (type == ARCH_RELOC_DTPOFF) {
        uint64_t *slot = (uint64_t *)(base + rel->r_offset);

        if (g_debug) {
            ldr_msg("[loader] runtime TLS DTPOFF: ");
            ldr_msg(obj->name);
            ldr_dbg_hex(" off=0x", rel->r_offset);
        }

        if (sidx != 0) {
            uint64_t off = obj->dynsym[sidx].st_value;

            if (obj->dynsym[sidx].st_shndx == 0) {
                const char *name = obj->dynstr + obj->dynsym[sidx].st_name;

                for (int j = 0; j < nobj; j++) {
                    const Elf64_Sym *ds = objs[j].gnu_hash
                        ? lookup_gnu_hash(&objs[j], name, gnu_hash_calc(name))
                        : lookup_linear(&objs[j], name);

                    if (ds && ds->st_shndx != 0) {
                        off = ds->st_value;
                        break;
                    }
                }
            }
            *slot = off + rel->r_addend;
        } else {
            *slot = rel->r_addend;
        }
        return;
    }

    if (type != ARCH_RELOC_GLOB_DAT &&
        type != ARCH_RELOC_JUMP_SLOT)
        return;

    if (sidx == 0)
        return;

    uint64_t *slot = (uint64_t *)(base + rel->r_offset);

    if (*slot != 0) {
        const char *name = obj->dynstr + obj->dynsym[sidx].st_name;
        if (maybe_runtime_override_name(name)) {
            uint32_t gh = gnu_hash_calc(name);
            uint64_t ovr = lookup_special(name, gh);
            if (ovr) {
                if (g_debug) {
                    ldr_msg("GOT patch: ");
                    ldr_msg(name);
                    ldr_msg(" in ");
                    ldr_msg(obj->name);
                    ldr_msg("\n");
                }
                /* GLOB_DAT/JUMP_SLOT: S (no addend per ELF ABI) */
                *slot = ovr;
            }
        }
        return;
    }

    {
        const char *name = obj->dynstr + obj->dynsym[sidx].st_name;
        uint32_t gh = gnu_hash_calc(name);
        uint64_t ovr = lookup_special(name, gh);
        if (ovr) {
            *slot = ovr;
        } else {
            uint64_t addr = resolve_sym(objs, nobj, name);
            if (addr) {
                *slot = addr;
            } else if (ELF64_ST_BIND(obj->dynsym[sidx].st_info) != STB_WEAK
                       && ELF64_ST_TYPE(obj->dynsym[sidx].st_info) == STT_OBJECT
                       && g_null_page) {
                *slot = (uint64_t)(uintptr_t)g_null_page;
            }
        }
    }
}

/* Fallback pass for pre-linked objects: ensure runtime override symbols
 * like dlopen/dlsym/__tls_get_addr are patched even if the packer's
 * runtime-fixup table omitted a relocation. Keep this narrowly focused
 * on override names so the hot prelinked path still avoids a full
 * generic relocation re-scan. */
static void apply_prelinked_override_fallbacks(struct loaded_obj *obj)
{
    const Elf64_Rela *tabs[] = { obj->rela, obj->jmprel };
    size_t counts[] = { obj->rela_count, obj->jmprel_count };

    for (int t = 0; t < 2; t++) {
        for (size_t i = 0; i < counts[t]; i++) {
            const Elf64_Rela *rel = &tabs[t][i];
            uint32_t type = ELF64_R_TYPE(rel->r_info);
            uint32_t sidx;
            const char *name;
            uint32_t gh;
            uint64_t ovr;
            uint64_t *slot;

            if (type != ARCH_RELOC_GLOB_DAT &&
                type != ARCH_RELOC_JUMP_SLOT)
                continue;

            sidx = ELF64_R_SYM(rel->r_info);
            if (sidx == 0 || sidx >= obj->dynsym_count)
                continue;

            name = obj->dynstr + obj->dynsym[sidx].st_name;
            if (!maybe_runtime_override_name(name))
                continue;

            gh = gnu_hash_calc(name);
            ovr = lookup_special(name, gh);
            if (!ovr)
                continue;

            slot = (uint64_t *)(obj->base + rel->r_offset);
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
        uint64_t lo = metas[mi].base_addr + (metas[mi].vaddr_lo & ~0xFFFULL);
        uint64_t hi = metas[mi].base_addr + ALIGN_UP(metas[mi].vaddr_hi, 4096);
        if (metas[mi].base_addr == 0) {
            if (lo < nat_lo) nat_lo = lo;
            if (hi > nat_hi) nat_hi = hi;
        } else {
            if (lo < rel_lo) rel_lo = lo;
            if (hi > rel_hi) rel_hi = hi;
        }
    }

    int res_prot = PROT_READ | PROT_WRITE;
    if (g_perf_mode || memcpy_mode) res_prot |= PROT_EXEC;

    if (nat_lo < nat_hi) {
        nat_hi += 4 * 4096;
        void *m = mmap((void *)nat_lo, nat_hi - nat_lo, res_prot,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                       -1, 0);
        if (m == MAP_FAILED) return -1;
    }
    if (rel_lo < rel_hi) {
        rel_hi += 4 * 4096;
        void *m = mmap((void *)rel_lo, rel_hi - rel_lo, res_prot,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                       -1, 0);
        if (m == MAP_FAILED) return -1;
    }
    if (nat_lo >= nat_hi && rel_lo >= rel_hi) return -1;
    return 0;
}

static void zero_segment_bss_tail(uint64_t base, const Elf64_Phdr *ph)
{
    if (ph->p_memsz <= ph->p_filesz || ph->p_filesz == 0)
        return;

    uint64_t zero_off = ph->p_vaddr + ph->p_filesz;
    uint64_t zero_end = ALIGN_UP(zero_off, 4096);
    uint64_t seg_end = ph->p_vaddr + ph->p_memsz;

    if (zero_end > seg_end)
        zero_end = seg_end;
    if (zero_end > zero_off)
        memset((void *)(uintptr_t)(base + zero_off), 0, zero_end - zero_off);
}

static int map_object(const uint8_t *mem, uint64_t mem_foff, int srcfd,
                      const struct dlfrz_lib_meta *meta,
                      const struct dlfrz_entry *ent,
                      struct loaded_obj *obj,
                      _Bool pre_reserved)
{
    uint64_t base = meta->base_addr;
    uint64_t lo   = meta->vaddr_lo & ~0xFFFULL;
    uint64_t hi   = ALIGN_UP(meta->vaddr_hi, 4096);

    if (!pre_reserved) {
        /* Lazy dlopen path — reserve the object's address range now */
        uint64_t span = hi - lo + 4 * 4096;
        void *m = mmap((void *)(base + lo), span,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                       -1, 0);
        if (m == MAP_FAILED)
            return -1;  /* address collision — do not use MAP_FIXED */
    }

    /* Copy/map each PT_LOAD segment from the payload. */
    const uint8_t *elf_base = mem + (ent->data_offset - mem_foff);
    /* phdr_off is a vaddr; convert to file offset for embedded data access */
    const uint8_t *phdr_base = elf_base + (meta->phdr_off - meta->vaddr_lo);
    for (int i = 0; i < meta->phdr_num; i++) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(phdr_base + i * meta->phdr_entsz);
        if (ph->p_type != PT_LOAD) continue;

        if (ph->p_filesz > 0 && srcfd >= 0 && mem_foff == 0 && 
            !(g_perf_mode && (meta->flags & LDR_FLAG_MAIN_EXE))) {
            uint64_t seg_page_vaddr = ph->p_vaddr & ~0xFFFULL;
            uint64_t seg_page_off   = ph->p_offset & ~0xFFFULL;
            uint64_t page_delta     = ph->p_vaddr - seg_page_vaddr;
            uint64_t map_len        = ALIGN_UP(page_delta + ph->p_filesz, 4096);
            uint64_t file_off       = ent->data_offset + seg_page_off;

            /* Map with correct ELF permissions + PROT_WRITE for
             * writable segments (relocation targets live here).
             * Text/rodata get their final perms immediately. */
            int prot = PROT_READ;
            if (ph->p_flags & PF_X) prot |= PROT_EXEC;
            if (ph->p_flags & PF_W) prot |= PROT_WRITE;

            void *m = mmap((void *)(base + seg_page_vaddr), map_len,
                           prot,
                           MAP_PRIVATE | MAP_FIXED,
                           srcfd, file_off);
            if (m == MAP_FAILED) {
                /* Fallback to memcpy for this segment if file mapping fails. */
                memcpy((void *)(base + ph->p_vaddr), elf_base + ph->p_offset,
                       ph->p_filesz);
            }
        } else if (ph->p_filesz > 0) {
            memcpy((void *)(base + ph->p_vaddr), elf_base + ph->p_offset,
                   ph->p_filesz);
        }
        /* Only clear the partial tail of the last file-backed page. Full
         * .bss pages are already zero from the anonymous reservation. */
        zero_segment_bss_tail(base, ph);
    }

    obj->base = base;
    obj->elf = elf_base;
    obj->elf_size = ent->data_size;
    return 0;
}

/* ==== Parse PT_DYNAMIC ================================================= */

static void parse_dynamic(struct loaded_obj *obj,
                           const struct dlfrz_lib_meta *meta)
{
    /* Find PT_DYNAMIC in loaded memory */
    uint64_t base = obj->base;
    const uint8_t *phdr_start = (const uint8_t *)(base + meta->phdr_off);
    const Elf64_Phdr *dyn_ph = NULL;

    for (int i = 0; i < meta->phdr_num; i++) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(phdr_start + i * meta->phdr_entsz);
        if (ph->p_type == PT_DYNAMIC) { dyn_ph = ph; break; }
    }
    if (!dyn_ph) return;

    const Elf64_Dyn *dyn = (const Elf64_Dyn *)(base + dyn_ph->p_vaddr);
    size_t dyn_count = dyn_ph->p_memsz / sizeof(Elf64_Dyn);

    uint64_t symtab = 0, strtab = 0, strsz = 0;
    uint64_t rela = 0, rela_sz = 0, relacount = 0;
    uint64_t jmprel = 0, pltrelsz = 0;
    uint64_t relr = 0, relr_sz = 0;
    uint64_t hash_addr = 0;
    uint64_t init = 0, init_array = 0, init_array_sz = 0;
    uint64_t versym_addr = 0;

    for (size_t i = 0; i < dyn_count && dyn[i].d_tag != DT_NULL; i++) {
        switch (dyn[i].d_tag) {
        case DT_SYMTAB:       symtab = dyn[i].d_un.d_ptr;       break;
        case DT_STRTAB:       strtab = dyn[i].d_un.d_ptr;       break;
        case DT_STRSZ:        strsz  = dyn[i].d_un.d_val;       break;
        case DT_RELA:         rela   = dyn[i].d_un.d_ptr;       break;
        case DT_RELASZ:       rela_sz = dyn[i].d_un.d_val;      break;
        case DT_JMPREL:       jmprel = dyn[i].d_un.d_ptr;       break;
        case DT_PLTRELSZ:     pltrelsz = dyn[i].d_un.d_val;     break;
        case DT_GNU_HASH:     hash_addr = dyn[i].d_un.d_ptr;    break;
        case DT_INIT:         init = dyn[i].d_un.d_ptr;         break;
        case DT_INIT_ARRAY:   init_array = dyn[i].d_un.d_ptr;   break;
        case DT_INIT_ARRAYSZ: init_array_sz = dyn[i].d_un.d_val; break;
        case 36: /* DT_RELR */   relr = dyn[i].d_un.d_ptr;      break;
        case 35: /* DT_RELRSZ */ relr_sz = dyn[i].d_un.d_val;   break;
        case DT_VERSYM:       versym_addr = dyn[i].d_un.d_ptr;  break;
        case DT_RELACOUNT:   relacount = dyn[i].d_un.d_val;    break;
        }
    }

    if (symtab)    obj->dynsym   = (const Elf64_Sym *)(base + symtab);
    if (strtab)    obj->dynstr   = (const char *)(base + strtab);
    if (hash_addr) obj->gnu_hash = (const uint32_t *)(base + hash_addr);
    if (versym_addr) obj->versym  = (const uint16_t *)(base + versym_addr);

    /* Count symbols via GNU hash table */
    if (obj->gnu_hash) {
        const uint32_t *ht = obj->gnu_hash;
        uint32_t nb = ht[0], so = ht[1], bs = ht[2];
        const uint32_t *bk = (const uint32_t *)((const uint64_t *)&ht[4] + bs);
        const uint32_t *ch = &bk[nb];
        uint32_t mx = so;
        for (uint32_t b = 0; b < nb; b++)
            if (bk[b] > mx) mx = bk[b];
        if (mx >= so)
            while (!(ch[mx - so] & 1)) mx++;
        obj->dynsym_count = mx + 1;
    }
    if (strsz > 0 && strtab > symtab) {
        uint32_t span_count = (uint32_t)((strtab - symtab) / sizeof(Elf64_Sym));

        if (span_count > obj->dynsym_count)
            obj->dynsym_count = span_count;
    }

    if (rela)       obj->rela       = (const Elf64_Rela *)(base + rela);
    obj->rela_count   = rela_sz / sizeof(Elf64_Rela);
    obj->rela_relative_count = relacount;
    if (jmprel)     obj->jmprel     = (const Elf64_Rela *)(base + jmprel);
    obj->jmprel_count = pltrelsz / sizeof(Elf64_Rela);
    if (relr)       obj->relr       = (const Elf64_Relr *)(base + relr);
    obj->relr_count   = relr_sz / sizeof(Elf64_Relr);

    if (init)       obj->init_func  = (void (*)(void))(base + init);
    if (init_array) obj->init_array = (void (**)(void))(base + init_array);
    obj->init_array_sz = init_array_sz / sizeof(void *);

    obj->entry = (meta->flags & LDR_FLAG_MAIN_EXE)
                 ? base + meta->entry : 0;
}

/* ==== Apply relocations ================================================ */

/* pass: 0 = all except IRELATIVE/COPY, 1 = only IRELATIVE, 2 = only COPY */
static int apply_relocs_rela(struct loaded_obj *obj,
                              const Elf64_Rela *rtab, size_t count,
                              struct loaded_obj *all, int nobj,
                              int pass)
{
    uint64_t base = obj->base;
    for (size_t i = 0; i < count; i++) {
        const Elf64_Rela *r = &rtab[i];
        uint64_t *slot = (uint64_t *)(base + r->r_offset);
        uint32_t type  = ELF64_R_TYPE(r->r_info);
        uint32_t sidx  = ELF64_R_SYM(r->r_info);

        if (type == ARCH_RELOC_IRELATIVE) {
            if (pass == 0) continue;  /* defer to second pass */
            typedef uint64_t (*ifunc_t)(void);
            ifunc_t resolver = (ifunc_t)(base + r->r_addend);
            *slot = resolver();
            continue;
        }
        if (type == ARCH_RELOC_COPY) {
            if (pass != 2) continue;

            /* Copy relocations must wait until source DSOs have already
             * applied their own RELATIVE/RELR relocations. */
            const char *name = obj->dynstr + obj->dynsym[sidx].st_name;
            uint64_t src_size = obj->dynsym[sidx].st_size;
            for (int j = 0; j < nobj; j++) {
                if (&all[j] == obj) continue;
                for (uint32_t k = 0; k < all[j].dynsym_count; k++) {
                    if (all[j].dynsym[k].st_shndx == 0) continue;
                    const char *sn = all[j].dynstr + all[j].dynsym[k].st_name;
                    if (strcmp(sn, name) != 0) continue;
                    uint64_t src = all[j].base + all[j].dynsym[k].st_value;
                    uint64_t sz = src_size ? src_size : all[j].dynsym[k].st_size;
                    memcpy((void *)(base + r->r_offset), (void *)src, sz);
                    goto copy_done;
                }
            }
copy_done:
            continue;
        }
        if (pass != 0) continue;

        switch (type) {
        case ARCH_RELOC_RELATIVE:
            *slot = base + r->r_addend;
            break;

        case ARCH_RELOC_GLOB_DAT:
        case ARCH_RELOC_JUMP_SLOT:
        case ARCH_RELOC_ABS: {
            const char *name = obj->dynstr + obj->dynsym[sidx].st_name;
            uint64_t addr = resolve_sym(all, nobj, name);
            if (!addr && ELF64_ST_BIND(obj->dynsym[sidx].st_info) != STB_WEAK) {
                /* Not fatal — symbol may come from ld.so which we don't load.
                 * Point OBJECT symbols at a safe zero page to prevent NULL
                 * dereference in IFUNC resolvers.  FUNC symbols get 0. */
                if (ELF64_ST_TYPE(obj->dynsym[sidx].st_info) == STT_OBJECT
                    && g_null_page)
                    addr = (uint64_t)(uintptr_t)g_null_page;
                else if (g_debug) {
                    ldr_dbg("[loader] unresolved: ");
                    ldr_dbg(name);
                    ldr_dbg(" in ");
                    ldr_dbg(obj->name);
                    ldr_dbg("\n");
                }
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
                const char *name = obj->dynstr + obj->dynsym[sidx].st_name;
                int64_t tp;
                if (resolve_tpoff(all, nobj, name, &tp) == 0)
                    *(int64_t *)slot = tp + r->r_addend;
                else if (ELF64_ST_BIND(obj->dynsym[sidx].st_info) != STB_WEAK)
                    ldr_err("unresolved TLS symbol", name);
            } else {
                *(int64_t *)slot = obj->tls.tpoff + r->r_addend;
            }
            break;
        }

        case ARCH_RELOC_DTPMOD:
            /* Module ID — for GD/LD TLS model.  Use the correct module ID
             * so __tls_get_addr indexes the right DTV slot. */
            if (sidx != 0) {
                const char *name = obj->dynstr + obj->dynsym[sidx].st_name;
                /* Find the defining object's module ID */
                size_t mid = obj->tls.modid ? obj->tls.modid : 1;
                for (int j = 0; j < nobj; j++) {
                    const Elf64_Sym *ds = all[j].gnu_hash
                        ? lookup_gnu_hash(&all[j], name, gnu_hash_calc(name))
                        : lookup_linear(&all[j], name);
                    if (ds && ds->st_shndx != 0) {
                        mid = all[j].tls.modid ? all[j].tls.modid : (size_t)(j + 1);
                        break;
                    }
                }
                *slot = mid;
            } else {
                *slot = obj->tls.modid ? obj->tls.modid : 1;
            }
            break;

        case ARCH_RELOC_DTPOFF:
            if (sidx != 0) {
                /* If the symbol is undefined locally (imported), look it
                 * up in the defining library to get the correct TLS offset. */
                uint64_t off = obj->dynsym[sidx].st_value;
                if (obj->dynsym[sidx].st_shndx == 0) {
                    const char *name = obj->dynstr + obj->dynsym[sidx].st_name;
                    for (int j = 0; j < nobj; j++) {
                        const Elf64_Sym *ds = all[j].gnu_hash
                            ? lookup_gnu_hash(&all[j], name, gnu_hash_calc(name))
                            : lookup_linear(&all[j], name);
                        if (ds && ds->st_shndx != 0) {
                            off = ds->st_value;
                            break;
                        }
                    }
                }
                *slot = off + r->r_addend;
            } else
                *slot = r->r_addend;
            break;

#if defined(__aarch64__)
        case ARCH_RELOC_TLSDESC:
            if (apply_aarch64_tlsdesc_reloc(obj, all, nobj, r) < 0)
                return -1;
            break;
#endif

        default:
            /* Ignore unknown types for prototype */
            break;
        }
    }
    return 0;
}

static void apply_relr(struct loaded_obj *obj)
{
    if (!obj->relr || obj->relr_count == 0) return;
    uint64_t base = obj->base;
    uint64_t *where = NULL;

    for (size_t i = 0; i < obj->relr_count; i++) {
        Elf64_Relr entry = obj->relr[i];
        if ((entry & 1) == 0) {
            where = (uint64_t *)(base + entry);
            *where += base;
            where++;
        } else {
            uint64_t bitmap = entry >> 1;
            for (int j = 0; bitmap; j++, bitmap >>= 1) {
                if (bitmap & 1) where[j] += base;
            }
            where += 63;
        }
    }
}

/*
 * Pre-seed _rtld_global / _rtld_global_ro GOT entries before any
 * relocations run.  IFUNC resolvers in glibc (memcpy, mempcpy, etc.)
 * read _rtld_global_ro through the GOT.  If a GLOB_DAT for an IFUNC
 * symbol is processed before _rtld_global_ro's own GLOB_DAT in the
 * same rela table, resolve_sym calls the IFUNC resolver → crash.
 * This pre-pass ensures the GOT slots are already populated.
 *
 * Optimised: only matches "_rtld_global" / "_rtld_global_ro" (2 names)
 * with a first-char + 6th-char filter and early exit once both found.
 */
static void preseed_rtld_got(struct loaded_obj *obj)
{
    uint64_t base = obj->base;
    int found = 0;   /* bitmask: bit 0 = _rtld_global, bit 1 = _rtld_global_ro */

    const Elf64_Rela *tabs[] = { obj->rela, obj->jmprel };
    size_t counts[] = { obj->rela_count, obj->jmprel_count };
    for (int t = 0; t < 2 && found != 3; t++) {
        for (size_t i = 0; i < counts[t]; i++) {
            const Elf64_Rela *r = &tabs[t][i];
            uint32_t type = ELF64_R_TYPE(r->r_info);
            if (type != ARCH_RELOC_GLOB_DAT && type != ARCH_RELOC_JUMP_SLOT)
                continue;
            uint32_t sidx = ELF64_R_SYM(r->r_info);
            const char *name = obj->dynstr + obj->dynsym[sidx].st_name;
            /* Fast filter: both targets start with '_r' */
            if (name[0] != '_' || name[1] != 'r') continue;
            uint64_t addr = lookup_fake_object(name);
            if (addr) {
                *(uint64_t *)(base + r->r_offset) = addr + r->r_addend;
                found |= (name[12] == '_') ? 2 : 1;  /* _ro vs plain */
                if (found == 3) break;
            }
        }
    }
}

/* pass: 0 = everything except IRELATIVE/COPY,
 *       1 = only IRELATIVE,
 *       2 = only COPY */
static int apply_all_relocs(struct loaded_obj *obj,
                             struct loaded_obj *all, int nobj,
                             int pass)
{
    if (pass == 0) {
        /* RELR first (all relative, no symbols) */
        apply_relr(obj);
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

#define MUSL_ENVIRON_TO_LIBC_OFF_OLD         0x24e0
#define MUSL_ENVIRON_TO_SYSINFO_OFF          0x30
#define MUSL_ENVIRON_TO_HWCAP_OFF            0x48
#define MUSL_LIBC_GLOBAL_LOCALE_OFF          0x38
#define MUSL_THREAD_SIZE_GUESS               0x100

struct musl_tls_module_state {
    struct musl_tls_module_state *next;
    void *image;
    size_t len;
    size_t size;
    size_t align;
    size_t offset;
};

struct musl_libc_state {
    char can_do_threads;
    char threaded;
    char secure;
    signed char need_locks;
    int threads_minus_1;
    size_t *auxv;
    void *tls_head;
    size_t tls_size;
    size_t tls_align;
    size_t tls_cnt;
    size_t page_size;
};

static uintptr_t get_auxval(char **envp, unsigned long type);
static Elf64_auxv_t *get_auxv_ptr(char **envp);
static const Elf64_Sym *lookup_linear(const struct loaded_obj *obj,
                                      const char *name);
static struct musl_tls_module_state g_musl_tls_modules[MAX_TOTAL_OBJS];

static uint64_t detect_musl_libc_state_addr(const struct loaded_obj *libc_obj,
                                            uint64_t env_addr,
                                            uint64_t prog_addr)
{
    uint64_t libc_addr;
    uint64_t prog_full_addr;

    libc_addr = musl_defined_symbol_addr(libc_obj, "__libc");
    if (libc_addr)
        return libc_addr;

    prog_full_addr = musl_defined_symbol_addr(libc_obj, "__progname_full");
    if (env_addr && prog_addr && prog_full_addr &&
        prog_addr > env_addr && prog_full_addr > env_addr) {
        uint64_t first = prog_addr < prog_full_addr ? prog_addr : prog_full_addr;
        uint64_t second = prog_addr < prog_full_addr ? prog_full_addr : prog_addr;

        if (second - first == sizeof(uintptr_t) &&
            first - env_addr >= MUSL_PROGNAME_NEAR_ENVIRON_MAX)
            return second + 2 * sizeof(uintptr_t);
    }

    if (env_addr >= MUSL_ENVIRON_TO_LIBC_OFF_OLD)
        return env_addr - MUSL_ENVIRON_TO_LIBC_OFF_OLD;
    return 0;
}

static uint64_t detect_musl_global_locale_addr(const struct loaded_obj *libc_obj,
                                               uint64_t libc_addr)
{
    static const char *const names[] = {
        "__global_locale",
        "global_locale",
        "c_locale",
        "C_locale",
    };

    for (size_t i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
        uint64_t addr = musl_defined_symbol_addr(libc_obj, names[i]);

        if (addr && loaded_obj_contains(libc_obj, (uintptr_t)addr, sizeof(uintptr_t)))
            return addr;
    }

    if (libc_addr && loaded_obj_contains(libc_obj,
                                         (uintptr_t)(libc_addr + MUSL_LIBC_GLOBAL_LOCALE_OFF),
                                         sizeof(uintptr_t)))
        return libc_addr + MUSL_LIBC_GLOBAL_LOCALE_OFF;
    return 0;
}

static void init_musl_process_state(struct loaded_obj *objs, int nobj,
                                    char **envp)
{
    const struct loaded_obj *libc_obj;
    uint64_t env_addr;
    uint64_t prog_addr;
    Elf64_auxv_t *auxv;
    struct musl_libc_state *libc;
    uint64_t libc_addr;
    uint64_t locale_addr;
    uintptr_t hwcap = 0;
    uintptr_t sysinfo = 0;
    uintptr_t pagesz = 4096;
    uint64_t sysinfo_addr;
    uint64_t hwcap_addr;
    uintptr_t tp = 0;
    int secure = 0;
    size_t max_modid = 0;
    size_t max_offset = 0;
    size_t max_align = sizeof(uintptr_t);

    if (!g_is_musl_runtime)
        return;

    libc_obj = find_musl_libc(objs, nobj);
    if (!libc_obj)
        return;

    env_addr = musl_defined_symbol_addr(libc_obj, "__environ");
    prog_addr = musl_defined_symbol_addr(libc_obj, "__progname");
    libc_addr = detect_musl_libc_state_addr(libc_obj, env_addr, prog_addr);
    if (!env_addr || !prog_addr || !libc_addr)
        return;

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

    libc = (struct musl_libc_state *)(uintptr_t)libc_addr;
    if (!loaded_obj_contains(libc_obj, (uintptr_t)libc, sizeof(*libc))) {
        if (g_debug)
            ldr_dbg("[loader] musl libc state probe failed: outside map\n");
        return;
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

            mod->image = (void *)(uintptr_t)(objs[i].base + objs[i].tls.vaddr);
            mod->len = objs[i].tls.filesz;
            mod->size = objs[i].tls.memsz;
            mod->align = objs[i].tls.align ? (size_t)objs[i].tls.align : 1;
            mod->offset = offset;
            if (offset > max_offset)
                max_offset = offset;
            break;
        }
        if (mod->align > max_align)
            max_align = mod->align;
    }

    libc->can_do_threads = 1;
    libc->tls_head = max_modid ? &g_musl_tls_modules[0] : NULL;
    libc->tls_cnt = max_modid;
    libc->tls_align = max_align;
    libc->tls_size = ALIGN_UP((max_modid + 1) * sizeof(uintptr_t)
                              + max_offset + MUSL_THREAD_SIZE_GUESS
                              + max_align * 2,
                              max_align);
    libc->auxv = (size_t *)auxv;
    libc->page_size = pagesz;
    libc->secure = secure;

    tp = arch_get_tp();
    if (tp) {
        uintptr_t self = musl_thread_self_ptr(tp);

        *(uintptr_t *)(self + MUSL_THREAD_PREV_OFF) = self;
        *(uintptr_t *)(self + MUSL_THREAD_NEXT_OFF) = self;
        *(uintptr_t *)(self + MUSL_THREAD_SYSINFO_OFF) = sysinfo;
        *(int *)(self + MUSL_THREAD_TID_OFF) = (int)syscall(SYS_gettid);
        *(int *)(self + MUSL_THREAD_ERRNO_OFF) = 0;
        *(int *)(self + MUSL_THREAD_DETACH_STATE_OFF) = 2;
        *(uintptr_t *)(self + MUSL_THREAD_ROBUST_HEAD_OFF) =
            self + MUSL_THREAD_ROBUST_HEAD_OFF;
        locale_addr = detect_musl_global_locale_addr(libc_obj, libc_addr);
        if (locale_addr)
            *(uintptr_t *)(self + MUSL_THREAD_LOCALE_OFF) = (uintptr_t)locale_addr;
    }

    sysinfo_addr = musl_defined_symbol_addr(libc_obj, "__sysinfo");
    if (!sysinfo_addr)
        sysinfo_addr = env_addr + MUSL_ENVIRON_TO_SYSINFO_OFF;
    if (loaded_obj_contains(libc_obj, (uintptr_t)sysinfo_addr, sizeof(uintptr_t)))
        *(uintptr_t *)(uintptr_t)sysinfo_addr = sysinfo;

    hwcap_addr = musl_defined_symbol_addr(libc_obj, "__hwcap");
    if (!hwcap_addr)
        hwcap_addr = env_addr + MUSL_ENVIRON_TO_HWCAP_OFF;
    if (loaded_obj_contains(libc_obj, (uintptr_t)hwcap_addr, sizeof(uintptr_t)))
        *(uintptr_t *)(uintptr_t)hwcap_addr = hwcap;
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
        const Elf64_Sym *sym = objs[i].gnu_hash
            ? lookup_gnu_hash(&objs[i], "__environ", gnu_hash_calc("__environ"))
            : lookup_linear(&objs[i], "__environ");
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
     *   +0x18  _dl_pagesize = 4096
     *   _dl_tls_static_size (non-zero, version-dependent offset)
     *   _dl_tls_static_align (non-zero, version-dependent offset)
     *
     * tcache TLS is already initialized from .tdata to &__tcache_dummy.
     * On first free(), glibc detects tcache == __tcache_dummy and calls
     * tcache_init() which allocates a real tcache via malloc. This is the
     * normal glibc initialization path — no manual tcache setup needed.
     */

    /* Detect glibc version and set version-dependent offsets in the fake
     * _rtld_global/_rtld_global_ro structs.  Must happen BEFORE
     * __libc_early_init which reads _dl_tls_static_align (divides by it).
     *
     * Primary detection happens earlier via detect_glibc_offsets_from_interp()
     * which parses ld-linux.so's symbol table.  This fallback handles the
     * case where the INTERP entry was missing or unparseable. */
    if (g_glibc_off == &glibc_2_40) {
        /* Check if fixup was already applied by the primary detection */
        int already_fixed = *(size_t *)(g_fake_rtld_global_ro +
                             g_glibc_off->glro_tls_static_align) != 0;
        if (!already_fixed) {
            const struct glibc_ver_offsets *glibc_off = &glibc_2_40;
            addr = resolve_sym(objs, nobj, "gnu_get_libc_version");
            if (addr) {
                const char *ver = ((const char *(*)(void))(uintptr_t)addr)();
                if (ver && ver[0] == '2' && ver[1] == '.') {
                    int minor = 0;
                    for (int i = 2; ver[i] >= '0' && ver[i] <= '9'; i++)
                        minor = minor * 10 + (ver[i] - '0');
                    if (minor >= 40)
                        glibc_off = &glibc_2_40;
                    else if (minor >= 37)
                        glibc_off = &glibc_2_37;
                    else if (minor >= 34)
                        glibc_off = &glibc_2_34;
                    else if (minor >= 29)
                        glibc_off = &glibc_2_29;
                    else
                        glibc_off = &glibc_2_17;
                    ldr_dbg("[loader] fallback: glibc version-based offset selection\n");
                }
            }
            fixup_rtld_for_glibc(glibc_off);
            g_glibc_off = glibc_off;
        }
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

static void protect_object(struct loaded_obj *obj,
                            const struct dlfrz_lib_meta *meta)
{
    const uint8_t *phdr_start = (const uint8_t *)(obj->base + meta->phdr_off);
    for (int i = 0; i < meta->phdr_num; i++) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(phdr_start + i * meta->phdr_entsz);
        if (ph->p_type != PT_LOAD) continue;

        int prot = 0;
        if (ph->p_flags & PF_R) prot |= PROT_READ;
        if (ph->p_flags & PF_W) prot |= PROT_WRITE;
        if (ph->p_flags & PF_X) prot |= PROT_EXEC;

        uint64_t ps = (obj->base + ph->p_vaddr) & ~0xFFFULL;
        uint64_t pe = ALIGN_UP(obj->base + ph->p_vaddr + ph->p_memsz, 4096);
        mprotect((void *)ps, pe - ps, prot);
    }
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

static const char *dl_store_name(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    n++;  /* include NUL */
    if (g_dl_strbuf_used + n > sizeof(g_dl_strbuf)) return "?";
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

/* Forward declarations — recursive loading between these functions */
static struct loaded_obj *load_elf_from_file(const char *path);
static struct loaded_obj *load_embedded_object(uint32_t mi);

/* file_has_static_tls — peek at an ELF file on disk and report whether
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
static int file_has_static_tls(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    Elf64_Ehdr eh;
    if (read(fd, &eh, sizeof(eh)) != (ssize_t)sizeof(eh)) {
        close(fd);
        return 0;
    }
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_type != ET_DYN ||
        eh.e_phnum == 0 || eh.e_phnum > 64) {
        close(fd);
        return 0;
    }

    Elf64_Phdr ph[64];
    size_t phsz = (size_t)eh.e_phnum * eh.e_phentsize;
    if (phsz > sizeof(ph) ||
        pread(fd, ph, phsz, eh.e_phoff) != (ssize_t)phsz) {
        close(fd);
        return 0;
    }

    /* Locate PT_DYNAMIC and PT_TLS.  DF_STATIC_TLS is only meaningful
     * if the object actually has a non-empty TLS template — many glibc
     * libs (e.g. libm.so.6) carry the flag for legacy reasons but
     * declare zero TLS, so loading them is harmless. */
    const Elf64_Phdr *dyn_ph = NULL;
    uint64_t tls_memsz = 0;
    for (int i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC) dyn_ph = &ph[i];
        else if (ph[i].p_type == PT_TLS) tls_memsz = ph[i].p_memsz;
    }
    if (!dyn_ph || dyn_ph->p_filesz == 0 ||
        dyn_ph->p_filesz > 64 * 1024 ||
        tls_memsz == 0) {
        close(fd);
        return 0;
    }

    /* Read the dynamic table */
    Elf64_Dyn *dyn = malloc(dyn_ph->p_filesz);
    if (!dyn) { close(fd); return 0; }
    if (pread(fd, dyn, dyn_ph->p_filesz, dyn_ph->p_offset) !=
        (ssize_t)dyn_ph->p_filesz) {
        free(dyn);
        close(fd);
        return 0;
    }
    close(fd);

    int found = 0;
    size_t n = dyn_ph->p_filesz / sizeof(Elf64_Dyn);
    for (size_t i = 0; i < n && dyn[i].d_tag != DT_NULL; i++) {
        if (dyn[i].d_tag == DT_FLAGS &&
            (dyn[i].d_un.d_val & 0x10 /* DF_STATIC_TLS */)) {
            found = 1;
            break;
        }
    }
    free(dyn);
    return found;
}

static const char *g_runtime_search_dirs[] = {
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
    "/lib/aarch64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
    NULL
};

static struct loaded_obj *load_needed_from_filesystem(const char *needed)
{
    char path[PATH_MAX];

    if (!needed || !needed[0])
        return NULL;

    if (needed[0] == '/') {
        int fd = open(needed, O_RDONLY);

        if (fd < 0)
            return NULL;
        close(fd);
        return load_elf_from_file(needed);
    }

    for (const char **dir = g_runtime_search_dirs; *dir; dir++) {
        int fd;

        if (snprintf(path, sizeof(path), "%s/%s", *dir, needed) >=
            (int)sizeof(path))
            continue;

        fd = open(path, O_RDONLY);
        if (fd < 0)
            continue;
        close(fd);
        return load_elf_from_file(path);
    }

    return NULL;
}

/*
 * Load DT_NEEDED dependencies of a just-loaded object.
 * Searches /usr/lib/ and /lib/ for each needed library.
 * Recursive: loading a dependency may trigger loading its own deps.
 */
static void dl_load_needed(struct loaded_obj *obj,
                            const struct dlfrz_lib_meta *meta)
{
    /* Find PT_DYNAMIC in loaded memory */
    const uint8_t *phdr_start = (const uint8_t *)(obj->base + meta->phdr_off);
    const Elf64_Phdr *dyn_ph = NULL;
    for (int i = 0; i < meta->phdr_num; i++) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(phdr_start + i * meta->phdr_entsz);
        if (ph->p_type == PT_DYNAMIC) { dyn_ph = ph; break; }
    }
    if (!dyn_ph || !obj->dynstr) return;

    const Elf64_Dyn *dyn = (const Elf64_Dyn *)(obj->base + dyn_ph->p_vaddr);
    size_t dyn_count = dyn_ph->p_memsz / sizeof(Elf64_Dyn);

    for (size_t i = 0; i < dyn_count && dyn[i].d_tag != DT_NULL; i++) {
        if (dyn[i].d_tag != DT_NEEDED) continue;
        const char *needed = obj->dynstr + dyn[i].d_un.d_val;

        /* Skip if already loaded (basename match) */
        int found = 0;
        for (int j = 0; j < g_nobj; j++) {
            if (!g_all_objs[j].name) continue;
            if (dl_name_matches(g_all_objs[j].name, needed)) {
                found = 1;
                break;
            }
        }
        if (found) continue;

        load_needed_from_filesystem(needed);
    }
}

/*
 * Load an ELF shared object from the filesystem.
 * Maps PT_LOAD segments, resolves symbols, applies relocations,
 * calls init functions.  Returns pointer to loaded_obj or NULL.
 */
static struct loaded_obj *load_elf_from_file(const char *path)
{
    int idx = g_nobj;
    if (idx >= MAX_TOTAL_OBJS) {
        dl_set_error("too many loaded objects", NULL);
        return NULL;
    }

    /* Refuse libraries built with DF_STATIC_TLS — they cannot be loaded
     * after startup without overwriting the calling thread's static TLS
     * area (see file_has_static_tls comment).  Surface this as a normal
     * dlopen failure so callers fall back to alternative ICDs / plugins
     * instead of taking down the process. */
    if (file_has_static_tls(path)) {
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

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        dl_set_error(path, ": cannot open");
        return NULL;
    }

    /* Read ELF header */
    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != (ssize_t)sizeof(ehdr)) {
        close(fd);
        dl_set_error(path, ": cannot read ELF header");
        return NULL;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr.e_type != ET_DYN) {
        close(fd);
        dl_set_error(path, ": not a 64-bit shared object");
        return NULL;
    }
    if (ehdr.e_machine != ARCH_ELF_MACHINE) {
        close(fd);
        dl_set_error(path, ": wrong architecture");
        return NULL;
    }

    /* Read program headers */
    Elf64_Phdr phdr_buf[64];
    if (ehdr.e_phnum > 64) {
        close(fd);
        dl_set_error(path, ": too many program headers");
        return NULL;
    }
    size_t phdr_size = (size_t)ehdr.e_phnum * ehdr.e_phentsize;
    if (pread(fd, phdr_buf, phdr_size, ehdr.e_phoff) != (ssize_t)phdr_size) {
        close(fd);
        dl_set_error(path, ": cannot read program headers");
        return NULL;
    }

    /* Determine vaddr range from PT_LOAD segments */
    uint64_t lo = UINT64_MAX, hi = 0;
    for (int i = 0; i < ehdr.e_phnum; i++) {
        if (phdr_buf[i].p_type != PT_LOAD) continue;
        if (phdr_buf[i].p_vaddr < lo) lo = phdr_buf[i].p_vaddr;
        uint64_t end = phdr_buf[i].p_vaddr + phdr_buf[i].p_memsz;
        if (end > hi) hi = end;
    }
    if (lo >= hi) {
        close(fd);
        dl_set_error(path, ": no PT_LOAD segments");
        return NULL;
    }

    lo &= ~0xFFFULL;
    hi = ALIGN_UP(hi, 4096);
    uint64_t span = hi - lo + 4 * 4096;  /* + guard pages */

    /* Map anonymous for the entire load range */
    void *mapped = mmap(NULL, span, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapped == MAP_FAILED) {
        close(fd);
        dl_set_error(path, ": mmap failed");
        return NULL;
    }

    uint64_t base = (uint64_t)mapped - lo;

    /* Map/copy each PT_LOAD segment from the file */
    for (int i = 0; i < ehdr.e_phnum; i++) {
        if (phdr_buf[i].p_type != PT_LOAD) continue;
        if (phdr_buf[i].p_filesz > 0) {
            uint64_t seg_lo  = phdr_buf[i].p_vaddr & ~0xFFFULL;
            uint64_t seg_off = phdr_buf[i].p_offset & ~0xFFFULL;
            uint64_t delta   = phdr_buf[i].p_vaddr - seg_lo;
            uint64_t map_len = ALIGN_UP(delta + phdr_buf[i].p_filesz, 4096);

            void *m = mmap((void *)(base + seg_lo), map_len,
                           PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_FIXED, fd, seg_off);
            if (m == MAP_FAILED)
                pread(fd, (void *)(base + phdr_buf[i].p_vaddr),
                      phdr_buf[i].p_filesz, phdr_buf[i].p_offset);
        }
        zero_segment_bss_tail(base, &phdr_buf[i]);
    }

    close(fd);

    /* Set up loaded_obj entry */
    struct loaded_obj *obj = &g_all_objs[idx];
    memset(obj, 0, sizeof(*obj));
    obj->base  = base;
    obj->name  = dl_store_name(path);
    obj->flags = LDR_FLAG_SHLIB;
    obj->phdr  = (const Elf64_Phdr *)(base + ehdr.e_phoff + lo);
    obj->phdr_num  = ehdr.e_phnum;
    obj->map_start = base + lo;
    obj->map_end   = base + hi;
    /* Find PT_GNU_EH_FRAME */
    obj->eh_frame_hdr = NULL;
    for (int p = 0; p < ehdr.e_phnum; p++) {
        if (phdr_buf[p].p_type == PT_GNU_EH_FRAME) {
            obj->eh_frame_hdr = (const void *)(base + phdr_buf[p].p_vaddr);
            break;
        }
    }

    /* Build metadata for parse_dynamic / protect_object */
    struct dlfrz_lib_meta *meta = &g_dl_metas[idx];
    memset(meta, 0, sizeof(*meta));
    meta->base_addr  = base;
    meta->vaddr_lo   = lo;
    meta->vaddr_hi   = hi;
    meta->phdr_off   = ehdr.e_phoff + lo;  /* store as vaddr */
    meta->phdr_num   = ehdr.e_phnum;
    meta->phdr_entsz = ehdr.e_phentsize;
    meta->flags      = LDR_FLAG_SHLIB;

    parse_dynamic(obj, meta);
    discover_tls_template(obj, phdr_buf, ehdr.e_phnum);
    if (obj->tls.memsz != 0)
        obj->tls.modid = next_tls_modid();

    /* Bump count so symbol resolution includes this object */
    g_nobj = idx + 1;

    /* Load DT_NEEDED dependencies before applying relocations.
     * This may recursively call load_elf_from_file and increase g_nobj. */
    dl_load_needed(obj, meta);

    /* Clear cached misses — new objects may provide symbols
     * that were previously unresolvable. */
    clear_resolution_caches();

    /* Apply relocations */
    preseed_rtld_got(obj);
    if (apply_all_relocs(obj, g_all_objs, g_nobj, 0) < 0) {
        dl_set_error(path, ": relocation failed");
        g_nobj = idx;  /* roll back */
        return NULL;
    }
    if (apply_all_relocs(obj, g_all_objs, g_nobj, 1) < 0) {
        dl_set_error(path, ": IRELATIVE failed");
        g_nobj = idx;
        return NULL;
    }

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

    /* Set final memory protections */
    protect_object(obj, meta);

    /* Restore pointer_guard before calling init functions — the bootstrap
     * libc may have corrupted it via errno writes during open/mmap. */
    restore_ptr_guard();

    /* Keep loader crash diagnostics active while running init code, but
     * restore any handler the library registers before returning. */
    typedef void (*init_fn_t)(int, char **, char **);
    if (obj->init_func) {
        if (g_special_tab_ready)
            begin_crash_handler_guard();
        else
            install_crash_handlers();
        ((init_fn_t)obj->init_func)(g_argc, g_argv, g_envp);
        if (g_special_tab_ready)
            end_crash_handler_guard();
    }
    for (size_t j = 0; j < obj->init_array_sz; j++) {
        if (g_special_tab_ready)
            begin_crash_handler_guard();
        else
            install_crash_handlers();
        ((init_fn_t)obj->init_array[j])(g_argc, g_argv, g_envp);
        if (g_special_tab_ready)
            end_crash_handler_guard();
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
static struct loaded_obj *load_embedded_object(uint32_t mi)
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
        return NULL;
    }

    obj->name     = ename;
    obj->flags    = emeta->flags;
    obj->phdr     = (const Elf64_Phdr *)(obj->base + emeta->phdr_off);
    obj->phdr_num = emeta->phdr_num;
    obj->map_start = obj->base + emeta->vaddr_lo;
    obj->map_end   = obj->base + emeta->vaddr_hi;

    /* Find PT_GNU_EH_FRAME */
    for (int p = 0; p < obj->phdr_num; p++) {
        if (obj->phdr[p].p_type == PT_GNU_EH_FRAME) {
            obj->eh_frame_hdr = (const void *)(obj->base + obj->phdr[p].p_vaddr);
            break;
        }
    }

    /* Store metadata for protect_object */
    struct dlfrz_lib_meta *meta = &g_dl_metas[idx];
    *meta = *emeta;

    parse_dynamic(obj, meta);
    discover_tls_template(obj, obj->phdr, obj->phdr_num);
    if (obj->tls.memsz != 0)
        obj->tls.modid = next_tls_modid();

    /* Bump count so symbol resolution includes this object */
    g_nobj = idx + 1;

    /* Load DT_NEEDED dependencies from frozen image (or filesystem) */
    if (obj->dynstr) {
        const Elf64_Phdr *dyn_ph = NULL;
        for (int p = 0; p < obj->phdr_num; p++) {
            if (obj->phdr[p].p_type == PT_DYNAMIC) { dyn_ph = &obj->phdr[p]; break; }
        }
        if (dyn_ph) {
            const Elf64_Dyn *dyn = (const Elf64_Dyn *)(obj->base + dyn_ph->p_vaddr);
            size_t dc = dyn_ph->p_memsz / sizeof(Elf64_Dyn);
            for (size_t di = 0; di < dc && dyn[di].d_tag != DT_NULL; di++) {
                if (dyn[di].d_tag != DT_NEEDED) continue;
                const char *needed = obj->dynstr + dyn[di].d_un.d_val;
                /* Skip if already loaded */
                int found = 0;
                for (int j = 0; j < g_nobj; j++) {
                    if (!g_all_objs[j].name && !g_all_objs[j].base) continue;
                    if (g_all_objs[j].name &&
                        dl_name_matches(g_all_objs[j].name, needed)) {
                        found = 1; break;
                    }
                }
                if (found) continue;
                /* Try to find in frozen image (skip INTERP — the dynamic
                 * linker is never needed in direct-load mode and its
                 * pre-assigned address may overlap other objects). */
                int dep_found = 0;
                for (uint32_t fi = 0; fi < g_frozen_num_entries; fi++) {
                    if (g_frozen_metas[fi].flags & LDR_FLAG_INTERP) continue;
                    if (g_frozen_metas[fi].flags & LDR_FLAG_DATA) continue;
                    if (!(g_frozen_metas[fi].flags & LDR_FLAG_SHLIB)) continue;
                    const char *fn = g_frozen_strtab + g_frozen_entries[fi].name_offset;
                    if (dl_name_matches(fn, needed)) {
                        load_embedded_object(fi);
                        dep_found = 1;
                        break;
                    }
                }
                if (!dep_found) {
                    /* Try filesystem */
                    load_needed_from_filesystem(needed);
                }
            }
        }
    }

    /* Clear cached misses — new objects may provide previously-missing symbols */
    clear_resolution_caches();

    /* Apply relocations */
    preseed_rtld_got(obj);
    if (apply_all_relocs(obj, g_all_objs, g_nobj, 0) < 0) {
        dl_set_error(ename, ": relocation failed");
        g_nobj = idx;
        return NULL;
    }
    if (apply_all_relocs(obj, g_all_objs, g_nobj, 1) < 0) {
        dl_set_error(ename, ": IRELATIVE failed");
        g_nobj = idx;
        return NULL;
    }

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

    /* Set final memory protections */
    protect_object(obj, meta);

    /* Restore pointer_guard before init functions — bootstrap libc errno
     * writes from dependency loading may have corrupted it. */
    restore_ptr_guard();

    /* Keep loader crash diagnostics active while running init code, but
     * restore any handler the library registers before returning. */
    typedef void (*init_fn_t)(int, char **, char **);
    if (obj->init_func) {
        if (g_special_tab_ready)
            begin_crash_handler_guard();
        else
            install_crash_handlers();
        ((init_fn_t)obj->init_func)(g_argc, g_argv, g_envp);
        if (g_special_tab_ready)
            end_crash_handler_guard();
    }
    for (size_t j = 0; j < obj->init_array_sz; j++) {
        if (g_special_tab_ready)
            begin_crash_handler_guard();
        else
            install_crash_handlers();
        ((init_fn_t)obj->init_array[j])(g_argc, g_argv, g_envp);
        if (g_special_tab_ready)
            end_crash_handler_guard();
    }

    ldr_dbg("[loader] dlopen (embedded): ");
    ldr_dbg(dl_basename(ename));
    ldr_dbg_hex(" base=0x", obj->base);

    return obj;
}

static void *my_dlopen(const char *path, int flags)
{
    (void)flags;
    g_dlerror_valid = 0;

    if (!path)
        return DL_GLOBAL_HANDLE;

    /* Check if already loaded (basename match) */
    const char *bn = dl_basename(path);

    for (int i = 0; i < g_nobj; i++) {
        if (!g_all_objs[i].name) continue;
        if (dl_name_matches(g_all_objs[i].name, bn))
            return &g_all_objs[i];
    }

    /* Check embedded DLOPEN objects in the frozen image */
    if (g_frozen_metas) {
        for (uint32_t i = 0; i < g_frozen_num_entries; i++) {
            if (!(g_frozen_metas[i].flags & LDR_FLAG_DLOPEN)) continue;
            if (g_frozen_metas[i].flags & LDR_FLAG_INTERP) continue;
            if (g_frozen_metas[i].flags & LDR_FLAG_DATA) continue;
            const char *ename = g_frozen_strtab + g_frozen_entries[i].name_offset;
            if (dl_name_matches(ename, bn)) {
                struct loaded_obj *obj = load_embedded_object(i);
                if (obj) {
                    restore_ptr_guard();
                    return obj;
                }
                /* Fall through to filesystem on error */
                break;
            }
        }
    }

    /* Fall back to the filesystem.  Per dlopen(3) semantics:
     *   - if `path` contains a slash it is used as a path directly
     *     (absolute or relative to the current working directory);
     *   - otherwise it is treated as a bare soname and resolved against
     *     the standard runtime library directories. */
    void *ret;
    int has_slash = 0;
    for (const char *p = path; *p; p++) {
        if (*p == '/') { has_slash = 1; break; }
    }
    if (has_slash)
        ret = load_elf_from_file(path);
    else
        ret = load_needed_from_filesystem(path);
    if (ret) {
        /* Loaded from disk — this library should have been captured */
        ldr_msg("dlfreeze: warning: dlopen loading '");
        ldr_msg(bn);
        ldr_msg("' from disk (not in frozen image)\n");
    } else {
        dl_set_error(path, ": cannot open shared object file");
    }
    restore_ptr_guard();
    return ret;
}

/* dlmopen(LMID, file, flags) — we don't implement separate link-map
 * namespaces, but we can satisfy the common case by ignoring the namespace
 * argument and routing the request through dlopen.  This lets programs that
 * use dlmopen for its side effect of loading a library still work. */
static void *my_dlmopen(long /*Lmid_t*/ lmid, const char *path, int flags)
{
    (void)lmid;
    return my_dlopen(path, flags);
}

static void *my_dlsym(void *handle, const char *symbol)
{
    g_dlerror_valid = 0;

    if (!symbol) {
        dl_set_error("dlsym: NULL symbol name", NULL);
        return NULL;
    }

    /* Handle-specific lookup: search the specific object first */
    if (handle && handle != DL_GLOBAL_HANDLE &&
        handle != (void *)(uintptr_t)-1L /* RTLD_DEFAULT */ &&
        handle != (void *)(uintptr_t)-2L /* RTLD_NEXT    */) {
        struct loaded_obj *obj = (struct loaded_obj *)handle;
        uint32_t gh = gnu_hash_calc(symbol);
        const Elf64_Sym *sym = obj->gnu_hash
            ? lookup_gnu_hash(obj, symbol, gh)
            : lookup_linear(obj, symbol);
        if (sym && sym->st_value) {
            uint64_t addr = obj->base + sym->st_value;
            if (ELF64_ST_TYPE(sym->st_info) == STT_GNU_IFUNC) {
                typedef uint64_t (*ifunc_t)(void);
                addr = ((ifunc_t)addr)();
            }
            return (void *)(uintptr_t)addr;
        }
    }

    /* Fallback: search all loaded objects */
    uint64_t addr = resolve_sym(g_all_objs, g_nobj, symbol);
    if (addr) return (void *)(uintptr_t)addr;

    dl_set_error("undefined symbol: ", symbol);
    return NULL;
}

/* dlvsym(handle, name, version) — versioned symbol lookup.
 *
 * The frozen loader does not maintain GNU symbol-version tables for the
 * libraries it embeds, so it cannot truly verify that a symbol has the
 * requested version.  However, the dominant real-world use of dlvsym is
 * a feature probe ("is this versioned symbol available at all?") rather
 * than strict version matching — e.g. libgcc's pthread shim does
 *   dlvsym(RTLD_DEFAULT, "pthread_self", "GLIBC_2.2.5")
 * to detect a real libpthread, and KCrash / various Qt/KDE plugins do
 * similar probes during startup.  Returning the unversioned symbol when
 * the name resolves is therefore the pragmatic and compatible behaviour
 * (and matches what glibc does for the default version of a symbol).
 *
 * If lookup fails we set the same error format glibc uses, so callers
 * that fall back to dlerror() see a familiar message. */
static void *my_dlvsym(void *handle, const char *symbol, const char *version)
{
    void *p = my_dlsym(handle, symbol);
    if (p) return p;
    /* my_dlsym already populated dlerror with "undefined symbol: ...";
     * leave it in place so the caller can read a sensible error.  We
     * deliberately don't surface the requested version here because the
     * common failure mode is the symbol not existing at all. */
    (void)version;
    return NULL;
}

static int my_dlclose(void *handle)
{
    (void)handle;
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
    uintptr_t old_tp = 0;
    uintptr_t old_self = 0;
    size_t bootstrap_self_to_tp = 0;
    uint64_t max_tls_align = 1;
    int64_t min_static_tpoff = 0;
#if defined(__aarch64__)
    (void)at_random;
#endif

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
        /* phdr_off is a vaddr; convert to file offset */
        const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(elf + metas[mi].phdr_off - metas[mi].vaddr_lo);

        for (int j = 0; j < metas[mi].phdr_num; j++) {
            if (phdrs[j].p_type != PT_TLS) continue;
            uint64_t align = phdrs[j].p_align ? phdrs[j].p_align : 1;
            if (align > max_tls_align)
                max_tls_align = align;
            if (tls_above_tp) {
                total_tls = ALIGN_UP(total_tls, align);
                objs[oi].tls.tpoff = (int64_t)total_tls;
                total_tls += phdrs[j].p_memsz;
            } else {
                total_tls = ALIGN_UP(total_tls + phdrs[j].p_memsz, align);
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
        size_t tls_static = ALIGN_UP(total_tls + 0x1800, 64);
        size_t tls_align = max_tls_align < 0x40 ? 0x40 : max_tls_align;

        g_tls_static_size = tls_static;
        g_tls_static_align = tls_align;

        /* In glibc ≥ 2.34, the TLS static size field is in _rtld_global_ro.
         * In glibc < 2.34, it's in _rtld_global (sentinel: glro_tls… = -1). */
        if (g_glibc_off->glro_tls_static_size >= 0)
            *(size_t *)(g_fake_rtld_global_ro + g_glibc_off->glro_tls_static_size)
                = tls_static;
        else if (g_glibc_off->gl_tls_static_size >= 0)
            *(size_t *)(g_fake_rtld_global + g_glibc_off->gl_tls_static_size)
                = tls_static;

        if (g_glibc_off->glro_tls_static_align >= 0)
            *(size_t *)(g_fake_rtld_global_ro + g_glibc_off->glro_tls_static_align)
                = tls_align;
        else if (g_glibc_off->gl_tls_static_align >= 0)
            *(size_t *)(g_fake_rtld_global + g_glibc_off->gl_tls_static_align)
                = tls_align;
    }

#if defined(__aarch64__)
    if (!g_is_musl_runtime) {
        if (glibc_aarch64_has_rseq_area()) {
            g_rseq_offset = (int64_t)glibc_aarch64_pthread_rseq_off() -
                            (int64_t)glibc_aarch64_pthread_size();
        } else {
            /* Pre-2.34 glibc: no rseq area in struct pthread. */
            g_rseq_offset = 0;
        }
        g_rseq_size = 0;
    }
#else
    if (!g_is_musl_runtime && min_static_tpoff < 0) {
        int64_t rseq_off = min_static_tpoff - (int64_t)32;

        g_rseq_offset = rseq_off & ~((int64_t)31);
    }
#endif

    if (g_is_musl_runtime) {
        old_tp = arch_get_tp_syscall();
        old_self = (uintptr_t)pthread_self();
        if (old_tp >= old_self) {
            bootstrap_self_to_tp = old_tp - old_self;
            g_musl_tp_self_delta = bootstrap_self_to_tp;
        }
        probe_musl_thread_layout(old_self, old_tp);
        probe_musl_thread_layout_from_target(find_musl_libc(objs, nobj));
    }

    /* Allocate TLS block + TCB */
    size_t alloc;
    uintptr_t tp;
    void *block;

    if (g_is_musl_runtime && musl_tls_above_tp()) {
        alloc = g_musl_tp_self_delta + total_tls + max_tls_align;
        block = mmap(NULL, alloc, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (block == MAP_FAILED) {
            ldr_err("TLS mmap failed", NULL);
            return 0;
        }
        tp = ALIGN_UP((uintptr_t)block + g_musl_tp_self_delta, max_tls_align);
    }
#if defined(__aarch64__)
    else if (glibc_tls_above_tp()) {
        size_t tls_aligned = ALIGN_UP(total_tls, 64);
        size_t pthread_size = glibc_aarch64_pthread_size();

        alloc = pthread_size + tls_aligned + max_tls_align;
        block = mmap(NULL, alloc, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (block == MAP_FAILED) {
            ldr_err("TLS mmap failed", NULL);
            return 0;
        }
        tp = ALIGN_UP((uintptr_t)block + pthread_size,
                      max_tls_align);
    }
#endif
    else {
        size_t tls_aligned = ALIGN_UP(total_tls, 64);

        alloc = tls_aligned + TCB_ALLOC;
        block = mmap(NULL, alloc, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (block == MAP_FAILED) {
            ldr_err("TLS mmap failed", NULL);
            return 0;
        }
        tp = (uintptr_t)block + tls_aligned;
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

        size_t musl_dtv_bytes = ALIGN_UP(dtv_slots * sizeof(uintptr_t), 4096);
        uintptr_t *musl_dtv = mmap(NULL, musl_dtv_bytes,
                                   PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (bootstrap_self_to_tp != 0 && old_self) {
            size_t preserve_len = bootstrap_self_to_tp;

            if (preserve_len > g_musl_tp_self_delta)
                preserve_len = g_musl_tp_self_delta;
            if (preserve_len)
                memcpy((void *)self, (void *)old_self, preserve_len);
        } else if (old_tp)
            /* Preserve the bootstrap musl main thread state beyond the
             * ABI header. This carries over initialized locale/pthread
             * fields that direct-loaded musl code may read via %fs. */
            memcpy((void *)(tp + MUSL_TCB_PRESERVE_OFF),
                   (void *)(old_tp + MUSL_TCB_PRESERVE_OFF),
                   MUSL_TCB_PRESERVE_LEN);

        *(uintptr_t *)(self + 0) = self;
        *(uintptr_t *)(self + MUSL_THREAD_PREV_OFF) = self;
        *(uintptr_t *)(self + MUSL_THREAD_NEXT_OFF) = self;
        *(uintptr_t *)(self + MUSL_THREAD_ROBUST_HEAD_OFF) =
            self + MUSL_THREAD_ROBUST_HEAD_OFF;
        *(int *)(self + MUSL_THREAD_TID_OFF) = (int)syscall(SYS_gettid);
        *(int *)(self + MUSL_THREAD_ERRNO_OFF) = 0;

        if (musl_dtv != MAP_FAILED) {
            musl_dtv[0] = dtv_slots - 1;
            for (int oi = 0; oi < nobj; oi++) {
                if (objs[oi].tls.memsz == 0)
                    continue;
                musl_dtv[objs[oi].tls.modid] = tp + (uintptr_t)objs[oi].tls.tpoff;
            }
            *(uintptr_t *)musl_thread_dtv_slot(tp) = (uintptr_t)musl_dtv;
        } else {
            *(uintptr_t *)musl_thread_dtv_slot(tp) = 0;
        }
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
#else
        *(int32_t *)(tp + TCB_OFF_TID) = (int32_t)syscall(SYS_gettid);
#endif
    }

    /*
     * Minimal DTV (Dynamic Thread Vector).
     * glibc expects tcb->dtv to be non-NULL.  Layout:
     *   dtv[0].counter = generation (size_t)
     *   dtv[1].pointer.val = pointer to TLS block for module 1
     *   dtv[1].pointer.to_free = NULL
     * We allocate a small array.  Module 1 = libc's TLS block.
     */
    /* Minimal DTV (Dynamic Thread Vector).
     * glibc convention: tcbhead.dtv points to raw_dtv[1] (offset by one
     * dtv_t entry = 16 bytes), so that dtv[-1].counter = generation.
     *   raw_dtv[0].counter = generation
     *   dtv = raw_dtv + 1 (in dtv_t units)
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

        size_t dtv_slots = 2 + max_modid;
        size_t raw_dtv_bytes = (1 + dtv_slots) * 2 * sizeof(uintptr_t);
        uintptr_t *raw_dtv = (uintptr_t *)mmap(NULL, ALIGN_UP(raw_dtv_bytes, 4096),
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (raw_dtv != MAP_FAILED) {
            /* raw_dtv[0] = generation counter (accessed as dtv[-1]) */
            raw_dtv[0] = 1;   /* generation */
            raw_dtv[1] = 0;
            /* dtv = raw_dtv + one dtv_t entry (2 uintptr_t's) */
            uintptr_t *dtv = raw_dtv + 2;
            /* dtv[modid] for each TLS module: .val = tp + tpoff, .to_free = NULL
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
        } else {
            *(uintptr_t *)(tp + TCB_OFF_DTV) = 0;
        }
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
        const uint8_t *src = (const uint8_t *)(objs[oi].base + objs[oi].tls.vaddr);
        memcpy(dst, src, objs[oi].tls.filesz);
        /* .tbss already zero from mmap */
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
    set_auxv_entry(auxv, &auxvc, AT_PAGESZ, 4096);
    set_auxv_entry(auxv, &auxvc, AT_BASE, at_base);
    set_auxv_entry(auxv, &auxvc, AT_ENTRY, at_entry);
    set_auxv_entry(auxv, &auxvc, AT_RANDOM, at_random);
    set_auxv_entry(auxv, &auxvc, AT_SECURE, 0);

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
    if (obj->phdr && obj->dynstr) {
        for (int p = 0; p < obj->phdr_num; p++) {
            if (obj->phdr[p].p_type != PT_DYNAMIC) continue;
            const Elf64_Dyn *dyn = (const Elf64_Dyn *)
                (obj->base + obj->phdr[p].p_vaddr);
            for (int d = 0; dyn[d].d_tag != DT_NULL; d++) {
                if (dyn[d].d_tag != DT_NEEDED) continue;
                const char *needed = obj->dynstr + dyn[d].d_un.d_val;
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
            break;
        }
    }
    state[idx] = 2;
    order[(*order_count)++] = idx;
}

/* ==== Main entry point ================================================= */

int loader_run(const uint8_t *mem, uint64_t mem_foff, int srcfd,
               const struct dlfrz_lib_meta *metas,
               const struct dlfrz_entry *entries,
               const char *strtab,
               uint32_t num_entries,
               const uint32_t *runtime_fixups,
               uint32_t runtime_fixup_count,
               int argc, char **argv, char **envp)
{
    /* Check env flags before TLS swap (getenv uses bootstrap's libc) */
    {
        const char *dbg = getenv("DLFREEZE_DEBUG");
        g_debug = (dbg && dbg[0] != '0' && dbg[0] != '\0');
        const char *perf = getenv("DLFREEZE_PERF");
        g_perf_mode = (perf && perf[0] != '0' && perf[0] != '\0');
    }

    clear_resolution_caches();

    int is_musl_runtime = frozen_uses_musl(metas, entries, strtab, num_entries);
    g_is_musl_runtime = is_musl_runtime;

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

    /* 1. Count non-INTERP libraries and build object array */
    /* Allocate a zero-filled page for unresolved OBJECT symbols */
    g_null_page = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    /* Allocate fake _rtld_global / _rtld_global_ro for libc */
    if (init_fake_rtld() < 0) return -1;

    /* Detect glibc struct layout from the embedded ld-linux.so and set
     * all version-dependent fields.  Must happen before any libc code
     * that reads _rtld_global{,_ro} (especially __libc_early_init). */
    {
        const struct glibc_ver_offsets *off =
            detect_glibc_offsets_from_interp(mem, mem_foff, entries, metas,
                                              num_entries);
        if (off) {
            g_glibc_off = off;
            fixup_rtld_for_glibc(off);
        }
        /* If detection failed (e.g. musl binary, no INTERP), the
         * version-dependent fields remain unset.  For musl this is fine
         * (they're not referenced).  For glibc, init_libc_process_state()
         * will retry with gnu_get_libc_version() as a fallback. */
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
        /* Find PT_GNU_EH_FRAME for DWARF unwinder */
        objs[i].eh_frame_hdr = NULL;
        for (int p = 0; p < objs[i].phdr_num; p++) {
            if (objs[i].phdr[p].p_type == PT_GNU_EH_FRAME) {
                objs[i].eh_frame_hdr = (const void *)(objs[i].base + objs[i].phdr[p].p_vaddr);
                break;
            }
        }
        ldr_dbg("  ");
        ldr_dbg(objs[i].name);
        ldr_dbg_hex("  base=0x", objs[i].base);
    }

    /* 3. Parse PT_DYNAMIC for each object */
    ldr_dbg("[loader] parsing dynamic sections...\n");
    for (int i = 0; i < nobj; i++)
        parse_dynamic(&objs[i], &metas[idx_map[i]]);

    /* 4. Set up TLS (must happen before relocations that reference TLS,
     *    and definitely before calling any IRELATIVE resolvers that might
     *    touch TLS / stack guard) */
    ldr_dbg("[loader] setting up TLS...\n");
    uintptr_t at_random = get_auxval(envp, 25 /* AT_RANDOM */);
    uintptr_t tp = setup_tls(objs, nobj, mem, mem_foff, metas, entries,
                              idx_map, num_entries, at_random);
    /* NOTE: After setup_tls, FS register is changed.  The bootstrap's
     * static glibc functions (printf, malloc etc.) are no longer safe
     * to call.  Use only write() and _exit() from here on. */

    /* 5. Apply relocations for all objects.
     *    Two-pass: first apply all non-IRELATIVE relocations across all
     *    objects so that GOT entries (e.g. _rtld_global_ro) are populated,
     *    then apply IRELATIVE whose resolvers depend on those GOT entries.
     *
     *    If the frozen binary was pre-linked, segments already contain
     *    resolved relocations.  We only need to patch GOT entries for
     *    runtime-only symbols (overrides like dlopen, __tls_get_addr,
     *    and the fake _rtld_global/_rtld_global_ro). */
    int prelinked = (metas[idx_map[0]].flags & LDR_FLAG_PRELINKED) != 0;

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
        for (int i = 0; i < nobj; i++)
            if (objs[i].flags & LDR_FLAG_NEEDS_RTLD)
                preseed_rtld_got(&objs[i]);

        /* Single merged pass: patch overrides + resolve IRELATIVE.
         * Skip leading RELATIVE entries in .rela.dyn (DT_RELACOUNT tells
         * us how many there are) — they were applied at pre-link time. */
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

            if (obj_fixups != NULL) {
                for (uint32_t f = 0; f < obj_fixup_count; f++) {
                    uint32_t encoded = obj_fixups[f];
                    const Elf64_Rela *tab;
                    size_t count;
                    uint32_t idx = encoded & ~LDR_PRELINK_FIXUP_JMPREL;

                    if (encoded & LDR_PRELINK_FIXUP_JMPREL) {
                        tab = objs[i].jmprel;
                        count = objs[i].jmprel_count;
                    } else {
                        tab = objs[i].rela;
                        count = objs[i].rela_count;
                    }
                    if (idx >= count)
                        continue;

                    apply_prelinked_runtime_reloc(&objs[i], objs, nobj,
                                                  &tab[idx]);
                }

                apply_prelinked_override_fallbacks(&objs[i]);
                continue;
            }

            if (!(objs[i].flags & LDR_FLAG_RUNTIME_SCAN))
                continue;

            {
                const Elf64_Rela *tabs[] = { objs[i].rela, objs[i].jmprel };
                size_t counts[] = { objs[i].rela_count, objs[i].jmprel_count };
                size_t starts[] = { objs[i].rela_relative_count, 0 };
                for (int t = 0; t < 2; t++) {
                    for (size_t r = starts[t]; r < counts[t]; r++)
                        apply_prelinked_runtime_reloc(&objs[i], objs, nobj,
                                                      &tabs[t][r]);
                }
            }

            apply_prelinked_override_fallbacks(&objs[i]);
        }
    } else {
        ldr_dbg("[loader] applying relocations...\n");

        /* Pre-seed _rtld_global/_rtld_global_ro GOT entries so IFUNC
         * resolvers called during GLOB_DAT processing work correctly. */
        for (int i = 0; i < nobj; i++)
            if (objs[i].flags & LDR_FLAG_NEEDS_RTLD)
                preseed_rtld_got(&objs[i]);

        for (int i = 0; i < nobj; i++) {
            if (apply_all_relocs(&objs[i], objs, nobj, 0) < 0) {
                ldr_msg("dlfreeze-loader: relocation failed for ");
                ldr_msg(objs[i].name);
                ldr_msg("\n");
                _exit(127);
            }
        }
        for (int i = 0; i < nobj; i++) {
            if (apply_all_relocs(&objs[i], objs, nobj, 1) < 0) {
                ldr_msg("dlfreeze-loader: IRELATIVE failed for ");
                ldr_msg(objs[i].name);
                ldr_msg("\n");
                _exit(127);
            }
        }
        for (int i = 0; i < nobj; i++) {
            if (apply_all_relocs(&objs[i], objs, nobj, 2) < 0) {
                ldr_msg("dlfreeze-loader: copy relocation failed for ");
                ldr_msg(objs[i].name);
                ldr_msg("\n");
                _exit(127);
            }
        }
    }

    /* 5b. Copy .tdata AFTER relocations — the TLS template contains
     *     pointers that need RELATIVE/RELR relocation first. */
    if (tp) {
        copy_tdata(objs, nobj, tp);
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
    for (int i = 0; i < nobj; i++)
        protect_object(&objs[i], &metas[idx_map[i]]);

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
     *    calling any init functions — init_array entries in libraries
     *    (e.g. libpython) may call malloc, so the arena must be ready. */
    init_libc_process_state(objs, nobj, argc, argv, runtime_envp, envp);

    /* 7b. Call shared library init functions (libc first, then others).
     *    Skip the exe — its constructors are called later.
     *    Now safe because _rtld_global/_rtld_global_ro stubs are in place
     *    and __tunable_get_val etc. resolve to our no-op stubs. */
    ldr_dbg("[loader] calling init functions...\n");
    typedef void (*init_fn_t)(int, char **, char **);

    /* Ensure pointer_guard is correct before init functions — init code
     * may call PTR_MANGLE-using functions like __cxa_atexit. */
    restore_ptr_guard();

    if (prelinked)
        begin_crash_handler_guard_from_saved(startup_crash_handlers);

    /* Topologically sort objects so dependencies init before dependents.
     * The packer's array order is not always a strict BFS dep order — e.g.
     * libGLX.so.0 may appear at a higher index than its dep libGLdispatch.so.0
     * even though libGLX's constructor calls into libGLdispatch.  A real
     * topo sort over DT_NEEDED edges is the only robust ordering. */
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
        if (objs[i].init_func)
            ((init_fn_t)objs[i].init_func)(argc, argv, runtime_envp);
        for (size_t j = 0; j < objs[i].init_array_sz; j++)
            ((init_fn_t)objs[i].init_array[j])(argc, argv, runtime_envp);
    }

    ldr_dbg("[loader] init functions done\n");

    if (prelinked)
        end_crash_handler_guard();
    else
        restore_crash_handlers_if_still_loader(startup_crash_handlers);

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
    typedef int (*main_fn_t)(int, char **, char **);
    uint64_t main_addr = resolve_main_address(objs, nobj, idx_map, metas,
                                              entry,
                                              1);

#if defined(__aarch64__)
     /* Prefer direct main after __libc_early_init; the bridge can crash on large VFS payloads. */
    if (main_addr && !is_musl_runtime && !g_glibc_early_init_done) {
        uint64_t lsm_addr = resolve_sym(objs, nobj, "__libc_start_main");
        if (lsm_addr) {
            typedef int (*libc_start_main_fn_t)(
                int (*)(int, char **, char **),
                int, char **,
                void (*)(void),
                void (*)(void),
                void (*)(void),
                void *);
            ldr_dbg("[loader] using __libc_start_main bridge...\n");
            restore_ptr_guard();
            int rc = ((libc_start_main_fn_t)(uintptr_t)lsm_addr)(
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

    if (main_addr && (is_musl_runtime || g_glibc_early_init_done ||
                      glibc_direct_main_without_early_init_ok())) {
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
        if (g_debug)
            install_crash_handlers();
        restore_ptr_guard();
        int rc = ((main_fn_t)(uintptr_t)main_addr)(argc, argv, runtime_envp);
        ldr_dbg("[loader] main() returned\n");
        /* Flush all stdio streams before _exit — _exit doesn't run atexit
         * handlers or flush stdio.  When stdout is a pipe (e.g. captured
         * by $(cmd)), libc uses full buffering so output would be lost. */
        uint64_t fflush_addr = resolve_sym(objs, nobj, "fflush");
        if (fflush_addr)
            ((int (*)(void *))(uintptr_t)fflush_addr)(NULL);
        _exit(rc);
    }

    if (main_addr && !is_musl_runtime && g_debug && !g_glibc_early_init_done)
        ldr_dbg("[loader] using _start path (glibc needs __libc_start_main init)\n");

    /* Fallback: transfer control via _start → __libc_start_main. */
    ldr_dbg("[loader] transferring to _start...\n");
    if (is_musl_runtime)
        seed_musl_startup_globals(objs, nobj);
    if (g_debug && is_musl_runtime)
        install_crash_handlers();
    restore_ptr_guard();
    transfer_to_entry(entry, argc, argv, envp,
                      exe_phdr, exe_phnum, at_base, entry, at_random,
                      is_musl_runtime);
    /* NOTREACHED */
}
