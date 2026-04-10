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
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <dirent.h>
#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <fcntl.h>

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

/* Zeroed page used as target for unresolved OBJECT symbols.
 * Prevents NULL dereference crashes in IFUNC resolvers. */
static void *g_null_page;

/* Debug verbosity — enabled by DLFREEZE_DEBUG=1 env var.
 * Set before TLS swap (getenv is safe in bootstrap's libc). */
static int g_debug;

/* Perf-friendly mode — enabled by DLFREEZE_PERF=1 env var.
 * Uses anonymous memory (memcpy) instead of file-backed mmap so that
 * perf falls back to /tmp/perf-<PID>.map for symbol resolution.
 * Without this, all loaded code is file-backed from the frozen binary
 * which has stripped section headers, so perf finds no symbols. */
static int g_perf_mode;

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
/* Saved pointer_guard value and its address, for crash diagnostics */
static uintptr_t g_saved_ptr_guard;
static uintptr_t g_ptr_guard_addr;

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
    if (g_ptr_guard_addr)
        *(uintptr_t *)g_ptr_guard_addr = g_saved_ptr_guard;
}

/* Fatal signals that the loader temporarily owns while running init code. */
static const int g_crash_signals[] = {
    SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL
};

#define CRASH_SIGNAL_COUNT \
    ((int)(sizeof(g_crash_signals) / sizeof(g_crash_signals[0])))

typedef void (*signal_handler_t)(int);

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
    /* Show FS:0x10 (thread self pointer) for TLS diagnosis */
    {
        uintptr_t fs_base = 0;
        syscall(SYS_arch_prctl, 0x1003 /*ARCH_GET_FS*/, &fs_base);
        ldr_hex("[loader] FS_BASE=0x", fs_base);
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
        sigaction(g_crash_signals[i], &sa, NULL);
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
        sigaction(g_crash_signals[i], NULL, &dst[i]);
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

        if (sigaction(g_crash_signals[i], NULL, &cur) < 0)
            continue;
        if (is_loader_crash_action(&cur))
            sigaction(g_crash_signals[i], &saved[i], NULL);
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
            sigaction(g_crash_signals[i], &g_deferred_crash_handlers[i].act,
                      NULL);
            break;
        case DEFERRED_CRASH_SIGNAL:
            signal(g_crash_signals[i], g_deferred_crash_handlers[i].handler);
            break;
        default:
            sigaction(g_crash_signals[i], &g_saved_crash_handlers[i], NULL);
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
    return sigaction(signum, act, oldact);
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

    return signal(signum, handler);
}

/* ---- fake _rtld_global / _rtld_global_ro for libc -------------------- */

/*
 * glibc's libc.so references _rtld_global and _rtld_global_ro (OBJECT
 * symbols normally provided by ld-linux.so).  We provide writable fake
 * copies with critical fields initialised so that malloc, stdio, etc.
 * work without the real dynamic linker.
 *
 * Field offsets are glibc-version-specific (determined for glibc 2.43
 * on x86-64).  When building on a system with a different glibc,
 * verify with: gdb -batch -ex 'start' -ex 'ptype /o struct rtld_global_ro' /bin/true
 */

/* _rtld_global_ro (928 bytes on glibc 2.43 x86-64) */
#define GLRO_SIZE        4096                /* generous allocation     */
#define GLRO_DL_PAGESIZE_OFF  24             /* offset 0x18             */
#define GLRO_DL_MINSIGSTKSZ_OFF 32           /* _dl_minsigstacksize     */
#define GLRO_DL_CLKTCK_OFF    64             /* offset 0x40             */
#define GLRO_DL_FPU_CONTROL_OFF 0x58           /* _dl_fpu_control         */
#define GLRO_DL_AUXV_OFF      104            /* _dl_auxv                */
#define GLRO_DL_TLS_STATIC_SIZE_OFF  672     /* 0x2a0                   */
#define GLRO_DL_TLS_STATIC_ALIGN_OFF 680     /* 0x2a8                   */

/* _rtld_global (2120 bytes on glibc 2.43 x86-64) */
#define GL_SIZE          4096                /* generous allocation     */
#define GL_DL_NNS_OFF         0x700          /* _dl_nns                 */
#define GL_DL_STACK_FLAGS_OFF 0x7b8          /* _dl_stack_flags         */
#define GL_DL_TLS_GENERATION_OFF 0x7f0       /* _dl_tls_generation      */
#define GL_DL_STACK_USED_OFF  0x800          /* _dl_stack_used (list_t) */
#define GL_DL_STACK_USER_OFF  0x810          /* _dl_stack_user (list_t) */
#define GL_DL_STACK_CACHE_OFF 0x820          /* _dl_stack_cache(list_t) */

static uint8_t *g_fake_rtld_global;
static uint8_t *g_fake_rtld_global_ro;

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
 * We provide our own copies.  __rseq_offset = -160 matches glibc 2.43
 * on x86-64 (offsetof(struct pthread, rseq_area) from the thread pointer).
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

/* Offsets of function pointers in struct rtld_global_ro (glibc 2.43 x86-64) */
#define GLRO_DL_DEBUG_PRINTF_OFF  816
#define GLRO_DL_MCOUNT_OFF        824
#define GLRO_DL_OPEN_OFF          840
#define GLRO_DL_CLOSE_OFF         848
#define GLRO_DL_CATCH_ERROR_OFF   856
#define GLRO_DL_ERROR_FREE_OFF    864
#define GLRO_DL_FIND_OBJECT_OFF   888

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
    *(int    *)(g_fake_rtld_global_ro + GLRO_DL_FPU_CONTROL_OFF) = 0x037f;
    /* TLS static fields needed by __libc_early_init → thread stack guard
     * computation.  Without these, __libc_early_init divides by zero. */
    *(size_t *)(g_fake_rtld_global_ro + GLRO_DL_TLS_STATIC_SIZE_OFF)  = 0x1080;
    *(size_t *)(g_fake_rtld_global_ro + GLRO_DL_TLS_STATIC_ALIGN_OFF) = 0x40;

    /*
     * Populate _dl_x86_cpu_features from CPUID so that IFUNC resolvers
     * (memcpy, memset, strcmp, etc.) pick CPU-appropriate implementations.
     * Without this, resolvers see all-zero features and fall back to
     * a generic SSE2 variant that prefetches 12 KiB ahead, causing
     * SIGSEGV on buffer boundaries.
     *
     * struct cpu_features layout (glibc 2.43 x86-64):
     *   +0x70  _dl_x86_cpu_features  (528 bytes)
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
         * cpu_features layout (glibc 2.43):
         *   +384  non_temporal_threshold         (8 bytes)
         *   +392  memset_non_temporal_threshold   (8 bytes)
         *   +400  rep_movsb_threshold             (8 bytes)
         *   +408  rep_movsb_stop_threshold        (8 bytes)
         *   +416  rep_stosb_threshold             (8 bytes)
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

    /* _rtld_global critical fields */
    *(size_t *)(g_fake_rtld_global + GL_DL_NNS_OFF)            = 1;
    *(int    *)(g_fake_rtld_global + GL_DL_STACK_FLAGS_OFF)     = 3; /* PROT_READ|PROT_WRITE */
    *(size_t *)(g_fake_rtld_global + GL_DL_TLS_GENERATION_OFF) = 1;

    /* _dl_ns[0]._ns_loaded — pointer to the head link_map.  Used by
     * __cxa_thread_atexit_impl when _dl_find_dso_for_object returns NULL:
     * it falls back to *(_rtld_global+0) to get a link_map and increments
     * a reference counter at link_map+0x498. */
    *(uintptr_t *)(g_fake_rtld_global + 0) = (uintptr_t)g_fake_link_map;

    /* Empty circular lists for stack tracking */
    init_empty_list(g_fake_rtld_global, GL_DL_STACK_USED_OFF);
    init_empty_list(g_fake_rtld_global, GL_DL_STACK_USER_OFF);
    init_empty_list(g_fake_rtld_global, GL_DL_STACK_CACHE_OFF);

    /* dl* function pointer stubs — makes dlopen/dlsym/dlclose return
     * error/NULL instead of SIGSEGV-ing through a NULL pointer. */
    *(void **)(g_fake_rtld_global_ro + GLRO_DL_DEBUG_PRINTF_OFF) = (void *)glro_dl_debug_printf;
    *(void **)(g_fake_rtld_global_ro + GLRO_DL_OPEN_OFF)         = (void *)glro_dl_open;
    *(void **)(g_fake_rtld_global_ro + GLRO_DL_CLOSE_OFF)        = (void *)glro_dl_close;
    *(void **)(g_fake_rtld_global_ro + GLRO_DL_CATCH_ERROR_OFF)  = (void *)glro_dl_catch_error;
    *(void **)(g_fake_rtld_global_ro + GLRO_DL_ERROR_FREE_OFF)   = (void *)glro_dl_error_free;
    *(void **)(g_fake_rtld_global_ro + GLRO_DL_FIND_OBJECT_OFF)  = (void *)glro_dl_find_object;
    *(void **)(g_fake_rtld_global_ro + GLRO_DL_MCOUNT_OFF)       = (void *)glro_dl_mcount;

    return 0;
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
static void *stub_dl_allocate_tls(void *mem);       /* impl below */
static void *stub_dl_allocate_tls_init(void *mem);   /* impl below */
static void  stub_dl_deallocate_tls(void *mem) { (void)mem; }

/* _dl_rtld_di_serinfo — no-op */
static int stub_dl_rtld_di_serinfo(void) { return -1; }

/* __tls_get_addr — GD/LD TLS model accessor.
 * Looks up the DTV entry for the module and adds the offset. */
struct tls_index { unsigned long ti_module; unsigned long ti_offset; };
static void *stub_tls_get_addr(struct tls_index *ti)
{
    uintptr_t tp;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(tp));
    uintptr_t *dtv = *(uintptr_t **)(tp + 8 /* TCB_OFF_DTV */);
    if (dtv) {
        /* glibc convention: tcb->dtv points to dtv[1] in the raw array.
         * dtv[modid] = {val, to_free} — each slot is 2 uintptr_t's.
         * So dtv[modid * 2] = pointer to start of that module's TLS block */
        uintptr_t tls_block = dtv[ti->ti_module * 2];
        if (tls_block) {
            return (void *)(tls_block + ti->ti_offset);
        }
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

/* ---- TLS / arch constants --------------------------------------------- */
#define ARCH_SET_FS   0x1002
#define TCB_ALLOC     4096     /* generous TCB allocation */

/* tcbhead_t offsets on x86-64 glibc */
#define TCB_OFF_SELF         0    /* void *tcb              */
#define TCB_OFF_DTV          8    /* dtv_t *dtv             */
#define TCB_OFF_SELF2       16    /* void *self             */
#define TCB_OFF_STACK_GUARD 40    /* uintptr_t stack_guard  (0x28) */
#define TCB_OFF_PTR_GUARD   48    /* uintptr_t pointer_guard (0x30) */
#define TCB_OFF_TID        720    /* pid_t tid (0x2D0) — thread ID */

/* ---- per-object runtime state ----------------------------------------- */
struct obj_tls {
    int64_t  tpoff;       /* negative offset from TP to TLS block  */
    uint64_t filesz;      /* .tdata initialization size             */
    uint64_t memsz;       /* total TLS block (tdata + tbss)         */
    uint64_t vaddr;       /* p_vaddr of PT_TLS (in loaded image)    */
    size_t   modid;       /* DTV module ID (1-indexed)              */
};

struct loaded_obj {
    const char       *name;
    uint64_t          base;
    uint32_t          flags;

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

/* ---- dlopen support globals ------------------------------------------ */

#define MAX_TOTAL_OBJS 512

/* Global object table — populated by loader_run, extended by my_dlopen. */
static struct loaded_obj g_all_objs[MAX_TOTAL_OBJS];
static int g_nobj;

/* Per-object metadata for dlopen'd objects (used by protect_object) */
static struct dlfrz_lib_meta g_dl_metas[MAX_TOTAL_OBJS];

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
        uintptr_t fs_self;
        __asm__ volatile("mov %%fs:0x10, %0" : "=r"(fs_self));
        ldr_dbg_hex("[loader]   caller fs:0x10=", fs_self);
        ldr_dbg_hex("[loader]   tp+0x10 before=", *(uintptr_t *)(tp + 16));
    }
    for (int i = 0; i < g_nobj; i++) {
        if (g_all_objs[i].tls.memsz == 0) continue;
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
            if (slot < dtv_slots) {
                dtv[slot * 2]     = tp + (uintptr_t)g_all_objs[i].tls.tpoff;
                dtv[slot * 2 + 1] = 0;
            }
        }
        *(uintptr_t *)(tp + 8 /* TCB_OFF_DTV */) = (uintptr_t)dtv;
    }

    /* Initialize TCB self-pointers so that %fs:0 and %fs:0x10 are valid
     * as soon as the new thread starts.  glibc's allocate_stack is
     * expected to set pd->header.self = pd after we return, but on some
     * builds the store is absent or overwritten, so we ensure it here. */
    *(uintptr_t *)(tp + TCB_OFF_SELF)  = tp;   /* tcbhead.tcb  (offset 0)  */
    *(uintptr_t *)(tp + TCB_OFF_SELF2) = tp;   /* tcbhead.self (offset 16) */

    /* Copy .tdata for all TLS modules */
    void *ret = stub_dl_allocate_tls_init(mem);

    restore_ptr_guard();

    /* Verify our writes survived — debug diagnostics */
    g_last_tls_tp = tp;
    if (g_debug) {
        ldr_dbg_hex("[loader] alloc_tls done tp+0x00=", *(uintptr_t *)(tp + 0));
        ldr_dbg_hex("[loader] alloc_tls done tp+0x08=", *(uintptr_t *)(tp + 8));
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
};

static struct vfs_entry g_vfs_table[VFS_HASH_SIZE];
static int g_vfs_count;

/*
 * VFS_SYSCALL — wrapper for syscall() in VFS functions.
 * musl's __syscall_ret writes errno at FS:0x34 on failure, corrupting
 * glibc's pointer_guard at FS:0x30.  This macro restores it after
 * every syscall so that atexit handlers can still PTR_DEMANGLE.
 */
#define VFS_SYSCALL(...) ({ long _r = syscall(__VA_ARGS__); restore_ptr_guard(); _r; })

/* Saved real libc fopen/fdopen for vfs_fopen fallthrough */
typedef void *(*fopen_fn)(const char *, const char *);
typedef void *(*fdopen_fn)(int, const char *);
static fopen_fn  g_real_fopen;
static fdopen_fn g_real_fdopen;

static uint32_t vfs_hash(const char *s)
{
    uint32_t h = 5381;
    for (; *s; s++)
        h = h * 33 + (uint8_t)*s;
    return h;
}

static void vfs_init_dirs(void);

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
        g_vfs_count++;
    }
    if (g_debug && g_vfs_count > 0) {
        ldr_dbg_hex("[loader] vfs: 0x", g_vfs_count);
        ldr_msg(" data files registered\n");
    }
    if (g_vfs_count > 0)
        vfs_init_dirs();
}

static const struct vfs_entry *vfs_lookup(const char *path)
{
    if (g_vfs_count == 0) return NULL;
    uint32_t idx = vfs_hash(path) & (VFS_HASH_SIZE - 1);
    for (int probes = 0; probes < (int)VFS_HASH_SIZE; probes++) {
        if (!g_vfs_table[idx].path) return NULL;
        if (strcmp(g_vfs_table[idx].path, path) == 0)
            return &g_vfs_table[idx];
        idx = (idx + 1) & (VFS_HASH_SIZE - 1);
    }
    return NULL;
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

static uint32_t vfs_hash_n(const char *s, int n)
{
    uint32_t h = 5381;
    for (int i = 0; i < n; i++)
        h = h * 33 + (uint8_t)s[i];
    return h;
}

/* Check if a directory path of exactly `len` bytes is already in the table */
static int vfs_dir_exists_n(const char *path, int len)
{
    uint32_t idx = vfs_hash_n(path, len) & (VFS_DIR_HASH_SIZE - 1);
    for (int p = 0; p < (int)VFS_DIR_HASH_SIZE; p++) {
        if (!g_vfs_dir_table[idx]) return 0;
        if (strncmp(g_vfs_dir_table[idx], path, len) == 0 &&
            g_vfs_dir_table[idx][len] == '\0')
            return 1;
        idx = (idx + 1) & (VFS_DIR_HASH_SIZE - 1);
    }
    return 0;
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
static int vfs_dir_has_children(const char *dirpath)
{
    int dlen = strlen(dirpath);
    for (int i = 0; i < (int)VFS_HASH_SIZE; i++) {
        if (!g_vfs_table[i].path) continue;
        const char *fp = g_vfs_table[i].path;
        if (strncmp(fp, dirpath, dlen) != 0) continue;
        if (fp[dlen] != '/') continue;
        const char *rest = fp + dlen + 1;
        if (strchr(rest, '/')) continue;  /* not direct child */
        /* Skip .dir markers */
        if (rest[0] == '.' && rest[1] == 'd' && rest[2] == 'i'
            && rest[3] == 'r' && rest[4] == '\0') continue;
        return 1;  /* real direct child file */
    }
    return 0;
}

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

static void *vfs_opendir(const char *path)
{
    int has_vfs = (path && path[0] == '/' && vfs_dir_exists(path));
    /* A captured dir has real child files in VFS (not just markers).
     * These dirs can be served entirely from VFS without opening the
     * real directory on disk. */
    int captured = (has_vfs && vfs_dir_has_children(path));
    int fd = -1;

    if (!captured) {
        fd = (int)VFS_SYSCALL(SYS_openat, AT_FDCWD, path,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0 && !has_vfs)
            return NULL;
    }

    /* Find a free handle */
    for (int i = 0; i < VFS_MAX_DIR_HANDLES; i++) {
        if (g_dir_handles[i].magic == VFS_FAKE_DIR_MAGIC) continue;
        struct vfs_dir_handle *h = &g_dir_handles[i];
        memset(h, 0, sizeof(*h));
        h->magic = VFS_FAKE_DIR_MAGIC;
        h->fd_compat = fd;
        if (captured) {
            /* Pure VFS: all files/subdirs from VFS, no real dir fd */
            h->vfs_path = path;
            h->vfs_path_len = strlen(path);
            h->scan_pos = 0;
            h->phase = 0;
        } else if (has_vfs) {
            /* Merged or VFS-only (no real dir) */
            h->vfs_path = path;
            h->vfs_path_len = strlen(path);
            h->scan_pos = 0;
            h->phase = (fd >= 0) ? -1 : 0;
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
    if (!h || h->magic != VFS_FAKE_DIR_MAGIC) return NULL;

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
                    /* Skip if real FS already has this file */
                    if (h->fd_compat >= 0) {
                        int r = (int)VFS_SYSCALL(SYS_faccessat, AT_FDCWD, fp, 0 /*F_OK*/, 0);
                        if (r == 0) continue;
                    }
                    h->result.d_ino = (ino_t)(si + 1);
                    h->result.d_off = (off_t)h->scan_pos;
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
                    h->result.d_off = (off_t)(VFS_HASH_SIZE + h->scan_pos);
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
    if (!h || h->magic != VFS_FAKE_DIR_MAGIC) return -1;
    if (h->fd_compat >= 0)
        VFS_SYSCALL(SYS_close, h->fd_compat);
    h->magic = 0;
    return 0;
}

/* Helper: create a memfd serving embedded VFS data for a file entry */
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
        const struct vfs_entry *ve = vfs_lookup(path);
        if (ve && ve->size > 0) {
            int fd = vfs_serve_memfd(ve, path);
            if (fd >= 0) return fd;
        }
    }
    return (int)VFS_SYSCALL(SYS_openat, AT_FDCWD, path, flags, mode);
}

static int vfs_openat(int dirfd, const char *path, int flags, int mode)
{
    if (path && path[0] == '/') {
        if ((flags & 3) == 0 /* O_RDONLY */) {
            const struct vfs_entry *ve = vfs_lookup(path);
            if (ve && ve->size > 0) {
                int fd = vfs_serve_memfd(ve, path);
                if (fd >= 0) return fd;
            }
        }
        /* O_DIRECTORY: captured dirs (with VFS children) use a dummy fd
         * to avoid the real openat.  Other VFS dirs try real FS first,
         * then fall back to dummy if the real dir doesn't exist. */
        if ((flags & O_DIRECTORY) && vfs_dir_exists(path)) {
            if (vfs_dir_has_children(path)) {
                if (g_debug) {
                    ldr_msg("vfs: dir openat dummy ");
                    ldr_msg(path);
                    ldr_msg("\n");
                }
                return (int)VFS_SYSCALL(SYS_openat, AT_FDCWD, "/",
                                    O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
            }
            int real_fd = (int)VFS_SYSCALL(SYS_openat, dirfd, path, flags, mode);
            if (real_fd >= 0) return real_fd;
            /* Real dir doesn't exist but VFS knows it */
            return (int)VFS_SYSCALL(SYS_openat, AT_FDCWD, "/",
                                O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
        }
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
        if (ve && ve->size > 0) {
            int fd = vfs_serve_memfd(ve, path);
            if (fd >= 0 && g_real_fdopen)
                return g_real_fdopen(fd, mode);
            if (fd >= 0) VFS_SYSCALL(SYS_close, fd);
        }
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
 * vfs_stat / vfs_fstatat — intercept stat calls for embedded files.
 * Python's import system checks if files exist via stat() before opening.
 * We fabricate a regular-file stat result for embedded VFS entries.
 */
static int vfs_stat(const char *path, struct stat *buf)
{
    if (path && path[0] == '/') {
        /* Files: VFS takes priority (serve embedded data) */
        const struct vfs_entry *ve = vfs_lookup(path);
        if (ve) {
            __builtin_memset(buf, 0, sizeof(*buf));
            buf->st_mode  = 0100644;  /* regular file, rw-r--r-- */
            buf->st_nlink = 1;
            buf->st_size  = ve->size;
            buf->st_blksize = 4096;
            buf->st_blocks  = (ve->size + 511) / 512;
            return 0;
        }
    }
    /* Directories & everything else: real FS first, VFS fallback */
    int ret = (int)VFS_SYSCALL(SYS_newfstatat, AT_FDCWD, path, buf, 0);
    if (ret == 0) return 0;
    if (path && path[0] == '/' && vfs_dir_exists(path)) {
        __builtin_memset(buf, 0, sizeof(*buf));
        buf->st_mode  = 040755;  /* directory, rwxr-xr-x */
        buf->st_nlink = 2;
        buf->st_blksize = 4096;
        return 0;
    }
    return ret;
}

static int vfs_fstatat(int dirfd, const char *path, struct stat *buf, int flag)
{
    if (path && path[0] == '/') {
        const struct vfs_entry *ve = vfs_lookup(path);
        if (ve) {
            __builtin_memset(buf, 0, sizeof(*buf));
            buf->st_mode  = 0100644;
            buf->st_nlink = 1;
            buf->st_size  = ve->size;
            buf->st_blksize = 4096;
            buf->st_blocks  = (ve->size + 511) / 512;
            return 0;
        }
    }
    int ret = (int)VFS_SYSCALL(SYS_newfstatat, dirfd, path, buf, flag);
    if (ret == 0) return 0;
    if (path && path[0] == '/' && vfs_dir_exists(path)) {
        __builtin_memset(buf, 0, sizeof(*buf));
        buf->st_mode  = 040755;
        buf->st_nlink = 2;
        buf->st_blksize = 4096;
        return 0;
    }
    return ret;
}

/* vfs_access / vfs_faccessat — Python calls os.access() / os.path.exists() */
static int vfs_access(const char *path, int amode)
{
    if (path && path[0] == '/') {
        if (vfs_lookup(path)) return 0;
    }
    int ret = (int)VFS_SYSCALL(SYS_faccessat, AT_FDCWD, path, amode, 0);
    if (ret == 0) return 0;
    if (path && path[0] == '/' && vfs_dir_exists(path)) return 0;
    return ret;
}

static int vfs_faccessat(int dirfd, const char *path, int amode, int flag)
{
    if (path && path[0] == '/') {
        if (vfs_lookup(path)) return 0;
    }
    int ret = (int)VFS_SYSCALL(SYS_faccessat, dirfd, path, amode, flag);
    if (ret == 0) return 0;
    if (path && path[0] == '/' && vfs_dir_exists(path)) return 0;
    return ret;
}

/* ==== Resolution cache ================================================ */

#define RESOLVE_CACHE_SIZE 8192U  /* must be power-of-two */

enum cache_state {
    CACHE_EMPTY = 0,
    CACHE_FOUND = 1,
    CACHE_MISS  = 2,
};

struct sym_cache_ent {
    const char *name;
    uint32_t    gh;
    uint8_t     state;
    uint64_t    value;
};

struct tls_cache_ent {
    const char *name;
    uint32_t    gh;
    uint8_t     state;
    int64_t     value;
};

static struct sym_cache_ent g_sym_cache[RESOLVE_CACHE_SIZE];
static struct tls_cache_ent g_tls_cache[RESOLVE_CACHE_SIZE];

static void clear_resolution_caches(void)
{
    memset(g_sym_cache, 0, sizeof(g_sym_cache));
    memset(g_tls_cache, 0, sizeof(g_tls_cache));
}

/* Return: 1 found, -1 cached miss, 0 not present in cache */
static int sym_cache_lookup(const char *name, uint32_t gh, uint64_t *out)
{
    uint32_t idx = gh & (RESOLVE_CACHE_SIZE - 1);
    for (uint32_t n = 0; n < RESOLVE_CACHE_SIZE; n++) {
        struct sym_cache_ent *e = &g_sym_cache[idx];
        if (e->state == CACHE_EMPTY) return 0;
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
        if (e->state == CACHE_EMPTY ||
            (e->gh == gh && e->name && strcmp(e->name, name) == 0)) {
            e->name = name;
            e->gh = gh;
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
        if (e->state == CACHE_EMPTY) return 0;
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
        if (e->state == CACHE_EMPTY ||
            (e->gh == gh && e->name && strcmp(e->name, name) == 0)) {
            e->name = name;
            e->gh = gh;
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

/* ---- dlopen override ------------------------------------------------- */

/* Forward declarations for dlopen replacements */
static void *my_dlopen(const char *path, int flags);
static void *my_dlsym(void *handle, const char *symbol);
static int   my_dlclose(void *handle);
static char *my_dlerror(void);
static int   my_dl_iterate_phdr(
                 int (*callback)(struct dl_phdr_info *, size_t, void *),
                 void *data);

/* Override table — these symbols take priority over libc's exports
 * so that dlopen/dlsym/dlclose/dlerror go through our implementation
 * which can load .so files from the filesystem at runtime. */
static const struct stub_sym g_overrides[] = {
    { "dlopen",          (void *)my_dlopen          },
    { "dlsym",           (void *)my_dlsym           },
    { "dlclose",         (void *)my_dlclose         },
    { "dlerror",         (void *)my_dlerror         },
    { "dl_iterate_phdr", (void *)my_dl_iterate_phdr },
    { "__tls_get_addr",  (void *)stub_tls_get_addr  },
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
    { "stat",            (void *)vfs_stat           },
    { "stat64",          (void *)vfs_stat           },
    { "fstatat",         (void *)vfs_fstatat        },
    { "fstatat64",       (void *)vfs_fstatat        },
    { "access",          (void *)vfs_access         },
    { "faccessat",       (void *)vfs_faccessat      },
    { "opendir",         (void *)vfs_opendir        },
    { "readdir",         (void *)vfs_readdir        },
    { "readdir64",       (void *)vfs_readdir        },
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

/* ==== Map one object's PT_LOAD segments ================================ */

/*
 * Reserve the entire virtual address range for all objects in a single
 * mmap call.  Individual objects are then mapped on top with MAP_FIXED.
 * Returns 0 on success, -1 on failure.
 */
static int reserve_address_range(const struct dlfrz_lib_meta *metas,
                                  const int *idx_map, int nobj,
                                  _Bool memcpy_mode)
{
    /* Find lowest and highest addresses across all objects */
    uint64_t range_lo = UINT64_MAX, range_hi = 0;
    for (int i = 0; i < nobj; i++) {
        int mi = idx_map[i];
        uint64_t lo = metas[mi].base_addr + (metas[mi].vaddr_lo & ~0xFFFULL);
        uint64_t hi = metas[mi].base_addr + ALIGN_UP(metas[mi].vaddr_hi, 4096);
        if (lo < range_lo) range_lo = lo;
        if (hi > range_hi) range_hi = hi;
    }
    if (range_lo >= range_hi) return -1;

    /* Add guard pages at the end */
    range_hi += 4 * 4096;

    /* When segments are populated via memcpy (perf mode or UPX path
     * where srcfd<0), include PROT_EXEC in the reservation so that
     * IRELATIVE resolvers can execute text before protect_object
     * sets final per-segment permissions. */
    int res_prot = PROT_READ | PROT_WRITE;
    if (g_perf_mode || memcpy_mode) res_prot |= PROT_EXEC;

    void *mapped = mmap((void *)range_lo, range_hi - range_lo,
                        res_prot,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                        -1, 0);
    if (mapped == MAP_FAILED) return -1;
    return 0;
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
        if (m == MAP_FAILED) {
            /* Already mapped (shouldn't happen on this path) — try MAP_FIXED */
            m = mmap((void *)(base + lo), span,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                     -1, 0);
            if (m == MAP_FAILED) return -1;
        }
    }

    /* Copy/map each PT_LOAD segment from the payload. */
    const uint8_t *elf_base = mem + (ent->data_offset - mem_foff);
    const uint8_t *phdr_base = elf_base + meta->phdr_off;
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

        /* Zero .bss tail in case file-backed map populated bytes past filesz
         * on the last data page. */
        if (ph->p_memsz > ph->p_filesz) {
            uint8_t *zb = (uint8_t *)(uintptr_t)(base + ph->p_vaddr + ph->p_filesz);
            uint64_t zlen = ph->p_memsz - ph->p_filesz;
            memset(zb, 0, zlen);
        }
        /* BSS (p_memsz - p_filesz) is zero from anon mmap */
    }

    obj->base = base;
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
    } else if (strsz > 0 && strtab > symtab) {
        obj->dynsym_count = (uint32_t)((strtab - symtab) / sizeof(Elf64_Sym));
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

/* pass: 0 = all except IRELATIVE, 1 = only IRELATIVE */
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

        if (type == R_X86_64_IRELATIVE) {
            if (pass == 0) continue;  /* defer to second pass */
            typedef uint64_t (*ifunc_t)(void);
            ifunc_t resolver = (ifunc_t)(base + r->r_addend);
            *slot = resolver();
            continue;
        }
        if (pass == 1) continue;  /* second pass only does IRELATIVE */

        switch (type) {
        case R_X86_64_RELATIVE:
            *slot = base + r->r_addend;
            break;

        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
        case R_X86_64_64: {
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
            *slot = addr + r->r_addend;
            break;
        }

        case R_X86_64_COPY: {
            /* Copy st_size bytes from the defining library into exe's slot */
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
            break;
        }

        case R_X86_64_TPOFF64: {
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

        case R_X86_64_DTPMOD64:
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

        case R_X86_64_DTPOFF64:
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
            if (type != R_X86_64_GLOB_DAT && type != R_X86_64_JUMP_SLOT)
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

/* pass: 0 = everything except IRELATIVE, 1 = only IRELATIVE */
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

static void init_libc_process_state(struct loaded_obj *objs, int nobj,
                                    int argc, char **argv, char **envp)
{
    uint64_t addr;

    addr = resolve_sym(objs, nobj, "__environ");
    if (addr) *(char ***)(uintptr_t)addr = envp;
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
        char **p = envp;
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
     *   +0x2a0 _dl_tls_static_size (non-zero, e.g. 0x1080)
     *   +0x2a8 _dl_tls_static_align (non-zero, e.g. 0x40)
     *
     * tcache TLS is already initialized from .tdata to &__tcache_dummy.
     * On first free(), glibc detects tcache == __tcache_dummy and calls
     * tcache_init() which allocates a real tcache via malloc. This is the
     * normal glibc initialization path — no manual tcache setup needed.
     */

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
            if (strcmp(dl_basename(g_all_objs[j].name), needed) == 0) {
                found = 1;
                break;
            }
        }
        if (found) continue;

        /* Build path and try standard locations */
        static const char *search_dirs[] = {
            "/usr/lib/", "/lib/", "/usr/lib64/", "/lib64/", NULL
        };
        for (const char **dir = search_dirs; *dir; dir++) {
            char path[512];
            char *d = path;
            const char *p = *dir;
            while (*p) *d++ = *p++;
            const char *n = needed;
            while (*n && d < path + sizeof(path) - 1) *d++ = *n++;
            *d = '\0';

            int fd = open(path, O_RDONLY);
            if (fd >= 0) {
                close(fd);
                load_elf_from_file(path);
                break;
            }
        }
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
        /* Zero BSS tail */
        if (phdr_buf[i].p_memsz > phdr_buf[i].p_filesz)
            memset((void *)(base + phdr_buf[i].p_vaddr + phdr_buf[i].p_filesz),
                   0, phdr_buf[i].p_memsz - phdr_buf[i].p_filesz);
    }

    close(fd);

    /* Set up loaded_obj entry */
    struct loaded_obj *obj = &g_all_objs[idx];
    memset(obj, 0, sizeof(*obj));
    obj->base  = base;
    obj->name  = dl_store_name(path);
    obj->flags = LDR_FLAG_SHLIB;
    obj->phdr  = (const Elf64_Phdr *)(base + ehdr.e_phoff);
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
    meta->phdr_off   = ehdr.e_phoff;
    meta->phdr_num   = ehdr.e_phnum;
    meta->phdr_entsz = ehdr.e_phentsize;
    meta->flags      = LDR_FLAG_SHLIB;

    parse_dynamic(obj, meta);

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
                        strcmp(dl_basename(g_all_objs[j].name), needed) == 0) {
                        found = 1; break;
                    }
                }
                if (found) continue;
                /* Try to find in frozen image */
                int dep_found = 0;
                for (uint32_t fi = 0; fi < g_frozen_num_entries; fi++) {
                    const char *fn = g_frozen_strtab + g_frozen_entries[fi].name_offset;
                    if (strcmp(dl_basename(fn), needed) == 0) {
                        load_embedded_object(fi);
                        dep_found = 1;
                        break;
                    }
                }
                if (!dep_found) {
                    /* Try filesystem */
                    static const char *dirs[] = {
                        "/usr/lib/", "/lib/", "/usr/lib64/", "/lib64/", NULL
                    };
                    for (const char **d = dirs; *d; d++) {
                        char path[512];
                        char *pp = path;
                        const char *s = *d;
                        while (*s) *pp++ = *s++;
                        s = needed;
                        while (*s && pp < path + sizeof(path) - 1) *pp++ = *s++;
                        *pp = '\0';
                        int fd = open(path, O_RDONLY);
                        if (fd >= 0) {
                            close(fd);
                            load_elf_from_file(path);
                            break;
                        }
                    }
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
        if (strcmp(dl_basename(g_all_objs[i].name), bn) == 0)
            return &g_all_objs[i];
    }

    /* Check embedded DLOPEN objects in the frozen image */
    if (g_frozen_metas) {
        for (uint32_t i = 0; i < g_frozen_num_entries; i++) {
            if (!(g_frozen_metas[i].flags & LDR_FLAG_DLOPEN)) continue;
            if (g_frozen_metas[i].flags & LDR_FLAG_INTERP) continue;
            const char *ename = g_frozen_strtab + g_frozen_entries[i].name_offset;
            if (strcmp(dl_basename(ename), bn) == 0) {
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

    void *ret = load_elf_from_file(path);
    if (ret) {
        /* Loaded from disk — this library should have been captured */
        ldr_msg("dlfreeze: warning: dlopen loading '");
        ldr_msg(bn);
        ldr_msg("' from disk (not in frozen image)\n");
    }
    restore_ptr_guard();
    return ret;
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
    /* Discover PT_TLS for each object and compute total static TLS size.
     * x86-64 uses Variant II: TLS blocks at negative TP offsets.
     * Layout: [TLS block N ... TLS block 1] [TCB]
     *                                        ^ TP (= FS register)
     */
    uint64_t total_tls = 0;
    for (int oi = 0; oi < nobj; oi++) {
        /* Find the matching manifest index */
        int mi = idx_map[oi];
        const uint8_t *elf = mem + (entries[mi].data_offset - mem_foff);
        const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(elf + metas[mi].phdr_off);

        for (int j = 0; j < metas[mi].phdr_num; j++) {
            if (phdrs[j].p_type != PT_TLS) continue;
            uint64_t align = phdrs[j].p_align ? phdrs[j].p_align : 1;
            total_tls = ALIGN_UP(total_tls + phdrs[j].p_memsz, align);
            objs[oi].tls.tpoff  = -(int64_t)total_tls;
            objs[oi].tls.filesz = phdrs[j].p_filesz;
            objs[oi].tls.memsz  = phdrs[j].p_memsz;
            objs[oi].tls.vaddr  = phdrs[j].p_vaddr;
            objs[oi].tls.modid  = (size_t)(oi + 1);
            break;
        }
    }

    /* Update _rtld_global_ro._dl_tls_static_size so glibc's nptl
     * reserves enough TLS space when creating new threads.
     * glibc formula: roundup(total_tls + surplus + sizeof(struct pthread), 64)
     * sizeof(struct pthread) ≈ 2304 (0x900) on glibc 2.43 x86-64.
     * TLS_STATIC_SURPLUS ≈ 1664.  We use 0x1800 as a safe combined margin. */
    {
        size_t tls_static =
            ALIGN_UP(total_tls + 0x1800, 64);
        *(size_t *)(g_fake_rtld_global_ro + GLRO_DL_TLS_STATIC_SIZE_OFF)
            = tls_static;
    }

    /* Allocate TLS block + TCB */
    size_t tls_aligned = ALIGN_UP(total_tls, 64);
    size_t alloc = tls_aligned + TCB_ALLOC;
    void *block = mmap(NULL, alloc, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (block == MAP_FAILED) {
        ldr_err("TLS mmap failed", NULL);
        return 0;
    }

    uintptr_t tp = (uintptr_t)block + tls_aligned;

    /* Initialize TCB header */
    *(uintptr_t *)(tp + TCB_OFF_SELF)  = tp;
    *(uintptr_t *)(tp + TCB_OFF_SELF2) = tp;

    /* Set thread ID so pthread_mutex_lock ERRORCHECK doesn't
     * falsely detect deadlock (owner==0 vs tid==0). */
    *(int32_t *)(tp + TCB_OFF_TID) = (int32_t)syscall(SYS_gettid);

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
    size_t dtv_slots = 2 + (size_t)nobj;
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
            size_t slot = (size_t)(oi + 1);
            if (slot < dtv_slots) {
                dtv[slot * 2]     = tp + (uintptr_t)objs[oi].tls.tpoff;
                dtv[slot * 2 + 1] = 0;  /* to_free = NULL */
            }
        }
        *(uintptr_t *)(tp + TCB_OFF_DTV) = (uintptr_t)dtv;
    } else {
        *(uintptr_t *)(tp + TCB_OFF_DTV) = 0;
    }

    /* Stack canary from AT_RANDOM */
    if (at_random) {
        uintptr_t canary;
        memcpy(&canary, (void *)at_random, sizeof(canary));
        canary &= ~(uintptr_t)0xFF;   /* glibc zeroes low byte */
        *(uintptr_t *)(tp + TCB_OFF_STACK_GUARD) = canary;

        /* Pointer guard — used by PTR_MANGLE / PTR_DEMANGLE */
        uintptr_t ptr_guard;
        memcpy(&ptr_guard, (void *)(at_random + sizeof(uintptr_t)), sizeof(ptr_guard));
        *(uintptr_t *)(tp + TCB_OFF_PTR_GUARD) = ptr_guard;
    }

    /* Preserve the bootstrap libc's stack canary so that SSP checks in
     * the static libc (musl or glibc) continue to work after we change FS.
     * Both musl and glibc store the canary at FS:0x28. */
    {
        uintptr_t old_canary;
        __asm__ volatile("mov %%fs:0x28, %0" : "=r"(old_canary));
        *(uintptr_t *)(tp + TCB_OFF_STACK_GUARD) = old_canary;
    }

    /* NOTE: .tdata is NOT copied here — it must be copied AFTER
     * relocations are applied so that RELATIVE/RELR-relocated
     * pointers in the TLS template have their final values. */

    /* Set FS register */
    if (syscall(SYS_arch_prctl, ARCH_SET_FS, tp) != 0) {
        ldr_err("arch_prctl ARCH_SET_FS failed", NULL);
        return 0;
    }

    /* Save pointer_guard value and address for crash diagnostics */
    g_ptr_guard_addr = tp + TCB_OFF_PTR_GUARD;
    g_saved_ptr_guard = *(uintptr_t *)(tp + TCB_OFF_PTR_GUARD);

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
                               uintptr_t at_entry, uintptr_t at_random)
{
    /* Count envp */
    int envc = 0;
    while (envp[envc]) envc++;

    /* Build auxiliary vector entries */
    Elf64_auxv_t auxv[] = {
        { AT_PHDR,    { phdr } },
        { AT_PHNUM,   { phnum } },
        { AT_PHENT,   { sizeof(Elf64_Phdr) } },
        { AT_PAGESZ,  { 4096 } },
        { AT_BASE,    { 0 } },          /* no interpreter */
        { AT_ENTRY,   { at_entry } },
        { AT_RANDOM,  { at_random } },
        { AT_SECURE,  { 0 } },
        { AT_NULL,    { 0 } },
    };
    int auxvc = sizeof(auxv) / sizeof(auxv[0]); /* includes AT_NULL */

    /* Total words on stack:
     *   1 (argc) + argc+1 (argv+NULL) + envc+1 (envp+NULL) + auxvc*2 (auxv pairs)
     */
    int nwords = 1 + (argc + 1) + (envc + 1) + auxvc * 2;

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
    for (int i = 0; i < auxvc; i++) {
        sp[p++] = auxv[i].a_type;
        sp[p++] = auxv[i].a_un.a_val;
    }

    __asm__ volatile(
        "mov %0, %%rsp\n\t"
        "xor %%edx, %%edx\n\t"    /* rdx = 0 (rtld_fini = NULL) */
        "xor %%ebp, %%ebp\n\t"    /* clear frame pointer        */
        "jmp *%1\n\t"
        : : "r"(sp), "r"(entry) : "memory"
    );
    __builtin_unreachable();
}

/* ==== Main entry point ================================================= */

int loader_run(const uint8_t *mem, uint64_t mem_foff, int srcfd,
               const struct dlfrz_lib_meta *metas,
               const struct dlfrz_entry *entries,
               const char *strtab,
               uint32_t num_entries,
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

    /* Initialize embedded data-file VFS (before any opens) */
    vfs_init(mem, mem_foff, entries, strtab, num_entries);

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

        /* Resolve real libc fopen/fdopen BEFORE overrides are applied,
         * so vfs_fopen can fall through to the real implementation.
         * Must bypass resolve_sym (which checks g_vfs_overrides and
         * would return our own vfs_fopen). Scan symbol tables directly. */
        if (g_vfs_count > 0) {
            for (int i = 0; i < nobj && (!g_real_fopen || !g_real_fdopen); i++) {
                if (!objs[i].dynsym || !objs[i].dynstr) continue;
                for (uint32_t s = 0; s < objs[i].dynsym_count; s++) {
                    const Elf64_Sym *sym = &objs[i].dynsym[s];
                    if (sym->st_shndx == 0 || sym->st_value == 0) continue;
                    if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC) continue;
                    const char *n = objs[i].dynstr + sym->st_name;
                    if (!g_real_fopen && n[0] == 'f' && n[1] == 'o'
                        && strcmp(n, "fopen64") == 0)
                        g_real_fopen = (fopen_fn)(uintptr_t)(objs[i].base + sym->st_value);
                    else if (!g_real_fdopen && n[0] == 'f' && n[1] == 'd'
                             && strcmp(n, "fdopen") == 0)
                        g_real_fdopen = (fdopen_fn)(uintptr_t)(objs[i].base + sym->st_value);
                }
            }
            ldr_dbg("[loader] g_real_fopen=");
            ldr_dbg_hex("0x", (uint64_t)(uintptr_t)g_real_fopen);
            ldr_dbg(" g_real_fdopen=");
            ldr_dbg_hex("0x", (uint64_t)(uintptr_t)g_real_fdopen);
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
            uint64_t base_i = objs[i].base;
            const Elf64_Rela *tabs[] = { objs[i].rela, objs[i].jmprel };
            size_t counts[] = { objs[i].rela_count, objs[i].jmprel_count };
            size_t starts[] = { objs[i].rela_relative_count, 0 };
            for (int t = 0; t < 2; t++) {
                for (size_t r = starts[t]; r < counts[t]; r++) {
                    const Elf64_Rela *rel = &tabs[t][r];
                    uint32_t type = ELF64_R_TYPE(rel->r_info);

                    if (type == R_X86_64_IRELATIVE) {
                        typedef uint64_t (*ifunc_t)(void);
                        ifunc_t resolver = (ifunc_t)(base_i + rel->r_addend);
                        *(uint64_t *)(base_i + rel->r_offset) = resolver();
                        continue;
                    }

                    if (type != R_X86_64_GLOB_DAT &&
                        type != R_X86_64_JUMP_SLOT) continue;
                    uint32_t sidx = ELF64_R_SYM(rel->r_info);
                    if (sidx == 0) continue;

                    uint64_t *slot = (uint64_t *)(base_i + rel->r_offset);

                    if (*slot != 0) {
                        /* Fast path: pre-linker already resolved this.
                         * Only patch if it's a special symbol (override/
                         * stub/fake_rtld) whose address is runtime-only.
                         * Prefix filter: all specials match dl*, signal,
                         * _rt*, _dl*, __t*, or __r* — reject _Z* (C++
                         * mangled, 95% of underscore symbols) and
                         * everything else. */
                        const char *name = objs[i].dynstr + objs[i].dynsym[sidx].st_name;
                        char c0 = name[0], c1 = name[1];
                        int maybe = (c0 == 'd' && c1 == 'l')
                                 || (c0 == 's' && c1 == 'i')
                                 || (c0 == '_' && (c1 == 'r' || c1 == 'd'
                                     || (c1 == '_' && (name[2] == 't' || name[2] == 'r'))));
                        if (!maybe && g_vfs_count > 0) {
                            maybe = (c0 == 'o')  /* open, open64, openat, openat64, opendir */
                                 || (c0 == 's')  /* stat, stat64 */
                                 || (c0 == 'f')  /* fstatat, fstatat64, faccessat */
                                 || (c0 == 'a')  /* access */
                                 || (c0 == 'r')  /* readdir, readdir64 */
                                 || (c0 == 'c' && c1 == 'l') /* closedir */
                                 || (c0 == '_' && c1 == '_' && name[2] == 'o'); /* __open64_2 */
                        }
                        if (maybe) {
                            uint32_t gh = gnu_hash_calc(name);
                            uint64_t ovr = lookup_special(name, gh);
                            if (ovr) {
                                if (g_debug) {
                                    ldr_msg("GOT patch: ");
                                    ldr_msg(name);
                                    ldr_msg(" in ");
                                    ldr_msg(objs[i].name);
                                    ldr_msg("\n");
                                }
                                *slot = ovr + rel->r_addend;
                            }
                        }
                    } else {
                        /* Slot is 0: truly unresolved at pre-link time.
                         * Try special table, then full resolve. */
                        const char *name = objs[i].dynstr + objs[i].dynsym[sidx].st_name;
                        uint32_t gh = gnu_hash_calc(name);
                        uint64_t ovr = lookup_special(name, gh);
                        if (ovr) {
                            *slot = ovr + rel->r_addend;
                        } else {
                            uint64_t addr = resolve_sym(objs, nobj, name);
                            if (addr) {
                                *slot = addr + rel->r_addend;
                            } else if (ELF64_ST_BIND(objs[i].dynsym[sidx].st_info) != STB_WEAK
                                       && ELF64_ST_TYPE(objs[i].dynsym[sidx].st_info) == STT_OBJECT
                                       && g_null_page) {
                                *slot = (uint64_t)(uintptr_t)g_null_page + rel->r_addend;
                            }
                        }
                    }
                }
            }
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
    if (!prelinked || srcfd < 0) {
        for (int i = 0; i < nobj; i++)
            protect_object(&objs[i], &metas[idx_map[i]]);
    } else if (g_perf_mode) {
        /* In perf mode for main exe: only protect the main exe (prelinked),
         * shared libraries stay file-backed and need no extra protection. */
        for (int i = 0; i < nobj; i++) {
            if (objs[i].flags & LDR_FLAG_MAIN_EXE)
                protect_object(&objs[i], &metas[idx_map[i]]);
        }
    }

    /* Set dlopen support globals before init functions or main() can
     * call dlopen.  g_nobj is the count of objects in g_all_objs. */
    g_nobj = nobj;
    g_argc = argc;
    g_argv = argv;
    g_envp = envp;

    /* Save frozen image context for lazy dlopen loading of embedded
     * DLFRZ_FLAG_DLOPEN objects. */
    g_frozen_mem         = mem;
    g_frozen_mem_foff    = mem_foff;
    g_frozen_srcfd       = srcfd;
    g_frozen_metas       = metas;
    g_frozen_entries     = entries;
    g_frozen_strtab      = strtab;
    g_frozen_num_entries = num_entries;

    /* 7. Initialise libc process state (environ, arena, tcache) BEFORE
     *    calling any init functions — init_array entries in libraries
     *    (e.g. libpython) may call malloc, so the arena must be ready. */
    init_libc_process_state(objs, nobj, argc, argv, envp);

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

    /* Call in reverse order: libraries without dependents first (libc, libm,
     * etc.) then libraries that depend on them (libpython, etc.).
     * The packer stores objects as: exe, direct-deps, transitive-deps...
     * so reversing gives a correct dependency-leaf-first order. */
    for (int i = nobj - 1; i >= 0; i--) {
        if (objs[i].flags & LDR_FLAG_MAIN_EXE) continue;
        ldr_dbg("[loader] init: ");
        ldr_dbg(objs[i].name);
        ldr_dbg("\n");
        if (objs[i].init_func)
            ((init_fn_t)objs[i].init_func)(argc, argv, envp);
        for (size_t j = 0; j < objs[i].init_array_sz; j++)
            ((init_fn_t)objs[i].init_array[j])(argc, argv, envp);
    }
    ldr_dbg("[loader] init functions done\n");

    if (prelinked)
        end_crash_handler_guard();
    else
        restore_crash_handlers_if_still_loader(startup_crash_handlers);

    /* 8. Find the exe's entry point and transfer control */
    uintptr_t entry = 0;
    uintptr_t exe_phdr = 0;
    int exe_phnum = 0;
    for (int i = 0; i < nobj; i++) {
        if (!(objs[i].flags & LDR_FLAG_MAIN_EXE)) continue;
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

    /* 8. Try to call main() directly, bypassing __libc_start_main.
     *    __libc_start_main accesses _rtld_global which requires ld.so.
     *    For simple programs, calling main() directly works because:
     *    - stdio FILE structs are statically initialized in libc's .data
     *    - __libc_single_threaded is 1 (from .data, no locking needed)
     *    - __environ gets set by us below */
    ldr_dbg("[loader] resolving main...\n");
    typedef int (*main_fn_t)(int, char **, char **);
    uint64_t main_addr = 0;
    for (int i = 0; i < nobj; i++) {
        if (!(objs[i].flags & LDR_FLAG_MAIN_EXE)) continue;
        int mi = idx_map[i];
        if (metas[mi].main_sym != 0) {
            main_addr = objs[i].base + metas[mi].main_sym;
            break;
        }
    }
    if (!main_addr)
        main_addr = resolve_sym(objs, nobj, "main");

    if (main_addr) {
        /* Warm up the mapped libc's allocator with a small malloc/free
         * cycle.  This forces __ptmalloc_init's first sbrk() call to
         * happen before we enter user code, establishing main_arena's
         * top chunk in the brk region.  After fork, parent and child
         * have independent brk spaces so there is no collision. */
        uint64_t libc_malloc_addr = resolve_sym(objs, nobj, "malloc");
        uint64_t libc_free_addr = resolve_sym(objs, nobj, "free");
        if (libc_malloc_addr && libc_free_addr) {
            void *p = ((void *(*)(size_t))(uintptr_t)libc_malloc_addr)(64);
            if (p)
                ((void (*)(void *))(uintptr_t)libc_free_addr)(p);
        }
        ldr_dbg("[loader] calling main() directly...\n");
        restore_ptr_guard();
        int rc = ((main_fn_t)(uintptr_t)main_addr)(argc, argv, envp);
        ldr_dbg("[loader] main() returned\n");
        /* Flush all stdio streams before _exit — _exit doesn't run atexit
         * handlers or flush stdio.  When stdout is a pipe (e.g. captured
         * by $(cmd)), libc uses full buffering so output would be lost. */
        uint64_t fflush_addr = resolve_sym(objs, nobj, "fflush");
        if (fflush_addr)
            ((int (*)(void *))(uintptr_t)fflush_addr)(NULL);
        _exit(rc);
    }

    /* Fallback: transfer control via _start → __libc_start_main. */
    ldr_dbg("[loader] transferring to _start...\n");
    restore_ptr_guard();
    transfer_to_entry(entry, argc, argv, envp,
                      exe_phdr, exe_phnum, entry, at_random);
    /* NOTREACHED */
}
