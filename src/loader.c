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
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <elf.h>
#include <stdint.h>

#include "common.h"
#include "loader.h"

/* ---- flag constants (must match common.h) ----------------------------- */
#define LDR_FLAG_MAIN_EXE  0x01
#define LDR_FLAG_INTERP    0x02
#define LDR_FLAG_SHLIB     0x04

/* Zeroed page used as target for unresolved OBJECT symbols.
 * Prevents NULL dereference crashes in IFUNC resolvers. */
static void *g_null_page;

/* ---- error output (no stdio — bootstrap may break after TLS swap) ----- */
static void ldr_msg(const char *s)
{
    if (s) write(STDERR_FILENO, s, strlen(s));
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
#define GL_DL_TLS_GENERATION_OFF 0x7f0       /* _dl_tls_generation      */
#define GL_DL_STACK_USED_OFF  0x800          /* _dl_stack_used (list_t) */
#define GL_DL_STACK_USER_OFF  0x810          /* _dl_stack_user (list_t) */
#define GL_DL_STACK_CACHE_OFF 0x820          /* _dl_stack_cache(list_t) */

static uint8_t *g_fake_rtld_global;
static uint8_t *g_fake_rtld_global_ro;

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
    *(size_t *)(g_fake_rtld_global + GL_DL_TLS_GENERATION_OFF) = 1;

    /* Empty circular lists for stack tracking */
    init_empty_list(g_fake_rtld_global, GL_DL_STACK_USED_OFF);
    init_empty_list(g_fake_rtld_global, GL_DL_STACK_USER_OFF);
    init_empty_list(g_fake_rtld_global, GL_DL_STACK_CACHE_OFF);

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

/* _dl_allocate_tls / _dl_allocate_tls_init / _dl_deallocate_tls — stubs */
static void *stub_dl_allocate_tls(void *mem) { return mem; }
static void *stub_dl_allocate_tls_init(void *mem) { return mem; }
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
        /* dtv[module * 2] = pointer to start of that module's TLS block */
        uintptr_t tls_block = dtv[ti->ti_module * 2];
        if (tls_block)
            return (void *)(tls_block + ti->ti_offset);
    }
    /* Fallback: single-module approximation */
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

/* ---- TLS / arch constants --------------------------------------------- */
#define ARCH_SET_FS   0x1002
#define TCB_ALLOC     4096     /* generous TCB allocation */

/* tcbhead_t offsets on x86-64 glibc */
#define TCB_OFF_SELF         0    /* void *tcb              */
#define TCB_OFF_DTV          8    /* dtv_t *dtv             */
#define TCB_OFF_SELF2       16    /* void *self             */
#define TCB_OFF_STACK_GUARD 40    /* uintptr_t stack_guard  (0x28) */
#define TCB_OFF_PTR_GUARD   48    /* uintptr_t pointer_guard (0x30) */

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

    /* TLS */
    struct obj_tls    tls;
};

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
    uint64_t stub = lookup_stub(name);
    if (!stub) stub = lookup_fake_object(name);
    if (stub) {
        sym_cache_store(name, gh, CACHE_FOUND, stub);
        return stub;
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

static int map_object(const uint8_t *mem, uint64_t mem_foff, int srcfd,
                      const struct dlfrz_lib_meta *meta,
                      const struct dlfrz_entry *ent,
                      struct loaded_obj *obj)
{
    uint64_t base = meta->base_addr;
    uint64_t lo   = meta->vaddr_lo & ~0xFFFULL;
    uint64_t hi   = ALIGN_UP(meta->vaddr_hi, 4096);
    uint64_t span = hi - lo;
    /* Add guard pages to cover glibc's optimised memcpy/memset which
     * prefetch up to 0x3040 bytes ahead of the source pointer.  When
     * a buffer ends near the last mapped page of an object, these
     * speculative reads would fault on the unmapped page after it.
     * 4 pages (16 KiB) covers the largest observed prefetch. */
    span += 4 * 4096;

    void *mapped = mmap((void *)(base + lo), span,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                        -1, 0);
    if (mapped == MAP_FAILED) {
        ldr_err("mmap failed", obj->name);
        return -1;
    }

    /* Copy/map each PT_LOAD segment from the payload.
     * If we have a real source fd for the frozen ELF (normal non-UPX path),
     * map file-backed pages directly to reduce copying and disk writes. */
    const uint8_t *elf_base = mem + (ent->data_offset - mem_foff);
    const uint8_t *phdr_base = elf_base + meta->phdr_off;
    for (int i = 0; i < meta->phdr_num; i++) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(phdr_base + i * meta->phdr_entsz);
        if (ph->p_type != PT_LOAD) continue;

        if (ph->p_filesz > 0 && srcfd >= 0 && mem_foff == 0) {
            uint64_t seg_page_vaddr = ph->p_vaddr & ~0xFFFULL;
            uint64_t seg_page_off   = ph->p_offset & ~0xFFFULL;
            uint64_t page_delta     = ph->p_vaddr - seg_page_vaddr;
            uint64_t map_len        = ALIGN_UP(page_delta + ph->p_filesz, 4096);
            uint64_t file_off       = ent->data_offset + seg_page_off;

            void *m = mmap((void *)(base + seg_page_vaddr), map_len,
                           PROT_READ | PROT_WRITE | PROT_EXEC,
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
    uint64_t rela = 0, rela_sz = 0;
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
            if (sidx != 0)
                *slot = obj->dynsym[sidx].st_value + r->r_addend;
            else
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
 */
static void preseed_rtld_got(struct loaded_obj *obj)
{
    uint64_t base = obj->base;

    /* scan rela.dyn */
    for (size_t i = 0; i < obj->rela_count; i++) {
        const Elf64_Rela *r = &obj->rela[i];
        if (ELF64_R_TYPE(r->r_info) != R_X86_64_GLOB_DAT) continue;
        uint32_t sidx = ELF64_R_SYM(r->r_info);
        const char *name = obj->dynstr + obj->dynsym[sidx].st_name;
        uint64_t addr = lookup_fake_object(name);
        if (addr) {
            uint64_t *slot = (uint64_t *)(base + r->r_offset);
            *slot = addr + r->r_addend;
        }
    }

    /* scan rela.plt */
    for (size_t i = 0; i < obj->jmprel_count; i++) {
        const Elf64_Rela *r = &obj->jmprel[i];
        uint32_t type = ELF64_R_TYPE(r->r_info);
        if (type != R_X86_64_JUMP_SLOT && type != R_X86_64_GLOB_DAT) continue;
        uint32_t sidx = ELF64_R_SYM(r->r_info);
        const char *name = obj->dynstr + obj->dynsym[sidx].st_name;
        uint64_t addr = lookup_fake_object(name);
        if (addr) {
            uint64_t *slot = (uint64_t *)(base + r->r_offset);
            *slot = addr + r->r_addend;
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
    addr = resolve_sym(objs, nobj, "__libc_early_init");
    if (addr) {
        ldr_msg("[loader] calling __libc_early_init...\n");
        ((void(*)(int))(uintptr_t)addr)(1);
        ldr_msg("[loader] __libc_early_init done\n");
    }

    /* Pre-initialize __curbrk in the mapped libc so that sbrk() has
     * the correct kernel brk value from the start. */
    addr = resolve_sym(objs, nobj, "__curbrk");
    if (addr) {
        void *cur = (void *)syscall(SYS_brk, 0);
        *(void **)(uintptr_t)addr = cur;
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

    /*
     * Minimal DTV (Dynamic Thread Vector).
     * glibc expects tcb->dtv to be non-NULL.  Layout:
     *   dtv[0].counter = generation (size_t)
     *   dtv[1].pointer.val = pointer to TLS block for module 1
     *   dtv[1].pointer.to_free = NULL
     * We allocate a small array.  Module 1 = libc's TLS block.
     */
    size_t dtv_slots = 2 + (size_t)nobj;
    size_t dtv_bytes = dtv_slots * 2 * sizeof(uintptr_t);
    uintptr_t *dtv = (uintptr_t *)mmap(NULL, ALIGN_UP(dtv_bytes, 4096),
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (dtv != MAP_FAILED) {
        /* dtv[0] = generation counter */
        dtv[0] = 1;   /* generation */
        dtv[1] = 0;
        /* dtv[i] for each TLS module: .val = tp + tpoff, .to_free = NULL
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

    /* NOTE: .tdata is NOT copied here — it must be copied AFTER
     * relocations are applied so that RELATIVE/RELR-relocated
     * pointers in the TLS template have their final values. */

    /* Set FS register */
    if (syscall(SYS_arch_prctl, ARCH_SET_FS, tp) != 0) {
        ldr_err("arch_prctl ARCH_SET_FS failed", NULL);
        return 0;
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
    clear_resolution_caches();

    /* Install crash handlers for debugging */
    {
        struct sigaction sa = {0};
        sa.sa_sigaction = crash_handler;
        sa.sa_flags = SA_SIGINFO;
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGABRT, &sa, NULL);
        sigaction(SIGBUS,  &sa, NULL);
        sigaction(SIGFPE,  &sa, NULL);
        sigaction(SIGILL,  &sa, NULL);
    }

    /* 1. Count non-INTERP libraries and build object array */
    /* Allocate a zero-filled page for unresolved OBJECT symbols */
    g_null_page = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    /* Allocate fake _rtld_global / _rtld_global_ro for libc */
    if (init_fake_rtld() < 0) return -1;

    int nobj = 0;
    for (uint32_t i = 0; i < num_entries; i++)
        if (!(metas[i].flags & LDR_FLAG_INTERP)) nobj++;

    if (nobj == 0) { ldr_err("no objects to load", NULL); return -1; }

    /* alloca-like: use a VLA for the small arrays */
    struct loaded_obj objs[nobj];
    int idx_map[nobj];    /* idx_map[oi] = manifest index */
    memset(objs, 0, sizeof(objs));

    /* Build in order: exe first, then shared libs */
    int oi = 0;
    for (uint32_t i = 0; i < num_entries; i++) {
        if (metas[i].flags & LDR_FLAG_INTERP) continue;
        if (!(metas[i].flags & LDR_FLAG_MAIN_EXE)) continue;
        objs[oi].name  = strtab + entries[i].name_offset;
        objs[oi].flags = metas[i].flags;
        idx_map[oi] = (int)i;
        oi++;
    }
    for (uint32_t i = 0; i < num_entries; i++) {
        if (metas[i].flags & LDR_FLAG_INTERP) continue;
        if (metas[i].flags & LDR_FLAG_MAIN_EXE) continue;
        objs[oi].name  = strtab + entries[i].name_offset;
        objs[oi].flags = metas[i].flags;
        idx_map[oi] = (int)i;
        oi++;
    }

    /* 2. Map all objects into memory at pre-assigned addresses */
    ldr_msg("[loader] mapping objects...\n");
    for (int i = 0; i < nobj; i++) {
        int mi = idx_map[i];
        if (map_object(mem, mem_foff, srcfd, &metas[mi], &entries[mi], &objs[i]) < 0)
            return -1;
        ldr_msg("  ");
        ldr_msg(objs[i].name);
        ldr_hex("  base=0x", objs[i].base);
    }

    /* 3. Parse PT_DYNAMIC for each object */
    ldr_msg("[loader] parsing dynamic sections...\n");
    for (int i = 0; i < nobj; i++)
        parse_dynamic(&objs[i], &metas[idx_map[i]]);

    /* 4. Set up TLS (must happen before relocations that reference TLS,
     *    and definitely before calling any IRELATIVE resolvers that might
     *    touch TLS / stack guard) */
    ldr_msg("[loader] setting up TLS...\n");
    uintptr_t at_random = get_auxval(envp, 25 /* AT_RANDOM */);
    uintptr_t tp = setup_tls(objs, nobj, mem, mem_foff, metas, entries,
                              idx_map, num_entries, at_random);
    /* NOTE: After setup_tls, FS register is changed.  The bootstrap's
     * static glibc functions (printf, malloc etc.) are no longer safe
     * to call.  Use only write() and _exit() from here on. */

    /* 5. Apply relocations for all objects.
     *    Two-pass: first apply all non-IRELATIVE relocations across all
     *    objects so that GOT entries (e.g. _rtld_global_ro) are populated,
     *    then apply IRELATIVE whose resolvers depend on those GOT entries. */
    ldr_msg("[loader] applying relocations...\n");

    /* Pre-seed _rtld_global/_rtld_global_ro GOT entries so IFUNC
     * resolvers called during GLOB_DAT processing work correctly. */
    for (int i = 0; i < nobj; i++)
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

    /* 5b. Copy .tdata AFTER relocations — the TLS template contains
     *     pointers that need RELATIVE/RELR relocation first. */
    if (tp)
        copy_tdata(objs, nobj, tp);

    /* 6. Set final memory protections */
    ldr_msg("[loader] setting protections...\n");
    for (int i = 0; i < nobj; i++)
        protect_object(&objs[i], &metas[idx_map[i]]);

    /* 7. Initialise libc process state (environ, arena, tcache) BEFORE
     *    calling any init functions — init_array entries in libraries
     *    (e.g. libpython) may call malloc, so the arena must be ready. */
    init_libc_process_state(objs, nobj, argc, argv, envp);

    /* 7b. Call shared library init functions (libc first, then others).
     *    Skip the exe — its constructors are called later.
     *    Now safe because _rtld_global/_rtld_global_ro stubs are in place
     *    and __tunable_get_val etc. resolve to our no-op stubs. */
    ldr_msg("[loader] calling init functions...\n");
    typedef void (*init_fn_t)(int, char **, char **);
    /* Call in reverse order: libraries without dependents first (libc, libm,
     * etc.) then libraries that depend on them (libpython, etc.).
     * The packer stores objects as: exe, direct-deps, transitive-deps...
     * so reversing gives a correct dependency-leaf-first order. */
    for (int i = nobj - 1; i >= 0; i--) {
        if (objs[i].flags & LDR_FLAG_MAIN_EXE) continue;
        ldr_msg("[loader] init: ");
        ldr_msg(objs[i].name);
        ldr_msg("\n");
        if (objs[i].init_func)
            ((init_fn_t)objs[i].init_func)(argc, argv, envp);
        for (size_t j = 0; j < objs[i].init_array_sz; j++)
            ((init_fn_t)objs[i].init_array[j])(argc, argv, envp);
    }
    ldr_msg("[loader] init functions done\n");

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
    ldr_msg("[loader] resolving main...\n");
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
        /* Configure the mapped libc's allocator.
         * Set M_MMAP_THRESHOLD=0 so that all allocations use mmap instead
         * of sbrk.  This works around a top-chunk corruption that occurs
         * in the direct-load environment when the bootstrap's static libc
         * and the mapped libc share the kernel program break.  With
         * mmap-based allocation, the arena's top stays at initial_top
         * (size 0) and the corruption is harmless.
         * M_MMAP_THRESHOLD = mallopt parameter -3. */
        uint64_t libc_mallopt_addr = resolve_sym(objs, nobj, "mallopt");
        if (libc_mallopt_addr)
            ((int(*)(int,int))(uintptr_t)libc_mallopt_addr)(-3, 0);

        uint64_t libc_malloc_addr = resolve_sym(objs, nobj, "malloc");
        uint64_t libc_free_addr = resolve_sym(objs, nobj, "free");
        if (libc_malloc_addr && libc_free_addr) {
            void *p = ((void *(*)(size_t))(uintptr_t)libc_malloc_addr)(64);
            if (p)
                ((void (*)(void *))(uintptr_t)libc_free_addr)(p);
        }
        ldr_msg("[loader] calling main() directly...\n");
        int rc = ((main_fn_t)(uintptr_t)main_addr)(argc, argv, envp);
        ldr_msg("[loader] main() returned\n");
        _exit(rc);
    }

    /* Fallback: transfer control via _start → __libc_start_main. */
    ldr_msg("[loader] transferring to _start...\n");
    transfer_to_entry(entry, argc, argv, envp,
                      exe_phdr, exe_phnum, entry, at_random);
    /* NOTREACHED */
}
