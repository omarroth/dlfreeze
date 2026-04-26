#include "dep_resolver.h"
#include "elf_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <libgen.h>

/* ------------------------------------------------------------------ */
/*  Default search paths (covers Debian/Ubuntu, Fedora/Arch, etc.)    */
/* ------------------------------------------------------------------ */
static const char *default_paths[] = {
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

/* Virtual/kernel-provided objects that are not real files */
static int is_virtual_lib(const char *name)
{
    return (strncmp(name, "linux-vdso", 10) == 0 ||
            strncmp(name, "linux-gate", 10) == 0 ||
            strcmp(name, "ld-linux-x86-64.so.2") == 0 ||
            strncmp(name, "ld-linux", 8) == 0 ||
            strncmp(name, "ld-musl", 7) == 0);
}

static int is_musl_interpreter(const char *path)
{
    const char *base;

    if (!path || !path[0]) return 0;
    base = strrchr(path, '/');
    base = base ? base + 1 : path;
    return strncmp(base, "ld-musl", 7) == 0;
}

static char *resolve_from_musl_interp_dir(const char *name,
                                          const char *interp_path)
{
    char *interp_real;
    char *interp_copy;
    char *interp_dir;
    char path[PATH_MAX];
    struct stat st;

    if (!is_musl_interpreter(interp_path)) return NULL;

    interp_real = realpath(interp_path, NULL);
    if (!interp_real) return NULL;

    interp_copy = strdup(interp_real);
    free(interp_real);
    if (!interp_copy) return NULL;

    interp_dir = dirname(interp_copy);
    snprintf(path, sizeof(path), "%s/%s", interp_dir, name);
    free(interp_copy);

    if (stat(path, &st) != 0) return NULL;

    {
        char *rp = realpath(path, NULL);
        return rp ? rp : strdup(path);
    }
}

/* Common glibc runtime libs loaded via dlopen (NSS, resolv …) */
static const char *glibc_runtime_libs[] = {
    "libnss_files.so.2",
    "libnss_dns.so.2",
    "libresolv.so.2",
    "libnss_myhostname.so.2",
    NULL
};

/* ------------------------------------------------------------------ */
/*  ldconfig -p cache                                                 */
/* ------------------------------------------------------------------ */
static struct { char *name; char *path; } *ldc_cache;
static int ldc_count;
static int ldc_loaded;

static void load_ldconfig_cache(void)
{
    if (ldc_loaded) return;
    ldc_loaded = 1;

    FILE *f = popen("ldconfig -p 2>/dev/null", "r");
    if (!f) return;

    char line[2048];
    /* skip header */
    if (!fgets(line, sizeof(line), f)) { pclose(f); return; }

    int cap = 256;
    ldc_cache = calloc(cap, sizeof(*ldc_cache));

    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;

        char *sp = strchr(p, ' ');
        if (!sp) continue;
        *sp = '\0';

        char *arrow = strstr(sp + 1, "=> ");
        if (!arrow) continue;
        char *path = arrow + 3;
        char *nl = strchr(path, '\n');
        if (nl) *nl = '\0';

        if (ldc_count >= cap) {
            cap *= 2;
            ldc_cache = realloc(ldc_cache, cap * sizeof(*ldc_cache));
        }
        ldc_cache[ldc_count].name = strdup(p);
        ldc_cache[ldc_count].path = strdup(path);
        ldc_count++;
    }
    pclose(f);
}

static char *resolve_from_ldconfig(const char *name)
{
    load_ldconfig_cache();
    for (int i = 0; i < ldc_count; i++)
        if (strcmp(ldc_cache[i].name, name) == 0) {
            char *rp = realpath(ldc_cache[i].path, NULL);
            return rp ? rp : strdup(ldc_cache[i].path);
        }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  dep_list helpers                                                  */
/* ------------------------------------------------------------------ */
static int dep_list_add(struct dep_list *deps, const char *name,
                        const char *path, int from_dlopen,
                        int dlopen_direct)
{
    /* deduplicate by resolved path */
    for (int i = 0; i < deps->count; i++) {
        if (strcmp(deps->libs[i].path, path) != 0)
            continue;

        if (!from_dlopen)
            deps->libs[i].from_dlopen = 0;
        if (dlopen_direct)
            deps->libs[i].dlopen_direct = 1;

        /* If the existing entry used a fully-versioned basename from a
         * traced realpath(), but we later discover the DT_SONAME, prefer
         * the soname so runtime DT_NEEDED basename matching works. */
        if (strcmp(deps->libs[i].name, name) != 0) {
            size_t nlen = strlen(name);

            if (strncmp(deps->libs[i].name, name, nlen) == 0 &&
                deps->libs[i].name[nlen] == '.') {
                char *nn = strdup(name);

                if (nn) {
                    free(deps->libs[i].name);
                    deps->libs[i].name = nn;
                }
            }
        }
        return 0;
    }

    if (deps->count >= deps->capacity) {
        int nc = deps->capacity ? deps->capacity * 2 : 64;
        struct resolved_lib *nl = realloc(deps->libs, nc * sizeof(*nl));
        if (!nl) return -1;
        deps->libs = nl;
        deps->capacity = nc;
    }
    deps->libs[deps->count].name        = strdup(name);
    deps->libs[deps->count].path        = strdup(path);
    deps->libs[deps->count].from_dlopen = from_dlopen;
    deps->libs[deps->count].dlopen_direct = dlopen_direct;
    deps->count++;
    return 1; /* added */
}

/* ------------------------------------------------------------------ */
/*  $ORIGIN expansion                                                 */
/* ------------------------------------------------------------------ */
static char *expand_origin(const char *tmpl, const char *origin)
{
    char *buf = malloc(PATH_MAX);
    if (!buf) return NULL;
    char *d = buf, *end = buf + PATH_MAX - 1;
    const char *s = tmpl;
    while (*s && d < end) {
        if (strncmp(s, "${ORIGIN}", 9) == 0) {
            size_t l = strlen(origin);
            if (d + l >= end) break;
            memcpy(d, origin, l); d += l; s += 9;
        } else if (strncmp(s, "$ORIGIN", 7) == 0 &&
                   (s[7] == '/' || s[7] == ':' || s[7] == '\0')) {
            size_t l = strlen(origin);
            if (d + l >= end) break;
            memcpy(d, origin, l); d += l; s += 7;
        } else {
            *d++ = *s++;
        }
    }
    *d = '\0';
    return buf;
}

/* ------------------------------------------------------------------ */
/*  Library search (RPATH → LD_LIBRARY_PATH → RUNPATH → defaults)     */
/* ------------------------------------------------------------------ */
static char *search_dirs(const char *name, const char *dirs, const char *origin)
{
    if (!dirs || !dirs[0]) return NULL;
    char *copy = strdup(dirs);
    if (!copy) return NULL;
    char *save, *tok;
    char path[PATH_MAX];
    struct stat st;

    for (tok = strtok_r(copy, ":", &save); tok; tok = strtok_r(NULL, ":", &save)) {
        char *expanded = expand_origin(tok, origin);
        snprintf(path, sizeof(path), "%s/%s", expanded, name);
        free(expanded);
        if (stat(path, &st) == 0) {
            free(copy);
            char *rp = realpath(path, NULL);
            return rp ? rp : strdup(path);
        }
    }
    free(copy);
    return NULL;
}

static char *find_library(const char *name,
                          const char *rpath, const char *runpath,
                          const char *origin, const char *interp_path)
{
    char *p;
    struct stat st;

    /* absolute path → use directly */
    if (name[0] == '/') {
        if (stat(name, &st) == 0) return realpath(name, NULL);
        return NULL;
    }

    /* 1. RPATH (only when RUNPATH absent) */
    if (rpath && rpath[0] && (!runpath || !runpath[0])) {
        p = search_dirs(name, rpath, origin);
        if (p) return p;
    }

    /* 2. LD_LIBRARY_PATH */
    const char *ldp = getenv("LD_LIBRARY_PATH");
    if (ldp && ldp[0]) {
        p = search_dirs(name, ldp, origin);
        if (p) return p;
    }

    /* 3. RUNPATH */
    if (runpath && runpath[0]) {
        p = search_dirs(name, runpath, origin);
        if (p) return p;
    }

    /* musl keeps its real runtime DSOs next to the interpreter */
    p = resolve_from_musl_interp_dir(name, interp_path);
    if (p) return p;

    /* 4. ldconfig cache */
    p = resolve_from_ldconfig(name);
    if (p) return p;

    /* 5. Default paths */
    char path[PATH_MAX];
    for (int i = 0; default_paths[i]; i++) {
        snprintf(path, sizeof(path), "%s/%s", default_paths[i], name);
        if (stat(path, &st) == 0) {
            char *rp = realpath(path, NULL);
            return rp ? rp : strdup(path);
        }
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/*  BFS queue                                                         */
/* ------------------------------------------------------------------ */
struct bfs_queue {
    char **items;
    int    head, tail, cap;
};

static void bfs_init(struct bfs_queue *q)
{
    q->cap   = 256;
    q->items = calloc(q->cap, sizeof(char *));
    q->head  = q->tail = 0;
}

static void bfs_push(struct bfs_queue *q, const char *s)
{
    if (q->tail >= q->cap) {
        q->cap *= 2;
        q->items = realloc(q->items, q->cap * sizeof(char *));
    }
    q->items[q->tail++] = strdup(s);
}

static char *bfs_pop(struct bfs_queue *q)
{
    if (q->head >= q->tail) return NULL;
    return q->items[q->head++];
}

static void bfs_free(struct bfs_queue *q)
{
    for (int i = q->head; i < q->tail; i++) free(q->items[i]);
    free(q->items);
}

/* ------------------------------------------------------------------ */
/*  Resolve all transitive deps of one ELF into deps                  */
/* ------------------------------------------------------------------ */
static void resolve_needed(struct elf_info *info, const char *origin,
                           struct dep_list *deps, struct bfs_queue *q,
                           int dlopen_flag)
{
    for (int i = 0; i < info->needed_count; i++) {
        const char *name = info->needed[i];
        if (is_virtual_lib(name)) continue;

        char *path = find_library(name, info->rpath, info->runpath, origin,
                                  deps->interp_path);
        if (!path) {
            fprintf(stderr, "dlfreeze: warning: library not found: %s\n", name);
            continue;
        }
        int added = dep_list_add(deps, name, path, dlopen_flag, 0);
        if (added > 0) bfs_push(q, path);
        free(path);
    }
}

/* ------------------------------------------------------------------ */
/*  Public: resolve all deps                                          */
/* ------------------------------------------------------------------ */
int dep_resolve(const char *exe_path, struct dep_list *deps)
{
    memset(deps, 0, sizeof(*deps));

    char *real = realpath(exe_path, NULL);
    if (!real) { perror(exe_path); return -1; }

    char *dir_tmp = strdup(real);
    char *origin  = strdup(dirname(dir_tmp));
    free(dir_tmp);

    struct elf_info info;
    if (elf_parse(real, &info) < 0) {
        fprintf(stderr, "dlfreeze: failed to parse %s\n", real);
        free(origin); free(real);
        return -1;
    }

    if (!info.is_dynamic) {
        fprintf(stderr, "dlfreeze: %s is not dynamically linked\n", real);
        elf_info_free(&info);
        free(origin); free(real);
        return -1;
    }

    if (info.interp[0])
        deps->interp_path = strdup(info.interp);

    struct bfs_queue q;
    bfs_init(&q);

    resolve_needed(&info, origin, deps, &q, 0);
    elf_info_free(&info);

    /* BFS: process transitive deps */
    char *lib_path;
    while ((lib_path = bfs_pop(&q))) {
        struct elf_info li;
        if (elf_parse(lib_path, &li) < 0) { free(lib_path); continue; }

        char *dt = strdup(lib_path);
        char *lo = strdup(dirname(dt));
        resolve_needed(&li, lo, deps, &q, 0);
        free(lo); free(dt);
        elf_info_free(&li);
        free(lib_path);
    }
    bfs_free(&q);

    /* Auto-add common glibc NSS libraries when libc.so.6 is present */
    int has_glibc = 0;
    for (int i = 0; i < deps->count; i++)
        if (strcmp(deps->libs[i].name, "libc.so.6") == 0) { has_glibc = 1; break; }

    if (has_glibc) {
        struct bfs_queue q2;
        bfs_init(&q2);

        for (int i = 0; glibc_runtime_libs[i]; i++) {
            char *p = find_library(glibc_runtime_libs[i], NULL, NULL, origin,
                                   deps->interp_path);
            if (p) {
                int added = dep_list_add(deps, glibc_runtime_libs[i], p, 0, 0);
                if (added > 0) bfs_push(&q2, p);
                free(p);
            }
        }

        /* resolve their deps too */
        while ((lib_path = bfs_pop(&q2))) {
            struct elf_info li;
            if (elf_parse(lib_path, &li) == 0) {
                char *dt = strdup(lib_path);
                char *lo = strdup(dirname(dt));
                resolve_needed(&li, lo, deps, &q2, 0);
                free(lo); free(dt);
                elf_info_free(&li);
            }
            free(lib_path);
        }
        bfs_free(&q2);
    }

    free(origin);
    free(real);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Merge dlopen-traced libraries                                     */
/* ------------------------------------------------------------------ */
int dep_add_dlopen_libs(struct dep_list *deps, const char *trace_file)
{
    FILE *f = fopen(trace_file, "r");
    if (!f) return -1;

    struct bfs_queue q;
    bfs_init(&q);

    char line[PATH_MAX];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (len == 0) continue;

        /* resolve to real path */
        char *rp = realpath(line, NULL);
        if (!rp) continue;

        const char *base = strrchr(rp, '/');
        const char *name;
        struct elf_info info;

        base = base ? base + 1 : rp;
        if (is_virtual_lib(base)) { free(rp); continue; }

        name = base;
        if (elf_parse(rp, &info) == 0) {
            if (info.soname[0])
                name = info.soname;
            elf_info_free(&info);
        }

        int added = dep_list_add(deps, name, rp, 1, 1);
        if (added > 0) bfs_push(&q, rp);
        free(rp);
    }
    fclose(f);

    /* resolve transitive deps of dlopen'd libs */
    char *lib_path;
    while ((lib_path = bfs_pop(&q))) {
        struct elf_info li;
        if (elf_parse(lib_path, &li) == 0) {
            char *dt = strdup(lib_path);
            char *lo = strdup(dirname(dt));
            resolve_needed(&li, lo, deps, &q, 1);
            free(lo); free(dt);
            elf_info_free(&li);
        }
        free(lib_path);
    }
    bfs_free(&q);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Cleanup                                                           */
/* ------------------------------------------------------------------ */
void dep_list_free(struct dep_list *deps)
{
    for (int i = 0; i < deps->count; i++) {
        free(deps->libs[i].name);
        free(deps->libs[i].path);
    }
    free(deps->libs);
    free(deps->interp_path);
    memset(deps, 0, sizeof(*deps));
}
