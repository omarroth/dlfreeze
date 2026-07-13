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

static int elf_matches_target(const char *path, const struct dep_list *deps)
{
    struct elf_info info;
    int matches;

    if (elf_parse(path, &info) < 0)
        return 0;
    matches = info.is_dynamic &&
              info.ei_class == deps->target_ei_class &&
              info.e_machine == deps->target_e_machine;
    elf_info_free(&info);
    return matches;
}

static char *validated_candidate(const char *path,
                                 const struct dep_list *deps)
{
    struct stat st;
    char *real;

    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return NULL;

    real = realpath(path, NULL);
    if (!real)
        return NULL;
    if (!elf_matches_target(real, deps)) {
        free(real);
        return NULL;
    }
    return real;
}

static char *resolve_from_interp_dir(const char *name,
                                     const struct dep_list *deps)
{
    char *interp_real;
    char *interp_copy;
    char *interp_dir;
    char path[PATH_MAX];

    if (!deps->interp_path || !deps->interp_path[0]) return NULL;

    interp_real = realpath(deps->interp_path, NULL);
    if (!interp_real) return NULL;

    interp_copy = strdup(interp_real);
    free(interp_real);
    if (!interp_copy) return NULL;

    interp_dir = dirname(interp_copy);
    if (snprintf(path, sizeof(path), "%s/%s", interp_dir, name) >=
        (int)sizeof(path)) {
        free(interp_copy);
        return NULL;
    }
    free(interp_copy);

    return validated_candidate(path, deps);
}

static int musl_arch_from_interp(const char *interp_path, char *arch,
                                 size_t arch_size)
{
    static const char prefix[] = "ld-musl-";
    const char *base;
    const char *suffix;
    size_t len;

    if (!is_musl_interpreter(interp_path) || arch_size == 0)
        return -1;
    base = strrchr(interp_path, '/');
    base = base ? base + 1 : interp_path;
    if (strncmp(base, prefix, sizeof(prefix) - 1) != 0)
        return -1;
    base += sizeof(prefix) - 1;
    suffix = strstr(base, ".so");
    if (!suffix || suffix == base)
        return -1;
    len = (size_t)(suffix - base);
    if (len >= arch_size)
        return -1;
    memcpy(arch, base, len);
    arch[len] = '\0';
    return 0;
}

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
    if (!ldc_cache) {
        pclose(f);
        return;
    }

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
            int new_cap = cap * 2;
            void *new_cache = realloc(ldc_cache,
                                      (size_t)new_cap * sizeof(*ldc_cache));
            if (!new_cache)
                break;
            ldc_cache = new_cache;
            cap = new_cap;
        }
        char *cache_name = strdup(p);
        char *cache_path = strdup(path);
        if (!cache_name || !cache_path) {
            free(cache_name);
            free(cache_path);
            continue;
        }
        ldc_cache[ldc_count].name = cache_name;
        ldc_cache[ldc_count].path = cache_path;
        ldc_count++;
    }
    pclose(f);
}

static char *resolve_from_ldconfig(const char *name,
                                   const struct dep_list *deps)
{
    load_ldconfig_cache();
    for (int i = 0; i < ldc_count; i++)
        if (strcmp(ldc_cache[i].name, name) == 0) {
            char *candidate = validated_candidate(ldc_cache[i].path, deps);

            if (candidate)
                return candidate;
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
    char *new_name = strdup(name);
    char *new_path = strdup(path);
    if (!new_name || !new_path) {
        free(new_name);
        free(new_path);
        return -1;
    }
    deps->libs[deps->count].name        = new_name;
    deps->libs[deps->count].path        = new_path;
    deps->libs[deps->count].from_dlopen = from_dlopen;
    deps->libs[deps->count].dlopen_direct = dlopen_direct;
    deps->count++;
    return 1; /* added */
}

/* ------------------------------------------------------------------ */
/*  $ORIGIN expansion                                                 */
/* ------------------------------------------------------------------ */
static int token_boundary(char value)
{
    return value == '/' || value == ':' || value == '\0';
}

static char *expand_origin(const char *tmpl, const char *origin)
{
    char *buf = malloc(PATH_MAX);
    if (!buf) return NULL;
    char *d = buf, *end = buf + PATH_MAX - 1;
    const char *s = tmpl;
    while (*s && d < end) {
        const char *replacement = NULL;
        size_t consumed = 0;

        if (strncmp(s, "${ORIGIN}", 9) == 0) {
            replacement = origin;
            consumed = 9;
        } else if (strncmp(s, "$ORIGIN", 7) == 0 && token_boundary(s[7])) {
            replacement = origin;
            consumed = 7;
        }

        if (replacement) {
            size_t l = strlen(replacement);
            if (d + l >= end) { free(buf); return NULL; }
            memcpy(d, replacement, l);
            d += l;
            s += consumed;
        } else if (d < end) {
            *d++ = *s++;
        } else {
            free(buf);
            return NULL;
        }
    }
    *d = '\0';
    return buf;
}

/* ------------------------------------------------------------------ */
/*  Library search (RPATH → LD_LIBRARY_PATH → RUNPATH → defaults)     */
/* ------------------------------------------------------------------ */
static char *search_dirs(const char *name, const char *dirs, const char *origin,
                         const struct dep_list *deps)
{
    if (!dirs || !dirs[0]) return NULL;
    const char *start = dirs;
    char path[PATH_MAX];

    for (;;) {
        const char *separator = strchr(start, ':');
        size_t length = separator ? (size_t)(separator - start) : strlen(start);
        char *tok = length ? strndup(start, length) : strdup(".");
        char *expanded = tok ? expand_origin(tok, origin) : NULL;
        char *candidate;

        free(tok);
        if (!expanded)
            goto next;
        if (snprintf(path, sizeof(path), "%s/%s", expanded, name) >=
            (int)sizeof(path)) {
            free(expanded);
            goto next;
        }
        free(expanded);
        candidate = validated_candidate(path, deps);
        if (candidate)
            return candidate;

next:
        if (!separator)
            break;
        start = separator + 1;
    }
    return NULL;
}

static char *resolve_from_musl_path_file(const char *name, const char *origin,
                                         const struct dep_list *deps)
{
    char arch[64];
    char config_path[PATH_MAX];
    char dirs[4096];
    FILE *f;
    size_t len;

    if (musl_arch_from_interp(deps->interp_path, arch, sizeof(arch)) < 0)
        return NULL;
    if (snprintf(config_path, sizeof(config_path), "/etc/ld-musl-%s.path",
                 arch) >= (int)sizeof(config_path))
        return NULL;

    f = fopen(config_path, "r");
    if (!f)
        return NULL;
    len = fread(dirs, 1, sizeof(dirs) - 1, f);
    fclose(f);
    if (len == 0)
        return NULL;
    dirs[len] = '\0';
    for (size_t i = 0; i < len; i++)
        if (dirs[i] == '\n' || dirs[i] == '\r')
            dirs[i] = ':';

    return search_dirs(name, dirs, origin, deps);
}

static char *find_library(const char *name,
                          const char *rpath, const char *runpath,
                          const char *origin, const struct dep_list *deps)
{
    char *p;

    /* A DT_NEEDED name containing a slash is a pathname, not a soname. */
    if (strchr(name, '/'))
        return validated_candidate(name, deps);

    /* 1. RPATH (only when RUNPATH absent) */
    if (rpath && rpath[0] && (!runpath || !runpath[0])) {
        p = search_dirs(name, rpath, origin, deps);
        if (p) return p;
    }

    /* 2. LD_LIBRARY_PATH */
    const char *ldp = getenv("LD_LIBRARY_PATH");
    if (ldp && ldp[0]) {
        p = search_dirs(name, ldp, origin, deps);
        if (p) return p;
    }

    /* 3. RUNPATH */
    if (runpath && runpath[0]) {
        p = search_dirs(name, runpath, origin, deps);
        if (p) return p;
    }

    /* Several libc families keep their runtime DSOs beside the interpreter. */
    p = resolve_from_interp_dir(name, deps);
    if (p) return p;

    /* musl's configured default search path */
    p = resolve_from_musl_path_file(name, origin, deps);
    if (p) return p;

    /* 4. ldconfig cache */
    p = resolve_from_ldconfig(name, deps);
    if (p) return p;

    /* 5. Default paths */
    char path[PATH_MAX];
    for (int i = 0; default_paths[i]; i++) {
        if (snprintf(path, sizeof(path), "%s/%s", default_paths[i], name) >=
            (int)sizeof(path))
            continue;
        p = validated_candidate(path, deps);
        if (p) return p;
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

static int bfs_init(struct bfs_queue *q)
{
    q->cap   = 256;
    q->items = calloc(q->cap, sizeof(char *));
    q->head  = q->tail = 0;
    return q->items ? 0 : -1;
}

static int bfs_push(struct bfs_queue *q, const char *s)
{
    if (q->tail >= q->cap) {
        int new_cap = q->cap * 2;
        char **new_items = realloc(q->items,
                                   (size_t)new_cap * sizeof(char *));
        if (!new_items)
            return -1;
        q->items = new_items;
        q->cap = new_cap;
    }
    q->items[q->tail] = strdup(s);
    if (!q->items[q->tail])
        return -1;
    q->tail++;
    return 0;
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
static int resolve_needed(struct elf_info *info, const char *origin,
                          struct dep_list *deps, struct bfs_queue *q,
                          int dlopen_flag)
{
    for (int i = 0; i < info->needed_count; i++) {
        const char *name = info->needed[i];
        if (is_virtual_lib(name)) continue;

        char *path = find_library(name, info->rpath, info->runpath, origin,
                                  deps);
        if (!path) {
            fprintf(stderr,
                    "dlfreeze: required library not found or incompatible: %s\n",
                    name);
            return -1;
        }
        int added = dep_list_add(deps, name, path, dlopen_flag, 0);
        if (added > 0 && bfs_push(q, path) < 0) {
            free(path);
            return -1;
        }
        free(path);
        if (added < 0)
            return -1;
    }
    return 0;
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
    char *origin  = dir_tmp ? strdup(dirname(dir_tmp)) : NULL;
    free(dir_tmp);
    if (!origin) { free(real); return -1; }

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

    deps->target_ei_class = info.ei_class;
    deps->target_e_machine = info.e_machine;

    if (info.interp[0]) {
        if (!elf_matches_target(info.interp, deps)) {
            fprintf(stderr,
                    "dlfreeze: interpreter is missing, invalid, or incompatible: %s\n",
                    info.interp);
            elf_info_free(&info);
            free(origin); free(real);
            return -1;
        }
        deps->interp_path = strdup(info.interp);
        if (!deps->interp_path) {
            elf_info_free(&info);
            free(origin); free(real);
            return -1;
        }
    }

    struct bfs_queue q;
    if (bfs_init(&q) < 0) {
        elf_info_free(&info);
        free(origin); free(real);
        dep_list_free(deps);
        return -1;
    }

    if (resolve_needed(&info, origin, deps, &q, 0) < 0) {
        elf_info_free(&info);
        bfs_free(&q);
        free(origin); free(real);
        dep_list_free(deps);
        return -1;
    }
    elf_info_free(&info);

    /* BFS: process transitive deps */
    char *lib_path;
    while ((lib_path = bfs_pop(&q))) {
        struct elf_info li;
        if (elf_parse(lib_path, &li) < 0 || !li.is_dynamic ||
            li.ei_class != deps->target_ei_class ||
            li.e_machine != deps->target_e_machine) {
            fprintf(stderr,
                    "dlfreeze: resolved library became invalid or incompatible: %s\n",
                    lib_path);
            elf_info_free(&li);
            free(lib_path);
            bfs_free(&q);
            free(origin); free(real);
            dep_list_free(deps);
            return -1;
        }

        char *dt = strdup(lib_path);
        char *lo = dt ? strdup(dirname(dt)) : NULL;
        if (!dt || !lo || resolve_needed(&li, lo, deps, &q, 0) < 0) {
            free(lo); free(dt);
            elf_info_free(&li);
            free(lib_path);
            bfs_free(&q);
            free(origin); free(real);
            dep_list_free(deps);
            return -1;
        }
        free(lo); free(dt);
        elf_info_free(&li);
        free(lib_path);
    }
    bfs_free(&q);

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
    if (bfs_init(&q) < 0) {
        fclose(f);
        return -1;
    }

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

        if (elf_parse(rp, &info) < 0 || !info.is_dynamic ||
            info.ei_class != deps->target_ei_class ||
            info.e_machine != deps->target_e_machine) {
            elf_info_free(&info);
            free(rp);
            continue;
        }
        name = info.soname[0] ? info.soname : base;

        int added = dep_list_add(deps, name, rp, 1, 1);
        if (added > 0 && bfs_push(&q, rp) < 0) {
            elf_info_free(&info);
            free(rp);
            fclose(f);
            bfs_free(&q);
            return -1;
        }
        elf_info_free(&info);
        free(rp);
        if (added < 0) {
            fclose(f);
            bfs_free(&q);
            return -1;
        }
    }
    fclose(f);

    /* resolve transitive deps of dlopen'd libs */
    char *lib_path;
    while ((lib_path = bfs_pop(&q))) {
        struct elf_info li;
        if (elf_parse(lib_path, &li) < 0 || !li.is_dynamic ||
            li.ei_class != deps->target_ei_class ||
            li.e_machine != deps->target_e_machine) {
            elf_info_free(&li);
            free(lib_path);
            bfs_free(&q);
            return -1;
        }

        char *dt = strdup(lib_path);
        char *lo = dt ? strdup(dirname(dt)) : NULL;
        if (!dt || !lo || resolve_needed(&li, lo, deps, &q, 1) < 0) {
            free(lo); free(dt);
            elf_info_free(&li);
            free(lib_path);
            bfs_free(&q);
            return -1;
        }
        free(lo); free(dt);
        elf_info_free(&li);
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
