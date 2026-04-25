//  Copyright 2026 Omar Roth
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>
#include <sys/wait.h>
#include <fnmatch.h>
#include <sys/stat.h>
#include <dirent.h>

#include "elf_parser.h"
#include "dep_resolver.h"
#include "packer.h"

extern char **environ;

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options] [--] <executable> [args...]\n\n"
        "Options:\n"
        "  -o <path>   Output file  (default: <name>.frozen)\n"
        "  -d          Direct-load mode (in-process loader, no tmpdir)\n"
        "  -t          Trace dlopen calls by running the program\n"
        "  -f <glob>   Embed data files matching glob (requires -t, repeatable)\n"
        "  -v          Verbose\n"
        "  -h          Help\n\n"
        "Examples:\n"
        "  %s /bin/ls\n"
        "  %s -o frozen_ls /bin/ls\n"
        "  %s -t -o frozen_py -- python3 -c 'import json'\n"
        "  %s -d -t -f '/usr/lib/python*' -- python3 -c 'import json'\n",
        prog, prog, prog, prog, prog);
}

/* locate helper binaries next to our own executable */
static char *find_sibling(const char *self, const char *name)
{
    char dir[PATH_MAX];
    strncpy(dir, self, sizeof(dir) - 1); dir[sizeof(dir)-1] = '\0';
    char *sl = strrchr(dir, '/');
    if (sl) *sl = '\0'; else strcpy(dir, ".");

    char path[PATH_MAX];
    const char *tries[] = { "%s/%s", "%s/build/%s", "%s/../lib/dlfreeze/%s", NULL };
    for (int i = 0; tries[i]; i++) {
        snprintf(path, sizeof(path), tries[i], dir, name);
        if (access(path, R_OK) == 0) {
            char *rp = realpath(path, NULL);
            return rp ? rp : strdup(path);
        }
    }
    return NULL;
}

/* resolve a program name via PATH */
static char *resolve_exe(const char *name)
{
    if (strchr(name, '/'))
        return realpath(name, NULL);

    const char *pathenv = getenv("PATH");
    if (!pathenv) return NULL;

    char *copy = strdup(pathenv), *save, *tok;
    char full[PATH_MAX];
    for (tok = strtok_r(copy, ":", &save); tok; tok = strtok_r(NULL, ":", &save)) {
        snprintf(full, sizeof(full), "%s/%s", tok, name);
        if (access(full, X_OK) == 0) { free(copy); return realpath(full, NULL); }
    }
    free(copy);
    return NULL;
}

// Match a path against a glob pattern.  fnmatch's '*' doesn't cross '/',
// but users expect -f '/usr/lib/*' to match anything under /usr/lib/.
// If the pattern ends with "/" + "*", we also do a prefix check so that
// deeply nested paths still match.
static int match_glob(const char *pattern, const char *path)
{
    if (fnmatch(pattern, path, 0) == 0)
        return 1;
    /* Prefix match: pattern ending in dir-slash-star */
    int plen = strlen(pattern);
    if (plen >= 2 && pattern[plen - 1] == '*' && pattern[plen - 2] == '/') {
        if (strncmp(path, pattern, plen - 1) == 0)
            return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Add all regular non-ELF files in a single directory (non-recursive) */
/* to the data-file list, skipping files already in deps.              */
/* ------------------------------------------------------------------ */
static void scan_dir_shallow(const char *dirpath,
                             struct data_file_list *out,
                             const struct dep_list *deps,
                             const char *exe_path)
{
    DIR *d = opendir(dirpath);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.' &&
            (e->d_name[1] == '\0' ||
             (e->d_name[1] == '.' && e->d_name[2] == '\0')))
            continue;
        char child[PATH_MAX];
        snprintf(child, sizeof(child), "%s/%s", dirpath, e->d_name);
        char rpath[PATH_MAX];
        if (!realpath(child, rpath)) continue;

        struct stat sb;
        if (stat(rpath, &sb) != 0) continue;

        /* Subdirectory: add a virtual .dir marker so the VFS dir table
         * will include this subdir in the parent's listing. */
        if (S_ISDIR(sb.st_mode)) {
            char marker[PATH_MAX];
            snprintf(marker, sizeof(marker), "%s/.dir", rpath);
            data_file_list_add_virtual(out, marker);
            continue;
        }

        if (!S_ISREG(sb.st_mode)) continue;

        /* Check if this file is a known dep (exe, interp, or resolved
         * shared lib / dlopen lib).  Known-dep ELF files are served at
         * runtime via frozen_dlopen_serve_memfd; add them as virtual
         * placeholders so VFS directory listings include them without
         * duplicating the payload.  ELF files that are NOT known deps
         * and non-ELF files are embedded as real data. */
        int skip = 0;
        if (!skip && strcmp(rpath, exe_path) == 0) skip = 1;
        if (!skip && deps->interp_path &&
            strcmp(rpath, deps->interp_path) == 0) skip = 1;
        for (int i = 0; !skip && i < deps->count; i++) {
            char dpath[PATH_MAX];
            if (realpath(deps->libs[i].path, dpath) &&
                strcmp(rpath, dpath) == 0)
                skip = 1;
        }

        if (skip) {
            data_file_list_add_virtual(out, rpath);
        } else {
            data_file_list_add(out, rpath);
        }
    }
    closedir(d);
}

/* ------------------------------------------------------------------ */
/* Capture data files opened during a traced run. Prefer the bundled   */
/* LD_PRELOAD tracer and fall back to strace if that helper is absent. */
/* ------------------------------------------------------------------ */
static char *find_traced_open_call(char *line)
{
    static const char *const names[] = {
        "openat2(",
        "openat(",
        "open(",
    };

    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char *p = strstr(line, names[i]);

        if (p)
            return p;
    }
    return NULL;
}

static int dir_matches_patterns(const char *rpath, const char **patterns,
                                int npatterns)
{
    for (int i = 0; i < npatterns; i++) {
        if (match_glob(patterns[i], rpath))
            return 1;

        /* Pattern may only match children of this directory. */
        char probe[PATH_MAX];
        int plen = snprintf(probe, sizeof(probe), "%s/x", rpath);
        if (plen > 0 && plen < (int)sizeof(probe) &&
            match_glob(patterns[i], probe))
            return 1;
    }

    return 0;
}

static int path_is_known_dep(const char *rpath, const char *exe_path,
                             const struct dep_list *deps)
{
    if (strcmp(rpath, exe_path) == 0)
        return 1;
    if (deps->interp_path && strcmp(rpath, deps->interp_path) == 0)
        return 1;

    for (int i = 0; i < deps->count; i++) {
        char dpath[PATH_MAX];

        if (realpath(deps->libs[i].path, dpath) && strcmp(rpath, dpath) == 0)
            return 1;
    }

    return 0;
}

static void add_capture_dir(char ***cap_dirs, int *ncap_dirs, int *cap_dirs_cap,
                            const char *rpath)
{
    for (int i = 0; i < *ncap_dirs; i++)
        if (strcmp((*cap_dirs)[i], rpath) == 0)
            return;

    if (*ncap_dirs >= *cap_dirs_cap) {
        *cap_dirs_cap = *cap_dirs_cap ? *cap_dirs_cap * 2 : 64;
        *cap_dirs = realloc(*cap_dirs, *cap_dirs_cap * sizeof(char *));
    }
    (*cap_dirs)[(*ncap_dirs)++] = strdup(rpath);
}

static void process_captured_path(const char *exe_path, const char **patterns,
                                  int npatterns, struct data_file_list *out,
                                  struct dep_list *deps, const char *rpath,
                                  int is_dir, char ***cap_dirs,
                                  int *ncap_dirs, int *cap_dirs_cap)
{
    struct stat sb;

    if (is_dir) {
        if (stat(rpath, &sb) != 0 || !S_ISDIR(sb.st_mode))
            return;
        if (!dir_matches_patterns(rpath, patterns, npatterns))
            return;

        add_capture_dir(cap_dirs, ncap_dirs, cap_dirs_cap, rpath);
        /* When a __pycache__ directory is captured, also capture its
         * parent package directory so the .py source files alongside
         * the .pyc cache files become available — Python may import
         * sibling submodules via frozen importlib that bypass the
         * trace (e.g. importlib._bootstrap loaded by frozen
         * importlib.machinery). */
        {
            const char *slash = strrchr(rpath, '/');
            if (slash && slash > rpath &&
                strcmp(slash + 1, "__pycache__") == 0) {
                char parent[PATH_MAX];
                size_t plen = (size_t)(slash - rpath);
                if (plen < sizeof(parent)) {
                    memcpy(parent, rpath, plen);
                    parent[plen] = '\0';
                    if (dir_matches_patterns(parent, patterns, npatterns))
                        add_capture_dir(cap_dirs, ncap_dirs,
                                        cap_dirs_cap, parent);
                }
            }
        }
        return;
    }

    if (stat(rpath, &sb) != 0 || !S_ISREG(sb.st_mode))
        return;

    int is_elf = elf_check(rpath);
    if (is_elf && path_is_known_dep(rpath, exe_path, deps)) {
        /* Already captured as a DLOPEN / shlib dep; the frozen_dlopen_serve_memfd
         * path handles probe-opens at runtime.  No separate data entry needed. */
        return;
    }

    if (path_is_known_dep(rpath, exe_path, deps))
        return;

    for (int i = 0; i < npatterns; i++) {
        if (match_glob(patterns[i], rpath)) {
            if (sb.st_size > 0)
                data_file_list_add(out, rpath);
            /* If the captured file lives inside a __pycache__ directory,
             * schedule a shallow scan of both that __pycache__ and its
             * parent package directory.  Frozen importlib can load
             * sibling submodules (e.g. importlib._bootstrap) without
             * the trace ever opening the package dir, so we need to
             * proactively pick up the .py/.pyc siblings. */
            const char *slash = strrchr(rpath, '/');
            if (slash && slash > rpath) {
                char parent[PATH_MAX];
                size_t plen = (size_t)(slash - rpath);
                if (plen < sizeof(parent)) {
                    memcpy(parent, rpath, plen);
                    parent[plen] = '\0';
                    const char *pslash = strrchr(parent, '/');
                    if (pslash && strcmp(pslash + 1, "__pycache__") == 0) {
                        if (dir_matches_patterns(parent, patterns, npatterns))
                            add_capture_dir(cap_dirs, ncap_dirs,
                                            cap_dirs_cap, parent);
                        char gparent[PATH_MAX];
                        size_t gplen = (size_t)(pslash - parent);
                        if (gplen > 0 && gplen < sizeof(gparent)) {
                            memcpy(gparent, parent, gplen);
                            gparent[gplen] = '\0';
                            if (dir_matches_patterns(gparent, patterns,
                                                     npatterns))
                                add_capture_dir(cap_dirs, ncap_dirs,
                                                cap_dirs_cap, gparent);
                        }
                    }
                }
            }
            return;
        }
    }
}

/* Record a path that was probed during execution but did not exist at
 * freeze time.  At runtime the VFS will honour these entries and return
 * ENOENT even if the file has since appeared on the target system. */
static void process_captured_negative_path(const char **patterns, int npatterns,
                                           struct data_file_list *out,
                                           const char *path)
{
    struct stat sb;

    if (!path || path[0] != '/')
        return;
    /* Must genuinely not exist at freeze time */
    if (stat(path, &sb) == 0)
        return;

    for (int i = 0; i < npatterns; i++) {
        if (match_glob(patterns[i], path)) {
            data_file_list_add_negative(out, path);
            return;
        }
    }
}

static void finish_captured_paths(const char *exe_path, struct data_file_list *out,
                                  struct dep_list *deps, int verbose,
                                  char **cap_dirs, int ncap_dirs)
{
    if (ncap_dirs > 0 && verbose) {
        printf("  captured dirs: %d\n", ncap_dirs);
        for (int i = 0; i < ncap_dirs; i++)
            printf("    %s\n", cap_dirs[i]);
    }

    for (int i = 0; i < ncap_dirs; i++) {
        scan_dir_shallow(cap_dirs[i], out, deps, exe_path);
        free(cap_dirs[i]);
    }
    free(cap_dirs);

    if (verbose || out->count > 0) {
        printf("  data files : %d matched\n", out->count);
        if (verbose) {
            for (int i = 0; i < out->count; i++)
                printf("    %s\n", out->paths[i]);
        }
    }
}

static int preload_trace_ready(const char *tracef)
{
    FILE *tf = fopen(tracef, "r");
    char line[128];
    int ready = 0;

    if (!tf)
        return 0;

    if (fgets(line, sizeof(line), tf)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        ready = strcmp(line, "#DLFREEZE_PRELOAD_TRACE_V1") == 0;
    }

    fclose(tf);
    return ready;
}

static int parse_preload_file_trace(const char *tracef, const char *exe_path,
                                    const char **patterns, int npatterns,
                                    struct data_file_list *out,
                                    struct dep_list *deps, int verbose)
{
    FILE *tf = fopen(tracef, "r");
    char **cap_dirs = NULL;
    int ncap_dirs = 0, cap_dirs_cap = 0;
    char line[4096];

    if (!tf)
        return -1;

    while (fgets(line, sizeof(line), tf)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';

        if (len < 3 || line[1] != ' ')
            continue;
        if (line[0] != 'F' && line[0] != 'D' && line[0] != 'N')
            continue;
        if (line[2] != '/')
            continue;

        if (line[0] == 'N') {
              process_captured_negative_path(patterns, npatterns, out, line + 2);
            continue;
        }
        process_captured_path(exe_path, patterns, npatterns, out, deps,
                              line + 2, line[0] == 'D',
                              &cap_dirs, &ncap_dirs, &cap_dirs_cap);
    }

    fclose(tf);
    finish_captured_paths(exe_path, out, deps, verbose, cap_dirs, ncap_dirs);
    return 0;
}

static int parse_strace_file_trace(const char *tracef, const char *exe_path,
                                   const char **patterns, int npatterns,
                                   struct data_file_list *out,
                                   struct dep_list *deps, int verbose,
                                   const char *elf_tracef)
{
    FILE *tf = fopen(tracef, "r");
    FILE *elf_tf = elf_tracef ? fopen(elf_tracef, "a") : NULL;
    char **cap_dirs = NULL;
    int ncap_dirs = 0, cap_dirs_cap = 0;
    char line[4096];

    if (!tf)
        return -1;

    while (fgets(line, sizeof(line), tf)) {
        char *p = find_traced_open_call(line);
        if (!p)
            continue;

        char *eq = strstr(p, ") = ");
        if (!eq)
            continue;

        char *q1 = strchr(p, '"');
        if (!q1)
            continue;
        q1++;
        char *q2 = strchr(q1, '"');
        if (!q2)
            continue;
        *q2 = '\0';

        if (q1[0] != '/')
            continue;

        if (atoi(eq + 4) < 0) {
            /* Failed open: record as negative entry if path matches patterns */
            process_captured_negative_path(patterns, npatterns, out, q1);
            continue;
        }

        {
            char rpath[PATH_MAX];
            int is_dir = (strstr(q2 + 1, "O_DIRECTORY") != NULL);

            if (!realpath(q1, rpath))
                continue;

            if (!is_dir && elf_check(rpath) &&
                !path_is_known_dep(rpath, exe_path, deps)) {
                if (elf_tf)
                    fprintf(elf_tf, "%s\n", rpath);
            }

            process_captured_path(exe_path, patterns, npatterns, out, deps,
                                  rpath, is_dir,
                                  &cap_dirs, &ncap_dirs, &cap_dirs_cap);
        }
    }

    fclose(tf);
    if (elf_tf)
        fclose(elf_tf);
    finish_captured_paths(exe_path, out, deps, verbose, cap_dirs, ncap_dirs);
    return 0;
}

static int capture_data_files(const char *exe_path, int argc, char **argv,
                              int optind_val, const char **patterns,
                              int npatterns, struct data_file_list *out,
                              struct dep_list *deps, int verbose,
                              const char *preload_path)
{
    char tracef[] = "/tmp/dlfreeze-file-trace.XXXXXX";
    char elf_tracef[] = "/tmp/dlfreeze-strace-dlopen.XXXXXX";
    int tfd = mkstemp(tracef);
    if (tfd < 0) { perror("mkstemp"); return -1; }
    close(tfd);

    if (!preload_path) {
        int efd = mkstemp(elf_tracef);
        if (efd < 0) {
            perror("mkstemp");
            unlink(tracef);
            return -1;
        }
        close(efd);
    }

    /* Optional dlopen trace file for combined run */
    char dlopen_tracef[] = "/tmp/dlfreeze-trace.XXXXXX";
    int have_preload = 0;
    if (preload_path) {
        int dtfd = mkstemp(dlopen_tracef);
        if (dtfd >= 0) { close(dtfd); have_preload = 1; }
    }

    printf("Tracing %s …\n",
           have_preload ? "dlopen calls and file access"
                        : "file access");

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork"); unlink(tracef);
        if (have_preload) unlink(dlopen_tracef);
        return -1;
    }

    if (pid == 0) {
        int tstart = optind_val + 1;  /* args after the executable */

        if (have_preload) {
            int nargs = 1 + (argc - tstart);
            char **tav;

            setenv("LD_PRELOAD", preload_path, 1);
            setenv("DLFREEZE_TRACE_FILE", dlopen_tracef, 1);
            setenv("DLFREEZE_FILE_TRACE_FILE", tracef, 1);

            tav = calloc(nargs + 1, sizeof(char *));
            tav[0] = (char *)exe_path;
            for (int i = tstart; i < argc; i++)
                tav[1 + i - tstart] = argv[i];
            tav[nargs] = NULL;
            execve(exe_path, tav, environ);
            _exit(127);
        }

        /* Build: strace -f -e trace=open,openat -o tracefile -- exe [args...] */
        int nargs = 7 + 1 + (argc - tstart) + 1;
        char **sav = calloc(nargs, sizeof(char *));
        int si = 0;
        sav[si++] = "strace";
        sav[si++] = "-f";
        sav[si++] = "-e";
        sav[si++] = "trace=open,openat";
        sav[si++] = "-o";
        sav[si++] = tracef;
        sav[si++] = (char *)exe_path;
        for (int i = tstart; i < argc; i++)
            sav[si++] = argv[i];
        sav[si] = NULL;
        execvp("strace", sav);
        perror("strace");
        _exit(127);
    }

    int st;
    waitpid(pid, &st, 0);
    if (!WIFEXITED(st) || (!have_preload && WEXITSTATUS(st) == 127)) {
        if (have_preload)
            fprintf(stderr, "dlfreeze: traced execution failed\n");
        else
            fprintf(stderr, "dlfreeze: strace failed (is strace installed?)\n");
        unlink(tracef);
        if (!have_preload) unlink(elf_tracef);
        if (have_preload) unlink(dlopen_tracef);
        return -1;
    }

    if (have_preload && !preload_trace_ready(tracef)) {
        fprintf(stderr, "dlfreeze: preload trace helper unavailable in target runtime, falling back to strace\n");
        unlink(tracef);
        unlink(dlopen_tracef);
        return capture_data_files(exe_path, argc, argv, optind_val, patterns,
                                  npatterns, out, deps, verbose, NULL);
    }

    /* Process dlopen trace first so deps is complete when filtering
     * strace output (newly discovered libs get skipped properly). */
    if (have_preload) {
        if (verbose) {
            FILE *dtf = fopen(dlopen_tracef, "r");
            if (dtf) {
                char ln[1024];
                printf("dlopen traced:\n");
                while (fgets(ln, sizeof(ln), dtf))
                    printf("  %s", ln);
                fclose(dtf);
            }
        }
        dep_add_dlopen_libs(deps, dlopen_tracef);
        if (verbose) {
            printf("libraries after trace: %d\n", deps->count);
            for (int i = 0; i < deps->count; i++)
                if (deps->libs[i].from_dlopen)
                    printf("  (dlopen) %-30s → %s\n",
                           deps->libs[i].name, deps->libs[i].path);
        }
        unlink(dlopen_tracef);
    }

    {
        int rc = have_preload
            ? parse_preload_file_trace(tracef, exe_path, patterns, npatterns,
                                       out, deps, verbose)
            : parse_strace_file_trace(tracef, exe_path, patterns, npatterns,
                                      out, deps, verbose, elf_tracef);

        if (!have_preload && rc == 0) {
            dep_add_dlopen_libs(deps, elf_tracef);
            if (verbose) {
                printf("libraries after strace fallback: %d\n", deps->count);
                for (int i = 0; i < deps->count; i++)
                    if (deps->libs[i].from_dlopen)
                        printf("  (dlopen) %-30s → %s\n",
                               deps->libs[i].name, deps->libs[i].path);
            }
        }

        unlink(tracef);
        if (!have_preload) unlink(elf_tracef);
        return rc;
    }
}

/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    const char *out_path = NULL;
    int do_trace = 0, verbose = 0, direct_load = 0;
    const char *file_patterns[64];
    int nfile_patterns = 0;

    int opt;
    while ((opt = getopt(argc, argv, "+o:f:dtvh")) != -1) {
        switch (opt) {
        case 'o': out_path = optarg;  break;
        case 'd': direct_load = 1;   break;
        case 't': do_trace = 1;      break;
        case 'f':
            if (nfile_patterns < 64)
                file_patterns[nfile_patterns++] = optarg;
            break;
        case 'v': verbose  = 1;      break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "dlfreeze: no executable specified\n");
        usage(argv[0]);
        return 1;
    }
    if (nfile_patterns > 0 && !do_trace) {
        fprintf(stderr, "dlfreeze: -f requires -t (tracing mode)\n");
        return 1;
    }

    /* resolve target */
    char *exe_path = resolve_exe(argv[optind]);
    if (!exe_path) {
        fprintf(stderr, "dlfreeze: cannot find: %s\n", argv[optind]);
        return 1;
    }
    if (!elf_check(exe_path)) {
        fprintf(stderr, "dlfreeze: not an ELF: %s\n", exe_path);
        free(exe_path); return 1;
    }

    /* locate our helper binaries */
    char self[PATH_MAX];
    ssize_t slen = readlink("/proc/self/exe", self, sizeof(self)-1);
    if (slen < 0) { perror("readlink"); free(exe_path); return 1; }
    self[slen] = '\0';

    char *bootstrap = find_sibling(self, "dlfreeze-bootstrap");
    if (!bootstrap) {
        fprintf(stderr, "dlfreeze: cannot find dlfreeze-bootstrap\n");
        free(exe_path); return 1;
    }

    if (verbose)
        printf("target    : %s\nbootstrap : %s\n", exe_path, bootstrap);

    /* resolve dependencies */
    printf("Resolving dependencies for %s …\n", exe_path);
    struct dep_list deps;
    if (dep_resolve(exe_path, &deps) < 0) {
        free(exe_path); free(bootstrap); return 1;
    }

    if (verbose) {
        printf("interpreter: %s\n", deps.interp_path ? deps.interp_path : "(none)");
        printf("libraries  : %d\n", deps.count);
        for (int i = 0; i < deps.count; i++)
            printf("  %-30s → %s%s\n", deps.libs[i].name, deps.libs[i].path,
                   deps.libs[i].from_dlopen ? " (dlopen)" : "");
    }

    /* optional tracing: dlopen + data-file capture in one run when possible */
    struct data_file_list data_files;
    data_file_list_init(&data_files);
    if (do_trace) {
        char *preload = find_sibling(self, "dlfreeze-preload.so");
        if (!preload)
            fprintf(stderr, "dlfreeze: warning: dlfreeze-preload.so not found, "
                    "skipping dlopen trace\n");

        if (nfile_patterns > 0) {
            int trace_rc;

            trace_rc = capture_data_files(exe_path, argc, argv, optind,
                                          file_patterns, nfile_patterns,
                                          &data_files, &deps, verbose, preload);
            free(preload);
            if (trace_rc < 0) {
                data_file_list_free(&data_files);
                dep_list_free(&deps);
                free(exe_path);
                free(bootstrap);
                return 1;
            }
            preload = NULL;
        } else if (preload) {
            /* dlopen-only tracing (no -f patterns, no strace needed) */
            char tracef[] = "/tmp/dlfreeze-trace.XXXXXX";
            int tfd = mkstemp(tracef);
            if (tfd >= 0) {
                close(tfd);
                printf("Tracing dlopen calls …\n");

                pid_t pid = fork();
                if (pid == 0) {
                    setenv("LD_PRELOAD", preload, 1);
                    setenv("DLFREEZE_TRACE_FILE", tracef, 1);

                    int tstart = optind + 1;  /* args after the executable */
                    int nargs = 1 + (argc - tstart);
                    char **tav = calloc(nargs + 1, sizeof(char *));
                    tav[0] = exe_path;
                    for (int i = tstart; i < argc; i++)
                        tav[1 + i - tstart] = argv[i];
                    tav[nargs] = NULL;
                    execve(exe_path, tav, environ);
                    _exit(127);
                }
                if (pid > 0) {
                    int st;
                    waitpid(pid, &st, 0);
                    if (verbose)
                        printf("trace exit status: %d\n",
                               WIFEXITED(st) ? WEXITSTATUS(st) : -1);
                    if (verbose) {
                        FILE *tf = fopen(tracef, "r");
                        if (tf) {
                            char ln[1024];
                            printf("traced:\n");
                            while (fgets(ln, sizeof(ln), tf))
                                printf("  %s", ln);
                            fclose(tf);
                        }
                    }
                    dep_add_dlopen_libs(&deps, tracef);
                    if (verbose) {
                        printf("libraries after trace: %d\n", deps.count);
                        for (int i = 0; i < deps.count; i++)
                            if (deps.libs[i].from_dlopen)
                                printf("  (dlopen) %-30s → %s\n",
                                       deps.libs[i].name, deps.libs[i].path);
                    }
                }
                unlink(tracef);
            }
        }
        free(preload);
    }

    /* output path */
    char outbuf[PATH_MAX];
    if (!out_path) {
        const char *b = strrchr(exe_path, '/');
        b = b ? b + 1 : exe_path;
        snprintf(outbuf, sizeof(outbuf), "%s.frozen", b);
        out_path = outbuf;
    }

    /* pack */
    int nfiles = deps.count + 2 + data_files.count;
    printf("Packing %d files into %s …\n", nfiles, out_path);
    struct pack_options po = {
        .exe_path       = exe_path,
        .output_path    = out_path,
        .bootstrap_path = bootstrap,
        .deps           = &deps,
        .direct_load    = direct_load,
        .data_files     = data_files.count > 0 ? &data_files : NULL,
    };
    int rc = pack_frozen(&po);

    data_file_list_free(&data_files);
    dep_list_free(&deps);
    free(exe_path);
    free(bootstrap);
    return rc < 0 ? 1 : 0;
}
