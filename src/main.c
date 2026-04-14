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

        /* Check if this file should be skipped (ELF, dep, exe).
         * Skipped files are still added as virtual entries (zero-byte,
         * listed by VFS readdir but not served from embedded data).
         * Real empty files are preserved so the VFS can serve them. */
        int skip = 0;
        if (!skip && elf_check(rpath)) skip = 1;
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
/* Capture data files opened during a traced run using strace.         */
/* Runs: strace -f -e trace=open,openat,openat2 -o <tracefile>         */
/*       <exe> [args...]                                               */
/* Then parses the output for successfully opened regular files and     */
/* filters them against the glob patterns.                             */
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

static int capture_data_files(const char *exe_path, int argc, char **argv,
                              int optind_val, const char **patterns,
                              int npatterns, struct data_file_list *out,
                              struct dep_list *deps, int verbose,
                              const char *preload_path)
{
    char tracef[] = "/tmp/dlfreeze-strace.XXXXXX";
    int tfd = mkstemp(tracef);
    if (tfd < 0) { perror("mkstemp"); return -1; }
    close(tfd);

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
        /* Set LD_PRELOAD for combined dlopen tracing */
        if (have_preload) {
            setenv("LD_PRELOAD", preload_path, 1);
            setenv("DLFREEZE_TRACE_FILE", dlopen_tracef, 1);
        }

        /* Build: strace -f -e trace=open,openat,openat2 -o tracefile -- exe [args...] */
        int tstart = optind_val + 1;  /* args after the executable */

        int nargs = 7 + 1 + (argc - tstart) + 1;
        char **sav = calloc(nargs, sizeof(char *));
        int si = 0;
        sav[si++] = "strace";
        sav[si++] = "-f";
        sav[si++] = "-e";
        sav[si++] = "trace=open,openat,openat2";
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
    if (!WIFEXITED(st) || WEXITSTATUS(st) == 127) {
        fprintf(stderr, "dlfreeze: strace failed (is strace installed?)\n");
        unlink(tracef);
        if (have_preload) unlink(dlopen_tracef);
        return -1;
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

    /* Parse strace output for open/openat/openat2 calls that returned a
     * valid fd. Formats:
     *   PID open("/path/file", O_RDONLY...) = 3
     *   PID openat(AT_FDCWD, "/path/file", O_RDONLY...) = 3
     *   PID openat2(AT_FDCWD, "/path/file", {...}) = 3
     *
     * Two kinds of captures:
     * 1. Regular files matching -f patterns → add to data files.
     * 2. O_DIRECTORY opens on dirs matching -f patterns → recursively
     *    capture ALL regular non-ELF files in that directory tree so the
     *    VFS can serve complete directory listings without hitting disk. */
    FILE *tf = fopen(tracef, "r");
    if (!tf) { unlink(tracef); return -1; }

    /* Collect directories to scan (deferred so we can close the file) */
    char **cap_dirs = NULL;
    int ncap_dirs = 0, cap_dirs_cap = 0;

    char line[4096];
    while (fgets(line, sizeof(line), tf)) {
        /* Must contain an open-like syscall and end with a valid fd (not -1) */
        char *p = find_traced_open_call(line);
        if (!p) continue;

        /* Find the return value: ") = N" at the end */
        char *eq = strstr(p, ") = ");
        if (!eq) continue;
        int retval = atoi(eq + 4);
        if (retval < 0) continue;  /* failed open */

        /* Extract path: first quoted string in open/openat/openat2 */
        char *q1 = strchr(p, '"');
        if (!q1) continue;
        q1++;
        char *q2 = strchr(q1, '"');
        if (!q2) continue;
        *q2 = '\0';

        /* Check for O_DIRECTORY flag (text after the closing quote) */
        int is_dir = (strstr(q2 + 1, "O_DIRECTORY") != NULL);

        /* Resolve to absolute path */
        char rpath[PATH_MAX];
        if (q1[0] != '/') continue;  /* skip relative paths */
        if (!realpath(q1, rpath)) continue;  /* skip deleted/inaccessible */

        if (is_dir) {
            /* Directory open — check if it matches a glob pattern */
            struct stat sb;
            if (stat(rpath, &sb) != 0 || !S_ISDIR(sb.st_mode)) continue;

            int matched = 0;
            for (int i = 0; i < npatterns; i++) {
                if (match_glob(patterns[i], rpath)) {
                    matched = 1; break;
                }
                /* Also match if the pattern covers children of this dir,
                   e.g. pattern '/usr/lib/X' matches '/usr/lib/python3.14' */
                char probe[PATH_MAX];
                int plen = snprintf(probe, sizeof(probe), "%s/x", rpath);
                if (plen > 0 && plen < (int)sizeof(probe) &&
                    match_glob(patterns[i], probe)) {
                    matched = 1; break;
                }
            }
            if (!matched) continue;

            /* Deduplicate */
            int dup = 0;
            for (int i = 0; i < ncap_dirs; i++)
                if (strcmp(cap_dirs[i], rpath) == 0) { dup = 1; break; }
            if (dup) continue;

            if (ncap_dirs >= cap_dirs_cap) {
                cap_dirs_cap = cap_dirs_cap ? cap_dirs_cap * 2 : 64;
                cap_dirs = realloc(cap_dirs, cap_dirs_cap * sizeof(char *));
            }
            cap_dirs[ncap_dirs++] = strdup(rpath);
            continue;
        }

        /* Regular file */
        struct stat sb;
        if (stat(rpath, &sb) != 0 || !S_ISREG(sb.st_mode)) continue;

        /* Skip ELF files (these are already handled as shared libs) */
        if (elf_check(rpath)) continue;

        /* Skip the executable itself */
        if (strcmp(rpath, exe_path) == 0) continue;

        /* Skip files already in deps */
        int skip = 0;
        if (deps->interp_path && strcmp(rpath, deps->interp_path) == 0)
            skip = 1;
        for (int i = 0; !skip && i < deps->count; i++) {
            char dpath[PATH_MAX];
            if (realpath(deps->libs[i].path, dpath) && strcmp(rpath, dpath) == 0)
                skip = 1;
        }
        if (skip) continue;

        /* Check against glob patterns */
        int matched = 0;
        for (int i = 0; i < npatterns; i++) {
            if (match_glob(patterns[i], rpath)) {
                matched = 1;
                break;
            }
        }
        if (!matched) continue;

        /* Skip empty files */
        if (sb.st_size == 0) continue;

        data_file_list_add(out, rpath);
    }

    fclose(tf);
    unlink(tracef);

    /* Scan captured directories — adds all non-ELF regular files */
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
    return 0;
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
            /* Combined: strace captures file access while LD_PRELOAD
             * captures dlopen calls — single program execution. */
            capture_data_files(exe_path, argc, argv, optind,
                               file_patterns, nfile_patterns,
                               &data_files, &deps, verbose, preload);
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
