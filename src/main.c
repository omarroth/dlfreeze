//   Copyright 2026 Omar Roth
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>
#include <sys/wait.h>

#include "elf_parser.h"
#include "dep_resolver.h"
#include "packer.h"

extern char **environ;

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options] <executable> [-- trace-args...]\n\n"
        "Options:\n"
        "  -o <path>   Output file  (default: <name>.frozen)\n"
        "  -d          Direct-load mode (in-process loader, no tmpdir)\n"
        "  -t          Trace dlopen calls by running the program\n"
        "  -v          Verbose\n"
        "  -h          Help\n\n"
        "Examples:\n"
        "  %s /bin/ls\n"
        "  %s -o frozen_ls /bin/ls\n"
        "  %s -t -o frozen_py python3 -- -c 'import json'\n",
        prog, prog, prog, prog);
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

/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    const char *out_path = NULL;
    int do_trace = 0, verbose = 0, direct_load = 0;

    int opt;
    while ((opt = getopt(argc, argv, "+o:dtvh")) != -1) {
        switch (opt) {
        case 'o': out_path = optarg;  break;
        case 'd': direct_load = 1;   break;
        case 't': do_trace = 1;      break;
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

    /* optional dlopen tracing */
    if (do_trace) {
        char *preload = find_sibling(self, "dlfreeze-preload.so");
        if (!preload) {
            fprintf(stderr, "dlfreeze: warning: dlfreeze-preload.so not found, skipping trace\n");
        } else {
            char tracef[] = "/tmp/dlfreeze-trace.XXXXXX";
            int tfd = mkstemp(tracef);
            if (tfd >= 0) {
                close(tfd);
                printf("Tracing dlopen calls …\n");

                pid_t pid = fork();
                if (pid == 0) {
                    setenv("LD_PRELOAD", preload, 1);
                    setenv("DLFREEZE_TRACE_FILE", tracef, 1);

                    /* build argv: exe + everything after "--" separator */
                    int tstart = optind + 1;
                    if (tstart < argc && strcmp(argv[tstart], "--") == 0)
                        tstart++;   /* skip the "--" separator */
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
                    /* Show trace contents before processing */
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
            free(preload);
        }
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
    printf("Packing %d files into %s …\n", deps.count + 2, out_path);
    struct pack_options po = {
        .exe_path       = exe_path,
        .output_path    = out_path,
        .bootstrap_path = bootstrap,
        .deps           = &deps,
        .direct_load    = direct_load,
    };
    int rc = pack_frozen(&po);

    dep_list_free(&deps);
    free(exe_path);
    free(bootstrap);
    return rc < 0 ? 1 : 0;
}
