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
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

#include "elf_parser.h"
#include "dep_resolver.h"
#include "packer.h"

extern char **environ;

/* A traced target shares dlfreeze's foreground process group so terminal
 * input and job control behave as they do when the target is run directly.
 * Keep the packer alive for terminal-generated signals that the target has
 * already received, while still forwarding process-directed signals sent to
 * the packer itself. */
static volatile sig_atomic_t g_trace_child = -1;

static const int g_trace_forward_signals[] = {
    SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2,
    SIGPIPE, SIGALRM, SIGCONT, SIGTSTP, SIGTTIN, SIGTTOU
};

#define TRACE_FORWARD_SIGNAL_COUNT \
    (sizeof(g_trace_forward_signals) / \
     sizeof(g_trace_forward_signals[0]))

static void trace_forward_signal(int sig, siginfo_t *info, void *context)
{
    int saved_errno = errno;

    (void)context;

    /* The terminal driver targets the entire foreground process group, so a
     * SI_KERNEL signal has already reached the trace child. */
    if (g_trace_child > 0 && (!info || info->si_code != SI_KERNEL))
        kill(g_trace_child, sig);
    errno = saved_errno;
}

static void build_trace_signal_set(sigset_t *set)
{
    sigemptyset(set);
    for (size_t i = 0; i < TRACE_FORWARD_SIGNAL_COUNT; i++)
        sigaddset(set, g_trace_forward_signals[i]);
}

static int install_trace_signal_handlers(struct sigaction *old_actions)
{
    struct sigaction action;
    size_t installed = 0;

    memset(&action, 0, sizeof(action));
    action.sa_sigaction = trace_forward_signal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_RESTART | SA_SIGINFO;

    for (; installed < TRACE_FORWARD_SIGNAL_COUNT; installed++) {
        if (sigaction(g_trace_forward_signals[installed], &action,
                      &old_actions[installed]) < 0)
            break;
    }
    if (installed == TRACE_FORWARD_SIGNAL_COUNT)
        return 0;
    while (installed > 0) {
        installed--;
        sigaction(g_trace_forward_signals[installed],
                  &old_actions[installed], NULL);
    }
    return -1;
}

static void restore_trace_signal_handlers(
    const struct sigaction *old_actions)
{
    for (size_t i = 0; i < TRACE_FORWARD_SIGNAL_COUNT; i++)
        sigaction(g_trace_forward_signals[i], &old_actions[i], NULL);
}

static int supervise_trace_child(pid_t child, const sigset_t *forward_set,
                                 const sigset_t *old_mask, int *status_out)
{
    struct sigaction old_actions[TRACE_FORWARD_SIGNAL_COUNT];
    int wait_failed = 0;

    g_trace_child = child;
    if (install_trace_signal_handlers(old_actions) < 0) {
        int saved_errno = errno;

        sigprocmask(SIG_SETMASK, old_mask, NULL);
        kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
        g_trace_child = -1;
        errno = saved_errno;
        return -1;
    }
    if (sigprocmask(SIG_SETMASK, old_mask, NULL) < 0) {
        int saved_errno = errno;

        kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
        g_trace_child = -1;
        restore_trace_signal_handlers(old_actions);
        errno = saved_errno;
        return -1;
    }

    for (;;) {
        int status;
        pid_t waited = waitpid(child, &status, WUNTRACED | WCONTINUED);

        if (waited < 0) {
            if (errno == EINTR)
                continue;
            wait_failed = 1;
            break;
        }
        if (WIFSTOPPED(status)) {
            if (kill(getpid(), SIGSTOP) < 0) {
                wait_failed = 1;
                break;
            }
            continue;
        }
        if (WIFCONTINUED(status))
            continue;
        *status_out = status;
        break;
    }

    if (wait_failed) {
        (void)kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
    }

    {
        int saved_errno = errno;

        sigprocmask(SIG_BLOCK, forward_set, NULL);
        g_trace_child = -1;
        restore_trace_signal_handlers(old_actions);
        sigprocmask(SIG_SETMASK, old_mask, NULL);
        errno = saved_errno;
    }
    return wait_failed ? -1 : 0;
}

static int prepend_ld_preload(const char *preload)
{
    const char *old = getenv("LD_PRELOAD");
    size_t preload_len = strlen(preload);
    size_t old_len = old && old[0] ? strlen(old) : 0;
    size_t value_len;
    char *value;
    int rc;

    if (old_len) {
        if (old_len > SIZE_MAX - 2 ||
            preload_len > SIZE_MAX - old_len - 2) {
            errno = EOVERFLOW;
            return -1;
        }
        value_len = preload_len + old_len + 2;
    } else {
        if (preload_len == SIZE_MAX) {
            errno = EOVERFLOW;
            return -1;
        }
        value_len = preload_len + 1;
    }
    value = malloc(value_len);
    if (!value)
        return -1;
    memcpy(value, preload, preload_len);
    if (old_len) {
        value[preload_len] = ':';
        memcpy(value + preload_len + 1, old, old_len + 1);
    } else {
        value[preload_len] = '\0';
    }
    rc = setenv("LD_PRELOAD", value, 1);
    free(value);
    return rc;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options] [--] <executable> [args...]\n\n"
        "Options:\n"
        "  -o <path>   Output file  (default: <name>.frozen)\n"
        "  -d          Direct-load mode (in-process loader, no tmpdir)\n"
        "  -t          Trace runtime loading by running the program (TTY preserved)\n"
        "  -f <glob>   Embed data files matching glob (requires -d -t, repeatable)\n"
        "  -v          Verbose\n"
        "  -h          Help\n\n"
        "Examples:\n"
        "  %s /bin/ls\n"
        "  %s -o frozen_ls /bin/ls\n"
        "  %s -t -o frozen_app -- myapp --load-plugins\n"
        "  %s -d -t -f '/usr/share/myapp/*' -- myapp --self-test\n",
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
        int len = snprintf(path, sizeof(path), tries[i], dir, name);

        if (len < 0 || (size_t)len >= sizeof(path))
            continue;
        if (access(path, R_OK) == 0) {
            char *rp = realpath(path, NULL);
            return rp ? rp : strdup(path);
        }
    }
    return NULL;
}

static char *target_interp_soname(const struct dep_list *deps)
{
    if (!deps || !deps->interp_soname || !deps->interp_soname[0])
        return NULL;
    return strdup(deps->interp_soname);
}

static int resolved_snapshot_matches_stat(
    const struct dep_file_snapshot *snapshot, const struct stat *st)
{
    return snapshot && snapshot->valid && st &&
           snapshot->device == st->st_dev &&
           snapshot->inode == st->st_ino &&
           snapshot->size == st->st_size &&
           snapshot->mtime_sec == st->st_mtim.tv_sec &&
           snapshot->mtime_nsec == st->st_mtim.tv_nsec &&
           snapshot->ctime_sec == st->st_ctim.tv_sec &&
           snapshot->ctime_nsec == st->st_ctim.tv_nsec;
}

/* A resolved_lib.name is the exact DT_NEEDED lookup identity and may contain
 * a slash.  Helper ABI selection also needs the provider's ELF identity, so
 * admit an exact DT_SONAME without inferring anything from a pathname.  Parse
 * the same snapshotted file revision the resolver admitted; a replacement
 * between resolution and tracing is an error, not a host-runtime fallback. */
static int resolved_lib_soname_matches(const struct resolved_lib *lib,
                                       const char *soname)
{
    struct elf_info info = {0};
    struct stat before;
    struct stat after;
    int fd;
    int matches = -1;

    if (!lib || !lib->path || !soname || !soname[0] ||
        !lib->snapshot.valid)
        return -1;
    fd = open(lib->path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (fstat(fd, &before) < 0 ||
        !resolved_snapshot_matches_stat(&lib->snapshot, &before) ||
        elf_parse_fd(fd, &info) < 0 ||
        fstat(fd, &after) < 0 ||
        !resolved_snapshot_matches_stat(&lib->snapshot, &after))
        goto out;
    matches = info.soname && strcmp(info.soname, soname) == 0;

out:
    elf_info_free(&info);
    close(fd);
    return matches;
}

static int target_runtime_has_soname(const struct dep_list *deps,
                                     const char *interp_soname,
                                     const char *soname)
{
    if (!deps || !soname || !soname[0])
        return 0;
    if (interp_soname && interp_soname[0] &&
        strcmp(interp_soname, soname) == 0)
        return 1;
    for (int i = 0; i < deps->count; i++) {
        int structural_match;

        if (deps->libs[i].name &&
            strcmp(deps->libs[i].name, soname) == 0)
            return 1;
        structural_match = resolved_lib_soname_matches(
            &deps->libs[i], soname);
        if (structural_match != 0)
            return structural_match;
    }
    return 0;
}

static int paths_name_same_file(const char *left, const char *right)
{
    struct stat left_stat;
    struct stat right_stat;

    if (strcmp(left, right) == 0)
        return 1;
    return stat(left, &left_stat) == 0 && stat(right, &right_stat) == 0 &&
           left_stat.st_dev == right_stat.st_dev &&
           left_stat.st_ino == right_stat.st_ino;
}

static int target_provider_add(const char **provider, const char *candidate)
{
    if (!candidate || !candidate[0])
        return 0;
    if (!*provider) {
        *provider = candidate;
        return 0;
    }
    return paths_name_same_file(*provider, candidate) ? 0 : -1;
}

/* Resolve a DT_VERNEED provider only through the already-selected target
 * interpreter/dependency closure.  Searching the packer's own filesystem
 * here could validate a host DSO instead of the runtime that will load the
 * helper.  Multiple distinct providers for one name are ambiguous and fail
 * closed. */
static int target_runtime_provider(const struct dep_list *deps,
                                   const char *interp_soname,
                                   const char *name,
                                   const char **path_out)
{
    const char *provider = NULL;

    if (!deps || !name || !name[0] || !path_out)
        return -1;
    if (deps->interp_path && interp_soname &&
        strcmp(interp_soname, name) == 0) {
        if (target_provider_add(&provider, deps->interp_path) < 0)
            return -1;
    }
    for (int i = 0; i < deps->count; i++) {
        int structural_match;

        if (deps->libs[i].name && strcmp(deps->libs[i].name, name) == 0) {
            structural_match = 1;
        } else {
            structural_match = resolved_lib_soname_matches(
                &deps->libs[i], name);
        }
        if (structural_match < 0)
            return -1;
        if (!structural_match)
            continue;
        if (target_provider_add(&provider, deps->libs[i].path) < 0)
            return -1;
    }
    if (!provider)
        return 0;
    *path_out = provider;
    return 1;
}

static int preload_versions_compatible(const char *helper_path,
                                       const struct elf_info *helper,
                                       struct dep_list *deps,
                                       const char *interp_soname)
{
    /* musl resolves relocations by symbol name and does not validate
     * DT_VERNEED/DT_VERDEF names.  Its Versym handling only excludes hidden
     * provider definitions.  The metadata was still parsed and bounded by
     * elf_parse(); no compatibility rejection is needed for this ABI. */
    if (deps->runtime_family == DEP_RUNTIME_MUSL)
        return 1;

    for (size_t i = 0; i < helper->version_requirement_count; i++) {
        const char *name = helper->version_requirements[i].file;
        const char *provider_path = NULL;
        char *aux_provider = NULL;
        struct elf_info provider;
        int resolved;
        int matches;

        /* One check covers every requirement in this VERNEED group. */
        for (size_t j = 0; j < i; j++)
            if (strcmp(helper->version_requirements[j].file, name) == 0)
                goto already_checked;

        resolved = target_runtime_provider(deps, interp_soname, name,
                                           &provider_path);
        if (resolved == 0) {
            resolved = dep_resolve_aux_dependency(
                deps, helper_path, name, &aux_provider);
            provider_path = aux_provider;
        }
        if (resolved != 1 || elf_parse(provider_path, &provider) < 0) {
            free(aux_provider);
            return 0;
        }
        matches = elf_version_requirements_match(helper, name, &provider);
        elf_info_free(&provider);
        free(aux_provider);
        if (!matches)
            return 0;

already_checked:
        ;
    }
    return 1;
}

/* Rank preload DSOs by ELF ABI and runtime identity, rather than compiler
 * names, libc path spelling, or application name.  A helper may legitimately
 * add unversioned dependencies which are not in the target's startup closure,
 * but every versioned dependency must match the selected target provider.
 * At least one DT_NEEDED runtime identity is required for a non-neutral
 * helper; a dependency-free helper remains a valid fallback. */
static int preload_target_score(const char *path, struct dep_list *deps,
                                const char *interp_soname)
{
    struct elf_info info;
    int score = -1;

    if (elf_parse(path, &info) < 0)
        return -1;
    if (!info.is_dynamic || !info.is_pie ||
        (info.interp && info.interp[0]) ||
        info.ei_class != deps->target_ei_class ||
        info.e_machine != deps->target_e_machine ||
        !preload_versions_compatible(path, &info, deps, interp_soname))
        goto out;

    score = 0;
    for (int i = 0; i < info.needed_count; i++) {
        int runtime_match = target_runtime_has_soname(
            deps, interp_soname, info.needed[i]);

        if (runtime_match < 0) {
            score = -1;
            goto out;
        }
        if (runtime_match > 0)
            score++;
    }

    /* A non-neutral helper with no shared runtime identity is incompatible. */
    if (info.needed_count > 0 && score == 0)
        score = -1;

out:
    elf_info_free(&info);
    return score;
}

static char *find_compatible_preload(const char *self,
                                     struct dep_list *deps,
                                     int verbose)
{
    static const char *const candidates[] = {
        "dlfreeze-preload.so",
        "dlfreeze-preload-static.so",
    };
    char *interp_soname;
    char *best = NULL;
    int best_score = -1;

    interp_soname = target_interp_soname(deps);

    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        char *path = find_sibling(self, candidates[i]);
        int score;

        if (!path)
            continue;
        score = preload_target_score(path, deps, interp_soname);
        if (score < 0) {
            if (verbose)
                printf("trace helper rejected: %s (target ABI mismatch)\n",
                       path);
            free(path);
            continue;
        }
        if (verbose)
            printf("trace helper candidate: %s (runtime score %d)\n",
                   path, score);
        if (score > best_score) {
            free(best);
            best = path;
            best_score = score;
        } else {
            free(path);
        }
    }
    if (verbose && best)
        printf("trace helper: %s\n", best);
    free(interp_soname);
    return best;
}

/* resolve a program name via PATH */
static char *resolve_executable_candidate(const char *path)
{
    struct stat st;
    char *resolved;

    if (!path || access(path, X_OK) < 0)
        return NULL;
    resolved = realpath(path, NULL);
    if (!resolved)
        return NULL;
    if (stat(resolved, &st) < 0 || !S_ISREG(st.st_mode) ||
        access(resolved, X_OK) < 0) {
        free(resolved);
        return NULL;
    }
    return resolved;
}

static char *resolve_exe(const char *name)
{
    const char *pathenv;
    const char *start;
    char *default_path = NULL;
    char *result = NULL;

    if (!name || !name[0])
        return NULL;
    if (strchr(name, '/'))
        return resolve_executable_candidate(name);

    pathenv = getenv("PATH");
    if (!pathenv) {
        size_t size = confstr(_CS_PATH, NULL, 0);

        if (size == 0 || !(default_path = malloc(size)) ||
            confstr(_CS_PATH, default_path, size) == 0) {
            free(default_path);
            return NULL;
        }
        pathenv = default_path;
    }

    /* Empty PATH components mean the current directory.  strtok_r() drops
     * those components and can therefore resolve a different executable
     * than execvp(3). */
    start = pathenv;
    for (;;) {
        const char *separator = strchr(start, ':');
        size_t dir_len = separator ? (size_t)(separator - start)
                                   : strlen(start);
        char full[PATH_MAX];
        int len;

        if (dir_len == 0)
            len = snprintf(full, sizeof(full), "./%s", name);
        else if (dir_len <= INT_MAX)
            len = snprintf(full, sizeof(full), "%.*s/%s", (int)dir_len,
                           start, name);
        else
            len = -1;
        if (len >= 0 && (size_t)len < sizeof(full) &&
            (result = resolve_executable_candidate(full)) != NULL) {
            free(default_path);
            return result;
        }
        if (!separator)
            break;
        start = separator + 1;
    }
    free(default_path);
    return NULL;
}

static int match_glob(const char *pattern, const char *path)
{
    /* Without FNM_PATHNAME, '*' intentionally spans directory separators. */
    return fnmatch(pattern, path, 0) == 0;
}

/* ------------------------------------------------------------------ */
/* Capture data files opened during a traced run with the same preload */
/* helper that records exact dlopen requests.                           */
/* ------------------------------------------------------------------ */
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

static void process_captured_path(const char *exe_path, const char **patterns,
                                  int npatterns, struct data_file_list *out,
                                  struct dep_list *deps,
                                  const char *request_path,
                                  const char *source_path, int is_dir)
{
    struct stat sb;

    if (is_dir) {
        if (stat(source_path, &sb) != 0 || !S_ISDIR(sb.st_mode))
            return;
        if (!dir_matches_patterns(request_path, patterns, npatterns))
            return;

        /* Preserve successful directory probes without bulk-pulling contents;
         * traced file probes carry per-child existence semantics. */
        data_file_list_add_directory(out, request_path);
        return;
    }

    if (stat(source_path, &sb) != 0 || !S_ISREG(sb.st_mode))
        return;

    int is_elf = elf_check(source_path);
    if (is_elf && strcmp(request_path, source_path) == 0 &&
        path_is_known_dep(source_path, exe_path, deps)) {
        /* Already captured as a DLOPEN / shlib dep; the frozen_dlopen_serve_memfd
         * path handles probe-opens at runtime.  No separate data entry needed. */
        return;
    }

    if (strcmp(request_path, source_path) == 0 &&
        path_is_known_dep(source_path, exe_path, deps))
        return;

    for (int i = 0; i < npatterns; i++) {
        if (match_glob(patterns[i], request_path)) {
            data_file_list_add(out, request_path, source_path);
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

static void finish_captured_paths(struct data_file_list *out, int verbose)
{
    if (verbose || out->count > 0) {
        printf("  data files : %d matched\n", out->count);
        if (verbose) {
            for (int i = 0; i < out->count; i++) {
                printf("    %s", out->paths[i]);
                if (out->source_paths[i] &&
                    strcmp(out->paths[i], out->source_paths[i]) != 0)
                    printf(" <- %s", out->source_paths[i]);
                putchar('\n');
            }
        }
    }
}

static int file_trace_hex_value(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

static int file_trace_hex_decode(const char *hex, size_t hex_len,
                                 char *out, size_t out_size)
{
    if (hex_len == 0 || (hex_len & 1) != 0 || hex_len / 2 >= out_size)
        return -1;
    for (size_t i = 0; i < hex_len; i += 2) {
        int hi = file_trace_hex_value(hex[i]);
        int lo = file_trace_hex_value(hex[i + 1]);

        if (hi < 0 || lo < 0 || (hi == 0 && lo == 0))
            return -1;
        out[i / 2] = (char)((hi << 4) | lo);
    }
    out[hex_len / 2] = '\0';
    return 0;
}

static int trace_file_has_header(const char *tracef, const char *expected)
{
    FILE *tf = fopen(tracef, "r");
    char line[128];
    int ready = 0;
    int read_failed;

    if (!tf)
        return 0;

    if (fgets(line, sizeof(line), tf)) {
        size_t len = strlen(line);

        if (len > 0 && line[len - 1] == '\n') {
            line[--len] = '\0';
            ready = (len == 0 || line[len - 1] != '\r') &&
                    strcmp(line, expected) == 0;
        }
    }
    read_failed = ferror(tf);
    if (fclose(tf) != 0 || read_failed)
        ready = 0;
    return ready;
}

static int parse_preload_file_trace(const char *tracef, const char *exe_path,
                                    const char **patterns, int npatterns,
                                    struct data_file_list *out,
                                    struct dep_list *deps, int verbose)
{
    FILE *tf = fopen(tracef, "r");
    char line[4 * PATH_MAX + 16];
    int saw_header = 0;

    if (!tf)
        return -1;

    while (fgets(line, sizeof(line), tf)) {
        size_t len = strlen(line);
        char request[PATH_MAX];
        char source[PATH_MAX];
        char *separator;
        size_t request_hex_len;

        if (len == 0 || line[len - 1] != '\n') {
            fprintf(stderr, "dlfreeze: malformed or truncated file trace\n");
            fclose(tf);
            return -1;
        }
        line[--len] = '\0';
        if (len > 0 && line[len - 1] == '\r') {
            fprintf(stderr, "dlfreeze: unsupported newline in file trace\n");
            fclose(tf);
            return -1;
        }

        if (strcmp(line, "#DLFREEZE_PRELOAD_TRACE_V4") == 0) {
            saw_header = 1;
            continue;
        }
        if (!saw_header) {
            fprintf(stderr, "dlfreeze: unsupported file trace format\n");
            fclose(tf);
            return -1;
        }
        if (len > 2 && line[0] == '!' && line[1] == ' ') {
            fprintf(stderr,
                    "dlfreeze: preload helper reported an incomplete file "
                    "trace: %s\n", line + 2);
            fclose(tf);
            return -1;
        }
        if (len < 4 || line[1] != ' ' ||
            (line[0] != 'F' && line[0] != 'D' && line[0] != 'N')) {
            fprintf(stderr, "dlfreeze: malformed file trace record\n");
            fclose(tf);
            return -1;
        }

        if (line[0] == 'N') {
            if (strchr(line + 2, ' ') ||
                file_trace_hex_decode(line + 2, strlen(line + 2),
                                      request, sizeof(request)) < 0 ||
                request[0] != '/') {
                fprintf(stderr, "dlfreeze: malformed file trace record\n");
                fclose(tf);
                return -1;
            }
            process_captured_negative_path(patterns, npatterns, out, request);
            continue;
        }
        separator = strchr(line + 2, ' ');
        if (!separator || strchr(separator + 1, ' ')) {
            fprintf(stderr, "dlfreeze: malformed file trace record\n");
            fclose(tf);
            return -1;
        }
        request_hex_len = (size_t)(separator - (line + 2));
        if (file_trace_hex_decode(line + 2, request_hex_len,
                                  request, sizeof(request)) < 0 ||
            file_trace_hex_decode(separator + 1, strlen(separator + 1),
                                  source, sizeof(source)) < 0 ||
            request[0] != '/' || source[0] != '/') {
            fprintf(stderr, "dlfreeze: malformed file trace encoding\n");
            fclose(tf);
            return -1;
        }
        /* A successful open may refer to a short-lived scratch file which is
         * deliberately removed before the traced process exits.  Such a file
         * is irrelevant when its request is outside every capture pattern;
         * do not let its later disappearance invalidate an otherwise complete
         * trace.  Records selected for capture remain strict: their source
         * must still be canonical and readable below. */
        if (line[0] == 'D') {
            if (!dir_matches_patterns(request, patterns, npatterns))
                continue;
        } else {
            int matched = 0;

            for (int i = 0; i < npatterns; i++) {
                if (match_glob(patterns[i], request)) {
                    matched = 1;
                    break;
                }
            }
            if (!matched)
                continue;
        }
        {
            char *canonical = realpath(source, NULL);

            if (!canonical || strcmp(canonical, source) != 0) {
                fprintf(stderr,
                        "dlfreeze: captured source is no longer canonical "
                        "or readable: %s\n", source);
                free(canonical);
                fclose(tf);
                return -1;
            }
            free(canonical);
        }
        process_captured_path(exe_path, patterns, npatterns, out, deps,
                              request, source, line[0] == 'D');
    }

    if (ferror(tf) || !saw_header) {
        fclose(tf);
        return -1;
    }

    fclose(tf);
    finish_captured_paths(out, verbose);
    return 0;
}

static int capture_data_files(const char *exe_path, const char *exe_identity,
                              int argc, char **argv,
                              int optind_val, const char **patterns,
                              int npatterns, struct data_file_list *out,
                              struct dep_list *deps, int verbose,
                              const char *preload_path)
{
    char tracef[] = "/tmp/dlfreeze-file-trace.XXXXXX";
    char dlopen_tracef[] = "/tmp/dlfreeze-trace.XXXXXX";
    sigset_t forward_set, old_mask;
    int tfd;
    int dtfd;
    int st;
    pid_t pid;

    /* -t promises complete runtime-loading discovery.  Syscall tracing can
     * identify opened ELF files, but cannot recover the caller's exact
     * dlopen request or lookup mode.  Never turn that lossy observation into
     * a manifest entry. */
    if (!preload_path) {
        fprintf(stderr,
                "dlfreeze: a compatible preload helper is required for "
                "complete -t tracing\n");
        errno = ENOTSUP;
        return -1;
    }

    tfd = mkstemp(tracef);
    if (tfd < 0) {
        perror("mkstemp");
        return -1;
    }
    if (close(tfd) < 0) {
        perror("close");
        unlink(tracef);
        return -1;
    }
    dtfd = mkstemp(dlopen_tracef);
    if (dtfd < 0) {
        perror("mkstemp");
        unlink(tracef);
        return -1;
    }
    if (close(dtfd) < 0) {
        perror("close");
        unlink(tracef);
        unlink(dlopen_tracef);
        return -1;
    }

    printf("Tracing dlopen calls and file access …\n");

    build_trace_signal_set(&forward_set);
    if (sigprocmask(SIG_BLOCK, &forward_set, &old_mask) < 0) {
        perror("sigprocmask");
        unlink(tracef);
        unlink(dlopen_tracef);
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
        perror("fork");
        unlink(tracef);
        unlink(dlopen_tracef);
        return -1;
    }

    if (pid == 0) {
        int tstart = optind_val + 1;
        int nargs = 1 + (argc - tstart);
        char **tav;

        if (sigprocmask(SIG_SETMASK, &old_mask, NULL) < 0)
            _exit(127);
        /* Keep the traced program in the packer's foreground process group.
         * Splitting it into a new group without also transferring the
         * controlling terminal makes an interactive target a background
         * reader: its first read is stopped by SIGTTIN while the parent waits
         * forever.  No trace timeout relies on a private process group. */
        if (prepend_ld_preload(preload_path) < 0 ||
            setenv("DLFREEZE_TRACE_FILE", dlopen_tracef, 1) < 0 ||
            setenv("DLFREEZE_FILE_TRACE_FILE", tracef, 1) < 0)
            _exit(127);
        tav = calloc((size_t)nargs + 1, sizeof(*tav));
        if (!tav)
            _exit(127);
        tav[0] = (char *)exe_identity;
        for (int i = tstart; i < argc; i++)
            tav[1 + i - tstart] = argv[i];
        tav[nargs] = NULL;
        execve(exe_path, tav, environ);
        _exit(127);
    }

    if (supervise_trace_child(pid, &forward_set, &old_mask, &st) < 0) {
        perror("waitpid");
        unlink(tracef);
        unlink(dlopen_tracef);
        return -1;
    }
    if (verbose)
        printf("trace exit status: %d\n",
               WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    if (!WIFEXITED(st)) {
        fprintf(stderr, "dlfreeze: traced execution did not exit normally\n");
        unlink(tracef);
        unlink(dlopen_tracef);
        return -1;
    }

    if (!trace_file_has_header(tracef, "#DLFREEZE_PRELOAD_TRACE_V4") ||
        !trace_file_has_header(dlopen_tracef,
                               "#DLFREEZE_DLOPEN_TRACE_V4")) {
        fprintf(stderr,
                "dlfreeze: preload trace helper is incompatible with the "
                "target runtime or produced incomplete readiness records\n");
        unlink(tracef);
        unlink(dlopen_tracef);
        return -1;
    }

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
    if (dep_add_dlopen_libs(deps, dlopen_tracef) < 0) {
        unlink(dlopen_tracef);
        unlink(tracef);
        return -1;
    }
    if (verbose) {
        printf("libraries after trace: %d\n", deps->count);
        for (int i = 0; i < deps->count; i++)
            if (deps->libs[i].from_dlopen)
                printf("  (dlopen) %-30s → %s\n",
                       deps->libs[i].name, deps->libs[i].path);
    }

    unlink(dlopen_tracef);
    st = parse_preload_file_trace(tracef, exe_path, patterns, npatterns,
                                  out, deps, verbose);
    unlink(tracef);
    return st;
}

/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    const char *out_path = NULL;
    int do_trace = 0, verbose = 0, direct_load = 0;
    const char **file_patterns;
    int nfile_patterns = 0;

    if (argc < 0 || (size_t)argc > SIZE_MAX / sizeof(*file_patterns)) {
        fprintf(stderr, "dlfreeze: invalid argument vector size\n");
        return 1;
    }
    file_patterns = calloc(argc > 0 ? (size_t)argc : 1,
                           sizeof(*file_patterns));
    if (!file_patterns) {
        fprintf(stderr, "dlfreeze: cannot allocate option storage\n");
        return 1;
    }

    int opt;
    while ((opt = getopt(argc, argv, "+o:f:dtvh")) != -1) {
        switch (opt) {
        case 'o': out_path = optarg;  break;
        case 'd': direct_load = 1;   break;
        case 't': do_trace = 1;      break;
        case 'f':
            file_patterns[nfile_patterns++] = optarg;
            break;
        case 'v': verbose  = 1;      break;
        case 'h': usage(argv[0]); free(file_patterns); return 0;
        default:  usage(argv[0]); free(file_patterns); return 1;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "dlfreeze: no executable specified\n");
        usage(argv[0]);
        free(file_patterns);
        return 1;
    }
    if (nfile_patterns > 0 && !do_trace) {
        fprintf(stderr, "dlfreeze: -f requires -t (tracing mode)\n");
        free(file_patterns);
        return 1;
    }
    if (nfile_patterns > 0 && !direct_load) {
        fprintf(stderr,
                "dlfreeze: captured files require direct-load mode (-d)\n");
        free(file_patterns);
        return 1;
    }

    /* resolve target */
    const char *requested_exe = argv[optind];
    char *exe_path = resolve_exe(argv[optind]);
    char *exe_name = strdup(requested_exe);
    if (!exe_path) {
        fprintf(stderr, "dlfreeze: cannot find: %s\n", argv[optind]);
        free(exe_name);
        free(file_patterns);
        return 1;
    }
    if (!exe_name)
        exe_name = strdup(exe_path);
    if (!exe_name) {
        fprintf(stderr, "dlfreeze: cannot allocate executable identity\n");
        free(exe_path);
        free(file_patterns);
        return 1;
    }
    if (!elf_check(exe_path)) {
        fprintf(stderr, "dlfreeze: not an ELF: %s\n", exe_path);
        free(exe_name); free(exe_path); free(file_patterns); return 1;
    }

    /* locate our helper binaries */
    char self[PATH_MAX];
    ssize_t slen = readlink("/proc/self/exe", self, sizeof(self)-1);
    if (slen < 0 || (size_t)slen >= sizeof(self) - 1) {
        if (slen >= 0)
            errno = ENAMETOOLONG;
        perror("readlink");
        free(exe_name); free(exe_path); free(file_patterns);
        return 1;
    }
    self[slen] = '\0';

    char *bootstrap = find_sibling(self, "dlfreeze-bootstrap");
    if (!bootstrap) {
        fprintf(stderr, "dlfreeze: cannot find dlfreeze-bootstrap\n");
        free(exe_name); free(exe_path); free(file_patterns); return 1;
    }

    if (verbose)
        printf("target    : %s\nbootstrap : %s\n", exe_path, bootstrap);

    /* resolve dependencies */
    printf("Resolving dependencies for %s …\n", exe_path);
    struct dep_list deps;
    if (dep_resolve(exe_path, &deps) < 0) {
        free(exe_name); free(exe_path); free(bootstrap);
        free(file_patterns);
        return 1;
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
        int trace_failed = 0;
        char *preload = find_compatible_preload(self, &deps, verbose);
        if (!preload) {
            fprintf(stderr,
                    "dlfreeze: -t has no ABI-compatible preload helper; "
                    "syscall tracing cannot recover exact dlopen requests\n");
            trace_failed = 1;
        }

        if (!trace_failed && nfile_patterns > 0) {
            int trace_rc;

            trace_rc = capture_data_files(exe_path, exe_name, argc, argv,
                                          optind, file_patterns, nfile_patterns,
                                          &data_files, &deps, verbose, preload);
            free(preload);
            if (trace_rc < 0) {
                data_file_list_free(&data_files);
                dep_list_free(&deps);
                free(exe_name);
                free(exe_path);
                free(bootstrap);
                free(file_patterns);
                return 1;
            }
            preload = NULL;
        } else if (!trace_failed) {
            /* dlopen-only tracing (no -f patterns, no strace needed) */
            char tracef[] = "/tmp/dlfreeze-trace.XXXXXX";
            int tfd = mkstemp(tracef);
            if (tfd < 0) {
                perror("mkstemp");
                trace_failed = 1;
            } else {
                if (close(tfd) < 0) {
                    perror("close");
                    trace_failed = 1;
                } else {
                    printf("Tracing dlopen calls …\n");

                    sigset_t forward_set, old_mask;
                    build_trace_signal_set(&forward_set);
                    if (sigprocmask(SIG_BLOCK, &forward_set, &old_mask) < 0) {
                        perror("sigprocmask");
                        trace_failed = 1;
                    } else {
                        pid_t pid = fork();

                        if (pid == 0) {
                            if (sigprocmask(SIG_SETMASK, &old_mask, NULL) < 0)
                                _exit(127);
                            /* Preserve foreground terminal ownership for traced
                             * interactive programs; see capture_data_files().
                             */
                            if (prepend_ld_preload(preload) < 0)
                                _exit(127);
                            if (setenv("DLFREEZE_TRACE_FILE", tracef, 1) < 0)
                                _exit(127);

                            int tstart = optind + 1; /* args after executable */
                            int nargs = 1 + (argc - tstart);
                            char **tav = calloc(nargs + 1, sizeof(char *));
                            if (!tav)
                                _exit(127);
                            tav[0] = (char *)requested_exe;
                            for (int i = tstart; i < argc; i++)
                                tav[1 + i - tstart] = argv[i];
                            tav[nargs] = NULL;
                            execve(exe_path, tav, environ);
                            _exit(127);
                        }
                        if (pid < 0) {
                            sigprocmask(SIG_SETMASK, &old_mask, NULL);
                            perror("fork");
                            trace_failed = 1;
                        } else {
                            int st;

                            if (supervise_trace_child(pid, &forward_set,
                                                      &old_mask, &st) < 0) {
                                perror("waitpid");
                                trace_failed = 1;
                            } else {
                                if (verbose)
                                    printf("trace exit status: %d\n",
                                           WIFEXITED(st) ? WEXITSTATUS(st)
                                                         : -1);
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
                                if (!WIFEXITED(st) ||
                                    !trace_file_has_header(
                                        tracef, "#DLFREEZE_DLOPEN_TRACE_V4")) {
                                    fprintf(
                                        stderr,
                                        "dlfreeze: preload trace helper is "
                                        "incompatible with the target runtime "
                                        "or produced no valid V4 readiness "
                                        "record\n");
                                    trace_failed = 1;
                                } else if (dep_add_dlopen_libs(&deps, tracef) <
                                           0) {
                                    trace_failed = 1;
                                }
                                if (verbose) {
                                    printf("libraries after trace: %d\n",
                                           deps.count);
                                    for (int i = 0; i < deps.count; i++)
                                        if (deps.libs[i].from_dlopen)
                                            printf("  (dlopen) %-30s → %s\n",
                                                   deps.libs[i].name,
                                                   deps.libs[i].path);
                                }
                            }
                        }
                    }
                }
                unlink(tracef);
            }
        }
        free(preload);
        if (trace_failed) {
            data_file_list_free(&data_files);
            dep_list_free(&deps);
            free(exe_name);
            free(exe_path);
            free(bootstrap);
            free(file_patterns);
            return 1;
        }
        if (data_files.failed) {
            fprintf(stderr,
                    "dlfreeze: cannot allocate captured-file manifest\n");
            data_file_list_free(&data_files);
            dep_list_free(&deps);
            free(exe_name);
            free(exe_path);
            free(bootstrap);
            free(file_patterns);
            return 1;
        }
    }

    /* output path */
    char outbuf[PATH_MAX];
    if (!out_path) {
        const char *b = strrchr(exe_path, '/');
        b = b ? b + 1 : exe_path;
        int out_len = snprintf(outbuf, sizeof(outbuf), "%s.frozen", b);

        if (out_len < 0 || (size_t)out_len >= sizeof(outbuf)) {
            fprintf(stderr, "dlfreeze: default output path is too long\n");
            data_file_list_free(&data_files);
            dep_list_free(&deps);
            free(exe_name);
            free(exe_path);
            free(bootstrap);
            free(file_patterns);
            return 1;
        }
        out_path = outbuf;
    }

    /* pack */
    size_t nfiles = (size_t)deps.count + 1U +
                    (deps.interp_path ? 1U : 0U) +
                    (size_t)data_files.count;
    printf("Packing %zu files into %s …\n", nfiles, out_path);
    struct pack_options po = {
        .exe_path       = exe_path,
        .exe_name       = exe_name,
        .output_path    = out_path,
        .bootstrap_path = bootstrap,
        .deps           = &deps,
        .direct_load    = direct_load,
        .data_files     = data_files.count > 0 ? &data_files : NULL,
    };
    if (fflush(stdout) != 0) {
        perror("dlfreeze: cannot flush diagnostics");
        data_file_list_free(&data_files);
        dep_list_free(&deps);
        free(exe_name);
        free(exe_path);
        free(bootstrap);
        free(file_patterns);
        return 1;
    }
    int rc = pack_frozen(&po);

    data_file_list_free(&data_files);
    dep_list_free(&deps);
    free(exe_name);
    free(exe_path);
    free(bootstrap);
    free(file_patterns);
    return rc < 0 ? 1 : 0;
}
