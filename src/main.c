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
#include <inttypes.h>
#include <sys/file.h>
#include <sys/auxv.h>

#include "elf_parser.h"
#include "dep_resolver.h"
#include "libc_semantics.h"
#include "packer.h"

extern char **environ;

static int set_trace_owner_environment(void)
{
    char owner[32];
    pid_t pid = getpid();
    int length;

    if (pid <= 0) {
        errno = EIO;
        return -1;
    }
    length = snprintf(owner, sizeof(owner), "%ld", (long)pid);
    if (length <= 0 || (size_t)length >= sizeof(owner)) {
        errno = EOVERFLOW;
        return -1;
    }
    return setenv("DLFREEZE_TRACE_OWNER_PID", owner, 1);
}

static int prepare_trace_descriptor(int fd)
{
    struct stat status;
    int descriptor_flags;
    int status_flags;

    if (fd < 0 || fstat(fd, &status) < 0 ||
        !S_ISREG(status.st_mode) || status.st_size != 0) {
        errno = EINVAL;
        return -1;
    }
    descriptor_flags = fcntl(fd, F_GETFD);
    status_flags = fcntl(fd, F_GETFL);
    if (descriptor_flags < 0 || status_flags < 0 ||
        fcntl(fd, F_SETFD, descriptor_flags & ~FD_CLOEXEC) < 0 ||
        fcntl(fd, F_SETFL, status_flags | O_APPEND | O_NONBLOCK) < 0)
        return -1;
    return 0;
}

static int set_trace_descriptor_environment(int fd, const char *fd_name,
                                            const char *identity_name)
{
    struct stat status;
    char fd_value[32];
    char identity_value[68];
    int fd_length;
    int identity_length;

    if (fd < 0 || !fd_name || !identity_name ||
        fstat(fd, &status) < 0 ||
        !S_ISREG(status.st_mode) ||
        status.st_size != 0) {
        errno = EINVAL;
        return -1;
    }
    fd_length = snprintf(fd_value, sizeof(fd_value), "%d", fd);
    if (fd_length <= 0 || (size_t)fd_length >= sizeof(fd_value)) {
        errno = EOVERFLOW;
        return -1;
    }
    identity_length = snprintf(
        identity_value, sizeof(identity_value),
        "%016" PRIx64 ":%016" PRIx64 ":%016" PRIx64 ":%016" PRIx64,
        (uint64_t)status.st_dev, (uint64_t)status.st_ino,
        (uint64_t)(status.st_mode & S_IFMT), (uint64_t)status.st_rdev);
    if (identity_length != (int)sizeof(identity_value) - 1) {
        errno = EOVERFLOW;
        return -1;
    }
    if (setenv(identity_name, identity_value, 1) < 0)
        return -1;
    return setenv(fd_name, fd_value, 1);
}

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
        "  -d          Prefer direct-load mode (the default)\n"
        "  -x          Force extraction mode instead of direct loading\n"
        "  -t          Trace runtime loading by running the program (TTY preserved)\n"
        "  -f <glob>   Embed data files matching glob (requires -t, repeatable)\n"
        "  -v          Verbose\n"
        "  -h          Help\n\n"
        "Examples:\n"
        "  %s /bin/ls\n"
        "  %s -o frozen_ls /bin/ls\n"
        "  %s -t -o frozen_app -- myapp --load-plugins\n"
        "  %s -t -f '/usr/share/myapp/*' -- myapp --self-test\n",
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

static void resolved_snapshot_from_stat(struct dep_file_snapshot *snapshot,
                                        const struct stat *st)
{
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->device = st->st_dev;
    snapshot->inode = st->st_ino;
    snapshot->size = st->st_size;
    snapshot->mtime_sec = st->st_mtim.tv_sec;
    snapshot->mtime_nsec = st->st_mtim.tv_nsec;
    snapshot->ctime_sec = st->st_ctim.tv_sec;
    snapshot->ctime_nsec = st->st_ctim.tv_nsec;
    snapshot->valid = 1;
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
    /* musl's reserved libc/libpthread/libdl-style names all bind to the
     * already-loaded combined PT_INTERP object, even when a minimal target
     * has no DT_NEEDED self-edge and the interpreter exports no SONAME. */
    if (deps->runtime_family == DEP_RUNTIME_MUSL &&
        ((interp_soname && strcmp(interp_soname, name) == 0) ||
         dlfrz_musl_reserved_soname(name))) {
        if (target_provider_add(&provider, deps->interp_path) < 0)
            return -1;
    }
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

/* musl resolves a slash-free DT_NEEDED by reusing the first already-loaded
 * object whose loader shortname exactly matches the request.  That identity
 * is the name by which the startup closure loaded the object, not an
 * arbitrary DT_SONAME or the provider selected by resolving the helper in
 * isolation.  Reproduce that rule from the immutable target closure and
 * reject distinct providers for one shortname as ambiguous. */
static int target_musl_shortname_provider(const struct dep_list *deps,
                                          const char *name,
                                          const char **path_out)
{
    const char *provider = NULL;

    if (!deps || deps->runtime_family != DEP_RUNTIME_MUSL || !name ||
        !name[0] || strchr(name, '/') || !path_out)
        return -1;
    if (dlfrz_musl_reserved_soname(name) &&
        target_provider_add(&provider, deps->interp_path) < 0)
        return -1;
    for (int i = 0; i < deps->count; i++) {
        const char *loaded_name = deps->libs[i].name;

        if (!loaded_name || strchr(loaded_name, '/') ||
            strcmp(loaded_name, name) != 0)
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
 * names, libc path spelling, or application name.  Every helper dependency
 * must resolve to the exact provider already present in the target startup
 * graph; a dependency-free helper remains a valid fallback. */
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
        const char *startup_provider = NULL;
        char *helper_provider = NULL;
        int runtime_match;
        int helper_match;

        /* Unlike the GNU loader, musl performs this slash-free lookup
         * against loader shortnames before searching the helper's RUNPATH.
         * Resolving the helper alone can therefore name a different file
         * even though that file will never be mapped.  The traced child is
         * still the authoritative strong-import/relocation check: a helper
         * whose name-only imports are absent cannot publish V8 readiness and
         * the trace fails without producing an artifact. */
        if (deps->runtime_family == DEP_RUNTIME_MUSL &&
            !strchr(info.needed[i], '/')) {
            runtime_match = target_musl_shortname_provider(
                deps, info.needed[i], &startup_provider);
            if (runtime_match != 1) {
                score = -1;
                goto out;
            }
            score++;
            continue;
        }

        runtime_match = target_runtime_provider(
            deps, interp_soname, info.needed[i], &startup_provider);

        if (runtime_match != 1 ||
            dep_resolve_aux_dependency(
                deps, path, info.needed[i], &helper_provider) != 1) {
            free(helper_provider);
            score = -1;
            goto out;
        }
        helper_match = paths_name_same_file(
            startup_provider, helper_provider);
        free(helper_provider);
        if (!helper_match) {
            score = -1;
            goto out;
        }
        score++;
    }

    /* Every helper DT_NEEDED must resolve to an identity which is already in
     * the target startup graph.  Instrumentation-only DSOs would perturb
     * RTLD_NOLOAD, weak/global lookup, and reuse semantics even if omitted
     * from the eventual manifest. */

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

/* /proc/self/exe is the strongest identity because it remains attached to
 * the running file after rename/unlink.  It is not universally mounted in
 * containers and chroots, however.  AT_EXECFN is kernel-supplied and normally
 * names the same execve input; argv[0]/PATH is the final conventional fallback.
 * Both fallback spellings are canonicalized before sibling discovery so a
 * relative invocation does not accidentally search the current directory. */
static int resolve_running_executable(const char *argv0,
                                      char path[PATH_MAX])
{
    ssize_t length;
    char *resolved = NULL;
    const char *execfn;

    if (!path) {
        errno = EINVAL;
        return -1;
    }
    length = readlink("/proc/self/exe", path, PATH_MAX - 1);
    if (length >= 0 && length < PATH_MAX - 1) {
        path[length] = '\0';
        return 0;
    }

    execfn = (const char *)(uintptr_t)getauxval(AT_EXECFN);
    if (execfn && execfn[0])
        resolved = resolve_exe(execfn);
    if (!resolved && argv0 && argv0[0] &&
        (!execfn || strcmp(argv0, execfn) != 0))
        resolved = resolve_exe(argv0);
    if (!resolved) {
        errno = ENOENT;
        return -1;
    }
    length = (ssize_t)strlen(resolved);
    if (length >= PATH_MAX) {
        free(resolved);
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(path, resolved, (size_t)length + 1);
    free(resolved);
    return 0;
}

static int match_glob(const char *pattern, const char *path)
{
    /* Without FNM_PATHNAME, '*' intentionally spans directory separators. */
    return fnmatch(pattern, path, 0) == 0;
}

enum glob_token_kind {
    GLOB_TOKEN_LITERAL,
    GLOB_TOKEN_ANY,
    GLOB_TOKEN_STAR
};

/* Parse only enough of fnmatch's grammar to answer an existential question.
 * Bracket expressions are deliberately over-approximated as "any byte": this
 * can retain an irrelevant directory but can never omit a relevant one. */
static enum glob_token_kind glob_token_at(const char *pattern, size_t length,
                                          size_t position,
                                          size_t *next_position,
                                          unsigned char *literal)
{
    unsigned char value = (unsigned char)pattern[position];

    if (value == '*') {
        *next_position = position + 1;
        return GLOB_TOKEN_STAR;
    }
    if (value == '?') {
        *next_position = position + 1;
        return GLOB_TOKEN_ANY;
    }
    if (value == '\\' && position + 1 < length) {
        *literal = (unsigned char)pattern[position + 1];
        *next_position = position + 2;
        return GLOB_TOKEN_LITERAL;
    }
    if (value == '[') {
        size_t end = position + 1;

        if (end < length && (pattern[end] == '!' || pattern[end] == '^'))
            end++;
        if (end < length && pattern[end] == ']')
            end++;
        while (end < length && pattern[end] != ']') {
            if (pattern[end] == '\\' && end + 1 < length)
                end += 2;
            else
                end++;
        }
        *next_position = end < length ? end + 1 : position + 1;
        return GLOB_TOKEN_ANY;
    }
    *literal = value;
    *next_position = position + 1;
    return GLOB_TOKEN_LITERAL;
}

static void glob_epsilon_closure(const char *pattern, size_t length,
                                 unsigned char states[PATH_MAX + 1])
{
    for (size_t position = 0; position < length; position++) {
        if (states[position] && pattern[position] == '*')
            states[position + 1] = 1;
    }
}

static void glob_consume_fixed(const char *pattern, size_t length,
                               const unsigned char current[PATH_MAX + 1],
                               unsigned char next[PATH_MAX + 1],
                               unsigned char input)
{
    memset(next, 0, PATH_MAX + 1);
    for (size_t position = 0; position < length; position++) {
        size_t after;
        unsigned char literal = 0;
        enum glob_token_kind kind;

        if (!current[position])
            continue;
        kind = glob_token_at(pattern, length, position, &after, &literal);
        if (kind == GLOB_TOKEN_STAR)
            next[position] = 1;
        else if (kind == GLOB_TOKEN_ANY || literal == input)
            next[after] = 1;
    }
    glob_epsilon_closure(pattern, length, next);
}

static void glob_consume_some_nonslash(
    const char *pattern, size_t length,
    const unsigned char current[PATH_MAX + 1],
    unsigned char next[PATH_MAX + 1])
{
    memset(next, 0, PATH_MAX + 1);
    for (size_t position = 0; position < length; position++) {
        size_t after;
        unsigned char literal = 0;
        enum glob_token_kind kind;

        if (!current[position])
            continue;
        kind = glob_token_at(pattern, length, position, &after, &literal);
        if (kind == GLOB_TOKEN_STAR)
            next[position] = 1;
        else if (kind == GLOB_TOKEN_ANY || literal != '/')
            next[after] = 1;
    }
    glob_epsilon_closure(pattern, length, next);
}

/* Return whether the glob can match rpath plus exactly one non-empty path
 * component.  This is the directory-probe scope intended by -f: a glob for
 * /foo/a-prefix selects an observed /foo, while a nested /foo/bar glob does
 * not select / or /foo.
 * The NFA uses fnmatch-compatible '*' slash behavior for the fixed prefix. */
static int glob_may_match_immediate_child(const char *pattern,
                                          const char *rpath)
{
    unsigned char states[PATH_MAX + 1] = {0};
    unsigned char next[PATH_MAX + 1];
    unsigned char reachable[PATH_MAX + 1];
    size_t pattern_len = strlen(pattern);
    size_t rpath_len = strlen(rpath);

    if (pattern_len >= PATH_MAX || rpath_len >= PATH_MAX)
        return 1;
    for (size_t i = 0; i < pattern_len; i++) {
        if ((unsigned char)pattern[i] >= 0x80)
            return 1;
    }
    for (size_t i = 0; i < rpath_len; i++) {
        if ((unsigned char)rpath[i] >= 0x80)
            return 1;
    }

    states[0] = 1;
    glob_epsilon_closure(pattern, pattern_len, states);
    for (size_t i = 0; i < rpath_len; i++) {
        glob_consume_fixed(pattern, pattern_len, states, next,
                           (unsigned char)rpath[i]);
        memcpy(states, next, sizeof(states));
    }
    if (rpath_len == 0 || rpath[rpath_len - 1] != '/') {
        glob_consume_fixed(pattern, pattern_len, states, next, '/');
        memcpy(states, next, sizeof(states));
    }

    /* A child component is non-empty.  Then find the transitive closure of
     * states reachable by additional non-slash bytes. */
    glob_consume_some_nonslash(pattern, pattern_len, states, reachable);
    for (;;) {
        int changed = 0;

        if (reachable[pattern_len])
            return 1;
        glob_consume_some_nonslash(pattern, pattern_len, reachable, next);
        for (size_t i = 0; i <= pattern_len; i++) {
            if (next[i] && !reachable[i]) {
                reachable[i] = 1;
                changed = 1;
            }
        }
        glob_epsilon_closure(pattern, pattern_len, reachable);
        if (!changed)
            return reachable[pattern_len] != 0;
    }
}

/* ------------------------------------------------------------------ */
/* Capture data files opened during a traced run with the same preload */
/* helper that records exact dlopen requests.                           */
/* ------------------------------------------------------------------ */
static int dir_matches_patterns(const char *rpath, const char **patterns,
                                int npatterns)
{
    for (int i = 0; i < npatterns; i++) {
        if (match_glob(patterns[i], rpath) ||
            glob_may_match_immediate_child(patterns[i], rpath))
            return 1;
    }

    return 0;
}

static int file_request_matches_patterns(const char *path, int is_dir,
                                         const char **patterns,
                                         int npatterns)
{
    if (is_dir)
        return dir_matches_patterns(path, patterns, npatterns);

    for (int i = 0; i < npatterns; i++) {
        if (match_glob(patterns[i], path))
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
        if (deps->libs[i].path && strcmp(rpath, deps->libs[i].path) == 0)
            return 1;
    }

    return 0;
}

static int process_captured_path(const char *exe_path, const char **patterns,
                                 int npatterns, struct data_file_list *out,
                                 struct dep_list *deps,
                                 const char *request_path,
                                 const char *source_path, int is_dir,
                                 const struct stat *source_st,
                                 const struct dep_file_snapshot *snapshot)
{
    if (is_dir) {
        if (!source_st || !S_ISDIR(source_st->st_mode))
            return -1;
        if (!dir_matches_patterns(request_path, patterns, npatterns))
            return 0;

        /* Preserve successful directory probes without bulk-pulling contents;
         * traced file probes carry per-child existence semantics. */
        data_file_list_add_directory(out, request_path);
        return out->failed ? -1 : 0;
    }

    if (!source_st || !S_ISREG(source_st->st_mode) || !snapshot ||
        !snapshot->valid)
        return -1;

    if (strcmp(request_path, source_path) == 0 &&
        path_is_known_dep(source_path, exe_path, deps))
        return 0;

    for (int i = 0; i < npatterns; i++) {
        if (match_glob(patterns[i], request_path)) {
            data_file_list_add(out, request_path, source_path, snapshot);
            return out->failed ? -1 : 0;
        }
    }
    return 0;
}

/* Record a path that was probed during execution but did not exist at
 * freeze time.  At runtime the VFS will honour these entries and return
 * ENOENT even if the file has since appeared on the target system. */
static int process_captured_negative_path(const char **patterns, int npatterns,
                                          struct data_file_list *out,
                                          const char *path)
{
    struct stat sb;
    int selected = 0;

    if (!path || path[0] != '/')
        return -1;

    for (int i = 0; i < npatterns; i++) {
        if (match_glob(patterns[i], path)) {
            selected = 1;
            break;
        }
    }
    if (!selected)
        return 0;

    /* A selected negative observation is part of runtime lookup semantics.
     * If it appeared after the trace, silently omitting the record would let
     * the frozen program fall through to unrelated host state. */
    if (stat(path, &sb) == 0) {
        errno = ESTALE;
        return -1;
    }
    if (errno != ENOENT && errno != ENOTDIR)
        return -1;
    data_file_list_add_negative(out, path);
    return out->failed ? -1 : 0;
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

struct file_trace_snapshot {
    uint64_t device;
    uint64_t inode;
    uint64_t type;
    uint64_t size;
    uint64_t mtime_sec;
    uint64_t mtime_nsec;
    uint64_t ctime_sec;
    uint64_t ctime_nsec;
};

struct file_trace_pending_operation {
    uint64_t pid;
    uint64_t attempt;
    char begin_kind;
};

static size_t file_trace_pending_operation_index(
    const struct file_trace_pending_operation *pending, size_t count,
    uint64_t pid, uint64_t attempt)
{
    size_t index;

    for (index = 0; index < count; index++) {
        if (pending[index].pid == pid &&
            pending[index].attempt == attempt)
            break;
    }
    return index;
}

static int file_trace_pid_has_pending_call(
    const struct file_trace_pending_operation *pending, size_t count,
    uint64_t pid)
{
    for (size_t index = 0; index < count; index++) {
        if (pending[index].pid == pid &&
            pending[index].begin_kind == 'B')
            return 1;
    }
    return 0;
}

_Static_assert(sizeof(((struct stat *)0)->st_dev) <= sizeof(uint64_t),
               "file-trace device identity exceeds wire width");
_Static_assert(sizeof(((struct stat *)0)->st_ino) <= sizeof(uint64_t),
               "file-trace inode identity exceeds wire width");
_Static_assert(sizeof(((struct stat *)0)->st_size) <= sizeof(uint64_t),
               "file-trace size exceeds wire width");
_Static_assert(sizeof(((struct stat *)0)->st_mtim.tv_sec) <= sizeof(uint64_t),
               "file-trace timestamp exceeds wire width");

static int file_trace_u64_decode(const char *hex, uint64_t *value_out)
{
    uint64_t value = 0;

    if (!hex || !value_out || strlen(hex) != 16)
        return -1;
    for (size_t i = 0; i < 16; i++) {
        int digit = file_trace_hex_value(hex[i]);

        if (digit < 0)
            return -1;
        value = (value << 4) | (uint64_t)digit;
    }
    *value_out = value;
    return 0;
}

static int file_trace_fixed_u64_decode(const char *hex, uint64_t *value_out)
{
    uint64_t value = 0;

    if (!hex || !value_out)
        return -1;
    for (size_t i = 0; i < 16; i++) {
        int digit = file_trace_hex_value(hex[i]);

        if (digit < 0)
            return -1;
        value = (value << 4) | (uint64_t)digit;
    }
    *value_out = value;
    return 0;
}

static int file_trace_snapshot_decode(char *const fields[8],
                                      struct file_trace_snapshot *snapshot)
{
    uint64_t values[8];

    if (!fields || !snapshot)
        return -1;
    for (size_t i = 0; i < 8; i++) {
        if (file_trace_u64_decode(fields[i], &values[i]) < 0)
            return -1;
    }
    snapshot->device = values[0];
    snapshot->inode = values[1];
    snapshot->type = values[2];
    snapshot->size = values[3];
    snapshot->mtime_sec = values[4];
    snapshot->mtime_nsec = values[5];
    snapshot->ctime_sec = values[6];
    snapshot->ctime_nsec = values[7];
    if (snapshot->mtime_nsec > 999999999 ||
        snapshot->ctime_nsec > 999999999)
        return -1;
    return 0;
}

static void file_trace_snapshot_from_stat(struct file_trace_snapshot *snapshot,
                                          const struct stat *st)
{
    snapshot->device = (uint64_t)st->st_dev;
    snapshot->inode = (uint64_t)st->st_ino;
    snapshot->type = (uint64_t)(st->st_mode & S_IFMT);
    snapshot->size = (uint64_t)st->st_size;
    snapshot->mtime_sec = (uint64_t)st->st_mtim.tv_sec;
    snapshot->mtime_nsec = (uint64_t)st->st_mtim.tv_nsec;
    snapshot->ctime_sec = (uint64_t)st->st_ctim.tv_sec;
    snapshot->ctime_nsec = (uint64_t)st->st_ctim.tv_nsec;
}

static int file_trace_snapshot_matches_stat(
    const struct file_trace_snapshot *snapshot, const struct stat *st,
    int is_dir)
{
    struct file_trace_snapshot current;

    if (!snapshot || !st)
        return 0;
    file_trace_snapshot_from_stat(&current, st);
    if (snapshot->device != current.device ||
        snapshot->inode != current.inode || snapshot->type != current.type)
        return 0;
    if (is_dir)
        return snapshot->type == (uint64_t)S_IFDIR;
    return snapshot->type == (uint64_t)S_IFREG &&
           snapshot->size == current.size &&
           snapshot->mtime_sec == current.mtime_sec &&
           snapshot->mtime_nsec == current.mtime_nsec &&
           snapshot->ctime_sec == current.ctime_sec &&
           snapshot->ctime_nsec == current.ctime_nsec;
}

static int trace_fd_has_header(int trace_fd, const char *expected)
{
    char line[128];
    size_t expected_length;
    ssize_t length;

    if (trace_fd < 0 || !expected)
        return 0;
    expected_length = strlen(expected);
    if (expected_length + 1 > sizeof(line))
        return 0;
    do {
        length = pread(trace_fd, line, expected_length + 1, 0);
    } while (length < 0 && errno == EINTR);
    return length == (ssize_t)(expected_length + 1) &&
           memcmp(line, expected, expected_length) == 0 &&
           line[expected_length] == '\n';
}

static void dump_trace_fd(int trace_fd, const char *heading)
{
    char buffer[4096];
    off_t offset = 0;

    if (trace_fd < 0)
        return;
    printf("%s\n", heading);
    for (;;) {
        ssize_t length;

        do {
            length = pread(trace_fd, buffer, sizeof(buffer), offset);
        } while (length < 0 && errno == EINTR);
        if (length <= 0)
            break;
        printf("  %.*s", (int)length, buffer);
        offset += length;
    }
}

static int parse_preload_file_trace(int trace_fd, const char *exe_path,
                                    const char **patterns, int npatterns,
                                    struct data_file_list *out,
                                    struct dep_list *deps, int verbose)
{
    FILE *tf = trace_fd >= 0 ? fdopen(trace_fd, "r") : NULL;
    char line[4 * PATH_MAX + 256];
    int saw_header = 0;
    int saw_owner = 0;
    int saw_record = 0;
    uint64_t owner_pid = 0;
    uint64_t pending_exec_attempts[1024];
    size_t pending_exec_count = 0;
    struct file_trace_pending_operation pending_operations[1024];
    size_t pending_operation_count = 0;

    if (!tf) {
        if (trace_fd >= 0)
            close(trace_fd);
        return -1;
    }
    if (flock(fileno(tf), LOCK_EX | LOCK_NB) < 0) {
        fprintf(stderr,
                "dlfreeze: file trace is still owned by a live traced "
                "process\n");
        fclose(tf);
        return -1;
    }

    while (fgets(line, sizeof(line), tf)) {
        size_t len = strlen(line);
        char request[PATH_MAX];
        char source[PATH_MAX];

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

        if (strcmp(line, "#DLFREEZE_PRELOAD_TRACE_V9") == 0) {
            if (saw_header) {
                fprintf(stderr,
                        "dlfreeze: duplicate file trace version header\n");
                fclose(tf);
                return -1;
            }
            saw_header = 1;
            continue;
        }
        if (strcmp(line, "#DLFREEZE_PRELOAD_TRACE_V8") == 0) {
            fprintf(stderr,
                    "dlfreeze: file trace V8 has no file-operation "
                    "transactions and is unsupported\n");
            fclose(tf);
            return -1;
        }
        if (strcmp(line, "#DLFREEZE_PRELOAD_TRACE_V7") == 0) {
            fprintf(stderr,
                    "dlfreeze: file trace V7 has no owner-exec provenance "
                    "and is unsupported\n");
            fclose(tf);
            return -1;
        }
        if (!saw_header) {
            fprintf(stderr, "dlfreeze: unsupported file trace format\n");
            fclose(tf);
            return -1;
        }
        if (len == 18 && line[0] == 'O' && line[1] == ' ') {
            if (saw_owner || saw_record ||
                file_trace_fixed_u64_decode(line + 2, &owner_pid) < 0 ||
                owner_pid == 0) {
                fprintf(stderr,
                        "dlfreeze: malformed or duplicate file trace owner "
                        "record\n");
                fclose(tf);
                return -1;
            }
            saw_owner = 1;
            continue;
        }
        if (len > 0 && line[0] == 'O') {
            fprintf(stderr,
                    "dlfreeze: malformed or duplicate file trace owner "
                    "record\n");
            fclose(tf);
            return -1;
        }
        if (saw_owner && len == 35 &&
            (line[0] == 'E' || line[0] == 'C') && line[1] == ' ' &&
            line[18] == ' ') {
            uint64_t record_pid;
            uint64_t attempt;
            size_t index;

            if (file_trace_fixed_u64_decode(line + 2, &record_pid) < 0 ||
                record_pid != owner_pid ||
                file_trace_fixed_u64_decode(line + 19, &attempt) < 0 ||
                attempt == 0) {
                fprintf(stderr, "dlfreeze: malformed file trace exec record\n");
                fclose(tf);
                return -1;
            }
            for (index = 0; index < pending_exec_count; index++) {
                if (pending_exec_attempts[index] == attempt)
                    break;
            }
            if (line[0] == 'E') {
                if (index != pending_exec_count ||
                    pending_exec_count >=
                        sizeof(pending_exec_attempts) /
                            sizeof(pending_exec_attempts[0])) {
                    fprintf(stderr,
                            "dlfreeze: malformed file trace exec record\n");
                    fclose(tf);
                    return -1;
                }
                pending_exec_attempts[pending_exec_count++] = attempt;
            } else {
                if (index == pending_exec_count) {
                    fprintf(stderr,
                            "dlfreeze: malformed file trace exec record\n");
                    fclose(tf);
                    return -1;
                }
                pending_exec_count--;
                pending_exec_attempts[index] =
                    pending_exec_attempts[pending_exec_count];
            }
            saw_record = 1;
            continue;
        }
        if (len > 0 && (line[0] == 'E' || line[0] == 'C')) {
            fprintf(stderr, "dlfreeze: malformed file trace exec record\n");
            fclose(tf);
            return -1;
        }
        /* V9 file calls use B/K and descriptor-table mutations use V/W.
         * Both share one pid+attempt namespace so malformed, duplicated, or
         * cross-process closes cannot make a partial trace look complete. */
        if (saw_owner && len == 35 &&
            (line[0] == 'B' || line[0] == 'K' ||
             line[0] == 'V' || line[0] == 'W') &&
            line[1] == ' ' && line[18] == ' ') {
            uint64_t record_pid;
            uint64_t attempt;
            size_t index;

            if (file_trace_fixed_u64_decode(line + 2, &record_pid) < 0 ||
                record_pid == 0 ||
                file_trace_fixed_u64_decode(line + 19, &attempt) < 0 ||
                attempt == 0) {
                fprintf(stderr,
                        "dlfreeze: malformed file trace operation record\n");
                fclose(tf);
                return -1;
            }
            index = file_trace_pending_operation_index(
                pending_operations, pending_operation_count,
                record_pid, attempt);
            if (line[0] == 'B' || line[0] == 'V') {
                if (index != pending_operation_count ||
                    pending_operation_count >=
                        sizeof(pending_operations) /
                            sizeof(pending_operations[0])) {
                    fprintf(stderr,
                            "dlfreeze: duplicate or excessive file trace "
                            "operation begin\n");
                    fclose(tf);
                    return -1;
                }
                pending_operations[pending_operation_count].pid = record_pid;
                pending_operations[pending_operation_count].attempt = attempt;
                pending_operations[pending_operation_count].begin_kind =
                    line[0];
                pending_operation_count++;
            } else {
                char expected = line[0] == 'K' ? 'B' : 'V';

                if (index == pending_operation_count ||
                    pending_operations[index].begin_kind != expected) {
                    fprintf(stderr,
                            "dlfreeze: unmatched file trace operation "
                            "commit\n");
                    fclose(tf);
                    return -1;
                }
                pending_operation_count--;
                pending_operations[index] =
                    pending_operations[pending_operation_count];
            }
            saw_record = 1;
            continue;
        }
        if (len > 0 &&
            (line[0] == 'B' || line[0] == 'K' ||
             line[0] == 'V' || line[0] == 'W')) {
            fprintf(stderr,
                    "dlfreeze: malformed file trace operation record\n");
            fclose(tf);
            return -1;
        }
        if (saw_owner && len >= 20 && line[0] == '!' && line[1] == ' ' &&
            line[18] == ' ' && line[19] != '\0') {
            uint64_t record_pid;
            int reason_valid = 1;

            for (size_t i = 19; i < len; i++) {
                if (!((line[i] >= 'a' && line[i] <= 'z') ||
                      (line[i] >= '0' && line[i] <= '9') ||
                      line[i] == '-')) {
                    reason_valid = 0;
                    break;
                }
            }
            if (!reason_valid ||
                file_trace_fixed_u64_decode(line + 2, &record_pid) < 0 ||
                record_pid == 0) {
                fprintf(stderr,
                        "dlfreeze: malformed file trace terminal record\n");
                fclose(tf);
                return -1;
            }
            fprintf(stderr,
                    "dlfreeze: preload helper reported an incomplete file "
                    "trace: %s\n", line + 19);
            fclose(tf);
            return -1;
        }
        if (len > 0 && line[0] == '!') {
            fprintf(stderr, "dlfreeze: malformed file trace terminal record\n");
            fclose(tf);
            return -1;
        }
        if (!saw_owner) {
            fprintf(stderr, "dlfreeze: missing file trace owner record\n");
            fclose(tf);
            return -1;
        }

        /* A successful open can refer to an object with no stable source
         * pathname (for example, a deleted file or a procfs file represented
         * by qemu-user as a deleted memfd).  Such an observation is harmless
         * only when its original request lies outside the capture scope. */
        if (len > 22 && line[0] == 'U' && line[1] == ' ' &&
            line[18] == ' ' && (line[19] == 'F' || line[19] == 'D') &&
            line[20] == ' ') {
            uint64_t record_pid;

            if (file_trace_fixed_u64_decode(line + 2, &record_pid) < 0 ||
                record_pid == 0 || strchr(line + 21, ' ') ||
                file_trace_hex_decode(line + 21, strlen(line + 21),
                                      request, sizeof(request)) < 0 ||
                request[0] != '/' ||
                !file_trace_pid_has_pending_call(
                    pending_operations, pending_operation_count,
                    record_pid)) {
                fprintf(stderr, "dlfreeze: malformed file trace record\n");
                fclose(tf);
                return -1;
            }
            saw_record = 1;
            if (file_request_matches_patterns(request, line[19] == 'D',
                                              patterns, npatterns)) {
                fprintf(stderr,
                        "dlfreeze: selected successful open has no stable "
                        "source path: %s\n", request);
                fclose(tf);
                return -1;
            }
            continue;
        }
        if (len < 4 || line[1] != ' ' ||
            (line[0] != 'F' && line[0] != 'D' && line[0] != 'N')) {
            fprintf(stderr, "dlfreeze: malformed file trace record\n");
            fclose(tf);
            return -1;
        }

        if (line[0] == 'N') {
            uint64_t record_pid;

            if (len <= 20 || line[18] != ' ' ||
                file_trace_fixed_u64_decode(line + 2, &record_pid) < 0 ||
                record_pid == 0 || strchr(line + 19, ' ') ||
                file_trace_hex_decode(line + 19, strlen(line + 19),
                                      request, sizeof(request)) < 0 ||
                request[0] != '/' ||
                !file_trace_pid_has_pending_call(
                    pending_operations, pending_operation_count,
                    record_pid)) {
                fprintf(stderr, "dlfreeze: malformed file trace record\n");
                fclose(tf);
                return -1;
            }
            saw_record = 1;
            if (process_captured_negative_path(patterns, npatterns, out,
                                               request) < 0) {
                fprintf(stderr,
                        "dlfreeze: selected missing path changed after "
                        "tracing: %s\n", request);
                fclose(tf);
                return -1;
            }
            continue;
        }
        {
            char *fields[11];
            char *cursor = line + 2;
            struct file_trace_snapshot trace_snapshot;
            struct dep_file_snapshot pack_snapshot = {0};
            struct stat source_st;
            int is_dir = line[0] == 'D';
            uint64_t record_pid;

            for (size_t i = 0; i < 11; i++) {
                char *next;

                fields[i] = cursor;
                next = strchr(cursor, ' ');
                if (i == 10) {
                    if (next)
                        goto malformed_success_record;
                } else {
                    if (!next)
                        goto malformed_success_record;
                    *next = '\0';
                    cursor = next + 1;
                }
                if (!fields[i][0])
                    goto malformed_success_record;
            }
            if (file_trace_u64_decode(fields[0], &record_pid) < 0 ||
                record_pid == 0 ||
                !file_trace_pid_has_pending_call(
                    pending_operations, pending_operation_count,
                    record_pid))
                goto malformed_success_record;
            if (file_trace_hex_decode(fields[1], strlen(fields[1]),
                                      request, sizeof(request)) < 0 ||
                file_trace_hex_decode(fields[2], strlen(fields[2]),
                                      source, sizeof(source)) < 0 ||
                file_trace_snapshot_decode(&fields[3], &trace_snapshot) < 0 ||
                request[0] != '/' || source[0] != '/' ||
                trace_snapshot.type !=
                    (uint64_t)(is_dir ? S_IFDIR : S_IFREG))
                goto malformed_success_record;
            saw_record = 1;

            /* Short-lived observations outside the requested capture scope
             * remain irrelevant.  Selected records below are strict. */
            if (!file_request_matches_patterns(request, is_dir,
                                               patterns, npatterns))
                continue;

            {
                char *canonical = realpath(source, NULL);

                if (!canonical || strcmp(canonical, source) != 0) {
                    fprintf(stderr,
                            "dlfreeze: captured source is no longer "
                            "canonical or readable: %s\n", source);
                    free(canonical);
                    fclose(tf);
                    return -1;
                }
                free(canonical);
            }
            if (stat(source, &source_st) != 0 ||
                (!is_dir && source_st.st_size < 0) ||
                !file_trace_snapshot_matches_stat(&trace_snapshot,
                                                  &source_st, is_dir)) {
                fprintf(stderr,
                        "dlfreeze: captured source changed after tracing: "
                        "%s\n", source);
                fclose(tf);
                return -1;
            }
            if (!is_dir)
                resolved_snapshot_from_stat(&pack_snapshot, &source_st);
            if (process_captured_path(
                    exe_path, patterns, npatterns, out, deps, request, source,
                    is_dir, &source_st, is_dir ? NULL : &pack_snapshot) < 0) {
                fprintf(stderr,
                        "dlfreeze: cannot retain captured source snapshot: "
                        "%s\n", source);
                fclose(tf);
                return -1;
            }
            continue;

malformed_success_record:
            fprintf(stderr, "dlfreeze: malformed file trace record\n");
            fclose(tf);
            return -1;
        }
    }

    if (ferror(tf) || !saw_header || !saw_owner ||
        pending_exec_count != 0 || pending_operation_count != 0) {
        if (!ferror(tf) && saw_header && saw_owner &&
            pending_exec_count != 0)
            fprintf(stderr,
                    "dlfreeze: traced owner replaced its process image "
                    "during file tracing\n");
        else if (!ferror(tf) && saw_header && saw_owner &&
                 pending_operation_count != 0)
            fprintf(stderr,
                    "dlfreeze: incomplete file operation evidence\n");
        fclose(tf);
        return -1;
    }

    fclose(tf);
    finish_captured_paths(out, verbose);
    return 0;
}

static int trace_temp_path_component_is_trusted(const struct stat *status)
{
    uid_t effective_uid = geteuid();

    if (!status || !S_ISDIR(status->st_mode)) {
        errno = ENOTDIR;
        return 0;
    }
    /* Every directory owner controls the name immediately below it.  A
     * sticky directory prevents unrelated writers from replacing that child,
     * but its owner retains that authority, so admit only root and this
     * effective user as path controllers. */
    if (status->st_uid != 0 && status->st_uid != effective_uid) {
        errno = EACCES;
        return 0;
    }
    if ((status->st_mode & (S_IWGRP | S_IWOTH)) != 0 &&
        (status->st_mode & S_ISVTX) == 0) {
        errno = EACCES;
        return 0;
    }
    return 1;
}

static int trace_temp_directory_matches_path(int directory_fd,
                                             const char *canonical)
{
    struct stat descriptor_status;
    struct stat path_status;
    int path_fd;

    path_fd = open(canonical,
                   O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (path_fd < 0)
        return 0;
    if (fstat(directory_fd, &descriptor_status) < 0 ||
        fstat(path_fd, &path_status) < 0 ||
        !trace_temp_path_component_is_trusted(&descriptor_status) ||
        !trace_temp_path_component_is_trusted(&path_status)) {
        int saved_errno = errno;

        close(path_fd);
        errno = saved_errno;
        return 0;
    }
    if (descriptor_status.st_dev != path_status.st_dev ||
        descriptor_status.st_ino != path_status.st_ino) {
        close(path_fd);
        errno = ESTALE;
        return 0;
    }
    close(path_fd);
    return 1;
}

/* Resolve a user preference once, then bind every component relative to the
 * preceding descriptor.  The canonical pathname may originate through a
 * symlink, but no symlink participates in the descriptor walk admitted for
 * the later mkstemp pathname. */
static int open_trace_temp_directory(const char *candidate, char *canonical,
                                     size_t canonical_size)
{
    char resolved[PATH_MAX];
    char component[NAME_MAX + 1];
    const char *cursor;
    size_t resolved_length;
    int current_fd;

    if (!candidate || candidate[0] != '/' || !canonical ||
        canonical_size == 0) {
        errno = EINVAL;
        return -1;
    }
    if (!realpath(candidate, resolved))
        return -1;
    resolved_length = strlen(resolved);
    if (resolved_length == 0 || resolved[0] != '/' ||
        resolved_length >= canonical_size) {
        errno = ENAMETOOLONG;
        return -1;
    }

    current_fd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (current_fd < 0)
        return -1;
    {
        struct stat status;

        if (fstat(current_fd, &status) < 0 ||
            !trace_temp_path_component_is_trusted(&status)) {
            int saved_errno = errno;

            close(current_fd);
            errno = saved_errno;
            return -1;
        }
    }

    cursor = resolved + 1;
    while (*cursor) {
        const char *end = strchr(cursor, '/');
        size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
        struct stat status;
        int next_fd;

        if (length == 0 || length > NAME_MAX) {
            close(current_fd);
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(component, cursor, length);
        component[length] = '\0';
        next_fd = openat(current_fd, component,
                         O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next_fd < 0) {
            int saved_errno = errno;

            close(current_fd);
            errno = saved_errno;
            return -1;
        }
        if (fstat(next_fd, &status) < 0 ||
            !trace_temp_path_component_is_trusted(&status)) {
            int saved_errno = errno;

            close(next_fd);
            close(current_fd);
            errno = saved_errno;
            return -1;
        }
        close(current_fd);
        current_fd = next_fd;
        cursor = end ? end + 1 : cursor + length;
    }

    memcpy(canonical, resolved, resolved_length + 1);
    if (!trace_temp_directory_matches_path(current_fd, canonical)) {
        int saved_errno = errno;

        close(current_fd);
        errno = saved_errno;
        return -1;
    }
    return current_fd;
}

static int trace_tempfile_identity_matches(int directory_fd, const char *name,
                                           int file_fd)
{
    struct stat descriptor_status;
    struct stat path_status;

    if (fstat(file_fd, &descriptor_status) < 0 ||
        fstatat(directory_fd, name, &path_status, AT_SYMLINK_NOFOLLOW) < 0)
        return 0;
    if (!S_ISREG(descriptor_status.st_mode) ||
        !S_ISREG(path_status.st_mode) ||
        descriptor_status.st_dev != path_status.st_dev ||
        descriptor_status.st_ino != path_status.st_ino) {
        errno = ESTALE;
        return 0;
    }
    return 1;
}

static int finalize_trace_tempfile(int directory_fd, const char *name,
                                   int file_fd)
{
    struct stat descriptor_status;
    struct stat path_status;
    int chmod_result;

    do {
        chmod_result = fchmod(file_fd, 0600);
    } while (chmod_result < 0 && errno == EINTR);
    if (chmod_result < 0 ||
        fstat(file_fd, &descriptor_status) < 0 ||
        fstatat(directory_fd, name, &path_status, AT_SYMLINK_NOFOLLOW) < 0)
        return -1;
    if (!S_ISREG(descriptor_status.st_mode) ||
        !S_ISREG(path_status.st_mode) ||
        descriptor_status.st_dev != path_status.st_dev ||
        descriptor_status.st_ino != path_status.st_ino) {
        errno = ESTALE;
        return -1;
    }
    if ((descriptor_status.st_mode & 07777) != 0600 ||
        (path_status.st_mode & 07777) != 0600) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

static int make_trace_tempfile(char *path, size_t path_size,
                               const char *stem, int *collector_fd_out)
{
    const char *candidate = NULL;
    const char *environment = NULL;

    if (collector_fd_out)
        *collector_fd_out = -1;
    if (!path || path_size == 0 || !stem || !stem[0] ||
        !collector_fd_out ||
        strchr(stem, '/')) {
        errno = EINVAL;
        return -1;
    }
    /* The packer is not a privileged launcher, but do not let a mismatched
     * real/effective identity choose a trace destination through an inherited
     * environment.  Runtime AT_SECURE handling is enforced separately by the
     * bootstrap. */
    if (getuid() == geteuid() && getgid() == getegid())
        environment = getenv("TMPDIR");
    if (environment && environment[0] && environment[0] == '/')
        candidate = environment;

    for (int attempt = 0; attempt < 2; attempt++) {
        const char *directory = attempt == 0 && candidate ? candidate : "/tmp";
        char canonical[PATH_MAX];
        size_t directory_length;
        int directory_fd;
        int length;
        int fd;
        int collector_fd = -1;
        const char *name;

        if (attempt == 1 && !candidate)
            break;
        directory_fd = open_trace_temp_directory(
            directory, canonical, sizeof(canonical));
        if (directory_fd < 0)
            continue;
        directory_length = strlen(canonical);
        if (directory_length > INT_MAX) {
            close(directory_fd);
            errno = ENAMETOOLONG;
            continue;
        }
        length = snprintf(path, path_size, "%.*s%s%s.XXXXXX",
                          (int)directory_length, canonical,
                          directory_length == 1 ? "" : "/", stem);
        if (length < 0 || (size_t)length >= path_size) {
            close(directory_fd);
            errno = ENAMETOOLONG;
            continue;
        }
        /* mkstemp consumes a pathname rather than a directory descriptor.
         * Reopen that pathname and compare it with the component-walk result
         * immediately before creation; permissions above prevent an unrelated
         * user from changing an admitted controller after this check. */
        if (!trace_temp_directory_matches_path(directory_fd, canonical)) {
            int saved_errno = errno;

            close(directory_fd);
            errno = saved_errno;
            continue;
        }
        fd = mkstemp(path);
        if (fd >= 0) {
            name = strrchr(path, '/');
            name = name ? name + 1 : path;
            if (name[0] &&
                finalize_trace_tempfile(directory_fd, name, fd) == 0) {
                /* Some flock implementations require a writable descriptor
                 * for LOCK_EX.  This is a distinct open file description from
                 * the helper writer, not merely dup(2) of it. */
                collector_fd = openat(directory_fd, name,
                                      O_RDWR | O_CLOEXEC | O_NOFOLLOW);
            }
            if (collector_fd >= 0 &&
                trace_tempfile_identity_matches(
                    directory_fd, name, collector_fd) &&
                unlinkat(directory_fd, name, 0) == 0) {
                *collector_fd_out = collector_fd;
                close(directory_fd);
                return fd;
            }
            {
                int saved_errno = errno ? errno : EIO;

                /* Remove only the name still bound to the descriptor returned
                 * by mkstemp; never unlink an intervening replacement. */
                if (name[0] && trace_tempfile_identity_matches(
                                      directory_fd, name, fd))
                    (void)unlinkat(directory_fd, name, 0);
                if (collector_fd >= 0)
                    close(collector_fd);
                close(fd);
                close(directory_fd);
                errno = saved_errno;
                continue;
            }
        }
        {
            int saved_errno = errno;

            close(directory_fd);
            errno = saved_errno;
        }
    }
    return -1;
}

static int capture_data_files(const char *exe_path, const char *exe_identity,
                              int argc, char **argv,
                              int optind_val, const char **patterns,
                              int npatterns, struct data_file_list *out,
                              struct dep_list *deps, int verbose,
                              const char *preload_path)
{
    char tracef[PATH_MAX];
    char dlopen_tracef[PATH_MAX];
    sigset_t forward_set, old_mask;
    int tfd;
    int dtfd;
    int tcollector = -1;
    int dtcollector = -1;
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

    tfd = make_trace_tempfile(tracef, sizeof(tracef),
                              "dlfreeze-file-trace", &tcollector);
    if (tfd < 0) {
        perror("mkstemp");
        return -1;
    }
    if (prepare_trace_descriptor(tfd) < 0) {
        perror("prepare trace descriptor");
        close(tfd);
        close(tcollector);
        return -1;
    }
    dtfd = make_trace_tempfile(dlopen_tracef, sizeof(dlopen_tracef),
                               "dlfreeze-trace", &dtcollector);
    if (dtfd < 0) {
        perror("mkstemp");
        close(tfd);
        close(tcollector);
        return -1;
    }
    if (prepare_trace_descriptor(dtfd) < 0) {
        perror("prepare trace descriptor");
        close(tfd);
        close(tcollector);
        close(dtfd);
        close(dtcollector);
        return -1;
    }

    printf("Tracing dlopen calls and file access …\n");

    build_trace_signal_set(&forward_set);
    if (sigprocmask(SIG_BLOCK, &forward_set, &old_mask) < 0) {
        perror("sigprocmask");
        close(tfd);
        close(tcollector);
        close(dtfd);
        close(dtcollector);
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
        perror("fork");
        close(tfd);
        close(tcollector);
        close(dtfd);
        close(dtcollector);
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
            set_trace_owner_environment() < 0 ||
            set_trace_descriptor_environment(
                dtfd, "DLFREEZE_TRACE_FD",
                "DLFREEZE_TRACE_IDENTITY") < 0 ||
            set_trace_descriptor_environment(
                tfd, "DLFREEZE_FILE_TRACE_FD",
                "DLFREEZE_FILE_TRACE_IDENTITY") < 0 ||
            unsetenv("DLFREEZE_TRACE_FILE") < 0 ||
            unsetenv("DLFREEZE_FILE_TRACE_FILE") < 0)
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

    /* These are the helper's open file descriptions.  Keeping either copy in
     * the collector would make its later nonblocking flock unable to detect a
     * still-running fork descendant. */
    close(tfd);
    tfd = -1;
    close(dtfd);
    dtfd = -1;

    if (supervise_trace_child(pid, &forward_set, &old_mask, &st) < 0) {
        perror("waitpid");
        close(tcollector);
        close(dtcollector);
        return -1;
    }
    if (verbose)
        printf("trace exit status: %d\n",
               WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    if (!WIFEXITED(st)) {
        fprintf(stderr, "dlfreeze: traced execution did not exit normally\n");
        close(tcollector);
        close(dtcollector);
        return -1;
    }

    if (!trace_fd_has_header(tcollector, "#DLFREEZE_PRELOAD_TRACE_V9") ||
        !trace_fd_has_header(dtcollector,
                             "#DLFREEZE_DLOPEN_TRACE_V8")) {
        fprintf(stderr,
                "dlfreeze: preload trace helper is incompatible with the "
                "target runtime or produced incomplete readiness records\n");
        close(tcollector);
        close(dtcollector);
        return -1;
    }

    if (verbose)
        dump_trace_fd(dtcollector, "dlopen traced:");
    if (dep_add_dlopen_libs_fd(deps, dtcollector) < 0) {
        dtcollector = -1;
        close(tcollector);
        return -1;
    }
    dtcollector = -1;
    if (verbose) {
        printf("libraries after trace: %d\n", deps->count);
        for (int i = 0; i < deps->count; i++)
            if (deps->libs[i].from_dlopen)
                printf("  (dlopen) %-30s → %s\n",
                       deps->libs[i].name, deps->libs[i].path);
    }

    st = parse_preload_file_trace(tcollector, exe_path, patterns, npatterns,
                                  out, deps, verbose);
    tcollector = -1;
    return st;
}

/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    const char *out_path = NULL;
    int do_trace = 0, verbose = 0, direct_load = 1;
    int direct_option = 0, extraction_option = 0;
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
    while ((opt = getopt(argc, argv, "+o:f:dtxvh")) != -1) {
        switch (opt) {
        case 'o': out_path = optarg;  break;
        case 'd': direct_load = 1; direct_option = 1; break;
        case 'x': direct_load = 0; extraction_option = 1; break;
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
    if (direct_option && extraction_option) {
        fprintf(stderr,
                "dlfreeze: -d and -x select incompatible runtime modes\n");
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
                "dlfreeze: captured files are incompatible with forced "
                "extraction mode (-x)\n");
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
    if (resolve_running_executable(argv[0], self) < 0) {
        perror("dlfreeze: cannot resolve its executable path");
        free(exe_name); free(exe_path); free(file_patterns);
        return 1;
    }

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
        const char *inherited_preload = getenv("LD_PRELOAD");
        const char *inherited_audit = getenv("LD_AUDIT");
        char *preload = NULL;

        /* A caller-supplied loader injection changes the target's initial
         * namespace before the trace helper can observe every source (audit
         * DSOs may live in a separate namespace).  Do not conflate those
         * effects with the target's resolved startup graph. */
        if ((inherited_preload && inherited_preload[0]) ||
            (inherited_audit && inherited_audit[0])) {
            fprintf(stderr,
                    "dlfreeze: -t does not admit inherited LD_PRELOAD or "
                    "LD_AUDIT injection\n");
            trace_failed = 1;
        }
        if (!trace_failed)
            preload = find_compatible_preload(self, &deps, verbose);
        if (!preload) {
            if (!trace_failed)
                fprintf(stderr,
                        "dlfreeze: -t has no ABI-compatible preload helper; "
                        "syscall tracing cannot recover exact dlopen "
                        "requests\n");
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
            char tracef[PATH_MAX];
            int collector_fd = -1;
            int tfd = make_trace_tempfile(tracef, sizeof(tracef),
                                          "dlfreeze-trace", &collector_fd);
            if (tfd < 0) {
                perror("mkstemp");
                trace_failed = 1;
            } else if (prepare_trace_descriptor(tfd) < 0) {
                perror("prepare trace descriptor");
                close(tfd);
                close(collector_fd);
                trace_failed = 1;
            } else {
                printf("Tracing dlopen calls …\n");

                sigset_t forward_set, old_mask;
                build_trace_signal_set(&forward_set);
                if (sigprocmask(SIG_BLOCK, &forward_set, &old_mask) < 0) {
                    perror("sigprocmask");
                    close(tfd);
                    close(collector_fd);
                    trace_failed = 1;
                } else {
                    pid_t pid = fork();

                    if (pid == 0) {
                        if (sigprocmask(SIG_SETMASK, &old_mask, NULL) < 0)
                            _exit(127);
                        /* Preserve foreground terminal ownership for traced
                         * interactive programs; see capture_data_files(). */
                        if (prepend_ld_preload(preload) < 0 ||
                            set_trace_owner_environment() < 0 ||
                            set_trace_descriptor_environment(
                                tfd, "DLFREEZE_TRACE_FD",
                                "DLFREEZE_TRACE_IDENTITY") < 0 ||
                            unsetenv("DLFREEZE_TRACE_FILE") < 0 ||
                            unsetenv("DLFREEZE_FILE_TRACE_FILE") < 0 ||
                            unsetenv("DLFREEZE_FILE_TRACE_FD") < 0 ||
                            unsetenv("DLFREEZE_FILE_TRACE_IDENTITY") < 0)
                            _exit(127);

                        int tstart = optind + 1; /* args after executable */
                        int nargs = 1 + (argc - tstart);
                        char **tav = calloc((size_t)nargs + 1,
                                           sizeof(char *));
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
                        close(tfd);
                        close(collector_fd);
                        trace_failed = 1;
                    } else {
                        int st;

                        /* Drop the collector's copy of the helper OFD before
                         * waiting, or a descendant-liveness lock could never
                         * distinguish parent ownership from target ownership. */
                        close(tfd);
                        tfd = -1;
                        if (supervise_trace_child(pid, &forward_set,
                                                  &old_mask, &st) < 0) {
                            perror("waitpid");
                            close(collector_fd);
                            collector_fd = -1;
                            trace_failed = 1;
                        } else {
                            if (verbose)
                                printf("trace exit status: %d\n",
                                       WIFEXITED(st) ? WEXITSTATUS(st) : -1);
                            if (verbose)
                                dump_trace_fd(collector_fd, "traced:");
                            if (!WIFEXITED(st) ||
                                !trace_fd_has_header(
                                    collector_fd,
                                    "#DLFREEZE_DLOPEN_TRACE_V8")) {
                                fprintf(
                                    stderr,
                                    "dlfreeze: preload trace helper is "
                                    "incompatible with the target runtime "
                                    "or produced no valid V8 readiness "
                                    "record\n");
                                trace_failed = 1;
                                close(collector_fd);
                                collector_fd = -1;
                            } else {
                                if (dep_add_dlopen_libs_fd(
                                        &deps, collector_fd) < 0)
                                    trace_failed = 1;
                                collector_fd = -1;
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
