/*
 * dlfreeze bootstrap – statically-linked runtime stub.
 *
 * This small binary IS the frozen executable.  It:
 *   1. Reads the embedded payload from its mapped PT_LOAD segment, with
 *      /proc/self/exe retained only as a compatibility fallback
 *   2. If direct-load metadata is present, maps libraries in-process
 *      and transfers control without ld.so (no tmpdir).
 *   3. Otherwise, extracts all files to a temporary directory and
 *      forks: child execve()s the real program via the bundled ld.so,
 *      parent waits and cleans up the tmpdir.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <stdint.h>
#include <elf.h>

#include "common.h"
#include "load_segments.h"
#include "loader.h"

/*
 * Reserve one program-header slot for the packer to turn into the payload
 * PT_LOAD.  Do not rely on a toolchain-provided build-id or property note:
 * several perfectly valid static musl linkers emit neither.  The reference
 * from main keeps this allocatable note alive under --gc-sections.
 *
 * The descriptor is intentionally a private marker rather than runtime
 * metadata.  It remains covered by the bootstrap's ordinary read-only LOAD;
 * only its PT_NOTE program header is repurposed in the frozen output.
 */
extern const unsigned char dlfrz_payload_note[];
__asm__(
#if defined(__aarch64__)
    ".pushsection .note.dlfreeze.payload,\"a\",%note\n"
#else
    ".pushsection .note.dlfreeze.payload,\"a\",@note\n"
#endif
    ".balign 4\n"
    ".global dlfrz_payload_note\n"
    "dlfrz_payload_note:\n"
    ".long 8\n"                 /* n_namesz */
    ".long 8\n"                 /* n_descsz */
    ".long 0x44504c44\n"        /* private note type: DPLD */
    ".ascii \"DLFREEZE\"\n"    /* note owner */
    ".balign 4\n"
    ".ascii \"DLFRZPLD\"\n"    /* descriptor / packer marker */
    ".balign 4\n"
    ".popsection\n");

/* Packer scans the binary for this sentinel and patches it. */
static volatile struct dlfrz_loader_info g_loader_info
    __attribute__((used, section(".data")))
    = { {'D','L','F','R','Z','L','D','R'}, 0, 0, 0 };

/* ---- globals ----------------------------------------------------- */
static volatile pid_t g_child;
static volatile sig_atomic_t g_forwarded_signal;
static char g_tmpdir[PATH_MAX];
static int g_tmpdir_fd = -1;
static int g_tmp_parent_fd = -1;
static dev_t g_tmpdir_dev;
static ino_t g_tmpdir_ino;
static uint64_t g_tmpdir_mount_id;
static int g_tmpdir_mount_id_valid;
static int g_bootstrap_secure_mode;
extern char **environ;

static int fdinfo_mount_id(int fd, uint64_t *mount_id)
{
    char path[64];
    char *line = NULL;
    size_t line_capacity = 0;
    FILE *stream;
    int info_fd;
    int path_len;
    int result = -1;
    int saved_errno = ENOENT;

    path_len = snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
    if (path_len < 0 || (size_t)path_len >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    info_fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (info_fd < 0)
        return -1;
    stream = fdopen(info_fd, "r");
    if (!stream) {
        saved_errno = errno;
        close(info_fd);
        errno = saved_errno;
        return -1;
    }

    for (;;) {
        static const char field[] = "mnt_id:";
        ssize_t line_length = getline(&line, &line_capacity, stream);
        char *end;
        char *value;
        uint64_t parsed = 0;

        if (line_length < 0)
            break;
        end = line + (size_t)line_length;
        if (end > line && end[-1] == '\n')
            end--;
        if ((size_t)(end - line) < sizeof(field) - 1 ||
            memcmp(line, field, sizeof(field) - 1) != 0)
            continue;
        value = line + sizeof(field) - 1;
        while (value < end && (*value == ' ' || *value == '\t'))
            value++;
        if (value == end) {
            saved_errno = EINVAL;
            goto out;
        }
        while (value < end && *value >= '0' && *value <= '9') {
            unsigned digit = (unsigned)(*value - '0');

            if (parsed > (UINT64_MAX - digit) / 10) {
                saved_errno = EOVERFLOW;
                goto out;
            }
            parsed = parsed * 10 + digit;
            value++;
        }
        if (value != end) {
            saved_errno = EINVAL;
            goto out;
        }
        *mount_id = parsed;
        result = 0;
        break;
    }
    if (result < 0 && ferror(stream))
        saved_errno = errno ? errno : EIO;

out:
    free(line);
    if (fclose(stream) != 0 && result == 0) {
        result = -1;
        saved_errno = errno;
    }
    if (result < 0)
        errno = saved_errno;
    return result;
}

static int fd_mount_id(int fd, uint64_t *mount_id)
{
#if defined(SYS_statx) && defined(STATX_MNT_ID) && defined(AT_EMPTY_PATH)
    struct statx mount_st;

    memset(&mount_st, 0, sizeof(mount_st));
    if (syscall(SYS_statx, fd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW,
                STATX_MNT_ID, &mount_st) == 0 &&
        (mount_st.stx_mask & STATX_MNT_ID) != 0) {
        *mount_id = mount_st.stx_mnt_id;
        return 0;
    }
#endif
    /* Linux exposed mount IDs through /proc/self/fdinfo before statx grew
     * STATX_MNT_ID.  Keep cleanup mount-bounded on older kernels, older libc
     * headers, and seccomp profiles that reject statx. */
    return fdinfo_mount_id(fd, mount_id);
}

#if defined(NSIG)
#define FORWARD_SIGNAL_CAPACITY NSIG
#elif defined(_NSIG)
#define FORWARD_SIGNAL_CAPACITY _NSIG
#else
/* Linux exposes signals 1..64 on every supported architecture. */
#define FORWARD_SIGNAL_CAPACITY 65
#endif

static int signal_can_report_synchronous_fault(int sig)
{
    return sig == SIGILL || sig == SIGTRAP || sig == SIGBUS ||
           sig == SIGFPE || sig == SIGSEGV || sig == SIGSYS;
}

/* Every catchable Linux signal except SIGCHLD is application-visible when it
 * is sent to the wrapper process.  Fault-number signals need special handling
 * below because those same numbers can also originate synchronously inside
 * the supervisor. */
static int signal_should_forward(int sig)
{
    switch (sig) {
    case SIGHUP:
    case SIGINT:
    case SIGQUIT:
    case SIGILL:
    case SIGTRAP:
    case SIGABRT:
    case SIGBUS:
    case SIGFPE:
    case SIGUSR1:
    case SIGSEGV:
    case SIGUSR2:
    case SIGPIPE:
    case SIGALRM:
    case SIGTERM:
#ifdef SIGSTKFLT
    case SIGSTKFLT:
#endif
    case SIGCONT:
    case SIGTSTP:
    case SIGTTIN:
    case SIGTTOU:
    case SIGURG:
    case SIGXCPU:
    case SIGXFSZ:
    case SIGVTALRM:
    case SIGPROF:
    case SIGWINCH:
#ifdef SIGIO
    case SIGIO:
#endif
#ifdef SIGPWR
    case SIGPWR:
#endif
    case SIGSYS:
        return 1;
    default:
        break;
    }
#if defined(SIGRTMIN) && defined(SIGRTMAX)
    if (sig >= SIGRTMIN && sig <= SIGRTMAX)
        return 1;
#endif
    return 0;
}

/* SA_RESETHAND protects the supervisor from retrying a real synchronous
 * fault.  For an asynchronously sent fault-number signal the handler rearms
 * this immutable action before forwarding, so repeated application signals
 * retain the same semantics.  sigaction() is async-signal-safe. */
static struct sigaction g_fault_forward_action;

/* ---- tmpdir selection -------------------------------------------- */
static int make_workdir(char *out, size_t out_sz)
{
    static const char tmp_prefix[] = "/tmp/";
    const char *name;
    struct stat path_st;
    mode_t old_umask;
    int n;

    if (g_tmpdir_fd >= 0 || g_tmp_parent_fd >= 0) {
        errno = EBUSY;
        return -1;
    }
    g_tmp_parent_fd = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                   O_NOFOLLOW);
    if (g_tmp_parent_fd < 0)
        return -1;

    n = snprintf(out, out_sz, "/tmp/dlfreeze.XXXXXX");
    if (n < 0 || (size_t)n >= out_sz) {
        close(g_tmp_parent_fd);
        g_tmp_parent_fd = -1;
        errno = ENAMETOOLONG;
        return -1;
    }
    /* mkdtemp applies the process umask to its requested 0700 mode.  A caller
     * is allowed to have a maximally restrictive umask, but that must not make
     * the bootstrap unable to reopen its own extraction root. */
    old_umask = umask(0077);
    char *created = mkdtemp(out);
    int mkdtemp_errno = errno;
    umask(old_umask);
    if (!created) {
        close(g_tmp_parent_fd);
        g_tmp_parent_fd = -1;
        errno = mkdtemp_errno;
        return -1;
    }

    name = out;
    if (strncmp(name, tmp_prefix, sizeof(tmp_prefix) - 1) == 0)
        name += sizeof(tmp_prefix) - 1;
    g_tmpdir_fd = openat(g_tmp_parent_fd, name,
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (g_tmpdir_fd < 0 || fstat(g_tmpdir_fd, &path_st) < 0) {
        int saved_errno = errno;

        if (g_tmpdir_fd >= 0)
            close(g_tmpdir_fd);
        g_tmpdir_fd = -1;
        (void)unlinkat(g_tmp_parent_fd, name, AT_REMOVEDIR);
        close(g_tmp_parent_fd);
        g_tmp_parent_fd = -1;
        errno = saved_errno;
        return -1;
    }
    if (!S_ISDIR(path_st.st_mode)) {
        close(g_tmpdir_fd);
        g_tmpdir_fd = -1;
        (void)unlinkat(g_tmp_parent_fd, name, AT_REMOVEDIR);
        close(g_tmp_parent_fd);
        g_tmp_parent_fd = -1;
        errno = ENOTDIR;
        return -1;
    }
    g_tmpdir_dev = path_st.st_dev;
    g_tmpdir_ino = path_st.st_ino;
    g_tmpdir_mount_id_valid =
        fd_mount_id(g_tmpdir_fd, &g_tmpdir_mount_id) == 0;
    if (!g_tmpdir_mount_id_valid)
        g_tmpdir_mount_id = 0;
    return 0;
}

static int mkdirat_with_exact_mode(int dirfd, const char *name, mode_t mode)
{
    mode_t old_umask = umask(0);
    int rc = mkdirat(dirfd, name, mode);
    int saved_errno = errno;

    umask(old_umask);
    errno = saved_errno;
    return rc;
}

static int ensure_relative_directories(int rootfd, const char *path,
                                       int include_last)
{
    char *copy;
    char *component;
    int current_fd;

    if (!path || !path[0])
        return -1;
    copy = strdup(path);
    if (!copy)
        return -1;
    current_fd = openat(rootfd, ".",
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (current_fd < 0) {
        free(copy);
        return -1;
    }

    component = copy;
    for (;;) {
        char *separator = strchr(component, '/');
        int next_fd;

        if (!separator && !include_last)
            break;
        if (separator)
            *separator = '\0';
        if (!component[0] ||
            (mkdirat_with_exact_mode(current_fd, component, 0755) < 0 &&
             errno != EEXIST))
            goto fail;
        next_fd = openat(current_fd, component,
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next_fd < 0)
            goto fail;
        close(current_fd);
        current_fd = next_fd;
        if (!separator)
            break;
        component = separator + 1;
    }
    close(current_fd);
    free(copy);
    return 0;

fail:
    close(current_fd);
    free(copy);
    return -1;
}

/* ---- signal forwarding ------------------------------------------- */
static int is_job_control_signal(int sig)
{
    return sig == SIGCONT || sig == SIGTSTP ||
           sig == SIGTTIN || sig == SIGTTOU;
}

/* Linux reports terminal-driver broadcasts with SI_KERNEL.  Those signals
 * are delivered to every member of the foreground/background process group,
 * so forwarding them would deliver a duplicate to the supervised process.
 *
 * SI_KERNEL is not itself evidence of a process-group broadcast: inherited
 * interval timers also use it, and those timers remain attached to this
 * process across exec but are not inherited by the supervisor's fork child.
 * Such process-local kernel signals must still be forwarded. */
static int signal_is_terminal_group_broadcast(int sig)
{
    return sig == SIGHUP || sig == SIGINT || sig == SIGQUIT ||
           sig == SIGCONT || sig == SIGTSTP || sig == SIGTTIN ||
           sig == SIGTTOU || sig == SIGWINCH;
}

static void fwd_signal(int sig, siginfo_t *info, void *context)
{
    int saved_errno = errno;

    (void)context;

    /* Positive si_code values on these signal numbers describe a fault
     * raised by the kernel, not an asynchronous signal sent to the wrapper.
     * Do not misdeliver a bootstrap fault as an application event.  The
     * handler was installed with SA_RESETHAND, so queueing the same signal
     * makes the wrapper terminate natively after this handler returns; kill
     * the supervised child first so a loader/bootstrap fault cannot orphan
     * it. */
    if (info && info->si_code > 0 &&
        signal_can_report_synchronous_fault(sig)) {
        if (g_child > 0)
            (void)kill(g_child, SIGKILL);
        if (kill(getpid(), sig) < 0)
            _exit(128 + sig);
        errno = saved_errno;
        return;
    }
    if (signal_can_report_synchronous_fault(sig) &&
        sigaction(sig, &g_fault_forward_action, NULL) < 0) {
        if (g_child > 0)
            (void)kill(g_child, SIGKILL);
        _exit(128 + sig);
    }

    /* A stop/continue cycle is not an interrupted direct-load attempt. */
    if (!is_job_control_signal(sig))
        g_forwarded_signal = sig;

    /* The terminal driver sends these broadcasts to the entire process
     * group.  The application shares that group with this supervisor and has
     * therefore already received them.  Other SI_KERNEL sources can be
     * process-local and need forwarding just like process-directed signals. */
    if (g_child > 0 &&
        (!info || info->si_code != SI_KERNEL ||
         !signal_is_terminal_group_broadcast(sig)))
        kill(g_child, sig);
    errno = saved_errno;
}

static void build_forward_signal_set(sigset_t *set)
{
    sigemptyset(set);
    for (int sig = 1; sig < FORWARD_SIGNAL_CAPACITY; sig++)
        if (signal_should_forward(sig))
            sigaddset(set, sig);
}

static int install_forward_signal_handlers(struct sigaction *old_actions)
{
    struct sigaction action;
    int failed_signal = FORWARD_SIGNAL_CAPACITY;

    memset(&action, 0, sizeof(action));
    action.sa_sigaction = fwd_signal;
    sigemptyset(&action.sa_mask);

    for (int sig = 1; sig < FORWARD_SIGNAL_CAPACITY; sig++) {
        if (!signal_should_forward(sig))
            continue;
        action.sa_flags = SA_RESTART | SA_SIGINFO;
        if (signal_can_report_synchronous_fault(sig)) {
            action.sa_flags |= SA_RESETHAND;
            g_fault_forward_action = action;
        }
        if (sigaction(sig, &action, &old_actions[sig]) < 0) {
            failed_signal = sig;
            break;
        }
    }
    if (failed_signal == FORWARD_SIGNAL_CAPACITY)
        return 0;
    for (int sig = 1; sig < failed_signal; sig++)
        if (signal_should_forward(sig))
            sigaction(sig, &old_actions[sig], NULL);
    return -1;
}

static int fail_supervised_wait(pid_t child, const sigset_t *forward_set,
                                int failure_errno)
{
    int block_errno = 0;

    if (sigprocmask(SIG_BLOCK, forward_set, NULL) < 0)
        block_errno = errno;
    /* Clearing the forwarding target before reaping also makes the failure
     * path safe if blocking signals unexpectedly failed. */
    g_child = -1;
    (void)kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
    errno = failure_errno ? failure_errno : block_errno;
    return -1;
}

/* Wait for a supervised application without breaking shell job control.
 * The wrapper and application intentionally remain in the same process group
 * so they share the controlling terminal.  The wrapper catches stop signals
 * in order to forward process-directed delivery, but it must not remain alive
 * while the application is stopped: wait for proof of the child stop, then
 * stop ourselves.  The shell's later SIGCONT resumes the whole group.
 *
 * Observe terminal status without consuming it, then block forwarding and
 * clear g_child before waitpid() releases the PID.  This closes the otherwise
 * tiny window in which a signal handler could send to a recycled process ID.
 * The forwarding set remains blocked when this function returns. */
static int wait_for_supervised_child(pid_t child, int *status_out,
                                     const sigset_t *forward_set)
{
    for (;;) {
        siginfo_t observed;

        memset(&observed, 0, sizeof(observed));
        if (waitid(P_PID, (id_t)child, &observed,
                   WEXITED | WSTOPPED | WCONTINUED | WNOWAIT) < 0) {
            if (errno == EINTR)
                continue;
            return fail_supervised_wait(child, forward_set, errno);
        }
        if (observed.si_code == CLD_EXITED ||
            observed.si_code == CLD_KILLED ||
            observed.si_code == CLD_DUMPED) {
            int status;
            pid_t waited;

            if (sigprocmask(SIG_BLOCK, forward_set, NULL) < 0)
                return fail_supervised_wait(child, forward_set, errno);
            g_child = -1;
            do {
                waited = waitpid(child, &status, 0);
            } while (waited < 0 && errno == EINTR);
            if (waited != child)
                return -1;
            *status_out = status;
            return 0;
        }
        if (observed.si_code == CLD_STOPPED ||
            observed.si_code == CLD_TRAPPED) {
            siginfo_t consumed;

            memset(&consumed, 0, sizeof(consumed));
            while (waitid(P_PID, (id_t)child, &consumed, WSTOPPED) < 0) {
                if (errno != EINTR)
                    return fail_supervised_wait(child, forward_set, errno);
            }
            if (kill(getpid(), SIGSTOP) < 0) {
                return fail_supervised_wait(child, forward_set, errno);
            }
            continue;
        }
        if (observed.si_code == CLD_CONTINUED) {
            siginfo_t consumed;

            memset(&consumed, 0, sizeof(consumed));
            while (waitid(P_PID, (id_t)child, &consumed, WCONTINUED) < 0) {
                if (errno != EINTR)
                    return fail_supervised_wait(child, forward_set, errno);
            }
            continue;
        }
        return fail_supervised_wait(child, forward_set, EPROTO);
    }
}

static void restore_forward_signal_handlers(
    const struct sigaction *old_actions)
{
    for (int sig = 1; sig < FORWARD_SIGNAL_CAPACITY; sig++)
        if (signal_should_forward(sig))
            sigaction(sig, &old_actions[sig], NULL);
}

/* SIG_IGN and SA_NOCLDWAIT make Linux auto-reap children.  A frozen program
 * is allowed to inherit either setting, but the wrapper itself must override
 * it while it owns a supervisor child.  The child restores the exact incoming
 * action before loader handoff/exec so application-visible disposition is not
 * changed.  Callers block SIGCHLD across this transition and fork. */
static int install_waitable_sigchld(struct sigaction *old_action)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    return sigaction(SIGCHLD, &action, old_action);
}

static int restore_inherited_sigchld(const struct sigaction *old_action)
{
    return sigaction(SIGCHLD, old_action, NULL);
}

static void reraise_child_signal(int signal_number)
{
    struct sigaction action;
    sigset_t unblocked;

    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    sigaction(signal_number, &action, NULL);

    sigemptyset(&unblocked);
    sigaddset(&unblocked, signal_number);
    sigprocmask(SIG_UNBLOCK, &unblocked, NULL);
    raise(signal_number);
}

/* ---- extraction-directory cleanup -------------------------------- */
static int same_file_identity(const struct stat *st, dev_t dev, ino_t ino)
{
    return st->st_dev == dev && st->st_ino == ino;
}

static int directory_is_on_workdir_mount(int fd)
{
    uint64_t mount_id;

    return g_tmpdir_mount_id_valid && fd_mount_id(fd, &mount_id) == 0 &&
           mount_id == g_tmpdir_mount_id;
}

#define CLEANUP_INITIAL_DEPTH 16

struct cleanup_directory_frame {
    DIR *directory;
    char *name_in_parent;
    dev_t dev;
    ino_t ino;
};

static void empty_directory_fd(int rootfd)
{
    struct cleanup_directory_frame *frames;
    size_t capacity = CLEANUP_INITIAL_DEPTH;
    size_t depth = 0;
    int scanfd = fcntl(rootfd, F_DUPFD_CLOEXEC, 0);

    if (scanfd < 0)
        return;
    frames = calloc(capacity, sizeof(*frames));
    if (!frames) {
        close(scanfd);
        return;
    }
    frames[0].directory = fdopendir(scanfd);
    if (!frames[0].directory) {
        close(scanfd);
        free(frames);
        return;
    }
    depth = 1;

    while (depth != 0) {
        struct cleanup_directory_frame *frame = &frames[depth - 1];
        int current_fd = dirfd(frame->directory);
        struct dirent *entry = current_fd >= 0
            ? readdir(frame->directory) : NULL;

        if (entry) {
            struct stat before;
            struct stat opened;
            int childfd;
            DIR *child_directory;
            char *child_name;

            if (entry->d_name[0] == '.' &&
                (entry->d_name[1] == '\0' ||
                 (entry->d_name[1] == '.' && entry->d_name[2] == '\0')))
                continue;
            if (fstatat(current_fd, entry->d_name, &before,
                        AT_SYMLINK_NOFOLLOW) < 0)
                continue;
            if (!S_ISDIR(before.st_mode)) {
                (void)unlinkat(current_fd, entry->d_name, 0);
                continue;
            }

            childfd = openat(current_fd, entry->d_name,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (childfd < 0)
                continue;
            if (fstat(childfd, &opened) < 0 ||
                !directory_is_on_workdir_mount(childfd) ||
                !same_file_identity(&opened, before.st_dev, before.st_ino)) {
                close(childfd);
                continue;
            }
            if (depth == capacity) {
                struct cleanup_directory_frame *grown;
                size_t new_capacity;

                if (capacity > SIZE_MAX / 2 / sizeof(*frames)) {
                    close(childfd);
                    continue;
                }
                new_capacity = capacity * 2;
                grown = realloc(frames, new_capacity * sizeof(*frames));
                if (!grown) {
                    close(childfd);
                    continue;
                }
                memset(grown + capacity, 0,
                       (new_capacity - capacity) * sizeof(*grown));
                frames = grown;
                capacity = new_capacity;
            }
            child_name = strdup(entry->d_name);
            if (!child_name) {
                close(childfd);
                continue;
            }
            child_directory = fdopendir(childfd);
            if (!child_directory) {
                close(childfd);
                free(child_name);
                continue;
            }

            frames[depth].directory = child_directory;
            frames[depth].name_in_parent = child_name;
            frames[depth].dev = opened.st_dev;
            frames[depth].ino = opened.st_ino;
            depth++;
            continue;
        }

        {
            char *name = frame->name_in_parent;
            dev_t dev = frame->dev;
            ino_t ino = frame->ino;

            (void)closedir(frame->directory);
            memset(frame, 0, sizeof(*frame));
            depth--;
            if (depth != 0) {
                struct stat current;
                int parent_fd = dirfd(frames[depth - 1].directory);

                if (parent_fd >= 0 &&
                    fstatat(parent_fd, name, &current,
                            AT_SYMLINK_NOFOLLOW) == 0 &&
                    S_ISDIR(current.st_mode) &&
                    same_file_identity(&current, dev, ino))
                    (void)unlinkat(parent_fd, name, AT_REMOVEDIR);
            }
            free(name);
        }
    }
    free(frames);
}

static void cleanup_workdir(void)
{
    struct stat current;
    const char *name = strrchr(g_tmpdir, '/');

    if (g_tmpdir_fd >= 0) {
        empty_directory_fd(g_tmpdir_fd);
        close(g_tmpdir_fd);
        g_tmpdir_fd = -1;
    }
    if (g_tmp_parent_fd >= 0) {
        name = name ? name + 1 : g_tmpdir;
        if (name[0] &&
            fstatat(g_tmp_parent_fd, name, &current,
                    AT_SYMLINK_NOFOLLOW) == 0 &&
            S_ISDIR(current.st_mode) &&
            same_file_identity(&current, g_tmpdir_dev, g_tmpdir_ino))
            (void)unlinkat(g_tmp_parent_fd, name, AT_REMOVEDIR);
        close(g_tmp_parent_fd);
        g_tmp_parent_fd = -1;
    }
    g_tmpdir_mount_id = 0;
    g_tmpdir_mount_id_valid = 0;
}

/* ---- extract one embedded blob to a file ------------------------- */
static const char *bs_basename(const char *path)
{
    const char *base = path;
    while (*path) { if (*path == '/') base = path + 1; path++; }
    return base;
}

enum extraction_path_kind {
    EXTRACTION_PATH_NONE = 0,
    EXTRACTION_PATH_FILE,
    EXTRACTION_PATH_DIRECTORY
};

struct extraction_plan_entry {
    char *relative_path;
    char *full_path;
    char *alias_relative_path;
    char *alias_full_path;
    enum extraction_path_kind kind;
    int materialize;
    int executable;
    int alias_materialize;
    int alias_executable;
};

struct extraction_destination {
    const char *relative_path;
    enum extraction_path_kind kind;
    uint64_t data_offset;
    uint64_t data_size;
    size_t order;
    int *materialize;
    int *executable;
};

static void free_extraction_plan(struct extraction_plan_entry *plan,
                                 uint32_t count)
{
    if (!plan)
        return;
    for (uint32_t i = 0; i < count; i++) {
        free(plan[i].relative_path);
        free(plan[i].full_path);
        free(plan[i].alias_relative_path);
        free(plan[i].alias_full_path);
    }
    free(plan);
}

/* Convert an embedded path into one canonical path relative to the private
 * extraction root.  Canonicalization is also important for collision checks:
 * repeated separators must not create distinct strings for the same file. */
static int normalize_extraction_path(const char *input, size_t input_len,
                                     char **out)
{
    char *normalized;
    size_t read_pos = 0;
    size_t write_pos = 0;

    *out = NULL;
    if (!input || input_len == SIZE_MAX) {
        errno = EINVAL;
        return -1;
    }
    normalized = malloc(input_len + 1);
    if (!normalized)
        return -1;

    while (read_pos < input_len) {
        size_t component_start;
        size_t component_len;

        while (read_pos < input_len && input[read_pos] == '/')
            read_pos++;
        if (read_pos == input_len)
            break;
        component_start = read_pos;
        while (read_pos < input_len && input[read_pos] != '/')
            read_pos++;
        component_len = read_pos - component_start;
        if ((component_len == 1 && input[component_start] == '.') ||
            (component_len == 2 && input[component_start] == '.' &&
             input[component_start + 1] == '.')) {
            free(normalized);
            errno = EINVAL;
            return -1;
        }
        if (write_pos != 0)
            normalized[write_pos++] = '/';
        memcpy(normalized + write_pos, input + component_start,
               component_len);
        write_pos += component_len;
    }

    if (write_pos == 0) {
        free(normalized);
        errno = EINVAL;
        return -1;
    }
    normalized[write_pos] = '\0';
    *out = normalized;
    return 0;
}

static int size_add_checked(size_t left, size_t right, size_t *out)
{
    if (right > SIZE_MAX - left)
        return 0;
    *out = left + right;
    return 1;
}

static int join_extraction_root(const char *relative_path, char **out)
{
    size_t root_len = strlen(g_tmpdir);
    size_t relative_len = strlen(relative_path);
    size_t full_size;
    char *full_path;

    *out = NULL;
    if (!size_add_checked(root_len, 1, &full_size) ||
        !size_add_checked(full_size, relative_len, &full_size) ||
        !size_add_checked(full_size, 1, &full_size)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    full_path = malloc(full_size);
    if (!full_path)
        return -1;
    memcpy(full_path, g_tmpdir, root_len);
    full_path[root_len] = '/';
    memcpy(full_path + root_len + 1, relative_path, relative_len + 1);
    *out = full_path;
    return 0;
}

static int build_flat_relative_path(const char *name, char **out)
{
    const char *base;
    char *flat;

    if (!name || !name[0]) {
        errno = EINVAL;
        return -1;
    }
    /* Only the final component is materialized for extraction-mode objects.
     * Prefix components belong to the original request/source identity and
     * may legitimately include `.` or `..` (for example `./program`).  Do not
     * reject those harmless spellings, but never copy them into the private
     * extraction root. */
    base = bs_basename(name);
    if (!base[0] || strcmp(base, ".") == 0 || strcmp(base, "..") == 0) {
        errno = EINVAL;
        return -1;
    }
    flat = strdup(base);
    if (!flat)
        return -1;
    *out = flat;
    return 0;
}

static int extraction_destination_cmp(const void *left_ptr,
                                      const void *right_ptr)
{
    const struct extraction_destination *left = left_ptr;
    const struct extraction_destination *right = right_ptr;

    return strcmp(left->relative_path, right->relative_path);
}

static int size_multiply_checked(size_t left, size_t right, size_t *out)
{
    if (right != 0 && left > SIZE_MAX / right)
        return 0;
    *out = left * right;
    return 1;
}

static int extraction_destinations_conflict(
    struct extraction_destination *destinations, size_t count)
{
    /* Multiple logical manifest roles may intentionally share one embedded
     * object (for example, a runtime loader which is also libc).  Coalesce
     * only an exact shared manifest range: equal names or merely equal bytes
     * are not sufficient proof that a malformed artifact is unambiguous. */
    for (size_t begin = 0; begin < count;) {
        size_t end = begin + 1;
        size_t owner = begin;
        int executable = *destinations[begin].executable;

        while (end < count &&
               strcmp(destinations[begin].relative_path,
                      destinations[end].relative_path) == 0)
            end++;
        for (size_t i = begin + 1; i < end; i++) {
            if (destinations[i].kind != destinations[begin].kind ||
                (destinations[i].kind == EXTRACTION_PATH_FILE &&
                 (destinations[i].data_offset !=
                      destinations[begin].data_offset ||
                  destinations[i].data_size !=
                      destinations[begin].data_size)))
                return 1;
            if (destinations[i].order < destinations[owner].order)
                owner = i;
            executable = executable || *destinations[i].executable;
        }
        if (end - begin > 1) {
            for (size_t i = begin; i < end; i++) {
                *destinations[i].materialize = i == owner;
                *destinations[i].executable = executable;
            }
        }
        begin = end;
    }

    for (size_t i = 0; i < count; i++) {
        const char *path = destinations[i].relative_path;
        size_t path_len;
        size_t prefix_len;
        size_t low = 0;
        size_t high = count;
        char *prefix;

        if (destinations[i].kind == EXTRACTION_PATH_DIRECTORY)
            continue;
        path_len = strlen(path);
        if (path_len > SIZE_MAX - 2)
            return 1;
        prefix_len = path_len + 1;
        prefix = malloc(prefix_len + 1);
        if (!prefix)
            return -1;
        memcpy(prefix, path, path_len);
        prefix[path_len] = '/';
        prefix[prefix_len] = '\0';

        while (low < high) {
            size_t middle = low + (high - low) / 2;

            if (strcmp(destinations[middle].relative_path, prefix) < 0)
                low = middle + 1;
            else
                high = middle;
        }
        if (low < count &&
            strncmp(destinations[low].relative_path, prefix,
                    prefix_len) == 0) {
            free(prefix);
            return 1;
        }
        free(prefix);
    }
    return 0;
}

static int build_extraction_plan(const struct dlfrz_entry *entries,
                                 uint32_t count, const char *strtab,
                                 struct extraction_plan_entry **plan_out)
{
    struct extraction_plan_entry *plan = NULL;
    struct extraction_destination *destinations = NULL;
    size_t destination_count = 0;
    size_t destination_capacity;
    size_t allocation_size;
    int conflict;

    *plan_out = NULL;
    if (!size_multiply_checked((size_t)count, 2,
                               &destination_capacity) ||
        !size_multiply_checked((size_t)count, sizeof(*plan),
                               &allocation_size) ||
        !size_multiply_checked(destination_capacity, sizeof(*destinations),
                               &allocation_size)) {
        errno = EOVERFLOW;
        return -1;
    }
    plan = calloc(count, sizeof(*plan));
    destinations = calloc(destination_capacity, sizeof(*destinations));
    if (!plan || !destinations)
        goto fail;

    for (uint32_t i = 0; i < count; i++) {
        const char *name = strtab + entries[i].name_offset;
        size_t name_len = strlen(name);
        struct extraction_plan_entry *item = &plan[i];

        if ((entries[i].flags & DLFRZ_FLAG_DATA_NEGATIVE) != 0)
            continue;

        if ((entries[i].flags & DLFRZ_FLAG_DATA_DIRECTORY) != 0) {
            if (normalize_extraction_path(name, name_len,
                                          &item->relative_path) < 0 ||
                join_extraction_root(item->relative_path,
                                     &item->full_path) < 0)
                goto fail;
            item->kind = EXTRACTION_PATH_DIRECTORY;
            item->materialize = 1;
        } else if ((entries[i].flags & DLFRZ_FLAG_DATA_VIRTUAL) != 0) {
            /* Virtual placeholders carry identity only and have no
             * extraction-mode representation. */
            continue;
        } else {
            int use_full_path = name[0] == '/' &&
                (entries[i].flags & DLFRZ_FLAG_DLOPEN) != 0;

            if (use_full_path) {
                if (normalize_extraction_path(name, name_len,
                                              &item->relative_path) < 0)
                    goto fail;
            } else if (build_flat_relative_path(name,
                                                &item->relative_path) < 0) {
                goto fail;
            }
            if (join_extraction_root(item->relative_path,
                                     &item->full_path) < 0)
                goto fail;
            item->kind = EXTRACTION_PATH_FILE;
            item->materialize = 1;
            item->executable =
                (entries[i].flags &
                 (DLFRZ_FLAG_MAIN_EXE | DLFRZ_FLAG_INTERP)) != 0;

            if (use_full_path) {
                if (build_flat_relative_path(name,
                                             &item->alias_relative_path) < 0)
                    goto fail;
                if (strcmp(item->relative_path,
                           item->alias_relative_path) == 0) {
                    free(item->alias_relative_path);
                    item->alias_relative_path = NULL;
                } else if (join_extraction_root(item->alias_relative_path,
                                                &item->alias_full_path) < 0) {
                    goto fail;
                } else {
                    item->alias_materialize = 1;
                    item->alias_executable = item->executable;
                }
            }
        }

        destinations[destination_count].relative_path = item->relative_path;
        destinations[destination_count].kind = item->kind;
        destinations[destination_count].data_offset = entries[i].data_offset;
        destinations[destination_count].data_size = entries[i].data_size;
        destinations[destination_count].order = (size_t)i * 2;
        destinations[destination_count].materialize = &item->materialize;
        destinations[destination_count].executable = &item->executable;
        destination_count++;
        if (item->alias_relative_path) {
            destinations[destination_count].relative_path =
                item->alias_relative_path;
            destinations[destination_count].kind = EXTRACTION_PATH_FILE;
            destinations[destination_count].data_offset =
                entries[i].data_offset;
            destinations[destination_count].data_size = entries[i].data_size;
            destinations[destination_count].order = (size_t)i * 2 + 1;
            destinations[destination_count].materialize =
                &item->alias_materialize;
            destinations[destination_count].executable =
                &item->alias_executable;
            destination_count++;
        }
    }

    qsort(destinations, destination_count, sizeof(*destinations),
          extraction_destination_cmp);
    conflict = extraction_destinations_conflict(destinations,
                                                destination_count);
    if (conflict != 0) {
        if (conflict > 0)
            errno = EEXIST;
        goto fail;
    }

    free(destinations);
    *plan_out = plan;
    return 0;

fail:
    free(destinations);
    free_extraction_plan(plan, count);
    return -1;
}

static int bs_detect_secure_mode(char **envp)
{
    Elf64_auxv_t *auxv;

    if (!envp)
        return 1;
    while (*envp)
        envp++;
    auxv = (Elf64_auxv_t *)(envp + 1);
    for (size_t i = 0; i < 256; i++, auxv++) {
        if (auxv->a_type == AT_SECURE)
            return auxv->a_un.a_val != 0;
        if (auxv->a_type == AT_NULL)
            return 0;
    }
    /* A malformed initial stack must not enable environment controls. */
    return 1;
}

static int bs_env_enabled(const char *name)
{
    const char *value;

    if (g_bootstrap_secure_mode)
        return 0;
    value = getenv(name);
    return value && value[0] && value[0] != '0';
}

static int bs_execution_context_supported(void)
{
    /* Extraction relies on dynamic-loader environment controls which secure
     * execution ignores, while the direct loader does not yet claim the full
     * set-user-ID/set-group-ID loader contract.  Refuse the whole artifact
     * before selecting either path; silently falling through could load host
     * libraries or run a target with different privilege semantics. */
    return !g_bootstrap_secure_mode;
}

static int uint64_to_off_t(uint64_t value, off_t *out)
{
    off_t converted = (off_t)value;

    if (converted < 0 || (uint64_t)converted != value) {
        errno = EOVERFLOW;
        return -1;
    }
    *out = converted;
    return 0;
}

/* Read exactly one manifest-declared range without changing the shared file
 * offset.  Keep every individual request representable by ssize_t and reject
 * both premature EOF and offsets that the host ABI cannot express. */
static int full_pread(int fd, void *buffer, size_t size, uint64_t offset)
{
    unsigned char *out = buffer;
    size_t done = 0;

    while (done < size) {
        uint64_t current;
        off_t file_offset;
        size_t request = size - done;
        ssize_t len;

        if (done > UINT64_MAX - offset) {
            errno = EOVERFLOW;
            return -1;
        }
        current = offset + done;
        if (uint64_to_off_t(current, &file_offset) < 0)
            return -1;
        if (request > (size_t)SSIZE_MAX)
            request = (size_t)SSIZE_MAX;
        len = pread(fd, out + done, request, file_offset);

        if (len < 0 && errno == EINTR)
            continue;
        if (len < 0)
            return -1;
        if (len == 0) {
            errno = EIO;
            return -1;
        }
        done += (size_t)len;
    }
    return 0;
}

static int files_identical(const char *left, const char *right)
{
    int left_fd = -1, right_fd = -1;
    struct stat left_st, right_st;
    unsigned char left_buf[16384], right_buf[16384];
    int identical = 0;

    if (!left || !right || !left[0] || !right[0])
        return 0;
    left_fd = open(left, O_RDONLY | O_CLOEXEC);
    if (left_fd < 0)
        goto out;
    right_fd = open(right, O_RDONLY | O_CLOEXEC);
    if (right_fd < 0)
        goto out;
    if (fstat(left_fd, &left_st) < 0 || fstat(right_fd, &right_st) < 0 ||
        !S_ISREG(left_st.st_mode) || !S_ISREG(right_st.st_mode) ||
        left_st.st_size != right_st.st_size)
        goto out;

    for (off_t offset = 0; offset < left_st.st_size;) {
        size_t remaining = (size_t)(left_st.st_size - offset);
        size_t chunk = remaining < sizeof(left_buf) ? remaining
                                                   : sizeof(left_buf);
        int left_rc = full_pread(left_fd, left_buf, chunk, (uint64_t)offset);
        int right_rc = full_pread(right_fd, right_buf, chunk,
                                  (uint64_t)offset);

        if (left_rc < 0 || right_rc < 0 ||
            memcmp(left_buf, right_buf, chunk) != 0)
            goto out;
        offset += (off_t)chunk;
    }
    identical = 1;

out:
    if (left_fd >= 0)
        close(left_fd);
    if (right_fd >= 0)
        close(right_fd);
    return identical;
}

static int bs_debug_enabled(void)
{
    return bs_env_enabled("DLFREEZE_DEBUG");
}

static int write_all(int fd, const void *buffer, size_t size)
{
    const unsigned char *bytes = buffer;
    size_t done = 0;

    while (done < size) {
        ssize_t written = write(fd, bytes + done, size - done);

        if (written < 0 && errno == EINTR)
            continue;
        if (written < 0)
            return -1;
        if (written == 0) {
            errno = EIO;
            return -1;
        }
        done += (size_t)written;
    }
    return 0;
}

static void unlink_extraction_file(int rootfd, const char *relative_path)
{
    int rc;

    do {
        rc = unlinkat(rootfd, relative_path, 0);
    } while (rc < 0 && errno == EINTR);
}

/* Linux closes the descriptor even when close reports EINTR, so retrying can
 * accidentally close a subsequently reused descriptor.  Call it exactly once
 * and treat any reported error as a failed extraction. */
static int finish_extraction_file(int rootfd, const char *relative_path,
                                  int fd)
{
    if (close(fd) == 0)
        return 0;

    int saved_errno = errno;
    unlink_extraction_file(rootfd, relative_path);
    errno = saved_errno;
    return -1;
}

static int abandon_extraction_file(int rootfd, const char *relative_path,
                                   int fd, int failure_errno)
{
    int close_errno = 0;

    if (close(fd) < 0)
        close_errno = errno;
    unlink_extraction_file(rootfd, relative_path);
    errno = failure_errno ? failure_errno :
            (close_errno ? close_errno : EIO);
    return -1;
}

static int extract(int srcfd, int rootfd, const char *relative_path,
                   uint64_t off, uint64_t sz, int exec)
{
    int dfd;

    if (ensure_relative_directories(rootfd, relative_path, 0) < 0)
        return -1;
    dfd = openat(rootfd, relative_path,
                 O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                 exec ? 0755 : 0644);
    if (dfd < 0)
        return -1;
    int chmod_rc;
    do {
        chmod_rc = fchmod(dfd, exec ? 0755 : 0644);
    } while (chmod_rc < 0 && errno == EINTR);
    if (chmod_rc < 0) {
        int saved_errno = errno;
        return abandon_extraction_file(rootfd, relative_path, dfd,
                                       saved_errno);
    }

    char buf[65536];
    uint64_t rem = sz;
    uint64_t source_offset = off;
    while (rem > 0) {
        size_t want = rem > sizeof(buf) ? sizeof(buf) : rem;
        if (full_pread(srcfd, buf, want, source_offset) < 0) {
            int saved_errno = errno;
            return abandon_extraction_file(rootfd, relative_path, dfd,
                                           saved_errno);
        }
        if (write_all(dfd, buf, want) < 0) {
            int saved_errno = errno;
            return abandon_extraction_file(rootfd, relative_path, dfd,
                                           saved_errno);
        }
        source_offset += want;
        rem -= want;
    }
    return finish_extraction_file(rootfd, relative_path, dfd);
}

/* ---- extract from memory (UPX path) to a file -------------------- */
static int extract_mem(const uint8_t *base, uint64_t base_foff, int rootfd,
                       const char *relative_path, uint64_t off, uint64_t sz,
                       int exec)
{
    int dfd;

    if (ensure_relative_directories(rootfd, relative_path, 0) < 0)
        return -1;
    dfd = openat(rootfd, relative_path,
                 O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                 exec ? 0755 : 0644);
    if (dfd < 0)
        return -1;
    int chmod_rc;
    do {
        chmod_rc = fchmod(dfd, exec ? 0755 : 0644);
    } while (chmod_rc < 0 && errno == EINTR);
    if (chmod_rc < 0) {
        int saved_errno = errno;
        return abandon_extraction_file(rootfd, relative_path, dfd,
                                       saved_errno);
    }
    const uint8_t *src = base + (off - base_foff);
    uint64_t rem = sz;
    while (rem > 0) {
        size_t want = rem > 65536 ? 65536 : rem;
        if (write_all(dfd, src, want) < 0) {
            int saved_errno = errno;
            return abandon_extraction_file(rootfd, relative_path, dfd,
                                           saved_errno);
        }
        src += want;
        rem -= want;
    }
    return finish_extraction_file(rootfd, relative_path, dfd);
}

static int payload_range_valid(uint64_t offset, uint64_t length,
                               uint64_t payload_offset,
                               uint64_t payload_size)
{
    uint64_t relative;

    if (offset < payload_offset)
        return 0;
    relative = offset - payload_offset;
    return relative <= payload_size && length <= payload_size - relative;
}

static int u64_add_checked(uint64_t left, uint64_t right, uint64_t *out)
{
    if (right > UINT64_MAX - left)
        return 0;
    *out = left + right;
    return 1;
}

static int u64_align_up_checked(uint64_t value, uint64_t align,
                                uint64_t *out)
{
    uint64_t mask;

    if (align == 0 || (align & (align - 1)) != 0)
        return 0;
    mask = align - 1;
    if (value > UINT64_MAX - mask)
        return 0;
    *out = (value + mask) & ~mask;
    return 1;
}

struct payload_file_range {
    uint64_t offset;
    uint64_t size;
};

enum payload_control_range_index {
    PAYLOAD_CONTROL_STRTAB,
    PAYLOAD_CONTROL_MANIFEST,
    PAYLOAD_CONTROL_FOOTER,
    PAYLOAD_CONTROL_COUNT
};

/* Empty manifest entries occupy no payload bytes.  Nonempty entry aliases
 * are intentional (the same pinned ELF may satisfy multiple manifest roles),
 * but a partial overlap has no canonical owner.  Loader-control tables are
 * never aliases, even when two malformed ranges happen to be identical. */
static int payload_ranges_compatible(const struct payload_file_range *left,
                                     const struct payload_file_range *right,
                                     int allow_exact_alias)
{
    uint64_t left_end;
    uint64_t right_end;

    if (left->size == 0 || right->size == 0)
        return 1;
    if (!u64_add_checked(left->offset, left->size, &left_end) ||
        !u64_add_checked(right->offset, right->size, &right_end))
        return 0;
    if (left_end <= right->offset || right_end <= left->offset)
        return 1;
    return allow_exact_alias && left->offset == right->offset &&
           left->size == right->size;
}

static int payload_file_range_cmp(const void *left_pointer,
                                  const void *right_pointer)
{
    const struct payload_file_range *left = left_pointer;
    const struct payload_file_range *right = right_pointer;

    if (left->offset < right->offset)
        return -1;
    if (left->offset > right->offset)
        return 1;
    if (left->size < right->size)
        return -1;
    if (left->size > right->size)
        return 1;
    return 0;
}

static int payload_control_ranges(
    const struct dlfrz_footer *footer, uint64_t payload_offset,
    uint64_t payload_size,
    struct payload_file_range controls[PAYLOAD_CONTROL_COUNT])
{
    uint64_t footer_offset;
    uint64_t manifest_size;

    if (!footer || payload_size < sizeof(*footer) ||
        !u64_add_checked(payload_offset,
                         payload_size - sizeof(*footer), &footer_offset))
        return 0;
    manifest_size = (uint64_t)footer->num_entries *
                    sizeof(struct dlfrz_entry);
    controls[PAYLOAD_CONTROL_STRTAB] =
        (struct payload_file_range){footer->strtab_offset,
                                    footer->strtab_size};
    controls[PAYLOAD_CONTROL_MANIFEST] =
        (struct payload_file_range){footer->manifest_offset, manifest_size};
    controls[PAYLOAD_CONTROL_FOOTER] =
        (struct payload_file_range){footer_offset, sizeof(*footer)};

    for (size_t i = 0; i < PAYLOAD_CONTROL_COUNT; i++) {
        if (!payload_range_valid(controls[i].offset, controls[i].size,
                                 payload_offset, payload_size))
            return 0;
        for (size_t j = 0; j < i; j++)
            if (!payload_ranges_compatible(&controls[i], &controls[j], 0))
                return 0;
    }
    return 1;
}

static int payload_entry_ranges_valid(
    const struct dlfrz_footer *footer, const struct dlfrz_entry *entries,
    uint64_t payload_offset, uint64_t payload_size)
{
    struct payload_file_range controls[PAYLOAD_CONTROL_COUNT];
    struct payload_file_range *occupied;
    size_t occupied_count = 0;
    int valid = 0;

    if (!footer || !entries ||
        !payload_control_ranges(footer, payload_offset, payload_size,
                                controls))
        return 0;
    occupied = malloc((size_t)footer->num_entries * sizeof(*occupied));
    if (!occupied)
        return 0;

    for (uint32_t i = 0; i < footer->num_entries; i++) {
        struct payload_file_range range = {
            entries[i].data_offset, entries[i].data_size
        };

        if (range.size == 0)
            continue;
        if (!payload_range_valid(range.offset, range.size,
                                 payload_offset, payload_size))
            goto out;
        for (size_t c = 0; c < PAYLOAD_CONTROL_COUNT; c++)
            if (!payload_ranges_compatible(&range, &controls[c], 0))
                goto out;
        occupied[occupied_count++] = range;
    }

    qsort(occupied, occupied_count, sizeof(*occupied),
          payload_file_range_cmp);
    for (size_t i = 1; i < occupied_count; i++)
        if (!payload_ranges_compatible(
                &occupied[i - 1], &occupied[i], 1))
            goto out;
    valid = 1;

out:
    free(occupied);
    return valid;
}

static int direct_payload_ranges_valid(
    const struct dlfrz_footer *footer, const struct dlfrz_entry *entries,
    uint64_t payload_offset, uint64_t payload_size,
    uint64_t metadata_offset, uint64_t metadata_size,
    uint64_t fixup_offset, uint64_t fixup_size)
{
    struct payload_file_range controls[PAYLOAD_CONTROL_COUNT];
    struct payload_file_range direct[2] = {
        {metadata_offset, metadata_size},
        {fixup_offset, fixup_size}
    };

    if (!footer || !entries || metadata_size == 0 ||
        !payload_control_ranges(footer, payload_offset, payload_size,
                                controls))
        return 0;
    for (size_t d = 0; d < 2; d++) {
        if (direct[d].size == 0)
            continue;
        if (!payload_range_valid(direct[d].offset, direct[d].size,
                                 payload_offset, payload_size))
            return 0;
        for (size_t c = 0; c < PAYLOAD_CONTROL_COUNT; c++)
            if (!payload_ranges_compatible(&direct[d], &controls[c], 0))
                return 0;
        for (uint32_t i = 0; i < footer->num_entries; i++) {
            struct payload_file_range entry = {
                entries[i].data_offset, entries[i].data_size
            };

            if (!payload_ranges_compatible(&direct[d], &entry, 0))
                return 0;
        }
    }
    return payload_ranges_compatible(&direct[0], &direct[1], 0);
}

static int embedded_address_aligned(const void *base, uint64_t base_foff,
                                    uint64_t file_offset, size_t alignment)
{
    uintptr_t address = (uintptr_t)base;
    uint64_t relative;

    if (alignment == 0 || file_offset < base_foff)
        return 0;
    relative = file_offset - base_foff;
    if (relative > UINTPTR_MAX - address)
        return 0;
    return (address + (uintptr_t)relative) % alignment == 0;
}

static int mapped_range_is_readable(uint64_t start_value, uint64_t size_value)
{
    extern char **environ;
    Elf64_auxv_t *auxv;
    uintptr_t phdr_address = 0;
    size_t phdr_count = 0;
    size_t phdr_size = 0;
    uintptr_t load_bias = 0;
    uint64_t end_value;

    if (start_value > UINTPTR_MAX || size_value == 0 ||
        size_value > UINT64_MAX - start_value)
        return 0;
    end_value = start_value + size_value;

    /* The kernel supplies the main executable's live program-header table on
     * the initial stack.  It is a stronger validation source than procfs and
     * remains available in mount namespaces/chroots without /proc. */
    char **env = environ;
    while (env && *env)
        env++;
    if (!env)
        return 0;
    auxv = (Elf64_auxv_t *)(env + 1);
    for (; auxv->a_type != AT_NULL; auxv++) {
        if (auxv->a_type == AT_PHDR)
            phdr_address = (uintptr_t)auxv->a_un.a_val;
        else if (auxv->a_type == AT_PHNUM)
            phdr_count = (size_t)auxv->a_un.a_val;
        else if (auxv->a_type == AT_PHENT)
            phdr_size = (size_t)auxv->a_un.a_val;
    }
    if (!phdr_address || phdr_count == 0 || phdr_count > UINT16_MAX ||
        phdr_size != sizeof(Elf64_Phdr) ||
        phdr_count > (UINTPTR_MAX - phdr_address) / phdr_size)
        return 0;

    const Elf64_Phdr *phdr = (const Elf64_Phdr *)phdr_address;
    for (size_t i = 0; i < phdr_count; i++) {
        if (phdr[i].p_type == PT_PHDR &&
            phdr_address >= phdr[i].p_vaddr) {
            load_bias = phdr_address - (uintptr_t)phdr[i].p_vaddr;
            break;
        }
    }

    /* Fixed-address static executables need no bias and commonly omit
     * PT_PHDR.  Static PIEs provide PT_PHDR, allowing the same check after
     * relocation by the kernel. */
    for (size_t i = 0; i < phdr_count; i++) {
        uint64_t segment_start;
        uint64_t segment_end;

        if (phdr[i].p_type != PT_LOAD || !(phdr[i].p_flags & PF_R) ||
            phdr[i].p_memsz == 0)
            continue;
        if (phdr[i].p_vaddr > UINT64_MAX - load_bias ||
            phdr[i].p_memsz >
                UINT64_MAX - (phdr[i].p_vaddr + load_bias))
            continue;
        segment_start = phdr[i].p_vaddr + load_bias;
        segment_end = segment_start + phdr[i].p_memsz;
        if (start_value >= segment_start && end_value <= segment_end)
            return 1;
    }
    return 0;
}

static int payload_descriptor_numbers_valid(uint64_t payload_vaddr,
                                            uint64_t payload_filesz,
                                            uint64_t payload_foff)
{
    return payload_vaddr != 0 && payload_foff != 0 &&
           payload_filesz >= sizeof(struct dlfrz_footer) &&
           payload_vaddr <= UINTPTR_MAX &&
           payload_vaddr % _Alignof(Elf64_Ehdr) == 0 &&
           payload_foff % _Alignof(Elf64_Ehdr) == 0 &&
           payload_filesz <= UINTPTR_MAX - (uintptr_t)payload_vaddr &&
           payload_filesz <= UINT64_MAX - payload_foff;
}

static int embedded_name_valid(const char *name)
{
    const char *base;

    if (!name || !name[0])
        return 0;
    base = bs_basename(name);
    return base[0] && strcmp(base, ".") != 0 && strcmp(base, "..") != 0;
}

enum manifest_string_role {
    MANIFEST_STRING_NAME,
    MANIFEST_STRING_LOGICAL_NAME,
    MANIFEST_STRING_DLOPEN_REQUEST,
};

struct manifest_string_ref {
    uint32_t offset;
    uint32_t entry_index;
    unsigned char role;
};

static int manifest_string_ref_compare(const void *left_pointer,
                                       const void *right_pointer)
{
    const struct manifest_string_ref *left = left_pointer;
    const struct manifest_string_ref *right = right_pointer;

    if (left->offset < right->offset)
        return -1;
    if (left->offset > right->offset)
        return 1;
    if (left->entry_index < right->entry_index)
        return -1;
    if (left->entry_index > right->entry_index)
        return 1;
    return (int)left->role - (int)right->role;
}

/* Manifest strings are emitted as complete, consecutive NUL-terminated
 * records.  Requiring every referenced offset to identify a record start
 * both removes ambiguous suffix identities and lets validation inspect each
 * distinct string once.  Without this canonical form, many entries can all
 * point into one long string and amplify a small artifact into O(N * L)
 * startup work. */
static int manifest_strings_are_valid(
    const struct dlfrz_footer *footer,
    const struct dlfrz_entry *entries, const char *strtab,
    struct manifest_string_ref *refs, size_t ref_count)
{
    size_t begin = 0;

    if (!footer || !entries || !strtab || !refs || ref_count == 0 ||
        strtab[footer->strtab_size - 1] != '\0')
        return 0;
    qsort(refs, ref_count, sizeof(*refs), manifest_string_ref_compare);

    while (begin < ref_count) {
        uint32_t offset = refs[begin].offset;
        const char *value;
        const char *terminator;
        size_t end = begin + 1;
        int nonempty;
        int has_slash;
        int valid_embedded_name;

        while (end < ref_count && refs[end].offset == offset)
            end++;
        if ((uint64_t)offset >= footer->strtab_size ||
            (offset != 0 && strtab[offset - 1] != '\0'))
            return 0;
        value = strtab + offset;
        terminator = memchr(value, '\0',
                            footer->strtab_size - (uint64_t)offset);
        if (!terminator)
            return 0;
        nonempty = terminator != value;
        has_slash = memchr(value, '/', (size_t)(terminator - value)) != NULL;
        valid_embedded_name = nonempty && embedded_name_valid(value);

        for (size_t i = begin; i < end; i++) {
            const struct dlfrz_entry *entry =
                &entries[refs[i].entry_index];
            uint32_t flags = entry->flags;

            switch ((enum manifest_string_role)refs[i].role) {
            case MANIFEST_STRING_NAME:
                if (!nonempty ||
                    ((flags & DLFRZ_FLAG_DATA) && value[0] != '/') ||
                    (!(flags & (DLFRZ_FLAG_DATA |
                                DLFRZ_FLAG_NEEDED_PATHFUL)) &&
                     !valid_embedded_name) ||
                    ((flags & DLFRZ_FLAG_NEEDED_PATHFUL) && !has_slash))
                    return 0;
                break;
            case MANIFEST_STRING_LOGICAL_NAME:
                if (!(flags & DLFRZ_FLAG_SHLIB) || !nonempty)
                    return 0;
                break;
            case MANIFEST_STRING_DLOPEN_REQUEST:
                if (!nonempty ||
                    !dlfrz_manifest_entry_flags_canonical(
                        flags, 1, has_slash))
                    return 0;
                break;
            default:
                return 0;
            }
        }
        begin = end;
    }
    return 1;
}

static int manifest_is_valid(const struct dlfrz_footer *footer,
                             const struct dlfrz_entry *entries,
                             const char *strtab,
                             uint64_t payload_offset,
                             uint64_t payload_size)
{
    uint32_t main_count = 0;
    uint32_t interp_count = 0;
    struct manifest_string_ref *refs = NULL;
    size_t ref_capacity;
    size_t ref_count = 0;
    int result = 0;

    if (!footer->strtab_size || footer->strtab_size > SIZE_MAX ||
        !payload_entry_ranges_valid(footer, entries,
                                    payload_offset, payload_size))
        return 0;

    ref_capacity = (size_t)footer->num_entries * 3;
    if (ref_capacity == 0)
        return 0;
    refs = malloc(ref_capacity * sizeof(*refs));
    if (!refs)
        return 0;

    for (uint32_t i = 0; i < footer->num_entries; i++) {
        uint32_t flags = entries[i].flags;
        uint32_t data_state = flags & (DLFRZ_FLAG_DATA_VIRTUAL |
                                       DLFRZ_FLAG_DATA_NEGATIVE |
                                       DLFRZ_FLAG_DATA_DIRECTORY);

        if (entries[i].name_offset >= footer->strtab_size)
            goto out;
        refs[ref_count++] = (struct manifest_string_ref) {
            entries[i].name_offset, i, MANIFEST_STRING_NAME
        };
        if (entries[i].logical_name_offset != 0) {
            if ((flags & DLFRZ_FLAG_SHLIB) == 0 ||
                entries[i].logical_name_offset >= footer->strtab_size)
                goto out;
            refs[ref_count++] = (struct manifest_string_ref) {
                entries[i].logical_name_offset, i,
                MANIFEST_STRING_LOGICAL_NAME
            };
        }
        if (entries[i].dlopen_request_offset != 0) {
            if (entries[i].dlopen_request_offset >= footer->strtab_size)
                goto out;
            refs[ref_count++] = (struct manifest_string_ref) {
                entries[i].dlopen_request_offset, i,
                MANIFEST_STRING_DLOPEN_REQUEST
            };
        } else if (!dlfrz_manifest_entry_flags_canonical(flags, 0, 0)) {
            goto out;
        }
        if ((data_state != 0)
                 ? (entries[i].data_offset != 0 ||
                    entries[i].data_size != 0)
                 : !payload_range_valid(entries[i].data_offset,
                                        entries[i].data_size,
                                        payload_offset, payload_size))
            goto out;
        if (entries[i].flags & DLFRZ_FLAG_MAIN_EXE)
            main_count++;
        if (entries[i].flags & DLFRZ_FLAG_INTERP)
            interp_count++;
    }
    result = main_count == 1 && interp_count <= 1 &&
             manifest_strings_are_valid(
                 footer, entries, strtab, refs, ref_count);

out:
    free(refs);
    return result;
}

static int direct_source_alias_role(uint32_t flags)
{
    uint32_t role = flags & (DLFRZ_FLAG_MAIN_EXE |
                             DLFRZ_FLAG_INTERP |
                             DLFRZ_FLAG_SHLIB |
                             DLFRZ_FLAG_DATA);

    return role == DLFRZ_FLAG_INTERP || role == DLFRZ_FLAG_SHLIB;
}

static int direct_object_source_alias(const struct dlfrz_entry *entries,
                                      uint32_t left, uint32_t right)
{
    return entries && direct_source_alias_role(entries[left].flags) &&
           direct_source_alias_role(entries[right].flags) &&
           entries[left].data_size != 0 &&
           entries[left].data_offset == entries[right].data_offset &&
           entries[left].data_size == entries[right].data_size;
}

static int direct_alias_geometry_matches(
    const struct dlfrz_lib_meta *left,
    const struct dlfrz_lib_meta *right)
{
    return left->base_addr == right->base_addr &&
           left->vaddr_lo == right->vaddr_lo &&
           left->vaddr_hi == right->vaddr_hi &&
           left->entry == right->entry &&
           left->phdr_file_off == right->phdr_file_off &&
           left->phdr_off == right->phdr_off &&
           left->phdr_num == right->phdr_num &&
           left->phdr_entsz == right->phdr_entsz &&
           ((left->flags ^ right->flags) & DLFRZ_FLAG_NEEDS_RTLD) == 0;
}

static int direct_entry_is_startup_mapped(
    const struct dlfrz_entry *entry,
    const struct dlfrz_lib_meta *meta)
{
    if (entry->flags & (DLFRZ_FLAG_INTERP | DLFRZ_FLAG_DATA))
        return 0;
    return !(entry->flags & DLFRZ_FLAG_DLOPEN) ||
           (meta->flags & DLFRZ_FLAG_DLOPEN_EARLY);
}

/* Exact source aliases may legitimately describe different lifecycle roles:
 * a startup DT_NEEDED object can also have one or more lazy/early dlopen
 * request aliases.  The startup object is always the relocation owner in
 * that case, independent of manifest order.  Two ordinary startup entries,
 * however, have equal ownership priority.  Require their prelink state and
 * fixup slice to agree so reordering a hostile manifest cannot select a
 * different interpretation of the shared mapped bytes.  DLOPEN entries are
 * already required above to carry no prelink state or fixups. */
static int direct_alias_runtime_state_matches(
    const struct dlfrz_lib_meta *left,
    const struct dlfrz_lib_meta *right)
{
    if ((left->flags | right->flags) & DLFRZ_FLAG_DLOPEN)
        return 1;
    return ((left->flags ^ right->flags) &
            (DLFRZ_FLAG_PRELINKED | DLFRZ_FLAG_RUNTIME_SCAN)) == 0 &&
           left->runtime_fixup_off == right->runtime_fixup_off &&
           left->runtime_fixup_count == right->runtime_fixup_count;
}

struct direct_source_ref {
    uint64_t data_offset;
    uint64_t data_size;
    uint32_t entry_index;
};

struct direct_reserved_interval {
    uint64_t lo;
    uint64_t hi;
};

struct direct_elf_summary {
    uint64_t tls_memsz;
    uint64_t tls_align;
    uint64_t reserved_lo;
    uint64_t reserved_hi;
};

struct direct_tls_event {
    uint64_t memsz;
    uint64_t align;
    uint32_t owner_index;
    int owner_priority;
};

static int direct_source_ref_cmp(const void *left_pointer,
                                 const void *right_pointer)
{
    const struct direct_source_ref *left = left_pointer;
    const struct direct_source_ref *right = right_pointer;

    if (left->data_offset < right->data_offset)
        return -1;
    if (left->data_offset > right->data_offset)
        return 1;
    if (left->data_size < right->data_size)
        return -1;
    if (left->data_size > right->data_size)
        return 1;
    if (left->entry_index < right->entry_index)
        return -1;
    if (left->entry_index > right->entry_index)
        return 1;
    return 0;
}

static int direct_reserved_interval_cmp(const void *left_pointer,
                                        const void *right_pointer)
{
    const struct direct_reserved_interval *left = left_pointer;
    const struct direct_reserved_interval *right = right_pointer;

    if (left->lo < right->lo)
        return -1;
    if (left->lo > right->lo)
        return 1;
    if (left->hi < right->hi)
        return -1;
    if (left->hi > right->hi)
        return 1;
    return 0;
}

static int direct_tls_event_cmp(const void *left_pointer,
                                const void *right_pointer)
{
    const struct direct_tls_event *left = left_pointer;
    const struct direct_tls_event *right = right_pointer;

    if (left->owner_priority < right->owner_priority)
        return -1;
    if (left->owner_priority > right->owner_priority)
        return 1;
    if (left->owner_index < right->owner_index)
        return -1;
    if (left->owner_index > right->owner_index)
        return 1;
    return 0;
}

static int direct_startup_owner_priority(
    const struct dlfrz_lib_meta *meta)
{
    if (meta->flags & DLFRZ_FLAG_MAIN_EXE)
        return 0;
    if (meta->flags & DLFRZ_FLAG_DLOPEN)
        return 2;
    return 1;
}

/* Keep this ordering identical to dl_manifest_startup_owner(): the main
 * object, then an ordinary startup identity, then an early dlopen identity;
 * manifest order breaks ties. */
static uint32_t direct_source_group_startup_owner(
    const struct direct_source_ref *refs, size_t begin, size_t end,
    const struct dlfrz_entry *entries,
    const struct dlfrz_lib_meta *metas)
{
    uint32_t owner = UINT32_MAX;
    int owner_priority = INT_MAX;

    for (size_t i = begin; i < end; i++) {
        uint32_t index = refs[i].entry_index;
        int priority;

        if (!direct_entry_is_startup_mapped(&entries[index], &metas[index]))
            continue;
        priority = direct_startup_owner_priority(&metas[index]);
        if (owner == UINT32_MAX || priority < owner_priority ||
            (priority == owner_priority && index < owner)) {
            owner = index;
            owner_priority = priority;
        }
    }
    return owner;
}

static int direct_elf_metadata_is_valid(
    const uint8_t *mem, uint64_t mem_foff,
    const struct dlfrz_entry *entry,
    const struct dlfrz_lib_meta *meta,
    uint64_t page_size, struct direct_elf_summary *summary)
{
    if (!mem || !entry || !meta || !summary ||
        page_size == 0 || (page_size & (page_size - 1)) != 0)
        return 0;
    if (entry->data_offset < mem_foff ||
        !embedded_address_aligned(mem, mem_foff, entry->data_offset,
                                  _Alignof(Elf64_Ehdr)) ||
        entry->data_size < sizeof(Elf64_Ehdr))
        return 0;

    const uint8_t *elf = mem + (entry->data_offset - mem_foff);
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf;
#if defined(__x86_64__)
        const uint16_t expected_machine = EM_X86_64;
#elif defined(__aarch64__)
        const uint16_t expected_machine = EM_AARCH64;
#else
#error "Unsupported architecture"
#endif

        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
            ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
            ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
            ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
            (ehdr->e_ident[EI_OSABI] != ELFOSABI_NONE &&
             ehdr->e_ident[EI_OSABI] != ELFOSABI_LINUX) ||
            ehdr->e_ident[EI_ABIVERSION] != 0 ||
            ehdr->e_version != EV_CURRENT ||
            ehdr->e_flags != 0 ||
            ehdr->e_machine != expected_machine ||
            (ehdr->e_type != ET_DYN && ehdr->e_type != ET_EXEC) ||
            (ehdr->e_type == ET_EXEC &&
             ((entry->flags & DLFRZ_FLAG_MAIN_EXE) == 0 ||
              meta->base_addr != 0)) ||
            (ehdr->e_type == ET_DYN && meta->base_addr == 0) ||
            ehdr->e_ehsize != sizeof(*ehdr) ||
            ehdr->e_phentsize != sizeof(Elf64_Phdr) ||
            ehdr->e_phnum == 0 || ehdr->e_phnum == PN_XNUM ||
            meta->phdr_num != ehdr->e_phnum ||
            meta->phdr_entsz != ehdr->e_phentsize ||
            ehdr->e_phoff > entry->data_size ||
            (uint64_t)ehdr->e_phnum >
                (entry->data_size - ehdr->e_phoff) / sizeof(Elf64_Phdr))
            return 0;
        for (size_t ident = EI_PAD; ident < EI_NIDENT; ident++)
            if (ehdr->e_ident[ident] != 0)
                return 0;

        /* e_phoff is not required to have Elf64_Phdr alignment.  Consume
         * the bounded file table as bytes and copy each entry into aligned
         * local storage before interpreting it. */
        const uint8_t *phdrs = elf + ehdr->e_phoff;
        uint64_t lo = UINT64_MAX;
        uint64_t hi = 0;
        uint64_t phdr_vaddr = UINT64_MAX;
        uint64_t tls_memsz = 0;
        uint64_t tls_align = 1;
        uint16_t tls_count = 0;
        uint16_t dynamic_count = 0;
        uint16_t gnu_stack_count = 0;
        uint16_t phdr_count = 0;
        int executable_stack = 0;
        int entry_is_executable = 0;
        int phdr_translation_ambiguous = 0;
        int phdr_translation_readable = 0;
        int saw_load_header = 0;
        /* Older GCC data-flow analysis does not reliably correlate the
         * have_tls_phdr guard with the whole-structure assignment below.
         * Keep the inactive state defined as well; it is never consumed, but
         * doing so makes that invariant explicit to every supported compiler. */
        Elf64_Phdr tls_phdr = {0};
        int have_tls_phdr = 0;
        Elf64_Phdr dynamic_phdr;
        int have_dynamic_phdr = 0;
        Elf64_Phdr self_phdr;
        int have_self_phdr = 0;
        uint64_t phdr_file_end;

        if (!u64_add_checked(
                ehdr->e_phoff,
                (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr),
                &phdr_file_end))
            return 0;

        for (uint16_t p = 0; p < ehdr->e_phnum; p++) {
            Elf64_Phdr ph_storage;
            const Elf64_Phdr *ph = &ph_storage;

            memcpy(&ph_storage, phdrs + (size_t)p * ehdr->e_phentsize,
                   sizeof(ph_storage));

            if (ph->p_type == PT_LOAD && ph->p_align > 1) {
                if ((ph->p_align & (ph->p_align - 1)) != 0 ||
                    (ph->p_vaddr & (ph->p_align - 1)) !=
                        (ph->p_offset & (ph->p_align - 1)))
                    return 0;
                /* A zero-sized PT_LOAD maps no pages and imposes no load
                 * bias alignment requirement. */
                if (ph->p_memsz != 0 &&
                    (meta->base_addr & (ph->p_align - 1)) != 0)
                    return 0;
            }
            if (ph->p_type == PT_PHDR) {
                if (++phdr_count != 1 || saw_load_header)
                    return 0;
                self_phdr = *ph;
                have_self_phdr = 1;
            }
            if (ph->p_type == PT_LOAD)
                saw_load_header = 1;
            if (ph->p_type == PT_TLS) {
                if (++tls_count != 1 ||
                    (ph->p_align > 1 &&
                     (ph->p_align & (ph->p_align - 1)) != 0))
                    return 0;
                tls_memsz = ph->p_memsz;
                tls_align = ph->p_align ? ph->p_align : 1;
                tls_phdr = *ph;
                have_tls_phdr = 1;
            }
            if (ph->p_type == PT_DYNAMIC) {
                if (++dynamic_count != 1)
                    return 0;
                dynamic_phdr = *ph;
                have_dynamic_phdr = 1;
            }
            if (ph->p_type == PT_GNU_STACK) {
                if (++gnu_stack_count != 1)
                    return 0;
                executable_stack = (ph->p_flags & PF_X) != 0;
            }
            if (ph->p_offset > entry->data_size ||
                ph->p_filesz > entry->data_size - ph->p_offset ||
                ph->p_memsz > UINT64_MAX - ph->p_vaddr)
                return 0;
            if ((ph->p_type == PT_LOAD || ph->p_type == PT_DYNAMIC ||
                 ph->p_type == PT_TLS) && ph->p_filesz > ph->p_memsz)
                return 0;
            if (ph->p_type != PT_LOAD)
                continue;

            if (ph->p_memsz == 0)
                continue;

            if ((entry->flags & DLFRZ_FLAG_MAIN_EXE) &&
                (ph->p_flags & PF_X) != 0 &&
                meta->entry >= ph->p_vaddr &&
                meta->entry - ph->p_vaddr < ph->p_filesz)
                entry_is_executable = 1;

            if (ph->p_vaddr < lo)
                lo = ph->p_vaddr;
            if (ph->p_vaddr + ph->p_memsz > hi)
                hi = ph->p_vaddr + ph->p_memsz;
            if (ehdr->e_phoff >= ph->p_offset &&
                phdr_file_end - ph->p_offset <= ph->p_filesz) {
                uint64_t candidate;

                if (!u64_add_checked(
                        ph->p_vaddr, ehdr->e_phoff - ph->p_offset,
                        &candidate))
                    return 0;
                if (phdr_vaddr != UINT64_MAX && phdr_vaddr != candidate)
                    phdr_translation_ambiguous = 1;
                else
                    phdr_vaddr = candidate;
                if (ph->p_flags & PF_R)
                    phdr_translation_readable = 1;
            }
        }

        if (!dlfrz_load_pages_do_not_overlap_bytes(
                phdrs, ehdr->e_phnum, ehdr->e_phentsize, page_size))
            return 0;
        if (have_dynamic_phdr &&
            !dlfrz_segment_is_contained_by_load_bytes(
                phdrs, ehdr->e_phnum, ehdr->e_phentsize,
                &dynamic_phdr))
            return 0;

        if (have_tls_phdr) {
            if ((tls_phdr.p_vaddr & (tls_align - 1)) !=
                (tls_phdr.p_offset & (tls_align - 1)))
                return 0;
            if (tls_phdr.p_filesz != 0) {
                int template_contained = 0;

                for (uint16_t p = 0; p < ehdr->e_phnum; p++) {
                    Elf64_Phdr load_storage;
                    const Elf64_Phdr *load = &load_storage;
                    uint64_t delta;

                    memcpy(&load_storage,
                           phdrs + (size_t)p * ehdr->e_phentsize,
                           sizeof(load_storage));

                    if (load->p_type != PT_LOAD ||
                        tls_phdr.p_vaddr < load->p_vaddr ||
                        tls_phdr.p_offset < load->p_offset)
                        continue;
                    delta = tls_phdr.p_vaddr - load->p_vaddr;
                    if (tls_phdr.p_offset - load->p_offset != delta ||
                        delta > load->p_filesz ||
                        tls_phdr.p_filesz > load->p_filesz - delta ||
                        delta > load->p_memsz ||
                        tls_phdr.p_filesz > load->p_memsz - delta)
                        continue;
                    template_contained = 1;
                    break;
                }
                if (!template_contained)
                    return 0;
            }
        }

        int phdr_has_canonical_mapping =
            phdr_vaddr != UINT64_MAX && phdr_translation_readable &&
            phdr_vaddr < DLFRZ_PHDR_EXTERNAL &&
            phdr_vaddr % _Alignof(Elf64_Phdr) == 0;
        int phdr_is_external = meta->phdr_off == DLFRZ_PHDR_EXTERNAL;

        if (lo >= hi || phdr_translation_ambiguous ||
            (have_self_phdr &&
             (!phdr_has_canonical_mapping ||
              self_phdr.p_offset != ehdr->e_phoff ||
              self_phdr.p_vaddr != phdr_vaddr ||
              self_phdr.p_filesz !=
                  (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr) ||
              self_phdr.p_memsz !=
                  (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr) ||
              !(self_phdr.p_flags & PF_R) ||
              (self_phdr.p_align > 1 &&
               ((self_phdr.p_align & (self_phdr.p_align - 1)) != 0 ||
                (self_phdr.p_vaddr & (self_phdr.p_align - 1)) !=
                    (self_phdr.p_offset &
                     (self_phdr.p_align - 1)))))) ||
            meta->vaddr_lo != lo || meta->vaddr_hi != hi ||
            meta->entry != ehdr->e_entry ||
            (phdr_has_canonical_mapping
                 ? (phdr_is_external || meta->phdr_file_off != 0 ||
                    meta->phdr_off != phdr_vaddr)
                 : (!phdr_is_external ||
                    meta->phdr_file_off != ehdr->e_phoff)) ||
            ((entry->flags & DLFRZ_FLAG_MAIN_EXE) &&
             !entry_is_executable) ||
            gnu_stack_count != 1 || executable_stack ||
            (meta->base_addr & (page_size - 1)) != 0 ||
            hi > UINT64_MAX - (page_size - 1) ||
            meta->base_addr >
                UINT64_MAX - ((hi + page_size - 1) & ~(page_size - 1)) ||
            meta->base_addr +
                ((hi + page_size - 1) & ~(page_size - 1)) >
                UINT64_MAX - 4 * page_size)
            return 0;

    summary->tls_memsz = tls_count != 0 ? tls_memsz : 0;
    summary->tls_align = tls_align;
    summary->reserved_lo = meta->base_addr +
                           (lo & ~(page_size - 1));
    summary->reserved_hi = meta->base_addr +
                           ((hi + page_size - 1) & ~(page_size - 1)) +
                           4 * page_size;
    return 1;
}

static int direct_metadata_is_valid(const uint8_t *mem, uint64_t mem_foff,
                                    const struct dlfrz_lib_meta *metas,
                                    const struct dlfrz_entry *entries,
                                    uint32_t num_entries,
                                    uint32_t runtime_fixup_count)
{
    const uint32_t entry_type_mask = DLFRZ_FLAG_MAIN_EXE |
                                     DLFRZ_FLAG_INTERP |
                                     DLFRZ_FLAG_SHLIB |
                                     DLFRZ_FLAG_DLOPEN |
                                     DLFRZ_FLAG_DATA |
                                     DLFRZ_FLAG_DLOPEN_PATHFUL |
                                     DLFRZ_FLAG_NEEDED_PATHFUL;
    const uint32_t metadata_flag_mask = entry_type_mask |
                                        DLFRZ_FLAG_PRELINKED |
                                        DLFRZ_FLAG_NEEDS_RTLD |
                                        DLFRZ_FLAG_RUNTIME_SCAN |
                                        DLFRZ_FLAG_DLOPEN_EARLY |
                                        DLFRZ_FLAG_DLOPEN_ROOT;
    struct direct_source_ref *refs = NULL;
    struct direct_reserved_interval *intervals = NULL;
    struct direct_tls_event *tls_events = NULL;
    size_t source_count = 0;
    size_t interval_count = 0;
    size_t tls_event_count = 0;
    uint32_t mapped_group_count = 0;
    long page_size_long;
    uint64_t page_size;
#if defined(__aarch64__)
    /* Both supported AArch64 TLS variants reserve two words above TP. */
    uint64_t total_tls = 16;
#else
    uint64_t total_tls = 0;
#endif
    int valid = 0;

    if (!mem || !metas || !entries || num_entries == 0)
        return 0;
    page_size_long = sysconf(_SC_PAGESIZE);
    if (page_size_long <= 0 ||
        ((uint64_t)page_size_long & ((uint64_t)page_size_long - 1)) != 0)
        return 0;
    page_size = (uint64_t)page_size_long;

    /* Validate role-specific state for every manifest identity before
     * collapsing shared immutable ELF sources.  DATA entries deliberately
     * remain outside the mapped-object view and may be high-cardinality. */
    for (uint32_t i = 0; i < num_entries; i++) {
        const struct dlfrz_entry *entry = &entries[i];
        const struct dlfrz_lib_meta *meta = &metas[i];

        if ((meta->flags & ~metadata_flag_mask) != 0 ||
            meta->_reserved != 0 ||
            (meta->flags & entry_type_mask) !=
                (entry->flags & entry_type_mask) ||
            ((meta->flags & (DLFRZ_FLAG_DLOPEN_EARLY |
                             DLFRZ_FLAG_DLOPEN_ROOT)) != 0 &&
             (meta->flags & (DLFRZ_FLAG_DLOPEN | DLFRZ_FLAG_SHLIB)) !=
                 (DLFRZ_FLAG_DLOPEN | DLFRZ_FLAG_SHLIB)) ||
            (((meta->flags & DLFRZ_FLAG_DLOPEN_ROOT) != 0) !=
             ((meta->flags & DLFRZ_FLAG_DLOPEN) != 0 &&
              entry->dlopen_request_offset != 0)) ||
            ((meta->flags & DLFRZ_FLAG_PRELINKED) != 0 &&
             (meta->flags & (DLFRZ_FLAG_INTERP |
                             DLFRZ_FLAG_DLOPEN |
                             DLFRZ_FLAG_DATA)) != 0) ||
            (((meta->flags & DLFRZ_FLAG_RUNTIME_SCAN) != 0) !=
             ((meta->flags & DLFRZ_FLAG_PRELINKED) != 0 &&
              meta->runtime_fixup_count != 0)) ||
            ((meta->flags & DLFRZ_FLAG_PRELINKED) == 0 &&
             (meta->runtime_fixup_off != 0 ||
              meta->runtime_fixup_count != 0)) ||
            (meta->runtime_fixup_count == 0 &&
             meta->runtime_fixup_off != 0) ||
            ((meta->flags & DLFRZ_FLAG_DLOPEN) != 0 &&
             (((meta->flags & (DLFRZ_FLAG_PRELINKED |
                               DLFRZ_FLAG_RUNTIME_SCAN)) != 0) ||
              meta->runtime_fixup_off != 0 ||
              meta->runtime_fixup_count != 0)) ||
            meta->runtime_fixup_off > runtime_fixup_count ||
            meta->runtime_fixup_count >
                runtime_fixup_count - meta->runtime_fixup_off)
            goto out;

        if ((entry->flags & DLFRZ_FLAG_DATA) != 0) {
            if (meta->flags != DLFRZ_FLAG_DATA ||
                meta->base_addr != 0 ||
                meta->vaddr_lo != 0 || meta->vaddr_hi != 0 ||
                meta->entry != 0 || meta->phdr_file_off != 0 ||
                meta->phdr_off != 0 ||
                meta->phdr_num != 0 || meta->phdr_entsz != 0 ||
                meta->runtime_fixup_off != 0 ||
                meta->runtime_fixup_count != 0)
                goto out;
            if (entry->data_size != 0)
                source_count++;
            continue;
        }

        source_count++;
    }
    if (source_count == 0)
        goto out;

    refs = malloc(source_count * sizeof(*refs));
    intervals = malloc(source_count * sizeof(*intervals));
    tls_events = malloc(source_count * sizeof(*tls_events));
    if (!refs || !intervals || !tls_events)
        goto out;
    {
        size_t ref_count = 0;

        for (uint32_t i = 0; i < num_entries; i++) {
            if ((entries[i].flags & DLFRZ_FLAG_DATA) &&
                entries[i].data_size == 0)
                continue;
            refs[ref_count++] = (struct direct_source_ref) {
                entries[i].data_offset, entries[i].data_size, i
            };
        }
        if (ref_count != source_count)
            goto out;
    }

    qsort(refs, source_count, sizeof(*refs), direct_source_ref_cmp);
    for (size_t begin = 0; begin < source_count;) {
        size_t end = begin + 1;
        uint32_t reference = refs[begin].entry_index;
        uint32_t ordinary_reference = UINT32_MAX;
        uint32_t owner;
        uint32_t representative;
        int dlopen_early_state = -1;
        struct direct_elf_summary summary;

        while (end < source_count &&
               refs[end].data_offset == refs[begin].data_offset &&
               refs[end].data_size == refs[begin].data_size)
            end++;

        /* One musl file may serve as both PT_INTERP and libc SHLIB.  Exact
         * nonempty ranges may otherwise alias only SHLIB identities; MAIN,
         * DATA, combined roles, and all unrelated kinds remain distinct. */
        if (end - begin > 1) {
            for (size_t i = begin + 1; i < end; i++)
                if (!direct_object_source_alias(
                        entries, reference, refs[i].entry_index))
                    goto out;
        }

        /* A nonempty regular DATA entry participates above only so exact
         * aliasing with an ELF role is rejected.  It is not an ELF object and
         * has no reserved virtual-address interval of its own. */
        if (entries[reference].flags & DLFRZ_FLAG_DATA) {
            begin = end;
            continue;
        }

        for (size_t i = begin; i < end; i++) {
            uint32_t index = refs[i].entry_index;
            const struct dlfrz_lib_meta *meta = &metas[index];

            if (!direct_alias_geometry_matches(&metas[reference], meta))
                goto out;
            if (meta->flags & DLFRZ_FLAG_INTERP) {
                continue;
            } else if ((meta->flags & DLFRZ_FLAG_DLOPEN) == 0) {
                if (ordinary_reference != UINT32_MAX &&
                    !direct_alias_runtime_state_matches(
                        &metas[ordinary_reference], meta))
                    goto out;
                ordinary_reference = index;
            } else {
                int early =
                    (meta->flags & DLFRZ_FLAG_DLOPEN_EARLY) != 0;

                if (dlopen_early_state >= 0 &&
                    dlopen_early_state != early)
                    goto out;
                dlopen_early_state = early;
            }
        }

        owner = direct_source_group_startup_owner(
            refs, begin, end, entries, metas);
        representative = owner != UINT32_MAX ? owner : reference;
        if ((entries[representative].flags & DLFRZ_FLAG_INTERP) == 0 &&
            ++mapped_group_count > DLFRZ_DIRECT_MAX_OBJECTS)
            goto out;
        if (!direct_elf_metadata_is_valid(
                mem, mem_foff, &entries[representative],
                &metas[representative], page_size, &summary))
            goto out;

        intervals[interval_count++] =
            (struct direct_reserved_interval) {
                summary.reserved_lo, summary.reserved_hi
            };
        if (owner != UINT32_MAX && summary.tls_memsz != 0) {
            tls_events[tls_event_count++] = (struct direct_tls_event) {
                summary.tls_memsz, summary.tls_align, owner,
                direct_startup_owner_priority(&metas[owner])
            };
        }
        begin = end;
    }

    qsort(intervals, interval_count, sizeof(*intervals),
          direct_reserved_interval_cmp);
    for (size_t i = 1; i < interval_count; i++)
        if (intervals[i].lo < intervals[i - 1].hi)
            goto out;

    /* Match the loader's startup object order when checking aggregate TLS:
     * main, ordinary objects, then promoted dlopen closures, with manifest
     * order inside each class. */
    qsort(tls_events, tls_event_count, sizeof(*tls_events),
          direct_tls_event_cmp);
    for (size_t i = 0; i < tls_event_count; i++) {
        uint64_t next_tls;

#if defined(__aarch64__)
        if (!u64_align_up_checked(total_tls, tls_events[i].align,
                                  &next_tls) ||
            !u64_add_checked(next_tls, tls_events[i].memsz, &total_tls))
            goto out;
#else
        if (!u64_add_checked(total_tls, tls_events[i].memsz, &next_tls) ||
            !u64_align_up_checked(next_tls, tls_events[i].align,
                                  &total_tls))
            goto out;
#endif
        if (total_tls > INT64_MAX)
            goto out;
    }

    valid = 1;
out:
    free(tls_events);
    free(intervals);
    free(refs);
    return valid;
}

enum extraction_fallback_refusal {
    EXTRACTION_FALLBACK_ALLOWED = 0,
    EXTRACTION_REFUSE_PRELINKED,
    EXTRACTION_REFUSE_DATA,
    EXTRACTION_REFUSE_PATHFUL_DLOPEN,
    EXTRACTION_REFUSE_PATHFUL_NEEDED,
    EXTRACTION_REFUSE_LOGICAL_NAME,
};

/* Extraction relocates every object beneath one private root.  A distinct
 * first-open name is therefore direct-only, except when the manifest proves
 * that the same nonempty payload is both PT_INTERP and SHLIB and the SHLIB's
 * logical-name record is exactly the interpreter's name record.  That object
 * is already present as the launched interpreter; its dependency spelling is
 * merely an additional lookup alias.  Compare offsets and payload ranges so
 * this remains linear even for adversarially large shared strings. */
static int manifest_has_unextractable_logical_names(
    const struct dlfrz_entry *entries, uint32_t count)
{
    uint32_t interp_index = UINT32_MAX;

    if (!entries)
        return 1;
    for (uint32_t i = 0; i < count; i++) {
        if ((entries[i].flags & DLFRZ_FLAG_INTERP) != 0) {
            interp_index = i;
            break;
        }
    }
    for (uint32_t i = 0; i < count; i++) {
        if (entries[i].logical_name_offset == 0)
            continue;
        if (interp_index == UINT32_MAX || entries[i].data_size == 0 ||
            entries[i].logical_name_offset !=
                entries[interp_index].name_offset ||
            entries[i].data_offset != entries[interp_index].data_offset ||
            entries[i].data_size != entries[interp_index].data_size)
            return 1;
    }
    return 0;
}

/* Direct startup only needs a supervisor while a failure before target
 * handoff can still be retried through extraction.  This one classification
 * drives both process selection and refusal diagnostics so a newly
 * direct-only manifest class cannot accidentally retain one behavior without
 * the other. */
static enum extraction_fallback_refusal classify_extraction_fallback(
    int prelinked_payload, int has_data_entries,
    int has_pathful_dlopen_entries, int has_pathful_needed_entries,
    int has_distinct_logical_names)
{
    if (prelinked_payload)
        return EXTRACTION_REFUSE_PRELINKED;
    if (has_data_entries)
        return EXTRACTION_REFUSE_DATA;
    if (has_pathful_dlopen_entries)
        return EXTRACTION_REFUSE_PATHFUL_DLOPEN;
    if (has_pathful_needed_entries)
        return EXTRACTION_REFUSE_PATHFUL_NEEDED;
    if (has_distinct_logical_names)
        return EXTRACTION_REFUSE_LOGICAL_NAME;
    return EXTRACTION_FALLBACK_ALLOWED;
}

static void report_extraction_fallback_refusal(
    enum extraction_fallback_refusal refusal)
{
    switch (refusal) {
    case EXTRACTION_REFUSE_PRELINKED:
        fprintf(stderr,
                "dlfreeze: refusing extraction fallback for a prelinked "
                "direct-load artifact\n");
        break;
    case EXTRACTION_REFUSE_DATA:
        fprintf(stderr,
                "dlfreeze: refusing extraction fallback for a captured-file "
                "artifact\n");
        break;
    case EXTRACTION_REFUSE_PATHFUL_DLOPEN:
        fprintf(stderr,
                "dlfreeze: refusing extraction fallback for a pathful traced "
                "dlopen artifact\n");
        break;
    case EXTRACTION_REFUSE_PATHFUL_NEEDED:
        fprintf(stderr,
                "dlfreeze: refusing extraction fallback for an artifact "
                "with pathful DT_NEEDED entries\n");
        break;
    case EXTRACTION_REFUSE_LOGICAL_NAME:
        fprintf(stderr,
                "dlfreeze: refusing extraction fallback for an artifact "
                "with separate logical load names\n");
        break;
    case EXTRACTION_FALLBACK_ALLOWED:
        break;
    }
}

/* ---- main -------------------------------------------------------- */
int main(int argc, char **argv)
{
    g_bootstrap_secure_mode = bs_detect_secure_mode(environ);
    if (!bs_execution_context_supported()) {
        fprintf(stderr,
                "dlfreeze-bootstrap: AT_SECURE execution is unsupported\n");
        return 127;
    }

    /* Force a relocation from live code to the reserved payload note. */
    __asm__ volatile("" : : "r"(dlfrz_payload_note) : "memory");

    /* Snapshot the packer-patched descriptor once.  Validate its live range
     * against the kernel-provided program headers before dereferencing it. */
    const uint64_t loader_payload_vaddr = g_loader_info.payload_vaddr;
    const uint64_t loader_payload_filesz = g_loader_info.payload_filesz;
    const uint64_t loader_payload_foff = g_loader_info.payload_foff;
    const int loader_descriptor_present = loader_payload_vaddr != 0 ||
        loader_payload_filesz != 0 || loader_payload_foff != 0;
    const int loader_descriptor_numeric_valid =
        payload_descriptor_numbers_valid(loader_payload_vaddr,
                                         loader_payload_filesz,
                                         loader_payload_foff);

    /* 1. Prefer the mapped payload.  Every current artifact carries it in a
     * dedicated readable PT_LOAD, so direct startup does not require procfs.
     * Reopen /proc/self/exe only for compatibility with older/unpatched
     * layouts whose mapped descriptor cannot be validated. */
    int sfd = -1;
    struct stat st;
    struct dlfrz_footer ft;
    int from_memory = 0;
    const uint8_t *mem_base = NULL;

    memset(&st, 0, sizeof(st));
    if (loader_descriptor_numeric_valid &&
        mapped_range_is_readable(loader_payload_vaddr,
                                 loader_payload_filesz)) {
        mem_base = (const uint8_t *)(uintptr_t)loader_payload_vaddr;
        const uint8_t *footer_ptr =
            mem_base + loader_payload_filesz - sizeof(ft);
        memcpy(&ft, footer_ptr, sizeof(ft));
        if (memcmp(ft.magic, DLFRZ_MAGIC, 8) == 0)
            from_memory = 1;
    }
    if (!from_memory) {
        /* Pin the actual executable rather than reopening a readlink string;
         * this remains safe across pathname replacement or unlink. */
        sfd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
        if (sfd < 0) {
            perror("/proc/self/exe");
            return 127;
        }
        if (fstat(sfd, &st) < 0) {
            perror("fstat"); close(sfd); return 127;
        }
        if (!S_ISREG(st.st_mode) || st.st_size < 0) {
            errno = EINVAL;
            perror("fstat"); close(sfd); return 127;
        }
        if (st.st_size < (off_t)sizeof(ft) ||
            full_pread(sfd, &ft, sizeof(ft),
                       (uint64_t)st.st_size - sizeof(ft)) < 0 ||
            memcmp(ft.magic, DLFRZ_MAGIC, 8) != 0) {
            fprintf(stderr, "dlfreeze-bootstrap: no embedded payload\n");
            close(sfd); return 127;
        }
    }

    if (ft.version != DLFRZ_VERSION) {
        fprintf(stderr, "dlfreeze-bootstrap: unsupported version %u\n", ft.version);
        close(sfd); return 127;
    }

    uint64_t payload_offset = 0;
    uint64_t payload_size = (uint64_t)st.st_size;
    if (from_memory) {
        payload_offset = loader_payload_foff;
        payload_size = loader_payload_filesz;
    } else if (loader_descriptor_present) {
        uint64_t file_size = (uint64_t)st.st_size;
        uint64_t footer_offset = file_size - sizeof(ft);

        if (!loader_descriptor_numeric_valid ||
            loader_payload_foff > file_size ||
            loader_payload_filesz > file_size - loader_payload_foff ||
            !payload_range_valid(footer_offset, sizeof(ft),
                                 loader_payload_foff,
                                 loader_payload_filesz)) {
            fprintf(stderr,
                    "dlfreeze-bootstrap: invalid payload descriptor\n");
            close(sfd); return 127;
        }
        payload_offset = loader_payload_foff;
        payload_size = loader_payload_filesz;
    }
    {
        struct payload_file_range controls[PAYLOAD_CONTROL_COUNT];

        if (ft.num_entries == 0 || ft.strtab_size == 0 ||
            ft.strtab_size > SIZE_MAX ||
            !payload_control_ranges(&ft, payload_offset, payload_size,
                                    controls)) {
            fprintf(stderr, "dlfreeze-bootstrap: invalid payload layout\n");
            close(sfd); return 127;
        }
    }

    /* 3. read string table */
    char *strtab = malloc(ft.strtab_size);
    if (!strtab) {
        fprintf(stderr, "dlfreeze-bootstrap: cannot read strtab\n");
        close(sfd); return 127;
    }
    if (from_memory) {
        memcpy(strtab,
               mem_base + (ft.strtab_offset - loader_payload_foff),
               ft.strtab_size);
    } else {
        if (full_pread(sfd, strtab, (size_t)ft.strtab_size,
                       ft.strtab_offset) < 0) {
            fprintf(stderr, "dlfreeze-bootstrap: cannot read strtab\n");
            free(strtab); close(sfd); return 127;
        }
    }

    /* 4. read manifest */
    size_t msz = ft.num_entries * sizeof(struct dlfrz_entry);
    struct dlfrz_entry *ent = malloc(msz);
    if (!ent) {
        fprintf(stderr, "dlfreeze-bootstrap: cannot read manifest\n");
        free(strtab); close(sfd); return 127;
    }
    if (from_memory) {
        memcpy(ent,
               mem_base + (ft.manifest_offset - loader_payload_foff),
               msz);
    } else {
        if (full_pread(sfd, ent, msz, ft.manifest_offset) < 0) {
            fprintf(stderr, "dlfreeze-bootstrap: cannot read manifest\n");
            free(ent); free(strtab); close(sfd); return 127;
        }
    }

    if (!manifest_is_valid(&ft, ent, strtab, payload_offset, payload_size)) {
        fprintf(stderr, "dlfreeze-bootstrap: invalid manifest\n");
        free(ent); free(strtab); close(sfd); return 127;
    }

    int has_data_entries = 0;
    int has_pathful_dlopen_entries = 0;
    int has_pathful_needed_entries = 0;
    int has_unextractable_logical_names;
    for (uint32_t i = 0; i < ft.num_entries; i++) {
        if (ent[i].flags & DLFRZ_FLAG_DATA) {
            has_data_entries = 1;
        }
        if ((ent[i].flags & DLFRZ_FLAG_DLOPEN_PATHFUL) != 0)
            has_pathful_dlopen_entries = 1;
        if ((ent[i].flags & DLFRZ_FLAG_NEEDED_PATHFUL) != 0)
            has_pathful_needed_entries = 1;
    }
    has_unextractable_logical_names =
        manifest_has_unextractable_logical_names(ent, ft.num_entries);

    /* 5. check for direct-load metadata in footer pad[0..7] */
    uint64_t meta_off = 0;
    uint64_t fixup_off = 0;
    uint64_t fixup_count = 0;
    memcpy(&meta_off, ft.pad, sizeof(meta_off));
    memcpy(&fixup_off, ft.pad + 8, sizeof(fixup_off));
    memcpy(&fixup_count, ft.pad + 16, sizeof(fixup_count));
    if ((meta_off == 0 && (fixup_off != 0 || fixup_count != 0)) ||
        (meta_off != 0 &&
         meta_off % _Alignof(struct dlfrz_lib_meta) != 0) ||
        ((fixup_off == 0) != (fixup_count == 0)) ||
        (fixup_off != 0 && fixup_off % _Alignof(uint32_t) != 0)) {
        fprintf(stderr,
                "dlfreeze-bootstrap: non-canonical direct-load metadata\n");
        free(ent); free(strtab); close(sfd); return 127;
    }
    if (meta_off != 0) {
        /* Direct-load mode: try in a child first.  A clean, runtime-relocated
         * payload may fall back to extraction before application handoff;
         * a prelinked payload must never be handed back to the system rtld. */
        size_t metasz = ft.num_entries * sizeof(struct dlfrz_lib_meta);
        uint64_t fixup_size = 0;

        if (fixup_count != 0 && fixup_count <= UINT32_MAX)
            fixup_size = fixup_count * sizeof(uint32_t);
        if (!payload_range_valid(meta_off, metasz,
                                 payload_offset, payload_size) ||
            fixup_count > UINT32_MAX ||
            (fixup_count != 0 &&
             (fixup_off == 0 || fixup_count > UINT64_MAX / sizeof(uint32_t) ||
              !payload_range_valid(fixup_off,
                                   fixup_count * sizeof(uint32_t),
                                   payload_offset, payload_size))) ||
            !direct_payload_ranges_valid(
                &ft, ent, payload_offset, payload_size,
                meta_off, metasz, fixup_off, fixup_size)) {
            fprintf(stderr, "dlfreeze-bootstrap: invalid direct-load metadata\n");
            free(ent); free(strtab); close(sfd); return 127;
        }
        struct dlfrz_lib_meta *metas = malloc(metasz);
        if (!metas) {
            fprintf(stderr, "dlfreeze-bootstrap: cannot alloc lib_meta\n");
            free(ent); free(strtab); close(sfd); return 127;
        }

        if (from_memory) {
            memcpy(metas,
                   mem_base + (meta_off - loader_payload_foff),
                   metasz);
        } else {
            if (full_pread(sfd, metas, metasz, meta_off) < 0) {
                fprintf(stderr, "dlfreeze-bootstrap: cannot read lib_meta\n");
                free(metas); free(ent); free(strtab); close(sfd);
                return 127;
            }
        }

        /* Set up mem/mem_foff for the loader.
         * Normal path: mmap the entire file.
         * UPX path: payload is already in virtual memory. */
        const uint8_t *ldr_mem;
        uint64_t ldr_mem_foff;
        int ldr_srcfd;

        if (from_memory) {
            ldr_mem = mem_base;
            ldr_mem_foff = loader_payload_foff;
            ldr_srcfd = -1;
        } else {
            void *file_map = mmap(NULL, st.st_size, PROT_READ,
                                  MAP_PRIVATE, sfd, 0);
            if (file_map == MAP_FAILED) {
                perror("mmap");
                free(metas); free(ent); free(strtab); close(sfd);
                return 127;
            }
            ldr_mem = (const uint8_t *)file_map;
            ldr_mem_foff = 0;
            ldr_srcfd = sfd;
        }

        const uint32_t *runtime_fixups = NULL;
        uint32_t runtime_fixup_count = 0;
        if (fixup_off != 0 && fixup_count != 0) {
            if (!embedded_address_aligned(ldr_mem, ldr_mem_foff, fixup_off,
                                          _Alignof(uint32_t))) {
                fprintf(stderr,
                        "dlfreeze-bootstrap: unaligned runtime fixup table\n");
                if (from_memory == 0 && ldr_mem_foff == 0)
                    munmap((void *)ldr_mem, st.st_size);
                free(metas); free(ent); free(strtab); close(sfd);
                return 127;
            }
            runtime_fixups = (const uint32_t *)(ldr_mem + (fixup_off - ldr_mem_foff));
            runtime_fixup_count = (uint32_t)fixup_count;
        }

        if (!direct_metadata_is_valid(ldr_mem, ldr_mem_foff, metas, ent,
                                      ft.num_entries,
                                      runtime_fixup_count)) {
            fprintf(stderr,
                    "dlfreeze-bootstrap: invalid direct-load object metadata\n");
            if (from_memory == 0 && ldr_mem_foff == 0)
                munmap((void *)ldr_mem, st.st_size);
            free(metas); free(ent); free(strtab); close(sfd);
            return 127;
        }

        int prelinked_payload = 0;
        for (uint32_t i = 0; i < ft.num_entries; i++) {
            if (!(metas[i].flags & DLFRZ_FLAG_DATA) &&
                (metas[i].flags & DLFRZ_FLAG_PRELINKED)) {
                prelinked_payload = 1;
                break;
            }
        }

        const enum extraction_fallback_refusal fallback_refusal =
            classify_extraction_fallback(
                prelinked_payload, has_data_entries,
                has_pathful_dlopen_entries,
                has_pathful_needed_entries,
                has_unextractable_logical_names);
        const int direct_only_payload =
            fallback_refusal != EXTRACTION_FALLBACK_ALLOWED;

        /* A supervised child exists solely to preserve extraction fallback
         * before application handoff.  When validated metadata proves that
         * extraction cannot reproduce the artifact, enter the loader in the
         * original process and preserve normal executable PID/signal/job-
         * control semantics.  DLFREEZE_NO_FORK remains a strict diagnostic
         * override for clean fallback-capable artifacts. */
        if (direct_only_payload || bs_env_enabled("DLFREEZE_NO_FORK")) {
            loader_run(ldr_mem, ldr_mem_foff, ldr_srcfd, metas, ent, strtab,
                       ft.num_entries, runtime_fixups, runtime_fixup_count,
                       -1,
                       argc, argv, environ);
            if (direct_only_payload)
                report_extraction_fallback_refusal(fallback_refusal);
            if (bs_debug_enabled())
                fprintf(stderr, "dlfreeze-bootstrap: in-process loader failed\n");
            close(sfd);
            return 127;
        }

        /* Run direct-load in a child so clean-payload failures before
         * application handoff can fall back without duplicated effects. */
        int handoff_pipe[2];
        if (pipe2(handoff_pipe, O_CLOEXEC) < 0) {
            perror("pipe2");
            free(metas); free(ent); free(strtab); close(sfd);
            return 127;
        }
        sigset_t forward_set, old_mask;
        struct sigaction old_forward_actions[FORWARD_SIGNAL_CAPACITY];
        struct sigaction old_sigchld_action;
        build_forward_signal_set(&forward_set);
        sigaddset(&forward_set, SIGCHLD);
        if (sigprocmask(SIG_BLOCK, &forward_set, &old_mask) < 0) {
            perror("sigprocmask");
            close(handoff_pipe[0]); close(handoff_pipe[1]);
            free(metas); free(ent); free(strtab); close(sfd);
            return 127;
        }
        if (install_waitable_sigchld(&old_sigchld_action) < 0) {
            perror("sigaction");
            sigprocmask(SIG_SETMASK, &old_mask, NULL);
            close(handoff_pipe[0]); close(handoff_pipe[1]);
            free(metas); free(ent); free(strtab); close(sfd);
            return 127;
        }
        pid_t lpid = fork();
        if (lpid < 0) {
            perror("fork");
            restore_inherited_sigchld(&old_sigchld_action);
            sigprocmask(SIG_SETMASK, &old_mask, NULL);
            close(handoff_pipe[0]); close(handoff_pipe[1]);
            free(metas); free(ent); free(strtab); close(sfd);
            return 127;
        }

        if (lpid == 0) {
            if (restore_inherited_sigchld(&old_sigchld_action) < 0)
                _exit(127);
            sigprocmask(SIG_SETMASK, &old_mask, NULL);
            close(handoff_pipe[0]);
            /* loader_run() does NOT return on success */
            loader_run(ldr_mem, ldr_mem_foff, ldr_srcfd, metas, ent, strtab,
                       ft.num_entries, runtime_fixups, runtime_fixup_count,
                       handoff_pipe[1],
                       argc, argv, environ);
            close(handoff_pipe[1]);
            close(sfd);
            if (bs_debug_enabled())
                fprintf(stderr, "dlfreeze-bootstrap: in-process loader failed\n");
            _exit(127);
        }

        close(handoff_pipe[1]);
        g_child = lpid;
        g_forwarded_signal = 0;
        if (install_forward_signal_handlers(old_forward_actions) < 0) {
            perror("sigaction");
            kill(lpid, SIGKILL);
            while (waitpid(lpid, NULL, 0) < 0 && errno == EINTR) {}
            g_child = -1;
            restore_inherited_sigchld(&old_sigchld_action);
            sigprocmask(SIG_SETMASK, &old_mask, NULL);
            close(handoff_pipe[0]);
            if (from_memory == 0 && ldr_mem_foff == 0 && ldr_mem)
                munmap((void *)ldr_mem, st.st_size);
            free(metas); free(ent); free(strtab); close(sfd);
            return 127;
        }
        sigprocmask(SIG_SETMASK, &old_mask, NULL);

        int lst = 0;
        int wait_failed = wait_for_supervised_child(lpid, &lst,
                                                    &forward_set) < 0;

        sigprocmask(SIG_BLOCK, &forward_set, NULL);
        int direct_interrupted = g_forwarded_signal != 0;
        g_child = -1;
        restore_forward_signal_handlers(old_forward_actions);
        restore_inherited_sigchld(&old_sigchld_action);
        sigprocmask(SIG_SETMASK, &old_mask, NULL);

        if (wait_failed) {
            perror("waitpid");
            close(handoff_pipe[0]);
            if (from_memory == 0 && ldr_mem_foff == 0 && ldr_mem)
                munmap((void *)ldr_mem, st.st_size);
            free(metas); free(ent); free(strtab); close(sfd);
            return 127;
        }

        char handoff_marker;
        ssize_t handoff_len;
        do {
            handoff_len = read(handoff_pipe[0], &handoff_marker,
                               sizeof(handoff_marker));
        } while (handoff_len < 0 && errno == EINTR);
        close(handoff_pipe[0]);
        int application_started = handoff_len == 1 &&
            handoff_marker == DLFRZ_HANDOFF_APPLICATION_STARTED;
        int terminal_refusal = handoff_len == 1 &&
            handoff_marker == DLFRZ_HANDOFF_TERMINAL_REFUSAL;

        if (from_memory == 0 && ldr_mem_foff == 0 && ldr_mem)
            munmap((void *)ldr_mem, st.st_size);

        free(metas);

        if (terminal_refusal) {
            free(ent); free(strtab); close(sfd);
            return 127;
        }
        if (application_started || direct_interrupted) {
            free(ent); free(strtab); close(sfd);
            if (WIFEXITED(lst))
                return WEXITSTATUS(lst);
            if (WIFSIGNALED(lst))
                reraise_child_signal(WTERMSIG(lst));
            return 127;
        }
        if (fallback_refusal != EXTRACTION_FALLBACK_ALLOWED) {
            report_extraction_fallback_refusal(fallback_refusal);
            free(ent); free(strtab); close(sfd);
            return 127;
        }
    }

    /* DATA entries describe an in-memory filesystem overlay, including
     * negative lookups.  Pathful dynamic-load requests and unrepresented
     * logical names likewise have exact identity/$ORIGIN semantics that a
     * temporary extraction prefix cannot retain. */
    enum extraction_fallback_refusal fallback_refusal =
        classify_extraction_fallback(
            0, has_data_entries, has_pathful_dlopen_entries,
            has_pathful_needed_entries, has_unextractable_logical_names);
    if (fallback_refusal != EXTRACTION_FALLBACK_ALLOWED) {
        report_extraction_fallback_refusal(fallback_refusal);
        free(ent); free(strtab); close(sfd);
        return 127;
    }

    /* 6. create workdir for extraction fallback (/tmp only). */
    if (make_workdir(g_tmpdir, sizeof(g_tmpdir)) < 0) {
        perror("mkdtemp");
        free(ent); free(strtab); close(sfd);
        return 127;
    }

    /* 7. Build and validate the complete destination set before creating any
     * payload files.  This prevents basename aliases or normalized paths from
     * silently overwriting an earlier manifest entry. */
    struct extraction_plan_entry *extraction_plan = NULL;
    char *exe_path = NULL;
    char *exe_identity = NULL;
    char *interp_path = NULL;
    char *system_interp_path = NULL;
    int extraction_failed = 0;

    if (build_extraction_plan(ent, ft.num_entries, strtab,
                              &extraction_plan) < 0) {
        fprintf(stderr,
                "dlfreeze-bootstrap: invalid or conflicting extraction paths\n");
        cleanup_workdir();
        free(ent); free(strtab); close(sfd);
        return 127;
    }

    for (uint32_t i = 0; i < ft.num_entries; i++) {
        const char *name = strtab + ent[i].name_offset;
        struct extraction_plan_entry *item = &extraction_plan[i];

        if (item->kind == EXTRACTION_PATH_NONE)
            continue;

        if (item->kind == EXTRACTION_PATH_DIRECTORY) {
            if (item->materialize &&
                ensure_relative_directories(g_tmpdir_fd,
                                            item->relative_path, 1) < 0) {
                fprintf(stderr, "dlfreeze-bootstrap: mkdir failed: %s\n",
                        item->full_path);
                extraction_failed = 1;
                break;
            }
            continue;
        }

        int rc = 0;

        if (item->materialize) {
            if (from_memory) {
                rc = extract_mem(mem_base, loader_payload_foff, g_tmpdir_fd,
                                 item->relative_path, ent[i].data_offset,
                                 ent[i].data_size, item->executable);
            } else {
                rc = extract(sfd, g_tmpdir_fd, item->relative_path,
                             ent[i].data_offset, ent[i].data_size,
                             item->executable);
            }
            if (rc < 0) {
                fprintf(stderr,
                        "dlfreeze-bootstrap: extract failed: %s\n", name);
                extraction_failed = 1;
                break;
            }
        }

        if (item->alias_relative_path && item->alias_materialize) {
            /* Hard links also share mode bits.  If destination coalescing
             * promoted only the alias to executable, materialize an
             * independent copy rather than changing the primary's mode. */
            if (item->alias_executable != item->executable ||
                linkat(g_tmpdir_fd, item->relative_path, g_tmpdir_fd,
                       item->alias_relative_path, 0) < 0) {
                if (from_memory) {
                    rc = extract_mem(mem_base, loader_payload_foff,
                                     g_tmpdir_fd, item->alias_relative_path,
                                     ent[i].data_offset, ent[i].data_size,
                                     item->alias_executable);
                } else {
                    rc = extract(sfd, g_tmpdir_fd, item->alias_relative_path,
                                 ent[i].data_offset, ent[i].data_size,
                                 item->alias_executable);
                }
                if (rc < 0) {
                    fprintf(stderr,
                            "dlfreeze-bootstrap: extract alias failed: %s\n",
                            item->alias_full_path);
                    extraction_failed = 1;
                    break;
                }
            }
        }

        if (ent[i].flags & DLFRZ_FLAG_MAIN_EXE) {
            exe_path = strdup(item->full_path);
            exe_identity = strdup(name);
            if (!exe_path || !exe_identity) {
                extraction_failed = 1;
                break;
            }
        }
        if (ent[i].flags & DLFRZ_FLAG_INTERP) {
            interp_path = strdup(item->full_path);
            system_interp_path = strdup(name);
            if (!interp_path || !system_interp_path) {
                extraction_failed = 1;
                break;
            }
        }
    }
    free_extraction_plan(extraction_plan, ft.num_entries);
    free(ent); free(strtab); close(sfd);

    if (extraction_failed || !exe_path) {
        if (!extraction_failed)
            fprintf(stderr,
                    "dlfreeze-bootstrap: no main executable in payload\n");
        cleanup_workdir();
        free(exe_path); free(exe_identity);
        free(interp_path); free(system_interp_path);
        return 127;
    }
    if (!exe_path[0]) {
        fprintf(stderr, "dlfreeze-bootstrap: no main executable in payload\n");
        cleanup_workdir();
        free(exe_path); free(exe_identity);
        free(interp_path); free(system_interp_path);
        return 127;
    }

    /* 8. Build argv for the real program.  Prefer normal kernel PT_INTERP
     * startup when the target has a byte-identical interpreter.  Besides
     * preserving normal /proc/self/exe and self-reexec behavior, this avoids
     * relying on libc-specific command-line options.  If the interpreter is
     * absent or differs, launch the executable through the bundled copy so
     * the bundled libc and loader remain a matched pair. */
    int launcher_available = interp_path != NULL;
    int direct_available = !launcher_available ||
        (system_interp_path && system_interp_path[0] == '/' &&
         access(system_interp_path, X_OK) == 0);
    int use_interp_launcher = launcher_available &&
        !(direct_available && files_identical(system_interp_path, interp_path));

    /* Build the kernel and explicit-interpreter argv variants. */
    char **direct_nav = calloc((size_t)argc + 1, sizeof(char *));
    if (!direct_nav) {
        cleanup_workdir();
        free(exe_path); free(exe_identity);
        free(interp_path); free(system_interp_path);
        return 127;
    }
    direct_nav[0] = exe_identity && exe_identity[0] ? exe_identity : exe_path;
    for (int i = 1; i < argc; i++)
        direct_nav[i] = argv[i];

    char **launcher_nav = NULL;
    if (launcher_available) {
        launcher_nav = calloc((size_t)argc + 2, sizeof(char *));
        if (!launcher_nav) {
            free(direct_nav);
            cleanup_workdir();
            free(exe_path); free(exe_identity);
            free(interp_path); free(system_interp_path);
            return 127;
        }
        launcher_nav[0] = interp_path;
        launcher_nav[1] = exe_path;
        for (int i = 1; i < argc; i++)
            launcher_nav[i + 1] = argv[i];
    }

    char **nav = use_interp_launcher ? launcher_nav : direct_nav;

    /* 9. set LD_LIBRARY_PATH */
    const char *oldlp = getenv("LD_LIBRARY_PATH");
    size_t root_len = strlen(g_tmpdir);
    size_t oldlp_len = oldlp && oldlp[0] ? strlen(oldlp) : 0;
    size_t lp_size = 0;
    char *lp = NULL;

    if (oldlp_len &&
        size_add_checked(root_len, 1, &lp_size) &&
        size_add_checked(lp_size, oldlp_len, &lp_size) &&
        size_add_checked(lp_size, 1, &lp_size)) {
        lp = malloc(lp_size);
        if (lp) {
            memcpy(lp, g_tmpdir, root_len);
            lp[root_len] = ':';
            memcpy(lp + root_len + 1, oldlp, oldlp_len + 1);
        }
    } else if (!oldlp_len) {
        lp = strdup(g_tmpdir);
    } else {
        errno = EOVERFLOW;
    }
    if (!lp || setenv("LD_LIBRARY_PATH", lp, 1) < 0) {
        perror("setenv");
        free(lp);
        cleanup_workdir();
        free(direct_nav); free(launcher_nav);
        free(exe_path); free(exe_identity);
        free(interp_path); free(system_interp_path);
        return 127;
    }
    free(lp);

    /* 10. fork→exec, parent waits + cleans up.  Block forwarded signals
     * across fork so only the parent installs the supervisor handlers; caught
     * dispositions inherited before exec would otherwise consume a terminal
     * stop in the child during the fork/exec window. */
    sigset_t forward_set, old_mask;
    struct sigaction old_forward_actions[FORWARD_SIGNAL_CAPACITY];
    struct sigaction old_sigchld_action;
    build_forward_signal_set(&forward_set);
    sigaddset(&forward_set, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &forward_set, &old_mask) < 0) {
        perror("sigprocmask");
        cleanup_workdir();
        free(direct_nav); free(launcher_nav);
        free(exe_path); free(exe_identity);
        free(interp_path); free(system_interp_path);
        return 127;
    }
    if (install_waitable_sigchld(&old_sigchld_action) < 0) {
        perror("sigaction");
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
        cleanup_workdir();
        free(direct_nav); free(launcher_nav);
        free(exe_path); free(exe_identity);
        free(interp_path); free(system_interp_path);
        return 127;
    }
    int status = 0;
    g_child = fork();
    if (g_child < 0) {
        restore_inherited_sigchld(&old_sigchld_action);
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
        perror("fork"); cleanup_workdir();
        free(direct_nav); free(launcher_nav);
        free(exe_path); free(exe_identity);
        free(interp_path); free(system_interp_path);
        return 127;
    }

    if (g_child == 0) {
        if (restore_inherited_sigchld(&old_sigchld_action) < 0)
            _exit(127);
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
        if (use_interp_launcher)
            execve(interp_path, nav, environ);
        else
            execve(exe_path, nav, environ);
        perror("execve");
        _exit(127);
    }

    pid_t child = g_child;
    g_forwarded_signal = 0;
    if (install_forward_signal_handlers(old_forward_actions) < 0) {
        perror("sigaction");
        kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
        g_child = -1;
        restore_inherited_sigchld(&old_sigchld_action);
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
        cleanup_workdir();
        free(direct_nav); free(launcher_nav);
        free(exe_path); free(exe_identity);
        free(interp_path); free(system_interp_path);
        return 127;
    }
    sigprocmask(SIG_SETMASK, &old_mask, NULL);

    int wait_failed = wait_for_supervised_child(child, &status,
                                                &forward_set) < 0;

    sigprocmask(SIG_BLOCK, &forward_set, NULL);
    g_child = -1;
    restore_forward_signal_handlers(old_forward_actions);
    restore_inherited_sigchld(&old_sigchld_action);
    sigprocmask(SIG_SETMASK, &old_mask, NULL);

    cleanup_workdir();
    free(direct_nav);
    free(launcher_nav);
    free(exe_path); free(exe_identity);
    free(interp_path); free(system_interp_path);

    if (wait_failed) {
        perror("waitpid");
        return 127;
    }

    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        reraise_child_signal(WTERMSIG(status));
    return 127;
}
