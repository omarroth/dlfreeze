/*
 * dlfreeze trace helper — LD_PRELOAD library.
 *
 * Logs dlopen() results and successful file / directory opens to collector-
 * supplied inherited descriptors.  Pathname destinations remain available
 * only for standalone helper tests.  File tracing avoids the external strace
 * dependency for -t -f capture.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <link.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>

#include "dynamic_semantics.h"
#include "linux_syscalls.h"

#if defined(__GLIBC__)
#define DLFREEZE_HAVE_GLIBC_STAT_ALIASES 1
#else
#define DLFREEZE_HAVE_GLIBC_STAT_ALIASES 0
#endif

/* Some libcs expose the large-file entry points as preprocessor aliases of
 * their base functions.  Defining both interposers in that environment would
 * become a duplicate definition after macro expansion; calls are already
 * covered by the base wrapper. */
#ifdef open64
#define DLFREEZE_HAVE_OPEN64_SYMBOL 0
#else
#define DLFREEZE_HAVE_OPEN64_SYMBOL 1
#endif
#ifdef openat64
#define DLFREEZE_HAVE_OPENAT64_SYMBOL 0
#else
#define DLFREEZE_HAVE_OPENAT64_SYMBOL 1
#endif
#ifdef fopen64
#define DLFREEZE_HAVE_FOPEN64_SYMBOL 0
#else
#define DLFREEZE_HAVE_FOPEN64_SYMBOL 1
#endif

#ifndef O_TMPFILE
#define O_TMPFILE 020000000
#endif

static _Atomic int g_dlopen_trace_fd = -1;
static _Atomic int g_file_trace_fd = -1;
static _Atomic int g_trace_collection_abandoned;

enum trace_stream_kind {
    TRACE_STREAM_DLOPEN,
    TRACE_STREAM_FILE
};

struct trace_fd_identity {
    dev_t device;
    ino_t inode;
    dev_t rdevice;
    mode_t type;
};

/* Fixed-width filesystem identity written into successful file records.
 * Object identity is sufficient for directories.  Regular files also carry
 * the revision fields used by the packer, binding the eventual bytes to the
 * exact revision observed by the interposed operation. */
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

struct file_trace_transaction {
    pid_t pid;
    uint64_t attempt;
};

struct descriptor_fd_reservation {
    struct descriptor_fd_reservation *next;
    unsigned int first;
    unsigned int last;
};

struct descriptor_fd_move {
    enum trace_stream_kind stream;
    int old_fd;
    int new_fd;
};

struct descriptor_trace_transaction {
    pid_t pid;
    uint64_t attempt;
    struct descriptor_fd_reservation *reservation;
    struct descriptor_fd_move moves[2];
    size_t move_count;
};

enum descriptor_operation_result {
    DESCRIPTOR_OPERATION_FAILED,
    DESCRIPTOR_OPERATION_SUCCEEDED,
    DESCRIPTOR_OPERATION_VOID
};

_Static_assert(sizeof(((struct stat *)0)->st_dev) <= sizeof(uint64_t),
               "file-trace device identity exceeds wire width");
_Static_assert(sizeof(((struct stat *)0)->st_ino) <= sizeof(uint64_t),
               "file-trace inode identity exceeds wire width");
_Static_assert(sizeof(((struct stat *)0)->st_size) <= sizeof(uint64_t),
               "file-trace size exceeds wire width");
_Static_assert(sizeof(((struct stat *)0)->st_mtim.tv_sec) <= sizeof(uint64_t),
               "file-trace timestamp exceeds wire width");

static struct trace_fd_identity g_dlopen_trace_identity;
static struct trace_fd_identity g_file_trace_identity;

static _Atomic(void *(*)(const char *, int)) real_dlopen;
#if defined(LM_ID_BASE) && defined(LM_ID_NEWLM)
#define DLFREEZE_HAVE_DLMOPEN 1
_Static_assert(sizeof(Lmid_t) <= sizeof(uint64_t),
               "dlmopen namespace identity exceeds trace wire width");
static _Atomic(void *(*)(Lmid_t, const char *, int)) real_dlmopen;
#else
#define DLFREEZE_HAVE_DLMOPEN 0
#endif
static _Atomic(int (*)(const char *, int, ...)) real_open;
#if DLFREEZE_HAVE_OPEN64_SYMBOL
static _Atomic(int (*)(const char *, int, ...)) real_open64;
#endif
static _Atomic(int (*)(int, const char *, int, ...)) real_openat;
#if DLFREEZE_HAVE_OPENAT64_SYMBOL
static _Atomic(int (*)(int, const char *, int, ...)) real_openat64;
#endif
#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
static _Atomic(int (*)(const char *, int)) real_open_2;
static _Atomic(int (*)(const char *, int)) real_open64_2;
static _Atomic(int (*)(int, const char *, int)) real_openat_2;
static _Atomic(int (*)(int, const char *, int)) real_openat64_2;
#endif
static _Atomic(FILE *(*)(const char *, const char *)) real_fopen;
#if DLFREEZE_HAVE_FOPEN64_SYMBOL
static _Atomic(FILE *(*)(const char *, const char *)) real_fopen64;
#endif
static _Atomic(DIR *(*)(const char *)) real_opendir;
static _Atomic(int (*)(const char *, struct stat *)) real_stat;
#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
static _Atomic(int (*)(const char *, struct stat64 *)) real_stat64;
#endif
static _Atomic(int (*)(const char *, struct stat *)) real_lstat;
#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
static _Atomic(int (*)(const char *, struct stat64 *)) real_lstat64;
#endif
static _Atomic(int (*)(int, const char *, struct stat *, int)) real_fstatat;
#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
static _Atomic(int (*)(int, const char *, struct stat64 *, int)) real_fstatat64;
static _Atomic(int (*)(int, const char *, struct stat *)) real_xstat;
static _Atomic(int (*)(int, const char *, struct stat64 *)) real_xstat64;
static _Atomic(int (*)(int, const char *, struct stat *)) real_lxstat;
static _Atomic(int (*)(int, const char *, struct stat64 *)) real_lxstat64;
static _Atomic(int (*)(int, int, const char *, struct stat *, int)) real_fxstatat;
static _Atomic(int (*)(int, int, const char *, struct stat64 *, int)) real_fxstatat64;
#endif
static _Atomic(int (*)(const char *, int)) real_access;
static _Atomic(int (*)(int, const char *, int, int)) real_faccessat;
static _Atomic(int (*)(const char *, char *const[], char *const[])) real_execve;
#if defined(SYS_execveat)
static _Atomic(int (*)(int, const char *, char *const[], char *const[], int))
    real_execveat;
#endif
static _Atomic(int (*)(int, char *const[], char *const[])) real_fexecve;
static _Atomic(int (*)(const char *, char *const[])) real_execvp;
static _Atomic(int (*)(const char *, char *const[], char *const[])) real_execvpe;
static _Atomic(pid_t (*)(void)) real_fork;
static _Atomic(int (*)(int)) real_close;
static _Atomic(int (*)(unsigned int, unsigned int, int)) real_close_range;
static _Atomic(void (*)(int)) real_closefrom;
static _Atomic(int (*)(int)) real_dup;
static _Atomic(int (*)(int, int)) real_dup2;
static _Atomic(int (*)(int, int, int)) real_dup3;
static _Atomic(int (*)(const char *)) real_chdir;
static _Atomic(int (*)(int)) real_fchdir;
static _Atomic(int (*)(const char *)) real_chroot;

static __thread int g_trace_depth;
static __thread int g_symbols_resolving;
static __thread int g_exec_depth;
static __thread unsigned int g_wrapped_fork_depth;
static __thread unsigned int g_loader_observation_depth;
static __thread unsigned int g_cwd_writer_depth;
static __thread pid_t g_cwd_recovered_child_pid;
static __thread unsigned int g_trace_fd_state_depth;
static __thread int g_trace_failure_active;
static __thread uint64_t g_trace_fd_state_saved_signal_mask;
static __thread int g_trace_fd_state_signals_blocked;
static __thread pid_t g_descriptor_recovered_child_pid;
static _Atomic int g_symbols_resolved;
static _Atomic int g_trace_excluded_image;
static _Atomic uintptr_t g_trace_init_state;
static _Atomic uint64_t g_exec_attempt_sequence;
static _Atomic uint64_t g_loader_attempt_sequence;
static _Atomic uint64_t g_file_operation_attempt_sequence;
static _Atomic int g_loader_observation_owner;
static _Atomic unsigned int g_cwd_active_writers;
static _Atomic uint64_t g_cwd_epoch;
static _Atomic int g_trace_fd_state_owner;
static struct descriptor_fd_reservation *g_descriptor_fd_reservations;
static pid_t g_trace_owner_pid;
static pid_t g_trace_participant_pid;

#define PRELOAD_TRACE_READY "#DLFREEZE_PRELOAD_TRACE_V9"
#define DLOPEN_TRACE_READY  "#DLFREEZE_DLOPEN_TRACE_V8"
#define TRACE_OWNER_ENV     "DLFREEZE_TRACE_OWNER_PID"
#define DLOPEN_TRACE_FD_ENV "DLFREEZE_TRACE_FD"
#define FILE_TRACE_FD_ENV   "DLFREEZE_FILE_TRACE_FD"
#define DLOPEN_TRACE_ID_ENV "DLFREEZE_TRACE_IDENTITY"
#define FILE_TRACE_ID_ENV   "DLFREEZE_FILE_TRACE_IDENTITY"
#define TRACE_INIT_READY UINTPTR_MAX
#define DLFREEZE_FUTEX_WAIT_PRIVATE (0 | 128)
#define DLFREEZE_FUTEX_WAKE_PRIVATE (1 | 128)

static int open_trace_fd(const char *path, struct trace_fd_identity *identity);
static int open_owned_trace_fd(
    const char *path, const char *fd_environment,
    const char *identity_environment,
    struct trace_fd_identity *identity);
static void write_trace_line(enum trace_stream_kind stream,
                             const char *prefix, const char *path);
static void write_trace_owner_record(enum trace_stream_kind stream);
static void write_trace_terminal_record(enum trace_stream_kind stream,
                                        const char *reason);
static void write_file_failure(const char *reason);
static int write_initial_map_evidence(void);
static void abandon_trace_collection(const char *reason);
static void trace_write_failure(void) __attribute__((noreturn));
static int absolute_link_map_name(const char *name, const char *lookup_cwd,
                                  char logical[PATH_MAX]);

/* Fork descendants inherit the claimed open file description and contribute
 * explicitly pid-tagged records.  An exec closes it; a newly initialized
 * helper refuses and poisons the already-claimed stream instead of silently
 * appending records from a different process image. */
static int dlopen_trace_is_active(void)
{
    return atomic_load_explicit(&g_dlopen_trace_fd,
                                memory_order_acquire) >= 0;
}

static int bounded_string_length(const char *string, size_t limit,
                                 size_t *length)
{
    size_t index;

    if (!string || !length)
        return 0;
    for (index = 0; index < limit; index++) {
        if (string[index] == '\0') {
            *length = index;
            return 1;
        }
    }
    return 0;
}

/* glibc does not publish environ until after startup relocations have run.
 * A target IFUNC/IRELATIVE resolver may nevertheless call an interposed
 * function while the dynamic loader is still applying those relocations.
 * Reading the tracing contract through getenv() at that point makes an
 * enabled trace look disabled and permanently loses the early operation.
 *
 * The contract is part of the initial exec environment, so recover it from
 * procfs with raw syscalls only while libc's environment pointer is still
 * unavailable.  This is libc-independent and does not depend on private
 * loader symbols or the initial-stack layout.  Once environ is published we
 * retain normal getenv() semantics, including an application deliberately
 * changing an optional pathname before a later standalone initialization.
 */
extern char **environ;

static int trace_environment_value_from_proc(
    const char *name, size_t name_length, char *value, size_t value_capacity)
{
    unsigned char buffer[1024];
    size_t key_position = 0;
    size_t value_length = 0;
    int candidate = 1;
    int in_value = 0;
    int overflow = 0;
    int result = 0;
    int saved_errno = errno;
    int fd;

    do {
        fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/environ",
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0)
        goto out;

    for (;;) {
        ssize_t count;

        do {
            count = syscall(SYS_read, fd, buffer, sizeof(buffer));
        } while (count < 0 && errno == EINTR);
        if (count < 0) {
            result = -1;
            break;
        }
        if (count == 0) {
            /* Linux normally terminates the environment with NUL.  Accept a
             * complete final value at EOF as well, but reject a truncated key
             * because it cannot be distinguished from an incomplete read. */
            if (candidate && in_value && !overflow) {
                value[value_length] = '\0';
                result = 1;
            } else if (key_position != 0 || in_value) {
                result = -1;
            }
            break;
        }

        for (ssize_t index = 0; index < count; index++) {
            unsigned char character = buffer[index];

            if (character == '\0') {
                if (candidate && in_value) {
                    if (overflow) {
                        result = -1;
                    } else {
                        value[value_length] = '\0';
                        result = 1;
                    }
                    goto close_fd;
                }
                key_position = 0;
                value_length = 0;
                candidate = 1;
                in_value = 0;
                overflow = 0;
                continue;
            }
            if (!candidate)
                continue;
            if (!in_value) {
                if (key_position < name_length) {
                    if (character != (unsigned char)name[key_position])
                        candidate = 0;
                    key_position++;
                } else if (character == '=') {
                    in_value = 1;
                } else {
                    candidate = 0;
                }
                continue;
            }
            if (value_length + 1 >= value_capacity)
                overflow = 1;
            else
                value[value_length++] = (char)character;
        }
    }

close_fd:
    (void)syscall(SYS_close, fd);
out:
    errno = saved_errno;
    return result;
}

/* Return 1 and a copied value when present, 0 when absent, and -1 when the
 * early environment cannot be read or the value exceeds its protocol bound. */
static int trace_environment_value(const char *name, char *value,
                                   size_t value_capacity)
{
    const char *published;
    size_t name_length;
    size_t value_length;

    if (!name || !value || value_capacity == 0 ||
        !bounded_string_length(name, 64, &name_length) || name_length == 0)
        return -1;
    if (environ == NULL)
        return trace_environment_value_from_proc(
            name, name_length, value, value_capacity);
    published = getenv(name);
    if (!published)
        return 0;
    if (!bounded_string_length(published, value_capacity, &value_length))
        return -1;
    memcpy(value, published, value_length + 1);
    return 1;
}

static pid_t expected_trace_owner_pid(void)
{
    char value[33];
    uint64_t parsed = 0;
    size_t length;

    if (trace_environment_value(TRACE_OWNER_ENV, value, sizeof(value)) != 1 ||
        !bounded_string_length(value, sizeof(value), &length) ||
        length == 0)
        return 0;
    for (size_t index = 0; index < length; index++) {
        unsigned int digit;

        if (value[index] < '0' || value[index] > '9')
            return 0;
        digit = (unsigned int)(value[index] - '0');
        if (parsed > (uint64_t)(INT_MAX - (int)digit) / 10U)
            return 0;
        parsed = parsed * 10U + digit;
    }
    return parsed == 0 ? 0 : (pid_t)parsed;
}

static pid_t trace_current_pid(void)
{
    long value = syscall(SYS_getpid);

    if (value <= 0 || value > INT_MAX)
        trace_write_failure();
    return (pid_t)value;
}

_Static_assert(ATOMIC_INT_LOCK_FREE == 2,
               "loader observation ownership must be lock-free");
_Static_assert(sizeof(_Atomic int) == sizeof(int),
               "futex word must have int representation");

static int trace_current_tid(void)
{
    long value = syscall(SYS_gettid);

    if (value <= 0 || value > INT_MAX)
        trace_write_failure();
    return (int)value;
}

static void recover_loader_state_in_wrapped_fork_child(void)
{
    if (g_wrapped_fork_depth == 0 || g_trace_participant_pid <= 0 ||
        trace_current_pid() == g_trace_participant_pid)
        return;
    /* Only the thread which called fork survives.  A nonzero TLS depth proves
     * that this thread owned the inherited recursive lock, so preserve its
     * outstanding frames and re-key the owner.  With zero depth, any owner was
     * a vanished sibling and can be discarded in the child's private image. */
    atomic_store_explicit(&g_loader_observation_owner,
                          g_loader_observation_depth != 0
                              ? trace_current_tid() : 0,
                          memory_order_release);
}

/* A post-dlopen process scan is meaningful only when no other traced loader
 * call can occur between its baseline and commit.  Native loader locks do not
 * provide that attribution: two callers may both capture a baseline and then
 * each observe the other's completed load.  Serialize the complete
 * observation interval with a recursive, helper-local lock keyed by kernel
 * TID.  Cross-thread overlap cannot be attributed safely, so abandon both
 * traces and let the native loader call proceed immediately. */
static int loader_observation_lock(void)
{
    int saved_errno = errno;
    int tid;
    pid_t pid;

    recover_loader_state_in_wrapped_fork_child();
    if (g_loader_observation_depth != 0) {
        if (g_loader_observation_depth == UINT_MAX)
            trace_write_failure();
        g_loader_observation_depth++;
        errno = saved_errno;
        return 1;
    }
    pid = trace_current_pid();
    if (g_trace_participant_pid > 0 &&
        pid != g_trace_participant_pid && g_wrapped_fork_depth == 0)
        trace_write_failure();
    tid = trace_current_tid();
    for (unsigned int attempt = 0; attempt < 6000; attempt++) {
        int expected = 0;
        int owner;

        if (atomic_compare_exchange_strong_explicit(
                &g_loader_observation_owner, &expected, tid,
                memory_order_acq_rel, memory_order_acquire)) {
            g_loader_observation_depth = 1;
            errno = saved_errno;
            return 1;
        }
        owner = atomic_load_explicit(&g_loader_observation_owner,
                                     memory_order_acquire);
        /* The owner may release between the failed compare-exchange and this
         * diagnostic load.  Zero is therefore an ordinary retry, not lock
         * corruption. */
        if (owner == 0)
            continue;
        if (owner < 0 || owner == tid)
            trace_write_failure();
        /* Never wait while another thread may be running application
         * constructors under its native loader call: a constructor is allowed
         * to join a worker which enters dlopen.  We cannot attribute two
         * overlapping post-call namespace scans, so reject this trace and let
         * the second native loader operation proceed without our lock. */
        abandon_trace_collection(
            "concurrent-loader-operations-cannot-be-attributed");
        errno = saved_errno;
        return 0;
    }
    trace_write_failure();
}

static void loader_observation_unlock(void)
{
    int saved_errno = errno;
    int previous;

    if (g_loader_observation_depth == 0)
        trace_write_failure();
    g_loader_observation_depth--;
    if (g_loader_observation_depth != 0) {
        errno = saved_errno;
        return;
    }
    previous = atomic_exchange_explicit(&g_loader_observation_owner, 0,
                                        memory_order_release);
    if (previous <= 0)
        trace_write_failure();
    (void)syscall(SYS_futex, (int *)&g_loader_observation_owner,
                  DLFREEZE_FUTEX_WAKE_PRIVATE, INT_MAX, NULL, NULL, 0);
    errno = saved_errno;
}

static void recover_cwd_state_in_wrapped_fork_child(void)
{
    pid_t pid;
    uint64_t previous;

    if (g_wrapped_fork_depth == 0 || g_trace_participant_pid <= 0)
        return;
    pid = trace_current_pid();
    if (pid == g_trace_participant_pid ||
        pid == g_cwd_recovered_child_pid)
        return;
    /* Only the caller survives fork.  Preserve its one outer mutation when
     * TLS depth is nonzero and discard active writers from vanished sibling
     * threads.  Bump the generation so no inherited reader snapshot can be
     * accepted in the child. */
    atomic_store_explicit(&g_cwd_active_writers,
                          g_cwd_writer_depth != 0 ? 1U : 0U,
                          memory_order_release);
    previous = atomic_fetch_add_explicit(&g_cwd_epoch, 1,
                                         memory_order_acq_rel);
    if (previous == UINT64_MAX)
        trace_write_failure();
    g_cwd_recovered_child_pid = pid;
}

/* Native cwd mutations are process-wide but need not serialize with one
 * another.  Track active outer calls and a monotonic generation without
 * adding an application-visible mutex.  Readers accept an attribution only
 * when no writer was active and the generation stayed unchanged. */
static void cwd_change_begin(void)
{
    unsigned int active;
    uint64_t previous;

    recover_cwd_state_in_wrapped_fork_child();
    if (g_cwd_writer_depth == UINT_MAX)
        trace_write_failure();
    g_cwd_writer_depth++;
    if (g_cwd_writer_depth != 1)
        return;
    active = atomic_fetch_add_explicit(&g_cwd_active_writers, 1,
                                       memory_order_acq_rel);
    if (active == UINT_MAX)
        trace_write_failure();
    previous = atomic_fetch_add_explicit(&g_cwd_epoch, 1,
                                         memory_order_acq_rel);
    if (previous == UINT64_MAX)
        trace_write_failure();
}

static void cwd_change_end(void)
{
    unsigned int active;
    uint64_t previous;

    if (g_cwd_writer_depth == 0)
        trace_write_failure();
    g_cwd_writer_depth--;
    if (g_cwd_writer_depth != 0)
        return;
    previous = atomic_fetch_add_explicit(&g_cwd_epoch, 1,
                                         memory_order_release);
    if (previous == UINT64_MAX)
        trace_write_failure();
    active = atomic_fetch_sub_explicit(&g_cwd_active_writers, 1,
                                       memory_order_release);
    if (active == 0)
        trace_write_failure();
}

static void recover_trace_fd_state_in_wrapped_fork_child(void)
{
    if (g_wrapped_fork_depth == 0 || g_trace_participant_pid <= 0 ||
        trace_current_pid() == g_trace_participant_pid)
        return;
    if (g_trace_fd_state_depth != 0) {
        /* The surviving owner inherited both its saved mask and the blocked
         * kernel mask.  Preserve them until its outermost unlock. */
        if (!g_trace_fd_state_signals_blocked)
            trace_write_failure();
        atomic_store_explicit(&g_trace_fd_state_owner, trace_current_tid(),
                              memory_order_release);
        return;
    }
    atomic_store_explicit(&g_trace_fd_state_owner, 0, memory_order_release);
    g_trace_fd_state_saved_signal_mask = 0;
    g_trace_fd_state_signals_blocked = 0;
}

static void recover_descriptor_operation_in_wrapped_fork_child(void)
{
    pid_t pid;

    if (g_wrapped_fork_depth == 0 || g_trace_participant_pid <= 0)
        return;
    pid = trace_current_pid();
    if (pid == g_trace_participant_pid ||
        pid == g_descriptor_recovered_child_pid)
        return;
    /* A descriptor operation may have called a lower interposer which then
     * forked.  Its V record and reservation belong to the parent operation.
     * The child's fd table is a private copy, so discard only the copied list;
     * the transaction suppresses a W record when it returns through the
     * inherited outer wrapper.  The TLS pid guard keeps child atfork handlers
     * from repeatedly discarding their own nested reservations. */
    g_descriptor_fd_reservations = NULL;
    g_descriptor_recovered_child_pid = pid;
}

static void trace_fd_state_lock(void)
{
    int saved_errno = errno;
    int tid;

    recover_trace_fd_state_in_wrapped_fork_child();
    if (g_trace_fd_state_depth != 0) {
        if (g_trace_fd_state_depth == UINT_MAX)
            trace_write_failure();
        g_trace_fd_state_depth++;
        errno = saved_errno;
        return;
    }
    {
        uint64_t blocked = UINT64_MAX;

        /* The lock is intentionally recursive for helper-internal calls, but
         * an asynchronous handler must not become another recursive fd
         * mutator: it could rehome a stream into an outer close/dup target.
         * Linux exposes 64 signal numbers on both supported architectures;
         * SIGKILL and SIGSTOP bits are silently ignored by the kernel. */
        if (syscall(SYS_rt_sigprocmask, SIG_SETMASK, &blocked,
                    &g_trace_fd_state_saved_signal_mask,
                    sizeof(blocked)) < 0)
            trace_write_failure();
        g_trace_fd_state_signals_blocked = 1;
    }
    tid = trace_current_tid();
    for (unsigned int attempt = 0; attempt < 6000; attempt++) {
        int expected = 0;
        int owner;

        if (atomic_compare_exchange_strong_explicit(
                &g_trace_fd_state_owner, &expected, tid,
                memory_order_acq_rel, memory_order_acquire)) {
            g_trace_fd_state_depth = 1;
            errno = saved_errno;
            return;
        }
        owner = atomic_load_explicit(&g_trace_fd_state_owner,
                                     memory_order_acquire);
        if (owner == 0)
            continue;
        if (owner < 0 || owner == tid)
            trace_write_failure();
        {
            const struct timespec timeout = {0, 10000000};
            long wait_result = syscall(
                SYS_futex, (int *)&g_trace_fd_state_owner,
                DLFREEZE_FUTEX_WAIT_PRIVATE, owner, &timeout, NULL, 0);

            if (wait_result < 0 && errno != EAGAIN && errno != EINTR &&
                errno != ETIMEDOUT)
                trace_write_failure();
        }
    }
    trace_write_failure();
}

static void trace_fd_state_unlock(void)
{
    int saved_errno = errno;
    int previous;

    if (g_trace_fd_state_depth == 0)
        trace_write_failure();
    g_trace_fd_state_depth--;
    if (g_trace_fd_state_depth != 0) {
        errno = saved_errno;
        return;
    }
    previous = atomic_exchange_explicit(&g_trace_fd_state_owner, 0,
                                        memory_order_release);
    if (previous <= 0)
        trace_write_failure();
    (void)syscall(SYS_futex, (int *)&g_trace_fd_state_owner,
                  DLFREEZE_FUTEX_WAKE_PRIVATE, INT_MAX, NULL, NULL, 0);
    if (!g_trace_fd_state_signals_blocked ||
        syscall(SYS_rt_sigprocmask, SIG_SETMASK,
                &g_trace_fd_state_saved_signal_mask, NULL,
                sizeof(g_trace_fd_state_saved_signal_mask)) < 0)
        trace_write_failure();
    g_trace_fd_state_signals_blocked = 0;
    errno = saved_errno;
}

static int open_needs_mode(int flags)
{
    return (flags & O_CREAT) || ((flags & O_TMPFILE) == O_TMPFILE);
}

/* Captured DATA is an immutable input snapshot.  A successful writable open
 * describes application output or mutable state, not a reproducible input;
 * recording it also races atomic-write temporaries which commonly disappear
 * before the trace is consumed.  O_PATH remains a pathname observation. */
static int open_is_capture_read(int flags)
{
#ifdef O_PATH
    if (flags & O_PATH)
        return 1;
#endif
    return (flags & O_ACCMODE) == O_RDONLY &&
           !(flags & (O_CREAT | O_TRUNC)) &&
           (flags & O_TMPFILE) != O_TMPFILE;
}

static int fopen_is_capture_read(const char *mode)
{
    return mode && mode[0] == 'r' && strchr(mode, '+') == NULL;
}

/* A helper earlier in LD_PRELOAD's list is not guaranteed to have the first
 * constructor.  In particular, one of its dependencies can run a constructor
 * while these interposers are already visible but before our constructor has
 * run.  Initialize the trace destinations at the first interposed call so no
 * successful operation can precede its readiness record.
 *
 * The TLS address identifies the initializing thread without requiring libc
 * or a loader lock.  A same-thread recursive entry cannot wait for itself and
 * therefore fails closed.  Other threads wait only for the small raw-syscall
 * initialization window; the finite bound also prevents a fork child from
 * hanging forever if it inherited an initializer owned by a vanished thread.
 */
static void ensure_trace_initialized(void)
{
    char dlopen_path[PATH_MAX];
    char file_path[PATH_MAX];
    const char *dlopen_path_value = NULL;
    const char *file_path_value = NULL;
    uintptr_t owner = (uintptr_t)&g_trace_depth;
    uintptr_t state;
    uintptr_t expected = 0;
    int saved_errno = errno;
    pid_t pid = trace_current_pid();
    pid_t expected_pid = expected_trace_owner_pid();

    if (atomic_load_explicit(&g_trace_excluded_image,
                             memory_order_acquire)) {
        errno = saved_errno;
        return;
    }
    state = atomic_load_explicit(&g_trace_init_state, memory_order_acquire);
    if (state == TRACE_INIT_READY)
        return;
    /* Before initialization a vfork child shares every writable byte with
     * its parent.  The collector-supplied immutable environment expectation
     * lets it decline initialization without changing TLS, atomics, or fds. */
    if (expected_pid != 0 && pid != expected_pid) {
        /* A fork+exec descendant may inherit LD_PRELOAD but intentionally not
         * the CLOEXEC trace claim.  Mark this fresh image excluded while
         * still allowing resolve_symbols() to publish transparent RTLD_NEXT
         * forwarders.  A vfork child is only permitted to exec/_exit and its
         * exec wrappers take the immutable PID gate before reaching here. */
        atomic_store_explicit(&g_trace_excluded_image, 1,
                              memory_order_release);
        errno = saved_errno;
        return;
    }
    if (state == owner)
        trace_write_failure();

    if (atomic_compare_exchange_strong_explicit(
            &g_trace_init_state, &expected, owner,
            memory_order_acq_rel, memory_order_acquire)) {
        if (trace_environment_value("DLFREEZE_TRACE_FILE", dlopen_path,
                                    sizeof(dlopen_path)) == 1)
            dlopen_path_value = dlopen_path;
        if (trace_environment_value("DLFREEZE_FILE_TRACE_FILE", file_path,
                                    sizeof(file_path)) == 1)
            file_path_value = file_path;
        g_trace_owner_pid = pid;
        g_trace_participant_pid = pid;
        atomic_store_explicit(&g_dlopen_trace_fd, open_owned_trace_fd(
            dlopen_path_value, DLOPEN_TRACE_FD_ENV,
            DLOPEN_TRACE_ID_ENV,
            &g_dlopen_trace_identity), memory_order_release);
        atomic_store_explicit(&g_file_trace_fd, open_owned_trace_fd(
            file_path_value, FILE_TRACE_FD_ENV,
            FILE_TRACE_ID_ENV,
            &g_file_trace_identity), memory_order_release);
        write_trace_line(TRACE_STREAM_DLOPEN, "", DLOPEN_TRACE_READY);
        write_trace_owner_record(TRACE_STREAM_DLOPEN);
        write_trace_line(TRACE_STREAM_FILE, "", PRELOAD_TRACE_READY);
        write_trace_owner_record(TRACE_STREAM_FILE);
        if (g_dlopen_trace_fd >= 0 && write_initial_map_evidence() < 0)
            write_trace_terminal_record(
                TRACE_STREAM_DLOPEN,
                "initial-mapped-object-evidence-is-unavailable");
        atomic_store_explicit(&g_trace_init_state, TRACE_INIT_READY,
                              memory_order_release);
        errno = saved_errno;
        return;
    }

    for (unsigned int attempt = 0; attempt < 65536; attempt++) {
        state = atomic_load_explicit(&g_trace_init_state,
                                     memory_order_acquire);
        if (state == TRACE_INIT_READY) {
            errno = saved_errno;
            return;
        }
        if (state == owner)
            trace_write_failure();
        (void)syscall(SYS_sched_yield);
    }
    trace_write_failure();
}

static void resolve_symbols(void)
{
    int saved_errno;
    pid_t expected_pid = expected_trace_owner_pid();

    if (g_trace_owner_pid == 0 && expected_pid != 0 &&
        trace_current_pid() != expected_pid)
        atomic_store_explicit(&g_trace_excluded_image, 1,
                              memory_order_release);
    else if (!atomic_load_explicit(&g_trace_excluded_image,
                                   memory_order_acquire))
        ensure_trace_initialized();

    /* Constructors normally resolve this table before application threads
     * exist, but another preload's constructor can call an interposed entry
     * point first.  Every slot and the completion flag are atomic so those
     * calls may resolve concurrently without publishing a torn table.
     *
     * dlsym itself is allowed to reach an interposed operation.  Do not
     * recursively start the whole pass on the same thread: the nested wrapper
     * will use any slot already published.  The open family has a raw-kernel
     * fallback because loader implementations may open files while resolving
     * symbols; higher-level operations fail cleanly until their slot exists.
     * No libc lock or pthread_once is used here, avoiding recursive-once
     * deadlocks during loader initialization. */
    if (atomic_load_explicit(&g_symbols_resolved, memory_order_acquire) ||
        g_symbols_resolving)
        return;

    saved_errno = errno;
    g_symbols_resolving = 1;
    g_trace_depth++;
    if (!real_dlopen)
        real_dlopen = dlsym(RTLD_NEXT, "dlopen");
#if DLFREEZE_HAVE_DLMOPEN
    if (!real_dlmopen)
        real_dlmopen = dlsym(RTLD_NEXT, "dlmopen");
#endif
    if (!real_open)
        real_open = dlsym(RTLD_NEXT, "open");
#if DLFREEZE_HAVE_OPEN64_SYMBOL
    if (!real_open64)
        real_open64 = dlsym(RTLD_NEXT, "open64");
#endif
    if (!real_openat)
        real_openat = dlsym(RTLD_NEXT, "openat");
#if DLFREEZE_HAVE_OPENAT64_SYMBOL
    if (!real_openat64)
        real_openat64 = dlsym(RTLD_NEXT, "openat64");
#endif
#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
    if (!real_open_2)
        real_open_2 = dlsym(RTLD_NEXT, "__open_2");
    if (!real_open64_2)
        real_open64_2 = dlsym(RTLD_NEXT, "__open64_2");
    if (!real_openat_2)
        real_openat_2 = dlsym(RTLD_NEXT, "__openat_2");
    if (!real_openat64_2)
        real_openat64_2 = dlsym(RTLD_NEXT, "__openat64_2");
#endif
    if (!real_fopen)
        real_fopen = dlsym(RTLD_NEXT, "fopen");
#if DLFREEZE_HAVE_FOPEN64_SYMBOL
    if (!real_fopen64)
        real_fopen64 = dlsym(RTLD_NEXT, "fopen64");
#endif
    if (!real_opendir)
        real_opendir = dlsym(RTLD_NEXT, "opendir");
    if (!real_stat)
        real_stat = dlsym(RTLD_NEXT, "stat");
#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
    if (!real_stat64)
        real_stat64 = dlsym(RTLD_NEXT, "stat64");
#endif
    if (!real_lstat)
        real_lstat = dlsym(RTLD_NEXT, "lstat");
#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
    if (!real_lstat64)
        real_lstat64 = dlsym(RTLD_NEXT, "lstat64");
#endif
    if (!real_fstatat)
        real_fstatat = dlsym(RTLD_NEXT, "fstatat");
#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
    if (!real_fstatat64)
        real_fstatat64 = dlsym(RTLD_NEXT, "fstatat64");
    if (!real_xstat)
        real_xstat = dlsym(RTLD_NEXT, "__xstat");
    if (!real_xstat64)
        real_xstat64 = dlsym(RTLD_NEXT, "__xstat64");
    if (!real_lxstat)
        real_lxstat = dlsym(RTLD_NEXT, "__lxstat");
    if (!real_lxstat64)
        real_lxstat64 = dlsym(RTLD_NEXT, "__lxstat64");
    if (!real_fxstatat)
        real_fxstatat = dlsym(RTLD_NEXT, "__fxstatat");
    if (!real_fxstatat64)
        real_fxstatat64 = dlsym(RTLD_NEXT, "__fxstatat64");
#endif
    if (!real_access)
        real_access = dlsym(RTLD_NEXT, "access");
    if (!real_faccessat)
        real_faccessat = dlsym(RTLD_NEXT, "faccessat");
    if (!real_execve)
        real_execve = dlsym(RTLD_NEXT, "execve");
#if defined(SYS_execveat)
    if (!real_execveat)
        real_execveat = dlsym(RTLD_NEXT, "execveat");
#endif
    if (!real_fexecve)
        real_fexecve = dlsym(RTLD_NEXT, "fexecve");
    if (!real_execvp)
        real_execvp = dlsym(RTLD_NEXT, "execvp");
    if (!real_execvpe)
        real_execvpe = dlsym(RTLD_NEXT, "execvpe");
    if (!real_fork)
        real_fork = dlsym(RTLD_NEXT, "fork");
    if (!real_close)
        real_close = dlsym(RTLD_NEXT, "close");
    if (!real_close_range)
        real_close_range = dlsym(RTLD_NEXT, "close_range");
    if (!real_closefrom)
        real_closefrom = dlsym(RTLD_NEXT, "closefrom");
    if (!real_dup)
        real_dup = dlsym(RTLD_NEXT, "dup");
    if (!real_dup2)
        real_dup2 = dlsym(RTLD_NEXT, "dup2");
    if (!real_dup3)
        real_dup3 = dlsym(RTLD_NEXT, "dup3");
    if (!real_chdir)
        real_chdir = dlsym(RTLD_NEXT, "chdir");
    if (!real_fchdir)
        real_fchdir = dlsym(RTLD_NEXT, "fchdir");
    if (!real_chroot)
        real_chroot = dlsym(RTLD_NEXT, "chroot");
    atomic_store_explicit(&g_symbols_resolved, 1, memory_order_release);
    g_trace_depth--;
    g_symbols_resolving = 0;
    errno = saved_errno;
}

static int raw_fstat(int fd, struct stat *st)
{
    int rc;

    do {
        rc = (int)syscall(SYS_fstat, fd, st);
    } while (rc < 0 && errno == EINTR);
    return rc;
}

static int raw_fstatat(int dirfd, const char *path, struct stat *st,
                       int flags)
{
    int rc;

#if defined(SYS_newfstatat)
    do {
        rc = (int)syscall(SYS_newfstatat, dirfd, path, st, flags);
    } while (rc < 0 && errno == EINTR);
    return rc;
#elif defined(SYS_fstatat64)
    do {
        rc = (int)syscall(SYS_fstatat64, dirfd, path, st, flags);
    } while (rc < 0 && errno == EINTR);
    return rc;
#else
    (void)dirfd;
    (void)path;
    (void)st;
    (void)flags;
    errno = ENOSYS;
    return -1;
#endif
}

static int stat_identity_matches(const struct stat *left,
                                 const struct stat *right)
{
    return left && right && left->st_dev == right->st_dev &&
           left->st_ino == right->st_ino &&
           left->st_rdev == right->st_rdev &&
           (left->st_mode & S_IFMT) == (right->st_mode & S_IFMT);
}

static void file_trace_snapshot_from_stat(struct file_trace_snapshot *out,
                                          const struct stat *st)
{
    out->device = (uint64_t)st->st_dev;
    out->inode = (uint64_t)st->st_ino;
    out->type = (uint64_t)(st->st_mode & S_IFMT);
    out->size = (uint64_t)st->st_size;
    out->mtime_sec = (uint64_t)st->st_mtim.tv_sec;
    out->mtime_nsec = (uint64_t)st->st_mtim.tv_nsec;
    out->ctime_sec = (uint64_t)st->st_ctim.tv_sec;
    out->ctime_nsec = (uint64_t)st->st_ctim.tv_nsec;
}

#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
static void file_trace_snapshot_from_stat64(struct file_trace_snapshot *out,
                                            const struct stat64 *st)
{
    out->device = (uint64_t)st->st_dev;
    out->inode = (uint64_t)st->st_ino;
    out->type = (uint64_t)(st->st_mode & S_IFMT);
    out->size = (uint64_t)st->st_size;
    out->mtime_sec = (uint64_t)st->st_mtim.tv_sec;
    out->mtime_nsec = (uint64_t)st->st_mtim.tv_nsec;
    out->ctime_sec = (uint64_t)st->st_ctim.tv_sec;
    out->ctime_nsec = (uint64_t)st->st_ctim.tv_nsec;
}
#endif

static int file_trace_snapshot_matches_stat(
    const struct file_trace_snapshot *snapshot, const struct stat *st)
{
    struct file_trace_snapshot current;

    if (!snapshot || !st)
        return 0;
    file_trace_snapshot_from_stat(&current, st);
    if (snapshot->device != current.device ||
        snapshot->inode != current.inode || snapshot->type != current.type)
        return 0;
    if (snapshot->type == S_IFDIR)
        return 1;
    return snapshot->type == S_IFREG && snapshot->size == current.size &&
           snapshot->mtime_sec == current.mtime_sec &&
           snapshot->mtime_nsec == current.mtime_nsec &&
           snapshot->ctime_sec == current.ctime_sec &&
           snapshot->ctime_nsec == current.ctime_nsec;
}

static int path_snapshot_matches(const char *path,
                                 const struct file_trace_snapshot *snapshot)
{
    struct stat st;

    return path && path[0] == '/' &&
           raw_fstatat(AT_FDCWD, path, &st, 0) == 0 &&
           file_trace_snapshot_matches_stat(snapshot, &st);
}

static int fd_snapshot_matches(int fd,
                               const struct file_trace_snapshot *snapshot)
{
    struct stat st;

    return raw_fstat(fd, &st) == 0 &&
           file_trace_snapshot_matches_stat(snapshot, &st);
}

static int path_identity_matches_fd(const char *path, int fd)
{
    struct stat path_st;
    struct stat fd_st;

    return path && path[0] == '/' && raw_fstat(fd, &fd_st) == 0 &&
           raw_fstatat(AT_FDCWD, path, &path_st, 0) == 0 &&
           stat_identity_matches(&fd_st, &path_st);
}

static void save_trace_fd_identity(const struct stat *st,
                                   struct trace_fd_identity *identity)
{
    identity->device = st->st_dev;
    identity->inode = st->st_ino;
    identity->rdevice = st->st_rdev;
    identity->type = st->st_mode & S_IFMT;
}

static int trace_fd_identity_matches(int fd,
                                     const struct trace_fd_identity *identity)
{
    struct stat st;

    return raw_fstat(fd, &st) == 0 &&
           st.st_dev == identity->device && st.st_ino == identity->inode &&
           st.st_rdev == identity->rdevice &&
           (st.st_mode & S_IFMT) == identity->type;
}

static int open_trace_fd(const char *path, struct trace_fd_identity *identity)
{
    struct stat st;
    int fd;
    int moved_fd;

    if (!path || !path[0])
        return -1;

    fd = (int)syscall(SYS_openat, AT_FDCWD, path,
                      O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC |
                          O_NOFOLLOW | O_NONBLOCK,
                      0600);
    if (fd < 0)
        return -1;
    /* Never retain the descriptor number returned by openat.  In particular,
     * the traced image may intentionally start with one or more of 0/1/2
     * closed.  Duplicating the same open file description and then closing
     * the original restores that first-free slot before application code can
     * observe it, while preserving O_APPEND and the later flock claim. */
    do {
        moved_fd = (int)syscall(SYS_fcntl, fd, F_DUPFD_CLOEXEC,
                                STDERR_FILENO + 1);
    } while (moved_fd < 0 && errno == EINTR);
    if (moved_fd < 0) {
        (void)syscall(SYS_close, fd);
        return -1;
    }
    (void)syscall(SYS_close, fd);
    fd = moved_fd;
    if (raw_fstat(fd, &st) < 0) {
        (void)syscall(SYS_close, fd);
        return -1;
    }
    save_trace_fd_identity(&st, identity);
    return fd;
}

static int decode_identity_hex(const char *value, size_t offset,
                               uint64_t *decoded)
{
    uint64_t result = 0;

    for (size_t index = 0; index < 16; index++) {
        unsigned int digit;
        char character = value[offset + index];

        if (character >= '0' && character <= '9')
            digit = (unsigned int)(character - '0');
        else if (character >= 'a' && character <= 'f')
            digit = (unsigned int)(character - 'a') + 10U;
        else
            return 0;
        result = (result << 4) | digit;
    }
    *decoded = result;
    return 1;
}

static int expected_trace_identity(const char *environment,
                                   struct trace_fd_identity *identity)
{
    char value[69];
    uint64_t fields[4];
    size_t length;

    if (!identity ||
        trace_environment_value(environment, value, sizeof(value)) != 1 ||
        !bounded_string_length(value, sizeof(value), &length) || length != 67 ||
        value[16] != ':' || value[33] != ':' || value[50] != ':' ||
        !decode_identity_hex(value, 0, &fields[0]) ||
        !decode_identity_hex(value, 17, &fields[1]) ||
        !decode_identity_hex(value, 34, &fields[2]) ||
        !decode_identity_hex(value, 51, &fields[3]))
        return 0;
    identity->device = (dev_t)fields[0];
    identity->inode = (ino_t)fields[1];
    identity->type = (mode_t)fields[2];
    identity->rdevice = (dev_t)fields[3];
    return (uint64_t)identity->device == fields[0] &&
           (uint64_t)identity->inode == fields[1] &&
           (uint64_t)identity->type == fields[2] &&
           (uint64_t)identity->rdevice == fields[3] &&
           identity->type == S_IFREG;
}

static int inherited_trace_fd(const char *fd_environment,
                              const char *identity_environment,
                              struct trace_fd_identity *identity)
{
    char fd_value[33];
    struct trace_fd_identity expected_identity;
    struct stat status;
    struct stat initial_status;
    uint64_t descriptor = 0;
    size_t fd_length;
    int original_fd;
    int moved_fd;
    int descriptor_flags;
    int environment_result;

    environment_result = trace_environment_value(
        fd_environment, fd_value, sizeof(fd_value));
    if (environment_result == 0)
        return -2;
    if (environment_result != 1)
        return -1;
    if (!identity_environment ||
        !expected_trace_identity(identity_environment, &expected_identity) ||
        !identity || !bounded_string_length(fd_value, sizeof(fd_value),
                                             &fd_length) ||
        fd_length == 0)
        return -1;
    for (size_t index = 0; index < fd_length; index++) {
        unsigned int digit;

        if (fd_value[index] < '0' || fd_value[index] > '9')
            return -1;
        digit = (unsigned int)(fd_value[index] - '0');
        if (descriptor > (uint64_t)(INT_MAX - (int)digit) / 10U)
            return -1;
        descriptor = descriptor * 10U + digit;
    }
    original_fd = (int)descriptor;
    if (raw_fstat(original_fd, &status) < 0 ||
        !S_ISREG(status.st_mode) || status.st_size != 0 ||
        status.st_dev != expected_identity.device ||
        status.st_ino != expected_identity.inode ||
        status.st_rdev != expected_identity.rdevice ||
        (status.st_mode & S_IFMT) != expected_identity.type)
        return -1;
    initial_status = status;
    descriptor_flags = (int)syscall(SYS_fcntl, original_fd, F_GETFL);
    if (descriptor_flags < 0 ||
        (descriptor_flags & O_APPEND) == 0)
        return -1;
    do {
        moved_fd = (int)syscall(SYS_fcntl, original_fd,
                                F_DUPFD_CLOEXEC, 3);
    } while (moved_fd < 0 && errno == EINTR);
    if (moved_fd < 0) {
        (void)syscall(SYS_close, original_fd);
        return -1;
    }
    (void)syscall(SYS_close, original_fd);
    if (raw_fstat(moved_fd, &status) < 0 || !S_ISREG(status.st_mode) ||
        status.st_size != 0 ||
        !stat_identity_matches(&initial_status, &status)) {
        (void)syscall(SYS_close, moved_fd);
        return -1;
    }
    save_trace_fd_identity(&status, identity);
    return moved_fd;
}

static void append_claim_failure_record(int fd)
{
    static const char digits[] = "0123456789abcdef";
    static const char reason[] = "trace-stream-already-claimed";
    char record[2 + 16 + 1 + sizeof(reason) - 1 + 1];
    uint64_t pid = (uint64_t)trace_current_pid();
    size_t pos = 0;
    ssize_t written;

    record[pos++] = '!';
    record[pos++] = ' ';
    for (unsigned int shift = 60; ; shift -= 4) {
        record[pos++] = digits[(pid >> shift) & 0xf];
        if (shift == 0)
            break;
    }
    record[pos++] = ' ';
    memcpy(record + pos, reason, sizeof(reason) - 1);
    pos += sizeof(reason) - 1;
    record[pos++] = '\n';
    if (pos != sizeof(record))
        trace_write_failure();
    do {
        written = syscall(SYS_write, fd, record, sizeof(record));
    } while (written < 0 && errno == EINTR);
    if (written < 0 || (size_t)written != sizeof(record))
        trace_write_failure();
}

/* Claim an empty stream for one process image.  flock locks are associated
 * with the open file description, so duplicated descriptors used for atomic
 * writes and fork descendants retain the claim.  O_CLOEXEC releases it when
 * a process replaces its image.  A newly loaded helper then appends a
 * terminal marker, rather than leaving the pre-exec trace prefix looking
 * complete. */
static int open_owned_trace_fd(
    const char *path, const char *fd_environment,
    const char *identity_environment,
    struct trace_fd_identity *identity)
{
    struct stat st;
    int fd = inherited_trace_fd(fd_environment, identity_environment,
                                identity);
    int lock_result;

    if (fd == -2)
        fd = open_trace_fd(path, identity);
    if (fd < 0)
        return -1;
    lock_result = (int)syscall(SYS_flock, fd, LOCK_EX | LOCK_NB);
    if (lock_result < 0) {
        /* The ordinary case is a fork+exec descendant while the original
         * process tree still owns the inherited OFD lock.  Exclude that new
         * process image without writing unlocked bytes into the owner's
         * stream.  Any other lock failure also leaves the root without a
         * readiness header and therefore fails closed at collection. */
        (void)syscall(SYS_close, fd);
        return -1;
    }
    if (raw_fstat(fd, &st) < 0 || st.st_size != 0) {
        /* With the lock acquired, a nonempty stream can only be an earlier
         * process image (most importantly, a same-pid exec).  Poison that
         * otherwise plausible prefix explicitly. */
        append_claim_failure_record(fd);
        (void)syscall(SYS_close, fd);
        return -1;
    }
    return fd;
}

static int raw_openat(int dirfd, const char *path, int flags, mode_t mode)
{
    return (int)syscall(SYS_openat, dirfd, path, flags, mode);
}

struct cwd_observation {
    uint64_t epoch;
    char cwd[PATH_MAX];
    char dirfd_path[PATH_MAX];
    struct trace_fd_identity cwd_identity;
    struct trace_fd_identity dirfd_identity;
    int dirfd;
    int required;
    int dirfd_required;
    int valid;
};

static int capture_stable_cwd(char cwd[PATH_MAX], uint64_t *epoch_out,
                              struct trace_fd_identity *identity_out)
{
    struct stat before_status;
    struct stat after_status;
    struct stat path_status;
    int saved_errno = errno;

    if (!cwd || !epoch_out)
        return 0;
    recover_cwd_state_in_wrapped_fork_child();
    for (unsigned int attempt = 0; attempt < 65536; attempt++) {
        uint64_t before = atomic_load_explicit(&g_cwd_epoch,
                                               memory_order_acquire);
        uint64_t after;

        if (atomic_load_explicit(&g_cwd_active_writers,
                                 memory_order_acquire) != 0)
            break;
        if (raw_fstatat(AT_FDCWD, ".", &before_status, 0) < 0 ||
            !S_ISDIR(before_status.st_mode)) {
            errno = saved_errno;
            return 0;
        }
        g_trace_depth++;
        if (!getcwd(cwd, PATH_MAX)) {
            g_trace_depth--;
            errno = saved_errno;
            return 0;
        }
        g_trace_depth--;
        if (raw_fstatat(AT_FDCWD, ".", &after_status, 0) < 0 ||
            raw_fstatat(AT_FDCWD, cwd, &path_status, 0) < 0 ||
            !stat_identity_matches(&before_status, &after_status) ||
            !stat_identity_matches(&after_status, &path_status)) {
            errno = saved_errno;
            return 0;
        }
        after = atomic_load_explicit(&g_cwd_epoch, memory_order_acquire);
        if (before == after &&
            atomic_load_explicit(&g_cwd_active_writers,
                                 memory_order_acquire) == 0) {
            *epoch_out = after;
            if (identity_out)
                save_trace_fd_identity(&after_status, identity_out);
            errno = saved_errno;
            return 1;
        }
    }
    errno = saved_errno;
    return 0;
}

static void begin_cwd_observation(int dirfd, const char *path,
                                  struct cwd_observation *observation)
{
    struct stat before;
    struct stat after;
    char proc_path[64];
    ssize_t length;
    int proc_length;
    int saved_errno = errno;

    memset(observation, 0, sizeof(*observation));
    if (g_file_trace_fd < 0 || !path || !path[0] || path[0] == '/')
        goto out;
    observation->required = dirfd == AT_FDCWD;
    observation->dirfd_required = dirfd != AT_FDCWD;
    observation->dirfd = dirfd;
    if (observation->required) {
        observation->valid = capture_stable_cwd(
            observation->cwd, &observation->epoch,
            &observation->cwd_identity);
        goto out;
    }
    proc_length = snprintf(proc_path, sizeof(proc_path),
                           "/proc/self/fd/%d", dirfd);
    if (proc_length < 0 || (size_t)proc_length >= sizeof(proc_path) ||
        raw_fstat(dirfd, &before) < 0 || !S_ISDIR(before.st_mode))
        goto out;
    length = readlink(proc_path, observation->dirfd_path,
                      sizeof(observation->dirfd_path) - 1);
    if (length < 0 ||
        (size_t)length >= sizeof(observation->dirfd_path) - 1 ||
        raw_fstat(dirfd, &after) < 0 ||
        !stat_identity_matches(&before, &after))
        goto out;
    observation->dirfd_path[length] = '\0';
    if (observation->dirfd_path[0] != '/' ||
        !path_identity_matches_fd(observation->dirfd_path, dirfd))
        goto out;
    save_trace_fd_identity(&after, &observation->dirfd_identity);
    observation->valid = 1;
out:
    errno = saved_errno;
}

static int finish_cwd_observation(
    const struct cwd_observation *observation)
{
    uint64_t current;
    int saved_errno = errno;
    int accepted = 0;

    if (!observation ||
        (!observation->required && !observation->dirfd_required)) {
        accepted = 1;
        goto out;
    }
    if (observation->dirfd_required) {
        struct stat current_status;

        if (observation->valid &&
            raw_fstat(observation->dirfd, &current_status) == 0 &&
            current_status.st_dev == observation->dirfd_identity.device &&
            current_status.st_ino == observation->dirfd_identity.inode &&
            current_status.st_rdev == observation->dirfd_identity.rdevice &&
            (current_status.st_mode & S_IFMT) ==
                observation->dirfd_identity.type &&
            path_identity_matches_fd(observation->dirfd_path,
                                     observation->dirfd))
            accepted = 1;
        if (accepted)
            goto out;
        write_file_failure("dirfd-changed-during-file-operation");
        goto out;
    }
    current = atomic_load_explicit(&g_cwd_epoch, memory_order_acquire);
    if (observation->valid && current == observation->epoch &&
        atomic_load_explicit(&g_cwd_active_writers,
                             memory_order_acquire) == 0) {
        struct stat cwd_status;
        struct stat path_status;

        if (raw_fstatat(AT_FDCWD, ".", &cwd_status, 0) == 0 &&
            raw_fstatat(AT_FDCWD, observation->cwd,
                        &path_status, 0) == 0 &&
            cwd_status.st_dev == observation->cwd_identity.device &&
            cwd_status.st_ino == observation->cwd_identity.inode &&
            cwd_status.st_rdev == observation->cwd_identity.rdevice &&
            (cwd_status.st_mode & S_IFMT) ==
                observation->cwd_identity.type &&
            stat_identity_matches(&cwd_status, &path_status))
            accepted = 1;
    }
    if (!accepted) {
        write_file_failure("cwd-changed-during-file-operation");
    }
out:
    errno = saved_errno;
    return accepted;
}

static int build_path(int dirfd, const char *path,
                      const struct cwd_observation *observation,
                      char *out, size_t out_sz)
{
    char base[PATH_MAX];
    size_t path_len;

    if (!path || !path[0] || !out || out_sz == 0)
        return 0;

    if (path[0] == '/') {
        if (!bounded_string_length(path, out_sz, &path_len))
            return 0;
        memcpy(out, path, path_len + 1);
        return 1;
    }

    if (dirfd == AT_FDCWD) {
        if (observation && observation->required && observation->valid)
            memcpy(base, observation->cwd,
                   strlen(observation->cwd) + 1);
        else if (!getcwd(base, sizeof(base)))
            return 0;
    } else if (observation && observation->dirfd_required &&
               observation->valid && observation->dirfd == dirfd) {
        memcpy(base, observation->dirfd_path,
               strlen(observation->dirfd_path) + 1);
    } else {
        char proc_path[64];
        ssize_t len;

        int proc_length = snprintf(proc_path, sizeof(proc_path),
                                   "/proc/self/fd/%d", dirfd);

        if (proc_length < 0 || (size_t)proc_length >= sizeof(proc_path))
            return 0;
        len = readlink(proc_path, base, sizeof(base) - 1);
        if (len < 0 || (size_t)len >= sizeof(base) - 1)
            return 0;
        base[len] = '\0';
        if (base[0] != '/' || !path_identity_matches_fd(base, dirfd))
            return 0;
    }

    {
        int length = snprintf(out, out_sz, "%s/%s", base, path);

        return length >= 0 && (size_t)length < out_sz;
    }
}

static int canonicalize_path(char *path, size_t path_sz)
{
    char resolved[PATH_MAX];
    size_t resolved_len;
    int canonicalized = 0;
    int saved_errno = errno;

    if (!path || !path[0])
        return 0;

    g_trace_depth++;
    if (realpath(path, resolved) &&
        bounded_string_length(resolved, path_sz, &resolved_len)) {
        memcpy(path, resolved, resolved_len + 1);
        canonicalized = 1;
    }
    g_trace_depth--;
    errno = saved_errno;
    return canonicalized;
}

static void best_effort_poison_trace_stream(
    int fd, const struct trace_fd_identity *identity,
    const char *path_environment)
{
    static const char poison[] = "!\n";
    char path[PATH_MAX];
    int reopened;

    if (!identity)
        return;
    if (fd >= 0 && trace_fd_identity_matches(fd, identity) &&
        syscall(SYS_write, fd, poison, sizeof(poison) - 1) ==
            (ssize_t)(sizeof(poison) - 1))
        return;
    if (trace_environment_value(path_environment, path, sizeof(path)) != 1 ||
        !path[0])
        return;
    reopened = (int)syscall(
        SYS_openat, AT_FDCWD, path,
        O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0);
    if (reopened < 0)
        return;
    if (trace_fd_identity_matches(reopened, identity))
        (void)syscall(SYS_write, reopened, poison, sizeof(poison) - 1);
    (void)syscall(SYS_close, reopened);
}

static void trace_write_failure(void)
{
    static const char message[] =
        "dlfreeze: trace helper cannot write a complete trace record\n";
    long raw_pid;

    /* Do not return to the traced program after losing a record: a complete
     * readiness header followed by an omitted record would otherwise be
     * indistinguishable from a complete trace.  Use raw syscalls so the
     * failure path cannot recurse through an interposed libc entry point. */
    if (!g_trace_failure_active) {
        g_trace_failure_active = 1;
        /* Wrapped close/dup/close_range operations use this same recursive
         * lock.  Hold it across each identity check and append so an
         * application descriptor cannot reuse the checked number before the
         * poison write.  If acquiring or releasing an already-corrupt lock
         * itself fails, the recursive failure skips poisoning and proceeds
         * directly to the uncatchable termination below. */
        trace_fd_state_lock();
        best_effort_poison_trace_stream(
            atomic_load_explicit(&g_dlopen_trace_fd,
                                 memory_order_acquire),
            &g_dlopen_trace_identity, "DLFREEZE_TRACE_FILE");
        best_effort_poison_trace_stream(
            atomic_load_explicit(&g_file_trace_fd,
                                 memory_order_acquire),
            &g_file_trace_identity, "DLFREEZE_FILE_TRACE_FILE");
        trace_fd_state_unlock();
    }
    (void)syscall(SYS_write, STDERR_FILENO, message, sizeof(message) - 1);
    /* The trace supervisor accepts every normal target exit code, including
     * 127.  Use an uncatchable signal so helper failure is distinguishable
     * without reserving an application status.  A seccomp RET_ERRNO policy
     * can make raw getpid fail; never turn that negative result into
     * kill(-1), which has process-set semantics. */
    raw_pid = syscall(SYS_getpid);
    if (raw_pid > 0 && raw_pid <= INT_MAX)
        (void)syscall(SYS_kill, (pid_t)raw_pid, SIGKILL);
    /* A seccomp policy may deny kill(2) and trace writes.  A compiler trap
     * still produces a signaled exit (or repeatedly faults if an application
     * handler returns), never the supervisor-accepted normal status 127. */
    __builtin_trap();
    /* Belt-and-suspenders only: the trap intrinsic is noreturn. */
    (void)syscall(SYS_exit_group, 127);
    __builtin_unreachable();
}

static _Atomic int *trace_stream_descriptor(enum trace_stream_kind stream)
{
    return stream == TRACE_STREAM_DLOPEN ? &g_dlopen_trace_fd
                                         : &g_file_trace_fd;
}

static const struct trace_fd_identity *trace_stream_identity(
    enum trace_stream_kind stream)
{
    return stream == TRACE_STREAM_DLOPEN ? &g_dlopen_trace_identity
                                         : &g_file_trace_identity;
}

/* Serialize the published descriptor through identity validation and the
 * append itself.  Wrapped close/dup/close_range operations take the same
 * recursive lock, so they cannot close and reuse the checked descriptor in
 * that interval.  One record is one append write: if the kernel ever reports
 * a partial regular-file write, the record is already unusable and continuing
 * could interleave it with another process, so terminate the trace instead of
 * manufacturing corrupt syntax. */
static void trace_write_exact(enum trace_stream_kind stream,
                              const void *buffer, size_t length)
{
    _Atomic int *published = trace_stream_descriptor(stream);
    const struct trace_fd_identity *identity = trace_stream_identity(stream);
    ssize_t written;
    int fd;

    if (!buffer || length == 0)
        trace_write_failure();
    trace_fd_state_lock();
    fd = atomic_load_explicit(published, memory_order_acquire);
    if (fd < 0) {
        /* A concurrent CLOSE_RANGE_UNSHARE abandonment has already emitted
         * terminal records.  Let an in-flight producer retire quietly after
         * that fail-closed publication instead of killing the target. */
        if (!atomic_load_explicit(&g_trace_collection_abandoned,
                                  memory_order_acquire))
            trace_write_failure();
        trace_fd_state_unlock();
        return;
    }
    if (!trace_fd_identity_matches(fd, identity))
        trace_write_failure();

    do {
        written = syscall(SYS_write, fd, buffer, length);
    } while (written < 0 && errno == EINTR);
    if (written < 0 || (size_t)written != length)
        trace_write_failure();
    trace_fd_state_unlock();
}

static void *allocate_trace_record(size_t length)
{
    void *allocation;

    if (length == 0)
        return NULL;
    allocation = (void *)syscall(SYS_mmap, NULL, length,
                                 PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return allocation == MAP_FAILED ? NULL : allocation;
}

static void release_trace_record(void *record, size_t length)
{
    if (record && length > 0)
        (void)syscall(SYS_munmap, record, length);
}

#define TRACE_MAPPED_OBJECT_LIMIT 65536U

struct mapped_file_identity {
    uint64_t device;
    uint64_t inode;
};

struct mapped_identity_set {
    struct mapped_file_identity *items;
    size_t count;
    size_t capacity;
};

static int parse_maps_unsigned(const char **cursor, int base, char terminator,
                               uint64_t *value_out)
{
    const char *p = *cursor;
    uint64_t value = 0;
    int digits = 0;

    while (*p && *p != terminator) {
        unsigned int digit;

        if (*p >= '0' && *p <= '9')
            digit = (unsigned int)(*p - '0');
        else if (base == 16 && *p >= 'a' && *p <= 'f')
            digit = (unsigned int)(*p - 'a') + 10U;
        else
            return 0;
        if (digit >= (unsigned int)base ||
            value > (UINT64_MAX - digit) / (uint64_t)base)
            return 0;
        value = value * (uint64_t)base + digit;
        digits = 1;
        p++;
    }
    if (!digits || *p != terminator)
        return 0;
    *cursor = p + 1;
    *value_out = value;
    return 1;
}

static int skip_maps_field(const char **cursor)
{
    const char *p = *cursor;

    if (!p || !*p || *p == ' ')
        return 0;
    while (*p && *p != ' ')
        p++;
    if (*p != ' ')
        return 0;
    while (*p == ' ')
        p++;
    *cursor = p;
    return 1;
}

static int decode_maps_path(const char *encoded, char *path, size_t path_size)
{
    size_t out = 0;

    if (!encoded || encoded[0] != '/' || !path || path_size == 0)
        return 0;
    for (size_t in = 0; encoded[in] != '\0'; in++) {
        unsigned char value = (unsigned char)encoded[in];

        if (value == '\\') {
            unsigned int decoded;

            if (encoded[in + 1] < '0' || encoded[in + 1] > '7' ||
                encoded[in + 2] < '0' || encoded[in + 2] > '7' ||
                encoded[in + 3] < '0' || encoded[in + 3] > '7')
                return 0;
            decoded = (unsigned int)(((encoded[in + 1] - '0') << 6) |
                                     ((encoded[in + 2] - '0') << 3) |
                                     (encoded[in + 3] - '0'));
            if (decoded > 0377U)
                return 0;
            value = (unsigned char)decoded;
            in += 3;
            if (value == '\0')
                return 0;
        }
        if (out + 1 >= path_size)
            return 0;
        path[out++] = (char)value;
    }
    path[out] = '\0';
    return out > 0;
}

/* Return one for a file-backed mapping, zero for a kernel/anonymous mapping,
 * and minus one if procfs cannot authoritatively describe the supplied
 * in-image address. */
static int parse_maps_line_for_address(
    char *line, uintptr_t address, struct mapped_file_identity *identity,
    char *path, size_t path_size)
{
    const char *cursor = line;
    uint64_t start, end, major_number, minor_number, inode;

    if (!parse_maps_unsigned(&cursor, 16, '-', &start) ||
        !parse_maps_unsigned(&cursor, 16, ' ', &end) || start >= end)
        return -1;
    while (*cursor == ' ')
        cursor++;
    if ((uint64_t)address < start || (uint64_t)address >= end)
        return -2;
    if (!skip_maps_field(&cursor) || !skip_maps_field(&cursor) ||
        !parse_maps_unsigned(&cursor, 16, ':', &major_number) ||
        !parse_maps_unsigned(&cursor, 16, ' ', &minor_number))
        return -1;
    while (*cursor == ' ')
        cursor++;
    {
        const char *inode_start = cursor;
        const char *inode_end = cursor;

        while (*inode_end >= '0' && *inode_end <= '9')
            inode_end++;
        if (inode_end == inode_start ||
            (*inode_end != '\0' && *inode_end != ' '))
            return -1;
        if (*inode_end == '\0') {
            const char *temporary = inode_start;

            if (!parse_maps_unsigned(&temporary, 10, '\0', &inode))
                return -1;
            cursor = inode_end;
        } else {
            const char *temporary = inode_start;

            if (!parse_maps_unsigned(&temporary, 10, ' ', &inode))
                return -1;
            cursor = temporary;
            while (*cursor == ' ')
                cursor++;
        }
    }
    if (inode == 0)
        return 0;
    if (major_number > UINT_MAX || minor_number > UINT_MAX ||
        !decode_maps_path(cursor, path, path_size))
        return -1;
    identity->device = (uint64_t)makedev((unsigned int)major_number,
                                        (unsigned int)minor_number);
    identity->inode = inode;
    return 1;
}

static int mapped_identity_for_address(
    uintptr_t address, struct mapped_file_identity *identity,
    char *path, size_t path_size)
{
    char read_buffer[4096];
    char line[PATH_MAX + 256];
    size_t line_length = 0;
    int fd;
    int result = -1;

    if (address == 0 || !identity || !path || path_size == 0)
        return -1;
    fd = raw_openat(AT_FDCWD, "/proc/self/maps",
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (fd < 0)
        return -1;
    for (;;) {
        ssize_t count;

        do {
            count = syscall(SYS_read, fd, read_buffer, sizeof(read_buffer));
        } while (count < 0 && errno == EINTR);
        if (count < 0)
            break;
        if (count == 0) {
            if (line_length != 0)
                break;
            result = -1;
            break;
        }
        for (ssize_t index = 0; index < count; index++) {
            if (read_buffer[index] != '\n') {
                if (line_length + 1 >= sizeof(line)) {
                    result = -1;
                    goto out;
                }
                line[line_length++] = read_buffer[index];
                continue;
            }
            line[line_length] = '\0';
            result = parse_maps_line_for_address(
                line, address, identity, path, path_size);
            line_length = 0;
            if (result != -2)
                goto out;
        }
    }
out:
    (void)syscall(SYS_close, fd);
    return result;
}

/* Recover a file-backed loader identity when a libc cannot publish a usable
 * in-image program-header pointer.  In particular, musl deliberately leaves
 * dlpi_phdr NULL when the legal ELF program-header table is outside every
 * PT_LOAD.  A pathname alone is not authority: require its current stat
 * identity to occur in /proc/self/maps, require every matching mapped path
 * to name that same regular-file revision, and recheck the caller-visible
 * name after the scan. */
static int snapshot_mapped_name(
    const char *logical, struct mapped_file_identity *identity,
    char source[PATH_MAX], struct file_trace_snapshot *snapshot)
{
    char read_buffer[4096];
    char line[PATH_MAX + 256];
    struct file_trace_snapshot initial_snapshot;
    struct stat initial_status;
    size_t line_length = 0;
    int fd = -1;
    int found = 0;
    int result = 0;

    if (!logical || logical[0] != '/' || !identity || !source ||
        !snapshot || raw_fstatat(AT_FDCWD, logical, &initial_status, 0) < 0 ||
        !S_ISREG(initial_status.st_mode))
        return 0;
    identity->device = (uint64_t)initial_status.st_dev;
    identity->inode = (uint64_t)initial_status.st_ino;
    file_trace_snapshot_from_stat(&initial_snapshot, &initial_status);

    fd = raw_openat(AT_FDCWD, "/proc/self/maps",
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (fd < 0)
        return 0;
    for (;;) {
        ssize_t count;

        do {
            count = syscall(SYS_read, fd, read_buffer, sizeof(read_buffer));
        } while (count < 0 && errno == EINTR);
        if (count < 0)
            goto out;
        if (count == 0) {
            if (line_length != 0)
                goto out;
            break;
        }
        for (ssize_t index = 0; index < count; index++) {
            struct mapped_file_identity mapped_identity;
            char mapped_source[PATH_MAX];
            const char *cursor;
            uint64_t start;
            int mapped;

            if (read_buffer[index] != '\n') {
                if (line_length + 1 >= sizeof(line))
                    goto out;
                line[line_length++] = read_buffer[index];
                continue;
            }
            line[line_length] = '\0';
            line_length = 0;
            cursor = line;
            if (!parse_maps_unsigned(&cursor, 16, '-', &start) ||
                start > UINTPTR_MAX)
                goto out;
            mapped = parse_maps_line_for_address(
                line, (uintptr_t)start, &mapped_identity,
                mapped_source, sizeof(mapped_source));
            if (mapped < 0)
                goto out;
            if (mapped == 0 ||
                mapped_identity.device != identity->device ||
                mapped_identity.inode != identity->inode)
                continue;
            {
                struct stat mapped_status;

                if (raw_fstatat(AT_FDCWD, mapped_source,
                                &mapped_status, 0) < 0 ||
                    !S_ISREG(mapped_status.st_mode) ||
                    (uint64_t)mapped_status.st_dev != identity->device ||
                    (uint64_t)mapped_status.st_ino != identity->inode ||
                    !file_trace_snapshot_matches_stat(
                        &initial_snapshot, &mapped_status))
                    goto out;
            }
            if (!found) {
                size_t length;

                if (!bounded_string_length(
                        mapped_source, sizeof(mapped_source), &length))
                    goto out;
                memcpy(source, mapped_source, length + 1);
                found = 1;
            }
        }
    }
    if (found) {
        struct stat final_status;

        if (raw_fstatat(AT_FDCWD, logical, &final_status, 0) < 0 ||
            !file_trace_snapshot_matches_stat(
                &initial_snapshot, &final_status))
            goto out;
        *snapshot = initial_snapshot;
        result = 1;
    }
out:
    (void)syscall(SYS_close, fd);
    return result;
}

static void mapped_identity_set_free(struct mapped_identity_set *set)
{
    if (!set)
        return;
    if (set->items)
        release_trace_record(set->items,
                             set->capacity * sizeof(*set->items));
    set->items = NULL;
    set->count = set->capacity = 0;
}

static int mapped_identity_set_contains(
    const struct mapped_identity_set *set,
    const struct mapped_file_identity *identity)
{
    if (!set || !identity)
        return 0;
    for (size_t index = 0; index < set->count; index++) {
        if (set->items[index].device == identity->device &&
            set->items[index].inode == identity->inode)
            return 1;
    }
    return 0;
}

static int mapped_identity_set_add(
    struct mapped_identity_set *set,
    const struct mapped_file_identity *identity)
{
    struct mapped_file_identity *items;
    size_t capacity;

    if (!set || !identity)
        return 0;
    if (mapped_identity_set_contains(set, identity))
        return 1;
    if (set->count >= TRACE_MAPPED_OBJECT_LIMIT)
        return 0;
    if (set->count < set->capacity) {
        set->items[set->count++] = *identity;
        return 1;
    }
    capacity = set->capacity ? set->capacity * 2 : 64;
    if (capacity > TRACE_MAPPED_OBJECT_LIMIT)
        capacity = TRACE_MAPPED_OBJECT_LIMIT;
    items = allocate_trace_record(capacity * sizeof(*items));
    if (!items)
        return 0;
    if (set->count)
        memcpy(items, set->items, set->count * sizeof(*items));
    if (set->items)
        release_trace_record(set->items,
                             set->capacity * sizeof(*set->items));
    set->items = items;
    set->capacity = capacity;
    set->items[set->count++] = *identity;
    return 1;
}

static uintptr_t phdr_probe_address(const struct dl_phdr_info *info)
{
    if (!info || !info->dlpi_phdr)
        return 0;
    for (ElfW(Half) index = 0; index < info->dlpi_phnum; index++) {
        const ElfW(Phdr) *header = &info->dlpi_phdr[index];

        if (header->p_type == PT_DYNAMIC && header->p_memsz != 0)
            return (uintptr_t)info->dlpi_addr +
                   (uintptr_t)header->p_vaddr;
    }
    for (ElfW(Half) index = 0; index < info->dlpi_phnum; index++) {
        const ElfW(Phdr) *header = &info->dlpi_phdr[index];

        if (header->p_type == PT_LOAD && header->p_memsz != 0)
            return (uintptr_t)info->dlpi_addr +
                   (uintptr_t)header->p_vaddr;
    }
    return 0;
}

static int phdr_contains_address(const struct dl_phdr_info *info,
                                 uintptr_t address)
{
    if (!info || !info->dlpi_phdr)
        return 0;
    for (ElfW(Half) index = 0; index < info->dlpi_phnum; index++) {
        const ElfW(Phdr) *header = &info->dlpi_phdr[index];
        uintptr_t start;
        uintptr_t end;

        if (header->p_type != PT_LOAD || header->p_memsz == 0 ||
            (uintptr_t)header->p_vaddr >
                UINTPTR_MAX - (uintptr_t)info->dlpi_addr)
            continue;
        start = (uintptr_t)info->dlpi_addr + (uintptr_t)header->p_vaddr;
        if ((uintptr_t)header->p_memsz > UINTPTR_MAX - start)
            continue;
        end = start + (uintptr_t)header->p_memsz;
        if (address >= start && address < end)
            return 1;
    }
    return 0;
}

static int dlpi_identity_name(const struct dl_phdr_info *info,
                              const char *lookup_cwd,
                              char logical[PATH_MAX])
{
    if (!info)
        return 0;
    /* The base-namespace main executable has the conventional empty
     * dlpi_name.  procfs provides its race-resistant kernel-held identity;
     * snapshot_mapped_name still requires that identity in the map table. */
    if (!info->dlpi_name || !info->dlpi_name[0]) {
        memcpy(logical, "/proc/self/exe", sizeof("/proc/self/exe"));
        return 1;
    }
    return absolute_link_map_name(info->dlpi_name, lookup_cwd, logical);
}

struct capture_mapped_set_context {
    struct mapped_identity_set *set;
    const char *lookup_cwd;
    int failed;
};

static int capture_mapped_set_callback(struct dl_phdr_info *info, size_t size,
                                       void *opaque)
{
    struct capture_mapped_set_context *context = opaque;
    struct mapped_file_identity identity;
    struct file_trace_snapshot snapshot;
    char logical[PATH_MAX];
    char path[PATH_MAX];
    uintptr_t address;
    int mapped;

    (void)size;
    address = phdr_probe_address(info);
    if (address) {
        mapped = mapped_identity_for_address(
            address, &identity, path, sizeof(path));
    } else if (dlpi_identity_name(info, context->lookup_cwd, logical) &&
               snapshot_mapped_name(
                   logical, &identity, path, &snapshot)) {
        mapped = 1;
    } else {
        mapped = -1;
    }
    if (mapped < 0) {
        context->failed = 1;
        return 1;
    }
    if (mapped > 0 && !mapped_identity_set_add(context->set, &identity)) {
        context->failed = 1;
        return 1;
    }
    return 0;
}

static int capture_mapped_identity_set(struct mapped_identity_set *set,
                                       const char *lookup_cwd)
{
    struct capture_mapped_set_context context = {set, lookup_cwd, 0};

    if (!set)
        return 0;
    memset(set, 0, sizeof(*set));
    if (dl_iterate_phdr(capture_mapped_set_callback, &context) != 0 ||
        context.failed) {
        mapped_identity_set_free(set);
        return 0;
    }
    return 1;
}

static void write_trace_line(enum trace_stream_kind stream,
                             const char *prefix, const char *path)
{
    int saved_errno = errno;
    char *record;
    size_t prefix_len, path_len, record_len;

    if (atomic_load_explicit(trace_stream_descriptor(stream),
                             memory_order_acquire) < 0 ||
        !path || !path[0])
        return;

    if (prefix) {
        if (!bounded_string_length(prefix, PATH_MAX, &prefix_len))
            trace_write_failure();
    } else {
        prefix_len = 0;
    }
    if (!bounded_string_length(path, PATH_MAX, &path_len) ||
        prefix_len > SIZE_MAX - path_len - 1)
        trace_write_failure();
    record_len = prefix_len + path_len + 1;
    record = allocate_trace_record(record_len);
    if (!record)
        trace_write_failure();
    memcpy(record, prefix ? prefix : "", prefix_len);
    memcpy(record + prefix_len, path, path_len);
    record[record_len - 1] = '\n';
    trace_write_exact(stream, record, record_len);
    release_trace_record(record, record_len);

    errno = saved_errno;
}

static char hex_digit(unsigned int value)
{
    return "0123456789abcdef"[value & 0xf];
}

static int add_hex_field_length(size_t *total, size_t input_length)
{
    if (!total || input_length > (SIZE_MAX - *total) / 2)
        return 0;
    *total += input_length * 2;
    return 1;
}

static void append_u64_hex(char *record, size_t *position, uint64_t value)
{
    for (unsigned int shift = 60; ; shift -= 4) {
        record[(*position)++] = hex_digit((unsigned int)(value >> shift));
        if (shift == 0)
            break;
    }
}

static void append_u32_hex(char *record, size_t *position, uint32_t value)
{
    for (unsigned int shift = 28; ; shift -= 4) {
        record[(*position)++] = hex_digit(value >> shift);
        if (shift == 0)
            break;
    }
}

static uint64_t next_loader_attempt(void)
{
    uint64_t previous = atomic_fetch_add_explicit(
        &g_loader_attempt_sequence, 1, memory_order_relaxed);

    return previous + 1;
}

static uint64_t next_file_trace_operation_attempt(void)
{
    uint64_t previous = atomic_fetch_add_explicit(
        &g_file_operation_attempt_sequence, 1, memory_order_relaxed);

    return previous + 1;
}

static void write_loader_control_record(char kind, uint64_t attempt,
                                        uint64_t evidence_count)
{
    int saved_errno = errno;
    char record[53];
    size_t pos = 0;
    size_t length;

    if (g_dlopen_trace_fd < 0)
        return;
    if ((kind != 'A' && kind != 'B' && kind != 'K' && kind != 'Q') ||
        attempt == 0)
        trace_write_failure();
    record[pos++] = kind;
    record[pos++] = ' ';
    append_u64_hex(record, &pos,
                   (uint64_t)trace_current_pid());
    record[pos++] = ' ';
    append_u64_hex(record, &pos, attempt);
    if (kind == 'K') {
        record[pos++] = ' ';
        append_u64_hex(record, &pos, evidence_count);
    }
    record[pos++] = '\n';
    length = kind == 'K' ? sizeof(record) : 36;
    if (pos != length)
        trace_write_failure();
    trace_write_exact(TRACE_STREAM_DLOPEN, record, length);
    errno = saved_errno;
}

static void write_file_operation_control_record(char kind, pid_t pid,
                                                uint64_t attempt)
{
    int saved_errno = errno;
    char record[36];
    size_t pos = 0;

    if (atomic_load_explicit(&g_file_trace_fd, memory_order_acquire) < 0)
        return;
    if ((kind != 'B' && kind != 'K' && kind != 'V' && kind != 'W') ||
        pid <= 0 || attempt == 0)
        trace_write_failure();
    record[pos++] = kind;
    record[pos++] = ' ';
    append_u64_hex(record, &pos, (uint64_t)pid);
    record[pos++] = ' ';
    append_u64_hex(record, &pos, attempt);
    record[pos++] = '\n';
    if (pos != sizeof(record))
        trace_write_failure();
    trace_write_exact(TRACE_STREAM_FILE, record, sizeof(record));
    errno = saved_errno;
}

static void write_descriptor_operation_control_record(char kind, pid_t pid,
                                                       uint64_t attempt)
{
    int saved_errno = errno;
    char record[36];
    size_t pos = 0;

    if (kind != 'V' && kind != 'W')
        trace_write_failure();
    if (pid <= 0 || attempt == 0)
        trace_write_failure();
    record[pos++] = kind;
    record[pos++] = ' ';
    append_u64_hex(record, &pos, (uint64_t)pid);
    record[pos++] = ' ';
    append_u64_hex(record, &pos, attempt);
    record[pos++] = '\n';
    if (pos != sizeof(record))
        trace_write_failure();
    /* Descriptor mutation can affect either helper-owned fd.  Bracket it in
     * every active stream so termination, cancellation, or exec during a
     * downstream interposer cannot leave an apparently complete artifact. */
    if (atomic_load_explicit(&g_dlopen_trace_fd,
                             memory_order_acquire) >= 0)
        trace_write_exact(TRACE_STREAM_DLOPEN, record, sizeof(record));
    if (atomic_load_explicit(&g_file_trace_fd,
                             memory_order_acquire) >= 0)
        trace_write_exact(TRACE_STREAM_FILE, record, sizeof(record));
    errno = saved_errno;
}

static void begin_file_trace_transaction(
    struct file_trace_transaction *transaction, int potentially_observed)
{
    int saved_errno = errno;

    memset(transaction, 0, sizeof(*transaction));
    if (!potentially_observed ||
        atomic_load_explicit(&g_file_trace_fd, memory_order_acquire) < 0)
        goto out;
    transaction->pid = trace_current_pid();
    transaction->attempt = next_file_trace_operation_attempt();
    if (transaction->attempt == 0) {
        write_file_failure("file-operation-sequence-overflow");
        transaction->pid = 0;
        goto out;
    }
    write_file_operation_control_record('B', transaction->pid,
                                        transaction->attempt);
out:
    errno = saved_errno;
}

static int file_trace_transaction_is_current(
    const struct file_trace_transaction *transaction)
{
    return transaction && transaction->attempt != 0 &&
           transaction->pid == trace_current_pid();
}

static void finish_file_trace_transaction(
    const struct file_trace_transaction *transaction)
{
    if (file_trace_transaction_is_current(transaction))
        write_file_operation_control_record('K', transaction->pid,
                                            transaction->attempt);
}

static void write_mapped_object_record(
    char kind, uint64_t attempt, const char *logical, const char *source,
    const struct file_trace_snapshot *snapshot)
{
    char *record;
    size_t logical_length, source_length, record_length, pos = 0;

    if (g_dlopen_trace_fd < 0)
        return;
    if ((kind != 'I' && kind != 'R') || attempt == 0 || !logical ||
        !source || !snapshot || logical[0] != '/' || source[0] != '/' ||
        snapshot->type != (uint64_t)S_IFREG ||
        snapshot->mtime_nsec > 999999999 ||
        snapshot->ctime_nsec > 999999999 ||
        !bounded_string_length(logical, PATH_MAX, &logical_length) ||
        !bounded_string_length(source, PATH_MAX, &source_length) ||
        logical_length == 0 || source_length == 0)
        trace_write_failure();
    /* kind, pid, attempt, two encoded paths, eight revision fields, newline. */
    record_length = 174;
    if (!add_hex_field_length(&record_length, logical_length) ||
        !add_hex_field_length(&record_length, source_length))
        trace_write_failure();
    record = allocate_trace_record(record_length);
    if (!record)
        trace_write_failure();
    record[pos++] = kind;
    record[pos++] = ' ';
    append_u64_hex(record, &pos,
                   (uint64_t)trace_current_pid());
    record[pos++] = ' ';
    append_u64_hex(record, &pos, attempt);
    record[pos++] = ' ';
    for (size_t index = 0; index < logical_length; index++) {
        unsigned char value = (unsigned char)logical[index];

        record[pos++] = hex_digit(value >> 4);
        record[pos++] = hex_digit(value);
    }
    record[pos++] = ' ';
    for (size_t index = 0; index < source_length; index++) {
        unsigned char value = (unsigned char)source[index];

        record[pos++] = hex_digit(value >> 4);
        record[pos++] = hex_digit(value);
    }
    {
        const uint64_t fields[] = {
            snapshot->device, snapshot->inode, snapshot->type,
            snapshot->size, snapshot->mtime_sec, snapshot->mtime_nsec,
            snapshot->ctime_sec, snapshot->ctime_nsec
        };

        for (size_t index = 0; index < sizeof(fields) / sizeof(fields[0]);
             index++) {
            record[pos++] = ' ';
            append_u64_hex(record, &pos, fields[index]);
        }
    }
    record[pos++] = '\n';
    if (pos != record_length)
        trace_write_failure();
    trace_write_exact(TRACE_STREAM_DLOPEN, record, record_length);
    release_trace_record(record, record_length);
}

static int snapshot_mapped_address(
    uintptr_t address, struct mapped_file_identity *identity,
    char source[PATH_MAX], struct file_trace_snapshot *snapshot)
{
    struct stat status;
    int mapped = mapped_identity_for_address(
        address, identity, source, PATH_MAX);

    if (mapped <= 0 || raw_fstatat(AT_FDCWD, source, &status, 0) < 0 ||
        !S_ISREG(status.st_mode) ||
        (uint64_t)status.st_dev != identity->device ||
        (uint64_t)status.st_ino != identity->inode)
        return 0;
    file_trace_snapshot_from_stat(snapshot, &status);
    return 1;
}

struct initial_evidence_context {
    uint64_t attempt;
    uint64_t count;
    int failed;
};

static int initial_evidence_callback(struct dl_phdr_info *info, size_t size,
                                     void *opaque)
{
    struct initial_evidence_context *context = opaque;
    struct mapped_file_identity identity;
    struct file_trace_snapshot snapshot;
    char logical[PATH_MAX];
    char source[PATH_MAX];
    uintptr_t address = phdr_probe_address(info);
    int mapped;

    (void)size;
    /* The helper is instrumentation, not part of the target's startup
     * dependency graph.  Identify it by an in-image function address instead
     * of by pathname or SONAME. */
    if (phdr_contains_address(
            info, (uintptr_t)(void *)&write_initial_map_evidence))
        return 0;
    if (address) {
        mapped = mapped_identity_for_address(
            address, &identity, source, sizeof(source));
    } else if (dlpi_identity_name(info, NULL, logical) &&
               snapshot_mapped_name(
                   logical, &identity, source, &snapshot)) {
        mapped = 1;
    } else {
        mapped = -1;
    }
    if (mapped == 0)
        return 0;
    if (mapped < 0 ||
        (address && !snapshot_mapped_address(
                        address, &identity, source, &snapshot))) {
        context->failed = 1;
        return 1;
    }
    write_mapped_object_record(
        'I', context->attempt, source, source, &snapshot);
    context->count++;
    return 0;
}

static int write_initial_map_evidence(void)
{
    struct initial_evidence_context context;

    context.attempt = next_loader_attempt();
    context.count = 0;
    context.failed = context.attempt == 0;
    if (context.failed)
        return -1;
    write_loader_control_record('A', context.attempt, 0);
    if (dl_iterate_phdr(initial_evidence_callback, &context) != 0 ||
        context.failed)
        return -1;
    write_loader_control_record('K', context.attempt, context.count);
    return 0;
}

/* The owner record is separate from the fixed readiness line so the packer
 * can perform its cheap helper-version probe without knowing the child pid.
 * The strict parser requires this record exactly once and before any calls. */
static void write_trace_owner_record(enum trace_stream_kind stream)
{
    char record[19];
    size_t pos = 0;

    if (atomic_load_explicit(trace_stream_descriptor(stream),
                             memory_order_acquire) < 0)
        return;
    record[pos++] = 'O';
    record[pos++] = ' ';
    append_u64_hex(record, &pos,
                   (uint64_t)trace_current_pid());
    record[pos++] = '\n';
    if (pos != sizeof(record))
        trace_write_failure();
    trace_write_exact(stream, record, sizeof(record));
}

/* A failed loader call has no link_map identity to encode, but its result and
 * loader-owned dlerror state remain observable.  Record enough call identity
 * to keep the protocol canonical while conservatively selecting native
 * loader semantics.  This function uses only fixed storage and raw trace
 * writes after the failed call: in particular it must not call dlinfo() or
 * dlerror(), and it restores errno before returning.
 *
 * Wire format (excluding the newline):
 *   F <16-hex pid> <16-hex attempt> <D|M> <N|P>
 *     <16-hex namespace> <8-hex mode>
 * D is dlopen (whose canonical namespace field is zero), M is dlmopen, and
 * N/P distinguish a NULL filename from a non-NULL filename. */
static void write_failed_load_record(char api, int filename_present,
                                     uint64_t namespace_id, int mode,
                                     uint64_t attempt)
{
    int saved_errno = errno;
    char record[66];
    size_t pos = 0;

    if (!dlopen_trace_is_active())
        return;
    if ((api != 'D' && api != 'M') ||
        (api == 'D' && namespace_id != 0) || attempt == 0)
        trace_write_failure();
    record[pos++] = 'F';
    record[pos++] = ' ';
    append_u64_hex(record, &pos,
                   (uint64_t)trace_current_pid());
    record[pos++] = ' ';
    append_u64_hex(record, &pos, attempt);
    record[pos++] = ' ';
    record[pos++] = api;
    record[pos++] = ' ';
    record[pos++] = filename_present ? 'P' : 'N';
    record[pos++] = ' ';
    append_u64_hex(record, &pos, namespace_id);
    record[pos++] = ' ';
    append_u32_hex(record, &pos, (uint32_t)mode);
    record[pos++] = '\n';
    if (pos != sizeof(record))
        trace_write_failure();
    trace_write_exact(TRACE_STREAM_DLOPEN, record, sizeof(record));
    errno = saved_errno;
}

/* One encoded record is one O_APPEND write.  V8 retains the exact public mode
 * so pack-time target-family policy can distinguish a newly loading GNU
 * RTLD_LAZY request from musl's deliberately eager interpretation.  It also
 * binds the canonical source to the file revision observed after the native
 * loader returned.  Hex encoding preserves pathnames byte-for-byte and keeps
 * record boundaries explicit. */
static void write_dlopen_record(const char *request, const char *logical,
                                const char *source, uint64_t attempt,
                                uint64_t evidence_count, int mode,
                                const struct file_trace_snapshot *snapshot)
{
    int saved_errno = errno;
    char *record;
    size_t request_len, logical_len, source_len, pos = 0;
    size_t record_len;

    if (!dlopen_trace_is_active() || !request || !logical || !source ||
        !snapshot || attempt == 0)
        return;
    if (!bounded_string_length(request, PATH_MAX, &request_len) ||
        !bounded_string_length(logical, PATH_MAX, &logical_len) ||
        !bounded_string_length(source, PATH_MAX, &source_len) ||
        request_len == 0 || logical_len == 0 || logical[0] != '/' ||
        source_len == 0 || source[0] != '/' ||
        snapshot->type != (uint64_t)S_IFREG ||
        snapshot->mtime_nsec > 999999999 ||
        snapshot->ctime_nsec > 999999999) {
        write_trace_terminal_record(TRACE_STREAM_DLOPEN,
                                    "invalid-dlopen-record");
        errno = saved_errno;
        return;
    }
    /* V8 carries a loader-operation token and its exact evidence count beside
     * the process, mode, three paths, and eight revision fields. */
    record_len = 14 + 11 * 17;
    if (!add_hex_field_length(&record_len, request_len) ||
        !add_hex_field_length(&record_len, logical_len) ||
        !add_hex_field_length(&record_len, source_len))
        trace_write_failure();
    record = allocate_trace_record(record_len);
    if (!record)
        trace_write_failure();

    record[pos++] = strchr(request, '/') ? 'P' : 'S';
    record[pos++] = ' ';
    append_u64_hex(record, &pos,
                   (uint64_t)trace_current_pid());
    record[pos++] = ' ';
    append_u64_hex(record, &pos, attempt);
    record[pos++] = ' ';
    append_u64_hex(record, &pos, evidence_count);
    record[pos++] = ' ';
    append_u32_hex(record, &pos, (uint32_t)mode);
    record[pos++] = ' ';
    for (size_t i = 0; i < request_len; i++) {
        unsigned char value = (unsigned char)request[i];
        record[pos++] = hex_digit(value >> 4);
        record[pos++] = hex_digit(value);
    }
    record[pos++] = ' ';
    for (size_t i = 0; i < logical_len; i++) {
        unsigned char value = (unsigned char)logical[i];

        record[pos++] = hex_digit(value >> 4);
        record[pos++] = hex_digit(value);
    }
    record[pos++] = ' ';
    for (size_t i = 0; i < source_len; i++) {
        unsigned char value = (unsigned char)source[i];
        record[pos++] = hex_digit(value >> 4);
        record[pos++] = hex_digit(value);
    }
    {
        const uint64_t fields[] = {
            snapshot->device, snapshot->inode, snapshot->type,
            snapshot->size, snapshot->mtime_sec, snapshot->mtime_nsec,
            snapshot->ctime_sec, snapshot->ctime_nsec
        };

        for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
            record[pos++] = ' ';
            append_u64_hex(record, &pos, fields[i]);
        }
    }
    record[pos++] = '\n';
    if (pos != record_len)
        trace_write_failure();
    trace_write_exact(TRACE_STREAM_DLOPEN, record, record_len);
    release_trace_record(record, record_len);
    errno = saved_errno;
}

/* File-trace V9 keeps the runtime lookup identity distinct from the
 * canonical source copied by the packer and carries the observed filesystem
 * revision.  Every record also carries its fork-process origin.  Negative
 * records have neither a source nor a snapshot. */
static void write_file_record(char kind, const char *request,
                              const char *source,
                              const struct file_trace_snapshot *snapshot)
{
    int saved_errno = errno;
    char *record;
    size_t request_len, source_len = 0, pos = 0;
    size_t record_len;

    if (g_file_trace_fd < 0 || !request)
        return;
    if (!bounded_string_length(request, PATH_MAX, &request_len) ||
        (source &&
         !bounded_string_length(source, PATH_MAX, &source_len)) ||
        (kind != 'F' && kind != 'D' && kind != 'N') ||
        request_len == 0 || request[0] != '/' ||
        ((kind == 'N') != (source == NULL)) ||
        ((kind == 'N') != (snapshot == NULL)) ||
        (snapshot &&
         ((kind == 'F' && snapshot->type != (uint64_t)S_IFREG) ||
          (kind == 'D' && snapshot->type != (uint64_t)S_IFDIR))) ||
        (source && (source_len == 0 || source[0] != '/'))) {
        write_trace_terminal_record(TRACE_STREAM_FILE,
                                    "invalid-file-trace-record");
        errno = saved_errno;
        return;
    }
    record_len = (source ? 4 + 8 * 17 : 3) + 17;
    if (!add_hex_field_length(&record_len, request_len) ||
        (source && !add_hex_field_length(&record_len, source_len)))
        trace_write_failure();
    record = allocate_trace_record(record_len);
    if (!record)
        trace_write_failure();

    record[pos++] = kind;
    record[pos++] = ' ';
    append_u64_hex(record, &pos,
                   (uint64_t)trace_current_pid());
    record[pos++] = ' ';
    for (size_t i = 0; i < request_len; i++) {
        unsigned char value = (unsigned char)request[i];

        record[pos++] = hex_digit(value >> 4);
        record[pos++] = hex_digit(value);
    }
    if (source) {
        record[pos++] = ' ';
        for (size_t i = 0; i < source_len; i++) {
            unsigned char value = (unsigned char)source[i];

            record[pos++] = hex_digit(value >> 4);
            record[pos++] = hex_digit(value);
        }
        {
            const uint64_t fields[] = {
                snapshot->device, snapshot->inode, snapshot->type,
                snapshot->size, snapshot->mtime_sec, snapshot->mtime_nsec,
                snapshot->ctime_sec, snapshot->ctime_nsec
            };

            for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
                record[pos++] = ' ';
                append_u64_hex(record, &pos, fields[i]);
            }
        }
    }
    record[pos++] = '\n';
    if (pos != record_len)
        trace_write_failure();
    trace_write_exact(TRACE_STREAM_FILE, record, record_len);
    release_trace_record(record, record_len);
    errno = saved_errno;
}

/* A successful regular-file or directory open need not have a stable source
 * pathname.  Deleted files are the ordinary example; qemu-user also serves
 * some procfs files through deleted memfds.  Preserve the absolute request
 * and its kind so the packer can ignore the observation only when it is
 * outside every capture pattern.  A selected unresolved request remains a
 * terminally incomplete trace rather than silently copying another object. */
static void write_file_unresolved(char kind, const char *request)
{
    int saved_errno = errno;
    char *record;
    size_t request_len, pos = 0;
    size_t record_len = 5 + 17; /* "U <pid> F " + request + newline */

    if (g_file_trace_fd < 0 || !request)
        return;
    if ((kind != 'F' && kind != 'D') ||
        !bounded_string_length(request, PATH_MAX, &request_len) ||
        request_len == 0 || request[0] != '/' ||
        !add_hex_field_length(&record_len, request_len)) {
        write_trace_terminal_record(
            TRACE_STREAM_FILE, "invalid-unresolved-file-trace-record");
        errno = saved_errno;
        return;
    }
    record = allocate_trace_record(record_len);
    if (!record)
        trace_write_failure();

    record[pos++] = 'U';
    record[pos++] = ' ';
    append_u64_hex(record, &pos,
                   (uint64_t)trace_current_pid());
    record[pos++] = ' ';
    record[pos++] = kind;
    record[pos++] = ' ';
    for (size_t i = 0; i < request_len; i++) {
        unsigned char value = (unsigned char)request[i];

        record[pos++] = hex_digit(value >> 4);
        record[pos++] = hex_digit(value);
    }
    record[pos++] = '\n';
    if (pos != record_len)
        trace_write_failure();
    trace_write_exact(TRACE_STREAM_FILE, record, record_len);
    release_trace_record(record, record_len);
    errno = saved_errno;
}

static void write_file_failure(const char *reason)
{
    if (g_file_trace_fd >= 0)
        write_trace_terminal_record(TRACE_STREAM_FILE, reason);
}

static void write_trace_terminal_record(enum trace_stream_kind stream,
                                        const char *reason)
{
    int saved_errno = errno;
    char record[256];
    size_t reason_len;
    size_t pos = 0;

    if (atomic_load_explicit(trace_stream_descriptor(stream),
                             memory_order_acquire) < 0)
        return;
    if (!bounded_string_length(reason, sizeof(record) - 21, &reason_len) ||
        reason_len == 0)
        trace_write_failure();
    record[pos++] = '!';
    record[pos++] = ' ';
    append_u64_hex(record, &pos,
                   (uint64_t)trace_current_pid());
    record[pos++] = ' ';
    memcpy(record + pos, reason, reason_len);
    pos += reason_len;
    record[pos++] = '\n';
    trace_write_exact(stream, record, pos);
    errno = saved_errno;
}

/* An owner process can replace itself without loading this helper in the new
 * image (a scrubbed environment or a static executable are common cases).
 * Mark each exported-libc exec attempt before entering libc and cancel it only
 * if the call returns.  A successful owner exec consequently leaves an
 * unmatched record which the collector rejects.  Fork and vfork children
 * compare their kernel pid before touching any shared/TLS tracing state. */
static void write_exec_attempt_record(enum trace_stream_kind stream,
                                      char kind, uint64_t attempt)
{
    int saved_errno = errno;
    char record[36];
    size_t pos = 0;

    if (atomic_load_explicit(trace_stream_descriptor(stream),
                             memory_order_acquire) < 0)
        return;
    if ((kind != 'E' && kind != 'C') || attempt == 0)
        trace_write_failure();
    record[pos++] = kind;
    record[pos++] = ' ';
    append_u64_hex(record, &pos, (uint64_t)g_trace_owner_pid);
    record[pos++] = ' ';
    append_u64_hex(record, &pos, attempt);
    record[pos++] = '\n';
    if (pos != sizeof(record))
        trace_write_failure();
    trace_write_exact(stream, record, sizeof(record));
    errno = saved_errno;
}

static uint64_t begin_owner_exec_attempt(void)
{
    pid_t pid = trace_current_pid();
    pid_t expected_pid = expected_trace_owner_pid();
    uint64_t previous;
    uint64_t attempt;

    /* This check deliberately precedes initialization and all atomics.  A
     * vfork child shares its parent's address space until exec/_exit and must
     * not mutate the parent's trace state. */
    if ((g_trace_owner_pid != 0 && pid != g_trace_owner_pid) ||
        (g_trace_owner_pid == 0 && expected_pid != 0 &&
         pid != expected_pid))
        return 0;
    ensure_trace_initialized();
    if (pid != g_trace_owner_pid || g_exec_depth != 0 ||
        (g_dlopen_trace_fd < 0 && g_file_trace_fd < 0))
        return 0;
    previous = atomic_fetch_add_explicit(&g_exec_attempt_sequence, 1,
                                         memory_order_relaxed);
    attempt = previous + 1;
    if (attempt == 0) {
        write_trace_terminal_record(TRACE_STREAM_DLOPEN,
                                    "exec-attempt-sequence-overflow");
        write_trace_terminal_record(TRACE_STREAM_FILE,
                                    "exec-attempt-sequence-overflow");
        return 0;
    }
    write_exec_attempt_record(TRACE_STREAM_DLOPEN, 'E', attempt);
    write_exec_attempt_record(TRACE_STREAM_FILE, 'E', attempt);
    return attempt;
}

static void cancel_owner_exec_attempt(uint64_t attempt)
{
    if (attempt == 0)
        return;
    write_exec_attempt_record(TRACE_STREAM_DLOPEN, 'C', attempt);
    write_exec_attempt_record(TRACE_STREAM_FILE, 'C', attempt);
}

/* A successful non-NULL dlopen must yield either a complete V8 record or a
 * record that makes the packer fail closed.  In particular, alternate libcs
 * are not required to provide a usable RTLD_DI_LINKMAP result. */
static void write_dlopen_failure(const char *reason)
{
    if (dlopen_trace_is_active())
        write_trace_terminal_record(TRACE_STREAM_DLOPEN, reason);
    else if (g_dlopen_trace_fd < 0 && g_file_trace_fd >= 0)
        write_trace_terminal_record(TRACE_STREAM_FILE, reason);
}

static void fail_if_tracing_cannot_forward(void)
{
    if (dlopen_trace_is_active() || g_file_trace_fd >= 0)
        trace_write_failure();
}

static int capture_lookup_cwd(char cwd[PATH_MAX], uint64_t *epoch,
                              struct trace_fd_identity *identity)
{
    return capture_stable_cwd(cwd, epoch, identity);
}

static int lookup_cwd_is_unchanged(
    const char cwd[PATH_MAX], uint64_t epoch,
    const struct trace_fd_identity *identity)
{
    struct stat current_status;
    struct stat path_status;
    uint64_t current_epoch;
    int saved_errno = errno;
    int unchanged = 0;

    if (!cwd || !identity)
        goto out;
    current_epoch = atomic_load_explicit(&g_cwd_epoch,
                                         memory_order_acquire);
    if (current_epoch != epoch ||
        atomic_load_explicit(&g_cwd_active_writers,
                             memory_order_acquire) != 0)
        goto out;
    if (raw_fstatat(AT_FDCWD, ".", &current_status, 0) < 0 ||
        raw_fstatat(AT_FDCWD, cwd, &path_status, 0) < 0)
        goto out;
    if (current_status.st_dev != identity->device ||
        current_status.st_ino != identity->inode ||
        current_status.st_rdev != identity->rdevice ||
        (current_status.st_mode & S_IFMT) != identity->type ||
        !stat_identity_matches(&current_status, &path_status))
        goto out;
    unchanged = 1;
out:
    errno = saved_errno;
    return unchanged;
}

static int absolute_link_map_name(const char *name, const char *lookup_cwd,
                                  char logical[PATH_MAX])
{
    int length;

    if (!name || !name[0])
        return 0;
    if (name[0] == '/')
        length = snprintf(logical, PATH_MAX, "%s", name);
    else if (lookup_cwd && lookup_cwd[0] == '/')
        length = snprintf(logical, PATH_MAX, "%s/%s", lookup_cwd, name);
    else
        return 0;
    return length >= 0 && length < PATH_MAX;
}

struct new_base_evidence_context {
    const char *lookup_cwd;
    const struct mapped_identity_set *before;
    const struct mapped_file_identity *root_identity;
    uint64_t attempt;
    uint64_t *evidence_count;
    int failed;
};

static int write_new_base_evidence_callback(
    struct dl_phdr_info *info, size_t size, void *opaque)
{
    struct new_base_evidence_context *context = opaque;
    struct mapped_file_identity identity;
    struct file_trace_snapshot snapshot;
    char logical[PATH_MAX];
    char source[PATH_MAX];
    uintptr_t address = phdr_probe_address(info);
    int snapshotted = 0;
    int mapped;

    (void)size;
    if (address) {
        mapped = mapped_identity_for_address(
            address, &identity, source, sizeof(source));
    } else if (dlpi_identity_name(
                   info, context->lookup_cwd, logical) &&
               snapshot_mapped_name(
                   logical, &identity, source, &snapshot)) {
        mapped = 1;
        snapshotted = 1;
    } else {
        mapped = -1;
    }
    if (mapped == 0)
        return 0;
    if (mapped < 0) {
        context->failed = 1;
        return 1;
    }
    if ((identity.device == context->root_identity->device &&
         identity.inode == context->root_identity->inode) ||
        mapped_identity_set_contains(context->before, &identity))
        return 0;
    if (!snapshotted && !snapshot_mapped_address(
                            address, &identity, source, &snapshot)) {
        context->failed = 1;
        return 1;
    }
    if (!dlpi_identity_name(info, context->lookup_cwd, logical))
        memcpy(logical, source, strlen(source) + 1);
    write_mapped_object_record(
        'R', context->attempt, logical, source, &snapshot);
    (*context->evidence_count)++;
    return 0;
}

/* dl_iterate_phdr holds the loader's map state stable for each callback on
 * supported base namespaces.  Prefer it to chasing unrelated l_next links
 * after the loader has unlocked, where a concurrent dlclose could otherwise
 * invalidate a link_map. */
static int write_new_base_namespace_evidence(
    const char *lookup_cwd, const struct mapped_identity_set *before,
    const struct mapped_file_identity *root_identity, uint64_t attempt,
    uint64_t *evidence_count)
{
    struct new_base_evidence_context context = {
        lookup_cwd, before, root_identity, attempt, evidence_count, 0
    };

    if (!before || !root_identity || !evidence_count)
        return 0;
    return dl_iterate_phdr(write_new_base_evidence_callback, &context) == 0 &&
           !context.failed;
}

static void trace_successful_dlopen(
    void *handle, const char *filename, const char *lookup_cwd, int mode,
    const struct mapped_identity_set *before, int baseline_valid,
    uint64_t attempt)
{
    struct link_map *lm = NULL;
    struct mapped_file_identity mapped_identity;
    struct file_trace_snapshot snapshot;
    char logical[PATH_MAX];
    char source[PATH_MAX];
    uint64_t evidence_count = 0;
    int saved_errno = errno;

    if (!handle || !filename ||
        (!dlopen_trace_is_active() && g_file_trace_fd < 0))
        return;
    g_trace_depth++;
    if (dlinfo(handle, RTLD_DI_LINKMAP, &lm) != 0 || !lm || !lm->l_name ||
        !lm->l_name[0]) {
        write_dlopen_failure("successful-dlopen-has-no-link-map");
        goto out;
    }
    if (!absolute_link_map_name(lm->l_name, lookup_cwd, logical)) {
        write_dlopen_failure("successful-dlopen-path-is-too-long");
        goto out;
    }
    if (!baseline_valid || !before) {
        write_dlopen_failure("pre-dlopen-mapped-object-baseline-is-unavailable");
        if (g_file_trace_fd >= 0)
            write_file_failure(
                "pre-dlopen-mapped-object-baseline-is-unavailable");
        goto out;
    }
    if (!snapshot_mapped_address(
            (uintptr_t)lm->l_ld, &mapped_identity, source, &snapshot)) {
        write_dlopen_failure("successful-dlopen-map-does-not-match-source");
        if (g_file_trace_fd >= 0)
            write_file_failure(
                "successful-dlopen-map-does-not-match-source");
        goto out;
    }
    if (dlopen_trace_is_active()) {
        if (attempt == 0) {
            write_dlopen_failure("loader-operation-has-no-begin-record");
            goto out;
        }
        if (!write_new_base_namespace_evidence(
                lookup_cwd, before, &mapped_identity, attempt,
                &evidence_count)) {
            write_dlopen_failure(
                "loaded-dependency-map-does-not-match-source");
            if (g_file_trace_fd >= 0)
                write_file_failure(
                    "loaded-dependency-map-does-not-match-source");
            goto out;
        }
        write_dlopen_record(filename, logical, source, attempt,
                            evidence_count, mode, &snapshot);
    }
    /* Some libcs open dlopen() targets internally and bypass the interposed
     * open() family, so the successful link-map path is authoritative. */
    if (g_file_trace_fd >= 0)
        write_file_record('F', logical, source, &snapshot);
out:
    g_trace_depth--;
    errno = saved_errno;
}

static void trace_path_kind(
    int dirfd, const char *path, int is_dir,
    const struct file_trace_snapshot *snapshot,
    const struct cwd_observation *observation)
{
    char request[PATH_MAX];
    char source[PATH_MAX];
    int saved_errno = errno;

    if (g_trace_depth || g_file_trace_fd < 0 || !snapshot)
        return;
    g_trace_depth++;

    if (!build_path(dirfd, path, observation, request, sizeof(request))) {
        write_file_failure("successful-file-request-cannot-be-made-absolute");
        goto out;
    }
    memcpy(source, request, strlen(request) + 1);
    if (!canonicalize_path(source, sizeof(source)) || source[0] != '/') {
        write_file_unresolved(is_dir ? 'D' : 'F', request);
        goto out;
    }
    if (!path_snapshot_matches(source, snapshot)) {
        write_file_unresolved(is_dir ? 'D' : 'F', request);
        goto out;
    }

    write_file_record(is_dir ? 'D' : 'F', request, source, snapshot);
out:
    g_trace_depth--;
    errno = saved_errno;
}

/* For a successful open, derive the copied source through the still-open file
 * descriptor instead of resolving the caller's pathname a second time.  This
 * binds the trace to the object the kernel actually opened if another thread
 * renames a directory or switches a symlink immediately after open(2). */
static void trace_fd_path_kind(int fd, int dirfd, const char *path, int is_dir,
                               const struct file_trace_snapshot *snapshot,
                               const struct cwd_observation *observation)
{
    char request[PATH_MAX];
    char source[PATH_MAX];
    int saved_errno = errno;
    int length;

    if (g_trace_depth || g_file_trace_fd < 0 || !snapshot)
        return;
    g_trace_depth++;

    if (!build_path(dirfd, path, observation, request, sizeof(request))) {
        write_file_failure("successful-file-request-cannot-be-made-absolute");
        goto out;
    }
    length = snprintf(source, sizeof(source), "/proc/self/fd/%d", fd);
    if (length < 0 || (size_t)length >= sizeof(source) ||
        !canonicalize_path(source, sizeof(source)) || source[0] != '/' ||
        !path_snapshot_matches(source, snapshot)) {
        /* procfs may be unavailable or may expose a non-path-backed object.
         * Re-resolving the request is safe only when it still names the exact
         * object held by the descriptor; otherwise retain an explicitly
         * unresolved observation for capture-pattern-aware handling. */
        memcpy(source, request, strlen(request) + 1);
        if (!canonicalize_path(source, sizeof(source)) || source[0] != '/' ||
            !path_snapshot_matches(source, snapshot)) {
            write_file_unresolved(is_dir ? 'D' : 'F', request);
            goto out;
        }
    }
    if (!fd_snapshot_matches(fd, snapshot)) {
        write_file_unresolved(is_dir ? 'D' : 'F', request);
        goto out;
    }

    write_file_record(is_dir ? 'D' : 'F', request, source, snapshot);
out:
    g_trace_depth--;
    errno = saved_errno;
}

/* Record a failed file-open (path not found) so the packer can embed a
 * negative VFS entry.  We deliberately do NOT call canonicalize_path here
 * because realpath(3) fails for non-existent paths. */
static void trace_failed_path(int dirfd, const char *path,
                              const struct cwd_observation *observation)
{
    char resolved[PATH_MAX];
    int saved_errno = errno;

    if (g_trace_depth || g_file_trace_fd < 0)
        return;
    g_trace_depth++;

    if (!build_path(dirfd, path, observation, resolved, sizeof(resolved))) {
        write_file_failure("missing-file-request-cannot-be-made-absolute");
        goto out;
    }

    /* Only record absolute paths; relative-without-dirfd would need cwd
     * normalisation which is error-prone for non-existent entries. */
    if (resolved[0] != '/')
        goto out;

    write_file_record('N', resolved, NULL, NULL);
out:
    g_trace_depth--;
    errno = saved_errno;
}

static void trace_missing_path(int dirfd, const char *path, int error,
                               const struct cwd_observation *observation)
{
    if (error == ENOENT || error == ENOTDIR)
        trace_failed_path(dirfd, path, observation);
}

static void trace_fd_result(int fd, int dirfd, const char *path,
                            const struct cwd_observation *observation)
{
    struct file_trace_snapshot snapshot;
    struct stat st;
    int saved_errno = errno;

    if (fd < 0 || g_trace_depth || g_file_trace_fd < 0 || !path || !path[0])
        goto out;

    if (raw_fstat(fd, &st) != 0) {
        write_file_failure("successful-open-cannot-be-classified");
        goto out;
    }
    if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
        goto out;

    file_trace_snapshot_from_stat(&snapshot, &st);
    trace_fd_path_kind(fd, dirfd, path, S_ISDIR(st.st_mode), &snapshot,
                       observation);
out:
    errno = saved_errno;
}

static void trace_stat_result(int rc, int dirfd, const char *path,
                              const struct stat *st,
                              const struct cwd_observation *observation)
{
    struct file_trace_snapshot snapshot;
    int saved_errno = errno;

    if (rc == 0 && st && (S_ISREG(st->st_mode) || S_ISDIR(st->st_mode))) {
        file_trace_snapshot_from_stat(&snapshot, st);
        trace_path_kind(dirfd, path, S_ISDIR(st->st_mode), &snapshot,
                        observation);
    } else if (rc < 0 && (saved_errno == ENOENT || saved_errno == ENOTDIR)) {
        trace_failed_path(dirfd, path, observation);
    }

    errno = saved_errno;
}

#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
static void trace_stat64_result(int rc, int dirfd, const char *path,
                                const struct stat64 *st,
                                const struct cwd_observation *observation)
{
    struct file_trace_snapshot snapshot;
    int saved_errno = errno;

    if (rc == 0 && st && (S_ISREG(st->st_mode) || S_ISDIR(st->st_mode))) {
        file_trace_snapshot_from_stat64(&snapshot, st);
        trace_path_kind(dirfd, path, S_ISDIR(st->st_mode), &snapshot,
                        observation);
    } else if (rc < 0 && (saved_errno == ENOENT || saved_errno == ENOTDIR)) {
        trace_failed_path(dirfd, path, observation);
    }

    errno = saved_errno;
}
#endif

static void trace_access_result(
    int rc, int dirfd, const char *path, int flags,
    const struct cwd_observation *observation)
{
    struct file_trace_snapshot snapshot;
    int saved_errno = errno;

    if (g_trace_depth || g_file_trace_fd < 0)
        goto out;

    if (rc == 0) {
        struct stat st;
        int stat_rc;

        g_trace_depth++;
        /* AT_EACCESS changes access-check credentials but is not a valid
         * fstatat(2) flag.  Preserve only pathname-resolution flags. */
        flags &= AT_SYMLINK_NOFOLLOW
#ifdef AT_EMPTY_PATH
              | AT_EMPTY_PATH
#endif
#ifdef AT_NO_AUTOMOUNT
              | AT_NO_AUTOMOUNT
#endif
              ;
        /* This is our metadata observation, not an application fstatat
         * call. Older libcs expose only versioned stat aliases; use the
         * same raw classifier as successful-open tracing. */
        stat_rc = raw_fstatat(dirfd, path, &st, flags);
        g_trace_depth--;
        if (stat_rc < 0) {
            write_file_failure("successful-access-cannot-be-classified");
        } else if (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode)) {
            file_trace_snapshot_from_stat(&snapshot, &st);
            trace_path_kind(dirfd, path, S_ISDIR(st.st_mode), &snapshot,
                            observation);
        }
    } else if (rc < 0 && (saved_errno == ENOENT || saved_errno == ENOTDIR)) {
        trace_failed_path(dirfd, path, observation);
    }

out:
    errno = saved_errno;
}

__attribute__((constructor))
static void dlfreeze_trace_init(void)
{
    ensure_trace_initialized();
    resolve_symbols();
}

void *dlopen(const char *filename, int flags)
{
    void *h;
    struct mapped_identity_set before = {0};
    struct file_trace_transaction file_transaction;
    char lookup_cwd[PATH_MAX] = "";
    struct trace_fd_identity lookup_cwd_identity = {0};
    uint64_t lookup_cwd_epoch = 0;
    char request[PATH_MAX];
    const char *trace_request = filename;
    size_t request_len = 0;
    int request_is_bounded = !filename;
    int unsupported_request = 0;
    int baseline_valid = 0;
    int lookup_cwd_valid = 1;
    int observing = 0;
    pid_t observation_pid = 0;
    uint64_t attempt = 0;
    int result_errno;

    ensure_trace_initialized();
    resolve_symbols();
    if (!real_dlopen) {
        if (dlopen_trace_is_active() || g_file_trace_fd >= 0)
            trace_write_failure();
        errno = ENOSYS;
        return NULL;
    }
    observing = dlopen_trace_is_active() || g_file_trace_fd >= 0;
    if (observing) {
        if (loader_observation_lock())
            observation_pid = trace_current_pid();
        else
            observing = 0;
    }
    if (filename &&
        observing) {
        request_is_bounded = bounded_string_length(
            filename, sizeof(request), &request_len);
        if (request_is_bounded) {
            memcpy(request, filename, request_len + 1);
            trace_request = request;
            unsupported_request = strchr(request, '$') != NULL;
        }
    }
    /* Calling the real loader through this interposer can change which ELF
     * object's $ORIGIN is used.  Record the unsupported request before that
     * call so even a native-success/trace-failure mismatch fails closed. */
    if (unsupported_request && observing)
        write_dlopen_failure(
            "dynamic-string-token-in-dlopen-request-is-unsupported");

    if (filename && observing) {
        lookup_cwd_valid = capture_lookup_cwd(
            lookup_cwd, &lookup_cwd_epoch, &lookup_cwd_identity);
        if (!lookup_cwd_valid)
            write_dlopen_failure("pre-dlopen-cwd-is-unstable");
    }
    if (filename && request_is_bounded && !unsupported_request &&
        dlfrz_dlopen_mode_is_supported(flags) &&
        observing) {
        int saved_errno = errno;

        g_trace_depth++;
        baseline_valid = capture_mapped_identity_set(&before, lookup_cwd);
        g_trace_depth--;
        errno = saved_errno;
    }
    /* Begin the operation before entering the native loader.  Constructors
     * can terminate the process, and another thread can do so concurrently;
     * in either case an unmatched B makes the otherwise complete-looking
     * trace prefix unconditionally invalid. */
    if (dlopen_trace_is_active()) {
        attempt = next_loader_attempt();
        if (attempt == 0)
            write_dlopen_failure("loader-operation-sequence-overflow");
        else
            write_loader_control_record('B', attempt, 0);
    }
    begin_file_trace_transaction(&file_transaction, observing);
    h = real_dlopen(filename, flags);
    result_errno = errno;

    /* A constructor can fork and let the child return through the inherited
     * outer loader call.  Its begin record belongs to the parent generation;
     * do not let the child manufacture evidence or a commit for that record.
     * The surviving lock frame is still ours and must be retired normally. */
    if (observing && trace_current_pid() != observation_pid) {
        mapped_identity_set_free(&before);
        loader_observation_unlock();
        errno = result_errno;
        return h;
    }

    if (filename && observing &&
        (!lookup_cwd_valid ||
         !lookup_cwd_is_unchanged(lookup_cwd, lookup_cwd_epoch,
                                  &lookup_cwd_identity))) {
        write_dlopen_failure("cwd-changed-during-dlopen");
        if (g_file_trace_fd >= 0)
            write_file_failure("cwd-changed-during-dlopen");
    } else if (h && !request_is_bounded)
        write_dlopen_failure("successful-dlopen-request-is-too-long");
    else if (h && !dlfrz_dlopen_mode_is_supported(flags))
        write_dlopen_failure("successful-dlopen-used-unsupported-mode-flags");
    else if (h && filename == NULL)
        write_loader_control_record('Q', attempt, 0);
    else if (!h && !unsupported_request)
        write_failed_load_record('D', filename != NULL, 0, flags, attempt);
    else if (!unsupported_request)
        trace_successful_dlopen(h, trace_request, lookup_cwd, flags,
                                &before, baseline_valid, attempt);

    finish_file_trace_transaction(&file_transaction);
    mapped_identity_set_free(&before);
    if (observing)
        loader_observation_unlock();
    errno = result_errno;
    return h;
}

#if DLFREEZE_HAVE_DLMOPEN
void *dlmopen(Lmid_t namespace_id, const char *filename, int flags)
{
    void *handle;
    struct mapped_identity_set before = {0};
    struct file_trace_transaction file_transaction;
    char lookup_cwd[PATH_MAX] = "";
    struct trace_fd_identity lookup_cwd_identity = {0};
    uint64_t lookup_cwd_epoch = 0;
    char request[PATH_MAX];
    const char *trace_request = filename;
    size_t request_len = 0;
    int request_is_bounded = !filename;
    int unsupported_request = 0;
    int baseline_valid = 0;
    int lookup_cwd_valid = 1;
    int observing = 0;
    pid_t observation_pid = 0;
    uint64_t attempt = 0;
    int result_errno;

    ensure_trace_initialized();
    resolve_symbols();
    if (!real_dlmopen) {
        if (dlopen_trace_is_active() || g_file_trace_fd >= 0)
            trace_write_failure();
        errno = ENOSYS;
        return NULL;
    }
    observing = dlopen_trace_is_active() || g_file_trace_fd >= 0;
    if (observing) {
        if (loader_observation_lock())
            observation_pid = trace_current_pid();
        else
            observing = 0;
    }
    if (filename &&
        observing) {
        request_is_bounded = bounded_string_length(
            filename, sizeof(request), &request_len);
        if (request_is_bounded) {
            memcpy(request, filename, request_len + 1);
            trace_request = request;
            unsupported_request = strchr(request, '$') != NULL;
        }
    }
    if (unsupported_request && observing)
        write_dlopen_failure(
            "dynamic-string-token-in-dlopen-request-is-unsupported");

    if (filename && observing) {
        lookup_cwd_valid = capture_lookup_cwd(
            lookup_cwd, &lookup_cwd_epoch, &lookup_cwd_identity);
        if (!lookup_cwd_valid)
            write_dlopen_failure("pre-dlmopen-cwd-is-unstable");
    }
    if (filename && request_is_bounded && !unsupported_request &&
        dlfrz_dlopen_mode_is_supported(flags) &&
        observing) {
        int saved_errno = errno;

        g_trace_depth++;
        baseline_valid = capture_mapped_identity_set(&before, lookup_cwd);
        g_trace_depth--;
        errno = saved_errno;
    }
    if (dlopen_trace_is_active()) {
        attempt = next_loader_attempt();
        if (attempt == 0)
            write_dlopen_failure("loader-operation-sequence-overflow");
        else
            write_loader_control_record('B', attempt, 0);
    }
    begin_file_trace_transaction(&file_transaction, observing);
    handle = real_dlmopen(namespace_id, filename, flags);
    result_errno = errno;
    if (observing && trace_current_pid() != observation_pid) {
        mapped_identity_set_free(&before);
        loader_observation_unlock();
        errno = result_errno;
        return handle;
    }
    if (filename && observing &&
        (!lookup_cwd_valid ||
         !lookup_cwd_is_unchanged(lookup_cwd, lookup_cwd_epoch,
                                  &lookup_cwd_identity))) {
        write_dlopen_failure("cwd-changed-during-dlmopen");
        if (g_file_trace_fd >= 0)
            write_file_failure("cwd-changed-during-dlmopen");
        finish_file_trace_transaction(&file_transaction);
        mapped_identity_set_free(&before);
        if (observing)
            loader_observation_unlock();
        errno = result_errno;
        return handle;
    }
    if (!handle) {
        if (!unsupported_request)
            write_failed_load_record('M', filename != NULL,
                                     (uint64_t)namespace_id, flags, attempt);
        finish_file_trace_transaction(&file_transaction);
        mapped_identity_set_free(&before);
        if (observing)
            loader_observation_unlock();
        errno = result_errno;
        return NULL;
    }

    if (!request_is_bounded) {
        write_dlopen_failure("successful-dlopen-request-is-too-long");
        finish_file_trace_transaction(&file_transaction);
        mapped_identity_set_free(&before);
        if (observing)
            loader_observation_unlock();
        errno = result_errno;
        return handle;
    }

    if (!dlfrz_dlopen_mode_is_supported(flags)) {
        write_dlopen_failure("successful-dlopen-used-unsupported-mode-flags");
        finish_file_trace_transaction(&file_transaction);
        mapped_identity_set_free(&before);
        if (observing)
            loader_observation_unlock();
        errno = result_errno;
        return handle;
    }

    if (namespace_id != LM_ID_BASE) {
        /* Non-base namespaces are terminally unsupported.  Do not chase raw
         * link_map links after the loader unlocks: an artifact cannot be
         * admitted from this trace, and unrelated concurrent dlclose calls
         * could invalidate that traversal. */
        if (dlopen_trace_is_active() || g_file_trace_fd >= 0)
            write_dlopen_failure(
                "successful-dlmopen-used-non-base-namespace");
        finish_file_trace_transaction(&file_transaction);
        mapped_identity_set_free(&before);
        if (observing)
            loader_observation_unlock();
        errno = result_errno;
        return handle;
    }

    if (filename == NULL) {
        write_loader_control_record('Q', attempt, 0);
        finish_file_trace_transaction(&file_transaction);
        mapped_identity_set_free(&before);
        if (observing)
            loader_observation_unlock();
        errno = result_errno;
        return handle;
    }

    if (!unsupported_request)
        trace_successful_dlopen(handle, trace_request, lookup_cwd, flags,
                                &before, baseline_valid, attempt);
    finish_file_trace_transaction(&file_transaction);
    mapped_identity_set_free(&before);
    if (observing)
        loader_observation_unlock();
    errno = result_errno;
    return handle;
}
#endif

static int exec_caller_may_touch_trace(void)
{
    pid_t pid = trace_current_pid();
    pid_t expected_pid = expected_trace_owner_pid();

    if (g_trace_owner_pid != 0)
        return pid == g_trace_owner_pid;
    /* A pre-exec vfork child shares the parent's globals and TLS.  The
     * immutable owner PID is therefore the only safe pre-initialization gate:
     * do not resolve symbols or publish an exclusion bit from that child.
     * A fresh fork+exec image with a stale owner expectation is excluded later
     * by resolve_symbols(), in its own address space. */
    return expected_pid == 0 || pid == expected_pid;
}

static int exec_name_has_slash(const char *file)
{
    if (!file)
        return 0;
    while (*file) {
        if (*file++ == '/')
            return 1;
    }
    return 0;
}

static int finish_exec_failure(uint64_t attempt, int result,
                               int result_errno)
{
    if (attempt != 0) {
        g_exec_depth--;
        cancel_owner_exec_attempt(attempt);
    }
    errno = result_errno;
    return result;
}

int execve(const char *path, char *const argv[], char *const envp[])
{
    int (*forward)(const char *, char *const[], char *const[]);
    uint64_t attempt = 0;
    int result;
    int result_errno;

    if (exec_caller_may_touch_trace())
        resolve_symbols();
    forward = atomic_load_explicit(&real_execve, memory_order_acquire);
    attempt = begin_owner_exec_attempt();
    if (attempt != 0)
        g_exec_depth++;
    result = forward ? forward(path, argv, envp)
                     : (int)syscall(SYS_execve, path, argv, envp);
    result_errno = errno;
    return finish_exec_failure(attempt, result, result_errno);
}

#if defined(SYS_execveat)
int execveat(int dirfd, const char *path, char *const argv[],
             char *const envp[], int flags)
{
    int (*forward)(int, const char *, char *const[], char *const[], int);
    uint64_t attempt = 0;
    int result;
    int result_errno;

    if (exec_caller_may_touch_trace())
        resolve_symbols();
    forward = atomic_load_explicit(&real_execveat, memory_order_acquire);
    attempt = begin_owner_exec_attempt();
    if (attempt != 0)
        g_exec_depth++;
    result = forward ? forward(dirfd, path, argv, envp, flags)
                     : (int)syscall(SYS_execveat, dirfd, path, argv, envp,
                                    flags);
    result_errno = errno;
    return finish_exec_failure(attempt, result, result_errno);
}
#endif

int fexecve(int fd, char *const argv[], char *const envp[])
{
    int (*forward)(int, char *const[], char *const[]);
    uint64_t attempt = 0;
    int result;
    int result_errno;

    if (exec_caller_may_touch_trace())
        resolve_symbols();
    forward = atomic_load_explicit(&real_fexecve, memory_order_acquire);
    attempt = begin_owner_exec_attempt();
    if (attempt != 0)
        g_exec_depth++;
    if (forward)
        result = forward(fd, argv, envp);
#if defined(SYS_execveat) && defined(AT_EMPTY_PATH)
    else
        result = (int)syscall(SYS_execveat, fd, "", argv, envp,
                              AT_EMPTY_PATH);
#else
    else {
        errno = ENOSYS;
        result = -1;
    }
#endif
    result_errno = errno;
    return finish_exec_failure(attempt, result, result_errno);
}

int execv(const char *path, char *const argv[])
{
    extern char **environ;

    return execve(path, argv, environ);
}

int execvp(const char *file, char *const argv[])
{
    extern char **environ;
    int (*forward)(const char *, char *const[]);
    uint64_t attempt = 0;
    int result;
    int result_errno;

    if (exec_caller_may_touch_trace())
        resolve_symbols();
    forward = atomic_load_explicit(&real_execvp, memory_order_acquire);
    attempt = begin_owner_exec_attempt();
    if (attempt != 0)
        g_exec_depth++;
    if (forward)
        result = forward(file, argv);
    else if (exec_name_has_slash(file))
        /* This is the only fully transparent pre-init vfork fallback that
         * needs neither libc state nor writable helper state.  PATH search
         * requires libc-specific default-path and ENOEXEC semantics, so a
         * pre-init non-owner request without a published forwarder fails
         * explicitly instead of guessing them. */
        result = (int)syscall(SYS_execve, file, argv, environ);
    else {
        errno = ENOSYS;
        result = -1;
    }
    result_errno = errno;
    return finish_exec_failure(attempt, result, result_errno);
}

int execvpe(const char *file, char *const argv[], char *const envp[])
{
    int (*forward)(const char *, char *const[], char *const[]);
    uint64_t attempt = 0;
    int result;
    int result_errno;

    if (exec_caller_may_touch_trace())
        resolve_symbols();
    forward = atomic_load_explicit(&real_execvpe, memory_order_acquire);
    attempt = begin_owner_exec_attempt();
    if (attempt != 0)
        g_exec_depth++;
    if (forward)
        result = forward(file, argv, envp);
    else if (exec_name_has_slash(file))
        result = (int)syscall(SYS_execve, file, argv, envp);
    else {
        errno = ENOSYS;
        result = -1;
    }
    result_errno = errno;
    return finish_exec_failure(attempt, result, result_errno);
}

/* Build the argv vector for the execl family without depending on malloc,
 * which may itself be in an interposed initialization path. */
static char **build_execl_argv(const char *arg, va_list arguments,
                              size_t *mapping_size, char *const **envp_out,
                              int has_envp)
{
    va_list count_args;
    va_list fill_args;
    size_t count = arg ? 1 : 0;
    size_t bytes;
    char **argv;
    const char *next = arg;

    if (!mapping_size || (has_envp && !envp_out)) {
        errno = EINVAL;
        return NULL;
    }
    va_copy(count_args, arguments);
    while (next) {
        if (count >= 1048576U) {
            va_end(count_args);
            errno = E2BIG;
            return NULL;
        }
        next = va_arg(count_args, const char *);
        if (next)
            count++;
    }
    va_end(count_args);
    if (count > (SIZE_MAX / sizeof(*argv)) - 1) {
        errno = EOVERFLOW;
        return NULL;
    }
    bytes = (count + 1) * sizeof(*argv);
    argv = allocate_trace_record(bytes);
    if (!argv) {
        errno = ENOMEM;
        return NULL;
    }
    va_copy(fill_args, arguments);
    if (arg)
        argv[0] = (char *)arg;
    for (size_t index = arg ? 1 : 0; index < count; index++)
        argv[index] = va_arg(fill_args, char *);
    /* Consume the terminating NULL.  If arg itself was NULL it occupied the
     * named parameter and there is no additional variadic terminator. */
    if (arg)
        (void)va_arg(fill_args, char *);
    argv[count] = NULL;
    if (has_envp)
        *envp_out = va_arg(fill_args, char *const *);
    va_end(fill_args);
    *mapping_size = bytes;
    return argv;
}

int execl(const char *path, const char *arg, ...)
{
    extern char **environ;
    va_list arguments;
    size_t mapping_size = 0;
    char **argv;
    int result;
    int result_errno;

    va_start(arguments, arg);
    argv = build_execl_argv(arg, arguments, &mapping_size, NULL, 0);
    va_end(arguments);
    if (!argv)
        return -1;
    result = execve(path, argv, environ);
    result_errno = errno;
    release_trace_record(argv, mapping_size);
    errno = result_errno;
    return result;
}

int execlp(const char *file, const char *arg, ...)
{
    va_list arguments;
    size_t mapping_size = 0;
    char **argv;
    int result;
    int result_errno;

    va_start(arguments, arg);
    argv = build_execl_argv(arg, arguments, &mapping_size, NULL, 0);
    va_end(arguments);
    if (!argv)
        return -1;
    result = execvp(file, argv);
    result_errno = errno;
    release_trace_record(argv, mapping_size);
    errno = result_errno;
    return result;
}

int execle(const char *path, const char *arg, ...)
{
    va_list arguments;
    size_t mapping_size = 0;
    char *const *envp = NULL;
    char **argv;
    int result;
    int result_errno;

    va_start(arguments, arg);
    argv = build_execl_argv(arg, arguments, &mapping_size, &envp, 1);
    va_end(arguments);
    if (!argv)
        return -1;
    result = execve(path, argv, (char *const *)envp);
    result_errno = errno;
    release_trace_record(argv, mapping_size);
    errno = result_errno;
    return result;
}

pid_t fork(void)
{
    pid_t (*forward)(void);
    pid_t result;
    int result_errno;

    /* Initialization before the process split makes an early-constructor
     * child inherit the same claimed OFDs.  The child can then contribute
     * pid-tagged records without ever trying to claim a new generation. */
    ensure_trace_initialized();
    resolve_symbols();
    forward = atomic_load_explicit(&real_fork, memory_order_acquire);
    if (!forward) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }
    if (g_wrapped_fork_depth == UINT_MAX) {
        if (dlopen_trace_is_active() || g_file_trace_fd >= 0)
            trace_write_failure();
        errno = EAGAIN;
        return -1;
    }
    g_wrapped_fork_depth++;
    result = forward();
    result_errno = errno;
    if (result == 0) {
        recover_loader_state_in_wrapped_fork_child();
        recover_cwd_state_in_wrapped_fork_child();
        recover_trace_fd_state_in_wrapped_fork_child();
        recover_descriptor_operation_in_wrapped_fork_child();
        g_trace_participant_pid = trace_current_pid();
        /* The child has one thread and a private copy of the helper state.
         * Child handlers already recover lazily if they enter an interposer;
         * after they finish, the recovery helpers have either re-keyed the
         * surviving caller's frames or discarded vanished sibling owners. */
    }
    g_wrapped_fork_depth--;
    errno = result_errno;
    return result;
}

static int trace_process_is_participant(void)
{
    pid_t pid = trace_current_pid();

    /* real fork invokes child atfork handlers before returning to this
     * wrapper.  The inherited nonzero depth identifies that short window;
     * after return the child publishes its own participant pid. */
    return pid == g_trace_participant_pid || g_wrapped_fork_depth != 0;
}

int chdir(const char *path)
{
    int (*forward)(const char *);
    int observing;
    int result;
    int result_errno;

    resolve_symbols();
    forward = atomic_load_explicit(&real_chdir, memory_order_acquire);
    observing = dlopen_trace_is_active() || g_file_trace_fd >= 0;
    if (observing)
        cwd_change_begin();
    result = forward ? forward(path) : (int)syscall(SYS_chdir, path);
    result_errno = errno;
    if (observing)
        cwd_change_end();
    errno = result_errno;
    return result;
}

int fchdir(int fd)
{
    int (*forward)(int);
    int observing;
    int result;
    int result_errno;

    resolve_symbols();
    forward = atomic_load_explicit(&real_fchdir, memory_order_acquire);
    observing = dlopen_trace_is_active() || g_file_trace_fd >= 0;
    if (observing)
        cwd_change_begin();
    result = forward ? forward(fd) : (int)syscall(SYS_fchdir, fd);
    result_errno = errno;
    if (observing)
        cwd_change_end();
    errno = result_errno;
    return result;
}

int chroot(const char *path)
{
    int (*forward)(const char *);
    int observing;
    int result;
    int result_errno;

    resolve_symbols();
    forward = atomic_load_explicit(&real_chroot, memory_order_acquire);
    observing = dlopen_trace_is_active() || g_file_trace_fd >= 0;
    if (observing)
        cwd_change_begin();
    result = forward ? forward(path) : (int)syscall(SYS_chroot, path);
    result_errno = errno;
    if (observing) {
        cwd_change_end();
        if (result == 0) {
            write_dlopen_failure("successful-chroot-is-unsupported");
            write_file_failure("successful-chroot-is-unsupported");
        }
    }
    errno = result_errno;
    return result;
}

static int descriptor_is_trace_fd(int fd)
{
    int dlopen_fd = atomic_load_explicit(&g_dlopen_trace_fd,
                                         memory_order_acquire);
    int file_fd = atomic_load_explicit(&g_file_trace_fd,
                                       memory_order_acquire);

    return fd >= 0 && (fd == dlopen_fd || fd == file_fd);
}

static int current_trace_stream_for_fd(int fd,
                                       enum trace_stream_kind *stream_out)
{
    int dlopen_fd = atomic_load_explicit(&g_dlopen_trace_fd,
                                         memory_order_acquire);
    int file_fd = atomic_load_explicit(&g_file_trace_fd,
                                       memory_order_acquire);

    if (fd == dlopen_fd) {
        *stream_out = TRACE_STREAM_DLOPEN;
        return 1;
    }
    if (fd == file_fd) {
        *stream_out = TRACE_STREAM_FILE;
        return 1;
    }
    return 0;
}

static int trace_collection_is_active(void)
{
    return atomic_load_explicit(&g_dlopen_trace_fd,
                                memory_order_acquire) >= 0 ||
           atomic_load_explicit(&g_file_trace_fd,
                                memory_order_acquire) >= 0;
}

static struct descriptor_fd_reservation *allocate_descriptor_reservation(
    unsigned int first, unsigned int last)
{
    struct descriptor_fd_reservation *reservation;

    reservation = allocate_trace_record(sizeof(*reservation));
    if (!reservation)
        return NULL;
    reservation->next = NULL;
    reservation->first = first;
    reservation->last = last;
    return reservation;
}

static int descriptor_number_is_reserved(unsigned int fd)
{
    const struct descriptor_fd_reservation *reservation;

    for (reservation = g_descriptor_fd_reservations; reservation;
         reservation = reservation->next) {
        if (fd >= reservation->first && fd <= reservation->last)
            return 1;
    }
    return 0;
}

static int descriptor_number_is_reserved_by_other(
    unsigned int fd, const struct descriptor_fd_reservation *own)
{
    const struct descriptor_fd_reservation *reservation;

    for (reservation = g_descriptor_fd_reservations; reservation;
         reservation = reservation->next) {
        if (reservation != own && fd >= reservation->first &&
            fd <= reservation->last)
            return 1;
    }
    return 0;
}

/* A V/W pair makes an interrupted downstream descriptor operation visible to
 * the collector.  In-flight target ranges remain reserved while the helper
 * lock is released, allowing unrelated operations to overlap without ever
 * selecting another caller's target as a new trace-fd number. */
static void begin_descriptor_trace_transaction_locked(
    struct descriptor_trace_transaction *transaction, int participant,
    struct descriptor_fd_reservation *reservation,
    int reservation_required)
{
    memset(transaction, 0, sizeof(*transaction));
    if (!participant || !trace_collection_is_active()) {
        if (reservation)
            release_trace_record(reservation, sizeof(*reservation));
        return;
    }
    recover_descriptor_operation_in_wrapped_fork_child();
    if (reservation_required && !reservation) {
        abandon_trace_collection(
            "descriptor-operation-reservation-is-unavailable");
        return;
    }
    transaction->pid = trace_current_pid();
    transaction->attempt = next_file_trace_operation_attempt();
    if (transaction->attempt == 0) {
        memset(transaction, 0, sizeof(*transaction));
        if (reservation)
            release_trace_record(reservation, sizeof(*reservation));
        abandon_trace_collection("descriptor-operation-sequence-overflow");
        return;
    }
    transaction->reservation = reservation;
    if (reservation) {
        reservation->next = g_descriptor_fd_reservations;
        g_descriptor_fd_reservations = reservation;
    }
    write_descriptor_operation_control_record(
        'V', transaction->pid, transaction->attempt);
}

static void discard_descriptor_reservation_locked(
    struct descriptor_trace_transaction *transaction)
{
    struct descriptor_fd_reservation **link;
    struct descriptor_fd_reservation *reservation;
    int reservation_found = 0;

    if (!transaction || !transaction->reservation)
        return;
    reservation = transaction->reservation;
    for (link = &g_descriptor_fd_reservations; *link;
         link = &(*link)->next) {
        if (*link == reservation) {
            *link = reservation->next;
            reservation_found = 1;
            break;
        }
    }
    if (!reservation_found)
        trace_write_failure();
    transaction->reservation = NULL;
    release_trace_record(reservation, sizeof(*reservation));
}

static void settle_descriptor_moves_locked(
    const struct descriptor_trace_transaction *transaction,
    enum descriptor_operation_result operation_result)
{
    for (size_t index = 0; index < transaction->move_count; index++) {
        const struct descriptor_fd_move *move = &transaction->moves[index];
        _Atomic int *published = trace_stream_descriptor(move->stream);
        const struct trace_fd_identity *identity =
            trace_stream_identity(move->stream);
        int expected;

        if (!trace_fd_identity_matches(move->old_fd, identity))
            continue;
        if (operation_result == DESCRIPTOR_OPERATION_SUCCEEDED) {
            abandon_trace_collection(
                "successful-descriptor-operation-left-trace-fd-open");
            return;
        }
        /* A failed close/replacement (or a void closefrom which ignored a
         * close error) left the original helper fd intact.  Restore the
         * pre-call publication and drop the temporary duplicate.  If another
         * in-flight operation now targets either the duplicate or moved the
         * publication again, rollback would change its native observation;
         * reject only that concrete conflict. */
        if (atomic_load_explicit(published, memory_order_acquire) !=
                move->new_fd ||
            descriptor_number_is_reserved_by_other(
                (unsigned int)move->new_fd, transaction->reservation)) {
            abandon_trace_collection(
                "descriptor-operation-rehome-rollback-conflict");
            return;
        }
        if (!trace_fd_identity_matches(move->new_fd, identity))
            trace_write_failure();
        expected = move->new_fd;
        if (!atomic_compare_exchange_strong_explicit(
                published, &expected, move->old_fd,
                memory_order_acq_rel, memory_order_acquire)) {
            abandon_trace_collection(
                "descriptor-operation-rehome-rollback-conflict");
            return;
        }
        (void)syscall(SYS_close, move->new_fd);
    }
}

static void finish_descriptor_trace_transaction(
    struct descriptor_trace_transaction *transaction,
    enum descriptor_operation_result operation_result)
{
    int saved_errno = errno;
    struct descriptor_fd_reservation *reservation;

    if (!transaction || transaction->attempt == 0)
        return;
    reservation = transaction->reservation;
    if (transaction->pid != trace_current_pid()) {
        trace_fd_state_lock();
        g_descriptor_fd_reservations = NULL;
        if (trace_collection_is_active())
            settle_descriptor_moves_locked(transaction, operation_result);
        trace_fd_state_unlock();
        if (reservation)
            release_trace_record(reservation, sizeof(*reservation));
        errno = saved_errno;
        return;
    }
    trace_fd_state_lock();
    if (trace_collection_is_active())
        settle_descriptor_moves_locked(transaction, operation_result);
    if (trace_collection_is_active())
        write_descriptor_operation_control_record(
            'W', transaction->pid, transaction->attempt);
    if (reservation)
        discard_descriptor_reservation_locked(transaction);
    trace_fd_state_unlock();
    errno = saved_errno;
}

static int duplicate_trace_fd(int fd, int minimum)
{
    int moved_fd;

    do {
        moved_fd = (int)syscall(SYS_fcntl, fd, F_DUPFD_CLOEXEC, minimum);
    } while (moved_fd < 0 && errno == EINTR);
    return moved_fd;
}

/* Move a helper-owned descriptor without changing its open file description
 * or flock.  Skip every in-flight target reservation, including the current
 * operation's range.  The caller holds the helper fd lock throughout this
 * publication-only operation. */
static int rehome_trace_fd_locked(
    int fd, struct descriptor_trace_transaction *transaction)
{
    enum trace_stream_kind stream;
    _Atomic int *published;
    const struct trace_fd_identity *identity;
    int expected;
    int moved_fd = -1;
    int minimum = 3;

    if (!current_trace_stream_for_fd(fd, &stream))
        return 1;
    published = trace_stream_descriptor(stream);
    identity = trace_stream_identity(stream);
    if (!trace_fd_identity_matches(fd, identity))
        trace_write_failure();

    for (;;) {
        unsigned int candidate;
        int advanced;

        do {
            advanced = 0;
            candidate = (unsigned int)minimum;
            for (const struct descriptor_fd_reservation *reservation =
                     g_descriptor_fd_reservations;
                 reservation; reservation = reservation->next) {
                if (candidate >= reservation->first &&
                    candidate <= reservation->last) {
                    if (reservation->last >= (unsigned int)INT_MAX)
                        return 0;
                    minimum = (int)reservation->last + 1;
                    advanced = 1;
                    break;
                }
            }
        } while (advanced);

        moved_fd = duplicate_trace_fd(fd, minimum);
        if (moved_fd < 0)
            return 0;
        if (!descriptor_number_is_reserved((unsigned int)moved_fd))
            break;
        (void)syscall(SYS_close, moved_fd);
        if (moved_fd == INT_MAX)
            return 0;
        minimum = moved_fd + 1;
        if (minimum < 3)
            return 0;
    }
    if (!trace_fd_identity_matches(moved_fd, identity)) {
        (void)syscall(SYS_close, moved_fd);
        trace_write_failure();
    }
    expected = fd;
    if (!atomic_compare_exchange_strong_explicit(
            published, &expected, moved_fd,
            memory_order_acq_rel, memory_order_acquire)) {
        (void)syscall(SYS_close, moved_fd);
        trace_write_failure();
    }
    if (!transaction ||
        transaction->move_count >=
            sizeof(transaction->moves) / sizeof(transaction->moves[0]))
        trace_write_failure();
    transaction->moves[transaction->move_count].stream = stream;
    transaction->moves[transaction->move_count].old_fd = fd;
    transaction->moves[transaction->move_count].new_fd = moved_fd;
    transaction->move_count++;
    return 1;
}

int close(int fd)
{
    struct descriptor_trace_transaction transaction;
    struct descriptor_fd_reservation *reservation = NULL;
    int (*forward)(int);
    int participant = 0;
    int result;
    int result_errno;

    /* Initialization itself can consume a descriptor the caller was about
     * to close, so establish the trace fds before classifying the close.
     * Nested loader closes while dlsym is publishing the table use the raw
     * fallback and cannot recursively initialize or poison the stream. */
    if (!g_symbols_resolving) {
        resolve_symbols();
        participant = trace_process_is_participant();
    }
    forward = atomic_load_explicit(&real_close, memory_order_acquire);
    if (!participant)
        return forward ? forward(fd) : (int)syscall(SYS_close, fd);

    if (fd >= 0 && trace_collection_is_active())
        reservation = allocate_descriptor_reservation(
            (unsigned int)fd, (unsigned int)fd);
    trace_fd_state_lock();
    begin_descriptor_trace_transaction_locked(
        &transaction, participant, reservation, fd >= 0);
    if (transaction.attempt != 0 && descriptor_is_trace_fd(fd) &&
        !rehome_trace_fd_locked(fd, &transaction))
        abandon_trace_collection("close-cannot-rehome-trace-fd");
    trace_fd_state_unlock();

    /* Never call an RTLD_NEXT implementation while holding a helper lock.
     * Lower interposers may call back, block, fork, or join another thread. */
    result = forward ? forward(fd) : (int)syscall(SYS_close, fd);
    result_errno = errno;
    finish_descriptor_trace_transaction(
        &transaction, result == 0 ? DESCRIPTOR_OPERATION_SUCCEEDED
                                  : DESCRIPTOR_OPERATION_FAILED);
    errno = result_errno;
    return result;
}

#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif
#ifndef CLOSE_RANGE_UNSHARE
#define CLOSE_RANGE_UNSHARE (1U << 1)
#endif

static int call_real_close_range(
    int (*forward)(unsigned int, unsigned int, int),
    unsigned int first, unsigned int last, int flags)
{
    if (forward)
        return forward(first, last, flags);
#if defined(SYS_close_range)
    return (int)syscall(SYS_close_range, first, last, flags);
#else
    errno = ENOSYS;
    return -1;
#endif
}

static size_t collect_trace_fds_in_range(unsigned int first,
                                         unsigned int last,
                                         unsigned int retained[2])
{
    int dlopen_fd = atomic_load_explicit(&g_dlopen_trace_fd,
                                         memory_order_acquire);
    int file_fd = atomic_load_explicit(&g_file_trace_fd,
                                       memory_order_acquire);
    size_t count = 0;

    if (dlopen_fd >= 0 && (unsigned int)dlopen_fd >= first &&
        (unsigned int)dlopen_fd <= last)
        retained[count++] = (unsigned int)dlopen_fd;
    if (file_fd >= 0 && file_fd != dlopen_fd &&
        (unsigned int)file_fd >= first && (unsigned int)file_fd <= last)
        retained[count++] = (unsigned int)file_fd;
    if (count == 2 && retained[0] > retained[1]) {
        unsigned int temporary = retained[0];

        retained[0] = retained[1];
        retained[1] = temporary;
    }
    return count;
}

/* This is the compatibility fallback for a destructive range which covers
 * every allocatable helper fd.  Exact one-call forwarding is preferred and
 * used whenever rehoming succeeds.  Segmentation is necessarily observable
 * to argument-sensitive lower interposers, but it retains traceability for
 * the ubiquitous close_range(3, UINT_MAX, 0) subprocess pattern. */
static int call_close_range_segments(
    int (*forward)(unsigned int, unsigned int, int),
    unsigned int first, unsigned int last, int flags,
    const unsigned int *retained, size_t retained_count,
    int *made_call_out)
{
    unsigned int cursor = first;
    int made_call = 0;

    for (size_t index = 0; index < retained_count; index++) {
        if (cursor < retained[index]) {
            made_call = 1;
            if (call_real_close_range(
                    forward, cursor, retained[index] - 1U, flags) < 0) {
                if (made_call_out)
                    *made_call_out = made_call;
                return -1;
            }
        }
        if (retained[index] == UINT_MAX) {
            cursor = UINT_MAX;
            break;
        }
        cursor = retained[index] + 1U;
    }
    if (cursor <= last &&
        (retained_count == 0 || retained[retained_count - 1] != last)) {
        made_call = 1;
        if (call_real_close_range(forward, cursor, last, flags) < 0) {
            if (made_call_out)
                *made_call_out = made_call;
            return -1;
        }
    }
    if (made_call_out)
        *made_call_out = made_call;
    return 0;
}

static int call_close_range_preserving_trace_fds(
    unsigned int first, unsigned int last, int flags, int *made_call_out)
{
    unsigned int retained[2];
    size_t retained_count;
    int result;
    int result_errno;

    /* The segmented compatibility path deliberately uses raw syscalls while
     * holding only the helper fd lock.  It never calls RTLD_NEXT here.  That
     * lets a concurrent close/dup rehome a stream before or after this short
     * kernel phase; the fresh snapshot below is stable through every segment
     * and the other wrapper then observes the resulting fd table normally. */
    trace_fd_state_lock();
    retained_count = collect_trace_fds_in_range(first, last, retained);
    result = call_close_range_segments(
        NULL, first, last, flags, retained, retained_count, made_call_out);
    result_errno = errno;
    trace_fd_state_unlock();
    errno = result_errno;
    return result;
}

static void abandon_trace_collection(const char *reason)
{
    trace_fd_state_lock();
    if (atomic_load_explicit(&g_dlopen_trace_fd,
                             memory_order_acquire) >= 0)
        write_trace_terminal_record(TRACE_STREAM_DLOPEN, reason);
    if (atomic_load_explicit(&g_file_trace_fd,
                             memory_order_acquire) >= 0)
        write_trace_terminal_record(TRACE_STREAM_FILE, reason);
    atomic_store_explicit(&g_trace_collection_abandoned, 1,
                          memory_order_release);
    atomic_store_explicit(&g_dlopen_trace_fd, -1, memory_order_release);
    atomic_store_explicit(&g_file_trace_fd, -1, memory_order_release);
    trace_fd_state_unlock();
}

int close_range(unsigned int first, unsigned int last, int flags)
{
    struct descriptor_trace_transaction transaction;
    struct descriptor_fd_reservation *reservation = NULL;
    int (*forward)(unsigned int, unsigned int, int);
    int participant = 0;
    int result;
    int result_errno;
    int valid_flags;
    int reservation_required;
    int segmented = 0;
    int made_segment_call = 0;

    if (!g_symbols_resolving) {
        resolve_symbols();
        participant = trace_process_is_participant();
    }
    forward = atomic_load_explicit(&real_close_range, memory_order_acquire);
    if (!participant)
        return call_real_close_range(forward, first, last, flags);

    valid_flags = ((unsigned int)flags &
                   ~(CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_UNSHARE)) == 0;
    reservation_required = first <= last && valid_flags &&
        ((unsigned int)flags &
         (CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_UNSHARE)) == 0;
    if (reservation_required && trace_collection_is_active())
        reservation = allocate_descriptor_reservation(first, last);
    trace_fd_state_lock();
    begin_descriptor_trace_transaction_locked(
        &transaction, participant, reservation, reservation_required);
    if (transaction.attempt != 0 && first <= last && valid_flags &&
        ((unsigned int)flags & CLOSE_RANGE_UNSHARE) != 0) {
        /* CLONE_FILES is split for only the calling thread.  One pair of
         * process-global descriptor numbers cannot describe both fd tables
         * after this exact operation. */
        abandon_trace_collection(
            "close-range-unshare-cannot-preserve-process-wide-trace-fds");
    } else if (transaction.attempt != 0 && first <= last && valid_flags &&
               ((unsigned int)flags & CLOSE_RANGE_CLOEXEC) == 0) {
        int dlopen_fd = atomic_load_explicit(&g_dlopen_trace_fd,
                                             memory_order_acquire);
        int file_fd = atomic_load_explicit(&g_file_trace_fd,
                                           memory_order_acquire);

        if (dlopen_fd >= 0 && (unsigned int)dlopen_fd >= first &&
            (unsigned int)dlopen_fd <= last &&
            !rehome_trace_fd_locked(dlopen_fd, &transaction))
            segmented = 1;
        file_fd = atomic_load_explicit(&g_file_trace_fd,
                                       memory_order_acquire);
        if (!segmented && trace_collection_is_active() && file_fd >= 0 &&
            (unsigned int)file_fd >= first &&
            (unsigned int)file_fd <= last &&
            !rehome_trace_fd_locked(file_fd, &transaction))
            segmented = 1;
        if (segmented)
            discard_descriptor_reservation_locked(&transaction);
    }
    trace_fd_state_unlock();

    if (segmented) {
        result = call_close_range_preserving_trace_fds(
            first, last, flags, &made_segment_call);
        if (!made_segment_call) {
            /* A range containing only helper fds offers no real syscall with
             * which to preserve native error behavior.  Reject the trace and
             * forward the exact operation instead of manufacturing success. */
            abandon_trace_collection(
                "close-range-cannot-preserve-trace-fds");
            result = call_real_close_range(forward, first, last, flags);
        } else if (result < 0) {
            int segmented_errno = errno;

            /* A tuple-sensitive policy may allow one segment and reject the
             * next.  That partial state is not equivalent to one exact native
             * call, so retain the application's result but reject the trace. */
            abandon_trace_collection(
                "segmented-close-range-did-not-complete");
            errno = segmented_errno;
        }
    } else {
        result = call_real_close_range(forward, first, last, flags);
    }
    result_errno = errno;
    finish_descriptor_trace_transaction(
        &transaction, result == 0 ? DESCRIPTOR_OPERATION_SUCCEEDED
                                  : DESCRIPTOR_OPERATION_FAILED);
    errno = result_errno;
    return result;
}

struct trace_linux_dirent64 {
    uint64_t inode;
    int64_t offset;
    unsigned short record_length;
    unsigned char type;
    char name[];
};

static int retained_descriptor(unsigned int fd,
                               const unsigned int *retained,
                               size_t retained_count)
{
    for (size_t index = 0; index < retained_count; index++) {
        if (fd == retained[index])
            return 1;
    }
    return 0;
}

static void fallback_closefrom(unsigned int first, int preserve_trace_fds)
{
    _Alignas(uint64_t) unsigned char entries[8192];
    unsigned int retained[2];
    size_t retained_count = 0;
    int directory_fd;
    int enumeration_failed = 0;
#if defined(SYS_close_range)
    int made_call = 0;
#endif

    if (preserve_trace_fds) {
        trace_fd_state_lock();
        retained_count = collect_trace_fds_in_range(
            first, UINT_MAX, retained);
    }

#if defined(SYS_close_range)
    /* closefrom ignores close errors.  Like libc implementations, try the
     * range syscall first and fall back after every error, not only ENOSYS;
     * seccomp commonly reports EPERM or EACCES. */
    if (retained_count == 0) {
        if (syscall(SYS_close_range, first, UINT_MAX, 0) == 0) {
            if (preserve_trace_fds)
                trace_fd_state_unlock();
            return;
        }
    } else if (call_close_range_segments(
                   NULL, first, UINT_MAX, 0, retained, retained_count,
                   &made_call) == 0 && made_call) {
        trace_fd_state_unlock();
        return;
    }
#endif

#if defined(SYS_getdents64)
    directory_fd = raw_openat(AT_FDCWD, "/proc/self/fd",
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
#else
    directory_fd = -1;
    errno = ENOSYS;
#endif
    if (directory_fd < 0) {
        enumeration_failed = 1;
    } else {
        for (;;) {
            long bytes;
            size_t position = 0;

            do {
#if defined(SYS_getdents64)
                bytes = syscall(SYS_getdents64, directory_fd,
                                entries, sizeof(entries));
#else
                bytes = -1;
#endif
            } while (bytes < 0 && errno == EINTR);
            if (bytes == 0)
                break;
            if (bytes < 0 || (size_t)bytes > sizeof(entries)) {
                enumeration_failed = 1;
                break;
            }
            while (position < (size_t)bytes) {
                const struct trace_linux_dirent64 *entry;
                const size_t name_offset =
                    offsetof(struct trace_linux_dirent64, name);
                size_t remaining = (size_t)bytes - position;
                size_t name_capacity;
                uint64_t parsed = 0;
                int numeric = 0;
                int terminated = 0;

                if (remaining < name_offset + 1) {
                    enumeration_failed = 1;
                    break;
                }
                entry = (const struct trace_linux_dirent64 *)
                    (const void *)(entries + position);
                if (entry->record_length < name_offset + 1 ||
                    entry->record_length > remaining ||
                    entry->record_length % _Alignof(uint64_t) != 0) {
                    enumeration_failed = 1;
                    break;
                }
                name_capacity = entry->record_length - name_offset;
                for (size_t index = 0; index < name_capacity; index++) {
                    unsigned char character =
                        (unsigned char)entry->name[index];

                    if (character == '\0') {
                        terminated = 1;
                        break;
                    }
                    if (character < '0' || character > '9') {
                        numeric = -1;
                        continue;
                    }
                    if (numeric < 0)
                        continue;
                    numeric = 1;
                    if (parsed >
                        (uint64_t)(INT_MAX -
                                   (int)(character - '0')) / 10U) {
                        numeric = -1;
                        continue;
                    }
                    parsed = parsed * 10U +
                             (unsigned int)(character - '0');
                }
                if (!terminated) {
                    enumeration_failed = 1;
                    break;
                }
                if (numeric > 0 && parsed >= first &&
                    (int)parsed != directory_fd &&
                    !retained_descriptor((unsigned int)parsed,
                                         retained, retained_count))
                    (void)syscall(SYS_close, (int)parsed);
                position += entry->record_length;
            }
            if (enumeration_failed)
                break;
        }
        (void)syscall(SYS_close, directory_fd);
    }
    if (enumeration_failed) {
        long maximum;

        if (preserve_trace_fds) {
            abandon_trace_collection(
                "closefrom-fallback-cannot-enumerate-descriptors");
            trace_fd_state_unlock();
            retained_count = 0;
        }
        maximum = sysconf(_SC_OPEN_MAX);
        if (maximum < 0)
            maximum = 1024;
        for (long fd = (long)first; fd < maximum && fd <= INT_MAX; fd++) {
            if (!retained_descriptor((unsigned int)fd,
                                     retained, retained_count))
                (void)syscall(SYS_close, (int)fd);
        }
    } else if (preserve_trace_fds) {
        trace_fd_state_unlock();
    }
}

void closefrom(int lowfd)
{
    struct descriptor_trace_transaction transaction;
    struct descriptor_fd_reservation *reservation = NULL;
    unsigned int first = lowfd < 0 ? 0U : (unsigned int)lowfd;
    void (*forward)(int);
    int participant = 0;
    int result_errno;
    int virtualized = 0;

    if (!g_symbols_resolving) {
        resolve_symbols();
        participant = trace_process_is_participant();
    }
    forward = atomic_load_explicit(&real_closefrom, memory_order_acquire);
    if (!participant) {
        if (forward)
            forward(lowfd);
        else
            fallback_closefrom(first, 0);
        return;
    }

    if (trace_collection_is_active())
        reservation = allocate_descriptor_reservation(first, UINT_MAX);
    trace_fd_state_lock();
    begin_descriptor_trace_transaction_locked(
        &transaction, participant, reservation, 1);
    if (transaction.attempt != 0) {
        int dlopen_fd = atomic_load_explicit(&g_dlopen_trace_fd,
                                             memory_order_acquire);
        int file_fd = atomic_load_explicit(&g_file_trace_fd,
                                           memory_order_acquire);

        if (dlopen_fd >= 0 && (unsigned int)dlopen_fd >= first &&
            !rehome_trace_fd_locked(dlopen_fd, &transaction))
            virtualized = 1;
        file_fd = atomic_load_explicit(&g_file_trace_fd,
                                       memory_order_acquire);
        if (!virtualized && trace_collection_is_active() && file_fd >= 0 &&
            (unsigned int)file_fd >= first &&
            !rehome_trace_fd_locked(file_fd, &transaction))
            virtualized = 1;
        if (virtualized)
            discard_descriptor_reservation_locked(&transaction);
    }
    trace_fd_state_unlock();

    if (virtualized)
        fallback_closefrom(first, 1);
    else if (forward)
        forward(lowfd);
    else
        fallback_closefrom(first, 0);
    result_errno = errno;
    finish_descriptor_trace_transaction(
        &transaction, DESCRIPTOR_OPERATION_VOID);
    errno = result_errno;
}

static void trace_descriptor_replacement_locked(
    int oldfd, int newfd,
    struct descriptor_trace_transaction *transaction)
{
    int saved_errno;
    int source_status;

    if (oldfd == newfd || !descriptor_is_trace_fd(newfd))
        return;
    saved_errno = errno;
    source_status = (int)syscall(SYS_fcntl, oldfd, F_GETFD);
    /* EBADF guarantees dup2/dup3 will leave the destination untouched.  For
     * a valid source, move the hidden destination first; the native call can
     * then succeed or fail without losing the stream or creating a false
     * terminal record. */
    if ((source_status >= 0 || errno != EBADF) &&
        !rehome_trace_fd_locked(newfd, transaction))
        abandon_trace_collection("dup-cannot-rehome-trace-fd");
    errno = saved_errno;
}

static int call_real_dup2(int (*forward)(int, int), int oldfd, int newfd)
{
    if (forward)
        return forward(oldfd, newfd);
#if defined(SYS_dup2)
    return (int)syscall(SYS_dup2, oldfd, newfd);
#elif defined(SYS_dup3)
    if (oldfd == newfd) {
        if ((int)syscall(SYS_fcntl, oldfd, F_GETFD) < 0)
            return -1;
        return newfd;
    }
    return (int)syscall(SYS_dup3, oldfd, newfd, 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int call_real_dup3(int (*forward)(int, int, int),
                          int oldfd, int newfd, int flags)
{
    if (forward)
        return forward(oldfd, newfd, flags);
#if defined(SYS_dup3)
    return (int)syscall(SYS_dup3, oldfd, newfd, flags);
#else
    errno = ENOSYS;
    return -1;
#endif
}

int dup(int oldfd)
{
    struct descriptor_trace_transaction transaction;
    int (*forward)(int);
    int participant = 0;
    int result;
    int result_errno;

    if (!g_symbols_resolving) {
        resolve_symbols();
        participant = trace_process_is_participant();
    }
    forward = atomic_load_explicit(&real_dup, memory_order_acquire);
    if (!participant)
        return forward ? forward(oldfd) : (int)syscall(SYS_dup, oldfd);
    trace_fd_state_lock();
    begin_descriptor_trace_transaction_locked(
        &transaction, participant, NULL, 0);
    if (transaction.attempt != 0 && descriptor_is_trace_fd(oldfd))
        abandon_trace_collection("dup-of-trace-fd-cannot-remain-hidden");
    trace_fd_state_unlock();
    result = forward ? forward(oldfd) : (int)syscall(SYS_dup, oldfd);
    result_errno = errno;
    finish_descriptor_trace_transaction(
        &transaction, result >= 0 ? DESCRIPTOR_OPERATION_SUCCEEDED
                                  : DESCRIPTOR_OPERATION_FAILED);
    errno = result_errno;
    return result;
}

int dup2(int oldfd, int newfd)
{
    struct descriptor_trace_transaction transaction;
    struct descriptor_fd_reservation *reservation = NULL;
    int (*forward)(int, int);
    int participant = 0;
    int result;
    int result_errno;

    if (!g_symbols_resolving) {
        resolve_symbols();
        participant = trace_process_is_participant();
    }
    forward = atomic_load_explicit(&real_dup2, memory_order_acquire);
    if (!participant)
        return call_real_dup2(forward, oldfd, newfd);
    if (oldfd != newfd && newfd >= 0 && trace_collection_is_active())
        reservation = allocate_descriptor_reservation(
            (unsigned int)newfd, (unsigned int)newfd);
    trace_fd_state_lock();
    begin_descriptor_trace_transaction_locked(
        &transaction, participant, reservation,
        oldfd != newfd && newfd >= 0);
    if (transaction.attempt != 0 && oldfd != newfd &&
        descriptor_is_trace_fd(oldfd))
        abandon_trace_collection("dup-of-trace-fd-cannot-remain-hidden");
    else if (transaction.attempt != 0)
        trace_descriptor_replacement_locked(oldfd, newfd, &transaction);
    trace_fd_state_unlock();
    result = call_real_dup2(forward, oldfd, newfd);
    result_errno = errno;
    finish_descriptor_trace_transaction(
        &transaction, result >= 0 ? DESCRIPTOR_OPERATION_SUCCEEDED
                                  : DESCRIPTOR_OPERATION_FAILED);
    errno = result_errno;
    return result;
}

int dup3(int oldfd, int newfd, int flags)
{
    struct descriptor_trace_transaction transaction;
    struct descriptor_fd_reservation *reservation = NULL;
    int (*forward)(int, int, int);
    int participant = 0;
    int result;
    int result_errno;

    if (!g_symbols_resolving) {
        resolve_symbols();
        participant = trace_process_is_participant();
    }
    forward = atomic_load_explicit(&real_dup3, memory_order_acquire);
    if (!participant)
        return call_real_dup3(forward, oldfd, newfd, flags);
    if (oldfd != newfd && newfd >= 0 &&
        (flags & ~O_CLOEXEC) == 0 && trace_collection_is_active())
        reservation = allocate_descriptor_reservation(
            (unsigned int)newfd, (unsigned int)newfd);
    trace_fd_state_lock();
    begin_descriptor_trace_transaction_locked(
        &transaction, participant, reservation,
        oldfd != newfd && newfd >= 0 && (flags & ~O_CLOEXEC) == 0);
    if (transaction.attempt != 0 && oldfd != newfd &&
        (flags & ~O_CLOEXEC) == 0 && descriptor_is_trace_fd(oldfd))
        abandon_trace_collection("dup-of-trace-fd-cannot-remain-hidden");
    else if (transaction.attempt != 0 && (flags & ~O_CLOEXEC) == 0)
        trace_descriptor_replacement_locked(oldfd, newfd, &transaction);
    trace_fd_state_unlock();
    result = call_real_dup3(forward, oldfd, newfd, flags);
    result_errno = errno;
    finish_descriptor_trace_transaction(
        &transaction, result >= 0 ? DESCRIPTOR_OPERATION_SUCCEEDED
                                  : DESCRIPTOR_OPERATION_FAILED);
    errno = result_errno;
    return result;
}

int open(const char *path, int flags, ...)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    mode_t mode = 0;
    int fd;
    int result_errno;

    if (open_needs_mode(flags)) {
        va_list ap;

        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    resolve_symbols();
    begin_cwd_observation(AT_FDCWD, path, &cwd);
    begin_file_trace_transaction(
        &transaction, open_is_capture_read(flags) && g_trace_depth == 0);
    if (real_open)
        fd = open_needs_mode(flags) ? real_open(path, flags, mode)
                                    : real_open(path, flags);
    else
        fd = raw_openat(AT_FDCWD, path, flags, mode);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd)) {
            trace_fd_result(fd, AT_FDCWD, path, &cwd);
            if (fd < 0)
                trace_missing_path(AT_FDCWD, path, result_errno, &cwd);
        }
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return fd;
}

#if DLFREEZE_HAVE_OPEN64_SYMBOL
int open64(const char *path, int flags, ...)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    mode_t mode = 0;
    int fd;
    int result_errno;

    if (open_needs_mode(flags)) {
        va_list ap;

        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    resolve_symbols();
    begin_cwd_observation(AT_FDCWD, path, &cwd);
    begin_file_trace_transaction(
        &transaction, open_is_capture_read(flags) && g_trace_depth == 0);
    if (real_open64)
        fd = open_needs_mode(flags) ? real_open64(path, flags, mode)
                                    : real_open64(path, flags);
    else if (real_open)
        fd = open_needs_mode(flags) ? real_open(path, flags, mode)
                                    : real_open(path, flags);
    else
        fd = raw_openat(AT_FDCWD, path, flags, mode);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd)) {
            trace_fd_result(fd, AT_FDCWD, path, &cwd);
            if (fd < 0)
                trace_missing_path(AT_FDCWD, path, result_errno, &cwd);
        }
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return fd;
}
#endif

int openat(int dirfd, const char *path, int flags, ...)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    mode_t mode = 0;
    int fd;
    int result_errno;

    if (open_needs_mode(flags)) {
        va_list ap;

        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    resolve_symbols();
    begin_cwd_observation(dirfd, path, &cwd);
    begin_file_trace_transaction(
        &transaction, open_is_capture_read(flags) && g_trace_depth == 0);
    if (real_openat)
        fd = open_needs_mode(flags) ? real_openat(dirfd, path, flags, mode)
                                    : real_openat(dirfd, path, flags);
    else
        fd = raw_openat(dirfd, path, flags, mode);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd)) {
            trace_fd_result(fd, dirfd, path, &cwd);
            if (fd < 0)
                trace_missing_path(dirfd, path, result_errno, &cwd);
        }
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return fd;
}

#if DLFREEZE_HAVE_OPENAT64_SYMBOL
int openat64(int dirfd, const char *path, int flags, ...)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    mode_t mode = 0;
    int fd;
    int result_errno;

    if (open_needs_mode(flags)) {
        va_list ap;

        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    resolve_symbols();
    begin_cwd_observation(dirfd, path, &cwd);
    begin_file_trace_transaction(
        &transaction, open_is_capture_read(flags) && g_trace_depth == 0);
    if (real_openat64)
        fd = open_needs_mode(flags) ? real_openat64(dirfd, path, flags, mode)
                                    : real_openat64(dirfd, path, flags);
    else if (real_openat)
        fd = open_needs_mode(flags) ? real_openat(dirfd, path, flags, mode)
                                    : real_openat(dirfd, path, flags);
    else
        fd = raw_openat(dirfd, path, flags, mode);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd)) {
            trace_fd_result(fd, dirfd, path, &cwd);
            if (fd < 0)
                trace_missing_path(dirfd, path, result_errno, &cwd);
        }
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return fd;
}
#endif

#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
int __open_2(const char *path, int flags)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    int fd;
    int result_errno;

    resolve_symbols();
    if (!real_open_2 && open_needs_mode(flags)) {
        fail_if_tracing_cannot_forward();
        errno = EINVAL;
        return -1;
    }
    begin_cwd_observation(AT_FDCWD, path, &cwd);
    begin_file_trace_transaction(
        &transaction, open_is_capture_read(flags) && g_trace_depth == 0);
    if (real_open_2)
        fd = real_open_2(path, flags);
    else
        fd = raw_openat(AT_FDCWD, path, flags, 0);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd)) {
            trace_fd_result(fd, AT_FDCWD, path, &cwd);
            if (fd < 0)
                trace_missing_path(AT_FDCWD, path, result_errno, &cwd);
        }
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return fd;
}

int __open64_2(const char *path, int flags)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    int fd;
    int result_errno;

    resolve_symbols();
    if (!real_open64_2 && !real_open_2 && open_needs_mode(flags)) {
        fail_if_tracing_cannot_forward();
        errno = EINVAL;
        return -1;
    }
    begin_cwd_observation(AT_FDCWD, path, &cwd);
    begin_file_trace_transaction(
        &transaction, open_is_capture_read(flags) && g_trace_depth == 0);
    if (real_open64_2)
        fd = real_open64_2(path, flags);
    else if (real_open_2)
        fd = real_open_2(path, flags);
    else
        fd = raw_openat(AT_FDCWD, path, flags, 0);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd)) {
            trace_fd_result(fd, AT_FDCWD, path, &cwd);
            if (fd < 0)
                trace_missing_path(AT_FDCWD, path, result_errno, &cwd);
        }
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return fd;
}

int __openat_2(int dirfd, const char *path, int flags)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    int fd;
    int result_errno;

    resolve_symbols();
    if (!real_openat_2 && open_needs_mode(flags)) {
        fail_if_tracing_cannot_forward();
        errno = EINVAL;
        return -1;
    }
    begin_cwd_observation(dirfd, path, &cwd);
    begin_file_trace_transaction(
        &transaction, open_is_capture_read(flags) && g_trace_depth == 0);
    if (real_openat_2)
        fd = real_openat_2(dirfd, path, flags);
    else
        fd = raw_openat(dirfd, path, flags, 0);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd)) {
            trace_fd_result(fd, dirfd, path, &cwd);
            if (fd < 0)
                trace_missing_path(dirfd, path, result_errno, &cwd);
        }
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return fd;
}

int __openat64_2(int dirfd, const char *path, int flags)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    int fd;
    int result_errno;

    resolve_symbols();
    if (!real_openat64_2 && !real_openat_2 && open_needs_mode(flags)) {
        fail_if_tracing_cannot_forward();
        errno = EINVAL;
        return -1;
    }
    begin_cwd_observation(dirfd, path, &cwd);
    begin_file_trace_transaction(
        &transaction, open_is_capture_read(flags) && g_trace_depth == 0);
    if (real_openat64_2)
        fd = real_openat64_2(dirfd, path, flags);
    else if (real_openat_2)
        fd = real_openat_2(dirfd, path, flags);
    else
        fd = raw_openat(dirfd, path, flags, 0);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd)) {
            trace_fd_result(fd, dirfd, path, &cwd);
            if (fd < 0)
                trace_missing_path(dirfd, path, result_errno, &cwd);
        }
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return fd;
}
#endif

FILE *fopen(const char *path, const char *mode)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    FILE *fp;
    int saved_errno;

    resolve_symbols();
    if (!real_fopen) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return NULL;
    }

    begin_cwd_observation(AT_FDCWD, path, &cwd);
    begin_file_trace_transaction(&transaction, g_trace_depth == 0);
    fp = real_fopen(path, mode);
    saved_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (fopen_is_capture_read(mode) && finish_cwd_observation(&cwd)) {
            if (fp) {
                int fd = fileno(fp);

                if (fd < 0)
                    write_file_failure(
                        "successful-fopen-has-no-file-descriptor");
                else
                    trace_fd_result(fd, AT_FDCWD, path, &cwd);
            } else {
                trace_missing_path(AT_FDCWD, path, saved_errno, &cwd);
            }
        }
        finish_file_trace_transaction(&transaction);
    }
    errno = saved_errno;
    return fp;
}

#if DLFREEZE_HAVE_FOPEN64_SYMBOL
FILE *fopen64(const char *path, const char *mode)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    FILE *fp;
    int saved_errno;

    resolve_symbols();
    if (!real_fopen64 && !real_fopen) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return NULL;
    }

    begin_cwd_observation(AT_FDCWD, path, &cwd);
    begin_file_trace_transaction(&transaction, g_trace_depth == 0);
    fp = real_fopen64 ? real_fopen64(path, mode) : real_fopen(path, mode);
    saved_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (fopen_is_capture_read(mode) && finish_cwd_observation(&cwd)) {
            if (fp) {
                int fd = fileno(fp);

                if (fd < 0)
                    write_file_failure(
                        "successful-fopen-has-no-file-descriptor");
                else
                    trace_fd_result(fd, AT_FDCWD, path, &cwd);
            } else {
                trace_missing_path(AT_FDCWD, path, saved_errno, &cwd);
            }
        }
        finish_file_trace_transaction(&transaction);
    }
    errno = saved_errno;
    return fp;
}
#endif

DIR *opendir(const char *path)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    DIR *dir;
    int result_errno;

    resolve_symbols();
    if (!real_opendir) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return NULL;
    }

    begin_cwd_observation(AT_FDCWD, path, &cwd);
    begin_file_trace_transaction(&transaction, g_trace_depth == 0);
    dir = real_opendir(path);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd)) {
            if (dir) {
                int fd = dirfd(dir);

                if (fd < 0)
                    write_file_failure(
                        "successful-opendir-has-no-file-descriptor");
                else
                    trace_fd_result(fd, AT_FDCWD, path, &cwd);
            } else {
                trace_missing_path(AT_FDCWD, path, result_errno, &cwd);
            }
        }
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return dir;
}

int stat(const char *path, struct stat *buf)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    int rc;
    int result_errno;

    resolve_symbols();
    if (!real_stat) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    begin_cwd_observation(AT_FDCWD, path, &cwd);
    begin_file_trace_transaction(&transaction, g_trace_depth == 0);
    rc = real_stat(path, buf);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd))
            trace_stat_result(rc, AT_FDCWD, path, buf, &cwd);
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return rc;
}

#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
int stat64(const char *path, struct stat64 *buf)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    int rc;
    int result_errno;

    resolve_symbols();
    if (!real_stat64) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    begin_cwd_observation(AT_FDCWD, path, &cwd);
    begin_file_trace_transaction(&transaction, g_trace_depth == 0);
    rc = real_stat64(path, buf);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd))
            trace_stat64_result(rc, AT_FDCWD, path, buf, &cwd);
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return rc;
}
#endif

int lstat(const char *path, struct stat *buf)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    int rc;
    int result_errno;

    resolve_symbols();
    if (!real_lstat) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    begin_cwd_observation(AT_FDCWD, path, &cwd);
    begin_file_trace_transaction(&transaction, g_trace_depth == 0);
    rc = real_lstat(path, buf);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd))
            trace_stat_result(rc, AT_FDCWD, path, buf, &cwd);
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return rc;
}

#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
int lstat64(const char *path, struct stat64 *buf)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    int rc;
    int result_errno;

    resolve_symbols();
    if (!real_lstat64) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    begin_cwd_observation(AT_FDCWD, path, &cwd);
    begin_file_trace_transaction(&transaction, g_trace_depth == 0);
    rc = real_lstat64(path, buf);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd))
            trace_stat64_result(rc, AT_FDCWD, path, buf, &cwd);
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return rc;
}
#endif

int fstatat(int dirfd, const char *path, struct stat *buf, int flags)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    int rc;
    int result_errno;

    resolve_symbols();
    if (!real_fstatat) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    begin_cwd_observation(dirfd, path, &cwd);
    begin_file_trace_transaction(&transaction, g_trace_depth == 0);
    rc = real_fstatat(dirfd, path, buf, flags);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd))
            trace_stat_result(rc, dirfd, path, buf, &cwd);
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return rc;
}

#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
int fstatat64(int dirfd, const char *path, struct stat64 *buf, int flags)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    int rc;
    int result_errno;

    resolve_symbols();
    if (!real_fstatat64) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    begin_cwd_observation(dirfd, path, &cwd);
    begin_file_trace_transaction(&transaction, g_trace_depth == 0);
    rc = real_fstatat64(dirfd, path, buf, flags);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd))
            trace_stat64_result(rc, dirfd, path, buf, &cwd);
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return rc;
}

int __xstat(int version, const char *path, struct stat *buf)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    int rc;
    int result_errno;

    resolve_symbols();
    if (!real_xstat) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    begin_cwd_observation(AT_FDCWD, path, &cwd);
    begin_file_trace_transaction(&transaction, g_trace_depth == 0);
    rc = real_xstat(version, path, buf);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd))
            trace_stat_result(rc, AT_FDCWD, path, buf, &cwd);
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return rc;
}

int __xstat64(int version, const char *path, struct stat64 *buf)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    int rc;
    int result_errno;

    resolve_symbols();
    if (!real_xstat64) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    begin_cwd_observation(AT_FDCWD, path, &cwd);
    begin_file_trace_transaction(&transaction, g_trace_depth == 0);
    rc = real_xstat64(version, path, buf);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd))
            trace_stat64_result(rc, AT_FDCWD, path, buf, &cwd);
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return rc;
}

int __lxstat(int version, const char *path, struct stat *buf)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    int rc;
    int result_errno;

    resolve_symbols();
    if (!real_lxstat) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    begin_cwd_observation(AT_FDCWD, path, &cwd);
    begin_file_trace_transaction(&transaction, g_trace_depth == 0);
    rc = real_lxstat(version, path, buf);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd))
            trace_stat_result(rc, AT_FDCWD, path, buf, &cwd);
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return rc;
}

int __lxstat64(int version, const char *path, struct stat64 *buf)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    int rc;
    int result_errno;

    resolve_symbols();
    if (!real_lxstat64) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    begin_cwd_observation(AT_FDCWD, path, &cwd);
    begin_file_trace_transaction(&transaction, g_trace_depth == 0);
    rc = real_lxstat64(version, path, buf);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd))
            trace_stat64_result(rc, AT_FDCWD, path, buf, &cwd);
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return rc;
}

int __fxstatat(int version, int dirfd, const char *path,
               struct stat *buf, int flags)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    int rc;
    int result_errno;

    resolve_symbols();
    if (!real_fxstatat) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    begin_cwd_observation(dirfd, path, &cwd);
    begin_file_trace_transaction(&transaction, g_trace_depth == 0);
    rc = real_fxstatat(version, dirfd, path, buf, flags);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd))
            trace_stat_result(rc, dirfd, path, buf, &cwd);
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return rc;
}

int __fxstatat64(int version, int dirfd, const char *path,
                 struct stat64 *buf, int flags)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    int rc;
    int result_errno;

    resolve_symbols();
    if (!real_fxstatat64) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    begin_cwd_observation(dirfd, path, &cwd);
    begin_file_trace_transaction(&transaction, g_trace_depth == 0);
    rc = real_fxstatat64(version, dirfd, path, buf, flags);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd))
            trace_stat64_result(rc, dirfd, path, buf, &cwd);
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return rc;
}
#endif

int access(const char *path, int mode)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    int rc;
    int result_errno;

    resolve_symbols();
    if (!real_access) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    begin_cwd_observation(AT_FDCWD, path, &cwd);
    begin_file_trace_transaction(&transaction, g_trace_depth == 0);
    rc = real_access(path, mode);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd))
            trace_access_result(rc, AT_FDCWD, path, 0, &cwd);
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return rc;
}

int faccessat(int dirfd, const char *path, int mode, int flags)
{
    struct cwd_observation cwd;
    struct file_trace_transaction transaction;
    int rc;
    int result_errno;

    resolve_symbols();
    if (!real_faccessat) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    begin_cwd_observation(dirfd, path, &cwd);
    begin_file_trace_transaction(&transaction, g_trace_depth == 0);
    rc = real_faccessat(dirfd, path, mode, flags);
    result_errno = errno;
    if (file_trace_transaction_is_current(&transaction)) {
        if (finish_cwd_observation(&cwd))
            trace_access_result(rc, dirfd, path, flags, &cwd);
        finish_file_trace_transaction(&transaction);
    }
    errno = result_errno;
    return rc;
}
