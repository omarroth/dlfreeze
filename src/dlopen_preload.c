/*
 * dlfreeze trace helper — LD_PRELOAD library.
 *
 * Logs dlopen() results to $DLFREEZE_TRACE_FILE and successful file /
 * directory opens to $DLFREEZE_FILE_TRACE_FILE.  File tracing avoids the
 * external strace dependency for -t -f capture.
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
#include <stdatomic.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "dynamic_semantics.h"

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

static int g_dlopen_trace_fd = -1;
static int g_file_trace_fd = -1;

struct trace_fd_identity {
    dev_t device;
    ino_t inode;
    dev_t rdevice;
    mode_t type;
};

static struct trace_fd_identity g_dlopen_trace_identity;
static struct trace_fd_identity g_file_trace_identity;

static _Atomic(void *(*)(const char *, int)) real_dlopen;
#if defined(LM_ID_BASE) && defined(LM_ID_NEWLM)
#define DLFREEZE_HAVE_DLMOPEN 1
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

static __thread int g_trace_depth;
static __thread int g_symbols_resolving;
static _Atomic int g_symbols_resolved;
static _Atomic uintptr_t g_trace_init_state;

#define PRELOAD_TRACE_READY "#DLFREEZE_PRELOAD_TRACE_V4"
#define DLOPEN_TRACE_READY  "#DLFREEZE_DLOPEN_TRACE_V4"
#define TRACE_INIT_READY UINTPTR_MAX

static int open_trace_fd(const char *path, struct trace_fd_identity *identity);
static void write_trace_line(int fd, const char *prefix, const char *path);
static void trace_write_failure(void) __attribute__((noreturn));

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
 * successful operation can precede the V4 readiness record.
 *
 * The TLS address identifies the initializing thread without requiring libc
 * or a loader lock.  A same-thread recursive entry cannot wait for itself and
 * therefore fails closed.  Other threads wait only for the small raw-syscall
 * initialization window; the finite bound also prevents a fork child from
 * hanging forever if it inherited an initializer owned by a vanished thread.
 */
static void ensure_trace_initialized(void)
{
    uintptr_t owner = (uintptr_t)&g_trace_depth;
    uintptr_t state;
    uintptr_t expected = 0;
    int saved_errno = errno;

    state = atomic_load_explicit(&g_trace_init_state, memory_order_acquire);
    if (state == TRACE_INIT_READY)
        return;
    if (state == owner)
        trace_write_failure();

    if (atomic_compare_exchange_strong_explicit(
            &g_trace_init_state, &expected, owner,
            memory_order_acq_rel, memory_order_acquire)) {
        g_dlopen_trace_fd = open_trace_fd(
            getenv("DLFREEZE_TRACE_FILE"), &g_dlopen_trace_identity);
        g_file_trace_fd = open_trace_fd(
            getenv("DLFREEZE_FILE_TRACE_FILE"), &g_file_trace_identity);
        write_trace_line(g_dlopen_trace_fd, "", DLOPEN_TRACE_READY);
        write_trace_line(g_file_trace_fd, "", PRELOAD_TRACE_READY);
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

    if (!path || !path[0])
        return -1;

    fd = (int)syscall(SYS_openat, AT_FDCWD, path,
                      O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC |
                          O_NOFOLLOW | O_NONBLOCK,
                      0600);
    if (fd < 0)
        return -1;
    if (raw_fstat(fd, &st) < 0) {
        (void)syscall(SYS_close, fd);
        return -1;
    }
    save_trace_fd_identity(&st, identity);
    return fd;
}

static int raw_openat(int dirfd, const char *path, int flags, mode_t mode)
{
    return (int)syscall(SYS_openat, dirfd, path, flags, mode);
}

static int build_path(int dirfd, const char *path, char *out, size_t out_sz)
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
        if (!getcwd(base, sizeof(base)))
            return 0;
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
        if (base[0] != '/')
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

static void trace_write_failure(void)
{
    static const char message[] =
        "dlfreeze: trace helper cannot write a complete trace record\n";

    /* Do not return to the traced program after losing a record: a complete
     * readiness header followed by an omitted record would otherwise be
     * indistinguishable from a complete trace.  Use raw syscalls so the
     * failure path cannot recurse through an interposed libc entry point. */
    (void)syscall(SYS_write, STDERR_FILENO, message, sizeof(message) - 1);
    /* The trace supervisor accepts every normal target exit code, including
     * 127.  Use an uncatchable signal so helper failure is distinguishable
     * without reserving an application status. */
    (void)syscall(SYS_kill, (pid_t)syscall(SYS_getpid), SIGKILL);
    /* Only reachable if a seccomp policy denied kill(2). */
    (void)syscall(SYS_exit_group, 127);
    __builtin_unreachable();
}

static const struct trace_fd_identity *trace_identity_for_fd(int fd)
{
    if (fd == g_dlopen_trace_fd)
        return &g_dlopen_trace_identity;
    if (fd == g_file_trace_fd)
        return &g_file_trace_identity;
    return NULL;
}

/* Duplicate the destination before validating it.  This closes the race in
 * which a traced program closes our descriptor and another thread reuses the
 * number between an identity check and write(2).  One record is one append
 * write: if the kernel ever reports a partial regular-file write, the record
 * is already unusable and continuing could interleave it with another
 * process, so terminate the trace instead of manufacturing corrupt syntax. */
static void trace_write_exact(int fd, const void *buffer, size_t length)
{
    const struct trace_fd_identity *identity = trace_identity_for_fd(fd);
    ssize_t written;
    int stable_fd;

    if (!identity || !buffer || length == 0)
        trace_write_failure();

    do {
        stable_fd = (int)syscall(SYS_fcntl, fd, F_DUPFD_CLOEXEC, 3);
    } while (stable_fd < 0 && errno == EINTR);
    if (stable_fd < 0 || !trace_fd_identity_matches(stable_fd, identity)) {
        if (stable_fd >= 0)
            (void)syscall(SYS_close, stable_fd);
        trace_write_failure();
    }

    do {
        written = syscall(SYS_write, stable_fd, buffer, length);
    } while (written < 0 && errno == EINTR);
    (void)syscall(SYS_close, stable_fd);
    if (written < 0 || (size_t)written != length)
        trace_write_failure();
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

static void write_trace_line(int fd, const char *prefix, const char *path)
{
    int saved_errno = errno;
    char *record;
    size_t prefix_len, path_len, record_len;

    if (fd < 0 || !path || !path[0])
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
    trace_write_exact(fd, record, record_len);
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

/* One encoded record is one O_APPEND write.  Hex encoding preserves the
 * caller's pathname byte-for-byte while keeping record boundaries explicit. */
static void write_dlopen_record(const char *request, const char *logical,
                                const char *source)
{
    int saved_errno = errno;
    char *record;
    size_t request_len, logical_len, source_len, pos = 0;
    size_t record_len;

    if (g_dlopen_trace_fd < 0 || !request || !logical || !source)
        return;
    if (!bounded_string_length(request, PATH_MAX, &request_len) ||
        !bounded_string_length(logical, PATH_MAX, &logical_len) ||
        !bounded_string_length(source, PATH_MAX, &source_len) ||
        request_len == 0 || logical_len == 0 || logical[0] != '/' ||
        source_len == 0 || source[0] != '/') {
        write_trace_line(g_dlopen_trace_fd, "", "! invalid-dlopen-record");
        errno = saved_errno;
        return;
    }
    record_len = 5;
    if (!add_hex_field_length(&record_len, request_len) ||
        !add_hex_field_length(&record_len, logical_len) ||
        !add_hex_field_length(&record_len, source_len))
        trace_write_failure();
    record = allocate_trace_record(record_len);
    if (!record)
        trace_write_failure();

    record[pos++] = strchr(request, '/') ? 'P' : 'S';
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
    record[pos++] = '\n';
    if (pos != record_len)
        trace_write_failure();
    trace_write_exact(g_dlopen_trace_fd, record, record_len);
    release_trace_record(record, record_len);
    errno = saved_errno;
}

/* File-trace V4 keeps the runtime lookup identity distinct from the
 * canonical source copied by the packer.  Negative records have no source. */
static void write_file_record(char kind, const char *request,
                              const char *source)
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
        (source && (source_len == 0 || source[0] != '/'))) {
        write_trace_line(g_file_trace_fd, "! ",
                         "invalid-file-trace-record");
        errno = saved_errno;
        return;
    }
    record_len = source ? 4 : 3;
    if (!add_hex_field_length(&record_len, request_len) ||
        (source && !add_hex_field_length(&record_len, source_len)))
        trace_write_failure();
    record = allocate_trace_record(record_len);
    if (!record)
        trace_write_failure();

    record[pos++] = kind;
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
    }
    record[pos++] = '\n';
    if (pos != record_len)
        trace_write_failure();
    trace_write_exact(g_file_trace_fd, record, record_len);
    release_trace_record(record, record_len);
    errno = saved_errno;
}

static void write_file_failure(const char *reason)
{
    if (g_file_trace_fd >= 0)
        write_trace_line(g_file_trace_fd, "! ", reason);
}

/* A successful non-NULL dlopen must yield either a complete V4 record or a
 * record that makes the packer fail closed.  In particular, alternate libcs
 * are not required to provide a usable RTLD_DI_LINKMAP result. */
static void write_dlopen_failure(const char *reason)
{
    if (g_dlopen_trace_fd >= 0)
        write_trace_line(g_dlopen_trace_fd, "! ", reason);
    else if (g_file_trace_fd >= 0)
        write_trace_line(g_file_trace_fd, "! ", reason);
}

static void fail_if_tracing_cannot_forward(void)
{
    if (g_dlopen_trace_fd >= 0 || g_file_trace_fd >= 0)
        trace_write_failure();
}

static int capture_lookup_cwd(char cwd[PATH_MAX])
{
    int saved_errno = errno;
    int captured;

    g_trace_depth++;
    captured = getcwd(cwd, PATH_MAX) != NULL;
    g_trace_depth--;
    errno = saved_errno;
    return captured;
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

static void trace_successful_dlopen(void *handle, const char *filename,
                                    const char *lookup_cwd)
{
    struct link_map *lm = NULL;
    char logical[PATH_MAX];
    char source[PATH_MAX];
    int saved_errno = errno;

    if (!handle || !filename ||
        (g_dlopen_trace_fd < 0 && g_file_trace_fd < 0))
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
    memcpy(source, logical, strlen(logical) + 1);
    if (!canonicalize_path(source, sizeof(source)) || source[0] != '/') {
        write_dlopen_failure("successful-dlopen-path-is-unresolvable");
        goto out;
    }
    if (g_dlopen_trace_fd >= 0)
        write_dlopen_record(filename, logical, source);
    /* Some libcs open dlopen() targets internally and bypass the interposed
     * open() family, so the successful link-map path is authoritative. */
    if (g_file_trace_fd >= 0)
        write_file_record('F', logical, source);
out:
    g_trace_depth--;
    errno = saved_errno;
}

static void trace_path_kind(int dirfd, const char *path, int is_dir)
{
    char request[PATH_MAX];
    char source[PATH_MAX];
    int saved_errno = errno;

    if (g_trace_depth || g_file_trace_fd < 0)
        return;
    g_trace_depth++;

    if (!build_path(dirfd, path, request, sizeof(request))) {
        write_file_failure("successful-file-request-cannot-be-made-absolute");
        goto out;
    }
    memcpy(source, request, strlen(request) + 1);
    if (!canonicalize_path(source, sizeof(source)) || source[0] != '/') {
        write_file_failure("successful-file-source-cannot-be-canonicalized");
        goto out;
    }

    write_file_record(is_dir ? 'D' : 'F', request, source);
out:
    g_trace_depth--;
    errno = saved_errno;
}

/* For a successful open, derive the copied source through the still-open file
 * descriptor instead of resolving the caller's pathname a second time.  This
 * binds the trace to the object the kernel actually opened if another thread
 * renames a directory or switches a symlink immediately after open(2). */
static void trace_fd_path_kind(int fd, int dirfd, const char *path, int is_dir)
{
    char request[PATH_MAX];
    char source[PATH_MAX];
    int saved_errno = errno;
    int length;

    if (g_trace_depth || g_file_trace_fd < 0)
        return;
    g_trace_depth++;

    if (!build_path(dirfd, path, request, sizeof(request))) {
        write_file_failure("successful-file-request-cannot-be-made-absolute");
        goto out;
    }
    length = snprintf(source, sizeof(source), "/proc/self/fd/%d", fd);
    if (length < 0 || (size_t)length >= sizeof(source) ||
        !canonicalize_path(source, sizeof(source)) || source[0] != '/') {
        write_file_failure("successful-open-source-cannot-be-canonicalized");
        goto out;
    }

    write_file_record(is_dir ? 'D' : 'F', request, source);
out:
    g_trace_depth--;
    errno = saved_errno;
}

/* Record a failed file-open (path not found) so the packer can embed a
 * negative VFS entry.  We deliberately do NOT call canonicalize_path here
 * because realpath(3) fails for non-existent paths. */
static void trace_failed_path(int dirfd, const char *path)
{
    char resolved[PATH_MAX];
    int saved_errno = errno;

    if (g_trace_depth || g_file_trace_fd < 0)
        return;
    g_trace_depth++;

    if (!build_path(dirfd, path, resolved, sizeof(resolved))) {
        write_file_failure("missing-file-request-cannot-be-made-absolute");
        goto out;
    }

    /* Only record absolute paths; relative-without-dirfd would need cwd
     * normalisation which is error-prone for non-existent entries. */
    if (resolved[0] != '/')
        goto out;

    write_file_record('N', resolved, NULL);
out:
    g_trace_depth--;
    errno = saved_errno;
}

static void trace_missing_path(int dirfd, const char *path, int error)
{
    if (error == ENOENT || error == ENOTDIR)
        trace_failed_path(dirfd, path);
}

static void trace_fd_result(int fd, int dirfd, const char *path)
{
    struct stat st;
    int saved_errno = errno;

    if (fd < 0 || g_trace_depth || g_file_trace_fd < 0 || !path || !path[0])
        goto out;

    g_trace_depth++;
    if (fstat(fd, &st) != 0) {
        g_trace_depth--;
        write_file_failure("successful-open-cannot-be-classified");
        goto out;
    }
    g_trace_depth--;
    if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
        goto out;

    trace_fd_path_kind(fd, dirfd, path, S_ISDIR(st.st_mode));
out:
    errno = saved_errno;
}

static void trace_stat_result(int rc, int dirfd, const char *path,
                              const struct stat *st)
{
    int saved_errno = errno;

    if (rc == 0 && st && (S_ISREG(st->st_mode) || S_ISDIR(st->st_mode))) {
        trace_path_kind(dirfd, path, S_ISDIR(st->st_mode));
    } else if (rc < 0 && (saved_errno == ENOENT || saved_errno == ENOTDIR)) {
        trace_failed_path(dirfd, path);
    }

    errno = saved_errno;
}

#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
static void trace_stat64_result(int rc, int dirfd, const char *path,
                                const struct stat64 *st)
{
    int saved_errno = errno;

    if (rc == 0 && st && (S_ISREG(st->st_mode) || S_ISDIR(st->st_mode))) {
        trace_path_kind(dirfd, path, S_ISDIR(st->st_mode));
    } else if (rc < 0 && (saved_errno == ENOENT || saved_errno == ENOTDIR)) {
        trace_failed_path(dirfd, path);
    }

    errno = saved_errno;
}
#endif

static void trace_access_result(int rc, int dirfd, const char *path, int flags)
{
    int saved_errno = errno;

    if (g_trace_depth || g_file_trace_fd < 0)
        goto out;

    if (rc == 0 && real_fstatat) {
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
        stat_rc = real_fstatat(dirfd, path, &st, flags);
        g_trace_depth--;
        if (stat_rc < 0) {
            write_file_failure("successful-access-cannot-be-classified");
        } else if (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode)) {
            trace_path_kind(dirfd, path, S_ISDIR(st.st_mode));
        }
    } else if (rc == 0) {
        write_file_failure("successful-access-cannot-be-classified");
    } else if (rc < 0 && (saved_errno == ENOENT || saved_errno == ENOTDIR)) {
        trace_failed_path(dirfd, path);
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
    char lookup_cwd[PATH_MAX] = "";
    char request[PATH_MAX];
    const char *trace_request = filename;
    size_t request_len = 0;
    int request_is_bounded = !filename;
    int unsupported_request = 0;

    ensure_trace_initialized();
    if (filename &&
        (g_dlopen_trace_fd >= 0 || g_file_trace_fd >= 0)) {
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
    if (unsupported_request &&
        (g_dlopen_trace_fd >= 0 || g_file_trace_fd >= 0))
        write_dlopen_failure(
            "dynamic-string-token-in-dlopen-request-is-unsupported");

    if (filename)
        (void)capture_lookup_cwd(lookup_cwd);
    resolve_symbols();
    if (!real_dlopen) {
        if (g_dlopen_trace_fd >= 0 || g_file_trace_fd >= 0)
            trace_write_failure();
        errno = ENOSYS;
        return NULL;
    }
    h = real_dlopen(filename, flags);

    if (h && !request_is_bounded)
        write_dlopen_failure("successful-dlopen-request-is-too-long");
    else if (h && !dlfrz_dlopen_mode_is_supported(flags))
        write_dlopen_failure("successful-dlopen-used-unsupported-mode-flags");
    else if (!unsupported_request)
        trace_successful_dlopen(h, trace_request, lookup_cwd);

    return h;
}

#if DLFREEZE_HAVE_DLMOPEN
void *dlmopen(Lmid_t namespace_id, const char *filename, int flags)
{
    void *handle;
    char lookup_cwd[PATH_MAX] = "";
    char request[PATH_MAX];
    const char *trace_request = filename;
    size_t request_len = 0;
    int request_is_bounded = !filename;
    int unsupported_request = 0;

    ensure_trace_initialized();
    if (filename &&
        (g_dlopen_trace_fd >= 0 || g_file_trace_fd >= 0)) {
        request_is_bounded = bounded_string_length(
            filename, sizeof(request), &request_len);
        if (request_is_bounded) {
            memcpy(request, filename, request_len + 1);
            trace_request = request;
            unsupported_request = strchr(request, '$') != NULL;
        }
    }
    if (unsupported_request &&
        (g_dlopen_trace_fd >= 0 || g_file_trace_fd >= 0))
        write_dlopen_failure(
            "dynamic-string-token-in-dlopen-request-is-unsupported");

    if (filename)
        (void)capture_lookup_cwd(lookup_cwd);
    resolve_symbols();
    if (!real_dlmopen) {
        if (g_dlopen_trace_fd >= 0 || g_file_trace_fd >= 0)
            trace_write_failure();
        errno = ENOSYS;
        return NULL;
    }
    handle = real_dlmopen(namespace_id, filename, flags);
    if (!handle)
        return NULL;

    if (!request_is_bounded) {
        write_dlopen_failure("successful-dlopen-request-is-too-long");
        return handle;
    }

    if (!dlfrz_dlopen_mode_is_supported(flags)) {
        write_dlopen_failure("successful-dlopen-used-unsupported-mode-flags");
        return handle;
    }

    if (namespace_id != LM_ID_BASE) {
        /* The direct loader has one global link-map namespace.  Capturing a
         * successful isolated load as an ordinary dlopen would silently
         * merge symbol scopes, so make the V4 trace terminally incomplete. */
        if (g_dlopen_trace_fd >= 0 || g_file_trace_fd >= 0)
            write_dlopen_failure(
                "successful-dlmopen-used-non-base-namespace");
        return handle;
    }

    if (!unsupported_request)
        trace_successful_dlopen(handle, trace_request, lookup_cwd);
    return handle;
}
#endif

int open(const char *path, int flags, ...)
{
    mode_t mode = 0;
    int fd;

    if (open_needs_mode(flags)) {
        va_list ap;

        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    resolve_symbols();
    if (real_open)
        fd = open_needs_mode(flags) ? real_open(path, flags, mode)
                                    : real_open(path, flags);
    else
        fd = raw_openat(AT_FDCWD, path, flags, mode);
    if (open_is_capture_read(flags)) {
        trace_fd_result(fd, AT_FDCWD, path);
        if (fd < 0)
            trace_missing_path(AT_FDCWD, path, errno);
    }
    return fd;
}

#if DLFREEZE_HAVE_OPEN64_SYMBOL
int open64(const char *path, int flags, ...)
{
    mode_t mode = 0;
    int fd;

    if (open_needs_mode(flags)) {
        va_list ap;

        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    resolve_symbols();
    if (real_open64)
        fd = open_needs_mode(flags) ? real_open64(path, flags, mode)
                                    : real_open64(path, flags);
    else if (real_open)
        fd = open_needs_mode(flags) ? real_open(path, flags, mode)
                                    : real_open(path, flags);
    else
        fd = raw_openat(AT_FDCWD, path, flags, mode);

    if (open_is_capture_read(flags)) {
        trace_fd_result(fd, AT_FDCWD, path);
        if (fd < 0)
            trace_missing_path(AT_FDCWD, path, errno);
    }
    return fd;
}
#endif

int openat(int dirfd, const char *path, int flags, ...)
{
    mode_t mode = 0;
    int fd;

    if (open_needs_mode(flags)) {
        va_list ap;

        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    resolve_symbols();
    if (real_openat)
        fd = open_needs_mode(flags) ? real_openat(dirfd, path, flags, mode)
                                    : real_openat(dirfd, path, flags);
    else
        fd = raw_openat(dirfd, path, flags, mode);
    if (open_is_capture_read(flags)) {
        trace_fd_result(fd, dirfd, path);
        if (fd < 0)
            trace_missing_path(dirfd, path, errno);
    }
    return fd;
}

#if DLFREEZE_HAVE_OPENAT64_SYMBOL
int openat64(int dirfd, const char *path, int flags, ...)
{
    mode_t mode = 0;
    int fd;

    if (open_needs_mode(flags)) {
        va_list ap;

        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    resolve_symbols();
    if (real_openat64)
        fd = open_needs_mode(flags) ? real_openat64(dirfd, path, flags, mode)
                                    : real_openat64(dirfd, path, flags);
    else if (real_openat)
        fd = open_needs_mode(flags) ? real_openat(dirfd, path, flags, mode)
                                    : real_openat(dirfd, path, flags);
    else
        fd = raw_openat(dirfd, path, flags, mode);

    if (open_is_capture_read(flags)) {
        trace_fd_result(fd, dirfd, path);
        if (fd < 0)
            trace_missing_path(dirfd, path, errno);
    }
    return fd;
}
#endif

#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
int __open_2(const char *path, int flags)
{
    int fd;

    resolve_symbols();
    if (real_open_2)
        fd = real_open_2(path, flags);
    else if (!open_needs_mode(flags))
        fd = raw_openat(AT_FDCWD, path, flags, 0);
    else {
        fail_if_tracing_cannot_forward();
        errno = EINVAL;
        return -1;
    }
    if (open_is_capture_read(flags)) {
        trace_fd_result(fd, AT_FDCWD, path);
        if (fd < 0)
            trace_missing_path(AT_FDCWD, path, errno);
    }
    return fd;
}

int __open64_2(const char *path, int flags)
{
    int fd;

    resolve_symbols();
    if (real_open64_2)
        fd = real_open64_2(path, flags);
    else if (real_open_2)
        fd = real_open_2(path, flags);
    else if (!open_needs_mode(flags))
        fd = raw_openat(AT_FDCWD, path, flags, 0);
    else {
        fail_if_tracing_cannot_forward();
        errno = EINVAL;
        return -1;
    }
    if (open_is_capture_read(flags)) {
        trace_fd_result(fd, AT_FDCWD, path);
        if (fd < 0)
            trace_missing_path(AT_FDCWD, path, errno);
    }
    return fd;
}

int __openat_2(int dirfd, const char *path, int flags)
{
    int fd;

    resolve_symbols();
    if (real_openat_2)
        fd = real_openat_2(dirfd, path, flags);
    else if (!open_needs_mode(flags))
        fd = raw_openat(dirfd, path, flags, 0);
    else {
        fail_if_tracing_cannot_forward();
        errno = EINVAL;
        return -1;
    }
    if (open_is_capture_read(flags)) {
        trace_fd_result(fd, dirfd, path);
        if (fd < 0)
            trace_missing_path(dirfd, path, errno);
    }
    return fd;
}

int __openat64_2(int dirfd, const char *path, int flags)
{
    int fd;

    resolve_symbols();
    if (real_openat64_2)
        fd = real_openat64_2(dirfd, path, flags);
    else if (real_openat_2)
        fd = real_openat_2(dirfd, path, flags);
    else if (!open_needs_mode(flags))
        fd = raw_openat(dirfd, path, flags, 0);
    else {
        fail_if_tracing_cannot_forward();
        errno = EINVAL;
        return -1;
    }
    if (open_is_capture_read(flags)) {
        trace_fd_result(fd, dirfd, path);
        if (fd < 0)
            trace_missing_path(dirfd, path, errno);
    }
    return fd;
}
#endif

FILE *fopen(const char *path, const char *mode)
{
    FILE *fp;
    int saved_errno;

    resolve_symbols();
    if (!real_fopen) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return NULL;
    }

    fp = real_fopen(path, mode);
    saved_errno = errno;
    if (fopen_is_capture_read(mode)) {
        if (fp) {
            int fd = fileno(fp);

            if (fd < 0)
                write_file_failure("successful-fopen-has-no-file-descriptor");
            else
                trace_fd_result(fd, AT_FDCWD, path);
        } else {
            trace_missing_path(AT_FDCWD, path, saved_errno);
        }
    }
    errno = saved_errno;
    return fp;
}

#if DLFREEZE_HAVE_FOPEN64_SYMBOL
FILE *fopen64(const char *path, const char *mode)
{
    FILE *fp;
    int saved_errno;

    resolve_symbols();
    if (!real_fopen64 && !real_fopen) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return NULL;
    }

    fp = real_fopen64 ? real_fopen64(path, mode) : real_fopen(path, mode);
    saved_errno = errno;
    if (fopen_is_capture_read(mode)) {
        if (fp) {
            int fd = fileno(fp);

            if (fd < 0)
                write_file_failure("successful-fopen-has-no-file-descriptor");
            else
                trace_fd_result(fd, AT_FDCWD, path);
        } else {
            trace_missing_path(AT_FDCWD, path, saved_errno);
        }
    }
    errno = saved_errno;
    return fp;
}
#endif

DIR *opendir(const char *path)
{
    DIR *dir;

    resolve_symbols();
    if (!real_opendir) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return NULL;
    }

    dir = real_opendir(path);
    if (dir)
        trace_path_kind(AT_FDCWD, path, 1);
    else
        trace_missing_path(AT_FDCWD, path, errno);
    return dir;
}

int stat(const char *path, struct stat *buf)
{
    int rc;

    resolve_symbols();
    if (!real_stat) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    rc = real_stat(path, buf);
    trace_stat_result(rc, AT_FDCWD, path, buf);
    return rc;
}

#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
int stat64(const char *path, struct stat64 *buf)
{
    int rc;

    resolve_symbols();
    if (!real_stat64) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    rc = real_stat64(path, buf);
    trace_stat64_result(rc, AT_FDCWD, path, buf);
    return rc;
}
#endif

int lstat(const char *path, struct stat *buf)
{
    int rc;

    resolve_symbols();
    if (!real_lstat) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    rc = real_lstat(path, buf);
    trace_stat_result(rc, AT_FDCWD, path, buf);
    return rc;
}

#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
int lstat64(const char *path, struct stat64 *buf)
{
    int rc;

    resolve_symbols();
    if (!real_lstat64) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    rc = real_lstat64(path, buf);
    trace_stat64_result(rc, AT_FDCWD, path, buf);
    return rc;
}
#endif

int fstatat(int dirfd, const char *path, struct stat *buf, int flags)
{
    int rc;

    resolve_symbols();
    if (!real_fstatat) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    rc = real_fstatat(dirfd, path, buf, flags);
    trace_stat_result(rc, dirfd, path, buf);
    return rc;
}

#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
int fstatat64(int dirfd, const char *path, struct stat64 *buf, int flags)
{
    int rc;

    resolve_symbols();
    if (!real_fstatat64) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    rc = real_fstatat64(dirfd, path, buf, flags);
    trace_stat64_result(rc, dirfd, path, buf);
    return rc;
}

int __xstat(int version, const char *path, struct stat *buf)
{
    int rc;

    resolve_symbols();
    if (!real_xstat) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    rc = real_xstat(version, path, buf);
    trace_stat_result(rc, AT_FDCWD, path, buf);
    return rc;
}

int __xstat64(int version, const char *path, struct stat64 *buf)
{
    int rc;

    resolve_symbols();
    if (!real_xstat64) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    rc = real_xstat64(version, path, buf);
    trace_stat64_result(rc, AT_FDCWD, path, buf);
    return rc;
}

int __lxstat(int version, const char *path, struct stat *buf)
{
    int rc;

    resolve_symbols();
    if (!real_lxstat) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    rc = real_lxstat(version, path, buf);
    trace_stat_result(rc, AT_FDCWD, path, buf);
    return rc;
}

int __lxstat64(int version, const char *path, struct stat64 *buf)
{
    int rc;

    resolve_symbols();
    if (!real_lxstat64) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    rc = real_lxstat64(version, path, buf);
    trace_stat64_result(rc, AT_FDCWD, path, buf);
    return rc;
}

int __fxstatat(int version, int dirfd, const char *path,
               struct stat *buf, int flags)
{
    int rc;

    resolve_symbols();
    if (!real_fxstatat) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    rc = real_fxstatat(version, dirfd, path, buf, flags);
    trace_stat_result(rc, dirfd, path, buf);
    return rc;
}

int __fxstatat64(int version, int dirfd, const char *path,
                 struct stat64 *buf, int flags)
{
    int rc;

    resolve_symbols();
    if (!real_fxstatat64) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    rc = real_fxstatat64(version, dirfd, path, buf, flags);
    trace_stat64_result(rc, dirfd, path, buf);
    return rc;
}
#endif

int access(const char *path, int mode)
{
    int rc;

    resolve_symbols();
    if (!real_access) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    rc = real_access(path, mode);
    trace_access_result(rc, AT_FDCWD, path, 0);
    return rc;
}

int faccessat(int dirfd, const char *path, int mode, int flags)
{
    int rc;

    resolve_symbols();
    if (!real_faccessat) {
        fail_if_tracing_cannot_forward();
        errno = ENOSYS;
        return -1;
    }

    rc = real_faccessat(dirfd, path, mode, flags);
    trace_access_result(rc, dirfd, path, flags);
    return rc;
}
